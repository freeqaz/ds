//! TLS-6 per-session and per-service rate limiter — the framework-agnostic library
//! core that tracks request counts per `(session, service)` tuple and enforces
//! configurable limits (doc 09 §5 TLS-6; doc 12 §3; D40 pingora confinement,
//! D77 block+log, D76/NFT-6 teardown hygiene).
//!
//! # What this is
//!
//! Once TLS-3 terminates the VM's TLS ([`crate::ca`] mints the leaf the VM sees)
//! the proxy reads the cleartext HTTP exchange — that is what unlocks HTTP-level
//! policy (doc 09 §5 TLS-3 → TLS-6). [`crate::http_policy`] is the method/host/path
//! rule + DoH-detection half of TLS-6; THIS unit is the per-session / per-service
//! **rate-limit** half: given the `(session, service)` an inspected request is bound
//! for, [`RateLimiter::allow`] increments that tuple's in-memory bucket and returns a
//! [`RateDecision`] carrying the POL-3 provenance triple (rule id / layer / policy
//! version) the boundary executable spec
//! (`boundary/tlsproxy/tlsproxy_httppolicy_test.go::TestRateLimit_PerSessionAndPerService_Isolated`,
//! D26) pins:
//!
//! - the first `N` requests on a tuple whose configured limit is `N` are **allowed**
//!   (reach upstream);
//! - request `N+1` is **refused** with a `429` (Too Many Requests) and a
//!   `Retry-After` ([`RateDecision::retry_after`]), and the caller emits a
//!   rate-refusal LOG-1 event ([`RateRefusalEvent`]) carrying the
//!   `rate:<service>` rule id + full POL-3 provenance;
//! - **bucket isolation** holds: session A's `github` bucket is independent of
//!   session A's `npm` bucket AND of session B's `github` bucket — the tuple is the
//!   whole key, so one bucket's breach never throttles another.
//!
//! A configured limit of `0` is **unlimited** (the tuple is never throttled) — the
//! boundary fake's `limitFn` returns `0` for every tuple it does not cap, and those
//! flows pass through untouched.
//!
//! # The rate decision is a TIGHTEN, never a loosen (POL-3)
//!
//! Rate limiting does not re-decide host admission: the host an inspected flow
//! reaches was already admitted by the shared `policy-core` engine the TLS-1 SNI
//! gate and DNS admission both ran (POL-3 "no consumer reimplements a rule"). This
//! unit only *tightens* — it caps the request RATE on an already-admitted
//! `(session, service)`, never admits a new one. A `429` refusal is therefore always
//! a deny layered on top of an allow, exactly like the HTTP-policy `403`
//! (deny-overrides, §1.2): the rate cap can only refuse, never grant.
//!
//! # Where it attaches (the integration seam — D40 pingora confinement, §13.1)
//!
//! No pingora type appears here. On the TLS-3 inspected path's request phase (the
//! `run_inspected_flow` request phase in `main.rs`, gated behind `DS_TLS3_LIVE`
//! exactly as the TLS-3 inspected path is) and on the TLS-2 explicit CONNECT path,
//! `main.rs` resolves the `(session, service)` the request is bound for, calls
//! [`RateLimiter::allow`] BEFORE any byte goes upstream, and on a refusal answers
//! the client an in-band `429` ([`RateDecision::deny_status`]) carrying the D77
//! structured machine-readable body (the matched `rate:<service>` rule + the
//! `Retry-After` retry-after-approval semantics) WITHOUT opening the upstream leg,
//! then emits the [`RateRefusalEvent`]. The opaque tunnel path (TLS-1 / TLS-4
//! pass-through, D17/D74) never terminates TLS, never resolves a request-level
//! service, and so never reaches this limiter — it is unaffected, and the default
//! (`DS_TLS3_LIVE` unset) path stays byte-identical. The live `main.rs` wiring is a
//! deferred unit; this is the lib-side decision core + its unit suite.
//!
//! # NFT-6 teardown hygiene (doc 12 §6, D76)
//!
//! A session's buckets are session-scoped runtime state, flushed at session-end
//! teardown ([`RateLimiter::flush_session`]) so a never-recycled session index can
//! never inherit a torn-down session's counts. This mirrors the
//! [`crate::scan::DigestSetMatcher::flush_session`] NFT-6 hygiene: session-scoped
//! entries are dropped at teardown, leaving no residue. The flush is driven by the
//! same SeveringRegistry teardown hook the other session-scoped modules hang off
//! (the live wiring is the deferred `main.rs` unit).
//!
//! # Never-log-the-secret (D73)
//!
//! [`RateRefusalEvent`] carries ONLY the tap name (LOG-2 attribution key), the
//! service name, the retry-after seconds, and the POL-3 provenance triple — all
//! `String` / `u64`. There is no header value, no body, no credential byte; the
//! boundary's leak canary cannot find a payload byte here because the shape carries
//! none — never-log-the-secret holds by construction.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::Duration;

use ds_contracts::session::SessionRef;

/// The default `Retry-After` a rate refusal advertises when the policy does not
/// override it — 30 seconds, matching the boundary fake's `30 * time.Second`. The
/// agent reads this to back off rather than spin (D77's anti-looping requirement).
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(30);

/// The policy layer a rate verdict's provenance carries — rate limits are a
/// session-scoped policy artifact (the boundary fake stamps `PolicyLayer: "session"`).
const RATE_POLICY_LAYER: &str = "session";

/// The `rule_id` prefix every rate verdict stamps. The full id is
/// `rate:<service>` so a refusal names the exact `(session, service)` bucket that
/// breached (the boundary asserts a `rate:`-prefixed rule id appears on the event),
/// and telemetry can tell two services' refusals apart.
const RATE_RULE_PREFIX: &str = "rate:";

/// Build the `rate:<service>` rule id a verdict on `service` stamps.
fn rate_rule_id(service: &str) -> String {
    format!("{RATE_RULE_PREFIX}{service}")
}

/// The POL-3 provenance triple a rate verdict carries (rule 4 — a
/// missing-provenance decision is a spec failure). Mirrors
/// [`crate::http_policy::HttpProvenance`]: it projects losslessly onto the
/// [`crate::telemetry_http::Provenance`] the LOG-1 event carries and the boundary
/// `Provenance{RuleID, PolicyLayer, PolicyVersion}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateProvenance {
    /// The matched rule id (`rate:<service>`).
    pub rule_id: String,
    /// The composing policy layer (`session` — rate limits are session-scoped).
    pub policy_layer: String,
    /// The policy version in force (the composed document's single version, rule 3).
    pub policy_version: String,
}

impl RateProvenance {
    /// Build a rate provenance for `service` at `policy_version`. The rule id is
    /// `rate:<service>` and the layer is `session`.
    pub fn for_service(service: &str, policy_version: impl Into<String>) -> RateProvenance {
        RateProvenance {
            rule_id: rate_rule_id(service),
            policy_layer: RATE_POLICY_LAYER.to_string(),
            policy_version: policy_version.into(),
        }
    }

    /// Project onto the [`crate::telemetry_http::Provenance`] the LOG-1
    /// rate-refusal record carries (the field set is identical — the mechanical
    /// migration the caller performs when it emits the refusal event).
    pub fn to_telemetry(&self) -> crate::telemetry_http::Provenance {
        crate::telemetry_http::Provenance::new(
            self.rule_id.clone(),
            self.policy_layer.clone(),
            self.policy_version.clone(),
        )
    }
}

/// A per-`(session, service)` rate-limit verdict (doc 09 §5 TLS-6) — the lib-side
/// mirror of the boundary `RateDecision{Allowed, RetryAfter, Provenance}`. An
/// allowed request proceeds upstream; a refused one is answered in-band as a `429`
/// ([`RateDecision::deny_status`]) carrying the `Retry-After`, and NEVER reaches
/// upstream. Every verdict carries mandatory POL-3 provenance (rule 4) on both
/// allow and refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateDecision {
    /// Whether the request is allowed to proceed upstream. `false` ⇒ the proxy
    /// answers the client a `429` in-band and opens NO upstream leg.
    pub allowed: bool,
    /// The `Retry-After` a refusal advertises (`Some` on a refusal, `None` on an
    /// allow) — the back-off the agent reads instead of spinning (D77 anti-looping).
    /// Rendered into the HTTP `Retry-After` header as whole seconds.
    pub retry_after: Option<Duration>,
    /// The mandatory POL-3 provenance triple (rule 4) — on both allow and refuse.
    pub provenance: RateProvenance,
}

impl RateDecision {
    /// An allow verdict for `service` (no retry-after; proceeds upstream).
    pub fn allow(provenance: RateProvenance) -> RateDecision {
        RateDecision {
            allowed: true,
            retry_after: None,
            provenance,
        }
    }

    /// A refuse verdict for `service` carrying the `Retry-After` back-off.
    pub fn refuse(retry_after: Duration, provenance: RateProvenance) -> RateDecision {
        RateDecision {
            allowed: false,
            retry_after: Some(retry_after),
            provenance,
        }
    }

    /// The client-facing status the proxy answers a refused request in-band: `429`
    /// Too Many Requests (D77 block+log — the agent sees a `429` with a structured
    /// body naming the matched `rate:<service>` rule + the `Retry-After`). An
    /// allowed request has no rate status (it proceeds upstream); `None` then.
    ///
    /// This is the rate-limit half; the HTTP-policy `403` is the sibling
    /// [`crate::http_policy`] unit's status (doc 09 §5 TLS-6 — "a 429 (rate) or 403
    /// (quota/content)").
    pub fn deny_status(&self) -> Option<u16> {
        if self.allowed {
            None
        } else {
            Some(429)
        }
    }

    /// The `Retry-After` value rendered as whole seconds for the HTTP header
    /// (RFC 7231 §7.1.3 delay-seconds form). `None` on an allow verdict. A
    /// sub-second retry-after rounds UP to at least `1` so the header is never the
    /// degenerate `Retry-After: 0` (which an agent could read as "retry now" and
    /// spin — the opposite of the anti-looping intent).
    pub fn retry_after_secs(&self) -> Option<u64> {
        self.retry_after.map(|d| {
            let secs = d.as_secs();
            if secs == 0 && d > Duration::ZERO {
                1
            } else {
                secs
            }
        })
    }
}

/// The key a rate bucket is tracked under: the full `(session, service)` tuple
/// (doc 09 §5 TLS-6). The session is keyed on its authoritative never-recycled join
/// key (the tap name — doc 14 §4) so two sessions sharing a host-local index residue
/// can never collide on a bucket; the service is the origin/service name the request
/// is bound for. The tuple being the WHOLE key is what gives bucket isolation: A's
/// github, A's npm, and B's github are three distinct keys.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BucketKey {
    /// The session's never-recycled tap name (the authoritative join key, doc 14 §4).
    tap_name: String,
    /// The service / origin the request is bound for.
    service: String,
}

impl BucketKey {
    fn new(session: &SessionRef, service: &str) -> BucketKey {
        BucketKey {
            tap_name: session.tap_name.clone(),
            service: service.to_string(),
        }
    }
}

/// The configured per-`(session, service)` limit lookup (doc 09 §5 TLS-6). Returns
/// the request-count ceiling for a tuple; `0` is **unlimited** (the tuple is never
/// throttled). This is the lib-side mirror of the boundary fake's
/// `limitFn func(sess SessionRef, service string) int` — the live binding reads the
/// ceiling off the composed policy snapshot (§1.2), a deferred unit; the unit suite
/// drives an in-memory closure.
pub trait RateLimitPolicy {
    /// The request-count ceiling for `(session, service)`; `0` ⇒ unlimited.
    fn limit_for(&self, session: &SessionRef, service: &str) -> u32;
}

/// A flat per-service rate-limit policy: one ceiling applied to every session's
/// bucket on the named service, `0` (unlimited) elsewhere. The minimal in-memory
/// shape the unit suite drives; the live policy-snapshot binding is a deferred unit.
#[derive(Clone, Debug, Default)]
pub struct ServiceRateLimits {
    /// `service -> ceiling`. An absent service is unlimited (`0`).
    by_service: HashMap<String, u32>,
}

impl ServiceRateLimits {
    /// An empty policy (every tuple unlimited).
    pub fn new() -> ServiceRateLimits {
        ServiceRateLimits::default()
    }

    /// Set `service`'s per-session ceiling to `limit` (`0` ⇒ unlimited).
    pub fn with_limit(mut self, service: impl Into<String>, limit: u32) -> ServiceRateLimits {
        self.by_service.insert(service.into(), limit);
        self
    }
}

impl RateLimitPolicy for ServiceRateLimits {
    fn limit_for(&self, _session: &SessionRef, service: &str) -> u32 {
        self.by_service.get(service).copied().unwrap_or(0)
    }
}

/// A `RateLimitPolicy` backed by a closure — the direct lib-side analogue of the
/// boundary fake's `limitFn`, so the unit suite can drive the exact
/// `(session, service) -> limit` mapping the boundary's isolation test uses (A's
/// github capped, everything else unlimited).
pub struct ClosurePolicy<F>(pub F)
where
    F: Fn(&SessionRef, &str) -> u32;

impl<F> RateLimitPolicy for ClosurePolicy<F>
where
    F: Fn(&SessionRef, &str) -> u32,
{
    fn limit_for(&self, session: &SessionRef, service: &str) -> u32 {
        (self.0)(session, service)
    }
}

/// The TLS-6 per-session / per-service rate limiter (doc 09 §5 TLS-6). Holds the
/// in-memory request-count buckets keyed on `(session, service)` and the single
/// policy version every verdict stamps (rule 3). It is the inspected-path /
/// explicit-CONNECT request-phase decision point: the caller (`main.rs`, behind
/// `DS_TLS3_LIVE`) resolves the `(session, service)` and asks [`RateLimiter::allow`]
/// before any byte goes upstream.
///
/// `P` is the configured-limit lookup ([`RateLimitPolicy`]); the buckets are owned
/// here and mutate on each [`RateLimiter::allow`], so the limiter takes `&mut self`
/// — the caller serializes access per limiter (one limiter instance per proxy, the
/// inspected request phase already runs under the per-flow task).
#[derive(Clone, Debug)]
pub struct RateLimiter<P> {
    /// The per-`(session, service)` request counts (the buckets).
    counts: HashMap<BucketKey, u64>,
    /// The configured-limit lookup.
    policy: P,
    /// The single policy version every verdict stamps (rule 3).
    policy_version: String,
    /// The `Retry-After` a refusal advertises.
    retry_after: Duration,
}

impl<P: RateLimitPolicy> RateLimiter<P> {
    /// Build a limiter over a configured-limit `policy` at `policy_version`, with
    /// the default 30s `Retry-After`.
    pub fn new(policy: P, policy_version: impl Into<String>) -> RateLimiter<P> {
        RateLimiter {
            counts: HashMap::new(),
            policy,
            policy_version: policy_version.into(),
            retry_after: DEFAULT_RETRY_AFTER,
        }
    }

    /// Override the `Retry-After` a refusal advertises (default 30s).
    pub fn with_retry_after(mut self, retry_after: Duration) -> RateLimiter<P> {
        self.retry_after = retry_after;
        self
    }

    /// The single policy version every verdict stamps (rule 3).
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Count one request on `(session, service)` and decide (doc 09 §5 TLS-6).
    ///
    /// The tuple's configured ceiling is `N = policy.limit_for(session, service)`.
    /// This is request `k` on the tuple (its post-increment count). Resolution:
    ///
    /// - `N == 0` (unlimited): **allow** — the bucket is not even incremented (an
    ///   unlimited tuple keeps no count, so it can never collide with a limited
    ///   sibling and never grows unbounded).
    /// - `k <= N`: **allow** — within the ceiling, proceeds upstream.
    /// - `k > N`: **refuse** — `429` + `Retry-After`, NEVER reaches upstream.
    ///
    /// Every verdict carries POL-3 provenance (rule 4: `rate:<service>` / `session`
    /// / the policy version) and the single policy version (rule 3). Bucket
    /// isolation holds because the bucket key is the WHOLE `(session, service)`
    /// tuple: `allow` on A/github touches only A/github's count.
    pub fn allow(&mut self, session: &SessionRef, service: &str) -> RateDecision {
        let provenance = RateProvenance::for_service(service, self.policy_version.clone());
        let limit = self.policy.limit_for(session, service);
        // 0 == unlimited: never throttled, never even counted (no unbounded growth
        // for an uncapped tuple, and it can never throttle a sibling).
        if limit == 0 {
            return RateDecision::allow(provenance);
        }
        let key = BucketKey::new(session, service);
        let count = self.counts.entry(key).or_insert(0);
        *count += 1;
        if *count > u64::from(limit) {
            RateDecision::refuse(self.retry_after, provenance)
        } else {
            RateDecision::allow(provenance)
        }
    }

    /// Flush all of `session`'s buckets at NFT-6 session-end teardown (doc 12 §6,
    /// D76) — every `(session, service)` count for this session's tap name is
    /// dropped so a never-recycled session index can never inherit a torn-down
    /// session's counts. Mirrors [`crate::scan::DigestSetMatcher::flush_session`]
    /// NFT-6 hygiene: session-scoped entries are dropped at teardown, leaving no
    /// residue. Other sessions' buckets are untouched (bucket isolation holds at
    /// teardown as at evaluation). Returns how many buckets were dropped.
    pub fn flush_session(&mut self, session: &SessionRef) -> usize {
        let tap = &session.tap_name;
        let before = self.counts.len();
        self.counts.retain(|k, _| &k.tap_name != tap);
        before - self.counts.len()
    }

    /// The current request count on `(session, service)` (for telemetry / tests). An
    /// unlimited (uncounted) tuple reads `0`.
    pub fn count(&self, session: &SessionRef, service: &str) -> u64 {
        self.counts
            .get(&BucketKey::new(session, service))
            .copied()
            .unwrap_or(0)
    }

    /// The number of live buckets (for tests / teardown-residue assertions).
    pub fn bucket_count(&self) -> usize {
        self.counts.len()
    }
}

/// A LOG-1 rate-refusal record the caller emits when [`RateLimiter::allow`] refuses
/// (doc 09 §5 TLS-6; the boundary's `requireEvent("", "rate:")` + full-provenance
/// assertion). The proxy-observed counterpart to [`crate::telemetry_http::HttpEvent`]
/// for the rate-cap path.
///
/// Never-log-the-secret (D73): the only fields are the tap name (LOG-2 attribution
/// key), the service name, the retry-after seconds, and the POL-3 provenance triple
/// — all `String` / `u64`. There is no header value, no body, no credential byte;
/// the boundary's leak canary cannot find a payload byte here because the shape
/// carries none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateRefusalEvent {
    /// The never-recycled session join key — the `dstap-<idx>` tap name (LOG-2
    /// attribution key, doc 14 §4).
    pub tap_name: String,
    /// The service / origin the refused request was bound for (the policy /
    /// attribution key).
    pub service: String,
    /// The `Retry-After` the refusal advertised, in whole seconds (the back-off the
    /// agent reads — D77 anti-looping).
    pub retry_after_secs: u64,
    /// The mandatory POL-3 provenance triple (rule 4) — `rate:<service>` / `session`
    /// / the policy version.
    pub provenance: crate::telemetry_http::Provenance,
}

impl RateRefusalEvent {
    /// Build a rate-refusal event from a refused [`RateDecision`] and the `session`
    /// it refused (for the LOG-2 tap name). Returns `None` if `decision` is an allow
    /// (an allow never produces a refusal event) — so the caller can
    /// unconditionally feed every decision and only emit when one is `Some`.
    ///
    /// The provenance is migrated off the decision's [`RateProvenance`] (the
    /// `rate:<service>` rule id + `session` layer + policy version), so the emitted
    /// event carries the SAME provenance the verdict decided — single-sourced.
    pub fn for_refusal(session: &SessionRef, decision: &RateDecision) -> Option<RateRefusalEvent> {
        if decision.allowed {
            return None;
        }
        Some(RateRefusalEvent {
            tap_name: session.tap_name.clone(),
            service: service_of(&decision.provenance.rule_id),
            retry_after_secs: decision.retry_after_secs().unwrap_or(0),
            provenance: decision.provenance.to_telemetry(),
        })
    }
}

/// Recover the service name from a `rate:<service>` rule id (the inverse of
/// [`rate_rule_id`]). A rule id that is not `rate:`-prefixed (it never should be
/// here) passes through whole, so the field is always populated.
fn service_of(rule_id: &str) -> String {
    rule_id
        .strip_prefix(RATE_RULE_PREFIX)
        .unwrap_or(rule_id)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "policy-v1";

    fn sess(uuid: &str, idx: u32, tap: &str) -> SessionRef {
        SessionRef::new(uuid.to_string(), "host-a".to_string(), idx, tap.to_string())
    }

    // The boundary isolation test's two sessions + two services. github maps to
    // api.github.com / npm to registry.npmjs.org, but the limiter keys on the
    // SERVICE name it is handed, so the unit suite uses the service tokens directly.
    fn sess_a() -> SessionRef {
        sess("aaaa-0000-0000-0000-000000000001", 1, "dstap-1")
    }
    fn sess_b() -> SessionRef {
        sess("bbbb-0000-0000-0000-000000000002", 2, "dstap-2")
    }
    const GH: &str = "github";
    const NPM: &str = "npm";

    // ── the boundary isolation test, modelled over the lib core ──────────────────

    /// `TestRateLimit_PerSessionAndPerService_Isolated`: A's github is capped at N;
    /// the first N pass, N+1 is a 429 with Retry-After + provenance; A's npm and B's
    /// github are unaffected by A's github bucket.
    #[test]
    fn per_session_and_per_service_isolated() {
        const N: u32 = 3;
        // Only A's github is capped (mirrors the boundary limitFn).
        let a_uuid = sess_a().session_uuid;
        let policy = ClosurePolicy(move |s: &SessionRef, svc: &str| {
            if s.session_uuid == a_uuid && svc.contains("github") {
                N
            } else {
                0
            }
        });
        // The boundary uses the long service tokens; mirror that so `contains`
        // matches.
        let gh = "service-github";
        let npm = "service-npm";
        let mut rl = RateLimiter::new(policy, V);

        // A -> github: N allowed.
        for i in 1..=N {
            let d = rl.allow(&sess_a(), gh);
            assert!(d.allowed, "A->github #{i} must be allowed");
            assert_eq!(d.deny_status(), None);
            assert!(d.retry_after.is_none());
            assert_eq!(d.provenance.rule_id, format!("rate:{gh}"));
            assert_eq!(d.provenance.policy_layer, "session");
            assert_eq!(d.provenance.policy_version, V);
        }
        // A -> github: N+1 refused with 429 + Retry-After + provenance.
        let over = rl.allow(&sess_a(), gh);
        assert!(!over.allowed, "A->github #{} must be refused", N + 1);
        assert_eq!(over.deny_status(), Some(429));
        assert_eq!(over.retry_after, Some(DEFAULT_RETRY_AFTER));
        assert!(
            over.retry_after_secs().unwrap() >= 1,
            "refusal must carry a non-zero Retry-After"
        );
        assert_eq!(over.provenance.rule_id, format!("rate:{gh}"));

        // The refusal produces a rate-refusal event carrying full POL-3 provenance
        // and a rate: rule id (the boundary requireEvent("", "rate:")).
        let ev = RateRefusalEvent::for_refusal(&sess_a(), &over).expect("refusal event");
        assert!(ev.provenance.rule_id.starts_with("rate:"));
        assert_eq!(ev.provenance.policy_layer, "session");
        assert_eq!(ev.provenance.policy_version, V);
        assert_eq!(ev.tap_name, "dstap-1");
        assert!(ev.retry_after_secs >= 1);

        // Bucket isolation: A->npm and B->github are unaffected (well past N).
        for i in 1..=(N + 2) {
            let an = rl.allow(&sess_a(), npm);
            assert!(an.allowed, "A->npm #{i} throttled by A's github bucket");
            let bg = rl.allow(&sess_b(), gh);
            assert!(bg.allowed, "B->github #{i} throttled by A's bucket");
        }
    }

    // ── unlimited (limit 0) ──────────────────────────────────────────────────────

    /// A `0` limit is unlimited: every request allowed, the bucket is never even
    /// created (no unbounded growth for an uncapped tuple).
    #[test]
    fn zero_limit_is_unlimited_and_uncounted() {
        let mut rl = RateLimiter::new(ServiceRateLimits::new(), V);
        for _ in 0..1000 {
            assert!(rl.allow(&sess_a(), GH).allowed);
        }
        assert_eq!(rl.count(&sess_a(), GH), 0, "unlimited tuple keeps no count");
        assert_eq!(rl.bucket_count(), 0, "unlimited tuple creates no bucket");
    }

    // ── the N-then-refuse boundary ───────────────────────────────────────────────

    /// Exactly N allowed, then every subsequent request refused (the count keeps
    /// climbing, so once breached it stays breached until flush).
    #[test]
    fn allows_n_then_refuses_all() {
        let mut rl = RateLimiter::new(ServiceRateLimits::new().with_limit(GH, 2), V);
        assert!(rl.allow(&sess_a(), GH).allowed); // 1
        assert!(rl.allow(&sess_a(), GH).allowed); // 2
        assert!(!rl.allow(&sess_a(), GH).allowed); // 3 -> refused
        assert!(!rl.allow(&sess_a(), GH).allowed); // 4 -> still refused
        assert_eq!(rl.count(&sess_a(), GH), 4);
    }

    /// A limit of 1 allows exactly the first request and refuses the second.
    #[test]
    fn limit_of_one_allows_exactly_one() {
        let mut rl = RateLimiter::new(ServiceRateLimits::new().with_limit(GH, 1), V);
        assert!(rl.allow(&sess_a(), GH).allowed);
        assert!(!rl.allow(&sess_a(), GH).allowed);
    }

    // ── bucket isolation, exhaustively ───────────────────────────────────────────

    /// The three isolation axes are independent keys: same session/different
    /// service, same service/different session, and the diagonal.
    #[test]
    fn buckets_isolate_on_every_axis() {
        // Cap BOTH services at 1 for BOTH sessions to prove each (s, svc) is its own
        // bucket: breaching one leaves the other three untouched.
        let policy = ServiceRateLimits::new()
            .with_limit(GH, 1)
            .with_limit(NPM, 1);
        let mut rl = RateLimiter::new(policy, V);

        // Breach A/github only.
        assert!(rl.allow(&sess_a(), GH).allowed);
        assert!(!rl.allow(&sess_a(), GH).allowed);

        // A/npm, B/github, B/npm are each still on their first request -> allowed.
        assert!(
            rl.allow(&sess_a(), NPM).allowed,
            "A/npm isolated from A/github"
        );
        assert!(
            rl.allow(&sess_b(), GH).allowed,
            "B/github isolated from A/github"
        );
        assert!(
            rl.allow(&sess_b(), NPM).allowed,
            "B/npm isolated from A/github"
        );
    }

    /// Two sessions whose host-local index residues could collide on the mark still
    /// get distinct buckets, because the key is the never-recycled tap name (doc 14
    /// §4), not the index.
    #[test]
    fn buckets_key_on_tap_name_not_index() {
        // Same index 1, different tap names + uuids (the orchestrator guarantees the
        // tap name is never recycled even if an index residue repeats).
        let s1 = sess("uuid-1", 1, "dstap-1");
        let s2 = sess("uuid-2", 1, "dstap-9");
        let mut rl = RateLimiter::new(ServiceRateLimits::new().with_limit(GH, 1), V);
        assert!(rl.allow(&s1, GH).allowed);
        assert!(!rl.allow(&s1, GH).allowed); // s1 breached
        assert!(rl.allow(&s2, GH).allowed, "s2 is a distinct bucket from s1");
    }

    // ── NFT-6 teardown hygiene ───────────────────────────────────────────────────

    /// Flushing a session at teardown drops only ITS buckets; a re-bound session on
    /// the same tap name starts fresh, and other sessions are untouched.
    #[test]
    fn flush_session_clears_only_that_sessions_buckets() {
        let policy = ServiceRateLimits::new()
            .with_limit(GH, 1)
            .with_limit(NPM, 1);
        let mut rl = RateLimiter::new(policy, V);

        // Breach A on both services, breach B on github.
        rl.allow(&sess_a(), GH);
        rl.allow(&sess_a(), NPM);
        rl.allow(&sess_b(), GH);
        assert_eq!(rl.bucket_count(), 3);

        // Teardown A: both of A's buckets drop, B's stays.
        let dropped = rl.flush_session(&sess_a());
        assert_eq!(dropped, 2, "A had two buckets");
        assert_eq!(rl.bucket_count(), 1);
        assert_eq!(rl.count(&sess_a(), GH), 0, "A's github bucket is gone");
        assert_eq!(rl.count(&sess_a(), NPM), 0, "A's npm bucket is gone");
        assert_eq!(rl.count(&sess_b(), GH), 1, "B's github bucket survives");

        // B is still breached (teardown of A left B alone).
        assert!(!rl.allow(&sess_b(), GH).allowed);

        // A re-bound on the same tap name starts fresh (no residue).
        assert!(rl.allow(&sess_a(), GH).allowed, "re-bound A starts fresh");
    }

    /// Flushing a session with no buckets (e.g. it only ever hit unlimited tuples)
    /// is a no-op that drops nothing.
    #[test]
    fn flush_session_with_no_buckets_is_a_noop() {
        let mut rl = RateLimiter::new(ServiceRateLimits::new(), V);
        rl.allow(&sess_a(), GH); // unlimited -> no bucket
        assert_eq!(rl.flush_session(&sess_a()), 0);
    }

    // ── provenance + projection ──────────────────────────────────────────────────

    /// Both allow and refuse carry the mandatory POL-3 provenance triple (rule 4).
    #[test]
    fn every_verdict_carries_provenance() {
        let mut rl = RateLimiter::new(ServiceRateLimits::new().with_limit(GH, 1), V);
        let allow = rl.allow(&sess_a(), GH);
        assert_eq!(allow.provenance.rule_id, "rate:github");
        assert_eq!(allow.provenance.policy_layer, "session");
        assert_eq!(allow.provenance.policy_version, V);
        let refuse = rl.allow(&sess_a(), GH);
        assert_eq!(refuse.provenance.rule_id, "rate:github");
        assert_eq!(refuse.provenance.policy_layer, "session");
        assert_eq!(refuse.provenance.policy_version, V);
    }

    /// The rate provenance projects losslessly onto the telemetry_http::Provenance
    /// the LOG-1 event carries.
    #[test]
    fn provenance_projects_onto_telemetry() {
        let p = RateProvenance::for_service("github", V);
        let t = p.to_telemetry();
        assert_eq!(t.rule_id, "rate:github");
        assert_eq!(t.policy_layer, "session");
        assert_eq!(t.policy_version, V);
    }

    // ── the refusal event ────────────────────────────────────────────────────────

    /// An allow verdict produces NO refusal event; a refuse verdict produces one
    /// carrying the tap name, service, retry-after seconds, and the migrated
    /// provenance.
    #[test]
    fn refusal_event_only_on_refusal() {
        let mut rl = RateLimiter::new(ServiceRateLimits::new().with_limit(GH, 1), V);
        let allow = rl.allow(&sess_a(), GH);
        assert!(RateRefusalEvent::for_refusal(&sess_a(), &allow).is_none());

        let refuse = rl.allow(&sess_a(), GH);
        let ev = RateRefusalEvent::for_refusal(&sess_a(), &refuse).expect("refusal event");
        assert_eq!(ev.tap_name, "dstap-1");
        assert_eq!(ev.service, "github");
        assert_eq!(ev.retry_after_secs, DEFAULT_RETRY_AFTER.as_secs());
        assert_eq!(ev.provenance.rule_id, "rate:github");
        assert_eq!(ev.provenance.policy_layer, "session");
    }

    // ── retry-after rendering ────────────────────────────────────────────────────

    /// `retry_after_secs` renders whole seconds, and a sub-second retry-after rounds
    /// up to 1 so the header is never the degenerate `Retry-After: 0`.
    #[test]
    fn retry_after_renders_whole_seconds_min_one() {
        let prov = RateProvenance::for_service("svc", V);
        // 30s -> 30.
        let d = RateDecision::refuse(Duration::from_secs(30), prov.clone());
        assert_eq!(d.retry_after_secs(), Some(30));
        // 500ms -> rounds up to 1 (never 0).
        let d = RateDecision::refuse(Duration::from_millis(500), prov.clone());
        assert_eq!(d.retry_after_secs(), Some(1));
        // an allow has no retry-after.
        let d = RateDecision::allow(prov);
        assert_eq!(d.retry_after_secs(), None);
    }

    /// A custom `Retry-After` overrides the 30s default on every refusal.
    #[test]
    fn custom_retry_after_is_honoured() {
        let mut rl = RateLimiter::new(
            ServiceRateLimits::new()
                .with_limit(GH, 0)
                .with_limit(NPM, 1),
            V,
        )
        .with_retry_after(Duration::from_secs(5));
        // npm capped at 1; second refused with the custom 5s.
        assert!(rl.allow(&sess_a(), NPM).allowed);
        let refuse = rl.allow(&sess_a(), NPM);
        assert_eq!(refuse.retry_after, Some(Duration::from_secs(5)));
        assert_eq!(refuse.retry_after_secs(), Some(5));
    }

    // ── the flat per-service policy ──────────────────────────────────────────────

    /// `ServiceRateLimits` applies one ceiling per service across sessions; an
    /// unset service is unlimited.
    #[test]
    fn service_rate_limits_applies_per_service() {
        let policy = ServiceRateLimits::new().with_limit(GH, 2);
        assert_eq!(policy.limit_for(&sess_a(), GH), 2);
        assert_eq!(
            policy.limit_for(&sess_b(), GH),
            2,
            "same ceiling, any session"
        );
        assert_eq!(
            policy.limit_for(&sess_a(), NPM),
            0,
            "unset service is unlimited"
        );
    }
}
