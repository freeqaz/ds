//! TLS-6 behavioral-cap monitor — the framework-agnostic library core that counts
//! sensitive resource actions (method/path) per session and enforces configurable
//! caps with action-dependent verdicts (doc 09 §5 TLS-6; doc 12 §3 / §13.1; D77
//! block+log default; D40 pingora confinement; D76/NFT-6 teardown hygiene).
//!
//! # What this is
//!
//! Once TLS-3 terminates the VM's TLS ([`crate::ca`] mints the leaf the VM sees) the
//! proxy reads the cleartext HTTP exchange — that is what unlocks HTTP-level policy
//! (doc 09 §5 TLS-3 → TLS-6). [`crate::http_policy`] is the method/host/path rule +
//! DoH-detection half and [`crate::rate_limit`] is the per-`(session, service)`
//! rate-limit half; THIS unit is the **behavioral-cap** half: it counts sensitive
//! resource ACTIONS (e.g. "DELETE on a critical repo") per session against a
//! configurable cap and, on the cap-breaching action, takes the cap's configured
//! VERDICT. Given the parsed request a flow carries, [`CapMonitor::record`]
//! increments the matching cap's per-`(session, cap)` counter and returns a
//! [`CapVerdict`] carrying whether the cap was breached, the cap id, the cap's
//! [`CapAction`], and the mandatory POL-3 provenance triple (rule id / layer / policy
//! version) the boundary executable spec
//! (`boundary/tlsproxy/tlsproxy_httppolicy_test.go::TestCap_BreachSuspendsMidAction_BreachingRequestHeld`
//! and `::TestCap_ResumeInvisibleToAgent`, D26) pins:
//!
//! - actions `1..=N` on a cap whose configured limit is `N` are **unaffected** (they
//!   reach upstream as ordinary requests);
//! - action `N+1` **trips the cap** ([`CapVerdict::breached`] is `true`) and the
//!   caller takes the cap's configured action: [`CapAction::Block`] (the D77 default)
//!   answers the agent a `403` in-band and opens NO upstream leg; [`CapAction::Suspend`]
//!   (reserved for explicitly dangerous operations) HOLDS the breaching request
//!   mid-action by signalling the [`SuspendGate`] and resumes — invisibly — only when
//!   orchestrator approval arrives, completing the held request with a normal `200`;
//! - the breach fires a [`BreachEvent`] LOG-1 record carrying the cap id + full
//!   POL-3 provenance (the boundary `requireEvent(EventBreach, capID)` +
//!   `requireProvenance` assertions).
//!
//! A configured limit of `0` is the degenerate cap the boundary's resume test drives:
//! **every** matching action breaches immediately (the first matching action is
//! `count == 1 > 0`).
//!
//! # The suspend-on-breach contract (doc 09 §5 done-when; doc 06 §3 suspend row)
//!
//! The headline TLS-6 invariant is that a cap breach on a SUSPEND cap holds the
//! breaching request MID-ACTION: the suspend signal fires BEFORE any of the breaching
//! request's bytes go upstream, and the held request then completes with one normal
//! `200` (not a `5xx` / reset / retry) after the orchestrator approves — the resume is
//! invisible to the agent. This module owns the COUNTING + the verdict; the HOLD/
//! RESUME mechanics are the [`SuspendGate`] seam (a per-session pause/resume the
//! orchestrator-coordination layer drives — doc 12 §13.1, the same lane as the D46
//! pause/resume marker [`crate::hold`] consumes). `main.rs` drives the ordering:
//! evaluate the cap on the inspected path's request phase, and on a SUSPEND breach
//! call [`SuspendGate::suspend`] BEFORE opening the upstream leg, so the suspend
//! happens-before any upstream byte; on the orchestrator's resume the held request
//! proceeds upstream normally. The lib-side [`enforce_breach`] composes this
//! ordering over the seam so the suspend-before-upstream + resume-to-200 contract is
//! unit-testable with no live socket.
//!
//! # The cap verdict is a TIGHTEN, never a loosen (POL-3)
//!
//! A behavioral cap does not re-decide host admission: the host an inspected flow
//! reaches was already admitted by the shared `policy-core` engine the TLS-1 SNI gate
//! and DNS admission both ran (POL-3 "no consumer reimplements a rule"). This unit
//! only *tightens* — it caps the RATE of a sensitive action on an already-admitted
//! flow, never admits a new one. A breach verdict (`403` block or a suspend hold) is
//! therefore always a deny/hold layered on top of an allow, exactly like the
//! HTTP-policy `403` (deny-overrides, §1.2) and the rate-limit `429`: the cap can only
//! refuse or hold, never grant.
//!
//! # Where it attaches (the integration seam — D40 pingora confinement, §13.1)
//!
//! No pingora type appears here. On the TLS-3 inspected path's request phase (the
//! `run_inspected_flow` request phase in `main.rs`, gated behind `DS_TLS3_LIVE`
//! exactly as the TLS-3 inspected path is), `main.rs` builds the [`ResourceAction`]
//! off the parsed cleartext request line, calls [`CapMonitor::record`] BEFORE any byte
//! goes upstream, and on a breach takes the verdict: [`CapAction::Block`] → answer the
//! agent the `403` ([`CapVerdict::block_status`]) WITHOUT opening the upstream leg;
//! [`CapAction::Suspend`] → drive [`enforce_breach`] over the wired [`SuspendGate`]
//! (hold mid-action, resume to a normal upstream forward on approval). Either way the
//! [`BreachEvent`] is emitted. The opaque tunnel path (TLS-1 / TLS-4 pass-through,
//! D17/D74) never terminates TLS, never parses a request, and so never reaches this
//! monitor — it is unaffected, and the default (`DS_TLS3_LIVE` unset) path stays
//! byte-identical. The live `main.rs` `SuspendGate` binding (the orchestrator
//! pause/resume coordination, doc 12 §13.1) is a deferred unit; this is the lib-side
//! counting + verdict core, the seam, and its unit suite.
//!
//! # NFT-6 teardown hygiene (doc 12 §6, D76)
//!
//! A session's cap counters are session-scoped runtime state, flushed at session-end
//! teardown ([`CapMonitor::flush_session`]) so a never-recycled session index can
//! never inherit a torn-down session's action counts. This mirrors the
//! [`crate::rate_limit::RateLimiter::flush_session`] / [`crate::scan::DigestSetMatcher::flush_session`]
//! NFT-6 hygiene: session-scoped entries are dropped at teardown, leaving no residue.
//!
//! # Never-log-the-secret (D73)
//!
//! [`BreachEvent`] carries ONLY the tap name (LOG-2 attribution key), the cap id, the
//! matched action's method/host/path (request METADATA, never a body byte), and the
//! POL-3 provenance triple — all `String`. There is no header value, no body, no
//! credential byte; the boundary's leak canary cannot find a payload byte here because
//! the shape carries none — never-log-the-secret holds by construction.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use ds_contracts::session::SessionRef;

/// The policy layer a cap verdict's provenance carries — behavioral caps are a
/// session-scoped policy artifact (the boundary fake stamps `PolicyLayer: "session"`).
const CAP_POLICY_LAYER: &str = "session";

/// One cap-counted action on a sensitive resource (doc 09 §5 TLS-6) — the lib-side
/// mirror of the boundary `ResourceAction{Method, Host, Path, Resource}`. The cap's
/// [`CapMatcher`] decides whether a given action is the kind this cap counts (e.g.
/// "a `DELETE`"); the monitor counts the matching actions per session.
///
/// METADATA only (D73): method / host / path / resource are request-line + routing
/// fields, never a body or header value — the cap decision reads the action shape,
/// never a payload byte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceAction {
    /// The HTTP method (e.g. `DELETE`) — the primary cap discriminator.
    pub method: String,
    /// The origin host the action targets (the SNI / `Host`).
    pub host: String,
    /// The request path the action targets (origin-form, e.g. `/repos/critical/branch`).
    pub path: String,
    /// An optional logical resource id the policy may key a cap on (e.g. a repo slug);
    /// empty when the cap keys on method/path alone.
    pub resource: String,
}

impl ResourceAction {
    /// Build a `ResourceAction` from its method / host / path (the common case; the
    /// `resource` field is left empty).
    pub fn new(
        method: impl Into<String>,
        host: impl Into<String>,
        path: impl Into<String>,
    ) -> ResourceAction {
        ResourceAction {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            resource: String::new(),
        }
    }

    /// Set the logical `resource` id (a cap may key on it; chains off [`new`]).
    ///
    /// [`new`]: ResourceAction::new
    pub fn with_resource(mut self, resource: impl Into<String>) -> ResourceAction {
        self.resource = resource.into();
        self
    }
}

/// The action a cap takes when it is BREACHED (doc 09 §5 TLS-6; D77). The DEFAULT is
/// [`CapAction::Block`] (block+log, D77 — the safe verdict for an ordinary cap);
/// [`CapAction::Suspend`] is RESERVED for explicitly dangerous operations (doc 12 §3:
/// suspend converts a breach into a human interrupt, so it is spent only where the
/// operation warrants pausing the agent mid-action).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapAction {
    /// Block + log (the D77 default): a breach answers the agent a `403` in-band and
    /// opens NO upstream leg. The safe verdict for an ordinary cap.
    #[default]
    Block,
    /// Suspend (reserved for explicitly dangerous operations, doc 12 §3): a breach
    /// HOLDS the breaching request mid-action by signalling the [`SuspendGate`] and
    /// resumes — invisibly to the agent — only when orchestrator approval arrives,
    /// completing the held request with a normal `200`.
    Suspend,
}

impl CapAction {
    /// Whether this action holds the breaching request (suspend) vs refusing it
    /// outright (block). True only for [`CapAction::Suspend`].
    pub fn holds(self) -> bool {
        matches!(self, CapAction::Suspend)
    }
}

/// The matcher half of a cap config: whether a given [`ResourceAction`] is the kind of
/// action this cap counts (doc 09 §5 TLS-6). The lib-side mirror of the boundary fake's
/// `match func(ResourceAction) bool` — the live binding reads the matcher off the
/// composed policy snapshot (a deferred unit); the unit suite drives an in-memory
/// closure ([`ClosureMatcher`]).
pub trait CapMatcher {
    /// Whether `action` is counted by this cap.
    fn matches(&self, action: &ResourceAction) -> bool;
}

/// A [`CapMatcher`] backed by a closure — the direct lib-side analogue of the boundary
/// fake's `match func(ResourceAction) bool`, so the unit suite can drive the exact
/// predicate the boundary's suspend test uses (`a.Method == DELETE`).
pub struct ClosureMatcher<F>(pub F)
where
    F: Fn(&ResourceAction) -> bool;

impl<F> CapMatcher for ClosureMatcher<F>
where
    F: Fn(&ResourceAction) -> bool,
{
    fn matches(&self, action: &ResourceAction) -> bool {
        (self.0)(action)
    }
}

/// A matcher that keys a cap on an exact HTTP method (e.g. only `DELETE`s count) — the
/// minimal in-memory matcher the unit suite and the strawman policy drive. Comparison
/// is case-insensitive (RFC 7231 methods are case-sensitive on the wire, but the proxy
/// normalizes, so the cap is robust to a lowercase `delete`).
#[derive(Clone, Debug)]
pub struct MethodMatcher {
    method: String,
}

impl MethodMatcher {
    /// A matcher that counts every action whose method equals `method`.
    pub fn new(method: impl Into<String>) -> MethodMatcher {
        MethodMatcher {
            method: method.into(),
        }
    }
}

impl CapMatcher for MethodMatcher {
    fn matches(&self, action: &ResourceAction) -> bool {
        action.method.eq_ignore_ascii_case(&self.method)
    }
}

/// A simple non-generic cap matcher the policy snapshot composes into a homogeneous
/// `Vec<CapConfig<PredicateMatcher>>` (doc 09 §5 TLS-6) — match an exact method, or
/// match any action. The non-generic enum lets a [`CapMonitor`] hold MANY caps with
/// DIFFERENT predicates under one matcher type (`CapMonitor<PredicateMatcher>`), which
/// the generic [`ClosureMatcher`] (one closure type per cap) cannot. The live policy
/// bind builds these off the composed snapshot; this is the minimal predicate set the
/// strawman + unit suite need.
#[derive(Clone, Debug)]
pub enum PredicateMatcher {
    /// Match every action whose method equals this (case-insensitive).
    Method(String),
    /// Match every action (a catch-all cap — e.g. an overall per-session action cap).
    Any,
}

impl PredicateMatcher {
    /// A method predicate (counts every action with method `method`).
    pub fn method(method: impl Into<String>) -> PredicateMatcher {
        PredicateMatcher::Method(method.into())
    }
}

impl CapMatcher for PredicateMatcher {
    fn matches(&self, action: &ResourceAction) -> bool {
        match self {
            PredicateMatcher::Method(m) => action.method.eq_ignore_ascii_case(m),
            PredicateMatcher::Any => true,
        }
    }
}

/// One configured behavioral cap (doc 09 §5 TLS-6): an `id`, a per-session `limit` (the
/// action-count ceiling — the first `limit` matching actions are unaffected, the
/// `limit + 1`th breaches), a [`CapMatcher`] (which actions it counts), and the
/// [`CapAction`] it takes on breach. The lib-side mirror of the boundary fake's
/// `(capID, limit, match, action)`.
///
/// `M` is the matcher; one `CapConfig` describes one cap. The live binding builds these
/// off the composed policy snapshot (a deferred unit); the unit suite builds them
/// in-memory.
#[derive(Clone, Debug)]
pub struct CapConfig<M> {
    /// The cap id (e.g. `cap:delete-5-per-hour`) — the rule id every verdict on this
    /// cap stamps and the breach event carries.
    pub id: String,
    /// The per-session action-count ceiling. The first `limit` matching actions are
    /// unaffected; the `limit + 1`th breaches. `0` ⇒ the first matching action
    /// breaches.
    pub limit: u32,
    /// Which actions this cap counts.
    pub matcher: M,
    /// The verdict the cap takes on breach (default [`CapAction::Block`], D77).
    pub action: CapAction,
}

impl<M: CapMatcher> CapConfig<M> {
    /// A block+log cap (the D77 default action) with id `id`, ceiling `limit`, and
    /// `matcher`. Use [`suspend`] for the reserved suspend action.
    ///
    /// [`suspend`]: CapConfig::suspend
    pub fn block(id: impl Into<String>, limit: u32, matcher: M) -> CapConfig<M> {
        CapConfig {
            id: id.into(),
            limit,
            matcher,
            action: CapAction::Block,
        }
    }

    /// A suspend cap (reserved for explicitly dangerous operations, doc 12 §3) with id
    /// `id`, ceiling `limit`, and `matcher` — a breach HOLDS the request mid-action via
    /// the [`SuspendGate`].
    pub fn suspend(id: impl Into<String>, limit: u32, matcher: M) -> CapConfig<M> {
        CapConfig {
            id: id.into(),
            limit,
            matcher,
            action: CapAction::Suspend,
        }
    }
}

/// The POL-3 provenance triple a cap verdict carries (rule 4 — a missing-provenance
/// decision is a spec failure). Mirrors [`crate::rate_limit::RateProvenance`]: it
/// projects losslessly onto the [`crate::telemetry_http::Provenance`] the LOG-1 breach
/// event carries and the boundary `Provenance{RuleID, PolicyLayer, PolicyVersion}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapProvenance {
    /// The matched rule id (the cap id, e.g. `cap:delete-5-per-hour`).
    pub rule_id: String,
    /// The composing policy layer (`session` — caps are session-scoped).
    pub policy_layer: String,
    /// The policy version in force (the composed document's single version, rule 3).
    pub policy_version: String,
}

impl CapProvenance {
    /// Build a cap provenance for `cap_id` at `policy_version`. The rule id is the cap
    /// id and the layer is `session`.
    pub fn for_cap(cap_id: &str, policy_version: impl Into<String>) -> CapProvenance {
        CapProvenance {
            rule_id: cap_id.to_string(),
            policy_layer: CAP_POLICY_LAYER.to_string(),
            policy_version: policy_version.into(),
        }
    }

    /// Project onto the [`crate::telemetry_http::Provenance`] the LOG-1 breach record
    /// carries (the field set is identical — the mechanical migration the caller
    /// performs when it emits the breach event).
    pub fn to_telemetry(&self) -> crate::telemetry_http::Provenance {
        crate::telemetry_http::Provenance::new(
            self.rule_id.clone(),
            self.policy_layer.clone(),
            self.policy_version.clone(),
        )
    }
}

/// A per-`(session, cap)` cap verdict (doc 09 §5 TLS-6) — the lib-side mirror of the
/// boundary `CapVerdict{Breached, CapID, Provenance}` plus the cap's [`CapAction`] the
/// caller needs to take the right verdict. An un-breached action proceeds upstream; a
/// breached one is handled per its `action` (block `403` or suspend hold), and NEVER
/// reaches upstream un-gated. Every verdict on a matched action carries mandatory POL-3
/// provenance (rule 4).
///
/// A `record` on an action NO cap matches returns [`CapVerdict::no_cap`] (no cap id, not
/// breached) — the action is ordinary and proceeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapVerdict {
    /// Whether this action tripped the cap (`count > limit`). `true` ⇒ the caller takes
    /// the `action` verdict and the action does NOT proceed un-gated.
    pub breached: bool,
    /// The matched cap id (empty when no cap matched the action).
    pub cap_id: String,
    /// The cap's configured action (default [`CapAction::Block`]). Only meaningful when
    /// `breached`; on a non-breach it carries the matched cap's action for context.
    pub action: CapAction,
    /// The POL-3 provenance triple. Present on every MATCHED action (`Some`); `None`
    /// when no cap matched the action (an ordinary request, no cap decision was made).
    pub provenance: Option<CapProvenance>,
}

impl CapVerdict {
    /// The verdict for an action no cap matched: not breached, no cap id, no
    /// provenance (no cap decision was made — the action is ordinary and proceeds).
    pub fn no_cap() -> CapVerdict {
        CapVerdict {
            breached: false,
            cap_id: String::new(),
            action: CapAction::Block,
            provenance: None,
        }
    }

    /// A within-limit verdict for a matched action: counted, not breached, carrying the
    /// cap id + action + provenance (the action proceeds upstream).
    pub fn within_limit(cap_id: &str, action: CapAction, provenance: CapProvenance) -> CapVerdict {
        CapVerdict {
            breached: false,
            cap_id: cap_id.to_string(),
            action,
            provenance: Some(provenance),
        }
    }

    /// A breach verdict for a matched action: counted past the ceiling, carrying the cap
    /// id + the cap's action + provenance. The caller takes the action verdict (block
    /// `403` or suspend hold) and the action does NOT proceed un-gated.
    pub fn breached(cap_id: &str, action: CapAction, provenance: CapProvenance) -> CapVerdict {
        CapVerdict {
            breached: true,
            cap_id: cap_id.to_string(),
            action,
            provenance: Some(provenance),
        }
    }

    /// The client-facing status the proxy answers a BLOCK-breach in-band: `403`
    /// Forbidden (D77 block+log). Returns `Some(403)` only on a breach whose action is
    /// [`CapAction::Block`]; a suspend breach is HELD (not refused) so it has no block
    /// status (`None`), and an un-breached action has none either.
    pub fn block_status(&self) -> Option<u16> {
        if self.breached && matches!(self.action, CapAction::Block) {
            Some(403)
        } else {
            None
        }
    }

    /// Whether this breach must be HELD via the [`SuspendGate`] (a suspend-action
    /// breach) rather than refused with a `403`. False for a non-breach or a block
    /// breach.
    pub fn must_suspend(&self) -> bool {
        self.breached && self.action.holds()
    }
}

/// The key a cap counter is tracked under: the `(session, cap)` tuple (doc 09 §5
/// TLS-6). The session is keyed on its authoritative never-recycled join key (the tap
/// name — doc 14 §4) so two sessions sharing a host-local index residue can never
/// collide on a counter; the cap is keyed on its id. The tuple being the WHOLE key is
/// what isolates one session's cap counts from another's and one cap from another.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CounterKey {
    /// The session's never-recycled tap name (the authoritative join key, doc 14 §4).
    tap_name: String,
    /// The cap id.
    cap_id: String,
}

impl CounterKey {
    fn new(session: &SessionRef, cap_id: &str) -> CounterKey {
        CounterKey {
            tap_name: session.tap_name.clone(),
            cap_id: cap_id.to_string(),
        }
    }
}

/// The TLS-6 behavioral-cap monitor (doc 09 §5 TLS-6). Holds the in-memory
/// per-`(session, cap)` action counters and the configured caps; the single policy
/// version every verdict stamps (rule 3). It is the inspected-path request-phase
/// decision point: the caller (`main.rs`, behind `DS_TLS3_LIVE`) builds the
/// [`ResourceAction`] off the parsed request and asks [`CapMonitor::record`] before any
/// byte goes upstream.
///
/// `M` is the cap matcher ([`CapMatcher`]); the monitor owns its caps + counters and
/// mutates the counters on each [`CapMonitor::record`], so it takes `&mut self` — the
/// caller serializes access per monitor (one monitor instance per proxy, the inspected
/// request phase already runs under the per-flow task).
#[derive(Clone, Debug)]
pub struct CapMonitor<M> {
    /// The configured caps (evaluated in order; the FIRST matching cap decides — a
    /// request matched by two caps is counted/decided by the first, deny-first §1.2).
    caps: Vec<CapConfig<M>>,
    /// The per-`(session, cap)` action counts.
    counts: HashMap<CounterKey, u64>,
    /// The single policy version every verdict stamps (rule 3).
    policy_version: String,
}

impl<M: CapMatcher> CapMonitor<M> {
    /// Build a monitor over `caps` at `policy_version`.
    pub fn new(caps: Vec<CapConfig<M>>, policy_version: impl Into<String>) -> CapMonitor<M> {
        CapMonitor {
            caps,
            counts: HashMap::new(),
            policy_version: policy_version.into(),
        }
    }

    /// A monitor with a single cap (the common case the unit suite and strawman drive).
    pub fn single(cap: CapConfig<M>, policy_version: impl Into<String>) -> CapMonitor<M> {
        CapMonitor::new(vec![cap], policy_version)
    }

    /// The single policy version every verdict stamps (rule 3).
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Count one `action` for `session` and decide (doc 09 §5 TLS-6).
    ///
    /// The FIRST configured cap whose [`CapMatcher`] matches `action` is the deciding
    /// cap (deny-first, §1.2 — at most one cap counts a given action). For that cap with
    /// ceiling `N`, this is action `k` on the `(session, cap)` counter (its
    /// post-increment count). Resolution:
    ///
    /// - no cap matches: [`CapVerdict::no_cap`] — the action is ordinary and proceeds
    ///   (no counter is touched).
    /// - `k <= N`: [`CapVerdict::within_limit`] — under the ceiling, proceeds upstream.
    /// - `k > N`: [`CapVerdict::breached`] — the cap is tripped; the caller takes the
    ///   cap's [`CapAction`] (block `403` or suspend hold) and the action does NOT
    ///   proceed un-gated.
    ///
    /// Every MATCHED verdict carries POL-3 provenance (rule 4: the cap id / `session`
    /// layer / the policy version) and the single policy version (rule 3). Counters
    /// isolate because the key is the WHOLE `(session, cap)` tuple keyed on the
    /// never-recycled tap name: `record` on A/cap-x touches only A/cap-x's count.
    pub fn record(&mut self, session: &SessionRef, action: &ResourceAction) -> CapVerdict {
        let Some(cap) = self.caps.iter().find(|c| c.matcher.matches(action)) else {
            // No cap counts this action — it is ordinary and proceeds. No counter is
            // created (an unmatched action keeps no state, so it never grows the map and
            // never collides with a capped sibling).
            return CapVerdict::no_cap();
        };
        let cap_id = cap.id.clone();
        let limit = cap.limit;
        let cap_action = cap.action;
        let provenance = CapProvenance::for_cap(&cap_id, self.policy_version.clone());

        let key = CounterKey::new(session, &cap_id);
        let count = self.counts.entry(key).or_insert(0);
        *count += 1;
        if *count > u64::from(limit) {
            CapVerdict::breached(&cap_id, cap_action, provenance)
        } else {
            CapVerdict::within_limit(&cap_id, cap_action, provenance)
        }
    }

    /// Flush all of `session`'s cap counters at NFT-6 session-end teardown (doc 12 §6,
    /// D76) — every `(session, cap)` count for this session's tap name is dropped so a
    /// never-recycled session index can never inherit a torn-down session's action
    /// counts. Mirrors [`crate::rate_limit::RateLimiter::flush_session`] NFT-6 hygiene.
    /// Other sessions' counters are untouched. Returns how many counters were dropped.
    pub fn flush_session(&mut self, session: &SessionRef) -> usize {
        let tap = &session.tap_name;
        let before = self.counts.len();
        self.counts.retain(|k, _| &k.tap_name != tap);
        before - self.counts.len()
    }

    /// The current action count on `(session, cap)` (for telemetry / tests). An
    /// unmatched (uncounted) cap reads `0`.
    pub fn count(&self, session: &SessionRef, cap_id: &str) -> u64 {
        self.counts
            .get(&CounterKey::new(session, cap_id))
            .copied()
            .unwrap_or(0)
    }

    /// The number of live counters (for tests / teardown-residue assertions).
    pub fn counter_count(&self) -> usize {
        self.counts.len()
    }
}

/// The breach payload the suspend signal carries (doc 09 §5 TLS-6) — the lib-side
/// mirror of the boundary `BreachInfo{CapID, Action, Provenance}`. It accompanies the
/// [`SuspendGate::suspend`] call so the orchestrator-coordination layer knows which cap
/// breached, on what action, with what provenance.
///
/// METADATA + provenance only (D73): the cap id, the action's method/host/path
/// (request metadata), and the POL-3 provenance triple — no body, no header value, no
/// credential byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreachInfo {
    /// The breached cap id.
    pub cap_id: String,
    /// The action that breached the cap.
    pub action: ResourceAction,
    /// The mandatory POL-3 provenance triple (rule 4).
    pub provenance: CapProvenance,
}

impl BreachInfo {
    /// Build the breach payload from a breached [`CapVerdict`] and the `action` that
    /// breached it. Returns `None` if `verdict` is not a breach (a non-breach never
    /// produces breach info) — so the caller can unconditionally feed every verdict and
    /// only signal when one is `Some`.
    pub fn for_breach(verdict: &CapVerdict, action: &ResourceAction) -> Option<BreachInfo> {
        if !verdict.breached {
            return None;
        }
        let provenance = verdict.provenance.clone()?;
        Some(BreachInfo {
            cap_id: verdict.cap_id.clone(),
            action: action.clone(),
            provenance,
        })
    }
}

/// The orchestrator suspend-signal seam (doc 12 §13.1) — the per-session pause/resume
/// the cap monitor signals on a SUSPEND-action breach. The lib-side abstraction of the
/// boundary `SuspendSignaler.Suspend(ctx, sess, BreachInfo)`: a call HOLDS the
/// breaching request mid-action and returns ONLY when the orchestrator approves
/// (resumes) — the held request then proceeds upstream and completes with a normal
/// `200` (the resume is invisible to the agent).
///
/// The signal MUST be issued BEFORE any of the breaching request's bytes go upstream
/// (the suspend-on-breach contract); the caller (`main.rs`) drives that ordering. This
/// is a frozen seam (doc 12 §13.1, the orchestrator-coordination lane the D46
/// pause/resume marker also rides); the live binding to the host-agent pause/resume
/// channel is the deferred `main.rs` unit, and the unit suite drives a fake gate.
///
/// `suspend` returns `Result<(), SuspendError>`: an `Ok` means the orchestrator
/// approved and the held request may proceed upstream; an `Err` means the hold could
/// not be established (the orchestrator channel is unreachable) — fail-closed, the
/// request is refused (never silently forwarded past an un-held suspend cap).
pub trait SuspendGate {
    /// Hold the breaching request for `session` mid-action, returning when the
    /// orchestrator approves (resume). `Err` ⇒ the hold could not be established
    /// (fail-closed; the caller refuses the request).
    fn suspend(&self, session: &SessionRef, breach: &BreachInfo) -> Result<(), SuspendError>;
}

/// A failure to establish the suspend hold (the orchestrator pause/resume channel is
/// unreachable). A suspend cap that cannot be held fails CLOSED — the breaching request
/// is refused, never silently forwarded (doc 12 §13.5 fail-closed posture).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuspendError {
    /// A secret-free reason CODE for the hold failure (the §10 class — never a payload
    /// byte). E.g. `orchestrator-unreachable`.
    pub reason: String,
}

impl SuspendError {
    /// Build a suspend error with a secret-free `reason` code.
    pub fn new(reason: impl Into<String>) -> SuspendError {
        SuspendError {
            reason: reason.into(),
        }
    }
}

/// The outcome of enforcing a breach over the [`SuspendGate`] (the verdict the caller
/// applies to the breaching request). Composed by [`enforce_breach`] so the
/// suspend-before-upstream + resume-to-200 ordering is unit-testable with no socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreachOutcome {
    /// The action did not breach (or no cap matched): forward upstream normally.
    Proceed,
    /// A BLOCK-action breach: answer the agent the in-band `403` and open NO upstream
    /// leg (D77 block+log).
    Block,
    /// A SUSPEND-action breach that was HELD and the orchestrator APPROVED: the held
    /// request now proceeds upstream and completes with a normal `200` (the resume is
    /// invisible to the agent). The suspend signal happened-before any upstream byte.
    SuspendedThenResumed,
    /// A SUSPEND-action breach whose hold could NOT be established (the orchestrator
    /// channel was unreachable): fail-closed — the request is refused, never forwarded
    /// past an un-held suspend cap. Carries the secret-free failure reason.
    SuspendFailed(SuspendError),
}

impl BreachOutcome {
    /// Whether the breaching request is allowed to proceed upstream under this outcome.
    /// True for [`BreachOutcome::Proceed`] (no breach) and
    /// [`BreachOutcome::SuspendedThenResumed`] (held then approved); false for a block
    /// or a failed suspend (both refuse).
    pub fn proceeds_upstream(&self) -> bool {
        matches!(
            self,
            BreachOutcome::Proceed | BreachOutcome::SuspendedThenResumed
        )
    }
}

/// Enforce a cap `verdict` over the wired [`SuspendGate`] for the breaching `action`,
/// returning the [`BreachOutcome`] the caller applies (doc 09 §5 TLS-6; doc 06 §3
/// suspend row). This composes the suspend-on-breach ordering so it is unit-testable
/// with no live socket — `main.rs` calls it on the inspected path's request phase
/// BEFORE opening the upstream leg, so the suspend signal provably happens-before any
/// upstream byte:
///
/// - not breached: [`BreachOutcome::Proceed`] — the action forwards upstream normally.
/// - BLOCK breach: [`BreachOutcome::Block`] — the agent gets the `403`, no upstream leg
///   opens (D77).
/// - SUSPEND breach: the [`BreachEvent`]-worthy breach is signalled to the `gate` FIRST
///   (the hold is established before any upstream byte); when the gate returns `Ok` (the
///   orchestrator approved) the held request proceeds — [`BreachOutcome::SuspendedThenResumed`]
///   — and completes with a normal `200`. A gate `Err` is fail-closed —
///   [`BreachOutcome::SuspendFailed`] — the request is refused (never forwarded past an
///   un-held suspend cap).
///
/// The caller is responsible for emitting the [`BreachEvent`] on every breach (block or
/// suspend) — [`enforce_breach`] decides the upstream/refuse verdict; the breach event
/// is a separate, always-on emission (the boundary asserts `requireEvent(EventBreach,
/// capID)` fires on the breach regardless of the action taken).
pub fn enforce_breach<G: SuspendGate + ?Sized>(
    gate: &G,
    session: &SessionRef,
    verdict: &CapVerdict,
    action: &ResourceAction,
) -> BreachOutcome {
    if !verdict.breached {
        return BreachOutcome::Proceed;
    }
    match verdict.action {
        CapAction::Block => BreachOutcome::Block,
        CapAction::Suspend => {
            // Build the breach payload and signal the gate BEFORE the caller opens the
            // upstream leg — the suspend-before-upstream invariant. The gate blocks
            // until the orchestrator approves (resume); on approval the held request
            // proceeds upstream and completes 200, on failure we fail closed.
            let Some(breach) = BreachInfo::for_breach(verdict, action) else {
                // Unreachable in practice (a breach always carries provenance), but
                // never forward un-held on a malformed verdict: fail closed.
                return BreachOutcome::SuspendFailed(SuspendError::new("breach-info-incomplete"));
            };
            match gate.suspend(session, &breach) {
                Ok(()) => BreachOutcome::SuspendedThenResumed,
                Err(e) => BreachOutcome::SuspendFailed(e),
            }
        }
    }
}

/// A LOG-1 cap-breach record the caller emits when [`CapMonitor::record`] breaches
/// (doc 09 §5 TLS-6; the boundary's `requireEvent(EventBreach, capID)` + full-provenance
/// assertion). The proxy-observed counterpart to [`crate::telemetry_http::HttpEvent`]
/// for the cap path. Emitted on EVERY breach (block or suspend), regardless of the
/// verdict taken.
///
/// Never-log-the-secret (D73): the only fields are the tap name (LOG-2 attribution
/// key), the cap id, the breaching action's method/host/path (request METADATA), and
/// the POL-3 provenance triple — all `String`. There is no header value, no body, no
/// credential byte; the boundary's leak canary cannot find a payload byte here because
/// the shape carries none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreachEvent {
    /// The never-recycled session join key — the `dstap-<idx>` tap name (LOG-2
    /// attribution key, doc 14 §4).
    pub tap_name: String,
    /// The breached cap id.
    pub cap_id: String,
    /// The method of the breaching action (request metadata).
    pub method: String,
    /// The host of the breaching action (request metadata).
    pub host: String,
    /// The path of the breaching action (request metadata).
    pub path: String,
    /// The mandatory POL-3 provenance triple (rule 4) — the cap id / `session` /
    /// the policy version.
    pub provenance: crate::telemetry_http::Provenance,
}

impl BreachEvent {
    /// Build a cap-breach event from a breached [`CapVerdict`], the `session` it
    /// breached on (for the LOG-2 tap name), and the breaching `action`. Returns `None`
    /// if `verdict` is not a breach (a non-breach never produces a breach event) — so
    /// the caller can unconditionally feed every verdict and only emit when one is
    /// `Some`.
    ///
    /// The provenance is migrated off the verdict's [`CapProvenance`] (the cap id +
    /// `session` layer + policy version), so the emitted event carries the SAME
    /// provenance the verdict decided — single-sourced.
    pub fn for_breach(
        session: &SessionRef,
        verdict: &CapVerdict,
        action: &ResourceAction,
    ) -> Option<BreachEvent> {
        if !verdict.breached {
            return None;
        }
        let provenance = verdict.provenance.as_ref()?;
        Some(BreachEvent {
            tap_name: session.tap_name.clone(),
            cap_id: verdict.cap_id.clone(),
            method: action.method.clone(),
            host: action.host.clone(),
            path: action.path.clone(),
            provenance: provenance.to_telemetry(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const V: &str = "policy-v1";

    fn sess(uuid: &str, idx: u32, tap: &str) -> SessionRef {
        SessionRef::new(uuid.to_string(), "host-a".to_string(), idx, tap.to_string())
    }

    fn sess_a() -> SessionRef {
        sess("aaaa-0000-0000-0000-000000000001", 1, "dstap-1")
    }
    fn sess_b() -> SessionRef {
        sess("bbbb-0000-0000-0000-000000000002", 2, "dstap-2")
    }

    const HOST: &str = "api.github.com";
    const CAP_ID: &str = "cap:delete-5-per-hour";

    /// A DELETE on a critical path — the boundary suspend test's breaching action shape.
    fn delete(path_n: u32) -> ResourceAction {
        ResourceAction::new("DELETE", HOST, format!("/repos/critical/branch-{path_n}"))
    }

    /// A DELETE-counting cap with the given limit + action (the boundary fake's match:
    /// `a.Method == DELETE`).
    fn delete_cap(limit: u32, action: CapAction) -> CapConfig<MethodMatcher> {
        CapConfig {
            id: CAP_ID.to_string(),
            limit,
            matcher: MethodMatcher::new("DELETE"),
            action,
        }
    }

    // ── the boundary suspend test, modelled over the lib core ────────────────────

    /// `TestCap_BreachSuspendsMidAction_BreachingRequestHeld`: actions 1-5 are
    /// unaffected; action 6 trips the cap, fires a breach (with cap id + full
    /// provenance), and signals the suspend gate BEFORE any upstream byte.
    #[test]
    fn breach_suspends_mid_action_breaching_request_held() {
        const N: u32 = 5;
        let mut mon = CapMonitor::single(delete_cap(N, CapAction::Suspend), V);

        // Requests 1-5: unaffected (within the ceiling).
        for i in 1..=N {
            let v = mon.record(&sess_a(), &delete(i));
            assert!(!v.breached, "DELETE #{i} must be unaffected");
            assert_eq!(v.cap_id, CAP_ID);
            assert_eq!(v.block_status(), None);
            assert!(!v.must_suspend());
            // A within-limit verdict still carries provenance (every matched verdict).
            let p = v
                .provenance
                .as_ref()
                .expect("matched verdict carries provenance");
            assert_eq!(p.rule_id, CAP_ID);
            assert_eq!(p.policy_layer, "session");
            assert_eq!(p.policy_version, V);
        }

        // Request 6 trips the cap.
        let action6 = delete(6);
        let v6 = mon.record(&sess_a(), &action6);
        assert!(v6.breached, "DELETE #6 must breach the cap");
        assert_eq!(v6.cap_id, CAP_ID);
        assert!(v6.must_suspend(), "a suspend cap holds, not 403s");
        assert_eq!(
            v6.block_status(),
            None,
            "a suspend breach is held, not blocked"
        );

        // The breach fires a Breach event carrying the cap id + full POL-3 provenance.
        let ev = BreachEvent::for_breach(&sess_a(), &v6, &action6).expect("breach event");
        assert_eq!(ev.cap_id, CAP_ID);
        assert_eq!(ev.tap_name, "dstap-1");
        assert_eq!(ev.method, "DELETE");
        assert_eq!(ev.host, HOST);
        assert_eq!(ev.provenance.rule_id, CAP_ID);
        assert_eq!(ev.provenance.policy_layer, "session");
        assert_eq!(ev.provenance.policy_version, V);

        // The suspend signal fires BEFORE any upstream byte: an order-recording gate
        // notes "suspend"; the caller would open the upstream leg only AFTER
        // enforce_breach returns. We prove the gate is signalled exactly once with the
        // breach payload, and the outcome lets the (held, approved) request proceed.
        let gate = OrderingGate::approving();
        let outcome = enforce_breach(&gate, &sess_a(), &v6, &action6);
        assert_eq!(outcome, BreachOutcome::SuspendedThenResumed);
        let calls = gate.calls();
        assert_eq!(calls.len(), 1, "suspend signalled exactly once");
        assert_eq!(calls[0].cap_id, CAP_ID);
        assert_eq!(calls[0].action, action6);
        assert_eq!(calls[0].provenance.rule_id, CAP_ID);
        // The recorded order proves the suspend note preceded the (post-return) upstream
        // step the caller would take.
        let order = gate.order();
        assert_eq!(order, vec!["suspend".to_string()]);
    }

    /// `TestCap_ResumeInvisibleToAgent`: with limit 0 every matching action breaches
    /// immediately; the held request, once the gate approves (resumes), completes with a
    /// normal 200 (modelled as `proceeds_upstream`) — no 5xx / reset / retry.
    #[test]
    fn resume_invisible_to_agent_held_request_completes_200() {
        // limit 0 ⇒ the first matching action breaches immediately.
        let mut mon = CapMonitor::single(delete_cap(0, CapAction::Suspend), V);
        let action = delete(0);
        let v = mon.record(&sess_a(), &action);
        assert!(v.breached, "limit 0: the first matching action breaches");
        assert!(v.must_suspend());

        // The gate approves (the orchestrator resumes): the held request proceeds and
        // completes with a normal 200 — proceeds_upstream is the lib-side proxy for
        // "the held request completed with one normal response".
        let gate = OrderingGate::approving();
        let outcome = enforce_breach(&gate, &sess_a(), &v, &action);
        assert_eq!(outcome, BreachOutcome::SuspendedThenResumed);
        assert!(
            outcome.proceeds_upstream(),
            "after resume the held request proceeds upstream (200, not 5xx/reset/retry)"
        );
        // The suspend was signalled (the request WAS held before completing).
        assert_eq!(gate.calls().len(), 1);
    }

    /// A suspend hold that cannot be established (the orchestrator channel is
    /// unreachable) fails CLOSED — the request is refused, NEVER forwarded past an
    /// un-held suspend cap.
    #[test]
    fn suspend_hold_failure_is_fail_closed() {
        let mut mon = CapMonitor::single(delete_cap(0, CapAction::Suspend), V);
        let action = delete(0);
        let v = mon.record(&sess_a(), &action);
        assert!(v.breached);

        let gate = OrderingGate::failing("orchestrator-unreachable");
        let outcome = enforce_breach(&gate, &sess_a(), &v, &action);
        assert!(
            !outcome.proceeds_upstream(),
            "a failed suspend hold must NOT forward upstream (fail-closed)"
        );
        match outcome {
            BreachOutcome::SuspendFailed(e) => assert_eq!(e.reason, "orchestrator-unreachable"),
            other => panic!("expected SuspendFailed, got {other:?}"),
        }
    }

    // ── the default action is block+log (D77) ────────────────────────────────────

    /// A cap whose action is the default [`CapAction::Block`] returns a 403 on breach
    /// (D77 block+log) and never reaches the suspend gate.
    #[test]
    fn default_action_block_returns_403_and_never_suspends() {
        // CapConfig::block is the D77 default-action constructor.
        let mut mon =
            CapMonitor::single(CapConfig::block(CAP_ID, 2, MethodMatcher::new("DELETE")), V);
        assert!(!mon.record(&sess_a(), &delete(1)).breached); // 1
        assert!(!mon.record(&sess_a(), &delete(2)).breached); // 2
        let action3 = delete(3);
        let v3 = mon.record(&sess_a(), &action3); // 3 -> breach
        assert!(v3.breached);
        assert_eq!(
            v3.block_status(),
            Some(403),
            "block breach answers 403 (D77)"
        );
        assert!(!v3.must_suspend(), "a block cap never suspends");

        // enforce_breach on a block verdict refuses (no upstream leg) and never touches
        // the gate.
        let gate = OrderingGate::approving();
        let outcome = enforce_breach(&gate, &sess_a(), &v3, &action3);
        assert_eq!(outcome, BreachOutcome::Block);
        assert!(
            !outcome.proceeds_upstream(),
            "a block breach does not forward"
        );
        assert_eq!(
            gate.calls().len(),
            0,
            "block never signals the suspend gate"
        );
    }

    /// The default [`CapAction`] is `Block` — a `CapConfig::block` and a bare default
    /// both carry it (the D77 safe verdict).
    #[test]
    fn cap_action_default_is_block() {
        assert_eq!(CapAction::default(), CapAction::Block);
        assert!(!CapAction::Block.holds());
        assert!(CapAction::Suspend.holds());
    }

    // ── action 1..N unaffected, N+1 trips (the counting boundary) ────────────────

    /// Exactly N matching actions unaffected, then every subsequent one breaches (the
    /// count keeps climbing, so once breached it stays breached until flush).
    #[test]
    fn n_unaffected_then_all_breach() {
        let mut mon = CapMonitor::single(delete_cap(3, CapAction::Block), V);
        assert!(!mon.record(&sess_a(), &delete(1)).breached); // 1
        assert!(!mon.record(&sess_a(), &delete(2)).breached); // 2
        assert!(!mon.record(&sess_a(), &delete(3)).breached); // 3
        assert!(mon.record(&sess_a(), &delete(4)).breached); // 4 -> breach
        assert!(mon.record(&sess_a(), &delete(5)).breached); // 5 -> still breached
        assert_eq!(mon.count(&sess_a(), CAP_ID), 5);
    }

    /// A non-matching action (a GET when the cap counts DELETEs) is never counted and
    /// returns the no-cap verdict — it proceeds untouched.
    #[test]
    fn non_matching_action_is_uncounted_and_proceeds() {
        let mut mon = CapMonitor::single(delete_cap(0, CapAction::Suspend), V);
        // A GET — the cap counts only DELETEs, so this matches no cap.
        let get = ResourceAction::new("GET", HOST, "/repos/critical/info");
        let v = mon.record(&sess_a(), &get);
        assert!(!v.breached);
        assert_eq!(v.cap_id, "", "no cap matched");
        assert!(v.provenance.is_none(), "no cap decision, no provenance");
        assert_eq!(v.block_status(), None);
        assert!(!v.must_suspend());
        assert_eq!(
            mon.counter_count(),
            0,
            "an unmatched action creates no counter"
        );
        // enforce_breach on a non-breach proceeds.
        let gate = OrderingGate::approving();
        assert_eq!(
            enforce_breach(&gate, &sess_a(), &v, &get),
            BreachOutcome::Proceed
        );
    }

    // ── counter isolation ────────────────────────────────────────────────────────

    /// Two sessions' counts on the same cap are independent: breaching A's cap leaves
    /// B's untouched (the counter key is the whole `(session, cap)` tuple).
    #[test]
    fn counters_isolate_across_sessions() {
        let mut mon = CapMonitor::single(delete_cap(1, CapAction::Block), V);
        // Breach A only.
        assert!(!mon.record(&sess_a(), &delete(1)).breached);
        assert!(mon.record(&sess_a(), &delete(2)).breached);
        // B is still on its first action -> unaffected.
        assert!(
            !mon.record(&sess_b(), &delete(1)).breached,
            "B's cap isolated from A's"
        );
    }

    /// Two caps on the same session are independent counters (a request matched by the
    /// FIRST cap is counted only there — deny-first).
    #[test]
    fn first_matching_cap_decides_and_counters_are_per_cap() {
        // Two caps: a DELETE cap (limit 1) and a broad "any method" cap (limit 100).
        // A DELETE matches the FIRST (delete) cap and is counted there only. Both caps
        // share the non-generic `PredicateMatcher` so a single CapMonitor holds them.
        let delete_first = CapConfig::block("cap:delete", 1, PredicateMatcher::method("DELETE"));
        let any = CapConfig::block("cap:any", 100, PredicateMatcher::Any);
        let mut mon = CapMonitor::new(vec![delete_first, any], V);

        let v1 = mon.record(&sess_a(), &delete(1));
        assert_eq!(v1.cap_id, "cap:delete", "the first matching cap decides");
        assert!(!v1.breached);
        let v2 = mon.record(&sess_a(), &delete(2));
        assert!(v2.breached, "the delete cap (limit 1) breaches on the 2nd");
        // The broad cap counted nothing (the delete cap matched first).
        assert_eq!(mon.count(&sess_a(), "cap:any"), 0);
        assert_eq!(mon.count(&sess_a(), "cap:delete"), 2);

        // A non-DELETE falls through to the broad cap and is counted there.
        let get = ResourceAction::new("GET", HOST, "/x");
        let vg = mon.record(&sess_a(), &get);
        assert_eq!(vg.cap_id, "cap:any");
        assert_eq!(mon.count(&sess_a(), "cap:any"), 1);
    }

    /// Two sessions whose host-local index residues could collide still get distinct
    /// counters, because the key is the never-recycled tap name (doc 14 §4), not the
    /// index.
    #[test]
    fn counters_key_on_tap_name_not_index() {
        let s1 = sess("uuid-1", 1, "dstap-1");
        let s2 = sess("uuid-2", 1, "dstap-9"); // same index, different tap
        let mut mon = CapMonitor::single(delete_cap(1, CapAction::Block), V);
        assert!(!mon.record(&s1, &delete(1)).breached);
        assert!(mon.record(&s1, &delete(2)).breached); // s1 breached
        assert!(
            !mon.record(&s2, &delete(1)).breached,
            "s2 is a distinct counter from s1"
        );
    }

    // ── NFT-6 teardown hygiene ───────────────────────────────────────────────────

    /// Flushing a session at teardown drops only ITS counters; a re-bound session on the
    /// same tap name starts fresh, and other sessions are untouched.
    #[test]
    fn flush_session_clears_only_that_sessions_counters() {
        let cap_a = CapConfig::block("cap:x", 1, MethodMatcher::new("DELETE"));
        let cap_b = CapConfig::block("cap:y", 1, MethodMatcher::new("POST"));
        let mut mon = CapMonitor::new(vec![cap_a, cap_b], V);

        // A breaches both caps; B breaches cap:x.
        mon.record(&sess_a(), &delete(1));
        mon.record(&sess_a(), &ResourceAction::new("POST", HOST, "/p"));
        mon.record(&sess_b(), &delete(1));
        assert_eq!(mon.counter_count(), 3);

        // Teardown A: both of A's counters drop, B's stays.
        let dropped = mon.flush_session(&sess_a());
        assert_eq!(dropped, 2, "A had two counters");
        assert_eq!(mon.counter_count(), 1);
        assert_eq!(
            mon.count(&sess_a(), "cap:x"),
            0,
            "A's cap:x counter is gone"
        );
        assert_eq!(
            mon.count(&sess_b(), "cap:x"),
            1,
            "B's cap:x counter survives"
        );

        // A re-bound on the same tap name starts fresh (no residue).
        assert!(
            !mon.record(&sess_a(), &delete(1)).breached,
            "re-bound A starts fresh"
        );
    }

    /// Flushing a session with no counters (e.g. it only ever hit non-matching actions)
    /// is a no-op that drops nothing.
    #[test]
    fn flush_session_with_no_counters_is_a_noop() {
        let mut mon = CapMonitor::single(delete_cap(1, CapAction::Block), V);
        mon.record(&sess_a(), &ResourceAction::new("GET", HOST, "/x")); // no match -> no counter
        assert_eq!(mon.flush_session(&sess_a()), 0);
    }

    // ── provenance + projection ──────────────────────────────────────────────────

    /// Both within-limit and breach verdicts carry the mandatory POL-3 provenance triple
    /// (rule 4) on a matched action.
    #[test]
    fn every_matched_verdict_carries_provenance() {
        let mut mon = CapMonitor::single(delete_cap(1, CapAction::Block), V);
        let within = mon.record(&sess_a(), &delete(1));
        let p = within.provenance.as_ref().unwrap();
        assert_eq!(p.rule_id, CAP_ID);
        assert_eq!(p.policy_layer, "session");
        assert_eq!(p.policy_version, V);
        let breach = mon.record(&sess_a(), &delete(2));
        let p = breach.provenance.as_ref().unwrap();
        assert_eq!(p.rule_id, CAP_ID);
        assert_eq!(p.policy_layer, "session");
        assert_eq!(p.policy_version, V);
    }

    /// The cap provenance projects losslessly onto the telemetry_http::Provenance the
    /// LOG-1 breach event carries.
    #[test]
    fn provenance_projects_onto_telemetry() {
        let p = CapProvenance::for_cap(CAP_ID, V);
        let t = p.to_telemetry();
        assert_eq!(t.rule_id, CAP_ID);
        assert_eq!(t.policy_layer, "session");
        assert_eq!(t.policy_version, V);
    }

    // ── the breach event + breach info ───────────────────────────────────────────

    /// A non-breach verdict produces NO breach event / breach info; a breach produces
    /// both, carrying the cap id, the breaching action, and the migrated provenance.
    #[test]
    fn breach_event_and_info_only_on_breach() {
        let mut mon = CapMonitor::single(delete_cap(1, CapAction::Suspend), V);
        let action1 = delete(1);
        let within = mon.record(&sess_a(), &action1);
        assert!(BreachEvent::for_breach(&sess_a(), &within, &action1).is_none());
        assert!(BreachInfo::for_breach(&within, &action1).is_none());

        let action2 = delete(2);
        let breach = mon.record(&sess_a(), &action2);
        let ev = BreachEvent::for_breach(&sess_a(), &breach, &action2).expect("breach event");
        assert_eq!(ev.tap_name, "dstap-1");
        assert_eq!(ev.cap_id, CAP_ID);
        assert_eq!(ev.path, "/repos/critical/branch-2");
        assert_eq!(ev.provenance.rule_id, CAP_ID);

        let info = BreachInfo::for_breach(&breach, &action2).expect("breach info");
        assert_eq!(info.cap_id, CAP_ID);
        assert_eq!(info.action, action2);
        assert_eq!(info.provenance.rule_id, CAP_ID);
    }

    // ── never-log-the-secret: the event shape carries no payload field ───────────

    /// The BreachEvent shape carries only metadata + provenance — there is no body /
    /// header-value field. We assert structurally by populating every field with a
    /// sentinel and confirming the only strings present are the metadata we put there.
    #[test]
    fn breach_event_carries_no_payload_field() {
        let mut mon = CapMonitor::single(delete_cap(0, CapAction::Block), V);
        let action = ResourceAction::new("DELETE", HOST, "/repos/critical/secret-path");
        let v = mon.record(&sess_a(), &action);
        let ev = BreachEvent::for_breach(&sess_a(), &v, &action).expect("breach event");
        // The event's fields are exactly: tap, cap id, method, host, path, provenance —
        // all metadata. A debug render contains none of a hypothetical body sentinel
        // because the shape has nowhere to hold one.
        let rendered = format!("{ev:?}");
        assert!(rendered.contains("DELETE"));
        assert!(rendered.contains(HOST));
        assert!(
            !rendered.contains("BODY-SENTINEL"),
            "no body field exists to leak into"
        );
    }

    // ── an order-recording / approving / failing SuspendGate fake ────────────────

    /// A [`SuspendGate`] fake that records each call (cap id + action + provenance) and
    /// notes "suspend" into an order log, then either approves (`Ok`) or fails (`Err`).
    /// Models the boundary `fakeSuspendSignaler`: the held request proceeds on approve,
    /// is refused on fail.
    struct OrderingGate {
        calls: RefCell<Vec<BreachInfo>>,
        order: RefCell<Vec<String>>,
        result: Result<(), SuspendError>,
    }

    impl OrderingGate {
        fn approving() -> OrderingGate {
            OrderingGate {
                calls: RefCell::new(Vec::new()),
                order: RefCell::new(Vec::new()),
                result: Ok(()),
            }
        }
        fn failing(reason: &str) -> OrderingGate {
            OrderingGate {
                calls: RefCell::new(Vec::new()),
                order: RefCell::new(Vec::new()),
                result: Err(SuspendError::new(reason)),
            }
        }
        fn calls(&self) -> Vec<BreachInfo> {
            self.calls.borrow().clone()
        }
        fn order(&self) -> Vec<String> {
            self.order.borrow().clone()
        }
    }

    impl SuspendGate for OrderingGate {
        fn suspend(&self, _session: &SessionRef, breach: &BreachInfo) -> Result<(), SuspendError> {
            self.calls.borrow_mut().push(breach.clone());
            self.order.borrow_mut().push("suspend".to_string());
            self.result.clone()
        }
    }
}
