//! The admission/policy seam — the frozen `evaluate(DnsQueryCtx) -> DnsVerdict`
//! interface (doc 11 §4, D67/D68/D71/D72).
//!
//! This module is the consumer skin ds-dnsgate puts on the ONE shared evaluator
//! ([`policy_core`]). Doc 11 §4 freezes the verdict family in `policy-core` itself
//! ([`policy_core::dns_gate`]): `evaluate(ComposedPolicy, DnsQueryCtx, Admit) ->
//! DnsVerdict ∈ {Allow{admit, ttl_clamp}, Deny{rcode_policy}, Ask{prompt_ref}}`, every
//! verdict carrying POL-3 provenance (rule id, layer, policy version). That frozen shape
//! now lives ONCE, in `policy-core`; this module no longer keeps a parallel copy.
//!
//! The gate binds the frozen verdict directly: [`PolicyHook::evaluate`] returns
//! [`policy_core::dns_gate::DnsVerdict`] (re-exported here as [`Verdict`]), so the
//! handler ([`crate::handler`]) authors each §3.2 arm — Deny → NXDOMAIN+SOA+EDE-15,
//! Ask → REFUSED, Allow{admit, ttl_clamp} — by reading the FROZEN fields. There is no
//! second verdict type to keep in lockstep: a future `ttl_clamp` window change or a D53
//! rung change lands in ONE place ([`policy_core::dns_gate`]).
//!
//! HARD CONTRACT (D67): this module is **hickory-free**. No `hickory_*` type appears in
//! any item below, and the frozen `policy-core` verdict family it re-exports is itself
//! hickory-free (`std`/`String` types only), so the seam stays a legal cross-service
//! shape and the documented raw-tokio fallback (doc 11 §2) stays a pure library
//! migration. The [`PolicyHook`] trait is what the handler depends on — never a
//! `policy-core` type directly at the *trait* boundary — so swapping the evaluator impl
//! never touches the listener shell (doc 11 §1: "a forwarder with a policy brain").
//!
//! No rule is reimplemented here (POL-3, doc 13 §1.1): [`PolicyCorePolicy`] routes the
//! query through `policy-core`'s frozen DNS-gate verdict surface
//! ([`policy_core::dns_gate::evaluate`], itself the one
//! [`policy_core::consumer::dns_admission_decision`] engine ds-tlsproxy and the NFT
//! programming path embed) — so the three boundary consumers can never disagree.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use policy_core::dns_gate::{self, Admit as CoreAdmit};
use policy_core::pol1_eval::ComposedPolicy;

// ── The frozen cross-service verdict seam, re-exported under this module's names ──────
//
// The verdict family is frozen ONCE, in `policy-core` (doc 11 §4 / doc 14 §6). The gate
// binds it directly; these re-exports keep the historical `crate::policy::{Verdict, ...}`
// names resolvable (lib.rs re-exports them, and the seam tests bind them) while there is
// exactly ONE underlying type per name — no service-internal duplicate to drift.

/// The frozen admission verdict (doc 11 §4): `Allow{admit, ttl_clamp}` |
/// `Deny{rcode_policy}` | `Ask{prompt_ref}`, every arm carrying POL-3 provenance.
///
/// This IS [`policy_core::dns_gate::DnsVerdict`] — the ONE frozen verdict type the gate's
/// hot path binds. The handler maps each arm to its frozen wire shape (Allow →
/// forward+scrub+answer; Deny → NXDOMAIN+SOA; Ask → REFUSED + ask-user seam).
pub use policy_core::dns_gate::DnsVerdict as Verdict;

/// How a `Deny` verdict maps to a wire rcode (doc 11 §3.2 / §4: `Deny{rcode_policy}`).
/// This IS [`policy_core::dns_gate::RcodePolicy`] (NXDOMAIN; SERVFAIL is never a verdict).
pub use policy_core::dns_gate::RcodePolicy;

/// The admission payload a frozen `Allow` verdict carries (doc 11 §4: `Allow{admit}`).
/// This IS [`policy_core::dns_gate::Admit`] — it carries the W2 TTL clamp window
/// (`ttl_floor`/`ttl_ceil`) the gate clamps the answer TTL into.
pub use policy_core::dns_gate::Admit;

/// The Ask-path prompt reference (doc 11 §4: `Ask{prompt_ref}`; §3.2/§5.5). This IS
/// [`policy_core::dns_gate::PromptRef`] — the session-scoped reference the §5.5
/// `AskUserRequest` emission keys on.
pub use policy_core::dns_gate::PromptRef;

/// POL-3 provenance on a verdict (doc 11 §4 / §5.5: rule id, layer, policy version on
/// EVERY verdict — missing provenance fails CI, §6.7). This IS
/// [`policy_core::pol1_eval::Provenance`], the family-agnostic triple `policy-core`
/// stamps; carried by value on every [`Verdict`] arm so the "provenance on every path"
/// invariant is structural. Re-exported as `SeamProvenance` for the names lib.rs / the
/// handler bridge already bind.
pub use policy_core::pol1_eval::Provenance as SeamProvenance;

/// The harness allow-all provenance the always-`Allow` [`FixedStubPolicy`] attaches.
///
/// That policy is NOT a real evaluator — it admits every name so the framework /
/// forwarder / suppression harnesses can drive arbitrary synthetic names no shipped pack
/// lists (a pack-backed evaluator would `Ask`/REFUSE them). So its provenance names the
/// harness rule explicitly (`harness/allow-all`) rather than a fixed "stub" marker: it
/// keeps the §6.7 "every verdict carries provenance" invariant true structurally, and a
/// downstream join reads an honest "this was the allow-all harness, not a pack rule". The
/// REAL pack rule id / layer / version ride [`PolicyCorePolicy`]'s verdict straight off
/// the frozen [`policy_core::dns_gate::evaluate`] (the production evaluator).
fn harness_default_provenance() -> SeamProvenance {
    SeamProvenance {
        rule_id: "harness/allow-all".to_string(),
        policy_layer: "harness".to_string(),
        policy_version: "allow-all".to_string(),
    }
}

/// A hickory-free query context handed to the policy seam (doc 11 §4: the frozen
/// `DnsQueryCtx{session, qname, qtype, source}`).
///
/// This is a THIN gate-facing input adapter over the frozen
/// [`policy_core::dns_gate::DnsQueryCtx`]: it carries the same `session`/`qname`/`qtype`
/// quad, plus the query `source` as a plain [`std::net::SocketAddr`] (the per-session
/// tap's local address — the §5.1 attribution input the handler holds as a wire socket
/// address). The seam projects it into the frozen ctx (rendering `source` as the
/// frozen shape's string descriptor) at the single [`policy_core::dns_gate::evaluate`]
/// call below, so the verdict TYPE the gate binds is the frozen one — this adapter only
/// shapes the evaluator INPUT, it carries no verdict logic to drift. Plain `std`/`String`
/// types only — never a hickory `LowerQuery`, `Name`, or `RecordType` (D67).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQueryCtx {
    /// The attributed session identity (doc 11 §5.1: interface-anchored, never raw
    /// source IP alone). A `String` token — the orchestrator session-record join key.
    /// At the pre-stage the handler threads a fixed token; real attribution (D44/D66)
    /// is a separate seam. Kept on the ctx from day one so the frozen shape is intact.
    pub session: String,
    /// The queried name, lower-cased, trailing-dot form (e.g. `"example.test."`).
    pub qname: String,
    /// The queried record type as its IANA numeric code (1 = A, 28 = AAAA, ...).
    /// A `u16`, never a hickory `RecordType`, keeps this surface engine-agnostic.
    pub qtype: u16,
    /// The query source (doc 11 §4: `source`). A plain `std::net::SocketAddr` — the
    /// per-session tap's local address is the authoritative attribution input (§5.1),
    /// carried here for the evaluator and the §5.5 event without binding a wire type.
    pub source: SocketAddr,
}

impl DnsQueryCtx {
    /// Project this gate-facing ctx into the frozen [`policy_core::dns_gate::DnsQueryCtx`]
    /// the evaluator consumes — the single point where the adapter meets the frozen seam.
    /// The frozen ctx renders `source` as its string descriptor (it never keys on the
    /// raw address — `session` is the §5.1 join key); `session`/`qname`/`qtype` carry
    /// through verbatim.
    fn to_core(&self) -> dns_gate::DnsQueryCtx {
        dns_gate::DnsQueryCtx {
            session: self.session.clone(),
            qname: self.qname.clone(),
            qtype: self.qtype,
            source: self.source.to_string(),
        }
    }
}

/// The W2 admission TTL clamp window in seconds (doc 11 §4 / W2, D68): the answer TTL
/// the VM sees is `clamp(chain_min_ttl, floor, ceil)`. A hickory-free second pair; the
/// POL-1 schema fills the real values (defaults pinned 60s/900s) — these are policy
/// VALUES, not a wire type. The clamp WINDOW is the gate's config knob; it is projected
/// onto the frozen [`Admit`]'s `ttl_floor`/`ttl_ceil` when the verdict is minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlClamp {
    /// The clamp floor in seconds (POL-1 `ttl_floor`, default 60).
    pub floor: u32,
    /// The clamp ceiling in seconds (POL-1 `ttl_ceil`, default 900).
    pub ceil: u32,
}

impl TtlClamp {
    /// The doc 11 §4 / W2 pinned default clamp window: FLOOR=60s, CEIL=900s (D42/D68).
    /// These are the POL-1 schema defaults the tests pin, not a hardcode of behavior;
    /// a policy push overrides the VALUES, never this SHAPE.
    pub const DEFAULT: TtlClamp = TtlClamp {
        floor: 60,
        ceil: 900,
    };

    /// Clamp a chain-minimum TTL into `[floor, ceil]` (doc 11 §3.1/§4, W2). The VM is
    /// answered this clamped value WITHOUT grace (the +GRACE store-side deadline is the
    /// `txn/` seam's; this is the wire TTL the handler authors onto the answer).
    pub fn clamp(&self, chain_min_ttl: u32) -> u32 {
        chain_min_ttl.clamp(self.floor, self.ceil)
    }

    /// Project the clamp window onto the frozen [`Admit`] payload an `Allow` carries
    /// (`ttl_floor`/`ttl_ceil`) — the gate config value flows into the frozen verdict.
    fn to_admit(self) -> Admit {
        CoreAdmit {
            ttl_floor: self.floor,
            ttl_ceil: self.ceil,
        }
    }
}

/// The policy seam (doc 11 §4). One method, no async, no hickory types.
///
/// The handler calls [`PolicyHook::evaluate`] once per query and authors a response
/// from the frozen [`Verdict`]. Swapping the evaluator is a matter of replacing the
/// impl, not the listener shell — the whole point of keeping the seam hickory-free.
///
/// `Unpin` is required because hickory's `RequestHandler` is `Unpin` and the handler
/// embeds the policy by value; every plain (non-self-referential) impl is.
pub trait PolicyHook: Send + Sync + Unpin + 'static {
    /// Return the frozen admission verdict for a query (doc 11 §4). Infallible by
    /// construction: a genuine evaluation failure is the handler's SERVFAIL path
    /// (§3.2), never a verdict — so the seam always yields a determinate Allow/Deny/Ask.
    fn evaluate(&self, ctx: &DnsQueryCtx) -> Verdict;
}

/// The default always-`Allow` policy: every query is admitted with the W2 default TTL
/// clamp and the harness allow-all provenance.
///
/// This is the policy the production `main` shell and the framework / forwarder /
/// suppression harnesses run with: those validate the listener, forwarder, and §3.3
/// scrub against arbitrary synthetic names that no shipped pack lists, so they need the
/// admit-everything default (a pack-backed evaluator would `Ask`/REFUSE them). The
/// REAL pack-backed admission decision is [`PolicyCorePolicy`], exercised by the seam
/// tests against the shipped POL-2 baseline. Swapping `main` onto a composed
/// [`PolicyCorePolicy`] is a later wiring step (the snapshot-subscriber seam, §5.3);
/// the verdict SHAPE is frozen in `policy-core` regardless of which impl is installed.
#[derive(Debug, Clone, Copy, Default)]
pub struct FixedStubPolicy;

impl FixedStubPolicy {
    /// Construct the default always-`Allow` policy.
    pub fn new() -> Self {
        Self
    }
}

impl PolicyHook for FixedStubPolicy {
    fn evaluate(&self, _ctx: &DnsQueryCtx) -> Verdict {
        Verdict::Allow {
            admit: TtlClamp::DEFAULT.to_admit(),
            provenance: harness_default_provenance(),
        }
    }
}

/// The pack-backed evaluator (doc 11 §4 / doc 13 §1.1, POL-3): routes the query through
/// `policy-core`'s frozen DNS-gate verdict surface
/// ([`policy_core::dns_gate::evaluate`]) and returns the frozen [`Verdict`] DIRECTLY. No
/// rule is reimplemented (POL-3) and no verdict is re-projected here — this is the SAME
/// evaluator (and now the SAME verdict type) ds-tlsproxy and the NFT programming path
/// embed, so a DNS admission, a TLS connect, and an NFT allow-set entry can never
/// disagree, by construction.
///
/// It holds the host's ONE composed policy document ([`ComposedPolicy`]) — the deny-wins
/// composition the host snapshot carries (doc 13 §1 rule 2) — and the W2 clamp window
/// that rides each `Allow`'s frozen [`Admit`]. `policy-core`'s verdict family is
/// hickory-free, so binding it costs the D67 seam nothing.
///
/// HOT-RELOADABLE (doc 11 §5.3 / D72): the composed document AND the W2 clamp window live
/// behind a shared `Arc<RwLock<…>>`, so the running evaluator can be RE-SOURCED from a
/// freshly-committed host snapshot WITHOUT re-binding the listeners — the same admitter-LAST
/// pattern the boundary-zone signature uses ([`crate::handler::BoundaryZoneReload`]). A
/// [`Clone`] is a SHARED-HANDLE clone (it shares the inner `Arc`), so `spawn_gate`'s two
/// per-transport handler clones and `main`'s reload handle all observe the SAME live policy:
/// a single [`PolicyCorePolicy::reload`] (driven by the `WatchPolicies` snapshot subscriber)
/// re-sources every transport's evaluator at once, never per-transport skew. `evaluate`
/// takes a fast read lock that is never held across an `await` (the trait method is
/// synchronous), so a reload between two queries simply changes which document the NEXT
/// query is evaluated against — admission is never minted mid-swap.
#[derive(Debug, Clone)]
pub struct PolicyCorePolicy {
    state: Arc<RwLock<PolicyCoreState>>,
}

/// The hot-reloadable evaluator state behind [`PolicyCorePolicy`]'s shared lock: the host's
/// ONE composed policy document plus the W2 clamp window. A D72 admitter-LAST reload swaps
/// BOTH together (one committed policy version → one composed document → one clamp window),
/// so the evaluator can never read a composed doc from one snapshot with a clamp from another.
#[derive(Debug, Clone)]
struct PolicyCoreState {
    composed: ComposedPolicy,
    ttl_clamp: TtlClamp,
}

impl PolicyCorePolicy {
    /// Wrap the host's composed policy document with the default W2 TTL clamp (the
    /// POL-1-pinned 60s/900s). The composed document is produced by `policy-core`'s
    /// `compose` over the parsed POL-2 baseline (the embedder builds it from the host
    /// snapshot; the seam tests build it from the shipped pack).
    pub fn new(composed: ComposedPolicy) -> Self {
        Self::with_ttl_clamp(composed, TtlClamp::DEFAULT)
    }

    /// Wrap the composed document with an explicit W2 TTL clamp window — the seam a
    /// policy push uses to override the POL-1 defaults (doc 11 §4: the clamp is a
    /// policy VALUE, not a code constant).
    pub fn with_ttl_clamp(composed: ComposedPolicy, ttl_clamp: TtlClamp) -> Self {
        Self {
            state: Arc::new(RwLock::new(PolicyCoreState {
                composed,
                ttl_clamp,
            })),
        }
    }

    /// Re-source the running evaluator from a freshly-committed host snapshot — the doc 11
    /// §5.3 admitter-LAST D72 evaluator hot-reload (the policy-document twin of
    /// [`crate::handler::BoundaryZoneReload::reload`]). Swaps BOTH the composed document and
    /// the W2 clamp window under the write lock in one step, so every subsequent query is
    /// evaluated against the new policy version — admitter-LAST, with no listener re-bind and
    /// no per-transport skew (all shared-handle clones read the one inner state). The
    /// `WatchPolicies` snapshot subscriber drives this on every committed snapshot that
    /// carries a composed policy ([`crate::server::watch_snapshots`]).
    pub fn reload(&self, composed: ComposedPolicy, ttl_clamp: TtlClamp) {
        let mut state = self.state.write().expect("policy evaluator lock poisoned");
        state.composed = composed;
        state.ttl_clamp = ttl_clamp;
    }

    /// The composed policy version the evaluator CURRENTLY decides against — the live value
    /// after the most recent [`reload`](Self::reload) (or the startup composed document if
    /// none yet). Reads the shared state, so it reflects the admitter's last commit; the
    /// snapshot-subscriber tests assert the evaluator re-sourced through this read.
    pub fn current_policy_version(&self) -> String {
        self.state
            .read()
            .expect("policy evaluator lock poisoned")
            .composed
            .policy_version
            .clone()
    }

    /// The W2 TTL clamp window the evaluator CURRENTLY mints each `Allow`'s [`Admit`] with —
    /// the live value after the most recent [`reload`](Self::reload). Reads the shared state;
    /// the snapshot-subscriber tests assert the clamp re-sourced through this read.
    pub fn current_ttl_clamp(&self) -> TtlClamp {
        self.state
            .read()
            .expect("policy evaluator lock poisoned")
            .ttl_clamp
    }
}

impl PolicyHook for PolicyCorePolicy {
    fn evaluate(&self, ctx: &DnsQueryCtx) -> Verdict {
        // Bind the ONE frozen seam (doc 11 §4 / doc 14 §6): route the gate-facing ctx
        // through `policy_core::dns_gate::evaluate`, which itself routes the single
        // `dns_admission_decision` engine (POL-3 — no rule reimplemented) and returns the
        // frozen `DnsVerdict` the handler authors directly. The W2 clamp window rides the
        // `Allow` arm's frozen `Admit`. No verdict is re-projected here: there is exactly
        // ONE verdict type from this call onward. The read lock is taken for the duration of
        // this synchronous call only (never across an `await`), so a concurrent D72 reload
        // simply applies to the NEXT query — admission is never minted mid-swap.
        let state = self.state.read().expect("policy evaluator lock poisoned");
        dns_gate::evaluate(&state.composed, &ctx.to_core(), state.ttl_clamp.to_admit())
    }
}

/// A non-routable sentinel in the RFC 2544 benchmarking range (198.18.0.0/15) — the
/// doc 11 §3.5 synthetic-A strawman pool. Retained as a `pub const` so external tooling
/// and the seam tests can name the reserved range without re-deriving it; it is NOT an
/// admission answer (the real answer is the scrubbed upstream forward, doc 11 §3.1).
pub const SYNTHETIC_A_SENTINEL: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 53);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ctx(qname: &str, qtype: u16) -> DnsQueryCtx {
        DnsQueryCtx {
            session: "test-session".to_string(),
            qname: qname.to_string(),
            qtype,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        }
    }

    #[test]
    fn fixed_policy_allows_everything_with_provenance() {
        let p = FixedStubPolicy::new();
        let v = p.evaluate(&ctx("anything.test.", 1));
        assert!(v.admits());
        // §6.7: every verdict carries non-empty provenance.
        let prov = v.provenance();
        assert!(!prov.rule_id.is_empty() && !prov.policy_version.is_empty());
        // qtype is ignored by the always-allow default — same verdict for AAAA.
        assert_eq!(
            p.evaluate(&ctx("anything.test.", 1)),
            p.evaluate(&ctx("anything.test.", 28))
        );
    }

    #[test]
    fn ttl_clamp_clamps_into_the_window() {
        let c = TtlClamp::DEFAULT;
        assert_eq!(c.clamp(5), 60); // below floor → floor
        assert_eq!(c.clamp(300), 300); // inside window → unchanged
        assert_eq!(c.clamp(100_000), 900); // above ceil → ceil
    }

    #[test]
    fn ttl_clamp_projects_onto_the_frozen_admit_window() {
        // The gate config clamp window flows verbatim onto the frozen Allow's `Admit`.
        let admit = TtlClamp::DEFAULT.to_admit();
        assert_eq!(admit.ttl_floor, 60);
        assert_eq!(admit.ttl_ceil, 900);
        // And the frozen Admit clamps identically to the gate-facing window.
        assert_eq!(admit.clamp_ttl(5), 60);
        assert_eq!(admit.clamp_ttl(100_000), 900);
    }

    // ── The pack-backed PolicyCorePolicy as the production evaluator, and its doc 11
    //    §5.3 / D72 admitter-LAST hot-reload (the snapshot-subscriber re-sources the
    //    running evaluator). Two tiny POL-1 layers compose to documents with DIFFERENT
    //    policy versions and DIFFERENT verdicts for the same name, so a `reload` is
    //    observable on the verdict — POL-3 provenance preserved on every arm. ──────────

    use ds_contracts::pol1::parse_layer;
    use policy_core::pol1_eval::compose;

    /// A POL-1 layer (`v1`) that DENIES `blocked-v1.example` at a severing rung and
    /// allowlists `kept.example`. Composes to a document whose `policy_version` is `pol1/v1`.
    const LAYER_V1: &str = r#"
schema_version: pol1/v1
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: kept.example
blocklist:
  - domain: blocked-v1.example
    reason: blocked-in-v1
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// A SECOND POL-1 layer (`v2`) — a NEW committed policy version. `blocked-v1.example`
    /// is no longer blocked here (it is an unknown-domain Ask now); `kept.example` stays
    /// allowlisted. Composes to a document whose `policy_version` is `pol1/v2`, so a
    /// `reload` from `v1` to `v2` flips the verdict for `blocked-v1.example`.
    const LAYER_V2: &str = r#"
schema_version: pol1/v2
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: kept.example
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    fn composed(layer_yaml: &str) -> ComposedPolicy {
        let layer = parse_layer(layer_yaml).expect("the test POL-1 layer parses");
        compose(&[layer], &[])
    }

    #[test]
    fn pack_backed_policy_is_the_production_evaluator_with_provenance() {
        // The production default is the REAL pack-backed PolicyCorePolicy (NOT the
        // allow-all FixedStubPolicy): a blocklisted name is the frozen §3.2 hard deny, and
        // the verdict carries the matched rule's POL-3 provenance (rule id / layer /
        // version) — never the `harness/allow-all` marker.
        let p = PolicyCorePolicy::new(composed(LAYER_V1));
        let v = p.evaluate(&ctx("blocked-v1.example.", 1));
        assert!(
            !v.admits(),
            "the pack-backed evaluator denies a blocklisted name (not allow-all)"
        );
        let prov = v.provenance();
        assert!(
            !prov.rule_id.is_empty()
                && !prov.policy_layer.is_empty()
                && !prov.policy_version.is_empty(),
            "POL-3 provenance triple is non-empty on the deny arm"
        );
        assert_ne!(
            prov.rule_id, "harness/allow-all",
            "the production verdict names the matched pack/blocklist rule, not the harness"
        );
        // An allowlisted name admits, also with non-empty provenance (POL-3 on EVERY arm).
        let allow = p.evaluate(&ctx("kept.example.", 1));
        assert!(allow.admits());
        assert!(!allow.provenance().rule_id.is_empty());
    }

    #[test]
    fn reload_re_sources_the_running_evaluator_and_preserves_provenance() {
        // A single PolicyCorePolicy handle. Under `v1`, `blocked-v1.example` is a hard deny.
        let p = PolicyCorePolicy::new(composed(LAYER_V1));
        assert_eq!(p.current_policy_version(), "pol1/v1");
        let before = p.evaluate(&ctx("blocked-v1.example.", 1));
        assert!(!before.admits(), "v1 denies blocked-v1.example");
        assert!(
            !before.provenance().rule_id.is_empty(),
            "POL-3 on the v1 deny"
        );

        // The D72 admitter-LAST reload re-sources the running evaluator from the v2 snapshot
        // (a NEW committed policy version + an explicit clamp window). No re-construction:
        // the SAME handle now decides against v2.
        p.reload(
            composed(LAYER_V2),
            TtlClamp {
                floor: 30,
                ceil: 600,
            },
        );
        assert_eq!(
            p.current_policy_version(),
            "pol1/v2",
            "the running evaluator re-sourced its composed document from the snapshot"
        );
        assert_eq!(
            p.current_ttl_clamp(),
            TtlClamp {
                floor: 30,
                ceil: 600
            },
            "the W2 clamp window re-sourced together with the composed document"
        );

        // The verdict for the SAME name flipped: `blocked-v1.example` is no longer blocked
        // under v2 — the running evaluator decides against the re-sourced document.
        let after = p.evaluate(&ctx("blocked-v1.example.", 1));
        assert_ne!(
            before, after,
            "the snapshot-driven reload changed the running evaluator's verdict"
        );
        assert!(
            !after.provenance().rule_id.is_empty() && !after.provenance().policy_version.is_empty(),
            "POL-3 provenance is preserved across the reload (every arm carries it)"
        );
    }

    #[test]
    fn clone_is_a_shared_handle_so_a_reload_is_observed_by_every_clone() {
        // `spawn_gate` clones the policy into the UDP + TCP handlers; `main` keeps a clone as
        // the reload handle. A SHARED-HANDLE clone means a single reload re-sources every
        // transport's evaluator at once — no per-transport skew. Asserted here: reloading one
        // clone is observed through another clone (the gate's handler view).
        let main_handle = PolicyCorePolicy::new(composed(LAYER_V1));
        let handler_view = main_handle.clone();
        assert_eq!(handler_view.current_policy_version(), "pol1/v1");
        assert!(
            !handler_view
                .evaluate(&ctx("blocked-v1.example.", 1))
                .admits(),
            "the handler-view clone denies under v1"
        );

        // `main`'s reload handle re-sources the evaluator; the handler-view clone — the same
        // shared inner state — observes it without being touched.
        main_handle.reload(composed(LAYER_V2), TtlClamp::DEFAULT);
        assert_eq!(
            handler_view.current_policy_version(),
            "pol1/v2",
            "the handler-view clone observed main's reload (one shared evaluator)"
        );
    }
}
