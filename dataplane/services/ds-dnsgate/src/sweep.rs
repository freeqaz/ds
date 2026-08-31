// SPDX-License-Identifier: Apache-2.0

//! ds-dnsgate's POST-COMMIT REVOCATION SWEEP driver (POL-4 part 3; D72/D53/D36, doc 13 §5,
//! doc 11 §5.4, doc 15 §5.2).
//!
//! # Where this sits in the D72 two-phase apply
//!
//! ds-dnsgate is the **admitter** — the consumer the host commits LAST in the
//! make-before-break order (ds-tlsproxy + the NFT flip move to `vN+1` first, so every
//! transient mixed-version window is FAIL-CLOSED). Once the admitter's evaluator has
//! been atomically re-sourced to `vN+1` (`crate::apply`'s pointer-swap commit), the
//! derived state the gate minted UNDER `vN` — the live DNS-2b admission map and the
//! parked TTL-ask-grants — may now reference names `vN+1` denies. The post-commit
//! sweep re-evaluates that derived state against `vN+1` and evicts everything the new
//! policy no longer admits. `applied_seq` advances ONLY after this sweep completes
//! (D72), and the host heartbeat reports the MIN over the three consumers.
//!
//! # ONE sweep, ONE refcount — this module is a DRIVER, not a second model
//!
//! The substance of the sweep lives in [`crate::server::LiveAdmissions`] — the ONE
//! production registry the W1/W2 admission transaction mints into, bound to the ONE
//! shared DNS-2b reverse index (`crate::txn::InMemoryAdmissionMap`'s
//! [`ds_contracts::dns_admission::ReverseIndex`]). Its [`crate::server::RevocationTarget::sweep`]
//! re-evaluates BOTH legs — the DNS-2b admissions AND the parked ask-grants — against
//! `vN+1` and reads its allow-set-deletion decision off that ONE shared refcount, so
//! there is no second, independently-derived survivor count that could drift from it
//! (the fork this module deliberately does NOT create).
//!
//! [`sweep_revocations`] is the thin driver `crate::apply`'s
//! `sweep_and_advance_applied_seq` invokes post-commit (and the `SweepSnapshots`-shaped
//! host callback the host agent drives): it runs the live registry's sweep against the
//! re-sourced evaluator, ROUTES the resulting [`crate::server::SweepOutcome`] to the
//! bound enforcement surface (the allow-set withdrawals + the D53 rung-conditional
//! `flush_session` conntrack flush, through the ONE shared
//! [`ds_contracts::flush::FlushSession`] primitive — never a forked severing path), and
//! returns a [`SweepReport`] whose [`SweepReport::swept_seq`] the consumer's
//! `applied_seq` then advances to. The sweep MUST complete (both legs re-evaluated, the
//! outcome routed) BEFORE `applied_seq` advances (D72).
//!
//! NEVER-LOG-THE-SECRET: nothing here logs a credential — an admission/grant names a
//! domain and an IP, never a secret; the flush carries only opaque destination keys.

#![forbid(unsafe_code)]

use crate::policy::PolicyCorePolicy;
use crate::server::{
    route_sweep_outcome, LiveAdmissions, RevocationTarget, SweepEnforcer, SweepOutcome,
};

/// The result of one post-commit revocation sweep DRIVE (doc 13 §5 / D72): the
/// [`crate::server::SweepOutcome`] the live registry resolved (the evicted admissions +
/// ask-grants, each with its D53 flush flag, and the freed allow-set IPs) plus the
/// [`Self::swept_seq`] — the snapshot seq the consumer's `applied_seq` advances to once
/// the sweep (and its enforcement routing) completes.
///
/// A no-op sweep (a policy LOOSENING, or one that leaves every live name admitted) carries
/// an empty [`SweepOutcome`] and still reports `swept_seq` — the steady-state advance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// What the live registry's sweep removed (revoked DNS-2b admissions, evicted
    /// ask-grants, freed allow-set IPs) — the production [`SweepOutcome`], NOT a second
    /// model. Routed to enforcement before this report is returned.
    pub outcome: SweepOutcome,
    /// The seq the sweep swept to — normally the committed snapshot's seq (the default
    /// frozen case is all-or-none, so a completed sweep always reaches the committed
    /// version). The consumer's `applied_seq` advances to this (D72) ONLY after the sweep
    /// (both legs) and its enforcement routing have completed.
    pub swept_seq: u64,
}

impl SweepReport {
    /// Whether the sweep evicted nothing — every live admission and ask-grant survived the
    /// `vN+1` re-evaluation (a policy loosening, or no derived state).
    pub fn is_noop(&self) -> bool {
        self.outcome.is_noop()
    }
}

/// Drive the post-commit revocation sweep over the LIVE production derived state
/// (doc 13 §5 / D72/D53). Runs [`LiveAdmissions::sweep`] — the ONE wired sweep that
/// re-evaluates every live DNS-2b admission AND every parked TTL-ask-grant through the
/// re-sourced `vN+1` evaluator, evicts those the new policy no longer admits, and frees
/// the allow-set IPs no survivor references off the ONE SHARED reverse index (bias to
/// under-delete, W4) — then ROUTES the resulting [`SweepOutcome`] to the bound enforcer
/// (the allow-set withdrawals + the D53 rung-conditional `flush_session` conntrack flush,
/// through the ONE shared severing primitive — never a fork). Returns the [`SweepReport`]
/// whose [`SweepReport::swept_seq`] the consumer's `applied_seq` advances to.
///
/// `admissions` is the production [`LiveAdmissions`] registry (the SAME one the W1/W2
/// transaction mints into and the POL-5 approval path parks ask-grants in — shared from
/// the gate via `crate::server::RunningGate::live_admissions`). `reevaluator` is the
/// gate's re-sourced running evaluator (the SAME `PolicyCorePolicy` the hot-path
/// `dns_admission_decision` queries — no rule re-implemented). `seq` is the committed
/// snapshot's seq. `enforcer` is the consumer's bound enforcement surface — the reportable
/// in-memory recorder by default, or the production `ds_nft::NftWriter` adapter behind
/// `DS_NFTGATE_LIVE`.
///
/// The sweep ALWAYS completes (both legs re-evaluated, the outcome routed) before this
/// returns, so the caller advances `applied_seq` only post-sweep (D72). FAIL-CLOSED /
/// additive: the eviction removes the ALLOW derived state first; a routed flush whose
/// bound primitive errors leaves an established flow riding until expiry (never an
/// over-admit), and never wedges the sweep — the routing logs and the sweep still reaches
/// `swept_seq` (the default frozen case is all-or-none).
pub fn sweep_revocations(
    admissions: &LiveAdmissions,
    reevaluator: &PolicyCorePolicy,
    seq: u64,
    enforcer: &dyn SweepEnforcer,
) -> SweepReport {
    // The ONE wired sweep: re-evaluate both legs against vN+1 off the ONE shared refcount.
    let outcome = admissions.sweep(reevaluator);
    // Route what the sweep RESOLVED to enforcement (allow-set withdrawals + the D53
    // rung-conditional conntrack flush through the ONE shared `flush_session`). A no-op
    // outcome routes nothing; this is the SAME `route_sweep_outcome` the production
    // `SnapshotCommitSink` commit path uses — one routing, no fork.
    route_sweep_outcome(&outcome, enforcer);
    SweepReport {
        outcome,
        // The sweep completes against the committed version: the default frozen case is
        // all-or-none, so the swept seq is the committed snapshot seq (D72).
        swept_seq: seq,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyCorePolicy;
    use crate::server::{LiveAdmission, LiveAskGrant, RecordingSweepEnforcer};
    use ds_contracts::pol1;
    use policy_core::pol1_eval::{compose, ComposedPolicy};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Compose a vN+1 document from one POL-1 session-layer text.
    fn composed(doc: &str) -> ComposedPolicy {
        let layer = pol1::parse_layer(doc).expect("layer parses");
        compose(std::slice::from_ref(&layer), &[])
    }

    /// A re-sourced gate evaluator decided against `doc` (the committed vN+1) — the SAME
    /// `PolicyCorePolicy` the hot path uses, so the sweep re-evaluates off the production
    /// verdict surface (no rule re-implemented).
    fn evaluator(doc: &str) -> PolicyCorePolicy {
        PolicyCorePolicy::new(composed(doc))
    }

    /// The acceptance scenario, end to end through the WIRED registry: 3 live admissions,
    /// 2 now denied (and severing) under vN+1; 1 still admits. 2 parked ask-grants, 1 now
    /// blocked (severing), 1 still allowed. The sweep evicts 2 admissions + 1 grant, frees
    /// their IPs, routes the allow-set withdrawals + the D53 rung-conditional flush, and
    /// returns the committed seq — proving the ask-grant leg runs in the SAME wired sweep.
    #[test]
    fn drives_the_wired_sweep_evicting_admissions_and_ask_grants_and_routing_enforcement() {
        let doc = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             allowlist:\n  - domain: keep.example\n  - domain: grant-keep.example\n\
             blocklist:\n  - domain: evil0.example\n    reason: r\n    rung: block+log\n  \
             - domain: evil1.example\n    reason: r\n    rung: block+log\n  \
             - domain: grant-block.example\n    reason: r\n    rung: block+log\n";
        let reeval = evaluator(doc);
        let session = "dstap-7/sess-1";

        // A bare synthetic registry (no bound shared map) — the isolation path the sweep
        // is still exercisable over; the survivor-derived refcount agrees with the shared
        // index by construction.
        let admissions = LiveAdmissions::new();
        admissions.admit(LiveAdmission::new(session, "keep.example", ip(10, 0, 0, 0)));
        admissions.admit(LiveAdmission::new(
            session,
            "evil0.example",
            ip(10, 0, 1, 0),
        ));
        admissions.admit(LiveAdmission::new(
            session,
            "evil1.example",
            ip(10, 0, 1, 1),
        ));
        admissions.park_ask_grant(LiveAskGrant::new(
            session,
            "grant-keep.example",
            vec![ip(10, 0, 2, 0)],
        ));
        admissions.park_ask_grant(LiveAskGrant::new(
            session,
            "grant-block.example",
            vec![ip(10, 0, 2, 1)],
        ));
        assert_eq!(admissions.len(), 3);
        assert_eq!(admissions.ask_grant_len(), 2);

        let enforcer = RecordingSweepEnforcer::new();
        let report = sweep_revocations(&admissions, &reeval, 42, &enforcer);

        // 2 admissions evicted, 1 survives; 1 ask-grant evicted, 1 survives.
        assert_eq!(report.outcome.revoked.len(), 2, "2 admissions denied");
        assert_eq!(admissions.len(), 1, "keep.example survives");
        assert_eq!(admissions.snapshot()[0].fqdn, "keep.example.");
        assert_eq!(
            report.outcome.evicted_ask_grants.len(),
            1,
            "grant-block evicted"
        );
        assert_eq!(admissions.ask_grant_len(), 1, "grant-keep survives");
        assert_eq!(
            admissions.ask_grant_snapshot()[0].fqdn,
            "grant-keep.example."
        );

        // Every eviction here is block+log → severing (D53).
        assert!(report.outcome.revoked.iter().all(|r| r.flush_conntrack));
        assert!(report
            .outcome
            .evicted_ask_grants
            .iter()
            .all(|g| g.flush_conntrack));

        // Allow-set freed: the 2 admission IPs + the 1 grant IP (none shared).
        assert_eq!(report.outcome.allow_set_deletions.len(), 3);
        assert!(report
            .outcome
            .allow_set_deletions
            .contains(&ip(10, 0, 1, 0)));
        assert!(report
            .outcome
            .allow_set_deletions
            .contains(&ip(10, 0, 1, 1)));
        assert!(report
            .outcome
            .allow_set_deletions
            .contains(&ip(10, 0, 2, 1)));

        // Enforcement ROUTED: 3 allow-set withdrawals + 1 rung-conditional conntrack flush.
        assert_eq!(enforcer.withdrawn().len(), 3, "3 freed IPs withdrawn");
        let flushes = enforcer.flushed();
        assert_eq!(flushes.len(), 1, "one severing flush for the session");
        assert_eq!(flushes[0].dst_keys.len(), 3, "narrowed to the freed IPs");

        assert_eq!(report.swept_seq, 42);
        assert!(!report.is_noop());
    }

    /// A policy LOOSENING (vN+1 admits everything live) is a no-op sweep that routes NO
    /// enforcement and still reports the committed seq — `applied_seq` advances post-sweep.
    #[test]
    fn loosening_policy_is_a_noop_drive_that_routes_nothing_and_still_advances_seq() {
        let doc = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             allowlist:\n  - domain: a.example\n  - domain: b.example\n";
        let reeval = evaluator(doc);
        let admissions = LiveAdmissions::new();
        admissions.admit(LiveAdmission::new("s", "a.example", ip(1, 1, 1, 1)));
        admissions.park_ask_grant(LiveAskGrant::new("s", "b.example", vec![ip(2, 2, 2, 2)]));

        let enforcer = RecordingSweepEnforcer::new();
        let report = sweep_revocations(&admissions, &reeval, 99, &enforcer);

        assert!(report.is_noop(), "loosening evicts nothing");
        assert_eq!(admissions.len(), 1, "admission survives");
        assert_eq!(admissions.ask_grant_len(), 1, "grant survives");
        assert!(enforcer.withdrawn().is_empty());
        assert!(enforcer.flushed().is_empty());
        assert_eq!(
            report.swept_seq, 99,
            "applied_seq still advances post-sweep"
        );
    }

    /// An `allow+log`-rung deny EVICTS a parked ask-grant (it no longer admits) but does
    /// NOT sever established flows (D53: only block-or-higher severs) — the allow-set
    /// element is withdrawn, but NO conntrack flush is routed.
    #[test]
    fn ask_grant_allow_log_rung_evicts_and_withdraws_but_does_not_flush() {
        let doc = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             blocklist:\n  - domain: noisy.example\n    reason: r\n    rung: allow+log\n";
        let reeval = evaluator(doc);
        let admissions = LiveAdmissions::new();
        admissions.park_ask_grant(LiveAskGrant::new(
            "s",
            "noisy.example",
            vec![ip(192, 0, 2, 5)],
        ));

        let enforcer = RecordingSweepEnforcer::new();
        let report = sweep_revocations(&admissions, &reeval, 7, &enforcer);

        assert_eq!(report.outcome.evicted_ask_grants.len(), 1, "grant evicted");
        assert_eq!(admissions.ask_grant_len(), 0);
        assert!(
            !report.outcome.evicted_ask_grants[0].flush_conntrack,
            "allow+log does NOT sever (D53)"
        );
        // The allow-set element is still freed + withdrawn (the ALLOW state is gone)...
        assert_eq!(report.outcome.allow_set_deletions, vec![ip(192, 0, 2, 5)]);
        assert_eq!(enforcer.withdrawn().len(), 1);
        // ...but NO conntrack flush (no severing).
        assert!(
            enforcer.flushed().is_empty(),
            "allow+log leaves established flows alone"
        );
        assert_eq!(report.swept_seq, 7);
    }

    /// A genuine UNRUNG `Deny{rung: None}` — a DISABLED-TIER baseline-pack entry, which
    /// `evaluate_domain` returns as `Deny{rung: None}` — evicts the parked ask-grant but
    /// does NOT sever (rule 8 / W4: only an explicit block-or-higher deny severs). This is
    /// a real Deny, NOT an `Ask` masquerading as one (an unknown domain returns `Ask`
    /// regardless of posture; posture is never consulted in `evaluate_domain`).
    #[test]
    fn ask_grant_unrung_tier_disabled_deny_evicts_without_severing() {
        // A baseline-pack entry in the `media` family, with the family tier DISABLED →
        // `evaluate_domain` returns `Deny { rung: None }` (a default/tier deny, no rung). The
        // D74 mandatory-provenance fields (`provenance_source_url` + `evidence`) are present so
        // the entry parses — it is the TIER (not provenance) that drives the deny here.
        let doc = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             baseline_pack:\n  pack_version: test-1\n  families:\n    media:\n      tier: disabled\n  \
             entries:\n    - fqdn: cdn.media.example\n      family: media\n      \
             provenance_source_url: https://example.test/pack\n      evidence: test-fixture\n";
        let reeval = evaluator(doc);
        let admissions = LiveAdmissions::new();
        admissions.park_ask_grant(LiveAskGrant::new(
            "s",
            "cdn.media.example",
            vec![ip(198, 51, 100, 4)],
        ));

        let enforcer = RecordingSweepEnforcer::new();
        let report = sweep_revocations(&admissions, &reeval, 3, &enforcer);

        assert_eq!(
            report.outcome.evicted_ask_grants.len(),
            1,
            "tier-disabled deny evicts the grant"
        );
        assert!(
            !report.outcome.evicted_ask_grants[0].flush_conntrack,
            "an unrung tier deny gates new flows only (rule 8)"
        );
        // The allow-set element is freed + withdrawn, but no conntrack flush fires.
        assert_eq!(
            report.outcome.allow_set_deletions,
            vec![ip(198, 51, 100, 4)]
        );
        assert_eq!(enforcer.withdrawn().len(), 1);
        assert!(enforcer.flushed().is_empty());
        assert_eq!(report.swept_seq, 3);
    }

    /// An `Ask` eviction (an unknown domain → `Eval::Ask`, which does not `admits()`)
    /// evicts the parked grant without severing — and the comment names it honestly as an
    /// Ask, not a Deny. Proves the Ask path evicts but never flushes (Ask is non-severing).
    #[test]
    fn ask_grant_unknown_domain_ask_evicts_without_severing() {
        // An empty standard policy: any unknown name → `Eval::Ask` (posture-independent).
        let doc = "schema_version: pol1/v0\nlayer: session\nposture: standard\n";
        let reeval = evaluator(doc);
        let admissions = LiveAdmissions::new();
        admissions.park_ask_grant(LiveAskGrant::new(
            "s",
            "unknown.example",
            vec![ip(203, 0, 113, 7)],
        ));

        let enforcer = RecordingSweepEnforcer::new();
        let report = sweep_revocations(&admissions, &reeval, 11, &enforcer);

        assert_eq!(report.outcome.evicted_ask_grants.len(), 1, "Ask evicts");
        assert!(
            !report.outcome.evicted_ask_grants[0].flush_conntrack,
            "an Ask is non-severing (D53)"
        );
        assert!(enforcer.flushed().is_empty(), "Ask never flushes conntrack");
        assert_eq!(report.swept_seq, 11);
    }

    /// A shared-CDN IP held by a SURVIVING admission is NOT freed (and NOT severed) when a
    /// sibling ask-grant sharing it is evicted — the unified under-delete refcount (W4)
    /// reads BOTH legs.
    #[test]
    fn shared_ip_held_by_a_surviving_admission_survives_an_ask_grant_eviction() {
        let doc = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             allowlist:\n  - domain: kept.example\n\
             blocklist:\n  - domain: dropped.example\n    reason: r\n    rung: block+log\n";
        let reeval = evaluator(doc);
        let shared = ip(203, 0, 113, 9);
        let admissions = LiveAdmissions::new();
        admissions.admit(LiveAdmission::new("s", "kept.example", shared));
        admissions.park_ask_grant(LiveAskGrant::new("s", "dropped.example", vec![shared]));

        let enforcer = RecordingSweepEnforcer::new();
        let report = sweep_revocations(&admissions, &reeval, 5, &enforcer);

        // The grant is evicted, the admission survives.
        assert_eq!(report.outcome.evicted_ask_grants.len(), 1);
        assert_eq!(admissions.len(), 1);
        // The shared IP is NOT freed (kept.example still holds it) — under-delete, so no
        // withdrawal and no flush.
        assert!(
            report.outcome.allow_set_deletions.is_empty(),
            "a shared IP a survivor holds is not freed (W4)"
        );
        assert!(enforcer.withdrawn().is_empty());
        assert!(enforcer.flushed().is_empty());
        assert_eq!(report.swept_seq, 5);
    }
}
