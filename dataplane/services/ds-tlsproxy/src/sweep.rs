// SPDX-License-Identifier: Apache-2.0

//! ds-tlsproxy's POST-COMMIT REVOCATION SWEEP — the three-consumer sweep coordination
//! (POL-4 part 3; D72/D53/D36, doc 13 §5, doc 15 §5.2).
//!
//! TWO derived-state implementors live here (01KV9N17NN CV2-failclosed): the
//! [`NoDerivedState`] no-op for the CONNECT-DECISION plane (correct — allow/deny is a
//! live evaluator query the commit pointer-swap already re-sourced), AND the REAL
//! [`SeveringDerivedState`] for the ESTABLISHED-TUNNEL plane (a CONNECT opaque tunnel
//! outlives the commit and must be SEVERED now when `vN+1` revokes it at a severing
//! rung — not left flowing until the client closes it). The latter replaces the
//! survivor-derived placeholder: a real flush through the shared FlushSession.
//!
//! # Where this sits in the D72 two-phase apply
//!
//! ds-tlsproxy is an **enforcer** — committed BEFORE the admitter in the
//! make-before-break order (`crate::apply`'s pointer-swap flips the proxy to `vN+1`
//! before ds-dnsgate starts admitting under it, so every transient mixed-version
//! window is FAIL-CLOSED). The frozen D72 contract requires EVERY consumer to sweep
//! post-commit and report a swept seq: `applied_seq` advances ONLY after the sweep
//! completes, and the host heartbeat reports the MIN over the three consumers (doc 15
//! §5.2). This module is ds-tlsproxy's contribution to that min.
//!
//! # Why this is a NO-OP today (no derived state to re-evaluate)
//!
//! The sibling consumers cache derived state UNDER `vN` that a stricter `vN+1` can
//! orphan: ds-nft holds the allow4/allow6 element sets, ds-dnsgate holds the DNS-2b
//! admission map + the parked TTL-ask-grants. Their sweeps re-evaluate those cached
//! sets against `vN+1` and evict what the new policy denies (the eviction lives in
//! `ds-dnsgate`'s `sweep_revocations`).
//!
//! ds-tlsproxy has NO such cached set: its allow/deny decisions are LIVE queries
//! against the embedded `policy-core` evaluator (`crate::explicit::tls_connect_decision`
//! and the TLS-1 SNI admission both call the evaluator on every connect). The commit's
//! atomic pointer-swap (`crate::apply::PolicyConsumer::commit`) is therefore the WHOLE
//! re-sourcing: the very next connect decision already reads `vN+1`. There is nothing
//! derived to re-walk, so the sweep re-evaluates nothing, evicts nothing, severs
//! nothing, and returns the committed snapshot seq UNCHANGED — a no-op that completes
//! instantly and contributes that seq to the min-over-three.
//!
//! This is a deliberate STRUCTURAL placeholder enforcing the frozen topology — exactly
//! three consumers, each one sweeps (doc 13 §5). The shape exists so the host agent's
//! multi-consumer coordinator can call `SweepSnapshots` on ALL three consumers
//! uniformly; ds-tlsproxy's contribution is honest and complete (a no-op IS a completed
//! sweep), never a special-cased "skip the proxy".
//!
//! # Forward-compatible: a future TLS path's derived state slots in here
//!
//! When the TLS path grows re-evaluable derived state — e.g. cached identity tokens
//! with TTLs (TLS-5 grant cache), or a re-evaluable TLS-policy/pass-through cache — its
//! eviction belongs in this module, behind the SAME [`SweepReport`] contract the host
//! coordinator already drives. The [`DerivedState`] seam is the extension point: today
//! the [`NoDerivedState`] implementor re-evaluates nothing; a future implementor walks
//! its cache against the re-sourced `vN+1` evaluator and severs rung-conditionally
//! through the ONE shared [`ds_contracts::flush::FlushSession`] primitive (D53) — never
//! a forked severing path. Adding that derived state changes neither the barrier
//! contract nor this module's signature: [`sweep_revocations`] still returns a
//! [`SweepReport`] and `applied_seq` still advances only post-sweep.
//!
//! NEVER-LOG-THE-SECRET: nothing here logs a credential — there is no derived state to
//! name, and a future eviction names only a destination/session, never a secret. The
//! crate-root `#![forbid(unsafe_code)]` binds this module.

#![forbid(unsafe_code)]

use ds_contracts::consumer::PolicyVersion;

use crate::{RevocationSweep, RevokedAdmission, SessionUpstreamPools, SeveringRegistry};

/// The result of one ds-tlsproxy post-commit revocation sweep DRIVE (doc 13 §5 / D72):
/// the [`Self::swept_seq`] the consumer's `applied_seq` advances to once the sweep
/// completes, plus a count of what was evicted (always `0` today — no derived state).
///
/// For M0 the sweep is a NO-OP: ds-tlsproxy holds no cached derived state, so every
/// sweep carries `evicted == 0` and `swept_seq == <committed seq>` (the steady-state
/// advance). The shape mirrors `ds-dnsgate`'s `SweepReport` so the host coordinator
/// reads one report type across all three consumers; a future TLS-path derived state
/// (see the module doc) populates `evicted` without changing this contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// The seq the sweep swept to — the committed snapshot's seq. The default frozen
    /// case is all-or-none, so a completed sweep always reaches the committed version
    /// (D72). The consumer's `applied_seq` advances to this ONLY after the sweep
    /// completes, and it feeds the host heartbeat's MIN over the three consumers.
    pub swept_seq: u64,
    /// How many derived-state entries this sweep evicted. ALWAYS `0` for M0 — the proxy
    /// has no cached set to re-evaluate (allow/deny are live evaluator queries). A
    /// future TLS-path derived state (cached identity tokens / a TLS-policy cache)
    /// increments this when `vN+1` orphans an entry; the no-op default stays honest.
    pub evicted: usize,
}

impl SweepReport {
    /// Whether the sweep evicted nothing — the M0 no-op steady state (no derived state,
    /// or a policy loosening a future derived state would survive).
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.evicted == 0
    }
}

/// The proxy's re-evaluable POST-COMMIT derived state — the extension seam a future
/// TLS path's cache (cached identity tokens with TTLs, a re-evaluable TLS-policy cache)
/// plugs into WITHOUT changing the barrier contract (doc 13 §5; the spec's "accepts a
/// future TLS path's derived state").
///
/// An implementor re-evaluates its cache against the just-committed `vN+1` evaluator and
/// reports how many entries it evicted. The eviction's severing (rung-conditional, D53)
/// rides the ONE shared [`ds_contracts::flush::FlushSession`] primitive inside the
/// implementor — this seam reports only the COUNT, so the sweep driver and the
/// `applied_seq` advance stay derived-state-agnostic. Today the only implementor is
/// [`NoDerivedState`] (the M0 no-op).
pub trait DerivedState {
    /// Re-evaluate this derived state against the committed `vN+1` policy and evict what
    /// the new policy no longer admits, returning the number of entries evicted. MUST
    /// complete (synchronously, within the apply budget) before the caller advances
    /// `applied_seq` (D72). A no-op implementor returns `0`.
    fn reevaluate_and_evict(&self) -> usize;
}

/// The M0 ds-tlsproxy derived-state: NONE. The proxy's allow/deny decisions are live
/// evaluator queries, not a cached set, so the commit's atomic evaluator pointer-swap
/// is the whole re-sourcing and there is nothing to re-walk. Re-evaluation evicts `0`.
///
/// This is the honest stand-in until a TLS path grows a re-evaluable cache — at which
/// point a real [`DerivedState`] implementor replaces it here, leaving
/// [`sweep_revocations`] and the barrier contract untouched.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDerivedState;

impl DerivedState for NoDerivedState {
    fn reevaluate_and_evict(&self) -> usize {
        // No cached derived state: nothing to re-evaluate, nothing to evict, nothing to
        // sever. The atomic evaluator flip (crate::apply::commit) already re-sourced
        // every future connect decision to vN+1.
        0
    }
}

/// The REAL ds-tlsproxy post-commit derived state (01KV9N17NN CV2-failclosed): the
/// set of LIVE established tunnels + warm pooled upstream sockets the just-committed
/// `vN+1` policy REVOKES, severed through the ONE shared
/// [`ds_contracts::flush::FlushSession`] primitive (D53/D72, doc 12 §8).
///
/// # Why this is the real severing, not a no-op
///
/// ds-tlsproxy's *connect-decision* state is a live evaluator query (the
/// [`NoDerivedState`] no-op is correct for THAT) — but an ALREADY-ESTABLISHED CONNECT
/// opaque tunnel (and any warm pooled upstream socket) is derived state that outlives
/// the commit: it keeps flowing under the old admission until the client closes it.
/// A `vN+1` that blocks / suspends / kills a destination at a SEVERING rung (D53
/// block-or-higher) MUST tear those live flows down NOW, not wait for client close —
/// the §8 destroy-event severing. This implementor is that sever: it drives
/// [`RevocationSweep`] over the [`SeveringRegistry`] for the revoked `(session, dst,
/// rung)` set the host apply driver computed from the vN→vN+1 diff, AND drops the
/// swept session's warm pool partition at a severing rung — the SAME rung-gated
/// drop the session-end teardown does unconditionally. It replaces the
/// survivor-derived placeholder: a real flush, not a returned-zero.
///
/// # Fail-closed + D53 rung discipline
///
/// Severing is rung-gated EXACTLY as [`RevocationSweep::apply`] and the promoted
/// `revocation_sweep_with_pools` driver gate it: a sub-block (allow+log) revocation
/// severs NOTHING (D53 non-severing rung), and D68 expiry is never a revocation so an
/// expiring admission is never in `revoked`. The flush is idempotent across re-drives
/// (a handle already severed counts once), so a re-driven barrier never double-severs.
///
/// `'a` borrows the live registries for the duration of the sweep; `T` is the pooled
/// upstream socket type ([`std::net::TcpStream`] in production), dropped (closed) when
/// its pool partition is dropped. NEVER-LOG-THE-SECRET: nothing here names a
/// credential — a severed entry is keyed by `(session, dst)` only.
pub struct SeveringDerivedState<'a, T> {
    severing: &'a SeveringRegistry,
    pools: &'a SessionUpstreamPools<T>,
    revoked: &'a [RevokedAdmission],
}

impl<'a, T> SeveringDerivedState<'a, T> {
    /// Build the real derived-state sweep over the live registries + the revoked set
    /// the host apply driver computed from the vN→vN+1 policy diff.
    #[must_use]
    pub fn new(
        severing: &'a SeveringRegistry,
        pools: &'a SessionUpstreamPools<T>,
        revoked: &'a [RevokedAdmission],
    ) -> SeveringDerivedState<'a, T> {
        SeveringDerivedState {
            severing,
            pools,
            revoked,
        }
    }
}

impl<T> DerivedState for SeveringDerivedState<'_, T> {
    fn reevaluate_and_evict(&self) -> usize {
        // Sever live tunnels for every block-or-higher revocation (rung-gated, D53)
        // through the shared FlushSession, then drop the swept session's warm pool
        // partition at a severing rung — the SAME two-population cleanup doc 12 §8
        // names ("tear down its live tunnels ... and drop pooled upstream sockets").
        let outcome = RevocationSweep::new(self.severing).apply(self.revoked);
        let mut pooled_dropped: usize = 0;
        for adm in self.revoked {
            if adm.rung.is_block_or_higher() {
                pooled_dropped =
                    pooled_dropped.saturating_add(self.pools.drop_session(&adm.session));
            }
        }
        // The eviction COUNT the SweepReport carries: live tunnel handles severed +
        // warm pooled sockets dropped. Both are derived-state entries vN+1 orphaned.
        (outcome.entries_severed as usize).saturating_add(pooled_dropped)
    }
}

/// Drive the post-commit revocation sweep for ds-tlsproxy (doc 13 §5 / D72/D53).
///
/// Re-evaluates the proxy's derived state against the just-committed `vN+1` policy
/// (today [`NoDerivedState`] — a no-op that re-evaluates nothing, evicts nothing, and
/// severs nothing) and returns the [`SweepReport`] whose [`SweepReport::swept_seq`] the
/// consumer's `applied_seq` advances to. `seq` is the committed snapshot's seq;
/// `derived` is the proxy's re-evaluable derived state.
///
/// The sweep ALWAYS completes before this returns, so the caller advances `applied_seq`
/// only post-sweep (D72). For M0 it completes instantly (no derived state); the
/// returned `swept_seq` is the committed `seq` (the default frozen case is all-or-none),
/// and the proxy contributes that seq to the host's MIN over the three consumers.
pub fn sweep_revocations(seq: u64, derived: &dyn DerivedState) -> SweepReport {
    // Re-evaluate the (today empty) derived state against vN+1. A future TLS-path cache
    // walks itself here and severs rung-conditionally through the ONE shared
    // flush_session; the M0 NoDerivedState evicts nothing.
    let evicted = derived.reevaluate_and_evict();
    SweepReport {
        // The sweep completes against the committed version: all-or-none, so the swept
        // seq is the committed snapshot seq (D72).
        swept_seq: seq,
        evicted,
    }
}

/// The M0 convenience: drive the sweep with the no-derived-state placeholder. The
/// `crate::apply` `sweep_and_advance_applied_seq` hook calls this so the no-op sweep is
/// the explicit, named path (rather than an inline trivial advance) — keeping the
/// three-consumer topology visible: each consumer sweeps.
#[must_use]
pub fn sweep_noop(seq: u64) -> SweepReport {
    sweep_revocations(seq, &NoDerivedState)
}

/// The `SweepSnapshots`-shaped post-commit sweep callback the host agent's
/// multi-consumer coordinator drives on ds-tlsproxy's `WatchSnapshots` boundary service
/// (doc 13 §5). Given the just-committed snapshot version, runs the no-op sweep and
/// returns the swept seq the coordinator folds into its MIN over the three consumers
/// (D72). Completes synchronously within budget — there is no derived state to walk —
/// and NEVER blocks or errors (a no-op sweep cannot fail), so it never holds back the
/// min and never aborts the host apply.
#[must_use]
pub fn sweep_snapshots(version: PolicyVersion) -> PolicyVersion {
    PolicyVersion(sweep_noop(version.seq()).swept_seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_sweep_returns_the_committed_seq_unchanged() {
        // The sweep accepts the new snapshot's seq, re-evaluates nothing (no derived
        // state), evicts nothing, and returns the seq unchanged.
        let report = sweep_revocations(42, &NoDerivedState);
        assert_eq!(report.swept_seq, 42, "swept to the committed seq");
        assert_eq!(report.evicted, 0, "no derived state → nothing evicted");
        assert!(report.is_noop(), "the M0 sweep is a no-op");
    }

    #[test]
    fn sweep_noop_and_sweep_snapshots_agree_on_the_seq() {
        // The named M0 helpers both pass the committed seq straight through.
        assert_eq!(sweep_noop(7).swept_seq, 7);
        assert_eq!(
            sweep_noop(0).swept_seq,
            0,
            "seq 0 (a booting host) passes through"
        );
        assert_eq!(
            sweep_snapshots(PolicyVersion(99)),
            PolicyVersion(99),
            "the SweepSnapshots callback contributes the seq unchanged"
        );
    }

    #[test]
    fn no_derived_state_evicts_nothing() {
        // The honest stand-in: the proxy holds no cached set, so re-evaluation against
        // vN+1 removes nothing (allow/deny are live evaluator queries — the commit flip
        // already re-sourced them).
        assert_eq!(NoDerivedState.reevaluate_and_evict(), 0);
        assert_eq!(NoDerivedState.reevaluate_and_evict(), 0);
    }

    #[test]
    fn a_future_derived_state_populates_evicted_without_changing_the_contract() {
        // PROVE the seam accepts a future TLS-path derived state without changing the
        // SweepReport contract: a stand-in cache that evicts some entries is reported
        // through the SAME shape, and swept_seq is still the committed seq.
        struct FakeTtlCache {
            orphaned_by_vnplus1: usize,
        }
        impl DerivedState for FakeTtlCache {
            fn reevaluate_and_evict(&self) -> usize {
                // A real impl would re-walk cached identity tokens against vN+1 and sever
                // rung-conditionally through the ONE shared flush_session; the fake just
                // reports the count so the contract surface is exercised.
                self.orphaned_by_vnplus1
            }
        }
        let report = sweep_revocations(
            11,
            &FakeTtlCache {
                orphaned_by_vnplus1: 3,
            },
        );
        assert_eq!(report.swept_seq, 11, "still the committed seq");
        assert_eq!(
            report.evicted, 3,
            "the future derived state's evictions surface"
        );
        assert!(!report.is_noop(), "an eviction is not a no-op");
    }

    #[test]
    fn sweep_report_default_is_an_empty_noop() {
        let r = SweepReport::default();
        assert_eq!(r.swept_seq, 0);
        assert_eq!(r.evicted, 0);
        assert!(r.is_noop());
    }
}
