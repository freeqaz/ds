// SPDX-License-Identifier: Apache-2.0

//! Integration coverage for ds-tlsproxy's POST-COMMIT REVOCATION SWEEP (POL-4 part 3;
//! D72/D36, doc 13 §5, doc 15 §5.2).
//!
//! These tests exercise the sweep END TO END through the real `Consumer` two-phase
//! barrier (prepare → commit → sweep) and prove the structural contract the unit
//! enforces:
//!
//! - the sweep ACCEPTS the just-committed snapshot, does NO re-evaluation (no derived
//!   state yet), RETURNS the snapshot seq, and completes within budget;
//! - `applied_seq` advances ONLY after the sweep completes (D72);
//! - the sweep is CALLABLE from a host-agent-shaped multi-consumer coordinator and
//!   CONTRIBUTES its seq to the MIN over the three consumers WITHOUT blocking or erroring.

use std::time::{Duration, Instant};

use ds_contracts::consumer::{Consumer, PolicyVersion};
use ds_tlsproxy::apply::{Evaluator, PolicyConsumer};
use ds_tlsproxy::sweep::{sweep_noop, sweep_snapshots, SweepReport};

/// A clean POL-1 session layer that stages + commits successfully.
const VALID_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                         dns:\n  boundary_zone: corp.example.\n";

/// Build a proxy consumer already serving an initial `vN` evaluator at `seq`.
fn consumer_at(seq: u64) -> PolicyConsumer {
    let layer = ds_contracts::pol1::parse_layer(VALID_DOC).expect("seed layer parses");
    PolicyConsumer::new(Evaluator::from_layer(&layer), PolicyVersion(seq))
}

/// A distinct-but-valid `vN+1` document so the commit is a real flip.
fn next_doc(zone: &str) -> String {
    format!(
        "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
         dns:\n  boundary_zone: {zone}.\n"
    )
}

#[test]
fn sweep_accepts_the_committed_snapshot_returns_its_seq_and_advances_applied_seq() {
    // The full barrier: prepare stages, commit flips, sweep returns the snapshot seq.
    let c = consumer_at(1);
    let doc = next_doc("beta.example");
    let token = c.prepare(doc.as_bytes(), PolicyVersion(2)).expect("stage");

    c.commit(&token).expect("commit");
    // applied_seq does NOT advance on commit — only after the sweep (D72).
    assert_eq!(
        c.applied_seq(),
        PolicyVersion(1),
        "commit does not advance applied_seq"
    );

    let swept = c
        .sweep_and_advance_applied_seq(&token)
        .expect("the no-op sweep accepts the committed snapshot and never errors");
    assert_eq!(
        swept,
        PolicyVersion(2),
        "sweep returns the committed snapshot seq"
    );
    assert_eq!(
        c.applied_seq(),
        PolicyVersion(2),
        "applied_seq advances only post-sweep"
    );
}

#[test]
fn the_sweep_does_no_reevaluation_and_completes_within_budget() {
    // ds-tlsproxy has no derived state: the sweep evicts nothing and returns instantly.
    let report: SweepReport = sweep_noop(7);
    assert_eq!(report.swept_seq, 7, "returns the snapshot seq unchanged");
    assert_eq!(
        report.evicted, 0,
        "no derived state → no re-evaluation, nothing evicted"
    );
    assert!(report.is_noop());

    // "Completes within budget": the synchronous no-op is effectively instant. Assert a
    // generous wall-clock ceiling so a regression that adds blocking work is caught.
    let started = Instant::now();
    for seq in 0..10_000u64 {
        let _ = sweep_noop(seq);
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "10k no-op sweeps complete well within budget (got {:?})",
        started.elapsed()
    );
}

#[test]
fn sweep_is_idempotent_and_does_not_resweep() {
    // A re-driven barrier re-presenting the committed token is a no-op success; the
    // applied_seq stays put (the no-op sweep never moves it backward or errors).
    let c = consumer_at(5);
    let doc = next_doc("gamma.example");
    let token = c.prepare(doc.as_bytes(), PolicyVersion(6)).expect("stage");
    c.commit(&token).expect("commit");

    let first = c.sweep_and_advance_applied_seq(&token).expect("sweep 1");
    let second = c
        .sweep_and_advance_applied_seq(&token)
        .expect("sweep 2 (idempotent, no re-sweep)");
    assert_eq!(first, PolicyVersion(6));
    assert_eq!(second, PolicyVersion(6));
    assert_eq!(c.applied_seq(), PolicyVersion(6));
}

// ─── The host-agent-shaped multi-consumer coordinator (D72 min-over-three) ───────────

/// A consumer's post-sweep applied seq as the coordinator reads it — modelling the
/// per-consumer `ServiceHealth.applied_seq` the host folds into `Heartbeat.applied_seq`
/// (doc 15 §5.2). The two sibling consumers (ds-dnsgate, ds-nft) are modelled by their
/// post-sweep seqs; ds-tlsproxy's is driven through the REAL sweep under test.
struct ThreeConsumerCoordinator {
    dnsgate_applied_seq: u64,
    nft_applied_seq: u64,
}

impl ThreeConsumerCoordinator {
    /// Drive ds-tlsproxy's post-commit sweep (the real one) and fold its swept seq into
    /// the MIN over the three consumers (D72). This mirrors how the host agent calls
    /// `SweepSnapshots` on each consumer and reports the min as the heartbeat's
    /// `applied_seq`. Returns the min — the value that would feed the heartbeat.
    fn heartbeat_applied_seq(&self, committed: PolicyVersion) -> PolicyVersion {
        // ds-tlsproxy's contribution: the SweepSnapshots-shaped callback the host drives.
        let tlsproxy_swept = sweep_snapshots(committed);
        PolicyVersion(
            tlsproxy_swept
                .seq()
                .min(self.dnsgate_applied_seq)
                .min(self.nft_applied_seq),
        )
    }
}

#[test]
fn tlsproxy_sweep_is_callable_from_the_coordinator_and_contributes_to_min_over_three() {
    // ds-tlsproxy's no-op sweep contributes the committed seq to the min. When the two
    // siblings are also at the committed seq, the min IS the committed seq — the proxy
    // never holds the min back (the no-op completes instantly and never errors).
    let coord = ThreeConsumerCoordinator {
        dnsgate_applied_seq: 9,
        nft_applied_seq: 9,
    };
    assert_eq!(
        coord.heartbeat_applied_seq(PolicyVersion(9)),
        PolicyVersion(9),
        "all three at vN+1 → heartbeat advances to vN+1; ds-tlsproxy did not block it"
    );
}

#[test]
fn min_over_three_is_held_back_by_a_lagging_sibling_not_by_tlsproxy() {
    // If a SIBLING lags (its sweep hasn't completed, so its applied_seq is still vN), the
    // min stays vN — but that is the SIBLING holding it back. ds-tlsproxy's no-op sweep
    // has already swept to vN+1 (it contributes the higher seq); it is never the laggard.
    let committed = PolicyVersion(9);
    let coord = ThreeConsumerCoordinator {
        dnsgate_applied_seq: 8, // ds-dnsgate (the admitter) still finishing its sweep
        nft_applied_seq: 9,
    };
    let tlsproxy_swept = sweep_snapshots(committed);
    assert_eq!(
        tlsproxy_swept,
        PolicyVersion(9),
        "ds-tlsproxy swept to vN+1 immediately"
    );
    assert_eq!(
        coord.heartbeat_applied_seq(committed),
        PolicyVersion(8),
        "the min is held at vN by the lagging admitter, NOT by ds-tlsproxy"
    );
}

#[test]
fn sweep_snapshots_never_errors_across_a_range_of_seqs_including_a_booting_host() {
    // The SweepSnapshots callback is total: it cannot fail (a no-op sweep has nothing to
    // fail at), so the host coordinator can fold it unconditionally — including seq 0,
    // the booting-host case before any flip beyond NFT-1 default-deny.
    for seq in [0u64, 1, 2, 42, u64::MAX] {
        assert_eq!(sweep_snapshots(PolicyVersion(seq)), PolicyVersion(seq));
    }
}
