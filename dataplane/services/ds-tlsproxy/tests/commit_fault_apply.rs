// SPDX-License-Identifier: Apache-2.0

//! Integration coverage for ds-tlsproxy's runtime-injectable commit-fault hook
//! (POL-4 / D72; doc 12 §8 the "Fault-injection hook" detail, doc 13 §5).
//!
//! The hook lets the host apply driver and the LOG-4 skew test
//! (`contract-tests::pol4_skew_test`) stall ds-tlsproxy's `commit` so the
//! transient TLS-staged-but-not-committed-while-dnsgate-on-vN window is
//! exercised. As the enforcer the proxy is committed BEFORE the admitter
//! (make-before-break), so a stalled commit that reverts to `vN` keeps that
//! window FAIL-CLOSED: the proxy on `vN` is at-least-as-strict as the still-`vN`
//! admitter, and the host driver aborts host-wide on the `CommitFailed`.
//!
//! These tests drive ONLY the published crate API — `ds_tlsproxy::apply`'s
//! `PolicyConsumer::{new, set_commit_fault, live, applied_seq}` plus the frozen
//! `ds_contracts::consumer::Consumer` two-phase seam — so they pin the hook as a
//! supported, runtime-injectable surface (not a compile-time test-only knob): the
//! same `set_commit_fault(bool)` the host driver / test harness call.

use ds_contracts::consumer::{ApplyError, Consumer, PolicyVersion};
use ds_contracts::pol1;
use ds_tlsproxy::apply::{Evaluator, PolicyConsumer};

/// A clean POL-1 session layer the proxy boots and re-stages against.
const VALID_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                         dns:\n  boundary_zone: corp.example.\n";

/// A distinct, still-valid `vN+1` document.
const NEXT_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                        dns:\n  boundary_zone: next.example.\n";

/// Seed a consumer already serving `seq` from the public compose path the proxy
/// boots with (verify→parse→compose via `Evaluator::from_layer`).
fn consumer_at(seq: u64, doc: &str) -> PolicyConsumer {
    let layer = pol1::parse_layer(doc).expect("seed layer parses");
    PolicyConsumer::new(Evaluator::from_layer(&layer), PolicyVersion(seq))
}

/// The full acceptance sequence (doc 12 §8): arm the fault → the next commit
/// fails fail-closed with `CommitFailed` → the proxy stays on `vN`, the stage is
/// left intact and `applied_seq` is unmoved → a re-driven commit of the SAME
/// token succeeds, flips to `vN+1`, and only the post-commit sweep advances
/// `applied_seq` (D72). Proves the hook is single-use-then-re-drivable and never
/// half-flips.
#[test]
fn armed_commit_fault_fails_closed_then_re_driven_commit_succeeds() {
    let c = consumer_at(7, VALID_DOC);
    let live_before = std::sync::Arc::as_ptr(&c.live());

    let token = c
        .prepare(NEXT_DOC.as_bytes(), PolicyVersion(8))
        .expect("vN+1 stages");

    // (1) Arm the runtime-injectable fault. Operationally a no-op the proxy never
    // sets in steady state; here it stalls the enforcer's commit so the host
    // driver's host-wide abort is exercised.
    c.set_commit_fault(true);

    // (2) The next commit fails-closed with CommitFailed naming vN+1; the reason
    // is the structural guard message and NEVER echoes the document body
    // (NEVER-LOG-THE-SECRET).
    match c.commit(&token) {
        Err(ApplyError::CommitFailed { version, reason }) => {
            assert_eq!(version, PolicyVersion(8), "the stalled commit names vN+1");
            assert_eq!(
                reason, "evaluator pointer-swap guard refused the flip",
                "the documented fault reason"
            );
            assert!(
                !reason.contains("next.example"),
                "reason must not echo the snapshot body"
            );
        }
        other => panic!("expected fail-closed CommitFailed, got {other:?}"),
    }

    // (3) The proxy stayed on vN (the flip was detected un-makeable BEFORE the
    // live pointer was touched); applied_seq is unmoved (it advances only
    // post-sweep, D72).
    assert_eq!(
        std::sync::Arc::as_ptr(&c.live()),
        live_before,
        "the proxy stays serving vN through the faulted commit"
    );
    assert_eq!(
        c.applied_seq(),
        PolicyVersion(7),
        "applied_seq never advances through a faulted commit"
    );

    // (4) The stage is left intact: a re-driven commit of the SAME token succeeds
    // once the fault is disarmed (explicit re-arm semantics — the host driver
    // re-drives; the hook does not loop or stall). A surviving stage is the only
    // way this second commit can flip.
    c.set_commit_fault(false);
    c.commit(&token).expect("re-driven commit flips to vN+1");
    assert_ne!(
        std::sync::Arc::as_ptr(&c.live()),
        live_before,
        "the proxy now serves vN+1 (the staged evaluator survived the fault)"
    );

    // (5) applied_seq advances ONLY after the post-commit sweep completes (D72).
    assert_eq!(
        c.applied_seq(),
        PolicyVersion(7),
        "commit alone does not advance applied_seq"
    );
    let swept = c
        .sweep_and_advance_applied_seq(&token)
        .expect("post-commit sweep advances applied_seq");
    assert_eq!(swept, PolicyVersion(8));
    assert_eq!(
        c.applied_seq(),
        PolicyVersion(8),
        "applied_seq is vN+1 post-sweep"
    );
}

/// The fault is not armed by default — a steady-state commit just flips. Proves
/// the hook is operationally a no-op until explicitly armed (spec requirement 4).
#[test]
fn unarmed_commit_flips_normally() {
    let c = consumer_at(1, VALID_DOC);
    let live_before = std::sync::Arc::as_ptr(&c.live());
    let token = c
        .prepare(NEXT_DOC.as_bytes(), PolicyVersion(2))
        .expect("stage");

    // No set_commit_fault(true): default is disarmed.
    c.commit(&token).expect("unarmed commit flips");
    assert_ne!(
        std::sync::Arc::as_ptr(&c.live()),
        live_before,
        "an unarmed commit flips to vN+1 with no fault"
    );
}

/// Re-arming after a recovery faults the NEXT commit again — the hook is
/// explicitly re-armable (single-use per arm; the host driver re-drives between
/// arms). Exercises the same arm/disarm contract the LOG-4 skew test relies on.
#[test]
fn fault_is_explicitly_re_armable_across_redrives() {
    let c = consumer_at(1, VALID_DOC);

    let t2 = c
        .prepare(NEXT_DOC.as_bytes(), PolicyVersion(2))
        .expect("stage 2");
    c.set_commit_fault(true);
    assert!(
        matches!(c.commit(&t2), Err(ApplyError::CommitFailed { .. })),
        "armed → first commit fails"
    );
    c.set_commit_fault(false);
    c.commit(&t2).expect("re-driven commit 2 succeeds");
    c.sweep_and_advance_applied_seq(&t2).expect("sweep 2");
    assert_eq!(c.applied_seq(), PolicyVersion(2));

    // Re-arm for the next barrier: the fault stalls the v3 commit until disarmed.
    let v3 = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
              dns:\n  boundary_zone: three.example.\n";
    let t3 = c.prepare(v3.as_bytes(), PolicyVersion(3)).expect("stage 3");
    c.set_commit_fault(true);
    assert!(
        matches!(c.commit(&t3), Err(ApplyError::CommitFailed { .. })),
        "re-armed → v3 commit fails-closed"
    );
    assert_eq!(
        c.applied_seq(),
        PolicyVersion(2),
        "still vN through the re-armed fault"
    );
    c.set_commit_fault(false);
    c.commit(&t3).expect("re-driven commit 3 succeeds");
    c.sweep_and_advance_applied_seq(&t3).expect("sweep 3");
    assert_eq!(c.applied_seq(), PolicyVersion(3));
}
