// SPDX-License-Identifier: Apache-2.0

//! Integration suite for the ds-dnsgate POST-COMMIT REVOCATION SWEEP, WIRED INTO THE
//! COMMITTED APPLY PATH (POL-4 part 3; D72/D53/D36, doc 13 §5, doc 11 §5.4, doc 15 §5.2).
//!
//! This drives the END-TO-END property the D72 `applied_seq` binding requires, NOT a pure
//! function in isolation: the public [`ds_dnsgate::apply::PolicyConsumer`] (the consumer
//! seam the host agent's prepare/commit/sweep barrier invokes) is built WITH the revocation
//! sweep wired ([`PolicyConsumer::with_revocation_sweep`]) over the SAME live derived-state
//! registry the W1/W2 admission transaction mints into and the POL-5 approval path parks
//! ask-grants in. The suite then asserts:
//!
//!   1. `applied_seq` does NOT advance on `commit` — only the post-commit sweep advances it
//!      (D72), and ONLY after the eviction (both legs) completes.
//!   2. The sweep re-evaluates BOTH legs — the DNS-2b admissions AND the parked ask-grants —
//!      against the just-committed `vN+1`, evicting what the new policy denies.
//!   3. The rung-conditional shared `flush_session` severing fires for the block-or-higher
//!      evictions and is withheld for non-severing ones (D53), routed to the bound enforcer.
//!
//! All against the FROZEN `policy_core::consumer::dns_admission_decision` evaluator (no rule
//! re-implemented) and the ONE shared reverse-index refcount (no forked survivor count).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use ds_contracts::consumer::{ApplyToken, Consumer, PolicyVersion};
use ds_contracts::pol1::parse_layer;
use ds_contracts::snapshot_verify::sha256;

use ds_dnsgate::apply::{Evaluator, PolicyConsumer};
use ds_dnsgate::policy::PolicyCorePolicy;
use ds_dnsgate::server::{LiveAdmission, LiveAdmissions, LiveAskGrant, RecordingSweepEnforcer};
use policy_core::pol1_eval::compose;

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// The vN seed: a permissive standard policy that admits the names the test admits.
const SEED_VN: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
     allowlist:\n  - domain: keep.example\n  - domain: evil0.example\n  - domain: evil1.example\n  \
     - domain: grant-keep.example\n  - domain: grant-block.example\n";

/// The vN+1 the apply commits: BLOCKS evil0/evil1/grant-block at a SEVERING rung (block+log)
/// and keeps keep/grant-keep — so the sweep flips 2 admissions + 1 ask-grant to denied.
const NEXT_VN1: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
     allowlist:\n  - domain: keep.example\n  - domain: grant-keep.example\n\
     blocklist:\n  - domain: evil0.example\n    reason: r\n    rung: block+log\n  \
     - domain: evil1.example\n    reason: r\n    rung: block+log\n  \
     - domain: grant-block.example\n    reason: r\n    rung: block+log\n";

fn seed_evaluator(doc: &str) -> Evaluator {
    Evaluator::from_layer(&parse_layer(doc).expect("seed layer parses"))
}

/// Build a `PolicyCorePolicy` (the gate's running evaluator) over `doc` — the shared-handle
/// evaluator the consumer's commit re-sources and the sweep re-evaluates against.
fn running_evaluator(doc: &str) -> PolicyCorePolicy {
    let layer = parse_layer(doc).expect("layer parses");
    PolicyCorePolicy::new(compose(std::slice::from_ref(&layer), &[]))
}

/// Build a consumer WITH the sweep wired over a populated live registry. Returns the
/// consumer, the shared registry, and the recording enforcer so the test asserts both the
/// eviction and the routed enforcement.
fn wired_consumer() -> (PolicyConsumer, LiveAdmissions, Arc<RecordingSweepEnforcer>) {
    let session = "dstap-7/sess-1";
    let admissions = LiveAdmissions::new();
    // 1 admission that still admits under vN+1, 2 that flip to denied (severing).
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
    // 1 ask-grant that still admits, 1 that flips to denied (severing) — the genuinely-new leg.
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

    let enforcer = Arc::new(RecordingSweepEnforcer::new());
    let consumer = PolicyConsumer::with_revocation_sweep(
        seed_evaluator(SEED_VN),
        PolicyVersion(1),
        admissions.clone(),
        running_evaluator(SEED_VN),
        enforcer.clone(),
    );
    (consumer, admissions, enforcer)
}

fn token_for(bytes: &[u8], seq: u64) -> ApplyToken {
    ApplyToken::new(PolicyVersion(seq), sha256(bytes))
}

/// THE D72 PROPERTY: `applied_seq` advances ONLY after the post-commit sweep completes — not
/// on `commit`. The commit flips the evaluator to vN+1; the sweep then evicts the now-denied
/// admissions AND ask-grants before `applied_seq` moves.
#[test]
fn applied_seq_does_not_advance_until_the_post_commit_sweep_completes() {
    let (consumer, admissions, enforcer) = wired_consumer();

    let token = consumer
        .prepare(NEXT_VN1.as_bytes(), PolicyVersion(2))
        .expect("prepare stages vN+1");

    // COMMIT flips the evaluator but does NOT advance applied_seq (D72) and runs NO sweep yet.
    consumer.commit(&token).expect("commit");
    assert_eq!(
        consumer.applied_seq(),
        PolicyVersion(1),
        "applied_seq stays at vN until the sweep completes"
    );
    assert_eq!(
        admissions.len(),
        3,
        "no eviction on commit — the sweep has not run"
    );
    assert_eq!(admissions.ask_grant_len(), 2, "no grant eviction on commit");
    assert!(
        enforcer.withdrawn().is_empty() && enforcer.flushed().is_empty(),
        "no enforcement routed before the sweep"
    );

    // THE SWEEP advances applied_seq — and only now, after evicting both legs.
    let swept = consumer
        .sweep_and_advance_applied_seq(&token)
        .expect("sweep advances applied_seq");
    assert_eq!(swept, PolicyVersion(2));
    assert_eq!(
        consumer.applied_seq(),
        PolicyVersion(2),
        "applied_seq advances ONLY after the sweep completes (D72)"
    );

    // Both legs swept against vN+1: 2 admissions + 1 ask-grant evicted, the rest survive.
    assert_eq!(admissions.len(), 1, "keep.example survives");
    assert_eq!(admissions.snapshot()[0].fqdn, "keep.example.");
    assert_eq!(admissions.ask_grant_len(), 1, "grant-keep survives");
    assert_eq!(
        admissions.ask_grant_snapshot()[0].fqdn,
        "grant-keep.example."
    );
}

/// The eviction is REAL and routed to enforcement: the freed allow-set elements are
/// withdrawn and the rung-conditional `flush_session` severs the block+log evictions (D53),
/// driven through the live commit path — not a pure-function call.
#[test]
fn the_committed_sweep_routes_eviction_and_rung_conditional_severing() {
    let (consumer, _admissions, enforcer) = wired_consumer();
    let token = consumer
        .prepare(NEXT_VN1.as_bytes(), PolicyVersion(2))
        .expect("prepare");
    consumer.commit(&token).expect("commit");
    consumer
        .sweep_and_advance_applied_seq(&token)
        .expect("sweep");

    // 3 freed IPs (2 admissions + 1 grant, none shared) withdrawn from the allow set.
    assert_eq!(
        enforcer.withdrawn().len(),
        3,
        "3 freed allow-set withdrawals"
    );

    // One severing flush for the single session, narrowed to the 3 freed severing IPs.
    let flushes = enforcer.flushed();
    assert_eq!(flushes.len(), 1, "one rung-conditional flush per session");
    assert_eq!(
        flushes[0].dst_keys.len(),
        3,
        "narrowed to the freed severing IPs (D53)"
    );
}

/// IDEMPOTENT on the token (D72): a re-driven `sweep_and_advance_applied_seq` for the same
/// already-swept token does not re-sweep or re-evict — applied_seq stays put and the registry
/// is unchanged.
#[test]
fn re_driven_sweep_is_idempotent_and_does_not_re_evict() {
    let (consumer, admissions, enforcer) = wired_consumer();
    let token = consumer
        .prepare(NEXT_VN1.as_bytes(), PolicyVersion(2))
        .expect("prepare");
    consumer.commit(&token).expect("commit");
    consumer
        .sweep_and_advance_applied_seq(&token)
        .expect("sweep 1");

    let withdrawn_after_first = enforcer.withdrawn().len();
    let live_after_first = admissions.len();
    let grants_after_first = admissions.ask_grant_len();

    // A second sweep on the same token is an idempotent no-op success.
    consumer
        .sweep_and_advance_applied_seq(&token)
        .expect("sweep 2 (idempotent)");
    assert_eq!(consumer.applied_seq(), PolicyVersion(2));
    assert_eq!(
        enforcer.withdrawn().len(),
        withdrawn_after_first,
        "no re-routing on the idempotent re-sweep"
    );
    assert_eq!(admissions.len(), live_after_first);
    assert_eq!(admissions.ask_grant_len(), grants_after_first);
}

/// A BARE two-phase consumer (no sweep wired) is unchanged: its sweep is the trivial advance
/// (nothing to re-decide), so the prepare/commit-only callers keep working.
#[test]
fn bare_consumer_without_a_wired_sweep_still_advances_seq() {
    let consumer = PolicyConsumer::new(seed_evaluator(SEED_VN), PolicyVersion(1));
    let token = token_for(NEXT_VN1.as_bytes(), 2);
    let t = consumer
        .prepare(NEXT_VN1.as_bytes(), PolicyVersion(2))
        .expect("prepare");
    assert_eq!(t.content_hash, token.content_hash);
    consumer.commit(&t).expect("commit");
    assert_eq!(
        consumer.applied_seq(),
        PolicyVersion(1),
        "no advance on commit"
    );
    let swept = consumer
        .sweep_and_advance_applied_seq(&t)
        .expect("trivial sweep advances");
    assert_eq!(swept, PolicyVersion(2));
    assert_eq!(consumer.applied_seq(), PolicyVersion(2));
}
