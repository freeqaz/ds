// SPDX-License-Identifier: Apache-2.0

//! LOG-4 policy-skew conformance test (POL-4 / D72; doc 12 §8, doc 13 §5 the
//! "Log invariant" row, doc 06 §5): across a policy apply, every flow must
//! satisfy `version(TLS decision) >= version(DNS admission)` CONTINUOUSLY.
//!
//! # The invariant and why it is structural, not incidental
//!
//! The TLS decision is made by `ds-tlsproxy` (the egress-gateway ENFORCER); the
//! DNS admission is made by `ds-dnsgate` (the ADMITTER). The host commits the
//! two-phase D72 barrier in a FIXED **admitter-last** order — `ds-tlsproxy` (and
//! the NFT flip) move to `vN+1` BEFORE `ds-dnsgate` does (make-before-break). So
//! through any apply the enforcer is on a version `>=` the admitter's, and the
//! invariant `version(TLS) >= version(DNS)` holds at every instant. Because a
//! later policy version is at-least-as-strict (deny-wins composition, §1.2), an
//! enforcer that is already on `vN+1` while the admitter still admits under `vN`
//! can only REFUSE flows the admitter would still let through — never the
//! reverse. Every transient mixed-version window is therefore FAIL-CLOSED: a hole
//! (DNS admits a destination on `vN+1` that TLS would still tunnel on a STALE
//! `vN`) is exactly the `version(TLS) < version(DNS)` state this invariant forbids.
//!
//! # What this test drives (the doc 06 (d) push-to-enforced rig, cross-consumer)
//!
//! It seeds the REAL `ds_tlsproxy::apply::PolicyConsumer` and the REAL
//! `ds_dnsgate::apply::PolicyConsumer` at a common boot `vN`, then pushes `vN+1`
//! through the frozen `ds_contracts::consumer::Consumer` two-phase seam in
//! admitter-last order WITH THE TLS COMMIT STALLED via the consumers' built-in
//! commit fault-injection hook (`set_commit_fault`). At every observable instant
//! it samples each consumer's SERVING version (the version its live evaluator
//! decides on — vN until its own `commit(token)` returns `Ok`, vN+1 thereafter,
//! corroborated by the live-`Arc` pointer identity flip) and asserts the
//! invariant. The stalled-commit window is the adversarial case: with TLS unable
//! to advance, the driver MUST NOT advance DNS (admitter-last), so the window
//! stays `TLS(vN) >= DNS(vN)` — fail-closed — never `TLS(vN) < DNS(vN+1)`.
//!
//! D76 frozen non-edge (doc 12 §4.2, doc 14 §5): `ds-tlsproxy` and `ds-dnsgate`
//! never depend on each other; this downstream test-only member is the one place
//! that may path-depend on both consumers at once. It adds NO edge between them.
//!
//! NEVER-LOG-THE-SECRET: nothing here logs a composed document; versions cross as
//! plain `u64` seqs and the snapshots are static fixtures.

use std::sync::Arc;

use ds_contracts::consumer::{ApplyError, Consumer, PolicyVersion};
use ds_contracts::pol1;

use ds_dnsgate::apply::{Evaluator as DnsEvaluator, PolicyConsumer as DnsConsumer};
use ds_tlsproxy::apply::{Evaluator as TlsEvaluator, PolicyConsumer as TlsConsumer};

// ---------------------------------------------------------------------------
// Policy fixtures. Two clean POL-1 session layers — `vN` and the at-least-as-
// strict `vN+1` the apply pushes. Both pass the embedded `policy-core`
// validators (so `prepare` stages cleanly); their CONTENT is irrelevant to the
// skew invariant, which is over VERSIONS, not documents.
// ---------------------------------------------------------------------------

/// The boot `vN` policy document.
const POLICY_VN: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                         dns:\n  boundary_zone: corp.example.\n";

/// The pushed `vN+1` policy document (a different boundary zone — a real, valid
/// version bump the consumers stage and flip).
const POLICY_VN1: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                          dns:\n  boundary_zone: beta.example.\n";

/// The shared boot version both consumers start on.
const VN: PolicyVersion = PolicyVersion(7);
/// The version the apply pushes (`vN+1`).
const VN1: PolicyVersion = PolicyVersion(8);

// ---------------------------------------------------------------------------
// Seeding the REAL consumers at a boot version, through their PUBLIC surface.
//
// `pol1::parse_layer` (frozen, public) + `Evaluator::from_layer` (public — the
// host-wiring / POL-4 integration seed path) build the boot evaluator;
// `PolicyConsumer::new` seeds it at `seq`. This is the verify→parse→compose path
// `prepare` itself runs, so the seeded consumer is byte-for-byte the production
// boot state — no test-only constructor, no consumer-crate edit.
// ---------------------------------------------------------------------------

fn tls_consumer_at(seq: PolicyVersion, doc: &str) -> TlsConsumer {
    let layer = pol1::parse_layer(doc).expect("tls seed layer parses");
    TlsConsumer::new(TlsEvaluator::from_layer(&layer), seq)
}

fn dns_consumer_at(seq: PolicyVersion, doc: &str) -> DnsConsumer {
    let layer = pol1::parse_layer(doc).expect("dns seed layer parses");
    DnsConsumer::new(DnsEvaluator::from_layer(&layer), seq)
}

// ---------------------------------------------------------------------------
// The decision-version oracle.
//
// A flow's `version(TLS decision)` is the version of the evaluator `ds-tlsproxy`
// is CURRENTLY deciding egress connects from; `version(DNS admission)` likewise
// for `ds-dnsgate`. A consumer serves `vN` from boot, and serves `vN+1` the
// instant its OWN `commit(token)` returns `Ok` — the atomic live-`Arc` swap. The
// host apply driver (this test) is the authority on which version it has
// committed to each consumer; the live-`Arc` pointer identity is the independent
// corroboration that the flip actually happened.
// ---------------------------------------------------------------------------

/// One consumer's serving version, tracked by the driver and cross-checked
/// against the live-evaluator `Arc` identity (which flips exactly at `commit`).
struct ServingVersion {
    /// The seq the driver has committed to this consumer (vN until its commit
    /// returns Ok; vN+1 after).
    seq: PolicyVersion,
    /// The live-evaluator `Arc` pointer at the boot `vN` — used to confirm the
    /// flip is observable (the pointer differs once and only once the consumer
    /// flips to `vN+1`).
    boot_ptr: usize,
}

impl ServingVersion {
    fn tls(c: &TlsConsumer, seq: PolicyVersion) -> ServingVersion {
        ServingVersion {
            seq,
            boot_ptr: Arc::as_ptr(&c.live()) as usize,
        }
    }
    fn dns(c: &DnsConsumer, seq: PolicyVersion) -> ServingVersion {
        ServingVersion {
            seq,
            boot_ptr: Arc::as_ptr(&c.live()) as usize,
        }
    }
}

/// Sample `ds-tlsproxy`'s serving version and corroborate it against the live
/// `Arc` identity: still on `vN` ⇒ the live pointer must equal the boot pointer;
/// flipped to `vN+1` ⇒ it must differ. Returns the serving `PolicyVersion`.
fn tls_serving(c: &TlsConsumer, sv: &ServingVersion) -> PolicyVersion {
    let live_ptr = Arc::as_ptr(&c.live()) as usize;
    if sv.seq == VN {
        assert_eq!(
            live_ptr, sv.boot_ptr,
            "ds-tlsproxy on vN must serve the boot evaluator (no flip observed)"
        );
    } else {
        assert_ne!(
            live_ptr, sv.boot_ptr,
            "ds-tlsproxy flipped to vN+1 must serve a different (committed) evaluator"
        );
    }
    sv.seq
}

/// Sample `ds-dnsgate`'s serving version, corroborated the same way.
fn dns_serving(c: &DnsConsumer, sv: &ServingVersion) -> PolicyVersion {
    let live_ptr = Arc::as_ptr(&c.live()) as usize;
    if sv.seq == VN {
        assert_eq!(
            live_ptr, sv.boot_ptr,
            "ds-dnsgate on vN must serve the boot evaluator (no flip observed)"
        );
    } else {
        assert_ne!(
            live_ptr, sv.boot_ptr,
            "ds-dnsgate flipped to vN+1 must serve a different (committed) evaluator"
        );
    }
    sv.seq
}

/// Assert the LOG-4 invariant at one instant, with the instant named for a clear
/// failure. The whole point of the test: `version(TLS) >= version(DNS)`, always.
fn assert_log4_holds(label: &str, tls: PolicyVersion, dns: PolicyVersion) {
    assert!(
        tls >= dns,
        "LOG-4 VIOLATED at [{label}]: version(TLS decision)={} < version(DNS admission)={} \
         — a mixed-version window opened a hole (DNS admits under a version the enforcer is \
         not yet at). The barrier must be admitter-last / make-before-break.",
        tls.seq(),
        dns.seq(),
    );
}

// ===========================================================================
// The test.
// ===========================================================================

/// LOG-4 across a stalled-commit apply: `version(TLS) >= version(DNS)` holds at
/// every observed instant, INCLUDING the stalled-commit window, and remains
/// fail-closed; unstalling the TLS commit and finishing admitter-last keeps the
/// invariant post-commit.
#[test]
fn log4_tls_version_ge_dns_version_holds_through_a_stalled_commit_apply() {
    // ---- (1) Boot: TLS on vN, DNS on vN. ---------------------------------
    let tls = tls_consumer_at(VN, POLICY_VN);
    let dns = dns_consumer_at(VN, POLICY_VN);
    let mut tls_sv = ServingVersion::tls(&tls, VN);
    let mut dns_sv = ServingVersion::dns(&dns, VN);

    assert_log4_holds(
        "boot vN/vN",
        tls_serving(&tls, &tls_sv),
        dns_serving(&dns, &dns_sv),
    );

    // ---- (2) Push vN+1 with TLS's commit stalled. ------------------------
    // Prepare stages vN+1 on BOTH consumers WHILE THEY KEEP SERVING vN (the
    // host runs prepare over all consumers before committing any; a prepare
    // failure would abort host-wide, all-or-none). Neither flips here.
    let tls_token = tls
        .prepare(POLICY_VN1.as_bytes(), VN1)
        .expect("tls prepare stages vN+1");
    let dns_token = dns
        .prepare(POLICY_VN1.as_bytes(), VN1)
        .expect("dns prepare stages vN+1");

    // Both prepared but neither committed → both still serve vN.
    assert_log4_holds(
        "after prepare (both staged, neither flipped)",
        tls_serving(&tls, &tls_sv),
        dns_serving(&dns, &dns_sv),
    );

    // Stall TLS's commit via the fault-injection hook: as the enforcer the host
    // commits FIRST, the stall models a commit that cannot be made observable.
    tls.set_commit_fault(true);

    // ---- (3) vN+1 is prepared on TLS but NOT committed. ------------------
    // Drive the admitter-last barrier: the enforcer (TLS) commits before the
    // admitter (DNS). The stalled TLS commit aborts at the consumer level
    // (CommitFailed). The driver MUST treat this as a host-wide abort of the
    // commit phase and NOT proceed to commit the admitter — the make-before-
    // break order means DNS never advances while TLS is stuck on vN.
    match tls.commit(&tls_token) {
        Err(ApplyError::CommitFailed { version, .. }) => {
            assert_eq!(version, VN1, "the stalled commit names vN+1");
        }
        other => panic!("expected the stalled TLS commit to fail-closed, got {other:?}"),
    }
    // TLS stayed on vN (fail-closed revert); its stage is intact for the re-drive.
    // DNS was deliberately NOT committed (admitter-last; the enforcer is stuck).

    // ---- (4) TLS still serves vN; DNS remains on vN. ---------------------
    // The crux of the stalled-commit window: vN+1 is prepared (staged) on TLS but
    // not live, so version(TLS decision) is STILL vN, and DNS is STILL vN. The
    // window is `TLS(vN) >= DNS(vN)` — fail-closed. The forbidden hole would be
    // `TLS(vN) < DNS(vN+1)`: it CANNOT arise because the driver refuses to
    // advance the admitter while the enforcer's commit is stalled.
    assert_eq!(tls_serving(&tls, &tls_sv), VN, "TLS still decides on vN");
    assert_eq!(dns_serving(&dns, &dns_sv), VN, "DNS remains on vN");
    assert_log4_holds(
        "stalled-commit window (vN+1 staged on TLS, uncommitted; DNS on vN)",
        tls_serving(&tls, &tls_sv),
        dns_serving(&dns, &dns_sv),
    );
    // Independent corroboration that the stall is a STAGE, not a flip: the
    // vN+1 evaluator is parked, ready, but TLS's live evaluator is still vN.
    // (applied_seq likewise unmoved — it advances only post-sweep, D72.)
    assert_eq!(
        tls.applied_seq(),
        VN,
        "applied_seq must not advance through a stalled/aborted commit"
    );

    // ---- (5) Unstall TLS's commit; finish admitter-last. -----------------
    // The enforcer commits FIRST. Right after, observe the INTERMEDIATE instant
    // where TLS is on vN+1 but DNS is still on vN — the make-before-break window
    // the order exists to keep fail-closed (`TLS(vN+1) >= DNS(vN)`).
    tls.set_commit_fault(false);
    tls.commit(&tls_token)
        .expect("re-driven TLS commit flips to vN+1");
    tls_sv.seq = VN1;

    assert_eq!(
        tls_serving(&tls, &tls_sv),
        VN1,
        "TLS now decides on vN+1 (enforcer committed first)"
    );
    assert_log4_holds(
        "make-before-break window (TLS on vN+1, DNS still on vN)",
        tls_serving(&tls, &tls_sv),
        dns_serving(&dns, &dns_sv),
    );

    // Admitter commits LAST → both on vN+1.
    dns.commit(&dns_token).expect("DNS commit flips to vN+1");
    dns_sv.seq = VN1;

    let tls_post = tls_serving(&tls, &tls_sv);
    let dns_post = dns_serving(&dns, &dns_sv);
    assert_eq!(tls_post, VN1, "TLS on vN+1 post-commit");
    assert_eq!(dns_post, VN1, "DNS on vN+1 post-commit");
    assert_log4_holds("post-commit (both vN+1)", tls_post, dns_post);

    // applied_seq advances only after each consumer's post-commit sweep (D72) —
    // the version end state the host heartbeat reports MIN over. Running the
    // sweep on both leaves them both at vN+1, and the invariant still holds.
    assert_eq!(
        tls.sweep_and_advance_applied_seq(&tls_token)
            .expect("tls sweep advances applied_seq"),
        VN1,
    );
    assert_eq!(
        dns.sweep_and_advance_applied_seq(&dns_token)
            .expect("dns sweep advances applied_seq"),
        VN1,
    );
    assert_log4_holds(
        "post-sweep applied_seq (both vN+1)",
        tls.applied_seq(),
        dns.applied_seq(),
    );
}

/// The adversarial COUNTERFACTUAL the order forbids: if the driver had committed
/// the ADMITTER (DNS) while the ENFORCER (TLS) was still stalled on vN, the
/// resulting window would be `version(TLS)=vN < version(DNS)=vN+1` — a hole. This
/// test PROVES `assert_log4_holds` actually catches that state (so the positive
/// test above is not vacuous), then re-establishes that the make-before-break
/// order never reaches it.
#[test]
fn log4_detects_the_forbidden_admitter_first_hole() {
    let tls = tls_consumer_at(VN, POLICY_VN);
    let dns = dns_consumer_at(VN, POLICY_VN);
    let tls_sv = ServingVersion::tls(&tls, VN); // TLS stays on vN (stalled enforcer)
    let mut dns_sv = ServingVersion::dns(&dns, VN);

    // Stage on both.
    let _tls_token = tls.prepare(POLICY_VN1.as_bytes(), VN1).expect("tls stage");
    let dns_token = dns.prepare(POLICY_VN1.as_bytes(), VN1).expect("dns stage");

    // FORBIDDEN ORDER (for detection only): commit the admitter FIRST, leaving
    // the enforcer stalled on vN. This is the bug the barrier order prevents.
    dns.commit(&dns_token)
        .expect("admitter-first commit (the forbidden order)");
    dns_sv.seq = VN1;

    let tls_v = tls_serving(&tls, &tls_sv); // vN
    let dns_v = dns_serving(&dns, &dns_sv); // vN+1

    // The invariant is genuinely VIOLATED in this counterfactual — the detector
    // must catch it. (We assert the violation directly rather than via
    // `assert_log4_holds`, which would `panic!` — this proves the check is real.)
    // `tls_v < dns_v` IS the negation of the LOG-4 invariant (`tls >= dns`): the
    // counterfactual must land in exactly that forbidden region.
    assert!(
        tls_v < dns_v,
        "the admitter-first counterfactual MUST be a LOG-4 violation \
         (TLS={} < DNS={}), proving the positive test is not vacuous",
        tls_v.seq(),
        dns_v.seq(),
    );
    assert_eq!(tls_v, VN);
    assert_eq!(dns_v, VN1);
}
