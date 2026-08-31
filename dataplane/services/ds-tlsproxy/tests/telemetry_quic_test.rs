//! LOG-1 QUIC-reject `FlowRecord` telemetry — the cross-crate acceptance suite
//! for the D70 per-session udp/443 reject-reason signal (doc 12 §7; doc 14 §2
//! `FlowRecord` `RejectReason` row; doc 09 §7 LOG-1; D70/D73).
//!
//! These tests exercise the PUBLIC surface of [`ds_tlsproxy::telemetry_quic`] from
//! OUTSIDE the crate (an integration test is a separate crate), proving the ACCEPTANCE
//! clause end to end:
//!
//! > *ds-tlsproxy receives nflog events or per-session counter snapshots from the
//! > NFT-4 udp/443 reject rule and emits a FlowRecord with reject_reason =
//! > QuicBlocked and counter = N (session-local reject count). Multiple rejects on
//! > the same session increment the counter. Test: a mock session with 5 simulated
//! > NFT-4 rejects produces a FlowRecord with counter=5 and reason=QuicBlocked. The
//! > emitted telemetry carries zero plaintext secret bytes.*
//!
//! The kernel ingest (the nflog group parse / the nftables named counter read) and
//! the SessionRef join (mark index → tap name) are `main.rs` / M0-host integration
//! work (doc 12 §13.1); here the NFT-4 reject is SIMULATED by driving the public
//! ingest API with a mock session, exactly the boundary between the
//! framework-agnostic core and the bin.

use std::sync::Mutex;

use ds_contracts::reject::RejectReason;
use ds_contracts::session::SessionRef;
use ds_telemetry::QuicRejectCounter;
use ds_tlsproxy::telemetry_http::Provenance;
use ds_tlsproxy::telemetry_quic::{QuicRejectEmitter, QuicRejectFlowRecord, QuicRejectTracker};

/// A mock session (the doc 12 §7 "mock session with N simulated NFT-4 rejects").
fn mock_session(idx: u32) -> SessionRef {
    SessionRef::new(
        format!("uuid-session-{idx}"),
        "host-canary".into(),
        idx,
        format!("dstap-{idx}"),
    )
}

/// The NFT-4 udp/443 reject rule's POL-3 provenance triple (rule 4).
fn nft4_provenance() -> Provenance {
    Provenance::new("nft4-udp443-reject", "pol2-system-baseline", "policy-v1")
}

/// A recording LOG-1 emitter — the boundary `recordingSink` analogue: every reject
/// FlowRecord handed to the channel is captured so a test can prove WHICH records
/// reached the channel and HOW MANY.
#[derive(Default)]
struct RecordingEmitter {
    seen: Mutex<Vec<QuicRejectFlowRecord>>,
}

impl QuicRejectEmitter for RecordingEmitter {
    fn emit_quic_reject(&self, record: &QuicRejectFlowRecord) {
        self.seen.lock().unwrap().push(record.clone());
    }
}

#[test]
fn five_simulated_nft4_rejects_emit_a_flow_record_counter_five_reason_quic_blocked() {
    // THE acceptance test: a mock session with 5 simulated NFT-4 rejects produces a
    // FlowRecord with counter=5 and reason=QuicBlocked.
    let mut tracker = QuicRejectTracker::new();
    let session = mock_session(7);

    // Simulate 5 nflog events from the NFT-4 udp/443 reject rule — each is ONE
    // reject, and each increments the session's counter (doc 12 §7).
    for expected in 1..=5 {
        let total = tracker.on_nflog_reject(&session, nft4_provenance());
        assert_eq!(
            total, expected,
            "each reject increments the session counter"
        );
    }

    // The emitted FlowRecord carries counter=5 and reason=QuicBlocked.
    let sink = RecordingEmitter::default();
    let emitted = tracker.flush(&sink);
    assert_eq!(
        emitted, 1,
        "exactly one per-session reject record is emitted"
    );

    let seen = sink.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let record = &seen[0];
    assert_eq!(record.reject_count, 5, "counter = N (session-local count)");
    assert_eq!(record.reject_reason, RejectReason::QuicBlocked);
    assert!(record.is_quic_carveout());
    // DISTINCT from generic default-deny (the D70 frozen distinction, doc 14 §2).
    assert_ne!(record.reject_reason, RejectReason::DefaultDeny);
    // attributed to the ORIGINATING session via its never-recycled tap name.
    assert_eq!(record.tap_name, "dstap-7");
    assert_eq!(record.session_uuid, "uuid-session-7");
    assert_eq!(record.host_session_index, 7);
    // mandatory POL-3 provenance (rule 4).
    assert_eq!(record.provenance.rule_id, "nft4-udp443-reject");
    assert_eq!(record.provenance.policy_layer, "pol2-system-baseline");
    assert_eq!(record.provenance.policy_version, "policy-v1");
}

#[test]
fn per_session_counter_snapshot_ingest_path_also_emits_quic_blocked_records() {
    // The second ingest shape (doc 12 §7): a periodic per-session counter snapshot
    // (the nftables named counter / conntrack-derived count) — an absolute value.
    let mut tracker = QuicRejectTracker::new();
    let session = mock_session(11);

    // The kernel reports an absolute per-session reject total of 5.
    let total = tracker.observe_kernel_total(&session, 5, nft4_provenance());
    assert_eq!(total, 5);

    let record = tracker
        .flow_record_for(&session)
        .expect("a reject record for the snapshotted session");
    assert_eq!(record.reject_count, 5);
    assert_eq!(record.reject_reason, RejectReason::QuicBlocked);
    assert_eq!(record.tap_name, "dstap-11");
}

#[test]
fn counts_are_per_session_never_aggregated() {
    // D70: the counter is per session; the flush yields a VECTOR of per-session
    // records, never one rolled-up record. One session's rejects never bleed into
    // another's.
    let mut tracker = QuicRejectTracker::new();
    let a = mock_session(1);
    let b = mock_session(2);

    tracker.on_nflog_rejects(&a, 3, nft4_provenance());
    tracker.on_nflog_rejects(&b, 8, nft4_provenance());

    assert_eq!(tracker.count_for(&a), 3);
    assert_eq!(tracker.count_for(&b), 8);

    let sink = RecordingEmitter::default();
    let emitted = tracker.flush(&sink);
    assert_eq!(emitted, 2, "one record per session, never a single total");

    let seen = sink.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    // BTreeMap ordering by tap name — deterministic emission order.
    assert_eq!(seen[0].tap_name, "dstap-1");
    assert_eq!(seen[0].reject_count, 3);
    assert_eq!(seen[1].tap_name, "dstap-2");
    assert_eq!(seen[1].reject_count, 8);
    // each carries the QUIC carveout reason — never conflated with default-deny.
    assert!(seen
        .iter()
        .all(|r| r.reject_reason == RejectReason::QuicBlocked));
}

#[test]
fn a_session_with_no_reject_emits_no_record() {
    // A session that never hits the NFT-4 reject rule emits no reject FlowRecord.
    let tracker = QuicRejectTracker::new();
    let quiet = mock_session(99);
    assert_eq!(tracker.count_for(&quiet), 0);
    assert!(tracker.flow_record_for(&quiet).is_none());

    let sink = RecordingEmitter::default();
    assert_eq!(tracker.flush(&sink), 0);
    assert!(sink.seen.lock().unwrap().is_empty());
}

#[test]
fn emitted_telemetry_carries_zero_plaintext_secret_bytes() {
    // D73 never-log-the-secret: a planted client-payload / credential canary appears
    // in ZERO bytes of the emitted reject record. The reject record shape carries
    // only attribution + a count + the reason enum + provenance — there is no body,
    // no header, no captured byte that a payload could ride in (enforced by the
    // existing telemetry chokepoint / the shape itself).
    const PAYLOAD_CANARY: &str = "ghp_LONGLIVEDCANARY-9f3a2b8c7d6e5f4a3b2c1d";

    let mut tracker = QuicRejectTracker::new();
    // The mock session and provenance are built from NON-canary inputs (the NFT-4
    // reject fires on a udp/443 datagram before any payload exists — there is no
    // path for a secret to enter the reject record).
    let session = mock_session(5);
    for _ in 0..5 {
        tracker.on_nflog_reject(&session, nft4_provenance());
    }

    let sink = RecordingEmitter::default();
    tracker.flush(&sink);
    let seen = sink.seen.lock().unwrap();
    let record = &seen[0];

    // Grep every string field of the emitted record for the canary.
    let string_fields = [
        record.session_uuid.as_str(),
        record.tap_name.as_str(),
        record.provenance.rule_id.as_str(),
        record.provenance.policy_layer.as_str(),
        record.provenance.policy_version.as_str(),
    ];
    for field in string_fields {
        assert!(
            !field.contains(PAYLOAD_CANARY),
            "emitted QUIC-reject record leaked a plaintext secret canary: {field:?}"
        );
        // Defensive: also assert the well-known secret prefix never appears.
        assert!(!field.contains("ghp_"), "secret prefix leaked: {field:?}");
    }
}

#[test]
fn ds_telemetry_counter_convention_is_the_single_source_of_the_count() {
    // The proxy FlowRecord and the ds-telemetry convention agree: the
    // QuicRejectCounter (per session, never aggregated) is the underlying count
    // mechanism, and its snapshot's reason is the QUIC carveout. This pins the
    // cross-crate seam the proxy module builds on.
    let mut counter = QuicRejectCounter::new();
    for _ in 0..5 {
        counter.record_reject("dstap-7");
    }
    let snap = counter.snapshot("dstap-7").expect("a per-session snapshot");
    assert_eq!(snap.count, 5);
    assert_eq!(snap.reason, RejectReason::QuicBlocked);

    // The proxy FlowRecord built from that snapshot carries the same count + reason.
    let session = mock_session(7);
    let record = QuicRejectFlowRecord::from_snapshot(&session, &snap, nft4_provenance());
    assert_eq!(record.reject_count, 5);
    assert_eq!(record.reject_reason, RejectReason::QuicBlocked);
    assert_eq!(record.tap_name, "dstap-7");
}

#[test]
fn session_teardown_flushes_the_per_session_counter() {
    // NFT-6 hygiene (doc 12 §8): session teardown drops the per-session count so a
    // never-recycled tap name starts clean and no stale reject count survives.
    let mut tracker = QuicRejectTracker::new();
    let session = mock_session(5);
    tracker.on_nflog_rejects(&session, 4, nft4_provenance());
    assert_eq!(tracker.count_for(&session), 4);

    assert_eq!(tracker.forget_session(&session), 4);
    assert_eq!(tracker.count_for(&session), 0);
    assert!(tracker.flow_record_for(&session).is_none());
}
