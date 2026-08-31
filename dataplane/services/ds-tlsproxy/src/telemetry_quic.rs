//! LOG-1 QUIC-reject `FlowRecord` telemetry — the D70 udp/443 reject-reason
//! signal wired into the proxy's LOG-1 emission path (doc 12 §7; doc 14 §2
//! `FlowRecord` `RejectReason` row; doc 09 §7 LOG-1; D70/D73).
//!
//! # What this is
//!
//! D70 freezes the udp/443 (QUIC) posture: the NFT-4 rule **rejects** udp/443
//! with icmp port-unreachable — *never silently dropped* — and **counts every
//! reject per session**. doc 12 §7's telemetry clause:
//!
//! > *"the reject rule carries a per-session counter and the LOG-1 schema
//! > includes a reject-reason code distinguishing `quic-blocked` from generic
//! > default-deny."*
//!
//! This module is the proxy-side LOG-1 `FlowRecord` SHAPE for that signal: it
//! ingests the kernel's NFT-4 udp/443 reject events (nflog events, or a periodic
//! per-session counter snapshot — doc 12 §7 design seam), accumulates them PER
//! SESSION via the [`ds_telemetry::QuicRejectCounter`] convention, and emits a
//! [`QuicRejectFlowRecord`] carrying `reject_reason = [`RejectReason::QuicBlocked`]`
//! and `reject_count = N` (the session-local reject count) attributed to the
//! originating session by its `dstap-<idx>` tap name (doc 14 §4).
//!
//! It mirrors [`crate::telemetry_http`] exactly: a local, pingora-free event
//! SHAPE keyed on the [`ds_contracts::session::SessionRef`] tap name (LOG-2
//! attribution) and carrying the mandatory POL-3 provenance triple. The kernel
//! ingest (parsing the nflog group / reading the nftables named counter) and the
//! pingora I/O live in `main.rs`; this module is the framework-agnostic core that
//! turns plain `(session, count)` values into the LOG-1 reject record. The
//! per-session counting convention lives in `ds-telemetry`
//! ([`ds_telemetry::QuicRejectCounter`]) so the "per session, never aggregated"
//! invariant has one home; this module owns the proxy's `FlowRecord` shape +
//! the per-session tracker + the emission seam.
//!
//! # Why a local shape and not a `ds-contracts` import
//!
//! The generated LOG-1 protos do NOT yet exist in `ds-contracts` (the Stage-0
//! freeze under its `src/gen/` is undelivered). So, exactly as
//! [`crate::telemetry_http`] does for the per-request / netflow records, we define
//! the reject-record SHAPE locally here. The `RejectReason` enum, however, IS
//! already frozen in `ds-contracts` ([`ds_contracts::reject::RejectReason`], the
//! D70 row), so the reason code is single-sourced from the contract — never a
//! re-declared variant. **Migration note:** when the LOG-1 Stage-0 freeze lands,
//! [`QuicRejectFlowRecord`] migrates onto the generated `FlowRecord` (whose
//! `reject_reason` field carries this same enum); the field set chosen here is the
//! boundary's, so the swap is mechanical.
//!
//! # Never-log-the-secret (D73 §5.1) — a TYPE-LEVEL property
//!
//! A QUIC-reject record carries ZERO payload: the only fields are the attribution
//! quartet (`String`/`u32`), the `u64` reject count, and the frozen
//! [`RejectReason`] enum, plus the POL-3 provenance triple. There is no body, no
//! header, no captured byte — the NFT-4 rule fires on a udp/443 datagram before
//! any payload context exists, so the record structurally cannot carry a client
//! byte (the convention TLS-5/TLS-7 rely on). A `#[cfg(test)]` canary additionally
//! greps every string field for a planted payload and asserts zero hits.
//!
//! # D40 pingora confinement (doc 12 §13.1)
//!
//! No pingora type appears here. `main.rs` parses the nflog group / reads the
//! kernel counter and feeds this module plain `(tap_name, count)` values; the
//! pingora / netlink wiring stays in the bin.

#![forbid(unsafe_code)]

use ds_contracts::reject::RejectReason;
use ds_contracts::session::SessionRef;
use ds_telemetry::quic_reject_counter::{QuicRejectCounter, QuicRejectSnapshot};

use crate::telemetry_http::Provenance;

/// A LOG-1 `FlowRecord` for the D70 udp/443 (QUIC) reject (doc 12 §7; doc 14 §2
/// `FlowRecord` `RejectReason` row). Built when a periodic flush (or session
/// teardown) reports a session's accumulated NFT-4 reject count: it carries the
/// LOG-2 attribution key (`tap_name`), the session-local reject `count`, the
/// frozen `reject_reason = [`RejectReason::QuicBlocked`]` (DISTINCT from generic
/// default-deny so the flip-to-inspect trigger is queryable off-box), and the
/// mandatory POL-3 provenance triple.
///
/// # Field set (LOG-1 `FlowRecord` reject parity, doc 14 §2)
///
/// doc 14 §2 freezes the `FlowRecord` `RejectReason` row: the udp/443 reject is
/// "counted per session; the reason code is what makes the D70 flip-to-inspect
/// trigger queryable off-box". The fields here are exactly that datum — the
/// session attribution quartet, the per-session count, and the reason code —
/// plus the rule-4 mandatory provenance.
///
/// # Never-log-the-secret (D73): a TYPE-LEVEL property
///
/// The only fields are `String`/`u32` attribution, a `u64` count, the
/// [`RejectReason`] enum, and the provenance triple — no body, no header value,
/// no `Secret`, no captured byte. A reject record cannot carry a client-payload
/// byte because the shape carries none (the boundary's leak canary finds nothing
/// to leak).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicRejectFlowRecord {
    /// The orchestrator session UUID — the global identity (LOG-1 attribution).
    pub session_uuid: String,
    /// The never-recycled `dstap-<idx>` tap name — the authoritative LOG-2
    /// attribution / join key (doc 14 §4). The reject is attributed to the
    /// ORIGINATING session via this key (the session-mark / session-ref), never
    /// raw source IP (doc 12 §2.1 invariant 2).
    pub tap_name: String,
    /// The host-local session index (the 14-bit residue rides the mark, doc 14
    /// §4) — the disambiguator, never the primary join key.
    pub host_session_index: u32,
    /// The session-local count of NFT-4 udp/443 rejects (D70). Per session,
    /// never aggregated: this is THIS session's reject count, not a fleet total.
    pub reject_count: u64,
    /// The frozen reject reason — always [`RejectReason::QuicBlocked`], the D70
    /// carveout DISTINCT from generic default-deny (doc 14 §2). Single-sourced
    /// from `ds-contracts`, never a re-declared variant.
    pub reject_reason: RejectReason,
    /// The mandatory POL-3 provenance triple (rule 4 — a missing-provenance event
    /// is a spec failure). The rule/layer/version of the NFT-4 reject rule (the
    /// D70 udp/443 reject) — a secret-free key, never a payload byte.
    pub provenance: Provenance,
}

impl QuicRejectFlowRecord {
    /// Build a QUIC-reject `FlowRecord` from a session and its accumulated reject
    /// count, with the mandatory POL-3 `provenance` of the NFT-4 reject rule. The
    /// `reject_reason` is fixed to [`RejectReason::QuicBlocked`] — this record only
    /// ever models the D70 QUIC carveout.
    pub fn for_session(
        session: &SessionRef,
        reject_count: u64,
        provenance: Provenance,
    ) -> QuicRejectFlowRecord {
        QuicRejectFlowRecord {
            session_uuid: session.session_uuid.clone(),
            tap_name: session.tap_name.clone(),
            host_session_index: session.host_session_index,
            reject_count,
            reject_reason: RejectReason::QuicBlocked,
            provenance,
        }
    }

    /// Build a QUIC-reject `FlowRecord` from a [`QuicRejectSnapshot`] (the
    /// `ds-telemetry` per-session counter readout) and the session it belongs to,
    /// with the NFT-4 reject rule's POL-3 `provenance`. The snapshot's tap name
    /// MUST belong to `session`; the reason code is carried through from the
    /// snapshot (always [`RejectReason::QuicBlocked`]).
    pub fn from_snapshot(
        session: &SessionRef,
        snapshot: &QuicRejectSnapshot,
        provenance: Provenance,
    ) -> QuicRejectFlowRecord {
        QuicRejectFlowRecord {
            session_uuid: session.session_uuid.clone(),
            tap_name: session.tap_name.clone(),
            host_session_index: session.host_session_index,
            reject_count: snapshot.count,
            reject_reason: snapshot.reason,
            provenance,
        }
    }

    /// Whether this record is the D70 QUIC carveout (it always is — the shape only
    /// ever carries [`RejectReason::QuicBlocked`]). The trigger-evaluation query
    /// uses this to filter QUIC rejects out of the generic default-deny stream.
    pub fn is_quic_carveout(&self) -> bool {
        self.reject_reason.is_quic_carveout()
    }
}

/// The proxy-side per-session QUIC-reject TRACKER: it owns the
/// [`ds_telemetry::QuicRejectCounter`] convention (per session, never aggregated)
/// and, on a periodic flush, turns each session's accumulated count into a
/// [`QuicRejectFlowRecord`] handed to a [`QuicRejectEmitter`].
///
/// This is the proxy's instrumentation point doc 12 §7 names: it "captures and
/// logs every udp/443 reject from the NFT-4 rule, attributing it to the
/// originating session (via session-mark or session-ref), and emitting a
/// FlowRecord … with the QuicBlocked reason code". The two kernel ingest shapes
/// (nflog events vs a periodic counter snapshot) both feed [`Self::on_nflog_reject`]
/// / [`Self::observe_kernel_total`]; the bin owns the kernel-side parsing/read and
/// the SessionRef join (mark-index → tap name).
///
/// To keep the per-session attribution + provenance one-shot, the tracker holds a
/// `SessionRef` and the NFT-4 rule's POL-3 provenance alongside the count — both
/// supplied when a session's first reject is recorded — so a flush builds a
/// fully-attributed, provenance-bearing record without the caller re-supplying
/// them.
#[derive(Default)]
pub struct QuicRejectTracker {
    counter: QuicRejectCounter,
    /// Per-session attribution + the NFT-4 rule provenance, keyed on the tap name
    /// (the same key the counter uses). Recorded on the session's first reject so
    /// a flush can build a fully-attributed record.
    sessions: std::collections::BTreeMap<String, SessionAttribution>,
}

/// The per-session attribution a flush needs to build a record: the full
/// `SessionRef` (uuid + tap + index) and the NFT-4 reject rule's POL-3
/// provenance. Held once per session so emission never re-derives them.
#[derive(Clone, Debug)]
struct SessionAttribution {
    session: SessionRef,
    provenance: Provenance,
}

impl QuicRejectTracker {
    /// A fresh tracker with no sessions recorded.
    pub fn new() -> QuicRejectTracker {
        QuicRejectTracker::default()
    }

    /// Record ONE NFT-4 udp/443 reject for `session` (the nflog-event ingest path,
    /// doc 12 §7), attributing it to the originating session and pinning the NFT-4
    /// reject rule's POL-3 `provenance` for this session's records. Each nflog
    /// event is exactly one reject. Returns the new session-local total.
    ///
    /// The `provenance` is recorded on every call but only the FIRST per session
    /// is retained (subsequent rejects on the same session share one rule); this
    /// keeps a fully-attributed record buildable at flush time without the caller
    /// re-supplying attribution.
    pub fn on_nflog_reject(&mut self, session: &SessionRef, provenance: Provenance) -> u64 {
        self.remember(session, provenance);
        self.counter.record_reject(&session.tap_name)
    }

    /// Record a BATCH of `n` NFT-4 rejects for `session` in one call (a drained
    /// nflog backlog). Returns the new session-local total.
    pub fn on_nflog_rejects(
        &mut self,
        session: &SessionRef,
        n: u64,
        provenance: Provenance,
    ) -> u64 {
        self.remember(session, provenance);
        self.counter.record_rejects(&session.tap_name, n)
    }

    /// Observe an ABSOLUTE per-session reject total from a periodic kernel counter
    /// snapshot (the second ingest shape, doc 12 §7 — the nftables named counter /
    /// conntrack-derived count). Monotonic (a racing reset never lowers it).
    /// Returns the resulting session-local total.
    pub fn observe_kernel_total(
        &mut self,
        session: &SessionRef,
        kernel_total: u64,
        provenance: Provenance,
    ) -> u64 {
        self.remember(session, provenance);
        self.counter
            .observe_kernel_total(&session.tap_name, kernel_total)
    }

    fn remember(&mut self, session: &SessionRef, provenance: Provenance) {
        self.sessions
            .entry(session.tap_name.clone())
            .or_insert_with(|| SessionAttribution {
                session: session.clone(),
                provenance,
            });
    }

    /// The session-local reject count for `session` (0 if none).
    pub fn count_for(&self, session: &SessionRef) -> u64 {
        self.counter.count_for(&session.tap_name)
    }

    /// Build the QUIC-reject `FlowRecord` for a single session, or `None` if the
    /// session has recorded no reject (a session with zero QUIC rejects emits no
    /// reject record). Uses the attribution + provenance pinned on the session's
    /// first reject.
    pub fn flow_record_for(&self, session: &SessionRef) -> Option<QuicRejectFlowRecord> {
        let snapshot = self.counter.snapshot(&session.tap_name)?;
        let attribution = self.sessions.get(&session.tap_name)?;
        Some(QuicRejectFlowRecord::from_snapshot(
            &attribution.session,
            &snapshot,
            attribution.provenance.clone(),
        ))
    }

    /// Build a QUIC-reject `FlowRecord` for EVERY session with a non-zero reject
    /// count — a VECTOR of per-session records, never one rolled-up record (D70
    /// per-session invariant). Ordered by tap name (deterministic). A periodic
    /// flush hands each record to the [`QuicRejectEmitter`].
    pub fn flow_records(&self) -> Vec<QuicRejectFlowRecord> {
        self.counter
            .snapshot_all()
            .into_iter()
            .filter_map(|snap| {
                let attribution = self.sessions.get(&snap.tap_name)?;
                Some(QuicRejectFlowRecord::from_snapshot(
                    &attribution.session,
                    &snap,
                    attribution.provenance.clone(),
                ))
            })
            .collect()
    }

    /// Flush every per-session QUIC-reject record onto the LOG-1 channel via
    /// `emitter`, returning how many records were emitted. One record per session
    /// with a non-zero count (D70 per-session, never aggregated).
    pub fn flush<E: QuicRejectEmitter + ?Sized>(&self, emitter: &E) -> usize {
        let records = self.flow_records();
        let n = records.len();
        for record in &records {
            emitter.emit_quic_reject(record);
        }
        n
    }

    /// Drop a session's reject count + attribution entirely (NFT-6 session-end
    /// teardown hygiene, doc 12 §8): on teardown the per-session counter is flushed
    /// with the session so no stale count rides a never-recycled tap name. Returns
    /// the count that was dropped (0 if none).
    pub fn forget_session(&mut self, session: &SessionRef) -> u64 {
        self.sessions.remove(&session.tap_name);
        self.counter.forget_session(&session.tap_name)
    }
}

/// The LOG-1 telemetry channel for [`QuicRejectFlowRecord`] emission (doc 09 §7
/// LOG-1; doc 12 §5.5 / §7 / §10; boundary `EventSink.Emit`). The single egress
/// every per-session QUIC-reject record flows through — the tracker builds the
/// record (reject-reason + count, payload-free by construction) and hands it to
/// this seam, which owns the spool/wire.
///
/// Shaped exactly like [`crate::telemetry_http::AuditEmitter`]: production
/// implements it over the wired `ds-telemetry` spool in `main.rs` (D40 — no
/// transport type leaks into the lib); tests implement it over an in-memory
/// recording fake. Never-log-the-secret (D73) is upheld by the SHAPE, not this
/// seam: a [`QuicRejectFlowRecord`] carries only attribution + a count + the
/// reason enum, so an emitter — however it serializes — has no payload byte to
/// leak.
pub trait QuicRejectEmitter {
    /// Emit one [`QuicRejectFlowRecord`] onto the LOG-1 channel. Borrows the
    /// record; the emitter must not retain it past the call.
    fn emit_quic_reject(&self, record: &QuicRejectFlowRecord);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    fn provenance() -> Provenance {
        // The NFT-4 udp/443 reject rule's POL-3 triple.
        Provenance::new("nft4-udp443-reject", "pol2-system-baseline", "policy-v1")
    }

    // ── the ACCEPTANCE shape: 5 rejects → counter=5, reason=QuicBlocked ──────

    #[test]
    fn five_nft4_rejects_produce_a_flow_record_with_count_five_and_quic_reason() {
        // ACCEPTANCE: a mock session with 5 simulated NFT-4 rejects produces a
        // FlowRecord with counter=5 and reason=QuicBlocked.
        let mut tracker = QuicRejectTracker::new();
        let s = session(7);
        for i in 1..=5 {
            assert_eq!(tracker.on_nflog_reject(&s, provenance()), i);
        }
        let record = tracker
            .flow_record_for(&s)
            .expect("a reject record for the session");
        assert_eq!(record.reject_count, 5);
        assert_eq!(record.reject_reason, RejectReason::QuicBlocked);
        assert!(record.is_quic_carveout());
        // distinct from generic default-deny (doc 14 §2).
        assert_ne!(record.reject_reason, RejectReason::DefaultDeny);
        // attributed to the originating session by its never-recycled tap name.
        assert_eq!(record.tap_name, "dstap-7");
        assert_eq!(record.session_uuid, s.session_uuid);
        assert_eq!(record.host_session_index, 7);
        // mandatory POL-3 provenance (rule 4).
        assert_eq!(record.provenance.rule_id, "nft4-udp443-reject");
        assert_eq!(record.provenance.policy_version, "policy-v1");
    }

    #[test]
    fn multiple_rejects_increment_the_same_sessions_counter() {
        // doc 12 §7: "each reject increments the session's QUIC-reject counter".
        let mut tracker = QuicRejectTracker::new();
        let s = session(3);
        assert_eq!(tracker.count_for(&s), 0);
        tracker.on_nflog_reject(&s, provenance());
        assert_eq!(tracker.count_for(&s), 1);
        tracker.on_nflog_reject(&s, provenance());
        tracker.on_nflog_reject(&s, provenance());
        assert_eq!(tracker.count_for(&s), 3);
        assert_eq!(tracker.flow_record_for(&s).unwrap().reject_count, 3);
    }

    // ── per session, never aggregated (D70) ─────────────────────────────────

    #[test]
    fn counts_are_per_session_and_records_are_a_vector_never_a_total() {
        let mut tracker = QuicRejectTracker::new();
        let a = session(1);
        let b = session(2);
        tracker.on_nflog_rejects(&a, 4, provenance());
        tracker.on_nflog_rejects(&b, 9, provenance());

        assert_eq!(tracker.count_for(&a), 4);
        assert_eq!(tracker.count_for(&b), 9);

        // a vector of per-session records, never one rolled-up record.
        let records = tracker.flow_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].tap_name, "dstap-1"); // BTreeMap order
        assert_eq!(records[0].reject_count, 4);
        assert_eq!(records[1].tap_name, "dstap-2");
        assert_eq!(records[1].reject_count, 9);
        // every record is the QUIC carveout.
        assert!(records
            .iter()
            .all(|r| r.reject_reason == RejectReason::QuicBlocked));
    }

    #[test]
    fn a_session_with_no_reject_emits_no_record() {
        let tracker = QuicRejectTracker::new();
        let s = session(9);
        assert!(tracker.flow_record_for(&s).is_none());
        assert!(tracker.flow_records().is_empty());
    }

    // ── kernel-snapshot ingest shape (doc 12 §7) ────────────────────────────

    #[test]
    fn kernel_total_snapshot_builds_an_absolute_count_record() {
        let mut tracker = QuicRejectTracker::new();
        let s = session(4);
        tracker.observe_kernel_total(&s, 12, provenance());
        assert_eq!(tracker.flow_record_for(&s).unwrap().reject_count, 12);
        // an nflog increment composes on top.
        tracker.on_nflog_reject(&s, provenance());
        assert_eq!(tracker.flow_record_for(&s).unwrap().reject_count, 13);
        // a stale lower snapshot does not regress the count.
        tracker.observe_kernel_total(&s, 5, provenance());
        assert_eq!(tracker.flow_record_for(&s).unwrap().reject_count, 13);
    }

    // ── emission seam ───────────────────────────────────────────────────────

    #[derive(Default)]
    struct RecordingEmitter {
        seen: std::sync::Mutex<Vec<QuicRejectFlowRecord>>,
    }

    impl QuicRejectEmitter for RecordingEmitter {
        fn emit_quic_reject(&self, record: &QuicRejectFlowRecord) {
            self.seen.lock().unwrap().push(record.clone());
        }
    }

    #[test]
    fn flush_emits_one_record_per_session_onto_the_log1_channel() {
        let mut tracker = QuicRejectTracker::new();
        tracker.on_nflog_rejects(&session(1), 2, provenance());
        tracker.on_nflog_rejects(&session(2), 5, provenance());

        let sink = RecordingEmitter::default();
        let n = tracker.flush(&sink);
        assert_eq!(n, 2);

        let seen = sink.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].tap_name, "dstap-1");
        assert_eq!(seen[0].reject_count, 2);
        assert_eq!(seen[1].tap_name, "dstap-2");
        assert_eq!(seen[1].reject_count, 5);
        assert!(seen
            .iter()
            .all(|r| r.reject_reason == RejectReason::QuicBlocked));
    }

    // ── NFT-6 teardown hygiene ──────────────────────────────────────────────

    #[test]
    fn forget_session_flushes_the_per_session_counter_and_attribution() {
        let mut tracker = QuicRejectTracker::new();
        let s = session(5);
        tracker.on_nflog_rejects(&s, 4, provenance());
        assert_eq!(tracker.forget_session(&s), 4);
        assert_eq!(tracker.count_for(&s), 0);
        assert!(tracker.flow_record_for(&s).is_none());
    }

    // ── never-log-the-secret canary (D73 §5.1) ──────────────────────────────

    #[test]
    fn no_record_field_ever_carries_a_client_payload_byte() {
        // Plant a canary standing in for a client-payload / credential byte and
        // assert it appears in NO string field of the record. The shape carries
        // only attribution + a count + the reason enum + provenance — no body, no
        // header value, no Secret — so a payload byte structurally cannot reach a
        // reject record (D73, the TLS-5/TLS-7 convention).
        const CANARY: &str = "SECRET-PAYLOAD-CANARY-9f3a2b";
        let mut tracker = QuicRejectTracker::new();
        let s = session(9);
        tracker.on_nflog_rejects(&s, 5, provenance());
        let record = tracker.flow_record_for(&s).unwrap();

        let fields = [
            record.session_uuid.as_str(),
            record.tap_name.as_str(),
            record.provenance.rule_id.as_str(),
            record.provenance.policy_layer.as_str(),
            record.provenance.policy_version.as_str(),
        ];
        for f in fields {
            assert!(
                !f.contains(CANARY),
                "QuicRejectFlowRecord field leaked a client-payload canary: {f:?}"
            );
        }
    }
}
