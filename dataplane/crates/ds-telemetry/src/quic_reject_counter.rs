//! Per-session QUIC-blocked reject counter — the LOG-1 reject-reason telemetry
//! convention for the D70 udp/443 reject rule (doc 12 §7; doc 14 §2 `FlowRecord`
//! `RejectReason` row; D70).
//!
//! # What this is
//!
//! D70 freezes the udp/443 (QUIC) posture: the NFT-4 rule **rejects** udp/443
//! with icmp port-unreachable — *never silently dropped* — and **counts every
//! reject per session**. doc 14 §2's `FlowRecord` row pins the wire contract:
//!
//! > *"`RejectReason` enum distinguishing `QUIC_BLOCKED` from generic
//! > default-deny … The udp/443 reject (icmp port-unreachable, never silently
//! > dropped) is counted per session; the reason code is what makes the D70
//! > flip-to-inspect trigger queryable off-box."*
//!
//! This module owns the **convention** half of that contract: a per-session
//! counter that aggregates the kernel's NFT-4 reject signal (nflog events, or a
//! periodic snapshot of the per-session reject counter) into the `(session,
//! count)` datum a LOG-1 `FlowRecord` carries with `reject_reason =
//! [`RejectReason::QuicBlocked`]`. The proxy-side `FlowRecord` SHAPE that
//! serializes this counter lives in `ds-tlsproxy::telemetry_quic` (the same
//! local-shape / migrate-at-Stage-0 pattern the HTTP/netflow events use); this
//! crate owns the cross-emitter counting convention so the "per session, never
//! aggregated" invariant has one home.
//!
//! # The frozen invariant: per session, never aggregated (D70)
//!
//! D70's count is **per session** — the trigger evaluation joins QUIC-reject
//! volume to the *originating session* (via the session-mark / session-ref), so a
//! fleet-wide sum is the wrong shape: it cannot answer "which session is being
//! forced onto H3". This counter is therefore keyed on the authoritative
//! never-recycled join key — the `dstap-<idx>` tap name (doc 14 §4) — and offers
//! NO cross-session total. A caller that wants a per-session snapshot reads
//! exactly one session's count; iterating all sessions yields a *vector of
//! per-session counts*, never a single rolled-up scalar.
//!
//! # Never-log-the-secret (D73) — structural
//!
//! A reject counter carries ZERO payload: it is a `(tap_name, u64 count, reason
//! code)` datum. There is no body, no header, no address octet that could carry a
//! client byte — the kernel's NFT-4 rule fires on a udp/443 SYN-equivalent before
//! any payload exists, and this counter records only that it fired and for whom.
//! Never-log-the-secret holds by the shape carrying no payload field at all
//! (the same convention [`crate::event`] / [`crate::scrub`] enforce elsewhere).
//!
//! License: OSS — Apache-2.0 (D25/D15; LOG-1 reject telemetry is data-plane).

use std::collections::BTreeMap;

use ds_contracts::reject::RejectReason;

/// The reject reason every count this module accumulates carries: the D70 QUIC
/// carveout, kept DISTINCT from generic default-deny (doc 14 §2). Re-exported as
/// a `const` so the proxy-side `FlowRecord` shape and the counter agree on one
/// value without re-declaring the enum variant.
pub const QUIC_REJECT_REASON: RejectReason = RejectReason::QuicBlocked;

/// A single per-session QUIC-reject snapshot: the authoritative session join key
/// (the never-recycled `dstap-<idx>` tap name, doc 14 §4), the session-local
/// reject count, and the frozen reason code. This is the `(session, count,
/// reason)` datum a LOG-1 `FlowRecord` is built from — the convention-layer
/// carrier the proxy's `FlowRecord` SHAPE migrates onto at the Stage-0 freeze.
///
/// The count is SESSION-LOCAL (D70 "per session, never aggregated"): it is the
/// number of NFT-4 udp/443 rejects attributed to THIS session, never a total
/// across sessions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicRejectSnapshot {
    /// The authoritative never-recycled session join key — the `dstap-<idx>` tap
    /// name (doc 14 §4 / LOG-2 attribution). The reject is attributed to the
    /// ORIGINATING session via this key (the session-mark / session-ref), never
    /// raw source IP (doc 12 §2.1 invariant 2).
    pub tap_name: String,
    /// The session-local count of NFT-4 udp/443 rejects (D70). Per session,
    /// never aggregated.
    pub count: u64,
    /// The frozen reject reason — always [`RejectReason::QuicBlocked`], the D70
    /// carveout DISTINCT from generic default-deny so the flip-to-inspect trigger
    /// is queryable off-box (doc 14 §2).
    pub reason: RejectReason,
}

impl QuicRejectSnapshot {
    /// Whether this snapshot is the D70 QUIC carveout (it always is — the type
    /// only ever carries [`RejectReason::QuicBlocked`]). A convenience the
    /// trigger-evaluation query uses to filter QUIC rejects out of the generic
    /// default-deny stream without matching on the variant by hand.
    pub fn is_quic_carveout(&self) -> bool {
        self.reason.is_quic_carveout()
    }
}

/// A per-session QUIC-reject counter (doc 12 §7, D70): it accumulates the kernel's
/// NFT-4 udp/443 reject signal — one increment per nflog event, or an absolute
/// set from a periodic per-session counter snapshot — keyed on the never-recycled
/// tap name (doc 14 §4), and produces per-session [`QuicRejectSnapshot`]s for
/// LOG-1 `FlowRecord` emission.
///
/// # Per session, never aggregated (D70)
///
/// The counter is a `BTreeMap<tap_name, u64>`: every operation names a session,
/// and the only readout is per-session ([`Self::snapshot`]) or a vector of
/// per-session snapshots ([`Self::snapshot_all`]). There is deliberately NO
/// `total()` accessor — a single rolled-up scalar is the wrong shape for the D70
/// trigger evaluation, which must attribute QUIC-reject volume to the
/// originating session.
///
/// # Two ingest shapes (doc 12 §7 design seam)
///
/// doc 12 §7's design seam names two ways the reject signal arrives:
/// (1) **nflog events** matching the NFT-4 reject rule — each is ONE reject, so
///     [`Self::record_reject`] increments by one;
/// (2) a **periodic snapshot** of the per-session reject counter (e.g. from
///     `/proc/net/nf_conntrack` marked with the session index, or the nftables
///     named counter) — an ABSOLUTE value the kernel maintains, so
///     [`Self::observe_kernel_total`] sets the count to the observed total
///     (monotonic: it never goes backwards, guarding against a counter read that
///     races a reset).
///
/// Both feed the same per-session count, so a deployment can use either source
/// (or both) and read one consistent snapshot.
#[derive(Debug, Default, Clone)]
pub struct QuicRejectCounter {
    /// Per-session reject counts, keyed on the authoritative `dstap-<idx>` tap
    /// name (doc 14 §4) — never the recyclable 14-bit mark index, never raw
    /// source IP.
    counts: BTreeMap<String, u64>,
}

impl QuicRejectCounter {
    /// A fresh counter with no sessions recorded.
    pub fn new() -> QuicRejectCounter {
        QuicRejectCounter::default()
    }

    /// Record ONE NFT-4 udp/443 reject for the session named by `tap_name` (the
    /// nflog-event ingest path, doc 12 §7): each nflog event is exactly one
    /// reject, so this increments the session's count by one and returns the new
    /// session-local total. Saturating so a pathological session can never
    /// overflow into a wrong (small) count.
    pub fn record_reject(&mut self, tap_name: &str) -> u64 {
        let slot = self.counts.entry(tap_name.to_string()).or_insert(0);
        *slot = slot.saturating_add(1);
        *slot
    }

    /// Record `n` NFT-4 rejects for `tap_name` in one call (a batched nflog
    /// drain). Equivalent to `n` calls to [`Self::record_reject`]; returns the new
    /// session-local total. Saturating.
    pub fn record_rejects(&mut self, tap_name: &str, n: u64) -> u64 {
        let slot = self.counts.entry(tap_name.to_string()).or_insert(0);
        *slot = slot.saturating_add(n);
        *slot
    }

    /// Observe an ABSOLUTE per-session reject total from a periodic kernel
    /// counter snapshot (the second ingest shape, doc 12 §7): the nftables named
    /// counter / conntrack-derived count is a running total the kernel maintains,
    /// so this SETS the session's count to `kernel_total` — but MONOTONICALLY: it
    /// never lowers a count below what is already recorded, so a snapshot that
    /// races a counter reset (or arrives out of order behind an nflog increment)
    /// cannot lose rejects. Returns the resulting session-local total.
    pub fn observe_kernel_total(&mut self, tap_name: &str, kernel_total: u64) -> u64 {
        let slot = self.counts.entry(tap_name.to_string()).or_insert(0);
        *slot = (*slot).max(kernel_total);
        *slot
    }

    /// The session-local reject count for `tap_name` (0 if the session has had no
    /// QUIC reject). Per session — there is no cross-session total by design
    /// (D70).
    pub fn count_for(&self, tap_name: &str) -> u64 {
        self.counts.get(tap_name).copied().unwrap_or(0)
    }

    /// A per-session [`QuicRejectSnapshot`] for `tap_name`, ready to build a LOG-1
    /// `FlowRecord` (`reject_reason = QuicBlocked`, `count = N`). Returns `None`
    /// when the session has recorded no reject — a session with zero QUIC rejects
    /// emits NO reject FlowRecord (there is nothing to report), so the snapshot is
    /// absent rather than a zero-count record.
    pub fn snapshot(&self, tap_name: &str) -> Option<QuicRejectSnapshot> {
        let count = self.counts.get(tap_name).copied()?;
        if count == 0 {
            return None;
        }
        Some(QuicRejectSnapshot {
            tap_name: tap_name.to_string(),
            count,
            reason: QUIC_REJECT_REASON,
        })
    }

    /// A per-session snapshot for EVERY session with a non-zero reject count — a
    /// VECTOR of per-session counts, never a single rolled-up scalar (D70 "per
    /// session, never aggregated"). Ordered by tap name (the `BTreeMap` order) so
    /// the emission order is deterministic. A periodic flush emits one LOG-1
    /// `FlowRecord` per element.
    pub fn snapshot_all(&self) -> Vec<QuicRejectSnapshot> {
        self.counts
            .iter()
            .filter(|(_, &c)| c > 0)
            .map(|(tap, &count)| QuicRejectSnapshot {
                tap_name: tap.clone(),
                count,
                reason: QUIC_REJECT_REASON,
            })
            .collect()
    }

    /// How many distinct sessions have recorded at least one QUIC reject
    /// (diagnostic). NOT a sum of rejects — that scalar is deliberately not
    /// offered (D70 per-session invariant).
    pub fn sessions_with_rejects(&self) -> usize {
        self.counts.values().filter(|&&c| c > 0).count()
    }

    /// Drop a session's reject count entirely (NFT-6 session-end teardown
    /// hygiene, doc 12 §8): on session teardown the per-session counter is
    /// flushed with the session, so a never-recycled tap name's slate is clean and
    /// no stale count survives. Returns the count that was dropped (0 if the
    /// session had none).
    pub fn forget_session(&mut self, tap_name: &str) -> u64 {
        self.counts.remove(tap_name).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_nflog_rejects_yield_a_count_of_five_with_quic_reason() {
        // The ACCEPTANCE shape (convention half): a session with 5 simulated NFT-4
        // rejects produces a per-session snapshot with count == 5 and reason ==
        // QuicBlocked (the value the proxy's FlowRecord carries).
        let mut counter = QuicRejectCounter::new();
        for i in 1..=5 {
            assert_eq!(counter.record_reject("dstap-7"), i);
        }
        let snap = counter
            .snapshot("dstap-7")
            .expect("a snapshot for the session");
        assert_eq!(snap.tap_name, "dstap-7");
        assert_eq!(snap.count, 5);
        assert_eq!(snap.reason, RejectReason::QuicBlocked);
        assert!(snap.is_quic_carveout());
        // distinct from generic default-deny (doc 14 §2).
        assert_ne!(snap.reason, RejectReason::DefaultDeny);
    }

    #[test]
    fn counts_are_per_session_never_aggregated() {
        // D70: the counter is keyed per session; one session's rejects never bleed
        // into another's, and there is no rolled-up cross-session scalar.
        let mut counter = QuicRejectCounter::new();
        counter.record_rejects("dstap-1", 3);
        counter.record_rejects("dstap-2", 7);

        assert_eq!(counter.count_for("dstap-1"), 3);
        assert_eq!(counter.count_for("dstap-2"), 7);
        // a vector of per-session snapshots, never a single total.
        let all = counter.snapshot_all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].tap_name, "dstap-1"); // BTreeMap order
        assert_eq!(all[0].count, 3);
        assert_eq!(all[1].tap_name, "dstap-2");
        assert_eq!(all[1].count, 7);
        // every element is the QUIC carveout reason.
        assert!(all.iter().all(|s| s.reason == RejectReason::QuicBlocked));
    }

    #[test]
    fn a_session_with_no_rejects_has_no_snapshot() {
        // A session with zero QUIC rejects emits NO reject FlowRecord — the
        // snapshot is absent, not a zero-count record.
        let counter = QuicRejectCounter::new();
        assert_eq!(counter.count_for("dstap-9"), 0);
        assert!(counter.snapshot("dstap-9").is_none());
        assert!(counter.snapshot_all().is_empty());
        assert_eq!(counter.sessions_with_rejects(), 0);
    }

    #[test]
    fn kernel_total_snapshot_sets_an_absolute_monotonic_count() {
        // The periodic-snapshot ingest shape (doc 12 §7): an absolute per-session
        // counter the kernel maintains. observe sets the count; a lower later read
        // (a racing reset) never lowers it.
        let mut counter = QuicRejectCounter::new();
        assert_eq!(counter.observe_kernel_total("dstap-3", 12), 12);
        assert_eq!(counter.count_for("dstap-3"), 12);
        // a higher observation advances it.
        assert_eq!(counter.observe_kernel_total("dstap-3", 20), 20);
        // a LOWER observation (counter reset / out-of-order read) does NOT lower
        // the recorded count — monotonic, so no reject is lost.
        assert_eq!(counter.observe_kernel_total("dstap-3", 5), 20);
        assert_eq!(counter.count_for("dstap-3"), 20);
    }

    #[test]
    fn nflog_increments_and_kernel_snapshots_compose() {
        // Both ingest shapes feed the same per-session count: an nflog increment
        // on top of a kernel snapshot reads as one consistent total.
        let mut counter = QuicRejectCounter::new();
        counter.observe_kernel_total("dstap-4", 10);
        assert_eq!(counter.record_reject("dstap-4"), 11);
        assert_eq!(counter.count_for("dstap-4"), 11);
        // a stale snapshot below the new total does not regress it.
        assert_eq!(counter.observe_kernel_total("dstap-4", 10), 11);
    }

    #[test]
    fn forget_session_flushes_the_per_session_counter() {
        // NFT-6 hygiene: session teardown drops the per-session count so a
        // never-recycled tap name starts clean.
        let mut counter = QuicRejectCounter::new();
        counter.record_rejects("dstap-5", 4);
        assert_eq!(counter.count_for("dstap-5"), 4);
        assert_eq!(counter.forget_session("dstap-5"), 4);
        assert_eq!(counter.count_for("dstap-5"), 0);
        assert!(counter.snapshot("dstap-5").is_none());
        // forgetting an unknown session is a no-op returning 0.
        assert_eq!(counter.forget_session("dstap-nope"), 0);
    }

    #[test]
    fn record_is_saturating_and_never_overflows() {
        // A pathological session can never overflow into a wrong (small) count.
        let mut counter = QuicRejectCounter::new();
        counter.record_rejects("dstap-6", u64::MAX);
        assert_eq!(counter.count_for("dstap-6"), u64::MAX);
        // one more reject saturates rather than wrapping to 0.
        assert_eq!(counter.record_reject("dstap-6"), u64::MAX);
    }

    #[test]
    fn reject_reason_const_is_the_quic_carveout() {
        // The single-sourced reason the counter and the proxy FlowRecord share.
        assert_eq!(QUIC_REJECT_REASON, RejectReason::QuicBlocked);
        assert!(QUIC_REJECT_REASON.is_quic_carveout());
    }
}
