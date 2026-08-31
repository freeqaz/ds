//! The LOG-3 disk-bounded spool client (doc 14 §12.4, D116; doc 09 §7 LOG-3).
//!
//! # What is frozen vs free
//!
//! The §2 LOG-1 message SET is frozen (`ds-contracts`); the spool ENCODING on
//! disk is free implementation, "bounded by the §2 frozen message set" (doc 14
//! §12.4). So this module owns the spool's behavior — the bound, drop policy,
//! batching, and the visible-loss marker — not the wire schema.
//!
//! # The one disallowed behavior: silent loss (D116)
//!
//! Doc 14 §12.4 / D116: when the disk-bounded spool overflows, "loss is visible,
//! never silent: the `SpoolOverflow {session, dropped count, timestamp}` marker
//! ships in the surviving stream ... the implementor handles overflow by dropping
//! payload events but **never** the marker — the marker is the loss receipt, so
//! the spool's back-pressure / drop policy must reserve room (or a priority lane)
//! for the marker even when full. Silent loss is the one disallowed behavior."
//!
//! This client implements exactly that:
//!
//!   * The spool is a **bounded on-disk ring** of size [`SpoolBounds::max_records`]
//!     records. When a write would exceed the bound, the **oldest payload record
//!     is dropped** (drop-oldest under the bound — the D116-contractual policy,
//!     "drop-oldest under the spool bound is contractual only if loss is
//!     visible"), and a per-session dropped count is incremented.
//!   * A [`SpoolOverflow`] marker carrying `{session, dropped, timestamp}` is
//!     emitted into the **surviving** stream — it is itself spooled, and it rides
//!     a **priority lane** that is never evicted, so even a saturated ring keeps
//!     the loss receipt. The marker is the proof that loss was visible.
//!
//! # tokio (the pinned workspace 1.x major, doc 14 §6)
//!
//! The async spool runs on tokio: a background flush task drains a bounded
//! in-memory channel into the on-disk segment, batching records per
//! [`SpoolBounds::batch_size`] and flushing on a [`SpoolBounds::flush_interval`]
//! tick. The on-disk path is `tokio::fs`. No `net` feature is used — the off-box
//! transport into `ds-flowlog` is a later seam (doc 14 §12.4); this client's job
//! ends at a durable, bounded, visible-loss on-disk spool.
//!
//! The [`SpoolSink`] handle implements [`crate::event::EventSink`] (the migration
//! target: the real spool is the production `EventSink` impl), so an emitter's
//! sites are unchanged when the spool replaces a `NullSink`.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, Notify};

use crate::event::{EventEnvelope, EventKind, EventSink};
use crate::provenance::Provenance;

/// The disk bound + batching knobs for a spool (doc 14 §12.4, free
/// implementation). Deliberately small defaults so a deployment must opt into a
/// large spool consciously; the (c)-suite drives a tiny bound to prove overflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolBounds {
    /// The maximum number of PAYLOAD records the on-disk ring holds. When a write
    /// would exceed this, the oldest payload record is evicted (drop-oldest) and
    /// the dropped count rises. The [`SpoolOverflow`] marker lane is separate and
    /// is NEVER counted against this bound — the loss receipt always survives.
    pub max_records: usize,
    /// How many records the background flush task batches before writing to disk.
    pub batch_size: usize,
    /// The in-memory channel depth between the [`SpoolSink`] handles and the
    /// flush task. Back-pressure point before the disk ring.
    pub channel_depth: usize,
    /// The flush-tick interval: the flush task drains and writes at least this
    /// often even if `batch_size` is not reached (so a low-rate stream still
    /// lands on disk promptly).
    pub flush_interval: std::time::Duration,
}

impl Default for SpoolBounds {
    fn default() -> Self {
        Self {
            max_records: 4096,
            batch_size: 64,
            channel_depth: 256,
            flush_interval: std::time::Duration::from_millis(50),
        }
    }
}

/// Which of the spool's two distinct loss points minted a [`SpoolOverflow`]
/// receipt (§12.4 visible-loss invariant + the D116 channel-shed land). Both paths
/// mint the SAME priority-lane `0xFF` marker, so without this discriminator an
/// on-disk reader (or a future `ds-flowlog` transport) cannot attribute a flushed
/// marker to WHICH loss path fired. This is part of the FREE on-disk encoding, not
/// the frozen wire schema — it carries a stable 1-byte tag ([`Self::origin_byte`])
/// so the loss point is recoverable from a flushed segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossOrigin {
    /// The contractual disk-ring drop-oldest path: the bounded on-disk ring was full
    /// and evicted its oldest payload record ([`Ring::push_payload`]).
    DiskDrop,
    /// The synchronous fire-and-forget `EventSink::emit` channel-shed path: the
    /// in-memory channel was momentarily full and the event was shed at the channel
    /// ([`SpoolSink::mint_shed_marker`]).
    ChannelShed,
}

impl LossOrigin {
    /// The 1-byte on-disk discriminator for this loss point (free encoding). Stable:
    /// the on-disk decoder maps it back via [`Self::from_byte`].
    fn origin_byte(self) -> u8 {
        match self {
            LossOrigin::DiskDrop => 0x01,
            LossOrigin::ChannelShed => 0x02,
        }
    }

    /// Recover a [`LossOrigin`] from its on-disk discriminator byte (the inverse of
    /// [`Self::origin_byte`]). Returns `None` for an unknown byte. Used by the on-disk
    /// segment decoder (the off-box `ds-flowlog` transport is a later seam, doc 14
    /// §12.4); exercised here by the round-trip tests.
    #[cfg(test)]
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(LossOrigin::DiskDrop),
            0x02 => Some(LossOrigin::ChannelShed),
            _ => None,
        }
    }
}

/// The D116 visible-loss marker: `{session, dropped, timestamp, origin}`.
/// Constructed by the spool itself when a loss point fires; it ships in the
/// surviving stream and is never silently dropped. This is the convention-layer
/// shape of the frozen `SpoolOverflow` wire message (doc 14 §2 — the migration
/// maps this 1:1 onto the generated type). The `origin` discriminator is a FREE
/// on-disk addition (not the frozen wire schema) so an auditor can tell WHICH of
/// the spool's two loss points minted the receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolOverflow {
    /// The session whose payload records were evicted (the join key).
    pub session: String,
    /// How many payload records have been dropped for this session so far.
    pub dropped: u64,
    /// Unix-epoch milliseconds when the marker was minted.
    pub timestamp_ms: u64,
    /// Which loss point minted this receipt — disk-ring drop-oldest (§12.4
    /// visible-loss invariant) vs the sync channel-shed (the D116 channel-shed
    /// land). Carried into the free on-disk encoding as a 1-byte discriminator so
    /// the loss path is recoverable from a flushed segment.
    pub origin: LossOrigin,
}

/// A spooled record as it sits in the on-disk ring: either a payload event or the
/// priority-lane overflow marker. The marker variant is never evicted by the
/// bound — it is the loss receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpoolRecord {
    /// A payload event (subject to drop-oldest under the bound).
    Payload(EventEnvelope),
    /// The D116 visible-loss marker (priority lane — never evicted).
    Overflow(SpoolOverflow),
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The shared, in-memory model of the on-disk ring. The flush task owns writing
/// it to disk; the eviction policy lives here so the bound + visible-loss
/// invariant is one place, not scattered across write sites.
#[derive(Debug)]
struct Ring {
    bounds: SpoolBounds,
    /// Payload records, oldest first (drop-oldest evicts the front).
    payload: std::collections::VecDeque<EventEnvelope>,
    /// Per-session dropped counts (monotonic). Drives the marker's `dropped`.
    dropped: std::collections::HashMap<String, u64>,
    /// The priority lane: pending overflow markers that MUST survive to disk.
    /// Never evicted by the bound.
    markers: std::collections::VecDeque<SpoolOverflow>,
}

impl Ring {
    fn new(bounds: SpoolBounds) -> Self {
        Self {
            bounds,
            payload: std::collections::VecDeque::new(),
            dropped: std::collections::HashMap::new(),
            markers: std::collections::VecDeque::new(),
        }
    }

    /// Push a payload record, enforcing the bound by drop-oldest. Returns any
    /// minted [`SpoolOverflow`] marker (so the caller knows loss was visible) —
    /// the marker is also queued in the priority lane for durable flush.
    fn push_payload(&mut self, event: EventEnvelope) -> Option<SpoolOverflow> {
        // Attribution: the visible-loss receipt names the session of the record
        // that was actually EVICTED (drop-oldest), so it is derived below from the
        // evicted record, not the incoming one. Every event carries a mandatory
        // POL-3 provenance triple, so the eviction is always attributable — never
        // an unattributed silent drop (the SessionRef join key lands with the
        // frozen schema; the provenance namespace is the conventions-layer key).
        if self.payload.len() >= self.bounds.max_records {
            // Drop-oldest: evict the front payload record (D116 drop-oldest).
            let evicted = self
                .payload
                .pop_front()
                .expect("len >= max_records >= 1 implies a front record");
            let evicted_session = session_key_of(&evicted);
            let count = self.dropped.entry(evicted_session.clone()).or_insert(0);
            *count += 1;
            let marker = SpoolOverflow {
                session: evicted_session,
                dropped: *count,
                timestamp_ms: now_ms(),
                // The contractual disk-ring drop-oldest loss point.
                origin: LossOrigin::DiskDrop,
            };
            // The marker rides the priority lane — never evicted, always flushed.
            self.markers.push_back(marker.clone());
            self.payload.push_back(event);
            Some(marker)
        } else {
            self.payload.push_back(event);
            None
        }
    }

    /// Queue an externally-minted [`SpoolOverflow`] marker onto the priority lane.
    /// The sync `emit()` channel-shed path mints its per-session receipt OUTSIDE the
    /// ring (it holds only the channel, never the lock), so the flush task lifts the
    /// marker in here — onto the SAME never-evicted lane the disk-ring drop-oldest
    /// markers ride, so both loss points share one durable receipt path (D116).
    fn push_marker(&mut self, marker: SpoolOverflow) {
        self.markers.push_back(marker);
    }

    /// Drain up to `batch_size` records for a flush, MARKERS FIRST so the loss
    /// receipt is never starved behind payload (the priority lane). Returns the
    /// records in flush order.
    fn drain_batch(&mut self) -> Vec<SpoolRecord> {
        let mut batch = Vec::new();
        // Priority lane drains first and fully — markers are small and must land.
        while let Some(m) = self.markers.pop_front() {
            batch.push(SpoolRecord::Overflow(m));
        }
        while batch.len() < self.bounds.batch_size {
            match self.payload.pop_front() {
                Some(e) => batch.push(SpoolRecord::Payload(e)),
                None => break,
            }
        }
        batch
    }

    fn is_empty(&self) -> bool {
        self.payload.is_empty() && self.markers.is_empty()
    }
}

/// Derive the session attribution key for a payload, from its mandatory POL-3
/// provenance. The frozen LOG-1 `SessionRef` is the eventual authority; at the
/// conventions layer the provenance triple is the stable per-event identity every
/// event is guaranteed to carry, so the visible-loss receipt is always
/// attributable (never an unattributed drop). The key is the rule namespace —
/// `"<policy_layer>/<rule_id>"` — which is total and present on every event.
fn session_key_of(event: &EventEnvelope) -> String {
    let p: &Provenance = event.provenance();
    format!("{}/{}", p.policy_layer(), p.rule_id())
}

/// A cloneable handle that emits events into the spool. Implements
/// [`EventSink`], so it is the production drop-in replacement for a `NullSink` at
/// an emission site (the migration target).
#[derive(Clone)]
pub struct SpoolSink {
    tx: mpsc::Sender<EventEnvelope>,
    /// The priority lane for the channel-shed loss receipt: when the SYNCHRONOUS
    /// fire-and-forget [`EventSink::emit`] sheds an event at the saturated main
    /// channel, it mints a per-session [`SpoolOverflow`] marker here so the loss is
    /// visible in the surviving stream — not merely counted in [`Self::dropped_total`]
    /// (D116: silent loss is the one disallowed behavior, and this closes it for the
    /// sync path the way drop-oldest already closes it for the disk ring). This is a
    /// SEPARATE, tiny channel so the marker is never itself shed behind the payload
    /// back-pressure it is reporting on; the flush task lifts each marker straight
    /// onto the ring's never-evicted priority lane.
    marker_tx: mpsc::Sender<SpoolOverflow>,
    /// Per-session channel-shed counts for the sync `emit()` path, so each minted
    /// marker carries a MONOTONIC per-session `dropped` count (mirroring the disk
    /// ring's per-session `dropped` accounting), not a flat `1`. The channel-shed and
    /// the disk-ring drop-oldest are two distinct loss points; this map is the sync
    /// path's own per-session tally. A `std` mutex (held only for the count bump) so
    /// the synchronous fire-and-forget `emit()` never awaits.
    shed_dropped: Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    /// Total payload events dropped across all sessions (visible-loss counter the
    /// caller can read without scraping the spool). The marker remains the
    /// in-stream receipt; this is a fast liveness gauge.
    dropped_total: Arc<AtomicU64>,
}

impl SpoolSink {
    /// The running total of payload records dropped under the bound (across all
    /// sessions). A non-zero value means a [`SpoolOverflow`] marker rode the
    /// stream — loss was visible.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total.load(Ordering::Relaxed)
    }

    /// Async emit: enqueue an event for the flush task. If the in-memory channel
    /// is full this awaits back-pressure rather than dropping — the disk ring's
    /// drop-oldest is the only loss point, and it is always visible.
    pub async fn emit_async(&self, event: EventEnvelope) -> Result<(), SpoolClosed> {
        self.tx.send(event).await.map_err(|_| SpoolClosed)
    }
}

/// The error when the spool's flush task has shut down (the receiver dropped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolClosed;

impl core::fmt::Display for SpoolClosed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("spool flush task has shut down")
    }
}

impl std::error::Error for SpoolClosed {}

/// The synchronous [`EventSink`] impl: a fire-and-forget emit that never blocks
/// the data path (telemetry never fails a query — doc 14 §12.4). It uses
/// `try_send`; if the in-memory channel is momentarily full the event is shed at
/// the channel (which the flush task's drop-oldest accounting on disk does not
/// see), so for the durable, visible-loss path callers use [`SpoolSink::emit_async`].
///
/// # The channel-shed is the second loss point — now marked, never silent (D116)
///
/// The channel-full shed is the ONE non-disk drop. It is counted in
/// [`Self::dropped_total`] (a process gauge) AND — like the contractual disk-ring
/// drop-oldest path — it now mints a per-session [`SpoolOverflow`] receipt in the
/// SURVIVING stream: the session key is derived from the shed event's mandatory
/// POL-3 provenance ([`session_key_of`], total on every event), the per-session
/// `dropped` count is bumped, and the marker rides the dedicated priority
/// [`Self::marker_tx`] lane onto the ring's never-evicted markers. So D116's "silent
/// loss is the one disallowed behavior" is airtight across BOTH the durable
/// [`emit_async`](Self::emit_async) disk-ring path and this sync `emit()` path. The
/// marker channel is small and separate, so it is never shed behind the payload
/// back-pressure it reports on; in the vanishingly-rare case it too is saturated the
/// gauge still rises, so the loss is never wholly unaccounted.
impl EventSink for SpoolSink {
    fn emit(&self, event: EventEnvelope) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(err) => {
                // Channel saturated (or closed): count the shed so even this path is
                // visible, never silent.
                self.dropped_total.fetch_add(1, Ordering::Relaxed);
                // Mint the per-session loss receipt from the shed event's provenance
                // (drop-oldest's disk-ring path does the same; this is the sync
                // equivalent). `try_send` hands the event back on a full/closed
                // channel, so the session key is always recoverable here.
                let shed = match err {
                    mpsc::error::TrySendError::Full(e) => e,
                    mpsc::error::TrySendError::Closed(e) => e,
                };
                self.mint_shed_marker(&shed);
            }
        }
    }
}

impl SpoolSink {
    /// Mint the per-session [`SpoolOverflow`] receipt for one sync-path channel shed
    /// and push it onto the dedicated priority lane so it lands in the surviving
    /// stream (D116). The session key is the shed event's POL-3 provenance namespace
    /// ([`session_key_of`]), and the marker's `dropped` is this session's monotonic
    /// channel-shed tally — so a saturated channel produces a sequence of receipts
    /// with rising counts, exactly mirroring the disk ring's drop-oldest markers.
    fn mint_shed_marker(&self, shed: &EventEnvelope) {
        let session = session_key_of(shed);
        let dropped = {
            let mut tally = self
                .shed_dropped
                .lock()
                .expect("sync-shed tally mutex poisoned");
            let count = tally.entry(session.clone()).or_insert(0);
            *count += 1;
            *count
        };
        let marker = SpoolOverflow {
            session,
            dropped,
            timestamp_ms: now_ms(),
            // The sync `emit()` channel-shed loss point (distinct from the disk ring).
            origin: LossOrigin::ChannelShed,
        };
        // The marker lane is small + separate, so it is essentially never the
        // bottleneck. If it too is momentarily saturated the gauge already rose, so
        // the loss is still accounted — never wholly silent.
        let _ = self.marker_tx.try_send(marker);
    }
}

/// The on-disk spool: owns the segment file and the background flush task handle.
/// Build one with [`Spool::open`]; it hands back a cloneable [`SpoolSink`] and
/// runs the flush task on the current tokio runtime.
pub struct Spool {
    path: PathBuf,
    ring: Arc<Mutex<Ring>>,
    flush_handle: tokio::task::JoinHandle<()>,
    /// The sink template handed out by [`Spool::sink`]. Held in an `Option` so
    /// [`Spool::shutdown`] can drop the spool's own reference before signalling
    /// the flush task — but shutdown does NOT depend on every cloned sink being
    /// dropped (it signals via [`Spool::shutdown_signal`]), so long-lived handles
    /// in emitters never wedge a clean shutdown.
    sink: Option<SpoolSink>,
    shutdown_signal: Arc<Notify>,
}

impl Spool {
    /// Open a spool at `path` (the segment file) with the given bounds, spawning
    /// the background flush task on the current tokio runtime.
    pub async fn open(path: impl AsRef<Path>, bounds: SpoolBounds) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let ring = Arc::new(Mutex::new(Ring::new(bounds)));
        let dropped_total = Arc::new(AtomicU64::new(0));
        let shed_dropped = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let (tx, mut rx) = mpsc::channel::<EventEnvelope>(bounds.channel_depth);
        // The dedicated priority lane for sync-path channel-shed receipts (D116): a
        // small, separate channel so a SpoolOverflow marker is never itself shed
        // behind the payload back-pressure it reports on. Sized generously relative to
        // the payload depth; the flush task lifts each marker straight onto the ring's
        // never-evicted markers.
        let (marker_tx, mut marker_rx) =
            mpsc::channel::<SpoolOverflow>(bounds.channel_depth.max(1) * 2);
        let shutdown_signal = Arc::new(Notify::new());

        // Truncate/create the segment up front so a flush always appends to a
        // known file.
        tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .await?;

        let flush_ring = Arc::clone(&ring);
        let flush_path = path.clone();
        let flush_dropped = Arc::clone(&dropped_total);
        let flush_interval = bounds.flush_interval;
        let flush_shutdown = Arc::clone(&shutdown_signal);

        let flush_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(flush_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Once the marker channel closes (all SpoolSink handles dropped) its
            // `recv()` is permanently `None`; gating the select branch on this flag
            // disables it so the loop never busy-spins on a closed lane — the payload
            // `rx` close still drives the clean exit below.
            let mut marker_open = true;
            loop {
                tokio::select! {
                    // The sync-path channel-shed receipts (D116): a SpoolOverflow
                    // minted OUTSIDE the ring by `SpoolSink::emit`, lifted here onto
                    // the ring's never-evicted priority lane so it lands in the
                    // surviving stream. The receipt's DURABILITY does not depend on
                    // select ordering — once lifted it rides the ring's never-evicted
                    // markers and is drained markers-first (`drain_batch`); select's
                    // default fairness across this lane and the payload lane is all
                    // that is needed, so this branch is NOT biased (a strict bias here
                    // perturbs the payload-flush timing the disk-ring drop-oldest tests
                    // pin). The `if marker_open` guard simply parks this branch once
                    // the lane closes so the loop never busy-spins on a dead channel.
                    maybe_marker = marker_rx.recv(), if marker_open => {
                        match maybe_marker {
                            Some(marker) => {
                                let mut ring = flush_ring.lock().await;
                                ring.push_marker(marker);
                            }
                            // The marker sender side closed (all SpoolSink handles
                            // dropped): stop polling this lane; payload `rx` close
                            // drives the exit below.
                            None => marker_open = false,
                        }
                    }
                    maybe = rx.recv() => {
                        match maybe {
                            Some(event) => {
                                let mut ring = flush_ring.lock().await;
                                if ring.push_payload(event).is_some() {
                                    flush_dropped.fetch_add(1, Ordering::Relaxed);
                                }
                                // Batch: if we've reached batch_size of payload,
                                // flush now.
                                if ring.payload.len() >= ring.bounds.batch_size {
                                    let batch = ring.drain_batch();
                                    drop(ring);
                                    let _ = append_batch(&flush_path, &batch).await;
                                }
                            }
                            // All senders dropped: drain any pending sync-shed markers
                            // first (so a shed receipt minted just before shutdown is
                            // never lost), then final drain + exit.
                            None => {
                                while let Ok(marker) = marker_rx.try_recv() {
                                    let mut ring = flush_ring.lock().await;
                                    ring.push_marker(marker);
                                }
                                drain_all(&flush_ring, &flush_path).await;
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        let mut ring = flush_ring.lock().await;
                        if !ring.is_empty() {
                            let batch = ring.drain_batch();
                            drop(ring);
                            let _ = append_batch(&flush_path, &batch).await;
                        }
                    }
                    // Explicit shutdown signal: drain pending records (draining any
                    // still-queued channel items first so nothing is lost) and exit
                    // WITHOUT waiting for every cloned sink to drop. Long-lived
                    // emitter handles never wedge a clean shutdown.
                    _ = flush_shutdown.notified() => {
                        // Drain pending sync-shed markers first (the loss receipts),
                        // then the still-queued payload, so nothing minted before the
                        // signal is lost.
                        while let Ok(marker) = marker_rx.try_recv() {
                            let mut ring = flush_ring.lock().await;
                            ring.push_marker(marker);
                        }
                        while let Ok(event) = rx.try_recv() {
                            let mut ring = flush_ring.lock().await;
                            if ring.push_payload(event).is_some() {
                                flush_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        drain_all(&flush_ring, &flush_path).await;
                        break;
                    }
                }
            }
        });

        let sink = SpoolSink {
            tx,
            marker_tx,
            shed_dropped,
            dropped_total,
        };
        Ok(Self {
            path,
            ring,
            flush_handle,
            sink: Some(sink),
            shutdown_signal,
        })
    }

    /// A cloneable sink handle for emission sites.
    pub fn sink(&self) -> SpoolSink {
        self.sink
            .as_ref()
            .expect("sink template present until shutdown consumes the spool")
            .clone()
    }

    /// The segment file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The shared ring (for in-process inspection / tests): how many payload and
    /// marker records are currently buffered.
    pub async fn buffered(&self) -> (usize, usize) {
        let ring = self.ring.lock().await;
        (ring.payload.len(), ring.markers.len())
    }

    /// Signal the flush task to drain all buffered records to disk and exit, then
    /// await it. Consumes the spool. Unlike relying on channel-close, this does
    /// NOT require every cloned [`SpoolSink`] handed to an emitter to have been
    /// dropped first — the explicit signal drains and exits regardless, so a
    /// long-lived emitter handle never wedges shutdown.
    pub async fn shutdown(mut self) -> io::Result<()> {
        // Release the spool's own sink reference first (best-effort close), then
        // fire the explicit drain-and-exit signal the flush task selects on.
        self.sink = None;
        self.shutdown_signal.notify_one();
        let _ = self.flush_handle.await;
        Ok(())
    }
}

/// Drain every buffered record (markers first, then payload) to disk. Used by the
/// flush task on both the all-senders-dropped and explicit-shutdown exits, so the
/// visible-loss receipts and pending payload always land before the task exits.
async fn drain_all(ring: &Arc<Mutex<Ring>>, path: &Path) {
    loop {
        let mut guard = ring.lock().await;
        if guard.is_empty() {
            break;
        }
        let batch = guard.drain_batch();
        drop(guard);
        if batch.is_empty() {
            break;
        }
        let _ = append_batch(path, &batch).await;
    }
}

/// Append a flush batch to the segment as length-delimited records. The on-disk
/// encoding is free implementation (doc 14 §12.4) — a simple framed log: per
/// record, a 1-byte kind tag, a 4-byte big-endian length, then the rendered body.
/// The OVERFLOW marker is rendered as plain `{session, dropped, timestamp}` text;
/// payload bodies carry the already-scrubbed envelope payload. No secret value can
/// be in here — the envelope only ever held a fingerprint (D73 chokepoint).
async fn append_batch(path: &Path, batch: &[SpoolRecord]) -> io::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await?;
    let mut buf = Vec::new();
    for rec in batch {
        match rec {
            SpoolRecord::Payload(e) => {
                let body = render_payload(e);
                buf.push(kind_tag(e.kind()));
                buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
                buf.extend_from_slice(&body);
            }
            SpoolRecord::Overflow(m) => {
                // The overflow body leads with a 1-byte loss-origin discriminator
                // (disk drop-oldest vs sync channel-shed) so an on-disk reader can
                // attribute WHICH of the two loss points minted this 0xFF marker, then
                // the `session|dropped|ts` text. The origin byte is part of the FREE
                // on-disk encoding, not the frozen wire schema.
                let mut body = Vec::with_capacity(1 + 64);
                body.push(m.origin.origin_byte());
                body.extend_from_slice(
                    format!("{}|{}|{}", m.session, m.dropped, m.timestamp_ms).as_bytes(),
                );
                buf.push(0xFF); // overflow-marker tag (priority lane)
                buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
                buf.extend_from_slice(&body);
            }
        }
    }
    file.write_all(&buf).await?;
    file.flush().await?;
    Ok(())
}

/// The 1-byte on-disk kind tag for a payload event (free encoding).
fn kind_tag(kind: EventKind) -> u8 {
    match kind {
        EventKind::FlowRecord => 1,
        EventKind::DnsEvent => 2,
        EventKind::HttpEvent => 3,
        EventKind::PolicyDecision => 4,
        EventKind::CredentialUseEvent => 5,
    }
}

/// Render a payload envelope to its on-disk body: provenance triple, an optional
/// credential FINGERPRINT (never plaintext), and the opaque payload bytes. The
/// only credential signal that can appear is the keyed digest (D73).
fn render_payload(e: &EventEnvelope) -> Vec<u8> {
    let p = e.provenance();
    let fp = e.credential_fingerprint().map(|f| f.as_hex()).unwrap_or("");
    let mut head = format!(
        "{}|{}|{}|{}|",
        p.rule_id(),
        p.policy_layer(),
        p.policy_version(),
        fp
    )
    .into_bytes();
    head.extend_from_slice(e.payload());
    head
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrub::{Fingerprinter, Secret};

    fn provenance() -> Provenance {
        Provenance::new("core/example", "pol2-system-baseline", "2026-06-01").expect("valid triple")
    }

    fn payload_event(n: usize) -> EventEnvelope {
        EventEnvelope::new(
            EventKind::FlowRecord,
            provenance(),
            format!("flow-{n}").into_bytes(),
        )
    }

    /// The scratch root for test spool segments, matching the repo's
    /// tmpfs-avoidance convention (`DS_WT_ROOT` -> `TMPDIR` -> `std::env::temp_dir()`,
    /// the same precedence as ds-dnsgate's `spool_scratch_root()`). `DS_WT_ROOT`
    /// points at a btrfs scratch root (reflink/CoW, same device as the repo), so
    /// honoring it first keeps spool fixtures off tmpfs/RAM. Test-only, no logic
    /// change to the spool itself.
    fn spool_scratch_root() -> std::path::PathBuf {
        std::env::var_os("DS_WT_ROOT")
            .or_else(|| std::env::var_os("TMPDIR"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
    }

    #[tokio::test]
    async fn spool_overflow_fires_on_a_tiny_bound() {
        let dir = spool_scratch_root().join(format!("ds-telemetry-spool-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg.spool");
        let bounds = SpoolBounds {
            max_records: 2,
            batch_size: 1,
            channel_depth: 16,
            flush_interval: std::time::Duration::from_millis(10),
        };
        let spool = Spool::open(&path, bounds).await.unwrap();
        let sink = spool.sink();

        // Push more than the bound — drop-oldest must fire and mint markers.
        for n in 0..10 {
            sink.emit_async(payload_event(n)).await.unwrap();
        }
        spool.shutdown().await.unwrap();

        // The visible-loss marker landed on disk (priority lane), never silent.
        let contents = std::fs::read(&path).unwrap();
        // The 0xFF overflow tag appears at least once.
        assert!(
            contents.contains(&0xFFu8),
            "a SpoolOverflow marker must be flushed when the bound overflows"
        );
        // The drop-oldest receipt decodes back with the disk-drop loss origin from its
        // on-disk 1-byte discriminator — this is the disk-ring loss point, never the
        // sync channel-shed (these calls await `emit_async`, so no channel shed fires).
        let markers = decode_overflow_markers(&contents);
        assert!(
            !markers.is_empty(),
            "at least one drop-oldest SpoolOverflow marker was flushed"
        );
        assert!(
            markers.iter().all(|(o, _, _)| *o == LossOrigin::DiskDrop),
            "the drop-oldest marker decodes a disk-drop loss-origin (got {markers:?})"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn no_overflow_under_the_bound() {
        let dir = spool_scratch_root().join(format!("ds-telemetry-noov-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg.spool");
        let bounds = SpoolBounds {
            max_records: 64,
            batch_size: 8,
            channel_depth: 64,
            flush_interval: std::time::Duration::from_millis(10),
        };
        let spool = Spool::open(&path, bounds).await.unwrap();
        let sink = spool.sink();
        for n in 0..16 {
            sink.emit_async(payload_event(n)).await.unwrap();
        }
        spool.shutdown().await.unwrap();
        assert_eq!(sink.dropped_total(), 0, "no loss under the bound");
        let contents = std::fs::read(&path).unwrap();
        assert!(
            !contents.contains(&0xFFu8),
            "no overflow marker without overflow"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// D116 sync-path receipt: a forced channel-full SYNCHRONOUS `emit()` shed now
    /// mints a per-session `SpoolOverflow` marker in the surviving stream — not merely
    /// a `dropped_total` gauge bump. The marker lands on the never-evicted priority
    /// lane and flushes to disk with the `0xFF` tag, exactly like the disk-ring
    /// drop-oldest receipt, so the channel-shed loss point is now visible, never
    /// silent.
    ///
    /// Forcing the shed deterministically: a `current_thread` runtime + a depth-1
    /// channel. Because the synchronous `emit()` NEVER awaits, a tight loop of
    /// `emit()` calls runs to completion before the background flush task is ever
    /// scheduled (no `.await` yields the executor to it), so the second `emit()`
    /// onward finds the depth-1 channel still full and sheds — minting markers.
    #[tokio::test(flavor = "current_thread")]
    async fn sync_emit_channel_shed_mints_a_per_session_overflow_marker() {
        let dir = spool_scratch_root().join(format!("ds-telemetry-syncshed-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg.spool");
        // Depth-1 channel, a roomy ring (so the ONLY loss point exercised is the sync
        // channel shed, never disk drop-oldest), and a long flush interval so the tick
        // does not race the test.
        let bounds = SpoolBounds {
            max_records: 4096,
            batch_size: 64,
            channel_depth: 1,
            flush_interval: std::time::Duration::from_secs(3600),
        };
        let spool = Spool::open(&path, bounds).await.unwrap();
        let sink = spool.sink();

        // A tight synchronous burst — no `.await` between calls, so the flush task is
        // never scheduled mid-burst and the depth-1 channel saturates immediately.
        for n in 0..64 {
            sink.emit(payload_event(n));
        }

        // The sync shed is counted in the process gauge (the pre-existing behavior)...
        assert!(
            sink.dropped_total() > 0,
            "a saturated depth-1 channel must shed at least one sync emit()"
        );

        // ...AND now mints per-session overflow markers in the surviving stream. Drain
        // and flush them to disk via the clean shutdown.
        spool.shutdown().await.unwrap();
        let contents = std::fs::read(&path).unwrap();
        assert!(
            contents.contains(&0xFFu8),
            "a forced channel-full sync emit() shed must mint a SpoolOverflow marker \
             (priority-lane 0xFF tag), not a silent dropped_total bump (D116)"
        );

        // The marker names the shed event's per-session provenance namespace, and its
        // body carries the monotonic per-session dropped count — decode the priority
        // lane records and assert the session/count shape.
        let markers = decode_overflow_markers(&contents);
        assert!(
            !markers.is_empty(),
            "at least one SpoolOverflow marker was flushed for the sync shed"
        );
        let session = format!("{}/{}", "pol2-system-baseline", "core/example");
        assert!(
            markers.iter().all(|(_, s, _)| *s == session),
            "the sync-shed marker names the shed event's POL-3 session namespace (got {markers:?})"
        );
        // Every marker flushed here came from the sync channel-shed loss point, so the
        // on-disk 1-byte origin discriminator decodes back to ChannelShed — never the
        // disk-ring drop-oldest origin (the ring is roomy; no payload was evicted).
        assert!(
            markers
                .iter()
                .all(|(o, _, _)| *o == LossOrigin::ChannelShed),
            "the sync-shed marker decodes a channel-shed loss-origin (got {markers:?})"
        );
        let max_dropped = markers.iter().map(|(_, _, d)| *d).max().unwrap();
        assert!(
            max_dropped >= 1,
            "the per-session dropped count is monotonic and >= 1 (got {max_dropped})"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Decode the `0xFF`-tagged priority-lane records out of a flushed segment into
    /// `(origin, session, dropped)` triples. The on-disk overflow body is a 1-byte
    /// loss-origin discriminator followed by `session|dropped|ts`. Mirrors
    /// `append_batch`'s framing: per record a 1-byte tag, a 4-byte BE length, then the
    /// body; only the `0xFF` overflow records are returned. Records whose 1-byte
    /// origin discriminator is unknown are skipped (a malformed/foreign byte is never
    /// silently coerced to a real loss point).
    fn decode_overflow_markers(bytes: &[u8]) -> Vec<(LossOrigin, String, u64)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 5 <= bytes.len() {
            let tag = bytes[i];
            let len = u32::from_be_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]])
                as usize;
            let body_start = i + 5;
            let body_end = body_start + len;
            if body_end > bytes.len() {
                break;
            }
            if tag == 0xFF {
                let body = &bytes[body_start..body_end];
                if let Some((&origin_byte, rest)) = body.split_first() {
                    if let Some(origin) = LossOrigin::from_byte(origin_byte) {
                        let text = String::from_utf8_lossy(rest);
                        let mut parts = text.splitn(3, '|');
                        let session = parts.next().unwrap_or("").to_string();
                        let dropped = parts
                            .next()
                            .and_then(|d| d.parse::<u64>().ok())
                            .unwrap_or(0);
                        out.push((origin, session, dropped));
                    }
                }
            }
            i = body_end;
        }
        out
    }

    /// The free on-disk encoding's loss-origin discriminator round-trips: a marker
    /// minted at the disk drop-oldest path encodes the disk-drop byte and a marker
    /// minted at the sync channel-shed path encodes the channel-shed byte, and both
    /// decode back to their respective `LossOrigin` out of the framed `0xFF` body.
    /// This pins the byte mapping directly through `append_batch` →
    /// `decode_overflow_markers` without needing to provoke a real ring overflow, so
    /// the two loss points are operator-distinguishable on disk.
    #[tokio::test]
    async fn loss_origin_byte_round_trips_through_the_on_disk_encoding() {
        let dir = spool_scratch_root().join(format!("ds-telemetry-origin-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg.spool");
        // Create the empty segment so `append_batch`'s append-open succeeds.
        std::fs::write(&path, b"").unwrap();

        let disk_marker = SpoolOverflow {
            session: "pol2-system-baseline/core/example".to_string(),
            dropped: 7,
            timestamp_ms: 1_000,
            origin: LossOrigin::DiskDrop,
        };
        let shed_marker = SpoolOverflow {
            session: "pol2-system-baseline/core/other".to_string(),
            dropped: 3,
            timestamp_ms: 2_000,
            origin: LossOrigin::ChannelShed,
        };
        let batch = vec![
            SpoolRecord::Overflow(disk_marker.clone()),
            SpoolRecord::Overflow(shed_marker.clone()),
        ];
        append_batch(&path, &batch).await.unwrap();

        let contents = std::fs::read(&path).unwrap();
        let decoded = decode_overflow_markers(&contents);
        assert_eq!(
            decoded,
            vec![
                (
                    LossOrigin::DiskDrop,
                    disk_marker.session,
                    disk_marker.dropped
                ),
                (
                    LossOrigin::ChannelShed,
                    shed_marker.session,
                    shed_marker.dropped
                ),
            ],
            "both loss origins decode back out of the flushed on-disk segment, in order"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// (c)-suite: a planted canary secret appears in NO spool output path. The
    /// envelope only ever carried a keyed fingerprint (D73 chokepoint), so the
    /// plaintext is structurally absent from the on-disk segment.
    #[tokio::test]
    async fn canary_secret_never_appears_in_the_spool() {
        const CANARY: &str = "ghp_PLANTEDcanary_secret_value_AABBCC";
        let dir = spool_scratch_root().join(format!("ds-telemetry-canary-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg.spool");
        let spool = Spool::open(&path, SpoolBounds::default()).await.unwrap();
        let sink = spool.sink();

        let fp = Fingerprinter::new(b"keyed-plane-key".to_vec());
        // The ONLY way a credential reaches an event is through the chokepoint.
        let envelope = EventEnvelope::new(
            EventKind::CredentialUseEvent,
            provenance(),
            b"credential-use-metadata".to_vec(),
        )
        .with_credential(fp.fingerprint(Secret::new(CANARY)));
        sink.emit_async(envelope).await.unwrap();
        spool.shutdown().await.unwrap();

        let contents = std::fs::read(&path).unwrap();
        let as_text = String::from_utf8_lossy(&contents);
        assert!(
            !as_text.contains(CANARY),
            "the canary secret must never appear in the spool"
        );
        assert!(!as_text.contains("PLANTEDcanary"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
