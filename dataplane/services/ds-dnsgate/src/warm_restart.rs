//! ds-dnsgate warm-restart — the DNS-2b admission-map REBUILD skeleton (OQ2).
//!
//! # Posture (OQ2 = REBUILD)
//!
//! The maintainer ruling of 2026-06-14 (recorded in taskdb note `01KV44KPNZ` as the
//! drafted, pending-§6-ratification **proposed D131**) settled the doc 11 §8.4
//! OQ2 open question on the **REBUILD** end of the design space (doc 11 §8.4
//! option A), NOT herd-acceptance. This module is the SKELETON of that rebuild
//! mechanism. It cites the maintainer direction as *"OQ2 rebuild posture, maintainer
//! ruling 2026-06-14 (proposed D131, pending §6 ratification)"*; it does not mint a
//! D-number, does not edit doc 04 §6 / doc 11 §8.4, and does not flip the doc 11
//! §8.4 "posture, not settled" prose (that ratification is the maintainer's, not
//! this code's).
//!
//! # The exposure window covered
//!
//! A `ds-dnsgate` restart loses the in-memory §5.2 DNS-2b admission map while the
//! kernel NFT-3 allow-set elements **persist** — they live in the kernel, not the
//! process (doc 11 §8.4). Established flows ride conntrack across the restart
//! untouched (expiry gates NEW flows only; expiry is not revocation — W4). The
//! window the rebuild covers is therefore purely **new** connections to
//! already-admitted IPs whose `(session, fqdn)` the freshly-started process has no
//! map entry for — the entry `ds-tlsproxy` reads synchronously on every
//! TLS-1/TLS-4 connection (doc 11 §5.2). Without a rebuilt entry, `ds-tlsproxy`
//! refuses such a connection until a live query re-admits the name.
//!
//! # The two-input reconstruction
//!
//! On a (simulated) restart the reconstructor rebuilds the §5.2 map from two
//! inputs, each modeled here as a synthetic in-memory fixture behind a
//! `TODO(seam: …)` hook (LOOPBACK/SYNTHETIC ONLY — no live kernel, no real spool
//! I/O):
//!
//!  1. **The per-session kernel NFT-3 set dump** — the IPs plus their element
//!     deadlines that persist in the kernel across the restart, modeled as
//!     [`KernelSetDump`] behind the [`KernelDumpSource`] trait
//!     (`TODO(seam: ds-nft kernel dump)`). In production this is the `ds-nft`
//!     kernel set-dump read; here a fixture stands in. **The kernel dump is the
//!     authoritative source of the element deadline.**
//!  2. **A replay of recent `DnsEvent`s from the §5.5 spool** — the
//!     `(session, fqdn) -> {ips, admission_type, real_targets, provenance}`
//!     provenance the gate emitted before the restart, modeled as
//!     [`SpoolReplayCorpus`] behind the [`SpoolReplaySource`] trait
//!     (`TODO(seam: spool replay)`). In production this is a bounded replay of the
//!     durable §5.5 spool; here a synthetic event corpus stands in.
//!
//! The reconstructor JOINS the two: for each kernel-resident `(session, ip)`, the
//! spool replay must substantiate the `(session, fqdn)` provenance and
//! original-query-name keying the IP was admitted under. A substantiated entry is
//! inserted through the **frozen DNS-2b API** ([`ds_contracts::dns_admission`]) —
//! it adopts the kernel element deadline for `expires_at` and reuses the existing
//! [`crate::txn::InMemoryAdmissionMap`] / [`crate::txn::InMemoryReverseIndex`]
//! machinery, NOT a parallel structure.
//!
//! # Invariants the skeleton encodes and tests (synthetic only)
//!
//! - **(a) W2 LOCKSTEP — adopt the kernel deadline, never recompute it.** A
//!   rebuilt entry's `expires_at` is ADOPTED from the kernel element deadline
//!   ([`KernelElement::deadline`]); the reconstructor NEVER invents or recomputes a
//!   timer (no `compose_deadline`, no clock read). W2 lockstep is preserved across
//!   the restart precisely because the kernel set already holds the authoritative
//!   deadline (doc 11 §8.4: *"the map adopts the element's deadline, never invents
//!   one"*). When several kernel elements back one `(session, fqdn)` (a multi-IP
//!   name), the entry's single shared deadline is the latest of the contributing
//!   element deadlines (`max`) — never shortened, mirroring the W2 refresh rule.
//! - **(b) REFCOUNT CORRECTNESS — populate the day-one reverse index.** The rebuild
//!   inserts through [`ds_contracts::dns_admission::AdmissionMap::admit`], which
//!   maintains the per-session IP↔domain refcount reverse index from day one
//!   (doc 11 §5.2). A shared-CDN IP backing N admitted fqdns ends at refcount N, so
//!   a later sibling-name revocation never severs a still-admitted name (the
//!   bias-to-under-delete property the §5.4 sweep depends on).
//! - **(c) FAIL-CLOSED ON LOSSY PROVENANCE — omit, never fabricate.** If the spool
//!   replay cannot recover the `(session, fqdn)` provenance / original-query-name
//!   keying for a kernel-resident IP, the reconstructor OMITS that entry and records
//!   the gap in [`RebuildReport::provenance_gaps`]. `ds-tlsproxy` re-admits the IP
//!   via the live TLS-1 re-resolve path on the next connection. The reconstructor
//!   NEVER fabricates an unsubstantiated vouching entry — an omitted entry is the
//!   honest, safe outcome (the herd-acceptance fallback, scoped to exactly the
//!   IPs the spool could not substantiate).
//!
//! # Herd-acceptance fallback
//!
//! The herd-acceptance path (start with an empty map and let TLS-1 re-admission
//! re-resolve on demand, doc 11 §8.4) is the HONEST FALLBACK if the spool proves
//! too lossy to reconstruct provenance — and invariant (c) is its in-the-small
//! realization: every IP the spool cannot substantiate degrades to exactly that
//! per-IP re-admission, so a wholly-empty spool degrades the entire rebuild to
//! herd-acceptance with no fabricated entries. The rebuild is therefore strictly
//! safer than, and continuous with, the fallback — never riskier.
//!
//! # The SO_REUSEPORT pairing (OUT OF SCOPE here)
//!
//! `TODO(seam: SO_REUSEPORT overlap-bind handoff)` — doc 11 §8.2 pairs the rebuild
//! with a `SO_REUSEPORT` overlap-bind handoff so the old process drains while the
//! new one rebuilds and the dead-air window approaches zero. That handoff is the
//! operational-continuity half and is OUT OF SCOPE for this skeleton; it is a
//! documented seam only, left to the socket-strategy unit (doc 11 §8.2 / §4-free).
//!
//! # Boundary discipline (D67 / file-grant honesty)
//!
//! This module speaks ONLY the family-agnostic frozen contract types
//! ([`ds_contracts::dns_admission`]) and `std` — no hickory type crosses into it
//! (the synthetic corpus carries `std::net::IpAddr`, projected to the frozen
//! [`AdmittedAddr`] at the insert boundary, exactly as `txn.rs` does). The two
//! external inputs are consumed as TRAITS ([`KernelDumpSource`],
//! [`SpoolReplaySource`]) whose bodies a production deployment supplies over
//! `ds-nft` and the §5.5 spool; the in-memory fixtures here are the
//! LOOPBACK/SYNTHETIC defaults that keep the W2-lockstep / refcount / fail-closed
//! invariants sandbox-verifiable with no live kernel and no real spool I/O.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ds_contracts::dns_admission::{
    AddressFamily, AdmissionEntry, AdmissionKey, AdmissionMap, AdmissionType, AdmittedAddr,
    Instant, Provenance,
};

use crate::txn::{is_plumbable, InMemoryAdmissionMap};

// ─────────────────────────────────────────────────────────────────────────────
// Input 1: the per-session kernel NFT-3 set dump (synthetic fixture; the
// authoritative source of the W2 deadline).  TODO(seam: ds-nft kernel dump)
// ─────────────────────────────────────────────────────────────────────────────

/// One element of a per-session kernel NFT-3 allow-set as it persists across a
/// `ds-dnsgate` restart (doc 11 §8.4): the admitted destination IP and **the
/// element's deadline** — the W2-authoritative `expires_at` the kernel still
/// holds. A rebuilt map entry ADOPTS this deadline; the reconstructor never
/// recomputes a timer (invariant (a), W2 lockstep).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelElement {
    /// The admitted destination IP the kernel allow-set element holds (a plain
    /// `std::net::IpAddr` — no hickory/proto type at this boundary; projected to
    /// the frozen [`AdmittedAddr`] at the map-insert boundary).
    pub ip: IpAddr,
    /// The element's deadline — the W2 shared deadline that survived the restart
    /// in the kernel (doc 11 W2/§8.4). This is the ONLY source of a rebuilt
    /// entry's `expires_at`; it is adopted verbatim, never recomputed.
    pub deadline: Instant,
}

/// The per-session kernel NFT-3 set dump (doc 11 §8.4): the IPs + element
/// deadlines a session's allow-set still holds in the kernel after a
/// `ds-dnsgate` restart, modeled as a synthetic in-memory fixture.
///
/// `TODO(seam: ds-nft kernel dump)` — in production this is the `ds-nft` kernel
/// set-dump read (the per-session `allow4`/`allow6` element enumeration with
/// remaining element timeouts); here a fixture stands in. NO live nft/netlink.
#[derive(Clone, Debug, Default)]
pub struct KernelSetDump {
    /// `session_uuid -> [kernel elements]`. The session UUID is the same
    /// authoritative key the DNS-2b map keys on (doc 11 §5.1/§5.2 / doc 14 §4).
    per_session: HashMap<String, Vec<KernelElement>>,
}

impl KernelSetDump {
    /// An empty kernel dump.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one kernel-resident allow-set element for a session (fixture
    /// builder). In production the `ds-nft` set-dump fills this.
    pub fn with_element(mut self, session_uuid: impl Into<String>, element: KernelElement) -> Self {
        self.per_session
            .entry(session_uuid.into())
            .or_default()
            .push(element);
        self
    }

    /// The sessions the dump holds elements for.
    pub fn sessions(&self) -> impl Iterator<Item = &str> {
        self.per_session.keys().map(String::as_str)
    }

    /// The kernel elements held for one session (empty slice if none).
    pub fn elements_for(&self, session_uuid: &str) -> &[KernelElement] {
        self.per_session
            .get(session_uuid)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Total kernel-resident `(session, ip)` elements across all sessions — the
    /// denominator the [`RebuildReport`] reconciles substantiated + omitted
    /// against.
    pub fn element_count(&self) -> usize {
        self.per_session.values().map(Vec::len).sum()
    }
}

/// The source of the kernel NFT-3 set dump — the production seam over `ds-nft`'s
/// kernel set-dump read (`TODO(seam: ds-nft kernel dump)`), consumed as a trait so
/// the reconstructor never names a live-kernel type. The in-memory
/// [`KernelSetDump`] fixture is the LOOPBACK/SYNTHETIC default.
pub trait KernelDumpSource {
    /// Dump the persisted per-session NFT-3 allow-set state. In production a real
    /// kernel read; here a synthetic fixture. The reconstructor treats the
    /// returned deadlines as authoritative (W2 lockstep).
    fn dump(&self) -> KernelSetDump;
}

impl KernelDumpSource for KernelSetDump {
    fn dump(&self) -> KernelSetDump {
        self.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Input 2: the §5.5 DnsEvent spool replay corpus (synthetic fixture; the source
// of (session,fqdn) provenance + admission_type + real_targets).
// TODO(seam: spool replay)
// ─────────────────────────────────────────────────────────────────────────────

/// One reconstructed provenance record recovered by replaying the §5.5 `DnsEvent`
/// spool (doc 11 §5.5/§8.4): the `(session, fqdn)` the admission was minted under
/// and everything about it EXCEPT the deadline — which the kernel dump owns (W2
/// lockstep). The replay supplies provenance and original-query-name keying; the
/// kernel supplies the IPs that persisted and their deadlines.
///
/// `admitted_at` is the spool-recorded admission time (recovered for the entry's
/// `admitted_at` field). It is provenance, NOT a deadline source — the deadline is
/// the kernel's alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolRecord {
    /// The session the admission was minted for (doc 11 §5.1) — one third of the
    /// DNS-2b key and the join key against the kernel dump.
    pub session_uuid: String,
    /// The ORIGINAL query FQDN the guest asked (pre-CNAME-chase) — the W3
    /// admission key the spool recovers. NEVER an intermediate CNAME target.
    pub original_query_fqdn: String,
    /// The IPs this `(session, fqdn)` admission covered, as recovered from the
    /// spool. The reconstructor INTERSECTS these with the kernel-resident IPs: an
    /// entry is built only from IPs that are BOTH spool-substantiated for the name
    /// AND still kernel-resident (a still-plumbed IP with recovered provenance).
    pub admitted_ips: Vec<IpAddr>,
    /// The admission class the spool recorded (doc 11 §5.2 / §3.5): `Normal` at v0,
    /// `Synthetic` for a phase-B synthetic-A admission. Recovered so the rebuilt
    /// entry carries the right class — a synthetic entry must keep its
    /// `real_targets`.
    pub admission_type: AdmissionType,
    /// The phase-B real (v6) targets a SYNTHETIC entry stands for (doc 11 §5.2) —
    /// empty for a NORMAL admission. Recovered from the spool so `ds-tlsproxy`'s
    /// synthetic-dial keying survives the restart.
    pub real_targets: Vec<IpAddr>,
    /// POL-3 provenance (rule id / layer / policy version) the admission carried —
    /// recovered so the rebuilt entry's provenance is the original verdict's, never
    /// a fabricated one. A record missing provenance cannot substantiate an entry
    /// (invariant (c)); see [`SpoolRecord::has_provenance`].
    pub provenance: Provenance,
    /// The spool-recorded admission time, recovered for the entry's `admitted_at`.
    /// Provenance only — NOT a deadline source (the kernel owns the deadline).
    pub admitted_at: Instant,
}

impl SpoolRecord {
    /// Whether this record carries usable POL-3 provenance — all three triple
    /// fields non-empty (doc 11 §6.7). A record whose provenance the spool could
    /// not recover (any field blank) CANNOT substantiate a rebuilt entry: the
    /// reconstructor fails closed and omits it (invariant (c)), never fabricating a
    /// blank-provenance vouching entry.
    pub fn has_provenance(&self) -> bool {
        !self.provenance.rule_id.is_empty()
            && !self.provenance.policy_layer.is_empty()
            && !self.provenance.policy_version.is_empty()
    }
}

/// The §5.5 `DnsEvent` spool replay corpus (doc 11 §8.4): the recent
/// `(session, fqdn)` provenance records recovered by replaying the durable spool,
/// modeled as a synthetic in-memory fixture.
///
/// `TODO(seam: spool replay)` — in production this is a bounded replay of the
/// §5.5 disk-bounded spool (the recent `DnsEvent`s, joined to recover each
/// admission's provenance and original-query-name keying); here a synthetic event
/// corpus stands in. NO live spool I/O.
#[derive(Clone, Debug, Default)]
pub struct SpoolReplayCorpus {
    /// `(session_uuid, original_query_fqdn) -> record`. One record per name: the
    /// spool replay collapses a name's recent admission events into the latest
    /// recovered provenance for it (the production replay folds re-resolutions;
    /// the fixture records the recovered end state).
    records: HashMap<(String, String), SpoolRecord>,
}

impl SpoolReplayCorpus {
    /// An empty corpus — the wholly-lossy spool. A rebuild against it omits every
    /// kernel-resident IP (invariant (c)), degrading cleanly to herd-acceptance
    /// with NO fabricated entries.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one recovered provenance record (fixture builder). In production the
    /// spool replay fills this.
    pub fn with_record(mut self, record: SpoolRecord) -> Self {
        self.records.insert(
            (
                record.session_uuid.clone(),
                record.original_query_fqdn.clone(),
            ),
            record,
        );
        self
    }

    /// The recovered records that mention a kernel-resident `(session, ip)` — the
    /// candidate names whose provenance might substantiate an entry for the IP. A
    /// shared-CDN IP backing several names yields several candidates (each
    /// substantiates its OWN `(session, fqdn)` entry, so the IP's refcount ends at
    /// the number of names — invariant (b)).
    fn records_vouching_for(&self, session_uuid: &str, ip: IpAddr) -> Vec<&SpoolRecord> {
        self.records
            .values()
            .filter(|r| r.session_uuid == session_uuid && r.admitted_ips.contains(&ip))
            .collect()
    }
}

/// The source of the §5.5 spool replay — the production seam over a bounded replay
/// of the durable spool (`TODO(seam: spool replay)`), consumed as a trait so the
/// reconstructor never names a live spool type. The in-memory [`SpoolReplayCorpus`]
/// fixture is the LOOPBACK/SYNTHETIC default.
pub trait SpoolReplaySource {
    /// Replay the recent spool to recover `(session, fqdn)` provenance. In
    /// production a bounded durable-spool read; here a synthetic corpus.
    fn replay(&self) -> SpoolReplayCorpus;
}

impl SpoolReplaySource for SpoolReplayCorpus {
    fn replay(&self) -> SpoolReplayCorpus {
        self.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The rebuild report — what was substantiated, what was omitted (fail-closed).
// ─────────────────────────────────────────────────────────────────────────────

/// A kernel-resident IP the rebuild could NOT substantiate from the spool replay
/// and therefore OMITTED (invariant (c), fail-closed). `ds-tlsproxy` re-admits it
/// via the live TLS-1 re-resolve path on the next connection; the reconstructor
/// never fabricates a vouching entry for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceGap {
    /// The session the unsubstantiated kernel element belonged to.
    pub session_uuid: String,
    /// The kernel-resident IP with no recoverable `(session, fqdn)` provenance.
    pub ip: IpAddr,
    /// Why the IP could not be substantiated (a diagnostic, not a behavior input).
    pub reason: GapReason,
}

/// Why a kernel-resident IP could not be substantiated from the spool replay
/// (invariant (c)). A diagnostic for operators / the §5.5 telemetry join — the
/// behavior is identical for every reason: OMIT the entry, fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GapReason {
    /// No spool record mentions this `(session, ip)` at all — the spool lost the
    /// admission's provenance entirely (the lossy-spool case doc 11 §8.4 names as
    /// the herd-acceptance fallback trigger, here scoped to the single IP).
    NoVouchingRecord,
    /// A spool record mentions the `(session, ip)` but carries incomplete POL-3
    /// provenance (a blank triple field) — it cannot stand up a vouching entry
    /// (doc 11 §6.7: provenance is mandatory), so the IP is omitted rather than
    /// admitted under fabricated provenance.
    IncompleteProvenance,
    /// The IP recovered for a substantiated name is not plumbable (it would be
    /// scrubbed by the DNS-4 / W5 sanity filter): a kernel element should never
    /// hold such an IP, but if a corrupt dump does, the reconstructor refuses to
    /// re-admit it (fail-closed; the same W5 discipline the live admit path runs).
    UnplumbableAddress,
    /// The frozen [`AdmissionMap::admit`] call REFUSED the substantiated entry —
    /// the insert-then-answer set-programming step (or a storage-backed map's
    /// persist) returned [`AdmissionError`] instead of `Ok(())`. The name is left
    /// OUT of the rebuilt map and OUT of the substantiated counters, exactly the
    /// W1 invariant-(c) fail-closed discipline the live forward path runs on a
    /// `SetProgrammingFailed` (doc 11 §3.1 W1 (c)): a half-written entry is NEVER
    /// claimed as rebuilt, and `ds-tlsproxy` re-admits the IP live on the next
    /// connection. The in-memory [`InMemoryAdmissionMap`] never trips this (its
    /// `admit` is infallible — see the `debug_assert` infallibility pin in
    /// [`Reconstructor::rebuild_into`]); a storage-backed `AdmissionMap` can, and
    /// this reason is how that failure surfaces as an honest provenance gap rather
    /// than a silently-dropped element.
    AdmitFailed,
}

/// The outcome of one warm-restart rebuild: how many kernel-resident IPs were
/// substantiated into the rebuilt map, and the per-IP provenance gaps that were
/// fail-closed omitted. Reconciles against the kernel dump's element count.
///
/// # Two substantiated metrics (REPORTING CLARITY, doc 11 §5.5)
///
/// The report carries the substantiated kernel-resident IPs under **two** counts,
/// which differ exactly when a shared-CDN IP backs more than one name:
///
///  - [`RebuildReport::ips_substantiated`] is the **per-name reference** count —
///    each name's contribution, so a shared IP backing N names contributes N. It
///    mirrors the §5.2 reverse-index refcount-N semantics (invariant (b)) and is
///    the diagnostic that tells operators how many `(session, fqdn)` references
///    the rebuilt reverse index holds.
///  - [`RebuildReport::distinct_ips_substantiated`] is the **distinct
///    `(session, ip)` element** count — each kernel-resident element counted ONCE
///    regardless of how many names back it. It is the metric that reconciles
///    against the kernel dump (each dump element is one allow-set element):
///
///    ```text
///    distinct_ips_substantiated + provenance_gaps.len() == kernel.element_count()
///    ```
///
///    holds in ALL cases, including shared IPs — the §5.5 telemetry join the doc
///    11 §5.5 LOG-1 telemetry needs. (`ips_substantiated` only reconciles that way
///    in the degenerate 1-name-per-element case.)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RebuildReport {
    /// The distinct `(session, fqdn)` entries written into the rebuilt map.
    pub entries_rebuilt: usize,
    /// The **per-name reference** count of kernel-resident `(session, ip)` elements
    /// substantiated into a rebuilt entry. A shared-CDN IP backing N names counts
    /// once PER name it substantiated (it is the same IP, but it vouches for N
    /// entries → refcount N, invariant (b)). This is the refcount diagnostic — it
    /// mirrors the §5.2 reverse-index membership, NOT the kernel element count. For
    /// the metric that reconciles against [`KernelSetDump::element_count`] in all
    /// cases (shared IPs included), see [`RebuildReport::distinct_ips_substantiated`].
    pub ips_substantiated: usize,
    /// The **distinct `(session, ip)` element** count of kernel-resident elements
    /// substantiated into the rebuilt map — each kernel allow-set element counted
    /// ONCE regardless of how many names back it. This is the metric the doc 11
    /// §5.5 telemetry join reconciles against the kernel dump, EXACTLY in all cases
    /// including shared IPs:
    /// `distinct_ips_substantiated + provenance_gaps.len() == kernel.element_count()`.
    /// (A shared-CDN IP backing N names is one kernel element → +1 here, but +N in
    /// [`RebuildReport::ips_substantiated`].)
    ///
    /// # Reconciliation choice on an admit failure (option (a))
    ///
    /// This count is bumped optimistically in the element loop the moment a kernel
    /// element clears every provenance check (before the per-name `admit`). If the
    /// frozen [`AdmissionMap::admit`] later REFUSES the name (a storage-backed map
    /// returning [`AdmissionError`]; the in-memory body is infallible), the
    /// reconstructor takes **option (a)**: it DECREMENTS this count **per element**
    /// — by the number of kernel elements that substantiated each unadmitted
    /// `(session, ip)` (a duplicate dump bumps the same IP once per element) — and
    /// pushes one [`GapReason::AdmitFailed`] gap per such element, so the
    /// `distinct_ips_substantiated + provenance_gaps.len() == element_count()`
    /// reconciliation in [`RebuildReport::reconciles_with`] stays EXACT through the
    /// failure EVEN under a duplicate-element dump — every admit-refused element
    /// migrates from the substantiated side to the gap side, never double-counted,
    /// never silently dropped (W1 (c)). A per-IP decrement (once per distinct IP)
    /// would leave a phantom substantiated count and under-report the gaps when
    /// several duplicate elements back one refused name.
    pub distinct_ips_substantiated: usize,
    /// The kernel-resident IPs the spool could not substantiate — OMITTED,
    /// fail-closed (invariant (c)). Never fabricated; re-admitted live by TLS-1.
    pub provenance_gaps: Vec<ProvenanceGap>,
}

impl RebuildReport {
    /// Whether every kernel-resident IP was substantiated (no fail-closed gaps) —
    /// the fully-recoverable spool case where the rebuilt map exactly mirrors the
    /// pre-restart map for the covered sessions.
    pub fn is_fully_substantiated(&self) -> bool {
        self.provenance_gaps.is_empty()
    }

    /// Whether the report reconciles EXACTLY against the kernel dump's element
    /// count: every kernel-resident `(session, ip)` element is accounted for as
    /// either a distinct substantiated element or a fail-closed omitted gap. This
    /// is the doc 11 §5.5 telemetry-join invariant, which holds in ALL cases
    /// (shared IPs included) BECAUSE it uses the distinct-element metric, not the
    /// per-name reference count. A reconstructor that obeys invariant (c) — every
    /// kernel element is substantiated XOR recorded as a gap — always satisfies it.
    pub fn reconciles_with(&self, kernel: &KernelSetDump) -> bool {
        self.distinct_ips_substantiated + self.provenance_gaps.len() == kernel.element_count()
    }

    /// Project this report onto the convention-layer warm-restart COMPLETION telemetry
    /// event ([`crate::event::WarmRestartCompletionEvent`]) so a `ds-dnsgate` restart's
    /// substantiation coverage is OPERATIONALLY OBSERVABLE on the §5.5 spool (doc 11
    /// §8.4 / §5.5). The event carries the **distinct `(session, ip)` substantiated
    /// element count** ([`Self::distinct_ips_substantiated`]) and the **reconciles bit**
    /// derived RIGHT HERE from [`Self::reconciles_with`] against the kernel dump (the
    /// dump is in scope at the warm_restart boundary, but never crosses into the
    /// hickory-free / `ds-contracts`-free event surface — only the projected scalars +
    /// the bit do, the §5.5 collapse discipline / D67 corollary).
    ///
    /// `provenance` is the POL-3 triple the rebuilt admissions were minted under (the
    /// live policy version), present on every event (§6.7). The completion event encodes
    /// to a convention-layer [`crate::event::EventEnvelope`]
    /// ([`crate::event::WarmRestartCompletionEvent::to_envelope`]) the production spool
    /// transports — so `main` can route a synthetic warm-restart completion onto the
    /// real `ds_telemetry::SpoolSink` exactly as the snapshot-drop leg routes a drop.
    pub fn completion_event(
        &self,
        kernel: &KernelSetDump,
        provenance: crate::event::EventProvenance,
    ) -> crate::event::WarmRestartCompletionEvent {
        crate::event::WarmRestartCompletionEvent::new(
            self.distinct_ips_substantiated,
            self.provenance_gaps.len(),
            self.entries_rebuilt,
            // The reconciles bit is DERIVED from `reconciles_with(&dump)` — the kernel
            // dump is consumed here for the bit only; it never crosses into the event.
            self.reconciles_with(kernel),
            provenance,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The reconstructor.
// ─────────────────────────────────────────────────────────────────────────────

/// The warm-restart reconstructor (doc 11 §8.4, OQ2 rebuild posture): rebuild the
/// in-memory §5.2 DNS-2b map from the two synthetic inputs, inserting each
/// substantiated `(session, fqdn)` entry through the **frozen DNS-2b API** and
/// reusing the existing [`InMemoryAdmissionMap`] machinery (NOT a parallel
/// structure).
///
/// The single entry point [`Reconstructor::rebuild`] consumes a
/// [`KernelDumpSource`] and a [`SpoolReplaySource`], produces a freshly-rebuilt
/// [`InMemoryAdmissionMap`] plus a [`RebuildReport`], and encodes invariants
/// (a) W2 lockstep, (b) refcount correctness, and (c) fail-closed-on-lossy
/// provenance.
#[derive(Debug, Default)]
pub struct Reconstructor;

impl Reconstructor {
    /// A fresh reconstructor.
    pub fn new() -> Self {
        Self
    }

    /// Rebuild the DNS-2b map from a kernel set dump + a spool replay (doc 11 §8.4
    /// OQ2 rebuild).
    ///
    /// For each kernel-resident `(session, ip)` the reconstructor finds the spool
    /// record(s) that vouch for the IP under a recovered `(session, fqdn)` name.
    /// Per substantiated name it builds an [`AdmissionEntry`] whose:
    ///  - `admitted_ips` are exactly the kernel-resident IPs the spool
    ///    substantiates for THAT name (the intersection of the kernel dump and the
    ///    record's `admitted_ips`),
    ///  - `expires_at` is ADOPTED from the kernel element deadline — the `max` of
    ///    the contributing elements' deadlines when a multi-IP name has several
    ///    (never recomputed, never shortened: invariant (a) / W2),
    ///  - `admission_type` / `real_targets` / `provenance` / `admitted_at` are the
    ///    spool-recovered values.
    ///
    /// The entry is inserted through [`AdmissionMap::admit`], which populates the
    /// day-one reverse index (invariant (b)). A kernel-resident IP with no usable
    /// vouching record is OMITTED and recorded as a [`ProvenanceGap`] (invariant (c)).
    ///
    /// Returns the freshly-rebuilt map and the reconciliation report. The map is
    /// the SAME [`InMemoryAdmissionMap`] type the live admit path writes, so a
    /// rebuilt map is byte-for-byte a normal DNS-2b map (`ds-tlsproxy` reads it
    /// through the identical frozen API).
    pub fn rebuild<K: KernelDumpSource, S: SpoolReplaySource>(
        &self,
        kernel: &K,
        spool: &S,
    ) -> (InMemoryAdmissionMap, RebuildReport) {
        // The production / loopback case writes the infallible in-memory body
        // ([`InMemoryAdmissionMap`]). The generic [`Reconstructor::rebuild_into`]
        // carries the actual reconstruction logic so a storage-backed (genuinely
        // fallible) `AdmissionMap` — and the `#[cfg(test)]` `FailingAdmissionMap`
        // fixture that drives the W1 (c) admit-failure arm — share ONE code path.
        self.rebuild_into::<K, S, InMemoryAdmissionMap>(kernel, spool)
    }

    /// The generic reconstruction core (doc 11 §8.4 OQ2 rebuild), parameterized over
    /// the target [`AdmissionMap`] body `M` so the SAME logic drives both the
    /// infallible in-memory body ([`Reconstructor::rebuild`]) and a genuinely
    /// fallible storage-backed map. `M::default()` is the empty rebuilt map.
    ///
    /// # W1 invariant (c) — a refused `admit` becomes an honest provenance gap
    ///
    /// If [`AdmissionMap::admit`] returns `Err` for a substantiated name, the
    /// reconstructor takes **reconciliation option (a)** (documented on
    /// [`RebuildReport::distinct_ips_substantiated`]): the name is left OUT of the
    /// map and OUT of the success counters (`entries_rebuilt` / `ips_substantiated`
    /// are bumped only on `Ok`), and for each unadmitted `(session, ip)` the failed
    /// entry held that NO other successful admit in this session substantiated, the
    /// reconstructor DECREMENTS `distinct_ips_substantiated` and pushes a
    /// [`GapReason::AdmitFailed`] gap **once per kernel element** that substantiated
    /// that IP (so a duplicate-element dump migrates every duplicated element, not
    /// just one). The elements thus migrate from the substantiated side to the gap
    /// side, keeping
    /// `distinct_ips_substantiated + provenance_gaps.len() == element_count()`
    /// EXACT through the failure (W1 (c): fail closed, never silently drop). An IP a
    /// sibling name already admitted successfully stays substantiated (it is still
    /// plumbed and reverse-indexed), so the shared-CDN refcount is never
    /// spuriously torn down.
    pub fn rebuild_into<
        K: KernelDumpSource,
        S: SpoolReplaySource,
        M: AdmissionMap + Default + 'static,
    >(
        &self,
        kernel: &K,
        spool: &S,
    ) -> (M, RebuildReport) {
        let dump = kernel.dump();
        let replay = spool.replay();

        let mut map = M::default();
        let mut report = RebuildReport::default();

        // Process each session's kernel elements. The session UUID is the shared
        // join key between the kernel dump and the spool replay (doc 11 §5.1).
        for session_uuid in dump.sessions() {
            let elements = dump.elements_for(session_uuid);

            // Group the kernel-resident IPs by the recovered `(session, fqdn)` name
            // that substantiates them. A name's entry is built from the
            // INTERSECTION of (its spool-recovered IPs) ∩ (the kernel-resident IPs)
            // so the rebuilt entry never claims an IP the kernel no longer holds,
            // and never an IP the spool did not record for the name. Each IP also
            // carries forward the kernel element's deadline (W2 lockstep).
            //
            // `per_name: (fqdn) -> (record, [(ip, kernel_deadline)])`
            let mut per_name: HashMap<String, NameRebuild<'_>> = HashMap::new();

            // Per `(session, ip)` count of kernel ELEMENTS that substantiated the IP
            // into `distinct_ips_substantiated`. A duplicate dump that repeats the
            // SAME element bumps the same IP once PER element (the increment below is
            // per-element, mirroring `element_count()`), so the W1 (c) admit-failure
            // arm must migrate the IP off the substantiated tally PER element too —
            // a per-IP decrement would leave a phantom count and under-report the
            // gaps when several elements back one refused name.
            let mut substantiated_elements: HashMap<IpAddr, usize> = HashMap::new();

            for element in elements {
                let ip = element.ip;

                // Invariant (c) edge: a corrupt kernel dump holding an unplumbable
                // IP is refused (the live admit path's W5 discipline), recorded as
                // a gap rather than re-admitted.
                if !is_plumbable(ip) {
                    report.provenance_gaps.push(ProvenanceGap {
                        session_uuid: session_uuid.to_string(),
                        ip,
                        reason: GapReason::UnplumbableAddress,
                    });
                    continue;
                }

                let vouching = replay.records_vouching_for(session_uuid, ip);
                if vouching.is_empty() {
                    // (c) FAIL-CLOSED: no recovered provenance for this kernel IP.
                    // Omit it — TLS-1 re-admits live. Never fabricate.
                    report.provenance_gaps.push(ProvenanceGap {
                        session_uuid: session_uuid.to_string(),
                        ip,
                        reason: GapReason::NoVouchingRecord,
                    });
                    continue;
                }

                // A record may mention the IP but lack usable POL-3 provenance: the
                // IP is unsubstantiated for any name. Only records WITH provenance
                // can stand up an entry (invariant (c) / doc 11 §6.7).
                let usable: Vec<&SpoolRecord> = vouching
                    .iter()
                    .copied()
                    .filter(|r| r.has_provenance())
                    .collect();
                if usable.is_empty() {
                    report.provenance_gaps.push(ProvenanceGap {
                        session_uuid: session_uuid.to_string(),
                        ip,
                        reason: GapReason::IncompleteProvenance,
                    });
                    continue;
                }

                // This kernel element passed every fail-closed check, so it WILL be
                // substantiated into the rebuilt map: count it ONCE as a distinct
                // `(session, ip)` element (regardless of how many names back it).
                // This is the metric that reconciles against the kernel dump's
                // element_count in all cases, shared IPs included (it is bumped
                // here, in the element loop, exactly once per substantiated kernel
                // element; the per-name reference count `ips_substantiated` is bumped
                // separately, once per name, at admit time below).
                report.distinct_ips_substantiated += 1;
                // Track the per-element substantiation count for THIS `(session, ip)`
                // so a refused admit can decrement it off PER element (a duplicate
                // dump bumps the same IP more than once here).
                *substantiated_elements.entry(ip).or_insert(0) += 1;

                // The IP is substantiated for each usable record's name. Add it (with
                // the kernel deadline) to every such name's rebuild — a shared-CDN IP
                // vouches for N names → N entries reference it → refcount N (b).
                for record in usable {
                    let entry = per_name
                        .entry(record.original_query_fqdn.clone())
                        .or_insert_with(|| NameRebuild::new(record));
                    entry.add_ip(ip, element.deadline);
                }
            }

            // Write each substantiated name through the FROZEN DNS-2b API. `admit`
            // populates the day-one reverse index (b); the entry adopts the kernel
            // deadline (a); provenance/type/real_targets are the spool's (c-safe).
            //
            // We track per-session which distinct `(session, ip)` elements were
            // actually admitted by at least one SUCCESSFUL name, and which the
            // admit refused, so the W1 (c) admit-failure arm can migrate a refused
            // element from the substantiated side to the gap side EXACTLY (option
            // (a)) — without tearing down an IP a sibling name admitted fine (a
            // shared-CDN IP stays plumbed/reverse-indexed if ANY name held it).
            let mut admitted_ips: HashSet<IpAddr> = HashSet::new();
            let mut failed_ips: HashSet<IpAddr> = HashSet::new();
            for (fqdn, rebuild) in per_name {
                // Capture the distinct kernel IPs this name carries BEFORE the entry
                // is consumed — they key the W1 (c) admit-failure gap below.
                let entry_ips = rebuild.ips.clone();
                let entry = rebuild.into_entry();
                let ip_count = entry.admitted_ips.len();
                let key = AdmissionKey {
                    session_uuid: session_uuid.to_string(),
                    original_query_fqdn: fqdn,
                };
                match map.admit(key, entry) {
                    Ok(()) => {
                        report.entries_rebuilt += 1;
                        report.ips_substantiated += ip_count;
                        admitted_ips.extend(entry_ips);
                    }
                    Err(_err) => {
                        // W1 INVARIANT (c) — FAIL CLOSED ON A REFUSED admit. The frozen
                        // `AdmissionMap::admit` surface is fallible (a storage-backed
                        // body can return `AdmissionError`; the in-memory body never
                        // does — see the infallibility pin below). A refused name is
                        // left OUT of the rebuilt map and OUT of the success counters
                        // (`entries_rebuilt` / `ips_substantiated` are bumped ONLY on
                        // `Ok`), so a half-written entry is never claimed as rebuilt.
                        // Per option (a) the refused entry's distinct IPs become
                        // `AdmitFailed` provenance gaps below (resolved after the loop
                        // so a sibling name that admitted the SAME IP still wins). The
                        // INFALLIBILITY PIN: for the in-memory case this is unreachable,
                        // so assert it — a future genuinely-fallible storage map trips
                        // the gap path, not this assert (which only guards the
                        // documented-infallible body).
                        debug_assert!(
                            !is_in_memory_map::<M>(),
                            "InMemoryAdmissionMap::admit is infallible but returned {_err:?}"
                        );
                        failed_ips.extend(entry_ips);
                    }
                }
            }

            // Resolve option (a): a distinct kernel IP whose ONLY admit(s) were
            // refused (no successful sibling name held it) migrates from the
            // substantiated tally to a `GapReason::AdmitFailed` gap — keeping
            // `distinct_ips_substantiated + provenance_gaps.len() == element_count()`
            // exact through the failure (W1 (c)). An IP a sibling admitted stays
            // substantiated (it is plumbed and reverse-indexed); never torn down.
            for ip in &failed_ips {
                if admitted_ips.contains(ip) {
                    continue;
                }
                // PER-ELEMENT migration: the IP was counted into
                // `distinct_ips_substantiated` once per kernel element that
                // substantiated it (a duplicate dump counts the same `(session, ip)`
                // more than once). Migrate EVERY such element off the substantiated
                // tally and record one `AdmitFailed` gap per element, so
                // `distinct_ips_substantiated + provenance_gaps.len() == element_count()`
                // stays EXACT even under a duplicate-element dump — a per-IP decrement
                // (once per distinct IP) would leave a phantom substantiated count and
                // under-report the gaps for the duplicated elements.
                let element_count = substantiated_elements.get(ip).copied().unwrap_or(0);
                for _ in 0..element_count {
                    report.distinct_ips_substantiated -= 1;
                    report.provenance_gaps.push(ProvenanceGap {
                        session_uuid: session_uuid.to_string(),
                        ip: *ip,
                        reason: GapReason::AdmitFailed,
                    });
                }
            }
        }

        (map, report)
    }
}

/// Whether `M` is the documented-INFALLIBLE in-memory admission body
/// ([`InMemoryAdmissionMap`]) — the predicate that scopes the `admit`-infallibility
/// `debug_assert` in [`Reconstructor::rebuild_into`] to exactly the body whose
/// `admit` is contractually `Ok`-only. A genuinely fallible storage-backed `M`
/// returns `false`, so its admit-failures flow to the W1 (c) `AdmitFailed` gap path
/// instead of tripping the assert.
fn is_in_memory_map<M: AdmissionMap + 'static>() -> bool {
    std::any::TypeId::of::<M>() == std::any::TypeId::of::<InMemoryAdmissionMap>()
}

/// The in-flight accumulation of one `(session, fqdn)` name's rebuilt entry while
/// the reconstructor walks the kernel elements: the spool-recovered provenance
/// (borrowed from the replay corpus) plus the kernel-resident IPs substantiated
/// for it and their adopted deadlines.
struct NameRebuild<'a> {
    /// The spool record this name's provenance / type / real_targets / admitted_at
    /// come from.
    record: &'a SpoolRecord,
    /// The kernel-resident IPs substantiated for this name, deduped (a malformed
    /// dump could repeat an IP; the entry holds each distinct IP once so the
    /// reverse-index refcount counts distinct-name membership, matching the live
    /// admit path).
    ips: Vec<IpAddr>,
    /// The single shared deadline the entry adopts: the `max` of the contributing
    /// kernel elements' deadlines (W2 — never shortened; the kernel is
    /// authoritative). `None` until the first IP is added.
    deadline: Option<Instant>,
}

impl<'a> NameRebuild<'a> {
    fn new(record: &'a SpoolRecord) -> Self {
        Self {
            record,
            ips: Vec::new(),
            deadline: None,
        }
    }

    /// Add one kernel-resident IP (with its adopted kernel deadline) to this name's
    /// rebuild. The IP is deduped; the entry's shared deadline becomes the `max` of
    /// the contributing element deadlines (W2 lockstep — adopt, never shorten).
    fn add_ip(&mut self, ip: IpAddr, kernel_deadline: Instant) {
        if !self.ips.contains(&ip) {
            self.ips.push(ip);
        }
        // Adopt the kernel deadline; for a multi-IP name take the latest so the
        // entry's single shared deadline never undercuts a still-live element
        // (mirrors the W2 `max(existing, new)` refresh rule — never shortened).
        self.deadline = Some(match self.deadline {
            Some(existing) if existing >= kernel_deadline => existing,
            _ => kernel_deadline,
        });
    }

    /// Finalize into the frozen [`AdmissionEntry`]: the adopted kernel deadline as
    /// `expires_at` (a), the spool-recovered admission_type / real_targets /
    /// provenance / admitted_at (c-safe — every field is recovered, none
    /// fabricated). Called only for a substantiated name (≥1 IP), so `deadline` is
    /// always `Some`.
    fn into_entry(self) -> AdmissionEntry {
        let expires_at = self
            .deadline
            .expect("a rebuilt name has at least one substantiated kernel IP");
        let admitted_ips = self.ips.iter().copied().map(to_admitted_addr).collect();
        let real_targets = self
            .record
            .real_targets
            .iter()
            .copied()
            .map(to_admitted_addr)
            .collect();
        AdmissionEntry {
            admitted_ips,
            admission_type: self.record.admission_type,
            real_targets,
            // W2 LOCKSTEP: adopted from the kernel element deadline, NEVER
            // recomputed (no compose_deadline, no clock read on this path).
            expires_at,
            admitted_at: self.record.admitted_at,
            provenance: self.record.provenance.clone(),
        }
    }
}

/// Project a `std::net::IpAddr` onto the frozen family-agnostic [`AdmittedAddr`]
/// (network-byte-order octets + family tag) — the SAME projection `txn.rs` runs at
/// the map-insert boundary, so a rebuilt entry's IPs are byte-identical to a
/// live-admitted entry's (no stdlib/framework address type crosses the frozen
/// map API). The reverse index keys on these octets, so the refcount agrees with
/// the live path's (invariant (b)).
fn to_admitted_addr(addr: IpAddr) -> AdmittedAddr {
    match addr {
        IpAddr::V4(v4) => AdmittedAddr {
            family: AddressFamily::V4,
            octets: v4.octets().to_vec(),
        },
        IpAddr::V6(v6) => AdmittedAddr {
            family: AddressFamily::V6,
            octets: v6.octets().to_vec(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ds_contracts::dns_admission::ReverseIndex;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const NANOS_PER_SEC: u64 = 1_000_000_000;

    fn deadline_secs(secs: u64) -> Instant {
        Instant::from_unix_nanos(secs * NANOS_PER_SEC)
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn prov(version: &str) -> Provenance {
        Provenance {
            rule_id: "rule-allow-1".into(),
            policy_layer: "org".into(),
            policy_version: version.into(),
        }
    }

    /// A normal spool record for `(session, fqdn)` over the given IPs.
    fn normal_record(session: &str, fqdn: &str, ips: Vec<IpAddr>, version: &str) -> SpoolRecord {
        SpoolRecord {
            session_uuid: session.into(),
            original_query_fqdn: fqdn.into(),
            admitted_ips: ips,
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
            provenance: prov(version),
            admitted_at: deadline_secs(1_000),
        }
    }

    fn key(session: &str, fqdn: &str) -> AdmissionKey {
        AdmissionKey {
            session_uuid: session.into(),
            original_query_fqdn: fqdn.into(),
        }
    }

    fn admitted_v4(a: u8, b: u8, c: u8, d: u8) -> AdmittedAddr {
        AdmittedAddr {
            family: AddressFamily::V4,
            octets: vec![a, b, c, d],
        }
    }

    // ── Acceptance: rebuilt map == pre-restart map for substantiated entries ────

    #[test]
    fn rebuilt_map_equals_pre_restart_map_for_substantiated_entries() {
        // Pre-restart: one session admitted example.test -> 93.184.216.34 with a
        // kernel element deadline of t=2000s. The spool recovered the provenance.
        let ip = v4(93, 184, 216, 34);
        let kernel_deadline = deadline_secs(2_000);

        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip,
                deadline: kernel_deadline,
            },
        );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "example.test.",
            vec![ip],
            "pol1/v0",
        ));

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        // Fully substantiated — no fail-closed gaps.
        assert!(report.is_fully_substantiated());
        assert_eq!(report.entries_rebuilt, 1);
        assert_eq!(report.ips_substantiated, 1);

        // The rebuilt entry mirrors the pre-restart admission field-for-field.
        let entry = map
            .lookup(&key("sess-1", "example.test."))
            .expect("rebuilt");
        assert_eq!(entry.admitted_ips, vec![admitted_v4(93, 184, 216, 34)]);
        assert_eq!(entry.admission_type, AdmissionType::Normal);
        assert!(entry.real_targets.is_empty());
        assert_eq!(entry.provenance, prov("pol1/v0"));
        assert_eq!(entry.admitted_at, deadline_secs(1_000));
    }

    // ── Acceptance (a): expires_at == the kernel deadline, NOT recomputed ───────

    #[test]
    fn expires_at_is_adopted_from_the_kernel_deadline_never_recomputed() {
        // The kernel element's deadline is an ARBITRARY instant that no
        // compose_deadline(answer_time, ttl, floor, ceil, grace) could produce from
        // the spool's admitted_at — proving the value is ADOPTED from the kernel,
        // not recomputed. answer-time recomputation would yield admitted_at + clamp
        // + grace; the kernel deadline here is deliberately unrelated.
        let ip = v4(203, 0, 113, 7);
        let kernel_deadline = deadline_secs(123_456); // arbitrary, kernel-authoritative

        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip,
                deadline: kernel_deadline,
            },
        );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "adopt.test.",
            vec![ip],
            "pol1/v0",
        ));

        let (map, _report) = Reconstructor::new().rebuild(&kernel, &spool);
        let entry = map.lookup(&key("sess-1", "adopt.test.")).expect("rebuilt");
        // expires_at is EXACTLY the kernel element deadline — adopted verbatim.
        assert_eq!(entry.expires_at, kernel_deadline);
    }

    #[test]
    fn multi_ip_name_adopts_the_latest_kernel_deadline_never_shortened() {
        // A two-IP name whose kernel elements carry DIFFERENT deadlines: the
        // entry's single shared deadline is the LATEST (max), never shortened —
        // mirroring the W2 max() refresh rule. The kernel remains authoritative;
        // no timer is recomputed.
        let ip_a = v4(93, 184, 216, 34);
        let ip_b = v4(93, 184, 216, 35);
        let earlier = deadline_secs(2_000);
        let later = deadline_secs(5_000);

        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: ip_a,
                    deadline: earlier,
                },
            )
            .with_element(
                "sess-1",
                KernelElement {
                    ip: ip_b,
                    deadline: later,
                },
            );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "multi.test.",
            vec![ip_a, ip_b],
            "pol1/v0",
        ));

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);
        assert_eq!(report.ips_substantiated, 2);
        // Two distinct kernel elements (two IPs) back the one name: per-name and
        // distinct counts coincide here (each IP backs exactly one name).
        assert_eq!(report.distinct_ips_substantiated, 2);
        assert!(report.reconciles_with(&kernel));
        let entry = map.lookup(&key("sess-1", "multi.test.")).expect("rebuilt");
        // The shared deadline is the LATER of the two kernel element deadlines.
        assert_eq!(entry.expires_at, later);
        assert_eq!(entry.admitted_ips.len(), 2);
    }

    // ── Acceptance (b): a shared IP across multiple fqdns ends at refcount N ─────

    #[test]
    fn shared_cdn_ip_across_multiple_fqdns_ends_at_correct_refcount() {
        // One CDN IP backs three admitted fqdns in the same session. After the
        // rebuild the per-session (session, ip) reverse-index refcount is exactly 3
        // — so a later sibling-name revocation never severs a still-admitted name
        // (the bias-to-under-delete property, invariant (b)).
        let cdn_ip = v4(151, 101, 1, 1);
        let kernel_deadline = deadline_secs(3_000);

        // The kernel holds ONE element for the shared IP (it is one allow-set
        // entry); the spool recovers THREE names that all admitted it.
        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip: cdn_ip,
                deadline: kernel_deadline,
            },
        );
        let spool = SpoolReplayCorpus::new()
            .with_record(normal_record(
                "sess-1",
                "a.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ))
            .with_record(normal_record(
                "sess-1",
                "b.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ))
            .with_record(normal_record(
                "sess-1",
                "c.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ));

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        // Three distinct entries, each referencing the shared IP.
        assert_eq!(report.entries_rebuilt, 3);
        // The two substantiated metrics diverge for a shared IP: per-name reference
        // count is 3 (one per name), distinct `(session, ip)` element count is 1.
        assert_eq!(report.ips_substantiated, 3);
        assert_eq!(report.distinct_ips_substantiated, 1);
        assert!(map.lookup(&key("sess-1", "a.cdn.test.")).is_some());
        assert!(map.lookup(&key("sess-1", "b.cdn.test.")).is_some());
        assert!(map.lookup(&key("sess-1", "c.cdn.test.")).is_some());

        // The reverse index — populated from day one through the frozen API — counts
        // the shared IP at refcount 3 (distinct-name membership).
        let count = map
            .reverse_index()
            .refcount("sess-1", &admitted_v4(151, 101, 1, 1));
        assert_eq!(
            count, 3,
            "a shared-CDN IP backing 3 fqdns ends at refcount 3"
        );
    }

    #[test]
    fn sole_reference_ip_ends_at_refcount_one() {
        let ip = v4(93, 184, 216, 34);
        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip,
                deadline: deadline_secs(2_000),
            },
        );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "sole.test.",
            vec![ip],
            "pol1/v0",
        ));
        let (map, _report) = Reconstructor::new().rebuild(&kernel, &spool);
        assert_eq!(
            map.reverse_index()
                .refcount("sess-1", &admitted_v4(93, 184, 216, 34)),
            1
        );
    }

    // ── Caller-independent distinct-IP: a DUPLICATE kernel element collapses ─────

    #[test]
    fn duplicate_kernel_element_for_one_name_collapses_to_one_membership_refcount_one() {
        // The distinct-IP discipline `txn::admit` enforces for the live forward path
        // (`admit_dedups_duplicate_input_ip_to_one_element_and_one_membership`) must
        // hold for the warm-restart REBUILD too — the IPs here originate OUTSIDE
        // handler.rs (a kernel set dump), so they are NOT pre-canonicalized by the
        // handler. A corrupt/malformed dump that repeats the SAME `(session, ip)`
        // element twice for one name must NOT fan out 1:1 into two memberships: the
        // rebuilt entry holds the IP ONCE and the `(session, ip)` reverse-index
        // refcount is 1, so a later sibling-name revocation frees it EXACTLY once
        // (the bias-to-under-delete property, invariant (b)). `NameRebuild::add_ip`'s
        // `contains` dedup is what makes this caller-independent; this test pins it so
        // the property cannot silently regress.
        let dup_ip = v4(93, 184, 216, 34);
        let kernel_deadline = deadline_secs(2_000);

        // The kernel dump repeats the SAME element twice for the session (a duplicated
        // kernel-resident IP — a malformed/replayed dump, the rebuild's analogue of a
        // duplicate-stuffed resolver answer on the live path).
        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: dup_ip,
                    deadline: kernel_deadline,
                },
            )
            .with_element(
                "sess-1",
                KernelElement {
                    ip: dup_ip,
                    deadline: kernel_deadline,
                },
            );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "dup.test.",
            vec![dup_ip],
            "pol1/v0",
        ));

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        // ONE name was rebuilt (the duplicate element did not mint a second entry).
        assert_eq!(report.entries_rebuilt, 1);

        // The rebuilt entry's admitted_ips collapsed to the DISTINCT count (1), not the
        // raw duplicated-element count (2) — distinct-IP regardless of dump shape.
        let entry = map.lookup(&key("sess-1", "dup.test.")).expect("rebuilt");
        assert_eq!(
            entry.admitted_ips.len(),
            1,
            "a duplicated kernel element collapses to one distinct admitted IP"
        );
        assert_eq!(entry.admitted_ips, vec![admitted_v4(93, 184, 216, 34)]);

        // The `(session, ip)` reverse-index refcount is 1, not 2 — the membership is
        // distinct-IP, so a later revoke frees it EXACTLY once (invariant (b),
        // bias-to-under-delete). This is the load-bearing distinctness property.
        assert_eq!(
            map.reverse_index()
                .refcount("sess-1", &admitted_v4(93, 184, 216, 34)),
            1,
            "a duplicated kernel element increfs the distinct IP exactly once"
        );
    }

    // ── Acceptance (c): missing provenance => OMITTED (fail-closed), not built ──

    #[test]
    fn kernel_ip_with_no_spool_record_is_omitted_fail_closed_not_fabricated() {
        // The kernel holds an IP the spool replay never recovered provenance for.
        // The reconstructor OMITS it (no map entry) and records the gap — TLS-1
        // re-admits it live. It NEVER fabricates a vouching entry.
        let ip = v4(198, 51, 100, 9);
        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip,
                deadline: deadline_secs(2_000),
            },
        );
        // Empty spool: wholly-lossy provenance for this IP.
        let spool = SpoolReplayCorpus::new();

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        // No entry was fabricated.
        assert_eq!(report.entries_rebuilt, 0);
        assert_eq!(report.ips_substantiated, 0);
        // The gap is recorded, fail-closed.
        assert!(!report.is_fully_substantiated());
        assert_eq!(report.provenance_gaps.len(), 1);
        let gap = &report.provenance_gaps[0];
        assert_eq!(gap.session_uuid, "sess-1");
        assert_eq!(gap.ip, ip);
        assert_eq!(gap.reason, GapReason::NoVouchingRecord);
        // No map entry exists for any name covering the IP — nothing was minted.
        assert_eq!(
            map.reverse_index()
                .refcount("sess-1", &admitted_v4(198, 51, 100, 9)),
            0
        );
    }

    #[test]
    fn record_with_incomplete_provenance_is_omitted_not_admitted_under_blank_provenance() {
        // A spool record mentions the kernel IP but lost its POL-3 provenance (a
        // blank policy_version). The reconstructor refuses to admit under fabricated
        // provenance (doc 11 §6.7) — the IP is omitted, fail-closed.
        let ip = v4(93, 184, 216, 34);
        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip,
                deadline: deadline_secs(2_000),
            },
        );
        let mut bad = normal_record("sess-1", "blankprov.test.", vec![ip], "pol1/v0");
        bad.provenance.policy_version = String::new(); // lost in the spool
        let spool = SpoolReplayCorpus::new().with_record(bad);

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        assert_eq!(report.entries_rebuilt, 0);
        assert_eq!(report.provenance_gaps.len(), 1);
        assert_eq!(
            report.provenance_gaps[0].reason,
            GapReason::IncompleteProvenance
        );
        assert!(map.lookup(&key("sess-1", "blankprov.test.")).is_none());
    }

    #[test]
    fn partial_spool_substantiates_recovered_ips_and_omits_the_rest() {
        // A mixed case: of two kernel IPs for a session, the spool recovered
        // provenance for ONE name/IP and lost the other. The rebuild substantiates
        // the recovered entry and fail-closed-omits the lost IP — the in-the-small
        // herd-acceptance fallback (only the unsubstantiated IP degrades).
        let good_ip = v4(93, 184, 216, 34);
        let lost_ip = v4(198, 51, 100, 9);

        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: good_ip,
                    deadline: deadline_secs(2_000),
                },
            )
            .with_element(
                "sess-1",
                KernelElement {
                    ip: lost_ip,
                    deadline: deadline_secs(2_500),
                },
            );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "recovered.test.",
            vec![good_ip],
            "pol1/v0",
        ));

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        // One entry rebuilt (the recovered name), one IP substantiated.
        assert_eq!(report.entries_rebuilt, 1);
        assert_eq!(report.ips_substantiated, 1);
        let entry = map
            .lookup(&key("sess-1", "recovered.test."))
            .expect("rebuilt");
        assert_eq!(entry.admitted_ips, vec![admitted_v4(93, 184, 216, 34)]);
        // The lost IP is a fail-closed gap, not fabricated.
        assert_eq!(report.provenance_gaps.len(), 1);
        assert_eq!(report.provenance_gaps[0].ip, lost_ip);
        assert_eq!(
            report.provenance_gaps[0].reason,
            GapReason::NoVouchingRecord
        );
    }

    #[test]
    fn wholly_lossy_spool_degrades_cleanly_to_herd_acceptance_no_fabrication() {
        // The wholly-lossy spool (doc 11 §8.4 herd-acceptance fallback trigger):
        // the rebuild omits EVERY kernel-resident IP and writes an EMPTY map — no
        // fabricated entries. This is exactly the herd-acceptance posture, reached
        // safely (the rebuild is strictly safer than, and continuous with, the
        // fallback).
        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: v4(93, 184, 216, 34),
                    deadline: deadline_secs(2_000),
                },
            )
            .with_element(
                "sess-2",
                KernelElement {
                    ip: v4(198, 51, 100, 9),
                    deadline: deadline_secs(2_500),
                },
            );
        let spool = SpoolReplayCorpus::new(); // empty — wholly lossy

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        assert_eq!(report.entries_rebuilt, 0);
        assert_eq!(report.ips_substantiated, 0);
        assert_eq!(report.provenance_gaps.len(), 2);
        assert!(map.lookup(&key("sess-1", "any.test.")).is_none());
    }

    // ── A synthetic-admission entry survives the rebuild with its real_targets ──

    #[test]
    fn synthetic_admission_rebuild_carries_real_targets() {
        // A phase-B synthetic-A admission: the kernel holds the synthetic v4 in
        // allow4; the spool recovered the real v6 targets. The rebuilt entry keeps
        // admission_type = Synthetic and the real_targets, so ds-tlsproxy's
        // synthetic-dial keying survives the restart.
        let synthetic_v4 = v4(198, 18, 0, 5); // RFC 2544 synthetic-A pool
        let real_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip: synthetic_v4,
                deadline: deadline_secs(2_000),
            },
        );
        let spool = SpoolReplayCorpus::new().with_record(SpoolRecord {
            session_uuid: "sess-1".into(),
            original_query_fqdn: "v6only.test.".into(),
            admitted_ips: vec![synthetic_v4],
            admission_type: AdmissionType::Synthetic,
            real_targets: vec![real_v6],
            provenance: prov("pol1/v0"),
            admitted_at: deadline_secs(1_000),
        });

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);
        assert_eq!(report.entries_rebuilt, 1);
        let entry = map.lookup(&key("sess-1", "v6only.test.")).expect("rebuilt");
        assert_eq!(entry.admission_type, AdmissionType::Synthetic);
        assert_eq!(entry.real_targets.len(), 1);
        assert_eq!(entry.real_targets[0].family, AddressFamily::V6);
    }

    // ── Invariant (c) edge: a corrupt kernel dump with an unplumbable IP ────────

    #[test]
    fn unplumbable_kernel_ip_is_refused_fail_closed() {
        // A corrupt dump that holds a private (W5-scrubbed) IP: even with a spool
        // record vouching for it, the reconstructor refuses to re-admit it (the
        // live admit path's W5 discipline), recording an UnplumbableAddress gap.
        let martian = v4(10, 0, 0, 5); // RFC1918 — never plumbable
        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip: martian,
                deadline: deadline_secs(2_000),
            },
        );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "martian.test.",
            vec![martian],
            "pol1/v0",
        ));

        let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);
        assert_eq!(report.entries_rebuilt, 0);
        assert_eq!(report.provenance_gaps.len(), 1);
        assert_eq!(
            report.provenance_gaps[0].reason,
            GapReason::UnplumbableAddress
        );
        assert!(map.lookup(&key("sess-1", "martian.test.")).is_none());
    }

    // ── The element-count reconciliation: substantiated + gaps == dump total ────

    #[test]
    fn report_reconciles_against_the_kernel_dump_element_count() {
        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: v4(93, 184, 216, 34),
                    deadline: deadline_secs(2_000),
                },
            )
            .with_element(
                "sess-1",
                KernelElement {
                    ip: v4(198, 51, 100, 9),
                    deadline: deadline_secs(2_000),
                },
            );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "one.test.",
            vec![v4(93, 184, 216, 34)],
            "pol1/v0",
        ));

        let (_map, report) = Reconstructor::new().rebuild(&kernel, &spool);
        // Every kernel element is accounted for: distinct substantiated elements +
        // gaps == total. This is the metric that reconciles in ALL cases.
        assert_eq!(
            report.distinct_ips_substantiated + report.provenance_gaps.len(),
            kernel.element_count()
        );
        assert!(report.reconciles_with(&kernel));
        assert_eq!(kernel.element_count(), 2);
        // In this degenerate 1-name-per-element case the per-name reference count
        // happens to coincide with the distinct count (one name substantiated, one
        // IP omitted).
        assert_eq!(report.distinct_ips_substantiated, 1);
        assert_eq!(report.ips_substantiated, 1);
        assert_eq!(report.provenance_gaps.len(), 1);
    }

    // ── The shared-IP reconciliation: distinct count reconciles, per-name doesn't ─

    #[test]
    fn distinct_count_reconciles_against_element_count_for_shared_ips() {
        // The case the per-name `ips_substantiated` metric CANNOT reconcile: ONE
        // kernel element (a shared-CDN IP) backs THREE names. The kernel dump holds
        // exactly one element for the IP, so `element_count() == 1`. After the
        // rebuild:
        //  - the per-name reference count is 3 (refcount-N semantics, invariant (b)),
        //  - the distinct `(session, ip)` element count is 1 (one kernel element),
        //  - there are no gaps,
        // so ONLY the distinct count reconciles against the kernel element_count.
        let cdn_ip = v4(151, 101, 1, 1);
        let kernel_deadline = deadline_secs(3_000);

        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip: cdn_ip,
                deadline: kernel_deadline,
            },
        );
        let spool = SpoolReplayCorpus::new()
            .with_record(normal_record(
                "sess-1",
                "a.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ))
            .with_record(normal_record(
                "sess-1",
                "b.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ))
            .with_record(normal_record(
                "sess-1",
                "c.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ));

        let (_map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        // The kernel holds ONE element for the shared IP.
        assert_eq!(kernel.element_count(), 1);
        // Three distinct entries reference it.
        assert_eq!(report.entries_rebuilt, 3);
        // Per-name reference count is 3 — the refcount-N diagnostic (invariant (b)).
        assert_eq!(report.ips_substantiated, 3);
        // Distinct `(session, ip)` element count is 1 — one kernel element.
        assert_eq!(report.distinct_ips_substantiated, 1);
        assert!(report.provenance_gaps.is_empty());

        // ONLY the distinct metric reconciles against the kernel element_count.
        assert!(report.reconciles_with(&kernel));
        assert_eq!(
            report.distinct_ips_substantiated + report.provenance_gaps.len(),
            kernel.element_count()
        );
        // The per-name reference count over-counts here (3 != 1) — proving why the
        // distinct metric is the one the §5.5 telemetry join must use.
        assert_ne!(
            report.ips_substantiated + report.provenance_gaps.len(),
            kernel.element_count()
        );
    }

    #[test]
    fn distinct_count_reconciles_with_shared_ips_and_gaps_mixed() {
        // The general case: a shared IP backing two names PLUS an unsubstantiated
        // kernel element. distinct_ips_substantiated (1) + gaps (1) == element_count
        // (2), even though the per-name reference count is 2.
        let cdn_ip = v4(151, 101, 1, 1);
        let lost_ip = v4(198, 51, 100, 9);

        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: cdn_ip,
                    deadline: deadline_secs(3_000),
                },
            )
            .with_element(
                "sess-1",
                KernelElement {
                    ip: lost_ip,
                    deadline: deadline_secs(3_500),
                },
            );
        let spool = SpoolReplayCorpus::new()
            .with_record(normal_record(
                "sess-1",
                "a.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ))
            .with_record(normal_record(
                "sess-1",
                "b.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ));

        let (_map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        assert_eq!(kernel.element_count(), 2);
        // two names
        assert_eq!(report.entries_rebuilt, 2);
        // per-name references for the shared IP
        assert_eq!(report.ips_substantiated, 2);
        // one distinct kernel element
        assert_eq!(report.distinct_ips_substantiated, 1);
        // the lost IP
        assert_eq!(report.provenance_gaps.len(), 1);
        // distinct (1) + gaps (1) == element_count (2). Exact reconciliation.
        assert!(report.reconciles_with(&kernel));
    }

    #[test]
    fn distinct_count_reconciles_across_multiple_sessions() {
        // Two sessions, each with a shared IP backing two names, no gaps:
        // element_count == 2 (one element per session), distinct == 2, per-name == 4.
        let ip_1 = v4(151, 101, 1, 1);
        let ip_2 = v4(151, 101, 2, 2);
        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: ip_1,
                    deadline: deadline_secs(3_000),
                },
            )
            .with_element(
                "sess-2",
                KernelElement {
                    ip: ip_2,
                    deadline: deadline_secs(3_000),
                },
            );
        let spool = SpoolReplayCorpus::new()
            .with_record(normal_record("sess-1", "a1.test.", vec![ip_1], "pol1/v0"))
            .with_record(normal_record("sess-1", "b1.test.", vec![ip_1], "pol1/v0"))
            .with_record(normal_record("sess-2", "a2.test.", vec![ip_2], "pol1/v0"))
            .with_record(normal_record("sess-2", "b2.test.", vec![ip_2], "pol1/v0"));

        let (_map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        assert_eq!(kernel.element_count(), 2);
        assert_eq!(report.distinct_ips_substantiated, 2);
        assert_eq!(report.ips_substantiated, 4);
        assert!(report.provenance_gaps.is_empty());
        assert!(report.reconciles_with(&kernel));
    }

    #[test]
    fn wholly_lossy_spool_distinct_count_is_zero_and_reconciles() {
        // The herd-acceptance fallback: nothing substantiated. distinct == 0,
        // gaps == element_count, reconciles trivially.
        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: v4(93, 184, 216, 34),
                    deadline: deadline_secs(2_000),
                },
            )
            .with_element(
                "sess-2",
                KernelElement {
                    ip: v4(198, 51, 100, 9),
                    deadline: deadline_secs(2_500),
                },
            );
        let spool = SpoolReplayCorpus::new(); // empty — wholly lossy

        let (_map, report) = Reconstructor::new().rebuild(&kernel, &spool);

        assert_eq!(report.distinct_ips_substantiated, 0);
        assert_eq!(report.ips_substantiated, 0);
        assert_eq!(report.provenance_gaps.len(), 2);
        assert!(report.reconciles_with(&kernel));
    }

    // ── The trait seams: a custom KernelDumpSource / SpoolReplaySource drives it ─

    #[test]
    fn rebuild_drives_through_the_trait_seams() {
        // Prove the reconstructor consumes the inputs as TRAITS (the production
        // ds-nft / spool seams), not just the concrete fixtures. A tiny custom
        // source pair stands in for the TODO(seam) production bodies.
        struct OneElementKernel;
        impl KernelDumpSource for OneElementKernel {
            fn dump(&self) -> KernelSetDump {
                KernelSetDump::new().with_element(
                    "sess-seam",
                    KernelElement {
                        ip: v4(93, 184, 216, 34),
                        deadline: deadline_secs(2_000),
                    },
                )
            }
        }
        struct OneRecordSpool;
        impl SpoolReplaySource for OneRecordSpool {
            fn replay(&self) -> SpoolReplayCorpus {
                SpoolReplayCorpus::new().with_record(normal_record(
                    "sess-seam",
                    "seam.test.",
                    vec![v4(93, 184, 216, 34)],
                    "pol1/v0",
                ))
            }
        }

        let (map, report) = Reconstructor::new().rebuild(&OneElementKernel, &OneRecordSpool);
        assert_eq!(report.entries_rebuilt, 1);
        assert!(map.lookup(&key("sess-seam", "seam.test.")).is_some());
    }

    // ── W1 invariant (c): a genuinely FALLIBLE admit yields an AdmitFailed gap ──
    //
    // The in-memory body's `admit` is infallible, so the production `rebuild`
    // path's `Err` arm is never taken (its `debug_assert` pins that). But the
    // FROZEN `AdmissionMap::admit` surface IS fallible — a storage-backed map can
    // return `AdmissionError`. This fixture stands in for such a body: its `admit`
    // ALWAYS refuses (the `SetProgrammingFailed` fail-closed verdict, doc 11 §3.1
    // W1 (c)). Driving `rebuild_into` with it proves the W1 (c) discipline survives
    // a real admit failure: the entry is NOT counted rebuilt / substantiated, it
    // becomes a `GapReason::AdmitFailed` provenance gap, and the distinct-element
    // reconciliation still holds EXACTLY (option (a)).

    use crate::txn::InMemoryReverseIndex;
    use ds_contracts::dns_admission::AdmissionError;

    /// A synthetic storage-backed [`AdmissionMap`] whose `admit` ALWAYS fails with
    /// [`AdmissionError::SetProgrammingFailed`] (the fail-closed verdict). Every
    /// other method defers to the in-memory body, so ONLY the admit-refusal is
    /// synthetic. Mirrors the `txn::tests::FailingMap` pattern but refuses every
    /// admit (the rebuild has no in-memory map handed in to pre-seed).
    #[derive(Default)]
    struct FailingAdmissionMap {
        inner: InMemoryAdmissionMap,
    }
    impl AdmissionMap for FailingAdmissionMap {
        type Reverse = InMemoryReverseIndex;
        fn admit(
            &mut self,
            _key: AdmissionKey,
            _entry: AdmissionEntry,
        ) -> Result<(), AdmissionError> {
            Err(AdmissionError::SetProgrammingFailed)
        }
        fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
            self.inner.lookup(key)
        }
        fn revoke(&mut self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
            self.inner.revoke(key)
        }
        fn reverse_index(&self) -> &Self::Reverse {
            self.inner.reverse_index()
        }
    }

    /// The one `(session, fqdn)` name a [`SiblingFailingAdmissionMap`] refuses; every
    /// other name is admitted through the in-memory body. Hardcoded (not a field)
    /// because [`Reconstructor::rebuild_into`] builds the target map with
    /// `M::default()` — it cannot hand a pre-configured refusal in — so the fixture
    /// pins the refused name as a constant its infallible-elsewhere `admit` matches.
    const SIBLING_REFUSED_FQDN: &str = "refused.sibling.test.";

    /// A synthetic storage-backed [`AdmissionMap`] whose `admit` refuses EXACTLY the
    /// one name [`SIBLING_REFUSED_FQDN`] (the `SetProgrammingFailed` fail-closed
    /// verdict) and delegates every OTHER admit to the in-memory body. Unlike
    /// [`FailingAdmissionMap`] (which refuses all), this lets ONE sibling name admit a
    /// shared IP successfully while ANOTHER sibling name for the SAME IP is refused —
    /// the PARTIAL/mixed-sibling case that exercises the option-(a) `admitted_ips`
    /// short-circuit in [`Reconstructor::rebuild_into`]: the refused sibling must NOT
    /// migrate the shared IP off the substantiated tally (it is still plumbed and
    /// reverse-indexed by the sibling that admitted it), so the IP is never withdrawn.
    #[derive(Default)]
    struct SiblingFailingAdmissionMap {
        inner: InMemoryAdmissionMap,
    }
    impl AdmissionMap for SiblingFailingAdmissionMap {
        type Reverse = InMemoryReverseIndex;
        fn admit(
            &mut self,
            key: AdmissionKey,
            entry: AdmissionEntry,
        ) -> Result<(), AdmissionError> {
            if key.original_query_fqdn == SIBLING_REFUSED_FQDN {
                return Err(AdmissionError::SetProgrammingFailed);
            }
            self.inner.admit(key, entry)
        }
        fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
            self.inner.lookup(key)
        }
        fn revoke(&mut self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
            self.inner.revoke(key)
        }
        fn reverse_index(&self) -> &Self::Reverse {
            self.inner.reverse_index()
        }
    }

    #[test]
    fn failing_admit_yields_admit_failed_gap_not_counted_and_reconciles() {
        // One kernel element, fully provenance-substantiated by the spool — on the
        // infallible body this rebuilds cleanly. Against the FAILING map the admit
        // is refused, so W1 (c) must hold: nothing counted rebuilt/substantiated,
        // the IP becomes an `AdmitFailed` gap, and the distinct reconciliation is
        // exact.
        let ip = v4(93, 184, 216, 34);
        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip,
                deadline: deadline_secs(2_000),
            },
        );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "fail.test.",
            vec![ip],
            "pol1/v0",
        ));

        let (map, report) =
            Reconstructor::new().rebuild_into::<_, _, FailingAdmissionMap>(&kernel, &spool);

        // The refused name is NOT counted rebuilt nor substantiated (counters are
        // bumped only on Ok) — a half-written entry is never claimed.
        assert_eq!(report.entries_rebuilt, 0, "a refused admit is not rebuilt");
        assert_eq!(
            report.ips_substantiated, 0,
            "a refused admit substantiates no per-name reference"
        );
        // Option (a): the element migrated from the substantiated tally to a gap,
        // so the distinct count is back to zero.
        assert_eq!(
            report.distinct_ips_substantiated, 0,
            "the refused element is decremented off the substantiated tally (option (a))"
        );
        // The gap is recorded with the AdmitFailed reason — fail-closed, never
        // silently dropped.
        assert!(!report.is_fully_substantiated());
        assert_eq!(report.provenance_gaps.len(), 1);
        let gap = &report.provenance_gaps[0];
        assert_eq!(gap.session_uuid, "sess-1");
        assert_eq!(gap.ip, ip);
        assert_eq!(gap.reason, GapReason::AdmitFailed);
        // The reconciliation invariant STILL holds exactly through the failure:
        // distinct_ips_substantiated (0) + gaps (1) == element_count (1).
        assert!(
            report.reconciles_with(&kernel),
            "distinct + gaps == element_count must survive an admit failure (W1 (c))"
        );
        // No entry exists for the refused name — fail-closed, ds-tlsproxy re-admits
        // it live on the next connection.
        assert!(map.lookup(&key("sess-1", "fail.test.")).is_none());
    }

    #[test]
    fn failing_admit_with_a_gap_and_a_refusal_both_reconcile() {
        // A mixed case proving the AdmitFailed migration composes with an ordinary
        // provenance gap: two kernel elements, one substantiated by the spool (the
        // admit then REFUSES it → AdmitFailed gap) and one the spool never recovered
        // (NoVouchingRecord gap). element_count == 2, distinct == 0, gaps == 2.
        let admit_fail_ip = v4(93, 184, 216, 34);
        let lost_ip = v4(198, 51, 100, 9);
        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: admit_fail_ip,
                    deadline: deadline_secs(2_000),
                },
            )
            .with_element(
                "sess-1",
                KernelElement {
                    ip: lost_ip,
                    deadline: deadline_secs(2_500),
                },
            );
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "fail.test.",
            vec![admit_fail_ip],
            "pol1/v0",
        ));

        let (_map, report) =
            Reconstructor::new().rebuild_into::<_, _, FailingAdmissionMap>(&kernel, &spool);

        assert_eq!(report.entries_rebuilt, 0);
        assert_eq!(report.distinct_ips_substantiated, 0);
        assert_eq!(report.provenance_gaps.len(), 2);
        let reasons: Vec<GapReason> = report.provenance_gaps.iter().map(|g| g.reason).collect();
        assert!(reasons.contains(&GapReason::AdmitFailed));
        assert!(reasons.contains(&GapReason::NoVouchingRecord));
        // distinct (0) + gaps (2) == element_count (2).
        assert!(report.reconciles_with(&kernel));
    }

    #[test]
    fn failing_admit_under_a_duplicate_element_dump_decrements_per_element_and_reconciles() {
        // The per-ELEMENT decrement regression: a corrupt/replayed kernel dump
        // repeats the SAME `(session, ip)` element TWICE for one name (the rebuild's
        // analogue of a duplicate-stuffed resolver answer). `distinct_ips_substantiated`
        // is bumped PER element, so the duplicated IP contributes +2 (element_count
        // also counts it twice). When the admit REFUSES the name (the W1 (c) fail-
        // closed arm), option (a) must migrate BOTH elements off the substantiated
        // tally and record one `AdmitFailed` gap PER element — a per-IP decrement
        // (once per distinct IP) would leave a phantom substantiated count (1 instead
        // of 0) and under-report the gaps (1 instead of 2), breaking the exact
        // `distinct_ips_substantiated + provenance_gaps.len() == element_count()`
        // reconciliation. This test pins the per-element decrement so that regression
        // cannot return silently.
        let dup_ip = v4(93, 184, 216, 34);
        let kernel_deadline = deadline_secs(2_000);

        // The dump repeats the SAME element twice — two kernel allow-set elements for
        // one `(session, ip)`, so element_count == 2.
        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: dup_ip,
                    deadline: kernel_deadline,
                },
            )
            .with_element(
                "sess-1",
                KernelElement {
                    ip: dup_ip,
                    deadline: kernel_deadline,
                },
            );
        assert_eq!(kernel.element_count(), 2);
        // The spool fully substantiates the name (so on the infallible body it would
        // rebuild cleanly); the FAILING map refuses the admit.
        let spool = SpoolReplayCorpus::new().with_record(normal_record(
            "sess-1",
            "dupfail.test.",
            vec![dup_ip],
            "pol1/v0",
        ));

        let (map, report) =
            Reconstructor::new().rebuild_into::<_, _, FailingAdmissionMap>(&kernel, &spool);

        // Nothing rebuilt / no per-name reference substantiated — the admit refused.
        assert_eq!(report.entries_rebuilt, 0);
        assert_eq!(report.ips_substantiated, 0);
        // Option (a), PER ELEMENT: BOTH duplicated elements migrate off the
        // substantiated tally → distinct is back to 0 (a per-IP decrement would
        // leave a phantom 1).
        assert_eq!(
            report.distinct_ips_substantiated, 0,
            "both duplicated kernel elements migrate off the substantiated tally"
        );
        // One `AdmitFailed` gap PER element — TWO gaps for the duplicated element (a
        // per-IP push would record only one).
        assert_eq!(
            report.provenance_gaps.len(),
            2,
            "a duplicate-element refusal records one AdmitFailed gap per element"
        );
        for gap in &report.provenance_gaps {
            assert_eq!(gap.session_uuid, "sess-1");
            assert_eq!(gap.ip, dup_ip);
            assert_eq!(gap.reason, GapReason::AdmitFailed);
        }
        // The headline invariant: distinct (0) + gaps (2) == element_count (2) holds
        // EXACTLY through the failing admit even under the duplicate-element dump.
        assert!(
            report.reconciles_with(&kernel),
            "reconciles_with must stay exact under a duplicate-element dump after a failing admit"
        );
        // Fail-closed: no entry exists for the refused name.
        assert!(map.lookup(&key("sess-1", "dupfail.test.")).is_none());
    }

    // ── W1 (c) mixed-sibling: one sibling admits, one is refused — IP NOT withdrawn ─

    #[test]
    fn mixed_sibling_admit_keeps_the_shared_ip_substantiated_and_never_withdraws_it() {
        // The PARTIAL/mixed-sibling path — the load-bearing option-(a) `admitted_ips`
        // short-circuit in `rebuild_into`. ONE kernel element (a shared-CDN IP, so
        // element_count == 1) is vouched for by TWO sibling names in the same session.
        // Against `SiblingFailingAdmissionMap` the first sibling (`admitted.sibling.test.`)
        // admits OK — holding the IP, plumbed and reverse-indexed — and the second
        // (`refused.sibling.test.`) is REFUSED.
        //
        // The W1 (c) admit-failure arm (option (a)) would, for a refused name, migrate
        // its distinct IPs off the substantiated tally into `AdmitFailed` gaps. Here it
        // MUST NOT: the resolution loop's `admitted_ips.contains(ip)` short-circuit sees
        // the sibling already admitted the IP and SKIPS the migration. So:
        //  - the full kernel element_count stays substantiated (distinct == 1),
        //  - NO `AdmitFailed` gap is pushed (the sibling held the IP),
        //  - the shared IP is NEVER withdrawn / flushed — its `(session, ip)` reverse-index
        //    refcount stays 1 (held by the admitted sibling), the bias-to-under-delete
        //    property (invariant (b)): a refused sibling must not tear down an IP a
        //    successful sibling still holds,
        //  - and `reconciles_with()` holds EXACTLY (distinct 1 + gaps 0 == element_count 1).
        // This pins the documented behavior directly, not by coincidence of a fully-
        // recoverable spool.
        let shared_ip = v4(151, 101, 1, 1);
        let kernel_deadline = deadline_secs(3_000);

        // The kernel holds ONE element for the shared IP (one allow-set element).
        let kernel = KernelSetDump::new().with_element(
            "sess-1",
            KernelElement {
                ip: shared_ip,
                deadline: kernel_deadline,
            },
        );
        // Two sibling names both vouch for the shared IP; the second is the one the
        // partial-failing map refuses.
        let spool = SpoolReplayCorpus::new()
            .with_record(normal_record(
                "sess-1",
                "admitted.sibling.test.",
                vec![shared_ip],
                "pol1/v0",
            ))
            .with_record(normal_record(
                "sess-1",
                SIBLING_REFUSED_FQDN,
                vec![shared_ip],
                "pol1/v0",
            ));

        let (map, report) =
            Reconstructor::new().rebuild_into::<_, _, SiblingFailingAdmissionMap>(&kernel, &spool);

        // Exactly ONE name rebuilt — the admitted sibling; the refused one is left out
        // of the map and out of the success counters (fail-closed on the refused admit).
        assert_eq!(
            report.entries_rebuilt, 1,
            "only the admitted sibling is rebuilt; the refused one is fail-closed omitted"
        );
        // One per-name reference substantiated (the admitted sibling only).
        assert_eq!(report.ips_substantiated, 1);
        // The FULL kernel element_count stays substantiated: the shared IP is NOT
        // migrated off the tally, because the admitted sibling still holds it (the
        // `admitted_ips.contains` short-circuit of option (a)).
        assert_eq!(
            report.distinct_ips_substantiated, 1,
            "the sibling-held shared IP stays substantiated despite the refused sibling"
        );
        // NO AdmitFailed gap: the refused sibling did NOT withdraw the IP (a naive
        // per-IP migration that ignored the surviving sibling would push one here).
        assert!(
            report.provenance_gaps.is_empty(),
            "no AdmitFailed gap — the shared IP is held by the admitted sibling, never withdrawn"
        );
        assert!(report.is_fully_substantiated());

        // reconciles_with() holds EXACTLY: distinct (1) + gaps (0) == element_count (1).
        assert_eq!(kernel.element_count(), 1);
        assert!(
            report.reconciles_with(&kernel),
            "distinct + gaps == element_count must hold through the mixed-sibling refusal"
        );

        // The shared IP is NEVER withdrawn / flushed: its `(session, ip)` reverse-index
        // refcount is 1 (held by the admitted sibling), so a later revoke frees it
        // EXACTLY once — the refused sibling neither tore it down nor double-freed it.
        assert_eq!(
            map.reverse_index()
                .refcount("sess-1", &admitted_v4(151, 101, 1, 1)),
            1,
            "the sibling-held IP survives at refcount 1 — never withdrawn by the refused sibling"
        );
        // The admitted sibling's entry exists; the refused sibling's does not.
        assert!(
            map.lookup(&key("sess-1", "admitted.sibling.test."))
                .is_some(),
            "the admitted sibling's entry is present"
        );
        assert!(
            map.lookup(&key("sess-1", SIBLING_REFUSED_FQDN)).is_none(),
            "the refused sibling's entry is fail-closed absent"
        );
    }

    // ── Completion telemetry: the report projects onto a spool envelope ──────────

    #[test]
    fn completion_event_projects_distinct_count_and_a_true_reconciles_bit() {
        // A shared-CDN IP backs two names (distinct=1, per-name=2) plus a lost IP
        // (one gap). element_count == 2; distinct (1) + gaps (1) == 2 ⇒ reconciles.
        // The completion event carries the DISTINCT count (the kernel-reconciling
        // metric), NOT the per-name reference count, plus the derived reconciles bit.
        let cdn_ip = v4(151, 101, 1, 1);
        let lost_ip = v4(198, 51, 100, 9);
        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: cdn_ip,
                    deadline: deadline_secs(3_000),
                },
            )
            .with_element(
                "sess-1",
                KernelElement {
                    ip: lost_ip,
                    deadline: deadline_secs(3_500),
                },
            );
        let spool = SpoolReplayCorpus::new()
            .with_record(normal_record(
                "sess-1",
                "a.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ))
            .with_record(normal_record(
                "sess-1",
                "b.cdn.test.",
                vec![cdn_ip],
                "pol1/v0",
            ));

        let (_map, report) = Reconstructor::new().rebuild(&kernel, &spool);
        // Per-name reference count is 2 (two names back the shared IP); distinct is 1.
        assert_eq!(report.ips_substantiated, 2);
        assert_eq!(report.distinct_ips_substantiated, 1);
        assert_eq!(report.provenance_gaps.len(), 1);
        assert!(report.reconciles_with(&kernel));

        let provenance = crate::event::EventProvenance {
            rule_id: "demo-allow".to_string(),
            policy_layer: "org".to_string(),
            policy_version: "pol1/v0".to_string(),
        };
        let event = report.completion_event(&kernel, provenance);
        // The completion event carries the DISTINCT element count (the kernel-reconciling
        // metric), the gap count, the entries count, and the derived reconciles bit.
        assert_eq!(event.distinct_ips_substantiated, 1);
        assert_eq!(event.provenance_gaps, 1);
        assert_eq!(event.entries_rebuilt, 2);
        assert!(event.reconciles);

        // It encodes onto the convention-layer spool envelope with the documented scalar.
        let envelope = event.to_envelope().expect("a live POL-3 triple encodes");
        let payload = String::from_utf8_lossy(envelope.payload());
        assert!(payload.contains("distinct_ips_substantiated=1"));
        assert!(payload.contains("reconciles=true"));
    }
}
