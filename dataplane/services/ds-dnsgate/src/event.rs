//! The service-internal LOG-1 `DnsEvent` surface (doc 11 §5.5 / §6 `event/` module).
//!
//! # The convention-layer collapse onto `ds_telemetry::event`
//!
//! This module now COLLAPSES its convention layer onto `ds-telemetry` (doc 14 §6:
//! `ds-telemetry` is the one LOG-1 emitter; doc 11 §5.5: "replace the type and the
//! `EventSink` impl — never the handler emission sites"). The cross-emitter
//! convention carriers are `pub use`d straight from `ds-telemetry` rather than
//! privately re-mirrored here:
//!
//!   * [`EventEnvelope`] / [`TelemetryEventSink`] — the convention-layer construction
//!     carrier and one-method emission seam (`ds_telemetry::event`). The production
//!     [`ds_telemetry::SpoolSink`] is the real [`TelemetryEventSink`] impl, so the
//!     gate's events now land in the genuine disk-bounded, visible-loss spool (D116).
//!   * [`Provenance`] — the mandatory POL-3 triple (`ds_telemetry::provenance`); the
//!     checked, never-blank constructor that makes "missing provenance fails CI" a
//!     construction-time property lives there, once.
//!
//! # What stays SERVICE-INTERNAL: the LOG-1 `DnsEvent` SCHEMA (doc 14 §12.4)
//!
//! `ds-telemetry` owns CONVENTIONS, never the LOG-1 SCHEMA — the `DnsEvent` FIELD set
//! (`aaaa_only` / `aaaa_stripped` / family-agnostic addresses / POL-3 provenance) is
//! frozen into `ds-contracts` from the one-shot Stage-0 proto freeze (a separate,
//! later seam). So the rich [`DnsEvent`] schema type, its [`EventProvenance`] /
//! [`AaaaOnly`] / [`DeferralReason`] / [`EventPath`] signals, and the [`EventSink`]
//! trait that records them stay here, service-internal — exactly the StubVerdict /
//! StubQuery pattern (`crate::policy`). The collapse wires the PRODUCTION path:
//! [`DnsEvent::to_envelope`] encodes the rich event into a convention-layer
//! [`EventEnvelope`], and [`TelemetrySink`] adapts any [`TelemetryEventSink`] (the
//! [`ds_telemetry::SpoolSink`]) into this module's [`EventSink`] — so the real spool
//! is the gate's sink with the handler emission sites UNCHANGED in shape.
//!
//! HARD CONTRACT (mirrors D67 for the policy seam): no `hickory_*` type and no
//! `ds-contracts` type appears in any item below. The handler (`crate::handler`) is
//! the only place that bridges hickory wire types into these plain `std`/`String`
//! signals before handing the event to the sink.
//!
//! # The two D75 signals (doc 11 §3.3 / §5.5)
//!
//! * [`DnsEvent::aaaa_stripped`] — a soft, expected-high-volume counter: how many
//!   AAAA records this query path removed before the answer reached the VM (the §3.3
//!   AAAA scrub on EITHER the fast-NODATA path or the forwarded-answer path). A
//!   non-zero count is the "we stripped v6 here" signal; it is intentionally a count,
//!   not a bool, so the high-volume aggregate stays joinable.
//! * [`DnsEvent::aaaa_only`] — the D75 TRIGGER metric: a needed domain that v4 can't
//!   reach (upstream had AAAA but **zero A** after the CNAME chase). T-C3's dogfood
//!   standing query joins on this flag, so its computation point is load-bearing —
//!   see the [`AaaaOnly`] doc for the parallel-A-probe-vs-recorded-deferral decision.

use std::sync::{Arc, Mutex};

// The convention-layer carriers, sourced from the one LOG-1 emitter (`ds-telemetry`,
// doc 14 §6) — the collapse `pub use`s them here in place of a private re-mirror.
// `EventSink` is RENAMED on import (`TelemetryEventSink`) because this module's own
// `EventSink` (below) is the rich-`DnsEvent`-taking service trait the handler emits to
// and the in-process tests capture from; the two coexist, bridged by [`TelemetrySink`].
pub use ds_telemetry::event::{EventEnvelope, EventKind, EventSink as TelemetryEventSink};
pub use ds_telemetry::provenance::Provenance;

/// POL-3 provenance (doc 11 §5.5: rule id, layer, policy version on **every** event —
/// missing provenance fails CI, §6.7). A SERVICE-INTERNAL mirror of the eventual
/// `ds-contracts::Provenance` field shape (`rule_id` / `policy_layer` /
/// `policy_version`); it is NOT that type and does not import it (the LOG-1 freeze is
/// the separate seam). Plain `String`s only — never a hickory or proto type.
///
/// The handler stamps every event with the LIVE verdict's POL-3 triple — the matched
/// rule id, the composing layer, and the policy version the
/// [`crate::policy::PolicyHook`] returned (doc 11 §5.5 LOG-1; D67 seam). The field is
/// present on every event from day one so the "provenance on every path" invariant
/// (§6.7) is structurally satisfied for every emission site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventProvenance {
    /// The rule id that produced the verdict (POL-3).
    pub rule_id: String,
    /// The policy layer the rule came from (POL-3).
    pub policy_layer: String,
    /// The policy version under which the verdict was minted (POL-3).
    pub policy_version: String,
}

impl EventProvenance {
    /// Bridge this service-internal triple into the convention-layer
    /// [`Provenance`] (`ds_telemetry::provenance`) the [`EventEnvelope`] requires.
    ///
    /// The handler stamps every event with the LIVE verdict's POL-3 triple, so all
    /// three fields are non-empty by construction (doc 11 §6.7) and the checked
    /// [`Provenance::new`] accepts them. In the (handler-unreachable) event that a
    /// field is somehow blank, this returns the [`ProvenanceError`] rather than
    /// fabricating a blank-provenance envelope — "missing provenance fails CI" stays a
    /// hard error, never a silent pass.
    pub fn to_provenance(&self) -> Result<Provenance, ProvenanceError> {
        Provenance::new(
            self.rule_id.clone(),
            self.policy_layer.clone(),
            self.policy_version.clone(),
        )
    }
}

/// Re-export the convention-layer provenance error (`ds_telemetry::provenance`) so a
/// caller of [`EventProvenance::to_provenance`] / [`DnsEvent::to_envelope`] handles the
/// "missing provenance fails CI" face without reaching across crates.
pub use ds_telemetry::provenance::ProvenanceError;

/// Why an `aaaa_only` determination was deferred rather than computed — recorded so a
/// consumer never confuses "we couldn't tell" with a genuine `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferralReason {
    /// The §3.3 fast-NODATA AAAA path: by contract it never forwards AAAA upstream, so
    /// it holds no A-count to compare. Computing the trigger here would require a
    /// parallel A-probe (rejected — see [`AaaaOnly`]).
    FastNodataNoForward,
    /// The forwarded A-lookup returned NoData AND the bounded explicit AAAA probe did
    /// not settle the trigger. MEASURED (hickory-resolver 0.26.x): a type-filtered
    /// `lookup(name, A)` over a v6-only origin (CNAME→AAAA-only or AAAA-only-under-qname)
    /// returns NoData and does **not** surface the AAAA RRs — so the gate cannot see
    /// "upstream had AAAA but zero A" from the A-lookup alone. The bounded explicit AAAA
    /// probe (doc 11 §3.5, riding the single upstream forwarder) settles the genuine
    /// pure-v6-only case to [`AaaaOnly::Determined`]`(true)`; this deferral remains only
    /// when the probe could not settle it — the probe budget was exhausted (the §1
    /// single-resolver/DoS-chokepoint bound), or the AAAA leg itself failed/NoData/
    /// NXDOMAIN (so neither A nor AAAA was observed, and the trigger is genuinely
    /// unknown rather than `false`).
    ForwardedNoDataV6Invisible,
    /// An ERROR path that carries NO answer set at all — neither a forwarded NoData nor a
    /// scrubbed answer: the FORMERR path (a malformed / query-less request) and the
    /// request-info-less SERVFAIL path (no query info to forward). These never forwarded
    /// and hold nothing to settle `aaaa_only` from, so the determination is deferred — but
    /// they are NOT a forwarded NoData, so labelling them
    /// [`DeferralReason::ForwardedNoDataV6Invisible`] would mislead a consumer reading only
    /// the reason. The `EventPath` tag already disambiguates and a deferral never triggers
    /// T-C3, so this is label PRECISION, not a behavior change: genuine forwarded-NoData
    /// emissions keep `ForwardedNoDataV6Invisible`; these error paths use this variant.
    ErrorPathNoAnswerSet,
}

/// The `aaaa_only` trigger metric (doc 11 §3.3 / §5.5, D75) and — crucially — *how it
/// was computed*, so a consumer can tell a genuine determination from a deferral.
///
/// # DESIGN DECISION (recorded, justified against D75): a BOUNDED explicit AAAA probe
/// # on the single forwarder — never an unbounded parallel fan-out.
///
/// `aaaa_only` means "upstream had AAAA but **zero A** after the CNAME chase" — a
/// needed domain v4 can't reach. Two facts shape the computation:
///
/// 1. **The fast-NODATA AAAA path never forwards** (§3.3 freeze;
///    `suppression_shapes.rs::aaaa_nodata_does_not_wait_on_upstream` asserts no
///    upstream round-trip). It holds no A-count and never probes — that freeze is
///    forward-free, so this path stays [`AaaaOnly::Deferred`]`(FastNodataNoForward)`.
///
/// 2. **MEASURED (hickory-resolver 0.26.x, the vendored engine):** a type-filtered
///    `lookup(name, A)` over a genuinely v6-only origin returns **NoData and does not
///    surface the AAAA RRs** — verified in-tree. So the forwarded A-path alone cannot
///    observe "AAAA but zero A" for a pure v6-only origin.
///
/// The settlement is the doc 11 §3.5 phase-B pre-step: a **bounded explicit AAAA
/// probe** on the *existing single upstream forwarder* (doc 11 §1 — ds-dnsgate is the
/// fleet single resolver / DoS chokepoint, so there is NO second resolver and NO
/// per-query fan-out). It fires ONLY on the forwarded NoData arm (a policy-allowed name
/// — Deny/Ask never forward), and ONLY while a small in-flight budget admits it; the
/// budget bounds resolver load so a flood of v6-only NoData names cannot multiply
/// upstream traffic. The genuine deferral remains where the probe cannot settle the
/// answer (budget exhausted, or the AAAA leg itself failed/NoData). The arms:
///   * `Determined(false)` — at least one A survived (v4 can reach the name).
///   * `Determined(true)` — either the held answer set carried AAAA and **no A** survived
///     the scrub (the bundled-AAAA-without-A shape), OR the A-lookup was NoData and the
///     bounded AAAA probe found AAAA RRs (the genuine pure-v6-only origin).
///   * `Deferred(reason)` — the trigger is real but uncomputable on this path
///     ([`DeferralReason`]): the forward-free fast-NODATA path, an error path with no
///     answer set, or a forwarded NoData the bounded probe could not settle.
///
/// T-C3's dogfood standing query joins on [`AaaaOnly::is_trigger`] (a `Determined(true)`
/// row), and treats `Deferred` rows as "unknown" — never as `false`, never as a trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AaaaOnly {
    /// The gate held the answer set and settled v4-reachability: `true` == AAAA present
    /// but zero A survived (the D75 trigger); `false` == at least one A survived.
    Determined(bool),
    /// The trigger could not be computed without a probe this pre-stage won't fire (the
    /// recorded-deferral decision); the genuine v6-only determination is phase-B work.
    Deferred(DeferralReason),
}

impl AaaaOnly {
    /// Whether this is a genuine, determined `aaaa_only == true` trigger (the D75
    /// metric T-C3 joins on). A deferral is never a trigger.
    pub fn is_trigger(&self) -> bool {
        matches!(self, AaaaOnly::Determined(true))
    }

    /// Whether the determination was deferred (uncomputable without a probe).
    pub fn is_deferred(&self) -> bool {
        matches!(self, AaaaOnly::Deferred(_))
    }
}

/// Which query path emitted the event — the §6.7 "every path" coverage made explicit
/// so a test can assert an event was emitted on each, and so a consumer can tell a
/// scrub-NODATA from a forwarded answer from a genuine failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventPath {
    /// A §3.3 fast NODATA for an AAAA / HTTPS(65) / SVCB(64) query (no upstream
    /// forward; the D71 authored SOA rode the authority section).
    FastNodata,
    /// A forwarded answer authored back to the VM after the §3.3 scrub.
    ForwardedAnswer,
    /// The upstream resolved with no records (NOERROR/NODATA empty), or NXDOMAIN
    /// folded to no-data at this pre-stage.
    NoData,
    /// A genuine upstream failure or timeout authored as SERVFAIL (doc 11 §8.5).
    ServFail,
    /// A malformed / query-less request authored as FORMERR.
    FormErr,
    /// A policy DENY (doc 11 §4 `Deny{rcode_policy}`) authored as the §3.2 hard-deny
    /// shape (NXDOMAIN + authored signature SOA, D71). Distinct from a §3.3 scrub
    /// NODATA: this is a policy decision, not record suppression.
    Denied,
    /// A policy ASK (doc 11 §4 `Ask{prompt_ref}`) in an ATTENDED session: authored as
    /// REFUSED (doc 11 §3.2) AND an `AskUserRequest` raised to the human over the Stage-0
    /// ask-user seam out of band (D18/D77). The post-approval retry resolves once the
    /// session-scoped grant lands on the policy stream; the VM is never suspended.
    Asked,
    /// A policy ASK in an UNATTENDED session: DOWNGRADED to immediate block+log (D53 as
    /// revised by D77). Authored as REFUSED on the wire (the §3.2 ask-posture shape — never
    /// a cacheable signal), but NO `AskUserRequest` raised (no human to interrupt). Distinct
    /// from [`EventPath::Asked`] so a LOG-1 join tells an attended ask from an unattended
    /// downgrade. The VM is never suspended (D77: suspension is for genuine threats only).
    AskDowngradedBlock,
}

/// The service-internal LOG-1 `DnsEvent` (doc 11 §5.5). A deliberately-narrower,
/// hickory-free, `ds-contracts`-free mirror of the eventual frozen LOG-1 event: it
/// carries the query identity, the two D75 signals, the path, and POL-3 provenance —
/// enough for the §6.7 "every query emits a DnsEvent with provenance" obligation to be
/// satisfied and tested at the pre-stage, ahead of the Stage-0 schema freeze.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEvent {
    /// The queried name, lower-cased trailing-dot form (mirrors `StubQuery::qname`).
    pub qname: String,
    /// The queried record type as its IANA numeric code (1 = A, 28 = AAAA, ...),
    /// a `u16` never a hickory `RecordType` (engine-agnostic, like `StubQuery::qtype`).
    pub qtype: u16,
    /// Which query path this event was emitted on (§6.7 "every path" coverage).
    pub path: EventPath,
    /// `aaaa_stripped` (doc 11 §5.5, D75): how many AAAA RRs this path removed before
    /// the answer reached the VM. A soft, expected-high-volume signal; a count, not a
    /// bool, so the aggregate stays joinable. Zero on paths that stripped nothing.
    pub aaaa_stripped: u32,
    /// `aaaa_only` (doc 11 §5.5, D75): the v6 trigger metric and how it was computed
    /// (see [`AaaaOnly`] for the recorded-deferral design decision).
    pub aaaa_only: AaaaOnly,
    /// `aimed_resolver` (doc 11 §5.5 / doc 14 §2, D69): the ORIGINAL destination
    /// (addr:port) of the redirected udp/53 query — the resolver the VM aimed at before
    /// the NFT-2 redirect landed it on the gate. Frozen at the Stage-0 LOG-1 freeze as a
    /// **reserved optional field** (doc 14 §2 `aimed_resolver` row), so the gate carries
    /// it as an `Option<SocketAddr>` and the field is present from day one — what keeps
    /// the NFT-5 foreign-resolver bypass counter joinable to which resolver was aimed at.
    ///
    /// # PENDING OQ3 (recover-vs-zero) — flagged for ratification, NOT a unilateral D-row
    ///
    /// doc 14 §2 / doc 11 §5.5 freeze the field shape but leave ONE thing open: "the
    /// recover-vs-zero population decision (conntrack lookup / `IP_RECVORIGDSTADDR`-class
    /// vs always-zero) is the only open part and gets its own decision-log entry". This
    /// pre-stage takes the **CONSERVATIVE default**: `aimed_resolver` is left ALWAYS-`None`
    /// (reserved-optional, unpopulated). The conntrack / `IP_RECVORIGDSTADDR`-class
    /// original-destination recovery that would populate it is owned by the SEPARATE
    /// ConnOrigin task (`01KTWJ6N78`), not this query-path unit — wiring it here would
    /// pre-empt that task and the OQ3 ratification. So the field is RESERVED and READY
    /// (every event carries it, the schema is frozen) but never populated until OQ3 is
    /// decided. This is a PENDING OQ3 decision for the ratification packet, deliberately
    /// NOT logged as a new doc 04 §6 D-row here.
    pub aimed_resolver: Option<std::net::SocketAddr>,
    /// POL-3 provenance — present on EVERY event (doc 11 §6.7, CI-fatal if missing).
    pub provenance: EventProvenance,
}

impl DnsEvent {
    /// Whether this event carries the genuine D75 `aaaa_only` trigger (a determined
    /// `true`, never a deferral). The T-C3 dogfood standing query's join predicate.
    pub fn is_aaaa_only_trigger(&self) -> bool {
        self.aaaa_only.is_trigger()
    }

    /// Encode this rich service-internal `DnsEvent` into the convention-layer
    /// [`EventEnvelope`] (`ds_telemetry::event`) the production spool transports — the
    /// PRODUCTION bridge the collapse wires (doc 11 §5.5: replace the type and the
    /// sink impl, never the emission sites). The envelope's [`EventKind`] is
    /// [`EventKind::DnsEvent`], its mandatory [`Provenance`] is this event's POL-3
    /// triple, and the opaque, already-scrubbed payload carries the schema signals
    /// (`qname` / `qtype` / `path` / `aaaa_stripped` / `aaaa_only`) in the free
    /// pre-freeze rendering below. No `hickory_*` / `ds-contracts` type crosses (the
    /// signals are plain `std`/`String`), so the D67 corollary holds, and no secret
    /// value can appear — a `DnsEvent` carries none (the credential chokepoint is the
    /// `CredentialUseEvent` shape, not this path).
    ///
    /// Returns the [`ProvenanceError`] (never a blank-provenance envelope) if the POL-3
    /// triple is somehow incomplete — unreachable on the handler path, where every
    /// event carries the live verdict's non-empty triple (§6.7).
    pub fn to_envelope(&self) -> Result<EventEnvelope, ProvenanceError> {
        let provenance = self.provenance.to_provenance()?;
        Ok(EventEnvelope::new(
            EventKind::DnsEvent,
            provenance,
            self.render_payload(),
        ))
    }

    /// The free pre-freeze payload rendering: a stable, greppable text encoding of the
    /// `DnsEvent` schema signals (the on-the-wire LOG-1 `DnsEvent` field set is the
    /// later Stage-0 `ds-contracts` freeze, never this). The encoding is opaque to the
    /// spool — it is `payload` bytes — and carries no secret (a `DnsEvent` holds none).
    fn render_payload(&self) -> Vec<u8> {
        // `aimed_resolver` renders as the reserved-optional sentinel `-` when unpopulated
        // (the conservative OQ3 default — always `None` until the ConnOrigin task wires
        // recovery). The field is ALWAYS present in the rendering so a downstream consumer
        // can rely on its position even before population is decided.
        let aimed = self
            .aimed_resolver
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".to_string());
        format!(
            "qname={} qtype={} path={:?} aaaa_stripped={} aaaa_only={:?} aimed_resolver={aimed}",
            self.qname, self.qtype, self.path, self.aaaa_stripped, self.aaaa_only,
        )
        .into_bytes()
    }
}

/// The emission seam: the handler hands every authored [`DnsEvent`] to a sink. One
/// method, no async, no hickory types — mirrors the [`crate::policy::PolicyHook`]
/// discipline so the real `ds-telemetry` spool can replace the impl without touching
/// the handler emission sites (doc 11 §6.7 / §8.6: events spool for the warm-restart
/// replay; the spool durability is the OQ2 seam, not this pre-stage's concern).
///
/// `Send + Sync + 'static` so the sink can live behind the `Arc` the handler shares
/// across the UDP `Server` and the capped TCP accept loop.
pub trait EventSink: Send + Sync + 'static {
    /// Record one authored event. Infallible by construction at the pre-stage: a
    /// dropped telemetry record never fails a query (the wire answer is authoritative;
    /// the §6.7 obligation is to EMIT, and the durability of that emission is OQ2).
    fn emit(&self, event: DnsEvent);
}

/// The default pre-stage sink: a no-op. `main` runs with this — there is no telemetry
/// transport at the pre-stage, only the obligation that the emission SITES exist and
/// fire on every path (which tests prove against the [`CapturingSink`] below).
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: DnsEvent) {}
}

/// An in-memory sink that records every emitted event, for the event-surface tests
/// (and any future in-process assertion). Clones share the same backing buffer, so a
/// test can hand a clone to the handler and read the events back through its own
/// handle. SERVICE-INTERNAL test/inspection seam; it is never a transport.
#[derive(Debug, Clone, Default)]
pub struct CapturingSink {
    events: Arc<Mutex<Vec<DnsEvent>>>,
}

impl CapturingSink {
    /// A fresh, empty capturing sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the events recorded so far (in emission order).
    pub fn events(&self) -> Vec<DnsEvent> {
        self.events
            .lock()
            .expect("event buffer mutex poisoned")
            .clone()
    }

    /// How many events have been recorded.
    pub fn len(&self) -> usize {
        self.events
            .lock()
            .expect("event buffer mutex poisoned")
            .len()
    }

    /// Whether no event has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl EventSink for CapturingSink {
    fn emit(&self, event: DnsEvent) {
        self.events
            .lock()
            .expect("event buffer mutex poisoned")
            .push(event);
    }
}

/// The PRODUCTION sink adapter: bridge any convention-layer [`TelemetryEventSink`]
/// (`ds_telemetry::event::EventSink` — chiefly the real [`ds_telemetry::SpoolSink`])
/// into this module's rich-`DnsEvent`-taking [`EventSink`], so the genuine
/// disk-bounded, visible-loss spool (D116) is the gate's sink. THIS is the collapse's
/// production wiring (doc 11 §5.5: "replace the type and the `EventSink` impl, never
/// the handler emission sites"): the handler still authors a [`DnsEvent`] and calls
/// `emit(event)` — only the SINK it targets swaps from a [`NullSink`] to this adapter
/// over a [`ds_telemetry::SpoolSink`].
///
/// Each [`DnsEvent`] is encoded to a convention-layer [`EventEnvelope`]
/// ([`DnsEvent::to_envelope`]) and handed to the wrapped sink's `emit`. Telemetry
/// emission never fails the data path (doc 14 §12.4): a `DnsEvent` always carries the
/// live verdict's complete POL-3 triple (§6.7), so the encode succeeds; on the
/// unreachable blank-provenance case the event is dropped here rather than panicking
/// the gate — the wire answer is authoritative, and a blank-provenance event would be
/// a CI failure long before this code path, never a silent ship of bad provenance.
#[derive(Debug, Clone)]
pub struct TelemetrySink<S: TelemetryEventSink> {
    inner: S,
}

impl<S: TelemetryEventSink> TelemetrySink<S> {
    /// Adapt a convention-layer [`TelemetryEventSink`] (e.g. a
    /// [`ds_telemetry::SpoolSink`]) into the gate's [`DnsEvent`] sink.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: TelemetryEventSink> EventSink for TelemetrySink<S> {
    fn emit(&self, event: DnsEvent) {
        // Encode the rich event into the convention carrier and transport it. A
        // complete POL-3 triple (always true on the handler path) encodes; the
        // (unreachable) blank-provenance case is dropped, never shipped blank.
        if let Ok(envelope) = event.to_envelope() {
            self.inner.emit(envelope);
        }
    }
}

// ===========================================================================
// The reload-boundary observability surface (doc 11 §5.3 / D72): the
// forward-only-seq DROP made OPERATIONALLY OBSERVABLE.
// ===========================================================================

/// WHY a host-local committed-snapshot fan-out did NOT advance the live policy version at
/// the reload boundary — the discriminator that tells a BENIGN dedup drop apart from a
/// real verify REJECTION.
///
/// `ds-dnsgate`'s subscriber commits one monotonic policy version (D72): it re-sources the
/// running evaluator + authored-SOA boundary zone only on a FORWARD seq, and DROPS a
/// re-delivered / out-of-order fan-out (seq ≤ the last committed seq) without re-sourcing
/// backwards (doc 11 §5.3). That drop is EXPECTED under a publisher burst (doc 11 §1
/// bounded-mpsc back-pressure fans the same commit out more than once) — it is NOT a fault.
///
/// A content_hash mismatch (D120) is the OPPOSITE: a snapshot whose committed identity does
/// not verify against its wire `content_hash` is REJECTED at the loader (doc 11 §5.4) — a
/// real integrity failure an operator must see and act on. The two non-commits are
/// operationally INDISTINGUISHABLE if both surface as a bare "no commit"; this reason is the
/// distinct, structured discriminator that keeps a benign fan-out dedup from being read as a
/// hash-mismatch rejection (and vice-versa). The variants are deliberately a CLOSED,
/// matchable set so a consumer (and a test) can assert distinctness structurally, not by
/// string-sniffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotDropReason {
    /// A DUPLICATE or OUT-OF-ORDER host-local fan-out: `dropped_seq ≤ committed_seq`, so the
    /// D72 forward-only commit drops it to keep one monotonic policy version (doc 11 §5.3).
    /// BENIGN — expected under a publisher burst; no integrity failure, nothing for an
    /// operator to chase. This is the signal THIS surface makes observable.
    StaleFanOut,
    /// A content_hash MISMATCH (D120): the snapshot's committed identity did not verify
    /// against its wire `content_hash`, so the loader NACKed it (doc 11 §5.4). A real
    /// integrity REJECTION — distinct from a benign [`StaleFanOut`](Self::StaleFanOut) dedup.
    /// Reserved here as the SECOND drop reason so the stale-fan-out signal is provably a
    /// DIFFERENT reason from a hash-mismatch NACK; the loader-side NACK that raises it is the
    /// SEPARATE content_hash task's surface (it is NOT raised from `watch_snapshots`).
    ContentHashMismatch,
    /// A SCHEMA FAILURE (doc 13 §5.1): the transported bytes VERIFIED against their wire
    /// `content_hash` (D120 hash check passed) but FAILED the POL-1 schema parse, so the loader
    /// NACKed the apply host-wide just like a hash mismatch (the host stays on vN). The SAME
    /// commit behavior as [`ContentHashMismatch`](Self::ContentHashMismatch) — a host-wide NACK,
    /// no new version committed — but a DISTINCT operator-telemetry reason so a verified-but-
    /// unparseable rejection (a bad authored/composed document) is separable from a tampered-
    /// transport rejection (a content_hash mismatch). Like a hash NACK and unlike a
    /// [`StaleFanOut`](Self::StaleFanOut) dedup, this is a real integrity REJECTION an operator
    /// must see and act on.
    SchemaFailure,
}

impl SnapshotDropReason {
    /// A stable, greppable token for this reason — the discriminator carried in the
    /// convention-layer payload so a downstream log/spool consumer can join on it. DISTINCT
    /// per variant (a stale-fan-out drop never renders the hash-mismatch token).
    pub fn as_str(&self) -> &'static str {
        match self {
            SnapshotDropReason::StaleFanOut => "stale_fan_out",
            SnapshotDropReason::ContentHashMismatch => "content_hash_mismatch",
            SnapshotDropReason::SchemaFailure => "schema_failure",
        }
    }

    /// Whether this is the benign duplicate/out-of-order fan-out dedup (the D72 forward-only
    /// drop) — `true` only for [`StaleFanOut`](Self::StaleFanOut), never for a hash-mismatch
    /// NACK. The predicate a consumer uses to keep a benign dedup off the integrity-alert path.
    pub fn is_stale_fan_out(&self) -> bool {
        matches!(self, SnapshotDropReason::StaleFanOut)
    }
}

/// A reload-boundary DROP event (doc 11 §5.3 / §5.5): a host-local committed-snapshot
/// fan-out that did NOT advance the live policy version, made OBSERVABLE so the §5.3
/// single-monotonic-version consistency story is visible at the reload boundary, not merely
/// correct. A service-internal convention-layer signal — the not-yet-frozen LOG-1 mirror,
/// exactly like [`DnsEvent`] (no `ds-contracts` / `hickory_*` type appears).
///
/// The [`reason`](Self::reason) is the load-bearing field: a [`SnapshotDropReason::StaleFanOut`]
/// is the benign D72 forward-only dedup; a [`SnapshotDropReason::ContentHashMismatch`] is a
/// D120 integrity REJECTION. Carrying the dropped seq AND the last committed seq alongside it
/// gives an operator the full identity to tell "fan-out re-delivered seq 4 while we are on 7"
/// (benign) apart from a verify failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDropEvent {
    /// WHY the snapshot was dropped — the discriminator (benign dedup vs hash-mismatch NACK).
    pub reason: SnapshotDropReason,
    /// The non-advancing `seq` of the dropped fan-out (the snapshot the subscriber declined to
    /// re-source).
    pub dropped_seq: u64,
    /// The last seq the admitter committed — the live monotonic policy version the dropped
    /// fan-out failed to advance past. `dropped_seq ≤ committed_seq` on a [`StaleFanOut`]
    /// (`SnapshotDropReason::StaleFanOut`).
    pub committed_seq: u64,
    /// POL-3 provenance — present on EVERY event (doc 11 §6.7, CI-fatal if missing), exactly
    /// as for [`DnsEvent`]. The reload-boundary drop carries the LIVE committed version's
    /// POL-3 triple (the version the dropped fan-out failed to advance past).
    pub provenance: EventProvenance,
}

impl SnapshotDropEvent {
    /// Construct a forward-only-seq STALE-FAN-OUT drop event (the D72 benign dedup): a
    /// duplicate / out-of-order fan-out at `dropped_seq` while the admitter is committed at
    /// `committed_seq`. The [`reason`](Self::reason) is fixed to
    /// [`SnapshotDropReason::StaleFanOut`] — the only drop `watch_snapshots` itself raises.
    pub fn stale_fan_out(
        dropped_seq: u64,
        committed_seq: u64,
        provenance: EventProvenance,
    ) -> Self {
        Self {
            reason: SnapshotDropReason::StaleFanOut,
            dropped_seq,
            committed_seq,
            provenance,
        }
    }

    /// Whether this drop is the benign D72 forward-only dedup (a stale fan-out), as opposed to
    /// a content_hash-mismatch NACK. The predicate that keeps a benign dedup off the
    /// integrity-alert path.
    pub fn is_stale_fan_out(&self) -> bool {
        self.reason.is_stale_fan_out()
    }

    /// Encode this reload-boundary drop into the convention-layer [`EventEnvelope`]
    /// (`ds_telemetry::event`) the production spool transports — the same bridge
    /// [`DnsEvent::to_envelope`] is, so the drop signal rides the genuine disk-bounded spool
    /// (D116). The envelope's [`EventKind`] is [`EventKind::PolicyDecision`] (a reload is a
    /// policy-version event, NOT a resolver query — so it is a DIFFERENT kind from a
    /// [`DnsEvent`]), and the greppable payload leads with the `reason` token
    /// ([`SnapshotDropReason::as_str`]) so a stale-fan-out dedup is joinable apart from a
    /// content_hash NACK. No secret crosses (a drop event carries none).
    ///
    /// Returns the [`ProvenanceError`] (never a blank-provenance envelope) if the POL-3 triple
    /// is somehow incomplete — unreachable on the subscriber path, where the live committed
    /// version's triple is non-empty (§6.7).
    pub fn to_envelope(&self) -> Result<EventEnvelope, ProvenanceError> {
        let provenance = self.provenance.to_provenance()?;
        Ok(EventEnvelope::new(
            EventKind::PolicyDecision,
            provenance,
            self.render_payload(),
        ))
    }

    /// The free pre-freeze payload rendering: a stable, greppable text encoding leading with
    /// the `reason` discriminator (the on-the-wire LOG-1 shape is the later Stage-0 freeze,
    /// never this). Opaque to the spool; carries no secret.
    fn render_payload(&self) -> Vec<u8> {
        format!(
            "snapshot_drop reason={} dropped_seq={} committed_seq={}",
            self.reason.as_str(),
            self.dropped_seq,
            self.committed_seq,
        )
        .into_bytes()
    }
}

/// The reload-boundary DROP emission seam: the subscriber loop ([`crate::server::watch_snapshots`])
/// hands every forward-only-seq drop to a sink, one method, no async, no `ds-contracts` type
/// — the [`EventSink`] twin for the reload boundary. A separate trait (not a method on
/// [`EventSink`]) so the query-path event sink and the reload-boundary drop sink compose
/// independently: the production wiring can route drops to the same spool the `DnsEvent`s land
/// in, while the in-process tests capture them without a transport.
///
/// `Send + Sync + 'static` so a sink can live behind the `Arc` the subscriber shares.
pub trait SnapshotDropSink: Send + Sync + 'static {
    /// Record one reload-boundary drop. Infallible by construction (a dropped telemetry record
    /// never changes the drop BEHAVIOR — the snapshot is dropped either way; the obligation is
    /// only to make the drop OBSERVABLE).
    fn observe_drop(&self, drop: SnapshotDropEvent);
}

/// The default reload-boundary drop sink: a no-op. The boundary-zone-only and production
/// commit paths that wire no drop observer default to this — the drop BEHAVIOR is unchanged
/// (still dropped, one monotonic version); only the OBSERVABILITY is opt-in via a real sink.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullDropSink;

impl SnapshotDropSink for NullDropSink {
    fn observe_drop(&self, _drop: SnapshotDropEvent) {}
}

/// An in-memory reload-boundary drop sink that records every observed drop, for the
/// event-surface tests (the [`CapturingSink`] twin). Clones share one backing buffer, so a
/// test hands a clone to the subscriber and reads the drops back through its own handle.
#[derive(Debug, Clone, Default)]
pub struct CapturingDropSink {
    drops: Arc<Mutex<Vec<SnapshotDropEvent>>>,
}

impl CapturingDropSink {
    /// A fresh, empty capturing drop sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the drops recorded so far (in observation order).
    pub fn drops(&self) -> Vec<SnapshotDropEvent> {
        self.drops
            .lock()
            .expect("drop buffer mutex poisoned")
            .clone()
    }

    /// How many drops have been recorded — the count an operator's dashboard joins on.
    pub fn len(&self) -> usize {
        self.drops.lock().expect("drop buffer mutex poisoned").len()
    }

    /// Whether no drop has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many recorded drops carry the given reason — the per-reason count that keeps a
    /// benign stale-fan-out dedup joinable apart from a content_hash NACK.
    pub fn count_with_reason(&self, reason: SnapshotDropReason) -> usize {
        self.drops
            .lock()
            .expect("drop buffer mutex poisoned")
            .iter()
            .filter(|d| d.reason == reason)
            .count()
    }
}

impl SnapshotDropSink for CapturingDropSink {
    fn observe_drop(&self, drop: SnapshotDropEvent) {
        self.drops
            .lock()
            .expect("drop buffer mutex poisoned")
            .push(drop);
    }
}

// ===========================================================================
// The warm-restart COMPLETION observability surface (doc 11 §8.4 / §5.5, OQ2
// rebuild posture): the DNS-2b admission-map REBUILD made OPERATIONALLY OBSERVABLE.
// ===========================================================================

/// A warm-restart REBUILD COMPLETION event (doc 11 §8.4 / §5.5): the
/// substantiation-coverage signal a `ds-dnsgate` restart emits once the OQ2 rebuild
/// reconstructs the in-memory §5.2 DNS-2b map from the kernel NFT-3 set dump + the
/// §5.5 spool replay (`crate::warm_restart`). It carries the **distinct
/// `(session, ip)` substantiated-element count** and a **reconciles bit** so an
/// operator observes restart-substantiation coverage live — how much of the
/// pre-restart admission surface the rebuild recovered, and whether the recovery
/// reconciled EXACTLY against the kernel dump (every kernel element accounted for
/// as either a substantiated element or a fail-closed gap).
///
/// A service-internal convention-layer signal — the not-yet-frozen LOG-1 mirror,
/// exactly like [`DnsEvent`] / [`SnapshotDropEvent`] (no `ds-contracts` /
/// `hickory_*` type appears; the scalars are plain `usize`/`bool`). The rich
/// `crate::warm_restart::RebuildReport` is projected onto this hickory-free,
/// `ds-contracts`-free carrier by [`crate::warm_restart::RebuildReport::completion_event`]
/// at the warm_restart → event boundary, so no `RebuildReport` type crosses into
/// the telemetry surface (the D67 corollary / §5.5 collapse discipline).
///
/// The [`distinct_ips_substantiated`](Self::distinct_ips_substantiated) scalar is
/// the metric the doc 11 §5.5 telemetry join reconciles against the kernel dump in
/// ALL cases (shared-CDN IPs included — see `RebuildReport::distinct_ips_substantiated`);
/// the [`reconciles`](Self::reconciles) bit is the derived
/// `distinct_ips_substantiated + provenance_gaps == kernel.element_count()` result
/// (`RebuildReport::reconciles_with`), so an operator reads coverage AND
/// integrity in one envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmRestartCompletionEvent {
    /// The distinct `(session, ip)` kernel-resident elements substantiated into the
    /// rebuilt map — each kernel allow-set element counted ONCE regardless of how
    /// many names back it (the `RebuildReport::distinct_ips_substantiated` metric).
    /// This is the scalar the §5.5 telemetry join reconciles against the kernel
    /// dump's element count in all cases, shared IPs included.
    pub distinct_ips_substantiated: usize,
    /// The number of kernel-resident IPs the spool could NOT substantiate — OMITTED
    /// fail-closed (the `RebuildReport::provenance_gaps` length). `ds-tlsproxy`
    /// re-admits each live via the TLS-1 re-resolve path; carried so the operator
    /// sees the coverage shortfall alongside the substantiated count.
    ///
    /// # CONTRACT — this is an ELEMENT-MULTIPLICITY count, NOT a distinct-`(session,ip)` count
    ///
    /// This scalar is `RebuildReport::provenance_gaps.len()` verbatim (see
    /// [`RebuildReport::completion_event`](crate::warm_restart::RebuildReport::completion_event) —
    /// the `completion_event()` consumer surface), and that vector can legitimately hold
    /// **DUPLICATE `(session, ip)` entries**: option (a) of the W1 (c) admit-failure arm
    /// pushes one [`GapReason::AdmitFailed`](crate::warm_restart::GapReason::AdmitFailed)
    /// gap **per kernel element**, so a duplicate-element dump that repeats the same
    /// `(session, ip)` migrates BOTH elements and records TWO gaps for the one IP. The
    /// count is therefore per-ELEMENT, in lockstep with
    /// [`KernelSetDump::element_count`](crate::warm_restart::KernelSetDump::element_count) —
    /// exactly what the `distinct_ips_substantiated + provenance_gaps == element_count`
    /// reconciliation ([`reconciles`](Self::reconciles)) balances against.
    ///
    /// A future gap consumer that DEDUPS by `(session, ip)` (e.g. collapsing the vector
    /// to unique IPs before counting) would silently UNDER-count the gaps and diverge
    /// from element-count reconciliation — the `reconciles` bit would read `true` while
    /// the deduped tally no longer balances. Consumers MUST treat this scalar (and the
    /// source `provenance_gaps` vector) as a multiplicity: count every element, never
    /// dedup by `(session, ip)`. Pinned by
    /// `warm_restart_completion_gap_count_is_element_multiplicity_not_deduped`.
    pub provenance_gaps: usize,
    /// The `(session, fqdn)` entries written into the rebuilt map (the
    /// `RebuildReport::entries_rebuilt` count) — context for the coverage signal.
    pub entries_rebuilt: usize,
    /// Whether the rebuild reconciled EXACTLY against the kernel dump's element count
    /// — the derived `RebuildReport::reconciles_with(&dump)` bit: every kernel
    /// element is accounted for as a distinct substantiated element XOR a
    /// fail-closed gap (`distinct_ips_substantiated + provenance_gaps == element_count`).
    /// A reconstructor that obeys the OQ2 invariant (c) always yields `true`; a
    /// `false` is an operator-visible accounting anomaly.
    pub reconciles: bool,
    /// POL-3 provenance — present on EVERY event (doc 11 §6.7, CI-fatal if missing),
    /// exactly as for [`DnsEvent`] / [`SnapshotDropEvent`]. The warm-restart
    /// completion carries the rebuild's provenance triple (the live policy version
    /// the rebuilt admissions were minted under).
    pub provenance: EventProvenance,
}

impl WarmRestartCompletionEvent {
    /// Construct a warm-restart completion event from the substantiation counts and a
    /// provenance triple. The [`reconciles`](Self::reconciles) bit is supplied by the
    /// caller (derived from `RebuildReport::reconciles_with(&dump)` at the
    /// warm_restart boundary, where the kernel dump is in scope).
    pub fn new(
        distinct_ips_substantiated: usize,
        provenance_gaps: usize,
        entries_rebuilt: usize,
        reconciles: bool,
        provenance: EventProvenance,
    ) -> Self {
        Self {
            distinct_ips_substantiated,
            provenance_gaps,
            entries_rebuilt,
            reconciles,
            provenance,
        }
    }

    /// Encode this warm-restart completion into the convention-layer [`EventEnvelope`]
    /// (`ds_telemetry::event`) the production spool transports — the same bridge
    /// [`DnsEvent::to_envelope`] / [`SnapshotDropEvent::to_envelope`] are, so the
    /// completion signal rides the genuine disk-bounded spool (D116). The envelope's
    /// [`EventKind`] is [`EventKind::PolicyDecision`] (a warm restart is a
    /// policy-version / lifecycle event, NOT a resolver query — so it is a DIFFERENT
    /// kind from a [`DnsEvent`], exactly as a [`SnapshotDropEvent`] is), and the
    /// greppable payload carries the `distinct_ips_substantiated` scalar and the
    /// `reconciles` bit. No secret crosses (a completion event carries none).
    ///
    /// Returns the [`ProvenanceError`] (never a blank-provenance envelope) if the
    /// POL-3 triple is somehow incomplete — unreachable on the rebuild path, where
    /// the rebuild's provenance triple is non-empty (§6.7).
    pub fn to_envelope(&self) -> Result<EventEnvelope, ProvenanceError> {
        let provenance = self.provenance.to_provenance()?;
        Ok(EventEnvelope::new(
            EventKind::PolicyDecision,
            provenance,
            self.render_payload(),
        ))
    }

    /// The free pre-freeze payload rendering: a stable, greppable text encoding
    /// leading with the `warm_restart_complete` marker and the
    /// `distinct_ips_substantiated` scalar + the `reconciles` bit (the on-the-wire
    /// LOG-1 shape is the later Stage-0 freeze, never this). Opaque to the spool;
    /// carries no secret.
    fn render_payload(&self) -> Vec<u8> {
        format!(
            "warm_restart_complete distinct_ips_substantiated={} provenance_gaps={} \
             entries_rebuilt={} reconciles={}",
            self.distinct_ips_substantiated,
            self.provenance_gaps,
            self.entries_rebuilt,
            self.reconciles,
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A live POL-3 triple — what the handler now stamps from the verdict (no fixed
    /// pre-stage marker remains).
    fn live_provenance() -> EventProvenance {
        EventProvenance {
            rule_id: "core/api.anthropic.com".to_string(),
            policy_layer: "pol2-system-baseline".to_string(),
            policy_version: "2026-06-01".to_string(),
        }
    }

    #[test]
    fn provenance_is_present_on_every_event() {
        // §6.7: provenance is present on every event — the handler stamps the LIVE
        // verdict's POL-3 triple, so the field is a non-empty {rule_id, layer, version}
        // and the "missing provenance fails CI" invariant holds structurally.
        let p = live_provenance();
        assert!(!p.rule_id.is_empty());
        assert!(!p.policy_layer.is_empty());
        assert!(!p.policy_version.is_empty());
    }

    #[test]
    fn aaaa_only_trigger_is_only_a_determined_true() {
        // The T-C3 join predicate: only a genuinely-determined v6-only answer is a
        // trigger. A deferral is "unknown", never counted as a trigger or as false.
        assert!(AaaaOnly::Determined(true).is_trigger());
        assert!(!AaaaOnly::Determined(false).is_trigger());
        assert!(!AaaaOnly::Deferred(DeferralReason::FastNodataNoForward).is_trigger());
        assert!(AaaaOnly::Deferred(DeferralReason::FastNodataNoForward).is_deferred());
        assert!(AaaaOnly::Deferred(DeferralReason::ForwardedNoDataV6Invisible).is_deferred());
        assert!(!AaaaOnly::Determined(false).is_deferred());
    }

    #[test]
    fn capturing_sink_records_in_order() {
        let sink = CapturingSink::new();
        assert!(sink.is_empty());
        for (i, path) in [EventPath::FastNodata, EventPath::ForwardedAnswer]
            .into_iter()
            .enumerate()
        {
            sink.emit(DnsEvent {
                qname: format!("q{i}.example.test."),
                qtype: 1,
                path,
                aaaa_stripped: 0,
                aaaa_only: AaaaOnly::Deferred(DeferralReason::FastNodataNoForward),
                aimed_resolver: None,
                provenance: live_provenance(),
            });
        }
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].path, EventPath::FastNodata);
        assert_eq!(events[1].path, EventPath::ForwardedAnswer);
        // Every event carries provenance (§6.7).
        assert!(events.iter().all(|e| !e.provenance.rule_id.is_empty()));
    }

    /// The collapse bridge: a `DnsEvent` encodes 1:1 into the convention-layer
    /// `EventEnvelope` (`ds_telemetry::event`) — kind `DnsEvent`, the POL-3 triple
    /// carried as the mandatory `Provenance`, and the schema signals in the opaque
    /// payload. The same triple the rich event holds is the envelope's provenance, so
    /// "missing provenance fails CI" stays structural across the collapse.
    #[test]
    fn dns_event_encodes_into_a_telemetry_envelope_with_its_provenance() {
        let event = DnsEvent {
            qname: "v6.example.test.".to_string(),
            qtype: 28,
            path: EventPath::FastNodata,
            aaaa_stripped: 1,
            aaaa_only: AaaaOnly::Deferred(DeferralReason::FastNodataNoForward),
            aimed_resolver: None,
            provenance: live_provenance(),
        };
        let envelope = event.to_envelope().expect("a live POL-3 triple encodes");
        assert_eq!(envelope.kind(), EventKind::DnsEvent);
        // The convention-layer provenance is the same triple the rich event carried.
        assert_eq!(envelope.provenance().rule_id(), "core/api.anthropic.com");
        assert_eq!(envelope.provenance().policy_layer(), "pol2-system-baseline");
        assert_eq!(envelope.provenance().policy_version(), "2026-06-01");
        // A DnsEvent never carries a credential signal (that is the CredentialUseEvent
        // shape), so the envelope's credential fingerprint is absent.
        assert!(envelope.credential_fingerprint().is_none());
        // The schema signals ride the opaque payload (the pre-freeze free rendering).
        let payload = String::from_utf8_lossy(envelope.payload());
        assert!(payload.contains("qname=v6.example.test."));
        assert!(payload.contains("qtype=28"));
        assert!(payload.contains("aaaa_stripped=1"));
        // OQ3 conservative default: the reserved-optional `aimed_resolver` is ALWAYS
        // present in the rendering, rendered as the `-` sentinel while unpopulated.
        assert!(
            payload.contains("aimed_resolver=-"),
            "aimed_resolver is reserved-optional and renders the `-` sentinel until OQ3 \
             populates it (payload: {payload})"
        );
    }

    #[test]
    fn aimed_resolver_renders_when_populated_but_defaults_unpopulated() {
        // The reserved-optional field carries an addr:port when a value IS present (the
        // shape the ConnOrigin task will populate once OQ3 is decided), and the `-`
        // sentinel when it is the conservative always-`None` default. The SHAPE is ready;
        // only the population is deferred.
        let unpopulated = DnsEvent {
            qname: "a.example.test.".to_string(),
            qtype: 1,
            path: EventPath::ForwardedAnswer,
            aaaa_stripped: 0,
            aaaa_only: AaaaOnly::Determined(false),
            aimed_resolver: None,
            provenance: live_provenance(),
        };
        assert!(String::from_utf8_lossy(&unpopulated.render_payload()).contains("aimed_resolver=-"));

        let populated = DnsEvent {
            aimed_resolver: Some("8.8.8.8:53".parse().unwrap()),
            ..unpopulated.clone()
        };
        assert!(String::from_utf8_lossy(&populated.render_payload())
            .contains("aimed_resolver=8.8.8.8:53"));
    }

    /// The PRODUCTION sink adapter: `TelemetrySink` bridges a convention-layer
    /// `TelemetryEventSink` into the gate's `DnsEvent` sink, so emitting a `DnsEvent`
    /// lands an encoded `EventEnvelope` in the wrapped sink — the path by which the real
    /// `ds_telemetry::SpoolSink` becomes the gate's sink with the emission sites
    /// unchanged. Asserted against a tiny in-memory `TelemetryEventSink` capture.
    #[test]
    fn telemetry_sink_adapter_forwards_an_encoded_envelope() {
        use std::sync::Mutex as StdMutex;

        #[derive(Default, Clone)]
        struct CapturingEnvelopeSink {
            seen: Arc<StdMutex<Vec<EventEnvelope>>>,
        }
        impl TelemetryEventSink for CapturingEnvelopeSink {
            fn emit(&self, event: EventEnvelope) {
                self.seen.lock().expect("poisoned").push(event);
            }
        }

        let capture = CapturingEnvelopeSink::default();
        // The gate's DnsEvent sink IS a TelemetrySink over a convention-layer sink —
        // the same shape `with_forwarder_boundary_zone_and_sink` accepts (an
        // `Arc<dyn EventSink>`), so the SpoolSink wiring is a drop-in here.
        let sink: Arc<dyn EventSink> = Arc::new(TelemetrySink::new(capture.clone()));

        sink.emit(DnsEvent {
            qname: "a.example.test.".to_string(),
            qtype: 1,
            path: EventPath::ForwardedAnswer,
            aaaa_stripped: 0,
            aaaa_only: AaaaOnly::Determined(false),
            aimed_resolver: None,
            provenance: live_provenance(),
        });

        let seen = capture.seen.lock().expect("poisoned");
        assert_eq!(seen.len(), 1, "the DnsEvent was encoded and forwarded once");
        assert_eq!(seen[0].kind(), EventKind::DnsEvent);
        assert_eq!(seen[0].provenance().rule_id(), "core/api.anthropic.com");
    }

    // -----------------------------------------------------------------------
    // The reload-boundary stale-fan-out-drop observability surface (D72 / §5.3).
    // -----------------------------------------------------------------------

    #[test]
    fn stale_fan_out_drop_reason_is_distinct_from_a_content_hash_nack() {
        // The load-bearing distinctness: a benign forward-only dedup drop and a content_hash
        // NACK are DIFFERENT reasons — a consumer (and the integration test) can tell them
        // apart structurally, not by string-sniffing.
        assert_ne!(
            SnapshotDropReason::StaleFanOut,
            SnapshotDropReason::ContentHashMismatch,
            "a stale-fan-out dedup is a DIFFERENT reason from a content_hash NACK (D120)"
        );
        assert!(SnapshotDropReason::StaleFanOut.is_stale_fan_out());
        assert!(!SnapshotDropReason::ContentHashMismatch.is_stale_fan_out());
        // The greppable tokens never collide.
        assert_ne!(
            SnapshotDropReason::StaleFanOut.as_str(),
            SnapshotDropReason::ContentHashMismatch.as_str(),
        );
        assert_eq!(SnapshotDropReason::StaleFanOut.as_str(), "stale_fan_out");

        // The THIRD reason: a SCHEMA FAILURE (verified bytes that fail the POL-1 parse) is a
        // DISTINCT integrity-rejection reason from both a tampered-transport hash NACK and a
        // benign stale fan-out, so operator telemetry separates the verified-but-unparseable case
        // from a content_hash mismatch (doc 13 §5.1) without changing the host-wide NACK behavior.
        assert_ne!(
            SnapshotDropReason::SchemaFailure,
            SnapshotDropReason::ContentHashMismatch,
            "a schema failure is a DIFFERENT reason from a content_hash NACK (doc 13 §5.1)"
        );
        assert_ne!(
            SnapshotDropReason::SchemaFailure,
            SnapshotDropReason::StaleFanOut,
            "a schema failure is a real integrity rejection, NOT a benign stale fan-out"
        );
        // Like a hash NACK and unlike a stale fan-out, a schema failure is NOT a benign dedup.
        assert!(!SnapshotDropReason::SchemaFailure.is_stale_fan_out());
        // The greppable tokens are all distinct.
        assert_ne!(
            SnapshotDropReason::SchemaFailure.as_str(),
            SnapshotDropReason::ContentHashMismatch.as_str(),
        );
        assert_ne!(
            SnapshotDropReason::SchemaFailure.as_str(),
            SnapshotDropReason::StaleFanOut.as_str(),
        );
        assert_eq!(
            SnapshotDropReason::ContentHashMismatch.as_str(),
            "content_hash_mismatch"
        );
        assert_eq!(SnapshotDropReason::SchemaFailure.as_str(), "schema_failure");
    }

    #[test]
    fn stale_fan_out_drop_event_carries_its_identity_and_reason() {
        // A duplicate of seq 4 while committed at 7: the benign D72 drop. The event names the
        // reason, the dropped seq, and the live committed version it failed to advance past.
        let drop = SnapshotDropEvent::stale_fan_out(4, 7, live_provenance());
        assert_eq!(drop.reason, SnapshotDropReason::StaleFanOut);
        assert!(drop.is_stale_fan_out());
        assert_eq!(drop.dropped_seq, 4);
        assert_eq!(drop.committed_seq, 7);
        assert!(!drop.provenance.rule_id.is_empty());
    }

    #[test]
    fn stale_fan_out_drop_encodes_into_a_policy_decision_envelope_distinct_from_a_dns_event() {
        // The reload-boundary drop rides the convention-layer spool as a PolicyDecision (a
        // reload is a policy-version event), a DIFFERENT kind from a resolver DnsEvent — and
        // its payload leads with the `stale_fan_out` reason token so it is joinable apart from
        // a content_hash NACK.
        let drop = SnapshotDropEvent::stale_fan_out(2, 5, live_provenance());
        let envelope = drop.to_envelope().expect("a live POL-3 triple encodes");
        assert_eq!(
            envelope.kind(),
            EventKind::PolicyDecision,
            "a reload-boundary drop is a PolicyDecision, NOT a resolver DnsEvent"
        );
        assert_ne!(envelope.kind(), EventKind::DnsEvent);
        // A drop event carries no credential signal.
        assert!(envelope.credential_fingerprint().is_none());
        let payload = String::from_utf8_lossy(envelope.payload());
        assert!(
            payload.contains("reason=stale_fan_out"),
            "the payload leads with the distinct stale-fan-out reason token (payload: {payload})"
        );
        assert!(payload.contains("dropped_seq=2"));
        assert!(payload.contains("committed_seq=5"));
        assert!(
            !payload.contains("content_hash_mismatch"),
            "a benign dedup drop never renders the hash-mismatch token"
        );
    }

    #[test]
    fn capturing_drop_sink_records_and_counts_by_reason() {
        let sink = CapturingDropSink::new();
        assert!(sink.is_empty());
        sink.observe_drop(SnapshotDropEvent::stale_fan_out(1, 1, live_provenance()));
        sink.observe_drop(SnapshotDropEvent::stale_fan_out(2, 3, live_provenance()));
        assert_eq!(sink.len(), 2);
        assert_eq!(
            sink.count_with_reason(SnapshotDropReason::StaleFanOut),
            2,
            "both observed drops were benign stale fan-outs"
        );
        assert_eq!(
            sink.count_with_reason(SnapshotDropReason::ContentHashMismatch),
            0,
            "no content_hash NACK was observed on this surface"
        );
        let drops = sink.drops();
        assert_eq!(drops[0].dropped_seq, 1);
        assert_eq!(drops[1].dropped_seq, 2);
    }

    // -----------------------------------------------------------------------
    // The warm-restart COMPLETION observability surface (OQ2 rebuild / §8.4 / §5.5).
    // -----------------------------------------------------------------------

    #[test]
    fn warm_restart_completion_carries_distinct_count_and_reconciles_bit() {
        // The completion event carries the distinct `(session, ip)` substantiated-element
        // count and the derived reconciles bit — what an operator joins on to observe
        // restart-substantiation coverage.
        let event = WarmRestartCompletionEvent::new(3, 1, 2, true, live_provenance());
        assert_eq!(event.distinct_ips_substantiated, 3);
        assert_eq!(event.provenance_gaps, 1);
        assert_eq!(event.entries_rebuilt, 2);
        assert!(event.reconciles);
        assert!(!event.provenance.rule_id.is_empty());
    }

    #[test]
    fn warm_restart_completion_encodes_into_a_policy_decision_envelope_distinct_from_a_dns_event() {
        // The completion rides the convention-layer spool as a PolicyDecision (a warm
        // restart is a policy-version / lifecycle event), a DIFFERENT kind from a resolver
        // DnsEvent — and its payload carries the documented `distinct_ips_substantiated`
        // scalar and the `reconciles` bit.
        let event = WarmRestartCompletionEvent::new(5, 0, 4, true, live_provenance());
        let envelope = event.to_envelope().expect("a live POL-3 triple encodes");
        assert_eq!(
            envelope.kind(),
            EventKind::PolicyDecision,
            "a warm-restart completion is a PolicyDecision, NOT a resolver DnsEvent"
        );
        assert_ne!(envelope.kind(), EventKind::DnsEvent);
        // A completion event carries no credential signal.
        assert!(envelope.credential_fingerprint().is_none());
        // The convention-layer provenance is the same triple the rich event carried.
        assert_eq!(envelope.provenance().rule_id(), "core/api.anthropic.com");
        let payload = String::from_utf8_lossy(envelope.payload());
        assert!(
            payload.contains("distinct_ips_substantiated=5"),
            "the payload carries the distinct-IP substantiated scalar (payload: {payload})"
        );
        assert!(
            payload.contains("reconciles=true"),
            "the payload carries the derived reconciles bit (payload: {payload})"
        );
        assert!(payload.contains("warm_restart_complete"));
        assert!(payload.contains("entries_rebuilt=4"));
        assert!(payload.contains("provenance_gaps=0"));
    }

    #[test]
    fn warm_restart_completion_gap_count_is_element_multiplicity_not_deduped() {
        // CONTRACT PIN (the `provenance_gaps` field doc): the completion event's gap
        // count is `RebuildReport::provenance_gaps.len()` — an ELEMENT-MULTIPLICITY
        // count that can legitimately hold DUPLICATE `(session, ip)` AdmitFailed
        // entries (option (a) pushes one gap PER kernel element). This test drives the
        // exact `completion_event()` consumer surface with a duplicate-element report
        // and pins that a future consumer deduping by `(session, ip)` would DIVERGE
        // from element-count reconciliation — so the multiplicity is load-bearing.
        use crate::warm_restart::{
            GapReason, KernelElement, KernelSetDump, ProvenanceGap, RebuildReport,
        };
        use ds_contracts::dns_admission::Instant;
        use std::collections::HashSet;
        use std::net::{IpAddr, Ipv4Addr};

        let dup_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let deadline = Instant::from_unix_nanos(2_000 * 1_000_000_000);

        // A duplicate-element kernel dump: the SAME `(session, ip)` element repeated
        // twice — element_count == 2 (the rebuild's analogue of a duplicate-stuffed
        // dump).
        let kernel = KernelSetDump::new()
            .with_element(
                "sess-1",
                KernelElement {
                    ip: dup_ip,
                    deadline,
                },
            )
            .with_element(
                "sess-1",
                KernelElement {
                    ip: dup_ip,
                    deadline,
                },
            );
        assert_eq!(kernel.element_count(), 2);

        // The report option (a) produces when the admit refuses the duplicated name:
        // BOTH elements migrate off the substantiated tally (distinct == 0) and become
        // TWO `AdmitFailed` gaps for the ONE `(session, ip)` — a legitimate duplicate.
        let report = RebuildReport {
            entries_rebuilt: 0,
            ips_substantiated: 0,
            distinct_ips_substantiated: 0,
            provenance_gaps: vec![
                ProvenanceGap {
                    session_uuid: "sess-1".into(),
                    ip: dup_ip,
                    reason: GapReason::AdmitFailed,
                },
                ProvenanceGap {
                    session_uuid: "sess-1".into(),
                    ip: dup_ip,
                    reason: GapReason::AdmitFailed,
                },
            ],
        };
        // The report itself reconciles: distinct (0) + gaps (2) == element_count (2).
        assert!(report.reconciles_with(&kernel));

        // The completion_event() consumer surface carries the MULTIPLICITY (2), NOT a
        // distinct-IP dedup (1), and the derived reconciles bit is true.
        let event = report.completion_event(&kernel, live_provenance());
        assert_eq!(
            event.provenance_gaps,
            report.provenance_gaps.len(),
            "the event's gap count is the vector length (element multiplicity), verbatim"
        );
        assert_eq!(
            event.provenance_gaps, 2,
            "two AdmitFailed gaps for one duplicated (session, ip) — the multiplicity"
        );
        assert!(event.reconciles);

        // The on-the-wire payload carries the multiplicity, so a spool consumer reads 2.
        let envelope = event.to_envelope().expect("a live POL-3 triple encodes");
        let payload = String::from_utf8_lossy(envelope.payload());
        assert!(
            payload.contains("provenance_gaps=2"),
            "the payload carries the element multiplicity, not a deduped count (payload: {payload})"
        );

        // THE DIVERGENCE PIN: a future consumer that DEDUPS the gaps by `(session, ip)`
        // would count 1, and `distinct_ips_substantiated + deduped != element_count` —
        // it silently diverges from element-count reconciliation while the reconciles
        // bit still reads true. This is exactly what the field contract forbids.
        let deduped: HashSet<(&str, IpAddr)> = report
            .provenance_gaps
            .iter()
            .map(|g| (g.session_uuid.as_str(), g.ip))
            .collect();
        assert_eq!(deduped.len(), 1, "dedup-by-(session,ip) collapses to one");
        assert_ne!(
            report.distinct_ips_substantiated + deduped.len(),
            kernel.element_count(),
            "a (session,ip)-deduped gap tally BREAKS element-count reconciliation — \
             the multiplicity contract is load-bearing"
        );
    }
}
