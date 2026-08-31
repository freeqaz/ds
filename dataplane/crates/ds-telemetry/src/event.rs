//! Event-construction convention surface — the trait the `ds-dnsgate`
//! `event.rs` mirror (and the future `ds-tlsproxy` / `ds-flowlog` emitters) can
//! later collapse onto (doc 14 §6/§12.4; doc 11 §5.5 / §6.7).
//!
//! # The migration contract: replace the type + sink impl, never the emission sites
//!
//! `ds-dnsgate` deliberately stood up a `ds-contracts`-free `DnsEvent` mirror
//! with its own `EventProvenance` and a one-method `EventSink` trait, because the
//! frozen LOG-1 message types are NOT generated yet (doc 11 §5.5: "Swapping in
//! the frozen `ds-contracts` LOG-1 event is a matter of replacing this type and
//! the `EventSink` impl — never the handler emission sites"). This module is the
//! shared convention that mirror collapses onto:
//!
//!   * [`EventEnvelope`] — the construction carrier: every event carries POL-3
//!     [`Provenance`](crate::provenance::Provenance) **mandatorily** (the field
//!     is non-optional and the only constructor takes it by value), and any
//!     credential-bearing value is a [`Fingerprint`](crate::scrub::Fingerprint),
//!     never plaintext (D73 chokepoint). So "provenance on every event" and
//!     "never-log-the-secret" are structural at construction time, not asserted
//!     after the fact.
//!   * [`EventSink`] — the one-method emission seam, shaped exactly like
//!     `ds-dnsgate::event::EventSink` so the service-internal mirror becomes a
//!     `pub use` (the type collapse) and the real `ds-telemetry` spool
//!     ([`crate::spool`]) becomes the production `EventSink` impl — the handler
//!     emission sites do not move.
//!
//! This module owns CONVENTIONS, never the LOG-1 SCHEMA (doc 14 §12.4): it does
//! not define `FlowRecord` / `DnsEvent` / `HttpEvent` / `PolicyDecision` field
//! sets — those land in `ds-contracts` from the one-shot Stage-0 proto freeze.
//! [`EventEnvelope`] carries the convention-level signals (kind, provenance,
//! optional credential fingerprint, opaque payload bytes) every emitter shares.

use crate::provenance::Provenance;
use crate::scrub::Fingerprint;

/// The LOG-1 message family an envelope belongs to (doc 09 §7 / doc 14 §2). This
/// is the convention-level discriminator the spool and reconciliation read; the
/// per-message FIELD set is the frozen schema (`ds-contracts`), not this enum.
/// Mirrors the six frozen wire messages plus the `SpoolOverflow` marker so the
/// migration onto the generated types is a 1:1 mapping, never a re-shaping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// `FlowRecord` — netflow-style per-flow metadata (doc 09 §7).
    FlowRecord,
    /// `DnsEvent` — a resolver query/answer event (doc 11 §5.5).
    DnsEvent,
    /// `HttpEvent` — HTTP(S) request metadata at the egress gateway (doc 12).
    HttpEvent,
    /// `PolicyDecision` — a verdict + POL-3 provenance (doc 12 §5.1).
    PolicyDecision,
    /// `CredentialUseEvent` — a credential use, fingerprint-only (D8/D73).
    CredentialUseEvent,
}

/// The construction carrier every emitter builds and hands to an [`EventSink`].
///
/// Two invariants are STRUCTURAL here, not asserted downstream:
///
///   1. **POL-3 provenance is mandatory** — [`provenance`](Self::provenance) is a
///      non-optional [`Provenance`], and the only constructor
///      ([`EventEnvelope::new`]) takes it by value. There is no way to build an
///      envelope without it; a `Provenance` itself cannot be blank
///      ([`Provenance::new`](crate::provenance::Provenance::new) rejects empty
///      fields). "Missing provenance fails CI" (doc 14 §2) is thus a
///      compile/construction-time property.
///   2. **Never-log-the-secret** — the credential field is a
///      [`Fingerprint`](crate::scrub::Fingerprint), never a raw value. There is
///      no API on this type that accepts plaintext, so the only credential signal
///      that can reach the spool is the keyed digest (D73 chokepoint,
///      [`crate::scrub`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventEnvelope {
    kind: EventKind,
    provenance: Provenance,
    credential_fingerprint: Option<Fingerprint>,
    /// Opaque, already-scrubbed payload bytes (the encoded message body). The
    /// emitter is responsible for never placing a secret value in here — and the
    /// only way it CAN place a credential signal is a [`Fingerprint`] via
    /// [`EventEnvelope::with_credential`], so the chokepoint stays the only path.
    payload: Vec<u8>,
}

impl EventEnvelope {
    /// Construct an event. POL-3 provenance is required by value — there is no
    /// provenance-free constructor. `payload` is the already-encoded, scrubbed
    /// message body (convention layer: this crate does not own the schema).
    ///
    /// # Missing provenance is a COMPILE-time failure (doc 14 §2)
    ///
    /// There is no way to construct an event without provenance — omitting the
    /// argument does not compile. This `compile_fail` doctest is the (tested)
    /// proof that "missing provenance fails CI" is structural, not a runtime hope:
    ///
    /// ```compile_fail
    /// use ds_telemetry::event::{EventEnvelope, EventKind};
    /// // No provenance argument — there is no such constructor; this does not build.
    /// let _ = EventEnvelope::new(EventKind::DnsEvent, b"payload".to_vec());
    /// ```
    ///
    /// The well-formed call takes a checked [`Provenance`](crate::provenance::Provenance)
    /// (whose own constructor rejects empty fields):
    ///
    /// ```
    /// use ds_telemetry::event::{EventEnvelope, EventKind};
    /// use ds_telemetry::provenance::Provenance;
    /// let prov = Provenance::new("core/rule", "pol2-system-baseline", "2026-06-01").unwrap();
    /// let _ = EventEnvelope::new(EventKind::DnsEvent, prov, b"payload".to_vec());
    /// ```
    pub fn new(kind: EventKind, provenance: Provenance, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            provenance,
            credential_fingerprint: None,
            payload: payload.into(),
        }
    }

    /// Attach a credential FINGERPRINT (never a plaintext value) — the D73
    /// fingerprint-only convention (the `CredentialUseEvent` shape). The argument
    /// type forbids plaintext: a caller must have already routed the secret
    /// through [`Fingerprinter`](crate::scrub::Fingerprinter).
    pub fn with_credential(mut self, fingerprint: Fingerprint) -> Self {
        self.credential_fingerprint = Some(fingerprint);
        self
    }

    /// The LOG-1 message family.
    pub fn kind(&self) -> EventKind {
        self.kind
    }

    /// The mandatory POL-3 provenance.
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// The credential fingerprint, if this event references a credential — keyed
    /// digest only, never plaintext (D73).
    pub fn credential_fingerprint(&self) -> Option<&Fingerprint> {
        self.credential_fingerprint.as_ref()
    }

    /// The opaque, already-scrubbed payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// The emission seam: an emitter hands every constructed [`EventEnvelope`] to a
/// sink. One method, no hickory/pingora types — shaped exactly like
/// `ds-dnsgate::event::EventSink` so that mirror becomes a `pub use` of this
/// trait, and the real spool ([`crate::spool::SpoolSink`]) is the production
/// impl. The migration replaces the impl, never the emission sites.
///
/// `Send + Sync + 'static` so a sink can live behind the `Arc` a handler shares
/// across its accept loops (the same bound `ds-dnsgate`'s `EventSink` carries).
pub trait EventSink: Send + Sync + 'static {
    /// Record one constructed event. Telemetry emission never fails the data path
    /// (the wire answer is authoritative; the obligation is to EMIT, and the
    /// durability of that emission is the spool's bounded-loss contract — doc 14
    /// §12.4, D116): an overflowing spool drops payload events but ships the
    /// visible-loss marker, it does not return an error here.
    fn emit(&self, event: EventEnvelope);
}

/// The default no-op sink — the convention-layer `NullSink` (mirrors
/// `ds-dnsgate::event::NullSink`): emission sites exist and fire, but nothing is
/// transported. Used where no spool is wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: EventEnvelope) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrub::{Fingerprinter, Secret};

    fn provenance() -> Provenance {
        Provenance::new(
            "core/api.anthropic.com",
            "pol2-system-baseline",
            "2026-06-01",
        )
        .expect("valid triple")
    }

    #[test]
    fn every_envelope_carries_provenance() {
        let e = EventEnvelope::new(EventKind::DnsEvent, provenance(), b"payload".to_vec());
        // §6.7: provenance is present on every event — structurally, the field is
        // non-optional and non-blank.
        assert!(!e.provenance().rule_id().is_empty());
        assert!(!e.provenance().policy_layer().is_empty());
        assert!(!e.provenance().policy_version().is_empty());
        assert_eq!(e.kind(), EventKind::DnsEvent);
        assert!(e.credential_fingerprint().is_none());
    }

    #[test]
    fn credential_field_takes_only_a_fingerprint() {
        let fp = Fingerprinter::new(b"k".to_vec());
        let envelope = EventEnvelope::new(
            EventKind::CredentialUseEvent,
            provenance(),
            b"meta".to_vec(),
        )
        .with_credential(fp.fingerprint(Secret::new("ghp_canary_value")));
        // The credential signal is a keyed digest, never the plaintext.
        let recorded = envelope.credential_fingerprint().unwrap().as_hex();
        assert!(!recorded.contains("canary"));
        assert!(!recorded.contains("ghp_"));
    }

    #[test]
    fn null_sink_accepts_events() {
        let sink = NullSink;
        sink.emit(EventEnvelope::new(
            EventKind::FlowRecord,
            provenance(),
            Vec::new(),
        ));
    }
}
