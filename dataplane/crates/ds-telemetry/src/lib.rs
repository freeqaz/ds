//! ds-telemetry — the LOG-1 emitter CONVENTIONS layer (doc 14 §6 crate map,
//! "LOG-1 emitter" row; doc 14 §12.4).
//!
//! One crate owns *how* data-plane events are constructed, scrubbed, and spooled
//! so the auditable record of "everything every VM did on the network" (doc 09
//! §7) has one set of conventions instead of three. Both proxies and `ds-flowlog`
//! emit through it.
//!
//! # What lives here (CONVENTIONS, not the LOG-1 SCHEMA)
//!
//! The frozen LOG-1 message FIELD sets (`FlowRecord` / `DnsEvent` / `HttpEvent` /
//! `PolicyDecision` / `CredentialUseEvent` / `SessionRef`) are generated into
//! `ds-contracts` from the one-shot Stage-0 proto freeze (doc 14 §12.4 "What must
//! NOT live here"). They are NOT defined here. This crate owns the cross-emitter
//! conventions the schema sits inside:
//!
//! - [`scrub`] — **D73 never-log-the-secret scrub/fingerprint chokepoint**,
//!   enforced ONCE: a [`scrub::Secret`] is a one-way wrapper (no `Debug`/accessor
//!   reaches its plaintext) whose only operation is becoming a keyed
//!   [`scrub::Fingerprint`] via [`scrub::Fingerprinter`]. Event construction
//!   accepts only fingerprints, so a matched secret or swapped credential appears
//!   in NO event, log, spool, or error path — fingerprint only.
//! - [`provenance`] — the **mandatory POL-3 provenance** triple
//!   ([`provenance::Provenance`] = `{rule_id, policy_layer, policy_version}`).
//!   It is non-optional on every event-construction entry point and its
//!   constructor rejects empty fields, so "missing provenance fails CI" (doc 14
//!   §2) is a compile/construction-time property, never a silent pass.
//! - [`spool`] — the **disk-bounded tokio spool client** (LOG-3): a bounded
//!   on-disk ring with drop-oldest under the bound and a
//!   [`spool::SpoolOverflow`] visible-loss marker (D116) that rides a
//!   never-evicted priority lane, batching, and a background flush task.
//! - [`event`] — the **event-construction trait surface** the `ds-dnsgate`
//!   `event.rs` mirror (and the later `ds-tlsproxy` / `ds-flowlog` emitters) can
//!   collapse onto: [`event::EventEnvelope`] (mandatory provenance + fingerprint-
//!   only credential field) and [`event::EventSink`] (the one-method emission
//!   seam the [`spool::SpoolSink`] is the production impl of). The migration is
//!   "replace the type + `EventSink` impl, never the emission sites".
//! - [`flow`] — the **NFT-5 kernel-flow → LOG-1 `FlowRecord` mapping** (doc 09
//!   §3 NFT-5; doc 14 §2/§5, D43/D76): conntrack accounting events (start/stop,
//!   bytes, packets, duration) and `nflog` drop events are parsed from their
//!   synthetic/offline text form and mapped onto a [`flow::FlowRecord`] carrying
//!   the decoded per-session D76 `ct mark` (interface-anchored attribution, never
//!   source IP), then onto an [`event::EventEnvelope`] the [`spool`] feeds to the
//!   Stage-1 local event log. An unresolvable session degrades to unmarked
//!   best-effort, never a refusal (mark-only-adds, doc 14 §5).
//! - [`quic_reject_counter`] — the **D70 per-session QUIC-blocked reject
//!   counter**: the udp/443 NFT-4 reject is counted PER SESSION (never
//!   aggregated) and surfaced as a `(tap_name, count,
//!   [`ds_contracts::reject::RejectReason::QuicBlocked`])` snapshot a LOG-1
//!   `FlowRecord` carries (doc 12 §7; doc 14 §2 `FlowRecord` `RejectReason` row).
//!
//! # Decisions this crate enforces
//!
//! D73 (fingerprint-only / never-log-the-secret, the egress-gateway
//! credential-swap and secret-scanning paths route through [`scrub`]); D75
//! (family-agnostic addresses — consumed via the frozen
//! [`ds_contracts::dns_admission::AdmittedAddr`], not restated here); POL-3/D67
//! (mandatory provenance); D116
//! (`SpoolOverflow` visible-loss marker). No new D-number is minted here.
//!
//! License: OSS — Apache-2.0 (D25/D15; LOG-1 events are data-plane and open).

#![forbid(unsafe_code)]

pub mod event;
pub mod flow;
pub mod provenance;
pub mod quic_reject_counter;
pub mod scrub;
pub mod spool;

// The conventions an emitter touches at every site, hoisted for a one-line use.
pub use event::{EventEnvelope, EventKind, EventSink, NullSink};
pub use flow::{FlowLifecycle, FlowRecord, Proto};
pub use provenance::{Provenance, ProvenanceError};
pub use quic_reject_counter::{QuicRejectCounter, QuicRejectSnapshot, QUIC_REJECT_REASON};
pub use scrub::{Fingerprint, Fingerprinter, Secret};
pub use spool::{LossOrigin, Spool, SpoolBounds, SpoolOverflow, SpoolSink};
