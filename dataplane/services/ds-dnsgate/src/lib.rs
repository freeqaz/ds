//! ds-dnsgate — the DNS gating proxy (doc 09 §4; component contract in doc 11).
//!
//! # Pre-stage status (NOT DNS-1 complete)
//!
//! This crate is the **hickory framework-validation pre-stage** for the DNS gate.
//! It stands up the real engine — hickory-server / hickory-resolver 0.26.x, pinned
//! and vendored (D67) — on a PLAIN tokio binary (not Pingora), behind a minimal
//! stub policy hook, and exercises the documented DNS-1 framework questions (doc 11
//! §3.4): TCP listener timeouts, concurrent-connection behavior, TC-bit truncation
//! thresholds, EDNS buffer-size interaction, and UDP/TCP parity. The measured
//! thresholds are recorded in the README findings section and asserted by the
//! `tests/framework_validation.rs` harness.
//!
//! On top of that framework validation the pre-stage runs the doc 11 §2/§8.1 upstream
//! forward with internal CNAME following, the §3.3 AAAA/HTTPS/SVCB record scrub (AAAA
//! fast-NODATA + bundled-RR stripping, D70/D75), the D71 authored-SOA negative shape with
//! a boundary-zone-derived MNAME, and the §5.5 LOG-1 [`DnsEvent`] surface ([`event`]) —
//! one event with POL-3 provenance on every query path (§6.7), to a [`NullSink`] default.
//!
//! The §5.5 event surface now COLLAPSES its convention layer onto `ds-telemetry` (doc 14
//! §6, the one LOG-1 emitter): [`EventEnvelope`] / [`TelemetryEventSink`] / [`Provenance`]
//! are `pub use`d from `ds-telemetry` in place of a private re-mirror, while the rich
//! LOG-1 `DnsEvent` SCHEMA stays service-internal (the field set is the later `ds-contracts`
//! Stage-0 freeze). [`TelemetrySink`] adapts the production `ds_telemetry::SpoolSink` into
//! the gate's `DnsEvent` sink, so [`spawn_gate_with_sink`] wires the real disk-bounded,
//! visible-loss spool (D116) with the handler emission sites unchanged in shape (doc 11
//! §5.5: replace the type and the sink impl, never the sites).
//!
//! The verdict ceiling is no longer `StubVerdict::Allow`: the [`policy`] module now lands
//! the frozen doc 11 §4 admission seam — `evaluate([`DnsQueryCtx`]) -> [`Verdict`] ∈
//! {Allow{admit, ttl_clamp}, Deny{rcode_policy}, Ask{prompt_ref}}`, every arm carrying
//! POL-3 provenance. [`PolicyCorePolicy`] wires `policy-core`'s PUBLIC consumer surface
//! (`dns_admission_decision`) as the evaluator (POL-3: no rule reimplemented); the handler
//! maps Deny → the §3.2 NXDOMAIN+authored-SOA shape and Ask → REFUSED + the Stage-0
//! ask-user seam. The always-`Allow` [`FixedStubPolicy`] remains the default the framework
//! / forwarder / suppression harnesses and `main` run with (they validate the listener and
//! scrub against synthetic names no shipped pack lists).
//!
//! The [`attrib`] module lands the §5.1 / W6 interface-anchored session-attribution
//! step as a pure function: the never-recycled tap name is the authoritative join key,
//! the 14-bit D76 mark index is a disambiguator only (with a monitored wrap alarm), and
//! the src-IP single-listener shortcut is REFUSED unless the NFT-2 three-keys-must-agree
//! drop precondition is asserted (D44). It is engine-agnostic and pure given the NFT-2
//! contract, and it is now LIVE-WIRED into the handler: when an [`attrib::AttributionTable`]
//! is wired (via `StubRequestHandler::with_attribution_local` / `_per_tap`), `query_ctx`
//! derives [`DnsQueryCtx::session`] through `attribute_local` (single-listener post-NAT
//! local-address) or `attribute_per_tap` (per-tap bind) — NEVER the raw source IP — and
//! FAILS CLOSED to SERVFAIL (a genuine ds-dnsgate failure per W1/§3.2, never a policy
//! NXDOMAIN) on an unknown interface. The frozen [`DnsQueryCtx`] shape is unchanged; only
//! how `session` is computed moved. The recorded-source `src:<addr>` token is now the
//! pre-stage FALLBACK only — kept where no table is wired (the framework / forwarder /
//! suppression harnesses dial from arbitrary loopback sources with no tap registry).
//!
//! What this still does **not** do (DNS-1+ work, out of scope): the W1/W2 insert-then-answer
//! transaction, the single shared deadline (W2/D68), full-admission-on-every-answer (W3),
//! the population of the [`attrib`] table from the orchestrator tap registry in `main`
//! (D44/D66 — the table is live-wired into the handler and fail-closed-tested, but the
//! production `main` still serves with the pre-stage fallback until the NFT-2 redirect /
//! per-session tap registry is plumbed), nft / DNS-2b map writes, and the `ds-contracts`
//! LOG-1 Stage-0 schema freeze (the `DnsEvent` here is service-internal, not that proto).
//! The verdict SHAPE is frozen; the admission transaction behind `Allow{admit}` is the
//! later `txn/` seam, and `main` must not claim DNS-1 done.
//!
//! The [`warm_restart`] module lands the OQ2 warm-restart REBUILD skeleton (OQ2 rebuild
//! posture, maintainer ruling 2026-06-14 — proposed D131, pending §6 ratification): on a
//! (simulated) restart the [`warm_restart::Reconstructor`] rebuilds the §5.2 DNS-2b map
//! from a SYNTHETIC kernel NFT-3 set dump (`TODO(seam: ds-nft kernel dump)`) plus a
//! SYNTHETIC §5.5 `DnsEvent` spool replay (`TODO(seam: spool replay)`), inserting each
//! substantiated `(session, fqdn)` entry through the FROZEN DNS-2b API and reusing the
//! [`txn::InMemoryAdmissionMap`] machinery. It encodes (a) W2 lockstep (the rebuilt
//! `expires_at` is ADOPTED from the kernel deadline, never recomputed), (b) refcount
//! correctness (the day-one reverse index counts a shared-CDN IP at refcount N), and
//! (c) fail-closed-on-lossy-provenance (an unsubstantiated kernel IP is OMITTED, never
//! fabricated — TLS-1 re-admits it live). The `SO_REUSEPORT` overlap-bind handoff (doc 11
//! §8.2) that pairs with rebuild is OUT OF SCOPE — a `TODO(seam)` doc-note only.
//!
//! The two trait seams now have PRODUCTION bodies in [`warm_restart_live`] (D131
//! ratified 2026-06-16 as tolerate-then-preserve; this reconstruct path is the
//! ratified *fallback* tier): [`NftKernelDump`] is a real `KernelDumpSource` over a
//! live `nft -j list set` read (the index↔uuid bridge is a caller-provided
//! [`ds_contracts::session::SessionRef`] roster; each element's deadline is ADOPTED
//! from the kernel's remaining timeout — W2 lockstep), and [`SpoolSegmentReplay`] is
//! a real `SpoolReplaySource` that inverse-parses a durable on-disk §5.5 spool
//! segment. Both are behind the `DS_WARM_RESTART_LIVE=1` env gate
//! ([`warm_restart_live::LIVE_ENV`]); the synthetic [`KernelSetDump`] /
//! [`SpoolReplayCorpus`] fixtures stay the LOOPBACK/SYNTHETIC defaults so CI/offline
//! stays green. NOTE (honest gaps, detailed in [`warm_restart_live`]): the DnsEvent
//! spool format carries no `session_uuid`/`admitted_ips` (the D131 "pure audit log"
//! demotion — the live, load-bearing reconstruct input is the kernel dump), and
//! `ds_telemetry::spool::Spool::open` truncates its segment on open (so the
//! spool-replay fallback is not durable until that is fixed in `ds-telemetry`).
//!
//! # D67 boundary discipline
//!
//! hickory is a LIBRARY here. Hickory wire types live only behind [`handler`]; the
//! cross-service-shaped policy seam ([`policy`]) is hickory-free, so the documented
//! raw-tokio fallback (doc 11 §2) stays a library migration, not a contract change.

pub mod apply;
pub mod ask;
pub mod attrib;
pub mod event;
pub mod handler;
pub mod policy;
pub mod reresolve;
pub mod server;
pub mod sweep;
pub mod txn;
pub mod warm_restart;
pub mod warm_restart_live;

pub use ask::{
    AskPosture, AskUserRequest, AskUserSink, CapturingAskSink, NullAskSink, RESOURCE_KIND_DOMAIN,
};
pub use attrib::{
    AttributionError, AttributionMode, AttributionTable, MarkIndex, SessionAttribution,
};
pub use event::{
    AaaaOnly, CapturingSink, DeferralReason, DnsEvent, EventEnvelope, EventKind, EventPath,
    EventProvenance, EventSink, NullSink, Provenance, ProvenanceError, TelemetryEventSink,
    TelemetrySink,
};
pub use policy::{
    Admit, DnsQueryCtx, FixedStubPolicy, PolicyCorePolicy, PolicyHook, PromptRef, RcodePolicy,
    SeamProvenance, TtlClamp, Verdict,
};
pub use reresolve::{
    request_over_uds, reresolve_endpoint, serve_reresolve, AdmissionReResolver, ReResolveRequest,
    ReResolveResolved, ReResolveResponse, ReResolveSeam, ReResolver, DEFAULT_RERESOLVE_ENDPOINT,
    RERESOLVE_ENDPOINT_ENV,
};
pub use server::{spawn_gate, spawn_gate_with_sink, GateConfig, RunningGate};
pub use sweep::{sweep_revocations, SweepReport};
pub use warm_restart::{
    GapReason, KernelDumpSource, KernelElement, KernelSetDump, ProvenanceGap, RebuildReport,
    Reconstructor, SpoolRecord, SpoolReplayCorpus, SpoolReplaySource,
};
pub use warm_restart_live::{
    live_enabled, NftKernelDump, SpoolSegmentReplay, DEFAULT_FILTER_TABLE, LIVE_ENV,
};
