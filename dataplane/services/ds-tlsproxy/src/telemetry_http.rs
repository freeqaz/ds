//! TLS-3 per-request HTTP telemetry — the LOG-1 `EventHTTP` + `EventError`
//! event SHAPES the now-terminated, HTTP-visible inspected path emits (doc 12
//! §3 / §5.5 / §10 / §13.1; doc 09 §5 TLS-3 done-when; D17/D82/D73).
//!
//! # What this is
//!
//! Once TLS-3 terminates the VM's TLS (the [`crate::ca`] per-session CA mints the
//! leaf the VM sees) the proxy can read the cleartext HTTP exchange — that is the
//! whole point of inspection: HTTP-level policy + telemetry (TLS-5/6/7 stack on
//! it). doc 09 §5 TLS-3 done-when requires the proxy conformance suite to see
//! "request/response metadata in telemetry"; the boundary executable spec
//! (`boundary/tlsproxy/tlsproxy_inspect_test.go`, D26) pins the exact shape:
//!
//! - **TLS-3.a** — `requireEvent(EventHTTP, "GET", domain, "/data", "200")`: an
//!   `HttpEvent` whose serialized fields carry the request method, the origin
//!   host, the request path, and the response status.
//! - **TLS-3.b** — `requireEvent(EventError, domain)`: on an upstream WebPKI
//!   refusal (the §13.5 "upstream WebPKI fail → REFUSE" row), an `ErrorEvent`
//!   carrying the origin domain + a stable reason CODE.
//!
//! This module is the framework-agnostic core that builds those two event shapes
//! from already-parsed primitives. It mirrors [`crate::explicit::RequestTelemetry`]
//! exactly: a local, pingora-free event SHAPE keyed on the
//! [`ds_contracts::session::SessionRef`] tap name (LOG-2 attribution) and carrying
//! the mandatory POL-3 provenance triple (rule 4 — every emitted event cites the
//! rule id / layer / version). `main.rs` does the pingora-side parsing and feeds
//! these constructors plain values; the §10 emitter owns the wire/spool.
//!
//! # Why a local shape and not a `ds-contracts` import
//!
//! doc 12 §13.1 names "the §5.5 / `ds-contracts` event types" as the surface every
//! module inward of pingora speaks. The generated LOG-1 protos do NOT yet exist in
//! `ds-contracts` (the Stage-0 freeze under its `src/gen/` is undelivered — its
//! `lib.rs` says so explicitly). So, exactly as [`crate::explicit::RequestTelemetry`]
//! does for the TLS-2 per-request record, we define the event SHAPE locally here.
//! **Migration note:** when the LOG-1 Stage-0 freeze lands, [`HttpEvent`] /
//! [`HttpErrorEvent`] migrate onto the generated `ds-contracts` `EventHTTP` /
//! `ErrorEvent` types; the field set chosen here is the boundary's, so the swap is
//! mechanical.
//!
//! # Never-log-the-secret (D73 §5.1) — a TYPE-LEVEL property
//!
//! These structs hold ONLY `String` / `u16` / enum fields enumerated below: there
//! is no `body`, no `bytes`, no `Secret`, no header-value map. The convention
//! TLS-5 / TLS-7 rely on (an event NEVER carries a client-payload / credential
//! byte) is enforced by the shape itself, not by a scrub pass — a
//! `#[cfg(test)]` canary additionally greps every field for a planted payload and
//! asserts zero hits.
//!
//! # D40 pingora confinement (doc 12 §13.1)
//!
//! No pingora type appears here. `main.rs` extracts the request line + response
//! status off the terminated stream and passes plain values; the pingora
//! `TlsAccept` / `ServerApp` wiring stays in the bin.

#![forbid(unsafe_code)]

use std::fmt;

use ds_contracts::session::SessionRef;

use crate::reoriginate::ReoriginateError;

/// The POL-3 provenance triple carried on every emitted event (rule 4 — a
/// missing-provenance event is a spec failure). The SAME shape
/// [`crate::explicit::RequestTelemetry`] carries off the shared `policy-core`
/// decision, and the boundary `Provenance{RuleID, PolicyLayer, PolicyVersion}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// The matched rule id off the shared decision.
    pub rule_id: String,
    /// The composing policy layer.
    pub policy_layer: String,
    /// The policy version in force.
    pub policy_version: String,
}

impl Provenance {
    /// Build a provenance triple from its three parts (the values `main.rs`
    /// reads off the shared `policy-core` decision that admitted the flow).
    pub fn new(
        rule_id: impl Into<String>,
        policy_layer: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Provenance {
        Provenance {
            rule_id: rule_id.into(),
            policy_layer: policy_layer.into(),
            policy_version: policy_version.into(),
        }
    }
}

/// A per-request LOG-1 `EventHTTP` record (doc 12 §5.5 / §10; doc 09 §5 TLS-3),
/// built over the cleartext HTTP exchange the inspected (terminated) path can
/// read. The field set is EXACTLY what the boundary TLS-3.a assertion
/// (`requireEvent(EventHTTP, "GET", domain, "/data", "200")`) requires to appear
/// in the serialized event fields, plus the LOG-2 attribution key (`tap_name`)
/// and the mandatory POL-3 provenance triple.
///
/// Never-log-the-secret (D73): the only fields are the method, host, path,
/// status, tap name, and provenance — all `String` / `u16`. There is no header
/// value, no body, no credential byte; the boundary's leak canary cannot find a
/// payload byte here because the shape carries none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpEvent {
    /// The never-recycled session join key (doc 14 §4) — the `dstap-<idx>` tap
    /// name (LOG-2 attribution key).
    pub tap_name: String,
    /// The HTTP request method (e.g. `GET`).
    pub method: String,
    /// The origin host the request is bound for (the SNI / `Host` on the
    /// terminated stream — the policy/attribution key, NOT the request-line
    /// target, which on the inspected path is origin-form).
    pub host: String,
    /// The request path (origin-form request target, e.g. `/data`).
    pub path: String,
    /// The response status. `0` models the request-only direction (no response
    /// observed yet) so a request can be emitted before its response lands.
    pub status: u16,
    /// The mandatory POL-3 provenance triple (rule 4).
    pub provenance: Provenance,
}

impl HttpEvent {
    /// Build an `HttpEvent` from a terminated-stream exchange: the parsed request
    /// `method` + `path`, the origin `host` (off the SNI / `Host` header), the
    /// response `status` (`0` if no response yet), the `session` (for the LOG-2
    /// tap name), and the POL-3 `provenance`.
    pub fn from_exchange(
        session: &SessionRef,
        method: impl Into<String>,
        host: impl Into<String>,
        path: impl Into<String>,
        status: u16,
        provenance: Provenance,
    ) -> HttpEvent {
        HttpEvent {
            tap_name: session.tap_name.clone(),
            method: method.into(),
            host: host.into(),
            path: path.into(),
            status,
            provenance,
        }
    }

    /// Whether a response status has been observed (a non-zero status). The
    /// request-only direction emits with `status == 0` and this returns `false`.
    pub fn has_response(&self) -> bool {
        self.status != 0
    }
}

/// A LOG-1 `EventError` record for an upstream WebPKI refusal on the
/// re-originated leg (doc 12 §13.5 "upstream WebPKI fail → REFUSE"; boundary
/// TLS-3.b `requireEvent(EventError, domain)`).
///
/// Never-log-the-secret (D73, the convention TLS-5/TLS-7 rely on): the event
/// carries ONLY the origin domain + a stable reason CODE + the tap name +
/// provenance. It NEVER carries the presented cert bytes, the SNI value beyond
/// the domain we asked for, or any client-payload byte — the refusal happens
/// BEFORE any payload byte is written, and the reason code is the secret-free
/// §10 class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpErrorEvent {
    /// The never-recycled session join key (LOG-2 attribution key).
    pub tap_name: String,
    /// The origin domain the re-origination was refused for (the domain we asked
    /// for — what the boundary TLS-3.b asserts appears in the event).
    pub origin_domain: String,
    /// The stable, secret-free reason CODE for the refusal — the §10 error class
    /// (e.g. `tls3-upstream-untrusted-chain`). Sourced from
    /// [`ReoriginateError::reason_code`] so it is single-sourced with the §13.5
    /// error table the re-origination leg owns; never a cert byte.
    pub reason: String,
    /// The mandatory POL-3 provenance triple (rule 4).
    pub provenance: Provenance,
}

impl HttpErrorEvent {
    /// Build an `HttpErrorEvent` for an upstream WebPKI refusal (§13.5). Takes the
    /// `session` (tap name), the `origin_domain` the re-origination targeted, the
    /// [`ReoriginateError`] whose stable [`ReoriginateError::reason_code`] is
    /// recorded as the secret-free reason class, and the POL-3 `provenance`.
    ///
    /// Only the reason CODE is read off the error — never the underlying
    /// `io::Error` message (which could in principle echo address detail), so the
    /// event stays a fixed, secret-free class.
    pub fn upstream_refused(
        session: &SessionRef,
        origin_domain: impl Into<String>,
        error: &ReoriginateError,
        provenance: Provenance,
    ) -> HttpErrorEvent {
        HttpErrorEvent {
            tap_name: session.tap_name.clone(),
            origin_domain: origin_domain.into(),
            reason: error.reason_code().to_string(),
            provenance,
        }
    }
}

/// A loggable credential FINGERPRINT — the secret-free stand-in a TLS-5 event
/// carries in place of a credential value (doc 12 §5.1 type-level scrubbing;
/// LOG-5 "fingerprint, never the credential"; boundary `Credential.Fingerprint`).
///
/// This is the ONLY credential-derived datum any event holds. It is a stable,
/// non-reversible identifier the secret store / Identity assigns (e.g.
/// `fp-long-github`) — NOT a hash of the live bytes computed here, and NEVER the
/// bytes themselves. The type wraps a plain `String` so it formats/serializes
/// freely; the never-log-the-secret property holds because the value placed in it
/// is, by construction, the fingerprint the upstream contract supplies — the
/// credential value is wrapped in a separate, non-`Display` zeroizing newtype
/// ([`crate::swap::FetchedCredential`] / [`crate::swap::PresentedCredential`])
/// that this type can never be built from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Wrap a credential fingerprint (the loggable, secret-free identifier the
    /// upstream contract supplies). The caller is responsible for passing a
    /// fingerprint and never a credential byte — the credential value lives in a
    /// distinct zeroizing newtype that has no path into this constructor.
    pub fn new(fingerprint: impl Into<String>) -> Fingerprint {
        Fingerprint(fingerprint.into())
    }

    /// The fingerprint string (for the §10 event field / wire encoding).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A per-swap LOG-5 `CredentialUseEvent` (doc 12 §5.1 / §5.5 / §10; doc 09 §5
/// TLS-5 "which session used which key, when, for what request"; boundary
/// `EventCredentialUse`). Emitted when the executor's back half SUBSTITUTES a
/// fetched long-lived credential into the upstream request: it records WHICH
/// session used WHICH service credential (by fingerprint) for WHAT request, and
/// WHEN — the attribution trail for the M1 credential swap.
///
/// # Type-level scrubbing (doc 12 §5.1) — the lib-side scrub core
///
/// Both credential values — the short-lived placeholder the VM presented AND the
/// long-lived secret fetched from the D39 store — are absent from this shape by
/// CONSTRUCTION. The only credential-derived field is the [`Fingerprint`]
/// (loggable, secret-free); every other field is request metadata (`String` /
/// `u16`) or the LOG-2 tap name / POL-3 provenance. There is no `Value`, no
/// `Secret`, no `PresentedCredential`, no `FetchedCredential`, and no header-value
/// map — so this shape carries no credential byte for a log path to leak. A
/// `#[cfg(test)]` canary greps every field for both planted credential needles and
/// asserts zero hits — that structural scrubbing is the genuinely-delivered
/// evidence here.
///
/// This is the lib-side scrub core the future conformance-adapter wiring will
/// build on; it is NOT, on its own, the boundary headline. The end-to-end
/// canary-absence row (`TestSwap_LeakAbsence_AllVMSurfaces_HeadlineCanaryGrep` /
/// `TestSwap_EveryLogPathScrubbed_FingerprintOnly`) exercises the live `main.rs`
/// wiring, the actual upstream substitution onto the request, the VM-bound
/// `ResponseScrubber`, and the proxy-generated 502 page — none of which land in
/// this unit; that boundary row stays RED until those land.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialUseEvent {
    /// The never-recycled session join key (LOG-2 attribution — WHICH session).
    pub tap_name: String,
    /// The service the credential was used for (the registry `service` key, e.g.
    /// `github` — WHICH service's key).
    pub service_id: String,
    /// The loggable, secret-free credential fingerprint (LOG-5 — never the value).
    pub fingerprint: Fingerprint,
    /// The HTTP request method the swap fired on (e.g. `GET`, `POST`).
    pub method: String,
    /// The origin host the swapped request targeted (e.g. `api.github.com`).
    pub host: String,
    /// The request path (origin-form request target, e.g. `/git-receive-pack` —
    /// FOR WHAT request).
    pub path: String,
    /// The mandatory POL-3 provenance triple (rule 4) — the swap-rule decision
    /// that authorized this credential use.
    pub provenance: Provenance,
}

impl CredentialUseEvent {
    /// Build a `CredentialUseEvent` for a fired swap. Takes the `session` (tap
    /// name), the `service_id`, the credential `fingerprint` (the secret-free
    /// LOG-5 identifier — NEVER a value), the request `method` / `host` / `path`,
    /// and the POL-3 `provenance`.
    ///
    /// The constructor takes a [`Fingerprint`], not raw bytes — the type system
    /// makes it impossible to pass a credential value where a fingerprint is
    /// expected (the credential lives in a distinct zeroizing newtype with no
    /// conversion into `Fingerprint`).
    #[allow(clippy::too_many_arguments)]
    pub fn fired(
        session: &SessionRef,
        service_id: impl Into<String>,
        fingerprint: Fingerprint,
        method: impl Into<String>,
        host: impl Into<String>,
        path: impl Into<String>,
        provenance: Provenance,
    ) -> CredentialUseEvent {
        CredentialUseEvent {
            tap_name: session.tap_name.clone(),
            service_id: service_id.into(),
            fingerprint,
            method: method.into(),
            host: host.into(),
            path: path.into(),
            provenance,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The LOG-1 telemetry channel (the `ds-telemetry` EventSink seam, doc 09 §7 /
// doc 12 §5.5 / §10) — the single egress every emitted event flows through.
//
// The generated LOG-1 `EventSink` proto is NOT yet frozen into `ds-contracts`
// (the Stage-0 freeze under its `src/gen/` is undelivered — its `lib.rs` says
// so). So, exactly as [`HttpEvent`] / [`CredentialUseEvent`] define their
// SHAPES locally here, the emission SEAM is a local trait mirroring the
// boundary `EventSink.Emit(ctx, Event)` (`boundary/tlsproxy/tlsproxy.go` /
// `boundary/flowlog/flowlog.go` `Collector.Ingest`). `main.rs` implements it
// over the wired `ds-telemetry` client (whose transport/proto types stay in
// the bin, D40); tests implement it over an in-memory recording fake (the
// boundary `recordingSink` analogue).
//
// **Migration note:** when the LOG-1 Stage-0 freeze lands its generated
// `EventSink`, [`AuditEmitter`] migrates onto it; the method shape chosen here
// is the boundary's, so the swap is mechanical.
// ─────────────────────────────────────────────────────────────────────────────

/// The LOG-1 telemetry channel for LOG-5 [`CredentialUseEvent`] emission (doc 09
/// §7 LOG-5; doc 12 §5.5 / §10; boundary `EventSink.Emit`). This is the single
/// egress the per-swap audit record flows through — the executor builds the
/// event (fingerprint-only, secret-free by construction) and hands it to this
/// seam, which owns the spool/wire (the §10 emitter's residual).
///
/// The event is borrowed (`&CredentialUseEvent`) — the emitter serializes it and
/// must not retain it past the call. The trait is the precise analogue of the
/// boundary `EventSink.Emit(ctx, Event) error`: production implements it over
/// the wired `ds-telemetry` client in `main.rs` (D40 — no transport type leaks
/// into the lib), tests over an in-memory recording fake.
///
/// Never-log-the-secret (D73) is upheld by the SHAPE, not this seam: a
/// [`CredentialUseEvent`] carries only the fingerprint + request metadata, so an
/// emitter — however it serializes — has no credential byte to leak.
pub trait AuditEmitter {
    /// Emit one LOG-5 [`CredentialUseEvent`] onto the LOG-1 channel. Borrows the
    /// event; the emitter must not retain it. Errors are the emitter's concern
    /// (spool pressure, transport) — the swap path's audit obligation is to
    /// HAND OFF the event exactly once, which [`crate::swap::PendingCredentialUse`]
    /// makes structural.
    fn emit_credential_use(&self, event: &CredentialUseEvent);
}

// ─────────────────────────────────────────────────────────────────────────────
// LOG-1 NETFLOW telemetry — the proxy-side per-flow `FlowEvent` / `FlowStartEvent`
// SHAPES with admitting-DNS-name attribution (doc 03 §4; doc 09 §7 LOG-1/LOG-2;
// doc 12 §5.5 / §10; D43). The proxy is the SYSTEM OF RECORD for netflow-style
// metadata (D43): per-flow source/destination, duration, bytes transferred, and
// protocol — *associated with the DNS name that admitted the flow*.
//
// These shapes are the proxy-side analogue of the boundary LOG-1 `FlowRecord`
// (`boundary/flowlog/flowlog.go`): the boundary `FlowRecord` is the kernel-join
// shape ds-flowlog produces over conntrack + the DNS-2 admission index; this is
// the proxy's own per-flow record (the proxy is the netflow system of record,
// D43), emitted onto the LOG-1 channel and reconciled against the kernel ledger
// (doc 03 §4 "the assurance suite reconciles the two").
//
// **No HTTP, no payload (D73).** Per doc 03 §4 the netflow shape captures
// metadata, NOT traffic ("full packet capture is explicitly out"): there is no
// method/host/path/status field (that is [`HttpEvent`]'s domain) and — crucially
// — NO body, NO header value, NO captured-byte field. Never-log-the-secret is a
// TYPE-LEVEL property exactly as it is for [`HttpEvent`]: the shape carries only
// L3/4 metadata + the admitting domain + the LOG-2 attribution quartet, so a
// payload byte structurally cannot reach a `FlowEvent`.
//
// **Migration note:** when the LOG-1 Stage-0 freeze lands its generated
// `FlowRecord` in `ds-contracts`, [`FlowEvent`] migrates onto it; the field set
// chosen here is the boundary's, so the swap is mechanical.
// ─────────────────────────────────────────────────────────────────────────────

/// The L4 protocol of a flow (doc 03 §4 "protocol"; boundary `flowlog.Proto`).
/// Modelled as a small enum mirroring the boundary `Proto` (the IANA protocol
/// numbers the kernel ledger uses) rather than a bare `u8`, so the netflow shape
/// is type-checked at construction and the secret-free wire value is single-
/// sourced via [`FlowProto::number`]. The wildcard `Other(u8)` carries any other
/// IANA number verbatim for forward-compatibility (still a plain value — never a
/// payload byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowProto {
    /// ICMP (IANA 1).
    Icmp,
    /// TCP (IANA 6) — the proxy's own flows.
    Tcp,
    /// UDP (IANA 17).
    Udp,
    /// Any other IANA L4 protocol number.
    Other(u8),
}

impl FlowProto {
    /// The IANA protocol number (the secret-free wire value; the SAME numbering
    /// the boundary `flowlog.Proto` / the conntrack ledger carries, so the
    /// LOG-4 reconciler joins on one value).
    pub fn number(self) -> u8 {
        match self {
            FlowProto::Icmp => 1,
            FlowProto::Tcp => 6,
            FlowProto::Udp => 17,
            FlowProto::Other(n) => n,
        }
    }

    /// Build a `FlowProto` from an IANA protocol number (the value `main.rs`
    /// reads off the established flow). The three named protocols round-trip to
    /// their variants; any other number is preserved as [`FlowProto::Other`].
    pub fn from_number(n: u8) -> FlowProto {
        match n {
            1 => FlowProto::Icmp,
            6 => FlowProto::Tcp,
            17 => FlowProto::Udp,
            other => FlowProto::Other(other),
        }
    }
}

/// The kernel disposition of a closed flow (doc 03 §4; boundary
/// `flowlog.FlowVerdict`). Mirrors the boundary `FlowVerdict` string enum
/// (`accepted` / `dropped`) so the LOG-4 reconciler joins the proxy's per-flow
/// record to the kernel conntrack ledger on one value. An inspected (terminated +
/// re-originated) flow that reached an upstream connection is [`FlowVerdict::Accepted`];
/// a flow torn down before it forwarded a byte (a fail-closed refusal) is
/// [`FlowVerdict::Dropped`]. A plain enum — never a payload byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowVerdict {
    /// The flow was accepted — bytes forwarded (the boundary `accepted`).
    Accepted,
    /// The flow was dropped — never forwarded (the boundary `dropped`).
    Dropped,
}

impl FlowVerdict {
    /// The stable, secret-free wire string the §10 record carries (the SAME
    /// value the boundary `flowlog.FlowVerdict` uses, so the LOG-4 reconciler
    /// joins on one token).
    pub fn as_str(self) -> &'static str {
        match self {
            FlowVerdict::Accepted => "accepted",
            FlowVerdict::Dropped => "dropped",
        }
    }
}

/// A LOG-1 NETFLOW `FlowEvent` — the proxy's per-flow record over an
/// established (and now closed/accounted) flow (doc 03 §4; doc 09 §7 LOG-1;
/// D43). Carries the LOG-2 session attribution quartet (the
/// [`ds_contracts::session::SessionRef`] fields), the admitting DNS name joined
/// from the DNS-2 event stream, the L3/4 metadata (src/dst address + port +
/// protocol), the byte counters in both directions, and the flow's start
/// timestamp.
///
/// # Field set (boundary LOG-1 `FlowRecord` parity)
///
/// The fields are EXACTLY the netflow datum doc 03 §4 names — source/destination,
/// duration (via the start timestamp + byte counters), bytes transferred,
/// protocol — *associated with the admitting DNS name* — plus the LOG-2
/// attribution quartet, a high-resolution start timestamp, and the mandatory
/// POL-3 provenance triple (rule 4 — the boundary `Event.Provenance` parity).
/// There is NO HTTP-level field (`method`/`host`/`path`/`status` live on
/// [`HttpEvent`]) and — by construction — NO payload field: doc 03 §4 makes full
/// packet capture explicitly out, so this shape carries metadata only.
///
/// # Never-log-the-secret (D73 §5.1) — a TYPE-LEVEL property
///
/// Every field is a plain value: `String` (the attribution quartet + admitting
/// domain + the POL-3 provenance triple), [`std::net::IpAddr`] / `u16` (the L3/4
/// endpoints), [`FlowProto`], `u64` (the byte counters + the nanosecond
/// timestamp). There is no `body`, no
/// `Vec<u8>`, no `Secret`, no header map — so a client-payload / credential byte
/// structurally cannot ride along (the convention LOG-5 / TLS-7 rely on). A
/// `#[cfg(test)]` canary additionally greps every string field for a planted
/// payload and asserts zero hits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowEvent {
    /// The orchestrator session UUID — the global identity (LOG-1 attribution).
    pub session_uuid: String,
    /// The never-recycled `dstap-<idx>` tap name — the authoritative LOG-2
    /// attribution / join key (doc 14 §4).
    pub tap_name: String,
    /// The host-local session index (the 14-bit residue rides the mark, doc 14
    /// §4).
    pub host_session_index: u32,
    /// The DNS name that ADMITTED this flow, joined from the DNS-2 event stream
    /// (doc 03 §4 "associated with the DNS name that admitted the flow"; LOG-2
    /// admitting-domain join). Empty models a flow with no resolvable admitting
    /// domain (it is flagged for reconciliation, never falsely joined — mirrors
    /// the boundary `AdmittingDomain == ""` row).
    pub admitting_domain: String,
    /// The flow's source IP address (the session VM side). An L3 datum, never an
    /// attribution input (addresses are forgeable; `tap_name` is the key).
    pub src_addr: std::net::IpAddr,
    /// The flow's source port.
    pub src_port: u16,
    /// The flow's destination IP address (the upstream peer).
    pub dst_addr: std::net::IpAddr,
    /// The flow's destination port.
    pub dst_port: u16,
    /// The L4 protocol (the IANA-numbered [`FlowProto`]).
    pub protocol: FlowProto,
    /// Bytes transmitted by the session VM (the conntrack originator / egress
    /// direction — the boundary `BytesOut`).
    pub bytes_tx: u64,
    /// Bytes received by the session VM (the reply direction — the boundary
    /// `BytesIn`).
    pub bytes_rx: u64,
    /// The flow's start time as nanoseconds since the Unix epoch (a plain `u64`,
    /// not a framework `Instant`/`SystemTime` — the bin reads the clock and
    /// feeds this value, so the lib stays clock-free and pingora-free). The
    /// boundary `FlowRecord.Start`.
    pub timestamp_nanos: u64,
    /// The flow's END time as nanoseconds since the Unix epoch (the boundary
    /// `FlowRecord.End`) — when the connection closed. On a closing record this
    /// is `>= timestamp_nanos`; the bin reads the clock at close and feeds the
    /// value (the lib stays clock-free).
    pub end_time_nanos: u64,
    /// The flow's duration in nanoseconds (the boundary `FlowRecord.Duration`) —
    /// `end_time_nanos.saturating_sub(timestamp_nanos)`, computed by the
    /// [`FlowEvent::over_flow`] constructor so the two timestamps and the duration
    /// can never drift apart. "How long was the session open" (doc 03 §4).
    pub duration_nanos: u64,
    /// The D76 upstream-leg `SO_MARK` this flow's re-originated socket carried
    /// (`compose(Leg::TlsproxyUpstream, host_session_index)`) — the boundary
    /// `FlowRecord.CtMark`, the kernel connection mark KEYED TO the session
    /// attribution (the same 14-bit index the `tap_name` encodes). The LOG-4
    /// reconciler joins the proxy's record to the conntrack ledger on this mark.
    /// A plain `u32`, never a payload byte.
    pub ct_mark: u32,
    /// The flow's kernel disposition (the boundary `FlowRecord.Verdict`) —
    /// [`FlowVerdict::Accepted`] for a flow that reached a validated upstream and
    /// forwarded, [`FlowVerdict::Dropped`] for a fail-closed teardown.
    pub verdict: FlowVerdict,
    /// The mandatory POL-3 provenance triple (rule 4 — a missing-provenance
    /// event is a spec failure). Carried on EVERY emitted event, exactly as the
    /// boundary `Event.Provenance` field is first-class on every `Event` kind
    /// (including `EventFlow`), and as the sibling [`HttpEvent`] /
    /// [`HttpErrorEvent`] / [`CredentialUseEvent`] shapes carry it. The triple is
    /// the rule/layer/version off the TLS-1 decision that admitted the flow — a
    /// secret-free key, never a credential or payload byte.
    pub provenance: Provenance,
}

/// Split a [`std::net::SocketAddr`] into the `(addr, port)` pair the netflow
/// shapes store. The constructors take the acceptance's `std::net::SocketAddr`
/// surface; the stored shape splits it so each component is an independently
/// asserted, secret-free field.
fn split_socket_addr(sa: std::net::SocketAddr) -> (std::net::IpAddr, u16) {
    (sa.ip(), sa.port())
}

impl FlowEvent {
    /// Build a `FlowEvent` over an established (and now closed) flow. Takes the
    /// `session` (the LOG-2 attribution quartet), the `admitting_domain` joined
    /// from the DNS-2 stream (empty when none resolves), the `src` / `dst`
    /// endpoints (plain [`std::net::SocketAddr`]), the `protocol`, the
    /// `bytes_tx` / `bytes_rx` counters, the flow `timestamp_nanos` (start) and
    /// `end_time_nanos` (close), the D76 `ct_mark` (the boundary `CtMark`), the
    /// `verdict` (the boundary `FlowVerdict`), and the mandatory POL-3
    /// `provenance` (rule 4 — the triple off the admitting decision).
    ///
    /// The `duration_nanos` is DERIVED here as
    /// `end_time_nanos.saturating_sub(timestamp_nanos)` so the two timestamps and
    /// the duration cannot drift apart (a non-monotonic clock that hands an end
    /// earlier than the start saturates to zero rather than underflowing).
    ///
    /// No HTTP datum and no payload byte can be passed — the signature accepts
    /// only L3/4 metadata + the admitting domain + the session + the provenance,
    /// so the shape is netflow-only by construction (doc 03 §4).
    #[allow(clippy::too_many_arguments)]
    pub fn over_flow(
        session: &SessionRef,
        admitting_domain: impl Into<String>,
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
        protocol: FlowProto,
        bytes_tx: u64,
        bytes_rx: u64,
        timestamp_nanos: u64,
        end_time_nanos: u64,
        ct_mark: u32,
        verdict: FlowVerdict,
        provenance: Provenance,
    ) -> FlowEvent {
        let (src_addr, src_port) = split_socket_addr(src);
        let (dst_addr, dst_port) = split_socket_addr(dst);
        FlowEvent {
            session_uuid: session.session_uuid.clone(),
            tap_name: session.tap_name.clone(),
            host_session_index: session.host_session_index,
            admitting_domain: admitting_domain.into(),
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            protocol,
            bytes_tx,
            bytes_rx,
            timestamp_nanos,
            end_time_nanos,
            // Derived so the (start, end, duration) triple is internally
            // consistent (the boundary `FlowRecord.Duration` parity).
            duration_nanos: end_time_nanos.saturating_sub(timestamp_nanos),
            ct_mark,
            verdict,
            provenance,
        }
    }

    /// Whether an admitting DNS name was joined for this flow (a non-empty
    /// `admitting_domain`). A flow with no resolvable admitting domain returns
    /// `false` and is flagged for reconciliation (doc 03 §4 / LOG-2), never
    /// falsely joined.
    pub fn has_admitting_domain(&self) -> bool {
        !self.admitting_domain.is_empty()
    }
}

/// A LOG-1 NETFLOW `FlowStartEvent` — the proxy emits this when a flow OPENS,
/// before its byte counters are final (doc 03 §4 "how long was the session
/// open"; doc 09 §7 LOG-1). It carries the SAME L3/4 + attribution + admitting-
/// domain metadata as [`FlowEvent`] but NO byte counters (none have accrued
/// yet): the flow-start record lets a query show a flow as OPEN before the
/// closing [`FlowEvent`] lands with the final byte accounting.
///
/// Never-log-the-secret holds identically — only L3/4 metadata + the admitting
/// domain + the attribution quartet + the start timestamp; no payload field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowStartEvent {
    /// The orchestrator session UUID (LOG-1 attribution).
    pub session_uuid: String,
    /// The never-recycled tap name (LOG-2 join key).
    pub tap_name: String,
    /// The host-local session index (doc 14 §4).
    pub host_session_index: u32,
    /// The DNS name that admitted this flow (DNS-2 join; empty when none).
    pub admitting_domain: String,
    /// The flow's source IP address.
    pub src_addr: std::net::IpAddr,
    /// The flow's source port.
    pub src_port: u16,
    /// The flow's destination IP address.
    pub dst_addr: std::net::IpAddr,
    /// The flow's destination port.
    pub dst_port: u16,
    /// The L4 protocol.
    pub protocol: FlowProto,
    /// The flow's start time as nanoseconds since the Unix epoch (the boundary
    /// `FlowRecord.Start`).
    pub timestamp_nanos: u64,
    /// The D76 upstream-leg `SO_MARK` the flow's re-originated socket carried
    /// (`compose(Leg::TlsproxyUpstream, host_session_index)`) — the boundary
    /// `FlowRecord.CtMark`, known at flow-open (the mark is set before connect).
    /// `End`/`Duration`/`Verdict` are NOT on the open record — none of those
    /// exist until the flow closes; the closing [`FlowEvent`] carries them.
    pub ct_mark: u32,
    /// The mandatory POL-3 provenance triple (rule 4) — the same first-class
    /// field the boundary `Event.Provenance` carries on every event kind. The
    /// flow-open record carries it so the closing [`FlowEvent`] is not the only
    /// provenance-bearing half of the pair.
    pub provenance: Provenance,
}

impl FlowStartEvent {
    /// Build a `FlowStartEvent` when a flow opens. Same metadata as
    /// [`FlowEvent::over_flow`] minus the byte counters AND the
    /// end/duration/verdict (a freshly opened flow has none of those yet), plus
    /// the D76 `ct_mark` (known at open — the mark is set before connect) and the
    /// mandatory POL-3 `provenance` (rule 4).
    #[allow(clippy::too_many_arguments)]
    pub fn opened(
        session: &SessionRef,
        admitting_domain: impl Into<String>,
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
        protocol: FlowProto,
        timestamp_nanos: u64,
        ct_mark: u32,
        provenance: Provenance,
    ) -> FlowStartEvent {
        let (src_addr, src_port) = split_socket_addr(src);
        let (dst_addr, dst_port) = split_socket_addr(dst);
        FlowStartEvent {
            session_uuid: session.session_uuid.clone(),
            tap_name: session.tap_name.clone(),
            host_session_index: session.host_session_index,
            admitting_domain: admitting_domain.into(),
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            protocol,
            timestamp_nanos,
            ct_mark,
            provenance,
        }
    }

    /// Whether an admitting DNS name was joined for this flow.
    pub fn has_admitting_domain(&self) -> bool {
        !self.admitting_domain.is_empty()
    }
}

/// The LOG-1 telemetry channel for NETFLOW [`FlowStartEvent`] / [`FlowEvent`]
/// emission (doc 09 §7 LOG-1; doc 03 §4 D43; doc 12 §5.5 / §10; the §10 telemetry
/// channel). The precise analogue of the boundary `EventSink.Emit(ctx, Event)`
/// (`boundary/tlsproxy/tlsproxy.go`) / `flowlog.Collector.Ingest` — the single
/// egress every per-flow record flows through.
///
/// Production implements it over the wired `ds-telemetry` / ds-flowlog client in
/// `main.rs` (D40 — no transport type leaks into the lib); tests implement it
/// over an in-memory recording fake (the boundary `recordingSink` analogue).
///
/// Both events are borrowed (`&FlowStartEvent` / `&FlowEvent`) — the emitter
/// serializes and must not retain. Never-log-the-secret (D73) is upheld by the
/// SHAPES, not this seam: a flow event carries only L3/4 metadata + the
/// admitting domain + the secret-free POL-3 provenance triple, so an emitter —
/// however it serializes — has no payload byte to leak. The mandatory provenance
/// (rule 4) rides ON the event (the boundary `Event.Provenance` parity), so it
/// reaches the production sink structurally rather than as a side channel.
///
/// **Migration note:** when the LOG-1 Stage-0 freeze lands its generated
/// `EventSink`, `AuditFlowEmitter` migrates onto it; the method shapes chosen
/// here are the boundary's, so the swap is mechanical.
pub trait AuditFlowEmitter {
    /// Emit one NETFLOW [`FlowStartEvent`] onto the LOG-1 channel (a flow
    /// opened). Borrows the event; the emitter must not retain it.
    fn emit_flow_start(&self, event: &FlowStartEvent);

    /// Emit one NETFLOW [`FlowEvent`] onto the LOG-1 channel (a flow closed /
    /// was accounted). Borrows the event; the emitter must not retain it. This
    /// is the §10 channel method that mirrors the boundary `EventSink.Emit`.
    fn emit_flow(&self, event: &FlowEvent);
}

/// Parse the first line of an HTTP request (`METHOD SP request-target SP
/// HTTP-version`, RFC 7230 §3.1.1) into `(method, request-target)`.
///
/// TOTAL and bounds-checked: an empty or malformed line (missing either space-
/// delimited field) yields `None` rather than panicking, and NO byte beyond the
/// method + target is retained. The version token is discarded (telemetry keys on
/// method + path, never the wire version). The target is returned verbatim — on
/// the inspected path it is origin-form (`/data`), which is exactly the `path` the
/// boundary TLS-3.a asserts; `main.rs` sources the `host` separately off the SNI /
/// `Host` header (an inspected request line names no host).
pub fn parse_request_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    // A request line MUST carry the HTTP-version third token; its absence is a
    // malformed line. We require it to be present but discard its value.
    parts.next()?;
    if method.is_empty() || target.is_empty() {
        return None;
    }
    Some((method, target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reoriginate::ReoriginateRefuse;

    fn session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    fn provenance() -> Provenance {
        Provenance::new("rule-allow-inspected", "org", "policy-v1")
    }

    // ── request-line parsing (total, no-panic) ──────────────────────────────

    #[test]
    fn parse_request_line_splits_method_and_origin_form_target() {
        // The inspected path sees an origin-form target — exactly the `path` the
        // boundary TLS-3.a asserts (`/data`).
        let (method, target) = parse_request_line("GET /data HTTP/1.1").unwrap();
        assert_eq!(method, "GET");
        assert_eq!(target, "/data");
    }

    #[test]
    fn parse_request_line_tolerates_surrounding_whitespace() {
        let (method, target) = parse_request_line("  POST /x HTTP/1.1\r\n").unwrap();
        assert_eq!(method, "POST");
        assert_eq!(target, "/x");
    }

    #[test]
    fn parse_request_line_rejects_malformed_lines_without_panicking() {
        assert_eq!(parse_request_line(""), None);
        assert_eq!(parse_request_line("   "), None);
        assert_eq!(parse_request_line("GET"), None); // no target, no version
        assert_eq!(parse_request_line("GET /x"), None); // no HTTP-version token
    }

    // ── HttpEvent (boundary TLS-3.a shape parity) ───────────────────────────

    #[test]
    fn http_event_built_over_a_terminated_exchange_carries_method_host_path_status() {
        // The ACCEPTANCE clause: an HttpEvent built over a terminated-stream
        // fixture carries the correct method / host / path / status — the exact
        // four the boundary `requireEvent(EventHTTP,"GET",domain,"/data","200")`
        // asserts appear in the serialized fields (D26 shape parity).
        let s = session(7);
        let (method, path) = parse_request_line("GET /data HTTP/1.1").unwrap();
        let ev = HttpEvent::from_exchange(&s, method, "inspected.example", path, 200, provenance());

        assert_eq!(ev.method, "GET");
        assert_eq!(ev.host, "inspected.example");
        assert_eq!(ev.path, "/data");
        assert_eq!(ev.status, 200);
        assert!(ev.has_response());
        // LOG-2 attribution + mandatory POL-3 provenance.
        assert_eq!(ev.tap_name, "dstap-7");
        assert_eq!(ev.provenance.policy_version, "policy-v1");
        assert!(!ev.provenance.rule_id.is_empty());
    }

    #[test]
    fn http_event_request_only_direction_has_zero_status() {
        // status == 0 models the request before its response lands.
        let s = session(3);
        let ev = HttpEvent::from_exchange(&s, "GET", "x.example", "/", 0, provenance());
        assert_eq!(ev.status, 0);
        assert!(!ev.has_response());
    }

    // ── HttpErrorEvent (boundary TLS-3.b shape parity) ──────────────────────

    #[test]
    fn webpki_refusal_builds_an_error_event_carrying_domain_and_reason_code() {
        // The ACCEPTANCE clause: a forced upstream-validation failure produces an
        // error event carrying the origin domain + a reason CODE. The boundary
        // `requireEvent(EventError, domain)` asserts the domain appears; the reason
        // code is the secret-free §10 class single-sourced from the §13.5 table.
        let s = session(5);
        let err = ReoriginateError::WebPki(ReoriginateRefuse::UntrustedChain);
        let ev = HttpErrorEvent::upstream_refused(&s, "self.example", &err, provenance());

        assert_eq!(ev.origin_domain, "self.example");
        assert_eq!(ev.reason, "tls3-upstream-untrusted-chain");
        assert_eq!(ev.tap_name, "dstap-5");
        assert!(!ev.provenance.policy_version.is_empty());
    }

    #[test]
    fn error_event_reason_is_single_sourced_with_the_reorigination_table() {
        // Every §13.5 WebPKI refusal class maps to its stable reason code — the
        // SAME mapping the re-origination leg owns (never a re-derived string).
        let s = session(2);
        for refuse in [
            ReoriginateRefuse::UntrustedChain,
            ReoriginateRefuse::SelfSigned,
            ReoriginateRefuse::Expired,
            ReoriginateRefuse::HostnameMismatch,
            ReoriginateRefuse::InvalidIntermediate,
            ReoriginateRefuse::MalformedCert,
        ] {
            let err = ReoriginateError::WebPki(refuse);
            let ev = HttpErrorEvent::upstream_refused(&s, "o.example", &err, provenance());
            assert_eq!(ev.reason, refuse.reason_code());
            assert!(ev.reason.starts_with("tls3-upstream-"));
        }
    }

    // ── never-log-the-secret canary (D73 §5.1) ──────────────────────────────

    #[test]
    fn no_event_field_ever_carries_a_client_payload_byte() {
        // Plant a canary that stands in for a client-payload / credential byte and
        // assert it appears in NO field of either event. The shape carries only
        // method/host/path/status (+ tap/provenance) and domain/reason (+ tap/
        // provenance) — there is no body, no header value, no Secret — so a payload
        // byte structurally cannot reach an event (D73, the TLS-5/TLS-7 convention).
        const CANARY: &str = "SECRET-PAYLOAD-CANARY-9f3a2b";
        let s = session(9);

        // Build both events from inputs that do NOT include the canary.
        let http =
            HttpEvent::from_exchange(&s, "GET", "inspected.example", "/data", 200, provenance());
        let err = ReoriginateError::WebPki(ReoriginateRefuse::SelfSigned);
        let error = HttpErrorEvent::upstream_refused(&s, "self.example", &err, provenance());

        // Every String field of the HttpEvent.
        let http_fields = [
            http.tap_name.as_str(),
            http.method.as_str(),
            http.host.as_str(),
            http.path.as_str(),
            http.provenance.rule_id.as_str(),
            http.provenance.policy_layer.as_str(),
            http.provenance.policy_version.as_str(),
        ];
        for f in http_fields {
            assert!(
                !f.contains(CANARY),
                "HttpEvent field leaked a client-payload canary: {f:?}"
            );
        }

        // Every String field of the HttpErrorEvent.
        let error_fields = [
            error.tap_name.as_str(),
            error.origin_domain.as_str(),
            error.reason.as_str(),
            error.provenance.rule_id.as_str(),
            error.provenance.policy_layer.as_str(),
            error.provenance.policy_version.as_str(),
        ];
        for f in error_fields {
            assert!(
                !f.contains(CANARY),
                "HttpErrorEvent field leaked a client-payload canary: {f:?}"
            );
        }
    }

    // ── CredentialUseEvent (LOG-5 / boundary EventCredentialUse shape) ───────

    #[test]
    fn credential_use_event_carries_session_service_fingerprint_request_line() {
        // ACCEPTANCE (3): the CredentialUseEvent carries service_id, the request
        // line (method/host/path), POL-3 provenance, the session tap name, and
        // the fingerprint — the exact fields the boundary `EventCredentialUse`
        // assertions read (`fp-long-github`, session, request).
        let s = session(7);
        let ev = CredentialUseEvent::fired(
            &s,
            "github",
            Fingerprint::new("fp-long-github"),
            "POST",
            "github.com",
            "/org/repo.git/git-receive-pack",
            provenance(),
        );
        assert_eq!(ev.tap_name, "dstap-7");
        assert_eq!(ev.service_id, "github");
        assert_eq!(ev.fingerprint.as_str(), "fp-long-github");
        assert_eq!(ev.method, "POST");
        assert_eq!(ev.host, "github.com");
        assert_eq!(ev.path, "/org/repo.git/git-receive-pack");
        assert_eq!(ev.provenance.policy_version, "policy-v1");
        assert!(!ev.provenance.rule_id.is_empty());
    }

    #[test]
    fn credential_use_event_holds_only_the_fingerprint_never_a_credential_byte() {
        // ACCEPTANCE (2): both the short-lived (presented) and long-lived
        // (fetched) credential values are absent from the event — only the
        // fingerprint appears. Plant BOTH needles and grep every field; the shape
        // carries no credential value by construction (doc 12 §5.1).
        const SHORT: &str = "sl-sess-a-github-SHORTCANARY-1a2b3c";
        const LONG: &str = "ghp_LONGLIVEDCANARY-9f3a2b8c7d6e5f4a3b2c1d";
        let s = session(9);
        // The event is built from the FINGERPRINT, never from either value — the
        // constructor takes a `Fingerprint`, so a value cannot even be passed.
        let ev = CredentialUseEvent::fired(
            &s,
            "github",
            Fingerprint::new("fp-long-github"),
            "GET",
            "api.github.com",
            "/user",
            provenance(),
        );
        let fields = [
            ev.tap_name.as_str(),
            ev.service_id.as_str(),
            ev.fingerprint.as_str(),
            ev.method.as_str(),
            ev.host.as_str(),
            ev.path.as_str(),
            ev.provenance.rule_id.as_str(),
            ev.provenance.policy_layer.as_str(),
            ev.provenance.policy_version.as_str(),
        ];
        for f in fields {
            assert!(
                !f.contains(SHORT),
                "CredentialUseEvent leaked short-lived: {f:?}"
            );
            assert!(
                !f.contains(LONG),
                "CredentialUseEvent leaked long-lived: {f:?}"
            );
        }
        // The fingerprint IS present (LOG-5 attribution must be usable).
        assert_eq!(ev.fingerprint.as_str(), "fp-long-github");
    }

    #[test]
    fn fingerprint_displays_as_its_loggable_value() {
        let fp = Fingerprint::new("fp-long-github");
        assert_eq!(fp.to_string(), "fp-long-github");
        assert_eq!(fp.as_str(), "fp-long-github");
    }

    // ── AuditEmitter seam (the LOG-1 channel) ───────────────────────────────

    /// A recording fake emitter (the boundary `recordingSink` analogue): every
    /// event handed to the LOG-1 channel is captured so a test can prove WHICH
    /// events reached the channel and HOW MANY times.
    #[derive(Default)]
    struct RecordingEmitter {
        seen: std::sync::Mutex<Vec<CredentialUseEvent>>,
    }

    impl AuditEmitter for RecordingEmitter {
        fn emit_credential_use(&self, event: &CredentialUseEvent) {
            self.seen.lock().unwrap().push(event.clone());
        }
    }

    #[test]
    fn audit_emitter_receives_the_credential_use_event_on_the_log1_channel() {
        // The seam carries a fingerprint-only event through to the channel: the
        // recording emitter sees exactly the event the executor built.
        let s = session(7);
        let sink = RecordingEmitter::default();
        let ev = CredentialUseEvent::fired(
            &s,
            "github",
            Fingerprint::new("fp-long-github"),
            "POST",
            "github.com",
            "/org/repo.git/git-receive-pack",
            provenance(),
        );
        sink.emit_credential_use(&ev);

        let seen = sink.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "exactly one event reached the LOG-1 channel");
        assert_eq!(seen[0].service_id, "github");
        assert_eq!(seen[0].fingerprint.as_str(), "fp-long-github");
        assert_eq!(seen[0].tap_name, "dstap-7");
    }

    // ── netflow FlowEvent / FlowStartEvent (boundary LOG-1 FlowRecord shape) ─

    use std::net::SocketAddr;

    fn src() -> SocketAddr {
        "10.0.0.5:51000".parse().unwrap()
    }

    fn dst() -> SocketAddr {
        "203.0.113.10:443".parse().unwrap()
    }

    #[test]
    fn flow_proto_numbers_are_the_iana_values_and_round_trip() {
        // The wire value is single-sourced (the boundary flowlog.Proto numbering:
        // ICMP 1, TCP 6, UDP 17) so the LOG-4 reconciler joins on one value.
        assert_eq!(FlowProto::Icmp.number(), 1);
        assert_eq!(FlowProto::Tcp.number(), 6);
        assert_eq!(FlowProto::Udp.number(), 17);
        assert_eq!(FlowProto::Other(132).number(), 132); // SCTP, e.g.
        for p in [
            FlowProto::Icmp,
            FlowProto::Tcp,
            FlowProto::Udp,
            FlowProto::Other(132),
        ] {
            assert_eq!(FlowProto::from_number(p.number()), p);
        }
    }

    #[test]
    fn flow_event_carries_attribution_l34_admitting_domain_and_byte_counters() {
        // ACCEPTANCE: a FlowEvent built over an established flow carries the
        // session attribution quartet, the admitting DNS name (the DNS-2 join),
        // the L3/4 metadata (src/dst addr+port, protocol), the byte counters in
        // both directions, and the start timestamp — the exact netflow datum
        // doc 03 §4 names, mirroring the boundary LOG-1 FlowRecord field set.
        let s = session(7);
        let ev = FlowEvent::over_flow(
            &s,
            "registry.npmjs.org",
            src(),
            dst(),
            FlowProto::Tcp,
            4096,
            8192,
            1_700_000_000_000_000_000,
            1_700_000_000_500_000_000,
            0xD000_0007,
            FlowVerdict::Accepted,
            provenance(),
        );

        // LOG-2 attribution quartet (the SessionRef fields).
        assert_eq!(ev.session_uuid, "11111111-2222-3333-4444-555555555555");
        assert_eq!(ev.tap_name, "dstap-7");
        assert_eq!(ev.host_session_index, 7);
        // The admitting-DNS-name join (doc 03 §4 / LOG-2).
        assert_eq!(ev.admitting_domain, "registry.npmjs.org");
        assert!(ev.has_admitting_domain());
        // L3/4 metadata.
        assert_eq!(ev.src_addr, src().ip());
        assert_eq!(ev.src_port, 51000);
        assert_eq!(ev.dst_addr, dst().ip());
        assert_eq!(ev.dst_port, 443);
        assert_eq!(ev.protocol, FlowProto::Tcp);
        // Byte counters (BytesOut = tx / egress, BytesIn = rx / reply).
        assert_eq!(ev.bytes_tx, 4096);
        assert_eq!(ev.bytes_rx, 8192);
        // Start / End / Duration (the boundary FlowRecord Start/End/Duration).
        assert_eq!(ev.timestamp_nanos, 1_700_000_000_000_000_000);
        assert_eq!(ev.end_time_nanos, 1_700_000_000_500_000_000);
        // Duration is DERIVED (end - start) so the triple cannot drift.
        assert_eq!(ev.duration_nanos, 500_000_000);
        // CtMark (the D76 upstream-leg mark keyed to the session attribution).
        assert_eq!(ev.ct_mark, 0xD000_0007);
        // Verdict (the boundary FlowVerdict — accepted for a forwarded flow).
        assert_eq!(ev.verdict, FlowVerdict::Accepted);
        // The mandatory POL-3 provenance (rule 4) rides ON the event (boundary
        // Event.Provenance parity), so the production sink receives it.
        assert_eq!(ev.provenance, provenance());
        assert_eq!(ev.provenance.rule_id, "rule-allow-inspected");
    }

    #[test]
    fn flow_event_derives_duration_and_saturates_a_non_monotonic_clock() {
        // The duration is end - start, derived by the constructor so the two
        // timestamps and the duration cannot drift apart. A non-monotonic clock
        // that hands an END earlier than the START saturates to zero rather than
        // underflowing (never a wildly-large bogus duration).
        let s = session(7);
        let forward = FlowEvent::over_flow(
            &s,
            "a.example",
            src(),
            dst(),
            FlowProto::Tcp,
            0,
            0,
            1_000,
            1_750,
            0xD000_0007,
            FlowVerdict::Accepted,
            provenance(),
        );
        assert_eq!(forward.duration_nanos, 750);

        // end < start (a clock that went backwards): saturate to zero.
        let backward = FlowEvent::over_flow(
            &s,
            "a.example",
            src(),
            dst(),
            FlowProto::Tcp,
            0,
            0,
            2_000,
            1_000,
            0xD000_0007,
            FlowVerdict::Accepted,
            provenance(),
        );
        assert_eq!(
            backward.duration_nanos, 0,
            "a non-monotonic clock saturates the duration to zero, never underflows"
        );
    }

    #[test]
    fn flow_verdict_wire_strings_match_the_boundary_flowverdict() {
        // The wire token is single-sourced with the boundary flowlog.FlowVerdict
        // ("accepted"/"dropped") so the LOG-4 reconciler joins on one value.
        assert_eq!(FlowVerdict::Accepted.as_str(), "accepted");
        assert_eq!(FlowVerdict::Dropped.as_str(), "dropped");
    }

    #[test]
    fn flow_event_field_set_matches_boundary_log1_flowrecord_exactly() {
        // ACCEPTANCE: the FlowEvent struct carries EXACTLY the documented field
        // set {session_uuid, tap_name, host_session_index, admitting_domain,
        // src_addr, src_port, dst_addr, dst_port, protocol, bytes_tx, bytes_rx,
        // timestamp_nanos, end_time_nanos, duration_nanos, ct_mark, verdict,
        // provenance} — no http_metadata (method/host/path/status), no payload
        // field. An exhaustive destructuring is the compile-time proof: it FAILS
        // TO COMPILE if a field is added or removed, so the field set is pinned to
        // the boundary LOG-1 FlowRecord (Session/Iface/AdmittingDomain/Dst/
        // Protocol/BytesIn/BytesOut/Start/End/Duration/CtMark/Verdict, which — like
        // every boundary Event — carries first-class Provenance) by the type system.
        let s = session(3);
        let ev = FlowEvent::over_flow(
            &s,
            "alloweda.example",
            src(),
            dst(),
            FlowProto::Tcp,
            1,
            2,
            3,
            9,
            0xD000_0003,
            FlowVerdict::Accepted,
            provenance(),
        );
        let FlowEvent {
            session_uuid,
            tap_name,
            host_session_index,
            admitting_domain,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            protocol,
            bytes_tx,
            bytes_rx,
            timestamp_nanos,
            end_time_nanos,
            duration_nanos,
            ct_mark,
            verdict,
            provenance,
        } = &ev;
        // Touch every binding so the destructuring is load-bearing (and so an
        // unused-variable lint cannot be silenced by dropping a field).
        let _ = (
            session_uuid,
            tap_name,
            host_session_index,
            admitting_domain,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            protocol,
            bytes_tx,
            bytes_rx,
            timestamp_nanos,
            end_time_nanos,
            duration_nanos,
            ct_mark,
            verdict,
            provenance,
        );
        // No HTTP-level field exists: there is intentionally NO method/host/path/
        // status binding above — the destructuring would not compile if one did.
    }

    #[test]
    fn flow_event_with_no_resolvable_admitting_domain_is_empty_not_falsely_joined() {
        // Mirrors the boundary `AdmittingDomain == ""` row: a flow with no valid
        // DNS-2 admission for its destination carries an empty admitting domain
        // (flagged for reconciliation), never a falsely-joined name.
        let s = session(4);
        let ev = FlowEvent::over_flow(
            &s,
            "",
            src(),
            dst(),
            FlowProto::Tcp,
            0,
            0,
            1,
            1,
            0xD000_0004,
            FlowVerdict::Accepted,
            provenance(),
        );
        assert_eq!(ev.admitting_domain, "");
        assert!(!ev.has_admitting_domain());
    }

    #[test]
    fn flow_start_event_carries_metadata_without_byte_counters() {
        // FlowStartEvent is the flow-OPEN record: same L3/4 + attribution +
        // admitting domain, but no byte counters (none have accrued yet).
        let s = session(9);
        let ev = FlowStartEvent::opened(
            &s,
            "github.com",
            src(),
            dst(),
            FlowProto::Tcp,
            42,
            0xD000_0009,
            provenance(),
        );
        assert_eq!(ev.session_uuid, "11111111-2222-3333-4444-555555555555");
        assert_eq!(ev.tap_name, "dstap-9");
        assert_eq!(ev.host_session_index, 9);
        assert_eq!(ev.admitting_domain, "github.com");
        assert!(ev.has_admitting_domain());
        assert_eq!(ev.src_addr, src().ip());
        assert_eq!(ev.src_port, 51000);
        assert_eq!(ev.dst_addr, dst().ip());
        assert_eq!(ev.dst_port, 443);
        assert_eq!(ev.protocol, FlowProto::Tcp);
        assert_eq!(ev.timestamp_nanos, 42);
        // CtMark is known at open (the mark is set before connect).
        assert_eq!(ev.ct_mark, 0xD000_0009);
        // The mandatory POL-3 provenance (rule 4) rides on the flow-open record too.
        assert_eq!(ev.provenance, provenance());

        // The start record carries NO byte counters and NO end/duration/verdict —
        // none of those exist at flow-open. The field set is the open shape (an
        // exhaustive destructuring would fail if bytes_tx/rx or end/duration/verdict
        // appeared).
        let FlowStartEvent {
            session_uuid: _,
            tap_name: _,
            host_session_index: _,
            admitting_domain: _,
            src_addr: _,
            src_port: _,
            dst_addr: _,
            dst_port: _,
            protocol: _,
            timestamp_nanos: _,
            ct_mark: _,
            provenance: _,
        } = &ev;
    }

    #[test]
    fn no_flow_event_field_ever_carries_a_payload_byte() {
        // never-log-the-secret (D73 §5.1): plant a canary standing in for a
        // client-payload byte and assert it appears in NO string field of either
        // flow event. The shapes carry only L3/4 metadata + the admitting domain
        // + the attribution quartet — there is no body, no header value, no
        // captured-byte field — so a payload byte structurally cannot ride along
        // (doc 03 §4 "full packet capture is explicitly out").
        const CANARY: &str = "SECRET-PAYLOAD-CANARY-7e1d4c";
        let s = session(9);

        // Build both events from inputs that do NOT include the canary.
        let flow = FlowEvent::over_flow(
            &s,
            "registry.npmjs.org",
            src(),
            dst(),
            FlowProto::Tcp,
            1024,
            2048,
            7,
            9,
            0xD000_0009,
            FlowVerdict::Accepted,
            provenance(),
        );
        let start = FlowStartEvent::opened(
            &s,
            "registry.npmjs.org",
            src(),
            dst(),
            FlowProto::Tcp,
            7,
            0xD000_0009,
            provenance(),
        );

        // Every String field of FlowEvent (the only fields a payload could hide
        // in; the rest are numeric / IpAddr / enum and cannot carry a byte). The
        // provenance triple is String-bearing too, so it is canary-checked.
        let flow_strs = [
            flow.session_uuid.as_str(),
            flow.tap_name.as_str(),
            flow.admitting_domain.as_str(),
            flow.provenance.rule_id.as_str(),
            flow.provenance.policy_layer.as_str(),
            flow.provenance.policy_version.as_str(),
        ];
        for f in flow_strs {
            assert!(
                !f.contains(CANARY),
                "FlowEvent field leaked a payload canary: {f:?}"
            );
        }
        let start_strs = [
            start.session_uuid.as_str(),
            start.tap_name.as_str(),
            start.admitting_domain.as_str(),
            start.provenance.rule_id.as_str(),
            start.provenance.policy_layer.as_str(),
            start.provenance.policy_version.as_str(),
        ];
        for f in start_strs {
            assert!(
                !f.contains(CANARY),
                "FlowStartEvent field leaked a payload canary: {f:?}"
            );
        }
    }

    /// A recording fake netflow emitter (the boundary `recordingSink` analogue):
    /// captures every flow-start and flow-close record handed to the LOG-1
    /// channel so a test can prove WHICH records reached the channel.
    #[derive(Default)]
    struct RecordingFlowEmitter {
        starts: std::sync::Mutex<Vec<FlowStartEvent>>,
        flows: std::sync::Mutex<Vec<FlowEvent>>,
    }

    impl AuditFlowEmitter for RecordingFlowEmitter {
        fn emit_flow_start(&self, event: &FlowStartEvent) {
            self.starts.lock().unwrap().push(event.clone());
        }
        fn emit_flow(&self, event: &FlowEvent) {
            self.flows.lock().unwrap().push(event.clone());
        }
    }

    #[test]
    fn audit_flow_emitter_receives_start_and_close_records_on_the_log1_channel() {
        // The §10 telemetry seam (mirrors boundary EventSink.Emit): a flow-open
        // FlowStartEvent and the closing FlowEvent both reach the channel exactly
        // as the proxy built them.
        let s = session(7);
        let sink = RecordingFlowEmitter::default();

        let start = FlowStartEvent::opened(
            &s,
            "registry.npmjs.org",
            src(),
            dst(),
            FlowProto::Tcp,
            1,
            0xD000_0007,
            provenance(),
        );
        let flow = FlowEvent::over_flow(
            &s,
            "registry.npmjs.org",
            src(),
            dst(),
            FlowProto::Tcp,
            4096,
            8192,
            1,
            5,
            0xD000_0007,
            FlowVerdict::Accepted,
            provenance(),
        );
        sink.emit_flow_start(&start);
        sink.emit_flow(&flow);

        let starts = sink.starts.lock().unwrap();
        assert_eq!(
            starts.len(),
            1,
            "exactly one flow-start reached the channel"
        );
        assert_eq!(starts[0].tap_name, "dstap-7");
        assert_eq!(starts[0].admitting_domain, "registry.npmjs.org");
        assert_eq!(starts[0].provenance, provenance());

        let flows = sink.flows.lock().unwrap();
        assert_eq!(flows.len(), 1, "exactly one flow-close reached the channel");
        assert_eq!(flows[0].tap_name, "dstap-7");
        assert_eq!(flows[0].bytes_tx, 4096);
        assert_eq!(flows[0].bytes_rx, 8192);
        assert_eq!(flows[0].protocol, FlowProto::Tcp);
        // The mandatory POL-3 provenance (rule 4) reached the §10 channel ON the
        // record — the production sink receives it structurally (boundary
        // Event.Provenance parity), not via a side channel.
        assert_eq!(flows[0].provenance, provenance());
    }
}
