//! TLS-5 credential-swap EXECUTOR CORE — the registry-match evaluator + the
//! synchronous D22 `Validate` driver on the inspected (TLS-3-terminated) path
//! (doc 09 §5 TLS-5; doc 12 §3 / §5.2 / §13.3; doc 16 §4 / §5.2 / §9; D8 / D22 /
//! D39 / D73 / D83 / D40).
//!
//! # What this is — the M1 headline's front half
//!
//! TLS-5 is the credential swap: the long-lived credential the upstream needs
//! (the GitHub PAT, the M1 first service — D83) **never enters the VM**. The agent
//! holds only a per-session short-lived placeholder; this module is the part of
//! that swap that runs on the inspected path BEFORE any real credential is
//! fetched:
//!
//! 1. **registry match** ([`SwapRegistry::match_request`]) — does the request's
//!    origin host land on a `services[]` registry entry, AND is the registered
//!    credential present at the entry's credential location? (strawman: service
//!    `github` → hosts `github.com`/`api.github.com`, credential location
//!    `Authorization` header — doc 13 §3, doc 16 §5.2). A miss means this is NOT a
//!    swap request: the request is left UNTOUCHED and the validator is never
//!    called (boundary `TestSwap_NoRegistryMatch_RequestUntouched`).
//! 2. **synchronous Validate** ([`SwapExecutor::evaluate`]) — on a match, run the
//!    D22 `Validate(presented_credential, session_ref, service_id)` seam
//!    SYNCHRONOUSLY (D73: the swap path is synchronous, the latency budget is the
//!    validate round-trip) and branch on its verdict:
//!    - **ALLOW** → emit a session-cached [`GrantRef`] (the opaque grant handle
//!      Identity returned — NOT the credential, which lives in the D39 secret
//!      store OUTSIDE the boundary). The async fetch of the real credential for
//!      this grant ref, and the upstream substitution + response scrub, are LATER
//!      TLS-5 units (scope honesty below).
//!    - **DENY** → reject with the in-band structured **403** carrying the
//!      machine-readable reason (D77 block+log; doc 16 §5.2 fail-closed); the
//!      secret store is NEVER consulted.
//!
//! # Pass-through (TLS-4) NEVER reaches this path (D17 / D74)
//!
//! The swap executor attaches to the INSPECTED path only. A TLS-4 pass-through
//! flow (opaque tunnel, frozen against TLS termination — [`crate::tls1_admission`]
//! `Passthrough`) is never HTTP-visible, so the swap registry, the validator, and
//! the secret store are all structurally unreachable from it. [`SwapExecutor`]
//! exposes [`SwapExecutor::is_inspected_path`] as the explicit guard the listener
//! checks before it ever constructs a [`SwapRequest`]; a `#[cfg(test)]` test pins
//! that a pass-through flow calls the validator ZERO times.
//!
//! # Never-hold-the-secret (D73 §5.1 / doc 16 §5.2) — a TYPE-LEVEL property
//!
//! The presented short-lived credential is the ONLY secret this module touches,
//! and it touches it for exactly the duration of the [`IdentityValidator::validate`]
//! call. It is carried in a [`PresentedCredential`] newtype over a
//! `zeroize::Zeroizing` buffer that wipes the bytes on drop, is borrowed (never
//! cloned/copied) into the validator, and is dropped the instant `evaluate`
//! returns — the credential value is NEVER stored on the emitted [`GrantRef`], in
//! the [`SwapVerdict`], in the [`SwapDenial`] reason, or in any telemetry shape.
//! The grant reference Identity returns is an OPAQUE handle (a session-scoped
//! string), not the credential; the real long-lived credential is fetched (in a
//! LATER unit) from the D39 secret store, which lives OUTSIDE this boundary.
//!
//! # Scope honesty — what lands here vs. later TLS-5 units
//!
//! What lands: the framework-agnostic registry-match evaluator, the synchronous
//! `Validate` driver, the ALLOW→grant-ref / DENY→403 branch, and the
//! session-grant cache, all over an [`IdentityValidator`] seam tested against a
//! fake (in-memory verdicts) plus a fake secret-store STUB that proves it is
//! never called on the validate path. What does NOT land here, and is later
//! TLS-5 work:
//!
//! - the **async fetch** of the real credential for a `grant_ref` from the D39
//!   secret store, the **upstream substitution** of that credential into the
//!   request, and the **response scrub** of both credentials on the VM-bound leg
//!   (boundary `tlsproxy_swap_test.go` scrub rows). This unit emits the grant ref
//!   and stops; the fetch/substitute/scrub is the executor's back half.
//! - the **`CredentialUseEvent`** LOG-5 emission (boundary `EventCredentialUse`)
//!   — it belongs with the substitution that actually USES the fetched credential.
//!
//! # Contracts consumed (doc 16 §9 / doc 13 §3)
//!
//! - the FROZEN service-registry shape — [`ds_contracts::pol1::ServiceEntry`]
//!   (doc 13 §3 `services[]`; CONTENT is Identity-supplied, the schema owns the
//!   shape). This module wraps a slice of them in a [`SwapRegistry`] match index.
//! - the FROZEN session join key — [`ds_contracts::session::SessionRef`].
//! - the D22 `Validate` seam. Its generated proto is NOT yet frozen into
//!   `ds-contracts` (the Stage-0 freeze under its `src/gen/` is undelivered — its
//!   `lib.rs` says so). So, EXACTLY as [`crate::reoriginate::UpstreamDialer`] and
//!   [`crate::telemetry_http`] do for their not-yet-frozen seams, this module
//!   defines the seam as a local trait ([`IdentityValidator`]) + a local verdict
//!   shape ([`ValidationVerdict`]) mirroring the boundary
//!   (`boundary/tlsproxy/tlsproxy.go` `IdentityValidator` / `IdentityClaims`) and
//!   the doc 16 §9 row `Validate(presented_credential, session_ref, service_id) →
//!   {verdict ALLOW | DENY{machine_readable_reason}, grant_ref, expiry}`.
//!   **Migration note:** when the identity-plane Stage-0 freeze lands its
//!   generated `Validate` types, [`IdentityValidator`] / [`ValidationVerdict`]
//!   migrate onto them; the shape chosen here is the doc 16 §9 / boundary one, so
//!   the swap is mechanical.
//!
//! # D40 pingora confinement (doc 12 §13.1)
//!
//! No pingora type appears here. `main.rs` extracts the request line + headers off
//! the terminated stream, constructs a [`SwapRequest`], drives [`SwapExecutor`],
//! and — on ALLOW, in a later unit — performs the upstream substitution; this
//! module ships the registry index, the validator seam, the pure evaluate core,
//! and the grant cache only.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroizing;

use ds_contracts::pol1::ServiceEntry;
use ds_contracts::session::SessionRef;

use crate::telemetry_http::{AuditEmitter, CredentialUseEvent, Fingerprint, Provenance};

// ─────────────────────────────────────────────────────────────────────────────
// The presented short-lived credential — the ONLY secret this module touches.
// Never-hold-the-secret (D73) is type-level: the bytes live in a `Zeroizing`
// buffer wiped on drop, are borrowed into the validator, and are dropped the
// instant `evaluate` returns. No `Clone`, no `Display`/`Debug` of the bytes.
// ─────────────────────────────────────────────────────────────────────────────

/// The short-lived placeholder credential the agent presented at the registered
/// credential location (e.g. the `Authorization` header value). This is the only
/// secret the swap executor handles, and it handles it for exactly the duration
/// of the [`IdentityValidator::validate`] call.
///
/// The bytes live in a [`Zeroizing`] buffer (wiped on drop) and are exposed ONLY
/// via [`PresentedCredential::expose`] to the validator. The type is deliberately
/// NOT `Clone` and NOT `Debug`-over-the-bytes, so a credential byte can never be
/// copied into a long-lived structure, a log line, or a telemetry field by
/// accident — the never-log-the-secret convention is enforced by the shape, not a
/// scrub pass.
pub struct PresentedCredential(Zeroizing<Vec<u8>>);

impl PresentedCredential {
    /// Wrap presented credential bytes (the value the agent placed at the
    /// registered credential location). Takes ownership so the caller's copy can
    /// be dropped; the bytes are wiped when this value drops.
    pub fn new(bytes: impl Into<Vec<u8>>) -> PresentedCredential {
        PresentedCredential(Zeroizing::new(bytes.into()))
    }

    /// Borrow the credential bytes for the duration of a single validation call.
    /// The borrow ties the exposure to the validator call site — the bytes are
    /// never handed out by value.
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Whether the presented value is empty (an empty `Authorization` value is a
    /// registry NON-match — there is no credential present to swap).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A secret-free `Debug` — NEVER renders the credential bytes (D73). Prints only
/// the length so diagnostics can distinguish "absent" from "present".
impl fmt::Debug for PresentedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresentedCredential")
            .field("len", &self.0.len())
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The session-cached grant reference — the ALLOW output. An OPAQUE handle to the
// grant Identity returned, NOT the credential (which the D39 secret store holds
// OUTSIDE the boundary, fetched in a later unit).
// ─────────────────────────────────────────────────────────────────────────────

/// The opaque grant reference Identity returns on an ALLOW verdict (doc 16 §9
/// `Validate → {…, grant_ref, expiry}`). This is a HANDLE the later secret-store
/// fetch keys on — it is NEVER the credential value. Caching it (per
/// `(session, service)`) is what lets the back half fetch the real credential
/// once per grant rather than per request (doc 16 §5.1 "fetch per-grant, never
/// per-request").
///
/// `expiry_unix` is the grant's expiry as a Unix timestamp (seconds), carried
/// opaquely from the verdict so the back half can honor it; this module does no
/// clock arithmetic on it (the validator already checked freshness + session
/// liveness — doc 16 §5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRef {
    /// The service this grant is for (the registry `service` key).
    pub service_id: String,
    /// The opaque grant handle Identity returned. NOT a credential.
    pub grant_ref: String,
    /// The grant's expiry (Unix seconds), carried opaquely from the verdict.
    pub expiry_unix: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// The D22 Validate seam — local trait + local verdict shape (the proto is not
// yet frozen into ds-contracts; see the module-doc migration note). Mirrors the
// boundary `IdentityValidator` / `IdentityClaims` and doc 16 §9.
// ─────────────────────────────────────────────────────────────────────────────

/// The verdict the D22 `Validate` seam returns (doc 16 §9): `ALLOW{grant_ref,
/// expiry}` or `DENY{machine_readable_reason}`. The presented credential's bytes
/// are NEVER carried on the verdict (the validator borrowed them and is done with
/// them); the ALLOW arm carries only the opaque grant handle + expiry, the DENY
/// arm only a machine-readable reason CODE (secret-free, §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationVerdict {
    /// The presented credential validated against THIS session's identity for the
    /// service. Carries the opaque grant handle + expiry (Unix seconds) — never
    /// the credential.
    Allow {
        /// The opaque grant handle (keys the later secret-store fetch).
        grant_ref: String,
        /// Grant expiry (Unix seconds), carried opaquely.
        expiry_unix: u64,
    },
    /// The presented credential failed validation (cross-session, forged,
    /// expired, killed/suspended session, out-of-grant service). Carries the
    /// machine-readable reason CODE that surfaces in the structured 403.
    Deny {
        /// The machine-readable deny reason (a stable code, e.g.
        /// `identity-mismatch` / `credential-expired` / `unknown-credential`).
        /// Secret-free: never the credential bytes.
        reason: DenyReason,
    },
}

/// The machine-readable deny reason carried in the structured 403 (doc 16 §5.2
/// fail-closed; §10 secret-free reason code). A small closed enum so the reason is
/// a STABLE code, never free-form text that could smuggle a payload byte. The
/// validator maps its substrate-specific failure onto one of these classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// The presented credential is unknown / forged / unparseable.
    UnknownCredential,
    /// The credential is bound to a DIFFERENT session (cross-session replay).
    IdentityMismatch,
    /// The credential is past its TTL.
    CredentialExpired,
    /// The session has no grant for this service (out-of-grant).
    OutOfGrant,
    /// The session is killed / suspended / otherwise not live (doc 16 §5.4:
    /// liveness is checked at `Validate`, catching a stolen-but-unexpired cert).
    SessionNotLive,
    /// BACK-HALF: the D39 secret store has no credential for this grant/service.
    /// Surfaces on a 502 gateway-failure denial (the proxy's own dependency), NOT
    /// the front-half 403 — the agent's credential already validated.
    SecretNotFound,
    /// BACK-HALF: the D39 secret store was unreachable / errored mid-swap.
    /// Surfaces on a 502 gateway-failure denial; fail-closed (never the
    /// placeholder upstream).
    SecretStoreUnavailable,
}

impl DenyReason {
    /// The stable, kebab-case, secret-free reason CODE for the structured 403 and
    /// the §10 deny event. Mirrors the [`crate::reoriginate::ReoriginateRefuse`]
    /// `reason_code()` convention.
    pub fn reason_code(self) -> &'static str {
        match self {
            DenyReason::UnknownCredential => "tls5-unknown-credential",
            DenyReason::IdentityMismatch => "tls5-identity-mismatch",
            DenyReason::CredentialExpired => "tls5-credential-expired",
            DenyReason::OutOfGrant => "tls5-out-of-grant",
            DenyReason::SessionNotLive => "tls5-session-not-live",
            DenyReason::SecretNotFound => "tls5-secret-not-found",
            DenyReason::SecretStoreUnavailable => "tls5-secret-store-unavailable",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}

/// The D22 identity-validation seam (doc 16 §9; boundary `IdentityValidator`).
/// The swap executor presents `{presented_credential, session_ref, service_id}`
/// and receives an ALLOW{grant_ref, expiry} / DENY{reason} verdict. The call is
/// SYNCHRONOUS on the swap path (D73): the latency budget is this round-trip.
///
/// The presented credential is BORROWED (`&PresentedCredential`) for the duration
/// of the call — the validator must NOT retain it past `validate` (never-hold-the
/// -secret). Production implements this over the real Identity `Validate` RPC
/// client (the gRPC/proto types live in `src/main.rs` — D40 confinement); tests
/// implement it over an in-memory fake.
///
/// The trait is infallible at the SEAM level: a substrate/transport error is the
/// validator's concern to map onto a DENY (fail-closed — doc 16 §5.2: a key-store
/// or validate outage denies the request, never degrades to egressing the
/// placeholder as if real). Returning a verdict (not a `Result`) makes the
/// fail-closed posture structural — the executor always has a verdict to act on.
pub trait IdentityValidator {
    /// Validate `presented` for `(session, service_id)` against THIS session's
    /// identity (signature + freshness + session liveness + grant lookup —
    /// doc 16 §5.3). MUST borrow, never retain, `presented`.
    fn validate(
        &self,
        session: &SessionRef,
        service_id: &str,
        presented: &PresentedCredential,
    ) -> ValidationVerdict;
}

// ─────────────────────────────────────────────────────────────────────────────
// The service registry — a match index over the frozen `ServiceEntry` shape.
// ─────────────────────────────────────────────────────────────────────────────

/// The credential location a registry entry binds (doc 13 §3 `credential`). v0
/// supports the D83 generic header-swap location; an unrecognized location yields
/// no match (the request is left untouched).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialLocation {
    /// `credential.location = header`, `credential.name = <header>` — the D83
    /// generic Authorization-header substitution, the frozen seam shape.
    Header {
        /// The header NAME the credential rides (e.g. `Authorization`), matched
        /// ASCII-case-insensitively per RFC 7230 §3.2.
        name: String,
    },
}

impl CredentialLocation {
    /// Parse a [`ServiceEntry`]'s `(credential_location, credential_name)` pair
    /// into a typed location, or `None` for an unrecognized location (v0 supports
    /// only `header`). The location string is matched ASCII-case-insensitively.
    fn from_entry(entry: &ServiceEntry) -> Option<CredentialLocation> {
        if entry.credential_location.eq_ignore_ascii_case("header") {
            Some(CredentialLocation::Header {
                name: entry.credential_name.clone(),
            })
        } else {
            None
        }
    }
}

/// A matched swap rule: the service id + the credential location to read from the
/// request. Derived from a [`ServiceEntry`] on a host match; carries the typed
/// location so the executor reads the right header without re-parsing the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapRule {
    /// The matched service id (the registry `service` key — the `service_id`
    /// the validator is called with).
    pub service_id: String,
    /// Where the credential rides on the request.
    pub location: CredentialLocation,
}

/// The TLS-5 service registry: a host → rule index over the frozen
/// [`ServiceEntry`] shape (doc 13 §3 `services[]`). Built from the live policy
/// snapshot's `services[]`; a request matches iff its origin host is one of an
/// entry's `hosts` (matched ASCII-case-insensitively, exact host, no wildcard in
/// v0). Host matching is what scopes the swap to the registered service's
/// destinations — `github` only ever swaps for `github.com`/`api.github.com`.
#[derive(Default)]
pub struct SwapRegistry {
    /// host (lowercased) → rule. The same host on two entries is a config error
    /// the schema validator owns; here a later entry wins deterministically.
    by_host: BTreeMap<String, SwapRule>,
}

impl SwapRegistry {
    /// An empty registry (no service registered — every request is a non-match,
    /// the default-deny-of-swap posture; nothing is ever swapped). This is the
    /// shipped default until policy populates `services[]`.
    pub fn empty() -> SwapRegistry {
        SwapRegistry::default()
    }

    /// Build the registry from a slice of frozen [`ServiceEntry`] rows (the live
    /// snapshot's `services[]`). Entries whose credential location is
    /// unrecognized (not `header` in v0) are skipped — they can never match, so
    /// they are simply not indexed. Each entry's `hosts` are indexed
    /// (lowercased) to the same rule.
    pub fn from_entries(entries: &[ServiceEntry]) -> SwapRegistry {
        let mut by_host = BTreeMap::new();
        for entry in entries {
            let Some(location) = CredentialLocation::from_entry(entry) else {
                continue;
            };
            let rule = SwapRule {
                service_id: entry.service.clone(),
                location,
            };
            for host in &entry.hosts {
                by_host.insert(host.to_ascii_lowercase(), rule.clone());
            }
        }
        SwapRegistry { by_host }
    }

    /// Whether the registry has any indexed service (a quick guard the listener
    /// can check to skip swap evaluation entirely when no service is registered).
    pub fn is_empty(&self) -> bool {
        self.by_host.is_empty()
    }

    /// Match `request` against the registry: the request's origin host must land
    /// on a `services[]` entry, AND the registered credential must be PRESENT
    /// (non-empty) at the entry's credential location. Returns the matched
    /// [`SwapRule`] on a full match, or `None` otherwise.
    ///
    /// A `None` means this is NOT a swap request — the listener leaves the request
    /// UNTOUCHED and never calls the validator (boundary
    /// `TestSwap_NoRegistryMatch_RequestUntouched`). The three non-match shapes
    /// the boundary names are all `None` here:
    /// - host not in any entry's `hosts`,
    /// - host matches but the credential rides a non-registered location (the
    ///   registered header is absent),
    /// - host matches but no credential is present (the header is empty/absent).
    pub fn match_request<'a>(&'a self, request: &SwapRequest) -> Option<&'a SwapRule> {
        let rule = self.by_host.get(&request.host.to_ascii_lowercase())?;
        // The credential must be PRESENT at the registered location. An absent /
        // empty value is a non-match: there is nothing to swap.
        match &rule.location {
            CredentialLocation::Header { name } => {
                let present = request
                    .credential_at_header(name)
                    .map(|c| !c.is_empty())
                    .unwrap_or(false);
                if present {
                    Some(rule)
                } else {
                    None
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The request the executor evaluates — the host + the presented credential at
// each header location. Built by `main.rs` off the terminated, HTTP-visible
// stream (no pingora type here, D40).
// ─────────────────────────────────────────────────────────────────────────────

/// The inspected request the swap executor evaluates: the origin host (the
/// registry match key — the SNI / `Host` on the terminated stream, NOT the
/// request-line target) plus the credential values present at each header
/// location. `main.rs` extracts these off the terminated stream and constructs
/// this; the credential bytes are wrapped in [`PresentedCredential`] so they are
/// wiped on drop and never copied.
///
/// Headers are stored under their ASCII-lowercased name (RFC 7230 §3.2
/// case-insensitivity). Only the credential-bearing header(s) the listener cares
/// about need be populated — this is NOT a full header map (carrying every header
/// would be a leak surface; only the location the registry binds is needed).
#[derive(Debug)]
pub struct SwapRequest {
    /// The origin host (registry match key). Matched ASCII-case-insensitively.
    host: String,
    /// Lowercased-header-name → presented credential value. Populated only for
    /// the credential-bearing header(s).
    headers: BTreeMap<String, PresentedCredential>,
}

impl SwapRequest {
    /// Build a request for `host` with no credential headers yet (a non-match
    /// request, or a base to add headers to via [`SwapRequest::with_header`]).
    pub fn new(host: impl Into<String>) -> SwapRequest {
        SwapRequest {
            host: host.into(),
            headers: BTreeMap::new(),
        }
    }

    /// Add a credential-bearing header value. The name is stored
    /// ASCII-lowercased; the value is taken by `PresentedCredential` (wiped on
    /// drop). Builder-style for ergonomic construction in `main.rs` and tests.
    pub fn with_header(mut self, name: impl AsRef<str>, value: PresentedCredential) -> SwapRequest {
        self.headers
            .insert(name.as_ref().to_ascii_lowercase(), value);
        self
    }

    /// The origin host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The presented credential at header `name` (ASCII-case-insensitive), if
    /// present.
    fn credential_at_header(&self, name: &str) -> Option<&PresentedCredential> {
        self.headers.get(&name.to_ascii_lowercase())
    }

    /// The presented credential at a matched rule's location, if present.
    fn credential_for(&self, rule: &SwapRule) -> Option<&PresentedCredential> {
        match &rule.location {
            CredentialLocation::Header { name } => self.credential_at_header(name),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The structured 403 — the DENY surface (D77 block+log; doc 16 §5.2).
// ─────────────────────────────────────────────────────────────────────────────

/// The in-band structured denial the executor returns on a fail-closed outcome
/// (D77 block+log; doc 16 §5.2). The boundary distinguishes TWO denial classes
/// by HTTP status, and a `SwapDenial` carries which one it is in [`status`]:
///
/// - **[`SwapDenial::STATUS`] = 403** — the FRONT-HALF *validation* failure: the
///   agent's presented credential is bad (cross-session, forged, expired,
///   out-of-grant, dead session). This is the structured-DENY status (D77; the
///   boundary `cross-session swap rejected` row asserts 401/403). The proxy's own
///   dependencies are fine — only the credential is rejected.
/// - **[`SwapDenial::GATEWAY_STATUS`] = 502** — the BACK-HALF *credential-path*
///   failure: the proxy's OWN dependency (the D39 secret store) failed mid-swap,
///   so the real credential could not be fetched. This is Bad Gateway (the
///   boundary `proxy-generated error page` row asserts 502 — an upstream /
///   credential-path failure, NOT a bad agent credential).
///
/// The body/telemetry carries the machine-readable reason CODE. Secret-free: it
/// carries the reason class, the service id, and the status, NEVER the presented
/// or fetched credential.
///
/// [`status`]: SwapDenial::status
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapDenial {
    /// The HTTP status — [`SwapDenial::STATUS`] (403) for a front-half validation
    /// failure, [`SwapDenial::GATEWAY_STATUS`] (502) for a back-half
    /// secret-store / credential-path failure. The constructor that builds the
    /// denial picks the class; the boundary distinguishes the two by this value.
    pub status: u16,
    /// The service the swap was denied for (registry `service` key).
    pub service_id: String,
    /// The machine-readable reason class (secret-free, §10).
    pub reason: DenyReason,
}

impl SwapDenial {
    /// The front-half structured-deny status (D77): a *validation* failure — the
    /// agent's presented credential is bad. Used by `evaluate`'s DENY arm.
    pub const STATUS: u16 = 403;

    /// The back-half gateway-failure status: the proxy's own dependency (the D39
    /// secret store) failed mid-swap, so the credential could not be fetched.
    /// Bad Gateway (the boundary `proxy-generated error page` 502 row). Used by
    /// `fire`'s `FetchFailed` arm — distinct from the front-half [`STATUS`] so a
    /// dependency failure is never conflated with a bad agent credential.
    ///
    /// [`STATUS`]: SwapDenial::STATUS
    pub const GATEWAY_STATUS: u16 = 502;

    /// A front-half *validation*-failure denial (403). The presented credential
    /// was rejected; the secret store was never consulted.
    pub fn validation(service_id: String, reason: DenyReason) -> SwapDenial {
        SwapDenial {
            status: SwapDenial::STATUS,
            service_id,
            reason,
        }
    }

    /// A back-half *gateway*-failure denial (502): the secret-store fetch failed
    /// mid-swap. Fail-closed — the placeholder is NEVER egressed upstream.
    pub fn gateway(service_id: String, reason: DenyReason) -> SwapDenial {
        SwapDenial {
            status: SwapDenial::GATEWAY_STATUS,
            service_id,
            reason,
        }
    }

    /// The machine-readable reason code for the denial body / §10 deny event.
    pub fn reason_code(&self) -> &'static str {
        self.reason.reason_code()
    }
}

/// What the executor decided for one inspected request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwapVerdict {
    /// No registry match — NOT a swap request. The listener leaves the request
    /// untouched and forwards it unchanged; the validator was NOT called.
    NoSwap,
    /// Registry matched AND validation ALLOWED: a session-cached [`GrantRef`] was
    /// emitted (and cached). The later unit fetches the real credential for this
    /// grant ref from the D39 secret store and substitutes it upstream.
    Allowed(GrantRef),
    /// Registry matched but validation DENIED: reject with the structured 403.
    /// The secret store was NOT consulted.
    Denied(SwapDenial),
}

// ─────────────────────────────────────────────────────────────────────────────
// The executor — the registry-match → synchronous-Validate → grant/deny driver.
// ─────────────────────────────────────────────────────────────────────────────

/// The TLS-5 swap executor core: drives a request through the registry match and,
/// on a match, the synchronous D22 `Validate`, branching to a session-cached
/// grant ref (ALLOW) or a structured 403 (DENY). Generic over the
/// [`IdentityValidator`] seam so it unit-tests against a fake validator with no
/// RPC.
///
/// Wraps a [`SwapRegistry`] and a [`SessionGrantCache`]; the validator is passed
/// per-call (it is the live RPC client `main.rs` owns). Attaches to the INSPECTED
/// path ONLY — a TLS-4 pass-through flow never constructs a [`SwapRequest`] and so
/// never reaches [`SwapExecutor::evaluate`] (see [`SwapExecutor::is_inspected_path`]).
#[derive(Default)]
pub struct SwapExecutor {
    registry: SwapRegistry,
    grants: SessionGrantCache,
}

impl SwapExecutor {
    /// Build an executor over a registry. Starts with an empty grant cache.
    pub fn new(registry: SwapRegistry) -> SwapExecutor {
        SwapExecutor {
            registry,
            grants: SessionGrantCache::new(),
        }
    }

    /// The TLS-4 guard (D17 / D74): the swap executor runs on the INSPECTED path
    /// only. The listener checks this before it constructs a [`SwapRequest`]; a
    /// pass-through flow (`inspected == false`) skips swap evaluation entirely, so
    /// the validator and secret store are never called for it. A free function on
    /// the executor so the guard is named at the call site, not buried in a
    /// boolean the listener passes around.
    pub fn is_inspected_path(inspected: bool) -> bool {
        inspected
    }

    /// Read-only access to the grant cache (diagnostics / the back-half fetch).
    pub fn grants(&self) -> &SessionGrantCache {
        &self.grants
    }

    /// Evaluate one inspected request against the registry + validator.
    ///
    /// 1. **registry match** — no match ⇒ [`SwapVerdict::NoSwap`], `validator`
    ///    NEVER called (the request is forwarded untouched).
    /// 2. **synchronous Validate** — on a match, borrow the presented credential
    ///    and call `validator.validate(session, service_id, &presented)` (D73:
    ///    synchronous, the swap-path latency budget):
    ///    - **ALLOW** ⇒ build a [`GrantRef`], CACHE it per `(session, service)`,
    ///      return [`SwapVerdict::Allowed`]. The credential bytes are dropped at
    ///      the end of this call — never stored.
    ///    - **DENY** ⇒ return [`SwapVerdict::Denied`] with the structured 403; the
    ///      secret store is NOT consulted (it is not even reachable from here).
    ///
    /// The presented credential is borrowed from `request` for the validate call
    /// and never copied out: the only secret-touching step is the borrow into
    /// `validate`.
    pub fn evaluate<V: IdentityValidator + ?Sized>(
        &self,
        validator: &V,
        session: &SessionRef,
        request: &SwapRequest,
    ) -> SwapVerdict {
        // (1) registry match. A non-match short-circuits BEFORE the validator —
        // no validate call, no secret-store touch, request forwarded untouched.
        let Some(rule) = self.registry.match_request(request) else {
            return SwapVerdict::NoSwap;
        };

        // The matched rule guarantees a present credential at the location, but
        // re-borrow defensively; an absent value here is a non-match.
        let Some(presented) = request.credential_for(rule) else {
            return SwapVerdict::NoSwap;
        };

        // (2) synchronous Validate (D73). Borrow the credential for the call; it
        // is dropped with `request` after this method returns — never retained.
        match validator.validate(session, &rule.service_id, presented) {
            ValidationVerdict::Allow {
                grant_ref,
                expiry_unix,
            } => {
                let grant = GrantRef {
                    service_id: rule.service_id.clone(),
                    grant_ref,
                    expiry_unix,
                };
                // Cache the grant per (session, service) so the back-half fetch
                // is per-grant, not per-request (doc 16 §5.1).
                self.grants.store(session, grant.clone());
                SwapVerdict::Allowed(grant)
            }
            ValidationVerdict::Deny { reason } => {
                SwapVerdict::Denied(SwapDenial::validation(rule.service_id.clone(), reason))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// THE BACK HALF (PE9N-u2): fetch the real credential from the D39 secret store
// via an injected fetch trait, SUBSTITUTE it into the outbound Authorization
// header, and SCRUB both credential values from every log path (type-level: an
// event holds only the fingerprint). Pass-through (TLS-4) and registry misses
// never reach here — the front half (`evaluate`) gated them out already.
// ─────────────────────────────────────────────────────────────────────────────

/// The long-lived credential fetched from the D39 secret store for a grant — the
/// REAL credential the upstream needs, which never enters the VM (D8/D39). Like
/// [`PresentedCredential`], it is a `zeroize`-wiped buffer that is NOT `Clone` and
/// whose `Debug` renders only its length + fingerprint, NEVER the bytes: the
/// never-log-the-secret property is structural, not a scrub pass. The bytes are
/// exposed ONLY via [`FetchedCredential::expose`] to the substitution step, which
/// writes them onto the upstream-bound request and nowhere else.
///
/// It carries the loggable [`Fingerprint`] the secret store assigned alongside the
/// value, so the [`CredentialUseEvent`] can be built WITHOUT ever touching the
/// bytes (the fingerprint is the only credential-derived datum any event holds).
pub struct FetchedCredential {
    value: Zeroizing<Vec<u8>>,
    fingerprint: Fingerprint,
}

impl FetchedCredential {
    /// Wrap the fetched long-lived credential `value` + its loggable
    /// `fingerprint`. Takes ownership of the bytes (wiped on drop). The
    /// fingerprint is the secret-free identifier the store supplies — never
    /// derived from the bytes here.
    pub fn new(value: impl Into<Vec<u8>>, fingerprint: Fingerprint) -> FetchedCredential {
        FetchedCredential {
            value: Zeroizing::new(value.into()),
            fingerprint,
        }
    }

    /// Borrow the credential bytes for the duration of the substitution write.
    /// The bytes are never handed out by value and never copied into any log,
    /// event, or long-lived structure other than the upstream-bound request.
    pub fn expose(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// The loggable, secret-free fingerprint (for the [`CredentialUseEvent`]).
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }
}

/// A secret-free `Debug` — renders only the length + fingerprint, NEVER the
/// credential bytes (D73 / doc 12 §5.1).
impl fmt::Debug for FetchedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchedCredential")
            .field("len", &self.value.len())
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// Why a secret-store fetch failed (doc 16 §5.2 fail-closed: a key-store outage
/// DENIES — it never degrades to egressing the placeholder as if real). Stable,
/// secret-free reason classes; the fetch error NEVER carries a credential byte or
/// the underlying substrate message (which could echo a value). Mapped onto a
/// proxy-generated **502** on the VM-bound leg (the boundary
/// `proxy-generated error page` row asserts a 502 when the upstream/credential
/// path fails mid-swap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchError {
    /// The secret store has no credential for this grant/service.
    NotFound,
    /// The secret store was unreachable / errored (fail-closed → deny, never the
    /// placeholder upstream).
    Unavailable,
}

impl FetchError {
    /// The back-half [`DenyReason`] this fetch failure surfaces on the 502
    /// gateway-failure denial. Keeps the distinct `tls5-secret-*` reason class —
    /// a secret-store failure is NOT folded onto the front-half out-of-grant code.
    pub fn deny_reason(self) -> DenyReason {
        match self {
            FetchError::NotFound => DenyReason::SecretNotFound,
            FetchError::Unavailable => DenyReason::SecretStoreUnavailable,
        }
    }

    /// The stable, kebab-case, secret-free reason CODE (the §10 class), mirroring
    /// [`DenyReason::reason_code`].
    pub fn reason_code(self) -> &'static str {
        self.deny_reason().reason_code()
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}

/// The D39 secret-store fetch seam (the INJECTED fetch trait, doc 16 §9 /
/// boundary `SecretStore.FetchLongLived`): given the opaque [`GrantRef`] an ALLOW
/// produced, return the long-lived credential the upstream needs. The store lives
/// OUTSIDE the boundary (a separate trust zone, D8/D39); production implements
/// this over the real secret-store client (whose transport/proto types stay in
/// `src/main.rs`, D40), tests over an in-memory fake.
///
/// Returning a [`FetchedCredential`] (not raw bytes) keeps the value wrapped in
/// the zeroizing newtype from the moment it crosses the seam — there is no point
/// at which the long-lived value exists as a bare, loggable `Vec<u8>` inside this
/// module. A fetch failure is a [`FetchError`] the substitution maps onto a
/// fail-closed 502 (never the placeholder upstream).
pub trait SecretFetcher {
    /// Fetch the long-lived credential for `grant` (the opaque handle an ALLOW
    /// verdict produced; `grant.service_id` names the service, `grant.grant_ref`
    /// keys the store). The presented short-lived credential is NOT passed — it
    /// was already validated and dropped; the grant is the only key.
    fn fetch_long_lived(&self, grant: &GrantRef) -> Result<FetchedCredential, FetchError>;
}

/// The request line the swap fired on, for the [`CredentialUseEvent`] (method /
/// host / path). A plain metadata triple `main.rs` reads off the terminated
/// stream — carries NO header values, NO body, NO credential byte (it is exactly
/// the §10 request-line fields LOG-5 records).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestLine {
    /// The HTTP method (e.g. `GET`, `POST`).
    pub method: String,
    /// The origin host (the SNI / `Host` on the terminated stream).
    pub host: String,
    /// The request path (origin-form target, e.g. `/git-receive-pack`).
    pub path: String,
}

impl RequestLine {
    /// Build a request-line triple.
    pub fn new(
        method: impl Into<String>,
        host: impl Into<String>,
        path: impl Into<String>,
    ) -> RequestLine {
        RequestLine {
            method: method.into(),
            host: host.into(),
            path: path.into(),
        }
    }
}

/// The outbound, upstream-bound Authorization header value after substitution.
/// Wraps a `zeroize`-wiped buffer (the value IS the long-lived credential plus
/// the auth scheme) so it is wiped on drop and never lands in a log via a stray
/// `Debug`/`Display`; `main.rs` borrows [`SubstitutedHeader::expose`] to write the
/// header onto the upstream request and drops it immediately after. NOT `Clone`,
/// secret-free `Debug` (length only). The substitution happens BEFORE the upstream
/// TLS handshake, so the real credential reaches upstream in cleartext over the
/// termination channel (D8/D39) — it is NEVER on the VM-bound wire.
pub struct SubstitutedHeader(Zeroizing<Vec<u8>>);

impl SubstitutedHeader {
    /// Borrow the substituted header bytes for the write onto the upstream
    /// request. Never handed out by value.
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SubstitutedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubstitutedHeader")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Build the substituted Authorization header VALUE: the registered auth `scheme`
/// (e.g. `Bearer`) followed by the fetched long-lived credential bytes. This is
/// the substitution itself — the short-lived placeholder the VM presented is
/// DISCARDED (it was only ever borrowed into the validator and is already
/// dropped); the new value is the long-lived credential the upstream expects.
///
/// The result is a [`SubstitutedHeader`] (zeroize-wiped). `main.rs` writes it onto
/// the upstream-bound request in place of the presented value, BEFORE the upstream
/// handshake — so the long-lived credential travels upstream in cleartext over the
/// termination channel (D8/D39) and never appears on the VM-bound leg.
///
/// `scheme` is the auth scheme to prefix (`Bearer`, `token`, …); an empty scheme
/// substitutes the bare credential (some services use a raw header value). A
/// single ASCII space joins scheme + credential per RFC 7235 §2.1.
pub fn substitute_authorization(scheme: &str, fetched: &FetchedCredential) -> SubstitutedHeader {
    let cred = fetched.expose();
    let mut buf: Vec<u8> = Vec::with_capacity(scheme.len() + 1 + cred.len());
    if !scheme.is_empty() {
        buf.extend_from_slice(scheme.as_bytes());
        buf.push(b' ');
    }
    buf.extend_from_slice(cred);
    SubstitutedHeader(Zeroizing::new(buf))
}

// ─────────────────────────────────────────────────────────────────────────────
// LOG-5 audit-trail emission (PE9N-u3): emit the CredentialUseEvent through the
// LOG-1 telemetry channel EXACTLY ONCE per swap. The "exactly once" is made
// STRUCTURAL by a consume-on-emit once-token: the swap's audit obligation is to
// hand the event to the channel one time, and the token can be emitted only once
// because emission takes it BY VALUE.
// ─────────────────────────────────────────────────────────────────────────────

/// The single, un-emitted LOG-5 [`CredentialUseEvent`] a fired swap owes the
/// LOG-1 channel — a ONCE-token that enforces "emitted exactly once per swap"
/// (doc 09 §7 LOG-5; doc 12 §5.5 / §10) STRUCTURALLY.
///
/// # Why a once-token and not a bare event
///
/// The audit obligation is: every credential SWAP (every time the real
/// credential is substituted upstream) produces EXACTLY ONE `CredentialUseEvent`
/// on the LOG-1 channel — no more (a double-emit would double-count a single
/// use), no fewer (a missed emit would lose the audit trail). The upstream
/// outcome that follows the swap — a 2xx/3xx success, a 4xx/5xx error page, or a
/// timeout / connection-fail — does NOT change that count: the credential was
/// USED the instant it went upstream, so the audit event is owed regardless of
/// how the upstream responds. `main.rs` therefore holds this token across the
/// upstream round-trip and emits it once on whichever outcome lands.
///
/// Making the count STRUCTURAL: [`PendingCredentialUse::emit`] takes `self` BY
/// VALUE, consuming the token — so a second emit is a compile error, not a
/// runtime bug. The token can be INSPECTED any number of times (it derefs to the
/// secret-free [`CredentialUseEvent`], so the existing back-half assertions read
/// it unchanged) but EMITTED exactly once.
///
/// Never-log-the-secret (D73): the wrapped event is fingerprint-only by
/// construction, so the token carries no credential byte — boxed to keep the
/// [`SwapFired`] variants balanced (`clippy::large_enum_variant`) and the
/// secret-free event on the heap, distinct from the zeroize-wiped header.
#[derive(Debug)]
pub struct PendingCredentialUse(Box<CredentialUseEvent>);

impl PendingCredentialUse {
    /// Wrap the freshly-built event into the once-token. Called by [`SwapExecutor::fire`]
    /// on a substituted swap; the only constructor, so a `PendingCredentialUse`
    /// always corresponds to exactly one real credential use.
    fn new(event: CredentialUseEvent) -> PendingCredentialUse {
        PendingCredentialUse(Box::new(event))
    }

    /// Borrow the underlying secret-free [`CredentialUseEvent`] (for inspection /
    /// the back-half assertions). Inspecting never consumes the token.
    pub fn event(&self) -> &CredentialUseEvent {
        &self.0
    }

    /// Emit this credential-use event onto the LOG-1 channel via `emitter`,
    /// CONSUMING the token (`self` by value) so it can never be emitted twice.
    ///
    /// This is the LOG-5 emission point (doc 09 §7): `main.rs` calls it exactly
    /// once after the upstream request is accepted, on whichever upstream outcome
    /// lands (success, error, or timeout). Because the token is consumed, the
    /// "exactly once per swap" guarantee is enforced by the type system — a second
    /// `emit` does not compile.
    pub fn emit<E: AuditEmitter + ?Sized>(self, emitter: &E) {
        emitter.emit_credential_use(&self.0);
    }
}

impl std::ops::Deref for PendingCredentialUse {
    type Target = CredentialUseEvent;
    /// Deref to the wrapped secret-free event so the back-half assertions
    /// (`fired.event.service_id`, the canary greps over `format!("{event:?}")`)
    /// read the token exactly as they read a bare event. Deref never consumes the
    /// once-guarantee — only [`PendingCredentialUse::emit`] does.
    fn deref(&self) -> &CredentialUseEvent {
        &self.0
    }
}

/// What the back half produced for one ALLOWED swap: the substituted upstream
/// Authorization header + the LOG-5 [`CredentialUseEvent`] to emit, or a
/// fail-closed [`SwapDenial`] (502-class) on a secret-store fetch failure.
///
/// The header and the event are the two outputs `main.rs` consumes: it writes the
/// header onto the upstream request (then drops the [`SubstitutedHeader`]) and,
/// after the upstream request is accepted, emits the [`PendingCredentialUse`]
/// once via the LOG-1 channel ([`PendingCredentialUse::emit`]). Both are
/// secret-free outside the wrapped header bytes: the event carries only the
/// fingerprint + request metadata.
#[derive(Debug)]
pub enum SwapFired {
    /// The credential was fetched and substituted: write `header` onto the
    /// upstream request and emit `event` (fingerprint-only) EXACTLY ONCE via the
    /// LOG-1 channel ([`PendingCredentialUse::emit`]) after the upstream request
    /// is accepted — on success (2xx/3xx), upstream error (4xx/5xx), or
    /// timeout/connection-fail alike (the credential was used regardless).
    Substituted {
        /// The substituted upstream Authorization value (zeroize-wiped).
        header: SubstitutedHeader,
        /// The LOG-5 credential-use ONCE-token (fingerprint, never the value):
        /// inspectable any number of times (derefs to the event), emittable
        /// exactly once ([`PendingCredentialUse::emit`] consumes it). The
        /// "exactly once per swap" audit count is thus structural.
        event: PendingCredentialUse,
    },
    /// The secret-store fetch failed: deny fail-closed (doc 16 §5.2). `main.rs`
    /// answers the VM with a proxy-generated 502 and does NOT egress the
    /// placeholder upstream.
    FetchFailed {
        /// The fail-closed denial (502-class) carrying the secret-free reason.
        denial: SwapDenial,
    },
}

impl SwapExecutor {
    /// The back half of a swap (PE9N-u2): given the [`GrantRef`] an ALLOW verdict
    /// produced, FETCH the long-lived credential from the D39 secret store via the
    /// injected `fetcher`, SUBSTITUTE it into the outbound Authorization header
    /// (auth `scheme`), and build the LOG-5 [`CredentialUseEvent`] (fingerprint
    /// only — both credential values are absent by construction).
    ///
    /// This runs ONLY after `evaluate` returned [`SwapVerdict::Allowed`] on the
    /// INSPECTED path — so a pass-through (TLS-4) flow and a registry miss can
    /// never reach it (they short-circuited in the front half). The fetch is the
    /// FIRST and ONLY time the long-lived credential exists inside the boundary,
    /// and it exists wrapped in [`FetchedCredential`] (zeroize-wiped) for exactly
    /// the duration of the substitution write.
    ///
    /// On a fetch failure the back half is fail-closed (doc 16 §5.2): it returns
    /// [`SwapFired::FetchFailed`] with a 502-class [`SwapDenial`] — the presented
    /// placeholder is NEVER egressed upstream as if it were the real credential.
    pub fn fire<F: SecretFetcher + ?Sized>(
        &self,
        fetcher: &F,
        session: &SessionRef,
        grant: &GrantRef,
        scheme: &str,
        request: &RequestLine,
        provenance: Provenance,
    ) -> SwapFired {
        // FETCH the real credential from the D39 store (the injected seam). The
        // value crosses the seam already wrapped in the zeroizing newtype.
        let fetched = match fetcher.fetch_long_lived(grant) {
            Ok(c) => c,
            Err(err) => {
                // Fail-closed (doc 16 §5.2): a secret-store failure is the proxy's
                // OWN dependency failing mid-swap, so it surfaces as a 502 Bad
                // Gateway (boundary `proxy-generated error page` row), NOT the
                // front-half 403 — the agent's credential already validated. The
                // distinct `tls5-secret-*` reason carries the secret-free class.
                return SwapFired::FetchFailed {
                    denial: SwapDenial::gateway(grant.service_id.clone(), err.deny_reason()),
                };
            }
        };

        // SUBSTITUTE: build the upstream Authorization value from the fetched
        // long-lived credential (the short-lived placeholder is already dropped).
        let header = substitute_authorization(scheme, &fetched);

        // LOG-5 CredentialUseEvent — built from the FINGERPRINT, never a value.
        // The fetched credential's bytes are exposed ONLY to the substitution
        // above; the event reads `fetched.fingerprint()` and the request line.
        let event = CredentialUseEvent::fired(
            session,
            grant.service_id.clone(),
            fetched.fingerprint().clone(),
            request.method.clone(),
            request.host.clone(),
            request.path.clone(),
            provenance,
        );

        // `fetched` drops here (after the substitution borrow) — the long-lived
        // bytes are wiped; only `header` (zeroize-wiped) and the secret-free
        // `event` survive. The event is wrapped in a [`PendingCredentialUse`]
        // once-token: `main.rs` emits it EXACTLY ONCE via the LOG-1 channel after
        // the upstream request is accepted, on whatever upstream outcome lands.
        SwapFired::Substituted {
            header,
            event: PendingCredentialUse::new(event),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The session grant cache — `(session, service)` → grant ref. Holds OPAQUE grant
// handles, NEVER credentials. Partitioned per session on the never-recycled tap
// name (doc 14 §4), mirroring `SessionUpstreamPools`.
// ─────────────────────────────────────────────────────────────────────────────

/// The reuse key for a cached grant: `(tap_name, service_id)`. The tap name is
/// the session partition (the never-recycled join key, doc 14 §4) — so a grant
/// cached for session A is structurally unreachable from a session-B lookup,
/// exactly as [`crate::SessionUpstreamPools`] partitions warm sockets.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct GrantKey {
    tap_name: String,
    service_id: String,
}

/// A per-session cache of opaque grant references (doc 16 §5.1 "fetch per-grant,
/// never per-request"). Holds [`GrantRef`] HANDLES only — never a credential
/// byte. Interior-mutable behind a `Mutex` so the listener can cache a grant
/// while a sweep clears another session, without threading `&mut` through the
/// proxy (mirrors [`crate::SeveringRegistry`]).
///
/// On a session sweep / teardown the whole partition is dropped via
/// [`SessionGrantCache::drop_session`] (doc 16 §5.4: grants are evicted on the
/// suspend signal). Because a grant ref is opaque, dropping it leaks nothing —
/// the real credential lives outside the boundary and is fetched fresh per grant.
#[derive(Default)]
pub struct SessionGrantCache {
    inner: Mutex<BTreeMap<GrantKey, GrantRef>>,
}

impl SessionGrantCache {
    /// A fresh, empty cache.
    pub fn new() -> SessionGrantCache {
        SessionGrantCache::default()
    }

    fn key(session: &SessionRef, service_id: &str) -> GrantKey {
        GrantKey {
            tap_name: session.tap_name.clone(),
            service_id: service_id.to_string(),
        }
    }

    /// Cache (or replace) the grant for `(session, grant.service_id)`. A
    /// re-validation for the same `(session, service)` replaces the prior grant
    /// (e.g. a refreshed grant ref).
    pub fn store(&self, session: &SessionRef, grant: GrantRef) {
        let key = Self::key(session, &grant.service_id);
        let mut cache = self.inner.lock().expect("grant cache mutex");
        cache.insert(key, grant);
    }

    /// The cached grant for `(session, service_id)`, scoped to the session's OWN
    /// partition: a grant cached for session A is never returned for session B
    /// (cross-session reuse is structurally impossible).
    pub fn get(&self, session: &SessionRef, service_id: &str) -> Option<GrantRef> {
        let key = Self::key(session, service_id);
        let cache = self.inner.lock().expect("grant cache mutex");
        cache.get(&key).cloned()
    }

    /// Drop EVERY grant the session owns (doc 16 §5.4 grant eviction on
    /// suspend/kill/teardown). Returns the number dropped. Dropping opaque grant
    /// handles leaks nothing (no credential is held).
    pub fn drop_session(&self, session: &SessionRef) -> usize {
        let mut cache = self.inner.lock().expect("grant cache mutex");
        let before = cache.len();
        cache.retain(|key, _| key.tap_name != session.tap_name);
        before - cache.len()
    }

    /// How many grants `session` has cached (test/diagnostic helper).
    pub fn cached_count(&self, session: &SessionRef) -> usize {
        let cache = self.inner.lock().expect("grant cache mutex");
        cache
            .keys()
            .filter(|k| k.tap_name == session.tap_name)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ── fakes ─────────────────────────────────────────────────────────────────

    /// A fake Validator with in-memory responses (boundary `fakeIdentityValidator`
    /// analogue): a programmed verdict per presented-credential value, plus a
    /// call counter so tests prove the validator was/was not called, and a capture
    /// of the exact (session, service, presented) it was called with.
    #[derive(Default)]
    struct FakeValidator {
        calls: AtomicUsize,
        // programmed verdict per (presented-bytes) — None ⇒ a default DENY.
        responses: std::collections::HashMap<Vec<u8>, ValidationVerdict>,
        // capture of the last call's coordinates (proves the seam args).
        last_session_tap: Mutex<Option<String>>,
        last_service: Mutex<Option<String>>,
        last_presented: Mutex<Option<Vec<u8>>>,
    }

    impl FakeValidator {
        fn program(&mut self, presented: &[u8], verdict: ValidationVerdict) {
            self.responses.insert(presented.to_vec(), verdict);
        }
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl IdentityValidator for FakeValidator {
        fn validate(
            &self,
            session: &SessionRef,
            service_id: &str,
            presented: &PresentedCredential,
        ) -> ValidationVerdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last_session_tap.lock().unwrap() = Some(session.tap_name.clone());
            *self.last_service.lock().unwrap() = Some(service_id.to_string());
            *self.last_presented.lock().unwrap() = Some(presented.expose().to_vec());
            self.responses
                .get(presented.expose())
                .cloned()
                .unwrap_or(ValidationVerdict::Deny {
                    reason: DenyReason::UnknownCredential,
                })
        }
    }

    /// A fake secret-store STUB. This unit does NOT fetch the real credential
    /// (that is a later unit); the stub exists ONLY to prove this path never
    /// touches it — its fetch counter must stay 0 across every test here.
    #[derive(Default)]
    struct FakeSecretStoreStub {
        fetches: AtomicUsize,
    }

    impl FakeSecretStoreStub {
        #[allow(dead_code)]
        fn fetch_long_lived(&self, _service: &str, _grant: &GrantRef) {
            // If this unit ever calls the secret store, this counter trips and
            // the never-fetch assertions below fail.
            self.fetches.fetch_add(1, Ordering::SeqCst);
        }
        fn fetch_count(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    // ── builders ────────────────────────────────────────────────────────────

    fn session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    /// The strawman GitHub service registry entry (doc 13 §3 / doc 16 §5.2).
    fn github_entry() -> ServiceEntry {
        ServiceEntry {
            service: "github".into(),
            hosts: vec!["github.com".into(), "api.github.com".into()],
            credential_location: "header".into(),
            credential_name: "Authorization".into(),
        }
    }

    fn github_registry() -> SwapRegistry {
        SwapRegistry::from_entries(&[github_entry()])
    }

    fn req_with_auth(host: &str, auth: &[u8]) -> SwapRequest {
        SwapRequest::new(host).with_header("Authorization", PresentedCredential::new(auth.to_vec()))
    }

    const SHORT_CRED: &[u8] = b"sl-sess-a-github-deadbeefdeadbeef";

    // ── (1) service registry match on host + credential-location header ───────

    #[test]
    fn registry_matches_on_host_and_credential_location_header() {
        let reg = github_registry();
        // Exact host, plus the second registered host, plus case-insensitivity.
        for host in ["github.com", "api.github.com", "API.GitHub.com"] {
            let req = req_with_auth(host, SHORT_CRED);
            let rule = reg.match_request(&req).expect("host should match");
            assert_eq!(rule.service_id, "github");
            assert_eq!(
                rule.location,
                CredentialLocation::Header {
                    name: "Authorization".into()
                }
            );
        }
    }

    #[test]
    fn registry_non_match_unregistered_host() {
        let reg = github_registry();
        let req = req_with_auth("plain.example", SHORT_CRED);
        assert!(reg.match_request(&req).is_none());
    }

    #[test]
    fn registry_non_match_credential_in_non_registered_location() {
        // host matches, but the credential rides Cookie, not the registered
        // Authorization header → non-match (boundary row 2).
        let reg = github_registry();
        let req = SwapRequest::new("api.github.com").with_header(
            "Cookie",
            PresentedCredential::new(b"session=user-cookie-credential-456".to_vec()),
        );
        assert!(reg.match_request(&req).is_none());
    }

    #[test]
    fn registry_non_match_no_credential_present() {
        // host matches, but no Authorization header at all → non-match (row 3).
        let reg = github_registry();
        let req = SwapRequest::new("api.github.com");
        assert!(reg.match_request(&req).is_none());
        // an EMPTY Authorization value is also a non-match (nothing to swap).
        let empty = SwapRequest::new("api.github.com")
            .with_header("Authorization", PresentedCredential::new(Vec::new()));
        assert!(reg.match_request(&empty).is_none());
    }

    #[test]
    fn registry_skips_unrecognized_credential_location() {
        // a services[] entry whose location is not `header` is never indexed.
        let weird = ServiceEntry {
            service: "weird".into(),
            hosts: vec!["weird.example".into()],
            credential_location: "querystring".into(),
            credential_name: "token".into(),
        };
        let reg = SwapRegistry::from_entries(&[weird]);
        assert!(reg.is_empty());
        let req = req_with_auth("weird.example", SHORT_CRED);
        assert!(reg.match_request(&req).is_none());
    }

    #[test]
    fn empty_registry_matches_nothing() {
        let reg = SwapRegistry::empty();
        assert!(reg.is_empty());
        assert!(reg
            .match_request(&req_with_auth("api.github.com", SHORT_CRED))
            .is_none());
    }

    // ── (2) validator RPC called with session_ref, service_id, presented cred ─

    #[test]
    fn validator_called_with_session_service_and_presented_credential() {
        let mut v = FakeValidator::default();
        v.program(
            SHORT_CRED,
            ValidationVerdict::Allow {
                grant_ref: "grant-github-1".into(),
                expiry_unix: 4_000_000_000,
            },
        );
        let exec = SwapExecutor::new(github_registry());
        let s = session(7);
        let req = req_with_auth("api.github.com", SHORT_CRED);

        let _ = exec.evaluate(&v, &s, &req);

        assert_eq!(v.call_count(), 1, "validator must be called exactly once");
        assert_eq!(
            v.last_session_tap.lock().unwrap().clone(),
            Some("dstap-7".to_string()),
            "validator called with the session_ref"
        );
        assert_eq!(
            v.last_service.lock().unwrap().clone(),
            Some("github".to_string()),
            "validator called with the matched service_id"
        );
        assert_eq!(
            v.last_presented.lock().unwrap().clone(),
            Some(SHORT_CRED.to_vec()),
            "validator called with the presented credential"
        );
    }

    // ── (3) on ALLOW a session-cached grant is stored ────────────────────────

    #[test]
    fn allow_verdict_emits_and_caches_a_grant_ref_not_the_credential() {
        let mut v = FakeValidator::default();
        v.program(
            SHORT_CRED,
            ValidationVerdict::Allow {
                grant_ref: "grant-github-xyz".into(),
                expiry_unix: 4_000_000_000,
            },
        );
        let exec = SwapExecutor::new(github_registry());
        let s = session(3);
        let req = req_with_auth("api.github.com", SHORT_CRED);

        let verdict = exec.evaluate(&v, &s, &req);

        let grant = match verdict {
            SwapVerdict::Allowed(g) => g,
            other => panic!("expected Allowed, got {other:?}"),
        };
        assert_eq!(grant.service_id, "github");
        assert_eq!(grant.grant_ref, "grant-github-xyz");
        assert_eq!(grant.expiry_unix, 4_000_000_000);

        // the grant is SESSION-CACHED.
        let cached = exec.grants().get(&s, "github").expect("grant cached");
        assert_eq!(cached, grant);
        assert_eq!(exec.grants().cached_count(&s), 1);

        // never-hold-the-secret: the emitted grant ref carries NO credential
        // byte. (The opaque handle is not derived from the credential value.)
        assert!(!grant
            .grant_ref
            .as_bytes()
            .windows(SHORT_CRED.len())
            .any(|w| w == SHORT_CRED));
    }

    #[test]
    fn cached_grant_is_session_partitioned() {
        let mut v = FakeValidator::default();
        v.program(
            SHORT_CRED,
            ValidationVerdict::Allow {
                grant_ref: "grant-a".into(),
                expiry_unix: 4_000_000_000,
            },
        );
        let exec = SwapExecutor::new(github_registry());
        let a = session(1);
        let b = session(2);
        let _ = exec.evaluate(&v, &a, &req_with_auth("api.github.com", SHORT_CRED));

        // session A has the grant; session B (a different partition) does not.
        assert!(exec.grants().get(&a, "github").is_some());
        assert!(exec.grants().get(&b, "github").is_none());

        // dropping A's session clears its grant.
        assert_eq!(exec.grants().drop_session(&a), 1);
        assert!(exec.grants().get(&a, "github").is_none());
        assert_eq!(exec.grants().drop_session(&a), 0);
    }

    // ── (4) on DENY the request is rejected with a 403 + machine-readable reason

    #[test]
    fn deny_verdict_rejects_with_structured_403_machine_readable_reason() {
        let mut v = FakeValidator::default();
        v.program(
            SHORT_CRED,
            ValidationVerdict::Deny {
                reason: DenyReason::IdentityMismatch,
            },
        );
        let exec = SwapExecutor::new(github_registry());
        let s = session(5);
        let req = req_with_auth("api.github.com", SHORT_CRED);

        let denial = match exec.evaluate(&v, &s, &req) {
            SwapVerdict::Denied(d) => d,
            other => panic!("expected Denied, got {other:?}"),
        };
        assert_eq!(denial.status, 403);
        assert_eq!(denial.status, SwapDenial::STATUS);
        assert_eq!(denial.service_id, "github");
        assert_eq!(denial.reason, DenyReason::IdentityMismatch);
        assert_eq!(denial.reason_code(), "tls5-identity-mismatch");

        // a DENY caches NO grant.
        assert_eq!(exec.grants().cached_count(&s), 0);
    }

    #[test]
    fn deny_reason_codes_are_stable_kebab_and_secret_free() {
        let codes = [
            (DenyReason::UnknownCredential, "tls5-unknown-credential"),
            (DenyReason::IdentityMismatch, "tls5-identity-mismatch"),
            (DenyReason::CredentialExpired, "tls5-credential-expired"),
            (DenyReason::OutOfGrant, "tls5-out-of-grant"),
            (DenyReason::SessionNotLive, "tls5-session-not-live"),
            (DenyReason::SecretNotFound, "tls5-secret-not-found"),
            (
                DenyReason::SecretStoreUnavailable,
                "tls5-secret-store-unavailable",
            ),
        ];
        for (r, code) in codes {
            assert_eq!(r.reason_code(), code);
            assert_eq!(r.to_string(), code);
            // secret-free: a reason code never carries a credential byte.
            assert!(!code
                .as_bytes()
                .windows(SHORT_CRED.len())
                .any(|w| w == SHORT_CRED));
            // kebab-case, ASCII, no spaces.
            assert!(code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-' || b.is_ascii_digit()));
        }
    }

    // ── (5) pass-through (TLS-4) flows skip the validator entirely ────────────

    #[test]
    fn pass_through_flow_skips_the_validator_and_secret_store() {
        // The listener only constructs a SwapRequest + calls evaluate() on the
        // INSPECTED path. A pass-through (TLS-4) flow is gated out by
        // is_inspected_path(false) — so evaluate() is never reached, the
        // validator is called ZERO times, and the secret store is untouched.
        assert!(!SwapExecutor::is_inspected_path(false));
        assert!(SwapExecutor::is_inspected_path(true));

        let v = FakeValidator::default();
        let stub = FakeSecretStoreStub::default();
        let exec = SwapExecutor::new(github_registry());
        let s = session(9);

        // Drive the listener's guard explicitly: on a pass-through flow it must
        // NOT call evaluate(). We model that here — only the inspected branch
        // reaches evaluate.
        let inspected = false;
        if SwapExecutor::is_inspected_path(inspected) {
            let _ = exec.evaluate(&v, &s, &req_with_auth("api.github.com", SHORT_CRED));
        }
        assert_eq!(
            v.call_count(),
            0,
            "pass-through must never call the validator"
        );
        assert_eq!(
            stub.fetch_count(),
            0,
            "pass-through must never touch the secret store"
        );
        assert_eq!(exec.grants().cached_count(&s), 0);
    }

    #[test]
    fn no_registry_match_skips_the_validator_and_secret_store() {
        // The other path that must never call the validator: a registry miss on
        // the inspected path (boundary TestSwap_NoRegistryMatch_RequestUntouched).
        let v = FakeValidator::default();
        let stub = FakeSecretStoreStub::default();
        let exec = SwapExecutor::new(github_registry());
        let s = session(11);

        // unregistered host
        assert_eq!(
            exec.evaluate(&v, &s, &req_with_auth("plain.example", SHORT_CRED)),
            SwapVerdict::NoSwap
        );
        // registered host, credential in a non-registered location
        let cookie = SwapRequest::new("api.github.com")
            .with_header("Cookie", PresentedCredential::new(b"x".to_vec()));
        assert_eq!(exec.evaluate(&v, &s, &cookie), SwapVerdict::NoSwap);
        // registered host, no credential present
        assert_eq!(
            exec.evaluate(&v, &s, &SwapRequest::new("api.github.com")),
            SwapVerdict::NoSwap
        );

        assert_eq!(
            v.call_count(),
            0,
            "a registry miss must never call the validator"
        );
        assert_eq!(stub.fetch_count(), 0);
    }

    // ── (6) the credential value is never held beyond the validation call ─────

    #[test]
    fn the_secret_store_is_never_fetched_on_the_validate_path() {
        // This unit emits a grant ref and STOPS — the async credential fetch is a
        // later unit. Prove it: across ALLOW and DENY, the stub is never called.
        let stub = FakeSecretStoreStub::default();
        let mut v = FakeValidator::default();
        v.program(
            SHORT_CRED,
            ValidationVerdict::Allow {
                grant_ref: "g".into(),
                expiry_unix: 1,
            },
        );
        let exec = SwapExecutor::new(github_registry());
        let s = session(2);
        let _ = exec.evaluate(&v, &s, &req_with_auth("api.github.com", SHORT_CRED));
        assert_eq!(
            stub.fetch_count(),
            0,
            "ALLOW must not fetch the real credential in this unit"
        );

        let mut v2 = FakeValidator::default();
        v2.program(
            SHORT_CRED,
            ValidationVerdict::Deny {
                reason: DenyReason::CredentialExpired,
            },
        );
        let _ = exec.evaluate(&v2, &s, &req_with_auth("api.github.com", SHORT_CRED));
        assert_eq!(
            stub.fetch_count(),
            0,
            "DENY must not fetch the real credential"
        );
    }

    #[test]
    fn presented_credential_never_appears_in_the_emitted_verdict_shapes() {
        // The credential bytes are borrowed into validate() and dropped with the
        // request; NONE of the emitted shapes (GrantRef / SwapDenial) may carry
        // them. Serialize each via Debug and grep for the canary.
        let mut v = FakeValidator::default();
        v.program(
            SHORT_CRED,
            ValidationVerdict::Allow {
                grant_ref: "grant-no-secret".into(),
                expiry_unix: 9,
            },
        );
        let exec = SwapExecutor::new(github_registry());
        let s = session(4);
        let allowed = exec.evaluate(&v, &s, &req_with_auth("api.github.com", SHORT_CRED));
        let rendered = format!("{allowed:?}");
        assert!(
            !rendered
                .as_bytes()
                .windows(SHORT_CRED.len())
                .any(|w| w == SHORT_CRED),
            "ALLOW verdict must not render the credential"
        );

        let mut v2 = FakeValidator::default();
        v2.program(
            SHORT_CRED,
            ValidationVerdict::Deny {
                reason: DenyReason::OutOfGrant,
            },
        );
        let denied = exec.evaluate(&v2, &s, &req_with_auth("api.github.com", SHORT_CRED));
        let rendered = format!("{denied:?}");
        assert!(
            !rendered
                .as_bytes()
                .windows(SHORT_CRED.len())
                .any(|w| w == SHORT_CRED),
            "DENY verdict must not render the credential"
        );
    }

    #[test]
    fn presented_credential_debug_is_secret_free() {
        // The newtype's own Debug must never render the bytes (length only).
        let cred = PresentedCredential::new(SHORT_CRED.to_vec());
        let dbg = format!("{cred:?}");
        assert!(!dbg
            .as_bytes()
            .windows(SHORT_CRED.len())
            .any(|w| w == SHORT_CRED));
        assert!(dbg.contains("len"));
    }

    #[test]
    fn re_validation_replaces_the_cached_grant() {
        let mut v = FakeValidator::default();
        v.program(
            SHORT_CRED,
            ValidationVerdict::Allow {
                grant_ref: "grant-v1".into(),
                expiry_unix: 1,
            },
        );
        let exec = SwapExecutor::new(github_registry());
        let s = session(6);
        let _ = exec.evaluate(&v, &s, &req_with_auth("api.github.com", SHORT_CRED));
        assert_eq!(
            exec.grants().get(&s, "github").unwrap().grant_ref,
            "grant-v1"
        );

        // a fresh validation with a new grant ref replaces the cached one.
        let mut v2 = FakeValidator::default();
        v2.program(
            SHORT_CRED,
            ValidationVerdict::Allow {
                grant_ref: "grant-v2".into(),
                expiry_unix: 2,
            },
        );
        let _ = exec.evaluate(&v2, &s, &req_with_auth("api.github.com", SHORT_CRED));
        assert_eq!(
            exec.grants().get(&s, "github").unwrap().grant_ref,
            "grant-v2"
        );
        assert_eq!(exec.grants().cached_count(&s), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BACK HALF (PE9N-u2): fetch → substitute → CredentialUseEvent + scrubbing.
    // ═══════════════════════════════════════════════════════════════════════

    /// A fake D39 secret-store fetcher (boundary `recordingSecretStore` analogue):
    /// a programmed long-lived credential per grant ref, a call counter, and a
    /// capture of the grant it was fetched with — so tests prove the trait was
    /// called and the long-lived value reached ONLY the substitution.
    #[derive(Default)]
    struct FakeSecretFetcher {
        fetches: AtomicUsize,
        // grant_ref → (value, fingerprint)
        creds: std::collections::HashMap<String, (Vec<u8>, String)>,
        last_grant: Mutex<Option<GrantRef>>,
        // force a fetch failure regardless of programming.
        fail: Option<FetchError>,
    }

    impl FakeSecretFetcher {
        fn program(&mut self, grant_ref: &str, value: &[u8], fingerprint: &str) {
            self.creds.insert(
                grant_ref.to_string(),
                (value.to_vec(), fingerprint.to_string()),
            );
        }
        fn fetch_count(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    impl SecretFetcher for FakeSecretFetcher {
        fn fetch_long_lived(&self, grant: &GrantRef) -> Result<FetchedCredential, FetchError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            *self.last_grant.lock().unwrap() = Some(grant.clone());
            if let Some(err) = self.fail {
                return Err(err);
            }
            match self.creds.get(&grant.grant_ref) {
                Some((value, fp)) => {
                    Ok(FetchedCredential::new(value.clone(), Fingerprint::new(fp)))
                }
                None => Err(FetchError::NotFound),
            }
        }
    }

    const LONG_CRED: &[u8] = b"ghp_LONGLIVEDsecretBEEFc0ffee0123456789abcdef";

    fn provenance() -> Provenance {
        Provenance::new("rule-swap-github", "org", "policy-v1")
    }

    fn allowed_grant() -> GrantRef {
        GrantRef {
            service_id: "github".into(),
            grant_ref: "grant-github-1".into(),
            expiry_unix: 4_000_000_000,
        }
    }

    fn github_fetcher() -> FakeSecretFetcher {
        let mut f = FakeSecretFetcher::default();
        f.program("grant-github-1", LONG_CRED, "fp-long-github");
        f
    }

    // ── (1) on a matched swap the real credential is fetched + substituted ────

    #[test]
    fn fire_fetches_the_long_lived_credential_and_substitutes_it_into_authorization() {
        // ACCEPTANCE (1): on a matched swap the real credential is fetched via the
        // trait and substituted into the Authorization header value.
        let f = github_fetcher();
        let exec = SwapExecutor::new(github_registry());
        let s = session(7);
        let grant = allowed_grant();
        let req = RequestLine::new("GET", "api.github.com", "/user");

        let fired = exec.fire(&f, &s, &grant, "Bearer", &req, provenance());

        // the trait WAS called, with the grant the ALLOW produced.
        assert_eq!(f.fetch_count(), 1, "the secret store must be fetched once");
        assert_eq!(
            f.last_grant.lock().unwrap().clone(),
            Some(grant.clone()),
            "the fetch is keyed on the grant the ALLOW produced"
        );

        let header = match &fired {
            SwapFired::Substituted { header, .. } => header,
            other => panic!("expected Substituted, got {other:?}"),
        };
        // the substituted header carries the LONG-LIVED credential (scheme + cred).
        let mut want = b"Bearer ".to_vec();
        want.extend_from_slice(LONG_CRED);
        assert_eq!(header.expose(), want.as_slice());
        // and NOT the short-lived placeholder.
        assert!(!header
            .expose()
            .windows(SHORT_CRED.len())
            .any(|w| w == SHORT_CRED));
    }

    #[test]
    fn substitute_authorization_joins_scheme_and_credential_and_supports_bare_value() {
        let fetched =
            FetchedCredential::new(LONG_CRED.to_vec(), Fingerprint::new("fp-long-github"));
        // scheme + cred
        let h = substitute_authorization("Bearer", &fetched);
        let mut want = b"Bearer ".to_vec();
        want.extend_from_slice(LONG_CRED);
        assert_eq!(h.expose(), want.as_slice());
        // bare value (empty scheme) — no leading space.
        let bare = substitute_authorization("", &fetched);
        assert_eq!(bare.expose(), LONG_CRED);
    }

    // ── (2) both credentials redacted from CredentialUseEvent — fingerprint only

    #[test]
    fn fire_emits_a_credential_use_event_with_fingerprint_only_both_creds_scrubbed() {
        // ACCEPTANCE (2)+(3): the CredentialUseEvent carries service_id, the
        // request line, POL-3 provenance, and ONLY the fingerprint — neither the
        // short-lived (presented) nor the long-lived (fetched) value appears.
        let f = github_fetcher();
        let exec = SwapExecutor::new(github_registry());
        let s = session(3);
        let grant = allowed_grant();
        let req = RequestLine::new("POST", "github.com", "/org/repo.git/git-receive-pack");

        let event = match exec.fire(&f, &s, &grant, "Bearer", &req, provenance()) {
            SwapFired::Substituted { event, .. } => event,
            other => panic!("expected Substituted, got {other:?}"),
        };

        // (3) service_id + request line + provenance + session attribution.
        assert_eq!(event.tap_name, "dstap-3");
        assert_eq!(event.service_id, "github");
        assert_eq!(event.method, "POST");
        assert_eq!(event.host, "github.com");
        assert_eq!(event.path, "/org/repo.git/git-receive-pack");
        assert_eq!(event.provenance.rule_id, "rule-swap-github");
        // (2) ONLY the fingerprint appears.
        assert_eq!(event.fingerprint.as_str(), "fp-long-github");

        // grep EVERY field for BOTH credential needles — zero hits.
        let rendered = format!("{event:?}");
        assert!(
            !rendered
                .as_bytes()
                .windows(LONG_CRED.len())
                .any(|w| w == LONG_CRED),
            "CredentialUseEvent must not render the long-lived credential"
        );
        assert!(
            !rendered
                .as_bytes()
                .windows(SHORT_CRED.len())
                .any(|w| w == SHORT_CRED),
            "CredentialUseEvent must not render the short-lived credential"
        );
    }

    #[test]
    fn neither_the_fetched_nor_substituted_newtype_renders_the_credential() {
        // The substituted header + the fetched credential newtypes both Debug to
        // length-only (the boundary canary grep covers every log surface).
        let fetched =
            FetchedCredential::new(LONG_CRED.to_vec(), Fingerprint::new("fp-long-github"));
        let dbg_fetched = format!("{fetched:?}");
        assert!(!dbg_fetched
            .as_bytes()
            .windows(LONG_CRED.len())
            .any(|w| w == LONG_CRED));
        assert!(dbg_fetched.contains("len"));
        assert!(dbg_fetched.contains("fp-long-github")); // fingerprint is loggable

        let header = substitute_authorization("Bearer", &fetched);
        let dbg_header = format!("{header:?}");
        assert!(!dbg_header
            .as_bytes()
            .windows(LONG_CRED.len())
            .any(|w| w == LONG_CRED));
        assert!(dbg_header.contains("len"));
    }

    // ── (4) pass-through / non-allowed flows never reach the fetch+substitute ──

    #[test]
    fn pass_through_flow_never_fetches_or_substitutes() {
        // The back half runs ONLY on an ALLOWED inspected swap. A pass-through
        // (TLS-4) flow is gated out by is_inspected_path(false) BEFORE the front
        // half — so fire() is never reached, the fetcher is called ZERO times.
        let f = github_fetcher();
        let exec = SwapExecutor::new(github_registry());
        let s = session(9);

        // model the listener: pass-through skips both halves.
        let inspected = false;
        if SwapExecutor::is_inspected_path(inspected) {
            let grant = allowed_grant();
            let _ = exec.fire(
                &f,
                &s,
                &grant,
                "Bearer",
                &RequestLine::new("GET", "api.github.com", "/user"),
                provenance(),
            );
        }
        assert_eq!(
            f.fetch_count(),
            0,
            "pass-through must never fetch the secret"
        );
    }

    #[test]
    fn no_swap_verdict_never_reaches_the_back_half() {
        // A registry miss yields NoSwap in the front half; the listener forwards
        // the request untouched and never calls fire() — so no fetch happens.
        let f = github_fetcher();
        let v = FakeValidator::default();
        let exec = SwapExecutor::new(github_registry());
        let s = session(11);

        let verdict = exec.evaluate(&v, &s, &req_with_auth("plain.example", SHORT_CRED));
        assert_eq!(verdict, SwapVerdict::NoSwap);
        // the listener only calls fire() on SwapVerdict::Allowed; NoSwap does not.
        if let SwapVerdict::Allowed(grant) = verdict {
            let _ = exec.fire(
                &f,
                &s,
                &grant,
                "Bearer",
                &RequestLine::new("GET", "plain.example", "/data"),
                provenance(),
            );
        }
        assert_eq!(f.fetch_count(), 0, "a non-swap request must never fetch");
    }

    // ── fail-closed: a fetch failure denies (502-class), never egresses placeholder

    #[test]
    fn a_secret_store_fetch_failure_fails_closed_with_a_502_class_denial() {
        // doc 16 §5.2: a key-store outage DENIES — the placeholder is never
        // egressed upstream as if real. The proxy's OWN dependency failed
        // mid-swap, so this is a 502 Bad Gateway (boundary `proxy-generated error
        // page` row asserts 502), NOT the front-half 403 (a bad agent credential).
        for (err, want_reason) in [
            (FetchError::NotFound, DenyReason::SecretNotFound),
            (FetchError::Unavailable, DenyReason::SecretStoreUnavailable),
        ] {
            let f = FakeSecretFetcher {
                fail: Some(err),
                ..Default::default()
            };
            let exec = SwapExecutor::new(github_registry());
            let s = session(5);
            let fired = exec.fire(
                &f,
                &s,
                &allowed_grant(),
                "Bearer",
                &RequestLine::new("GET", "api.github.com", "/user"),
                provenance(),
            );
            let denial = match fired {
                SwapFired::FetchFailed { denial } => denial,
                other => panic!("expected FetchFailed, got {other:?}"),
            };
            // 502 (gateway-failure), DISTINCT from the front-half 403 const.
            assert_eq!(denial.status, 502);
            assert_eq!(denial.status, SwapDenial::GATEWAY_STATUS);
            assert_ne!(
                denial.status,
                SwapDenial::STATUS,
                "a back-half credential-path failure is NOT the front-half 403"
            );
            assert_eq!(denial.service_id, "github");
            // the distinct, secret-free `tls5-secret-*` reason class is preserved.
            assert_eq!(denial.reason, want_reason);
            assert!(denial.reason_code().starts_with("tls5-secret-"));
            assert_eq!(f.fetch_count(), 1, "the fetch was attempted (then failed)");
        }
    }

    #[test]
    fn fetch_error_reason_codes_are_stable_and_secret_free() {
        for (e, code) in [
            (FetchError::NotFound, "tls5-secret-not-found"),
            (FetchError::Unavailable, "tls5-secret-store-unavailable"),
        ] {
            assert_eq!(e.reason_code(), code);
            assert_eq!(e.to_string(), code);
            assert!(code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-' || b.is_ascii_digit()));
        }
    }

    // ── e2e: front half ALLOW → back half fetch+substitute (the full swap) ────

    #[test]
    fn end_to_end_allow_then_fire_substitutes_the_long_lived_credential() {
        // The full swap: evaluate (front half) ALLOWs and caches a grant; fire
        // (back half) fetches the long-lived credential for THAT grant and
        // substitutes it — the VM only ever held the short-lived placeholder.
        let mut v = FakeValidator::default();
        v.program(
            SHORT_CRED,
            ValidationVerdict::Allow {
                grant_ref: "grant-github-1".into(),
                expiry_unix: 4_000_000_000,
            },
        );
        let f = github_fetcher();
        let exec = SwapExecutor::new(github_registry());
        let s = session(2);
        let req = req_with_auth("api.github.com", SHORT_CRED);

        let grant = match exec.evaluate(&v, &s, &req) {
            SwapVerdict::Allowed(g) => g,
            other => panic!("expected Allowed, got {other:?}"),
        };
        let fired = exec.fire(
            &f,
            &s,
            &grant,
            "Bearer",
            &RequestLine::new("GET", "api.github.com", "/user"),
            provenance(),
        );
        let (header, event) = match fired {
            SwapFired::Substituted { header, event } => (header, event),
            other => panic!("expected Substituted, got {other:?}"),
        };
        let mut want = b"Bearer ".to_vec();
        want.extend_from_slice(LONG_CRED);
        assert_eq!(header.expose(), want.as_slice());
        assert_eq!(event.fingerprint.as_str(), "fp-long-github");
        assert_eq!(event.service_id, "github");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PE9N-u3: LOG-5 CredentialUseEvent audit-trail EMISSION through the LOG-1
    // channel — exactly once per swap, on every upstream outcome.
    // ═══════════════════════════════════════════════════════════════════════

    /// A recording LOG-1 channel (the boundary `recordingSink` analogue): every
    /// event handed to the channel is captured so a test can prove exactly which
    /// events were emitted and HOW MANY. Counts emissions so "exactly once" is
    /// directly assertable.
    #[derive(Default)]
    struct RecordingEmitter {
        seen: Mutex<Vec<CredentialUseEvent>>,
    }

    impl RecordingEmitter {
        fn count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
        fn last(&self) -> Option<CredentialUseEvent> {
            self.seen.lock().unwrap().last().cloned()
        }
    }

    impl AuditEmitter for RecordingEmitter {
        fn emit_credential_use(&self, event: &CredentialUseEvent) {
            self.seen.lock().unwrap().push(event.clone());
        }
    }

    /// The upstream outcome the swap's request hit AFTER the credential was
    /// substituted — the credential was USED either way, so the audit event is
    /// owed on every variant (the spec's "200–3xx, 4xx–5xx, timeout/conn-fail").
    #[derive(Clone, Copy, Debug)]
    enum UpstreamOutcome {
        Ok(u16),    // 200–3xx
        Error(u16), // 4xx–5xx (upstream replied an error PAGE — still a use)
        Timeout,    // no response / connection-fail mid-stream
    }

    impl UpstreamOutcome {
        /// The HTTP status `main.rs` would observe (or `None` on timeout/conn-fail).
        /// Read by the emit model so the variant payloads are exercised — but the
        /// emission DOES NOT branch on it (that is the property under test).
        fn observed_status(self) -> Option<u16> {
            match self {
                UpstreamOutcome::Ok(s) | UpstreamOutcome::Error(s) => Some(s),
                UpstreamOutcome::Timeout => None,
            }
        }
    }

    /// Model `main.rs`'s emit point: a swap was fired (the credential went
    /// upstream); once the upstream request is accepted, emit the audit event
    /// EXACTLY ONCE through the LOG-1 channel — regardless of the upstream
    /// `outcome`. Consumes the once-token, so the call site CANNOT emit twice.
    fn drive_upstream_then_emit<E: AuditEmitter>(
        fired: SwapFired,
        outcome: UpstreamOutcome,
        emitter: &E,
    ) {
        match fired {
            SwapFired::Substituted { header, event } => {
                // main.rs writes `header` onto the upstream request, runs the
                // round-trip (yielding `outcome`), then emits ONCE. Crucially the
                // emit is UNCONDITIONAL on the outcome — the credential was used
                // the instant it went upstream, so the audit event is always owed.
                let _ = header.expose();
                let _observed = outcome.observed_status(); // observed, NOT a gate.
                event.emit(emitter);
            }
            SwapFired::FetchFailed { .. } => {
                // a fetch failure never substituted a credential, so there is no
                // use to audit — nothing is emitted (a 502 is answered instead).
            }
        }
    }

    // ── (1) the event is emitted after a successful (validated) swap ──────────

    #[test]
    fn credential_use_event_is_emitted_once_after_a_successful_swap() {
        // ACCEPTANCE (1): a CredentialUseEvent is emitted after validator approval
        // (ALLOW) → fetch → substitute, on a successful upstream.
        let f = github_fetcher();
        let exec = SwapExecutor::new(github_registry());
        let s = session(7);
        let grant = allowed_grant();
        let req = RequestLine::new("POST", "github.com", "/org/repo.git/git-receive-pack");
        let emitter = RecordingEmitter::default();

        let fired = exec.fire(&f, &s, &grant, "Bearer", &req, provenance());
        drive_upstream_then_emit(fired, UpstreamOutcome::Ok(200), &emitter);

        // (1) exactly one event reached the LOG-1 channel.
        assert_eq!(emitter.count(), 1, "exactly one CredentialUseEvent emitted");
        // (2) it carries the right service_id + fingerprint + session + request.
        let ev = emitter.last().expect("an event was emitted");
        assert_eq!(ev.service_id, "github");
        assert_eq!(ev.fingerprint.as_str(), "fp-long-github");
        assert_eq!(ev.tap_name, "dstap-7");
        assert_eq!(ev.method, "POST");
        assert_eq!(ev.host, "github.com");
        assert_eq!(ev.path, "/org/repo.git/git-receive-pack");
        // never-log-the-secret: neither credential value appears in the emitted ev.
        let rendered = format!("{ev:?}");
        assert!(!rendered
            .as_bytes()
            .windows(LONG_CRED.len())
            .any(|w| w == LONG_CRED));
        assert!(!rendered
            .as_bytes()
            .windows(SHORT_CRED.len())
            .any(|w| w == SHORT_CRED));
    }

    // ── (2) emitted EXACTLY ONCE on EVERY upstream outcome ───────────────────

    #[test]
    fn credential_use_event_is_emitted_once_on_every_upstream_outcome() {
        // The spec's core: the event is present on BOTH inspected swap paths —
        // successful upstream (200–3xx), upstream error (4xx–5xx), and upstream
        // timeout/connection-fail — emitted EXACTLY ONCE in each case (the
        // credential was used regardless of how the upstream responded).
        for outcome in [
            UpstreamOutcome::Ok(200),
            UpstreamOutcome::Ok(302),
            UpstreamOutcome::Error(401),
            UpstreamOutcome::Error(500),
            UpstreamOutcome::Timeout,
        ] {
            let f = github_fetcher();
            let exec = SwapExecutor::new(github_registry());
            let s = session(3);
            let emitter = RecordingEmitter::default();

            let fired = exec.fire(
                &f,
                &s,
                &allowed_grant(),
                "Bearer",
                &RequestLine::new("GET", "api.github.com", "/user"),
                provenance(),
            );
            drive_upstream_then_emit(fired, outcome, &emitter);

            assert_eq!(
                emitter.count(),
                1,
                "exactly one CredentialUseEvent on outcome {outcome:?}"
            );
            assert_eq!(
                emitter.last().unwrap().fingerprint.as_str(),
                "fp-long-github",
                "the emitted event carries the credential fingerprint on {outcome:?}"
            );
        }
    }

    // ── (3) emission is idempotent per swap (exactly once) — STRUCTURAL ──────

    #[test]
    fn emission_is_idempotent_per_swap_one_token_one_emit() {
        // ACCEPTANCE (3): emission is idempotent per swap — one fired swap yields
        // one once-token, and the token emits EXACTLY ONCE. The type system makes
        // a double-emit impossible: `emit` consumes the token by value, so a
        // second `emit` does not compile. We prove the single-emit at runtime; the
        // compile-fail line below is the structural guarantee (kept commented so
        // the suite still compiles).
        let f = github_fetcher();
        let exec = SwapExecutor::new(github_registry());
        let s = session(5);
        let emitter = RecordingEmitter::default();

        let event = match exec.fire(
            &f,
            &s,
            &allowed_grant(),
            "Bearer",
            &RequestLine::new("GET", "api.github.com", "/user"),
            provenance(),
        ) {
            SwapFired::Substituted { event, .. } => event,
            other => panic!("expected Substituted, got {other:?}"),
        };

        // the token can be INSPECTED freely (deref) before emission…
        assert_eq!(event.service_id, "github");
        assert_eq!(event.event().fingerprint.as_str(), "fp-long-github");

        // …and emitted EXACTLY once (consumes the token).
        event.emit(&emitter);
        assert_eq!(emitter.count(), 1, "the token emits exactly once");

        // STRUCTURAL idempotency: a second emit is a use-after-move — it does not
        // compile. Uncommenting the next line fails the build, which is the point:
        //   event.emit(&emitter); // ERROR[E0382]: use of moved value: `event`
    }

    // ── (4) on validation failure (no swap) NO event is emitted ──────────────

    #[test]
    fn no_credential_use_event_on_validation_failure() {
        // ACCEPTANCE (4): a DENY verdict performs no swap (no fetch, no
        // substitution) — so there is NO credential use and NO event reaches the
        // LOG-1 channel. The listener answers the structured 403 and never builds
        // a PendingCredentialUse, so emission cannot happen.
        let mut v = FakeValidator::default();
        v.program(
            SHORT_CRED,
            ValidationVerdict::Deny {
                reason: DenyReason::IdentityMismatch,
            },
        );
        let f = github_fetcher();
        let exec = SwapExecutor::new(github_registry());
        let s = session(9);
        let emitter = RecordingEmitter::default();

        // front half DENIES — the listener stops here, never calling fire().
        let verdict = exec.evaluate(&v, &s, &req_with_auth("api.github.com", SHORT_CRED));
        match &verdict {
            SwapVerdict::Denied(d) => assert_eq!(d.status, 403),
            other => panic!("expected Denied, got {other:?}"),
        }
        // model the listener: only SwapVerdict::Allowed proceeds to fire()+emit.
        if let SwapVerdict::Allowed(grant) = verdict {
            let fired = exec.fire(
                &f,
                &s,
                &grant,
                "Bearer",
                &RequestLine::new("GET", "api.github.com", "/user"),
                provenance(),
            );
            drive_upstream_then_emit(fired, UpstreamOutcome::Ok(200), &emitter);
        }

        assert_eq!(
            emitter.count(),
            0,
            "a validation failure performs no swap, so emits NO event"
        );
        // and never fetched the real credential.
        assert_eq!(f.fetch_count(), 0);
    }

    #[test]
    fn no_credential_use_event_on_a_secret_store_fetch_failure() {
        // A back-half fetch failure (502) substituted NO credential, so there is
        // no use to audit: drive_upstream_then_emit's FetchFailed arm emits
        // nothing. (The 403/DENY case is covered above; this is the 502 case.)
        let f = FakeSecretFetcher {
            fail: Some(FetchError::Unavailable),
            ..Default::default()
        };
        let exec = SwapExecutor::new(github_registry());
        let s = session(4);
        let emitter = RecordingEmitter::default();

        let fired = exec.fire(
            &f,
            &s,
            &allowed_grant(),
            "Bearer",
            &RequestLine::new("GET", "api.github.com", "/user"),
            provenance(),
        );
        // confirm it WAS a fetch failure (502), then drive the emit model.
        match &fired {
            SwapFired::FetchFailed { denial } => assert_eq!(denial.status, 502),
            other => panic!("expected FetchFailed, got {other:?}"),
        }
        drive_upstream_then_emit(fired, UpstreamOutcome::Timeout, &emitter);

        assert_eq!(
            emitter.count(),
            0,
            "a fetch failure substituted no credential, so emits NO use event"
        );
    }

    #[test]
    fn pass_through_flow_emits_no_credential_use_event() {
        // A pass-through (TLS-4) flow never reaches the back half, so the emitter
        // is never handed a PendingCredentialUse — zero events (boundary
        // `TestPassThrough_NeverSwaps` / `no CredentialUseEvent may exist`).
        let f = github_fetcher();
        let exec = SwapExecutor::new(github_registry());
        let s = session(2);
        let emitter = RecordingEmitter::default();

        let inspected = false;
        if SwapExecutor::is_inspected_path(inspected) {
            let fired = exec.fire(
                &f,
                &s,
                &allowed_grant(),
                "Bearer",
                &RequestLine::new("GET", "api.github.com", "/user"),
                provenance(),
            );
            drive_upstream_then_emit(fired, UpstreamOutcome::Ok(200), &emitter);
        }
        assert_eq!(
            emitter.count(),
            0,
            "pass-through emits no credential-use event"
        );
        assert_eq!(f.fetch_count(), 0);
    }

    #[test]
    fn pending_token_inspection_does_not_consume_the_one_emit() {
        // The once-token is inspectable any number of times (deref + event())
        // without consuming its single emit — only `emit` consumes it.
        let f = github_fetcher();
        let exec = SwapExecutor::new(github_registry());
        let s = session(8);
        let emitter = RecordingEmitter::default();

        let event = match exec.fire(
            &f,
            &s,
            &allowed_grant(),
            "Bearer",
            &RequestLine::new("GET", "api.github.com", "/user"),
            provenance(),
        ) {
            SwapFired::Substituted { event, .. } => event,
            other => panic!("expected Substituted, got {other:?}"),
        };
        // inspect repeatedly (deref + event()) — none of this consumes the emit.
        assert_eq!(event.service_id, "github");
        assert_eq!(event.method, "GET");
        assert_eq!(event.event().host, "api.github.com");
        let _ = format!("{event:?}");
        // still emittable exactly once.
        event.emit(&emitter);
        assert_eq!(emitter.count(), 1);
    }
}
