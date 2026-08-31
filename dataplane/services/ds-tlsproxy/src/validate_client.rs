// SPDX-License-Identifier: Apache-2.0
//! The D22 identity-`Validate` UDS client — the LIVE front half of the TLS-5
//! credential swap (doc 16 §4 / §9; doc 12 §13.3; D22 / D73 / D40 / D67).
//!
//! # What this is
//!
//! `ds-tlsproxy`'s [`ds_tlsproxy::swap::SwapExecutor`] drives a synchronous D22
//! `Validate` call on every registry-matched, inspected swap request (`swap.rs`
//! step 2). The PRODUCTION validator is the Identity `Validate(presented_credential,
//! session_ref, service_id)` RPC. This module is that client — but, exactly as
//! `ds_tlsproxy::reoriginate`/the D68 re-resolve client do for THEIR not-yet-frozen
//! seams, it speaks the wire WITHOUT tonic/prost: there is no gRPC/tower/hyper in
//! the dataplane workspace (D40/D67), and the identity-plane Stage-0 `Validate`
//! types are not yet frozen into `ds-contracts`. So the transport is the lightest
//! thing that works and is byte-compatible with a real protobuf server:
//!
//! * a **length-prefixed frame** (a 4-byte big-endian body length + the body) over a
//!   `tokio` `UnixStream` — the SAME frame shape `ds-dnsgate/src/reresolve.rs` and
//!   the D68 re-resolve client in `main.rs` use; and
//! * a **hand-rolled protobuf codec** ([`encode_validate_request`] /
//!   [`decode_validate_response`]) that emits/parses the EXACT proto3 wire form of
//!   `dreamserpent.identity.v1.ValidateRequest` / `ValidateResponse` (see
//!   `proto/dreamserpent/identity/v1/validate.proto` for the field numbers) — so the
//!   server half can be a real prost/tonic-generated decoder reading the frame body
//!   as a `ValidateRequest`, no custom server framing assumed beyond the 4-byte
//!   length prefix.
//!
//! # Fail-closed by construction (doc 16 §5.2)
//!
//! A connect/io/timeout/malformed-frame/unspecified-verdict outcome is NEVER a
//! fabricated ALLOW: every such fault collapses to a DENY verdict
//! ([`DenyReason::OutOfGrant`] — the honest "no grant proven" class), exactly as the
//! historical fail-closed stub does. A key-store/validate outage denies the request;
//! it never degrades to egressing the placeholder credential as if real.
//!
//! # No new dependency
//!
//! `tokio` (already a dep, for the D68 re-resolve client) is the only crate used; the
//! protobuf codec is hand-rolled. `#![forbid(unsafe_code)]` (workspace-wide).

#![forbid(unsafe_code)]

use std::time::Duration;

use ds_contracts::session::SessionRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use ds_tlsproxy::swap::{DenyReason, ValidationVerdict};

/// The default UDS path the live D22 `Validate` client dials when no explicit
/// endpoint is configured. A host-local socket under `/run`, alongside the
/// re-resolve seam convention (`/run/ds-dnsgate/reresolve.sock`).
pub const DEFAULT_VALIDATE_UDS: &str = "/run/ds-identity/validate.sock";

/// The env var that single-sources the `Validate` UDS endpoint path. Unset/empty →
/// [`DEFAULT_VALIDATE_UDS`]. Read by [`validate_endpoint`].
pub const VALIDATE_UDS_ENV: &str = "DS_SWAP_VALIDATE_UDS";

/// The endpoint path the live client dials — the env override ([`VALIDATE_UDS_ENV`])
/// when set non-empty, else [`DEFAULT_VALIDATE_UDS`]. The ONE place the path is
/// resolved (mirrors the re-resolve `reresolve_endpoint` single-sourcing).
pub fn validate_endpoint() -> String {
    match std::env::var(VALIDATE_UDS_ENV) {
        Ok(v) if !v.is_empty() => v,
        _ => DEFAULT_VALIDATE_UDS.to_string(),
    }
}

/// The hard cap on a single `Validate` frame body (bytes). A request is a small
/// credential blob + a session quartet + a service id; a response is a verdict + a
/// short reason/grant-ref. The cap bounds a malformed/hostile length prefix so a
/// single connection can never make the client allocate unboundedly (a length over
/// the cap is a malformed frame → fail-closed deny).
pub const MAX_FRAME_BODY: u32 = 64 * 1024;

/// The bounded budget for ONE `Validate` round-trip (connect + send + receive). The
/// swap path is synchronous (D73): a hung Identity server must fail the swap CLOSED
/// (→ deny) fast, never park a pingora worker. Generous enough for a healthy
/// host-local UDS round-trip (the server-side signature/liveness/grant checks run
/// under the server's OWN budget; this only bounds the intra-host hop).
pub const VALIDATE_TIMEOUT: Duration = Duration::from_secs(5);

// ─────────────────────────────────────────────────────────────────────────────
// proto3 wire-format field numbers (proto/dreamserpent/identity/v1/validate.proto
// and proto/dreamserpent/boundary/v1/session_ref.proto). Hand-rolled — no prost.
// ─────────────────────────────────────────────────────────────────────────────

/// `ValidateRequest` field numbers.
mod req_field {
    /// `bytes presented_credential = 1` (LEN).
    pub const PRESENTED_CREDENTIAL: u32 = 1;
    /// `dreamserpent.boundary.v1.SessionRef session_ref = 2` (LEN, embedded message).
    pub const SESSION_REF: u32 = 2;
    /// `string service_id = 3` (LEN).
    pub const SERVICE_ID: u32 = 3;
}

/// `dreamserpent.boundary.v1.SessionRef` field numbers (the embedded message).
mod session_field {
    /// `string session_uuid = 1` (LEN).
    pub const SESSION_UUID: u32 = 1;
    /// `string host_id = 2` (LEN).
    pub const HOST_ID: u32 = 2;
    /// `uint64 host_session_index = 3` (VARINT).
    pub const HOST_SESSION_INDEX: u32 = 3;
    /// `string tap_name = 4` (LEN).
    pub const TAP_NAME: u32 = 4;
}

/// `ValidateResponse` field numbers.
mod resp_field {
    /// `ValidateVerdict verdict = 1` (VARINT, enum).
    pub const VERDICT: u32 = 1;
    /// `string machine_readable_reason = 2` (LEN).
    pub const MACHINE_READABLE_REASON: u32 = 2;
    /// `string grant_ref = 3` (LEN).
    pub const GRANT_REF: u32 = 3;
    /// `int64 expiry_unix_seconds = 4` (VARINT).
    pub const EXPIRY_UNIX_SECONDS: u32 = 4;
}

/// proto3 wire types (the low 3 bits of a field tag).
const WIRE_VARINT: u32 = 0;
const WIRE_LEN: u32 = 2;

/// `ValidateVerdict` enum values (validate.proto).
const VERDICT_UNSPECIFIED: u64 = 0;
const VERDICT_ALLOW: u64 = 1;
const VERDICT_DENY: u64 = 2;

// ─────────────────────────────────────────────────────────────────────────────
// Hand-rolled protobuf ENCODE (the request side).
// ─────────────────────────────────────────────────────────────────────────────

/// Append a base-128 varint (LEB128, little-endian groups) to `out`.
fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Append a field tag `(field_number << 3) | wire_type`.
fn put_tag(out: &mut Vec<u8>, field_number: u32, wire_type: u32) {
    put_varint(out, ((field_number << 3) | wire_type) as u64);
}

/// Append a length-delimited (LEN) field: the tag, a length varint, then `bytes`.
fn put_len_field(out: &mut Vec<u8>, field_number: u32, bytes: &[u8]) {
    put_tag(out, field_number, WIRE_LEN);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Append a varint (VARINT) field: the tag, then the value varint.
fn put_varint_field(out: &mut Vec<u8>, field_number: u32, value: u64) {
    put_tag(out, field_number, WIRE_VARINT);
    put_varint(out, value);
}

/// Encode the embedded `dreamserpent.boundary.v1.SessionRef` message body (no tag /
/// length prefix). proto3 omits empty/zero scalar fields; the quartet is always
/// populated in practice, but a zero `host_session_index` is correctly omitted (it
/// is the proto3 default), which a real server reads back as 0.
fn encode_session_ref(session: &SessionRef) -> Vec<u8> {
    let mut out = Vec::new();
    if !session.session_uuid.is_empty() {
        put_len_field(
            &mut out,
            session_field::SESSION_UUID,
            session.session_uuid.as_bytes(),
        );
    }
    if !session.host_id.is_empty() {
        put_len_field(&mut out, session_field::HOST_ID, session.host_id.as_bytes());
    }
    if session.host_session_index != 0 {
        put_varint_field(
            &mut out,
            session_field::HOST_SESSION_INDEX,
            u64::from(session.host_session_index),
        );
    }
    if !session.tap_name.is_empty() {
        put_len_field(
            &mut out,
            session_field::TAP_NAME,
            session.tap_name.as_bytes(),
        );
    }
    out
}

/// Encode a `dreamserpent.identity.v1.ValidateRequest` message body (no frame length
/// prefix): the presented credential bytes, the embedded session quartet, the
/// service id. The credential is BORROWED and written once into this buffer.
///
/// The returned buffer carries the presented credential bytes in cleartext (proto3
/// `bytes presented_credential = 1`), so it is wrapped in [`Zeroizing`] — wiped on
/// drop, never `Debug`/`Display`-leaked — exactly as [`ds_tlsproxy::swap::SubstitutedHeader`]
/// wraps the OTHER credential-bearing wire buffer in this service (D73 never-hold-
/// the-secret made type-level, not a scrub pass). The caller holds the `Zeroizing`
/// buffer for exactly the one round-trip and drops it at swap-evaluate exit. The
/// buffer derefs to `&[u8]` for the frame writer, so no copy escapes the wrapper.
pub fn encode_validate_request(
    presented_credential: &[u8],
    session: &SessionRef,
    service_id: &str,
) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::new();
    // field 1: presented_credential (bytes). proto3 omits an empty bytes field; an
    // empty presented credential would not reach here (a registry match requires a
    // present credential), but the encoder stays faithful to proto3 default-omission.
    if !presented_credential.is_empty() {
        put_len_field(
            &mut out,
            req_field::PRESENTED_CREDENTIAL,
            presented_credential,
        );
    }
    // field 2: session_ref (embedded message).
    let session_body = encode_session_ref(session);
    if !session_body.is_empty() {
        put_len_field(&mut out, req_field::SESSION_REF, &session_body);
    }
    // field 3: service_id (string).
    if !service_id.is_empty() {
        put_len_field(&mut out, req_field::SERVICE_ID, service_id.as_bytes());
    }
    Zeroizing::new(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Hand-rolled protobuf DECODE (the response side).
// ─────────────────────────────────────────────────────────────────────────────

/// A cursor over a protobuf message body that yields one field at a time. All
/// reads are bounds-checked; a truncated/malformed encoding yields `None` (→ the
/// client fails closed).
struct ProtoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// One decoded protobuf field: its number and its (wire-type-specific) payload.
enum Field<'a> {
    /// A VARINT field (the decoded value).
    Varint(u32, u64),
    /// A LEN field (the raw bytes; the consumer interprets them).
    Len(u32, &'a [u8]),
}

impl<'a> ProtoReader<'a> {
    fn new(buf: &'a [u8]) -> ProtoReader<'a> {
        ProtoReader { buf, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Read a base-128 varint (max 10 bytes / 64 bits). `None` on truncation or an
    /// over-long encoding.
    fn read_varint(&mut self) -> Option<u64> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            if shift >= 64 {
                // Over-long varint (more than 10 groups) — malformed.
                return None;
            }
            let byte = *self.buf.get(self.pos)?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
        }
    }

    /// Read `len` raw bytes, advancing the cursor. `None` if fewer remain.
    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    /// Read the next field. `None` at clean EOF is signalled by [`Self::done`]; a
    /// `None` HERE means a malformed/truncated field (the caller fails closed).
    ///
    /// Unknown wire types (32-bit / 64-bit / groups) are NOT expected on these two
    /// messages (every field is VARINT or LEN), so an unrecognized wire type is
    /// treated as malformed rather than skipped — a stricter, fail-closed posture.
    fn next_field(&mut self) -> Option<Field<'a>> {
        let tag = self.read_varint()?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u32;
        match wire_type {
            WIRE_VARINT => {
                let v = self.read_varint()?;
                Some(Field::Varint(field_number, v))
            }
            WIRE_LEN => {
                let len = self.read_varint()?;
                let len = usize::try_from(len).ok()?;
                if len > MAX_FRAME_BODY as usize {
                    return None;
                }
                let bytes = self.read_bytes(len)?;
                Some(Field::Len(field_number, bytes))
            }
            _ => None,
        }
    }
}

/// Decode a `dreamserpent.identity.v1.ValidateResponse` body into the swap-core
/// [`ValidationVerdict`]. proto3 default-omission means an ALLOW with a zero expiry
/// or a DENY with an empty reason are both well-formed; the mapping is fail-closed:
///
/// * verdict == ALLOW → [`ValidationVerdict::Allow`] with the grant ref + expiry
///   (a non-negative expiry; a negative `int64` clamps to 0);
/// * verdict == DENY  → [`ValidationVerdict::Deny`] with the reason string mapped
///   onto the [`DenyReason`] taxonomy via [`map_reason`];
/// * verdict == UNSPECIFIED, an unknown verdict value, or a structurally malformed
///   body → `None` (the client maps it to a fail-closed deny). An UNSPECIFIED
///   verdict is NEVER an ALLOW.
///
/// A repeated scalar field follows proto3 last-wins semantics (a later occurrence
/// overwrites an earlier one); an unrecognized field NUMBER is skipped for proto3
/// forward-compat. Only a truncated/over-long varint, an out-of-bounds length, or
/// an unsupported wire type makes the body malformed.
///
/// Returns `None` ONLY on a structurally malformed body; a well-formed DENY (or an
/// UNSPECIFIED verdict) returns `Some(Deny{..})` so the caller has an explicit
/// verdict. The dial-layer maps both `None` and any transport error to the same
/// fail-closed deny.
pub fn decode_validate_response(body: &[u8]) -> Option<ValidationVerdict> {
    let mut reader = ProtoReader::new(body);
    let mut verdict_raw: u64 = VERDICT_UNSPECIFIED;
    let mut reason = String::new();
    let mut grant_ref = String::new();
    let mut expiry_unix: u64 = 0;

    while !reader.done() {
        match reader.next_field()? {
            Field::Varint(resp_field::VERDICT, v) => verdict_raw = v,
            Field::Len(resp_field::MACHINE_READABLE_REASON, bytes) => {
                reason = String::from_utf8(bytes.to_vec()).ok()?;
            }
            Field::Len(resp_field::GRANT_REF, bytes) => {
                grant_ref = String::from_utf8(bytes.to_vec()).ok()?;
            }
            Field::Varint(resp_field::EXPIRY_UNIX_SECONDS, v) => {
                // `int64` on the wire: a negative value rides as a 64-bit varint with
                // the high bit set. A negative expiry has already lapsed, so clamp it
                // to 0 (never trust a "future" overflow) — the back half honors it.
                expiry_unix = if (v as i64) < 0 { 0 } else { v };
            }
            // A field with the right number but the wrong wire type, or an unknown
            // field number on a wire type we read, is tolerated only if it is one of
            // the two wire types we parse; an unrecognized field NUMBER is skipped
            // (proto3 forward-compat) so a future additive field never breaks decode.
            Field::Varint(_, _) | Field::Len(_, _) => {}
        }
    }

    match verdict_raw {
        VERDICT_ALLOW => Some(ValidationVerdict::Allow {
            grant_ref,
            expiry_unix,
        }),
        VERDICT_DENY => Some(ValidationVerdict::Deny {
            reason: map_reason(&reason),
        }),
        // UNSPECIFIED or an unknown verdict value is NEVER an allow — fail closed.
        _ => None,
    }
}

/// Map the proto `machine_readable_reason` STRING onto the swap-core [`DenyReason`]
/// taxonomy (`swap.rs`). The wire carries a free-form-ish string; the canonical
/// values are the [`DenyReason::reason_code`] kebab codes (`tls5-*`). An exact match
/// on a known code maps to its variant; an empty/unknown reason maps to the
/// conservative [`DenyReason::OutOfGrant`] (the honest "no grant proven" class — the
/// SAME class the fail-closed stub uses), so an unrecognized reason never silently
/// becomes an allow and never fabricates a more specific class than the server sent.
pub fn map_reason(reason: &str) -> DenyReason {
    match reason {
        "tls5-unknown-credential" => DenyReason::UnknownCredential,
        "tls5-identity-mismatch" => DenyReason::IdentityMismatch,
        "tls5-credential-expired" => DenyReason::CredentialExpired,
        "tls5-out-of-grant" => DenyReason::OutOfGrant,
        "tls5-session-not-live" => DenyReason::SessionNotLive,
        "tls5-secret-not-found" => DenyReason::SecretNotFound,
        "tls5-secret-store-unavailable" => DenyReason::SecretStoreUnavailable,
        // Empty or unrecognized: the conservative out-of-grant class.
        _ => DenyReason::OutOfGrant,
    }
}

/// The verdict a transport/protocol fault collapses to — the honest, fail-closed
/// DENY (doc 16 §5.2): a connect/io/timeout/malformed/unspecified outcome NEVER
/// fabricates an allow. [`DenyReason::OutOfGrant`] is the SAME class the historical
/// stub denies with, so the armed-but-server-absent path is byte-identical to the
/// disarmed default's verdict.
pub fn fail_closed_verdict() -> ValidationVerdict {
    ValidationVerdict::Deny {
        reason: DenyReason::OutOfGrant,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The length-prefixed frame transport (the SAME 4-byte-BE frame the re-resolve
// seam uses) over a tokio UnixStream.
// ─────────────────────────────────────────────────────────────────────────────

/// Perform ONE `Validate` UDS round-trip against `endpoint`: connect, write the
/// length-prefixed `ValidateRequest` frame, read the length-prefixed
/// `ValidateResponse` frame, decode it. Returns `Ok(Some(verdict))` on a well-formed
/// response, `Ok(None)` on a malformed/unspecified response body, and `Err` on any
/// connect/io fault. A fresh UDS connection is dialed per call (validate is on the
/// connection-setup path, rare enough not to pool).
pub async fn validate_round_trip(
    endpoint: &str,
    request_body: &[u8],
) -> std::io::Result<Option<ValidationVerdict>> {
    if request_body.len() as u64 > MAX_FRAME_BODY as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "validate request frame body over cap",
        ));
    }
    let mut stream = UnixStream::connect(endpoint).await?;
    // Write the length-prefixed request frame.
    stream
        .write_all(&(request_body.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(request_body).await?;
    stream.flush().await?;
    // Read the length-prefixed response frame (a length over the cap is malformed).
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "validate response frame over cap",
        ));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    Ok(decode_validate_response(&body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    // ── round-trip the codec in isolation ───────────────────────────────────

    /// A minimal independent protobuf field reader for the request side, so the
    /// tests verify `encode_validate_request` against a SECOND decoder (not just its
    /// own inverse) — proving the bytes are genuine proto3 wire form a real server
    /// would parse.
    fn fields(body: &[u8]) -> Vec<(u32, Vec<u8>, Option<u64>)> {
        let mut r = ProtoReader::new(body);
        let mut out = Vec::new();
        while !r.done() {
            match r.next_field().expect("well-formed field") {
                Field::Varint(n, v) => out.push((n, Vec::new(), Some(v))),
                Field::Len(n, b) => out.push((n, b.to_vec(), None)),
            }
        }
        out
    }

    fn session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    #[test]
    fn varint_round_trips_across_boundaries() {
        for v in [
            0u64,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let mut r = ProtoReader::new(&buf);
            assert_eq!(r.read_varint(), Some(v), "varint {v} round-trips");
            assert!(r.done(), "no trailing bytes after a single varint");
        }
    }

    #[test]
    fn request_encodes_the_proto3_wire_shape() {
        let s = session(7);
        let body = encode_validate_request(b"short-lived-token", &s, "github");
        let f = fields(&body);
        // field 1: presented_credential (bytes).
        assert_eq!(f[0].0, req_field::PRESENTED_CREDENTIAL);
        assert_eq!(f[0].1, b"short-lived-token");
        // field 2: session_ref (embedded message) — decode the nested body.
        assert_eq!(f[1].0, req_field::SESSION_REF);
        let nested = fields(&f[1].1);
        assert_eq!(nested[0].0, session_field::SESSION_UUID);
        assert_eq!(nested[0].1, s.session_uuid.as_bytes());
        assert_eq!(nested[1].0, session_field::HOST_ID);
        assert_eq!(nested[1].1, s.host_id.as_bytes());
        assert_eq!(nested[2].0, session_field::HOST_SESSION_INDEX);
        assert_eq!(nested[2].2, Some(7));
        assert_eq!(nested[3].0, session_field::TAP_NAME);
        assert_eq!(nested[3].1, b"dstap-7");
        // field 3: service_id (string).
        assert_eq!(f[2].0, req_field::SERVICE_ID);
        assert_eq!(f[2].1, b"github");
    }

    #[test]
    fn request_omits_proto3_default_index() {
        // A zero host_session_index is the proto3 default → omitted on the wire (a
        // real server reads it back as 0). The other three fields are still present.
        let s = session(0);
        let body = encode_validate_request(b"t", &s, "github");
        let f = fields(&body);
        let nested = fields(&f[1].1);
        assert!(
            nested
                .iter()
                .all(|(n, _, _)| *n != session_field::HOST_SESSION_INDEX),
            "a zero index is omitted (proto3 default)"
        );
    }

    /// Build a `ValidateResponse` body the SAME way a prost/tonic server would, so
    /// the decoder is tested against an independently-constructed wire message.
    fn build_response(
        verdict: u64,
        reason: Option<&str>,
        grant_ref: Option<&str>,
        expiry: Option<i64>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        // proto3 omits a zero-valued verdict, but for test clarity we always emit it
        // (a real server emitting verdict=0 / omitting it both decode to UNSPECIFIED).
        if verdict != VERDICT_UNSPECIFIED {
            put_varint_field(&mut out, resp_field::VERDICT, verdict);
        }
        if let Some(r) = reason {
            put_len_field(&mut out, resp_field::MACHINE_READABLE_REASON, r.as_bytes());
        }
        if let Some(g) = grant_ref {
            put_len_field(&mut out, resp_field::GRANT_REF, g.as_bytes());
        }
        if let Some(e) = expiry {
            put_varint_field(&mut out, resp_field::EXPIRY_UNIX_SECONDS, e as u64);
        }
        out
    }

    #[test]
    fn decode_allow_carries_grant_ref_and_expiry() {
        let body = build_response(VERDICT_ALLOW, None, Some("grant-abc"), Some(1_700_000_000));
        assert_eq!(
            decode_validate_response(&body),
            Some(ValidationVerdict::Allow {
                grant_ref: "grant-abc".into(),
                expiry_unix: 1_700_000_000,
            })
        );
    }

    #[test]
    fn decode_allow_with_omitted_defaults_is_empty_grant_zero_expiry() {
        // A bare ALLOW (proto3-omitted grant_ref + expiry) decodes to empty/zero.
        let body = build_response(VERDICT_ALLOW, None, None, None);
        assert_eq!(
            decode_validate_response(&body),
            Some(ValidationVerdict::Allow {
                grant_ref: String::new(),
                expiry_unix: 0,
            })
        );
    }

    #[test]
    fn decode_negative_expiry_clamps_to_zero() {
        let body = build_response(VERDICT_ALLOW, None, Some("g"), Some(-5));
        assert_eq!(
            decode_validate_response(&body),
            Some(ValidationVerdict::Allow {
                grant_ref: "g".into(),
                expiry_unix: 0,
            })
        );
    }

    #[test]
    fn decode_deny_maps_every_reason_code() {
        let cases = [
            ("tls5-unknown-credential", DenyReason::UnknownCredential),
            ("tls5-identity-mismatch", DenyReason::IdentityMismatch),
            ("tls5-credential-expired", DenyReason::CredentialExpired),
            ("tls5-out-of-grant", DenyReason::OutOfGrant),
            ("tls5-session-not-live", DenyReason::SessionNotLive),
            ("tls5-secret-not-found", DenyReason::SecretNotFound),
            (
                "tls5-secret-store-unavailable",
                DenyReason::SecretStoreUnavailable,
            ),
        ];
        for (code, want) in cases {
            let body = build_response(VERDICT_DENY, Some(code), None, None);
            assert_eq!(
                decode_validate_response(&body),
                Some(ValidationVerdict::Deny { reason: want }),
                "reason {code} maps to its DenyReason"
            );
        }
    }

    #[test]
    fn decode_deny_empty_or_unknown_reason_is_out_of_grant() {
        for reason in [None, Some(""), Some("some-future-reason")] {
            let body = build_response(VERDICT_DENY, reason, None, None);
            assert_eq!(
                decode_validate_response(&body),
                Some(ValidationVerdict::Deny {
                    reason: DenyReason::OutOfGrant,
                }),
                "an empty/unknown reason is the conservative out-of-grant class"
            );
        }
    }

    #[test]
    fn decode_unspecified_verdict_is_none_fail_closed() {
        // verdict=UNSPECIFIED (or omitted) is never an allow — decode to None so the
        // caller fails closed to a deny.
        assert_eq!(
            decode_validate_response(&build_response(VERDICT_UNSPECIFIED, None, None, None)),
            None
        );
        // An unknown verdict value (e.g. 9) is also fail-closed None.
        assert_eq!(
            decode_validate_response(&build_response(9, None, None, None)),
            None
        );
    }

    #[test]
    fn decode_malformed_bodies_are_none() {
        // A truncated varint tag.
        assert_eq!(decode_validate_response(&[0x80]), None);
        // A LEN field claiming 10 bytes but with none following.
        assert_eq!(
            decode_validate_response(&[(resp_field::GRANT_REF << 3 | WIRE_LEN) as u8, 10]),
            None
        );
        // A 32-bit wire type (5) is unsupported on these messages → malformed.
        assert_eq!(
            decode_validate_response(&[(resp_field::VERDICT << 3 | 5) as u8]),
            None
        );
    }

    #[test]
    fn decode_tolerates_unknown_additive_field() {
        // A future additive field (number 8, LEN) is skipped (proto3 forward-compat),
        // the known verdict still decodes.
        let mut body = build_response(VERDICT_ALLOW, None, Some("g"), None);
        put_len_field(&mut body, 8, b"future-bytes");
        assert_eq!(
            decode_validate_response(&body),
            Some(ValidationVerdict::Allow {
                grant_ref: "g".into(),
                expiry_unix: 0,
            })
        );
    }

    // ── the UDS transport against a MOCK in-process server ───────────────────

    /// Bind a mock Identity `Validate` server UDS at `sock`. The bound listener is
    /// returned so the test can move it into a server task that accepts ONE
    /// connection and replies through [`serve_one_validate`]; binding before the
    /// client dials guarantees the socket exists (no accept race).
    fn mock_validate_server(sock: &std::path::Path) -> UnixListener {
        UnixListener::bind(sock).expect("bind mock validate socket")
    }

    /// Read ONE framed request off `stream`, verify the decoded request matches the
    /// expectations, then write the framed `response_body`.
    async fn serve_one_validate(
        listener: &UnixListener,
        response_body: Vec<u8>,
        expect_credential: Vec<u8>,
        expect_service_id: String,
    ) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.expect("read req len");
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.expect("read req body");

        // Decode the request with the SAME hand-rolled reader to prove the client
        // emitted a real proto3 ValidateRequest (credential + service_id present).
        let f = fields(&body);
        let got_cred = f
            .iter()
            .find(|(n, _, _)| *n == req_field::PRESENTED_CREDENTIAL)
            .map(|(_, b, _)| b.clone())
            .unwrap_or_default();
        let got_service = f
            .iter()
            .find(|(n, _, _)| *n == req_field::SERVICE_ID)
            .map(|(_, b, _)| String::from_utf8(b.clone()).unwrap())
            .unwrap_or_default();
        assert_eq!(
            got_cred, expect_credential,
            "server sees the presented credential"
        );
        assert_eq!(got_service, expect_service_id, "server sees the service id");

        stream
            .write_all(&(response_body.len() as u32).to_be_bytes())
            .await
            .expect("write resp len");
        stream
            .write_all(&response_body)
            .await
            .expect("write resp body");
        stream.flush().await.expect("flush resp");
    }

    fn temp_sock(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ds-validate-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join(format!("{name}.sock"));
        let _ = std::fs::remove_file(&sock);
        sock
    }

    #[tokio::test]
    async fn uds_round_trip_allow() {
        let sock = temp_sock("allow");
        let response = build_response(VERDICT_ALLOW, None, Some("grant-xyz"), Some(1_800_000_000));
        let listener = mock_validate_server(&sock);
        let server = tokio::spawn(async move {
            serve_one_validate(&listener, response, b"tok".to_vec(), "github".into()).await;
        });

        let s = session(3);
        let req = encode_validate_request(b"tok", &s, "github");
        let verdict = validate_round_trip(sock.to_str().unwrap(), &req)
            .await
            .expect("round-trip");
        assert_eq!(
            verdict,
            Some(ValidationVerdict::Allow {
                grant_ref: "grant-xyz".into(),
                expiry_unix: 1_800_000_000,
            })
        );
        server.await.expect("server task");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn uds_round_trip_each_deny_reason() {
        for (code, want) in [
            ("tls5-out-of-grant", DenyReason::OutOfGrant),
            ("tls5-identity-mismatch", DenyReason::IdentityMismatch),
            ("tls5-credential-expired", DenyReason::CredentialExpired),
            ("tls5-session-not-live", DenyReason::SessionNotLive),
            ("tls5-unknown-credential", DenyReason::UnknownCredential),
        ] {
            let sock = temp_sock(&format!("deny-{}", code));
            let response = build_response(VERDICT_DENY, Some(code), None, None);
            let listener = mock_validate_server(&sock);
            let server = tokio::spawn(async move {
                serve_one_validate(&listener, response, b"c".to_vec(), "svc".into()).await;
            });

            let s = session(1);
            let req = encode_validate_request(b"c", &s, "svc");
            let verdict = validate_round_trip(sock.to_str().unwrap(), &req)
                .await
                .expect("round-trip");
            assert_eq!(
                verdict,
                Some(ValidationVerdict::Deny { reason: want }),
                "deny reason {code} propagates over UDS"
            );
            server.await.expect("server task");
            let _ = std::fs::remove_file(&sock);
        }
    }

    #[tokio::test]
    async fn uds_unreachable_endpoint_is_a_transport_error() {
        // A dial against a path with no listener is a connect error; the caller maps
        // it to the fail-closed deny (never a silent allow).
        let missing = std::env::temp_dir().join("ds-validate-nope.sock");
        let _ = std::fs::remove_file(&missing);
        let s = session(1);
        let req = encode_validate_request(b"c", &s, "svc");
        let res = validate_round_trip(missing.to_str().unwrap(), &req).await;
        assert!(
            res.is_err(),
            "an unreachable endpoint is a transport error, not a silent allow"
        );
        // The documented mapping: any transport error → fail-closed deny.
        assert_eq!(
            fail_closed_verdict(),
            ValidationVerdict::Deny {
                reason: DenyReason::OutOfGrant
            }
        );
    }

    #[tokio::test]
    async fn uds_unspecified_verdict_decodes_to_none() {
        // A server that answers with an UNSPECIFIED verdict (e.g. a buggy/forged
        // response) → the client sees Ok(None) → fail-closed deny at the caller.
        let sock = temp_sock("unspec");
        let response = build_response(VERDICT_UNSPECIFIED, None, None, None);
        let listener = mock_validate_server(&sock);
        let server = tokio::spawn(async move {
            serve_one_validate(&listener, response, b"c".to_vec(), "svc".into()).await;
        });

        let s = session(1);
        let req = encode_validate_request(b"c", &s, "svc");
        let verdict = validate_round_trip(sock.to_str().unwrap(), &req)
            .await
            .expect("round-trip");
        assert_eq!(
            verdict, None,
            "an unspecified verdict is None (fail-closed)"
        );
        server.await.expect("server task");
        let _ = std::fs::remove_file(&sock);
    }
}
