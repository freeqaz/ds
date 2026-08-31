// SPDX-License-Identifier: Apache-2.0

// Package grantwire is the cross-service conformance fixture for the D77
// grant-return wire frame (docs/09 §5 TLS-1, doc 12 §12; D77/D22).
//
// The grant-return feed is host-LOCAL: the host-agent's grant-return producer (a Go
// encoder, orchestrator/internal/hostagent/grantreturn_producer.go encodeAllowGrant)
// frames a session-scoped TTL'd allow grant, and the ds-tlsproxy ingest
// (GrantReturnWire::decode_grant, Rust main.rs) DECODES it back into an AllowGrant
// recorded into the shared GrantReturnFeed. The two services share NO crate (D40/D67)
// — there is no gRPC/tonic in the dataplane workspace, no FFI, no shared type — so the
// frame layout is duplicated by construction, and a byte-order flip / field reorder /
// expiry-encoding change would surface ONLY at live integration (a delivered grant
// silently dropped as malformed, so a human's approval never releases the held Ask).
//
// This fixture is the single artifact BOTH halves assert against, exactly as
// attendwire single-sources the D78 attendedness frame and revocationwire the D53
// rung↔wire-byte table:
//
//   - the Go producer test (grantreturn_producer_test.go) pins encodeAllowGrant against
//     the byte-identical golden hex;
//   - the Rust decoder test (main.rs grant_return_wire_matches_conformance_golden) pins
//     GrantReturnWire::decode_grant against the byte-identical golden hex;
//   - this fixture RE-DERIVES the golden with its own independent encoder
//     (EncodeAllowGrant) and asserts equality (grantwire_test.go), so the golden is the
//     authoritative produce-once wire form, not an unchecked literal.
//
// A real wire drift can never pass all three, because all three must reproduce the SAME
// bytes this fixture freezes.
//
// THE GRANT CARRIES ITS OWN ABSOLUTE EXPIRY. Unlike the attendedness fact (whose
// freshness budget is a proxy-side policy value the wire never carries), the grant's
// expires_at_unix_s is authoritative and travels on the wire — a session-scoped TTL'd
// allow, never a permanent one. This fixture pins the four session join-keys + the SNI
// domain + the absolute expiry, exactly the bytes on the wire.
//
// WHY A FIXTURE, NOT A RUNTIME IMPORT (the round-constraint): neither tree can import
// this package at runtime — the orchestrator module may import ONLY proto/gen/go
// cross-tree (D80), and the Rust dataplane cannot import a Go package at all. So
// the single-source property is the SAME one attendwire/revocationwire use: this fixture
// is the AUTHORITATIVE artifact, every value is RE-COMPUTED here from the canonical
// inputs by an independent codec, and the per-tree literal copies are each pinned by
// their own suite against their own independent re-derivation.
//
// Stdlib-only, zero dependencies — the package mirrors the wire contract, it does not
// import the Rust crate (it can't), any proto, or the orchestrator hostagent package.
// NEVER-LOG-THE-SECRET (D73): every fixture value is a SYNTHETIC conformance string (a
// ULID-shaped test uuid, a fixed ASCII host id, a distinct-byte index/timestamp), never
// a real session/secret byte.
package grantwire

import "encoding/binary"

// GrantFrameMaxBody is the hard cap on a single grant frame body — MUST match
// GrantReturnWire::MAX_FRAME_BODY (64*1024) in the Rust consumer and grantFrameMaxBody in
// the Go producer. A body over the cap is a malformed frame both halves drop fail-closed.
const GrantFrameMaxBody = 64 * 1024

// ─── The grant-return golden (the single source both trees pin) ───

// The canonical fixture grant — byte-identical across the Go producer test, the Rust
// decoder test, and this fixture. Distinct-byte fields make a byte-order or field-order
// divergence visible (a little-endian host_session_index would render 04 03 02 01).

// GoldenSessionUUID is the fixture session UUID (a ULID-shaped test id).
const GoldenSessionUUID = "01HZX9K6Q2VN7T4M8B0CWRD5EF"

// GoldenHostID is the fixture host id.
const GoldenHostID = "host-grant-conformance"

// GoldenHostSessionIndex is the fixture host-local session index. The distinct bytes
// (01 02 03 04) make a byte-order divergence in the 4-byte big-endian field visible.
const GoldenHostSessionIndex uint32 = 0x0102_0304

// GoldenTapName is the fixture tap name (the authoritative join key the feed is keyed by).
const GoldenTapName = "dstap-9"

// GoldenSniDomain is the fixture SNI domain the grant permits — it must match the held
// connection's domain for the hold to proceed.
const GoldenSniDomain = "api.anthropic.com"

// GoldenExpiresAtUnixS is the fixture absolute expiry. The distinct bytes make a byte-order
// divergence in the 8-byte big-endian field visible.
const GoldenExpiresAtUnixS uint64 = 0x0000_0000_6600_0000

// GoldenGrantHex is the canonical grant-frame BODY bytes the grant-return wire contract
// serialises the golden grant to, as hex:
//
//	str(session_uuid) || str(host_id) || host_session_index(4B BE) || str(tap_name) ||
//	str(sni_domain) || expires_at_unix_s(8B BE)
//
// where str(x) = len(4B BE) || utf8(x). This is the byte-for-byte frame BODY (no outer
// 4-byte frame length prefix) BOTH languages agree on; the conformance suite re-derives it
// with EncodeAllowGrant and asserts equality, so the golden is never an unchecked literal.
// IDENTICAL to the Go test's goldenHex and the Rust test's GRANTWIRE_GOLDEN_GRANT_HEX.
const GoldenGrantHex = "0000001a3031485a58394b365132564e3754344d3842304357524435454600000016686f73742d6772616e742d636f6e666f726d616e6365010203040000000764737461702d39000000116170692e616e7468726f7069632e636f6d0000000066000000"

// EncodeAllowGrant is the INDEPENDENT reference encoder for one grant frame body — a
// byte-for-byte port of the Go producer's encodeAllowGrant (grantreturn_producer.go) and
// the inverse of the Rust consumer's GrantReturnWire::decode_grant (main.rs):
//
//	str(session_uuid) || str(host_id) || host_session_index(4B BE) || str(tap_name) ||
//	str(sni_domain) || expires_at_unix_s(8B BE).
//
// The conformance suite encodes the canonical grant with THIS and asserts it equals the
// pinned GoldenGrantHex, so the golden is the authoritative produce-once wire form derived
// from the canonical inputs, not an unverified literal. A frame-shape drift in this single
// source turns the suite RED.
func EncodeAllowGrant(sessionUUID, hostID string, hostSessionIndex uint32, tapName, sniDomain string, expiresAtUnixS uint64) []byte {
	out := make([]byte, 0, 48)
	out = putStr(out, sessionUUID)
	out = putStr(out, hostID)
	out = binary.BigEndian.AppendUint32(out, hostSessionIndex)
	out = putStr(out, tapName)
	out = putStr(out, sniDomain)
	out = binary.BigEndian.AppendUint64(out, expiresAtUnixS)
	return out
}

// putStr appends a length-prefixed string (len(4B BE) || utf8 bytes) — the SAME framing
// both halves' put_str / putGrantWireStr use.
func putStr(out []byte, s string) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
	return append(out, s...)
}

// DecodeAllowGrant is the INDEPENDENT reference decoder — the byte-for-byte mirror of the
// Rust GrantReturnWire::decode_grant (main.rs) and the Go decodeAllowGrantForTest
// (grantreturn_producer_test.go). It returns ok=false FAIL-CLOSED for a malformed frame,
// with the SAME rejection set both decoders pin:
//
//   - a truncated field (the body ends before a length prefix / a declared field / the
//     8-byte expires_at);
//   - a length prefix over GrantFrameMaxBody (a hostile/oversized frame);
//   - trailing bytes AFTER expires_at (an over-long frame — the body did not consume exactly).
//
// It never fabricates a grant from a malformed frame (the ingest drops the connection
// fail-closed, records nothing → the held Ask times out). The conformance suite drives
// truncated / over-long inputs through it and asserts they are rejected identically to both
// sides. NOTE: an already-expired grant is NOT a decode-time rejection — the codec never
// judges TTL; the consumer's resolution-time check (expires_at > now) fails a past expiry
// closed.
func DecodeAllowGrant(body []byte) (sessionUUID, hostID string, hostSessionIndex uint32, tapName, sniDomain string, expiresAtUnixS uint64, ok bool) {
	cur := body
	var got bool
	if sessionUUID, cur, got = takeStr(cur); !got {
		return "", "", 0, "", "", 0, false
	}
	if hostID, cur, got = takeStr(cur); !got {
		return "", "", 0, "", "", 0, false
	}
	if hostSessionIndex, cur, got = takeU32(cur); !got {
		return "", "", 0, "", "", 0, false
	}
	if tapName, cur, got = takeStr(cur); !got {
		return "", "", 0, "", "", 0, false
	}
	if sniDomain, cur, got = takeStr(cur); !got {
		return "", "", 0, "", "", 0, false
	}
	if expiresAtUnixS, cur, got = takeU64(cur); !got {
		return "", "", 0, "", "", 0, false
	}
	// The frame must consume EXACTLY: trailing bytes are an over-long (malformed) frame.
	if len(cur) != 0 {
		return "", "", 0, "", "", 0, false
	}
	return sessionUUID, hostID, hostSessionIndex, tapName, sniDomain, expiresAtUnixS, true
}

// takeU32 reads a 4-byte big-endian u32, returning the remainder and ok=false on a short body.
func takeU32(cur []byte) (uint32, []byte, bool) {
	if len(cur) < 4 {
		return 0, cur, false
	}
	return binary.BigEndian.Uint32(cur[:4]), cur[4:], true
}

// takeU64 reads an 8-byte big-endian u64, returning the remainder and ok=false on a short body.
func takeU64(cur []byte) (uint64, []byte, bool) {
	if len(cur) < 8 {
		return 0, cur, false
	}
	return binary.BigEndian.Uint64(cur[:8]), cur[8:], true
}

// takeStr reads a length-prefixed string (len(4B BE) || bytes), returning the remainder.
// ok=false on a short body or a length over GrantFrameMaxBody (a hostile prefix).
func takeStr(cur []byte) (string, []byte, bool) {
	n, rest, ok := takeU32(cur)
	if !ok {
		return "", cur, false
	}
	if int(n) > GrantFrameMaxBody || len(rest) < int(n) {
		return "", cur, false
	}
	return string(rest[:n]), rest[n:], true
}
