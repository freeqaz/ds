// SPDX-License-Identifier: Apache-2.0

// Package attendwire is the cross-service conformance fixture for the D78
// attendedness-fact wire frame (doc 12 §12, doc 15 §5.5).
//
// The attendedness-fact feed is host-LOCAL: the host-agent's attendedness
// producer (a Go encoder, orchestrator/internal/hostagent/attendedness_producer.go
// encodeAttendednessFact) frames a fact, and the ds-tlsproxy ingest
// (AttendednessFactWire::decode_fact, Rust main.rs) DECODES it back into an
// AttendednessFact recorded into the shared AttendednessFeed. The two services
// share NO crate (D40/D67) — there is no gRPC/tonic in the dataplane workspace, no
// FFI, no shared type — so the frame layout is duplicated by construction, and a
// byte-order flip / field reorder / attended-encoding change would surface ONLY at
// live integration (a delivered ATTENDED fact silently dropped as malformed, or a
// fabricated verdict from a misread byte).
//
// This fixture is the single artifact BOTH halves assert against, exactly as
// revocationwire single-sources the D53 rung↔wire-byte table:
//
//   - the Go producer test (attendedness_producer_test.go) pins encodeAttendednessFact
//     against the byte-identical golden hex;
//   - the Rust decoder test (main.rs attendedness_wire_matches_conformance_golden)
//     pins AttendednessFactWire::decode_fact against the byte-identical golden hex;
//   - this fixture RE-DERIVES the golden with its own independent encoder
//     (EncodeAttendednessFact) and asserts equality (attendwire_test.go), so the
//     golden is the authoritative produce-once wire form, not an unchecked literal.
//
// A real wire drift can never pass all three, because all three must reproduce the
// SAME bytes this fixture freezes.
//
// THE WIRE DOES NOT CARRY THE FRESHNESS BUDGET. AttendednessFact (hold.rs) needs a
// freshness_budget_s, but that is a proxy-side POLICY value the ds-tlsproxy ingest
// supplies from a rig-tuned env — NEVER a frozen wire field. This fixture therefore
// pins only the four session join-keys + attended + attended_at, exactly the bytes
// on the wire.
//
// WHY A FIXTURE, NOT A RUNTIME IMPORT (the round-constraint): neither tree can import
// this package at runtime — the orchestrator module may import ONLY proto/gen/go
// cross-tree (D80), and the Rust dataplane cannot import a Go package at all.
// So the single-source property is the SAME one revocationwire uses: this fixture is
// the AUTHORITATIVE artifact, every value is RE-COMPUTED here from the canonical
// inputs by an independent codec, and the per-tree literal copies are each pinned by
// their own suite against their own independent re-derivation.
//
// Stdlib-only, zero dependencies — the package mirrors the wire contract, it does not
// import the Rust crate (it can't), any proto, or the orchestrator hostagent package.
// NEVER-LOG-THE-SECRET (D73): every fixture value is a SYNTHETIC conformance string (a
// ULID-shaped test uuid, a fixed ASCII host id, a distinct-byte index/timestamp),
// never a real session/secret byte.
package attendwire

import "encoding/binary"

// AttendednessFrameMaxBody is the hard cap on a single attendedness-fact frame body —
// MUST match AttendednessFactWire::MAX_FRAME_BODY (64*1024) in the Rust consumer and
// attendednessFrameMaxBody in the Go producer. A body over the cap is a malformed frame
// both halves drop fail-closed.
const AttendednessFrameMaxBody = 64 * 1024

// ─── The attendedness-fact golden (the single source both trees pin) ───

// The canonical fixture fact — byte-identical across the Go producer test, the Rust
// decoder test, and this fixture. Distinct-byte fields make a byte-order or field-order
// divergence visible (a little-endian host_session_index would render 04 03 02 01).

// GoldenSessionUUID is the fixture session UUID (a ULID-shaped test id).
const GoldenSessionUUID = "01HZX9K6Q2VN7T4M8B0CWRD5EF"

// GoldenHostID is the fixture host id.
const GoldenHostID = "host-att-conformance"

// GoldenHostSessionIndex is the fixture host-local session index. The distinct bytes
// (01 02 03 04) make a byte-order divergence in the 4-byte big-endian field visible.
const GoldenHostSessionIndex uint32 = 0x0102_0304

// GoldenTapName is the fixture tap name (the authoritative join key the feed is keyed by).
const GoldenTapName = "dstap-9"

// GoldenAttended is the fixture attended verdict (ATTENDED — a non-zero attended byte the
// consumer records as a live human signal).
const GoldenAttended = true

// GoldenAttendedAtUnixS is the fixture server-stamped freshness clock. The distinct bytes
// make a byte-order divergence in the 8-byte big-endian field visible.
const GoldenAttendedAtUnixS uint64 = 0x0000_0000_6600_0000

// GoldenFactHex is the canonical fact-frame BODY bytes the attendedness wire contract
// serialises the golden fact to, as hex:
//
//	str(session_uuid) || str(host_id) || host_session_index(4B BE) || str(tap_name) ||
//	attended(1B) || attended_at_unix_s(8B BE)
//
// where str(x) = len(4B BE) || utf8(x). This is the byte-for-byte frame BODY (no outer
// 4-byte frame length prefix) BOTH languages agree on; the conformance suite re-derives it
// with EncodeAttendednessFact and asserts equality, so the golden is never an unchecked
// literal. IDENTICAL to the Go test's goldenHex and the Rust test's ATTENDWIRE_GOLDEN_FACT_HEX.
const GoldenFactHex = "0000001a3031485a58394b365132564e3754344d3842304357524435454600000014686f73742d6174742d636f6e666f726d616e6365010203040000000764737461702d39010000000066000000"

// EncodeAttendednessFact is the INDEPENDENT reference encoder for one attendedness-fact
// frame body — a byte-for-byte port of the Go producer's encodeAttendednessFact
// (attendedness_producer.go) and the inverse of the Rust consumer's
// AttendednessFactWire::decode_fact (main.rs):
//
//	str(session_uuid) || str(host_id) || host_session_index(4B BE) || str(tap_name) ||
//	attended(1B: 0|1) || attended_at_unix_s(8B BE).
//
// The conformance suite encodes the canonical fact with THIS and asserts it equals the
// pinned GoldenFactHex, so the golden is the authoritative produce-once wire form derived
// from the canonical inputs, not an unverified literal. A frame-shape drift in this single
// source turns the suite RED.
func EncodeAttendednessFact(sessionUUID, hostID string, hostSessionIndex uint32, tapName string, attended bool, attendedAtUnixS uint64) []byte {
	out := make([]byte, 0, 32)
	out = putStr(out, sessionUUID)
	out = putStr(out, hostID)
	out = binary.BigEndian.AppendUint32(out, hostSessionIndex)
	out = putStr(out, tapName)
	// attended: 1 iff true, 0 otherwise — an honest UNATTENDED is a real 0 byte.
	if attended {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = binary.BigEndian.AppendUint64(out, attendedAtUnixS)
	return out
}

// putStr appends a length-prefixed string (len(4B BE) || utf8 bytes) — the SAME framing
// both halves' put_str / putAttWireStr use.
func putStr(out []byte, s string) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
	return append(out, s...)
}

// DecodeAttendednessFact is the INDEPENDENT reference decoder — the byte-for-byte mirror of
// the Rust AttendednessFactWire::decode_fact (main.rs) and the Go
// decodeAttendednessFactForTest (attendedness_producer_test.go). It returns ok=false
// FAIL-CLOSED for a malformed frame, with the SAME rejection set both decoders pin:
//
//   - a truncated field (the body ends before a length prefix / a declared field / the
//     1-byte attended / the 8-byte attended_at);
//   - an attended byte outside {0,1} (never a guessed verdict — the fail-OPEN hole to avoid);
//   - a length prefix over AttendednessFrameMaxBody (a hostile/oversized frame);
//   - trailing bytes AFTER attended_at (an over-long frame — the body did not consume exactly).
//
// It never fabricates a fact from a malformed frame (the ingest drops the connection
// fail-closed, records nothing → the session stays UNATTENDED). The conformance suite drives
// truncated / over-long / bad-attended-byte inputs through it and asserts they are rejected
// identically to both sides.
func DecodeAttendednessFact(body []byte) (sessionUUID, hostID string, hostSessionIndex uint32, tapName string, attended bool, attendedAtUnixS uint64, ok bool) {
	cur := body
	var got bool
	if sessionUUID, cur, got = takeStr(cur); !got {
		return "", "", 0, "", false, 0, false
	}
	if hostID, cur, got = takeStr(cur); !got {
		return "", "", 0, "", false, 0, false
	}
	if hostSessionIndex, cur, got = takeU32(cur); !got {
		return "", "", 0, "", false, 0, false
	}
	if tapName, cur, got = takeStr(cur); !got {
		return "", "", 0, "", false, 0, false
	}
	if len(cur) < 1 {
		return "", "", 0, "", false, 0, false
	}
	switch cur[0] {
	case 0:
		attended = false
	case 1:
		attended = true
	default:
		// An attended byte outside {0,1} is malformed — never a guessed verdict.
		return "", "", 0, "", false, 0, false
	}
	cur = cur[1:]
	if attendedAtUnixS, cur, got = takeU64(cur); !got {
		return "", "", 0, "", false, 0, false
	}
	// The frame must consume EXACTLY: trailing bytes are an over-long (malformed) frame.
	if len(cur) != 0 {
		return "", "", 0, "", false, 0, false
	}
	return sessionUUID, hostID, hostSessionIndex, tapName, attended, attendedAtUnixS, true
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
// ok=false on a short body or a length over AttendednessFrameMaxBody (a hostile prefix).
func takeStr(cur []byte) (string, []byte, bool) {
	n, rest, ok := takeU32(cur)
	if !ok {
		return "", cur, false
	}
	if int(n) > AttendednessFrameMaxBody || len(rest) < int(n) {
		return "", cur, false
	}
	return string(rest[:n]), rest[n:], true
}
