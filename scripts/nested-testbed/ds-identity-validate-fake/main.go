// SPDX-License-Identifier: Apache-2.0

// ds-identity-validate-fake — a minimal, stdlib-only FAKE of the D22
// dreamserpent.identity.v1 Validate UDS responder, for the nested KVM testbed
// (doc 16 §4 / §9; Phase B posture-b cred-swap live proof, gap B2).
//
// # Why this exists
//
// ds-tlsproxy's live D22 Validate client
// (dataplane/services/ds-tlsproxy/src/validate_client.rs) dials a UDS, sends a
// length-prefixed ValidateRequest frame, and expects a length-prefixed
// ValidateResponse frame back. Nothing answers that socket in the testbed today.
// This program is that responder — a TEST FAKE only. It must never run on a path
// that gates production credential egress.
//
// By default (no --verdict, or --verdict=allow) it ALWAYS allows, ignoring the
// request body entirely. Pass --verdict=deny to drive the DENY leg of the live
// posture-b proof: the client's fail-closed DENY mapping (each tls5-* reason →
// DenyReason; UNSPECIFIED/transport-fault → fail-closed DENY) has no coverage
// against a real responder until something can return an actual DENY verdict.
//
// --verdict=unspecified and --verdict=garbage drive the FAIL-CLOSED half of that
// mapping. UNSPECIFIED is a well-formed ValidateResponse whose verdict field is
// the proto3 default (0 / VALIDATE_VERDICT_UNSPECIFIED, omitted on the wire) — a
// responder that answered but proved nothing; the client MUST collapse it to a
// DENY (never an ALLOW), so it may carry no grant_ref/expiry. GARBAGE is a
// deliberately malformed/truncated response body (a dangling LEN tag whose length
// prefix runs past the buffer) — an unparseable frame the client MUST also treat
// as a fail-closed DENY, never salvaging a partial ALLOW. Both let the client's
// fail-closed collapse in ds-tlsproxy validate_client.rs be proven against a REAL
// responder, not only unit-decode-tested.
//
// # Wire shape (must match validate_client.rs EXACTLY)
//
//   - Transport: a UnixStream. Each frame is a 4-byte BIG-ENDIAN body length
//     followed by that many body bytes (the proto3 message).
//   - The client opens a fresh connection per Validate call and writes one
//     request frame, but we also loop reading frames until EOF so the fake works
//     whether the client sends one-request-per-connection or many.
//   - The request body is the proto3 ValidateRequest. We CONSUME it (read exactly
//     the advertised length) but never decode it, and NEVER log it — it carries
//     the presented credential in cleartext (D50: never log a presented
//     credential/token).
//   - The ALLOW reply body is a fixed proto3 ValidateResponse encoding:
//     field 1 verdict             = 1 (VALIDATE_VERDICT_ALLOW)  [VARINT]
//     field 3 grant_ref           = --grant-ref (default grant-anthropic) [LEN]
//     field 4 expiry_unix_seconds = --expiry (default far-future)         [VARINT]
//     proto3 default-omission is irrelevant here: the always-ALLOW reply always
//     populates verdict (non-zero), and grant_ref/expiry are configured non-empty.
//   - The DENY reply body (--verdict=deny) is a proto3 ValidateResponse encoding:
//     field 1 verdict                 = 2 (VALIDATE_VERDICT_DENY)         [VARINT]
//     field 2 machine_readable_reason = --reason (default tls5-out-of-grant) [LEN]
//     The verdict (non-zero DENY=2) is always emitted; the reason is emitted when
//     non-empty (proto3 default-omission). No grant_ref / expiry rides a deny.
//   - The UNSPECIFIED reply body (--verdict=unspecified) is a proto3
//     ValidateResponse whose verdict = 0 (VALIDATE_VERDICT_UNSPECIFIED). Because 0
//     is the proto3 default, the field is OMITTED entirely — the body is empty (a
//     zero-length frame). An empty body decodes to every field at its default
//     (verdict=0, no grant_ref/expiry/reason), which the client MUST fail-closed to
//     a DENY: a responder that answered but proved nothing is not an ALLOW.
//   - The GARBAGE reply body (--verdict=garbage) is intentionally MALFORMED: a
//     grant_ref (field 3) LEN tag followed by a length prefix that overruns the
//     truncated body. No proto3 decoder can parse it; the client MUST treat an
//     unparseable response as a fail-closed DENY, never salvaging a partial ALLOW.
//
// # No dependencies
//
// stdlib only (net, encoding/binary, flag, os, log, io, time, errors,
// path/filepath). Its OWN go.mod (module ds-identity-validate-fake) with NO
// require lines, so `GOWORK=off go build .` works offline and outside go.work —
// no proto import, no prost analogue, the proto3 bytes are hand-encoded.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	// defaultUDS mirrors validate_client.rs DEFAULT_VALIDATE_UDS and the
	// DS_SWAP_VALIDATE_UDS env single-source.
	defaultUDS = "/run/ds-identity/validate.sock"
	// udsEnv is the env var that overrides the listen path, matching the
	// client's DS_SWAP_VALIDATE_UDS.
	udsEnv = "DS_SWAP_VALIDATE_UDS"

	// maxFrameBody bounds a single request frame body (bytes), matching the
	// client's MAX_FRAME_BODY (64 KiB). A length prefix over this cap is a
	// malformed/hostile frame — we drop the connection rather than allocate.
	maxFrameBody uint32 = 64 * 1024

	// proto3 wire types (low 3 bits of a field tag).
	wireVarint uint32 = 0
	wireLen    uint32 = 2

	// ValidateResponse field numbers (proto/dreamserpent/identity/v1/validate.proto).
	fieldVerdict  uint32 = 1
	fieldReason   uint32 = 2
	fieldGrantRef uint32 = 3
	fieldExpiry   uint32 = 4

	// ValidateVerdict enum values (validate.proto): VALIDATE_VERDICT_UNSPECIFIED = 0,
	// VALIDATE_VERDICT_ALLOW = 1, VALIDATE_VERDICT_DENY = 2 — the exact values
	// validate_client.rs decodes. UNSPECIFIED is the proto3 default (0): a
	// well-formed response that carries it OMITS the field, so an UNSPECIFIED body
	// is empty, and an empty/absent verdict is exactly what the client fail-closes
	// to a DENY.
	verdictUnspecified uint64 = 0
	verdictAllow       uint64 = 1
	verdictDeny        uint64 = 2

	// defaultDenyReason is the machine_readable_reason returned by --verdict=deny
	// when no --reason is given. It is one of the client's canonical tls5-* kebab
	// codes (validate_client.rs map_reason) — the conservative "no grant proven"
	// class (DenyReason::OutOfGrant).
	defaultDenyReason = "tls5-out-of-grant"
)

// appendVarint appends a base-128 varint (LEB128, little-endian groups) to out.
func appendVarint(out []byte, v uint64) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// appendTag appends a field tag (field_number << 3 | wire_type).
func appendTag(out []byte, fieldNumber, wireType uint32) []byte {
	return appendVarint(out, uint64(fieldNumber<<3|wireType))
}

// appendVarintField appends a VARINT field: tag then value.
func appendVarintField(out []byte, fieldNumber uint32, value uint64) []byte {
	out = appendTag(out, fieldNumber, wireVarint)
	return appendVarint(out, value)
}

// appendLenField appends a length-delimited (LEN) field: tag, length varint, bytes.
func appendLenField(out []byte, fieldNumber uint32, b []byte) []byte {
	out = appendTag(out, fieldNumber, wireLen)
	out = appendVarint(out, uint64(len(b)))
	return append(out, b...)
}

// encodeAllowResponse hand-encodes the fixed always-ALLOW ValidateResponse body:
// verdict=ALLOW, grant_ref, expiry_unix_seconds. No proto import.
func encodeAllowResponse(grantRef string, expiryUnix int64) []byte {
	out := make([]byte, 0, 32+len(grantRef))
	// field 1: verdict = 1 (ALLOW). Always emitted (non-default).
	out = appendVarintField(out, fieldVerdict, verdictAllow)
	// field 3: grant_ref (string). Emitted when non-empty (proto3 default-omission).
	if grantRef != "" {
		out = appendLenField(out, fieldGrantRef, []byte(grantRef))
	}
	// field 4: expiry_unix_seconds (int64). A negative value rides as a 64-bit
	// varint with the high bit set, matching the client's int64-over-varint decode.
	if expiryUnix != 0 {
		out = appendVarintField(out, fieldExpiry, uint64(expiryUnix))
	}
	return out
}

// encodeDenyResponse hand-encodes a DENY ValidateResponse body: verdict=DENY (2)
// and a machine_readable_reason string. No grant_ref / expiry rides a deny (they
// are proto3 defaults on the response and the client ignores them on DENY). No
// proto import. This drives the client's fail-closed DENY mapping in the live
// posture-b proof.
func encodeDenyResponse(reason string) []byte {
	out := make([]byte, 0, 16+len(reason))
	// field 1: verdict = 2 (DENY). Always emitted (non-default).
	out = appendVarintField(out, fieldVerdict, verdictDeny)
	// field 2: machine_readable_reason (string). Emitted when non-empty (proto3
	// default-omission); an empty reason maps to OutOfGrant on the client side.
	if reason != "" {
		out = appendLenField(out, fieldReason, []byte(reason))
	}
	return out
}

// encodeUnspecifiedResponse hand-encodes a well-formed ValidateResponse whose
// verdict is VALIDATE_VERDICT_UNSPECIFIED (0). Because 0 is the proto3 default,
// the verdict field is OMITTED, so this returns an EMPTY body — a responder that
// answered but proved nothing. No grant_ref / expiry / reason ride it (all proto3
// defaults). The client MUST fail-closed this to a DENY (verdict != ALLOW), never
// to an ALLOW: an absent/UNSPECIFIED verdict is the whole point of the
// fail-closed leg. No proto import.
func encodeUnspecifiedResponse() []byte {
	// The empty slice IS the encoding: proto3 omits every default-valued field, so
	// an all-default ValidateResponse (verdict=0, no other fields) is zero bytes.
	return []byte{}
}

// encodeGarbageResponse hand-encodes a deliberately MALFORMED ValidateResponse
// body the client cannot parse: a grant_ref (field 3) LEN tag followed by a
// length prefix that advertises more bytes than actually follow (the body is
// truncated right after the length). A proto3 decoder reading this hits a LEN
// field that overruns the buffer and errors out — the client MUST treat that
// unparseable frame as a fail-closed DENY, never salvaging a partial ALLOW. This
// is NOT a valid ValidateResponse and MUST never decode to one. No proto import.
func encodeGarbageResponse() []byte {
	out := make([]byte, 0, 4)
	// field 3 (grant_ref), wire type LEN: a well-formed tag...
	out = appendTag(out, fieldGrantRef, wireLen)
	// ...followed by a length prefix claiming 10 bytes, but we append NONE — the
	// body ends here, so any decoder trying to read those 10 bytes overruns.
	out = appendVarint(out, 10)
	return out
}

// handleConn serves one connection: read framed requests in a loop until EOF,
// reply a framed ALLOW response to each. The request body is consumed but never
// decoded and never logged (D50). resp is the pre-encoded fixed ALLOW body.
func handleConn(conn net.Conn, resp []byte) {
	defer conn.Close()
	var lenBuf [4]byte
	for {
		// Read the 4-byte BE request length prefix. Clean EOF ends the loop.
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				log.Printf("validate-fake: read length: %v", err)
			}
			return
		}
		bodyLen := binary.BigEndian.Uint32(lenBuf[:])
		if bodyLen > maxFrameBody {
			// A length over the cap is a malformed/hostile frame — drop the
			// connection (never allocate unboundedly). Length only; never the body.
			log.Printf("validate-fake: request frame body over cap (%d > %d) — dropping connection", bodyLen, maxFrameBody)
			return
		}
		// Consume exactly bodyLen bytes (the ValidateRequest). NEVER decode or log it.
		if bodyLen > 0 {
			if _, err := io.CopyN(io.Discard, conn, int64(bodyLen)); err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					log.Printf("validate-fake: read request body: %v", err)
				}
				return
			}
		}
		// Reply: 4-byte BE response length + the fixed ALLOW body.
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(resp)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			log.Printf("validate-fake: write response length: %v", err)
			return
		}
		if _, err := conn.Write(resp); err != nil {
			log.Printf("validate-fake: write response body: %v", err)
			return
		}
	}
}

// resolveUDS picks the listen path: the explicit --uds flag wins, else the
// DS_SWAP_VALIDATE_UDS env (matching the client), else defaultUDS.
func resolveUDS(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv(udsEnv); env != "" {
		return env
	}
	return defaultUDS
}

// listenUDS prepares the socket: 0700 parent dir, unlink any stale socket, then
// Listen. Returns the listener (the caller closes it).
func listenUDS(path string) (net.Listener, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	// Unlink-then-Listen: a stale socket file from a prior run would make bind fail.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return net.Listen("unix", path)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("ds-identity-validate-fake: ")

	udsFlag := flag.String("uds", "", "UDS listen path (default $"+udsEnv+" or "+defaultUDS+")")
	verdict := flag.String("verdict", "allow", "verdict to return: allow | deny | unspecified | garbage")
	grantRef := flag.String("grant-ref", "grant-anthropic", "grant_ref string returned in every ALLOW response")
	reason := flag.String("reason", defaultDenyReason, "machine_readable_reason returned in every DENY response (a tls5-* code)")
	// 4102444800 = 2100-01-01T00:00:00Z, a far-future expiry so the fake's ALLOW
	// never lapses during a testbed run.
	expiry := flag.Int64("expiry", 4102444800, "expiry_unix_seconds returned in every ALLOW response")
	flag.Parse()

	path := resolveUDS(*udsFlag)

	// Pick the fixed reply body from the configured verdict. The default verdict is
	// "allow", so the no-flag invocation is byte-identical to the historical
	// always-ALLOW fake. Any unrecognized verdict is a hard config error — fail
	// loudly rather than silently fall back to ALLOW (a deny test that accidentally
	// allowed would silently pass).
	var resp []byte
	switch *verdict {
	case "allow":
		resp = encodeAllowResponse(*grantRef, *expiry)
	case "deny":
		resp = encodeDenyResponse(*reason)
	case "unspecified":
		// A well-formed but verdict-UNSPECIFIED (proto3 default 0 → empty body)
		// response: the client must fail-closed this to a DENY.
		resp = encodeUnspecifiedResponse()
	case "garbage":
		// A malformed/truncated body the client cannot parse: also a fail-closed DENY.
		resp = encodeGarbageResponse()
	default:
		log.Fatalf("invalid --verdict %q: want allow | deny | unspecified | garbage", *verdict)
	}

	ln, err := listenUDS(path)
	if err != nil {
		log.Fatalf("listen on %s: %v", path, err)
	}
	defer ln.Close()
	// Never log the credential/request; the verdict + grant_ref/reason + expiry are
	// non-secret fake config, safe to log so an operator can see what the fake returns.
	switch *verdict {
	case "deny":
		log.Printf("FAKE always-DENY Validate server listening on %s (reason=%q) — TEST USE ONLY",
			path, *reason)
	case "unspecified":
		log.Printf("FAKE always-UNSPECIFIED Validate server listening on %s (verdict=0, empty body — client must fail-closed to DENY) — TEST USE ONLY",
			path)
	case "garbage":
		log.Printf("FAKE always-GARBAGE Validate server listening on %s (malformed/truncated body — client must fail-closed to DENY) — TEST USE ONLY",
			path)
	default:
		log.Printf("FAKE always-ALLOW Validate server listening on %s (grant_ref=%q expiry=%s) — TEST USE ONLY",
			path, *grantRef, time.Unix(*expiry, 0).UTC().Format(time.RFC3339))
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed listener (shutdown) ends the loop; transient accept errors
			// are logged and retried.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, resp)
	}
}
