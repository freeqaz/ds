// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// decodedResponse is the set of ValidateResponse fields the independent in-test
// decoder recovers. It mirrors the four fields validate_client.rs reads.
type decodedResponse struct {
	verdict  uint64
	reason   string
	grantRef string
	expiry   uint64
}

// decodeResponseFields parses the hand-encoded ValidateResponse into its fields,
// using the same wire rules validate_client.rs uses. This is an INDEPENDENT decoder
// (not encodeAllowResponse/encodeDenyResponse's own inverse) so the test checks the
// produced bytes against a SECOND reader, proving genuine proto3 bytes. It is the
// t.Fatalf convenience wrapper over tryDecodeResponseFields — one decode loop, two
// failure postures — for cases whose body MUST be well-formed.
func decodeResponseFields(t *testing.T, body []byte) decodedResponse {
	t.Helper()
	got, err := tryDecodeResponseFields(body)
	if err != nil {
		t.Fatalf("decode ValidateResponse: %v", err)
	}
	return got
}

// errMalformed is returned by tryDecodeResponseFields for any body that a proto3
// decoder cannot parse (a truncated varint, a LEN field whose length overruns the
// body, or an unknown wire type). It stands in for the parse failure the client's
// real decoder would raise on a garbage frame.
var errMalformed = errors.New("malformed ValidateResponse body")

// readVarintErr reads a base-128 varint from b at off, returning errMalformed
// (never calling t.Fatalf) on a truncated varint, so tryDecodeResponseFields can
// report a parse failure the way the client's decoder would rather than aborting
// the test. Used to prove the GARBAGE body does not parse.
func readVarintErr(b []byte, off int) (uint64, int, error) {
	var v uint64
	var shift uint
	for {
		if off >= len(b) {
			return 0, off, errMalformed
		}
		c := b[off]
		off++
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, off, nil
		}
		shift += 7
	}
}

// tryDecodeResponseFields is THE decode loop: it parses a ValidateResponse using
// the same wire rules validate_client.rs uses, returning errMalformed instead of
// t.Fatalf on any unparseable byte, so a test can assert that a GARBAGE body fails
// to decode AND that no (partial) ALLOW is ever salvaged from it. A clean parse of
// an empty body yields all-default fields (verdict=0), which is exactly the
// UNSPECIFIED case. decodeResponseFields is its fatal wrapper for must-parse cases.
func tryDecodeResponseFields(body []byte) (decodedResponse, error) {
	var got decodedResponse
	off := 0
	for off < len(body) {
		tag, n, err := readVarintErr(body, off)
		if err != nil {
			return decodedResponse{}, err
		}
		off = n
		field := uint32(tag >> 3)
		wt := uint32(tag & 0x7)
		switch wt {
		case wireVarint:
			val, n2, err := readVarintErr(body, off)
			if err != nil {
				return decodedResponse{}, err
			}
			off = n2
			switch field {
			case fieldVerdict:
				got.verdict = val
			case fieldExpiry:
				got.expiry = val
			}
		case wireLen:
			l, n2, err := readVarintErr(body, off)
			if err != nil {
				return decodedResponse{}, err
			}
			off = n2
			end := off + int(l)
			if end > len(body) {
				return decodedResponse{}, fmt.Errorf("%w: LEN field %d overruns body (need %d, have %d)", errMalformed, field, end, len(body))
			}
			switch field {
			case fieldReason:
				got.reason = string(body[off:end])
			case fieldGrantRef:
				got.grantRef = string(body[off:end])
			}
			off = end
		default:
			return decodedResponse{}, fmt.Errorf("%w: unknown wire type %d on field %d", errMalformed, wt, field)
		}
	}
	return got, nil
}

func TestEncodeAllowResponseShape(t *testing.T) {
	body := encodeAllowResponse("grant-anthropic", 4102444800)
	got := decodeResponseFields(t, body)
	if got.verdict != verdictAllow {
		t.Fatalf("verdict = %d, want %d (ALLOW)", got.verdict, verdictAllow)
	}
	if got.grantRef != "grant-anthropic" {
		t.Fatalf("grant_ref = %q, want %q", got.grantRef, "grant-anthropic")
	}
	if got.expiry != 4102444800 {
		t.Fatalf("expiry = %d, want %d", got.expiry, 4102444800)
	}
	if got.reason != "" {
		t.Fatalf("reason = %q, want empty on an ALLOW", got.reason)
	}
}

func TestEncodeAllowResponseOmitsEmptyGrantRef(t *testing.T) {
	// proto3 default-omission: an empty grant_ref is not emitted, but verdict
	// (non-default ALLOW) and a non-zero expiry still are.
	body := encodeAllowResponse("", 1)
	got := decodeResponseFields(t, body)
	if got.verdict != verdictAllow {
		t.Fatalf("verdict = %d, want ALLOW", got.verdict)
	}
	if got.grantRef != "" {
		t.Fatalf("grant_ref = %q, want empty", got.grantRef)
	}
	if got.expiry != 1 {
		t.Fatalf("expiry = %d, want 1", got.expiry)
	}
}

// TestEncodeDenyResponseShape proves the DENY encoder emits a real proto3 DENY:
// verdict=DENY (2) + the configured machine_readable_reason, decoded back via the
// INDEPENDENT in-test decoder. This is the leg the live posture-b proof drives so
// the client's fail-closed DENY mapping is exercised against a real responder.
func TestEncodeDenyResponseShape(t *testing.T) {
	body := encodeDenyResponse("tls5-out-of-grant")
	got := decodeResponseFields(t, body)
	if got.verdict != verdictDeny {
		t.Fatalf("verdict = %d, want %d (DENY)", got.verdict, verdictDeny)
	}
	if got.reason != "tls5-out-of-grant" {
		t.Fatalf("reason = %q, want %q", got.reason, "tls5-out-of-grant")
	}
	// A DENY carries no grant_ref / expiry.
	if got.grantRef != "" {
		t.Fatalf("grant_ref = %q, want empty on a DENY", got.grantRef)
	}
	if got.expiry != 0 {
		t.Fatalf("expiry = %d, want 0 on a DENY", got.expiry)
	}
}

// TestEncodeDenyResponseOmitsEmptyReason: proto3 default-omission drops an empty
// reason, but the DENY verdict (non-default) is still emitted, so the client reads
// a DENY and maps the empty reason to its conservative OutOfGrant class.
func TestEncodeDenyResponseOmitsEmptyReason(t *testing.T) {
	body := encodeDenyResponse("")
	got := decodeResponseFields(t, body)
	if got.verdict != verdictDeny {
		t.Fatalf("verdict = %d, want DENY", got.verdict)
	}
	if got.reason != "" {
		t.Fatalf("reason = %q, want empty", got.reason)
	}
}

// TestVerdictsDiffer guards against an accidental ALLOW/DENY collision: the two
// reply bodies must never be byte-identical, or a deny test could silently pass on
// an allow body.
func TestVerdictsDiffer(t *testing.T) {
	allow := encodeAllowResponse("grant-anthropic", 4102444800)
	deny := encodeDenyResponse("tls5-out-of-grant")
	if string(allow) == string(deny) {
		t.Fatal("ALLOW and DENY bodies are byte-identical")
	}
}

// TestEncodeUnspecifiedResponseFailsClosed proves the UNSPECIFIED emitter yields a
// well-formed but verdict-UNSPECIFIED (proto3 default 0 → empty body) response that
// the client MUST fail-closed to a DENY: it parses cleanly, but verdict != ALLOW
// and NO grant_ref/expiry rides it. A responder that answered but proved nothing is
// not an ALLOW.
func TestEncodeUnspecifiedResponseFailsClosed(t *testing.T) {
	body := encodeUnspecifiedResponse()
	// The UNSPECIFIED body is empty: proto3 omits the default-valued verdict field.
	if len(body) != 0 {
		t.Fatalf("unspecified body = %v (len %d), want empty (verdict=0 is a proto3 default and is omitted)", body, len(body))
	}
	// It still decodes cleanly (an empty message is valid proto3) to all-defaults.
	got, err := tryDecodeResponseFields(body)
	if err != nil {
		t.Fatalf("unspecified body should decode cleanly (empty message is valid proto3): %v", err)
	}
	// FAIL-CLOSED: the verdict is UNSPECIFIED (0), which is NOT ALLOW — the client
	// must map it to a DENY.
	if got.verdict == verdictAllow {
		t.Fatalf("verdict = %d (ALLOW) — an UNSPECIFIED response must NEVER decode to ALLOW", got.verdict)
	}
	if got.verdict != verdictUnspecified {
		t.Fatalf("verdict = %d, want %d (UNSPECIFIED)", got.verdict, verdictUnspecified)
	}
	// No grant may ride an UNSPECIFIED: no grant_ref, no expiry.
	if got.grantRef != "" {
		t.Fatalf("grant_ref = %q, want empty on an UNSPECIFIED response", got.grantRef)
	}
	if got.expiry != 0 {
		t.Fatalf("expiry = %d, want 0 on an UNSPECIFIED response", got.expiry)
	}
}

// TestEncodeGarbageResponseFailsClosed proves the GARBAGE emitter yields a
// malformed/truncated body that a proto3 decoder CANNOT parse — so no ALLOW can be
// salvaged from it — and that it is not byte-identical to a valid ALLOW. The client
// must treat an unparseable response as a fail-closed DENY.
func TestEncodeGarbageResponseFailsClosed(t *testing.T) {
	body := encodeGarbageResponse()
	if len(body) == 0 {
		t.Fatal("garbage body is empty; want a malformed non-empty frame that fails to parse")
	}
	// It must NOT parse: a real decoder errors on the overrunning LEN field.
	got, err := tryDecodeResponseFields(body)
	if err == nil {
		t.Fatalf("garbage body decoded to %+v with no error — a malformed frame must NOT parse", got)
	}
	if !errors.Is(err, errMalformed) {
		t.Fatalf("garbage decode error = %v, want errMalformed", err)
	}
	// Belt-and-suspenders: it must never be byte-identical to a valid ALLOW body,
	// so a fail-closed reader can never mistake it for a grant.
	if string(body) == string(encodeAllowResponse("grant-anthropic", 4102444800)) {
		t.Fatal("garbage body is byte-identical to a valid ALLOW body")
	}
}

// TestUnspecifiedAndGarbageDifferFromAllow guards the fail-closed emitters against
// an accidental ALLOW collision: neither the UNSPECIFIED nor the GARBAGE body may
// ever equal the ALLOW body, or a fail-closed test could silently pass on an ALLOW.
func TestUnspecifiedAndGarbageDifferFromAllow(t *testing.T) {
	allow := encodeAllowResponse("grant-anthropic", 4102444800)
	if string(encodeUnspecifiedResponse()) == string(allow) {
		t.Fatal("UNSPECIFIED and ALLOW bodies are byte-identical")
	}
	if string(encodeGarbageResponse()) == string(allow) {
		t.Fatal("GARBAGE and ALLOW bodies are byte-identical")
	}
}

// TestUDSRoundTripUnspecified drives the full server framing with an UNSPECIFIED
// (empty) response body: the client reads a length-prefixed, zero-length body over
// the UDS and MUST fail-closed it to a DENY (verdict != ALLOW, no grant rides),
// proving the fail-closed leg works end-to-end against a REAL responder.
func TestUDSRoundTripUnspecified(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "validate.sock")

	ln, err := listenUDS(sock)
	if err != nil {
		t.Fatalf("listenUDS: %v", err)
	}
	defer ln.Close()

	resp := encodeUnspecifiedResponse()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleConn(conn, resp)
	}()

	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	reqBody := []byte("opaque-validate-request-bytes")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(reqBody)))
	if _, err := c.Write(lenBuf[:]); err != nil {
		t.Fatalf("write req len: %v", err)
	}
	if _, err := c.Write(reqBody); err != nil {
		t.Fatalf("write req body: %v", err)
	}

	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		t.Fatalf("read resp len: %v", err)
	}
	rl := binary.BigEndian.Uint32(lenBuf[:])
	// The UNSPECIFIED frame carries a zero-length body — a valid, empty response.
	if rl != 0 {
		t.Fatalf("round-trip resp len = %d, want 0 (empty UNSPECIFIED body)", rl)
	}
	got := make([]byte, rl)
	if rl > 0 {
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("read resp body: %v", err)
		}
	}

	rt, err := tryDecodeResponseFields(got)
	if err != nil {
		t.Fatalf("empty UNSPECIFIED body should decode cleanly: %v", err)
	}
	if rt.verdict == verdictAllow {
		t.Fatalf("round-trip verdict = %d (ALLOW) — UNSPECIFIED must fail-closed to DENY", rt.verdict)
	}
	if rt.grantRef != "" || rt.expiry != 0 {
		t.Fatalf("round-trip carried a grant (grant_ref=%q expiry=%d) on an UNSPECIFIED response", rt.grantRef, rt.expiry)
	}
}

// TestUDSRoundTripGarbage drives the full server framing with a GARBAGE response
// body: the client reads the length-prefixed malformed frame over the UDS and MUST
// fail to parse it (fail-closed to a DENY — never a salvaged ALLOW), proving the
// malformed-frame fail-closed leg works end-to-end against a REAL responder.
func TestUDSRoundTripGarbage(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "validate.sock")

	ln, err := listenUDS(sock)
	if err != nil {
		t.Fatalf("listenUDS: %v", err)
	}
	defer ln.Close()

	resp := encodeGarbageResponse()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleConn(conn, resp)
	}()

	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	reqBody := []byte("opaque-validate-request-bytes")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(reqBody)))
	if _, err := c.Write(lenBuf[:]); err != nil {
		t.Fatalf("write req len: %v", err)
	}
	if _, err := c.Write(reqBody); err != nil {
		t.Fatalf("write req body: %v", err)
	}

	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		t.Fatalf("read resp len: %v", err)
	}
	rl := binary.BigEndian.Uint32(lenBuf[:])
	got := make([]byte, rl)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read resp body: %v", err)
	}

	// The framed body is transported intact — but it MUST NOT parse to a verdict.
	if _, err := tryDecodeResponseFields(got); err == nil {
		t.Fatal("round-trip GARBAGE body parsed cleanly — a malformed frame must fail-closed to a DENY")
	}
}

// TestUDSRoundTripAllow drives the full server framing: bind, dial, write a
// length-prefixed request frame (a synthetic body the server must consume but
// never decode), and assert a length-prefixed ALLOW response comes back.
func TestUDSRoundTripAllow(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "validate.sock")

	ln, err := listenUDS(sock)
	if err != nil {
		t.Fatalf("listenUDS: %v", err)
	}
	defer ln.Close()

	resp := encodeAllowResponse("grant-anthropic", 4102444800)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleConn(conn, resp)
	}()

	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	// Write one synthetic request frame (opaque bytes — the fake ignores it).
	reqBody := []byte("opaque-validate-request-bytes")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(reqBody)))
	if _, err := c.Write(lenBuf[:]); err != nil {
		t.Fatalf("write req len: %v", err)
	}
	if _, err := c.Write(reqBody); err != nil {
		t.Fatalf("write req body: %v", err)
	}

	// Read the framed response.
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		t.Fatalf("read resp len: %v", err)
	}
	rl := binary.BigEndian.Uint32(lenBuf[:])
	got := make([]byte, rl)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read resp body: %v", err)
	}

	rt := decodeResponseFields(t, got)
	if rt.verdict != verdictAllow {
		t.Fatalf("round-trip verdict = %d, want ALLOW", rt.verdict)
	}
	if rt.grantRef != "grant-anthropic" {
		t.Fatalf("round-trip grant_ref = %q, want grant-anthropic", rt.grantRef)
	}
	if rt.expiry != 4102444800 {
		t.Fatalf("round-trip expiry = %d, want 4102444800", rt.expiry)
	}
}

// TestUDSRoundTripDeny drives the full server framing with a DENY response body:
// the client must read back verdict=DENY + the reason over the same length-prefixed
// frame, proving the deny leg works end-to-end over the UDS transport.
func TestUDSRoundTripDeny(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "validate.sock")

	ln, err := listenUDS(sock)
	if err != nil {
		t.Fatalf("listenUDS: %v", err)
	}
	defer ln.Close()

	resp := encodeDenyResponse("tls5-out-of-grant")
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleConn(conn, resp)
	}()

	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	reqBody := []byte("opaque-validate-request-bytes")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(reqBody)))
	if _, err := c.Write(lenBuf[:]); err != nil {
		t.Fatalf("write req len: %v", err)
	}
	if _, err := c.Write(reqBody); err != nil {
		t.Fatalf("write req body: %v", err)
	}

	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		t.Fatalf("read resp len: %v", err)
	}
	rl := binary.BigEndian.Uint32(lenBuf[:])
	got := make([]byte, rl)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read resp body: %v", err)
	}

	rt := decodeResponseFields(t, got)
	if rt.verdict != verdictDeny {
		t.Fatalf("round-trip verdict = %d, want DENY", rt.verdict)
	}
	if rt.reason != "tls5-out-of-grant" {
		t.Fatalf("round-trip reason = %q, want tls5-out-of-grant", rt.reason)
	}
}

// TestResolveUDS checks the flag > env > default precedence.
func TestResolveUDS(t *testing.T) {
	if got := resolveUDS("/explicit.sock"); got != "/explicit.sock" {
		t.Fatalf("flag should win: got %q", got)
	}
	t.Setenv(udsEnv, "/from-env.sock")
	if got := resolveUDS(""); got != "/from-env.sock" {
		t.Fatalf("env should be used when flag empty: got %q", got)
	}
	if err := os.Unsetenv(udsEnv); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if got := resolveUDS(""); got != defaultUDS {
		t.Fatalf("default should be used when both empty: got %q", got)
	}
}
