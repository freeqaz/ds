// SPDX-License-Identifier: Apache-2.0

package hostagent

// attendedness_producer_test.go is the SYNTHETIC in-process proof of the D78
// attendedness-fact PRODUCER (attendedness_producer.go) against the CROSS-PROCESS wire
// contract the ds-tlsproxy consumer (dataplane/services/ds-tlsproxy/src/main.rs
// AttendednessFactWire / serve_attendedness_feed) decodes. There is no live
// claude/cia/qemu/podman and no Rust here — the test drives the Go encoder + producer and
// asserts the EXACT bytes-on-the-wire the consumer parses, using a Go re-implementation of
// that decoder (decodeAttendednessFactForTest) built INDEPENDENTLY from the encoder so a
// drift on either side fails the round-trip.
//
// The DS_ATTENDEDNESS_FEED_LIVE-gated e2e (TestAttendednessProducer_LiveDeliversFrame)
// stands up a synthetic in-process UDS server that reads ONE length-prefixed frame the SAME
// way serve_attendedness_feed's read_attendedness_frame does, and proves a fact is encoded
// + delivered byte-for-byte. With the gate UNSET the producer is a no-op (no dial) — the
// default-OFF byte-identical posture.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// ── a Go mirror of the consumer's AttendednessFactWire::decode_fact (main.rs) ──
//
// Built independently from the producer's encoder so the round-trip catches a drift on
// EITHER side. It parses the exact body layout the Rust decoder does and returns ok=false
// on any structural mismatch (a truncated field, an attended byte outside {0,1}, trailing
// bytes) — the fail-closed posture the subscriber takes. Uses the takeU32/takeU64/takeStr
// helpers already defined in revocation_producer_test.go (same package).

func decodeAttendednessFactForTest(body []byte) (*AttendednessFact, bool) {
	cur := body
	sessionUUID, ok := takeStr(&cur)
	if !ok {
		return nil, false
	}
	hostID, ok := takeStr(&cur)
	if !ok {
		return nil, false
	}
	idx, ok := takeU32(&cur)
	if !ok {
		return nil, false
	}
	tapName, ok := takeStr(&cur)
	if !ok {
		return nil, false
	}
	attByte, ok := takeU8(&cur)
	if !ok {
		return nil, false
	}
	var attended bool
	switch attByte {
	case 0:
		attended = false
	case 1:
		attended = true
	default:
		// An attended byte outside {0,1} is malformed — never a guessed verdict.
		return nil, false
	}
	at, ok := takeU64(&cur)
	if !ok {
		return nil, false
	}
	// Trailing bytes after the declared fact are a malformed frame.
	if len(cur) != 0 {
		return nil, false
	}
	return &AttendednessFact{
		Session: AttendednessSessionRef{
			SessionUUID:      sessionUUID,
			HostID:           hostID,
			HostSessionIndex: idx,
			TapName:          tapName,
		},
		Attended:        attended,
		AttendedAtUnixS: at,
	}, true
}

func sampleAttSession() AttendednessSessionRef {
	return AttendednessSessionRef{
		SessionUUID:      "01HZX9K6Q2VN7T4M8B0CWRD5EF",
		HostID:           "host-att",
		HostSessionIndex: 0x0102_0304,
		TapName:          "dstap-9",
	}
}

// TestAttendednessProducer_EncodeRoundTrips proves the encoder ⇄ independent decoder agree
// for both an attended and an unattended fact.
func TestAttendednessProducer_EncodeRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name     string
		attended bool
		at       uint64
	}{
		{"attended", true, 1_700_000_042},
		{"unattended", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fact := &AttendednessFact{Session: sampleAttSession(), Attended: tc.attended, AttendedAtUnixS: tc.at}
			body, err := encodeAttendednessFact(fact)
			if err != nil {
				t.Fatalf("encodeAttendednessFact: %v", err)
			}
			got, ok := decodeAttendednessFactForTest(body)
			if !ok {
				t.Fatal("independent decoder rejected a well-formed fact")
			}
			if got.Session != fact.Session || got.Attended != fact.Attended || got.AttendedAtUnixS != fact.AttendedAtUnixS {
				t.Fatalf("round-trip mismatch: got %+v, want %+v", got, fact)
			}
		})
	}
}

// TestAttendednessProducer_EncodeExactBytes pins the EXACT bytes-on-the-wire — the
// byte-for-byte match of the ds-tlsproxy consumer's AttendednessFactWire::decode_fact input
// AND the assurance/conformance-adapter/attendwire golden. This is the cross-process /
// cross-language pin: the hex here is hand-copied byte-identical with the Rust
// ATTENDWIRE_GOLDEN_FACT_HEX and the attendwire fixture's AttendednessGoldenFactHex, each
// re-derived by its own independent encoder, so a wire drift on any tree fails a suite.
func TestAttendednessProducer_EncodeExactBytes(t *testing.T) {
	// Canonical inputs — MUST be byte-identical with the attendwire fixture + the Rust golden.
	fact := &AttendednessFact{
		Session: AttendednessSessionRef{
			SessionUUID:      "01HZX9K6Q2VN7T4M8B0CWRD5EF",
			HostID:           "host-att-conformance",
			HostSessionIndex: 0x0102_0304,
			TapName:          "dstap-9",
		},
		Attended:        true,
		AttendedAtUnixS: 0x0000_0000_6600_0000,
	}
	const goldenHex = "0000001a3031485a58394b365132564e3754344d3842304357524435454600000014686f73742d6174742d636f6e666f726d616e6365010203040000000764737461702d39010000000066000000"

	body, err := encodeAttendednessFact(fact)
	if err != nil {
		t.Fatalf("encodeAttendednessFact: %v", err)
	}
	gotHex := hexOf(body)
	if gotHex != goldenHex {
		t.Fatalf("wire bytes drifted from the cross-language golden:\n got  %s\n want %s", gotHex, goldenHex)
	}
}

// hexOf renders bytes as lowercase hex (a tiny local helper — no dependency).
func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	return string(out)
}

// TestAttendednessProducer_FactFromLifecycleUpdate proves the projection off a
// SessionLifecycleUpdate reads ONLY the frozen attended=4 / attended_at=5 slots and NEVER
// fabricates attended.
func TestAttendednessProducer_FactFromLifecycleUpdate(t *testing.T) {
	ref := sampleAttSession()

	t.Run("attended true rides through", func(t *testing.T) {
		up := &hostagentv1.SessionLifecycleUpdate{SessionUuid: ref.SessionUUID, Attended: true, AttendedAt: 1_700_000_500}
		fact, err := FactFromLifecycleUpdate(ref, up)
		if err != nil {
			t.Fatalf("FactFromLifecycleUpdate: %v", err)
		}
		if !fact.Attended || fact.AttendedAtUnixS != 1_700_000_500 {
			t.Fatalf("attended fact = %+v, want attended=true at 1700000500", fact)
		}
		if fact.Session != ref {
			t.Errorf("session quartet = %+v, want %+v (the host's resolved join-keys)", fact.Session, ref)
		}
	})

	t.Run("attended false forwards honestly (never fabricated)", func(t *testing.T) {
		up := &hostagentv1.SessionLifecycleUpdate{SessionUuid: ref.SessionUUID, Attended: false, AttendedAt: 42}
		fact, err := FactFromLifecycleUpdate(ref, up)
		if err != nil {
			t.Fatalf("FactFromLifecycleUpdate: %v", err)
		}
		if fact.Attended {
			t.Fatal("a false attended field must NOT be upgraded to attended=true")
		}
	})

	t.Run("absent attended field defaults to false", func(t *testing.T) {
		// A zero-value update (attended unset) reads attended=false via GetAttended — an
		// absent D78 signal is an honest UNATTENDED, never fabricated.
		up := &hostagentv1.SessionLifecycleUpdate{SessionUuid: ref.SessionUUID}
		fact, err := FactFromLifecycleUpdate(ref, up)
		if err != nil {
			t.Fatalf("FactFromLifecycleUpdate: %v", err)
		}
		if fact.Attended {
			t.Fatal("an absent attended field must read as UNATTENDED")
		}
	})

	t.Run("nil update rejected", func(t *testing.T) {
		if _, err := FactFromLifecycleUpdate(ref, nil); err == nil {
			t.Fatal("FactFromLifecycleUpdate accepted a nil update")
		}
	})
}

// TestAttendednessProducer_DefaultOffIsNoDial proves the DEFAULT-OFF posture: with the live
// gate UNSET the producer's Forward builds the fact but dials NOTHING — byte-identical to
// the pre-producer daemon. The endpoint is an address nothing is listening on, so a dial
// would error; the clean nil return proves no dial happened.
func TestAttendednessProducer_DefaultOffIsNoDial(t *testing.T) {
	p, err := NewAttendednessProducerAt(filepath.Join(t.TempDir(), "nonexistent.sock"), false)
	if err != nil {
		t.Fatalf("NewAttendednessProducerAt: %v", err)
	}
	if p.Live() {
		t.Fatal("producer reports Live() with live=false")
	}
	up := &hostagentv1.SessionLifecycleUpdate{SessionUuid: sampleAttSession().SessionUUID, Attended: true, AttendedAt: 99}
	if err := p.Forward(context.Background(), sampleAttSession(), up); err != nil {
		t.Fatalf("default-off Forward returned an error (it must not dial): %v", err)
	}
}

// TestAttendednessProducer_LiveEmptyEndpointRejected proves a live producer with no
// endpoint is rejected (it could never deliver).
func TestAttendednessProducer_LiveEmptyEndpointRejected(t *testing.T) {
	if _, err := NewAttendednessProducerAt("", true); err == nil {
		t.Fatal("NewAttendednessProducerAt accepted a live producer with an empty endpoint")
	}
}

// TestAttendednessProducer_NilFactRejected proves ForwardFact rejects a nil fact.
func TestAttendednessProducer_NilFactRejected(t *testing.T) {
	p, err := NewAttendednessProducerAt("/run/unused.sock", false)
	if err != nil {
		t.Fatalf("NewAttendednessProducerAt: %v", err)
	}
	if err := p.ForwardFact(context.Background(), nil); err == nil {
		t.Fatal("ForwardFact accepted a nil fact")
	}
}

// TestAttendednessFeedLiveEnabled_PresenceOnly proves the gate is presence-only (mirrors
// the consumer's attendedness_feed_live_enabled).
func TestAttendednessFeedLiveEnabled_PresenceOnly(t *testing.T) {
	// Ensure the gate is ABSENT for the disabled check (restore any prior value after).
	if orig, had := os.LookupEnv(attendednessFeedLiveEnv); had {
		if err := os.Unsetenv(attendednessFeedLiveEnv); err != nil {
			t.Fatalf("unset %s: %v", attendednessFeedLiveEnv, err)
		}
		t.Cleanup(func() { _ = os.Setenv(attendednessFeedLiveEnv, orig) })
	}
	if AttendednessFeedLiveEnabled() {
		t.Fatal("absent env ⇒ disabled (default)")
	}
	t.Setenv(attendednessFeedLiveEnv, "")
	if !AttendednessFeedLiveEnabled() {
		t.Fatal("present (even empty) ⇒ enabled (presence-only)")
	}
}

// TestAttendednessFeedEndpoint_Resolves proves the endpoint resolves the env override, else
// the default (mirrors the consumer's attendedness_feed_endpoint).
func TestAttendednessFeedEndpoint_Resolves(t *testing.T) {
	t.Setenv(attendednessFeedEndpointEnv, "")
	if got := AttendednessFeedEndpoint(); got != AttendednessFeedDefaultEndpoint {
		t.Errorf("empty override ⇒ %q, want default %q", got, AttendednessFeedDefaultEndpoint)
	}
	t.Setenv(attendednessFeedEndpointEnv, "/run/x/att.sock")
	if got := AttendednessFeedEndpoint(); got != "/run/x/att.sock" {
		t.Errorf("override ⇒ %q, want /run/x/att.sock", got)
	}
}

// readOneAttendednessFrameForTest mirrors the consumer's read_attendedness_frame (main.rs):
// read the 4-byte BE length, reject an over-cap length, then read the body.
func readOneAttendednessFrameForTest(conn net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if uint64(n) > attendednessFrameMaxBody {
		return nil, errors.New("attendedness-fact frame length over cap")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// TestAttendednessProducer_LiveDeliversFrame is the DS_ATTENDEDNESS_FEED_LIVE-gated e2e: it
// stands up a synthetic in-process UDS server that reads ONE framed fact the SAME way the
// ds-tlsproxy subscriber (serve_attendedness_feed → read_attendedness_frame →
// AttendednessFactWire::decode_fact) does, drives the producer's Forward behind the live
// gate over a synthetic SessionLifecycleUpdate, and proves the fact is encoded + delivered
// byte-for-byte (mirrors TestRevocationProducer_LiveDeliversFrame).
//
// DEFAULT-OFF / BYTE-IDENTICAL: the gate is UNSET in the normal `go test` run, so this body
// is SKIPPED — the live cross-process delivery is opt-in. There is no live
// claude/cia/qemu/podman; the "live" leg here is the in-process UDS server standing in for a
// running ds-tlsproxy. A real ds-tlsproxy subscriber bound at DS_TLSPROXY_ATTENDEDNESS_LISTEN
// is the DEFERRED MANUAL cross-process step an operator runs end to end.
func TestAttendednessProducer_LiveDeliversFrame(t *testing.T) {
	if !AttendednessFeedLiveEnabled() {
		t.Skipf("DS_ATTENDEDNESS_FEED_LIVE unset — skipping the live attendedness-fact delivery e2e (default-OFF byte-identical)")
	}

	dir := t.TempDir()
	sock := filepath.Join(dir, "attendedness.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("bind synthetic subscriber UDS: %v", err)
	}
	defer ln.Close()

	var (
		mu        sync.Mutex
		gotFact   *AttendednessFact
		gotOK     bool
		acceptErr error
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			mu.Lock()
			acceptErr = err
			mu.Unlock()
			return
		}
		defer conn.Close()
		body, err := readOneAttendednessFrameForTest(conn)
		if err != nil {
			mu.Lock()
			acceptErr = err
			mu.Unlock()
			return
		}
		f, ok := decodeAttendednessFactForTest(body)
		mu.Lock()
		gotFact, gotOK = f, ok
		mu.Unlock()
	}()

	ref := sampleAttSession()
	up := &hostagentv1.SessionLifecycleUpdate{SessionUuid: ref.SessionUUID, Attended: true, AttendedAt: 1_700_000_777}
	p, err := NewAttendednessProducerAt(sock, true)
	if err != nil {
		t.Fatalf("NewAttendednessProducerAt(live): %v", err)
	}
	if !p.Live() {
		t.Fatal("producer reports !Live() with live=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Forward(ctx, ref, up); err != nil {
		t.Fatalf("live Forward: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("synthetic subscriber did not receive the frame within 5s")
	}

	mu.Lock()
	defer mu.Unlock()
	if acceptErr != nil {
		t.Fatalf("synthetic subscriber error: %v", acceptErr)
	}
	if !gotOK {
		t.Fatal("synthetic subscriber decoded a MALFORMED frame (the delivered bytes drifted from the consumer layout)")
	}
	if gotFact.Session != ref {
		t.Errorf("delivered session = %+v, want %+v", gotFact.Session, ref)
	}
	if !gotFact.Attended || gotFact.AttendedAtUnixS != 1_700_000_777 {
		t.Errorf("delivered fact = %+v, want attended=true at 1700000777", gotFact)
	}
}
