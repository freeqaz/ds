// SPDX-License-Identifier: Apache-2.0

package hostagent

// revocation_producer_test.go is the SYNTHETIC in-process proof of the POL-4
// post-commit REVOCATION-DELTA producer (revocation_producer.go) against the
// CROSS-PROCESS wire contract the ds-tlsproxy consumer (dataplane/services/
// ds-tlsproxy/src/main.rs RevocationDeltaWire / serve_revocation_feed) decodes. There
// is no live claude/cia/qemu/podman and no Rust here — the test drives the Go encoder
// + producer and asserts the EXACT bytes-on-the-wire the consumer's RevocationDeltaWire
// parses, using a Go re-implementation of that decoder (decodeRevocationDeltaForTest)
// built INDEPENDENTLY from the encoder so a drift on either side fails the round-trip.
//
// The DS_REVOCATION_FEED_LIVE-gated e2e (TestRevocationProducer_LiveDeliversFrame)
// stands up a synthetic in-process UDS server that reads ONE length-prefixed frame the
// SAME way serve_revocation_feed's read_revocation_frame does, and proves a
// severing-rung delta is encoded + delivered byte-for-byte. With the gate UNSET the
// producer is a no-op (no dial) — the default-OFF byte-identical posture.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// ── a Go mirror of the consumer's RevocationDeltaWire::decode_delta (main.rs) ──
//
// Built independently from the producer's encoder so the round-trip catches a drift on
// EITHER side. It parses the exact body layout the Rust decoder does and returns None
// (nil) on any structural mismatch (a truncated field, an unknown rung byte, trailing
// bytes) — the fail-closed posture the subscriber takes.

func decodeRevocationDeltaForTest(body []byte) (*RevocationDelta, bool) {
	cur := body
	seq, ok := takeU64(&cur)
	if !ok {
		return nil, false
	}
	count, ok := takeU32(&cur)
	if !ok {
		return nil, false
	}
	revoked := make([]RevokedAdmission, 0, count)
	for i := uint32(0); i < count; i++ {
		sessionUUID, ok := takeStr(&cur)
		if !ok {
			return nil, false
		}
		hostID, ok := takeStr(&cur)
		if !ok {
			return nil, false
		}
		hostSessionIndex, ok := takeU32(&cur)
		if !ok {
			return nil, false
		}
		tapName, ok := takeStr(&cur)
		if !ok {
			return nil, false
		}
		rungByte, ok := takeU8(&cur)
		if !ok {
			return nil, false
		}
		rung, ok := rungFromWireByteForTest(rungByte)
		if !ok {
			return nil, false // unknown rung byte → malformed frame (fail-closed)
		}
		dstCount, ok := takeU32(&cur)
		if !ok {
			return nil, false
		}
		dstKeys := make([]string, 0, dstCount)
		for j := uint32(0); j < dstCount; j++ {
			dst, ok := takeStr(&cur)
			if !ok {
				return nil, false
			}
			dstKeys = append(dstKeys, dst)
		}
		revoked = append(revoked, RevokedAdmission{
			SessionUUID:      sessionUUID,
			HostID:           hostID,
			HostSessionIndex: hostSessionIndex,
			TapName:          tapName,
			Rung:             rung,
			DstKeys:          dstKeys,
		})
	}
	if len(cur) != 0 {
		return nil, false // trailing bytes → malformed frame
	}
	return &RevocationDelta{Seq: seq, Revoked: revoked}, true
}

// rungFromWireByteForTest is the inverse of rungWireByte — the consumer's
// RevocationDeltaWire::rung_from_byte (ds_tlsproxy::Rung::rung_from_wire_byte). It is
// pinned against the FROZEN D53 byte table in TestRevocationProducer_RungWireBytePinsD53Table
// so it cannot silently disagree with the encoder.
func rungFromWireByteForTest(b byte) (Rung, bool) {
	switch b {
	case 0:
		return RungAllowLog, true
	case 1:
		return RungBlockLog, true
	case 2:
		return RungSuspendAsk, true
	case 3:
		return RungKillSnapshot, true
	default:
		return 0, false
	}
}

func takeU8(cur *[]byte) (byte, bool) {
	if len(*cur) < 1 {
		return 0, false
	}
	b := (*cur)[0]
	*cur = (*cur)[1:]
	return b, true
}

func takeU32(cur *[]byte) (uint32, bool) {
	if len(*cur) < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32((*cur)[:4])
	*cur = (*cur)[4:]
	return v, true
}

func takeU64(cur *[]byte) (uint64, bool) {
	if len(*cur) < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64((*cur)[:8])
	*cur = (*cur)[8:]
	return v, true
}

func takeStr(cur *[]byte) (string, bool) {
	n, ok := takeU32(cur)
	if !ok {
		return "", false
	}
	if uint64(n) > revocationFrameMaxBody || uint32(len(*cur)) < n {
		return "", false
	}
	s := string((*cur)[:n])
	*cur = (*cur)[n:]
	return s, true
}

// sampleDelta is a representative two-admission delta covering a severing rung
// (kill+snapshot, with dst-keys) and a non-severing rung (allow+log, no dst-keys) so the
// round-trip and the live frame exercise both arms of the D53 ladder.
func sampleDelta() *RevocationDelta {
	return &RevocationDelta{
		Seq: 42,
		Revoked: []RevokedAdmission{
			{
				SessionUUID:      "11111111-2222-3333-4444-555555555555",
				HostID:           "host-a",
				HostSessionIndex: 7,
				TapName:          "dstap-7",
				Rung:             RungKillSnapshot,
				DstKeys:          []string{"api.example.com:443", "cdn.example.net:443"},
			},
			{
				SessionUUID:      "99999999-8888-7777-6666-555555555555",
				HostID:           "host-a",
				HostSessionIndex: 3,
				TapName:          "dstap-3",
				Rung:             RungAllowLog,
				DstKeys:          nil,
			},
		},
	}
}

// TestRevocationProducer_EncodeRoundTrips proves the encoder and an INDEPENDENT mirror of
// the consumer's decoder agree — the property that makes the cross-process wire faithful
// (a delivered delta decodes to the delta the host computed).
func TestRevocationProducer_EncodeRoundTrips(t *testing.T) {
	delta := sampleDelta()
	body, err := encodeRevocationDelta(delta)
	if err != nil {
		t.Fatalf("encodeRevocationDelta: %v", err)
	}
	got, ok := decodeRevocationDeltaForTest(body)
	if !ok {
		t.Fatalf("decodeRevocationDeltaForTest: malformed (the encoder drifted from the consumer layout)")
	}
	if got.Seq != delta.Seq {
		t.Errorf("seq = %d, want %d", got.Seq, delta.Seq)
	}
	if len(got.Revoked) != len(delta.Revoked) {
		t.Fatalf("revoked_count = %d, want %d", len(got.Revoked), len(delta.Revoked))
	}
	for i := range delta.Revoked {
		w, g := delta.Revoked[i], got.Revoked[i]
		if g.SessionUUID != w.SessionUUID || g.HostID != w.HostID ||
			g.HostSessionIndex != w.HostSessionIndex || g.TapName != w.TapName || g.Rung != w.Rung {
			t.Errorf("revoked[%d] = %+v, want %+v", i, g, w)
		}
		if len(g.DstKeys) != len(w.DstKeys) {
			t.Fatalf("revoked[%d] dst_count = %d, want %d", i, len(g.DstKeys), len(w.DstKeys))
		}
		for j := range w.DstKeys {
			if g.DstKeys[j] != w.DstKeys[j] {
				t.Errorf("revoked[%d] dst[%d] = %q, want %q", i, j, g.DstKeys[j], w.DstKeys[j])
			}
		}
	}
}

// TestRevocationProducer_EncodeExactBytes pins the EXACT wire bytes of a minimal delta so
// the byte-for-byte match to the consumer's RevocationDeltaWire layout is a hard
// assertion, not just a round-trip (a round-trip alone could pass with two halves that
// agreed on a WRONG layout). One revoked admission, one dst-key, block+log rung.
func TestRevocationProducer_EncodeExactBytes(t *testing.T) {
	delta := &RevocationDelta{
		Seq: 1,
		Revoked: []RevokedAdmission{{
			SessionUUID:      "s", // len 1
			HostID:           "h", // len 1
			HostSessionIndex: 0x01020304,
			TapName:          "dstap-1", // len 7
			Rung:             RungBlockLog,
			DstKeys:          []string{"d"}, // len 1
		}},
	}
	got, err := encodeRevocationDelta(delta)
	if err != nil {
		t.Fatalf("encodeRevocationDelta: %v", err)
	}
	want := []byte{
		0, 0, 0, 0, 0, 0, 0, 1, // seq = 1 (u64 BE)
		0, 0, 0, 1, // revoked_count = 1 (u32 BE)
		0, 0, 0, 1, 's', // session_uuid len=1 + "s"
		0, 0, 0, 1, 'h', // host_id len=1 + "h"
		0x01, 0x02, 0x03, 0x04, // host_session_index (u32 BE)
		0, 0, 0, 7, 'd', 's', 't', 'a', 'p', '-', '1', // tap_name len=7 + "dstap-1"
		1,          // rung = block+log
		0, 0, 0, 1, // dst_count = 1
		0, 0, 0, 1, 'd', // dst_key len=1 + "d"
	}
	if len(got) != len(want) {
		t.Fatalf("encoded body len = %d, want %d\n got=%v\nwant=%v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d = %d, want %d\n got=%v\nwant=%v", i, got[i], want[i], got, want)
		}
	}
}

// TestRevocationProducer_RungWireBytePinsD53Table pins the FROZEN D53 rung→wire-byte
// table the encoder emits — byte-for-byte the values the assurance/conformance-adapter/
// revocationwire fixture (RungToWireByte) and the Rust ds_tlsproxy::Rung::rung_to_wire_byte
// freeze, so a ladder change cannot silently UNDER-SEVER (a kill+snapshot arriving as a
// no-op allow+log). The orchestrator module cannot import the fixture cross-tree
// (CLAUDE.md), so this re-states the SAME explicit table the fixture pins; the conformance
// suite + the Rust pin test catch any drift.
func TestRevocationProducer_RungWireBytePinsD53Table(t *testing.T) {
	cases := []struct {
		rung Rung
		name string
		b    byte
	}{
		{RungAllowLog, "allow+log", 0},
		{RungBlockLog, "block+log", 1},
		{RungSuspendAsk, "suspend+ask", 2},
		{RungKillSnapshot, "kill+snapshot", 3},
	}
	for _, tc := range cases {
		b, ok := rungWireByte(tc.rung)
		if !ok {
			t.Fatalf("rungWireByte(%s): ok=false for a defined rung", tc.name)
		}
		if b != tc.b {
			t.Errorf("rungWireByte(%s) = %d, want frozen wire byte %d", tc.name, b, tc.b)
		}
		back, ok := rungFromWireByteForTest(b)
		if !ok || back != tc.rung {
			t.Errorf("round-trip %s: byte %d decoded to %v ok=%v, want %s", tc.name, b, back, ok, tc.name)
		}
	}
}

// TestRevocationProducer_Severs pins the D53 sever threshold (block-or-higher) the
// delivered rung ultimately gates at the proxy — mirrors the Rust is_block_or_higher /
// the fixture's Severs so the producer's view agrees with what the proxy enforces.
func TestRevocationProducer_Severs(t *testing.T) {
	if RungAllowLog.Severs() {
		t.Error("allow+log must not sever")
	}
	for _, r := range []Rung{RungBlockLog, RungSuspendAsk, RungKillSnapshot} {
		if !r.Severs() {
			t.Errorf("rung %v must sever (block-or-higher)", r)
		}
	}
}

// TestRevocationProducer_EncodeRejectsOutOfLadderRung proves an out-of-ladder rung is
// refused at encode (never emitted as a guessed byte) — the encoder fails LOUD rather
// than serving a rung the proxy would mis-enforce.
func TestRevocationProducer_EncodeRejectsOutOfLadderRung(t *testing.T) {
	delta := &RevocationDelta{
		Seq:     1,
		Revoked: []RevokedAdmission{{SessionUUID: "s", TapName: "dstap-1", Rung: Rung(99)}},
	}
	if _, err := encodeRevocationDelta(delta); err == nil {
		t.Fatal("encodeRevocationDelta accepted an out-of-ladder rung; want a fail-loud error")
	}
}

// TestRevocationProducer_DefaultOffIsNoDial proves the DEFAULT-OFF posture: with the live
// gate UNSET the producer's Sweep reads the revoked set but dials NOTHING — byte-identical
// to the pre-producer daemon. The source records that it was called (the seam is exercised
// identically on both paths), and the endpoint is an address nothing is listening on, so a
// dial would error — the clean (seq, nil) return proves no dial happened.
func TestRevocationProducer_DefaultOffIsNoDial(t *testing.T) {
	var called bool
	src := RevokedSetFunc(func(_ context.Context, snap *boundaryv1.PolicySnapshot) ([]RevokedAdmission, error) {
		called = true
		return sampleDelta().Revoked, nil
	})
	// live=false, an endpoint nothing serves: a no-op Sweep must NOT dial it.
	p, err := NewRevocationProducerAt(src, filepath.Join(t.TempDir(), "nonexistent.sock"), false)
	if err != nil {
		t.Fatalf("NewRevocationProducerAt: %v", err)
	}
	if p.Live() {
		t.Fatal("producer reports Live() with live=false")
	}
	got, err := p.Sweep(context.Background(), snapAt(5, "doc-v5"))
	if err != nil {
		t.Fatalf("default-off Sweep returned an error (it must not dial): %v", err)
	}
	if got != 5 {
		t.Errorf("default-off swept seq = %d, want 5", got)
	}
	if !called {
		t.Error("source was not consulted on the default-off path (the seam must be exercised identically)")
	}
}

// TestRevocationProducer_SourceErrorHoldsSeq proves a revoked-set computation failure
// HOLDS apply_seq (Sweep returns seq 0 + error) — fail-closed: a committed version whose
// revoked-set is unknown must not advance the resume cursor (a tunnel that should sever
// might be missed).
func TestRevocationProducer_SourceErrorHoldsSeq(t *testing.T) {
	src := RevokedSetFunc(func(_ context.Context, _ *boundaryv1.PolicySnapshot) ([]RevokedAdmission, error) {
		return nil, errors.New("diff engine fault")
	})
	p, err := NewRevocationProducerAt(src, "/run/unused.sock", false)
	if err != nil {
		t.Fatalf("NewRevocationProducerAt: %v", err)
	}
	seq, err := p.Sweep(context.Background(), snapAt(9, "doc-v9"))
	if err == nil {
		t.Fatal("Sweep accepted a source error; want it held apply_seq fail-closed")
	}
	if seq != 0 {
		t.Errorf("held swept seq = %d, want 0 (apply_seq held on a source fault)", seq)
	}
}

// TestRevocationProducer_NilSourceRejected proves the constructor rejects a nil source
// (a producer with no diff engine could never know what to revoke).
func TestRevocationProducer_NilSourceRejected(t *testing.T) {
	if _, err := NewRevocationProducerAt(nil, "/run/x.sock", false); err == nil {
		t.Fatal("NewRevocationProducerAt accepted a nil source")
	}
}

// readOneRevocationFrameForTest mirrors the consumer's read_revocation_frame (main.rs):
// read the 4-byte BE length, reject an over-cap length, then read the body. It is the
// synthetic in-process stand-in for serve_revocation_feed's frame read.
func readOneRevocationFrameForTest(conn net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if uint64(n) > revocationFrameMaxBody {
		return nil, errors.New("revocation-delta frame length over cap")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// TestRevocationProducer_LiveDeliversFrame is the DS_REVOCATION_FEED_LIVE-gated e2e: it
// stands up a synthetic in-process UDS server that reads ONE framed delta the SAME way
// the ds-tlsproxy subscriber (serve_revocation_feed → read_revocation_frame →
// RevocationDeltaWire::decode_delta) does, drives the producer's Sweep behind the live
// gate, and proves the SEVERING-RUNG delta is encoded + delivered byte-for-byte.
//
// DEFAULT-OFF / BYTE-IDENTICAL: the gate is UNSET in the normal `go test` run, so this
// body is SKIPPED — the live cross-process delivery is opt-in. There is no live
// claude/cia/qemu/podman; the "live" leg here is the in-process UDS server standing in
// for a running ds-tlsproxy, the way the dataplane-free producer tests are built. A
// real ds-tlsproxy subscriber bound at DS_TLSPROXY_REVOCATION_LISTEN is the DEFERRED
// MANUAL cross-process step an operator runs end to end.
func TestRevocationProducer_LiveDeliversFrame(t *testing.T) {
	if !RevocationFeedLiveEnabled() {
		t.Skipf("DS_REVOCATION_FEED_LIVE unset — skipping the live revocation-delta delivery e2e (default-OFF byte-identical)")
	}

	// A synthetic in-process subscriber: bind a temp UDS, accept one connection, read one
	// framed delta, decode it, and hand it back. This is the producer-test stand-in for
	// serve_revocation_feed (no Rust, no running proxy).
	dir := t.TempDir()
	sock := filepath.Join(dir, "revocation.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("bind synthetic subscriber UDS: %v", err)
	}
	defer ln.Close()

	var (
		mu        sync.Mutex
		gotDelta  *RevocationDelta
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
		body, err := readOneRevocationFrameForTest(conn)
		if err != nil {
			mu.Lock()
			acceptErr = err
			mu.Unlock()
			return
		}
		d, ok := decodeRevocationDeltaForTest(body)
		mu.Lock()
		gotDelta, gotOK = d, ok
		mu.Unlock()
	}()

	delta := sampleDelta()
	src := RevokedSetFunc(func(_ context.Context, _ *boundaryv1.PolicySnapshot) ([]RevokedAdmission, error) {
		return delta.Revoked, nil
	})
	// live=true at the explicit temp endpoint — the real cross-process dial, against the
	// synthetic subscriber above.
	p, err := NewRevocationProducerAt(src, sock, true)
	if err != nil {
		t.Fatalf("NewRevocationProducerAt(live): %v", err)
	}
	if !p.Live() {
		t.Fatal("producer reports !Live() with live=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	seq, err := p.Sweep(ctx, snapAt(delta.Seq, "doc-v42"))
	if err != nil {
		t.Fatalf("live Sweep: %v", err)
	}
	if seq != delta.Seq {
		t.Errorf("live swept seq = %d, want %d", seq, delta.Seq)
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
	if gotDelta.Seq != delta.Seq || len(gotDelta.Revoked) != len(delta.Revoked) {
		t.Fatalf("delivered delta = seq %d / %d revoked, want seq %d / %d revoked",
			gotDelta.Seq, len(gotDelta.Revoked), delta.Seq, len(delta.Revoked))
	}
	// Prove the SEVERING rung survived the round trip (a kill+snapshot delivered as a
	// no-op allow+log would be the silent under-sever this whole contract guards).
	if got := gotDelta.Revoked[0].Rung; got != RungKillSnapshot || !got.Severs() {
		t.Errorf("delivered revoked[0].Rung = %v (severs=%v), want kill+snapshot (severs)", got, got.Severs())
	}
	if got := gotDelta.Revoked[1].Rung; got != RungAllowLog || got.Severs() {
		t.Errorf("delivered revoked[1].Rung = %v (severs=%v), want allow+log (non-severing)", got, got.Severs())
	}
}
