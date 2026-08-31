// SPDX-License-Identifier: Apache-2.0

package hostagent

// grantreturn_producer_test.go is the SYNTHETIC in-process proof of the D77 grant-return
// PRODUCER (grantreturn_producer.go) against the CROSS-PROCESS wire contract the
// ds-tlsproxy consumer (dataplane/services/ds-tlsproxy/src/main.rs GrantReturnWire /
// serve_grant_feed) decodes. There is no live claude/cia/qemu/podman and no Rust here —
// the test drives the Go encoder + producer and asserts the EXACT bytes-on-the-wire the
// consumer parses, using a Go re-implementation of that decoder
// (decodeAllowGrantForTest) built INDEPENDENTLY from the encoder so a drift on either
// side fails the round-trip.
//
// The DS_GRANT_RETURN_FEED_LIVE-gated e2e (TestGrantReturnProducer_LiveDeliversFrame)
// stands up a synthetic in-process UDS server that reads ONE length-prefixed frame the
// SAME way serve_grant_feed's read_grant_frame does, and proves a grant is encoded +
// delivered byte-for-byte. With the gate UNSET the producer is a no-op (no dial) — the
// default-OFF byte-identical posture.
//
// The takeStr/takeU32/takeU64/hexOf helpers are already defined in the same package
// (revocation_producer_test.go / attendedness_producer_test.go); this file reuses them.

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

	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// ── a Go mirror of the consumer's GrantReturnWire::decode_grant (main.rs) ──
//
// Built independently from the producer's encoder so the round-trip catches a drift on
// EITHER side. It parses the exact body layout the Rust decoder does and returns ok=false
// on any structural mismatch (a truncated field, trailing bytes) — the fail-closed posture
// the subscriber takes.
func decodeAllowGrantForTest(body []byte) (*AllowGrant, bool) {
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
	sniDomain, ok := takeStr(&cur)
	if !ok {
		return nil, false
	}
	expiresAt, ok := takeU64(&cur)
	if !ok {
		return nil, false
	}
	// Trailing bytes after the declared grant are a malformed frame.
	if len(cur) != 0 {
		return nil, false
	}
	return &AllowGrant{
		Session: GrantReturnSessionRef{
			SessionUUID:      sessionUUID,
			HostID:           hostID,
			HostSessionIndex: idx,
			TapName:          tapName,
		},
		SniDomain:      sniDomain,
		ExpiresAtUnixS: expiresAt,
	}, true
}

func sampleGrantSession() GrantReturnSessionRef {
	return GrantReturnSessionRef{
		SessionUUID:      "01HZX9K6Q2VN7T4M8B0CWRD5EF",
		HostID:           "host-grant",
		HostSessionIndex: 0x0102_0304,
		TapName:          "dstap-9",
	}
}

// TestGrantReturnProducer_EncodeRoundTrips proves the encoder ⇄ independent decoder agree
// for a future-expiry and a zero-expiry grant.
func TestGrantReturnProducer_EncodeRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name    string
		domain  string
		expires uint64
	}{
		{"future expiry", "api.anthropic.com", 1_700_000_042},
		{"zero expiry", "example.com", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := &AllowGrant{Session: sampleGrantSession(), SniDomain: tc.domain, ExpiresAtUnixS: tc.expires}
			body, err := encodeAllowGrant(grant)
			if err != nil {
				t.Fatalf("encodeAllowGrant: %v", err)
			}
			got, ok := decodeAllowGrantForTest(body)
			if !ok {
				t.Fatal("independent decoder rejected a well-formed grant")
			}
			if got.Session != grant.Session || got.SniDomain != grant.SniDomain || got.ExpiresAtUnixS != grant.ExpiresAtUnixS {
				t.Fatalf("round-trip mismatch: got %+v, want %+v", got, grant)
			}
		})
	}
}

// TestGrantReturnProducer_EncodeExactBytes pins the EXACT bytes-on-the-wire — the
// byte-for-byte match of the ds-tlsproxy consumer's GrantReturnWire::decode_grant input
// AND the assurance/conformance-adapter/grantwire golden. This is the cross-process /
// cross-language pin: the hex here is hand-copied byte-identical with the Rust
// GRANTWIRE_GOLDEN_GRANT_HEX and the grantwire fixture's GoldenGrantHex, each re-derived by
// its own independent encoder, so a wire drift on any tree fails a suite.
func TestGrantReturnProducer_EncodeExactBytes(t *testing.T) {
	// Canonical inputs — MUST be byte-identical with the grantwire fixture + the Rust golden.
	grant := &AllowGrant{
		Session: GrantReturnSessionRef{
			SessionUUID:      "01HZX9K6Q2VN7T4M8B0CWRD5EF",
			HostID:           "host-grant-conformance",
			HostSessionIndex: 0x0102_0304,
			TapName:          "dstap-9",
		},
		SniDomain:      "api.anthropic.com",
		ExpiresAtUnixS: 0x0000_0000_6600_0000,
	}
	const goldenHex = "0000001a3031485a58394b365132564e3754344d3842304357524435454600000016686f73742d6772616e742d636f6e666f726d616e6365010203040000000764737461702d39000000116170692e616e7468726f7069632e636f6d0000000066000000"

	body, err := encodeAllowGrant(grant)
	if err != nil {
		t.Fatalf("encodeAllowGrant: %v", err)
	}
	gotHex := hexOf(body)
	if gotHex != goldenHex {
		t.Fatalf("wire bytes drifted from the cross-language golden:\n got  %s\n want %s", gotHex, goldenHex)
	}
}

// TestGrantReturnProducer_GrantFromApproval proves the projection off a frozen POL-5
// ask-grant computes the ABSOLUTE expiry (appended_at + ttl_seconds) and rejects every
// ill-formed grant WITHOUT fabricating one.
func TestGrantReturnProducer_GrantFromApproval(t *testing.T) {
	ref := sampleGrantSession()
	askGrantRow := func(appendedAt uint64) *orchestratorv1.PolicyLogRow {
		return &orchestratorv1.PolicyLogRow{Kind: orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ASK_GRANT, AppendedAt: appendedAt}
	}

	t.Run("computes absolute expiry from appended_at + ttl", func(t *testing.T) {
		req := &orchestratorv1.ApproveAskRequest{SessionUuid: ref.SessionUUID, GrantScope: "api.anthropic.com", TtlSeconds: 300}
		grant, err := GrantFromApproval(ref, "api.anthropic.com", askGrantRow(1_700_000_000), req)
		if err != nil {
			t.Fatalf("GrantFromApproval: %v", err)
		}
		if grant.ExpiresAtUnixS != 1_700_000_300 {
			t.Fatalf("expires_at = %d, want 1700000300 (appended_at + ttl)", grant.ExpiresAtUnixS)
		}
		if grant.SniDomain != "api.anthropic.com" || grant.Session != ref {
			t.Errorf("grant = %+v, want domain api.anthropic.com + session %+v", grant, ref)
		}
	})

	t.Run("zero ttl yields an already-expired grant (forwarded honestly)", func(t *testing.T) {
		req := &orchestratorv1.ApproveAskRequest{SessionUuid: ref.SessionUUID, TtlSeconds: 0}
		grant, err := GrantFromApproval(ref, "api.anthropic.com", askGrantRow(42), req)
		if err != nil {
			t.Fatalf("GrantFromApproval: %v", err)
		}
		if grant.ExpiresAtUnixS != 42 {
			t.Fatalf("zero-ttl expires_at = %d, want appended_at 42", grant.ExpiresAtUnixS)
		}
	})

	t.Run("saturates on ttl overflow (never wraps)", func(t *testing.T) {
		req := &orchestratorv1.ApproveAskRequest{SessionUuid: ref.SessionUUID, TtlSeconds: ^uint64(0)}
		grant, err := GrantFromApproval(ref, "api.anthropic.com", askGrantRow(100), req)
		if err != nil {
			t.Fatalf("GrantFromApproval: %v", err)
		}
		if grant.ExpiresAtUnixS != ^uint64(0) {
			t.Fatalf("overflowing ttl must saturate to max, got %d", grant.ExpiresAtUnixS)
		}
	})

	t.Run("nil row rejected", func(t *testing.T) {
		req := &orchestratorv1.ApproveAskRequest{SessionUuid: ref.SessionUUID, TtlSeconds: 1}
		if _, err := GrantFromApproval(ref, "d", nil, req); err == nil {
			t.Fatal("GrantFromApproval accepted a nil row")
		}
	})

	t.Run("nil req rejected", func(t *testing.T) {
		if _, err := GrantFromApproval(ref, "d", askGrantRow(1), nil); err == nil {
			t.Fatal("GrantFromApproval accepted a nil req")
		}
	})

	t.Run("non-ask-grant row kind rejected", func(t *testing.T) {
		row := &orchestratorv1.PolicyLogRow{Kind: orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ORG_EDIT, AppendedAt: 1}
		req := &orchestratorv1.ApproveAskRequest{SessionUuid: ref.SessionUUID, TtlSeconds: 1}
		if _, err := GrantFromApproval(ref, "d", row, req); err == nil {
			t.Fatal("GrantFromApproval accepted a non-ask-grant row (only an ask-grant is an approval)")
		}
	})

	t.Run("empty domain rejected", func(t *testing.T) {
		req := &orchestratorv1.ApproveAskRequest{SessionUuid: ref.SessionUUID, TtlSeconds: 1}
		if _, err := GrantFromApproval(ref, "", askGrantRow(1), req); err == nil {
			t.Fatal("GrantFromApproval accepted an empty domain (could never match a hold)")
		}
	})

	t.Run("cross-session grant rejected", func(t *testing.T) {
		req := &orchestratorv1.ApproveAskRequest{SessionUuid: "a-different-session", TtlSeconds: 1}
		if _, err := GrantFromApproval(ref, "d", askGrantRow(1), req); err == nil {
			t.Fatal("GrantFromApproval accepted a grant for a different session (never a cross-session grant)")
		}
	})

	t.Run("empty req session_uuid rides the caller's ref", func(t *testing.T) {
		// An ApproveAskRequest whose session_uuid is unset is joined to the caller's
		// resolved quartet (the caller is the session authority) — not a mismatch.
		req := &orchestratorv1.ApproveAskRequest{TtlSeconds: 5}
		grant, err := GrantFromApproval(ref, "d", askGrantRow(10), req)
		if err != nil {
			t.Fatalf("GrantFromApproval rejected an empty-uuid req: %v", err)
		}
		if grant.Session != ref {
			t.Errorf("session = %+v, want the caller's ref %+v", grant.Session, ref)
		}
	})
}

// TestGrantReturnProducer_DefaultOffIsNoDial proves the DEFAULT-OFF posture: with the live
// gate UNSET the producer's Forward builds the grant but dials NOTHING — byte-identical to
// the pre-producer daemon. The endpoint is an address nothing is listening on, so a dial
// would error; the clean nil return proves no dial happened.
func TestGrantReturnProducer_DefaultOffIsNoDial(t *testing.T) {
	p, err := NewGrantReturnProducerAt(filepath.Join(t.TempDir(), "nonexistent.sock"), false)
	if err != nil {
		t.Fatalf("NewGrantReturnProducerAt: %v", err)
	}
	if p.Live() {
		t.Fatal("producer reports Live() with live=false")
	}
	ref := sampleGrantSession()
	row := &orchestratorv1.PolicyLogRow{Kind: orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ASK_GRANT, AppendedAt: 100}
	req := &orchestratorv1.ApproveAskRequest{SessionUuid: ref.SessionUUID, TtlSeconds: 60}
	if err := p.Forward(context.Background(), ref, "api.anthropic.com", row, req); err != nil {
		t.Fatalf("default-off Forward returned an error (it must not dial): %v", err)
	}
}

// TestGrantReturnProducer_LiveEmptyEndpointRejected proves a live producer with no endpoint
// is rejected (it could never deliver).
func TestGrantReturnProducer_LiveEmptyEndpointRejected(t *testing.T) {
	if _, err := NewGrantReturnProducerAt("", true); err == nil {
		t.Fatal("NewGrantReturnProducerAt accepted a live producer with an empty endpoint")
	}
}

// TestGrantReturnProducer_NilGrantRejected proves ForwardGrant rejects a nil grant.
func TestGrantReturnProducer_NilGrantRejected(t *testing.T) {
	p, err := NewGrantReturnProducerAt("/run/unused.sock", false)
	if err != nil {
		t.Fatalf("NewGrantReturnProducerAt: %v", err)
	}
	if err := p.ForwardGrant(context.Background(), nil); err == nil {
		t.Fatal("ForwardGrant accepted a nil grant")
	}
}

// TestGrantFeedLiveEnabled_PresenceOnly proves the gate is presence-only (mirrors the
// consumer's grant_feed_live_enabled).
func TestGrantFeedLiveEnabled_PresenceOnly(t *testing.T) {
	// Ensure the gate is ABSENT for the disabled check (restore any prior value after).
	if orig, had := os.LookupEnv(grantFeedLiveEnv); had {
		if err := os.Unsetenv(grantFeedLiveEnv); err != nil {
			t.Fatalf("unset %s: %v", grantFeedLiveEnv, err)
		}
		t.Cleanup(func() { _ = os.Setenv(grantFeedLiveEnv, orig) })
	}
	if GrantFeedLiveEnabled() {
		t.Fatal("absent env ⇒ disabled (default)")
	}
	t.Setenv(grantFeedLiveEnv, "")
	if !GrantFeedLiveEnabled() {
		t.Fatal("present (even empty) ⇒ enabled (presence-only)")
	}
}

// TestGrantFeedEndpoint_Resolves proves the endpoint resolves the env override, else the
// default (mirrors the consumer's grant_feed_endpoint).
func TestGrantFeedEndpoint_Resolves(t *testing.T) {
	t.Setenv(grantFeedEndpointEnv, "")
	if got := GrantFeedEndpoint(); got != GrantFeedDefaultEndpoint {
		t.Errorf("empty override ⇒ %q, want default %q", got, GrantFeedDefaultEndpoint)
	}
	t.Setenv(grantFeedEndpointEnv, "/run/x/grants.sock")
	if got := GrantFeedEndpoint(); got != "/run/x/grants.sock" {
		t.Errorf("override ⇒ %q, want /run/x/grants.sock", got)
	}
}

// readOneGrantFrameForTest mirrors the consumer's read_grant_frame (main.rs): read the
// 4-byte BE length, reject an over-cap length, then read the body.
func readOneGrantFrameForTest(conn net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if uint64(n) > grantFrameMaxBody {
		return nil, errors.New("grant-return frame length over cap")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// TestGrantReturnProducer_LiveDeliversFrame is the DS_GRANT_RETURN_FEED_LIVE-gated e2e: it
// stands up a synthetic in-process UDS server that reads ONE framed grant the SAME way the
// ds-tlsproxy subscriber (serve_grant_feed → read_grant_frame → GrantReturnWire::decode_grant)
// does, drives the producer's Forward behind the live gate over a synthetic approved
// ask-grant, and proves the grant is encoded + delivered byte-for-byte (mirrors
// TestAttendednessProducer_LiveDeliversFrame).
//
// DEFAULT-OFF / BYTE-IDENTICAL: the gate is UNSET in the normal `go test` run, so this body
// is SKIPPED — the live cross-process delivery is opt-in. There is no live
// claude/cia/qemu/podman; the "live" leg here is the in-process UDS server standing in for a
// running ds-tlsproxy. A real ds-tlsproxy subscriber bound at DS_TLSPROXY_GRANT_LISTEN is the
// DEFERRED MANUAL cross-process step an operator runs end to end.
func TestGrantReturnProducer_LiveDeliversFrame(t *testing.T) {
	if !GrantFeedLiveEnabled() {
		t.Skipf("DS_GRANT_RETURN_FEED_LIVE unset — skipping the live grant-return delivery e2e (default-OFF byte-identical)")
	}

	dir := t.TempDir()
	sock := filepath.Join(dir, "grants.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("bind synthetic subscriber UDS: %v", err)
	}
	defer ln.Close()

	var (
		mu        sync.Mutex
		gotGrant  *AllowGrant
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
		body, err := readOneGrantFrameForTest(conn)
		if err != nil {
			mu.Lock()
			acceptErr = err
			mu.Unlock()
			return
		}
		g, ok := decodeAllowGrantForTest(body)
		mu.Lock()
		gotGrant, gotOK = g, ok
		mu.Unlock()
	}()

	ref := sampleGrantSession()
	row := &orchestratorv1.PolicyLogRow{Kind: orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ASK_GRANT, AppendedAt: 1_700_000_000}
	req := &orchestratorv1.ApproveAskRequest{SessionUuid: ref.SessionUUID, GrantScope: "api.anthropic.com", TtlSeconds: 777}
	p, err := NewGrantReturnProducerAt(sock, true)
	if err != nil {
		t.Fatalf("NewGrantReturnProducerAt(live): %v", err)
	}
	if !p.Live() {
		t.Fatal("producer reports !Live() with live=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Forward(ctx, ref, "api.anthropic.com", row, req); err != nil {
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
	if gotGrant.Session != ref {
		t.Errorf("delivered session = %+v, want %+v", gotGrant.Session, ref)
	}
	if gotGrant.SniDomain != "api.anthropic.com" || gotGrant.ExpiresAtUnixS != 1_700_000_777 {
		t.Errorf("delivered grant = %+v, want domain api.anthropic.com expires 1700000777", gotGrant)
	}
}
