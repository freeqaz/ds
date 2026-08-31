// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/attenuation"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/token"
	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
)

// fakeSeveringRegistry is a synthetic SeveringRegistry (D50): it records every
// jti handed to Sever so a test can assert the lineage chain reaches the seam.
type fakeSeveringRegistry struct {
	mu      sync.Mutex
	severed []string
	// failOn, if non-empty, makes Sever return an error for that jti.
	failOn string
}

func (f *fakeSeveringRegistry) Sever(_ context.Context, jti string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn != "" && jti == f.failOn {
		return errors.New("synthetic sever failure")
	}
	f.severed = append(f.severed, jti)
	return nil
}

func (f *fakeSeveringRegistry) counts() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := make(map[string]int, len(f.severed))
	for _, j := range f.severed {
		m[j]++
	}
	return m
}

// newSessionServerForRevoke builds a minimal SessionServer wired with a lineage
// store, a fake severing registry, and a recording sink — no IdP needed.
func newSessionServerForRevoke(t *testing.T, lin *attenuation.LineageStore, reg SeveringRegistry, sink EventSink) *SessionServer {
	t.Helper()
	kp, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return NewSessionServer(
		NewRegistry(), kp, token.NewRevocationSet(),
		WithLineageStore(lin),
		WithSeveringRegistry(reg),
		WithEventSink(sink),
	)
}

// TestRevokeToken_SeversWholeLineageOnce is the acceptance test: a one-parent-
// N-children chain must reach the SeveringRegistry seam exactly once per jti,
// RevokeToken must return the real CascadeRevokedCount, and the D128
// auth.token.revoked event must be emitted.
func TestRevokeToken_SeversWholeLineageOnce(t *testing.T) {
	ctx := context.Background()
	const parentJTI = "parent-jti-0001"
	const nChildren = 5

	lin := attenuation.NewLineageStore()
	want := map[string]int{parentJTI: 1}
	for i := 0; i < nChildren; i++ {
		child := "d-child-" + string(rune('a'+i))
		lin.Record(attenuation.DerivedRecord{
			DerivedJTI:       child,
			ParentJTI:        parentJTI,
			HostSessionIndex: int32(i),
			Scopes:           []string{token.ScopeCodeRead},
			IssuedAt:         1,
			ExpiresAt:        1 << 40,
		})
		want[child] = 1
	}

	fake := &fakeSeveringRegistry{}
	sink := &RecordingEventSink{}
	srv := newSessionServerForRevoke(t, lin, fake, sink)

	resp, err := srv.RevokeToken(ctx, &authv1.RevokeTokenRequest{
		Jti:    parentJTI,
		Reason: "session-ended",
	})
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// CascadeRevokedCount must be the real number of derived children, not 0.
	if got := resp.GetCascadeRevokedCount(); got != nChildren {
		t.Errorf("CascadeRevokedCount = %d, want %d", got, nChildren)
	}

	// Every jti in the lineage (parent + N children) reaches Sever exactly once.
	got := fake.counts()
	if len(got) != len(want) {
		t.Errorf("severed %d distinct jtis, want %d (got=%v)", len(got), len(want), keys(got))
	}
	for jti, wc := range want {
		if got[jti] != wc {
			t.Errorf("jti %q severed %d times, want %d", jti, got[jti], wc)
		}
	}

	// The D128 auth.token.revoked event must be emitted, carrying the parent jti
	// and the cascade count.
	revEvents := sink.EventsOfKind(EventTokenRevoked)
	if len(revEvents) != 1 {
		t.Fatalf("auth.token.revoked events = %d, want 1", len(revEvents))
	}
	ev := revEvents[0]
	if ev.JTI != parentJTI {
		t.Errorf("event JTI = %q, want %q", ev.JTI, parentJTI)
	}
	if ev.Fields["cascade"] != "5" {
		t.Errorf("event cascade field = %q, want %q", ev.Fields["cascade"], "5")
	}
	if ev.Fields["reason"] != "session-ended" {
		t.Errorf("event reason field = %q, want %q", ev.Fields["reason"], "session-ended")
	}

	// After revoke, the lineage store reports the children as revoked.
	if live := lin.ListDerivedTokens(parentJTI); len(live) != 0 {
		t.Errorf("post-revoke live derived tokens = %d, want 0", len(live))
	}
}

// TestRevokeToken_NoLineageWired keeps the additive contract: with no lineage
// store or severing registry wired, RevokeToken still revokes the parent and
// returns a zero cascade count without severing anything.
func TestRevokeToken_NoLineageWired(t *testing.T) {
	ctx := context.Background()
	kp, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	sink := &RecordingEventSink{}
	srv := NewSessionServer(NewRegistry(), kp, token.NewRevocationSet(), WithEventSink(sink))

	resp, err := srv.RevokeToken(ctx, &authv1.RevokeTokenRequest{Jti: "lonely-jti"})
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if got := resp.GetCascadeRevokedCount(); got != 0 {
		t.Errorf("CascadeRevokedCount = %d, want 0", got)
	}
	if n := len(sink.EventsOfKind(EventTokenRevoked)); n != 1 {
		t.Errorf("auth.token.revoked events = %d, want 1", n)
	}
}

// TestRevokeToken_EmptyJTIRejected preserves the input-validation contract.
func TestRevokeToken_EmptyJTIRejected(t *testing.T) {
	srv := newSessionServerForRevoke(t, attenuation.NewLineageStore(), &fakeSeveringRegistry{}, &RecordingEventSink{})
	if _, err := srv.RevokeToken(context.Background(), &authv1.RevokeTokenRequest{}); err == nil {
		t.Fatal("RevokeToken with empty jti should fail")
	}
}

// TestRevocationSweep_ApplyDedup asserts the seam severs each distinct jti once,
// skips empties, and short-circuits when no registry is wired.
func TestRevocationSweep_ApplyDedup(t *testing.T) {
	fake := &fakeSeveringRegistry{}
	sweep := NewRevocationSweep(fake)
	n, err := sweep.apply(context.Background(), []string{"a", "b", "a", "", "c", "b"})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if n != 3 {
		t.Errorf("severed count = %d, want 3", n)
	}
	got := fake.counts()
	for _, jti := range []string{"a", "b", "c"} {
		if got[jti] != 1 {
			t.Errorf("jti %q severed %d times, want 1", jti, got[jti])
		}
	}

	// Nil registry is a no-op sweep.
	noop := NewRevocationSweep(nil)
	if n, err := noop.apply(context.Background(), []string{"x", "y"}); n != 0 || err != nil {
		t.Errorf("nil-registry apply = (%d, %v), want (0, nil)", n, err)
	}
}

// TestRevocationSweep_ApplyPropagatesError confirms a Sever failure aborts the
// sweep and surfaces the error.
func TestRevocationSweep_ApplyPropagatesError(t *testing.T) {
	fake := &fakeSeveringRegistry{failOn: "boom"}
	sweep := NewRevocationSweep(fake)
	if _, err := sweep.apply(context.Background(), []string{"ok", "boom", "never"}); err == nil {
		t.Fatal("apply should propagate the Sever error")
	}
}

func keys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestRevokeToken_EmitsEventWhenSeverFails pins the secfu audit-completeness
// posture: when the SeveringRegistry returns an error, RevokeToken must STILL
// emit the D128 auth.token.revoked event (a complete audit trail — the prior
// ordering returned before emitting, leaving a revoked-but-unobserved state)
// and only THEN surface the failure. The event carries sever="error".
func TestRevokeToken_EmitsEventWhenSeverFails(t *testing.T) {
	ctx := context.Background()
	const parentJTI = "parent-fail-0001"

	lin := attenuation.NewLineageStore()
	lin.Record(attenuation.DerivedRecord{
		DerivedJTI: "child-fail-a", ParentJTI: parentJTI,
		HostSessionIndex: 0, Scopes: []string{token.ScopeCodeRead},
		IssuedAt: 1, ExpiresAt: 1 << 40,
	})

	// The registry fails on the parent jti, so the sweep aborts with an error.
	fake := &fakeSeveringRegistry{failOn: parentJTI}
	sink := &RecordingEventSink{}
	srv := newSessionServerForRevoke(t, lin, fake, sink)

	_, err := srv.RevokeToken(ctx, &authv1.RevokeTokenRequest{
		Jti:    parentJTI,
		Reason: "session-ended",
	})
	if err == nil {
		t.Fatal("RevokeToken should surface the Sever failure")
	}

	// The audit event MUST still have been emitted, exactly once, for the parent.
	revEvents := sink.EventsOfKind(EventTokenRevoked)
	if len(revEvents) != 1 {
		t.Fatalf("auth.token.revoked events = %d, want 1 (audit trail must be complete on sever failure)", len(revEvents))
	}
	ev := revEvents[0]
	if ev.JTI != parentJTI {
		t.Errorf("event JTI = %q, want %q", ev.JTI, parentJTI)
	}
	if ev.Fields["reason"] != "session-ended" {
		t.Errorf("event reason field = %q, want %q", ev.Fields["reason"], "session-ended")
	}
	if ev.Fields["sever"] != "error" {
		t.Errorf("event sever field = %q, want %q", ev.Fields["sever"], "error")
	}
	// And the token is still revoked in the admission set despite the sever fault.
	if !srv.revocationSet.IsRevoked(parentJTI) {
		t.Errorf("parent jti not in revocation set after failed sever; revocation must stand")
	}
}

// severWireServer is a synthetic IN-PROCESS ds-tlsproxy sever endpoint (D50): it
// decodes each length-prefixed sever-request frame off the wire, records the
// (op, legs, jti) it received, and answers a well-formed OK response frame. It
// exists only to prove the concrete SeveringClient's codec/wire path offline —
// no real ds-tlsproxy, no real socket, no DS_SEVER_LIVE.
type severWireServer struct {
	mu       sync.Mutex
	requests []severWireRequest
}

type severWireRequest struct {
	op   byte
	legs byte
	jti  string
}

// dialFunc returns a SeverDialFunc that, per call, hands the client one end of
// an in-process pipe and serves the other end with this server. Each Sever thus
// gets a fresh connection — mirroring the connect-per-jti production wire.
func (s *severWireServer) dialFunc() SeverDialFunc {
	return func(_ context.Context) (net.Conn, error) {
		clientEnd, serverEnd := net.Pipe()
		go s.serveConn(serverEnd)
		return clientEnd, nil
	}
}

func (s *severWireServer) serveConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	var lp [4]byte
	if _, err := io.ReadFull(conn, lp[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(lp[:])
	if n < 6 || n > severFrameMaxBody {
		return
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}
	op, legs := body[0], body[1]
	jtiLen := binary.BigEndian.Uint32(body[2:6])
	if int(6+jtiLen) > len(body) {
		return
	}
	jti := string(body[6 : 6+jtiLen])

	s.mu.Lock()
	s.requests = append(s.requests, severWireRequest{op: op, legs: legs, jti: jti})
	s.mu.Unlock()

	// Answer a well-formed OK response frame: body = status(1) + severed(4).
	resp := make([]byte, 4+severRespBodyLen)
	binary.BigEndian.PutUint32(resp[:4], uint32(severRespBodyLen))
	resp[4] = severStatusOK
	binary.BigEndian.PutUint32(resp[5:9], 1) // one connection severed
	_, _ = conn.Write(resp)
}

func (s *severWireServer) jtiCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := make(map[string]int, len(s.requests))
	for _, r := range s.requests {
		m[r.jti]++
	}
	return m
}

// TestSeveringClient_EachJTIReachesWireOnce drives the CONCRETE SeveringClient
// through a RevocationSweep against the synthetic in-process server and asserts
// every distinct jti reaches the wire exactly once (dedup + full-fidelity codec),
// with the default sever_pair op and both legs on the wire.
func TestSeveringClient_EachJTIReachesWireOnce(t *testing.T) {
	srv := &severWireServer{}
	client := NewSeveringClient(srv.dialFunc())
	sweep := NewRevocationSweep(client)

	// Duplicates + an empty jti in the input; each distinct jti must hit the wire once.
	n, err := sweep.apply(context.Background(), []string{"j-a", "j-b", "j-a", "", "j-c", "j-b"})
	if err != nil {
		t.Fatalf("sweep.apply: %v", err)
	}
	if n != 3 {
		t.Errorf("severed count = %d, want 3", n)
	}

	got := srv.jtiCounts()
	for _, jti := range []string{"j-a", "j-b", "j-c"} {
		if got[jti] != 1 {
			t.Errorf("jti %q reached the wire %d times, want 1", jti, got[jti])
		}
	}
	if len(got) != 3 {
		t.Errorf("distinct jtis on wire = %d, want 3 (got %v)", len(got), keys(got))
	}

	// The wire carried the default sever_pair op and both legs.
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, r := range srv.requests {
		if r.op != opSeverPair {
			t.Errorf("wire op = %d, want opSeverPair(%d)", r.op, opSeverPair)
		}
		if r.legs != legsBoth {
			t.Errorf("wire legs = %#x, want legsBoth(%#x)", r.legs, legsBoth)
		}
	}
}

// TestSeveringClient_IdempotentUnknownJTI confirms an OK/severed=0 response (the
// proxy's idempotent no-op for an unknown jti) yields a nil error.
func TestSeveringClient_IdempotentUnknownJTI(t *testing.T) {
	srv := &severWireServer{}
	client := NewSeveringClient(srv.dialFunc())
	if err := client.Sever(context.Background(), "never-seen"); err != nil {
		t.Fatalf("Sever of unknown jti should be a nil no-op, got %v", err)
	}
	// An empty jti is a pure no-op that never touches the wire.
	if err := client.Sever(context.Background(), ""); err != nil {
		t.Fatalf("Sever of empty jti should be nil, got %v", err)
	}
	if c := srv.jtiCounts()[""]; c != 0 {
		t.Errorf("empty jti reached the wire %d times, want 0", c)
	}
}

// severLegsServer is a minimal recorder used to assert WithSeverLegs.
func TestSeveringClient_WithSeverLegsUsesSeverLegsOp(t *testing.T) {
	srv := &severWireServer{}
	client := NewSeveringClient(srv.dialFunc(), WithSeverLegs(legUpstream))
	if err := client.Sever(context.Background(), "j-legs"); err != nil {
		t.Fatalf("Sever: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.requests) != 1 {
		t.Fatalf("wire requests = %d, want 1", len(srv.requests))
	}
	if srv.requests[0].op != opSeverLegs {
		t.Errorf("wire op = %d, want opSeverLegs(%d)", srv.requests[0].op, opSeverLegs)
	}
	if srv.requests[0].legs != legUpstream {
		t.Errorf("wire legs = %#x, want legUpstream(%#x)", srv.requests[0].legs, legUpstream)
	}
}

// TestSeveringClient_NonOKStatusErrors confirms a non-OK remote status surfaces
// as an error (a failed datapath sever is never swallowed).
func TestSeveringClient_NonOKStatusErrors(t *testing.T) {
	dial := func(_ context.Context) (net.Conn, error) {
		clientEnd, serverEnd := net.Pipe()
		go func() {
			defer serverEnd.Close()
			_ = serverEnd.SetDeadline(time.Now().Add(2 * time.Second))
			// Drain the request frame, then answer a non-OK status.
			var lp [4]byte
			if _, err := io.ReadFull(serverEnd, lp[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(lp[:])
			if n > severFrameMaxBody {
				return
			}
			if _, err := io.ReadFull(serverEnd, make([]byte, n)); err != nil {
				return
			}
			resp := make([]byte, 4+severRespBodyLen)
			binary.BigEndian.PutUint32(resp[:4], uint32(severRespBodyLen))
			resp[4] = 9 // non-OK status
			_, _ = serverEnd.Write(resp)
		}()
		return clientEnd, nil
	}
	client := NewSeveringClient(dial)
	if err := client.Sever(context.Background(), "j-x"); err == nil {
		t.Fatal("Sever should error on a non-OK remote status")
	}
}

// TestSeveringClient_DialErrorSurfaces confirms a dial failure surfaces (so a
// RevocationSweep aborts rather than silently missing a sever).
func TestSeveringClient_DialErrorSurfaces(t *testing.T) {
	dial := func(_ context.Context) (net.Conn, error) {
		return nil, errors.New("synthetic dial failure")
	}
	client := NewSeveringClient(dial)
	if err := client.Sever(context.Background(), "j-y"); err == nil {
		t.Fatal("Sever should surface a dial failure")
	}
	// A nil dialer is a loud misconfiguration, not a silent no-op.
	if err := NewSeveringClient(nil).Sever(context.Background(), "j-z"); err == nil {
		t.Fatal("Sever with a nil dialer should error")
	}
}

// TestNewLiveSeveringClient_GatedOffByDefault pins the deferred-manual live leg:
// without DS_SEVER_LIVE the constructor arms nothing and dials no socket.
func TestNewLiveSeveringClient_GatedOffByDefault(t *testing.T) {
	t.Setenv(envSeverLive, "")
	if c, ok := NewLiveSeveringClient(); ok || c != nil {
		t.Fatalf("NewLiveSeveringClient with DS_SEVER_LIVE unset = (%v, %v), want (nil, false)", c, ok)
	}
	// When armed, it builds a client (but is NOT dialed here — that is the
	// deferred-manual leg exercised only against a real proxy socket).
	t.Setenv(envSeverLive, "1")
	if c, ok := NewLiveSeveringClient(); !ok || c == nil {
		t.Fatalf("NewLiveSeveringClient with DS_SEVER_LIVE set = (%v, %v), want (non-nil, true)", c, ok)
	}
}

// TestSeverLiveDialDeferred is the DS_SEVER_LIVE-gated real-UDS leg. It is a
// deferred-manual step: skipped offline, so the live dial is never exercised in
// the default build (only run when an operator arms DS_SEVER_LIVE against a real
// ds-tlsproxy sever socket).
func TestSeverLiveDialDeferred(t *testing.T) {
	if os.Getenv(envSeverLive) == "" {
		t.Skip("DS_SEVER_LIVE unset: live sever dial is a deferred-manual leg (D50)")
	}
	client, ok := NewLiveSeveringClient(WithSeverTimeout(2 * time.Second))
	if !ok {
		t.Fatal("NewLiveSeveringClient not armed despite DS_SEVER_LIVE set")
	}
	if err := client.Sever(context.Background(), "live-probe-jti"); err != nil {
		t.Fatalf("live Sever against real ds-tlsproxy socket: %v", err)
	}
}

// TestEncodeSeverRequest_RefusesOverLargeBody confirms the encoder refuses a
// frame larger than the shared MAX_FRAME_BODY rather than emitting one the
// consumer would silently drop (a dropped sever is a missed sever).
func TestEncodeSeverRequest_RefusesOverLargeBody(t *testing.T) {
	huge := make([]byte, severFrameMaxBody+1)
	for i := range huge {
		huge[i] = 'a'
	}
	if _, err := encodeSeverRequest(opSeverPair, legsBoth, string(huge)); err == nil {
		t.Fatal("encodeSeverRequest should refuse an over-large body")
	}
	// A normal jti round-trips through encode.
	frame, err := encodeSeverRequest(opSeverPair, legsBoth, "ok-jti")
	if err != nil {
		t.Fatalf("encodeSeverRequest: %v", err)
	}
	if got := binary.BigEndian.Uint32(frame[:4]); int(got) != len(frame)-4 {
		t.Errorf("frame length prefix = %d, want %d", got, len(frame)-4)
	}
}
