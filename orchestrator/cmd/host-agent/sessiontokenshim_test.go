// SPDX-License-Identifier: Apache-2.0

// sessiontokenshim_test.go — OFFLINE tests for the host-local D22 session-token
// shim (U5, hardened by the U5 authz fix). CGO-free, NO live vsock, no
// DS_HOSTAGENT_LIVE (the default offline substrate, mirroring main_test.go's
// in-process style). They drive the PURE authz core (serveConn) over a FAKE
// accepted-conn carrying a chosen peer CID — matching attachfwd/vsockdial's
// offline-test split (the live AF_VSOCK bind/accept is operator-validated on the KVM
// box, never in a unit test). They prove the four required cases:
//
//	(a) SAME-session   — a conn whose peer CID is registered to session S yields S's
//	                     token bytes.
//	(b) CROSS-session  — a conn whose peer CID maps to session A can NEVER obtain
//	                     session B's token (the core exfiltration fix: the handler only
//	                     ever serves the token for the CID's OWN session).
//	(c) UNAUTHENTICATED — a conn whose peer CID is not in the registry gets NOTHING and
//	                     the conn is closed (fail-closed, no fallback token).
//	(d) OFFLINE        — the gate-aware source serves the NON-SECRET placeholder, never
//	                     an error, never a real token; the reference-only invariant
//	                     (the value never enters EntrypointFacts/config) holds.
//
// Plus the Serve/Shutdown lifecycle deadlock-regression guard, driven over a FAKE
// listener (no live vsock) so CI without vhost_vsock stays green.
package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// fakeTokenSource is an in-package tokenSource keyed BY SESSION: it returns the bytes
// registered for the requested session UUID, or an error when err is set. Keying by
// session is what lets the CROSS-session test prove the handler serves ONLY the CID's
// own session — asking for B's token requires B's session string, which the handler
// never derives from A's CID.
type fakeTokenSource struct {
	bySession map[string][]byte
	err       error
}

func (f fakeTokenSource) TokenFor(_ context.Context, sessionUUID string) ([]byte, int64, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	return f.bySession[sessionUUID], 0, nil
}

// fakePeerConn is an in-memory peerCIDConn: it carries a chosen peer CID and captures
// everything the handler Writes to it (the served token bytes), so a test asserts the
// exact bytes without any live vsock. Read returns EOF (the guest sends nothing
// identifying — the CID is the whole credential). closed records the fail-closed path.
type fakePeerConn struct {
	peerCID uint32
	mu      sync.Mutex
	written bytes.Buffer
	closed  bool
}

func (c *fakePeerConn) PeerCID() uint32 { return c.peerCID }

func (c *fakePeerConn) Read(_ []byte) (int, error) { return 0, net.ErrClosed }

func (c *fakePeerConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.Write(p)
}

func (c *fakePeerConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakePeerConn) bytesWritten() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written.Bytes()...)
}

func (c *fakePeerConn) wasClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// the net.Conn address/deadline methods the interface requires but the authz core
// never calls — supplied as inert stubs so fakePeerConn satisfies peerCIDConn.
func (c *fakePeerConn) LocalAddr() net.Addr                { return fakeVsockAddr{} }
func (c *fakePeerConn) RemoteAddr() net.Addr               { return fakeVsockAddr{cid: c.peerCID} }
func (c *fakePeerConn) SetDeadline(_ time.Time) error      { return nil }
func (c *fakePeerConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fakePeerConn) SetWriteDeadline(_ time.Time) error { return nil }

type fakeVsockAddr struct{ cid uint32 }

func (fakeVsockAddr) Network() string  { return "vsock" }
func (a fakeVsockAddr) String() string { return "vsock:peer" }

// TestSessionTokenShimSameSessionServesOwnToken is case (a): a conn whose peer CID is
// registered to session S is served S's token bytes (and the conn is closed after).
func TestSessionTokenShimSameSessionServesOwnToken(t *testing.T) {
	const (
		cidA      = uint32(7)
		sessionA  = "sess-AAAA"
		tokenAStr = "token-for-session-A"
	)
	reg := newSessionCIDRegistry()
	reg.Bind(cidA, sessionA)
	src := fakeTokenSource{bySession: map[string][]byte{sessionA: []byte(tokenAStr)}}
	shim := newSessionTokenShim(src, reg)

	conn := &fakePeerConn{peerCID: cidA}
	shim.serveConn(context.Background(), conn)

	if got := conn.bytesWritten(); string(got) != tokenAStr {
		t.Errorf("same-session served %q, want session A's own token %q", got, tokenAStr)
	}
	if !conn.wasClosed() {
		t.Error("conn was not closed after serving (one-shot serve must close)")
	}
}

// TestSessionTokenShimCrossSessionCannotGetOthersToken is case (b), THE CORE FIX: a
// conn whose peer CID maps to session A can NEVER obtain session B's token. The
// handler derives the session purely from the (unforgeable) CID, so a guest with A's
// CID is served A's token — never B's. B's token is only ever reachable by a conn
// presenting B's CID. There is no UUID on the wire to spoof.
func TestSessionTokenShimCrossSessionCannotGetOthersToken(t *testing.T) {
	const (
		cidA      = uint32(7)
		cidB      = uint32(8)
		sessionA  = "sess-AAAA"
		sessionB  = "sess-BBBB"
		tokenAStr = "token-for-session-A"
		tokenBStr = "token-for-session-B"
	)
	reg := newSessionCIDRegistry()
	reg.Bind(cidA, sessionA)
	reg.Bind(cidB, sessionB)
	src := fakeTokenSource{bySession: map[string][]byte{
		sessionA: []byte(tokenAStr),
		sessionB: []byte(tokenBStr),
	}}
	shim := newSessionTokenShim(src, reg)

	// A guest connecting from A's CID is served A's token — and CANNOT obtain B's.
	connA := &fakePeerConn{peerCID: cidA}
	shim.serveConn(context.Background(), connA)
	gotA := connA.bytesWritten()
	if string(gotA) != tokenAStr {
		t.Errorf("CID A served %q, want A's own token %q", gotA, tokenAStr)
	}
	if bytes.Contains(gotA, []byte(tokenBStr)) {
		t.Fatal("CROSS-SESSION LEAK: a connection from session A's CID obtained session B's token (the exact U5 exfiltration surface this fix closes)")
	}

	// Symmetrically, B's CID is served B's token, never A's.
	connB := &fakePeerConn{peerCID: cidB}
	shim.serveConn(context.Background(), connB)
	gotB := connB.bytesWritten()
	if string(gotB) != tokenBStr {
		t.Errorf("CID B served %q, want B's own token %q", gotB, tokenBStr)
	}
	if bytes.Contains(gotB, []byte(tokenAStr)) {
		t.Fatal("CROSS-SESSION LEAK: a connection from session B's CID obtained session A's token")
	}
}

// TestSessionTokenShimUnauthenticatedCIDFailsClosed is case (c): a conn whose peer CID
// is NOT in the registry (an unknown guest, or a session torn down) gets NOTHING and
// the conn is closed — fail-closed, never a fallback token, never another session's.
func TestSessionTokenShimUnauthenticatedCIDFailsClosed(t *testing.T) {
	const (
		cidKnown   = uint32(7)
		cidUnknown = uint32(99)
		sessionA   = "sess-AAAA"
		tokenAStr  = "token-for-session-A"
	)
	reg := newSessionCIDRegistry()
	reg.Bind(cidKnown, sessionA)
	src := fakeTokenSource{bySession: map[string][]byte{sessionA: []byte(tokenAStr)}}
	shim := newSessionTokenShim(src, reg)

	conn := &fakePeerConn{peerCID: cidUnknown}
	shim.serveConn(context.Background(), conn)

	if got := conn.bytesWritten(); len(got) != 0 {
		t.Errorf("unauthenticated (unmapped) CID was served %q, want NOTHING (fail-closed)", got)
	}
	if !conn.wasClosed() {
		t.Error("unauthenticated conn was not closed (fail-closed must close with no bytes)")
	}
}

// TestSessionTokenShimUnbindFailsClosedAfterTeardown proves the destroy-hook path: once
// a session's CID is UnbindSession'd, a connection from that (now-defunct) CID fails
// closed (the same fail-closed path as an unknown CID), so a torn-down session's CID
// stops resolving.
func TestSessionTokenShimUnbindFailsClosedAfterTeardown(t *testing.T) {
	const (
		cidA      = uint32(7)
		sessionA  = "sess-AAAA"
		tokenAStr = "token-for-session-A"
	)
	reg := newSessionCIDRegistry()
	reg.Bind(cidA, sessionA)
	src := fakeTokenSource{bySession: map[string][]byte{sessionA: []byte(tokenAStr)}}
	shim := newSessionTokenShim(src, reg)

	// Before teardown: served.
	pre := &fakePeerConn{peerCID: cidA}
	shim.serveConn(context.Background(), pre)
	if string(pre.bytesWritten()) != tokenAStr {
		t.Fatalf("pre-teardown served %q, want %q", pre.bytesWritten(), tokenAStr)
	}

	// Teardown (the destroy hook calls UnbindSession with only the session UUID).
	reg.UnbindSession(sessionA)

	// After teardown: fail-closed (the CID no longer resolves).
	post := &fakePeerConn{peerCID: cidA}
	shim.serveConn(context.Background(), post)
	if got := post.bytesWritten(); len(got) != 0 {
		t.Errorf("after teardown, CID %d was served %q, want NOTHING (fail-closed after Unbind)", cidA, got)
	}
}

// TestSessionTokenShimSourceErrorFailsClosed proves a TokenFor error fails closed: the
// conn gets NOTHING and is closed, never a partial/invented token (the live mint
// not-yet-contracted / unreachable path).
func TestSessionTokenShimSourceErrorFailsClosed(t *testing.T) {
	const (
		cidA     = uint32(7)
		sessionA = "sess-AAAA"
	)
	reg := newSessionCIDRegistry()
	reg.Bind(cidA, sessionA)
	src := fakeTokenSource{err: errors.New("mint unreachable")}
	shim := newSessionTokenShim(src, reg)

	conn := &fakePeerConn{peerCID: cidA}
	shim.serveConn(context.Background(), conn)
	if got := conn.bytesWritten(); len(got) != 0 {
		t.Errorf("source-error path served %q, want NOTHING (fail-closed; never a partial token)", got)
	}
	if !conn.wasClosed() {
		t.Error("source-error conn was not closed")
	}
}

// ── Serve/Shutdown lifecycle over a FAKE listener (NO live vsock) ────────────────

// fakeVsockListener is an in-process peerCIDListener: Accept blocks until a conn is fed
// (or Close is called, which unblocks pending Accepts with net.ErrClosed — the clean
// Shutdown path). It lets the Serve/Shutdown deadlock-regression guard run with NO live
// AF_VSOCK bind, so CI without vhost_vsock stays green.
type fakeVsockListener struct {
	conns  chan peerCIDConn
	closed chan struct{}
	once   sync.Once
}

func newFakeVsockListener() *fakeVsockListener {
	return &fakeVsockListener{conns: make(chan peerCIDConn, 16), closed: make(chan struct{})}
}

func (l *fakeVsockListener) Accept() (peerCIDConn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fakeVsockListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *fakeVsockListener) Addr() net.Addr { return fakeVsockAddr{} }

func (l *fakeVsockListener) feed(c peerCIDConn) {
	select {
	case l.conns <- c:
	case <-l.closed:
	}
}

// TestSessionTokenShimServeShutdownRoundTrip exercises the REAL Serve()+Shutdown()
// lifecycle over a fake listener (no live vsock): a fed conn is authorized + served,
// then Shutdown closes the listener and Serve MUST return promptly — the regression
// guard for the run()-ordering bug (Shutdown must cause Serve to return, or the
// daemon's wg.Wait() deadlocks).
func TestSessionTokenShimServeShutdownRoundTrip(t *testing.T) {
	const (
		cidA      = uint32(7)
		sessionA  = "sess-roundtrip"
		tokenAStr = "sl-sess-roundtrip-token"
	)
	reg := newSessionCIDRegistry()
	reg.Bind(cidA, sessionA)
	src := fakeTokenSource{bySession: map[string][]byte{sessionA: []byte(tokenAStr)}}
	shim := newSessionTokenShim(src, reg)

	lis := newFakeVsockListener()
	shim.listen = func(_ uint32) (peerCIDListener, error) { return lis, nil }

	errCh := make(chan error, 1)
	go func() { errCh <- shim.Serve(defaultSessionTokenVsockPort) }()

	// Wait for the listener to bind (Addr becomes non-nil).
	var bound bool
	for i := 0; i < 200; i++ {
		if shim.Addr() != nil {
			bound = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !bound {
		t.Fatal("shim never bound a listener within 1s")
	}

	// Feed a same-session conn and confirm it is served its own token.
	conn := &fakePeerConn{peerCID: cidA}
	lis.feed(conn)
	served := false
	for i := 0; i < 200; i++ {
		if string(conn.bytesWritten()) == tokenAStr {
			served = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !served {
		t.Fatalf("fed conn was not served its token within 1s; got %q", conn.bytesWritten())
	}

	// Shutdown, then assert Serve RETURNS promptly — the deadlock regression guard.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shim.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned an error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return within 3s after Shutdown (deadlock regression)")
	}
}

// TestSessionTokenShimNeverLeaksValueIntoConfig pins the reference-only invariant
// (D39): EntrypointFacts.SessionTokenEndpoint carries only the vsock ADDRESS the guest
// is told to dial, never the token value. The shim serves the value; it never enters
// the config the producer folds in.
func TestSessionTokenShimNeverLeaksValueIntoConfig(t *testing.T) {
	const endpoint = "vsock://host:8200/token"
	c, err := parseConfig([]string{"-session-token-endpoint", endpoint})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	facts := entrypointFacts(c)
	if facts.SessionTokenEndpoint != endpoint {
		t.Errorf("SessionTokenEndpoint = %q, want the advertised vsock reference %q", facts.SessionTokenEndpoint, endpoint)
	}
	// The placeholder token value must NOT appear anywhere in the facts the producer
	// folds into the EntrypointConfig — the value is served at boot, never embedded.
	if strings.Contains(facts.SessionTokenEndpoint, offlinePlaceholderToken) {
		t.Error("EntrypointFacts embedded the token value (D39: reference only, never the value)")
	}
}

// TestGatedSessionTokenSourceOffline asserts the D50 offline behavior: with
// DS_HOSTAGENT_LIVE unset, newGatedSessionTokenSource returns the offline source and
// TokenFor yields the NON-SECRET placeholder (not an error, so the daemon serves
// offline) — never a real token.
func TestGatedSessionTokenSourceOffline(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate OFF (the default offline substrate)

	src := newGatedSessionTokenSource("") // no mint addr needed offline
	if _, ok := src.(offlineTokenSource); !ok {
		t.Fatalf("off the gate newGatedSessionTokenSource returned %T, want offlineTokenSource (D50)", src)
	}
	token, expiry, err := src.TokenFor(context.Background(), "sess-offline")
	if err != nil {
		t.Fatalf("offline TokenFor must not error (the daemon serves offline): %v", err)
	}
	if string(token) != offlinePlaceholderToken {
		t.Errorf("offline token = %q, want the documented NON-SECRET placeholder %q", token, offlinePlaceholderToken)
	}
	if expiry != 0 {
		t.Errorf("offline placeholder expiry = %d, want 0 (no real expiry on a placeholder)", expiry)
	}
	// Defense-in-depth: the placeholder must be CLEARLY marked as not-a-real-token.
	if !strings.Contains(offlinePlaceholderToken, "NOT-A-REAL") {
		t.Error("offline placeholder is not clearly marked as a non-secret placeholder")
	}
}

// TestOfflineEndToEndServesPlaceholderToOwnCID ties the offline gate-aware source to the
// authz core: an offline daemon serves the NON-SECRET placeholder to a registered CID
// (proving the offline path is unchanged end-to-end — the same-session fetch succeeds
// with the placeholder, never an error, never a real token).
func TestOfflineEndToEndServesPlaceholderToOwnCID(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "")
	const (
		cidA     = uint32(7)
		sessionA = "sess-offline-e2e"
	)
	reg := newSessionCIDRegistry()
	reg.Bind(cidA, sessionA)
	shim := newSessionTokenShim(newGatedSessionTokenSource(""), reg)

	conn := &fakePeerConn{peerCID: cidA}
	shim.serveConn(context.Background(), conn)
	if got := conn.bytesWritten(); string(got) != offlinePlaceholderToken {
		t.Errorf("offline same-session served %q, want the NON-SECRET placeholder %q", got, offlinePlaceholderToken)
	}
}

// TestLiveSessionTokenSourceFailsClosedWithoutMintAddr proves the live source fails
// CLOSED (an error, never a placeholder-as-real-token) when no mint endpoint is
// configured — the live shim must never serve a placeholder as if it were real.
func TestLiveSessionTokenSourceFailsClosedWithoutMintAddr(t *testing.T) {
	src := &liveMintTokenSource{mintAddr: ""}
	if _, _, err := src.TokenFor(context.Background(), "sess-live"); err == nil {
		t.Error("live source with no mint addr must fail closed (D17), got a token")
	}
}

// fakeMintClient is an in-package mintClient (the injectable seam): it records the
// request and returns a canned response or error, exercising the live source's call
// onto the promoted MintSessionToken RPC WITHOUT a real grpc dial (the existing
// fakeTokenSource mock style, approach (a)).
type fakeMintClient struct {
	resp   *identityv1.MintSessionTokenResponse
	err    error
	gotReq *identityv1.MintSessionTokenRequest
}

func (f *fakeMintClient) MintSessionToken(_ context.Context, in *identityv1.MintSessionTokenRequest, _ ...grpc.CallOption) (*identityv1.MintSessionTokenResponse, error) {
	f.gotReq = in
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

// TestLiveSessionTokenSourceRoundTripsMintedToken proves the live source, wired to a
// (mocked) IdentityMintServiceClient, round-trips the minted token bytes + expiry from
// the promoted MintSessionToken RPC and passes the boot-time sessionUUID as the request
// scope (the U5 seam only has the UUID; the mint resolves the rest shim-side). No real
// grpc dial — the newClient seam injects the fake. The real DS_HOSTAGENT_LIVE dial stays
// operator-validated on the box.
func TestLiveSessionTokenSourceRoundTripsMintedToken(t *testing.T) {
	wantToken := []byte("real-d22-session-token-bytes")
	const wantExpiry int64 = 1_700_000_000
	fake := &fakeMintClient{resp: &identityv1.MintSessionTokenResponse{
		Token:             wantToken,
		ExpiryUnixSeconds: wantExpiry,
		SessionUuid:       "sess-live",
	}}
	src := &liveMintTokenSource{
		mintAddr:  "127.0.0.1:9100", // non-empty so the source does not fail closed early
		newClient: func(grpc.ClientConnInterface) mintClient { return fake },
	}

	token, expiry, err := src.TokenFor(context.Background(), "sess-live")
	if err != nil {
		t.Fatalf("live TokenFor returned an error: %v", err)
	}
	if !bytes.Equal(token, wantToken) {
		t.Errorf("token = %q, want the minted bytes %q", token, wantToken)
	}
	if expiry != wantExpiry {
		t.Errorf("expiry = %d, want the minted expiry %d", expiry, wantExpiry)
	}
	if fake.gotReq == nil || fake.gotReq.GetSessionUuid() != "sess-live" {
		t.Errorf("MintSessionToken request session_uuid = %q, want the boot-time UUID %q",
			fake.gotReq.GetSessionUuid(), "sess-live")
	}
}

// TestLiveSessionTokenSourceFailsClosedOnMintError proves the live source fails CLOSED
// (an error, never a partial/invented token) when the promoted MintSessionToken RPC
// returns an error — the handler maps it to a 502.
func TestLiveSessionTokenSourceFailsClosedOnMintError(t *testing.T) {
	fake := &fakeMintClient{err: errors.New("mint denied: session revoked")}
	src := &liveMintTokenSource{
		mintAddr:  "127.0.0.1:9100",
		newClient: func(grpc.ClientConnInterface) mintClient { return fake },
	}

	token, expiry, err := src.TokenFor(context.Background(), "sess-live")
	if err == nil {
		t.Fatal("live TokenFor must fail closed on a mint error, got a token")
	}
	if token != nil || expiry != 0 {
		t.Errorf("fail-closed path leaked a token/expiry: token=%q expiry=%d", token, expiry)
	}
}

// TestParseConfigSessionTokenFlags asserts the U5 flags parse and thread into the
// config (the vsock-port form replacing the old host:port listen addr).
func TestParseConfigSessionTokenFlags(t *testing.T) {
	c, err := parseConfig([]string{
		"-session-token-endpoint", "vsock://host:8200/token",
		"-session-token-listen-port", "8250",
		"-identity-mint-addr", "127.0.0.1:9100",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if c.sessionTokenEndpoint != "vsock://host:8200/token" {
		t.Errorf("sessionTokenEndpoint = %q", c.sessionTokenEndpoint)
	}
	if c.sessionTokenVsockPort != 8250 {
		t.Errorf("sessionTokenVsockPort = %d, want 8250", c.sessionTokenVsockPort)
	}
	if c.identityMintAddr != "127.0.0.1:9100" {
		t.Errorf("identityMintAddr = %q", c.identityMintAddr)
	}
	// Default port is the well-known token vsock port (distinct from attach 4242).
	d, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig(nil): %v", err)
	}
	if d.sessionTokenVsockPort != uint(defaultSessionTokenVsockPort) {
		t.Errorf("default sessionTokenVsockPort = %d, want %d", d.sessionTokenVsockPort, defaultSessionTokenVsockPort)
	}
	if defaultSessionTokenVsockPort == 4242 {
		t.Error("the token vsock port must be distinct from the attach carriage port 4242")
	}
}
