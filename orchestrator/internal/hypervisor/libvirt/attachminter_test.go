// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// attachBinding is a well-formed IPv4 binding for the minter tests (the three-keys
// shape; only GuestIP is load-bearing for the endpoint render).
func attachBinding(ip ...byte) Binding {
	if len(ip) == 0 {
		ip = []byte{10, 20, 0, 7}
	}
	return Binding{
		HostSessionIndex: 7,
		TapName:          "dstap-7",
		GuestIP:          GuestAddress{Family: AddressFamilyIPv4, Address: ip},
		OverlayPath:      "/var/lib/ds/overlays/sess.qcow2",
	}
}

func TestLiveAttachMinter_MintsServedUDSEndpointFromBinding(t *testing.T) {
	dir := t.TempDir()
	m, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: dir, AttachPort: 4242})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}

	h, err := m.MintAttachHandle(context.Background(), "sess-A", attachBinding(10, 20, 0, 7), attachv1.Role_ROLE_WRITER)
	if err != nil {
		t.Fatalf("MintAttachHandle: %v", err)
	}

	if h.GetSessionUuid() != "sess-A" {
		t.Errorf("session_uuid = %q, want sess-A", h.GetSessionUuid())
	}
	if got := len(h.GetEndpoints()); got != 1 {
		t.Fatalf("endpoints = %d, want exactly 1 (M0 DIRECT only)", got)
	}
	ep := h.GetEndpoints()[0]
	if ep.GetTransport() != attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT {
		t.Errorf("transport = %v, want DIRECT", ep.GetTransport())
	}
	// The DIRECT endpoint is the host-local SERVED UDS path (what serpent-tui's
	// DIRECT→TransportUnix carrier dials) — NOT GuestIP:port. It is keyed exactly like the
	// AttachBridge serves it and the orchestrator endpoint resolver advertises it.
	if want := DefaultAttachSocketDir + "/sess-A.sock"; ep.GetAddress() != want {
		t.Errorf("address = %q, want the served host-local UDS path %q", ep.GetAddress(), want)
	}
	if ep.GetServerName() != "" {
		t.Errorf("serverName = %q, want empty (host-local hop has no SNI)", ep.GetServerName())
	}
	if h.GetRole() != attachv1.Role_ROLE_WRITER {
		t.Errorf("role = %v, want WRITER (faithful passthrough)", h.GetRole())
	}
	if len(h.GetAuth().GetToken()) == 0 {
		t.Error("auth token is empty; want a minted session-scoped token")
	}
	if h.GetExpiresAt() == 0 {
		t.Error("handle expires_at is 0; want a bounded TTL")
	}
	// AuthMaterial.expires_at == whole-handle expires_at at M0 (one shared TTL).
	if h.GetAuth().GetExpiresAt() != h.GetExpiresAt() {
		t.Errorf("auth.expires_at (%d) != handle.expires_at (%d)", h.GetAuth().GetExpiresAt(), h.GetExpiresAt())
	}
}

// TestLiveAttachMinter_EndpointIsUDSNotGuestIP pins the carriage-swap correctness: the
// minted endpoint address must NOT be the guest IP:port (a TCP host:port serpent-tui would
// then try to dial as a UDS path) — it must be the served host-local socket. The same
// session always renders the same socket name (idempotent), independent of the guest IP.
func TestLiveAttachMinter_EndpointIsUDSNotGuestIP(t *testing.T) {
	m, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}
	h, err := m.MintAttachHandle(context.Background(), "sess-X", attachBinding(10, 20, 0, 99), attachv1.Role_ROLE_WRITER)
	if err != nil {
		t.Fatalf("MintAttachHandle: %v", err)
	}
	addr := h.GetEndpoints()[0].GetAddress()
	if want := DefaultAttachSocketDir + "/sess-X.sock"; addr != want {
		t.Errorf("address = %q, want served UDS %q (not a guest IP:port)", addr, want)
	}
	// Belt-and-suspenders: the address must not carry the guest IP literal.
	if got := h.GetEndpoints()[0].GetAddress(); got == "10.20.0.99:4242" {
		t.Errorf("address is the guest IP:port %q — serpent-tui would dial a TCP host:port as a UDS", got)
	}
}

// TestLiveAttachMinter_DefaultSocketDir proves a minter built with no explicit socket dir
// renders the endpoint under DefaultAttachSocketDir, which MUST equal the host-agent
// AttachBridge's served-UDS dir so the minted endpoint and the served socket name one path.
func TestLiveAttachMinter_DefaultSocketDir(t *testing.T) {
	m, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}
	h, err := m.MintAttachHandle(context.Background(), "sess", attachBinding(10, 20, 0, 9), attachv1.Role_ROLE_READER)
	if err != nil {
		t.Fatalf("MintAttachHandle: %v", err)
	}
	if got, want := h.GetEndpoints()[0].GetAddress(), DefaultAttachSocketDir+"/sess.sock"; got != want {
		t.Errorf("address = %q, want %q (DefaultAttachSocketDir-keyed served UDS)", got, want)
	}
	if h.GetRole() != attachv1.Role_ROLE_READER {
		t.Errorf("role = %v, want READER", h.GetRole())
	}
}

func TestLiveAttachMinter_IdempotentOnSessionAndRole(t *testing.T) {
	m, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}
	b := attachBinding()
	h1, err := m.MintAttachHandle(context.Background(), "sess", b, attachv1.Role_ROLE_WRITER)
	if err != nil {
		t.Fatalf("mint 1: %v", err)
	}
	h2, err := m.MintAttachHandle(context.Background(), "sess", b, attachv1.Role_ROLE_WRITER)
	if err != nil {
		t.Fatalf("mint 2: %v", err)
	}
	// A retry within the TTL re-issues an EQUIVALENT handle: same endpoint, same token,
	// same expiry (never a second conflicting seat).
	if h1.GetEndpoints()[0].GetAddress() != h2.GetEndpoints()[0].GetAddress() {
		t.Errorf("endpoint drifted on retry: %q vs %q", h1.GetEndpoints()[0].GetAddress(), h2.GetEndpoints()[0].GetAddress())
	}
	if !bytes.Equal(h1.GetAuth().GetToken(), h2.GetAuth().GetToken()) {
		t.Error("auth token drifted on retry; want the SAME token (idempotent mint)")
	}
	if h1.GetExpiresAt() != h2.GetExpiresAt() {
		t.Errorf("expiry drifted on retry: %d vs %d", h1.GetExpiresAt(), h2.GetExpiresAt())
	}
}

func TestLiveAttachMinter_RejectsMalformedGuestAddress(t *testing.T) {
	m, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}
	// A 3-byte "IPv4" address disagrees with the family tag — a malformed binding.
	bad := Binding{GuestIP: GuestAddress{Family: AddressFamilyIPv4, Address: []byte{10, 0, 0}}}
	if _, err := m.MintAttachHandle(context.Background(), "sess", bad, attachv1.Role_ROLE_WRITER); err == nil {
		t.Fatal("expected an error for a malformed guest address; got nil")
	}
}

func TestLiveAttachMinter_EmptySessionRejected(t *testing.T) {
	m, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}
	if _, err := m.MintAttachHandle(context.Background(), "", attachBinding(), attachv1.Role_ROLE_WRITER); err == nil {
		t.Fatal("expected an error for an empty session uuid; got nil")
	}
}

func TestNewLiveAttachMinter_RequiresOverlayDir(t *testing.T) {
	if _, err := NewLiveAttachHandleMinter(LiveConfig{}); err == nil {
		t.Fatal("expected an error when OverlayDir is empty; got nil")
	}
}

// ── resolved-mode transport tag (U-HOST-SERVE) ─────────────────────────────────

// TestLiveAttachMinter_StructuredMintsDIRECT proves a session whose resolved mode is
// STRUCTURED (or has no persisted marker — the absent-default) mints a DIRECT endpoint,
// byte-identical to the pre-terminal behavior. NewLiveAttachHandleMinter reads the
// session-mode store under the SAME OverlayDir the producer wrote; with no marker the
// session reads structured.
func TestLiveAttachMinter_StructuredMintsDIRECT(t *testing.T) {
	dir := t.TempDir()
	m, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: dir})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}
	// An EXPLICIT structured marker (the producer persisted structured) and the ABSENT
	// marker must both mint DIRECT.
	modes, err := NewFileSessionModeStore(dir)
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	if err := modes.PutMode(context.Background(), "sess-struct", SessionModeStructured); err != nil {
		t.Fatalf("PutMode: %v", err)
	}
	for _, sess := range []string{"sess-struct", "sess-no-marker"} {
		h, err := m.MintAttachHandle(context.Background(), sess, attachBinding(), attachv1.Role_ROLE_WRITER)
		if err != nil {
			t.Fatalf("MintAttachHandle(%s): %v", sess, err)
		}
		if got := h.GetEndpoints()[0].GetTransport(); got != attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT {
			t.Errorf("session %s transport = %v, want DIRECT (structured/absent default)", sess, got)
		}
	}
}

// TestLiveAttachMinter_TerminalMintsRawTerminal proves a session whose resolved mode is
// TERMINAL (the producer persisted terminal) mints a RAW_TERMINAL endpoint — the SAME
// served UDS path, only the transport TAG differs (RAW_TERMINAL is a fourth byte-format
// on the same DIRECT host-local hop, doc 04 §2.7). The token/expiry/idempotency are
// IDENTICAL to a structured session (the same store, the same TTL).
func TestLiveAttachMinter_TerminalMintsRawTerminal(t *testing.T) {
	dir := t.TempDir()
	m, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: dir})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}
	modes, err := NewFileSessionModeStore(dir)
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	if err := modes.PutMode(context.Background(), "sess-term", SessionModeTerminal); err != nil {
		t.Fatalf("PutMode: %v", err)
	}
	h, err := m.MintAttachHandle(context.Background(), "sess-term", attachBinding(), attachv1.Role_ROLE_WRITER)
	if err != nil {
		t.Fatalf("MintAttachHandle: %v", err)
	}
	ep := h.GetEndpoints()[0]
	if ep.GetTransport() != attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL {
		t.Errorf("terminal-session transport = %v, want RAW_TERMINAL", ep.GetTransport())
	}
	// The address is the SAME served UDS path — only the tag differs.
	if want := DefaultAttachSocketDir + "/sess-term.sock"; ep.GetAddress() != want {
		t.Errorf("terminal address = %q, want the SAME served UDS %q (only the tag differs)", ep.GetAddress(), want)
	}
	// Token/TTL machinery is unchanged: a re-mint within the TTL is idempotent (same
	// token, same expiry) exactly like a structured session.
	h2, err := m.MintAttachHandle(context.Background(), "sess-term", attachBinding(), attachv1.Role_ROLE_WRITER)
	if err != nil {
		t.Fatalf("re-mint: %v", err)
	}
	if !bytes.Equal(h.GetAuth().GetToken(), h2.GetAuth().GetToken()) {
		t.Error("terminal session token drifted on retry; want the SAME token (idempotent, store unchanged)")
	}
	if h.GetExpiresAt() != h2.GetExpiresAt() {
		t.Errorf("terminal session expiry drifted: %d vs %d", h.GetExpiresAt(), h2.GetExpiresAt())
	}
	if len(h.GetAuth().GetToken()) == 0 || h.GetExpiresAt() == 0 {
		t.Error("terminal handle missing token/expiry; the token/TTL machinery must be identical to structured")
	}
}

// TestLiveAttachMinter_CorruptModeMarkerFailsLoud proves a corrupt resolved-mode marker
// is fail-loud at mint (an error) — it must NOT silently downgrade a terminal session to
// a DIRECT handle and mis-route the client onto the structured carrier.
func TestLiveAttachMinter_CorruptModeMarkerFailsLoud(t *testing.T) {
	dir := t.TempDir()
	m, err := NewLiveAttachHandleMinter(LiveConfig{OverlayDir: dir})
	if err != nil {
		t.Fatalf("NewLiveAttachHandleMinter: %v", err)
	}
	bad := filepath.Join(dir, sessionModeSubdir, "sess-bad")
	if err := os.WriteFile(bad, []byte("not-a-mode"), 0o600); err != nil {
		t.Fatalf("seed garbage marker: %v", err)
	}
	if _, err := m.MintAttachHandle(context.Background(), "sess-bad", attachBinding(), attachv1.Role_ROLE_WRITER); err == nil {
		t.Fatal("MintAttachHandle with a corrupt mode marker must fail loud, got nil err")
	}
}

// ── token store ──────────────────────────────────────────────────────────────

func TestAttachTokenStore_PersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("store 1: %v", err)
	}
	tok1, exp1, err := s1.TokenFor(context.Background(), "sess")
	if err != nil {
		t.Fatalf("TokenFor 1: %v", err)
	}

	// A SECOND store over the same dir (a host-agent restart) returns the SAME token —
	// the durability the serving leg relies on to validate a handle issued before the
	// restart.
	s2, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("store 2: %v", err)
	}
	tok2, exp2, err := s2.TokenFor(context.Background(), "sess")
	if err != nil {
		t.Fatalf("TokenFor 2: %v", err)
	}
	if !bytes.Equal(tok1, tok2) {
		t.Error("token changed across store instances; want durable reuse")
	}
	if !exp1.Equal(exp2) {
		t.Errorf("expiry changed across store instances: %v vs %v", exp1, exp2)
	}
}

func TestAttachTokenStore_ReMintsAfterExpiry(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	base := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return base }
	tok1, _, err := s.TokenFor(context.Background(), "sess")
	if err != nil {
		t.Fatalf("TokenFor 1: %v", err)
	}
	// Advance past the TTL: the next call must mint a FRESH token (a legitimately
	// re-issued handle after expiry, not the idempotent same-token path).
	s.now = func() time.Time { return base.Add(2 * time.Hour) }
	tok2, _, err := s.TokenFor(context.Background(), "sess")
	if err != nil {
		t.Fatalf("TokenFor 2: %v", err)
	}
	if bytes.Equal(tok1, tok2) {
		t.Error("token unchanged after expiry; want a fresh mint")
	}
}

func TestAttachTokenStore_DistinctTokensPerSession(t *testing.T) {
	s, err := NewFileAttachTokenStore(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	a, _, err := s.TokenFor(context.Background(), "sess-A")
	if err != nil {
		t.Fatalf("TokenFor A: %v", err)
	}
	b, _, err := s.TokenFor(context.Background(), "sess-B")
	if err != nil {
		t.Fatalf("TokenFor B: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two sessions share a token; want session-scoped distinctness (D39)")
	}
}

func TestAttachTokenStore_ConcurrentSameSessionConverges(t *testing.T) {
	s, err := NewFileAttachTokenStore(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	const n = 16
	toks := make([][]byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, _, err := s.TokenFor(context.Background(), "sess")
			if err != nil {
				t.Errorf("concurrent TokenFor: %v", err)
				return
			}
			toks[i] = tok
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if !bytes.Equal(toks[0], toks[i]) {
			t.Fatalf("concurrent mints diverged: token[0] != token[%d]; want one converged token", i)
		}
	}
}

// ── §4.2 teardown purge (AttachTokenDisposer) ────────────────────────────────

// TestAttachTokenStore_RemoveTokenPurgesTheCredential asserts the §4.2 teardown removes
// the session's persisted bearer token (doc 15 §4.2; the doc 06 §(b) "no leftover minted
// identity" row). Without it a DESTROYED session's D39 credential stayed valid on disk
// until attachHandleTTL lapsed — and that TTL is this store's ONLY revocation mechanism
// (doc 19 §7). A second session's token is left untouched (the purge is session-scoped).
func TestAttachTokenStore_RemoveTokenPurgesTheCredential(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctx := context.Background()
	if _, _, err := s.TokenFor(ctx, "sess-gone"); err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	if _, _, err := s.TokenFor(ctx, "sess-live"); err != nil {
		t.Fatalf("TokenFor (sibling): %v", err)
	}
	if _, err := os.Stat(s.tokenPath("sess-gone")); err != nil {
		t.Fatalf("precondition: the token must exist before the teardown purge: %v", err)
	}

	if err := s.RemoveToken(ctx, "sess-gone"); err != nil {
		t.Fatalf("RemoveToken: %v", err)
	}
	if _, err := os.Stat(s.tokenPath("sess-gone")); !os.IsNotExist(err) {
		t.Fatalf("the destroyed session's token must be gone, stat err = %v", err)
	}
	// A live token is a PURE read after the purge (TokenPeek never mints), so this asserts
	// the credential is genuinely unusable, not merely unlinked from one code path.
	if _, _, ok, err := s.TokenPeek(ctx, "sess-gone"); err != nil || ok {
		t.Fatalf("TokenPeek after purge = (ok=%v, err=%v), want a clean read-only miss", ok, err)
	}
	if _, _, ok, err := s.TokenPeek(ctx, "sess-live"); err != nil || !ok {
		t.Fatalf("a sibling session's token must survive the purge (ok=%v, err=%v)", ok, err)
	}
}

// TestAttachTokenStore_RemoveTokenAbsentIsCleanNoOp: an ABSENT token file is a clean
// success — a session that never minted (the offline no-launch path, a create that rolled
// back before the post-boot mint) and a §4.2 RE-DRIVE over an already-purged session both
// converge, exactly like the sibling fileSessionRecordStore.Remove contract.
func TestAttachTokenStore_RemoveTokenAbsentIsCleanNoOp(t *testing.T) {
	s, err := NewFileAttachTokenStore(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctx := context.Background()
	if err := s.RemoveToken(ctx, "never-minted"); err != nil {
		t.Fatalf("RemoveToken(absent) = %v, want a clean no-op success", err)
	}
	if _, _, err := s.TokenFor(ctx, "sess-x"); err != nil {
		t.Fatalf("TokenFor: %v", err)
	}
	if err := s.RemoveToken(ctx, "sess-x"); err != nil {
		t.Fatalf("RemoveToken: %v", err)
	}
	if err := s.RemoveToken(ctx, "sess-x"); err != nil {
		t.Fatalf("RemoveToken (re-drive) = %v, want a clean no-op success", err)
	}
}

// TestAttachTokenStore_RemoveTokenFaultPropagates: a genuine store fault is NEVER
// swallowed — a credential the host could not delete must surface so the §4.2 Destroy is
// truthful and the reconciler re-drives. The fault is staged as a NON-EMPTY DIRECTORY at
// the token path (os.Remove then fails with ENOTEMPTY rather than ENOENT).
func TestAttachTokenStore_RemoveTokenFaultPropagates(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	blocked := s.tokenPath("sess-wedged")
	if err := os.MkdirAll(filepath.Join(blocked, "occupied"), 0o700); err != nil {
		t.Fatalf("stage the un-removable token path: %v", err)
	}
	err = s.RemoveToken(context.Background(), "sess-wedged")
	if err == nil {
		t.Fatal("a genuine remove fault must propagate, never a swallowed clean success")
	}
	if !strings.Contains(err.Error(), "sess-wedged") {
		t.Fatalf("error %q must name the session for the §4.2 destroy_error", err)
	}
}

// TestAttachTokenStore_RemoveTokenEmptySessionIsRejected: trustpath.Sanitize maps "" to
// the literal "session", so a blind purge on an empty uuid would delete an unrelated
// store leaf. It is a caller error, and nothing is touched.
func TestAttachTokenStore_RemoveTokenEmptySessionIsRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	// The leaf an empty uuid would sanitize onto — seeded so a blind removal is visible.
	victim := s.tokenPath("")
	if err := os.WriteFile(victim, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed the sanitize-collision leaf: %v", err)
	}
	if err := s.RemoveToken(context.Background(), ""); err == nil {
		t.Fatal("an empty session uuid must be a caller error")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("an empty session uuid must touch nothing, stat = %v", err)
	}
}

// Compile-time: the production token store satisfies the teardown role the daemon root
// type-asserts it up to (the MintClient→MintExpiryClient extension posture).
var _ AttachTokenDisposer = (*fileAttachTokenStore)(nil)
