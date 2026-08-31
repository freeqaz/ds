// SPDX-License-Identifier: Apache-2.0

// sessiontokenshim.go — the host-local D22 session-token shim (U5, hardened by the
// U5 authz fix). The in-guest runtime fetches its short-lived D22 session token from
// this host-side server at boot. The daemon stands the shim up gate-aware
// (DS_HOSTAGENT_LIVE, exactly like every other live binding in the composition root —
// newGatedCAInjector / NewGatedEntrypointProducer): under the gate it dials the
// identity mint and serves REAL tokens; offline (the default, and the only sandbox /
// CI / unit path) it is a no-op/fake (D50) that serves a clearly-marked NON-SECRET
// offline placeholder so the daemon still builds CGO-free and serves offline.
//
// AUTHZ MECHANISM — AF_VSOCK PEER-CID (the U5 hardening, the core exfiltration fix):
// The shim serves the token over AF_VSOCK (the host listens on VMADDR_CID_HOST(2) at
// a well-known port; the guest dials it) and authorizes by the CONNECTING GUEST'S
// vsock CID. The host-agent ALONE derived each session's per-session CID at allocate
// (alloc.go: VsockCID = HostSessionIndex + reservedVsockCIDs, recorded in
// Binding.VsockCID). On accept, the peer Sockaddr is a *unix.SockaddrVM whose .CID is
// the connecting guest's CID; a guest CANNOT forge its source CID (the hypervisor
// assigns it per-VM at boot), so a connection arriving from CID X IS proof the caller
// is the session whose Binding.VsockCID==X. The shim maps peer-CID -> session (the
// sessionCIDRegistry, populated by the create/destroy hooks) and serves ONLY that
// session's token. The guest sends NOTHING identifying (no session UUID on the wire,
// no secret) — there is nothing to steal or replay, and a cross-session ask is
// structurally impossible: the caller can only ever present its OWN CID.
//
// This REPLACES the old GET /token?session=<uuid> over HTTP-on-SLIRP, which returned
// the token for ANY session UUID to ANY caller that could reach the port (the U7
// review's cross-session token-exfiltration surface). The guest no longer NAMES a
// session; the host DERIVES it from the unforgeable CID.
//
// FAIL CLOSED: an unknown/unmapped peer CID (no session bound for it) writes NOTHING
// and closes the conn (the analogue of 403 — never a fallback token, never another
// session's token); a TokenFor error likewise closes the conn with no bytes.
//
// VALUE-vs-REFERENCE (D39): only the shim ADDRESS ever rides EntrypointFacts /
// EntrypointConfig (now a vsock://host:<port>/token REFERENCE, still never the value);
// the token VALUE is served here at boot and never enters config. The token bytes are
// NEVER logged (fingerprint-only posture).
//
// UNBLOCKED (the core blocker this unit anticipated is resolved): the additive
// MintSessionToken RPC is now PROMOTED in identity.v1 ca_mint.proto (the same
// buf-safe path MintGrants/MintWorkloadIdentity/RevokeSession took, D111/D99/D97),
// so proto/gen/go's IdentityMintServiceClient now exposes MintSessionToken alongside
// MintInterceptionCA / MintGrants / MintWorkloadIdentity / RevokeSession. The live
// source dials it directly via the GENERATED client — consuming proto/gen/go ONLY,
// NEVER importing identity/mint (the OSS/paid fence is real + CI-enforced, D80). The
// U5 seam only has the sessionUUID (derived from the unforgeable peer CID), so the
// live call passes session_uuid and lets the mint resolve the rest shim-side
// (launching_user via its PrincipalResolver, defaults for org/repo/services/ttl); the
// richer request fields are flagged for seam-owner confirmation. The serving +
// gate-aware structure + tests are fully real; the live dial itself stays
// operator-validated on the box. The vsock accept loop (serveConn) authorizes by peer
// CID, resolves it to a session, and serves the token THIS live source mints — on any
// mint/dial error the conn fails closed (no bytes).

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// defaultSessionTokenVsockPort is the well-known AF_VSOCK port the host-local D22
// token shim listens on (host side, VMADDR_CID_HOST). It is distinct from the attach
// carriage port (4242, libvirt.DefaultAttachPort / attachfwd.WireAttachPort) so the
// two well-known vsock services never collide. Single-sourced here as the ONE place
// the token port lives; the guest is told a vsock://host:<port>/token reference that
// names it, and the daemon's -session-token-listen-port flag defaults to it.
const defaultSessionTokenVsockPort uint32 = 8200

// tokenSource is the ONE seam the accept loop calls: it returns the short-lived D22
// session token bytes for a session (never a long-lived credential, D39). It is the
// mint-backed seam — under DS_HOSTAGENT_LIVE a liveMintTokenSource that dials the
// identity.v1 mint; offline an offlineTokenSource serving a NON-SECRET marker.
// expiryUnix is the token's expiry (Unix seconds); the loop treats the bytes as
// opaque and NEVER logs them.
type tokenSource interface {
	TokenFor(ctx context.Context, sessionUUID string) (token []byte, expiryUnix int64, err error)
}

// cidResolver maps a connecting guest's (unforgeable) AF_VSOCK peer CID to the
// session UUID it belongs to. The accept loop looks the peer CID up here; a miss is
// fail-closed (no session ⇒ no token). The production implementation is
// sessionCIDRegistry, populated by the create post-boot hook (Bind) and the destroy
// post-destroy hook (UnbindSession); tests inject a fake.
type cidResolver interface {
	// Lookup returns the session UUID bound to peer CID, and ok=false if none is
	// bound (the fail-closed case — the caller writes nothing and closes the conn).
	Lookup(cid uint32) (sessionUUID string, ok bool)
}

// peerCIDConn is a net.Conn that ALSO reports its AF_VSOCK peer CID. The vsock
// listener (sessiontokenvsock_linux.go) yields these; the authz core reads PeerCID()
// to authorize. Keeping the authz handler over THIS interface (not a raw fd) makes it
// unit-testable with a fake accepted-conn carrying a chosen peer CID — NO live vsock
// needed (mirrors the attachfwd / vsockdial offline-test split).
type peerCIDConn interface {
	net.Conn
	PeerCID() uint32
}

// peerCIDListener is the AF_VSOCK listener seam: Accept yields a peerCIDConn. The
// linux implementation binds VMADDR_CID_HOST:<port>; a test can supply a fake that
// feeds chosen-CID conns so the authz core runs with no live vsock.
type peerCIDListener interface {
	Accept() (peerCIDConn, error)
	Close() error
	Addr() net.Addr
}

// sessionTokenShim is the host-local D22 token server: an AF_VSOCK acceptor that
// authorizes each connection by its peer CID and serves ONLY that session's token. It
// is stood up by run() only when a session-token endpoint is configured, and torn
// down on the graceful drain alongside bridge.Shutdown().
type sessionTokenShim struct {
	src      tokenSource
	resolver cidResolver

	mu  sync.Mutex
	lis peerCIDListener // bound in Serve; nil before/after

	// listen is the AF_VSOCK listener factory, indirected for tests (a test injects a
	// fake listener so the accept loop runs with NO live vsock). Nil => the production
	// listenTokenVsock (split per build tag: real on linux, fail-closed stub elsewhere).
	listen func(port uint32) (peerCIDListener, error)
}

// newSessionTokenShim builds the shim over a tokenSource and a cidResolver. The vsock
// listener is bound in Serve.
func newSessionTokenShim(src tokenSource, resolver cidResolver) *sessionTokenShim {
	return &sessionTokenShim{src: src, resolver: resolver}
}

// listener resolves the AF_VSOCK listener factory: the injected fake when set
// (offline tests), else the production listenTokenVsock (per build tag).
func (s *sessionTokenShim) listener() func(port uint32) (peerCIDListener, error) {
	if s.listen != nil {
		return s.listen
	}
	return listenTokenVsock
}

// serveConn is the PURE authz core, factored out so a test can drive it directly over
// a fake accepted-conn carrying a chosen peer CID (no live vsock). It reads the peer
// CID, resolves it to a session, and writes ONLY that session's token bytes —
// FAIL-CLOSED on every miss/error: an unmapped CID writes NOTHING and the conn is
// closed; a TokenFor error writes NOTHING and the conn is closed. The token bytes are
// NEVER logged or echoed into an error. The guest sends nothing identifying, so there
// is no request to parse — the connection's CID is the whole credential.
func (s *sessionTokenShim) serveConn(ctx context.Context, conn peerCIDConn) {
	defer conn.Close()

	cid := conn.PeerCID()
	session, ok := s.resolver.Lookup(cid)
	if !ok {
		// FAIL CLOSED: no session is bound to this peer CID (an unknown/unmapped guest,
		// or a session already torn down). Write NOTHING and close — never a fallback
		// token, never another session's token. This is the 403 analogue. The CID is
		// not logged as a value-bearing fact beyond a count; we stay quiet here.
		return
	}
	token, _, err := s.src.TokenFor(ctx, session)
	if err != nil {
		// FAIL CLOSED: a source error (mint unreachable / not-yet-contracted) writes
		// NOTHING and closes. The token bytes never appear (there are none); only the
		// non-secret source error would surface to a higher logger — never here.
		return
	}
	// Serve ONLY this CID's own session token. No framing, no headers — the guest reads
	// the bytes and TrimSpaces them (the wire shape it already trims). The token is
	// NEVER logged.
	_, _ = conn.Write(token)
}

// Serve binds the AF_VSOCK listener on VMADDR_CID_HOST:port and accepts until
// Shutdown. Each accepted connection is authorized by its peer CID and served its own
// session's token (serveConn). It returns once the listener is closed (Shutdown):
// net.ErrClosed (the clean-shutdown path) is folded to nil. A bind fault is returned
// loudly (run() fails the daemon — a guest would be advertised an endpoint that serves
// nothing).
func (s *sessionTokenShim) Serve(port uint32) error {
	lis, err := s.listener()(port)
	if err != nil {
		return fmt.Errorf("session-token shim listen vsock port %d: %w", port, err)
	}
	s.mu.Lock()
	s.lis = lis
	s.mu.Unlock()

	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil // clean Shutdown
			}
			return fmt.Errorf("session-token shim accept: %w", err)
		}
		// Serve each connection in its own goroutine so a slow/stalled guest never
		// blocks the accept loop. Each is a one-shot: authorize by CID, write the
		// token (or fail closed), close.
		go s.serveConn(context.Background(), conn)
	}
}

// Addr reports the bound listener address (CID:port). Empty before Serve binds.
func (s *sessionTokenShim) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lis == nil {
		return nil
	}
	return s.lis.Addr()
}

// Shutdown closes the listener so the accept loop returns (the graceful-drain path,
// run() calls this alongside bridge.Shutdown()). A never-Served shim is a no-op. ctx
// is accepted for signature parity with the previous http.Server.Shutdown so run()'s
// drain is unchanged; the vsock close is immediate.
func (s *sessionTokenShim) Shutdown(_ context.Context) error {
	s.mu.Lock()
	lis := s.lis
	s.mu.Unlock()
	if lis == nil {
		return nil
	}
	return lis.Close()
}

// ── peer-CID -> session registry ───────────────────────────────────────────────

// sessionCIDRegistry maps an AF_VSOCK peer CID to the session UUID it belongs to. The
// daemon owns ONE registry, shared between the shim's accept loop (Lookup, the authz
// resolver) and the create/destroy hooks (Bind at post-boot when Binding.VsockCID is
// known, UnbindSession at destroy so a torn-down session's CID stops resolving —
// fail-closed after teardown). It is mutex-guarded for the concurrent accept loop +
// lifecycle hooks. A reverse session->CID index lets the destroy hook (which only has
// the session UUID, not the CID) unbind cleanly.
type sessionCIDRegistry struct {
	mu        sync.RWMutex
	byCID     map[uint32]string // peer CID -> session UUID
	bySession map[string]uint32 // session UUID -> peer CID (for UnbindSession)
}

// newSessionCIDRegistry builds an empty registry.
func newSessionCIDRegistry() *sessionCIDRegistry {
	return &sessionCIDRegistry{
		byCID:     make(map[uint32]string),
		bySession: make(map[string]uint32),
	}
}

// Bind records that the guest at peer CID is session sessionUUID — called from the
// create post-boot hook once Binding.VsockCID is known (and non-zero). After this, a
// connection from that CID resolves to (and is served) this session's token. A zero
// CID or empty session is ignored (nothing to authorize). Re-binding the same CID is
// idempotent (a retried create re-derives the SAME CID).
func (r *sessionCIDRegistry) Bind(cid uint32, sessionUUID string) {
	if cid == 0 || sessionUUID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byCID[cid] = sessionUUID
	r.bySession[sessionUUID] = cid
}

// UnbindSession removes a session's CID mapping at destroy — called from the destroy
// post-destroy hook (which has the session UUID, not the CID). After this a connection
// from that (now-defunct) CID fails closed. Best-effort: an unknown session is a no-op.
// CIDs are never recycled (alloc.go derives from a never-recycled monotonic index), so
// this is belt-and-suspenders, but it keeps the resolvable set tight: only LIVE
// sessions resolve.
func (r *sessionCIDRegistry) UnbindSession(sessionUUID string) {
	if sessionUUID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cid, ok := r.bySession[sessionUUID]; ok {
		delete(r.byCID, cid)
		delete(r.bySession, sessionUUID)
	}
}

// Lookup resolves a connecting guest's peer CID to its session UUID (the cidResolver
// the shim authorizes with). ok=false when no LIVE session is bound to the CID — the
// fail-closed case.
func (r *sessionCIDRegistry) Lookup(cid uint32) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byCID[cid]
	return s, ok
}

// ── gate-aware token source selection ─────────────────────────────────────────

// newGatedSessionTokenSource selects the token source the SAME way the rest of the
// composition root gates (newGatedCAInjector / the booter / overlay store): under
// DS_HOSTAGENT_LIVE it returns a liveMintTokenSource that lazily dials the
// identity.v1 IdentityMintServiceClient at mintAddr (an address is a host-bring-up
// fact); off the gate (the default / only sandbox-CI path) it returns an
// offlineTokenSource that serves a fixed NON-SECRET placeholder (D50). The mint dial
// is lazy (inside TokenFor) so building the source never reaches the network — a
// mint outage at boot never unwinds the daemon.
func newGatedSessionTokenSource(mintAddr string) tokenSource {
	if libvirt.LiveEnabled() {
		return &liveMintTokenSource{mintAddr: mintAddr}
	}
	return offlineTokenSource{}
}

// offlinePlaceholderToken is the fixed, NON-SECRET marker the offline source serves
// (D50). It is CLEARLY a placeholder, never a real token, and it carries no usable
// credential material — the ds-tlsproxy D22 Validate seam would REJECT it. The
// offline daemon serves it so the boot-time fetch has a deterministic, non-error body
// to exercise the serving path; the live path serves a real token instead.
const offlinePlaceholderToken = "DS-OFFLINE-PLACEHOLDER-SESSION-TOKEN-NOT-A-REAL-D22-TOKEN"

// offlineTokenSource is the D50 offline/no-op token source: it returns the fixed
// non-secret placeholder for any session, never an error (so the daemon serves
// offline) and never a real token. expiryUnix is 0 (no real expiry on a placeholder).
type offlineTokenSource struct{}

func (offlineTokenSource) TokenFor(_ context.Context, _ string) ([]byte, int64, error) {
	return []byte(offlinePlaceholderToken), 0, nil
}

// ── live mint-backed source (wired to the promoted MintSessionToken RPC) ───────

// mintClient is the clearly-marked seam the live token source calls: the ONE
// generated-client method it needs. It is satisfied by the GENERATED identity.v1
// IdentityMintServiceClient (NewIdentityMintServiceClient) — proto/gen/go ONLY,
// never an identity/mint import (the D80 OSS/paid fence). Carrying it as a narrow
// interface keeps the dial seam injectable in tests (a canned MintSessionToken
// responder) without standing up a real grpc dial.
type mintClient interface {
	MintSessionToken(ctx context.Context, in *identityv1.MintSessionTokenRequest, opts ...grpc.CallOption) (*identityv1.MintSessionTokenResponse, error)
}

// liveMintTokenSource is the live token source. Under DS_HOSTAGENT_LIVE it lazily
// dials the identity.v1 IdentityMintServiceClient at mintAddr and calls the promoted
// MintSessionToken RPC (D111/D99/D97), returning the real short-lived D22 token bytes
// + expiry. The dial is lazy (inside TokenFor) so a mint outage at boot never unwinds
// the daemon — a failed dial / mint error fails CLOSED (the vsock accept loop closes
// the conn with no bytes), never a placeholder-as-real-token.
type liveMintTokenSource struct {
	mintAddr string
	// newClient builds the mintClient over a dialed conn. Nil in production (the dial
	// path below is used); a test injects a fake here to exercise TokenFor without a
	// real grpc dial (the existing fakeTokenSource mock style, approach (a)).
	newClient func(conn grpc.ClientConnInterface) mintClient
}

// TokenFor lazily dials the mint and mints the session token via the promoted
// MintSessionToken RPC. The dial is lazy (here, not at construction) so a mint outage
// never crashes the daemon at boot — a failed dial / mint error fails CLOSED (the
// vsock accept loop closes the conn with no bytes), and a booted session is never
// unwound by it.
//
// The U5 seam only has the sessionUUID (the vsock accept loop derives it from the
// unforgeable peer CID), so the request carries session_uuid and lets the mint resolve
// the rest shim-side (launching_user via its PrincipalResolver, defaults for
// org/repo/services/ttl) — flagged for seam-owner confirmation (the richer request
// fields are not available here).
func (l *liveMintTokenSource) TokenFor(ctx context.Context, sessionUUID string) ([]byte, int64, error) {
	if l.mintAddr == "" {
		// No mint endpoint configured ⇒ the live source cannot mint. Fail closed (D17):
		// the live shim must never serve a placeholder as if it were a real token.
		return nil, 0, fmt.Errorf("live session-token source: no -identity-mint-addr configured (fail-closed, D17)")
	}
	// Dial the identity.v1 mint as a gRPC CLIENT — NEVER import identity/mint (the
	// OSS/paid fence, CI-enforced). grpc.NewClient does not block on connect; the
	// address is a host-bring-up fact. The connection is closed when this call
	// returns (a per-boot one-shot mint; a long-lived pool is a later refinement).
	conn, err := grpc.NewClient(l.mintAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, 0, fmt.Errorf("live session-token source: dial identity mint %s: %w", l.mintAddr, err)
	}
	defer func() { _ = conn.Close() }()

	// The generated identity.v1 mint client (proto/gen/go only); a test may inject a
	// fake via newClient to exercise this path without a real dial.
	var client mintClient
	if l.newClient != nil {
		client = l.newClient(conn)
	} else {
		client = identityv1.NewIdentityMintServiceClient(conn)
	}

	resp, err := client.MintSessionToken(ctx, &identityv1.MintSessionTokenRequest{SessionUuid: sessionUUID})
	if err != nil {
		return nil, 0, fmt.Errorf("live session-token source: mint %s: %w", l.mintAddr, err)
	}
	return resp.GetToken(), resp.GetExpiryUnixSeconds(), nil
}
