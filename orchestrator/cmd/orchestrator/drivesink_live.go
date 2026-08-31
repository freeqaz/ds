// SPDX-License-Identifier: Apache-2.0

package main

// drivesink_live.go supplies the production adapter main.go's liveDeps wires onto the W3
// host-agent relay seam (controlplane.DriveSink, declared narrow in
// internal/controlplane/writerrelay.go because the orchestrator may not import the
// host-agent runtime module directly — the only legal cross-tree import is proto/gen/go,
// enforced by the .github/workflows/go.yml import-boundary gate). It is the WRITE-LEG twin
// of the W2 writer-seat auth adapters (writerauth_live.go): constructed ONLY under
// DS_ORCH_LIVE=1 (a non-live run never resolves liveDeps, D50), fail-CLOSED when its
// backing is absent (a nil seam leaves DriveSession refusing Unavailable — no relay ⇒ an
// admitted frame is never silently dropped), and exercised OFFLINE by unit tests over a
// synthetic host-agent endpoint (D50: no live VM/host-agent in CI).
//
// WHAT THIS CLOSES. W3 landed the offline DriveSink seam + the full DriveSession
// validate→forward→emit→ack logic, but main.go left the live adapter nil (DriveSession
// refuses Unavailable, fail-closed). This is the missing OUTBOUND host-agent client for the
// write leg: it forwards an ADMITTED DriveInput onto the host-agent's per-session bridge —
// the symmetric twin of the host-ward READ leg (attachrelay.go feeds the Fanout from
// heartbeats; this carries an admitted write frame host-ward to Claude Code's stdin via the
// host-agent bridge's Bridge.DriveInput → writeRecord under stdinMu). The orchestrator is
// the SINGLE choke point: the SeatArbiter admits the frame for the live seat-holder, then
// this seam carries ONLY that admitted frame (the relay originates no input of its own — the
// confused-deputy mitigation, sessions/10 §5 claim 5).
//
// WHY A HAND-ROLLED WIRE, NOT AN IMPORT OF client/hostbridge. The host-agent bridge's
// framed-UDS carrier lives in client/hostbridge (a SEPARATE Go module / tree). The
// orchestrator may not import it (the import-boundary gate forbids any cross-tree Go import
// but proto/gen/go), so — exactly as the ds-nft ingest client (internal/hostagent/
// nftfeed_client.go), the revocation-delta producer, and the WatchPolicies carrier all do —
// this leg speaks the bridge's DOCUMENTED framed-UDS wire contract directly with a
// hand-rolled, stdlib-only codec (the SAME no-shared-crate, no-FFI discipline, D40/D67). That
// shared wire — the frame codec, the attach-handshake handle, the reject mapping, and the
// wire string/number space — is single-sourced in wire.go (this leg and the READ leg
// contentsource_live.go both speak it); this file adds ONLY the write-leg specifics: the
// endpoint resolver, the per-session writer connection, and the admitted-frame → frameInput
// forward. The wire.go header documents the frame contract in full.
//
// NEVER-LOG-THE-SECRET (D73): nothing here logs the DriveInput payload or the attach token;
// the bytes cross the wire opaquely and every error names only the session + the structural
// fault. The live e2e (a real host-agent bridge terminating a real CC session) is
// operator-gated — the unit tests validate this producer against a synthetic endpoint; the
// remaining live-validation steps are recorded as a taskdb note.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// The shared framed-UDS wire contract this leg speaks — bridgeFrameType/bridgeRejectCode +
// their consts, bridgeMaxFrameBytes, bridgeTransportUnix, bridgeRoleWriter/bridgeRoleReader,
// wireAttachHandle/wireEndpointCandidate/wireAuthMaterial, wireDriveInput, the frame codec
// (writeBridgeFrame/readBridgeFrame/readFull), and rejectError — lives in wire.go (single
// source, mirrored by the READ leg too). This file uses those symbols; it defines only the
// write-leg-specific endpoint resolver + sink below.

// --- the endpoint resolver seam (where to dial + the session-scoped attach auth) ---

// driveRelayEndpoint is the resolved host-local relay endpoint for a session: the framed-UDS
// address the host-agent bridge serves the per-session write leg on, the short-lived
// session-scoped attach token (D39) the bridge validates the attach against, and the token's
// expiry (the handle's hard expiry — a stale handle cannot attach even with the right token).
type driveRelayEndpoint struct {
	address   string
	token     []byte
	expiresAt time.Time
}

// driveEndpointResolver resolves a session UUID to its host-local relay endpoint. It is a
// NARROW seam this package declares so the sink is offline-testable: the production adapter
// (overlayDriveEndpointResolver) renders the per-session UDS path + reads the host-agent's
// per-session attach-token store; a test supplies a fake. ok=false is a clean fail-closed
// refusal (no persisted token / no servable endpoint — the session was never attach-
// provisioned); a non-nil err is a transient store fault.
type driveEndpointResolver interface {
	ResolveRelayEndpoint(ctx context.Context, sessionUUID string) (ep driveRelayEndpoint, ok bool, err error)
}

// overlayDriveEndpointResolver is the production driveEndpointResolver for the single-box
// MVP. It renders the deterministic per-session UDS path under the host's attach socket dir
// (the SAME keying the host-agent AttachBridge serves under and the orchestrator's DIRECT
// endpoint resolver advertises — controlplane/attachendpoint.go, hostagent/attachbridge.go)
// and reads the session-scoped attach token from the host-side fileAttachTokenStore under
// the overlay dir (the SAME store the W2 attach-auth validator validates against and the
// libvirt IssueAttachHandle minter issues from). So the write leg dials exactly the socket
// the host-agent bridge binds and presents exactly the token the bridge validates.
//
// It reads through the store's READ-ONLY libvirt.AttachTokenPeeker (TokenPeek), NOT
// TokenFor: a resolve for a session the host-agent never issued a handle for (or whose
// token expired) is a clean fail-closed miss that mints/rewrites NOTHING — the SAME
// anti-spray + no-re-mint posture as the W2 attach-auth validator, with no os.Stat pre-gate
// (TokenPeek is already read-only, so an unknown/expired session cannot become a disk write).
type overlayDriveEndpointResolver struct {
	socketDir string
	peek      libvirt.AttachTokenPeeker
}

// newOverlayDriveEndpointResolver builds the production resolver over the host overlay dir
// (the token store home) and the attach socket dir (where the bridge serves). An empty
// socketDir falls back to the SAME default the host-agent AttachBridge + the DIRECT resolver
// use (hostagent.DefaultAttachSocketDir), so the three sides cannot drift to different dirs.
// An empty overlayDir is a caller error (liveDeps only calls this inside the overlay block).
func newOverlayDriveEndpointResolver(overlayDir, socketDir string) (*overlayDriveEndpointResolver, error) {
	if overlayDir == "" {
		return nil, fmt.Errorf("writer drive sink: empty overlay dir (no attach-token store to authenticate the relay attach)")
	}
	if socketDir == "" {
		socketDir = hostagent.DefaultAttachSocketDir
	}
	store, err := libvirt.NewFileAttachTokenStore(overlayDir, 0)
	if err != nil {
		return nil, fmt.Errorf("writer drive sink: %w", err)
	}
	// The store is read through its READ-ONLY peeker: a resolve for an unknown or expired
	// session is a clean fail-closed miss that mints/rewrites NOTHING (no os.Stat pre-gate
	// needed — TokenPeek never writes).
	return &overlayDriveEndpointResolver{socketDir: socketDir, peek: store}, nil
}

// ResolveRelayEndpoint renders the session's relay UDS address and reads its attach token.
// A session with no persisted token is a clean fail-closed refusal (ok=false — the host-
// agent never issued a handle for it, so there is nothing to drive). A store fault is a
// transient err. On success it returns the address + the live token + its expiry.
func (r *overlayDriveEndpointResolver) ResolveRelayEndpoint(ctx context.Context, sessionUUID string) (driveRelayEndpoint, bool, error) {
	if r == nil || r.peek == nil || sessionUUID == "" {
		return driveRelayEndpoint{}, false, nil
	}
	// Read-only peek: no live persisted token (an unknown session, or an expired one) ⇒ a
	// clean fail-closed miss that mints/rewrites NOTHING. TokenPeek never touches disk on a
	// miss, so a resolve cannot fabricate a file for a session the host-agent never issued a
	// handle for, nor re-mint an expired one.
	token, expiresAt, ok, err := r.peek.TokenPeek(ctx, sessionUUID)
	if err != nil {
		return driveRelayEndpoint{}, false, fmt.Errorf("writer drive sink: resolve attach token for session %q: %w", sessionUUID, err)
	}
	if !ok || len(token) == 0 {
		return driveRelayEndpoint{}, false, nil
	}
	return driveRelayEndpoint{
		address:   relaySocketPath(r.socketDir, sessionUUID),
		token:     token,
		expiresAt: expiresAt,
	}, true, nil
}

// relaySocketPath renders the deterministic host-local UDS path for a session: a per-session
// socket under the host's attach socket dir, keyed on the SANITIZED session UUID. It mirrors
// hostagent.AttachBridge.socketPathFor / controlplane.sessionEndpointResolver.socketPathFor
// (filepath.Join(dir, sanitize(uuid)+".sock")) so the write leg dials exactly the socket the
// host-agent serves and the DIRECT resolver advertises — one shared path, minted there,
// dialed here. The UUID is sanitized to a single safe path component so a crafted UUID can
// never escape the socket dir (defense in depth; session UUIDs are orchestrator-minted).
func relaySocketPath(socketDir, sessionUUID string) string {
	return filepath.Join(socketDir, sanitizeRelaySocketComponent(sessionUUID)+".sock")
}

// sanitizeRelaySocketComponent reduces a session UUID to a single safe path component,
// byte-for-byte mirroring hostagent.sanitizeAttachComponent /
// controlplane.sanitizeSocketComponent (the two sides the rendered path must agree with).
// Any path separator or traversal byte becomes '_'; an empty result is "_".
func sanitizeRelaySocketComponent(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '-' || c == '_' || c == '.':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "_"
	}
	return string(out)
}

// --- the live DriveSink ---

// defaultRelayDialTimeout bounds the live host-local UDS connect so a wedged / absent
// host-agent bridge listener never hangs the write leg indefinitely. A healthy host-local
// UDS connects in microseconds; a few seconds is a generous ceiling that still refuses the
// drive promptly (fail-closed — the frame is refused in-band and the driver can retry) when
// the listener is down.
const defaultRelayDialTimeout = 3 * time.Second

// defaultRelayHandshakeTimeout bounds the attach handshake (frameAttach → frameAccept/
// frameReject). The host-agent bridge resolves a structured attach after a short server-side
// mode-peek (client/hostbridge peekMode, ~250ms), so the accept lands well within this
// window; a wedged server is refused rather than hanging the write leg.
const defaultRelayHandshakeTimeout = 5 * time.Second

// relayWriteTimeout bounds ONE frameInput write onto the relay so a wedged host-agent bridge
// (a server that stopped reading, filling the socket buffer) cannot stall the write leg
// forever — a stalled write would hang DriveSession's single-goroutine frame loop. It is a
// WRITE-only deadline (SetWriteDeadline), so it never disturbs the drain goroutine's
// deadline-free reads on the same connection. A write that trips it flags the connection dead
// (a partial frame corrupts it) and the next admitted frame re-dials — fail-closed.
const relayWriteTimeout = 5 * time.Second

// hostAgentDriveSink is the production controlplane.DriveSink: it forwards an ADMITTED
// DriveInput onto the host-agent's per-session bridge over the framed-UDS RELAY carrier. It
// holds ONE writer connection per session (dialed + attached lazily on the first Drive for a
// session, reused for every subsequent frame — a fresh attach per frame would re-take the
// D61 writer seat on every keystroke and churn the host-agent bridge), keyed by the session
// UUID the arbiter resolved (never a wire-supplied session). A per-session connection is
// re-dialed after a transport fault or a server-initiated close: the drain goroutine flags it
// dead and EAGERLY evicts it from the cache (markDead → onDead → evict), so a torn relay
// leaves no lingering entry and recovers on the next admitted frame.
type hostAgentDriveSink struct {
	resolve driveEndpointResolver
	// dial connects the host-local relay UDS. Injectable so a test can exercise dial faults;
	// the production default is a UDS net.Dialer bounded by defaultRelayDialTimeout.
	dial func(ctx context.Context, address string) (net.Conn, error)
	// handshakeTimeout bounds the attach handshake; 0 ⇒ defaultRelayHandshakeTimeout.
	handshakeTimeout time.Duration

	mu     sync.Mutex
	conns  map[string]*relayWriterConn // session UUID → cached live writer conn
	closed bool
}

// newHostAgentDriveSink builds the live sink over the endpoint resolver. A nil resolver is a
// wiring bug rejected at construction (fail-closed: a sink that cannot resolve where to dial
// could never forward a frame). The production dialer is installed here; a test overrides it
// after construction.
func newHostAgentDriveSink(resolve driveEndpointResolver) (*hostAgentDriveSink, error) {
	if resolve == nil {
		return nil, fmt.Errorf("writer drive sink: nil endpoint resolver (no way to resolve the relay endpoint)")
	}
	return &hostAgentDriveSink{
		resolve: resolve,
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: defaultRelayDialTimeout}
			return d.DialContext(ctx, "unix", address)
		},
		conns: make(map[string]*relayWriterConn),
	}, nil
}

// Drive forwards an admitted DriveInput for sessionUUID to Claude Code's stdin via the host-
// agent relay (the controlplane.DriveSink contract). It maps the admitted frame to the
// bridge's write-side shape, gets-or-dials the per-session writer connection, and pushes ONE
// frameInput. It returns nil once the frame is on the wire to the host-agent bridge (whose
// Bridge.DriveInput → writeRecord lands it on CC stdin under stdinMu); a non-nil err is a
// resolve/dial/attach/transport fault the DriveSession handler surfaces (an input that did
// not reach the relay is refused in-band and emits NO InputActivity — an input CC never
// received is not projected as activity).
func (s *hostAgentDriveSink) Drive(ctx context.Context, sessionUUID string, in *attachv1.DriveInput) error {
	if sessionUUID == "" {
		return fmt.Errorf("writer drive sink: Drive with empty session uuid")
	}
	// Map the admitted proto frame to the bridge's write-side shape BEFORE any dial, so a
	// non-forwardable frame fails without touching a socket. The M0 write leg forwards TEXT
	// blocks (the only shape the host-agent bridge's Driver.EncodeInput drives onto CC
	// stdin); tool_result / image / multi_block are a deferred capability (recorded in the
	// taskdb note) and are refused fail-closed rather than mis-encoded as text.
	payload, err := writeLegPayload(in)
	if err != nil {
		return err
	}

	conn, err := s.connFor(ctx, sessionUUID)
	if err != nil {
		return err
	}
	if err := conn.writeInput(payload); err != nil {
		// A transport fault on a cached connection: evict + close it so the NEXT admitted
		// frame re-dials a fresh relay (a torn write leg recovers on retry). writeInput's
		// markDead already fired onDead → evict; this explicit evict is the idempotent
		// belt-and-suspenders (and covers a conn with no onDead). The frame is refused
		// (surfaced to DriveSession) — never silently dropped.
		s.evict(sessionUUID, conn)
		return err
	}
	return nil
}

// connFor returns the live per-session writer connection, dialing + attaching a fresh one
// when there is no cached connection or the cached one has been flagged dead (a server-
// initiated close or a prior transport fault). The dial + handshake run WITHOUT the map lock
// held (a ~250ms handshake must not block other sessions' Drives); the resolved connection is
// stored under the lock. A same-session Drive is serial (one DriveSession stream per
// session), so this never races itself; different sessions key disjoint entries.
func (s *hostAgentDriveSink) connFor(ctx context.Context, sessionUUID string) (*relayWriterConn, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("writer drive sink: closed")
	}
	if c := s.conns[sessionUUID]; c != nil && !c.isDead() {
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()

	ep, ok, err := s.resolve.ResolveRelayEndpoint(ctx, sessionUUID)
	if err != nil {
		return nil, err
	}
	if !ok {
		// Fail-closed: no servable relay endpoint / no session-scoped attach token — the
		// session was never attach-provisioned, so there is nothing to drive.
		return nil, fmt.Errorf("writer drive sink: no relay endpoint for session %q (no persisted attach token — fail-closed)", sessionUUID)
	}

	conn, err := s.dialAttach(ctx, sessionUUID, ep)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.close()
		return nil, fmt.Errorf("writer drive sink: closed")
	}
	// Double-check: if a live connection was cached while we dialed (cannot happen for a
	// serial same-session stream, but handled for safety), keep the existing one and drop
	// ours. Otherwise install ours (evicting any dead placeholder).
	if existing := s.conns[sessionUUID]; existing != nil && !existing.isDead() {
		s.mu.Unlock()
		conn.close()
		return existing, nil
	}
	s.conns[sessionUUID] = conn
	s.mu.Unlock()
	return conn, nil
}

// dialAttach dials the relay UDS and performs the writer-seat attach handshake: it presents a
// WRITER AttachHandle (the resolved address + the session-scoped token) and awaits
// frameAccept / frameReject. On accept it launches the drain goroutine (which discards the
// server's frameEvent stream — the orchestrator's read projection is the heartbeat relay, not
// this leg — and flags the connection dead on frameEnd/EOF) and returns the live connection.
// A reject maps back to a readable cause; a dial/handshake fault is surfaced.
func (s *hostAgentDriveSink) dialAttach(ctx context.Context, sessionUUID string, ep driveRelayEndpoint) (*relayWriterConn, error) {
	raw, err := s.dial(ctx, ep.address)
	if err != nil {
		return nil, fmt.Errorf("writer drive sink: dial relay %q for session %q: %w", ep.address, sessionUUID, err)
	}

	handle := wireAttachHandle{
		SessionUUID: sessionUUID,
		Endpoints:   []wireEndpointCandidate{{Transport: bridgeTransportUnix, Address: ep.address}},
		Auth:        wireAuthMaterial{Token: string(ep.token)},
		Role:        bridgeRoleWriter,
		ExpiresAt:   ep.expiresAt,
	}
	hjson, err := json.Marshal(handle)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("writer drive sink: marshal attach handle for session %q: %w", sessionUUID, err)
	}

	// Bound the handshake so a wedged server never hangs the write leg; the deadline is
	// cleared before the drain reads with no deadline.
	hsTimeout := s.handshakeTimeout
	if hsTimeout <= 0 {
		hsTimeout = defaultRelayHandshakeTimeout
	}
	_ = raw.SetDeadline(time.Now().Add(hsTimeout))

	bw := bufio.NewWriter(raw)
	br := bufio.NewReader(raw)
	if err := writeBridgeFrame(bw, bridgeFrameAttach, hjson); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("writer drive sink: send attach for session %q: %w", sessionUUID, err)
	}
	ft, replyPayload, err := readBridgeFrame(br)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("writer drive sink: read attach reply for session %q: %w", sessionUUID, err)
	}
	switch ft {
	case bridgeFrameAccept:
		_ = raw.SetDeadline(time.Time{}) // clear: the drain reads with no deadline
		c := &relayWriterConn{raw: raw, bw: bw, br: br}
		// Evict eagerly: the instant this conn dies (drain EOF/frameEnd/fault or a write
		// fault), drop it from the per-session cache so a stale dead entry never lingers.
		// evict is a no-op unless c is still the cached conn, so the pre-cache window (drain
		// racing the connFor store below) is safe.
		c.onDead = func() { s.evict(sessionUUID, c) }
		go c.drain()
		return c, nil
	case bridgeFrameReject:
		_ = raw.Close()
		return nil, rejectError(sessionUUID, replyPayload)
	default:
		_ = raw.Close()
		return nil, fmt.Errorf("writer drive sink: unexpected attach reply frame %d for session %q", ft, sessionUUID)
	}
}

// evict removes conn from the per-session cache (only when it is still the cached one — a
// re-dial may already have replaced it) and closes it. Idempotent.
func (s *hostAgentDriveSink) evict(sessionUUID string, conn *relayWriterConn) {
	s.mu.Lock()
	if s.conns[sessionUUID] == conn {
		delete(s.conns, sessionUUID)
	}
	s.mu.Unlock()
	conn.close()
}

// Close tears down every cached per-session writer connection (the liveDeps closer-chain
// leg). Idempotent; after Close a Drive refuses fail-closed rather than dialing a new relay.
func (s *hostAgentDriveSink) Close() error {
	s.mu.Lock()
	s.closed = true
	conns := s.conns
	s.conns = make(map[string]*relayWriterConn)
	s.mu.Unlock()
	for _, c := range conns {
		c.close()
	}
	return nil
}

var _ controlplane.DriveSink = (*hostAgentDriveSink)(nil)

// relayWriterConn is one live writer attachment to a host-agent bridge: the raw UDS conn, the
// buffered writer frameInput frames go out on (serialized by writeMu so two frames never
// interleave), and a drain goroutine that consumes the server's frameEvent stream and flags
// the connection dead on frameEnd / EOF / fault. A dead connection is re-dialed by connFor;
// the first transition to dead ALSO fires onDead so the sink evicts it from the per-session
// cache eagerly (the drain goroutine / a faulting write drops the entry the instant the relay
// dies, rather than leaving it to linger until the next Drive or Close).
type relayWriterConn struct {
	raw net.Conn
	bw  *bufio.Writer
	br  *bufio.Reader

	writeMu   sync.Mutex
	dead      atomic.Bool
	closeOnce sync.Once
	// onDead fires exactly once, on the connection's first transition to dead (drain EOF /
	// frameEnd / read fault, or a write fault). The sink installs it in dialAttach to evict
	// this conn from its per-session cache. It runs WITHOUT any conn or sink lock held (see
	// markDead), so it may safely take the sink's map lock. nil for a conn never cached (e.g.
	// a test-constructed conn), so markDead stays valid without a sink.
	onDead func()
}

// writeInput frames a wireDriveInput as frameInput and writes it under writeMu. A dead
// connection (a prior fault or a server-initiated close the drain observed) refuses BEFORE
// the wire so the caller re-dials. A write fault flags the connection dead (the next Drive
// re-dials).
func (c *relayWriterConn) writeInput(payload wireDriveInput) error {
	if c.dead.Load() {
		return fmt.Errorf("writer drive sink: relay connection is closed")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("writer drive sink: marshal drive input: %w", err)
	}
	c.writeMu.Lock()
	// Write-only deadline: bound this frame so a wedged server cannot stall the write leg,
	// without touching the drain goroutine's deadline-free reads on the same conn. Cleared
	// after the write so a later write re-arms its own bound.
	_ = c.raw.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
	err = writeBridgeFrame(c.bw, bridgeFrameInput, body)
	_ = c.raw.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if err != nil {
		c.markDead()
		return fmt.Errorf("writer drive sink: write drive input: %w", err)
	}
	return nil
}

// drain consumes the server→client frames (frameEvent, drained + discarded — the read
// projection is the heartbeat relay, not this write leg) so the host-agent bridge's per-conn
// outbox never wedges on a full socket buffer, and flags the connection dead on frameEnd, a
// clean EOF, or a read fault. markDead's onDead callback then EVICTS the dead conn from the
// sink cache immediately (so a torn relay leaves no lingering entry; connFor re-dials a fresh
// one on the next admitted frame). It exits when the connection is closed (close() wakes a
// blocked readFrame).
func (c *relayWriterConn) drain() {
	for {
		ft, _, err := readBridgeFrame(c.br)
		if err != nil {
			c.markDead()
			return
		}
		if ft == bridgeFrameEnd {
			c.markDead()
			return
		}
		// Any other frame (frameEvent, a resume reply, ...) is discarded: this leg only
		// writes; the read projection rides the heartbeat relay (attachrelay.go).
	}
}

// markDead flags the connection dead and closes it once (waking a blocked drain read and
// refusing further writes), then fires onDead so the sink evicts it from the per-session
// cache. Idempotent: the atomic swap gates the close + the onDead callback to the FIRST
// caller, so concurrent drain/writeInput deaths run the eviction exactly once. onDead runs
// with no lock held (the map lock it takes is never held across a markDead call).
func (c *relayWriterConn) markDead() {
	if c.dead.Swap(true) {
		return // already dead — close + eviction already ran for this conn
	}
	c.close()
	if c.onDead != nil {
		c.onDead()
	}
}

// isDead reports whether the connection has been flagged dead (a fault or a server close).
func (c *relayWriterConn) isDead() bool { return c.dead.Load() }

// close closes the underlying UDS conn once (idempotent). It does NOT set dead directly —
// markDead is the flag path — but a closed conn's next read/write faults, so drain/writeInput
// converge on dead regardless.
func (c *relayWriterConn) close() {
	c.closeOnce.Do(func() { _ = c.raw.Close() })
}

// writeLegPayload maps an admitted proto DriveInput onto the host-agent bridge's write-side
// shape. The M0 write leg forwards TEXT blocks only — the single shape the bridge's
// Driver.EncodeInput drives onto CC stdin (its DriveInput carries just `text`). The payload
// bytes ARE the text body (attach.v1 DriveInput.payload is the input body, carried only on
// the write leg). A nil input, a non-TEXT kind, or an empty payload is refused fail-closed
// (an empty text is a caller error the Driver would reject anyway; a non-text kind is a
// deferred capability, not silently mis-encoded as text).
func writeLegPayload(in *attachv1.DriveInput) (wireDriveInput, error) {
	if in == nil {
		return wireDriveInput{}, fmt.Errorf("writer drive sink: nil drive input")
	}
	if in.GetKind() != attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT {
		return wireDriveInput{}, fmt.Errorf("writer drive sink: unsupported drive block kind %v (the M0 write leg forwards TEXT blocks only; tool_result/image/multi_block are a deferred capability)", in.GetKind())
	}
	if len(in.GetPayload()) == 0 {
		return wireDriveInput{}, fmt.Errorf("writer drive sink: empty text payload")
	}
	return wireDriveInput{Text: string(in.GetPayload())}, nil
}

// resolveWriterDriveSink resolves the W3 host-agent relay seam (Deps.WriterDriveSink) from
// the environment gates — the offline-testable slice of liveDeps' wiring (the twin of
// resolveWriterIdentityValidator, writerauth_live.go). getenv is injected (os.Getenv in main,
// a map lookup in tests). It gates on DS_ORCH_OVERLAY_DIR (the host-agent's per-session
// attach-token store home the relay attach authenticates against): UNSET ⇒ a NIL sink and a
// no-op closer (DriveSession refuses Unavailable fail-closed — no relay configured), so a
// deployment without the co-located host overlay dir never grants a write leg. SET ⇒ the live
// sink over the overlay token store + the attach socket dir (DS_ORCH_ATTACH_SOCKET_DIR, or
// the shared default), plus its Close for the closer chain. A construction fault (an
// unreadable token store) is a loud error (a live run that MEANT to wire the write leg must
// not degrade silently).
func resolveWriterDriveSink(getenv func(string) string) (controlplane.DriveSink, func() error, error) {
	overlayDir := getenv("DS_ORCH_OVERLAY_DIR")
	if overlayDir == "" {
		// A typed-nil pointer must never leave here inside the interface (it would defeat the
		// handler's `drive == nil` fail-closed check), so the gate-off arm returns the untyped
		// nil interface value directly, with a no-op closer.
		return nil, func() error { return nil }, nil
	}
	resolver, err := newOverlayDriveEndpointResolver(overlayDir, getenv("DS_ORCH_ATTACH_SOCKET_DIR"))
	if err != nil {
		return nil, func() error { return nil }, err
	}
	sink, err := newHostAgentDriveSink(resolver)
	if err != nil {
		return nil, func() error { return nil }, err
	}
	return sink, sink.Close, nil
}
