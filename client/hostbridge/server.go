// server.go — the WatchSession terminator: the SERVER half of the D61
// one-writer/N-reader seam (docs/15 §5.3-5.4; attach.v1 freeze checklist row 2).
//
// The client-side arbitration already exists in the TUI (01KTWJ23Q0); this is the
// server half that the freeze row mandates be enforced "server-side at the
// WatchSession terminator." The writer seat lives in the session record (here,
// the per-session Server state — docs/15 §5.4: "the writer seat lives in the
// session record"), NOT on the handle:
//
//   - the FIRST WRITER attach takes the seat; a SECOND WRITER attach is REJECTED
//     (ErrWriterSeatTaken) — never silently demoted, the client must learn the
//     seat is taken;
//   - N READER attaches all succeed and receive the event stream, but any write
//     from a READER is REFUSED (ErrReaderCannotWrite);
//   - the seat is released when the writer detaches, so a later WRITER can take
//     it (driver handoff = a record mutation, docs/15 §5.4).
//
// The Server also enforces handle validity at attach (handle.go): AuthMaterial
// must match what it minted for the session, and ExpiresAt must be in the future
// — an expired or wrong-token handle is rejected before any seat is granted.
package hostbridge

import (
	"crypto/subtle"
	"sync"
	"time"
)

// Session is the per-session server record. It owns the bridge (the CC ⇄ adapter
// /driver pump) and the writer-seat arbitration state. One Session per wrapped CC
// process. It is the authoritative writer-seat home (docs/15 §5.4): the seat is a
// field here, mutated under mu, never a property of an issued handle.
type Session struct {
	uuid   string
	bridge *Bridge

	// authToken is the AuthMaterial.Token the Server minted for this session;
	// every attach is checked against it in constant time. Session-scoped: a
	// token for session A is useless against session B (HARDENING-NOTES §1.2).
	authToken string

	mu sync.Mutex
	// writerHeld is true while a WRITER attachment holds the one seat. A second
	// WRITER attach while held is rejected (ErrWriterSeatTaken).
	writerHeld bool

	// terminal is the optional raw-pty carriage for TERMINAL-mode attaches
	// (serpent claude --vm). It is the guest pty's byte duplex + winsize sink/
	// source (docs/serpent-cli-mvp/01 §2.6) — nil for a structured-only session,
	// so a terminal attach against a session with no carriage is a clean internal
	// reject rather than a wedge. The host-agent serving leg (PR-3) supplies the
	// real one; tests supply a fake. Guarded by mu (set once at registration).
	terminal TerminalCarriage
}

// Bridge exposes the session's bridge so a caller can Subscribe or run Pump. The
// Server's Attach is the gated path that returns an Attachment; this accessor is
// for the bridge operator (the binary) that owns the CC process lifecycle.
func (s *Session) Bridge() *Bridge { return s.bridge }

// UUID returns the session UUID.
func (s *Session) UUID() string { return s.uuid }

// TerminalCarriage is the server-side raw-pty carriage a TERMINAL-mode attach
// serves: the byte duplex + winsize toward the guest pty master (serpent claude
// --vm; docs/serpent-cli-mvp/01 §2.6). The serving leg pumps RawOut → the client
// (frameRawOut, BLOCKING — drops are unrecoverable, §2.4) and forwards the
// client's frameRawIn/frameResize → RawInput/Resize. It is supplied by the
// host-agent (the real guest-vsock-backed carriage) or a test fake; the wire layer
// (this unit) is carriage-agnostic — it only frames bytes in/out of it.
//
// One TERMINAL writer per session at this MVP (the writer seat already enforces
// it), so a carriage serves exactly one terminal attach at a time. Close is called
// when the serving leg unwinds (the client detached / the carriage EOF'd) so the
// guest-side leg can hang up the pty session (the in-guest SIGHUP path).
type TerminalCarriage interface {
	// RawOut yields opaque pty output chunks (the guest pty master's output). A
	// read returning io.EOF ends the terminal session (CC exited / pty closed);
	// the serving leg emits a frameEnd. Chunk boundaries are meaningless.
	RawOut() ([]byte, error)
	// RawInput delivers opaque keystroke bytes toward the guest pty master. It is
	// called once per client frameRawIn.
	RawInput(p []byte) error
	// Resize applies a winsize toward the guest pty (TIOCSWINSZ in-guest). Called
	// once per client frameResize.
	Resize(ws Winsize) error
	// Close releases the carriage (the guest-side hangup). It MUST unblock a
	// concurrently-blocked RawOut (returning io.EOF or an error) so the blocking
	// out-pump unwinds when the client closes — the standard io.Closer-on-a-
	// blocked-reader discipline. Idempotent.
	Close() error
}

// SetTerminalCarriage registers tc as this session's raw-pty carriage so a
// TERMINAL-mode attach (serpent claude --vm) can be served. A session with no
// carriage rejects a terminal attach as an internal error (the structured surface
// is unaffected — the land-dark invariant). Called by the host-agent serving leg
// once at session wiring; a test supplies a fake.
func (s *Session) SetTerminalCarriage(tc TerminalCarriage) {
	s.mu.Lock()
	s.terminal = tc
	s.mu.Unlock()
}

// terminalCarriage returns the session's registered terminal carriage (nil if
// none). Read under mu.
func (s *Session) terminalCarriage() TerminalCarriage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminal
}

// Server is the WatchSession terminator for one or more sessions. It mints and
// validates AttachHandles and enforces the D61 seat arbitration. A single Server
// can host multiple sessions (keyed by UUID); the M0 binary hosts exactly one.
type Server struct {
	mu       sync.Mutex
	sessions map[string]*Session
	// now is the clock for expiry checks and IssueHandle TTLs; overridable in
	// tests. Defaults to the package nowFunc (time.Now).
	now func() time.Time
	// mintToken produces a session's AuthMaterial token. Defaults to a
	// crypto/rand token; overridable in tests for determinism. The token is never
	// logged (HARDENING-NOTES §2.2).
	mintToken func() string
	// noAuth, when set, makes validate ACCEPT any presented AuthMaterial token (the
	// MVP no-auth posture: the attach token is fake/no-op, D-deferred real auth). It is
	// OFF by default so the fail-closed constant-time token check is the production
	// behavior; a serving leg opts in explicitly (DS_HOSTBRIDGE_NO_AUTH) when the
	// orchestrator-side issuer mints a token from a DIFFERENT source than this server's
	// store (the single-box MVP, where the attach credential is not yet single-sourced
	// across the orchestrator issuer + the host-agent token store). Every OTHER validity
	// check (session known, role, expiry, servable endpoint) still runs unchanged.
	noAuth bool

	// onInputActivity is the COUNT-ONLY input-activity sink (D78 attendedness "driver
	// typed"; docs/serpent-cli-mvp/10-build-decisions §A6). In TERMINAL mode the writer
	// stream is OPAQUE keystrokes the carriage must NEVER parse, so the serving leg fires
	// this hook payload-free, ONCE per inbound raw-input frame (frameRawIn), to keep the
	// attendedness signal working WITHOUT inspecting bytes. nil ⇒ no-op (the structured
	// path and any test that wires no observer are unaffected). A serving leg supplies a
	// real observer (WithInputActivityObserver); the count-only contract is enforced HERE
	// (the hook takes no argument), so a sink can never reach the keystroke bytes.
	onInputActivity func()
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithClock overrides the Server clock (handle expiry + IssueHandle TTL).
func WithClock(now func() time.Time) ServerOption {
	return func(s *Server) { s.now = now }
}

// WithTokenMinter overrides the AuthMaterial token source — deterministic tokens
// in tests. The minter must return a fresh, unguessable token per session in
// production.
func WithTokenMinter(mint func() string) ServerOption {
	return func(s *Server) { s.mintToken = mint }
}

// WithNoAuth makes the Server ACCEPT any presented attach token (the MVP no-auth
// posture — the attach token is fake/no-op). It is OFF by default; a serving leg
// opts in explicitly (the single-box MVP, where the orchestrator-side issuer mints
// the handle token from a different source than this server's token store, so a
// constant-time match would always fail). Every OTHER handle check still runs.
func WithNoAuth(noAuth bool) ServerOption {
	return func(s *Server) { s.noAuth = noAuth }
}

// WithInputActivityObserver registers the COUNT-ONLY input-activity sink the
// TERMINAL serving leg fires once per inbound raw-input frame (frameRawIn) so the
// D78 attendedness "driver typed" signal keeps working without parsing keystrokes
// (docs/serpent-cli-mvp/10-build-decisions §A6). The observer takes NO argument —
// the count-only contract is structural: a sink cannot reach the opaque keystroke
// bytes. nil (the default) is a no-op. A serving leg that wires a real observer gets
// a payload-free "the writer typed" tick per frame; the structured path never fires
// it (it has no raw-input frames).
func WithInputActivityObserver(observe func()) ServerOption {
	return func(s *Server) { s.onInputActivity = observe }
}

// noteInputActivity fires the count-only input-activity sink, if one is wired. It is
// the SOLE call site (the TERMINAL raw-in reader, serveTerminalDrive) so the
// payload-free contract holds at one place; a nil observer is a clean no-op.
func (s *Server) noteInputActivity() {
	if s.onInputActivity != nil {
		s.onInputActivity()
	}
}

// NewServer constructs a WatchSession terminator with no sessions. Register a
// session with AddSession before issuing handles for it.
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		sessions:  make(map[string]*Session),
		now:       nowFunc,
		mintToken: randomToken,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// AddSession registers a session: it mints the session's AuthMaterial token and
// records the bridge under sessionUUID. Returns the Session record. A subsequent
// IssueHandle for this UUID embeds the minted token; an attach with any other
// token is rejected (ErrAuthInvalid). Re-adding the same UUID replaces the prior
// record (idempotent re-create on the same session UUID, mirroring the driver's
// idempotent-on-session-UUID contract).
func (s *Server) AddSession(sessionUUID string, bridge *Bridge) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := &Session{
		uuid:      sessionUUID,
		bridge:    bridge,
		authToken: s.mintToken(),
	}
	s.sessions[sessionUUID] = sess
	return sess
}

// session looks up a registered session by UUID.
func (s *Server) session(uuid string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[uuid]
	return sess, ok
}

// IssueHandle mints an AttachHandle for a registered session: it stamps the
// session's AuthMaterial token, the single M0 direct endpoint (addressed by
// address), the requested role, and an expiry of now+ttl. This is the
// host-agent's "issue a handle" leg (docs/15 §4.1 step 10; the driver's
// IssueAttachHandle counterpart). Returns ErrUnknownSession if the UUID is not
// registered.
//
// Issuing a handle does NOT take the writer seat — the seat is taken at Attach
// (so an unused WRITER handle never starves the seat). A WRITER handle plus a
// not-yet-attached state means the seat is still free.
func (s *Server) IssueHandle(sessionUUID string, role Role, address string, ttl time.Duration) (AttachHandle, error) {
	return s.IssueHandleFor(sessionUUID, role, TransportDirect, address, ttl)
}

// IssueHandleFor is IssueHandle with an explicit endpoint transport: it mints a
// handle whose single M0 endpoint advertises the given transport (TransportDirect
// for the in-process loopback carrier, TransportUnix for the framed-UDS carrier
// the SocketTransport dials). Used by the socket transport's issuer to stamp a
// unix endpoint (address = the UDS path the client outside the process dials);
// IssueHandle is the TransportDirect convenience wrapper. The auth token, role,
// and expiry are minted identically — only the carrier the handle advertises
// differs (the transport-ambivalent D79 promise: same handle shape, different
// endpoint candidate).
func (s *Server) IssueHandleFor(sessionUUID string, role Role, transport EndpointTransport, address string, ttl time.Duration) (AttachHandle, error) {
	sess, ok := s.session(sessionUUID)
	if !ok {
		return AttachHandle{}, ErrUnknownSession
	}
	if !role.valid() {
		return AttachHandle{}, ErrHandleMalformed
	}
	return AttachHandle{
		SessionUUID: sessionUUID,
		Endpoints: []EndpointCandidate{
			{Transport: transport, Address: address},
		},
		Auth:      AuthMaterial{Token: sess.authToken},
		Role:      role,
		ExpiresAt: s.now().Add(ttl),
	}, nil
}

// Attachment is a granted attach: a live subscription plus, for a WRITER, the
// drive seat. Detach releases the subscription and (for a WRITER) the seat so a
// later WRITER can attach. A READER's write methods always refuse
// (ErrReaderCannotWrite); a WRITER's forward to the bridge.
type Attachment struct {
	server  *Server
	session *Session
	role    Role

	unsubscribe func()

	detachOnce sync.Once
}

// Role returns the attachment's role (WRITER or READER).
func (a *Attachment) Role() Role { return a.role }

// Attach validates handle and grants an attachment, subscribing sub to the
// session's event stream. Validation order (fail closed at the first failure):
//
//  1. handle structure (non-empty UUID, ≥1 endpoint, valid role) — ErrHandleMalformed;
//  2. known session — ErrUnknownSession;
//  3. AuthMaterial matches the session's minted token (constant-time) — ErrAuthInvalid;
//  4. ExpiresAt is in the future — ErrHandleExpired;
//  5. a servable M0 direct endpoint is present — ErrHandleMalformed;
//  6. for a WRITER, the seat is free — ErrWriterSeatTaken.
//
// On success the subscriber is registered for the WatchSession fan-out and (for a
// WRITER) the seat is held until Detach. This is the server-side enforcement the
// freeze row 2 mandates — arbitration lives here, at the terminator, not on the
// client.
func (s *Server) Attach(handle AttachHandle, sub Subscriber) (*Attachment, error) {
	if err := s.validate(handle); err != nil {
		return nil, err
	}
	sess, ok := s.session(handle.SessionUUID)
	if !ok {
		return nil, ErrUnknownSession
	}

	if handle.Role == RoleWriter {
		sess.mu.Lock()
		if sess.writerHeld {
			sess.mu.Unlock()
			return nil, ErrWriterSeatTaken
		}
		sess.writerHeld = true
		sess.mu.Unlock()
	}

	unsub := sess.bridge.Subscribe(sub)
	return &Attachment{
		server:      s,
		session:     sess,
		role:        handle.Role,
		unsubscribe: unsub,
	}, nil
}

// validate runs the handle-validity checks (structure, session, auth, expiry,
// servable endpoint) without touching the seat. Returns the first failure as the
// matching sentinel.
func (s *Server) validate(handle AttachHandle) error {
	if handle.SessionUUID == "" || len(handle.Endpoints) == 0 || !handle.Role.valid() {
		return ErrHandleMalformed
	}
	sess, ok := s.session(handle.SessionUUID)
	if !ok {
		return ErrUnknownSession
	}
	// Constant-time compare so a timing side channel cannot probe the token
	// (HARDENING-NOTES posture). An empty handle token fails here too. The MVP
	// no-auth posture (s.noAuth) SKIPS this single check — the attach token is
	// fake/no-op — while every other handle check above/below still runs.
	if !s.noAuth && subtle.ConstantTimeCompare([]byte(handle.Auth.Token), []byte(sess.authToken)) != 1 {
		return ErrAuthInvalid
	}
	if handle.expired(s.now()) {
		return ErrHandleExpired
	}
	if _, ok := handle.servableEndpoint(); !ok {
		// M0 serves the realized transports — direct (loopback) and unix (socket);
		// a handle with only a relay endpoint has no servable carrier yet (M2).
		return ErrHandleMalformed
	}
	return nil
}

// DriveInput drives a user-input record through the writer seat. A READER
// attachment refuses (ErrReaderCannotWrite) — the write never reaches the bridge.
// A WRITER forwards to the bridge's existing-driver-backed DriveInput.
func (a *Attachment) DriveInput(in DriveInput) error {
	if a.role != RoleWriter {
		return ErrReaderCannotWrite
	}
	return a.session.bridge.DriveInput(in)
}

// DriveGrant drives an ask-response grant through the writer seat. A READER
// refuses (ErrReaderCannotWrite). A WRITER forwards to the bridge with the chosen
// route.
func (a *Attachment) DriveGrant(grant DriveGrant, route GrantRoute) error {
	if a.role != RoleWriter {
		return ErrReaderCannotWrite
	}
	return a.session.bridge.DriveGrant(grant, route)
}

// RawInput forwards opaque terminal input bytes (a client frameRawIn) toward the
// guest pty master through the session's terminal carriage. A READER refuses
// (ErrReaderCannotWrite) — the SAME defence-in-depth as DriveInput, so a forged
// reader raw-input frame is rejected server-side even though the client also
// refuses it (docs/serpent-cli-mvp/01 §2.2). A terminal attach only seats with a
// carriage present, so a nil carriage here is a programming error surfaced as a
// clean failure rather than a panic.
func (a *Attachment) RawInput(p []byte) error {
	if a.role != RoleWriter {
		return ErrReaderCannotWrite
	}
	tc := a.session.terminalCarriage()
	if tc == nil {
		return ErrTerminalReaderUnsupported
	}
	return tc.RawInput(p)
}

// Resize forwards a winsize (a client frameResize) toward the guest pty through
// the session's terminal carriage. A READER refuses (ErrReaderCannotWrite), the
// same defence-in-depth as RawInput.
func (a *Attachment) Resize(ws Winsize) error {
	if a.role != RoleWriter {
		return ErrReaderCannotWrite
	}
	tc := a.session.terminalCarriage()
	if tc == nil {
		return ErrTerminalReaderUnsupported
	}
	return tc.Resize(ws)
}

// Detach releases the subscription and, for a WRITER, frees the seat so a later
// WRITER can attach (the driver-handoff record mutation, docs/15 §5.4).
// Idempotent.
func (a *Attachment) Detach() {
	a.detachOnce.Do(func() {
		if a.unsubscribe != nil {
			a.unsubscribe()
		}
		if a.role == RoleWriter {
			a.session.mu.Lock()
			a.session.writerHeld = false
			a.session.mu.Unlock()
		}
	})
}
