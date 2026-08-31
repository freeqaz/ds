package hostbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// socket_test.go — the UDS-path equivalents of the four M0 ACCEPTANCE clauses,
// run over a REAL UDS under t.TempDir, fed by a SYNTHETIC CC stream (the same
// fixture-replay-through-the-adapter projection the loopback acceptance and the
// goldentrace replay tier pin). No container, no live claude/cia/podman: the
// transport is exercised end to end in-process over a socketpair, exactly the way
// loopback is (DRIVE-PROTOCOL.md "synthetic fixtures, zero egress", D50).
//
// The same four clauses the loopback battery asserts, now over the wire:
//
//  1. A WRITER over UDS receives the SAME adapter-projected attach.v1 deltas as
//     the standalone adapter for the same fixture stream.
//  2. DriveInput / DriveGrant land bytes on CC stdin that BYTE-MATCH the existing
//     Driver's EncodeInput / EncodeGrantPromptTool / EncodeGrant — the transport
//     never re-encodes a CC record (the Driver is the only encoder).
//  3. A second WRITER attach is rejected (ErrWriterSeatTaken); N READERs attach
//     and receive events but every READER write is refused (ErrReaderCannotWrite).
//  4. Expired / invalid-auth / malformed / unknown-session handles are rejected
//     with the SAME sentinels as loopback, via errors.Is over the wire.

// --- a live UDS server over a fixture-fed bridge ------------------------------

// socketHarness is a running Serve loop on a fresh UDS under t.TempDir, fronting
// a Server with one registered session whose Bridge pumps a fixture stream. The
// transport under test dials udsPath. pump() drives the fixture's CC stdout
// through the bridge (the bridge operator's job — Session.Bridge); start it after
// the clients have attached so they receive the full fan-out.
type socketHarness struct {
	udsPath string
	srv     *Server
	bridge  *Bridge
	stdin   *captureStdin
	ln      net.Listener
	fixture string
}

// newSocketHarness binds a UDS, registers sessUUID with a pinned-clock,
// fixture-backed bridge, and starts Serve. The auth token is fixed so handles are
// testable. Cleanup closes the listener.
func newSocketHarness(t *testing.T, sessUUID, token, fixture string, now time.Time) *socketHarness {
	t.Helper()
	dir := t.TempDir()
	// UDS sun_path is ~108 bytes; a bare filename under t.TempDir stays well under.
	sock := filepath.Join(dir, "attach.sock")

	stdin := &captureStdin{}
	bridge := NewBridge(stdin, BridgeConfig{
		Adapter: claudecode.New(claudecode.WithClock(pinnedClock())),
	})
	srv := pinnedServer(t, now, token)
	srv.AddSession(sessUUID, bridge)

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	go func() { _ = Serve(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })

	return &socketHarness{udsPath: sock, srv: srv, bridge: bridge, stdin: stdin, ln: ln, fixture: fixture}
}

// pump drives the harness's fixture CC stdout through the bridge — the synthetic
// CC process emitting its stream-json. Returns when the stream ends (the fan-out
// then closes, each socket client's Events channel closes).
func (h *socketHarness) pump(t *testing.T) {
	t.Helper()
	if err := h.bridge.Pump(context.Background(), fixtureCCStdout(t, h.fixture)); err != nil {
		t.Fatalf("Pump %s: %v", h.fixture, err)
	}
}

// unixHandle issues a unix-endpoint handle for the harness's session.
func (h *socketHarness) unixHandle(t *testing.T, sessUUID string, role Role, ttl time.Duration) AttachHandle {
	t.Helper()
	handle, err := h.srv.IssueHandleFor(sessUUID, role, TransportUnix, h.udsPath, ttl)
	if err != nil {
		t.Fatalf("IssueHandleFor unix: %v", err)
	}
	return handle
}

// drainSocketEvents reads a SocketConn's Events to channel close, failing on a
// timeout so a wedged transport cannot hang the suite.
func drainSocketEvents(t *testing.T, c *SocketConn) []attach.Event {
	t.Helper()
	var got []attach.Event
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-c.Events():
			if !ok {
				return got
			}
			got = append(got, ev)
		case <-timeout:
			t.Fatalf("timed out draining socket events (got %d)", len(got))
		}
	}
}

const (
	socketSession = "00000000-0000-4000-8000-000000000010"
	socketToken   = "synthetic-attach-token-0001"
)

// --- ACCEPTANCE (1): WRITER over UDS receives adapter-projected deltas ---------

func TestSocketWriterReceivesProjectedDeltas(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	h := newSocketHarness(t, socketSession, socketToken, "ask-control", now)

	handle := h.unixHandle(t, socketSession, RoleWriter, time.Hour)
	conn, err := NewSocketTransport().Dial(handle)
	if err != nil {
		t.Fatalf("socket Dial WRITER: %v", err)
	}
	defer conn.Close()
	if conn.Role() != RoleWriter {
		t.Fatalf("Role = %q, want WRITER", conn.Role())
	}

	// Collect events off the wire concurrently while the pump runs.
	var got []attach.Event
	var collectWG sync.WaitGroup
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		got = drainSocketEvents(t, conn)
	}()

	h.pump(t)
	collectWG.Wait()

	if len(got) == 0 {
		t.Fatal("WRITER received no deltas over UDS from the fixture-driven CC stream")
	}

	// The deltas must be EXACTLY what the standalone adapter projects from the
	// same fixture — import-don't-duplicate, asserted against the adapter, never
	// re-derived. The wire (JSON marshal/unmarshal) must not mutate them.
	want := adapterProject(t, "ask-control")
	if len(got) != len(want) {
		t.Fatalf("socket delta count = %d, adapter projects %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].Seq != want[i].Seq || got[i].SessionID != want[i].SessionID {
			t.Fatalf("socket delta[%d] = {seq:%d type:%s sess:%s}, adapter = {seq:%d type:%s sess:%s}",
				i, got[i].Seq, got[i].Type, got[i].SessionID,
				want[i].Seq, want[i].Type, want[i].SessionID)
		}
	}
	// At least one ask surfaced (ask-control carries a can_use_tool ask).
	if !hasType(got, attach.TypeAskRequested) {
		t.Fatal("expected an ask.requested delta over UDS from the ask-control fixture")
	}
}

// --- ACCEPTANCE (2): drive input + grant; bytes byte-match the driver ---------

func TestSocketWriterDrivesBytesByteMatchDriver(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	// A held-open session: the bridge's CC stdout never EOFs (an io.Reader that
	// blocks), so the writer-seat session stays live and the three drive frames
	// are processed before any session-terminal can race them. The pump runs in a
	// goroutine; the test ends it by closing the blocking reader after the sink
	// is satisfied.
	bridge, stdin, srv := newHeldSocketServer(t, socketSession, socketToken, now)
	dir := t.TempDir()
	sock := filepath.Join(dir, "attach.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = Serve(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })

	blocked, unblock := blockingReader()
	go func() { _ = bridge.Pump(context.Background(), blocked) }()

	handle, err := srv.IssueHandleFor(socketSession, RoleWriter, TransportUnix, sock, time.Hour)
	if err != nil {
		t.Fatalf("IssueHandleFor: %v", err)
	}
	conn, err := NewSocketTransport().Dial(handle)
	if err != nil {
		t.Fatalf("socket Dial: %v", err)
	}

	in := DriveInput{Text: "drive the session over UDS"}
	grant := DriveGrant{RequestID: "creq_synthetic_0301", ToolUseID: "toolu_SYNTHETIC000000000301", Allow: true}

	if err := conn.DriveInput(in); err != nil {
		t.Fatalf("DriveInput: %v", err)
	}
	if err := conn.DriveGrant(grant, GrantRoutePromptTool); err != nil {
		t.Fatalf("DriveGrant promptTool: %v", err)
	}
	if err := conn.DriveGrant(grant, GrantRouteNativeControl); err != nil {
		t.Fatalf("DriveGrant native: %v", err)
	}

	// The three drive frames cross the wire to the server's drive reader, which
	// forwards them to the bridge's existing-driver-backed DriveInput/DriveGrant.
	// Wait for all three to land on CC stdin, then assert byte-identity vs the
	// Driver — the transport carried the typed shapes verbatim, the Driver did
	// the (only) encoding.
	recs := waitForStdinRecords(t, stdin, 3)

	drv := claudecode.NewDriver()
	wantInput, err := drv.EncodeInput(in)
	if err != nil {
		t.Fatalf("driver EncodeInput: %v", err)
	}
	if !bytes.Equal(recs[0], wantInput) {
		t.Fatalf("CC stdin input record over UDS\n got: %s\nwant: %s", recs[0], wantInput)
	}
	wantPrompt, err := drv.EncodeGrantPromptTool(grant)
	if err != nil {
		t.Fatalf("driver EncodeGrantPromptTool: %v", err)
	}
	if !bytes.Equal(recs[1], wantPrompt) {
		t.Fatalf("CC stdin promptTool grant over UDS\n got: %s\nwant: %s", recs[1], wantPrompt)
	}
	wantNative, err := drv.EncodeGrant(grant)
	if err != nil {
		t.Fatalf("driver EncodeGrant: %v", err)
	}
	if !bytes.Equal(recs[2], wantNative) {
		t.Fatalf("CC stdin native grant over UDS\n got: %s\nwant: %s", recs[2], wantNative)
	}

	_ = conn.Close()
	unblock()
}

// --- ACCEPTANCE (3): second WRITER rejected; N READERs read, cannot write -----

func TestSocketWriterSeatArbitration(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	// Held-open session so the first writer's seat stays claimed across the table
	// (a small fixture would fan out, close, and free the seat before the second
	// dial).
	bridge, stdin, srv := newHeldSocketServer(t, socketSession, socketToken, now)
	dir := t.TempDir()
	sock := filepath.Join(dir, "attach.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = Serve(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })

	blocked, unblock := blockingReader()
	defer unblock()
	go func() { _ = bridge.Pump(context.Background(), blocked) }()

	tr := NewSocketTransport()
	writerHandle, _ := srv.IssueHandleFor(socketSession, RoleWriter, TransportUnix, sock, time.Hour)
	readerHandle, _ := srv.IssueHandleFor(socketSession, RoleReader, TransportUnix, sock, time.Hour)

	// First WRITER takes the seat.
	w1, err := tr.Dial(writerHandle)
	if err != nil {
		t.Fatalf("first WRITER Dial: %v", err)
	}
	defer w1.Close()

	// Second WRITER is rejected server-side, surfaced via errors.Is over the wire.
	if _, err := tr.Dial(writerHandle); !errors.Is(err, ErrWriterSeatTaken) {
		t.Fatalf("second WRITER err = %v, want ErrWriterSeatTaken", err)
	}

	// N READERs all attach.
	const nReaders = 3
	var readers []*SocketConn
	for i := 0; i < nReaders; i++ {
		r, err := tr.Dial(readerHandle)
		if err != nil {
			t.Fatalf("READER %d Dial: %v", i, err)
		}
		readers = append(readers, r)
		defer r.Close()
		if r.Role() != RoleReader {
			t.Fatalf("READER %d role = %q, want READER", i, r.Role())
		}
	}

	// A READER write is refused before the wire (D61).
	if err := readers[0].DriveInput(DriveInput{Text: "nope"}); !errors.Is(err, ErrReaderCannotWrite) {
		t.Fatalf("READER DriveInput err = %v, want ErrReaderCannotWrite", err)
	}
	if err := readers[0].DriveGrant(DriveGrant{ToolUseID: "x"}, GrantRoutePromptTool); !errors.Is(err, ErrReaderCannotWrite) {
		t.Fatalf("READER DriveGrant err = %v, want ErrReaderCannotWrite", err)
	}
	// Nothing a READER attempted reached CC stdin (the refusal is client-side).
	if recs := stdin.records(); len(recs) != 0 {
		t.Fatalf("READER writes leaked %d records onto CC stdin", len(recs))
	}
}

// After the writer detaches (Close), the seat frees for a later WRITER.
func TestSocketWriterSeatReleasedOnClose(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	bridge, _, srv := newHeldSocketServer(t, socketSession, socketToken, now)
	dir := t.TempDir()
	sock := filepath.Join(dir, "attach.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = Serve(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })

	blocked, unblock := blockingReader()
	defer unblock()
	go func() { _ = bridge.Pump(context.Background(), blocked) }()

	tr := NewSocketTransport()
	wh, _ := srv.IssueHandleFor(socketSession, RoleWriter, TransportUnix, sock, time.Hour)

	w1, err := tr.Dial(wh)
	if err != nil {
		t.Fatalf("first WRITER: %v", err)
	}
	// Seat held: a second writer is rejected.
	if _, err := tr.Dial(wh); !errors.Is(err, ErrWriterSeatTaken) {
		t.Fatalf("seat not held: %v", err)
	}
	// Detach releases the seat. The server-side seat frees when the conn's drive
	// reader hits EOF (Close closes the socket); poll until a fresh WRITER seats.
	_ = w1.Close()
	if err := dialUntilSeated(t, tr, wh); err != nil {
		t.Fatalf("WRITER handoff after Close failed: %v", err)
	}
}

// --- ACCEPTANCE (4): expired / invalid / malformed / unknown handles rejected -

func TestSocketAttachRejectionSentinels(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	// A live server with the writer seat pre-claimed (held-open) so the
	// writer-seat-taken case fires; the other cases are handle defects independent
	// of the seat.
	bridge, _, srv := newHeldSocketServer(t, socketSession, socketToken, now)
	dir := t.TempDir()
	sock := filepath.Join(dir, "attach.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = Serve(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })

	blocked, unblock := blockingReader()
	defer unblock()
	go func() { _ = bridge.Pump(context.Background(), blocked) }()

	tr := NewSocketTransport()

	// Seat the first writer and hold it for the duration.
	first, err := tr.Dial(srv.mustUnixHandle(t, socketSession, socketToken, RoleWriter, now.Add(time.Hour), sock))
	if err != nil {
		t.Fatalf("seat first writer: %v", err)
	}
	defer first.Close()

	valid := srv.mustUnixHandle(t, socketSession, socketToken, RoleReader, now.Add(time.Hour), sock)

	cases := []struct {
		name   string
		handle AttachHandle
		want   error
	}{
		{
			name:   "writer-seat-taken",
			handle: srv.mustUnixHandle(t, socketSession, socketToken, RoleWriter, now.Add(time.Hour), sock),
			want:   ErrWriterSeatTaken,
		},
		{
			name:   "auth-invalid",
			handle: srv.mustUnixHandle(t, socketSession, "wrong-token", RoleReader, now.Add(time.Hour), sock),
			want:   ErrAuthInvalid,
		},
		{
			name:   "handle-expired",
			handle: srv.mustUnixHandle(t, socketSession, socketToken, RoleReader, now.Add(-time.Minute), sock),
			want:   ErrHandleExpired,
		},
		{
			name:   "unknown-session",
			handle: srv.mustUnixHandle(t, "00000000-0000-4000-8000-0000deadbeef", socketToken, RoleReader, now.Add(time.Hour), sock),
			want:   ErrUnknownSession,
		},
		{
			// Malformed: no auth token (Dial shape-validates locally AND the server
			// re-validates; both yield ErrHandleMalformed).
			name: "handle-malformed-no-token",
			handle: AttachHandle{
				SessionUUID: socketSession,
				Endpoints:   []EndpointCandidate{{Transport: TransportUnix, Address: sock}},
				Role:        RoleReader,
				ExpiresAt:   now.Add(time.Hour),
			},
			want: ErrHandleMalformed,
		},
		{
			// Malformed: no "unix" endpoint this transport can serve (relay-only).
			name: "handle-malformed-no-unix-endpoint",
			handle: AttachHandle{
				SessionUUID: socketSession,
				Endpoints:   []EndpointCandidate{{Transport: TransportRelay, Address: "relay://x"}},
				Auth:        AuthMaterial{Token: socketToken},
				Role:        RoleReader,
				ExpiresAt:   now.Add(time.Hour),
			},
			want: ErrHandleMalformed,
		},
		{
			// Malformed: bad role.
			name: "handle-malformed-bad-role",
			handle: func() AttachHandle {
				h := valid
				h.Role = Role("SPECTATOR")
				return h
			}(),
			want: ErrHandleMalformed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tr.Dial(tc.handle)
			if c != nil {
				_ = c.Close()
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Dial error = %v, want errors.Is(_, %v)", err, tc.want)
			}
		})
	}

	// The valid READER handle still attaches over the wire.
	rc, err := tr.Dial(valid)
	if err != nil {
		t.Fatalf("valid READER handle rejected: %v", err)
	}
	_ = rc.Close()
}

// --- ServeBridge: gated-off RunLiveBridge binds nothing; the seam serves -------

// TestServeBridgeServesOneAttach proves the realized socket carrier (ServeBridge)
// actually serves the AttachHandle seam to a client over a real UDS — the in-fleet
// (non-live) half of the tier-2 step list. No container/claude/cia: the session is
// a fixture-fed bridge, exactly like every other test here.
func TestServeBridgeServesOneAttach(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	stdin := &captureStdin{}
	bridge := NewBridge(stdin, BridgeConfig{Adapter: claudecode.New(claudecode.WithClock(pinnedClock()))})
	srv := pinnedServer(t, now, socketToken)
	srv.AddSession(socketSession, bridge)

	sock := filepath.Join(t.TempDir(), "serve.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ServeBridge(ctx, sock, srv) }()
	waitForSocketPath(t, sock)

	handle, err := srv.IssueHandleFor(socketSession, RoleReader, TransportUnix, sock, time.Hour)
	if err != nil {
		t.Fatalf("IssueHandleFor: %v", err)
	}
	conn, err := NewSocketTransport().Dial(handle)
	if err != nil {
		t.Fatalf("dial served bridge: %v", err)
	}
	var got []attach.Event
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); got = drainSocketEvents(t, conn) }()
	if err := bridge.Pump(ctx, fixtureCCStdout(t, "ask-control")); err != nil {
		t.Fatalf("Pump: %v", err)
	}
	wg.Wait()
	_ = conn.Close()

	want := adapterProject(t, "ask-control")
	if len(got) != len(want) {
		t.Fatalf("ServeBridge fanned %d deltas, adapter projects %d", len(got), len(want))
	}
}

// --- shared socket test helpers ----------------------------------------------

// newHeldSocketServer builds a bridge whose CC stdout is supplied later (a
// blocking reader the caller pumps), plus a Server with one registered session.
// Used by the drive / arbitration / rejection tests that need the session to stay
// live across multiple dials.
func newHeldSocketServer(t *testing.T, sessUUID, token string, now time.Time) (*Bridge, *captureStdin, *Server) {
	t.Helper()
	stdin := &captureStdin{}
	bridge := NewBridge(stdin, BridgeConfig{Adapter: claudecode.New(claudecode.WithClock(pinnedClock()))})
	srv := pinnedServer(t, now, token)
	srv.AddSession(sessUUID, bridge)
	return bridge, stdin, srv
}

// mustUnixHandle issues a unix handle and overrides its auth token + expiry for
// the rejection table (so a wrong-token / expired / unknown-session handle can be
// constructed without the server minting a valid one).
func (s *Server) mustUnixHandle(t *testing.T, sessUUID, token string, role Role, expires time.Time, sock string) AttachHandle {
	t.Helper()
	return AttachHandle{
		SessionUUID: sessUUID,
		Endpoints:   []EndpointCandidate{{Transport: TransportUnix, Address: sock}},
		Auth:        AuthMaterial{Token: token},
		Role:        role,
		ExpiresAt:   expires,
	}
}

// blockingReader returns an io.Reader that blocks on Read until unblock is
// called, then returns io.EOF — a CC stdout that "stays open" for the duration of
// a held-session test, then cleanly EOFs so the pump goroutine exits.
func blockingReader() (r *blockReader, unblock func()) {
	br := &blockReader{release: make(chan struct{})}
	return br, func() { br.once.Do(func() { close(br.release) }) }
}

type blockReader struct {
	release chan struct{}
	once    sync.Once
}

func (b *blockReader) Read(p []byte) (int, error) {
	<-b.release
	return 0, errEOF
}

var errEOF = errors.New("EOF")

// waitForStdinRecords polls the capture sink until it holds at least n records or
// the deadline passes (the drive frames cross the wire asynchronously).
func waitForStdinRecords(t *testing.T, stdin *captureStdin, n int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		recs := stdin.records()
		if len(recs) >= n {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d drive records on CC stdin (have %d)", n, len(recs))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitForSocketPath polls until the UDS path exists (ServeBridge bound it) or the
// deadline passes.
func waitForSocketPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %s never appeared", path)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// dialUntilSeated retries a WRITER dial until it seats (the prior writer's
// server-side seat release is async on socket close) or the deadline passes.
func dialUntilSeated(t *testing.T, tr *SocketTransport, wh AttachHandle) error {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := tr.Dial(wh)
		if err == nil {
			_ = c.Close()
			return nil
		}
		if !errors.Is(err, ErrWriterSeatTaken) {
			return err
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- resume over the wire: the loopback resume battery, now over a real UDS ----
//
// The slow-reader recovery contract resume_test.go asserts for the in-process
// loopback Conn (Conn.Resume → Bridge.ReplayFrom over the bounded history ring)
// is mirrored here over a REAL framed UDS in a t.TempDir, fed by SYNTHETIC events
// (rev(), the same builder resume_test.go uses) so a forced Seq gap, a
// window-exceeded miss, and a malformed request are deterministic. No container,
// no live claude/cia/podman.
//
//   - (a) a slow READER whose bounded server-side outbox overflows drops events,
//     detects the Seq hole (Gap), and recovers the exact missing span once, in
//     order, via SocketConn.Resume — NO re-attach (TestSocketResumeSlowReaderGapRecovery);
//   - (b) errors.Is(err, ErrResumeWindowExceeded) holds ACROSS THE WIRE when the
//     span aged out of the bounded ring (TestSocketResumeWindowExceededOverWire);
//   - (c) the socket-recovered span EQUALS loopback Conn.Resume's for the same
//     afterSeq — the single-ring property (TestSocketResumeLoopbackParity);
//   - (d) a malformed/oversized resume frame is rejected cleanly, never dropping
//     the connection (TestSocketResumeMalformedRejectedCleanly);
//   - backfill: Resume(0) returns the whole retained ring (TestSocketResumeBackfillFromZero);
//   - race: a Resume racing the pump's fanout is race-clean (TestSocketResumeRaceClean).

// withSocketOutboxDepth shrinks the server-side per-conn outbox so a non-draining
// client deterministically overflows it, forcing a server-side drop over a real
// socket. It restores the production default on cleanup; production never
// reassigns socketOutboxDepth.
func withSocketOutboxDepth(t *testing.T, d int) {
	t.Helper()
	prev := socketOutboxDepth
	socketOutboxDepth = d
	t.Cleanup(func() { socketOutboxDepth = prev })
}

// newSyntheticSocketServer binds a UDS under t.TempDir fronting a Server with one
// session whose bridge has the given history-ring size (<=0 ⇒ the default). The
// bridge is fed SYNTHETIC events directly via fanRange (the same fan-out path Pump
// drives, recording each into the ring) — no fixture, no CC stream — so the test
// controls Seq and count exactly. Returns the bridge, the server, and the UDS path.
func newSyntheticSocketServer(t *testing.T, sessUUID, token string, now time.Time, historySize int) (*Bridge, *Server, string) {
	t.Helper()
	stdin := &captureStdin{}
	bridge := NewBridge(stdin, BridgeConfig{HistorySize: historySize})
	srv := pinnedServer(t, now, token)
	srv.AddSession(sessUUID, bridge)

	sock := filepath.Join(t.TempDir(), "resume.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	go func() { _ = Serve(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })
	return bridge, srv, sock
}

// --- (a) slow READER over UDS recovers a forced Seq gap exactly-once-in-order --

func TestSocketResumeSlowReaderGapRecovery(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	// Shrink the server outbox so a non-draining client deterministically overflows
	// it once enough events are fanned, dropping a span the client then recovers
	// over a real socket — no re-attach. A generous ring retains the dropped span.
	withSocketOutboxDepth(t, 8)
	bridge, srv, sock := newSyntheticSocketServer(t, socketSession, socketToken, now, 8192)

	conn, err := NewSocketTransport().Dial(mustUnixReaderHandle(t, srv, sock))
	if err != nil {
		t.Fatalf("Dial READER: %v", err)
	}
	defer conn.Close()

	// Fan a long stream WITHOUT draining: the wire backs up, the server outbox
	// fills, and the server DROPS the overflow for this slow conn (never stalling
	// the pump). >> outbox + OS socket buffer, so drops are forced.
	const n = 6000
	fanRange(bridge, 1, n)
	// The server fans synchronously; once fanRange returns, every event has been
	// enqueued-or-dropped server-side. A brief settle lets the server's outbox
	// writer push what fit on the wire before the test drains the (gapped) tail.
	waitForRingLast(t, bridge, n)
	time.Sleep(80 * time.Millisecond)

	// Drain the live tail the client DID receive, folding each consumed event into
	// a Gap watcher. The slow reader drops a span the server could not fit on the
	// wire — whether the hole lands mid-stream (a positive Gap.Observe) or at the
	// tail (LastGood < the bridge's LastSeq), the recovery key is the SAME:
	// gap.LastGood(), the highest contiguous Seq this reader durably consumed
	// (exactly as resume_test.go's TestResumeSlowReaderOverrunDropsAndTailGapDetectable).
	gap := NewGap(0)
	var consumed int
drain:
	for {
		select {
		case ev, ok := <-conn.Events():
			if !ok {
				break drain
			}
			gap.Observe(ev)
			consumed++
		case <-time.After(300 * time.Millisecond):
			// The wire has gone quiet: the slow reader has received its whole
			// (gapped) live tail. The bridge stays live, so Events() never closes —
			// an idle window is the drain terminator.
			break drain
		}
	}

	lastGood := gap.LastGood()
	// A drop MUST have occurred: the reader saw strictly fewer than the n fanned
	// events (the bounded outbox + socket buffer could not hold all n).
	if consumed >= n {
		t.Fatalf("no drop forced: reader consumed %d of %d (outbox/socket buffer too large)", consumed, n)
	}
	if b := bridge.LastSeq(); lastGood >= b {
		t.Fatalf("no recoverable gap: LastGood %d >= bridge LastSeq %d", lastGood, b)
	}

	// Recover the missing span from the bridge ring OVER THE WIRE — no re-attach.
	// The session is still LIVE (the bridge was never closed), so the resume reply
	// races no frameEnd. Resume(lastGood) returns exactly (lastGood, LastSeq] from
	// the same ring loopback Conn.Resume reads.
	recovered, err := conn.Resume(lastGood)
	if err != nil {
		t.Fatalf("Resume(%d): %v", lastGood, err)
	}
	if len(recovered) == 0 {
		t.Fatalf("Resume returned an empty span for gap after Seq %d", lastGood)
	}

	// EXACTLY-ONCE + IN-ORDER: the recovered span is strictly ascending and
	// contiguous from lastGood+1, and reaches the highest fanned Seq — so stitched
	// ahead of nothing (the tail case) or the post-gap live tail (the mid case) it
	// closes the hole with no duplicate and no remaining gap.
	wantFirst := lastGood + 1
	for i, ev := range recovered {
		if ev.Seq != wantFirst+uint64(i) {
			t.Fatalf("recovered[%d].Seq = %d, want %d (span must be contiguous and ascending)", i, ev.Seq, wantFirst+uint64(i))
		}
	}
	if last := recovered[len(recovered)-1].Seq; last != bridge.LastSeq() {
		t.Fatalf("recovered span ends at Seq %d but the bridge fanned up to %d — the hole is not fully covered", last, bridge.LastSeq())
	}

	// EXACTLY-ONCE at the consumer: re-feeding the recovered span through the SAME
	// Gap watcher closes the hole and advances LastGood to the highest Seq with no
	// new gap flagged (the documented consumer recipe, resume_test.go
	// TestResumeGapThenResumeClosesHole).
	for _, ev := range recovered {
		if miss := gap.Observe(ev); miss != 0 {
			t.Fatalf("recovered event Seq %d re-flagged a gap of %d (not exactly-once / in-order)", ev.Seq, miss)
		}
	}
	if gap.LastGood() != bridge.LastSeq() {
		t.Fatalf("after recovery LastGood = %d, want %d (hole closed)", gap.LastGood(), bridge.LastSeq())
	}
}

// --- (b) window-exceeded crosses the wire via errors.Is -----------------------

func TestSocketResumeWindowExceededOverWire(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	// A tiny ring (4 events) and a long stream (40): early Seqs age out, so a
	// resume from an aged-out afterSeq must fail loud — over the wire. The session
	// stays LIVE (the bridge is never closed) so the reject reply races no frameEnd.
	const n = 40
	const ring = 4
	bridge, srv, sock := newSyntheticSocketServer(t, socketSession, socketToken, now, ring)

	conn, err := NewSocketTransport().Dial(mustUnixReaderHandle(t, srv, sock))
	if err != nil {
		t.Fatalf("Dial READER: %v", err)
	}
	defer conn.Close()

	// Drain whatever the wire delivers in the background while the stream fans, so
	// the reader never wedges the server's outbox writer. The session stays live.
	go func() {
		for range conn.Events() {
		}
	}()
	fanRange(bridge, 1, n)
	waitForRingOldest(t, bridge, n-ring+1) // ring now retains 37..40

	// Resume from Seq 1 — long aged out of a 4-deep ring after 40 events.
	if _, err := conn.Resume(1); !errors.Is(err, ErrResumeWindowExceeded) {
		t.Fatalf("Resume(1) over wire err = %v, want ErrResumeWindowExceeded via errors.Is", err)
	}
}

// --- (c) socket-recovered span == loopback Conn.Resume span -------------------

func TestSocketResumeLoopbackParity(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	const n = 30
	const afterSeq = 7

	// Socket side: a generous ring so afterSeq=7 is fully retained. The session
	// stays LIVE (the bridge is never closed) so the resume reply races no frameEnd.
	sockBridge, srv, sock := newSyntheticSocketServer(t, socketSession, socketToken, now, 64)
	connS, err := NewSocketTransport().Dial(mustUnixReaderHandle(t, srv, sock))
	if err != nil {
		t.Fatalf("socket Dial: %v", err)
	}
	defer connS.Close()
	go func() {
		for range connS.Events() {
		}
	}()
	fanRange(sockBridge, 1, n)
	waitForRingLast(t, sockBridge, n)
	socketSpan, err := connS.Resume(afterSeq)
	if err != nil {
		t.Fatalf("socket Resume(%d): %v", afterSeq, err)
	}

	// Loopback side: an identical synthetic stream through an identical-size ring.
	loopBridge := NewBridge(&captureStdin{}, BridgeConfig{HistorySize: 64})
	loopConn := subscribeConn(t, loopBridge, 256) // big buffer, keeps up
	defer loopConn.unsubscribeFn()
	fanRange(loopBridge, 1, n)
	drainChan(loopConn)
	loopSpan, err := loopConn.Resume(afterSeq)
	if err != nil {
		t.Fatalf("loopback Resume(%d): %v", afterSeq, err)
	}

	// The single-ring property: same afterSeq, same recovered Seq sequence.
	if !equalUint64s(resumeSeqs(socketSpan), resumeSeqs(loopSpan)) {
		t.Fatalf("socket span %v != loopback span %v for afterSeq %d (single-ring property violated)",
			resumeSeqs(socketSpan), resumeSeqs(loopSpan), afterSeq)
	}
	if want := []uint64{8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30}; !equalUint64s(resumeSeqs(socketSpan), want) {
		t.Fatalf("recovered span %v, want %v", resumeSeqs(socketSpan), want)
	}
}

// --- (d) a malformed resume frame is rejected cleanly, never a dropped conn ----

func TestSocketResumeMalformedRejectedCleanly(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	bridge, srv, sock := newSyntheticSocketServer(t, socketSession, socketToken, now, 64)
	fanRange(bridge, 1, 10)

	// Speak the wire by hand so we can send a deliberately malformed frameResume (a
	// 3-byte afterSeq, not the required 8). The server must answer frameResumeReject
	// (internal code) and KEEP the connection so a subsequent valid resume succeeds.
	handle := mustUnixReaderHandle(t, srv, sock)
	raw, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	br := bufio.NewReader(raw)
	bw := bufio.NewWriter(raw)

	hjson, _ := json.Marshal(handle)
	if err := writeFrame(bw, frameAttach, hjson); err != nil {
		t.Fatalf("send attach: %v", err)
	}
	ft, _, err := readFrame(br)
	if err != nil || ft != frameAccept {
		t.Fatalf("attach reply ft=%d err=%v, want frameAccept", ft, err)
	}

	// Malformed resume: 3 bytes, not 8. Expect a clean frameResumeReject; events
	// may interleave on the wire, so scan past frameEvent frames for the reject.
	if err := writeFrame(bw, frameResume, []byte{0, 0, 0}); err != nil {
		t.Fatalf("send malformed resume: %v", err)
	}
	if got := readUntilFrame(t, br, frameResumeReject); got == nil {
		t.Fatal("no frameResumeReject for a malformed resume frame")
	}

	// The connection is still alive: a well-formed resume now succeeds, proving the
	// malformed request was a clean reply, not a dropped connection.
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], 5)
	if err := writeFrame(bw, frameResume, seq[:]); err != nil {
		t.Fatalf("send valid resume after malformed: %v", err)
	}
	payload := readUntilFrame(t, br, frameResumeReply)
	if payload == nil {
		t.Fatal("valid resume after malformed got no frameResumeReply (connection dropped?)")
	}
	span, err := decodeSpan(payload)
	if err != nil {
		t.Fatalf("decode resume reply: %v", err)
	}
	if want := []uint64{6, 7, 8, 9, 10}; !equalUint64s(resumeSeqs(span), want) {
		t.Fatalf("resume(5) after malformed recovered %v, want %v", resumeSeqs(span), want)
	}
}

// --- backfill: Resume(0) returns the whole retained ring over the wire ---------

func TestSocketResumeBackfillFromZero(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	// Ring retains the last 5 of 12; Resume(0) is the late-joiner backfill — never
	// the window-exceeded case. A late-joining conn dials AFTER the stream fanned
	// and backfills the retained ring over the wire; the session stays live.
	bridge, srv, sock := newSyntheticSocketServer(t, socketSession, socketToken, now, 5)
	fanRange(bridge, 1, 12)
	waitForRingLast(t, bridge, 12)

	conn, err := NewSocketTransport().Dial(mustUnixReaderHandle(t, srv, sock))
	if err != nil {
		t.Fatalf("late-joiner Dial: %v", err)
	}
	defer conn.Close()
	span, err := conn.Resume(0)
	if err != nil {
		t.Fatalf("backfill Resume(0): %v", err)
	}
	if want := []uint64{8, 9, 10, 11, 12}; !equalUint64s(resumeSeqs(span), want) {
		t.Fatalf("Resume(0) backfilled %v, want %v (last HistorySize retained)", resumeSeqs(span), want)
	}
}

// --- race: a Resume racing the pump's fanout is race-clean ---------------------

func TestSocketResumeRaceClean(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	bridge, srv, sock := newSyntheticSocketServer(t, socketSession, socketToken, now, 512)
	conn, err := NewSocketTransport().Dial(mustUnixReaderHandle(t, srv, sock))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(3)
	// Drain the live stream.
	go func() {
		defer wg.Done()
		for range conn.Events() {
		}
	}()
	// Fan a stream concurrently.
	go func() {
		defer wg.Done()
		fanRange(bridge, 1, 300)
		bridge.closeFanout(nil)
	}()
	// Hammer Resume against the fanout; the session may end mid-flight, in which
	// case Resume returns the terminal cause — never a panic, never a race.
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = conn.Resume(0)
		}
	}()
	wg.Wait()
}

// readUntilFrame reads frames from br until one of type want is seen (returning
// its payload) or a non-want, non-frameEvent frame appears (returning nil) or a
// deadline passes. frameEvent frames that interleave with the resume answer are
// skipped — they are the live stream, not the reply under test.
func readUntilFrame(t *testing.T, br *bufio.Reader, want frameType) []byte {
	t.Helper()
	for i := 0; i < 4096; i++ {
		ft, payload, err := readFrame(br)
		if err != nil {
			return nil
		}
		switch ft {
		case want:
			return payload
		case frameEvent:
			continue // live stream interleaving the reply; keep scanning
		default:
			return nil
		}
	}
	t.Fatalf("did not see frame %d within the scan budget", want)
	return nil
}

// waitForRingLast confirms the bridge's history ring has recorded up to wantLast
// (fanRange is synchronous, so this holds the moment it returns; the helper makes
// the dependency explicit and tolerates any future async).
func waitForRingLast(t *testing.T, b *Bridge, wantLast uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if b.LastSeq() >= wantLast {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ring never reached LastSeq %d (have %d)", wantLast, b.LastSeq())
		}
		time.Sleep(time.Millisecond)
	}
}

// waitForRingOldest confirms the bridge's history ring has evicted down to oldest
// retained Seq == wantOldest (the window-exceeded precondition).
func waitForRingOldest(t *testing.T, b *Bridge, wantOldest uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if b.OldestRetainedSeq() == wantOldest {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ring oldest retained never reached %d (have %d)", wantOldest, b.OldestRetainedSeq())
		}
		time.Sleep(time.Millisecond)
	}
}

// mustUnixReaderHandle issues a valid unix READER handle for the synthetic-server
// session, failing the test on error.
func mustUnixReaderHandle(t *testing.T, srv *Server, sock string) AttachHandle {
	t.Helper()
	h, err := srv.IssueHandleFor(socketSession, RoleReader, TransportUnix, sock, time.Hour)
	if err != nil {
		t.Fatalf("IssueHandleFor unix READER: %v", err)
	}
	return h
}

// --- benchmarks: socket vs the loopback baseline -----------------------------
//
// These produce the throughput + per-event latency numbers the README
// Language-verdict section cites (DRIVE-PROTOCOL.md "decided by measurement").
// BenchmarkLoopback_* is the in-process floor; BenchmarkSocket_* is the framed
// UDS realization. The delta is the cost of crossing a real socket — the byte
// the Go-vs-Rust verdict weighs. Both feed a fixture-projected event stream
// through a fresh bridge per iteration; no live process.

// benchProjected projects a fixture once for reuse across bench iterations.
func benchProjected(b *testing.B, fixture string) []attach.Event {
	b.Helper()
	a := claudecode.New(claudecode.WithClock(pinnedClock()))
	r, err := os.Open(filepath.FromSlash("../fixtures/" + fixture + fixtureSuffix))
	if err != nil {
		b.Fatalf("open fixture: %v", err)
	}
	defer r.Close()
	evs, err := a.ProcessStream(r)
	if err != nil {
		b.Fatalf("project: %v", err)
	}
	if len(evs) == 0 {
		b.Fatalf("fixture %s projected zero events", fixture)
	}
	return evs
}

// fanSource is a tiny Subscriber-pushing helper: it fans evs into sub and closes
// it, the same shape the bridge's fan-out drives — used so the benchmark times
// the transport carrier, not the adapter projection.
func fanSource(sub Subscriber, evs []attach.Event) {
	for _, ev := range evs {
		sub.OnEvent(ev)
	}
	sub.OnClose(nil)
}

func BenchmarkLoopbackEventThroughput(b *testing.B) {
	evs := benchProjected(b, "parallel-fanout")
	b.ReportAllocs()
	b.ResetTimer()
	var total int
	for i := 0; i < b.N; i++ {
		// A bare loopbackSubscriber over a fresh Conn channel: the in-process floor.
		conn := &Conn{events: make(chan attach.Event, eventBuffer), done: make(chan struct{})}
		sub := &loopbackSubscriber{conn: conn}
		go fanSource(sub, evs)
		for range conn.events {
			total++
		}
	}
	b.StopTimer()
	reportPerEvent(b, total)
}

func BenchmarkSocketEventThroughput(b *testing.B) {
	evs := benchProjected(b, "parallel-fanout")
	tr := NewSocketTransport()
	b.ReportAllocs()
	b.ResetTimer()
	var total int
	for i := 0; i < b.N; i++ {
		// A fresh bridge + UDS per iteration: the framed-socket carrier cost end
		// to end (dial + handshake + fan-out over the wire). Fanning starts after
		// the conn subscribes so the reader receives the whole stream.
		bridge := NewBridge(&captureStdin{}, BridgeConfig{})
		srv := NewServer()
		srv.AddSession(socketSession, bridge)
		sock := filepath.Join(b.TempDir(), "bench.sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			b.Fatalf("listen: %v", err)
		}
		go func() { _ = Serve(ln, srv) }()

		handle, _ := srv.IssueHandleFor(socketSession, RoleReader, TransportUnix, sock, time.Hour)
		c, err := tr.Dial(handle)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}
		go func() {
			for _, ev := range evs {
				bridge.fanout(ev)
			}
			bridge.closeFanout(nil)
		}()
		for range c.Events() {
			total++
		}
		_ = c.Close()
		_ = ln.Close()
	}
	b.StopTimer()
	reportPerEvent(b, total)
}

// reportPerEvent emits a ns/event custom metric so the README can cite per-event
// latency directly, not just ns/op.
func reportPerEvent(b *testing.B, totalEvents int) {
	if totalEvents == 0 {
		return
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(totalEvents), "ns/event")
}

// TestSocketSubscriberRequestEndIdempotent reproduces the close-of-closed-channel
// teardown race: the two end-signal paths — serveDrive's client-fault path and
// OnClose's bridge-pump path — can fire requestEnd concurrently. The pre-fix racy
// select{ case <-stopCh: default: close(stopCh) } let both callers fall through to
// default and double-close stopCh, panicking "close of closed channel"
// (socket.go ~1611). The stopOnce guard makes requestEnd idempotent.
//
// A panic in any of the N goroutines fails the test (the goroutine's deferred
// recover re-fails on the test); under -race this also surfaces any data race on
// the stopCh close. Run with -count to amplify the scheduling interleavings that
// expose the double-close. Reverting the stopOnce guard makes this panic.
func TestSocketSubscriberRequestEndIdempotent(t *testing.T) {
	const goroutines = 64
	for trial := 0; trial < 50; trial++ {
		// requestEnd/OnClose never touch the wire, so a buffer-backed writer is a
		// stand-in carrier; the subject under test is purely the stopCh teardown.
		sub := newSocketSubscriber(bufio.NewWriter(&bytes.Buffer{}))

		var start sync.WaitGroup
		start.Add(1)
		var done sync.WaitGroup
		done.Add(goroutines)
		panicked := make(chan any, goroutines)

		for i := 0; i < goroutines; i++ {
			go func(i int) {
				defer done.Done()
				defer func() {
					if r := recover(); r != nil {
						panicked <- r
					}
				}()
				start.Wait() // release all goroutines at once to maximize the race window
				// Alternate the two real call sites: serveDrive's requestEnd(err)
				// client-fault path and the bridge pump's OnClose(err) path.
				if i%2 == 0 {
					sub.requestEnd(errors.New("client fault"))
				} else {
					sub.OnClose(errors.New("bridge close"))
				}
			}(i)
		}

		start.Done()
		done.Wait()
		close(panicked)
		if r, ok := <-panicked; ok {
			t.Fatalf("trial %d: requestEnd/OnClose panicked under concurrent teardown: %v", trial, r)
		}

		// stopCh must be closed exactly once (the drainer's wind-down signal); a
		// receive must not block — proves the single close happened.
		select {
		case <-sub.stopCh:
		default:
			t.Fatalf("trial %d: stopCh not closed after requestEnd", trial)
		}

		// endErr is first-writer-wins (one of the two causes, never empty); a
		// subsequent requestEnd must neither overwrite it nor panic (idempotent).
		sub.mu.Lock()
		gotErr := sub.endErr
		sub.mu.Unlock()
		if gotErr == nil {
			t.Fatalf("trial %d: endErr not recorded under concurrent teardown", trial)
		}
		sub.requestEnd(errors.New("late call after close"))
		sub.mu.Lock()
		if sub.endErr != gotErr {
			t.Fatalf("trial %d: endErr overwritten by a late requestEnd (want first-writer-wins)", trial)
		}
		sub.mu.Unlock()
	}
}

// ── writeFrame byte-layout pin against the shared cross-tree golden ────────────
//
// hostBridgeWireGoldenLink is the tracked in-module symlink through which this test
// reads the shared golden hex vectors that assurance/conformance-adapter/hostbridgewire
// publishes (testdata/hostbridge_wire.golden.json). The golden lives in ANOTHER module
// (the OSS conformance adapter), so it is a cross-tree file; reading it directly via
// ../../../assurance/… would defeat Go's test cache — cmd/go computeTestInputsID hashes
// only files opened at paths lexically inside THIS module's root ("Do not recheck files
// outside the module"), so a warm cache would serve a stale PASS after the golden
// changes. Routing the read through this in-module link (os.ReadFile FOLLOWS it, so the
// tracked size+mtime are the real golden's) keeps the pin honest. hostbridgewire's own
// TestClientWireNumbersMatchGolden proves socket.go's frame NUMBERS equal this golden by
// scraping socket.go's source; this pin closes the last inferential gap by proving the
// LIVE writeFrame emitter renders the exact on-wire BYTES the golden encodes, so both
// emitters (client writeFrame + orchestrator writeBridgeFrame) are pinned byte-identical
// to one golden, not merely to matching constants. TestHostBridgeWireGoldenLinkResolves
// guards the link target so a stale copy cannot freeze the pin.
const hostBridgeWireGoldenLink = "hostbridge_wire_golden"

// hostBridgeWireGoldenLinkTarget is the repo-relative file the link must point at,
// checked by TestHostBridgeWireGoldenLinkResolves (via the fixed ../../../../ prefix from
// client/hostbridge/testdata/srclinks up to the repo root).
const hostBridgeWireGoldenLinkTarget = "assurance/conformance-adapter/hostbridgewire/testdata/hostbridge_wire.golden.json"

// hostBridgeWireGolden is the subset of the shared golden this pin consumes: the frame
// type numbers, the reject-code numbers, and the representative on-wire frame hex. It is
// a LOCAL struct (client/ may not import the conformance adapter across the tree
// boundary, D26/D80), so only the fields the byte pin needs are modeled.
type hostBridgeWireGolden struct {
	Frames          map[string]int    `json:"frames"`
	RejectCodes     map[string]int    `json:"reject_codes"`
	GoldenFramesHex map[string]string `json:"golden_frames_hex"`
}

func loadHostBridgeWireGolden(t *testing.T) hostBridgeWireGolden {
	t.Helper()
	// go test runs with cwd = package dir, so the in-module link path resolves.
	path := filepath.Join("testdata", "srclinks", hostBridgeWireGoldenLink)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared wire golden through %s: %v", path, err)
	}
	var g hostBridgeWireGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("unmarshal shared wire golden: %v", err)
	}
	return g
}

// emitFrameBytes captures the EXACT bytes writeFrame flushes for one frame — the real
// production emitter, not a reimplementation — so the pin catches a framing change in
// writeFrame itself (header order, endianness, length width), not only a number change.
func emitFrameBytes(t *testing.T, ft frameType, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	if err := writeFrame(bw, ft, payload); err != nil {
		t.Fatalf("writeFrame(%d): %v", ft, err)
	}
	return buf.Bytes()
}

// TestWriteFrameBytesMatchSharedGolden pins the LIVE writeFrame emitter's on-wire byte
// layout to the shared cross-tree golden hex vectors. It first cross-checks that this
// package's frame/reject CONSTANTS equal the golden's numbers (so the vectors are built
// from the same numbers hostbridgewire pins socket.go's source against), then asserts
// writeFrame renders those frames to the exact golden bytes. A change to writeFrame's
// framing, or a renumber of frameInput/frameReject/rejectWriterSeatTaken, shifts these
// bytes and REDs here.
func TestWriteFrameBytesMatchSharedGolden(t *testing.T) {
	g := loadHostBridgeWireGolden(t)

	// Cross-check the constants against the golden numbers first (so a byte match can
	// never be a coincidence of two compensating drifts).
	if got, want := int(frameInput), g.Frames["input"]; got != want {
		t.Errorf("frameInput = %d; shared golden wants %d (wire number drift)", got, want)
	}
	if got, want := int(frameReject), g.Frames["reject"]; got != want {
		t.Errorf("frameReject = %d; shared golden wants %d (wire number drift)", got, want)
	}
	if got, want := int(rejectWriterSeatTaken), g.RejectCodes["writer_seat_taken"]; got != want {
		t.Errorf("rejectWriterSeatTaken = %d; shared golden wants %d (reject code drift)", got, want)
	}

	// input frame carrying {"text":"hi"} — the golden's representative DriveInput frame.
	inputBytes := emitFrameBytes(t, frameInput, []byte(`{"text":"hi"}`))
	assertFrameHex(t, "input_text_hi", inputBytes, g.GoldenFramesHex["input_text_hi"])

	// reject frame carrying the 1-byte writer-seat-taken code.
	rejectBytes := emitFrameBytes(t, frameReject, []byte{byte(rejectWriterSeatTaken)})
	assertFrameHex(t, "reject_writer_seat_taken", rejectBytes, g.GoldenFramesHex["reject_writer_seat_taken"])
}

func assertFrameHex(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	if wantHex == "" {
		t.Fatalf("shared golden hex for %q is empty (the golden lost a vector?)", name)
	}
	if h := hex.EncodeToString(got); h != wantHex {
		t.Fatalf("writeFrame %q bytes = %s; shared golden wants %s (wire framing/number drift — client writeFrame no longer emits the pinned on-wire layout)", name, h, wantHex)
	}
}

// TestHostBridgeWireGoldenLinkResolves guards the cross-tree source link: it must BE a
// symlink whose target is exactly ../../../../<repo-relative golden> and be readable. A
// link replaced by a stale COPY (which would freeze this byte pin against a dead golden
// snapshot) or retargeted turns RED here.
func TestHostBridgeWireGoldenLinkResolves(t *testing.T) {
	path := filepath.Join("testdata", "srclinks", hostBridgeWireGoldenLink)
	got, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("%s: not a symlink (a stale copy would freeze the byte pin against a dead golden snapshot): %v", path, err)
	}
	want := filepath.FromSlash("../../../../" + hostBridgeWireGoldenLinkTarget)
	if got != want {
		t.Fatalf("%s -> %q; want %q (link retargeted — the pin would read the wrong golden)", path, got, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s: target unreadable (golden moved/removed?): %v", path, err)
	}
}
