package hostbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
)

// socket_pty_test.go — the U-FRAMES terminal-mode wire layer over a REAL UDS
// round-trip, the same in-process / synthetic posture socket_test.go uses (no
// container, no live claude/cia/podman). It exercises the four new frames
// (frameMode/frameRawOut/frameRawIn/frameResize, tags 11-14) and the design's
// load-bearing properties (docs/serpent-cli-mvp/01 §6, 10 build-decisions §A4):
//
//  1. mode negotiation + the byte-identical STRUCTURED back-compat default;
//  2. raw-out delivery (incl. binary payloads with embedded NULs and >maxFrameBytes
//     chunks the SENDER splits losslessly);
//  3. raw-in delivery (the keystroke bytes reach the guest carriage verbatim);
//  4. resize delivery (the exact 8-byte BE Winsize reaches the carriage);
//  5. the BLOCKING raw-out pump — a stalled client back-pressures the carriage read
//     rather than dropping/buffering (the highest-risk §2.4 item), AND a stalled
//     terminal writer on a session does NOT stall a STRUCTURED reader on the same
//     session (separate bw / outbox);
//  6. the terminal-READER reject (rejectTerminalReaderUnsupported);
//  7. the writer-seat (D61) shared with the structured path: a second terminal
//     writer is ErrWriterSeatTaken;
//  8. EOF/close: carriage EOF ⇒ a single frameEnd ⇒ TerminalConn.Done resolves;
//     client Close ⇒ the guest carriage Close (the in-guest SIGHUP path) fires.

// --- a fake terminal carriage (the guest pty stand-in) ------------------------

// fakeCarriage is an in-process TerminalCarriage: RawOut yields chunks fed on a
// channel (io.EOF when closed), RawInput/Resize record what the client sent, and
// Close marks the guest hangup. It is the test stand-in for the real
// guest-vsock-backed pty carriage (PR-3) — the wire layer is carriage-agnostic.
type fakeCarriage struct {
	out      chan []byte   // chunks the pump reads via RawOut (closed ⇒ io.EOF)
	closeCh  chan struct{} // closed by Close to unblock a pending RawOut (the hangup)
	closeOne sync.Once

	mu      sync.Mutex
	rawIn   [][]byte
	resizes []Winsize
	closed  bool

	// outDelivered counts chunks the pump has actually PULLED via RawOut — the
	// back-pressure probe: when the client stalls, the blocking pump stops pulling,
	// so this stops advancing while feed() keeps offering.
	outDelivered int64
}

func newFakeCarriage(buf int) *fakeCarriage {
	return &fakeCarriage{out: make(chan []byte, buf), closeCh: make(chan struct{})}
}

func (f *fakeCarriage) RawOut() ([]byte, error) {
	select {
	case chunk, ok := <-f.out:
		if !ok {
			return nil, io.EOF
		}
		atomic.AddInt64(&f.outDelivered, 1)
		return chunk, nil
	case <-f.closeCh:
		// Close unblocks a pending RawOut with EOF — the io.Closer-on-a-blocked-
		// reader contract the TerminalCarriage doc requires (the guest hangup).
		return nil, io.EOF
	}
}

func (f *fakeCarriage) RawInput(p []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rawIn = append(f.rawIn, append([]byte(nil), p...))
	return nil
}

func (f *fakeCarriage) Resize(ws Winsize) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resizes = append(f.resizes, ws)
	return nil
}

func (f *fakeCarriage) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	// Unblock a pending RawOut (the guest hangup). Idempotent via closeOne.
	f.closeOne.Do(func() { close(f.closeCh) })
	return nil
}

// feedOut offers one output chunk to the pump. It blocks if the carriage's out
// buffer is full AND the pump is not pulling (the back-pressure condition).
func (f *fakeCarriage) feedOut(b []byte) { f.out <- b }

// eofOut closes the output side so the next RawOut returns io.EOF (CC exited).
func (f *fakeCarriage) eofOut() { close(f.out) }

func (f *fakeCarriage) inRecords() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.rawIn...)
}

func (f *fakeCarriage) resizeRecords() []Winsize {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Winsize(nil), f.resizes...)
}

func (f *fakeCarriage) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeCarriage) delivered() int64 { return atomic.LoadInt64(&f.outDelivered) }

// --- a terminal-serving UDS harness -------------------------------------------

// termHarness is a running Serve loop on a UDS under t.TempDir, fronting a Server
// with one session that has BOTH a (held-open) structured bridge and a registered
// fakeCarriage, so a terminal attach is servable and a structured reader can
// coexist on the same session.
type termHarness struct {
	udsPath  string
	srv      *Server
	bridge   *Bridge
	carriage *fakeCarriage
	sess     string
	token    string
}

func newTermHarness(t *testing.T, carriageBuf int) *termHarness {
	t.Helper()
	const sess = "00000000-0000-4000-8000-000000000050"
	const token = "synthetic-terminal-token-0001"
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)

	stdin := &captureStdin{}
	bridge := NewBridge(stdin, BridgeConfig{Adapter: claudecode.New(claudecode.WithClock(pinnedClock()))})
	srv := pinnedServer(t, now, token)
	session := srv.AddSession(sess, bridge)
	carriage := newFakeCarriage(carriageBuf)
	session.SetTerminalCarriage(carriage)

	// Hold the bridge open so the session stays live across dials (a structured
	// reader's fan-out won't close mid-test); the terminal path ignores the bridge.
	blocked, unblock := blockingReader()
	go func() { _ = bridge.Pump(context.Background(), blocked) }()
	t.Cleanup(unblock)

	sock := filepath.Join(t.TempDir(), "term.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	go func() { _ = Serve(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })

	return &termHarness{udsPath: sock, srv: srv, bridge: bridge, carriage: carriage, sess: sess, token: token}
}

func (h *termHarness) handle(t *testing.T, role Role) AttachHandle {
	t.Helper()
	hd, err := h.srv.IssueHandleFor(h.sess, role, TransportUnix, h.udsPath, time.Hour)
	if err != nil {
		t.Fatalf("IssueHandleFor unix %s: %v", role, err)
	}
	return hd
}

// dialTerm dials a TERMINAL-mode WRITER and fails the test on a dial error.
func (h *termHarness) dialTerm(t *testing.T) *TerminalConn {
	t.Helper()
	c, err := NewSocketTransport().DialTerminal(h.handle(t, RoleWriter))
	if err != nil {
		t.Fatalf("DialTerminal WRITER: %v", err)
	}
	return c
}

// collectRawOut drains a TerminalConn's RawOut to channel close, concatenating the
// chunks, failing on a timeout so a wedged transport cannot hang the suite.
func collectRawOut(t *testing.T, c *TerminalConn) []byte {
	t.Helper()
	var got []byte
	timeout := time.After(10 * time.Second)
	for {
		select {
		case chunk, ok := <-c.RawOut():
			if !ok {
				return got
			}
			got = append(got, chunk...)
		case <-timeout:
			t.Fatalf("timed out draining raw-out (have %d bytes)", len(got))
		}
	}
}

// --- (1) mode negotiation + the STRUCTURED back-compat default ----------------

// A structured Dial (no frameMode) serves the existing event stream byte-identical
// to today — the back-compat negative control. (The full structured battery in
// socket_test.go is the regression guard; this asserts the mode-peek default does
// not perturb a no-mode client on a terminal-capable session.)
func TestTerminalModeDefaultsStructuredForOldClient(t *testing.T) {
	h := newTermHarness(t, 4)

	conn, err := NewSocketTransport().Dial(h.handle(t, RoleReader))
	if err != nil {
		t.Fatalf("structured Dial READER on terminal-capable session: %v", err)
	}
	defer conn.Close()
	if conn.Role() != RoleReader {
		t.Fatalf("Role = %q, want READER", conn.Role())
	}
	// The session is held-open (no fixture pumped), so no events flow; the point is
	// the dial SUCCEEDS as a structured attach despite the mode-peek — i.e. the peek
	// timed out cleanly and the conn defaulted to STRUCTURED. A read fault would
	// surface on Done.
	select {
	case err := <-conn.Done():
		t.Fatalf("structured conn ended unexpectedly: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Healthy: the structured conn is live, no spurious end from the peek.
	}
}

// A TERMINAL-mode WRITER negotiates the raw surface and gets a *TerminalConn.
func TestTerminalModeWriterNegotiatesRawSurface(t *testing.T) {
	h := newTermHarness(t, 4)
	conn := h.dialTerm(t)
	defer conn.Close()
	if conn.Role() != RoleWriter {
		t.Fatalf("Role = %q, want WRITER", conn.Role())
	}
}

// --- (2) raw-out delivery: binary payloads + lossless split over maxFrameBytes -

func TestTerminalRawOutDeliversBytesIdentically(t *testing.T) {
	h := newTermHarness(t, 8)
	conn := h.dialTerm(t)
	defer conn.Close()

	// A binary payload with embedded NULs + a chunk LARGER than maxFrameBytes that
	// the carriage hands the pump as one read; the SENDER (the carriage feeding the
	// pump) frames it, and a frame is capped at maxFrameBytes, so the producer must
	// split a too-large read. We split here (the carriage's job) into cap-sized
	// chunks; the receiver concatenates losslessly (chunk boundaries are meaningless).
	want := bytes.Repeat([]byte{0x1b, '[', '0', 'm', 0x00, 0xff, 'A'}, maxFrameBytes/7+10)

	go func() {
		// Feed the payload as cap-sized chunks (a real pty read larger than the cap
		// is split by the sender; terminal byte streams have no record boundary).
		for off := 0; off < len(want); off += maxFrameBytes {
			end := off + maxFrameBytes
			if end > len(want) {
				end = len(want)
			}
			h.carriage.feedOut(append([]byte(nil), want[off:end]...))
		}
		h.carriage.eofOut() // CC exits ⇒ frameEnd ⇒ RawOut closes
	}()

	got := collectRawOut(t, conn)
	if !bytes.Equal(got, want) {
		t.Fatalf("raw-out mismatch: got %d bytes, want %d (first-diff or length)", len(got), len(want))
	}
	// Carriage EOF surfaced as a clean (nil-cause) terminal end.
	select {
	case err := <-conn.Done():
		if err != nil {
			t.Fatalf("Done after carriage EOF = %v, want nil (clean exit)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not resolve after carriage EOF")
	}
}

// An empty frameRawOut is legal and ignored (it is NOT EOF — EOF is frameEnd).
func TestTerminalRawOutEmptyChunkIsNotEOF(t *testing.T) {
	h := newTermHarness(t, 4)
	conn := h.dialTerm(t)
	defer conn.Close()

	go func() {
		h.carriage.feedOut([]byte{})        // empty chunk: legal, carries nothing
		h.carriage.feedOut([]byte("after")) // a real chunk AFTER the empty one
		h.carriage.eofOut()
	}()

	got := collectRawOut(t, conn)
	if string(got) != "after" {
		t.Fatalf("raw-out = %q, want %q (empty chunk must not terminate the stream)", got, "after")
	}
}

// --- (3) raw-in delivery: keystrokes reach the guest carriage verbatim --------

func TestTerminalRawInReachesCarriage(t *testing.T) {
	h := newTermHarness(t, 4)
	conn := h.dialTerm(t)
	defer conn.Close()

	keystrokes := [][]byte{
		[]byte("ls -la\r"),
		{0x03},                              // Ctrl-C
		{0x1b, '[', 'A'},                    // up arrow
		bytes.Repeat([]byte{0x00, 'x'}, 64), // binary with NULs
	}
	for _, k := range keystrokes {
		n, err := conn.Write(k)
		if err != nil {
			t.Fatalf("Write %q: %v", k, err)
		}
		if n != len(k) {
			t.Fatalf("Write returned %d, want %d", n, len(k))
		}
	}

	got := waitForCarriageIn(t, h.carriage, len(keystrokes))
	for i, k := range keystrokes {
		if !bytes.Equal(got[i], k) {
			t.Fatalf("raw-in[%d] = %v, want %v (keystroke bytes must cross verbatim)", i, got[i], k)
		}
	}

	// An empty Write is a no-op (an empty frameRawIn carries nothing) — it does not
	// reach the carriage.
	n, err := conn.Write(nil)
	if err != nil || n != 0 {
		t.Fatalf("empty Write = (%d, %v), want (0, nil)", n, err)
	}
}

// --- (4) resize delivery: the exact 8-byte BE Winsize reaches the carriage -----

func TestTerminalResizeReachesCarriage(t *testing.T) {
	h := newTermHarness(t, 4)
	conn := h.dialTerm(t)
	defer conn.Close()

	want := []Winsize{
		{Rows: 24, Cols: 80, Xpix: 0, Ypix: 0},
		{Rows: 50, Cols: 200, Xpix: 1920, Ypix: 1080}, // graphical: pixel geometry carried through
	}
	for _, ws := range want {
		if err := conn.SendResize(ws); err != nil {
			t.Fatalf("SendResize %+v: %v", ws, err)
		}
	}

	got := waitForCarriageResizes(t, h.carriage, len(want))
	for i, ws := range want {
		if got[i] != ws {
			t.Fatalf("resize[%d] = %+v, want %+v (exact 8-byte BE winsize must cross)", i, got[i], ws)
		}
	}
}

// A non-8-byte frameResize is a clean protocol end (frameEnd), never a silent drop
// or a wedge — symmetric with the malformed-resume handling. We speak the wire by
// hand to send a deliberately-short resize.
func TestTerminalMalformedResizeIsCleanEnd(t *testing.T) {
	h := newTermHarness(t, 4)

	raw, br, _ := dialTerminalRaw(t, h)
	defer raw.Close()

	// A 3-byte resize (not 8). The server must end the session cleanly (frameEnd),
	// never wedge.
	bw := bufio.NewWriter(raw)
	if err := writeFrame(bw, frameResize, []byte{0, 1, 2}); err != nil {
		t.Fatalf("send malformed resize: %v", err)
	}
	ft, _, err := readFrame(br)
	if err != nil {
		// EOF is also an acceptable clean termination (the server closed the conn).
		if errors.Is(err, io.EOF) {
			return
		}
		t.Fatalf("read after malformed resize: %v", err)
	}
	if ft != frameEnd {
		t.Fatalf("after malformed resize got frame %d, want frameEnd (clean protocol end)", ft)
	}
}

// --- (5) the BLOCKING raw-out pump (the highest-risk §2.4 item) ----------------

// A stalled terminal client back-pressures the carriage read: the blocking pump
// stops PULLING from the carriage rather than dropping bytes or buffering an
// unbounded queue. We feed more chunks than the carriage's out buffer + the OS
// socket buffer can hold while the client never reads, and assert the carriage's
// delivered-count plateaus (the pump blocked) — distinct from the structured
// path's drop-then-resume (which has a dropped counter; the terminal path has
// NONE).
func TestTerminalRawOutBlocksOnStalledClient(t *testing.T) {
	// A tiny carriage out buffer so the pump blocks promptly once the client stalls.
	h := newTermHarness(t, 1)
	conn := h.dialTerm(t)
	defer conn.Close()
	// Deliberately do NOT drain conn.RawOut(): the client is stalled.

	// Feed in the background; feedOut blocks once the carriage buffer fills and the
	// pump (blocked on the wire to the stalled client) stops pulling.
	const flood = 2000
	fed := make(chan int, 1)
	go func() {
		i := 0
		for ; i < flood; i++ {
			// A sizeable chunk so the OS socket buffer fills fast.
			h.carriage.feedOut(bytes.Repeat([]byte("Z"), 4096))
		}
		fed <- i
	}()

	// Give the pump time to fill the wire + socket buffer and then BLOCK.
	time.Sleep(200 * time.Millisecond)
	d1 := h.carriage.delivered()
	time.Sleep(200 * time.Millisecond)
	d2 := h.carriage.delivered()

	// The feeder must NOT have completed (it is back-pressured), and the pump's pull
	// count must have plateaued (it is blocked on the stalled wire, not draining).
	select {
	case <-fed:
		t.Fatalf("carriage drained all %d chunks despite a stalled client — the pump did not back-pressure (it dropped or buffered unboundedly)", flood)
	default:
	}
	if d2 != d1 {
		t.Fatalf("pump kept pulling while the client was stalled (delivered %d→%d): back-pressure not blocking", d1, d2)
	}
	if d1 == 0 {
		t.Fatal("pump pulled nothing at all — the carriage never started")
	}

	// Now drain the client: the pump unblocks and the feeder makes progress, proving
	// the block was back-pressure (recoverable), not a deadlock.
	drained := make(chan struct{})
	go func() {
		for range conn.RawOut() {
		}
		close(drained)
	}()
	// Close the conn after a moment so RawOut eventually closes and the drain ends.
	time.Sleep(100 * time.Millisecond)
	if got := h.carriage.delivered(); got <= d2 {
		t.Fatalf("draining the client did not unblock the pump (delivered stuck at %d)", got)
	}
	_ = conn.Close()
	<-drained
}

// A stalled TERMINAL writer on a session does NOT stall a STRUCTURED reader on the
// SAME session: they are separate conns with separate bw / outbox, so the terminal
// block cannot starve the structured fan-out (the §2.4 / risk-1 isolation).
func TestTerminalBlockDoesNotStallStructuredReader(t *testing.T) {
	h := newTermHarness(t, 1)

	// A stalled terminal writer (never drains RawOut).
	term := h.dialTerm(t)
	defer term.Close()
	go func() {
		for i := 0; i < 1000; i++ {
			h.carriage.feedOut(bytes.Repeat([]byte("Z"), 4096))
		}
	}()
	time.Sleep(150 * time.Millisecond) // let the terminal pump wedge

	// A STRUCTURED reader on the SAME session must still attach and receive its
	// fan-out. Pump a fixture through the bridge and assert the reader gets deltas.
	reader, err := NewSocketTransport().Dial(h.handle(t, RoleReader))
	if err != nil {
		t.Fatalf("structured READER dial while terminal writer wedged: %v", err)
	}
	defer reader.Close()

	// Fan synthetic events directly through the bridge (the held-open Pump is
	// blocked on its reader, so drive the fan-out path the same way resume tests do).
	var got int64
	go func() {
		for range reader.Events() {
			atomic.AddInt64(&got, 1)
		}
	}()
	fanRange(h.bridge, 1, 20)
	// The structured reader should receive its events promptly despite the wedged
	// terminal writer; give the fan-out a moment, then assert progress.
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt64(&got) < 20 {
		if time.Now().After(deadline) {
			t.Fatalf("structured reader got %d/20 events — the wedged terminal writer starved it (isolation broken)", atomic.LoadInt64(&got))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- (5b) count-only input-activity (D78 "driver typed", §A6) ------------------

// TestTerminalInputActivityIsCountOnly proves the WithInputActivityObserver seam fires
// the payload-free sink EXACTLY ONCE per inbound frameRawIn — and the SAME keystroke
// bytes still reach the carriage verbatim (the count is in ADDITION to forwarding, not
// instead of it). The observer takes NO argument, so the count-only contract is
// structural: a sink can never reach the opaque keystroke bytes (§A6 — the carriage must
// not parse them). The count equals the number of frames sent, regardless of payload.
func TestTerminalInputActivityIsCountOnly(t *testing.T) {
	const sess = "00000000-0000-4000-8000-000000000051"
	const token = "synthetic-terminal-token-0002"
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)

	var activity int64
	stdin := &captureStdin{}
	bridge := NewBridge(stdin, BridgeConfig{Adapter: claudecode.New(claudecode.WithClock(pinnedClock()))})
	srv := NewServer(
		WithClock(func() time.Time { return now }),
		WithTokenMinter(func() string { return token }),
		WithInputActivityObserver(func() { atomic.AddInt64(&activity, 1) }),
	)
	session := srv.AddSession(sess, bridge)
	carriage := newFakeCarriage(8)
	session.SetTerminalCarriage(carriage)

	blocked, unblock := blockingReader()
	go func() { _ = bridge.Pump(context.Background(), blocked) }()
	t.Cleanup(unblock)

	sock := filepath.Join(t.TempDir(), "term.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	go func() { _ = Serve(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })

	handle, err := srv.IssueHandleFor(sess, RoleWriter, TransportUnix, sock, time.Hour)
	if err != nil {
		t.Fatalf("IssueHandleFor: %v", err)
	}
	conn, err := NewSocketTransport().DialTerminal(handle)
	if err != nil {
		t.Fatalf("DialTerminal WRITER: %v", err)
	}
	defer conn.Close()

	// Send N raw-input frames of varying payloads; the count-only sink must tick once per
	// frame regardless of byte content.
	keystrokes := [][]byte{
		[]byte("a"),
		[]byte("ls -la\r"),
		{0x03},                              // Ctrl-C
		bytes.Repeat([]byte{0x00, 'x'}, 32), // binary with NULs
	}
	for _, k := range keystrokes {
		if _, err := conn.Write(k); err != nil {
			t.Fatalf("Write %q: %v", k, err)
		}
	}

	// The bytes reach the carriage verbatim (forwarding is unaffected by the count hook).
	got := waitForCarriageIn(t, carriage, len(keystrokes))
	for i, k := range keystrokes {
		if !bytes.Equal(got[i], k) {
			t.Fatalf("raw-in[%d] = %v, want %v (count hook must not alter forwarding)", i, got[i], k)
		}
	}

	// The count-only sink ticked exactly once per frame (a frameResize does NOT tick — it
	// is not raw input; assert by sending one and confirming the count stays put).
	if err := conn.SendResize(Winsize{Rows: 24, Cols: 80}); err != nil {
		t.Fatalf("SendResize: %v", err)
	}
	_ = waitForCarriageResizes(t, carriage, 1)

	if got := atomic.LoadInt64(&activity); got != int64(len(keystrokes)) {
		t.Fatalf("input-activity count = %d, want %d (once per frameRawIn, never for resize)", got, len(keystrokes))
	}
}

// --- (6) terminal-READER reject -----------------------------------------------

func TestTerminalReaderRejected(t *testing.T) {
	h := newTermHarness(t, 4)
	_, err := NewSocketTransport().DialTerminal(h.handle(t, RoleReader))
	if !errors.Is(err, ErrTerminalReaderUnsupported) {
		t.Fatalf("terminal READER err = %v, want ErrTerminalReaderUnsupported via errors.Is", err)
	}
}

// --- (7) the writer seat (D61) is shared with the structured path -------------

func TestTerminalSecondWriterSeatTaken(t *testing.T) {
	h := newTermHarness(t, 4)

	w1 := h.dialTerm(t)
	defer w1.Close()

	// A second TERMINAL writer is rejected with the SAME seat sentinel the
	// structured path uses, surfaced via errors.Is over the wire.
	if _, err := NewSocketTransport().DialTerminal(h.handle(t, RoleWriter)); !errors.Is(err, ErrWriterSeatTaken) {
		t.Fatalf("second terminal WRITER err = %v, want ErrWriterSeatTaken", err)
	}
}

// A terminal attach against a session with NO carriage is a clean internal reject
// (not a wedge) — the structured surface is unaffected.
func TestTerminalNoCarriageInternalReject(t *testing.T) {
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	const sess = "00000000-0000-4000-8000-000000000051"
	const token = "synthetic-terminal-token-0002"
	stdin := &captureStdin{}
	bridge := NewBridge(stdin, BridgeConfig{Adapter: claudecode.New(claudecode.WithClock(pinnedClock()))})
	srv := pinnedServer(t, now, token)
	srv.AddSession(sess, bridge) // NO SetTerminalCarriage

	blocked, unblock := blockingReader()
	defer unblock()
	go func() { _ = bridge.Pump(context.Background(), blocked) }()

	sock := filepath.Join(t.TempDir(), "nocarriage.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = Serve(ln, srv) }()
	t.Cleanup(func() { _ = ln.Close() })

	handle, _ := srv.IssueHandleFor(sess, RoleWriter, TransportUnix, sock, time.Hour)
	_, err = NewSocketTransport().DialTerminal(handle)
	if err == nil {
		t.Fatal("terminal attach to a session with no carriage succeeded; want an internal reject")
	}
	// The reject is a generic internal error (not a typed sentinel), surfaced as a
	// non-nil error — the seat is released, so a subsequent structured dial works.
	rc, derr := NewSocketTransport().Dial(srv.mustUnixHandle(t, sess, token, RoleReader, now.Add(time.Hour), sock))
	if derr != nil {
		t.Fatalf("structured dial after a no-carriage terminal reject failed: %v", derr)
	}
	_ = rc.Close()
}

// --- (8) EOF/close: client Close fires the guest-carriage hangup --------------

func TestTerminalClientCloseHangsUpCarriage(t *testing.T) {
	h := newTermHarness(t, 4)
	conn := h.dialTerm(t)

	// Drain raw-out in the background so the pump is not the thing that ends.
	go func() {
		for range conn.RawOut() {
		}
	}()

	// Client closes the terminal: the server's raw-in reader hits EOF, the serve
	// leg unwinds, and the carriage Close (the in-guest SIGHUP path) fires.
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for !h.carriage.isClosed() {
		if time.Now().After(deadline) {
			t.Fatal("carriage Close (the guest hangup) never fired after client Close")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- shared terminal test helpers ---------------------------------------------

// dialTerminalRaw speaks the terminal handshake by hand (frameAttach +
// frameMode{TERMINAL}, await frameAccept), returning the live raw conn + framed
// reader so a test can send a deliberately-malformed raw frame. Mirrors the
// hand-rolled handshake the resume malformed-frame test uses.
func dialTerminalRaw(t *testing.T, h *termHarness) (net.Conn, *bufio.Reader, *bufio.Writer) {
	t.Helper()
	handle := h.handle(t, RoleWriter)
	raw, err := net.Dial("unix", h.udsPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	br := bufio.NewReader(raw)
	bw := bufio.NewWriter(raw)
	hjson := mustJSON(t, handle)
	if err := writeFrame(bw, frameAttach, hjson); err != nil {
		t.Fatalf("send attach: %v", err)
	}
	if err := writeFrame(bw, frameMode, []byte{byte(modeTerminal)}); err != nil {
		t.Fatalf("send mode: %v", err)
	}
	ft, _, err := readFrame(br)
	if err != nil || ft != frameAccept {
		t.Fatalf("terminal attach reply ft=%d err=%v, want frameAccept", ft, err)
	}
	return raw, br, bw
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func waitForCarriageIn(t *testing.T, c *fakeCarriage, n int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		recs := c.inRecords()
		if len(recs) >= n {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d raw-in records (have %d)", n, len(recs))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitForCarriageResizes(t *testing.T, c *fakeCarriage, n int) []Winsize {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		recs := c.resizeRecords()
		if len(recs) >= n {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d resize records (have %d)", n, len(recs))
		}
		time.Sleep(2 * time.Millisecond)
	}
}
