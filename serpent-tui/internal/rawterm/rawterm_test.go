// SPDX-License-Identifier: Apache-2.0

package rawterm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
)

// --- compile-time: the production carrier satisfies the seam -----------------

// A *hostbridge.TerminalConn must satisfy Conn verbatim (RawOut/Write/SendResize/
// Done/Close), so the cmd binary can hand a real DialTerminal conn to Run with no
// adapter. This assertion fails the build if the carrier surface drifts.
var _ Conn = (*hostbridge.TerminalConn)(nil)

// --- fakes -------------------------------------------------------------------

// fakeConn is an in-process Conn: writes land on a buffer, RawOut is fed by the
// test, resizes are recorded, Done is closeable. It models the TerminalConn
// surface with no socket, so Run is exercised with no VM.
type fakeConn struct {
	mu      sync.Mutex
	written bytes.Buffer         // bytes Run forwarded via Write (frameRawIn)
	resizes []hostbridge.Winsize // resizes Run sent (frameResize), in order
	role    hostbridge.Role      // RoleWriter unless a reader-refusal test sets RoleReader

	out  chan []byte // RawOut feed (the test pushes pty output chunks)
	done chan error  // Done feed

	closeOnce sync.Once
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		role: hostbridge.RoleWriter,
		out:  make(chan []byte, 16),
		done: make(chan error, 1),
	}
}

func (f *fakeConn) RawOut() <-chan []byte { return f.out }

func (f *fakeConn) Write(p []byte) (int, error) {
	if f.role != hostbridge.RoleWriter {
		return 0, hostbridge.ErrReaderCannotWrite
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written.Write(p)
	return len(p), nil
}

func (f *fakeConn) SendResize(ws hostbridge.Winsize) error {
	if f.role != hostbridge.RoleWriter {
		return hostbridge.ErrReaderCannotWrite
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resizes = append(f.resizes, ws)
	return nil
}

func (f *fakeConn) Done() <-chan error { return f.done }

func (f *fakeConn) Close() error {
	f.closeOnce.Do(func() { close(f.out) })
	return nil
}

func (f *fakeConn) writtenBytes() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.written.Bytes()...)
}

func (f *fakeConn) resizeList() []hostbridge.Winsize {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostbridge.Winsize(nil), f.resizes...)
}

// endSession pushes a terminal cause onto Done (nil = clean).
func (f *fakeConn) endSession(cause error) { f.done <- cause }

// fakeTerm is an in-process Terminal: it records the raw-mode lifecycle (made /
// restored counts), serves a fixed size, and exposes a winch tick the test
// drives. It proves raw-mode setup/restore idempotency and the resize path with
// no real TTY.
type fakeTerm struct {
	mu sync.Mutex

	madeRaw     int    // MakeRaw call count
	restored    int    // Restore call count (the non-nil-token ones)
	altEntered  int    // EnterAltScreen count
	altLeft     int    // LeaveAltScreen count
	makeRawErr  error  // when set, MakeRaw fails (the non-TTY path)
	makeRawHook func() // called inside MakeRaw (a panic-injection seam)

	cols, rows uint16

	winch chan struct{} // the test pushes a SIGWINCH tick here
}

func newFakeTerm(cols, rows uint16) *fakeTerm {
	return &fakeTerm{cols: cols, rows: rows, winch: make(chan struct{}, 4)}
}

func (t *fakeTerm) MakeRaw() (any, error) {
	if t.makeRawHook != nil {
		t.makeRawHook()
	}
	if t.makeRawErr != nil {
		return nil, t.makeRawErr
	}
	t.mu.Lock()
	t.madeRaw++
	t.mu.Unlock()
	return "raw-token", nil
}

func (t *fakeTerm) Restore(token any) error {
	if token == nil {
		return nil
	}
	t.mu.Lock()
	t.restored++
	t.mu.Unlock()
	return nil
}

func (t *fakeTerm) Size() (uint16, uint16, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cols, t.rows, nil
}

func (t *fakeTerm) EnterAltScreen() error {
	t.mu.Lock()
	t.altEntered++
	t.mu.Unlock()
	return nil
}

func (t *fakeTerm) LeaveAltScreen() error {
	t.mu.Lock()
	t.altLeft++
	t.mu.Unlock()
	return nil
}

func (t *fakeTerm) WinchSignals(ctx context.Context) (<-chan struct{}, func()) {
	return t.winch, func() {}
}

func (t *fakeTerm) counts() (made, restored, entered, left int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.madeRaw, t.restored, t.altEntered, t.altLeft
}

func (t *fakeTerm) setSize(cols, rows uint16) {
	t.mu.Lock()
	t.cols, t.rows = cols, rows
	t.mu.Unlock()
}

// blockingReader blocks on Read until ctx is done, then returns EOF. It models a
// quiet stdin (the dev typing nothing) so a test can end Run via Conn.Done /
// detach rather than racing a stdin EOF.
type blockingReader struct{ ctx context.Context }

func (b blockingReader) Read(p []byte) (int, error) {
	<-b.ctx.Done()
	return 0, io.EOF
}

// --- tests -------------------------------------------------------------------

// runAsync starts Run in a goroutine and returns a channel carrying its error.
func runAsync(ctx context.Context, c Conn, in io.Reader, out io.Writer, opt Options) <-chan error {
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, c, in, out, opt) }()
	return errCh
}

// waitErr drains the Run error within a bound (a wedged Run fails the test fast).
func waitErr(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s — a pump/select regression wedged it")
		return nil
	}
}

// TestInitialResizeBeforeInput proves the INITIAL window size is sent on connect,
// before any input byte (§2.3/§A7) — so CC paints at the right size from frame 1.
func TestInitialResizeBeforeInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(120, 40)

	errCh := runAsync(ctx, c, blockingReader{ctx}, io.Discard, Options{Terminal: term})

	// End the session cleanly; Run returns nil and the initial resize must already
	// be recorded (it fires before the pumps start).
	c.endSession(nil)
	if err := waitErr(t, errCh); err != nil {
		t.Fatalf("Run = %v, want nil (clean session end)", err)
	}
	resizes := c.resizeList()
	if len(resizes) == 0 {
		t.Fatal("no resize sent — the INITIAL window size must be seeded on connect")
	}
	if resizes[0].Cols != 120 || resizes[0].Rows != 40 {
		t.Errorf("initial resize = %+v, want Cols=120 Rows=40", resizes[0])
	}
	if c := len(c.writtenBytes()); c != 0 {
		t.Errorf("no input should have been written in this test, got %d bytes", c)
	}
}

// TestStdinToRawIn proves stdin bytes are forwarded to Conn.Write (frameRawIn)
// verbatim — minus the detach key (tested separately).
func TestStdinToRawIn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)

	in := bytes.NewReader([]byte("hello, claude\x1b[A")) // text + an arrow-up CSI
	errCh := runAsync(ctx, c, in, io.Discard, Options{Terminal: term})

	// The reader hits EOF after the bytes; Run returns nil (clean local end).
	if err := waitErr(t, errCh); err != nil {
		t.Fatalf("Run = %v, want nil (stdin EOF)", err)
	}
	if got, want := string(c.writtenBytes()), "hello, claude\x1b[A"; got != want {
		t.Errorf("forwarded stdin = %q, want %q", got, want)
	}
}

// TestRawOutToStdout proves pty output chunks (Conn.RawOut) are written to the
// local stdout verbatim, concatenated across chunk boundaries.
func TestRawOutToStdout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)
	var out lockedBuf

	errCh := runAsync(ctx, c, blockingReader{ctx}, &out, Options{Terminal: term})

	c.out <- []byte("\x1b[2J")         // CC clears the screen
	c.out <- []byte("Welcome to CC\n") // then writes
	c.out <- []byte{}                  // an empty frame is legal and dropped
	// Give the output pump a beat to drain, then end the session.
	waitFor(t, func() bool { return out.String() == "\x1b[2JWelcome to CC\n" })
	c.endSession(nil)
	if err := waitErr(t, errCh); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if got, want := out.String(), "\x1b[2JWelcome to CC\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

// TestDetachKeyCleanExit proves the detach byte (default Ctrl-]) returns nil
// (clean detach, VM session kept) and forwards everything BEFORE it but nothing
// after.
func TestDetachKeyCleanExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)

	// "abc" then Ctrl-] then "xyz": abc is forwarded, the detach fires, xyz dropped.
	in := bytes.NewReader([]byte{'a', 'b', 'c', DefaultDetachKey, 'x', 'y', 'z'})
	errCh := runAsync(ctx, c, in, io.Discard, Options{Terminal: term})

	if err := waitErr(t, errCh); err != nil {
		t.Fatalf("Run on detach = %v, want nil (clean detach)", err)
	}
	if got, want := string(c.writtenBytes()), "abc"; got != want {
		t.Errorf("forwarded before detach = %q, want %q (nothing after the detach key)", got, want)
	}
}

// TestCustomDetachKey proves Options.DetachKey overrides the default.
func TestCustomDetachKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)

	const customKey = 0x1e // Ctrl-^
	in := bytes.NewReader([]byte{'h', 'i', customKey})
	errCh := runAsync(ctx, c, in, io.Discard, Options{Terminal: term, DetachKey: customKey})

	if err := waitErr(t, errCh); err != nil {
		t.Fatalf("Run on custom detach = %v, want nil", err)
	}
	if got := string(c.writtenBytes()); got != "hi" {
		t.Errorf("forwarded = %q, want hi", got)
	}
}

// TestDoneErrorSurfaces proves a Conn.Done error (a transport fault) is RETURNED
// from Run (a non-zero exit), distinct from a clean detach.
func TestDoneErrorSurfaces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)

	errCh := runAsync(ctx, c, blockingReader{ctx}, io.Discard, Options{Terminal: term})

	wantErr := errors.New("guest pty hung up")
	c.endSession(wantErr)
	if err := waitErr(t, errCh); !errors.Is(err, wantErr) {
		t.Fatalf("Run = %v, want the Done cause %v", err, wantErr)
	}
}

// TestResizeOnWinch proves a SIGWINCH tick re-reads the size and sends a new
// resize (frameResize) with the current grid.
func TestResizeOnWinch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)

	errCh := runAsync(ctx, c, blockingReader{ctx}, io.Discard, Options{Terminal: term})

	// Wait for the INITIAL resize (80x24) to land before changing the size, so the
	// first recorded resize is unambiguously the connect-time one.
	waitFor(t, func() bool { return len(c.resizeList()) >= 1 })

	// Resize the terminal, then deliver a SIGWINCH tick.
	term.setSize(100, 30)
	term.winch <- struct{}{}

	waitFor(t, func() bool {
		rs := c.resizeList()
		return len(rs) >= 2 && rs[len(rs)-1].Cols == 100 && rs[len(rs)-1].Rows == 30
	})
	c.endSession(nil)
	if err := waitErr(t, errCh); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	rs := c.resizeList()
	// resize[0] is the initial (80x24); a later one is the 100x30 from the winch.
	if rs[0].Cols != 80 || rs[0].Rows != 24 {
		t.Errorf("initial resize = %+v, want 80x24", rs[0])
	}
	last := rs[len(rs)-1]
	if last.Cols != 100 || last.Rows != 30 {
		t.Errorf("post-winch resize = %+v, want 100x30", last)
	}
}

// TestRestoreOnCleanExit proves raw mode is entered once and restored once on a
// clean exit, and the alt-screen is entered and left in balance.
func TestRestoreOnCleanExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)

	errCh := runAsync(ctx, c, blockingReader{ctx}, io.Discard, Options{Terminal: term})
	c.endSession(nil)
	if err := waitErr(t, errCh); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	made, restored, entered, left := term.counts()
	if made != 1 || restored != 1 {
		t.Errorf("raw lifecycle = made %d restored %d, want 1/1 (idempotent restore)", made, restored)
	}
	if entered != 1 || left != 1 {
		t.Errorf("alt-screen lifecycle = entered %d left %d, want 1/1", entered, left)
	}
}

// TestNoAltScreen proves Options.NoAltScreen skips the alt-screen enter/leave but
// still enters and restores raw mode (the --no-alt-screen flag).
func TestNoAltScreen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)

	errCh := runAsync(ctx, c, blockingReader{ctx}, io.Discard, Options{Terminal: term, NoAltScreen: true})
	c.endSession(nil)
	if err := waitErr(t, errCh); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	made, restored, entered, left := term.counts()
	if made != 1 || restored != 1 {
		t.Errorf("raw lifecycle = made %d restored %d, want 1/1", made, restored)
	}
	if entered != 0 || left != 0 {
		t.Errorf("alt-screen lifecycle = entered %d left %d, want 0/0 (NoAltScreen)", entered, left)
	}
}

// TestRestoreOnPanic proves a panic in the OUTPUT pump goroutine still restores
// the terminal (the §2.6 panic-safety guarantee): the pump recovers the panic and
// surfaces it as an error, the process does NOT die, and raw mode is restored. We
// drive the panic by writing to a panicWriter out while the conn feeds a chunk.
func TestRestoreOnPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	term := newFakeTerm(80, 24)
	c := newFakeConn()
	c.out <- []byte("boom") // the output pump will write this to the panicWriter

	errCh := runAsync(ctx, c, blockingReader{ctx}, panicWriter{}, Options{Terminal: term})

	err := waitErr(t, errCh)
	if err == nil {
		t.Fatal("Run should surface the output-pump panic as an error")
	}
	// The terminal MUST be restored even though a goroutine panicked.
	made, restored, _, _ := term.counts()
	if made != 1 || restored != 1 {
		t.Errorf("after a pump panic: made %d restored %d, want 1/1 (restore guaranteed)", made, restored)
	}
}

// TestRestoreOnInputPanic proves a panic in the STDIN pump goroutine (here, a
// Conn.Write that panics) is recovered and surfaced as an error with the terminal
// restored — the §2.6 guarantee on the input leg.
func TestRestoreOnInputPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	term := newFakeTerm(80, 24)
	c := newPanicOnWriteConn()

	in := bytes.NewReader([]byte("trigger"))
	errCh := runAsync(ctx, c, in, io.Discard, Options{Terminal: term})

	err := waitErr(t, errCh)
	if err == nil {
		t.Fatal("Run should surface the input-pump panic as an error")
	}
	made, restored, _, _ := term.counts()
	if made != 1 || restored != 1 {
		t.Errorf("after an input-pump panic: made %d restored %d, want 1/1", made, restored)
	}
}

// TestMakeRawFailureRestoresNothing proves a MakeRaw failure (the non-TTY
// defence-in-depth path) returns an error and does NOT leave a dangling restore
// (the deferred guard runs with a nil token = no-op, never a spurious Restore).
func TestMakeRawFailureRestoresNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)
	term.makeRawErr = errors.New("inappropriate ioctl for device")

	err := Run(ctx, c, blockingReader{ctx}, io.Discard, Options{Terminal: term})
	if err == nil {
		t.Fatal("Run should fail when MakeRaw fails (non-TTY)")
	}
	_, restored, entered, _ := term.counts()
	if restored != 0 {
		t.Errorf("Restore called %d times after MakeRaw failed, want 0 (nil token no-op)", restored)
	}
	if entered != 0 {
		t.Errorf("alt-screen entered %d times after MakeRaw failed, want 0", entered)
	}
}

// TestCtxCancelRestores proves an external signal (modeled by ctx cancel) ends
// Run with the ctx error and the restore runs (the §2.6 external-signal safety).
func TestCtxCancelRestores(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := newFakeConn()
	term := newFakeTerm(80, 24)

	errCh := runAsync(ctx, c, blockingReader{ctx}, io.Discard, Options{Terminal: term})
	cancel() // an external SIGINT/SIGTERM cancels the ctx

	err := waitErr(t, errCh)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run on ctx cancel = %v, want context.Canceled", err)
	}
	made, restored, _, _ := term.counts()
	if made != 1 || restored != 1 {
		t.Errorf("after ctx cancel: made %d restored %d, want 1/1 (restore on external signal)", made, restored)
	}
}

// TestLargePasteSplit proves a paste larger than readChunk is split across
// multiple Conn.Write calls (each ≤ readChunk) and arrives intact, never dropped
// (§R7). The fake Conn concatenates, so a byte-equality check proves losslessness.
func TestLargePasteSplit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newFakeConn()
	term := newFakeTerm(80, 24)

	// 3.5x the read chunk, a deterministic pattern.
	big := bytes.Repeat([]byte("0123456789abcdef"), (readChunk*7/2)/16)
	in := bytes.NewReader(big)
	errCh := runAsync(ctx, c, in, io.Discard, Options{Terminal: term})

	if err := waitErr(t, errCh); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if got := c.writtenBytes(); !bytes.Equal(got, big) {
		t.Errorf("large paste round-trip mismatch: got %d bytes, want %d (lossless split)", len(got), len(big))
	}
}

// --- panic-injecting fixtures ------------------------------------------------

// panicWriter panics on Write — drives the output pump's recover path.
type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("rawterm test: out write panic") }

// panicOnWriteConn panics inside Conn.Write — drives the stdin pump's recover.
type panicOnWriteConn struct {
	*fakeConn
}

func newPanicOnWriteConn() *panicOnWriteConn {
	return &panicOnWriteConn{fakeConn: newFakeConn()}
}

func (p *panicOnWriteConn) Write([]byte) (int, error) { panic("rawterm test: conn write panic") }

// --- small test utilities ----------------------------------------------------

// lockedBuf is a goroutine-safe bytes.Buffer (the output pump writes from its own
// goroutine while the test reads).
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor polls cond until true or a 3s deadline (a missed condition fails fast).
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within 3s")
}
