// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"bytes"
	"context"
	"io"
	"sync"
	"syscall"
	"testing"
	"time"
)

// rwcPipe is an in-memory full-duplex ReadWriteCloser standing in for the FRAMED
// attach carriage (the guest UDS / vsock conn) on the host↔guest leg. It is a pair
// of io.Pipes: bytes the bridge WRITES (master->carriage, FRAMED wireRawOut) land on
// toHost (the test reads + decodes them as the "host"); bytes the test queues on
// fromHost (the "host"'s wireRawIn/wireResize frames) are READ + decoded by the
// bridge (carriage->master). Close closes both ends so a blocked bridge read unblocks
// — the raw-conn teardown discipline bridgePTY relies on. CloseWrite half-closes only
// the to-host (output) direction, mirroring a *net.UnixConn (the production carriage).
type rwcPipe struct {
	toHostR   *io.PipeReader // the test ("host") reads framed pty output here
	toHostW   *io.PipeWriter // the bridge writes framed pty output here
	fromHostR *io.PipeReader // the bridge reads framed host frames here
	fromHostW *io.PipeWriter // the test ("host") writes framed host frames here

	mu          sync.Mutex
	closed      bool
	writeClosed bool
}

func newRWCPipe() *rwcPipe {
	thR, thW := io.Pipe()
	fhR, fhW := io.Pipe()
	return &rwcPipe{toHostR: thR, toHostW: thW, fromHostR: fhR, fromHostW: fhW}
}

// Read serves the bridge's carriage->master direction (host frames to decode).
func (p *rwcPipe) Read(b []byte) (int, error) { return p.fromHostR.Read(b) }

// Write serves the bridge's master->carriage direction (framed pty output toward the host).
func (p *rwcPipe) Write(b []byte) (int, error) { return p.toHostW.Write(b) }

// Close closes BOTH directions: it ends the bridge's blocked carriage Read AND signals
// the host read EOF. Mirrors a net.Conn full close.
func (p *rwcPipe) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	_ = p.toHostW.Close()
	_ = p.fromHostR.Close()
	return nil
}

// CloseWrite half-closes only the to-host (output) direction: the host's read of pty
// output sees EOF, but the host->guest (carriage->master) direction stays open. This is
// the *net.UnixConn CloseWrite the production carriage exposes.
func (p *rwcPipe) CloseWrite() error {
	p.mu.Lock()
	p.writeClosed = true
	p.mu.Unlock()
	return p.toHostW.Close()
}

func (p *rwcPipe) wasCloseWrite() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.writeClosed
}

func (p *rwcPipe) wasClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// hostWriteFrame writes one host->guest frame (wireRawIn / wireResize) toward the
// bridge — the test acts as the host carriage end.
func (p *rwcPipe) hostWriteFrame(t wireFrameType, payload []byte) error {
	return writeWireFrame(p.fromHostW, t, payload)
}

// fakeMaster is an in-memory stand-in for the pty master: out is what the runtime
// "wrote to its pty" (the bridge reads it, frames each chunk as wireRawOut, and the
// host decodes it); in records what the bridge wrote toward the master (the decoded
// wireRawIn keystrokes, byte-exact). readErr, when set, is returned after out drains —
// the test uses syscall.EIO to simulate the pty-master hangup after the child exits.
// applied records every wireResize the bridge applied (TIOCSWINSZ stand-in), proving
// the resize control reached the master WITHOUT touching the data path.
type fakeMaster struct {
	out     *bytes.Reader // pty output the runtime emitted
	readErr error         // surfaced after out drains (e.g. EIO hangup)

	mu      sync.Mutex
	in      bytes.Buffer  // keystrokes the bridge delivered toward the master (byte-exact)
	applied []wireWinsize // winsizes applied via the TIOCSWINSZ seam
	eof     bool
}

func newFakeMaster(out []byte, readErr error) *fakeMaster {
	return &fakeMaster{out: bytes.NewReader(out), readErr: readErr}
}

func (m *fakeMaster) Read(b []byte) (int, error) {
	n, err := m.out.Read(b)
	if err == io.EOF {
		m.mu.Lock()
		m.eof = true
		m.mu.Unlock()
		if m.readErr != nil {
			return n, m.readErr // simulate the pty-master EIO hangup
		}
	}
	return n, err
}

func (m *fakeMaster) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.in.Write(b)
}

// applyWinsize satisfies winsizeApplier so masterApplier records the resize instead of
// issuing a real ioctl — the OFFLINE stand-in for TIOCSWINSZ on a real fd. This is the
// guest twin of the host carriage WRITING a wireResize frame: here the bridge DECODES
// it and applies it to the master.
func (m *fakeMaster) applyWinsize(ws wireWinsize) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied = append(m.applied, ws)
	return nil
}

func (m *fakeMaster) keystrokes() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.in.String()
}

func (m *fakeMaster) keystrokeBytes() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.in.Bytes()...)
}

func (m *fakeMaster) appliedWinsizes() []wireWinsize {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]wireWinsize(nil), m.applied...)
}

// gatedMaster is a pty-master stand-in whose Read first drains a queue of output
// chunks (each becomes one wireRawOut frame) and then BLOCKS until release is closed,
// returning io.EOF only then. This lets a test send host→guest frames (wireRawIn /
// wireResize) and assert their effect on the master BEFORE the master ends — so the
// output leg never closes the carriage out from under an in-flight host write. Write
// records keystrokes byte-exact; applyWinsize records resizes (the TIOCSWINSZ seam).
type gatedMaster struct {
	mu      sync.Mutex
	out     [][]byte // queued output chunks; one Read per chunk
	in      bytes.Buffer
	applied []wireWinsize
	release chan struct{} // closed to let the blocked Read return io.EOF
}

func newGatedMaster(out ...[]byte) *gatedMaster {
	return &gatedMaster{out: out, release: make(chan struct{})}
}

func (m *gatedMaster) Read(b []byte) (int, error) {
	m.mu.Lock()
	if len(m.out) > 0 {
		chunk := m.out[0]
		m.out = m.out[1:]
		m.mu.Unlock()
		return copy(b, chunk), nil
	}
	m.mu.Unlock()
	<-m.release // block until the test ends the session
	return 0, io.EOF
}

func (m *gatedMaster) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.in.Write(b)
}

func (m *gatedMaster) applyWinsize(ws wireWinsize) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied = append(m.applied, ws)
	return nil
}

func (m *gatedMaster) keystrokes() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.in.String()
}

func (m *gatedMaster) keystrokeBytes() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.in.Bytes()...)
}

func (m *gatedMaster) appliedWinsizes() []wireWinsize {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]wireWinsize(nil), m.applied...)
}

func (m *gatedMaster) end() { close(m.release) }

// hostReadAllFrames decodes every framed message the bridge wrote toward the host
// until the to-host direction EOFs, returning the CONCATENATED wireRawOut payloads
// (the reconstructed pty byte stream — must be byte-exact) and the count of rawOut
// frames seen. A non-rawOut frame on the guest->host direction is a test failure.
func hostReadAllFrames(t *testing.T, r io.Reader) (out []byte, frames int) {
	t.Helper()
	for {
		ft, payload, err := readWireFrame(r)
		if err == io.EOF {
			return out, frames
		}
		if err != nil {
			t.Fatalf("host decode frame: %v", err)
		}
		if ft != wireRawOut {
			t.Fatalf("guest->host frame type = %d, want wireRawOut(%d)", ft, wireRawOut)
		}
		out = append(out, payload...)
		frames++
	}
}

// TestBridgePTY_RawDuplex_ByteExact proves the FRAMED bidirectional bridge keeps the
// DATA path byte-exact: pty OUTPUT (master->carriage) reaches the host as wireRawOut
// payloads that CONCATENATE to the exact original bytes, and host KEYSTROKES
// (carriage->master, wireRawIn) reach the master byte-for-byte — NO data byte is
// inspected or altered. This is the in-guest twin of the host's vsockTerminalCarriage
// RawOut/RawInput, now over the framed leg.
func TestBridgePTY_RawDuplex_ByteExact(t *testing.T) {
	const ptyOut = "\x1b[2J\x1b[H\x1b[38;5;42mhello-TUI\x1b[0m\x00\xff\xfe" // ANSI/VT + raw/NUL bytes
	const keys = "\x03\x1b[Ayes\r\x00"                                      // Ctrl-C, up-arrow, raw keystrokes + NUL

	// A gated master so the keystroke (carriage->master) lands BEFORE the master EOFs:
	// it emits ptyOut as one chunk, then blocks on Read until end() — so the output leg
	// never closes the carriage out from under the in-flight host wireRawIn.
	master := newGatedMaster([]byte(ptyOut))
	carriage := newRWCPipe()

	// Collect + decode what the host receives as framed pty output.
	type hostResult struct {
		out    []byte
		frames int
	}
	hostDone := make(chan hostResult, 1)
	go func() {
		out, frames := hostReadAllFrames(t, carriage.toHostR)
		hostDone <- hostResult{out: out, frames: frames}
	}()

	done := make(chan error, 1)
	go func() { done <- bridgePTY(master, carriage) }()

	// Host sends a wireRawIn frame; wait for the keystrokes to reach the master byte-exact.
	if err := carriage.hostWriteFrame(wireRawIn, []byte(keys)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for master.keystrokes() != keys {
		if time.Now().After(deadline) {
			t.Fatalf("master received keystrokes %q; want %q (byte-exact, decoded from wireRawIn)", master.keystrokes(), keys)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// End the session: the master EOFs (output leg CloseWrites the carriage so the host
	// sees RawOut EOF) and the host closes its input direction.
	master.end()
	_ = carriage.fromHostW.Close()

	if err := <-done; err != nil {
		t.Fatalf("bridgePTY returned error: %v", err)
	}
	res := <-hostDone

	if !bytes.Equal(res.out, []byte(ptyOut)) {
		t.Errorf("host reconstructed pty output %q; want %q (byte-exact across frames)", res.out, ptyOut)
	}
	if res.frames == 0 {
		t.Error("host saw no wireRawOut frames; want at least one")
	}
	// The output direction must half-close the carriage when the pty drains so the host
	// sees EOF on RawOut.
	if !carriage.wasCloseWrite() {
		t.Error("bridgePTY should CloseWrite the carriage when the pty output EOFs")
	}
}

// TestBridgePTY_ResizeAppliesTIOCSWINSZ proves a wireResize frame round-trips
// host->guest and is APPLIED to the pty master (the TIOCSWINSZ seam) — WITHOUT any
// resize byte leaking into the data path. The bridge decodes the 8-byte BE
// rows|cols|xpix|ypix payload and calls the master's applyWinsize; the master records
// it. The DATA path (keystrokes after the resize) stays byte-exact.
func TestBridgePTY_ResizeAppliesTIOCSWINSZ(t *testing.T) {
	master := newGatedMaster() // no pty output; blocks on Read until end() (no early carriage close)
	carriage := newRWCPipe()

	// Drain (and discard) any framed pty output so the output leg is never back-pressured.
	go func() { _, _ = io.Copy(io.Discard, carriage.toHostR) }()

	done := make(chan error, 1)
	go func() { done <- bridgePTY(master, carriage) }()

	const wantRows, wantCols, wantXpix, wantYpix = 50, 200, 1600, 900
	want := wireWinsize{rows: wantRows, cols: wantCols, xpix: wantXpix, ypix: wantYpix}

	// Host sends a wireResize, then a wireRawIn AFTER it (proving the data path is
	// unaffected by the interleaved control).
	if err := carriage.hostWriteFrame(wireResize, encodeWireWinsize(want)); err != nil {
		t.Fatal(err)
	}
	const afterResizeKeys = "echo sized\r"
	if err := carriage.hostWriteFrame(wireRawIn, []byte(afterResizeKeys)); err != nil {
		t.Fatal(err)
	}

	// Wait for BOTH the resize to land (TIOCSWINSZ seam) and the post-resize keystrokes
	// to reach the master — proving the control applied AND the data path stayed exact.
	deadline := time.Now().Add(2 * time.Second)
	for {
		applied := master.appliedWinsizes()
		keys := master.keystrokes()
		if len(applied) == 1 && keys == afterResizeKeys {
			if applied[0] != want {
				t.Fatalf("applied winsize = %+v; want %+v", applied[0], want)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resize/keys never landed (applied=%v keys=%q)", master.appliedWinsizes(), master.keystrokes())
		}
		time.Sleep(2 * time.Millisecond)
	}

	// No resize byte leaked into the keystroke (data) stream.
	if bytes.Contains(master.keystrokeBytes(), encodeWireWinsize(want)) {
		t.Error("resize payload bytes leaked into the pty data path")
	}

	// End the session: close the host input direction AND release the master Read.
	_ = carriage.fromHostW.Close()
	master.end()
	if err := <-done; err != nil {
		t.Fatalf("bridgePTY returned error: %v", err)
	}
}

// TestBridgePTY_ZeroLengthRawInIsNoOpNotEOF proves a zero-length wireRawIn frame is a
// tolerated NO-OP (it is NOT treated as EOF / session-end): the bridge keeps decoding,
// and a following non-empty wireRawIn still reaches the master byte-exact. It also
// proves a zero-length MASTER read is not mistaken for EOF — the bridge keeps pumping
// and a following real output chunk still reaches the host.
func TestBridgePTY_ZeroLengthRawInIsNoOpNotEOF(t *testing.T) {
	// The master yields a zero-length output read (no bytes, no error) THEN a real chunk
	// THEN blocks — proving a zero-length read is not EOF (the real chunk still arrives).
	master := newGatedMaster([]byte{}, []byte("payload"))
	carriage := newRWCPipe()

	type hostResult struct {
		out    []byte
		frames int
	}
	hostDone := make(chan hostResult, 1)
	go func() {
		out, frames := hostReadAllFrames(t, carriage.toHostR)
		hostDone <- hostResult{out: out, frames: frames}
	}()

	done := make(chan error, 1)
	go func() { done <- bridgePTY(master, carriage) }()

	// A zero-length wireRawIn from the host is a tolerated no-op (not a session end),
	// then a real frame.
	if err := carriage.hostWriteFrame(wireRawIn, nil); err != nil {
		t.Fatal(err)
	}
	if err := carriage.hostWriteFrame(wireRawIn, []byte("k")); err != nil {
		t.Fatal(err)
	}

	// The non-empty keystroke reached the master byte-exact despite the preceding empty
	// frame (the session did NOT end on the zero-length wireRawIn).
	deadline := time.Now().Add(2 * time.Second)
	for master.keystrokes() != "k" {
		if time.Now().After(deadline) {
			t.Fatalf("master keystrokes = %q; want %q (zero-length wireRawIn was not a no-op)", master.keystrokes(), "k")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// End the session and confirm the real output chunk reached the host (the zero-length
	// master read was not EOF).
	_ = carriage.fromHostW.Close()
	master.end()
	if err := <-done; err != nil {
		t.Fatalf("bridgePTY returned error: %v", err)
	}
	res := <-hostDone
	if string(res.out) != "payload" {
		t.Errorf("host reconstructed %q; want %q (zero-length master read was not EOF)", res.out, "payload")
	}
}

// TestBridgePTY_PTYHangupIsClean proves the pty-master EIO hangup (the child exited and
// the last slave reference closed) is treated as a CLEAN end of session, not a bridge
// error — mirroring transport.go's isPTYHangup discipline. The carriage->master leg is
// ended by closing the carriage; bridgePTY must return nil.
func TestBridgePTY_PTYHangupIsClean(t *testing.T) {
	master := newFakeMaster([]byte("final-paint"), syscall.EIO) // EIO after the output drains
	carriage := newRWCPipe()

	// Drain framed pty output as the host so master->carriage completes.
	go func() { _, _ = io.Copy(io.Discard, carriage.toHostR) }()

	done := make(chan error, 1)
	go func() { done <- bridgePTY(master, carriage) }()

	// After the pty hangs up, master->carriage CloseWrites; the host->guest direction is
	// still open, so close the carriage (as the host would on RawOut EOF) to end it.
	time.Sleep(100 * time.Millisecond)
	_ = carriage.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pty EIO hangup must be a clean end (nil); got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridgePTY did not return after the pty hangup + carriage close")
	}
}

// TestBridgePTY_HalfCloseTearsDownOtherSide proves closing one side tears down the
// other: when the host hangs up the carriage (the host->guest direction EOFs), the
// carriage->master goroutine does a FULL carriage.Close(), which aborts the in-flight
// master->carriage frame write (its write to the now-closed carriage fails) — so
// bridgePTY RETURNS instead of hanging on the still-producing master. A regression that
// did NOT close the carriage on the carriage->master EOF would leave master->carriage
// blocked on its write and the bridge would hang until the deadline.
//
// We drive a master that produces output indefinitely (a never-closed io.Pipe whose
// writer keeps the source alive), so master->carriage is genuinely in flight (not
// already EOF'd) when the host hangs up — proving the cross-teardown, not a lucky race.
func TestBridgePTY_HalfCloseTearsDownOtherSide(t *testing.T) {
	srcR, srcW := io.Pipe() // the master's "pty output" source; never EOF'd by the test
	master := &streamingMaster{r: srcR}
	carriage := newRWCPipe()

	// The host does NOT drain pty output: we want master->carriage to be blocked/active
	// on its WRITE when the host hangs up, so the carriage.Close() must abort it.
	// Feed a little output so the copy is mid-stream.
	go func() {
		for i := 0; i < 3; i++ {
			if _, err := srcW.Write([]byte("paint")); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		// leave srcW open: the master never EOFs on its own.
	}()

	done := make(chan error, 1)
	go func() { done <- bridgePTY(master, carriage) }()

	// Give the bridge a beat to start copying, then the host hangs up the carriage
	// (full close, both directions) — the carriage->master read EOFs and its goroutine
	// full-closes the carriage, which must tear down the master->carriage side too.
	time.Sleep(50 * time.Millisecond)
	_ = carriage.Close()

	select {
	case err := <-done:
		// A clean host-driven teardown: closed-conn / closed-pipe errors are swallowed
		// as the normal teardown (isTeardownClose), so the bridge returns nil.
		if err != nil {
			t.Errorf("host-close teardown should be clean; got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridgePTY did not tear down when the carriage was closed (closing one side did not tear down the other)")
	}
	_ = srcW.Close() // release the feeder goroutine
}

// streamingMaster is a master whose Read drains an io.Pipe (its "pty output" source) and
// whose Write records keystrokes — used to keep master->carriage genuinely in flight
// while the host hangs up, proving the cross-teardown.
type streamingMaster struct {
	r  *io.PipeReader
	mu sync.Mutex
	in bytes.Buffer
}

func (m *streamingMaster) Read(b []byte) (int, error) { return m.r.Read(b) }
func (m *streamingMaster) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.in.Write(b)
}

// TestWireFrameCodec_RoundTrip is a unit check of the leg-local codec: writeWireFrame
// then readWireFrame round-trips the type + payload (including an empty payload), and a
// length over the cap is a clean error, never a panic.
func TestWireFrameCodec_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ft      wireFrameType
		payload []byte
	}{
		{"rawOut", wireRawOut, []byte("\x1b[0mraw\x00\xff")},
		{"rawIn", wireRawIn, []byte("keys\r")},
		{"resize", wireResize, encodeWireWinsize(wireWinsize{rows: 24, cols: 80})},
		{"empty-rawOut", wireRawOut, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeWireFrame(&buf, tc.ft, tc.payload); err != nil {
				t.Fatalf("writeWireFrame: %v", err)
			}
			ft, payload, err := readWireFrame(&buf)
			if err != nil {
				t.Fatalf("readWireFrame: %v", err)
			}
			if ft != tc.ft {
				t.Errorf("type = %d; want %d", ft, tc.ft)
			}
			if !bytes.Equal(payload, tc.payload) {
				t.Errorf("payload = %q; want %q", payload, tc.payload)
			}
		})
	}
}

// TestDecodeWireWinsize_Malformed proves a non-8-byte resize payload is a clean error
// (never a panic), so a malformed control is dropped, not a crash.
func TestDecodeWireWinsize_Malformed(t *testing.T) {
	for _, n := range []int{0, 1, 7, 9, 16} {
		if _, err := decodeWireWinsize(make([]byte, n)); err == nil {
			t.Errorf("decodeWireWinsize(%d bytes) = nil error; want a clean error", n)
		}
	}
	ws, err := decodeWireWinsize(encodeWireWinsize(wireWinsize{rows: 1, cols: 2, xpix: 3, ypix: 4}))
	if err != nil {
		t.Fatalf("decodeWireWinsize(8 bytes): %v", err)
	}
	if (ws != wireWinsize{rows: 1, cols: 2, xpix: 3, ypix: 4}) {
		t.Errorf("decoded winsize = %+v; want {1 2 3 4}", ws)
	}
}

// TestBridgePTY_UnknownFrameEndsSession proves an unknown host frame type is a clean
// protocol fault that ends the in leg (and thus the session) rather than wedging or
// being silently consumed. bridgePTY returns a non-nil error naming the bad frame.
//
// The master NEVER EOFs on its own (a never-closed io.Pipe source) so the ONLY way the
// session ends is the unknown frame — making this a deterministic check of the
// protocol-fault path, not a race against a self-ending pty.
func TestBridgePTY_UnknownFrameEndsSession(t *testing.T) {
	srcR, srcW := io.Pipe()
	defer srcW.Close() // release the master's blocked Read at test end
	master := &streamingMaster{r: srcR}
	carriage := newRWCPipe()

	// Feed the master output the host does NOT drain, so the master->carriage (output)
	// leg blocks on a wireRawOut WRITE — that way the fault-path carriage.Close() aborts
	// it and bridgePTY can return (closing the carriage cannot unblock a master READ).
	go func() {
		for {
			if _, err := srcW.Write([]byte("paint")); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	time.Sleep(20 * time.Millisecond) // let the output leg get back-pressured on a write

	done := make(chan error, 1)
	go func() { done <- bridgePTY(master, carriage) }()

	// An unknown frame type (99) — the in leg returns a fault and closes the carriage,
	// which aborts the blocked output write so the whole bridge unwinds with the fault.
	if err := carriage.hostWriteFrame(wireFrameType(99), []byte("bogus")); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an unknown host frame must end the session with an error; got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridgePTY did not return after an unknown frame")
	}
}

// TestSupervise_StructuredPathUnchanged_NoPTYBridge is the byte-identical invariant: a
// config with NO pty (the historical pipes disposition, stdio.ptyMaster == nil) drives
// the STRUCTURED bridge() path verbatim — stdout->socket, socket->stdin, stderr drain —
// and bridgePTY is NEVER reached. We run the full supervisor with the pipes
// helperLauncher (ptyMaster stays nil) and assert the structured outcome: clean exit,
// ReportReady once, ReportExit(completed), and the runtime output reaching the socket
// via the structured stdout->socket leg (which a raw pty bridge would NOT produce).
func TestSupervise_StructuredPathUnchanged_NoPTYBridge(t *testing.T) {
	rep := &recordingReporter{}
	sock := newPipeSocket()
	d := &fakeDialer{sock: sock}
	// helperLauncher uses execLauncher => three pipes => runtimeStdio.ptyMaster == nil.
	sup := newSupervisorFor(t, "emit-then-exit", rep, d)

	code, err := sup.run(context.Background(), cfgForSupervise())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("structured exit code = %d; want 0", code)
	}
	if rep.ready != 1 {
		t.Errorf("ReportReady = %d; want 1", rep.ready)
	}
	if len(rep.exits) != 1 || rep.exits[0] != exitReasonCompleted {
		t.Errorf("exit reasons = %v; want [completed] (structured path unchanged)", rep.exits)
	}
	// The structured stdout->socket leg carried the runtime output to the socket. A raw
	// pty bridge would never have run for a pipes config; this asserts the structured
	// surface produced it.
	sock.mu.Lock()
	got := sock.written.String()
	sock.mu.Unlock()
	if got != "runtime-output" {
		t.Errorf("structured stdout->socket carried %q; want %q (bridge() path, not bridgePTY)", got, "runtime-output")
	}
}
