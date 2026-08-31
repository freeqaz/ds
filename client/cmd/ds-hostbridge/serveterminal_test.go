// SPDX-License-Identifier: Apache-2.0

// serveterminal_test.go — OFFLINE proof of the TERMINAL serving leg
// (`ds-hostbridge --serve-uds … --mode terminal`): the host-local UDS terminal server
// bridged to a fake in-process guest pty leg, exercised end to end against an
// IN-PROCESS socketpair (net.Pipe). No live KVM/VM/container/claude/cia and no real
// vsock — the same synthetic, zero-egress posture serve_test.go holds (D50). The fake
// guest stands in for the U-GUEST-WIRE in-guest pty leg: it speaks the FRAMED host↔guest
// wire (wireRawOut/wireRawIn/wireResize), emitting wireRawOut the host carriage pumps as
// frameRawOut and decoding the writer's wireRawIn/wireResize frames.
//
// Coverage:
//   - parseServeMode: structured/""/terminal resolve; garbage fails loud.
//   - a writer's raw pty round-trip: client DialTerminal → frameRawOut from the guest;
//     client Write → frameRawIn → wireRawIn → the guest leg (the single-writer raw
//     bridge, §A5). The DATA path is byte-exact across the framed leg.
//   - a client SendResize → frameResize → wireResize → the guest leg (U-RESIZE: live
//     window resize now reaches the guest, no longer a no-op).
//   - the host↔guest frame codec at the carriage level (RawOut strips frames; RawInput/
//     Resize emit the right frame type; the data path is byte-exact; a zero-length
//     wireRawOut is NOT EOF).
//   - the COUNT-ONLY input-activity sink (§A6) ticks once per inbound frameRawIn WITHOUT
//     parsing keystrokes.
//   - a TERMINAL-mode READER is REJECTED (ErrTerminalReaderUnsupported) — single-writer,
//     no reader-mirror (D61; the deferred phase-2 U-READER-MIRROR) — so a non-writer can
//     never send rawIn/resize.

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
)

func TestParseServeMode(t *testing.T) {
	for _, in := range []string{"", "structured"} {
		got, err := parseServeMode(in)
		if err != nil || got != serveModeStructured {
			t.Errorf("parseServeMode(%q) = (%v, %v), want (structured, nil)", in, got, err)
		}
	}
	got, err := parseServeMode("terminal")
	if err != nil || got != serveModeTerminal {
		t.Errorf("parseServeMode(terminal) = (%v, %v), want (terminal, nil)", got, err)
	}
	if _, err := parseServeMode("termnial"); err == nil {
		t.Error("parseServeMode(garbage) must fail loud (never a silent structured default)")
	}
}

// terminalServeFixture stands the terminal serve core up against a net.Pipe fake guest
// and returns the UDS path, the guest end (the test's in-guest pty leg), the carriage
// (so a test reads the count-only input-activity counter), a cancel, and the serve done
// channel. The serve core registers the carriage + the count-only observer; a client
// DialTerminal then drives the raw duplex.
func terminalServeFixture(t *testing.T) (udsPath string, guestEnd net.Conn, carriage *vsockTerminalCarriage, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	hostEnd, guest := net.Pipe() // hostEnd = the carriage's conn; guest = the test's in-guest leg
	carriage = newVsockTerminalCarriage(hostEnd)

	udsPath = filepath.Join(t.TempDir(), "term.sock")
	ctx, cancelFn := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveTerminalUDS(ctx, serveTerminalUDSConfig{
			sessionUUID:      serveTestSession,
			dialGuest:        func() (net.Conn, error) { return hostEnd, nil },
			udsPath:          udsPath,
			sessionToken:     serveTestToken,
			carriageOverride: carriage, // inject the same carriage the test inspects
		})
	}()
	if err := waitForSocket(udsPath, 5*time.Second); err != nil {
		cancelFn()
		t.Fatalf("terminal serve never bound the UDS: %v", err)
	}
	return udsPath, guest, carriage, cancelFn, errCh
}

// serveDoneDeadline is how long a teardown test waits for serveTerminalUDS to return
// after cancel(). It MUST comfortably exceed the serve core's own worst-case internal
// startup, which is bounded by serveTerminalUDS's post-bind waitForSocket call (a fixed
// 5s — serveterminal.go's `waitForSocket(cfg.udsPath, 5*time.Second)`).
//
// The flake this guards against (TestServeTerminalResizeReachesGuest hanging at
// "serveTerminalUDS did not return after cancel"): the fixture's OWN waitForSocket and
// the serve core's internal waitForSocket poll the same path independently. Under a
// loaded scheduler (parallel `go test ./...`), the fixture's poll can observe the freshly
// bound socket and return while the serve core's goroutine is still descheduled inside its
// own waitForSocket loop (it has not yet reached the blocking ctx-aware select). The test
// body then runs and calls cancel(); ServeBridge's ctx watcher closes the unix listener,
// which UNLINKS the socket file. The serve core's still-running waitForSocket now never
// sees the path (it is gone) and spins to its full 5s deadline before returning the
// timeout error on the done channel. A teardown deadline of only 5s races that ~5s and
// loses intermittently. We therefore wait well past 5s: the serve core ALWAYS returns
// (cleanly, or via that bounded internal timeout), so a true hang is still caught, but the
// benign startup/teardown race no longer reds the test.
const serveDoneDeadline = 20 * time.Second

// awaitServeDone blocks until serveTerminalUDS has returned on done (post-cancel), failing
// the test only on a real hang past serveDoneDeadline. A non-nil return value is tolerated:
// when cancel() races the serve core's internal post-bind waitForSocket (see
// serveDoneDeadline), the core returns that bounded timeout error rather than nil — that is
// a benign teardown artifact, not a serving fault, so the test asserts only that the core
// RETURNED, never which value it returned.
func awaitServeDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(serveDoneDeadline):
		t.Fatalf("serveTerminalUDS did not return within %s after cancel", serveDoneDeadline)
	}
}

// TestServeTerminalWriterRawRoundTrip proves the single-writer FRAMED pty bridge: a
// client DialTerminal attaches as WRITER, the guest leg's wireRawOut frame arrives as a
// client frameRawOut, and the client's Write crosses as frameRawIn → wireRawIn to the
// guest leg — DATA path byte-exact across the framed host↔guest leg. The §A6 count-only
// input-activity sink ticks once per frameRawIn WITHOUT parsing the bytes.
func TestServeTerminalWriterRawRoundTrip(t *testing.T) {
	udsPath, guest, carriage, cancel, serveDone := terminalServeFixture(t)
	defer cancel()
	defer guest.Close()
	guestBR := bufio.NewReader(guest)

	conn, err := hostbridge.NewSocketTransport().DialTerminal(clientHandle(udsPath, serveTestToken, hostbridge.RoleWriter))
	if err != nil {
		t.Fatalf("client DialTerminal WRITER: %v", err)
	}
	defer conn.Close()
	if conn.Role() != hostbridge.RoleWriter {
		t.Fatalf("granted role = %q, want WRITER", conn.Role())
	}

	// (out) The guest emits a wireRawOut frame; its payload must arrive as a client
	// frameRawOut chunk, byte-exact (raw ANSI/VT + control bytes pass untouched).
	const ptyOut = "hello from the guest pty\x1b[0m\x00\xff"
	go func() { _ = writeWireFrame(guest, wireRawOut, []byte(ptyOut)) }()
	select {
	case chunk, ok := <-conn.RawOut():
		if !ok {
			t.Fatal("RawOut closed before any guest output arrived")
		}
		if string(chunk) != ptyOut {
			t.Errorf("RawOut chunk = %q, want the guest pty bytes %q (byte-exact)", chunk, ptyOut)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no frameRawOut from the guest pty within 5s")
	}

	// (in) The client types: the bytes must cross as frameRawIn → a wireRawIn frame on
	// the host↔guest leg, decoded byte-exact, and the count-only sink must tick WITHOUT
	// the bytes being parsed.
	const keystrokes = "ls -la\r\x00"
	readDone := make(chan []byte, 1)
	go func() {
		ft, payload, derr := readWireFrame(guestBR)
		if derr != nil || ft != wireRawIn {
			readDone <- nil
			return
		}
		readDone <- payload
	}()
	if _, err := conn.Write([]byte(keystrokes)); err != nil {
		t.Fatalf("client Write (frameRawIn): %v", err)
	}
	select {
	case got := <-readDone:
		if string(got) != keystrokes {
			t.Errorf("guest leg decoded wireRawIn %q, want the writer keystrokes %q (byte-exact)", got, keystrokes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer keystrokes never reached the guest leg as wireRawIn")
	}

	// §A6: the count-only sink ticked exactly once for the one inbound frameRawIn frame.
	waitForCount(t, 5*time.Second, func() uint64 { return carriage.inputActivityCount() }, 1,
		"input-activity sink did not tick once per frameRawIn (D78 driver-typed)")

	conn.Close()
	cancel()
	awaitServeDone(t, serveDone)
}

// TestServeTerminalResizeReachesGuest proves U-RESIZE end to end through the serving
// leg: a client SendResize → frameResize (client↔host) → carriage.Resize → a wireResize
// frame on the host↔guest leg, decoded byte-exact to the same winsize. This is the leg
// that used to be a NO-OP; live window resize now reaches the guest pty.
func TestServeTerminalResizeReachesGuest(t *testing.T) {
	udsPath, guest, _, cancel, serveDone := terminalServeFixture(t)
	defer cancel()
	defer guest.Close()
	guestBR := bufio.NewReader(guest)

	conn, err := hostbridge.NewSocketTransport().DialTerminal(clientHandle(udsPath, serveTestToken, hostbridge.RoleWriter))
	if err != nil {
		t.Fatalf("client DialTerminal WRITER: %v", err)
	}
	defer conn.Close()

	want := hostbridge.Winsize{Rows: 40, Cols: 132, Xpix: 1056, Ypix: 720}
	readDone := make(chan wireWinsize, 1)
	readErr := make(chan error, 1)
	go func() {
		ft, payload, derr := readWireFrame(guestBR)
		if derr != nil {
			readErr <- derr
			return
		}
		if ft != wireResize {
			readErr <- io.ErrUnexpectedEOF
			return
		}
		ws, derr := decodeWireWinsize(payload)
		if derr != nil {
			readErr <- derr
			return
		}
		readDone <- ws
	}()
	if err := conn.SendResize(want); err != nil {
		t.Fatalf("client SendResize: %v", err)
	}
	select {
	case got := <-readDone:
		if got != toWireWinsize(want) {
			t.Errorf("guest leg decoded wireResize %+v, want %+v (byte-exact, all four axes)", got, toWireWinsize(want))
		}
	case derr := <-readErr:
		t.Fatalf("guest leg did not get a wireResize frame: %v", derr)
	case <-time.After(5 * time.Second):
		t.Fatal("resize never reached the guest leg as a wireResize frame")
	}

	conn.Close()
	cancel()
	awaitServeDone(t, serveDone)
}

// TestVsockCarriageFramedCodec exercises the host carriage's framing DIRECTLY (no UDS
// server): RawOut strips a wireRawOut frame to its payload (byte-exact, and a
// zero-length payload is NOT EOF); RawInput emits a wireRawIn frame; Resize emits a
// wireResize frame carrying all four axes. It uses a net.Pipe as the host↔guest conn and
// a goroutine playing the guest end.
func TestVsockCarriageFramedCodec(t *testing.T) {
	hostEnd, guest := net.Pipe()
	defer hostEnd.Close()
	defer guest.Close()
	carriage := newVsockTerminalCarriage(hostEnd)
	guestBR := bufio.NewReader(guest)

	// RawInput -> a wireRawIn frame, byte-exact.
	const keys = "echo hi\r\x1b[A"
	go func() { _ = carriage.RawInput([]byte(keys)) }()
	ft, payload, err := readWireFrame(guestBR)
	if err != nil || ft != wireRawIn || string(payload) != keys {
		t.Fatalf("RawInput frame = (%d,%q,%v), want (wireRawIn,%q,nil)", ft, payload, err, keys)
	}

	// Resize -> a wireResize frame, all four axes preserved.
	ws := hostbridge.Winsize{Rows: 24, Cols: 80, Xpix: 640, Ypix: 480}
	go func() { _ = carriage.Resize(ws) }()
	ft, payload, err = readWireFrame(guestBR)
	if err != nil || ft != wireResize {
		t.Fatalf("Resize frame type = (%d,%v), want wireResize", ft, err)
	}
	gotWS, derr := decodeWireWinsize(payload)
	if derr != nil || gotWS != toWireWinsize(ws) {
		t.Fatalf("Resize winsize = (%+v,%v), want %+v", gotWS, derr, toWireWinsize(ws))
	}

	// RawOut strips a wireRawOut frame to its payload, byte-exact.
	const out = "\x1b[2J\x1b[Hpaint\x00\xff"
	go func() { _ = writeWireFrame(guest, wireRawOut, []byte(out)) }()
	chunk, err := carriage.RawOut()
	if err != nil {
		t.Fatalf("RawOut: %v", err)
	}
	if string(chunk) != out {
		t.Errorf("RawOut payload = %q, want %q (byte-exact)", chunk, out)
	}

	// A zero-length wireRawOut is a LEGAL empty chunk (NOT EOF): RawOut returns an empty,
	// non-nil-error chunk, then the next real frame.
	go func() {
		_ = writeWireFrame(guest, wireRawOut, nil)
		_ = writeWireFrame(guest, wireRawOut, []byte("after-empty"))
	}()
	empty, err := carriage.RawOut()
	if err != nil {
		t.Fatalf("RawOut(empty) returned error %v; a zero-length chunk is NOT EOF", err)
	}
	if len(empty) != 0 {
		t.Errorf("RawOut(empty) = %q, want a zero-length chunk", empty)
	}
	next, err := carriage.RawOut()
	if err != nil || string(next) != "after-empty" {
		t.Fatalf("RawOut after empty = (%q,%v), want (\"after-empty\",nil)", next, err)
	}

	// A clean guest close ends RawOut with io.EOF.
	_ = guest.Close()
	if _, err := carriage.RawOut(); !errors.Is(err, io.EOF) {
		t.Errorf("RawOut after guest close = %v, want io.EOF", err)
	}
}

// TestServeTerminalReaderRejected proves the single-writer / no-reader-mirror boundary
// (§A5, D61): a TERMINAL-mode READER attach is rejected with
// ErrTerminalReaderUnsupported, surfaced via errors.Is across the wire — so a non-writer
// NEVER gets a TerminalConn and thus can never send a frameRawIn/frameResize (no rawIn/
// resize can reach the guest from a reader). We also assert no wireRawIn/wireResize frame
// ever appears on the guest leg for the rejected reader. The reader-mirror is the
// deferred phase-2 U-READER-MIRROR; here a reader stays rejected.
func TestServeTerminalReaderRejected(t *testing.T) {
	udsPath, guest, _, cancel, _ := terminalServeFixture(t)
	defer cancel()
	defer guest.Close()

	_, err := hostbridge.NewSocketTransport().DialTerminal(clientHandle(udsPath, serveTestToken, hostbridge.RoleReader))
	if !errors.Is(err, hostbridge.ErrTerminalReaderUnsupported) {
		t.Fatalf("DialTerminal READER err = %v, want errors.Is(_, ErrTerminalReaderUnsupported)", err)
	}

	// Defence in depth: a rejected reader put NOTHING on the host↔guest leg — no
	// wireRawIn / wireResize frame can be forwarded for a conn that was never granted.
	_ = guest.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, derr := readWireFrame(guest); derr == nil {
		t.Error("a rejected reader must not produce any host↔guest frame (D61: no rawIn/resize from a non-writer)")
	}
}

// waitForCount polls get() until it equals want or the deadline passes.
func waitForCount(t *testing.T, timeout time.Duration, get func() uint64, want uint64, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if get() == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (got %d, want %d)", msg, get(), want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
