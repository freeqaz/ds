// SPDX-License-Identifier: Apache-2.0

// pty_scenario.go — the TERMINAL (PTY-mode) acceptance tier of the live-drive
// engine (docs/serpent-cli-mvp/08-spike-and-acceptance.md §4.5, U-LIVE-E2E). Where
// live_drive.go drives the STRUCTURED attach.v1 surface (events in, DriveInput/
// DriveGrant out) and script.go steps a multi-turn JSONL over it, THIS file drives
// the RAW-TERMINAL surface: the dev's terminal IS the in-VM Claude Code — stdin
// keystrokes ride frameRawIn, the in-guest pty's output rides frameRawOut, and a
// SIGWINCH becomes a frameResize (client/hostbridge/socket.go tags 11-14).
//
// THE TWO TIERS, ONE SCENARIO (mirroring the structured engine's fake/live split):
//
//   - FAKE-PTY (always-on, offline, in the wave gate): an in-process terminal
//     server (NewServer + AddSession + SetTerminalCarriage + Serve over a UDS) is
//     fronted by a SYNTHETIC pty carriage (scriptedCarriage) that echoes a scripted
//     terminal stream on each keystroke. The REAL client carrier (a
//     *hostbridge.TerminalConn dialed by SocketTransport.DialTerminal) is driven by
//     the SAME raw-pump shape serpent-tui's rawterm.Run uses (stdin→Conn.Write,
//     Conn.RawOut→stdout, the connect-resize on attach) — so the broker + frames +
//     raw client carrier are exercised end to end with NO real pty, NO VM, NO
//     claude. This is the U-FRAMES in-process UDS round-trip reused as an
//     acceptance fixture.
//
//     MODULE HYGIENE (D80): the client module imports only proto/gen/go cross-tree,
//     and serpent-tui is a SEPARATE module (GOWORK=off, internal/rawterm) the
//     client cannot import. So the harness drives the rawterm.Conn CONTRACT
//     (RawOut/Write/SendResize/Done/Close) — which *hostbridge.TerminalConn
//     satisfies verbatim — through the thin termPump replicated here (the ~30-line
//     stdin↔Write / RawOut↔stdout copy rawterm.Run wraps), not serpent-tui's
//     package. The carrier, frames, broker, and DialTerminal handshake under test
//     are the production ones; only the terminal-owning shell (raw-mode/alt-screen/
//     SIGWINCH, which a headless harness has no real tty for anyway) is local.
//
//   - LIVE KVM (gated DS_KVM_LIVE=1 + DS_KVM_LIVE_PTY=1): the SAME TermScenario
//     drives a REAL terminal-mode VM session's RAW_TERMINAL writer seat (resolved
//     from DS_KVM_LIVE_*), asserting on a rendered-grid substring + a /work
//     side-effect proof. It launches NO podman/claude itself (the live VM already
//     serves the seat) — the transport-target swap, exactly like DriveKVMScripted.
//
// THE ASSERTION DISCIPLINE (08 §4.4, §2.4): a terminal byte stream is noisy
// (equivalent escape encodings, incidental redraws, cursor jitter), so we NEVER
// assert raw-byte equality. The scenario canonicalizes the accumulated pty output
// into a small rendered grid (renderGrid: a minimal VT applier — printable runs,
// CR/LF, and ESC[...m SGR stripped) and asserts on grid SUBSTRINGS (a banner, a
// prompt, an echoed line). This is the terminal twin of fidelity/canon.go's
// id-relative structural compare for the structured stream.
//
// D144 (the PTY-mode ask surface, 08 §4.2): in terminal mode the permission ask is
// CC's OWN native in-terminal prompt — there is NO ask.requested / DriveGrant frame
// on the raw carriage (those are the STRUCTURED writer surface). The TermStep models
// this directly: a step's Send carries the human's `y`/`n` BYTES into the pty byte
// stream, and ExpectGridContains asserts the prompt + the post-answer effect render
// in frameRawOut. The carriage carries opaque keystrokes; it parses nothing.
//
// Pure stdlib + client/hostbridge (no serpent-tui import — D80 module hygiene; the
// rawterm.Conn contract is mirrored locally as termConn). The offline tier touches
// no real pty/VM/claude; the gated tier dials a pre-advertised live writer seat.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
)

// termConn is the raw byte/resize seam DriveTermScenario drives — the exact shape
// of serpent-tui's rawterm.Conn (RawOut/Write/SendResize/Done/Close), declared
// LOCALLY because the client module cannot import serpent-tui's internal package
// (D80; separate GOWORK=off module). *hostbridge.TerminalConn — the PRODUCTION
// client carrier — satisfies this interface verbatim, so the fleet tier drives the
// real frames/broker/DialTerminal carrier through it; a test fake can also satisfy
// it. It mirrors rawterm.Conn so the harness exercises the same contract the real
// client does.
type termConn interface {
	RawOut() <-chan []byte
	Write(p []byte) (int, error)
	SendResize(ws hostbridge.Winsize) error
	Done() <-chan error
	Close() error
}

// compile-time proof the production carrier satisfies the local seam (so a drift in
// hostbridge.TerminalConn's surface is caught here, not at a live run).
var _ termConn = (*hostbridge.TerminalConn)(nil)

// TermStep is one step of a scripted TERMINAL drive: a chunk of keystroke bytes to
// send into the in-VM CC pty (frameRawIn) and the grid substring(s) the resulting
// pty output (frameRawOut) must render after the step settles. It is runtime-
// ignorant (no CC vocabulary) — Send is opaque terminal input, ExpectGridContains
// is asserted on the canonicalized rendered grid, never on raw bytes.
type TermStep struct {
	// Send is the keystroke byte sequence driven into the pty this step (e.g. a
	// command line ending in "\r", or a single "y" answering a native ask). Empty
	// Send is a pure wait-and-assert step (e.g. the initial banner before any
	// input). Bytes are forwarded verbatim; the carriage never parses them.
	Send string `json:"send"`
	// ExpectGridContains are substrings the rendered grid (renderGrid over the
	// accumulated frameRawOut) must contain after this step settles. Each is matched
	// against the canonicalized grid (SGR/control stripped), never the raw stream.
	// Empty ⇒ the step only sends (no output assertion).
	ExpectGridContains []string `json:"expect_grid_contains,omitempty"`
	// ExpectNativePrompt, when set, additionally asserts the rendered grid carries a
	// native in-terminal ask prompt marker (D144: the PTY ask surface is CC's own
	// prompt, NOT an attach.v1 ask.requested frame). It is shorthand for asserting
	// the prompt glyph renders; the operator pins the exact text in
	// ExpectGridContains. Default false.
	ExpectNativePrompt bool `json:"expect_native_prompt,omitempty"`
}

// TermScenario is a scripted TERMINAL drive: an ordered list of TermSteps plus the
// per-step settle window the grid assertion polls within. It is the raw-terminal
// analogue of script.go's []Turn + DriveScriptScenario — runtime-ignorant, so the
// SAME scenario drives the fake-pty fleet path and the real KVM writer seat.
type TermScenario struct {
	// Steps is the ordered keystroke→grid exchange. At least one step is required.
	Steps []TermStep
	// SettleTimeout bounds how long each step polls for its ExpectGridContains to
	// render before failing. Zero ⇒ a sensible default (5s offline, generous for the
	// live tier where it is overridden).
	SettleTimeout time.Duration
}

// nativePromptMarkers are the substrings any of which signals CC's own native
// in-terminal permission prompt rendered in the byte stream (D144). CC's prompt is
// an interactive numbered/y-n menu ("Do you want to proceed?", a "❯" selector, a
// "(y/n)" affordance); a fake fixture renders a deterministic one of these. The set
// is matched case-insensitively against the rendered grid.
var nativePromptMarkers = []string{"(y/n)", "do you want to proceed", "❯", "1. yes", "allow?"}

// DriveTermScenario runs scenario over the given termConn (a real
// *hostbridge.TerminalConn in both tiers), capturing the pty output stream and
// asserting each step's grid substrings. It is the shared core both tiers call:
//
//  1. start termPump over conn — the SAME raw-pump shape rawterm.Run wraps:
//     stdin(in-pipe)→Conn.Write, Conn.RawOut→stdout(capture buffer), plus the
//     connect-resize on attach (an initial SendResize so CC paints at the right
//     size from frame 1, §2.3/§A7) — with NO real tty (the harness has none);
//  2. for each step: write Send to the in-pipe, then poll the captured output's
//     rendered grid until every ExpectGridContains substring appears (and, if
//     ExpectNativePrompt, a native-prompt marker) or SettleTimeout elapses;
//  3. after the last step, close the in-pipe (EOF ⇒ the pump returns) and the conn
//     (releases the seat / ends the carriage), drain, and return the full captured
//     raw output + its final rendered grid for any side-effect / structural
//     assertions the caller layers on.
//
// It speaks ONLY the raw-terminal surface (no attach.v1 events, no DriveGrant) — the
// D144 invariant is structural: there is no grant path on this carriage at all.
func DriveTermScenario(ctx context.Context, conn termConn, scenario TermScenario) (*TermResult, error) {
	if len(scenario.Steps) == 0 {
		return nil, errors.New("e2e: TermScenario has no steps")
	}
	settle := scenario.SettleTimeout
	if settle <= 0 {
		settle = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The keystroke source: an in-process pipe whose write end the scenario feeds
	// per step and whose read end is the pump's stdin. Closing the write end is the
	// clean end-of-scenario EOF (the pump returns on stdin close).
	inR, inW := io.Pipe()
	// The pty output sink: the pump writes the in-VM pty output here; a mutexed
	// buffer accumulates it for the grid assertions.
	out := &syncBuffer{}

	// The connect-resize (§2.3/§A7): seed an 80x24 window before any input so the
	// guest pty is sized from frame 1 (no 80x24-then-reflow jump on a real CC). A
	// resize error is non-fatal (the guest falls back to its launch-seeded size).
	_ = conn.SendResize(hostbridge.Winsize{Rows: 24, Cols: 80})

	runDone := make(chan error, 1)
	go func() { runDone <- termPump(ctx, conn, inR, out) }()

	// Step the scenario: feed each Send, then wait for its grid expectation.
	stepErr := func() error {
		for i, step := range scenario.Steps {
			if step.Send != "" {
				if _, err := inW.Write([]byte(step.Send)); err != nil {
					return fmt.Errorf("step %d: write keystrokes: %w", i+1, err)
				}
			}
			if len(step.ExpectGridContains) == 0 && !step.ExpectNativePrompt {
				continue // pure send step
			}
			if err := waitForGrid(ctx, out, step, settle); err != nil {
				return fmt.Errorf("step %d: %w", i+1, err)
			}
		}
		return nil
	}()

	// End the drive: close the keystroke source (stdin EOF) so the pump returns
	// cleanly, then close the conn (releases the seat / ends the carriage) and wait
	// for the pump to unwind.
	_ = inW.Close()
	_ = conn.Close()
	var runErr error
	select {
	case runErr = <-runDone:
	case <-time.After(10 * time.Second):
		runErr = errors.New("term pump did not return after stdin close + conn close")
	}

	if stepErr != nil {
		return nil, stepErr
	}
	// A clean stdin EOF / session-end is nil; a transport fault is the cause.
	if runErr != nil {
		return nil, fmt.Errorf("e2e: terminal drive transport: %w", runErr)
	}

	raw := out.bytes()
	return &TermResult{RawOutput: raw, FinalGrid: renderGrid(raw)}, nil
}

// termPump is the minimal raw byte duplex rawterm.Run wraps (sans the terminal-
// owning shell): it copies in→conn.Write (keystrokes) and conn.RawOut→out (pty
// output), and ends on whichever leg finishes first — stdin EOF (clean local end),
// the output stream closing (RawOut closed = session end), conn.Done (the carriage
// ended), or ctx cancel. It is the exact contract serpent-tui's pumpStdin/pumpOutput
// drive, replicated here so the harness exercises the real carrier without importing
// the serpent-tui internal package (D80).
func termPump(ctx context.Context, conn termConn, in io.Reader, out io.Writer) error {
	// (a) output pump: RawOut → out, until the stream closes (session end).
	outDone := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				outDone <- ctx.Err()
				return
			case chunk, ok := <-conn.RawOut():
				if !ok {
					outDone <- nil // RawOut closed: a clean session end
					return
				}
				if len(chunk) == 0 {
					continue // an empty frameRawOut carries nothing (not EOF)
				}
				if _, werr := out.Write(chunk); werr != nil {
					outDone <- werr
					return
				}
			}
		}
	}()

	// (b) input pump: in → conn.Write, in bounded chunks (a large paste splits
	// losslessly across frames — a pty byte stream has no record boundary).
	inDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			if ctx.Err() != nil {
				inDone <- ctx.Err()
				return
			}
			n, rerr := in.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					inDone <- werr
					return
				}
			}
			if rerr != nil {
				inDone <- rerr // io.EOF on a clean stdin close
				return
			}
		}
	}()

	// (c) the select: whichever leg ends first wins. stdin EOF and a clean RawOut
	// close are not faults; conn.Done / a write fault are.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-inDone:
		if errors.Is(err, io.EOF) || err == nil {
			return nil // stdin closed: a clean local end
		}
		return err
	case err := <-outDone:
		return err
	case err := <-conn.Done():
		return err
	}
}

// TermResult is the outcome of a TermScenario drive: the full captured pty output
// (raw-class; never committed — a live capture carries session bytes) and its final
// rendered grid (the canonicalized, SGR/control-stripped text the assertions read).
type TermResult struct {
	// RawOutput is every frameRawOut byte the client wrote to its stdout, in order.
	RawOutput []byte
	// FinalGrid is renderGrid(RawOutput) — the canonicalized rendered text.
	FinalGrid string
}

// waitForGrid polls out's rendered grid until every substring in step appears (and,
// if ExpectNativePrompt, a native-prompt marker) or the settle window elapses. It
// returns a precise diagnostic (which substring is missing + the rendered grid) so
// a failure is reviewable, never a bare timeout.
func waitForGrid(ctx context.Context, out *syncBuffer, step TermStep, settle time.Duration) error {
	deadline := time.Now().Add(settle)
	for {
		grid := renderGrid(out.bytes())
		missing := ""
		for _, want := range step.ExpectGridContains {
			if !strings.Contains(grid, want) {
				missing = want
				break
			}
		}
		promptOK := !step.ExpectNativePrompt || containsAnyFold(grid, nativePromptMarkers)
		if missing == "" && promptOK {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			if missing != "" {
				return fmt.Errorf("grid did not render %q within %s; rendered grid:\n%s", missing, settle, grid)
			}
			return fmt.Errorf("native ask prompt did not render within %s (D144); rendered grid:\n%s", settle, grid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// containsAnyFold reports whether s contains any of subs, case-insensitively.
func containsAnyFold(s string, subs []string) bool {
	low := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(low, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// renderGrid canonicalizes a raw terminal byte stream into plain rendered text — a
// MINIMAL VT applier sufficient for substring assertions, not a full terminal
// emulator (08 §4.4: assert on a small rendered grid, never raw bytes). It:
//
//   - strips CSI sequences (ESC [ ... final-byte), the bulk of which is SGR color
//     (…m), cursor moves, and erase — none of which carry assertable TEXT;
//   - strips OSC sequences (ESC ] … BEL|ST), e.g. title/hyperlink set;
//   - drops other ESC-introduced two-byte sequences (ESC ( B, ESC =, etc.);
//   - normalizes CR to nothing and keeps LF as a line break, and drops other C0
//     control bytes except TAB (rendered as a space) — so a backspace/redraw does
//     not inject a literal control glyph into the assertion text;
//   - passes printable bytes (incl. UTF-8 multibyte, e.g. box glyphs / ❯) through.
//
// The result is the visible text a human would read, with color and cursor motion
// erased — stable across equivalent escape encodings, which is exactly the
// perturbation-tolerance the fidelity harness mandates. It is deliberately small:
// a redraw that overwrites a line in place is NOT collapsed (we keep both the old
// and new text), so an assertion must target text that is PRINTED, not text that
// happens to occupy a final cursor cell — which is the right discipline for a
// deterministic low-entropy fixture (a banner/prompt/echoed line is printed once).
func renderGrid(raw []byte) string {
	var sb strings.Builder
	i := 0
	n := len(raw)
	for i < n {
		b := raw[i]
		switch {
		case b == 0x1b: // ESC — start of an escape sequence
			i = skipEscape(raw, i)
		case b == '\r':
			i++ // carriage return: drop (LF carries the line break)
		case b == '\n':
			sb.WriteByte('\n')
			i++
		case b == '\t':
			sb.WriteByte(' ')
			i++
		case b < 0x20 || b == 0x7f:
			i++ // other C0 control / DEL: drop (no assertable text)
		default:
			sb.WriteByte(b) // printable (incl. UTF-8 continuation bytes)
			i++
		}
	}
	return sb.String()
}

// skipEscape advances past one ESC-introduced sequence starting at i (raw[i] ==
// 0x1b) and returns the index just past it. It handles CSI (ESC [ … final 0x40-0x7e),
// OSC (ESC ] … BEL or ST), and the common short ESC sequences (ESC followed by a
// single intermediate/final byte). An ESC at end-of-buffer or an unterminated CSI/OSC
// consumes to end-of-buffer (a truncated capture never injects stray glyphs).
func skipEscape(raw []byte, i int) int {
	n := len(raw)
	// i points at ESC.
	if i+1 >= n {
		return n
	}
	switch raw[i+1] {
	case '[': // CSI: ESC [ params/intermediates final(0x40-0x7e)
		j := i + 2
		for j < n {
			c := raw[j]
			if c >= 0x40 && c <= 0x7e {
				return j + 1 // consumed the final byte
			}
			j++
		}
		return n // unterminated CSI
	case ']': // OSC: ESC ] … (BEL | ESC \)
		j := i + 2
		for j < n {
			if raw[j] == 0x07 { // BEL terminator
				return j + 1
			}
			if raw[j] == 0x1b && j+1 < n && raw[j+1] == '\\' { // ST terminator
				return j + 2
			}
			j++
		}
		return n // unterminated OSC
	default:
		// A short ESC sequence (ESC = , ESC ( B , ESC > , …): consume ESC + the next
		// byte. This is an approximation sufficient for the fixture's escape set.
		return i + 2
	}
}

// --- the in-process terminal server (the FAKE-PTY fleet tier) -----------------

// scriptedCarriage is the FAKE in-VM pty: a synthetic hostbridge.TerminalCarriage
// that drives a deterministic terminal stream in response to keystrokes, with NO
// real pty, VM, or claude. It is the terminal twin of the structured fake-CC: it
// stands in for the in-guest pty master so the broker + frames + real client raw
// path are exercised end to end offline.
//
// Its behavior is a small reactive script: it emits a fixed BANNER immediately on
// attach, then for each line of keystroke input (terminated by CR or LF) it runs a
// reactor func that returns the bytes to emit (the "pty echo + program output"). An
// EOF reactor result ends the stream (RawOut → io.EOF), modelling CC exiting.
type scriptedCarriage struct {
	// banner is emitted to RawOut once, immediately, before any input (the connect
	// paint — a real pty TUI repaints on attach).
	banner []byte
	// react maps a completed input line (CR/LF stripped) to the output bytes the
	// fake "program" emits for it, plus whether this line ends the session. It is
	// the deterministic stand-in for CC's reaction to a keystroke line.
	react func(line string) (out []byte, end bool)

	out     chan []byte
	closeCh chan struct{}
	closeOK sync.Once

	mu      sync.Mutex
	inBuf   []byte   // accumulates keystrokes until a CR/LF completes a line
	rawIn   [][]byte // every frameRawIn the broker forwarded (the input record)
	resizes []hostbridge.Winsize
	closed  bool
}

func newScriptedCarriage(banner string, react func(line string) (out []byte, end bool)) *scriptedCarriage {
	c := &scriptedCarriage{
		banner:  []byte(banner),
		react:   react,
		out:     make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}
	if len(c.banner) > 0 {
		c.out <- c.banner // the connect paint, available on the first RawOut
	}
	return c
}

// RawOut yields the next scripted output chunk, or io.EOF when the stream ends (a
// reactor returned end=true and the EOF sentinel was pushed) or Close is called.
func (c *scriptedCarriage) RawOut() ([]byte, error) {
	select {
	case chunk, ok := <-c.out:
		if !ok {
			return nil, io.EOF
		}
		return chunk, nil
	case <-c.closeCh:
		return nil, io.EOF // the io.Closer-on-a-blocked-reader contract (the hangup)
	}
}

// RawInput accumulates keystroke bytes; each completed line (CR or LF) is fed to the
// reactor and its output pushed to RawOut. A reactor end=true closes the out stream
// (CC exited). The bytes are opaque — the carriage records them for the input
// assertion but the wire never parses them (D78 count-only is the broker's job).
func (c *scriptedCarriage) RawInput(p []byte) error {
	c.mu.Lock()
	c.rawIn = append(c.rawIn, append([]byte(nil), p...))
	c.inBuf = append(c.inBuf, p...)
	// Pull every complete line out of the buffer.
	var lines []string
	for {
		idx := bytes.IndexAny(c.inBuf, "\r\n")
		if idx < 0 {
			break
		}
		line := string(c.inBuf[:idx])
		// consume the line plus its terminator (and a following \n in a \r\n pair).
		end := idx + 1
		if end < len(c.inBuf) && c.inBuf[idx] == '\r' && c.inBuf[end] == '\n' {
			end++
		}
		c.inBuf = c.inBuf[end:]
		lines = append(lines, line)
	}
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil
	}
	for _, line := range lines {
		out, end := c.react(line)
		if len(out) > 0 {
			select {
			case c.out <- out:
			case <-c.closeCh:
				return nil
			}
		}
		if end {
			c.closeOnce()
			return nil
		}
	}
	return nil
}

// Resize records a winsize (the client's SIGWINCH-on-connect + drag). The fake does
// not reflow, but recording proves the resize reached the carriage through the
// broker (the §2.2 forward path).
func (c *scriptedCarriage) Resize(ws hostbridge.Winsize) error {
	c.mu.Lock()
	c.resizes = append(c.resizes, ws)
	c.mu.Unlock()
	return nil
}

// Close marks the guest hangup and unblocks a pending RawOut with io.EOF.
func (c *scriptedCarriage) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.closeOK.Do(func() { close(c.closeCh) })
	return nil
}

// closeOnce closes the out stream once (a reactor end=true → CC exited → RawOut EOF).
func (c *scriptedCarriage) closeOnce() {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.out)
	}
	c.mu.Unlock()
}

func (c *scriptedCarriage) inputRecords() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.rawIn...)
}

func (c *scriptedCarriage) resizeRecords() []hostbridge.Winsize {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]hostbridge.Winsize(nil), c.resizes...)
}

// termFleet is a running in-process terminal server: a Serve loop on a UDS fronting
// a Server with one session that registers a scriptedCarriage. A WRITER terminal
// dial (SocketTransport.DialTerminal) against its issued handle negotiates the raw
// surface and is served by the carriage — the U-FRAMES in-process round-trip reused
// as the always-on acceptance fixture.
type termFleet struct {
	udsPath  string
	srv      *hostbridge.Server
	carriage *scriptedCarriage
	sess     string
	closeFn  func()
}

const termFleetSession = "00000000-0000-4000-8000-0000000000e2"

// newTermFleet stands up the in-process terminal server fronting carriage. It binds
// a UDS under dir (a caller-owned t.TempDir), so nothing escapes the test. The
// Server is built WithNoAuth so the issued handle's minted token is accepted without
// a separate token store (the offline fixture, mirroring the live no-auth MVP
// posture). The caller defers Close.
func newTermFleet(dir string, carriage *scriptedCarriage) (*termFleet, error) {
	srv := hostbridge.NewServer(hostbridge.WithNoAuth(true))
	// The structured bridge is required by AddSession but the terminal path ignores
	// it; a discard stdin is sufficient (no structured drive happens).
	bridge := hostbridge.NewBridge(io.Discard, hostbridge.BridgeConfig{})
	session := srv.AddSession(termFleetSession, bridge)
	session.SetTerminalCarriage(carriage)

	sock := filepath.Join(dir, "term.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("e2e: listen unix %s: %w", sock, err)
	}
	go func() { _ = hostbridge.Serve(ln, srv) }()

	return &termFleet{
		udsPath:  sock,
		srv:      srv,
		carriage: carriage,
		sess:     termFleetSession,
		closeFn:  func() { _ = ln.Close() },
	}, nil
}

// dialWriter dials a TERMINAL-mode WRITER over the fleet's issued handle and returns
// the live TerminalConn (the production client carrier rawterm.Run drives).
func (f *termFleet) dialWriter() (*hostbridge.TerminalConn, error) {
	handle, err := f.srv.IssueHandleFor(f.sess, hostbridge.RoleWriter, hostbridge.TransportUnix, f.udsPath, time.Hour)
	if err != nil {
		return nil, fmt.Errorf("e2e: issue terminal writer handle: %w", err)
	}
	return hostbridge.NewSocketTransport().DialTerminal(handle)
}

func (f *termFleet) Close() {
	if f.closeFn != nil {
		f.closeFn()
	}
}

// --- the gated KVM-PTY tier resolution ----------------------------------------

// PTYLiveSubGateEnv is the SUB-gate that, on top of DS_KVM_LIVE=1, selects the
// PTY/terminal writer-seat carriage instead of the structured one (08 §4.5). The
// KVM tier is shared with the structured DriveKVMScripted, so a single boolean
// distinguishes "dial the RAW_TERMINAL seat" from "dial the structured seat". Unset
// ⇒ TestPTYDriveKVM skips even when DS_KVM_LIVE is armed (an operator who armed the
// VM for the structured drive does not accidentally dial it as a terminal).
const PTYLiveSubGateEnv = "DS_KVM_LIVE_PTY"

// ptyLiveSubGateArmed reports whether the PTY sub-gate is set (in ADDITION to
// DS_KVM_LIVE=1, checked by kvmGateArmed). Both are required to dial the live
// terminal seat.
func ptyLiveSubGateArmed() bool { return os.Getenv(PTYLiveSubGateEnv) == "1" }

// ErrPTYKVMGateUnset is returned by DialKVMTerminal when the KVM PTY tier is not
// fully armed (DS_KVM_LIVE != 1 OR DS_KVM_LIVE_PTY != 1): it dials nothing.
var ErrPTYKVMGateUnset = fmt.Errorf("e2e: per-session KVM-VM RAW_TERMINAL writer-seat tier is gated: set %s=1 AND %s=1 to arm (a live terminal-mode VM must serve the session)", KVMLiveGateEnv, PTYLiveSubGateEnv)

// terminalWriterHandle builds the TERMINAL-mode WRITER handle DialTerminal dials for
// the live KVM seat. DialTerminal resolves a TransportUnix endpoint (the framed-UDS
// carrier underneath the RAW_TERMINAL advertisement), so the handle carries a
// TransportUnix candidate at the advertised host-local address — the same address
// the structured KVMAttachConfig.writerHandle uses, only the negotiated MODE differs
// (frameMode{TERMINAL}, sent by DialTerminal). It carries the session-scoped token +
// UUID the live serving child validates.
func terminalWriterHandle(k KVMAttachConfig) hostbridge.AttachHandle {
	return hostbridge.AttachHandle{
		SessionUUID: k.SessionUUID,
		Endpoints: []hostbridge.EndpointCandidate{
			{Transport: hostbridge.TransportUnix, Address: k.Endpoint},
		},
		Auth:      hostbridge.AuthMaterial{Token: k.Token},
		Role:      hostbridge.RoleWriter,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// DialKVMTerminal dials the live per-session KVM-VM RAW_TERMINAL writer seat the
// terminal-mode serving child advertises (resolved from DS_KVM_LIVE_* via
// kvmAttachFromEnv) and returns a *hostbridge.TerminalConn the SAME TermScenario
// drives. It is GATED behind DS_KVM_LIVE=1 AND DS_KVM_LIVE_PTY=1; unfully-armed, it
// dials nothing and returns ErrPTYKVMGateUnset. It launches NO podman/claude/VM —
// the live terminal-mode VM already serves the seat (the transport-target swap).
func DialKVMTerminal(k KVMAttachConfig) (*hostbridge.TerminalConn, error) {
	if !kvmGateArmed() || !ptyLiveSubGateArmed() {
		return nil, ErrPTYKVMGateUnset
	}
	if k.Endpoint == "" {
		return nil, errors.New("e2e: DialKVMTerminal requires a KVMAttach.Endpoint (the advertised RAW_TERMINAL writer-seat); resolve it from DS_KVM_LIVE_* via kvmAttachFromEnv")
	}
	conn, err := hostbridge.NewSocketTransport().DialTerminal(terminalWriterHandle(k))
	if err != nil {
		return nil, fmt.Errorf("e2e: KVM-tier terminal dial over the advertised RAW_TERMINAL writer-seat: %w", err)
	}
	return conn, nil
}

// --- a goroutine-safe capture buffer ------------------------------------------

// syncBuffer is a goroutine-safe byte sink: termPump's output pump writes pty
// output here while the scenario stepper reads the accumulated bytes for grid
// assertions. A plain bytes.Buffer is not safe for that concurrent access.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

// --- a JSONL loader for a TermScenario fixture (parity with ParseScript) -------

// termStepLine is the on-disk JSONL shape of a TermStep (the exported field tags).
// ParseTermScenario decodes one per non-blank, non-comment line — the same self-
// documenting fixture idiom as ParseScript, so a committed cassette is reviewable.
type termStepLine = TermStep

// ParseTermScenario parses a JSONL TermScenario fixture: one JSON TermStep per
// non-blank line ({"send":…,"expect_grid_contains":[…],"expect_native_prompt":…}),
// blank/`#`-comment lines skipped. It is STRICT (DisallowUnknownFields) so a typo'd
// key is a loud parse error, and requires at least one step. Stdlib-only — the
// terminal twin of ParseScript.
func ParseTermScenario(r io.Reader, settle time.Duration) (TermScenario, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	var steps []TermStep
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 || raw[0] == '#' {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var s termStepLine
		if err := dec.Decode(&s); err != nil {
			return TermScenario{}, fmt.Errorf("e2e: term scenario line %d: %w", lineNo, err)
		}
		steps = append(steps, s)
	}
	if err := sc.Err(); err != nil {
		return TermScenario{}, fmt.Errorf("e2e: read term scenario: %w", err)
	}
	if len(steps) == 0 {
		return TermScenario{}, errors.New("e2e: term scenario has no steps (empty or all-comment)")
	}
	return TermScenario{Steps: steps, SettleTimeout: settle}, nil
}
