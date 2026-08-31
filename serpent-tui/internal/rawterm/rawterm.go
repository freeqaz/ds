// SPDX-License-Identifier: Apache-2.0
//
// Package rawterm is serpent-tui's terminal-first writer surface: after a WRITER
// attach to a handle carrying a RAW_TERMINAL endpoint (docs/serpent-cli-mvp/03
// §2.3, 10-build-decisions §A3), the dev's terminal IS Claude Code — stdin bytes
// are forwarded to the in-VM CC pty (frameRawIn), the pty's output bytes are
// written to stdout (frameRawOut), and SIGWINCH is translated to a resize frame
// (frameResize). CC stays inside the VM in every phase (the hard constraint;
// D1/D4/D8/D28/D39/D44/D52/D72/D73); this carries terminal bytes only, runs no
// claude, proxies no syscall.
//
// The package is a SIBLING of internal/loop, not a mode of it: it bypasses
// bubbletea entirely (a direct os.File <-> Conn byte copy), so no control
// sequence is swallowed or translated. It is DARK by default — the cmd binary
// only enters it when the AttachHandle advertises a RAW_TERMINAL endpoint AND the
// writer seat was granted AND stdin/stdout are a real TTY (docs/serpent-cli-mvp/03
// §2.2); otherwise the structured bubbletea loop runs unchanged.
//
// The non-negotiable invariant (§2.6): the local terminal is restored on EVERY
// exit path — clean return, transport fault, ctx cancel, detach, AND panic — via
// a deferred, idempotent restore taken BEFORE MakeRaw and a panic-wrapped body.
package rawterm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
)

// Conn is the raw byte/resize seam Run drives. It is satisfied by a
// *hostbridge.TerminalConn (the production carrier, dialed via
// SocketTransport.DialTerminal) and by an in-process fake (tests) — so Run is
// unit-testable with no VM, no orchestrator, and no socket. One method per
// terminal wire frame the U-FRAMES rider added (client/hostbridge/socket.go).
//
// *hostbridge.TerminalConn satisfies this interface verbatim: RawOut/Write/
// SendResize/Done/Close already match these signatures (Write is the io.Writer
// shape; a READER refuses with ErrReaderCannotWrite before the wire, D61).
type Conn interface {
	// RawOut is the stream of opaque pty output chunks from the guest, closed at
	// session end. Chunk boundaries are meaningless (a pty byte stream has no
	// record boundary); the consumer concatenates and writes them to stdout.
	RawOut() <-chan []byte
	// Write forwards a slice of stdin bytes to the in-VM CC pty (one frameRawIn).
	// It is the io.Writer shape: returns the number of bytes accepted. A READER
	// refuses with hostbridge.ErrReaderCannotWrite before the wire (D61).
	Write(p []byte) (int, error)
	// SendResize forwards a terminal-size change (one frameResize) to the guest,
	// which applies it via TIOCSWINSZ. A READER refuses (D61).
	SendResize(ws hostbridge.Winsize) error
	// Done yields the terminal cause (nil on a clean end), select-able.
	Done() <-chan error
	// Close releases the attach (idempotent).
	Close() error
}

// Terminal is the local-TTY seam Run owns: termios raw mode, the alt-screen, the
// window size, and SIGWINCH delivery. The production impl (osTerminal, the
// default when Options.Terminal is nil) is a thin wrapper over
// github.com/charmbracelet/x/term + os/signal; tests inject a fake so raw-mode
// setup/restore and resize are exercised with no real TTY.
//
// The contract: MakeRaw returns a token Restore consumes; Restore is called once,
// AFTER the deferred guard already snapshotted (so a MakeRaw failure still
// restores nothing-harmful). Size returns the current cell grid (cols, rows);
// WinchSignals delivers a tick on every SIGWINCH until ctx is done.
type Terminal interface {
	// MakeRaw puts the terminal into termios raw mode and returns a restore token
	// (opaque to Run; handed back to Restore). On a non-TTY it errors — Run treats
	// that as fatal (selectMode TTY-guards, so this is defence-in-depth).
	MakeRaw() (restoreToken any, err error)
	// Restore returns the terminal to the pre-MakeRaw state from the token. It is
	// called via a sync.Once guard so the deferred-and-explicit double call is
	// safe; a nil token (MakeRaw never succeeded) is a no-op.
	Restore(restoreToken any) error
	// Size returns the current terminal cell grid (cols, rows).
	Size() (cols, rows uint16, err error)
	// EnterAltScreen / LeaveAltScreen switch the alt-screen buffer (no-ops when
	// Options.NoAltScreen is set — Run skips them). LeaveAltScreen also shows the
	// cursor and resets SGR (belt-and-suspenders, §2.6).
	EnterAltScreen() error
	LeaveAltScreen() error
	// WinchSignals returns a channel that ticks on every SIGWINCH until ctx is
	// done, plus a stop func to release the signal registration.
	WinchSignals(ctx context.Context) (<-chan struct{}, func())
}

// DefaultDetachKey is the local escape byte that detaches without killing CC —
// Ctrl-] (0x1d), the telnet/ssh-class escape (docs/serpent-cli-mvp/03 §2.5). The
// raw terminal makes Ctrl-C a BYTE forwarded to CC (interrupt the turn, like
// ssh), so a distinct local escape is needed to leave the VM session running.
const DefaultDetachKey byte = 0x1d // Ctrl-]

// readChunk bounds a single stdin read so a large paste is split across frames
// (each ≤ the carrier's frame cap) rather than overrunning it (§R7). A pty byte
// stream has no record boundary, so splitting is lossless.
const readChunk = 32 << 10 // 32 KiB

// Options carries Run's operator-facing knobs and the test seams.
type Options struct {
	// DetachKey is the local single-byte escape that detaches (clean exit 0, VM
	// session kept) without forwarding to CC. Zero ⇒ DefaultDetachKey (Ctrl-]).
	DetachKey byte
	// NoAltScreen stays on the main screen buffer (no \x1b[?1049h) — for
	// scrollback-keeping or dumb terminals (the --no-alt-screen flag).
	NoAltScreen bool

	// Terminal is the local-TTY seam (nil ⇒ a real osTerminal over out). Tests
	// inject a fake so raw-mode setup/restore + resize run with no real TTY.
	Terminal Terminal
}

// detachKey resolves the configured detach byte (zero ⇒ the default).
func (o Options) detachKey() byte {
	if o.DetachKey == 0 {
		return DefaultDetachKey
	}
	return o.DetachKey
}

// errDetach is the internal sentinel a detach keypress raises through the select:
// it returns nil from Run (a clean detach, exit 0, the VM session keeps running),
// distinct from a transport fault (which surfaces the cause). Never escapes Run.
var errDetach = errors.New("rawterm: operator detached")

// Run runs the raw passthrough until the session ends (Conn.Done), the operator
// detaches (the detach key), or stdin closes (EOF). It OWNS the local terminal:
// raw mode + alt-screen on entry, GUARANTEED idempotent restore on EVERY exit
// path (return, transport fault, ctx cancel, detach, panic — §2.6). It is the
// single entry point the cmd binary drives and is unit-testable against a fake
// Conn + a fake Terminal (no VM).
//
//   - in  is the local stdin (os.Stdin in production): keystrokes → Conn.Write.
//   - out is the local stdout (os.Stdout in production): Conn.RawOut → out.
//
// A detach returns nil (clean, VM kept); a Conn.Done error or a transport fault
// returns the cause (a non-zero exit). A panic anywhere still runs the deferred
// restore, then re-panics with the terminal already sane.
func Run(ctx context.Context, c Conn, in io.Reader, out io.Writer, opt Options) (runErr error) {
	term := opt.Terminal
	if term == nil {
		f, ok := out.(*os.File)
		if !ok {
			return errors.New("rawterm: production Run requires an *os.File out (a real TTY)")
		}
		term = newOSTerminal(f)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// --- the layered restore guard (§2.6) ------------------------------------
	// Snapshot the restore token BEFORE MakeRaw so the deferred restore is the
	// LAST defer to run on ANY return path, and a restore is harmless if MakeRaw
	// never succeeded (nil token ⇒ a no-op). A sync.Once-style guard via the
	// restored flag makes the deferred-and-any-explicit call idempotent.
	var restoreToken any
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if !opt.NoAltScreen {
			_ = term.LeaveAltScreen() // also shows cursor + resets SGR
		}
		_ = term.Restore(restoreToken)
	}
	// Deferred FIRST (runs LAST): the terminal is sane before Run returns or the
	// process unwinds a panic. On a panic, restore runs, then we re-panic — so a
	// bug never leaves a wedged terminal (the §2.6 panic-safety guarantee).
	defer func() {
		restore()
		if r := recover(); r != nil {
			panic(r) // terminal already restored; let the process die loudly
		}
	}()

	tok, err := term.MakeRaw()
	if err != nil {
		return fmt.Errorf("rawterm: enter raw mode: %w", err)
	}
	restoreToken = tok

	if !opt.NoAltScreen {
		if err := term.EnterAltScreen(); err != nil {
			return fmt.Errorf("rawterm: enter alt-screen: %w", err)
		}
	}

	// INITIAL window size on connect, BEFORE any input byte (§2.3/§A7) — so CC
	// paints at the right size from frame 1 (no 80x24-then-reflow jump). A size
	// error is non-fatal: the guest falls back to its launch-seeded size.
	if cols, rows, sErr := term.Size(); sErr == nil {
		_ = c.SendResize(hostbridge.Winsize{Rows: rows, Cols: cols})
	}

	// --- the three pumps + the select ----------------------------------------
	detachKey := opt.detachKey()

	// (a) stdin reader: read in → split out the detach byte → Conn.Write the rest.
	inErr := make(chan error, 1)
	go func() {
		inErr <- pumpStdin(ctx, c, in, detachKey)
	}()

	// (b) output writer: range Conn.RawOut() → out.Write. A write fault ends it.
	outErr := make(chan error, 1)
	go func() {
		outErr <- pumpOutput(c, out)
	}()

	// (c) signal watcher: SIGWINCH → re-Size → Conn.SendResize. Coalesced by the
	// OS (one tick per delivery) and idempotent on the guest, so dragging a
	// resize never floods the wire beyond the kernel's own coalescing.
	winch, stopWinch := term.WinchSignals(ctx)
	defer stopWinch()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-winch:
				if !ok {
					return
				}
				if cols, rows, sErr := term.Size(); sErr == nil {
					_ = c.SendResize(hostbridge.Winsize{Rows: rows, Cols: cols})
				}
			}
		}
	}()

	// (d) the select: whichever leg ends first wins. ctx cancel (external signal),
	// a detach, stdin EOF, an output fault, or Conn.Done all tear the loop down;
	// the deferred restore then runs in the normal flow.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-inErr:
		if errors.Is(err, errDetach) {
			return nil // clean detach: VM session keeps running, exit 0
		}
		if errors.Is(err, io.EOF) || err == nil {
			return nil // stdin closed: a clean local end
		}
		return err
	case err := <-outErr:
		return err
	case err := <-c.Done():
		return err
	}
}

// pumpStdin reads stdin in bounded chunks, scans each chunk for the detach byte,
// and forwards the remaining bytes to the in-VM CC pty (Conn.Write). On the
// detach byte it stops forwarding and returns errDetach (a clean local exit). A
// read EOF (stdin closed) returns io.EOF; a Conn.Write fault returns that cause.
// It recovers a panic and returns it as an error rather than crashing the process
// (so the select tears down cleanly and the deferred restore runs, §2.6).
func pumpStdin(ctx context.Context, c Conn, in io.Reader, detachKey byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("rawterm: stdin pump panic: %v", r)
		}
	}()
	buf := make([]byte, readChunk)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, rerr := in.Read(buf)
		if n > 0 {
			// Detach byte: forward everything BEFORE it, then stop. The bytes after
			// the detach key are dropped (the operator chose to leave; CC keeps
			// running and re-attach replays the live pty).
			if i := indexByte(buf[:n], detachKey); i >= 0 {
				if i > 0 {
					if _, werr := c.Write(buf[:i]); werr != nil {
						return werr
					}
				}
				return errDetach
			}
			if _, werr := c.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			return rerr // io.EOF on a clean stdin close, else the read fault
		}
	}
}

// pumpOutput ranges the pty output chunks and writes each to the local stdout.
// It returns nil on a clean RawOut close (session end) and the write fault if the
// local stdout dies. A panic is recovered and returned as an error (§2.6).
func pumpOutput(c Conn, out io.Writer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("rawterm: output pump panic: %v", r)
		}
	}()
	for chunk := range c.RawOut() {
		if len(chunk) == 0 {
			continue // an empty frameRawOut is legal and carries nothing
		}
		if _, werr := out.Write(chunk); werr != nil {
			return werr
		}
	}
	return nil
}

// indexByte returns the index of the first occurrence of b in p, or -1. A tiny
// local helper to keep the stdin pump free of a bytes import (and to make the
// detach scan obvious at the call site).
func indexByte(p []byte, b byte) int {
	for i := range p {
		if p[i] == b {
			return i
		}
	}
	return -1
}
