// SPDX-License-Identifier: Apache-2.0

package rawterm

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/x/term"
)

// osTerminal is the production Terminal: a thin wrapper over
// github.com/charmbracelet/x/term (termios raw mode + size — already an indirect
// bubbletea dep, so no new module weight, docs/serpent-cli-mvp/03 §2.1) and
// os/signal (SIGWINCH). It owns the OUTPUT tty fd (the dev's terminal); the raw
// state token is the *term.State MakeRaw returns.
//
// The alt-screen and cursor/SGR resets are raw ANSI writes to the output file —
// no extra dep. These are the §2.6 belt-and-suspenders restores.
type osTerminal struct {
	out *os.File
	fd  uintptr
}

// newOSTerminal builds the production Terminal over the output file (os.Stdout in
// the cmd binary). The fd is snapshotted once; raw mode + size both key on it.
func newOSTerminal(out *os.File) *osTerminal {
	return &osTerminal{out: out, fd: out.Fd()}
}

// MakeRaw puts the output tty into termios raw mode (term.MakeRaw) and returns
// the prior *term.State as the restore token. On a non-TTY it errors — Run treats
// that as fatal (selectMode TTY-guards upstream, so this is defence-in-depth).
func (t *osTerminal) MakeRaw() (any, error) {
	st, err := term.MakeRaw(t.fd)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// Restore returns the tty to the pre-MakeRaw state. A nil token (MakeRaw never
// succeeded) is a no-op so the deferred guard is always safe to call.
func (t *osTerminal) Restore(token any) error {
	if token == nil {
		return nil
	}
	st, ok := token.(*term.State)
	if !ok || st == nil {
		return nil
	}
	return term.Restore(t.fd, st)
}

// Size returns the output tty's current cell grid as (cols, rows). term.GetSize
// returns (width, height) = (cols, rows).
func (t *osTerminal) Size() (uint16, uint16, error) {
	w, h, err := term.GetSize(t.fd)
	if err != nil {
		return 0, 0, err
	}
	return clampU16(w), clampU16(h), nil
}

// EnterAltScreen switches to the alt-screen buffer (\x1b[?1049h) so CC's TUI gets
// a clean canvas and the dev's scrollback is preserved on exit.
func (t *osTerminal) EnterAltScreen() error {
	_, err := t.out.WriteString("\x1b[?1049h")
	return err
}

// LeaveAltScreen switches back to the main buffer (\x1b[?1049l) and shows the
// cursor (\x1b[?25h) + resets SGR (\x1b[0m) — the §2.6 belt-and-suspenders so a
// CC that left the cursor hidden or a color set does not bleed into the shell.
func (t *osTerminal) LeaveAltScreen() error {
	_, err := t.out.WriteString("\x1b[?1049l\x1b[?25h\x1b[0m")
	return err
}

// WinchSignals delivers a tick on every SIGWINCH until ctx is done. It registers
// a buffered os/signal channel and fans it onto a plain struct{} channel (so the
// Terminal seam stays os-signal-free for the fake). The stop func releases the
// registration; ctx cancel also stops the fan-out goroutine.
func (t *osTerminal) WinchSignals(ctx context.Context) (<-chan struct{}, func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	ticks := make(chan struct{}, 1)
	go func() {
		defer close(ticks)
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-sig:
				if !ok {
					return
				}
				select {
				case ticks <- struct{}{}:
				default: // coalesce: a pending tick already says "resize"
				}
			}
		}
	}()
	stop := func() { signal.Stop(sig); signal.Reset(syscall.SIGWINCH) }
	return ticks, stop
}

// clampU16 saturates an int terminal dimension into a uint16 (a Winsize field).
// A pathological >65535 dimension clamps rather than wrapping to a tiny size.
func clampU16(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > 0xFFFF {
		return 0xFFFF
	}
	return uint16(n)
}

// IsTTY reports whether fd is a terminal — the cmd binary's selectMode TTY guard
// (docs/serpent-cli-mvp/03 §2.2). Exposed here so the mode-selection lives next to
// the term dependency and the cmd package does not import charmbracelet/x/term
// directly twice.
func IsTTY(fd uintptr) bool { return term.IsTerminal(fd) }

// ensure the production type satisfies the seam at compile time.
var _ Terminal = (*osTerminal)(nil)
