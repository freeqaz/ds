// SPDX-License-Identifier: Apache-2.0

package entrypoint

// launchmode.go is the PROTO-FREE launch-mode surface (the terminal-MVP rider,
// docs/serpent-cli-mvp/10-build-decisions §A3 res. 7). It carries the two pieces
// the supervisor needs to choose how to wire the runtime's stdio at launch — the
// stdio disposition (pipes vs pty) and the initial pty window size — WITHOUT any
// protobuf machinery. runtimev1_bridge.go is the single place that projects the
// frozen runtime.v1 LaunchSpec.{stdio,initial_window} onto these plain types; the
// rest of the package (run.go, supervise.go, pty_linux.go) operates only on them.
//
// ADDITIVE (D38 runtime-agnostic): the historical/zero disposition is PIPES, so a
// config that predates the rider (or one that names PIPES/UNSPECIFIED) keeps the
// byte-identical execLauncher pipes path. PTY is the only opt-in.

// stdioDisposition selects how the runtime's stdin/stdout/stderr are wired at
// launch. The ZERO value is stdioPipes (the historical disposition), so an
// absent/unspecified launch mode is the existing pipes path with no change.
type stdioDisposition int

const (
	// stdioPipes wires the runtime over three os.Pipe()s (the historical D38
	// attach byte-path). The zero value, so it is the default for any config that
	// does not opt in to a pty.
	stdioPipes stdioDisposition = iota
	// stdioPTY allocates a pseudo-terminal and runs the runtime with the pty slave
	// as a controlling tty, so a terminal UI (the real `claude` TUI) renders
	// faithfully. The opt-in disposition; only meaningful on Linux.
	stdioPTY
)

// defaultWinsizeCols / defaultWinsizeRows are the fallback pty dimensions when the
// launch surface leaves an axis unset (a zero cols or rows). 80x24 is the
// historical terminal default — never a literal 0x0 window (which would make the
// runtime paint into a degenerate terminal).
const (
	defaultWinsizeCols uint16 = 80
	defaultWinsizeRows uint16 = 24
)

// winsize is the proto-free pty window size (columns x rows). It mirrors
// runtime.v1 TerminalSize but carries no protobuf machinery. A zero on either
// axis means "unset" and is filled by resolved() at use — never an error, never a
// literal 0x0 window seeded into the kernel.
type winsize struct {
	cols uint16
	rows uint16
}

// resolved returns a winsize with each zero axis defaulted to 80x24. It is applied
// at the point of use (the TIOCSWINSZ seed), so the wire/config can legitimately
// carry a partially-set or fully-unset window and the runtime still paints into a
// sane terminal from frame 1.
func (w winsize) resolved() winsize {
	out := w
	if out.cols == 0 {
		out.cols = defaultWinsizeCols
	}
	if out.rows == 0 {
		out.rows = defaultWinsizeRows
	}
	return out
}
