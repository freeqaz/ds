// SPDX-License-Identifier: Apache-2.0

//go:build linux

package entrypoint

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// pty_linux.go is the Linux pty launch-MODE of ds-entrypoint (the terminal-MVP
// rider, docs/serpent-cli-mvp/10-build-decisions §A3 res. 7 / G7-G9, doc 02). It
// is selected (run.go chooseLauncher) only when the launch surface carries
// stdio==PTY; the PIPES path stays the byte-identical execLauncher (supervise.go).
//
// The pty primitives use golang.org/x/sys/unix only — NO new third-party pty
// dependency. openPTY opens /dev/ptmx, unlocks + resolves the slave, and the
// launcher runs the runtime with the slave as a CONTROLLING tty (Setsid+Setctty),
// seeds the initial window size on the master BEFORE the child's first paint
// (TIOCSWINSZ from winsize.resolved()), and tears the whole pty SESSION down on a
// teardown signal (negative-pgid SIGHUP then SIGTERM) so a pty child that spawned
// a Bash tool gets a clean hangup.

// errPtyUnsupported is returned by the !linux stub (pty_other.go). Declared here
// too so both build tags resolve the same symbol.
var errPtyUnsupported = errors.New("pty launch mode is only supported on linux")

// ptyLauncher launches the runtime under a pseudo-terminal. initialWinsize is the
// window the master is sized to BEFORE exec (G9: CC paints at the right size from
// frame 1, no 80x24-then-reflow jump); a zero axis defaults to 80x24 at use.
type ptyLauncher struct {
	initialWinsize winsize
}

// openPTY opens the pty master (/dev/ptmx), unlocks the slave (TIOCSPTLCK <- 0),
// resolves the slave index (TIOCGPTN), and returns the master *os.File plus the
// /dev/pts/N slave path. All via golang.org/x/sys/unix — no third-party dep.
//
// The caller owns the returned master (closes it) and opens/closes the slave by
// the returned path.
func openPTY() (master *os.File, slavePath string, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/ptmx: %w", err)
	}
	// Unlock the slave side: TIOCSPTLCK takes a *pointer to int*; 0 = unlocked.
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = m.Close()
		return nil, "", fmt.Errorf("unlock pty slave (TIOCSPTLCK): %w", err)
	}
	// Resolve the slave's index N so we can open /dev/pts/N.
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = m.Close()
		return nil, "", fmt.Errorf("resolve pty index (TIOCGPTN): %w", err)
	}
	return m, fmt.Sprintf("/dev/pts/%d", n), nil
}

// setWinsize seeds the pty master's window size (TIOCSWINSZ) from a resolved
// winsize (a zero axis already defaulted to 80x24). Sizing the MASTER propagates
// to the slave's termios, so the runtime sees the right dimensions from its first
// TIOCGWINSZ.
func setWinsize(masterFd uintptr, ws winsize) error {
	r := ws.resolved()
	return unix.IoctlSetWinsize(int(masterFd), unix.TIOCSWINSZ, &unix.Winsize{
		Col: r.cols,
		Row: r.rows,
	})
}

// start allocates a pty, runs the runtime with the slave as a controlling tty,
// seeds the initial window size on the master, and returns the supervised process
// plus a runtimeStdio whose stdout/stdin are the (non-owning) pty master and whose
// ptyMaster field hands the raw master to the U-GUEST-WIRE seam. stderr is MERGED
// onto the pty (a tty has one output stream), so runtimeStdio.stderr is nil.
func (l ptyLauncher) start(spec launchSpec, env []string) (runtimeProcess, runtimeStdio, error) {
	master, slavePath, err := openPTY()
	if err != nil {
		return nil, runtimeStdio{}, err
	}

	// Open the slave; it becomes the child's stdin/stdout/stderr (a single tty).
	slave, err := os.OpenFile(slavePath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		return nil, runtimeStdio{}, fmt.Errorf("open pty slave %q: %w", slavePath, err)
	}

	cmd := exec.Command(spec.command, spec.args...)
	cmd.Env = env
	cmd.Dir = spec.workingDir
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave // merge stderr onto the pty: a tty has one output stream.
	// Setsid: new session (pgid == pid, so the negative-pgid teardown targets the
	// whole pty session). Setctty + Ctty=0: make the slave (fd 0 in the child) the
	// CONTROLLING tty, so job-control signals (Ctrl-C) reach the foreground group
	// and a terminal UI behaves. Setsid ALREADY makes pgid==pid — do NOT also set
	// Setpgid (they are mutually exclusive: Setsid implies a new pgid).
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    0,
	}

	// Seed the initial window size on the MASTER before exec so the runtime's first
	// paint is sized (G9). A failure here is non-fatal — fall back to the kernel's
	// default (the resolved() default is 80x24) rather than fail the launch.
	if err := setWinsize(master.Fd(), l.initialWinsize); err != nil {
		// non-fatal: the runtime still launches at the kernel default winsize.
		_ = err
	}

	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		_ = master.Close()
		return nil, runtimeStdio{}, fmt.Errorf("start %q under pty: %w", spec.command, err)
	}

	// The parent closes the slave right after Start: the child holds its own dup'd
	// fds, and closing our copy means the master read drains (returns) when the
	// child exits and closes the last slave reference. (Keeping the slave open here
	// would wedge the bridge — the master would never see the child's hangup.)
	_ = slave.Close()

	// Wrap the master in a NON-OWNING Read/Write closer so the bridge's Close on
	// the stdio side does not race the supervisor (proc.wait/signal) on the SAME
	// underlying fd. The real master is closed once, by ptyProcess.wait, after the
	// child is reaped.
	shared := &sharedPTY{f: master}
	stdio := runtimeStdio{
		stdin:     nopWriteCloser{shared},
		stdout:    nopReadCloser{shared},
		stderr:    nil, // merged onto the pty; no separate stderr drain.
		ptyMaster: master,
	}
	proc := &ptyProcess{cmd: cmd, master: master}
	return proc, stdio, nil
}

// sharedPTY is the pty master shared between the bridge (Read/Write) and the
// supervisor (which owns the single Close). It exists so the non-owning closers
// below can wrap the SAME fd without each holding a real Close.
type sharedPTY struct {
	f *os.File
}

func (s *sharedPTY) Read(b []byte) (int, error)  { return s.f.Read(b) }
func (s *sharedPTY) Write(b []byte) (int, error) { return s.f.Write(b) }

// nopReadCloser / nopWriteCloser wrap the shared master so bridge's Close on the
// stdio interfaces is a no-op — the real master fd is closed exactly once by
// ptyProcess.wait after the child is reaped, never by the bridge mid-stream.
type nopReadCloser struct{ *sharedPTY }

func (nopReadCloser) Close() error { return nil }

type nopWriteCloser struct{ *sharedPTY }

func (nopWriteCloser) Close() error { return nil }

// ptyProcess supervises the pty child. It owns the single Close of the master fd.
type ptyProcess struct {
	cmd      *exec.Cmd
	master   *os.File
	closeOne sync.Once
}

// wait blocks until the pty child exits, then closes the master exactly once.
// Reading the pty master AFTER the child exits returns Linux EIO (not io.EOF), so
// the bridge's stdout->socket copy may surface an EIO; that is the normal pty
// hangup and must NOT change the exit code, so wait classifies purely from the
// child's WaitStatus (the EIO is the bridge's concern, treated as clean there).
func (p *ptyProcess) wait() processResult {
	err := p.cmd.Wait()
	// Close the master once the child is reaped: it unblocks any lingering master
	// read and releases the fd. Guarded so a concurrent teardown cannot double-close.
	p.closeOne.Do(func() { _ = p.master.Close() })

	if err == nil {
		return processResult{exitCode: 0}
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res := processResult{exitCode: ee.ExitCode()}
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.signaled = true
			res.exitCode = 128 + int(ws.Signal())
		}
		return res
	}
	return processResult{exitCode: -1, err: err}
}

// signal tears the pty SESSION down: SIGHUP then SIGTERM to the NEGATIVE pgid
// (syscall.Kill(-pid, ...)). The child was started Setsid, so pgid==pid and the
// negative target hits the whole foreground group — the clean session hangup for a
// pty child that itself spawned a Bash tool (the tool gets the hangup too, no
// orphan). SIGHUP first is the terminal-disconnect signal a tty session expects;
// SIGTERM follows as the polite-kill backstop.
func (p *ptyProcess) signal(_ os.Signal) error {
	if p.cmd.Process == nil {
		return errors.New("process not started")
	}
	pid := p.cmd.Process.Pid
	// SIGHUP: the controlling-terminal hangup the pty session expects.
	hupErr := syscall.Kill(-pid, syscall.SIGHUP)
	// SIGTERM: polite-kill backstop to the same group.
	termErr := syscall.Kill(-pid, syscall.SIGTERM)
	if hupErr != nil && termErr != nil {
		// Both group signals failed (e.g. the group already gone); fall back to the
		// single-process signal so a caller still gets a best-effort teardown.
		return p.cmd.Process.Signal(syscall.SIGTERM)
	}
	return nil
}
