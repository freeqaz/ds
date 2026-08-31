// SPDX-License-Identifier: Apache-2.0

//go:build linux

package entrypoint

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPTYHelperProcess is the re-exec child the pty launcher tests drive as a REAL
// OS process (the os/exec helper-process pattern, mirroring supervise_test.go's
// TestHelperProcess but with its OWN env gate so supervise_test.go stays untouched).
// When DS_PTY_HELPER=1 it runs as the "runtime" the ptyLauncher launches under a
// pseudo-terminal, then exits. It reports what a pty child observes — whether its
// stdin is a controlling tty and the winsize the kernel handed it — onto its stdout
// (which the launcher wires to the pty slave, so the parent reads it off the master).
func TestPTYHelperProcess(t *testing.T) {
	if os.Getenv("DS_PTY_HELPER") != "1" {
		return
	}
	mode := os.Getenv("DS_PTY_HELPER_MODE")
	switch mode {
	case "report-tty":
		// isatty: a successful TCGETS on fd 0 means stdin is a terminal.
		_, ttyErr := unix.IoctlGetTermios(0, unix.TCGETS)
		isatty := ttyErr == nil
		// The winsize the kernel seeded onto the slave (propagated from the master).
		ws, wsErr := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ)
		cols, rows := uint16(0), uint16(0)
		if wsErr == nil {
			cols, rows = ws.Col, ws.Row
		}
		// Emit a single parseable line on stdout (the pty), then exit cleanly.
		fmt.Printf("PTYREPORT isatty=%t cols=%d rows=%d\n", isatty, cols, rows)
		os.Exit(0)
	case "sleep":
		// Run until the teardown signal reaps the pty session group.
		time.Sleep(30 * time.Second)
		os.Exit(0)
	default:
		os.Exit(0)
	}
}

// ptyHelperLauncher launches the test binary itself under the ptyLauncher in a
// given pty-helper mode. It reuses the REAL ptyLauncher.start so the controlling-tty
// exec + initial-winsize seed are exercised against a real pty + real child — no
// real Claude Code/VM. initialWinsize is the window the launcher seeds.
type ptyHelperLauncher struct {
	mode           string
	initialWinsize winsize
}

func (h ptyHelperLauncher) start(spec launchSpec, env []string) (runtimeProcess, runtimeStdio, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, runtimeStdio{}, err
	}
	helperEnv := append([]string{}, env...)
	helperEnv = append(helperEnv, "DS_PTY_HELPER=1", "DS_PTY_HELPER_MODE="+h.mode)
	pl := ptyLauncher{initialWinsize: h.initialWinsize}
	return pl.start(launchSpec{
		command:    exe,
		args:       []string{"-test.run=TestPTYHelperProcess", "--"},
		workingDir: spec.workingDir,
	}, helperEnv)
}

// TestPTYLauncher_ControllingTTYAndInitialWinsize is the pty launcher's core
// positive path. It launches the re-exec child UNDER A REAL PTY via ptyLauncher,
// reads what the child observes off the master, and asserts:
//   - the child's stdin is a CONTROLLING TTY (isatty true: Setsid+Setctty worked),
//   - the kernel seeded the NON-DEFAULT initial winsize on the master before the
//     child's first read (G9: paint at the right size from frame 1),
//   - the master DRAINS on the child's exit (the parent closed the slave at Start),
//   - the child is reaped CLEANLY (exit 0).
func TestPTYLauncher_ControllingTTYAndInitialWinsize(t *testing.T) {
	const wantCols, wantRows uint16 = 132, 43 // deliberately NOT 80x24, to prove the seed.
	l := ptyHelperLauncher{mode: "report-tty", initialWinsize: winsize{cols: wantCols, rows: wantRows}}

	proc, stdio, err := l.start(launchSpec{}, os.Environ())
	if err != nil {
		t.Fatalf("ptyLauncher.start: %v", err)
	}
	if stdio.ptyMaster == nil {
		t.Fatal("runtimeStdio.ptyMaster is nil; PTY mode must expose the master fd")
	}
	if stdio.stderr != nil {
		t.Error("PTY mode merges stderr onto the pty; runtimeStdio.stderr must be nil")
	}

	// Read the child's report off the pty master. The master DRAINS (read returns)
	// once the child exits and the last slave reference closes — proof the parent
	// closed its slave copy at Start. (Reading after exit may surface EIO instead of
	// EOF; treat that as the clean hangup.)
	out, readErr := io.ReadAll(stdio.stdout)
	if readErr != nil && !isPTYHangup(readErr) {
		t.Fatalf("read pty master: %v", readErr)
	}
	report := string(out)

	res := proc.wait()
	if res.exitCode != 0 || res.signaled || res.err != nil {
		t.Fatalf("child did not reap cleanly: %+v (report=%q)", res, report)
	}

	if !strings.Contains(report, "PTYREPORT") {
		t.Fatalf("no pty report drained off the master; got %q", report)
	}
	if !strings.Contains(report, "isatty=true") {
		t.Errorf("pty child stdin is not a controlling tty; report=%q", report)
	}
	if !strings.Contains(report, fmt.Sprintf("cols=%d rows=%d", wantCols, wantRows)) {
		t.Errorf("initial winsize not seeded; want cols=%d rows=%d, report=%q", wantCols, wantRows, report)
	}
}

// TestPTYLauncher_DefaultWinsize proves a zero initial winsize is seeded as the
// 80x24 default (winsize.resolved()), never a literal 0x0 window.
func TestPTYLauncher_DefaultWinsize(t *testing.T) {
	l := ptyHelperLauncher{mode: "report-tty", initialWinsize: winsize{}} // zero => default.

	proc, stdio, err := l.start(launchSpec{}, os.Environ())
	if err != nil {
		t.Fatalf("ptyLauncher.start: %v", err)
	}
	out, readErr := io.ReadAll(stdio.stdout)
	if readErr != nil && !isPTYHangup(readErr) {
		t.Fatalf("read pty master: %v", readErr)
	}
	res := proc.wait()
	if res.exitCode != 0 {
		t.Fatalf("child exit = %d; want 0 (report=%q)", res.exitCode, string(out))
	}
	if want := fmt.Sprintf("cols=%d rows=%d", defaultWinsizeCols, defaultWinsizeRows); !strings.Contains(string(out), want) {
		t.Errorf("zero winsize must default to %s; report=%q", want, string(out))
	}
}

// TestPTYLauncher_SignalTearsDownGroup proves ptyProcess.signal hangs up the whole
// pty SESSION GROUP: it launches a SLEEPING pty child (one that would run 30s) and
// asserts signal() reaps it promptly via the negative-pgid SIGHUP+SIGTERM. A
// regression that signalled only the single pid (or the wrong group) would leave
// the child sleeping and wait() would block until the test deadline.
func TestPTYLauncher_SignalTearsDownGroup(t *testing.T) {
	l := ptyHelperLauncher{mode: "sleep", initialWinsize: winsize{cols: 80, rows: 24}}

	proc, stdio, err := l.start(launchSpec{}, os.Environ())
	if err != nil {
		t.Fatalf("ptyLauncher.start: %v", err)
	}
	// Drain the master in the background so the child never blocks on output and the
	// read goroutine unblocks when the master closes on exit.
	go func() { _, _ = io.Copy(io.Discard, stdio.stdout) }()

	// Give the child a beat to reach its sleep + establish its session group.
	time.Sleep(100 * time.Millisecond)

	if err := proc.signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}

	done := make(chan processResult, 1)
	go func() { done <- proc.wait() }()
	select {
	case res := <-done:
		// The session-group hangup reaps the child; it was signal-killed, so a
		// signaled result (or a SIGHUP/SIGTERM-coded exit) — NOT a clean exit-0.
		if !res.signaled {
			t.Errorf("pty child should be signal-terminated by the group hangup; got %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pty child was NOT reaped by the group hangup within 5s; signal() did not tear down the session group")
	}
}

// TestSupervise_PTYConfig_EndToEnd drives the FULL supervisor (dial -> launch ->
// report ready -> bridge -> reap) with a PTY launch config, through chooseLauncher's
// production PTY selection. We inject the launcherHook with a ptyHelperLauncher (so
// the re-exec child runs under a REAL pty), a fake dialer, and a recording reporter,
// and assert a clean run: code 0, ReportReady once, ReportExit(completed). This is
// the regression guard that supervise.run wires a pty launcher's stdio onto the
// attach byte-path and reaps it correctly (the pty-master EIO hangup must not change
// the exit code).
func TestSupervise_PTYConfig_EndToEnd(t *testing.T) {
	// Install the pty helper launcher on the injection seam so chooseLauncher returns
	// it (launcherHook wins) — but the config STILL carries stdioPTY so this also
	// exercises a PTY-disposition config end to end.
	prev := launcherHook
	launcherHook = ptyHelperLauncher{mode: "report-tty", initialWinsize: winsize{cols: 100, rows: 30}}
	t.Cleanup(func() { launcherHook = prev })

	rep := &recordingReporter{}
	d := &fakeDialer{sock: newPipeSocket()}
	sup := &supervisor{
		dial:    d,
		report:  rep,
		logf:    func(string, ...any) {},
		errSink: io.Discard,
	}

	cfg := entrypointConfig{
		session: sessionRef{sessionUUID: "s-pty"},
		launch:  launchSpec{command: "helper", stdio: stdioPTY, initialWinsize: winsize{cols: 100, rows: 30}},
		attach:  attachWiring{eventSocketPath: "/run/ds/attach.sock"},
	}

	code, err := sup.run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("pty end-to-end exit code = %d; want 0 (clean reap, pty EIO must not change it)", code)
	}
	if rep.ready != 1 {
		t.Errorf("ReportReady called %d times; want 1", rep.ready)
	}
	if len(rep.exits) != 1 || rep.exits[0] != exitReasonCompleted {
		t.Errorf("exit reasons = %v; want [completed]", rep.exits)
	}
}
