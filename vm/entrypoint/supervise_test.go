// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestHelperProcess is the re-exec child the supervise state-machine tests drive
// as a REAL OS process (the standard os/exec helper-process pattern). It is not a
// real test: it inspects GO_WANT_HELPER_PROCESS and, when set, behaves as the
// "runtime" the supervisor launches, then exits.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	mode := os.Getenv("DS_HELPER_MODE")
	switch mode {
	case "echo":
		// Copy stdin -> stdout so the bridge has bytes flowing, then exit 0.
		_, _ = io.Copy(os.Stdout, os.Stdin)
		os.Exit(0)
	case "emit-then-exit":
		fmt.Fprint(os.Stdout, "runtime-output")
		os.Exit(0)
	case "fail":
		fmt.Fprint(os.Stderr, "boom")
		os.Exit(3)
	case "sleep":
		// Run until terminated by a signal (teardown path).
		time.Sleep(30 * time.Second)
		os.Exit(0)
	default:
		os.Exit(0)
	}
}

// helperLauncher launches the test binary itself as the "runtime", in the given
// helper mode. This exercises execLauncher's real os/exec path against a real
// child without a real Claude Code/VM.
type helperLauncher struct {
	mode string
}

func (h helperLauncher) start(spec launchSpec, env []string) (runtimeProcess, runtimeStdio, error) {
	// Re-exec this test binary into TestHelperProcess.
	args := append([]string{"-test.run=TestHelperProcess", "--"}, spec.args...)
	exe, err := os.Executable()
	if err != nil {
		return nil, runtimeStdio{}, err
	}
	helperEnv := append([]string{}, env...)
	helperEnv = append(helperEnv, "GO_WANT_HELPER_PROCESS=1", "DS_HELPER_MODE="+h.mode)
	real := execLauncher{}
	return real.start(launchSpec{
		command:    exe,
		args:       args,
		env:        helperEnv,
		workingDir: spec.workingDir,
	}, helperEnv)
}

// fakeDialer hands the supervisor an in-memory socket. When seq is non-nil it
// records the relative order in which dial was reached (next(seq)), so an
// ordering test can assert the event socket is DIALED BEFORE launch.start()
// (supervise.go step 1 — the fail-closed "no unobserved runtime" invariant).
type fakeDialer struct {
	sock     io.ReadWriteCloser
	dialErr  error
	dialedAt string
	seq      *orderSeq // optional: records the dial's position in the boot sequence
	dialAt   int       // the recorded sequence position of this dial (0 = not recorded)
}

func (d *fakeDialer) dial(path string) (io.ReadWriteCloser, error) {
	d.dialedAt = path
	if d.seq != nil {
		d.dialAt = d.seq.next()
	}
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	return d.sock, nil
}

// orderSeq is a shared monotonic counter the ordering test threads through both
// fakeDialer.dial and orderingLauncher.start to prove their relative order.
type orderSeq struct {
	mu sync.Mutex
	n  int
}

func (s *orderSeq) next() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return s.n
}

// orderingLauncher is a thin recording wrapper around an inner launcher (the
// helperLauncher re-exec child) that stamps the shared sequence counter when
// start() is reached, so a test can compare it against the dialer's stamp. It
// exec's no runtime of its own — it delegates to the inner offline launcher — so
// the ordering test stays fully offline.
type orderingLauncher struct {
	inner   launcher
	seq     *orderSeq
	startAt int // the recorded sequence position of start (0 = never started)
}

func (l *orderingLauncher) start(spec launchSpec, env []string) (runtimeProcess, runtimeStdio, error) {
	l.startAt = l.seq.next()
	return l.inner.start(spec, env)
}

// pipeSocket is a self-contained in-memory socket: what's written is readable
// back (loopback), enough to drain the bridge in tests.
type pipeSocket struct {
	r       *io.PipeReader
	w       *io.PipeWriter
	mu      sync.Mutex
	written bytes.Buffer
}

func newPipeSocket() *pipeSocket {
	r, w := io.Pipe()
	return &pipeSocket{r: r, w: w}
}

func (p *pipeSocket) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *pipeSocket) Write(b []byte) (int, error) {
	p.mu.Lock()
	p.written.Write(b)
	p.mu.Unlock()
	return len(b), nil
}
func (p *pipeSocket) Close() error      { return p.r.Close() }
func (p *pipeSocket) CloseWrite() error { return p.w.Close() }

// recordingReporter records readiness/exit calls.
type recordingReporter struct {
	mu       sync.Mutex
	ready    int
	exits    []exitReason
	codes    []int
	readyErr error
}

func (r *recordingReporter) ReportReady() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready++
	return r.readyErr
}
func (r *recordingReporter) ReportExit(reason exitReason, code int, detail string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exits = append(r.exits, reason)
	r.codes = append(r.codes, code)
	return nil
}

func newSupervisorFor(t *testing.T, mode string, rep reporter, d *fakeDialer) *supervisor {
	t.Helper()
	var log bytes.Buffer
	return &supervisor{
		launch:  helperLauncher{mode: mode},
		dial:    d,
		report:  rep,
		logf:    func(f string, a ...any) { fmt.Fprintf(&log, f, a...) },
		errSink: io.Discard,
	}
}

func cfgForSupervise() entrypointConfig {
	return entrypointConfig{
		session: sessionRef{sessionUUID: "s1"},
		launch:  launchSpec{command: "helper"},
		attach:  attachWiring{eventSocketPath: "/run/ds/attach.sock"},
	}
}

func TestSupervise_RuntimeCompletesCleanly(t *testing.T) {
	rep := &recordingReporter{}
	d := &fakeDialer{sock: newPipeSocket()}
	sup := newSupervisorFor(t, "emit-then-exit", rep, d)

	code, err := sup.run(context.Background(), cfgForSupervise())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d; want 0", code)
	}
	if rep.ready != 1 {
		t.Errorf("ReportReady called %d times; want 1", rep.ready)
	}
	if len(rep.exits) != 1 || rep.exits[0] != exitReasonCompleted {
		t.Errorf("exit reasons = %v; want [completed]", rep.exits)
	}
	if d.dialedAt != "/run/ds/attach.sock" {
		t.Errorf("dialed %q; want the event socket path", d.dialedAt)
	}
}

func TestSupervise_RuntimeExitsNonZero(t *testing.T) {
	rep := &recordingReporter{}
	d := &fakeDialer{sock: newPipeSocket()}
	sup := newSupervisorFor(t, "fail", rep, d)

	code, err := sup.run(context.Background(), cfgForSupervise())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 3 {
		t.Errorf("exit code = %d; want 3 (propagated runtime code)", code)
	}
	if len(rep.exits) != 1 || rep.exits[0] != exitReasonError {
		t.Errorf("exit reasons = %v; want [error]", rep.exits)
	}
}

func TestSupervise_FailClosed_DialError(t *testing.T) {
	rep := &recordingReporter{}
	d := &fakeDialer{dialErr: fmt.Errorf("connection refused")}
	sup := newSupervisorFor(t, "echo", rep, d)

	code, err := sup.run(context.Background(), cfgForSupervise())
	if err == nil {
		t.Fatal("expected fail-closed error when the event socket is unreachable")
	}
	if code != exitFailClosed {
		t.Errorf("exit code = %d; want exitFailClosed=%d", code, exitFailClosed)
	}
	// Fail-closed: never reported ready, never launched a runtime.
	if rep.ready != 0 {
		t.Errorf("must not report ready when the socket is unreachable; got %d", rep.ready)
	}
}

func TestSupervise_FailClosed_ReadyError_TearsDownRuntime(t *testing.T) {
	rep := &recordingReporter{readyErr: fmt.Errorf("notify socket gone")}
	d := &fakeDialer{sock: newPipeSocket()}
	// A long-running child so we can observe it gets torn down on a ready failure.
	sup := newSupervisorFor(t, "sleep", rep, d)

	code, err := sup.run(context.Background(), cfgForSupervise())
	if err == nil {
		t.Fatal("expected fail-closed error when readiness reporting fails")
	}
	if code != exitFailClosed {
		t.Errorf("exit code = %d; want exitFailClosed=%d", code, exitFailClosed)
	}
	if !strings.Contains(err.Error(), "report ready") {
		t.Errorf("error should mention report ready: %v", err)
	}
}

func TestSupervise_Teardown_OnContextCancel(t *testing.T) {
	rep := &recordingReporter{}
	d := &fakeDialer{sock: newPipeSocket()}
	sup := newSupervisorFor(t, "sleep", rep, d)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Give the supervisor time to launch + report ready, then tear down.
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	code, err := sup.run(ctx, cfgForSupervise())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.ready != 1 {
		t.Errorf("ReportReady = %d; want 1", rep.ready)
	}
	if len(rep.exits) != 1 || rep.exits[0] != exitReasonTerminated {
		t.Errorf("exit reasons = %v; want [terminated]", rep.exits)
	}
	// A signal-killed process yields a 128+signal code.
	if code == 0 {
		t.Errorf("teardown exit code = %d; want nonzero (signal-driven)", code)
	}
}

// TestSupervise_DialsBeforeLaunch pins supervise.run's load-bearing ordering
// invariant (supervise.go step 1 before step 2): the guest-local event socket is
// DIALED BEFORE the runtime is launched, so a runtime never runs unobserved
// (fail-closed — no observation channel => no runtime, doc 16 §1). We thread a
// shared sequence counter through fakeDialer.dial and a recording launcher's
// start and assert dial's stamp strictly precedes start's. Fully offline (the
// dialer returns an in-mem socket; the launcher re-execs the test binary).
//
// REGRESSION GUARD: if supervise.run is reordered to launch.start() before
// dial.dial() (running the runtime before the observation socket is up), the
// launcher would stamp first and dialAt > startAt, failing this assertion.
func TestSupervise_DialsBeforeLaunch(t *testing.T) {
	seq := &orderSeq{}
	d := &fakeDialer{sock: newPipeSocket(), seq: seq}
	recL := &orderingLauncher{inner: helperLauncher{mode: "emit-then-exit"}, seq: seq}
	rep := &recordingReporter{}

	var log bytes.Buffer
	sup := &supervisor{
		launch:  recL,
		dial:    d,
		report:  rep,
		logf:    func(f string, a ...any) { fmt.Fprintf(&log, f, a...) },
		errSink: io.Discard,
	}

	code, err := sup.run(context.Background(), cfgForSupervise())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d; want 0 (clean runtime completion)", code)
	}

	// Both effects must have happened.
	if d.dialAt == 0 {
		t.Fatal("dialer was never reached; supervise.run must dial the event socket")
	}
	if recL.startAt == 0 {
		t.Fatal("launcher was never reached; supervise.run must launch the runtime")
	}
	// THE INVARIANT: dial strictly precedes launch.start.
	if !(d.dialAt < recL.startAt) {
		t.Errorf("dial-before-launch invariant violated: dial at seq %d, launch.start at seq %d; "+
			"the event socket MUST be dialed before the runtime is launched (no unobserved runtime)",
			d.dialAt, recL.startAt)
	}
}
