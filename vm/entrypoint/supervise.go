// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// supervise.go is the boot -> launch -> wire-stdio -> supervise -> teardown state
// machine. Each step is FAIL-CLOSED: if the config is absent/invalid, the runtime
// cannot be launched, its stdio cannot be wired, or the event socket cannot be
// reached, the entrypoint aborts with a nonzero exit and NO runtime runs (no
// runtime => no egress, doc 16 §1). The host agent drives the lifecycle
// (Restart=no, doc 15 §4.2): a fail-closed exit ends the session.
//
// RUNTIME-AGNOSTIC (D20/D38): the supervisor launches a LaunchSpec, copies bytes
// (transport.go), and waits for the process. It never inspects the runtime's
// protocol.

// launcher starts a configured runtime process and exposes its stdio + a Wait.
// The interface is the test seam: the production implementation is execLauncher
// (os/exec); tests inject a fake that re-execs the test binary as a child (the
// helper-process pattern) so the state machine is exercised against a REAL OS
// process without a real runtime/VM.
type launcher interface {
	// start launches the process with the given command/args/env/working dir and
	// returns its stdio pipes. The returned runtimeProcess supervises the child.
	start(spec launchSpec, env []string) (runtimeProcess, runtimeStdio, error)
}

// runtimeProcess is a launched, supervised child.
type runtimeProcess interface {
	// wait blocks until the process exits and returns its classification.
	wait() processResult
	// signal sends a termination signal during teardown.
	signal(sig os.Signal) error
}

// processResult is the outcome of a runtime process exit.
type processResult struct {
	// exitCode is the process exit code (0 = clean; -1 when killed by a signal
	// with no code).
	exitCode int
	// signaled is true when the process was terminated by a signal.
	signaled bool
	// err is a non-exit error from waiting (e.g. an I/O failure), if any.
	err error
}

// reason classifies the result into the observability taxonomy.
func (r processResult) reason() exitReason {
	switch {
	case r.err != nil:
		return exitReasonError
	case r.signaled:
		return exitReasonTerminated
	case r.exitCode == 0:
		return exitReasonCompleted
	default:
		return exitReasonError
	}
}

// dialer dials the guest-local event socket. Injected so tests use an in-memory
// fake socket.
type dialer interface {
	dial(path string) (io.ReadWriteCloser, error)
}

// supervisor wires the dependencies the boot state machine drives. All external
// effects (process launch, socket dial, readiness reporting) are interfaces so
// the machine is fully unit-testable offline.
type supervisor struct {
	launch   launcher
	dial     dialer
	report   reporter
	fetcher  tokenFetcher // nil => the production httpTokenFetcher (resolved in run)
	logf     stderrLogf
	errSink  io.Writer
	notifies chan os.Signal
}

// tokenFetcherOrDefault resolves the session-token fetcher: the injected fake when
// set (offline tests), else the production httpTokenFetcher. A nil fetcher
// resolves to exactly httpTokenFetcher{}, so the production path is byte-identical
// when the field is unset (matching the launcher/dialer nil-default convention).
func (s *supervisor) tokenFetcherOrDefault() tokenFetcher {
	if s.fetcher != nil {
		return s.fetcher
	}
	return httpTokenFetcher{}
}

// run executes the full boot-to-teardown machine for a validated config. It
// returns the process exit code to propagate (0 on a clean runtime completion,
// nonzero on any fail-closed abort or abnormal runtime exit).
func (s *supervisor) run(ctx context.Context, cfg entrypointConfig) (int, error) {
	if s.logf == nil {
		s.logf = defaultLogf
	}
	if s.errSink == nil {
		s.errSink = os.Stderr
	}

	// 1. Dial the guest-local event socket BEFORE launching the runtime: if the
	// attach byte-path is unreachable the runtime must not run unobserved
	// (fail-closed). The host agent is listening (doc 15 §5.4).
	socket, err := s.dial.dial(cfg.attach.eventSocketPath)
	if err != nil {
		return exitFailClosed, fmt.Errorf("attach socket: %w", err)
	}
	defer socket.Close()

	// 2. Launch the runtime with the composed, credential-free environment, plus
	// the freshly-fetched session token when a token-fetch endpoint is wired.
	env := buildRuntimeEnv(os.Environ(), cfg)

	// Fetch the short-lived session token in-guest from the host-local D22 shim
	// (U5) and inject it as the runtime's bearer credential. This happens AFTER
	// the event-socket dial (preserving the dial-before-launch invariant) and
	// BEFORE launch, so a fetch failure fails closed with NO runtime — no runtime
	// may run without auth. An empty endpoint skips the fetch entirely, leaving the
	// synthetic/offline launch path (and the no-credentials env) untouched.
	if cfg.sessionTokenEndpoint != "" {
		token, err := s.tokenFetcherOrDefault().fetch(cfg.sessionTokenEndpoint)
		if err != nil {
			return exitFailClosed, fmt.Errorf("fetch session token: %w", err)
		}
		env = injectSessionToken(env, token)
	}

	// Select the launcher for THIS config: the launcherHook test seam, then an
	// explicitly-set s.launch, then the production launcher chosen by the launch
	// surface's stdio disposition (stdioPTY => ptyLauncher, else execLauncher). The
	// dial above already happened, so the dial-before-launch invariant holds. The
	// teardown below is unchanged and now correct for a pty child: proc.signal
	// dispatches to ptyProcess.signal (negative-pgid SIGHUP+SIGTERM).
	proc, stdio, err := s.chooseLauncher(cfg).start(cfg.launch, env)
	if err != nil {
		return exitFailClosed, fmt.Errorf("launch runtime: %w", err)
	}

	// 3. Report readiness — the close of the D81 boot-to-entrypoint segment. The
	// load-bearing sd_notify READY=1 happens here; a failure to notify systemd is
	// fatal (the unit is Type=notify and would otherwise time out).
	if s.report != nil {
		if err := s.report.ReportReady(); err != nil {
			// Tear the runtime down: we could not signal readiness, so the boot
			// is failed at the init layer — do not leave an unobserved runtime.
			_ = proc.signal(syscall.SIGTERM)
			_ = stdio.stdin.Close()
			res := proc.wait()
			return exitFailClosed, fmt.Errorf("report ready: %w (runtime torn down, exit=%d)", err, res.exitCode)
		}
	}

	// 4. Wire the runtime's stdio onto the event socket and supervise the
	// process concurrently. The bridge returns when the attach byte-path is done;
	// the wait returns when the process exits. Either, plus a context
	// cancellation (a teardown signal), drives teardown.
	//
	// TERMINAL vs STRUCTURED byte path. When the launcher allocated a pty
	// (stdio.ptyMaster != nil — terminal mode, the ptyLauncher path), the byte path
	// is the FRAMED bidirectional bridge between the pty master and the carriage
	// (bridgePTY, ptywire.go): master->carriage chunks the raw pty output into
	// wireRawOut frames, and carriage->master applies the host's framed traffic —
	// wireRawIn keystroke bytes written VERBATIM to the master, and wireResize an
	// 8-byte TIOCSWINSZ winsize control (NOT a no-op): bridgePTY applies it to the
	// master via applyWinsize, and the kernel SIGWINCHes the runtime (CC) so it
	// reflows. The pty payload bytes themselves stay byte-exact; framing only wraps
	// each chunk. The STRUCTURED path (ptyMaster == nil — the historical pipes
	// disposition) is UNCHANGED and byte-identical: it still runs bridge() (stdout<->
	// socket, socket<->stdin, stderr drain). The terminal master is the same fd already
	// exposed via stdio.stdin/stdout (the non-owning sharedPTY wrappers), but bridgePTY
	// drives it directly so the half-close/EIO-hangup teardown is explicit and there is
	// no stderr leg (a tty has one output stream).
	bridgeDone := make(chan error, 1)
	if stdio.ptyMaster != nil {
		go func() { bridgeDone <- bridgePTY(stdio.ptyMaster, socket) }()
	} else {
		go func() { bridgeDone <- bridge(stdio, socket, s.errSink) }()
	}

	waitDone := make(chan processResult, 1)
	go func() { waitDone <- proc.wait() }()

	var result processResult
	select {
	case result = <-waitDone:
		// Runtime exited on its own — drain the bridge.
		<-bridgeDone
	case <-ctx.Done():
		// External teardown (a SIGTERM from the host agent / systemd stop).
		s.logf("teardown signal received: terminating runtime")
		_ = proc.signal(syscall.SIGTERM)
		result = <-waitDone
		<-bridgeDone
		// A signal-driven teardown is TERMINATED regardless of the child's code.
		if !result.signaled {
			result.signaled = true
		}
	}

	// 5. Report exit (best-effort app report + sd_notify STOPPING) and propagate
	// the runtime's exit code.
	reason := result.reason()
	detail := ""
	if result.err != nil {
		detail = result.err.Error()
	}
	if s.report != nil {
		if err := s.report.ReportExit(reason, result.exitCode, detail); err != nil {
			s.logf("report exit: %v", err)
		}
	}

	if result.err != nil {
		return exitFailClosed, fmt.Errorf("supervise runtime: %w", result.err)
	}
	return result.exitCode, nil
}

// exitFailClosed is the exit code the entrypoint uses for any fail-closed abort
// (no config, dial failure, launch failure, readiness failure). Distinct from a
// runtime's own nonzero code so an operator can tell "the entrypoint refused"
// from "the runtime crashed".
const exitFailClosed = 78 // EX_CONFIG (sysexits.h): configuration/precondition error.

// installSignalHandler returns a context that is cancelled on SIGTERM/SIGINT,
// the teardown signals systemd/the host agent send to stop the session.
func installSignalHandler(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(ch)
	}()
	return ctx, cancel
}

// --- production launcher (os/exec) ---

// execLauncher launches the runtime as a real child process.
type execLauncher struct{}

func (execLauncher) start(spec launchSpec, env []string) (runtimeProcess, runtimeStdio, error) {
	cmd := exec.Command(spec.command, spec.args...)
	cmd.Env = env
	cmd.Dir = spec.workingDir
	// Put the child in its own process group so a teardown signal can target the
	// whole runtime tree, not just the immediate process.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, runtimeStdio{}, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, runtimeStdio{}, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, runtimeStdio{}, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, runtimeStdio{}, fmt.Errorf("start %q: %w", spec.command, err)
	}
	return &execProcess{cmd: cmd}, runtimeStdio{stdin: stdin, stdout: stdout, stderr: stderr}, nil
}

// execProcess supervises a real *exec.Cmd.
type execProcess struct {
	cmd *exec.Cmd
}

func (p *execProcess) wait() processResult {
	err := p.cmd.Wait()
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

func (p *execProcess) signal(sig os.Signal) error {
	if p.cmd.Process == nil {
		return errors.New("process not started")
	}
	// Signal the whole process group (negative pid).
	if ssig, ok := sig.(syscall.Signal); ok {
		if err := syscall.Kill(-p.cmd.Process.Pid, ssig); err == nil {
			return nil
		}
	}
	return p.cmd.Process.Signal(sig)
}

// --- production dialer (net unix) ---

// unixDialerImpl dials the guest-local event socket as a real UDS.
type unixDialerImpl struct{}

func (unixDialerImpl) dial(path string) (io.ReadWriteCloser, error) {
	return dialEventSocket(path)
}
