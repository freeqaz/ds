// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain_FailClosed_NoConfig: an unset config dir => fail-closed nonzero exit,
// no panic.
func TestMain_FailClosed_NoConfig(t *testing.T) {
	var errSink bytes.Buffer
	code := Main(context.Background(), func(string) string { return "" }, &errSink)
	if code != exitFailClosed {
		t.Errorf("exit code = %d; want exitFailClosed=%d", code, exitFailClosed)
	}
	if !strings.Contains(errSink.String(), "fail-closed") {
		t.Errorf("expected fail-closed diagnostic, got: %q", errSink.String())
	}
}

// TestMain_FailClosed_InvalidConfig: a present-but-invalid config => fail-closed.
func TestMain_FailClosed_InvalidConfig(t *testing.T) {
	pb := validProto()
	pb.Launch.Command = "" // invalid: no command
	getenv := writeConfigDir(t, pb)
	var errSink bytes.Buffer
	code := Main(context.Background(), getenv, &errSink)
	if code != exitFailClosed {
		t.Errorf("exit code = %d; want exitFailClosed", code)
	}
}

// TestMain_ValidConfig_EntersLiveLeg: a valid config present is itself the
// launch signal (config-presence, maintainer ruling 2026-06-15) — Main falls straight
// into supervisor.run. We point attach.event_socket_path at a non-existent UDS;
// supervisor.run dials it BEFORE launching the runtime, so a valid-but-undialable
// socket makes Main return exitFailClosed with an attach-socket diagnostic. That
// proves Main reached the live leg rather than returning 0 without launching.
// Fully offline: no real runtime/VM is exec'd (the dial fails first).
func TestMain_ValidConfig_EntersLiveLeg(t *testing.T) {
	// Fail fast past the boot-race retry: this asserts the live leg is REACHED on
	// an undialable socket, not that the dial eventually succeeds, so shrink the
	// retry deadline to fail closed at once.
	defer func(d time.Duration) { eventSocketDialDeadline = d }(eventSocketDialDeadline)
	eventSocketDialDeadline = 0
	pb := validProto()
	// Absolute (validate requires it) but non-existent => the live-leg dial fails.
	pb.Attach.EventSocketPath = filepath.Join(t.TempDir(), "nonexistent-attach.sock")
	getenv := writeConfigDir(t, pb)
	var errSink bytes.Buffer
	code := Main(context.Background(), getenv, &errSink)
	if code != exitFailClosed {
		t.Errorf("valid-config exit code = %d; want exitFailClosed=%d (live leg reached). stderr=%q",
			code, exitFailClosed, errSink.String())
	}
	if !strings.Contains(errSink.String(), "attach socket") {
		t.Errorf("expected attach-socket dial diagnostic proving the live leg was entered, got: %q", errSink.String())
	}
}

// recordingLauncher wraps an offline launcher (the helperLauncher re-exec child,
// reused from supervise_test.go) and records that Main's live leg reached
// launch.start(). It exec's NO real runtime of its own — it delegates to the
// inner offline launcher — so the positive-launch tests stay fully offline (no
// real KVM/qemu/podman/claude).
type recordingLauncher struct {
	inner  launcher
	starts int
}

func (r *recordingLauncher) start(spec launchSpec, env []string) (runtimeProcess, runtimeStdio, error) {
	r.starts++
	return r.inner.start(spec, env)
}

// withLauncherDialer installs test launcher/dialer overrides on Main's injection
// seam for the duration of the test and restores them afterward. It is the ONLY
// way the seam is exercised — production never reads launcherHook/dialerHook.
func withLauncherDialer(t *testing.T, l launcher, d dialer) {
	t.Helper()
	prevL, prevD := launcherHook, dialerHook
	launcherHook, dialerHook = l, d
	t.Cleanup(func() { launcherHook, dialerHook = prevL, prevD })
}

// withReporter installs a test reporter override on Main's reporterHook seam for
// the duration of the test and restores it afterward. Production never reads
// reporterHook (nil => Main's multiReporter), so this is the only way a test can
// observe Main's live-leg ReportReady()/ReportExit() directly.
func withReporter(t *testing.T, r reporter) {
	t.Helper()
	prev := reporterHook
	reporterHook = r
	t.Cleanup(func() { reporterHook = prev })
}

// withTokenFetcher installs a test session-token fetcher override on Main's
// tokenFetcherHook seam (production never reads it: nil => the real
// httpTokenFetcher). validProto carries a set session_token_endpoint, so any test
// that drives Main's live leg past launch must inject an OFFLINE fetcher here —
// otherwise the live leg would attempt a real HTTP GET to the host-local shim and
// fail closed. This is the same offline-seam contract as withLauncherDialer.
func withTokenFetcher(t *testing.T, f tokenFetcher) {
	t.Helper()
	prev := tokenFetcherHook
	tokenFetcherHook = f
	t.Cleanup(func() { tokenFetcherHook = prev })
}

// TestMain_ValidConfig_PositiveLaunch is the live-leg positive path: a valid
// config (config-presence is the launch signal) carries Main's REAL supervisor
// assembly PAST the event-socket dial into launch.start() + ReportReady() +
// supervise, fully offline. We inject a fake dialer (an in-memory pipeSocket, no
// real UDS) and a recording fake launcher (helperLauncher re-execs the test
// binary as the "runtime" — a real OS process, but NOT a real Claude Code/VM/
// qemu). Asserting code==0, ReportReady was called exactly once, the fake dialer
// was reached with the configured socket path, and the fake launcher recorded a
// start (so the live-leg wiring past the dial actually ran), all without exec'ing
// any real runtime.
//
// This is the regression guard for Main's launcher/dialer assembly past the dial:
// if Main stopped building the supervisor from the injected launcher+dialer (or
// short-circuited before launch.start()/ReportReady()), the fake launcher would
// never record a start and/or ReportReady would never fire, and this test fails.
func TestMain_ValidConfig_PositiveLaunch(t *testing.T) {
	// Main builds its OWN reporter (multiReporter over sd_notify + best-effort
	// app reporter) — it is not injectable, so we observe ReportReady INDIRECTLY:
	// the supervisor reports ready BEFORE wiring stdio, and a ReportReady failure
	// tears the runtime down and returns exitFailClosed (supervisor.run step 3).
	// Therefore code==0 with a recorded launcher start proves ReportReady fired.
	//
	// We use the offline helper launcher (re-exec child, mode "emit-then-exit": it
	// writes a little output and exits 0) so the supervisor reaches a clean exit.
	recL := &recordingLauncher{inner: helperLauncher{mode: "emit-then-exit"}}
	d := &fakeDialer{sock: newPipeSocket()}
	withLauncherDialer(t, recL, d)
	// validProto sets session_token_endpoint => inject an offline fetcher so the
	// live leg does not attempt a real HTTP GET to the host-local shim.
	withTokenFetcher(t, &fakeTokenFetcher{token: "sk-test-token"})

	pb := validProto()
	// A valid, absolute event socket path. The fake dialer ignores it (returns the
	// in-mem socket), so no real UDS is touched; we still assert it was dialed.
	pb.Attach.EventSocketPath = filepath.Join(t.TempDir(), "attach.sock")
	// The helper re-exec child runs with cmd.Dir = WorkingDir; point it at an
	// existing dir so the offline child can actually start (the default /work does
	// not exist on the test host).
	pb.Launch.WorkingDir = t.TempDir()
	getenv := writeConfigDir(t, pb)

	var errSink bytes.Buffer
	code := Main(context.Background(), getenv, &errSink)

	if code != 0 {
		t.Fatalf("positive-launch exit code = %d; want 0 (clean runtime completion). stderr=%q", code, errSink.String())
	}
	if recL.starts != 1 {
		t.Errorf("fake launcher start called %d times; want 1 (Main's live leg must launch via the injected launcher)", recL.starts)
	}
	if d.dialedAt != pb.Attach.EventSocketPath {
		t.Errorf("fake dialer dialed %q; want the configured event socket %q (Main must dial before launch)", d.dialedAt, pb.Attach.EventSocketPath)
	}
	// code==0 with a recorded launcher start proves ReportReady succeeded: a
	// ReportReady failure tears the runtime down and returns exitFailClosed
	// (supervisor.run step 3), so the clean exit IS the readiness assertion.
}

// TestMain_ValidConfig_ReportsReadyAndExit_OnLiveLeg directly observes Main's
// live-leg readiness/exit reporting via an INJECTED fake reporter (the
// reporterHook seam). A valid config (config-presence is the launch signal)
// carries Main PAST the dial into launch.start() + ReportReady() + supervise +
// ReportExit, fully offline (fake dialer + recording launcher re-exec child).
//
// We assert the fake reporter saw EXACTLY ONE ReportReady() and a single
// ReportExit(reason=completed) on the clean runtime exit — the D81
// boot-segment-close observation. Unlike TestMain_ValidConfig_PositiveLaunch
// (which infers ReportReady INDIRECTLY from code==0), this pins the calls
// PRECISELY, so a Main/supervise regression that SHORT-CIRCUITS before
// ReportReady is caught: ready would be 0 (or exits empty), failing this test
// even if the exit code happened to land at 0.
func TestMain_ValidConfig_ReportsReadyAndExit_OnLiveLeg(t *testing.T) {
	recL := &recordingLauncher{inner: helperLauncher{mode: "emit-then-exit"}}
	d := &fakeDialer{sock: newPipeSocket()}
	rep := &recordingReporter{}
	withLauncherDialer(t, recL, d)
	withReporter(t, rep)
	withTokenFetcher(t, &fakeTokenFetcher{token: "sk-test-token"})

	pb := validProto()
	pb.Attach.EventSocketPath = filepath.Join(t.TempDir(), "attach.sock")
	pb.Launch.WorkingDir = t.TempDir() // existing dir for the offline re-exec child
	getenv := writeConfigDir(t, pb)

	var errSink bytes.Buffer
	code := Main(context.Background(), getenv, &errSink)

	if code != 0 {
		t.Fatalf("live-leg exit code = %d; want 0 (clean runtime completion). stderr=%q", code, errSink.String())
	}
	if recL.starts != 1 {
		t.Fatalf("fake launcher start called %d times; want 1 (Main's live leg must launch)", recL.starts)
	}
	// The load-bearing assertion: Main drove ReportReady exactly once. A
	// short-circuit before ReportReady (e.g. Main returning before supervisor.run
	// reaches step 3) makes this 0.
	if rep.ready != 1 {
		t.Errorf("ReportReady called %d times; want exactly 1 (D81 boot-segment-close on the live leg)", rep.ready)
	}
	// And ReportExit(completed) fired once on the clean runtime exit.
	if len(rep.exits) != 1 || rep.exits[0] != exitReasonCompleted {
		t.Errorf("exit reasons = %v; want [completed] (clean runtime exit observed)", rep.exits)
	}
	if len(rep.codes) != 1 || rep.codes[0] != 0 {
		t.Errorf("exit codes = %v; want [0] (clean runtime exit code reported)", rep.codes)
	}
	// The reporter override must have been the one the supervisor drove — if Main's
	// nil-default production multiReporter had been used instead, the fake would
	// have recorded nothing, which the ready/exit assertions above already catch.
}

// TestMain_ReporterHook_NilUsesProductionReporter pins the byte-identical
// guarantee of the reporterHook seam: with reporterHook nil (the default,
// production), supervisorReporter returns the production multiReporter Main
// builds UNCHANGED. We assert the resolver returns the exact same object so the
// production wiring is provably untouched when the hook is unset.
func TestMain_ReporterHook_NilUsesProductionReporter(t *testing.T) {
	if reporterHook != nil {
		t.Fatalf("reporterHook must default to nil (production); got %T", reporterHook)
	}
	prod := &multiReporter{primary: newSDNotifier(func(string) string { return "" })}
	if got := supervisorReporter(prod); got != reporter(prod) {
		t.Errorf("nil reporterHook must resolve to the production reporter unchanged; got %p, want %p", got, prod)
	}

	// With an override installed, the resolver returns the override instead.
	rep := &recordingReporter{}
	withReporter(t, rep)
	if got := supervisorReporter(prod); got != reporter(rep) {
		t.Errorf("set reporterHook must override the production reporter; got %p, want %p", got, rep)
	}
}

// TestMain_ConfigPresence_IsTheSoleSignal pins the maintainer ruling (2026-06-15,
// Option A): config-presence is the SOLE launch signal. There are EXACTLY TWO
// outcomes and no third path:
//
//   - a valid config present  => launch (Main enters the live leg; here that
//     reaches the injected launcher and returns the runtime's clean code 0).
//   - an absent/invalid config => exitFailClosed=78 and NO launch.
//
// There is NO LONGER a benign exit-0 validate-only path: a successful loadConfig
// falls straight through to supervisor.run, and the only non-launch outcome is
// loadConfig failing. This test guards against the reintroduction of an env gate
// (or any other "validate but don't launch, return 0" branch) — if such a path
// were added, the absent-config case below would have to return 0 to be benign,
// which this test forbids, OR the valid-config case would stop reaching the
// launcher, which the positive assertion forbids.
func TestMain_ConfigPresence_IsTheSoleSignal(t *testing.T) {
	// Outcome 1: valid config present => launch (reaches the injected launcher,
	// returns the clean runtime code). Offline: fake dialer + recording launcher.
	t.Run("valid_config_launches", func(t *testing.T) {
		recL := &recordingLauncher{inner: helperLauncher{mode: "emit-then-exit"}}
		d := &fakeDialer{sock: newPipeSocket()}
		withLauncherDialer(t, recL, d)
		// validProto sets session_token_endpoint => offline fetcher for the live leg.
		withTokenFetcher(t, &fakeTokenFetcher{token: "sk-test-token"})

		pb := validProto()
		pb.Attach.EventSocketPath = filepath.Join(t.TempDir(), "attach.sock")
		pb.Launch.WorkingDir = t.TempDir() // existing dir for the offline re-exec child
		getenv := writeConfigDir(t, pb)

		var errSink bytes.Buffer
		code := Main(context.Background(), getenv, &errSink)
		if code != 0 {
			t.Fatalf("valid config must launch: code = %d; want 0. stderr=%q", code, errSink.String())
		}
		if recL.starts != 1 {
			t.Fatalf("valid config must reach launch.start; starts = %d; want 1", recL.starts)
		}
	})

	// Outcome 2: absent config (non-existent config dir) => exitFailClosed=78 and
	// NO launch. This is the boot-validate / dry-boot case. There is no exit-0
	// validate-only path: a missing config is the ONLY non-launch outcome, and it
	// is fail-closed, never benign-zero.
	t.Run("absent_config_fail_closed_78", func(t *testing.T) {
		recL := &recordingLauncher{inner: helperLauncher{mode: "emit-then-exit"}}
		d := &fakeDialer{sock: newPipeSocket()}
		withLauncherDialer(t, recL, d)

		// Point at a non-existent config dir => loadConfig fails (no config.pb).
		missing := filepath.Join(t.TempDir(), "no-such-config-dir")
		getenv := func(k string) string {
			if k == configDirEnv {
				return missing
			}
			return ""
		}

		var errSink bytes.Buffer
		code := Main(context.Background(), getenv, &errSink)
		if code != exitFailClosed {
			t.Fatalf("absent config must fail closed: code = %d; want exitFailClosed=%d (NOT a benign exit-0 validate-only path). stderr=%q",
				code, exitFailClosed, errSink.String())
		}
		if recL.starts != 0 {
			t.Errorf("absent config must NOT launch a runtime; launcher started %d times", recL.starts)
		}
	})
}

func TestAppReporterSocketPath(t *testing.T) {
	cfg := entrypointConfig{attach: attachWiring{eventSocketPath: "/run/ds/attach.sock"}}
	if got := appReporterSocketPath(cfg); got != "/run/ds/attach.sock.rpc" {
		t.Errorf("appReporterSocketPath = %q", got)
	}
	if got := appReporterSocketPath(entrypointConfig{}); got != "" {
		t.Errorf("empty attach => empty rpc path; got %q", got)
	}
}
