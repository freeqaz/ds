// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"context"
	"io"
)

// run.go is the package-level entry point the thin cmd/ds-entrypoint shell calls.
// It assembles the fail-closed boot: load+validate the config, build the
// readiness reporters, then launch and supervise the runtime. Keeping the
// assembly here (not in package main) means the boot path is exercised by this
// package's own offline tests with injected fakes.
//
// CONFIG-PRESENCE LAUNCH SIGNAL (maintainer ruling 2026-06-15, Option A): a valid
// EntrypointConfig present in DS_ENTRYPOINT_CONFIG_DIR is ITSELF the launch
// signal — a successful loadConfig falls straight into supervisor.run. There is
// no separate live-leg env gate. The only no-launch path is loadConfig failing
// (absent/empty/invalid config.pb), which is the boot-validate / dry-boot case:
// it drops no config and returns exitFailClosed without launching a runtime.

// Main runs the entrypoint and returns the process exit code. getenv reads the
// environment (injected for tests); errSink receives diagnostics. It NEVER
// panics on a bad config — every failure is a fail-closed nonzero exit.
func Main(ctx context.Context, getenv func(string) string, errSink io.Writer) int {
	logf := func(format string, args ...any) {
		// route through the same prefix as defaultLogf but to the injected sink
		writeLogf(errSink, format, args...)
	}

	cfg, err := loadConfig(getenv)
	if err != nil {
		logf("fail-closed: %v", err)
		return exitFailClosed
	}

	// Build the load-bearing sd_notify reporter and the best-effort
	// EntrypointService app reporter. The app reporter is wired only when the
	// host-agent terminator is reachable over the guest-local transport; its
	// failures are non-fatal (the §3 state machine is the lifecycle authority).
	sd := newSDNotifier(getenv)
	rep := &multiReporter{
		primary:         sd,
		onBestEffortErr: func(e error) { logf("%v", e) },
	}
	if r, closeFn := maybeDialAppReporter(cfg, logf); r != nil {
		rep.best = append(rep.best, r)
		if closeFn != nil {
			defer func() { _ = closeFn() }()
		}
	}

	// A valid config is present => launch + supervise. (The boot-validate /
	// dry-boot no-launch path is loadConfig failing above; it returns
	// exitFailClosed and never reaches here.)
	sigCtx, cancel := installSignalHandler(ctx)
	defer cancel()

	// NOTE: launch is NOT pre-resolved here. The supervisor selects its launcher
	// per-config at run time via chooseLauncher(cfg): the launcherHook test seam
	// wins, then an explicitly-set s.launch, then the production launcher chosen by
	// the launch surface's stdio disposition (PTY => ptyLauncher, else execLauncher).
	// Leaving s.launch nil is the production case.
	sup := &supervisor{
		dial:    supervisorDialer(),
		report:  supervisorReporter(rep),
		fetcher: supervisorTokenFetcher(),
		logf:    logf,
		errSink: errSink,
	}
	code, err := sup.run(sigCtx, cfg)
	if err != nil {
		logf("fail-closed: %v", err)
	}
	return code
}

// --- launcher/dialer injection seam (test-only) ---
//
// Main's live leg assembles the supervisor from a launcher and a dialer
// (event-socket UDS). The PRODUCTION launcher is chosen per-config by
// (*supervisor).chooseLauncher (stdioPTY => ptyLauncher, else execLauncher); the
// production dialer is fixed as unixDialerImpl{}. These package-private hooks exist
// ONLY so this package's offline tests can substitute a fake launcher + fake
// dialer and drive Main's real assembly PAST the event-socket dial into
// supervisor.run — launch.start(), ReportReady(), and supervise — without a real
// KVM/qemu/runtime process or a real UDS.
//
// Default (nil) => the production path, so Main's production path is BYTE-IDENTICAL
// when the hooks are not overridden: a nil launcherHook lets chooseLauncher pick
// the production launcher by disposition, and a nil dialerHook resolves to
// unixDialerImpl{} — exactly the behavior the prod path had before the seam
// existed. A test sets these (and restores them via t.Cleanup); no env var, build
// tag, or production branch ever reads them.
//
// reporterHook follows the SAME contract for the readiness/exit reporter: the
// PRODUCTION reporter is the multiReporter (sd_notify + best-effort app reporter)
// Main builds above, and a nil reporterHook resolves to exactly THAT object — so
// the production path is BYTE-IDENTICAL when the hook is unset. When set it
// SUPPLIES the reporter the supervisor drives, letting a test inject a fake
// recording reporter to observe ReportReady()/ReportExit() on the live leg
// without standing up a real sd_notify/EntrypointService transport.
var (
	launcherHook     launcher     // nil => execLauncher{}
	dialerHook       dialer       // nil => unixDialerImpl{}
	reporterHook     reporter     // nil => the production multiReporter Main builds
	tokenFetcherHook tokenFetcher // nil => the production httpTokenFetcher{}
)

// chooseLauncher resolves the launcher the supervisor drives FOR THIS CONFIG, in
// precedence order:
//
//  1. launcherHook (the test-only injection seam, run.go) — when set it wins, so
//     the package's offline tests substitute a fake launcher regardless of the
//     config's stdio disposition. Production never sets it (nil).
//  2. an explicitly-set s.launch — so existing tests that build a supervisor with a
//     concrete launcher (supervise_test.go's helperLauncher) keep working untouched.
//  3. the PRODUCTION launcher chosen by the launch surface: stdioPTY selects the
//     ptyLauncher (seeded with the launch surface's initial window), every other
//     disposition (pipes / unspecified) selects execLauncher — the byte-identical
//     historical pipes path.
//
// Resolving per-config (not once in Main) is what lets the launch surface's stdio
// disposition pick the launcher; the dial-before-launch invariant is unchanged
// (supervise.run still dials before calling start()).
func (s *supervisor) chooseLauncher(cfg entrypointConfig) launcher {
	if launcherHook != nil {
		return launcherHook
	}
	if s.launch != nil {
		return s.launch
	}
	if cfg.launch.stdio == stdioPTY {
		return ptyLauncher{initialWinsize: cfg.launch.initialWinsize}
	}
	return execLauncher{}
}

// supervisorDialer returns the dialer Main wires into the supervisor: the test
// override when set, else the production unixDialerImpl{}.
func supervisorDialer() dialer {
	if dialerHook != nil {
		return dialerHook
	}
	return unixDialerImpl{}
}

// supervisorReporter returns the reporter Main wires into the supervisor: the
// test override when set, else the production reporter (prod) Main just built.
// A nil reporterHook returns prod unchanged, so the production path is
// byte-identical to passing the multiReporter directly.
func supervisorReporter(prod reporter) reporter {
	if reporterHook != nil {
		return reporterHook
	}
	return prod
}

// supervisorTokenFetcher returns the session-token fetcher Main wires into the
// supervisor: the test override when set, else nil (the supervisor then resolves
// nil to the production httpTokenFetcher{} at use). A nil tokenFetcherHook yields
// a nil fetcher field, so the production path is byte-identical to leaving the
// field unset — same test-only-seam contract as launcherHook/dialerHook.
func supervisorTokenFetcher() tokenFetcher {
	return tokenFetcherHook
}

// maybeDialAppReporter best-effort dials the EntrypointService terminator so the
// guest can send the app-level readiness/exit reports. The transport is FREE
// (OQ-C); we reach the host agent over a guest-local UDS adjacent to the event
// socket. A dial failure is logged and ignored — sd_notify remains the
// load-bearing readiness signal. Returns (nil, nil) when no app reporter is
// available.
func maybeDialAppReporter(cfg entrypointConfig, logf stderrLogf) (reporter, func() error) {
	path := appReporterSocketPath(cfg)
	if path == "" {
		return nil, nil
	}
	client, closeFn, err := dialEntrypointService(path)
	if err != nil {
		logf("EntrypointService app report unavailable (best-effort): %v", err)
		return nil, nil
	}
	return newEntrypointServiceReporter(client, cfg.session), closeFn
}

// appReporterSocketPath derives the EntrypointService UDS path. The frozen
// EntrypointConfig does not carry a dedicated field for the EntrypointService
// endpoint (the delivery/transport of EntrypointService is FREE under OQ-C), so
// we derive it from the same guest-local convention as the event socket: a
// sibling ".rpc" suffix beside AttachWiring.event_socket_path. If the host agent
// later names an explicit endpoint, only this one function changes.
//
// Empty event socket => no app reporter (sd_notify still covers readiness).
func appReporterSocketPath(cfg entrypointConfig) string {
	base := cfg.attach.eventSocketPath
	if base == "" {
		return ""
	}
	return base + ".rpc"
}
