// SPDX-License-Identifier: Apache-2.0

package logreconcileadapter

import (
	"errors"
	"os"
	"testing"
)

// live_test.go — the LIVE half of the LOG-4 per-session stream-reconciliation
// conformance suite (doc 06 §3c / doc 09 §7). DEFERRED MANUAL, env-gated behind
// DS_LOG4_LIVE=1, and SKIPPED BY DEFAULT so `go test ./...` stays green offline
// and in CI. The live runner would drive a REAL ds-flowlog proxy
// system-of-record stream against the independent kernel conntrack ledger for one
// live session (LiveSession()), join them into the SAME
// logreconcile.SessionReconciliation shape the offline half asserts, and run
// logreconcile.CheckReconciliation — so the wire pass and the offline spec can
// never disagree on a reconciliation verdict.
//
// Per the wave rules we never run live claude / cia run / podman, and never stand
// up a real ds-flowlog / conntrack / nft / KVM here (D50): the runner is
// SCAFFOLDED via RunLive, which fails LOUDLY with ErrLiveDriverNotWired until an
// operator wires the deferred manual pass against a real session. A
// half-configured live run can therefore never look like a pass (HONEST STATUS).

// requireLive skips the calling test unless DS_LOG4_LIVE=1. This is the
// default-skip behavior the acceptance criteria name: with the var unset, every
// live test is skipped and the package is green.
func requireLive(t *testing.T) {
	t.Helper()
	if !LiveEnabled() {
		t.Skipf("live LOG-4 per-session stream-reconciliation conformance is a deferred manual pass; set %s=1 to run (default skip — no live ds-flowlog/conntrack/boundary in-wave, D50)", LiveEnvVar)
	}
}

// TestLive_PerSessionStreamReconciliation is the env-gated live conformance pass
// for the doc 06 §3c / doc 09 §7 LOG-4 claim: the boundary continuously
// reconciles a session's ds-flowlog proxy system-of-record stream against the
// kernel conntrack ledger, with no proxy-flow gap, no unexplained conntrack flow,
// no D44 three-keys disagreement, no double-count, no D72 version inversion, and
// every divergence alarmed. Skipped by default. Under DS_LOG4_LIVE=1 it drives a
// REAL reconciliation via RunLive, then asserts convergence (an empty violation
// set).
//
// Until an operator wires the real driver, RunLive returns ErrLiveDriverNotWired
// and this test FAILS LOUDLY (never a false green) — the scaffold makes the
// deferred manual step explicit. There is no live ds-flowlog/conntrack in this
// wave.
func TestLive_PerSessionStreamReconciliation(t *testing.T) {
	requireLive(t)

	v, err := RunLive()
	if err != nil {
		// The scaffolded state: the real driver is not wired. Fail loudly with the
		// exact thing an operator must stand up.
		t.Fatalf("live LOG-4 reconciliation driver not wired: %v "+
			"(set %s to the live session id once the deferred manual pass is wired; "+
			"the synthetic offline half — guardrail-conformance/logreconcile — is the in-wave proof)",
			err, SessionEnvVar)
	}

	if !v.Reconciled {
		t.Fatalf("live session %q did NOT reconcile — the LOG-4 per-session accounting identity was violated: %v "+
			"(every byte that left a VM interface must be explained by the other stream; an unexplained "+
			"divergence is an alarm, not a log line — doc 09 §7 LOG-4, doc 12 §2.3)", v.Session, v.Violations)
	}
	if len(v.Violations) != 0 {
		t.Errorf("live verdict reports Reconciled but carries %d violation(s): %v — a reconciled verdict must be empty", len(v.Violations), v.Violations)
	}
}

// TestLiveDefaultSkip is a guard that ALWAYS runs (it does not call requireLive):
// it asserts the gate is named DS_LOG4_LIVE and that, with the var unset, the
// live half is skipped by default — the acceptance criterion "live tests skipped
// by default; no live ds-flowlog/conntrack in-wave". When the var is unset it
// verifies LiveEnabled() is false; when an operator sets it to 1 it verifies the
// opt-in is honored. Either way this guard itself never needs the live fixtures.
func TestLiveDefaultSkip(t *testing.T) {
	if LiveEnvVar != "DS_LOG4_LIVE" {
		t.Fatalf("live gate env var = %q, want DS_LOG4_LIVE", LiveEnvVar)
	}
	switch os.Getenv(LiveEnvVar) {
	case "":
		if LiveEnabled() {
			t.Error("DS_LOG4_LIVE unset but LiveEnabled() is true; the live half must be skipped by default")
		}
	case "1":
		if !LiveEnabled() {
			t.Error("DS_LOG4_LIVE=1 but LiveEnabled() is false; the opt-in must be honored")
		}
	}
}

// TestRunLive_NotWiredUntilOperatorWiresIt asserts the scaffold contract WITHOUT
// the live gate (pure, runs in ordinary CI): RunLive fails with
// ErrLiveDriverNotWired so the deferred manual pass can never silently report a
// false green. It calls RunLive directly (not the gated test) so the scaffolded
// state is regression-protected even when DS_LOG4_LIVE is unset.
func TestRunLive_NotWiredUntilOperatorWiresIt(t *testing.T) {
	_, err := RunLive()
	if !errors.Is(err, ErrLiveDriverNotWired) {
		t.Fatalf("RunLive should return ErrLiveDriverNotWired until the operator wires the deferred manual pass, got %v", err)
	}
}

// TestLiveViolationClassesMatchLogreconcile pins the LOG-4 taxonomy mirror to the
// canonical class strings the offline package
// (assurance/guardrail-conformance/logreconcile) single-sources, so a rename in
// EITHER half fails LOUDLY here rather than letting the live driver report a
// verdict in terms the offline spec no longer names. This runs WITHOUT the live
// gate (pure table consistency) — it is the git-side twin of logreconcile's own
// taxonomy and the single-sourcing seam that makes the eventual swap to a direct
// `type LiveViolationClass = logreconcile.ViolationClass` alias mechanical.
//
// The expected strings are the doc 09 §7 class names verbatim. When the go.mod
// require+replace lands, this test is upgraded to compare against
// logreconcile.ViolationClass(...) directly; until then it pins the documented
// values so the mirror cannot silently drift from the package it mirrors.
func TestLiveViolationClassesMatchLogreconcile(t *testing.T) {
	// The canonical six, in the doc 09 §7 / logreconcile enumeration order.
	want := []LiveViolationClass{
		"proxy-flow-unreconciled-in-conntrack",
		"conntrack-flow-unexplained",
		"three-keys-disagree-not-dropped",
		"flow-double-counted",
		"decision-version-older-than-admitting-dns",
		"divergence-not-alarmed",
	}
	got := LiveViolationClasses()
	if len(got) != len(want) {
		t.Fatalf("LiveViolationClasses() has %d classes, want %d (the six named LOG-4 reconciliation failure modes; doc 09 §7)", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("LOG-4 violation class[%d] = %q, want %q — the mirror has drifted from logreconcile's canonical taxonomy (doc 09 §7); re-sync the mirror or the offline package", i, got[i], want[i])
		}
	}
	// Guard against duplicates / empties slipping into the enum.
	seen := map[LiveViolationClass]bool{}
	for _, c := range got {
		if c == "" {
			t.Error("LiveViolationClasses() contains an empty class name")
		}
		if seen[c] {
			t.Errorf("LiveViolationClasses() contains duplicate class %q", c)
		}
		seen[c] = true
	}
}

// TestRunLiveReturnsSentinelWhenDisabled asserts that even a direct RunLive call
// with the gate unset surfaces ErrLiveDriverNotWired (never an empty,
// vacuously-reconciled verdict) — so a caller that forgets requireLive can never
// mistake a disabled run for a clean reconciliation. Pure; runs in ordinary CI.
func TestRunLiveReturnsSentinelWhenDisabled(t *testing.T) {
	if LiveEnabled() {
		t.Skip("DS_LOG4_LIVE=1 — this guard covers the disabled path only")
	}
	v, err := RunLive()
	if !errors.Is(err, ErrLiveDriverNotWired) {
		t.Fatalf("RunLive with the gate unset must return ErrLiveDriverNotWired, got %v", err)
	}
	if v.Reconciled {
		t.Error("a disabled RunLive must NOT report Reconciled=true (no vacuous convergence)")
	}
	if len(v.Violations) != 0 {
		t.Errorf("a disabled RunLive must return a zero LiveVerdict, got %d violations", len(v.Violations))
	}
}
