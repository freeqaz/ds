// SPDX-License-Identifier: Apache-2.0

package hostredeployconverge

import (
	"errors"
	"os"
	"testing"
)

// live_test.go — the LIVE half of the re-key-on-host-redeploy conformance suite.
// DEFERRED MANUAL, env-gated behind DS_HOST_REDEPLOY_LIVE=1, and SKIPPED BY
// DEFAULT so `go test ./...` stays green offline and in CI. The live runner drives
// a REAL host redeploy on a real KVM boundary host (LiveHost()) and feeds the
// observed re-key into the SAME Evaluate the offline half asserts — so the wire
// pass and the offline spec can never disagree on a converged/violated verdict.
//
// Per the wave rules we never stand up a live KVM/host/boundary here (D50): the
// runner is SCAFFOLDED via RunLive, which fails LOUDLY with ErrLiveDriverNotWired
// until an operator wires the deferred manual pass against a real redeploy. A
// half-configured live run can therefore never look like a pass (HONEST STATUS).

// requireLive skips the calling test unless DS_HOST_REDEPLOY_LIVE=1. This is the
// default-skip behavior the acceptance criteria name: with the var unset, every
// live test is skipped and the package is green.
func requireLive(t *testing.T) {
	t.Helper()
	if !LiveEnabled() {
		t.Skipf("live re-key-on-host-redeploy conformance is a deferred manual pass; set %s=1 to run (default skip — no live KVM/host/boundary in-wave, D50)", LiveEnvVar)
	}
}

// TestLive_RekeyOnHostRedeployConverges is the env-gated live conformance pass for
// the doc 16 §6.3 / D26/D51 claim: a real host redeploy re-pushes every live
// digest under the new key without violating mint-before-attach. Skipped by
// default. Under DS_HOST_REDEPLOY_LIVE=1 it drives a REAL redeploy via RunLive,
// then verdicts the observed re-key with Evaluate, asserting convergence with no
// violations.
//
// Until an operator wires the real driver, RunLive returns ErrLiveDriverNotWired
// and this test FAILS LOUDLY (never a false green) — the scaffold makes the
// deferred manual step explicit. There is no live KVM in this wave.
func TestLive_RekeyOnHostRedeployConverges(t *testing.T) {
	requireLive(t)

	obs, err := RunLive()
	if err != nil {
		// The scaffolded state: the real driver is not wired. Fail loudly with the
		// exact thing an operator must stand up.
		t.Fatalf("live host-redeploy driver not wired: %v "+
			"(set %s to the KVM boundary host once the deferred manual pass is wired; "+
			"the synthetic offline half is the in-wave proof)", err, HostEnvVar)
	}

	v := Evaluate(obs)
	if !v.Converged {
		t.Fatalf("live re-key did NOT converge — mint-before-attach or completeness violated: %v", v.Violations)
	}
	if v.CarriedForward != v.LiveCount {
		t.Errorf("live re-key carried %d of %d live digests forward; every live digest must be re-pushed (doc 16 §6.3)", v.CarriedForward, v.LiveCount)
	}
}

// TestLiveDefaultSkip is a guard that ALWAYS runs (it does not call requireLive):
// it asserts the gate is named DS_HOST_REDEPLOY_LIVE and that, with the var unset,
// the live half is skipped by default — the acceptance criterion "live tests
// skipped by default; no live KVM in-wave". When the var is unset it verifies
// LiveEnabled() is false; when an operator sets it to 1 it verifies the opt-in is
// honored. Either way this guard itself never needs the live fixtures.
func TestLiveDefaultSkip(t *testing.T) {
	if LiveEnvVar != "DS_HOST_REDEPLOY_LIVE" {
		t.Fatalf("live gate env var = %q, want DS_HOST_REDEPLOY_LIVE", LiveEnvVar)
	}
	switch os.Getenv(LiveEnvVar) {
	case "":
		if LiveEnabled() {
			t.Error("DS_HOST_REDEPLOY_LIVE unset but LiveEnabled() is true; the live half must be skipped by default")
		}
	case "1":
		if !LiveEnabled() {
			t.Error("DS_HOST_REDEPLOY_LIVE=1 but LiveEnabled() is false; the opt-in must be honored")
		}
	}
}

// TestRunLive_NotWiredUntilOperatorWiresIt asserts the scaffold contract WITHOUT
// the live gate (pure, runs in ordinary CI): RunLive fails with
// ErrLiveDriverNotWired so the deferred manual pass can never silently report a
// false green. It calls RunLive directly (not the gated test) so the scaffolded
// state is regression-protected even when DS_HOST_REDEPLOY_LIVE is unset.
func TestRunLive_NotWiredUntilOperatorWiresIt(t *testing.T) {
	_, err := RunLive()
	if !errors.Is(err, ErrLiveDriverNotWired) {
		t.Fatalf("RunLive should return ErrLiveDriverNotWired until the operator wires the deferred manual pass, got %v", err)
	}
}
