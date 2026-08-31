// SPDX-License-Identifier: Apache-2.0

package e2e

// lifecycle_live_test.go — the LIVE full-stack half of the (b) session-lifecycle
// suite. DEFERRED MANUAL, env-gated behind DS_E2E_LIFECYCLE_LIVE=1, and SKIPPED BY
// DEFAULT so `go test ./...` stays green offline and in CI (the nested-ok lane in
// lifecycle_test.go is the per-commit suite).
//
// PROJECT CONSTRAINT (binding): no live claude / cia / podman, and no KVM /
// nested-virt in CI. The live runner would drive orchestrator-lite under
// DS_ORCH_LITE_LIVE=1 against a REAL host agent (a real hypervisor.v1 driver +
// the Identity service + the boundary CA-inject/boot verbs) on a virtual-metal
// host and observe the actual create→attach→[work]→destroy lifecycle on real
// infrastructure — including the metal-only assertions (D34): the pause budgets
// (D46) and the snapshot/CoW storage semantics nested KVM cannot prove honestly.
//
// It is SCAFFOLDED, not implemented: per the wave rules we stand up no real host
// here. The runner fails LOUDLY with a "not yet wired" marker naming exactly what
// an operator must stand up, so a half-configured live run can never look like a
// pass (HONEST STATUS), and so the metal-nightly lane (.github/workflows/e2e.yml)
// has a real target to invoke once a virtual-metal runner exists.

import (
	"os"
	"strings"
	"testing"
)

// liveEnvVar is the single gate for the deferred live full-stack lifecycle pass.
const liveEnvVar = "DS_E2E_LIFECYCLE_LIVE"

// liveEnabled reports whether the operator opted into the live pass.
func liveEnabled() bool { return os.Getenv(liveEnvVar) == "1" }

// notWiredReason is the pure (testable) body of the deferred-runner failure
// message: exactly what an operator must stand up for the live full-stack pass.
// Keeping it pure lets the non-vacuity guard assert the runner always fails loud
// without faking a *testing.T.
func notWiredReason() string {
	return "live full-stack lifecycle runner is a DEFERRED MANUAL step: run orchestrator-lite under " +
		"DS_ORCH_LITE_LIVE=1 against a real host agent (hypervisor.v1 driver) + Identity service on a " +
		"virtual-metal host, and observe create→attach→[work]→destroy plus the metal-only assertions " +
		"(D34 fidelity: D46 pause budgets, snapshot/CoW semantics). No live claude/cia/podman and no " +
		"KVM/nested-virt in CI; the nested-ok lane (lifecycle_test.go) is the per-commit suite."
}

// TestLive_FullStackLifecycle drives the live full-stack lifecycle under the gate.
// Skipped by default; fails loud (not yet wired) when the operator opts in,
// pending a virtual-metal host.
func TestLive_FullStackLifecycle(t *testing.T) {
	if !liveEnabled() {
		t.Skipf("live full-stack lifecycle is a deferred manual pass; set %s=1 to run "+
			"(default skip; needs a real host agent + KVM, never run in CI)", liveEnvVar)
	}
	t.Fatal(notWiredReason())
}

// TestLiveDefaultSkip is a guard that ALWAYS runs (it does not call the gate): it
// asserts the gate is named DS_E2E_LIFECYCLE_LIVE and that, with the var unset,
// the live half is skipped by default — the acceptance criterion that any live
// leg is env-gated and fails-loud-but-off by default.
func TestLiveDefaultSkip(t *testing.T) {
	if liveEnvVar != "DS_E2E_LIFECYCLE_LIVE" {
		t.Fatalf("live gate env var = %q, want DS_E2E_LIFECYCLE_LIVE", liveEnvVar)
	}
	switch os.Getenv(liveEnvVar) {
	case "":
		if liveEnabled() {
			t.Error("DS_E2E_LIFECYCLE_LIVE unset but liveEnabled() is true; the live half must be skipped by default")
		}
	case "1":
		if !liveEnabled() {
			t.Error("DS_E2E_LIFECYCLE_LIVE=1 but liveEnabled() is false; the opt-in must be honored")
		}
	}
}

// TestLiveFailsLoud proves the deferred runner is NOT vacuous: it has a loud,
// specific "not yet wired" reason naming what to stand up — so an unwired live leg
// can never silently look like a pass. Runs WITHOUT the live gate (the fail-loud
// contract itself is what we check, not a live observation).
func TestLiveFailsLoud(t *testing.T) {
	reason := notWiredReason()
	if reason == "" {
		t.Fatal("the live full-stack runner has an empty fail reason; an unwired live leg must fail loudly")
	}
	for _, want := range []string{"DS_ORCH_LITE_LIVE=1", "virtual-metal", "D46", "DEFERRED MANUAL"} {
		if !strings.Contains(reason, want) {
			t.Errorf("live runner reason must name %q so an operator knows what to stand up: %q", want, reason)
		}
	}
}
