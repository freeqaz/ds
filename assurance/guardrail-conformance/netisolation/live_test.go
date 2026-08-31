// SPDX-License-Identifier: Apache-2.0

package netisolation

// live_test.go — the LIVE half of the Stage-2 network-isolation (c) rows.
// DEFERRED MANUAL, env-gated behind DS_NETISO_LIVE=1, and SKIPPED BY DEFAULT so
// `go test ./...` stays green offline and in CI.
//
// PROJECT CONSTRAINT (binding): no live claude / cia / podman, and NO
// CAP_NET_ADMIN / live-nft / live-KVM execution in CI. The live runners would
// drive a real boundary (a real ds-nft ruleset + two agent taps + the boundary
// host network namespace on a virtual-metal VM) and observe the actual
// disposition of each isolation probe:
//
//   - in-VM spoofing: a packet on an agent tap with a forged source IP is matched
//     on `iifname` (not source IP), redirected to the boundary, and a three-keys
//     disagreement is a kernel drop (NFT-2 / D44);
//   - ECH / HTTPS-SVCB: an HTTPS (type 65) / SVCB (type 64) query returns NODATA
//     with an authored SOA — no such record reaches the VM — and a TLS ClientHello
//     carrying ECH is refused (DNS-4 + TLS-1);
//   - session isolation: no L2 path exists between two agent taps, proven
//     structurally (routed tap / per-session bridge) or under the BR_ISOLATED flag
//     audit, never inherited from the inet default-deny (§2 placement + NFT-1, D66);
//   - IPv6 dormant closure: AAAA → fast NOERROR/NODATA, no v6 reach is open from an
//     agent tap, and a sibling fe80::/10 probe between taps shows the host netns
//     closes the link-local path (D75 nightly row);
//   - controls unreachable: a probe at a control-plane endpoint (proxy / nftables /
//     policy / identity) from a VM interface is dropped, not answered (NFT-1 + §2).
//
// Each runner is SCAFFOLDED, not implemented: per the wave rules and the
// live-nft / live-KVM constraint we stand up no real boundary here. A runner
// fails LOUDLY with a "not yet wired" marker naming the row's tag so an operator
// running the deferred manual pass knows exactly what to stand up, and a
// half-configured live run can never look like a pass (HONEST STATUS). The
// runner table is keyed on the single-sourced Tags, so the live table and the
// offline row set can never drift (the nftgate / resolverlock live-runner
// precedent).

import (
	"os"
	"strings"
	"testing"
)

// liveEnvVar is the single gate. The suite is a deferred manual pass; nothing
// here runs unless an operator opts in explicitly. (Sibling of the nftgate
// DS_NFTGATE_LIVE and resolverlock DS_RESOLVERLOCK_LIVE gates.)
const liveEnvVar = "DS_NETISO_LIVE"

// liveEnabled reports whether the operator opted into the live pass.
func liveEnabled() bool { return os.Getenv(liveEnvVar) == "1" }

// requireLive skips the calling test unless DS_NETISO_LIVE=1.
func requireLive(t *testing.T) {
	t.Helper()
	if !liveEnabled() {
		t.Skipf("live Stage-2 network-isolation conformance is a deferred manual pass; set %s=1 to "+
			"run (default skip; needs a real boundary + two agent taps + CAP_NET_ADMIN, never run "+
			"in CI)", liveEnvVar)
	}
}

// liveRunner is the signature every documented live observation implements once
// an operator wires the deferred manual pass to a real boundary.
type liveRunner func(t *testing.T, tag string)

// notWiredReason is the pure (testable) body of the deferred-runner failure
// message: the exact row (by single-sourced tag) an operator must stand up and
// the binding live-execution constraint. Keeping it a pure function lets the
// non-vacuity guard (TestLiveFailsLoud) assert the runner always has a loud
// reason without faking a *testing.T.
func notWiredReason(tag string) string {
	return "live runner for row " + tag + " is a DEFERRED MANUAL step: wire it against a real " +
		"boundary only (no live claude/cia/podman; no CAP_NET_ADMIN / live nft / live KVM in CI). " +
		"It must observe the documented disposition on the wire, reusing the same modeled Check the " +
		"offline half asserts so the two can never disagree."
}

// notYetWired is the placeholder body for every runner. It is a DEFERRED MANUAL
// step gated behind DS_NETISO_LIVE=1 and additionally behind an operator standing
// up a real boundary; until then it fails loudly with the exact row it needs, so
// a half-configured live run can never look like a pass.
func notYetWired(t *testing.T, tag string) {
	t.Helper()
	t.Fatal(notWiredReason(tag))
}

// liveRunners maps each Stage-2 row (by single-sourced tag) to its (scaffolded)
// live observation runner. Every tag in Tags has an entry; an operator wiring the
// deferred pass replaces notYetWired one row at a time.
func liveRunners() map[string]liveRunner {
	return map[string]liveRunner{
		TagInVMSpoofingFails:           notYetWired,
		TagECHHTTPSSVCBSuppression:     notYetWired,
		TagSessionANotBNoL2Path:        notYetWired,
		TagIPv6ClosureDormantFe80Probe: notYetWired,
		TagControlsUnreachableFromVM:   notYetWired,
	}
}

// TestLive_Stage2Isolation drives every Stage-2 row against its live runner under
// DS_NETISO_LIVE=1. Skipped by default.
func TestLive_Stage2Isolation(t *testing.T) {
	requireLive(t)
	runners := liveRunners()
	for _, tag := range Tags {
		run, ok := runners[tag]
		if !ok {
			t.Fatalf("row %q has no registered live runner", tag)
		}
		t.Run(tag, func(t *testing.T) { run(t, tag) })
	}
}

// TestLiveDefaultSkip is a guard that ALWAYS runs (it does not call requireLive):
// it asserts the gate is named DS_NETISO_LIVE and that, with the var unset, the
// live half is skipped by default — the acceptance criterion "any live leg is
// env-gated and fails-loud-but-off by default".
func TestLiveDefaultSkip(t *testing.T) {
	if liveEnvVar != "DS_NETISO_LIVE" {
		t.Fatalf("live gate env var = %q, want DS_NETISO_LIVE", liveEnvVar)
	}
	switch os.Getenv(liveEnvVar) {
	case "":
		if liveEnabled() {
			t.Error("DS_NETISO_LIVE unset but liveEnabled() is true; the live half must be skipped by default")
		}
	case "1":
		if !liveEnabled() {
			t.Error("DS_NETISO_LIVE=1 but liveEnabled() is false; the opt-in must be honored")
		}
	}
}

// TestLiveRunnerCoverage asserts every Stage-2 row (Tags) has a registered live
// runner and no registered runner is orphaned. This runs WITHOUT the live gate
// (pure table consistency), so a drift between the row table and the runner table
// is caught in ordinary CI.
func TestLiveRunnerCoverage(t *testing.T) {
	runners := liveRunners()
	known := map[string]bool{}
	for _, tag := range Tags {
		known[tag] = true
		if _, ok := runners[tag]; !ok {
			t.Errorf("Stage-2 row %q has no registered live runner", tag)
		}
	}
	for tag := range runners {
		if !known[tag] {
			t.Errorf("registered live runner for %q is not a Stage-2 row tag", tag)
		}
	}
}

// TestLiveFailsLoud proves the deferred runners are NOT vacuous: every row's
// scaffolded runner has a loud, specific "not yet wired" reason naming the row's
// tag — so an unwired live leg can never silently look like a pass. It asserts
// the pure reason function (the body notYetWired delegates to) without faking a
// *testing.T. Runs WITHOUT the live gate (the fail-loud contract itself is what
// we check, not a wire observation).
func TestLiveFailsLoud(t *testing.T) {
	for _, tag := range Tags {
		reason := notWiredReason(tag)
		if reason == "" {
			t.Errorf("live runner for row %q has an empty fail reason; an unwired live leg must fail loudly", tag)
		}
		if !strings.Contains(reason, tag) {
			t.Errorf("live runner reason for %q does not name the row tag: %q", tag, reason)
		}
	}
}
