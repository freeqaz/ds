// SPDX-License-Identifier: Apache-2.0

package tlsproxyinspect

// live_test.go — the LIVE half of the TLS-3.a-d conformance. DEFERRED MANUAL,
// env-gated behind DS_TLS3_LIVE=1, SKIPPED BY DEFAULT so `go test ./...` stays
// green offline and in CI. The live runners drive the documented client wire
// shapes against a RUNNING ds-tlsproxy (the egress gateway terminating TLS) at
// DS_TLS3_TLSPROXY_ADDR:
//
//   - 3.a: curl / npm / git over HTTPS through the egress gateway see VALID TLS
//     (the per-session-CA leaf chains to the session trust pool) and the
//     request/response METADATA appears in telemetry (doc 09 §5 TLS-3 done-when);
//   - 3.c: session A's per-session interception CA is USELESS against session B
//     over the wire — a client trusting only A's pool fails B's flow, and an
//     A-CA-signed cert is refused inside B's strict-WebPKI re-origination.
//
// Each runner is SCAFFOLDED, not implemented against a live binary: per the wave
// rules we never run live curl/npm/git or `ds-tlsproxy` from CI here. The runner
// bodies record the documented wire shape + expected verdict, then fail with a
// clear "not yet wired" marker so a half-configured live run can never look like
// a pass (HONEST STATUS). The offline half (tlsproxyinspect_test.go) covers the
// 3.b strict-WebPKI re-validation row in-process; the 3.a/3.c over-the-wire rows
// are the deferred-to-CI tier these scaffolds reserve.

import (
	"os"
	"testing"
)

// requireLive skips the calling test unless DS_TLS3_LIVE=1. With the var unset
// every live test is skipped and the package is green (the acceptance criterion
// "live tests skipped by default").
func requireLive(t *testing.T) {
	t.Helper()
	if !LiveEnabled() {
		t.Skipf("live TLS-3 conformance is a deferred manual pass; set %s=1 to run against a running ds-tlsproxy at %s (default skip)",
			LiveEnvVar, LiveTargetFromEnv().TLSProxyAddr)
	}
}

// liveCase is one documented over-the-wire row.
type liveCase struct {
	// Name is the subtest name (the TLS-3 row letter + workload).
	Name string
	// Runner is the registered live runner key (driven against the egress gateway).
	Runner string
	// Want is the human-readable expected verdict the wire pass must observe.
	Want string
	// Why anchors the row to the done-when / decision it proves.
	Why string
}

// liveCases enumerates the over-the-wire TLS-3.a/3.c rows. 3.b runs offline
// in-process (the strict-WebPKI re-validation bad-cert table), so it is NOT a
// live row.
func liveCases() []liveCase {
	return []liveCase{
		{
			Name:   "3a-curl-valid-tls-and-metadata-telemetry",
			Runner: "curl-valid-tls-metadata",
			Want:   "curl sees a valid per-session-CA leaf chaining to the session trust pool; the GET's request/response metadata appears in telemetry",
			Why:    "doc 09 §5 TLS-3 done-when: clients see valid TLS + request/response metadata in telemetry",
		},
		{
			Name:   "3a-npm-install-through-egress-gateway",
			Runner: "npm-valid-tls-metadata",
			Want:   "npm install completes over inspected TLS; the registry fetch metadata appears in telemetry",
			Why:    "doc 06 proxy conformance suite (npm) over the TLS-terminating egress gateway",
		},
		{
			Name:   "3a-git-over-https-through-egress-gateway",
			Runner: "git-https-valid-tls-metadata",
			Want:   "git clone/fetch over HTTPS completes over inspected TLS; the smart-HTTP metadata appears in telemetry",
			Why:    "doc 06 proxy conformance suite (git-over-HTTPS) over the egress gateway",
		},
		{
			Name:   "3c-session-A-CA-useless-against-B-over-wire",
			Runner: "per-session-ca-isolation-wire",
			Want:   "a client trusting only session A's pool fails session B's flow, and an A-CA-signed cert is refused inside B's strict-WebPKI re-origination",
			Why:    "doc 09 §5 TLS-3 done-when: session A's per-session CA is useless against session B; D17",
		},
	}
}

// liveRunner is the signature every documented over-the-wire workload
// implements once an operator wires the deferred manual pass to a running
// ds-tlsproxy.
type liveRunner func(t *testing.T, c liveCase, target LiveTarget)

// notYetWired is the placeholder body for every runner. It is a DEFERRED MANUAL
// step (gated behind DS_TLS3_LIVE=1 AND the operator standing up a running
// ds-tlsproxy); until then it fails loudly with the exact wire shape it needs,
// so a half-configured live run can never look like a pass (HONEST STATUS).
func notYetWired(t *testing.T, c liveCase, target LiveTarget) {
	t.Helper()
	t.Fatalf("live runner %q (case %q) is a DEFERRED MANUAL step: wire it against a running ds-tlsproxy at %s "+
		"(no live curl/npm/git/ds-tlsproxy from CI). Expected: %s. Why: %s",
		c.Runner, c.Name, target.TLSProxyAddr, c.Want, c.Why)
}

// liveRunners maps each documented runner key to its (scaffolded) body. Every
// distinct runner a live case names has an entry; an operator wiring the
// deferred pass replaces notYetWired one workload at a time. TestLiveRunnerCoverage
// asserts completeness so a new live row without a runner fails fast.
func liveRunners() map[string]liveRunner {
	return map[string]liveRunner{
		"curl-valid-tls-metadata":       notYetWired,
		"npm-valid-tls-metadata":        notYetWired,
		"git-https-valid-tls-metadata":  notYetWired,
		"per-session-ca-isolation-wire": notYetWired,
	}
}

// TestLive_InspectConformance drives every over-the-wire TLS-3.a/3.c row against
// its documented runner under DS_TLS3_LIVE=1. Skipped by default.
func TestLive_InspectConformance(t *testing.T) {
	requireLive(t)
	target := LiveTargetFromEnv()
	runners := liveRunners()
	for _, c := range liveCases() {
		t.Run(c.Name, func(t *testing.T) {
			run, ok := runners[c.Runner]
			if !ok {
				t.Fatalf("live case %q names runner %q with no implementation registered", c.Name, c.Runner)
			}
			run(t, c, target)
		})
	}
}

// TestLiveGateDefaultsOff is a guard that ALWAYS runs (it does not call
// requireLive): it asserts the gate is named DS_TLS3_LIVE and that, with the var
// unset, the live half is disabled by default — the acceptance criterion "live
// tests skipped by default". It never touches the network.
func TestLiveGateDefaultsOff(t *testing.T) {
	if LiveEnvVar != "DS_TLS3_LIVE" {
		t.Fatalf("live gate env var = %q, want DS_TLS3_LIVE", LiveEnvVar)
	}
	switch os.Getenv(LiveEnvVar) {
	case "":
		if LiveEnabled() {
			t.Error("DS_TLS3_LIVE unset but LiveEnabled() is true; the live half must be skipped by default")
		}
	case "1":
		if !LiveEnabled() {
			t.Error("DS_TLS3_LIVE=1 but LiveEnabled() is false; the opt-in must be honored")
		}
	}
}

// TestLiveDefaultSkip confirms the default-skip posture without touching the
// network: with the gate unset, requireLive must skip. (When an operator sets
// DS_TLS3_LIVE=1 this test does not run the network either — it only verifies
// the gate is honored, which TestLiveGateDefaultsOff covers.)
func TestLiveDefaultSkip(t *testing.T) {
	if os.Getenv(LiveEnvVar) == "1" {
		t.Skip("DS_TLS3_LIVE=1: default-skip posture is exercised only with the gate unset")
	}
	if LiveEnabled() {
		t.Fatal("with DS_TLS3_LIVE unset, LiveEnabled() must be false")
	}
}

// TestLiveRunnerCoverage asserts every live case names a registered runner and
// no registered runner is orphaned. Runs WITHOUT the live gate (pure table
// consistency), so a drift between the case list and the runner table is caught
// in ordinary CI.
func TestLiveRunnerCoverage(t *testing.T) {
	runners := liveRunners()
	named := map[string]bool{}
	for _, c := range liveCases() {
		if c.Runner == "" {
			t.Errorf("live case %q names no runner", c.Name)
			continue
		}
		named[c.Runner] = true
		if _, ok := runners[c.Runner]; !ok {
			t.Errorf("live case %q names runner %q with no registered implementation", c.Name, c.Runner)
		}
	}
	for name := range runners {
		if !named[name] {
			t.Errorf("registered runner %q is not referenced by any live case", name)
		}
	}
}
