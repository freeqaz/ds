// SPDX-License-Identifier: Apache-2.0

package resolverhardening

// live_test.go — the LIVE half of the D42 resolver-hardening (c) unit. DEFERRED
// MANUAL, env-gated behind DS_RESOLVERHARD_LIVE=1, and SKIPPED BY DEFAULT so
// `go test ./...` stays green offline and in CI.
//
// PROJECT CONSTRAINT (binding): no live claude / cia / podman, and NO
// CAP_NET_ADMIN / live-nft / live-dataplane / live-identity execution in CI. The
// live runners would drive a real boundary (a real ds-dnsgate + ds-tlsproxy +
// ds-nft ruleset on a virtual-metal VM) and observe the actual disposition of
// each resolution / connection attempt for every D42 clause:
//
//   - sole resolution path: an in-VM `nameserver 8.8.8.8` lookup still lands on
//     ds-dnsgate (NFT-4 port-53 redirect);
//   - DoT dropped: a tcp/853 attempt is dropped (NFT-4);
//   - DoH blocked: a DoH request to a blocklisted resolver domain is denied (DNS-3
//     + the TLS-1 SNI check, POL-2);
//   - bypass-attempt counted: the foreign-resolver bypass attempt increments the
//     per-session NFT-5 counter + nflog rule;
//   - ECH params stripped: an HTTPS (type 65) / SVCB (type 64) query returns NODATA
//     with no ECH config delivered (DNS-4 rule 4);
//   - private-range never admitted: an approved domain answering an RFC1918 /
//     embedded-v4 address is scrubbed, never inserted (W5);
//   - TTL clamp: the VM is answered clamp(ttl, 60s, 900s) and re-resolution goes
//     through full admission, never silently widening (W2/W3);
//   - udp/443 reject+count: QUIC is rejected with ICMP port-unreachable and counted
//     per session, never silently dropped (D70);
//   - SNI↔admitted-IP cross-check: a TLS connection on a shared-CDN IP not admitted
//     for the SNI domain is refused (TLS-1, doc 03 OQ1).
//
// Each runner is SCAFFOLDED, not implemented: per the wave rules and the live-nft
// / live-dataplane constraint we stand up no real boundary here. A runner fails
// LOUDLY with a "not yet wired" marker naming the clause so an operator running
// the deferred manual pass knows exactly what to stand up, and a half-configured
// live run can never look like a pass (HONEST STATUS). The runner table is keyed
// on the single-sourced clause set (Clauses), so the live table and the offline
// clause set can never drift (the nftgate / resolverlock live-runner precedent).

import (
	"os"
	"strings"
	"testing"
)

// liveEnvVar is the single gate. The suite is a deferred manual pass; nothing
// here runs unless an operator opts in explicitly. (Sibling of the nftgate
// DS_NFTGATE_LIVE and resolverlock DS_RESOLVERLOCK_LIVE gates.)
const liveEnvVar = "DS_RESOLVERHARD_LIVE"

// liveEnabled reports whether the operator opted into the live pass.
func liveEnabled() bool { return os.Getenv(liveEnvVar) == "1" }

// requireLive skips the calling test unless DS_RESOLVERHARD_LIVE=1.
func requireLive(t *testing.T) {
	t.Helper()
	if !liveEnabled() {
		t.Skipf("live D42 resolver-hardening conformance is a deferred manual pass; set %s=1 to run "+
			"(default skip; needs a real ds-dnsgate + ds-tlsproxy + ds-nft + CAP_NET_ADMIN, never run "+
			"in CI)", liveEnvVar)
	}
}

// liveRunner is the signature every documented live observation implements once
// an operator wires the deferred manual pass to a real boundary.
type liveRunner func(t *testing.T, clause ViolationClass)

// notWiredReason is the pure (testable) body of the deferred-runner failure
// message: the exact clause an operator must stand up and the binding
// live-execution constraint. Keeping it a pure function lets the non-vacuity guard
// (TestLiveFailsLoud) assert the runner always has a loud reason without faking a
// *testing.T.
func notWiredReason(clause ViolationClass) string {
	return "live runner for D42 clause " + string(clause) + " is a DEFERRED MANUAL step: wire it " +
		"against a real boundary only (no live claude/cia/podman; no CAP_NET_ADMIN / live nft / live " +
		"dataplane / live identity in CI). It must observe the documented disposition on the wire, " +
		"reusing the same modeled Check the offline half asserts so the two can never disagree."
}

// notYetWired is the placeholder body for every runner. It is a DEFERRED MANUAL
// step gated behind DS_RESOLVERHARD_LIVE=1 and additionally behind an operator
// standing up a real boundary; until then it fails loudly with the exact clause it
// needs, so a half-configured live run can never look like a pass.
func notYetWired(t *testing.T, clause ViolationClass) {
	t.Helper()
	t.Fatal(notWiredReason(clause))
}

// liveRunners maps each D42 clause to its (scaffolded) live observation runner.
// Every clause in Clauses() has an entry; an operator wiring the deferred pass
// replaces notYetWired one clause at a time.
func liveRunners() map[ViolationClass]liveRunner {
	m := map[ViolationClass]liveRunner{}
	for _, c := range Clauses() {
		m[c] = notYetWired
	}
	return m
}

// TestLive_ResolverHardening drives every D42 clause against its live runner under
// DS_RESOLVERHARD_LIVE=1. Skipped by default.
func TestLive_ResolverHardening(t *testing.T) {
	requireLive(t)
	runners := liveRunners()
	for _, c := range Clauses() {
		run, ok := runners[c]
		if !ok {
			t.Fatalf("clause %q has no registered live runner", c)
		}
		t.Run(string(c), func(t *testing.T) { run(t, c) })
	}
}

// TestLiveDefaultSkip is a guard that ALWAYS runs (it does not call requireLive):
// it asserts the gate is named DS_RESOLVERHARD_LIVE and that, with the var unset,
// the live half is skipped by default — the acceptance criterion "any live leg is
// env-gated and fails-loud-but-off by default".
func TestLiveDefaultSkip(t *testing.T) {
	if liveEnvVar != "DS_RESOLVERHARD_LIVE" {
		t.Fatalf("live gate env var = %q, want DS_RESOLVERHARD_LIVE", liveEnvVar)
	}
	switch os.Getenv(liveEnvVar) {
	case "":
		if liveEnabled() {
			t.Error("DS_RESOLVERHARD_LIVE unset but liveEnabled() is true; the live half must be skipped by default")
		}
	case "1":
		if !liveEnabled() {
			t.Error("DS_RESOLVERHARD_LIVE=1 but liveEnabled() is false; the opt-in must be honored")
		}
	}
}

// TestLiveRunnerCoverage asserts every D42 clause has a registered live runner and
// no registered runner is orphaned. This runs WITHOUT the live gate (pure table
// consistency), so a drift between the clause set and the runner table is caught
// in ordinary CI.
func TestLiveRunnerCoverage(t *testing.T) {
	runners := liveRunners()
	known := map[ViolationClass]bool{}
	for _, c := range Clauses() {
		known[c] = true
		if _, ok := runners[c]; !ok {
			t.Errorf("D42 clause %q has no registered live runner", c)
		}
	}
	for c := range runners {
		if !known[c] {
			t.Errorf("registered live runner for %q is not a D42 clause", c)
		}
	}
}

// TestLiveFailsLoud proves the deferred runners are NOT vacuous: every clause's
// scaffolded runner has a loud, specific "not yet wired" reason naming the clause
// — so an unwired live leg can never silently look like a pass. It asserts the
// pure reason function (the body notYetWired delegates to) without faking a
// *testing.T. Runs WITHOUT the live gate (the fail-loud contract itself is what we
// check, not a wire observation).
func TestLiveFailsLoud(t *testing.T) {
	for _, c := range Clauses() {
		reason := notWiredReason(c)
		if reason == "" {
			t.Errorf("live runner for clause %q has an empty fail reason; an unwired live leg must fail loudly", c)
		}
		if !strings.Contains(reason, string(c)) {
			t.Errorf("live runner reason for %q does not name the clause: %q", c, reason)
		}
	}
}
