// SPDX-License-Identifier: Apache-2.0

package nftgate

// live_test.go — the LIVE half of the M0 network-boundary (c) rows. DEFERRED
// MANUAL, env-gated behind DS_NFTGATE_LIVE=1, and SKIPPED BY DEFAULT so
// `go test ./...` stays green offline and in CI.
//
// PROJECT CONSTRAINT (binding): no live claude / cia / podman, and NO
// CAP_NET_ADMIN / live-nft execution in CI. The live runners would drive a real
// boundary (a real NFTables ruleset + ds-dnsgate + ds-tlsproxy on a virtual-metal
// VM) and observe the actual disposition of each egress attempt:
//
//   - default-deny L3/4: a raw connect from inside the VM to an unadmitted IP is
//     dropped by the NFT-1 base chains (NFT-1);
//   - default-deny via-proxy: a TLS connection whose SNI/IP is not an admitted
//     (domain, IP) pair is refused at the egress gateway (TLS-1);
//   - rebinding: an approved name re-resolving to an internal address is scrubbed
//     and never widens the allow-set (DNS-4 + NFT-3);
//   - DoT/DoH bypass: tcp/853 drops; a known-resolver DoH is denied (NFT-4 + POL-2);
//   - port-53 redirect: an in-VM `nameserver 8.8.8.8` still resolves through
//     ds-dnsgate (NFT-4);
//   - QUIC: udp/443 is rejected with ICMP port-unreachable AND the per-session
//     counter increments — verified to be a reject, not a silent drop (D70).
//
// Each runner is SCAFFOLDED, not implemented: per the wave rules and the live-nft
// constraint we stand up no real NFTables ruleset here. A runner records the
// documented observation it needs and fails LOUDLY with a "not yet wired" marker
// so an operator running the deferred manual pass knows exactly what to stand up,
// and a half-configured live run can never look like a pass (HONEST STATUS). Each
// runner REUSES the same modeled disposition the offline half asserts (via the
// referencePosture decision function), so the wire pass and the offline spec can
// never disagree on a verdict.

import (
	"os"
	"strings"
	"testing"
)

// liveEnvVar is the single gate. The suite is a deferred manual pass; nothing
// here runs unless an operator opts in explicitly. (Sibling of the resolverlock
// DS_RESOLVERLOCK_LIVE and pol2reachability DS_POL2_LIVE gates.)
const liveEnvVar = "DS_NFTGATE_LIVE"

// liveEnabled reports whether the operator opted into the live pass.
func liveEnabled() bool { return os.Getenv(liveEnvVar) == "1" }

// requireLive skips the calling test unless DS_NFTGATE_LIVE=1.
func requireLive(t *testing.T) {
	t.Helper()
	if !liveEnabled() {
		t.Skipf("live M0 network-boundary conformance is a deferred manual pass; set %s=1 to run "+
			"(default skip; needs a real boundary + CAP_NET_ADMIN, never run in CI)", liveEnvVar)
	}
}

// liveRunner is the signature every documented live observation implements once
// an operator wires the deferred manual pass to a real boundary.
type liveRunner func(t *testing.T, f Fixture)

// notWiredReason is the pure (testable) body of the deferred-runner failure
// message: the exact observation an operator must stand up, the expected
// disposition, and the doc anchor. Keeping it a pure function lets the
// non-vacuity guard (TestLiveFailsLoud) assert the runner always has a loud
// reason without faking a *testing.T.
func notWiredReason(f Fixture) string {
	return "live runner for row " + string(f.Row) + " (attempt " + f.Attempt.Name +
		", kind " + string(f.Kind) + ") is a DEFERRED MANUAL step: wire it against a real boundary only " +
		"(no live claude/cia/podman; no CAP_NET_ADMIN / live nft in CI). " +
		"Expected disposition: " + string(f.Want) + ". Why: " + f.Why
}

// notYetWired is the placeholder body for every runner. It is a DEFERRED MANUAL
// step gated behind DS_NFTGATE_LIVE=1 and additionally behind an operator
// standing up a real boundary; until then it fails loudly with the exact
// observation it needs, so a half-configured live run can never look like a pass.
func notYetWired(t *testing.T, f Fixture) {
	t.Helper()
	t.Fatal(notWiredReason(f))
}

// liveRunners maps each modeled (c) row — the M0 seed set (RowOwners) AND the
// band-c extension (BandCRowOwners), i.e. every row in AllRowOwners() — to its
// (scaffolded) live observation runner. Every row has an entry so that under
// DS_NFTGATE_LIVE=1 each fixture reaches the HONEST notYetWired t.Fatal naming
// the observation an operator must stand up, never a registry-SHAPE fatal
// ("names row … with no registered live runner") that would hide which leg is
// unwired. The band-c rows carry the same notYetWired stub as the M0 rows: their
// live wiring is the same deferred manual step, gated behind a real boundary +
// CAP_NET_ADMIN (never CI). An operator wiring the deferred pass replaces
// notYetWired one row at a time. TestLiveRunnerCoverage pins this map to
// AllRowOwners() in both directions so it can never silently drift behind the
// fixture/row set again.
func liveRunners() map[Row]liveRunner {
	return map[Row]liveRunner{
		// M0 seed set (RowOwners()).
		RowDefaultDeny:    defaultDenyLiveRunner, // WIRED (l3/4 leg) — live_probe_test.go
		RowRebinding:      notYetWired,
		RowDoHDoTBypass:   dohDotBypassLiveRunner,   // WIRED (DoT leg; DoH leg = POL-2 policy, skips) — live_probe_nft4_test.go
		RowPort53Redirect: port53RedirectLiveRunner, // WIRED — live_probe_dns_test.go
		RowQUICReject:     quicRejectLiveRunner,     // WIRED (NFT-4 udp/443 reject) — live_probe_nft4_test.go
		// Band-c extension (BandCRowOwners()): same honest deferred-manual stub so
		// every band-c fixture reaches notYetWired, not the registry-shape fatal.
		RowInterfaceMatch:     notYetWired,
		RowECHSVCBSuppression: svcbSuppressLiveRunner, // WIRED (svcb leg; ech leg skips) — live_probe_dns_test.go
		RowSessionIsolation:   notYetWired,
		RowIPv6Closure:        aaaaStripLiveRunner, // WIRED (aaaa leg; v6-reach leg skips) — live_probe_dns_test.go
	}
}

// TestLive_M0Boundary drives every fixture against its row's live runner under
// DS_NFTGATE_LIVE=1. Skipped by default. Each subtest first cross-checks the
// fixture's required disposition against the modeled posture (the same decision
// function the offline half asserts), so the wire pass and the offline spec can
// never disagree before the live observation runs.
func TestLive_M0Boundary(t *testing.T) {
	requireLive(t)
	p := referencePosture()
	runners := liveRunners()
	fixtures, err := LoadFixtures()
	if err != nil {
		t.Fatalf("loading egress-attempt fixtures: %v", err)
	}
	for _, f := range fixtures {
		t.Run(f.Attempt.Name, func(t *testing.T) {
			// Cross-check the spec the live run is about to observe on the wire.
			if got := p.Dispose(f.Attempt); got != f.Want {
				t.Fatalf("offline spec disagrees with fixture %q before the wire run: model=%q want=%q",
					f.Attempt.Name, got, f.Want)
			}
			run, ok := runners[f.Row]
			if !ok {
				t.Fatalf("fixture %q names row %q with no registered live runner", f.Attempt.Name, f.Row)
			}
			run(t, f)
		})
	}
}

// TestLiveDefaultSkip is a guard that ALWAYS runs (it does not call requireLive):
// it asserts the gate is named DS_NFTGATE_LIVE and that, with the var unset, the
// live half is skipped by default — the acceptance criterion "any live leg is
// env-gated and fails-loud-but-off by default".
func TestLiveDefaultSkip(t *testing.T) {
	if liveEnvVar != "DS_NFTGATE_LIVE" {
		t.Fatalf("live gate env var = %q, want DS_NFTGATE_LIVE", liveEnvVar)
	}
	switch os.Getenv(liveEnvVar) {
	case "":
		if liveEnabled() {
			t.Error("DS_NFTGATE_LIVE unset but liveEnabled() is true; the live half must be skipped by default")
		}
	case "1":
		if !liveEnabled() {
			t.Error("DS_NFTGATE_LIVE=1 but liveEnabled() is false; the opt-in must be honored")
		}
	}
}

// TestLiveRunnerCoverage asserts the live-runner registry exactly matches the
// full modeled (c) row set — AllRowOwners() = the M0 seed set (RowOwners) ∪ the
// band-c extension (BandCRowOwners) — in BOTH directions: every modeled row has
// a registered live runner (so TestLive_M0Boundary reaches an honest notYetWired
// for every fixture instead of a registry-shape fatal), and no registered runner
// is orphaned (names a row the package does not model). This runs WITHOUT the
// live gate (pure table consistency), so a drift between the row table and the
// runner table is caught in ordinary CI — the registry can never silently fall
// behind the fixture/row set again.
func TestLiveRunnerCoverage(t *testing.T) {
	runners := liveRunners()
	allRows := AllRowOwners()
	for row := range allRows {
		if _, ok := runners[row]; !ok {
			t.Errorf("modeled (c) row %q has no registered live runner", row)
		}
	}
	for row := range runners {
		if _, ok := allRows[row]; !ok {
			t.Errorf("registered live runner for row %q is not a modeled (c) row (AllRowOwners)", row)
		}
	}
}

// TestLiveFailsLoud proves the deferred runners are NOT vacuous: every fixture's
// scaffolded runner has a loud, specific "not yet wired" reason naming the
// expected disposition — so an unwired live leg can never silently look like a
// pass. It asserts the pure reason function (the body notYetWired delegates to)
// without faking a *testing.T. Runs WITHOUT the live gate (the fail-loud contract
// itself is what we check, not a wire observation).
func TestLiveFailsLoud(t *testing.T) {
	fixtures, err := LoadFixtures()
	if err != nil {
		t.Fatalf("loading egress-attempt fixtures: %v", err)
	}
	for _, f := range fixtures {
		reason := notWiredReason(f)
		if reason == "" {
			t.Errorf("live runner for row %q (attempt %q) has an empty fail reason; an unwired live leg must fail loudly",
				f.Row, f.Attempt.Name)
		}
		// The reason must name the expected disposition so an operator wiring the
		// pass knows what the wire must produce (honest deferred status).
		if !strings.Contains(reason, string(f.Want)) {
			t.Errorf("live runner reason for %q does not name the expected disposition %q: %q",
				f.Attempt.Name, f.Want, reason)
		}
	}
}
