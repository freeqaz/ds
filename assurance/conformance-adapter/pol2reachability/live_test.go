// SPDX-License-Identifier: Apache-2.0

package pol2reachability

// live_test.go — the LIVE half of the POL-2 done-when suite. DEFERRED MANUAL,
// env-gated behind DS_POL2_LIVE=1, and SKIPPED BY DEFAULT so `go test ./...`
// stays green offline and in CI. The live runners drive the documented client
// wire shapes against a real fresh install + pack only:
//
//   - an Anthropic streaming call (the agent's own model calls);
//   - git clone/fetch/push over HTTPS (vcs family);
//   - gh api (REST over api.github.com);
//   - npm install of a CNAME-chained package, yarn-classic, pnpm-via-corepack;
//   - canary refusal at BOTH DNS-3 and TLS-1 (the two-layer non-pack refusal);
//   - the zero-flows-outside-pack audit (LOG-4 semantics);
//   - the TLS-6 capability-gate paths: with TLS-6 absent the path-scoped
//     storage.googleapis.com entry admits nothing + logs the inert warning;
//     with TLS-6 present the browser install succeeds path-scoped and any other
//     bucket path refuses.
//
// Each runner is SCAFFOLDED, not implemented against a live binary: per the
// wave rules we never run live `claude`, `cia run`, `git push` to a real
// remote, or `podman run` of Claude Code here. The runner bodies record the
// documented wire shape and the expected verdict, then fail with a clear
// "not yet wired" marker so an operator running the deferred manual pass knows
// exactly what to stand up. They REUSE the shared Matrix() — the same cases the
// offline half asserts — so the two halves can never drift.

import (
	"os"
	"testing"
)

// liveEnvVar is the single gate. The suite is a deferred manual pass; nothing
// here runs unless an operator opts in explicitly.
const liveEnvVar = "DS_POL2_LIVE"

// liveEnabled reports whether the operator opted into the live pass.
func liveEnabled() bool { return os.Getenv(liveEnvVar) == "1" }

// requireLive skips the calling test unless DS_POL2_LIVE=1. This is the
// default-skip behavior the acceptance criteria name: with the var unset, every
// live test is skipped and the package is green.
func requireLive(t *testing.T) {
	t.Helper()
	if !liveEnabled() {
		t.Skipf("live POL-2 conformance is a deferred manual pass; set %s=1 to run (default skip)", liveEnvVar)
	}
}

// packForCase returns the pack state the live case's verdict is defined
// against. Most cases evaluate against the FROZEN pack verbatim. The one
// exception is the capability-gate-ACTIVE case (RequiresTLS6 with a reachable
// Want): a browser install through the path-scoped storage.googleapis.com entry
// presumes the operator BOTH flipped its disabled-by-default binary-cdn family
// on (ordinary org policy) AND has TLS-6 present — only then does the entry
// "activate path-scoped" (doc 13 §7). Evaluating that case against the frozen
// pack (binary-cdn disabled) would wrongly read DisabledTier; the residual
// admission control the case proves is the capability gate, not the tier. The
// inert (TLS-6-absent) case stays on the frozen pack: inertness must hold even
// if the family is enabled, which the offline half asserts directly.
func packForCase(p *Pack, c Case) *Pack {
	if c.RequiresTLS6 && c.Want == VerdictReachable {
		if e, ok := p.Lookup(c.FQDN); ok {
			return p.WithFamilyEnabled(e.Family)
		}
	}
	return p
}

// liveRunner is the signature every documented live workload implements once an
// operator wires the deferred manual pass to a real fresh install + pack.
type liveRunner func(t *testing.T, c Case)

// notYetWired is the placeholder body for every runner. It is a DEFERRED MANUAL
// step, gated behind DS_POL2_LIVE=1 and additionally behind the operator
// actually standing up the live fixtures; until then it fails loudly with the
// exact wire shape it needs, so a half-configured live run can never look like
// a pass (HONEST STATUS).
func notYetWired(t *testing.T, c Case) {
	t.Helper()
	t.Fatalf("live runner %q (case %q) is a DEFERRED MANUAL step: wire it against a real fresh install + pack only "+
		"(no live claude/cia/podman from CI). Expected verdict: %s. Why: %s",
		c.LiveRunner, c.Name, c.Want, c.Why)
}

// liveRunners maps each documented LiveRunner name to its (scaffolded) body.
// Every distinct runner the matrix names has an entry here; an operator wiring
// the deferred pass replaces notYetWired one workload at a time. Keeping the
// table here (and asserting completeness in TestLiveRunnerCoverage) means a new
// live matrix row without a runner fails fast rather than silently no-running.
func liveRunners() map[string]liveRunner {
	return map[string]liveRunner{
		"anthropic-streaming-call":        notYetWired,
		"git-clone-fetch-push":            notYetWired,
		"gh-api":                          notYetWired,
		"npm-install-cname-chained":       notYetWired,
		"yarn-classic-install":            notYetWired,
		"pnpm-via-corepack-install":       notYetWired,
		"canary-refusal-dns3-and-tls1":    notYetWired,
		"zero-flows-outside-pack-audit":   notYetWired,
		"tls6-browser-install-pathscoped": notYetWired,
	}
}

// TestLive_ReachabilityMatrix drives every LIVE matrix row against its
// documented runner under DS_POL2_LIVE=1. Skipped by default. Each subtest also
// cross-checks the live case's expected verdict against the frozen pack via
// EvalOffline, so the wire pass and the offline spec can never disagree on a
// reachable/refused/inert claim.
func TestLive_ReachabilityMatrix(t *testing.T) {
	requireLive(t)
	p := ParsePack()
	runners := liveRunners()
	for _, c := range LiveCases() {
		t.Run(c.Name, func(t *testing.T) {
			// Cross-check the spec the live run is about to prove on the wire.
			present := capsTLS6Absent
			if c.RequiresTLS6 && c.Want == VerdictReachable {
				present = capsTLS6Present
			}
			if c.FQDN != "" {
				if got := EvalOffline(packForCase(p, c), c, present); got != c.Want {
					t.Fatalf("offline spec disagrees with live case %q before the wire run: spec=%q want=%q", c.Name, got, c.Want)
				}
			}
			run, ok := runners[c.LiveRunner]
			if !ok {
				t.Fatalf("live case %q names runner %q with no implementation registered", c.Name, c.LiveRunner)
			}
			run(t, c)
		})
	}
}

// TestLiveDefaultSkip is a guard that ALWAYS runs (it does not call
// requireLive): it asserts the gate is named DS_POL2_LIVE and that, with the
// var unset, the live half is skipped by default — the acceptance criterion
// "live tests skipped by default". When the var is unset it verifies
// liveEnabled() is false; when an operator sets it to 1 it verifies the opt-in
// is honored. Either way this guard itself never needs the live fixtures.
func TestLiveDefaultSkip(t *testing.T) {
	if liveEnvVar != "DS_POL2_LIVE" {
		t.Fatalf("live gate env var = %q, want DS_POL2_LIVE", liveEnvVar)
	}
	switch os.Getenv(liveEnvVar) {
	case "":
		if liveEnabled() {
			t.Error("DS_POL2_LIVE unset but liveEnabled() is true; the live half must be skipped by default")
		}
	case "1":
		if !liveEnabled() {
			t.Error("DS_POL2_LIVE=1 but liveEnabled() is false; the opt-in must be honored")
		}
	}
}

// TestLiveRunnerCoverage asserts every LIVE matrix row that names a runner has
// a registered implementation (scaffolded today), and that no registered runner
// is orphaned. This runs WITHOUT the live gate (pure table consistency), so a
// drift between the matrix and the runner table is caught in ordinary CI.
func TestLiveRunnerCoverage(t *testing.T) {
	runners := liveRunners()
	named := map[string]bool{}
	for _, c := range LiveCases() {
		if c.LiveRunner == "" {
			t.Errorf("live case %q names no runner", c.Name)
			continue
		}
		named[c.LiveRunner] = true
		if _, ok := runners[c.LiveRunner]; !ok {
			t.Errorf("live case %q names runner %q with no registered implementation", c.Name, c.LiveRunner)
		}
	}
	for name := range runners {
		if !named[name] {
			t.Errorf("registered runner %q is not referenced by any live matrix case", name)
		}
	}
}
