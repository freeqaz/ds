// SPDX-License-Identifier: Apache-2.0

package logreconcile

import (
	"sort"
	"strings"
	"testing"
)

// This file exercises the doc 06 §3c per-session stream-reconciliation (c) row
// (suite member LOG-4) as the netisolation / orchctl siblings do: a CONFORMING
// control fixture must pass clean, and each NAMED violation class must be tripped
// by at least one synthetic fixture (D50). All fixtures are in-code Go literals —
// there is no fixtures/ dir, no file I/O, and no working-directory dependency;
// "synthetic only" is structural here. A coverage gate fails closed if a declared
// violation class is never exercised, so a new class cannot land un-asserted.

// ── shared helpers ──────────────────────────────────────────────────────────

// classesOf collects the sorted, deduped violation classes a check reported.
func classesOf(vs []Violation) []ViolationClass {
	set := map[ViolationClass]bool{}
	for _, v := range vs {
		set[v.Class] = true
	}
	out := make([]ViolationClass, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sameClasses reports whether got's class set equals want exactly.
func sameClasses(got []Violation, want []ViolationClass) bool {
	g := classesOf(got)
	w := append([]ViolationClass(nil), want...)
	sort.Slice(w, func(i, j int) bool { return w[i] < w[j] })
	if len(g) != len(w) {
		return false
	}
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

// render formats a violation slice for failure messages.
func render(vs []Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("  ")
		b.WriteString(v.String())
		b.WriteString("\n")
	}
	return b.String()
}

// assertClasses is the shared per-case assertion: a CONFORMING fixture (want empty)
// must report NO violations, and a violation fixture must FAIL with its NAMED class
// set exactly — a silent pass is the regression this row exists to catch.
func assertClasses(t *testing.T, name string, got []Violation, want []ViolationClass) {
	t.Helper()
	if len(want) == 0 {
		if len(got) != 0 {
			t.Fatalf("CONFORMING fixture %q reported %d violation(s) — the guardrail holds, so "+
				"this must pass clean:\n%s", name, len(got), render(got))
		}
		return
	}
	if len(got) == 0 {
		t.Fatalf("VIOLATION fixture %q reported NO violations — the check must fail on %v (a "+
			"silent pass is the regression this row exists to catch)", name, want)
	}
	if !sameClasses(got, want) {
		t.Fatalf("VIOLATION fixture %q reported the WRONG violation class set —\n want: %v\n "+
			"got: %v\nfull:\n%s", name, want, classesOf(got), render(got))
	}
}

// coverageGate asserts that the union of violation classes the fixtures produced
// equals the declared class set — a CONFORMING control was proven (the green case)
// AND every declared class was exercised at least once, failing closed on either a
// missing control or an un-exercised class.
func coverageGate(t *testing.T, row string, declared []ViolationClass, seen map[ViolationClass]bool, sawControl bool) {
	t.Helper()
	if !sawControl {
		t.Errorf("%s: no CONFORMING control fixture passed clean — the green case must be proven", row)
	}
	for _, c := range declared {
		if !seen[c] {
			t.Errorf("%s: violation class %q is never exercised by a fixture — every declared "+
				"failure mode must have a named fixture (fail-closed coverage gate)", row, c)
		}
	}
}

// ── the documented-vocabulary guard (doc 06 §3c language note) ──────────────

// TestNoAttackVocabulary pins the doc 06 §3c language note for this package: no
// ViolationClass string may carry attack / redteam / intrusion framing. These are
// assurance tests for advertised properties, not a security-audit exercise; a row
// named for an attacker would violate the binding vocabulary note.
func TestNoAttackVocabulary(t *testing.T) {
	banned := []string{"attack", "redteam", "red-team", "intrusion", "exploit", "adversary"}
	all := []ViolationClass{
		ViolationProxyFlowUnreconciled,
		ViolationConntrackFlowUnexplained,
		ViolationThreeKeysDisagreeNotDropped,
		ViolationFlowDoubleCounted,
		ViolationDecisionVersionOlderThanDNS,
		ViolationDivergenceNotAlarmed,
	}
	for _, c := range all {
		low := strings.ToLower(string(c))
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("violation class %q carries banned %q framing — doc 06 §3c forbids "+
					"attack/redteam/intrusion naming; name the row for the property it proves", c, b)
			}
		}
	}
}

// ── the tag guard (the suspendbreach/goldenfreshness const-Tag discipline) ──

// TestTagStable pins the single-sourced guardrail tag to the doc.go REGISTRATION
// value. The repo-root guardrail-map.yaml's logreconcile glob row (at the first
// per-claim seeding) names this SAME tag; if the tag string drifts without
// re-reconciling the map row and the doc.go table, this fails HERE rather than
// letting the package and the map name different rows (the honest-map-row
// discipline: a map row names a real single-sourced tag value, never a placeholder).
func TestTagStable(t *testing.T) {
	const want = "per-session-stream-reconciliation"
	if Tag != want {
		t.Fatalf("Tag = %q, want %q (doc.go REGISTRATION / guardrail-map.yaml logreconcile row)",
			Tag, want)
	}
	if len(Tags) != 1 || Tags[0] != want {
		t.Fatalf("Tags = %v, want [%q] (single-sourced from Tag)", Tags, want)
	}
}

// ── ROW — LOG-4 per-session stream reconciliation (D43/D44/D72) ─────────────

func TestRowReconciliation(t *testing.T) {
	declared := []ViolationClass{
		ViolationProxyFlowUnreconciled,
		ViolationConntrackFlowUnexplained,
		ViolationThreeKeysDisagreeNotDropped,
		ViolationFlowDoubleCounted,
		ViolationDecisionVersionOlderThanDNS,
		ViolationDivergenceNotAlarmed,
	}

	// A canonical agreeing D44 key pair: the proxy and conntrack views match.
	keyA := FlowKey{GuestIP: "10.66.0.2", Tap: "dstap-0", CtMark: "0xd1000001"}
	keyB := FlowKey{GuestIP: "10.66.0.3", Tap: "dstap-1", CtMark: "0xd1000002"}

	type tc struct {
		name string
		rec  SessionReconciliation
		want []ViolationClass
	}
	cases := []tc{
		{
			// CONTROL: both proxy flows join a conntrack flow on agreeing keys, a denied
			// flow and an escape-hatch flow are legitimately conntrack-only, versions are
			// ordered, no divergence so no alarm needed.
			name: "conforming-streams-reconcile-clean",
			rec: SessionReconciliation{
				Session: "sess-1",
				ProxyFlows: []ProxyFlow{
					{ID: "f1", Key: keyA, Domain: "api.allowed.example", AdmittingDNSVersion: 41, DecisionVersion: 41},
					{ID: "f2", Key: keyB, Domain: "cdn.allowed.example", AdmittingDNSVersion: 41, DecisionVersion: 42},
				},
				ConntrackFlows: []ConntrackFlow{
					{ID: "f1", Key: keyA},
					{ID: "f2", Key: keyB},
					{ID: "denied-1", Key: FlowKey{GuestIP: "10.66.0.2", Tap: "dstap-0", CtMark: "0xd1000001"}, Denied: true},
					{ID: "esc-1", Key: FlowKey{GuestIP: "10.66.0.3", Tap: "dstap-1", CtMark: "0xd1000002"}, EscapeHatch: true},
				},
				DivergenceRaisedAlarm: false, // no divergence, so no alarm is owed
			},
			want: nil,
		},
		{
			// CONTROL: decision version strictly AHEAD of the admitting DNS version is
			// fine (a newer policy than the admission) — only OLDER is the violation.
			name: "conforming-decision-version-ahead-of-dns",
			rec: SessionReconciliation{
				Session: "sess-2",
				ProxyFlows: []ProxyFlow{
					{ID: "f1", Key: keyA, Domain: "api.allowed.example", AdmittingDNSVersion: 7, DecisionVersion: 9},
				},
				ConntrackFlows:        []ConntrackFlow{{ID: "f1", Key: keyA}},
				DivergenceRaisedAlarm: false,
			},
			want: nil,
		},
		{
			// (1) a proxy flow with no joining conntrack entry — alarm raised, so ONLY the
			// proxy-unreconciled class is named.
			name: "violation-proxy-flow-unreconciled",
			rec: SessionReconciliation{
				Session: "sess-3",
				ProxyFlows: []ProxyFlow{
					{ID: "f1", Key: keyA, Domain: "api.allowed.example", AdmittingDNSVersion: 1, DecisionVersion: 1},
				},
				ConntrackFlows:        []ConntrackFlow{}, // kernel lost the flow
				DivergenceRaisedAlarm: true,              // divergence WAS alarmed → only (1) names
			},
			want: []ViolationClass{ViolationProxyFlowUnreconciled},
		},
		{
			// (2) a conntrack flow with no proxy join and no explanation (not denied, not
			// escape-hatch) — a redirect hole. Alarm raised, so ONLY (2) names.
			name: "violation-conntrack-flow-unexplained",
			rec: SessionReconciliation{
				Session:    "sess-4",
				ProxyFlows: []ProxyFlow{},
				ConntrackFlows: []ConntrackFlow{
					{ID: "rogue-1", Key: keyA, Denied: false, EscapeHatch: false},
				},
				DivergenceRaisedAlarm: true,
			},
			want: []ViolationClass{ViolationConntrackFlowUnexplained},
		},
		{
			// (3) the streams join on ID but the D44 keys disagree (a forged/mismatched ct
			// mark) — must have been a kernel drop, not an honored reconciled flow. Alarm
			// raised, so ONLY (3) names.
			name: "violation-three-keys-disagree-not-dropped",
			rec: SessionReconciliation{
				Session: "sess-5",
				ProxyFlows: []ProxyFlow{
					{ID: "f1", Key: keyA, Domain: "api.allowed.example", AdmittingDNSVersion: 3, DecisionVersion: 3},
				},
				ConntrackFlows: []ConntrackFlow{
					// same ID join, but the ct mark disagrees with the proxy view.
					{ID: "f1", Key: FlowKey{GuestIP: "10.66.0.2", Tap: "dstap-0", CtMark: "0xd1009999"}},
				},
				DivergenceRaisedAlarm: true,
			},
			want: []ViolationClass{ViolationThreeKeysDisagreeNotDropped},
		},
		{
			// (4) the same proxy flow appears twice (double-counted) — the ledger join is
			// corrupted. Both copies join conntrack so no unreconciled gap; alarm raised,
			// so ONLY (4) names.
			name: "violation-flow-double-counted",
			rec: SessionReconciliation{
				Session: "sess-6",
				ProxyFlows: []ProxyFlow{
					{ID: "f1", Key: keyA, Domain: "api.allowed.example", AdmittingDNSVersion: 5, DecisionVersion: 5},
					{ID: "f1", Key: keyA, Domain: "api.allowed.example", AdmittingDNSVersion: 5, DecisionVersion: 5},
				},
				ConntrackFlows:        []ConntrackFlow{{ID: "f1", Key: keyA}},
				DivergenceRaisedAlarm: true,
			},
			want: []ViolationClass{ViolationFlowDoubleCounted},
		},
		{
			// (5) the decision enforced an OLDER policy version than the admitting DNS
			// event — the LOG-4 version-ordering assertion. Alarm raised, so ONLY (5)
			// names.
			name: "violation-decision-version-older-than-dns",
			rec: SessionReconciliation{
				Session: "sess-7",
				ProxyFlows: []ProxyFlow{
					{ID: "f1", Key: keyA, Domain: "api.allowed.example", AdmittingDNSVersion: 12, DecisionVersion: 10},
				},
				ConntrackFlows:        []ConntrackFlow{{ID: "f1", Key: keyA}},
				DivergenceRaisedAlarm: true,
			},
			want: []ViolationClass{ViolationDecisionVersionOlderThanDNS},
		},
		{
			// (6) divergence-not-alarmed in isolation: a non-zero conntrack-drop counter is
			// itself a boundary-hole alarm obligation (doc 12 §2.3), with NO per-flow
			// divergence, surfaced WITHOUT an alarm.
			name: "violation-divergence-not-alarmed-drop-counter",
			rec: SessionReconciliation{
				Session: "sess-8",
				ProxyFlows: []ProxyFlow{
					{ID: "f1", Key: keyA, Domain: "api.allowed.example", AdmittingDNSVersion: 2, DecisionVersion: 2},
				},
				ConntrackFlows:        []ConntrackFlow{{ID: "f1", Key: keyA}},
				ConntrackDropCounter:  3,     // a boundary-hole alarm obligation
				DivergenceRaisedAlarm: false, // but only a log line → the regression
			},
			want: []ViolationClass{ViolationDivergenceNotAlarmed},
		},
		{
			// A per-flow divergence that ALSO was not alarmed: both the per-flow class AND
			// divergence-not-alarmed name (the realistic compound failure — a redirect hole
			// that no one was paged about).
			name: "violation-unexplained-flow-and-not-alarmed",
			rec: SessionReconciliation{
				Session:    "sess-9",
				ProxyFlows: []ProxyFlow{},
				ConntrackFlows: []ConntrackFlow{
					{ID: "rogue-2", Key: keyB, Denied: false, EscapeHatch: false},
				},
				DivergenceRaisedAlarm: false,
			},
			want: []ViolationClass{ViolationConntrackFlowUnexplained, ViolationDivergenceNotAlarmed},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckReconciliation(c.rec)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "per-session-stream-reconciliation", declared, seen, sawControl)
}
