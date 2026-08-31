// SPDX-License-Identifier: Apache-2.0

package orchctl

import (
	"sort"
	"strings"
	"testing"
)

// This file exercises the five doc 15 §11 orchestrator (c)-tier rows as the
// goldenfreshness sibling does: per row, a CONFORMING control fixture must pass
// clean, and each NAMED violation class must be tripped by at least one synthetic
// fixture (D50). All fixtures are in-code Go literals — there is no fixtures/
// dir, no file I/O, and no working-directory dependency; "synthetic only" is
// structural here. A per-row coverage gate fails closed if a declared violation
// class is never exercised, so a new class cannot land un-asserted.

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

// coverageGate asserts that the union of violation classes the row's fixtures
// produced equals the declared class set for that row — a CONFORMING control was
// proven (the green case) AND every declared class was exercised at least once,
// failing closed on either a missing control or an un-exercised class.
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
		// row 1
		ViolationSuspendNotFired, ViolationSuspendOverEscalated,
		ViolationSuspendReasonUnmapped, ViolationSuspendProvenanceMissing,
		// row 2
		ViolationGrantNotEnforcedPostApply, ViolationGrantEnforcedPreApply,
		ViolationGrantMidWindowNotDnsRefused,
		// row 3
		ViolationStalePlacementAdmitted, ViolationFreshPlacementRefused,
		ViolationStaleRoutableAdmitted,
		// row 4
		ViolationDerivedStateNotEvicted, ViolationAppliedSeqAdvancedPreSweep,
		ViolationNonSeveringFlowSevered,
		// row 5
		ViolationCanaryShadowCountedAsHit, ViolationCanaryGapReadAsZero,
		ViolationCanaryRetiredWithEnforcingHits,
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

// ── the anchor guard (the goldenfreshness DefaultRotationWindow discipline) ──

// TestCanaryWindowMatchesDocumentedCadence pins DefaultCanaryWindowDays to the
// documented 30-day retirement cadence (doc 13 §7 "Staleness canary": "30 days of
// zero enforcing-mode hits opens the same [removal-review PR]"). If the constant
// drifts without re-ratifying the cadence, this fails HERE rather than letting the
// row quietly judge against a different window than the doc promises.
func TestCanaryWindowMatchesDocumentedCadence(t *testing.T) {
	const documentedCanaryWindowDays = 30
	if DefaultCanaryWindowDays != documentedCanaryWindowDays {
		t.Fatalf("DefaultCanaryWindowDays = %d, want %d (doc 13 §7 staleness-canary retirement "+
			"window); a window change must be reconciled with the documented cadence (D74)",
			DefaultCanaryWindowDays, documentedCanaryWindowDays)
	}
}

// ── the tag guard (the goldenfreshness/suspendbreach const-Tag discipline) ──

// TestTagsStable pins the single-sourced guardrail tags to the doc.go
// REGISTRATION values, in order. The repo-root guardrail-map.yaml's orchctl glob
// row names these SAME tags; if a tag string drifts without re-reconciling the
// map row and the doc.go table, this fails HERE rather than letting the package
// and the map name different rows (the honest-map-row discipline: a map row names
// a real single-sourced tag value, never a placeholder).
func TestTagsStable(t *testing.T) {
	want := []string{
		"orch-suspend-on-breach",
		"orch-ask-grant-atomicity",
		"orch-skew-widening-scheduler-refusal",
		"orch-revocation-of-derived-state-clock",
		"orch-pack-staleness-canary-evidence-feed",
	}
	if len(Tags) != len(want) {
		t.Fatalf("Tags has %d entries, want %d (the five doc 15 §11 orchestrator (c) rows; "+
			"doc.go REGISTRATION)", len(Tags), len(want))
	}
	for i := range want {
		if Tags[i] != want[i] {
			t.Errorf("Tags[%d] = %q, want %q (doc.go REGISTRATION / guardrail-map.yaml orchctl row)",
				i, Tags[i], want[i])
		}
	}
}

// ── ROW 1 — suspend-on-breach execution (D77) ───────────────────────────────

func TestRowSuspendOnBreach(t *testing.T) {
	declared := []ViolationClass{
		ViolationSuspendNotFired, ViolationSuspendOverEscalated,
		ViolationSuspendReasonUnmapped, ViolationSuspendProvenanceMissing,
	}
	type tc struct {
		name   string
		signal SuspendSignal
		got    SuspendOutcome
		want   []ViolationClass
	}
	cases := []tc{
		{
			name:   "conforming-blocklist-suspends-with-provenance",
			signal: SuspendSignal{Session: "s1", Blocklist: true, Provenance: "rule=block-X layer=org v=42"},
			got:    SuspendOutcome{SuspendFired: true, Reason: ReasonPolicy},
			want:   nil,
		},
		{
			name:   "conforming-block-cap-does-not-suspend",
			signal: SuspendSignal{Session: "s2", RuleAction: ActionBlock},
			got:    SuspendOutcome{SuspendFired: false},
			want:   nil,
		},
		{
			name:   "conforming-explicit-suspend-rule-suspends",
			signal: SuspendSignal{Session: "s3", RuleAction: ActionSuspend, Provenance: "rule=cap-Y layer=global v=7"},
			got:    SuspendOutcome{SuspendFired: true, Reason: ReasonPolicy},
			want:   nil,
		},
		{
			name:   "violation-genuine-threat-not-suspended",
			signal: SuspendSignal{Session: "s4", Blocklist: true, Provenance: "rule=block-Z layer=org v=9"},
			got:    SuspendOutcome{SuspendFired: false},
			want:   []ViolationClass{ViolationSuspendNotFired},
		},
		{
			name:   "violation-block-cap-over-escalated",
			signal: SuspendSignal{Session: "s5", RuleAction: ActionBlock, Provenance: "rule=cap-A layer=org v=3"},
			got:    SuspendOutcome{SuspendFired: true, Reason: ReasonPolicy},
			want:   []ViolationClass{ViolationSuspendOverEscalated},
		},
		{
			name:   "violation-reason-outside-enum",
			signal: SuspendSignal{Session: "s6", Blocklist: true, Provenance: "rule=block-Q layer=org v=1"},
			got:    SuspendOutcome{SuspendFired: true, Reason: SuspendReason("quarantine")},
			want:   []ViolationClass{ViolationSuspendReasonUnmapped},
		},
		{
			name:   "violation-policy-breach-without-provenance",
			signal: SuspendSignal{Session: "s7", RuleAction: ActionSuspend, Provenance: ""},
			got:    SuspendOutcome{SuspendFired: true, Reason: ReasonPolicy},
			want:   []ViolationClass{ViolationSuspendProvenanceMissing},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckSuspendOnBreach(c.signal, c.got)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "suspend-on-breach", declared, seen, sawControl)
}

// ── ROW 2 — ask-grant atomicity (doc 13 §7) ─────────────────────────────────

func TestRowAskGrantAtomicity(t *testing.T) {
	declared := []ViolationClass{
		ViolationGrantNotEnforcedPostApply, ViolationGrantEnforcedPreApply,
		ViolationGrantMidWindowNotDnsRefused,
	}
	type tc struct {
		name  string
		grant GrantRetry
		want  []ViolationClass
	}
	cases := []tc{
		{
			name:  "conforming-post-apply-retry-succeeds",
			grant: GrantRetry{Session: "g1", Phase: PhaseApplied, Got: RetrySucceeded},
			want:  nil,
		},
		{
			name:  "conforming-streamed-retry-dns-refused",
			grant: GrantRetry{Session: "g2", Phase: PhaseStreamed, Got: RetryDnsRefused},
			want:  nil,
		},
		{
			name:  "conforming-barriered-retry-dns-refused",
			grant: GrantRetry{Session: "g3", Phase: PhaseBarriered, Got: RetryDnsRefused},
			want:  nil,
		},
		{
			name:  "violation-applied-grant-not-enforced",
			grant: GrantRetry{Session: "g4", Phase: PhaseApplied, Got: RetryDnsRefused},
			want:  []ViolationClass{ViolationGrantNotEnforcedPostApply},
		},
		{
			name:  "violation-streamed-grant-enforced-pre-apply",
			grant: GrantRetry{Session: "g5", Phase: PhaseStreamed, Got: RetrySucceeded},
			want:  []ViolationClass{ViolationGrantEnforcedPreApply},
		},
		{
			name:  "violation-mid-window-resolve-then-tls-refuse",
			grant: GrantRetry{Session: "g6", Phase: PhaseBarriered, Got: RetryResolveThenTlsRej},
			want:  []ViolationClass{ViolationGrantMidWindowNotDnsRefused},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckAskGrantAtomicity(c.grant)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "ask-grant-atomicity", declared, seen, sawControl)
}

// ── ROW 3 — skew-widening / scheduler-refusal (D72) ─────────────────────────

func TestRowSkewWidening(t *testing.T) {
	declared := []ViolationClass{
		ViolationStalePlacementAdmitted, ViolationFreshPlacementRefused,
		ViolationStaleRoutableAdmitted,
	}
	type tc struct {
		name string
		host HostFreshness
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-fresh-host-placed-and-routable",
			host: HostFreshness{Host: "h1", PolicyHead: 100, AppliedSeq: 98, BudgetN: 5, Placed: true, Routable: true},
			want: nil,
		},
		{
			name: "conforming-stale-host-refused",
			host: HostFreshness{Host: "h2", PolicyHead: 100, AppliedSeq: 80, BudgetN: 5, Placed: false},
			want: nil,
		},
		{
			name: "conforming-host-at-budget-edge-is-fresh-placed",
			host: HostFreshness{Host: "h3", PolicyHead: 100, AppliedSeq: 95, BudgetN: 5, Placed: true, Routable: true},
			want: nil,
		},
		{
			name: "violation-stale-placement-admitted",
			host: HostFreshness{Host: "h4", PolicyHead: 100, AppliedSeq: 80, BudgetN: 5, Placed: true, Routable: false},
			want: []ViolationClass{ViolationStalePlacementAdmitted},
		},
		{
			name: "violation-fresh-placement-refused",
			host: HostFreshness{Host: "h5", PolicyHead: 100, AppliedSeq: 99, BudgetN: 5, Placed: false},
			want: []ViolationClass{ViolationFreshPlacementRefused},
		},
		{
			name: "violation-stale-routable-admitted",
			host: HostFreshness{Host: "h6", PolicyHead: 100, AppliedSeq: 80, BudgetN: 5, Placed: true, Routable: true},
			// placed-on-stale (caught by step-3 rule) AND reached routable on stale
			// (caught by the step-9 re-check) — both NAMED.
			want: []ViolationClass{ViolationStalePlacementAdmitted, ViolationStaleRoutableAdmitted},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckSkewWidening(c.host)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "skew-widening", declared, seen, sawControl)
}

// ── ROW 4 — revocation-of-derived-state clock (D72/D68/D53) ─────────────────

func TestRowRevocationClock(t *testing.T) {
	declared := []ViolationClass{
		ViolationDerivedStateNotEvicted, ViolationAppliedSeqAdvancedPreSweep,
		ViolationNonSeveringFlowSevered,
	}
	type tc struct {
		name string
		rev  Revocation
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-severing-evicts-and-applied-post-sweep",
			rev: Revocation{
				Domain: "evil.example", Severing: true, CommitSeq: 50,
				DerivedStateEvicted: true, EstablishedFlowSevered: true,
				SweepCompleted: true, AppliedSeq: 50,
			},
			want: nil,
		},
		{
			name: "conforming-non-severing-leaves-flow-alone",
			rev: Revocation{
				Domain: "logged.example", Severing: false, CommitSeq: 51,
				DerivedStateEvicted: false, EstablishedFlowSevered: false,
				SweepCompleted: true, AppliedSeq: 51,
			},
			want: nil,
		},
		{
			name: "conforming-applied-lags-until-sweep-done",
			rev: Revocation{
				Domain: "evil2.example", Severing: true, CommitSeq: 52,
				DerivedStateEvicted: false, EstablishedFlowSevered: false,
				SweepCompleted: false, AppliedSeq: 51, // not yet at CommitSeq — correct
			},
			want: nil,
		},
		{
			name: "violation-derived-state-survives-sweep",
			rev: Revocation{
				Domain: "evil3.example", Severing: true, CommitSeq: 53,
				DerivedStateEvicted: false, EstablishedFlowSevered: true,
				SweepCompleted: true, AppliedSeq: 53,
			},
			want: []ViolationClass{ViolationDerivedStateNotEvicted},
		},
		{
			name: "violation-applied-seq-advanced-pre-sweep",
			rev: Revocation{
				Domain: "evil4.example", Severing: true, CommitSeq: 54,
				DerivedStateEvicted: false, EstablishedFlowSevered: false,
				SweepCompleted: false, AppliedSeq: 54, // reached CommitSeq before sweep — wrong
			},
			want: []ViolationClass{ViolationAppliedSeqAdvancedPreSweep},
		},
		{
			name: "violation-non-severing-severed-flow",
			rev: Revocation{
				Domain: "logged2.example", Severing: false, CommitSeq: 55,
				DerivedStateEvicted: false, EstablishedFlowSevered: true,
				SweepCompleted: true, AppliedSeq: 55,
			},
			want: []ViolationClass{ViolationNonSeveringFlowSevered},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckRevocationClock(c.rev)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "revocation-of-derived-state-clock", declared, seen, sawControl)
}

// ── ROW 5 — D74 pack-staleness canary evidence feed (co-owned) ──────────────

func TestRowCanaryEvidenceFeed(t *testing.T) {
	declared := []ViolationClass{
		ViolationCanaryShadowCountedAsHit, ViolationCanaryGapReadAsZero,
		ViolationCanaryRetiredWithEnforcingHits,
	}
	type tc struct {
		name string
		ev   CanaryEvidence
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-zero-enforcing-complete-window-retired",
			ev: CanaryEvidence{
				Entry: "stale.pkg.example", WindowDays: 30, EnforcingHits: 0,
				ShadowHits: 0, DaysWithTelemetry: 30, Retired: true,
			},
			want: nil,
		},
		{
			name: "conforming-enforcing-hits-keep-entry",
			ev: CanaryEvidence{
				Entry: "used.pkg.example", WindowDays: 30, EnforcingHits: 12,
				ShadowHits: 3, DaysWithTelemetry: 30, Retired: false,
			},
			want: nil,
		},
		{
			name: "conforming-shadow-only-still-retires",
			ev: CanaryEvidence{
				Entry: "observed.pkg.example", WindowDays: 30, EnforcingHits: 0,
				ShadowHits: 9, DaysWithTelemetry: 30, Retired: true, // shadow is not evidence of use
			},
			want: nil,
		},
		{
			name: "violation-retired-despite-enforcing-hits",
			ev: CanaryEvidence{
				Entry: "wrongly-retired.example", WindowDays: 30, EnforcingHits: 4,
				ShadowHits: 0, DaysWithTelemetry: 30, Retired: true,
			},
			want: []ViolationClass{ViolationCanaryRetiredWithEnforcingHits},
		},
		{
			name: "violation-gap-read-as-zero",
			ev: CanaryEvidence{
				Entry: "gappy.example", WindowDays: 30, EnforcingHits: 0,
				ShadowHits: 0, DaysWithTelemetry: 11, Retired: true, // incomplete window
			},
			want: []ViolationClass{ViolationCanaryGapReadAsZero},
		},
		{
			name: "violation-shadow-counted-as-enforcing",
			ev: CanaryEvidence{
				Entry: "shadow-folded.example", WindowDays: 30, EnforcingHits: 0,
				ShadowHits: 7, DaysWithTelemetry: 30, Retired: false, // should have retired
			},
			want: []ViolationClass{ViolationCanaryShadowCountedAsHit},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckCanaryEvidenceFeed(c.ev)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "pack-staleness-canary-evidence-feed", declared, seen, sawControl)
}

// assertClasses is the shared per-case assertion: a CONFORMING fixture (want
// empty) must report NO violations, and a violation fixture must FAIL with its
// NAMED class set exactly — a silent pass is the regression each row exists to
// catch.
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
