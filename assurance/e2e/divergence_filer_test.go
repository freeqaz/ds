// SPDX-License-Identifier: Apache-2.0

package e2e

// divergence_filer_test.go — SYNTHETIC-fixture coverage for the D34
// nested-green/metal-red divergence auto-filer (divergence_filer.go). Pure and
// offline: it never dials taskdb, a hypervisor, or metal — the "metal" lane here
// is a hand-authored fixture standing in for the deferred metal-nightly run, the
// same synthetic-wire-shape discipline the rest of this tier uses (D50). It
// asserts the ONLY thing that files (nested green + metal red on the same
// assertion), the many things that must NOT file, dedup-key stability across
// runs, and that the emitted record is a well-formed taskdb-file-able payload.

import (
	"strings"
	"testing"
)

// nestedLane / metalLane name the two synthetic lanes used throughout.
const (
	testNestedLane = "nested-ok"
	testMetalLane  = "metal-nightly"
)

// syntheticDivergenceCase is the load-bearing fixture: a lifecycle run where one
// metal-only assertion is green nested but red on metal (the D34 trigger),
// alongside assertions that agree — so the filer must pick out exactly the one
// diverging assertion and nothing else.
func syntheticDivergenceCase() (nested, metal LaneResults) {
	nested = LaneResults{
		Lane: testNestedLane,
		Results: []AssertionResult{
			{Name: "create-attach-reaches-ATTACHED", Fidelity: FidelityNestedOK, Passed: true},
			{Name: "clean-teardown-no-leaked-nft-rules", Fidelity: FidelityNestedOK, Passed: true},
			// The divergence: snapshot/CoW is a metal-only assertion that the nested
			// substrate proved GREEN (nested CoW happens to behave) but that metal
			// finds RED — the exact fidelity gap D34 says to auto-file.
			{Name: "snapshot-cow-preserves-overlay", Fidelity: FidelityMetalOnly, Passed: true, Detail: "nested overlay CoW looked correct"},
		},
	}
	metal = LaneResults{
		Lane: testMetalLane,
		Results: []AssertionResult{
			{Name: "create-attach-reaches-ATTACHED", Fidelity: FidelityNestedOK, Passed: true},
			{Name: "clean-teardown-no-leaked-nft-rules", Fidelity: FidelityNestedOK, Passed: true},
			{Name: "snapshot-cow-preserves-overlay", Fidelity: FidelityMetalOnly, Passed: false, Detail: "metal virtio overlay diverged after resume"},
		},
	}
	return nested, metal
}

// TestDetectDivergences_FilesTheNestedGreenMetalRedPair is the positive case: the
// filer detects exactly the one nested-green/metal-red assertion and emits a
// single, well-formed record for it.
func TestDetectDivergences_FilesTheNestedGreenMetalRedPair(t *testing.T) {
	nested, metal := syntheticDivergenceCase()

	records, err := DetectDivergences(nested, metal)
	if err != nil {
		t.Fatalf("DetectDivergences returned error on a valid pair: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want exactly 1 divergence record for the one nested-green/metal-red assertion, got %d: %+v", len(records), records)
	}

	rec := records[0]
	if rec.Assertion != "snapshot-cow-preserves-overlay" {
		t.Errorf("filed the wrong assertion: got %q, want the diverging %q", rec.Assertion, "snapshot-cow-preserves-overlay")
	}
	if rec.NestedLane != testNestedLane || rec.MetalLane != testMetalLane {
		t.Errorf("record lane provenance wrong: nested=%q metal=%q", rec.NestedLane, rec.MetalLane)
	}
}

// TestDivergenceRecord_IsTaskdbFileable asserts the emitted record is a
// well-formed `taskdb task add` payload: non-empty title + body, a valid
// priority, a stable dedup key, and — crucially for HONEST STATUS — a body that
// frames the divergence as a TEST-ENVIRONMENT bug (D34) and names both lanes and
// the diverging assertion, so an operator reading the filed task knows it is a
// fidelity gap to close, not a product regression to chase.
func TestDivergenceRecord_IsTaskdbFileable(t *testing.T) {
	nested, metal := syntheticDivergenceCase()
	records, err := DetectDivergences(nested, metal)
	if err != nil {
		t.Fatalf("DetectDivergences: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	rec := records[0]

	if strings.TrimSpace(rec.Title) == "" {
		t.Error("record Title is empty; a filed taskdb task needs a title")
	}
	if strings.TrimSpace(rec.Body) == "" {
		t.Error("record Body is empty; a filed taskdb task needs a body")
	}
	if rec.DedupKey == "" {
		t.Error("record DedupKey is empty; the add-or-skip caller needs a stable identity")
	}
	if rec.Priority < 0 || rec.Priority > 3 {
		t.Errorf("record Priority = %d, want a valid taskdb priority (`task add --priority 0-3`)", rec.Priority)
	}

	// The D34 framing + provenance must be present so the filed task is honest and
	// actionable.
	for _, want := range []string{
		"D34",                            // the governing decision
		"TEST ENVIRONMENT",               // framed as a fidelity bug, not a product regression
		"snapshot-cow-preserves-overlay", // the diverging assertion
		testNestedLane,                   // the green lane
		testMetalLane,                    // the red lane
		"metal-only",                     // the fidelity tag carried through
		"metal virtio overlay diverged",  // the metal-side detail carried through
	} {
		if !strings.Contains(rec.Body, want) {
			t.Errorf("filed body must name %q so the divergence is actionable and honest:\n%s", want, rec.Body)
		}
	}

	// The title must scope the record to the fidelity/D34 filer so it is greppable
	// and cannot be mistaken for a product bug.
	if !strings.Contains(rec.Title, "D34") {
		t.Errorf("record Title should scope to D34: %q", rec.Title)
	}
}

// TestDetectDivergences_NoFileWhenLanesAgreeOrMetalGreen is the negative-control
// battery: the filer must file ONLY on nested-green/metal-red, never on any other
// combination. A filer that fired on agreement (or on metal-green/nested-red)
// would spam false test-environment bugs and make the mechanism worse than the
// prose it replaces.
func TestDetectDivergences_NoFileWhenLanesAgreeOrMetalGreen(t *testing.T) {
	cases := []struct {
		name          string
		nestedPassed  bool
		metalPassed   bool
		wantDivergent bool
	}{
		{"both-green", true, true, false},
		{"both-red", false, false, false},
		{"metal-green-nested-red (a real product bug, NOT a fidelity bug)", false, true, false},
		{"nested-green-metal-red (the ONLY D34 trigger)", true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nested := LaneResults{Lane: testNestedLane, Results: []AssertionResult{
				{Name: "an-assertion", Fidelity: FidelityMetalOnly, Passed: tc.nestedPassed},
			}}
			metal := LaneResults{Lane: testMetalLane, Results: []AssertionResult{
				{Name: "an-assertion", Fidelity: FidelityMetalOnly, Passed: tc.metalPassed},
			}}
			records, err := DetectDivergences(nested, metal)
			if err != nil {
				t.Fatalf("DetectDivergences: %v", err)
			}
			got := len(records) > 0
			if got != tc.wantDivergent {
				t.Errorf("nested=%v metal=%v: divergence filed=%v, want %v (records=%+v)",
					tc.nestedPassed, tc.metalPassed, got, tc.wantDivergent, records)
			}
		})
	}
}

// TestDetectDivergences_SingleLaneOnlyAssertionNeverFiles proves the join is on
// the SAME assertion across BOTH lanes: an assertion present on only one lane
// (e.g. a metal-only assertion the nested lane does not even run, or vice-versa)
// is not a divergence, regardless of its verdict — there is no cross-lane pair to
// disagree.
func TestDetectDivergences_SingleLaneOnlyAssertionNeverFiles(t *testing.T) {
	nested := LaneResults{Lane: testNestedLane, Results: []AssertionResult{
		{Name: "nested-side-only", Fidelity: FidelityNestedOK, Passed: true},
	}}
	metal := LaneResults{Lane: testMetalLane, Results: []AssertionResult{
		{Name: "metal-side-only", Fidelity: FidelityMetalOnly, Passed: false},
	}}
	records, err := DetectDivergences(nested, metal)
	if err != nil {
		t.Fatalf("DetectDivergences: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("assertions present on only one lane must not file; got %d records: %+v", len(records), records)
	}
}

// TestDetectDivergences_MultipleDivergencesAreDeterministic asserts every
// nested-green/metal-red pair files, and the record set is sorted by assertion
// name so repeated runs / diffs are stable.
func TestDetectDivergences_MultipleDivergencesAreDeterministic(t *testing.T) {
	nested := LaneResults{Lane: testNestedLane, Results: []AssertionResult{
		{Name: "zeta-timing-within-budget", Fidelity: FidelityMetalOnly, Passed: true},
		{Name: "alpha-snapshot-cow", Fidelity: FidelityMetalOnly, Passed: true},
		{Name: "agree-attached", Fidelity: FidelityNestedOK, Passed: true},
	}}
	metal := LaneResults{Lane: testMetalLane, Results: []AssertionResult{
		{Name: "zeta-timing-within-budget", Fidelity: FidelityMetalOnly, Passed: false},
		{Name: "alpha-snapshot-cow", Fidelity: FidelityMetalOnly, Passed: false},
		{Name: "agree-attached", Fidelity: FidelityNestedOK, Passed: true},
	}}
	records, err := DetectDivergences(nested, metal)
	if err != nil {
		t.Fatalf("DetectDivergences: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("want 2 divergence records, got %d: %+v", len(records), records)
	}
	// Deterministic order: sorted by assertion name.
	if records[0].Assertion != "alpha-snapshot-cow" || records[1].Assertion != "zeta-timing-within-budget" {
		t.Errorf("records not sorted deterministically by assertion: %q then %q",
			records[0].Assertion, records[1].Assertion)
	}
}

// TestDivergenceRecord_DedupKeyIsStableAndLanePairIndependent proves the
// add-or-skip identity is stable across runs and normalizes cosmetic variation,
// so the SAME unclosed fidelity gap seen night after night maps to ONE task, not
// one per nightly run — and that two DIFFERENT assertions get DIFFERENT keys.
func TestDivergenceRecord_DedupKeyIsStableAndLanePairIndependent(t *testing.T) {
	mk := func(assertion, nestedLane, metalLane string) DivergenceRecord {
		nested := LaneResults{Lane: nestedLane, Results: []AssertionResult{
			{Name: assertion, Fidelity: FidelityMetalOnly, Passed: true},
		}}
		metal := LaneResults{Lane: metalLane, Results: []AssertionResult{
			{Name: assertion, Fidelity: FidelityMetalOnly, Passed: false},
		}}
		recs, err := DetectDivergences(nested, metal)
		if err != nil {
			t.Fatalf("DetectDivergences: %v", err)
		}
		if len(recs) != 1 {
			t.Fatalf("want 1 record for %q, got %d", assertion, len(recs))
		}
		return recs[0]
	}

	// Same assertion, cosmetic variation (case + surrounding whitespace) and a
	// DIFFERENT lane-pair label → the SAME dedup key.
	a := mk("Snapshot-CoW-Preserves-Overlay", "nested-ok", "metal-nightly")
	b := mk("  snapshot-cow-preserves-overlay  ", "nested-run-2", "metal-run-2")
	if a.DedupKey != b.DedupKey {
		t.Errorf("dedup key must be stable across cosmetic + lane-pair variation: %q vs %q", a.DedupKey, b.DedupKey)
	}

	// A different assertion → a different key.
	c := mk("pause-budget-5min-transparent", "nested-ok", "metal-nightly")
	if c.DedupKey == a.DedupKey {
		t.Errorf("distinct assertions must get distinct dedup keys: both %q", a.DedupKey)
	}
}

// TestDetectDivergences_RejectsDuplicateAssertionName proves the filer refuses an
// internally inconsistent lane (the same assertion Name twice) rather than
// silently mis-joining and mis-filing.
func TestDetectDivergences_RejectsDuplicateAssertionName(t *testing.T) {
	nested := LaneResults{Lane: testNestedLane, Results: []AssertionResult{
		{Name: "dup", Fidelity: FidelityNestedOK, Passed: true},
		{Name: "dup", Fidelity: FidelityNestedOK, Passed: true},
	}}
	metal := LaneResults{Lane: testMetalLane, Results: []AssertionResult{
		{Name: "dup", Fidelity: FidelityNestedOK, Passed: false},
	}}
	if _, err := DetectDivergences(nested, metal); err == nil {
		t.Fatal("DetectDivergences must reject a lane with a duplicate assertion Name (ambiguous cross-lane join)")
	}
}

// TestDetectDivergences_RejectsEmptyAssertionName proves an assertion with no
// stable identity is rejected — it could not be joined across lanes.
func TestDetectDivergences_RejectsEmptyAssertionName(t *testing.T) {
	nested := LaneResults{Lane: testNestedLane, Results: []AssertionResult{
		{Name: "", Fidelity: FidelityNestedOK, Passed: true},
	}}
	metal := LaneResults{Lane: testMetalLane}
	if _, err := DetectDivergences(nested, metal); err == nil {
		t.Fatal("DetectDivergences must reject an assertion with an empty Name")
	}
}
