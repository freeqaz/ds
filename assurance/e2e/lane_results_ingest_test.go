// SPDX-License-Identifier: Apache-2.0

package e2e

// lane_results_ingest_test.go — SYNTHETIC-fixture coverage for the offline
// `go test -json` → LaneResults ingest adapter (lane_results_ingest.go) plus the
// cross-lane fidelity-tag consistency arm the adapter's landing added to
// DetectDivergences (divergence_filer.go).
//
// Pure and offline, matching the rest of this tier (D50): the "go test -json"
// streams here are hand-authored embedded strings standing in for a real lane
// run, never a live `go test` invocation. It asserts the pass/fail/skip verdict
// mapping, subtest folding, output→Detail capture, that ingest is deterministic
// (parse twice → equal), that a parsed LaneResults feeds DetectDivergences and
// files the expected divergence, and that a same-Name/different-Fidelity mismatch
// across lanes is FLAGGED rather than silently absorbed.

import (
	"reflect"
	"strings"
	"testing"
)

// nestedRunJSON is a synthetic `go test -json` stream for the nested lane. It
// covers every terminal verdict the adapter maps — pass, fail, skip — plus a
// package-level event (empty Test) and a subtest, so the fixture exercises the
// full mapping surface.
const nestedRunJSON = `
{"Time":"2026-07-07T00:00:00Z","Action":"start","Package":"lifecycle"}
{"Time":"2026-07-07T00:00:00Z","Action":"run","Package":"lifecycle","Test":"TestCreateAttachReachesATTACHED"}
{"Time":"2026-07-07T00:00:00Z","Action":"output","Package":"lifecycle","Test":"TestCreateAttachReachesATTACHED","Output":"=== RUN   TestCreateAttachReachesATTACHED\n"}
{"Time":"2026-07-07T00:00:01Z","Action":"pass","Package":"lifecycle","Test":"TestCreateAttachReachesATTACHED","Elapsed":1.0}
{"Time":"2026-07-07T00:00:01Z","Action":"run","Package":"lifecycle","Test":"TestSnapshotCoWPreservesOverlay"}
{"Time":"2026-07-07T00:00:01Z","Action":"output","Package":"lifecycle","Test":"TestSnapshotCoWPreservesOverlay","Output":"    nested overlay CoW looked correct\n"}
{"Time":"2026-07-07T00:00:02Z","Action":"pass","Package":"lifecycle","Test":"TestSnapshotCoWPreservesOverlay","Elapsed":1.0}
{"Time":"2026-07-07T00:00:02Z","Action":"run","Package":"lifecycle","Test":"TestPauseBudgetTransparent"}
{"Time":"2026-07-07T00:00:02Z","Action":"output","Package":"lifecycle","Test":"TestPauseBudgetTransparent","Output":"    metal-only: not run nested\n"}
{"Time":"2026-07-07T00:00:02Z","Action":"skip","Package":"lifecycle","Test":"TestPauseBudgetTransparent","Elapsed":0.0}
{"Time":"2026-07-07T00:00:02Z","Action":"run","Package":"lifecycle","Test":"TestCleanTeardown"}
{"Time":"2026-07-07T00:00:03Z","Action":"run","Package":"lifecycle","Test":"TestCleanTeardown/no_leaked_nft_rules"}
{"Time":"2026-07-07T00:00:03Z","Action":"pass","Package":"lifecycle","Test":"TestCleanTeardown/no_leaked_nft_rules","Elapsed":0.5}
{"Time":"2026-07-07T00:00:03Z","Action":"pass","Package":"lifecycle","Test":"TestCleanTeardown","Elapsed":0.6}
{"Time":"2026-07-07T00:00:03Z","Action":"pass","Package":"lifecycle","Elapsed":3.0}
`

// metalRunJSON is the matching metal-nightly stream. The one difference from
// nested: TestSnapshotCoWPreservesOverlay FAILS on metal — the D34
// nested-green/metal-red divergence — and it carries a failing message the
// adapter should surface as the assertion's Detail. Like a REAL stream, the
// failing test's last output line is the "--- FAIL: ..." framing trailer; the
// Detail must quote the failure text, not that trailer.
const metalRunJSON = `
{"Time":"2026-07-07T01:00:00Z","Action":"start","Package":"lifecycle"}
{"Time":"2026-07-07T01:00:01Z","Action":"pass","Package":"lifecycle","Test":"TestCreateAttachReachesATTACHED","Elapsed":1.0}
{"Time":"2026-07-07T01:00:01Z","Action":"output","Package":"lifecycle","Test":"TestSnapshotCoWPreservesOverlay","Output":"    metal virtio overlay diverged after resume\n"}
{"Time":"2026-07-07T01:00:02Z","Action":"output","Package":"lifecycle","Test":"TestSnapshotCoWPreservesOverlay","Output":"--- FAIL: TestSnapshotCoWPreservesOverlay (1.00s)\n"}
{"Time":"2026-07-07T01:00:02Z","Action":"fail","Package":"lifecycle","Test":"TestSnapshotCoWPreservesOverlay","Elapsed":1.0}
{"Time":"2026-07-07T01:00:03Z","Action":"pass","Package":"lifecycle","Test":"TestCleanTeardown","Elapsed":0.6}
{"Time":"2026-07-07T01:00:03Z","Action":"fail","Package":"lifecycle","Elapsed":3.0}
`

// ingestFidelityTags is the Name→Fidelity lookup a wired lane would supply; the
// go test -json stream carries no fidelity tag itself (it is metadata about the
// assertion, D34), so the adapter takes it from the caller.
var ingestFidelityTags = map[string]Fidelity{
	"TestCreateAttachReachesATTACHED": FidelityNestedOK,
	"TestSnapshotCoWPreservesOverlay": FidelityMetalOnly,
	"TestCleanTeardown":               FidelityNestedOK,
	"TestPauseBudgetTransparent":      FidelityMetalOnly,
}

// TestIngestGoTestJSON_MapsVerdicts asserts the pass/fail/skip mapping, subtest
// folding, fidelity-tag lookup, and output→Detail capture for a single lane.
func TestIngestGoTestJSON_MapsVerdicts(t *testing.T) {
	lr, err := IngestGoTestJSON(strings.NewReader(nestedRunJSON), IngestOptions{
		Lane:         "nested-ok",
		FidelityTags: ingestFidelityTags,
	})
	if err != nil {
		t.Fatalf("IngestGoTestJSON: %v", err)
	}
	if lr.Lane != "nested-ok" {
		t.Errorf("Lane = %q, want %q", lr.Lane, "nested-ok")
	}

	// A skipped test carries no verdict → omitted; subtests fold into the parent →
	// omitted. So the two passing top-level tests remain.
	got := map[string]AssertionResult{}
	for _, r := range lr.Results {
		got[r.Name] = r
	}
	if _, ok := got["TestPauseBudgetTransparent"]; ok {
		t.Error("a SKIPPED test must not be ingested (it produced no green/red verdict)")
	}
	if _, ok := got["TestCleanTeardown/no_leaked_nft_rules"]; ok {
		t.Error("a subtest must fold into its parent, not ingest as its own assertion")
	}
	if len(lr.Results) != 3 {
		t.Fatalf("want 3 assertions (2 pass + 1 pass, skip omitted, subtest folded), got %d: %+v", len(lr.Results), lr.Results)
	}

	attach := got["TestCreateAttachReachesATTACHED"]
	if !attach.Passed {
		t.Error("TestCreateAttachReachesATTACHED should map to Passed=true")
	}
	if attach.Fidelity != FidelityNestedOK {
		t.Errorf("fidelity tag not applied from lookup: got %q, want %q", attach.Fidelity, FidelityNestedOK)
	}

	snap := got["TestSnapshotCoWPreservesOverlay"]
	if !snap.Passed {
		t.Error("TestSnapshotCoWPreservesOverlay passed nested, should map to Passed=true")
	}
	if snap.Fidelity != FidelityMetalOnly {
		t.Errorf("metal-only fidelity not applied: got %q", snap.Fidelity)
	}
	if !strings.Contains(snap.Detail, "nested overlay CoW looked correct") {
		t.Errorf("output line should be captured into Detail, got %q", snap.Detail)
	}
}

// TestIngestGoTestJSON_MapsFailVerdict asserts a "fail" action maps to
// Passed=false and the failing output line rides Detail.
func TestIngestGoTestJSON_MapsFailVerdict(t *testing.T) {
	lr, err := IngestGoTestJSON(strings.NewReader(metalRunJSON), IngestOptions{
		Lane:         "metal-nightly",
		FidelityTags: ingestFidelityTags,
	})
	if err != nil {
		t.Fatalf("IngestGoTestJSON: %v", err)
	}
	var snap *AssertionResult
	for i := range lr.Results {
		if lr.Results[i].Name == "TestSnapshotCoWPreservesOverlay" {
			snap = &lr.Results[i]
		}
	}
	if snap == nil {
		t.Fatal("TestSnapshotCoWPreservesOverlay missing from metal ingest")
	}
	if snap.Passed {
		t.Error("a FAIL action must map to Passed=false")
	}
	if !strings.Contains(snap.Detail, "metal virtio overlay diverged after resume") {
		t.Errorf("failing output line should ride Detail, got %q", snap.Detail)
	}
	// On a real stream the LAST output line is the "--- FAIL: ..." framing
	// trailer; Detail must quote the failure text, not the framing.
	if strings.Contains(snap.Detail, "--- FAIL") {
		t.Errorf("Detail must quote the failure text, not the go test framing trailer, got %q", snap.Detail)
	}
}

// TestIngestGoTestJSON_BuildFailureFailsLoud pins the build-failure posture: a
// stream recording that the lane's package failed to BUILD (the documented
// "build-fail" / package-level fail + FailedBuild shape) produced no honest
// verdicts, so it must be rejected loud — an empty LaneResults would feed
// DetectDivergences a blank lane that reads as "no divergences", the exact
// false confidence D34 exists to prevent.
func TestIngestGoTestJSON_BuildFailureFailsLoud(t *testing.T) {
	t.Run("build-fail event", func(t *testing.T) {
		stream := `{"ImportPath":".","Action":"build-output","Output":"# .\n"}
{"ImportPath":".","Action":"build-output","Output":"no Go files in /repo\n"}
{"ImportPath":".","Action":"build-fail"}
`
		_, err := IngestGoTestJSON(strings.NewReader(stream), IngestOptions{Lane: "metal-nightly"})
		if err == nil {
			t.Fatal("a build-fail stream must be rejected loud, not ingested as an empty lane")
		}
		if !strings.Contains(err.Error(), "build failed") {
			t.Errorf("the error should name the build failure, got: %v", err)
		}
	})
	t.Run("package fail with FailedBuild", func(t *testing.T) {
		stream := `{"Time":"2026-07-07T05:49:18Z","Action":"start","Package":"."}
{"Time":"2026-07-07T05:49:18Z","Action":"output","Package":".","Output":"FAIL\t. [setup failed]\n"}
{"Time":"2026-07-07T05:49:18Z","Action":"fail","Package":".","Elapsed":0,"FailedBuild":"."}
`
		_, err := IngestGoTestJSON(strings.NewReader(stream), IngestOptions{Lane: "metal-nightly"})
		if err == nil {
			t.Fatal("a setup-failed package (FailedBuild) must be rejected loud, not ingested as an empty lane")
		}
		if !strings.Contains(err.Error(), "build failed") {
			t.Errorf("the error should name the build failure, got: %v", err)
		}
	})
}

// TestIngestGoTestJSON_Deterministic proves parsing the same stream twice yields
// an EQUAL LaneResults — no map-iteration nondeterminism leaks into the output
// (Results are sorted by Name).
func TestIngestGoTestJSON_Deterministic(t *testing.T) {
	opts := IngestOptions{Lane: "nested-ok", FidelityTags: ingestFidelityTags}
	a, err := IngestGoTestJSON(strings.NewReader(nestedRunJSON), opts)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	b, err := IngestGoTestJSON(strings.NewReader(nestedRunJSON), opts)
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("ingest must be deterministic (same stream → equal LaneResults):\n a=%+v\n b=%+v", a, b)
	}
	// And the Results really are sorted by Name.
	for i := 1; i < len(a.Results); i++ {
		if a.Results[i-1].Name > a.Results[i].Name {
			t.Errorf("Results not sorted by Name: %q before %q", a.Results[i-1].Name, a.Results[i].Name)
		}
	}
}

// TestIngestGoTestJSON_FeedsDetectDivergences is the end-to-end offline proof:
// the two ingested lane runs feed DetectDivergences and file exactly the one
// nested-green/metal-red divergence, with the ingested Detail carried through —
// the whole point of the adapter (feed the D34 filer a REAL run shape).
func TestIngestGoTestJSON_FeedsDetectDivergences(t *testing.T) {
	nested, err := IngestGoTestJSON(strings.NewReader(nestedRunJSON), IngestOptions{Lane: "nested-ok", FidelityTags: ingestFidelityTags})
	if err != nil {
		t.Fatalf("nested ingest: %v", err)
	}
	metal, err := IngestGoTestJSON(strings.NewReader(metalRunJSON), IngestOptions{Lane: "metal-nightly", FidelityTags: ingestFidelityTags})
	if err != nil {
		t.Fatalf("metal ingest: %v", err)
	}

	records, err := DetectDivergences(nested, metal)
	if err != nil {
		t.Fatalf("DetectDivergences over ingested lanes: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want exactly 1 divergence from the ingested runs, got %d: %+v", len(records), records)
	}
	rec := records[0]
	if rec.Assertion != "TestSnapshotCoWPreservesOverlay" {
		t.Errorf("filed the wrong assertion: %q", rec.Assertion)
	}
	if !strings.Contains(rec.Body, "metal virtio overlay diverged after resume") {
		t.Errorf("ingested metal Detail should carry into the filed body:\n%s", rec.Body)
	}
	if !strings.Contains(rec.Body, "metal-only") {
		t.Errorf("ingested fidelity tag should carry into the filed body:\n%s", rec.Body)
	}
}

// TestIngestGoTestJSON_RejectsMalformed asserts a non-JSON line fails loud rather
// than silently ingesting a partial lane result.
func TestIngestGoTestJSON_RejectsMalformed(t *testing.T) {
	bad := `{"Action":"pass","Test":"TestOK"}
this is not json
`
	if _, err := IngestGoTestJSON(strings.NewReader(bad), IngestOptions{Lane: "nested-ok"}); err == nil {
		t.Fatal("a malformed event line must be rejected, not silently skipped")
	}
}

// TestIngestGoTestJSON_RequiresLane asserts an empty Lane is a caller error — a
// LaneResults with no provenance cannot be joined.
func TestIngestGoTestJSON_RequiresLane(t *testing.T) {
	if _, err := IngestGoTestJSON(strings.NewReader(nestedRunJSON), IngestOptions{}); err == nil {
		t.Fatal("an empty Lane must be rejected")
	}
}

// TestIngestGoTestJSON_UntaggedTestGetsZeroFidelity proves the adapter never
// invents a fidelity tag: a test absent from FidelityTags ingests with the zero
// Fidelity (""), which the filer renders "(untagged)".
func TestIngestGoTestJSON_UntaggedTestGetsZeroFidelity(t *testing.T) {
	stream := `{"Action":"pass","Test":"TestUntagged"}` + "\n"
	lr, err := IngestGoTestJSON(strings.NewReader(stream), IngestOptions{Lane: "nested-ok"})
	if err != nil {
		t.Fatalf("IngestGoTestJSON: %v", err)
	}
	if len(lr.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(lr.Results))
	}
	if lr.Results[0].Fidelity != Fidelity("") {
		t.Errorf("untagged test must keep the zero Fidelity, got %q", lr.Results[0].Fidelity)
	}
}

// TestDetectDivergences_FlagsFidelityTagMismatch is the cross-lane fidelity-tag
// consistency arm: the SAME assertion tagged DIFFERENTLY on the two lanes
// (nested-ok on one, metal-only on the other) is an inconsistency that must be
// FLAGGED — analogous to the duplicate-Name rejection — not silently absorbed
// into a mis-framed verdict. This test fails before the arm (the mismatch was
// carried silently and the pair filed / suppressed under one lane's tag) and
// passes after it.
func TestDetectDivergences_FlagsFidelityTagMismatch(t *testing.T) {
	nested := LaneResults{Lane: testNestedLane, Results: []AssertionResult{
		{Name: "snapshot-cow-preserves-overlay", Fidelity: FidelityNestedOK, Passed: true},
	}}
	metal := LaneResults{Lane: testMetalLane, Results: []AssertionResult{
		// SAME assertion Name, DIFFERENT fidelity tag — the suite disagrees about
		// what this assertion even is.
		{Name: "snapshot-cow-preserves-overlay", Fidelity: FidelityMetalOnly, Passed: false},
	}}
	_, err := DetectDivergences(nested, metal)
	if err == nil {
		t.Fatal("a same-assertion/different-fidelity mismatch across lanes must be FLAGGED, not silently absorbed")
	}
	if !strings.Contains(err.Error(), "fidelity") {
		t.Errorf("the flag should name the fidelity-tag inconsistency, got: %v", err)
	}
}

// TestDetectDivergences_ConsistentFidelityStillFiles is the control for the arm:
// when both lanes tag the assertion the SAME, the fidelity-consistency check does
// not fire and the ordinary nested-green/metal-red detection still works.
func TestDetectDivergences_ConsistentFidelityStillFiles(t *testing.T) {
	nested := LaneResults{Lane: testNestedLane, Results: []AssertionResult{
		{Name: "snapshot-cow-preserves-overlay", Fidelity: FidelityMetalOnly, Passed: true},
	}}
	metal := LaneResults{Lane: testMetalLane, Results: []AssertionResult{
		{Name: "snapshot-cow-preserves-overlay", Fidelity: FidelityMetalOnly, Passed: false},
	}}
	records, err := DetectDivergences(nested, metal)
	if err != nil {
		t.Fatalf("consistent fidelity tags must not trip the arm: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 divergence with consistent tags, got %d", len(records))
	}
}
