// perturbation_test.go — proves the fidelity loop has TEETH: a deliberate
// CC-shape perturbation is CAUGHT as a reviewable diff, not silently tolerated.
//
// The "Done when…" bar of taskdb 01KTXBGTK6: "a deliberate CC-shape perturbation
// is caught as a reviewable diff." A green TestFidelityProjectionEquality alone
// cannot distinguish "the cassettes are faithful" from "the equality check stopped
// looking" — the classic vacuous-assertion failure mode. This file closes that
// gap: it takes the live-equiv leg, mutates the CC wire IN MEMORY to model a real
// drift class (a changed field shape, a dropped frame, a renamed type), projects
// the mutant, and asserts the id-relative equality now FAILS and the failure
// REPORT is reviewable (names the divergent event, points at stale-vs-drift).
//
// The mutation is confined to memory — nothing is written under client/fixtures/
// or testdata/, so no D50 provenance header is needed and the committed cassettes
// are untouched (HARDENING-NOTES §2.3). Each row also passes a STALE-ANCHOR GUARD:
// the mutation must actually change the cassette bytes, else a re-authoring slid
// the anchor out from under it and the row is silently vacuous — itself a hard
// failure.
package fidelity

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// perturbation models one CC-shape drift class as a byte mutation on a cassette
// stream. anchor must occur in the cassette (the stale-anchor guard); replacement
// is the drifted shape.
type perturbation struct {
	name        string
	anchor      string
	replacement string
	// why documents the real CC-drift class this perturbation stands in for.
	why string
}

// drifts is the catalogue: each perturbs a DISTINCT, high-value surface. The
// control channel (gap 2) and the assistant/result framing are the costliest
// blind spots (DRIVE-PROTOCOL.md "three gaps"); a silent regression there is the
// one we most need the loop to catch.
var drifts = []perturbation{
	{
		name:        "chat-text-drift",
		anchor:      `"text":"Created /work/scratch."`,
		replacement: `"text":"Made the scratch directory."`,
		why:         "assistant chat content changed — a stale cassette or a model/format shift",
	},
	{
		name: "result-outcome-drift",
		// A result subtype change is the textbook CC terminal-shape drift (P13).
		anchor:      `"subtype":"success","session_id":"f24b8a07`,
		replacement: `"subtype":"error_during_execution","session_id":"f24b8a07`,
		why:         "result terminal subtype changed — CC outcome-vocabulary drift (P13)",
	},
	{
		name: "ask-behavior-drift",
		// The control_response behavior flips allow->deny: the costliest blind spot
		// (gap 2, the native control channel) — a silent miss here is the worst.
		anchor:      `"response":{"behavior":"allow","updatedInput"`,
		replacement: `"response":{"behavior":"deny","message":"drifted","updatedInput"`,
		why:         "control_response behavior changed — native control-channel drift (gap 2)",
	},
	{
		name: "dropped-tool-use-drift",
		// Renaming the tool_use type drops the tool invocation from the projection
		// entirely — a structural (length) divergence the loop must still catch.
		anchor:      `"type":"tool_use","id":"toolu_01XkLm7pQ9NpRtUvWxYz2Ab"`,
		replacement: `"type":"tool_use_RENAMED","id":"toolu_01XkLm7pQ9NpRtUvWxYz2Ab"`,
		why:         "a frame type was renamed — CC record-type drift drops an event",
	},
}

func TestPerturbationCaughtAsReviewableDiff(t *testing.T) {
	// We perturb the native-ask live-equiv leg: it carries chat, the result
	// terminal, AND the control channel + tool_use, so every drift row has its
	// anchor in one cassette.
	const synthetic = "drive-fid-native-ask"
	const liveEquiv = "drive-fid-native-ask-live-equiv"

	pristine, err := os.ReadFile(cassettePath(liveEquiv))
	if err != nil {
		t.Fatalf("read live-equiv cassette: %v", err)
	}

	// Baseline: the unperturbed pair MUST be equal (else the test is testing the
	// wrong thing).
	base, err := EqualFiles(cassettePath(synthetic), cassettePath(liveEquiv))
	if err != nil {
		t.Fatalf("baseline equality: %v", err)
	}
	if !base.Equal {
		t.Fatalf("baseline pair is not equal; cannot prove perturbation catch:\n%s", base.Report)
	}

	synEvs, err := ProjectFile(cassettePath(synthetic))
	if err != nil {
		t.Fatalf("project synthetic: %v", err)
	}

	for _, d := range drifts {
		t.Run(d.name, func(t *testing.T) {
			// STALE-ANCHOR GUARD: the anchor must exist and the mutation must
			// change the bytes — a no-op mutation makes the row vacuous.
			if !bytes.Contains(pristine, []byte(d.anchor)) {
				t.Fatalf("stale anchor: %q no longer occurs in %s — re-point the "+
					"perturbation (a vacuous row is a hard failure)", d.anchor, liveEquiv)
			}
			mutant := bytes.Replace(pristine, []byte(d.anchor), []byte(d.replacement), 1)
			if bytes.Equal(mutant, pristine) {
				t.Fatalf("mutation %q was a no-op (bytes unchanged)", d.name)
			}

			mutantEvs, err := ProjectStream(bytes.NewReader(mutant))
			if err != nil {
				// A parse error on a drifted shape is ALSO a valid catch (the
				// adapter refusing to project the drift is a loud signal). Pass.
				t.Logf("perturbation %q caught as a projection error (a valid catch): %v", d.name, err)
				return
			}

			diff := EqualProjections("synthetic", synEvs, "live(drifted)", mutantEvs)
			if diff.Equal {
				t.Errorf("BLIND SPOT: perturbation %q (%s) was NOT caught — the "+
					"projections still compare EQUAL. The fidelity loop tolerated a "+
					"CC-shape drift it must flag.", d.name, d.why)
				return
			}
			// The catch must be REVIEWABLE: a non-empty report naming the divergence
			// and pointing the reviewer at stale-vs-drift triage.
			if strings.TrimSpace(diff.Report) == "" {
				t.Errorf("perturbation %q diverged but produced an empty report — a "+
					"catch must be reviewable", d.name)
			}
			if !strings.Contains(diff.Report, "diverges") {
				t.Errorf("perturbation %q report is not a recognizable diff:\n%s", d.name, diff.Report)
			}
			t.Logf("caught %q (%s):\n%s", d.name, d.why, diff.Report)
		})
	}
}
