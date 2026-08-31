// fidelity_test.go — the always-on fidelity loop, run BY COMMAND over the
// re-authored synthetic cassette set:
//
//	cd client && go test ./goldentrace/fidelity -run TestFidelityProjectionEquality
//
// THE QUESTION it answers (DRIVE-PROTOCOL.md §Determinism; taskdb 01KTXBGTK6):
// "are our hand-authored synthetic cassettes actually faithful?" For each
// scenario it projects two re-authored synthetic cassettes — the canonical
// synthetic and a "-live-equiv" twin authored with DIFFERENT minted ids and
// timing/cost (the stand-in for a live CC capture, since the live tier is
// DS_E2E_LIVE-gated, fidelity_live_test.go) — and asserts the adapter's
// projections are EQUAL id-relative. Because the twins carry different concrete
// ids/timings, byte-equal projections are impossible: a green run proves the
// equality is genuinely STRUCTURAL, not a tautology. The live-vs-synthetic form
// of the same assertion runs in fidelity_live_test.go behind the gate.
//
// All synthetic, fixture-fed, ZERO egress (D50): no live claude/cia/podman.
package fidelity

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/replay"
)

// The fidelity scenario set the tests run over is fidScenarios (runner.go) — the
// single source of truth shared with the fidcheck command. Each is a (synthetic,
// live-equiv) pair under client/fixtures/; the live-equiv leg stands in for a
// CIA-ground-truthed live capture re-authored per D50 (different ids/timing/cost,
// same structure).

func cassettePath(base string) string {
	return filepath.FromSlash("../../fixtures/" + base + ".cc-wire.ndjson")
}

// TestFidelityProjectionEquality is the loop, by command: for every scenario,
// the projection of the synthetic cassette must EQUAL the projection of its
// live-equiv twin, id-relative. A divergence here is a STALE cassette or CC
// drift (the report says so and how to tell which).
func TestFidelityProjectionEquality(t *testing.T) {
	for _, p := range fidScenarios {
		t.Run(p.name, func(t *testing.T) {
			diff, err := EqualFiles(cassettePath(p.synthetic), cassettePath(p.liveEquiv))
			if err != nil {
				t.Fatalf("fidelity equality %s: %v", p.name, err)
			}
			if !diff.Equal {
				t.Errorf("scenario %q: synthetic and live-equiv projections diverge.\n%s",
					p.name, diff.Report)
			}
		})
	}
}

// TestFidelityLoopIsNonVacuous guards against the loop silently becoming a
// tautology: the RAW (pre-canon) projections of the two legs MUST differ in
// bytes (different ids/timing/cost), so the id-relative equality is doing real
// work. If a future edit made the two legs byte-identical, this fails — the
// "n=1 / circularity" worry the findings keep flagging would have crept back in.
func TestFidelityLoopIsNonVacuous(t *testing.T) {
	for _, p := range fidScenarios {
		t.Run(p.name, func(t *testing.T) {
			synEvs, err := ProjectFile(cassettePath(p.synthetic))
			if err != nil {
				t.Fatal(err)
			}
			liveEvs, err := ProjectFile(cassettePath(p.liveEquiv))
			if err != nil {
				t.Fatal(err)
			}
			var rawSyn, rawLive bytes.Buffer
			if err := replay.WriteNDJSON(&rawSyn, synEvs); err != nil {
				t.Fatal(err)
			}
			if err := replay.WriteNDJSON(&rawLive, liveEvs); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(rawSyn.Bytes(), rawLive.Bytes()) {
				t.Errorf("scenario %q: the two legs project BYTE-IDENTICALLY — the "+
					"id-relative equality is vacuous. Re-author the live-equiv twin "+
					"with distinct ids/timing/cost so the loop tests structure, not "+
					"a tautology.", p.name)
			}
		})
	}
}

// TestFidelitySelfEqual sanity-checks the canon transform: a projection always
// equals itself.
func TestFidelitySelfEqual(t *testing.T) {
	for _, p := range fidScenarios {
		evs, err := ProjectFile(cassettePath(p.synthetic))
		if err != nil {
			t.Fatal(err)
		}
		if d := EqualProjections("a", evs, "b", evs); !d.Equal {
			t.Errorf("scenario %q: a projection is not equal to itself:\n%s", p.name, d.Report)
		}
	}
}
