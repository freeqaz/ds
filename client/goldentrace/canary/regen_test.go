// regen_test.go — proves the always-on capture-review engine: fixtures
// regenerate BY COMMAND, offline against the committed cassettes, and a planted
// drift produces a REVIEWABLE diff. All offline, fixture-only, no
// claude/cia/podman (the live leg is DS_E2E_LIVE-gated, never run here).
package canary

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegenMatchesCommittedGoldens is the always-on regen: every committed
// cassette projects to its committed canon golden. Run from the package dir
// (pkgLayout). A drift here means a committed golden is stale relative to its
// cassette — re-run `... regen -update` after review.
func TestRegenMatchesCommittedGoldens(t *testing.T) {
	results, drifts, err := Regenerate(pkgLayout(), false)
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("regen produced no results — the fixtures glob matched nothing")
	}
	if drifts != 0 {
		var sb strings.Builder
		WriteReport(&sb, results, drifts)
		t.Errorf("committed canon goldens DIVERGE from the cassettes (%d drift) — "+
			"re-run `go run ./goldentrace/canary/cmd/canary regen -update` after review:\n%s",
			drifts, sb.String())
	}
}

// TestRegenIsByCommandAndOffline proves the regen is a genuine BY-COMMAND
// projection: it covers every committed cassette (no cassette is silently
// skipped) and each golden equals the freshly-projected canon. A green run is
// the "fixtures regenerate by command offline against committed cassettes"
// acceptance criterion.
func TestRegenIsByCommandAndOffline(t *testing.T) {
	l := pkgLayout()
	cassettes, err := l.discover()
	if err != nil {
		t.Fatal(err)
	}
	for _, cassette := range cassettes {
		got, err := CassetteCanon(cassette)
		if err != nil {
			t.Errorf("project %s: %v", cassette, err)
			continue
		}
		golden := l.goldenPath(cassette)
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Errorf("read golden for %s (%s): %v — every committed cassette must have a "+
				"regenerated canon golden", filepath.Base(cassette), golden, err)
			continue
		}
		if !bytes.Equal(want, got) {
			t.Errorf("%s: committed golden != regenerated canon (by-command regen drifted)", filepath.Base(cassette))
		}
	}
}

// TestPlantedDriftProducesReviewableDiff proves a drift is CAUGHT as a
// reviewable diff: it points the regen at a TEMP golden dir seeded with a
// deliberately-mutated golden and asserts the regen reports a DRIFT whose report
// names the divergent event. Nothing under the committed testdata/ is touched.
func TestPlantedDriftProducesReviewableDiff(t *testing.T) {
	src := pkgLayout()
	tmp := t.TempDir()

	// Seed the temp golden dir from the committed goldens, then PLANT a drift in
	// one of them (corrupt a canon line) so the regen of the matching cassette
	// must diverge from this tampered golden.
	const target = "baseline-chat"
	cassettes, err := src.discover()
	if err != nil {
		t.Fatal(err)
	}
	var targetCassette string
	for _, c := range cassettes {
		want, err := os.ReadFile(src.goldenPath(c))
		if err != nil {
			t.Fatalf("read committed golden %s: %v", src.goldenPath(c), err)
		}
		if base(c) == target {
			// Plant a drift: append a bogus extra canon event so length+content diverge.
			want = append(bytes.TrimRight(want, "\n"), []byte("\n{\"type\":\"planted.drift\",\"seq\":999}\n")...)
			targetCassette = c
		}
		if err := os.WriteFile(filepath.Join(tmp, filepath.Base(src.goldenPath(c))), want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if targetCassette == "" {
		t.Fatalf("did not find the %s cassette to plant a drift on", target)
	}

	tampered := Layout{FixturesGlob: src.FixturesGlob, GoldenDir: tmp}
	results, drifts, err := Regenerate(tampered, false)
	if err != nil {
		t.Fatal(err)
	}
	if drifts == 0 {
		t.Fatal("a planted golden drift was NOT caught — the regen tolerated a divergence")
	}

	// The drift must be on the target cassette and its report must be reviewable
	// (name the divergence and point at stale-vs-drift triage).
	var found bool
	for _, r := range results {
		if base(r.Cassette) != target {
			continue
		}
		found = true
		if r.Status != "drift" {
			t.Errorf("%s: status = %q, want drift", target, r.Status)
		}
		if strings.TrimSpace(r.Report) == "" {
			t.Errorf("%s: drift produced an empty report — a catch must be reviewable", target)
		}
		for _, marker := range []string{"DIVERGES", "first diff", "STALE cassette", "CC DRIFT"} {
			if !strings.Contains(r.Report, marker) {
				t.Errorf("%s: drift report missing %q (not a reviewable diff):\n%s", target, marker, r.Report)
			}
		}
	}
	if !found {
		t.Errorf("the planted drift on %s did not appear in the results", target)
	}
}

// TestRegenUpdateRewritesGoldens proves the insta-style refresh: with update=true
// the goldens are rewritten and a subsequent compare is clean. Runs in a temp
// dir so the committed goldens are untouched.
func TestRegenUpdateRewritesGoldens(t *testing.T) {
	src := pkgLayout()
	tmp := t.TempDir()
	l := Layout{FixturesGlob: src.FixturesGlob, GoldenDir: tmp}

	// First update authors every golden from scratch (none exist in tmp): every
	// result must be "new" (the stat-before-write distinction — a golden that did
	// not exist is authored, not "updated").
	first, drifts, err := Regenerate(l, true)
	if err != nil {
		t.Fatal(err)
	}
	if drifts != 0 {
		t.Errorf("update pass reported %d drift; -update must rewrite, not diverge", drifts)
	}
	for _, r := range first {
		if r.Status != "new" {
			t.Errorf("%s: first -update status = %q, want %q (the golden dir was empty, so every "+
				"golden is freshly authored — 'updated' would mean the stat ran after the write)",
				base(r.Cassette), r.Status, "new")
		}
	}
	// A second update rewrites the now-existing goldens: every result must be
	// "updated" (the goldens pre-exist this pass).
	second, drifts, err := Regenerate(l, true)
	if err != nil {
		t.Fatal(err)
	}
	if drifts != 0 {
		t.Errorf("second update pass reported %d drift", drifts)
	}
	for _, r := range second {
		if r.Status != "updated" {
			t.Errorf("%s: second -update status = %q, want %q (the golden pre-existed this pass)",
				base(r.Cassette), r.Status, "updated")
		}
	}
	// A following compare must be clean — the goldens now match the cassettes.
	_, drifts, err = Regenerate(l, false)
	if err != nil {
		t.Fatal(err)
	}
	if drifts != 0 {
		t.Errorf("compare after -update reported %d drift; the refresh did not stabilize", drifts)
	}
}
