// SPDX-License-Identifier: Apache-2.0

package goldenfreshness

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── The anchor guard: the documented rotation window must not silently drift ─

// TestDefaultRotationWindowMatchesDocumentedCadence pins DefaultRotationWindow to
// the documented nightly cadence (24h, doc 03 §6 / images/golden/README.md
// "Rotation window = DS_GOLDEN_MAX_AGE_HOURS (default 24h)"). If someone edits the
// constant without re-ratifying the cadence, this fails HERE rather than letting
// the claim quietly assert against a different window than the runtime uses.
func TestDefaultRotationWindowMatchesDocumentedCadence(t *testing.T) {
	const documentedNightlyCadenceHours = 24
	if DefaultRotationWindow != documentedNightlyCadenceHours {
		t.Fatalf("DefaultRotationWindow = %d, want %d (the documented nightly cadence, doc 03 "+
			"§6 / images/golden/README.md); a window change must be reconciled with the "+
			"runtime rotation check (DS_GOLDEN_MAX_AGE_HOURS default)",
			DefaultRotationWindow, documentedNightlyCadenceHours)
	}
	if MaxAgeEnvVar != "DS_GOLDEN_MAX_AGE_HOURS" {
		t.Fatalf("MaxAgeEnvVar = %q, want the documented override name DS_GOLDEN_MAX_AGE_HOURS",
			MaxAgeEnvVar)
	}
}

// TestBoundaryGoldenIsFresh restates the boundary semantics directly: a golden
// exactly at the window age is FRESH (the window is the maximum tolerated age,
// not the first stale age), and one hour past it is STALE — matching the runtime
// "older than the window is STALE" phrasing.
func TestBoundaryGoldenIsFresh(t *testing.T) {
	p := Policy{MaxAgeHours: 24}
	atWindow := Manifest{
		Name:    "synthetic-boundary",
		Policy:  p,
		Goldens: []GoldenRow{{Repo: "acme/app", Branch: "main", Present: true, AgeHours: 24}},
	}
	if got := Diff(atWindow, p); len(got) != 0 {
		t.Fatalf("a golden exactly at the %dh window must be FRESH, got:\n%s", p.MaxAgeHours, render(got))
	}
	pastWindow := Manifest{
		Name:    "synthetic-boundary",
		Policy:  p,
		Goldens: []GoldenRow{{Repo: "acme/app", Branch: "main", Present: true, AgeHours: 25}},
	}
	got := Diff(pastWindow, p)
	if len(got) != 1 || got[0].Class != ViolationStale {
		t.Fatalf("a golden one hour past the %dh window must be STALE, got:\n%s", p.MaxAgeHours, render(got))
	}
}

// ── The corpus: conforming passes, every violation fails NAMED ──────────────

// corpusExpectation declares, per fixture, the violation classes the check must
// report (empty set = must pass clean). Every fixture on disk MUST be registered
// here; the coverage gate fails closed on any unlisted fixture.
var corpusExpectation = map[string][]ViolationClass{
	"00-conforming.json":  nil,
	"01-stale.json":       {ViolationStale},
	"02-missing.json":     {ViolationMissing},
	"03-unrotatable.json": {ViolationUnrotatable},
}

// TestGoldenFreshnessRotation is the row's executable form: it diffs every
// synthetic golden manifest against its rotation policy and asserts the
// conforming fixture passes clean while each violation fixture fails with its
// NAMED class. This is the mechanical freshness diff the rotation row describes.
func TestGoldenFreshnessRotation(t *testing.T) {
	for _, name := range listFixtures(t) {
		want, ok := corpusExpectation[name]
		if !ok {
			continue // coverage gate (below) owns the fail-closed message
		}
		t.Run(name, func(t *testing.T) {
			m, err := LoadManifest(filepath.Join(FixturesDir(), name))
			if err != nil {
				t.Fatalf("loading fixture %s: %v", name, err)
			}
			got := Diff(m, m.Policy)

			if len(want) == 0 {
				if len(got) != 0 {
					t.Fatalf("CONFORMING fixture %s reported %d violation(s) — every opted-in "+
						"golden present and within the window must pass clean:\n%s",
						name, len(got), render(got))
				}
				return
			}

			// Violation fixture: it must FAIL, and the named classes must match exactly.
			if len(got) == 0 {
				t.Fatalf("VIOLATION fixture %s reported NO violations — the check must fail on "+
					"%v (a silent pass is the regression this row exists to catch)", name, want)
			}
			if !sameClasses(got, want) {
				t.Fatalf("VIOLATION fixture %s reported the WRONG violation class set —\n"+
					" want: %v\n got: %v\nfull:\n%s", name, want, classesOf(got), render(got))
			}
		})
	}
}

// TestCorpusCoverage is the fail-closed coverage gate: every fixture on disk must
// be registered in corpusExpectation, and every registered key must exist on
// disk. A fixture added to fixtures/ without an expectation row fails HERE, so a
// new manifest cannot land un-asserted. The corpus must also cover the conforming
// control AND all three freshness failure modes at least once.
func TestCorpusCoverage(t *testing.T) {
	onDisk := listFixtures(t)
	onDiskSet := map[string]bool{}
	for _, n := range onDisk {
		onDiskSet[n] = true
		if _, ok := corpusExpectation[n]; !ok {
			t.Errorf("fixture %s has NO expectation row — every fixture must be wired into "+
				"corpusExpectation (fail-closed: a new manifest cannot land un-asserted)", n)
		}
	}
	for name := range corpusExpectation {
		if !onDiskSet[name] {
			t.Errorf("corpusExpectation lists %s but no such fixture exists on disk "+
				"(stale expectation — deleting a fixture must drop its row)", name)
		}
	}
	seen := map[ViolationClass]bool{}
	sawConforming := false
	for _, classes := range corpusExpectation {
		if len(classes) == 0 {
			sawConforming = true
		}
		for _, c := range classes {
			seen[c] = true
		}
	}
	if !sawConforming {
		t.Error("corpus has no CONFORMING control fixture — the green case must be proven")
	}
	for _, c := range []ViolationClass{
		ViolationStale, ViolationMissing, ViolationUnrotatable,
	} {
		if !seen[c] {
			t.Errorf("corpus never exercises violation class %q — each of the three freshness "+
				"failure modes the rotation row enumerates must have a named fixture", c)
		}
	}
}

// TestEveryFixtureHasProvenance enforces the D50 sidecar contract: every *.json
// manifest on disk must carry a committed <name>.provenance sidecar beside it, so
// no fixture can land without its synthetic-origin tag.
func TestEveryFixtureHasProvenance(t *testing.T) {
	for _, name := range listFixtures(t) {
		sidecar := filepath.Join(FixturesDir(), name+".provenance")
		if _, err := os.Stat(sidecar); err != nil {
			t.Errorf("fixture %s has no .provenance sidecar (%s) — every D50 synthetic fixture "+
				"must carry one", name, filepath.Base(sidecar))
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// listFixtures returns the sorted *.json manifest filenames on disk (the
// .provenance sidecars are excluded). Anchored via FixturesDir (runtime.Caller),
// so it walks correctly under `go test` from any cwd.
func listFixtures(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(FixturesDir())
	if err != nil {
		t.Fatalf("reading fixtures dir %s: %v", FixturesDir(), err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".json") && !strings.HasSuffix(n, ".provenance") {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		t.Fatalf("the fixtures dir %s is empty — expected synthetic golden manifests", FixturesDir())
	}
	sort.Strings(names)
	return names
}

// classesOf collects the (sorted, deduped) violation classes a diff reported.
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

// sameClasses reports whether the diff's class set equals want exactly.
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
