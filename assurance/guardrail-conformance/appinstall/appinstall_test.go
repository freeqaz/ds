// SPDX-License-Identifier: Apache-2.0

package appinstall

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── The doc anchor: parse §5.2 once, prove it carries the ratified invariant ─

// TestInventoryParsesFromDoc16 proves the §5.2 inventory parses out of the live
// doc 16 markdown (the single anchor) and carries EXACTLY the ratified read-only
// triplet at read level, with at least the positioning rows present. A doc edit
// that widened the read level (a fourth `*:read` row), promoted a write row to
// read, or dropped a read row fails HERE — so the inventory the check diffs
// against can never silently drift from the doc.
func TestInventoryParsesFromDoc16(t *testing.T) {
	inv, err := InventoryFromDoc16()
	if err != nil {
		t.Fatalf("parsing the §5.2 inventory from doc 16: %v", err)
	}

	// The read level must be EXACTLY the ratified triplet — no more, no fewer.
	reads := inv.readPermissions()
	wantReads := map[string]bool{}
	for _, p := range RatifiedOnboardingReadScope {
		wantReads[p] = true
	}
	if len(reads) != len(wantReads) {
		t.Fatalf("§5.2 read level has %d concrete `*:read` rows, want exactly the "+
			"ratified triplet (%d): a read-level widening or shrink must be reconciled "+
			"here\n got: %v\nwant: %v", len(reads), len(wantReads),
			sortedKeys(reads), RatifiedOnboardingReadScope)
	}
	for p := range wantReads {
		if !reads[p] {
			t.Errorf("§5.2 read level is missing ratified read scope %q", p)
		}
	}
	for p := range reads {
		if !wantReads[p] {
			t.Errorf("§5.2 read level carries %q, which is NOT in the ratified onboarding "+
				"read scope — a fresh read-level grant must be ratified, not parsed in", p)
		}
	}

	// No read row may itself be a write/positioning level (belt-and-suspenders over
	// the parser): every read-permission key must classify read.
	for _, r := range inv.Rows {
		if r.Level == LevelRead && r.Positioning {
			t.Errorf("§5.2 row %q is read level but flagged positioning — a read row must "+
				"be a concrete grant the subset claim anchors on", r.Permission)
		}
	}

	// The positioning rows (CI dispatch, status checks, the D56 enrollment flow)
	// must be present as non-read rows so "absent from inventory" is judged against
	// the WHOLE table. We assert at least one write and one not-derivable row exist.
	var sawWrite, sawNotDerivable bool
	for _, r := range inv.Rows {
		switch r.Level {
		case LevelWrite:
			sawWrite = true
		case LevelNotDerivable:
			sawNotDerivable = true
		}
	}
	if !sawWrite {
		t.Error("§5.2 inventory has no write-level positioning row — the CI-dispatch / " +
			"status-check rows are expected as recorded positioning")
	}
	if !sawNotDerivable {
		t.Error("§5.2 inventory has no not-derivable positioning row — the D56 " +
			"enrollment-flow row is expected as recorded positioning")
	}
}

// TestNoWriteScopeAtReadLevel restates the §13 invariant directly against the
// parsed inventory: no `*:write` permission may appear at read level. This is the
// "no write scope exists at read level" half of the claim, checked structurally.
func TestNoWriteScopeAtReadLevel(t *testing.T) {
	inv, err := InventoryFromDoc16()
	if err != nil {
		t.Fatalf("parsing the §5.2 inventory: %v", err)
	}
	for _, r := range inv.Rows {
		if r.Level == LevelRead && strings.HasSuffix(r.Permission, ":write") {
			t.Errorf("§5.2 read level carries a write-suffixed permission %q — no write "+
				"scope may exist at read level (doc 16 §13)", r.Permission)
		}
	}
}

// ── The corpus: conforming passes, every violation fails NAMED ──────────────

// corpusExpectation declares, per fixture, the violation classes the check must
// report (empty set = must pass clean). Every fixture on disk MUST be registered
// here; the coverage gate fails closed on any unlisted fixture.
var corpusExpectation = map[string][]ViolationClass{
	"00-conforming.json":            nil,
	"01-above-read-level.json":      {ViolationAboveReadLevel},
	"02-write-on-read-path.json":    {ViolationWriteOnReadPath},
	"03-absent-from-inventory.json": {ViolationAbsentFromInventory},
}

// TestAppInstallReadLevelSubset is the row's executable form: it diffs every
// synthetic fixture manifest against the doc-parsed §5.2 inventory and asserts
// the conforming fixture passes clean while each violation fixture fails with its
// NAMED class. This is the mechanical diff the §13 row describes.
func TestAppInstallReadLevelSubset(t *testing.T) {
	inv, err := InventoryFromDoc16()
	if err != nil {
		t.Fatalf("parsing the §5.2 inventory: %v", err)
	}

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
			got := Diff(m, inv)

			if len(want) == 0 {
				if len(got) != 0 {
					t.Fatalf("CONFORMING fixture %s reported %d violation(s) — the ratified "+
						"read triplet must pass clean:\n%s", name, len(got), render(got))
				}
				return
			}

			// Violation fixture: it must FAIL, and the named classes must match exactly.
			if len(got) == 0 {
				t.Fatalf("VIOLATION fixture %s reported NO violations — the check must "+
					"fail on %v (a silent pass is the regression this row exists to catch)",
					name, want)
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
// new manifest cannot land un-asserted.
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
	// The corpus must cover the conforming control AND all three violation classes
	// at least once, so the check is proven non-vacuous on every shape the row
	// forbids.
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
		ViolationAboveReadLevel, ViolationWriteOnReadPath, ViolationAbsentFromInventory,
	} {
		if !seen[c] {
			t.Errorf("corpus never exercises violation class %q — each of the three "+
				"failure modes the §13 row enumerates must have a named fixture", c)
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
		t.Fatalf("the fixtures dir %s is empty — expected synthetic manifests", FixturesDir())
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

// sortedKeys returns the sorted keys of a string-set for stable messages.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
