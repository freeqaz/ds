// SPDX-License-Identifier: Apache-2.0

package injectdigest

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Synthetic service ids every inline test asserts against. Obviously-synthetic
// so no reader mistakes them for a real registry row.
const (
	issuedService = "github"       // the ISSUED{service_id} the digest is issued to
	wrongService  = "evil.example" // a destination the digest is NOT issued to
	otherService  = "gitlab"       // a second wrong destination
)

// ── The tag anchor: the single-sourced guardrail tag must not silently drift ─

// TestTagStable pins the single-sourced guardrail tag to the value the
// guardrail-map.yaml glob and doc.go REGISTRATION name. A rename that desyncs the
// map from the package fails HERE (the per-package twin of
// check-guardrail-map-tags.sh).
func TestTagStable(t *testing.T) {
	if Tag != "identity-inject-class-wrong-destination-blocked" {
		t.Fatalf("Tag = %q, want identity-inject-class-wrong-destination-blocked (doc.go REGISTRATION / guardrail-map.yaml)", Tag)
	}
}

// ── The block semantics (stated directly, no fixture) ───────────────────────

// TestWrongDestinationMustBeBlocked is the headline: an ISSUED{service_id} digest
// presented to a destination it is NOT issued to must be blocked. A blocked
// wrong-destination attempt conforms; the SAME attempt UNBLOCKED is the regression
// this row exists to catch, and it must be reported as WrongDestinationEgressed.
func TestWrongDestinationMustBeBlocked(t *testing.T) {
	blocked := Picture{Presentations: []Presentation{
		{Name: "synthetic-wrong-blocked", IssuedServiceID: issuedService, EgressDestination: wrongService, Blocked: true},
	}}
	if got := Check(blocked); len(got) != 0 {
		t.Fatalf("a wrong-destination egress that WAS blocked must conform, got:\n%s", render(got))
	}

	leaked := Picture{Presentations: []Presentation{
		{Name: "synthetic-wrong-leaked", IssuedServiceID: issuedService, EgressDestination: wrongService, Blocked: false},
	}}
	got := Check(leaked)
	if len(got) != 1 || got[0].Class != ViolationWrongDestinationEgressed {
		t.Fatalf("a wrong-destination egress that was NOT blocked must be WrongDestinationEgressed "+
			"(the block regressing to a silent pass is exactly what this row catches), got:\n%s", render(got))
	}
}

// TestIntendedDestinationMustPass is the complementary corner: an ISSUED digest
// presented to its OWN intended service must NOT be blocked (it fires exactly once
// and passes, doc 16 §10). Not-blocked conforms; blocked is
// IntendedDestinationBlocked.
func TestIntendedDestinationMustPass(t *testing.T) {
	passes := Picture{Presentations: []Presentation{
		{Name: "synthetic-intended-passes", IssuedServiceID: issuedService, EgressDestination: issuedService, Blocked: false},
	}}
	if got := Check(passes); len(got) != 0 {
		t.Fatalf("an intended-destination egress that was NOT blocked must conform, got:\n%s", render(got))
	}

	falselyBlocked := Picture{Presentations: []Presentation{
		{Name: "synthetic-intended-blocked", IssuedServiceID: issuedService, EgressDestination: issuedService, Blocked: true},
	}}
	got := Check(falselyBlocked)
	if len(got) != 1 || got[0].Class != ViolationIntendedDestinationBlocked {
		t.Fatalf("an intended-destination egress that WAS blocked must be IntendedDestinationBlocked, got:\n%s", render(got))
	}
}

// TestUndecidableDestination pins the undecidable corner: a presentation with a
// blank issued service (or blank destination) names no destination fence, so the
// verdict is UNDECIDABLE — a breach, never masked as a routine pass.
func TestUndecidableDestination(t *testing.T) {
	for _, pr := range []Presentation{
		{Name: "synthetic-no-issued", IssuedServiceID: "", EgressDestination: wrongService, Blocked: false},
		{Name: "synthetic-no-dest", IssuedServiceID: issuedService, EgressDestination: "", Blocked: true},
	} {
		got := Check(Picture{Presentations: []Presentation{pr}})
		if len(got) != 1 || got[0].Class != ViolationUndecidableDestination {
			t.Fatalf("presentation %s must be UNDECIDABLE (no destination fence), got:\n%s", pr.Name, render(got))
		}
	}
}

// TestLegsAreIndependent proves the diff never short-circuits: a picture with a
// wrong-destination leak, a falsely-blocked intended egress, and an undecidable
// attempt reports ALL THREE named classes at once.
func TestLegsAreIndependent(t *testing.T) {
	pic := Picture{Presentations: []Presentation{
		{Name: "leak", IssuedServiceID: issuedService, EgressDestination: wrongService, Blocked: false},
		{Name: "false-block", IssuedServiceID: issuedService, EgressDestination: issuedService, Blocked: true},
		{Name: "undecidable", IssuedServiceID: "", EgressDestination: otherService, Blocked: false},
	}}
	got := Check(pic)
	if !hasClass(got, ViolationWrongDestinationEgressed) ||
		!hasClass(got, ViolationIntendedDestinationBlocked) ||
		!hasClass(got, ViolationUndecidableDestination) {
		t.Fatalf("all three failing attempts must be reported independently, got:\n%s", render(got))
	}
}

// ── The corpus: conforming passes, every violation fails NAMED ──────────────

// corpusExpectation declares, per fixture, the violation classes the check must
// report (empty set = must pass clean). Every fixture on disk MUST be registered
// here; the coverage gate fails closed on any unlisted fixture.
var corpusExpectation = map[string][]ViolationClass{
	"00-conforming.json":                   nil,
	"01-wrong-destination-egressed.json":   {ViolationWrongDestinationEgressed},
	"02-intended-destination-blocked.json": {ViolationIntendedDestinationBlocked},
	"03-undecidable.json":                  {ViolationUndecidableDestination},
}

// TestInjectDigestBound is the row's executable form: it diffs every synthetic
// egress picture and asserts the conforming fixture passes clean while each
// violation fixture fails with its NAMED class. This is the mechanical
// destination diff the row describes.
func TestInjectDigestBound(t *testing.T) {
	for _, name := range listFixtures(t) {
		want, ok := corpusExpectation[name]
		if !ok {
			continue // coverage gate (below) owns the fail-closed message
		}
		t.Run(name, func(t *testing.T) {
			p, err := Load(filepath.Join(FixturesDir(), name))
			if err != nil {
				t.Fatalf("loading fixture %s: %v", name, err)
			}
			got := Check(p)

			if len(want) == 0 {
				if len(got) != 0 {
					t.Fatalf("CONFORMING fixture %s reported %d violation(s) — a blocked wrong "+
						"destination and a passing intended destination must pass clean:\n%s",
						name, len(got), render(got))
				}
				// The conforming control must actually EXERCISE both dispositions:
				// at least one wrong-destination-blocked and one intended-passes.
				assertConformingControlExercisesBoth(t, name, p)
				return
			}

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

// assertConformingControlExercisesBoth checks the green control is not vacuous:
// it must carry BOTH a wrong-destination egress that was blocked AND an
// intended-destination egress that passed (the acceptance's "wrong-destination
// digest egress-blocked, matching destination passes" in one picture).
func assertConformingControlExercisesBoth(t *testing.T, name string, p Picture) {
	t.Helper()
	var wrongBlocked, intendedPassed bool
	for _, pr := range p.Presentations {
		if pr.IssuedServiceID == "" || pr.EgressDestination == "" {
			continue
		}
		switch {
		case pr.EgressDestination != pr.IssuedServiceID && pr.Blocked:
			wrongBlocked = true
		case pr.EgressDestination == pr.IssuedServiceID && !pr.Blocked:
			intendedPassed = true
		}
	}
	if !wrongBlocked {
		t.Errorf("CONFORMING fixture %s never exercises a wrong-destination egress that WAS blocked — "+
			"the green control must prove the wrong-destination block holds", name)
	}
	if !intendedPassed {
		t.Errorf("CONFORMING fixture %s never exercises an intended-destination egress that PASSED — "+
			"the green control must prove the matching destination passes", name)
	}
}

// TestCorpusCoverage is the fail-closed coverage gate: every fixture on disk must
// be registered in corpusExpectation, and every registered key must exist on
// disk. A fixture added to fixtures/ without an expectation row fails HERE, so a
// new presentation cannot land un-asserted. The corpus must also cover the
// conforming control AND all three failure modes at least once.
func TestCorpusCoverage(t *testing.T) {
	onDisk := listFixtures(t)
	onDiskSet := map[string]bool{}
	for _, n := range onDisk {
		onDiskSet[n] = true
		if _, ok := corpusExpectation[n]; !ok {
			t.Errorf("fixture %s has NO expectation row — every fixture must be wired into "+
				"corpusExpectation (fail-closed: a new presentation cannot land un-asserted)", n)
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
		ViolationWrongDestinationEgressed, ViolationIntendedDestinationBlocked, ViolationUndecidableDestination,
	} {
		if !seen[c] {
			t.Errorf("corpus never exercises violation class %q — each of the three failure modes the "+
				"row enumerates must have a named fixture", c)
		}
	}
}

// TestEveryFixtureHasProvenance enforces the D50 sidecar contract: every *.json
// fixture on disk must carry a committed <name>.provenance sidecar beside it, so
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

// listFixtures returns the sorted *.json fixture filenames on disk (the
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
		t.Fatalf("the fixtures dir %s is empty — expected synthetic ISSUED-digest egress pictures", FixturesDir())
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

// hasClass reports whether the diff contains a violation of the given class.
func hasClass(vs []Violation, c ViolationClass) bool {
	for _, v := range vs {
		if v.Class == c {
			return true
		}
	}
	return false
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
