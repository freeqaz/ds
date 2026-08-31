// SPDX-License-Identifier: Apache-2.0

package suspendbreach

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── The anchor guard: the documented pause budget must not silently drift ────

// TestPauseBudgetMatchesDocumentedTier pins PauseBudgetSeconds to the D46
// fully-transparent tier (5 min = 300s). A drift of the constant fails HERE
// rather than letting the claim assert against a different budget than D46 names.
func TestPauseBudgetMatchesDocumentedTier(t *testing.T) {
	const documentedFullyTransparentSeconds = 5 * 60
	if PauseBudgetSeconds != documentedFullyTransparentSeconds {
		t.Fatalf("PauseBudgetSeconds = %d, want %d (the D46 fully-transparent tier, ≤5 min); a "+
			"budget change must be reconciled with D46", PauseBudgetSeconds, documentedFullyTransparentSeconds)
	}
}

// ── The corpus: conforming passes, every violation fails NAMED ──────────────

var corpusExpectation = map[string][]ViolationClass{
	"00-conforming.json":         nil,
	"01-no-suspend.json":         {ViolationSuspendClassNotSuspended},
	"02-resume-over-budget.json": {ViolationResumeOverBudget},
}

// TestSuspendOnBreachFires is the row's executable form: it diffs every synthetic
// trip picture against the D77/D46 contract and asserts the conforming fixture
// passes clean while each violation fixture fails with its NAMED class set.
func TestSuspendOnBreachFires(t *testing.T) {
	for _, name := range listFixtures(t) {
		want, ok := corpusExpectation[name]
		if !ok {
			continue
		}
		t.Run(name, func(t *testing.T) {
			p, err := Load(filepath.Join(FixturesDir(), name))
			if err != nil {
				t.Fatalf("loading fixture %s: %v", name, err)
			}
			got := Check(p)

			if len(want) == 0 {
				if len(got) != 0 {
					t.Fatalf("CONFORMING fixture %s reported %d violation(s) — every suspend-class trip "+
						"must suspend and resume within budget, every action:block trip must stay in-band "+
						"with a reason + async notify and never suspend:\n%s", name, len(got), render(got))
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("VIOLATION fixture %s reported NO violations — the check must fail on %v "+
					"(a silent pass is the regression this row exists to catch)", name, want)
			}
			if !sameClasses(got, want) {
				t.Fatalf("VIOLATION fixture %s reported the WRONG violation class set —\n"+
					" want: %v\n got: %v\nfull:\n%s", name, want, classesOf(got), render(got))
			}
		})
	}
}

// TestSuspendClassNotSuspendedFailsNamed is the first negative control's sharp
// edge: a suspend-class trip (blocklist / action:suspend) that did NOT suspend
// must fail named — proving the row catches a suspend-on-breach that did not fire.
func TestSuspendClassNotSuspendedFailsNamed(t *testing.T) {
	p, err := Load(filepath.Join(FixturesDir(), "01-no-suspend.json"))
	if err != nil {
		t.Fatalf("loading 01-no-suspend.json: %v", err)
	}
	got := Check(p)
	if !hasClass(got, ViolationSuspendClassNotSuspended) {
		t.Fatalf("a suspend-class trip that did not suspend must fail with %s, got:\n%s",
			ViolationSuspendClassNotSuspended, render(got))
	}
}

// TestResumeOverBudgetFailsNamed is the second negative control's sharp edge: a
// suspend whose resume latency is past the D46 budget must fail named — proving
// the row catches a non-transparent resume.
func TestResumeOverBudgetFailsNamed(t *testing.T) {
	p, err := Load(filepath.Join(FixturesDir(), "02-resume-over-budget.json"))
	if err != nil {
		t.Fatalf("loading 02-resume-over-budget.json: %v", err)
	}
	got := Check(p)
	if !hasClass(got, ViolationResumeOverBudget) {
		t.Fatalf("a resume past the pause budget must fail with %s, got:\n%s",
			ViolationResumeOverBudget, render(got))
	}
}

// TestBlockClassStaysInBand pins the D77 fork's other side: an action:block
// behavioral cap that serves an in-band machine-readable reason + async notify
// and does NOT suspend is CONFORMING — proving the row does not over-claim by
// demanding a suspend on an ordinary policy event.
func TestBlockClassStaysInBand(t *testing.T) {
	p := Picture{
		Name: "synthetic-block-inband",
		Trips: []Trip{{
			Name:         "rate cap exceeded",
			Class:        ClassActionBlock,
			Outcome:      OutcomeInBandError,
			InBandReason: true,
			AsyncNotify:  true,
		}},
	}
	if got := Check(p); len(got) != 0 {
		t.Fatalf("an action:block cap serving an in-band reason + async notify without suspending "+
			"must be CONFORMING (D77 defaults behavioral caps to block), got:\n%s", render(got))
	}
}

// TestBlockClassSuspendedFailsNamed pins violation (c): an action:block trip that
// suspended the VM fails named — D77 reserves suspension for genuine threats.
func TestBlockClassSuspendedFailsNamed(t *testing.T) {
	p := Picture{
		Name: "synthetic-block-suspended",
		Trips: []Trip{{
			Name:         "rate cap exceeded",
			Class:        ClassActionBlock,
			Outcome:      OutcomeSuspended,
			InBandReason: true,
			AsyncNotify:  true,
		}},
	}
	got := Check(p)
	if !hasClass(got, ViolationBlockClassSuspended) {
		t.Fatalf("an action:block trip that suspended the VM must fail with %s, got:\n%s",
			ViolationBlockClassSuspended, render(got))
	}
}

// TestBlockClassNoInBandReasonFailsNamed pins violation (d): an action:block trip
// that served no machine-readable in-band reason fails named (D77 densest-channel
// rule).
func TestBlockClassNoInBandReasonFailsNamed(t *testing.T) {
	p := Picture{
		Name: "synthetic-block-no-reason",
		Trips: []Trip{{
			Name:         "rate cap exceeded",
			Class:        ClassActionBlock,
			Outcome:      OutcomeInBandError,
			InBandReason: false,
			AsyncNotify:  true,
		}},
	}
	got := Check(p)
	if !hasClass(got, ViolationBlockClassNoInBandReason) {
		t.Fatalf("an action:block trip with no in-band reason must fail with %s, got:\n%s",
			ViolationBlockClassNoInBandReason, render(got))
	}
}

// TestResumeAtBudgetIsTransparent restates the boundary semantics: a suspend
// resuming EXACTLY at the budget is transparent (the budget is the maximum
// tolerated latency, not the first over-budget latency), one second past it is
// over budget.
func TestResumeAtBudgetIsTransparent(t *testing.T) {
	atBudget := Picture{
		Name: "synthetic-at-budget",
		Trips: []Trip{{
			Name: "blocklist hit", Class: ClassBlocklist, Outcome: OutcomeSuspended,
			ResumeLatencySeconds: PauseBudgetSeconds,
		}},
	}
	if got := Check(atBudget); len(got) != 0 {
		t.Fatalf("a resume exactly at the %ds budget must be transparent, got:\n%s",
			PauseBudgetSeconds, render(got))
	}
	pastBudget := atBudget
	pastBudget.Trips = []Trip{{
		Name: "blocklist hit", Class: ClassBlocklist, Outcome: OutcomeSuspended,
		ResumeLatencySeconds: PauseBudgetSeconds + 1,
	}}
	got := Check(pastBudget)
	if len(got) != 1 || got[0].Class != ViolationResumeOverBudget {
		t.Fatalf("a resume one second past the %ds budget must fail with %s, got:\n%s",
			PauseBudgetSeconds, ViolationResumeOverBudget, render(got))
	}
}

// TestCorpusCoverage is the fail-closed coverage gate.
func TestCorpusCoverage(t *testing.T) {
	onDisk := listFixtures(t)
	onDiskSet := map[string]bool{}
	for _, n := range onDisk {
		onDiskSet[n] = true
		if _, ok := corpusExpectation[n]; !ok {
			t.Errorf("fixture %s has NO expectation row — every fixture must be wired into "+
				"corpusExpectation (fail-closed)", n)
		}
	}
	for name := range corpusExpectation {
		if !onDiskSet[name] {
			t.Errorf("corpusExpectation lists %s but no such fixture exists on disk", name)
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
	for _, c := range []ViolationClass{ViolationSuspendClassNotSuspended, ViolationResumeOverBudget} {
		if !seen[c] {
			t.Errorf("corpus never exercises violation class %q — both fixture negative controls "+
				"(no-suspend, resume-over-budget) must have a fixture", c)
		}
	}
}

// TestEveryFixtureHasProvenance enforces the D50 sidecar contract.
func TestEveryFixtureHasProvenance(t *testing.T) {
	for _, name := range listFixtures(t) {
		sidecar := filepath.Join(FixturesDir(), name+".provenance")
		if _, err := os.Stat(sidecar); err != nil {
			t.Errorf("fixture %s has no .provenance sidecar (%s) — every D50 synthetic fixture must "+
				"carry one", name, filepath.Base(sidecar))
		}
	}
}

// TestTagStable pins the single-sourced guardrail tag.
func TestTagStable(t *testing.T) {
	if Tag != "suspend-on-breach-fires" {
		t.Fatalf("Tag = %q, want suspend-on-breach-fires (doc.go REGISTRATION)", Tag)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

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
		t.Fatalf("the fixtures dir %s is empty — expected synthetic trip pictures", FixturesDir())
	}
	sort.Strings(names)
	return names
}

func hasClass(vs []Violation, c ViolationClass) bool {
	for _, v := range vs {
		if v.Class == c {
			return true
		}
	}
	return false
}

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

func render(vs []Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("  ")
		b.WriteString(v.String())
		b.WriteString("\n")
	}
	return b.String()
}
