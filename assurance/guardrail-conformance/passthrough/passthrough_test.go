// SPDX-License-Identifier: Apache-2.0

package passthrough

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── The corpus: conforming passes, every violation fails NAMED ──────────────

var corpusExpectation = map[string][]ViolationClass{
	"00-empty-default.json":       nil,
	"01-nonempty-default.json":    {ViolationNonemptyDefault},
	"02-swap-on-passthrough.json": {ViolationSwapOnPassThrough},
}

// TestPassThroughEmptyByDefault is the row's executable form: it diffs every
// synthetic pass-through configuration against the D17/D74 invariant and asserts
// the conforming fixture passes clean while each violation fixture fails with its
// NAMED class set.
func TestPassThroughEmptyByDefault(t *testing.T) {
	for _, name := range listFixtures(t) {
		want, ok := corpusExpectation[name]
		if !ok {
			continue
		}
		t.Run(name, func(t *testing.T) {
			c, err := Load(filepath.Join(FixturesDir(), name))
			if err != nil {
				t.Fatalf("loading fixture %s: %v", name, err)
			}
			got := Check(c)

			if len(want) == 0 {
				if len(got) != 0 {
					t.Fatalf("CONFORMING fixture %s reported %d violation(s) — the default config must "+
						"carry an empty pass-through list, pass-through endpoints must have no swap, and "+
						"non-listed endpoints must be TLS-terminated:\n%s", name, len(got), render(got))
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

// TestNonemptyDefaultFailsNamed is the first negative control's sharp edge: a
// baseline pack shipping a pass-through entry must fail with the named class —
// proving the row catches a regressed empty-by-default invariant (D74).
func TestNonemptyDefaultFailsNamed(t *testing.T) {
	c, err := Load(filepath.Join(FixturesDir(), "01-nonempty-default.json"))
	if err != nil {
		t.Fatalf("loading 01-nonempty-default.json: %v", err)
	}
	got := Check(c)
	if !hasClass(got, ViolationNonemptyDefault) {
		t.Fatalf("a non-empty default pass-through list must fail with %s, got:\n%s",
			ViolationNonemptyDefault, render(got))
	}
}

// TestSwapOnPassThroughFailsNamed is the second negative control's sharp edge: a
// swap performed on a pass-through endpoint must fail with the named class —
// proving the row catches a swap on an opaque tunnel (D17/D74).
func TestSwapOnPassThroughFailsNamed(t *testing.T) {
	c, err := Load(filepath.Join(FixturesDir(), "02-swap-on-passthrough.json"))
	if err != nil {
		t.Fatalf("loading 02-swap-on-passthrough.json: %v", err)
	}
	got := Check(c)
	if !hasClass(got, ViolationSwapOnPassThrough) {
		t.Fatalf("a swap on a pass-through endpoint must fail with %s, got:\n%s",
			ViolationSwapOnPassThrough, render(got))
	}
}

// TestNonDefaultMayCarryEntries pins the invariant's scope: the empty-by-default
// rule binds ONLY the shipped baseline (is_default). An explicitly configured,
// evidence-backed config (is_default=false) MAY carry a pass-through entry — so
// long as that entry is opaque (no swap) and every non-listed endpoint is
// terminated. This proves the row does not over-claim by forbidding all entries.
func TestNonDefaultMayCarryEntries(t *testing.T) {
	c := Config{
		Name:      "synthetic-explicit-config",
		IsDefault: false,
		Endpoints: []Endpoint{
			{Host: "pinned.example.com", PassThrough: true, TLSTerminated: false, SwapPerformed: false},
			{Host: "api.example.com", PassThrough: false, TLSTerminated: true, SwapPerformed: true},
		},
	}
	if got := Check(c); len(got) != 0 {
		t.Fatalf("a non-default evidence-backed config may carry an opaque pass-through entry "+
			"(D74 binds only the baseline), got:\n%s", render(got))
	}
}

// TestUnterminatedNonPassThroughFailsNamed pins violation (c): a non-listed
// endpoint whose flow was not TLS-terminated at the per-session CA fails named —
// everything not pass-through-listed must be terminated (D17).
func TestUnterminatedNonPassThroughFailsNamed(t *testing.T) {
	c := Config{
		Name:      "synthetic-unterminated",
		IsDefault: true,
		Endpoints: []Endpoint{
			{Host: "leaky.example.com", PassThrough: false, TLSTerminated: false, SwapPerformed: false},
		},
	}
	got := Check(c)
	if !hasClass(got, ViolationUnterminatedNonPassThrough) {
		t.Fatalf("a non-listed endpoint not TLS-terminated must fail with %s, got:\n%s",
			ViolationUnterminatedNonPassThrough, render(got))
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
	for _, c := range []ViolationClass{ViolationNonemptyDefault, ViolationSwapOnPassThrough} {
		if !seen[c] {
			t.Errorf("corpus never exercises violation class %q — both negative controls (nonempty "+
				"default, swap-on-pass-through) must have a fixture", c)
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
	if Tag != "pass-through-empty-by-default" {
		t.Fatalf("Tag = %q, want pass-through-empty-by-default (doc.go REGISTRATION)", Tag)
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
		t.Fatalf("the fixtures dir %s is empty — expected synthetic pass-through configs", FixturesDir())
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
