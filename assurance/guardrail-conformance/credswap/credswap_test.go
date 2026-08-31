// SPDX-License-Identifier: Apache-2.0

package credswap

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── The corpus: conforming passes, every violation fails NAMED ──────────────

// corpusExpectation declares, per fixture, the violation classes the check must
// report (empty set = must pass clean). Every fixture on disk MUST be registered
// here; the coverage gate fails closed on any unlisted fixture.
var corpusExpectation = map[string][]ViolationClass{
	"00-conforming.json":   nil,
	"01-leak-in-vm.json":   {ViolationSwapLeakOnSurface},
	"02-inject-class.json": {ViolationInjectTTLUnbounded, ViolationInjectDigestMissing},
}

// TestCredSwapNeverLeaks is the row's executable form: it scans every synthetic
// credential picture and asserts the conforming fixture passes clean while each
// violation fixture fails with its NAMED class set. This is the mechanical
// surface-vs-class diff the row describes.
func TestCredSwapNeverLeaks(t *testing.T) {
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
					t.Fatalf("CONFORMING fixture %s reported %d violation(s) — every swap-class "+
						"long-lived secret must be absent from all five surfaces and every inject-class "+
						"credential must carry a positive TTL + ISSUED digest:\n%s",
						name, len(got), render(got))
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

// TestSwapLeakNamesTheSurface is the negative control's sharp edge: the
// swap-class leak fixture must fail with the leak class AND name the exact
// surface the secret appeared on, so a regressed/absent swap (long-lived
// credential present inside the VM) is caught with a surface-named verdict, not
// a silent pass.
func TestSwapLeakNamesTheSurface(t *testing.T) {
	p, err := Load(filepath.Join(FixturesDir(), "01-leak-in-vm.json"))
	if err != nil {
		t.Fatalf("loading 01-leak-in-vm.json: %v", err)
	}
	got := Check(p)
	if len(got) == 0 {
		t.Fatal("the swap-class leak fixture reported NO violations — a long-lived credential " +
			"planted on an in-VM surface must FAIL (this is the regression the row catches)")
	}
	var sawSurface bool
	for _, v := range got {
		if v.Class == ViolationSwapLeakOnSurface {
			if v.Surface == "" {
				t.Errorf("swap-leak violation for %s names no surface — the verdict must say WHERE "+
					"the long-lived credential appeared", v.Credential)
			}
			sawSurface = true
		}
	}
	if !sawSurface {
		t.Fatalf("expected a %s violation, got:\n%s", ViolationSwapLeakOnSurface, render(got))
	}
}

// TestInjectClassInVMPresenceIsNotABreach pins the deliberately-weaker split
// claim (doc 20 §7.3): an inject-class credential present inside the VM by
// design — but carrying a positive TTL and an ISSUED digest — is CONFORMING.
// Only a missing TTL bound or a missing ISSUED digest trips the twin. This
// proves the row does not over-claim by treating inject-class like swap-class.
func TestInjectClassInVMPresenceIsNotABreach(t *testing.T) {
	p := Picture{
		Name: "synthetic-inject-conforming",
		Credentials: []Credential{{
			Name:                "aws-sts-session",
			Class:               ClassInject,
			LongLivedOnSurfaces: []Surface{SurfaceEnv, SurfaceDisk}, // by design, irrelevant for inject
			TTLSeconds:          900,
			IssuedDigest:        "ISSUED{aws}:hmac-sha256:abc123",
		}},
	}
	if got := Check(p); len(got) != 0 {
		t.Fatalf("an inject-class credential present in the VM by design with a positive TTL + "+
			"ISSUED digest must be CONFORMING (doc 20 §7.3 keeps the claim split), got:\n%s", render(got))
	}
}

// TestSwapClassAbsenceProvenOnEverySurface restates the claim's breadth: a
// swap-class long-lived secret on EACH enumerated surface, taken one at a time,
// fails — so the row covers the full doc 06 §3c surface list (disk, env, CoW
// delta, agent-readable response, metal host), not a subset.
func TestSwapClassAbsenceProvenOnEverySurface(t *testing.T) {
	for _, s := range EnumeratedSurfaces() {
		s := s
		t.Run(string(s), func(t *testing.T) {
			p := Picture{
				Name: "synthetic-single-surface",
				Credentials: []Credential{{
					Name:                "github-pat",
					Class:               ClassSwap,
					LongLivedOnSurfaces: []Surface{s},
				}},
			}
			got := Check(p)
			if len(got) != 1 || got[0].Class != ViolationSwapLeakOnSurface || got[0].Surface != s {
				t.Fatalf("a swap-class long-lived secret on surface %q must fail with a "+
					"surface-named %s violation, got:\n%s", s, ViolationSwapLeakOnSurface, render(got))
			}
		})
	}
}

// TestCorpusCoverage is the fail-closed coverage gate: every fixture on disk
// must be registered in corpusExpectation, every registered key must exist on
// disk, and the corpus must cover the conforming control plus all three named
// violation classes at least once.
func TestCorpusCoverage(t *testing.T) {
	onDisk := listFixtures(t)
	onDiskSet := map[string]bool{}
	for _, n := range onDisk {
		onDiskSet[n] = true
		if _, ok := corpusExpectation[n]; !ok {
			t.Errorf("fixture %s has NO expectation row — every fixture must be wired into "+
				"corpusExpectation (fail-closed: a new picture cannot land un-asserted)", n)
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
	for _, c := range []ViolationClass{
		ViolationSwapLeakOnSurface, ViolationInjectTTLUnbounded, ViolationInjectDigestMissing,
	} {
		if !seen[c] {
			t.Errorf("corpus never exercises violation class %q — each named failure mode must have "+
				"a fixture", c)
		}
	}
}

// TestEveryFixtureHasProvenance enforces the D50 sidecar contract: every *.json
// picture on disk must carry a committed <name>.provenance sidecar beside it.
func TestEveryFixtureHasProvenance(t *testing.T) {
	for _, name := range listFixtures(t) {
		sidecar := filepath.Join(FixturesDir(), name+".provenance")
		if _, err := os.Stat(sidecar); err != nil {
			t.Errorf("fixture %s has no .provenance sidecar (%s) — every D50 synthetic fixture must "+
				"carry one", name, filepath.Base(sidecar))
		}
	}
}

// TestTagStable pins the single-sourced guardrail tag so a rename is a conscious
// edit, keeping the package metadata and any future guardrail-map row in lockstep.
func TestTagStable(t *testing.T) {
	if Tag != "cred-swap-never-leaks" {
		t.Fatalf("Tag = %q, want cred-swap-never-leaks (doc.go REGISTRATION; the map row must match)", Tag)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// listFixtures returns the sorted *.json picture filenames on disk (the
// .provenance sidecars are excluded). Anchored via FixturesDir (runtime.Caller).
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
		t.Fatalf("the fixtures dir %s is empty — expected synthetic credential pictures", FixturesDir())
	}
	sort.Strings(names)
	return names
}

// classesOf collects the (sorted, deduped) violation classes a check reported.
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

// sameClasses reports whether the check's class set equals want exactly.
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
