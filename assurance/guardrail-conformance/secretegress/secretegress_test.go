// SPDX-License-Identifier: Apache-2.0

package secretegress

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
	"00-conforming.json":    nil,
	"01-canary-egress.json": {ViolationCanaryEgressedInspected},
}

// TestCanaryNeverEgresses is the row's executable form: it scans every synthetic
// feed + egress picture and asserts the conforming fixture passes clean while
// each violation fixture fails with its NAMED class set.
func TestCanaryNeverEgresses(t *testing.T) {
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
					t.Fatalf("CONFORMING fixture %s reported %d violation(s) — every inspected-path "+
						"canary attempt must be blocked with zero canary bytes in any spool:\n%s",
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

// TestCanaryLeakOnInspectedPathFailsNamed is the negative control's sharp edge:
// a canary that egresses unblocked on an inspected path must fail with the named
// class — proving the row catches a regressed/absent secret-scanning gate.
func TestCanaryLeakOnInspectedPathFailsNamed(t *testing.T) {
	p, err := Load(filepath.Join(FixturesDir(), "01-canary-egress.json"))
	if err != nil {
		t.Fatalf("loading 01-canary-egress.json: %v", err)
	}
	got := Check(p)
	if len(got) == 0 {
		t.Fatal("the canary-egress fixture reported NO violations — a canary leaking unblocked on " +
			"an inspected path must FAIL (this is the regression the row catches)")
	}
	var saw bool
	for _, v := range got {
		if v.Class == ViolationCanaryEgressedInspected {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("expected a %s violation, got:\n%s", ViolationCanaryEgressedInspected, render(got))
	}
}

// TestPassThroughCanaryIsNotAClaimViolation pins non-claim 1 (doc 12 §5.3, doc
// 16 §1): a canary leaving on a TLS-4 pass-through tunnel — no inspection / swap
// / scanning — is NOT flagged for egress. This proves the row carries its stated
// boundary and does not over-claim a pass-through path as inspected.
func TestPassThroughCanaryIsNotAClaimViolation(t *testing.T) {
	p := Picture{
		Name: "synthetic-passthrough",
		Feed: Feed{Canary: "deploy-token-canary", PushedVariants: KnownVariants()},
		Attempts: []Attempt{{
			Dest:          "pinned-client tunnel",
			Path:          PathPassThrough,
			CanaryVariant: VariantRaw,
			Blocked:       false, // pass-through is not inspected; "blocked" is irrelevant
			CanaryInSpool: false,
		}},
	}
	if got := Check(p); len(got) != 0 {
		t.Fatalf("a canary on a TLS-4 pass-through path must NOT be flagged for egress (stated "+
			"non-claim, doc 12 §5.3 / doc 16 §1), got:\n%s", render(got))
	}
}

// TestSpoolLeakBindsEveryPathClass pins the fingerprint-only invariant (D73): the
// canary value in a log/event/spool byte fails on ANY path class — even a blocked
// inspected attempt and even a pass-through attempt — because the logging-plane
// invariant is path-independent.
func TestSpoolLeakBindsEveryPathClass(t *testing.T) {
	for _, path := range []PathClass{PathInspected, PathPassThrough} {
		path := path
		t.Run(string(path), func(t *testing.T) {
			p := Picture{
				Name: "synthetic-spool-leak",
				Feed: Feed{Canary: "deploy-token-canary", PushedVariants: KnownVariants()},
				Attempts: []Attempt{{
					Dest:          "record path",
					Path:          path,
					CanaryVariant: VariantRaw,
					Blocked:       true, // even a blocked attempt must not log the value
					CanaryInSpool: true,
				}},
			}
			got := Check(p)
			var saw bool
			for _, v := range got {
				if v.Class == ViolationCanaryInSpool {
					saw = true
				}
			}
			if !saw {
				t.Fatalf("the canary value in a spool byte must fail with %s on path class %q "+
					"(fingerprint-only, D73), got:\n%s", ViolationCanaryInSpool, path, render(got))
			}
		})
	}
}

// TestEveryPushedVariantIsCaughtOnInspectedPath restates the claim's breadth: a
// canary in EACH pushed variant (raw + BASE64 + URLENC + HEX, doc 14 §7), taken
// one at a time on an inspected path, must be blocked to conform — and is a
// violation if not blocked. This proves the row covers the full variant set.
func TestEveryPushedVariantIsCaughtOnInspectedPath(t *testing.T) {
	for _, variant := range KnownVariants() {
		variant := variant
		t.Run(string(variant), func(t *testing.T) {
			blocked := Picture{
				Name: "synthetic-variant-blocked",
				Feed: Feed{Canary: "deploy-token-canary", PushedVariants: KnownVariants()},
				Attempts: []Attempt{{
					Dest: "allowed-domain body", Path: PathInspected,
					CanaryVariant: variant, Blocked: true,
				}},
			}
			if got := Check(blocked); len(got) != 0 {
				t.Fatalf("a blocked inspected-path canary in variant %q must conform, got:\n%s",
					variant, render(got))
			}
			leaked := blocked
			leaked.Attempts = []Attempt{{
				Dest: "allowed-domain body", Path: PathInspected,
				CanaryVariant: variant, Blocked: false,
			}}
			got := Check(leaked)
			if len(got) != 1 || got[0].Class != ViolationCanaryEgressedInspected {
				t.Fatalf("an unblocked inspected-path canary in variant %q must fail with %s, got:\n%s",
					variant, ViolationCanaryEgressedInspected, render(got))
			}
		})
	}
}

// TestUnknownVariantIsUndecidable pins violation (c): a canary observed in a
// variant the feed never pushed is undecidable and treated as a breach.
func TestUnknownVariantIsUndecidable(t *testing.T) {
	p := Picture{
		Name: "synthetic-unknown-variant",
		Feed: Feed{Canary: "deploy-token-canary", PushedVariants: []Variant{VariantRaw, VariantBase64}},
		Attempts: []Attempt{{
			Dest: "allowed-domain body", Path: PathInspected,
			CanaryVariant: VariantHex, Blocked: true,
		}},
	}
	got := Check(p)
	if len(got) != 1 || got[0].Class != ViolationUnknownVariant {
		t.Fatalf("a canary in a variant the feed never pushed must fail with %s, got:\n%s",
			ViolationUnknownVariant, render(got))
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
	sawConforming := false
	sawEgress := false
	for _, classes := range corpusExpectation {
		if len(classes) == 0 {
			sawConforming = true
		}
		for _, c := range classes {
			if c == ViolationCanaryEgressedInspected {
				sawEgress = true
			}
		}
	}
	if !sawConforming {
		t.Error("corpus has no CONFORMING control fixture — the green case must be proven")
	}
	if !sawEgress {
		t.Errorf("corpus never exercises %q — the core negative control (canary leaks on an "+
			"inspected path) must have a fixture", ViolationCanaryEgressedInspected)
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
	if Tag != "secret-egress-canary-blocked" {
		t.Fatalf("Tag = %q, want secret-egress-canary-blocked (doc.go REGISTRATION)", Tag)
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
		t.Fatalf("the fixtures dir %s is empty — expected synthetic feed + egress pictures", FixturesDir())
	}
	sort.Strings(names)
	return names
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
