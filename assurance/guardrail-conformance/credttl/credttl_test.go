// SPDX-License-Identifier: Apache-2.0

package credttl

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The synthetic validation fence and horizons every inline test asserts against.
// Obviously-synthetic, well inside a plausible range so the ± offsets are
// unambiguous; mirrors the identity-validate seam's synthNow fence convention.
const (
	nowFence   = int64(1_700_000_000)
	farFuture  = nowFence + 3600 // fresh, the wider horizon
	nearFuture = nowFence + 600  // fresh, the tighter horizon (wins the min)
	pastFence  = nowFence - 600  // expired
)

// ── The tag anchor: the single-sourced guardrail tag must not silently drift ─

// TestTagStable pins the single-sourced guardrail tag to the value the
// guardrail-map.yaml glob and doc.go REGISTRATION name. A rename that desyncs the
// map from the package fails HERE.
func TestTagStable(t *testing.T) {
	if Tag != "identity-inject-class-ttl-bound" {
		t.Fatalf("Tag = %q, want identity-inject-class-ttl-bound (doc.go REGISTRATION / guardrail-map.yaml)", Tag)
	}
}

// ── The boundary + intersection semantics (stated directly, no fixture) ─────

// TestFenceBoundaryIsInclusiveLapse restates the boundary directly: a horizon
// EXACTLY at the fence is EXPIRED (the inclusive-lapse `ttl <= now` boundary
// refimpl.go uses), and one instant past it is FRESH.
func TestFenceBoundaryIsInclusiveLapse(t *testing.T) {
	p := Policy{NowUnixSeconds: nowFence}

	atFence := Presentation{Name: "synthetic-boundary", TokenTTLUnixSeconds: nowFence, GrantTTLUnixSeconds: farFuture}
	got := Check(atFence, p)
	if len(got) != 1 || got[0].Class != ViolationTokenExpired {
		t.Fatalf("a token TTL exactly at the fence must be TOKEN-EXPIRED (inclusive lapse), got:\n%s", render(got))
	}

	oneInstantFresh := Presentation{Name: "synthetic-boundary", TokenTTLUnixSeconds: nowFence + 1, GrantTTLUnixSeconds: farFuture}
	if got := Check(oneInstantFresh, p); len(got) != 0 {
		t.Fatalf("a token TTL one second past the fence must be FRESH, got:\n%s", render(got))
	}
}

// TestGrantWinsTheMin is the symmetric grant-wins-the-min corner: a FRESH token
// (far-future) over a FRESH but TIGHTER grant (near-future) conforms, and the
// earned ALLOW horizon is the GRANT's near horizon — the grant wins the min
// (doc 16 §5.1, doc 19 §8). This is the leg the identity-validate token-wins
// coverage does not pin.
func TestGrantWinsTheMin(t *testing.T) {
	p := Policy{NowUnixSeconds: nowFence}
	pres := Presentation{Name: "synthetic-grant-wins", TokenTTLUnixSeconds: farFuture, GrantTTLUnixSeconds: nearFuture}

	if got := Check(pres, p); len(got) != 0 {
		t.Fatalf("both horizons fresh must conform, got:\n%s", render(got))
	}
	if got := AllowHorizon(pres); got != nearFuture {
		t.Fatalf("grant-wins-the-min: AllowHorizon = %d, want the TIGHTER grant horizon %d", got, nearFuture)
	}
	if got := HorizonWinner(pres); got != "grant" {
		t.Fatalf("grant-wins-the-min: HorizonWinner = %q, want \"grant\"", got)
	}
}

// TestTokenWinsTheMin is the complementary corner (the leg identity-validate
// already pins, restated here so the package proves BOTH ends of the
// intersection): a FRESH but TIGHTER token (near-future) over a FRESH grant
// (far-future) conforms, and the ALLOW horizon is the TOKEN's near horizon.
func TestTokenWinsTheMin(t *testing.T) {
	p := Policy{NowUnixSeconds: nowFence}
	pres := Presentation{Name: "synthetic-token-wins", TokenTTLUnixSeconds: nearFuture, GrantTTLUnixSeconds: farFuture}

	if got := Check(pres, p); len(got) != 0 {
		t.Fatalf("both horizons fresh must conform, got:\n%s", render(got))
	}
	if got := AllowHorizon(pres); got != nearFuture {
		t.Fatalf("token-wins-the-min: AllowHorizon = %d, want the TIGHTER token horizon %d", got, nearFuture)
	}
	if got := HorizonWinner(pres); got != "token" {
		t.Fatalf("token-wins-the-min: HorizonWinner = %q, want \"token\"", got)
	}
}

// TestEqualHorizonsCoincide pins the degenerate corner: when the two horizons are
// identical neither strictly wins, so HorizonWinner reports "equal" and
// AllowHorizon returns the shared value — the min is well-defined regardless.
func TestEqualHorizonsCoincide(t *testing.T) {
	p := Policy{NowUnixSeconds: nowFence}
	pres := Presentation{Name: "synthetic-equal", TokenTTLUnixSeconds: farFuture, GrantTTLUnixSeconds: farFuture}
	if got := Check(pres, p); len(got) != 0 {
		t.Fatalf("both horizons fresh must conform, got:\n%s", render(got))
	}
	if got := AllowHorizon(pres); got != farFuture {
		t.Fatalf("equal horizons: AllowHorizon = %d, want %d", got, farFuture)
	}
	if got := HorizonWinner(pres); got != "equal" {
		t.Fatalf("equal horizons: HorizonWinner = %q, want \"equal\"", got)
	}
}

// TestBothLegsExpireIndependently proves the two legs are INDEPENDENT: a
// presentation whose token AND grant are both stale reports BOTH named
// violations (the diff does not short-circuit after the first failing leg).
func TestBothLegsExpireIndependently(t *testing.T) {
	p := Policy{NowUnixSeconds: nowFence}
	pres := Presentation{Name: "synthetic-both-stale", TokenTTLUnixSeconds: pastFence, GrantTTLUnixSeconds: pastFence}
	got := Check(pres, p)
	if !hasClass(got, ViolationTokenExpired) || !hasClass(got, ViolationGrantExpired) {
		t.Fatalf("both legs stale must report BOTH TokenExpired AND GrantExpired, got:\n%s", render(got))
	}
}

// ── The corpus: conforming passes, every violation fails NAMED ──────────────

// corpusExpectation declares, per fixture, the violation classes the check must
// report (empty set = must pass clean). Every fixture on disk MUST be registered
// here; the coverage gate fails closed on any unlisted fixture.
var corpusExpectation = map[string][]ViolationClass{
	"00-conforming-grant-wins.json": nil,
	"01-token-expired.json":         {ViolationTokenExpired},
	"02-grant-expired.json":         {ViolationGrantExpired},
	"03-undecidable.json":           {ViolationUndecidableTTL},
}

// TestCredTTLBound is the row's executable form: it diffs every synthetic
// presentation against its validation policy and asserts the conforming fixture
// passes clean while each violation fixture fails with its NAMED class. This is
// the mechanical TTL diff the row describes.
func TestCredTTLBound(t *testing.T) {
	for _, name := range listFixtures(t) {
		want, ok := corpusExpectation[name]
		if !ok {
			continue // coverage gate (below) owns the fail-closed message
		}
		t.Run(name, func(t *testing.T) {
			f, err := Load(filepath.Join(FixturesDir(), name))
			if err != nil {
				t.Fatalf("loading fixture %s: %v", name, err)
			}
			got := Check(f.Presentation, f.Policy)

			if len(want) == 0 {
				if len(got) != 0 {
					t.Fatalf("CONFORMING fixture %s reported %d violation(s) — both horizons fresh "+
						"must pass clean:\n%s", name, len(got), render(got))
				}
				// A conforming fixture also earns a well-defined ALLOW horizon.
				if h := AllowHorizon(f.Presentation); h <= f.Policy.NowUnixSeconds {
					t.Fatalf("CONFORMING fixture %s earned a non-fresh ALLOW horizon %d (fence %d)",
						name, h, f.Policy.NowUnixSeconds)
				}
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

// TestCorpusCoverage is the fail-closed coverage gate: every fixture on disk must
// be registered in corpusExpectation, and every registered key must exist on
// disk. A fixture added to fixtures/ without an expectation row fails HERE, so a
// new presentation cannot land un-asserted. The corpus must also cover the
// conforming control AND all three TTL failure modes at least once.
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
		ViolationTokenExpired, ViolationGrantExpired, ViolationUndecidableTTL,
	} {
		if !seen[c] {
			t.Errorf("corpus never exercises violation class %q — each of the three TTL failure "+
				"modes the row enumerates must have a named fixture", c)
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
		t.Fatalf("the fixtures dir %s is empty — expected synthetic TTL presentations", FixturesDir())
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
