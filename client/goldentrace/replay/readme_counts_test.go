package replay

// readme_counts_test.go — the machine-checkable reconciliation of the
// goldentrace README's two count markers against the actual artifacts they
// describe. The README carries human-readable counts in prose ("20 cassettes",
// "10 drift classes"); prose drifts silently as fixtures and perturbations are
// added. These markers — <!-- CASSETTE-COUNT -->N<!-- /CASSETTE-COUNT --> and
// <!-- DRIFT-CLASS-COUNT -->N<!-- /DRIFT-CLASS-COUNT --> — make those counts
// machine-extractable, and this test fails if EITHER marker disagrees with disk
// reality:
//
//   - CASSETTE-COUNT must equal `ls ../../fixtures/*.cc-wire.ndjson` (the same
//     glob TestGoldens / DiscoverSpawnFixtures / the canary regen scan), so
//     adding or removing a fixture without updating the README trips this test
//     by exact count.
//   - DRIFT-CLASS-COUNT must equal len(perturbations) (the perturbation-drift
//     self-test table in perturbation_test.go), so adding or removing a drift
//     class without updating the README trips this test by exact count.
//
// This is the read-side teeth behind the README's "self-reconciling counts"
// claim: the markers are not documentation that may rot, they are assertions.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const readmePath = "../README.md"

// cassetteCountMarker / driftClassCountMarker extract the integer between a
// named HTML-comment marker pair in the README. The markers are invisible in
// rendered Markdown (HTML comments), so the prose reads naturally while the
// count stays machine-extractable.
var (
	cassetteCountMarker   = regexp.MustCompile(`<!-- CASSETTE-COUNT -->(\d+)<!-- /CASSETTE-COUNT -->`)
	driftClassCountMarker = regexp.MustCompile(`<!-- DRIFT-CLASS-COUNT -->(\d+)<!-- /DRIFT-CLASS-COUNT -->`)
)

// readmeMarkerRegion reads the README and returns the first capture group of the
// single occurrence of marker (the text the marker wraps — an integer for the
// count markers, the enumerated-name region for CASSETTE-NAMES). It is the one
// home of the single-occurrence marker-extraction discipline shared by every
// marker reconciliation in this file: it fails the test by name if the marker is
// absent (the reconciliation is no longer machine-checkable) or appears more than
// once (an ambiguous marker is a doc bug worth a hard failure). The reason string
// is appended to each fatal so a caller can spell out, per marker, what restoring
// the single occurrence protects (the count cannot drift / the names cannot drift).
func readmeMarkerRegion(t *testing.T, marker *regexp.Regexp, label, absentReason string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.FromSlash(readmePath))
	if err != nil {
		t.Fatalf("read README %s: %v", readmePath, err)
	}
	matches := marker.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		t.Fatalf("README %s carries no %s marker (%s) — %s", readmePath, label, marker.String(), absentReason)
	}
	if len(matches) > 1 {
		t.Fatalf("README %s carries %d %s markers — exactly one is required so the checked %s is unambiguous",
			readmePath, len(matches), label, label)
	}
	return matches[0][1]
}

// readmeMarkerCount reads the README and returns the integer captured by the
// single occurrence of marker. It fails the test if the marker is absent or
// appears more than once (an ambiguous marker is a doc bug worth a hard failure),
// delegating that single-occurrence discipline to readmeMarkerRegion.
func readmeMarkerCount(t *testing.T, marker *regexp.Regexp, label string) int {
	t.Helper()
	value := readmeMarkerRegion(t, marker, label,
		"the count is no longer machine-checkable; restore the marker so the prose count cannot silently drift")
	n, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("README %s %s marker value %q is not an integer: %v", readmePath, label, value, err)
	}
	return n
}

// diskCassetteCount globs the committed fixtures the same way TestGoldens does
// and returns the count — the disk reality the CASSETTE-COUNT marker must match.
func diskCassetteCount(t *testing.T) int {
	t.Helper()
	cassettes, err := filepath.Glob(filepath.FromSlash("../../fixtures/*" + cassetteSuffix))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	return len(cassettes)
}

// TestReadmeCassetteCountMatchesDisk pins the README's CASSETTE-COUNT marker
// equal to the number of *.cc-wire.ndjson fixtures on disk. Adding the
// negative-control fixture moved this from 19 to 20; any future add/remove that
// forgets the README trips here by exact count.
func TestReadmeCassetteCountMatchesDisk(t *testing.T) {
	want := diskCassetteCount(t)
	got := readmeMarkerCount(t, cassetteCountMarker, "CASSETTE-COUNT")
	if got != want {
		t.Errorf("README CASSETTE-COUNT marker = %d, but `ls ../../fixtures/*%s` reports %d — "+
			"update the marker in %s (or the fixture set) so the documented count matches disk",
			got, cassetteSuffix, want, readmePath)
	}
}

// TestReadmeDriftClassCountMatchesPerturbations pins the README's
// DRIFT-CLASS-COUNT marker equal to len(perturbations) (the perturbation-drift
// self-test table). The two are wired so a drift class added to
// perturbation_test.go without updating the README — or vice versa — fails here.
// perturbations is the test-package table defined in perturbation_test.go (same
// package, so it is referenced directly).
func TestReadmeDriftClassCountMatchesPerturbations(t *testing.T) {
	want := len(perturbations)
	got := readmeMarkerCount(t, driftClassCountMarker, "DRIFT-CLASS-COUNT")
	if got != want {
		t.Errorf("README DRIFT-CLASS-COUNT marker = %d, but len(perturbations) = %d — "+
			"update the marker in %s (or the perturbations table) so the documented drift-class count matches the suite",
			got, want, readmePath)
	}
}

// The CASSETTE-COUNT marker above pins the *number* of fixtures the README
// enumerates, but the README's replay-suite section also HAND-LISTS the cassette
// names inline (the read-path list and the drive-* family). A count marker cannot
// catch a name that drifts while the count stays put — a fixture renamed, or one
// added while another is removed, leaves the count right and the names wrong. The
// CASSETTE-NAMES marker region and the test below close that: the region wraps the
// enumerated names, and the test asserts SET-EQUALITY between the names written
// there and the actual `../../fixtures/*.cc-wire.ndjson` base names — the same glob
// CASSETTE-COUNT / TestGoldens / DiscoverSpawnFixtures use — failing by name on any
// missing or extra cassette.

// cassetteNamesMarker captures the body between the CASSETTE-NAMES HTML-comment
// markers. Like the count markers it is invisible in rendered Markdown, so the
// enumerated names read as ordinary prose while staying machine-extractable. The
// body is matched non-greedily so a stray second open/close pair is caught as a
// duplicate rather than swallowed.
var cassetteNamesMarker = regexp.MustCompile(`(?s)<!-- CASSETTE-NAMES -->(.*?)<!-- /CASSETTE-NAMES -->`)

// codeSpan captures the text inside a Markdown backtick code-span. Cassette names
// in the marked region are written as code-spans (the README convention), so we
// extract names ONLY from inside code-spans — never from the surrounding prose,
// which would otherwise contribute ordinary English words ("spans", "the",
// "read-path") that happen to fit the base-name grammar.
var codeSpan = regexp.MustCompile("`([^`]+)`")

// fixtureNameToken matches the fixture base-name grammar: lowercase
// alphanumerics in hyphen-separated segments, anchored, so a token must start and
// end on an alphanumeric (e.g. `drive-fid-chat-live-equiv`). This deliberately
// REJECTS the README's glob shorthands — `drive-*` / `drive-fid-*` (contain `*`)
// and the bare `-live-equiv` suffix (leading hyphen) — so only concrete base names
// are extracted, never a wildcard or a fragment. Matching code-span fragments
// against this grammar (rather than parsing prose positions) keeps extraction
// robust to commas, slashes, and line-wraps in the marked region.
var fixtureNameToken = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// readmeCassetteNames reads the README, isolates the single CASSETTE-NAMES marker
// region (failing loudly if the marker pair is absent or duplicated, mirroring
// readmeMarkerCount's single-occurrence discipline), and returns the set of
// cassette base names enumerated inside it. Names inside the region are written as
// backtick code-spans; each code-span body is split on slashes and whitespace
// (the `a` / `b` pair notation), and every fragment matching fixtureNameToken is
// collected — so commas, line-wraps, and the pair notation do not defeat
// extraction, while prose words (outside code-spans) and the glob shorthands
// (`drive-*`, `-live-equiv`, inside code-spans but failing the grammar) are
// excluded.
func readmeCassetteNames(t *testing.T) map[string]bool {
	t.Helper()
	region := readmeMarkerRegion(t, cassetteNamesMarker, "CASSETTE-NAMES",
		"the enumerated cassette names are no longer machine-checkable against ../../fixtures/; "+
			"restore the marker pair around the name list so the names cannot silently drift from disk")
	names := map[string]bool{}
	for _, span := range codeSpan.FindAllStringSubmatch(region, -1) {
		// A code-span may hold a single name or a `a` / `b` pair; split on the
		// slash and any whitespace, then grammar-filter each fragment.
		for _, frag := range strings.FieldsFunc(span[1], func(r rune) bool {
			return r == '/' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			if fixtureNameToken.MatchString(frag) {
				names[frag] = true
			}
		}
	}
	if len(names) == 0 {
		t.Fatalf("README %s CASSETTE-NAMES region matched no cassette names — the marked region "+
			"has no backtick code-spans fitting the base-name grammar; the region must enumerate "+
			"the ../../fixtures/ base names as code-spans", readmePath)
	}
	return names
}

// diskCassetteNames globs the committed fixtures the same way diskCassetteCount /
// TestGoldens do and returns their base names (suffix trimmed) — the disk reality
// the CASSETTE-NAMES region must match exactly.
func diskCassetteNames(t *testing.T) map[string]bool {
	t.Helper()
	cassettes, err := filepath.Glob(filepath.FromSlash("../../fixtures/*" + cassetteSuffix))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	names := map[string]bool{}
	for _, c := range cassettes {
		names[strings.TrimSuffix(filepath.Base(c), cassetteSuffix)] = true
	}
	return names
}

// sortedKeys (stable, readable key listing for a string set) is the
// same-package helper defined in spawn_test.go; reused here for failure output.

// TestReadmeCassetteNamesMatchDisk asserts SET-EQUALITY between the cassette names
// the README enumerates in its CASSETTE-NAMES region and the
// `../../fixtures/*.cc-wire.ndjson` base names on disk. It is the name-level
// complement to TestReadmeCassetteCountMatchesDisk: the count marker catches a
// changed *number* of fixtures, this catches a changed *name* set even when the
// count is unmoved (a rename, or a simultaneous add+remove). Failures name the
// exact offending cassette(s):
//
//   - a fixture on disk not enumerated in the region → "missing from README",
//   - a name enumerated in the region with no fixture on disk → "extra in README".
//
// It reads the SAME glob as CASSETTE-COUNT, so the two checks can never disagree
// about which fixture set is canonical.
func TestReadmeCassetteNamesMatchDisk(t *testing.T) {
	readme := readmeCassetteNames(t)
	disk := diskCassetteNames(t)

	var missing []string // on disk, absent from the README region
	for name := range disk {
		if !readme[name] {
			missing = append(missing, name)
		}
	}
	var extra []string // named in the README region, absent from disk
	for name := range readme {
		if !disk[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("fixtures on disk not named in the README CASSETTE-NAMES region: %v — add each to "+
			"the marked names list in %s (or remove the fixture); the region must enumerate every "+
			"../../fixtures/*%s base name", missing, readmePath, cassetteSuffix)
	}
	if len(extra) > 0 {
		t.Errorf("names in the README CASSETTE-NAMES region with no matching fixture on disk: %v — "+
			"remove each from the marked list in %s (or add the fixture); every region-named cassette "+
			"must exist under ../../fixtures/", extra, readmePath)
	}
	if len(missing) == 0 && len(extra) == 0 && len(readme) != len(disk) {
		// Defensive: set-equality held element-wise but cardinalities differ — only
		// possible via a bug above; surface it rather than pass vacuously.
		t.Errorf("README CASSETTE-NAMES region and disk agree element-wise but differ in size "+
			"(README %d: %v, disk %d: %v)", len(readme), sortedKeys(readme), len(disk), sortedKeys(disk))
	}
}

// The three reconciliations above all pin the README markers against the *input*
// side — the `../../fixtures/*.cc-wire.ndjson` cassettes. But every cassette is
// replayed against a committed golden under `testdata/*.attach.ndjson`, and
// `TestGoldens` pairs the two by base name (`base+goldenSuffix`) one cassette at a
// time. A half-add — a fixture committed without its golden, or a golden left
// behind after its fixture was removed — only surfaces inside that per-cassette
// loop (a missing-golden subtest, or simply an unvisited stale golden that no test
// names at all). The two tests below close that as a named set-level reconciliation
// of the input and output corpora, and pin the disk-name grammar both globs must
// obey for the CASSETTE-NAMES extraction to even see a name.

// diskGoldenNames globs the committed goldens under testdata/ the same way
// TestGoldens resolves them (base+goldenSuffix) and returns their base names
// (suffix trimmed) — the output-side corpus the input-side fixtures must match.
func diskGoldenNames(t *testing.T) map[string]bool {
	t.Helper()
	goldens, err := filepath.Glob(filepath.FromSlash("testdata/*" + goldenSuffix))
	if err != nil {
		t.Fatalf("glob goldens: %v", err)
	}
	names := map[string]bool{}
	for _, g := range goldens {
		names[strings.TrimSuffix(filepath.Base(g), goldenSuffix)] = true
	}
	return names
}

// TestReplayFixturesAndGoldensReconcile asserts SET-EQUALITY between the replay
// suite's INPUT corpus (`../../fixtures/*.cc-wire.ndjson` base names, the same glob
// CASSETTE-COUNT / CASSETTE-NAMES / TestGoldens read) and its OUTPUT corpus
// (`testdata/*.attach.ndjson` base names, the goldens TestGoldens pairs each
// cassette against). The two are wired one-to-one by base name, so a fixture
// without its golden — or a golden orphaned by a removed fixture — is a half-add
// the per-cassette TestGoldens loop reports late (a missing-golden subtest) or not
// at all (an unvisited stale golden). This names each offender as a set mismatch:
//
//   - a cassette on disk with no matching golden → "missing golden",
//   - a golden on disk with no matching cassette → "stale golden".
//
// Currently 20/20, so it passes as-is and trips by name on the next half-add.
func TestReplayFixturesAndGoldensReconcile(t *testing.T) {
	fixtures := diskCassetteNames(t)
	goldens := diskGoldenNames(t)

	var missingGolden []string // cassette on disk, no matching golden
	for name := range fixtures {
		if !goldens[name] {
			missingGolden = append(missingGolden, name)
		}
	}
	var staleGolden []string // golden on disk, no matching cassette
	for name := range goldens {
		if !fixtures[name] {
			staleGolden = append(staleGolden, name)
		}
	}
	sort.Strings(missingGolden)
	sort.Strings(staleGolden)

	if len(missingGolden) > 0 {
		t.Errorf("cassettes with no golden (missing golden): %v — regenerate with "+
			"`go test ./goldentrace/replay -run TestGoldens -update` (review the diff) so every "+
			"../../fixtures/*%s cassette has its testdata/*%s golden, or remove the fixture",
			missingGolden, cassetteSuffix, goldenSuffix)
	}
	if len(staleGolden) > 0 {
		t.Errorf("goldens with no cassette (stale golden): %v — delete each from testdata/ (or "+
			"restore the fixture under ../../fixtures/); every testdata/*%s golden must back a "+
			"../../fixtures/*%s cassette", staleGolden, goldenSuffix, cassetteSuffix)
	}
	if len(missingGolden) == 0 && len(staleGolden) == 0 && len(fixtures) != len(goldens) {
		// Defensive: element-wise equal but cardinalities differ — only a bug above
		// could produce this; surface it rather than pass vacuously (mirrors the
		// CASSETTE-NAMES reconciliation's size guard).
		t.Errorf("fixtures and goldens agree element-wise but differ in size "+
			"(fixtures %d: %v, goldens %d: %v)",
			len(fixtures), sortedKeys(fixtures), len(goldens), sortedKeys(goldens))
	}
}

// TestDiskCassetteNamesMatchGrammar asserts that every base name on disk — across
// BOTH the input fixtures glob (`../../fixtures/*.cc-wire.ndjson`) and the output
// goldens glob (`testdata/*.attach.ndjson`) — matches fixtureNameToken, the
// lowercase-hyphenated grammar (^[a-z0-9]+(?:-[a-z0-9]+)*$) the CASSETTE-NAMES
// extraction filters region code-spans through. An out-of-grammar base name (an
// uppercase letter, an underscore, a leading/trailing hyphen) is INVISIBLE to that
// extraction: it could never be matched in the README region, so
// TestReadmeCassetteNamesMatchDisk would later report it as a confusing
// "missing from README" set mismatch instead of the real cause — the name itself
// is unrepresentable in the marker idiom. This pins the grammar at the source so
// such a name fails here, by named cause, the moment it lands on disk.
func TestDiskCassetteNamesMatchGrammar(t *testing.T) {
	corpora := []struct {
		label string
		names map[string]bool
	}{
		{"../../fixtures/*" + cassetteSuffix, diskCassetteNames(t)},
		{"testdata/*" + goldenSuffix, diskGoldenNames(t)},
	}
	for _, corpus := range corpora {
		var offenders []string
		for name := range corpus.names {
			if !fixtureNameToken.MatchString(name) {
				offenders = append(offenders, name)
			}
		}
		sort.Strings(offenders)
		if len(offenders) > 0 {
			t.Errorf("disk base names under %s that violate the fixtureNameToken grammar (%s): %v — "+
				"each is INVISIBLE to the README CASSETTE-NAMES extraction (it can never appear as a "+
				"grammar-matching code-span in the marked region), so it would surface as a confusing "+
				"set mismatch in TestReadmeCassetteNamesMatchDisk rather than a named cause; rename it to "+
				"lowercase hyphen-separated segments", corpus.label, fixtureNameToken.String(), offenders)
		}
	}
}
