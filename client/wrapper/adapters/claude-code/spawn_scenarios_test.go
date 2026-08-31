// spawn_scenarios_test.go — the WRITE-SIDE (package claudecode) CONSUMER of the
// shared spawn-scenario table, plus the write-side completeness check.
//
// THE DRIFT THIS CLOSES (read it with goldentrace/replay/spawn_scenarios.go).
// The read side (package replay) asserts the spawn-tree PROJECTION of the spawn
// cassettes; this package (the driver) asserts the spawn-driving INPUT bytes
// (driveInputGoldens) and ask grants (driveGrantGoldens). The two suites used to
// enumerate their spawn scenarios INDEPENDENTLY, so a spawn fixture added to
// client/fixtures could be covered on one side and silently missed on the other.
// This file is the write-side CONSUMER of the canonical spawn-fixture
// enumeration and the check that forces every spawn-path fixture onto the
// write-side coverage.
//
// WHERE THE TABLE LIVES — one cycle-free leaf, sourced here. The canonical
// spawn-fixture table used to be hand-MIRRORED in this file because this package
// — `claudecode`, the adapter/driver — CANNOT import package `replay`
// (goldentrace already imports this package's `attach` model and the adapter
// itself, so a claudecode→goldentrace edge would cycle). The pure-DATA table now
// lives in the cycle-free leaf `client/goldentrace/spawnscen`, which imports
// nothing from client/, so this package imports it directly — no cycle — and
// derives spawnScenarioFixtures (below) from spawnscen.SpawnScenarios rather than
// re-typing the row literals. The read side (goldentrace/replay/spawn_scenarios.go)
// sources the SAME leaf. The two suites are still kept honest by a COMPLETENESS
// CHECK on EACH side — not by the shared import alone — that rediscovers the
// spawn-path fixtures from disk and fails if its package's coverage is missing
// any. A spawn fixture added without covering BOTH sides fails the uncovered
// side's check, naming the fixture.
//
// HOW COMPLETENESS DISCOVERS FIXTURES (the glob basis, mirrored from the read
// side). Discovery does NOT trust the hand-maintained list to decide what should
// exist; it GLOBS client/fixtures/*.cc-wire.ndjson and classifies each cassette
// as spawn-path by CONTENT: spawn-path iff it carries an assistant tool_use block
// the adapter would route to registerSpawn. The per-block discriminator is NOT
// re-implemented here — this is in-package claudecode, so lineHasSpawnBlockCC
// calls the SAME exported predicate handleToolUse routes on, IsSpawnToolUse
// (classify.go: name ∈ spawnToolNames AND input.subagent_type set). Only the
// glob + assistant-record file walk are mirrored from the read side's
// DiscoverSpawnFixtures (the FIXTURE-TABLE cycle is uncrossable, see the read-side
// file header); the CLASSIFIER is single-sourced, so this side and the read side
// classify identically by construction, not by two verbatim copies. Keying on the
// real spawn signal means a new spawn cassette is discovered the moment it can
// actually drive a spawn — no per-fixture annotation.
package claudecode

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/spawnscen"
)

// ccCassetteSuffix mirrors the read side's cassetteSuffix (golden_test.go). It is
// re-declared here because the constant lives in package replay, which this
// package cannot import (import-cycle, see file header).
const ccCassetteSuffix = ".cc-wire.ndjson"

// ccFixturesDir is client/fixtures relative to this package
// (client/wrapper/adapters/claude-code), the single fixture set both sides scan.
const ccFixturesDir = "../../../fixtures"

// spawnScenarioFixtures is the write-side handle on the canonical spawn-scenario
// table — the Fixture set DERIVED from the one shared leaf table
// (spawnscen.SpawnScenarios), not re-typed as a row literal here. It MUST stay
// equal to the read-side table's fixture set, which it now is by construction:
// both sides read the same spawnscen.SpawnScenarios. TestSpawnScenarioTableMirrorsDisk
// still enforces it against the glob-discovered truth on disk, and the matching
// read-side check enforces it there — so neither side can carry a spawn fixture
// the other lacks. The depth3-nested-spawn fixture appears here (via the leaf)
// AND on the read side (acceptance pin). A package-level var is kept (not an
// inlined call) so driver_roundtrip_test.go's two spawnScenarioFixtures
// references resolve unchanged.
var spawnScenarioFixtures = func() []string {
	out := make([]string, 0, len(spawnscen.SpawnScenarios))
	for _, s := range spawnscen.SpawnScenarios {
		out = append(out, s.Fixture)
	}
	return out
}()

// discoverSpawnFixturesCC globs ccFixturesDir's cassettes and returns the sorted
// base names of those that are spawn-path (an assistant tool_use block the adapter
// would route to registerSpawn, decided by the single-sourced IsSpawnToolUse). It
// mirrors the read side's replay.DiscoverSpawnFixtures glob+walk STRUCTURE, but the
// per-block discriminator is the one exported classify.go predicate, not a verbatim
// copy. It returns errors so a swallowed glob/IO/parse failure cannot make
// completeness pass vacuously.
func discoverSpawnFixturesCC(dir string) ([]string, error) {
	cassettes, err := filepath.Glob(filepath.Join(dir, "*"+ccCassetteSuffix))
	if err != nil {
		return nil, err
	}
	var spawn []string
	for _, path := range cassettes {
		isSpawn, err := cassetteIsSpawnPathCC(path)
		if err != nil {
			return nil, err
		}
		if isSpawn {
			spawn = append(spawn, strings.TrimSuffix(filepath.Base(path), ccCassetteSuffix))
		}
	}
	sort.Strings(spawn)
	return spawn, nil
}

// cassetteIsSpawnPathCC reports whether the NDJSON cassette carries a spawn-
// trigger tool_use block. Verbatim mirror of the read side's cassetteIsSpawnPath.
func cassetteIsSpawnPathCC(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Grow past bufio's 64 KiB default so a long assistant turn line is never
	// silently truncated (which would hide a spawn block and undercount).
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec map[string]json.RawMessage
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if lineHasSpawnBlockCC(rec) {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// lineHasSpawnBlockCC reports whether a decoded cassette line is an assistant
// record carrying a spawn-trigger tool_use block. It walks message.content and
// asks the SINGLE exported classifier IsSpawnToolUse per block — the EXACT
// predicate handleToolUse routes to registerSpawn (in-package, so the call is
// direct, no import-cycle). Only the assistant-record framing + content walk are
// mirrored from the read side's lineHasSpawnBlock; the discriminator itself is
// single-sourced in classify.go, so this no longer re-implements it verbatim.
func lineHasSpawnBlockCC(rec map[string]json.RawMessage) bool {
	if !ccRawStringEq(rec["type"], "assistant") {
		return false
	}
	msgRaw, ok := rec["message"]
	if !ok {
		return false
	}
	var msg struct {
		Content []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(msgRaw, &msg); err != nil {
		return false
	}
	for _, b := range msg.Content {
		if b.Type != "tool_use" {
			continue
		}
		if IsSpawnToolUse(b.Name, b.Input) {
			return true
		}
	}
	return false
}

// ccRawStringEq reports whether a json.RawMessage decodes to the string `want`.
func ccRawStringEq(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false
	}
	return s == want
}

// writeSideSpawnCoverage returns the set of spawn-path fixtures the write-side
// drive goldens actually cover, derived from the `scenario` field of
// driveInputGoldens and driveGrantGoldens. A spawn fixture is "covered" on the
// write side iff at least one drive golden names it as its scenario — i.e. the
// driver pins the bytes that would drive that spawn cassette's turn. ask-control
// is a drive scenario too but is NOT a spawn-path fixture (no spawn tool_use), so
// it never appears in the disk-discovered set and is irrelevant to completeness.
func writeSideSpawnCoverage() map[string]bool {
	covered := map[string]bool{}
	for _, g := range driveInputGoldens {
		covered[g.scenario] = true
	}
	for _, g := range driveGrantGoldens {
		covered[g.scenario] = true
	}
	return covered
}

// TestSpawnScenarioTableMirrorsDisk is the write-side half of the per-package-
// mirror drift guard. It rediscovers the spawn-path fixtures from disk (same glob
// + content discriminator as the read side) and asserts:
//
//  1. the write-side mirror list (spawnScenarioFixtures) equals the disk-discovered
//     set — so the mirror cannot drift from the real fixtures; and
//  2. every disk-discovered spawn-path fixture is COVERED by a write-side drive
//     golden (writeSideSpawnCoverage) — so a spawn fixture added to client/fixtures
//     without a driveInputGoldens/driveGrantGoldens scenario fails HERE by name.
//
// Together with the read side's TestSpawnScenarioTableComplete, this makes adding
// a spawn fixture to client/fixtures without covering BOTH sides fail a test.
func TestSpawnScenarioTableMirrorsDisk(t *testing.T) {
	discovered, err := discoverSpawnFixturesCC(filepath.FromSlash(ccFixturesDir))
	if err != nil {
		t.Fatalf("discover spawn-path fixtures: %v", err)
	}
	if len(discovered) == 0 {
		t.Fatal("discovered no spawn-path fixtures under client/fixtures/ — the glob/discriminator is broken (expected at least the spawn cassettes)")
	}

	discoveredSet := map[string]bool{}
	for _, f := range discovered {
		discoveredSet[f] = true
	}
	mirrorSet := map[string]bool{}
	for _, f := range spawnScenarioFixtures {
		mirrorSet[f] = true
	}

	// (1) Mirror equals disk: every discovered fixture is in the mirror, and the
	// mirror carries no stale entry that disk no longer backs.
	for _, f := range discovered {
		if !mirrorSet[f] {
			t.Errorf("spawn-path fixture %q (client/fixtures/%s%s) is missing from the write-side mirror list spawnScenarioFixtures — add it AND a drive golden covering it",
				f, f, ccCassetteSuffix)
		}
	}
	for _, f := range spawnScenarioFixtures {
		if !discoveredSet[f] {
			t.Errorf("write-side mirror lists %q but no spawn-path fixture on disk backs it (client/fixtures/%s%s missing or no longer a spawn cassette) — remove the stale entry or restore the fixture",
				f, f, ccCassetteSuffix)
		}
	}

	// (2) Every spawn-path fixture is covered by a write-side drive golden, so a
	// new spawn cassette cannot land write-side-uncovered.
	covered := writeSideSpawnCoverage()
	for _, f := range discovered {
		if !covered[f] {
			t.Errorf("spawn-path fixture %q has NO write-side drive coverage — add a driveInputGoldens (or driveGrantGoldens) row with scenario %q so the driver pins the bytes that drive its spawn turn",
				f, f)
		}
	}

	// The depth-3 fixture must be present on both sides (acceptance pin).
	if !mirrorSet["depth3-nested-spawn"] || !covered["depth3-nested-spawn"] {
		t.Errorf("depth3-nested-spawn must be in the write-side mirror AND covered by a drive golden (mirror=%v covered=%v)",
			mirrorSet["depth3-nested-spawn"], covered["depth3-nested-spawn"])
	}
}

// --- WRITE-SIDE NEGATIVE-CONTROL MIRROR -------------------------------------
//
// The per-file MIRROR of the spawn-EXCLUSION control on the driver write side.
// Where spawnScenarioFixtures (above) is the write-side handle on the POSITIVE table
// (spawnscen.SpawnScenarios — the cassettes that MUST classify spawn-path and MUST be
// covered on both sides), the list below is the write-side mirror of the NEGATIVE
// table (spawnscen.NegativeControlFixtures — the bare-Task case that MUST NOT round-
// trip as a spawn from the driver). The canonical DATA enumeration is single-sourced
// in the cycle-free leaf client/goldentrace/spawnscen and imported here directly (the
// same import that backs spawnScenarioFixtures); the per-file mirror below is kept
// equal to it by TestSpawnNegativeControlMirror and kept honest by the disk walk —
// proving the name is not among the discovered spawn-path fixtures and carries no
// drive-golden coverage. The spawn-EXCLUSION rule thereby joins the same cannot-drift
// guarantee the positive table has: a silent inversion (the control starting to
// classify spawn-path, or acquiring a drive-golden row) fails a test BY NAME on each
// side.
//
// What stays per-side is the CLASSIFIER, not the data table: this package cannot
// import the read-side discovery helpers (the claudecode→goldentrace edge cycles), so
// the spawn discriminator is single-sourced in classify.go (IsSpawnToolUse) and called
// in-package on both the as-is-false and the flips-true-with-subagent_type proofs — the
// SAME predicate the read side asserts, not a second copy. The pure-DATA enumeration,
// by contrast, lives in the leaf and is imported, not hand-mirrored a third time.

// writeSideNegativeControlFixtures is the per-file MIRROR of the canonical negative-
// control enumeration (spawnscen.NegativeControlFixtures, imported from the cycle-free
// leaf). It MUST stay equal to that canonical set; TestSpawnNegativeControlMirror
// enforces the equality against the imported leaf and the disk walk keeps it honest
// (the named control must NOT be a discovered spawn-path fixture and must carry no
// drive-golden coverage). It is kept as a separate per-file list — not folded into the
// leaf import — so the mirror<->canonical equality is a real two-source assertion the
// disk walk underwrites, not a tautology.
var writeSideNegativeControlFixtures = []string{
	"task-todo-no-subagent",
}

// taskTodoNoSubagentBlock is the committed in-test bytes of the negative control:
// a bare Task tool_use with NO input.subagent_type — the todo-list tool (P14),
// which classify.go's IsSpawnToolUse excludes from the spawn path. These in-test
// bytes are the SOLE-EXCLUSION proof's input (assertion 2): the same block is scanned
// through the single-sourced IsSpawnToolUse on both the as-is-false and the flips-true
// proofs below, so subagent_type is shown to be the one gating field independent of
// any file. The cassette client/fixtures/task-todo-no-subagent.cc-wire.ndjson is
// itself committed; the control's guarantee is content-based — discoverSpawnFixturesCC
// globs that file but IsSpawnToolUse never classifies it spawn-path (assertion 1) — so
// the non-discovery is a real claim about a real file, not a claim about an absent one.
const taskTodoNoSubagentBlock = `{"type":"tool_use","id":"toolu_SYNTHETIC_TODO000001","name":"Task","input":{"description":"track the steps","todos":[{"content":"step one","status":"pending"}]}}`

// withSubagentType is the SAME bare-Task block with input.subagent_type added — the
// SOLE field whose presence flips the todo-list tool into a subagent spawn (P14).
// Pinned here so the sole-exclusion proof shows the exclusion turns on exactly that
// one field and nothing else: scan the as-is block ⇒ IsSpawnToolUse false; add only
// subagent_type ⇒ IsSpawnToolUse true.
const taskTodoWithSubagentTypeBlock = `{"type":"tool_use","id":"toolu_SYNTHETIC_TODO000001","name":"Task","input":{"description":"track the steps","subagent_type":"worker","todos":[{"content":"step one","status":"pending"}]}}`

// scanBlockIsSpawn decodes a single committed tool_use block (the negative-control
// bytes) and asks the single-sourced IsSpawnToolUse — the EXACT predicate
// handleToolUse routes registerSpawn on. It is the per-block half of
// lineHasSpawnBlockCC reused on an in-test block rather than a fixture line, so the
// sole-exclusion proof keys on the same classifier the disk walk and the adapter do.
func scanBlockIsSpawn(t *testing.T, raw string) bool {
	t.Helper()
	var b struct {
		Type  string          `json:"type"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatalf("decode negative-control block: %v (raw=%s)", err, raw)
	}
	if b.Type != "tool_use" {
		t.Fatalf("negative-control block is %q, want tool_use", b.Type)
	}
	return IsSpawnToolUse(b.Name, b.Input)
}

// TestSpawnNegativeControlMirror is the WRITE-SIDE half of the spawn-EXCLUSION
// negative control — the mirror of the read-side control. It joins the same cannot-
// drift guarantee the positive table has, with four assertions:
//
//  1. NOT DISCOVERED — discoverSpawnFixturesCC (the same glob + content discriminator
//     the positive completeness check uses) must NOT classify task-todo-no-subagent
//     as a spawn-path fixture. The cassette client/fixtures/task-todo-no-subagent.cc-
//     wire.ndjson IS committed (it is a Task tool_use with no input.subagent_type);
//     the guarantee is CONTENT-BASED — discovery globs the file but IsSpawnToolUse
//     never classifies it spawn-path — so a bare-Task case can never enter the
//     discovered spawn set even though the file is on disk.
//  2. SOLE-EXCLUSION GATE — the committed bare-Task bytes have IsSpawnToolUse false
//     as-is, and flip true when (and only when) input.subagent_type is added. This is
//     the in-package proof that subagent_type is the SOLE field gating the spawn path
//     (P14), run identically to the read side because both call the one exported
//     classifier.
//  3. NO DRIVE-GOLDEN COVERAGE — neither spawnScenarioFixtures (the positive mirror)
//     nor writeSideSpawnCoverage (the driveInput/driveGrant scenarios) carries an
//     entry for it: no drive golden ever pins bytes that drive it as a spawn. If a row
//     for it were ever added, the driver would be claiming to drive a spawn from the
//     todo-list tool — caught here by name.
//  4. MIRROR-LIST EQUALITY — the re-declared write-side negative mirror equals the
//     canonical spawnscen.NegativeControlFixtures set (imported from the cycle-free
//     leaf, exactly as spawnScenarioFixtures imports spawnscen.SpawnScenarios), and
//     the disk walk keeps that equality honest (the named control is provably NOT
//     discovered, per assertion 1). Only the CLASSIFIER stays per-side (importing it
//     would cycle); the pure-DATA enumeration is single-sourced in the leaf, so the
//     equality is asserted against the imported canonical list — not a third hand-kept
//     restatement of the name.
func TestSpawnNegativeControlMirror(t *testing.T) {
	if len(writeSideNegativeControlFixtures) == 0 {
		t.Fatal("writeSideNegativeControlFixtures is empty — the write-side negative-control mirror has no entries")
	}

	// (1) NOT DISCOVERED: the named control is not among the disk-discovered
	// spawn-path fixtures. discoverSpawnFixturesCC is the SAME machinery the
	// positive completeness check trusts, so this proves the exclusion against the
	// exact discovery path, not a bespoke one.
	discovered, err := discoverSpawnFixturesCC(filepath.FromSlash(ccFixturesDir))
	if err != nil {
		t.Fatalf("discover spawn-path fixtures: %v", err)
	}
	discoveredSet := map[string]bool{}
	for _, f := range discovered {
		discoveredSet[f] = true
	}
	for _, nc := range writeSideNegativeControlFixtures {
		if discoveredSet[nc] {
			t.Errorf("negative control %q WAS discovered as a spawn-path fixture (client/fixtures/%s%s) — a spawn-EXCLUSION case must never classify spawn-path; the exclusion has inverted",
				nc, nc, ccCassetteSuffix)
		}
	}

	// (2) SOLE-EXCLUSION GATE: the bare-Task bytes are not a spawn as-is, and the
	// SOLE field that flips them to a spawn is input.subagent_type. Run through the
	// single-sourced IsSpawnToolUse — identical to the read-side proof.
	if scanBlockIsSpawn(t, taskTodoNoSubagentBlock) {
		t.Error("bare-Task block (no input.subagent_type) classified as a spawn — IsSpawnToolUse must exclude the todo-list tool (P14); the spawn discriminator has broken")
	}
	if !scanBlockIsSpawn(t, taskTodoWithSubagentTypeBlock) {
		t.Error("the SAME Task block WITH input.subagent_type added did NOT classify as a spawn — subagent_type is the sole field that gates the spawn path (P14); the discriminator no longer keys on it")
	}

	// (3) NO DRIVE-GOLDEN COVERAGE: no write-side mirror entry and no drive-golden
	// scenario names the control. spawnScenarioFixtures is the POSITIVE mirror (a
	// control must never appear there); writeSideSpawnCoverage is the union of
	// driveInputGoldens/driveGrantGoldens scenarios (no drive golden may pin bytes
	// driving it as a spawn).
	positiveMirror := map[string]bool{}
	for _, f := range spawnScenarioFixtures {
		positiveMirror[f] = true
	}
	coverage := writeSideSpawnCoverage()
	for _, nc := range writeSideNegativeControlFixtures {
		if positiveMirror[nc] {
			t.Errorf("negative control %q appears in the POSITIVE spawn mirror spawnScenarioFixtures — an exclusion case must never be enumerated as a spawn fixture",
				nc)
		}
		if coverage[nc] {
			t.Errorf("negative control %q is named by a write-side drive golden (driveInputGoldens/driveGrantGoldens scenario) — no drive golden may pin bytes that drive the todo-list tool as a spawn",
				nc)
		}
	}

	// (4) MIRROR-LIST EQUALITY: the re-declared write-side negative mirror equals the
	// canonical spawnscen.NegativeControlFixtures. The pure-DATA enumeration lives in
	// the cycle-free leaf and is imported here directly (the same import that backs
	// spawnScenarioFixtures); only the CLASSIFIER stays per-side (importing it would
	// cycle, see file header). So equality is asserted against the imported canonical
	// list — not a third hand-kept restatement of the name — and the disk walk
	// (assertion 1) keeps the per-file mirror honest by proving every named control is
	// absent from the discovered spawn set.
	mirrorSet := map[string]bool{}
	for _, f := range writeSideNegativeControlFixtures {
		mirrorSet[f] = true
	}
	canonicalSet := map[string]bool{}
	for _, f := range spawnscen.NegativeControlFixtures {
		canonicalSet[f] = true
	}
	for _, f := range spawnscen.NegativeControlFixtures {
		if !mirrorSet[f] {
			t.Errorf("canonical negative control %q (spawnscen.NegativeControlFixtures) is missing from the write-side mirror writeSideNegativeControlFixtures — the mirror has drifted from the canonical set",
				f)
		}
	}
	for _, f := range writeSideNegativeControlFixtures {
		if !canonicalSet[f] {
			t.Errorf("write-side mirror lists negative control %q not in the canonical spawnscen.NegativeControlFixtures set — remove the stale entry or add it canonically",
				f)
		}
	}
}
