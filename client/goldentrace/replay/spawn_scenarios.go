package replay

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/spawnscen"
	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
)

// spawn_scenarios.go — the read-side CONSUMER of the canonical, fixture-derived
// spawn-scenario table, plus the classifier-driven discovery the read-side
// completeness check globs against.
//
// WHY THIS FILE EXISTS (the drift it closes). The read-side spawn assertions
// (spawn_test.go, package replay) and the write-side driver mirror
// (../../wrapper/adapters/claude-code/driver_roundtrip_test.go, package
// claudecode) used to enumerate their spawn scenarios INDEPENDENTLY: the read
// side indexed the spawn cassettes by hand, the write side pinned
// driveInputGoldens/driveGrantGoldens by hand. A spawn fixture added to one
// side was therefore NOT forced onto the other — coverage could silently drift.
// The canonical enumeration both suites consume now has ONE shared home.
//
// WHERE THE TABLE LIVES NOW — one cycle-free leaf, no per-package mirror. The
// two suites live in two DIFFERENT Go packages — `replay` (goldentrace) and
// `claudecode` (the adapter) — and the adapter cannot import goldentrace
// (goldentrace already imports the adapter's `attach` model, and a back-edge
// would cycle). For a long time that meant the table was hand-MIRRORED once per
// package. It no longer is: the pure-DATA table moved to the cycle-free leaf
// `client/goldentrace/spawnscen`, which imports nothing from client/, so BOTH
// `replay` (here) AND the in-package `claudecode` test import the ONE copy. This
// file RE-EXPORTS the leaf's SpawnScenario/SpawnScenarios/NegativeControlFixtures
// so spawn_test.go and external references keep compiling unchanged; the write
// side sources the same leaf. The two suites are still kept honest NOT by the
// shared import alone but by a COMPLETENESS CHECK on EACH side that rediscovers
// the spawn-path fixtures from disk and fails if its coverage is missing any —
// so a spawn fixture added to client/fixtures without covering BOTH sides fails a
// test on the uncovered side, naming the fixture.
//
// WHAT STAYS HERE — the CLASSIFIER-DRIVEN DISCOVERY, which cannot move. Only the
// pure-data table moved to the leaf. DiscoverSpawnFixtures and its helpers
// (cassetteIsSpawnPath, lineHasSpawnBlock) call claudecode.IsSpawnToolUse, so
// moving them into the leaf would make the leaf import the adapter and re-create
// the cycle this leaf exists to avoid. They STAY in this package, on the legal
// goldentrace→adapter edge; the write side keeps its own twins, in-package.
//
// SCOPE — only the TABLE single-sourced, never the CLASSIFIER. The spawn-path
// DISCRIMINATOR is NOT duplicated — it is single-sourced in classify.go's
// exported claudecode.IsSpawnToolUse, which both completeness checks call (this
// file's lineHasSpawnBlock across the legal goldentrace→adapter edge; the write
// side's lineHasSpawnBlockCC directly, in-package). So neither side
// re-implements the name+subagent_type predicate verbatim.
//
// HOW COMPLETENESS DISCOVERS FIXTURES (the glob basis). The check does NOT read
// the canonical table to decide what "should" exist; it GLOBS
// client/fixtures/*.cc-wire.ndjson and classifies each cassette as spawn-path by
// CONTENT: a fixture is spawn-path iff it carries an assistant `tool_use` block
// the adapter would route to registerSpawn. That per-block discriminator is NOT
// re-implemented here — it is the SINGLE exported predicate
// claudecode.IsSpawnToolUse (name ∈ spawnToolNames AND input.subagent_type set;
// a bare Task/TaskCreate without subagent_type is the todo-list tool, not a
// spawn). lineHasSpawnBlock below walks an assistant record's content blocks and
// asks that one helper per block, so the completeness signal cannot drift from
// the routing rule: the same predicate the adapter routes on is the predicate
// discovery keys on. (This is the legal goldentrace→adapter import edge; the
// reverse adapter→goldentrace edge is what would cycle, so the write-side mirror
// in spawn_scenarios_test.go calls IsSpawnToolUse directly, in-package.) Keying
// completeness on the projection's own discriminator means a new spawn cassette
// is discovered the moment it can actually drive a spawn, with zero per-fixture
// annotation.

// SpawnScenario re-exports the canonical leaf type
// (spawnscen.SpawnScenario) so spawn_test.go and external references that name
// replay.SpawnScenario keep compiling. The struct — Fixture join key +
// WantSpawns read-side fact — is defined ONCE, in the cycle-free leaf; this is a
// type alias, not a second definition.
type SpawnScenario = spawnscen.SpawnScenario

// SpawnScenarios re-exports the canonical leaf table (spawnscen.SpawnScenarios)
// at var level, so spawn_test.go drives its subtests from this slice and
// TestSpawnScenarioTableComplete asserts it covers every spawn-path fixture the
// glob discovers — all without changing a single read-side reference. The write
// side (package claudecode) sources the SAME leaf slice; the depth3-nested-spawn
// fixture MUST appear in it (re-asserted by both completeness checks). This is a
// var re-export of the ONE table, not a hand-kept mirror.
var SpawnScenarios = spawnscen.SpawnScenarios

// spawnCassetteSuffix is the cassette extension this non-test file scans. The
// matching test-only constant `cassetteSuffix` (golden_test.go) is unavailable
// to non-test code, so the value is restated here as the single non-test source;
// the two are pinned equal by spawn_test.go's TestSpawnCassetteSuffixAgrees.
const spawnCassetteSuffix = ".cc-wire.ndjson"

// spawnFixtureGlob is the glob the completeness checks expand to discover
// candidate cassettes, relative to the replay package dir. It mirrors the glob
// TestGoldens uses (golden_test.go), so the spawn-completeness check and the
// golden check scan the SAME fixture set.
const spawnFixtureGlob = "../../fixtures/*" + spawnCassetteSuffix

// DiscoverSpawnFixtures globs `dir`'s *.cc-wire.ndjson cassettes and returns the
// sorted base names of those that are spawn-path — i.e. carry an assistant
// tool_use block the adapter would route to registerSpawn, decided by the single
// exported discriminator claudecode.IsSpawnToolUse (no allowlist is re-declared
// in this file: the classifier is single-sourced in classify.go). This is the COMPLETENESS
// BASIS: spawn_test.go's completeness check diffs this disk-derived set against
// the hand-maintained SpawnScenarios table, so a spawn fixture dropped into
// client/fixtures without a table row fails the check by name. It reads only the
// cassette's CONTENT (no provenance annotation, no naming convention), so the
// signal cannot drift from what actually drives a spawn.
//
// It returns the discovered set and any glob/IO/parse errors so the caller can
// fail LOUD rather than silently undercount (a swallowed read error would make
// completeness pass vacuously).
func DiscoverSpawnFixtures(dir string) ([]string, error) {
	cassettes, err := filepath.Glob(filepath.Join(dir, "*"+spawnCassetteSuffix))
	if err != nil {
		return nil, err
	}
	var spawn []string
	for _, path := range cassettes {
		isSpawn, err := cassetteIsSpawnPath(path)
		if err != nil {
			return nil, err
		}
		if isSpawn {
			spawn = append(spawn, strings.TrimSuffix(filepath.Base(path), spawnCassetteSuffix))
		}
	}
	sort.Strings(spawn)
	return spawn, nil
}

// cassetteIsSpawnPath reports whether the NDJSON cassette at `path` carries a
// spawn-trigger tool_use block (the single-sourced claudecode.IsSpawnToolUse
// discriminator). It is the per-file half of DiscoverSpawnFixtures; the write
// side mirrors only the file-walk structure (cassetteIsSpawnPathCC), but both
// sides ask the SAME exported classifier per block.
func cassetteIsSpawnPath(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Cassette lines can be long (full assistant turns); grow the buffer well
	// past bufio's 64 KiB default so a long line is never silently truncated
	// (which would make a spawn block invisible and undercount completeness).
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec map[string]json.RawMessage
		if err := json.Unmarshal(line, &rec); err != nil {
			// Not an object line (or malformed) — not a spawn-bearing assistant
			// record. The golden suite is the authority on well-formedness; here
			// we only skip what we cannot classify, we do not fail the run.
			continue
		}
		if lineHasSpawnBlock(rec) {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// lineHasSpawnBlock reports whether a decoded cassette line is an assistant
// record carrying a spawn-trigger tool_use block. It walks message.content and
// asks the SINGLE exported classifier claudecode.IsSpawnToolUse per block — the
// EXACT predicate classify.go's handleToolUse routes to registerSpawn — so the
// completeness signal and the routing rule are one source, not two verbatim
// copies. (Only the assistant-record framing + content walk live here; the
// discriminator itself does not.)
func lineHasSpawnBlock(rec map[string]json.RawMessage) bool {
	if !rawStringEq(rec["type"], "assistant") {
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
		if claudecode.IsSpawnToolUse(b.Name, b.Input) {
			return true
		}
	}
	return false
}

// rawStringEq reports whether a json.RawMessage decodes to the string `want`.
func rawStringEq(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false
	}
	return s == want
}

// SpawnScenarioFixtures returns the Fixture names in SpawnScenarios as a sorted
// slice — the hand-maintained set the completeness check diffs against the
// disk-discovered set.
func SpawnScenarioFixtures() []string {
	out := make([]string, 0, len(SpawnScenarios))
	for _, s := range SpawnScenarios {
		out = append(out, s.Fixture)
	}
	sort.Strings(out)
	return out
}

// NegativeControlFixtures re-exports the canonical leaf enumeration
// (spawnscen.NegativeControlFixtures) of the spawn-EXCLUSION negative controls —
// the inverse of SpawnScenarios. Where SpawnScenarios names the cassettes that
// MUST classify spawn-path (and therefore MUST acquire coverage on both sides),
// this names the cases that MUST NOT: a bare Task/TaskCreate tool_use with NO
// input.subagent_type is the todo-list tool, not a spawn (P14, classify.go), and
// the whole point of a negative control is to prove that exclusion can never
// silently invert into a spawn.
//
// WHY THIS JOINS THE CANNOT-DRIFT GUARANTEE. The positive table is kept honest by
// the disk walk: a spawn cassette added without covering both sides fails a
// completeness check by name. The negative control needs the SAME bilateral
// discipline pointed the other way: if task-todo-no-subagent ever (a) starts being
// DISCOVERED as a spawn-path fixture, or (b) acquires a drive-golden scenario row,
// the exclusion has silently broken — and that break must fail a test BY NAME on
// each side, not pass vacuously. The name is enumerated ONCE in the cycle-free
// leaf and consumed on both sides; the write side (spawn_scenarios_test.go)
// asserts its re-declared mirror equals the canonical list while keeping it
// honest by the same disk walk.
//
// WHY THE LEAF, NOT A PER-PACKAGE MIRROR (the same uncrossable cycle, now solved).
// This list could not be imported across the goldentrace↔adapter seam any more
// than SpawnScenarios could: the adapter (package claudecode) already has
// goldentrace importing it, so a claudecode→goldentrace edge to read this
// enumeration would cycle. The pure-data list now lives in the cycle-free leaf
// `client/goldentrace/spawnscen` (imports nothing from client/), so both sides
// consume one copy. The CLASSIFIER stays single-sourced in classify.go's
// IsSpawnToolUse, which both the as-is-false and the flips-true-with-subagent_type
// proofs call — so the exclusion both sides assert is one predicate, not two
// verbatim copies.
//
// task-todo-no-subagent is INTENTIONALLY NOT a committed *.cc-wire.ndjson cassette:
// a spawn-EXCLUSION control proves a NON-event, so it must never be discoverable as
// spawn-path. Its bare-Task bytes live in-test (scanned from the same committed
// test bytes on each side), exercised through IsSpawnToolUse directly; committing
// it as a fixture would make the disk walk discover it and defeat the control.
var NegativeControlFixtures = spawnscen.NegativeControlFixtures
