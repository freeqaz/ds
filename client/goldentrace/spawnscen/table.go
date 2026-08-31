// Package spawnscen is the single canonical home for the spawn-scenario
// ENUMERATION — the pure-data fixture table both the read side (package replay,
// goldentrace) and the write side (the in-package claudecode driver test) drive
// their spawn coverage from. It is a CYCLE-FREE LEAF: it imports NOTHING from
// client/ (in fact nothing at all beyond what a bare data table needs), so BOTH
// replay AND the claudecode test can import it without re-creating the
// goldentrace↔adapter import cycle that forced the table to be hand-mirrored
// once per package before this package existed.
//
// WHAT LIVES HERE — ONLY the pure-data table. The canonical SpawnScenario
// enumeration (the Fixture join key + the shared facts each side agrees on) and
// the NegativeControlFixtures list. Nothing else.
//
// WHAT MUST NOT LIVE HERE — and why. The spawn DISCRIMINATOR
// (claudecode.IsSpawnToolUse) and every classifier-driven discovery helper that
// calls it — DiscoverSpawnFixtures, cassetteIsSpawnPath, lineHasSpawnBlock and
// their write-side twins — MUST STAY per-side. Moving them here would make this
// leaf import client/wrapper/adapters/claude-code, and goldentrace already
// imports that adapter, so the back-edge would cycle (the exact cycle this leaf
// exists to avoid). The classifier itself is already single-sourced in
// classify.go (IsSpawnToolUse); it does not belong here either. And no fixture
// BYTES live here — this is the table that NAMES the fixtures, not a copy of
// them; the cassettes stay under client/fixtures/ and the negative-control bytes
// stay in-test on each side.
//
// HONESTY GUARANTEE (unchanged by the move). The table is not trusted to decide
// what fixtures "should" exist: each side runs a COMPLETENESS CHECK
// (TestSpawnScenarioTableComplete read / TestSpawnScenarioTableMirrorsDisk
// write) that re-globs client/fixtures, classifies each cassette by content
// through the single-sourced IsSpawnToolUse, and fails BY NAME if this table is
// missing (or carries a stale) spawn-path fixture. Both witnesses survive the
// move to this shared home; this package only retires the SECOND hand-kept copy
// of the table, not the disk-vs-table checks that keep it honest.
package spawnscen

// SpawnScenario names one spawn-path cassette and the read-side facts the
// completeness machinery needs. The per-node structural assertions
// (parent/confidence/lifecycle) stay in spawn_test.go where they already live —
// this table is the ENUMERATION both sides must agree on, not a re-encoding of
// every assertion. Adding a spawn cassette means adding a row HERE (the single
// canonical home) and, on each side, a drive/projection golden that covers it;
// omitting either fails that side's completeness check by name.
type SpawnScenario struct {
	// Fixture is the cassette base name (client/fixtures/<Fixture>.cc-wire.ndjson),
	// the join key both packages consume.
	Fixture string
	// WantSpawns is the number of subagent.spawned events the read side expects
	// from this cassette's projection. subagent-spawn is the missed-lifecycle
	// case (0 spawned, accounting-only); the rest emit one spawned per node.
	WantSpawns int
}

// SpawnScenarios is THE canonical spawn-scenario table — the single source both
// sides consume. The read side (package replay) re-exports this slice as
// replay.SpawnScenarios and TestSpawnScenarioTableComplete asserts it covers
// every spawn-path fixture the glob discovers; the write side (package
// claudecode) sources the same Fixture set and TestSpawnScenarioTableMirrorsDisk
// asserts the same against disk. The depth3-nested-spawn fixture MUST appear
// here — it is an acceptance pin both completeness checks re-assert.
var SpawnScenarios = []SpawnScenario{
	// The legacy smoke cassette: the system/task_* lifecycle is ABSENT, so the
	// spawn join never finalizes and NO subagent.spawned is emitted — only the
	// accounting trailer survives (the "accounting-only" branch).
	{Fixture: "subagent-spawn", WantSpawns: 0},
	// Depth-2 chain: outer spawns inner; both nodes spawn (full lifecycle).
	{Fixture: "nested-spawn", WantSpawns: 2},
	// One turn fans out three rooted siblings (alpha/bravo/charlie).
	{Fixture: "parallel-fanout", WantSpawns: 3},
	// Depth-3 chain (root → outer → middle → grand): drives the depth-≥3
	// "inferred" parent-confidence branch no depth-≤2 fixture reaches.
	{Fixture: "depth3-nested-spawn", WantSpawns: 3},
}

// NegativeControlFixtures is the canonical enumeration of the spawn-EXCLUSION
// negative controls — the inverse of SpawnScenarios. Where SpawnScenarios names
// the cassettes that MUST classify spawn-path (and therefore MUST acquire
// coverage on both sides), this names the cases that MUST NOT: a bare
// Task/TaskCreate tool_use with NO input.subagent_type is the todo-list tool,
// not a spawn (P14, classify.go), and the whole point of a negative control is
// to prove that exclusion can never silently invert into a spawn.
//
// Like SpawnScenarios, this is pure DATA living in the cycle-free leaf so both
// sides consume one copy. The honesty is unchanged: each side's negative-control
// test proves the named control is NOT among the disk-discovered spawn-path
// fixtures and carries no drive-golden coverage, with the classifier
// (IsSpawnToolUse) single-sourced in classify.go.
//
// task-todo-no-subagent IS a committed *.cc-wire.ndjson cassette (a Task tool_use
// with NO input.subagent_type). Its guarantee is CONTENT-BASED, not file-absence:
// the disk walk globs the file, but because IsSpawnToolUse classifies a bare Task
// without subagent_type as the todo-list tool (P14), the cassette is never
// classified spawn-path and so never enters the discovered spawn set. Each side
// ALSO pins the same bare-Task bytes in-test and scans them through IsSpawnToolUse
// directly, proving subagent_type is the sole field that would flip the exclusion —
// the proof of the NON-event therefore rests on the classifier, not on the file
// being absent.
var NegativeControlFixtures = []string{
	// A bare Task tool_use with no input.subagent_type — the todo-list tool, the
	// SOLE non-spawn case among the Task-family names. Must never round-trip as a
	// spawn on either the read (projection) or write (driver) side.
	"task-todo-no-subagent",
}
