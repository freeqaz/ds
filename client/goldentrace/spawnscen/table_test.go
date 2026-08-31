// table_test.go — the leaf's OWN self-validation, in-package and stdlib-only.
//
// WHY THIS EXISTS. spawnscen is the single canonical home for the spawn-scenario
// ENUMERATION (table.go), consumed by both the read side (package replay) and the
// write side (the in-package claudecode driver test). Those downstream completeness
// checks discover fixtures from disk and diff against this table — but they cannot
// catch a table that is internally malformed at the SOURCE (a duplicate Fixture key, a
// negative WantSpawns, a negative control that has drifted INTO the positive set, the
// depth-3 acceptance pin dropped). A malformed edit here should fail IN-PACKAGE, where
// the data lives, not only downstream. These invariants are the leaf's own teeth; they
// re-assert (never weaken) the structural facts the table's doc comments promise, and
// every failure NAMES the offending row so the break is actionable at the source.
package spawnscen

import "testing"

// TestSpawnScenariosKeysNonEmptyUnique pins that every SpawnScenario carries a
// non-empty Fixture join key and that no two rows share one — a duplicate or blank key
// would silently collapse two scenarios into one (or join nothing) downstream.
func TestSpawnScenariosKeysNonEmptyUnique(t *testing.T) {
	if len(SpawnScenarios) == 0 {
		t.Fatal("SpawnScenarios is empty — the canonical spawn-scenario table has no rows")
	}
	seen := map[string]int{}
	for i, s := range SpawnScenarios {
		if s.Fixture == "" {
			t.Errorf("SpawnScenarios[%d] has an empty Fixture key — every row must name a cassette base name", i)
			continue
		}
		if prev, dup := seen[s.Fixture]; dup {
			t.Errorf("SpawnScenarios[%d] Fixture %q duplicates SpawnScenarios[%d] — the join key must be unique", i, s.Fixture, prev)
			continue
		}
		seen[s.Fixture] = i
	}
}

// TestSpawnScenariosWantSpawnsNonNegative pins that no row declares a negative
// expected-spawn count. WantSpawns is a count of subagent.spawned events (0 for the
// accounting-only case, ≥1 otherwise); a negative value is a corrupt row.
func TestSpawnScenariosWantSpawnsNonNegative(t *testing.T) {
	for i, s := range SpawnScenarios {
		if s.WantSpawns < 0 {
			t.Errorf("SpawnScenarios[%d] (Fixture %q) has WantSpawns=%d — the expected spawn count must be >= 0", i, s.Fixture, s.WantSpawns)
		}
	}
}

// TestNegativeControlFixturesNonEmptyUniqueDisjoint pins that the negative-control
// enumeration is non-empty and unique, and — the load-bearing invariant — DISJOINT
// from the positive SpawnScenarios fixture set. A name appearing in BOTH tables is a
// silent inversion of the exclusion: the same fixture would be asserted to MUST and
// MUST-NOT classify spawn-path. Catching it here names the offending control.
func TestNegativeControlFixturesNonEmptyUniqueDisjoint(t *testing.T) {
	if len(NegativeControlFixtures) == 0 {
		t.Fatal("NegativeControlFixtures is empty — the spawn-EXCLUSION negative control has no entries")
	}

	positive := map[string]bool{}
	for _, s := range SpawnScenarios {
		positive[s.Fixture] = true
	}

	seen := map[string]int{}
	for i, nc := range NegativeControlFixtures {
		if nc == "" {
			t.Errorf("NegativeControlFixtures[%d] is an empty name — every negative control must name a case", i)
			continue
		}
		if prev, dup := seen[nc]; dup {
			t.Errorf("NegativeControlFixtures[%d] %q duplicates NegativeControlFixtures[%d] — the negative-control list must be unique", i, nc, prev)
			continue
		}
		seen[nc] = i
		if positive[nc] {
			t.Errorf("NegativeControlFixtures[%d] %q also appears in SpawnScenarios — a spawn-EXCLUSION control must be DISJOINT from the positive spawn table; the exclusion has inverted", i, nc)
		}
	}
}

// TestDepth3NestedSpawnPinPresent pins the depth3-nested-spawn acceptance fixture in
// SpawnScenarios. It is the only fixture that drives the depth-≥3 "inferred"
// parent-confidence branch (table.go), so both completeness checks re-assert it; this
// leaf-level pin fails at the SOURCE if it is ever dropped from the table.
func TestDepth3NestedSpawnPinPresent(t *testing.T) {
	const pin = "depth3-nested-spawn"
	for _, s := range SpawnScenarios {
		if s.Fixture == pin {
			return
		}
	}
	t.Errorf("acceptance pin %q is missing from SpawnScenarios — the depth-3 nested-spawn fixture must stay enumerated (it is the sole depth-≥3 coverage)", pin)
}
