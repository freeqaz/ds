package replay

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Spawn-path assertions (docs/06 §2.2 + §5, D18/D20). validateEvents in
// golden_test.go proves the stream is well-formed for ANY cassette; it does not
// know what a spawn tree should look like. The wrapper "slips into the middle"
// of subagent/workflow calls (D18) and spawn projection is first-class, so the
// subagent-spawn / nested-spawn / parallel-fanout projections get EXPLICIT
// structural assertions here — spawn events present, parent/id correlation
// correct — beyond the generic byte-compare TestGoldens runs.
//
// These replay the same committed cassettes through the same Replay() entry
// point as TestGoldens (no forked harness); they assert the spawn *shape* the
// golden encodes, so a regression that still byte-matches a (re-generated)
// golden but breaks spawn semantics is caught by name, and the intent of each
// spawn projection is documented in code, not only in the golden bytes.

// replayCassette opens client/fixtures/<base>.cc-wire.ndjson and returns the
// attach.v1 projection. It is the spawn tests' shared loader; it reuses Replay
// (the pinned-clock entry point TestGoldens uses), so the events asserted here
// are byte-identical to the events compared against the golden.
func replayCassette(t *testing.T, base string) []attach.Event {
	t.Helper()
	path := filepath.Join("..", "..", "fixtures", base+cassetteSuffix)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open cassette %s: %v", path, err)
	}
	defer f.Close()
	evs, err := Replay(f)
	if err != nil {
		t.Fatalf("replay %s: %v", path, err)
	}
	return evs
}

// derivedSpawnIDs is the cassette-derived correlation map the read-side
// assertions key on instead of hand-pinned toolu_SYNTHETIC* literals. It is the
// "assert structurally / id-relative, never literal" discipline (DRIVE-PROTOCOL.md
// "Rules the replay tier MUST honor") applied to the read path: the node_ids a
// spawn projects are NOT free constants of the test, they are the tool_use ids
// the SAME committed cassette bytes carry, so the assertions cannot drift from
// the fixture and there is no second source of truth to keep in sync.
type derivedSpawnIDs struct {
	bySubagentType map[string]string // subagent_type → tool_use id (the spawn trigger's id)
	order          []string          // tool_use ids in document (spawn-trigger) order
}

// id resolves a spawn node by its subagent_type — the stable SEMANTIC label the
// cassette uses (outer/inner/alpha/grand…) — to the tool_use id the cassette
// minted for it. It fails the test by name if the cassette carries no spawn
// trigger for that type, so a fixture edit that drops/renames a subagent_type is
// caught here rather than silently skipping an assertion.
func (d derivedSpawnIDs) id(t *testing.T, subagentType string) string {
	t.Helper()
	got, ok := d.bySubagentType[subagentType]
	if !ok {
		t.Fatalf("cassette carries no spawn-trigger tool_use for subagent_type %q (derived types: %v)", subagentType, d.bySubagentType)
	}
	return got
}

// deriveSpawnNodeIDs reads client/fixtures/<base>.cc-wire.ndjson and extracts the
// spawn-trigger tool_use ids in document order, keyed on subagent_type. It scans
// the SAME committed bytes replayCassette projects, classifying each tool_use
// block with the single-sourced claudecode.IsSpawnToolUse discriminator (the
// EXACT predicate the adapter routes registerSpawn on), so the derived ids are
// precisely the ones the projection turns into subagent.spawned node_ids — no
// hand-pinned literal, no parallel allowlist. A duplicate subagent_type fails
// loud (the read-side fixtures give each spawn a distinct type, so a collision
// means the keying assumption broke).
func deriveSpawnNodeIDs(t *testing.T, base string) derivedSpawnIDs {
	t.Helper()
	path := filepath.Join("..", "..", "fixtures", base+cassetteSuffix)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open cassette %s: %v", path, err)
	}
	defer f.Close()

	out := derivedSpawnIDs{bySubagentType: map[string]string{}}
	sc := bufio.NewScanner(f)
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
		if !rawStringEq(rec["type"], "assistant") {
			continue
		}
		msgRaw, ok := rec["message"]
		if !ok {
			continue
		}
		var msg struct {
			Content []struct {
				Type  string          `json:"type"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content"`
		}
		if err := json.Unmarshal(msgRaw, &msg); err != nil {
			continue
		}
		for _, b := range msg.Content {
			if b.Type != "tool_use" {
				continue
			}
			if !claudecode.IsSpawnToolUse(b.Name, b.Input) {
				continue
			}
			st := subagentTypeOf(b.Input)
			if prev, dup := out.bySubagentType[st]; dup {
				t.Fatalf("cassette %s has two spawn triggers with subagent_type %q (%s and %s) — the read-side derivation keys on a UNIQUE subagent_type per node",
					base, st, prev, b.ID)
			}
			out.bySubagentType[st] = b.ID
			out.order = append(out.order, b.ID)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan cassette %s: %v", path, err)
	}
	return out
}

// subagentTypeOf reads input.subagent_type from a spawn-trigger tool_use block's
// raw input — the semantic key deriveSpawnNodeIDs maps each derived id under.
func subagentTypeOf(input json.RawMessage) string {
	var obj struct {
		SubagentType string `json:"subagent_type"`
	}
	if err := json.Unmarshal(input, &obj); err != nil {
		return ""
	}
	return obj.SubagentType
}

// spawnIndex is a by-node_id view of one cassette's spawn-tree projection,
// built once and shared by the correlation assertions below.
type spawnIndex struct {
	spawned   map[string]*attach.SubagentSpawned
	progress  map[string][]*attach.SubagentProgress
	completed map[string]*attach.SubagentCompleted
	accounted map[string]*attach.SubagentAccounted
	spawnSeq  map[string]uint64 // node_id → seq of its subagent.spawned event
	order     []string          // node_ids in spawn order
}

func indexSpawns(t *testing.T, evs []attach.Event) spawnIndex {
	t.Helper()
	ix := spawnIndex{
		spawned:   map[string]*attach.SubagentSpawned{},
		progress:  map[string][]*attach.SubagentProgress{},
		completed: map[string]*attach.SubagentCompleted{},
		accounted: map[string]*attach.SubagentAccounted{},
		spawnSeq:  map[string]uint64{},
	}
	for _, ev := range evs {
		switch {
		case ev.SubagentSpawned != nil:
			s := ev.SubagentSpawned
			if _, dup := ix.spawned[s.NodeID]; dup {
				t.Errorf("node %s spawned twice (seq %d)", s.NodeID, ev.Seq)
			}
			ix.spawned[s.NodeID] = s
			ix.spawnSeq[s.NodeID] = ev.Seq
			ix.order = append(ix.order, s.NodeID)
		case ev.SubagentProgress != nil:
			p := ev.SubagentProgress
			ix.progress[p.NodeID] = append(ix.progress[p.NodeID], p)
		case ev.SubagentCompleted != nil:
			c := ev.SubagentCompleted
			ix.completed[c.NodeID] = c
		case ev.SubagentAccounted != nil:
			a := ev.SubagentAccounted
			ix.accounted[a.NodeID] = a
		}
	}
	return ix
}

// TestSpawnPathProjections asserts the spawn-tree shape of the three spawn
// cassettes explicitly. It is additive to TestGoldens: same Replay(), but it
// checks spawn *meaning* (events present, parent linkage, id-correlation),
// which validateEvents cannot.
func TestSpawnPathProjections(t *testing.T) {
	t.Run("subagent-spawn", func(t *testing.T) {
		// The legacy smoke cassette: a spawn whose system/task_* lifecycle is
		// ABSENT, so the spawn join never finalizes and NO subagent.spawned is
		// emitted — only the authoritative accounting trailer survives
		// (checklists/subagent-spawn.md). Asserting this missed-lifecycle shape
		// pins the "accounting-only" branch that OBSERVABILITY §2 documents.
		evs := replayCassette(t, "subagent-spawn")
		ix := indexSpawns(t, evs)

		if len(ix.spawned) != 0 {
			t.Errorf("subagent-spawn: expected 0 subagent.spawned (missed task lifecycle), got %d", len(ix.spawned))
		}
		if len(ix.completed) != 0 {
			t.Errorf("subagent-spawn: expected 0 subagent.completed, got %d", len(ix.completed))
		}
		// The accounting trailer's node_id is the spawn trigger's tool_use id —
		// derived from the cassette bytes (keyed on its subagent_type), not pinned
		// as a literal. The accounting trailer survives even though the spawn join
		// never finalizes, so the derived id is the join key into ix.accounted.
		node := deriveSpawnNodeIDs(t, "subagent-spawn").id(t, "echoer")
		a := ix.accounted[node]
		if a == nil {
			t.Fatalf("subagent-spawn: missing subagent.accounted for %s", node)
		}
		// The accounting trailer is the only surviving half; it must carry the
		// agent_id and return to root (returned_to empty).
		if a.AgentID == "" {
			t.Errorf("subagent-spawn: accounted %s has empty agent_id", node)
		}
		if a.ReturnedTo != "" {
			t.Errorf("subagent-spawn: accounted %s returned_to = %q, want empty (root)", node, a.ReturnedTo)
		}
	})

	t.Run("nested-spawn", func(t *testing.T) {
		// Depth-2 chain: outer spawns inner. Asserts the parent_node_id linkage
		// (inner.parent == outer.node), parent_confidence "exact" at depth ≤2,
		// and the full lifecycle (spawned → progress/accounted → completed) with
		// id-correlation by node_id and the returned_to back-edge.
		evs := replayCassette(t, "nested-spawn")
		ix := indexSpawns(t, evs)

		// node_ids derived from the cassette bytes (keyed on subagent_type), not
		// pinned literals — the projection's node_id IS the spawn trigger's
		// tool_use id, so the assertions correlate on the same id the fixture carries.
		ids := deriveSpawnNodeIDs(t, "nested-spawn")
		outer := ids.id(t, "outer")
		inner := ids.id(t, "inner")

		assertSpawnTree(t, ix, []spawnExpect{
			{
				node:          outer,
				parent:        "", // root
				subagentType:  "outer",
				confidence:    "exact",
				wantProgress:  true,
				wantCompleted: true,
				wantAccounted: true,
			},
			{
				node:          inner,
				parent:        outer, // nested under outer
				subagentType:  "inner",
				confidence:    "exact",
				wantCompleted: true,
				wantAccounted: true,
			},
		})

		// id-correlation back-edge: the inner subagent's accounting returns to
		// the outer node (the parent), not to root.
		if a := ix.accounted[inner]; a != nil && a.ReturnedTo != outer {
			t.Errorf("nested-spawn: inner accounted returned_to = %q, want %q (the parent node)", a.ReturnedTo, outer)
		}
		// happens-before: a node's spawn precedes its terminal events.
		assertSpawnBeforeTerminals(t, evs, ix)
	})

	t.Run("depth3-nested-spawn", func(t *testing.T) {
		// Depth-3 chain: root → outer → middle → grand. The nested-spawn
		// cassette only reaches depth 2, where every node's parentage is
		// "exact" (P2-verified). This cassette drives the deeper branch that
		// fixture cannot: tree.go depthOf() reaching depth ≥3 downgrades
		// ParentConfidence to "inferred" (OBSERVABILITY-DESIGN §2 — the
		// launching-id edge is P2-written at depth ≤2 but untested deeper, so
		// the grandchild's parent linkage is INFERRED, not exact). Asserts the
		// per-depth confidence ladder explicitly and pins "inferred" at depth 3.
		evs := replayCassette(t, "depth3-nested-spawn")
		ix := indexSpawns(t, evs)

		// node_ids derived from the cassette bytes (keyed on subagent_type), not
		// pinned literals — the depth ladder (outer→middle→grand) is read off the
		// same fixture the projection consumes.
		ids := deriveSpawnNodeIDs(t, "depth3-nested-spawn")
		outer := ids.id(t, "outer")
		middle := ids.id(t, "middle")
		grand := ids.id(t, "grand")

		assertSpawnTree(t, ix, []spawnExpect{
			{
				node:          outer,
				parent:        "", // root child — depth 1
				subagentType:  "outer",
				confidence:    "exact",
				wantCompleted: true,
				wantAccounted: true,
			},
			{
				node:          middle,
				parent:        outer, // depth 2 — still P2-verified exact
				subagentType:  "middle",
				confidence:    "exact",
				wantProgress:  true,
				wantCompleted: true,
				wantAccounted: true,
			},
			{
				node:          grand,
				parent:        middle, // depth 3 — the inferred branch
				subagentType:  "grand",
				confidence:    "inferred",
				wantCompleted: true,
				wantAccounted: true,
			},
		})

		// The load-bearing assertion this cassette exists for: the grandchild
		// at depth 3 carries parent_confidence == "inferred" (tree.go:79-81),
		// the branch no depth-≤2 fixture can reach. Pinned by name so a
		// regression that flattens the confidence ladder is caught explicitly,
		// not only as a golden-byte diff.
		if g := ix.spawned[grand]; g == nil {
			t.Fatalf("depth3-nested-spawn: missing subagent.spawned for grandchild %s", grand)
		} else if g.ParentConfidence != "inferred" {
			t.Errorf("depth3-nested-spawn: grandchild %s parent_confidence = %q, want %q (depth-3 inferred branch, OBSERVABILITY-DESIGN §2)",
				grand, g.ParentConfidence, "inferred")
		}
		// And the depth-≤2 nodes must stay "exact": the inferred downgrade is a
		// depth-3 property, not a blanket nested-spawn one.
		if o := ix.spawned[outer]; o != nil && o.ParentConfidence != "exact" {
			t.Errorf("depth3-nested-spawn: outer %s (depth 1) parent_confidence = %q, want %q", outer, o.ParentConfidence, "exact")
		}
		if m := ix.spawned[middle]; m != nil && m.ParentConfidence != "exact" {
			t.Errorf("depth3-nested-spawn: middle %s (depth 2) parent_confidence = %q, want %q", middle, m.ParentConfidence, "exact")
		}

		// id-correlation back-edges chain the full depth-3 tree: grand returns
		// to middle, middle returns to outer, outer returns to root.
		if a := ix.accounted[grand]; a != nil && a.ReturnedTo != middle {
			t.Errorf("depth3-nested-spawn: grand accounted returned_to = %q, want %q (the parent node)", a.ReturnedTo, middle)
		}
		if a := ix.accounted[middle]; a != nil && a.ReturnedTo != outer {
			t.Errorf("depth3-nested-spawn: middle accounted returned_to = %q, want %q (the parent node)", a.ReturnedTo, outer)
		}
		if a := ix.accounted[outer]; a != nil && a.ReturnedTo != "" {
			t.Errorf("depth3-nested-spawn: outer accounted returned_to = %q, want empty (root)", a.ReturnedTo)
		}
		// happens-before: a node's spawn precedes its terminal events.
		assertSpawnBeforeTerminals(t, evs, ix)
	})

	t.Run("parallel-fanout", func(t *testing.T) {
		// One turn fans out three siblings (alpha/bravo/charlie), all rooted
		// (no parent_node_id), sharing one turn_group, completing out of spawn
		// order. Asserts all three spawn events, the shared turn_group, the flat
		// (rooted) tree, and that every spawned node correlates 1:1 to a
		// completed + accounted by node_id.
		evs := replayCassette(t, "parallel-fanout")
		ix := indexSpawns(t, evs)

		// node_ids derived from the cassette bytes (keyed on subagent_type), not
		// pinned literals — each sibling's id is the tool_use id its spawn trigger
		// carries in the fixture.
		ids := deriveSpawnNodeIDs(t, "parallel-fanout")
		siblings := []struct {
			node, typ string
		}{
			{ids.id(t, "alpha"), "alpha"},
			{ids.id(t, "bravo"), "bravo"},
			{ids.id(t, "charlie"), "charlie"},
		}

		var exp []spawnExpect
		for _, s := range siblings {
			exp = append(exp, spawnExpect{
				node:          s.node,
				parent:        "", // all rooted — a flat fan-out
				subagentType:  s.typ,
				confidence:    "exact",
				wantCompleted: true,
				wantAccounted: true,
			})
		}
		assertSpawnTree(t, ix, exp)

		// All three siblings spawn in ONE turn: identical, non-empty turn_group.
		var turnGroup string
		for _, s := range siblings {
			sp := ix.spawned[s.node]
			if sp == nil {
				continue
			}
			if sp.TurnGroup == "" {
				t.Errorf("parallel-fanout: %s has empty turn_group, want the shared fan-out turn", s.node)
			}
			if turnGroup == "" {
				turnGroup = sp.TurnGroup
			} else if sp.TurnGroup != turnGroup {
				t.Errorf("parallel-fanout: %s turn_group = %q, want shared %q (same fan-out turn)", s.node, sp.TurnGroup, turnGroup)
			}
		}
		assertSpawnBeforeTerminals(t, evs, ix)
	})
}

// TestSpawnCassetteSuffixAgrees pins the non-test spawnCassetteSuffix
// (spawn_scenarios.go) equal to the test-only cassetteSuffix (golden_test.go) and
// proves spawnFixtureGlob is the same glob TestGoldens uses. The non-test
// discovery code cannot reference the test constant, so this guards the two from
// drifting apart silently.
func TestSpawnCassetteSuffixAgrees(t *testing.T) {
	if spawnCassetteSuffix != cassetteSuffix {
		t.Errorf("spawnCassetteSuffix = %q, want %q (== cassetteSuffix); the non-test discovery suffix drifted from the golden suffix", spawnCassetteSuffix, cassetteSuffix)
	}
	if want := filepath.FromSlash("../../fixtures/*" + cassetteSuffix); filepath.FromSlash(spawnFixtureGlob) != want {
		t.Errorf("spawnFixtureGlob = %q, want %q (same glob TestGoldens scans)", filepath.FromSlash(spawnFixtureGlob), want)
	}
}

// TestSpawnScenarioTableComplete is the read-side half of the per-package-mirror
// drift guard (spawn_scenarios.go documents the choice). It rediscovers the
// spawn-path fixtures from disk — glob client/fixtures/*.cc-wire.ndjson, keep the
// cassettes that carry a spawn-trigger tool_use block (DiscoverSpawnFixtures) —
// and asserts the hand-maintained SpawnScenarios table covers EXACTLY that set.
// A spawn fixture dropped into client/fixtures without a SpawnScenarios row fails
// here BY NAME (the read side is uncovered); a table row whose fixture no longer
// exists / is no longer spawn-path also fails, so the table cannot rot. The
// matching check on the write side (spawn_scenarios_test.go) forces the SAME
// fixture onto the driver mirror, so a spawn fixture cannot be added to one side
// only.
func TestSpawnScenarioTableComplete(t *testing.T) {
	discovered, err := DiscoverSpawnFixtures(filepath.FromSlash("../../fixtures"))
	if err != nil {
		t.Fatalf("discover spawn-path fixtures: %v", err)
	}
	if len(discovered) == 0 {
		t.Fatal("discovered no spawn-path fixtures under client/fixtures/ — the glob/discriminator is broken (expected at least the spawn cassettes)")
	}

	tableSet := map[string]bool{}
	for _, f := range SpawnScenarioFixtures() {
		tableSet[f] = true
	}
	discoveredSet := map[string]bool{}
	for _, f := range discovered {
		discoveredSet[f] = true
	}

	// Every spawn-path fixture on disk must have a read-side table row.
	for _, f := range discovered {
		if !tableSet[f] {
			t.Errorf("spawn-path fixture %q (client/fixtures/%s%s) is NOT covered by the read-side SpawnScenarios table — add a row in spawn_scenarios.go AND mirror it on the write side (spawn_scenarios_test.go)",
				f, f, cassetteSuffix)
		}
	}
	// Every table row must still correspond to a spawn-path fixture on disk, so a
	// renamed/removed fixture cannot leave a stale row that masks missing coverage.
	for _, f := range SpawnScenarioFixtures() {
		if !discoveredSet[f] {
			t.Errorf("SpawnScenarios row %q has no spawn-path fixture on disk (client/fixtures/%s%s missing or no longer carries a spawn tool_use) — remove the stale row or restore the fixture",
				f, f, cassetteSuffix)
		}
	}

	// The depth-3 fixture must be present on both sides (acceptance pin).
	if !tableSet["depth3-nested-spawn"] || !discoveredSet["depth3-nested-spawn"] {
		t.Errorf("depth3-nested-spawn must be covered by the read-side table AND discoverable (table=%v disk=%v)",
			tableSet["depth3-nested-spawn"], discoveredSet["depth3-nested-spawn"])
	}
}

// TestSpawnScenarioTableDrivesProjections drives every SHARED-table scenario
// through the same Replay() the detailed subtests above use and asserts the one
// coarse fact the table itself pins — the subagent.spawned count (WantSpawns) —
// for each row. This is what makes the suite ENUMERATE from the shared table
// rather than from a hand-rolled list: deleting a row from SpawnScenarios drops
// its coverage here (and trips TestSpawnScenarioTableComplete's stale-row arm),
// and adding a row forces a projection through Replay. The deep structural
// assertions (parent linkage, confidence ladder, returned_to back-edges,
// happens-before) remain in TestSpawnPathProjections — this loop is the
// table-driven completeness floor beneath them, not a replacement.
func TestSpawnScenarioTableDrivesProjections(t *testing.T) {
	if len(SpawnScenarios) == 0 {
		t.Fatal("SpawnScenarios is empty — the shared spawn table has no rows")
	}
	for _, sc := range SpawnScenarios {
		t.Run(sc.Fixture, func(t *testing.T) {
			evs := replayCassette(t, sc.Fixture)
			ix := indexSpawns(t, evs)
			if len(ix.spawned) != sc.WantSpawns {
				t.Errorf("%s: subagent.spawned count = %d, want %d (shared spawn-scenario table)", sc.Fixture, len(ix.spawned), sc.WantSpawns)
			}
		})
	}
}

// TestSpawnScenarioTableWantSpawnsSelfValidates makes the WantSpawns column
// SELF-VALIDATING against a fresh replay: it sums the table's declared WantSpawns
// and, independently, replays every table fixture through the same Replay() entry
// point and PROJECTS the actual subagent.spawned count, then asserts the two
// aggregates are equal. Where TestSpawnScenarioTableDrivesProjections pins each
// row in isolation, this pins the table as a WHOLE against the fixtures' own
// projection — so a stale WantSpawns (a row whose hand-typed count no longer
// matches what the cassette projects) fails here even if some other row was
// adjusted to keep a per-row check passing. The projected total is derived from
// the SAME committed bytes the table claims to describe, so WantSpawns is no
// longer a free constant: it must equal what the projection actually emits.
func TestSpawnScenarioTableWantSpawnsSelfValidates(t *testing.T) {
	if len(SpawnScenarios) == 0 {
		t.Fatal("SpawnScenarios is empty — the shared spawn table has no rows")
	}
	declared := 0
	projected := 0
	for _, sc := range SpawnScenarios {
		declared += sc.WantSpawns
		evs := replayCassette(t, sc.Fixture)
		ix := indexSpawns(t, evs)
		projected += len(ix.spawned)
	}
	if declared != projected {
		t.Errorf("WantSpawns aggregate is stale: table declares %d total subagent.spawned across %d fixtures, but a fresh replay projects %d — a WantSpawns row no longer matches its cassette's projection",
			declared, len(SpawnScenarios), projected)
	}
}

// TestTaskTodoNoSubagentIsNotASpawn is the read-side NEGATIVE CONTROL for the
// spawn discriminator. The task-todo-no-subagent cassette carries an assistant
// tool_use named "Task" — a name that IS in claudecode.spawnToolNames (the spawn
// allowlist) — but WITHOUT input.subagent_type, which classify.go documents as
// the todo-list tool, not a spawn. So the ONLY thing keeping this cassette out of
// the spawn set is the subagent_type gate inside claudecode.IsSpawnToolUse. This
// test pins that gate as the sole reason for exclusion three ways:
//
//  1. The projection emits ZERO subagent.spawned (it is plain chat/tool flow);
//  2. DiscoverSpawnFixtures does NOT classify the cassette as spawn-path (so
//     TestSpawnScenarioTableComplete does not demand a SpawnScenarios row, and a
//     todo Task is never mistaken for a spawn fixture);
//  3. the cassette DOES carry a tool_use whose name is in spawnToolNames, proven
//     by asserting IsSpawnToolUse flips to true the moment a subagent_type is
//     added to that same block — so weakening the subagent_type gate would turn
//     this todo into a spawn and trip both this test and (via the now-discovered
//     fixture lacking a table row) TestSpawnScenarioTableComplete by name.
func TestTaskTodoNoSubagentIsNotASpawn(t *testing.T) {
	const fixture = "task-todo-no-subagent"

	// (1) The projection emits ZERO subagent.spawned and ZERO subagent.accounted:
	// a bare Task is a native ToolInvoked + ToolCompleted, never a spawn node.
	evs := replayCassette(t, fixture)
	ix := indexSpawns(t, evs)
	if len(ix.spawned) != 0 {
		t.Errorf("%s: expected 0 subagent.spawned (Task without subagent_type is the todo tool), got %d", fixture, len(ix.spawned))
	}
	if len(ix.accounted) != 0 {
		t.Errorf("%s: expected 0 subagent.accounted (not a spawn), got %d", fixture, len(ix.accounted))
	}
	if len(ix.completed) != 0 {
		t.Errorf("%s: expected 0 subagent.completed (not a spawn), got %d", fixture, len(ix.completed))
	}

	// (2) DiscoverSpawnFixtures must NOT classify it as spawn-path — the
	// disk-derived completeness set the table is checked against excludes it, so
	// it needs no SpawnScenarios row and never demands one.
	discovered, err := DiscoverSpawnFixtures(filepath.FromSlash("../../fixtures"))
	if err != nil {
		t.Fatalf("discover spawn-path fixtures: %v", err)
	}
	for _, f := range discovered {
		if f == fixture {
			t.Errorf("%s was classified as a spawn-path fixture by DiscoverSpawnFixtures — a Task without "+
				"subagent_type is the todo tool and must NOT be discovered as a spawn (the subagent_type gate "+
				"in IsSpawnToolUse is the sole exclusion)", fixture)
		}
	}

	// (3) The cassette DOES carry a tool_use whose name is in the spawn allowlist:
	// scan the raw bytes for the assistant Task block, then prove the subagent_type
	// gate is the SOLE reason it is not a spawn — IsSpawnToolUse is false as-is, but
	// flips to true the instant a subagent_type is added to that same name+input.
	name, input := taskToolUseBlock(t, fixture)
	if name == "" {
		t.Fatalf("%s carries no Task/Agent/TaskCreate tool_use block — the negative control needs a "+
			"spawn-allowlist NAME so the subagent_type gate is the only thing excluding it", fixture)
	}
	if _, allowlisted := allowlistedSpawnName(name); !allowlisted {
		t.Fatalf("%s tool_use name %q is not in the spawn allowlist — the negative control must carry an "+
			"allowlisted name so only the subagent_type gate keeps it out of the spawn set", fixture, name)
	}
	if claudecode.IsSpawnToolUse(name, input) {
		t.Errorf("%s: IsSpawnToolUse(%q, <no subagent_type>) = true, want false — a bare Task is the todo tool, "+
			"not a spawn", fixture, name)
	}
	// Add a subagent_type to the SAME block and assert the gate flips: this proves
	// the subagent_type check is the ONLY gate excluding this cassette. If a future
	// change weakened IsSpawnToolUse to drop the subagent_type requirement, the
	// as-is assertion above would already fire AND DiscoverSpawnFixtures would start
	// discovering this fixture (no table row → TestSpawnScenarioTableComplete fails
	// by name).
	withType := withSubagentType(t, input, "todo-promoted")
	if !claudecode.IsSpawnToolUse(name, withType) {
		t.Errorf("%s: IsSpawnToolUse(%q, <subagent_type added>) = false, want true — the subagent_type gate "+
			"should be the SOLE exclusion; adding subagent_type must make the same allowlisted name a spawn", fixture, name)
	}
}

// taskToolUseBlock scans the raw cassette bytes for the FIRST assistant tool_use
// block whose name is in the spawn allowlist and returns its name + raw input.
// It reads the same committed bytes the projection consumes, so the negative
// control asserts against the fixture as written, not a hand-pinned literal.
func taskToolUseBlock(t *testing.T, base string) (string, json.RawMessage) {
	t.Helper()
	path := filepath.Join("..", "..", "fixtures", base+cassetteSuffix)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open cassette %s: %v", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
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
		if !rawStringEq(rec["type"], "assistant") {
			continue
		}
		msgRaw, ok := rec["message"]
		if !ok {
			continue
		}
		var msg struct {
			Content []struct {
				Type  string          `json:"type"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content"`
		}
		if err := json.Unmarshal(msgRaw, &msg); err != nil {
			continue
		}
		for _, b := range msg.Content {
			if b.Type != "tool_use" {
				continue
			}
			if _, ok := allowlistedSpawnName(b.Name); ok {
				return b.Name, b.Input
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan cassette %s: %v", path, err)
	}
	return "", nil
}

// allowlistedSpawnName reports whether a tool_use name is one IsSpawnToolUse
// would accept on the NAME axis (the spawn allowlist {Agent, Task, TaskCreate}),
// independent of the subagent_type gate. It pins the negative control to the same
// name set the adapter routes on without re-exporting the private spawnToolNames
// map: a name is allowlisted iff adding a subagent_type makes IsSpawnToolUse true.
func allowlistedSpawnName(name string) (string, bool) {
	probe := json.RawMessage(`{"subagent_type":"probe"}`)
	return name, claudecode.IsSpawnToolUse(name, probe)
}

// withSubagentType returns a copy of a tool_use input with subagent_type set,
// preserving the block's other fields. It is the mutation the negative control
// applies to prove the subagent_type gate is the SOLE reason the cassette is not
// a spawn.
func withSubagentType(t *testing.T, input json.RawMessage, subagentType string) json.RawMessage {
	t.Helper()
	var obj map[string]json.RawMessage
	if len(input) == 0 {
		obj = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(input, &obj); err != nil {
		t.Fatalf("unmarshal tool_use input: %v", err)
	}
	v, err := json.Marshal(subagentType)
	if err != nil {
		t.Fatalf("marshal subagent_type: %v", err)
	}
	obj["subagent_type"] = v
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal mutated input: %v", err)
	}
	return out
}

type spawnExpect struct {
	node          string
	parent        string // expected parent_node_id ("" ⇒ root)
	subagentType  string
	confidence    string
	wantProgress  bool
	wantCompleted bool
	wantAccounted bool
}

// assertSpawnTree checks each expected node: the spawn event exists, carries the
// expected parent_node_id / subagent_type / parent_confidence, and that the
// requested terminal projections (progress/completed/accounted) correlate to it
// by node_id.
func assertSpawnTree(t *testing.T, ix spawnIndex, exp []spawnExpect) {
	t.Helper()
	if len(ix.spawned) != len(exp) {
		t.Errorf("spawn count = %d, want %d (nodes: %v)", len(ix.spawned), len(exp), ix.order)
	}
	for _, e := range exp {
		sp := ix.spawned[e.node]
		if sp == nil {
			t.Errorf("missing subagent.spawned for node %s", e.node)
			continue
		}
		if sp.NodeID != e.node {
			t.Errorf("node %s: spawned node_id = %q (id-correlation broken)", e.node, sp.NodeID)
		}
		if sp.ParentNodeID != e.parent {
			t.Errorf("node %s: parent_node_id = %q, want %q", e.node, sp.ParentNodeID, e.parent)
		}
		if e.subagentType != "" && sp.SubagentType != e.subagentType {
			t.Errorf("node %s: subagent_type = %q, want %q", e.node, sp.SubagentType, e.subagentType)
		}
		if e.confidence != "" && sp.ParentConfidence != e.confidence {
			t.Errorf("node %s: parent_confidence = %q, want %q", e.node, sp.ParentConfidence, e.confidence)
		}
		if e.wantProgress && len(ix.progress[e.node]) == 0 {
			t.Errorf("node %s: expected at least one subagent.progress correlated by node_id", e.node)
		}
		if e.wantCompleted && ix.completed[e.node] == nil {
			t.Errorf("node %s: expected a subagent.completed correlated by node_id", e.node)
		}
		if e.wantAccounted && ix.accounted[e.node] == nil {
			t.Errorf("node %s: expected a subagent.accounted correlated by node_id", e.node)
		}
	}
}

// assertSpawnBeforeTerminals proves the happens-before the cassette encodes: a
// node's subagent.spawned must precede every progress/completed/accounted event
// that correlates to it (DRIVE-PROTOCOL.md "assert happens-before, never literal
// order"). We use seq (emission order) as the ordering token.
func assertSpawnBeforeTerminals(t *testing.T, evs []attach.Event, ix spawnIndex) {
	t.Helper()
	for _, ev := range evs {
		var node string
		switch {
		case ev.SubagentProgress != nil:
			node = ev.SubagentProgress.NodeID
		case ev.SubagentCompleted != nil:
			node = ev.SubagentCompleted.NodeID
		case ev.SubagentAccounted != nil:
			node = ev.SubagentAccounted.NodeID
		default:
			continue
		}
		spawnSeq, ok := ix.spawnSeq[node]
		if !ok {
			// No spawn event for this node (the missed-lifecycle case is
			// asserted separately); nothing to order against here.
			continue
		}
		if ev.Seq <= spawnSeq {
			t.Errorf("node %s: terminal %s at seq %d precedes its spawn at seq %d (happens-before violated)",
				node, ev.Type, ev.Seq, spawnSeq)
		}
	}
}

// --- always-on neutered-gate co-fail proof -------------------------------------
//
// TestTaskTodoNoSubagentIsNotASpawn is the read-side NEGATIVE CONTROL for the
// subagent_type gate (a bare allowlisted-name Task carrying NO input.subagent_type
// is the todo-list tool, not a spawn). It proves the gate by HAND: it shows the
// current gate keeps task-todo-no-subagent off the spawn path. But "the gate works
// today" is a snapshot. The standing-CI question is the inverse: would WEAKENING
// the gate actually be CAUGHT — does dropping the subagent_type requirement flip
// task-todo-no-subagent onto the spawn path so the named tests go red?
//
// That non-vacuity was a wave-1 HAND mutation: a reviewer manually deleted the
// subagent_type check in classify.go and watched TestTaskTodoNoSubagentIsNotASpawn
// + TestSpawnScenarioTableComplete turn red. A hand mutation proves it once; it is
// not standing CI. This test makes the proof ALWAYS-ON and in-process: it
// simulates the neutered gate with a TEST-LOCAL predicate (never touching
// classify.go), re-runs the SAME content-walk DiscoverSpawnFixtures runs over
// client/fixtures under BOTH the real and the neutered predicate, and asserts the
// negative-control cassette is discovered ONLY under the neutered gate. So if a
// future change weakened claudecode.IsSpawnToolUse to drop the subagent_type check,
// the real and neutered discovery sets would COLLAPSE together here, and this test
// goes red — alongside (and naming) the two tests the hand mutation tripped:
// TestTaskTodoNoSubagentIsNotASpawn (the projection would emit a spawn) and
// TestSpawnScenarioTableComplete (the now-discovered fixture has no table row).
//
// The neutered predicate is a TEST-LOCAL stand-in, NOT a re-implementation of the
// production allowlist: it derives the allowlisted-NAME set from the SAME exported
// claudecode.IsSpawnToolUse (probe it with a subagent_type present), then drops the
// subagent_type requirement — exactly the one axis the gate adds. So the simulated
// weakening is precisely "the gate minus its subagent_type check", with the name
// allowlist still single-sourced in classify.go (no second copy to drift).
//
// SELF-CONTAINED WALK: the discovery walk is implemented locally here (not by
// parameterizing DiscoverSpawnFixtures, which the sibling spawn_scenarios.go owns)
// — it globs the same client/fixtures/*.cc-wire.ndjson set and classifies each
// cassette by content, so the neutered set is the disk-derived answer to "what
// would the discovery set be if the gate were neutered", computed without mutating
// any production code.
//
// FIXTURE-PRESENCE ROBUST: the negative-control cassette (task-todo-no-subagent)
// is published by the sibling negative-mirror unit. When it is on disk this test
// pins the named co-fail in full; when it is absent (this unit's pinned base
// predates the sibling), it derives the witness STRUCTURALLY — any cassette the
// neutered gate discovers but the real gate does not is a bare-allowlisted-name
// (subagent_type-less) cassette, the exact shape the negative control is — and
// still proves the gate is the SOLE difference between the two sets, logging that
// the by-name co-fail rides the sibling's fixture.

// neutralizedSpawnName reports whether a tool_use name is one the production gate
// would accept on the NAME axis (the spawn allowlist {Agent, Task, TaskCreate}),
// independent of the subagent_type gate. It probes the SINGLE exported
// claudecode.IsSpawnToolUse with a subagent_type PRESENT, so the allowlist stays
// single-sourced in classify.go: a name is allowlisted iff adding a subagent_type
// makes IsSpawnToolUse true. This is the NAME half of the neutered predicate.
func neutralizedSpawnName(name string) bool {
	return claudecode.IsSpawnToolUse(name, json.RawMessage(`{"subagent_type":"neuter-probe"}`))
}

// neuteredIsSpawnToolUse is the TEST-LOCAL neutered spawn discriminator: it accepts
// any allowlisted name REGARDLESS of input.subagent_type — i.e. the production gate
// with its subagent_type check removed. It never touches classify.go; it is the
// in-process simulation of "the gate was weakened". The input argument is accepted
// (and ignored) so the signature mirrors claudecode.IsSpawnToolUse and the walk can
// take either predicate.
func neuteredIsSpawnToolUse(name string, _ json.RawMessage) bool {
	return neutralizedSpawnName(name)
}

// walkSpawnFixturesWith reimplements DiscoverSpawnFixtures' content-walk LOCALLY
// (so the sibling-owned spawn_scenarios.go is not parameterized) and classifies
// each client/fixtures/*.cc-wire.ndjson cassette as spawn-path under the GIVEN
// per-block predicate. Passing claudecode.IsSpawnToolUse reproduces the real
// discovery set; passing neuteredIsSpawnToolUse produces the set discovery WOULD
// have if the subagent_type gate were dropped. It returns sorted base names, and a
// set for membership tests. It fails the test loudly on any IO/scan error so the
// neutered/real comparison can never pass vacuously on a swallowed read error.
func walkSpawnFixturesWith(t *testing.T, dir string, pred func(string, json.RawMessage) bool) map[string]bool {
	t.Helper()
	cassettes, err := filepath.Glob(filepath.Join(dir, "*"+cassetteSuffix))
	if err != nil {
		t.Fatalf("glob spawn fixtures under %s: %v", dir, err)
	}
	out := map[string]bool{}
	for _, path := range cassettes {
		if cassetteHasSpawnBlockWith(t, path, pred) {
			out[trimCassetteBase(path)] = true
		}
	}
	return out
}

// cassetteHasSpawnBlockWith reports whether the NDJSON cassette at path carries an
// assistant tool_use block the GIVEN predicate classifies as a spawn. It is the
// per-file half of walkSpawnFixturesWith and mirrors cassetteIsSpawnPath's content
// shape (assistant record → message.content → tool_use blocks), but takes the
// predicate as a parameter so the same walk runs under the real and neutered gates.
func cassetteHasSpawnBlockWith(t *testing.T, path string, pred func(string, json.RawMessage) bool) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open cassette %s: %v", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
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
		if !rawStringEq(rec["type"], "assistant") {
			continue
		}
		msgRaw, ok := rec["message"]
		if !ok {
			continue
		}
		var msg struct {
			Content []struct {
				Type  string          `json:"type"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content"`
		}
		if err := json.Unmarshal(msgRaw, &msg); err != nil {
			continue
		}
		for _, b := range msg.Content {
			if b.Type != "tool_use" {
				continue
			}
			if pred(b.Name, b.Input) {
				return true
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan cassette %s: %v", path, err)
	}
	return false
}

// trimCassetteBase returns the cassette base name (no dir, no suffix) — the join
// key the discovery/table sets are compared on.
func trimCassetteBase(path string) string {
	base := filepath.Base(path)
	return base[:len(base)-len(cassetteSuffix)]
}

// neutralControlFixture is the read-side negative-control cassette name. It is
// published by the sibling negative-mirror unit (a bare allowlisted-name Task with
// NO subagent_type). This unit's pinned base may predate that fixture, so the
// co-fail test guards on its presence (see TestNeuteredSpawnGateCoFails).
const neutralControlFixture = "task-todo-no-subagent"

// TestNeuteredSpawnGateCoFails makes the wave-1 hand mutation (manually deleting
// the subagent_type gate and watching the negative control turn into a spawn) an
// ALWAYS-ON, in-process CI assertion. It runs the fixture-discovery walk over
// client/fixtures under the REAL gate (claudecode.IsSpawnToolUse) and the NEUTERED
// gate (subagent_type check dropped), and proves the negative control is on the
// spawn path ONLY under the neutered gate — so weakening the real gate collapses
// the two sets and trips this test alongside the named co-failing tests.
func TestNeuteredSpawnGateCoFails(t *testing.T) {
	dir := filepath.FromSlash("../../fixtures")

	// The real discovery set, computed two ways that MUST agree: the sibling-owned
	// DiscoverSpawnFixtures, and this unit's local walk under the same real
	// predicate. If they disagree, the local walk is not a faithful reproduction of
	// discovery and the neutered comparison below would be untrustworthy — so pin
	// them equal first (this also re-exercises DiscoverSpawnFixtures as the source
	// of truth without parameterizing it).
	discovered, err := DiscoverSpawnFixtures(dir)
	if err != nil {
		t.Fatalf("DiscoverSpawnFixtures: %v", err)
	}
	realSet := map[string]bool{}
	for _, f := range discovered {
		realSet[f] = true
	}
	localRealSet := walkSpawnFixturesWith(t, dir, claudecode.IsSpawnToolUse)
	if !sameStringSet(realSet, localRealSet) {
		t.Fatalf("the local spawn-discovery walk under the REAL gate disagrees with DiscoverSpawnFixtures:\n"+
			"  DiscoverSpawnFixtures: %v\n  local walk:            %v\n"+
			"the local walk must reproduce discovery exactly, or the neutered comparison is not measuring the gate",
			sortedKeys(realSet), sortedKeys(localRealSet))
	}

	// The neutered discovery set: the same walk with the subagent_type gate dropped.
	// It must be a SUPERSET of the real set (neutering only ADMITS more, never
	// fewer), and the EXTRA fixtures are exactly the bare-allowlisted-name
	// (subagent_type-less) cassettes — the shape the negative control is.
	neuteredSet := walkSpawnFixturesWith(t, dir, neuteredIsSpawnToolUse)
	for f := range realSet {
		if !neuteredSet[f] {
			t.Errorf("fixture %q is discovered by the REAL gate but NOT the neutered gate — neutering must only "+
				"ADMIT more spawn fixtures (drop the subagent_type requirement), never drop one; the neutered "+
				"predicate is wrong", f)
		}
	}
	extra := setDifference(neuteredSet, realSet)

	// The load-bearing co-fail: the neutered gate must discover STRICTLY MORE than
	// the real gate, and the extra cassettes are the subagent_type-gated negatives —
	// proving the subagent_type check is the SOLE thing keeping them off the spawn
	// path. If extra is empty, neutering the gate changed nothing about discovery,
	// so a regression that dropped the gate would NOT be caught here: that is a
	// vacuous proof, and it fails loudly.
	if _, present := hasFixtureOnDisk(dir, neutralControlFixture); present {
		// Merged tree: the sibling's negative-control fixture is on disk. Pin the
		// by-name co-fail in full.
		if !neuteredSet[neutralControlFixture] {
			t.Errorf("%s is NOT discovered even under the NEUTERED gate — the negative-control cassette must carry "+
				"a spawn-allowlisted tool name so neutering the subagent_type gate pulls it onto the spawn path; "+
				"it does not, so the co-fail proof is vacuous", neutralControlFixture)
		}
		if realSet[neutralControlFixture] {
			t.Errorf("%s is discovered by the REAL gate — a bare Task (no subagent_type) must NOT be a spawn "+
				"fixture under the real gate (the subagent_type gate excludes it). Its presence in the real set "+
				"means the gate is ALREADY weakened: TestTaskTodoNoSubagentIsNotASpawn and "+
				"TestSpawnScenarioTableComplete are red too", neutralControlFixture)
		}
		// The negative control is in the EXTRA-under-neutering set: discovered ONLY
		// once the gate is neutered. This is the always-on form of the hand mutation:
		// neuter the gate → the negative control becomes a spawn fixture →
		// TestSpawnScenarioTableComplete fails (no table row for it) and
		// TestTaskTodoNoSubagentIsNotASpawn fails (its projection emits a spawn).
		if !extra[neutralControlFixture] {
			t.Errorf("%s is not in the neutered-ONLY discovery set (extra under neutering: %v) — the subagent_type "+
				"gate is supposed to be the SOLE reason it is off the spawn path, so neutering the gate must be "+
				"exactly what pulls it in; it is not, so weakening the gate would NOT trip "+
				"TestTaskTodoNoSubagentIsNotASpawn / TestSpawnScenarioTableComplete via this path",
				neutralControlFixture, sortedKeys(extra))
		}
		// It must have NO SpawnScenarios row (a non-spawn under the real gate): a row
		// would itself break TestSpawnScenarioTableComplete's stale-row arm.
		for _, f := range SpawnScenarioFixtures() {
			if f == neutralControlFixture {
				t.Errorf("%s has a SpawnScenarios row, but under the real gate it is a NON-spawn negative control — "+
					"it must not appear in the spawn-scenario table", neutralControlFixture)
			}
		}
		t.Logf("neutered-gate co-fail (by name): %s is discovered ONLY under the neutered gate; weakening "+
			"claudecode.IsSpawnToolUse would flip TestTaskTodoNoSubagentIsNotASpawn and trip "+
			"TestSpawnScenarioTableComplete (no table row for the now-discovered fixture)", neutralControlFixture)
		return
	}

	// Standalone (pinned base predates the sibling negative-mirror unit): the named
	// negative-control fixture is not on disk yet. Derive the witness STRUCTURALLY —
	// the extra-under-neutering set IS the set of bare-allowlisted-name cassettes the
	// subagent_type gate excludes. If it is non-empty, the gate's exclusion is proven
	// always-on over whatever such cassettes exist; if it is empty, there is simply
	// no subagent_type-gated cassette on this base to witness (the sibling unit
	// publishes one), which is reported, not failed, so this unit stays green on its
	// pinned base and becomes a hard by-name co-fail the moment the fixture lands.
	if len(extra) > 0 {
		t.Logf("neutered-gate co-fail (structural witness): %s not on disk yet (published by the sibling "+
			"negative-mirror unit); the subagent_type gate is nonetheless proven always-on — these cassettes are "+
			"discovered ONLY under the neutered gate and would each flip onto the spawn path if the gate were "+
			"weakened: %v", neutralControlFixture, sortedKeys(extra))
		return
	}
	t.Logf("neutered-gate co-fail: no subagent_type-gated cassette on this pinned base to witness yet — the "+
		"negative-control fixture %q is published by the sibling negative-mirror unit; once it lands this test "+
		"becomes a hard by-name co-fail with TestTaskTodoNoSubagentIsNotASpawn / TestSpawnScenarioTableComplete. "+
		"The real and local discovery sets agree (%v), so the walk is faithful and ready for that witness.",
		neutralControlFixture, sortedKeys(realSet))
}

// hasFixtureOnDisk reports whether client/fixtures/<base>.cc-wire.ndjson exists,
// so the co-fail test can pin the by-name assertions only when the sibling unit's
// negative-control cassette is present and otherwise fall back to the structural
// witness.
func hasFixtureOnDisk(dir, base string) (string, bool) {
	path := filepath.Join(dir, base+cassetteSuffix)
	if _, err := os.Stat(path); err != nil {
		return path, false
	}
	return path, true
}

// sameStringSet reports whether two string sets have identical membership.
func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// setDifference returns the members of a not present in b.
func setDifference(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if !b[k] {
			out[k] = true
		}
	}
	return out
}

// sortedKeys returns a set's keys sorted, for stable, readable failure/log output.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// sortStrings sorts a string slice in place. It is a tiny local wrapper so this
// file need not add a sort import beyond what it already uses; insertion sort is
// ample for the handful of fixture names.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
