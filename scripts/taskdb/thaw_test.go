// SPDX-License-Identifier: Apache-2.0
package main

// Hermetic tests for the thaw guardrail (taskdb 01KTXSZ8PYBRC8VJVZJ6HRSQZF).
//
// Two incidents on 2026-06-12 (5+ parallel waves) wiped live-only tasks: an
// external thaw dropped 8 wave-6b rows, and `taskdb thaw --help` — which did not
// parse subcommand flags — executed a real thaw and dropped 13. These tests pin
// the three fixes:
//
//   - TestThawRefusesDroppingLiveOnlyTask: a thaw whose rebuild would drop a row
//     present in the DB but absent from tasks/*.json exits non-zero, names the
//     count + the ID, and does NOT mutate the DB.
//   - TestThawForceDropsLiveOnlyTask: --force overrides the guard and proceeds.
//   - TestThawNoDropExitsZero: a thaw with no drops succeeds (exit 0) so the
//     non-interactive post-checkout/merge/rewrite hooks keep working.
//   - TestThawRejectsUnknownFlag / TestRejectUnknownFlags: the --help footgun and
//     every flagless verb reject unrecognized flags instead of silently running.
//
// The same drop-guard extends one table over to notes (thaw's rebuild also
// DELETEs + reinserts notes, so a note minted live but not yet frozen is the
// same loss class). These pin the notes half:
//
//   - TestThawRefusesDroppingLiveOnlyNote: a live-only note refuses, names the
//     note count + ID, and does NOT mutate the DB.
//   - TestThawForceDropsLiveOnlyNote: --force overrides the guard for notes too.
//   - TestThawNoteInBothDoesNotRefuse: a note in both DB and JSON is preserved
//     with no refusal (the no-op path).
//   - TestThawRefusesMixedLiveOnlyTaskAndNote: a live-only task AND note both show
//     up in one refusal, each kind counted and listed.
//
// The guard extends one more table over to dep edges: thaw's rebuild also DELETEs
// task_deps and reinserts edges solely from frozen DependsOn arrays, so an edge
// minted live on an already-frozen task is the same loss class (both endpoints
// exist in both stores; only the edge does not). These pin the dep-edge half, and
// also pin the copy-pasteable recovery one-liner the refusal now carries:
//
//   - TestThawRefusesDroppingLiveOnlyDepEdge: a live-only edge between two frozen
//     tasks refuses, names the edge "A -> B", and carries the recovery one-liner.
//   - TestThawForceDropsLiveOnlyDepEdge: --force overrides the guard for edges too.
//   - TestThawFrozenDepEdgeDoesNotRefuse: an edge frozen into a DependsOn array is
//     preserved with no refusal (the no-op path).
//   - TestThawDroppedDepEdgesSorted: live-only edges come back sorted.
//
// Each full-thaw test runs inside an isolated temp repo (a dir with its own
// .git/ + tasks/) so it never reads or writes the sandbox's real taskdb.sqlite
// or tasks/. `taskdb thaw` is NEVER invoked against any real repo here.

import (
	"bufio"
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// withIsolatedDBEnv clears the ambient database-path overrides for the duration
// of a test (the thaw-env-isolation pattern, shared with readonly_test.go). A
// task-wave sandbox pins TASKDB_DBPATH (or TASKDB_DB) at a mode-0444 read-only
// snapshot; left set, dbPath() honors it and every openDB() / spawned taskdb
// subprocess in a test resolves to that snapshot instead of the test's own temp
// repo — surfacing either "attempt to write a readonly database (8)" on a write
// or, worse, READING the live wave corpus on a read (a false pass/fail driven by
// the ambient env, not the code under test). Clearing both names (dbPath() skips
// an empty value, and a cleared parent env propagates to child processes that
// inherit os.Environ()) forces resolution to the repo-local taskdb.sqlite under
// the test's temp root. t.Setenv restores the prior values at cleanup, and also
// asserts the test is not running in parallel (the documented t.Setenv contract).
func withIsolatedDBEnv(t *testing.T) {
	t.Helper()
	for _, ev := range dbPathEnvVars {
		t.Setenv(ev, "")
	}
}

// thawTestRepo builds an isolated temp repo (its own .git/ so repoRoot resolves
// here, plus an empty tasks/) and chdirs into it for the duration of the test.
// openDB/tasksDir/dbPath all resolve against this temp root, never the sandbox.
func thawTestRepo(t *testing.T) string {
	t.Helper()
	withIsolatedDBEnv(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "tasks"), 0755); err != nil {
		t.Fatalf("mkdir tasks: %v", err)
	}
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	return root
}

// addLiveTask inserts a task straight into the live DB (no freeze), making it a
// live-only row a thaw would drop.
func addLiveTask(t *testing.T, root, id, title string) {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		id, title, "", string(StatusOpen), 0, now, now,
	); err != nil {
		t.Fatalf("insert live task %s: %v", id, err)
	}
}

// freezeTaskJSON writes a canonical task-<id>.json into tasks/, so a thaw will
// reinsert (not drop) that ID.
func freezeTaskJSON(t *testing.T, root, id, title string) {
	t.Helper()
	now := time.Now().UTC()
	task := &Task{ID: id, Title: title, Status: StatusOpen, CreatedAt: now, UpdatedAt: now}
	if err := writeJSON(filepath.Join(root, "tasks", "task-"+id+".json"), task); err != nil {
		t.Fatalf("write task json %s: %v", id, err)
	}
}

// addLiveNote inserts a note straight into the live DB (no freeze), making it a
// live-only row a thaw would drop. taskID must reference a row that exists in
// the DB (the notes FK is ON DELETE CASCADE), so callers add a frozen+live
// parent task first.
func addLiveNote(t *testing.T, root, id, taskID, body string) {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	var tid any = nil
	if taskID != "" {
		tid = taskID
	}
	if _, err := db.Exec(
		`INSERT INTO notes(id,task_id,body,author,created_at) VALUES(?,?,?,?,?)`,
		id, tid, body, "", timeToMs(time.Now().UTC()),
	); err != nil {
		t.Fatalf("insert live note %s: %v", id, err)
	}
}

// addLiveDepEdge inserts a task_deps edge (taskID -> dependsOn) straight into the
// live DB (no freeze), making it a live-only edge a thaw would drop. Both ends
// must reference rows that exist in the DB (the task_deps FKs are ON DELETE
// CASCADE), so callers add the endpoint tasks first.
func addLiveDepEdge(t *testing.T, root, taskID, dependsOn string) {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(
		`INSERT INTO task_deps(task_id,depends_on) VALUES(?,?)`,
		taskID, dependsOn,
	); err != nil {
		t.Fatalf("insert live dep edge %s -> %s: %v", taskID, dependsOn, err)
	}
}

// freezeTaskJSONWithDeps writes a canonical task-<id>.json carrying a DependsOn
// array into tasks/, so a thaw will reinsert (not drop) those edges. The task
// itself is also reinserted, like freezeTaskJSON.
func freezeTaskJSONWithDeps(t *testing.T, root, id, title string, dependsOn []string) {
	t.Helper()
	now := time.Now().UTC()
	task := &Task{ID: id, Title: title, Status: StatusOpen, DependsOn: dependsOn, CreatedAt: now, UpdatedAt: now}
	if err := writeJSON(filepath.Join(root, "tasks", "task-"+id+".json"), task); err != nil {
		t.Fatalf("write task json %s: %v", id, err)
	}
}

// liveDepEdges returns the set of task_deps edges currently in the live DB, each
// keyed "task_id -> depends_on" (the same shape the refusal lists).
func liveDepEdges(t *testing.T) map[string]bool {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT task_id, depends_on FROM task_deps`)
	if err != nil {
		t.Fatalf("query dep edges: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var taskID, dependsOn string
		if err := rows.Scan(&taskID, &dependsOn); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[taskID+" -> "+dependsOn] = true
	}
	return out
}

// freezeNoteJSON writes a canonical note-<id>.json into tasks/, so a thaw will
// reinsert (not drop) that ID.
func freezeNoteJSON(t *testing.T, root, id, taskID, body string) {
	t.Helper()
	note := &Note{ID: id, TaskID: taskID, Body: body, CreatedAt: time.Now().UTC()}
	if err := writeJSON(filepath.Join(root, "tasks", "note-"+id+".json"), note); err != nil {
		t.Fatalf("write note json %s: %v", id, err)
	}
}

// liveNoteIDs returns the set of note IDs currently in the live DB.
func liveNoteIDs(t *testing.T) map[string]bool {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id FROM notes`)
	if err != nil {
		t.Fatalf("query note ids: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[id] = true
	}
	return out
}

func liveTaskIDs(t *testing.T) map[string]bool {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id FROM tasks`)
	if err != nil {
		t.Fatalf("query ids: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[id] = true
	}
	return out
}

const (
	frozenID = "01TEST0000000000000FROZEN0" // 26 chars; lives in both DB and JSON
	liveID   = "01TEST0000000000000LIVE000" // 26 chars; DB-only, would be dropped

	// Note IDs for the notes drop-guard tests. The parent task (frozenID) is
	// frozen+live so the notes FK (ON DELETE CASCADE) is satisfied and the task
	// itself never triggers the refusal.
	frozenNoteID = "01TEST00000000000FROZENNOTE" // 27 chars; lives in both DB and JSON
	liveNoteID   = "01TEST000000000000LIVENOTE0" // 27 chars; DB-only, would be dropped

	// A second frozen+live task so a dep edge between two already-frozen tasks can
	// be minted live-only — the exact gap this unit closes. Both endpoints exist
	// in both stores; only the edge between them is live-only.
	frozenID2 = "01TEST000000000000FROZEN02" // 26 chars; lives in both DB and JSON
)

func TestThawRefusesDroppingLiveOnlyTask(t *testing.T) {
	root := thawTestRepo(t)
	// One task that is frozen+committed (survives) and one live-only row (would
	// be dropped). The frozen one is also inserted live so the DB matches a real
	// "thaw would reinsert this, drop that" state.
	freezeTaskJSON(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, liveID, "minted by a parallel wave, not yet frozen")

	err := cmdThaw(openDBForTest(t), []string{})
	if err == nil {
		t.Fatal("expected thaw to refuse, got nil error")
	}
	msg := err.Error()
	if !strings.Contains(msg, liveID) {
		t.Errorf("refusal must name the dropped ID %s; got:\n%s", liveID, msg)
	}
	if !strings.Contains(msg, "1 live-only") {
		t.Errorf("refusal must name the count (1 live-only); got:\n%s", msg)
	}
	if !strings.Contains(msg, "--force") {
		t.Errorf("refusal must point at the --force override; got:\n%s", msg)
	}
	if !strings.Contains(msg, "taskdb freeze") {
		t.Errorf("refusal must offer `taskdb freeze` as the recovery path; got:\n%s", msg)
	}
	// State must be untouched: the live-only row is still present (the refusal
	// returns before db.Begin, so nothing was deleted).
	if ids := liveTaskIDs(t); !ids[liveID] {
		t.Errorf("refused thaw must not drop %s — DB was mutated", liveID)
	}
}

func TestThawForceDropsLiveOnlyTask(t *testing.T) {
	root := thawTestRepo(t)
	freezeTaskJSON(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, liveID, "minted by a parallel wave, not yet frozen")

	if err := cmdThaw(openDBForTest(t), []string{"--force"}); err != nil {
		t.Fatalf("--force thaw should proceed, got: %v", err)
	}
	ids := liveTaskIDs(t)
	if ids[liveID] {
		t.Errorf("--force thaw should have dropped the live-only row %s", liveID)
	}
	if !ids[frozenID] {
		t.Errorf("--force thaw should have reinserted the frozen row %s", frozenID)
	}
}

// TestThawRefusesDroppingLiveOnlyNote: a note minted live but not yet frozen
// makes a non-force thaw refuse, naming the note count + ID, and leaves the DB
// intact (the refusal returns before db.Begin).
func TestThawRefusesDroppingLiveOnlyNote(t *testing.T) {
	root := thawTestRepo(t)
	// A task that is frozen+live so the note's FK parent survives the reinsert
	// and the task itself is NOT what triggers the refusal.
	freezeTaskJSON(t, root, frozenID, "kept parent task")
	addLiveTask(t, root, frozenID, "kept parent task")
	// A live-only note: never frozen, attached to the kept task.
	addLiveNote(t, root, liveNoteID, frozenID, "minted by a parallel wave, not yet frozen")

	err := cmdThaw(openDBForTest(t), []string{})
	if err == nil {
		t.Fatal("expected thaw to refuse, got nil error")
	}
	msg := err.Error()
	if !strings.Contains(msg, liveNoteID) {
		t.Errorf("refusal must name the dropped note ID %s; got:\n%s", liveNoteID, msg)
	}
	if !strings.Contains(msg, "1 live-only note") {
		t.Errorf("refusal must name the note count (1 live-only note); got:\n%s", msg)
	}
	if !strings.Contains(msg, "--force") {
		t.Errorf("refusal must point at the --force override; got:\n%s", msg)
	}
	if !strings.Contains(msg, "taskdb freeze") {
		t.Errorf("refusal must offer `taskdb freeze` as the recovery path; got:\n%s", msg)
	}
	// State must be untouched: the live-only note is still present.
	if ids := liveNoteIDs(t); !ids[liveNoteID] {
		t.Errorf("refused thaw must not drop note %s — DB was mutated", liveNoteID)
	}
}

// TestThawForceDropsLiveOnlyNote: --force overrides the guard, on-records the
// dropped note, and the row is gone after the reinsert.
func TestThawForceDropsLiveOnlyNote(t *testing.T) {
	root := thawTestRepo(t)
	freezeTaskJSON(t, root, frozenID, "kept parent task")
	addLiveTask(t, root, frozenID, "kept parent task")
	addLiveNote(t, root, liveNoteID, frozenID, "drop me")

	if err := cmdThaw(openDBForTest(t), []string{"--force"}); err != nil {
		t.Fatalf("--force thaw should proceed, got: %v", err)
	}
	if ids := liveNoteIDs(t); ids[liveNoteID] {
		t.Errorf("--force thaw should have dropped the live-only note %s", liveNoteID)
	}
	// The frozen parent task survives the reinsert.
	if ids := liveTaskIDs(t); !ids[frozenID] {
		t.Errorf("--force thaw should have reinserted the frozen task %s", frozenID)
	}
}

// TestThawNoteInBothDoesNotRefuse: a note present in both the DB and the frozen
// JSON does not refuse and is preserved across the reinsert — the no-op path,
// zero behaviour change.
func TestThawNoteInBothDoesNotRefuse(t *testing.T) {
	root := thawTestRepo(t)
	freezeTaskJSON(t, root, frozenID, "kept parent task")
	addLiveTask(t, root, frozenID, "kept parent task")
	freezeNoteJSON(t, root, frozenNoteID, frozenID, "frozen note")
	addLiveNote(t, root, frozenNoteID, frozenID, "frozen note")

	if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
		t.Fatalf("agreeing thaw must not refuse, got: %v", err)
	}
	if ids := liveNoteIDs(t); !ids[frozenNoteID] {
		t.Errorf("agreeing thaw should have reinserted note %s", frozenNoteID)
	}
}

// TestThawRefusesMixedLiveOnlyTaskAndNote: a live-only task AND a live-only note
// both appear in one refusal, each kind counted and its ID listed; neither is
// dropped (the refusal returns before any transaction).
func TestThawRefusesMixedLiveOnlyTaskAndNote(t *testing.T) {
	root := thawTestRepo(t)
	// Frozen parent so the live-only note has a valid FK parent that survives.
	freezeTaskJSON(t, root, frozenID, "kept parent task")
	addLiveTask(t, root, frozenID, "kept parent task")
	// One live-only task and one live-only note.
	addLiveTask(t, root, liveID, "live-only task, not yet frozen")
	addLiveNote(t, root, liveNoteID, frozenID, "live-only note, not yet frozen")

	err := cmdThaw(openDBForTest(t), []string{})
	if err == nil {
		t.Fatal("expected mixed thaw to refuse, got nil error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "1 live-only task") {
		t.Errorf("refusal must name the task count (1 live-only task); got:\n%s", msg)
	}
	if !strings.Contains(msg, "1 live-only note") {
		t.Errorf("refusal must name the note count (1 live-only note); got:\n%s", msg)
	}
	if !strings.Contains(msg, liveID) {
		t.Errorf("refusal must list the dropped task ID %s; got:\n%s", liveID, msg)
	}
	if !strings.Contains(msg, liveNoteID) {
		t.Errorf("refusal must list the dropped note ID %s; got:\n%s", liveNoteID, msg)
	}
	// Nothing dropped: both rows still present.
	if ids := liveTaskIDs(t); !ids[liveID] {
		t.Errorf("refused thaw must not drop the live-only task %s", liveID)
	}
	if ids := liveNoteIDs(t); !ids[liveNoteID] {
		t.Errorf("refused thaw must not drop the live-only note %s", liveNoteID)
	}
}

// TestThawRefusesDroppingLiveOnlyDepEdge: a dep edge minted live
// (`taskdb task dep A --on B`) between two already-frozen tasks is invisible to
// the task/note guard (both endpoints exist in both stores) but the rebuild would
// erase it. The non-force thaw must refuse, name the edge as "A -> B", carry the
// copy-pasteable recovery one-liner, and leave the DB intact (the refusal returns
// before db.Begin).
func TestThawRefusesDroppingLiveOnlyDepEdge(t *testing.T) {
	root := thawTestRepo(t)
	// Two tasks frozen+live with NO frozen edge between them.
	freezeTaskJSON(t, root, frozenID, "task A")
	addLiveTask(t, root, frozenID, "task A")
	freezeTaskJSON(t, root, frozenID2, "task B")
	addLiveTask(t, root, frozenID2, "task B")
	// The edge A -> B exists only in the live DB.
	addLiveDepEdge(t, root, frozenID, frozenID2)

	err := cmdThaw(openDBForTest(t), []string{})
	if err == nil {
		t.Fatal("expected thaw to refuse the live-only dep edge, got nil error")
	}
	msg := err.Error()
	wantEdge := frozenID + " -> " + frozenID2
	if !strings.Contains(msg, wantEdge) {
		t.Errorf("refusal must name the dropped edge %q; got:\n%s", wantEdge, msg)
	}
	if !strings.Contains(msg, "1 live-only dep edge") {
		t.Errorf("refusal must name the dep-edge count (1 live-only dep edge); got:\n%s", msg)
	}
	if !strings.Contains(msg, "--force") {
		t.Errorf("refusal must point at the --force override; got:\n%s", msg)
	}
	// The copy-pasteable recovery one-liner must appear verbatim.
	if !strings.Contains(msg, "taskdb freeze && git add tasks/ && taskdb thaw") {
		t.Errorf("refusal must carry the exact recovery one-liner; got:\n%s", msg)
	}
	// State must be untouched: the live-only edge is still present.
	if edges := liveDepEdges(t); !edges[wantEdge] {
		t.Errorf("refused thaw must not drop edge %q — DB was mutated", wantEdge)
	}
}

// TestThawForceDropsLiveOnlyDepEdge: --force overrides the dep-edge guard and
// proceeds; the reinsert drops the live-only edge (it is in no frozen DependsOn
// array) while both endpoint tasks survive.
func TestThawForceDropsLiveOnlyDepEdge(t *testing.T) {
	root := thawTestRepo(t)
	freezeTaskJSON(t, root, frozenID, "task A")
	addLiveTask(t, root, frozenID, "task A")
	freezeTaskJSON(t, root, frozenID2, "task B")
	addLiveTask(t, root, frozenID2, "task B")
	addLiveDepEdge(t, root, frozenID, frozenID2)

	if err := cmdThaw(openDBForTest(t), []string{"--force"}); err != nil {
		t.Fatalf("--force thaw should proceed past the dep-edge guard, got: %v", err)
	}
	wantEdge := frozenID + " -> " + frozenID2
	if edges := liveDepEdges(t); edges[wantEdge] {
		t.Errorf("--force thaw should have dropped the live-only edge %q", wantEdge)
	}
	// Both endpoint tasks survive the reinsert.
	if ids := liveTaskIDs(t); !ids[frozenID] || !ids[frozenID2] {
		t.Errorf("--force thaw should have reinserted both endpoint tasks %s, %s", frozenID, frozenID2)
	}
}

// TestThawFrozenDepEdgeDoesNotRefuse: an edge present in both the live DB and a
// frozen task's DependsOn array is the no-op path — no refusal, and the edge is
// preserved across the reinsert.
func TestThawFrozenDepEdgeDoesNotRefuse(t *testing.T) {
	root := thawTestRepo(t)
	// A -> B is frozen into task A's DependsOn array AND present live.
	freezeTaskJSONWithDeps(t, root, frozenID, "task A", []string{frozenID2})
	addLiveTask(t, root, frozenID, "task A")
	freezeTaskJSON(t, root, frozenID2, "task B")
	addLiveTask(t, root, frozenID2, "task B")
	addLiveDepEdge(t, root, frozenID, frozenID2)

	if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
		t.Fatalf("agreeing thaw with a frozen dep edge must not refuse, got: %v", err)
	}
	wantEdge := frozenID + " -> " + frozenID2
	if edges := liveDepEdges(t); !edges[wantEdge] {
		t.Errorf("agreeing thaw should have reinserted the frozen edge %q", wantEdge)
	}
}

// TestThawDroppedDepEdgesSorted: several live-only edges out of order come back
// sorted so the refusal message is deterministic.
func TestThawDroppedDepEdgesSorted(t *testing.T) {
	root := thawTestRepo(t)
	a := "01TEST0000000000000000000A"
	b := "01TEST0000000000000000000B"
	c := "01TEST0000000000000000000C"
	for _, id := range []string{a, b, c} {
		freezeTaskJSON(t, root, id, id)
		addLiveTask(t, root, id, id)
	}
	// Insert edges out of sorted order.
	addLiveDepEdge(t, root, c, a)
	addLiveDepEdge(t, root, a, b)
	addLiveDepEdge(t, root, b, c)
	db := openDBForTest(t)
	dir := filepath.Join(root, "tasks")
	dropped, err := thawDroppedDepEdges(db, dir)
	if err != nil {
		t.Fatalf("thawDroppedDepEdges: %v", err)
	}
	want := []string{
		a + " -> " + b,
		b + " -> " + c,
		c + " -> " + a,
	}
	if strings.Join(dropped, ",") != strings.Join(want, ",") {
		t.Errorf("dropped dep edges not sorted: got %v want %v", dropped, want)
	}
}

// taskFileExists reports whether tasks/task-<id>.json is present on disk (the
// auto-freeze remedy writes it additively so a live-only row survives). A
// pathHelper for the auto-freeze tests below.
func taskFileExists(t *testing.T, root, id string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(root, "tasks", "task-"+id+".json"))
	return err == nil
}

// noteFileExists reports whether tasks/note-<id>.json is present on disk.
func noteFileExists(t *testing.T, root, id string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(root, "tasks", "note-"+id+".json"))
	return err == nil
}

// diskTaskDeps reads the depends_on array of an on-disk task-<id>.json (used to
// assert the auto-freeze dep-edge patch unioned the live-only edge in).
func diskTaskDeps(t *testing.T, root, id string) []string {
	t.Helper()
	var task Task
	if err := readJSON(filepath.Join(root, "tasks", "task-"+id+".json"), &task); err != nil {
		t.Fatalf("read task json %s: %v", id, err)
	}
	return task.DependsOn
}

// TestThawAutoFreezePreservesLiveOnlyTask: with --auto-freeze, a live-only task
// is NOT dropped and NOT refused — the remedy writes task-<id>.json additively,
// the thaw proceeds, and the row survives in BOTH stores (DB reinserted, JSON
// on disk). This is the docs/23 OQ3 hook-path fix.
func TestThawAutoFreezePreservesLiveOnlyTask(t *testing.T) {
	root := thawTestRepo(t)
	freezeTaskJSON(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, liveID, "minted by a parallel wave, not yet frozen")

	warn := captureThawWarn(t, func() {
		if err := cmdThaw(openDBForTest(t), []string{"--auto-freeze"}); err != nil {
			t.Fatalf("--auto-freeze thaw should proceed, not refuse; got: %v", err)
		}
	})

	// Survives in the live DB (reinserted from the freshly-written JSON).
	if ids := liveTaskIDs(t); !ids[liveID] {
		t.Errorf("--auto-freeze must preserve the live-only task %s in the DB", liveID)
	}
	if !taskFileExists(t, root, liveID) {
		t.Errorf("--auto-freeze must have written tasks/task-%s.json on disk", liveID)
	}
	// The frozen row is still there too.
	if ids := liveTaskIDs(t); !ids[frozenID] {
		t.Errorf("--auto-freeze thaw should have reinserted the frozen row %s", frozenID)
	}
	if !strings.Contains(warn, "auto-freeze") {
		t.Errorf("--auto-freeze should emit a one-line notice; got:\n%s", warn)
	}
}

// TestThawAutoFreezePreservesLiveOnlyNote: the note counterpart — a live-only
// note is written additively and survives the thaw.
func TestThawAutoFreezePreservesLiveOnlyNote(t *testing.T) {
	root := thawTestRepo(t)
	freezeTaskJSON(t, root, frozenID, "kept parent task")
	addLiveTask(t, root, frozenID, "kept parent task")
	addLiveNote(t, root, liveNoteID, frozenID, "minted by a parallel wave, not yet frozen")

	if err := cmdThaw(openDBForTest(t), []string{"--auto-freeze"}); err != nil {
		t.Fatalf("--auto-freeze thaw should proceed for a live-only note; got: %v", err)
	}
	if ids := liveNoteIDs(t); !ids[liveNoteID] {
		t.Errorf("--auto-freeze must preserve the live-only note %s in the DB", liveNoteID)
	}
	if !noteFileExists(t, root, liveNoteID) {
		t.Errorf("--auto-freeze must have written tasks/note-%s.json on disk", liveNoteID)
	}
}

// TestThawAutoFreezePreservesLiveOnlyDepEdge: a live-only edge between two
// already-frozen tasks is unioned into owner A's on-disk depends_on (scalars
// untouched) and survives the thaw.
func TestThawAutoFreezePreservesLiveOnlyDepEdge(t *testing.T) {
	root := thawTestRepo(t)
	freezeTaskJSON(t, root, frozenID, "task A")
	addLiveTask(t, root, frozenID, "task A")
	freezeTaskJSON(t, root, frozenID2, "task B")
	addLiveTask(t, root, frozenID2, "task B")
	addLiveDepEdge(t, root, frozenID, frozenID2)

	if err := cmdThaw(openDBForTest(t), []string{"--auto-freeze"}); err != nil {
		t.Fatalf("--auto-freeze thaw should proceed for a live-only dep edge; got: %v", err)
	}
	wantEdge := frozenID + " -> " + frozenID2
	if edges := liveDepEdges(t); !edges[wantEdge] {
		t.Errorf("--auto-freeze must preserve the live-only edge %q in the DB", wantEdge)
	}
	// Owner A's on-disk depends_on now carries B (the union patch), and A's other
	// fields are unchanged (still loads as task A).
	found := false
	for _, d := range diskTaskDeps(t, root, frozenID) {
		if d == frozenID2 {
			found = true
		}
	}
	if !found {
		t.Errorf("--auto-freeze must union %s into task-%s.json depends_on; got %v", frozenID2, frozenID, diskTaskDeps(t, root, frozenID))
	}
}

// TestThawAutoFreezeMixed: a live-only task, note, AND dep edge in one thaw are
// all preserved by --auto-freeze; the drop-diff is empty afterward.
func TestThawAutoFreezeMixed(t *testing.T) {
	root := thawTestRepo(t)
	// Two frozen tasks so an edge between them can be live-only.
	freezeTaskJSON(t, root, frozenID, "task A")
	addLiveTask(t, root, frozenID, "task A")
	freezeTaskJSON(t, root, frozenID2, "task B")
	addLiveTask(t, root, frozenID2, "task B")
	// A live-only task, a live-only note on it, and a live-only edge A -> B.
	addLiveTask(t, root, liveID, "live-only task")
	addLiveNote(t, root, liveNoteID, liveID, "live-only note on the live-only task")
	addLiveDepEdge(t, root, frozenID, frozenID2)

	if err := cmdThaw(openDBForTest(t), []string{"--auto-freeze"}); err != nil {
		t.Fatalf("--auto-freeze thaw should proceed for the mixed case; got: %v", err)
	}
	if ids := liveTaskIDs(t); !ids[liveID] {
		t.Errorf("--auto-freeze must preserve live-only task %s", liveID)
	}
	if ids := liveNoteIDs(t); !ids[liveNoteID] {
		t.Errorf("--auto-freeze must preserve live-only note %s", liveNoteID)
	}
	if edges := liveDepEdges(t); !edges[frozenID+" -> "+frozenID2] {
		t.Errorf("--auto-freeze must preserve live-only edge %s -> %s", frozenID, frozenID2)
	}
	// All three files are on disk (untracked; they travel with the next commit).
	if !taskFileExists(t, root, liveID) || !noteFileExists(t, root, liveNoteID) {
		t.Errorf("--auto-freeze must have written the live-only task+note JSON to disk")
	}
}

// TestThawAutoFreezeViaEnv: TASKDB_THAW_AUTOFREEZE=1 enables the same remedy as
// the flag, with no --auto-freeze token on the command line (the env is the knob
// a manual/scripted run reaches for).
func TestThawAutoFreezeViaEnv(t *testing.T) {
	root := thawTestRepo(t)
	t.Setenv("TASKDB_THAW_AUTOFREEZE", "1")
	freezeTaskJSON(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, liveID, "minted by a parallel wave, not yet frozen")

	if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
		t.Fatalf("TASKDB_THAW_AUTOFREEZE=1 thaw should proceed, not refuse; got: %v", err)
	}
	if ids := liveTaskIDs(t); !ids[liveID] {
		t.Errorf("env-enabled auto-freeze must preserve the live-only task %s", liveID)
	}
	if !taskFileExists(t, root, liveID) {
		t.Errorf("env-enabled auto-freeze must have written tasks/task-%s.json", liveID)
	}
}

// TestThawFlaglessStillRefusesWithLiveOnly: the manual default is unchanged — a
// flagless thaw (no --auto-freeze, env unset) still REFUSES a live-only drop and
// writes NO JSON, so an operator never loses work by accident.
func TestThawFlaglessStillRefusesWithLiveOnly(t *testing.T) {
	root := thawTestRepo(t)
	// Belt-and-suspenders: ensure the env knob is not set from an outer scope.
	t.Setenv("TASKDB_THAW_AUTOFREEZE", "")
	freezeTaskJSON(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, liveID, "minted by a parallel wave, not yet frozen")

	if err := cmdThaw(openDBForTest(t), []string{}); err == nil {
		t.Fatal("flagless thaw must still refuse a live-only drop")
	}
	// No JSON was written (the refusal returns before any auto-freeze write).
	if taskFileExists(t, root, liveID) {
		t.Errorf("flagless refusal must NOT write tasks/task-%s.json", liveID)
	}
	// DB untouched.
	if ids := liveTaskIDs(t); !ids[liveID] {
		t.Errorf("flagless refusal must not drop %s from the DB", liveID)
	}
}

// TestThawAutoFreezeDoesNotMaskPruneAndWarn: --auto-freeze intercepts ONLY the
// live-only DROP-guard (checked before any transaction). A dangling depends_on in
// a FROZEN task is a prune-and-warn case that surfaces later, inside the thaw —
// --auto-freeze must not swallow it: the edge is still pruned + loudly warned,
// exactly as a flagless thaw handles it.
func TestThawAutoFreezeDoesNotMaskPruneAndWarn(t *testing.T) {
	root := thawTestRepo(t)
	freezeTaskRaw(t, root, frozenID, "task A depends on a missing target", "", []string{missingTargetID})
	addLiveTask(t, root, frozenID, "task A depends on a missing target")

	warn := captureThawWarn(t, func() {
		if err := cmdThaw(openDBForTest(t), []string{"--auto-freeze"}); err != nil {
			t.Fatalf("--auto-freeze must still tolerate (prune) a dangling depends_on, not abort; got: %v", err)
		}
	})
	// The dangling edge was pruned, NOT auto-frozen into existence.
	if edges := liveDepEdges(t); edges[frozenID+" -> "+missingTargetID] {
		t.Errorf("--auto-freeze must not resurrect the dangling edge %s -> %s", frozenID, missingTargetID)
	}
	if !taskFileExists(t, root, frozenID) {
		// frozenID was already frozen; it must still be on disk, unchanged.
		t.Errorf("frozen task %s should remain on disk", frozenID)
	}
	// The prune warning still fired (auto-freeze did not swallow the FK/prune path).
	if !strings.Contains(warn, "DANGLING depends_on") {
		t.Errorf("--auto-freeze must preserve the prune-and-warn behavior; got:\n%s", warn)
	}
	assertFKClean(t)
}

// captureThawWarn redirects thawWarnOut to a buffer for the duration of fn and
// returns whatever thaw wrote there (the loud dangling-reference warnings). It
// restores the previous writer on return, so tests stay hermetic.
func captureThawWarn(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := thawWarnOut
	thawWarnOut = &buf
	defer func() { thawWarnOut = prev }()
	fn()
	return buf.String()
}

// assertFKClean runs PRAGMA foreign_key_check against the live DB and fails the
// test if it returns ANY row — a clean check is the proof that thaw's pruning
// left no dangling reference behind (the whole point of F5: the rebuild loads
// the valid remainder with referential integrity intact).
func assertFKClean(t *testing.T) {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	var violations []string
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan fk row: %v", err)
		}
		violations = append(violations, fmt.Sprintf("%v", vals))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("fk rows.Err: %v", err)
	}
	if len(violations) > 0 {
		t.Errorf("foreign_key_check must be clean after a pruning thaw; got %d violation(s): %v", len(violations), violations)
	}
}

// freezeTaskRaw writes a canonical task-<id>.json carrying an explicit
// ParentID + DependsOn (used to plant a dangling reference into the frozen
// store; the named target task is deliberately NOT frozen).
func freezeTaskRaw(t *testing.T, root, id, title, parentID string, dependsOn []string) {
	t.Helper()
	now := time.Now().UTC()
	task := &Task{ID: id, Title: title, Status: StatusOpen, ParentID: parentID, DependsOn: dependsOn, CreatedAt: now, UpdatedAt: now}
	if err := writeJSON(filepath.Join(root, "tasks", "task-"+id+".json"), task); err != nil {
		t.Fatalf("write task json %s: %v", id, err)
	}
}

const missingTargetID = "01TEST00000000000MISSING00" // 26 chars; never frozen, never live

// TestThawPrunesDanglingDependsOn pins the F5 fix for a dangling depends_on
// target: a frozen task A whose DependsOn names a task that is absent from
// tasks/*.json must NOT abort the whole thaw with a FOREIGN KEY error. The
// rebuild drops the dangling edge, LOUDLY warns naming source + missing target,
// loads the valid task A, and leaves foreign_key_check clean.
func TestThawPrunesDanglingDependsOn(t *testing.T) {
	root := thawTestRepo(t)
	// Task A is frozen+live with a depends_on pointing at a task that is NOT
	// frozen (missingTargetID). A is live too so the live-only drop-guard passes.
	freezeTaskRaw(t, root, frozenID, "task A depends on a missing target", "", []string{missingTargetID})
	addLiveTask(t, root, frozenID, "task A depends on a missing target")

	warn := captureThawWarn(t, func() {
		if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
			t.Fatalf("thaw must tolerate a dangling depends_on, not abort; got: %v", err)
		}
	})

	// The valid task loaded.
	if ids := liveTaskIDs(t); !ids[frozenID] {
		t.Errorf("valid task %s must load after pruning the dangling edge", frozenID)
	}
	// The dangling edge was pruned (no A -> missing edge remains).
	if edges := liveDepEdges(t); edges[frozenID+" -> "+missingTargetID] {
		t.Errorf("dangling edge %s -> %s must be pruned, not loaded", frozenID, missingTargetID)
	}
	// A loud warning named the source + missing target.
	if !strings.Contains(warn, "DANGLING depends_on") {
		t.Errorf("thaw must warn loudly about the pruned depends_on; got warn output:\n%s", warn)
	}
	if !strings.Contains(warn, frozenID) || !strings.Contains(warn, missingTargetID) {
		t.Errorf("warning must name source %s and missing target %s; got:\n%s", frozenID, missingTargetID, warn)
	}
	// Referential integrity intact.
	assertFKClean(t)
}

// TestThawPrunesDanglingParentID pins the F5 fix for a dangling parent_id: a
// frozen task whose parent_id names a task absent from tasks/*.json must NOT
// abort the thaw. The rebuild NULLs the parent_id (mirroring ON DELETE SET
// NULL), LOUDLY warns, loads the task, and leaves foreign_key_check clean.
func TestThawPrunesDanglingParentID(t *testing.T) {
	root := thawTestRepo(t)
	freezeTaskRaw(t, root, frozenID, "child whose parent is missing", missingTargetID, nil)
	addLiveTask(t, root, frozenID, "child whose parent is missing")

	warn := captureThawWarn(t, func() {
		if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
			t.Fatalf("thaw must tolerate a dangling parent_id, not abort; got: %v", err)
		}
	})

	// The valid task loaded.
	if ids := liveTaskIDs(t); !ids[frozenID] {
		t.Errorf("valid task %s must load after NULLing the dangling parent_id", frozenID)
	}
	// parent_id was NULLed, not left dangling.
	db := openDBForTest(t)
	var parent sql.NullString
	if err := db.QueryRow(`SELECT parent_id FROM tasks WHERE id=?`, frozenID).Scan(&parent); err != nil {
		t.Fatalf("select parent_id: %v", err)
	}
	if parent.Valid {
		t.Errorf("dangling parent_id must be NULLed; got %q", parent.String)
	}
	// A loud warning named the source + missing parent.
	if !strings.Contains(warn, "DANGLING parent_id") {
		t.Errorf("thaw must warn loudly about the NULLed parent_id; got:\n%s", warn)
	}
	if !strings.Contains(warn, frozenID) || !strings.Contains(warn, missingTargetID) {
		t.Errorf("warning must name task %s and missing parent %s; got:\n%s", frozenID, missingTargetID, warn)
	}
	assertFKClean(t)
}

// TestThawPrunesDanglingNoteTaskID pins the F5 fix for a dangling note.task_id:
// a frozen note whose task_id names a task absent from tasks/*.json must NOT
// abort the thaw. The rebuild SKIPS the orphan note, LOUDLY warns, loads the
// valid task, and leaves foreign_key_check clean.
func TestThawPrunesDanglingNoteTaskID(t *testing.T) {
	root := thawTestRepo(t)
	// A valid task that loads, plus a frozen note whose task_id is missing. The
	// note lives only in JSON (never live), so the note drop-guard does not fire.
	freezeTaskJSON(t, root, frozenID, "a valid task that loads")
	addLiveTask(t, root, frozenID, "a valid task that loads")
	freezeNoteJSON(t, root, liveNoteID, missingTargetID, "note attached to a missing task")

	warn := captureThawWarn(t, func() {
		if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
			t.Fatalf("thaw must tolerate a dangling note.task_id, not abort; got: %v", err)
		}
	})

	// The valid task loaded.
	if ids := liveTaskIDs(t); !ids[frozenID] {
		t.Errorf("valid task %s must load after skipping the orphan note", frozenID)
	}
	// The orphan note was skipped, not loaded.
	if notes := liveNoteIDs(t); notes[liveNoteID] {
		t.Errorf("orphan note %s must be skipped, not loaded", liveNoteID)
	}
	// A loud warning named the note + missing task.
	if !strings.Contains(warn, "DANGLING note.task_id") {
		t.Errorf("thaw must warn loudly about the skipped note; got:\n%s", warn)
	}
	if !strings.Contains(warn, liveNoteID) || !strings.Contains(warn, missingTargetID) {
		t.Errorf("warning must name note %s and missing task %s; got:\n%s", liveNoteID, missingTargetID, warn)
	}
	assertFKClean(t)
}

// TestThawPrunesAllThreeDanglingKinds pins that a single thaw resiliently
// prunes all three dangling-target kinds at once (depends_on + parent_id +
// note.task_id), still loads the valid remainder, warns for each, and leaves
// foreign_key_check clean — the integrated F5 resilience guarantee.
func TestThawPrunesAllThreeDanglingKinds(t *testing.T) {
	root := thawTestRepo(t)
	// Valid anchor task that everything else hangs off / that survives.
	freezeTaskJSON(t, root, frozenID, "valid anchor")
	addLiveTask(t, root, frozenID, "valid anchor")
	// A second task carrying BOTH a dangling parent_id and a dangling depends_on.
	freezeTaskRaw(t, root, frozenID2, "task with two dangling refs", missingTargetID, []string{missingTargetID})
	addLiveTask(t, root, frozenID2, "task with two dangling refs")
	// A frozen note whose task_id is missing.
	freezeNoteJSON(t, root, liveNoteID, missingTargetID, "orphan note")

	warn := captureThawWarn(t, func() {
		if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
			t.Fatalf("thaw must prune all three dangling kinds, not abort; got: %v", err)
		}
	})

	// Both valid tasks loaded.
	ids := liveTaskIDs(t)
	if !ids[frozenID] || !ids[frozenID2] {
		t.Errorf("both valid tasks must load; got %s=%v %s=%v", frozenID, ids[frozenID], frozenID2, ids[frozenID2])
	}
	// No dangling edge, no orphan note.
	if edges := liveDepEdges(t); edges[frozenID2+" -> "+missingTargetID] {
		t.Errorf("dangling edge must be pruned")
	}
	if notes := liveNoteIDs(t); notes[liveNoteID] {
		t.Errorf("orphan note must be skipped")
	}
	// All three warning kinds present.
	for _, kind := range []string{"DANGLING depends_on", "DANGLING parent_id", "DANGLING note.task_id"} {
		if !strings.Contains(warn, kind) {
			t.Errorf("thaw must warn about %q; got:\n%s", kind, warn)
		}
	}
	assertFKClean(t)
}

func TestThawNoDropExitsZero(t *testing.T) {
	root := thawTestRepo(t)
	// Every live row is also frozen → no drops → thaw must succeed (the hook
	// path depends on this exit-0 invariant).
	freezeTaskJSON(t, root, frozenID, "frozen and committed")
	addLiveTask(t, root, frozenID, "frozen and committed")

	if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
		t.Fatalf("no-drop thaw must exit 0 for hooks, got: %v", err)
	}
	if ids := liveTaskIDs(t); !ids[frozenID] {
		t.Errorf("no-drop thaw should have reinserted %s", frozenID)
	}
}

func TestThawEmptyDBExitsZero(t *testing.T) {
	thawTestRepo(t)
	// Fresh clone: empty live DB, empty tasks/. The hook fires on every checkout,
	// so this baseline must be exit 0.
	if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
		t.Fatalf("thaw on empty DB/empty tasks must exit 0, got: %v", err)
	}
}

func TestThawRejectsUnknownFlag(t *testing.T) {
	thawTestRepo(t)
	// THE incident: `taskdb thaw --help`. It must NOT thaw; it must error.
	for _, bad := range []string{"--help", "-h", "--dry-run", "--frce"} {
		err := cmdThaw(openDBForTest(t), []string{bad})
		if err == nil {
			t.Errorf("thaw %s must be rejected, not executed", bad)
		}
	}
}

func TestThawRejectsUnexpectedPositional(t *testing.T) {
	thawTestRepo(t)
	if err := cmdThaw(openDBForTest(t), []string{"somefile.json"}); err == nil {
		t.Error("thaw with an unexpected positional arg must be rejected")
	}
}

// TestThawReparentedChildBeforeParent pins the cold-thaw FK fix: a child whose
// ULID sorts BEFORE its parent's — the shape `task edit --parent` produces when
// an older task is re-parented onto a task created later — must thaw cleanly. The
// task-*.json glob inserts in lexical id order, so the child is reached first;
// before the fix, setting parent_id inline violated the tasks(parent_id)->
// tasks(id) FK because the parent row did not exist yet (the live failure on
// origin/main: child 01KV7SBQ6C… -> parent 01KV8XSNEX…). Thaw must wire parents
// order-independently and still record the linkage.
func TestThawReparentedChildBeforeParent(t *testing.T) {
	root := thawTestRepo(t)
	const childID = "01AAAA0000000000000CHILD00"  // sorts BEFORE the parent
	const parentID = "01ZZZZ0000000000000PARENT0" // sorts AFTER the child
	now := time.Now().UTC()
	// Parent: a plain task created "later". Child: parent_id -> parent, but its id
	// sorts first, so the glob inserts it before the parent row exists.
	if err := writeJSON(filepath.Join(root, "tasks", "task-"+parentID+".json"),
		&Task{ID: parentID, Title: "parent created later", Status: StatusOpen, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("write parent json: %v", err)
	}
	if err := writeJSON(filepath.Join(root, "tasks", "task-"+childID+".json"),
		&Task{ID: childID, Title: "older child, re-parented", Status: StatusDropped, ParentID: parentID, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("write child json: %v", err)
	}

	if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
		t.Fatalf("thaw must tolerate a child sorted before its parent, got: %v", err)
	}

	// Both rows thawed, and the child's parent_id is wired through the second pass.
	if ids := liveTaskIDs(t); !ids[childID] || !ids[parentID] {
		t.Fatalf("both tasks must thaw; got child=%v parent=%v", ids[childID], ids[parentID])
	}
	var got sql.NullString
	if err := openDBForTest(t).QueryRow(`SELECT parent_id FROM tasks WHERE id=?`, childID).Scan(&got); err != nil {
		t.Fatalf("select child parent_id: %v", err)
	}
	if !got.Valid || got.String != parentID {
		t.Errorf("child parent_id must be wired to %s; got %#v", parentID, got)
	}
}

// openDBForTest opens the isolated temp repo's DB (thawTestRepo has already
// chdir'd into it). Caller is the cmd* function, which closes nothing — these
// pooled DBs are GC'd at process exit; the file is in t.TempDir.
func openDBForTest(t *testing.T) *sql.DB {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestRejectUnknownFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"empty", nil, false},
		{"single flag", []string{"--help"}, true},
		{"short flag", []string{"-x"}, true},
		{"positional only", []string{"extra"}, true},
		{"flag after nothing", []string{"--force"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := rejectUnknownFlags(c.args, "taskdb demo")
			if (err != nil) != c.wantErr {
				t.Errorf("rejectUnknownFlags(%v) err=%v, wantErr=%v", c.args, err, c.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "taskdb demo") {
				t.Errorf("error should echo the usage string; got: %v", err)
			}
		})
	}
}

func TestThawDroppedIDsSorted(t *testing.T) {
	root := thawTestRepo(t)
	// Insert several live-only rows out of order; the diff must come back sorted
	// so the refusal message is deterministic.
	addLiveTask(t, root, "01TEST00000000000000000ZZZ", "z")
	addLiveTask(t, root, "01TEST00000000000000000AAA", "a")
	addLiveTask(t, root, "01TEST00000000000000000MMM", "m")
	db := openDBForTest(t)
	dir := filepath.Join(root, "tasks")
	dropped, err := thawDroppedIDs(db, dir)
	if err != nil {
		t.Fatalf("thawDroppedIDs: %v", err)
	}
	want := []string{
		"01TEST00000000000000000AAA",
		"01TEST00000000000000000MMM",
		"01TEST00000000000000000ZZZ",
	}
	if strings.Join(dropped, ",") != strings.Join(want, ",") {
		t.Errorf("dropped IDs not sorted: got %v want %v", dropped, want)
	}
}

// TestThawLockSurvivesThaw pins the by-design behaviour that locks are
// runtime-only and are intentionally excluded from the guard diff:
//
//   - A held lock does NOT cause a thaw refusal (the guard diffs tasks, notes,
//     and dep edges — never lock state, which cannot exist in tasks/*.json).
//   - A held lock is NOT dropped by a successful thaw — the lock is still held
//     after thaw returns (thaw saves live claims before the drop-and-reinsert
//     and restores them into the reinserted row).
//
// This test runs on its own isolated temp repo, never against the sandbox DB.
func TestThawLockSurvivesThaw(t *testing.T) {
	root := thawTestRepo(t)

	// A task that is frozen+live so it survives the thaw reinsert.
	freezeTaskJSON(t, root, frozenID, "a frozen task held by an agent")
	addLiveTask(t, root, frozenID, "a frozen task held by an agent")

	// Acquire a lock on the task — written directly into the live DB to simulate
	// an agent that has claimed the task and is mid-flight during the thaw.
	const lockHolder = "session-agent-XYZ"
	lockNow := timeToMs(time.Now().UTC())
	{
		db, err := openDB()
		if err != nil {
			t.Fatalf("openDB for lock: %v", err)
		}
		_, lockErr := db.Exec(
			`UPDATE tasks SET locked_by=?, locked_at=? WHERE id=?`,
			lockHolder, lockNow, frozenID,
		)
		db.Close()
		if lockErr != nil {
			t.Fatalf("set lock: %v", lockErr)
		}
	}

	// Verify the lock is held before the thaw.
	assertLock := func(label string) {
		t.Helper()
		db, err := openDB()
		if err != nil {
			t.Fatalf("%s openDB: %v", label, err)
		}
		defer db.Close()
		var lockedBy sql.NullString
		if err := db.QueryRow(`SELECT locked_by FROM tasks WHERE id=?`, frozenID).Scan(&lockedBy); err != nil {
			t.Fatalf("%s: query locked_by: %v", label, err)
		}
		if !lockedBy.Valid || lockedBy.String != lockHolder {
			t.Errorf("%s: expected locked_by=%q, got %v", label, lockHolder, lockedBy)
		}
	}
	assertLock("before thaw")

	// A thaw on a DB where every task is also frozen must NOT refuse (the guard
	// diff sees no live-only tasks/notes/dep-edges; lock state is excluded from
	// the diff by design — locks are tagged json:"-" and never appear in
	// tasks/*.json).
	if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
		t.Fatalf("thaw with a held lock must not refuse, got: %v", err)
	}

	// After the thaw the lock must still be held — thaw carries live claims
	// across the drop-and-reinsert (thawLiveClaims / thawRestoreClaims).
	assertLock("after thaw")
}

// freezeTaskJSONWithStatus writes a canonical task-<id>.json with an explicit
// status (e.g. "done", "blocked") into tasks/. Used by thawRestoreClaims branch
// tests where the frozen state differs from the live-DB lock state.
func freezeTaskJSONWithStatus(t *testing.T, root, id, title string, status Status) {
	t.Helper()
	now := time.Now().UTC()
	task := &Task{ID: id, Title: title, Status: status, CreatedAt: now, UpdatedAt: now}
	if err := writeJSON(filepath.Join(root, "tasks", "task-"+id+".json"), task); err != nil {
		t.Fatalf("write task json %s: %v", id, err)
	}
}

// lockTaskWithStatus sets locked_by/locked_at on a task and optionally updates
// its status column, simulating an agent that has claimed the task. The task
// must already exist in the live DB.
func lockTaskWithStatus(t *testing.T, id, lockHolder string, claimStatus Status) {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB for lock: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(
		`UPDATE tasks SET locked_by=?, locked_at=?, status=? WHERE id=?`,
		lockHolder, timeToMs(time.Now().UTC()), string(claimStatus), id,
	)
	if err != nil {
		t.Fatalf("lockTaskWithStatus %s: %v", id, err)
	}
}

// taskStatus reads the current status column of a task from the live DB.
func taskStatus(t *testing.T, id string) string {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	var status string
	if err := db.QueryRow(`SELECT status FROM tasks WHERE id=?`, id).Scan(&status); err != nil {
		t.Fatalf("taskStatus %s: %v", id, err)
	}
	return status
}

// taskLockedBy reads the current locked_by column of a task from the live DB.
// Returns "" if the task is absent or the lock is NULL.
func taskLockedBy(t *testing.T, id string) string {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	var lockedBy sql.NullString
	err = db.QueryRow(`SELECT locked_by FROM tasks WHERE id=?`, id).Scan(&lockedBy)
	if err != nil {
		// Row absent (deleted-task case): return empty, not a fatal error.
		return ""
	}
	if !lockedBy.Valid {
		return ""
	}
	return lockedBy.String
}

// TestThawRestoreClaimsTerminalDrop pins the terminal-drop branch of
// thawRestoreClaims: when a task is frozen with a terminal status ("done" or
// "blocked"), an in-flight lock on it is NOT carried across the thaw — the
// canonical frozen terminal status beats the unfrozen in-progress claim.
//
// Mechanism: thawRestoreClaims's UPDATE carries the lock only onto rows whose
// status is NOT IN ('done','blocked'). A frozen-done row is reinserted as done,
// so the WHERE predicate matches nothing → RowsAffected == 0 → claim dropped.
func TestThawRestoreClaimsTerminalDrop(t *testing.T) {
	const taskID = "01THAWTEST00000000TERMINAL1"
	const lockHolder = "session-terminal-drop"

	for _, terminalStatus := range []Status{StatusDone, StatusBlocked} {
		terminalStatus := terminalStatus // capture
		t.Run(string(terminalStatus), func(t *testing.T) {
			root := thawTestRepo(t)

			// Freeze the task with the terminal status (canonical state says it is
			// finished) and insert it live with the same terminal status so the
			// drop-guard sees no discrepancy.
			freezeTaskJSONWithStatus(t, root, taskID, "terminal task", terminalStatus)
			now := timeToMs(time.Now().UTC())
			db0, err := openDB()
			if err != nil {
				t.Fatalf("openDB: %v", err)
			}
			if _, err := db0.Exec(
				`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
				taskID, "terminal task", "", string(terminalStatus), 0, now, now,
			); err != nil {
				db0.Close()
				t.Fatalf("insert task: %v", err)
			}
			db0.Close()

			// Simulate an in-flight agent that holds a lock on this task.
			lockTaskWithStatus(t, taskID, lockHolder, StatusInProgress)

			// Run the thaw. The drop-guard passes (both DB and JSON have the task).
			if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
				t.Fatalf("thaw must not refuse, got: %v", err)
			}

			// The task must survive the reinsert (it was in the JSON).
			ids := liveTaskIDs(t)
			if !ids[taskID] {
				t.Fatalf("task %s must exist after thaw", taskID)
			}

			// The claim must NOT be carried: the frozen terminal status beats the
			// unfrozen in-progress claim (thawRestoreClaims drops it).
			if lb := taskLockedBy(t, taskID); lb != "" {
				t.Errorf("terminal-drop: lock must be dropped after thaw, but locked_by=%q", lb)
			}

			// The task status must remain the frozen terminal status (not flipped
			// to in-progress, since the carry was dropped).
			if s := taskStatus(t, taskID); Status(s) != terminalStatus {
				t.Errorf("terminal-drop: status must stay %q after thaw, got %q", terminalStatus, s)
			}
		})
	}
}

// TestThawRestoreClaimsDeletedTask pins the deleted-task branch of
// thawRestoreClaims: when a locked task is absent from the frozen JSON (the task
// was removed from tasks/*.json on a branch switch), the claim is silently dropped
// — the deleted task simply does not exist for the UPDATE to match.
//
// The drop-guard normally refuses a thaw that would erase a live-only task, so
// this test uses --force to exercise the post-drop-guard path in thawRestoreClaims.
// (The real-world trigger is a post-checkout thaw switching to a branch where the
// task's JSON file does not exist; --force is what the git hook uses in that case.)
func TestThawRestoreClaimsDeletedTask(t *testing.T) {
	const deletedTaskID = "01THAWTEST00000000DELETED01"
	const anchorTaskID = "01THAWTEST00000000ANCHOR001"
	const lockHolder = "session-deleted-task"

	root := thawTestRepo(t)

	// An anchor task that is frozen+live — it gives the thaw something to
	// reinsert, confirming the thaw ran successfully.
	freezeTaskJSON(t, root, anchorTaskID, "anchor task")
	addLiveTask(t, root, anchorTaskID, "anchor task")

	// The deleted task: present in the live DB, absent from tasks/*.json. It
	// carries a lock, simulating a running agent whose task was removed from the
	// canonical store during the same branch switch that triggered the thaw.
	addLiveTask(t, root, deletedTaskID, "task removed from frozen store")
	lockTaskWithStatus(t, deletedTaskID, lockHolder, StatusInProgress)

	// Without --force the drop-guard must refuse (the deleted task is live-only).
	if err := cmdThaw(openDBForTest(t), []string{}); err == nil {
		t.Fatal("expected thaw to refuse the live-only deleted task, got nil error")
	}

	// With --force the thaw proceeds; the deleted task is not reinserted (absent
	// from JSON), so thawRestoreClaims finds no row to UPDATE → claim is dropped.
	if err := cmdThaw(openDBForTest(t), []string{"--force"}); err != nil {
		t.Fatalf("--force thaw must proceed, got: %v", err)
	}

	// The anchor task survives the reinsert.
	if ids := liveTaskIDs(t); !ids[anchorTaskID] {
		t.Errorf("anchor task %s must survive the --force thaw", anchorTaskID)
	}

	// The deleted task must be gone after the --force thaw.
	if ids := liveTaskIDs(t); ids[deletedTaskID] {
		t.Errorf("deleted task %s must be absent after --force thaw", deletedTaskID)
	}

	// taskLockedBy returns "" for an absent row; that is the expected state.
	if lb := taskLockedBy(t, deletedTaskID); lb != "" {
		t.Errorf("deleted-task: locked_by must be empty for absent task, got %q", lb)
	}
}

// TestThawRestoreClaimsOpenToInProgress pins the open->in-progress flip branch
// of thawRestoreClaims: when an agent held a task as in-progress (the live DB
// row had status=in-progress + a lock) and the frozen JSON has the same task as
// open (the JSON was committed before the agent claimed it), thaw carries the
// lock AND flips the reinserted open row back to in-progress so the running
// agent is not surprised by a silent status regression.
//
// Mechanism: after thawRestoreClaims re-applies the lock (the UPDATE succeeds
// because the reinserted row is not terminal), it checks c.status == "in-progress"
// and issues UPDATE SET status='in-progress' WHERE id=? AND status='open'.
func TestThawRestoreClaimsOpenToInProgress(t *testing.T) {
	const taskID = "01THAWTEST00000000INPROG001"
	const lockHolder = "session-open-to-inprogress"

	root := thawTestRepo(t)

	// Freeze the task as open (the JSON was committed before the agent claimed it).
	freezeTaskJSON(t, root, taskID, "task frozen as open, claimed as in-progress")

	// Insert the task live as open, then simulate the agent claiming it
	// (status → in-progress, lock set).
	addLiveTask(t, root, taskID, "task frozen as open, claimed as in-progress")
	lockTaskWithStatus(t, taskID, lockHolder, StatusInProgress)

	// Verify the pre-thaw state: task is locked and in-progress in the live DB.
	if s := taskStatus(t, taskID); s != string(StatusInProgress) {
		t.Fatalf("pre-thaw status must be in-progress, got %q", s)
	}
	if lb := taskLockedBy(t, taskID); lb != lockHolder {
		t.Fatalf("pre-thaw locked_by must be %q, got %q", lockHolder, lb)
	}

	// Run the thaw. The drop-guard passes (task is in both DB and JSON). The
	// thaw DELETEs and reinserts from JSON (status reset to open), then
	// thawRestoreClaims carries the lock and flips the status back to in-progress.
	if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
		t.Fatalf("thaw must not refuse, got: %v", err)
	}

	// The task must survive the reinsert.
	if ids := liveTaskIDs(t); !ids[taskID] {
		t.Fatalf("task %s must exist after thaw", taskID)
	}

	// The lock must be carried across the thaw.
	if lb := taskLockedBy(t, taskID); lb != lockHolder {
		t.Errorf("open->in-progress: lock must survive thaw; locked_by=%q, want %q", lb, lockHolder)
	}

	// The status must have been flipped from open (frozen value) back to
	// in-progress (the agent's live claim status) — the flip branch in
	// thawRestoreClaims.
	if s := taskStatus(t, taskID); s != string(StatusInProgress) {
		t.Errorf("open->in-progress flip: status must be in-progress after thaw, got %q", s)
	}
}

// freezeTaskJSONWithBranch writes a canonical task-<id>.json with an explicit
// branch field into tasks/. Used by thawRestoreClaims branch-carry tests where
// the frozen branch differs from (or is absent from) the live-lock state.
func freezeTaskJSONWithBranch(t *testing.T, root, id, title, branch string) {
	t.Helper()
	now := time.Now().UTC()
	task := &Task{ID: id, Title: title, Status: StatusOpen, Branch: branch, CreatedAt: now, UpdatedAt: now}
	if err := writeJSON(filepath.Join(root, "tasks", "task-"+id+".json"), task); err != nil {
		t.Fatalf("write task json %s: %v", id, err)
	}
}

// setLiveBranch sets the branch column on a task that already exists in the
// live DB, simulating an agent that has set a branch on its claimed task.
func setLiveBranch(t *testing.T, id, branch string) {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB for setLiveBranch: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE tasks SET branch=? WHERE id=?`, branch, id); err != nil {
		t.Fatalf("setLiveBranch %s: %v", id, err)
	}
}

// taskBranch reads the current branch column of a task from the live DB.
func taskBranch(t *testing.T, id string) string {
	t.Helper()
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	var branch string
	if err := db.QueryRow(`SELECT branch FROM tasks WHERE id=?`, id).Scan(&branch); err != nil {
		t.Fatalf("taskBranch %s: %v", id, err)
	}
	return branch
}

// TestThawRestoreClaimsBranchCarry pins the branch-carry guard of
// thawRestoreClaims: the UPDATE in thawRestoreClaims carries the live lock's
// branch ONLY when the frozen branch is empty (WHERE branch=”). When the
// frozen branch is non-empty it wins — the live lock's branch is a no-op.
//
// Mechanism: thawRestoreClaims issues
//
//	UPDATE tasks SET branch=? WHERE id=? AND branch=''
//
// After the drop-and-reinsert the row's branch column holds the frozen value.
// If that value is non-empty the WHERE predicate does not match → the live
// lock's branch is not applied → the frozen branch survives.
// If the frozen branch is empty the predicate matches → the live lock's branch
// IS applied.
//
// Two sub-tests cover both sides of the predicate:
//
//	(a) frozen non-empty branch — live lock's branch is a no-op, frozen branch wins.
//	(b) frozen empty branch — live lock's branch IS carried.
func TestThawRestoreClaimsBranchCarry(t *testing.T) {
	const taskID = "01THAWTEST00000000BRANCHCRY"
	const lockHolder = "session-branch-carry"
	const frozenBranch = "wave13b/frozen-branch"
	const liveBranch = "wave13b/live-lock-branch"

	// (a) Frozen non-empty branch wins over the live lock's branch.
	t.Run("frozen-branch-wins", func(t *testing.T) {
		root := thawTestRepo(t)

		// Freeze the task with a non-empty branch (this is the canonical state).
		freezeTaskJSONWithBranch(t, root, taskID, "task frozen with a branch", frozenBranch)

		// Insert the task live as open with no branch, then simulate the agent
		// setting a DIFFERENT branch and acquiring a lock on it.
		addLiveTask(t, root, taskID, "task frozen with a branch")
		setLiveBranch(t, taskID, liveBranch)
		lockTaskWithStatus(t, taskID, lockHolder, StatusInProgress)

		// Verify pre-thaw state: live DB has the live branch.
		if b := taskBranch(t, taskID); b != liveBranch {
			t.Fatalf("pre-thaw branch must be %q, got %q", liveBranch, b)
		}

		// Run the thaw. The drop-guard passes (task is in both DB and JSON).
		if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
			t.Fatalf("thaw must not refuse, got: %v", err)
		}

		// The task must survive the reinsert.
		if ids := liveTaskIDs(t); !ids[taskID] {
			t.Fatalf("task %s must exist after thaw", taskID)
		}

		// The frozen non-empty branch must win: the live lock's branch is NOT
		// applied because the WHERE AND branch='' predicate does not match.
		if b := taskBranch(t, taskID); b != frozenBranch {
			t.Errorf("frozen-branch-wins: branch must be frozen value %q after thaw, got %q", frozenBranch, b)
		}
	})

	// (b) Frozen empty branch: the live lock's branch IS carried.
	t.Run("frozen-empty-branch-carry", func(t *testing.T) {
		root := thawTestRepo(t)

		// Freeze the task with an empty branch (omitempty means branch is absent
		// from the JSON; thaw reinserts the row with branch='').
		freezeTaskJSON(t, root, taskID, "task frozen without a branch")

		// Insert the task live as open, then simulate the agent setting a branch
		// and acquiring a lock.
		addLiveTask(t, root, taskID, "task frozen without a branch")
		setLiveBranch(t, taskID, liveBranch)
		lockTaskWithStatus(t, taskID, lockHolder, StatusInProgress)

		// Verify pre-thaw state: live DB has the live branch.
		if b := taskBranch(t, taskID); b != liveBranch {
			t.Fatalf("pre-thaw branch must be %q, got %q", liveBranch, b)
		}

		// Run the thaw.
		if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
			t.Fatalf("thaw must not refuse, got: %v", err)
		}

		// The task must survive the reinsert.
		if ids := liveTaskIDs(t); !ids[taskID] {
			t.Fatalf("task %s must exist after thaw", taskID)
		}

		// The frozen branch is empty, so the live lock's branch IS applied by
		// the WHERE AND branch='' predicate.
		if b := taskBranch(t, taskID); b != liveBranch {
			t.Errorf("frozen-empty-branch-carry: branch must be live value %q after thaw, got %q", liveBranch, b)
		}
	})
}

// TestThawRestoreClaimsIndexMatchesTestFuncs is the anti-drift guard for the
// thawRestoreClaims doc-comment branch coverage index in thaw.go.
//
// It parses the "Branch coverage index (thaw_test.go):" block from the
// thawRestoreClaims doc-comment and cross-checks it against the real
// func Test… names in this package:
//
//  1. Every name listed in the index (numbered AND incidental) must resolve to
//     a real func Test… declared in thaw_test.go (no phantom entries).
//  2. All four PINNED branches — numbered (1)–(4) — must be present in the
//     index (no silent removal of a branch test).
//
// Both sides are computed from the live source files; nothing is a
// literal-frozen constant, so a future edit that renames both the doc-comment
// entry and the test function stays green, while a one-sided edit fails here.
func TestThawRestoreClaimsIndexMatchesTestFuncs(t *testing.T) {
	// Locate the source files alongside this test file.
	// os.Getwd() during `go test` is the package directory.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	thawGoPath := filepath.Join(wd, "thaw.go")
	thawTestPath := filepath.Join(wd, "thaw_test.go")

	// ------------------------------------------------------------------ //
	// Step 1: parse the thawRestoreClaims branch coverage index from thaw.go.
	// ------------------------------------------------------------------ //
	indexedNames, pinnedCount, err := parseThawRestoreClaimsIndex(thawGoPath)
	if err != nil {
		t.Fatalf("parsing thaw.go branch coverage index: %v", err)
	}
	if len(indexedNames) == 0 {
		t.Fatal("no names found in thawRestoreClaims branch coverage index — anchor gone?")
	}
	if pinnedCount == 0 {
		t.Fatal("no numbered (pinned) branches found in thawRestoreClaims index — anchor gone?")
	}

	// ------------------------------------------------------------------ //
	// Step 2: collect all func Test… names declared in thaw_test.go.
	// ------------------------------------------------------------------ //
	realTestFuncs, err := parseTestFuncNames(thawTestPath)
	if err != nil {
		t.Fatalf("parsing thaw_test.go func Test names: %v", err)
	}
	if len(realTestFuncs) == 0 {
		t.Fatal("no func Test... names found in thaw_test.go — file may be empty?")
	}

	// ------------------------------------------------------------------ //
	// Step 3: every indexed name must resolve to a real func Test….
	// ------------------------------------------------------------------ //
	for _, name := range indexedNames {
		if !realTestFuncs[name] {
			t.Errorf("index entry %q is not a real func Test… in thaw_test.go "+
				"(phantom entry — update the doc-comment in thaw.go or add the missing test)", name)
		}
	}

	// ------------------------------------------------------------------ //
	// Step 4: all four pinned branches must be in the index.
	// ------------------------------------------------------------------ //
	const wantPinned = 4
	if pinnedCount != wantPinned {
		t.Errorf("thawRestoreClaims branch coverage index has %d numbered (pinned) branches, want %d "+
			"(one of the four canonical thawRestoreClaims branches was removed from the index — "+
			"restore it or update the pinned-count expectation here)", pinnedCount, wantPinned)
	}
}

// parseThawRestoreClaimsIndex reads path (thaw.go), finds the
// "Branch coverage index (thaw_test.go):" block inside the thawRestoreClaims
// doc-comment, and returns:
//   - indexedNames: every TestXxx name listed (numbered and incidental)
//   - pinnedCount:  count of NUMBERED entries ( "(N)" prefix lines )
//
// The block is bounded by the first "// Branch coverage index" line and ends
// at the first line that is NOT a doc-comment continuation (// prefix) after
// the block starts, OR at the "func thawRestoreClaims" declaration line.
// Returns an error if the anchor comment is not found.
func parseThawRestoreClaimsIndex(path string) (names []string, pinned int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// The index block starts at this anchor comment.
		if strings.Contains(trimmed, "Branch coverage index") && strings.HasPrefix(trimmed, "//") {
			inBlock = true
			continue
		}

		if !inBlock {
			continue
		}

		// End of the block: the function declaration itself.
		if strings.HasPrefix(trimmed, "func thawRestoreClaims") {
			break
		}

		// Any non-comment line ends the block too.
		if !strings.HasPrefix(trimmed, "//") {
			break
		}

		// Parse an index entry.  Expected forms:
		//   //   (N) label:        TestXxxName
		//   //   incidental:       TestXxxName
		// The test function name is the last whitespace-separated token on the line.
		stripped := strings.TrimPrefix(trimmed, "//")
		stripped = strings.TrimSpace(stripped)
		if stripped == "" {
			continue
		}

		fields := strings.Fields(stripped)
		if len(fields) < 2 {
			continue
		}
		// The last field is the test function name.
		candidate := fields[len(fields)-1]
		if !strings.HasPrefix(candidate, "Test") {
			continue
		}
		names = append(names, candidate)

		// A numbered entry starts with "(N)" where N is a digit.
		first := fields[0]
		if strings.HasPrefix(first, "(") && strings.HasSuffix(first, ")") {
			inner := first[1 : len(first)-1]
			// Must be purely numeric to count as a pinned branch.
			allDigits := true
			for _, r := range inner {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if allDigits && len(inner) > 0 {
				pinned++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	if !inBlock {
		return nil, 0, fmt.Errorf("anchor comment 'Branch coverage index' not found in %s", path)
	}
	return names, pinned, nil
}

// parseTestFuncNames reads path (thaw_test.go) and returns the set of
// top-level func Test… names declared in the file.  Lines of the form
// "func TestXxx(" are collected; sub-tests (t.Run) are not collected since
// they are anonymous string literals, not declared function names.
func parseTestFuncNames(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "func Test") {
			continue
		}
		// Extract the name: "func TestFoo(t *testing.T)" → "TestFoo"
		after := strings.TrimPrefix(line, "func ")
		paren := strings.Index(after, "(")
		if paren < 0 {
			continue
		}
		name := after[:paren]
		if strings.HasPrefix(name, "Test") {
			out[name] = true
		}
	}
	return out, scanner.Err()
}

// ---------------------------------------------------------------------------
// searchsvc_ingest defensive cleanups (reviewer-flagged, low priority):
//   - the batch-unsupported sentinel is matched with errors.Is, so a future
//     %w-wrap of errIngestBatchUnsupported still triggers the per-chunk fallback
//     instead of silently being treated as a hard transport failure.
//   - the /ingest_batch chunk count is DS_SEARCHSVC_INGEST_BATCH-overridable,
//     parsed once with a >=1 clamp and a loud fallback on an invalid value.
// These pin the production code in searchsvc_ingest.go; they live here (an owned
// general taskdb test file) under strict file fencing, not in the ingest test
// files this unit does not own.
// ---------------------------------------------------------------------------

// TestErrIngestBatchUnsupported_MatchesThroughWrap is the load-bearing guard for
// the errors.Is switch: the 404 batch→per-chunk fallback keys off the
// errIngestBatchUnsupported sentinel, and pushChangedChunks now matches it with
// errors.Is, NOT ==. A future refactor that returns the sentinel %w-wrapped (for
// added context) must still be recognized as "batch verb unsupported" so the
// fallback fires; a bare == compare would silently miss the wrap and treat the
// 404 as a hard transport failure (degraded, corpus never ingested by an older
// service). This asserts both that the bare sentinel matches AND that a wrap
// matches, while an unrelated error does not.
func TestErrIngestBatchUnsupported_MatchesThroughWrap(t *testing.T) {
	if !errors.Is(errIngestBatchUnsupported, errIngestBatchUnsupported) {
		t.Fatal("the bare sentinel must match itself under errors.Is")
	}
	wrapped := fmt.Errorf("postIngestBatch: %w", errIngestBatchUnsupported)
	if !errors.Is(wrapped, errIngestBatchUnsupported) {
		t.Fatalf("a %%w-wrapped sentinel must match under errors.Is, got no match for %v", wrapped)
	}
	// A doubly-wrapped sentinel still matches (errors.Is walks the whole chain).
	doubly := fmt.Errorf("outer: %w", wrapped)
	if !errors.Is(doubly, errIngestBatchUnsupported) {
		t.Fatalf("a doubly-wrapped sentinel must still match under errors.Is, got no match for %v", doubly)
	}
	// An unrelated error must NOT match — the fallback must be specific to the
	// 404-batch-unsupported signal, never any transport error.
	if errors.Is(errors.New("connection refused"), errIngestBatchUnsupported) {
		t.Fatal("an unrelated error must not match the batch-unsupported sentinel")
	}
}

// TestResolveIngestBatchSize covers the DS_SEARCHSVC_INGEST_BATCH parse: an unset
// value is the silent default; a valid positive override is honored; an
// unparseable or non-positive value clamps LOUDLY back to the default (one banner
// on searchWarnOut). The full set of cases is asserted, including the banner
// presence/absence on each.
func TestResolveIngestBatchSize(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		want       int
		wantBanner bool
	}{
		{"unset is the silent default", "", defaultIngestBatchSize, false},
		{"blanks-only is the silent default", "   ", defaultIngestBatchSize, false},
		{"valid override is honored", "32", 32, false},
		{"override with surrounding space is honored", "  7  ", 7, false},
		{"one is the minimum and is honored", "1", 1, false},
		{"zero clamps loudly to the default", "0", defaultIngestBatchSize, true},
		{"negative clamps loudly to the default", "-5", defaultIngestBatchSize, true},
		{"non-integer falls back loudly to the default", "lots", defaultIngestBatchSize, true},
		{"float falls back loudly to the default", "12.5", defaultIngestBatchSize, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			restore := searchWarnOut
			searchWarnOut = &buf
			defer func() { searchWarnOut = restore }()

			got := resolveIngestBatchSize(tc.raw)
			if got != tc.want {
				t.Fatalf("resolveIngestBatchSize(%q)=%d, want %d", tc.raw, got, tc.want)
			}
			gotBanner := buf.Len() > 0
			if gotBanner != tc.wantBanner {
				t.Fatalf("resolveIngestBatchSize(%q) banner=%v, want %v (banner text: %q)", tc.raw, gotBanner, tc.wantBanner, buf.String())
			}
			if tc.wantBanner && !strings.Contains(buf.String(), ingestBatchEnvVar) {
				t.Fatalf("the fallback banner must name %s, got %q", ingestBatchEnvVar, buf.String())
			}
		})
	}
}

// TestIngestBatchSizeDefaultBinding pins that the package-level ingestBatchSize is
// resolved at init and equals the default when no override is set — the value the
// batch loop in pushChangedChunks strides by. (The wave gate runs with
// DS_SEARCHSVC_INGEST_BATCH unset, so this is the resident binding.)
func TestIngestBatchSizeDefaultBinding(t *testing.T) {
	if os.Getenv(ingestBatchEnvVar) != "" {
		t.Skipf("%s is set in this environment (%q) — default-binding assertion does not apply", ingestBatchEnvVar, os.Getenv(ingestBatchEnvVar))
	}
	if ingestBatchSize != defaultIngestBatchSize {
		t.Fatalf("ingestBatchSize=%d with %s unset, want default %d", ingestBatchSize, ingestBatchEnvVar, defaultIngestBatchSize)
	}
	if ingestBatchSize < 1 {
		t.Fatalf("ingestBatchSize=%d must always be >= 1", ingestBatchSize)
	}
}
