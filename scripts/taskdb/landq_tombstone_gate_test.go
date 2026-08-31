// SPDX-License-Identifier: Apache-2.0
package main

// landq_tombstone_gate_test.go pins the F9 leader-side done-tombstone gate:
// landedTaskTerminal / tombstoneLandedTasks must tombstone an enqueued --tasks id
// as "done" ONLY when that id is terminal (done/dropped) IN THE TREE THE LEADER
// JUST LANDED, and must SKIP (never tombstone) any id that is open, absent, or
// unparseable in the landed tree. This is the defense-in-depth fix for the
// 2026-06-21 false-tombstone-of-deferred-followups incident: open ids leaked into
// --tasks (a stale-tree box, or a hand `landq enqueue --tasks ...`) must not be
// marked done cross-machine while the deliverable is absent from main.
//
// PURE GIT, NO POSTGRES. landedTaskTerminal reads the landed file via
// `git show <sha>:tasks/task-<id>.json` from the throwaway worktree, so it is
// exercised against a real temp git repo (reusing gitT/writeFileT from
// landq_canonical_sync_test.go) with no lock server. The terminal-path WRITE
// (upsertTombstone) is Postgres-only and covered by the gated *Live suite; here we
// assert the gate DECISION and that the SKIP path never touches the db.

import (
	"path/filepath"
	"testing"
)

// seedTaskRepo builds a tiny git repo with the given task files committed and
// returns (repoDir, committedSHA). Each entry maps a task id to the JSON body to
// write at tasks/task-<id>.json; an empty body means "do not create this file".
func seedTaskRepo(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	gitT(t, dir, "init", "-b", "main")
	for id, body := range files {
		if body == "" {
			continue
		}
		writeFileT(t, dir, filepath.Join("tasks", "task-"+id+".json"), body)
	}
	gitT(t, dir, "add", "-A")
	gitT(t, dir, "commit", "-m", "seed")
	return dir, gitT(t, dir, "rev-parse", "HEAD")
}

func taskJSON(id, status string) string {
	return `{"id":"` + id + `","title":"t","status":"` + status + `","priority":0}`
}

func TestLandedTaskTerminal_Done(t *testing.T) {
	id := "01TERMDONE000000000000000"
	dir, sha := seedTaskRepo(t, map[string]string{id: taskJSON(id, "done")})
	ok, reason := landedTaskTerminal(dir, sha, id)
	if !ok {
		t.Fatalf("done id should be terminal, got skip: %s", reason)
	}
}

func TestLandedTaskTerminal_Dropped(t *testing.T) {
	id := "01TERMDROP000000000000000"
	dir, sha := seedTaskRepo(t, map[string]string{id: taskJSON(id, "dropped")})
	ok, reason := landedTaskTerminal(dir, sha, id)
	if !ok {
		t.Fatalf("dropped id should be terminal, got skip: %s", reason)
	}
}

func TestLandedTaskTerminal_Open_Skipped(t *testing.T) {
	// The exact F9 incident shape: an OPEN id leaked into --tasks must NOT tombstone.
	id := "01OPENLEAK000000000000000"
	dir, sha := seedTaskRepo(t, map[string]string{id: taskJSON(id, "open")})
	ok, reason := landedTaskTerminal(dir, sha, id)
	if ok {
		t.Fatalf("open id must be skipped (not tombstoned), but was treated terminal")
	}
	if reason == "" {
		t.Fatalf("skip must carry a reason for the warning log")
	}
}

func TestLandedTaskTerminal_InProgress_Skipped(t *testing.T) {
	id := "01INPROGRESS0000000000000"
	dir, sha := seedTaskRepo(t, map[string]string{id: taskJSON(id, "in-progress")})
	if ok, _ := landedTaskTerminal(dir, sha, id); ok {
		t.Fatalf("in-progress id must be skipped, but was treated terminal")
	}
}

func TestLandedTaskTerminal_MissingFile_Skipped(t *testing.T) {
	// id is NOT present in the landed tree → fail-safe: skip, never tombstone.
	other := "01OTHERTASK00000000000000"
	missing := "01MISSINGTASK000000000000"
	dir, sha := seedTaskRepo(t, map[string]string{other: taskJSON(other, "done")})
	ok, reason := landedTaskTerminal(dir, sha, missing)
	if ok {
		t.Fatalf("absent id must be skipped (under-tombstone is the safe direction)")
	}
	if reason == "" {
		t.Fatalf("missing-file skip must carry a reason")
	}
}

func TestLandedTaskTerminal_Unparseable_Skipped(t *testing.T) {
	id := "01GARBAGEJSON00000000000A"
	dir, sha := seedTaskRepo(t, map[string]string{id: "{not valid json"})
	if ok, _ := landedTaskTerminal(dir, sha, id); ok {
		t.Fatalf("unparseable landed file must be skipped, never tombstoned")
	}
}

func TestLandedTaskTerminal_NoStatusField_Skipped(t *testing.T) {
	id := "01NOSTATUS0000000000000AB"
	dir, sha := seedTaskRepo(t, map[string]string{id: `{"id":"` + id + `","title":"t"}`})
	if ok, _ := landedTaskTerminal(dir, sha, id); ok {
		t.Fatalf("landed file with no status must be skipped")
	}
}

// TestTombstoneLandedTasks_SkipPathNeverTouchesDB asserts that a --tasks list of
// ONLY non-terminal ids drives every id down the skip branch and so never calls
// ls.upsertTombstone — proving the gate, not the write, decides. We pass a
// lockServer with a nil db; if any id wrongly reached upsertTombstone it would
// dereference nil and panic the test. (The terminal-path WRITE is Postgres-only
// and is covered by the gated *Live tombstone suite.)
func TestTombstoneLandedTasks_SkipPathNeverTouchesDB(t *testing.T) {
	open1 := "01OPENONE0000000000000000"
	open2 := "01OPENTWO0000000000000000"
	absent := "01ABSENTONE00000000000000"
	dir, sha := seedTaskRepo(t, map[string]string{
		open1: taskJSON(open1, "open"),
		open2: taskJSON(open2, "blocked"),
		// absent: intentionally not created
	})
	ls := &lockServer{} // db is nil; a stray upsertTombstone would panic
	taskIDs := open1 + " " + open2 + " " + absent
	// Must not panic: all three ids are non-terminal/absent → all skipped.
	tombstoneLandedTasks(ls, dir, sha, taskIDs, "test-session", 1, "feature/x")
}
