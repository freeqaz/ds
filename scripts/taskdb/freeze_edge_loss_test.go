// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFreezeSkipPropagatesNewDepEdge pins F6: when the freeze regression guard
// SKIPS a task (on-disk row newer by updated_at — P4 — or terminal — P1), it must
// still ADDITIVELY propagate a NEW depends_on edge the DB row gained, touching
// ONLY depends_on and never regressing the protected scalars the skip deliberately
// keeps. depends_on is a union-merged field (the merge driver never drops an edge
// either side added); a blind skip would silently lose a DB-side edge whose
// updated_at trails the on-disk file — invisible, since thaw's drop-guard only
// catches the opposite direction.
func TestFreezeSkipPropagatesNewDepEdge(t *testing.T) {
	root := thawTestRepo(t)
	dir := filepath.Join(root, "tasks")

	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	old := time.Now().UTC().Add(-2 * time.Hour)
	recent := time.Now().UTC()

	seed := func(id, status, title string, updated time.Time) {
		if _, err := db.Exec(
			`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			id, title, "", status, 0, timeToMs(old), timeToMs(updated),
		); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	addDep := func(id, on string) {
		if _, err := db.Exec(`INSERT INTO task_deps(task_id,depends_on) VALUES(?,?)`, id, on); err != nil {
			t.Fatalf("addDep %s->%s: %v", id, on, err)
		}
	}
	disk := func(tk *Task) {
		if err := writeJSON(filepath.Join(dir, "task-"+tk.ID+".json"), tk); err != nil {
			t.Fatalf("disk %s: %v", tk.ID, err)
		}
	}
	read := func(id string) Task {
		var tk Task
		if err := readJSON(filepath.Join(dir, "task-"+id+".json"), &tk); err != nil {
			t.Fatalf("readJSON(%s): %v", id, err)
		}
		return tk
	}
	hasDep := func(tk Task, want string) bool {
		for _, d := range tk.DependsOn {
			if d == want {
				return true
			}
		}
		return false
	}

	// Dep targets (FK: task_deps.depends_on REFERENCES tasks(id)).
	seed("01DEPOLD0000000000000000AA", "open", "depold", old)
	seed("01DEPNEW0000000000000000AA", "open", "depnew", old)

	// P4 case: DB row carries an OLD edge + a NEW edge, updated_at OLDER than disk;
	// on disk: status open, title disk-title, edge OLD only, updated_at recent.
	// Skip fires (disk is newer) — but the NEW edge must still land, and the
	// protected scalars (title/status/updated_at) must stay at their disk values.
	const p4 = "01P4NEWEDGE000000000000AA"
	seed(p4, "open", "db-title", old)
	addDep(p4, "01DEPOLD0000000000000000AA")
	addDep(p4, "01DEPNEW0000000000000000AA")
	disk(&Task{
		ID: p4, Title: "disk-title", Status: StatusOpen,
		DependsOn: []string{"01DEPOLD0000000000000000AA"},
		CreatedAt: old, UpdatedAt: recent,
	})

	// P1 case: on-disk terminal (done) outranks the DB's open — terminal regression
	// skip — but the DB gained a NEW edge that must still propagate; the disk's
	// terminal status/title must NOT be walked back.
	const p1 = "01P1TERMEDGE0000000000AAAA"
	seed(p1, "open", "db-title", recent) // DB even NEWER, yet terminal disk still wins
	addDep(p1, "01DEPNEW0000000000000000AA")
	disk(&Task{
		ID: p1, Title: "disk-title", Status: StatusDone,
		CreatedAt: old, UpdatedAt: old,
	})

	if err := cmdFreeze(db, nil); err != nil {
		t.Fatalf("freeze: %v", err)
	}

	// --- P4 assertions ---
	got := read(p4)
	if !hasDep(got, "01DEPNEW0000000000000000AA") {
		t.Fatalf("F6 P4: new dep edge LOST on skip — depends_on = %v, want it to include the new edge", got.DependsOn)
	}
	if !hasDep(got, "01DEPOLD0000000000000000AA") {
		t.Fatalf("F6 P4: existing dep edge dropped — depends_on = %v", got.DependsOn)
	}
	// Protected scalars must be the DISK values (the skip kept them).
	if got.Title != "disk-title" {
		t.Fatalf("F6 P4: title regressed — got %q, want disk-title (scalar must be untouched)", got.Title)
	}
	if got.Status != StatusOpen {
		t.Fatalf("F6 P4: status changed — got %q, want open", got.Status)
	}
	if !got.UpdatedAt.Truncate(time.Millisecond).Equal(recent.Truncate(time.Millisecond)) {
		t.Fatalf("F6 P4: updated_at regressed — got %s, want disk's %s", got.UpdatedAt, recent)
	}

	// --- P1 assertions ---
	gp1 := read(p1)
	if !hasDep(gp1, "01DEPNEW0000000000000000AA") {
		t.Fatalf("F6 P1: new dep edge LOST on terminal-regression skip — depends_on = %v", gp1.DependsOn)
	}
	if gp1.Status != StatusDone {
		t.Fatalf("F6 P1: terminal status walked backward — got %q, want done", gp1.Status)
	}
	if gp1.Title != "disk-title" {
		t.Fatalf("F6 P1: title regressed on terminal skip — got %q, want disk-title", gp1.Title)
	}
}

// TestFreezeSkipNoEdgeDeltaLeavesFileUntouched pins that the F6 reconciliation is
// strictly additive and a no-op when the DB adds no edge: a skipped task whose DB
// depends_on is a subset of (or equal to) the on-disk set must be left BYTE-for-
// byte as the skip left it — no spurious rewrite, no scalar change.
func TestFreezeSkipNoEdgeDeltaLeavesFileUntouched(t *testing.T) {
	root := thawTestRepo(t)
	dir := filepath.Join(root, "tasks")

	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	old := time.Now().UTC().Add(-2 * time.Hour)
	recent := time.Now().UTC()

	seed := func(id, status, title string, updated time.Time) {
		if _, err := db.Exec(
			`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			id, title, "", status, 0, timeToMs(old), timeToMs(updated),
		); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("01DEPONLY000000000000000AA", "open", "dep", old)

	const id = "01NODELTA000000000000000AA"
	seed(id, "open", "db-title", old) // DB older than disk → P4 skip
	if _, err := db.Exec(`INSERT INTO task_deps(task_id,depends_on) VALUES(?,?)`, id, "01DEPONLY000000000000000AA"); err != nil {
		t.Fatalf("addDep: %v", err)
	}
	path := filepath.Join(dir, "task-"+id+".json")
	// Disk already carries the SAME edge, newer scalar.
	if err := writeJSON(path, &Task{
		ID: id, Title: "disk-title", Status: StatusOpen,
		DependsOn: []string{"01DEPONLY000000000000000AA"},
		CreatedAt: old, UpdatedAt: recent,
	}); err != nil {
		t.Fatalf("disk: %v", err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	if err := cmdFreeze(db, nil); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("F6 no-op: skipped file with no NEW edge was rewritten\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestStageOwnedSkipPropagatesNewDepEdge mirrors F6 for the stage-owned path
// (identical regression-guard skip): a skipped owned task whose DB row gained a
// new depends_on edge must still propagate that edge (depends_on only) AND have
// the reconciled file STAGED, so the additively recovered edge actually lands with
// the rest of the owned set rather than sitting unstaged in the working tree.
func TestStageOwnedSkipPropagatesNewDepEdge(t *testing.T) {
	for _, ev := range dbPathEnvVars {
		t.Setenv(ev, "")
	}
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@t")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@t")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")

	root := t.TempDir()
	gitStage(t, root, "init", "-q")
	if err := os.Mkdir(filepath.Join(root, "tasks"), 0755); err != nil {
		t.Fatal(err)
	}

	prev, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(prev) })
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	old := time.Now().UTC().Add(-2 * time.Hour)
	recent := time.Now().UTC()
	seed := func(id, status, title string, updated time.Time) {
		if _, err := db.Exec(
			`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			id, title, "", status, 0, timeToMs(old), timeToMs(updated),
		); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("01SDEPNEW000000000000000AA", "open", "depnew", old)

	const id = "01STAGEEDGE00000000000AAAA"
	seed(id, "open", "db-title", old) // DB older than disk → P4 skip
	if _, err := db.Exec(`INSERT INTO task_deps(task_id,depends_on) VALUES(?,?)`, id, "01SDEPNEW000000000000000AA"); err != nil {
		t.Fatalf("addDep: %v", err)
	}
	path := filepath.Join(root, "tasks", "task-"+id+".json")
	// Disk: newer scalar, NO edge yet.
	if err := writeJSON(path, &Task{
		ID: id, Title: "disk-title", Status: StatusOpen,
		CreatedAt: old, UpdatedAt: recent,
	}); err != nil {
		t.Fatalf("disk: %v", err)
	}

	if err := cmdStageOwned(db, []string{id}); err != nil {
		t.Fatalf("stage-owned: %v", err)
	}

	// Edge landed on disk, depends_on only; scalars kept at disk values.
	var got Task
	if err := readJSON(path, &got); err != nil {
		t.Fatalf("readJSON: %v", err)
	}
	if len(got.DependsOn) != 1 || got.DependsOn[0] != "01SDEPNEW000000000000000AA" {
		t.Fatalf("F6 stage-owned: new dep edge not propagated — depends_on = %v", got.DependsOn)
	}
	if got.Title != "disk-title" || got.Status != StatusOpen {
		t.Fatalf("F6 stage-owned: protected scalar regressed — title=%q status=%q", got.Title, got.Status)
	}

	// And the reconciled path must be STAGED (not left as an unstaged worktree edit).
	staged := gitStage(t, root, "diff", "--cached", "--name-only")
	if want := "tasks/task-" + id + ".json"; !strings.Contains(staged, want) {
		t.Fatalf("F6 stage-owned: reconciled file not staged — `git diff --cached` = %q, want %s", staged, want)
	}
}
