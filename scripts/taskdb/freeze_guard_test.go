// SPDX-License-Identifier: Apache-2.0
package main

import (
	"path/filepath"
	"testing"
	"time"
)

// TestFreezeGuardsRegression pins the freeze regression guard — the one DB→JSON
// direction that previously had no protection (thaw has the drop-guard, the merge
// driver has most-progressed-wins + newest-updated_at-wins). A freeze→commit is a
// clean edit, so the 3-way merge driver never fires to catch a stale-DB write;
// d4e1ad11 un-completed 6 `done` tasks this way. Two skips, both --force-able:
//
//	P1 — terminal-status regression (done/dropped walked backward), any timestamp.
//	P4 — on-disk row is NEWER by updated_at (a peer's later edit, or merged-in
//	     tasks/*.json this DB hasn't thawed) → don't regress scalar content.
//
// Forward progress and non-terminal churn (a newer DB) must still propagate.
func TestFreezeGuardsRegression(t *testing.T) {
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
	disk := func(id, status, title string, updated time.Time) {
		tk := &Task{ID: id, Title: title, Status: Status(status), CreatedAt: old, UpdatedAt: updated}
		if err := writeJSON(filepath.Join(dir, "task-"+id+".json"), tk); err != nil {
			t.Fatalf("disk %s: %v", id, err)
		}
	}
	onDisk := func(id string) string {
		s, _, ok := diskTaskMeta(filepath.Join(dir, "task-"+id+".json"))
		if !ok {
			t.Fatalf("diskTaskMeta(%s): not ok", id)
		}
		return string(s)
	}
	diskTitle := func(id string) string {
		var tk Task
		if err := readJSON(filepath.Join(dir, "task-"+id+".json"), &tk); err != nil {
			t.Fatalf("readJSON(%s): %v", id, err)
		}
		return tk.Title
	}

	// (DB state @when, on-disk state @when)
	seed("01STALEDONE", "open", "x", old) // disk done@recent — P1 terminal regression → keep done
	disk("01STALEDONE", "done", "x", recent)
	seed("01STALEDROP", "open", "x", old) // disk dropped@recent — P1 terminal regression → keep dropped
	disk("01STALEDROP", "dropped", "x", recent)
	seed("01FWDDONE", "done", "x", recent) // disk open@old, DB newer → forward, write done
	disk("01FWDDONE", "open", "x", old)
	seed("01REOPEN", "open", "x", recent) // disk in-progress@old, DB newer → reopen, write open
	disk("01REOPEN", "in-progress", "x", old)
	seed("01DISKNEWER", "open", "db-title", old) // disk open@recent, newer scalar → P4 → keep disk-title
	disk("01DISKNEWER", "open", "disk-title", recent)

	if err := cmdFreeze(db, nil); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if got := onDisk("01STALEDONE"); got != "done" {
		t.Fatalf("P1 done→open NOT guarded: on disk = %q, want done (kept)", got)
	}
	if got := onDisk("01STALEDROP"); got != "dropped" {
		t.Fatalf("P1 dropped→open NOT guarded: on disk = %q, want dropped (kept)", got)
	}
	if got := onDisk("01FWDDONE"); got != "done" {
		t.Fatalf("forward progress blocked: on disk = %q, want done", got)
	}
	if got := onDisk("01REOPEN"); got != "open" {
		t.Fatalf("non-terminal reopen (newer DB) blocked: on disk = %q, want open", got)
	}
	if got := diskTitle("01DISKNEWER"); got != "disk-title" {
		t.Fatalf("P4 newer-on-disk scalar NOT guarded: title = %q, want disk-title (kept)", got)
	}

	// --force lets the stale DB win, both guards (a deliberate single-owner override).
	if err := cmdFreeze(db, []string{"--force"}); err != nil {
		t.Fatalf("freeze --force: %v", err)
	}
	if got := onDisk("01STALEDONE"); got != "open" {
		t.Fatalf("--force did not override P1: on disk = %q, want open", got)
	}
	if got := diskTitle("01DISKNEWER"); got != "db-title" {
		t.Fatalf("--force did not override P4: title = %q, want db-title", got)
	}
}
