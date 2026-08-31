// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// newDropTestDB builds a temp full-schema taskdb (production initSchema) and
// forces local-only locking so taskDrop's lock-clear path never reaches a real
// shared registry. Returns the live read-write DB.
func newDropTestDB(t *testing.T) *sql.DB {
	t.Helper()
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	dbFile := filepath.Join(t.TempDir(), "taskdb.sqlite")
	db, err := sql.Open("sqlite", dbFile+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema: %v", err)
	}
	return db
}

func insertDropTask(t *testing.T, db *sql.DB, id, status, lockedBy string) {
	t.Helper()
	now := timeToMs(time.Now().UTC())
	var lb, la any
	if lockedBy != "" {
		lb, la = lockedBy, now
	}
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,locked_by,locked_at,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		id, "t-"+id, "body", status, 0, lb, la, now, now,
	); err != nil {
		t.Fatalf("insert %s: %v", id, err)
	}
}

// TestTaskDrop_SetsDroppedClearsLockAddsNote proves `task drop` flips status to
// dropped, clears any held lock, and records the --reason as a note.
func TestTaskDrop_SetsDroppedClearsLockAddsNote(t *testing.T) {
	db := newDropTestDB(t)
	insertDropTask(t, db, "01DROP1", "in-progress", "sess-a")

	if err := taskDrop(db, []string{"01DROP1", "--reason", "superseded by X"}); err != nil {
		t.Fatalf("taskDrop: %v", err)
	}

	tk, err := getTask(db, "01DROP1")
	if err != nil {
		t.Fatalf("getTask: %v", err)
	}
	if tk.Status != StatusDropped {
		t.Errorf("status = %q, want dropped", tk.Status)
	}
	if tk.LockedBy != "" {
		t.Errorf("locked_by = %q, want cleared", tk.LockedBy)
	}
	var noteBody string
	if err := db.QueryRow(`SELECT body FROM notes WHERE task_id=?`, "01DROP1").Scan(&noteBody); err != nil {
		t.Fatalf("note lookup: %v", err)
	}
	if noteBody != "dropped: superseded by X" {
		t.Errorf("note = %q, want 'dropped: superseded by X'", noteBody)
	}
}

// TestTaskDrop_NoReasonNoNote proves --reason is optional: a bare drop records
// no note.
func TestTaskDrop_NoReasonNoNote(t *testing.T) {
	db := newDropTestDB(t)
	insertDropTask(t, db, "01DROP2", "open", "")
	if err := taskDrop(db, []string{"01DROP2"}); err != nil {
		t.Fatalf("taskDrop: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM notes WHERE task_id=?`, "01DROP2").Scan(&n); err != nil {
		t.Fatalf("count notes: %v", err)
	}
	if n != 0 {
		t.Errorf("note count = %d, want 0 (no --reason)", n)
	}
	if tk, _ := getTask(db, "01DROP2"); tk.Status != StatusDropped {
		t.Errorf("status = %q, want dropped", tk.Status)
	}
}

// TestTaskDrop_NotFound proves an unknown id is a clean error, not a panic.
func TestTaskDrop_NotFound(t *testing.T) {
	db := newDropTestDB(t)
	if err := taskDrop(db, []string{"01NOPE"}); err == nil {
		t.Fatal("taskDrop on missing id returned nil, want error")
	}
}

// TestDropped_IsTerminalNeverReady proves a dropped task is never ready (like
// done) AND that a dropped DEPENDENCY no longer blocks its dependents.
func TestDropped_IsTerminalNeverReady(t *testing.T) {
	db := newDropTestDB(t)
	// A is dropped; B depends on A and is open+unlocked with no children.
	insertDropTask(t, db, "01AAA", "dropped", "")
	insertDropTask(t, db, "01BBB", "open", "")
	if _, err := db.Exec(`INSERT INTO task_deps(task_id,depends_on) VALUES(?,?)`, "01BBB", "01AAA"); err != nil {
		t.Fatalf("insert dep: %v", err)
	}

	rows, err := db.Query(`SELECT t.id FROM tasks t WHERE ` + readyWhere + ` ORDER BY t.id`)
	if err != nil {
		t.Fatalf("ready query: %v", err)
	}
	defer rows.Close()
	var ready []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		ready = append(ready, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	// A (dropped) must NOT be ready; B must be ready because its only dep is
	// terminal (dropped unblocks exactly as done would).
	for _, id := range ready {
		if id == "01AAA" {
			t.Error("dropped task 01AAA appeared in ready set — dropped must be terminal")
		}
	}
	sawB := false
	for _, id := range ready {
		if id == "01BBB" {
			sawB = true
		}
	}
	if !sawB {
		t.Errorf("01BBB not ready; a dropped dependency must unblock dependents (got ready=%v)", ready)
	}
}
