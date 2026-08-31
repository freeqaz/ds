// SPDX-License-Identifier: Apache-2.0
package main

// Hermetic tests for the read-only-snapshot path (taskdb 01KTYGNNWKRDPT7VPVEKNZ0QF6).
//
// The wave sandboxes ship taskdb.sqlite as a mode-0444 snapshot with no
// -wal/-shm sidecars. The old openDB always opened read-write (journal_mode(WAL)
// + _txlock=immediate + initSchema), so even a pure read verb died with
// "attempt to write a readonly database (8)". openDB now detects the unwritable
// file and opens a read-only connection (file: URI, mode=ro, immutable=1,
// query_only(1)); read verbs run, write verbs are refused up front by main with
// a single clear line naming the snapshot.
//
// These run the built binary as a subprocess against a temp repo whose
// taskdb.sqlite is chmod 0444 — the real CLI entry point, exercising openDB's
// writability probe and main's write-verb gate as a user hits them. The global
// dbReadOnly flag is process-scoped, so a subprocess is the only honest way to
// assert the per-invocation behavior without cross-test contamination.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"database/sql"

	_ "modernc.org/sqlite"
)

// buildTaskdbBin compiles the package into a temp binary once per test that
// needs it and returns its path.
func buildTaskdbBin(t *testing.T) string {
	t.Helper()
	// Isolate the spawned taskdb subprocesses from the ambient DB-path overrides.
	// runTaskdb inherits the parent env and buildTaskdbBin's go build uses
	// os.Environ(); under a wave sandbox's pinned TASKDB_DBPATH (a 0444 snapshot of
	// the LIVE corpus) an un-isolated subprocess would resolve to that snapshot
	// instead of the test's seeded temp repo — reads would return the live corpus
	// (false fail) rather than the one seeded task. Clearing both names here, the
	// shared chokepoint every read-only test calls first, pins every child to the
	// temp-repo taskdb.sqlite (cmd.Dir). See withIsolatedDBEnv in thaw_test.go.
	withIsolatedDBEnv(t)
	bin := filepath.Join(t.TempDir(), "taskdb")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build taskdb: %v\n%s", err, out)
	}
	return bin
}

// seedReadOnlyRepo builds a temp repo (its own .git/ so repoRoot resolves here)
// with a populated taskdb.sqlite, then chmods it 0444 and strips any -wal/-shm
// sidecars — exactly the wave-sandbox snapshot shape. Returns the repo root and
// the id of the one seeded task.
func seedReadOnlyRepo(t *testing.T) (root, taskID string) {
	t.Helper()
	root = t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	dbFile := filepath.Join(root, "taskdb.sqlite")

	// Seed via a direct writable connection rather than openDB (openDB resolves
	// against CWD, and we must not touch the sandbox's real DB). Mirror the
	// production schema by reusing initSchema.
	db, err := sql.Open("sqlite", dbFile+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema: %v", err)
	}
	taskID = "01TESTREADONLY0000000000AA"
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		taskID, "seed read-only task", "body", string(StatusOpen), 1, now, now,
	); err != nil {
		t.Fatalf("insert seed task: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	// Drop the WAL sidecars so the snapshot is self-contained (immutable=1 is
	// only safe without them), matching wave_sandbox provisioning.
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(dbFile + suffix)
	}
	if err := os.Chmod(dbFile, 0o444); err != nil {
		t.Fatalf("chmod 0444: %v", err)
	}
	return root, taskID
}

// runTaskdb runs the binary in root and returns combined output + exit code.
func runTaskdb(t *testing.T, bin, root string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run taskdb %v: %v", args, err)
		}
	}
	return string(out), code
}

// TestReadOnlySnapshotReadsSucceed: task get/list and status all exit 0 and
// return real content against a 0444 snapshot with no -wal/-shm.
func TestReadOnlySnapshotReadsSucceed(t *testing.T) {
	bin := buildTaskdbBin(t)
	root, taskID := seedReadOnlyRepo(t)

	t.Run("status", func(t *testing.T) {
		out, code := runTaskdb(t, bin, root, "status")
		if code != 0 {
			t.Fatalf("status exit=%d, want 0; output:\n%s", code, out)
		}
		if !strings.Contains(out, "tasks: 1 total") {
			t.Fatalf("status missing task count; output:\n%s", out)
		}
	})

	t.Run("task get", func(t *testing.T) {
		out, code := runTaskdb(t, bin, root, "task", "get", taskID)
		if code != 0 {
			t.Fatalf("task get exit=%d, want 0; output:\n%s", code, out)
		}
		if !strings.Contains(out, taskID) || !strings.Contains(out, "seed read-only task") {
			t.Fatalf("task get missing task; output:\n%s", out)
		}
	})

	t.Run("task list", func(t *testing.T) {
		out, code := runTaskdb(t, bin, root, "task", "list")
		if code != 0 {
			t.Fatalf("task list exit=%d, want 0; output:\n%s", code, out)
		}
		if !strings.Contains(out, taskID) {
			t.Fatalf("task list missing task; output:\n%s", out)
		}
	})

	t.Run("task list --ready", func(t *testing.T) {
		out, code := runTaskdb(t, bin, root, "task", "list", "--ready")
		if code != 0 {
			t.Fatalf("task list --ready exit=%d, want 0; output:\n%s", code, out)
		}
		if !strings.Contains(out, taskID) {
			t.Fatalf("task list --ready missing the ready task; output:\n%s", out)
		}
	})
}

// TestReadOnlySnapshotWritesRefused: every DB-mutating verb fails non-zero with
// the single-line refusal that names the snapshot, and does NOT surface the bare
// engine error.
func TestReadOnlySnapshotWritesRefused(t *testing.T) {
	bin := buildTaskdbBin(t)
	root, taskID := seedReadOnlyRepo(t)

	cases := []struct {
		name string
		args []string
	}{
		{"task add", []string{"task", "add", "--title", "nope"}},
		{"task set", []string{"task", "set", taskID, "--status", "done"}},
		{"task lock", []string{"task", "lock", taskID, "--session", "sess"}},
		{"note add", []string{"note", "add", "--body", "nope"}},
		{"thaw", []string{"thaw"}},
		{"freeze", []string{"freeze"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runTaskdb(t, bin, root, tc.args...)
			if code == 0 {
				t.Fatalf("%s exit=0, want non-zero; output:\n%s", tc.name, out)
			}
			if !strings.Contains(out, "read-only snapshot") {
				t.Fatalf("%s missing the read-only refusal; output:\n%s", tc.name, out)
			}
			// The refusal must name the snapshot file, not leak the raw engine error.
			if !strings.Contains(out, "taskdb.sqlite") {
				t.Fatalf("%s refusal does not name the snapshot; output:\n%s", tc.name, out)
			}
			if strings.Contains(out, "attempt to write a readonly database") {
				t.Fatalf("%s leaked the bare engine error instead of the clear refusal; output:\n%s", tc.name, out)
			}
		})
	}
}

// TestReadOnlySnapshotDidNotMutate: a refused write leaves the snapshot file
// unchanged (size + a re-read still shows exactly the one seeded task).
func TestReadOnlySnapshotDidNotMutate(t *testing.T) {
	bin := buildTaskdbBin(t)
	root, _ := seedReadOnlyRepo(t)
	dbFile := filepath.Join(root, "taskdb.sqlite")

	before, err := os.Stat(dbFile)
	if err != nil {
		t.Fatalf("stat before: %v", err)
	}
	if _, code := runTaskdb(t, bin, root, "task", "add", "--title", "nope"); code == 0 {
		t.Fatal("task add unexpectedly succeeded against read-only snapshot")
	}
	after, err := os.Stat(dbFile)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if before.Size() != after.Size() {
		t.Fatalf("snapshot size changed: before=%d after=%d", before.Size(), after.Size())
	}
	// No new sidecars either.
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(dbFile + suffix); err == nil {
			t.Fatalf("read-only open created %s sidecar", dbFile+suffix)
		}
	}

	out, code := runTaskdb(t, bin, root, "status")
	if code != 0 {
		t.Fatalf("status after refused write exit=%d; output:\n%s", code, out)
	}
	if !strings.Contains(out, "tasks: 1 total") {
		t.Fatalf("snapshot task count changed after refused write; output:\n%s", out)
	}
}

// TestWritableDBStillReadWrite: the read-only path must NOT trigger on a normal
// writable taskdb.sqlite — a mode-0644 DB still accepts writes.
func TestWritableDBStillReadWrite(t *testing.T) {
	bin := buildTaskdbBin(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	out, code := runTaskdb(t, bin, root, "task", "add", "--title", "writable")
	if code != 0 {
		t.Fatalf("task add against a fresh writable repo exit=%d; output:\n%s", code, out)
	}
	if strings.Contains(out, "read-only snapshot") {
		t.Fatalf("writable repo wrongly treated as read-only; output:\n%s", out)
	}
	if !strings.Contains(out, "writable") {
		t.Fatalf("task add did not echo the created task; output:\n%s", out)
	}
}
