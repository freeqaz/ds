// SPDX-License-Identifier: Apache-2.0
package main

// Concurrency hardening tests (B2 = F1 retry/backoff + F8 contention proof).
//
// THE BUG (F1): there was NO app-layer retry on SQLITE_BUSY anywhere in the
// taskdb write path. claimLocal's `UPDATE … RETURNING` (cores.go) is a single
// autocommit statement that upgrades to the write lock late; under many
// simultaneous claims on one shared WAL DB a fraction hard-fail with
// "database is locked (5) (SQLITE_BUSY)" once busy_timeout elapses, and an agent
// loop misreads that exit-1 as spurious idle/failure. The fix routes claimLocal
// through queryRetry (db.go), which retries ONLY a BUSY/locked failure with a
// bounded backoff ladder (0.2/0.4/0.8/1.6/3.2s) — never a constraint/FK/syntax
// error — and preserves exact-once claim semantics (a retried UPDATE…RETURNING
// updated NO row on the BUSY, so the re-run still claims at most one task).
//
// WITHOUT THE F1 FIX these tests FAIL: TestConcurrentClaimsExactlyOnce sees
// nonzero SQLITE_BUSY errors (and fewer than M successes), because the bare
// db.Query has no retry. With the fix the BUSY count is zero, every successful
// claim is a DISTINCT task id, and exactly M of N goroutines win.

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openSharedConcDB opens a NEW read-write connection to dbFile (production DSN
// shape: _txlock=immediate + WAL + foreign_keys) with an explicit busyTimeoutMs,
// so each goroutine drives an INDEPENDENT connection to the one shared WAL DB —
// the in-process stand-in for N separate `taskdb` processes contending on the
// live taskdb.sqlite.
//
// busyTimeoutMs is parameterized DELIBERATELY: the concurrency test pins it LOW
// (busyTighten ms) so the engine's own spin runs out under the collision and the
// residual SQLITE_BUSY surfaces to the app layer — exactly the cross-process load
// the production busy_timeout(15000) only widens, never eliminates. Probed: at 50
// ms, bare db.Query yields ~19/24 BUSY; queryRetry's ladder drives that to 0.
// That is what makes TestConcurrentClaimsExactlyOnce a genuine F1 regression
// guard (it FAILS on a bare db.Query, PASSES through queryRetry) rather than a
// test the raised timeout alone would pass. Each handle is closed at cleanup.
func openSharedConcDB(t *testing.T, dbFile string, busyTimeoutMs int) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf("%s?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(%d)", dbFile, busyTimeoutMs)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open shared conc DB: %v", err)
	}
	// One physical connection per handle keeps the contention honest: a pooled
	// handle could satisfy a goroutine from an idle conn and mask the BUSY race.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

// busyTighten is the low busy_timeout (ms) the contention test pins so the
// app-layer retry — not the engine spin — is the thing under test.
const busyTighten = 50

// seedReadyTasks inserts m ready (open, unlocked, dep-free, childless) tasks.
func seedReadyTasks(t *testing.T, db *sql.DB, m int) {
	t.Helper()
	now := timeToMs(time.Now().UTC())
	for i := 0; i < m; i++ {
		id := concTaskID(i)
		if _, err := db.Exec(
			`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			id, "conc-"+id, "", string(StatusOpen), 0, now, now,
		); err != nil {
			t.Fatalf("seed task %s: %v", id, err)
		}
	}
}

// concTaskID builds a deterministic 26-char ULID-shaped id for seed index i.
func concTaskID(i int) string {
	// "01CONC" + 18 zero-padded digits = 6 + 18 = 24, pad to 26.
	base := "01CONC0000000000000000"
	suffix := []byte("0000")
	d := []byte{byte('0' + (i/1000)%10), byte('0' + (i/100)%10), byte('0' + (i/10)%10), byte('0' + i%10)}
	copy(suffix, d)
	return base + string(suffix)
}

// TestConcurrentClaimsExactlyOnce spins N goroutines (N=24 > M) each calling the
// claim path against ONE shared WAL DB seeded with M (< N) ready tasks. It
// asserts: exactly M successes, every successful claim a DISTINCT task id, ZERO
// duplicate claims, and ZERO SQLITE_BUSY errors after the F1 fix. Without F1 the
// BUSY assertion FAILS (and successes < M) because claimLocal's autocommit
// UPDATE…RETURNING has no retry under contention.
func TestConcurrentClaimsExactlyOnce(t *testing.T) {
	const (
		n = 24 // goroutines
		m = 12 // ready tasks (m < n: the surplus goroutines drain to ErrNoRows)
	)
	t.Setenv("TASKDB_LOCK_DISABLE", "1") // exercise the local leg, no Postgres

	dbFile := filepath.Join(t.TempDir(), "taskdb.sqlite")
	seed := openSharedConcDB(t, dbFile, busyTighten)
	if err := initSchema(seed); err != nil {
		t.Fatalf("initSchema: %v", err)
	}
	seedReadyTasks(t, seed, m)

	type outcome struct {
		id    string
		err   error
		drain bool // claimTask returned ErrNoRows (queue drained / not ready)
		busy  bool // claim hard-failed with a SQLITE_BUSY/locked error
	}
	results := make([]outcome, n)

	// Each goroutine gets its OWN connection to the shared file, then they all
	// release together off a single barrier so the claims collide.
	dbs := make([]*sql.DB, n)
	for i := range dbs {
		dbs[i] = openSharedConcDB(t, dbFile, busyTighten)
	}

	var ready, done sync.WaitGroup
	ready.Add(n)
	done.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start // barrier: maximize collision
			task, err := claimTask(dbs[i], "sess-conc", "")
			switch {
			case err == nil:
				results[i] = outcome{id: task.ID}
			case err == sql.ErrNoRows:
				results[i] = outcome{drain: true}
			case isBusyErr(err):
				results[i] = outcome{err: err, busy: true}
			default:
				results[i] = outcome{err: err}
			}
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()

	// Tally.
	seen := map[string]int{}
	var successes, drains, busies, others int
	for _, r := range results {
		switch {
		case r.busy:
			busies++
		case r.err != nil:
			others++
			t.Errorf("unexpected non-BUSY claim error: %v", r.err)
		case r.drain:
			drains++
		default:
			successes++
			seen[r.id]++
		}
	}

	// ZERO SQLITE_BUSY after F1 (this is the regression line — it FAILS without
	// the queryRetry wrapper around claimLocal).
	if busies != 0 {
		t.Errorf("F1: expected 0 SQLITE_BUSY errors after retry/backoff, got %d", busies)
	}
	// Exactly M successes (every ready task claimed once; the surplus goroutines
	// drained to ErrNoRows).
	if successes != m {
		t.Errorf("expected exactly %d successful claims, got %d (drains=%d busy=%d other=%d)",
			m, successes, drains, busies, others)
	}
	// Every successful claim DISTINCT — no double-claim (exact-once under retry).
	for id, c := range seen {
		if c != 1 {
			t.Errorf("task %s was claimed %d times (must be exactly once)", id, c)
		}
	}
	if len(seen) != successes {
		t.Errorf("distinct claimed ids %d != successes %d (a retry double-claimed)", len(seen), successes)
	}
	// The surplus goroutines (n-m) all see a drained queue.
	if drains != n-m {
		t.Errorf("expected %d drained (ErrNoRows) goroutines, got %d", n-m, drains)
	}
}

// TestIsBusyErrClassification pins isBusyErr's precision: it must match the
// SQLITE_BUSY/locked class (primary result code 5/6, incl. extended variants)
// and must NOT match constraint/FK/other errors — only BUSY/locked may retry.
func TestIsBusyErrClassification(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	dbFile := filepath.Join(t.TempDir(), "taskdb.sqlite")
	db := openSharedConcDB(t, dbFile, 15000)
	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema: %v", err)
	}
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		"01CONCDUP000000000000DUP00", "dup", "", string(StatusOpen), 0, now, now,
	); err != nil {
		t.Fatalf("seed dup task: %v", err)
	}
	// A PRIMARY KEY collision is a genuine constraint error — execRetry must NOT
	// retry it (isBusyErr false) so it surfaces immediately, not after the ladder.
	_, cErr := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		"01CONCDUP000000000000DUP00", "dup2", "", string(StatusOpen), 0, now, now,
	)
	if cErr == nil {
		t.Fatal("expected a constraint error on duplicate primary key")
	}
	if isBusyErr(cErr) {
		t.Errorf("isBusyErr must be FALSE for a constraint error (would wrongly retry): %v", cErr)
	}
	// nil and a plain non-driver error are not BUSY.
	if isBusyErr(nil) {
		t.Error("isBusyErr(nil) must be false")
	}
	// The canonical BUSY message-text fallback (a non-driver-typed error) matches.
	if !isBusyErr(errFromString("database is locked (5) (SQLITE_BUSY)")) {
		t.Error("isBusyErr must match the canonical 'database is locked' message text")
	}
	if isBusyErr(errFromString("UNIQUE constraint failed: tasks.id")) {
		t.Error("isBusyErr must NOT match a constraint message")
	}
}

// errFromString is a tiny non-driver error carrying msg, for the message-text
// fallback arm of isBusyErr (a *sqlite.Error would take the code path instead).
type errFromString string

func (e errFromString) Error() string { return string(e) }

// TestColdThawForeignKeyCheckClean is the cold-thaw smoke (F8): a fresh temp DB,
// thaw a tiny tasks/ set, then PRAGMA foreign_key_check must return ZERO rows.
// This guards the F-status regression class (a thaw that loads rows with a
// dangling parent_id/depends_on/note.task_id leaving the rebuilt DB with FK
// violations). It reuses the in-package isolated-repo + FK-clean helpers from
// thaw_test.go (thawTestRepo / freezeTaskJSON / addLiveTask / openDBForTest /
// assertFKClean), so it stays small and shares the exact thaw drive path.
func TestColdThawForeignKeyCheckClean(t *testing.T) {
	root := thawTestRepo(t)
	// A tiny, self-consistent tasks/ set: a parent epic and a child task, plus a
	// free-standing task, plus a dep edge between two of them — every reference
	// resolves inside the frozen set, so a clean thaw must leave FK-check empty.
	const (
		epic  = "01COLDTHAW00000000000EPIC0"
		child = "01COLDTHAW00000000000CHILD"
		other = "01COLDTHAW00000000000OTHER"
	)
	freezeTaskJSON(t, root, epic, "cold-thaw epic")
	// child has parent=epic and depends_on=other — both targets are frozen below.
	freezeTaskRaw(t, root, child, "cold-thaw child", epic, []string{other})
	freezeTaskJSON(t, root, other, "cold-thaw other")

	// Cold DB: every row is JSON-only (none live), so the thaw is a pure rebuild
	// with nothing to drop — the fresh-clone / post-checkout cold path.
	if err := cmdThaw(openDBForTest(t), []string{}); err != nil {
		t.Fatalf("cold thaw of a self-consistent tasks/ set must exit 0, got: %v", err)
	}
	// Every frozen task loaded.
	ids := liveTaskIDs(t)
	for _, want := range []string{epic, child, other} {
		if !ids[want] {
			t.Errorf("cold thaw should have loaded %s", want)
		}
	}
	// The guard: zero FK violations after the rebuild.
	assertFKClean(t)
}
