// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TASKDB_LOCK_REQUIRED=1 is the opt-in FAIL-CLOSED dispatch mode: when the
// shared lock server is enabled-but-unreachable, a claim/lock must REFUSE rather
// than silently fall back to a local-only lock that coordinates nothing across
// machines. FAIL-OPEN stays the byte-identical default when the flag is unset,
// and TASKDB_LOCK_DISABLE=1 (intentional solo) wins over REQUIRED. These tests
// exercise the pure policy core + the two acquisition entry points without a
// live Postgres (a bogus DSN to a refused port stands in for "unreachable").

// resetLockConfigCache clears the process-global once-caches so a t.Setenv in a
// test is actually observed by loadLockConfig()/warnDegraded() (production reads
// each at most once per process, so resetting between table cases is test-only
// and harmless). It ALSO registers a t.Cleanup that resets the caches AGAIN on
// test exit, so this test never leaks a resolved (e.g. live-enabled) config into
// a later sibling test whose own loadLockConfig() would otherwise read the stale
// memoized value (e.g. reap_session_test's TASKDB_LOCK_DISABLE expectation).
func resetLockConfigCache(t *testing.T) {
	t.Helper()
	doReset := func() {
		lockCfgOnce = sync.Once{}
		lockCfg = nil
		lockCfgErr = nil
		degradeOnce = sync.Once{}
	}
	doReset()
	t.Cleanup(doReset)
}

// deadDSN is a keyword/value DSN aimed at a refused local port with a 1s connect
// timeout, so openLockServer fails FAST (connection refused) — the "unreachable
// server" stand-in. 127.0.0.1:1 is reserved/unused and refuses immediately
// rather than routing out or hanging.
const deadDSN = "host=127.0.0.1 port=1 dbname=taskdb user=x sslmode=disable connect_timeout=1"

// TestLockRequiredError is a pure table-test of the fail-closed message: it must
// be non-nil and name the flag, the tunnel command, and the DISABLE override so
// an operator can self-serve.
func TestLockRequiredError(t *testing.T) {
	err := lockRequiredError("ssh -N -L 5433:127.0.0.1:5432 u@h", errors.New("connection refused"))
	if err == nil {
		t.Fatal("lockRequiredError returned nil, want a non-nil refusal")
	}
	msg := err.Error()
	for _, want := range []string{
		"TASKDB_LOCK_REQUIRED",              // names the flag
		"ssh -N -L 5433:127.0.0.1:5432 u@h", // names the tunnel command
		"TASKDB_LOCK_DISABLE",               // names the DISABLE override
		"connection refused",                // surfaces the underlying cause
		"REFUSING",                          // loud
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
}

// TestLockPolicyDecision table-tests the PURE policy core across the four cases.
// cfg here is a minimal enabled config (the disabled case is handled by
// lockServerOrLocal BEFORE calling lockPolicyDecision, and is covered separately
// by the precedence test below).
func TestLockPolicyDecision(t *testing.T) {
	cfg := &lockConfig{Enabled: true}
	dummyLS := &lockServer{} // non-nil sentinel for the reachable case

	t.Run("reachable returns ls,nil regardless of REQUIRED", func(t *testing.T) {
		for _, req := range []string{"", "1"} {
			resetLockConfigCache(t)
			t.Setenv("TASKDB_LOCK_REQUIRED", req)
			ls, err := lockPolicyDecision(cfg, dummyLS, nil)
			if err != nil {
				t.Fatalf("REQUIRED=%q reachable: want nil err, got %v", req, err)
			}
			if ls != dummyLS {
				t.Fatalf("REQUIRED=%q reachable: want the ls back, got %v", req, ls)
			}
		}
	})

	t.Run("unreachable + REQUIRED unset => fail-open (nil,nil)", func(t *testing.T) {
		resetLockConfigCache(t)
		t.Setenv("TASKDB_LOCK_REQUIRED", "")
		ls, err := lockPolicyDecision(cfg, nil, errors.New("connection refused"))
		if ls != nil || err != nil {
			t.Fatalf("fail-open: want (nil,nil), got (%v,%v)", ls, err)
		}
	})

	t.Run("unreachable + REQUIRED set => fail-closed (nil,err)", func(t *testing.T) {
		resetLockConfigCache(t)
		t.Setenv("TASKDB_LOCK_REQUIRED", "1")
		ls, err := lockPolicyDecision(cfg, nil, errors.New("connection refused"))
		if ls != nil {
			t.Fatalf("fail-closed: want nil ls, got %v", ls)
		}
		if err == nil {
			t.Fatal("fail-closed: want a non-nil refusal, got nil")
		}
		if !strings.Contains(err.Error(), "TASKDB_LOCK_REQUIRED") {
			t.Errorf("refusal %q does not name the flag", err)
		}
	})
}

// TestRequiredPrecedence_DisableWins asserts DISABLE wins over REQUIRED: with
// both set, resolveLockConfig returns Enabled=false, so lockServerOrLocal()
// short-circuits to (nil,nil) BEFORE ever attempting a connection — REQUIRED is
// moot for intentional solo work, exactly as documented.
func TestRequiredPrecedence_DisableWins(t *testing.T) {
	resetLockConfigCache(t)
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	t.Setenv("TASKDB_LOCK_REQUIRED", "1")
	// Even an (irrelevant) bogus DSN must not change the outcome: DISABLE
	// short-circuits before any open.
	t.Setenv("TASKDB_LOCK_DSN", deadDSN)

	cfg, err := resolveLockConfig()
	if err != nil {
		t.Fatalf("resolveLockConfig: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("DISABLE=1 must yield Enabled=false even with REQUIRED=1 set")
	}
	ls, err := lockServerOrLocal()
	if ls != nil || err != nil {
		t.Fatalf("DISABLE wins: want (nil,nil) local-only, got (%v,%v)", ls, err)
	}
}

// newRequiredTestDB builds a temp full-schema taskdb. Unlike newDropTestDB it
// does NOT pin TASKDB_LOCK_DISABLE — each test sets the lock env it needs and
// resets the config cache so loadLockConfig observes it.
func newRequiredTestDB(t *testing.T) *sql.DB {
	t.Helper()
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

func insertOpenTask(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		id, "t-"+id, "body", "open", 0, now, now,
	); err != nil {
		t.Fatalf("insert %s: %v", id, err)
	}
}

func taskRow(t *testing.T, db *sql.DB, id string) (status, lockedBy string) {
	t.Helper()
	var lb sql.NullString
	if err := db.QueryRow(`SELECT status, locked_by FROM tasks WHERE id=?`, id).Scan(&status, &lb); err != nil {
		t.Fatalf("read task %s: %v", id, err)
	}
	return status, lb.String
}

// TestRequired_ClaimRefusesNoLocalLock is the headline acceptance: with
// TASKDB_LOCK_REQUIRED=1 and an unreachable server (bogus DSN), claimTask and
// taskLock must RETURN a non-nil error AND leave the task row open & unlocked —
// no local-only lock is acquired. Inserts NOTHING into Postgres (the dead DSN
// never connects); the temp sqlite DB is discarded with t.TempDir.
func TestRequired_ClaimRefusesNoLocalLock(t *testing.T) {
	t.Run("claimTask", func(t *testing.T) {
		resetLockConfigCache(t)
		t.Setenv("TASKDB_LOCK_DISABLE", "")
		t.Setenv("TASKDB_LOCK_REQUIRED", "1")
		t.Setenv("TASKDB_LOCK_DSN", deadDSN)

		db := newRequiredTestDB(t)
		insertOpenTask(t, db, "01REQCLAIM")

		_, err := claimTask(db, "sess-x", "01REQCLAIM")
		if err == nil {
			t.Fatal("claimTask with REQUIRED + unreachable returned nil, want a refusal")
		}
		if !strings.Contains(err.Error(), "TASKDB_LOCK_REQUIRED") {
			t.Errorf("refusal %q does not name the flag", err)
		}
		status, lockedBy := taskRow(t, db, "01REQCLAIM")
		if status != "open" {
			t.Errorf("status = %q, want open (no local claim acquired)", status)
		}
		if lockedBy != "" {
			t.Errorf("locked_by = %q, want empty (no local lock acquired)", lockedBy)
		}
	})

	t.Run("taskLock", func(t *testing.T) {
		resetLockConfigCache(t)
		t.Setenv("TASKDB_LOCK_DISABLE", "")
		t.Setenv("TASKDB_LOCK_REQUIRED", "1")
		t.Setenv("TASKDB_LOCK_DSN", deadDSN)

		db := newRequiredTestDB(t)
		insertOpenTask(t, db, "01REQLOCK")

		err := taskLock(db, []string{"01REQLOCK", "--session", "sess-y"})
		if err == nil {
			t.Fatal("taskLock with REQUIRED + unreachable returned nil, want a refusal")
		}
		if !strings.Contains(err.Error(), "TASKDB_LOCK_REQUIRED") {
			t.Errorf("refusal %q does not name the flag", err)
		}
		_, lockedBy := taskRow(t, db, "01REQLOCK")
		if lockedBy != "" {
			t.Errorf("locked_by = %q, want empty (no local lock acquired)", lockedBy)
		}
	})
}

// TestUnset_ClaimFailsOpenLocal is the fail-open default: with REQUIRED UNSET
// and an unreachable server, claimTask must NOT error — it falls back to a local
// claim, flipping the task to in-progress and locking it locally (the
// warnDegraded banner fires once, to stderr). This is today's byte-identical
// behavior; the test guards against the new code regressing it.
func TestUnset_ClaimFailsOpenLocal(t *testing.T) {
	resetLockConfigCache(t)
	t.Setenv("TASKDB_LOCK_DISABLE", "")
	t.Setenv("TASKDB_LOCK_REQUIRED", "")
	t.Setenv("TASKDB_LOCK_DSN", deadDSN)

	db := newRequiredTestDB(t)
	insertOpenTask(t, db, "01OPENCLAIM")

	tk, err := claimTask(db, "sess-z", "01OPENCLAIM")
	if err != nil {
		t.Fatalf("fail-open claim should succeed locally, got %v", err)
	}
	if tk == nil || tk.ID != "01OPENCLAIM" {
		t.Fatalf("claimTask returned %v, want the claimed task", tk)
	}
	status, lockedBy := taskRow(t, db, "01OPENCLAIM")
	if status != "in-progress" {
		t.Errorf("status = %q, want in-progress (local claim)", status)
	}
	if lockedBy != "sess-z" {
		t.Errorf("locked_by = %q, want sess-z (local claim)", lockedBy)
	}
}

// TestRequired_ReachableClaimsRemote is the positive live case: with
// TASKDB_LOCK_REQUIRED=1 and a REACHABLE server, a claim succeeds (registers
// remotely) exactly as today. It routes its server setup through
// landqServerForTest (the B7 isolation gate), so with DS_LANDQ_EPHEMERAL_PG UNSET
// it SKIPS IMMEDIATELY — before resolving any config or opening any connection —
// and never touches (let alone CLAIMS/RELEASEs a lock row on) the SHARED
// production lock server. The prior Enabled/reachable-only skip did NOT fire when
// lockserver.json is enabled and the tunnel is up, so this test otherwise
// registered a live lock row in shared prod. With the gate SET it runs against a
// throwaway Postgres and CLEANS UP its lock row in teardown.
func TestRequired_ReachableClaimsRemote(t *testing.T) {
	// Gate + ephemeral provisioning + migrate; pins TASKDB_LOCK_DSN at the
	// throwaway instance (so claimTask's own loadLockConfig→lockServerOrLocal
	// resolves to the SAME ephemeral server) and clears TASKDB_LOCK_DISABLE.
	// landqServerForTest registers ls.close() via t.Cleanup FIRST → it runs LAST.
	ls := landqServerForTest(t)

	const id = "01REQREMOTE_TEST"
	const sess = "required-reachable-test"
	// The release MUST run while ls is still OPEN. landqServerForTest registered
	// close FIRST (runs LAST, Go runs t.Cleanup LIFO); registering the release
	// here means it runs BEFORE close, on the open handle — never leaking the row.
	t.Cleanup(func() {
		_, _ = ls.release(id, sess, true)
	})
	// Best-effort pre-clean (still on the open handle) in case a prior run leaked.
	_, _ = ls.release(id, sess, true)

	t.Setenv("TASKDB_LOCK_REQUIRED", "1")
	resetLockConfigCache(t)

	db := newRequiredTestDB(t)
	insertOpenTask(t, db, id)

	tk, err := claimTask(db, sess, id)
	if err != nil {
		t.Fatalf("REQUIRED + reachable claim should succeed, got %v", err)
	}
	if tk == nil || tk.ID != id {
		t.Fatalf("claimTask returned %v, want the claimed task", tk)
	}
	// The remote registry should now hold it.
	locks, err := ls.list()
	if err != nil {
		t.Fatalf("ls.list: %v", err)
	}
	found := false
	for _, l := range locks {
		if l.TaskID == id && l.LockedBy == sess {
			found = true
		}
	}
	if !found {
		t.Errorf("remote registry missing the claimed lock for %s/%s", id, sess)
	}
}
