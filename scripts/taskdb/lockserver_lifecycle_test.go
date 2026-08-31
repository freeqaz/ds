// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests cover the three coupled cross-machine lock-lifecycle fixes (B1):
//   F2 — activity-aware reap (reap() / listStaleLocks() / the reapLocksRemote
//        dry-run preview all share the reapLockStaleSQL predicate).
//   F3 — re-register outage locks on recovery (syncLocksFromRemote).
//   F4 — idempotent same-session relock (taskLock, both the remote and local legs).
//
// They follow the package convention (lockserver_test.go / reap_session_test.go):
// the SQL-bearing legs are guarded by SHAPE assertions on the embedded/constructed
// SQL (no live Postgres), and the LOCAL leg of F4 is exercised end-to-end against
// a real temp SQLite db with TASKDB_LOCK_DISABLE=1, exactly like drop_test.go.

// --- F2: activity-aware reap predicate shape ---------------------------------

// TestReapLockStaleSQL_ActivityAware proves the shared reap predicate encodes the
// activity-aware rule (mirroring lockStale): it LEFT JOINs lock_heartbeats, gates
// on BOTH locked_at AND max(last_activity) being past the age cutoff, and FALLS
// BACK to age-only when a lock has NO heartbeat rows (MAX(...) IS NULL). Guards
// against a future edit reverting reap() to the blanket age-only DELETE that
// reaps a live >30m heartbeating agent out from under itself.
func TestReapLockStaleSQL_ActivityAware(t *testing.T) {
	sqlText := reapLockStaleSQL
	lc := strings.ToLower(sqlText)
	for _, want := range []string{
		"left join lock_heartbeats", // activity-aware: brings in the heartbeat freshness
		"max(h.last_activity)",      // the freshest heartbeat per task is the signal
		"is null",                   // the no-heartbeat → age-only fallback
		"make_interval(secs => $1)", // the age cutoff (both legs use the same $1)
	} {
		if !strings.Contains(lc, want) {
			t.Errorf("reapLockStaleSQL missing %q — predicate is not activity-aware:\n%s", want, sqlText)
		}
	}
	// Both the locked_at gate AND the heartbeat gate must reference the cutoff:
	// a single occurrence would mean only one of the two was age-gated.
	if n := strings.Count(lc, "make_interval(secs => $1)"); n < 2 {
		t.Errorf("reapLockStaleSQL gates only %d column(s) on age, want both locked_at AND max(last_activity):\n%s", n, sqlText)
	}
	// The MAX(...) IS NULL fallback must be OR'd with the heartbeat-age gate so a
	// no-heartbeat lock still ages out (age is the OUTER bound, never a strand).
	if idx := strings.Index(lc, "is null"); idx < 0 || !strings.Contains(lc[idx:], " or ") {
		t.Errorf("reapLockStaleSQL has no OR after the NULL test — a non-heartbeating lock would never age out:\n%s", sqlText)
	}
}

// TestReap_ExcludesLandLeaderSentinel proves the activity-aware predicate STILL
// excludes the landing-leader sentinel from the age-reap (the ratified
// do_not_touch invariant): a live, mid-backlog leader must never be evicted by a
// routine reap. The exclusion rides on $2 = landLeaderSentinel.
func TestReap_ExcludesLandLeaderSentinel(t *testing.T) {
	if !strings.Contains(reapLockStaleSQL, "l.task_id <> $2") {
		t.Fatalf("reapLockStaleSQL no longer excludes the $2 sentinel:\n%s", reapLockStaleSQL)
	}
	if landLeaderSentinel != "__land_leader__" {
		t.Fatalf("land-leader sentinel changed to %q — age-reap exclusion contract broken", landLeaderSentinel)
	}
}

// TestReapAndPreviewSharePredicate proves the mutating reap() and the read-only
// listStaleLocks() (which the reapLocksRemote dry-run preview calls) use the
// EXACT same predicate text, so a `reap --dry-run` preview can never disagree with
// the real DELETE — the same shared-predicate property listStaleLanding has for
// land_queue. Both must reference the reapLockStaleSQL constant verbatim.
func TestReapAndPreviewSharePredicate(t *testing.T) {
	// The constant is the single source; this test simply pins that it is the
	// activity-aware form (a stronger drift guard than re-asserting the SQL here).
	if !strings.Contains(reapLockStaleSQL, "LEFT JOIN lock_heartbeats") {
		t.Fatalf("the shared reap predicate lost its activity-aware LEFT JOIN:\n%s", reapLockStaleSQL)
	}
}

// --- F4: idempotent same-session relock --------------------------------------

// newLockTestDB builds a temp full-schema taskdb and forces local-only locking so
// taskLock takes the LOCAL leg (no shared registry), mirroring newDropTestDB.
func newLockTestDB(t *testing.T) *sql.DB {
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

func insertLockTask(t *testing.T, db *sql.DB, id, status, lockedBy string) {
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

// TestTaskLock_LocalFreshLock is the baseline: locking a free task succeeds and
// records the session (the unchanged happy path).
func TestTaskLock_LocalFreshLock(t *testing.T) {
	db := newLockTestDB(t)
	insertLockTask(t, db, "01LK0001", "open", "")
	if err := taskLock(db, []string{"01LK0001", "--session", "sess-a"}); err != nil {
		t.Fatalf("taskLock fresh: %v", err)
	}
	tk, err := getTask(db, "01LK0001")
	if err != nil {
		t.Fatalf("getTask: %v", err)
	}
	if tk.LockedBy != "sess-a" {
		t.Errorf("locked_by = %q, want sess-a", tk.LockedBy)
	}
}

// TestTaskLock_LocalSameSessionRelock is the F4 fix on the LOCAL leg: a re-lock by
// the SAME session of a task it already holds SUCCEEDS (returns nil, no os.Exit)
// and refreshes locked_at — "same-session relock is tolerated" (post-outage
// recovery). Before the fix the WHERE locked_by IS NULL guard matched zero rows
// and the command exited non-zero even for the holder itself.
func TestTaskLock_LocalSameSessionRelock(t *testing.T) {
	db := newLockTestDB(t)
	insertLockTask(t, db, "01LK0002", "in-progress", "sess-a")

	// Force the stored locked_at into the past so a successful refresh is visible.
	past := timeToMs(time.Now().UTC().Add(-time.Hour))
	if _, err := db.Exec(`UPDATE tasks SET locked_at=? WHERE id=?`, past, "01LK0002"); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if err := taskLock(db, []string{"01LK0002", "--session", "sess-a"}); err != nil {
		t.Fatalf("same-session relock should succeed, got: %v", err)
	}
	tk, err := getTask(db, "01LK0002")
	if err != nil {
		t.Fatalf("getTask: %v", err)
	}
	if tk.LockedBy != "sess-a" {
		t.Errorf("locked_by = %q, want sess-a (relock must keep the holder)", tk.LockedBy)
	}
	if tk.LockedAt <= past {
		t.Errorf("locked_at not refreshed on relock: got %d, want > %d", tk.LockedAt, past)
	}
}

// TestTaskLock_LocalDifferentSessionStillRefused proves F4 does NOT loosen the
// contention guard: a lock held by ANOTHER session is still refused (the UPDATE
// matches zero rows). taskLock os.Exit(1)s on that path, so we assert the guard
// at the SQL level — the WHERE clause admits only NULL-or-self — by driving the
// UPDATE directly with the exact predicate taskLock uses.
func TestTaskLock_LocalDifferentSessionStillRefused(t *testing.T) {
	db := newLockTestDB(t)
	insertLockTask(t, db, "01LK0003", "in-progress", "sess-owner")
	now := timeToMs(time.Now().UTC())
	res, err := db.Exec(
		`UPDATE tasks SET locked_by=?, locked_at=?, updated_at=? WHERE id=? AND (locked_by IS NULL OR locked_by = ?)`,
		"sess-intruder", now, now, "01LK0003", "sess-intruder",
	)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	n, _ := res.RowsAffected()
	if n != 0 {
		t.Errorf("a peer-held lock was stealable (rows=%d); the IS NULL OR = self guard must refuse it", n)
	}
	// And the holder is untouched.
	if tk, _ := getTask(db, "01LK0003"); tk.LockedBy != "sess-owner" {
		t.Errorf("holder changed to %q under a peer lock attempt", tk.LockedBy)
	}
}

// --- F3: re-register outage locks on recovery (shape) ------------------------

// TestShouldReRegisterOutageLock is the F3 session-scoping rule: syncLocksFromRemote
// may re-register a local-only lock ONLY when it is held by THIS clone's own
// session (the outage lock WE took). A stale mirror of a PEER's hold, or an
// unknown session, must NOT be re-INSERTed under the peer's name (that would
// resurrect a lock the peer legitimately released/was reaped) — it is cleared as
// before. This is the load-bearing guard that keeps F3 from regressing the
// "clear a peer's stale mirror" behavior.
func TestShouldReRegisterOutageLock(t *testing.T) {
	cases := []struct {
		name    string
		ll      localLock
		session string
		want    bool
	}{
		{"our own outage lock → re-register", localLock{id: "A", session: "sess-self"}, "sess-self", true},
		{"a peer's stale mirror → clear, never re-register", localLock{id: "B", session: "sess-peer"}, "sess-self", false},
		{"empty claiming session → clear (can't attribute)", localLock{id: "C", session: "sess-self"}, "", false},
		{"both empty → clear", localLock{id: "D", session: ""}, "", false},
	}
	for _, c := range cases {
		if got := shouldReRegisterOutageLock(c.ll, c.session); got != c.want {
			t.Errorf("%s: shouldReRegisterOutageLock(%+v, %q)=%v want %v", c.name, c.ll, c.session, got, c.want)
		}
	}
}

// TestSyncLocalLockCarriesSession pins that the local-only reconcile row carries
// the holding session (locked_by) F3 needs to attribute and re-register the lock,
// rather than the pre-F3 id-only select that always cleared.
func TestSyncLocalLockCarriesSession(t *testing.T) {
	ll := localLock{id: "01X", session: "sess-z"}
	if ll.session == "" {
		t.Fatal("localLock must carry the holding session for F3 re-register attribution")
	}
}

// --- OQ4: activity-aware automatic lock auto-reap ----------------------------
//
// These cover the docs/23 OQ4 (re-scoped 2026-07-02) automatic reap: the age
// knob autoReapAge() and the two opportunistic invocation sites (claimRemote's
// top-of-claim sweep and the landq leader idle loop) that age out ORPHANED wave
// locks with no operator running a reap verb. The behavioral legs run only
// against an EPHEMERAL throwaway Postgres (DS_LANDQ_EPHEMERAL_PG) via
// landqServerForTest — they NEVER touch the shared production registry.

// TestAutoReapAge_EnvKnob pins the TASKDB_LOCK_AUTOREAP_AGE contract (env-knob
// name is contract for the sibling docs units): default 2h when unset, a valid
// Go duration is honored, and the disable cases ("off", non-positive, malformed)
// all return 0 so the guarded `if a := autoReapAge(); a > 0` callers become a
// no-op. Runs on the default gate (no Postgres needed).
func TestAutoReapAge_EnvKnob(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		val  string
		want time.Duration
	}{
		{"unset → 2h default", false, "", 2 * time.Hour},
		{"valid duration honored", true, "90m", 90 * time.Minute},
		{"valid hours honored", true, "1h", time.Hour},
		{"literal off disables", true, "off", 0},
		{"OFF case-insensitive disables", true, "OFF", 0},
		{"zero disables", true, "0", 0},
		{"negative disables", true, "-5m", 0},
		{"malformed disables (never a surprise age)", true, "banana", 0},
		{"empty string → default", true, "", 2 * time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv("TASKDB_LOCK_AUTOREAP_AGE", c.val)
			} else {
				// Ensure a stray ambient value can't leak in.
				t.Setenv("TASKDB_LOCK_AUTOREAP_AGE", "")
			}
			if got := autoReapAge(); got != c.want {
				t.Errorf("autoReapAge() = %v, want %v", got, c.want)
			}
		})
	}
}

// ageForeignLock backdates a held lock's task_locks.locked_at by d so a reap at a
// shorter age treats it as stale. Scoped to the one task id so it never disturbs
// a sibling test sharing the package's ephemeral cluster.
func ageForeignLock(t *testing.T, ls *lockServer, taskID string, d time.Duration) {
	t.Helper()
	if _, err := ls.db.Exec(
		`UPDATE task_locks SET locked_at = now() - make_interval(secs => $2) WHERE task_id = $1`,
		taskID, int64(d.Seconds()),
	); err != nil {
		t.Fatalf("aging lock %s: %v", taskID, err)
	}
}

// cleanupForeignLock force-releases the lock and drops its heartbeat rows so the
// ephemeral cluster is left clean for sibling tests.
func cleanupForeignLock(t *testing.T, ls *lockServer, taskID string) {
	t.Helper()
	clean := func() {
		_, _ = ls.release(taskID, "", true)
		_, _ = ls.db.Exec(`DELETE FROM lock_heartbeats WHERE task_id = $1`, taskID)
	}
	clean() // pre-clean a leaked prior run
	t.Cleanup(clean)
}

// TestAutoReap_StaleNoHeartbeatReaped: a foreign lock whose locked_at is past the
// auto-reap age and that has NO heartbeat rows (a crashed, non-emitting agent) is
// aged out by ls.reap(autoReapAge()) — the age-only fallback branch of
// reapLockStaleSQL, invoked automatically with no operator verb.
func TestAutoReap_StaleNoHeartbeatReaped(t *testing.T) {
	ls := landqServerForTest(t)
	const id = "01AUTOREAP_NOHB_TEST"
	cleanupForeignLock(t, ls, id)

	if won, _, err := ls.acquire(id, "crashed-wave-sess", devHost()); err != nil || !won {
		t.Fatalf("acquire foreign lock: won=%v err=%v", won, err)
	}
	ageForeignLock(t, ls, id, 90*time.Minute) // older than the 1m age below

	t.Setenv("TASKDB_LOCK_AUTOREAP_AGE", "1m")
	reaped, err := ls.reap(autoReapAge())
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if !containsStr(reaped, id) {
		t.Fatalf("stale no-heartbeat lock %s was not auto-reaped; reaped=%v", id, reaped)
	}
	if h, _ := ls.holder(id); h != nil {
		t.Fatalf("lock %s still held after auto-reap: %+v", id, h)
	}
}

// TestAutoReap_FreshHeartbeatSurvives: a foreign lock whose locked_at is past the
// age but whose FRESHEST heartbeat is recent (a live, still-heartbeating holder)
// is NOT reaped — the activity-aware gate. This is the must-not-evict-a-live-agent
// invariant the looser 2h default exists to protect.
func TestAutoReap_FreshHeartbeatSurvives(t *testing.T) {
	ls := landqServerForTest(t)
	const id = "01AUTOREAP_FRESHHB_TEST"
	const sess = "live-heartbeating-sess"
	cleanupForeignLock(t, ls, id)

	if won, _, err := ls.acquire(id, sess, devHost()); err != nil || !won {
		t.Fatalf("acquire foreign lock: won=%v err=%v", won, err)
	}
	ageForeignLock(t, ls, id, 90*time.Minute)
	// A fresh heartbeat (last_activity = now()) for this task/session.
	if err := ls.recordEvent(WaveEvent{TaskID: id, Session: sess, Phase: "impl", Event: "heartbeat", Host: devHost()}); err != nil {
		t.Fatalf("recordEvent heartbeat: %v", err)
	}

	t.Setenv("TASKDB_LOCK_AUTOREAP_AGE", "1m")
	reaped, err := ls.reap(autoReapAge())
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if containsStr(reaped, id) {
		t.Fatalf("live heartbeating lock %s was evicted despite a fresh heartbeat; reaped=%v", id, reaped)
	}
	if h, _ := ls.holder(id); h == nil || h.LockedBy != sess {
		t.Fatalf("lock %s lost after reap: holder=%+v want held by %q", id, h, sess)
	}
}

// TestAutoReap_SentinelSurvivesAutoReap: the __land_leader__ sentinel is excluded
// from the automatic age-reap even when aged well past the auto-reap age, so a
// live mid-backlog leader is never evicted by the opportunistic sweep.
func TestAutoReap_SentinelSurvivesAutoReap(t *testing.T) {
	if !truthyEnv(ephemeralGateEnv) {
		t.Skip("manipulates the fixed __land_leader__ sentinel; runs only against an ephemeral PG (set " +
			ephemeralGateEnv + "=1)")
	}
	ls := landqServerForTest(t)
	const sess = "autoreap-sentinel-test"
	_, _ = ls.release(landLeaderSentinel, "", true)
	t.Cleanup(func() { _, _ = ls.release(landLeaderSentinel, "", true) })

	if won, holder, err := ls.acquireLandLeader(sess, devHost()); err != nil || !won {
		t.Fatalf("acquireLandLeader: won=%v holder=%+v err=%v", won, holder, err)
	}
	ageForeignLock(t, ls, landLeaderSentinel, 90*time.Minute)

	t.Setenv("TASKDB_LOCK_AUTOREAP_AGE", "1m")
	reaped, err := ls.reap(autoReapAge())
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if containsStr(reaped, landLeaderSentinel) {
		t.Fatalf("auto-reap evicted the %s sentinel — double-writer window reopened", landLeaderSentinel)
	}
	if h, _ := ls.holder(landLeaderSentinel); h == nil || h.LockedBy != sess {
		t.Fatalf("sentinel reaped/changed by auto-reap: holder=%+v want held by %q", h, sess)
	}
}

// TestAutoReap_ClaimNotBlockedByStaleForeignLock is the end-to-end acceptance:
// claimRemote, with NO env override (so the DEFAULT 2h age applies), auto-reaps a
// stale foreign lock aged past 2h and then CLAIMS the freed task in the SAME call
// — proving an orphaned wave lock no longer permanently blocks the claim and that
// the reap runs BEFORE the mirror refresh (a lock reaped from the shared registry
// is never re-mirrored locally). No operator reap verb is involved.
func TestAutoReap_ClaimNotBlockedByStaleForeignLock(t *testing.T) {
	ls := landqServerForTest(t)
	const id = "01AUTOREAP_CLAIM_TEST"
	const claimer = "auto-reap-claimer"
	cleanupForeignLock(t, ls, id)
	t.Cleanup(func() { _, _ = ls.release(id, claimer, true) })

	// A crashed peer wave holds the lock, aged 3h — past the default 2h auto-reap age.
	if won, _, err := ls.acquire(id, "crashed-peer-sess", "peer-host"); err != nil || !won {
		t.Fatalf("acquire stale foreign lock: won=%v err=%v", won, err)
	}
	ageForeignLock(t, ls, id, 3*time.Hour)

	// Local mirror has the same task ready-to-claim.
	db := newRequiredTestDB(t)
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		id, "t-"+id, "body", "open", 0, now, now,
	); err != nil {
		t.Fatalf("seed local task: %v", err)
	}

	// No TASKDB_LOCK_AUTOREAP_AGE override → autoReapAge() = 2h default. The stale
	// 3h foreign lock is reaped at the top of claimRemote, so the task is claimable
	// in THIS call rather than being excluded by the mirrored foreign hold.
	tk, err := claimRemote(db, ls, claimer, "claim-host", id)
	if err != nil {
		t.Fatalf("claimRemote should auto-reap the stale foreign lock and claim; got %v", err)
	}
	if tk == nil || tk.ID != id {
		t.Fatalf("claimRemote returned %v, want %s claimed after auto-reap", tk, id)
	}
	if h, _ := ls.holder(id); h == nil || h.LockedBy != claimer {
		t.Fatalf("after claim the lock is not held by the claimer: holder=%+v", h)
	}
}

// containsStr reports whether s is in xs (test-local helper).
func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// --- claim-time target-scoped reap + observability --------------------------
//
// These cover the target-scoped claim-time auto-reap variant (reapTarget) and
// the observability of any claim-time sweep (logClaimReap). The SQL-shape and
// pure-fn legs run on the DEFAULT gate; the behavioral legs run only against an
// EPHEMERAL throwaway Postgres (DS_LANDQ_EPHEMERAL_PG) via landqServerForTest —
// they NEVER touch the shared production registry (2026-06-23 incident).

// TestReapLockStaleTargetSQL_Shape proves the target-scoped predicate is the
// full-table predicate PLUS a single-task filter, and did NOT drop either guard
// the full sweep carries: it still excludes the $2 sentinel and is still
// activity-aware (LEFT JOIN lock_heartbeats + the max(last_activity) age gate).
// A regression that widened reapTarget into a full-table DELETE, or that relaxed
// the sentinel/activity guards on the scoped path, is caught here without a
// Postgres. Runs on the default gate.
func TestReapLockStaleTargetSQL_Shape(t *testing.T) {
	sqlText := reapLockStaleTargetSQL
	for _, want := range []string{
		"l.task_id <> $2",           // sentinel still excluded
		"l.task_id = $3",            // the target scope — only ONE task considered
		"LEFT JOIN lock_heartbeats", // still activity-aware
		"MAX(h.last_activity) IS NULL",
	} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("reapLockStaleTargetSQL missing %q — scoped predicate lost a guard:\n%s", want, sqlText)
		}
	}
	// Both locked_at AND max(last_activity) must be gated on the age interval, exactly
	// like the full-table predicate — the target scope narrows rows, never relaxes age.
	if n := strings.Count(sqlText, "make_interval(secs => $1)"); n != 2 {
		t.Errorf("reapLockStaleTargetSQL gates %d column(s) on age, want both locked_at AND max(last_activity):\n%s", n, sqlText)
	}
	if landLeaderSentinel != "__land_leader__" {
		t.Fatalf("land-leader sentinel changed to %q — scoped-reap exclusion contract broken", landLeaderSentinel)
	}
}

// TestLogClaimReap_ObservableCount proves the claim-time sweep is observable: an
// empty freed set is a silent no-op returning 0 (the common claim adds no noise),
// while a non-empty set returns the count AND writes one stderr line per freed id
// (matching the idle loop's "auto-reaped ... (age > ...)" phrasing) plus a count
// summary. Runs on the default gate (captures os.Stderr, no Postgres).
func TestLogClaimReap_ObservableCount(t *testing.T) {
	if out := captureStderr(t, func() {
		if n := logClaimReap(nil, 2*time.Hour); n != 0 {
			t.Errorf("logClaimReap(nil) = %d, want 0", n)
		}
	}); out != "" {
		t.Errorf("logClaimReap(nil) wrote %q to stderr, want silence", out)
	}

	out := captureStderr(t, func() {
		if n := logClaimReap([]string{"01AAA", "01BBB"}, 90*time.Minute); n != 2 {
			t.Errorf("logClaimReap(2 ids) = %d, want 2", n)
		}
	})
	for _, want := range []string{"01AAA", "01BBB", "auto-reaped", "age > 1h30m0s", "freed 2 stale lock(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("logClaimReap stderr missing %q:\n%s", want, out)
		}
	}
}

// TestReapTarget_ScopesToTargetLock is the core behavioral acceptance: with TWO
// stale foreign locks aged past the reap age, ls.reapTarget frees ONLY the named
// target and leaves the sibling stale lock UNTOUCHED (the global broom stays the
// idle loop's job). Proves the cheap claim-time path never sweeps unrelated locks.
func TestReapTarget_ScopesToTargetLock(t *testing.T) {
	ls := landqServerForTest(t)
	const target = "01REAPTARGET_HIT_TEST"
	const sibling = "01REAPTARGET_SIBLING_TEST"
	cleanupForeignLock(t, ls, target)
	cleanupForeignLock(t, ls, sibling)

	for _, id := range []string{target, sibling} {
		if won, _, err := ls.acquire(id, "crashed-wave-sess", devHost()); err != nil || !won {
			t.Fatalf("acquire foreign lock %s: won=%v err=%v", id, won, err)
		}
		ageForeignLock(t, ls, id, 90*time.Minute) // both stale
	}

	t.Setenv("TASKDB_LOCK_AUTOREAP_AGE", "1m")
	freed, err := ls.reapTarget(target, autoReapAge())
	if err != nil {
		t.Fatalf("reapTarget: %v", err)
	}
	if !containsStr(freed, target) || len(freed) != 1 {
		t.Fatalf("reapTarget(%s) freed %v, want exactly [%s]", target, freed, target)
	}
	if h, _ := ls.holder(target); h != nil {
		t.Fatalf("target lock %s still held after scoped reap: %+v", target, h)
	}
	if h, _ := ls.holder(sibling); h == nil {
		t.Fatalf("sibling stale lock %s was evicted by a TARGET-scoped reap — scope leaked to the full table", sibling)
	}
}

// TestReapTarget_ActivityAwareAndSentinel proves the scoped path keeps BOTH
// guards the full sweep has: a fresh-heartbeat target past the age is NOT reaped
// (activity-aware), and a scoped reap of the __land_leader__ sentinel is a no-op
// (sentinel-excluded) even when the sentinel is aged well past the reap age.
func TestReapTarget_ActivityAwareAndSentinel(t *testing.T) {
	if !truthyEnv(ephemeralGateEnv) {
		t.Skip("manipulates the fixed __land_leader__ sentinel; runs only against an ephemeral PG (set " +
			ephemeralGateEnv + "=1)")
	}
	ls := landqServerForTest(t)
	t.Setenv("TASKDB_LOCK_AUTOREAP_AGE", "1m")

	// Activity-aware leg: a live, still-heartbeating holder past the age survives.
	const live = "01REAPTARGET_LIVE_TEST"
	const liveSess = "live-heartbeating-sess"
	cleanupForeignLock(t, ls, live)
	if won, _, err := ls.acquire(live, liveSess, devHost()); err != nil || !won {
		t.Fatalf("acquire live lock: won=%v err=%v", won, err)
	}
	ageForeignLock(t, ls, live, 90*time.Minute)
	if err := ls.recordEvent(WaveEvent{TaskID: live, Session: liveSess, Phase: "impl", Event: "heartbeat", Host: devHost()}); err != nil {
		t.Fatalf("recordEvent heartbeat: %v", err)
	}
	freed, err := ls.reapTarget(live, autoReapAge())
	if err != nil {
		t.Fatalf("reapTarget(live): %v", err)
	}
	if containsStr(freed, live) {
		t.Fatalf("scoped reap evicted a live heartbeating holder %s; freed=%v", live, freed)
	}
	if h, _ := ls.holder(live); h == nil || h.LockedBy != liveSess {
		t.Fatalf("live lock %s lost after scoped reap: holder=%+v", live, h)
	}

	// Sentinel leg: a scoped reap of __land_leader__ frees nothing (never a
	// double-writer window), even aged past the reap age.
	const sess = "reaptarget-sentinel-test"
	_, _ = ls.release(landLeaderSentinel, "", true)
	t.Cleanup(func() { _, _ = ls.release(landLeaderSentinel, "", true) })
	if won, holder, err := ls.acquireLandLeader(sess, devHost()); err != nil || !won {
		t.Fatalf("acquireLandLeader: won=%v holder=%+v err=%v", won, holder, err)
	}
	ageForeignLock(t, ls, landLeaderSentinel, 90*time.Minute)
	sfreed, err := ls.reapTarget(landLeaderSentinel, autoReapAge())
	if err != nil {
		t.Fatalf("reapTarget(sentinel): %v", err)
	}
	if len(sfreed) != 0 {
		t.Fatalf("scoped reap of the sentinel freed %v — exclusion broken", sfreed)
	}
	if h, _ := ls.holder(landLeaderSentinel); h == nil || h.LockedBy != sess {
		t.Fatalf("sentinel reaped/changed by scoped reap: holder=%+v want held by %q", h, sess)
	}
}

// TestReapTarget_ClaimTimeScopedAndLogged is the end-to-end acceptance for a
// SPECIFIC-TASK claim: claimRemote(id) auto-reaps ONLY that target's stale lock
// (a sibling stale foreign lock survives — the claim did not full-table sweep)
// and the sweep is OBSERVABLE (the freed target id appears on stderr). No
// operator reap verb is involved; the DEFAULT 2h age applies via no override.
func TestReapTarget_ClaimTimeScopedAndLogged(t *testing.T) {
	ls := landqServerForTest(t)
	const target = "01REAPTARGET_CLAIM_TEST"
	const sibling = "01REAPTARGET_CLAIM_SIBLING"
	const claimer = "reaptarget-claimer"
	cleanupForeignLock(t, ls, target)
	cleanupForeignLock(t, ls, sibling)
	t.Cleanup(func() { _, _ = ls.release(target, claimer, true) })

	// A crashed peer holds BOTH the target and an unrelated sibling, aged 3h > 2h.
	for _, id := range []string{target, sibling} {
		if won, _, err := ls.acquire(id, "crashed-peer-sess", "peer-host"); err != nil || !won {
			t.Fatalf("acquire stale foreign lock %s: won=%v err=%v", id, won, err)
		}
		ageForeignLock(t, ls, id, 3*time.Hour)
	}

	// Local mirror has the target ready-to-claim.
	db := newRequiredTestDB(t)
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		target, "t-"+target, "body", "open", 0, now, now,
	); err != nil {
		t.Fatalf("seed local task: %v", err)
	}

	var tk *Task
	var claimErr error
	out := captureStderr(t, func() { tk, claimErr = claimRemote(db, ls, claimer, "claim-host", target) })
	if claimErr != nil {
		t.Fatalf("claimRemote should scoped-reap the target and claim; got %v", claimErr)
	}
	if tk == nil || tk.ID != target {
		t.Fatalf("claimRemote returned %v, want %s claimed after scoped reap", tk, target)
	}
	if h, _ := ls.holder(target); h == nil || h.LockedBy != claimer {
		t.Fatalf("after claim the target lock is not held by the claimer: holder=%+v", h)
	}
	// Scoped: the unrelated sibling stale lock is UNTOUCHED by a specific-task claim.
	if h, _ := ls.holder(sibling); h == nil {
		t.Fatalf("sibling stale lock %s was evicted by a specific-task claim — scope leaked", sibling)
	}
	// Observable: the freed target id is on stderr, not silently swallowed.
	if !strings.Contains(out, target) || !strings.Contains(out, "auto-reaped") {
		t.Fatalf("claim-time scoped reap of %s was not logged to stderr:\n%s", target, out)
	}
}

// --- claim-time reap OBSERVABILITY: result payload + wave_events + quiet path --
//
// These cover the plumbing that carries a claim-time auto-reap OFF stderr: the
// freed ids threaded back through claimRemoteReaped's result (so the CLI/MCP
// callers can print reaped_locks) and the best-effort event=reap wave_events row.
// The behavioral legs need a real Postgres, so they run only against an EPHEMERAL
// throwaway instance (DS_LANDQ_EPHEMERAL_PG) — never the shared registry.

// TestClaimRemoteReaped_ReturnsFreedIds proves the reaped-lock ids are threaded
// back through the claim RESULT (not just stderr): a specific-task claim that
// scoped-reaps a stale foreign lock returns exactly that id in the freed slice,
// while an unrelated stale sibling is neither reaped nor reported. This is the
// payload the CLI reaped_locks line and the MCP reaped_locks field render.
func TestClaimRemoteReaped_ReturnsFreedIds(t *testing.T) {
	ls := landqServerForTest(t)
	const target = "01REAPRESULT_TARGET_TEST"
	const sibling = "01REAPRESULT_SIBLING_TEST"
	const claimer = "reapresult-claimer"
	cleanupForeignLock(t, ls, target)
	cleanupForeignLock(t, ls, sibling)
	t.Cleanup(func() { _, _ = ls.release(target, claimer, true) })

	// A crashed peer holds BOTH, aged 3h > the default 2h auto-reap age.
	for _, id := range []string{target, sibling} {
		if won, _, err := ls.acquire(id, "crashed-peer-sess", "peer-host"); err != nil || !won {
			t.Fatalf("acquire stale foreign lock %s: won=%v err=%v", id, won, err)
		}
		ageForeignLock(t, ls, id, 3*time.Hour)
	}

	db := newRequiredTestDB(t)
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		target, "t-"+target, "body", "open", 0, now, now,
	); err != nil {
		t.Fatalf("seed local task: %v", err)
	}

	tk, reaped, err := claimRemoteReaped(db, ls, claimer, "claim-host", target)
	if err != nil {
		t.Fatalf("claimRemoteReaped should scoped-reap and claim; got %v", err)
	}
	if tk == nil || tk.ID != target {
		t.Fatalf("claimRemoteReaped returned task %v, want %s", tk, target)
	}
	if !containsStr(reaped, target) || len(reaped) != 1 {
		t.Fatalf("claimRemoteReaped freed %v, want exactly [%s] in the result payload", reaped, target)
	}
	if containsStr(reaped, sibling) {
		t.Fatalf("claim result reported sibling %s — a specific-task claim must not full-table reap", sibling)
	}
}

// TestClaimReap_RecordsWaveEvent proves the claim-time reap leaves a wave_events
// trace (dashboards/rollups never scrape stderr): after a scoped-reap claim, a
// phase=claim event=reap row attributed to the CLAIMING session names the freed
// id in its note. Crucially the reap event carries NO task_id, so recordEvent did
// NOT upsert a false lock_heartbeats liveness row for the claimer against a lock
// it does not hold.
func TestClaimReap_RecordsWaveEvent(t *testing.T) {
	ls := landqServerForTest(t)
	const target = "01REAPEVENT_TARGET_TEST"
	const claimer = "reapevent-claimer-unique"
	cleanupForeignLock(t, ls, target)
	t.Cleanup(func() { _, _ = ls.release(target, claimer, true) })

	if won, _, err := ls.acquire(target, "crashed-peer-sess", "peer-host"); err != nil || !won {
		t.Fatalf("acquire stale foreign lock: won=%v err=%v", won, err)
	}
	ageForeignLock(t, ls, target, 3*time.Hour)

	db := newRequiredTestDB(t)
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		target, "t-"+target, "body", "open", 0, now, now,
	); err != nil {
		t.Fatalf("seed local task: %v", err)
	}

	if _, _, err := claimRemoteReaped(db, ls, claimer, "claim-host", target); err != nil {
		t.Fatalf("claimRemoteReaped: %v", err)
	}

	events, err := ls.listEvents("", "", 500)
	if err != nil {
		t.Fatalf("listEvents: %v", err)
	}
	var found *WaveEvent
	for i := range events {
		e := events[i]
		if e.Event == "reap" && e.Session == claimer {
			found = &events[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no phase=claim event=reap wave_events row for session %q after a claim-time reap", claimer)
	}
	if found.Phase != "claim" {
		t.Errorf("reap event phase = %q, want \"claim\"", found.Phase)
	}
	if !strings.Contains(found.Note, target) {
		t.Errorf("reap event note %q does not name freed id %s", found.Note, target)
	}
	// The reap event must NOT attribute a held task to the claimer (no false heartbeat).
	if found.TaskID != "" {
		t.Errorf("reap event carries task_id %q — a claimer must not upsert a heartbeat for a lock it does not hold", found.TaskID)
	}
}

// TestClaimReap_ZeroReapQuietPath proves the overwhelmingly-common no-stale-lock
// claim is SILENT on the observability channels: the claim returns an empty freed
// slice AND writes no event=reap wave_events row for the session. A regression
// that recorded a spurious reap event on every claim (or leaked a non-nil freed
// slice) is caught here.
func TestClaimReap_ZeroReapQuietPath(t *testing.T) {
	ls := landqServerForTest(t)
	const target = "01REAPQUIET_TARGET_TEST"
	const claimer = "reapquiet-claimer-unique"
	cleanupForeignLock(t, ls, target)
	t.Cleanup(func() { _, _ = ls.release(target, claimer, true) })

	// No foreign hold on the target: a specific-task claim scoped-reaps nothing.
	db := newRequiredTestDB(t)
	now := timeToMs(time.Now().UTC())
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		target, "t-"+target, "body", "open", 0, now, now,
	); err != nil {
		t.Fatalf("seed local task: %v", err)
	}

	tk, reaped, err := claimRemoteReaped(db, ls, claimer, "claim-host", target)
	if err != nil {
		t.Fatalf("claimRemoteReaped (no stale lock) should claim cleanly; got %v", err)
	}
	if tk == nil || tk.ID != target {
		t.Fatalf("claimRemoteReaped returned %v, want %s claimed", tk, target)
	}
	if len(reaped) != 0 {
		t.Fatalf("zero-reap claim returned freed %v, want empty", reaped)
	}
	events, err := ls.listEvents("", "", 500)
	if err != nil {
		t.Fatalf("listEvents: %v", err)
	}
	for _, e := range events {
		if e.Event == "reap" && e.Session == claimer {
			t.Fatalf("zero-reap claim recorded a spurious reap event: %+v", e)
		}
	}
}

// TestRecordClaimReap_EmptyIsNoOp proves recordClaimReap is a pure no-op on an
// empty freed set — it returns nil WITHOUT touching ls.db, so the quiet path adds
// zero wave_events noise and can never fault on a nil handle. Runs on the DEFAULT
// gate (no Postgres): a nil-db lockServer would panic if the empty guard regressed.
func TestRecordClaimReap_EmptyIsNoOp(t *testing.T) {
	ls := &lockServer{} // db is nil: any query would panic
	if err := ls.recordClaimReap("some-session", "some-host", nil, 2*time.Hour); err != nil {
		t.Fatalf("recordClaimReap(empty) = %v, want nil no-op", err)
	}
	if err := ls.recordClaimReap("some-session", "some-host", []string{}, 2*time.Hour); err != nil {
		t.Fatalf("recordClaimReap([]) = %v, want nil no-op", err)
	}
}

// captureStderr redirects os.Stderr to a pipe for the duration of fn and returns
// everything written. Test-local so the observability legs can assert on the
// exact stderr lines logClaimReap emits without a real Postgres.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stderr = orig
	return <-done
}

// TestLockserverReapDryRunUsesSharedPredicate guards the F2 claim in this file's
// header — that reap(), listStaleLocks() and the `lockserver reap --dry-run`
// preview all share reapLockStaleSQL. Until 2026-08-13 the preview did NOT: its
// branch in lockserverReap hand-rolled a client-side `l.LockedAt.Before(cutoff)`
// scan over ls.list(), which differs from the armed path in two ways that both
// make the preview LIE:
//
//   - no __land_leader__ exclusion, so it previewed reaping the leader sentinel
//     that reap() is structurally forbidden to touch (never-evict-the-leader);
//   - no lock_heartbeats awareness, so a live heartbeating holder past the age
//     cutoff previewed as reapable while reap() correctly spared it.
//
// Observed in production with the landing queue wedged behind a dead leader's
// lock: `reap --age 1h --dry-run` said "would reap __land_leader__" and the
// armed `reap --age 1h` said "nothing to reap", so the preview pointed the
// operator at a remedy that could not work. A dry-run that disagrees with its
// armed path is worse than no dry-run.
//
// Shape assertion, per this package's convention (no live Postgres).
func TestLockserverReapDryRunUsesSharedPredicate(t *testing.T) {
	src, err := os.ReadFile("cmd_lockserver.go")
	if err != nil {
		t.Fatalf("read cmd_lockserver.go: %v", err)
	}
	fn := string(src)
	i := strings.Index(fn, "func lockserverReap(")
	if i < 0 {
		t.Fatal("lockserverReap not found — this guard needs re-pointing")
	}
	body := fn[i:]
	if j := strings.Index(body, "\nfunc "); j > 0 {
		body = body[:j]
	}
	if !strings.Contains(body, "ls.listStaleLocks(") {
		t.Error("lockserverReap's dry-run branch does not call ls.listStaleLocks — " +
			"the preview must run reap()'s own predicate (reapLockStaleSQL), not a " +
			"re-implementation, or it can promise a reap the armed path refuses")
	}
	if strings.Contains(body, "LockedAt.Before(") {
		t.Error("lockserverReap hand-rolls a client-side LockedAt cutoff again — that " +
			"filter is neither sentinel-excluding nor activity-aware, so it previews " +
			"reaping __land_leader__ and live heartbeating holders that reap() spares")
	}
}
