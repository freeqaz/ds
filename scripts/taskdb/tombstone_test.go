// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
	"time"
)

// The done-tombstone (docs/23 Proposal A, OQ-A1/A2/A3) is a short-lived task_done
// row a terminal completion writes so a claim consults it and SKIPS (auto) or
// REFUSES (explicit id) re-doing work another clone already finished, before that
// clone has pulled the terminal state. Schema-text tests run everywhere; the live
// tests route their server setup through liveTombstoneServer → landqServerForTest,
// so with DS_LANDQ_EPHEMERAL_PG UNSET they SKIP IMMEDIATELY (never touching the
// shared production lock server) and with it SET they run against a throwaway
// Postgres, DELETE-ing every inserted row in a defer so that DB is left clean.

// --- pure / schema-text tests (no server) ---

// TestTombstoneSchemaPresent: the embedded schema carries the task_done DDL and
// its reap index (cheap guard that the additive block reached lockserver.sql and
// //go:embed wired it in).
func TestTombstoneSchemaPresent(t *testing.T) {
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS task_done",
		"idx_task_done_at",
		"task_id TEXT PRIMARY KEY",
	} {
		if !strings.Contains(lockSchemaSQL, want) {
			t.Errorf("embedded lockserver.sql missing task_done DDL %q", want)
		}
	}
}

// TestTombstoneSchemaAdditive: the task_done migration is backwards-compatible —
// it adds one table + one index with IF NOT EXISTS and NEVER alters/drops/renames
// task_done OR any pre-existing table. An old lock-server client on the prior
// binary keeps reading/writing the existing tables unchanged, and never names
// task_done. Mirrors TestLandQueueSchemaAdditive's intent for the new table.
func TestTombstoneSchemaAdditive(t *testing.T) {
	lc := strings.ToLower(lockSchemaSQL)
	for _, forbidden := range []string{
		"alter table task_done", "drop table task_done",
	} {
		if strings.Contains(lc, forbidden) {
			t.Errorf("lockserver.sql contains a NON-additive task_done statement %q — would break an old client mid-flight", forbidden)
		}
	}
}

// TestTombstoneTTL: the default is 24h, env-tunable via TASKDB_TOMBSTONE_TTL, and
// a malformed/non-positive value falls back to the default (never zero, which
// would reap every tombstone instantly).
func TestTombstoneTTL(t *testing.T) {
	const def = 24 * time.Hour
	cases := []struct {
		env  string
		want time.Duration
	}{
		{"", def},
		{"12h", 12 * time.Hour},
		{"90m", 90 * time.Minute},
		{"not-a-duration", def},
		{"0", def}, // non-positive falls back, never reap-everything
		{"-5m", def},
	}
	for _, c := range cases {
		t.Setenv("TASKDB_TOMBSTONE_TTL", c.env)
		if got := tombstoneTTL(); got != c.want {
			t.Errorf("TASKDB_TOMBSTONE_TTL=%q: tombstoneTTL()=%v want %v", c.env, got, c.want)
		}
	}
}

// TestTombstoneGates pins the load-bearing freshness rule: a tombstone gates a
// candidate ONLY when it is STRICTLY NEWER than the local row's updated_at (the
// clone has not yet pulled the terminal state). Equal or older never gates; a nil
// tombstone never gates.
func TestTombstoneGates(t *testing.T) {
	base := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	ts := &RemoteTombstone{At: base}
	if !tombstoneGates(ts, base.Add(-time.Minute)) {
		t.Error("tombstone newer than local updated_at should GATE")
	}
	if tombstoneGates(ts, base) {
		t.Error("tombstone == local updated_at must NOT gate (clone pulled the terminal state)")
	}
	if tombstoneGates(ts, base.Add(time.Minute)) {
		t.Error("tombstone older than local updated_at must NOT gate (reopen bumped updated_at past it)")
	}
	if tombstoneGates(nil, base) {
		t.Error("nil tombstone must NEVER gate")
	}
}

// TestTombstoneRefusal: the explicit-id refusal names the task, the completing
// status/host, and the two escape hatches (git pull / reopen).
func TestTombstoneRefusal(t *testing.T) {
	err := tombstoneRefusal("01ABCDONE", &RemoteTombstone{
		Status: "done", Host: "rig-2", By: "sess-7", At: time.Now(),
	})
	if err == nil {
		t.Fatal("tombstoneRefusal returned nil")
	}
	msg := err.Error()
	for _, want := range []string{"01ABCDONE", "done", "rig-2", "git pull", "--status open", "REFUSING"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q missing %q", msg, want)
		}
	}
}

// --- live tests (require a reachable shared Postgres; SKIP otherwise) ---

// liveTombstoneServer returns a migrated *lockServer for the tombstone live
// tests. It is the SINGLE CHOKEPOINT every TestTombstone*Live routes its setup
// through, and it delegates to landqServerForTest (landq_test_helpers_test.go) —
// the same B7 isolation gate the landq live tests use:
//
//   - DS_LANDQ_EPHEMERAL_PG unset → SKIP IMMEDIATELY, before any config
//     resolution or connection, so no tombstone live test can touch (let alone
//     upsert/delete/reap rows on) the SHARED production lock server in the normal
//     environment (lockserver.json enabled + tunnel up on 127.0.0.1:5433). The
//     prior gate (Enabled / reachable only) NEVER fired in that environment, so
//     these mutating tests ran against shared prod — this closes that hole.
//   - DS_LANDQ_EPHEMERAL_PG set → provision a throwaway Postgres, migrate the
//     full lock schema (task_locks/land_queue/task_done), and return it, with a
//     defence-in-depth backstop refusing a DSN that points at shared prod.
//
// landqServerForTest registers ls.close() via t.Cleanup FIRST, so it runs LAST
// (Go runs t.Cleanup in LIFO order): the test then registers its deleteTombstone
// cleanup, which runs FIRST on the still-open handle, then close — the same
// ordering the previous body relied on.
func liveTombstoneServer(t *testing.T) *lockServer {
	t.Helper()
	return landqServerForTest(t)
}

// cleanupTombstone registers a defer-delete of one tombstone id on the OPEN
// handle so the shared DB is left clean. Best-effort pre-clean too (a prior
// leaked run). NEVER leave a row behind.
func cleanupTombstone(t *testing.T, ls *lockServer, id string) {
	t.Helper()
	_ = ls.deleteTombstone(id) // pre-clean
	t.Cleanup(func() { _ = ls.deleteTombstone(id) })
}

// TestTombstoneUpsertRoundtripLive: upsert then isTombstoned/tombstonedTasks
// returns it with status/by/host; a second upsert collapses to one row (PK).
func TestTombstoneUpsertRoundtripLive(t *testing.T) {
	ls := liveTombstoneServer(t)
	const id = "01TOMBROUNDTRIP_TEST"
	cleanupTombstone(t, ls, id)

	if err := ls.upsertTombstone(id, "done", "sess-rt", "rig-rt"); err != nil {
		t.Fatalf("upsertTombstone: %v", err)
	}
	ts, err := ls.isTombstoned(id)
	if err != nil {
		t.Fatalf("isTombstoned: %v", err)
	}
	if ts == nil {
		t.Fatal("isTombstoned returned nil after upsert")
	}
	if ts.Status != "done" || ts.By != "sess-rt" || ts.Host != "rig-rt" {
		t.Errorf("tombstone = %+v, want status=done by=sess-rt host=rig-rt", ts)
	}
	all, err := ls.tombstonedTasks()
	if err != nil {
		t.Fatalf("tombstonedTasks: %v", err)
	}
	if _, ok := all[id]; !ok {
		t.Errorf("tombstonedTasks missing %s", id)
	}
	// Second upsert (dropped) collapses to the one PK row and updates fields.
	if err := ls.upsertTombstone(id, "dropped", "sess-rt2", "rig-rt2"); err != nil {
		t.Fatalf("second upsertTombstone: %v", err)
	}
	ts2, _ := ls.isTombstoned(id)
	if ts2 == nil || ts2.Status != "dropped" || ts2.By != "sess-rt2" {
		t.Errorf("after second upsert tombstone = %+v, want status=dropped by=sess-rt2", ts2)
	}
}

// TestTombstoneClaimSkipLive: claimRemote SKIPS a tombstoned auto-candidate whose
// local row is OLDER than the tombstone, and RE-OFFERS it once deleteTombstone
// clears it. Seeds a local sqlite task with an old updated_at.
func TestTombstoneClaimSkipLive(t *testing.T) {
	ls := liveTombstoneServer(t)
	const id = "01TOMBSKIP_TEST"
	const sess = "tomb-skip-test"
	cleanupTombstone(t, ls, id)
	// Also clean any stray remote lock the claim might take on the re-offer leg.
	t.Cleanup(func() { _, _ = ls.release(id, sess, true) })

	db := newRequiredTestDB(t)
	// Seed the task with an updated_at in the PAST so the about-to-be-written
	// tombstone (at=now()) is strictly newer → it gates.
	old := timeToMs(time.Now().Add(-time.Hour))
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		id, "t-"+id, "body", "open", 0, old, old,
	); err != nil {
		t.Fatalf("seed task: %v", err)
	}

	if err := ls.upsertTombstone(id, "done", "other-clone", "rig-other"); err != nil {
		t.Fatalf("upsertTombstone: %v", err)
	}

	// Auto-claim (optionalID=="") must SKIP the tombstoned candidate. With only
	// this one ready task, the queue reads as drained → sql.ErrNoRows.
	tk, err := claimRemote(db, ls, sess, "rig-claimer", "")
	if tk != nil {
		t.Errorf("auto-claim returned %v, want nil (tombstoned candidate must be skipped)", tk.ID)
	}
	if err == nil {
		t.Error("auto-claim of a fully-tombstoned ready set should report drained (sql.ErrNoRows), got nil err")
	}

	// Clear the tombstone (OQ-A3 reopen analog) → the candidate is re-offered.
	if err := ls.deleteTombstone(id); err != nil {
		t.Fatalf("deleteTombstone: %v", err)
	}
	tk2, err := claimRemote(db, ls, sess, "rig-claimer", "")
	if err != nil {
		t.Fatalf("auto-claim after clearing tombstone: %v", err)
	}
	if tk2 == nil || tk2.ID != id {
		t.Fatalf("after clear, auto-claim returned %v, want %s re-offered", tk2, id)
	}
}

// TestTombstoneExplicitClaimRefusesLive: an EXPLICIT claimRemote(optionalID) of a
// tombstoned id RETURNS the loud typed refusal (OQ-A1), and leaves the task
// open+unlocked (no claim acquired).
func TestTombstoneExplicitClaimRefusesLive(t *testing.T) {
	ls := liveTombstoneServer(t)
	const id = "01TOMBEXPLICIT_TEST"
	const sess = "tomb-explicit-test"
	cleanupTombstone(t, ls, id)
	t.Cleanup(func() { _, _ = ls.release(id, sess, true) })

	db := newRequiredTestDB(t)
	old := timeToMs(time.Now().Add(-time.Hour))
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		id, "t-"+id, "body", "open", 0, old, old,
	); err != nil {
		t.Fatalf("seed task: %v", err)
	}
	if err := ls.upsertTombstone(id, "done", "other-clone", "rig-other"); err != nil {
		t.Fatalf("upsertTombstone: %v", err)
	}

	_, err := claimRemote(db, ls, sess, "rig-claimer", id)
	if err == nil {
		t.Fatal("explicit claim of a tombstoned id returned nil, want the loud refusal")
	}
	if !strings.Contains(err.Error(), "completed elsewhere") || !strings.Contains(err.Error(), "REFUSING") {
		t.Errorf("refusal %q is not the loud OQ-A1 message", err)
	}
	status, lockedBy := taskRow(t, db, id)
	if status != "open" || lockedBy != "" {
		t.Errorf("after refused explicit claim: status=%q locked_by=%q, want open/unlocked (no claim acquired)", status, lockedBy)
	}
}

// TestTombstoneStaleLocalNotGatedLive: a clone that HAS pulled the terminal state
// (local updated_at >= tombstone.at) is NOT gated — the explicit claim proceeds
// to acquire. Guards the freshness direction end-to-end against the live clock.
func TestTombstoneStaleLocalNotGatedLive(t *testing.T) {
	ls := liveTombstoneServer(t)
	const id = "01TOMBFRESH_TEST"
	const sess = "tomb-fresh-test"
	cleanupTombstone(t, ls, id)
	t.Cleanup(func() { _, _ = ls.release(id, sess, true) })

	db := newRequiredTestDB(t)

	// Write the tombstone FIRST, then seed the task with updated_at = NOW (after
	// the tombstone's server-clock `at`), modeling a clone that already pulled the
	// done/reopened row. It must NOT gate → the explicit claim succeeds.
	if err := ls.upsertTombstone(id, "done", "other-clone", "rig-other"); err != nil {
		t.Fatalf("upsertTombstone: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // ensure local updated_at strictly exceeds at
	fresh := timeToMs(time.Now().Add(2 * time.Second))
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		id, "t-"+id, "body", "open", 0, fresh, fresh,
	); err != nil {
		t.Fatalf("seed task: %v", err)
	}

	tk, err := claimRemote(db, ls, sess, "rig-claimer", id)
	if err != nil {
		t.Fatalf("explicit claim of a pulled (not-gated) task should succeed, got %v", err)
	}
	if tk == nil || tk.ID != id {
		t.Fatalf("claim returned %v, want %s claimed", tk, id)
	}
}

// TestTombstoneReleaseUpsertsAndReopenClearsLive exercises the writer side end to
// end (OQ-A3): a TERMINAL release upserts the tombstone; a NON-terminal release
// (reopen) DELETEs it. Uses the real release path (claim → release).
func TestTombstoneReleaseUpsertsAndReopenClearsLive(t *testing.T) {
	ls := liveTombstoneServer(t)
	const id = "01TOMBRELEASE_TEST"
	const sess = "tomb-release-test"
	cleanupTombstone(t, ls, id)
	t.Cleanup(func() { _, _ = ls.release(id, sess, true) })

	db := newRequiredTestDB(t)
	insertOpenTask(t, db, id)

	if _, err := claimRemote(db, ls, sess, "rig-rel", id); err != nil {
		t.Fatalf("claim to set up release: %v", err)
	}
	// Terminal release → tombstone written.
	if _, err := releaseTaskRemote(db, ls, id, sess, "done", ""); err != nil {
		t.Fatalf("terminal release: %v", err)
	}
	if ts, _ := ls.isTombstoned(id); ts == nil {
		t.Error("terminal release did not write a tombstone")
	} else if ts.Status != "done" {
		t.Errorf("tombstone status = %q, want done", ts.Status)
	}

	// Re-claim and NON-terminal release (reopen) → tombstone cleared.
	if _, err := claimRemote(db, ls, sess, "rig-rel", id); err != nil {
		// The task is 'done' locally now; a re-claim of a done task is not ready,
		// so claim it via a direct re-open first to make it claimable again.
		if _, e := db.Exec(`UPDATE tasks SET status='open', updated_at=? WHERE id=?`, timeToMs(time.Now()), id); e != nil {
			t.Fatalf("reopen for re-claim: %v", e)
		}
		// Clear the tombstone so the re-claim is not refused, then re-claim.
		_ = ls.deleteTombstone(id)
		if _, e := claimRemote(db, ls, sess, "rig-rel", id); e != nil {
			t.Fatalf("re-claim after reopen: %v", e)
		}
	}
	if _, err := releaseTaskRemote(db, ls, id, sess, "open", ""); err != nil {
		t.Fatalf("non-terminal release (reopen): %v", err)
	}
	if ts, _ := ls.isTombstoned(id); ts != nil {
		t.Errorf("non-terminal release left a tombstone %+v, want it cleared (OQ-A3)", ts)
	}
}

// TestTombstoneReapLive: reapTombstones drops a row whose `at` is aged past the
// supplied age. Backdates the row via a direct UPDATE, then reaps with a 1s age.
func TestTombstoneReapLive(t *testing.T) {
	ls := liveTombstoneServer(t)
	const id = "01TOMBREAP_TEST"
	cleanupTombstone(t, ls, id)

	if err := ls.upsertTombstone(id, "done", "sess-reap", "rig-reap"); err != nil {
		t.Fatalf("upsertTombstone: %v", err)
	}
	// Backdate the row well past the reap age (server clock).
	if _, err := ls.db.Exec(`UPDATE task_done SET at = now() - interval '1 hour' WHERE task_id=$1`, id); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	reaped, err := ls.reapTombstones(1 * time.Second)
	if err != nil {
		t.Fatalf("reapTombstones: %v", err)
	}
	found := false
	for _, r := range reaped {
		if r == id {
			found = true
		}
	}
	if !found {
		t.Errorf("reapTombstones did not reap the backdated row %s (reaped=%v)", id, reaped)
	}
	if ts, _ := ls.isTombstoned(id); ts != nil {
		t.Errorf("tombstone still present after reap: %+v", ts)
	}
}

// TestTombstoneCleanLive is a residue audit: after the live tests above run (each
// cleaning its own ids), none of this file's synthetic ids remain. It double-
// checks the cleanup discipline so a leaked tombstone can never (briefly, until
// reaped) gate another machine's claim of that id.
func TestTombstoneCleanLive(t *testing.T) {
	ls := liveTombstoneServer(t)
	all, err := ls.tombstonedTasks()
	if err != nil {
		t.Fatalf("tombstonedTasks: %v", err)
	}
	for id := range all {
		if strings.HasSuffix(id, "_TEST") {
			// Defensive sweep + fail: a _TEST tombstone surviving means a sibling
			// test leaked. Clean it so we never gate a real claim, then flag it.
			_ = ls.deleteTombstone(id)
			t.Errorf("leaked test tombstone %s found in the shared DB (cleaned now)", id)
		}
	}
}
