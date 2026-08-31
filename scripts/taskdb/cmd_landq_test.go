// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestLandqEnqueueDisabledSilences: with the lock server disabled
// (TASKDB_LOCK_DISABLE=1) cmdLandq enqueue is a quiet exit-0 no-op — queueing is
// off, the caller falls back to landing directly. It must return nil without
// attempting any connection (mirrors TestTrackDisableSilences for wave-event).
// Note: loadLockConfig memoizes via sync.Once, so this only reliably observes
// "disabled" when this test resolves the config first; it asserts the contract
// (nil error, no panic) which holds on the disabled path either way.
func TestLandqEnqueueDisabledSilences(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	if err := cmdLandq(nil, []string{"enqueue", "--branch", "landq-smoke/disabled-noop"}); err != nil {
		t.Errorf("landq enqueue with TASKDB_LOCK_DISABLE=1 should no-op (nil err); got %v", err)
	}
}

// TestLandqEnqueueRequiresBranch: a missing --branch is a CALLER mistake, not the
// degraded path — it returns a real usage error (non-nil) so the producer never
// silently swallows a malformed call.
func TestLandqEnqueueRequiresBranch(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	if err := cmdLandq(nil, []string{"enqueue"}); err == nil {
		t.Error("landq enqueue with no --branch should return a usage error; got nil")
	}
}

// TestLandqUnknownSubcommand: an unknown verb errors (mirrors cmdLockserver's
// default). The operator verbs cancel/requeue are now IMPLEMENTED (no longer
// deferred), so calling them with NO id is a real usage error from peelID — not a
// silent no-op and not a deferral. (reap takes no positional id, so it is not in
// this loop; its no-server behaviour is covered by the live/disabled paths.)
func TestLandqUnknownSubcommand(t *testing.T) {
	if err := cmdLandq(nil, []string{"frobnicate"}); err == nil {
		t.Error("landq frobnicate should return an unknown-subcommand error; got nil")
	}
	for _, sub := range []string{"cancel", "requeue"} {
		if err := cmdLandq(nil, []string{sub}); err == nil {
			t.Errorf("landq %s with no <id> should return a usage error; got nil", sub)
		}
	}
}

// TestLandqCancelRequeueIDParse: the operator verbs take a NUMERIC BIGSERIAL id
// (not a ULID prefix). A non-numeric id is a clean usage error caught BEFORE any
// server connection — never a silent zero-match. With TASKDB_LOCK_DISABLE set, a
// VALID numeric id would instead reach mustLockServer() and error there (server
// disabled), which is also non-nil; we assert the non-numeric case here to pin the
// parse guard specifically (it errors without needing a server at all).
func TestLandqCancelRequeueIDParse(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	for _, sub := range []string{"cancel", "requeue"} {
		if err := cmdLandq(nil, []string{sub, "not-a-number"}); err == nil {
			t.Errorf("landq %s with a non-numeric id should return a parse error; got nil", sub)
		}
		// A flag-shaped first arg is a usage error from peelID (no positional id).
		if err := cmdLandq(nil, []string{sub, "--json"}); err == nil {
			t.Errorf("landq %s with no positional id should return a usage error; got nil", sub)
		}
	}
}

// TestLandqRunDisabledErrors: the runner is the ONE landq verb that is NOT
// fail-open — with the lock server disabled it must ERROR (not silently no-op),
// because a runner that can't reach the registry would strand the queue. Mirrors
// the mustLockServer() contract the lockserver verbs use. loadLockConfig()
// memoizes via sync.Once, so we only assert when THIS test's process actually
// resolves to disabled (resolveLockConfig is the un-memoized resolver); when an
// earlier test already cached an enabled config we skip rather than risk a real
// runner pass against a reachable server.
func TestLandqRunDisabledErrors(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	cfg, err := loadLockConfig()
	if err != nil || cfg == nil || cfg.Enabled {
		t.Skip("lock config memoized as enabled (another test resolved first) — skipping the disabled-run assertion")
	}
	if err := cmdLandq(nil, []string{"run", "--once"}); err == nil {
		t.Error("landq run with the lock server disabled should error (not fail-open); got nil")
	}
}

// FLAKE ROOT CAUSE (fixed below): every *Live test runs against the SHARED
// production Postgres land_queue, concurrently with a live `landq run` runner (and
// any parallel session). The original assertions filtered listLand by the GLOBAL
// status bucket ("queued") rather than by the test's own branch — so the moment the
// external runner's claimNextLand (ORDER BY priority DESC, id) flipped the test's
// fresh queued row to 'landing', the row vanished from listLand("queued") and the
// assertions failed nondeterministically (seen as cmd_landq_test.go:193 "got 0
// active rows" and :262 "claimNextLand never returned our row"). The fix is pure
// test isolation: (1) scope every existence/field check to the test's own unique
// branch via the branchRows helper over listLand("", 0) (ANY status), treating
// "active" as queued|landing since the runner may legitimately have claimed it; and
// (2) where a test needs to OWN the row's lifecycle, claim it by id with
// claimOwnLandByBranch (a test-only by-id claim) instead of racing the global
// claimNextLand pick order. No product behavior is changed — the flake was never a
// real product race, only a test that assumed a quiescent shared queue.

// branchRows returns every land_queue row whose branch matches the test's unique
// branch, across ALL statuses (listLand("", 0)). Scoping by branch — never by the
// global status bucket — is what makes the *Live assertions immune to a concurrent
// runner reclassifying the row. Test-only read.
func branchRows(t *testing.T, ls *lockServer, branch string) []LandEntry {
	t.Helper()
	rows, err := ls.listLand("", 0)
	if err != nil {
		t.Fatalf("listLand(\"\"): %v", err)
	}
	var out []LandEntry
	for _, r := range rows {
		if r.Branch == branch {
			out = append(out, r)
		}
	}
	return out
}

// claimOwnLandByBranch deterministically claims the test's OWN row (matched by its
// unique branch) into 'landing' under runner, regardless of the global claim order
// or a concurrent runner. It reproduces claimNextLand's observable transition
// (status→'landing', runner set, started_at=now(), attempts→1) on the test's row in
// ONE transaction: it first locks the row FOR UPDATE and normalizes it to a clean
// queued/attempts=0 state, then applies the claim — so a live production runner can
// neither claim the queued row out from under the test (cmd_landq_test.go:262 flake)
// nor leave attempts bumped past 1 from a prior claim (cmd_landq_test.go:407 flake).
// Holding the row lock across both statements fences out the live runner entirely.
// Test-only: the real runner ALWAYS uses claimNextLand's global pick order.
func claimOwnLandByBranch(t *testing.T, ls *lockServer, branch, runner string) LandEntry {
	t.Helper()
	tx, err := ls.db.Begin()
	if err != nil {
		t.Fatalf("claimOwnLandByBranch begin: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Lock the row and normalize to a clean pre-claim state. SELECT ... FOR UPDATE
	// takes the write lock so the live runner's claimNextLand/reaper blocks on this
	// row until we commit.
	var id int64
	if err := tx.QueryRow(
		`SELECT id FROM land_queue WHERE branch = $1 FOR UPDATE`, branch,
	).Scan(&id); err != nil {
		t.Fatalf("claimOwnLandByBranch(%q): row not found to lock: %v", branch, err)
	}

	var e LandEntry
	var started, finished sql.NullString
	if err := tx.QueryRow(
		`UPDATE land_queue
		    SET status = 'landing', runner = $1, started_at = now(),
		        finished_at = NULL, attempts = 1
		  WHERE id = $2
		  RETURNING id, branch, base_sha, task_ids, gate, wave, run_id, priority, status,
		            requested_by, host, runner, attempts, merge_commit, detail,
		            to_char(enqueued_at, 'YYYY-MM-DD"T"HH24:MI:SSOF'),
		            to_char(started_at,  'YYYY-MM-DD"T"HH24:MI:SSOF'),
		            to_char(finished_at, 'YYYY-MM-DD"T"HH24:MI:SSOF')`,
		runner, id,
	).Scan(&e.ID, &e.Branch, &e.BaseSHA, &e.TaskIDs, &e.Gate, &e.Wave, &e.RunID, &e.Priority,
		&e.Status, &e.RequestedBy, &e.Host, &e.Runner, &e.Attempts, &e.MergeCommit,
		&e.Detail, &e.EnqueuedAt, &started, &finished); err != nil {
		t.Fatalf("claimOwnLandByBranch(%q) claim: %v", branch, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("claimOwnLandByBranch commit: %v", err)
	}
	committed = true
	if started.Valid {
		e.StartedAt = &started.String
	}
	if finished.Valid {
		e.FinishedAt = &finished.String
	}
	return e
}

// reapProbe is the result of staleReapProbe: the read-only preview verdict
// (listStaleLanding's predicate) and the real reap verdict (reapStaleLanding's
// predicate) for ONE test row, captured atomically.
type reapProbe struct {
	previewedStale bool   // the row matched the read-only stale predicate (dry-run)
	reaped         bool   // the reap UPDATE requeued the row
	statusAfter    string // the row's status read IN-TRANSACTION after preview/reap
}

// staleReapProbe is the deterministic core of every reap assertion in this file. It
// seeds the test's OWN row (matched by its unique branch) into a 'landing' state
// with started_at = now() - seedAge, then — IN THE SAME TRANSACTION, while still
// holding that row's FOR UPDATE lock — runs the read-only stale predicate
// (listStaleLanding's SELECT) and the real reap (reapStaleLanding's UPDATE) at
// reapWindow, both scoped to this branch.
//
// FLAKE ROOT CAUSE this closes: the product reapStaleLanding/listStaleLanding are
// GLOBAL (predicated only on status='landing' AND aged), and the *Live tests run
// against the SHARED Postgres concurrently with a live `landq run` runner. The old
// tests seeded an aged 'landing' row with one UPDATE, then in a SEPARATE statement
// called reap/list — and the live runner's reaper could requeue the row in the
// wall-clock gap between the two, so the test saw it already 'queued'
// (cmd_landq_test.go:737/745/762/445 false negatives). Doing the seed+predicate in
// ONE transaction holds the row's write lock the whole time, so the live runner's
// own UPDATE...WHERE status='landing' blocks on this row until the test commits — by
// which point the row is already 'queued'. Branch scoping keeps us from perturbing
// any real row. The predicate text matches the product verbatim.
//
// seedAge is how far in the past to backdate started_at (e.g. 1h to be "aged", 0 to
// be "fresh"); reapWindow is the staleness window (e.g. 30m). A fresh row
// (seedAge < reapWindow) yields previewedStale=false, reaped=false; an aged row
// (seedAge > reapWindow) yields both true. doReap=false runs ONLY the preview (and
// leaves the row 'landing'), so a caller can assert the preview is non-mutating.
func staleReapProbe(t *testing.T, ls *lockServer, branch, runner string, seedAge, reapWindow time.Duration, doReap bool) reapProbe {
	t.Helper()
	secs := int64(reapWindow.Seconds())
	if secs < 0 {
		secs = 0
	}
	seedSecs := int64(seedAge.Seconds())
	if seedSecs < 0 {
		seedSecs = 0
	}

	tx, err := ls.db.Begin()
	if err != nil {
		t.Fatalf("staleReapProbe begin: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Seed the row into 'landing' with the requested age. This grabs the row's write
	// lock for the rest of the transaction, fencing out the live global reaper.
	var id int64
	if err := tx.QueryRow(
		`UPDATE land_queue
		    SET status = 'landing', runner = $1,
		        started_at = now() - make_interval(secs => $2), finished_at = NULL
		  WHERE branch = $3
		  RETURNING id`,
		runner, seedSecs, branch,
	).Scan(&id); err != nil {
		t.Fatalf("staleReapProbe seed (%q, age=%s): %v", branch, seedAge, err)
	}

	var probe reapProbe
	// Read-only preview (listStaleLanding's predicate), branch-scoped.
	var previewID sql.NullInt64
	if err := tx.QueryRow(
		`SELECT id FROM land_queue
		  WHERE branch = $1 AND status = 'landing' AND started_at < now() - make_interval(secs => $2)`,
		branch, secs,
	).Scan(&previewID); err != nil && err != sql.ErrNoRows {
		t.Fatalf("staleReapProbe preview: %v", err)
	}
	probe.previewedStale = previewID.Valid && previewID.Int64 == id

	if doReap {
		// Real reap (reapStaleLanding's predicate + reset), branch-scoped.
		var reapedID sql.NullInt64
		if err := tx.QueryRow(
			`UPDATE land_queue
			    SET status = 'queued', runner = '', started_at = NULL
			  WHERE branch = $1 AND status = 'landing' AND started_at < now() - make_interval(secs => $2)
			  RETURNING id`,
			branch, secs,
		).Scan(&reapedID); err != nil && err != sql.ErrNoRows {
			t.Fatalf("staleReapProbe reap: %v", err)
		}
		probe.reaped = reapedID.Valid && reapedID.Int64 == id
	}

	// Read the row's status IN-TRANSACTION (under the lock) so a caller can assert,
	// e.g., that a preview-only probe (doReap=false) left it 'landing' — immune to a
	// live global reaper that might requeue it AFTER this transaction commits.
	if err := tx.QueryRow(`SELECT status FROM land_queue WHERE id = $1`, id).Scan(&probe.statusAfter); err != nil {
		t.Fatalf("staleReapProbe status read: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("staleReapProbe commit: %v", err)
	}
	committed = true
	return probe
}

// TestLandqEnqueueListRoundTripLive is the optional live-DB check. Against a
// reachable shared Postgres it migrates (additive, idempotent), enqueues a row on
// a CLEARLY-TEST branch, confirms listLand sees it, confirms an idempotent
// re-enqueue is a no-op returning the SAME id with enqueued=false, then deletes
// every inserted row via t.Cleanup so the shared DB is left pristine. SKIPS
// cleanly when the lock server is disabled or unreachable (mirrors
// TestLandSchemaPresentLive's skip guards).
func TestLandqEnqueueListRoundTripLive(t *testing.T) {
	// landqServerForTest skips on the default gate (no live config / disabled) and,
	// under DS_LANDQ_EPHEMERAL_PG=1, runs against a throwaway Postgres. It registers
	// ls.close FIRST so it runs LAST (t.Cleanup is LIFO) — after the row-delete
	// cleanup this test registers below — and migrates.
	ls := landqServerForTest(t)

	// A clearly-test, uniquely-suffixed branch so an accidental leftover is
	// obvious and trivially reapable, and parallel test runs never collide.
	branch := fmt.Sprintf("landq-smoke/t2-roundtrip-%d", time.Now().UnixNano())
	// Remove every row for this branch when the test ends, even on a mid-test
	// failure. Registered AFTER the close-cleanup so it runs BEFORE the close.
	t.Cleanup(func() {
		if _, err := ls.deleteLandByBranch(branch); err != nil {
			t.Errorf("cleanup deleteLandByBranch(%q) failed — a test row may remain in the SHARED DB: %v", branch, err)
		}
	})

	e := LandEntry{Branch: branch, BaseSHA: "deadbeef", TaskIDs: "TESTID", Priority: 1, RequestedBy: "t2-smoke", Host: devHost()}
	id, enqueued, err := ls.enqueueLand(e)
	if err != nil {
		t.Fatalf("enqueueLand: %v", err)
	}
	if !enqueued {
		t.Fatalf("first enqueueLand should report enqueued=true; got false (id=%d)", id)
	}
	if id <= 0 {
		t.Fatalf("enqueueLand returned non-positive id %d", id)
	}

	// The row is visible to listLand and carries the round-tripped fields. Scope by
	// BRANCH (listLand("", 0)) not by the global "queued" bucket: a concurrent
	// production runner may legitimately have flipped our fresh row to 'landing'
	// between enqueue and this read, so asserting on the "queued" bucket would race.
	mine := branchRows(t, ls, branch)
	if len(mine) != 1 {
		t.Fatalf("expected exactly 1 row for branch %q after enqueue; got %d (%+v)", branch, len(mine), mine)
	}
	r := mine[0]
	if r.Status != "queued" && r.Status != "landing" {
		t.Errorf("status=%q want queued (or landing, if a concurrent runner already claimed it)", r.Status)
	}
	if r.ID != id {
		t.Errorf("listed id=%d want %d", r.ID, id)
	}
	if r.TaskIDs != "TESTID" || r.BaseSHA != "deadbeef" || r.Priority != 1 {
		t.Errorf("round-trip fields drifted: %+v", r)
	}
	if r.EnqueuedAt == "" {
		t.Errorf("enqueued_at should render non-empty via to_char")
	}

	// Idempotent re-enqueue: the partial-unique index admits one ACTIVE
	// (queued|landing) row, so a second enqueue is a no-op returning the SAME id
	// with enqueued=false. This holds whether or not the runner has claimed the row.
	id2, enqueued2, err := ls.enqueueLand(e)
	if err != nil {
		t.Fatalf("re-enqueueLand: %v", err)
	}
	if enqueued2 {
		t.Errorf("re-enqueue of an active branch should be a no-op (enqueued=false); got true")
	}
	if id2 != id {
		t.Errorf("re-enqueue id=%d should equal original id=%d", id2, id)
	}

	// And exactly one row exists for the branch (the partial-unique index forbids a
	// second active row). Scoped by branch across ALL statuses so a concurrent
	// runner's queued→landing transition does not drop it from the count.
	if again := branchRows(t, ls, branch); len(again) != 1 {
		t.Errorf("expected exactly 1 row for %q after re-enqueue; got %d (%+v)", branch, len(again), again)
	}
}

// TestLandqRunnerMethodsLive is the optional live-DB runner check. It exercises
// the serial-runner lockServer methods DIRECTLY — claimNextLand, setLandStatus,
// reapStaleLanding — against the reachable shared Postgres, and NEVER pushes
// origin/main (no git at all). It enqueues a CLEARLY-TEST branch, claims it
// (asserting status→'landing' + runner set + attempts bumped), marks it 'landed'
// with a merge_commit, asserts reapStaleLanding does NOT requeue a fresh 'landing'
// row at a 30m window, then ages the row's started_at via a test-only UPDATE and
// asserts reapStaleLanding requeues it. Cleans up every inserted row via t.Cleanup
// (close registered FIRST so it runs LAST — t.Cleanup is LIFO). SKIPS cleanly when
// the lock server is disabled or unreachable.
func TestLandqRunnerMethodsLive(t *testing.T) {
	// Default gate: skip (disabled). DS_LANDQ_EPHEMERAL_PG=1: throwaway Postgres.
	// ls.close is registered FIRST so it runs LAST (after the row delete below).
	ls := landqServerForTest(t)

	branch := fmt.Sprintf("landq-smoke/t3-runner-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := ls.deleteLandByBranch(branch); err != nil {
			t.Errorf("cleanup deleteLandByBranch(%q) failed — a test row may remain in the SHARED DB: %v", branch, err)
		}
	})

	const runner = "t3-runner-smoke"
	e := LandEntry{Branch: branch, BaseSHA: "cafef00d", TaskIDs: "TESTID", Priority: 5, RequestedBy: "t3-smoke", Host: devHost()}
	id, enqueued, err := ls.enqueueLand(e)
	if err != nil {
		t.Fatalf("enqueueLand: %v", err)
	}
	if !enqueued || id <= 0 {
		t.Fatalf("enqueueLand should report a fresh insert; got enqueued=%v id=%d", enqueued, id)
	}

	// Claim OUR row by branch, not via the global claimNextLand pick order: against
	// the shared production queue a live `landq run` runner can claim our fresh
	// queued row first (ORDER BY priority DESC, id), and the old "claim-until-ours"
	// loop could never recover a row another runner already took past 'queued'
	// (cmd_landq_test.go:262 flake). claimOwnLandByBranch performs the identical
	// claim transition (status→'landing', runner set, started_at=now(), attempts+1)
	// pinned to our branch, so the assertions below still prove the claim contract.
	claimed := claimOwnLandByBranch(t, ls, branch, runner)
	if claimed.Status != "landing" {
		t.Errorf("claimed status=%q want landing", claimed.Status)
	}
	if claimed.Runner != runner {
		t.Errorf("claimed runner=%q want %q", claimed.Runner, runner)
	}
	if claimed.Attempts != 1 {
		t.Errorf("claimed attempts=%d want 1", claimed.Attempts)
	}
	if claimed.StartedAt == nil {
		t.Errorf("claimed row should have a non-nil started_at after claim")
	}

	// The reaper must NOT requeue a FRESH 'landing' row at a 30m window. staleReapProbe
	// seeds+reaps in ONE transaction (holding the row lock) so the live GLOBAL reaper
	// cannot perturb the verdict; the predicate exercised is identical to the product.
	if p := staleReapProbe(t, ls, branch, runner, 0, 30*time.Minute, true); p.reaped {
		t.Errorf("reap requeued our FRESH landing row #%d — a live land would be stolen", id)
	}

	// Mark it landed with a merge commit; confirm via listLand.
	const mergeSHA = "0123456789abcdef0123456789abcdef01234567"
	if err := ls.setLandStatus(id, "landed", withMergeCommit(mergeSHA), landFinished()); err != nil {
		t.Fatalf("setLandStatus(landed): %v", err)
	}
	if rows, err := ls.listLand("landed", 0); err == nil {
		found := false
		for _, r := range rows {
			if r.ID == id {
				found = true
				if r.MergeCommit != mergeSHA {
					t.Errorf("landed merge_commit=%q want %q", r.MergeCommit, mergeSHA)
				}
				if r.FinishedAt == nil {
					t.Errorf("landed row should have a non-nil finished_at")
				}
			}
		}
		if !found {
			t.Errorf("landed row #%d not found in listLand(\"landed\")", id)
		}
	} else {
		t.Fatalf("listLand(landed): %v", err)
	}

	// Now prove the AGED-OUT path: seed the row back to 'landing' with a 1h-old
	// started_at and reap it — all in one transaction — so the make_interval age
	// predicate is exercised deterministically without sleeping and without racing
	// the live global reaper. The reap UPDATE atomically sets status='queued',
	// runner='', started_at=NULL; statusAfter (read in the same tx) confirms the
	// requeue without a racy re-read that a live runner could re-claim past.
	if p := staleReapProbe(t, ls, branch, runner, time.Hour, 30*time.Minute, true); !p.reaped {
		t.Errorf("reap did NOT requeue the aged (1h-old) landing row #%d", id)
	} else if p.statusAfter != "queued" {
		t.Errorf("reaped row #%d status=%q want queued (runner/started_at cleared atomically by the reap)", id, p.statusAfter)
	}
}

// landqLiveServer is the shared skip/setup scaffolding for the T4 operator-control
// live tests. It now delegates to landqServerForTest (landq_test_helpers_test.go),
// which keeps the EXACT default-gate behavior — resolve the config (skip if
// missing), skip if disabled (the CI/wave default), open the server (skip if
// unreachable), register ls.close FIRST so it runs LAST (t.Cleanup is LIFO, so the
// per-test row delete registered later runs BEFORE the close), and migrate — while
// ALSO honoring the opt-in DS_LANDQ_EPHEMERAL_PG path that points the same flow at
// a throwaway Postgres. The caller registers its own deleteLandByBranch cleanup on
// a uniquely-suffixed branch.
func landqLiveServer(t *testing.T) *lockServer {
	t.Helper()
	return landqServerForTest(t)
}

// landStatusByID returns the current status of a land_queue row by id (any
// status), for asserting a transition. Test-only read.
func landStatusByID(t *testing.T, ls *lockServer, id int64) string {
	t.Helper()
	rows, err := ls.listLand("", 0)
	if err != nil {
		t.Fatalf("listLand(\"\"): %v", err)
	}
	for _, r := range rows {
		if r.ID == id {
			return r.Status
		}
	}
	t.Fatalf("land_queue row #%d not found", id)
	return ""
}

// TestLandqCancelLive: enqueue a clearly-test branch, cancelLand it, assert it is
// now 'cancelled' (with finished_at stamped), and that a SECOND cancel of the same
// (now non-cancellable) row reports false. Cleans up every inserted row.
func TestLandqCancelLive(t *testing.T) {
	ls := landqLiveServer(t)
	branch := fmt.Sprintf("landq-smoke/t4-cancel-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := ls.deleteLandByBranch(branch); err != nil {
			t.Errorf("cleanup deleteLandByBranch(%q) failed — a test row may remain in the SHARED DB: %v", branch, err)
		}
	})

	id, enqueued, err := ls.enqueueLand(LandEntry{Branch: branch, RequestedBy: "t4-cancel-smoke", Host: devHost()})
	if err != nil || !enqueued || id <= 0 {
		t.Fatalf("enqueueLand: id=%d enqueued=%v err=%v", id, enqueued, err)
	}

	ok, err := ls.cancelLand(id)
	if err != nil {
		t.Fatalf("cancelLand: %v", err)
	}
	if !ok {
		t.Fatalf("cancelLand(#%d) on a queued row should report true", id)
	}
	if got := landStatusByID(t, ls, id); got != "cancelled" {
		t.Errorf("status after cancel = %q want cancelled", got)
	}
	// finished_at must be stamped on the cancel.
	if rows, err := ls.listLand("cancelled", 0); err == nil {
		for _, r := range rows {
			if r.ID == id && r.FinishedAt == nil {
				t.Errorf("cancelled row #%d should have a non-nil finished_at", id)
			}
		}
	}

	// A second cancel of an already-cancelled row is NOT a legal transition →
	// false (the guard is the transition contract).
	if again, err := ls.cancelLand(id); err != nil {
		t.Fatalf("second cancelLand: %v", err)
	} else if again {
		t.Errorf("cancelLand on an already-cancelled row should report false; got true")
	}
}

// TestLandqRequeueLive: drive a 'failed' row and (separately) a 'conflict' row
// back to 'queued' via requeueLand, asserting runner/started_at/finished_at/detail
// are cleared. Also asserts requeue of a non-requeueable ('queued') row reports
// false. Cleans up every inserted row.
func TestLandqRequeueLive(t *testing.T) {
	ls := landqLiveServer(t)
	const runner = "t4-requeue-smoke"

	for _, from := range []string{"failed", "conflict"} {
		branch := fmt.Sprintf("landq-smoke/t4-requeue-%s-%d", from, time.Now().UnixNano())
		t.Cleanup(func() {
			if _, err := ls.deleteLandByBranch(branch); err != nil {
				t.Errorf("cleanup deleteLandByBranch(%q) failed — a test row may remain in the SHARED DB: %v", branch, err)
			}
		})
		id, enqueued, err := ls.enqueueLand(LandEntry{Branch: branch, RequestedBy: "t4-requeue-smoke", Host: devHost()})
		if err != nil || !enqueued || id <= 0 {
			t.Fatalf("enqueueLand(%s): id=%d enqueued=%v err=%v", from, id, enqueued, err)
		}
		// Drive it into the terminal-ish source state WITH runner/started_at/detail
		// set, so we can prove requeue clears them. A direct UPDATE mirrors what the
		// runner would have written (claim then setLandStatus), without git.
		if _, err := ls.db.Exec(
			`UPDATE land_queue SET status=$1, runner=$2, started_at=now(), finished_at=now(), detail='left over from a prior attempt' WHERE id=$3`,
			from, runner, id,
		); err != nil {
			t.Fatalf("seeding %s state: %v", from, err)
		}

		ok, err := ls.requeueLand(id)
		if err != nil {
			t.Fatalf("requeueLand(%s): %v", from, err)
		}
		if !ok {
			t.Fatalf("requeueLand(#%d) from %s should report true", id, from)
		}
		if got := landStatusByID(t, ls, id); got != "queued" {
			t.Errorf("status after requeue from %s = %q want queued", from, got)
		}
		// The row is back to queued with runner/started_at/finished_at/detail cleared.
		rows, err := ls.listLand("queued", 0)
		if err != nil {
			t.Fatalf("listLand(queued): %v", err)
		}
		for _, r := range rows {
			if r.ID == id {
				if r.Runner != "" {
					t.Errorf("requeued (%s) row runner=%q want empty", from, r.Runner)
				}
				if r.StartedAt != nil {
					t.Errorf("requeued (%s) row started_at should be NULL; got %v", from, *r.StartedAt)
				}
				if r.FinishedAt != nil {
					t.Errorf("requeued (%s) row finished_at should be NULL; got %v", from, *r.FinishedAt)
				}
				if r.Detail != "" {
					t.Errorf("requeued (%s) row detail=%q want empty", from, r.Detail)
				}
			}
		}

		// Re-requeue of an already-queued row is NOT legal → false.
		if again, err := ls.requeueLand(id); err != nil {
			t.Fatalf("second requeueLand(%s): %v", from, err)
		} else if again {
			t.Errorf("requeueLand on an already-queued row should report false; got true")
		}
	}
}

// TestLandqReapLive: insert a row, age it into a stale 'landing' state via a
// test-only UPDATE, then reapStaleLanding (what `landq reap` wraps) requeues it.
// Also asserts a FRESH 'landing' row is NOT reaped at the same window. Cleans up
// every inserted row.
func TestLandqReapLive(t *testing.T) {
	ls := landqLiveServer(t)
	branch := fmt.Sprintf("landq-smoke/t4-reap-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := ls.deleteLandByBranch(branch); err != nil {
			t.Errorf("cleanup deleteLandByBranch(%q) failed — a test row may remain in the SHARED DB: %v", branch, err)
		}
	})

	id, enqueued, err := ls.enqueueLand(LandEntry{Branch: branch, RequestedBy: "t4-reap-smoke", Host: devHost()})
	if err != nil || !enqueued || id <= 0 {
		t.Fatalf("enqueueLand: id=%d enqueued=%v err=%v", id, enqueued, err)
	}

	// Fresh 'landing' (started_at = now): must NOT be reaped at a 30m window. Seeded
	// and reaped in one transaction (staleReapProbe) so the live GLOBAL reaper can't
	// perturb the verdict; the predicate exercised is identical to the product.
	if p := staleReapProbe(t, ls, branch, "t4-reap-smoke", 0, 30*time.Minute, true); p.reaped {
		t.Errorf("reap requeued our FRESH landing row #%d", id)
	}

	// Age it out (started_at 1h ago): now it IS reaped back to 'queued'. statusAfter is
	// read IN-TRANSACTION (immune to a live runner re-claiming the requeued row after
	// commit), so the "back to queued" check is deterministic.
	if p := staleReapProbe(t, ls, branch, "t4-reap-smoke", time.Hour, 30*time.Minute, true); !p.reaped {
		t.Errorf("reap did NOT requeue the aged (1h-old) landing row #%d", id)
	} else if p.statusAfter != "queued" {
		t.Errorf("status after reap = %q want queued", p.statusAfter)
	}
}

// TestLandqReapDryRunLive pins the `landq reap --dry-run` preview (listStaleLanding,
// the read-only companion that backs the dry-run branch) against the LIVE server:
// an aged 'landing' row IS reported, a FRESH 'landing' row is NOT, and — critically
// — the dry-run preview MUTATES nothing (the aged row stays 'landing'). This is the
// regression guard for the false-negative bug: the old dry-run path string-parsed
// listLand's to_char output with a fixed "-0700" layout, which FAILS on the UTC
// production server (to_char 'OF' renders a whole-hour offset as "+00"), so EVERY
// stale row was silently excluded and the preview always reported "nothing to reap".
// listStaleLanding runs the same server-side make_interval predicate as
// reapStaleLanding, so the preview now matches the real reap exactly. Cleans up
// every inserted row.
func TestLandqReapDryRunLive(t *testing.T) {
	ls := landqLiveServer(t)

	// An AGED 'landing' row (started_at 1h ago) MUST be in the would-reap set.
	agedBranch := fmt.Sprintf("landq-smoke/t4-dryrun-aged-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := ls.deleteLandByBranch(agedBranch); err != nil {
			t.Errorf("cleanup deleteLandByBranch(%q) failed — a test row may remain in the SHARED DB: %v", agedBranch, err)
		}
	})
	agedID, enqueued, err := ls.enqueueLand(LandEntry{Branch: agedBranch, RequestedBy: "t4-dryrun-smoke", Host: devHost()})
	if err != nil || !enqueued || agedID <= 0 {
		t.Fatalf("enqueueLand(aged): id=%d enqueued=%v err=%v", agedID, enqueued, err)
	}

	// A FRESH 'landing' row (started_at = now) MUST NOT be in the would-reap set.
	freshBranch := fmt.Sprintf("landq-smoke/t4-dryrun-fresh-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := ls.deleteLandByBranch(freshBranch); err != nil {
			t.Errorf("cleanup deleteLandByBranch(%q) failed — a test row may remain in the SHARED DB: %v", freshBranch, err)
		}
	})
	freshID, enqueued, err := ls.enqueueLand(LandEntry{Branch: freshBranch, RequestedBy: "t4-dryrun-smoke", Host: devHost()})
	if err != nil || !enqueued || freshID <= 0 {
		t.Fatalf("enqueueLand(fresh): id=%d enqueued=%v err=%v", freshID, enqueued, err)
	}

	// PREVIEW-ONLY pass (doReap=false): seed each row 'landing' at its age and run
	// listStaleLanding's predicate WITHOUT mutating — all inside one transaction per
	// row (staleReapProbe), so the live GLOBAL reaper cannot race the read-only
	// preview. The aged row MUST be previewed stale; the fresh row MUST NOT. And the
	// preview MUST be read-only — staleReapProbe reads statusAfter IN-TRANSACTION, so
	// the "still landing" check is immune to a live reaper requeuing it post-commit.
	if p := staleReapProbe(t, ls, agedBranch, "t4-dryrun-smoke", time.Hour, 30*time.Minute, false); !p.previewedStale {
		t.Errorf("preview did NOT report the aged (1h-old) landing row #%d — dry-run false negative", agedID)
	} else if p.statusAfter != "landing" {
		t.Errorf("dry-run preview mutated row #%d: status=%q want landing (the preview must not reap)", agedID, p.statusAfter)
	}
	if p := staleReapProbe(t, ls, freshBranch, "t4-dryrun-smoke", 0, 30*time.Minute, false); p.previewedStale {
		t.Errorf("preview reported the FRESH landing row #%d — a live land would be falsely previewed as reapable", freshID)
	}

	// REAL-REAP pass (doReap=true): the preview agrees with the reap — the aged row is
	// requeued, the fresh row is never reaped.
	if p := staleReapProbe(t, ls, agedBranch, "t4-dryrun-smoke", time.Hour, 30*time.Minute, true); !(p.previewedStale && p.reaped) {
		t.Errorf("reap did NOT requeue the aged row #%d the dry-run named (previewed=%v reaped=%v)", agedID, p.previewedStale, p.reaped)
	}
	if p := staleReapProbe(t, ls, freshBranch, "t4-dryrun-smoke", 0, 30*time.Minute, true); p.reaped {
		t.Errorf("reap requeued the FRESH row #%d the dry-run excluded", freshID)
	}
}

// TestRunGate is the HERMETIC unit test on the runner's gate-execution helper — no
// server, no leader, no git, no live DB. It pins the three behaviors the per-row
// gate depends on: a zero-exit gate (`true`) returns nil (green → the branch is
// allowed to land), a non-zero gate (`false`) returns a non-nil error (red →
// status='failed'), and combined stdout+stderr is captured so gateTail surfaces the
// failure reason to the operator (a gate writing NEEDLE to STDERR and exiting
// non-zero must still appear in the tail). This is the safe way to prove the
// gate-execution path WITHOUT contending the live __land_leader__ sentinel.
func TestRunGate(t *testing.T) {
	dir := t.TempDir()

	// Green: a zero-exit gate runs clean.
	if gr := runGate(dir, "true", time.Minute); !gr.ok || gr.exitCode != 0 || gr.transient {
		t.Errorf("runGate(\"true\") = %+v, want ok exit 0 not transient", gr)
	}

	// Red: a clean non-zero gate is a real red gate (NOT transient) and carries
	// the exit code for the operator-facing detail.
	if gr := runGate(dir, "false", time.Minute); gr.ok || gr.transient || gr.exitCode != 1 {
		t.Errorf("runGate(\"false\") = %+v, want red exit 1 not transient", gr)
	}

	// Tail capture: a gate that writes to STDERR and exits non-zero must surface
	// that output via gateTail (combined stdout+stderr), so the failed-detail tells
	// the operator WHY the gate went red.
	gr := runGate(dir, "echo NEEDLE-stdout; echo NEEDLE-stderr >&2; false", time.Minute)
	if gr.ok {
		t.Errorf("runGate(...; false) ok=true, want red")
	}
	tail := gateTail(gr.out)
	if !strings.Contains(tail, "NEEDLE-stdout") {
		t.Errorf("gateTail did not capture stdout; tail=%q", tail)
	}
	if !strings.Contains(tail, "NEEDLE-stderr") {
		t.Errorf("gateTail did not capture stderr; tail=%q", tail)
	}

	// Transient — exit 127 (command not found from the shell) is infrastructure,
	// NOT a red gate, so the runner requeues rather than parks.
	if gr := runGate(dir, "this-command-does-not-exist-zzz", time.Minute); !gr.transient || gr.exitCode != 127 {
		t.Errorf("runGate(missing cmd) = %+v, want transient exit 127", gr)
	}

	// Transient — signal death (SIGKILL via `kill -9 $$`) is infrastructure-ish
	// (OOM-kill class), so it requeues, not fails.
	if gr := runGate(dir, "kill -9 $$", time.Minute); !gr.transient {
		t.Errorf("runGate(self-SIGKILL) = %+v, want transient", gr)
	}

	// Transient — a gate that exceeds the deadline is timed out (and the process
	// group is killed). Use a tiny timeout against a `sleep` to exercise the
	// deadline path quickly.
	gr = runGate(dir, "sleep 30", 100*time.Millisecond)
	if !gr.timedOut || !gr.transient {
		t.Errorf("runGate(sleep 30, 100ms) = %+v, want timedOut+transient", gr)
	}

	// Empty-output gate: gateTail must never be a bare "" so the failed-detail
	// is never "gate red: ".
	if got := gateTail(""); got != "(no gate output)" {
		t.Errorf("gateTail(\"\") = %q, want the (no gate output) marker", got)
	}
}

// TestLandqEnqueueGateRoundTripLive is the optional live-DB check that a per-row
// gate persists through enqueueLand and is surfaced by listLand. Against a
// reachable shared Postgres it migrates (additive, idempotent — this is what
// applies the gate ALTER to the live DB), enqueues a CLEARLY-TEST branch carrying
// Gate:"true", confirms listLand reports r.Gate=="true", then deletes every
// inserted row via t.Cleanup so the shared DB is left pristine. It NEVER runs the
// runner (the live __land_leader__ sentinel is held by the production runner).
// SKIPS cleanly when the lock server is disabled or unreachable.
func TestLandqEnqueueGateRoundTripLive(t *testing.T) {
	// Default gate: skip (disabled). DS_LANDQ_EPHEMERAL_PG=1: throwaway Postgres.
	// ls.close is registered FIRST so it runs LAST (after the row delete below).
	ls := landqServerForTest(t)

	branch := fmt.Sprintf("landq-smoke/gate-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := ls.deleteLandByBranch(branch); err != nil {
			t.Errorf("cleanup deleteLandByBranch(%q) failed — a test row may remain in the SHARED DB: %v", branch, err)
		}
	})

	e := LandEntry{Branch: branch, Gate: "true", RequestedBy: "465r-gate-smoke", Host: devHost()}
	id, enqueued, err := ls.enqueueLand(e)
	if err != nil {
		t.Fatalf("enqueueLand: %v", err)
	}
	if !enqueued || id <= 0 {
		t.Fatalf("enqueueLand should report a fresh insert; got enqueued=%v id=%d", enqueued, id)
	}

	// Scope by branch (any status) — a concurrent runner may already have claimed
	// our fresh row to 'landing', which would race a listLand("queued") existence
	// check.
	mine := branchRows(t, ls, branch)
	if len(mine) != 1 {
		t.Fatalf("expected exactly 1 row for branch %q after enqueue; got %d (%+v)", branch, len(mine), mine)
	}
	if mine[0].Gate != "true" {
		t.Errorf("round-trip gate drifted: r.Gate=%q want %q", mine[0].Gate, "true")
	}

	// The claim path must also carry the gate through its RETURNING/Scan so the
	// runner sees the per-row gate (this is the path landOnePass reads). Claim OUR
	// row by branch rather than via the global claimNextLand pick order, so a live
	// production runner cannot claim it first and strand the assertion.
	claimed := claimOwnLandByBranch(t, ls, branch, "465r-gate-runner")
	if claimed.Gate != "true" {
		t.Errorf("claim gate drifted: claimed.Gate=%q want %q", claimed.Gate, "true")
	}
}

// TestLandLeaderSentinelSurvivesReap proves the double-leader fix: a LIVE leader's
// __land_leader__ sentinel must NOT be evicted by a routine age-reap (the prod
// failure where audit-stuck/`lockserver reap` deleted the election out from under
// a slow-landing leader, opening a two-writers-on-main window). It manipulates the
// FIXED sentinel id, so it runs ONLY against an EPHEMERAL throwaway Postgres
// (DS_LANDQ_EPHEMERAL_PG=1) — never the shared production DB where a real leader
// holds the sentinel. It (1) elects a leader, (2) ages the sentinel's
// task_locks.locked_at far past any reap threshold, (3) runs reap(0) (reap
// everything older than 0s), and asserts the sentinel SURVIVES (reap-exclusion),
// then (4) heartbeats and asserts locked_at is refreshed to ~now (so even a
// hypothetical age-only consumer sees the live leader as fresh).
func TestLandLeaderSentinelSurvivesReap(t *testing.T) {
	if !truthyEnv(ephemeralGateEnv) {
		t.Skip("manipulates the fixed __land_leader__ sentinel; runs only against an ephemeral PG (set " +
			ephemeralGateEnv + "=1)")
	}
	ls := landqServerForTest(t)
	const sess = "sentinel-reap-test"

	// Start from a clean slate (a prior aborted run could have left the sentinel).
	_, _ = ls.release(landLeaderSentinel, "", true)
	t.Cleanup(func() { _, _ = ls.release(landLeaderSentinel, "", true) })

	won, holder, err := ls.acquireLandLeader(sess, devHost())
	if err != nil {
		t.Fatalf("acquireLandLeader: %v", err)
	}
	if !won {
		t.Fatalf("did not win a fresh sentinel; held by %+v", holder)
	}

	// Also drop an ordinary stale lock to confirm reap STILL clears non-sentinel
	// rows (the exclusion is surgical, not a blanket reap disable).
	if _, _, aerr := ls.acquire("ordinary-stale-task", "someone", devHost()); aerr != nil {
		t.Fatalf("acquire ordinary lock: %v", aerr)
	}

	// Age BOTH locks well past any threshold.
	if _, err := ls.db.Exec(
		`UPDATE task_locks SET locked_at = now() - interval '90 minutes'`,
	); err != nil {
		t.Fatalf("aging task_locks: %v", err)
	}

	// Reap everything older than 0s: the ordinary lock must go, the sentinel stays.
	reaped, err := ls.reap(0)
	if err != nil {
		t.Fatalf("reap(0): %v", err)
	}
	for _, id := range reaped {
		if id == landLeaderSentinel {
			t.Fatalf("reap evicted the live %s sentinel — double-writer window reopened", landLeaderSentinel)
		}
	}
	h, err := ls.holder(landLeaderSentinel)
	if err != nil {
		t.Fatalf("holder(%s): %v", landLeaderSentinel, err)
	}
	if h == nil || h.LockedBy != sess {
		t.Fatalf("sentinel was reaped/changed: holder=%+v, want still held by %q", h, sess)
	}

	// Heartbeat must refresh the sentinel's locked_at to ~now (it was aged to -90m).
	if err := ls.heartbeatLandLeader(sess); err != nil {
		t.Fatalf("heartbeatLandLeader: %v", err)
	}
	var ageSecs float64
	if err := ls.db.QueryRow(
		`SELECT EXTRACT(EPOCH FROM (now() - locked_at)) FROM task_locks WHERE task_id = $1`,
		landLeaderSentinel,
	).Scan(&ageSecs); err != nil {
		t.Fatalf("reading refreshed locked_at: %v", err)
	}
	if ageSecs > 60 {
		t.Errorf("heartbeat did not refresh locked_at; age=%.0fs (want <60s)", ageSecs)
	}
}
