// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"testing"
	"time"
)

// cmd_wave_live_test.go is the OPT-IN hermetic-Postgres suite for the wave SDK and
// the new landq leader / status --json read primitives. Every test here routes its
// setup through landqServerForTest(t) (landq_test_helpers_test.go): on the default
// CI/wave gate it SKIPS (lock server disabled/unreachable); under
// DS_LANDQ_EPHEMERAL_PG=1 it runs against a throwaway Postgres. They exercise the
// lockServer seam the `taskdb wave`/`landq leader` verbs are thin wrappers over —
// recordEvent/recordEvents, unitRollup + unitActivityAges (the staleness join),
// acquireLandLeader/holder, listLand — against a real DB, the SAME shape the
// existing landq *Live tests use. Each test scopes to a unique wave/branch and
// cleans up its rows so the suite is reentrant on a caller-owned ephemeral DSN.

// cleanupWaveEvents deletes every wave_events / lock_heartbeats row for a wave so
// a caller-owned ephemeral DSN stays clean across runs (the auto-spun DB is fresh
// per run, but a reused DSN is not). Best-effort: a delete error is reported, not
// fatal.
func cleanupWaveEvents(t *testing.T, ls *lockServer, wave string) {
	t.Helper()
	if _, err := ls.db.Exec(`DELETE FROM wave_events WHERE wave = $1`, wave); err != nil {
		t.Errorf("cleanup wave_events(%q): %v", wave, err)
	}
}

// TestWaveReportRecordEventLive: a single recordEvent round-trips into wave_events
// and is visible to listEvents and unitRollup — the core of `wave report`.
func TestWaveReportRecordEventLive(t *testing.T) {
	ls := landqServerForTest(t)
	wave := fmt.Sprintf("wave-smoke/report-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupWaveEvents(t, ls, wave) })

	e := WaveEvent{
		Wave: wave, RunID: "r1", UnitKey: "u1", TaskID: "TASKID1",
		Phase: "implement", Event: "start", Status: "in-progress",
		Session: "sess-A", Host: devHost(), Tokens: 42, Note: "hello",
	}
	if err := ls.recordEvent(e); err != nil {
		t.Fatalf("recordEvent: %v", err)
	}

	evs, err := ls.listEvents(wave, "", 50)
	if err != nil {
		t.Fatalf("listEvents: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("listEvents returned %d events, want 1", len(evs))
	}
	got := evs[0]
	if got.UnitKey != "u1" || got.Phase != "implement" || got.Status != "in-progress" || got.Note != "hello" {
		t.Errorf("round-trip drift: %+v", got)
	}
	if got.Tokens != 42 {
		t.Errorf("tokens=%d want 42", got.Tokens)
	}
	if got.Ts == "" {
		t.Errorf("ts should render non-empty via to_char")
	}

	rollup, err := ls.unitRollup(wave, "")
	if err != nil {
		t.Fatalf("unitRollup: %v", err)
	}
	if len(rollup) != 1 || rollup[0].UnitKey != "u1" || rollup[0].EventCount != 1 {
		t.Errorf("rollup drift: %+v", rollup)
	}
}

// TestWaveReportBatchLive: recordEvents records a whole batch in ONE transaction
// and every row is visible — the core of `wave report --batch`.
func TestWaveReportBatchLive(t *testing.T) {
	ls := landqServerForTest(t)
	wave := fmt.Sprintf("wave-smoke/batch-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupWaveEvents(t, ls, wave) })

	batch := []WaveEvent{
		{Wave: wave, RunID: "r1", UnitKey: "u1", Phase: "scope", Event: "start", Host: devHost()},
		{Wave: wave, RunID: "r1", UnitKey: "u1", Phase: "implement", Event: "start", Status: "in-progress", Host: devHost()},
		{Wave: wave, RunID: "r1", UnitKey: "u2", Phase: "implement", Event: "start", Status: "in-progress", Host: devHost()},
		{Wave: wave, RunID: "r1", UnitKey: "u2", Phase: "review", Event: "end", Status: "done", Host: devHost()},
	}
	if err := ls.recordEvents(batch); err != nil {
		t.Fatalf("recordEvents: %v", err)
	}

	evs, err := ls.listEvents(wave, "", 50)
	if err != nil {
		t.Fatalf("listEvents: %v", err)
	}
	if len(evs) != 4 {
		t.Fatalf("listEvents returned %d events, want 4", len(evs))
	}

	rollup, err := ls.unitRollup(wave, "")
	if err != nil {
		t.Fatalf("unitRollup: %v", err)
	}
	byUnit := map[string]WaveUnitRollup{}
	for _, r := range rollup {
		byUnit[r.UnitKey] = r
	}
	if len(byUnit) != 2 {
		t.Fatalf("rollup has %d units, want 2 (%+v)", len(byUnit), rollup)
	}
	if byUnit["u1"].EventCount != 2 || byUnit["u1"].LastPhase != "implement" {
		t.Errorf("u1 rollup drift: %+v", byUnit["u1"])
	}
	if byUnit["u2"].EventCount != 2 || byUnit["u2"].LastStatus != "done" || byUnit["u2"].LastPhase != "review" {
		t.Errorf("u2 rollup drift: %+v", byUnit["u2"])
	}

	// An EMPTY batch is a no-op (no error, no rows).
	if err := ls.recordEvents(nil); err != nil {
		t.Errorf("recordEvents(nil) should be a no-op, got %v", err)
	}
}

// TestWaveStatusStalenessLive: unitRollup + unitActivityAges (the join `wave
// status` makes) yield the right staleness verdict. A unit with a session+task
// gets a fresh lock_heartbeats row (recordEvent upserts it) → NOT stale; a unit
// with NO heartbeat falls back to event-age → fresh event → NOT stale either.
func TestWaveStatusStalenessLive(t *testing.T) {
	ls := landqServerForTest(t)
	wave := fmt.Sprintf("wave-smoke/status-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupWaveEvents(t, ls, wave)
		// recordEvent also upserts lock_heartbeats for the session+task row; clean it.
		_, _ = ls.db.Exec(`DELETE FROM lock_heartbeats WHERE task_id = $1`, "WSTASK1")
	})

	// u1 has a session+task → a heartbeat row is upserted (fresh activity).
	if err := ls.recordEvent(WaveEvent{
		Wave: wave, RunID: "r1", UnitKey: "u1", TaskID: "WSTASK1",
		Phase: "implement", Event: "heartbeat", Session: "sess-live", Host: devHost(),
	}); err != nil {
		t.Fatalf("recordEvent u1: %v", err)
	}
	// u2 has NO session/task → no heartbeat; staleness falls back to event-age.
	if err := ls.recordEvent(WaveEvent{
		Wave: wave, RunID: "r1", UnitKey: "u2",
		Phase: "scope", Event: "start", Host: devHost(),
	}); err != nil {
		t.Fatalf("recordEvent u2: %v", err)
	}

	rollup, err := ls.unitRollup(wave, "")
	if err != nil {
		t.Fatalf("unitRollup: %v", err)
	}
	activity, err := ls.unitActivityAges(wave, "")
	if err != nil {
		t.Fatalf("unitActivityAges: %v", err)
	}
	if len(rollup) != 2 {
		t.Fatalf("rollup has %d units, want 2", len(rollup))
	}

	for _, r := range rollup {
		ua := activity[r.UnitKey]
		stale := lockStale(ua.EventAge, ua.HBAge, ua.HasHeartbeat)
		if stale {
			t.Errorf("unit %q flagged stale on a freshly-recorded event (eventAge=%v hbAge=%v hasHB=%v)",
				r.UnitKey, ua.EventAge, ua.HBAge, ua.HasHeartbeat)
		}
		if r.UnitKey == "u1" && !ua.HasHeartbeat {
			t.Errorf("u1 had a session+task → should have a heartbeat in activity, got none")
		}
		if r.UnitKey == "u2" && ua.HasHeartbeat {
			t.Errorf("u2 had no session/task → should have NO heartbeat, got hbAge=%v", ua.HBAge)
		}
	}
}

// TestLandqLeaderHolderLive: acquireLandLeader elects the sentinel and holder()
// reports the elected session — the read `landq leader` surfaces. After
// releaseLandLeader the sentinel is gone (no leader → runner down).
func TestLandqLeaderHolderLive(t *testing.T) {
	ls := landqServerForTest(t)
	const sess = "leader-smoke-sess"
	t.Cleanup(func() { _, _ = ls.releaseLandLeader(sess) })

	// Start clean: ensure no stale sentinel from a prior aborted run.
	_, _ = ls.release(landLeaderSentinel, sess, true)

	// No leader yet.
	if h, err := ls.holder(landLeaderSentinel); err != nil {
		t.Fatalf("holder(pre-elect): %v", err)
	} else if h != nil {
		t.Skipf("a real landq runner already holds %s (held by %s) — skipping the no-leader assertion", landLeaderSentinel, h.LockedBy)
	}

	won, _, err := ls.acquireLandLeader(sess, devHost())
	if err != nil {
		t.Fatalf("acquireLandLeader: %v", err)
	}
	if !won {
		t.Skip("could not win the election sentinel (a live runner holds it) — skipping")
	}

	h, err := ls.holder(landLeaderSentinel)
	if err != nil {
		t.Fatalf("holder(post-elect): %v", err)
	}
	if h == nil {
		t.Fatalf("holder returned nil right after a winning election")
	}
	if h.LockedBy != sess {
		t.Errorf("leader=%q want %q", h.LockedBy, sess)
	}
	if h.Host != devHost() {
		t.Errorf("leader host=%q want %q", h.Host, devHost())
	}

	// Release → no leader (the "runner down?" state).
	if _, err := ls.releaseLandLeader(sess); err != nil {
		t.Fatalf("releaseLandLeader: %v", err)
	}
	if h, err := ls.holder(landLeaderSentinel); err != nil {
		t.Fatalf("holder(post-release): %v", err)
	} else if h != nil {
		t.Errorf("sentinel still held after release: %+v", h)
	}
}

// TestStatusJSONLandqDepthLive: the landing-queue depth section of `status --json`
// (ls.listLand("", 0) rolled up by status) reflects an enqueued row. Asserts the
// queue read the JSON path uses, scoped to a unique branch.
func TestStatusJSONLandqDepthLive(t *testing.T) {
	ls := landqServerForTest(t)
	branch := fmt.Sprintf("status-json-smoke/%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := ls.deleteLandByBranch(branch); err != nil {
			t.Errorf("cleanup deleteLandByBranch(%q): %v", branch, err)
		}
	})

	id, enqueued, err := ls.enqueueLand(LandEntry{Branch: branch, RequestedBy: "status-json-smoke", Host: devHost()})
	if err != nil {
		t.Fatalf("enqueueLand: %v", err)
	}
	if !enqueued || id <= 0 {
		t.Fatalf("enqueueLand should be a fresh insert; got enqueued=%v id=%d", enqueued, id)
	}

	// The depth read `status --json` performs: list all rows, roll up by status.
	rows, err := ls.listLand("", 0)
	if err != nil {
		t.Fatalf("listLand: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.Branch == branch {
			found = true
			if r.Status != "queued" && r.Status != "landing" {
				t.Errorf("our row status=%q want queued (or landing if a live runner claimed it)", r.Status)
			}
		}
	}
	if !found {
		t.Errorf("enqueued branch %q not visible in listLand (the status --json depth source)", branch)
	}
}
