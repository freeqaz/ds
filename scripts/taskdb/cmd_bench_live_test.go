// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// cmd_bench_live_test.go is the OPT-IN hermetic-Postgres suite for the doc-27
// Lever-0 land_retry scorer (cmd_bench.go + lockserver.go landRetryStats). Like
// the other landq *Live tests it routes setup through landqServerForTest(t): on
// the default CI/wave gate it SKIPS (lock server disabled/unreachable); under
// DS_LANDQ_EPHEMERAL_PG=1 it runs against a throwaway Postgres. It seeds synthetic
// phase='land' wave_events on a unique wave id and asserts landRetryStats derives
// the right land_retry, then t.Cleanup deletes every seeded row (NEVER leaves rows
// behind — the shared DB is live).

// TestBenchScoreLandRetryLive seeds two branches on one synthetic wave — a clean
// land (one claimed/landing + landed → land_retry 0 for that branch) and a
// conflict-then-reland (claimed/landing + conflict + claimed/landing + landed →
// one extra attempt) — and asserts the aggregate: 3 landing events dispatched, 2
// distinct landed branches, land_retry 1, 1 conflict, 0 failures. It then asserts
// an all-clean wave scores land_retry 0 (the healthy-serial-queue invariant of doc
// 27 L132), and round-trips the benchPayload through JSON to lock the --json field
// names.
func TestBenchScoreLandRetryLive(t *testing.T) {
	ls := landqServerForTest(t)
	wave := fmt.Sprintf("bench-smoke/score-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupWaveEvents(t, ls, wave) })

	// seed emits a phase='land' wave_event exactly as emitLandEvent would, with the
	// "landq #<id> <branch>" note carrying the stable per-branch key.
	seed := func(id int, branch, event, status string) {
		t.Helper()
		if err := ls.recordEvent(WaveEvent{
			Wave: wave, RunID: "r1", Phase: "land",
			Event: event, Status: status, Session: "bench-smoke-sess",
			Host: devHost(), Note: fmt.Sprintf("landq #%d %s", id, branch),
		}); err != nil {
			t.Fatalf("seed land event (#%d %s/%s): %v", id, event, status, err)
		}
	}

	// Branch #9001: a CLEAN land — one claim that succeeds (land_retry 0).
	seed(9001, "feat/clean", "claimed", "landing")
	seed(9001, "feat/clean", "status-change", "landed")
	// Branch #9002: a CONFLICT-THEN-RELAND — first claim conflicts, second lands
	// (one EXTRA land attempt → land_retry 1 for this branch).
	seed(9002, "feat/retry", "claimed", "landing")
	seed(9002, "feat/retry", "status-change", "conflict")
	seed(9002, "feat/retry", "claimed", "landing")
	seed(9002, "feat/retry", "status-change", "landed")

	st, err := ls.landRetryStats(wave, 0)
	if err != nil {
		t.Fatalf("landRetryStats: %v", err)
	}
	if st.Dispatched != 3 {
		t.Errorf("Dispatched=%d want 3 (3 'landing' events)", st.Dispatched)
	}
	if st.LandedBranches != 2 {
		t.Errorf("LandedBranches=%d want 2 (#9001, #9002)", st.LandedBranches)
	}
	if st.LandRetry != 1 {
		t.Errorf("LandRetry=%d want 1 (one extra attempt on #9002)", st.LandRetry)
	}
	if st.Conflicts != 1 {
		t.Errorf("Conflicts=%d want 1", st.Conflicts)
	}
	if st.Failures != 0 {
		t.Errorf("Failures=%d want 0", st.Failures)
	}

	// Healthy-serial-queue invariant (doc 27 L132): a single clean land scores 0.
	cleanWave := fmt.Sprintf("bench-smoke/clean-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupWaveEvents(t, ls, cleanWave) })
	if err := ls.recordEvent(WaveEvent{
		Wave: cleanWave, RunID: "r1", Phase: "land", Event: "claimed", Status: "landing",
		Session: "bench-smoke-sess", Host: devHost(), Note: "landq #9100 feat/only",
	}); err != nil {
		t.Fatalf("seed clean claimed: %v", err)
	}
	if err := ls.recordEvent(WaveEvent{
		Wave: cleanWave, RunID: "r1", Phase: "land", Event: "status-change", Status: "landed",
		Session: "bench-smoke-sess", Host: devHost(), Note: "landq #9100 feat/only",
	}); err != nil {
		t.Fatalf("seed clean landed: %v", err)
	}
	cst, err := ls.landRetryStats(cleanWave, 0)
	if err != nil {
		t.Fatalf("landRetryStats(clean): %v", err)
	}
	if cst.Dispatched != 1 || cst.LandedBranches != 1 || cst.LandRetry != 0 {
		t.Errorf("clean wave: dispatched=%d landed=%d land_retry=%d, want 1/1/0", cst.Dispatched, cst.LandedBranches, cst.LandRetry)
	}

	// Lock the --json field names by round-tripping a benchPayload built from the
	// stats (the same payload benchScore marshals).
	p := benchPayload{
		Dispatched: st.Dispatched, LandedBranches: st.LandedBranches,
		LandRetry: st.LandRetry, LandRetryRate: float64(st.LandRetry) / float64(st.Dispatched),
		Conflicts: st.Conflicts, Failures: st.Failures, Wave: wave, Reachable: true,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal benchPayload: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal benchPayload: %v", err)
	}
	for _, k := range []string{"dispatched", "landed_branches", "land_retry", "land_retry_rate", "conflicts", "failures", "reachable"} {
		if _, ok := back[k]; !ok {
			t.Errorf("--json payload missing field %q (got %s)", k, string(b))
		}
	}
}

// TestParseLandBranchKey covers the note parser in isolation (no DB): the
// "landq #<id> <branch>" shape, an id with no trailing branch, and the defensive
// no-'#' fallback that keeps distinct notes from collapsing to one key.
func TestParseLandBranchKey(t *testing.T) {
	cases := []struct{ note, want string }{
		{"landq #9001 feat/clean", "9001"},
		{"landq #42", "42"},
		{"no hash here", "no hash here"},
		{"", ""},
		{"landq #7 feat/with spaces in branch", "7"},
	}
	for _, c := range cases {
		if got := parseLandBranchKey(c.note); got != c.want {
			t.Errorf("parseLandBranchKey(%q)=%q want %q", c.note, got, c.want)
		}
	}
}
