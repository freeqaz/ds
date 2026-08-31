// SPDX-License-Identifier: Apache-2.0

package parkstore

import (
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// sql_test.go — coverage for the database/sql twin of parkstore.Store.
//
// Two tiers, both stdlib-only:
//
//  1. SEAM + WRITE-SHAPE tests run UNCONDITIONALLY in the sandbox with NO
//     database. *SQL satisfies the SAME Store / askhold.ParkRecorder seam Memory
//     does, and the empty-session-UUID write-shape guard returns the SAME
//     errEmptySession Memory returns BEFORE touching the *sql.DB — so they run
//     against a nil-db *SQL and never reach a driver (D50: no live IO in the
//     gate).
//
//  2. The CONFORMANCE round-trip is DS_PG_DSN-gated and SKIPS without a database,
//     mirroring internal/store's openPostgresOrSkip pattern (the deferred manual
//     step). It drives the askhold PARK/RESTART/RESUME state machine THROUGH the
//     live SQL backing — the genuinely-durable twin of parkstore_test.go's
//     in-memory restart-survival assertion — and never runs in `go test ./...`,
//     so the wave gate stays green with no live DB. The target DB must have
//     migrations 0001..0012 applied.

// TestSQL_SatisfiesParkRecorderSeam pins the seam contract structurally: a *SQL
// is both a parkstore.Store and the askhold.ParkRecorder askhold injects — the
// SAME assertion parkstore_test.go makes for *Memory, so the two backings are
// interchangeable behind the seam. If askhold's seam shape drifts, this stops
// compiling. No database is touched (the assertion is purely type-level).
func TestSQL_SatisfiesParkRecorderSeam(t *testing.T) {
	var _ Store = NewSQL(nil)
	var _ askhold.ParkRecorder = NewSQL(nil)
}

// TestSQL_EmptySessionIsWriteShapeFault asserts the empty-session-UUID guard
// returns the SAME errEmptySession Memory returns, on EVERY keyed method, BEFORE
// any *sql.DB access — so the in-memory and SQL backings reject a malformed write
// indistinguishably. It runs against a nil-db *SQL precisely to prove the guard
// short-circuits ahead of the driver: if any path reached the (nil) db it would
// panic instead of returning the sentinel. No database, no driver (D50).
func TestSQL_EmptySessionIsWriteShapeFault(t *testing.T) {
	st := NewSQL(nil)

	if err := st.RecordParked(askhold.Parked{SessionUUID: ""}); !errors.Is(err, errEmptySession) {
		t.Fatalf("RecordParked(empty) = %v, want errEmptySession (same as Memory)", err)
	}
	if err := st.ClearParked(askhold.Parked{SessionUUID: ""}); !errors.Is(err, errEmptySession) {
		t.Fatalf("ClearParked(empty) = %v, want errEmptySession (same as Memory)", err)
	}
	if _, _, err := st.Lookup(""); !errors.Is(err, errEmptySession) {
		t.Fatalf("Lookup(empty) = %v, want errEmptySession (same as Memory)", err)
	}

	// Parity check: Memory returns the identical sentinel on the identical inputs,
	// so a caller's errors.Is(err, errEmptySession) cannot tell the backings apart.
	mem := NewMemory()
	if memErr, sqlErr := mem.RecordParked(askhold.Parked{SessionUUID: ""}), st.RecordParked(askhold.Parked{SessionUUID: ""}); !errors.Is(memErr, errEmptySession) || !errors.Is(sqlErr, errEmptySession) {
		t.Fatalf("Memory/SQL empty-UUID parity broken: mem=%v sql=%v", memErr, sqlErr)
	}
}

// rung2AskSQL is a synthetic genuine rung-2 ask (the class that PARKS per D46),
// the only ask askhold.NewParked accepts. Synthetic only (D50): no live IO. It
// mirrors parkstore_test.go's rung2Ask so the SQL conformance drives the SAME
// shape the in-memory tests do.
func rung2AskSQL() askhold.Ask {
	return askhold.Ask{
		ResourceKind:  "service",
		ResourceName:  "bulk-delete",
		MatchedRuleID: "rule-suspend",
		Rung2:         true,
	}
}

// openSQLParkOrSkip wires a *SQL from DS_PG_DSN (driver from DS_PG_DRIVER,
// default "postgres"), clearing park_join so each test starts empty — the same
// driver-agnostic, stdlib-only, SKIP-without-DB gating internal/store's
// openPostgresOrSkip uses. It SKIPS (never fails) when the env / driver /
// database is absent, so the live conformance is a DEFERRED MANUAL STEP, not a
// sandbox gate: `go test ./...` runs the seam tests above and skips this. The
// target DB must have migrations 0001..0012 applied (0012 adds park_join).
func openSQLParkOrSkip(t *testing.T) *SQL {
	t.Helper()
	// The sql.Open + ping + skip dance is single-sourced through storetest.OpenOrSkip
	// (its SkipMessages reproduce this caller's exact skip wording byte-for-byte): this
	// caller keeps its OWN env var (DS_PG_DSN / DS_PG_DRIVER). The `DELETE FROM park_join`
	// stays a POST-OPEN step here (with its own skip-on-err, byte-identical) — it clears
	// the table so each test starts empty, the per-test lifecycle the helper does not own.
	db := storetest.OpenOrSkip(t, "DS_PG_DSN", "DS_PG_DRIVER", storetest.SkipMessages{
		Unset:   "DS_PG_DSN not set: skipping live-Postgres parkstore conformance (deferred manual step)",
		OpenErr: "sql.Open(%q): %v — register a Postgres driver and apply migrations 0001..0012 to run this",
		PingErr: "ping %s: %v — Postgres unreachable; deferred manual step",
	})
	if _, err := db.Exec(`DELETE FROM park_join`); err != nil {
		t.Skipf("clear park_join: %v — apply migration 0012_park_join.sql to run this", err)
	}
	return NewSQL(db)
}

// TestSQL_RecordRestartResume_SurvivesAndResumesOnAnswer is the headline
// restart-survival assertion against the LIVE backing — the genuinely-durable
// twin of parkstore_test.go's TestRecordRestartResume_SurvivesAndResumesOnAnswer
// (which re-reads an in-memory value). A rung-2 ask is PARKED and recorded
// through the SQL store; the control plane "restarts" (we re-read the join from
// the SAME table); the park is still PARKED with NO verdict; a human ALLOW
// answer resumes it; and the resume CLEARS the row so a second re-read finds
// nothing. DS_PG_DSN-gated: SKIPS in the sandbox.
func TestSQL_RecordRestartResume_SurvivesAndResumesOnAnswer(t *testing.T) {
	st := openSQLParkOrSkip(t)
	parkedAt := time.Date(2026, 6, 16, 9, 0, 0, 0, time.UTC)

	// --- epoch #1: park the ask through the durable SQL backing. ---
	if _, err := askhold.NewParked(st, "sess-7", rung2AskSQL(), parkedAt); err != nil {
		t.Fatalf("epoch#1 NewParked through SQL: %v", err)
	}

	// --- CONTROL-PLANE RESTART: re-read the join from the SAME table (the row
	// outlives the process; nothing was held across the "restart"). ---
	reread, ok, err := st.Lookup("sess-7")
	if err != nil {
		t.Fatalf("post-restart Lookup: %v", err)
	}
	if !ok {
		t.Fatalf("a parked ask MUST survive a restart — the join was not re-readable from the table")
	}
	if reread.Phase != askhold.ParkPhaseParked {
		t.Fatalf("re-read ask must still be PARKED (never timed out into allow/kill); phase=%v", reread.Phase)
	}
	if reread.Verdict != askhold.ResumeVerdictUnspecified {
		t.Fatalf("a survived park must carry NO verdict; verdict=%v", reread.Verdict)
	}
	if reread.Ask.ResourceName != "bulk-delete" || reread.Ask.MatchedRuleID != "rule-suspend" || !reread.Ask.Rung2 {
		t.Fatalf("re-read Ask not faithful through the table: %+v", reread.Ask)
	}
	if !reread.ParkedAt.Equal(parkedAt) {
		t.Fatalf("parked_at not round-tripped through timestamptz: got %v, want %v", reread.ParkedAt, parkedAt)
	}

	// --- the human answer arrives; resume the RE-READ park through the SAME
	// backing — proving the resume is driven by the recovered join. ---
	answeredAt := parkedAt.Add(3 * time.Hour)
	resumed, err := reread.Resume(st, askhold.ResumeVerdictAllow, "allow-once:service/bulk-delete;ttl=session", askhold.DenyReason{}, answeredAt)
	if err != nil {
		t.Fatalf("resume of the re-read park through SQL: %v", err)
	}
	if resumed.Phase != askhold.ParkPhaseResumed || resumed.Verdict != askhold.ResumeVerdictAllow {
		t.Fatalf("resume must carry the human ALLOW answer; phase=%v verdict=%v", resumed.Phase, resumed.Verdict)
	}

	// --- after the resume the row is gone: a SECOND restart re-read finds nothing
	// (the ask resolved on an answer, not a timeout), and List is empty. ---
	if _, ok, err := st.Lookup("sess-7"); err != nil {
		t.Fatalf("post-resume Lookup: %v", err)
	} else if ok {
		t.Fatalf("a resumed park must be cleared from the durable join")
	}
	if list, err := st.List(); err != nil {
		t.Fatalf("post-resume List: %v", err)
	} else if len(list) != 0 {
		t.Fatalf("no outstanding parks should remain after resume, got %+v", list)
	}
}

// TestSQL_UpsertAndListOutstanding pins RecordParked-as-UPSERT and
// List-outstanding-only against the live engine: re-recording a still-parked
// session OVERWRITES in place (one row per session, not a duplicate), List
// enumerates only still-parked joins in session-UUID order, and a cleared join
// drops out. The in-memory equivalent lives in parkstore_test.go
// (TestList_OutstandingOnly_DeterministicOrder). DS_PG_DSN-gated: SKIPS in the
// sandbox.
func TestSQL_UpsertAndListOutstanding(t *testing.T) {
	st := openSQLParkOrSkip(t)
	now := time.Date(2026, 6, 16, 8, 0, 0, 0, time.UTC)

	for _, sid := range []string{"sess-c", "sess-a", "sess-b"} {
		if _, err := askhold.NewParked(st, sid, rung2AskSQL(), now); err != nil {
			t.Fatalf("park %s: %v", sid, err)
		}
	}

	// Re-record sess-a (still parked): the UPSERT must overwrite in place, not
	// duplicate — List must still show exactly three rows.
	if err := st.RecordParked(askhold.Parked{SessionUUID: "sess-a", Ask: rung2AskSQL(), ParkedAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("re-record sess-a (UPSERT): %v", err)
	}

	// Resume one — it must drop out of the outstanding set (ClearParked DELETE).
	mid, ok, err := st.Lookup("sess-b")
	if err != nil || !ok {
		t.Fatalf("setup lookup sess-b: ok=%v err=%v", ok, err)
	}
	if _, err := mid.Resume(st, askhold.ResumeVerdictDeny, "", askhold.DenyReason{Code: askhold.DenyUnattended}, now.Add(time.Minute)); err != nil {
		t.Fatalf("resume sess-b: %v", err)
	}

	list, err := st.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List must contain only the 2 outstanding parks (UPSERT did not duplicate), got %d: %+v", len(list), list)
	}
	if list[0].SessionUUID != "sess-a" || list[1].SessionUUID != "sess-c" {
		t.Fatalf("List must be session-UUID ordered, got [%s %s]", list[0].SessionUUID, list[1].SessionUUID)
	}
}

// TestSQL_ClearParkedIdempotent pins ClearParked as an idempotent DELETE against
// the live engine: clearing an absent / already-cleared join is a no-op success,
// so a re-driven clear after a partial write never errors. Mirrors
// parkstore_test.go's TestClearParked_Idempotent. DS_PG_DSN-gated: SKIPS in the
// sandbox.
func TestSQL_ClearParkedIdempotent(t *testing.T) {
	st := openSQLParkOrSkip(t)

	// Clear a never-recorded join: no row, no error.
	if err := st.ClearParked(askhold.Parked{SessionUUID: "ghost"}); err != nil {
		t.Fatalf("clearing an absent join must be a no-op success, got %v", err)
	}

	// Record then clear twice: the second clear is still a no-op success.
	now := time.Date(2026, 6, 16, 7, 0, 0, 0, time.UTC)
	if _, err := askhold.NewParked(st, "sess-idem", rung2AskSQL(), now); err != nil {
		t.Fatalf("park sess-idem: %v", err)
	}
	if err := st.ClearParked(askhold.Parked{SessionUUID: "sess-idem"}); err != nil {
		t.Fatalf("first clear: %v", err)
	}
	if err := st.ClearParked(askhold.Parked{SessionUUID: "sess-idem"}); err != nil {
		t.Fatalf("re-driven clear must be a no-op success, got %v", err)
	}
	if _, ok, err := st.Lookup("sess-idem"); err != nil || ok {
		t.Fatalf("cleared join must be absent: ok=%v err=%v", ok, err)
	}
}

// TestSQL_LookupAbsent pins the absence read against the live engine: a
// never-recorded session is absent (false, nil) — sql.ErrNoRows is the absence
// signal, NOT a fault. Mirrors parkstore_test.go's TestLookup_AbsentAndEmpty
// (live half). DS_PG_DSN-gated: SKIPS in the sandbox.
func TestSQL_LookupAbsent(t *testing.T) {
	st := openSQLParkOrSkip(t)
	if _, ok, err := st.Lookup("nope"); err != nil || ok {
		t.Fatalf("absent lookup: want (_, false, nil), got ok=%v err=%v", ok, err)
	}
}
