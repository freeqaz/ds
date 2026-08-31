// SPDX-License-Identifier: Apache-2.0
package store

// plan_session_fk_pg_conformance_test.go — live-Postgres proof for the §5.6
// Repository FK edges this unit mirrors in-memory, in a NEW file so the existing
// (effectively frozen) conformance_test.go / postgres_test.go are never touched.
//
// The shared Repository suite (testRepositoryOrphanFKWrites) proves BOTH impls
// REJECT an orphan write and ADMIT the legal (empty/nullable, real-referent)
// cases. This file proves the LIVE engine half independently: the real
// REFERENCES sessions(session_uuid) FKs actually fire on the orphan write —
//
//   - plans.session_uuid REFERENCES sessions (0004_plans.sql, NULLABLE)
//   - sessions.parent_session_uuid REFERENCES sessions (0001_sessions.sql,
//     NULLABLE self-ref)
//
// — so the in-memory guards added in memory.go are mirroring a real constraint,
// not an imagined one.
//
// PG-SIDE MAPPING NOW LANDED (commit 2978abdf): Postgres.PutPlan and
// Postgres.CreateSession route their 23503 through the shared mapFKErr
// (postgres.go:157, :386), so a live orphan write surfaces the SAME ErrInvalid
// sentinel the in-memory guards return — sentinel parity is now exact on the live
// engine, not merely "once the follow-up lands". This file therefore asserts the
// orphan write maps to ErrInvalid DIRECTLY (not just err != nil) and the legal
// cases SUCCEED. The deliberately-SOFT refs (metering_events / policy_log
// session_uuid, no REFERENCES) are proven legal here too, pinning the
// don't-over-constrain posture against the live schema.
//
// COUPLING GUARD (option-(b), TestSinglePlanSessionFK below): mapFKErr maps ANY
// 23503 on a PutPlan / CreateSession write to ErrInvalid, which is exact ONLY while
// plans and sessions each carry EXACTLY ONE foreign key (the session_uuid /
// parent_session_uuid attribution edge). A SECOND FK on either table would let an
// unrelated integrity failure masquerade as the attribution orphan; the guard
// reads the migration DDL and FAILS LOUDLY the day that lands, forcing mapFKErr
// (or its CreateSession/PutPlan call sites) to be re-pinned to the constraint NAME
// in lockstep before the new FK ships. (Its sibling, TestSingleFKPerContextTable
// in sessioncontext_test.go, pins the same invariant for the prompts /
// session_context tables that mapContextErr covers.)
//
// LIVE CONFORMANCE IS AN OPERATOR-RUN STEP. The Test*Postgres* cases here are
// DS_PG_DSN-gated and SKIP-by-default (via openPostgresOrSkip / pgInventory from
// inventory_test.go, which truncate the shared tables), matching the existing
// deferred-manual-step pattern — they NEVER touch a live engine in the normal
// `go test ./...` gate. To run the live half, an operator applies migrations
// 0001..0008 to a scratch DB and exports DS_PG_DSN (e.g.
// `DS_PG_DSN=postgres://… DS_PG_DRIVER=pgx go test ./internal/store -run Postgres`);
// the CI lane (.github/workflows/pg-conformance.yml) exports DS_PG_DSN so these RUN
// rather than skip. The single-FK guard (TestSinglePlanSessionFK) is DDL-only and
// runs in every gate.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestPostgres_PlanSessionFKRejectsOrphan proves the live plans.session_uuid FK
// (0004) rejects an orphan PutPlan — mapping it to ErrInvalid via mapFKErr — and
// admits the nullable-empty + real-session cases. The live half of the
// testRepositoryOrphanFKWrites plan edge, asserting sentinel parity directly.
func TestPostgres_PlanSessionFKRejectsOrphan(t *testing.T) {
	repo := openPostgresOrSkip(t) // skip-without-DB + truncateAll
	ctx := context.Background()

	// A real session for the legal control case.
	_, err := repo.CreateSession(ctx, newSession("sess-plan-fk", "host-a", 1))
	mustNoErr(t, err)

	// Orphan: a non-empty session_uuid naming no session row. The live FK fires and
	// PutPlan routes the 23503 through mapFKErr → ErrInvalid (sentinel parity with
	// the in-memory guard, since 2978abdf).
	if _, err := repo.PutPlan(ctx, Plan{ID: "plan-orphan-pg", SessionUUID: "ghost-session"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("live plans.session_uuid FK orphan PutPlan: got %v, want ErrInvalid (mapFKErr 23503→ErrInvalid, postgres.go:386, landed 2978abdf)", err)
	}
	// The rejected write left no row behind.
	if _, err := repo.GetPlan(ctx, "plan-orphan-pg"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected orphan plan persisted on the live engine: got %v, want ErrNotFound", err)
	}

	// Legal: an EMPTY session_uuid (nullable, unscoped plan) is accepted by the FK.
	if _, err := repo.PutPlan(ctx, Plan{ID: "plan-unscoped-pg"}); err != nil {
		t.Fatalf("live FK rejected an unscoped (empty session_uuid) plan; nullable column must admit it: %v", err)
	}
	// Legal: a real session_uuid is accepted.
	if _, err := repo.PutPlan(ctx, Plan{ID: "plan-real-pg", SessionUUID: "sess-plan-fk"}); err != nil {
		t.Fatalf("live FK rejected a plan attributed to a real session: %v", err)
	}
}

// TestPostgres_ParentSessionFKRejectsOrphan proves the live
// sessions.parent_session_uuid self-ref FK (0001) rejects an orphan parent link —
// mapping it to ErrInvalid via mapFKErr — and admits the nullable-empty (root) +
// real-parent cases. The live half of the testRepositoryOrphanFKWrites parent
// edge, asserting sentinel parity directly.
func TestPostgres_ParentSessionFKRejectsOrphan(t *testing.T) {
	repo := openPostgresOrSkip(t)
	ctx := context.Background()

	// Orphan: a non-empty parent naming no session row. The live self-ref FK fires
	// and CreateSession routes the 23503 through mapFKErr → ErrInvalid (postgres.go:157).
	orphanParent := newSession("sess-orphan-parent-pg", "host-a", 1)
	orphanParent.ParentSessionUUID = "ghost-session"
	if _, err := repo.CreateSession(ctx, orphanParent); !errors.Is(err, ErrInvalid) {
		t.Fatalf("live sessions.parent_session_uuid FK orphan link: got %v, want ErrInvalid (mapFKErr 23503→ErrInvalid, postgres.go:157, landed 2978abdf)", err)
	}
	if _, err := repo.GetSession(ctx, "sess-orphan-parent-pg"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected orphan-parent session persisted on the live engine: got %v, want ErrNotFound", err)
	}

	// Legal: a root session (EMPTY parent) is accepted.
	if _, err := repo.CreateSession(ctx, newSession("sess-root-pg", "host-a", 2)); err != nil {
		t.Fatalf("live FK rejected a root session (empty parent); nullable self-ref must admit it: %v", err)
	}
	// Legal: a real parent is accepted.
	child := newSession("sess-child-pg", "host-a", 3)
	child.ParentSessionUUID = "sess-root-pg"
	if _, err := repo.CreateSession(ctx, child); err != nil {
		t.Fatalf("live FK rejected a child with a real parent: %v", err)
	}
}

// TestPostgres_SoftSessionRefsAdmitOrphan pins the DON'T-OVER-CONSTRAIN posture
// against the live schema: metering_events.session_uuid (0005) and
// policy_log.session_uuid (0002) carry NO REFERENCES clause — deliberately soft,
// attribution-only text columns — so the live engine ADMITS a write whose
// session_uuid names no session row. The in-memory impl must NOT add a guard here
// (and does not), keeping parity with the live soft refs.
func TestPostgres_SoftSessionRefsAdmitOrphan(t *testing.T) {
	repo := openPostgresOrSkip(t)
	ctx := context.Background()

	// metering_events: a session_uuid with no sessions row is legal (soft ref).
	if err := repo.AppendMeteringEvent(ctx, MeteringEvent{
		EventID: "evt-soft-pg", SessionUUID: "no-such-session", Kind: "sample",
	}); err != nil {
		t.Fatalf("live metering_events rejected a soft (no-FK) session_uuid; column must admit it: %v", err)
	}

	// policy_log: an append carrying a session_uuid with no sessions row is legal.
	if _, err := repo.AppendPolicy(ctx, PolicyLogRow{
		Actor: "org-admin", SessionUUID: "no-such-session", ContentHash: "h",
	}); err != nil {
		t.Fatalf("live policy_log rejected a soft (no-FK) session_uuid; column must admit it: %v", err)
	}
}

// --- mapFKErr plan/session coupling guard (DDL-only, runs in every gate) ---

// TestSinglePlanSessionFK pins the invariant mapFKErr's any-23503→ErrInvalid
// mapping depends on for the PutPlan / CreateSession call sites (postgres.go:386,
// :157, landed 2978abdf): the plans and sessions tables each carry EXACTLY ONE
// foreign key — plans.session_uuid REFERENCES sessions (0004) and
// sessions.parent_session_uuid REFERENCES sessions (0001) — so a foreign-key
// violation on either write is UNAMBIGUOUSLY the attribution-orphan FK and mapping
// it to ErrInvalid is exact.
//
// This is the option-(b) guard for the plan/session FK edges (the sibling of
// TestSingleFKPerContextTable in sessioncontext_test.go, which pins the same
// invariant for the prompts / session_context tables mapContextErr covers): rather
// than re-pinning detection to the (auto-generated) constraint NAME today, it
// asserts the single-FK-per-table invariant and FAILS LOUDLY the day a SECOND FK
// is introduced on either table — the moment mapFKErr would start silently
// misclassifying a DIFFERENT integrity failure (a host binding, a policy ref) as
// the attribution ErrInvalid. That failure forces the detection to be re-pinned to
// the constraint name in lockstep before the new FK ships. It is stdlib-only and
// driver-agnostic (it reads the migration DDL, not a live engine), so it runs in
// the sandbox like any unit test — independent of the DS_PG_DSN-gated cases above.
//
// It reuses createTableBody (sessioncontext_test.go), the same dependency-free
// brace-matcher the context-table guard uses.
func TestSinglePlanSessionFK(t *testing.T) {
	for _, c := range []struct {
		migration string
		table     string
	}{
		{"../../migrations/0004_plans.sql", "plans"},
		{"../../migrations/0001_sessions.sql", "sessions"},
	} {
		src, err := os.ReadFile(c.migration)
		if err != nil {
			t.Fatalf("read %s: %v", c.migration, err)
		}
		body, ok := createTableBody(string(src), c.table)
		if !ok {
			t.Fatalf("no CREATE TABLE %s block found in %s", c.table, c.migration)
		}
		// Count REFERENCES (the inline-FK syntax these migrations use) plus any
		// explicit FOREIGN KEY clause, so the guard catches BOTH spellings of a
		// future second FK.
		n := strings.Count(body, "REFERENCES") + strings.Count(body, "FOREIGN KEY")
		if n != 1 {
			t.Fatalf("table %s declares %d foreign keys, want exactly 1: mapFKErr maps ANY 23503 on this "+
				"table to the attribution ErrInvalid (postgres.go PutPlan/CreateSession), which is only correct "+
				"while the lone FK is the session_uuid / parent_session_uuid attribution edge. A second FK "+
				"landed — re-pin mapFKErr's call site to the constraint NAME before shipping it, or this "+
				"orphan-attribution sentinel will mask the new FK's violation.\nblock:\n%s", c.table, n, body)
		}
	}
}
