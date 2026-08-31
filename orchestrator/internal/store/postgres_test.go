package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// TestMapFKErr_Synthetic23503ToErrInvalid proves — without a live database — that
// the shared mapFKErr helper maps a foreign-key violation (SQLSTATE 23503) to the
// package ErrInvalid sentinel, the SAME sentinel the in-memory orphan guards
// return. This is the driver-free half of the D33 parity claim that the
// PutPlan-INSERT and CreateSession-session-INSERT sites now rely on: the live FK
// raises 23503 (proven in plan_session_fk_pg_conformance_test.go under DS_PG_DSN),
// and that error string is what mapFKErr translates here.
//
// It also pins fall-through: a NON-FK error keeps mapErr's existing translation
// (e.g. 23505 → ErrConflict, an arbitrary driver error stays NOT ErrInvalid), so
// routing the two INSERT sites through mapFKErr is a behavior-preserving SUPERSET
// of mapErr for everything except the orphan-FK case.
func TestMapFKErr_Synthetic23503ToErrInvalid(t *testing.T) {
	// The SQLSTATE-23503 and human FK phrases that surface across stdlib-compatible
	// drivers; isFKViolation (and thus mapFKErr) keys off these driver-agnostic
	// substrings, so a synthetic error carrying any of them must map to ErrInvalid.
	fkCases := []string{
		`pq: insert or update on table "plans" violates foreign key constraint "plans_session_uuid_fkey" (SQLSTATE 23503)`,
		`ERROR: insert or update on table "sessions" violates foreign key constraint "sessions_parent_session_uuid_fkey" (23503)`,
		"violates foreign key constraint",
	}
	for _, msg := range fkCases {
		if got := mapFKErr(errors.New(msg)); !errors.Is(got, ErrInvalid) {
			t.Errorf("mapFKErr(%q) = %v, want ErrInvalid (the orphan-FK sentinel parity)", msg, got)
		}
	}

	// nil in → nil out.
	if got := mapFKErr(nil); got != nil {
		t.Errorf("mapFKErr(nil) = %v, want nil", got)
	}

	// Fall-through (behavior-preserving superset of mapErr): a unique-violation
	// keeps mapErr's ErrConflict, and an unrelated driver error is NOT misclassified
	// as the orphan-FK ErrInvalid.
	if got := mapFKErr(fmt.Errorf("duplicate key value violates unique constraint (SQLSTATE 23505)")); !errors.Is(got, ErrConflict) {
		t.Errorf("mapFKErr(23505) = %v, want ErrConflict (fall-through to mapErr)", got)
	}
	if got := mapFKErr(errors.New("connection reset by peer")); errors.Is(got, ErrInvalid) {
		t.Errorf("mapFKErr(non-FK error) = %v, must NOT be ErrInvalid (no over-mapping)", got)
	}
}

// TestPostgres_Conformance runs the SHARED conformance suite against the
// database/sql implementation. It is a DEFERRED MANUAL STEP, env-gated behind
// DS_PG_DSN and SKIPPED otherwise (it is never run in the sandbox).
//
// Wiring (intentionally driver-agnostic so this package — and orchestrator/go.mod
// — stays stdlib-only, importing NO Postgres driver):
//
//   - DS_PG_DSN       the data-source name passed to sql.Open.
//   - DS_PG_DRIVER    the registered driver name (default "postgres"); the
//     operator running this test imports a driver for its side
//     effect (e.g. _ "github.com/jackc/pgx/v5/stdlib" registered
//     as "pgx", or lib/pq as "postgres") in a small local main_test
//     shim or via a build that adds the dependency OUTSIDE this
//     module. This file adds no such import.
//
// The target database must already have orchestrator/migrations/*.sql applied.
// The suite factory TRUNCATEs the tables before each sub-case so every case
// starts empty, mirroring the in-memory factory's fresh-store contract.
func TestPostgres_Conformance(t *testing.T) {
	// The sql.Open + 5s-ping + skip dance is single-sourced through storetest.OpenOrSkip
	// (its SkipMessages reproduce this test's exact skip wording byte-for-byte): this
	// caller keeps its OWN env var (DS_PG_DSN / DS_PG_DRIVER) and its OWN post-open step
	// — the per-case truncate + NewPostgresClock factory below.
	db := storetest.OpenOrSkip(t, "DS_PG_DSN", "DS_PG_DRIVER", storetest.SkipMessages{
		Unset:   "DS_PG_DSN not set: skipping live-Postgres conformance (deferred manual step)",
		OpenErr: "sql.Open(%q): %v — register a Postgres driver and apply migrations to run this",
		PingErr: "ping %s: %v — Postgres unreachable; deferred manual step",
	})

	RunConformance(t, func(now func() time.Time) Repository {
		truncateAll(t, db)
		return NewPostgresClock(db, now)
	})
}

// truncateAll resets every table the suite touches, so the shared factory hands
// out an empty store on each call (the in-memory parity contract).
func truncateAll(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// RESTART IDENTITY resets the policy_log bigserial so the monotonic-seq
	// assertions start from a known base; CASCADE handles the FK edges
	// (including the 0006 sessions.launching_principal -> principals(id) edge).
	const stmt = `TRUNCATE session_index_epochs, metering_events, plans,
		policy_log, env_configs, sessions, principals RESTART IDENTITY CASCADE`
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}
