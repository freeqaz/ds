package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestMemory_Conformance runs the shared repository conformance suite against
// the in-memory implementation. This is the always-on pin: the in-memory impl
// must pass the same suite the Postgres impl runs behind DS_PG_DSN (D33).
func TestMemory_Conformance(t *testing.T) {
	RunConformance(t, func(now func() time.Time) Repository {
		return NewMemoryClock(now)
	})
}

// TestMemory_OrphanFKWritesReturnErrInvalid pins the EXACT in-memory sentinel for
// the two FK edges this unit closes — the half the shared conformance case
// (testRepositoryOrphanFKWrites) cannot assert because the live Postgres impl
// still routes its 23503 through mapErr (a raw error) rather than mapFKErr. The
// in-memory mirror of plans.session_uuid (0004) and sessions.parent_session_uuid
// (0001) returns ErrInvalid — the same sentinel mapFKErr produces — so once the
// pg side adopts mapFKErr the two are byte-for-byte indistinguishable. It also
// re-asserts that the NULLABLE columns admit an EMPTY value (the orphan is a
// NON-EMPTY missing referent only).
func TestMemory_OrphanFKWritesReturnErrInvalid(t *testing.T) {
	repo := NewMemoryClock(fixedClock(baseTime))
	ctx := context.Background()

	// plans.session_uuid: a non-empty missing referent is ErrInvalid; empty is legal.
	if _, err := repo.PutPlan(ctx, Plan{ID: "p-orphan", SessionUUID: "ghost"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("orphan PutPlan in-memory sentinel: got %v, want ErrInvalid", err)
	}
	if _, err := repo.PutPlan(ctx, Plan{ID: "p-unscoped"}); err != nil {
		t.Fatalf("unscoped plan (empty session_uuid) must be legal: got %v", err)
	}

	// sessions.parent_session_uuid: a non-empty missing parent is ErrInvalid; empty is legal.
	orphan := newSession("s-orphan", "host-a", 1)
	orphan.ParentSessionUUID = "ghost"
	if _, err := repo.CreateSession(ctx, orphan); !errors.Is(err, ErrInvalid) {
		t.Fatalf("orphan parent_session_uuid in-memory sentinel: got %v, want ErrInvalid", err)
	}
	if _, err := repo.CreateSession(ctx, newSession("s-root", "host-a", 2)); err != nil {
		t.Fatalf("root session (empty parent) must be legal: got %v", err)
	}
}
