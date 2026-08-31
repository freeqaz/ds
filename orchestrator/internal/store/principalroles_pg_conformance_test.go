package store

// principalroles_pg_conformance_test.go — live-Postgres coverage for the
// approver-attribution ROW ROUND-TRIP (doc 16 §8/§9, D45) in a NEW file, so the
// FROZEN principalroles_test.go is never touched.
//
// principalroles_test.go covers the pure predicates (MayApprove / HasRole) and the
// shape projection (AskApproval.AskGrantRow → PolicyLogRow), and exercises the
// append + LiveGrants surface against *Memory only. The approver-attribution
// CLAIM is that an approved ask is "still a PolicyKindAskGrant policy_log row whose
// Actor IS the approver" — additive over the frozen 0002_policy_log.sql shape, NO
// new column. This file proves that claim against the LIVE engine: the row built
// from an AskApproval round-trips through the real append-only policy_log and the
// approver lands in the persisted `actor` column (the audit attribution), with the
// TTL and session-scope surviving the round trip exactly as the in-memory case.
//
// DS_PG_DSN-gated, skip-without-DB (reusing openPostgresOrSkip from
// inventory_test.go, which truncates the shared tables), matching the existing
// deferred-manual-step pattern. The target DB must have migrations 0001..0007
// applied. The CI lane (.github/workflows/pg-conformance.yml) exports DS_PG_DSN so
// these RUN rather than skip; human task 01KTY31QVR confirms the lane on the first
// real push.

import (
	"context"
	"testing"
	"time"
)

// TestPostgres_AskApprovalRowRoundTrip pins the approver-attribution row landing in
// the LIVE append-only policy_log: an AskApproval projects to a PolicyKindAskGrant
// row, appends through the real engine (assigning a monotonic seq), and surfaces in
// the session's live-grant view with the approver as Actor and the TTL/scope
// intact. The in-memory equivalent is principalroles_test.go's
// TestAskApprovalAppendsToPolicyLog; this is the same assertion against Postgres,
// which additionally exercises the 0002 append-only trigger, the actor-non-empty
// CHECK, and the timestamptz TTL round trip the in-memory store does not have.
func TestPostgres_AskApprovalRowRoundTrip(t *testing.T) {
	repo := openPostgresOrSkip(t) // skip-without-DB + truncateAll
	ctx := context.Background()

	now := inventoryClock

	// A session for the grant to be scoped to (policy_log.session_uuid is a soft
	// reference; the grant dies with the session, §4.3).
	_, err := repo.CreateSession(ctx, newSession("sess-ask-pg", "host-a", 1))
	mustNoErr(t, err)

	// An approver principal holding the approver role — the role gate the ask path
	// checks before stamping attribution. The principal id rides the row Actor.
	approver := Principal{ID: "p-approver-pg", IdPSubject: "okta|carol", Org: "acme", Roles: []PrincipalRole{RoleApprover}}
	if !approver.MayApprove() {
		t.Fatalf("approver principal should be authorized to approve")
	}
	_, err = repo.CreatePrincipal(ctx, approver)
	mustNoErr(t, err)

	exp := now.Add(time.Hour)
	approval := AskApproval{
		ApproverPrincipalID: approver.ID,
		SessionUUID:         "sess-ask-pg",
		Rule:                "allow api.github.com",
		ExpiresAt:           OptTime{V: &exp},
	}
	appended, err := repo.AppendPolicy(ctx, approval.AskGrantRow([]byte(`{"rule":"allow api.github.com"}`)))
	mustNoErr(t, err)
	if appended.Seq == 0 {
		t.Fatalf("ask-grant append did not assign a seq on the live engine")
	}
	if appended.Kind != PolicyKindAskGrant {
		t.Fatalf("appended row kind: got %q, want ask_grant", appended.Kind)
	}
	if appended.Actor != approver.ID {
		t.Fatalf("approver attribution lost on append: got %q, want %q", appended.Actor, approver.ID)
	}

	// Before expiry: the grant is live, attributed to the approver.
	live, err := repo.LiveGrants(ctx, "sess-ask-pg", now.Add(time.Minute))
	mustNoErr(t, err)
	if len(live) != 1 {
		t.Fatalf("approved ask should surface as one live grant on the live engine, got %d", len(live))
	}
	if live[0].Actor != approver.ID {
		t.Fatalf("live grant approver attribution: got %q, want %q", live[0].Actor, approver.ID)
	}
	if live[0].Kind != PolicyKindAskGrant {
		t.Fatalf("live grant kind: got %q, want ask_grant", live[0].Kind)
	}
	if live[0].SessionUUID != "sess-ask-pg" {
		t.Fatalf("live grant session-scope lost: got %q, want sess-ask-pg", live[0].SessionUUID)
	}
	if live[0].ExpiresAt == nil || !live[0].ExpiresAt.Equal(exp) {
		t.Fatalf("live grant TTL not round-tripped through timestamptz: got %v, want %v", live[0].ExpiresAt, exp)
	}

	// After expiry: gone from the live view, but retained as an audit row (the
	// append-only policy_log keeps every row, D36 — the 0002 trigger forbids
	// DELETE, so the expired grant is still listable).
	live, err = repo.LiveGrants(ctx, "sess-ask-pg", now.Add(2*time.Hour))
	mustNoErr(t, err)
	if len(live) != 0 {
		t.Fatalf("expired ask-grant still live on the engine: %d", len(live))
	}
	all, err := repo.ListPolicy(ctx, 0, 0)
	mustNoErr(t, err)
	if len(all) != 1 {
		t.Fatalf("approver audit row not retained in append-only policy_log: %d", len(all))
	}
	if all[0].Actor != approver.ID {
		t.Fatalf("retained audit row approver attribution: got %q, want %q", all[0].Actor, approver.ID)
	}
}

// TestPostgres_AskApprovalActorColumn confirms the approver attribution lands in
// the persisted policy_log.actor COLUMN at the raw-SQL level (not just through the
// typed read path), so the "approver rides the existing Actor column, no new
// column" claim is verified against the actual table shape. It reuses the concrete
// *Postgres so it can read the column directly.
func TestPostgres_AskApprovalActorColumn(t *testing.T) {
	pg, db := pgInventory(t) // skip-without-DB + truncateAll; concrete *Postgres + *sql.DB
	ctx := context.Background()

	_, err := pg.CreateSession(ctx, newSession("sess-actor-pg", "host-a", 1))
	mustNoErr(t, err)

	exp := inventoryClock.Add(time.Hour)
	approval := AskApproval{
		ApproverPrincipalID: "p-actor",
		SessionUUID:         "sess-actor-pg",
		Rule:                "allow example.com",
		ExpiresAt:           OptTime{V: &exp},
	}
	appended, err := pg.AppendPolicy(ctx, approval.AskGrantRow([]byte(`{"rule":"allow example.com"}`)))
	mustNoErr(t, err)

	// Read the persisted row back at the SQL level: the approver must be in the
	// `actor` column (the D36 per-row attribution), the kind must be 'ask_grant',
	// and the session-scope + TTL must match — no separate approver column exists.
	var (
		actor   string
		kind    string
		session string
		expires time.Time
	)
	if err := db.QueryRowContext(ctx,
		`SELECT actor, kind, session_uuid, expires_at FROM policy_log WHERE seq = $1`,
		appended.Seq).Scan(&actor, &kind, &session, &expires); err != nil {
		t.Fatalf("read back persisted policy_log row: %v", err)
	}
	if actor != "p-actor" {
		t.Fatalf("persisted policy_log.actor: got %q, want p-actor (approver attribution rides Actor)", actor)
	}
	if kind != string(PolicyKindAskGrant) {
		t.Fatalf("persisted policy_log.kind: got %q, want ask_grant", kind)
	}
	if session != "sess-actor-pg" {
		t.Fatalf("persisted policy_log.session_uuid: got %q, want sess-actor-pg", session)
	}
	if !expires.UTC().Equal(exp) {
		t.Fatalf("persisted policy_log.expires_at: got %v, want %v", expires.UTC(), exp)
	}
}
