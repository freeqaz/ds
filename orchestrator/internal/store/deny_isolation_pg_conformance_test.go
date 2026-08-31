// SPDX-License-Identifier: Apache-2.0

package store

// deny_isolation_pg_conformance_test.go — live-Postgres coverage that a deny_memo
// NEVER surfaces as an allow grant (and vice versa) when BOTH ride the same
// session on the single append-only policy_log seq namespace (D36). It is the
// cross-kind ISOLATION twin of the per-kind round-trips (denymemo_test.go's
// TestLiveDenyMemos_Postgres for deny memos, principalroles_pg_conformance_test.go's
// TestPostgres_AskApprovalRowRoundTrip for ask grants): those each append ONE kind
// and read it back; this one appends BOTH to the SAME session and proves the kind
// column isolates the two reads at the SQL level — LiveGrants (parameterized on
// PolicyKindAskGrant) returns ONLY the ask_grant, LiveDenyMemos (parameterized on
// PolicyKindDenyMemo) returns ONLY the deny_memo. A deny can never be mistaken for
// an allow on the production read path against the live engine.
//
// DS_PG_DSN-gated, skip-without-DB: it reuses pgInventory (→ openPostgresOrSkip +
// truncateAll, NewPostgresClock-wired), the same deferred-manual-step pattern the
// other live legs use, so the default `go test ./...` pass is unaffected. The
// target DB must have migrations 0001..0013 applied (0013_policy_log_deny_memo_kind
// widens the policy_log kind CHECK to admit 'deny_memo'); the CI lane
// (.github/workflows/pg-conformance.yml) applies those and exports DS_PG_DSN so this
// RUNS rather than skips. The name starts with TestPostgres so the lane's
// `-run '^(TestPostgres|TestLiveDenyMemos)'` selector picks it up.

import (
	"context"
	"testing"
	"time"
)

// TestPostgres_DenyMemoNeverSurfacesAsAllowGrant appends a deny_memo AND an
// ask_grant for the SAME session against the live engine and proves the two reads
// stay disjoint: the deny memo surfaces ONLY through LiveDenyMemos (attributed to
// the denier), the ask grant surfaces ONLY through LiveGrants (attributed to the
// approver), and neither bleeds into the other's view. This is the live-Postgres
// proof that the kind column — not just the in-memory predicate — isolates allow
// from deny on the shared seq namespace, so a recorded denial can never be read
// back as a grant (a safety-relevant confusion, D118/D36).
func TestPostgres_DenyMemoNeverSurfacesAsAllowGrant(t *testing.T) {
	pg, _ := pgInventory(t) // skip-without-DB + truncateAll; concrete *Postgres
	ctx := context.Background()

	const sessionUUID = "sess-deny-isolation-pg"
	if _, err := pg.CreateSession(ctx, newSession(sessionUUID, "host-a", 1)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	exp := inventoryClock.Add(time.Hour)

	// A deny_memo on this session, attributed to the denier (rides Actor, D36).
	memo := DenyMemo{
		DenierPrincipalID: "p-denier",
		SessionUUID:       sessionUUID,
		Rule:              "deny evil.com",
		Reason:            "domain-blocklisted",
		ExpiresAt:         OptTime{V: &exp},
	}
	denyRow, err := pg.AppendPolicy(ctx, memo.DenyMemoRow([]byte("domain-blocklisted")))
	if err != nil {
		t.Fatalf("AppendPolicy deny_memo: %v — is 0013_policy_log_deny_memo_kind.sql applied (widens the policy_log kind CHECK to admit 'deny_memo')?", err)
	}
	if denyRow.Kind != PolicyKindDenyMemo {
		t.Fatalf("appended deny row kind: got %q, want deny_memo", denyRow.Kind)
	}

	// An ask_grant on the SAME session, attributed to the approver.
	approval := AskApproval{
		ApproverPrincipalID: "p-approver",
		SessionUUID:         sessionUUID,
		Rule:                "allow api.github.com",
		ExpiresAt:           OptTime{V: &exp},
	}
	grantRow, err := pg.AppendPolicy(ctx, approval.AskGrantRow([]byte(`{"rule":"allow api.github.com"}`)))
	if err != nil {
		t.Fatalf("AppendPolicy ask_grant: %v", err)
	}
	if grantRow.Kind != PolicyKindAskGrant {
		t.Fatalf("appended grant row kind: got %q, want ask_grant", grantRow.Kind)
	}
	// Two distinct rows on the single seq namespace (D36) — sanity that both landed.
	if denyRow.Seq == 0 || grantRow.Seq == 0 || denyRow.Seq == grantRow.Seq {
		t.Fatalf("expected two distinct seqs on the single namespace, got deny=%d grant=%d", denyRow.Seq, grantRow.Seq)
	}

	// LiveGrants must return ONLY the ask_grant — the deny_memo must NOT leak in.
	grants, err := pg.LiveGrants(ctx, sessionUUID, inventoryClock)
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("LiveGrants must return exactly the one ask_grant (the deny_memo must not surface as an allow), got %d: %+v", len(grants), grants)
	}
	if grants[0].Kind != PolicyKindAskGrant {
		t.Fatalf("LiveGrants returned a non-ask_grant row: kind=%q — a deny_memo leaked onto the allow path", grants[0].Kind)
	}
	if grants[0].Actor != "p-approver" {
		t.Fatalf("LiveGrants approver attribution: got %q, want p-approver", grants[0].Actor)
	}
	if grants[0].Seq != grantRow.Seq {
		t.Fatalf("LiveGrants surfaced seq %d, want the ask_grant seq %d", grants[0].Seq, grantRow.Seq)
	}

	// LiveDenyMemos must return ONLY the deny_memo — the ask_grant must NOT leak in.
	memos, err := pg.LiveDenyMemos(ctx, sessionUUID, inventoryClock)
	if err != nil {
		t.Fatalf("LiveDenyMemos: %v", err)
	}
	if len(memos) != 1 {
		t.Fatalf("LiveDenyMemos must return exactly the one deny_memo (the ask_grant must not surface as a deny), got %d: %+v", len(memos), memos)
	}
	if memos[0].Kind != PolicyKindDenyMemo {
		t.Fatalf("LiveDenyMemos returned a non-deny_memo row: kind=%q — an ask_grant leaked onto the deny path", memos[0].Kind)
	}
	if memos[0].Actor != "p-denier" {
		t.Fatalf("LiveDenyMemos denier attribution: got %q, want p-denier", memos[0].Actor)
	}
	if memos[0].Seq != denyRow.Seq {
		t.Fatalf("LiveDenyMemos surfaced seq %d, want the deny_memo seq %d", memos[0].Seq, denyRow.Seq)
	}
}

// TestPostgres_ExpiredDenyMemoNotLiveWhileGrantStays pins the live-Postgres
// deny_memo TTL/sweep predicate against the real engine: an ALREADY-EXPIRED
// deny_memo (ExpiresAt in the past relative to now) must be absent from
// (*Postgres).LiveDenyMemos, while a still-live ask_grant on the SAME session
// remains surfaced by (*Postgres).LiveGrants. It is the live twin of the
// after-TTL leg in TestLiveDenyMemos_Memory (denymemo_test.go), which the existing
// live deny-memo legs do NOT cover — TestLiveDenyMemos_Postgres reads a live memo
// and the isolation twin above uses only future-dated rows, so neither exercises
// the "expires_at > now" bound on the real SQL. LiveGrants/LiveDenyMemos share the
// sqlLiveGrants predicate "expires_at IS NULL OR expires_at > $3" (parameterized on
// the kind), so this proves the expiry filter fires on Postgres for the deny path
// while leaving a co-session live grant untouched.
//
// DS_PG_DSN-gated, skip-without-DB via pgInventory (→ openPostgresOrSkip +
// truncateAll); TestPostgres-prefixed so the lane's
// `-run '^(TestPostgres|TestLiveDenyMemos)'` selector picks it up. Target DB needs
// migrations 0001..0013 applied (0013 widens the policy_log kind CHECK).
func TestPostgres_ExpiredDenyMemoNotLiveWhileGrantStays(t *testing.T) {
	pg, _ := pgInventory(t) // skip-without-DB + truncateAll; concrete *Postgres
	ctx := context.Background()

	const sessionUUID = "sess-deny-ttl-pg"
	if _, err := pg.CreateSession(ctx, newSession(sessionUUID, "host-a", 1)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// An ALREADY-EXPIRED deny_memo: ExpiresAt one hour BEFORE the read clock, so the
	// "expires_at > now" bound must exclude it at now=inventoryClock.
	past := inventoryClock.Add(-time.Hour)
	memo := DenyMemo{
		DenierPrincipalID: "p-denier",
		SessionUUID:       sessionUUID,
		Rule:              "deny evil.com",
		Reason:            "domain-blocklisted",
		ExpiresAt:         OptTime{V: &past},
	}
	if _, err := pg.AppendPolicy(ctx, memo.DenyMemoRow([]byte("domain-blocklisted"))); err != nil {
		t.Fatalf("AppendPolicy deny_memo: %v — is 0013_policy_log_deny_memo_kind.sql applied (widens the policy_log kind CHECK to admit 'deny_memo')?", err)
	}

	// A still-LIVE ask_grant on the SAME session: ExpiresAt one hour AFTER the read
	// clock, so it must survive the same bound.
	future := inventoryClock.Add(time.Hour)
	approval := AskApproval{
		ApproverPrincipalID: "p-approver",
		SessionUUID:         sessionUUID,
		Rule:                "allow api.github.com",
		ExpiresAt:           OptTime{V: &future},
	}
	grantRow, err := pg.AppendPolicy(ctx, approval.AskGrantRow([]byte(`{"rule":"allow api.github.com"}`)))
	if err != nil {
		t.Fatalf("AppendPolicy ask_grant: %v", err)
	}
	if grantRow.Kind != PolicyKindAskGrant {
		t.Fatalf("appended grant row kind: got %q, want ask_grant", grantRow.Kind)
	}

	// The expired deny_memo must NOT surface at now=inventoryClock — the TTL bound
	// swept it, even though the row is still physically in the append-only log.
	memos, err := pg.LiveDenyMemos(ctx, sessionUUID, inventoryClock)
	if err != nil {
		t.Fatalf("LiveDenyMemos: %v", err)
	}
	if len(memos) != 0 {
		t.Fatalf("an already-expired deny_memo must not surface as live, got %d: %+v", len(memos), memos)
	}

	// The live ask_grant on the SAME session must STILL surface — the expiry filter
	// removed only the past-dated deny_memo, not the future-dated grant.
	grants, err := pg.LiveGrants(ctx, sessionUUID, inventoryClock)
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("the still-live ask_grant must surface (only the expired deny_memo is swept), got %d: %+v", len(grants), grants)
	}
	if grants[0].Kind != PolicyKindAskGrant {
		t.Fatalf("LiveGrants returned a non-ask_grant row: kind=%q", grants[0].Kind)
	}
	if grants[0].Actor != "p-approver" {
		t.Fatalf("LiveGrants approver attribution: got %q, want p-approver", grants[0].Actor)
	}
	if grants[0].Seq != grantRow.Seq {
		t.Fatalf("LiveGrants surfaced seq %d, want the ask_grant seq %d", grants[0].Seq, grantRow.Seq)
	}
}
