// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// TestDenyMemoRowShape pins the D118 denier-attribution mapping (doc 16 §8.2):
// a denial projects to a PolicyKindDenyMemo policy_log row whose Actor IS the
// denier principal — SYMMETRIC with AskApproval.AskGrantRow and additive over
// the existing policy_log shape (records.go), no new column. The D77
// machine-readable reason rides the payload, and the TTL + session-scope ride the
// existing row fields. The TTL must be COPIED, never aliased.
func TestDenyMemoRowShape(t *testing.T) {
	exp := time.Date(2026, 6, 12, 13, 0, 0, 0, time.UTC)
	memo := DenyMemo{
		DenierPrincipalID: "p-denier",
		SessionUUID:       "sess-1",
		Rule:              "deny evil.com",
		Reason:            "domain-blocklisted",
		ExpiresAt:         OptTime{V: &exp},
	}
	row := memo.DenyMemoRow([]byte(`{"rule":"deny evil.com","reason":"domain-blocklisted"}`))

	if row.Kind != PolicyKindDenyMemo {
		t.Fatalf("a denial must be a PolicyKindDenyMemo row, got %q", row.Kind)
	}
	if row.Kind == PolicyKindAskGrant {
		t.Fatalf("a deny memo must never be an ask_grant (no allow on the policy stream)")
	}
	if row.Actor != "p-denier" {
		t.Fatalf("denier attribution must ride Actor (D36), got %q", row.Actor)
	}
	if row.SessionUUID != "sess-1" {
		t.Fatalf("deny memo must be session-scoped, got %q", row.SessionUUID)
	}
	if string(row.Payload) == "" {
		t.Fatalf("the D77 machine-readable reason must ride the payload")
	}
	if row.ExpiresAt == nil || !row.ExpiresAt.Equal(exp) {
		t.Fatalf("memo TTL not carried: %v", row.ExpiresAt)
	}
	// The projection must COPY the TTL, never alias the DenyMemo's pointer.
	exp2 := exp.Add(time.Hour)
	*memo.ExpiresAt.V = exp2
	if row.ExpiresAt.Equal(exp2) {
		t.Fatalf("DenyMemoRow aliased the caller's ExpiresAt pointer")
	}
}

// TestLiveDenyMemos_Memory proves the deny memo lands in the actual policy_log
// via the existing AppendPolicy verb and surfaces through LiveDenyMemos before
// its TTL and NOT after — symmetric with the ask-grant LiveGrants read. The same
// row must NOT surface as an allow grant (LiveGrants), proving deny memos and
// allow grants are disjoint kinds on the single seq namespace.
func TestLiveDenyMemos_Memory(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryClock(fixedClock(inventoryClock))

	if _, err := repo.CreateSession(ctx, newSession("sess-deny", "host-a", 1)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	exp := inventoryClock.Add(time.Hour)
	memo := DenyMemo{
		DenierPrincipalID: "p-denier",
		SessionUUID:       "sess-deny",
		Rule:              "deny evil.com",
		Reason:            "domain-blocklisted",
		ExpiresAt:         OptTime{V: &exp},
	}
	appended, err := repo.AppendPolicy(ctx, memo.DenyMemoRow([]byte("domain-blocklisted")))
	if err != nil {
		t.Fatalf("AppendPolicy deny memo: %v", err)
	}
	if appended.Seq == 0 {
		t.Fatalf("deny-memo append did not assign a seq (single namespace, D36)")
	}
	if appended.Kind != PolicyKindDenyMemo {
		t.Fatalf("appended kind = %q, want deny_memo", appended.Kind)
	}

	// Before the TTL: the memo is live and surfaces with the denier in Actor.
	live, err := repo.LiveDenyMemos(ctx, "sess-deny", inventoryClock)
	if err != nil {
		t.Fatalf("LiveDenyMemos before TTL: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("deny memo should surface as one live memo before TTL, got %d", len(live))
	}
	if live[0].Actor != "p-denier" {
		t.Fatalf("live memo denier attribution: got %q, want p-denier", live[0].Actor)
	}
	if string(live[0].Payload) != "domain-blocklisted" {
		t.Fatalf("live memo lost the D77 reason: got %q", string(live[0].Payload))
	}

	// The deny memo must NOT surface as an ALLOW grant — disjoint kinds.
	grants, err := repo.LiveGrants(ctx, "sess-deny", inventoryClock)
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("a deny memo must never appear as an allow grant, got %d grants", len(grants))
	}

	// After the TTL: the memo has died with the session window (D72 sweep / flush).
	after, err := repo.LiveDenyMemos(ctx, "sess-deny", exp.Add(time.Minute))
	if err != nil {
		t.Fatalf("LiveDenyMemos after TTL: %v", err)
	}
	if len(after) != 0 {
		t.Fatalf("an expired deny memo must not surface, got %d", len(after))
	}
}

// TestLiveDenyMemos_Postgres is the live-Postgres leg: it proves
// (*Postgres).LiveDenyMemos reads the deny-memo rows the existing sqlLiveGrants
// query returns when parameterized on PolicyKindDenyMemo — no new SQL. It is a
// deferred manual step: it skips clean unless DS_PG_DSN points at a reachable
// database with orchestrator/migrations/*.sql applied (0001..0013).
//
// The deny_memo INSERT below is now ACCEPTED on Postgres: 0013_policy_log_deny_memo_kind.sql
// widens the 0002 policy_log kind CHECK from ('append','ask_grant') to additionally
// admit 'deny_memo' (additive, D36 — a strict superset that rewrites no existing
// row). With that migration applied this leg runs green under DS_PG_DSN; with
// DS_PG_DSN unset it still skips clean, so the default `go test ./...` pass is
// unaffected.
func TestLiveDenyMemos_Postgres(t *testing.T) {
	// The open/ping/skip dance is single-sourced through storetest.OpenOrSkip (its
	// SkipMessages reproduce this test's exact skip wording byte-for-byte); the
	// NewPostgresClock wrap is this caller's own post-open step.
	db := storetest.OpenOrSkip(t, "DS_PG_DSN", "DS_PG_DRIVER", storetest.SkipMessages{
		Unset:   "DS_PG_DSN not set: skipping live-Postgres deny-memo read (deferred manual step)",
		OpenErr: "sql.Open(%q): %v — register a Postgres driver and apply migrations to run this",
		PingErr: "ping %s: %v — Postgres unreachable; deferred manual step",
	})

	ctx := context.Background()
	repo := NewPostgresClock(db, fixedClock(inventoryClock))
	exp := inventoryClock.Add(time.Hour)
	memo := DenyMemo{
		DenierPrincipalID: "p-denier",
		SessionUUID:       "sess-pg-deny",
		Rule:              "deny evil.com",
		Reason:            "domain-blocklisted",
		ExpiresAt:         OptTime{V: &exp},
	}
	if _, err := repo.AppendPolicy(ctx, memo.DenyMemoRow([]byte("domain-blocklisted"))); err != nil {
		t.Fatalf("AppendPolicy (Postgres) deny memo: %v — is 0013_policy_log_deny_memo_kind.sql applied (widens the policy_log kind CHECK to admit 'deny_memo')?", err)
	}
	live, err := repo.LiveDenyMemos(ctx, "sess-pg-deny", inventoryClock)
	if err != nil {
		t.Fatalf("LiveDenyMemos (Postgres): %v", err)
	}
	if len(live) != 1 || live[0].Actor != "p-denier" || live[0].Kind != PolicyKindDenyMemo {
		t.Fatalf("Postgres LiveDenyMemos = %+v, want one deny_memo attributed to p-denier", live)
	}
}
