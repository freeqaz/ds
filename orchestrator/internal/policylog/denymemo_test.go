// SPDX-License-Identifier: Apache-2.0

package policylog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// denierPrincipal is a principal holding the approver role — the SAME role gate
// that authorizes an allow also authorizes a deny (both are the human's recorded
// ask DECISION, D45).
func denierPrincipal() store.Principal {
	return store.Principal{
		ID: "p-carol", IdPSubject: "okta|carol", Org: "acme",
		Roles: []store.PrincipalRole{store.RoleApprover},
	}
}

// TestDenyAsk_RefusesNonApprover proves the role-gate is symmetric with the allow
// path: a principal that may not approve is refused with ErrNotApprover and NO
// deny-memo row is written — a stray principal records neither an allow nor a deny
// on the policy stream.
func TestDenyAsk_RefusesNonApprover(t *testing.T) {
	f := &appenderFake{}
	_, err := DenyAsk(context.Background(), f, nonApproverPrincipal(),
		"sess-1", "deny evil.com", "domain-blocklisted", store.OptTime{}, []byte("domain-blocklisted"))
	if !errors.Is(err, ErrNotApprover) {
		t.Fatalf("DenyAsk error = %v, want ErrNotApprover", err)
	}
	if len(f.rows) != 0 {
		t.Fatalf("a refused denial must write no row, got %d", len(f.rows))
	}
}

// TestDenyAsk_AttributesDenier proves the attribution step: an authorized denier
// appends EXACTLY ONE PolicyKindDenyMemo row whose Actor IS the denier and whose
// payload carries the D77 machine-readable reason — and it is NOT an allow grant.
func TestDenyAsk_AttributesDenier(t *testing.T) {
	f := &appenderFake{}
	exp := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	row, err := DenyAsk(context.Background(), f, denierPrincipal(),
		"sess-1", "deny evil.com", "domain-blocklisted", *store.SetTime(exp), []byte("domain-blocklisted"))
	if err != nil {
		t.Fatalf("DenyAsk(authorized): %v", err)
	}
	if len(f.rows) != 1 {
		t.Fatalf("an authorized denial must write exactly one row, got %d", len(f.rows))
	}
	if row.Kind != store.PolicyKindDenyMemo {
		t.Errorf("row Kind = %q, want %q", row.Kind, store.PolicyKindDenyMemo)
	}
	if row.Kind == store.PolicyKindAskGrant {
		t.Errorf("a deny memo must never be an allow grant")
	}
	if row.Actor != "p-carol" {
		t.Errorf("row Actor = %q, want the denier principal ID p-carol", row.Actor)
	}
	if row.SessionUUID != "sess-1" {
		t.Errorf("row SessionUUID = %q, want sess-1", row.SessionUUID)
	}
	if string(row.Payload) != "domain-blocklisted" {
		t.Errorf("row payload lost the D77 reason: got %q", string(row.Payload))
	}
	if row.ExpiresAt == nil || !row.ExpiresAt.Equal(exp) {
		t.Errorf("row ExpiresAt = %v, want %v", row.ExpiresAt, exp)
	}
	if row.Seq == 0 {
		t.Error("row Seq = 0, want a store-assigned seq")
	}
}

// denyReaderFake is a synthetic denyMemoReader returning a scripted memo slice,
// so the fast-fail read can be asserted without a live store.
type denyReaderFake struct {
	memos []store.PolicyLogRow
	err   error
}

func (f *denyReaderFake) LiveDenyMemos(_ context.Context, _ string, _ time.Time) ([]store.PolicyLogRow, error) {
	return f.memos, f.err
}

// TestLiveDenyMemo_NoMemoProceeds proves a retry is free to proceed when no live
// memo exists: (zeroRow, false, nil).
func TestLiveDenyMemo_NoMemoProceeds(t *testing.T) {
	row, found, err := LiveDenyMemo(context.Background(), &denyReaderFake{}, "sess-1", time.Now())
	if err != nil {
		t.Fatalf("LiveDenyMemo(no memo): unexpected error %v", err)
	}
	if found {
		t.Errorf("found = true, want false when no live memo")
	}
	if row.Seq != 0 {
		t.Errorf("row = %+v, want zero row when no live memo", row)
	}
}

// TestLiveDenyMemo_FastFailsWithReason proves a retry FAST-FAILS on a live memo:
// found is true, the error wraps ErrDeniedByMemo (branchable via errors.Is) and
// carries the D77 reason, and the latest (highest-seq) memo governs.
func TestLiveDenyMemo_FastFailsWithReason(t *testing.T) {
	f := &denyReaderFake{memos: []store.PolicyLogRow{
		{Seq: 1, Kind: store.PolicyKindDenyMemo, Actor: "p-carol", SessionUUID: "sess-1", Payload: []byte("first-reason")},
		{Seq: 2, Kind: store.PolicyKindDenyMemo, Actor: "p-carol", SessionUUID: "sess-1", Payload: []byte("latest-reason")},
	}}
	row, found, err := LiveDenyMemo(context.Background(), f, "sess-1", time.Now())
	if !found {
		t.Fatalf("found = false, want true when a live memo exists")
	}
	if !errors.Is(err, ErrDeniedByMemo) {
		t.Fatalf("error = %v, want wrapping ErrDeniedByMemo", err)
	}
	if row.Seq != 2 {
		t.Errorf("surfaced memo seq = %d, want the latest (2)", row.Seq)
	}
	if got := err.Error(); !contains(got, "latest-reason") {
		t.Errorf("error %q does not carry the latest D77 reason", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestDenyAsk_WithMemoryStore proves the deny path wires against the REAL store
// seams (AppendPolicy + LiveDenyMemos): an authorized denial lands a retrievable
// deny memo attributed to the denier, a retry fast-fails on it via LiveDenyMemo,
// the memo dies after its TTL (session flush), and it never appears as an allow
// grant. A non-approver's denial writes nothing.
func TestDenyAsk_WithMemoryStore(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)
	repo := store.NewMemoryClock(func() time.Time { return base })

	if _, err := repo.CreatePrincipal(ctx, denierPrincipal()); err != nil {
		t.Fatalf("CreatePrincipal denier: %v", err)
	}
	if _, err := repo.CreatePrincipal(ctx, nonApproverPrincipal()); err != nil {
		t.Fatalf("CreatePrincipal non-approver: %v", err)
	}

	exp := base.Add(time.Hour)
	row, err := DenyAsk(ctx, repo, denierPrincipal(),
		"sess-mem", "deny evil.com", "domain-blocklisted", *store.SetTime(exp), []byte("domain-blocklisted"))
	if err != nil {
		t.Fatalf("DenyAsk(memory): %v", err)
	}
	if row.Kind != store.PolicyKindDenyMemo || row.Actor != "p-carol" {
		t.Fatalf("memory deny result = %+v, want deny_memo attributed to p-carol", row)
	}

	// A retry fast-fails on the live memo with the D77 reason.
	got, found, err := LiveDenyMemo(ctx, repo, "sess-mem", base)
	if !found || !errors.Is(err, ErrDeniedByMemo) {
		t.Fatalf("LiveDenyMemo = (found=%v, err=%v), want found with ErrDeniedByMemo", found, err)
	}
	if got.Actor != "p-carol" {
		t.Fatalf("fast-fail memo Actor = %q, want p-carol", got.Actor)
	}

	// The deny memo must NOT surface as an allow grant.
	grants, err := repo.LiveGrants(ctx, "sess-mem", base)
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("a deny memo must never be an allow grant, got %d", len(grants))
	}

	// After the TTL the memo has died (session flush, D72): a retry may proceed.
	_, found, err = LiveDenyMemo(ctx, repo, "sess-mem", exp.Add(time.Minute))
	if err != nil {
		t.Fatalf("LiveDenyMemo after TTL: %v", err)
	}
	if found {
		t.Fatalf("expired deny memo must not fast-fail a retry")
	}

	// A non-approver's denial writes nothing through the real store.
	if _, err := DenyAsk(ctx, repo, nonApproverPrincipal(),
		"sess-mem", "deny evil.com", "domain-blocklisted", store.OptTime{}, []byte("x")); !errors.Is(err, ErrNotApprover) {
		t.Fatalf("non-approver DenyAsk error = %v, want ErrNotApprover", err)
	}
}
