package store

import (
	"context"
	"testing"
	"time"
)

// TestPrincipalMayApprove pins the doc 16 §8 approver-authorization role gate:
// launcher (the default approver), approver, and org-admin may approve; viewer
// and repo-admin alone may not.
func TestPrincipalMayApprove(t *testing.T) {
	cases := []struct {
		roles []PrincipalRole
		want  bool
	}{
		{[]PrincipalRole{RoleLauncher}, true},               // default approver = launching user
		{[]PrincipalRole{RoleApprover}, true},               // the dedicated approval role
		{[]PrincipalRole{RoleOrgAdmin}, true},               // D45 allow-always acceptance
		{[]PrincipalRole{RoleViewer}, false},                // read-only spectate, never approves
		{[]PrincipalRole{RoleRepoAdmin}, false},             // repo admin alone does not approve
		{nil, false},                                        // no roles → no approval
		{[]PrincipalRole{RoleViewer, RoleApprover}, true},   // any qualifying role in the set
		{[]PrincipalRole{RoleViewer, RoleRepoAdmin}, false}, // neither qualifies
	}
	for _, tc := range cases {
		p := Principal{Roles: tc.roles}
		if got := p.MayApprove(); got != tc.want {
			t.Fatalf("MayApprove(%v) = %v, want %v", tc.roles, got, tc.want)
		}
	}
}

// TestPrincipalHasRole pins the role-membership predicate.
func TestPrincipalHasRole(t *testing.T) {
	p := Principal{Roles: []PrincipalRole{RoleLauncher, RoleApprover}}
	if !p.HasRole(RoleLauncher) || !p.HasRole(RoleApprover) {
		t.Fatalf("HasRole missed a held role: %+v", p.Roles)
	}
	if p.HasRole(RoleOrgAdmin) || p.HasRole(RoleViewer) {
		t.Fatalf("HasRole reported an unheld role: %+v", p.Roles)
	}
}

// TestAskApprovalRowShape pins the approver-attribution mapping: an approved ask
// projects to a PolicyKindAskGrant policy_log row whose Actor IS the approver
// principal — additive over the existing ask-grant shape (records.go), no new
// column. The TTL and session-scope ride the existing row fields.
func TestAskApprovalRowShape(t *testing.T) {
	exp := time.Date(2026, 6, 12, 13, 0, 0, 0, time.UTC)
	approval := AskApproval{
		ApproverPrincipalID: "p-approver",
		SessionUUID:         "sess-1",
		Rule:                "allow github.com",
		ExpiresAt:           OptTime{V: &exp},
		Consent:             ConsentClassUnspecified,
	}
	row := approval.AskGrantRow([]byte(`{"rule":"allow github.com"}`))

	if row.Kind != PolicyKindAskGrant {
		t.Fatalf("approved ask must be a PolicyKindAskGrant row, got %q", row.Kind)
	}
	if row.Actor != "p-approver" {
		t.Fatalf("approver attribution must ride Actor, got %q", row.Actor)
	}
	if row.SessionUUID != "sess-1" {
		t.Fatalf("grant must be session-scoped, got %q", row.SessionUUID)
	}
	if row.ExpiresAt == nil || !row.ExpiresAt.Equal(exp) {
		t.Fatalf("grant TTL not carried: %v", row.ExpiresAt)
	}
	// The projection must COPY the TTL, never alias the AskApproval's pointer.
	exp2 := exp.Add(time.Hour)
	*approval.ExpiresAt.V = exp2
	if row.ExpiresAt.Equal(exp2) {
		t.Fatalf("AskGrantRow aliased the caller's ExpiresAt pointer")
	}
}

// TestAskApprovalAppendsToPolicyLog confirms the approver-attribution shape lands
// in the actual policy_log via the existing AppendPolicy verb (the additive,
// shape-only claim made concrete): the approver row appends, gets a seq, and
// surfaces in the session's live-grant view with the approver as Actor — exactly
// the way the existing AskGrantTTL conformance case reads an ask-grant, now built
// through the AskApproval shape.
func TestAskApprovalAppendsToPolicyLog(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryClock(fixedClock(inventoryClock))

	_, err := repo.CreateSession(ctx, newSession("sess-ask", "host-a", 1))
	mustNoErr(t, err)

	// An approver principal holding the approver role (the role gate the ask path
	// checks before stamping attribution).
	approver := Principal{ID: "p-approver", IdPSubject: "okta|carol", Org: "acme", Roles: []PrincipalRole{RoleApprover}}
	if !approver.MayApprove() {
		t.Fatalf("approver principal should be authorized to approve")
	}
	_, err = repo.CreatePrincipal(ctx, approver)
	mustNoErr(t, err)

	exp := inventoryClock.Add(time.Hour)
	approval := AskApproval{
		ApproverPrincipalID: approver.ID,
		SessionUUID:         "sess-ask",
		Rule:                "allow api.github.com",
		ExpiresAt:           OptTime{V: &exp},
	}
	appended, err := repo.AppendPolicy(ctx, approval.AskGrantRow([]byte(`{"rule":"allow api.github.com"}`)))
	mustNoErr(t, err)
	if appended.Seq == 0 {
		t.Fatalf("ask-grant append did not assign a seq")
	}

	live, err := repo.LiveGrants(ctx, "sess-ask", inventoryClock)
	mustNoErr(t, err)
	if len(live) != 1 {
		t.Fatalf("approved ask should surface as one live grant, got %d", len(live))
	}
	if live[0].Actor != "p-approver" {
		t.Fatalf("live grant approver attribution: got %q, want p-approver", live[0].Actor)
	}
	if live[0].Kind != PolicyKindAskGrant {
		t.Fatalf("live grant kind: got %q, want ask_grant", live[0].Kind)
	}
}
