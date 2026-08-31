package policylog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// appenderFake is a synthetic policyAppender that records the rows it is asked
// to append (and can be scripted to fail), so the ask-approval caller's gate and
// attribution can be asserted without a live store. The store's own append
// semantics (seq assignment, empty-actor refusal) are covered by its conformance
// suite; this exercises only that the CALLER gates on MayApprove and attributes
// the approver.
type appenderFake struct {
	rows []store.PolicyLogRow
	err  error
}

func (f *appenderFake) AppendPolicy(_ context.Context, row store.PolicyLogRow) (store.PolicyLogRow, error) {
	if f.err != nil {
		return store.PolicyLogRow{}, f.err
	}
	row.Seq = int64(len(f.rows) + 1) // mimic the store's monotonic seq assignment
	f.rows = append(f.rows, row)
	return row, nil
}

// approver is a principal holding the launcher role (a permitted approver, D45).
func approverPrincipal() store.Principal {
	return store.Principal{
		ID: "p-ada", IdPSubject: "okta|ada", Org: "acme",
		Roles: []store.PrincipalRole{store.RoleLauncher},
	}
}

// nonApprover is a principal holding only the viewer role (NOT a permitted
// approver — viewers never approve, D57/D45).
func nonApproverPrincipal() store.Principal {
	return store.Principal{
		ID: "p-eve", IdPSubject: "okta|eve", Org: "acme",
		Roles: []store.PrincipalRole{store.RoleViewer},
	}
}

// TestApproveAsk_RefusesNonApprover proves the role-gate: a principal that may
// not approve is refused with ErrNotApprover and NO policy_log row is written.
func TestApproveAsk_RefusesNonApprover(t *testing.T) {
	f := &appenderFake{}
	_, err := ApproveAsk(context.Background(), f, nonApproverPrincipal(),
		"sess-1", "allow github.com", store.OptTime{}, store.ConsentClassUnspecified, []byte(`{}`))
	if !errors.Is(err, ErrNotApprover) {
		t.Fatalf("ApproveAsk error = %v, want ErrNotApprover", err)
	}
	if len(f.rows) != 0 {
		t.Fatalf("a refused approval must write no row, got %d", len(f.rows))
	}
}

// TestApproveAsk_AttributesApprover proves the attribution path: an authorized
// approver produces an ask-grant policy_log row whose Actor IS the approver's
// principal ID, carrying the session scope, kind, and TTL.
func TestApproveAsk_AttributesApprover(t *testing.T) {
	f := &appenderFake{}
	exp := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	row, err := ApproveAsk(context.Background(), f, approverPrincipal(),
		"sess-1", "allow github.com", *store.SetTime(exp), store.ConsentClassUnspecified, []byte(`{"rule":"allow github.com"}`))
	if err != nil {
		t.Fatalf("ApproveAsk: unexpected error: %v", err)
	}
	if len(f.rows) != 1 {
		t.Fatalf("expected exactly one appended row, got %d", len(f.rows))
	}
	if row.Actor != "p-ada" {
		t.Errorf("row Actor = %q, want the approver principal ID %q", row.Actor, "p-ada")
	}
	if row.Kind != store.PolicyKindAskGrant {
		t.Errorf("row Kind = %q, want %q", row.Kind, store.PolicyKindAskGrant)
	}
	if row.SessionUUID != "sess-1" {
		t.Errorf("row SessionUUID = %q, want %q", row.SessionUUID, "sess-1")
	}
	if row.ExpiresAt == nil || !row.ExpiresAt.Equal(exp) {
		t.Errorf("row ExpiresAt = %v, want %v", row.ExpiresAt, exp)
	}
	if row.Seq == 0 {
		t.Error("row Seq = 0, want a store-assigned seq")
	}
}

// TestApproveAsk_OrgAdminApproves proves the org-admin role also gates open
// (D45 allow-always escalation lands on org-admin acceptance).
func TestApproveAsk_OrgAdminApproves(t *testing.T) {
	f := &appenderFake{}
	admin := store.Principal{
		ID: "p-admin", IdPSubject: "okta|admin", Org: "acme",
		Roles: []store.PrincipalRole{store.RoleOrgAdmin},
	}
	row, err := ApproveAsk(context.Background(), f, admin,
		"sess-2", "allow *", store.OptTime{}, store.ConsentClassUnspecified, []byte(`{}`))
	if err != nil {
		t.Fatalf("ApproveAsk(org-admin): %v", err)
	}
	if row.Actor != "p-admin" {
		t.Errorf("row Actor = %q, want %q", row.Actor, "p-admin")
	}
}

// TestApproveAsk_AppendError surfaces a store append failure (e.g. ErrUnavailable
// degraded mode) rather than swallowing it.
func TestApproveAsk_AppendError(t *testing.T) {
	f := &appenderFake{err: store.ErrUnavailable}
	_, err := ApproveAsk(context.Background(), f, approverPrincipal(),
		"sess-1", "allow github.com", store.OptTime{}, store.ConsentClassUnspecified, []byte(`{}`))
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("ApproveAsk error = %v, want wrapping store.ErrUnavailable", err)
	}
}

// TestApproveAsk_WithMemoryStore proves the caller wires against the REAL store
// append seam: an authorized approval lands a retrievable ask-grant attributed
// to the approver, and a non-approver writes nothing.
func TestApproveAsk_WithMemoryStore(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()

	exp := time.Now().Add(time.Hour)
	row, err := ApproveAsk(ctx, repo, approverPrincipal(),
		"sess-mem", "allow github.com", *store.SetTime(exp), store.ConsentClassUnspecified, []byte(`{}`))
	if err != nil {
		t.Fatalf("ApproveAsk(memory): %v", err)
	}
	if row.Actor != "p-ada" || row.Kind != store.PolicyKindAskGrant {
		t.Fatalf("appended row = %+v, want approver p-ada / ask_grant", row)
	}

	grants, err := repo.LiveGrants(ctx, "sess-mem", time.Now())
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].Actor != "p-ada" {
		t.Fatalf("LiveGrants = %+v, want one grant attributed to p-ada", grants)
	}

	// A non-approver writes nothing through the real store either.
	if _, err := ApproveAsk(ctx, repo, nonApproverPrincipal(),
		"sess-mem", "allow evil.com", store.OptTime{}, store.ConsentClassUnspecified, []byte(`{}`)); !errors.Is(err, ErrNotApprover) {
		t.Fatalf("non-approver error = %v, want ErrNotApprover", err)
	}
	grants, err = repo.LiveGrants(ctx, "sess-mem", time.Now())
	if err != nil {
		t.Fatalf("LiveGrants after refusal: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("refused approval must not add a grant, got %d live grants", len(grants))
	}
}
