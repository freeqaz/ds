package auth

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// resolve_test.go drives the principal-upsert path (doc 16 §3.2/§11.2) against
// both a synthetic principalStore fake and the REAL in-memory store, proving the
// IdP subject becomes the §3.2 key and the §11.2 group→role mapping becomes the
// role set — re-derived (not a stale ACL) on every resolve.

// TestResolvePrincipal_NewCreates proves a never-seen IdP subject is CREATED as
// a §3.2 principal keyed on the subject, with the mapped role set.
func TestResolvePrincipal_NewCreates(t *testing.T) {
	repo := store.NewMemory()
	r := NewResolver(repo, WithIDGen(seqID("p")))

	got, err := r.ResolvePrincipal(context.Background(), ResolvedAuth{
		Org:         "acme",
		Subject:     "okta|ada",
		Roles:       []store.PrincipalRole{store.RoleLauncher, store.RoleApprover},
		DisplayName: "Ada Lovelace",
	})
	if err != nil {
		t.Fatalf("ResolvePrincipal(new): %v", err)
	}
	if got.IdPSubject != "okta|ada" || got.Org != "acme" {
		t.Errorf("principal key = (%q,%q), want (okta|ada,acme)", got.IdPSubject, got.Org)
	}
	if !reflect.DeepEqual(got.Roles, []store.PrincipalRole{store.RoleLauncher, store.RoleApprover}) {
		t.Errorf("roles = %v, want [launcher approver]", got.Roles)
	}
	// Persisted: GetPrincipalByIdP returns the same record.
	persisted, err := repo.GetPrincipalByIdP(context.Background(), "okta|ada", "acme")
	if err != nil || persisted.ID != got.ID {
		t.Fatalf("created principal not persisted: %v / %+v", err, persisted)
	}
}

// TestResolvePrincipal_ExistingReDerivesRoles proves a re-auth of a KNOWN
// subject REPLACES the role set with the freshly-asserted mapping — a removed
// group drops its role (doc 16 §11.2 offboarding/role-drift), and the IdP
// subject + org stay the immutable business key (same principal ID).
func TestResolvePrincipal_ExistingReDerivesRoles(t *testing.T) {
	repo := store.NewMemory()
	r := NewResolver(repo, WithIDGen(seqID("p")))

	first, err := r.ResolvePrincipal(context.Background(), ResolvedAuth{
		Org: "acme", Subject: "okta|ada",
		Roles: []store.PrincipalRole{store.RoleLauncher, store.RoleOrgAdmin},
	})
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}

	// Re-auth: the org-admin group was removed at the IdP, so only launcher maps.
	second, err := r.ResolvePrincipal(context.Background(), ResolvedAuth{
		Org: "acme", Subject: "okta|ada",
		Roles: []store.PrincipalRole{store.RoleLauncher},
	})
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("re-auth changed principal ID %q → %q (business key must be stable)", first.ID, second.ID)
	}
	if !reflect.DeepEqual(second.Roles, []store.PrincipalRole{store.RoleLauncher}) {
		t.Errorf("re-derived roles = %v, want [launcher] (org-admin dropped)", second.Roles)
	}
}

// TestResolvePrincipal_Refusals proves the launch-gate preconditions: no
// subject, no org, or an out-of-vocabulary role is ErrAuth before any write.
func TestResolvePrincipal_Refusals(t *testing.T) {
	repo := store.NewMemory()
	r := NewResolver(repo, WithIDGen(seqID("p")))
	cases := []struct {
		name string
		ra   ResolvedAuth
	}{
		{"no subject", ResolvedAuth{Org: "acme"}},
		{"no org", ResolvedAuth{Subject: "okta|ada"}},
		{"bad role", ResolvedAuth{Org: "acme", Subject: "okta|ada",
			Roles: []store.PrincipalRole{"superuser"}}},
	}
	for _, tc := range cases {
		if _, err := r.ResolvePrincipal(context.Background(), tc.ra); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: want ErrAuth, got %v", tc.name, err)
		}
	}
}

// TestResolvePrincipal_StoreFaultSurfaced proves a store fault (degraded mode)
// is surfaced — the launch gate stalls rather than proceeding without a
// principal.
func TestResolvePrincipal_StoreFaultSurfaced(t *testing.T) {
	r := NewResolver(&faultyStore{err: store.ErrUnavailable}, WithIDGen(seqID("p")))
	_, err := r.ResolvePrincipal(context.Background(), ResolvedAuth{
		Org: "acme", Subject: "okta|ada", Roles: []store.PrincipalRole{store.RoleLauncher},
	})
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("store fault should surface ErrUnavailable, got %v", err)
	}
}

// TestRandomPrincipalID proves the default generator mints distinct,
// prefixed IDs (the create path needs only collision-resistance; the business
// key dedupes a human).
func TestRandomPrincipalID(t *testing.T) {
	a, b := randomPrincipalID(), randomPrincipalID()
	if a == b {
		t.Fatal("randomPrincipalID returned a duplicate")
	}
	for _, id := range []string{a, b} {
		if len(id) < 5 || id[:4] != "prn_" {
			t.Errorf("principal ID %q lacks the prn_ prefix", id)
		}
	}
}

// --- test seams ---

// seqID returns a deterministic, incrementing ID generator for tests.
func seqID(prefix string) func() string {
	n := 0
	return func() string {
		n++
		return prefix + strconv.Itoa(n)
	}
}

// faultyStore is a principalStore that fails GetPrincipalByIdP with a fixed
// error (the degraded-mode path).
type faultyStore struct{ err error }

func (f *faultyStore) GetPrincipalByIdP(context.Context, string, string) (store.Principal, error) {
	return store.Principal{}, f.err
}
func (f *faultyStore) CreatePrincipal(context.Context, store.Principal) (store.Principal, error) {
	return store.Principal{}, f.err
}
func (f *faultyStore) SetPrincipalRoles(context.Context, string, []store.PrincipalRole) (store.Principal, error) {
	return store.Principal{}, f.err
}
