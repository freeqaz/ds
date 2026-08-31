package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// launchgate_test.go is the acceptance proof of the launch gate (doc 16 §11.2):
//   - an UNAUTHENTICATED launch is REFUSED (no principal, no session link);
//   - an AUTHENTICATED launch yields an IdP-backed principal whose
//     ResolveLaunchingUserClaim value feeds the mint request shape
//     (sessions.ResolveMintClaims, the orch8-landed caller).
// It runs against the REAL in-memory store end to end.

// newGate stands up the launch gate over a fresh in-memory store with a
// deterministic principal-ID generator. It returns the gate and the store so the
// test can drive ResolveMintClaims against the same store.
func newGate(t *testing.T) (*LaunchGate, *store.Memory) {
	t.Helper()
	repo := store.NewMemory()
	resolver := NewResolver(repo, WithIDGen(seqID("p")))
	return NewLaunchGate(resolver, repo), repo
}

// seedSession creates a minimal session row so the gate can link a principal to
// it (SetSessionLaunchingPrincipal requires the session to exist).
func seedSession(t *testing.T, repo *store.Memory, uuid string, idx uint64) {
	t.Helper()
	_, err := repo.CreateSession(context.Background(), store.Session{
		Ref: store.SessionRef{
			SessionUUID:      uuid,
			HostID:           "host-a",
			HostSessionIndex: idx,
			TapName:          "tap-" + uuid,
		},
		State: store.SessionPending,
	})
	if err != nil {
		t.Fatalf("CreateSession(%s): %v", uuid, err)
	}
}

// TestAuthorizeLaunch_UnauthenticatedRefused proves a launch with no IdP auth
// (nil *ResolvedAuth) is refused and writes NO session link — the session stays
// nullable, so ResolveMintClaims would stamp no launching_user (never a
// fabricated subject).
func TestAuthorizeLaunch_UnauthenticatedRefused(t *testing.T) {
	gate, repo := newGate(t)
	seedSession(t, repo, "sess-anon", 1)

	if _, err := gate.AuthorizeLaunch(context.Background(), "sess-anon", nil); !errors.Is(err, ErrAuth) {
		t.Fatalf("unauthenticated launch should be ErrAuth, got %v", err)
	}

	// No link was written: the session resolves to the nullable case, and the
	// mint caller stamps NO launching_user (no fabricated subject).
	claims, err := sessions.ResolveMintClaims(context.Background(), repo, "sess-anon")
	if err != nil {
		t.Fatalf("ResolveMintClaims(sess-anon): %v", err)
	}
	if claims.HasLaunchingUser {
		t.Errorf("refused launch left a launching_user %q, want nullable", claims.LaunchingUser)
	}
}

// TestAuthorizeLaunch_AuthenticatedFeedsMint is the headline acceptance: an
// authenticated launch yields an IdP-backed principal, and the launching_user
// the gate links is exactly what sessions.ResolveMintClaims sources for the
// MintWorkloadIdentity request — the IdP subject, not a placeholder.
func TestAuthorizeLaunch_AuthenticatedFeedsMint(t *testing.T) {
	gate, repo := newGate(t)
	seedSession(t, repo, "sess-ada", 2)

	ra := &ResolvedAuth{
		Org:         "acme",
		Subject:     "okta|ada",
		Roles:       []store.PrincipalRole{store.RoleLauncher, store.RoleApprover},
		DisplayName: "Ada",
	}
	authz, err := gate.AuthorizeLaunch(context.Background(), "sess-ada", ra)
	if err != nil {
		t.Fatalf("authenticated launch: %v", err)
	}

	// The gate returned an IdP-backed principal.
	if authz.Principal.IdPSubject != "okta|ada" || authz.Principal.Org != "acme" {
		t.Errorf("principal = (%q,%q), want (okta|ada,acme)", authz.Principal.IdPSubject, authz.Principal.Org)
	}
	// The gate's resolved claim is the IdP subject (the mint stamps this value).
	if authz.Claim.Subject != "okta|ada" {
		t.Errorf("gate claim subject = %q, want okta|ada", authz.Claim.Subject)
	}

	// THE PROOF: ResolveMintClaims — the orch8-landed mint-request caller — reads
	// the link the gate wrote and sources the SAME IdP subject as launching_user.
	claims, err := sessions.ResolveMintClaims(context.Background(), repo, "sess-ada")
	if err != nil {
		t.Fatalf("ResolveMintClaims(sess-ada): %v", err)
	}
	if !claims.HasLaunchingUser {
		t.Fatal("authenticated launch did not feed launching_user into the mint shape")
	}
	if claims.LaunchingUser != "okta|ada" {
		t.Errorf("mint launching_user = %q, want the IdP subject okta|ada", claims.LaunchingUser)
	}
	if claims.LaunchingPrincipal != authz.Principal.ID {
		t.Errorf("mint launching_principal = %q, want gate principal ID %q", claims.LaunchingPrincipal, authz.Principal.ID)
	}
	if claims.Org != "acme" {
		t.Errorf("mint org = %q, want acme", claims.Org)
	}
}

// TestAuthorizeLaunch_ApproverRoleReachesStore proves the §11.2 group→role
// mapping lands on the stored principal so the §8.2 approver gate
// (store.Principal.MayApprove) sees an IdP-derived role — the IdP is the
// authentication source for the role set, the store the authority the ask path
// reads.
func TestAuthorizeLaunch_ApproverRoleReachesStore(t *testing.T) {
	gate, repo := newGate(t)
	seedSession(t, repo, "sess-app", 3)

	authz, err := gate.AuthorizeLaunch(context.Background(), "sess-app", &ResolvedAuth{
		Org: "acme", Subject: "okta|approver",
		Roles: []store.PrincipalRole{store.RoleApprover},
	})
	if err != nil {
		t.Fatalf("authenticated launch: %v", err)
	}
	if !authz.Principal.MayApprove() {
		t.Error("IdP-derived approver role did not reach MayApprove()")
	}
}

// TestAuthorizeLaunch_UnknownSessionSurfaced proves linking to a session that
// does not exist surfaces the store error (the gate does not silently mint).
func TestAuthorizeLaunch_UnknownSessionSurfaced(t *testing.T) {
	gate, _ := newGate(t)
	_, err := gate.AuthorizeLaunch(context.Background(), "no-such-session", &ResolvedAuth{
		Org: "acme", Subject: "okta|ada", Roles: []store.PrincipalRole{store.RoleLauncher},
	})
	if err == nil || errors.Is(err, ErrAuth) {
		t.Fatalf("unknown session should surface the store error, got %v", err)
	}
}
