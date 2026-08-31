package sessions

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestAssembleStep5_ConsultsResolver_Resolved proves the §4.1 step-5 stage
// CONSULTS the launching_user resolver and threads its resolved value onto the
// assembled mint request: the IdP subject, principal ID, and org all flow through
// into Claims, and the resolver is called with the session UUID exactly once.
func TestAssembleStep5_ConsultsResolver_Resolved(t *testing.T) {
	f := &resolverFake{
		claim: store.LaunchingUserClaim{
			PrincipalID: "p-ada",
			Subject:     "okta|ada",
			Org:         "acme",
		},
		ok: true,
	}
	got, err := AssembleStep5MintRequest(context.Background(), f, CreateStep5Request{
		SessionUUID: "sess-launched",
	})
	if err != nil {
		t.Fatalf("AssembleStep5MintRequest: unexpected error: %v", err)
	}
	if len(f.calls) != 1 || f.calls[0] != "sess-launched" {
		t.Fatalf("step 5 must consult the resolver once with the session UUID, got calls %v", f.calls)
	}
	if !got.Claims.HasLaunchingUser {
		t.Fatal("Claims.HasLaunchingUser = false, want true for a resolved claim")
	}
	if got.Claims.LaunchingUser != "okta|ada" {
		t.Errorf("Claims.LaunchingUser = %q, want resolver subject %q", got.Claims.LaunchingUser, "okta|ada")
	}
	if got.Claims.LaunchingPrincipal != "p-ada" || got.Claims.Org != "acme" {
		t.Errorf("Claims principal/org = %q/%q, want p-ada/acme", got.Claims.LaunchingPrincipal, got.Claims.Org)
	}
	if got.Claims.SessionUUID != "sess-launched" {
		t.Errorf("Claims.SessionUUID = %q, want %q", got.Claims.SessionUUID, "sess-launched")
	}
}

// TestAssembleStep5_NullableHandled proves the explicit ok=false nullable case
// the acceptance calls out: when the resolver reports no launching principal
// (ok=false, no error), step 5 returns a VALID mint shape with NO launching_user
// claim — HasLaunchingUser false, attribution fields empty, no fabricated subject
// — and a nil error (a system / pre-mint session mints workload identity without
// a launching_user claim, not a create failure).
func TestAssembleStep5_NullableHandled(t *testing.T) {
	f := &resolverFake{ok: false} // resolver: session exists, no launching principal
	got, err := AssembleStep5MintRequest(context.Background(), f, CreateStep5Request{
		SessionUUID: "sess-system",
	})
	if err != nil {
		t.Fatalf("AssembleStep5MintRequest: nullable case must be a non-error mint shape, got %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("step 5 must still consult the resolver in the nullable case, got calls %v", f.calls)
	}
	if got.Claims.HasLaunchingUser {
		t.Error("Claims.HasLaunchingUser = true, want false for the nullable case")
	}
	if got.Claims.LaunchingUser != "" || got.Claims.LaunchingPrincipal != "" || got.Claims.Org != "" {
		t.Errorf("nullable case must carry no attribution, got user=%q principal=%q org=%q",
			got.Claims.LaunchingUser, got.Claims.LaunchingPrincipal, got.Claims.Org)
	}
	if got.Claims.SessionUUID != "sess-system" {
		t.Errorf("Claims.SessionUUID = %q, want %q", got.Claims.SessionUUID, "sess-system")
	}
}

// TestAssembleStep5_ResolverErrorSurfaced proves a resolver error (unknown
// session or dangling principal link) is surfaced from step 5, never swallowed
// into a fabricated claim — what lets the §4.1 rollback path drive identity/CA
// revocation on a step-5 failure.
func TestAssembleStep5_ResolverErrorSurfaced(t *testing.T) {
	f := &resolverFake{err: store.ErrNotFound}
	_, err := AssembleStep5MintRequest(context.Background(), f, CreateStep5Request{
		SessionUUID: "sess-unknown",
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("AssembleStep5MintRequest error = %v, want wrapping store.ErrNotFound", err)
	}
}

// TestAssembleStep5_RoleRefCarriedVerbatim_DefaultPosture pins the role_ref the
// step-5 stage passes TODAY (the deferral coordination with taskdb 01KTWJ5A88):
// step 5 does NOT resolve role_ref — it carries whatever the create chose at
// steps 1–2 through verbatim. The default/absent posture (empty RoleRef) rides
// through unchanged, and the resolution/content-hash pinning stays 01KTWJ5A88's
// deferred work at steps 1–2.
func TestAssembleStep5_RoleRefCarriedVerbatim_DefaultPosture(t *testing.T) {
	f := &resolverFake{ok: true, claim: store.LaunchingUserClaim{PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"}}

	// Default/absent posture: step 5 carries the empty RoleRef through (no
	// resolution here — that is 01KTWJ5A88's deferred job).
	got, err := AssembleStep5MintRequest(context.Background(), f, CreateStep5Request{SessionUUID: "sess-a"})
	if err != nil {
		t.Fatalf("AssembleStep5MintRequest(default role): %v", err)
	}
	if got.RoleRef != "" {
		t.Errorf("RoleRef = %q, want the empty/default posture carried through at step 5", got.RoleRef)
	}

	// An explicit ref the create chose at steps 1–2 rides through verbatim,
	// UNresolved (step 5 never pins it to a content hash).
	got, err = AssembleStep5MintRequest(context.Background(), f, CreateStep5Request{SessionUUID: "sess-b", RoleRef: "reviewer@2"})
	if err != nil {
		t.Fatalf("AssembleStep5MintRequest(explicit role): %v", err)
	}
	if got.RoleRef != "reviewer@2" {
		t.Errorf("RoleRef = %q, want the create's ref carried verbatim %q", got.RoleRef, "reviewer@2")
	}
}

// TestAssembleStep5_WithMemoryStore proves step 5 consults the REAL resolver seam
// (not just the fake): a session linked to a principal assembles a resolved
// launching_user claim, and an unlinked session assembles the nullable shape —
// the two outcomes that drive whether the mint stamps a launching_user.
func TestAssembleStep5_WithMemoryStore(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()

	if _, err := repo.CreatePrincipal(ctx, store.Principal{
		ID: "p-ada", IdPSubject: "okta|ada", Org: "acme",
		Roles: []store.PrincipalRole{store.RoleLauncher},
	}); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	if _, err := repo.CreateSession(ctx, newLaunchSession("sess-launched", "host-a", 1)); err != nil {
		t.Fatalf("CreateSession launched: %v", err)
	}
	if err := repo.SetSessionLaunchingPrincipal(ctx, "sess-launched", "p-ada"); err != nil {
		t.Fatalf("SetSessionLaunchingPrincipal: %v", err)
	}
	if _, err := repo.CreateSession(ctx, newLaunchSession("sess-system", "host-a", 2)); err != nil {
		t.Fatalf("CreateSession system: %v", err)
	}

	got, err := AssembleStep5MintRequest(ctx, repo, CreateStep5Request{SessionUUID: "sess-launched"})
	if err != nil {
		t.Fatalf("AssembleStep5MintRequest(launched): %v", err)
	}
	if !got.Claims.HasLaunchingUser || got.Claims.LaunchingUser != "okta|ada" || got.Claims.Org != "acme" {
		t.Errorf("launched step-5 claims = %+v, want subject okta|ada in org acme", got.Claims)
	}

	got, err = AssembleStep5MintRequest(ctx, repo, CreateStep5Request{SessionUUID: "sess-system"})
	if err != nil {
		t.Fatalf("AssembleStep5MintRequest(system): %v", err)
	}
	if got.Claims.HasLaunchingUser {
		t.Errorf("system session step-5 must be nullable, got %+v", got.Claims)
	}
}
