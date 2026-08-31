package sessions

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// resolverFake is a synthetic launchingUserResolver: it returns a scripted
// (claim, ok, err) per session UUID, so the mint-request caller's three
// outcomes (resolved / nullable / error) can be driven without standing up a
// store. The store's own resolver behavior is covered by its conformance suite;
// this exercises only that the CALLER consumes the resolver value, including the
// ok=false nullable case.
type resolverFake struct {
	claim store.LaunchingUserClaim
	ok    bool
	err   error
	calls []string
}

func (f *resolverFake) ResolveLaunchingUserClaim(_ context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error) {
	f.calls = append(f.calls, sessionUUID)
	return f.claim, f.ok, f.err
}

// TestResolveMintClaims_Resolved proves the mint-request path CONSUMES the
// resolver value: the IdP subject becomes the launching_user claim, and the
// principal ID + org ride along into the MintReq projection.
func TestResolveMintClaims_Resolved(t *testing.T) {
	f := &resolverFake{
		claim: store.LaunchingUserClaim{
			PrincipalID: "p-ada",
			Subject:     "okta|ada",
			Org:         "acme",
		},
		ok: true,
	}
	got, err := ResolveMintClaims(context.Background(), f, "sess-launched")
	if err != nil {
		t.Fatalf("ResolveMintClaims: unexpected error: %v", err)
	}
	if len(f.calls) != 1 || f.calls[0] != "sess-launched" {
		t.Fatalf("resolver called with %v, want [sess-launched]", f.calls)
	}
	if !got.HasLaunchingUser {
		t.Fatal("HasLaunchingUser = false, want true for a resolved claim")
	}
	if got.LaunchingUser != "okta|ada" {
		t.Errorf("LaunchingUser = %q, want the resolver subject %q", got.LaunchingUser, "okta|ada")
	}
	if got.LaunchingPrincipal != "p-ada" {
		t.Errorf("LaunchingPrincipal = %q, want %q", got.LaunchingPrincipal, "p-ada")
	}
	if got.Org != "acme" {
		t.Errorf("Org = %q, want %q", got.Org, "acme")
	}
	if got.SessionUUID != "sess-launched" {
		t.Errorf("SessionUUID = %q, want %q", got.SessionUUID, "sess-launched")
	}
}

// TestResolveMintClaims_Nullable proves the ok=false nullable case (a session
// with no launching principal): the caller stamps NO launching_user claim and
// fabricates no subject, returning a valid request that carries only the
// session UUID. This is the acceptance's explicit ok=false case.
func TestResolveMintClaims_Nullable(t *testing.T) {
	f := &resolverFake{ok: false} // resolver: session exists, no launching principal
	got, err := ResolveMintClaims(context.Background(), f, "sess-system")
	if err != nil {
		t.Fatalf("ResolveMintClaims: unexpected error for nullable case: %v", err)
	}
	if got.HasLaunchingUser {
		t.Error("HasLaunchingUser = true, want false for the nullable case")
	}
	if got.LaunchingUser != "" || got.LaunchingPrincipal != "" || got.Org != "" {
		t.Errorf("nullable case must carry no attribution, got user=%q principal=%q org=%q",
			got.LaunchingUser, got.LaunchingPrincipal, got.Org)
	}
	if got.SessionUUID != "sess-system" {
		t.Errorf("SessionUUID = %q, want %q", got.SessionUUID, "sess-system")
	}
}

// TestResolveMintClaims_Error proves a resolver error (unknown session or
// dangling principal link) is surfaced, never swallowed into a fabricated claim.
func TestResolveMintClaims_Error(t *testing.T) {
	f := &resolverFake{err: store.ErrNotFound}
	_, err := ResolveMintClaims(context.Background(), f, "sess-unknown")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ResolveMintClaims error = %v, want wrapping store.ErrNotFound", err)
	}
}

// TestResolveMintClaims_WithMemoryStore proves the caller wires against the REAL
// store seam (not just the fake): a session linked to a principal resolves the
// IdP subject into the claim, and an unlinked session yields the nullable case.
func TestResolveMintClaims_WithMemoryStore(t *testing.T) {
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

	got, err := ResolveMintClaims(ctx, repo, "sess-launched")
	if err != nil {
		t.Fatalf("ResolveMintClaims(launched): %v", err)
	}
	if !got.HasLaunchingUser || got.LaunchingUser != "okta|ada" || got.Org != "acme" {
		t.Errorf("launched claim = %+v, want subject okta|ada in org acme", got)
	}

	got, err = ResolveMintClaims(ctx, repo, "sess-system")
	if err != nil {
		t.Fatalf("ResolveMintClaims(system): %v", err)
	}
	if got.HasLaunchingUser {
		t.Errorf("system session must be nullable, got %+v", got)
	}
}

// newLaunchSession builds a minimal session record for the store-backed test.
func newLaunchSession(uuid, host string, idx uint64) store.Session {
	return store.Session{
		Ref: store.SessionRef{
			SessionUUID:      uuid,
			HostID:           host,
			HostSessionIndex: idx,
			TapName:          "tap-" + uuid,
		},
		State: store.SessionPending,
	}
}
