package sessions

// Tests for the §3 rule-b/rule-c RE-DRIVE entrypoint into the SHARED create spine
// (RedriveSpine, createspine.go): it re-asserts an already-created record's desired
// state by reconstructing the create request from the PERSISTED record (its
// already-linked launching principal + its pinned role) and re-running the SAME
// RunCreateSpine the CreateSession RPC runs — never a copy. The headline
// acceptances:
//
//   - a re-drive of an already-linked session re-asserts through RunCreateSpine with
//     the record's IdP-backed subject (never fabricated) and its pinned role;
//   - the gate re-link is idempotent (re-asserting twice is stable);
//   - a record with NO linked launching principal (nullable / system session)
//     surfaces ErrRedriveNoLaunchingUser (so the reconciler takes the
//     fail-to-DESTROYED-with-audit arm), never a fabricated subject;
//   - an empty-UUID record is rejected.
//
// These run against the REAL store + REAL launch gate end to end (the spine seams
// the create RPC uses), so the re-drive shares the create path by construction.

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/auth"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// createLinkedSession runs the create spine ONCE for an authenticated launch so the
// record carries a linked launching principal + a persisted role pin — the
// already-created state a re-drive re-asserts. Returns the persisted record.
func createLinkedSession(t *testing.T, repo *store.Memory, gate launchGate, roleR RoleResolver, uuid, subject, org, roleRef string) store.Session {
	t.Helper()
	seedSpineSession(t, repo, uuid, 7)
	_, err := RunCreateSpine(context.Background(), gate, roleR, repo, repo, CreateSpineRequest{
		SessionUUID: uuid,
		Auth:        &LaunchInput{Org: org, Subject: subject, Roles: []string{string(store.RoleLauncher)}},
		RoleRef:     roleRef,
	}, nil)
	if err != nil {
		t.Fatalf("create spine for %s: %v", uuid, err)
	}
	rec, err := repo.GetSession(context.Background(), uuid)
	if err != nil {
		t.Fatalf("GetSession(%s): %v", uuid, err)
	}
	return rec
}

// TestRedriveSpine_ReassertsLinkedSessionThroughSpine is the headline re-drive
// acceptance: a record created with an authenticated launch is RE-ASSERTED through
// the SAME RunCreateSpine, sourcing the launching_user from the PERSISTED link (the
// IdP-backed subject, never fabricated) and re-asserting the PINNED role.
func TestRedriveSpine_ReassertsLinkedSessionThroughSpine(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	roleR := &spineRoleResolver{
		dflt: recordedDefault(),
		byRef: map[string]RoleResolution{
			"developer@2026.06.11-v1": {
				Name: "developer", Version: "2026.06.11-v1", ContentHash: "sha256:dev-abc",
				WideningsRatified: true,
			},
		},
	}

	// Create the session once (authenticated) so it carries a linked principal + pin.
	rec := createLinkedSession(t, repo, gate, roleR, "sess-redrive", "okta|ada", "acme", "developer@2026.06.11-v1")
	if rec.RolePin.Ref() != "developer@2026.06.11-v1" {
		t.Fatalf("precondition: created record must carry the pin; got %q", rec.RolePin.Ref())
	}

	// RE-DRIVE: re-assert the persisted record through the SAME spine.
	out, err := RedriveSpine(ctx, gate, roleR, repo, repo, rec, nil)
	if err != nil {
		t.Fatalf("RedriveSpine(linked session): %v", err)
	}

	// The launching_user came from the PERSISTED link (IdP-backed subject), never
	// fabricated — the re-drive re-asserts the SAME attribution.
	if !out.MintClaims.Claims.HasLaunchingUser {
		t.Fatal("re-drive must re-assert the launching_user from the persisted link")
	}
	if out.MintClaims.Claims.LaunchingUser != "okta|ada" || out.MintClaims.Claims.Org != "acme" {
		t.Errorf("re-driven step-5 claims = %+v, want the persisted IdP subject okta|ada in org acme", out.MintClaims.Claims)
	}
	if !out.Launch.Linked || out.Launch.Subject != "okta|ada" {
		t.Errorf("re-drive launch outcome = %+v, want the re-linked IdP subject", out.Launch)
	}
	// The PINNED role was re-asserted (the record's pin, not a re-pick).
	if out.PinnedRole.Ref() != "developer@2026.06.11-v1" {
		t.Errorf("re-driven pin = %q, want the record's pinned role developer@2026.06.11-v1", out.PinnedRole.Ref())
	}
	if out.MintClaims.RoleRef != "developer@2026.06.11-v1" {
		t.Errorf("re-driven step-5 RoleRef = %q, want the pinned role survives to the re-asserted step-5 claims", out.MintClaims.RoleRef)
	}
}

// TestRedriveSpine_Idempotent proves a re-drive re-asserted twice is stable — the
// gate re-link is idempotent (same principal, same link), so a re-issued re-drive
// on the next reconcile tick is a no-op, never a double-create.
func TestRedriveSpine_Idempotent(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	// The catalog resolver recognizes the recorded default BOTH via Default() (the
	// absent-ref create) AND via Resolve("default@<current>") (the re-drive, which
	// passes the record's concrete pinned ref) — a real catalog resolver resolves its
	// own default ref; the fake mirrors that so a default-pinned re-drive re-resolves.
	roleR := &spineRoleResolver{
		dflt:  recordedDefault(),
		byRef: map[string]RoleResolution{"default@2026.06.11-v1": recordedDefault()},
	}

	rec := createLinkedSession(t, repo, gate, roleR, "sess-idem", "okta|bob", "acme", "")

	var firstSubject string
	for i := 0; i < 3; i++ {
		out, err := RedriveSpine(ctx, gate, roleR, repo, repo, rec, nil)
		if err != nil {
			t.Fatalf("RedriveSpine tick %d: %v", i, err)
		}
		if i == 0 {
			firstSubject = out.Launch.Subject
		} else if out.Launch.Subject != firstSubject {
			t.Fatalf("re-drive must be stable across ticks; tick %d subject %q != %q", i, out.Launch.Subject, firstSubject)
		}
		if out.PinnedRole.Ref() != "default@2026.06.11-v1" {
			t.Fatalf("re-drive must re-assert the recorded default pin; got %q", out.PinnedRole.Ref())
		}
	}
}

// TestRedriveSpine_NoLaunchingUser_Sentinel proves a record with NO linked
// launching principal (a pre-mint / system session) surfaces
// ErrRedriveNoLaunchingUser — the re-drive cannot honestly re-assert it through the
// user-launch spine (it would have to fabricate a subject), so the reconciler takes
// the fail-to-DESTROYED-with-audit arm. NO fabricated subject is ever produced.
func TestRedriveSpine_NoLaunchingUser_Sentinel(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	// A session row that was NEVER linked (a system / pre-mint session).
	seedSpineSession(t, repo, "sess-sys", 9)
	rec, err := repo.GetSession(ctx, "sess-sys")
	if err != nil {
		t.Fatalf("GetSession(sess-sys): %v", err)
	}

	_, err = RedriveSpine(ctx, gate, roleR, repo, repo, rec, nil)
	if !errors.Is(err, ErrRedriveNoLaunchingUser) {
		t.Fatalf("an unlinked record must surface ErrRedriveNoLaunchingUser; got %v", err)
	}
	if !ErrIsRedriveNoLaunchingUser(err) {
		t.Error("ErrIsRedriveNoLaunchingUser must classify the nullable/system-session case")
	}
}

// TestRedriveSpine_EmptyUUID_Rejected proves an empty-UUID record is rejected
// before any spine work (it cannot key the gate / resolvers).
func TestRedriveSpine_EmptyUUID_Rejected(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	if _, err := RedriveSpine(ctx, gate, roleR, repo, repo, store.Session{}, nil); err == nil {
		t.Fatal("an empty-UUID record must be rejected")
	}
}
