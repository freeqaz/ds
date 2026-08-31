package sessions

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/auth"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// realGateAdapter wraps the REAL *auth.LaunchGate behind the spine's DATA seam
// (launchGate over LaunchInput/LaunchOutcome). This is the adapter the production
// wiring site installs — kept in the TEST here because sessions[test] MAY import
// auth (sessions[test]→auth[prod] is acyclic), while sessions[prod] may NOT (that
// would cycle with auth's own test that imports sessions). It converts *LaunchInput
// → *auth.ResolvedAuth, the gate's auth.LaunchAuthorization → LaunchOutcome, and —
// critically — wraps the gate's auth.ErrAuth refusal as the spine's ErrLaunchRefused
// sentinel (so ErrIsLaunchRefused classifies it) while surfacing a store/catalog
// FAULT verbatim (NOT a refusal).
type realGateAdapter struct{ gate *auth.LaunchGate }

func (a realGateAdapter) AuthorizeLaunch(ctx context.Context, sessionUUID string, in *LaunchInput) (LaunchOutcome, error) {
	var ra *auth.ResolvedAuth
	if in != nil {
		roles := make([]store.PrincipalRole, 0, len(in.Roles))
		for _, r := range in.Roles {
			roles = append(roles, store.PrincipalRole(r))
		}
		ra = &auth.ResolvedAuth{Org: in.Org, Subject: in.Subject, Roles: roles, DisplayName: in.DisplayName}
	}
	authz, err := a.gate.AuthorizeLaunch(ctx, sessionUUID, ra)
	if err != nil {
		if errors.Is(err, auth.ErrAuth) {
			// A refusal (unauthenticated / over-vocabulary launch): wrap as the spine
			// sentinel so the spine classifies it as fail-closed + attributable.
			return LaunchOutcome{}, fmt.Errorf("%w: %v", ErrLaunchRefused, err)
		}
		return LaunchOutcome{}, err // a store/catalog fault: surface verbatim
	}
	return LaunchOutcome{
		PrincipalID: authz.Principal.ID,
		Subject:     authz.Claim.Subject,
		Org:         authz.Claim.Org,
		Linked:      true,
	}, nil
}

// launchGateFake is a synthetic launchGate: it scripts the gate's outcome and
// RECORDS whether AuthorizeLaunch was called, so the spine's ordering — the gate
// runs BEFORE role resolution and mint assembly, and a gate refusal stops the spine
// before either — can be asserted without standing up the principal store.
type launchGateFake struct {
	out    LaunchOutcome
	err    error
	called bool
}

func (f *launchGateFake) AuthorizeLaunch(_ context.Context, _ string, _ *LaunchInput) (LaunchOutcome, error) {
	f.called = true
	return f.out, f.err
}

// spineRoleResolver returns a fake RoleResolver that records the recorded default
// plus one known role, and tracks whether Resolve/Default ran (so a refused launch
// can be shown to NEVER reach role resolution).
type spineRoleResolver struct {
	dflt  RoleResolution
	byRef map[string]RoleResolution
	ran   bool
}

func (r *spineRoleResolver) Resolve(_ context.Context, ref string) (RoleResolution, bool, error) {
	r.ran = true
	res, ok := r.byRef[ref]
	return res, ok, nil
}

func (r *spineRoleResolver) Default(_ context.Context) (RoleResolution, error) {
	r.ran = true
	return r.dflt, nil
}

// trackingMintResolver wraps the launching_user resolver and records whether it ran
// (so a refused launch can be shown to NEVER reach the step-5 mint assembly).
type trackingMintResolver struct {
	inner launchingUserResolver
	ran   bool
}

func (m *trackingMintResolver) ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error) {
	m.ran = true
	return m.inner.ResolveLaunchingUserClaim(ctx, sessionUUID)
}

// TestRunCreateSpine_UnauthenticatedRefusedBeforeMint is the headline auth
// acceptance: an unauthenticated launch (req.Auth == nil) is REFUSED via
// AuthorizeLaunch BEFORE any role is resolved or any mint is assembled — fail-closed
// and attributable (auth.ErrAuth). The role resolver and the mint resolver must NEVER
// have run on a refused launch.
func TestRunCreateSpine_UnauthenticatedRefusedBeforeMint(t *testing.T) {
	ctx := context.Background()

	// A REAL launch gate (behind the spine's data seam) over a real store proves the
	// refusal end to end (the gate's own ErrAuth, wrapped as ErrLaunchRefused), and a
	// seeded session lets us prove no link was written.
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	seedSpineSession(t, repo, "sess-anon", 1)

	roleR := &spineRoleResolver{dflt: recordedDefault()}
	mintR := &trackingMintResolver{inner: repo}

	_, err := RunCreateSpine(ctx, gate, roleR, mintR, repo, CreateSpineRequest{
		SessionUUID: "sess-anon",
		Auth:        nil, // unauthenticated
		RoleRef:     "",
	}, nil)
	if !errors.Is(err, ErrLaunchRefused) {
		t.Fatalf("unauthenticated launch must be refused via the gate (ErrLaunchRefused), got %v", err)
	}
	if !ErrIsLaunchRefused(err) {
		t.Error("ErrIsLaunchRefused must classify the refusal")
	}
	// The refusal happened BEFORE role resolution and BEFORE mint assembly.
	if roleR.ran {
		t.Error("role resolution ran on a refused launch — the gate must short-circuit before steps 1–2 role work")
	}
	if mintR.ran {
		t.Error("mint assembly ran on a refused launch — the gate must short-circuit before step 5")
	}

	// And the session was left nullable (no link) — ResolveMintClaims stamps no
	// launching_user (no fabricated subject).
	claims, err := ResolveMintClaims(ctx, repo, "sess-anon")
	if err != nil {
		t.Fatalf("ResolveMintClaims(sess-anon): %v", err)
	}
	if claims.HasLaunchingUser {
		t.Error("a refused launch must leave the session nullable, never a fabricated launching_user")
	}
}

// TestRunCreateSpine_AuthenticatedPinSurvivesToStep5 is the headline end-to-end
// proof: an AUTHENTICATED launch runs the gate FIRST (writing the session→principal
// link), then resolves+pins the role, then assembles step 5 — and the result proves
// (a) the IdP-backed launching_user reached the mint claims (the gate ran before the
// step-5 resolver read the link), and (b) the PINNED role_ref survived to the step-5
// claims. Runs against the REAL store + REAL launch gate end to end.
func TestRunCreateSpine_AuthenticatedPinSurvivesToStep5(t *testing.T) {
	ctx := context.Background()

	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	seedSpineSession(t, repo, "sess-ada", 2)

	roleR := &spineRoleResolver{
		dflt: recordedDefault(),
		byRef: map[string]RoleResolution{
			"developer@2026.06.11-v1": {
				Name: "developer", Version: "2026.06.11-v1", ContentHash: "sha256:dev-abc",
				WideningsRatified: true,
			},
		},
	}

	out, err := RunCreateSpine(ctx, gate, roleR, repo, repo, CreateSpineRequest{
		SessionUUID: "sess-ada",
		Auth: &LaunchInput{
			Org:     "acme",
			Subject: "okta|ada",
			Roles:   []string{string(store.RoleLauncher)},
		},
		RoleRef: "developer@2026.06.11-v1",
	}, nil)
	if err != nil {
		t.Fatalf("RunCreateSpine(authenticated): %v", err)
	}

	// (a) The gate ran first, so the step-5 mint claims carry the IdP-backed subject
	// — proving "the create choreography writes the gate's principal link before
	// ResolveMintClaims reads it".
	if !out.MintClaims.Claims.HasLaunchingUser {
		t.Fatal("authenticated launch must yield a launching_user in the step-5 claims")
	}
	if out.MintClaims.Claims.LaunchingUser != "okta|ada" || out.MintClaims.Claims.Org != "acme" {
		t.Errorf("step-5 claims = %+v, want IdP subject okta|ada in org acme", out.MintClaims.Claims)
	}
	if out.Launch.Subject != "okta|ada" || !out.Launch.Linked {
		t.Errorf("launch outcome = %+v, want linked IdP subject okta|ada", out.Launch)
	}

	// (b) The PINNED role survived to the step-5 claims (RoleRef stamped on the mint
	// request) and to the result pin.
	if out.PinnedRole.Ref() != "developer@2026.06.11-v1" {
		t.Errorf("pinned role = %q, want developer@2026.06.11-v1", out.PinnedRole.Ref())
	}
	if out.MintClaims.RoleRef != "developer@2026.06.11-v1" {
		t.Errorf("step-5 RoleRef = %q, want the pinned role survives to step-5 claims", out.MintClaims.RoleRef)
	}

	// (c) The pin PERSISTED onto the never-recycled session record (migration 0009,
	// doc 18 §11 pin-and-audit row) — re-readable through the store seam, the triple
	// the spine resolved.
	rec, err := repo.GetSession(ctx, "sess-ada")
	if err != nil {
		t.Fatalf("GetSession(sess-ada): %v", err)
	}
	if !rec.RolePin.Pinned() {
		t.Fatal("the resolved pin must persist onto the session record (doc 18 §11)")
	}
	if rec.RolePin.Ref() != "developer@2026.06.11-v1" || rec.RolePin.ContentHash != "sha256:dev-abc" {
		t.Errorf("persisted pin = %+v, want developer@2026.06.11-v1 / sha256:dev-abc", rec.RolePin)
	}
}

// TestRunCreateSpine_AbsentRoleDefaultStamped proves the absent-role path through the
// full spine: an authenticated launch with no role_ref pins default@<current>
// explicitly and stamps it onto the step-5 claims.
func TestRunCreateSpine_AbsentRoleDefaultStamped(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	seedSpineSession(t, repo, "sess-def", 3)

	roleR := &spineRoleResolver{dflt: recordedDefault()}
	out, err := RunCreateSpine(ctx, gate, roleR, repo, repo, CreateSpineRequest{
		SessionUUID: "sess-def",
		Auth:        &LaunchInput{Org: "acme", Subject: "okta|bob", Roles: []string{string(store.RoleLauncher)}},
		RoleRef:     "", // absent
	}, nil)
	if err != nil {
		t.Fatalf("RunCreateSpine(absent role): %v", err)
	}
	if out.PinnedRole.Ref() != "default@2026.06.11-v1" {
		t.Errorf("absent role must pin default@<current> explicitly, got %q", out.PinnedRole.Ref())
	}
	if out.MintClaims.RoleRef != "default@2026.06.11-v1" {
		t.Errorf("step-5 RoleRef = %q, want default@<current> stamped", out.MintClaims.RoleRef)
	}

	// The recorded default persists onto the record EXPLICITLY (doc 18 §7: "Default
	// is recorded, not null") — the non-empty default@<current> triple, never the
	// pre-pin zero value.
	rec, err := repo.GetSession(ctx, "sess-def")
	if err != nil {
		t.Fatalf("GetSession(sess-def): %v", err)
	}
	if !rec.RolePin.Pinned() || rec.RolePin.Ref() != "default@2026.06.11-v1" {
		t.Errorf("recorded default not persisted explicitly: %+v", rec.RolePin)
	}
}

// TestRunCreateSpine_UnknownRoleRefusesAfterGate proves that on an AUTHENTICATED
// launch, an UNKNOWN role_ref refuses the create fail-closed (ErrRoleRefRefused) —
// the gate ran (the launch is authenticated) but the role refusal stops the spine
// before step-5 mint assembly. The two refusals (auth, role) are both fail-closed.
func TestRunCreateSpine_UnknownRoleRefusesAfterGate(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	seedSpineSession(t, repo, "sess-ghost", 4)

	roleR := &spineRoleResolver{dflt: recordedDefault(), byRef: map[string]RoleResolution{}}
	mintR := &trackingMintResolver{inner: repo}

	_, err := RunCreateSpine(ctx, gate, roleR, mintR, repo, CreateSpineRequest{
		SessionUUID: "sess-ghost",
		Auth:        &LaunchInput{Org: "acme", Subject: "okta|eve", Roles: []string{string(store.RoleLauncher)}},
		RoleRef:     "ghost@9",
	}, nil)
	if !errors.Is(err, ErrRoleRefRefused) {
		t.Fatalf("unknown role on an authenticated launch must refuse with ErrRoleRefRefused, got %v", err)
	}
	// The role refusal stopped the spine before step-5 mint assembly.
	if mintR.ran {
		t.Error("step-5 mint assembly ran despite a refused role — the role refusal must short-circuit before step 5")
	}
	// And no pin was persisted: a refused role never writes a triple onto the record
	// (the persistence rides AFTER a successful resolve+pin).
	rec, err := repo.GetSession(ctx, "sess-ghost")
	if err != nil {
		t.Fatalf("GetSession(sess-ghost): %v", err)
	}
	if rec.RolePin.Pinned() {
		t.Errorf("a refused role must leave the record un-pinned, got %+v", rec.RolePin)
	}
}

// faultyPinWriter is a rolePinWriter whose UpdateSession always faults — used to
// prove the spine fails closed on a pin-persistence fault (the §4.1 rollback note).
type faultyPinWriter struct{ err error }

func (f faultyPinWriter) UpdateSession(_ context.Context, _ string, _ store.SessionUpdate) (store.Session, error) {
	return store.Session{}, f.err
}

// TestRunCreateSpine_PinWriteFaultFailsClosed proves that a pin-persistence FAULT
// (the store rejecting the UpdateSession that writes the doc 18 §7 triple) stops
// the spine fail-closed BEFORE step-5 mint assembly — the create never proceeds
// past a half-written pin (the §4.1 rollback note covers the compensation).
func TestRunCreateSpine_PinWriteFaultFailsClosed(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	seedSpineSession(t, repo, "sess-fault", 9)

	roleR := &spineRoleResolver{dflt: recordedDefault()}
	mintR := &trackingMintResolver{inner: repo}
	writeErr := errors.New("store: unavailable")

	_, err := RunCreateSpine(ctx, gate, roleR, mintR, faultyPinWriter{err: writeErr},
		CreateSpineRequest{
			SessionUUID: "sess-fault",
			Auth:        &LaunchInput{Org: "acme", Subject: "okta|sam", Roles: []string{string(store.RoleLauncher)}},
			RoleRef:     "",
		}, nil)
	if !errors.Is(err, writeErr) {
		t.Fatalf("a pin-write fault must surface verbatim (fail-closed), got %v", err)
	}
	if mintR.ran {
		t.Error("step-5 mint assembly ran despite a pin-write fault — persistence must short-circuit before step 5")
	}
}

// TestRunCreateSpine_NilWriterSkipsPersistence proves the pin writer is OPTIONAL:
// a nil writer runs the spine without persisting (the in-package pin still rides
// the result), preserving the pre-unfreeze behavior for callers with no store.
func TestRunCreateSpine_NilWriterSkipsPersistence(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	seedSpineSession(t, repo, "sess-nil", 10)

	roleR := &spineRoleResolver{dflt: recordedDefault()}
	out, err := RunCreateSpine(ctx, gate, roleR, repo, nil, CreateSpineRequest{
		SessionUUID: "sess-nil",
		Auth:        &LaunchInput{Org: "acme", Subject: "okta|nil", Roles: []string{string(store.RoleLauncher)}},
		RoleRef:     "",
	}, nil)
	if err != nil {
		t.Fatalf("RunCreateSpine(nil writer): %v", err)
	}
	// The in-package pin still rides the result.
	if out.PinnedRole.Ref() != "default@2026.06.11-v1" {
		t.Errorf("in-package pin = %q, want default@<current>", out.PinnedRole.Ref())
	}
	// But the record was NOT pinned (no writer).
	rec, err := repo.GetSession(ctx, "sess-nil")
	if err != nil {
		t.Fatalf("GetSession(sess-nil): %v", err)
	}
	if rec.RolePin.Pinned() {
		t.Errorf("a nil writer must not persist the pin, got %+v", rec.RolePin)
	}
}

// TestRunCreateSpine_CatalogResolverPinsRealHash is the end-to-end orchestrator-side
// step-5 join with the REAL catalog resolver: an authenticated launch resolves the
// pinned role against the checked-in roles/ catalog, persists the pin with its REAL
// nftbridge content_hash (not a v0 marker), and stamps the pinned ref onto the step-5
// mint claims (where identity/mint's MintGrantsScoped consumes it). This proves the
// catalog resolver installs behind the steps-1–2 seam WITHOUT changing RunCreateSpine.
func TestRunCreateSpine_CatalogResolverPinsRealHash(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	seedSpineSession(t, repo, "sess-cat", 11)

	resolver, err := NewCatalogRoleResolverFromDir(rolesDir)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	out, err := RunCreateSpine(ctx, gate, resolver, repo, repo, CreateSpineRequest{
		SessionUUID: "sess-cat",
		Auth:        &LaunchInput{Org: "acme", Subject: "okta|cat", Roles: []string{string(store.RoleLauncher)}},
		RoleRef:     "developer@2026.06.11-v1",
	}, nil)
	if err != nil {
		t.Fatalf("RunCreateSpine(catalog developer): %v", err)
	}

	// The pinned ref survives to the step-5 claims (where MintGrantsScoped reads it).
	if out.MintClaims.RoleRef != "developer@2026.06.11-v1" {
		t.Errorf("step-5 RoleRef = %q, want developer@2026.06.11-v1 stamped from the catalog pin", out.MintClaims.RoleRef)
	}
	// The persisted pin carries the REAL nftbridge content_hash (the golden value),
	// not a v0 marker.
	rec, err := repo.GetSession(ctx, "sess-cat")
	if err != nil {
		t.Fatalf("GetSession(sess-cat): %v", err)
	}
	const wantHash = "d548f4c0d6e793b66765271f8feaeb904274ded563c077b7d6df4ead42adbf2c" // developer, golden
	if rec.RolePin.ContentHash != wantHash {
		t.Errorf("persisted content_hash = %q, want the catalog-computed %q", rec.RolePin.ContentHash, wantHash)
	}
	if rec.RolePin.Ref() != "developer@2026.06.11-v1" {
		t.Errorf("persisted pin ref = %q, want developer@2026.06.11-v1", rec.RolePin.Ref())
	}

	// A researcher pin records the inert-widening posture on the row (the §11
	// widening-gate audit bit) — the catalog ships it unratified.
	seedSpineSession(t, repo, "sess-res", 12)
	_, err = RunCreateSpine(ctx, gate, resolver, repo, repo, CreateSpineRequest{
		SessionUUID: "sess-res",
		Auth:        &LaunchInput{Org: "acme", Subject: "okta|res", Roles: []string{string(store.RoleLauncher)}},
		RoleRef:     "researcher@2026.06.11-v1",
	}, nil)
	if err != nil {
		t.Fatalf("RunCreateSpine(catalog researcher): %v", err)
	}
	resRec, err := repo.GetSession(ctx, "sess-res")
	if err != nil {
		t.Fatalf("GetSession(sess-res): %v", err)
	}
	if !resRec.RolePin.WideningsInert {
		t.Error("researcher's unratified widenings must record the inert posture on the persisted record (doc 18 §11)")
	}
}

// TestRunCreateSpine_GateRunsBeforeRole uses the gate FAKE to assert the ordering
// invariant directly: even when the gate is satisfied, the spine consults it BEFORE
// touching the role resolver; and a gate ERROR (any flavor) short-circuits before
// role resolution.
func TestRunCreateSpine_GateRunsBeforeRole(t *testing.T) {
	ctx := context.Background()

	// Gate refuses with a non-ErrAuth fault (e.g. a store fault): still short-circuits
	// before role resolution and mint assembly.
	gateFault := errors.New("store: unavailable")
	gf := &launchGateFake{err: gateFault}
	roleR := &spineRoleResolver{dflt: recordedDefault()}
	mintR := &trackingMintResolver{inner: store.NewMemory()}

	_, err := RunCreateSpine(ctx, gf, roleR, mintR, nil, CreateSpineRequest{SessionUUID: "s", Auth: &LaunchInput{}}, nil)
	if !errors.Is(err, gateFault) {
		t.Fatalf("a gate fault must surface verbatim, got %v", err)
	}
	if !gf.called {
		t.Error("the gate must have been consulted")
	}
	if roleR.ran || mintR.ran {
		t.Error("a gate fault must short-circuit before role resolution and mint assembly")
	}
}

// TestRunCreateSpine_FailsClosedOnMisconfig proves the spine fails closed on a nil
// gate or an empty session UUID (misconfiguration, distinct from a refusal).
func TestRunCreateSpine_FailsClosedOnMisconfig(t *testing.T) {
	ctx := context.Background()
	roleR := &spineRoleResolver{dflt: recordedDefault()}
	mintR := &trackingMintResolver{inner: store.NewMemory()}

	if _, err := RunCreateSpine(ctx, nil, roleR, mintR, nil, CreateSpineRequest{SessionUUID: "s"}, nil); err == nil {
		t.Error("a nil gate must fail closed")
	}
	if _, err := RunCreateSpine(ctx, &launchGateFake{}, roleR, mintR, nil, CreateSpineRequest{SessionUUID: ""}, nil); err == nil {
		t.Error("an empty session UUID must fail closed")
	}
}

// TestChildDerivationFromPin_InheritsParentRole proves the pinned role flows to the
// childsession.go fan-out as DATA: a child inherits the parent's pinned role_ref
// unless an explicit per-child override narrows to a different recorded role (doc 19
// §4: lineage inherited; doc 18 §6: the pinned role flows to the fan-out). The
// resulting ChildSessionDerivation is exactly what CreateChildSession consumes.
func TestChildDerivationFromPin_InheritsParentRole(t *testing.T) {
	parent := PinnedRole{Name: "developer", Version: "2026.06.11-v1", ContentHash: "sha256:dev-abc"}

	// Inherit (no per-child override): the child carries the parent's pinned ref.
	inherited := ChildDerivationFromPin(parent, "child-a", "", []string{"github"}, 30*time.Minute, "task-1")
	if inherited.RoleRef != "developer@2026.06.11-v1" {
		t.Errorf("child must inherit the parent's pinned role, got RoleRef %q", inherited.RoleRef)
	}
	if inherited.ChildSessionUUID != "child-a" || inherited.TaskRef != "task-1" {
		t.Errorf("child derivation = %+v, want the carried fan-out axes", inherited)
	}

	// Override: the child runs under a different recorded role the fan-out chose.
	overridden := ChildDerivationFromPin(parent, "child-b", "security-engineer@2026.06.11-v1", nil, 0, "task-2")
	if overridden.RoleRef != "security-engineer@2026.06.11-v1" {
		t.Errorf("explicit per-child role must override the inherited ref, got %q", overridden.RoleRef)
	}
}

// TestChildDerivationFromPin_FlowsThroughFanOut proves the pinned role reaches a REAL
// CreateChildSession fan-out derivation end to end: the parent's pinned role_ref is
// carried into the deriver's per-child narrowing (the deriver keys the doc 19 §11
// template seam on it). Uses the package's fan-out leg with a recording deriver.
func TestChildDerivationFromPin_FlowsThroughFanOut(t *testing.T) {
	parent := PinnedRole{Name: "developer", Version: "2026.06.11-v1", ContentHash: "sha256:dev-abc"}

	rec := &roleRecordingDeriver{}
	child := ChildDerivationFromPin(parent, "child-a", "", []string{"github"}, 0, "task-1")

	_, err := CreateChildSession(context.Background(), rec, CreateChildSessionRequest{
		ParentSessionUUID: "parent",
		ParentToken:       []byte("parent-token"),
		Children:          []ChildSessionDerivation{child},
	})
	if err != nil {
		t.Fatalf("CreateChildSession: %v", err)
	}
	if len(rec.sawRoleRefs) != 1 || rec.sawRoleRefs[0] != "developer@2026.06.11-v1" {
		t.Errorf("the pinned role must flow to the fan-out derivation, deriver saw %v", rec.sawRoleRefs)
	}
}

// roleRecordingDeriver is a minimal ChildTokenDeriver that records the role_ref each
// child derivation carried (proving the pinned role reaches the fan-out) and returns
// a well-formed derived token so the leg succeeds.
type roleRecordingDeriver struct {
	sawRoleRefs []string
}

func (d *roleRecordingDeriver) DeriveChildToken(_ context.Context, _ []byte, dv ChildSessionDerivation) (DerivedChildToken, error) {
	d.sawRoleRefs = append(d.sawRoleRefs, dv.RoleRef)
	return DerivedChildToken{
		Token:             []byte("child-token"),
		SessionUUID:       dv.ChildSessionUUID,
		AttenuationDepth:  1,
		BlockFingerprints: []string{"fp0", "fp1"},
		ParentSessions:    []string{dv.ChildSessionUUID},
	}, nil
}

// seedSpineSession creates a minimal session row so the launch gate can link a
// principal to it (SetSessionLaunchingPrincipal requires the session to exist).
func seedSpineSession(t *testing.T, repo *store.Memory, uuid string, idx uint64) {
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

// seqIDLocal is a deterministic principal-ID generator for the spine tests (the auth
// package's own seqID is test-internal to that package; this mirrors it here).
func seqIDLocal(prefix string) func() string {
	n := 0
	return func() string {
		n++
		return prefix + "-" + string(rune('0'+n))
	}
}
