package sessions

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/auth"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// gateFromSeams builds the REAL launch gate over the SAME store the bundle was
// cut from — the principal Resolver needs the full principal store (CreatePrincipal
// etc.), while the gate's session linker is the bundle's store-backed GateLinker
// (the same object) — and stamps the data-seam adapter with the bundle's store
// identity via TagGate. This mirrors exactly what a production wiring site does
// once main.go is reachable: one store value backs the resolver, the linker, the
// launching_user resolver, and the pin writer. It lives in the test because
// sessions[test] MAY import auth.
func gateFromSeams(repo *store.Memory, seams SpineSeams) launchGate {
	gate := auth.NewLaunchGate(
		auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))),
		seams.GateLinker,
	)
	return seams.TagGate(realGateAdapter{gate: gate})
}

// TestStoreSeams_SameStoreWiringAccepted is the headline coherent-by-construction
// proof: wiring the gate, resolver, and pin writer ALL from ONE StoreSeams bundle
// passes the runtime coherence assertion and runs the spine end to end — the
// authenticated launch's link is readable by step 5 (one store) and the pin lands
// on that same row.
func TestStoreSeams_SameStoreWiringAccepted(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSpineSession(t, repo, "sess-coh", 1)

	seams, err := StoreSeams(repo)
	if err != nil {
		t.Fatalf("StoreSeams: %v", err)
	}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	out, err := RunCreateSpine(ctx, gateFromSeams(repo, seams), roleR, seams.Resolver, seams.PinWriter,
		CreateSpineRequest{
			SessionUUID: "sess-coh",
			Auth:        &LaunchInput{Org: "acme", Subject: "okta|coh", Roles: []string{string(store.RoleLauncher)}},
			RoleRef:     "",
		}, nil)
	if err != nil {
		t.Fatalf("same-store wiring must be accepted, got %v", err)
	}
	// The single store made the gate's link readable by step 5 (the launching_user
	// resolved, not nullified) — the coherence the assertion guards.
	if !out.MintClaims.Claims.HasLaunchingUser || out.MintClaims.Claims.LaunchingUser != "okta|coh" {
		t.Errorf("coherent wiring must resolve the IdP launching_user, got %+v", out.MintClaims.Claims)
	}
	// And the pin landed on the same linked row.
	rec, err := repo.GetSession(ctx, "sess-coh")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !rec.RolePin.Pinned() {
		t.Error("coherent wiring must persist the pin on the linked row")
	}
}

// TestStoreSeams_CrossStoreWiringRefused is the headline fail-closed proof: a
// DELIBERATELY mismatched wiring — the gate built over store A, the resolver and
// pin writer from store B (two separate StoreSeams bundles) — is REFUSED with
// ErrStoreIncoherent BEFORE any store work. This is the exact bug the invariant
// closes: a split store would leave the gate's link unreadable by step 5.
func TestStoreSeams_CrossStoreWiringRefused(t *testing.T) {
	ctx := context.Background()
	storeA := store.NewMemory()
	storeB := store.NewMemory()
	seedSpineSession(t, storeA, "sess-x", 1)
	seedSpineSession(t, storeB, "sess-x", 1)

	seamsA, err := StoreSeams(storeA)
	if err != nil {
		t.Fatalf("StoreSeams(A): %v", err)
	}
	seamsB, err := StoreSeams(storeB)
	if err != nil {
		t.Fatalf("StoreSeams(B): %v", err)
	}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	// Gate over store A; resolver + pin writer from store B — incoherent.
	_, err = RunCreateSpine(ctx, gateFromSeams(storeA, seamsA), roleR, seamsB.Resolver, seamsB.PinWriter,
		CreateSpineRequest{
			SessionUUID: "sess-x",
			Auth:        &LaunchInput{Org: "acme", Subject: "okta|x", Roles: []string{string(store.RoleLauncher)}},
			RoleRef:     "",
		}, nil)
	if !errors.Is(err, ErrStoreIncoherent) {
		t.Fatalf("cross-store wiring must be refused with ErrStoreIncoherent, got %v", err)
	}

	// The refusal happened BEFORE any store work: store A's session was never
	// linked (the gate never ran) and store B's row never pinned.
	claimA, okA, err := storeA.ResolveLaunchingUserClaim(ctx, "sess-x")
	if err != nil {
		t.Fatalf("ResolveLaunchingUserClaim(A): %v", err)
	}
	if okA {
		t.Errorf("incoherent wiring must refuse before the gate links any store, got claim %+v on store A", claimA)
	}
	recB, err := storeB.GetSession(ctx, "sess-x")
	if err != nil {
		t.Fatalf("GetSession(B): %v", err)
	}
	if recB.RolePin.Pinned() {
		t.Error("incoherent wiring must refuse before any pin is written to store B")
	}
}

// TestStoreSeams_ResolverPinWriterCrossStoreRefused proves the assertion also
// catches a split between the resolver and the pin writer alone (no gate tag in
// play): a tagged resolver from store A and a tagged pin writer from store B are
// refused — every tagged pair is compared, not just the gate.
func TestStoreSeams_ResolverPinWriterCrossStoreRefused(t *testing.T) {
	ctx := context.Background()
	seamsA, err := StoreSeams(store.NewMemory())
	if err != nil {
		t.Fatalf("StoreSeams(A): %v", err)
	}
	seamsB, err := StoreSeams(store.NewMemory())
	if err != nil {
		t.Fatalf("StoreSeams(B): %v", err)
	}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	// An untagged gate fake (opts out) but a resolver from A and a pin writer from B.
	_, err = RunCreateSpine(ctx, &launchGateFake{out: LaunchOutcome{Linked: true}}, roleR,
		seamsA.Resolver, seamsB.PinWriter,
		CreateSpineRequest{SessionUUID: "s", Auth: &LaunchInput{}}, nil)
	if !errors.Is(err, ErrStoreIncoherent) {
		t.Fatalf("a resolver/pin-writer store split must be refused, got %v", err)
	}
}

// TestStoreSeams_UntaggedSeamsOptOut proves the assertion is a no-op for bare
// fakes (the existing RunCreateSpine test wiring): an untagged gate, an untagged
// resolver, and an untagged pin writer never trip the coherence check even when
// they are genuinely different objects — the convention still governs them, so the
// pre-coherence tests stay green.
func TestStoreSeams_UntaggedSeamsOptOut(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSpineSession(t, repo, "sess-bare", 1)
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	// Bare fakes / a plain store value — none carry a tag.
	_, err := RunCreateSpine(ctx, &launchGateFake{out: LaunchOutcome{Linked: true}}, roleR, repo, repo,
		CreateSpineRequest{SessionUUID: "sess-bare", Auth: &LaunchInput{}}, nil)
	if err != nil {
		t.Fatalf("untagged seams must opt out of the coherence check, got %v", err)
	}
}

// TestStoreSeams_MixedTaggedUntaggedAccepted proves a wiring where only SOME seams
// are tagged is accepted (the tagged ones agree; the untagged opt out) — the
// assertion compares only seams that BOTH carry a tag, so a partial migration to
// the accessor is not punished.
func TestStoreSeams_MixedTaggedUntaggedAccepted(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSpineSession(t, repo, "sess-mix", 1)
	seams, err := StoreSeams(repo)
	if err != nil {
		t.Fatalf("StoreSeams: %v", err)
	}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	// Tagged resolver + tagged pin writer (same store), but an UNTAGGED gate fake.
	out, err := RunCreateSpine(ctx, &launchGateFake{out: LaunchOutcome{Linked: true}}, roleR,
		seams.Resolver, seams.PinWriter,
		CreateSpineRequest{SessionUUID: "sess-mix", Auth: &LaunchInput{}}, nil)
	if err != nil {
		t.Fatalf("mixed tagged/untagged (tagged agree) must be accepted, got %v", err)
	}
	if out.PinnedRole.Ref() != "default@2026.06.11-v1" {
		t.Errorf("spine still ran: pin = %q", out.PinnedRole.Ref())
	}
}

// TestStoreSeams_NilStoreRefused proves the accessor refuses a nil store (there is
// no store to be coherent over).
func TestStoreSeams_NilStoreRefused(t *testing.T) {
	if _, err := StoreSeams(nil); err == nil {
		t.Error("StoreSeams(nil) must be refused")
	}
}

// TestStoreSeamsStrict_NilStoreRefused proves the strict accessor refuses a nil
// store identically to the lenient one.
func TestStoreSeamsStrict_NilStoreRefused(t *testing.T) {
	if _, err := StoreSeamsStrict(nil); err == nil {
		t.Error("StoreSeamsStrict(nil) must be refused")
	}
}

// untaggedStorePinWriter is a HAND-ROLLED store-backed pin writer that does NOT
// carry a store-identity tag (unlike the accessor's coherentPinWriter). It is the
// half-migrated-wiring stand-in: a real store sits behind it, but the coherence
// machinery cannot see which one. Under the lenient posture it opts out; under
// require-coherence it must be refused (ErrStoreUntagged) — that is the gap this
// unit closes. It is a POINTER type so a nil *untaggedStorePinWriter can be used
// to forge a typed-nil seam for the typed-nil test.
type untaggedStorePinWriter struct {
	inner *store.Memory
}

func (w *untaggedStorePinWriter) UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error) {
	return w.inner.UpdateSession(ctx, sessionUUID, u)
}

// TestStoreSeamsStrict_MixedTaggedUntaggedDifferentStoreRefused is the headline
// fix for the MIXED-store gap: a half-migrated wiring pairs a STRICT-tagged seam
// set (gate + resolver, store A) with a hand-rolled UNTAGGED store-backed pin
// writer over a DIFFERENT store B. Under the lenient posture the untagged pin
// writer would opt out and the split store would slip through to convention; under
// require-coherence (StoreSeamsStrict) it is REFUSED with ErrStoreUntagged BEFORE
// any store work — the exact failure class spine-coherence set out to make
// impossible.
func TestStoreSeamsStrict_MixedTaggedUntaggedDifferentStoreRefused(t *testing.T) {
	ctx := context.Background()
	storeA := store.NewMemory()
	storeB := store.NewMemory()
	seedSpineSession(t, storeA, "sess-half", 1)
	seedSpineSession(t, storeB, "sess-half", 1)

	seamsA, err := StoreSeamsStrict(storeA)
	if err != nil {
		t.Fatalf("StoreSeamsStrict(A): %v", err)
	}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	// Gate + resolver are strict-tagged over store A; the pin writer is an UNTAGGED
	// hand-rolled seam over store B — a half-migrated split store.
	untaggedB := &untaggedStorePinWriter{inner: storeB}
	_, err = RunCreateSpine(ctx, gateFromSeams(storeA, seamsA), roleR, seamsA.Resolver, untaggedB,
		CreateSpineRequest{
			SessionUUID: "sess-half",
			Auth:        &LaunchInput{Org: "acme", Subject: "okta|half", Roles: []string{string(store.RoleLauncher)}},
			RoleRef:     "",
		}, nil)
	if !errors.Is(err, ErrStoreUntagged) {
		t.Fatalf("strict wiring with an untagged store-backed seam must be refused with ErrStoreUntagged, got %v", err)
	}
	// The refusal happened BEFORE any store work: store A's session was never linked
	// and store B's row never pinned.
	if _, okA, _ := storeA.ResolveLaunchingUserClaim(ctx, "sess-half"); okA {
		t.Error("strict refusal must precede the gate's link write on store A")
	}
	if recB, _ := storeB.GetSession(ctx, "sess-half"); recB.RolePin.Pinned() {
		t.Error("strict refusal must precede any pin write to store B")
	}
}

// TestStoreSeamsStrict_AllTaggedSameStoreAccepted is the strict happy path: a
// wiring cut entirely from ONE StoreSeamsStrict bundle (gate + resolver + pin
// writer, one store) is ACCEPTED and runs the spine end to end — strict refuses
// untagged seams, not coherent tagged ones.
func TestStoreSeamsStrict_AllTaggedSameStoreAccepted(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSpineSession(t, repo, "sess-strict", 1)

	seams, err := StoreSeamsStrict(repo)
	if err != nil {
		t.Fatalf("StoreSeamsStrict: %v", err)
	}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	out, err := RunCreateSpine(ctx, gateFromSeams(repo, seams), roleR, seams.Resolver, seams.PinWriter,
		CreateSpineRequest{
			SessionUUID: "sess-strict",
			Auth:        &LaunchInput{Org: "acme", Subject: "okta|strict", Roles: []string{string(store.RoleLauncher)}},
			RoleRef:     "",
		}, nil)
	if err != nil {
		t.Fatalf("strict all-tagged same-store wiring must be accepted, got %v", err)
	}
	if !out.MintClaims.Claims.HasLaunchingUser || out.MintClaims.Claims.LaunchingUser != "okta|strict" {
		t.Errorf("strict coherent wiring must resolve the IdP launching_user, got %+v", out.MintClaims.Claims)
	}
}

// TestStoreSeamsStrict_UntaggedResolverRefused proves the strict posture is
// declared by ANY one strict-tagged seam in the wiring (here the pin writer) and
// then refuses an untagged store-backed seam that PRECEDES it in evaluation (the
// resolver) — the two-pass discovery is what makes that ordering-independent.
func TestStoreSeamsStrict_UntaggedResolverRefused(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSpineSession(t, repo, "sess-strict-r", 1)
	seams, err := StoreSeamsStrict(repo)
	if err != nil {
		t.Fatalf("StoreSeamsStrict: %v", err)
	}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	// Strict-tagged pin writer, but a BARE untagged resolver (the plain store value)
	// and an untagged gate fake. Strict must refuse the untagged store-backed seam.
	_, err = RunCreateSpine(ctx, &launchGateFake{out: LaunchOutcome{Linked: true}}, roleR,
		repo, seams.PinWriter,
		CreateSpineRequest{SessionUUID: "sess-strict-r", Auth: &LaunchInput{}}, nil)
	if !errors.Is(err, ErrStoreUntagged) {
		t.Fatalf("a strict wiring with an untagged resolver must be refused with ErrStoreUntagged, got %v", err)
	}
}

// TestStoreSeamsStrict_CrossStoreStillIncoherent proves the strict posture
// ESCALATES what counts as a refusal (an untagged seam) WITHOUT masking the more
// specific crossed-store sentinel: when EVERY store-backed seam is strict-tagged
// but they name DIFFERENT stores, the refusal is ErrStoreIncoherent, not
// ErrStoreUntagged. The require-coherence flag governs untagged seams; a
// disagreeing tagged pair is classified on the crossed store it actually is, so a
// driver can tell "missing tag" from "crossed store". (Every seam is tagged here —
// an UNTAGGED seam in the same wiring would, under strict, refuse first as
// ErrStoreUntagged before the crossed-store comparison runs; the two refusals are
// order-distinct, both fail-closed, and ErrStoreUntagged is the harder warning, so
// that precedence is correct.)
func TestStoreSeamsStrict_CrossStoreStillIncoherent(t *testing.T) {
	ctx := context.Background()
	storeA := store.NewMemory()
	seamsA, err := StoreSeamsStrict(storeA)
	if err != nil {
		t.Fatalf("StoreSeamsStrict(A): %v", err)
	}
	seamsB, err := StoreSeamsStrict(store.NewMemory())
	if err != nil {
		t.Fatalf("StoreSeamsStrict(B): %v", err)
	}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	// All three seams are strict-tagged (gate + resolver over store A, pin writer
	// over store B) — no untagged seam to mask the crossed store. The failure is the
	// crossed store, so the refusal must be ErrStoreIncoherent.
	_, err = RunCreateSpine(ctx, gateFromSeams(storeA, seamsA), roleR,
		seamsA.Resolver, seamsB.PinWriter,
		CreateSpineRequest{SessionUUID: "s", Auth: &LaunchInput{}}, nil)
	if !errors.Is(err, ErrStoreIncoherent) {
		t.Fatalf("all-tagged strict seams over different stores must be ErrStoreIncoherent, got %v", err)
	}
	if errors.Is(err, ErrStoreUntagged) {
		t.Error("a fully-tagged crossed-store strict wiring must NOT be classified as ErrStoreUntagged")
	}
}

// TestStoreSeams_TypedNilPinWriterRefusedNoPanic is the typed-nil hardening proof:
// a non-nil rolePinWriter interface holding a NIL concrete pointer
// (*untaggedStorePinWriter) passes the `pinWriter != nil` guard in RunCreateSpine,
// but the coherence assertion reflect-detects the typed nil and refuses it
// fail-closed with ErrStoreSeamNil — no panic, no silent bypass, no store work.
func TestStoreSeams_TypedNilPinWriterRefusedNoPanic(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSpineSession(t, repo, "sess-tn", 1)
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	// A typed nil: non-nil interface, nil concrete pointer.
	var typedNil rolePinWriter = (*untaggedStorePinWriter)(nil)
	if typedNil == nil {
		t.Fatal("test setup: the typed-nil seam must be a non-nil interface")
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("typed-nil pin writer must not panic, recovered %v", r)
		}
	}()

	_, err := RunCreateSpine(ctx, &launchGateFake{out: LaunchOutcome{Linked: true}}, roleR, repo, typedNil,
		CreateSpineRequest{SessionUUID: "sess-tn", Auth: &LaunchInput{}}, nil)
	if !errors.Is(err, ErrStoreSeamNil) {
		t.Fatalf("typed-nil pin writer must fail closed with ErrStoreSeamNil, got %v", err)
	}
	// Fail-closed before any store work: the row was never pinned.
	if rec, _ := repo.GetSession(ctx, "sess-tn"); rec.RolePin.Pinned() {
		t.Error("typed-nil refusal must precede any pin write")
	}
}

// TestAssertStoreCoherence_TypedNilDetectedDirectly is a unit-level proof that the
// assertion's typed-nil guard fires for a typed-nil seam in ANY of the three slots,
// without standing up the spine.
func TestAssertStoreCoherence_TypedNilDetectedDirectly(t *testing.T) {
	var nilWriter rolePinWriter = (*untaggedStorePinWriter)(nil)
	if err := assertStoreCoherence(nil, nil, nilWriter); !errors.Is(err, ErrStoreSeamNil) {
		t.Fatalf("typed-nil pin writer slot must be ErrStoreSeamNil, got %v", err)
	}

	var nilResolver launchingUserResolver = (*untaggedStoreResolver)(nil)
	if err := assertStoreCoherence(nil, nilResolver, nil); !errors.Is(err, ErrStoreSeamNil) {
		t.Fatalf("typed-nil resolver slot must be ErrStoreSeamNil, got %v", err)
	}

	// The GATE slot is the one that passes RunCreateSpine's `if gate == nil` guard
	// when it is a typed nil (a non-nil interface) — so the assertion must catch it
	// there too. launchGateFake is a pointer type, so a nil one forges a typed-nil gate.
	var nilGate launchGate = (*launchGateFake)(nil)
	if err := assertStoreCoherence(nilGate, nil, nil); !errors.Is(err, ErrStoreSeamNil) {
		t.Fatalf("typed-nil gate slot must be ErrStoreSeamNil, got %v", err)
	}

	// A genuinely nil pin writer (sanctioned no-persist) is NOT a typed nil: with no
	// other tagged seam in play, the assertion is a clean no-op.
	if err := assertStoreCoherence(&launchGateFake{}, nil, nil); err != nil {
		t.Fatalf("genuinely nil seams must be a no-op, got %v", err)
	}
}

// untaggedStoreResolver is a hand-rolled, untagged store-backed resolver (pointer
// type) used to forge a typed-nil resolver seam in the unit test above.
type untaggedStoreResolver struct {
	inner *store.Memory
}

func (r *untaggedStoreResolver) ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error) {
	return r.inner.ResolveLaunchingUserClaim(ctx, sessionUUID)
}

// TestStoreSeams_SameStoreIdentity is a unit-level proof of the identity token:
// two seams from ONE bundle share identity; two seams from two bundles over two
// stores do not.
func TestStoreSeams_SameStoreIdentity(t *testing.T) {
	repo := store.NewMemory()
	seams, err := StoreSeams(repo)
	if err != nil {
		t.Fatalf("StoreSeams: %v", err)
	}
	r := seams.Resolver.(storeCoherent).storeCoherenceID()
	w := seams.PinWriter.(storeCoherent).storeCoherenceID()
	if !r.same(w) {
		t.Error("resolver and pin writer from one bundle must share store identity")
	}

	other, err := StoreSeams(store.NewMemory())
	if err != nil {
		t.Fatalf("StoreSeams(other): %v", err)
	}
	o := other.Resolver.(storeCoherent).storeCoherenceID()
	if r.same(o) {
		t.Error("seams from two distinct stores must NOT share identity")
	}
}
