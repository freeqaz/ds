package sessions

// storeseams.go turns the doc 15 §4.1 spine's "all the store-backed seams must
// share ONE backing store" convention — until now only a DOC COMMENT on
// RunCreateSpine — into an ENFORCED runtime invariant.
//
// THE INVARIANT (why it matters). RunCreateSpine threads three STORE-BACKED
// seams that the ordering proof depends on hitting the SAME *store.Memory /
// *store.Postgres value:
//
//   - the GATE LINKER — the launch gate writes the session→principal link in
//     step 1 (auth.LaunchGate.SetSessionLaunchingPrincipal through its store
//     linker);
//   - the LAUNCHING-USER RESOLVER — step 5 READS that link back
//     (store.ResolveLaunchingUserClaim) to source the IdP-backed launching_user;
//   - the PIN WRITER — the steps-1–2 role pin PERSISTS onto the same session row
//     (store.UpdateSession).
//
// If the gate links session→principal on store A but step 5 resolves against
// store B, the resolver reads NOTHING — the launching_user silently goes
// nullable on an authenticated launch (a fabricated-attribution-shaped failure),
// and the pin lands on a row the gate never linked. The orch12/13 RunCreateSpine
// asserted "the caller injects one store value that satisfies both seams" in
// prose ONLY; nothing refused a mismatched wiring. This file closes that gap two
// ways, belt-and-suspenders:
//
//  1. A SINGLE-STORE ACCESSOR (StoreSeams) — the caller hands ONE store value and
//     gets the three store-backed seams back, each carrying that one store's
//     identity. Wiring through the accessor is coherent BY CONSTRUCTION (there is
//     only one store to hand out), so the happy path can never drift.
//  2. A RUNTIME COHERENCE ASSERTION in RunCreateSpine (assertStoreCoherence) —
//     for seams that carry a store-identity tag (the accessor stamps it; a
//     gate adapter MAY stamp it via TagGate), the spine REFUSES fail-closed if
//     the gate, resolver, and pin writer do not resolve to the SAME store. An
//     untagged seam (a bare test fake, or a pre-accessor caller) opts OUT — the
//     assertion is skipped for it, preserving the pre-coherence behavior and the
//     existing RunCreateSpine tests. A MIXED wiring (some tagged, some not) is
//     left to the convention; only seams that BOTH carry a tag are compared.
//
// THE MIXED-STORE GAP, AND THE REQUIRE-COHERENCE POSTURE (this revision). The
// opt-out default above leaves one failure class open: a HALF-MIGRATED wiring
// that pairs an accessor-tagged seam (say the resolver, over store A) with a
// hand-rolled UNTAGGED store-backed seam (say a pin writer over a DIFFERENT
// store B). The untagged seam opts out, the lone tagged seam has nothing to
// disagree with, and the split store slips through to convention — exactly the
// fabricated-attribution-shaped failure spine-coherence set out to make
// impossible. So the accessor now offers a STRICT posture (StoreSeamsStrict,
// which stamps the require-coherence flag onto the storeIdentity tags it cuts):
// under it, the assertion treats ANY non-nil store-backed seam that is UNTAGGED as a refusal
// (ErrStoreUntagged) — a half-migrated wiring fails closed rather than relying
// on convention. The strict posture is carried IN the tag (the StoreSeams
// accessor controls it), NOT threaded as a RunCreateSpine parameter, because the
// assertion's call site (createspine.go) hands it the same three seams either
// way. The default (lenient) posture is unchanged: bare test fakes and
// pre-accessor callers — none carrying a require-coherence tag — still opt out,
// so the existing RunCreateSpine + untagged-opt-out tests stay green.
//
// Production wiring SHOULD flip require-coherence on (cut its seams through
// StoreSeamsStrict): once main.go (P-T2, proto-gated) wires the real store, a
// half-migrated wiring must fail closed, not silently split. The lenient
// StoreSeams stays for bare fakes / pre-accessor callers only. See the comment
// on StoreSeamsStrict for the wiring-site contract.
//
// TYPED-NIL HARDENING (this revision). A non-nil interface holding a nil
// concrete pointer (a "typed nil") passes the `pinWriter != nil` guard in
// RunCreateSpine, then — if that concrete type implements storeCoherent —
// reaches storeCoherenceID() on a NIL receiver, which panics (or, on a value
// receiver, silently reads a zero identity and bypasses the check). assertStore-
// Coherence now reflect-detects a typed-nil seam and refuses it fail-closed
// (ErrStoreSeamNil) — a typed-nil seam is a wiring bug, never a sanctioned
// no-persist (the sanctioned no-persist is a genuinely nil interface, caught by
// the `pinWriter != nil` guard upstream).
//
// CROSS-TREE / SAME-TREE DISCIPLINE (binding, same reason createspine.go is
// data-typed). The gate lives in orchestrator/internal/auth, and auth's TEST
// imports THIS package — so a PRODUCTION import sessions→auth would cycle. The
// accessor therefore does NOT build the gate (that needs auth.NewLaunchGate). It
// hands out the store-backed LINKER (the sessionLinker shape the gate consumes)
// so the wiring site — which MAY import auth — builds the gate over the SAME
// store value, and offers TagGate to stamp the resulting launchGate adapter with
// that store's identity so the runtime assertion can compare it. The store source
// (orchestrator/internal/store) stays FROZEN: the accessor reads the store value's
// IDENTITY through the seam interfaces it already exposes, adding no store method.

import (
	"context"
	"errors"
	"reflect"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// SessionStore is the single store value the §4.1 spine is wired from: the union
// of the three store-backed seams the create cluster needs — the gate's link
// write (SetSessionLaunchingPrincipal), step 5's link read
// (ResolveLaunchingUserClaim), and the pin write (UpdateSession). Both
// *store.Memory and *store.Postgres satisfy it identically (these are EXISTING
// exported store methods — the store package stays frozen). Handing ONE
// SessionStore to StoreSeams is what makes the three seams provably coherent.
type SessionStore interface {
	SetSessionLaunchingPrincipal(ctx context.Context, sessionUUID, principalID string) error
	ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error)
	UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error)
}

// storeIdentity is the comparable token that proves two seams share one backing
// store. It wraps the store value as an interface (a pointer receiver — both
// *store.Memory and *store.Postgres are pointers — so the interface value is
// COMPARABLE and equal iff it is the SAME store object). The runtime assertion
// compares these; identity is OBJECT identity, never structural equality.
//
// requireCoherence rides on the tag (not on the assertion's call site, which is
// fixed): a tag cut by the STRICT accessor (StoreSeamsStrict) sets it, marking
// the whole wiring as one that must fail closed on ANY untagged store-backed
// seam, not merely on a disagreeing tagged pair. It does NOT participate in
// `same` — two seams over one store are coherent regardless of posture; the flag
// only ESCALATES what counts as a refusal.
type storeIdentity struct {
	store SessionStore
	// requireCoherence marks a tag cut by the strict accessor: under it, the
	// runtime assertion refuses ANY non-nil untagged store-backed seam in the
	// wiring (ErrStoreUntagged), so a half-migrated split store cannot slip
	// through to convention. Default (lenient) tags leave it false.
	requireCoherence bool
}

// same reports whether two store identities name the SAME backing store object.
// The comparison is on the wrapped interface value (pointer identity for the
// real stores), so two distinct *store.Memory values — even if equally empty —
// are NOT the same, and a single store value handed to every seam IS. The
// requireCoherence posture flag is deliberately NOT compared: it governs whether
// an UNTAGGED seam is a refusal, not whether two TAGGED stores match.
func (a storeIdentity) same(b storeIdentity) bool { return a.store == b.store }

// storeCoherent is the optional interface a store-backed seam implements to
// expose which store backs it. The accessor's seams implement it (stamped with
// the one store's identity); a gate adapter MAY implement it via TagGate. A seam
// that does NOT implement it opts OUT of the runtime coherence check — the
// pre-coherence convention still governs it (so bare test fakes and pre-accessor
// callers are unaffected). The method name is unexported so ONLY this package's
// own wrappers can claim coherence — a foreign type cannot forge a tag.
type storeCoherent interface {
	storeCoherenceID() storeIdentity
}

// ErrStoreIncoherent is the fail-closed refusal the runtime assertion returns
// when the gate, resolver, and pin writer carry store-identity tags that do NOT
// all name the same backing store. It is a MISCONFIGURATION (the wiring crossed
// stores), distinct from a launch/role refusal — surfaced so a create driver
// never runs the spine against a split store (where the gate's link would be
// unreadable by step 5 and the pin would land on an unlinked row).
var ErrStoreIncoherent = errors.New("sessions: store-incoherent wiring (gate linker, launching_user resolver, and pin writer must share one backing store)")

// ErrStoreUntagged is the fail-closed refusal the runtime assertion returns under
// the STRICT (require-coherence) posture when a non-nil store-backed seam carries
// NO store-identity tag. It is the sibling of ErrStoreIncoherent: where that one
// catches a wiring that crossed stores while claiming coherence, this one catches
// a HALF-MIGRATED wiring — an accessor-tagged seam paired with a hand-rolled
// untagged store-backed seam — that the lenient posture would have let slip to
// convention. A strict wiring whose seams are not ALL tagged (and coherent) is
// refused before any store work. errors.Is(err, ErrStoreIncoherent) does NOT
// match this; classify on ErrStoreUntagged to distinguish a missing tag from a
// crossed store (the three sentinels — ErrStoreIncoherent, ErrStoreUntagged,
// ErrStoreSeamNil — are siblings, not wrapped under a shared umbrella).
var ErrStoreUntagged = errors.New("sessions: store-untagged seam under require-coherence (a half-migrated wiring: every store-backed seam must be cut from one StoreSeamsStrict bundle)")

// ErrStoreSeamNil is the fail-closed refusal the runtime assertion returns when a
// seam is a TYPED NIL — a non-nil interface holding a nil concrete pointer. Such a
// seam passes the upstream `pinWriter != nil` guard yet would panic (or silently
// bypass) on storeCoherenceID() / its actual store call; it is always a wiring
// bug, never the sanctioned no-persist (which is a GENUINELY nil interface). The
// assertion reflect-detects it and refuses fail-closed rather than dereferencing.
var ErrStoreSeamNil = errors.New("sessions: typed-nil store seam (a non-nil interface over a nil pointer — a wiring bug; the sanctioned no-persist is a genuinely nil seam)")

// coherentGate wraps a launchGate with a store-identity tag — the value TagGate
// returns. It forwards AuthorizeLaunch verbatim and answers storeCoherenceID with
// the store the gate's linker was built over, so the runtime assertion can prove
// the gate hits the same store as the resolver and pin writer.
type coherentGate struct {
	inner launchGate
	id    storeIdentity
}

func (g coherentGate) AuthorizeLaunch(ctx context.Context, sessionUUID string, in *LaunchInput) (LaunchOutcome, error) {
	return g.inner.AuthorizeLaunch(ctx, sessionUUID, in)
}

func (g coherentGate) storeCoherenceID() storeIdentity { return g.id }

// coherentResolver wraps the launching_user resolver with a store-identity tag.
// It forwards ResolveLaunchingUserClaim to the one store and answers
// storeCoherenceID with that store's identity.
type coherentResolver struct {
	inner launchingUserResolver
	id    storeIdentity
}

func (r coherentResolver) ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error) {
	return r.inner.ResolveLaunchingUserClaim(ctx, sessionUUID)
}

func (r coherentResolver) storeCoherenceID() storeIdentity { return r.id }

// coherentPinWriter wraps the pin writer with a store-identity tag. It forwards
// UpdateSession to the one store and answers storeCoherenceID with that store's
// identity.
type coherentPinWriter struct {
	inner rolePinWriter
	id    storeIdentity
}

func (w coherentPinWriter) UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error) {
	return w.inner.UpdateSession(ctx, sessionUUID, u)
}

func (w coherentPinWriter) storeCoherenceID() storeIdentity { return w.id }

// SpineSeams is the bundle StoreSeams hands back: the §4.1 spine's store-backed
// seams, all carrying the SAME store's identity tag. The launching_user resolver
// (Resolver) and the pin writer (PinWriter) are ready to pass straight into
// RunCreateSpine. The gate is NOT in the bundle — building it needs auth (the
// sessions→auth import cycle, see the file header) — so the bundle instead hands
// the store-backed GateLinker (the sessionLinker shape auth.NewLaunchGate
// consumes, built over the SAME store) plus TagGate to stamp the resulting gate
// adapter with this store's identity. Wiring entirely through this bundle is
// coherent by construction; the runtime assertion then re-proves it fail-closed.
type SpineSeams struct {
	// Resolver is the launching_user resolver (step 5's link read), tagged with
	// the one store's identity. Pass as RunCreateSpine's mintResolver.
	Resolver launchingUserResolver
	// PinWriter is the role-pin persistence seam (UpdateSession), tagged with the
	// one store's identity. Pass as RunCreateSpine's pinWriter.
	PinWriter rolePinWriter
	// GateLinker is the store-backed session linker the launch gate writes the
	// session→principal link through (SetSessionLaunchingPrincipal +
	// ResolveLaunchingUserClaim). It is the SAME store value behind Resolver and
	// PinWriter. The wiring site (which may import auth) passes it to
	// auth.NewLaunchGate so the gate links the SAME store step 5 reads. It is the
	// bare store seam — UNTAGGED, because the gate is what carries the tag (the
	// adapter wraps the gate, not the linker); TagGate stamps the built gate.
	GateLinker GateLinker

	id storeIdentity
}

// GateLinker is the store seam the launch gate writes the session→principal link
// through (the auth package's sessionLinker shape, mirrored here so the wiring
// site can take it from the bundle without this package importing auth). Both
// methods are EXISTING store methods; auth.NewLaunchGate consumes exactly this.
type GateLinker interface {
	SetSessionLaunchingPrincipal(ctx context.Context, sessionUUID, principalID string) error
	ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error)
}

// StoreSeams is the single-store accessor: it takes ONE store value and hands out
// the §4.1 spine's store-backed seams, each stamped with that one store's
// identity. This is the coherent-by-construction path — there is only one store
// to distribute, so the gate linker, the launching_user resolver, and the pin
// writer cannot drift onto different stores. The returned bundle's Resolver and
// PinWriter drop straight into RunCreateSpine; GateLinker builds the gate over
// the same store; TagGate stamps the built gate so the runtime assertion can
// re-prove coherence fail-closed.
//
// A nil store is a misconfiguration the accessor refuses (the spine has no store
// to be coherent over).
//
// POSTURE. StoreSeams cuts LENIENT tags: the runtime assertion compares tagged
// seams to each other but lets an untagged store-backed seam opt out (the
// pre-coherence convention). That keeps bare-fake test wirings green, and is the
// right posture for a partial migration where not every seam is on the accessor
// yet. PRODUCTION wiring SHOULD instead use StoreSeamsStrict, which cuts tags
// that refuse ANY untagged store-backed seam — a half-migrated split store fails
// closed rather than slipping to convention.
func StoreSeams(s SessionStore) (SpineSeams, error) {
	return storeSeams(s, false)
}

// StoreSeamsStrict is the STRICT accessor: like StoreSeams, it takes ONE store
// value and hands out the §4.1 spine's store-backed seams stamped with that one
// store's identity, but the tags it cuts carry the REQUIRE-COHERENCE posture. A
// wiring cut entirely from a StoreSeamsStrict bundle is coherent by construction
// AND, at the runtime assertion, refuses fail-closed (ErrStoreUntagged) if ANY
// non-nil store-backed seam in the wiring is UNTAGGED — closing the mixed-store
// gap where an accessor-tagged seam paired with a hand-rolled untagged seam over
// a DIFFERENT store would otherwise slip through to convention.
//
// WIRING-SITE CONTRACT. Cut all three store-backed seams from ONE strict bundle:
// pass Resolver and PinWriter straight into RunCreateSpine, build the gate over
// GateLinker (the same store) and pass TagGate(adapter) as the gate. The gate
// tag inherits this bundle's strict posture, so the assertion sees the whole
// wiring as strict and a stray untagged seam (e.g. a half-migrated pin writer) is
// a refusal. A nil pinWriter remains the sanctioned no-persist case even under
// strict (a genuinely nil interface opts out; a TYPED-nil one is ErrStoreSeamNil).
//
// This is the posture production wiring SHOULD adopt once main.go (P-T2, proto-
// gated) wires the real store; until then there is no production caller, so
// flipping it on is a wiring-site decision recorded here, not a code change to a
// reachable call.
func StoreSeamsStrict(s SessionStore) (SpineSeams, error) {
	return storeSeams(s, true)
}

// storeSeams is the shared constructor behind StoreSeams (lenient) and
// StoreSeamsStrict (require-coherence). A nil store is refused either way.
func storeSeams(s SessionStore, requireCoherence bool) (SpineSeams, error) {
	if s == nil {
		return SpineSeams{}, errors.New("sessions: StoreSeams: nil store")
	}
	id := storeIdentity{store: s, requireCoherence: requireCoherence}
	return SpineSeams{
		Resolver:   coherentResolver{inner: s, id: id},
		PinWriter:  coherentPinWriter{inner: s, id: id},
		GateLinker: s,
		id:         id,
	}, nil
}

// TagGate stamps a launchGate adapter (the realGateAdapter the wiring site builds
// over this bundle's GateLinker) with this bundle's store identity, so the
// runtime coherence assertion in RunCreateSpine can prove the gate hits the SAME
// store as the resolver and pin writer. The wiring site builds the
// auth.LaunchGate over GateLinker, wraps it in its data-seam adapter, then passes
// TagGate(adapter) as RunCreateSpine's gate. An already-tagged gate is re-stamped
// with this bundle's identity (the bundle is the source of truth).
func (b SpineSeams) TagGate(gate launchGate) launchGate {
	return coherentGate{inner: gate, id: b.id}
}

// isTypedNil reports whether an interface value is a TYPED NIL — a non-nil
// interface header whose concrete value is a nil pointer (or nil chan/func/map/
// slice/unsafe.Pointer). Such a value passes a plain `seam != nil` guard yet
// dereferences to nothing: calling storeCoherenceID() (or the seam's real store
// method) on it panics on a pointer receiver, or silently reads a zero on a value
// receiver. The assertion uses this to refuse a typed-nil seam fail-closed rather
// than touch it. A genuinely nil interface (seam == nil) returns false here — it
// is handled by the caller's `!= nil` guard as the sanctioned no-persist case.
func isTypedNil(seam any) bool {
	if seam == nil {
		return false
	}
	v := reflect.ValueOf(seam)
	switch v.Kind() {
	case reflect.Ptr, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}

// assertStoreCoherence is the runtime coherence check RunCreateSpine runs before
// it touches the store, over the three store-backed seams (gate, resolver, pin
// writer). It enforces two invariants, fail-closed before any store work:
//
//   - TAGGED SEAMS AGREE. Every seam that exposes a store-identity tag (the
//     StoreSeams accessor stamps it; a gate adapter MAY via TagGate) must name
//     the SAME backing store; a disagreeing pair is ErrStoreIncoherent.
//   - STRICT POSTURE (require-coherence). If ANY tagged seam carries the strict
//     posture (cut by StoreSeamsStrict), the whole wiring is strict: every
//     NON-NIL store-backed seam must be tagged (and coherent). A non-nil UNTAGGED
//     seam under strict is ErrStoreUntagged — closing the mixed-store gap where a
//     half-migrated wiring (one tagged seam + one untagged seam over a DIFFERENT
//     store) would otherwise slip to convention.
//
// In the DEFAULT (lenient) posture an untagged seam opts out (the convention
// governs it), so this is a no-op for bare-fake test wirings and pre-accessor
// callers, and a hard gate only for a wiring that crosses stores while claiming
// coherence — preserving the existing RunCreateSpine + untagged-opt-out tests.
//
// TYPED-NIL: any seam that is a typed nil (non-nil interface over a nil pointer)
// is ErrStoreSeamNil regardless of posture — it is a wiring bug, never a tag and
// never the sanctioned no-persist (which is a genuinely nil interface, filtered
// by the caller's `!= nil` guard before this runs).
//
// Two passes are deliberate: the strict posture can be declared by ANY one tagged
// seam, so we discover whether the wiring is strict (pass 1) before deciding
// whether an untagged seam is a refusal (pass 2). A single pass would let an
// untagged seam that PRECEDES the strict-tagged seam escape the strict check.
//
// SENTINEL PRECEDENCE (a doubly-broken wiring). A wiring can break two ways at
// once under strict — carry an untagged store-backed seam AND cross stores on its
// tagged pair. Pass 2 walks the seam set in slot order (gate, resolver, pin
// writer) and returns on the FIRST break it hits, so an untagged seam encountered
// before the disagreeing tagged pair surfaces as ErrStoreUntagged rather than
// ErrStoreIncoherent. That precedence is intentional and harmless: BOTH are
// fail-closed refusals before any store work, and ErrStoreUntagged (a wiring not
// cut entirely from one strict bundle) is the more actionable signal — fix the
// wiring to use one bundle and the crossed store cannot arise. A driver that needs
// the crossed-store classification specifically gets it whenever the wiring is
// fully tagged (no untagged seam to refuse first).
func assertStoreCoherence(gate launchGate, resolver launchingUserResolver, pinWriter rolePinWriter) error {
	// Order is irrelevant to the result; the slice is the set of seams to vet. A
	// genuinely nil interface (the sanctioned no-persist pinWriter) is dropped
	// here so it never counts as a store-backed seam; a TYPED nil is kept so the
	// reflect guard can refuse it.
	seams := make([]any, 0, 3)
	for _, s := range []any{gate, resolver, pinWriter} {
		if s == nil {
			continue // genuinely nil interface: the sanctioned no-persist / no-seam case
		}
		seams = append(seams, s)
	}

	// PASS 1 — typed-nil refusal + discover whether the wiring is strict. A typed
	// nil is refused immediately (never dereferenced). The strict posture is set
	// by ANY tagged seam declaring it.
	strict := false
	for _, s := range seams {
		if isTypedNil(s) {
			return ErrStoreSeamNil
		}
		if c, ok := s.(storeCoherent); ok {
			if c.storeCoherenceID().requireCoherence {
				strict = true
			}
		}
	}

	// PASS 2 — tagged seams must agree; under strict, untagged store-backed seams
	// are refused.
	var first storeIdentity
	have := false
	for _, s := range seams {
		c, ok := s.(storeCoherent)
		if !ok {
			// Untagged seam. Lenient: opt out (convention governs). Strict: a
			// non-nil untagged store-backed seam is a half-migrated wiring — refuse.
			if strict {
				return ErrStoreUntagged
			}
			continue
		}
		id := c.storeCoherenceID()
		if !have {
			first, have = id, true
			continue
		}
		if !first.same(id) {
			return ErrStoreIncoherent
		}
	}
	return nil
}
