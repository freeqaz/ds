package sessions

// createspine.go is the minimal honest CreateSession CHOREOGRAPHY SPINE for the
// doc 15 §4.1 canonical sequence — the data-driven driver that ORDERS the
// create-time stages the orchestrator already landed as isolated points
// (createstep5.go's step-5 mint assembly, the auth.LaunchGate launch gate,
// roleref.go's steps-1–2 role resolution+pin) into the one master order doc 15
// §4.1 owns, honoring the frozen precedence constraints. It carries NO proto and
// stands up NO RPC: it is the in-process spine that proves the stages run in the
// right order with the right data flowing between them.
//
// WHY A SPINE (the gap this closes). createstep5.go pins step 5; launchgate.go
// pins the launch gate; roleref.go pins steps 1–2. Until now NOTHING ordered them:
// the gate and the role pin were reachable only in unit tests. This spine is the
// create-sequence driver that:
//   1. consults auth.LaunchGate.AuthorizeLaunch BEFORE minting (doc 16 §11.2: only
//      an IdP-authenticated principal may launch) — so the gate writes the session→
//      principal link the step-5 resolver (ResolveMintClaims) then reads. Refusal
//      is fail-closed and attributable (ErrAuth), and NO role is resolved and NO
//      mint is assembled on a refused launch.
//   2. resolves + PINS role_ref at §4.1 steps 1–2 (ResolveAndPinRole) — the pinned
//      (name, version, content_hash) is what step 5 stamps and what the
//      childsession.go fan-out carries as data.
//   3. assembles the step-5 mint claims (AssembleStep5MintRequest), stamping the
//      pinned role_ref — so the mint request carries the IdP-backed launching_user
//      (from step 1's gate) AND the pinned role (from steps 1–2).
//
// FROZEN PRECEDENCE HONORED (doc 15 §4.1: `1 ≺ 2 ≺ 3 ≺ {6,7,8}; 5 ≺ 6; …`). The
// spine runs the launch gate + role pin (the steps-1–2 cluster) BEFORE the step-5
// mint assembly, and the step-5 assembly reads the gate's principal link — so
// "the create choreography writes the gate's principal link before ResolveMintClaims
// reads it" is structurally true here (the acceptance's attributability ordering).
// This spine does NOT implement steps 3–4 or 7–10 (placement, host allocation,
// overlay, boot, routable, attach) — those are host-agent / boundary points out of
// this unit's scope; the spine threads the steps-1–2 + step-5 cluster that this
// wave's stages cover, leaving the later steps to their owning trees. It DOES thread
// the step-6 DIGEST-PUBLISH (doc 16 §6.1 mint-before-attach, D73) as a FLAG-GATED
// (DS_ORCH_DIGEST_PUBLISH_WIRE) fail-closed step BETWEEN cred-mint and mark-routable —
// default OFF (byte-identical), so the security-load-bearing routable gate is wired
// without changing the disarmed create (digestpublish.go).
//
// CROSS-TREE / SAME-TREE NOTE (binding, the import-cycle reason this seam is
// data-typed). The launch gate lives in orchestrator/internal/auth, but that
// package's TEST imports THIS package (auth's launchgate_test.go proves the gate
// against sessions.ResolveMintClaims). So a PRODUCTION import sessions→auth would
// form the cycle auth[test]→sessions[prod]→auth[prod] (Go rejects a cycle even
// through a test edge). The spine therefore consults the gate through a DATA seam
// (launchGate over local mirror types), never importing auth in production: a tiny
// adapter wraps the real *auth.LaunchGate at the wiring site (and in this package's
// tests, which MAY import auth — sessions[test]→auth[prod] is acyclic). This is the
// SAME data-across-the-seam discipline ResolvedAuth/MintWorkloadIdentityClaims use
// across the proto edge, applied here to break the same-tree test cycle without
// editing launchgate.go.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/metering"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// LaunchInput is the spine's local mirror of the resolved IdP auth the launch gate
// consumes (auth.ResolvedAuth) — carried as DATA so the spine never imports auth.
// The adapter at the wiring site copies an *auth.ResolvedAuth into this shape. A NIL
// *LaunchInput is the UNAUTHENTICATED launch the gate REFUSES fail-closed.
type LaunchInput struct {
	Org         string   // the org the subject is asserted within (§3.2 business key)
	Subject     string   // the OIDC `sub` — the §3.2 key / launching_user value
	Roles       []string // the §11.2 group→role mapping result (derived, not an ACL)
	DisplayName string   // display metadata only
}

// LaunchOutcome is the spine's local mirror of the gate's authorization
// (auth.LaunchAuthorization) — the resolved launching_user the gate wrote, carried
// back as DATA. The adapter copies the gate's result into this shape; the spine
// records it as the proof the authenticated launch fed the mint shape.
type LaunchOutcome struct {
	PrincipalID string // the IdP-backed principal's stable ID (§3.2)
	Subject     string // the resolved launching_user value (§3.1/§4) — the IdP subject
	Org         string // the org the subject is asserted within
	Linked      bool   // the gate wrote the session→principal link (true on success)
}

// ErrLaunchRefused is the spine's local sentinel for a launch-gate refusal — the
// adapter MUST wrap the gate's auth.ErrAuth as this when the refusal is an
// unauthenticated/over-vocabulary launch, so the spine and its callers can classify
// the fail-closed, attributable refusal WITHOUT importing auth. (A catalog/store
// FAULT from the gate is surfaced verbatim, NOT wrapped as this.)
var ErrLaunchRefused = errors.New("sessions: launch refused (unauthenticated / not IdP-authenticated)")

// rolePinWriter is the narrow store-write seam the spine uses to PERSIST the
// steps-1–2 pin onto the never-recycled session record (migration 0009, doc 18
// §7/§11). It is a dependency-injected interface — not the full store.Repository —
// so the spine depends only on the one update it performs and a test fake or
// either store impl (*store.Memory / *store.Postgres) satisfies it identically
// (UpdateSession's signature). The pin crosses as store.RolePin DATA; the store is
// the pin's system of record once written.
//
// It is OPTIONAL: a nil writer runs the spine WITHOUT persisting (the in-package
// CreateSpineResult.PinnedRole still carries the pin), preserving the pre-unfreeze
// behavior for callers that have no store wired. A non-nil writer makes the §11
// pin-and-audit row ("every session record carries role fields") actually hold.
type rolePinWriter interface {
	UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error)
}

// pinToStore projects the in-package PinnedRole onto the persisted store.RolePin
// triple (doc 18 §7). The widening posture collapses to the boolean the record
// carries: WideningsInert is true exactly when the resolved role had UNRATIFIED
// widenings that rode inert at create (the §11 widening-gate row) — i.e. the
// in-package pin recorded InertWidenings. The widening SET itself stays the
// catalog's (the actor-recorded ratification event), never duplicated onto the row.
func pinToStore(p PinnedRole) store.RolePin {
	return store.RolePin{
		Name:           p.Name,
		Version:        p.Version,
		ContentHash:    p.ContentHash,
		WideningsInert: len(p.InertWidenings) > 0 && !p.WideningsRatified,
	}
}

// pinPtr returns a pointer to a store.RolePin for the SessionUpdate payload (a
// non-nil RolePin replaces the persisted pin atomically; nil leaves it unchanged).
func pinPtr(p store.RolePin) *store.RolePin { return &p }

// launchGate is the narrow DATA seam the spine consults: it authorizes the launch
// (refusing an unauthenticated one — a nil *LaunchInput) and writes the session→
// principal link the step-5 resolver reads, returning the resolved launching_user as
// a LaunchOutcome. It is satisfied by a thin adapter over the real *auth.LaunchGate
// (and by a test fake) — the spine depends only on the DATA, never the auth types.
type launchGate interface {
	AuthorizeLaunch(ctx context.Context, sessionUUID string, in *LaunchInput) (LaunchOutcome, error)
}

// CreateSpineRequest is the input to the steps-1–2 + step-5 create cluster: the
// session being created, the resolved IdP auth (nil = an unauthenticated launch,
// REFUSED by the gate), and the requested role_ref (empty = the recorded default).
type CreateSpineRequest struct {
	// SessionUUID is the session being created (the gate's link key, the step-5
	// resolver key, and the mint request's session_uuid). Required.
	SessionUUID string
	// Auth is the resolved IdP auth (doc 16 §11.2), carried as DATA. NIL is the
	// unauthenticated launch the gate REFUSES fail-closed — no role resolved, no mint
	// assembled. A non-nil *LaunchInput is the authenticated launch (the gate upserts
	// the principal and links it to the session).
	Auth *LaunchInput
	// RoleRef is the requested role (doc 18 §6: `<name>@<version>` or catalog UUID;
	// empty = the recorded `default@<current>`). Resolved + pinned at steps 1–2.
	RoleRef string
	// DigestPublisher backs the §6.1 DIGEST-PUBLISH step (mint-before-attach, D73):
	// BETWEEN step-5 cred-mint and mark-routable the spine drives it to push the
	// session's secret digests to the boundary and gate routability on the host ack.
	// FLAG-GATED (DS_ORCH_DIGEST_PUBLISH_WIRE), default OFF: when the flag is unset the
	// step is SKIPPED and this field is unused (byte-identical to the pre-wire spine —
	// D50). When ARMED, a nil publisher, a publish/transport error, or an uncommitted
	// ack all FAIL the create fail-closed (the session is never marked routable). The
	// production adapter (DigestFeedPublisher, digestpublish.go) speaks the frozen
	// identityv1.DigestFeedServiceClient via proto/gen/go; a test fake satisfies it in
	// tests (D50). The re-drive path leaves it nil (a re-drive re-asserts an
	// already-routable session; its digest re-push rides the identity-side LiveRekey
	// path, not this create step).
	DigestPublisher digestPublisher
}

// CreateSpineResult is the create cluster's output: the launch outcome (the
// IdP-backed principal + the resolved launching_user the gate wrote), the
// PINNED role (the steps-1–2 pin the session record carries and the fan-out
// inherits), and the assembled step-5 mint claims (carrying the pinned role_ref and
// the gate-sourced launching_user). It is the DATA the rest of the create sequence
// (placement, host allocation, digest, overlay, boot) and the childsession.go
// fan-out consume.
type CreateSpineResult struct {
	// Launch is the gate's outcome: the IdP-backed launching principal and the
	// resolved launching_user value (the proof the authenticated launch feeds the
	// mint shape — doc 16 §3.1/§11.2).
	Launch LaunchOutcome
	// PinnedRole is the steps-1–2 pin (doc 18 §7): the immutable
	// (name, version, content_hash) the never-recycled session record carries, plus
	// the inert-widening posture. Its Ref() is what step 5 stamped and what the
	// childsession.go fan-out carries as ChildSessionDerivation.RoleRef.
	PinnedRole PinnedRole
	// MintClaims is the assembled step-5 output (createstep5.go): the launching-user
	// claims (gate-sourced) plus the pinned role_ref carried onto the mint request.
	MintClaims CreateStep5Result
	// DigestPublish is the §6.1 DIGEST-PUBLISH step outcome (mint-before-attach ack,
	// D73). Its Routable bit is the single signal the downstream mark-routable gate
	// turns on: true ONLY on an armed, committed publish. The ZERO value
	// (Routable=false) is the disarmed / not-reached path (the flag-off default), so a
	// spine result that never ran the step reads as "no digest ack recorded" — exactly
	// as before this field existed. On any armed fail-closed case the spine returns an
	// ERROR (not this result), so a session is never marked routable off a false ack.
	DigestPublish DigestPublishOutcome
}

// RunCreateSpine drives the doc 15 §4.1 steps-1–2 + step-5 create cluster in the
// frozen order, with each stage's data flowing to the next:
//
//	(1) AUTHORIZE LAUNCH (doc 16 §11.2) — gate.AuthorizeLaunch BEFORE any mint. An
//	    unauthenticated launch (req.Auth == nil) is REFUSED fail-closed
//	    (ErrLaunchRefused, the spine sentinel the adapter wraps auth.ErrAuth as);
//	    NO role is resolved and NO mint is assembled — the refusal is attributable
//	    and nothing mint-side happens. An authenticated launch writes the session→
//	    principal link the step-5 resolver then reads.
//	(2) RESOLVE + PIN role_ref (doc 18 §6 steps 1–2) — ResolveAndPinRole. Unknown/
//	    schema-invalid/unresolvable = structural refusal (ErrRoleRefRefused);
//	    unratified widenings ride inert + logged warning (NOT a refusal); absent =
//	    `default@<current>` recorded explicitly.
//	(5) ASSEMBLE step-5 mint claims (doc 15 §4.1 step 5) — AssembleStep5MintRequest
//	    over the SAME resolver, stamping the pinned role_ref onto the request. The
//	    resolver now sees the gate's link (step 1 ran first), so the launching_user
//	    claim is the IdP-backed subject, not a placeholder.
//	(6) DIGEST-PUBLISH (doc 16 §6.1 mint-before-attach, D73) — FLAG-GATED
//	    (DS_ORCH_DIGEST_PUBLISH_WIRE), the step BETWEEN cred-mint and mark-routable:
//	    push the session's secret digests to the boundary and gate routability on the
//	    host-agent ack. Default OFF the step is skipped (byte-identical). ARMED, a nil
//	    publisher / publish error / uncommitted ack fails the create fail-closed so the
//	    session is never marked routable (digestpublish.go).
//
// The resolver seam is consulted by BOTH the gate (write) and step 5 (read) — they
// must be the SAME backing store for the ordering to hold; the caller injects one
// store value that satisfies both seams (the real *store.Memory / *store.Postgres
// does, and the gate's linker is that same value). pinWriter PERSISTS the steps-1–2
// pin onto the never-recycled session record (migration 0009, doc 18 §7/§11); it
// MAY be nil (the spine then runs without persisting — the in-package pin still
// rides on the result, the pre-unfreeze behavior). When non-nil it is the SAME
// store value (UpdateSession), so the pin lands on the row the gate just linked.
// logger carries the widening-gate warning (nil → slog.Default).
//
// SINGLE-STORE COHERENCE (storeseams.go) — the "same backing store" requirement
// above is no longer convention-only. Wire the three store-backed seams (gate
// linker, resolver, pinWriter) through StoreSeams, which hands them out from ONE
// store value, and the spine's assertStoreCoherence REFUSES fail-closed
// (ErrStoreIncoherent) before any store work if the tagged seams do not name the
// same store — so a split-store wiring can never silently nullify the
// launching_user or land the pin on an unlinked row. Untagged seams (bare test
// fakes, pre-accessor callers) opt out, preserving the prior behavior.
func RunCreateSpine(
	ctx context.Context,
	gate launchGate,
	roleResolver RoleResolver,
	mintResolver launchingUserResolver,
	pinWriter rolePinWriter,
	req CreateSpineRequest,
	logger *slog.Logger,
) (CreateSpineResult, error) {
	if gate == nil {
		return CreateSpineResult{}, fmt.Errorf("sessions: RunCreateSpine: no launch gate configured")
	}
	if req.SessionUUID == "" {
		return CreateSpineResult{}, fmt.Errorf("sessions: RunCreateSpine: empty session UUID")
	}

	// (0) ENFORCE SINGLE-STORE COHERENCE — the ordering invariant below (gate
	// writes the link in step 1; step 5 reads it; the pin lands on that row) holds
	// ONLY if the gate linker, the launching_user resolver, and the pin writer all
	// hit the SAME backing store. For seams stamped with a store-identity tag (the
	// StoreSeams accessor's, see storeseams.go), refuse fail-closed BEFORE any
	// store work if they do not name one store — turning the doc-comment convention
	// into an enforced invariant. Untagged seams opt out (the convention governs).
	if err := assertStoreCoherence(gate, mintResolver, pinWriter); err != nil {
		return CreateSpineResult{}, fmt.Errorf("sessions: create spine: %w", err)
	}

	// (1) AUTHORIZE LAUNCH — doc 16 §11.2, BEFORE minting. A nil req.Auth is the
	// unauthenticated launch the gate refuses (ErrAuth); the spine surfaces it
	// WITHOUT resolving a role or assembling a mint, so no mint-side work happens on
	// a refused launch and the refusal is attributable to the missing IdP auth. The
	// gate writes the session→principal link here, BEFORE step 5 reads it below.
	launch, err := gate.AuthorizeLaunch(ctx, req.SessionUUID, req.Auth)
	if err != nil {
		// Fail-closed and attributable: an unauthenticated launch (ErrLaunchRefused)
		// never reaches role resolution or mint assembly. Surfaced verbatim (already
		// wrapped by the gate adapter — refusal vs store-fault preserved).
		return CreateSpineResult{}, fmt.Errorf("sessions: create spine: authorize launch for session %s: %w", req.SessionUUID, err)
	}

	// (2) RESOLVE + PIN role_ref — doc 18 §6 steps 1–2. A bad ref refuses fail-closed
	// (ErrRoleRefRefused); unratified widenings ride inert + a logged warning here.
	pin, err := ResolveAndPinRole(ctx, roleResolver, req.RoleRef, logger)
	if err != nil {
		return CreateSpineResult{}, fmt.Errorf("sessions: create spine: resolve+pin role for session %s: %w", req.SessionUUID, err)
	}

	// (2b) PERSIST the pin onto the never-recycled session record (migration 0009,
	// doc 18 §7/§11). The triple now lives on the D66 row — the §11 pin-and-audit
	// row's "every session record carries role fields" actually holds, and a catalog
	// update mid-flight does not change this pinned session (the pin was taken once,
	// here). A nil writer skips persistence (the in-package pin still rides the
	// result); a write fault is surfaced (the §4.1 rollback note covers it) so the
	// create driver never proceeds past a half-written pin.
	if pinWriter != nil {
		persisted, err := pinWriter.UpdateSession(ctx, req.SessionUUID, store.SessionUpdate{
			RolePin: pinPtr(pinToStore(pin)),
		})
		if err != nil {
			return CreateSpineResult{}, fmt.Errorf("sessions: create spine: persist role pin for session %s: %w", req.SessionUUID, err)
		}

		// (2c) FLAG-GATED D57 CREATE-SIDE METERING (metering-wire) — arm the landed
		// create-side MeteringWire on the LIVE create path: emit one idempotent §3
		// state-entry metering event for the session record the pin write just
		// returned (its current §3 state at the steps-1–2 boundary). Default OFF
		// (DS_ORCH_METERING_WIRE unset) this is a no-op BEFORE any store touch, so the
		// create path stays byte-for-byte unchanged; ON, a live create metabolizes a
		// D57 transition into the metering stream. The emit reuses the pin writer as
		// the metering sink (both *store.Memory and *store.Postgres satisfy the narrow
		// AppendMeteringEvent seam), so the transition lands on the SAME store the pin
		// just wrote — no new dependency threaded through RunCreateSpine's signature
		// (keeping the create RPC + re-drive callers unchanged). A metering fault is
		// LOGGED, never fatal: billing is additive + idempotent (the metering EventID
		// is deterministic, so a re-drive re-emits), and a create must not fail because
		// a billing append hiccuped.
		emitCreateTransition(ctx, pinWriter, persisted, logger)
	}

	// (5) ASSEMBLE step-5 mint claims — doc 15 §4.1 step 5. The resolver now sees the
	// gate's link (step 1 wrote it), so the launching_user claim is the IdP-backed
	// subject. The PINNED role_ref (pin.Ref()) is stamped onto the request — the
	// pin survives to the step-5 claims (the acceptance's "pinned role survives to
	// step-5 claims").
	claims, err := AssembleStep5MintRequest(ctx, mintResolver, CreateStep5Request{
		SessionUUID: req.SessionUUID,
		RoleRef:     pin.Ref(),
	})
	if err != nil {
		// A step-5 resolver fault (unknown session / dangling link) is surfaced so the
		// §4.1 rollback note can drive identity/CA revocation. Not reachable on a clean
		// authenticated launch (the gate just wrote the link), but surfaced honestly.
		return CreateSpineResult{}, fmt.Errorf("sessions: create spine: assemble step-5 mint for session %s: %w", req.SessionUUID, err)
	}

	// (6) DIGEST-PUBLISH — doc 16 §6.1 mint-before-attach, BETWEEN cred-mint (step 5,
	// just above) and mark-routable (downstream: the coordinator flips READY off this
	// result). Push the session's secret digests to the boundary and gate routability
	// on the host-agent ack (D73/D84). FLAG-GATED (DS_ORCH_DIGEST_PUBLISH_WIRE), default
	// OFF: disarmed, this SKIPS the step and returns the zero outcome, so the spine is
	// byte-identical to the pre-wire behavior (D50). ARMED, it fails the create closed
	// on a nil publisher, a publish/transport error, or an uncommitted ack — the session
	// is NEVER marked routable when its digests did not land (the security-load-bearing
	// gate this file wires). The publish is the last thing the spine does, so any
	// fail-closed error here provably prevents the caller's mark-routable.
	digestOut, err := runCreateDigestPublish(ctx, req.DigestPublisher, req.SessionUUID)
	if err != nil {
		return CreateSpineResult{}, fmt.Errorf("sessions: create spine: publish session digests for session %s: %w", req.SessionUUID, err)
	}

	return CreateSpineResult{
		Launch:        launch,
		PinnedRole:    pin,
		MintClaims:    claims,
		DigestPublish: digestOut,
	}, nil
}

// emitCreateTransition is the FLAG-GATED create-side metering call-site (metering-wire):
// it arms the landed create-side MeteringWire on the live create path, appending one
// idempotent D57 §3 state-entry event for the just-persisted session record. It is the
// insertion the metering bridge (meteringwire.go) was staged for but nothing on the
// production spine called — RunCreateSpine now calls it after the steps-1–2 pin write.
//
// DEFAULT OFF, BYTE-IDENTICAL (D50). When DS_ORCH_METERING_WIRE is unset (the wave
// default) this returns BEFORE any store touch, so the create path is unchanged and no
// metering row is ever appended. It arms only when the flag is set AND the pin writer
// also satisfies the narrow metering.Sink seam (AppendMeteringEvent) — both *store.Memory
// and *store.Postgres do, so the transition lands on the SAME store that just persisted
// the pin. A pin writer with no metering sink (a bare test fake) stays inert.
//
// A metering append fault is LOGGED and swallowed, never surfaced: the metering stream is
// idempotent on a deterministic EventID (a §3 re-drive re-emits the same logical
// transition as a no-op success at the store), so a transient append hiccup must not fail
// an otherwise-good create. occurredAt is stamped time.Now().UTC() at the call site (the
// create-spine has no injected clock); the deterministic EventID keys on it, so a re-drive
// at a different instant is a distinct-but-harmless additional transition row, while an
// exact re-drive collapses.
func emitCreateTransition(ctx context.Context, pinWriter rolePinWriter, rec store.Session, logger *slog.Logger) {
	if !MeteringWireEnabled() {
		return
	}
	sink, ok := pinWriter.(metering.Sink)
	if !ok {
		return
	}
	if err := NewMeteringWire(sink, true).EmitSessionEntry(ctx, rec, time.Now().UTC()); err != nil {
		if logger == nil {
			logger = slog.Default()
		}
		logger.WarnContext(ctx, "sessions: create spine: D57 metering emit failed (continuing; the metering stream is idempotent — a re-drive re-emits)",
			slog.String("session", rec.Ref.SessionUUID), slog.String("state", string(rec.State)), slog.Any("err", err))
	}
}

// ErrRedriveNoLaunchingUser is the re-drive's local sentinel for the NULLABLE /
// system-session case (doc 16 §3.1): the record being re-driven has NO linked
// launching principal (a pre-mint / system session). The user-launch gate
// (RunCreateSpine's step 1) refuses an unauthenticated launch fail-closed, so the
// re-drive entrypoint CANNOT honestly re-assert such a record through the
// user-launch spine — it would have to fabricate a subject, which §3.1 forbids.
// RedriveSpine surfaces this sentinel so the reconciler classifies it (and falls
// to the §3 rule-b fail-to-DESTROYED-with-audit arm) rather than minting a
// placeholder identity. A genuine user session always has a link (the create-time
// gate wrote it), so this is only reached for a record that never authenticated.
var ErrRedriveNoLaunchingUser = errors.New("sessions: re-drive: session has no linked launching principal (pre-mint/system session — cannot re-assert through the user-launch spine)")

// ErrIsRedriveNoLaunchingUser reports whether err is the re-drive nullable/
// system-session sentinel (ErrRedriveNoLaunchingUser) — exposed so the reconciler
// can distinguish "this record cannot be honestly re-asserted through the spine"
// (take the fail-to-DESTROYED-with-audit arm) from a transient resolver/store
// fault (retry next tick).
func ErrIsRedriveNoLaunchingUser(err error) bool { return errors.Is(err, ErrRedriveNoLaunchingUser) }

// RedriveSpine is the §3 rule-b/rule-c RE-DRIVE entrypoint into the SAME create
// spine the CreateSession RPC runs (RunCreateSpine) — the bridge that lets the
// reconciler RE-ASSERT a record's desired state WITHOUT re-implementing the create
// choreography. It is the convergence-loop closer: when the level-triggered
// reconciler finds a host-resident record whose VM is missing (rule b) or a VM
// that slipped back (rule c), it hands the persisted record here, and this
// re-runs the launch-gate → role-pin → step-5-mint cluster against the record's
// OWN persisted attribution. Both the create RPC and the reconciler re-drive thus
// flow through ONE spine (the task's "the Redriver calls the SAME RunCreateSpine,
// not a copy").
//
// RE-ASSERT FROM THE PERSISTED RECORD (never a fabricated launch). A re-drive
// re-asserts an ALREADY-CREATED session: its launching principal is already linked
// (the create-time gate wrote it) and its role is already pinned on the record. So
// RedriveSpine reconstructs the CreateSpineRequest from the record itself —
//
//   - Auth: rebuilt from the PERSISTED launching-user link (resolved via the
//     mintResolver). The gate re-link is IDEMPOTENT (it upserts the same principal
//     and re-writes the same session→principal link), so the IdP-backed subject the
//     record already carries flows back through the spine — never a self-declared
//     one (doc 16 §3.1: IdP-asserted or absent, never fabricated). A record with NO
//     link (the nullable / system-session case) cannot be honestly re-asserted
//     through the USER-launch gate — RedriveSpine returns ErrRedriveNoLaunchingUser
//     so the reconciler takes the §3 rule-b fail-to-DESTROYED-with-audit arm rather
//     than minting a placeholder.
//   - RoleRef: the record's PINNED role (rec.RolePin.Ref()), so the re-driven
//     session re-asserts the SAME pinned role (doc 18 §7: the pin is taken once, at
//     create; a re-drive does not re-pick it). An empty pin (a pre-pin record)
//     resolves the recorded default exactly as a fresh create does.
//
// The seam set is IDENTICAL to RunCreateSpine's (the create RPC and the re-drive
// share it by construction); the pinWriter MAY be nil (the re-drive re-asserts the
// already-persisted pin — re-persisting it is a harmless idempotent write, and a
// nil writer skips it). logger carries the widening-gate warning (nil →
// slog.Default).
//
// The returned CreateSpineResult is the re-asserted cluster output (the re-driven
// session's launch outcome + pinned role + step-5 mint claims) — the DATA the
// reconciler's concrete Redriver hands onward to the host-side re-create steps
// (the full ten-step coordinator drives those; the spine closes the steps-1–2 +
// step-5 cluster, which is the part that must NOT be re-implemented by the
// reconciler). A spine error (launch/role refusal, resolver/store fault) is
// surfaced verbatim so the reconciler classifies it.
func RedriveSpine(
	ctx context.Context,
	gate launchGate,
	roleResolver RoleResolver,
	mintResolver launchingUserResolver,
	pinWriter rolePinWriter,
	rec store.Session,
	logger *slog.Logger,
) (CreateSpineResult, error) {
	sessionUUID := rec.Ref.SessionUUID
	if sessionUUID == "" {
		return CreateSpineResult{}, fmt.Errorf("sessions: RedriveSpine: record has empty session UUID")
	}
	if mintResolver == nil {
		return CreateSpineResult{}, fmt.Errorf("sessions: RedriveSpine: no launching_user resolver configured")
	}

	// Rebuild the launch input from the PERSISTED link (never fabricated). The
	// mintResolver reads the session→principal link the create-time gate wrote; its
	// resolved claim is the IdP-backed subject we re-authorize the launch against.
	claim, ok, err := mintResolver.ResolveLaunchingUserClaim(ctx, sessionUUID)
	if err != nil {
		// An unknown session / dangling link — a store fault, surfaced so the
		// reconciler retries (not the nullable case, which is ok==false with no error).
		return CreateSpineResult{}, fmt.Errorf("sessions: re-drive: resolve persisted launching_user for session %s: %w", sessionUUID, err)
	}
	if !ok {
		// NULLABLE / system session: no linked principal. The user-launch gate would
		// refuse this fail-closed; re-asserting it through the spine would require a
		// fabricated subject (§3.1 forbids). Surface the classified sentinel so the
		// reconciler takes the fail-to-DESTROYED-with-audit arm.
		return CreateSpineResult{}, fmt.Errorf("%w (session %s)", ErrRedriveNoLaunchingUser, sessionUUID)
	}

	// The persisted subject/org rebuild the LaunchInput; the gate re-link is
	// idempotent (same principal, same session→principal link). Roles drive only the
	// principal upsert's group→role mapping, which already ran at create — the
	// re-link does not depend on them, so an empty Roles re-asserts the SAME linked
	// principal without inventing an authorization it never had.
	auth := &LaunchInput{
		Org:     claim.Org,
		Subject: claim.Subject,
	}

	return RunCreateSpine(ctx, gate, roleResolver, mintResolver, pinWriter, CreateSpineRequest{
		SessionUUID: sessionUUID,
		Auth:        auth,
		RoleRef:     rec.RolePin.Ref(),
	}, logger)
}

// ChildDerivationFromPin builds the per-child fan-out narrowing (childsession.go's
// ChildSessionDerivation) for one child VM, INHERITING the parent's pinned role as
// DATA (doc 19 §4: "the launching user is inherited unchanged"; doc 18 §6: the role
// is pinned and flows to the fan-out). The child carries the parent's pinned
// role_ref UNLESS an explicit per-child override narrows to a different recorded
// role — the role flows as data through the fan-out, never re-resolved here (the
// mint-side template seam, doc 19 §11, keys on the carried ref). It is the bridge
// the spine hands to CreateChildSession so children inherit the parent's pinned role.
//
// childSessionUUID is the child VM's session; explicitRoleRef (empty = inherit) is an
// optional per-child role the fan-out chose; services/ttl/taskRef are the other
// fan-out narrowing axes (carried verbatim, see childsession.go).
func ChildDerivationFromPin(parent PinnedRole, childSessionUUID, explicitRoleRef string, services []string, ttl time.Duration, taskRef string) ChildSessionDerivation {
	roleRef := parent.Ref()
	if explicitRoleRef != "" {
		// A per-child override: the child runs under a different recorded role the
		// fan-out chose. The mint-side template seam (doc 19 §11) folds that role's
		// default narrowing; this leg only carries the ref, never resolves it.
		roleRef = explicitRoleRef
	}
	return ChildSessionDerivation{
		ChildSessionUUID: childSessionUUID,
		Services:         services,
		TTL:              ttl,
		TaskRef:          taskRef,
		RoleRef:          roleRef,
	}
}

// ErrIsRoleRefused reports whether err is the steps-1–2 structural role refusal
// (ErrRoleRefRefused) — exposed so a create driver can distinguish a refused role
// (attributable, the requester's bad ref) from a resolver fault (a transient stall).
// It is the role-axis analog of ErrIsLaunchRefused for the launch gate.
func ErrIsRoleRefused(err error) bool { return errors.Is(err, ErrRoleRefRefused) }

// ErrIsLaunchRefused reports whether err is the launch-gate refusal
// (ErrLaunchRefused — the spine's local sentinel the gate adapter wraps auth.ErrAuth
// as) — exposed so a create driver can distinguish an unauthenticated launch
// (attributable) from a store/catalog fault. Paired with ErrIsRoleRefused, these are
// the two fail-closed, attributable refusals the steps-1–2 cluster surfaces.
func ErrIsLaunchRefused(err error) bool { return errors.Is(err, ErrLaunchRefused) }
