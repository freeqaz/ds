// SPDX-License-Identifier: Apache-2.0

package grantfetchconform

import (
	"context"
	"time"

	grantservice "github.com/dream-serpent/dream-serpent/identity/grant-service"

	// attachv1 is consumed READ-ONLY for the §5.4 SUSPENDED(reason) cause (D35/D77):
	// the frozen attach.v1 SuspendReason the real Service records on a reasoned
	// suspend, exposed here so the central dual-run can drive it and read it back.
	// Projection only — no re-declare, no new enum (D80: proto/gen/go the only legal
	// cross-tree import).
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Grant is one synthetic stored grant the real grant-service Backend returns for a
// session×service binding: the real (synthetic) swap-class credential the swap
// executor substitutes, the non-secret delivery location, and the grant's TTL
// ceiling. It maps onto the in-process grantservice.Credential plus the cache
// expiry the Service clamps against. Synthetic only (D50).
type Grant struct {
	Secret   []byte
	Location string
	// Expiry is the grant TTL as wall-clock UNIX seconds (0 = no grant-side TTL,
	// the request horizon / session deadline then governs). The conform clock is
	// pinned to the suite's fixed "now" so the cache clamp is deterministic.
	Expiry int64
}

// FleetSpec describes the synthetic fleet the real grant-service Service should
// reproduce so the central dual-run can dial it instead of an honest in-test
// responder. It is fixture-shaped, not a copy of any production state — the
// suite owns the synthetic constants and hands them in here, so the adapter stays
// generic and the fixtures live in one place (D50).
type FleetSpec struct {
	// LiveSessions are the sessions the Service RegisterSessions (own-session §5.4
	// liveness): session_uuid -> service_id -> stored Grant. A session NOT in this
	// map is never registered, so a fetch against it fails closed as
	// SESSION_NOT_LIVE — the revoked/unknown fixture.
	LiveSessions map[string]map[string]Grant

	// StoreDownRefs are grant_refs whose Backend.Fetch must return
	// ErrStoreUnavailable — the per-session §5.1 key-store outage. The real Service
	// classifies a cache-miss store-unavailable as the retryable STORE_UNAVAILABLE
	// stall (distinct from a definitive deny), exactly as service.go does. A ref
	// here still needs its stored Grant present in LiveSessions (the binding is
	// good; only the store read stalls).
	StoreDownRefs map[string]bool

	// NowUnix pins the Service clock (UNIX seconds) so TTL/expiry clamping is
	// deterministic across the real and fake dual-run ends.
	NowUnix int64

	// SessionDeadlineUnix is the session-lifetime ceiling (UNIX seconds) used when
	// registering each live session (the cache ceiling, ≤ session, §5.1). It must
	// be far enough in the future that the suite's far-future grant TTLs are not
	// clamped down by it. 0 leaves the deadline zero (no ceiling).
	SessionDeadlineUnix int64
}

// clock returns the pinned conform clock as a func() time.Time.
func (s FleetSpec) clock() func() time.Time {
	now := unixToTime(s.NowUnix)
	if now.IsZero() {
		now = time.Now()
	}
	return func() time.Time { return now }
}

// unixToTime maps UNIX seconds onto a time.Time, mapping a zero/negative value to
// the zero time (the house ca_mint/grants/validate convention, mirrored from
// grant-service/wire.go so the adapter agrees with the served path field-for-field).
func unixToTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// refStallBackend is the synthetic grant-service Backend the static real end runs
// over (D50). It is keyed by grant_ref (which encodes session×service), so it
// reproduces the responder's PER-SESSION store-outage shape — some refs stall
// while others succeed in the SAME suite run — through the REAL Service's
// fetch/cache/deny logic. It is never a live store: it returns the synthetic
// credential for a known ref, ErrStoreUnavailable for a ref marked store-down (the
// §5.1 transient outage stall), and ErrGrantNotFound for any unknown ref (the
// definitive deny). This is exactly the D39 Backend seam the Service is designed
// for; the per-ref bit just lets one Service exhibit both an OK fetch and a stall.
type refStallBackend struct {
	creds     map[string]grantservice.Credential
	storeDown map[string]bool
}

// Fetch implements grantservice.Backend: a store-down ref stalls
// (ErrStoreUnavailable, retryable), an unknown ref is a definitive deny
// (ErrGrantNotFound), and a known ref returns the synthetic credential.
func (b *refStallBackend) Fetch(grantRef string) (grantservice.Credential, error) {
	if b.storeDown[grantRef] {
		return grantservice.Credential{}, grantservice.ErrStoreUnavailable
	}
	cred, ok := b.creds[grantRef]
	if !ok {
		return grantservice.Credential{}, grantservice.ErrGrantNotFound
	}
	// Defensive copy so a caller can never mutate the fixture's secret.
	return grantservice.Credential{
		Secret:   append([]byte(nil), cred.Secret...),
		Location: cred.Location,
	}, nil
}

// credsFromSpec flattens the spec's LiveSessions into the grant_ref -> Credential
// map the Backend keys on (grant_ref = FormatGrantRef(session, service)).
func credsFromSpec(spec FleetSpec) map[string]grantservice.Credential {
	creds := map[string]grantservice.Credential{}
	for session, services := range spec.LiveSessions {
		for service, g := range services {
			creds[grantservice.FormatGrantRef(session, service)] = grantservice.Credential{
				Secret:   append([]byte(nil), g.Secret...),
				Location: g.Location,
			}
		}
	}
	return creds
}

// newService builds a real grantservice.Service over the given Backend, with the
// pinned clock, and registers every live session in the spec at the spec's
// session-lifetime deadline (the §5.1 cache ceiling). The returned Service is the
// genuine implementation — RegisterSession/Fetch/cache/liveness all run for real.
func (s FleetSpec) newService(backend grantservice.Backend) *grantservice.Service {
	svc := grantservice.New(backend, grantservice.WithClock(s.clock()))
	deadline := unixToTime(s.SessionDeadlineUnix)
	for session := range s.LiveSessions {
		svc.RegisterSession(session, deadline)
	}
	return svc
}

// register is the generated RegisterGrantFetchServiceServer call bound to the REAL
// Server adapter (grant-service/server.go) — the exact registration the
// ds-tlsproxy swap executor's served path uses. The caller hands the returned
// func to a dual-run in-process bufconn dialer (dualrun.InProcess), so the only
// thing that varies between the real and fake dual-run ends is whether this real
// Server or the generated fake is registered.
func register(svc *grantservice.Service) func(grpc.ServiceRegistrar) {
	return func(reg grpc.ServiceRegistrar) {
		identityv1.RegisterGrantFetchServiceServer(reg, grantservice.NewServer(svc))
	}
}

// RegisterStaticReal builds the REAL grant-service Server over a per-ref synthetic
// Backend (refStallBackend) and returns the gRPC registration func to stand it up
// on an in-process bufconn. This is the "real" end of the central STATIC GrantFetch
// dual-run: an OK fetch, the request-horizon TTL clamp, the three fail-closed
// denies (GRANT_NOT_FOUND, SESSION_NOT_LIVE, GRANT_REF_MISMATCH), and the §5.1
// STORE_UNAVAILABLE stall all flow through the actual Service + Server, classified
// by the real wire.go reason mapping. The Backend is keyed by grant_ref so a
// single Service exhibits both a successful fetch and a per-session store-outage
// stall in the same suite run.
func RegisterStaticReal(spec FleetSpec) func(grpc.ServiceRegistrar) {
	backend := &refStallBackend{creds: credsFromSpec(spec), storeDown: spec.StoreDownRefs}
	return register(spec.newService(backend))
}

// WarmCacheRealEnd is the REAL grant-service Server stood up for the §5.1
// cache-rides-outage dual-run AND the §5.4 suspend/park/resume grant-eviction
// lifecycle: its store availability can be flipped DOWN mid-run to model the
// outage onset (after which a warm cached session rides while a cold never-warmed
// session's NEW fetch stalls), and individual sessions can be SUSPENDED (evicted
// -> SESSION_NOT_LIVE), PARKED (cache kept, NEW fetch refused -> SESSION_PARKED),
// or RESUMED (re-validated against liveness + TTL). It wraps the production
// FileKVBackend (the actual §5.1 outage lever, SetAvailable) AND retains the
// genuine grantservice.Service handle (the §5.4 lifecycle lever) rather than the
// per-ref stall backend, because the warm-cache + lifecycle contracts ARE the
// global-store flip and the session-state transitions on the real Service.
// Register is the gRPC registration func; SetStoreAvailable is the §5.1 outage
// lever; Suspend/Park/Resume are the §5.4 lifecycle levers — all drive the SAME
// genuine Service that Register stood up, so the central dual-run observes the
// real Service's own classification, not a re-implemented stand-in.
type WarmCacheRealEnd struct {
	// Register stands the real Server up on the dual-run's in-process bufconn.
	Register func(grpc.ServiceRegistrar)
	backend  *grantservice.FileKVBackend
	// svc is the genuine grant-service Service the Register func stood up — the
	// SAME instance the dual-run dials. Retaining it lets the suite drive the §5.4
	// Suspend/Park/Resume transitions on the real Service's own session state
	// (mirroring how SetStoreAvailable drives the real backend's availability), so
	// a real-impl drift in the eviction/park/resume mapping fails the central seam.
	svc *grantservice.Service
	// deadline is the spec's session-lifetime ceiling (the §5.1 cache ceiling each
	// session was registered at). Resume defaults to keeping it (passes it through)
	// so the resumed session retains its lifetime unless the caller overrides.
	deadline time.Time
}

// SetStoreAvailable flips the real Service's backing store up/down — the §5.1
// outage lever the warm-cache suite drives at outage onset. After down(), a warm
// (cached) session rides the outage from cache (no store read) while a cold
// session's NEW fetch stalls with STORE_UNAVAILABLE.
func (e *WarmCacheRealEnd) SetStoreAvailable(up bool) { e.backend.SetAvailable(up) }

// Suspend EVICTS the session on the genuine Service (§5.4): the real
// Service.Suspend drops the whole session cache entry, so a subsequent fetch
// fails closed SESSION_NOT_LIVE through the real wire.go mapping. This is the
// active-eviction half of "TTL-as-revocation plus active eviction" (§5.4),
// driven on the SAME Service the dual-run dials — so a real impl that fails to
// evict (still serves the warmed grant after suspend) diverges at the central
// seam.
func (e *WarmCacheRealEnd) Suspend(session string) { e.svc.Suspend(session) }

// SuspendWithReason EVICTS the session on the genuine Service (§5.4) AND records
// the frozen attach.v1 SUSPENDED(reason) cause (D35/D77) that drove it — the
// reasoned form of Suspend, driven on the SAME Service the dual-run dials. Eviction
// behavior is UNCHANGED (a subsequent fetch fails closed SESSION_NOT_LIVE through
// the real wire.go mapping); only the CAUSE is now recorded and read-back-able via
// LastSuspendReason. This is an ADDITIVE affordance beside the existing Suspend
// lever (unchanged): it lets the central dual-run drive a USER vs POLICY_BREACH
// eviction on the REAL Service and observe the recorded cause, so a real impl that
// dropped or mis-recorded the cause diverges at the seam. The reason is a NON-SECRET
// classification (doc 16 §5.2), projected read-only from the frozen enum.
func (e *WarmCacheRealEnd) SuspendWithReason(session string, reason attachv1.SuspendReason) {
	e.svc.SuspendWithReason(session, reason)
}

// LastSuspendReason reads the frozen attach.v1 SUSPENDED(reason) cause the genuine
// Service recorded for the session's most recent suspend (§5.4; D35/D77), read-only,
// and whether such a record exists. It reads the SAME Service the dual-run dials, so
// the recorded eviction cause the suite drove via SuspendWithReason is observable at
// the central seam AFTER the grants are evicted — the read-back the §8.2
// resume-authority split relies on. The returned reason is a NON-SECRET
// classification (doc 16 §5.2), never credential material.
func (e *WarmCacheRealEnd) LastSuspendReason(session string) (attachv1.SuspendReason, bool) {
	return e.svc.LastSuspendReason(session)
}

// Park marks the session parked on the genuine Service (§5.4): the real
// Service.Park keeps the session cache (a warmed pair still rides) but refuses a
// NEW (cache-miss) fetch with SESSION_PARKED until Resume. Driven on the SAME
// Service the dual-run dials, so a real impl that lets a parked session fetch a
// NEW grant diverges at the central seam.
func (e *WarmCacheRealEnd) Park(session string) { e.svc.Park(session) }

// Resume re-validates a parked session against liveness + TTLs on the genuine
// Service and returns it to LIVE (§5.4): the real Service.Resume clears the
// parked bit, drops any cached grant past its own TTL (expired creds re-mint),
// and fails closed (ErrSessionNotLive) for a session past its session-lifetime
// deadline (a dead session does not silently come back). deadlineUnix optionally
// extends the session-lifetime ceiling (UNIX seconds; <= 0 keeps the spec's
// registered deadline). It returns the real Service's error so the suite can pin
// the resume-of-a-dead-session fail-closed verdict. Driven on the SAME Service
// the dual-run dials, so a real impl that re-admits a dead session diverges at
// the central seam.
func (e *WarmCacheRealEnd) Resume(session string, deadlineUnix int64) error {
	newDeadline := unixToTime(deadlineUnix)
	if newDeadline.IsZero() {
		// Keep the spec's registered session-lifetime ceiling (the §5.1 cache
		// ceiling) rather than zeroing it: Service.Resume treats the zero time as
		// "keep the existing deadline", and the existing deadline IS this ceiling,
		// so passing it through is behavior-identical and explicit.
		newDeadline = e.deadline
	}
	return e.svc.Resume(session, newDeadline)
}

// ResumeWithApproval drives the §8.2 approval-gated resume surface on the genuine
// Service (doc 16 §8.2; D35): a session whose recorded last-suspend reason is the
// genuine-threat POLICY_BREACH resumes ONLY under an explicit human-approval
// attestation (approver != ""), and fails closed (ErrResumeApprovalRequired)
// without one; USER/REBALANCE/no-recorded-reason paths resume unchanged. The
// attestation is a NON-SECRET marker (§5.2), never a credential — approver plus an
// audit reference. deadlineUnix follows Resume (<= 0 keeps the spec's registered
// ceiling). It returns the real Service's error so the suite can pin the
// fail-closed-vs-proceeds verdict, driven on the SAME Service the dual-run dials —
// an ADDITIVE affordance beside Suspend/Park/Resume (existing levers untouched).
func (e *WarmCacheRealEnd) ResumeWithApproval(session string, deadlineUnix int64, approver, reference string) error {
	newDeadline := unixToTime(deadlineUnix)
	if newDeadline.IsZero() {
		newDeadline = e.deadline
	}
	return e.svc.ResumeWithApproval(session, newDeadline, grantservice.ResumeApproval{Approver: approver, Reference: reference})
}

// RegisterSession re-admits a session on the genuine Service at the spec's
// registered session-lifetime deadline (§5.1 cache ceiling). It is the affordance
// the §8.2 resume-authority walk needs: Suspend/SuspendWithReason EVICT the session
// (§5.4), so before a resume can act on it the session is re-admitted — the recorded
// last-suspend cause SURVIVES the eviction (LastSuspendReason), so the re-admitted
// session's plain-resume authority still keys on it. Driven on the SAME Service the
// dual-run dials — an ADDITIVE affordance (existing levers untouched).
func (e *WarmCacheRealEnd) RegisterSession(session string) {
	e.svc.RegisterSession(session, e.deadline)
}

// NewWarmCacheRealEnd builds the REAL grant-service Server over a production
// FileKVBackend (seeded in-memory with the spec's grants) and returns the
// WarmCacheRealEnd handle (a registration func + the SetStoreAvailable §5.1
// outage lever + the Suspend/Park/Resume §5.4 lifecycle levers). The store starts
// AVAILABLE; the suite warms an in-flight session, then flips it down via
// SetStoreAvailable, or drives the §5.4 transitions via Suspend/Park/Resume —
// all through the SAME genuine Service the returned Register func stands up, so
// the dual-run dials exactly the Service the levers mutate.
func NewWarmCacheRealEnd(spec FleetSpec) *WarmCacheRealEnd {
	backend := grantservice.NewInMemoryBackend(credsFromSpec(spec))
	svc := spec.newService(backend)
	return &WarmCacheRealEnd{
		Register: register(svc),
		backend:  backend,
		svc:      svc,
		deadline: unixToTime(spec.SessionDeadlineUnix),
	}
}

// RealServerFetchStatus drives ONE GrantFetchRequest against the REAL
// grant-service Server (built over spec, over the SAME per-ref synthetic Backend
// RegisterStaticReal stands up) through the genuine served Fetch handler
// (grantservice.Server.Fetch, grant-service/server.go) and returns the gRPC
// status CODE the served RPC yields, plus the response and the raw error. It is
// the adapter's MALFORMED-request probe for the central dual-run's transport-error
// arm: the caller hands a deliberately malformed request — nil, empty, a garbage
// grant_ref that cannot bind, or an unknown session — and reads back the TRANSPORT
// status verdict the real impl produces, distinct from the in-band
// GrantFetchReason the response carries.
//
// The verdict this affordance PINS is a fact about the frozen contract, not a
// contract widening: grant-service's server.go folds every documented deny/stall
// into GrantFetchResponse.reason IN-BAND and returns a nil error (open-question
// default #2; FetchWire tolerates even a nil request, mapping it to an all-zero
// request that fails closed in-band). So a contract-shaped request — however
// malformed its field VALUES — always yields codes.OK here. A non-OK code would
// mean the impl manufactured a transport status from a request payload, which the
// genuine Server never does: on this seam a gRPC status only ever comes from a
// real transport fault, never from the fetch-domain classification. A conformance
// test uses this to pin that invariant against the genuine Server surface, so a
// future real impl that STARTED classifying a malformed request as a transport
// status (rather than an in-band reason) would trip the pin at the central seam.
//
// SYNTHETIC only (D50): the Server runs over the in-process refStallBackend, no
// live network/store. No secret bytes are returned to the caller beyond the
// response the real Server itself produced (a malformed request carries no
// credential); the caller reads the status code, never a secret (doc 16 §5.2).
func RealServerFetchStatus(spec FleetSpec, req *identityv1.GrantFetchRequest) (codes.Code, *identityv1.GrantFetchResponse, error) {
	backend := &refStallBackend{creds: credsFromSpec(spec), storeDown: spec.StoreDownRefs}
	srv := grantservice.NewServer(spec.newService(backend))
	resp, err := srv.Fetch(context.Background(), req)
	return status.Code(err), resp, err
}
