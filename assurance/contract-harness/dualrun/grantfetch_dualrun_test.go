// SPDX-License-Identifier: Apache-2.0

package dualrun_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/conformance-adapter/grantfetchconform"
	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	// attachv1 is consumed READ-ONLY for the §3 SuspendReason projection (D77): the
	// §5.4 suspend signal that drives grant eviction carries a frozen attach.v1
	// SuspendReason. Projection only — no re-declare, no new enum (D80: proto/gen/go
	// is the only legal cross-tree import).
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
)

// grantfetch_dualrun_test registers the identity.v1 GrantFetchService
// credential-swap-fetch seam (doc 16 §5.1/§9, doc 06 §2.1) in the CENTRAL
// dualrun harness, alongside the Validate / Mint / digest-feed seams. The
// module-local wire_test.go in identity/grant-service dual-runs the same verb
// but is not visible to the cross-tree conformance suite; assurance/contract-
// harness/dualrun is the canonical home for fakes-first conformance — the suite
// runs against BOTH the real implementation and the generated programmable fake
// and is green only if every scenario observes the same thing on both (D24/D14).
//
// This unit is PROPOSE-ONLY for the seam: it does NOT touch identity/grant-
// service. The "real" end is an honest in-test responder that encodes the
// GrantFetch contract (the same shape service.go encodes), and the "fake" end is
// the generated identityv1fake.GrantFetchServiceFake; both are wired through the
// shared dualrun.InProcess bufconn dialer (bufconn.go) so the only thing that
// varies between the two passes is the registered server. Synthetic fixtures
// only (D50); imports proto/gen/go generated types only.

// Synthetic fixtures local to the test (D50) — obviously-synthetic, never a real
// session uuid, service id, credential, or grant ref.
const (
	gfTestNow = int64(1_700_000_000)

	gfSessionLive    = "ses-synthetic-grantfetch-live-aaaa0000"
	gfSessionRevoked = "ses-synthetic-grantfetch-revoked-bbbb1111"
	// gfSessionStoreDown is a LIVE session granted github, but whose key store is
	// in a transient outage: a NEW grant fetch against it stalls (STORE_UNAVAILABLE,
	// retryable) rather than denying — the doc 16 §5.1/§11.1-step4 outage contract.
	gfSessionStoreDown = "ses-synthetic-grantfetch-storedown-cccc2222"

	gfServiceGitHub    = "svc-synthetic-grantfetch-github"
	gfServiceUngranted = "svc-synthetic-grantfetch-ungranted"

	gfSecretGitHub   = "synthetic-grantfetch-secret-github-d34db33f"
	gfLocationHeader = "Authorization"

	gfExpiryFarFuture  = gfTestNow + 3600
	gfExpiryNearFuture = gfTestNow + 600
)

// gfGrantRef mirrors identity/grant-service/grantref.go's FormatGrantRef wire
// shape ("grant:<session>:<service>") without importing that propose-only module:
// the swap executor receives this opaque, secret-free handle from the Validate
// ALLOW and the fetch reader fail-closed rejects any ref that does not parse back
// to the requested (session, service) binding (GRANT_REF_MISMATCH).
func gfGrantRef(sessionUUID, serviceID string) string {
	return "grant:" + sessionUUID + ":" + serviceID
}

// gfGrant is one synthetic stored grant: the real credential the swap executor
// substitutes, its delivery class, and the authoritative grant-TTL ceiling.
type gfGrant struct {
	secret   string
	location string
	class    identityv1.CredentialClass
	expiry   int64
}

// gfSession is a synthetic session in the honest fleet: whether its session is
// live (doc 16 §5.4 liveness), whether its key store is in a transient outage
// (doc 16 §5.1 availability dependency — an outage stalls NEW grant fetches),
// and the grants it holds, keyed by service id.
type gfSession struct {
	live bool
	// storeDown models the §5.1 key-store outage: the session is live and the grant
	// is present, but a NEW fetch cannot reach the store, so it STALLS
	// (STORE_UNAVAILABLE, retryable) with an empty credential — distinct from a
	// definitive DENY, which fails closed. The outage gates only what would
	// otherwise be a successful store read; the fail-closed denies still deny.
	storeDown bool
	grants    map[string]gfGrant
}

// gfFleet is the synthetic stored-grant fleet both ends are driven over: a single
// live session granted github far-future, an own-session-dead session with no
// grants (the liveness-rejection fixture), and a live-but-store-down session
// granted github (the §5.1 transient-stall fixture — its NEW fetch stalls rather
// than denying). Kept identical for the real and fake ends so a divergence is
// attributable to the contract, not the fixture.
func gfFleet() map[string]gfSession {
	githubGrant := gfGrant{
		secret:   gfSecretGitHub,
		location: gfLocationHeader,
		class:    identityv1.CredentialClass_CREDENTIAL_CLASS_SWAP,
		expiry:   gfExpiryFarFuture,
	}
	return map[string]gfSession{
		gfSessionLive:    {live: true, grants: map[string]gfGrant{gfServiceGitHub: githubGrant}},
		gfSessionRevoked: {live: false},
		// Live session, github granted, but the key store is in a transient outage:
		// a NEW fetch STALLS (STORE_UNAVAILABLE) instead of returning the credential.
		gfSessionStoreDown: {live: true, storeDown: true, grants: map[string]gfGrant{gfServiceGitHub: githubGrant}},
	}
}

// honestGrantFetchResponder encodes the GrantFetchService contract (doc 16
// §5.1/§9) over the given fleet — the same decision shape service.go encodes,
// restated here so this unit need not import the propose-only grant-service
// module. On a clean fetch it returns OK with the real credential, the issued-
// service-id binding echoed back, and the grant-TTL clamped to the tighter of
// (request horizon, stored grant TTL); on each failure it returns the distinct
// in-band reason with an EMPTY credential (the executor fails closed on a deny,
// retries only a stall). It NEVER returns a zero-value success.
func honestGrantFetchResponder(fleet map[string]gfSession) func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
	return func(_ context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
		deny := func(r identityv1.GrantFetchReason) *identityv1.GrantFetchResponse {
			return &identityv1.GrantFetchResponse{Reason: r}
		}

		// Fail-closed grant_ref binding: the ref MUST parse back to exactly the
		// requested (session, service); any mismatch is GRANT_REF_MISMATCH and no
		// store lookup happens.
		if req.GetGrantRef() != gfGrantRef(req.GetSessionUuid(), req.GetServiceId()) {
			return deny(identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_REF_MISMATCH), nil
		}

		sess, known := fleet[req.GetSessionUuid()]
		if !known || !sess.live {
			// Own-session liveness: an unknown or revoked session is not live.
			return deny(identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE), nil
		}
		g, granted := sess.grants[req.GetServiceId()]
		if !granted {
			return deny(identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_NOT_FOUND), nil
		}

		// §5.1 availability dependency: the binding is good and the grant exists, but
		// the key store is in a transient outage, so this NEW fetch cannot read the
		// secret. It STALLS in-band (STORE_UNAVAILABLE, ReasonIsStall — retryable)
		// with an EMPTY credential, distinct from the fail-closed denies above: the
		// executor RETRIES a stall, never degrades to egressing the placeholder. The
		// outage gates only what would otherwise be a successful store read, so it is
		// checked AFTER the denies (a deny is still a definitive deny under outage).
		if sess.storeDown {
			return deny(identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE), nil
		}

		// Cache ceiling = the tighter of the request horizon and the stored grant
		// TTL (service.go expiry clamp). A non-positive request horizon means the
		// caller carried no ceiling, so the stored grant TTL governs.
		expiry := g.expiry
		if req.GetGrantExpiryUnixSeconds() > 0 && req.GetGrantExpiryUnixSeconds() < expiry {
			expiry = req.GetGrantExpiryUnixSeconds()
		}
		return &identityv1.GrantFetchResponse{
			Credential:             &identityv1.FetchedCredential{Secret: []byte(g.secret), Location: g.location},
			CredentialClass:        g.class,
			IssuedServiceId:        req.GetServiceId(),
			GrantExpiryUnixSeconds: expiry,
			Reason:                 identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK,
		}, nil
	}
}

// grantFetchEnd wires the given honest responder into the generated fake and
// returns a dualrun.Dialer that stands it up on the shared in-process bufconn.
// Both the "real" and "fake" dual-run ends are stood up this way — the generated
// fake IS the registration both passes share — so the dual-run proves the
// honest-responder contract and the generated fake's recorder/registration agree
// scenario-for-scenario. The transport, codec, and client are identical between
// passes (bufconn.go), so any divergence is attributable to the contract.
func grantFetchEnd(responder func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error)) dualrun.Dialer {
	dialer, _ := grantFetchEndWithFake(responder)
	return dialer
}

// grantFetchEndWithFake is grantFetchEnd that ALSO returns the generated fake it
// stood up, so a directed test can read the fake's call-capture surface
// (FetchRecorded) AFTER the dual run drove it — instead of re-driving a SECOND
// out-of-band fake just to inspect the recorder. The fake records every Fetch the
// dual run sends through this end; query it once the run returns.
func grantFetchEndWithFake(responder func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error)) (dualrun.Dialer, *identityv1fake.GrantFetchServiceFake) {
	f := identityv1fake.NewGrantFetchServiceFake()
	f.FetchResponder = responder
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		identityv1fake.RegisterGrantFetchService(s, f)
	}), f
}

// staticGfSpec translates the synthetic gfFleet() fixture into a
// grantfetchconform.FleetSpec so the central dual-run's "real" end dials the ACTUAL
// identity/grant-service Server (grantfetchconform.RegisterStaticReal) instead of
// the honest in-test responder. The real Service's own grant_ref-binding guard,
// liveness check, per-session cache, and §5.1 stall-vs-deny classification then run
// for the static suite — so a drifted real impl fails the CENTRAL seam, not just
// the module-local server_test.go pin. The mapping mirrors gfFleet() exactly:
//   - gfSessionLive is live and github-granted far-future;
//   - gfSessionRevoked is NOT a live session (omitted from LiveSessions), so the
//     real Service fails it closed as SESSION_NOT_LIVE;
//   - gfSessionStoreDown is live and github-granted, but its grant_ref is marked
//     store-down, so a NEW fetch against it stalls (STORE_UNAVAILABLE) while
//     gfSessionLive's fetch and the GRANT_NOT_FOUND deny still resolve — the
//     per-session §5.1 outage shape, driven through the per-ref synthetic Backend.
//
// The clock is pinned to gfTestNow and the session deadline is set beyond the
// far-future grant TTL so the deadline never clamps the suite's expiry echoes.
func staticGfSpec() grantfetchconform.FleetSpec {
	githubGrant := grantfetchconform.Grant{
		Secret:   []byte(gfSecretGitHub),
		Location: gfLocationHeader,
		Expiry:   gfExpiryFarFuture,
	}
	return grantfetchconform.FleetSpec{
		LiveSessions: map[string]map[string]grantfetchconform.Grant{
			gfSessionLive:      {gfServiceGitHub: githubGrant},
			gfSessionStoreDown: {gfServiceGitHub: githubGrant},
		},
		// gfSessionStoreDown's github grant_ref is in a transient §5.1 store outage:
		// a NEW fetch stalls (STORE_UNAVAILABLE), distinct from gfSessionLive's OK.
		StoreDownRefs: map[string]bool{
			gfGrantRef(gfSessionStoreDown, gfServiceGitHub): true,
		},
		NowUnix:             gfTestNow,
		SessionDeadlineUnix: gfExpiryFarFuture + 3600,
	}
}

// grantFetchStaticRealEnd stands up the REAL grant-service Server (over the static
// gfFleet spec) on the shared in-process bufconn — the "real" end of the central
// static dual-run. It is wired through the SAME dualrun.InProcess dialer the fake
// end uses, so the only thing that varies between the two passes is whether the
// real Server or the generated fake is registered, and any divergence is
// attributable to the contract.
func grantFetchStaticRealEnd() dualrun.Dialer {
	return dualrun.InProcess(grantfetchconform.RegisterStaticReal(staticGfSpec()))
}

// warmGfSpec translates the warm-cache fixture (gfSessionWarm + gfSessionColdMiss,
// both live and github-granted) into a grantfetchconform.FleetSpec for the §5.1
// cache-rides-outage dual-run. The store starts available; the real end's outage
// is driven by grantfetchconform's SetStoreAvailable (the production FileKVBackend
// flip), so the warm session warms its cache pre-outage and rides while the cold
// session stalls — the actual §5.1 global-store-outage contract.
func warmGfSpec() grantfetchconform.FleetSpec {
	githubGrant := grantfetchconform.Grant{
		Secret:   []byte(gfSecretGitHub),
		Location: gfLocationHeader,
		Expiry:   gfExpiryFarFuture,
	}
	return grantfetchconform.FleetSpec{
		LiveSessions: map[string]map[string]grantfetchconform.Grant{
			gfSessionWarm:     {gfServiceGitHub: githubGrant},
			gfSessionColdMiss: {gfServiceGitHub: githubGrant},
		},
		NowUnix:             gfTestNow,
		SessionDeadlineUnix: gfExpiryFarFuture + 3600,
	}
}

// reasonIsStall MIRRORS identity/grant-service wire.go ReasonIsStall — the doc 16
// §5.1 retry-only-a-stall split (the store is transiently unreachable, so the
// executor RETRIES rather than failing closed) — for the assurance trees. D80
// (proto/gen/go is the only legal cross-tree import) forbids this tree importing
// the grant-service module, so the split is MIRRORED here against the frozen enum
// rather than called in. This is the SINGLE place this suite derives the stall
// predicate: gfFetchObservation and gfAssertDirected both route through it, so the
// re-derivation is defined once. TestGrantFetchReason_StallClassificationIsExhaustive
// pins this mirror against the FULL generated enum, so a new retryable reason
// (a second stall) added to grant_fetch.proto trips CI in THIS tree — the mirror of
// the init() completeness panic wire.go carries in the identity tree, keeping the
// two halves in lockstep.
func reasonIsStall(r identityv1.GrantFetchReason) bool {
	return r == identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE
}

// TestGrantFetchReason_StallClassificationIsExhaustive is the assurance-tree half
// of the cross-tree single-source of the §5.1 stall predicate. Because D80 forbids
// this tree importing identity/grant-service, reasonIsStall above MIRRORS wire.go
// ReasonIsStall rather than calling it; this guard makes that mirror safe. It walks
// EVERY value the frozen GrantFetchReason enum declares (GrantFetchReason_name) and
// requires each to carry an explicit stall/non-stall verdict here, and cross-checks
// reasonIsStall against that verdict.
//
// The drift it exists to catch: a NEW enum member added to grant_fetch.proto — for
// example a hypothetical GRANT_FETCH_REASON_STORE_DEGRADED, a SECOND retryable
// reason — would be absent from wantStall below, so the coverage loop FAILS (a loud
// CI failure in this tree), forcing the mirror to be updated on the correct side of
// the split in lockstep with wire.go's own init() completeness panic. Since the
// enum is frozen, in steady state every member is classified and this is green.
func TestGrantFetchReason_StallClassificationIsExhaustive(t *testing.T) {
	t.Parallel()
	// The explicit stall/non-stall verdict for EVERY declared reason. STORE_UNAVAILABLE
	// is the SOLE retryable stall (doc 16 §5.1); OK, the four denies, and the
	// fail-closed UNSPECIFIED are all non-stalls. A new enum member (a second stall)
	// must be added here on the correct side, or the coverage loop below fails.
	wantStall := map[identityv1.GrantFetchReason]bool{
		identityv1.GrantFetchReason_GRANT_FETCH_REASON_UNSPECIFIED:        false,
		identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK:                 false,
		identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE:  true,
		identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_NOT_FOUND:    false,
		identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE:   false,
		identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_PARKED:     false,
		identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_REF_MISMATCH: false,
	}

	// Coverage: every value the generated enum declares MUST be classified above. A
	// new member (the hypothetical GRANT_FETCH_REASON_STORE_DEGRADED second stall) is
	// absent from wantStall, so this fails until it is placed on the split — and the
	// failure message points the author at wire.go's mirror too.
	for v, name := range identityv1.GrantFetchReason_name {
		r := identityv1.GrantFetchReason(v)
		if _, ok := wantStall[r]; !ok {
			t.Errorf("GrantFetchReason %s (=%d) is unclassified in wantStall — a new enum member (e.g. a second stall) must be placed on the stall/non-stall split here and mirrored in grant-service wire.go ReasonIsStall", name, v)
		}
	}
	// And no phantom classification for a value the enum does not declare.
	for r := range wantStall {
		if _, ok := identityv1.GrantFetchReason_name[int32(r)]; !ok {
			t.Errorf("wantStall classifies %d, which is not a declared GrantFetchReason", int32(r))
		}
	}
	// The mirror predicate must agree with the classification for every known value.
	for r, want := range wantStall {
		if got := reasonIsStall(r); got != want {
			t.Errorf("reasonIsStall(%s) = %t, want %t", r, got, want)
		}
	}
}

// gfFetchObservation folds the contract-observable outcome of ONE Fetch (its
// response + transport error) into a comparable Observation — the single shared
// projection EVERY GrantFetch dual-run scenario records: the in-band reason, the
// gRPC status, the §5.1 retryable-stall split (reason==STORE_UNAVAILABLE), the
// credential class, the echoed issued-service-id binding, the clamped grant-TTL,
// and WHETHER a credential rode back plus its non-secret location. It records ONLY
// what the contract promises — NEVER the secret bytes (doc 16 §5.2: the credential
// crosses only off-VM; the observation surface must not leak it) — so a faithful
// real impl and a faithful fake observe identically.
//
// This is the deduped projection: the wave-1 grantFetchSuite scenario closure, the
// §5.1 gfWarmFetchObservation, and the §5.4 suspend/park-resume suite all call it,
// so the seam projection is defined ONCE. A transport/status error is itself a
// contract-observable outcome here (e.g. an unprogrammed fake's Unimplemented), so
// it is folded into status= rather than failing the scenario, so a lying fake
// DIVERGES loudly. Behaviour-preserving: the emitted key/value set is byte-for-byte
// what the wave-1 inline projection emitted, so the wave-1 suite outcome is
// unchanged by the fold.
func gfFetchObservation(resp *identityv1.GrantFetchResponse, err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	if err != nil {
		// A transport/status error is a contract-observable outcome here (e.g. an
		// unprogrammed fake's Unimplemented); fold it in rather than failing the
		// scenario, so a lying fake DIVERGES loudly.
		obs.Set("status", status.Code(err).String())
		return obs
	}
	obs.Set("status", codes.OK.String())
	obs.Set("reason", resp.GetReason().String())
	// Whether the outcome is the RETRYABLE stall (the §5.1 key-store outage) as
	// opposed to OK or a definitive deny — the wire's ReasonIsStall split
	// (grant-service wire.go), folded in so the retry-only-a-stall contract is
	// seam-visible. Routed through the single reasonIsStall mirror below (D80: no
	// propose-only import) so the split is derived in exactly one place here.
	obs.Setf("reason_is_stall", "%t", reasonIsStall(resp.GetReason()))
	obs.Set("credential_class", resp.GetCredentialClass().String())
	obs.Set("issued_service_id", resp.GetIssuedServiceId())
	obs.Setf("grant_expiry_unix_seconds", "%d", resp.GetGrantExpiryUnixSeconds())
	// Record only WHETHER a credential rode back and its non-secret location —
	// never the secret bytes (doc 16 §5.2: the credential crosses only off-VM; the
	// observation surface must not leak it).
	obs.Setf("has_credential", "%t", resp.GetCredential() != nil)
	obs.Set("credential_location", resp.GetCredential().GetLocation())
	return obs
}

// grantFetchSuite is the GrantFetchService seam's single conformance suite. Each
// scenario presents one synthetic fetch and folds the contract-observable outcome
// (in-band reason, gRPC status, whether a credential rode back, the echoed
// issued-service-id binding, and the clamped grant-TTL) into a comparable
// Observation via the shared gfFetchObservation projection. It records ONLY what
// the contract promises — never the secret bytes — so a faithful real impl and a
// faithful fake observe identically.
func grantFetchSuite() dualrun.Suite {
	type fetchCase struct {
		name      string
		sessionID string
		serviceID string
		grantRef  string
		reqExpiry int64
	}
	cases := []fetchCase{
		// Clean fetch: live session, granted service, matching ref, far-future
		// request horizon -> OK with the credential and the stored grant TTL.
		{"ok-clean-fetch", gfSessionLive, gfServiceGitHub, gfGrantRef(gfSessionLive, gfServiceGitHub), gfExpiryFarFuture},
		// Tighter request horizon clamps the cached grant-TTL down to it.
		{"ok-request-horizon-clamps-ttl", gfSessionLive, gfServiceGitHub, gfGrantRef(gfSessionLive, gfServiceGitHub), gfExpiryNearFuture},
		// Ungranted service on a live session -> GRANT_NOT_FOUND, no credential.
		{"deny-grant-not-found", gfSessionLive, gfServiceUngranted, gfGrantRef(gfSessionLive, gfServiceUngranted), gfExpiryFarFuture},
		// Own-session-dead session -> SESSION_NOT_LIVE, no credential.
		{"deny-session-not-live", gfSessionRevoked, gfServiceGitHub, gfGrantRef(gfSessionRevoked, gfServiceGitHub), gfExpiryFarFuture},
		// A ref bound to a DIFFERENT service than requested -> GRANT_REF_MISMATCH,
		// fail-closed before any store lookup.
		{"deny-grant-ref-mismatch", gfSessionLive, gfServiceGitHub, gfGrantRef(gfSessionLive, gfServiceUngranted), gfExpiryFarFuture},
		// Live session, granted service, matching ref, but the key store is in a
		// transient outage -> STORE_UNAVAILABLE: a retryable STALL with no credential
		// (doc 16 §5.1/§11.1-step4). Distinct from the three denies above — the
		// executor RETRIES this, it does NOT fail closed and it does NOT egress the
		// placeholder. Observed at the seam as reason==STORE_UNAVAILABLE /
		// reason_is_stall==true / has_credential==false.
		{"stall-store-unavailable", gfSessionStoreDown, gfServiceGitHub, gfGrantRef(gfSessionStoreDown, gfServiceGitHub), gfExpiryFarFuture},
	}

	scenarios := make([]dualrun.Scenario, 0, len(cases))
	for _, c := range cases {
		c := c
		scenarios = append(scenarios, dualrun.Scenario{
			Name: c.name,
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewGrantFetchServiceClient(conn)
				resp, err := cl.Fetch(ctx, &identityv1.GrantFetchRequest{
					SessionUuid:            c.sessionID,
					ServiceId:              c.serviceID,
					GrantRef:               c.grantRef,
					GrantExpiryUnixSeconds: c.reqExpiry,
				})
				// The shared projection (gfFetchObservation): in-band reason, gRPC
				// status, the §5.1 retryable-stall split, class, issued-service-id, the
				// clamped grant-TTL, and WHETHER a credential rode back + its non-secret
				// location — never the secret bytes (doc 16 §5.2).
				return gfFetchObservation(resp, err), nil
			},
		})
	}

	return dualrun.Suite{
		Seam:      "ds-tlsproxy(swap-executor)<->identity GrantFetchService.Fetch",
		Scenarios: scenarios,
	}
}

// TestDualRun_GrantFetch_RealVsGeneratedFake is the per-commit gate for the
// identity.v1 GrantFetchService credential-swap-fetch seam (doc 16 §5.1/§9, doc 06
// §2.1): the seam's conformance suite runs against BOTH the honest real impl AND
// the generated programmable fake, and the seam is green only if every scenario
// observes the same outcome on both. The suite exercises the OK fetch, the grant-
// TTL request-horizon clamp, the three fail-closed deny reasons (GRANT_NOT_FOUND,
// SESSION_NOT_LIVE, GRANT_REF_MISMATCH), and the §5.1 retryable STORE_UNAVAILABLE
// stall (reason_is_stall, empty credential) — so the stall-vs-deny split is
// conformance-visible at the seam for both the real impl and the generated fake.
func TestDualRun_GrantFetch_RealVsGeneratedFake(t *testing.T) {
	t.Parallel()
	// The "real" end dials the ACTUAL identity/grant-service Server (via the
	// grantfetchconform conformance adapter), not the honest in-test responder, so
	// a real-impl drift fails THIS central seam. The "fake" end is the generated
	// programmable fake driven by the honest responder.
	real := grantFetchStaticRealEnd()
	fake := grantFetchEnd(honestGrantFetchResponder(gfFleet()))
	res, err := grantFetchSuite().Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("identity GrantFetchService seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestDualRun_GrantFetch_HarnessCatchesADriftedFake is the negative proof: a fake
// that drifts from the contract (here, a Fetch that returns the credential on a
// SESSION_NOT_LIVE session instead of failing closed — the doc 16 §5.4 liveness
// violation) MUST fail the seam. Without this a green dual-run would be
// meaningless — it could pass because the gate never fires. The drift lives only
// in this test's local fake, never in the committed generated fake.
func TestDualRun_GrantFetch_HarnessCatchesADriftedFake(t *testing.T) {
	t.Parallel()
	fleet := gfFleet()
	// The non-drifted end is now the ACTUAL grant-service Server (via
	// grantfetchconform), so this also confirms the genuine impl diverges from a
	// drifted fake — strengthening the gate beyond the prior responder-vs-fake form.
	real := grantFetchStaticRealEnd()
	drifted := grantFetchEnd(func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
		// DRIFT: a dead session must fail closed (SESSION_NOT_LIVE, empty
		// credential), but this fake hands back a live-credential OK for it.
		if req.GetSessionUuid() == gfSessionRevoked {
			return &identityv1.GrantFetchResponse{
				Credential:             &identityv1.FetchedCredential{Secret: []byte(gfSecretGitHub), Location: gfLocationHeader},
				CredentialClass:        identityv1.CredentialClass_CREDENTIAL_CLASS_SWAP,
				IssuedServiceId:        req.GetServiceId(),
				GrantExpiryUnixSeconds: gfExpiryFarFuture,
				Reason:                 identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK,
			}, nil
		}
		return honestGrantFetchResponder(fleet)(ctx, req)
	})
	res, err := grantFetchSuite().Run(context.Background(), real, drifted)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a drifted fake passed the seam — the GrantFetch dual-run gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or fake error, got report:\n%s", res.Report())
	}
}

// TestDualRun_GrantFetch_HarnessCatchesADriftedRealImpl is the NEGATIVE proof for
// the newly-real "real" end (01KV4KBZYF): now that the central dual-run dials the
// ACTUAL grant-service Server, a real impl that DRIFTS from the contract MUST fail
// the central seam — not just the module-local pin. This mirrors
// TestDualRun_GrantFetch_HarnessCatchesADriftedFake but on the REAL side: the
// genuine grant-service Server occupies one end, and a deliberately-drifted real
// impl (a §5.4 liveness violation — handing back a live-credential OK for the
// revoked session instead of failing closed) occupies the other. The suite MUST
// diverge. Without this, swapping the real end to the genuine Server could pass
// vacuously — it could be green because the gate never fires against a real drift.
// The genuine Server is correct, so the divergence is forced by the drifted end;
// the drift lives only in this test, never in identity/grant-service.
func TestDualRun_GrantFetch_HarnessCatchesADriftedRealImpl(t *testing.T) {
	t.Parallel()
	// The honest reference end: the genuine grant-service Server over the static fleet.
	honest := grantFetchStaticRealEnd()
	// The drifted "real impl": a stand-in that violates the §5.4 own-session
	// liveness fail-closed by returning a live-credential OK for the revoked session.
	fleet := gfFleet()
	driftedReal := grantFetchEnd(func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
		if req.GetSessionUuid() == gfSessionRevoked {
			return &identityv1.GrantFetchResponse{
				Credential:             &identityv1.FetchedCredential{Secret: []byte(gfSecretGitHub), Location: gfLocationHeader},
				CredentialClass:        identityv1.CredentialClass_CREDENTIAL_CLASS_SWAP,
				IssuedServiceId:        req.GetServiceId(),
				GrantExpiryUnixSeconds: gfExpiryFarFuture,
				Reason:                 identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK,
			}, nil
		}
		return honestGrantFetchResponder(fleet)(ctx, req)
	})
	// Run the genuine Server against the drifted real impl: the seam must catch it.
	res, err := grantFetchSuite().Run(context.Background(), honest, driftedReal)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a drifted real impl passed the central seam — the genuine-Server GrantFetch dual-run gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.RealErrors) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or harness error, got report:\n%s", res.Report())
	}
}

// TestDualRun_GrantFetch_UnprogrammedFakeIsHonestUnimplemented asserts the
// generated fake's contract-honest default: an unprogrammed Fetch responder must
// surface codes.Unimplemented, not a silent zero-value success — so a dual-run
// against a real impl that DOES implement the verb diverges loudly rather than
// passing on a fiction (the very "lying fake" the harness exists to catch).
func TestDualRun_GrantFetch_UnprogrammedFakeIsHonestUnimplemented(t *testing.T) {
	t.Parallel()
	// The "real" end is the genuine grant-service Server (via grantfetchconform):
	// it implements Fetch, so an unprogrammed fake (Unimplemented) must diverge.
	real := grantFetchStaticRealEnd()
	bare := dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		identityv1fake.RegisterGrantFetchService(s, identityv1fake.NewGrantFetchServiceFake())
	})
	res, err := grantFetchSuite().Run(context.Background(), real, bare)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("an unprogrammed GrantFetch fake vs a programmed impl must diverge")
	}
}

// ---------------------------------------------------------------------------
// §5.1 cache-rides-outage: the COMPLEMENT of the wave-1 stall scenario, lifted.
//
// The wave-1 stall scenario above pins the NEW-fetch leg of the doc 16 §5.1
// availability contract: during a key-store outage a NEW grant fetch STALLS
// (STORE_UNAVAILABLE, retryable). Its complement — "an in-flight session keeps
// egressing on its session-CACHED grant during the outage with NO re-fetch and
// NO stall, returning OK" (doc 16 §5.1 line "an outage stalls new grant fetches
// only, while in-flight sessions ride their session-cached grants"; §11.1 step-4)
// — was pinned only module-locally in identity/grant-service (service_test.go
// TestFetch_CacheRidesOutage in-process, AND, decisively, server_test.go
// TestServedRPC_StallVsDeny over the REAL bufconn-served GrantFetchService.Fetch
// RPC). That served-RPC test confirms the complement IS a per-RPC seam-observable
// outcome: the grant Service caches fetched grants per (session, service) ≤
// session, and the wire distinguishes a WARM (session, service) — a cache HIT
// that rides the outage as OK without consulting the store — from a NEW one — a
// cache MISS that, during the outage, stalls with STORE_UNAVAILABLE. The cache
// lives server-side on the grant Service; the swap executor's per-session cache
// (doc 16 §5.1/§5.2/§138) is the consumer-side mirror, but the ride-vs-stall
// split is already visible on GrantFetchResponse.reason at the Fetch wire. So we
// take option (a): LIFT a seam-visible warm-cache+availability scenario into the
// central dual-run. (Were the ride invisible at the wire — cache only in the
// executor — option (b) would instead doccomment the module-local pinning here.)
//
// To make ride-vs-stall observable, the honest responder this scenario drives is
// STATEFUL (a synthetic stand-in for the server-side per-session cache + the
// store-availability bit, NOT a real Service import — D50): a first Fetch of a
// (session, service) while the store is up WARMS that pair (cache MISS -> store
// read -> OK, cached); the store then goes down (a fleet-wide availability flip);
// thereafter a WARM pair is a cache HIT that rides the outage as OK with the
// credential while a NEW pair is a cache MISS that stalls with STORE_UNAVAILABLE.
// Both dual-run ends are built from the SAME stateful construction and driven by
// the SAME ordered scenarios (Suite.Run walks scenarios in declaration order,
// running each once against the real end then once against the fake end before
// advancing — see dualrun.go Run; no in-suite concurrency), so the real and fake
// observe field-for-field identically — a divergence is attributable to the
// contract, never the fixture. The two ends are over SEPARATE fleets and the
// only state-mutating scenarios are conn-routed (warm/ride/miss touch only the
// fleet behind their own conn) or idempotent (the outage-onset down() flips both
// fleets and is safe to repeat), so the real-then-fake interleaving leaves each
// end walking its own lifecycle identically. This is ADDITIVE: it adds a SECOND suite/test and shares none of the
// wave-1 suite's state, so the wave-1 stall scenario and every existing assertion
// are untouched. No secret bytes ride any Observation (only WHETHER a credential
// rode back and its non-secret location, as in the wave-1 suite).

// gfSessionWarm is the in-flight session whose grant is warmed BEFORE the outage
// and then rides the outage from cache; gfSessionColdMiss is a second live
// session whose FIRST (and only) fetch happens DURING the outage, so it is a
// cache miss that stalls. Both are live and github-granted in the warm-cache
// fleet — the only thing that differs is whether the pair was warmed pre-outage.
const (
	gfSessionWarm     = "ses-synthetic-grantfetch-warm-dddd3333"
	gfSessionColdMiss = "ses-synthetic-grantfetch-coldmiss-eeee4444"
)

// gfServiceNpm is a SECOND synthetic granted service on the warm-cache fleet, used
// only by the §5.4 suspend/park-resume suite: it lets one (session, service) pair
// be WARMED before a park (so it rides) while a DIFFERENT, not-yet-cached pair on
// the same session is a cache MISS that the park refuses (SESSION_PARKED) and that
// resume then admits. The §5.1 warm/cold legs never fetch it, so granting it is
// behavior-preserving for them (they request only gfServiceGitHub by explicit key).
const gfServiceNpm = "svc-synthetic-grantfetch-npm"

// gfWarmFleet is a stateful synthetic stand-in for the grant Service's server-
// side per-(session, service) cache plus its store-availability bit (doc 16
// §5.1). It is NOT a real Service (D50): it restates only the ride-vs-stall
// decision the served GrantFetchService.Fetch wire exposes. A Fetch WARMS a pair
// on a cache miss while the store is up; once down(), a warm pair rides from
// cache (OK) and a cold pair stalls (STORE_UNAVAILABLE). Construction seeds the
// same static grants gfFleet does, so the OK credential/class/expiry match the
// wave-1 suite field-for-field.
type gfWarmFleet struct {
	live      map[string]bool               // session -> liveness (own-session §5.4)
	parked    map[string]bool               // session -> parked (§5.4 snapshot+park; refuses a NEW fetch)
	grants    map[string]map[string]gfGrant // session -> service -> stored grant
	cache     map[string]map[string]gfGrant // session -> service -> WARMED grant
	available bool                          // false models the §5.1 store outage
	// storeReads counts the number of times the responder actually READ the backing
	// store (a cache MISS on a live, available store that warms the pair). A cache
	// HIT — the §5.1/§5.4 ride — serves entirely from the warmed cache and must NOT
	// bump it: that no-store-read fact is exactly the doc 16 §5.1 "in-flight sessions
	// ride their session-cached grants" / §5.4 "grants survive snapshot+park"
	// contract, otherwise invisible at the Fetch wire (a ride and a fresh read both
	// observe reason==OK). The store-read-skipped assertions read this counter; the
	// fail-closed denies, the outage stall, and the park refusal all return BEFORE a
	// store read, so they never bump it either.
	storeReads int
}

// newGfWarmFleet builds the warm-cache fleet: two live github-granted sessions
// (warm + cold-miss), store initially UP, nothing warmed yet.
func newGfWarmFleet() *gfWarmFleet {
	githubGrant := gfGrant{
		secret:   gfSecretGitHub,
		location: gfLocationHeader,
		class:    identityv1.CredentialClass_CREDENTIAL_CLASS_SWAP,
		expiry:   gfExpiryFarFuture,
	}
	// The cold-miss session additionally holds a github+npm pair: the §5.4 suite
	// warms one (github) before a park so it rides, while the other (npm) stays a
	// cache miss the park refuses and resume admits. The §5.1 legs never request
	// npm, so the extra grant is invisible to them (they fetch only github).
	mk := func() map[string]map[string]gfGrant {
		return map[string]map[string]gfGrant{
			gfSessionWarm:     {gfServiceGitHub: githubGrant},
			gfSessionColdMiss: {gfServiceGitHub: githubGrant, gfServiceNpm: githubGrant},
		}
	}
	return &gfWarmFleet{
		live:      map[string]bool{gfSessionWarm: true, gfSessionColdMiss: true},
		parked:    map[string]bool{},
		grants:    mk(),
		cache:     map[string]map[string]gfGrant{},
		available: true,
	}
}

// down flips the fleet into the §5.1 store outage (no new store reads succeed).
func (w *gfWarmFleet) down() { w.available = false }

// storeReadCount returns how many times the responder actually read the backing
// store across the run so far (cache misses that warmed a pair). A cache-HIT ride
// — the §5.1 outage ride and the §5.4 parked-warm-pair ride — serves from cache
// and never bumps it, so a directed test can pin the served-from-cache (no store
// read) contract by asserting the count is unchanged across the ride.
func (w *gfWarmFleet) storeReadCount() int { return w.storeReads }

// ---------------------------------------------------------------------------
// §5.4 suspend/park/resume verbs on gfWarmFleet (the grant-eviction lifecycle).
//
// These mirror the grant Service's own §5.4 own-session invariants — pinned only
// module-locally today in identity/grant-service/service_test.go
// (TestSuspend_EvictsGrants / TestParkResume_SurvivesAndReValidates) — so the
// central dual-run carries them too. The seam-visible decisions they drive:
//   - suspend EVICTS: drops the session cache entry AND flips it not-live, so a
//     subsequent fetch fails closed SESSION_NOT_LIVE (the active-eviction half of
//     "TTL-as-revocation plus active eviction", §5.4). service.go Suspend deletes
//     the whole session record, after which an unknown session is ErrSessionNotLive
//     -> GRANT_FETCH_REASON_SESSION_NOT_LIVE.
//   - park KEEPS the cache (grants survive snapshot+park, §5.4) but refuses a NEW
//     (cache-miss) fetch (SESSION_PARKED) — the responder's parked branch above.
//   - resume CLEARS parked and re-validates against liveness + TTLs: a session
//     still live is admitted again, expired cached grants are dropped so the caller
//     re-mints ("expired creds re-mint", §5.4). A not-live session is NOT resumed
//     (fail-closed) — a dead session does not silently come back.
//
// They are behavior-preserving for the existing §5.1 warm/cold legs: a fleet that
// is never suspended/parked/resumed has parked empty and live unchanged, so the
// warm-ride and cold-stall scenarios observe exactly as before.

// suspend EVICTS the session on the suspend signal (§5.4): the cache entry is
// dropped AND the session is flipped not-live, so the next fetch fails closed
// SESSION_NOT_LIVE. Mirrors service.go Suspend (delete the session record).
func (w *gfWarmFleet) suspend(sessionUUID string) {
	w.live[sessionUUID] = false
	delete(w.cache, sessionUUID)
}

// park marks the session parked (§5.4 snapshot+park): the cache SURVIVES (a warm
// pair still rides), but a NEW (cache-miss) fetch is refused (SESSION_PARKED) until
// resume. Mirrors service.go Park (sess.state = parked).
func (w *gfWarmFleet) park(sessionUUID string) { w.parked[sessionUUID] = true }

// resume re-validates a parked session against liveness + TTLs and returns it to
// LIVE (§5.4). It clears the parked bit, and — when stillLive is false — leaves the
// session not-live (a dead-past-deadline session is NOT resumed, fail-closed). Any
// cached grant in dropExpired (the pairs whose grant TTL lapsed across the park) is
// evicted so the caller re-mints ("expired creds re-mint"). The TTL clock is the
// caller's responsibility (the dual-run has no wall clock); dropExpired names the
// (service) keys to drop for the session, mirroring service.go Resume's per-grant
// TTL re-validation without importing a clock.
func (w *gfWarmFleet) resume(sessionUUID string, stillLive bool, dropExpired ...string) {
	delete(w.parked, sessionUUID)
	if !stillLive {
		// Liveness re-validation failed: the session is past its deadline and is NOT
		// resumed — it stays not-live and holds no live cache (fail-closed).
		w.live[sessionUUID] = false
		delete(w.cache, sessionUUID)
		return
	}
	w.live[sessionUUID] = true
	for _, svc := range dropExpired {
		if m := w.cache[sessionUUID]; m != nil {
			delete(m, svc)
		}
	}
}

// responder encodes the SAME GrantFetch contract decisions honestGrantFetch-
// Responder does, with the §5.1 cache layer made explicit: fail-closed ref-bind
// and liveness/grant denies first (a deny is definitive even under outage), then
// the cache-HIT ride (no store consulted), then — only on a cache MISS — the
// availability gate (down -> STORE_UNAVAILABLE stall; up -> store read, warm, OK).
// It never returns a zero-value success.
func (w *gfWarmFleet) responder() func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
	return func(_ context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
		deny := func(r identityv1.GrantFetchReason) *identityv1.GrantFetchResponse {
			return &identityv1.GrantFetchResponse{Reason: r}
		}
		okResp := func(g gfGrant, req *identityv1.GrantFetchRequest) *identityv1.GrantFetchResponse {
			expiry := g.expiry
			if req.GetGrantExpiryUnixSeconds() > 0 && req.GetGrantExpiryUnixSeconds() < expiry {
				expiry = req.GetGrantExpiryUnixSeconds()
			}
			return &identityv1.GrantFetchResponse{
				Credential:             &identityv1.FetchedCredential{Secret: []byte(g.secret), Location: g.location},
				CredentialClass:        g.class,
				IssuedServiceId:        req.GetServiceId(),
				GrantExpiryUnixSeconds: expiry,
				Reason:                 identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK,
			}
		}

		// Fail-closed grant_ref binding, identical to the wave-1 responder.
		if req.GetGrantRef() != gfGrantRef(req.GetSessionUuid(), req.GetServiceId()) {
			return deny(identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_REF_MISMATCH), nil
		}
		if !w.live[req.GetSessionUuid()] {
			return deny(identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE), nil
		}
		g, granted := w.grants[req.GetSessionUuid()][req.GetServiceId()]
		if !granted {
			return deny(identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_NOT_FOUND), nil
		}

		// CACHE HIT: the in-flight session already warmed this (session, service),
		// so it rides — OK with the cached credential, the STORE NEVER CONSULTED.
		// This is the §5.1 "in-flight sessions ride their session-cached grants"
		// leg; it serves whether or not the store is available — AND whether or not
		// the session is parked (park keeps the cache and its grants still serve,
		// §5.4: "grants and digests survive snapshot+park"). The hit therefore
		// precedes the park-refusal below, mirroring service.go's Fetch ordering.
		if cached, hit := w.cache[req.GetSessionUuid()][req.GetServiceId()]; hit {
			return okResp(cached, req), nil
		}

		// CACHE MISS + PARKED: a parked session fetches no NEW grants until Resume
		// (§5.4 snapshot+park). It rides only what it cached before park (the hit
		// path above); a NEW (cache-miss) fetch is refused, fail-closed, with an
		// EMPTY credential and the distinct SESSION_PARKED reason (grant-service
		// wire.go errParkedSession -> GRANT_FETCH_REASON_SESSION_PARKED). Checked
		// AFTER the hit (parked grants still ride) and BEFORE the store gate (the
		// refusal is the park policy, not a store outage).
		if w.parked[req.GetSessionUuid()] {
			return deny(identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_PARKED), nil
		}

		// CACHE MISS: this fetch must read the store. Under a §5.1 outage it STALLS
		// (STORE_UNAVAILABLE, retryable, empty credential) — this is the wave-1 NEW-
		// fetch leg. With the store up it reads, WARMS the (session, service) for a
		// future ride, and returns OK.
		if !w.available {
			return deny(identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE), nil
		}
		// The ONLY path that actually consults the backing store: a cache miss on a
		// live, non-parked, available store. Count it so a directed test can assert
		// that the cache-HIT ride above (the §5.1/§5.4 served-from-cache contract)
		// consulted NO store — the no-store-read fact otherwise invisible at the wire.
		w.storeReads++
		if w.cache[req.GetSessionUuid()] == nil {
			w.cache[req.GetSessionUuid()] = map[string]gfGrant{}
		}
		w.cache[req.GetSessionUuid()][req.GetServiceId()] = g
		return okResp(g, req), nil
	}
}

// gfWarmFetchObservation drives one Fetch over the warm-cache path and folds its
// outcome through the SAME shared gfFetchObservation projection the wave-1 suite
// records (in-band reason, gRPC status, the retryable-stall split, class,
// issued-service-id, clamped grant-TTL, and WHETHER a credential rode back + its
// non-secret location). Never the secret bytes (doc 16 §5.2). The fetch always
// carries the far-future request horizon, so the §5.1/§5.4 scenarios observe the
// stored grant TTL unless a per-grant TTL is tighter.
func gfWarmFetchObservation(ctx context.Context, conn *grpc.ClientConn, sessionID, serviceID string) *dualrun.Observation {
	cl := identityv1.NewGrantFetchServiceClient(conn)
	resp, err := cl.Fetch(ctx, &identityv1.GrantFetchRequest{
		SessionUuid:            sessionID,
		ServiceId:              serviceID,
		GrantRef:               gfGrantRef(sessionID, serviceID),
		GrantExpiryUnixSeconds: gfExpiryFarFuture,
	})
	return gfFetchObservation(resp, err)
}

// grantFetchWarmCacheSuite is the §5.1 cache-rides-outage conformance suite. Its
// scenarios run in DECLARATION ORDER against the (stateful) responder, walking
// the in-flight lifecycle: warm the in-flight session pre-outage, take the store
// down, then observe that the WARM pair rides the outage as OK while a COLD pair
// stalls. The down() flip rides its own scenario (so it is part of the ordered
// walk both ends replay identically) and records the no-op observation that the
// flip itself surfaced nothing on the wire.
//
// Both end-fleets are flipped in the outage-onset scenario, because the suite
// runner calls each scenario once per end (real then fake) and a scenario closure
// cannot tell which conn it is driving: the real and fake responders are built
// over SEPARATE fleets, so flipping only one would leave the other's store up and
// manufacture a spurious divergence. down() is idempotent (it only sets the
// availability bit false), so flipping both on each of the two per-scenario
// invocations is safe and leaves both ends in the same outage state.
func grantFetchWarmCacheSuite(realFleet, fakeFleet *gfWarmFleet) dualrun.Suite {
	return dualrun.Suite{
		Seam: "ds-tlsproxy(swap-executor)<->identity GrantFetchService.Fetch (§5.1 cache-rides-outage)",
		Scenarios: []dualrun.Scenario{
			{
				// 1. Pre-outage WARM: the in-flight session's first fetch is a cache
				// miss while the store is up -> OK, and it warms the pair for the ride.
				Name: "warm-inflight-grant-before-outage-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
				},
			},
			{
				// 2. The store goes DOWN. This is a fleet-state transition, not a
				// fetch; it surfaces nothing on the Fetch wire, recorded as such so the
				// ordered walk has an explicit outage-onset step on both ends.
				Name: "store-outage-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realFleet.down()
					fakeFleet.down()
					return dualrun.NewObservation().Set("store_available", "false"), nil
				},
			},
			{
				// 3. The WARM in-flight pair RIDES the outage: cache hit -> OK with the
				// credential, NO re-fetch, NO stall (the §5.1 complement of the wave-1
				// stall). Observed at the seam as reason==OK / reason_is_stall==false /
				// has_credential==true, even though the store is down.
				Name: "warm-inflight-grant-rides-outage-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
				},
			},
			{
				// 4. A NEW (cold) pair's FIRST fetch during the outage is a cache miss
				// -> STORE_UNAVAILABLE stall — the wave-1 NEW-fetch leg, observed here
				// in the SAME run beside the ride to make the ride-vs-stall split
				// conformance-visible together. reason==STORE_UNAVAILABLE /
				// reason_is_stall==true / has_credential==false.
				Name: "new-grant-during-outage-stalls",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
		},
	}
}

// TestDualRun_GrantFetch_WarmCacheRidesOutage lifts the doc 16 §5.1 cache-rides-
// outage invariant — the complement of the wave-1 STORE_UNAVAILABLE stall — into
// the central dual-run (option (a)): a warm in-flight (session, service) Fetch
// returns OK with the credential while a new (session, service) Fetch returns
// STORE_UNAVAILABLE during the same store outage, BOTH the honest real impl and
// the generated fake observing field-for-field identically. The two ends are
// independent stateful responders over identical fleets driven by the same
// ordered scenarios, so a divergence is attributable to the contract. This is
// additive: it shares no state with grantFetchSuite, so the wave-1 stall scenario
// stays green. (server_test.go TestServedRPC_StallVsDeny / service_test.go
// TestFetch_CacheRidesOutage remain the module-local pins this lifts from.)
// grantFetchWarmCacheSuiteRealVsFake is the warm-cache suite wired for the
// genuine-Server "real" end: the §5.1 store outage is driven on the real end via
// grantfetchconform's SetStoreAvailable (the production FileKVBackend flip) AND on
// the fake fleet via down(), in the SAME outage-onset scenario. As with
// grantFetchWarmCacheSuite, the suite runner calls each scenario once per end and a
// scenario closure cannot tell which conn it is driving, so both ends are flipped
// on each invocation; both flips are idempotent, so the two ends end in the same
// outage state. The scenario sequence and observation projection are identical to
// grantFetchWarmCacheSuite — only the outage lever for the real end differs.
func grantFetchWarmCacheSuiteRealVsFake(realEnd *grantfetchconform.WarmCacheRealEnd, fakeFleet *gfWarmFleet) dualrun.Suite {
	return dualrun.Suite{
		Seam: "ds-tlsproxy(swap-executor)<->identity GrantFetchService.Fetch (§5.1 cache-rides-outage, real Server)",
		Scenarios: []dualrun.Scenario{
			{
				Name: "warm-inflight-grant-before-outage-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
				},
			},
			{
				// The store goes DOWN on BOTH ends: the genuine Server's backend via
				// SetStoreAvailable(false) and the fake fleet via down(). Both are
				// idempotent, so flipping on each of the two per-scenario invocations is
				// safe and leaves both ends in the same outage state.
				Name: "store-outage-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realEnd.SetStoreAvailable(false)
					fakeFleet.down()
					return dualrun.NewObservation().Set("store_available", "false"), nil
				},
			},
			{
				Name: "warm-inflight-grant-rides-outage-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
				},
			},
			{
				Name: "new-grant-during-outage-stalls",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
		},
	}
}

// TestDualRun_GrantFetch_WarmCacheRidesOutage is the §5.1 cache-rides-outage
// dual-run with the "real" end dialing the genuine grant-service Server: a warm
// in-flight (session, service) Fetch returns OK with the credential while a new
// (cold) Fetch returns STORE_UNAVAILABLE during the same store outage, the ACTUAL
// Server and the generated fake observing field-for-field identically. The real
// end's §5.1 outage is the production FileKVBackend SetAvailable flip; the fake
// end's is the stateful gfWarmFleet down(). Both walk the same ordered lifecycle,
// so a divergence is attributable to the contract. Additive: it shares no state
// with grantFetchSuite, so the wave-1 stall scenario stays green.
func TestDualRun_GrantFetch_WarmCacheRidesOutage(t *testing.T) {
	t.Parallel()
	realEnd := grantfetchconform.NewWarmCacheRealEnd(warmGfSpec())
	fakeFleet := newGfWarmFleet()
	real := dualrun.InProcess(realEnd.Register)
	fake := grantFetchEnd(fakeFleet.responder())
	res, err := grantFetchWarmCacheSuiteRealVsFake(realEnd, fakeFleet).Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("identity GrantFetchService §5.1 cache-rides-outage seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the warm-cache suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestDualRun_GrantFetch_WarmCacheRidesOutage_FakeVsFake preserves the original
// honest-responder-vs-generated-fake warm-cache dual-run (both ends the stateful
// gfWarmFleet responder) alongside the genuine-Server variant above. It pins that
// the honest §5.1 cache model and the generated fake still agree field-for-field —
// the additive fake-first coverage the wave-1 lift established, unweakened.
func TestDualRun_GrantFetch_WarmCacheRidesOutage_FakeVsFake(t *testing.T) {
	t.Parallel()
	realFleet := newGfWarmFleet()
	fakeFleet := newGfWarmFleet()
	real := grantFetchEnd(realFleet.responder())
	fake := grantFetchEnd(fakeFleet.responder())
	res, err := grantFetchWarmCacheSuite(realFleet, fakeFleet).Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("identity GrantFetchService §5.1 cache-rides-outage (fake-vs-fake) seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the fake-vs-fake warm-cache suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestDualRun_GrantFetch_WarmCacheRidesOutage_DirectedReasons is the DIRECTED
// complement of the warm-cache dual-run: the dual-run above proves the real impl
// and the generated fake observe the §5.1 lifecycle field-for-field IDENTICALLY,
// but — like the wave-1 RealVsGeneratedFake gate — equality alone cannot tell a
// faithful pair from a pair that agrees on the WRONG verdict. This pins the exact
// ride-vs-stall reasons the served-RPC module-local pin (server_test.go
// TestServedRPC_StallVsDeny) asserts, so the central lift carries the contract
// VALUES (not just cross-end agreement): over the SAME warm-cache fetch path, a
// WARM in-flight (session, service) rides a store outage as OK with the credential
// and no stall, while a NEW (cold) pair's first fetch during that outage stalls
// with STORE_UNAVAILABLE and carries no credential.
//
// It reads the ACTUAL per-scenario Observations the dual run already drove
// (Result.ObservationsFor) instead of constructing a SECOND out-of-band responder
// — so it asserts on the same fetch the real-vs-fake equality check compared,
// pinning the verdict on BOTH the genuine Server and the generated fake at once.
// No secret bytes ride any Observation (doc 16 §5.2): each pins only WHETHER a
// credential rode and its non-secret location.
func TestDualRun_GrantFetch_WarmCacheRidesOutage_DirectedReasons(t *testing.T) {
	t.Parallel()
	realEnd := grantfetchconform.NewWarmCacheRealEnd(warmGfSpec())
	fakeFleet := newGfWarmFleet()
	real := dualrun.InProcess(realEnd.Register)
	fake := grantFetchEnd(fakeFleet.responder())
	res, err := grantFetchWarmCacheSuiteRealVsFake(realEnd, fakeFleet).Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	// The directed verdict is only meaningful if the seam is green AND every
	// scenario actually ran cleanly on both ends (an end-error would leave a nil
	// Observation, so the assertions below would otherwise silently pass).
	if !res.OK() {
		t.Fatalf("warm-cache dual-run DIVERGED before the directed check:\n%s", res.Report())
	}

	// assertObs reads both ends' Observation for one scenario from the run and
	// applies the per-key contract checks to EACH end (real and fake), proving the
	// verdict value on the impls the dual run already compared.
	assertObs := func(scenario string, check func(end string, kv map[string]string)) {
		t.Helper()
		realObs, fakeObs, ok := res.ObservationsFor(scenario)
		if !ok {
			t.Fatalf("scenario %q not found in dual-run observations", scenario)
		}
		if realObs == nil || fakeObs == nil {
			t.Fatalf("scenario %q is missing an observation (real=%v fake=%v)", scenario, realObs, fakeObs)
		}
		check("real", dualrun.ParseObs(realObs.Canonical()))
		check("fake", dualrun.ParseObs(fakeObs.Canonical()))
	}

	// 1. Pre-outage WARM: the in-flight session's first fetch is a cache miss while
	// the store is up -> OK, and it warms the pair for the ride.
	assertObs("warm-inflight-grant-before-outage-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s pre-outage warm fetch reason = %q, want OK", end, got)
		}
	})

	// 2. Store goes DOWN — a fleet-state transition that surfaces nothing on the
	// Fetch wire, recorded as the explicit outage-onset step.
	assertObs("store-outage-onset", func(end string, kv map[string]string) {
		if got := kv["store_available"]; got != "false" {
			t.Errorf("%s outage-onset store_available = %q, want false", end, got)
		}
	})

	// 3. The WARM in-flight pair RIDES the outage: OK with the credential at the
	// non-secret header location, no stall.
	assertObs("warm-inflight-grant-rides-outage-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s warm-ride reason = %q, want OK", end, got)
		}
		if got := kv["reason_is_stall"]; got != "false" {
			t.Errorf("%s warm-ride reason_is_stall = %q, want false", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s warm ride must carry the credential, has_credential = %q", end, got)
		}
		if got := kv["credential_location"]; got != gfLocationHeader {
			t.Errorf("%s warm-ride credential_location = %q, want %q", end, got, gfLocationHeader)
		}
	})

	// 4. A NEW (cold) pair's first fetch DURING the outage is a cache miss -> the
	// retryable STORE_UNAVAILABLE stall, no credential.
	assertObs("new-grant-during-outage-stalls", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE.String() {
			t.Errorf("%s cold-miss reason = %q, want STORE_UNAVAILABLE", end, got)
		}
		if got := kv["reason_is_stall"]; got != "true" {
			t.Errorf("%s cold-miss reason_is_stall = %q, want true", end, got)
		}
		if got := kv["has_credential"]; got != "false" {
			t.Errorf("%s a stall must carry no credential, has_credential = %q", end, got)
		}
	})
}

// TestDualRun_GrantFetch_RecordedViaFakeAccessors asserts the fetch contract
// against the generated fake's FetchRecorded() call-capture accessor — the
// assertion the dual-run's end-observable comparison alone cannot make. The
// dual-run compares end-observable verdicts; the recorded-call surface is what
// lets a downstream consumer verify "the store was asked these fetches, each
// carrying the session/service/ref binding". It also pins the no-secret-on-the-
// request-surface fact (GrantFetchRequest carries only a reference, never
// credential material).
//
// Rather than re-drive a SECOND out-of-band fake purely to get a recorder to
// inspect, it drives the wave-1 grantFetchSuite dual run ONCE — the SAME run the
// RealVsGeneratedFake gate uses (static real Server vs the held generated fake) —
// reads the OK / GRANT_REF_MISMATCH verdicts back from the per-scenario
// Observations (Result.ObservationsFor), and inspects FetchRecorded() on the held
// fake the run already drove. No secret bytes ride any Observation (doc 16 §5.2):
// the per-scenario Observation records only WHETHER a credential rode and its
// non-secret location, and the recorded REQUEST surface carries only references.
func TestDualRun_GrantFetch_RecordedViaFakeAccessors(t *testing.T) {
	t.Parallel()
	real := grantFetchStaticRealEnd()
	fake, fakeImpl := grantFetchEndWithFake(honestGrantFetchResponder(gfFleet()))
	res, err := grantFetchSuite().Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	// The recorded-call assertions below only carry weight if the verdicts the run
	// observed are the contract's — so gate on the same green seam RealVsGeneratedFake
	// pins, then read the directed verdicts from the run's Observations.
	if !res.OK() {
		t.Fatalf("grantFetchSuite dual-run DIVERGED before the recorded-call check:\n%s", res.Report())
	}

	// (a) clean fetch -> OK with the credential at the non-secret header location,
	// the echoed issued-service-id binding, and the stored grant TTL — read from the
	// fake end's Observation for the ok-clean-fetch scenario (no re-drive).
	_, okFakeObs, ok := res.ObservationsFor("ok-clean-fetch")
	if !ok || okFakeObs == nil {
		t.Fatal("ok-clean-fetch scenario missing a fake Observation")
	}
	okKV := dualrun.ParseObs(okFakeObs.Canonical())
	if got := okKV["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
		t.Errorf("clean fetch reason = %q, want OK", got)
	}
	if got := okKV["has_credential"]; got != "true" {
		t.Errorf("clean fetch has_credential = %q, want true", got)
	}
	if got := okKV["credential_location"]; got != gfLocationHeader {
		t.Errorf("clean fetch credential_location = %q, want %q", got, gfLocationHeader)
	}
	if got := okKV["issued_service_id"]; got != gfServiceGitHub {
		t.Errorf("clean fetch issued_service_id = %q, want %q", got, gfServiceGitHub)
	}
	if got := okKV["grant_expiry_unix_seconds"]; got != fmt.Sprintf("%d", gfExpiryFarFuture) {
		t.Errorf("clean fetch grant_expiry_unix_seconds = %q, want far-future %d", got, gfExpiryFarFuture)
	}

	// (b) grant_ref bound to the wrong service -> GRANT_REF_MISMATCH, no credential.
	_, mmFakeObs, ok := res.ObservationsFor("deny-grant-ref-mismatch")
	if !ok || mmFakeObs == nil {
		t.Fatal("deny-grant-ref-mismatch scenario missing a fake Observation")
	}
	mmKV := dualrun.ParseObs(mmFakeObs.Canonical())
	if got := mmKV["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_REF_MISMATCH.String() {
		t.Errorf("ref-mismatch reason = %q, want GRANT_REF_MISMATCH", got)
	}
	if got := mmKV["has_credential"]; got != "false" {
		t.Errorf("a denied fetch must carry no credential, has_credential = %q", got)
	}

	// The recorder must have captured the run's fetches, each carrying the session,
	// service, and ref binding — and NO secret on the request surface. (The dual run
	// walks every wave-1 scenario, so the recorder holds one call per scenario; we
	// pin the per-request invariants that hold across ALL of them plus that the OK
	// and mismatch fetches above were among them.)
	calls := fakeImpl.FetchRecorded()
	if len(calls) != len(grantFetchSuite().Scenarios) {
		t.Fatalf("FetchRecorded: want %d captured calls (one per scenario), got %d", len(grantFetchSuite().Scenarios), len(calls))
	}
	sawOK, sawMismatch := false, false
	for i, c := range calls {
		if got := c.Req.GetSessionUuid(); got == "" {
			t.Errorf("FetchRecorded[%d].session_uuid is empty — every fetch must carry its session binding", i)
		}
		if got := c.Req.GetServiceId(); got == "" {
			t.Errorf("FetchRecorded[%d].service_id is empty — every fetch must carry its service binding", i)
		}
		// The grant_ref is an opaque handle, never secret material: it must parse to
		// the "grant:" wire shape.
		if !strings.HasPrefix(c.Req.GetGrantRef(), "grant:") {
			t.Errorf("FetchRecorded[%d].grant_ref = %q, want a grant:<session>:<service> handle", i, c.Req.GetGrantRef())
		}
		// No-secret-on-the-request-surface: the synthetic credential bytes must never
		// appear anywhere on a recorded REQUEST (the request carries only references).
		if strings.Contains(c.Req.GetGrantRef(), gfSecretGitHub) {
			t.Errorf("FetchRecorded[%d].grant_ref leaked the credential secret", i)
		}
		if c.Req.GetSessionUuid() == gfSessionLive && c.Req.GetServiceId() == gfServiceGitHub &&
			c.Req.GetGrantRef() == gfGrantRef(gfSessionLive, gfServiceGitHub) {
			sawOK = true
		}
		if c.Req.GetSessionUuid() == gfSessionLive && c.Req.GetServiceId() == gfServiceGitHub &&
			c.Req.GetGrantRef() == gfGrantRef(gfSessionLive, gfServiceUngranted) {
			sawMismatch = true
		}
	}
	if !sawOK {
		t.Error("FetchRecorded did not capture the OK clean-fetch request")
	}
	if !sawMismatch {
		t.Error("FetchRecorded did not capture the GRANT_REF_MISMATCH request")
	}
}

// ---------------------------------------------------------------------------
// Per-reason DIRECTED assertions for the wave-1 grantFetchSuite scenarios — the
// non-vacuity lift this unit adds.
//
// TestDualRun_GrantFetch_RealVsGeneratedFake (above) asserts only res.OK()
// cross-end EQUALITY: the real impl and the generated fake observe the same
// thing scenario-for-scenario. But — exactly as the warm-cache lift observed
// for its own RidesOutage dual-run (closed by WarmCacheRidesOutage_Directed-
// Reasons) — cross-end equality alone cannot distinguish a faithful pair from a
// pair that AGREES ON THE WRONG VERDICT: if both ends returned GRANT_NOT_FOUND
// for the SESSION_NOT_LIVE fixture, res.OK() would still be green. The wave-1
// dual-run gate therefore pins that the two impls agree, but NOT what they agree
// ON. This block closes that gap for the REMAINING wave-1 scenarios (the OK
// fetch and the four deny/stall reasons), mirroring what WarmCacheRidesOutage_-
// DirectedReasons did for the warm-cache lift.
//
// It is purely ADDITIVE: it adds two tests driven through the generated fake's
// Fetch (the registration both dual-run ends share) and a shared expectation
// table. It does NOT touch grantFetchSuite, the res.OK() cross-end checks, or
// any of the three negative controls — those stay byte-untouched. The frozen
// GrantFetchReason enum is consumed READ-ONLY (projection only, no re-declare).
// No secret bytes ride any assertion (doc 16 §5.2): each case pins only WHETHER
// a credential rode back and its non-secret location.

// gfDirectedCase is one wave-1 scenario's EXACT contract verdict: the in-band
// reason, whether that reason is the retryable §5.1 stall, and whether a
// credential rode back. The deny/stall cases additionally pin that NO credential
// is present; the OK case pins that the credential rode at the non-secret header
// location. This is the value-level contract the wave-1 res.OK() equality check
// alone does not carry.
type gfDirectedCase struct {
	name         string
	sessionID    string
	serviceID    string
	grantRef     string
	wantReason   identityv1.GrantFetchReason
	wantStall    bool
	wantHasCred  bool
	wantLocation string // only meaningful when wantHasCred (else "")
	wantStatusOK bool   // the in-band-reason contract returns codes.OK; a stall is in-band, never a transport error
	// wantStatusCode is the gRPC transport status the case expects when
	// wantStatusOK is false — a TRANSPORT error (e.g. codes.InvalidArgument on a
	// malformed request), distinct from the in-band GrantFetchReason verdicts. It is
	// the lever that makes the wantStatusOK split in gfAssertDirected / gfAssert-
	// DirectedObs non-vacuous: every in-band case sets wantStatusOK=true (so the
	// codes!=OK arm never fired before this), so the transport-error arm needs a case
	// that drives a synthetic status error. Meaningful only when wantStatusOK==false.
	wantStatusCode codes.Code
}

// gfDirectedCases is the per-reason expectation table for the wave-1
// grantFetchSuite fixtures (gfFleet): the clean OK fetch plus each of the four
// fail-closed/stall reasons, pinning the EXACT verdict (not just cross-end
// agreement). The grant_refs mirror the wave-1 fetchCase table exactly — the OK
// pair, the GRANT_NOT_FOUND ungranted service, the SESSION_NOT_LIVE revoked
// session, the GRANT_REF_MISMATCH ref bound to the wrong service, and the
// STORE_UNAVAILABLE §5.1 stall against the store-down session.
func gfDirectedCases() []gfDirectedCase {
	return []gfDirectedCase{
		{
			name:         "ok-clean-fetch",
			sessionID:    gfSessionLive,
			serviceID:    gfServiceGitHub,
			grantRef:     gfGrantRef(gfSessionLive, gfServiceGitHub),
			wantReason:   identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK,
			wantStall:    false,
			wantHasCred:  true,
			wantLocation: gfLocationHeader,
			wantStatusOK: true,
		},
		{
			name:         "deny-grant-not-found",
			sessionID:    gfSessionLive,
			serviceID:    gfServiceUngranted,
			grantRef:     gfGrantRef(gfSessionLive, gfServiceUngranted),
			wantReason:   identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_NOT_FOUND,
			wantStall:    false,
			wantHasCred:  false,
			wantStatusOK: true,
		},
		{
			name:         "deny-session-not-live",
			sessionID:    gfSessionRevoked,
			serviceID:    gfServiceGitHub,
			grantRef:     gfGrantRef(gfSessionRevoked, gfServiceGitHub),
			wantReason:   identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE,
			wantStall:    false,
			wantHasCred:  false,
			wantStatusOK: true,
		},
		{
			name:         "deny-grant-ref-mismatch",
			sessionID:    gfSessionLive,
			serviceID:    gfServiceGitHub,
			grantRef:     gfGrantRef(gfSessionLive, gfServiceUngranted),
			wantReason:   identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_REF_MISMATCH,
			wantStall:    false,
			wantHasCred:  false,
			wantStatusOK: true,
		},
		{
			name:         "stall-store-unavailable",
			sessionID:    gfSessionStoreDown,
			serviceID:    gfServiceGitHub,
			grantRef:     gfGrantRef(gfSessionStoreDown, gfServiceGitHub),
			wantReason:   identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE,
			wantStall:    true,
			wantHasCred:  false,
			wantStatusOK: true,
		},
	}
}

// gfReporter is the minimal failure sink the directed assertion drives — just a
// Helper()+Errorf shim. The real test passes *testing.T; the non-vacuity proof
// passes a capturing implementation so it can assert the assertion FIRES on a
// wrong-reason responder without aborting the parent test.
type gfReporter interface {
	Helper()
	Errorf(format string, args ...interface{})
}

// gfCaptureReporter records whether any failure was reported (and the first
// message), so the adversarial non-vacuity proof can prove the directed
// assertion is non-vacuous: a wrong-reason responder MUST make it fire.
type gfCaptureReporter struct {
	failed bool
	first  string
}

func (c *gfCaptureReporter) Helper() {}
func (c *gfCaptureReporter) Errorf(format string, args ...interface{}) {
	if !c.failed {
		c.first = fmt.Sprintf(format, args...)
	}
	c.failed = true
}

// gfAssertDirected drives ONE Fetch against the supplied responder (wired into a
// fresh generated fake — the registration both dual-run ends share) and asserts
// the EXACT contract verdict for the case: the in-band reason, the §5.1 stall
// split, and whether a credential rode back (plus its non-secret location on the
// OK case). It reports via gfReporter so the same assertion body backs both the
// real directed test and the adversarial non-vacuity proof. It records no secret
// bytes. It returns whether all assertions passed (for the non-vacuity proof to
// observe), independent of how the reporter handled the failures.
func gfAssertDirected(t gfReporter, responder func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error), c gfDirectedCase) {
	t.Helper()
	ctx := context.Background()
	f := identityv1fake.NewGrantFetchServiceFake()
	f.FetchResponder = responder
	resp, err := f.Fetch(ctx, &identityv1.GrantFetchRequest{
		SessionUuid:            c.sessionID,
		ServiceId:              c.serviceID,
		GrantRef:               c.grantRef,
		GrantExpiryUnixSeconds: gfExpiryFarFuture,
	})
	// Every wave-1 outcome — OK, the three denies, and the §5.1 stall — is an
	// IN-BAND reason, never a transport error. A status error here is itself a
	// contract violation for these cases.
	if c.wantStatusOK && err != nil {
		t.Errorf("%s: want in-band reason (codes.OK), got transport error %v", c.name, err)
		return
	}
	// The TRANSPORT-ERROR arm (wantStatusOK==false): the case expects a gRPC status
	// error (e.g. INVALID_ARGUMENT on a malformed request) DISTINCT from the in-band
	// reasons — so the wantStatusOK split is non-vacuous and the codes!=OK branch is
	// exercised. A transport error carries no in-band response, so we assert the
	// status code and stop (the in-band reason/credential checks below do not apply).
	if !c.wantStatusOK {
		if err == nil {
			t.Errorf("%s: want transport status %s, got in-band reason %s", c.name, c.wantStatusCode, resp.GetReason())
			return
		}
		if got := status.Code(err); got != c.wantStatusCode {
			t.Errorf("%s: transport status = %s, want %s", c.name, got, c.wantStatusCode)
		}
		return
	}
	if got := resp.GetReason(); got != c.wantReason {
		t.Errorf("%s: reason = %s, want %s", c.name, got, c.wantReason)
	}
	// reason_is_stall via the single reasonIsStall mirror (D80: no propose-only
	// import): the retry-only-a-stall split must be value-pinned, not merely
	// cross-end equal.
	if gotStall := reasonIsStall(resp.GetReason()); gotStall != c.wantStall {
		t.Errorf("%s: reason_is_stall = %t, want %t", c.name, gotStall, c.wantStall)
	}
	if gotHasCred := resp.GetCredential() != nil; gotHasCred != c.wantHasCred {
		t.Errorf("%s: has_credential = %t, want %t", c.name, gotHasCred, c.wantHasCred)
	}
	// A deny or a stall must carry NO credential (fail-closed / retry, never
	// degrade to egressing the placeholder); the OK fetch must carry it at the
	// non-secret header location. Only the location rides the assertion — never
	// the secret bytes (doc 16 §5.2).
	if c.wantHasCred {
		if got := resp.GetCredential().GetLocation(); got != c.wantLocation {
			t.Errorf("%s: credential_location = %q, want %q", c.name, got, c.wantLocation)
		}
	}
}

// gfAssertDirectedObs applies one gfDirectedCase's EXACT contract verdict to the
// per-scenario Observation form (the sorted "key=value" lines Observation.
// Canonical produces, parsed by dualrun.ParseObs) — the same value-level checks
// gfAssertDirected makes on a live response, but read from an Observation the
// dual run already recorded. It reports via the same gfReporter shim so the
// migrated DirectedReasons test can assert on BOTH ends of the run without a
// second out-of-band responder drive. It records no secret bytes (the
// Observation already carries only whether-a-credential-rode + its location).
func gfAssertDirectedObs(t gfReporter, end string, kv map[string]string, c gfDirectedCase) {
	t.Helper()
	// Every wave-1 outcome is an IN-BAND reason, never a transport error: the
	// scenario observation records status==OK for these cases.
	if c.wantStatusOK {
		if got := kv["status"]; got != codes.OK.String() {
			t.Errorf("%s/%s: status = %q, want in-band reason (OK)", end, c.name, got)
			return
		}
	} else {
		// TRANSPORT-ERROR arm: gfFetchObservation folds a status error into the
		// status= key ONLY (no reason/has_credential), so the directed check on the
		// Observation form pins the transport code and stops — the in-band reason /
		// credential keys are absent for a transport error.
		if got := kv["status"]; got != c.wantStatusCode.String() {
			t.Errorf("%s/%s: status = %q, want transport %s", end, c.name, got, c.wantStatusCode)
		}
		return
	}
	if got := kv["reason"]; got != c.wantReason.String() {
		t.Errorf("%s/%s: reason = %q, want %s", end, c.name, got, c.wantReason)
	}
	// reason_is_stall is exactly STORE_UNAVAILABLE (frozen-enum projection): the
	// retry-only-a-stall split must be value-pinned, not merely cross-end equal.
	if got := kv["reason_is_stall"]; got != fmt.Sprintf("%t", c.wantStall) {
		t.Errorf("%s/%s: reason_is_stall = %q, want %t", end, c.name, got, c.wantStall)
	}
	if got := kv["has_credential"]; got != fmt.Sprintf("%t", c.wantHasCred) {
		t.Errorf("%s/%s: has_credential = %q, want %t", end, c.name, got, c.wantHasCred)
	}
	// A deny/stall carries NO credential; the OK fetch carries it at the non-secret
	// header location. Only the location rides the assertion — never the secret
	// bytes (doc 16 §5.2).
	if c.wantHasCred {
		if got := kv["credential_location"]; got != c.wantLocation {
			t.Errorf("%s/%s: credential_location = %q, want %q", end, c.name, got, c.wantLocation)
		}
	}
}

// TestDualRun_GrantFetch_DirectedReasons is the per-reason DIRECTED complement of
// the wave-1 TestDualRun_GrantFetch_RealVsGeneratedFake gate. That gate proves
// the genuine grant-service Server and the generated fake AGREE scenario-for-
// scenario (res.OK() cross-end equality); this pins WHAT they must agree on — the
// exact contract verdict for each wave-1 scenario: the clean fetch is OK with the
// credential at the non-secret header location, GRANT_NOT_FOUND / SESSION_NOT_LIVE
// / GRANT_REF_MISMATCH each deny with no credential and reason_is_stall==false,
// and the §5.1 STORE_UNAVAILABLE fetch is the retryable stall (reason_is_stall==
// true) with no credential.
//
// It reads the ACTUAL per-scenario Observations from the SAME dual run the
// RealVsGeneratedFake gate drives (static real Server vs the generated fake) via
// Result.ObservationsFor — pinning the verdict on BOTH the genuine Server and the
// generated fake at once, with no second out-of-band responder drive. The
// companion NonVacuous test (which must inject a wrong-reason responder it cannot
// get from the real-vs-fake run) keeps the direct gfAssertDirected drive and
// proves these assertions actually FIRE on a wrong-reason responder.
func TestDualRun_GrantFetch_DirectedReasons(t *testing.T) {
	t.Parallel()
	real := grantFetchStaticRealEnd()
	fake := grantFetchEnd(honestGrantFetchResponder(gfFleet()))
	res, err := grantFetchSuite().Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	// The directed verdict is only meaningful on a green seam where every scenario
	// ran cleanly on both ends (a harness error would leave a nil Observation).
	if !res.OK() {
		t.Fatalf("grantFetchSuite dual-run DIVERGED before the directed check:\n%s", res.Report())
	}
	for _, c := range gfDirectedCases() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			realObs, fakeObs, ok := res.ObservationsFor(c.name)
			if !ok {
				t.Fatalf("scenario %q not found in dual-run observations", c.name)
			}
			if realObs == nil || fakeObs == nil {
				t.Fatalf("scenario %q is missing an observation (real=%v fake=%v)", c.name, realObs, fakeObs)
			}
			// Pin the verdict on EACH end the dual run compared.
			gfAssertDirectedObs(t, "real", dualrun.ParseObs(realObs.Canonical()), c)
			gfAssertDirectedObs(t, "fake", dualrun.ParseObs(fakeObs.Canonical()), c)
		})
	}
}

// TestDualRun_GrantFetch_DirectedReasons_NonVacuous is the ADVERSARIAL proof that
// each directed per-reason assertion is NON-VACUOUS: for every wave-1 scenario, a
// responder that returns the WRONG reason for THAT scenario MUST make exactly that
// scenario's directed assertion FAIL. Without this, the directed table above could
// pass for a degenerate reason (a typo'd expectation, an assertion that never
// compares anything) — the same vacuity trap the res.OK() cross-end equality check
// has and that this unit exists to close. We wrap the honest responder with a
// per-case override that flips the reason (OK<->a deny, each deny<->another reason)
// and drive the SAME gfAssertDirected body through a capturing reporter; it must
// report a failure for the flipped case. This lives only in this test — the
// committed responder is never drifted.
func TestDualRun_GrantFetch_DirectedReasons_NonVacuous(t *testing.T) {
	t.Parallel()
	honest := honestGrantFetchResponder(gfFleet())
	for _, c := range gfDirectedCases() {
		c := c
		// wrongReason is a verdict DISTINCT from the case's true reason: flipping to
		// it must trip at least the reason assertion (and, for the OK<->deny and
		// stall<->deny flips, the reason_is_stall / has_credential assertions too).
		wrongReason := identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_NOT_FOUND
		if c.wantReason == wrongReason {
			// The GRANT_NOT_FOUND case needs a different wrong verdict; SESSION_NOT_LIVE
			// is a distinct deny, so flipping to it still trips the reason assertion.
			wrongReason = identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE
		}
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// Drift ONLY this scenario's reason; all others stay honest so the flip is
			// localized to the case under test (proving the assertion is scoped to it).
			drifted := func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
				if req.GetSessionUuid() == c.sessionID && req.GetServiceId() == c.serviceID && req.GetGrantRef() == c.grantRef {
					return &identityv1.GrantFetchResponse{Reason: wrongReason}, nil
				}
				return honest(ctx, req)
			}
			cap := &gfCaptureReporter{}
			gfAssertDirected(cap, drifted, c)
			if !cap.failed {
				t.Fatalf("directed assertion for %q did not fire when the responder returned the wrong reason %s — the assertion is VACUOUS", c.name, wrongReason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TRANSPORT-ERROR split — exercising the gfAssertDirected wantStatusOK==false arm.
//
// gfAssertDirected / gfAssertDirectedObs split on wantStatusOK: an in-band reason
// (codes.OK on the wire, the verdict carried on GrantFetchResponse.reason) vs a
// TRANSPORT status error (codes != OK). Every wave-1 / §5.1 / §5.4 case is an
// in-band reason, so they all set wantStatusOK=true — which left the codes!=OK arm
// of both assertions NEVER fired, i.e. the split was vacuous. This block adds the
// missing half: a SYNTHETIC transport-error scenario (codes.InvalidArgument on a
// malformed request — a gRPC status DISTINCT from the in-band GrantFetchReason
// verdicts) so the wantStatusOK split is non-vacuous and the transport-error arm is
// genuinely exercised.
//
// The malformed-request fixture is fully synthetic (D50): a request whose service-id
// is the sentinel gfServiceMalformed makes the responder return a gRPC INVALID_-
// ARGUMENT status (no in-band response). This is NOT a contract widening — it models
// the transport-layer rejection of a structurally-invalid request, which is observed
// at the seam as a status code rather than an in-band reason. No grant-service real
// impl is dialed for this arm: the transport rejection is a synthetic responder
// behaviour driven through the generated fake (the registration both dual-run ends
// share), exactly as the NonVacuous adversarial drives a synthetic responder. No
// secret bytes ride anywhere (doc 16 §5.2): a status code carries no credential.

// gfServiceMalformed is the SYNTHETIC sentinel service-id that drives the transport-
// error arm: a Fetch carrying it is treated as a structurally-malformed request and
// rejected with a gRPC INVALID_ARGUMENT status (a transport error), distinct from
// every in-band GrantFetchReason verdict. It is obviously-synthetic and never a real
// service id; the in-band wave-1/§5.1/§5.4 cases never request it, so adding the
// transport-error path is behaviour-preserving for them.
const gfServiceMalformed = "svc-synthetic-grantfetch-MALFORMED"

// gfTransportErrorResponder wraps an honest in-band responder with the synthetic
// transport-rejection: a request for gfServiceMalformed returns a gRPC INVALID_-
// ARGUMENT status error (no in-band response), every other request defers to the
// honest verdict. The status error is the codes!=OK outcome the wantStatusOK split
// exists to handle.
func gfTransportErrorResponder(honest func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error)) func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
	return func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
		if req.GetServiceId() == gfServiceMalformed {
			// A structurally-malformed request is rejected at the transport: a gRPC
			// INVALID_ARGUMENT status, not an in-band reason. nil response so the
			// caller observes the status code only.
			return nil, status.Errorf(codes.InvalidArgument, "malformed grant-fetch request: synthetic transport rejection")
		}
		return honest(ctx, req)
	}
}

// gfTransportErrorCase is the directed case for the transport-error arm: a malformed
// request expects a codes.InvalidArgument TRANSPORT status (wantStatusOK=false),
// NOT an in-band reason. wantReason is left at the zero value and is not asserted on
// this arm (gfAssertDirected / gfAssertDirectedObs return after the status check when
// wantStatusOK is false).
func gfTransportErrorCase() gfDirectedCase {
	return gfDirectedCase{
		name:           "transport-error-malformed-request",
		sessionID:      gfSessionLive,
		serviceID:      gfServiceMalformed,
		grantRef:       gfGrantRef(gfSessionLive, gfServiceMalformed),
		wantStatusOK:   false,
		wantStatusCode: codes.InvalidArgument,
	}
}

// transportErrorSuite is a one-scenario dual-run suite over the transport-error
// responder: a malformed-request Fetch whose observation folds the gRPC status code
// into the status= key (gfFetchObservation records status= and nothing else on a
// transport error). Both ends are the SAME synthetic transport-error responder
// (fake-vs-fake), so they observe field-for-field identically and a divergence is
// attributable to the contract; the directed test reads the status verdict back off
// the run via ObservationsFor (no second out-of-band drive).
func transportErrorSuite() dualrun.Suite {
	c := gfTransportErrorCase()
	return dualrun.Suite{
		Seam: "ds-tlsproxy(swap-executor)<->identity GrantFetchService.Fetch (transport-error arm)",
		Scenarios: []dualrun.Scenario{
			{
				Name: c.name,
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					cl := identityv1.NewGrantFetchServiceClient(conn)
					resp, err := cl.Fetch(ctx, &identityv1.GrantFetchRequest{
						SessionUuid:            c.sessionID,
						ServiceId:              c.serviceID,
						GrantRef:               c.grantRef,
						GrantExpiryUnixSeconds: gfExpiryFarFuture,
					})
					return gfFetchObservation(resp, err), nil
				},
			},
		},
	}
}

// TestDualRun_GrantFetch_DirectedReasons_TransportError exercises the previously-
// vacuous wantStatusOK==false arm of the directed assertions: a malformed request is
// rejected at the TRANSPORT with codes.InvalidArgument — a gRPC status distinct from
// the in-band GrantFetchReason verdicts — so the codes!=OK branch of both
// gfAssertDirected (live response) and gfAssertDirectedObs (run Observation) is
// genuinely hit.
//
// It reads the ACTUAL status verdict back off the dual run via Result.ObservationsFor
// (the observation form, status= key) — the same ObservationsFor migration the
// in-band directed tests use, no second out-of-band drive — AND also drives the
// live-response form gfAssertDirected, which asserts on the gRPC err itself (the
// transport code the Observation folds into status=). No secret bytes ride the
// assertion (doc 16 §5.2): a status code carries no credential.
func TestDualRun_GrantFetch_DirectedReasons_TransportError(t *testing.T) {
	t.Parallel()
	c := gfTransportErrorCase()
	honest := honestGrantFetchResponder(gfFleet())
	responder := gfTransportErrorResponder(honest)

	// (1) Read the transport status verdict off the dual run's Observations — the
	// ObservationsFor migration: assert on the same fetch the cross-end equality
	// check compared, on BOTH ends, with no second out-of-band drive.
	real := grantFetchEnd(responder)
	fake := grantFetchEnd(responder)
	res, err := transportErrorSuite().Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("transport-error suite DIVERGED before the directed check:\n%s", res.Report())
	}
	realObs, fakeObs, ok := res.ObservationsFor(c.name)
	if !ok || realObs == nil || fakeObs == nil {
		t.Fatalf("scenario %q missing an observation (real=%v fake=%v)", c.name, realObs, fakeObs)
	}
	gfAssertDirectedObs(t, "real", dualrun.ParseObs(realObs.Canonical()), c)
	gfAssertDirectedObs(t, "fake", dualrun.ParseObs(fakeObs.Canonical()), c)

	// (2) Drive the live-response form too, so the gfAssertDirected wantStatusOK==
	// false arm asserts on the gRPC err object itself (not just the folded status=
	// key). This is the live counterpart the Observation form cannot make.
	gfAssertDirected(t, responder, c)
}

// TestDualRun_GrantFetch_DirectedReasons_TransportError_NonVacuous is the ADVERSARIAL
// proof that the transport-error arm is NON-VACUOUS: a responder that does NOT reject
// the malformed request at the transport (returns an in-band reason instead) MUST
// make the transport-error directed assertion FIRE. Without this, the wantStatusOK==
// false arm could pass for a degenerate reason. Two drifts are proved: (a) the
// responder returns an in-band OK instead of the status error (err==nil), and (b) it
// returns a DIFFERENT transport code (codes.Internal) than the expected codes.Invalid-
// Argument. Each must trip exactly the transport-error case. The drift lives only in
// this test; the committed responders are never drifted.
func TestDualRun_GrantFetch_DirectedReasons_TransportError_NonVacuous(t *testing.T) {
	t.Parallel()
	c := gfTransportErrorCase()
	honest := honestGrantFetchResponder(gfFleet())

	// (a) No transport rejection at all: the malformed request gets an in-band OK
	// (err==nil). The wantStatusOK==false arm must fire (want status, got in-band).
	t.Run("no-transport-error-is-caught", func(t *testing.T) {
		t.Parallel()
		inBandInstead := func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
			if req.GetServiceId() == gfServiceMalformed {
				return &identityv1.GrantFetchResponse{Reason: identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK}, nil
			}
			return honest(ctx, req)
		}
		cap := &gfCaptureReporter{}
		gfAssertDirected(cap, inBandInstead, c)
		if !cap.failed {
			t.Fatal("transport-error assertion did not fire when the responder returned an in-band reason instead of a status error — the wantStatusOK arm is VACUOUS")
		}
	})

	// (b) A DIFFERENT transport code (Internal) than the expected InvalidArgument:
	// the code mismatch must trip the assertion (proving it pins the exact code, not
	// merely "some error").
	t.Run("wrong-transport-code-is-caught", func(t *testing.T) {
		t.Parallel()
		wrongCode := func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
			if req.GetServiceId() == gfServiceMalformed {
				return nil, status.Errorf(codes.Internal, "synthetic wrong transport code")
			}
			return honest(ctx, req)
		}
		cap := &gfCaptureReporter{}
		gfAssertDirected(cap, wrongCode, c)
		if !cap.failed {
			t.Fatal("transport-error assertion did not fire when the responder returned codes.Internal instead of codes.InvalidArgument — the code pin is VACUOUS")
		}
	})
}

// ---------------------------------------------------------------------------
// TRANSPORT-ERROR arm on the REAL grant-service Server (grantfetchconform).
//
// The transport-error split above (gfTransportErrorResponder + the fake-vs-fake
// transportErrorSuite) proves the wantStatusOK==false arm is exercisable, but ONLY
// against a SYNTHETIC responder that deliberately manufactures a gRPC status. It
// never asks the QUESTION on the genuine grant-service Server dialed through
// grantfetchconform: when handed a structurally MALFORMED GrantFetchRequest (an
// empty request, a garbage grant_ref that cannot bind, an unknown session), does
// the REAL Server fold it into an in-band GrantFetchReason, or does it manufacture
// a transport status? A real-impl that classified a malformed request as a gRPC
// status (rather than an in-band reason) would change the seam's observable shape,
// and nothing on the real-Server path pinned which way it must go.
//
// This block answers it against the genuine Server surface and finds the ALL-IN-
// BAND case: grant-service/server.go folds EVERY documented deny/stall into
// GrantFetchResponse.reason and returns a nil error (open-question default #2;
// FetchWire tolerates even a nil request), so a contract-shaped request — however
// malformed its field VALUES — is classified IN-BAND, never as a manufactured
// status. On this seam a gRPC status only ever comes from a real transport fault,
// never from the fetch-domain classification. So — exactly as the unit scope
// anticipates for the all-in-band case — this block PINS that invariant as the
// real-Server transport-error directed assertion: it reads the status verdict off
// Result.ObservationsFor (the status= key gfFetchObservation records) for a battery
// of malformed requests driven against the real end, and asserts each is in-band
// (status==OK, a reason rode). A future real impl that STARTED manufacturing a
// status from a contract-shaped request would trip it at the central seam. It also
// drives the malformed battery — plus the nil request a gRPC client cannot express
// — straight against the genuine Server via the new grantfetchconform.RealServer-
// FetchStatus affordance. Purely ADDITIVE: it shares NO state with grantFetchSuite,
// the §5.1/§5.4 suites, the fake-vs-fake transport-error arm, or any negative
// control; it consumes the FROZEN GrantFetchReason enum READ-ONLY (projection
// only); no secret bytes ride any Observation (doc 16 §5.2 — a status carries no
// credential, and a malformed request fetches none).

// gfMalformedReq is one synthetic MALFORMED GrantFetchRequest for the real-Server
// transport-error arm plus its name. Each is a structurally-invalid fetch the real
// Server classifies IN-BAND (never a manufactured status). Synthetic only (D50).
type gfMalformedReq struct {
	name string
	req  *identityv1.GrantFetchRequest
}

// gfMalformedRequests is the battery of MALFORMED requests the real-Server
// transport-error arm drives against BOTH the genuine Server and the honest fake:
// an empty request and two garbage/wrong-prefix grant_refs (each fails the §9
// grant_ref bind guard FIRST -> GRANT_REF_MISMATCH), and a well-formed ref for an
// unknown session (bind passes, liveness fails -> SESSION_NOT_LIVE). The real
// Service checks the bind guard before liveness (service.go), exactly as the honest
// responder does, so the two ends agree field-for-field and the dual run is green —
// the point being pinned is the STATUS shape (in-band, not a manufactured gRPC
// status), which holds for every one. No secret rides any request.
func gfMalformedRequests() []gfMalformedReq {
	return []gfMalformedReq{
		{"empty-request", &identityv1.GrantFetchRequest{}},
		{"garbage-grant-ref", &identityv1.GrantFetchRequest{
			SessionUuid:            gfSessionLive,
			ServiceId:              gfServiceGitHub,
			GrantRef:               "::garbage::not-a-parseable-ref::",
			GrantExpiryUnixSeconds: gfExpiryFarFuture,
		}},
		{"grant-ref-wrong-prefix", &identityv1.GrantFetchRequest{
			SessionUuid:            gfSessionLive,
			ServiceId:              gfServiceGitHub,
			GrantRef:               "NOTgrant:" + gfSessionLive + ":" + gfServiceGitHub,
			GrantExpiryUnixSeconds: gfExpiryFarFuture,
		}},
		{"unknown-session-not-live", &identityv1.GrantFetchRequest{
			SessionUuid:            "session-synthetic-unknown-not-live",
			ServiceId:              gfServiceGitHub,
			GrantRef:               gfGrantRef("session-synthetic-unknown-not-live", gfServiceGitHub),
			GrantExpiryUnixSeconds: gfExpiryFarFuture,
		}},
	}
}

// gfTransportErrorRealSuite is a dual-run suite driving each malformed request
// through the SAME shared gfFetchObservation projection: on the real end
// (grantfetchconform.RegisterStaticReal over the static gfFleet spec) and the
// honest fake end, the malformed request folds to an in-band reason with a nil
// transport error, so gfFetchObservation records status==OK. Both ends agree
// field-for-field (the bind-then-liveness order matches), so a divergence is
// attributable to the contract, and the directed check reads the status verdict
// back off ObservationsFor.
func gfTransportErrorRealSuite() dualrun.Suite {
	reqs := gfMalformedRequests()
	scenarios := make([]dualrun.Scenario, 0, len(reqs))
	for _, m := range reqs {
		m := m
		scenarios = append(scenarios, dualrun.Scenario{
			Name: m.name,
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewGrantFetchServiceClient(conn)
				resp, err := cl.Fetch(ctx, m.req)
				return gfFetchObservation(resp, err), nil
			},
		})
	}
	return dualrun.Suite{
		Seam:      "ds-tlsproxy(swap-executor)<->identity GrantFetchService.Fetch (real-Server transport-error arm)",
		Scenarios: scenarios,
	}
}

// gfAssertRealNeverManufacturesStatus asserts, from a recorded Observation's parsed
// key/value set, that the end classified a MALFORMED request IN-BAND (status==OK
// with a GrantFetchReason on the response) rather than manufacturing a transport
// status. This is the all-in-band directed verdict for the real-Server transport-
// error arm: on this seam a gRPC status only ever comes from a transport fault,
// never from the impl. It reports via the shared gfReporter shim so the adversarial
// non-vacuity proof can drive the SAME body against a status-bearing observation and
// confirm it FIRES. No secret bytes are read (the Observation carries none).
func gfAssertRealNeverManufacturesStatus(t gfReporter, end, name string, kv map[string]string) {
	t.Helper()
	if got := kv["status"]; got != codes.OK.String() {
		t.Errorf("%s/%s: end manufactured transport status %q from a contract-shaped request; want in-band (status=OK) — a gRPC status must only ever come from transport, never the fetch-domain impl", end, name, got)
		return
	}
	// status==OK means an in-band response rode; gfFetchObservation then records the
	// reason. Its absence would mean a status was folded in without a code (never
	// happens), so pin that the in-band reason is present.
	if _, ok := kv["reason"]; !ok {
		t.Errorf("%s/%s: status=OK but no in-band reason recorded; the real Server must classify every contract-shaped request with a GrantFetchReason", end, name)
	}
}

// TestDualRun_GrantFetch_TransportError_RealServer pins the ALL-IN-BAND real-Server
// transport-error verdict: a battery of MALFORMED GrantFetchRequests driven against
// the genuine grant-service Server (via grantfetchconform) is classified IN-BAND
// (an in-band GrantFetchReason, status==OK), never a manufactured gRPC status. It
// reads the status verdict off Result.ObservationsFor on the real end (and the fake,
// which rode the same run) AND drives the battery — plus the nil request a gRPC
// client cannot express — straight against the Server through the new
// grantfetchconform.RealServerFetchStatus affordance. A real impl that began
// manufacturing a transport status from a contract-shaped request would fail this
// subtest at the central seam.
func TestDualRun_GrantFetch_TransportError_RealServer(t *testing.T) {
	t.Parallel()
	spec := staticGfSpec()
	real := grantFetchStaticRealEnd()
	fake := grantFetchEnd(honestGrantFetchResponder(gfFleet()))
	res, err := gfTransportErrorRealSuite().Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	// The directed verdict is only meaningful on a green seam where every malformed
	// scenario ran cleanly on both ends (a harness error would leave a nil Observation).
	if !res.OK() {
		t.Fatalf("real-Server transport-error suite DIVERGED before the directed check:\n%s", res.Report())
	}

	// (1) Read the status verdict off the dual run's Observations on BOTH ends — the
	// central-seam pin, no second out-of-band drive.
	for _, m := range gfMalformedRequests() {
		m := m
		t.Run("observed/"+m.name, func(t *testing.T) {
			t.Parallel()
			realObs, fakeObs, ok := res.ObservationsFor(m.name)
			if !ok || realObs == nil || fakeObs == nil {
				t.Fatalf("scenario %q missing an observation (real=%v fake=%v)", m.name, realObs, fakeObs)
			}
			gfAssertRealNeverManufacturesStatus(t, "real", m.name, dualrun.ParseObs(realObs.Canonical()))
			gfAssertRealNeverManufacturesStatus(t, "fake", m.name, dualrun.ParseObs(fakeObs.Canonical()))
		})
	}

	// (2) Drive the malformed battery — plus the nil request a gRPC client cannot
	// express — straight against the genuine Server via the RealServerFetchStatus
	// affordance, and confirm each yields codes.OK with an in-band reason and NO
	// credential: the real Server never manufactures a transport status, and a
	// malformed request fetches no secret (doc 16 §5.2).
	directCases := append([]gfMalformedReq{{"nil-request", nil}}, gfMalformedRequests()...)
	for _, m := range directCases {
		m := m
		t.Run("direct/"+m.name, func(t *testing.T) {
			t.Parallel()
			code, resp, ferr := grantfetchconform.RealServerFetchStatus(spec, m.req)
			if code != codes.OK || ferr != nil {
				t.Errorf("%s: real Server manufactured transport status %s (err=%v) from a contract-shaped request; want codes.OK / in-band", m.name, code, ferr)
			}
			if resp == nil {
				t.Fatalf("%s: nil response with no error; the real Server must classify the request in-band", m.name)
			}
			// A malformed request is a fail-closed deny — no credential rides. Only the
			// non-secret presence is asserted, never the secret bytes (doc 16 §5.2).
			if resp.GetCredential() != nil {
				t.Errorf("%s: a malformed request unexpectedly carried a credential (reason=%s)", m.name, resp.GetReason())
			}
			// The verdict rode in-band on the response, not as a status.
			if resp.GetReason() == identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK {
				t.Errorf("%s: malformed request classified REASON_OK; want a fail-closed in-band deny reason", m.name)
			}
		})
	}
}

// TestDualRun_GrantFetch_TransportError_RealServer_NonVacuous is the ADVERSARIAL
// proof that the all-in-band pin is NON-VACUOUS: if an end EVER manufactured a
// transport status from a contract-shaped request, gfFetchObservation would fold it
// into the status= key (no reason), and gfAssertRealNeverManufacturesStatus MUST
// fire. Two synthetic manufactured codes are proved (InvalidArgument and Internal),
// so the pin keys on "not in-band", not one specific code. The drift lives only in
// this test; the genuine Server is never modified (no production edit).
func TestDualRun_GrantFetch_TransportError_RealServer_NonVacuous(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		code codes.Code
	}{
		{"manufactured-invalid-argument-is-caught", codes.InvalidArgument},
		{"manufactured-internal-is-caught", codes.Internal},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			statusObs := gfFetchObservation(nil, status.Errorf(tc.code, "synthetic manufactured transport status"))
			cap := &gfCaptureReporter{}
			gfAssertRealNeverManufacturesStatus(cap, "real", "synthetic-status", dualrun.ParseObs(statusObs.Canonical()))
			if !cap.failed {
				t.Fatalf("in-band pin did NOT fire on a manufactured %s status — the real-Server transport-error assertion is VACUOUS", tc.code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// §5.4 suspend / park-resume grant-eviction lifecycle, lifted into the central
// dual-run.
//
// The §5.4 own-session invariants — suspend EVICTS a session's grants (a
// subsequent fetch fails closed SESSION_NOT_LIVE), park KEEPS the cache but
// refuses a NEW fetch (SESSION_PARKED) while a warmed pair still rides, and resume
// re-validates liveness + TTLs and admits the session again — are today pinned
// ONLY module-locally in identity/grant-service/service_test.go
// (TestSuspend_EvictsGrants / TestParkResume_SurvivesAndReValidates). This block
// lifts them into the cross-tree central dual-run, mirroring how the §5.1
// cache-rides-outage lift took the warm/stall split central: it reuses the SAME
// stateful gfWarmFleet responder + the SAME shared gfFetchObservation projection,
// extended with the §5.4 suspend/park/resume transition verbs.
//
// As with the §5.1 warm-cache suite this is fake-vs-fake (two independent
// gfWarmFleet responders over identical construction): the suspend/park/resume
// LIFECYCLE is the module-local own-session pin, with no grantfetchconform
// real-Server adapter seam for it (unlike the §5.1 SetStoreAvailable lever), so
// the central lift drives the honest stateful §5.4 model against the generated
// fake the SAME way grantFetchWarmCacheSuite does. The two ends share NO state
// (separate fleets) and walk the SAME ordered lifecycle, so a divergence is
// attributable to the contract, never the fixture. It is purely ADDITIVE: it adds
// a SECOND suite/test that shares no state with grantFetchSuite or the §5.1 suite,
// so every wave-1 and §5.1 scenario stays byte-untouched. No secret bytes ride any
// Observation (doc 16 §5.2): only WHETHER a credential rode + its non-secret
// location, exactly as the wave-1 / §5.1 suites record.
//
// The transition scenarios (suspend-onset, park-onset, resume-onset) flip BOTH end
// fleets, because the suite runner calls each scenario once per end (real then
// fake) and a scenario closure cannot tell which conn it is driving: flipping only
// one would leave the other end's lifecycle un-advanced and manufacture a spurious
// divergence. suspend/park/resume are idempotent for the (session) they target —
// suspend re-deletes an already-evicted cache and re-sets not-live; park re-sets
// the parked bit; resume re-clears it and re-asserts live — so flipping both on
// each of the two per-scenario invocations is safe and leaves both ends in the
// same lifecycle state.

// gfSuspendParkResumeSuite is the §5.4 grant-eviction lifecycle conformance suite.
// Its scenarios run in DECLARATION ORDER against the (stateful) responders, walking
// the full own-session lifecycle on two separate sessions:
//
//	gfSessionWarm  : warm a grant -> SUSPEND -> a subsequent fetch fails closed
//	                 SESSION_NOT_LIVE with no credential (eviction: even the warmed
//	                 pair is gone).
//	gfSessionColdMiss: warm a github grant -> PARK -> the warmed github pair still
//	                 rides (OK), a NEW npm pair is refused (SESSION_PARKED) -> RESUME
//	                 -> the npm pair is admitted again (OK with the credential).
//
// The three transition scenarios (suspend-/park-/resume-onset) advance BOTH end
// fleets and record the no-op transition observation (the flip itself surfaces
// nothing on the Fetch wire). Both ends share no state; the ordered walk is
// replayed identically on each, so a divergence is attributable to the contract.
func gfSuspendParkResumeSuite(realFleet, fakeFleet *gfWarmFleet) dualrun.Suite {
	return dualrun.Suite{
		Seam: "ds-tlsproxy(swap-executor)<->identity GrantFetchService.Fetch (§5.4 suspend/park-resume)",
		Scenarios: []dualrun.Scenario{
			{
				// 1. Pre-suspend WARM: the in-flight session's first github fetch is a
				// cache miss while live -> OK, warming the pair.
				Name: "warm-grant-before-suspend-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
				},
			},
			{
				// 2. SUSPEND fires on BOTH end fleets: the cache entry is evicted AND the
				// session flips not-live. A fleet-state transition, surfacing nothing on
				// the Fetch wire — recorded as the explicit suspend-onset step.
				Name: "suspend-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realFleet.suspend(gfSessionWarm)
					fakeFleet.suspend(gfSessionWarm)
					return dualrun.NewObservation().Set("session_live", "false"), nil
				},
			},
			{
				// 3. Post-suspend FETCH fails closed: even the previously-warmed pair is
				// gone (eviction, not mere not-live) -> SESSION_NOT_LIVE, no credential.
				// reason==SESSION_NOT_LIVE / has_credential==false.
				Name: "fetch-after-suspend-fails-closed",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
				},
			},
			{
				// 4. On a SECOND live session, warm a github grant before parking, so it
				// survives the park and rides -> OK, warming the pair.
				Name: "warm-grant-before-park-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
			{
				// 5. PARK fires on BOTH end fleets: the cache SURVIVES (grants survive
				// snapshot+park, §5.4) but a NEW fetch will be refused. Transition step.
				Name: "park-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realFleet.park(gfSessionColdMiss)
					fakeFleet.park(gfSessionColdMiss)
					return dualrun.NewObservation().Set("session_parked", "true"), nil
				},
			},
			{
				// 6. The PARKED session's WARMED github pair still RIDES: cache hit -> OK
				// with the credential, even while parked (grants survive park). reason==OK
				// / has_credential==true.
				Name: "parked-warm-pair-still-rides-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
			{
				// 7. A NEW (not-yet-cached) npm pair on the SAME parked session is a cache
				// MISS -> the park refuses it: SESSION_PARKED, no credential (a parked
				// session fetches no NEW grants until resume). reason==SESSION_PARKED /
				// has_credential==false.
				Name: "parked-new-fetch-refused",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceNpm), nil
				},
			},
			{
				// 8. RESUME fires on BOTH end fleets: clears parked and re-validates
				// liveness (the session is within deadline, so it stays live). Transition
				// step.
				Name: "resume-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realFleet.resume(gfSessionColdMiss, true)
					fakeFleet.resume(gfSessionColdMiss, true)
					return dualrun.NewObservation().Set("session_parked", "false"), nil
				},
			},
			{
				// 9. Post-resume, the previously-refused npm pair is ADMITTED again: cache
				// miss -> store read -> OK with the credential (the session fetches NEW
				// grants again). reason==OK / has_credential==true.
				Name: "fetch-after-resume-admits-again-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceNpm), nil
				},
			},
		},
	}
}

// TestDualRun_GrantFetch_SuspendParkResume lifts the doc 16 §5.4 grant-eviction
// lifecycle into the central dual-run: over one ordered walk, a SUSPEND evicts a
// warmed session (a subsequent fetch fails closed SESSION_NOT_LIVE with no
// credential), and on a second session a PARK keeps the cache (a warmed pair still
// rides OK) while refusing a NEW fetch (SESSION_PARKED), then a RESUME admits the
// session again (OK with the credential). The honest stateful §5.4 model and the
// generated fake observe the lifecycle field-for-field identically. Both ends are
// independent stateful responders over identical fleets driven by the same ordered
// scenarios, so a divergence is attributable to the contract. Additive: it shares
// no state with grantFetchSuite or the §5.1 warm-cache suite, so those stay green.
// (service_test.go TestSuspend_EvictsGrants / TestParkResume_SurvivesAndReValidates
// remain the module-local pins this lifts from.)
func TestDualRun_GrantFetch_SuspendParkResume(t *testing.T) {
	t.Parallel()
	realFleet := newGfWarmFleet()
	fakeFleet := newGfWarmFleet()
	real := grantFetchEnd(realFleet.responder())
	fake := grantFetchEnd(fakeFleet.responder())
	res, err := gfSuspendParkResumeSuite(realFleet, fakeFleet).Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("identity GrantFetchService §5.4 suspend/park-resume seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suspend/park-resume suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestDualRun_GrantFetch_SuspendParkResume_DirectedReasons is the DIRECTED
// complement of the §5.4 dual-run (mirroring WarmCacheRidesOutage_DirectedReasons):
// the dual-run above proves the honest §5.4 model and the generated fake observe
// the lifecycle field-for-field IDENTICALLY, but cross-end equality alone cannot
// tell a faithful pair from a pair that agrees on the WRONG verdict (both ends
// could return GRANT_NOT_FOUND for the suspended session and res.OK() would still
// be green). This pins the EXACT in-band reasons the module-local §5.4 pins assert
// — SESSION_NOT_LIVE after suspend, OK on the parked warm-pair ride, SESSION_PARKED
// on the parked new-fetch refusal, and OK again after resume — so the central lift
// carries the contract VALUES, not just cross-end agreement.
//
// It reads the ACTUAL per-scenario Observations the dual run already drove
// (Result.ObservationsFor) instead of constructing a SECOND out-of-band responder,
// so it asserts on the same fetch the real-vs-fake equality check compared, pinning
// the verdict on BOTH ends at once. No secret bytes ride any Observation (doc 16
// §5.2): each pins only WHETHER a credential rode and its non-secret location.
func TestDualRun_GrantFetch_SuspendParkResume_DirectedReasons(t *testing.T) {
	t.Parallel()
	realFleet := newGfWarmFleet()
	fakeFleet := newGfWarmFleet()
	real := grantFetchEnd(realFleet.responder())
	fake := grantFetchEnd(fakeFleet.responder())
	res, err := gfSuspendParkResumeSuite(realFleet, fakeFleet).Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	// The directed verdict is only meaningful if the seam is green AND every
	// scenario actually ran cleanly on both ends (an end-error would leave a nil
	// Observation, so the assertions below would otherwise silently pass).
	if !res.OK() {
		t.Fatalf("§5.4 suspend/park-resume dual-run DIVERGED before the directed check:\n%s", res.Report())
	}

	// assertObs reads both ends' Observation for one scenario from the run and
	// applies the per-key contract checks to EACH end (real and fake), proving the
	// verdict value on the impls the dual run already compared.
	assertObs := func(scenario string, check func(end string, kv map[string]string)) {
		t.Helper()
		realObs, fakeObs, ok := res.ObservationsFor(scenario)
		if !ok {
			t.Fatalf("scenario %q not found in dual-run observations", scenario)
		}
		if realObs == nil || fakeObs == nil {
			t.Fatalf("scenario %q is missing an observation (real=%v fake=%v)", scenario, realObs, fakeObs)
		}
		check("real", dualrun.ParseObs(realObs.Canonical()))
		check("fake", dualrun.ParseObs(fakeObs.Canonical()))
	}

	// 1. Pre-suspend warm fetch -> OK with the credential.
	assertObs("warm-grant-before-suspend-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s pre-suspend warm fetch reason = %q, want OK", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s pre-suspend warm fetch must carry the credential, has_credential = %q", end, got)
		}
	})

	// 2. Suspend onset — a fleet transition, nothing on the Fetch wire.
	assertObs("suspend-onset", func(end string, kv map[string]string) {
		if got := kv["session_live"]; got != "false" {
			t.Errorf("%s suspend-onset session_live = %q, want false", end, got)
		}
	})

	// 3. Post-suspend fetch FAILS CLOSED: the eviction is seam-visible as
	// SESSION_NOT_LIVE with no credential (even the warmed pair is gone), and it is
	// NOT the retryable stall.
	assertObs("fetch-after-suspend-fails-closed", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE.String() {
			t.Errorf("%s post-suspend reason = %q, want SESSION_NOT_LIVE", end, got)
		}
		if got := kv["reason_is_stall"]; got != "false" {
			t.Errorf("%s post-suspend reason_is_stall = %q, want false (eviction is a definitive deny, not a stall)", end, got)
		}
		if got := kv["has_credential"]; got != "false" {
			t.Errorf("%s a suspended-session fetch must carry no credential, has_credential = %q", end, got)
		}
	})

	// 4. Pre-park warm fetch on the second session -> OK with the credential.
	assertObs("warm-grant-before-park-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s pre-park warm fetch reason = %q, want OK", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s pre-park warm fetch must carry the credential, has_credential = %q", end, got)
		}
	})

	// 5. Park onset — a fleet transition, nothing on the Fetch wire.
	assertObs("park-onset", func(end string, kv map[string]string) {
		if got := kv["session_parked"]; got != "true" {
			t.Errorf("%s park-onset session_parked = %q, want true", end, got)
		}
	})

	// 6. The parked session's WARMED pair still RIDES: OK with the credential, no
	// stall — grants survive snapshot+park (§5.4).
	assertObs("parked-warm-pair-still-rides-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s parked-ride reason = %q, want OK", end, got)
		}
		if got := kv["reason_is_stall"]; got != "false" {
			t.Errorf("%s parked-ride reason_is_stall = %q, want false", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s parked warm-pair ride must carry the credential, has_credential = %q", end, got)
		}
		if got := kv["credential_location"]; got != gfLocationHeader {
			t.Errorf("%s parked-ride credential_location = %q, want %q", end, got, gfLocationHeader)
		}
	})

	// 7. A NEW fetch on the parked session is REFUSED: SESSION_PARKED, no credential
	// — a parked session fetches no NEW grants until resume, and it is NOT the
	// retryable stall (the refusal is the park policy, not a store outage).
	assertObs("parked-new-fetch-refused", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_PARKED.String() {
			t.Errorf("%s parked new-fetch reason = %q, want SESSION_PARKED", end, got)
		}
		if got := kv["reason_is_stall"]; got != "false" {
			t.Errorf("%s parked new-fetch reason_is_stall = %q, want false (park refusal is a deny, not a stall)", end, got)
		}
		if got := kv["has_credential"]; got != "false" {
			t.Errorf("%s a parked new-fetch refusal must carry no credential, has_credential = %q", end, got)
		}
	})

	// 8. Resume onset — a fleet transition, nothing on the Fetch wire.
	assertObs("resume-onset", func(end string, kv map[string]string) {
		if got := kv["session_parked"]; got != "false" {
			t.Errorf("%s resume-onset session_parked = %q, want false", end, got)
		}
	})

	// 9. Post-resume, the previously-refused NEW pair is ADMITTED again: OK with the
	// credential — the session fetches NEW grants once more.
	assertObs("fetch-after-resume-admits-again-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s post-resume reason = %q, want OK", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s post-resume admit must carry the credential, has_credential = %q", end, got)
		}
		if got := kv["credential_location"]; got != gfLocationHeader {
			t.Errorf("%s post-resume credential_location = %q, want %q", end, got, gfLocationHeader)
		}
	})
}

// TestDualRun_GrantFetch_ParkedWarmPairRideConsultsNoStore closes the §5.4 gap the
// directed-reasons test left open: SuspendParkResume_DirectedReasons pins that the
// parked session's warmed pair RIDES as OK (reason==OK, has_credential==true), but
// reason==OK is observed BOTH for a cache-HIT ride AND for a fresh store read — so
// "observed OK" alone does not prove the contract requirement that an in-flight/
// parked session serves its warmed grant FROM CACHE WITHOUT consulting the store
// (doc 16 §5.1 "in-flight sessions ride their session-cached grants" / §5.4 "grants
// survive snapshot+park"). This pins the no-store-read fact directly via the
// responder's store-read counter: across the parked-warm-pair ride the store-read
// count is UNCHANGED, so the ride was served from cache.
//
// It brackets the ride with counter snapshots captured by closure inside the ordered
// dual-run scenarios: the count is sampled right after park-onset (pre-ride) and
// right after the ride, on BOTH the real and fake fleets (each scenario drives its
// own conn's fleet exactly once, Suite.Run real-then-fake per scenario). A cache hit
// returns before the store-read leg, so the delta MUST be zero on both ends.
// Additive: it shares no state with the existing §5.4 suite/tests (its own fresh
// fleets) and reads only the non-secret store-read count — no secret bytes (doc 16
// §5.2).
func TestDualRun_GrantFetch_ParkedWarmPairRideConsultsNoStore(t *testing.T) {
	t.Parallel()
	realFleet := newGfWarmFleet()
	fakeFleet := newGfWarmFleet()
	real := grantFetchEnd(realFleet.responder())
	fake := grantFetchEnd(fakeFleet.responder())

	// Store-read snapshots bracketing the parked-warm-pair ride, captured by closure.
	// Each is [realCount, fakeCount]; the parked ride must add zero on both ends.
	var preRideReal, preRideFake int
	var postRideReal, postRideFake int

	suite := dualrun.Suite{
		Seam: "§5.4 parked-warm-pair ride consults no store",
		Scenarios: []dualrun.Scenario{
			{
				// Warm the github pair while live (a genuine store read on each fleet).
				Name: "warm-grant-before-park-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
			{
				// Park BOTH fleets, then snapshot each fleet's store-read count as the
				// pre-ride baseline (the warm above bumped each fleet exactly once).
				Name: "park-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realFleet.park(gfSessionColdMiss)
					fakeFleet.park(gfSessionColdMiss)
					preRideReal = realFleet.storeReadCount()
					preRideFake = fakeFleet.storeReadCount()
					return dualrun.NewObservation().Set("session_parked", "true"), nil
				},
			},
			{
				// The parked session's WARMED github pair RIDES: cache hit -> OK. This
				// must consult NO store. Snapshot each fleet's count right after the ride
				// (Suite.Run drives real then fake within this scenario, so both fleets
				// have served the ride by the time the fake-end invocation records).
				Name: "parked-warm-pair-still-rides-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					obs := gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub)
					postRideReal = realFleet.storeReadCount()
					postRideFake = fakeFleet.storeReadCount()
					return obs, nil
				},
			},
		},
	}

	res, err := suite.Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("parked-ride no-store-read suite DIVERGED:\n%s", res.Report())
	}

	// The ride is OK with the credential on both ends (the verdict the directed test
	// pins) — re-confirm here off the run's Observation so the no-store-read claim is
	// anchored to an actual successful ride, not a silent failure.
	realObs, fakeObs, ok := res.ObservationsFor("parked-warm-pair-still-rides-ok")
	if !ok || realObs == nil || fakeObs == nil {
		t.Fatalf("parked ride scenario missing an observation (real=%v fake=%v)", realObs, fakeObs)
	}
	for end, obs := range map[string]*dualrun.Observation{"real": realObs, "fake": fakeObs} {
		kv := dualrun.ParseObs(obs.Canonical())
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s parked ride reason = %q, want OK", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s parked ride must carry the credential, has_credential = %q", end, got)
		}
	}

	// The contract: the parked ride served from cache, so the store-read count is
	// UNCHANGED across the ride on BOTH ends. A targeted mutation that makes the ride
	// re-read the store (skip the cache hit) bumps the delta and fails exactly here.
	if got := postRideReal - preRideReal; got != 0 {
		t.Errorf("parked warm-pair ride consulted the store on the REAL end: store-read delta = %d, want 0 (the ride must serve from cache)", got)
	}
	if got := postRideFake - preRideFake; got != 0 {
		t.Errorf("parked warm-pair ride consulted the store on the FAKE end: store-read delta = %d, want 0 (the ride must serve from cache)", got)
	}
}

// TestDualRun_GrantFetch_ParkedWarmPairRideConsultsNoStore_NonVacuous is the
// ADVERSARIAL proof that the no-store-read assertion is NON-VACUOUS: a responder
// whose parked ride RE-READS the store (it does NOT serve the warmed pair from cache)
// MUST make the store-read delta non-zero across the ride. Without this, the counter
// assertion could pass for a degenerate reason (a counter that never moves, a ride
// that never happens). We drive a fleet whose cache is CLEARED before the ride so the
// ride is forced down the store-read leg, and assert the count moved — proving the
// honest test's zero-delta is meaningful. The drift lives only in this test.
func TestDualRun_GrantFetch_ParkedWarmPairRideConsultsNoStore_NonVacuous(t *testing.T) {
	t.Parallel()
	fleet := newGfWarmFleet()
	resp := fleet.responder()
	ctx := context.Background()

	// Warm the github pair while live (one store read).
	warmReq := &identityv1.GrantFetchRequest{
		SessionUuid:            gfSessionColdMiss,
		ServiceId:              gfServiceGitHub,
		GrantRef:               gfGrantRef(gfSessionColdMiss, gfServiceGitHub),
		GrantExpiryUnixSeconds: gfExpiryFarFuture,
	}
	if _, err := resp(ctx, warmReq); err != nil {
		t.Fatalf("warm: %v", err)
	}
	if fleet.storeReadCount() != 1 {
		t.Fatalf("warm fetch store-read count = %d, want 1", fleet.storeReadCount())
	}

	// DRIFT: clear the warmed cache so the "ride" is forced to re-read the store —
	// the very violation the honest no-store-read assertion guards against. The honest
	// model would serve this from cache (zero store reads); the drift re-reads.
	delete(fleet.cache, gfSessionColdMiss)

	before := fleet.storeReadCount()
	if _, err := resp(ctx, warmReq); err != nil {
		t.Fatalf("ride: %v", err)
	}
	if got := fleet.storeReadCount() - before; got == 0 {
		t.Fatal("a parked ride that re-reads the store produced a zero store-read delta — the no-store-read assertion is VACUOUS")
	}
}

// TestDualRun_GrantFetch_SuspendParkResume_NonVacuous is the ADVERSARIAL proof that
// the §5.4 lifecycle suite is NON-VACUOUS: a fake that violates a §5.4 invariant —
// here, one that RESUMES a still-SUSPENDED (dead) session and re-admits its evicted
// grant, and one that SKIPS suspend cache-eviction (still riding the warmed pair
// after suspend) — MUST be caught by the dual-run (a divergence) or by the directed
// reasons. Without this, the §5.4 suite could pass for a degenerate reason (a
// responder that never actually evicts/refuses). The drift lives only in this test;
// the committed responder is never drifted.
//
// The drift is asymmetric (only the "fake" end is drifted) so the honest §5.4 model
// and the drifted fake DIVERGE — exactly the lying-fake the harness exists to catch.
func TestDualRun_GrantFetch_SuspendParkResume_NonVacuous(t *testing.T) {
	t.Parallel()

	// (a) A fake that SKIPS suspend cache-eviction: it never drops the warmed pair,
	// so after suspend the previously-warmed (session, service) still rides OK. The
	// honest model evicts (SESSION_NOT_LIVE), so the post-suspend fetch DIVERGES.
	t.Run("skips-suspend-eviction-is-caught", func(t *testing.T) {
		t.Parallel()
		honestFleet := newGfWarmFleet()
		driftFleet := newGfWarmFleet()
		// The drifted fake's suspend is a NO-OP on the cache: it flips not-live but
		// does NOT evict — except gfWarmFleet's responder gates on live first, so to
		// make the drift observable we keep the session live AND keep its cache. The
		// honest model evicts + flips not-live, the drift keeps both, so the
		// post-suspend warmed fetch is OK on the drift and SESSION_NOT_LIVE on honest.
		real := grantFetchEnd(honestFleet.responder())
		fake := grantFetchEnd(driftFleet.responder())
		suite := dualrun.Suite{
			Seam: "§5.4 suspend-eviction non-vacuity",
			Scenarios: []dualrun.Scenario{
				{
					Name: "warm",
					Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
						return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
					},
				},
				{
					Name: "suspend",
					Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
						honestFleet.suspend(gfSessionWarm) // honest: evict + not-live
						// drift: SKIP eviction entirely (the bug) — leave the warmed pair live.
						return dualrun.NewObservation().Set("session_live", "false"), nil
					},
				},
				{
					Name: "fetch-after-suspend",
					Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
						return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
					},
				},
			},
		}
		res, err := suite.Run(context.Background(), real, fake)
		if err != nil {
			t.Fatalf("dual-run: %v", err)
		}
		if res.OK() {
			t.Fatal("a fake that skips suspend cache-eviction passed the §5.4 seam — the suspend/park-resume gate is not firing")
		}
	})

	// (b) A fake that RESUMES a dead (still-suspended) session and re-admits it: the
	// honest model leaves a suspended session not-live (resume of a never-suspended
	// session is a no-op here; the drift force-re-admits the evicted session). The
	// post-resume fetch is OK on the drift and SESSION_NOT_LIVE on honest -> diverge.
	t.Run("resumes-dead-session-is-caught", func(t *testing.T) {
		t.Parallel()
		honestFleet := newGfWarmFleet()
		driftFleet := newGfWarmFleet()
		real := grantFetchEnd(honestFleet.responder())
		fake := grantFetchEnd(driftFleet.responder())
		suite := dualrun.Suite{
			Seam: "§5.4 resume-dead-session non-vacuity",
			Scenarios: []dualrun.Scenario{
				{
					Name: "warm",
					Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
						return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
					},
				},
				{
					Name: "suspend",
					Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
						honestFleet.suspend(gfSessionColdMiss)
						driftFleet.suspend(gfSessionColdMiss)
						return dualrun.NewObservation().Set("session_live", "false"), nil
					},
				},
				{
					Name: "resume-dead",
					Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
						// honest: a suspended session is dead (not-live), and resume of a
						// not-live session must NOT re-admit it (fail-closed §5.4). The honest
						// model leaves it not-live (resume with stillLive=false). The drift
						// FORCE-re-admits it (stillLive=true + re-warm), the §5.4 violation.
						honestFleet.resume(gfSessionColdMiss, false)
						driftFleet.live[gfSessionColdMiss] = true // drift: re-admit a dead session
						return dualrun.NewObservation().Set("session_parked", "false"), nil
					},
				},
				{
					Name: "fetch-after-resume",
					Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
						return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
					},
				},
			},
		}
		res, err := suite.Run(context.Background(), real, fake)
		if err != nil {
			t.Fatalf("dual-run: %v", err)
		}
		if res.OK() {
			t.Fatal("a fake that resumes a dead (suspended) session passed the §5.4 seam — the suspend/park-resume gate is not firing")
		}
	})
}

// ---------------------------------------------------------------------------
// §3 SuspendReason projection — the FROZEN attach.v1 SuspendReason enum consumed
// READ-ONLY (D77).
//
// The §5.4 suspend signal that drives grant eviction carries a SuspendReason on
// the attach.v1 SessionState (proto/gen/go/.../attach/v1) — the D77 genuine-threat
// classification of WHY a session was suspended. This block consumes that frozen
// enum READ-ONLY as a §3 projection only: it asserts that the suspend reasons the
// §5.4 eviction lifecycle can carry are exactly the frozen attach.v1 values, with
// no re-declaration and no new enum. It NEVER projects a secret (a SuspendReason is
// a non-secret classification), and it does NOT widen the enum or propose a new
// D-number — it pins the read-only projection so a drift in the frozen attach.v1
// surface (a renamed/removed reason the eviction lifecycle leans on) is caught
// here at the central seam.

// TestDualRun_GrantFetch_SuspendReasonProjectionIsReadOnly pins that the §5.4
// suspend-eviction lifecycle's suspend reasons project from the FROZEN attach.v1
// SuspendReason enum READ-ONLY (D77): the D77 genuine-threat suspension class
// (POLICY_BREACH) and the offboarding/user-initiated class (USER) — the two §5.4
// drivers of grant eviction (doc 16 §5.4 "on suspend/kill/admin-revoke ... grants
// are evicted on the suspend signal"; §11.2 offboarding fires the existing suspend
// signal) — are exactly the frozen enum values, consumed by their canonical String
// projection with no re-declaration. This is a projection-only read of the frozen
// surface; it mints no enum and proposes no D-number.
func TestDualRun_GrantFetch_SuspendReasonProjectionIsReadOnly(t *testing.T) {
	t.Parallel()
	// The frozen attach.v1 SuspendReason values the §5.4 eviction lifecycle leans on,
	// projected READ-ONLY by their canonical String form. POLICY_BREACH is the D77
	// genuine-threat suspension class; USER is the offboarding/user-initiated class
	// (§11.2 fires the existing suspend signal). The UNSPECIFIED zero value anchors
	// the enum's frozen base. No re-declaration: these are the generated constants.
	cases := []struct {
		reason attachv1.SuspendReason
		want   string
	}{
		{attachv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED, "SUSPEND_REASON_UNSPECIFIED"},
		{attachv1.SuspendReason_SUSPEND_REASON_USER, "SUSPEND_REASON_USER"},
		{attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, "SUSPEND_REASON_POLICY_BREACH"},
	}
	for _, c := range cases {
		if got := c.reason.String(); got != c.want {
			t.Errorf("frozen attach.v1 SuspendReason projection drifted: %d.String() = %q, want %q", int32(c.reason), got, c.want)
		}
	}
	// The projection is a non-secret classification: it must never carry credential
	// material (doc 16 §5.2). A SuspendReason String is one of the frozen enum names
	// — assert none of them contains the synthetic secret, the structural no-leak
	// guard mirrored from the Observation surface.
	for _, c := range cases {
		if strings.Contains(c.reason.String(), gfSecretGitHub) {
			t.Errorf("a SuspendReason projection must never carry secret material: %q", c.reason.String())
		}
	}
}

// ---------------------------------------------------------------------------
// REAL-Server directed + §5.4 lifecycle lift (01KVS63HRY).
//
// The directed tests above (TestDualRun_GrantFetch_DirectedReasons,
// _WarmCacheRidesOutage_DirectedReasons, _SuspendParkResume_DirectedReasons) pin
// the EXACT per-reason verdict — but the genuine grant-service Server occupies an
// end in only ONE of them by VALUE: DirectedReasons reads the static dual run's
// Observations, which includes the real Server end. The §5.4 lifecycle, however,
// was pinned only fake-vs-fake (the honest stateful gfWarmFleet model vs the
// generated fake) — the real Server had NO lever for suspend/park/resume, so a
// real Server that drifted its eviction/park/resume mapping IN AGREEMENT with a
// co-drifted fake escaped value-level detection at the central seam (the
// RealVsGeneratedFake cross-end OK() equality cannot tell a faithful pair from a
// pair agreeing on the WRONG verdict). The grant Service ALREADY exposes
// Suspend/Park/Resume; the adapter's WarmCacheRealEnd now retains the genuine
// Service handle and exposes those as control levers (grantfetchconform Suspend/
// Park/Resume), so this block gives the REAL impl its own per-reason directed pin
// (1) AND its own per-transition §5.4 directed pin (2), driving the SAME genuine
// Service the dual-run dials.
//
// It is purely ADDITIVE: it adds new tests + a real-Server §5.4 suite that share
// NO state with grantFetchSuite, the §5.1 suite, the fake-vs-fake §5.4 suite, or
// any negative control — those stay byte-untouched. It consumes the frozen
// GrantFetchReason enum READ-ONLY (projection only) and reuses the existing
// gfDirectedCases() table + gfAssertDirectedObs projection. No secret bytes ride
// any Observation (doc 16 §5.2): each pins only WHETHER a credential rode + its
// non-secret location.

// TestDualRun_GrantFetch_DirectedReasons_StaticReal lifts the per-reason directed
// table onto the REAL grant-service Server explicitly: it runs gfDirectedCases()
// — the clean OK fetch plus each of the four fail-closed/stall reasons — against
// the dual run whose "real" end dials the ACTUAL grant-service Server (via
// grantfetchconform.RegisterStaticReal over the static gfFleet spec) and whose
// "fake" end is the generated programmable fake. It reads the ACTUAL per-scenario
// Observations the run drove (Result.ObservationsFor) and asserts the EXACT
// verdict on the REAL end with gfAssertDirectedObs — so a real-impl reason-mapping
// drift (e.g. classifying the store-down session as GRANT_NOT_FOUND instead of the
// retryable STORE_UNAVAILABLE, or the revoked session as anything but
// SESSION_NOT_LIVE) fails a directed subtest at the CENTRAL seam, not just the
// module-local server_test.go. This is the value-level pin the RealVsGeneratedFake
// cross-end OK() equality alone does not carry: equality cannot distinguish a
// faithful real Server from one that agrees with a co-drifted fake on the WRONG
// verdict. The fake end is pinned for free (it is the same run), but the directed
// purpose here is the REAL end.
func TestDualRun_GrantFetch_DirectedReasons_StaticReal(t *testing.T) {
	t.Parallel()
	real := grantFetchStaticRealEnd()
	fake := grantFetchEnd(honestGrantFetchResponder(gfFleet()))
	res, err := grantFetchSuite().Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	// The directed verdict is only meaningful on a green seam where every scenario
	// ran cleanly on both ends (a harness error would leave a nil Observation).
	if !res.OK() {
		t.Fatalf("static real-Server grantFetchSuite dual-run DIVERGED before the directed check:\n%s", res.Report())
	}
	for _, c := range gfDirectedCases() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			realObs, fakeObs, ok := res.ObservationsFor(c.name)
			if !ok {
				t.Fatalf("scenario %q not found in dual-run observations", c.name)
			}
			if realObs == nil || fakeObs == nil {
				t.Fatalf("scenario %q is missing an observation (real=%v fake=%v)", c.name, realObs, fakeObs)
			}
			// Pin the EXACT verdict on the REAL grant-service Server end (the lift's
			// purpose); the fake end rode the same run, so pin it too for completeness.
			gfAssertDirectedObs(t, "real", dualrun.ParseObs(realObs.Canonical()), c)
			gfAssertDirectedObs(t, "fake", dualrun.ParseObs(fakeObs.Canonical()), c)
		})
	}
}

// realLifecycleGfSpec is the §5.4 real-Server lifecycle fixture: the SAME two
// live github-granted sessions as warmGfSpec (gfSessionWarm + gfSessionColdMiss),
// but gfSessionColdMiss additionally holds the npm grant the §5.4 walk parks-then-
// resumes. warmGfSpec (shared with the §5.1 warm-cache suite, which fetches only
// github) is left BYTE-UNTOUCHED; this dedicated spec mirrors the fake fleet's
// newGfWarmFleet construction (its coldMiss session holds github+npm) so the real
// Server and the fake agree field-for-field on the post-resume npm admit. The
// clock and session deadline are pinned exactly as warmGfSpec so the OK echoes
// (class/expiry/location) match the fake. Synthetic only (D50).
func realLifecycleGfSpec() grantfetchconform.FleetSpec {
	githubGrant := grantfetchconform.Grant{
		Secret:   []byte(gfSecretGitHub),
		Location: gfLocationHeader,
		Expiry:   gfExpiryFarFuture,
	}
	return grantfetchconform.FleetSpec{
		LiveSessions: map[string]map[string]grantfetchconform.Grant{
			gfSessionWarm: {gfServiceGitHub: githubGrant},
			// coldMiss holds BOTH github (warmed pre-park, rides) AND npm (the NEW pair
			// the park refuses and resume admits), mirroring the fake newGfWarmFleet.
			gfSessionColdMiss: {gfServiceGitHub: githubGrant, gfServiceNpm: githubGrant},
		},
		NowUnix:             gfTestNow,
		SessionDeadlineUnix: gfExpiryFarFuture + 3600,
	}
}

// gfRealSuspendParkResumeSuite is the §5.4 grant-eviction lifecycle suite wired
// for the genuine-Server "real" end: the suspend/park/resume TRANSITIONS are
// driven on the REAL grant-service Service via the WarmCacheRealEnd levers
// (Suspend/Park/Resume), while the "fake" end's transitions ride the stateful
// gfWarmFleet model (suspend/park/resume). It walks the SAME ordered lifecycle
// gfSuspendParkResumeSuite walks — warm a session then suspend it (a subsequent
// fetch fails closed SESSION_NOT_LIVE), and on a second session park it (the
// warmed pair still rides, a NEW pair is refused SESSION_PARKED) then resume it
// (the NEW pair is admitted again) — only the lever for the REAL end's transitions
// differs (the genuine Service's own Suspend/Park/Resume vs the model's).
//
// As with grantFetchWarmCacheSuiteRealVsFake, the transition scenarios drive BOTH
// ends (the real Service via realEnd and the fake fleet via fakeFleet) because the
// suite runner calls each scenario once per end and a scenario closure cannot tell
// which conn it is driving; the real Service's Suspend/Park/Resume are idempotent
// for the targeted session (suspend re-deletes an already-evicted entry, park
// re-sets the parked bit, resume re-clears it), so flipping both on each of the
// two per-scenario invocations is safe and leaves both ends in the same lifecycle
// state. The deadline passed to Resume is 0, so the real Service keeps the spec's
// registered session-lifetime ceiling (the session is well within it, so it
// resumes live).
func gfRealSuspendParkResumeSuite(realEnd *grantfetchconform.WarmCacheRealEnd, fakeFleet *gfWarmFleet) dualrun.Suite {
	return dualrun.Suite{
		Seam: "ds-tlsproxy(swap-executor)<->identity GrantFetchService.Fetch (§5.4 suspend/park-resume, real Server)",
		Scenarios: []dualrun.Scenario{
			{
				// 1. Pre-suspend WARM: the in-flight session's first github fetch is a
				// cache miss while live -> OK, warming the pair on each end.
				Name: "warm-grant-before-suspend-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
				},
			},
			{
				// 2. SUSPEND fires on BOTH ends: the genuine Service.Suspend (real) and
				// the model suspend (fake). Real eviction drops the whole session entry,
				// so a subsequent fetch fails closed. A fleet-state transition, surfacing
				// nothing on the Fetch wire.
				Name: "suspend-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realEnd.Suspend(gfSessionWarm)
					fakeFleet.suspend(gfSessionWarm)
					return dualrun.NewObservation().Set("session_live", "false"), nil
				},
			},
			{
				// 3. Post-suspend FETCH fails closed: even the previously-warmed pair is
				// gone (the genuine Service evicted the whole entry) -> SESSION_NOT_LIVE,
				// no credential.
				Name: "fetch-after-suspend-fails-closed",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
				},
			},
			{
				// 4. On a SECOND live session, warm a github grant before parking, so it
				// survives the park and rides -> OK, warming the pair.
				Name: "warm-grant-before-park-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
			{
				// 5. PARK fires on BOTH ends: the genuine Service.Park (real) keeps the
				// cache but refuses a NEW fetch; the model park (fake) mirrors it.
				// Transition step.
				Name: "park-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realEnd.Park(gfSessionColdMiss)
					fakeFleet.park(gfSessionColdMiss)
					return dualrun.NewObservation().Set("session_parked", "true"), nil
				},
			},
			{
				// 6. The PARKED session's WARMED github pair still RIDES on the genuine
				// Service: cache hit -> OK with the credential, even while parked (grants
				// survive snapshot+park, §5.4).
				Name: "parked-warm-pair-still-rides-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
			{
				// 7. A NEW (not-yet-cached) npm pair on the SAME parked session is a cache
				// MISS -> the genuine Service refuses it: SESSION_PARKED, no credential (a
				// parked session fetches no NEW grants until resume).
				Name: "parked-new-fetch-refused",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceNpm), nil
				},
			},
			{
				// 8. RESUME fires on BOTH ends: the genuine Service.Resume (real) clears
				// parked and re-validates liveness (the session is within deadline, so it
				// stays live); the model resume (fake) mirrors it. deadlineUnix=0 keeps the
				// spec's registered ceiling. Transition step.
				Name: "resume-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					// The real Service's Resume returns an error only for a dead (past-
					// deadline) session; this session is well within its registered ceiling,
					// so resume succeeds — but a non-nil error here is a real-impl drift, so
					// surface it on the observation for the directed check to catch.
					resumeErr := realEnd.Resume(gfSessionColdMiss, 0)
					fakeFleet.resume(gfSessionColdMiss, true)
					obs := dualrun.NewObservation().Set("session_parked", "false")
					obs.Setf("resume_ok", "%t", resumeErr == nil)
					return obs, nil
				},
			},
			{
				// 9. Post-resume, the previously-refused npm pair is ADMITTED again on the
				// genuine Service: cache miss -> store read -> OK with the credential (the
				// session fetches NEW grants once more).
				Name: "fetch-after-resume-admits-again-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceNpm), nil
				},
			},
		},
	}
}

// TestDualRun_GrantFetch_SuspendParkResume_RealServer lifts the doc 16 §5.4
// grant-eviction lifecycle onto the REAL grant-service Server: the suspend, park,
// and resume transitions are driven on the GENUINE grantservice.Service (via the
// WarmCacheRealEnd Suspend/Park/Resume levers, which mutate the SAME Service the
// dual-run dials) rather than only the honest stateful model. Over one ordered
// walk, a SUSPEND evicts a warmed session on the real Service (a subsequent fetch
// fails closed SESSION_NOT_LIVE with no credential), and on a second session a
// PARK keeps the cache (a warmed pair still rides OK) while refusing a NEW fetch
// (SESSION_PARKED), then a RESUME admits the session again (OK with the
// credential). The genuine Service and the generated fake observe the lifecycle
// field-for-field identically. Additive: it shares no state with the fake-vs-fake
// §5.4 suite, so that stays green.
func TestDualRun_GrantFetch_SuspendParkResume_RealServer(t *testing.T) {
	t.Parallel()
	realEnd := grantfetchconform.NewWarmCacheRealEnd(realLifecycleGfSpec())
	fakeFleet := newGfWarmFleet()
	real := dualrun.InProcess(realEnd.Register)
	fake := grantFetchEnd(fakeFleet.responder())
	res, err := gfRealSuspendParkResumeSuite(realEnd, fakeFleet).Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("identity GrantFetchService §5.4 suspend/park-resume (real Server) seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the real-Server suspend/park-resume suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestDualRun_GrantFetch_SuspendParkResume_RealServer_DirectedReasons is the
// DIRECTED complement of the real-Server §5.4 dual-run: the dual-run above proves
// the genuine Service and the generated fake observe the lifecycle field-for-field
// IDENTICALLY, but cross-end equality alone cannot tell a faithful pair from a
// pair that agrees on the WRONG verdict (a real Server that fails to evict on
// suspend, or admits a NEW fetch while parked, in agreement with a co-drifted
// fake, would still be res.OK()). This pins the EXACT per-transition reasons the
// §5.4 contract requires — SESSION_NOT_LIVE after the real Service's suspend
// eviction, OK on the parked warm-pair ride, SESSION_PARKED on the parked
// new-fetch refusal, and OK again after the real Service's resume — so the lift
// carries the contract VALUES on the REAL Server, not just cross-end agreement.
//
// It reads the ACTUAL per-scenario Observations the dual run already drove
// (Result.ObservationsFor) and asserts on the REAL end (and the fake, for
// completeness) — pinning the verdict on the genuine Service the dual-run dialed.
// No secret bytes ride any Observation (doc 16 §5.2): each pins only WHETHER a
// credential rode and its non-secret location.
func TestDualRun_GrantFetch_SuspendParkResume_RealServer_DirectedReasons(t *testing.T) {
	t.Parallel()
	realEnd := grantfetchconform.NewWarmCacheRealEnd(realLifecycleGfSpec())
	fakeFleet := newGfWarmFleet()
	real := dualrun.InProcess(realEnd.Register)
	fake := grantFetchEnd(fakeFleet.responder())
	res, err := gfRealSuspendParkResumeSuite(realEnd, fakeFleet).Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	// The directed verdict is only meaningful if the seam is green AND every
	// scenario actually ran cleanly on both ends (an end-error would leave a nil
	// Observation, so the assertions below would otherwise silently pass).
	if !res.OK() {
		t.Fatalf("real-Server §5.4 suspend/park-resume dual-run DIVERGED before the directed check:\n%s", res.Report())
	}

	// assertObs reads both ends' Observation for one scenario from the run and
	// applies the per-key contract checks to EACH end, proving the verdict value on
	// the genuine Service the dual run dialed (and the fake, for completeness).
	assertObs := func(scenario string, check func(end string, kv map[string]string)) {
		t.Helper()
		realObs, fakeObs, ok := res.ObservationsFor(scenario)
		if !ok {
			t.Fatalf("scenario %q not found in dual-run observations", scenario)
		}
		if realObs == nil || fakeObs == nil {
			t.Fatalf("scenario %q is missing an observation (real=%v fake=%v)", scenario, realObs, fakeObs)
		}
		check("real", dualrun.ParseObs(realObs.Canonical()))
		check("fake", dualrun.ParseObs(fakeObs.Canonical()))
	}

	// 1. Pre-suspend warm fetch on the genuine Service -> OK with the credential.
	assertObs("warm-grant-before-suspend-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s pre-suspend warm fetch reason = %q, want OK", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s pre-suspend warm fetch must carry the credential, has_credential = %q", end, got)
		}
	})

	// 2. Suspend onset — a real-Service transition, nothing on the Fetch wire.
	assertObs("suspend-onset", func(end string, kv map[string]string) {
		if got := kv["session_live"]; got != "false" {
			t.Errorf("%s suspend-onset session_live = %q, want false", end, got)
		}
	})

	// 3. Post-suspend fetch FAILS CLOSED on the genuine Service: the real
	// Service.Suspend evicted the whole session entry, so even the warmed pair is
	// gone -> SESSION_NOT_LIVE, no credential, and it is NOT the retryable stall.
	assertObs("fetch-after-suspend-fails-closed", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE.String() {
			t.Errorf("%s post-suspend reason = %q, want SESSION_NOT_LIVE (the real Service must evict on suspend)", end, got)
		}
		if got := kv["reason_is_stall"]; got != "false" {
			t.Errorf("%s post-suspend reason_is_stall = %q, want false (eviction is a definitive deny, not a stall)", end, got)
		}
		if got := kv["has_credential"]; got != "false" {
			t.Errorf("%s a suspended-session fetch must carry no credential, has_credential = %q", end, got)
		}
	})

	// 4. Pre-park warm fetch on the second session -> OK with the credential.
	assertObs("warm-grant-before-park-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s pre-park warm fetch reason = %q, want OK", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s pre-park warm fetch must carry the credential, has_credential = %q", end, got)
		}
	})

	// 5. Park onset — a real-Service transition, nothing on the Fetch wire; the
	// real Service's Resume succeeded record rides scenario 8.
	assertObs("park-onset", func(end string, kv map[string]string) {
		if got := kv["session_parked"]; got != "true" {
			t.Errorf("%s park-onset session_parked = %q, want true", end, got)
		}
	})

	// 6. The parked session's WARMED pair still RIDES on the genuine Service: OK
	// with the credential, no stall — grants survive snapshot+park (§5.4).
	assertObs("parked-warm-pair-still-rides-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s parked-ride reason = %q, want OK", end, got)
		}
		if got := kv["reason_is_stall"]; got != "false" {
			t.Errorf("%s parked-ride reason_is_stall = %q, want false", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s parked warm-pair ride must carry the credential, has_credential = %q", end, got)
		}
		if got := kv["credential_location"]; got != gfLocationHeader {
			t.Errorf("%s parked-ride credential_location = %q, want %q", end, got, gfLocationHeader)
		}
	})

	// 7. A NEW fetch on the parked session is REFUSED by the genuine Service:
	// SESSION_PARKED, no credential — a parked session fetches no NEW grants until
	// resume, and it is NOT the retryable stall.
	assertObs("parked-new-fetch-refused", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_PARKED.String() {
			t.Errorf("%s parked new-fetch reason = %q, want SESSION_PARKED (the real Service must refuse a NEW fetch while parked)", end, got)
		}
		if got := kv["reason_is_stall"]; got != "false" {
			t.Errorf("%s parked new-fetch reason_is_stall = %q, want false (park refusal is a deny, not a stall)", end, got)
		}
		if got := kv["has_credential"]; got != "false" {
			t.Errorf("%s a parked new-fetch refusal must carry no credential, has_credential = %q", end, got)
		}
	})

	// 8. Resume onset — the genuine Service's Resume cleared parked and re-validated
	// liveness (the session is within deadline). The real end records resume_ok=true
	// (a non-nil resume error would be a real-impl drift re-admitting a live session
	// as dead); the fake end records only session_parked.
	assertObs("resume-onset", func(end string, kv map[string]string) {
		if got := kv["session_parked"]; got != "false" {
			t.Errorf("%s resume-onset session_parked = %q, want false", end, got)
		}
		if end == "real" {
			if got := kv["resume_ok"]; got != "true" {
				t.Errorf("real resume_ok = %q, want true (the genuine Service must resume a live, within-deadline session)", got)
			}
		}
	})

	// 9. Post-resume, the previously-refused NEW pair is ADMITTED again on the
	// genuine Service: OK with the credential — the session fetches NEW grants once
	// more.
	assertObs("fetch-after-resume-admits-again-ok", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s post-resume reason = %q, want OK (the real Service must admit NEW fetches after resume)", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s post-resume admit must carry the credential, has_credential = %q", end, got)
		}
		if got := kv["credential_location"]; got != gfLocationHeader {
			t.Errorf("%s post-resume credential_location = %q, want %q", end, got, gfLocationHeader)
		}
	})
}

// TestDualRun_GrantFetch_SuspendParkResume_RealServer_NonVacuous is the ADVERSARIAL
// proof that the real-Server §5.4 directed lift is NON-VACUOUS: a §5.4 transition
// applied to the FAKE end but DELIBERATELY SKIPPED on the genuine Service (so the
// real Service does NOT perform the eviction/refusal) MUST make the genuine Server
// DIVERGE from the honest fake — proving the real-Server levers actually drive the
// genuine Service's state, not a no-op. Two drifts are proved against the genuine
// Service:
//
//	(a) suspend is SKIPPED on the real Service (only the fake suspends): the honest
//	    fake evicts -> SESSION_NOT_LIVE, but the un-suspended real Service still
//	    rides the warmed pair -> OK. They diverge.
//	(b) park is SKIPPED on the real Service (only the fake parks): the honest fake
//	    refuses the NEW pair -> SESSION_PARKED, but the un-parked real Service fetches
//	    it -> OK. They diverge.
//
// Without this, the directed test could pass for a degenerate reason (a real lever
// that never mutates the Service). The drift lives only in this test; the genuine
// Service is never modified — only WHETHER the lever is called on it differs.
func TestDualRun_GrantFetch_SuspendParkResume_RealServer_NonVacuous(t *testing.T) {
	t.Parallel()

	// (a) Suspend SKIPPED on the real Service: the honest fake evicts, the real
	// Service does not, so the post-suspend fetch is SESSION_NOT_LIVE on the fake and
	// OK (still riding the warmed pair) on the real Service -> divergence.
	t.Run("real-skips-suspend-eviction-is-caught", func(t *testing.T) {
		t.Parallel()
		realEnd := grantfetchconform.NewWarmCacheRealEnd(realLifecycleGfSpec())
		fakeFleet := newGfWarmFleet()
		real := dualrun.InProcess(realEnd.Register)
		fake := grantFetchEnd(fakeFleet.responder())
		suite := dualrun.Suite{
			Seam: "§5.4 real-Server suspend-eviction non-vacuity",
			Scenarios: []dualrun.Scenario{
				{
					Name: "warm",
					Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
						return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
					},
				},
				{
					Name: "suspend",
					Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
						// DRIFT: suspend ONLY the fake; the real Service is left live+warmed.
						fakeFleet.suspend(gfSessionWarm)
						return dualrun.NewObservation().Set("session_live", "false"), nil
					},
				},
				{
					Name: "fetch-after-suspend",
					Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
						return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
					},
				},
			},
		}
		res, err := suite.Run(context.Background(), real, fake)
		if err != nil {
			t.Fatalf("dual-run: %v", err)
		}
		if res.OK() {
			t.Fatal("the real Service skipping suspend-eviction passed the §5.4 seam — the real-Server Suspend lever is a no-op (VACUOUS)")
		}
	})

	// (b) Park SKIPPED on the real Service: the honest fake refuses the NEW npm pair
	// (SESSION_PARKED), the real Service fetches it (OK) -> divergence.
	t.Run("real-skips-park-refusal-is-caught", func(t *testing.T) {
		t.Parallel()
		realEnd := grantfetchconform.NewWarmCacheRealEnd(realLifecycleGfSpec())
		fakeFleet := newGfWarmFleet()
		real := dualrun.InProcess(realEnd.Register)
		fake := grantFetchEnd(fakeFleet.responder())
		suite := dualrun.Suite{
			Seam: "§5.4 real-Server park-refusal non-vacuity",
			Scenarios: []dualrun.Scenario{
				{
					Name: "warm",
					Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
						return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
					},
				},
				{
					Name: "park",
					Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
						// DRIFT: park ONLY the fake; the real Service is left live (un-parked).
						fakeFleet.park(gfSessionColdMiss)
						return dualrun.NewObservation().Set("session_parked", "true"), nil
					},
				},
				{
					Name: "new-fetch-while-parked",
					Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
						// The honest fake refuses (SESSION_PARKED); the un-parked real Service
						// fetches the NEW npm pair (OK) -> divergence.
						return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceNpm), nil
					},
				},
			},
		}
		res, err := suite.Run(context.Background(), real, fake)
		if err != nil {
			t.Fatalf("dual-run: %v", err)
		}
		if res.OK() {
			t.Fatal("the real Service skipping the park refusal passed the §5.4 seam — the real-Server Park lever is a no-op (VACUOUS)")
		}
	})
}

// ---------------------------------------------------------------------------
// Residual coverage gaps (01KVSBMFEG): three ADDITIVE directed pins folded here.
//   (1) PerScenario mixed-ordering — Suite.Run's declaration-order guarantee across
//       a green + an errored-end + a diverged scenario, INDEPENDENT of any seam suite.
//   (2) Warm-cache zero-store-read — the §5.1 warm-ride served-from-cache claim
//       pinned by a ZERO store-read delta (not just reason==OK).
//   (3) Resume-of-past-deadline real verdict — the genuine grant-service Service
//       fails closed (ErrSessionNotLive / SESSION_NOT_LIVE) on Resume past deadline,
//       pinned at the CENTRAL seam on the REAL Server (today only fake-vs-fake covers
//       resume-re-admits-dead-session).
// All read the FROZEN GrantFetchReason enum READ-ONLY, record no secret bytes (doc
// 16 §5.2), and drive only synthetic fixtures (D50). No new D-number.

// TestDualRun_GrantFetch_PerScenario_MixedOrdering pins Suite.Run's declaration-
// order guarantee on Result.PerScenario() across a MIXED run — a green (agree) fetch,
// an errored end (one side fails at the harness level, leaving a nil per-end
// Observation), and a diverged fetch (the two ends observe different verdicts) — all
// in ONE suite. The wave-1 harness-accessors tests cover only single-scenario shapes;
// this exercises the multi-scenario ordering contract INDEPENDENT of any GrantFetch
// seam suite: it builds its own three-scenario suite over two controlled ends, so the
// only thing under test is that PerScenario() returns the scenarios in DECLARATION
// order with the failed end's Observation nil.
//
// Non-vacuous: the scenario names are deliberately NOT in sorted order (declaration
// green→errored→diverged; sorted diverged→errored→green), so reordering the
// perScenario append in dualrun.go — a prepend, a reverse, or a sort-by-name — makes
// the ordered ps[i].Scenario checks below fail EXACTLY here. No secret bytes ride any
// Observation (doc 16 §5.2).
func TestDualRun_GrantFetch_PerScenario_MixedOrdering(t *testing.T) {
	t.Parallel()

	// Synthetic sessions local to this ordering pin (D50) — obviously synthetic.
	const (
		poSessGreen   = "ses-synthetic-perscenario-green-1111"
		poSessErrored = "ses-synthetic-perscenario-errored-2222"
		poSessDiverge = "ses-synthetic-perscenario-diverge-3333"
	)

	githubGrant := gfGrant{
		secret:   gfSecretGitHub,
		location: gfLocationHeader,
		class:    identityv1.CredentialClass_CREDENTIAL_CLASS_SWAP,
		expiry:   gfExpiryFarFuture,
	}
	// All three sessions are live+github-granted, so the honest real end returns OK
	// for each; the fake end below overrides two of them to manufacture the errored
	// and diverged shapes.
	fleet := map[string]gfSession{
		poSessGreen:   {live: true, grants: map[string]gfGrant{gfServiceGitHub: githubGrant}},
		poSessErrored: {live: true, grants: map[string]gfGrant{gfServiceGitHub: githubGrant}},
		poSessDiverge: {live: true, grants: map[string]gfGrant{gfServiceGitHub: githubGrant}},
	}
	honest := honestGrantFetchResponder(fleet)
	real := grantFetchEnd(honest)
	fake := grantFetchEnd(func(ctx context.Context, req *identityv1.GrantFetchRequest) (*identityv1.GrantFetchResponse, error) {
		switch req.GetSessionUuid() {
		case poSessErrored:
			// A harness-level (non-contract) TRANSPORT failure on the fake end only: the
			// scenario Run below turns this into a returned error, so the fake's per-end
			// Observation is nil and the failure rides Result.FakeErrors — the "failed
			// end" whose PerScenario Observation must be nil.
			return nil, status.Error(codes.Unavailable, "synthetic harness-level transport failure")
		case poSessDiverge:
			// A CONTRACT divergence: the honest real end returns OK with the credential,
			// but the fake denies SESSION_NOT_LIVE — the two ends observe different
			// verdicts, so this scenario diverges (both Observations present, unequal).
			return &identityv1.GrantFetchResponse{Reason: identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE}, nil
		default:
			return honest(ctx, req)
		}
	})

	// mkScenario drives one Fetch and folds the outcome through the shared projection,
	// EXCEPT it returns a harness-level error (nil Observation) on a transport error —
	// so an errored end leaves a nil per-end Observation the PerScenario record carries.
	mkScenario := func(name, session string) dualrun.Scenario {
		return dualrun.Scenario{
			Name: name,
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewGrantFetchServiceClient(conn)
				resp, err := cl.Fetch(ctx, &identityv1.GrantFetchRequest{
					SessionUuid:            session,
					ServiceId:              gfServiceGitHub,
					GrantRef:               gfGrantRef(session, gfServiceGitHub),
					GrantExpiryUnixSeconds: gfExpiryFarFuture,
				})
				if err != nil {
					// Harness-level failure: a nil Observation + error, so this end's
					// per-scenario Observation is nil and the error rides *Errors.
					return nil, fmt.Errorf("%s: fetch transport error: %w", name, err)
				}
				return gfFetchObservation(resp, nil), nil
			},
		}
	}

	// DECLARATION ORDER: green, errored, diverged — deliberately NOT sorted order.
	suite := dualrun.Suite{
		Seam: "PerScenario declaration-order guarantee (mixed green/errored/diverged)",
		Scenarios: []dualrun.Scenario{
			mkScenario("green-ok-fetch", poSessGreen),
			mkScenario("errored-unimplemented-end", poSessErrored),
			mkScenario("diverged-end", poSessDiverge),
		},
	}

	res, err := suite.Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.Ran != 3 {
		t.Fatalf("ran = %d, want 3", res.Ran)
	}

	// The core pin: PerScenario returns the scenarios in DECLARATION order. This is a
	// slice (Suite.Run ordering), independent of the randomized RealErrors/FakeErrors
	// map iteration. Reordering the perScenario append in dualrun.go fails exactly here.
	ps := res.PerScenario()
	wantOrder := []string{"green-ok-fetch", "errored-unimplemented-end", "diverged-end"}
	if len(ps) != len(wantOrder) {
		t.Fatalf("PerScenario returned %d records, want %d", len(ps), len(wantOrder))
	}
	for i, want := range wantOrder {
		if ps[i].Scenario != want {
			t.Errorf("PerScenario[%d].Scenario = %q, want %q (Suite.Run must record in declaration order)", i, ps[i].Scenario, want)
		}
	}

	// 1. Green: both ends observed (both Observations present) and agree — no divergence.
	if ps[0].Real == nil || ps[0].Fake == nil {
		t.Errorf("green scenario must have BOTH per-end Observations, got real=%v fake=%v", ps[0].Real, ps[0].Fake)
	}
	if _, found := res.FakeErrors["green-ok-fetch"]; found {
		t.Error("green scenario must not record a fake error")
	}

	// 2. Errored end: the fake end failed at the harness level, so its per-end
	// Observation is NIL and the error rides Result.FakeErrors; the real end still
	// observed (non-nil). This is the "per-end nil on the failed end" pin.
	if ps[1].Real == nil {
		t.Error("errored scenario: the REAL end succeeded, its Observation must be non-nil")
	}
	if ps[1].Fake != nil {
		t.Errorf("errored scenario: the FAKE end failed at the harness level, its Observation must be nil, got %q", ps[1].Fake.Canonical())
	}
	if _, found := res.FakeErrors["errored-unimplemented-end"]; !found {
		t.Error("errored scenario: the fake-end harness failure must ride Result.FakeErrors")
	}

	// 3. Diverged: both ends observed (both Observations present) but disagree — the
	// verdict differs, so it is a Divergence (not a harness error), and both per-end
	// Observations are present and UNEQUAL.
	if ps[2].Real == nil || ps[2].Fake == nil {
		t.Fatalf("diverged scenario must have BOTH per-end Observations, got real=%v fake=%v", ps[2].Real, ps[2].Fake)
	}
	if ps[2].Real.Canonical() == ps[2].Fake.Canonical() {
		t.Errorf("diverged scenario: the two ends must observe DIFFERENT verdicts, both = %q", ps[2].Real.Canonical())
	}
	var sawDiverge bool
	for _, d := range res.Divergences {
		if d.Scenario == "diverged-end" {
			sawDiverge = true
		}
	}
	if !sawDiverge {
		t.Errorf("diverged scenario must be recorded in Result.Divergences, got %s", res.Report())
	}

	// ObservationsFor must agree with the PerScenario slice for a named scenario — the
	// same records, reachable by name (read-only against the wave-1 accessors).
	if r0, f0, ok := res.ObservationsFor("errored-unimplemented-end"); !ok || r0 == nil || f0 != nil {
		t.Errorf("ObservationsFor(errored) = (%v, %v, %v), want (non-nil, nil, true)", r0, f0, ok)
	}
}

// TestDualRun_GrantFetch_WarmCacheRidesOutage_ConsultsNoStore pins the §5.1 warm-ride
// served-from-cache claim with a ZERO store-read assertion, threading the wave-1
// storeReadCount() accessor into the warm-rides-outage lifecycle (the DirectedReasons
// test above pins only reason==OK on the ride). It walks the same ordered §5.1
// sequence grantFetchWarmCacheSuite walks — warm the in-flight pair pre-outage, take
// the store down, then RIDE the outage — but brackets the ride scenario with
// store-read snapshots captured by closure on BOTH the real and fake fleets, and
// asserts the count is UNCHANGED across the ride: the ride served from cache, no store
// consulted. That no-store-read fact is otherwise invisible at the Fetch wire (a ride
// and a fresh read both observe reason==OK). Additive: fresh fleets, shares no state
// with the existing §5.1 suite/tests; reads only the non-secret store-read count (no
// secret bytes, doc 16 §5.2).
func TestDualRun_GrantFetch_WarmCacheRidesOutage_ConsultsNoStore(t *testing.T) {
	t.Parallel()
	realFleet := newGfWarmFleet()
	fakeFleet := newGfWarmFleet()
	real := grantFetchEnd(realFleet.responder())
	fake := grantFetchEnd(fakeFleet.responder())

	// Store-read snapshots bracketing the warm-ride, captured by closure. Each is
	// [realCount, fakeCount]; the ride during the outage must add zero on both ends.
	var preRideReal, preRideFake int
	var postRideReal, postRideFake int

	suite := dualrun.Suite{
		Seam: "§5.1 warm-inflight ride consults no store",
		Scenarios: []dualrun.Scenario{
			{
				// Warm the in-flight github pair while the store is up (a genuine store
				// read on each fleet — the only store read in the walk).
				Name: "warm-inflight-grant-before-outage-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub), nil
				},
			},
			{
				// The store goes DOWN on both ends, then snapshot each fleet's store-read
				// count as the pre-ride baseline (the warm above bumped each fleet once).
				Name: "store-outage-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realFleet.down()
					fakeFleet.down()
					preRideReal = realFleet.storeReadCount()
					preRideFake = fakeFleet.storeReadCount()
					return dualrun.NewObservation().Set("store_available", "false"), nil
				},
			},
			{
				// The WARM in-flight pair RIDES the outage: cache hit -> OK, NO store read.
				// Snapshot each fleet's count right after the ride (Suite.Run drives real
				// then fake within this scenario, so both fleets have served the ride by the
				// time the fake-end invocation records).
				Name: "warm-inflight-grant-rides-outage-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					obs := gfWarmFetchObservation(ctx, conn, gfSessionWarm, gfServiceGitHub)
					postRideReal = realFleet.storeReadCount()
					postRideFake = fakeFleet.storeReadCount()
					return obs, nil
				},
			},
			{
				// A NEW (cold) pair during the outage is a cache miss -> STORE_UNAVAILABLE
				// stall (the wave-1 NEW-fetch leg), returning BEFORE the store-read leg so it
				// never bumps the counter either.
				Name: "new-grant-during-outage-stalls",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
		},
	}

	res, err := suite.Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("§5.1 warm-ride no-store-read suite DIVERGED:\n%s", res.Report())
	}

	// The ride is OK with the credential on both ends — anchor the no-store-read claim
	// to an actual successful ride, not a silent failure.
	realObs, fakeObs, ok := res.ObservationsFor("warm-inflight-grant-rides-outage-ok")
	if !ok || realObs == nil || fakeObs == nil {
		t.Fatalf("warm-ride scenario missing an observation (real=%v fake=%v)", realObs, fakeObs)
	}
	for end, obs := range map[string]*dualrun.Observation{"real": realObs, "fake": fakeObs} {
		kv := dualrun.ParseObs(obs.Canonical())
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
			t.Errorf("%s warm ride reason = %q, want OK", end, got)
		}
		if got := kv["has_credential"]; got != "true" {
			t.Errorf("%s warm ride must carry the credential, has_credential = %q", end, got)
		}
	}

	// The contract: the warm ride served from cache, so the store-read count is
	// UNCHANGED across the ride on BOTH ends. A cache-bypass that re-reads the store
	// (with the store up) bumps the delta and fails exactly here.
	if got := postRideReal - preRideReal; got != 0 {
		t.Errorf("§5.1 warm ride consulted the store on the REAL end: store-read delta = %d, want 0 (the ride must serve from cache)", got)
	}
	if got := postRideFake - preRideFake; got != 0 {
		t.Errorf("§5.1 warm ride consulted the store on the FAKE end: store-read delta = %d, want 0 (the ride must serve from cache)", got)
	}
}

// TestDualRun_GrantFetch_WarmCacheRidesOutage_ConsultsNoStore_NonVacuous is the
// ADVERSARIAL proof that the §5.1 warm-ride zero-store-read assertion is NON-VACUOUS:
// a responder whose "ride" RE-READS the store (its warmed pair is NOT served from
// cache) MUST bump the store-read count. Without this, the zero-delta could pass for a
// degenerate reason (a counter that never moves). We warm a pair (store UP, one read),
// then a deliberate LOCAL cache-bypass (clear the warmed cache, store still up) forces
// the "ride" down the store-read leg, and we assert the count moved — proving the
// honest test's zero-delta is a real constraint. The drift lives only in this test;
// the committed responder is never drifted.
func TestDualRun_GrantFetch_WarmCacheRidesOutage_ConsultsNoStore_NonVacuous(t *testing.T) {
	t.Parallel()
	fleet := newGfWarmFleet()
	resp := fleet.responder()
	ctx := context.Background()

	warmReq := &identityv1.GrantFetchRequest{
		SessionUuid:            gfSessionWarm,
		ServiceId:              gfServiceGitHub,
		GrantRef:               gfGrantRef(gfSessionWarm, gfServiceGitHub),
		GrantExpiryUnixSeconds: gfExpiryFarFuture,
	}
	if _, err := resp(ctx, warmReq); err != nil {
		t.Fatalf("warm: %v", err)
	}
	if fleet.storeReadCount() != 1 {
		t.Fatalf("warm fetch store-read count = %d, want 1", fleet.storeReadCount())
	}

	// DRIFT: clear the warmed cache so the "ride" is forced to re-read the store — the
	// very cache-bypass the honest no-store-read assertion guards against. The store is
	// left UP so the bypass reaches the store-read leg (during a real §5.1 outage a
	// cache-bypass would instead STALL, which the reason==OK assertion catches).
	delete(fleet.cache, gfSessionWarm)

	before := fleet.storeReadCount()
	if _, err := resp(ctx, warmReq); err != nil {
		t.Fatalf("ride: %v", err)
	}
	if got := fleet.storeReadCount() - before; got == 0 {
		t.Fatal("a warm ride that re-reads the store produced a zero store-read delta — the §5.1 no-store-read assertion is VACUOUS")
	}
}

// gfResumePastDeadlineUnix is a session-lifetime deadline BEFORE the pinned conform
// clock (gfTestNow): a Resume that sets this deadline re-validates the session as past
// its lifetime and fails closed (ErrSessionNotLive) — a dead session does not silently
// come back (§5.4). Synthetic (D50).
const gfResumePastDeadlineUnix = gfTestNow - 3600

// gfResumePastDeadlineSuite is the §5.4 resume-of-past-deadline suite wired for the
// genuine-Server "real" end: warm a session's pair, park it, then RESUME it with a
// past-deadline ceiling — the genuine grantservice.Service.Resume re-validates
// liveness and FAILS CLOSED (evicts the session, returns ErrSessionNotLive), so a
// subsequent fetch observes SESSION_NOT_LIVE. The fake end mirrors the fail-closed
// resume via the stateful model (resume with stillLive=false). Both the real
// Service's Resume error and the model's fail-closed state are computed on each
// per-scenario invocation (Suite.Run drives real then fake); the resume levers are
// idempotent (a re-Resume of an already-evicted session again returns
// ErrSessionNotLive), so both ends record the same resume verdict and the ordered
// walk is replayed identically. The past deadline is passed through the existing
// WarmCacheRealEnd.Resume(session, deadlineUnix) lever — no adapter change needed.
func gfResumePastDeadlineSuite(realEnd *grantfetchconform.WarmCacheRealEnd, fakeFleet *gfWarmFleet) dualrun.Suite {
	return dualrun.Suite{
		Seam: "ds-tlsproxy(swap-executor)<->identity GrantFetchService.Fetch (§5.4 resume-of-past-deadline fails closed, real Server)",
		Scenarios: []dualrun.Scenario{
			{
				// 1. Warm the session's github pair while live+within-deadline -> OK, warming
				// the pair on each end.
				Name: "warm-grant-before-resume-ok",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
			{
				// 2. PARK fires on both ends (the genuine Service.Park keeps the cache; the
				// model park mirrors it). A transition step so the resume below re-validates
				// a parked session, the §5.4 park->resume path.
				Name: "park-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realEnd.Park(gfSessionColdMiss)
					fakeFleet.park(gfSessionColdMiss)
					return dualrun.NewObservation().Set("session_parked", "true"), nil
				},
			},
			{
				// 3. RESUME with a PAST deadline fires on both ends: the genuine
				// Service.Resume sets the session-lifetime ceiling into the past and
				// re-validates liveness -> the session is dead, so it is EVICTED and Resume
				// returns ErrSessionNotLive (fail-closed). The fake models the same via
				// resume(stillLive=false). The real Service's resume error is recorded
				// (resume_failed_closed) — computed from the REAL end on each per-scenario
				// invocation, so both ends record the same true value (no spurious
				// divergence at this transition; the fail-closed FETCH below is the pin).
				Name: "resume-past-deadline-onset",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					resumeErr := realEnd.Resume(gfSessionColdMiss, gfResumePastDeadlineUnix)
					fakeFleet.resume(gfSessionColdMiss, false)
					obs := dualrun.NewObservation().Set("session_parked", "false")
					// resume_failed_closed==true is the genuine Service's fail-closed verdict:
					// a non-nil Resume error. A real impl that RE-ADMITTED the dead session
					// (nil error) would record false here AND serve the fetch below OK, so the
					// directed check and the dual-run both catch a resume-re-admits drift.
					obs.Setf("resume_failed_closed", "%t", resumeErr != nil)
					return obs, nil
				},
			},
			{
				// 4. Post-resume FETCH FAILS CLOSED on the genuine Service: the session was
				// evicted by the fail-closed resume, so even the warmed pair is gone ->
				// SESSION_NOT_LIVE, no credential, and it is NOT the retryable stall.
				Name: "fetch-after-resume-past-deadline-fails-closed",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
		},
	}
}

// TestDualRun_GrantFetch_ResumePastDeadline_RealServer lifts the doc 16 §5.4
// resume-fail-closed invariant onto the REAL grant-service Server at the CENTRAL seam:
// a Resume of a session past its session-lifetime deadline does NOT silently re-admit
// it — the genuine grantservice.Service.Resume re-validates liveness, evicts the dead
// session, and returns ErrSessionNotLive, so a subsequent fetch observes
// SESSION_NOT_LIVE with no credential. Today only the fake-vs-fake
// _SuspendParkResume_NonVacuous covers resume-re-admits-dead-session; this pins the
// fail-closed verdict on the ACTUAL Server (the honest fail-closed end), driven
// through the existing WarmCacheRealEnd.Resume(session, deadlineUnix) lever with a
// PAST deadline. The genuine Service and the generated fake observe the fail-closed
// resume field-for-field identically. Additive: fresh fleets, shares no state with the
// §5.4 suite; synthetic only (D50), no secret bytes (doc 16 §5.2).
func TestDualRun_GrantFetch_ResumePastDeadline_RealServer(t *testing.T) {
	t.Parallel()
	realEnd := grantfetchconform.NewWarmCacheRealEnd(realLifecycleGfSpec())
	fakeFleet := newGfWarmFleet()
	real := dualrun.InProcess(realEnd.Register)
	fake := grantFetchEnd(fakeFleet.responder())
	res, err := gfResumePastDeadlineSuite(realEnd, fakeFleet).Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("identity GrantFetchService §5.4 resume-of-past-deadline (real Server) seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the resume-past-deadline suite is empty")
	}

	// Directed verdict is meaningful only on a green run where every scenario ran
	// cleanly on both ends (a nil Observation would otherwise let the asserts pass).
	assertObs := func(scenario string, check func(end string, kv map[string]string)) {
		t.Helper()
		realObs, fakeObs, ok := res.ObservationsFor(scenario)
		if !ok {
			t.Fatalf("scenario %q not found in dual-run observations", scenario)
		}
		if realObs == nil || fakeObs == nil {
			t.Fatalf("scenario %q is missing an observation (real=%v fake=%v)", scenario, realObs, fakeObs)
		}
		check("real", dualrun.ParseObs(realObs.Canonical()))
		check("fake", dualrun.ParseObs(fakeObs.Canonical()))
	}

	// The resume of the past-deadline session FAILED CLOSED on the genuine Service —
	// the real Service's Resume returned ErrSessionNotLive (resume_failed_closed=true).
	assertObs("resume-past-deadline-onset", func(end string, kv map[string]string) {
		if got := kv["resume_failed_closed"]; got != "true" {
			t.Errorf("%s resume-past-deadline resume_failed_closed = %q, want true (the genuine Service must fail closed on a past-deadline resume)", end, got)
		}
	})

	// The post-resume fetch FAILS CLOSED on the genuine Service: SESSION_NOT_LIVE, no
	// credential, not the retryable stall — a dead session does not come back (§5.4).
	assertObs("fetch-after-resume-past-deadline-fails-closed", func(end string, kv map[string]string) {
		if got := kv["reason"]; got != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE.String() {
			t.Errorf("%s post-resume reason = %q, want SESSION_NOT_LIVE (the real Service must fail closed after a past-deadline resume)", end, got)
		}
		if got := kv["reason_is_stall"]; got != "false" {
			t.Errorf("%s post-resume reason_is_stall = %q, want false (a fail-closed resume is a definitive deny, not a stall)", end, got)
		}
		if got := kv["has_credential"]; got != "false" {
			t.Errorf("%s a fetch after a fail-closed resume must carry no credential, has_credential = %q", end, got)
		}
	})
}

// TestDualRun_GrantFetch_ResumePastDeadline_RealServer_NonVacuous is the ADVERSARIAL
// proof that the real-Server resume-past-deadline pin is NON-VACUOUS: it stands the
// GENUINE grant-service Server up as the honest fail-closed end against a DRIFTED fake
// that RE-ADMITS the dead session on resume (keeps it live and keeps its warmed cache).
// The genuine Server's past-deadline Resume evicts the session (fetch -> SESSION_NOT_-
// LIVE) while the drifted fake serves the warmed pair (fetch -> OK), so the two ends
// DIVERGE — proving the seam catches a resume-re-admits-dead-session drift with the
// REAL Server as the honest end (today only fake-vs-fake covers this). Without it, the
// pin could pass for a degenerate reason (a resume lever that never evicts). The drift
// lives only in this test; the genuine Service is never modified — only WHETHER the
// model re-admits differs.
func TestDualRun_GrantFetch_ResumePastDeadline_RealServer_NonVacuous(t *testing.T) {
	t.Parallel()
	realEnd := grantfetchconform.NewWarmCacheRealEnd(realLifecycleGfSpec())
	driftFleet := newGfWarmFleet()
	real := dualrun.InProcess(realEnd.Register)
	fake := grantFetchEnd(driftFleet.responder())
	suite := dualrun.Suite{
		Seam: "§5.4 real-Server resume-past-deadline fail-closed non-vacuity",
		Scenarios: []dualrun.Scenario{
			{
				Name: "warm",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
			{
				Name: "park",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					realEnd.Park(gfSessionColdMiss)
					driftFleet.park(gfSessionColdMiss)
					return dualrun.NewObservation().Set("session_parked", "true"), nil
				},
			},
			{
				Name: "resume-past-deadline",
				Run: func(_ context.Context, _ *grpc.ClientConn) (*dualrun.Observation, error) {
					// Real: fail-closed resume (past deadline evicts the dead session).
					realEnd.Resume(gfSessionColdMiss, gfResumePastDeadlineUnix)
					// DRIFT: the fake RE-ADMITS the dead session (stillLive=true keeps it live
					// and keeps the warmed cache) — the §5.4 violation the pin must catch.
					driftFleet.resume(gfSessionColdMiss, true)
					return dualrun.NewObservation().Set("session_parked", "false"), nil
				},
			},
			{
				Name: "fetch-after-resume",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					// Real: SESSION_NOT_LIVE (evicted). Drift: OK (rides the re-admitted warm
					// pair) -> divergence.
					return gfWarmFetchObservation(ctx, conn, gfSessionColdMiss, gfServiceGitHub), nil
				},
			},
		},
	}
	res, err := suite.Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a fake that re-admits a past-deadline (dead) session passed the §5.4 seam against the genuine Server — the real-Server resume-past-deadline pin is VACUOUS")
	}
}

// ---------------------------------------------------------------------------
// REAL-Server §5.4 SUSPENDED(reason) eviction-cause observability (01KVSBNR76).
//
// The SuspendReasonProjectionIsReadOnly test above pins the FROZEN attach.v1
// SuspendReason enum (USER vs POLICY_BREACH) read-only — but until now that
// projection was VACUOUS against the real eviction path: the genuine grant-service
// Service.Suspend(sessionUUID) carried NO reason, so the recorded eviction CAUSE was
// not observable at the seam. The Service now records the SUSPENDED(reason) cause on
// a reasoned suspend (SuspendWithReason) and exposes it read-only (LastSuspendReason),
// and the adapter's WarmCacheRealEnd drives both on the SAME genuine Service the
// dual-run dials (grantfetchconform SuspendWithReason / LastSuspendReason).
//
// This block gives the real eviction path its own directed subtest: a Suspend driven
// with POLICY_BREACH vs USER is DISTINGUISHABLE in the real eviction verdict at the
// central seam, projected READ-ONLY from the frozen enum, while EVICTION BEHAVIOR is
// UNCHANGED (a post-suspend fetch still fails closed SESSION_NOT_LIVE with no
// credential). It is purely ADDITIVE: it stands up its OWN WarmCacheRealEnd and shares
// no state with grantFetchSuite, the §5.1 suite, the §5.4 fake-vs-fake or real-Server
// suites, or any negative control — those stay byte-untouched, as does
// SuspendReasonProjectionIsReadOnly. No secret bytes ride any observation (doc 16
// §5.2): the recorded cause is a NON-SECRET classification and the fetch legs pin only
// the reason/has_credential, never the secret.

// TestDualRun_GrantFetch_SuspendReason_RealServer_Observable drives the real
// grant-service Server's §5.4 eviction with a per-session SUSPENDED(reason) cause and
// asserts the cause is observable + distinguishable at the central seam. For each of
// two live github-granted sessions it (1) warms the grant over the served Fetch RPC
// (OK, credential rides), (2) drives a reasoned suspend on the genuine Service via the
// adapter (POLICY_BREACH on one, USER on the other), (3) re-fetches over the seam and
// asserts eviction behavior is UNCHANGED (SESSION_NOT_LIVE, no credential, not a
// stall), and (4) reads the recorded cause back through the read-only accessor and
// asserts it equals the driven reason, projected via the frozen attach.v1 enum. It
// then asserts the two recorded causes are DISTINGUISHABLE — the read-only projection
// the §8.2 resume-authority split reads to tell a USER offboarding from a POLICY_BREACH
// BIC suspension. The frozen enum is consumed READ-ONLY (D77): no re-declare, no new
// enum, no proto edit.
func TestDualRun_GrantFetch_SuspendReason_RealServer_Observable(t *testing.T) {
	t.Parallel()
	realEnd := grantfetchconform.NewWarmCacheRealEnd(realLifecycleGfSpec())
	real := dualrun.InProcess(realEnd.Register)
	conn, stop, err := real.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial real grant-service Server: %v", err)
	}
	defer stop()
	ctx := context.Background()

	// reasonOf drives one Fetch over the served seam and reads the observed in-band
	// reason (the frozen GrantFetchReason projection), never a secret.
	reasonOf := func(session, service string) map[string]string {
		obs := gfWarmFetchObservation(ctx, conn, session, service)
		return dualrun.ParseObs(obs.Canonical())
	}

	cases := []struct {
		name    string
		session string
		suspend func(session string)
		want    attachv1.SuspendReason
	}{
		{
			// POLICY_BREACH is the D77 genuine-threat class, driven via the reasoned
			// SuspendWithReason lever on the genuine Service.
			name:    "policy-breach",
			session: gfSessionColdMiss,
			suspend: func(s string) {
				realEnd.SuspendWithReason(s, attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH)
			},
			want: attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		},
		{
			// USER is the offboarding/user-initiated class; the bare Suspend shim records
			// it, so this drives the sessionUUID-only lever and expects USER.
			name:    "user-offboarding",
			session: gfSessionWarm,
			suspend: func(s string) { realEnd.Suspend(s) },
			want:    attachv1.SuspendReason_SUSPEND_REASON_USER,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// 1. Warm the github grant over the served RPC: OK with the credential.
			if kv := reasonOf(c.session, gfServiceGitHub); kv["reason"] != identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String() {
				t.Fatalf("pre-suspend warm fetch reason = %q, want OK", kv["reason"])
			}
			// No cause recorded before the suspend fires (fail-closed absence).
			if _, ok := realEnd.LastSuspendReason(c.session); ok {
				t.Fatalf("no suspend reason should be recorded for %q before suspend", c.session)
			}

			// 2. Drive the reasoned suspend on the genuine Service.
			c.suspend(c.session)

			// 3. Eviction behavior UNCHANGED: a post-suspend fetch fails closed
			// SESSION_NOT_LIVE with no credential, and it is NOT the retryable stall.
			kv := reasonOf(c.session, gfServiceGitHub)
			if kv["reason"] != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE.String() {
				t.Fatalf("post-suspend reason = %q, want SESSION_NOT_LIVE (eviction behavior must be unchanged)", kv["reason"])
			}
			if kv["has_credential"] != "false" {
				t.Fatalf("suspended-session fetch must carry no credential, has_credential = %q", kv["has_credential"])
			}
			if kv["reason_is_stall"] != "false" {
				t.Fatalf("eviction is a definitive deny, not a stall, reason_is_stall = %q", kv["reason_is_stall"])
			}

			// 4. The recorded cause is observable at the seam AFTER eviction, projected
			// read-only from the frozen enum, and equals the driven reason.
			got, ok := realEnd.LastSuspendReason(c.session)
			if !ok {
				t.Fatal("the real Service must record the SUSPENDED(reason) cause, read-back-able after eviction")
			}
			if got != c.want {
				t.Fatalf("recorded suspend cause = %q, want %q", got.String(), c.want.String())
			}
			// The projection is a non-secret classification (doc 16 §5.2).
			if strings.Contains(got.String(), gfSecretGitHub) {
				t.Fatalf("a SuspendReason projection must never carry secret material: %q", got.String())
			}
		})
	}

	// 5. The two recorded causes are DISTINGUISHABLE in the real eviction verdict —
	// the read-only projection the §8.2 resume-authority split reads to tell a USER
	// offboarding from a POLICY_BREACH BIC suspension.
	policy, okP := realEnd.LastSuspendReason(gfSessionColdMiss)
	user, okU := realEnd.LastSuspendReason(gfSessionWarm)
	if !okP || !okU {
		t.Fatalf("both sessions must carry a recorded cause (policy=%v user=%v)", okP, okU)
	}
	if policy == user {
		t.Fatalf("USER and POLICY_BREACH eviction causes must be distinguishable at the seam, both = %q", policy.String())
	}
	if policy != attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH || user != attachv1.SuspendReason_SUSPEND_REASON_USER {
		t.Fatalf("recorded causes drifted: policy=%q user=%q", policy.String(), user.String())
	}
}

// ---------------------------------------------------------------------------
// REAL-Server §8.2 resume-authority split (01KWXTZM68).
//
// SuspendReason_RealServer_Observable above pins that the eviction CAUSE
// (POLICY_BREACH vs USER) is recorded + read-back-able at the seam. This block
// pins what the recorded cause is FOR: the doc 16 §8.2 resume-authority split (D35).
// The genuine grant-service Service now consumes LastSuspendReason at the resume
// site — a session whose recorded last-suspend reason is the genuine-threat
// POLICY_BREACH FAILS CLOSED on the plain Resume path (resume authority is human
// approval) and PROCEEDS only through ResumeWithApproval carrying an explicit
// attestation, while USER/REBALANCE/no-recorded-reason resume on the existing plain
// path UNCHANGED. The adapter's WarmCacheRealEnd drives Resume/ResumeWithApproval/
// RegisterSession on the SAME Service the dual-run dials, so the split's verdict is
// observable at the central seam: a POLICY_BREACH session's plain resume is
// DISTINGUISHABLE from a USER session's (blocked vs proceeds), and the POLICY_BREACH
// session serves again over the Fetch RPC ONLY after the approved resume.
//
// It is purely ADDITIVE: it stands up its OWN WarmCacheRealEnd and shares no state
// with grantFetchSuite, the §5.1 suite, any §5.4 suite, SuspendReasonProjectionIsReadOnly,
// or any negative control — those stay byte-untouched. The frozen attach.v1
// SuspendReason enum is consumed READ-ONLY (D77): no re-declare, no new enum, no
// proto edit. No secret bytes ride any observation (doc 16 §5.2): the fetch legs pin
// only reason/has_credential, and the approval attestation is a non-secret marker.

// TestDualRun_GrantFetch_ResumeAuthority_RealServer drives the real grant-service
// Server's §8.2 resume-authority split and asserts the POLICY_BREACH resume path is
// observably distinguishable from the USER path at the central seam. For the
// POLICY_BREACH session it (1) warms the grant over the served Fetch RPC (OK), (2)
// drives a genuine-threat suspend (SuspendWithReason POLICY_BREACH), (3) confirms
// eviction behavior is UNCHANGED at the seam (post-suspend fetch fails closed
// SESSION_NOT_LIVE, no credential), (4) re-admits the session and asserts the plain
// Resume FAILS CLOSED (the §8.2 gate keys on the read-back-able POLICY_BREACH
// record, which survived eviction), (5) drives ResumeWithApproval carrying an
// explicit human-approval attestation and asserts it PROCEEDS, and (6) confirms the
// session serves again over the Fetch RPC (OK). For the USER session it drives the
// bare Suspend, re-admits, and asserts the plain Resume PROCEEDS unchanged (no
// attestation) and the session serves again — the observable distinction: the
// POLICY_BREACH session's plain resume is blocked where the USER session's is not.
func TestDualRun_GrantFetch_ResumeAuthority_RealServer(t *testing.T) {
	t.Parallel()
	realEnd := grantfetchconform.NewWarmCacheRealEnd(realLifecycleGfSpec())
	real := dualrun.InProcess(realEnd.Register)
	conn, stop, err := real.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial real grant-service Server: %v", err)
	}
	defer stop()
	ctx := context.Background()

	// reasonOf drives one Fetch over the served seam and reads the observed in-band
	// reason (the frozen GrantFetchReason projection), never a secret.
	reasonOf := func(session, service string) map[string]string {
		obs := gfWarmFetchObservation(ctx, conn, session, service)
		return dualrun.ParseObs(obs.Canonical())
	}
	okReason := identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK.String()
	notLive := identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE.String()

	// --- POLICY_BREACH session: resume authority is human approval (§8.2, D35). ---
	pb := gfSessionColdMiss
	t.Run("policy-breach-plain-resume-blocked-approved-proceeds", func(t *testing.T) {
		// 1. Warm the github grant over the served RPC: OK with the credential.
		if kv := reasonOf(pb, gfServiceGitHub); kv["reason"] != okReason {
			t.Fatalf("pre-suspend warm fetch reason = %q, want OK", kv["reason"])
		}
		// 2. A genuine-threat (BIC) suspend: evict + record POLICY_BREACH.
		realEnd.SuspendWithReason(pb, attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH)
		// 3. Eviction behavior UNCHANGED at the seam: post-suspend fetch fails closed.
		if kv := reasonOf(pb, gfServiceGitHub); kv["reason"] != notLive || kv["has_credential"] != "false" {
			t.Fatalf("post-suspend fetch reason = %q has_credential = %q, want SESSION_NOT_LIVE / false (eviction unchanged)", kv["reason"], kv["has_credential"])
		}
		// 4. Re-admit the session; the POLICY_BREACH cause survived eviction and is
		// still on record — the plain Resume FAILS CLOSED (resume authority is human
		// approval, not the plain path).
		realEnd.RegisterSession(pb)
		if err := realEnd.Resume(pb, 0); err == nil {
			t.Fatal("plain Resume of a POLICY_BREACH-suspended session must fail closed at the seam")
		}
		// 5. ResumeWithApproval carrying an explicit NON-SECRET attestation PROCEEDS.
		if err := realEnd.ResumeWithApproval(pb, 0, "org-admin:alice", "ask-grant:synthetic-001"); err != nil {
			t.Fatalf("approved resume of a POLICY_BREACH-suspended session must proceed, got: %v", err)
		}
		// 6. The session serves again over the Fetch RPC: OK with the credential.
		if kv := reasonOf(pb, gfServiceGitHub); kv["reason"] != okReason || kv["has_credential"] != "true" {
			t.Fatalf("post-approved-resume fetch reason = %q has_credential = %q, want OK / true", kv["reason"], kv["has_credential"])
		}
	})

	// --- USER session: resumes on the existing plain path UNCHANGED (no attestation). ---
	user := gfSessionWarm
	t.Run("user-plain-resume-proceeds-unchanged", func(t *testing.T) {
		// 1. Warm over the served RPC: OK.
		if kv := reasonOf(user, gfServiceGitHub); kv["reason"] != okReason {
			t.Fatalf("pre-suspend warm fetch reason = %q, want OK", kv["reason"])
		}
		// 2. The bare Suspend shim records USER (§11.2 offboarding fires the existing signal).
		realEnd.Suspend(user)
		if kv := reasonOf(user, gfServiceGitHub); kv["reason"] != notLive {
			t.Fatalf("post-suspend fetch reason = %q, want SESSION_NOT_LIVE", kv["reason"])
		}
		// 3. Re-admit; the plain Resume PROCEEDS unchanged — USER is NOT made to fail
		// closed and no attestation is invented for it (the D35 split enforced exactly).
		realEnd.RegisterSession(user)
		if err := realEnd.Resume(user, 0); err != nil {
			t.Fatalf("plain Resume of a USER-suspended session must proceed unchanged, got: %v", err)
		}
		if kv := reasonOf(user, gfServiceGitHub); kv["reason"] != okReason {
			t.Fatalf("post-resume fetch reason = %q, want OK", kv["reason"])
		}
	})

	// The observable distinction at the seam: a POLICY_BREACH-suspended session's
	// plain resume is BLOCKED (fails closed) where a USER-suspended session's plain
	// resume PROCEEDS — the §8.2 authority split, read from the recorded cause.
	realEnd2 := grantfetchconform.NewWarmCacheRealEnd(realLifecycleGfSpec())
	realEnd2.SuspendWithReason(gfSessionColdMiss, attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH)
	realEnd2.Suspend(gfSessionWarm)
	realEnd2.RegisterSession(gfSessionColdMiss)
	realEnd2.RegisterSession(gfSessionWarm)
	pbErr := realEnd2.Resume(gfSessionColdMiss, 0)
	userErr := realEnd2.Resume(gfSessionWarm, 0)
	if pbErr == nil {
		t.Fatal("POLICY_BREACH plain resume must be blocked (the §8.2 gate)")
	}
	if userErr != nil {
		t.Fatalf("USER plain resume must proceed unchanged, got: %v", userErr)
	}
	// A NON-SECRET attestation clears the POLICY_BREACH gate; the two paths are
	// distinguishable only by the recorded cause, not by any secret material.
	if err := realEnd2.ResumeWithApproval(gfSessionColdMiss, 0, "org-admin:bob", "ref-2"); err != nil {
		t.Fatalf("approved POLICY_BREACH resume must proceed, got: %v", err)
	}
	if strings.Contains("org-admin:bobref-2", gfSecretGitHub) {
		t.Fatal("a resume approval attestation must never carry secret material (doc 16 §5.2)")
	}
}
