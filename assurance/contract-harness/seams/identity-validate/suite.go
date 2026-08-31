// SPDX-License-Identifier: Apache-2.0

package identityvalidate

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
)

// Synthetic fixtures (D50). Every identifier is obviously-synthetic — no real
// session uuids, service ids, tokens, or grant refs. synthNow is the fixed
// validation fence the reference impl and the fake both compare expiries
// against: an expiry <= synthNow is expired, one > synthNow is fresh, so the two
// ends agree deterministically without a wall clock. The seeded session and its
// two-service grant set are the standing live fleet the suite validates against;
// no scenario mutates them, so the dual-run is order-independent.
const (
	// synthNow is the synthetic "current time" fence (obviously-synthetic, well
	// inside a plausible range so the +/- offsets below are unambiguous).
	synthNow = int64(1_700_000_000)

	synthSessionLive    = "ses-synthetic-live-aaaa0000"
	synthSessionRevoked = "ses-synthetic-revoked-bbbb1111"
	synthSessionUnknown = "ses-synthetic-unknown-cccc2222"

	// A distinct LIVE session whose github grant's OWN TTL is already in the past
	// — the seedable past-TTL grant fleet that drives the PRODUCTION RefImpl.Validate
	// caller down the GRANT-TTL freshness leg (HonestDecision step 4, grantExpiry <=
	// now -> credential_expired, refimpl.go), distinct from the token-expiry leg
	// step 3 exercises. Its own session is live and a FRESH token is presented, so
	// the ONLY thing that fails is the grant's own TTL. A dedicated uuid (nothing
	// else references it) keeps the standing fleet's behavior unchanged — this
	// session is opt-in via RealDialerWithExpiredGrant(), never the default fleet.
	synthSessionExpiredGrant = "ses-synthetic-expiredgrant-eeee6666"

	// A distinct LIVE session whose github grant's OWN TTL is NEAR-future (fresh,
	// but TIGHTER than a far-future token) — the grant-wins-the-min fleet that
	// closes the symmetric intersection-horizon corner. Existing coverage pins only
	// the token-wins leg (a near-future TOKEN over synthSessionLive's far-future
	// grant, the tighter TOKEN horizon wins). This session is the mirror image: a
	// FRESH far-future token over a fresh but NEARER grant, so the ALLOW horizon is
	// the tighter GRANT horizon (min(grant TTL, token TTL) = the grant, doc 16 §5.1,
	// doc 19 §8). Its own session is live and the grant is FRESH, so the presentation
	// ALLOWs — unlike synthSessionExpiredGrant, whose grant is PAST (a DENY). A
	// dedicated uuid nothing else references keeps every other scenario unchanged; it
	// is seeded into the standing fleet (StandingFleetSeeds) exactly as synthSessionLive
	// is, so the grant-wins scenario rides the shared RealDialer()/FakeDialer() pair.
	synthSessionNearGrant = "ses-synthetic-neargrant-ffff7777"

	// Chained-token (doc 19 §7) fleet. The root is the chain origin; two
	// descendants re-root off it. synthSessionDescLive is a live descendant of a
	// LIVE root (good chain). synthSessionDescOfRevokedRoot is a live descendant
	// of a REVOKED root — its own session is independently live, but whole-chain
	// liveness keys on the dead root, so it fails closed (the cascade). The
	// cross-host descendant inherits a root the validating host has NO record of,
	// so it is governed by its own liveness alone.
	synthRootLive    = "ses-synthetic-root-live-dddd3333"
	synthRootRevoked = "ses-synthetic-root-revoked-eeee4444"
	// A root naming a chain origin this validating host never minted/recorded —
	// the cross-host case (governed by the descendant's own liveness).
	synthRootCrossHost = "ses-synthetic-root-crosshost-ffff5555"

	synthSessionDescLive          = "ses-synthetic-desc-live-1111aaaa"
	synthSessionDescOfRevokedRoot = "ses-synthetic-desc-ofrevoked-2222bbbb"
	synthSessionDescCrossHost     = "ses-synthetic-desc-crosshost-3333cccc"
	// A per-child-revoked descendant of the LIVE root: the child's own session is
	// dead, but the root (and its siblings) stay live — per-child revocation is
	// scoped, it does not take the chain down.
	synthSessionDescChildRevoked = "ses-synthetic-desc-childrevoked-4444dddd"

	// The DEDICATED revoked-root chain fleet, on its OWN synthetic uuids (nothing
	// else references them). It mirrors the seedable past-TTL grant fleet pattern
	// (synthSessionExpiredGrant above) but for the dead-root CASCADE leg: a KNOWN-
	// dead inherited ROOT plus an INDEPENDENTLY-LIVE descendant re-rooted off it.
	// RealDialerWithRevokedRootChain() seeds the PRODUCTION RefImpl with this pair
	// only, so the dead-root cascade (HonestDecision step 2, whole-chain liveness)
	// can be pinned on the REAL caller in isolation — the cascade DENYs the live
	// descendant on the dead root BEFORE the grant leg is ever consulted, so no
	// descendant grant is needed to observe it. Because these uuids are dedicated
	// (distinct from synthRootRevoked / synthSessionDescOfRevokedRoot, which are
	// coupled to the standing seedFleet), seeding them perturbs no standing fixture.
	synthChainRootRevoked  = "ses-synthetic-chainroot-revoked-7777eeee"
	synthChainDescLiveRoot = "ses-synthetic-chaindesc-liveroot-8888ffff"

	synthHostID    = "host-synthetic-validate-01"
	synthHostIndex = uint64(7)
	synthTapName   = "dstap-7"

	// The two services the live session is granted. The github row is the doc 16
	// §11.1 strawman; the registry row is a second synthetic service so the
	// intersection narrowing has something to exclude.
	synthServiceGitHub   = "svc-synthetic-github"
	synthServiceRegistry = "svc-synthetic-registry"
	// A service the session holds NO grant for — the out-of-grant target.
	synthServiceUngranted = "svc-synthetic-ungranted"

	synthGrantRefGitHub   = "grantref-synthetic-github-d34db33f"
	synthGrantRefRegistry = "grantref-synthetic-registry-f00dcafe"
	// The grant_ref a descendant session resolves on ALLOW — distinct from the
	// root's so a verdict observably names the descendant's own grant record.
	synthGrantRefDescGitHub = "grantref-synthetic-desc-github-c0ffee01"
	// The grant_ref the past-TTL grant fleet's github grant carries. It is never
	// returned (the grant's own TTL fails freshness, so the verdict is a DENY that
	// carries no grant_ref), but it keeps the past-TTL grant record contract-shaped.
	synthGrantRefExpiredGitHub = "grantref-synthetic-expired-github-deadc0de"
	// The grant_ref the near-future grant fleet's github grant carries. Unlike the
	// expired ref, this one IS returned on ALLOW (the grant is fresh), so the
	// grant-wins-the-min scenario observably names the near-grant record.
	synthGrantRefNearGitHub = "grantref-synthetic-near-github-beefcafe"
)

// Fixed expiry horizons, expressed relative to synthNow so the freshness and
// intersection-narrowing semantics are legible at the call site.
const (
	expiryFarFuture  = synthNow + 3600 // fresh, the wider horizon
	expiryNearFuture = synthNow + 600  // fresh, the tighter horizon (token wins the min)
	expiryPast       = synthNow - 600  // expired
)

// SyntheticFixtureConstants projects the production-side synthetic fixture constants
// (the unexported synth* / expiry* values above, D50) into an exported map keyed by a
// stable name, so the external _test package can read the SAME authoritative values it
// keeps a test* twin of (testNow == synthNow, testSessionLive == synthSessionLive, …).
// The two constant sets were previously kept equal only by convention across the
// production/_test boundary; this accessor lets dualrun_test.go pin each test* ==
// synth* pair as a STANDING guard so a future edit to either side that desyncs a value
// fails CI instead of silently splitting the fence the two ends validate against. The
// keys are the suffix the test* / synth* names share (e.g. "SessionLive" for
// synthSessionLive / testSessionLive), so the guard table reads as a direct pairing.
// Behavior-preserving and additive: it only reads the existing constants, mutates
// nothing, and is referenced solely by the cross-boundary constant guard. Synthetic
// fixtures only (D50).
func SyntheticFixtureConstants() map[string]any {
	return map[string]any{
		"Now": synthNow,

		"SessionLive":         synthSessionLive,
		"SessionRevoked":      synthSessionRevoked,
		"SessionUnknown":      synthSessionUnknown,
		"SessionExpiredGrant": synthSessionExpiredGrant,

		"RootLive":      synthRootLive,
		"RootRevoked":   synthRootRevoked,
		"RootCrossHost": synthRootCrossHost,

		"SessionDescLive":          synthSessionDescLive,
		"SessionDescOfRevokedRoot": synthSessionDescOfRevokedRoot,
		"SessionDescCrossHost":     synthSessionDescCrossHost,
		"SessionDescChildRevoked":  synthSessionDescChildRevoked,

		"ChainRootRevoked":  synthChainRootRevoked,
		"ChainDescLiveRoot": synthChainDescLiveRoot,

		"ServiceGitHub":    synthServiceGitHub,
		"ServiceRegistry":  synthServiceRegistry,
		"ServiceUngranted": synthServiceUngranted,

		"GrantRefGitHub":        synthGrantRefGitHub,
		"GrantRefRegistry":      synthGrantRefRegistry,
		"GrantRefDescGitHub":    synthGrantRefDescGitHub,
		"GrantRefExpiredGitHub": synthGrantRefExpiredGitHub,

		"ExpiryFarFuture":  int64(expiryFarFuture),
		"ExpiryNearFuture": int64(expiryNearFuture),
		"ExpiryPast":       int64(expiryPast),
	}
}

// liveGrants is the standing live session's grant set: github + registry, both
// far-future. The suite seeds this on both ends.
func liveGrants() map[string]grant {
	return map[string]grant{
		synthServiceGitHub:   {ref: synthGrantRefGitHub, expiryUnixSecond: expiryFarFuture},
		synthServiceRegistry: {ref: synthGrantRefRegistry, expiryUnixSecond: expiryFarFuture},
	}
}

// descGrants is a descendant session's far-future grant set (github only,
// re-rooted off a chain). The descendant resolves its OWN grant_ref, so a chained
// ALLOW observably names the descendant's grant record, not the root's. The suite
// seeds this on both ends for every descendant whose own session is live.
func descGrants() map[string]grant {
	return map[string]grant{
		synthServiceGitHub: {ref: synthGrantRefDescGitHub, expiryUnixSecond: expiryFarFuture},
	}
}

// expiredGrants is a session's PAST-TTL grant set: a github grant whose OWN TTL
// (expiryPast, <= synthNow) is already expired. A FRESH token over a LIVE session
// holding this grant passes signature/binding, two-key liveness, and token
// freshness, then fails HonestDecision step 4's grant-TTL check (grantExpiry <=
// now -> credential_expired, refimpl.go) — the grant-TTL freshness leg, distinct
// from the token-expiry leg. Seeded only via RealDialerWithExpiredGrant() onto a
// dedicated session uuid, so the standing fleet stays unchanged.
func expiredGrants() map[string]grant {
	return map[string]grant{
		synthServiceGitHub: {ref: synthGrantRefExpiredGitHub, expiryUnixSecond: expiryPast},
	}
}

// nearGrants is a session's NEAR-future grant set: a github grant whose OWN TTL
// (expiryNearFuture, > synthNow) is fresh but TIGHTER than a far-future token. A
// FRESH far-future token over a LIVE session holding this grant passes every leg
// and ALLOWs, with the ALLOW expiry narrowed to the GRANT's nearer horizon —
// min(grant TTL, token TTL) = the grant (doc 16 §5.1, doc 19 §8). It is the
// grant-wins mirror of the token-wins leg (which narrows to the tighter TOKEN).
// Seeded into the standing fleet on the dedicated synthSessionNearGrant uuid, so
// the grant-wins scenario rides the shared RealDialer()/FakeDialer() pair.
func nearGrants() map[string]grant {
	return map[string]grant{
		synthServiceGitHub: {ref: synthGrantRefNearGitHub, expiryUnixSecond: expiryNearFuture},
	}
}

// SeedGrant is the exported projection of one per-service grant the standing
// fleet table carries: the grant_ref returned on ALLOW and the grant's own TTL.
// It exists so the external _test package can read the SAME authoritative seed
// list seedFleet consumes (the production-side grant struct is unexported), the
// way TestToken exposes parseToken's view — the test-side honestStandingFleet()
// mirror projects these fields into its own honestGrant. Synthetic fixtures only
// (D50).
type SeedGrant struct {
	Ref              string
	ExpiryUnixSecond int64
}

// SeedEntry is the exported projection of ONE standing-fleet session: its uuid,
// own-session liveness bit, and the grants it holds (keyed by service_id). It is
// the single, exported-enough shape that makes StandingFleetSeeds() readable from
// the external _test package, so suite.go's seedFleet and dualrun_test.go's
// honestStandingFleet() both derive from one list instead of two hand-maintained
// mirrors. Synthetic fixtures only (D50).
type SeedEntry struct {
	UUID   string
	Live   bool
	Grants map[string]SeedGrant
}

// seedGrants projects an internal grant set into its exported SeedGrant view so
// the standing-fleet table reuses the SAME liveGrants()/descGrants() data the
// dialers seed, rather than re-typing the grant_ref/expiry pairs. A nil input
// (an ungranted liveness anchor) projects to nil, exactly as seedFleet seeded it.
func seedGrants(g map[string]grant) map[string]SeedGrant {
	if g == nil {
		return nil
	}
	out := make(map[string]SeedGrant, len(g))
	for svc, gr := range g {
		out[svc] = SeedGrant{Ref: gr.ref, ExpiryUnixSecond: gr.expiryUnixSecond}
	}
	return out
}

// StandingFleetSeeds is the SINGLE authoritative declaration of the standing
// validate fleet — the ordered session set seedFleet installs on a reference impl
// AND that dualrun_test.go's honestStandingFleet() mirrors on the honest-responder
// side. Both ends derive from THIS list (suite.go projects each entry into
// RefImpl.SeedSession; the _test package projects each into its honestSession map),
// so the two can no longer silently desync: a future seeded session or grant is
// added here ONCE and both ends pick it up, keeping the callers-table joint-pinning
// guarantee self-maintaining. The dedicated revoked-root chain pair is NOT part of
// this list — it is layered on the RefImpl side by seedRevokedRootChainFleet and is
// deliberately absent from the honest standing mirror, exactly as before. The
// cross-host root and the unknown session are likewise absent (the validating host
// has no record of them). Synthetic fixtures only (D50).
func StandingFleetSeeds() []SeedEntry {
	return []SeedEntry{
		// The standing live session with its two-service (github+registry) grant set
		// and the own-session-revoked session (no grants, not live, doc 16 §5.4).
		{UUID: synthSessionLive, Live: true, Grants: seedGrants(liveGrants())},
		{UUID: synthSessionRevoked, Live: false, Grants: nil},

		// The grant-wins-the-min session: a LIVE session whose github grant is fresh
		// but NEARER than a far-future token, so a far-future token ALLOWs with the
		// tighter GRANT horizon (the mirror of synthSessionLive's token-wins leg). On
		// a dedicated uuid nothing else references, so it perturbs no other scenario.
		{UUID: synthSessionNearGrant, Live: true, Grants: seedGrants(nearGrants())},

		// Chained-token (doc 19 §7) fleet. Roots carry no grants of their own — they
		// exist only as liveness anchors the descendants inherit; the descendant
		// resolves the grant. The cross-host root is deliberately NOT seeded: the
		// validating host has no record of it (the cross-host leg).
		{UUID: synthRootLive, Live: true, Grants: nil},
		{UUID: synthRootRevoked, Live: false, Grants: nil},

		// Descendants whose OWN session is live. synthSessionDescOfRevokedRoot is
		// itself live on purpose — proving the cascade kills it via the dead ROOT,
		// not via its own session.
		{UUID: synthSessionDescLive, Live: true, Grants: seedGrants(descGrants())},
		{UUID: synthSessionDescOfRevokedRoot, Live: true, Grants: seedGrants(descGrants())},
		{UUID: synthSessionDescCrossHost, Live: true, Grants: seedGrants(descGrants())},
		// A descendant of the LIVE root whose OWN session has been per-child revoked:
		// scoped revocation, the root and siblings stay live.
		{UUID: synthSessionDescChildRevoked, Live: false, Grants: seedGrants(descGrants())},
	}
}

// sessionRef builds the shared boundary.v1.SessionRef join quartet for a uuid
// (doc 14 §2/§4 — imported, never redefined). The host/index/tap fields are
// obviously-synthetic and stable so the request shape is deterministic.
func sessionRef(uuid string) *boundaryv1.SessionRef {
	return &boundaryv1.SessionRef{
		SessionUuid:      uuid,
		HostId:           synthHostID,
		HostSessionIndex: synthHostIndex,
		TapName:          synthTapName,
	}
}

// Suite is the identity-validate seam's single conformance suite (doc 06 §3a:
// one suite, run against real + fake). Every scenario is stated purely in terms
// of the frozen identity.v1 IdentityValidationService.Validate contract (the D22
// seam, doc 16 §4 / §9), so the same suite is meaningful against any faithful
// validator substrate (M0 shim -> M1 minimal CA -> M3 SPIFFE/SPIRE, doc 16 §2).
// It drives the Validate verb across the properties the contract turns on
// (doc 16 §5.1, doc 19 §5/§8): grant-intersection NARROWING (a token narrower
// than the session's grants reaches only the intersection, and the ALLOW expiry
// is the tighter horizon), EXPIRY rejection (a stale credential is denied),
// OVER-SCOPE refusal (a service outside the token's attenuated scope, or outside
// the session's grants, is refused), SESSION-LIVENESS rejection (a revoked /
// unknown session fails closed), CHAINED-TOKEN TWO-KEY liveness (doc 19 §7: a
// good chain validates; a broken link — revoked root — cascades to every
// descendant even while the descendant's own session is live, proven on both the
// standing fleet AND a DEDICATED revoked-root chain fleet whose live descendant
// presented un-rooted instead falls through to the grant leg; per-child revocation
// stays scoped to the child; a cross-host unknown root is governed by the
// descendant's own liveness), and IDEMPOTENT validation (re-presenting yields the
// same verdict).
//
// These scenarios realize the doc 19 §13 token-assurance rows ("Assurance hooks
// (proposed (c)-row candidates)"): the chained-token two-key-liveness matrix
// (good chain / revoked-root cascade / scoped per-child / cross-host unknown
// root) and the idempotency row map one-to-one onto the chainedScenario(...)
// builds and validate/idempotent-re-presentation-same-verdict below. §13 and this
// suite are kept in lockstep — a §7 semantics change moves both.
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "ds-tlsproxy(swap-executor)<->identity(IdentityValidationService.Validate)",
		Scenarios: scenarios(),
	}
}

// chainedScenario builds ONE chained-token (doc 19 §7) scenario from the only
// three things the four standing chained-cascade scenarios actually vary: the
// scenario name, the DESCENDANT session the token re-roots to, and the inherited
// ROOT it carries. Every chained-cascade body is otherwise byte-identical — mint a
// chained token for (descUUID, rootUUID) over the github service and the far-future
// horizon, present it against the descendant's own SessionRef for the github
// service, and project the verdict (or the gRPC error) into the shared Observation
// shape — so the four scenarios differ ONLY in their {name, descendant, root}
// triple. Folding that triple into one builder means a future change to the chained
// presentation (a new field on the request, a different service, a tweak to the
// observation projection) lands in ONE place for all four, and a new chained-cascade
// case is one more builder call rather than another copied closure. The verdict the
// scenario observes is decided ENTIRELY by the fleet the dialer seeds (whole-chain
// liveness on the root, own-session liveness on the descendant, then the grant leg),
// so the builder states no expectation of its own — the good chain ALLOWs, a dead
// root cascades to session_not_live, a per-child-revoked descendant fails on its own
// session, and an unknown cross-host root falls through to the descendant's liveness,
// each because the seeded fleet says so, not because the builder special-cases it.
// Synthetic fixtures only (D50).
func chainedScenario(name, descUUID, rootUUID string) dualrun.Scenario {
	return dualrun.Scenario{
		Name: name,
		Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
			cl := identityv1.NewIdentityValidationServiceClient(conn)
			tok := MintChainedToken(descUUID, rootUUID, expiryFarFuture, synthServiceGitHub)
			resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
				PresentedCredential: tok,
				SessionRef:          sessionRef(descUUID),
				ServiceId:           synthServiceGitHub,
			})
			if err != nil {
				return errObservation(err), nil
			}
			return verdictObservation(resp), nil
		},
	}
}

func scenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "validate/allow-in-grant-and-in-scope",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// A token scoped to the github service, presented against the live
				// session for the github service: in-grant AND in-scope -> ALLOW,
				// with the granted ref and the far-future grant horizon (the token's
				// own far-future expiry is not tighter).
				tok := MintToken(synthSessionLive, expiryFarFuture, synthServiceGitHub, synthServiceRegistry)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionLive),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/grant-intersection-narrows-expiry-to-tighter-horizon",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// The session's github grant is far-future, but the presented token
				// attenuates to a NEARER expiry. The intersection horizon is the
				// tighter of the two — the ALLOW expiry must be the token's near
				// future, not the grant's far future (doc 16 §5.1, doc 19 §8).
				tok := MintToken(synthSessionLive, expiryNearFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionLive),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/grant-intersection-narrows-expiry-to-tighter-grant-horizon",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// The SYMMETRIC grant-wins-the-min corner (mirror of the token-wins
				// scenario above). The presented token is FAR-future, but the near-grant
				// session's github grant is NEARER (still fresh). The intersection horizon
				// is the tighter of the two — here the ALLOW expiry must be the GRANT's
				// near future, not the token's far future, and it carries the near-grant
				// ref (doc 16 §5.1, doc 19 §8). Existing coverage pinned only the token-wins
				// leg; this closes the last intersection-horizon corner.
				tok := MintToken(synthSessionNearGrant, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionNearGrant),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/over-scope-refused-service-outside-token-attenuation",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// The session IS granted the registry service, but the presented
				// token's attenuated scope is github-ONLY. Requesting the registry
				// service is OVER-SCOPED relative to the token: the grant-intersection
				// refuses it with out_of_grant, even though the session-level grant
				// exists (doc 16 §5.1, doc 19 §5/§8). This is the attenuation leg the
				// session-grant lookup alone would miss.
				tok := MintToken(synthSessionLive, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionLive),
					ServiceId:           synthServiceRegistry,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/over-scope-refused-service-outside-session-grants",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// The token names a service the SESSION holds no grant for. Even an
				// honest token cannot reach a service the session was never granted —
				// out_of_grant on the grant-set side of the intersection.
				tok := MintToken(synthSessionLive, expiryFarFuture, synthServiceGitHub, synthServiceUngranted)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionLive),
					ServiceId:           synthServiceUngranted,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/expired-credential-rejected",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// A token whose expiry is in the past fails the freshness leg —
				// credential_expired — regardless of grant/scope. TTL is the
				// minimal-CA revocation instrument (doc 16 §5.4).
				tok := MintToken(synthSessionLive, expiryPast, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionLive),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/revoked-session-fails-closed",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// A still-unexpired, in-scope token presented against a session that
				// has been admin-revoked / killed fails the SESSION-LIVENESS leg —
				// session_not_live. The minimal CA has no CRL/OCSP, so liveness is
				// what makes a stolen-but-unexpired credential fail immediately
				// (doc 16 §5.4).
				tok := MintToken(synthSessionRevoked, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionRevoked),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		// The four standing chained-cascade (doc 19 §7) scenarios, each built from the
		// shared chainedScenario(name, descendant, root) builder — they vary ONLY in
		// the {name, descendant, root} triple, every closure body otherwise identical.
		// The verdict each observes is decided by the seeded fleet's two-key liveness +
		// grant legs, not the builder:
		//
		//   - good chain: a LIVE descendant inheriting a LIVE root — both keys hold, so
		//     the chain validates and resolves the descendant's OWN grant_ref;
		chainedScenario("validate/chained-good-chain-live-root-and-live-descendant-allows",
			synthSessionDescLive, synthRootLive),
		//   - broken link: the descendant's OWN session is independently live, but the
		//     inherited ROOT is revoked — whole-chain liveness keys on root_session, so
		//     the descendant fails closed session_not_live despite its live own-session;
		chainedScenario("validate/chained-broken-link-revoked-root-cascades-even-while-descendant-live",
			synthSessionDescOfRevokedRoot, synthRootRevoked),
		//   - per-child: a descendant of the LIVE root whose OWN session has been
		//     revoked — it fails closed (session_not_live) on its own session, but the
		//     cascade does NOT run the other way (the good-chain sibling proves the root
		//     and its other descendants stay live);
		chainedScenario("validate/chained-per-child-revocation-stays-scoped-to-the-child",
			synthSessionDescChildRevoked, synthRootLive),
		//   - cross-host: the inherited root names a chain origin this host has NO record
		//     of — an unknown root is not evidence of revocation, so the descendant's OWN
		//     liveness governs; the live descendant ALLOWs on its grant_ref.
		chainedScenario("validate/chained-cross-host-unknown-root-governed-by-descendant-liveness",
			synthSessionDescCrossHost, synthRootCrossHost),
		{
			Name: "validate/chained-dedicated-fleet-revoked-root-cascades-on-live-descendant",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// The dead-root cascade on a DEDICATED revoked-root chain fleet,
				// distinct from the standing-fleet broken-link scenario above. The
				// inherited ROOT (synthChainRootRevoked) is KNOWN-dead and the
				// descendant (synthChainDescLiveRoot) is INDEPENDENTLY LIVE and holds
				// NO grant — so whole-chain liveness (HonestDecision step 2) DENYs
				// session_not_live BEFORE the grant leg is ever consulted, proving the
				// cascade is driven by the dead ROOT, not the descendant's own session
				// (doc 19 §7). Driven through the shared dual-run, this proves real ==
				// honest-generated fake on the revoked-root chain even on the dedicated
				// uuids — hardening against a fake that drifts the cascade only on
				// non-standing-fleet sessions.
				tok := MintChainedToken(synthChainDescLiveRoot, synthChainRootRevoked, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthChainDescLiveRoot),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/chained-dedicated-fleet-live-descendant-unrooted-falls-through-to-grant-leg",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// The control leg of the dedicated revoked-root chain: the SAME
				// descendant (synthChainDescLiveRoot) presented UN-rooted (a non-chained
				// token). With no inherited root the cascade cannot fire, so the
				// descendant clears step 2's OWN-session liveness (it is live) and falls
				// through to the grant leg — out_of_grant, since the dedicated descendant
				// holds no grant. This proves the cascade DENY above is driven by the
				// dead ROOT, not a dead own session; both ends must agree on the
				// non-cascade verdict too (doc 19 §7).
				tok := MintToken(synthChainDescLiveRoot, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthChainDescLiveRoot),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/unknown-session-fails-closed",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// An unknown session (never minted, or already swept) fails closed
				// the same way as a revoked one — session_not_live, never a default
				// ALLOW.
				tok := MintToken(synthSessionUnknown, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionUnknown),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/malformed-credential-rejected",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// A credential whose opaque bytes do not parse as a well-formed
				// session token fails the signature/shape leg — malformed_credential.
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: []byte("not-a-synthetic-token"),
					SessionRef:          sessionRef(synthSessionLive),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/wrong-session-binding-rejected",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// A well-formed token minted for the live session, but presented
				// against a DIFFERENT session_ref. Session A's credential is useless
				// against session B — the per-session binding fails the shape leg
				// (doc 16 §4). Here the token is bound to the live session but
				// presented under the revoked session's ref.
				tok := MintToken(synthSessionLive, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionRevoked),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/idempotent-re-presentation-same-verdict",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// Validation is side-effect-free: re-presenting the SAME credential
				// against the same session yields the SAME verdict/grant_ref/expiry
				// (no nonce burn; the swap path may re-validate per the latency
				// budget, doc 16 §4). The observation records that both calls agree.
				tok := MintToken(synthSessionLive, expiryFarFuture, synthServiceGitHub)
				req := &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionLive),
					ServiceId:           synthServiceGitHub,
				}
				first, err := cl.Validate(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				second, err := cl.Validate(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				obs := verdictObservation(second)
				obs.Setf("idempotent", "%t", verdictsEqual(first, second))
				return obs, nil
			},
		},
	}
}

// --- Observation builders ----------------------------------------------------

func errObservation(err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", status.Code(err).String())
	return obs
}

// verdictObservation records the contract-observable SHAPE of a Validate verdict
// (doc 16 §4): the ALLOW|DENY decision, the machine-readable reason (DENY only),
// whether a grant_ref was returned (ALLOW only — the raw ref value is recorded
// too, since it is a deterministic synthetic grant key both ends agree on), and
// the expiry horizon. This is the seam's observable: a faithful fake and a
// faithful validator must produce the identical verdict shape on every scenario.
func verdictObservation(resp *identityv1.ValidateResponse) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", codes.OK.String())
	obs.Set("verdict", resp.GetVerdict().String())
	obs.Set("reason", resp.GetMachineReadableReason())
	obs.Set("grant_ref", resp.GetGrantRef())
	obs.Setf("expiry_unix_seconds", "%d", resp.GetExpiryUnixSeconds())
	return obs
}

// verdictsEqual reports whether two Validate responses are contract-identical —
// the idempotency anchor (a re-presentation yields the SAME decision).
func verdictsEqual(a, b *identityv1.ValidateResponse) bool {
	return a.GetVerdict() == b.GetVerdict() &&
		a.GetMachineReadableReason() == b.GetMachineReadableReason() &&
		a.GetGrantRef() == b.GetGrantRef() &&
		a.GetExpiryUnixSeconds() == b.GetExpiryUnixSeconds()
}

// --- dialers: real reference impl AND the generated fake --------------------
//
// Both ends of the seam need a matched pair of dialers (one for the real impl,
// one for the fake) pre-seeded with the SAME standing fleet — the live session
// with its github+registry grant set and the revoked session — so the only thing
// that varies across the two dual-run passes is which server is registered.

// RealDialer returns the dual-run Dialer for the reference validator, pre-seeded
// with the live session (github+registry grants) and a revoked session (doc 16
// §5.4 liveness). The unknown session is deliberately NOT seeded.
func RealDialer() dualrun.Dialer {
	impl := NewRefImpl()
	seedFleet(impl)
	return dualrun.InProcess(impl.Register)
}

// RealDialerWithExpiredGrant returns the dual-run Dialer for the reference
// validator pre-seeded with the standing fleet (seedFleet, unchanged) PLUS the
// seedable past-TTL grant fleet: a distinct LIVE session whose github grant's
// OWN TTL is already in the past. The standing fleet is seeded first and is
// byte-identical to RealDialer()'s, so every existing scenario and the
// callers-table stay green; the extra session is on a dedicated uuid nothing
// else references, so this is a PARAMETERIZED addition, not a mutation of the
// default. It lets the PRODUCTION RefImpl.Validate caller carry an expired grant
// so the grant-TTL freshness leg (HonestDecision step 4) is pinned on the real
// caller — without touching refimpl.go. Synthetic fixtures only (D50).
func RealDialerWithExpiredGrant() dualrun.Dialer {
	impl := NewRefImpl()
	seedFleet(impl)
	seedExpiredGrantSession(impl)
	return dualrun.InProcess(impl.Register)
}

// RealDialerWithRevokedRootChain returns the dual-run Dialer for the reference
// validator pre-seeded with the DEDICATED revoked-root chain fleet ONLY (a KNOWN-
// dead inherited root plus an independently-live descendant re-rooted off it), on
// its own self-contained synthetic uuids nothing else references. It mirrors
// RealDialerWithExpiredGrant(): a fresh RefImpl seeded on a dedicated fleet so the
// PRODUCTION RefImpl.Validate caller can be driven down the dead-root CASCADE leg
// (HonestDecision step 2, whole-chain liveness) in ISOLATION — the cascade DENYs
// the live descendant on the dead root, and the SAME descendant presented un-rooted
// falls through to out_of_grant (own session live, no grant), proving the DENY is
// driven by the dead root and not a dead own session (doc 19 §7). This is the
// reusable suite affordance the dedicated revoked-root chain dialer was promoted
// into — the standing seedFleet is NOT layered in, so the fleet is exactly the two
// chain sessions and nothing else. Synthetic fixtures only (D50); refimpl.go
// untouched.
func RealDialerWithRevokedRootChain() dualrun.Dialer {
	impl := NewRefImpl()
	seedRevokedRootChainFleet(impl)
	return dualrun.InProcess(impl.Register)
}

// RevokedRootChainSuite is the FOCUSED dual-run suite scoped to the DEDICATED
// revoked-root chain fleet ALONE — exactly the two presentations
// RealDialerWithRevokedRootChain() seeds for (the dead-root cascade leg and its
// un-rooted control leg), and NOTHING that references the standing seedFleet. The
// standing Suite() validates the whole reason matrix and so can only be dual-run
// against dialers carrying the standing fleet; this narrower suite lets a caller
// dual-run the DEDICATED-fleet dialers (RealDialerWithRevokedRootChain() on the
// real end, a matched dedicated-fleet fake on the other) WITHOUT needing the
// standing sessions seeded. Its scenarios are byte-for-byte the same two
// presentations the standing Suite()'s chained-dedicated-fleet scenarios assert
// (the cascade DENYs session_not_live; the same descendant un-rooted falls through
// to out_of_grant), so it adds NO new contract surface — it only re-scopes the
// existing dedicated-fleet coverage to a fleet a dedicated-fleet fake can mirror.
//
// It is the seedable affordance (mirroring RealDialerWithRevokedRootChain()'s
// promotion) that lets the matched fake-only-isolation gate prove the revoked-root
// coverage is NON-VACUOUS: a fake honest everywhere EXCEPT it drops the dead-root
// cascade on THIS fleet diverges here, so the harness catches the drift. Additive
// and behavior-preserving: it adds a new exported affordance, weakens no existing
// scenario, and touches no production code. Synthetic fixtures only (D50).
func RevokedRootChainSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "ds-tlsproxy(swap-executor)<->identity(IdentityValidationService.Validate):revoked-root-chain",
		Scenarios: revokedRootChainScenarios(),
	}
}

// revokedRootChainScenarios is the two-scenario set RevokedRootChainSuite() runs,
// each expressed PURELY over the dedicated revoked-root chain fleet
// (synthChainRootRevoked + synthChainDescLiveRoot) so a dialer seeded with that
// fleet ALONE — RealDialerWithRevokedRootChain() and its matched fakes — satisfies
// every scenario. The two legs restate the dedicated-fleet coverage the standing
// Suite() already carries, so the focused suite cannot drift from the contract:
//
//   - cascade: a CHAINED token re-rooted to the independently-live descendant,
//     inheriting the KNOWN-dead root — whole-chain liveness (HonestDecision step 2)
//     DENYs session_not_live BEFORE the grant leg, even though the descendant's OWN
//     session is live (doc 19 §7);
//   - un-rooted control: the SAME descendant presented UN-rooted — with no inherited
//     root the cascade cannot fire, so own-session liveness clears and the
//     presentation falls through to out_of_grant (the dedicated descendant holds no
//     grant), proving the cascade DENY is driven by the dead ROOT, not a dead own
//     session.
//
// Synthetic fixtures only (D50).
func revokedRootChainScenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "validate/revoked-root-chain-isolated/revoked-root-cascades-on-live-descendant",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				tok := MintChainedToken(synthChainDescLiveRoot, synthChainRootRevoked, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthChainDescLiveRoot),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/revoked-root-chain-isolated/live-descendant-unrooted-falls-through-to-grant-leg",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				tok := MintToken(synthChainDescLiveRoot, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthChainDescLiveRoot),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
	}
}

// RealDialerWithExpiredGrantOnly returns the dual-run Dialer for the reference
// validator pre-seeded with the DEDICATED past-TTL grant fleet ALONE — the single
// LIVE session whose github grant's OWN TTL is already in the past
// (seedExpiredGrantSession), on its own self-contained synthetic uuid nothing else
// references, with NO standing fleet layered in. It is the grant-TTL-leg analogue of
// RealDialerWithRevokedRootChain(): where that promotes the dedicated revoked-root
// CHAIN fleet so the dead-root cascade can be pinned (and its non-vacuity gated) in
// ISOLATION, this promotes the dedicated past-TTL grant fleet so the grant-TTL
// freshness leg (HonestDecision step 4) can likewise be pinned and gated in isolation
// against a fleet a matched dedicated-fleet fake can mirror. RealDialerWithExpiredGrant()
// stays the standing-fleet-PLUS variant the callers/fold matrices consume; this is the
// dedicated-fleet-ONLY variant the focused ExpiredGrantSuite() drives. Synthetic
// fixtures only (D50); refimpl.go untouched.
func RealDialerWithExpiredGrantOnly() dualrun.Dialer {
	impl := NewRefImpl()
	seedExpiredGrantSession(impl)
	return dualrun.InProcess(impl.Register)
}

// ExpiredGrantSuite is the FOCUSED dual-run suite scoped to the DEDICATED past-TTL
// grant fleet ALONE — exactly the two presentations RealDialerWithExpiredGrantOnly()
// seeds for, and NOTHING that references the standing seedFleet. It is the grant-TTL
// analogue of RevokedRootChainSuite(): the standing Suite() validates the whole reason
// matrix and so can only be dual-run against dialers carrying the standing fleet, while
// this narrower suite lets a caller dual-run the DEDICATED-fleet dialers
// (RealDialerWithExpiredGrantOnly() on the real end, a matched dedicated-fleet fake on
// the other) WITHOUT needing the standing sessions seeded — the seedable affordance the
// matched fake-only-isolation gate needs to prove the grant-TTL coverage is NON-VACUOUS.
//
// Its two legs (mirroring RevokedRootChainSuite()'s cascade + un-rooted-control pair)
// are:
//
//   - grant-TTL DENY: a FRESH token over the LIVE expired-grant session for the github
//     service the session DOES hold — but the matched grant's OWN TTL is past, so the
//     grant-TTL freshness leg (HonestDecision step 4) DENYs credential_expired. This is
//     the leg a freshness-ignoring fake drifts on (it ALLOWs where RefImpl DENYs);
//   - away-from-drift control: the SAME session presented for a service it holds NO
//     grant for — the grant-intersection leg (HonestDecision step 5) DENYs out_of_grant
//     BEFORE any grant-TTL is consulted, so a freshness-only-drift fake never reaches
//     its drift here and AGREES with RefImpl (both DENY out_of_grant).
//
// The two legs restate coverage the standing reason matrix already carries (the
// expired-grant cell DENYs credential_expired; an out-of-grant presentation DENYs
// out_of_grant), so the focused suite adds NO new contract surface — it only re-scopes
// the existing grant-TTL coverage to a fleet a dedicated-fleet fake can mirror.
// Additive and behavior-preserving; touches no production decision code. Synthetic
// fixtures only (D50).
func ExpiredGrantSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "ds-tlsproxy(swap-executor)<->identity(IdentityValidationService.Validate):expired-grant",
		Scenarios: expiredGrantScenarios(),
	}
}

// expiredGrantScenarios is the two-scenario set ExpiredGrantSuite() runs, each
// expressed PURELY over the dedicated past-TTL grant fleet (synthSessionExpiredGrant)
// so a dialer seeded with that fleet ALONE — RealDialerWithExpiredGrantOnly() and its
// matched fakes — satisfies every scenario. The first leg is the grant-TTL DENY the
// freshness-drift fake diverges on; the second is the away-from-drift out_of_grant
// control the same fake must AGREE on (it never reaches the freshness leg for an
// ungranted service), exactly mirroring revokedRootChainScenarios()'s cascade +
// un-rooted-control structure. Synthetic fixtures only (D50).
func expiredGrantScenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "validate/expired-grant-isolated/fresh-token-past-ttl-grant-denies-credential-expired",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// A FRESH token (far-future) over the LIVE expired-grant session for the
				// github service it DOES hold — but that grant's OWN TTL is past, so the
				// grant-TTL freshness leg DENYs credential_expired. The freshness-drift
				// fake ALLOWs here; RefImpl DENYs — the gate must bite on this leg.
				tok := MintToken(synthSessionExpiredGrant, expiryFarFuture, synthServiceGitHub)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionExpiredGrant),
					ServiceId:           synthServiceGitHub,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
		{
			Name: "validate/expired-grant-isolated/ungranted-service-falls-through-to-out-of-grant",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewIdentityValidationServiceClient(conn)
				// The away-from-drift control: the SAME live expired-grant session
				// presented for a service it holds NO grant for. The grant-intersection
				// leg DENYs out_of_grant BEFORE any grant-TTL is consulted, so the
				// freshness-drift fake never reaches its drift and AGREES with RefImpl
				// (both DENY out_of_grant) — proving the gate above bites on the
				// grant-TTL leg and ONLY on the grant-TTL leg.
				tok := MintToken(synthSessionExpiredGrant, expiryFarFuture, synthServiceUngranted)
				resp, err := cl.Validate(ctx, &identityv1.ValidateRequest{
					PresentedCredential: tok,
					SessionRef:          sessionRef(synthSessionExpiredGrant),
					ServiceId:           synthServiceUngranted,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return verdictObservation(resp), nil
			},
		},
	}
}

// FakeDialer returns the dual-run Dialer for the GENERATED programmable fake,
// programmed to the same contract Suite() asserts. The fake is driven only
// through its canned-response surface — its Validate responder is routed at a
// mirror RefImpl seeded with the same fleet — so the dual-run proves it is
// observationally identical to the real impl on every scenario (doc 06 §2.1).
func FakeDialer() dualrun.Dialer {
	f, mirror := programmedFake()
	seedFleet(mirror)
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		identityv1fake.RegisterIdentityValidationService(s, f)
	})
}

// seedFleet installs the standing validate fleet on a reference impl: the live
// session with its two-service grant set and the revoked session (no grants,
// not live), plus the chain-liveness anchors and descendants. Shared by both
// dialers so real and fake start identical. It derives the fleet entirely from
// the SINGLE authoritative StandingFleetSeeds() table — the same list
// dualrun_test.go's honestStandingFleet() mirrors on the honest-responder side —
// so a future seeded session or grant is added in ONE place and both ends pick it
// up (the mirror is self-maintaining, no longer kept in step by convention).
func seedFleet(impl *RefImpl) {
	for _, s := range StandingFleetSeeds() {
		var grants map[string]grant
		if s.Grants != nil {
			grants = make(map[string]grant, len(s.Grants))
			for svc, g := range s.Grants {
				grants[svc] = grant{ref: g.Ref, expiryUnixSecond: g.ExpiryUnixSecond}
			}
		}
		impl.SeedSession(s.UUID, s.Live, grants)
	}

	// The dedicated revoked-root chain pair. These uuids are referenced by nothing
	// in the standing fleet (so they are deliberately NOT in StandingFleetSeeds()),
	// so seeding them here is additive — it lets the chained-dedicated-fleet cascade
	// scenarios run over the shared RealDialer() / FakeDialer() pair without
	// perturbing any existing fixture (doc 19 §7).
	seedRevokedRootChainFleet(impl)
}

// seedRevokedRootChainFleet installs the DEDICATED revoked-root chain fleet on a
// reference impl: a KNOWN-dead inherited ROOT (synthChainRootRevoked, live==false)
// plus an INDEPENDENTLY-LIVE descendant (synthChainDescLiveRoot, live==true) that
// re-roots off it. Both are seeded WITHOUT grants: the dead-root cascade
// (HonestDecision step 2, whole-chain liveness) DENYs session_not_live BEFORE the
// grant-intersection leg is consulted, so no descendant grant is needed to observe
// it; the un-rooted control presentation of the live descendant clears own-session
// liveness and falls through to out_of_grant. It lives on dedicated uuids nothing
// else references, so it is additive — it does NOT perturb the standing fleet.
// Shared by seedFleet (so the shared dual-run dialers carry it for the
// chained-dedicated-fleet scenarios) and by RealDialerWithRevokedRootChain (so the
// production RefImpl.Validate caller can be driven down the dead-root cascade leg in
// isolation). Synthetic fixtures only (D50).
func seedRevokedRootChainFleet(impl *RefImpl) {
	// The inherited root: KNOWN-dead (seeded, live==false), no grants — a pure
	// liveness anchor, like the standing chain roots.
	impl.SeedSession(synthChainRootRevoked, false, nil)
	// The descendant: independently LIVE (seeded, live==true), no grants. Its own
	// session passes own-session liveness; only the dead inherited root takes it
	// down via the cascade.
	impl.SeedSession(synthChainDescLiveRoot, true, nil)
}

// seedExpiredGrantSession installs the seedable past-TTL grant fleet on a
// reference impl: a single LIVE session (synthSessionExpiredGrant) whose github
// grant's OWN TTL is in the past (expiredGrants). It reuses the same
// SeedSession affordance seedFleet does and lives on a dedicated uuid, so it is
// additive — it does NOT perturb the standing fleet. Layered on top of seedFleet
// by RealDialerWithExpiredGrant so the production RefImpl.Validate caller can be
// driven down the grant-TTL freshness leg (HonestDecision step 4). Synthetic
// fixtures only (D50).
func seedExpiredGrantSession(impl *RefImpl) {
	impl.SeedSession(synthSessionExpiredGrant, true, expiredGrants())
}

// programmedFake programs the generated fake to the honest contract by routing
// its Validate responder at a mirror RefImpl — so the fake and the real impl
// share one honest behavior definition (grant-intersection, expiry, liveness).
// It returns both the fake (to register) and the mirror (so a dialer can
// pre-seed the standing fleet). This is the programmable-fake-driven-only-
// through-its-surface pattern (doc 06 §2.1): the dual-run still proves the fake
// observationally matches the production validator when it lands, because the
// suite never touches the mirror directly.
func programmedFake() (*identityv1fake.IdentityValidationServiceFake, *RefImpl) {
	f := identityv1fake.NewIdentityValidationServiceFake()
	mirror := NewRefImpl()
	f.ValidateResponder = mirror.Validate
	return f, mirror
}
