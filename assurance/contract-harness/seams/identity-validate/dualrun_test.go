// SPDX-License-Identifier: Apache-2.0

package identityvalidate_test

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	identityvalidate "github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/identity-validate"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
)

// Synthetic fixtures local to the test (D50) — obviously-synthetic, never a real
// session uuid, service id, token, or grant ref. Kept in lockstep with the
// suite's seeded fleet so the *Recorded() assertions exercise the same shapes.
const (
	testNow = int64(1_700_000_000)

	testSessionLive = "ses-synthetic-live-aaaa0000"

	testServiceGitHub   = "svc-synthetic-github"
	testServiceRegistry = "svc-synthetic-registry"

	testGrantRefGitHub     = "grantref-synthetic-github-d34db33f"
	testGrantRefDescGitHub = "grantref-synthetic-desc-github-c0ffee01"

	testExpiryFarFuture  = testNow + 3600
	testExpiryNearFuture = testNow + 600

	// Chained-token (doc 19 §7) descendant fixtures, in lockstep with the suite's
	// seeded chain fleet. Both descendants are independently LIVE so the
	// non-cascading drift gate proves the cascade is driven by the ROOT, not the
	// own-session: the descendant of the revoked root ALLOWs under a fake that
	// ignores root_session while the reference validator DENYs.
	testSessionDescLive          = "ses-synthetic-desc-live-1111aaaa"
	testSessionDescOfRevokedRoot = "ses-synthetic-desc-ofrevoked-2222bbbb"
	testSessionDescCrossHost     = "ses-synthetic-desc-crosshost-3333cccc"
	testSessionDescChildRevoked  = "ses-synthetic-desc-childrevoked-4444dddd"

	// Chain roots — liveness anchors only (no grants of their own). The cross-host
	// root is NOT recorded by the validating host (that is the cross-host leg).
	testRootLive      = "ses-synthetic-root-live-dddd3333"
	testRootRevoked   = "ses-synthetic-root-revoked-eeee4444"
	testRootCrossHost = "ses-synthetic-root-crosshost-ffff5555"

	// Standing fleet fixtures kept in lockstep with the suite's seedFleet (suite.go)
	// — the canonical RefImpl-side fleet the RealDialer() validator is pre-seeded
	// with, mirrored on the honest-responder side so the callers-table below drives
	// BOTH callers over one identical fleet. The revoked session is own-session-dead
	// with no grants (doc 16 §5.4 liveness); the registry grant_ref is the second
	// live-session grant the over-scope / intersection cells exclude.
	testSessionRevoked   = "ses-synthetic-revoked-bbbb1111"
	testSessionUnknown   = "ses-synthetic-unknown-cccc2222"
	testServiceUngranted = "svc-synthetic-ungranted"
	testGrantRefRegistry = "grantref-synthetic-registry-f00dcafe"

	// The seedable past-TTL grant fleet's session, in lockstep with suite.go's
	// synthSessionExpiredGrant: a LIVE session whose github grant's OWN TTL is in
	// the past. RealDialerWithExpiredGrant() pre-seeds the production RefImpl with
	// it, so the grant-TTL-expired cell below can be pinned on the REAL caller.
	testSessionExpiredGrant = "ses-synthetic-expiredgrant-eeee6666"

	// The grant_ref the past-TTL grant fleet's github grant carries, in lockstep
	// with suite.go's synthGrantRefExpiredGitHub — the DEDICATED expired-grant ref
	// the production RefImpl seeds (seedExpiredGrantSession). It is never returned
	// (the grant's own TTL fails freshness, so the expired-grant cell DENYs
	// credential_expired with no grant_ref), so this is a naming-only alignment with
	// no behavior change: it brings the honest-responder-side expiredGrantFleet()
	// mirror onto the same per-cell convention every other fleet uses (its own
	// dedicated ref constant — testGrantRefDescGitHub for the descendant fleet,
	// testGrantRefRegistry for registry), rather than reusing the generic
	// testGrantRefGitHub, so the test mirror names the SAME grant record the
	// production side does.
	testGrantRefExpiredGitHub = "grantref-synthetic-expired-github-deadc0de"

	// The grant-wins-the-min fleet, in lockstep with suite.go's synthSessionNearGrant
	// / synthGrantRefNearGitHub: a LIVE session whose github grant's OWN TTL is
	// NEAR-future (fresh, but tighter than a far-future token). A far-future token
	// over it ALLOWs with the GRANT's nearer horizon and the near-grant ref, closing
	// the symmetric intersection-horizon corner the token-wins leg leaves open. The
	// ref IS returned on ALLOW (the grant is fresh), unlike the expired-grant ref.
	testSessionNearGrant   = "ses-synthetic-neargrant-ffff7777"
	testGrantRefNearGitHub = "grantref-synthetic-near-github-beefcafe"

	// The DEDICATED revoked-root chain fleet, on its OWN synthetic uuids (nothing
	// else references them). It mirrors the seedable past-TTL grant fleet pattern
	// (testSessionExpiredGrant above) but for the dead-root CASCADE leg: a KNOWN-
	// dead inherited ROOT plus an INDEPENDENTLY-LIVE descendant re-rooted off it.
	// RealDialerWithRevokedRootChain() (the exported suite affordance, suite.go)
	// pre-seeds the PRODUCTION RefImpl with this
	// pair on top of nothing else, so the dead-root cascade (HonestDecision step 2,
	// whole-chain liveness) can be pinned on the REAL caller — the cascade DENYs the
	// live descendant on the dead root BEFORE the grant leg is ever consulted, so no
	// descendant grant is needed to observe it. Because these uuids are dedicated
	// (distinct from testRootRevoked / testSessionDescOfRevokedRoot, which are
	// coupled to the standing seedFleet), seeding them perturbs no standing fixture.
	testChainRootRevoked  = "ses-synthetic-chainroot-revoked-7777eeee"
	testChainDescLiveRoot = "ses-synthetic-chaindesc-liveroot-8888ffff"

	// Expiry horizons relative to testNow (== suite.synthNow), legible at the call
	// site: an expiry <= testNow is expired, one > testNow is fresh, and the tighter
	// of (grant TTL, token TTL) wins the ALLOW (doc 16 §5.1, doc 19 §8).
	testExpiryPast = testNow - 600
)

func testSessionRef(uuid string) *boundaryv1.SessionRef {
	return &boundaryv1.SessionRef{
		SessionUuid:      uuid,
		HostId:           "host-synthetic-validate-01",
		HostSessionIndex: 7,
		TapName:          "dstap-7",
	}
}

// TestSyntheticFixtureConstants_TestMirrorMatchesProduction is the cross-boundary
// constant guard: it pins every test* synthetic-fixture constant in THIS file equal to
// its synth* / expiry* twin in suite.go (the production package), across the
// production/_test boundary. The two constant sets are deliberate byte-for-byte mirrors —
// testNow == synthNow is the shared validation fence both ends compare expiries against,
// testSessionLive == synthSessionLive names the SAME seeded session, testGrantRefGitHub
// == synthGrantRefGitHub names the SAME grant record, and so on — but the _test package
// cannot reference the unexported synth* constants directly, so until now the two were
// kept equal ONLY by convention. A drift on either side (a renamed uuid, a retyped
// expiry offset, a fat-fingered grant ref) would silently split the fence the dual-run
// validates against: the RefImpl seeds one value while the honest-responder mirror seeds
// another, and a scenario could pass vacuously because both ends agree on the WRONG
// thing for a session no test actually exercises. This guard reads the authoritative
// production values through the exported SyntheticFixtureConstants() projection
// (suite.go) and asserts each test* twin matches, so any future desync fails CI here
// instead. Hermetic and additive: it stands up no fleet, no gRPC, no RefImpl — it only
// compares constants. Synthetic fixtures only (D50).
func TestSyntheticFixtureConstants_TestMirrorMatchesProduction(t *testing.T) {
	prod := identityvalidate.SyntheticFixtureConstants()

	// Each row pairs a test* constant (this file) with the KEY its synth* twin is
	// projected under in SyntheticFixtureConstants() (suite.go). The shared value is
	// asserted equal across the boundary so the two mirrors can no longer desync.
	stringPairs := map[string]string{
		"SessionLive":         testSessionLive,
		"SessionRevoked":      testSessionRevoked,
		"SessionUnknown":      testSessionUnknown,
		"SessionExpiredGrant": testSessionExpiredGrant,

		"RootLive":      testRootLive,
		"RootRevoked":   testRootRevoked,
		"RootCrossHost": testRootCrossHost,

		"SessionDescLive":          testSessionDescLive,
		"SessionDescOfRevokedRoot": testSessionDescOfRevokedRoot,
		"SessionDescCrossHost":     testSessionDescCrossHost,
		"SessionDescChildRevoked":  testSessionDescChildRevoked,

		"ChainRootRevoked":  testChainRootRevoked,
		"ChainDescLiveRoot": testChainDescLiveRoot,

		"ServiceGitHub":    testServiceGitHub,
		"ServiceRegistry":  testServiceRegistry,
		"ServiceUngranted": testServiceUngranted,

		"GrantRefGitHub":        testGrantRefGitHub,
		"GrantRefRegistry":      testGrantRefRegistry,
		"GrantRefDescGitHub":    testGrantRefDescGitHub,
		"GrantRefExpiredGitHub": testGrantRefExpiredGitHub,
	}
	int64Pairs := map[string]int64{
		"Now":              testNow,
		"ExpiryFarFuture":  testExpiryFarFuture,
		"ExpiryNearFuture": testExpiryNearFuture,
		"ExpiryPast":       testExpiryPast,
	}

	// The completeness count, per-key existence, per-key type, and per-key value-equality
	// checks are run by the reusable assertProjectionComplete helper (below), so this guard
	// declares only its two pair tables and the projection's name. SyntheticFixtureConstants
	// names the production accessor (suite.go) for self-locating diagnostics.
	assertProjectionComplete(t, "SyntheticFixtureConstants", prod, stringPairs, int64Pairs)
}

// assertProjectionComplete is the reusable cross-boundary projection guard, generalized
// out of the hand-inlined completeness-pin + per-type compare loops that
// TestSyntheticFixtureConstants_TestMirrorMatchesProduction used to carry. Given a
// production-side `map[string]any` projection (an exported accessor over unexported synth*
// constants, e.g. SyntheticFixtureConstants()) and the test*-side pair tables that mirror
// it (one for string values, one for int64 values, keyed by the SAME stable name the
// projection uses), it asserts the four properties a cross-boundary fixture mirror needs:
//
//  1. COMPLETENESS: the pair tables cover EXACTLY the projection's key set
//     (len(stringPairs)+len(int64Pairs) == len(prod)), so a production constant added
//     without a test* twin (or vice versa) fails loudly rather than slipping the guard;
//  2. EXISTENCE: every paired key is present in the projection;
//  3. TYPE: the projection's value has the type the pair table treats it as (a retyped
//     constant — string flipped to int64 or back — is caught, not silently coerced);
//  4. VALUE: the test* twin equals the production synth* value, so the two ends cannot seed
//     DIFFERENT values for the same fixture and split the fence the dual-run validates
//     against.
//
// projName names the production accessor for self-locating diagnostics. t is the narrow
// fatalReporter so the helper is exercisable both by the live test and by any future
// fatal-capturing meta-test. Test-only; synthetic/hermetic (D50): it only compares
// in-memory constants.
//
// SIBLING-SEAM SWEEP FINDING (folded from the projection-completeness consolidation,
// 01KV4JMT8N): the orchestrator-session and hypervisor seams (assurance/contract-harness/
// seams/) carry the SAME hand-inlined completeness-pin + per-type compare shape over their
// own exported fixture-constant projections. They are file-disjoint from this unit (the
// sibling streaming-seams unit owns them), so converging them onto THIS helper is left as a
// next-wave follow-up rather than reached across the file boundary here; this doc records
// the finding so that sweep has a named, reusable target.
func assertProjectionComplete(t fatalReporter, projName string, prod map[string]any, stringPairs map[string]string, int64Pairs map[string]int64) {
	t.Helper()

	// (1) COMPLETENESS: the two pair tables together must cover EXACTLY the projection's
	// key set, so a future constant added to the projection without a matching test* twin
	// (or removed while a twin lingers) fails here. (The reverse — a test* twin with no
	// projection key — is caught by the per-key EXISTENCE checks below.)
	if got, want := len(stringPairs)+len(int64Pairs), len(prod); got != want {
		t.Fatalf("cross-boundary constant guard covers %d pairs but %s() exports %d keys — a constant was added/removed without updating the test* mirror table; reconcile the two sets so every production fixture constant is pinned to its test twin", got, want, projName)
	}

	for key, testVal := range stringPairs {
		prodRaw, ok := prod[key]
		if !ok {
			t.Fatalf("%s() has no key %q — the test* mirror references a production constant the projection does not export (a desync between the two boundary sets)", projName, key)
		}
		prodVal, ok := prodRaw.(string)
		if !ok {
			t.Fatalf("%s()[%q] is %T, want string — the production projection retyped a fixture constant the test mirror treats as a string", projName, key, prodRaw)
		}
		if testVal != prodVal {
			t.Fatalf("cross-boundary constant DESYNC at %q: test* mirror = %q, production = %q — the two ends seed DIFFERENT values for the same fixture, splitting the fence the dual-run validates against", key, testVal, prodVal)
		}
	}

	for key, testVal := range int64Pairs {
		prodRaw, ok := prod[key]
		if !ok {
			t.Fatalf("%s() has no key %q — the test* mirror references a production constant the projection does not export (a desync between the two boundary sets)", projName, key)
		}
		prodVal, ok := prodRaw.(int64)
		if !ok {
			t.Fatalf("%s()[%q] is %T, want int64 — the production projection retyped a fixture constant the test mirror treats as an int64", projName, key, prodRaw)
		}
		if testVal != prodVal {
			t.Fatalf("cross-boundary constant DESYNC at %q: test* mirror = %d, production = %d — the two ends seed DIFFERENT values for the same fixture, splitting the fence the dual-run validates against", key, testVal, prodVal)
		}
	}
}

// TestSeam_RealVsGeneratedFake is the per-commit gate for the
// ds-tlsproxy(swap-executor) <-> identity IdentityValidationService.Validate
// seam (the D22 seam, doc 16 §4 / §9, doc 06 §2.1): the seam's conformance suite
// runs against BOTH the real reference validator AND the generated programmable
// fake, and the seam is green only if every scenario observes the same verdict
// on both. The suite exercises the Validate verb across grant-intersection
// narrowing, expiry rejection, over-scope refusal, session-liveness rejection,
// and idempotent re-presentation.
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := identityvalidate.Suite().Run(context.Background(), identityvalidate.RealDialer(), identityvalidate.FakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("identity Validate seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_HarnessCatchesADriftedFake is the negative proof: a fake that drifts
// from the contract (here, a Validate that ALLOWs an over-scoped request the
// grant-intersection must refuse — the doc 16 §5.1 / doc 19 §8 violation) must
// fail the seam. Without this, a green dual-run would be meaningless — it could
// be passing because the gate never fires. The drift is injected only in this
// test's local fake, never in the committed generated fake.
func TestSeam_HarnessCatchesADriftedFake(t *testing.T) {
	res, err := identityvalidate.Suite().Run(context.Background(), identityvalidate.RealDialer(), driftedAllowAllFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a drifted fake passed the seam — the dual-run gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or fake error, got report:\n%s", res.Report())
	}
}

// TestGrantIntersection_RecordedViaFakeAccessors asserts the grant-intersection,
// expiry, and over-scope contract DIRECTLY against the generated fake's
// Validate *Recorded() call-capture accessor (doc 16 §5.1, doc 19 §5/§8). This
// is the assertion the dual-run alone cannot make: the dual-run compares
// end-observable verdicts; the recorded-call surface is what lets a downstream
// consumer verify "the validator was asked exactly these presentations and
// answered honestly each time" — that the recorder sees every presentation while
// the contract decides each correctly.
func TestGrantIntersection_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()

	// Program the honest contract via the shared honestRecordingFake constructor: a single
	// live session granted github+registry far-future, with the Validate decision
	// intersecting the session grants against the presented token's attenuated scope and
	// taking the tighter expiry. honestRecordingFake wires the same recorder-backed honest
	// fake (the shared honestValidateResponder over the per-test fleet) the idempotency and
	// chained-liveness *Recorded() tests use; here only the github/registry grant fleet is
	// the per-test knob, so the assertions read against the *Recorded() surface without a
	// hand-restated responder that could drift.
	f := honestRecordingFake(map[string]honestSession{
		testSessionLive: {live: true, grants: map[string]honestGrant{
			testServiceGitHub:   {ref: testGrantRefGitHub, expiry: testExpiryFarFuture},
			testServiceRegistry: {ref: testGrantRefRegistry, expiry: testExpiryFarFuture},
		}},
	})

	// (a) in-grant + in-scope -> ALLOW with the granted ref and far-future expiry.
	allowReq := &identityv1.ValidateRequest{
		PresentedCredential: identityvalidate.MintToken(testSessionLive, testExpiryFarFuture, testServiceGitHub, testServiceRegistry),
		SessionRef:          testSessionRef(testSessionLive),
		ServiceId:           testServiceGitHub,
	}
	allow, err := f.Validate(ctx, allowReq)
	if err != nil {
		t.Fatalf("ALLOW Validate: %v", err)
	}
	if allow.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("in-grant in-scope: want ALLOW, got %s (%s)", allow.GetVerdict(), allow.GetMachineReadableReason())
	}
	if allow.GetGrantRef() != testGrantRefGitHub {
		t.Fatalf("ALLOW grant_ref = %q, want %q", allow.GetGrantRef(), testGrantRefGitHub)
	}
	if allow.GetExpiryUnixSeconds() != testExpiryFarFuture {
		t.Fatalf("ALLOW expiry = %d, want far-future %d", allow.GetExpiryUnixSeconds(), testExpiryFarFuture)
	}

	// (b) intersection narrows the expiry to the tighter token horizon.
	narrowReq := &identityv1.ValidateRequest{
		PresentedCredential: identityvalidate.MintToken(testSessionLive, testExpiryNearFuture, testServiceGitHub),
		SessionRef:          testSessionRef(testSessionLive),
		ServiceId:           testServiceGitHub,
	}
	narrow, err := f.Validate(ctx, narrowReq)
	if err != nil {
		t.Fatalf("narrow Validate: %v", err)
	}
	if narrow.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("narrow: want ALLOW, got %s", narrow.GetVerdict())
	}
	if narrow.GetExpiryUnixSeconds() != testExpiryNearFuture {
		t.Fatalf("intersection expiry = %d, want the TIGHTER token horizon %d", narrow.GetExpiryUnixSeconds(), testExpiryNearFuture)
	}

	// (c) over-scope: registry requested with a github-only token -> out_of_grant.
	overReq := &identityv1.ValidateRequest{
		PresentedCredential: identityvalidate.MintToken(testSessionLive, testExpiryFarFuture, testServiceGitHub),
		SessionRef:          testSessionRef(testSessionLive),
		ServiceId:           testServiceRegistry,
	}
	over, err := f.Validate(ctx, overReq)
	if err != nil {
		t.Fatalf("over-scope Validate: %v", err)
	}
	if over.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY || over.GetMachineReadableReason() != "out_of_grant" {
		t.Fatalf("over-scope: want DENY out_of_grant, got %s (%s)", over.GetVerdict(), over.GetMachineReadableReason())
	}
	if over.GetGrantRef() != "" {
		t.Fatalf("over-scope DENY must not carry a grant_ref, got %q", over.GetGrantRef())
	}

	// The recorder must have captured ALL THREE presentations, each carrying the
	// presented service_id and session_ref — the downstream-consumer audit
	// surface the dual-run cannot provide.
	calls := f.ValidateRecorded()
	if len(calls) != 3 {
		t.Fatalf("ValidateRecorded: want 3 captured calls, got %d", len(calls))
	}
	wantServices := []string{testServiceGitHub, testServiceGitHub, testServiceRegistry}
	for i, c := range calls {
		if got := c.Req.GetServiceId(); got != wantServices[i] {
			t.Fatalf("ValidateRecorded[%d].service_id = %q, want %q", i, got, wantServices[i])
		}
		if got := c.Req.GetSessionRef().GetSessionUuid(); got != testSessionLive {
			t.Fatalf("ValidateRecorded[%d].session_ref.session_uuid = %q, want %q", i, got, testSessionLive)
		}
		if len(c.Req.GetPresentedCredential()) == 0 {
			t.Fatalf("ValidateRecorded[%d] captured an empty presented_credential", i)
		}
	}
}

// TestGrantWinsTheMin_RecordedViaFakeAccessors is the SYMMETRIC companion to the
// token-wins narrowing case (b) in TestGrantIntersection_RecordedViaFakeAccessors:
// it pins the grant-wins-the-min corner DIRECTLY against the generated fake's
// Validate *Recorded() accessor. Existing coverage narrows the ALLOW expiry to the
// tighter TOKEN horizon (a near-future token over a far-future grant); this pins
// the mirror — a FAR-future token over a NEAR-future but fresh grant, where the
// intersection horizon is the tighter GRANT TTL. The ALLOW must carry the
// near-grant ref and the grant's near-future expiry (doc 16 §5.1, doc 19 §8),
// closing the last intersection-horizon corner. It programs the honest contract
// via the shared honestRecordingFake constructor over a per-test near-grant fleet,
// so the assertion reads against the *Recorded() surface without a hand-restated
// responder that could drift. Additive and test-only; synthetic fixtures only (D50).
func TestGrantWinsTheMin_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()

	// A single LIVE session whose github grant is FRESH but NEARER than a far-future
	// token — the grant-wins-the-min fleet (mirror of suite.go's synthSessionNearGrant).
	f := honestRecordingFake(map[string]honestSession{
		testSessionNearGrant: {live: true, grants: map[string]honestGrant{
			testServiceGitHub: {ref: testGrantRefNearGitHub, expiry: testExpiryNearFuture},
		}},
	})

	// A FAR-future token presented for the github service the near-grant session
	// holds: in-grant AND in-scope -> ALLOW, but the intersection narrows the expiry
	// to the tighter GRANT horizon (near-future), not the token's far future.
	grantWinsReq := &identityv1.ValidateRequest{
		PresentedCredential: identityvalidate.MintToken(testSessionNearGrant, testExpiryFarFuture, testServiceGitHub),
		SessionRef:          testSessionRef(testSessionNearGrant),
		ServiceId:           testServiceGitHub,
	}
	got, err := f.Validate(ctx, grantWinsReq)
	if err != nil {
		t.Fatalf("grant-wins Validate: %v", err)
	}
	if got.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("grant-wins: want ALLOW, got %s (%s)", got.GetVerdict(), got.GetMachineReadableReason())
	}
	if got.GetGrantRef() != testGrantRefNearGitHub {
		t.Fatalf("grant-wins ALLOW grant_ref = %q, want the near-grant ref %q", got.GetGrantRef(), testGrantRefNearGitHub)
	}
	if got.GetExpiryUnixSeconds() != testExpiryNearFuture {
		t.Fatalf("grant-wins intersection expiry = %d, want the TIGHTER grant horizon %d (the grant wins the min, not the far-future token)",
			got.GetExpiryUnixSeconds(), testExpiryNearFuture)
	}

	// The recorder must have captured the presentation, carrying the presented
	// service_id and session_ref — the downstream-consumer audit surface.
	calls := f.ValidateRecorded()
	if len(calls) != 1 {
		t.Fatalf("ValidateRecorded: want 1 captured call, got %d", len(calls))
	}
	if svc := calls[0].Req.GetServiceId(); svc != testServiceGitHub {
		t.Fatalf("ValidateRecorded[0].service_id = %q, want %q", svc, testServiceGitHub)
	}
	if uuid := calls[0].Req.GetSessionRef().GetSessionUuid(); uuid != testSessionNearGrant {
		t.Fatalf("ValidateRecorded[0].session_ref.session_uuid = %q, want %q", uuid, testSessionNearGrant)
	}
}

// TestIdempotency_RecordedViaFakeAccessors asserts the idempotency-on-re-
// presentation contract DIRECTLY against the generated fake's Validate
// *Recorded() call-capture accessor (doc 16 §4: the swap path may re-validate per
// the latency budget, side-effect-free). Two captured IDENTICAL re-presentations
// return the SAME verdict / grant_ref / expiry — AND the fake records BOTH calls,
// so the test proves the recorder sees every presentation while the contract
// collapses them to one decision. This mirrors the orchestrator-session
// TestIdempotency_RecordedViaFakeAccessors pattern and the
// TestGrantIntersection_RecordedViaFakeAccessors style above; it is the assertion
// the dual-run alone cannot make (the dual-run compares end-observable verdicts;
// the recorded-call surface is the downstream-consumer audit trail).
func TestIdempotency_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()

	// Program the honest contract via the shared honestRecordingFake constructor: github
	// granted far-future, intersected against the token's attenuated scope, tighter expiry
	// wins — the same recorder-backed honest fake (the shared honestValidateResponder over
	// the per-test fleet) the grant-intersection / chained-liveness *Recorded() tests use,
	// so all three share one source of honest behavior. The single live session + its
	// github grant is the per-test knob.
	f := honestRecordingFake(map[string]honestSession{
		testSessionLive: {live: true, grants: map[string]honestGrant{
			testServiceGitHub: {ref: testGrantRefGitHub, expiry: testExpiryFarFuture},
		}},
	})

	// Re-present the SAME credential against the same session twice.
	req := &identityv1.ValidateRequest{
		PresentedCredential: identityvalidate.MintToken(testSessionLive, testExpiryFarFuture, testServiceGitHub),
		SessionRef:          testSessionRef(testSessionLive),
		ServiceId:           testServiceGitHub,
	}
	first, err := f.Validate(ctx, req)
	if err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	second, err := f.Validate(ctx, req)
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}

	// Idempotent: identical re-presentations -> the SAME verdict / grant_ref /
	// expiry (no nonce burn at the seam).
	if first.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("first re-presentation: want ALLOW, got %s (%s)", first.GetVerdict(), first.GetMachineReadableReason())
	}
	if first.GetVerdict() != second.GetVerdict() ||
		first.GetGrantRef() != second.GetGrantRef() ||
		first.GetExpiryUnixSeconds() != second.GetExpiryUnixSeconds() {
		t.Fatalf("re-presentation not idempotent: %v vs %v", first, second)
	}
	if second.GetGrantRef() != testGrantRefGitHub {
		t.Fatalf("idempotent grant_ref = %q, want %q", second.GetGrantRef(), testGrantRefGitHub)
	}

	// The recorder must have captured BOTH presentations — same keys each time —
	// even though the contract collapsed them to one decision.
	calls := f.ValidateRecorded()
	if len(calls) != 2 {
		t.Fatalf("ValidateRecorded: want 2 captured calls, got %d", len(calls))
	}
	for i, c := range calls {
		if got := c.Req.GetServiceId(); got != testServiceGitHub {
			t.Fatalf("ValidateRecorded[%d].service_id = %q, want %q", i, got, testServiceGitHub)
		}
		if got := c.Req.GetSessionRef().GetSessionUuid(); got != testSessionLive {
			t.Fatalf("ValidateRecorded[%d].session_ref.session_uuid = %q, want %q", i, got, testSessionLive)
		}
		if len(c.Req.GetPresentedCredential()) == 0 {
			t.Fatalf("ValidateRecorded[%d] captured an empty presented_credential", i)
		}
	}
}

// TestChainedLiveness_RecordedViaFakeAccessors asserts ABSOLUTE verdicts for the
// four chained-token two-key liveness legs (doc 19 §7) DIRECTLY against the
// generated fake — an independent anchor the mirror-driven dual-run cannot
// provide. The dual-run proves real==fake, but because the suite's FakeDialer
// routes the fake at a mirror RefImpl, a contract change applied to BOTH ends
// (e.g. the cross-host root silently flipped to fail-closed) would keep the
// dual-run green; only a test that pins the EXPECTED verdict catches it. So this
// nails down, against an honest hand-programmed responder:
//
//   - good chain (live root, live descendant) -> ALLOW on the DESCENDANT's own
//     grant_ref (not the root's);
//   - broken-link (revoked root, live descendant) -> DENY session_not_live — the
//     cascade, with the contracted reason code;
//   - per-child revocation (live root, dead own session) -> DENY session_not_live,
//     scoped to the child;
//   - cross-host (unknown root, live descendant) -> ALLOW, governed by the
//     descendant's own liveness (an unknown root is NOT evidence of revocation).
//
// All four presentations must also be captured on the ValidateRecorded() surface.
// Synthetic fixtures only (D50).
func TestChainedLiveness_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()

	// Honest two-key chained contract via the shared honestRecordingFake constructor — the
	// same recorder-backed honest fake (the shared honestValidateResponder over the per-test
	// fleet) the grant-intersection / idempotency *Recorded() tests use, so the three copies
	// cannot drift. Own-session liveness keyed by session_uuid; whole-chain liveness
	// cascades when the host KNOWS the root is dead; an unknown root falls through to the
	// descendant's own liveness. The chain fleet (roots as liveness anchors, descendants
	// with their own grant) is the per-test knob; all grants are far-future, so the
	// intersected ALLOW expiry is the (far-future) token horizon, as the legs below assert.
	f := honestRecordingFake(map[string]honestSession{
		testRootLive:                 {live: true},
		testRootRevoked:              {live: false},
		testSessionDescLive:          {live: true, grants: map[string]honestGrant{testServiceGitHub: {ref: testGrantRefDescGitHub, expiry: testExpiryFarFuture}}},
		testSessionDescOfRevokedRoot: {live: true, grants: map[string]honestGrant{testServiceGitHub: {ref: testGrantRefDescGitHub, expiry: testExpiryFarFuture}}},
		testSessionDescCrossHost:     {live: true, grants: map[string]honestGrant{testServiceGitHub: {ref: testGrantRefDescGitHub, expiry: testExpiryFarFuture}}},
		testSessionDescChildRevoked:  {live: false, grants: map[string]honestGrant{testServiceGitHub: {ref: testGrantRefDescGitHub, expiry: testExpiryFarFuture}}},
		// testRootCrossHost deliberately absent — the validating host has no record.
	})

	type legWant struct {
		name      string
		ownUUID   string
		root      string
		wantAllow bool
		wantRef   string // ALLOW only
		wantDeny  string // DENY reason only
	}
	legs := []legWant{
		{"good-chain", testSessionDescLive, testRootLive, true, testGrantRefDescGitHub, ""},
		{"broken-link-revoked-root-cascade", testSessionDescOfRevokedRoot, testRootRevoked, false, "", "session_not_live"},
		{"per-child-revocation-scoped", testSessionDescChildRevoked, testRootLive, false, "", "session_not_live"},
		{"cross-host-unknown-root", testSessionDescCrossHost, testRootCrossHost, true, testGrantRefDescGitHub, ""},
	}
	for _, leg := range legs {
		resp, err := f.Validate(ctx, &identityv1.ValidateRequest{
			PresentedCredential: identityvalidate.MintChainedToken(leg.ownUUID, leg.root, testExpiryFarFuture, testServiceGitHub),
			SessionRef:          testSessionRef(leg.ownUUID),
			ServiceId:           testServiceGitHub,
		})
		if err != nil {
			t.Fatalf("%s Validate: %v", leg.name, err)
		}
		if leg.wantAllow {
			if resp.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
				t.Fatalf("%s: want ALLOW, got %s (%s)", leg.name, resp.GetVerdict(), resp.GetMachineReadableReason())
			}
			if resp.GetGrantRef() != leg.wantRef {
				t.Fatalf("%s: grant_ref = %q, want descendant ref %q", leg.name, resp.GetGrantRef(), leg.wantRef)
			}
		} else {
			if resp.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY || resp.GetMachineReadableReason() != leg.wantDeny {
				t.Fatalf("%s: want DENY %s, got %s (%s)", leg.name, leg.wantDeny, resp.GetVerdict(), resp.GetMachineReadableReason())
			}
			if resp.GetGrantRef() != "" {
				t.Fatalf("%s: DENY must not carry a grant_ref, got %q", leg.name, resp.GetGrantRef())
			}
		}
	}

	// All four chained presentations must be on the recorded surface, in order.
	calls := f.ValidateRecorded()
	if len(calls) != len(legs) {
		t.Fatalf("ValidateRecorded: want %d captured calls, got %d", len(legs), len(calls))
	}
	for i, c := range calls {
		if got := c.Req.GetSessionRef().GetSessionUuid(); got != legs[i].ownUUID {
			t.Fatalf("ValidateRecorded[%d].session_ref.session_uuid = %q, want %q", i, got, legs[i].ownUUID)
		}
		if len(c.Req.GetPresentedCredential()) == 0 {
			t.Fatalf("ValidateRecorded[%d] captured an empty presented_credential", i)
		}
	}
}

// TestChainedLiveness_HarnessCatchesANonCascadingFake is the negative drift-gate
// proof for the chained-token two-key liveness leg (doc 19 §7): a fake that does
// NOT cascade ROOT revocation — it keys liveness ONLY on the descendant's own
// session and ignores the inherited root_session — passes its own liveness but
// MUST fail the seam. The reference validator fails the broken-link chain closed
// (revoked root cascades), so the non-cascading fake ALLOWs where the real impl
// DENYs: the dual-run gate bites. Without this, the cascade contract could be
// silently dropped by a downstream fake. The drift lives only in this test's
// local fake, never in the committed generated fake.
func TestChainedLiveness_HarnessCatchesANonCascadingFake(t *testing.T) {
	res, err := identityvalidate.Suite().Run(context.Background(), identityvalidate.RealDialer(), nonCascadingFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a non-cascading (root-revocation-ignoring) fake passed the seam — the chained-liveness gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or fake error, got report:\n%s", res.Report())
	}
}

// honestStandingFleet is the honest-responder-side mirror of the suite's seedFleet
// (suite.go): the live session with its github+registry far-future grants, the
// own-session-revoked session (no grants), the chain roots (liveness anchors, no
// grants), and the descendants whose own session is live (github descendant grant,
// far-future) plus the per-child-revoked descendant (dead own session). The
// cross-host root and the unknown session are DELIBERATELY ABSENT — the validating
// host has no record of them — exactly as seedFleet leaves them unseeded. This is
// the fleet the honest-responder caller is driven over in the callers-table below,
// kept identical to the RefImpl-side RealDialer() fleet so the two callers of the
// shared HonestDecision core can be pinned to identical outputs.
//
// It is no longer a hand-maintained byte-for-byte twin: it PROJECTS the ONE
// authoritative identityvalidate.StandingFleetSeeds() table (the same list
// seedFleet installs on the RefImpl side) into the honestSession map this responder
// takes, so a future seeded session or grant added to that table updates BOTH ends
// at once — the mirror is self-maintaining and can no longer silently desync. The
// seed-side grant_ref/expiry values ARE the testGrantRef*/testExpiry* fixtures (the
// shared table reuses suite.go's liveGrants()/descGrants(), whose synthetic refs and
// far-future horizons equal these constants), so the projected fleet is byte-identical
// to the prior hand-written literal. Synthetic fixtures only (D50).
func honestStandingFleet() map[string]honestSession {
	seeds := identityvalidate.StandingFleetSeeds()
	fleet := make(map[string]honestSession, len(seeds))
	for _, s := range seeds {
		var grants map[string]honestGrant
		if s.Grants != nil {
			grants = make(map[string]honestGrant, len(s.Grants))
			for svc, g := range s.Grants {
				grants[svc] = honestGrant{ref: g.Ref, expiry: g.ExpiryUnixSecond}
			}
		}
		fleet[s.UUID] = honestSession{live: s.Live, grants: grants}
	}
	return fleet
}

// TestSeedFleetLiveness_DeadRootOverDeadDescendantFixturesStayDead is the defensive
// fixture-liveness guard for the dead-root-over-dead-descendant reason cell. That cell
// is a NON-drift cell for the non-cascading fake EXACTLY because BOTH of its fixtures
// are dead: the inherited root (testSessionRevoked) AND the descendant's own session
// (testSessionDescChildRevoked) are seeded live==false, so dropping the dead inherited
// root (nonCascading's one drift) still leaves a dead OWN session — the fake DENYs
// session_not_live and AGREES with RefImpl. Its presence in the NON-drift set is what
// tightens the fold-invariant's claim that nonCascading's drift is EXACTLY the
// inherited-root-key live-descendant-RESCUE path (a dead root over a LIVE descendant),
// not any dead-root presentation.
//
// That tightness is silently load-bearing on the two fixtures STAYING dead. If a future
// edit flipped EITHER to live==true — say testSessionDescChildRevoked were re-seeded
// live to reuse it elsewhere — the cell would morph: dropping the dead root would now
// rescue a LIVE descendant, so the non-cascading fake would ALLOW where RefImpl DENYs,
// turning a declared NON-drift cell into a drift cell. The fold-invariant matrix
// (TestNegativeDialers_FoldInvariant_MatchRefImplExceptOneCell) would then FAIL with a
// confusing "drifted on UNDRIFTED cell" message, far from the fixture flip that caused
// it. This guard pins the invariant at its source so a fixture flip fails HERE, loudly,
// naming the fixture — rather than surfacing as a downstream fold-invariant break.
//
// It is NON-VACUOUS in two independent ways: (1) it asserts the honest-fleet liveness
// lookup reports BOTH fixtures live==false / known==true (a flip to live==true fails the
// assertion directly); and (2) it drives the SAME dead-root-over-dead-descendant
// presentation the reason cell uses through BOTH the production RefImpl.Validate (over
// the standing seedFleet) AND the honest responder, asserting BOTH still DENY
// session_not_live — so even a flip that somehow slipped the liveness assertion would be
// caught by the end-observable verdict changing. Additive and test-only: it reuses the
// existing standing fleet, the honest responder, and the synthetic presentation builders;
// it modifies no production code and weakens no existing assertion. Synthetic fixtures
// only (D50).
func TestSeedFleetLiveness_DeadRootOverDeadDescendantFixturesStayDead(t *testing.T) {
	ctx := context.Background()

	// (1) Liveness-lookup assertion: the honest-fleet liveness lookup (the byte-for-byte
	// mirror of the production seedFleet, projected from StandingFleetSeeds()) MUST report
	// both fixtures dead-but-known. A future flip to live==true — or a fixture dropped from
	// the fleet entirely (known==false) — fails here, naming the fixture.
	live := fleetLiveness(honestStandingFleet())
	for _, f := range []struct {
		name string
		uuid string
	}{
		{"inherited-root", testSessionRevoked},
		{"own-descendant", testSessionDescChildRevoked},
	} {
		isLive, known := live(f.uuid)
		if !known {
			t.Fatalf("dead-root-over-dead-descendant fixture %s (%q) is NOT in the standing fleet (known==false) — the non-drift cell can no longer be expressed; re-seed it dead", f.name, f.uuid)
		}
		if isLive {
			t.Fatalf("dead-root-over-dead-descendant fixture %s (%q) flipped to live==true — the cell would morph from a NON-drift cell into a drift cell for the non-cascading fake (dropping the dead root would rescue a live descendant). Keep it live==false or move the dead-root cell's fixtures", f.name, f.uuid)
		}
	}

	// (2) End-observable verdict assertion: the SAME presentation the
	// dead-root-over-dead-descendant reason cell drives — a chained token re-rooted to
	// the dead own-session descendant, inheriting the dead root — MUST still DENY
	// session_not_live on BOTH callers of the shared core, so a fixture flip that somehow
	// slipped the liveness assertion above still fails here.
	req := &identityv1.ValidateRequest{
		PresentedCredential: identityvalidate.MintChainedToken(testSessionDescChildRevoked, testSessionRevoked, testExpiryFarFuture, testServiceGitHub),
		SessionRef:          testSessionRef(testSessionDescChildRevoked),
		ServiceId:           testServiceGitHub,
	}

	// Caller A: the production RefImpl.Validate over the standing seedFleet.
	conn, stop, err := identityvalidate.RealDialer().Dial(ctx)
	if err != nil {
		t.Fatalf("dial RealDialer: %v", err)
	}
	defer stop()
	gotA, err := identityv1.NewIdentityValidationServiceClient(conn).Validate(ctx, req)
	if err != nil {
		t.Fatalf("RefImpl.Validate: %v", err)
	}
	if gotA.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY || gotA.GetMachineReadableReason() != "session_not_live" {
		t.Fatalf("dead-root-over-dead-descendant on RefImpl: want DENY session_not_live, got %s (%s) — a fixture flip morphed the non-drift cell", gotA.GetVerdict(), gotA.GetMachineReadableReason())
	}

	// Caller B: the honest responder over the byte-for-byte mirror.
	gotB, err := honestValidateResponder(honestStandingFleet())(ctx, req)
	if err != nil {
		t.Fatalf("honestValidateResponder: %v", err)
	}
	if gotB.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY || gotB.GetMachineReadableReason() != "session_not_live" {
		t.Fatalf("dead-root-over-dead-descendant on honestValidateResponder: want DENY session_not_live, got %s (%s) — a fixture flip morphed the non-drift cell", gotB.GetVerdict(), gotB.GetMachineReadableReason())
	}
}

// TestHonestDecisionCallers_AgreeAcrossReasonMatrix pins the TWO callers of the
// shared honest decision core (refimpl.go HonestDecision) to BYTE-IDENTICAL
// verdict / grant_ref / expiry across the FULL reason matrix, driving both over
// ONE identical synthetic presentation per cell:
//
//   - caller A: the production RefImpl.Validate, reached over the in-process gRPC
//     seam via RealDialer() (pre-seeded with the suite's standing seedFleet);
//   - caller B: the test's honestValidateResponder, programmed with
//     honestStandingFleet() — the byte-for-byte mirror of that same seedFleet.
//
// orch61 folded RefImpl.Validate and honestValidateResponder onto the one shared
// HonestDecision core, and the dual-run proves real-vs-generated-fake equivalence
// end-to-end — but no DIRECT test pins the two HonestDecision CALLERS to identical
// outputs on every reason cell. The dual-run compares end-observable verdicts
// scenario-by-scenario; this table instead drives the SAME presentation through
// both callers and asserts they answer identically, so a future divergence in
// EITHER caller's wiring (e.g. a caller keying its GrantLookup closure on the
// wrong session uuid, or dropping the root_session from its LivenessLookup) fails
// THIS table even where a dual-run scenario happens to miss that exact cell.
//
// Additive and test-only: it reuses the existing same-package synthetic
// presentation builders (MintToken / MintChainedToken / testSessionRef) and the
// existing honestValidateResponder; it does NOT modify refimpl.go, weaken any
// existing assertion, or touch the drifted dialers. Synthetic fixtures only (D50).
func TestHonestDecisionCallers_AgreeAcrossReasonMatrix(t *testing.T) {
	ctx := context.Background()

	// Caller A: the production RefImpl.Validate behind the in-process gRPC seam,
	// pre-seeded with the standing seedFleet (suite.go). Driven through the real
	// client so the cells exercise the actual production decision path, not a
	// hand-restated copy of it.
	conn, stop, err := identityvalidate.RealDialer().Dial(ctx)
	if err != nil {
		t.Fatalf("dial RealDialer: %v", err)
	}
	defer stop()
	refClient := identityv1.NewIdentityValidationServiceClient(conn)

	// Caller B: the test's honestValidateResponder over the byte-for-byte mirror of
	// that same fleet — the other caller of the shared HonestDecision core.
	responder := honestValidateResponder(honestStandingFleet())

	const (
		allow = "ALLOW"
		deny  = "DENY"
	)

	// The cell SET — identifiers + the synthetic presentation each drives — is the
	// ONE canonical reasonMatrixCells() the negative-dialer fold matrix also
	// consumes; this matrix layers the contracted want* OUTCOME on each cell via
	// wantByName below (keyed by cell name), so the enumeration is declared once and
	// cannot drift between the two matrices. The want* fields document the contracted
	// outcome so the table is also a readable statement of the reason matrix (doc 16
	// §4/§5.1, doc 19 §7/§8); the per-cell assertions check BOTH callers against those
	// expectations AND against each other, so the table fails if either caller drifts
	// from the contract OR from its sibling caller. Most cells are expressible against
	// the standing seedFleet, so caller A (the real RefImpl) reaches them over the
	// shared refClient; the ONE cell carrying the optional pre-presentation
	// fleet-setup hook (expired-grant, whose grant-TTL leg the all-far-future standing
	// fleet cannot express) instead dials its own past-TTL grant dialer and runs
	// caller B over the matching fleet — so the real RefImpl participates in EVERY
	// cell, including expired-grant.
	type cellExpectation struct {
		wantVerN   string // "ALLOW" / "DENY"
		wantReason string // DENY only
		wantRef    string // ALLOW only
		wantExpiry int64  // ALLOW only
	}
	wantByName := map[string]cellExpectation{
		"malformed": {wantVerN: deny, wantReason: "malformed_credential"},
		// A token minted for the REVOKED session but presented against the LIVE
		// session: bound to A, presented against B -> malformed_credential (the
		// per-session-binding leg fires before any liveness/grant check).
		"binding-mismatch":  {wantVerN: deny, wantReason: "malformed_credential"},
		"dead-root-cascade": {wantVerN: deny, wantReason: "session_not_live"},
		// A SECOND dead-inherited-root / independently-live-descendant cell, with a
		// DISTINCT configuration from dead-root-cascade above, so the two-key
		// AND-liveness contract (a KNOWN-dead inherited root cascades to
		// session_not_live even while the descendant's OWN session is live —
		// doc 19 §7) is pinned by MORE THAN ONE fixture. A single isolating cell
		// could be slipped past by a regression that special-cased that cell's exact
		// identifiers (or narrowed the cascade drift to just the one declared root);
		// a second cell with different identifiers hardens the negative gate's bite.
		// Here the inherited root is testSessionRevoked — a different known-dead
		// session in the standing fleet (seedFleet seeds it live==false /
		// known==true), re-used as the chain origin — and the descendant is
		// testSessionDescLive, a DIFFERENT independently-live descendant (its own
		// session is live and holds the github descendant grant, so it ALLOWs on its
		// own when rooted live, as the good-chain leg proves). Because the root is
		// KNOWN-dead, the cascade (HonestDecision step 2) DENYs session_not_live
		// before own-session liveness is even consulted — proving the dead root, not
		// the descendant, drives the verdict. Both fixtures are already in the
		// standing seedFleet (and its honestStandingFleet() mirror), so caller A the
		// real RefImpl participates and the standing fleet is unchanged.
		"dead-root-cascade-distinct-revoked-root-over-live-desc": {wantVerN: deny, wantReason: "session_not_live"},
		// CASCADE-PRECEDENCE cell: a KNOWN-dead inherited root over a descendant whose
		// OWN session is ALSO dead. The two dead-root cells above each pair a dead root
		// with an independently-LIVE descendant (which is exactly what makes the dropped
		// cascade OBSERVABLE — dropping the dead root lets the live descendant ALLOW). This
		// cell pins the COMPLEMENT: when both root AND own-session are dead, the deny holds
		// REGARDLESS. HonestDecision step 2 checks the whole-chain root FIRST (refimpl.go
		// line ordering): the KNOWN-dead inherited root (testSessionRevoked) cascades to
		// session_not_live BEFORE the own-session liveness leg is consulted — so the verdict
		// is driven by the dead ROOT's precedence even though the descendant
		// (testSessionDescChildRevoked) is itself dead. Both callers DENY session_not_live
		// and must agree. Both fixtures are already in the standing seedFleet (and its
		// honestStandingFleet() mirror) — testSessionRevoked live==false/known==true,
		// testSessionDescChildRevoked live==false/known==true — so caller A the real RefImpl
		// participates and the standing fleet is unchanged.
		"dead-root-over-dead-descendant": {wantVerN: deny, wantReason: "session_not_live"},
		"cross-host-root":                {wantVerN: allow, wantRef: testGrantRefDescGitHub, wantExpiry: testExpiryFarFuture},
		"child-revoked":                  {wantVerN: deny, wantReason: "session_not_live"},
		"expired-token":                  {wantVerN: deny, wantReason: "credential_expired"},
		"out-of-grant":                   {wantVerN: deny, wantReason: "out_of_grant"},
		"in-scope-ALLOW":                 {wantVerN: allow, wantRef: testGrantRefGitHub, wantExpiry: testExpiryFarFuture},
		// github granted far-future, token narrower (near-future): the ALLOW expiry
		// is the TIGHTER token horizon (doc 16 §5.1, doc 19 §8).
		"tighter-token-expiry": {wantVerN: allow, wantRef: testGrantRefGitHub, wantExpiry: testExpiryNearFuture},
		// expired-GRANT — a FRESH token whose matched grant's OWN TTL is in the past
		// -> credential_expired (the GRANT-TTL freshness leg, HonestDecision step 4,
		// distinct from the token-TTL expired-token cell). The cell carries the
		// optional pre-presentation fleet-setup hook (cellSetup) that seeds its
		// dedicated past-TTL grant fleet on BOTH callers; the contracted outcome is the
		// same DENY-with-no-grant_ref/expiry shape as every other DENY cell.
		"expired-grant": {wantVerN: deny, wantReason: "credential_expired"},
	}

	cells := reasonMatrixCells()
	if len(wantByName) != len(cells) {
		t.Fatalf("wantByName carries %d expectations but the canonical reason matrix has %d cells — they must cover the same set", len(wantByName), len(cells))
	}

	// FOLD-COMPLETENESS guard: record the canonical cells this matrix actually
	// drives BOTH callers (A: RefImpl.Validate, B: honestValidateResponder) over,
	// and assert below it is the FULL canonical cell-NAME SET — not a bare count. The
	// wantByName/len check above proves every cell HAS an expectation, but a cell
	// silently skipped in the loop (an early continue, a dropped iteration) — or
	// exercised TWICE while another is skipped, which nets the same count — would let
	// the two callers go uncompared for it while the agreement assertion never fired.
	// The tracker records reach at the top of each cell's subtest (before any branch)
	// so the post-loop verify is exactly "both callers were driven over EXACTLY the
	// canonical cell set (no dup, no skip, no foreign)"; it also pins the
	// serial-execution invariant the shared refClient/responder rely on (a future
	// t.Parallel() inside a cell would race the shared fleet — verify catches it).
	canonical := reasonMatrixCellNames(t, cells)
	tracker := newFoldCompletenessTracker()
	cellsExercised := 0

	for _, c := range cells {
		want, ok := wantByName[c.name]
		if !ok {
			t.Fatalf("canonical cell %q has no want* expectation in wantByName — every shared cell must be covered", c.name)
		}
		t.Run(c.name, func(t *testing.T) {
			defer tracker.enter(c.name)()
			cellsExercised++

			req := &identityv1.ValidateRequest{
				PresentedCredential: c.cred,
				SessionRef:          testSessionRef(c.sessionUUID),
				ServiceId:           c.serviceID,
			}

			// Caller A — production RefImpl.Validate over the gRPC seam. A hookless
			// cell rides the shared standing-fleet client (refClient). A cell carrying
			// the optional pre-presentation fleet-setup hook (setup) instead dials its
			// own dialer — for expired-grant, RealDialerWithExpiredGrant(), which seeds
			// the past-TTL grant session — so the REAL caller goes down that cell's leg.
			callerA := refClient
			if c.setup != nil {
				hookConn, hookStop, err := c.setup.refDialer().Dial(ctx)
				if err != nil {
					t.Fatalf("dial setup refDialer for %q: %v", c.name, err)
				}
				defer hookStop()
				callerA = identityv1.NewIdentityValidationServiceClient(hookConn)
			}
			gotA, err := callerA.Validate(ctx, req)
			if err != nil {
				t.Fatalf("RefImpl.Validate: %v", err)
			}
			// Caller B — the test's honestValidateResponder. A hookless cell rides the
			// shared standing-fleet responder; a hooked cell runs over the byte-for-byte
			// mirror of its setup fleet (expiredGrantFleet() for expired-grant). A fresh
			// request value is not required (Validate is side-effect-free), but use the
			// same req so the two callers see byte-identical input.
			callerB := responder
			if c.setup != nil {
				callerB = honestValidateResponder(c.setup.fleet)
			}
			gotB, err := callerB(ctx, req)
			if err != nil {
				t.Fatalf("honestValidateResponder: %v", err)
			}

			// 1. each caller matches the contracted outcome for this cell.
			assertCellOutcome(t, "RefImpl.Validate", want.wantVerN, want.wantReason, want.wantRef, want.wantExpiry, gotA)
			assertCellOutcome(t, "honestValidateResponder", want.wantVerN, want.wantReason, want.wantRef, want.wantExpiry, gotB)

			// 2. and — the load-bearing assertion — the two callers of the shared
			// core agree byte-for-byte on verdict / reason / grant_ref / expiry. A
			// future divergence in either caller's closure wiring fails HERE.
			if gotA.GetVerdict() != gotB.GetVerdict() ||
				gotA.GetMachineReadableReason() != gotB.GetMachineReadableReason() ||
				gotA.GetGrantRef() != gotB.GetGrantRef() ||
				gotA.GetExpiryUnixSeconds() != gotB.GetExpiryUnixSeconds() {
				t.Fatalf("callers diverged on %q:\n  RefImpl.Validate          = {verdict:%s reason:%q grant_ref:%q expiry:%d}\n  honestValidateResponder   = {verdict:%s reason:%q grant_ref:%q expiry:%d}",
					c.name,
					gotA.GetVerdict(), gotA.GetMachineReadableReason(), gotA.GetGrantRef(), gotA.GetExpiryUnixSeconds(),
					gotB.GetVerdict(), gotB.GetMachineReadableReason(), gotB.GetGrantRef(), gotB.GetExpiryUnixSeconds())
			}

			// ASSERT-FIRED PIN: the agreement assertions (1 + 2) above have now run
			// for this cell, so record the assert-fired marker at the assert site.
			// verify requires this set to equal the canonical set, so a future cell
			// body that enters then short-circuits BEFORE reaching this point is
			// FLAGGED (reach without assert) rather than silently counted as covered.
			tracker.markAsserted(c.name)
		})
	}

	// FOLD-COMPLETENESS (name set + serial): the EXACT set of cell names both callers
	// were driven over must equal the canonical name set — no duplicate visit, no
	// skip, no foreign cell (vacuous to neither a swap nor a double) — AND the cells
	// settled synchronously (cellsExercised, captured at loop exit) so no cell was
	// t.Parallel()'d off the shared refClient/responder, with no concurrent overlap.
	// Run BEFORE the count anchor so its precise name-set/serial message is the one
	// that fires on a swap or a parallelized cell.
	tracker.verify(t, "callers-agreement", canonical, cellsExercised)

	// FOLD-COMPLETENESS (count anchor): both callers must have been driven over the
	// FULL canonical cell-set — exactly len(reasonMatrixCells()) cells, no silent
	// skip. The cell subtests run synchronously (no t.Parallel), so the counter is
	// settled here. A short count means a cell was dropped from the agreement fold
	// and its caller-vs-caller comparison never fired for it — a vacuous pass this
	// guard turns into a LOUD failure. Retained as a redundant anchor; the name-set
	// verify above SUBSUMES it (and additionally catches a double-visit + skip a bare
	// count cannot).
	if cellsExercised != len(cells) {
		t.Fatalf("callers-agreement fold-completeness: exercised %d cells but the canonical reason matrix has %d — a cell was silently skipped, so its caller-agreement check passed vacuously",
			cellsExercised, len(cells))
	}
}

// cellSetup is the OPTIONAL per-cell pre-presentation fleet-setup hook a reason
// cell may carry. The canonical cells drive BOTH callers over ONE shared standing
// fleet (caller A reaches RefImpl over RealDialer()'s seedFleet; caller B is an
// honestValidateResponder over honestStandingFleet(), its byte-for-byte mirror),
// and the negative-dialer fold drives RefImpl + each negative dialer over that
// same standing fleet — none of those cells needs a pre-presentation step. The
// ONE exception is the expired-GRANT cell: its grant-TTL-expired leg needs a LIVE
// session whose matched grant's OWN TTL is already in the past, which the standing
// (all-far-future) fleet cannot express. Rather than keep that cell a hand-written
// twin OUTSIDE the canonical matrix, a cell may supply this hook to SELECT, per
// cell, the dialer the RefImpl-side caller dials and the honest fleet the
// honest-responder-side caller (and the negative dialers) run over — seeding the
// dedicated past-TTL grant fleet ahead of presentation. A cell that leaves setup
// nil behaves EXACTLY as before: the matrices fall back to the shared standing
// dialer / responder / negative dialers, so every hookless cell is unchanged.
// Test-only type; synthetic fixtures only (D50).
type cellSetup struct {
	// refDialer is the dialer the RefImpl-side caller dials for this cell instead
	// of the shared RealDialer() — for expired-grant it is RealDialerWithExpiredGrant(),
	// which seeds the past-TTL grant session ON TOP of the standing fleet so the
	// production RefImpl.Validate caller goes down the grant-TTL leg. It also
	// becomes the honest BASELINE in the negative-dialer fold (the dialer every
	// negative dialer is measured against on this cell).
	refDialer func() dualrun.Dialer
	// fleet is the honest, fleet-backed session set the honest-responder-side
	// caller B runs over for this cell instead of honestStandingFleet(), and the
	// fleet each negative dialer is rebuilt over in the fold matrix — the
	// byte-for-byte mirror of what refDialer seeds.
	fleet map[string]honestSession
}

// reasonCell is ONE synthetic presentation in the canonical reason matrix: the
// cell's name plus the {credential, presenting session, requested service} tuple
// that drives it, plus an OPTIONAL pre-presentation fleet-setup hook (setup, nil
// for the standing-fleet cells). It carries NO want* expectation — that is layered
// ON TOP per caller (the honest agreement matrix maps name -> expected
// verdict/reason/ref/expiry; the negative-dialer fold matrix needs only the
// presentation, comparing each dialer against RefImpl). Test-only type.
type reasonCell struct {
	name        string
	cred        []byte
	sessionUUID string
	serviceID   string
	// setup is the optional per-cell pre-presentation fleet-setup hook (cellSetup);
	// nil for every cell that drives the shared standing fleet, set only on the
	// expired-grant cell to seed its dedicated past-TTL grant fleet.
	setup *cellSetup
}

// reasonMatrixCells is the SINGLE canonical declaration of the reason matrix —
// the ordered cell set (identifiers + the synthetic presentation each drives, plus
// an OPTIONAL per-cell pre-presentation fleet-setup hook). Most cells are
// expressible against the standing seedFleet so RefImpl participates in them over
// the shared standing dialer; the ONE exception is the expired-grant cell, which
// carries the optional cellSetup hook to seed its dedicated past-TTL grant fleet
// (the all-far-future standing fleet cannot express the grant-TTL leg) — so RefImpl
// participates in EVERY cell, that one over its own dialer. BOTH fold matrices
// consume this set: TestHonestDecisionCallers_Agree... pins the two HONEST callers
// to identical verdicts across these cells (layering its want* expectations over
// them), and TestNegativeDialers_FoldInvariant... drives each NEGATIVE dialer over
// the SAME cells, pinning the undrifted legs to RefImpl; both honor a cell's setup
// hook to run that cell over its dedicated fleet. Declaring the enumeration here
// once makes a cell present in one matrix but not the other impossible to express —
// the two cannot silently drift apart. Synthetic fixtures only (D50).
func reasonMatrixCells() []reasonCell {
	return []reasonCell{
		{name: "malformed", cred: []byte("not-a-synthetic-token|garbage"), sessionUUID: testSessionLive, serviceID: testServiceGitHub},
		// A token bound to the REVOKED session but presented against the LIVE session
		// -> malformed_credential (per-session binding fires first).
		{name: "binding-mismatch", cred: identityvalidate.MintToken(testSessionRevoked, testExpiryFarFuture, testServiceGitHub), sessionUUID: testSessionLive, serviceID: testServiceGitHub},
		{name: "dead-root-cascade", cred: identityvalidate.MintChainedToken(testSessionDescOfRevokedRoot, testRootRevoked, testExpiryFarFuture, testServiceGitHub), sessionUUID: testSessionDescOfRevokedRoot, serviceID: testServiceGitHub},
		// A SECOND dead-inherited-root / independently-live-descendant cell on a
		// DISTINCT configuration from dead-root-cascade above (mirroring the
		// callers-matrix cell orch66 added to TestHonestDecisionCallers_Agree...):
		// the inherited root is testSessionRevoked — a different known-dead session
		// in the standing seedFleet, re-used as the chain origin — and the descendant
		// is testSessionDescLive, a DIFFERENT independently-live descendant (its own
		// session is live and holds the github descendant grant). RefImpl DENYs
		// session_not_live here too (HonestDecision step 2 cascades the KNOWN-dead
		// root before own-session liveness is consulted), so this is a SECOND
		// dead-root cell the negative-dialer fold-invariant below pins. Both fixtures
		// are already in the standing seedFleet (and its honestStandingFleet() mirror),
		// so RefImpl participates and the standing fleet is unchanged. Having TWO
		// dead-root configs in the fold matrix proves the fold-invariant holds for both
		// and catches a regression that special-cased the first fixture's identifiers.
		{name: "dead-root-cascade-distinct-revoked-root-over-live-desc", cred: identityvalidate.MintChainedToken(testSessionDescLive, testSessionRevoked, testExpiryFarFuture, testServiceGitHub), sessionUUID: testSessionDescLive, serviceID: testServiceGitHub},
		// CASCADE-PRECEDENCE cell: a KNOWN-dead inherited root (testSessionRevoked) over a
		// descendant whose OWN session is ALSO dead (testSessionDescChildRevoked, live==false
		// in the standing seedFleet). The two dead-root cells above pair a dead root with an
		// independently-LIVE descendant — the configuration that makes nonCascading's dropped
		// cascade OBSERVABLE (dropping the dead root lets the live descendant ALLOW). This
		// cell is the COMPLEMENT and a NON-drift cell for nonCascading: RefImpl DENYs
		// session_not_live because HonestDecision step 2 cascades the KNOWN-dead root BEFORE
		// own-session liveness is consulted, and the non-cascading fake — which drops the
		// inherited root — still DENYs session_not_live because the descendant's OWN session
		// is dead too, so the fake AGREES with RefImpl here. It is therefore in nonCascading's
		// NON-drift set (NOT in its driftCells below), tightening the fold-invariant's claim
		// that nonCascading's drift is EXACTLY the inherited-root-key (live-descendant-rescue)
		// path — not any dead-root presentation. Both fixtures are already in the standing
		// seedFleet and its honestStandingFleet() mirror, so RefImpl participates and the
		// standing fleet is unchanged.
		{name: "dead-root-over-dead-descendant", cred: identityvalidate.MintChainedToken(testSessionDescChildRevoked, testSessionRevoked, testExpiryFarFuture, testServiceGitHub), sessionUUID: testSessionDescChildRevoked, serviceID: testServiceGitHub},
		{name: "cross-host-root", cred: identityvalidate.MintChainedToken(testSessionDescCrossHost, testRootCrossHost, testExpiryFarFuture, testServiceGitHub), sessionUUID: testSessionDescCrossHost, serviceID: testServiceGitHub},
		{name: "child-revoked", cred: identityvalidate.MintChainedToken(testSessionDescChildRevoked, testRootLive, testExpiryFarFuture, testServiceGitHub), sessionUUID: testSessionDescChildRevoked, serviceID: testServiceGitHub},
		{name: "expired-token", cred: identityvalidate.MintToken(testSessionLive, testExpiryPast, testServiceGitHub), sessionUUID: testSessionLive, serviceID: testServiceGitHub},
		{name: "out-of-grant", cred: identityvalidate.MintToken(testSessionLive, testExpiryFarFuture, testServiceGitHub, testServiceUngranted), sessionUUID: testSessionLive, serviceID: testServiceUngranted},
		{name: "in-scope-ALLOW", cred: identityvalidate.MintToken(testSessionLive, testExpiryFarFuture, testServiceGitHub, testServiceRegistry), sessionUUID: testSessionLive, serviceID: testServiceGitHub},
		{name: "tighter-token-expiry", cred: identityvalidate.MintToken(testSessionLive, testExpiryNearFuture, testServiceGitHub), sessionUUID: testSessionLive, serviceID: testServiceGitHub},
		// expired-GRANT — a FRESH token whose matched grant's OWN TTL is in the past
		// -> credential_expired — the GRANT-TTL freshness leg (HonestDecision step 4,
		// grantExpiry <= now), distinct from the token-TTL leg the expired-token cell
		// above exercises. It is the ONE canonical cell that carries the optional
		// pre-presentation fleet-setup hook (setup, above): the standing seedFleet is
		// all far-future, so the grant-TTL leg cannot be expressed against it. The hook
		// SELECTS, per cell, the past-TTL grant fleet for BOTH fold matrices — the
		// RefImpl-side caller dials RealDialerWithExpiredGrant() (which seeds a LIVE
		// session whose github grant's OWN TTL is past, ON TOP of the standing fleet,
		// on a dedicated uuid nothing else references), and the honest-responder-side
		// caller (plus each negative dialer in the fold) runs over expiredGrantFleet()
		// — the byte-for-byte mirror. The standing fleet is NOT mutated: the hook seeds
		// PER CELL, so every hookless cell still drives the unchanged standing fleet.
		// Folding it into the canonical set runs it through BOTH the callers-agreement
		// matrix and the negative-dialer fold-invariant matrix like every other cell.
		// Synthetic fixtures only (D50).
		{
			name:        "expired-grant",
			cred:        identityvalidate.MintToken(testSessionExpiredGrant, testExpiryFarFuture, testServiceGitHub),
			sessionUUID: testSessionExpiredGrant,
			serviceID:   testServiceGitHub,
			setup: &cellSetup{
				refDialer: identityvalidate.RealDialerWithExpiredGrant,
				fleet:     expiredGrantFleet(),
			},
		},
	}
}

// reasonMatrixCellNames is the canonical cell-NAME SET derived once from
// reasonMatrixCells() — the authoritative set of cell names BOTH fold matrices
// must drive their callers/dialers over, no duplicate, no skip, no foreign cell.
// It is the yardstick foldCompletenessTracker.verify measures the EXERCISED set
// against: a name-set equality (not a bare count) catches a fold that visits one
// cell TWICE and skips another for the same total — a swap a count check waves
// through. It also rejects a malformed canonical declaration (a duplicate name in
// reasonMatrixCells() itself), so the yardstick cannot silently be the wrong
// shape. Test-only helper; synthetic fixtures only (D50).
func reasonMatrixCellNames(t *testing.T, cells []reasonCell) map[string]struct{} {
	t.Helper()
	set := make(map[string]struct{}, len(cells))
	for _, c := range cells {
		if _, dup := set[c.name]; dup {
			t.Fatalf("reasonMatrixCells declares the cell name %q twice — the canonical reason matrix must be a SET (each name appears once)", c.name)
		}
		set[c.name] = struct{}{}
	}
	return set
}

// foldCompletenessTracker strengthens the per-fold completeness guard from a bare
// cell COUNT to a cell-NAME-SET equality AND pins the serial-execution invariant
// the fold matrices rely on.
//
//   - NAME SET: a count (cellsExercised == len(cells)) catches a DROPPED cell but
//     is vacuous to a SWAP — a fold that exercises one cell TWICE and skips another
//     nets the same total and slips past. enter(name) records the EXACT name
//     each cell subtest drives, and verify asserts the recorded set equals the
//     canonical reasonMatrixCellNames() set: a duplicate visit, a skip, or a
//     foreign name each fails LOUDLY.
//   - SERIAL EXECUTION: the count's (and the name set's) correctness silently
//     depends on the per-cell subtests running serially against the ONE shared
//     fleet/client. A future t.Parallel() inside a cell subtest would race the
//     shared fleet (a -race violation) — but it ALSO defeats the "settled after the
//     loop" assumption the post-loop assertion makes: Go PAUSES a t.Parallel()
//     subtest until its parent returns, so at verify() time (still inside the
//     parent) a parallelized cell has NOT YET RUN. This guard pins the invariant two
//     independent ways rather than leaving it a comment:
//     (1) verify is handed the count the parent captured SYNCHRONOUSLY at loop exit
//     (settledAtReturn) and asserts it already equals the full canonical size — if a
//     cell were t.Parallel()'d it would still be paused here, so the synchronous
//     count would be short and this fires LOUDLY (the primary, timing-robust pin);
//     (2) enter/exit also bracket each cell with an atomic in-flight counter whose
//     MAX overlap verify asserts never exceeded 1 — a belt-and-suspenders that
//     catches a hand-rolled goroutine fan-out (which, unlike t.Parallel(), is NOT
//     deferred past the parent). The counters are atomic so the detector is
//     -race-clean even when it is the thing catching the race.
//
// Test-only; reused by both fold matrices so the strengthened guard is declared
// once and cannot drift between them. Synthetic fixtures only (D50).
type foldCompletenessTracker struct {
	mu        sync.Mutex
	exercised map[string]int // cell name -> times REACHED (enter() at top; catches a double-visit)
	asserted  map[string]int // cell name -> times its agreement/invariant ASSERT FIRED (markAsserted() at the assert site)
	inFlight  int64          // cells currently inside their subtest body (atomic)
	maxInFly  int64          // high-water mark of concurrent cells (atomic)
}

func newFoldCompletenessTracker() *foldCompletenessTracker {
	return &foldCompletenessTracker{exercised: make(map[string]int), asserted: make(map[string]int)}
}

// enter is called at the TOP of each cell subtest, before any branch/early return,
// so it counts REACH not outcome. It records the cell name (so verify can compare
// the exercised SET against the canonical set) and bumps the in-flight overlap
// counter; the returned func must be deferred to release it.
func (ft *foldCompletenessTracker) enter(name string) (done func()) {
	ft.mu.Lock()
	ft.exercised[name]++
	ft.mu.Unlock()

	n := atomic.AddInt64(&ft.inFlight, 1)
	for {
		hi := atomic.LoadInt64(&ft.maxInFly)
		if n <= hi || atomic.CompareAndSwapInt64(&ft.maxInFly, hi, n) {
			break
		}
	}
	return func() { atomic.AddInt64(&ft.inFlight, -1) }
}

// markAsserted is called at the ASSERT SITE — right AFTER a cell's agreement /
// invariant assertion block has run (the point past which the verdict has been
// checked), on EVERY path the assertion is reachable by (including a path that
// returns early once it has asserted). It records that the cell's load-bearing
// assertion ACTUALLY FIRED, as distinct from enter()'s REACH (recorded at the top
// of the subtest, before any branch). verify then requires the asserted SET to
// equal the canonical set in ADDITION to the reach set: a cell whose body
// short-circuits AFTER enter() but BEFORE its assert records reach without
// recording an assert, so verify flags it instead of silently counting it as
// covered. Keying on the cell name (not a bare count) catches a cell asserted
// TWICE while another never asserts — the same swap the reach name-set guards
// against, now on the assert-fired axis.
func (ft *foldCompletenessTracker) markAsserted(name string) {
	ft.mu.Lock()
	ft.asserted[name]++
	ft.mu.Unlock()
}

// verify is called after the cell loop. settledAtReturn is the count the caller
// captured SYNCHRONOUSLY right after the loop (the parent's own cellsExercised),
// used to pin serial execution: under serial subtests it already equals
// len(canonical), but a t.Parallel()'d cell is paused until the parent returns so
// it would NOT have run yet here, leaving the synchronous count short. verify
// asserts (a) the EXACT set of REACHED cell names equals the canonical name set —
// no duplicate visit, no skip, no foreign cell; (a') the EXACT set of cell names
// whose agreement/invariant ASSERTION FIRED (markAsserted at the assert site) also
// equals the canonical set — so a cell whose body short-circuits AFTER enter() but
// BEFORE its assert is FLAGGED, not silently counted as covered by reach alone; and
// (b) the serial-execution invariant held (every cell settled before the parent
// returned AND no two cell subtests were ever in flight at once). label names the
// fold for a self-locating failure.
//
// t is typed as the narrow fatalReporter interface (the {Helper, Fatalf} subset of
// *testing.T that this method actually uses) rather than *testing.T concretely, so
// the in-tree negative meta-test below
// (TestFoldCompletenessTracker_AssertFiredGuardFlagsVisitedButUnasserted) can drive
// verify with a fatal-capturing recorder and prove the guard FLAGS a
// visited-but-unasserted cell WITHOUT failing the meta-test. The two production
// callers (TestHonestDecisionCallers_Agree... and TestNegativeDialers_FoldInvariant...)
// pass their *testing.T unchanged — it satisfies fatalReporter — so every existing
// assertion is byte-for-byte preserved; this is a behavior-preserving widening, not
// a weakening.
// nameSetMessages carries the three per-axis fatal-message builders the
// sorted-split-pass name-set walk needs, so the reach (a) and assert (a') axes can
// share ONE implementation (verifyNameSetSortedSplitPass) while keeping their
// distinct diagnostics byte-for-byte. Each builder returns the FULLY-FORMATTED fatal
// string (label and all directives already interpolated); the shared walk emits it
// verbatim via t.Fatalf("%s", msg), so the emitted bytes are identical to the
// pre-extraction inline blocks and the meta-tests' substring matches still hold.
//   - foreign: a sorted key not in the canonical set (FOREIGN pass), given the offending name.
//   - double:  a sorted key whose count != 1 (COUNT pass), given the name and its count.
//   - length:  the post-loop LENGTH mismatch, given have, want, and the sorted missing names.
type nameSetMessages struct {
	foreign func(name string) string
	double  func(name string, n int) string
	length  func(have, want int, missing []string) string
}

// verifyNameSetSortedSplitPass is the ONE shared sorted-split-pass name-set walk the
// reach (a) and assert (a') axes of verify both call, so the two axes share a single
// implementation and cannot silently desync. It reproduces the per-axis logic
// EXACTLY: collect counts' keys, sort.Strings them, run the FOREIGN-membership pass
// over every key FIRST, then the n != 1 COUNT pass — so a FOREIGN cell and a
// (distinct) DOUBLED cell present at once fire the foreign guard first,
// deterministically and independent of map-iteration order — then the POST-loop
// LENGTH check (missing names collected and sort.Strings'd before emission). Every
// fatal is the caller's own fully-formatted message emitted verbatim, so the emitted
// bytes match the pre-extraction inline blocks. A single call runs all three guards
// to completion, so calling it for reach and THEN for assert preserves the
// whole-reach-block-before-first-assert-guard boundary (A5). caller holds ft.mu.
// Test-only; synthetic fixtures only (D50).
func verifyNameSetSortedSplitPass(t fatalReporter, counts map[string]int, canonical map[string]struct{}, msgs nameSetMessages) {
	t.Helper()
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := canonical[name]; !ok {
			t.Fatalf("%s", msgs.foreign(name))
		}
	}
	for _, name := range names {
		if n := counts[name]; n != 1 {
			t.Fatalf("%s", msgs.double(name, n))
		}
	}
	if len(counts) != len(canonical) {
		missing := make([]string, 0)
		for name := range canonical {
			if _, ok := counts[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		t.Fatalf("%s", msgs.length(len(counts), len(canonical), missing))
	}
}

func (ft *foldCompletenessTracker) verify(t fatalReporter, label string, canonical map[string]struct{}, settledAtReturn int) {
	t.Helper()

	// (b.1) SERIAL EXECUTION — primary, timing-robust pin: every cell must have run
	// SYNCHRONOUSLY (settled before the parent returned). A t.Parallel() inside a
	// cell defers it past the parent, so the synchronously-captured count would be
	// short here even though the cell will eventually run.
	if settledAtReturn != len(canonical) {
		t.Fatalf("%s serial-execution invariant VIOLATED: only %d of %d cells had settled synchronously when the loop returned — a cell subtest deferred its body past the parent (a t.Parallel() against the shared fleet?), so the post-loop fold-completeness counters are not yet settled and the shared client is no longer single-threaded",
			label, settledAtReturn, len(canonical))
	}

	// (b.2) SERIAL EXECUTION — belt-and-suspenders: a hand-rolled goroutine fan-out
	// (not deferred past the parent like t.Parallel) would let cells overlap and race
	// the shared fleet; the high-water mark proves none did.
	if hi := atomic.LoadInt64(&ft.maxInFly); hi > 1 {
		t.Fatalf("%s serial-execution invariant VIOLATED: up to %d cell subtests ran concurrently — the per-cell loop must stay serial against the shared fleet (no t.Parallel, no goroutine fan-out), or the fold-completeness counters race and the shared client is no longer single-threaded",
			label, hi)
	}

	// (a) REACH NAME SET: dup / skip / foreign all fail here. The exercised keys are
	// walked in SORTED order (not Go's randomized map iteration) so the per-name guards
	// fire deterministically, and the two per-name checks are SPLIT into two sequential
	// sorted passes — FOREIGN-membership for every key FIRST, then the n != 1
	// double-visit check — so that when a FOREIGN cell and a (distinct) DOUBLED cell are
	// BOTH present, the foreign guard ALWAYS wins regardless of which name sorts first.
	// This pins foreign-before-double as a STANDING invariant; the single-violation
	// fatal messages are byte-identical to the pre-sort loop.
	ft.mu.Lock()
	defer ft.mu.Unlock()
	verifyNameSetSortedSplitPass(t, ft.exercised, canonical, nameSetMessages{
		foreign: func(name string) string {
			return fmt.Sprintf("%s fold-completeness: exercised FOREIGN cell %q not in the canonical reason matrix — the fold drifted off the canonical cell set", label, name)
		},
		double: func(name string, n int) string {
			return fmt.Sprintf("%s fold-completeness: cell %q was exercised %d times, want exactly once — a double-visit (which, paired with a skip, a bare count would wave through) breaks the name-set fold", label, name, n)
		},
		length: func(have, want int, missing []string) string {
			return fmt.Sprintf("%s fold-completeness: exercised %d distinct cells but the canonical reason matrix has %d — SKIPPED cells %v never had their per-cell fold assertion fire, a vacuous pass this name-set guard turns into a LOUD failure",
				label, have, want, missing)
		},
	})

	// (a') ASSERT-FIRED NAME SET: reach (above) proves each cell's subtest BODY was
	// entered; this proves each cell's agreement/invariant ASSERTION ACTUALLY RAN.
	// markAsserted is recorded at the assert site (after the verdict has been
	// checked), so a cell that enters then short-circuits BEFORE asserting — a body
	// that early-returns or skips past its agreement/invariant block — records reach
	// but NOT an assert, and is FLAGGED here instead of being silently counted as
	// covered by reach alone. A foreign assert, a double-assert (paired with a
	// never-asserted cell), or a never-asserted cell each fails LOUDLY — the
	// assert-fired analogue of the reach name-set guard above. This turns
	// reach-coverage into PROOF-OF-ASSERTION coverage.
	// Mirroring the reach axis: the asserted keys are walked in SORTED order and the
	// per-name guards are SPLIT into two sequential sorted passes — FOREIGN-membership
	// for every key FIRST, then the n != 1 double-assert check — so a foreign assert
	// and a (distinct) doubled assert present at once fire the foreign guard FIRST,
	// deterministically and independent of map-iteration order. Single-violation fatal
	// messages stay byte-identical to the pre-sort loop.
	verifyNameSetSortedSplitPass(t, ft.asserted, canonical, nameSetMessages{
		foreign: func(name string) string {
			return fmt.Sprintf("%s fold-completeness: asserted FOREIGN cell %q not in the canonical reason matrix — markAsserted fired for a cell off the canonical set", label, name)
		},
		double: func(name string, n int) string {
			return fmt.Sprintf("%s fold-completeness: cell %q recorded its assert-fired marker %d times, want exactly once — a double-assert (paired with a never-asserted cell) breaks the assert-fired fold", label, name, n)
		},
		length: func(have, want int, missing []string) string {
			return fmt.Sprintf("%s fold-completeness: %d of %d cells fired their agreement/invariant assertion — cells %v were REACHED but short-circuited BEFORE their assert (markAsserted never ran), so coverage was by NAME, not by assert-fired; this guard turns that vacuous pass into a LOUD failure",
				label, have, want, missing)
		},
	})
}

// fatalReporter is the narrow {Helper, Fatalf} subset of *testing.T that
// foldCompletenessTracker.verify uses. verify is typed against it (not *testing.T
// concretely) so the negative meta-test can drive verify with a fatal-CAPTURING
// recorder — observing that the guard fires WITHOUT failing the meta-test — while
// the two production callers keep passing their *testing.T (which satisfies this
// interface), so their assertions are unchanged. Test-only; the variadic uses any
// to match testing.T.Fatalf exactly.
type fatalReporter interface {
	Helper()
	Fatalf(format string, args ...any)
}

// fatalCapture is a fatalReporter that records the FIRST Fatalf as a fired guard
// and then unwinds via runtime.Goexit — exactly as *testing.T.Fatalf does — so the
// code under test (verify) stops at the fatal site just as it would under a real
// test. It is driven on its OWN goroutine (runVerifyExpectingFatal) so the Goexit
// unwinds only that goroutine; the parent meta-test goroutine observes the captured
// message and stays green when the guard fires as expected. Helper is a no-op (no
// line attribution needed for a capture). Test-only.
type fatalCapture struct {
	fired bool
	msg   string
}

func (c *fatalCapture) Helper() {}

func (c *fatalCapture) Fatalf(format string, args ...any) {
	c.fired = true
	c.msg = fmt.Sprintf(format, args...)
	runtime.Goexit() // unwind the capture goroutine, mirroring *testing.T.Fatalf
}

// runVerifyExpectingFatal drives foldCompletenessTracker.verify on a dedicated
// goroutine against a fatalCapture and returns the capture once that goroutine has
// settled. If verify's guard fires, Fatalf records the message and Goexit unwinds
// the goroutine (cap.fired stays true); if verify returns cleanly, the goroutine
// completes normally (cap.fired stays false). Either way the parent meta-test
// goroutine is untouched, so an EXPECTED fatal does not fail the meta-test.
// Test-only helper; synthetic fixtures only (D50).
func runVerifyExpectingFatal(ft *foldCompletenessTracker, label string, canonical map[string]struct{}, settledAtReturn int) *fatalCapture {
	fc := &fatalCapture{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ft.verify(fc, label, canonical, settledAtReturn)
	}()
	<-done
	return fc
}

// TestFoldCompletenessTracker_VerifyAxesRouteThroughOneSortedSplitHelper PINS the
// no-desync property that orch91 made STRUCTURAL but left guarded only by reviewer
// inspection: the reach (a) and assert (a') axes of foldCompletenessTracker.verify
// both route their per-axis name-set walk through the ONE shared
// verifyNameSetSortedSplitPass helper, so the sorted-split / foreign-before-double /
// length logic is declared ONCE and the two axes cannot silently diverge. The
// extraction makes that true today; nothing else makes it STAY true — a future edit
// could re-inline ONE axis's sorted-split (re-introducing a private sort.Strings + per-
// name Fatalf loop inside verify) and silently re-open the per-axis divergence with the
// gate still green, because every behavioral meta-test would still pass against the
// re-inlined-but-equivalent code.
//
// This meta-test closes that gap STRUCTURALLY, mirroring the resolverlock drift-corpus
// go/ast scanner pattern: it parses THIS _test.go (located via runtime.Caller, so the
// check is hermetic and working-directory-independent — no fold, gRPC, fleet, or live
// identity), locates foldCompletenessTracker.verify, and asserts:
//
//   - verify contains EXACTLY TWO calls to verifyNameSetSortedSplitPass — one per axis;
//   - the two calls feed DISTINCT first map arguments (ft.exercised for the reach axis,
//     ft.asserted for the assert axis), so each axis routes its OWN counts through the
//     shared walk rather than one axis being dropped or both reading the same map;
//   - verify itself re-inlines NO private sorted-split: it contains ZERO direct
//     sort.Strings calls (the sorted-split — sort.Strings then the FOREIGN pass then the
//     COUNT pass — lives ONLY in verifyNameSetSortedSplitPass; a re-inlined axis would
//     re-introduce a sort.Strings into verify's own body and trip this guard).
//
// A non-vacuity / liveness control proves the property is meaningful and not passing by
// accident: the shared helper verifyNameSetSortedSplitPass MUST itself contain the
// sorted-split (at least one sort.Strings call), so "verify has zero sort.Strings"
// genuinely means the sorted-split was HOISTED into the helper, not that the sorted-
// split vanished from the file entirely.
//
// Additive and test-only: it parses (never edits) the source, touches no production
// code (refimpl.go/suite.go untouched), weakens no existing fold-completeness meta-test
// or precedence-suite assertion, and adds no dependency beyond stdlib go/ast already
// used by sibling scanners. Synthetic/hermetic (D50): the only input is this file's own
// bytes.
func TestFoldCompletenessTracker_VerifyAxesRouteThroughOneSortedSplitHelper(t *testing.T) {
	const (
		sharedHelper = "verifyNameSetSortedSplitPass" // the ONE extracted sorted-split-pass walk
		verifyMethod = "verify"                       // foldCompletenessTracker.verify
		recvType     = "foldCompletenessTracker"      // verify's receiver (a value or pointer of)
		reachArg     = "exercised"                    // ft.exercised — the reach (a) axis map
		assertArg    = "asserted"                     // ft.asserted — the assert (a') axis map
	)

	// Run the ONE shared scanner: it self-locates this file, parses it, finds
	// foldCompletenessTracker.verify + the standalone shared helper, and returns the
	// per-axis call facts. The message pin and the source-order pin run the SAME scanner,
	// so the location/parse/lookup discipline is declared once.
	scan := findVerifyHelperCalls(t)
	if scan.helperDecl == nil {
		t.Fatalf("could not locate the shared %s helper — the extracted sorted-split-pass walk is gone; the reach and assert axes may have re-inlined their own", sharedHelper)
	}

	// (1) EXACTLY two call sites — one per axis — inside verify.
	axisFields := make([]string, 0, len(scan.calls))
	for _, c := range scan.calls {
		axisFields = append(axisFields, c.field)
	}
	if len(axisFields) != 2 {
		t.Fatalf("%s.%s contains %d call(s) to the shared %s helper, want EXACTLY 2 (one for the reach axis, one for the assert axis): a count != 2 means an axis was DROPPED, DUPLICATED, or RE-INLINED, re-opening the per-axis desync the extraction closed; mapped first-arg fields = %v",
			recvType, verifyMethod, len(axisFields), sharedHelper, axisFields)
	}

	// (2) The two calls feed DISTINCT per-axis maps: ft.exercised (reach) and
	// ft.asserted (assert). Identical fields would mean one axis reads the OTHER's
	// counts (a silent desync that behavioral tests on a single fixture could miss);
	// a missing field ("") means the first arg is no longer the recv-field selector the
	// pin expects (the routing was rewired).
	got := map[string]bool{}
	for _, f := range axisFields {
		if f == "" {
			t.Fatalf("a %s call inside %s.%s does not pass a `<recv>.FIELD` selector as its first map argument (mapped fields = %v) — the per-axis routing the structural pin checks was rewired; verify the reach/assert axes still pass ft.%s and ft.%s",
				sharedHelper, recvType, verifyMethod, axisFields, reachArg, assertArg)
		}
		got[f] = true
	}
	for _, want := range []string{reachArg, assertArg} {
		if !got[want] {
			t.Fatalf("the two %s calls inside %s.%s feed first-arg fields %v, but the %s axis (ft.%s) is MISSING — both axes must route their OWN per-axis map through the shared sorted-split-pass walk, or they have silently desynced",
				sharedHelper, recvType, verifyMethod, axisFields, want, want)
		}
	}

	verifyDecl, helperDecl := scan.verifyDecl, scan.helperDecl

	// (3) verify re-inlines NO private sorted-split. The sorted-split (sort.Strings,
	// then the FOREIGN pass, then the COUNT pass) lives ONLY in the shared helper; a
	// re-inlined axis would re-introduce a direct sort.Strings into verify's own body.
	// Count sort.Strings calls lexically inside verify — expect ZERO.
	countSortStrings := func(body *ast.BlockStmt) (n int) {
		ast.Inspect(body, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall {
				return true
			}
			sel, isSel := call.Fun.(*ast.SelectorExpr)
			if !isSel || sel.Sel.Name != "Strings" {
				return true
			}
			if pkg, isPkg := sel.X.(*ast.Ident); isPkg && pkg.Name == "sort" {
				n++
			}
			return true
		})
		return n
	}
	if n := countSortStrings(verifyDecl.Body); n != 0 {
		t.Fatalf("%s.%s contains %d direct sort.Strings call(s), want 0 — the sorted-split-pass walk must live ONLY in the shared %s helper, never re-inlined into an axis; a sort.Strings inside verify means a per-axis sorted-split was re-introduced, re-opening the desync the extraction closed",
			recvType, verifyMethod, n, sharedHelper)
	}

	// (4) NON-VACUITY / LIVENESS CONTROL: the shared helper MUST itself contain the
	// sorted-split (>= 1 sort.Strings call). Without this, "verify has zero
	// sort.Strings" could pass simply because the sorted-split was DELETED from the
	// file entirely (no axis sorts anymore) rather than HOISTED into the helper — the
	// property would be vacuously satisfied. Pinning the helper still holds the
	// sorted-split makes the zero-in-verify assertion meaningful.
	if n := countSortStrings(helperDecl.Body); n < 1 {
		t.Fatalf("the shared %s helper contains %d sort.Strings call(s), want >= 1 — the sorted-split must live IN the helper; if it has vanished from the helper too, the 'verify has zero sort.Strings' pin above is vacuous and the deterministic sorted FOREIGN-before-COUNT ordering is no longer enforced anywhere",
			sharedHelper, n)
	}
}

// TestFoldCompletenessTracker_VerifyAxisMessageClosuresStayDistinct EXTENDS the
// verify-axis structural pin above (VerifyAxesRouteThroughOneSortedSplitHelper) to
// close a gap it leaves open. That pin proves the reach (a) and assert (a') axes both
// route through the ONE shared verifyNameSetSortedSplitPass helper and feed DISTINCT
// FIRST map args (ft.exercised for reach, ft.asserted for assert). But the shared walk
// is PARAMETERIZED by per-axis fatal-message builders — the nameSetMessages composite
// literal each call passes as its FOURTH arg — and the routing pin never inspects that
// arg. So a future edit could pass the REACH axis's nameSetMessages closures to the
// ASSERT call (or vice versa) — both calls would STILL feed distinct first-arg maps,
// STILL pass the count==2 / distinctness / zero-sort.Strings checks — while silently
// emitting REACH-worded fatals ("exercised FOREIGN cell", "was exercised %d times") on
// an ASSERT-axis violation, or ASSERT-worded fatals ("asserted FOREIGN cell",
// "markAsserted fired") on a REACH-axis violation. Behavioral tests on a single fixture
// would NOT catch the swap: the count / distinctness / length logic is identical across
// axes; only the diagnostic WORDING differs, and the swapped wording is still a valid
// fatal string — so every existing meta-test would stay green with the diagnostics
// crossed.
//
// This sibling pin closes that gap STRUCTURALLY, mirroring the routing pin's go/ast
// approach: it parses THIS _test.go (located via runtime.Caller, so the check is
// hermetic and working-directory-independent — no fold, gRPC, fleet, or live identity),
// locates foldCompletenessTracker.verify, finds its TWO verifyNameSetSortedSplitPass
// call sites, and for EACH call extracts (i) the first-map-arg field name — the SAME
// `recv.FIELD` selector the routing pin keys on (ft.exercised => reach, ft.asserted =>
// assert) — and (ii) the set of string-literal contents of the FOURTH arg's
// nameSetMessages composite literal (walking the builder FuncLit bodies' BasicLit
// strings). It then asserts message-to-axis CORRESPONDENCE, coupled to that SAME
// routing field so a swap fails LOUDLY:
//
//   - the call whose first map arg is ft.exercised (the REACH axis) must build messages
//     mentioning the reach axis word "exercised" and must NOT mention the assert axis
//     words "asserted"/"markAsserted";
//   - the call whose first map arg is ft.asserted (the ASSERT axis) must build messages
//     mentioning an assert axis word ("asserted" and/or "markAsserted") and must NOT
//     mention the reach axis word "exercised".
//
// Tying the message-axis word to the first-arg field the routing pin already extracts
// makes the two pins COUPLED: if a future edit hands the assert call the reach axis's
// nameSetMessages (so ft.asserted's diagnostics now say "exercised"), THIS pin trips on
// the assert call mentioning the forbidden reach word AND missing its own assert word,
// even though the routing pin stays green.
//
// A NON-VACUITY / liveness control proves the discriminating substrings genuinely
// appear, so "the reach call mentions exercised" is not trivially satisfiable: across
// BOTH calls' message corpora, the reach axis word "exercised" and at least one assert
// axis word ("asserted"/"markAsserted") must each appear at least once — if BOTH axes
// dropped all discriminating wording (so every "must mention" check passed vacuously
// against empty corpora), this control fails loudly.
//
// Additive and test-only: it parses (never edits) the source, touches no production
// code (refimpl.go/suite.go untouched), weakens no existing fold-completeness meta-test,
// the precedence suite, or the routing pin, and adds no dependency beyond the stdlib
// go/ast already used by the routing pin and the sibling resolverlock scanners.
// Synthetic/hermetic (D50): the only input is this file's own bytes.
func TestFoldCompletenessTracker_VerifyAxisMessageClosuresStayDistinct(t *testing.T) {
	const (
		sharedHelper = "verifyNameSetSortedSplitPass" // the ONE extracted sorted-split-pass walk
		verifyMethod = "verify"                       // foldCompletenessTracker.verify
		recvType     = "foldCompletenessTracker"      // verify's receiver (a value or pointer of)
		reachArg     = "exercised"                    // ft.exercised — the reach (a) axis map
		assertArg    = "asserted"                     // ft.asserted — the assert (a') axis map
	)
	// Axis-discriminating message words. The reach (a) axis's fatal closures speak of a
	// cell being "exercised"; the assert (a') axis's speak of an assertion being
	// "asserted" / "markAsserted" firing. A correct per-axis message set mentions its OWN
	// axis word and NEVER the other axis's — so a swap (reach call given assert's
	// nameSetMessages, or vice versa) flips both the present and the forbidden word.
	const reachAxisWord = "exercised"
	assertAxisWords := []string{"asserted", "markAsserted"}

	// Run the ONE shared scanner — the SAME findVerifyHelperCalls the routing pin and the
	// source-order pin use — so the runtime.Caller/parse/verify-lookup/call-walk discipline
	// (including extracting each call's 4th-arg nameSetMessages string literals) is declared
	// once. The scanner returns one verifyHelperCall per site IN SOURCE ORDER, each carrying
	// the first-arg field and the per-axis message literals this pin reasons about.
	calls := findVerifyHelperCalls(t).calls

	// EXACTLY two call sites — one per axis — must be present (the routing pin pins this
	// too; re-asserting here keeps THIS pin self-standing if the routing pin is ever
	// renamed or moved). A count != 2 means the shape this pin reasons about is gone.
	if len(calls) != 2 {
		t.Fatalf("%s.%s contains %d call(s) to the shared %s helper, want EXACTLY 2 (one reach, one assert) for the message-correspondence pin to reason about per-axis message closures",
			recvType, verifyMethod, len(calls), sharedHelper)
	}

	// Index the two calls by their routing field; require ft.exercised (reach) and
	// ft.asserted (assert) — the SAME coupling the routing pin enforces — so message
	// correspondence is checked against the axis the helper actually walks.
	byField := map[string]verifyHelperCall{}
	for _, c := range calls {
		if c.field == "" {
			t.Fatalf("a %s call inside %s.%s does not pass a `<recv>.FIELD` selector as its first map argument — the per-axis routing was rewired, so the message-correspondence pin cannot bind a message closure to its axis",
				sharedHelper, recvType, verifyMethod)
		}
		if _, dup := byField[c.field]; dup {
			t.Fatalf("two %s calls inside %s.%s feed the SAME first-arg field ft.%s — the reach/assert axes have collapsed onto one map; per-axis message correspondence is undefined",
				sharedHelper, recvType, verifyMethod, c.field)
		}
		byField[c.field] = c
	}
	reachCall, hasReach := byField[reachArg]
	assertCall, hasAssert := byField[assertArg]
	if !hasReach {
		t.Fatalf("no %s call inside %s.%s routes the reach axis (ft.%s) — the message-correspondence pin cannot locate the reach-axis message closures",
			sharedHelper, recvType, verifyMethod, reachArg)
	}
	if !hasAssert {
		t.Fatalf("no %s call inside %s.%s routes the assert axis (ft.%s) — the message-correspondence pin cannot locate the assert-axis message closures",
			sharedHelper, recvType, verifyMethod, assertArg)
	}

	// mentions reports whether any message in corpus contains substr.
	mentions := func(corpus []string, substr string) bool {
		for _, m := range corpus {
			if strings.Contains(m, substr) {
				return true
			}
		}
		return false
	}
	mentionsAny := func(corpus []string, substrs []string) bool {
		for _, s := range substrs {
			if mentions(corpus, s) {
				return true
			}
		}
		return false
	}

	// CORRESPONDENCE — REACH axis (ft.exercised): its message closures must speak the
	// reach axis word and must NOT speak the assert axis words.
	if !mentions(reachCall.msgs, reachAxisWord) {
		t.Fatalf("the REACH-axis (ft.%s) %s call's nameSetMessages closures do not mention the reach axis word %q anywhere (collected message literals: %q) — the reach call may have been handed the ASSERT axis's nameSetMessages, so a reach-axis violation would now emit ASSERT-worded diagnostics",
			reachArg, sharedHelper, reachAxisWord, reachCall.msgs)
	}
	if w := firstMatch(reachCall.msgs, assertAxisWords); w != "" {
		t.Fatalf("the REACH-axis (ft.%s) %s call's nameSetMessages closures mention the ASSERT axis word %q (collected message literals: %q) — the reach axis is emitting assert-axis wording; the two axes' message closures have been swapped or collapsed",
			reachArg, sharedHelper, w, reachCall.msgs)
	}

	// CORRESPONDENCE — ASSERT axis (ft.asserted): its message closures must speak an
	// assert axis word and must NOT speak the reach axis word.
	if !mentionsAny(assertCall.msgs, assertAxisWords) {
		t.Fatalf("the ASSERT-axis (ft.%s) %s call's nameSetMessages closures do not mention any assert axis word %q anywhere (collected message literals: %q) — the assert call may have been handed the REACH axis's nameSetMessages, so an assert-axis violation would now emit REACH-worded diagnostics",
			assertArg, sharedHelper, assertAxisWords, assertCall.msgs)
	}
	if mentions(assertCall.msgs, reachAxisWord) {
		t.Fatalf("the ASSERT-axis (ft.%s) %s call's nameSetMessages closures mention the REACH axis word %q (collected message literals: %q) — the assert axis is emitting reach-axis wording; the two axes' message closures have been swapped or collapsed",
			assertArg, sharedHelper, reachAxisWord, assertCall.msgs)
	}

	// NON-VACUITY / LIVENESS CONTROL: across BOTH calls' corpora the reach axis word and
	// at least one assert axis word must each genuinely appear, so the "must mention"
	// checks above are not vacuously satisfiable against empty/whitespace corpora (e.g. if
	// a future edit dropped all discriminating wording from both axes). Without this, the
	// distinctness pin could pass simply because no axis word exists anywhere.
	allMsgs := append(append([]string{}, reachCall.msgs...), assertCall.msgs...)
	if !mentions(allMsgs, reachAxisWord) {
		t.Fatalf("non-vacuity control: the reach axis word %q does not appear in EITHER call's nameSetMessages closures (all collected message literals: %q) — the discriminating wording has vanished, so the per-axis message-correspondence checks are vacuous",
			reachAxisWord, allMsgs)
	}
	if !mentionsAny(allMsgs, assertAxisWords) {
		t.Fatalf("non-vacuity control: no assert axis word %q appears in EITHER call's nameSetMessages closures (all collected message literals: %q) — the discriminating wording has vanished, so the per-axis message-correspondence checks are vacuous",
			assertAxisWords, allMsgs)
	}
}

// TestFoldCompletenessTracker_VerifyReachAxisCallPrecedesAssertAxis is the THIRD
// verify-axis structural pin, closing the gap the routing and message-correspondence pins
// leave open: SOURCE ORDER. Those two prove the reach (ft.exercised) and assert
// (ft.asserted) axes each route their own per-axis map through the ONE shared
// verifyNameSetSortedSplitPass helper with the right per-axis diagnostics — but neither
// constrains WHICH axis runs FIRST. verifyNameSetSortedSplitPass runs all three of an
// axis's guards (FOREIGN, COUNT, LENGTH) to completion in a single call, so calling it for
// reach and THEN for assert is what preserves the whole-reach-block-before-first-assert-
// guard boundary the helper's doc calls out as A5: a presentation that is REACHED but
// short-circuits before asserting must trip the REACH guard (a vacuous-by-name pass) on
// its own terms before any assert-axis guard speaks. If a future edit SWAPPED the two
// calls — running the assert axis first — verify would emit an assert-fired LENGTH/FOREIGN
// fatal for the same skipped cell before the reach guard ever ran, inverting the
// diagnostic order the meta-tests (e.g. the precedence suite's reach-before-assert cases)
// rely on, while the routing and message pins both STAY GREEN (two distinct calls, correct
// per-axis maps, correct per-axis wording — only their lexical order changed).
//
// This pin closes that gap by comparing the two calls' source POSITIONS: it runs the SAME
// shared findVerifyHelperCalls scanner (so the location/parse/verify-lookup discipline and
// the per-call-site facts are identical to the other two pins, with each call's token.Pos()
// recorded), indexes the two calls by their routing field, and asserts the ft.exercised
// (reach) call's Pos() is STRICTLY BEFORE the ft.asserted (assert) call's Pos(). A
// non-vacuity control re-asserts the two positions are distinct and the scanner returns the
// two sites in ascending position order, so "reach before assert" cannot pass by both
// resolving to the same position. Additive and test-only: it parses (never edits) the
// source, touches no production code, and weakens no existing meta-test. Synthetic/hermetic
// (D50): the only input is this file's own bytes.
func TestFoldCompletenessTracker_VerifyReachAxisCallPrecedesAssertAxis(t *testing.T) {
	const (
		sharedHelper = "verifyNameSetSortedSplitPass" // the ONE extracted sorted-split-pass walk
		verifyMethod = "verify"                       // foldCompletenessTracker.verify
		recvType     = "foldCompletenessTracker"      // verify's receiver
		reachArg     = "exercised"                    // ft.exercised — the reach (a) axis map
		assertArg    = "asserted"                     // ft.asserted — the assert (a') axis map
	)

	// Run the ONE shared scanner — the SAME findVerifyHelperCalls the routing and message
	// pins use — so each call site's token.Pos() is recorded under the identical
	// location/parse/verify-lookup discipline.
	calls := findVerifyHelperCalls(t).calls

	// EXACTLY two call sites — one per axis (self-standing re-assert, as the sibling pins do).
	if len(calls) != 2 {
		t.Fatalf("%s.%s contains %d call(s) to the shared %s helper, want EXACTLY 2 (one reach, one assert) for the source-order pin to compare per-axis positions",
			recvType, verifyMethod, len(calls), sharedHelper)
	}

	// Index the two calls by their routing field so the order check is keyed on the SAME
	// axis coupling (ft.exercised => reach, ft.asserted => assert) the routing pin enforces,
	// not on raw slice order — a missing/duplicate field means the axes were rewired and the
	// order question is undefined.
	byField := map[string]verifyHelperCall{}
	for _, c := range calls {
		if c.field == "" {
			t.Fatalf("a %s call inside %s.%s does not pass a `<recv>.FIELD` selector as its first map argument — the per-axis routing was rewired, so the source-order pin cannot bind a call to its axis",
				sharedHelper, recvType, verifyMethod)
		}
		if _, dup := byField[c.field]; dup {
			t.Fatalf("two %s calls inside %s.%s feed the SAME first-arg field ft.%s — the reach/assert axes have collapsed onto one map; per-axis source order is undefined",
				sharedHelper, recvType, verifyMethod, c.field)
		}
		byField[c.field] = c
	}
	reachCall, hasReach := byField[reachArg]
	assertCall, hasAssert := byField[assertArg]
	if !hasReach {
		t.Fatalf("no %s call inside %s.%s routes the reach axis (ft.%s) — the source-order pin cannot locate the reach-axis call", sharedHelper, recvType, verifyMethod, reachArg)
	}
	if !hasAssert {
		t.Fatalf("no %s call inside %s.%s routes the assert axis (ft.%s) — the source-order pin cannot locate the assert-axis call", sharedHelper, recvType, verifyMethod, assertArg)
	}

	// NON-VACUITY CONTROL: the two positions must be distinct (and valid), so the strict
	// ordering below cannot be vacuously satisfied by both calls resolving to the same Pos.
	if !reachCall.pos.IsValid() || !assertCall.pos.IsValid() {
		t.Fatalf("non-vacuity control: a verify-axis call has an invalid source position (reach=%v, assert=%v) — the scanner could not position the calls, so the source-order pin cannot reason about which axis runs first",
			reachCall.pos, assertCall.pos)
	}
	if reachCall.pos == assertCall.pos {
		t.Fatalf("non-vacuity control: the reach (ft.%s) and assert (ft.%s) calls share the SAME source position %v — the two axes are not two distinct call sites, so 'reach before assert' is undefined",
			reachArg, assertArg, reachCall.pos)
	}

	// SOURCE ORDER: the reach axis call must lexically PRECEDE the assert axis call, so
	// verify runs the whole reach name-set block (all of reach's FOREIGN/COUNT/LENGTH
	// guards) BEFORE the first assert-axis guard — the A5 whole-reach-before-first-assert
	// boundary verifyNameSetSortedSplitPass's doc declares. A swap would invert the
	// diagnostic order the precedence meta-tests rely on while the routing/message pins stay
	// green.
	if reachCall.pos >= assertCall.pos {
		t.Fatalf("%s.%s calls the shared %s helper for the ASSERT axis (ft.%s, pos %v) at or before the REACH axis (ft.%s, pos %v) — the two calls were SWAPPED, so an assert-axis guard can now fire before the whole reach name-set block has run, inverting the reach-before-assert (A5) boundary the precedence meta-tests depend on; the routing and message pins do NOT catch a pure reorder",
			recvType, verifyMethod, sharedHelper, assertArg, assertCall.pos, reachArg, reachCall.pos)
	}
}

// firstMatch returns the first substr in substrs that appears in any message of corpus,
// or "" if none do. Used by the message-correspondence pin to name the offending word in
// a forbidden-mention diagnostic.
func firstMatch(corpus []string, substrs []string) string {
	for _, s := range substrs {
		for _, m := range corpus {
			if strings.Contains(m, s) {
				return s
			}
		}
	}
	return ""
}

// verifyHelperCall is ONE verifyNameSetSortedSplitPass call site inside
// foldCompletenessTracker.verify, projected into the three facts the three verify-axis
// structural pins reason about:
//
//   - field: the call's FIRST map argument when it is a `<recv>.FIELD` selector
//     (ft.exercised => "exercised" for the reach axis, ft.asserted => "asserted" for the
//     assert axis); "" for any other shape, so a future edit that stops routing a
//     per-axis map through the helper is caught rather than silently passing;
//   - msgs: every string-literal content reachable inside the call's FOURTH argument
//     when it is the nameSetMessages composite literal (the per-axis fatal builders'
//     wording), collected by walking the composite literal's FuncLit bodies;
//   - pos: the call's source position, so the reach-before-assert ordering pin can
//     compare the two axes' lexical order without re-walking verify itself.
//
// It is the shared currency findVerifyHelperCalls hands every verify-axis pin.
type verifyHelperCall struct {
	field string    // first-map-arg selector field ("" if not a recv.FIELD selector)
	msgs  []string  // unquoted string-literal contents of the 4th-arg composite literal
	pos   token.Pos // source position of the call expression (for source-order pins)
}

// verifyScan is the full result of one findVerifyHelperCalls run: the per-call-site
// facts every verify-axis pin reasons about, PLUS the parsed file and the located
// foldCompletenessTracker.verify and verifyNameSetSortedSplitPass FuncDecls, so the
// routing pin can run its sort.Strings re-inline check over verify's and the helper's
// bodies WITHOUT re-parsing the file or re-locating the decls (which would re-duplicate
// exactly the lookup this scanner exists to share). file is retained for completeness;
// the decls are what the structural sort.Strings passes walk.
type verifyScan struct {
	calls      []verifyHelperCall
	file       *ast.File
	verifyDecl *ast.FuncDecl
	helperDecl *ast.FuncDecl // nil if the standalone shared helper func is absent
}

// findVerifyHelperCalls is the ONE shared go/ast scanner the three verify-axis
// structural pins (VerifyAxesRouteThroughOneSortedSplitHelper,
// VerifyAxisMessageClosuresStayDistinct, VerifyReachAxisCallPrecedesAssertAxis) all run
// through, so the runtime.Caller(0) + parser.ParseFile + foldCompletenessTracker.verify
// lookup + verifyNameSetSortedSplitPass call walk lives in ONE place instead of being
// hand-inlined three times (each inline an opportunity to silently diverge in how it
// locates verify or extracts a call's facts). It locates THIS _test.go at runtime (so the
// scan is hermetic and working-directory-independent — no fold, gRPC, fleet, or live
// identity), finds foldCompletenessTracker.verify, and returns one verifyHelperCall per
// direct verifyNameSetSortedSplitPass call site IN SOURCE ORDER (ast.Inspect visits in
// lexical position order), each carrying the first-arg field, the 4th-arg message
// literals, and the call's source Pos(). The result also carries the parsed file and the
// located verify / standalone-helper FuncDecls so the routing pin can run its sort.Strings
// re-inline check without re-parsing or re-locating. Any structural failure (cannot
// self-locate, parse error, missing/ambiguous verify) is reported via t.Fatalf with the
// same wording the inlined lookups used, so a regression diagnoses the same way.
// Test-only; synthetic/hermetic (D50): the only input is this file's own bytes.
func findVerifyHelperCalls(t fatalReporter) verifyScan {
	t.Helper()
	const (
		sharedHelper = "verifyNameSetSortedSplitPass" // the ONE extracted sorted-split-pass walk
		verifyMethod = "verify"                       // foldCompletenessTracker.verify
		recvType     = "foldCompletenessTracker"      // verify's receiver (a value or pointer of)
	)

	// Locate THIS source file at runtime (absolute path, independent of the test's
	// working directory) so the scan is hermetic — it reads only this file's bytes.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) could not locate this test's source file — the verify-axis structural pins cannot run")
		return verifyScan{}
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, thisFile, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s for the verify-axis structural pins: %v", thisFile, err)
		return verifyScan{}
	}

	// Find foldCompletenessTracker.verify (verify is declared against
	// *foldCompletenessTracker; unwrap the star to match the receiver type name) AND the
	// standalone shared helper func (the routing pin's sort.Strings non-vacuity control
	// pins the sorted-split still lives in it).
	var verifyDecl, helperDecl *ast.FuncDecl
	for _, d := range file.Decls {
		fn, isFn := d.(*ast.FuncDecl)
		if !isFn {
			continue
		}
		if fn.Recv != nil {
			if fn.Name.Name != verifyMethod || len(fn.Recv.List) != 1 {
				continue
			}
			rt := fn.Recv.List[0].Type
			if star, isStar := rt.(*ast.StarExpr); isStar {
				rt = star.X
			}
			if id, isID := rt.(*ast.Ident); isID && id.Name == recvType {
				if verifyDecl != nil {
					t.Fatalf("found more than one %s.%s declaration — the verify-axis structural pins' verify lookup is ambiguous", recvType, verifyMethod)
					return verifyScan{}
				}
				verifyDecl = fn
			}
			continue
		}
		if fn.Name.Name == sharedHelper {
			if helperDecl != nil {
				t.Fatalf("found more than one %s declaration — the verify-axis structural pins' helper lookup is ambiguous", sharedHelper)
				return verifyScan{}
			}
			helperDecl = fn
		}
	}
	if verifyDecl == nil {
		t.Fatalf("could not locate %s.%s in %s — the reach/assert axes are no longer where the verify-axis structural pins expect them", recvType, verifyMethod, thisFile)
		return verifyScan{}
	}

	// For each direct verifyNameSetSortedSplitPass call site, project the three facts
	// every verify-axis pin needs. ast.Inspect visits nodes in source-position order, so
	// the returned slice is the call sites' lexical order (the reach call precedes the
	// assert call), which the ordering pin relies on alongside the recorded Pos().
	var calls []verifyHelperCall
	ast.Inspect(verifyDecl.Body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		id, isID := call.Fun.(*ast.Ident)
		if !isID || id.Name != sharedHelper {
			return true
		}
		c := verifyHelperCall{pos: call.Pos()}
		// (i) first map arg: verifyNameSetSortedSplitPass(t, recv.FIELD, canonical, msgs)
		if len(call.Args) >= 2 {
			if sel, isSel := call.Args[1].(*ast.SelectorExpr); isSel {
				c.field = sel.Sel.Name
			}
		}
		// (ii) fourth arg: the nameSetMessages composite literal; collect every string
		// literal under it (the per-axis builder closures' fatal wording).
		if len(call.Args) >= 4 {
			if lit, isLit := call.Args[3].(*ast.CompositeLit); isLit {
				ast.Inspect(lit, func(m ast.Node) bool {
					bl, isBL := m.(*ast.BasicLit)
					if !isBL || bl.Kind != token.STRING {
						return true
					}
					if s, uerr := strconv.Unquote(bl.Value); uerr == nil {
						c.msgs = append(c.msgs, s)
					}
					return true
				})
			}
		}
		calls = append(calls, c)
		return true
	})
	return verifyScan{calls: calls, file: file, verifyDecl: verifyDecl, helperDecl: helperDecl}
}

// --- single-deviation verify-guard meta-test scaffold ------------------------
//
// The six/seven single-deviation verify-guard meta-tests below
// (AssertFired{VisitedButUnasserted,DoubleAssert,ForeignAssert},
// Reach{DoubleVisit,SkippedCell}, Serial{ShortSynchronousSettle,ConcurrentOverlap})
// were six/seven near-identical 60-80-line bodies differing only in ONE deliberate
// deviation: each constructs a tracker state where exactly one guard can bite, runs
// verify expecting a fatal, pins WHICH branch fired by its diagnostic substring(s),
// and proves the bite is non-vacuous with a positive control. The shared control flow
// — canonical setup, deterministic lexicographic name sort, runVerifyExpectingFatal,
// the fired assertion, the substring branch-pins, the label pin, and the
// positive-control PASS check — is identical across all of them; only the per-test
// deviation, the settledAtReturn value, the exact diagnostic substrings, and the
// failure-message wording differ. This scaffold lifts that shared flow into ONE
// table-driven runner (runVerifyGuardMetaTest) so each meta-test states only its one
// deviation as data, preserving EVERY existing assertion and the EXACT fatal-substring
// matches byte-for-byte (the substrings and failure messages pass through as data, so
// a wording change still forces the owning test to be revisited). Behavior-preserving
// and test-only; synthetic fixtures only (D50).

// substrCheck is one branch-pin assertion lifted verbatim from a meta-test: the
// captured verify message must CONTAIN want, else the test fails with failf — a lazy
// formatter handed the captured message so the EXACT "... captured: %q" diagnostics
// (which interpolate the captured verify message, unknown until the run) reproduce
// byte-for-byte. The offending-cell name, known at build time, is closed over by the
// caller before this is constructed.
type substrCheck struct {
	want  string
	failf func(capturedMsg string) string
}

// verifyGuardMetaSpec is the per-test data the scaffold needs to reproduce ONE
// single-deviation verify-guard meta-test exactly. Everything that varied across the
// near-identical bodies is captured here; the shared control flow lives in
// runVerifyGuardMetaTest.
type verifyGuardMetaSpec struct {
	// minCells is the minimum canonical-cell count this meta-test needs to be
	// meaningful; minCellsFailf is the EXACT Fatalf message emitted when it is not met
	// (already formatted with len(canonical)).
	minCells      int
	minCellsFailf func(n int) string

	// label is the self-locating label passed to verify for the NEGATIVE run.
	label string

	// build constructs the deliberately-incomplete NEGATIVE tracker (its ONE deviation)
	// from the deterministic, lexicographically-sorted canonical names, and returns the
	// settledAtReturn to drive verify with plus the EXACT "did NOT fire" failure message
	// (interpolated with the deviation's cells) and the ordered branch-pin substring
	// checks. Some meta-tests (Serial) return early via a control flow the scaffold does
	// not model — those are NOT routed through this scaffold.
	build func(t *testing.T, names []string, canonical map[string]struct{}) (bad *foldCompletenessTracker, settledAtReturn int, notFiredFailf string, checks []substrCheck)

	// positiveControl builds the discriminating POSITIVE control: a tracker + its
	// settledAtReturn + the control label + the EXACT "false positive" failure message
	// (formatted lazily with the captured message via posFailf). It runs verify and MUST
	// NOT fire. When reuseBad is true the negative `bad` tracker is re-run with a
	// different settledAtReturn instead of building a fresh tracker (the Serial
	// short-settle pattern); buildGood is then ignored.
	posLabel  string
	reuseBad  bool
	posSettle func(canonical map[string]struct{}) int
	buildGood func(t *testing.T, names []string, canonical map[string]struct{}) *foldCompletenessTracker
	posFailf  func(capturedMsg string) string
}

// runVerifyGuardMetaTest is the shared table-driven runner the single-deviation
// verify-guard meta-tests delegate to. It reproduces the common control flow exactly:
// resolve the canonical reason matrix, enforce the meta-test's minimum-cell
// requirement, sort the names lexicographically for deterministic cell choice, build
// the NEGATIVE tracker via spec.build, run verify expecting a fatal, assert it fired
// with the spec's exact message, pin the fired branch via the spec's exact diagnostic
// substrings, pin the label, then run the POSITIVE control and assert it does NOT fire.
// Every assertion and every fatal-substring is the spec's own verbatim data, so no
// assertion is weakened and no emitted byte changes. Synthetic fixtures only (D50).
func runVerifyGuardMetaTest(t *testing.T, spec verifyGuardMetaSpec) {
	t.Helper()
	canonical := reasonMatrixCellNames(t, reasonMatrixCells())
	if len(canonical) < spec.minCells {
		t.Fatal(spec.minCellsFailf(len(canonical)))
	}

	// Deterministic cell choice (lexicographic) so every deviation is reproducible
	// regardless of map iteration order.
	names := make([]string, 0, len(canonical))
	for name := range canonical {
		names = append(names, name)
	}
	sort.Strings(names)

	// (1) NEGATIVE: build the one-deviation tracker, drive verify expecting a fatal.
	bad, settledAtReturn, notFiredFailf, checks := spec.build(t, names, canonical)
	got := runVerifyExpectingFatal(bad, spec.label, canonical, settledAtReturn)
	if !got.fired {
		t.Fatal(notFiredFailf)
	}
	// PIN THE BRANCH: every diagnostic substring the meta-test pins must be present in
	// the captured message, verbatim.
	for _, c := range checks {
		if !strings.Contains(got.msg, c.want) {
			t.Fatal(c.failf(got.msg))
		}
	}

	// (2) POSITIVE CONTROL: prove the bite is non-vacuous — the discriminating control
	// state must PASS verify.
	if spec.reuseBad {
		if pass := runVerifyExpectingFatal(bad, spec.posLabel, canonical, spec.posSettle(canonical)); pass.fired {
			t.Fatal(spec.posFailf(pass.msg))
		}
		return
	}
	good := spec.buildGood(t, names, canonical)
	if pass := runVerifyExpectingFatal(good, spec.posLabel, canonical, len(canonical)); pass.fired {
		t.Fatal(spec.posFailf(pass.msg))
	}
}

// TestFoldCompletenessTracker_AssertFiredGuardFlagsVisitedButUnasserted is the
// IN-TREE negative meta-test that PERMANENTLY pins the per-cell ASSERT-FIRED fold
// guard orch77 added to foldCompletenessTracker (the (a') name-set check in
// verify): a cell counts as covered ONLY if its agreement/invariant assertion
// ACTUALLY FIRED (markAsserted at the assert site), not merely because the cell's
// subtest body was REACHED (enter at the top). orch77 proved the guard bites only
// via a MANUAL reverted-scratch sabotage during review — nothing committed locks
// the behavior, so a future refactor that silently neutered markAsserted (e.g.
// dropped the markAsserted call, or collapsed asserted back into the reach map)
// would pass CI with the guard dead. This meta-test turns that one-time manual
// proof into a STANDING CI invariant.
//
// It drives the real foldCompletenessTracker DIRECTLY (it does NOT run the fold or
// the reason matrix, so it is hermetic — no gRPC, no fleet, no RefImpl): it
// constructs a deliberately-INCOMPLETE tracker state — every canonical cell
// enter()'d exactly once (reach complete, serial, in-flight never above 1) but ONE
// cell's markAsserted() deliberately NOT called (its assert "never ran") — and
// asserts verify FLAGS it. Because the state is otherwise complete, the ONLY guard
// in verify that can fire is the (a') assert-fired name-set check (the (b) serial
// pins pass: settledAtReturn == len(canonical) and maxInFly <= 1; the (a) reach
// name-set passes: every cell entered exactly once), so a fired guard is
// attributable to the assert-fired guard by construction. A POSITIVE control then
// proves the guard is not simply always-failing: the SAME fully-reached tracker
// with EVERY cell's markAsserted called PASSES verify.
//
// Additive and test-only: it reuses the existing foldCompletenessTracker and the
// canonical reasonMatrixCellNames(), modifies no production code (refimpl.go
// untouched), weakens no existing assertion, and adds no dependency. Synthetic
// fixtures only (D50).
func TestFoldCompletenessTracker_AssertFiredGuardFlagsVisitedButUnasserted(t *testing.T) {
	runVerifyGuardMetaTest(t, verifyGuardMetaSpec{
		minCells: 2,
		minCellsFailf: func(n int) string {
			return fmt.Sprintf("the canonical reason matrix has %d cells; this meta-test needs >= 2 (one held-back assert + at least one other) to be meaningful", n)
		},
		label: "assert-fired-negative",
		build: func(_ *testing.T, names []string, _ map[string]struct{}) (*foldCompletenessTracker, int, string, []substrCheck) {
			// Pick ONE cell to leave un-asserted — the cell whose assert "never ran". A
			// deterministic choice (lexicographically smallest name) keeps the meta-test
			// reproducible regardless of map iteration order.
			unassertedCell := names[0]

			// (1) NEGATIVE: build the deliberately-incomplete tracker — every cell REACHED
			// (enter at the top of its subtest, released so in-flight settles to 0, mirroring
			// the real fold's deferred done()), but the chosen cell's assert marker withheld
			// (its agreement/invariant block "short-circuited before asserting"). Every OTHER
			// guard in verify is satisfied, so only the assert-fired guard can flag this.
			bad := newFoldCompletenessTracker()
			for _, name := range names {
				done := bad.enter(name) // REACH recorded (catches a double-visit; here exactly once)
				done()                  // release in-flight, as the real fold's deferred done() does
				if name == unassertedCell {
					continue // DELIBERATE: this cell's assert NEVER fired — markAsserted withheld
				}
				bad.markAsserted(name)
			}

			// verify must FLAG the visited-but-unasserted cell. settledAtReturn ==
			// len(canonical) (every cell settled synchronously) and maxInFly <= 1 (no
			// overlap), so the serial pins (b.1)/(b.2) pass; the reach name-set is complete
			// (every cell entered exactly once), so (a) passes; the ONLY guard left to fire
			// is (a') assert-fired. Drive verify on a capture goroutine so its Fatalf does
			// not fail THIS meta-test.
			notFired := fmt.Sprintf("foldCompletenessTracker.verify did NOT flag a cell that was VISITED (enter) but whose assert NEVER FIRED (markAsserted withheld for %q) — the assert-fired fold guard is dead; a future refactor could neuter markAsserted and CI would stay green",
				unassertedCell)

			// PIN THE AXIS: the fired guard must be the (a') ASSERT-FIRED check, naming the
			// withheld cell — not the reach guard, the serial guard, or some unrelated path.
			// The (a') failure message is the only one that says "fired their agreement/
			// invariant assertion" AND names the missing cell; matching both substrings proves
			// the bite is precisely the assert-fired axis, so a future refactor that, say,
			// merged asserted into reach would make THIS substring assertion fail (the message
			// would change) even if some other guard still fired.
			checks := []substrCheck{
				{want: "fired their agreement/invariant assertion", failf: func(msg string) string {
					return fmt.Sprintf("verify fired, but NOT via the (a') assert-fired guard — the bite is not pinned to the assert-fired axis. captured: %q", msg)
				}},
				{want: unassertedCell, failf: func(msg string) string {
					return fmt.Sprintf("the assert-fired guard fired but did not name the withheld cell %q — the diagnostic does not locate the visited-but-unasserted cell. captured: %q", unassertedCell, msg)
				}},
				{want: "assert-fired-negative", failf: func(msg string) string {
					return fmt.Sprintf("the assert-fired guard fired but did not carry its label %q (self-locating failure broken). captured: %q", "assert-fired-negative", msg)
				}},
			}
			return bad, len(names), notFired, checks
		},
		posLabel: "assert-fired-positive-control",
		// (2) POSITIVE CONTROL: the SAME fully-reached tracker shape but with EVERY cell's
		// assert fired must PASS verify — proving the guard is DISCRIMINATING (it flags the
		// withheld assert in (1) because of the withholding, not because verify always
		// fails) and is not a false positive that would reject legitimately-complete
		// coverage. Because the ONLY difference from (1) is that markAsserted is now called
		// for unassertedCell too, a clean pass here isolates the (1) bite to exactly the
		// withheld assert.
		buildGood: func(_ *testing.T, names []string, _ map[string]struct{}) *foldCompletenessTracker {
			good := newFoldCompletenessTracker()
			for _, name := range names {
				done := good.enter(name)
				done()
				good.markAsserted(name) // EVERY cell asserts — a legitimately-complete fold
			}
			return good
		},
		posFailf: func(msg string) string {
			return fmt.Sprintf("foldCompletenessTracker.verify FLAGGED a legitimately-complete fold (every cell reached AND asserted) — the assert-fired guard is a false positive, rejecting honest coverage. captured: %q", msg)
		},
	})
}

// TestFoldCompletenessTracker_AssertFiredGuardFlagsDoubleAssert is the IN-TREE
// negative meta-test that PERMANENTLY pins the PER-NAME (n != 1) branch of the (a')
// assert-fired fold guard in foldCompletenessTracker.verify (the count-per-name
// check at ~the `if n != 1` site in the asserted loop). The sibling
// TestFoldCompletenessTracker_AssertFiredGuardFlagsVisitedButUnasserted pins the
// LENGTH-MISMATCH branch (a never-asserted cell shortens the asserted set); this
// one pins the adjacent DOUBLE-ASSERT branch, where the asserted set has the SAME
// LENGTH as the canonical set but is the wrong SET: one cell recorded its
// assert-fired marker TWICE while another never fired at all. A bare count
// (len(asserted) == len(canonical)) is vacuous to that swap — 2 + 0 nets the same
// total as 1 + 1 — so only the per-name keying catches it. This is the assert-fired
// analogue of the reach-axis double-VISIT guard (the `n != 1` check in the exercised
// loop) that the reach name-set already pins.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet,
// no RefImpl — hermetic): it constructs a tracker whose asserted map has one
// canonical cell at count 2 and another at count 0, with the reach set kept
// COMPLETE and the length guard deliberately SATISFIED (len(asserted) ==
// len(canonical)), so the ONLY guard in verify that can fire is the (a') per-name
// double-assert check. A POSITIVE control (every cell asserted exactly once) then
// proves the guard is discriminating, not always-failing.
//
// Additive and test-only: it reuses the existing foldCompletenessTracker, the
// canonical reasonMatrixCellNames(), and the orch78 fatal-capture harness
// (runVerifyExpectingFatal); modifies no production code (refimpl.go untouched);
// weakens no existing assertion; and adds no dependency. Synthetic fixtures only
// (D50).
func TestFoldCompletenessTracker_AssertFiredGuardFlagsDoubleAssert(t *testing.T) {
	runVerifyGuardMetaTest(t, verifyGuardMetaSpec{
		minCells: 2,
		minCellsFailf: func(n int) string {
			return fmt.Sprintf("the canonical reason matrix has %d cells; this meta-test needs >= 2 (one double-asserted cell + one never-asserted cell) to be meaningful", n)
		},
		label: "assert-fired-double",
		build: func(_ *testing.T, names []string, _ map[string]struct{}) (*foldCompletenessTracker, int, string, []substrCheck) {
			// Deterministic cell choice (lexicographic) so the swap is reproducible
			// regardless of map iteration order: the smallest name is asserted TWICE, the
			// next-smallest never asserts. The 2 + 0 over two cells is a per-name SWAP that a
			// bare total count (2 + 0 == 1 + 1) cannot see; only the per-name n != 1 keying
			// catches it. verify evaluates the per-name asserted loop (the foreign + n != 1
			// checks) BEFORE the length check and stops at the first Fatalf (Goexit), so the
			// per-name double-assert branch is what bites on doubleAssertedCell — the
			// substring pin below confirms that branch fired, not the length branch (which,
			// because the never-asserted cell is simply absent from the asserted map, would
			// also be unequal and is not what we are pinning here).
			doubleAssertedCell := names[0] // asserted TWICE
			unassertedCell := names[1]     // never asserts (its count stays 0)

			// (1) NEGATIVE: every cell REACHED exactly once (reach set complete, serial,
			// in-flight settles to 0 via the deferred done() the real fold uses); then assert
			// markers laid down as a per-name SWAP — doubleAssertedCell fired TWICE,
			// unassertedCell never fired, all others fired once. A bare total assert count
			// (2 + 0 == 1 + 1) is vacuous to this swap; only the (a') per-name n != 1 keying
			// catches it. Because verify walks the per-name asserted loop before the length
			// check and Goexits on the first Fatalf, the per-name double-assert branch is the
			// one that bites on doubleAssertedCell.
			bad := newFoldCompletenessTracker()
			for _, name := range names {
				done := bad.enter(name) // REACH recorded exactly once (reach set stays complete)
				done()                  // release in-flight, as the real fold's deferred done() does
				switch name {
				case doubleAssertedCell:
					bad.markAsserted(name)
					bad.markAsserted(name) // DELIBERATE: assert-fired marker recorded TWICE (count 2)
				case unassertedCell:
					// DELIBERATE: this cell's assert NEVER fires (it stays absent from the
					// asserted map) — the counterweight half of the 2 + 0 per-name swap that a
					// bare total count cannot distinguish from 1 + 1.
				default:
					bad.markAsserted(name) // every other cell asserts exactly once
				}
			}

			// verify must FLAG the double-asserted cell via the per-name n != 1 branch.
			// settledAtReturn == len(canonical) and maxInFly <= 1 (serial pins pass); reach
			// name-set is complete (every cell entered exactly once, so (a) passes); and the
			// (a') per-name asserted loop runs BEFORE the length check, so the n != 1 branch on
			// doubleAssertedCell fires first (the substring pin below proves it is that branch).
			// Drive verify on a capture goroutine so its Fatalf does not fail THIS meta-test.
			notFired := fmt.Sprintf("foldCompletenessTracker.verify did NOT flag a DOUBLE-asserted cell (markAsserted(%q) fired twice, markAsserted(%q) never fired, len(asserted) == len(canonical)) — the per-name double-assert branch of the assert-fired guard is dead; a future refactor could collapse asserted to a bare count and CI would stay green",
				doubleAssertedCell, unassertedCell)

			// PIN THE BRANCH: the fired guard must be the (a') per-name DOUBLE-ASSERT check,
			// naming the doubly-asserted cell — not the length branch, the reach guard, the
			// serial guard, or some unrelated path. The double-assert message is the only one
			// that says "recorded its assert-fired marker" (the per-name n != 1 diagnostic) AND
			// names the offending cell; matching both substrings proves the bite is precisely
			// the per-name branch, so a refactor that, say, dropped the per-name keying for a
			// bare count would make THIS substring assertion fail even if another guard fired.
			checks := []substrCheck{
				{want: "recorded its assert-fired marker", failf: func(msg string) string {
					return fmt.Sprintf("verify fired, but NOT via the (a') per-name double-assert branch — the bite is not pinned to the double-assert axis. captured: %q", msg)
				}},
				{want: doubleAssertedCell, failf: func(msg string) string {
					return fmt.Sprintf("the double-assert guard fired but did not name the doubly-asserted cell %q — the diagnostic does not locate the offending cell. captured: %q", doubleAssertedCell, msg)
				}},
				{want: "assert-fired-double", failf: func(msg string) string {
					return fmt.Sprintf("the double-assert guard fired but did not carry its label %q (self-locating failure broken). captured: %q", "assert-fired-double", msg)
				}},
			}
			return bad, len(names), notFired, checks
		},
		posLabel: "assert-fired-double-positive-control",
		// (2) POSITIVE CONTROL: the SAME fully-reached tracker shape but with EVERY cell's
		// assert fired EXACTLY ONCE must PASS verify — proving the guard flags (1) because
		// of the 2 + 0 SWAP, not because verify always fails. Because the ONLY difference
		// from (1) is that doubleAssertedCell now asserts once and unassertedCell asserts
		// once (instead of 2 + 0), a clean pass here isolates the (1) bite to exactly the
		// double-assert swap.
		buildGood: func(_ *testing.T, names []string, _ map[string]struct{}) *foldCompletenessTracker {
			good := newFoldCompletenessTracker()
			for _, name := range names {
				done := good.enter(name)
				done()
				good.markAsserted(name) // EVERY cell asserts exactly once — a legitimately-complete fold
			}
			return good
		},
		posFailf: func(msg string) string {
			return fmt.Sprintf("foldCompletenessTracker.verify FLAGGED a legitimately-complete fold (every cell reached AND asserted exactly once) — the double-assert guard is a false positive, rejecting honest coverage. captured: %q", msg)
		},
	})
}

// TestFoldCompletenessTracker_AssertFiredGuardFlagsForeignAssert is the IN-TREE
// negative meta-test that PERMANENTLY pins the canonical-MEMBERSHIP (foreign-assert)
// branch of the (a') assert-fired fold guard in foldCompletenessTracker.verify (the
// `if _, ok := canonical[name]; !ok` check at the top of the asserted loop). A cell
// whose markAsserted fired for a name NOT in the canonical reason matrix — an
// off-matrix assert, the fold drifting off the canonical cell set on the assert axis
// — must fail LOUDLY. This is the assert-fired analogue of the reach-axis FOREIGN
// guard (the membership check in the exercised loop) that the reach name-set already
// pins; together with the sibling double-assert and visited-but-unasserted
// meta-tests it closes the last unguarded refactor-neuter paths on the assert-fired
// axis.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet,
// no RefImpl — hermetic): it seeds the asserted map with a cell name ABSENT from the
// canonical set (every canonical cell still reached and asserted, so the only
// deviation is the off-matrix assert), then asserts verify FLAGS the foreign assert.
// A POSITIVE control (only canonical cells asserted) then proves the guard is
// discriminating, not always-failing.
//
// Additive and test-only: it reuses the existing foldCompletenessTracker, the
// canonical reasonMatrixCellNames(), and the orch78 fatal-capture harness
// (runVerifyExpectingFatal); modifies no production code (refimpl.go untouched);
// weakens no existing assertion; and adds no dependency. Synthetic fixtures only
// (D50).
func TestFoldCompletenessTracker_AssertFiredGuardFlagsForeignAssert(t *testing.T) {
	runVerifyGuardMetaTest(t, verifyGuardMetaSpec{
		minCells: 1,
		minCellsFailf: func(n int) string {
			return fmt.Sprintf("the canonical reason matrix has %d cells; this meta-test needs >= 1 to be meaningful", n)
		},
		label: "assert-fired-foreign",
		build: func(_ *testing.T, names []string, canonical map[string]struct{}) (*foldCompletenessTracker, int, string, []substrCheck) {
			// Synthesize a cell name guaranteed ABSENT from the canonical set — the off-matrix
			// assert. A fixed sentinel plus a membership re-check keeps it deterministic and
			// proof against any future canonical name happening to collide with the literal.
			foreignCell := "__off_canonical_foreign_assert_cell__"
			for {
				if _, clash := canonical[foreignCell]; !clash {
					break
				}
				foreignCell += "_x" // vanishingly unlikely; keep extending until disjoint
			}

			// (1) NEGATIVE: every canonical cell REACHED once and asserted once (reach and
			// assert sets otherwise complete), PLUS one markAsserted for the off-matrix
			// foreignCell. The foreign assert is the ONLY deviation, so the (a') membership
			// branch is the lone guard that can bite. (Reach stays canonical-only, so the (a)
			// reach guards all pass; settledAtReturn == len(canonical) keeps the serial pins
			// green.)
			bad := newFoldCompletenessTracker()
			for _, name := range names {
				done := bad.enter(name) // REACH recorded for the canonical cell exactly once
				done()                  // release in-flight, as the real fold's deferred done() does
				bad.markAsserted(name)  // every canonical cell asserts exactly once
			}
			bad.markAsserted(foreignCell) // DELIBERATE: an OFF-CANONICAL cell's assert fired

			// verify must FLAG the foreign assert via the (a') membership branch. The reach
			// set is exactly canonical (the foreign name was never enter()'d), the serial pins
			// pass (settledAtReturn == len(canonical), maxInFly <= 1), and every canonical cell
			// asserted once — so the off-canonical name in the asserted map is the lone guard
			// left to fire. Drive verify on a capture goroutine so its Fatalf does not fail
			// THIS meta-test.
			notFired := fmt.Sprintf("foldCompletenessTracker.verify did NOT flag an OFF-CANONICAL asserted cell (markAsserted(%q), a name absent from the canonical reason matrix) — the foreign-assert membership branch of the assert-fired guard is dead; a future refactor could drop the canonical-membership check on the assert axis and CI would stay green",
				foreignCell)

			// PIN THE BRANCH: the fired guard must be the (a') FOREIGN-ASSERT membership check,
			// naming the off-canonical cell — not the double-assert branch, the length branch,
			// the reach guards, the serial guards, or some unrelated path. The foreign-assert
			// message is the only one that says "asserted FOREIGN cell" AND names the offending
			// name; matching both substrings proves the bite is precisely the membership branch
			// on the assert axis, so a refactor that dropped the canonical[name] check on the
			// asserted loop would make THIS substring assertion fail even if another guard fired.
			checks := []substrCheck{
				{want: "asserted FOREIGN cell", failf: func(msg string) string {
					return fmt.Sprintf("verify fired, but NOT via the (a') foreign-assert membership branch — the bite is not pinned to the foreign-assert axis. captured: %q", msg)
				}},
				{want: foreignCell, failf: func(msg string) string {
					return fmt.Sprintf("the foreign-assert guard fired but did not name the off-canonical cell %q — the diagnostic does not locate the foreign assert. captured: %q", foreignCell, msg)
				}},
				{want: "assert-fired-foreign", failf: func(msg string) string {
					return fmt.Sprintf("the foreign-assert guard fired but did not carry its label %q (self-locating failure broken). captured: %q", "assert-fired-foreign", msg)
				}},
			}
			return bad, len(names), notFired, checks
		},
		posLabel: "assert-fired-foreign-positive-control",
		// (2) POSITIVE CONTROL: the SAME fully-reached tracker shape WITHOUT the off-matrix
		// assert must PASS verify — proving the guard flags (1) because of the foreign
		// assert, not because verify always fails. Because the ONLY difference from (1) is
		// the absent markAsserted(foreignCell), a clean pass here isolates the (1) bite to
		// exactly the off-canonical assert.
		buildGood: func(_ *testing.T, names []string, _ map[string]struct{}) *foldCompletenessTracker {
			good := newFoldCompletenessTracker()
			for _, name := range names {
				done := good.enter(name)
				done()
				good.markAsserted(name) // ONLY canonical cells assert — a legitimately-complete fold
			}
			return good
		},
		posFailf: func(msg string) string {
			return fmt.Sprintf("foldCompletenessTracker.verify FLAGGED a legitimately-complete fold (every canonical cell reached AND asserted, no foreign assert) — the foreign-assert guard is a false positive, rejecting honest coverage. captured: %q", msg)
		},
	})
}

// TestFoldCompletenessTracker_ReachGuardFlagsDoubleVisit is the IN-TREE negative
// meta-test that PERMANENTLY pins the PER-NAME (n != 1) branch of the (a) REACH
// fold guard in foldCompletenessTracker.verify (the count-per-name check at the
// `if n != 1` site in the exercised loop). The sibling assert-fired meta-tests
// (orch78/81) pin the ASSERT axis; this one symmetrically pins the REACH axis. A
// cell whose subtest body is REACHED (enter at the top) TWICE while another is
// skipped is a per-name SWAP: the reach set has the SAME total visit count as a
// clean fold (2 + 0 nets the same as 1 + 1), so a bare count
// (cellsExercised == len(canonical)) is vacuous to it and only the per-name
// keying on ft.exercised catches it. A refactor collapsing exercised to a bare
// count could neuter this branch with CI green; this meta-test turns the one-time
// manual proof into a STANDING CI invariant.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet,
// no RefImpl — hermetic): it enter()s every canonical cell exactly once and the
// SMALLEST canonical cell a SECOND time, with markAsserted laid down for every
// cell so the (a') assert-fired guards stay green, the reach LENGTH guard
// deliberately SATISFIED (len(exercised) == len(canonical), since the double-visit
// only inflates one cell's count, not the distinct-cell count), and the serial
// pins passed (settledAtReturn == len(canonical), maxInFly <= 1 — each enter() is
// released by its done() before the next, so in-flight never exceeds 1). Because
// verify walks the per-name exercised loop (foreign + n != 1) BEFORE the reach
// length check and Goexits on the first Fatalf, the per-name double-visit branch
// is the one that bites on doubleVisitedCell. A POSITIVE control (every cell
// reached exactly once) then proves the guard is discriminating, not
// always-failing.
//
// Additive and test-only: it reuses the existing foldCompletenessTracker, the
// canonical reasonMatrixCellNames(), and the orch78 fatal-capture harness
// (runVerifyExpectingFatal); modifies no production code (refimpl.go untouched);
// weakens no existing assertion; and adds no dependency. Synthetic fixtures only
// (D50).
func TestFoldCompletenessTracker_ReachGuardFlagsDoubleVisit(t *testing.T) {
	runVerifyGuardMetaTest(t, verifyGuardMetaSpec{
		minCells: 2,
		minCellsFailf: func(n int) string {
			return fmt.Sprintf("the canonical reason matrix has %d cells; this meta-test needs >= 2 (one double-visited cell + at least one other) to be meaningful", n)
		},
		label: "reach-double-visit",
		build: func(_ *testing.T, names []string, _ map[string]struct{}) (*foldCompletenessTracker, int, string, []substrCheck) {
			// Deterministic cell choice (lexicographic) so the double-visit is reproducible
			// regardless of map iteration order: the smallest name is enter()'d TWICE while
			// every cell is still visited at least once, so the distinct-cell count stays at
			// len(canonical) and the reach LENGTH guard is satisfied — isolating the bite to
			// the per-name n != 1 branch.
			doubleVisitedCell := names[0] // enter()'d TWICE

			// (1) NEGATIVE: every cell REACHED once (and the smallest cell a second time),
			// each enter() released by its done() before the next so in-flight settles to 0
			// (maxInFly <= 1, mirroring the real fold's deferred done()); every cell asserts
			// once so the (a') assert-fired guards stay green. The ONLY deviation is
			// doubleVisitedCell's reach count of 2, so the (a) per-name double-visit branch is
			// the lone guard that can bite.
			bad := newFoldCompletenessTracker()
			for _, name := range names {
				done := bad.enter(name) // REACH recorded
				done()                  // release in-flight, as the real fold's deferred done() does
				bad.markAsserted(name)  // keep the assert-fired set complete so (a') stays green
			}
			doneDup := bad.enter(doubleVisitedCell) // DELIBERATE: a SECOND visit (reach count 2)
			doneDup()                               // released, so in-flight still never exceeds 1

			// verify must FLAG the double-visited cell via the per-name n != 1 branch.
			// settledAtReturn == len(canonical) and maxInFly <= 1 (serial pins pass); the
			// distinct-cell count is still len(canonical) (reach length guard passes); the
			// assert-fired set is complete ((a') passes); and the (a) per-name exercised loop
			// runs BEFORE the length check, so the n != 1 branch on doubleVisitedCell fires
			// first (the substring pin below proves it is that branch). Drive verify on a
			// capture goroutine so its Fatalf does not fail THIS meta-test.
			notFired := fmt.Sprintf("foldCompletenessTracker.verify did NOT flag a DOUBLE-visited cell (enter(%q) ran twice, len(exercised) == len(canonical)) — the per-name double-visit branch of the reach guard is dead; a future refactor could collapse exercised to a bare count and CI would stay green",
				doubleVisitedCell)

			// PIN THE BRANCH: the fired guard must be the (a) per-name DOUBLE-VISIT check,
			// naming the doubly-visited cell — not the length branch, the assert-fired guards,
			// the serial guards, or some unrelated path. The double-visit message is the only
			// one that says "was exercised" (the per-name n != 1 diagnostic) AND names the
			// offending cell; matching both substrings proves the bite is precisely the
			// per-name reach branch, so a refactor that dropped the per-name keying for a bare
			// count would make THIS substring assertion fail even if another guard fired.
			checks := []substrCheck{
				{want: "was exercised", failf: func(msg string) string {
					return fmt.Sprintf("verify fired, but NOT via the (a) per-name double-visit branch — the bite is not pinned to the reach double-visit axis. captured: %q", msg)
				}},
				{want: doubleVisitedCell, failf: func(msg string) string {
					return fmt.Sprintf("the double-visit guard fired but did not name the doubly-visited cell %q — the diagnostic does not locate the offending cell. captured: %q", doubleVisitedCell, msg)
				}},
				{want: "reach-double-visit", failf: func(msg string) string {
					return fmt.Sprintf("the double-visit guard fired but did not carry its label %q (self-locating failure broken). captured: %q", "reach-double-visit", msg)
				}},
			}
			return bad, len(names), notFired, checks
		},
		posLabel: "reach-double-visit-positive-control",
		// (2) POSITIVE CONTROL: the SAME fully-reached tracker shape but with EVERY cell
		// visited EXACTLY ONCE must PASS verify — proving the guard flags (1) because of
		// the second visit, not because verify always fails. Because the ONLY difference
		// from (1) is the absent second enter(doubleVisitedCell), a clean pass here
		// isolates the (1) bite to exactly the double visit.
		buildGood: func(_ *testing.T, names []string, _ map[string]struct{}) *foldCompletenessTracker {
			good := newFoldCompletenessTracker()
			for _, name := range names {
				done := good.enter(name)
				done()
				good.markAsserted(name) // every cell reached once AND asserted once — a legitimately-complete fold
			}
			return good
		},
		posFailf: func(msg string) string {
			return fmt.Sprintf("foldCompletenessTracker.verify FLAGGED a legitimately-complete fold (every cell reached AND asserted exactly once) — the double-visit guard is a false positive, rejecting honest coverage. captured: %q", msg)
		},
	})
}

// TestFoldCompletenessTracker_ReachGuardFlagsSkippedCell is the IN-TREE negative
// meta-test that PERMANENTLY pins the reach-LENGTH (skipped-cells) branch of the
// (a) REACH fold guard in foldCompletenessTracker.verify (the
// `len(ft.exercised) != len(canonical)` check after the exercised loop, whose
// message names the SKIPPED cells). This is the reach-axis analogue of the
// assert-fired LENGTH branch the sibling visited-but-unasserted meta-test pins. A
// cell that is NEVER enter()'d shortens the reach set below the canonical size — a
// fold that silently dropped a cell — and must fail LOUDLY rather than passing
// vacuously. A refactor that dropped the reach length check could neuter this with
// CI green; this meta-test turns the one-time manual proof into a STANDING CI
// invariant.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet,
// no RefImpl — hermetic): it enter()s every canonical cell EXCEPT one (the smallest
// name, deliberately SKIPPED) and asserts every cell it reaches, so the per-name
// exercised loop cannot fire (every reached cell has count 1 and is canonical) and
// the ONLY guard left to bite is the reach LENGTH check. The serial pins pass
// (settledAtReturn == len(canonical), maxInFly <= 1) — note settledAtReturn is
// passed as len(canonical) so the (b.1) synchronous-settle guard stays green and
// the length mismatch is attributed to the missing reach, not to a short settle.
// A POSITIVE control (every cell reached) then proves the guard is discriminating,
// not always-failing.
//
// Additive and test-only: it reuses the existing foldCompletenessTracker, the
// canonical reasonMatrixCellNames(), and the orch78 fatal-capture harness
// (runVerifyExpectingFatal); modifies no production code (refimpl.go untouched);
// weakens no existing assertion; and adds no dependency. Synthetic fixtures only
// (D50).
func TestFoldCompletenessTracker_ReachGuardFlagsSkippedCell(t *testing.T) {
	runVerifyGuardMetaTest(t, verifyGuardMetaSpec{
		minCells: 2,
		minCellsFailf: func(n int) string {
			return fmt.Sprintf("the canonical reason matrix has %d cells; this meta-test needs >= 2 (one skipped cell + at least one reached) to be meaningful", n)
		},
		label: "reach-skipped-cell",
		build: func(_ *testing.T, names []string, _ map[string]struct{}) (*foldCompletenessTracker, int, string, []substrCheck) {
			// Deterministic cell choice (lexicographic) so the skip is reproducible regardless
			// of map iteration order: the smallest name is NEVER enter()'d, shortening the
			// reach set by exactly one.
			skippedCell := names[0] // NEVER enter()'d

			// (1) NEGATIVE: every cell REACHED once EXCEPT skippedCell, each enter() released
			// by its done() before the next so in-flight settles to 0 (maxInFly <= 1); every
			// reached cell asserts once. The reach set is short by exactly one (skippedCell),
			// so the per-name exercised loop cannot fire (every reached cell has count 1 and is
			// canonical) and the reach LENGTH branch is the lone guard that can bite.
			bad := newFoldCompletenessTracker()
			for _, name := range names {
				if name == skippedCell {
					continue // DELIBERATE: this cell is NEVER enter()'d — the reach set is short by one
				}
				done := bad.enter(name) // REACH recorded for every other cell exactly once
				done()                  // release in-flight, as the real fold's deferred done() does
				bad.markAsserted(name)  // keep the assert-fired set in lockstep with reach
			}

			// verify must FLAG the skipped cell via the reach LENGTH branch. settledAtReturn is
			// passed as len(canonical) so the (b.1) synchronous-settle guard stays green (the
			// mismatch is the MISSING reach, not a short settle); maxInFly <= 1 (b.2 passes);
			// the per-name exercised loop cannot fire (every reached cell is canonical with
			// count 1), so the reach LENGTH check is what bites — the substring pin below proves
			// it. Drive verify on a capture goroutine so its Fatalf does not fail THIS meta-test.
			notFired := fmt.Sprintf("foldCompletenessTracker.verify did NOT flag a SKIPPED cell (enter(%q) never ran, len(exercised) < len(canonical)) — the reach-length skipped-cells branch of the reach guard is dead; a future refactor could drop the reach length check and CI would stay green",
				skippedCell)

			// PIN THE BRANCH: the fired guard must be the (a) reach-LENGTH skipped-cells check,
			// naming the skipped cell — not the per-name double-visit branch, the assert-fired
			// guards, the serial guards, or some unrelated path. The skipped-cells message is
			// the only one that says "SKIPPED cells" AND names the offending cell; matching both
			// substrings proves the bite is precisely the reach length branch, so a refactor that
			// dropped the reach length check would make THIS substring assertion fail even if
			// another guard fired.
			checks := []substrCheck{
				{want: "SKIPPED cells", failf: func(msg string) string {
					return fmt.Sprintf("verify fired, but NOT via the (a) reach-length skipped-cells branch — the bite is not pinned to the reach length axis. captured: %q", msg)
				}},
				{want: skippedCell, failf: func(msg string) string {
					return fmt.Sprintf("the skipped-cells guard fired but did not name the skipped cell %q — the diagnostic does not locate the missing cell. captured: %q", skippedCell, msg)
				}},
				{want: "reach-skipped-cell", failf: func(msg string) string {
					return fmt.Sprintf("the skipped-cells guard fired but did not carry its label %q (self-locating failure broken). captured: %q", "reach-skipped-cell", msg)
				}},
			}
			return bad, len(names), notFired, checks
		},
		posLabel: "reach-skipped-cell-positive-control",
		// (2) POSITIVE CONTROL: the SAME tracker shape but with EVERY cell reached must PASS
		// verify — proving the guard flags (1) because of the skipped cell, not because
		// verify always fails. Because the ONLY difference from (1) is that skippedCell is
		// now reached and asserted too, a clean pass here isolates the (1) bite to exactly
		// the skipped cell.
		buildGood: func(_ *testing.T, names []string, _ map[string]struct{}) *foldCompletenessTracker {
			good := newFoldCompletenessTracker()
			for _, name := range names {
				done := good.enter(name)
				done()
				good.markAsserted(name) // every cell reached AND asserted — a legitimately-complete fold
			}
			return good
		},
		posFailf: func(msg string) string {
			return fmt.Sprintf("foldCompletenessTracker.verify FLAGGED a legitimately-complete fold (every cell reached AND asserted) — the skipped-cells guard is a false positive, rejecting honest coverage. captured: %q", msg)
		},
	})
}

// TestFoldCompletenessTracker_SerialGuardFlagsShortSynchronousSettle is the IN-TREE
// negative meta-test that PERMANENTLY pins the (b.1) SYNCHRONOUS-SETTLE count guard
// in foldCompletenessTracker.verify (the `settledAtReturn != len(canonical)` check,
// whose message says "settled synchronously when the loop returned"). This guard is
// load-bearing — it guarantees the shared fleet stayed single-threaded, since a
// t.Parallel()'d cell is paused past the parent and would leave the synchronously-
// captured count SHORT — but had no in-tree negative meta-test, so a refactor could
// remove it with CI green. This meta-test turns that into a STANDING CI invariant,
// completing the SERIAL family of the verify-guard coverage.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet,
// no RefImpl — hermetic): it builds a fully-reached, fully-asserted, serial tracker
// (every guard except the serial-settle count would PASS) and then drives verify
// with a SHORT settledAtReturn (< len(canonical)) — the count a parent would have
// captured if a cell had deferred its body past the loop. Because every other guard
// is satisfied and the (b.1) settle check runs FIRST in verify, the short-settle
// guard is the lone guard that can bite. A POSITIVE control (settledAtReturn ==
// len(canonical)) then proves the guard is discriminating, not always-failing.
//
// Additive and test-only: it reuses the existing foldCompletenessTracker, the
// canonical reasonMatrixCellNames(), and the orch78 fatal-capture harness
// (runVerifyExpectingFatal); modifies no production code (refimpl.go untouched);
// weakens no existing assertion; and adds no dependency. Synthetic fixtures only
// (D50).
func TestFoldCompletenessTracker_SerialGuardFlagsShortSynchronousSettle(t *testing.T) {
	runVerifyGuardMetaTest(t, verifyGuardMetaSpec{
		minCells: 1,
		minCellsFailf: func(n int) string {
			return fmt.Sprintf("the canonical reason matrix has %d cells; this meta-test needs >= 1 to be meaningful", n)
		},
		label: "serial-short-settle",
		build: func(_ *testing.T, names []string, _ map[string]struct{}) (*foldCompletenessTracker, int, string, []substrCheck) {
			// (1) NEGATIVE: a fully-reached, fully-asserted, SERIAL tracker — every cell
			// enter()'d once and released by its done() (maxInFly <= 1), every cell asserted
			// once. The reach and assert sets are both complete, so the ONLY thing that can
			// fire is the (b.1) synchronous-settle guard, which we trip by passing a SHORT
			// settledAtReturn — the count a parent captures synchronously when a cell deferred
			// its body past the loop (a t.Parallel() against the shared fleet).
			bad := newFoldCompletenessTracker()
			for _, name := range names {
				done := bad.enter(name)
				done()
				bad.markAsserted(name)
			}
			shortSettle := len(names) - 1 // DELIBERATE: a cell "did not settle synchronously"

			// verify must FLAG the short settle via the (b.1) count guard, which runs FIRST so
			// it bites before any reach/assert guard (all of which would pass here). Drive
			// verify on a capture goroutine so its Fatalf does not fail THIS meta-test.
			notFired := fmt.Sprintf("foldCompletenessTracker.verify did NOT flag a SHORT synchronous settle (settledAtReturn=%d < len(canonical)=%d) — the (b.1) synchronous-settle serial guard is dead; a future refactor could drop it and a t.Parallel()'d cell against the shared fleet would slip past with CI green",
				shortSettle, len(names))

			// PIN THE BRANCH: the fired guard must be the (b.1) SYNCHRONOUS-SETTLE count check —
			// not the maxInFly high-water guard, the reach guards, the assert-fired guards, or
			// some unrelated path. The settle message is the only one that says both
			// "serial-execution invariant VIOLATED" AND "settled synchronously"; matching both
			// substrings proves the bite is precisely the (b.1) count branch, so a refactor that
			// dropped the synchronous-settle check would make THIS substring assertion fail even
			// if another guard fired.
			checks := []substrCheck{
				{want: "serial-execution invariant VIOLATED", failf: func(msg string) string {
					return fmt.Sprintf("verify fired, but NOT via a serial-execution guard — the bite is not pinned to the serial axis. captured: %q", msg)
				}},
				{want: "settled synchronously", failf: func(msg string) string {
					return fmt.Sprintf("the serial guard fired, but NOT via the (b.1) synchronous-settle count branch — the bite is not pinned to the short-settle axis. captured: %q", msg)
				}},
				{want: "serial-short-settle", failf: func(msg string) string {
					return fmt.Sprintf("the synchronous-settle guard fired but did not carry its label %q (self-locating failure broken). captured: %q", "serial-short-settle", msg)
				}},
			}
			return bad, shortSettle, notFired, checks
		},
		posLabel: "serial-short-settle-positive-control",
		// (2) POSITIVE CONTROL: the SAME fully-reached, fully-asserted, serial tracker with
		// settledAtReturn == len(canonical) must PASS verify — proving the guard flags (1)
		// because of the SHORT settle, not because verify always fails. Because the ONLY
		// difference from (1) is the settledAtReturn argument, a clean pass here isolates
		// the (1) bite to exactly the short settle. Re-running the SAME `bad` tracker (not a
		// fresh one) is the load-bearing isolation: only the settle arg changes.
		reuseBad:  true,
		posSettle: func(canonical map[string]struct{}) int { return len(canonical) },
		posFailf: func(msg string) string {
			return fmt.Sprintf("foldCompletenessTracker.verify FLAGGED a legitimately-serial fold (every cell settled synchronously, settledAtReturn == len(canonical)) — the synchronous-settle guard is a false positive, rejecting honest coverage. captured: %q", msg)
		},
	})
}

// TestFoldCompletenessTracker_SerialGuardFlagsConcurrentOverlap is the IN-TREE
// negative meta-test that PERMANENTLY pins the (b.2) maxInFly HIGH-WATER guard in
// foldCompletenessTracker.verify (the `hi := atomic.LoadInt64(&ft.maxInFly); hi > 1`
// check, whose message says "ran concurrently"). This belt-and-suspenders guard
// catches a hand-rolled goroutine fan-out (which, unlike t.Parallel(), is NOT
// deferred past the parent so the synchronous-settle count would NOT be short) by
// proving no two cell subtests were ever in flight at once. It had no in-tree
// negative meta-test, so a refactor could remove it with CI green. This meta-test
// turns that into a STANDING CI invariant, completing the SERIAL family alongside
// the synchronous-settle pin.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet,
// no RefImpl — hermetic): it enter()s every canonical cell once but, for one pair,
// drives TWO OVERLAPPING enter()s with NO done() between them — so in-flight reaches
// 2 and maxInFly records the high-water mark of 2 (a hand-rolled fan-out that raced
// the shared fleet). It releases both before verify so the run is otherwise clean;
// the high-water mark, once set, stays at 2. settledAtReturn == len(canonical) keeps
// the (b.1) settle guard green, and the reach/assert sets are kept complete, so the
// ONLY guard that can fire is the (b.2) maxInFly check, which runs before the reach
// loop. A POSITIVE control (every enter() released before the next, maxInFly <= 1)
// then proves the guard is discriminating, not always-failing.
//
// Additive and test-only: it reuses the existing foldCompletenessTracker, the
// canonical reasonMatrixCellNames(), and the orch78 fatal-capture harness
// (runVerifyExpectingFatal); modifies no production code (refimpl.go untouched);
// weakens no existing assertion; and adds no dependency. Synthetic fixtures only
// (D50).
func TestFoldCompletenessTracker_SerialGuardFlagsConcurrentOverlap(t *testing.T) {
	runVerifyGuardMetaTest(t, verifyGuardMetaSpec{
		minCells: 2,
		minCellsFailf: func(n int) string {
			return fmt.Sprintf("the canonical reason matrix has %d cells; this meta-test needs >= 2 (a pair to overlap) to be meaningful", n)
		},
		label: "serial-concurrent-overlap",
		build: func(_ *testing.T, names []string, _ map[string]struct{}) (*foldCompletenessTracker, int, string, []substrCheck) {
			overlapA := names[0]
			overlapB := names[1]

			// (1) NEGATIVE: every canonical cell REACHED once and asserted once, but the first
			// two cells are entered with their bodies OVERLAPPING — enter(overlapA) and
			// enter(overlapB) with NO done() between them, so in-flight reaches 2 and the
			// high-water maxInFly records 2 (a hand-rolled goroutine fan-out that raced the
			// shared fleet). Both are then released before verify, so the run is otherwise
			// clean; the high-water mark, once recorded, stays at 2. Every OTHER cell is entered
			// serially (released before the next). Because the reach/assert sets are complete and
			// settledAtReturn == len(canonical) keeps the (b.1) settle guard green, the (b.2)
			// maxInFly guard is the lone guard that can bite.
			bad := newFoldCompletenessTracker()
			doneA := bad.enter(overlapA) // enter A...
			doneB := bad.enter(overlapB) // ...then B with NO done() between — in-flight is now 2, maxInFly records 2
			doneA()
			doneB()
			bad.markAsserted(overlapA)
			bad.markAsserted(overlapB)
			for _, name := range names {
				if name == overlapA || name == overlapB {
					continue // already reached (overlapping) above
				}
				done := bad.enter(name) // every remaining cell entered SERIALLY (released before the next)
				done()
				bad.markAsserted(name)
			}

			// verify must FLAG the concurrent overlap via the (b.2) maxInFly guard, which runs
			// before the reach loop. settledAtReturn == len(canonical) keeps (b.1) green, the
			// reach and assert sets are complete, so the high-water mark of 2 is the lone
			// deviation. Drive verify on a capture goroutine so its Fatalf does not fail THIS
			// meta-test.
			notFired := fmt.Sprintf("foldCompletenessTracker.verify did NOT flag a CONCURRENT overlap (enter(%q) and enter(%q) overlapped with no done() between, driving maxInFly to 2) — the (b.2) maxInFly high-water serial guard is dead; a future refactor could drop it and a hand-rolled goroutine fan-out racing the shared fleet would slip past with CI green",
				overlapA, overlapB)

			// PIN THE BRANCH: the fired guard must be the (b.2) maxInFly HIGH-WATER check — not
			// the synchronous-settle count guard, the reach guards, the assert-fired guards, or
			// some unrelated path. The high-water message is the only one that says both
			// "serial-execution invariant VIOLATED" AND "ran concurrently"; matching both
			// substrings proves the bite is precisely the (b.2) maxInFly branch, so a refactor
			// that dropped the high-water check would make THIS substring assertion fail even if
			// another guard fired.
			checks := []substrCheck{
				{want: "serial-execution invariant VIOLATED", failf: func(msg string) string {
					return fmt.Sprintf("verify fired, but NOT via a serial-execution guard — the bite is not pinned to the serial axis. captured: %q", msg)
				}},
				{want: "ran concurrently", failf: func(msg string) string {
					return fmt.Sprintf("the serial guard fired, but NOT via the (b.2) maxInFly high-water branch — the bite is not pinned to the concurrent-overlap axis. captured: %q", msg)
				}},
				{want: "serial-concurrent-overlap", failf: func(msg string) string {
					return fmt.Sprintf("the maxInFly guard fired but did not carry its label %q (self-locating failure broken). captured: %q", "serial-concurrent-overlap", msg)
				}},
			}
			return bad, len(names), notFired, checks
		},
		posLabel: "serial-concurrent-overlap-positive-control",
		// (2) POSITIVE CONTROL: the SAME fully-reached, fully-asserted tracker but with every
		// enter() RELEASED before the next (maxInFly <= 1) must PASS verify — proving the
		// guard flags (1) because of the overlap, not because verify always fails. Because
		// the ONLY difference from (1) is that overlapA/overlapB are now entered serially,
		// a clean pass here isolates the (1) bite to exactly the concurrent overlap.
		buildGood: func(_ *testing.T, names []string, _ map[string]struct{}) *foldCompletenessTracker {
			good := newFoldCompletenessTracker()
			for _, name := range names {
				done := good.enter(name) // every cell entered serially — in-flight never exceeds 1
				done()
				good.markAsserted(name)
			}
			return good
		},
		posFailf: func(msg string) string {
			return fmt.Sprintf("foldCompletenessTracker.verify FLAGGED a legitimately-serial fold (every cell entered and released before the next, maxInFly <= 1) — the maxInFly high-water guard is a false positive, rejecting honest coverage. captured: %q", msg)
		},
	})
}

// TestFoldCompletenessTracker_VerifyGuardPrecedence is the IN-TREE PRECEDENCE
// meta-test that PERMANENTLY pins the guard EVALUATION ORDER in
// foldCompletenessTracker.verify. The sibling family above pins each guard
// INDIVIDUALLY — reach foreign / double-visit / LENGTH, assert-fired foreign /
// double / LENGTH, serial (b.1) synchronous-settle and (b.2) maxInFly — by
// constructing a state where exactly ONE guard can bite and matching its
// substring. But the soundness of those substring attributions silently rests on
// an UNPINNED invariant: the guards are CHECKED IN A FIXED ORDER. The
// reach-skipped-cell branch-pin, for instance, attributes its bite to "SKIPPED
// cells" ONLY because the reach-LENGTH check runs BEFORE the assert-LENGTH check —
// a skipped cell is short on BOTH the reach AND the assert axis, so if a refactor
// reordered assert-LENGTH ahead of reach-LENGTH, that sibling would suddenly
// capture the assert-fired message instead, its attribution silently unsound while
// every individual test stayed green-then-surprising. This meta-test turns that
// ORDER into a STANDING CI invariant: it constructs foldCompletenessTracker states
// that trip TWO guards AT ONCE and asserts WHICH message wins — the EARLIER guard,
// since verify's first Fatalf Goexits the capture goroutine before any later guard
// runs. So a refactor that reorders the guards is caught here rather than silently
// making a sibling branch-pin's attribution unsound.
//
// The documented precedence (top wins): (b.1) serial synchronous-settle, (b.2)
// serial maxInFly, (a) reach foreign, (a) reach double-visit, (a) reach-LENGTH,
// (a') assert-fired foreign, (a') assert double, (a') assert-LENGTH. This test pins
// the LOAD-BEARING ADJACENT orderings with >= 2 two-guards-at-once pairs:
//   - reach-LENGTH BEFORE assert-LENGTH (the exact adjacency the reach-skipped-cell
//     branch-pin's attribution depends on): a cell short on both axes yields the
//     reach "SKIPPED cells" message, NOT the assert "fired their agreement/invariant
//     assertion" message;
//   - serial (b.1) synchronous-settle BEFORE the reach axis: a short settle PLUS a
//     skipped cell yields the (b.1) "settled synchronously" message, NOT "SKIPPED
//     cells";
//   - serial (b.2) maxInFly BEFORE the reach axis: a concurrent overlap PLUS a
//     skipped cell yields the (b.2) "ran concurrently" message, NOT "SKIPPED cells".
//
// Each pair also proves both guards are INDIVIDUALLY live (a control tripping ONLY
// the later guard fires the later message), so the precedence assertion cannot pass
// vacuously by the later guard simply never firing.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet,
// no RefImpl — hermetic) through the orch78 fatal-capture harness
// (runVerifyExpectingFatal), reusing newFoldCompletenessTracker/enter/markAsserted
// and the canonical reasonMatrixCellNames(). Additive and test-only: it modifies no
// production code (refimpl.go untouched), weakens no existing assertion, and adds no
// dependency. Synthetic fixtures only (D50).
func TestFoldCompletenessTracker_VerifyGuardPrecedence(t *testing.T) {
	canonical := reasonMatrixCellNames(t, reasonMatrixCells())
	if len(canonical) < 2 {
		t.Fatalf("the canonical reason matrix has %d cells; this precedence meta-test needs >= 2 (one cell short on one axis, a DIFFERENT cell short on another) to be meaningful", len(canonical))
	}

	// Deterministic cell choice (lexicographic) so every pairing is reproducible
	// regardless of map iteration order.
	names := make([]string, 0, len(canonical))
	for name := range canonical {
		names = append(names, name)
	}
	sort.Strings(names)

	// Substrings that uniquely identify each guard's diagnostic in verify, lifted
	// verbatim from the Fatalf messages so a wording change there forces this test to
	// be revisited rather than silently passing on a stale substring.
	const (
		reachLengthSubstr   = "SKIPPED cells"                             // (a) reach-LENGTH
		assertLengthSubstr  = "fired their agreement/invariant assertion" // (a') assert-LENGTH
		settleSubstr        = "settled synchronously"                     // (b.1) serial synchronous-settle
		concurrentSubstr    = "ran concurrently"                          // (b.2) serial maxInFly
		serialViolatedTitle = "serial-execution invariant VIOLATED"       // shared (b.*) title
	)

	// ---- PAIR 1: reach-LENGTH wins over assert-LENGTH -----------------------------
	//
	// This is the EXACT adjacency the reach-skipped-cell branch-pin's "SKIPPED cells"
	// attribution rests on. Construct a state short on BOTH the reach and the assert
	// axis, via TWO DIFFERENT cells so each shortfall is independently real:
	//   - reachOnly is NEVER enter()'d and NEVER markAsserted() — short on reach AND
	//     assert (a cell cannot assert without being reached);
	//   - assertOnly IS enter()'d (reach recorded) but NEVER markAsserted() — short on
	//     assert ONLY.
	// So the reach set is short by one (reachOnly) and the assert set is short by two
	// (reachOnly, assertOnly): BOTH the reach-LENGTH and the assert-LENGTH guard would
	// fire. Because reach-LENGTH is checked FIRST, its "SKIPPED cells" message must win;
	// the assert "fired their agreement/invariant assertion" message must NOT appear.
	{
		reachOnly := names[0]  // short on reach AND assert
		assertOnly := names[1] // reached but NOT asserted — short on assert only
		bad := newFoldCompletenessTracker()
		for _, name := range names {
			if name == reachOnly {
				continue // DELIBERATE: never reached (and so never asserted) — short on BOTH axes
			}
			done := bad.enter(name)
			done()
			if name == assertOnly {
				continue // DELIBERATE: reached but its assert never fires — short on the assert axis only
			}
			bad.markAsserted(name)
		}
		// settledAtReturn == len(canonical) keeps (b.1) green; every reached cell has
		// reach-count 1 and is canonical so the reach foreign/double-visit branches cannot
		// fire; maxInFly <= 1 keeps (b.2) green. The reach-LENGTH and assert-LENGTH guards
		// are the only two that can bite, and reach-LENGTH is earlier — so it wins.
		const label = "precedence-reach-before-assert"
		got := runVerifyExpectingFatal(bad, label, canonical, len(canonical))
		if !got.fired {
			t.Fatalf("two-guards-at-once state (reach short by %q, assert short by %q+%q) did NOT trip verify at all — the precedence pin cannot observe an order", reachOnly, reachOnly, assertOnly)
		}
		if !strings.Contains(got.msg, reachLengthSubstr) {
			t.Fatalf("PRECEDENCE VIOLATED: with BOTH the reach-LENGTH and assert-LENGTH guards tripped, verify did NOT fire the reach-LENGTH %q message FIRST — the documented order (reach-LENGTH before assert-LENGTH) is broken, which would silently make the reach-skipped-cell branch-pin's attribution unsound. captured: %q", reachLengthSubstr, got.msg)
		}
		if strings.Contains(got.msg, assertLengthSubstr) {
			t.Fatalf("PRECEDENCE VIOLATED: verify fired the LATER assert-LENGTH %q message while the EARLIER reach-LENGTH guard was also tripped — the guards are evaluated out of the documented order. captured: %q", assertLengthSubstr, got.msg)
		}
		if !strings.Contains(got.msg, label) {
			t.Fatalf("the precedence bite fired but did not carry its label %q (self-locating failure broken). captured: %q", label, got.msg)
		}

		// LATER-GUARD LIVENESS CONTROL: the SAME shape but with reachOnly now reached
		// (closing the reach shortfall) leaves ONLY the assert-LENGTH guard short (assertOnly
		// still never asserts) — so verify must now fire the assert-LENGTH message. This
		// proves Pair 1's precedence assertion is NOT passing vacuously because the
		// assert-LENGTH guard never fires: it fires once the earlier reach guard is satisfied.
		ctrl := newFoldCompletenessTracker()
		for _, name := range names {
			done := ctrl.enter(name) // EVERY cell reached now — reach set complete
			done()
			if name == assertOnly {
				continue // assertOnly still never asserts — assert set short by exactly one
			}
			ctrl.markAsserted(name)
		}
		ctrlGot := runVerifyExpectingFatal(ctrl, "precedence-reach-before-assert-later-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("later-guard liveness control did NOT fire: with the reach set complete and the assert set short by %q, the assert-LENGTH guard must bite — if it never fires, Pair 1's precedence assertion is vacuous", assertOnly)
		}
		if !strings.Contains(ctrlGot.msg, assertLengthSubstr) {
			t.Fatalf("later-guard liveness control fired, but NOT via the assert-LENGTH %q branch — the later guard of Pair 1 is not actually the assert-LENGTH check, so the precedence pin is comparing the wrong pair. captured: %q", assertLengthSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, reachLengthSubstr) {
			t.Fatalf("later-guard liveness control fired the reach-LENGTH message though the reach set is complete — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}

	// ---- PAIR 2: serial (b.1) synchronous-settle wins over the reach axis ----------
	//
	// Pins the adjacency that the serial pins precede the reach axis. Construct a state
	// short on reach (one cell never enter()'d, so reach-LENGTH would fire "SKIPPED
	// cells") AND drive verify with a SHORT settledAtReturn (so the (b.1) synchronous-
	// settle guard would fire "settled synchronously"). (b.1) is checked FIRST, so its
	// message must win and "SKIPPED cells" must NOT appear.
	{
		skipped := names[0] // never reached — reach-LENGTH would fire
		bad := newFoldCompletenessTracker()
		for _, name := range names {
			if name == skipped {
				continue // DELIBERATE: reach set short by one
			}
			done := bad.enter(name)
			done()
			bad.markAsserted(name)
		}
		shortSettle := len(canonical) - 1 // DELIBERATE: (b.1) synchronous-settle would fire
		const label = "precedence-settle-before-reach"
		got := runVerifyExpectingFatal(bad, label, canonical, shortSettle)
		if !got.fired {
			t.Fatalf("two-guards-at-once state (reach short by %q, settledAtReturn=%d<%d) did NOT trip verify at all — the precedence pin cannot observe an order", skipped, shortSettle, len(canonical))
		}
		if !strings.Contains(got.msg, serialViolatedTitle) || !strings.Contains(got.msg, settleSubstr) {
			t.Fatalf("PRECEDENCE VIOLATED: with BOTH the (b.1) synchronous-settle and the reach-LENGTH guards tripped, verify did NOT fire the (b.1) %q message FIRST — the documented order (serial pins before the reach axis) is broken. captured: %q", settleSubstr, got.msg)
		}
		if strings.Contains(got.msg, reachLengthSubstr) {
			t.Fatalf("PRECEDENCE VIOLATED: verify fired the LATER reach-LENGTH %q message while the EARLIER (b.1) synchronous-settle guard was also tripped — the serial pins no longer precede the reach axis. captured: %q", reachLengthSubstr, got.msg)
		}
		if !strings.Contains(got.msg, label) {
			t.Fatalf("the precedence bite fired but did not carry its label %q (self-locating failure broken). captured: %q", label, got.msg)
		}

		// LATER-GUARD LIVENESS CONTROL: the SAME reach-short shape with a FULL
		// settledAtReturn closes the (b.1) shortfall, leaving ONLY the reach-LENGTH guard —
		// so verify must now fire "SKIPPED cells". This proves Pair 2's precedence assertion
		// is not vacuous (the reach-LENGTH guard does fire once the earlier serial pin is
		// satisfied).
		ctrlGot := runVerifyExpectingFatal(bad, "precedence-settle-before-reach-later-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("later-guard liveness control did NOT fire: with settledAtReturn full and the reach set short by %q, the reach-LENGTH guard must bite — if it never fires, Pair 2's precedence assertion is vacuous", skipped)
		}
		if !strings.Contains(ctrlGot.msg, reachLengthSubstr) {
			t.Fatalf("later-guard liveness control fired, but NOT via the reach-LENGTH %q branch — the later guard of Pair 2 is not the reach-LENGTH check, so the precedence pin is comparing the wrong pair. captured: %q", reachLengthSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, settleSubstr) {
			t.Fatalf("later-guard liveness control fired the (b.1) synchronous-settle message though settledAtReturn is full — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}

	// ---- PAIR 3: serial (b.2) maxInFly wins over the reach axis --------------------
	//
	// Pins the other serial-before-reach adjacency. Construct a state short on reach
	// (one cell never enter()'d) AND with a concurrent overlap (two enter()s with no
	// done() between, driving maxInFly to 2, so (b.2) would fire "ran concurrently").
	// (b.2) is checked before the reach loop, so its message must win and "SKIPPED
	// cells" must NOT appear. The overlap uses two cells DISTINCT from the skipped one,
	// so the overlap is independently real and the reach shortfall is exactly one cell.
	{
		skipped := names[0]  // never reached — reach-LENGTH would fire
		overlapA := names[1] // overlapped with overlapB — drives maxInFly to 2
		overlapB := names[2%len(names)]
		// With exactly 2 canonical cells, names[2%2]==names[0]==skipped, which would make
		// the overlap collide with the skip; require >= 3 to keep all three roles distinct.
		if len(canonical) < 3 {
			// Fall back to a 2-cell-safe construction: overlap the only two cells and skip
			// none on reach, but trip reach via a FOREIGN cell instead so two guards still
			// co-fire (b.2 maxInFly vs (a) reach-foreign). This keeps Pair 3 meaningful even
			// at the 2-cell floor without colliding roles.
			bad := newFoldCompletenessTracker()
			doneA := bad.enter(overlapA)
			doneB := bad.enter(overlapB) // overlap: maxInFly -> 2
			doneA()
			doneB()
			bad.markAsserted(overlapA)
			bad.markAsserted(overlapB)
			foreign := "cell-synthetic-off-canonical-precedence"
			if _, clash := canonical[foreign]; clash {
				t.Fatalf("the synthetic FOREIGN precedence cell name %q is unexpectedly IN the canonical set — pick a name guaranteed off-canonical", foreign)
			}
			df := bad.enter(foreign) // reach-FOREIGN would fire
			df()
			const label = "precedence-maxinfly-before-reach-foreign"
			got := runVerifyExpectingFatal(bad, label, canonical, len(canonical))
			if !got.fired {
				t.Fatalf("two-guards-at-once state (maxInFly=2, reach-foreign %q) did NOT trip verify at all", foreign)
			}
			if !strings.Contains(got.msg, serialViolatedTitle) || !strings.Contains(got.msg, concurrentSubstr) {
				t.Fatalf("PRECEDENCE VIOLATED: with BOTH the (b.2) maxInFly and a reach-foreign guard tripped, verify did NOT fire the (b.2) %q message FIRST — the serial pins no longer precede the reach axis. captured: %q", concurrentSubstr, got.msg)
			}
			if strings.Contains(got.msg, "exercised FOREIGN cell") {
				t.Fatalf("PRECEDENCE VIOLATED: verify fired the LATER reach-foreign message while the EARLIER (b.2) maxInFly guard was also tripped. captured: %q", got.msg)
			}
			if !strings.Contains(got.msg, label) {
				t.Fatalf("the precedence bite fired but did not carry its label %q. captured: %q", label, got.msg)
			}
			return
		}
		// >= 3 cells: skipped, overlapA, overlapB are three distinct names.
		bad := newFoldCompletenessTracker()
		doneA := bad.enter(overlapA)
		doneB := bad.enter(overlapB) // overlap with NO done() between — maxInFly -> 2
		doneA()
		doneB()
		bad.markAsserted(overlapA)
		bad.markAsserted(overlapB)
		for _, name := range names {
			if name == skipped {
				continue // DELIBERATE: reach set short by one
			}
			if name == overlapA || name == overlapB {
				continue // already reached (overlapping) above
			}
			done := bad.enter(name)
			done()
			bad.markAsserted(name)
		}
		const label = "precedence-maxinfly-before-reach"
		got := runVerifyExpectingFatal(bad, label, canonical, len(canonical))
		if !got.fired {
			t.Fatalf("two-guards-at-once state (maxInFly=2 via %q/%q, reach short by %q) did NOT trip verify at all — the precedence pin cannot observe an order", overlapA, overlapB, skipped)
		}
		if !strings.Contains(got.msg, serialViolatedTitle) || !strings.Contains(got.msg, concurrentSubstr) {
			t.Fatalf("PRECEDENCE VIOLATED: with BOTH the (b.2) maxInFly and the reach-LENGTH guards tripped, verify did NOT fire the (b.2) %q message FIRST — the documented order (serial pins before the reach axis) is broken. captured: %q", concurrentSubstr, got.msg)
		}
		if strings.Contains(got.msg, reachLengthSubstr) {
			t.Fatalf("PRECEDENCE VIOLATED: verify fired the LATER reach-LENGTH %q message while the EARLIER (b.2) maxInFly guard was also tripped — the serial pins no longer precede the reach axis. captured: %q", reachLengthSubstr, got.msg)
		}
		if !strings.Contains(got.msg, label) {
			t.Fatalf("the precedence bite fired but did not carry its label %q (self-locating failure broken). captured: %q", label, got.msg)
		}

		// LATER-GUARD LIVENESS CONTROL: the SAME reach-short shape WITHOUT the overlap
		// (every cell entered serially, maxInFly <= 1) closes the (b.2) shortfall, leaving
		// ONLY the reach-LENGTH guard — so verify must now fire "SKIPPED cells". This proves
		// Pair 3's precedence assertion is not vacuous.
		ctrl := newFoldCompletenessTracker()
		for _, name := range names {
			if name == skipped {
				continue // reach set still short by one
			}
			done := ctrl.enter(name) // every reached cell entered serially — maxInFly <= 1
			done()
			ctrl.markAsserted(name)
		}
		ctrlGot := runVerifyExpectingFatal(ctrl, "precedence-maxinfly-before-reach-later-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("later-guard liveness control did NOT fire: with maxInFly <= 1 and the reach set short by %q, the reach-LENGTH guard must bite — if it never fires, Pair 3's precedence assertion is vacuous", skipped)
		}
		if !strings.Contains(ctrlGot.msg, reachLengthSubstr) {
			t.Fatalf("later-guard liveness control fired, but NOT via the reach-LENGTH %q branch — the later guard of Pair 3 is not the reach-LENGTH check, so the precedence pin is comparing the wrong pair. captured: %q", reachLengthSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, concurrentSubstr) {
			t.Fatalf("later-guard liveness control fired the (b.2) maxInFly message though every cell was entered serially — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}
}

// TestFoldCompletenessTracker_VerifyGuardIntraAxisPrecedence is the IN-TREE
// PRECEDENCE meta-test that PERMANENTLY pins the guard EVALUATION ORDER *WITHIN*
// each of foldCompletenessTracker.verify's two name-set blocks — the orderings the
// orch83 cross-axis sibling (TestFoldCompletenessTracker_VerifyGuardPrecedence)
// deliberately did NOT cover. orch83 pinned the THREE load-bearing CROSS-axis
// adjacencies (serial (b.1)/(b.2) BEFORE the reach axis; reach-LENGTH BEFORE
// assert-LENGTH). But verify walks each block as a per-name map loop FOLLOWED BY a
// post-loop LENGTH check, and those INTRA-axis orderings were left unpinned:
//
//	(a)  reach block:  {foreign, per-name double-visit}  ->  reach-LENGTH
//	(a') assert block: {foreign, per-name double-assert}  ->  assert-LENGTH
//
// A refactor that reordered, say, reach-LENGTH ahead of the reach per-name loop, or
// the assert-LENGTH check ahead of the assert per-name loop, would keep EVERY
// single-deviation sibling meta-test green (each constructs a state where exactly ONE
// guard can bite, so the order among the others is invisible to it) while silently
// mis-attributing a FUTURE branch-pin — the same soundness hole the cross-axis pins
// closed at the block boundaries, now closed WITHIN each block. This test turns each
// DETERMINISTIC intra-axis order into a STANDING CI invariant by constructing states
// that trip TWO guards AT ONCE and asserting WHICH message wins — the EARLIER guard,
// since verify's first Fatalf Goexits the capture goroutine before any later guard
// runs.
//
// DETERMINISM NOTE (load-bearing): within ONE block verify now walks the keys in
// SORTED order and SPLITS the two per-name checks into two sequential sorted passes —
// FOREIGN-membership for every key FIRST, then the n != 1 count check. So when a
// FOREIGN cell and a (distinct) DOUBLED cell are BOTH present, the foreign guard ALWAYS
// fires first, deterministically and independent of map-iteration order. That
// foreign-before-double adjacency is now itself a pinned invariant (see
// TestFoldCompletenessTracker_VerifyForeignBeforeDoubleDeterministic, the
// two-guards-at-once sibling that drives the tracker directly for both axes). Also
// deterministic is that the ENTIRE per-name loop (foreign OR double, whichever key it
// hits) precedes the POST-loop LENGTH check. This test pins the FIVE intra/inter-block
// adjacencies below, each a per-name-loop guard BEFORE a post-loop LENGTH guard (or a
// whole-reach-block-before-first-assert-guard boundary).
//
// The FIVE deterministic two-guards-at-once pairs, each with a later-guard LIVENESS
// CONTROL (a state tripping ONLY the later guard fires the later message), so no
// precedence assertion passes vacuously by the later guard simply never firing:
//
//	reach block (a):
//	  A1  reach-foreign        BEFORE reach-LENGTH    (foreign + missing co-fire)
//	  A2  reach-double-visit   BEFORE reach-LENGTH    (double  + missing co-fire)
//	assert block (a'):
//	  A3  assert-foreign       BEFORE assert-LENGTH   (foreign + never-asserted co-fire)
//	  A4  assert-double-assert BEFORE assert-LENGTH   (double  + never-asserted co-fire)
//	block boundary:
//	  A5  reach-LENGTH         BEFORE assert-foreign  (the WHOLE reach block precedes the
//	      FIRST assert-block guard — a finer boundary than orch83's reach-LENGTH-before-
//	      assert-LENGTH, since assert-foreign is the assert block's earliest guard)
//
// A1+A2 pin both reach per-name guards ahead of reach-LENGTH; A3+A4 pin both assert
// per-name guards ahead of assert-LENGTH; A5 pins the reach block whole ahead of the
// assert block's first guard. Together with orch83's cross-axis pins this closes the
// remaining DETERMINISTIC attribution surface in verify's guard order.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet,
// no RefImpl — hermetic) through the orch78 fatal-capture harness
// (runVerifyExpectingFatal), reusing newFoldCompletenessTracker/enter/markAsserted
// and the canonical reasonMatrixCellNames(). Additive and test-only: it modifies no
// production code (refimpl.go untouched), weakens no existing assertion, and adds no
// dependency. Synthetic fixtures only (D50).
func TestFoldCompletenessTracker_VerifyGuardIntraAxisPrecedence(t *testing.T) {
	canonical := reasonMatrixCellNames(t, reasonMatrixCells())
	if len(canonical) < 2 {
		t.Fatalf("the canonical reason matrix has %d cells; this intra-axis precedence meta-test needs >= 2 (one cell short on one guard, a DIFFERENT cell short on another within the same block) to be meaningful", len(canonical))
	}

	// Deterministic cell choice (lexicographic) so every pairing is reproducible
	// regardless of map iteration order.
	names := make([]string, 0, len(canonical))
	for name := range canonical {
		names = append(names, name)
	}
	sort.Strings(names)

	// Substrings that uniquely identify each guard's diagnostic in verify, lifted
	// verbatim from the Fatalf messages so a wording change there forces this test to
	// be revisited rather than silently passing on a stale substring.
	const (
		reachForeignSubstr  = "exercised FOREIGN cell"                    // (a) reach-foreign (per-name loop)
		reachDoubleSubstr   = "was exercised"                             // (a) reach per-name double-visit (per-name loop)
		reachLengthSubstr   = "SKIPPED cells"                             // (a) reach-LENGTH (post-loop)
		assertForeignSubstr = "asserted FOREIGN cell"                     // (a') assert-foreign (per-name loop)
		assertDoubleSubstr  = "recorded its assert-fired marker"          // (a') assert per-name double-assert (per-name loop)
		assertLengthSubstr  = "fired their agreement/invariant assertion" // (a') assert-LENGTH (post-loop)
	)

	// A FOREIGN cell name guaranteed ABSENT from the canonical set, reused by the pairs
	// that need an off-matrix marker. A fixed sentinel plus a membership re-check keeps
	// it deterministic and proof against any future canonical name colliding with it.
	foreignCell := "__off_canonical_intraaxis_precedence_cell__"
	for {
		if _, clash := canonical[foreignCell]; !clash {
			break
		}
		foreignCell += "_x" // vanishingly unlikely; keep extending until disjoint
	}

	// ---- PAIR A1: reach-foreign wins over reach-LENGTH -----------------------------
	//
	// Pins that the reach per-name FOREIGN-membership branch (inside the exercised loop)
	// runs BEFORE the post-loop reach-LENGTH check — the named reach "foreign+missing"
	// pairing. Construct a state that trips BOTH: enter() the off-canonical foreignCell
	// (so the reach foreign branch would fire) AND SKIP one canonical cell (so the reach
	// distinct-count is short by one and reach-LENGTH would fire "SKIPPED cells"). The
	// foreign cell is NEVER markAsserted (so no assert-axis guard pre-empts). Because the
	// per-name exercised loop runs to completion (or to its first Fatalf) BEFORE the
	// length check, the foreign message must win and "SKIPPED cells" must NOT appear.
	{
		skipped := names[0] // never reached — reach-LENGTH would fire
		bad := newFoldCompletenessTracker()
		for _, name := range names {
			if name == skipped {
				continue // DELIBERATE: reach set short by one — reach-LENGTH co-trips
			}
			done := bad.enter(name)
			done()
			bad.markAsserted(name)
		}
		df := bad.enter(foreignCell) // DELIBERATE: an off-canonical REACH visit
		df()
		// foreignCell is NOT markAsserted — pure reach-axis pairing.
		const label = "intra-precedence-reach-foreign-before-length"
		got := runVerifyExpectingFatal(bad, label, canonical, len(canonical))
		if !got.fired {
			t.Fatalf("two-guards-at-once state (reach-foreign %q, reach short by %q) did NOT trip verify at all — the intra-reach precedence pin cannot observe an order", foreignCell, skipped)
		}
		if !strings.Contains(got.msg, reachForeignSubstr) {
			t.Fatalf("INTRA-AXIS PRECEDENCE VIOLATED: with BOTH the reach-foreign and reach-LENGTH guards tripped, verify did NOT fire the reach-foreign %q message FIRST — the documented order (the reach per-name loop before reach-LENGTH) is broken, which would silently make a future reach branch-pin's attribution unsound. captured: %q", reachForeignSubstr, got.msg)
		}
		if strings.Contains(got.msg, reachLengthSubstr) {
			t.Fatalf("INTRA-AXIS PRECEDENCE VIOLATED: verify fired the LATER reach-LENGTH %q message while the EARLIER reach-foreign guard was also tripped — the reach per-name loop no longer precedes reach-LENGTH. captured: %q", reachLengthSubstr, got.msg)
		}
		if !strings.Contains(got.msg, label) {
			t.Fatalf("the intra-axis precedence bite fired but did not carry its label %q (self-locating failure broken). captured: %q", label, got.msg)
		}

		// LATER-GUARD LIVENESS CONTROL: the SAME reach-short shape WITHOUT the foreign
		// reach visit leaves ONLY reach-LENGTH short — so verify must now fire "SKIPPED
		// cells". Proves A1's assertion is not vacuous.
		ctrl := newFoldCompletenessTracker()
		for _, name := range names {
			if name == skipped {
				continue // reach set still short by one
			}
			done := ctrl.enter(name)
			done()
			ctrl.markAsserted(name)
		}
		ctrlGot := runVerifyExpectingFatal(ctrl, "intra-precedence-reach-foreign-before-length-later-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("later-guard liveness control did NOT fire: with no foreign reach visit and the reach set short by %q, the reach-LENGTH guard must bite — if it never fires, A1's precedence assertion is vacuous", skipped)
		}
		if !strings.Contains(ctrlGot.msg, reachLengthSubstr) {
			t.Fatalf("later-guard liveness control fired, but NOT via the reach-LENGTH %q branch — the later guard of A1 is not reach-LENGTH, so the precedence pin is comparing the wrong pair. captured: %q", reachLengthSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, reachForeignSubstr) {
			t.Fatalf("later-guard liveness control fired the reach-foreign message though no foreign cell was reached — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}

	// ---- PAIR A2: reach per-name double-visit wins over reach-LENGTH ----------------
	//
	// Pins that the reach per-name DOUBLE-VISIT branch (inside the exercised loop) runs
	// BEFORE the post-loop reach-LENGTH check — the named reach "double+missing" pairing.
	// A double-visit alone does NOT shorten the distinct-cell count, so to co-trip
	// reach-LENGTH the state ALSO SKIPS a different cell: skipping one canonical and
	// double-visiting another leaves the distinct-cell count short by one (reach-LENGTH
	// would fire) while the doubled cell carries reach-count 2 (the per-name double-visit
	// branch would fire). The per-name loop precedes the post-loop length check, so the
	// double-visit message must win and "SKIPPED cells" must NOT appear. (Needs >= 2
	// cells: one skipped, a DIFFERENT one doubled — guaranteed by the floor check above.)
	{
		skipped := names[0] // never reached — reach-LENGTH would fire
		doubled := names[1] // reached twice — reach double-visit would fire
		bad := newFoldCompletenessTracker()
		for _, name := range names {
			if name == skipped {
				continue // DELIBERATE: reach set short by one — reach-LENGTH co-trips
			}
			done := bad.enter(name)
			done()
			bad.markAsserted(name)
		}
		doneDup := bad.enter(doubled) // DELIBERATE: a SECOND reach visit (count 2)
		doneDup()
		const label = "intra-precedence-reach-double-before-length"
		got := runVerifyExpectingFatal(bad, label, canonical, len(canonical))
		if !got.fired {
			t.Fatalf("two-guards-at-once state (reach-double %q, reach short by %q) did NOT trip verify at all — the intra-reach precedence pin cannot observe an order", doubled, skipped)
		}
		if !strings.Contains(got.msg, reachDoubleSubstr) {
			t.Fatalf("INTRA-AXIS PRECEDENCE VIOLATED: with BOTH the reach-double-visit and reach-LENGTH guards tripped, verify did NOT fire the reach-double-visit %q message FIRST — the documented order (the reach per-name loop before reach-LENGTH) is broken, which would silently make the reach-double-visit branch-pin's attribution unsound. captured: %q", reachDoubleSubstr, got.msg)
		}
		if strings.Contains(got.msg, reachLengthSubstr) {
			t.Fatalf("INTRA-AXIS PRECEDENCE VIOLATED: verify fired the LATER reach-LENGTH %q message while the EARLIER reach-double-visit guard was also tripped — the reach per-name loop no longer precedes reach-LENGTH. captured: %q", reachLengthSubstr, got.msg)
		}
		if !strings.Contains(got.msg, label) {
			t.Fatalf("the intra-axis precedence bite fired but did not carry its label %q (self-locating failure broken). captured: %q", label, got.msg)
		}

		// LATER-GUARD LIVENESS CONTROL: the SAME reach-short shape but with doubled
		// entered ONCE (closing the double-visit shortfall) leaves ONLY reach-LENGTH short —
		// so verify must now fire "SKIPPED cells". Proves A2 is not vacuous.
		ctrl := newFoldCompletenessTracker()
		for _, name := range names {
			if name == skipped {
				continue // reach set still short by one
			}
			done := ctrl.enter(name) // every reached cell entered exactly once — no double-visit
			done()
			ctrl.markAsserted(name)
		}
		ctrlGot := runVerifyExpectingFatal(ctrl, "intra-precedence-reach-double-before-length-later-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("later-guard liveness control did NOT fire: with no double-visit and the reach set short by %q, the reach-LENGTH guard must bite — if it never fires, A2's precedence assertion is vacuous", skipped)
		}
		if !strings.Contains(ctrlGot.msg, reachLengthSubstr) {
			t.Fatalf("later-guard liveness control fired, but NOT via the reach-LENGTH %q branch — the later guard of A2 is not reach-LENGTH, so the precedence pin is comparing the wrong pair. captured: %q", reachLengthSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, reachDoubleSubstr) {
			t.Fatalf("later-guard liveness control fired the reach double-visit message though every reached cell was entered once — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}

	// ---- PAIR A3: assert-foreign wins over assert-LENGTH ----------------------------
	//
	// Pins that the assert per-name FOREIGN-membership branch (inside the asserted loop)
	// runs BEFORE the post-loop assert-LENGTH check — the named assert
	// "foreign+never-asserted" pairing. The reach set is kept COMPLETE and CLEAN (every
	// canonical cell reached exactly once, no foreign reach visit) so the entire reach
	// block passes and the bite is forced into the assert block. markAsserted then trips
	// BOTH assert guards: markAsserted the off-canonical foreignCell (the assert foreign
	// branch would fire) while leaving one canonical cell NEVER asserted (so the
	// distinct-asserted count is short by one and assert-LENGTH would fire). The per-name
	// asserted loop precedes the post-loop assert-LENGTH check, so the foreign message
	// must win and "fired their agreement/invariant assertion" must NOT appear.
	{
		neverAsserted := names[0] // its assert never fires — assert-LENGTH would fire
		bad := newFoldCompletenessTracker()
		for _, name := range names {
			done := bad.enter(name) // reach stays complete + clean
			done()
			if name == neverAsserted {
				continue // DELIBERATE: assert set short by one — assert-LENGTH co-trips
			}
			bad.markAsserted(name)
		}
		bad.markAsserted(foreignCell) // DELIBERATE: an off-canonical assert
		const label = "intra-precedence-assert-foreign-before-length"
		got := runVerifyExpectingFatal(bad, label, canonical, len(canonical))
		if !got.fired {
			t.Fatalf("two-guards-at-once state (assert-foreign %q, assert short by %q) did NOT trip verify at all — the intra-assert precedence pin cannot observe an order", foreignCell, neverAsserted)
		}
		if !strings.Contains(got.msg, assertForeignSubstr) {
			t.Fatalf("INTRA-AXIS PRECEDENCE VIOLATED: with BOTH the assert-foreign and assert-LENGTH guards tripped, verify did NOT fire the assert-foreign %q message FIRST — the documented order (the assert per-name loop before assert-LENGTH) is broken, which would silently make a future assert branch-pin's attribution unsound. captured: %q", assertForeignSubstr, got.msg)
		}
		if strings.Contains(got.msg, assertLengthSubstr) {
			t.Fatalf("INTRA-AXIS PRECEDENCE VIOLATED: verify fired the LATER assert-LENGTH %q message while the EARLIER assert-foreign guard was also tripped — the assert per-name loop no longer precedes assert-LENGTH. captured: %q", assertLengthSubstr, got.msg)
		}
		if !strings.Contains(got.msg, label) {
			t.Fatalf("the intra-axis precedence bite fired but did not carry its label %q (self-locating failure broken). captured: %q", label, got.msg)
		}

		// LATER-GUARD LIVENESS CONTROL: the SAME assert-short shape WITHOUT the foreign
		// assert leaves ONLY assert-LENGTH short — so verify must now fire "fired their
		// agreement/invariant assertion". Proves A3 is not vacuous.
		ctrl := newFoldCompletenessTracker()
		for _, name := range names {
			done := ctrl.enter(name)
			done()
			if name == neverAsserted {
				continue // assert set still short by one
			}
			ctrl.markAsserted(name) // only canonical cells assert — no foreign assert
		}
		ctrlGot := runVerifyExpectingFatal(ctrl, "intra-precedence-assert-foreign-before-length-later-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("later-guard liveness control did NOT fire: with no foreign assert and the assert set short by %q, the assert-LENGTH guard must bite — if it never fires, A3's precedence assertion is vacuous", neverAsserted)
		}
		if !strings.Contains(ctrlGot.msg, assertLengthSubstr) {
			t.Fatalf("later-guard liveness control fired, but NOT via the assert-LENGTH %q branch — the later guard of A3 is not assert-LENGTH, so the precedence pin is comparing the wrong pair. captured: %q", assertLengthSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, assertForeignSubstr) {
			t.Fatalf("later-guard liveness control fired the assert-foreign message though no foreign cell was asserted — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}

	// ---- PAIR A4: assert per-name double-assert wins over assert-LENGTH -------------
	//
	// Pins that the assert per-name DOUBLE-ASSERT branch (inside the asserted loop) runs
	// BEFORE the post-loop assert-LENGTH check — the named assert "double+never-asserted"
	// pairing. Reach stays complete + clean. A double-assert alone does NOT shorten the
	// distinct-asserted count, so to co-trip assert-LENGTH the state ALSO leaves one cell
	// NEVER asserted: skipping one cell's markAsserted and double-asserting another leaves
	// the distinct-asserted count short by one (assert-LENGTH would fire) while the doubled
	// cell carries assert-count 2 (the per-name double-assert branch would fire). The
	// per-name asserted loop precedes the post-loop assert-LENGTH check, so the
	// double-assert message must win and "fired their agreement/invariant assertion" must
	// NOT appear.
	{
		neverAsserted := names[0] // its assert never fires — assert-LENGTH would fire
		doubled := names[1]       // asserted twice — assert double-assert would fire
		bad := newFoldCompletenessTracker()
		for _, name := range names {
			done := bad.enter(name) // reach stays complete + clean
			done()
			if name == neverAsserted {
				continue // DELIBERATE: assert set short by one — assert-LENGTH co-trips
			}
			bad.markAsserted(name)
		}
		bad.markAsserted(doubled) // DELIBERATE: a SECOND assert (count 2)
		const label = "intra-precedence-assert-double-before-length"
		got := runVerifyExpectingFatal(bad, label, canonical, len(canonical))
		if !got.fired {
			t.Fatalf("two-guards-at-once state (assert-double %q, assert short by %q) did NOT trip verify at all — the intra-assert precedence pin cannot observe an order", doubled, neverAsserted)
		}
		if !strings.Contains(got.msg, assertDoubleSubstr) {
			t.Fatalf("INTRA-AXIS PRECEDENCE VIOLATED: with BOTH the assert-double and assert-LENGTH guards tripped, verify did NOT fire the assert-double %q message FIRST — the documented order (the assert per-name loop before assert-LENGTH) is broken, which would silently make the assert-double branch-pin's attribution unsound. captured: %q", assertDoubleSubstr, got.msg)
		}
		if strings.Contains(got.msg, assertLengthSubstr) {
			t.Fatalf("INTRA-AXIS PRECEDENCE VIOLATED: verify fired the LATER assert-LENGTH %q message while the EARLIER assert-double guard was also tripped — the assert per-name loop no longer precedes assert-LENGTH. captured: %q", assertLengthSubstr, got.msg)
		}
		if !strings.Contains(got.msg, label) {
			t.Fatalf("the intra-axis precedence bite fired but did not carry its label %q (self-locating failure broken). captured: %q", label, got.msg)
		}

		// LATER-GUARD LIVENESS CONTROL: the SAME assert-short shape but with doubled
		// asserted ONCE (closing the double-assert shortfall) leaves ONLY assert-LENGTH
		// short — so verify must now fire "fired their agreement/invariant assertion".
		// Proves A4 is not vacuous.
		ctrl := newFoldCompletenessTracker()
		for _, name := range names {
			done := ctrl.enter(name)
			done()
			if name == neverAsserted {
				continue // assert set still short by one
			}
			ctrl.markAsserted(name) // every other cell asserts exactly once — no double-assert
		}
		ctrlGot := runVerifyExpectingFatal(ctrl, "intra-precedence-assert-double-before-length-later-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("later-guard liveness control did NOT fire: with no double-assert and the assert set short by %q, the assert-LENGTH guard must bite — if it never fires, A4's precedence assertion is vacuous", neverAsserted)
		}
		if !strings.Contains(ctrlGot.msg, assertLengthSubstr) {
			t.Fatalf("later-guard liveness control fired, but NOT via the assert-LENGTH %q branch — the later guard of A4 is not assert-LENGTH, so the precedence pin is comparing the wrong pair. captured: %q", assertLengthSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, assertDoubleSubstr) {
			t.Fatalf("later-guard liveness control fired the assert double-assert message though every asserted cell asserted once — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}

	// ---- PAIR A5: reach-LENGTH wins over assert-foreign (block boundary) ------------
	//
	// Pins the FINER block-boundary adjacency the orch83 cross-axis sibling did not: the
	// WHOLE reach block (its per-name loop AND its post-loop LENGTH check) precedes the
	// FIRST guard of the assert block (assert-foreign), not merely the assert-LENGTH check
	// orch83 pinned. Construct a state short on the reach axis (one cell never enter()'d,
	// so reach-LENGTH would fire "SKIPPED cells") AND carrying an off-canonical assert (so
	// the assert-foreign membership branch would fire). Because the entire reach block is
	// evaluated before the assert loop, the reach-LENGTH message must win and "asserted
	// FOREIGN cell" must NOT appear. This guarantees a future reach-LENGTH attribution
	// cannot be silently captured by the assert-foreign branch if a refactor hoisted the
	// assert block ahead of the reach length check.
	{
		skipped := names[0] // never reached — reach-LENGTH would fire
		bad := newFoldCompletenessTracker()
		for _, name := range names {
			if name == skipped {
				continue // DELIBERATE: reach set short by one — reach-LENGTH co-trips
			}
			done := bad.enter(name)
			done()
			bad.markAsserted(name)
		}
		bad.markAsserted(foreignCell) // DELIBERATE: an off-canonical assert — assert-foreign would fire
		const label = "intra-precedence-reach-length-before-assert-foreign"
		got := runVerifyExpectingFatal(bad, label, canonical, len(canonical))
		if !got.fired {
			t.Fatalf("two-guards-at-once state (reach short by %q, assert-foreign %q) did NOT trip verify at all — the block-boundary precedence pin cannot observe an order", skipped, foreignCell)
		}
		if !strings.Contains(got.msg, reachLengthSubstr) {
			t.Fatalf("BLOCK-BOUNDARY PRECEDENCE VIOLATED: with BOTH the reach-LENGTH and assert-foreign guards tripped, verify did NOT fire the reach-LENGTH %q message FIRST — the documented order (the whole reach block before the assert block) is broken. captured: %q", reachLengthSubstr, got.msg)
		}
		if strings.Contains(got.msg, assertForeignSubstr) {
			t.Fatalf("BLOCK-BOUNDARY PRECEDENCE VIOLATED: verify fired the LATER assert-foreign %q message while the EARLIER reach-LENGTH guard was also tripped — the reach block no longer precedes the assert block. captured: %q", assertForeignSubstr, got.msg)
		}
		if !strings.Contains(got.msg, label) {
			t.Fatalf("the block-boundary precedence bite fired but did not carry its label %q (self-locating failure broken). captured: %q", label, got.msg)
		}

		// LATER-GUARD LIVENESS CONTROL: the SAME shape with the reach set COMPLETE
		// (skipped now reached) closes the reach-LENGTH shortfall, leaving ONLY the
		// off-canonical assert — so verify must now fire "asserted FOREIGN cell". Proves
		// A5 is not vacuous (the assert-foreign guard does fire once the reach block is
		// satisfied).
		ctrl := newFoldCompletenessTracker()
		for _, name := range names {
			done := ctrl.enter(name) // EVERY cell reached now — reach block complete
			done()
			ctrl.markAsserted(name)
		}
		ctrl.markAsserted(foreignCell) // off-canonical assert retained
		ctrlGot := runVerifyExpectingFatal(ctrl, "intra-precedence-reach-length-before-assert-foreign-later-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("later-guard liveness control did NOT fire: with the reach block complete and an off-canonical assert (%q), the assert-foreign guard must bite — if it never fires, A5's precedence assertion is vacuous", foreignCell)
		}
		if !strings.Contains(ctrlGot.msg, assertForeignSubstr) {
			t.Fatalf("later-guard liveness control fired, but NOT via the assert-foreign %q branch — the later guard of A5 is not assert-foreign, so the precedence pin is comparing the wrong pair. captured: %q", assertForeignSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, reachLengthSubstr) {
			t.Fatalf("later-guard liveness control fired the reach-LENGTH message though the reach block is complete — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}
}

// TestFoldCompletenessTracker_VerifyForeignBeforeDoubleDeterministic PERMANENTLY pins
// the LAST map-order-dependent adjacency in foldCompletenessTracker.verify: within a
// single name-set block, when a FOREIGN cell (off the canonical set) and a separately
// DOUBLED cell (entered/asserted twice) are BOTH present as DISTINCT keys, the foreign
// guard must fire FIRST. Before orch86 the two checks shared one
// `for name, n := range ft.<map>` loop, so which Fatalf won was governed by Go's
// RANDOMIZED map iteration — orch84/orch85 correctly DECLINED to pin it (a flaky pin).
// verify now walks the keys in SORTED order and SPLITS the two checks into two
// sequential passes (FOREIGN-membership for every key, THEN n != 1), so foreign always
// precedes double deterministically and independent of map order. This test turns that
// new guarantee into a STANDING CI invariant for BOTH the reach (a) and assert (a')
// axes.
//
// ADVERSARIAL NAME CHOICE (load-bearing): the DOUBLED cell is a CANONICAL name and the
// FOREIGN cell is an off-canonical sentinel chosen to sort lexicographically BEFORE
// every canonical name (a leading "!" — the smallest printable ASCII, below digits and
// letters). If verify merely sorted keys and kept the per-key {foreign, count} order,
// the foreign cell — sorting first — would still win here and the test would pass for
// the WRONG reason. To make this test prove the SPLIT-PASS design (foreign-pass before
// count-pass, not lexicographic luck), each axis is exercised TWICE: once with the
// foreign name sorting BEFORE the doubled name, and once with a foreign name
// (a trailing "~" — the largest printable ASCII, above letters) sorting AFTER it. The
// foreign guard must win in BOTH orderings; the second case can only pass if the
// foreign pass runs to completion before the count pass begins.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet, no
// RefImpl — hermetic) through the orch78 fatal-capture harness
// (runVerifyExpectingFatal), reusing newFoldCompletenessTracker/enter/markAsserted and
// the canonical reasonMatrixCellNames(). A double-guard LIVENESS CONTROL per axis (the
// SAME state with the foreign cell removed) proves the double guard is individually
// live, so the foreign-wins assertion is not vacuous. Additive and test-only: it
// modifies no production code (refimpl.go untouched), weakens no existing assertion,
// and adds no dependency. Synthetic fixtures only (D50).
func TestFoldCompletenessTracker_VerifyForeignBeforeDoubleDeterministic(t *testing.T) {
	canonical := reasonMatrixCellNames(t, reasonMatrixCells())
	if len(canonical) < 2 {
		t.Fatalf("the canonical reason matrix has %d cells; this foreign-before-double pin needs >= 2 (one doubled cell plus at least one other to keep the set complete) to be meaningful", len(canonical))
	}

	// Canonical names in sorted order; the doubled cell is canonical so the name-set
	// stays COMPLETE (every canonical cell reached/asserted exactly once except the one
	// we double), forcing the bite into the per-name foreign/count checks rather than a
	// LENGTH guard.
	names := make([]string, 0, len(canonical))
	for name := range canonical {
		names = append(names, name)
	}
	sort.Strings(names)
	doubled := names[0] // a canonical cell visited/asserted twice — the n != 1 guard

	// Two FOREIGN sentinels, both guaranteed off-canonical, chosen to BRACKET the
	// canonical names in sort order: foreignLow sorts BEFORE every canonical name (so it
	// would win on lexicographic order alone — the trap), foreignHigh sorts AFTER every
	// canonical name (so it can ONLY win if the FOREIGN pass precedes the COUNT pass).
	foreignLow := "!__off_canonical_foreign_before_double_low__"
	for {
		if _, clash := canonical[foreignLow]; !clash {
			break
		}
		foreignLow = "!" + foreignLow // keep it sorting first while disjoint
	}
	foreignHigh := "~__off_canonical_foreign_before_double_high__"
	for {
		if _, clash := canonical[foreignHigh]; !clash {
			break
		}
		foreignHigh += "~" // keep it sorting last while disjoint
	}

	const (
		reachForeignSubstr  = "exercised FOREIGN cell"           // (a) reach-foreign — must WIN
		reachDoubleSubstr   = "was exercised"                    // (a) reach double-visit — must be SUPPRESSED
		assertForeignSubstr = "asserted FOREIGN cell"            // (a') assert-foreign — must WIN
		assertDoubleSubstr  = "recorded its assert-fired marker" // (a') assert double-assert — must be SUPPRESSED
	)

	// reachCase drives the reach (a) axis: every canonical cell entered once (the set
	// stays complete), `doubled` entered a SECOND time (reach double-visit would fire),
	// and `foreign` entered once (reach-foreign would fire). Both per-name guards are
	// tripped at once; the foreign guard must win.
	reachCase := func(foreign string) *fatalCapture {
		bad := newFoldCompletenessTracker()
		for _, name := range names {
			done := bad.enter(name)
			done()
			bad.markAsserted(name) // keep the assert axis CLEAN so the bite is on reach
		}
		dd := bad.enter(doubled) // DELIBERATE: second reach visit — count 2
		dd()
		df := bad.enter(foreign) // DELIBERATE: off-canonical reach visit — foreign would fire
		df()
		// foreign is NOT markAsserted (keeps the assert axis clean); settledAtReturn ==
		// len(canonical) and maxInFly <= 1 keep the (b) serial pins green, so only the
		// reach per-name foreign/count guards can bite.
		return runVerifyExpectingFatal(bad, "foreign-before-double-reach", canonical, len(canonical))
	}

	// assertCase drives the assert (a') axis: reach stays complete + clean, every cell
	// asserted once, `doubled` asserted a SECOND time (assert double-assert would fire),
	// and `foreign` asserted once (assert-foreign would fire). The foreign guard must win.
	assertCase := func(foreign string) *fatalCapture {
		bad := newFoldCompletenessTracker()
		for _, name := range names {
			done := bad.enter(name) // reach stays complete + clean
			done()
			bad.markAsserted(name)
		}
		bad.markAsserted(doubled) // DELIBERATE: second assert — count 2
		bad.markAsserted(foreign) // DELIBERATE: off-canonical assert — foreign would fire
		return runVerifyExpectingFatal(bad, "foreign-before-double-assert", canonical, len(canonical))
	}

	// ---- REACH AXIS: foreign wins over double, in BOTH sort orderings -----------------
	for _, tc := range []struct {
		name    string
		foreign string
	}{
		{"foreign-sorts-before-doubled", foreignLow},
		{"foreign-sorts-after-doubled", foreignHigh},
	} {
		got := reachCase(tc.foreign)
		if !got.fired {
			t.Fatalf("reach two-guards-at-once state (%s: foreign %q + doubled %q) did NOT trip verify at all — the foreign-before-double pin cannot observe an order", tc.name, tc.foreign, doubled)
		}
		if !strings.Contains(got.msg, reachForeignSubstr) {
			t.Fatalf("FOREIGN-BEFORE-DOUBLE VIOLATED (reach, %s): with BOTH the reach-foreign (%q) and reach-double-visit (%q) guards tripped, verify did NOT fire the reach-foreign message FIRST — the foreign pass must precede the count pass in the exercised loop regardless of key sort order. captured: %q", tc.name, tc.foreign, doubled, got.msg)
		}
		if strings.Contains(got.msg, reachDoubleSubstr) {
			t.Fatalf("FOREIGN-BEFORE-DOUBLE VIOLATED (reach, %s): verify fired the reach-double-visit %q message while the foreign guard was also tripped — foreign no longer wins over double in the exercised loop. captured: %q", tc.name, reachDoubleSubstr, got.msg)
		}
	}

	// DOUBLE-GUARD LIVENESS CONTROL (reach): the SAME complete state with `doubled`
	// entered twice but NO foreign cell — only the reach double-visit guard is tripped,
	// so verify must fire "was exercised". Proves the foreign-wins assertion above is
	// not vacuous (the double guard is individually live; foreign genuinely PRE-EMPTS it).
	{
		ctrl := newFoldCompletenessTracker()
		for _, name := range names {
			done := ctrl.enter(name)
			done()
			ctrl.markAsserted(name)
		}
		dd := ctrl.enter(doubled) // second visit, no foreign cell
		dd()
		ctrlGot := runVerifyExpectingFatal(ctrl, "foreign-before-double-reach-double-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("reach double-guard liveness control did NOT fire: with %q entered twice and no foreign cell, the reach double-visit guard must bite — if it never fires, the foreign-wins assertion is vacuous", doubled)
		}
		if !strings.Contains(ctrlGot.msg, reachDoubleSubstr) {
			t.Fatalf("reach double-guard liveness control fired, but NOT via the reach double-visit %q branch — the suppressed guard is not the one being pinned. captured: %q", reachDoubleSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, reachForeignSubstr) {
			t.Fatalf("reach double-guard liveness control fired the reach-foreign message though no foreign cell was reached — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}

	// ---- ASSERT AXIS: foreign wins over double, in BOTH sort orderings ----------------
	for _, tc := range []struct {
		name    string
		foreign string
	}{
		{"foreign-sorts-before-doubled", foreignLow},
		{"foreign-sorts-after-doubled", foreignHigh},
	} {
		got := assertCase(tc.foreign)
		if !got.fired {
			t.Fatalf("assert two-guards-at-once state (%s: foreign %q + doubled %q) did NOT trip verify at all — the foreign-before-double pin cannot observe an order", tc.name, tc.foreign, doubled)
		}
		if !strings.Contains(got.msg, assertForeignSubstr) {
			t.Fatalf("FOREIGN-BEFORE-DOUBLE VIOLATED (assert, %s): with BOTH the assert-foreign (%q) and assert-double (%q) guards tripped, verify did NOT fire the assert-foreign message FIRST — the foreign pass must precede the count pass in the asserted loop regardless of key sort order. captured: %q", tc.name, tc.foreign, doubled, got.msg)
		}
		if strings.Contains(got.msg, assertDoubleSubstr) {
			t.Fatalf("FOREIGN-BEFORE-DOUBLE VIOLATED (assert, %s): verify fired the assert-double %q message while the foreign guard was also tripped — foreign no longer wins over double in the asserted loop. captured: %q", tc.name, assertDoubleSubstr, got.msg)
		}
	}

	// DOUBLE-GUARD LIVENESS CONTROL (assert): the SAME complete state with `doubled`
	// asserted twice but NO foreign assert — only the assert double-assert guard is
	// tripped, so verify must fire "recorded its assert-fired marker". Proves the
	// assert foreign-wins assertion is not vacuous.
	{
		ctrl := newFoldCompletenessTracker()
		for _, name := range names {
			done := ctrl.enter(name)
			done()
			ctrl.markAsserted(name)
		}
		ctrl.markAsserted(doubled) // second assert, no foreign assert
		ctrlGot := runVerifyExpectingFatal(ctrl, "foreign-before-double-assert-double-liveness", canonical, len(canonical))
		if !ctrlGot.fired {
			t.Fatalf("assert double-guard liveness control did NOT fire: with %q asserted twice and no foreign assert, the assert double-assert guard must bite — if it never fires, the foreign-wins assertion is vacuous", doubled)
		}
		if !strings.Contains(ctrlGot.msg, assertDoubleSubstr) {
			t.Fatalf("assert double-guard liveness control fired, but NOT via the assert double-assert %q branch — the suppressed guard is not the one being pinned. captured: %q", assertDoubleSubstr, ctrlGot.msg)
		}
		if strings.Contains(ctrlGot.msg, assertForeignSubstr) {
			t.Fatalf("assert double-guard liveness control fired the assert-foreign message though no foreign cell was asserted — the control state is malformed. captured: %q", ctrlGot.msg)
		}
	}
}

// TestFoldCompletenessTracker_VerifyGuardPrecedenceTwoCellFloorFallback EXERCISES
// the len(canonical)<3 FALLBACK branch of Pair 3 in
// TestFoldCompletenessTracker_VerifyGuardPrecedence (the (b.2) maxInFly-vs-reach
// precedence pin). That sibling drives the LIVE reasonMatrixCellNames() set; with
// the live matrix at 13 cells, len(canonical)<3 is ALWAYS false there, so its
// 2-cell-floor fallback construction — overlap the only two cells to drive maxInFly
// to 2, then trip the reach axis via a FOREIGN cell (a reachable two-guards-at-once
// state when only two roles, not three, are available) — is DEAD against the live
// matrix and NEVER runs in CI. A future shrink of the reason matrix to exactly two
// cells would suddenly route Pair 3 through that fallback, and a latent break there
// (e.g. the foreign-reach guard reordered ahead of the (b.2) maxInFly serial pin)
// would go unnoticed because nothing exercises it today.
//
// This meta-test pins the fallback's precedence claim PERMANENTLY by driving the
// real foldCompletenessTracker.verify over a SYNTHETIC two-name canonical set built
// locally (a map[string]struct{} of two obviously-synthetic names — NOT
// reasonMatrixCellNames(), which is 13 cells), so len(canonical)==2 < 3 and the
// fallback's exact shape is ACTUALLY taken: overlap the only two cells (maxInFly ->
// 2, so the (b.2) serial guard would fire "ran concurrently") AND reach a FOREIGN
// cell (so the (a) reach-foreign guard would fire "exercised FOREIGN cell"). With
// BOTH the (b.2) serial guard and the reach-foreign guard tripped at once, the
// EARLIER guard must win — the (b.2) serial pin is checked before the reach loop in
// verify, so its "ran concurrently" message must appear and the later reach-foreign
// message must NOT. This is the SAME earlier-guard-wins precedence the live-matrix
// Pair 3 asserts (its >=3-cell path pins (b.2) maxInFly before reach-LENGTH; this
// 2-cell-floor path pins (b.2) maxInFly before reach-FOREIGN) — so a 2-cell shrink
// can no longer silently break the fallback while CI stays green.
//
// A LATER-GUARD LIVENESS CONTROL mirrors the Pair-3 structure's positive control:
// the SAME synthetic 2-cell state WITHOUT the overlap (both cells entered serially,
// maxInFly <= 1) but STILL reaching the foreign cell closes the (b.2) shortfall,
// leaving ONLY the reach-foreign guard — so verify must now fire "exercised FOREIGN
// cell". That proves the precedence assertion is not vacuous (the later guard is
// individually live and bites once the earlier serial pin is satisfied), not passing
// simply because the foreign-reach guard never fires.
//
// It drives the real foldCompletenessTracker DIRECTLY (no fold, no gRPC, no fleet,
// no RefImpl — hermetic) through the orch78 fatal-capture harness
// (runVerifyExpectingFatal), reusing newFoldCompletenessTracker/enter/markAsserted.
// The canonical set is SYNTHETIC and local by design (the whole point is to take the
// len(canonical)<3 branch the live 13-cell set cannot). Additive and test-only: it
// modifies no production code (refimpl.go untouched), weakens no existing assertion,
// and adds no dependency. Synthetic fixtures only (D50).
func TestFoldCompletenessTracker_VerifyGuardPrecedenceTwoCellFloorFallback(t *testing.T) {
	// SYNTHETIC 2-name canonical set, built locally — NOT reasonMatrixCellNames()
	// (which is the live 13-cell matrix). Two obviously-synthetic cell names so
	// len(canonical) == 2 < 3 and verify takes the same shape the Pair-3 fallback
	// guards against. These names never appear in the live reason matrix; they exist
	// only to make the 2-cell floor expressible in-tree.
	const (
		synthCellA = "cell-synthetic-twocellfloor-a"
		synthCellB = "cell-synthetic-twocellfloor-b"
	)
	canonical := map[string]struct{}{
		synthCellA: {},
		synthCellB: {},
	}
	if len(canonical) != 2 {
		t.Fatalf("the synthetic canonical set has %d names, want exactly 2 to exercise the len(canonical)<3 floor — the two synthetic names must be distinct", len(canonical))
	}

	// The FOREIGN cell that trips the reach axis — guaranteed off the synthetic
	// canonical set (and off the live matrix too, by its obviously-synthetic name).
	const foreign = "cell-synthetic-off-canonical-twocellfloor"
	if _, clash := canonical[foreign]; clash {
		t.Fatalf("the synthetic FOREIGN cell name %q is unexpectedly IN the synthetic canonical set — pick a name guaranteed off-canonical", foreign)
	}

	// Substrings lifted verbatim from verify's Fatalf messages so a wording change
	// there forces this test to be revisited rather than silently passing on a stale
	// substring — mirroring the Pair-3 sibling's constants.
	const (
		concurrentSubstr    = "ran concurrently"                    // (b.2) serial maxInFly — the EARLIER guard
		reachForeignSubstr  = "exercised FOREIGN cell"              // (a) reach-foreign — the LATER guard
		serialViolatedTitle = "serial-execution invariant VIOLATED" // shared (b.*) title
	)

	// (1) NEGATIVE — the 2-cell-floor two-guards-at-once state, byte-for-byte the
	// fallback's construction: overlap the only two cells (enter both with no done()
	// between, driving maxInFly to 2) and assert both, then reach a FOREIGN cell. Both
	// the (b.2) maxInFly serial guard and the (a) reach-foreign guard are now tripped.
	bad := newFoldCompletenessTracker()
	doneA := bad.enter(synthCellA)
	doneB := bad.enter(synthCellB) // overlap with NO done() between — maxInFly -> 2
	doneA()
	doneB()
	bad.markAsserted(synthCellA)
	bad.markAsserted(synthCellB)
	df := bad.enter(foreign) // reach-FOREIGN would fire
	df()

	// settledAtReturn == len(canonical) keeps the (b.1) synchronous-settle guard green,
	// so the ONLY two guards that can bite are (b.2) maxInFly and (a) reach-foreign —
	// and (b.2) is checked before the reach loop, so it must win.
	const label = "twocellfloor-maxinfly-before-reach-foreign"
	got := runVerifyExpectingFatal(bad, label, canonical, len(canonical))
	if !got.fired {
		t.Fatalf("two-guards-at-once state over the synthetic 2-cell floor (maxInFly=2 via %q/%q, reach-foreign %q) did NOT trip verify at all — the precedence pin cannot observe an order", synthCellA, synthCellB, foreign)
	}
	if !strings.Contains(got.msg, serialViolatedTitle) || !strings.Contains(got.msg, concurrentSubstr) {
		t.Fatalf("PRECEDENCE VIOLATED: over the 2-cell floor, with BOTH the (b.2) maxInFly and the reach-foreign guards tripped, verify did NOT fire the EARLIER (b.2) %q message FIRST — the documented order (serial pins before the reach axis) is broken in the len(canonical)<3 fallback. captured: %q", concurrentSubstr, got.msg)
	}
	if strings.Contains(got.msg, reachForeignSubstr) {
		t.Fatalf("PRECEDENCE VIOLATED: over the 2-cell floor, verify fired the LATER reach-foreign %q message while the EARLIER (b.2) maxInFly guard was also tripped — the serial pins no longer precede the reach axis in the fallback. captured: %q", reachForeignSubstr, got.msg)
	}
	if !strings.Contains(got.msg, label) {
		t.Fatalf("the precedence bite fired but did not carry its label %q (self-locating failure broken). captured: %q", label, got.msg)
	}

	// (2) LATER-GUARD LIVENESS CONTROL — the SAME synthetic 2-cell state but WITHOUT
	// the overlap (both canonical cells entered serially, maxInFly <= 1) while STILL
	// reaching the foreign cell. The (b.2) shortfall is closed, leaving ONLY the
	// reach-foreign guard — so verify must now fire "exercised FOREIGN cell". This
	// proves the fallback's precedence assertion is not vacuous: the later
	// reach-foreign guard is individually live and bites once the earlier serial pin is
	// satisfied. Mirrors the Pair-3 sibling's positive control.
	ctrl := newFoldCompletenessTracker()
	doneCA := ctrl.enter(synthCellA) // serial — released before the next enter()
	doneCA()
	doneCB := ctrl.enter(synthCellB) // serial — maxInFly stays <= 1
	doneCB()
	ctrl.markAsserted(synthCellA)
	ctrl.markAsserted(synthCellB)
	dfc := ctrl.enter(foreign) // reach-foreign still tripped
	dfc()
	ctrlGot := runVerifyExpectingFatal(ctrl, "twocellfloor-maxinfly-before-reach-foreign-later-liveness", canonical, len(canonical))
	if !ctrlGot.fired {
		t.Fatalf("later-guard liveness control did NOT fire: over the 2-cell floor with maxInFly <= 1 and a foreign cell %q reached, the reach-foreign guard must bite — if it never fires, the fallback's precedence assertion is vacuous", foreign)
	}
	if !strings.Contains(ctrlGot.msg, reachForeignSubstr) {
		t.Fatalf("later-guard liveness control fired, but NOT via the reach-foreign %q branch — the later guard of the 2-cell floor is not the reach-foreign check, so the precedence pin is comparing the wrong pair. captured: %q", reachForeignSubstr, ctrlGot.msg)
	}
	if strings.Contains(ctrlGot.msg, concurrentSubstr) {
		t.Fatalf("later-guard liveness control fired the (b.2) maxInFly message though every canonical cell was entered serially — the control state is malformed. captured: %q", ctrlGot.msg)
	}
}

// expiredGrantFleet is the honest-responder-side mirror of the past-TTL grant
// fleet RealDialerWithExpiredGrant() seeds the production RefImpl with: a LIVE
// session (testSessionExpiredGrant) whose github grant carries a past TTL
// (testExpiryPast <= testNow) on the DEDICATED expired-grant ref
// (testGrantRefExpiredGitHub, the byte-for-byte mirror of suite.go's
// synthGrantRefExpiredGitHub), so a FRESH token presented against it DENYs
// credential_expired on the grant-TTL freshness leg (HonestDecision step 4). The
// ref is never returned (the DENY carries no grant_ref), so naming it for the
// dedicated expired-grant record rather than the generic github ref is a
// consistency-only alignment with the production side — no behavior change. It is
// dedicated and self-contained — nothing from the standing fleet is
// present — so the expired-grant cell's honest-responder-side caller B (and each
// negative dialer rebuilt over it in the fold matrix) decides this ONE presentation
// through the shared HonestDecision core over exactly this fleet, mirroring the
// RefImpl side byte-for-byte. Synthetic fixtures only (D50).
func expiredGrantFleet() map[string]honestSession {
	return map[string]honestSession{
		testSessionExpiredGrant: {live: true, grants: map[string]honestGrant{
			testServiceGitHub: {ref: testGrantRefExpiredGitHub, expiry: testExpiryPast},
		}},
	}
}

// TestNegativeDialers_FoldInvariant_MatchRefImplExceptOneCell is the soundness
// proof for the orch64 fold: each negative dialer reuses the shared HonestDecision
// core for its UNDRIFTED legs (only one single-point hook — nonCascading's liveness
// override / driftedAllowAll's postDecision override — diverges), so the fold is
// sound IFF every dialer reproduces RefImpl's verdict on EVERY reason-matrix cell
// EXCEPT the exact cell(s) its one deliberate drift touches. This table pins that:
// it drives RefImpl and each negative dialer over reasonMatrixCells() (the one
// canonical cell set the honest agreement matrix also consumes) and asserts, per cell,
//
//   - in a NON-drift cell: the dialer's {verdict, reason, grant_ref, expiry} is
//     byte-identical to RefImpl's (the undrifted legs ride the shared core, so they
//     cannot have drifted) — this is what proves the fold preserved behavior;
//   - in a DRIFT cell: the dialer DIVERGES from RefImpl (the deliberate drift is
//     present and biting, not silently neutralized to green).
//
// The drift cells are declared per dialer and are exactly:
//
//   - nonCascadingFakeDialer: ONLY the two dead-root-over-LIVE-descendant cells
//     {dead-root-cascade, dead-root-cascade-distinct-revoked-root-over-live-desc} —
//     each a distinct KNOWN-dead-inherited-root / independently-LIVE-descendant
//     config, where the literalized req.root_session override drops the dead root so
//     the fake ALLOWs where RefImpl DENYs session_not_live. Pinning BOTH dead-root
//     configs proves the fold-invariant holds for the second config too and catches a
//     regression that special-cased the first fixture (or narrowed the cascade drift
//     to the one declared root). Every other cell (own-session liveness, freshness,
//     binding, grant-intersection, the cross-host/child legs) must match RefImpl —
//     INCLUDING the dead-root-over-DEAD-descendant cell, which is NON-drift here
//     because dropping the dead root still leaves a dead own session (the fake still
//     DENYs session_not_live, agreeing with RefImpl) — proving the literalization
//     narrowed the drift to exactly the inherited-root-key live-descendant-RESCUE
//     path and nothing else — INCLUDING the expired-grant cell, which is NON-drift
//     here: its FRESH token carries no inherited root to drop, so the fake rides the
//     shared core's grant-TTL leg untouched and DENYs credential_expired in agreement
//     with RefImpl over the past-TTL grant fleet;
//   - driftedAllowAllFakeDialer: EVERY cell — the blanket-ALLOW override discards
//     the honest verdict on every presentation, flipping each DENY cell to ALLOW
//     and re-stamping each ALLOW cell with a fabricated grant_ref/expiry, so it
//     diverges from RefImpl everywhere (its undrifted-leg set is empty by design),
//     the expired-grant cell included.
//
// The expired-grant cell carries an OPTIONAL pre-presentation fleet-setup hook
// (cellSetup): the standing seedFleet is all far-future, so its grant-TTL leg cannot
// be expressed against it. For that one cell this matrix dials the cell's past-TTL
// grant dialer (RealDialerWithExpiredGrant()) for the RefImpl baseline and rebuilds
// each negative dialer over the matching fleet, measuring both ends over the cell's
// dedicated fleet; every hookless cell rides the shared standing-fleet dialers
// exactly as before.
//
// Additive and test-only: it reuses the existing negative dialers and synthetic
// presentation builders, modifies no production code, and weakens no existing
// assertion. Synthetic fixtures only (D50).
func TestNegativeDialers_FoldInvariant_MatchRefImplExceptOneCell(t *testing.T) {
	ctx := context.Background()

	// RefImpl over the standing seedFleet — the honest baseline every cell is
	// measured against, reached through the real client so the baseline is the
	// actual production decision path.
	refConn, refStop, err := identityvalidate.RealDialer().Dial(ctx)
	if err != nil {
		t.Fatalf("dial RealDialer: %v", err)
	}
	defer refStop()
	refClient := identityv1.NewIdentityValidationServiceClient(refConn)

	cells := reasonMatrixCells()
	canonical := reasonMatrixCellNames(t, cells)

	// Each negative dialer plus the SET of cells its one deliberate drift touches.
	// A cell named here MUST diverge from RefImpl; every other cell MUST match.
	// dialerForFleet rebuilds the negative dialer over an arbitrary honest fleet so a
	// cell carrying the optional pre-presentation fleet-setup hook (expired-grant)
	// can drive the negative dialer over its dedicated past-TTL grant fleet rather
	// than the standing fleet; for a hookless cell the standing-fleet dialer field is
	// used as-is.
	negatives := []struct {
		name           string
		dialer         dualrun.Dialer
		dialerForFleet func(map[string]honestSession) dualrun.Dialer
		driftCells     map[string]bool
	}{
		{
			name:           "nonCascadingFakeDialer",
			dialer:         nonCascadingFakeDialer(),
			dialerForFleet: nonCascadingFakeDialerOverFleet,
			// The dropped-cascade drift bites on EVERY dead-inherited-root config:
			// both the first (dead-root-cascade) and the second, distinct
			// (dead-root-cascade-distinct-revoked-root-over-live-desc) dead-root
			// cells. On each, RefImpl DENYs session_not_live via the cascade while
			// this fake — which reports the inherited root as if unrecorded — drops
			// the cascade and falls through to the descendant's own (LIVE) session, so
			// it diverges from RefImpl. Pinning BOTH configs proves the fold-invariant
			// holds for the second dead-root shape too and catches a regression that
			// special-cased the first fixture's identifiers (or narrowed the cascade
			// drift to just the one declared root). Every other cell still must match
			// RefImpl — including the dead-root-over-dead-descendant cell, which is
			// DELIBERATELY a NON-drift cell here: dropping the dead inherited root still
			// leaves a dead OWN session, so the fake DENYs session_not_live and AGREES
			// with RefImpl. Its presence in the NON-drift set (NOT this map) tightens the
			// claim that nonCascading's drift is EXACTLY the inherited-root-key
			// (live-descendant-rescue) path, not any dead-root presentation. The
			// expired-grant cell is ALSO a NON-drift cell here: its FRESH token carries
			// no inherited root, so there is nothing for the cascade override to drop —
			// the fake rides the shared HonestDecision core's grant-TTL leg untouched
			// and DENYs credential_expired, agreeing with RefImpl over the past-TTL
			// grant fleet.
			driftCells: map[string]bool{
				"dead-root-cascade": true,
				"dead-root-cascade-distinct-revoked-root-over-live-desc": true,
			},
		},
		{
			name:           "driftedAllowAllFakeDialer",
			dialer:         driftedAllowAllFakeDialer(),
			dialerForFleet: driftedAllowAllFakeDialerOverFleet,
			// The blanket-ALLOW override touches every cell — including expired-grant,
			// where it ALLOWs over the past-TTL grant fleet while RefImpl DENYs
			// credential_expired.
			driftCells: map[string]bool{
				"malformed": true, "binding-mismatch": true, "dead-root-cascade": true,
				"dead-root-cascade-distinct-revoked-root-over-live-desc": true,
				"dead-root-over-dead-descendant":                         true,
				"cross-host-root":                                        true, "child-revoked": true, "expired-token": true,
				"out-of-grant": true, "in-scope-ALLOW": true, "tighter-token-expiry": true,
				"expired-grant": true,
			},
		},
	}

	for _, neg := range negatives {
		t.Run(neg.name, func(t *testing.T) {
			conn, stop, err := neg.dialer.Dial(ctx)
			if err != nil {
				t.Fatalf("dial %s: %v", neg.name, err)
			}
			defer stop()
			negClient := identityv1.NewIdentityValidationServiceClient(conn)

			// FOLD-COMPLETENESS guard: record the canonical cells this dialer actually
			// exercises and assert below that it is the FULL canonical cell-NAME SET —
			// not a bare count. The fold-invariant only proves something for a cell a
			// dialer is RUN over; a cell silently skipped (an early continue, a guarded
			// branch that drops a cell, a stale hand-maintained sub-set) — or a cell
			// visited TWICE while another is skipped, which nets the same count — would
			// let the invariant pass VACUOUSLY for that cell while the assertions never
			// fired. The per-dialer tracker records reach at the TOP of each cell's
			// subtest (before any branch / early return) so the post-loop verify is
			// exactly "this dialer visited EXACTLY the canonical cell set (no dup, no
			// skip, no foreign)"; it also pins the serial-execution invariant the shared
			// refClient/negClient rely on (a future t.Parallel() inside a cell would race
			// the shared clients — verify catches it).
			tracker := newFoldCompletenessTracker()
			cellsExercised := 0

			for _, c := range cells {
				t.Run(c.name, func(t *testing.T) {
					defer tracker.enter(c.name)()
					cellsExercised++

					req := &identityv1.ValidateRequest{
						PresentedCredential: c.cred,
						SessionRef:          testSessionRef(c.sessionUUID),
						ServiceId:           c.serviceID,
					}

					// Baseline + negative client for this cell. A hookless cell measures
					// the standing-fleet negative dialer against the standing-fleet RefImpl
					// (refClient). A cell carrying the optional pre-presentation
					// fleet-setup hook (expired-grant) instead dials its own past-TTL
					// grant dialer for the RefImpl baseline and rebuilds the negative
					// dialer over the matching fleet, so both ends are measured over the
					// cell's dedicated fleet.
					cellRefClient := refClient
					cellNegClient := negClient
					if c.setup != nil {
						hookRefConn, hookRefStop, err := c.setup.refDialer().Dial(ctx)
						if err != nil {
							t.Fatalf("dial setup refDialer for %q: %v", c.name, err)
						}
						defer hookRefStop()
						cellRefClient = identityv1.NewIdentityValidationServiceClient(hookRefConn)

						hookNegConn, hookNegStop, err := neg.dialerForFleet(c.setup.fleet).Dial(ctx)
						if err != nil {
							t.Fatalf("dial %s over setup fleet for %q: %v", neg.name, c.name, err)
						}
						defer hookNegStop()
						cellNegClient = identityv1.NewIdentityValidationServiceClient(hookNegConn)
					}

					ref, err := cellRefClient.Validate(ctx, req)
					if err != nil {
						t.Fatalf("RefImpl.Validate(%s): %v", c.name, err)
					}
					got, err := cellNegClient.Validate(ctx, req)
					if err != nil {
						t.Fatalf("%s.Validate(%s): %v", neg.name, c.name, err)
					}

					same := ref.GetVerdict() == got.GetVerdict() &&
						ref.GetMachineReadableReason() == got.GetMachineReadableReason() &&
						ref.GetGrantRef() == got.GetGrantRef() &&
						ref.GetExpiryUnixSeconds() == got.GetExpiryUnixSeconds()

					if neg.driftCells[c.name] {
						// This is the dialer's deliberate drift cell — it MUST diverge.
						// A match here means the drift was silently neutralized to green.
						if same {
							t.Fatalf("%s did NOT drift on its declared drift cell %q — the deliberate drift is neutralized:\n  RefImpl = {verdict:%s reason:%q grant_ref:%q expiry:%d}",
								neg.name, c.name,
								ref.GetVerdict(), ref.GetMachineReadableReason(), ref.GetGrantRef(), ref.GetExpiryUnixSeconds())
						}
						// ASSERT-FIRED PIN: the drift-cell invariant has now run; record
						// the marker at the assert site BEFORE this branch's early return,
						// so the assert-fired set verify checks against the canonical set
						// counts this cell as proven-asserted, not merely reached.
						tracker.markAsserted(c.name)
						return
					}

					// An UNDRIFTED leg — it rides the shared HonestDecision core, so it
					// MUST be byte-identical to RefImpl. Divergence here means the fold
					// leaked past the one intended cell.
					if !same {
						t.Fatalf("%s drifted on UNDRIFTED cell %q — the fold leaked past its one deliberate drift:\n  RefImpl = {verdict:%s reason:%q grant_ref:%q expiry:%d}\n  %s     = {verdict:%s reason:%q grant_ref:%q expiry:%d}",
							neg.name, c.name,
							ref.GetVerdict(), ref.GetMachineReadableReason(), ref.GetGrantRef(), ref.GetExpiryUnixSeconds(),
							neg.name, got.GetVerdict(), got.GetMachineReadableReason(), got.GetGrantRef(), got.GetExpiryUnixSeconds())
					}

					// ASSERT-FIRED PIN: the undrifted-leg invariant has now run; record
					// the marker at the assert site so the assert-fired set verify checks
					// against the canonical set counts this cell as proven-asserted.
					tracker.markAsserted(c.name)
				})
			}

			// FOLD-COMPLETENESS (name set + serial): the EXACT set of cell names this
			// dialer was driven over must equal the canonical name set — no duplicate
			// visit, no skip, no foreign cell (vacuous to neither a swap nor a double) —
			// AND the cells settled synchronously (cellsExercised, captured at loop exit)
			// so no cell was t.Parallel()'d off the shared refClient/negClient, with no
			// concurrent overlap. Run BEFORE the count anchor so its precise
			// name-set/serial message is the one that fires on a swap or a parallelized
			// cell.
			tracker.verify(t, neg.name, canonical, cellsExercised)

			// FOLD-COMPLETENESS (count anchor): this dialer must have been driven over
			// the FULL canonical cell-set — exactly len(reasonMatrixCells()) cells, no
			// silent skip. The cell subtests run synchronously (no t.Parallel), so the
			// counter is settled here. A short count means a cell was dropped from this
			// dialer's fold and its invariant (drift cells diverge, non-drift cells
			// match) was never asserted for it — a vacuous pass this guard turns into a
			// LOUD failure. Retained as a redundant anchor; the name-set verify above
			// SUBSUMES it (and additionally catches a double-visit + skip a bare count
			// cannot).
			if cellsExercised != len(cells) {
				t.Fatalf("%s fold-completeness: exercised %d cells but the canonical reason matrix has %d — a cell was silently skipped, so its fold-invariant passed vacuously",
					neg.name, cellsExercised, len(cells))
			}
		})
	}
}

// TestNegativeDialers_FoldInvariant_UndriftedLegsMatchRefImpl is the per-commit
// enforcement of the claim TestNegativeDialers_FoldInvariant_MatchRefImplExceptOneCell
// only ASSERTS for each dialer's NON-drift cells: that folding the negative dialers'
// honest legs onto the shared HonestDecision core (orch64) introduced NO honest-leg
// divergence from the core BEYOND each dialer's ONE declared drift. The
// except-one-cell matrix above drives the DRIFT-ON dialers and tolerates (indeed
// requires) divergence on their declared drift cells, so it cannot speak to what each
// dialer would do on those cells with its drift ABSENT — that "the folded honest legs
// cannot silently drift from the core" was, on the drift cells specifically, only
// REVIEW-asserted (confirmed by manually neutering each drift to RED and observing the
// remaining legs still matched). This matrix closes that gap: it drives the UNDRIFTED
// form of BOTH negative dialers — each negative dialer's exact plumbing with its one
// drift OVERRIDE ABSENT (nil) — over the SAME canonical reasonMatrixCells() the honest
// agreement matrix and the except-one-cell matrix consume, and asserts EVERY cell
// (the would-be drift cells INCLUDED) is byte-for-byte equal to RefImpl on
// {verdict, reason, grant_ref, expiry}. Because the undrifted dialer differs from its
// drifted sibling ONLY by the nil-vs-present drift hook, a green row here proves the
// dialer's honest legs are a faithful fold of the core on the FULL cell set — so any
// future silent honest-leg drift (a caller keying a lookup on the wrong uuid, dropping
// root_session from a non-drift leg, etc.) BEYOND the one declared, hook-localized
// drift is caught per commit rather than at manual review.
//
// It does NOT weaken the deliberate drift: the drift-ON dialers
// (nonCascadingFakeDialer / driftedAllowAllFakeDialer) keep failing their existing
// seam gates (TestSeam_HarnessCatchesADriftedFake,
// TestChainedLiveness_HarnessCatchesANonCascadingFake) and keep diverging on their
// declared drift cells in the except-one-cell matrix — all unchanged. This is a NEW,
// additive matrix over the UNDRIFTED dialers; nothing here touches the drift-ON path.
//
// The expired-grant cell carries the same OPTIONAL pre-presentation fleet-setup hook
// (cellSetup) the other two matrices honor: the standing seedFleet is all far-future,
// so its grant-TTL leg cannot be expressed against it; for that one cell this matrix
// dials the cell's past-TTL grant dialer (RealDialerWithExpiredGrant()) for the
// RefImpl baseline and rebuilds each UNDRIFTED dialer over the matching fleet, so both
// ends are measured over the cell's dedicated fleet. Every hookless cell rides the
// shared standing-fleet dialers.
//
// Additive and test-only: it reuses the existing negative dialers' undrifted
// constructors, the canonical reasonMatrixCells(), the foldCompletenessTracker, and
// the synthetic presentation builders; it modifies no production code (refimpl.go
// untouched) and weakens no existing assertion. Synthetic fixtures only (D50).
func TestNegativeDialers_FoldInvariant_UndriftedLegsMatchRefImpl(t *testing.T) {
	ctx := context.Background()

	// RefImpl over the standing seedFleet — the honest baseline every undrifted leg is
	// measured against, reached through the real client so the baseline is the actual
	// production decision path.
	refConn, refStop, err := identityvalidate.RealDialer().Dial(ctx)
	if err != nil {
		t.Fatalf("dial RealDialer: %v", err)
	}
	defer refStop()
	refClient := identityv1.NewIdentityValidationServiceClient(refConn)

	cells := reasonMatrixCells()
	canonical := reasonMatrixCellNames(t, cells)

	// Each negative dialer in its UNDRIFTED form (drift override nil), parameterized on
	// the honest fleet it runs over so a cell carrying the optional pre-presentation
	// fleet-setup hook (expired-grant) can drive the undrifted dialer over its dedicated
	// past-TTL grant fleet rather than the standing fleet. There is NO driftCells set:
	// with the drift override absent EVERY cell must match RefImpl — that is exactly the
	// fold-invariant this matrix enforces.
	undrifted := []struct {
		name           string
		dialerForFleet func(map[string]honestSession) dualrun.Dialer
	}{
		{name: "nonCascadingFakeDialer/undrifted", dialerForFleet: nonCascadingFakeDialerUndriftedOverFleet},
		{name: "driftedAllowAllFakeDialer/undrifted", dialerForFleet: driftedAllowAllFakeDialerUndriftedOverFleet},
	}

	for _, ud := range undrifted {
		t.Run(ud.name, func(t *testing.T) {
			// The standing-fleet dialer this run measures every hookless cell over.
			conn, stop, err := ud.dialerForFleet(honestStandingFleet()).Dial(ctx)
			if err != nil {
				t.Fatalf("dial %s: %v", ud.name, err)
			}
			defer stop()
			undriftedClient := identityv1.NewIdentityValidationServiceClient(conn)

			// FOLD-COMPLETENESS guard: record the canonical cells this undrifted dialer
			// actually exercises and assert below that it is the FULL canonical cell-NAME
			// SET — not a bare count — and that the cells settled serially against the
			// shared clients. The fold-invariant only proves something for a cell a dialer
			// is RUN over; a silently skipped cell (or a cell visited TWICE while another is
			// skipped, which nets the same count) would let the invariant pass VACUOUSLY for
			// it. The per-dialer tracker records reach at the TOP of each cell's subtest
			// (before any branch), markAsserted at the assert site, and verify checks both
			// the reach and the assert-fired name sets equal the canonical set.
			tracker := newFoldCompletenessTracker()
			cellsExercised := 0

			for _, c := range cells {
				t.Run(c.name, func(t *testing.T) {
					defer tracker.enter(c.name)()
					cellsExercised++

					req := &identityv1.ValidateRequest{
						PresentedCredential: c.cred,
						SessionRef:          testSessionRef(c.sessionUUID),
						ServiceId:           c.serviceID,
					}

					// Baseline + undrifted client for this cell. A hookless cell measures the
					// standing-fleet undrifted dialer against the standing-fleet RefImpl
					// (refClient). A cell carrying the optional pre-presentation fleet-setup
					// hook (expired-grant) instead dials its own past-TTL grant dialer for the
					// RefImpl baseline and rebuilds the undrifted dialer over the matching
					// fleet, so both ends are measured over the cell's dedicated fleet.
					cellRefClient := refClient
					cellUndriftedClient := undriftedClient
					if c.setup != nil {
						hookRefConn, hookRefStop, err := c.setup.refDialer().Dial(ctx)
						if err != nil {
							t.Fatalf("dial setup refDialer for %q: %v", c.name, err)
						}
						defer hookRefStop()
						cellRefClient = identityv1.NewIdentityValidationServiceClient(hookRefConn)

						hookConn, hookStop, err := ud.dialerForFleet(c.setup.fleet).Dial(ctx)
						if err != nil {
							t.Fatalf("dial %s over setup fleet for %q: %v", ud.name, c.name, err)
						}
						defer hookStop()
						cellUndriftedClient = identityv1.NewIdentityValidationServiceClient(hookConn)
					}

					ref, err := cellRefClient.Validate(ctx, req)
					if err != nil {
						t.Fatalf("RefImpl.Validate(%s): %v", c.name, err)
					}
					got, err := cellUndriftedClient.Validate(ctx, req)
					if err != nil {
						t.Fatalf("%s.Validate(%s): %v", ud.name, c.name, err)
					}

					// THE LOAD-BEARING INVARIANT: with the drift override ABSENT, the
					// undrifted dialer's honest legs ride the shared HonestDecision core, so
					// EVERY cell — the would-be drift cells included — must be byte-for-byte
					// equal to RefImpl on {verdict, reason, grant_ref, expiry}. A divergence
					// here means the fold leaked an honest-leg difference from the core BEYOND
					// the one declared, hook-localized drift.
					if ref.GetVerdict() != got.GetVerdict() ||
						ref.GetMachineReadableReason() != got.GetMachineReadableReason() ||
						ref.GetGrantRef() != got.GetGrantRef() ||
						ref.GetExpiryUnixSeconds() != got.GetExpiryUnixSeconds() {
						t.Fatalf("%s diverged from RefImpl on UNDRIFTED cell %q — the folded honest legs silently drifted from the core beyond the one declared drift:\n  RefImpl              = {verdict:%s reason:%q grant_ref:%q expiry:%d}\n  %s = {verdict:%s reason:%q grant_ref:%q expiry:%d}",
							ud.name, c.name,
							ref.GetVerdict(), ref.GetMachineReadableReason(), ref.GetGrantRef(), ref.GetExpiryUnixSeconds(),
							ud.name, got.GetVerdict(), got.GetMachineReadableReason(), got.GetGrantRef(), got.GetExpiryUnixSeconds())
					}

					// ASSERT-FIRED PIN: the undrifted-leg invariant has now run for this cell;
					// record the marker at the assert site so the assert-fired set verify
					// checks against the canonical set counts this cell as proven-asserted,
					// not merely reached.
					tracker.markAsserted(c.name)
				})
			}

			// FOLD-COMPLETENESS (name set + serial): the EXACT set of cell names this
			// undrifted dialer was driven over must equal the canonical name set — no
			// duplicate visit, no skip, no foreign cell — AND the cells settled
			// synchronously (cellsExercised, captured at loop exit) so no cell was
			// t.Parallel()'d off the shared refClient/undriftedClient.
			tracker.verify(t, ud.name, canonical, cellsExercised)

			// FOLD-COMPLETENESS (count anchor): this undrifted dialer must have been driven
			// over the FULL canonical cell-set — exactly len(reasonMatrixCells()) cells, no
			// silent skip. A short count means a cell was dropped from this dialer's fold
			// and its undrifted-leg invariant never fired for it — a vacuous pass this guard
			// turns into a LOUD failure. Retained as a redundant anchor; the name-set verify
			// above SUBSUMES it.
			if cellsExercised != len(cells) {
				t.Fatalf("%s fold-completeness: exercised %d cells but the canonical reason matrix has %d — a cell was silently skipped, so its undrifted-leg invariant passed vacuously",
					ud.name, cellsExercised, len(cells))
			}
		})
	}
}

// assertCellOutcome checks one Validate response against a callers-table cell's
// contracted outcome: an ALLOW must carry the expected grant_ref + expiry and no
// reason; a DENY must carry the expected machine-readable reason and NEITHER a
// grant_ref nor an expiry (they are ALLOW-only fields, doc 16 §4). caller names
// the caller under test so a failure is self-locating. Test-only helper.
func assertCellOutcome(t *testing.T, caller, wantVerdict, wantReason, wantRef string, wantExpiry int64, got *identityv1.ValidateResponse) {
	t.Helper()
	switch wantVerdict {
	case "ALLOW":
		if got.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
			t.Fatalf("%s: want ALLOW, got %s (%s)", caller, got.GetVerdict(), got.GetMachineReadableReason())
		}
		if got.GetGrantRef() != wantRef {
			t.Fatalf("%s: ALLOW grant_ref = %q, want %q", caller, got.GetGrantRef(), wantRef)
		}
		if got.GetExpiryUnixSeconds() != wantExpiry {
			t.Fatalf("%s: ALLOW expiry = %d, want %d", caller, got.GetExpiryUnixSeconds(), wantExpiry)
		}
	case "DENY":
		if got.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY || got.GetMachineReadableReason() != wantReason {
			t.Fatalf("%s: want DENY %s, got %s (%s)", caller, wantReason, got.GetVerdict(), got.GetMachineReadableReason())
		}
		if got.GetGrantRef() != "" {
			t.Fatalf("%s: DENY must not carry a grant_ref, got %q", caller, got.GetGrantRef())
		}
		if got.GetExpiryUnixSeconds() != 0 {
			t.Fatalf("%s: DENY must not carry an expiry, got %d", caller, got.GetExpiryUnixSeconds())
		}
	default:
		t.Fatalf("assertCellOutcome: unknown wantVerdict %q", wantVerdict)
	}
}

func denyForTest(reason string) *identityv1.ValidateResponse {
	return &identityv1.ValidateResponse{
		Verdict:               identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY,
		MachineReadableReason: reason,
	}
}

// honestGrant is a per-service grant entry in the honest test fleet: the
// grant_ref returned on ALLOW and the grant's own TTL. The ALLOW expiry is the
// INTERSECTION horizon — the tighter of this grant TTL and the presented token's
// TTL (doc 16 §5.1, doc 19 §8) — so a far-future grant defers to a tighter token
// and vice-versa.
type honestGrant struct {
	ref    string
	expiry int64
}

// honestSession is one session in the honest test fleet: its own-session
// liveness and the grants it holds, keyed by service_id (doc 19 §7/§8).
type honestSession struct {
	live   bool
	grants map[string]honestGrant
}

// fleetLiveness builds the honest, fleet-backed session-liveness lookup the
// shared HonestDecision core consults: a session present in the fleet reports
// its liveness bit and known==true; one absent reports known==false (an unknown
// session — and, for a chained token, an unknown root — is not evidence of
// revocation, doc 19 §7 cross-host). This is the ONE honest liveness derivation
// the honest responder and the negative dialers all start from; a negative
// dialer that drifts the cascade overrides this lookup at a single point rather
// than re-deriving it. Synthetic fixtures only (D50).
func fleetLiveness(fleet map[string]honestSession) identityvalidate.LivenessLookup {
	return func(uuid string) (live, known bool) {
		s, ok := fleet[uuid]
		if !ok {
			return false, false
		}
		return s.live, true
	}
}

// fleetGrants builds the honest, fleet-backed grant lookup the shared
// HonestDecision core consults for a fixed presenting session: it resolves the
// (grant_ref, grant TTL) the session holds for a service, or granted==false on a
// miss. Keyed on the SESSION the credential is presented against (not the token's
// own claimed session) so the per-session binding the core enforces upstream is
// honored. Synthetic fixtures only (D50).
func fleetGrants(fleet map[string]honestSession, sessionUUID string) identityvalidate.GrantLookup {
	return func(serviceID string) (ref string, expiry int64, granted bool) {
		s, ok := fleet[sessionUUID]
		if !ok {
			return "", 0, false
		}
		g, ok := s.grants[serviceID]
		if !ok {
			return "", 0, false
		}
		return g.ref, g.expiry, true
	}
}

// honestFleetResponder is the SINGLE parameterized honest stub: it parses the
// format-opaque credential (the malformed-credential leg) and hands the rest of
// the decision — per-session binding, two-key liveness, freshness,
// grant-intersection, ALLOW-with-tighter-expiry — to the ONE shared honest core
// the production RefImpl.Validate also routes through
// (identityvalidate.HonestDecision), backed by the per-call fleet's liveness +
// grant lookups, so no caller can re-implement (and thus silently drift) the
// honest legs.
//
// Two single-point drift hooks let the negative dialers reuse those honest legs
// while diverging at EXACTLY one place; honest callers pass nil for both:
//
//   - liveness overrides the liveness lookup HonestDecision consults — the
//     non-cascading gate supplies one that drops the root cascade;
//   - postDecision rewrites the honest verdict the core returned — the
//     blanket-ALLOW gate supplies one that discards it for ALLOW.
//
// Synthetic fixtures only (D50).
func honestFleetResponder(
	fleet map[string]honestSession,
	liveness func(req *identityv1.ValidateRequest) identityvalidate.LivenessLookup,
	postDecision func(honest *identityv1.ValidateResponse) *identityv1.ValidateResponse,
) func(context.Context, *identityv1.ValidateRequest) (*identityv1.ValidateResponse, error) {
	return func(_ context.Context, req *identityv1.ValidateRequest) (*identityv1.ValidateResponse, error) {
		tok, ok := identityvalidate.ParseTokenForTest(req.GetPresentedCredential())
		if !ok {
			if postDecision != nil {
				return postDecision(denyForTest("malformed_credential")), nil
			}
			return denyForTest("malformed_credential"), nil
		}
		sessionUUID := req.GetSessionRef().GetSessionUuid()
		live := fleetLiveness(fleet)
		if liveness != nil {
			live = liveness(req)
		}
		honest := identityvalidate.HonestDecision(
			sessionUUID,
			req.GetServiceId(),
			identityvalidate.HonestToken{
				SessionUUID:      tok.SessionUUID,
				ExpiryUnixSecond: tok.ExpiryUnixSecond,
				RootSession:      tok.RootSession,
				ScopeContains:    tok.ScopeContains,
			},
			testNow,
			live,
			fleetGrants(fleet, sessionUUID),
		)
		if postDecision != nil {
			return postDecision(honest), nil
		}
		return honest, nil
	}
}

// honestValidateResponder is the SINGLE source of the honest two-key
// chained-token liveness contract (doc 16 §4/§5.1, doc 19 §7/§8), used to
// program f.ValidateResponder identically across the grant-intersection,
// idempotency, and chained-liveness fake-accessor tests so the honest copies
// cannot silently drift apart and the absolute-verdict anchors stay
// authoritative. It is honestFleetResponder with no liveness override — every
// leg routed through the shared HonestDecision core. The per-test fleet is the
// only knob: a test seeds the sessions, liveness legs, and grant set it
// exercises, and this responder decides every presentation against that fleet
// with the reference validator's exact ordering —
//
//  1. signature/shape: parse the token, session_uuid must match the ref;
//  2. whole-chain liveness: a KNOWN-dead inherited root cascades to
//     session_not_live; an unknown root falls through to own-session liveness;
//  3. own-session liveness: an unknown or dead session is session_not_live;
//  4. freshness: an expired token is credential_expired;
//  5. grant-intersection: the session must grant the service AND the token's
//     attenuated scope must cover it, else out_of_grant;
//  6. ALLOW carrying the grant_ref and the tighter of the grant/token expiry.
//
// Synthetic fixtures only (D50).
func honestValidateResponder(fleet map[string]honestSession) func(context.Context, *identityv1.ValidateRequest) (*identityv1.ValidateResponse, error) {
	return honestFleetResponder(fleet, nil, nil)
}

// honestRecordingFake is the ONE constructor the three *Recorded()-accessor tests
// (TestGrantIntersection_RecordedViaFakeAccessors,
// TestIdempotency_RecordedViaFakeAccessors,
// TestChainedLiveness_RecordedViaFakeAccessors) build their fake through: a fresh
// generated IdentityValidationServiceFake whose ValidateResponder is the shared
// honestValidateResponder over the per-test fleet. The three tests previously hand-inlined
// the SAME two lines — NewIdentityValidationServiceFake() then `f.ValidateResponder =
// honestValidateResponder(<fleet>)` — three times, each inline an opportunity to silently
// diverge in how the recording fake is wired (a forgotten responder assignment, a
// different fake constructor, a responder that is not the shared honest one), which the
// dual-run cannot catch because these tests drive the fake DIRECTLY (not through the
// suite). Folding the wiring here means all three exercise the SAME recorder-backed honest
// fake; only the per-test fleet — the actual knob each test varies — stays at the call
// site. The returned fake's ValidateRecorded() call-capture surface is exactly what the
// three tests assert over (the downstream-consumer audit trail the dual-run cannot
// provide). Synthetic fixtures only (D50).
func honestRecordingFake(fleet map[string]honestSession) *identityv1fake.IdentityValidationServiceFake {
	f := identityv1fake.NewIdentityValidationServiceFake()
	f.ValidateResponder = honestValidateResponder(fleet)
	return f
}

// nonCascadingFakeDialer programs the generated fake with a responder that is
// honest on EVERY leg — signature/shape, own-session liveness, freshness,
// grant-intersection — EXCEPT it does not cascade ROOT revocation: it keys
// liveness ONLY on the descendant's own session_uuid and ignores the inherited
// root_session entirely (doc 19 §7 broken-link). On the broken-link scenario (a
// live descendant of a REVOKED root) the reference validator DENYs
// session_not_live while this fake ALLOWs, so the dual-run gate must bite. It
// matches the reference on all the standing scenarios, so the divergence is
// precisely the dropped cascade.
//
// The honest legs are NOT re-implemented: this dialer drives the SAME shared
// HonestDecision core over the SAME honestStandingFleet() the honest responder
// uses (so the parse, per-session binding, own-session liveness, freshness, and
// grant-intersection legs cannot drift from the core). Its ONE deliberate drift
// is the liveness override below, keyed LITERALLY on the presentation's inherited
// root (req.root_session — the chain origin carried inside the format-opaque
// credential): HonestDecision consults the liveness lookup for BOTH the inherited
// root and the own session, so an override that answers honestly for EVERY uuid
// EXCEPT the inherited root — reporting that ONE key as if the host had no record
// of it — makes a KNOWN-dead root no longer cascade (it falls through to
// own-session liveness), i.e. the cascade is dropped, while keeping every other
// liveness answer (own session AND any future third queried uuid) honest. Keying
// on req.root_session rather than "every uuid != own-session" makes the drift a
// LITERAL single key: a future scenario that adds a third queried uuid stays
// honest there, so the deliberate drift cannot silently widen past the one cell
// it declares. Synthetic fixtures only (D50).
func nonCascadingFakeDialer() dualrun.Dialer {
	return nonCascadingFakeDialerOverFleet(honestStandingFleet())
}

// nonCascadingFakeDialerOverFleet is nonCascadingFakeDialer parameterized on the
// honest fleet it runs over, so the negative-dialer fold matrix can rebuild the
// non-cascading fake over a cell's optional pre-presentation fleet-setup fleet
// (expiredGrantFleet() for the expired-grant cell) instead of the standing fleet.
// nonCascadingFakeDialer() is exactly this over honestStandingFleet(), so every
// existing caller is unchanged. The ONE deliberate drift — the inherited-root
// liveness override — is identical regardless of fleet: on a cell with no inherited
// root (e.g. expired-grant) there is nothing to drop, so the fake rides the shared
// HonestDecision core untouched and AGREES with RefImpl. Synthetic fixtures only
// (D50).
func nonCascadingFakeDialerOverFleet(fleet map[string]honestSession) dualrun.Dialer {
	// Built through the SAME shared fakeDialerOverFleet plumbing as its undrifted twin
	// (nonCascadingFakeDialerUndriftedOverFleet), passing its ONE deliberate drift —
	// the inherited-root liveness override (nonCascadingLivenessDrift) — where the twin
	// passes nil. Routing both through one builder means the twin is the drift-OFF
	// derivation of THIS constructor (a nil driftHook param), so a future change to the
	// fake-registration plumbing flows to both and the twin cannot desync.
	return fakeDialerOverFleet(fleet, nonCascadingLivenessDrift(fleet), nil)
}

// nonCascadingLivenessDrift is the ONE deliberate drift the non-cascading negative
// dialer carries: the inherited-root liveness override that reports the presentation's
// inherited root_session — and ONLY that one key — as if the host had no record of it,
// so a KNOWN-dead root no longer cascades (it falls through to own-session liveness).
// Factored out of nonCascadingFakeDialerOverFleet so the drifted constructor passes it
// and the undrifted twin passes nil through the SAME fakeDialerOverFleet builder — the
// drift is the only thing that differs between the two, made literal as a hook value.
// Synthetic fixtures only (D50).
func nonCascadingLivenessDrift(fleet map[string]honestSession) func(req *identityv1.ValidateRequest) identityvalidate.LivenessLookup {
	return func(req *identityv1.ValidateRequest) identityvalidate.LivenessLookup {
		// The inherited root is the ONE key this fake drifts. It rides inside the
		// format-opaque credential (there is no root_session proto field on
		// ValidateRequest), so parse it out the same way the shared core does. A
		// non-chained or unparseable presentation has no inherited root to drop.
		var driftRoot string
		if tok, ok := identityvalidate.ParseTokenForTest(req.GetPresentedCredential()); ok {
			driftRoot = tok.RootSession
		}
		honest := fleetLiveness(fleet)
		return func(uuid string) (live, known bool) {
			// DRIFT: the inherited root_session — and ONLY that one key — is reported
			// as if the host had no record of it, so a KNOWN-dead root no longer
			// cascades (it falls through to own-session liveness). Every other uuid,
			// the own session included, gets the honest fleet answer. This is the one
			// and only deviation from the reference validator.
			if driftRoot != "" && uuid == driftRoot {
				return false, false
			}
			return honest(uuid)
		}
	}
}

// fakeDialerOverFleet is the shared fake-registration plumbing both the drifted
// negative dialers and their undrifted twins run through: a generated fake whose
// Validate responder is the honestFleetResponder over the given fleet, with optional
// liveness / postDecision drift hooks (nil on either => that leg is honest), registered
// through the dualrun.InProcess seam. The drifted constructors pass their ONE hook; the
// undrifted twins pass nil for BOTH — so each twin is the literal drift-OFF derivation
// of its drifted sibling (same builder, same fleet, same seam), and a future plumbing
// change flows to both ends, keeping the twin from silently desyncing. Synthetic
// fixtures only (D50).
func fakeDialerOverFleet(
	fleet map[string]honestSession,
	liveness func(req *identityv1.ValidateRequest) identityvalidate.LivenessLookup,
	postDecision func(honest *identityv1.ValidateResponse) *identityv1.ValidateResponse,
) dualrun.Dialer {
	f := identityv1fake.NewIdentityValidationServiceFake()
	f.ValidateResponder = honestFleetResponder(fleet, liveness, postDecision)
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		identityv1fake.RegisterIdentityValidationService(s, f)
	})
}

// driftedAllowAllFakeDialer programs the generated fake with a deliberately wrong
// Validate responder that returns ALLOW for EVERY presentation — ignoring the
// grant-intersection, expiry, and session-liveness checks entirely. This is the
// "lying fake" the dual-run exists to catch: it diverges from the reference
// validator on every DENY scenario (over-scope, expired, revoked, malformed), so
// the gate must bite.
//
// The honest decision is still derived from the shared HonestDecision core over
// honestStandingFleet() (so the honest legs cannot drift from the core), but its
// ONE deliberate drift is the blanket-ALLOW postDecision override below: the
// honest verdict is computed and then discarded, every presentation answered
// ALLOW with a fabricated grant_ref. Synthetic fixtures only (D50).
func driftedAllowAllFakeDialer() dualrun.Dialer {
	return driftedAllowAllFakeDialerOverFleet(honestStandingFleet())
}

// driftedAllowAllFakeDialerOverFleet is driftedAllowAllFakeDialer parameterized on
// the honest fleet it derives its (discarded) honest verdict over, so the
// negative-dialer fold matrix can rebuild the blanket-ALLOW fake over a cell's
// optional pre-presentation fleet-setup fleet (expiredGrantFleet() for the
// expired-grant cell) instead of the standing fleet. driftedAllowAllFakeDialer() is
// exactly this over honestStandingFleet(), so every existing caller is unchanged.
// The blanket-ALLOW postDecision override discards the honest verdict on EVERY
// presentation regardless of fleet, so it diverges from RefImpl on every cell —
// including expired-grant (ALLOW vs DENY credential_expired). Synthetic fixtures
// only (D50).
func driftedAllowAllFakeDialerOverFleet(fleet map[string]honestSession) dualrun.Dialer {
	// Built through the SAME shared fakeDialerOverFleet plumbing as its undrifted twin
	// (driftedAllowAllFakeDialerUndriftedOverFleet), passing its ONE deliberate drift —
	// the blanket-ALLOW postDecision override (driftedAllowAllPostDecision) — where the
	// twin passes nil. Routing both through one builder means the twin is the drift-OFF
	// derivation of THIS constructor (a nil driftHook param), so a future change to the
	// fake-registration plumbing flows to both and the twin cannot desync.
	return fakeDialerOverFleet(fleet, nil, driftedAllowAllPostDecision())
}

// driftedAllowAllPostDecision is the ONE deliberate drift the blanket-ALLOW negative
// dialer carries: the postDecision override that discards the honest verdict the shared
// HonestDecision core computed and returns a blanket ALLOW with a fabricated grant_ref —
// never an honest reject, never an intersection check. Factored out of
// driftedAllowAllFakeDialerOverFleet so the drifted constructor passes it and the
// undrifted twin passes nil through the SAME fakeDialerOverFleet builder — the drift is
// the only thing that differs between the two, made literal as a hook value. Synthetic
// fixtures only (D50).
func driftedAllowAllPostDecision() func(honest *identityv1.ValidateResponse) *identityv1.ValidateResponse {
	return func(_ *identityv1.ValidateResponse) *identityv1.ValidateResponse {
		// DRIFT: discard the honest verdict and return a blanket ALLOW with a
		// fabricated grant_ref — never an honest reject, never an intersection
		// check.
		return &identityv1.ValidateResponse{
			Verdict:           identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW,
			GrantRef:          "grantref-synthetic-drift-deadbeef",
			ExpiryUnixSeconds: testExpiryFarFuture,
		}
	}
}

// nonCascadingFakeDialerUndriftedOverFleet is nonCascadingFakeDialerOverFleet with
// its ONE deliberate drift OVERRIDE ABSENT — the inherited-root liveness override is
// nil, so the fake is honest on EVERY leg, the inherited-root cascade INCLUDED. It is
// the UNDRIFTED form of the non-cascading negative dialer: structurally identical
// plumbing (the same generated fake, the same honestFleetResponder over the same
// fleet, registered through the same dualrun.InProcess seam), differing from
// nonCascadingFakeDialerOverFleet ONLY in that the liveness drift hook is nil instead
// of the inherited-root-dropping override. Driving it through the reason matrix and
// asserting EVERY cell equals RefImpl byte-for-byte makes "folding the non-cascading
// dialer's honest legs onto the shared HonestDecision core introduced NO honest-leg
// divergence beyond its one declared drift" test-enforced per commit rather than
// review-asserted (previously confirmed only by manually neutering the drift to RED).
// It is NOT registered as a negative dialer in any seam gate — the drift-ON
// nonCascadingFakeDialer keeps failing its existing gates unchanged. Synthetic
// fixtures only (D50).
func nonCascadingFakeDialerUndriftedOverFleet(fleet map[string]honestSession) dualrun.Dialer {
	// DERIVED from the drifted constructor via a nil driftHook param: it runs through the
	// SAME fakeDialerOverFleet plumbing nonCascadingFakeDialerOverFleet does, passing nil
	// for the liveness drift hook (the inherited-root override is ABSENT) and nil for the
	// postDecision hook. So the inherited-root cascade is NOT dropped — this rides the
	// shared HonestDecision core's whole-chain liveness leg untouched, byte-for-byte the
	// honest responder's behavior, reached through the EXACT same fake-registration
	// plumbing as its drifted sibling. Because both share fakeDialerOverFleet and differ
	// ONLY in the nil-vs-hook liveness param, a future change to that constructor's
	// plumbing flows to this twin automatically — it can no longer desync.
	return fakeDialerOverFleet(fleet, nil, nil)
}

// driftedAllowAllFakeDialerUndriftedOverFleet is driftedAllowAllFakeDialerOverFleet
// with its ONE deliberate drift OVERRIDE ABSENT — the blanket-ALLOW postDecision
// override is nil, so the honest verdict the shared HonestDecision core computes is
// returned as-is instead of being discarded for a fabricated ALLOW. It is the
// UNDRIFTED form of the blanket-ALLOW negative dialer: structurally identical
// plumbing (the same generated fake, the same honestFleetResponder over the same
// fleet, registered through the same dualrun.InProcess seam), differing from
// driftedAllowAllFakeDialerOverFleet ONLY in that the postDecision drift hook is nil
// instead of the verdict-discarding override. Driving it through the reason matrix
// and asserting EVERY cell equals RefImpl byte-for-byte makes "folding the
// blanket-ALLOW dialer's honest legs onto the shared HonestDecision core introduced
// NO honest-leg divergence beyond its one declared drift" test-enforced per commit
// rather than review-asserted (previously confirmed only by manually neutering the
// drift to RED). It is NOT registered as a negative dialer in any seam gate — the
// drift-ON driftedAllowAllFakeDialer keeps failing its existing gates unchanged.
// Synthetic fixtures only (D50).
func driftedAllowAllFakeDialerUndriftedOverFleet(fleet map[string]honestSession) dualrun.Dialer {
	// DERIVED from the drifted constructor via a nil driftHook param: it runs through the
	// SAME fakeDialerOverFleet plumbing driftedAllowAllFakeDialerOverFleet does, passing
	// nil for the postDecision drift hook (the blanket-ALLOW override is ABSENT) and nil
	// for the liveness hook. So the honest verdict is returned as the core computed it,
	// never discarded for a blanket ALLOW — byte-for-byte the honest responder's behavior,
	// reached through the EXACT same fake-registration plumbing as its drifted sibling.
	// Because both share fakeDialerOverFleet and differ ONLY in the nil-vs-hook
	// postDecision param, a future change to that constructor's plumbing flows to this
	// twin automatically — it can no longer desync.
	return fakeDialerOverFleet(fleet, nil, nil)
}

// honestRevokedRootChainFleet is the honest-responder-side mirror of the suite's
// seedRevokedRootChainFleet (suite.go): the DEDICATED revoked-root chain pair on
// its own synthetic uuids — a KNOWN-dead inherited root (testChainRootRevoked,
// live==false, no grants) plus an INDEPENDENTLY-LIVE descendant
// (testChainDescLiveRoot, live==true, no grants) re-rooted off it. It is the
// byte-for-byte mirror of the fleet RealDialerWithRevokedRootChain() seeds the
// production RefImpl with, so the matched dedicated-fleet fake below decides every
// dedicated-fleet presentation through the shared HonestDecision core over the same
// fleet — its ONLY drift is the single-point root-cascade override. Nothing from
// the standing fleet is present (this fleet is dedicated and self-contained), so a
// fake built on it answers honestly on exactly the two presentations
// RevokedRootChainSuite() drives and nothing else. Synthetic fixtures only (D50).
func honestRevokedRootChainFleet() map[string]honestSession {
	return map[string]honestSession{
		testChainRootRevoked:  {live: false},
		testChainDescLiveRoot: {live: true},
	}
}

// nonCascadingFakeDialerOverRevokedRootChain is the MATCHED fake-only-isolation
// dialer for the DEDICATED revoked-root chain fleet: the dead-root-cascade analogue
// of nonCascadingFakeDialer, but scoped to the dedicated chain uuids rather than the
// standing fleet. It programs the generated fake with a responder that is honest on
// EVERY leg — signature/shape, own-session liveness, freshness, grant-intersection —
// EXCEPT it does NOT cascade ROOT revocation on this fleet: it reports the inherited
// root_session as if the host had no record of it, so the KNOWN-dead dedicated root
// no longer cascades — the presentation falls through to the descendant's OWN (live)
// session and then to the grant leg, where the dedicated descendant holds no grant,
// yielding out_of_grant. The reference validator over the SAME dedicated fleet
// (RealDialerWithRevokedRootChain()) DENYs session_not_live via the cascade, so the
// two ends DIVERGE on the cascade leg: the dual-run gate must bite. The un-rooted
// control leg has no inherited root to drop, so the fake matches the reference there
// (both fall through to out_of_grant) — the divergence is PRECISELY the dropped
// dedicated-fleet cascade.
//
// The honest legs are NOT re-implemented: this dialer drives the SAME shared
// HonestDecision core over the SAME honestRevokedRootChainFleet() the focused suite
// validates against (so parse, per-session binding, own-session liveness, freshness,
// and grant-intersection cannot drift from the core). Its ONE deliberate drift is the
// liveness override, keyed LITERALLY on the presentation's inherited root
// (req.root_session, the chain origin carried inside the format-opaque credential),
// exactly as nonCascadingFakeDialer drifts over the standing fleet — so the drift is
// a single literal key and cannot silently widen past the dedicated revoked root it
// declares. This matched fake + the HarnessCatches gate below prove the revoked-root
// coverage is NON-VACUOUS: a broken harness that silently passed would be caught.
// Synthetic fixtures only (D50).
func nonCascadingFakeDialerOverRevokedRootChain() dualrun.Dialer {
	// Built through the SAME shared fakeDialerOverFleet plumbing as every other
	// negative dialer (its standing-fleet sibling nonCascadingFakeDialerOverFleet
	// included), and carrying the SAME factored inherited-root liveness drift
	// (nonCascadingLivenessDrift) as that sibling — only the fleet differs (the
	// dedicated revoked-root chain rather than the standing fleet). It formerly
	// hand-inlined both the fake-registration plumbing and a byte-for-byte copy of
	// nonCascadingLivenessDrift's override; routing it through the one builder + the
	// one factored hook means the drift can no longer desync from the standing-fleet
	// non-cascading dialer it is the dedicated-fleet analogue of (a future change to
	// the drift or the plumbing flows to both), and passing nil for the postDecision
	// hook makes its undrifted form the literal drift-OFF derivation, exactly as the
	// other negative dialers. Synthetic fixtures only (D50).
	fleet := honestRevokedRootChainFleet()
	return fakeDialerOverFleet(fleet, nonCascadingLivenessDrift(fleet), nil)
}

// TestRevokedRootChain_HarnessCatchesANonCascadingFake is the negative drift-gate
// proof over the DEDICATED revoked-root chain fleet: it dual-runs the production
// reference validator seeded with that fleet (RealDialerWithRevokedRootChain()) vs
// a matched fake honest everywhere EXCEPT it drops the dead-root cascade on this
// fleet (nonCascadingFakeDialerOverRevokedRootChain()), over the focused
// RevokedRootChainSuite(), and asserts the dual-run gate BITES.
//
// TestRevokedRootChain_CascadeOnProductionCaller and the standing Suite()'s
// chained-dedicated-fleet scenarios prove the real-vs-fake dual-run AGREES on the
// dead-root cascade over this dedicated fleet — but agreement alone does not prove
// the harness would CATCH a fake that drifts the cascade ONLY on these dedicated
// uuids. Without this negative gate the dedicated-fleet coverage could be vacuous: a
// broken harness that silently passed would go unnoticed. The reference validator
// DENYs session_not_live on the cascade leg (the dead root cascades) while the
// non-cascading fake — which reports the inherited dedicated root as if unrecorded —
// drops the cascade and falls through to out_of_grant, so real != fake on that leg
// and the gate must report the mismatch. This is the dedicated-fleet analogue of
// TestChainedLiveness_HarnessCatchesANonCascadingFake (which runs over the standing
// fleet), proving the revoked-root coverage BITES. The drift lives only in this
// test's local fake, never in the committed generated fake. Synthetic fixtures only
// (D50).
func TestRevokedRootChain_HarnessCatchesANonCascadingFake(t *testing.T) {
	res, err := identityvalidate.RevokedRootChainSuite().Run(context.Background(), identityvalidate.RealDialerWithRevokedRootChain(), nonCascadingFakeDialerOverRevokedRootChain())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a non-cascading (root-revocation-ignoring) fake passed the seam over the dedicated revoked-root chain fleet — the revoked-root drift gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or fake error over the dedicated revoked-root chain fleet, got report:\n%s", res.Report())
	}
}

// TestRevokedRootChain_IsolatedFakeAgreesAwayFromTheDrift is the companion
// soundness check for the matched dedicated-fleet fake: it pins that the fake's ONE
// deliberate drift is narrowed to EXACTLY the cascade leg. It dual-runs the same
// reference validator vs the non-cascading fake but over only the un-rooted CONTROL
// scenario (the second leg of RevokedRootChainSuite()), where there is no inherited
// root to drop — so the fake rides the shared HonestDecision core untouched and MUST
// AGREE with the reference (both fall through to out_of_grant). A divergence here
// would mean the drift leaked past the cascade leg, making the HarnessCatches gate
// above prove less than it claims. Together the two tests show the gate bites on the
// cascade leg and ONLY on the cascade leg. Additive and test-only; synthetic
// fixtures only (D50).
func TestRevokedRootChain_IsolatedFakeAgreesAwayFromTheDrift(t *testing.T) {
	// The un-rooted control scenario is the SECOND leg of the focused suite; running
	// the matched fake against it alone proves the undrifted leg still agrees.
	controlOnly := dualrun.Suite{
		Seam:      "ds-tlsproxy(swap-executor)<->identity(IdentityValidationService.Validate):revoked-root-chain-control",
		Scenarios: identityvalidate.RevokedRootChainSuite().Scenarios[1:],
	}
	res, err := controlOnly.Run(context.Background(), identityvalidate.RealDialerWithRevokedRootChain(), nonCascadingFakeDialerOverRevokedRootChain())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("the matched dedicated-fleet fake DIVERGED on the un-rooted control leg — its drift leaked past the cascade leg:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("control-only dual-run ran zero scenarios — the focused suite is missing its un-rooted control leg")
	}
}

// freshnessIgnoringPostDecision is the ONE deliberate drift the grant-TTL negative
// dialer carries: a postDecision override that rewrites a credential_expired DENY the
// shared HonestDecision core returned into an ALLOW — ignoring the grant's OWN TTL on
// the freshness leg (HonestDecision step 4) — while leaving EVERY other verdict the
// core produced untouched. Keying the rewrite LITERALLY on the credential_expired
// reason (not "rewrite every DENY", which is what driftedAllowAllPostDecision does)
// makes the drift a single point: an away-from-drift presentation that DENYs for any
// OTHER reason (out_of_grant, session_not_live, malformed_credential) is passed through
// honestly, so the drift cannot silently widen past the grant-TTL leg it declares. It
// is the grant-TTL analogue of nonCascadingLivenessDrift (the dropped-root-cascade
// single-point liveness override): both reuse the shared honest core for every other
// leg and diverge at EXACTLY one place. The ALLOW it fabricates carries a synthetic
// grant_ref/expiry so the verdict shape is well-formed (the divergence the gate
// observes is ALLOW-vs-DENY, not a malformed response). Synthetic fixtures only (D50).
func freshnessIgnoringPostDecision() func(honest *identityv1.ValidateResponse) *identityv1.ValidateResponse {
	return func(honest *identityv1.ValidateResponse) *identityv1.ValidateResponse {
		// DRIFT: a credential_expired DENY — and ONLY that one reason — is flipped to
		// an ALLOW, ignoring the grant's own TTL. Every other verdict (ALLOW, or a DENY
		// for any other reason) is returned exactly as the honest core decided it.
		if honest.GetVerdict() == identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY &&
			honest.GetMachineReadableReason() == "credential_expired" {
			return &identityv1.ValidateResponse{
				Verdict:           identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW,
				GrantRef:          "grantref-synthetic-freshnessdrift-deadbeef",
				ExpiryUnixSeconds: testExpiryFarFuture,
			}
		}
		return honest
	}
}

// freshnessIgnoringFakeDialerOverExpiredGrant is the MATCHED fake-only-isolation
// dialer for the DEDICATED past-TTL grant fleet: the grant-TTL analogue of
// nonCascadingFakeDialerOverRevokedRootChain, but scoped to the dedicated expired-grant
// uuid rather than the dedicated revoked-root chain. It programs the generated fake
// with a responder honest on EVERY leg — signature/shape, liveness, grant-intersection
// — EXCEPT it does NOT honor the grant's OWN TTL: a credential_expired DENY is rewritten
// to ALLOW (freshnessIgnoringPostDecision). The reference validator over the SAME
// dedicated fleet (RealDialerWithExpiredGrantOnly()) DENYs credential_expired on the
// grant-TTL leg, so the two ends DIVERGE there — the dual-run gate must bite. The
// away-from-drift control leg (the same session for an ungranted service) DENYs
// out_of_grant on the grant-intersection leg BEFORE any grant-TTL is consulted, so the
// freshness drift never fires there and the fake matches the reference — the divergence
// is PRECISELY the ignored grant-TTL.
//
// The honest legs are NOT re-implemented: this dialer drives the SAME shared
// HonestDecision core over the SAME expiredGrantFleet() the focused suite validates
// against (so parse, binding, liveness, and grant-intersection cannot drift from the
// core), routed through the one shared fakeDialerOverFleet plumbing every other negative
// dialer uses, carrying its ONE factored drift hook. This matched fake + the
// HarnessCatches gate below prove the grant-TTL coverage is NON-VACUOUS: a broken harness
// that silently passed would be caught. Synthetic fixtures only (D50).
func freshnessIgnoringFakeDialerOverExpiredGrant() dualrun.Dialer {
	return fakeDialerOverFleet(expiredGrantFleet(), nil, freshnessIgnoringPostDecision())
}

// TestExpiredGrant_HarnessCatchesAFreshnessIgnoringFake is the negative drift-gate
// proof over the DEDICATED past-TTL grant fleet: it dual-runs the production reference
// validator seeded with that fleet (RealDialerWithExpiredGrantOnly()) vs a matched fake
// honest everywhere EXCEPT it ignores the grant's OWN TTL on this fleet
// (freshnessIgnoringFakeDialerOverExpiredGrant()), over the focused ExpiredGrantSuite(),
// and asserts the dual-run gate BITES.
//
// The standing reason matrix and the callers/fold matrices prove the real-vs-fake
// dual-run AGREES on the grant-TTL DENY over the past-TTL grant fleet — but agreement
// alone does not prove the harness would CATCH a fake that drifts the grant-TTL leg
// ONLY on this dedicated fleet. Without this negative gate the grant-TTL coverage could
// be vacuous: a broken harness that silently passed would go unnoticed. The reference
// validator DENYs credential_expired on the grant-TTL leg (the grant's own TTL is past)
// while the freshness-ignoring fake — which rewrites that one DENY to ALLOW — ALLOWs, so
// real != fake on that leg and the gate must report the mismatch. This is the grant-TTL
// analogue of TestRevokedRootChain_HarnessCatchesANonCascadingFake (the dead-root
// cascade leg) and TestChainedLiveness_HarnessCatchesANonCascadingFake (the standing
// fleet), proving the grant-TTL coverage BITES. The drift lives only in this test's
// local fake, never in the committed generated fake. Synthetic fixtures only (D50).
func TestExpiredGrant_HarnessCatchesAFreshnessIgnoringFake(t *testing.T) {
	res, err := identityvalidate.ExpiredGrantSuite().Run(context.Background(), identityvalidate.RealDialerWithExpiredGrantOnly(), freshnessIgnoringFakeDialerOverExpiredGrant())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a freshness-ignoring (grant-TTL-dropping) fake passed the seam over the dedicated past-TTL grant fleet — the grant-TTL drift gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or fake error over the dedicated past-TTL grant fleet, got report:\n%s", res.Report())
	}
}

// TestExpiredGrant_IsolatedFakeAgreesAwayFromTheDrift is the companion soundness check
// for the matched dedicated-fleet fake: it pins that the fake's ONE deliberate drift is
// narrowed to EXACTLY the grant-TTL leg. It dual-runs the same reference validator vs
// the freshness-ignoring fake but over only the away-from-drift CONTROL scenario (the
// second leg of ExpiredGrantSuite() — the same session presented for an ungranted
// service), where the grant-intersection leg DENYs out_of_grant before any grant-TTL is
// consulted, so the fake's credential_expired-keyed rewrite never fires and it MUST
// AGREE with the reference (both DENY out_of_grant). A divergence here would mean the
// drift leaked past the grant-TTL leg, making the HarnessCatches gate above prove less
// than it claims. Together the two tests show the gate bites on the grant-TTL leg and
// ONLY on the grant-TTL leg — exactly as the dedicated revoked-root pair
// (TestRevokedRootChain_HarnessCatchesANonCascadingFake +
// TestRevokedRootChain_IsolatedFakeAgreesAwayFromTheDrift) does for the cascade leg.
// Additive and test-only; synthetic fixtures only (D50).
func TestExpiredGrant_IsolatedFakeAgreesAwayFromTheDrift(t *testing.T) {
	// The away-from-drift control scenario is the SECOND leg of the focused suite;
	// running the matched fake against it alone proves the undrifted leg still agrees.
	controlOnly := dualrun.Suite{
		Seam:      "ds-tlsproxy(swap-executor)<->identity(IdentityValidationService.Validate):expired-grant-control",
		Scenarios: identityvalidate.ExpiredGrantSuite().Scenarios[1:],
	}
	res, err := controlOnly.Run(context.Background(), identityvalidate.RealDialerWithExpiredGrantOnly(), freshnessIgnoringFakeDialerOverExpiredGrant())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("the matched dedicated-fleet fake DIVERGED on the away-from-drift control leg — its drift leaked past the grant-TTL leg:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("control-only dual-run ran zero scenarios — the focused suite is missing its away-from-drift control leg")
	}
}

// TestRevokedRootChain_CascadeOnProductionCaller pins the dead-root cascade on
// the PRODUCTION RefImpl.Validate caller via the dedicated revoked-root chain
// dialer, exactly mirroring how the expired-grant production-caller cell
// (TestHonestDecisionCallers_AgreeAcrossReasonMatrix/expired-grant) pins the
// grant-TTL leg on the real caller through RealDialerWithExpiredGrant().
//
// orch65/orch66 added dead-root cells to the callers-matrix (RefImpl.Validate vs
// honestValidateResponder agreement), but those ride the STANDING seedFleet's
// revoked-root fixtures. This cell instead drives the real caller over a
// DEDICATED revoked-root chain fleet — a KNOWN-dead inherited root plus an
// independently-live descendant on their own synthetic uuids — and asserts the
// two-key liveness AND-semantics (doc 19 §7) bites on the production caller
// specifically: a dead inherited root DENYs even a LIVE descendant with the
// dead-root cascade reason (session_not_live), NOT ALLOW. The companion un-rooted
// presentation of the SAME descendant proves the cascade is driven by the dead
// ROOT, not the descendant's own session: un-rooted it clears step 2's own-session
// liveness and falls through to out_of_grant (the descendant holds no grant),
// never session_not_live.
//
// Additive and test-only: it stands up its own RefImpl on dedicated uuids via the
// shared RealDialerWithRevokedRootChain() suite affordance (suite.go) — into which
// the formerly-local dialer was promoted so Suite() can drive the same dedicated
// chain fleet — reuses the existing synthetic presentation builders
// (MintChainedToken / MintToken / testSessionRef), modifies no production code, and
// weakens no existing assertion; the standing fleet is unchanged. Synthetic
// fixtures only (D50).
func TestRevokedRootChain_CascadeOnProductionCaller(t *testing.T) {
	ctx := context.Background()

	// Caller: the production RefImpl.Validate over the in-process gRPC seam,
	// pre-seeded with the dedicated revoked-root chain fleet via the shared
	// RealDialerWithRevokedRootChain() affordance. Driven through the real client so
	// the cell exercises the actual production decision path.
	conn, stop, err := identityvalidate.RealDialerWithRevokedRootChain().Dial(ctx)
	if err != nil {
		t.Fatalf("dial RealDialerWithRevokedRootChain: %v", err)
	}
	defer stop()
	refClient := identityv1.NewIdentityValidationServiceClient(conn)

	// The load-bearing leg: a CHAINED token re-rooted to the independently-live
	// descendant, inheriting the KNOWN-dead root. Whole-chain liveness keys on the
	// dead root (HonestDecision step 2), so the production caller DENYs
	// session_not_live — the dead-root cascade — even though the descendant's OWN
	// session is live. This is the dead-root cascade pinned on the PRODUCTION
	// caller, mirroring the expired-grant production-caller cell.
	cascadeReq := &identityv1.ValidateRequest{
		PresentedCredential: identityvalidate.MintChainedToken(testChainDescLiveRoot, testChainRootRevoked, testExpiryFarFuture, testServiceGitHub),
		SessionRef:          testSessionRef(testChainDescLiveRoot),
		ServiceId:           testServiceGitHub,
	}
	cascade, err := refClient.Validate(ctx, cascadeReq)
	if err != nil {
		t.Fatalf("revoked-root cascade RefImpl.Validate: %v", err)
	}
	if cascade.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY || cascade.GetMachineReadableReason() != "session_not_live" {
		t.Fatalf("dead-root cascade on production caller: want DENY session_not_live, got %s (%s)", cascade.GetVerdict(), cascade.GetMachineReadableReason())
	}
	if cascade.GetVerdict() == identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("dead-root cascade on production caller ALLOWed a live descendant of a dead root — the cascade did not bite")
	}
	if cascade.GetGrantRef() != "" {
		t.Fatalf("dead-root cascade DENY must not carry a grant_ref, got %q", cascade.GetGrantRef())
	}
	if cascade.GetExpiryUnixSeconds() != 0 {
		t.Fatalf("dead-root cascade DENY must not carry an expiry, got %d", cascade.GetExpiryUnixSeconds())
	}

	// Control leg: the SAME descendant presented UN-rooted (a non-chained token).
	// With no inherited root the cascade cannot fire, so the production caller
	// clears step 2's own-session liveness (the descendant IS live) and falls
	// through to out_of_grant (the descendant holds no grant) — NOT session_not_live.
	// This proves the cascade DENY above is driven by the dead ROOT, not by a dead
	// own session: the descendant is independently live.
	unrootedReq := &identityv1.ValidateRequest{
		PresentedCredential: identityvalidate.MintToken(testChainDescLiveRoot, testExpiryFarFuture, testServiceGitHub),
		SessionRef:          testSessionRef(testChainDescLiveRoot),
		ServiceId:           testServiceGitHub,
	}
	unrooted, err := refClient.Validate(ctx, unrootedReq)
	if err != nil {
		t.Fatalf("un-rooted descendant RefImpl.Validate: %v", err)
	}
	if unrooted.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY || unrooted.GetMachineReadableReason() != "out_of_grant" {
		t.Fatalf("un-rooted live descendant: want DENY out_of_grant (own session is live; no grant), got %s (%s) — if this is session_not_live the descendant's own session is dead and the cascade cell proves nothing",
			unrooted.GetVerdict(), unrooted.GetMachineReadableReason())
	}
}
