// SPDX-License-Identifier: Apache-2.0

package controlplane

// subtoken_test.go drives the orchestrator's D18 fan-out sub-token seam (subtoken.go,
// doc 23 §5) against synthetic fixtures (D50): the generated authv1fake
// TokenAttenuationService fake stands in for the auth SDK, an in-memory sink stands in
// for the in-VM mount, and there is NO live VM/host-agent/auth-sdk service. The tests
// assert the three acceptance properties:
//
//   (a) the fan-out calls TokenAttenuationService.DeriveAgentToken EXACTLY ONCE per VM,
//       with that VM's host_session_index + a requested-scope SUBSET of the parent scopes;
//   (b) a scope-WIDENING request surfaces as an error/rejection (the auth SDK returns
//       codes.InvalidArgument; the handler propagates it, mounting nothing);
//   (c) the derived token lands at the documented well-known in-VM mount path.

import (
	"context"
	"math"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1/authv1fake"
)

const (
	testParentUserAuthToken = "parent-user-auth-token-jwt"
	// testParentScopes is the parent ds_scopes the fan-out narrows from (doc 23 §6).
	// The fan-out requests a strict SUBSET for the agent.
	testFanoutMountDir = "/run/ds/agent-token-test"
)

var (
	testParentScopes  = []string{"v1:code:read", "v1:code:write", "v1:network:egress", "v1:identity:mint"}
	testRequestSubset = []string{"v1:code:read", "v1:network:egress"} // a strict subset (the narrowed agent grant)
	testRequestWiden  = []string{"v1:code:read", "v1:secrets:read"}   // v1:secrets:read NOT in the parent → widening
)

// subsetOf reports whether want is a subset of have (the §5 rule-1 monotonicity the auth
// SDK enforces; the fake below models it so a widening request is rejected exactly as the
// real AttenuationServer rejects it).
func subsetOf(want, have []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

// programmedAttenuationFake returns a generated authv1fake TokenAttenuationService fake
// programmed to model the auth SDK's §5 attenuation contract: it grants the requested
// scopes when they are a SUBSET of the parent (echoing them back as the authoritative
// granted set), and rejects a WIDENING request with codes.InvalidArgument (the
// attenuation.ErrScopeWidening → status the real AttenuationServer returns, doc 23 §5
// rule 1). The fake records every call so the test asserts the exactly-once property.
func programmedAttenuationFake() *authv1fake.TokenAttenuationServiceFake {
	f := authv1fake.NewTokenAttenuationServiceFake()
	f.DeriveAgentTokenResponder = func(_ context.Context, req *authv1.DeriveAgentTokenRequest) (*authv1.DeriveAgentTokenResponse, error) {
		if !subsetOf(req.GetRequestedScopes(), testParentScopes) {
			return nil, status.Errorf(codes.InvalidArgument,
				"DeriveAgentToken: requested scopes exceed parent scopes (D126 monotonicity)")
		}
		return &authv1.DeriveAgentTokenResponse{
			AgentToken:    []byte("derived-biscuit-for-index-" + req.GetSessionRef().GetSessionUuid()),
			DerivedJti:    "d-test-jti",
			ExpiresAtUnix: 1_700_000_900,
			GrantedScopes: req.GetRequestedScopes(),
		}, nil
	}
	return f
}

// fixedAuthority returns a subTokenAuthorityFunc that resolves a fixed parent token +
// requested-scope subset for every create (the IdP-boundary resolution the seam stands in
// for, doc 16 §3.2). The frozen CreateSessionRequest carries only the launching_user
// subject, so this is where the parent token + scopes enter at the orchestrator side.
func fixedAuthority(parentToken string, scopes []string) subTokenAuthorityFunc {
	return func(_ context.Context, _ *orchestratorv1.CreateSessionRequest) (string, []string, int32) {
		return parentToken, scopes, 0
	}
}

// TestCreateSession_FansOutSubToken proves the three acceptance properties end-to-end
// through the CreateSession handler: a valid create derives EXACTLY ONE sub-token for the
// launched VM (the §4.1 step-4 host_session_index 7 the driver fake binds), the derive
// carries that index + the requested-scope SUBSET, and the derived token lands at the
// documented well-known in-VM mount path. No live VM/auth-sdk — the generated fake + the
// in-memory sink (D50).
func TestCreateSession_FansOutSubToken(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	att := programmedAttenuationFake()
	sink := &memSubTokenSink{byIndex: map[uint64][]byte{}, byPath: map[string][]byte{}, MountDir: testFanoutMountDir}
	f.cp.Sessions.SetSubTokenServing(
		newSubTokenInjector(att, sink),
		fixedAuthority(testParentUserAuthToken, testRequestSubset),
	)

	resp, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: unexpected error: %v", err)
	}
	idx := resp.GetSession().GetHostSessionIndex()
	if idx != 7 {
		t.Fatalf("host_session_index = %d, want 7 (the §4.1 step-4 binding)", idx)
	}

	// (a) EXACTLY ONE derive call, for THIS VM's host_session_index, with the SUBSET.
	calls := att.DeriveAgentTokenRecorded()
	if len(calls) != 1 {
		t.Fatalf("DeriveAgentToken calls = %d, want exactly 1 per VM", len(calls))
	}
	got := calls[0].Req
	if got.GetParentUserAuthToken() != testParentUserAuthToken {
		t.Errorf("derive parent token = %q, want %q", got.GetParentUserAuthToken(), testParentUserAuthToken)
	}
	if got.GetHostSessionIndex() != int32(idx) {
		t.Errorf("derive host_session_index = %d, want %d (the launched VM's index)", got.GetHostSessionIndex(), idx)
	}
	if !subsetOf(got.GetRequestedScopes(), testParentScopes) {
		t.Errorf("derive requested_scopes %v not a subset of parent %v (§5 rule 1)", got.GetRequestedScopes(), testParentScopes)
	}
	if len(got.GetRequestedScopes()) >= len(testParentScopes) {
		t.Errorf("derive requested_scopes %v should be a STRICT narrowing of parent %v", got.GetRequestedScopes(), testParentScopes)
	}
	if got.GetSessionRef().GetSessionUuid() != resp.GetSession().GetSessionUuid() {
		t.Errorf("derive session_ref uuid = %q, want %q", got.GetSessionRef().GetSessionUuid(), resp.GetSession().GetSessionUuid())
	}

	// (c) The derived token landed at the documented well-known in-VM mount path.
	wantPath := AgentSubTokenMountPath(testFanoutMountDir, idx)
	tok, ok := sink.tokenAt(wantPath)
	if !ok {
		t.Fatalf("no sub-token mounted at the documented well-known path %q", wantPath)
	}
	if len(tok) == 0 {
		t.Errorf("mounted sub-token at %q is empty", wantPath)
	}
}

// TestCreateSession_SubTokenScopeWideningRejected proves property (b): a fan-out that
// requests a scope the parent does NOT carry is REJECTED — the auth SDK returns
// codes.InvalidArgument (the §5 rule-1 monotonicity refusal), the handler propagates that
// code as the create's error, and NOTHING is mounted (a token the service refused never
// lands at the mount path).
func TestCreateSession_SubTokenScopeWideningRejected(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	att := programmedAttenuationFake()
	sink := &memSubTokenSink{byIndex: map[uint64][]byte{}, byPath: map[string][]byte{}, MountDir: testFanoutMountDir}
	f.cp.Sessions.SetSubTokenServing(
		newSubTokenInjector(att, sink),
		fixedAuthority(testParentUserAuthToken, testRequestWiden), // requests a scope the parent lacks
	)

	_, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err == nil {
		t.Fatal("CreateSession: expected a scope-widening rejection, got nil")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("scope-widening rejection code = %v, want InvalidArgument (§5 rule 1)", status.Code(err))
	}

	// The auth SDK was still CALLED once (the rejection is the SDK's, surfaced) ...
	if got := len(att.DeriveAgentTokenRecorded()); got != 1 {
		t.Errorf("DeriveAgentToken calls = %d, want 1 (the rejected derive)", got)
	}
	// ... but NOTHING was mounted (a refused token never lands at the mount path).
	if got := len(sink.byPath); got != 0 {
		t.Errorf("mounted %d sub-tokens on a rejected widening, want 0", got)
	}
}

// TestCreateSession_NoSubTokenSeamIsNoOp proves the seam is ADDITIVE: a handler with no
// sub-token leg wired derives + mounts nothing and the create still reaches ATTACHED
// (the existing CreateSession behavior is unweakened — no derive, no mount, no error).
func TestCreateSession_NoSubTokenSeamIsNoOp(t *testing.T) {
	f := newFixture(t, fixtureOpts{}) // no SetSubTokenServing

	resp, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession with no sub-token leg: unexpected error: %v", err)
	}
	if resp.GetSession().GetHostSessionIndex() != 7 {
		t.Errorf("host_session_index = %d, want 7 (create unaffected)", resp.GetSession().GetHostSessionIndex())
	}
}

// TestCreateSession_NoParentAuthoritySkipsDerive proves the "no parent, no derive" path:
// when the authority seam resolves an EMPTY parent token (the unauthenticated launch / a
// deployment that mints no user auth token), the injector skips the derive entirely — no
// call, no mount, no error — and the create is unaffected.
func TestCreateSession_NoParentAuthoritySkipsDerive(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	att := programmedAttenuationFake()
	sink := newMemSubTokenSink()
	f.cp.Sessions.SetSubTokenServing(
		newSubTokenInjector(att, sink),
		fixedAuthority("", testRequestSubset), // empty parent token
	)

	if _, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq()); err != nil {
		t.Fatalf("CreateSession: unexpected error: %v", err)
	}
	if got := len(att.DeriveAgentTokenRecorded()); got != 0 {
		t.Errorf("DeriveAgentToken calls = %d, want 0 (no parent authority → skip)", got)
	}
	if got := len(sink.byPath); got != 0 {
		t.Errorf("mounted %d sub-tokens with no parent authority, want 0", got)
	}
}

// TestAgentSubTokenMountPath_DocumentedPath pins the documented well-known in-VM mount
// path shape (doc 23 §5): <DefaultAgentSubTokenMountDir>/<host_session_index>.token by
// default, and an explicit dir composes the same way. This is the single source of the
// path the production sink writes and an in-VM reader resolves.
func TestAgentSubTokenMountPath_DocumentedPath(t *testing.T) {
	if got := AgentSubTokenMountPath("", 7); got != "/run/ds/agent-token/7.token" {
		t.Errorf("default mount path = %q, want /run/ds/agent-token/7.token", got)
	}
	if got := AgentSubTokenMountPath("/custom/dir", 42); got != "/custom/dir/42.token" {
		t.Errorf("explicit mount path = %q, want /custom/dir/42.token", got)
	}
}

// TestDeriveAndMount_OnePerVM unit-tests the injector directly: deriveAndMount makes
// EXACTLY ONE derive call and mounts the returned token at the documented path, returning
// that path + the derived jti. This isolates the one-call + mount-path properties from the
// full create spine.
func TestDeriveAndMount_OnePerVM(t *testing.T) {
	att := programmedAttenuationFake()
	sink := &memSubTokenSink{byIndex: map[uint64][]byte{}, byPath: map[string][]byte{}, MountDir: testFanoutMountDir}
	in := newSubTokenInjector(att, sink)

	ft := fanoutSubToken{
		parentUserAuthToken: testParentUserAuthToken,
		hostSessionIndex:    9,
		requestedScopes:     testRequestSubset,
	}
	path, jti, err := in.deriveAndMount(context.Background(), ft)
	if err != nil {
		t.Fatalf("deriveAndMount: unexpected error: %v", err)
	}
	if len(att.DeriveAgentTokenRecorded()) != 1 {
		t.Fatalf("DeriveAgentToken calls = %d, want exactly 1", len(att.DeriveAgentTokenRecorded()))
	}
	wantPath := AgentSubTokenMountPath(testFanoutMountDir, 9)
	if path != wantPath {
		t.Errorf("mount path = %q, want %q", path, wantPath)
	}
	if jti != "d-test-jti" {
		t.Errorf("derived jti = %q, want d-test-jti", jti)
	}
	if _, ok := sink.tokenAt(wantPath); !ok {
		t.Errorf("no token mounted at %q", wantPath)
	}
}

// TestDeriveAndMount_OutOfRangeIndexFailsClosed proves the §5 rule-2 fail-closed guard:
// a hostSessionIndex > math.MaxInt32 would SILENTLY WRAP under the int32() cast on the
// frozen DeriveAgentTokenRequest.host_session_index field, mis-attributing the derived
// sub-token's aud to the WRONG VM. deriveAndMount must REJECT it — return a non-nil
// error, NEVER call DeriveAgentToken (the guard short-circuits before the derive), and
// mount nothing. The valid in-range arm proves the guard is non-vacuous (no regression).
func TestDeriveAndMount_OutOfRangeIndexFailsClosed(t *testing.T) {
	att := programmedAttenuationFake()
	sink := &memSubTokenSink{byIndex: map[uint64][]byte{}, byPath: map[string][]byte{}, MountDir: testFanoutMountDir}
	in := newSubTokenInjector(att, sink)

	// Out-of-range arm: an index just past int32 max must be refused, fail-closed.
	ft := fanoutSubToken{
		parentUserAuthToken: testParentUserAuthToken,
		hostSessionIndex:    uint64(math.MaxInt32) + 1,
		requestedScopes:     testRequestSubset,
	}
	path, jti, err := in.deriveAndMount(context.Background(), ft)
	if err == nil {
		t.Fatal("deriveAndMount: expected an out-of-range index rejection, got nil error")
	}
	if path != "" || jti != "" {
		t.Errorf("deriveAndMount on a rejected index returned path=%q jti=%q, want both empty", path, jti)
	}
	// The guard short-circuits BEFORE the derive: the attenuator must never be called.
	if got := len(att.DeriveAgentTokenRecorded()); got != 0 {
		t.Errorf("DeriveAgentToken calls = %d on an out-of-range index, want 0 (guard short-circuits)", got)
	}
	// Nothing mounted — a sub-token the guard refused never lands at the mount path.
	if got := len(sink.byPath); got != 0 {
		t.Errorf("mounted %d sub-tokens on a rejected out-of-range index, want 0", got)
	}

	// Non-vacuity arm: a valid in-range index still derives + mounts (no regression).
	ftOK := fanoutSubToken{
		parentUserAuthToken: testParentUserAuthToken,
		hostSessionIndex:    11,
		requestedScopes:     testRequestSubset,
	}
	okPath, okJTI, okErr := in.deriveAndMount(context.Background(), ftOK)
	if okErr != nil {
		t.Fatalf("deriveAndMount on a valid in-range index: unexpected error: %v", okErr)
	}
	if got := len(att.DeriveAgentTokenRecorded()); got != 1 {
		t.Fatalf("DeriveAgentToken calls = %d after the valid derive, want exactly 1", got)
	}
	wantPath := AgentSubTokenMountPath(testFanoutMountDir, 11)
	if okPath != wantPath {
		t.Errorf("mount path = %q, want %q", okPath, wantPath)
	}
	if okJTI != "d-test-jti" {
		t.Errorf("derived jti = %q, want d-test-jti", okJTI)
	}
	if _, ok := sink.tokenAt(wantPath); !ok {
		t.Errorf("no token mounted at %q on the valid in-range index", wantPath)
	}
}
