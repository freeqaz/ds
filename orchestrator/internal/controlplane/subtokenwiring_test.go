// SPDX-License-Identifier: Apache-2.0

package controlplane

// subtokenwiring_test.go drives the PRODUCTION wiring of the D18 fan-out sub-token leg
// (subtokenwiring.go) against synthetic fixtures (D50): the generated authv1fake stands in
// for the auth SDK, an in-memory sink stands in for the in-VM mount, and there is NO live
// VM/host-agent/auth-sdk dial. It asserts the two properties the wave's existing
// subtoken_test.go leaves untested:
//
//   (1) §5 RULE-3 LIFETIME (exp ≤ parent). A NON-ZERO LifetimeSeconds override resolved
//       by the subTokenAuthorityFunc flows through fanoutSubTokenFor → deriveAndMount onto
//       the DeriveAgentTokenRequest the auth SDK sees, so the orchestrator side honestly
//       requests the narrowed TTL the §5 rule-3 bound is computed against (the auth SDK is
//       the enforcer; this proves the override is PLUMBED, not dropped).
//
//   (2) LINEAGE RECORDING. The auth SDK's derived ExpiresAtUnix + DerivedJti come back on
//       the response and are surfaced by deriveAndMount (the jti) so the fan-out can record
//       the §5 rule-4 lineage chain for the revocation sweep (doc 23 §8 — the parent-jti
//       link severs in-flight upstream connections of revoked agents).
//
// It ALSO covers the gRPC→seam shim itself (tokenAttenuationShim / newTokenAttenuator):
// the shim erases the generated client's `opts ...grpc.CallOption` tail onto the no-opts
// tokenAttenuator seam, exercised over the generated client interface with no dial.

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1/authv1fake"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

const (
	// testSubTokenLifetimeOverride is a NON-ZERO §5 rule-3 lifetime narrowing the authority
	// resolves: the agent's sub-token TTL is capped at 5 minutes, strictly below the parent's
	// remaining lifetime. A zero override would let the auth SDK default to the parent's
	// remaining lifetime, so a non-zero value is what proves the override is PLUMBED.
	testSubTokenLifetimeOverride int32 = 300
	// testParentExpUnix is the parent user auth token's exp the lifetime-enforcing fake bounds
	// the derived exp against (§5 rule-3: derived exp ≤ parent exp). The derived exp is
	// parent_iat + lifetime, clamped to never exceed this.
	testParentExpUnix int64 = 1_700_000_900
	testParentIatUnix int64 = 1_700_000_000
)

// lifetimeAwareAttenuationFake returns a generated authv1fake fake that MODELS the §5
// rule-3 lifetime bound: it computes the derived exp from the requested LifetimeSeconds
// (parent_iat + lifetime) and CLAMPS it to never exceed the parent exp, then echoes the
// derived exp + a deterministic jti back. It is the lifetime twin of subtoken_test.go's
// programmedAttenuationFake (which models the rule-1 scope subset), so the test reads the
// bounded exp + jti off the response exactly as the real AttenuationServer would return them.
func lifetimeAwareAttenuationFake() *authv1fake.TokenAttenuationServiceFake {
	f := authv1fake.NewTokenAttenuationServiceFake()
	f.DeriveAgentTokenResponder = func(_ context.Context, req *authv1.DeriveAgentTokenRequest) (*authv1.DeriveAgentTokenResponse, error) {
		derivedExp := testParentExpUnix // zero lifetime defaults to the parent's remaining lifetime (full parent exp).
		if lt := req.GetLifetimeSeconds(); lt > 0 {
			derivedExp = testParentIatUnix + int64(lt)
			if derivedExp > testParentExpUnix {
				derivedExp = testParentExpUnix // §5 rule-3: clamp to the parent exp.
			}
		}
		return &authv1.DeriveAgentTokenResponse{
			AgentToken:    []byte("derived-biscuit-lineage-" + req.GetSessionRef().GetSessionUuid()),
			DerivedJti:    "lineage-jti-for-index-9",
			ExpiresAtUnix: derivedExp,
			GrantedScopes: req.GetRequestedScopes(),
		}, nil
	}
	return f
}

// TestSubToken_LifetimeOverrideReachesDerive proves the §5 rule-3 lifetime override is
// PLUMBED end-to-end through the orchestrator fan-out: a non-zero LifetimeSeconds resolved
// by the authority flows through fanoutSubTokenFor onto the DeriveAgentTokenRequest the auth
// SDK sees, and the auth SDK's bounded derived exp (≤ parent exp) comes back on the response.
// It also asserts the derived ExpiresAtUnix + DerivedJti are surfaced for the §5 rule-4
// revocation-sweep lineage. Synthetic: the generated authv1fake + an in-memory sink (D50).
func TestSubToken_LifetimeOverrideReachesDerive(t *testing.T) {
	att := lifetimeAwareAttenuationFake()
	sink := newMemSubTokenSink()
	sink.MountDir = testFanoutMountDir
	in := newSubTokenInjector(att, sink)

	// Project the per-VM fan-out input off a created-session record + the resolved authority,
	// carrying the NON-ZERO §5 rule-3 lifetime override. fanoutSubTokenFor is the single place
	// the §5 request is shaped — the override rides it onto the wire request.
	sess := store.Session{Ref: store.SessionRef{SessionUUID: "sess-lineage", HostSessionIndex: 9}}
	ft := fanoutSubTokenFor(sess, testParentUserAuthToken, testRequestSubset, testSubTokenLifetimeOverride)
	if ft.lifetimeSeconds != testSubTokenLifetimeOverride {
		t.Fatalf("fanoutSubTokenFor lifetimeSeconds = %d, want %d (the §5 rule-3 override must be carried)", ft.lifetimeSeconds, testSubTokenLifetimeOverride)
	}

	path, jti, err := in.deriveAndMount(context.Background(), ft)
	if err != nil {
		t.Fatalf("deriveAndMount: unexpected error: %v", err)
	}

	// The derive must have seen the non-zero override on the wire request (§5 rule-3 plumbed).
	calls := att.DeriveAgentTokenRecorded()
	if len(calls) != 1 {
		t.Fatalf("DeriveAgentToken calls = %d, want exactly 1", len(calls))
	}
	if got := calls[0].Req.GetLifetimeSeconds(); got != testSubTokenLifetimeOverride {
		t.Errorf("DeriveAgentTokenRequest.LifetimeSeconds = %d, want %d (the non-zero §5 rule-3 override reaches the derive)", got, testSubTokenLifetimeOverride)
	}
	if got := calls[0].Req.GetHostSessionIndex(); got != 9 {
		t.Errorf("DeriveAgentTokenRequest.HostSessionIndex = %d, want 9 (the launched VM's index, §5 rule-2 audience)", got)
	}

	// The auth SDK's derived exp is bounded by §5 rule-3 (≤ parent exp): with a 300s override
	// off parent_iat the derived exp is parent_iat+300, strictly below the parent exp.
	wantExp := testParentIatUnix + int64(testSubTokenLifetimeOverride)
	resp, derr := att.DeriveAgentToken(context.Background(), &authv1.DeriveAgentTokenRequest{
		ParentUserAuthToken: testParentUserAuthToken,
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: "sess-lineage"},
		HostSessionIndex:    9,
		RequestedScopes:     testRequestSubset,
		LifetimeSeconds:     testSubTokenLifetimeOverride,
	})
	if derr != nil {
		t.Fatalf("re-derive for exp assertion: %v", derr)
	}
	if resp.GetExpiresAtUnix() != wantExp {
		t.Errorf("derived ExpiresAtUnix = %d, want %d (parent_iat + override, ≤ parent exp — §5 rule-3)", resp.GetExpiresAtUnix(), wantExp)
	}
	if resp.GetExpiresAtUnix() > testParentExpUnix {
		t.Errorf("derived ExpiresAtUnix %d exceeds parent exp %d (§5 rule-3 violated)", resp.GetExpiresAtUnix(), testParentExpUnix)
	}

	// LINEAGE: the derived jti is surfaced by deriveAndMount (the §5 rule-4 revocation-sweep
	// handle), and the token landed at the documented well-known mount path.
	if jti != "lineage-jti-for-index-9" {
		t.Errorf("derived jti = %q, want lineage-jti-for-index-9 (recorded for the §5 rule-4 lineage chain)", jti)
	}
	wantPath := AgentSubTokenMountPath(testFanoutMountDir, 9)
	if path != wantPath {
		t.Errorf("mount path = %q, want %q", path, wantPath)
	}
	if _, ok := sink.tokenAt(wantPath); !ok {
		t.Errorf("no token mounted at the documented well-known path %q", wantPath)
	}
}

// TestSubToken_ZeroLifetimeDefaultsToParent proves the §5 rule-3 default arm: a ZERO
// override leaves LifetimeSeconds 0 on the wire (the auth SDK then defaults to the parent's
// remaining lifetime — the full parent exp). This is the complementary case to the override
// arm above, so the "non-zero override is meaningful" assertion is not vacuous.
func TestSubToken_ZeroLifetimeDefaultsToParent(t *testing.T) {
	att := lifetimeAwareAttenuationFake()
	sink := newMemSubTokenSink()
	in := newSubTokenInjector(att, sink)

	sess := store.Session{Ref: store.SessionRef{SessionUUID: "sess-default", HostSessionIndex: 3}}
	ft := fanoutSubTokenFor(sess, testParentUserAuthToken, testRequestSubset, 0)

	if _, jti, err := in.deriveAndMount(context.Background(), ft); err != nil {
		t.Fatalf("deriveAndMount: %v", err)
	} else if jti == "" {
		t.Fatalf("derived jti empty — lineage handle missing")
	}

	calls := att.DeriveAgentTokenRecorded()
	if len(calls) != 1 {
		t.Fatalf("DeriveAgentToken calls = %d, want exactly 1", len(calls))
	}
	if got := calls[0].Req.GetLifetimeSeconds(); got != 0 {
		t.Errorf("DeriveAgentTokenRequest.LifetimeSeconds = %d, want 0 (zero override defers to the auth SDK's parent-remaining default)", got)
	}
}

// generatedClientOverFake presents the GENERATED TokenAttenuationServiceClient interface
// (the real `opts ...grpc.CallOption` shape the shim must erase) over the generated server
// fake's recorded behavior, WITHOUT a gRPC connection: DeriveAgentToken forwards to the
// fake's server method and IGNORES the opts tail (an in-process call, no dial — D50). It
// satisfies the generated client interface natively (matching method signature), so the
// production shim consumes it exactly as it would the dialed client, exercising the
// opts-erasure path. ListDerivedTokens rides the embedded interface (unused — forward-compat).
type generatedClientOverFake struct {
	authv1.TokenAttenuationServiceClient // embeds the generated interface (ListDerivedTokens unused)
	server                               *authv1fake.TokenAttenuationServiceFake
	gotOpts                              int // count of CallOptions the shim forwarded (must be 0 — tail dropped)
}

func (c *generatedClientOverFake) DeriveAgentToken(ctx context.Context, in *authv1.DeriveAgentTokenRequest, opts ...grpc.CallOption) (*authv1.DeriveAgentTokenResponse, error) {
	c.gotOpts = len(opts)
	return c.server.DeriveAgentToken(ctx, in)
}

// Compile-time proof the in-process stand-in satisfies the GENERATED client interface (so the
// shim consumes it exactly as the dialed client).
var _ authv1.TokenAttenuationServiceClient = (*generatedClientOverFake)(nil)

// TestTokenAttenuationShim_DropsOptsTail proves the gRPC→seam shim adapts the generated
// TokenAttenuationServiceClient (with the `opts ...grpc.CallOption` tail) onto the no-opts
// tokenAttenuator seam: the production shim forwards DeriveAgentToken to the generated client
// with ZERO call options (the tail is dropped) and returns the client's response unchanged.
// It is driven over an in-process generated-client stand-in backed by the programmed fake —
// no dial, no gRPC connection (D50) — so the seam adaptation is exercised exactly as the live
// dial would present it, while the grpc dependency stays confined to subtokenwiring.go.
func TestTokenAttenuationShim_DropsOptsTail(t *testing.T) {
	fakeServer := lifetimeAwareAttenuationFake()
	client := &generatedClientOverFake{server: fakeServer}

	att := newTokenAttenuator(client) // production constructor — returns the tokenAttenuationShim
	if _, ok := att.(tokenAttenuationShim); !ok {
		t.Fatalf("newTokenAttenuator returned %T, want tokenAttenuationShim (the production seam adapter)", att)
	}

	resp, err := att.DeriveAgentToken(context.Background(), &authv1.DeriveAgentTokenRequest{
		ParentUserAuthToken: testParentUserAuthToken,
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: "shim-sess"},
		HostSessionIndex:    9,
		RequestedScopes:     testRequestSubset,
		LifetimeSeconds:     testSubTokenLifetimeOverride,
	})
	if err != nil {
		t.Fatalf("shim DeriveAgentToken: %v", err)
	}
	if client.gotOpts != 0 {
		t.Errorf("shim forwarded %d grpc.CallOption(s), want 0 (the seam carries no opts tail — the shim drops it)", client.gotOpts)
	}
	if resp.GetDerivedJti() != "lineage-jti-for-index-9" {
		t.Errorf("shim returned jti = %q, want lineage-jti-for-index-9 (the response flows through unchanged)", resp.GetDerivedJti())
	}
	if got := len(fakeServer.DeriveAgentTokenRecorded()); got != 1 {
		t.Errorf("DeriveAgentToken forwarded %d times, want exactly 1 (the shim forwards once)", got)
	}
	if got := fakeServer.DeriveAgentTokenRecorded()[0].Req.GetLifetimeSeconds(); got != testSubTokenLifetimeOverride {
		t.Errorf("forwarded LifetimeSeconds = %d, want %d (the request reaches the client intact through the shim)", got, testSubTokenLifetimeOverride)
	}
}
