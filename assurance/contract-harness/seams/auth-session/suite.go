// SPDX-License-Identifier: Apache-2.0

package authsession

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1/authv1fake"
)

// Synthetic fixtures (D50).  These identifiers are obviously synthetic — no
// real JTIs, scopes, or tokens.  synthNow is the fixed validation fence;
// an expiry <= synthNow is expired, one > synthNow is fresh.
const (
	synthNow = int64(1_700_000_000)

	synthParentJTI  = "jti-synthetic-parent-aaaa0001"
	synthParentExp  = synthNow + 900 // 15 min from synthNow
	synthDerivedJTI = "derived-synthetic-" + synthParentJTI
	synthHostIndex  = int32(3)
	synthOrgID      = "org-synthetic-test-0001"
)

var synthParentScopes = []string{"v1:code:read", "v1:code:write", "v1:network:egress"}
var synthSubsetScopes = []string{"v1:code:read"} // strict subset

// Suite is the TokenAttenuationService seam's single conformance suite (doc 06
// §3a: one suite, run against real + fake).  Every scenario is stated purely in
// terms of the frozen auth.v1 TokenAttenuationService contract (D126/D129, doc
// 23 §9), so the same suite is meaningful against any faithful attenuation
// substrate.  It exercises DeriveAgentToken and ListDerivedTokens across the
// three invariants: monotonic narrowing, cascade revocation, and JTI separation.
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "orchestrator(fan-out)<->auth(TokenAttenuationService.DeriveAgentToken+ListDerivedTokens)",
		Scenarios: scenarios(),
	}
}

func scenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			// 1. Happy-path: derive with scopes ⊂ parent → success, granted_scopes = requested.
			Name: "derive/happy-path-subset-scopes",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := authv1.NewTokenAttenuationServiceClient(conn)
				parentToken := MintUserAuthToken(synthParentJTI, synthParentExp, synthParentScopes...)
				resp, err := cl.DeriveAgentToken(ctx, &authv1.DeriveAgentTokenRequest{
					ParentUserAuthToken: parentToken,
					HostSessionIndex:    synthHostIndex,
					RequestedScopes:     synthSubsetScopes,
				})
				if err != nil {
					return statusObservation(err), nil
				}
				return deriveObservation(resp), nil
			},
		},
		{
			// 2. Derive with all parent scopes → success.
			Name: "derive/full-parent-scopes-allowed",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := authv1.NewTokenAttenuationServiceClient(conn)
				parentToken := MintUserAuthToken(synthParentJTI, synthParentExp, synthParentScopes...)
				resp, err := cl.DeriveAgentToken(ctx, &authv1.DeriveAgentTokenRequest{
					ParentUserAuthToken: parentToken,
					HostSessionIndex:    synthHostIndex,
					RequestedScopes:     synthParentScopes,
				})
				if err != nil {
					return statusObservation(err), nil
				}
				return deriveObservation(resp), nil
			},
		},
		{
			// 3. Requested scope not in parent → INVALID_ARGUMENT.
			Name: "derive/widened-scope-rejected",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := authv1.NewTokenAttenuationServiceClient(conn)
				parentToken := MintUserAuthToken(synthParentJTI, synthParentExp, synthParentScopes...)
				_, err := cl.DeriveAgentToken(ctx, &authv1.DeriveAgentTokenRequest{
					ParentUserAuthToken: parentToken,
					HostSessionIndex:    synthHostIndex,
					// v1:secrets:read is NOT in synthParentScopes → widening.
					RequestedScopes: []string{"v1:code:read", "v1:secrets:read"},
				})
				obs := dualrun.NewObservation()
				obs.Set("status", status.Code(err).String())
				return obs, nil
			},
		},
		{
			// 4. Lifetime > parent remaining → INVALID_ARGUMENT.
			Name: "derive/lifetime-widening-rejected",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := authv1.NewTokenAttenuationServiceClient(conn)
				parentToken := MintUserAuthToken(synthParentJTI, synthParentExp, synthParentScopes...)
				// Parent expires at synthNow+900.  Request lifetime > 900s from synthNow.
				_, err := cl.DeriveAgentToken(ctx, &authv1.DeriveAgentTokenRequest{
					ParentUserAuthToken: parentToken,
					HostSessionIndex:    synthHostIndex,
					RequestedScopes:     synthSubsetScopes,
					LifetimeSeconds:     int32(901),
				})
				obs := dualrun.NewObservation()
				obs.Set("status", status.Code(err).String())
				return obs, nil
			},
		},
		{
			// 5. After DeriveAgentToken, ListDerivedTokens returns that record.
			Name: "list/returns-derived-records",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := authv1.NewTokenAttenuationServiceClient(conn)
				parentToken := MintUserAuthToken(synthParentJTI, synthParentExp, synthParentScopes...)
				_, err := cl.DeriveAgentToken(ctx, &authv1.DeriveAgentTokenRequest{
					ParentUserAuthToken: parentToken,
					HostSessionIndex:    synthHostIndex,
					RequestedScopes:     synthSubsetScopes,
				})
				if err != nil {
					return statusObservation(err), nil
				}
				listResp, err := cl.ListDerivedTokens(ctx, &authv1.ListDerivedTokensRequest{
					ParentJti:      synthParentJTI,
					IncludeExpired: false,
				})
				if err != nil {
					return statusObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("token_count", "%d", len(listResp.GetTokens()))
				if len(listResp.GetTokens()) > 0 {
					t := listResp.GetTokens()[0]
					obs.Set("derived_jti", t.GetDerivedJti())
					obs.Setf("status_active", "%t",
						t.GetStatus() == authv1.DerivedTokenStatus_DERIVED_TOKEN_STATUS_ACTIVE)
				}
				return obs, nil
			},
		},
		{
			// 6. After cascade revoke, inactive records excluded when include_expired=false.
			Name: "list/include-revoked-false-excludes-revoked",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				// This scenario is driven by the dialers: both real and fake dialers seed
				// and revoke a dedicated parent JTI so the list returns zero active records.
				// The seam JTI for this scenario is a separate constant to avoid
				// interference with the standing fleet used by derive scenarios.
				const revokedParentJTI = "jti-synthetic-revoked-bbbb0002"
				cl := authv1.NewTokenAttenuationServiceClient(conn)
				listResp, err := cl.ListDerivedTokens(ctx, &authv1.ListDerivedTokensRequest{
					ParentJti:      revokedParentJTI,
					IncludeExpired: false,
				})
				if err != nil {
					return statusObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("active_count", "%d", len(listResp.GetTokens()))
				return obs, nil
			},
		},
		{
			// 7. derived_jti != parent_jti (token hierarchy separation).
			Name: "separation/derived-jti-differs-from-parent-jti",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := authv1.NewTokenAttenuationServiceClient(conn)
				parentToken := MintUserAuthToken(synthParentJTI, synthParentExp, synthParentScopes...)
				resp, err := cl.DeriveAgentToken(ctx, &authv1.DeriveAgentTokenRequest{
					ParentUserAuthToken: parentToken,
					HostSessionIndex:    synthHostIndex,
					RequestedScopes:     synthSubsetScopes,
				})
				if err != nil {
					return statusObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("jti_differs", "%t", resp.GetDerivedJti() != synthParentJTI)
				obs.Set("derived_jti_nonempty", fmt.Sprintf("%t", resp.GetDerivedJti() != ""))
				return obs, nil
			},
		},
	}
}

// --- Observation builders ----------------------------------------------------

func statusObservation(err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", status.Code(err).String())
	return obs
}

// deriveObservation records the contract-observable shape of a DeriveAgentToken
// response: gRPC status, derived_jti presence, scopes (sorted, joined), expiry.
func deriveObservation(resp *authv1.DeriveAgentTokenResponse) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", codes.OK.String())
	obs.Set("derived_jti", resp.GetDerivedJti())
	sorted := make([]string, len(resp.GetGrantedScopes()))
	copy(sorted, resp.GetGrantedScopes())
	// scopes are already sorted by the refimpl; record the canonical joined form.
	obs.Set("scopes", strings.Join(sorted, ","))
	obs.Setf("expiry_unix", "%d", resp.GetExpiresAtUnix())
	obs.Setf("agent_token_nonempty", "%t", len(resp.GetAgentToken()) > 0)
	return obs
}

// --- Dialers -----------------------------------------------------------------

// RealDialer returns the dual-run Dialer for the reference implementation,
// pre-seeded with the standing fleet of synthetic parent tokens.
func RealDialer() dualrun.Dialer {
	impl := NewRefImpl()
	seedFleet(impl)
	return dualrun.InProcess(impl.Register)
}

// FakeDialer returns the dual-run Dialer for the generated programmable fake,
// programmed to the honest contract by routing its responders at a mirror RefImpl
// seeded with the same fleet — the dual-run proves the fake is observationally
// identical to the real impl on every scenario (doc 06 §2.1).
func FakeDialer() dualrun.Dialer {
	f, mirror := programmedFake()
	seedFleet(mirror)
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		authv1fake.RegisterTokenAttenuationService(s, f)
	})
}

// seedFleet installs the standing token fleet on a reference impl.  Both dialers
// share this so the real and fake start from the same state.
func seedFleet(impl *RefImpl) {
	// Standing derivable parent (used by derive/* and separation/* scenarios).
	impl.SeedParentToken(synthParentJTI, synthParentScopes, synthParentExp)

	// Revoked parent for the list/include-revoked-false-excludes-revoked scenario.
	// We seed a derived token for it, then revoke the parent so ListDerivedTokens
	// with include_expired=false returns zero records.
	const revokedParentJTI = "jti-synthetic-revoked-bbbb0002"
	const revokedParentExp = synthNow + 300
	impl.SeedParentToken(revokedParentJTI, synthParentScopes, revokedParentExp)
	// Manually insert a derived record for the revoked parent so the list has
	// something to exclude.
	impl.mu.Lock()
	derivedJTI := "derived-synthetic-" + revokedParentJTI
	agentToken := MintAgentToken(derivedJTI, revokedParentJTI, synthHostIndex, revokedParentExp, synthSubsetScopes...)
	impl.derived[revokedParentJTI] = append(impl.derived[revokedParentJTI], &derivedRecord{
		derivedJTI: derivedJTI,
		parentJTI:  revokedParentJTI,
		hostIndex:  synthHostIndex,
		expUnix:    revokedParentExp,
		scopes:     synthSubsetScopes,
		tokenBytes: agentToken,
	})
	impl.mu.Unlock()
	impl.RevokeParentForTest(revokedParentJTI)
}

// programmedFake programs the generated fake to the honest contract by routing
// its method responders at a mirror RefImpl.  Returns both the fake (to
// register) and the mirror (so a dialer can pre-seed the fleet).
func programmedFake() (*authv1fake.TokenAttenuationServiceFake, *RefImpl) {
	f := authv1fake.NewTokenAttenuationServiceFake()
	mirror := NewRefImpl()
	f.DeriveAgentTokenResponder = mirror.DeriveAgentToken
	f.ListDerivedTokensResponder = mirror.ListDerivedTokens
	return f, mirror
}
