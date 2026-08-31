// SPDX-License-Identifier: Apache-2.0

package controlplane

// subtokenwiring.go is the PRODUCTION live-edge for the D18 fan-out sub-token leg
// (subtoken.go, doc 23 §5): it adapts the FROZEN dreamserpent.auth.v1
// TokenAttenuationServiceClient (whose DeriveAgentToken carries the generated
// `opts ...grpc.CallOption` tail) onto the package-local tokenAttenuator seam (no opts
// tail) so the rest of the package — and the synthetic tests — stay gRPC-free against
// the generated authv1fake (D50), exactly the DriverClient/ClientShim discipline
// dialregistry.go uses for the hypervisor driver and NewIdentityClients uses for the
// Identity link.
//
// WHY THE gRPC IMPORT LIVES HERE (the gRPC-confinement rule, CLAUDE.md). The auth SDK is
// reached ONLY through the frozen generated TokenAttenuationServiceClient (the one legal
// cross-tree import). This file is the SINGLE place in the sub-token leg that:
//   - holds the grpc dependency (the dial + the ClientConn), and
//   - drops the generated client's `opts ...grpc.CallOption` tail onto tokenAttenuator.
// wiring.go (the construction site) and main.go (the bootstrap) carry NO grpc import for
// this leg — they thread the narrow seam and the env-gated endpoint string respectively.
//
// LIVE-EDGE GATING (D50). The dial is a LIVE network edge: it opens a real gRPC
// connection to the auth SDK. So NewTokenAttenuatorClient is reached ONLY under
// main.go's DS_AUTHSDK_ENDPOINT gate (itself under DS_ORCH_LIVE=1), never in a test — the
// tests drive the seam over the generated authv1fake. This file imports grpc (subpackages
// of the already-declared google.golang.org/grpc require — NOT a new third-party
// dependency); the dial it performs is reached only on a live run.

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
)

// tokenAttenuationShim adapts the generated authv1.TokenAttenuationServiceClient onto the
// package-local tokenAttenuator seam (subtoken.go): it forwards DeriveAgentToken to the
// generated client, DROPPING the `opts ...grpc.CallOption` tail the seam does not carry.
// It is the production attenuator the fan-out injector derives through; tests substitute
// the generated authv1fake.TokenAttenuationServiceFake directly (it already satisfies
// tokenAttenuator natively — no opts tail — so no shim is needed in the test path).
//
// It holds the generated client by interface (TokenAttenuationServiceClient), so it is
// constructed over EITHER a dialed grpc.ClientConn (production, NewTokenAttenuatorClient)
// or any other client implementation, with no gRPC type leaking past this file.
type tokenAttenuationShim struct {
	client authv1.TokenAttenuationServiceClient
}

// Compile-time proof the shim satisfies the package-local seam.
var _ tokenAttenuator = tokenAttenuationShim{}

// DeriveAgentToken forwards to the generated client with no call options — the shim's sole
// job is to erase the `opts ...grpc.CallOption` tail so the generated client satisfies the
// no-opts tokenAttenuator seam (D50: the seam shape the authv1fake satisfies natively).
func (s tokenAttenuationShim) DeriveAgentToken(ctx context.Context, in *authv1.DeriveAgentTokenRequest) (*authv1.DeriveAgentTokenResponse, error) {
	return s.client.DeriveAgentToken(ctx, in)
}

// newTokenAttenuator wraps a generated TokenAttenuationServiceClient in the seam shim. It
// is the gRPC-free adapter core (it takes the generated client interface, not a
// grpc.ClientConn), so it is unit-testable over a fake client without a dial; the live
// dial constructor (NewTokenAttenuatorClient) builds the client from a ClientConn and
// hands it here.
func newTokenAttenuator(client authv1.TokenAttenuationServiceClient) tokenAttenuator {
	return tokenAttenuationShim{client: client}
}

// SubTokenAttenuatorClient is the live-edge handle main.go holds for the D18 sub-token
// leg: the tokenAttenuator seam wired into Deps.SubTokenAttenuator plus the dialed
// connection's Close, so the bootstrap registers one closer at shutdown (mirroring
// IdentityClients.Close). It confines the grpc.ClientConn to this file — main.go sees only
// the seam + the closer.
type SubTokenAttenuatorClient struct {
	// Attenuator is the package-local seam NewControlPlane installs onto the sub-token
	// injector (Deps.SubTokenAttenuator). It is the gRPC-erased face over the dialed
	// generated client.
	Attenuator tokenAttenuator
	conn       *grpc.ClientConn
}

// Close tears down the dialed connection at graceful shutdown (main.go registers it on the
// closer chain, like IdentityClients.Close). Nil-safe so a degraded/unwired handle is a
// no-op close.
func (c *SubTokenAttenuatorClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("controlplane: close auth-sdk TokenAttenuationService connection: %w", err)
	}
	return nil
}

// NewTokenAttenuatorClient dials the auth SDK's TokenAttenuationService at endpoint and
// assembles the D18 fan-out sub-token attenuator seam over it. It is the live-edge
// constructor main.go calls under DS_AUTHSDK_ENDPOINT (itself under DS_ORCH_LIVE=1); tests
// build the seam over the generated authv1fake via newTokenAttenuator instead, so a
// non-live run never dials (D50).
//
// The dialOpts default to an insecure transport (the internal, network-isolated
// orchestrator↔auth-SDK link, doc 15 §2): with an EMPTY dialOpts tail this applies
// defaultDialOpts (the same insecure posture the host-driver registry + the Identity dial
// take). A deployment that fronts this edge with mTLS supplies its own
// transport-credentials DialOption on the variadic tail — main.go threads the SAME
// DS_ORCH_TLS_CERT/KEY/CA-derived dialOpts the other live edges read, so all the live
// edges share one transport posture, additively, with no constructor change.
//
// An empty endpoint is rejected — a live run that opted into the sub-token leg with no
// auth-SDK endpoint must fail loudly at construction, never half-wire a dead attenuator.
func NewTokenAttenuatorClient(endpoint string, dialOpts ...DialOption) (*SubTokenAttenuatorClient, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("controlplane: NewTokenAttenuatorClient: empty auth-sdk endpoint (set DS_AUTHSDK_ENDPOINT for the dreamserpent.auth.v1 TokenAttenuationService)")
	}
	if len(dialOpts) == 0 {
		dialOpts = defaultDialOpts()
	}
	conn, err := grpc.NewClient(endpoint, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("controlplane: dial auth-sdk TokenAttenuationService (%s): %w", endpoint, err)
	}
	return &SubTokenAttenuatorClient{
		Attenuator: newTokenAttenuator(authv1.NewTokenAttenuationServiceClient(conn)),
		conn:       conn,
	}, nil
}
