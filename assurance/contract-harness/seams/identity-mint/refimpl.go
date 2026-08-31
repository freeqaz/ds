// SPDX-License-Identifier: Apache-2.0

package identitymint

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// Synthetic root-hierarchy markers (D50, D82). The minted interception-CA
// material is tagged with the INTERCEPTION-root identifier and NEVER the
// workload-identity-root one — the doc 16 §4 / D82 separation property the suite
// asserts where it is observable on this seam: an interception-root signature
// can never validate as a workload identity, so the egress-gateway
// TLS-termination capability and the attribution capability fail independently.
// Both are obviously-synthetic constants; the workload marker exists only as the
// value the minted CA must NOT carry.
const (
	// synthInterceptionRootID tags every byte of minted interception-CA material
	// (hierarchy 2, D82). It is the only root this seam's mint signs under.
	synthInterceptionRootID = "ds-synthetic-interception-root-h2"

	// synthWorkloadRootID is the workload-identity root (hierarchy 1, D82) — the
	// SEPARATE hierarchy. It never appears in interception-CA material; the suite
	// asserts its absence to prove the separation holds where observable.
	synthWorkloadRootID = "ds-synthetic-workload-root-h1"

	// synthCAExpiryBase is the synthetic per-session CA expiry the reference impl
	// stamps (lifetime = session, doc 16 §4). Obviously-synthetic, deterministic.
	synthCAExpiryBase = int64(1_700_000_000)
)

// RefImpl is a minimal honest reference implementation of IdentityMintService —
// the "real implementation" side of the dual-run. It implements exactly the
// doc 16 §4 interception-CA mint contract: MintInterceptionCA is idempotent on
// the session key (the request's SessionRef.session_uuid), so a re-issue for the
// same session returns the SAME per-session CA material — same cert, key, and
// expiry — never a freshly-allocated second CA. Per-session CA material is
// session-lifecycle data (the D72-exempt class, doc 16 §4), so the mint is a
// once-per-session allocation reused on retry.
//
// Every minted CA is signed under the INTERCEPTION root (hierarchy 2, D82) and
// carries that root's identifier — never the workload-identity root's (hierarchy
// 1). That is the observable face of the D82 separation on this seam: compromise
// of the interception capability never yields workload-identity signing.
//
// This is the M0 stand-in until the production Identity mint service (a skeleton
// today) lands. When that lands it replaces RefImpl as the "real" end and the
// conformance suite is unchanged — which is the whole point: the suite is the
// contract, not the implementation.
//
// State is held in-memory, keyed by session_uuid; access is mutex-guarded so the
// in-process gRPC server is safe under concurrent calls. CA material is
// content-derived from the session key so the reference impl and a fake
// programmed to the same contract observe identically. Synthetic fixtures only
// (D50): the cert/key bytes are obviously-synthetic short tags, never real PEM.
type RefImpl struct {
	identityv1.UnimplementedIdentityMintServiceServer

	mu  sync.Mutex
	cas map[string]*identityv1.MintInterceptionCAResponse
}

// NewRefImpl returns a reference IdentityMintService server with an empty store.
func NewRefImpl() *RefImpl {
	return &RefImpl{cas: map[string]*identityv1.MintInterceptionCAResponse{}}
}

// MintInterceptionCA mints the per-session interception CA (doc 16 §4) and
// returns the per-session CA material. Idempotent on the session key: the CA is
// keyed by the request's SessionRef.session_uuid, so a re-issue for the SAME
// session finds the existing CA and returns it verbatim — the per-session CA is
// allocated ONCE and reused, never a duplicate (per-session-lifecycle data, the
// D72-exempt class, doc 16 §4). The material is minted under the interception
// root (hierarchy 2, D82) and carries that root's identifier, never the
// workload-identity root's. A request missing the session_ref join key is
// refused InvalidArgument before any CA is materialized (honest error path).
func (s *RefImpl) MintInterceptionCA(_ context.Context, req *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
	uuid := req.GetSessionRef().GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "MintInterceptionCARequest.session_ref.session_uuid is required (the identity-plane join key)")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.cas[uuid]; ok {
		// Idempotent re-issue: same session -> same per-session CA material.
		return existing, nil
	}

	resp := mintInterceptionCA(uuid)
	s.cas[uuid] = resp
	return resp, nil
}

// Register registers the reference impl on a grpc.ServiceRegistrar.
func (s *RefImpl) Register(reg grpc.ServiceRegistrar) {
	identityv1.RegisterIdentityMintServiceServer(reg, s)
}

// mintInterceptionCA synthesizes the per-session interception-CA response
// deterministically from the session uuid (doc 16 §4). The cert and key bytes
// are obviously-synthetic tags that EMBED the interception-root identifier
// (hierarchy 2, D82) and NEVER the workload-identity root — so a fake programmed
// to the same derivation mints byte-identical material, and the suite can read
// the root tag back off the minted material to prove the D82 separation holds
// where observable. Synthetic fixtures only (D50).
func mintInterceptionCA(uuid string) *identityv1.MintInterceptionCAResponse {
	return &identityv1.MintInterceptionCAResponse{
		CaCertificate:     syntheticCACertificate(uuid),
		CaPrivateKey:      syntheticCAPrivateKey(uuid),
		ExpiryUnixSeconds: synthCAExpiryBase + int64(len(uuid)),
	}
}

// syntheticCACertificate builds the obviously-synthetic per-session CA cert
// bytes. It is NOT real PEM — it is a synthetic tag that carries the
// interception-root identifier (hierarchy 2, D82) so the suite can assert the
// material is interception-rooted, plus the session uuid so a re-issue is
// byte-identical. Synthetic fixtures only (D50).
func syntheticCACertificate(uuid string) []byte {
	return []byte("ds-synthetic-ca-cert/root=" + synthInterceptionRootID + "/session=" + uuid)
}

// syntheticCAPrivateKey builds the obviously-synthetic per-session CA private
// key bytes — proxy-bound, session-lifetime material (doc 16 §4). It is NOT a
// real key: a synthetic tag carrying the interception-root identifier and the
// session uuid. Synthetic fixtures only (D50).
func syntheticCAPrivateKey(uuid string) []byte {
	return []byte("ds-synthetic-ca-key/root=" + synthInterceptionRootID + "/session=" + uuid)
}

// MintedCAFor exposes the deterministic synthetic interception-CA material for a
// session so the external _test package can program an honest MintInterceptionCA
// responder on a hand-built fake (the negative-test drifted fake) and assert the
// expected mint shape. Synthetic fixtures only (D50).
func MintedCAFor(uuid string) *identityv1.MintInterceptionCAResponse {
	return mintInterceptionCA(uuid)
}

// InterceptionRootID / WorkloadRootID expose the synthetic D82 root identifiers
// so the external _test package can assert the separation property without
// re-declaring the markers. Synthetic fixtures only (D50).
func InterceptionRootID() string { return synthInterceptionRootID }

func WorkloadRootID() string { return synthWorkloadRootID }

// SessionRef builds a synthetic identity-plane join-key SessionRef for a session
// uuid (the request key MintInterceptionCA is idempotent on). SessionRef is the
// shared boundary.v1 canonical message (doc 14 §2/§4), imported never redefined.
// Synthetic fixtures only (D50).
func SessionRef(uuid string) *boundaryv1.SessionRef {
	return &boundaryv1.SessionRef{SessionUuid: uuid}
}
