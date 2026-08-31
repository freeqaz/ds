// SPDX-License-Identifier: Apache-2.0

// Package attenuation implements DeriveAgentToken (D126) — the TokenAttenuationService
// consumed exclusively by the orchestrator fan-out path (D18).
//
// At D18 fan-out time, the orchestrator calls DeriveAgentToken once per agent VM.
// The derived sub-token is a Biscuit (D98 primary substrate) with:
//   - scopes ⊆ parent JWT scopes (monotonic narrowing, D126)
//   - aud = host_session_index (the agent VM index within the session)
//   - exp ≤ parent JWT exp
//   - ds_parent_jti = parent JWT jti (revocation lineage chain, D126)
//
// The Biscuit signing key is a fresh Ed25519 keypair per-service-instance
// (same third-context discipline as identity/mint, D99).
//
// IMPORTANT: The agent sub-token Biscuit is NEWLY MINTED (not attenuating the
// JWT parent). The JWT parent is validated externally to extract its claims
// (jti, scopes, expiry); those claims are then narrowed into a fresh Biscuit.
// This means monotonic narrowing is enforced structurally here — at derive time
// — rather than by the Biscuit append-only chain, because the parent is not
// itself a Biscuit.
package attenuation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	biscuit "github.com/biscuit-auth/biscuit-go/v2"
)

var (
	// ErrScopeWidening is returned when RequestedScopes ⊄ parentScopes (D126
	// monotonicity violation): a holder can only remove authority, never add it.
	ErrScopeWidening = errors.New("attenuation: requested scopes exceed parent scopes (monotonicity violation)")
	// ErrLifetimeWidening is returned when the requested lifetime would produce an
	// expiry after the parent token's expiry (D126 monotonicity violation on TTL).
	ErrLifetimeWidening = errors.New("attenuation: requested lifetime exceeds parent token remaining lifetime")
	// ErrMalformedParent is returned when the parent token claims are unparseable
	// or structurally invalid.
	ErrMalformedParent = errors.New("attenuation: parent token is malformed or unparseable")
)

// agentClaimsFact is the single typed Biscuit authority fact name (D52 discipline:
// one typed fact per block, programmatically constructed — never a hand-authored
// Datalog string).
const agentClaimsFact = "agent_token_claims"

// claimEnc is the base64url alphabet the claim payload rides in. Encoding the JSON
// keeps the term value free of quotes/braces, ensuring it is unambiguous through
// the Biscuit authority Query path (biscuit-go's debug renderer does not escape
// inner quotes; base64url's [A-Za-z0-9_-] alphabet sidesteps that entirely).
var claimEnc = base64.RawURLEncoding

// AgentClaims is the claim record encoded in each agent sub-token's Biscuit
// authority block. It carries the revocation-lineage chain (ds_parent_jti, D126),
// the fan-out target (host_session_index, D18), the narrowed scope set, and the
// token horizon.
type AgentClaims struct {
	// ParentJTI is the jti of the parent user auth JWT (revocation lineage, D126).
	ParentJTI string `json:"parent_jti"`
	// HostSessionIndex is the agent VM index within the session (aud = fan-out
	// slot, D18).
	HostSessionIndex int32 `json:"host_session_index"`
	// DerivedJTI is the unique identifier of this derived sub-token (used as the
	// lineage store key).
	DerivedJTI string `json:"derived_jti"`
	// Scopes is the narrowed scope set (⊆ parent JWT scopes, D126).
	Scopes []string `json:"scopes"`
	// ExpiresAt is the token horizon in Unix seconds (≤ parent JWT exp, D126).
	ExpiresAt int64 `json:"expires_at"`
}

// DeriveRequest is the caller-supplied narrowing applied at a D18 fan-out hop.
// Every field can only narrow or equal the parent JWT claims — never widen.
type DeriveRequest struct {
	// HostSessionIndex is the agent VM index the sub-token scopes to.
	HostSessionIndex int32
	// RequestedScopes is the narrowed scope set (must be ⊆ parent JWT scopes).
	RequestedScopes []string
	// LifetimeSeconds is the requested sub-token TTL. Zero means "use the parent
	// JWT's remaining lifetime"; positive values must not push ExpiresAt past the
	// parent exp.
	LifetimeSeconds int32
	// DerivedJTI is the caller-assigned unique identifier for this sub-token (used
	// for lineage tracking and revocation).
	DerivedJTI string
}

// Attenuator mints agent sub-tokens from parent user auth JWT claims (D126).
// It owns a fresh Ed25519 signing context (third-context discipline, D99) and is
// the sole authority that can verify tokens it has minted.
type Attenuator struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewAttenuator generates a fresh Ed25519 signing context for agent sub-tokens.
// Each service instance creates its own keypair (synthetic, D50) — the public key
// is the sole verification material; the private key never leaves the Attenuator.
func NewAttenuator() (*Attenuator, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("attenuation: generate ed25519 key: %w", err)
	}
	return &Attenuator{priv: priv, pub: pub}, nil
}

// PublicKeyDER returns the Ed25519 verification key bytes. Exposed so isolation
// tests can confirm it is structurally distinct from the D82 root hierarchies
// (same discipline as identity/mint's PublicKeyDER — a session-token signature
// must never validate as workload identity or interception material, D99).
func (a *Attenuator) PublicKeyDER() []byte {
	return append([]byte(nil), a.pub...)
}

// DeriveAgentToken mints one attenuated agent sub-token for a D18 fan-out hop
// (D126). It validates the monotonicity constraints (scope ⊆ parent, exp ≤ parent)
// then mints a FRESH Biscuit — not an append to the JWT parent — carrying the
// narrowed AgentClaims in its authority block (D52: one typed fact, no
// hand-authored Datalog).
//
// Parameters:
//   - parentJTI: the jti claim of the parent user auth JWT (revocation lineage).
//   - parentScopes: the scope set from the parent JWT (the monotonicity ceiling).
//   - parentExp: the exp claim of the parent JWT in Unix seconds.
//   - req: the requested narrowing (HostSessionIndex, RequestedScopes, LifetimeSeconds, DerivedJTI).
//   - nowUnix: the current time in Unix seconds (used for lifetime calculation).
//
// Returns the serialized Biscuit bytes, the encoded AgentClaims, and any error.
func (a *Attenuator) DeriveAgentToken(
	parentJTI string,
	parentScopes []string,
	parentExp int64,
	req DeriveRequest,
	nowUnix int64,
) ([]byte, AgentClaims, error) {
	var zero AgentClaims

	// Monotonicity check — scopes (D126): requested ⊆ parent.
	if !subsetOf(req.RequestedScopes, parentScopes) {
		return nil, zero, ErrScopeWidening
	}

	// Monotonicity check — lifetime (D126): derived exp ≤ parent exp.
	var expiresAt int64
	if req.LifetimeSeconds > 0 {
		expiresAt = nowUnix + int64(req.LifetimeSeconds)
		if expiresAt > parentExp {
			return nil, zero, ErrLifetimeWidening
		}
	} else {
		expiresAt = parentExp
	}

	claims := AgentClaims{
		ParentJTI:        parentJTI,
		HostSessionIndex: req.HostSessionIndex,
		DerivedJTI:       req.DerivedJTI,
		Scopes:           append([]string(nil), req.RequestedScopes...),
		ExpiresAt:        expiresAt,
	}

	// Encode claims as base64url(JSON) — the term value of the authority fact
	// (D52 discipline: typed fact, programmatically constructed).
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, zero, fmt.Errorf("attenuation: marshal agent claims: %w", err)
	}
	encoded := claimEnc.EncodeToString(raw)

	// Build the Biscuit: one authority fact carrying the encoded claim payload.
	builder := biscuit.NewBuilder(a.priv)
	fact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: agentClaimsFact,
		IDs:  []biscuit.Term{biscuit.String(encoded)},
	}}
	if err := builder.AddAuthorityFact(fact); err != nil {
		return nil, zero, fmt.Errorf("attenuation: add authority fact: %w", err)
	}
	tok, err := builder.Build()
	if err != nil {
		return nil, zero, fmt.Errorf("attenuation: build biscuit: %w", err)
	}
	serialized, err := tok.Serialize()
	if err != nil {
		return nil, zero, fmt.Errorf("attenuation: serialize biscuit: %w", err)
	}
	return serialized, claims, nil
}

// VerifyAgentToken checks the Biscuit chain signature against the Attenuator's
// third-context public key and returns the decoded AgentClaims. It performs
// SIGNATURE verification only — never session liveness or grant checks, which
// belong to the D22 seam.
//
// A token signed by any other key (forged or foreign) fails the chain check here.
// Callers are responsible for checking ExpiresAt against the current time.
func (a *Attenuator) VerifyAgentToken(tokenBytes []byte) (AgentClaims, error) {
	var zero AgentClaims

	b, err := biscuit.Unmarshal(tokenBytes)
	if err != nil {
		return zero, ErrMalformedParent
	}

	// Authorizer(pub) verifies the full Ed25519 block chain against the
	// third-context public key — the load-bearing signature check.
	authorizer, err := b.Authorizer(a.pub)
	if err != nil {
		return zero, fmt.Errorf("attenuation: biscuit signature invalid: %w", err)
	}
	authorizer.AddPolicy(biscuit.DefaultAllowPolicy)
	if err := authorizer.Authorize(); err != nil {
		return zero, fmt.Errorf("attenuation: biscuit authorize: %w", err)
	}

	// Query for the agent_token_claims fact (programmatic rule, D52 — no
	// hand-authored Datalog strings).
	rule := biscuit.Rule{
		Head: biscuit.Predicate{
			Name: "data",
			IDs:  []biscuit.Term{biscuit.Variable("p")},
		},
		Body: []biscuit.Predicate{{
			Name: agentClaimsFact,
			IDs:  []biscuit.Term{biscuit.Variable("p")},
		}},
	}
	facts, err := authorizer.Query(rule)
	if err != nil {
		return zero, fmt.Errorf("attenuation: query agent claims fact: %w", err)
	}
	for _, f := range facts {
		if len(f.IDs) != 1 {
			continue
		}
		p, ok := f.IDs[0].(biscuit.String)
		if !ok {
			continue
		}
		raw, err := claimEnc.DecodeString(string(p))
		if err != nil {
			return zero, ErrMalformedParent
		}
		var claims AgentClaims
		if err := json.Unmarshal(raw, &claims); err != nil {
			return zero, ErrMalformedParent
		}
		return claims, nil
	}
	return zero, ErrMalformedParent
}

// subsetOf reports whether every element of want is present in have (the
// monotonic-narrowing check, D126). An empty want set is always a subset.
func subsetOf(want, have []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, h := range have {
		set[h] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}
