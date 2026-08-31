// SPDX-License-Identifier: Apache-2.0

// The stdlib-only fallback SubstrateSigner for the scoped session token.
//
// The brief's seam requirement: the substrate is reached through a clean
// SubstrateSigner seam (doc 19 §6) with a STDLIB default implementation, so a
// deployment that cannot ship the Biscuit/Datalog default — the §6
// security-review flip trigger, or simply a no-third-party-deps build — can swap
// it in via WithSubstrateSigner without touching MintSessionToken or Validate
// (the format-opaque D22 posture, doc 19 §5). Biscuit remains the ratified
// PRIMARY (D98); this is the named alternative behind the same seam.
//
// FORMAT (a REAL stdlib chain, never a faked Biscuit wire format): a session
// token is a compact JSON envelope `{blocks:[...], sigs:[...]}` where each block
// is a JSON-encoded SessionTokenClaims record and each signature is Ed25519 over
// (prev_sig || block_json) under the third-context key (doc 19 §3). Attenuation
// appends a strictly-narrower block + its chained signature (the same monotonic
// narrowing as Biscuit, doc 19 §4); the per-block signatures ARE the revocation
// identifiers (doc 19 §7). This is its own honest format — it does NOT claim to
// be Biscuit. Ed25519 + JSON are stdlib (crypto/ed25519, encoding/json).
package mint

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// stdlibSubstrateName identifies the fallback substrate in audit (doc 19 §6).
const stdlibSubstrateName = "stdlib-ed25519-chain-v1"

// stdlibTokenPrefix is the domain-separation marker (so IsSessionToken's
// signer.Verify routing is structural; the envelope is self-describing).
const stdlibTokenPrefix = "dsst1." // "ds session-token v1"

// stdlibEnvelope is the on-wire token: an append-only chain of claim blocks, each
// signed by the third-context Ed25519 key, with the signature chained on the
// previous block's signature (so a block cannot be reordered or replayed onto a
// different chain).
type stdlibEnvelope struct {
	Blocks [][]byte `json:"blocks"` // each is a JSON-encoded SessionTokenClaims
	Sigs   [][]byte `json:"sigs"`   // sigs[i] = Ed25519(prev_sig || blocks[i])
}

// stdlibSigner is the stdlib fallback SubstrateSigner. It owns ONLY the
// third-context Ed25519 keypair — never a D82 hierarchy, never session
// liveness/grants (those resolve at the D22 seam, doc 19 §5).
type stdlibSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// newStdlibSigner mints a fresh third-context Ed25519 keypair (synthetic, D50).
func newStdlibSigner() (*stdlibSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint: generate stdlib session-token key: %w", err)
	}
	return &stdlibSigner{priv: priv, pub: pub}, nil
}

// Name reports the substrate (doc 19 §6).
func (s *stdlibSigner) Name() string { return stdlibSubstrateName }

// PublicKeyDER returns the third-context Ed25519 verification key bytes.
func (s *stdlibSigner) PublicKeyDER() []byte { return append([]byte(nil), s.pub...) }

// signBlock signs blockJSON chained on prevSig (nil for the authority block).
func (s *stdlibSigner) signBlock(prevSig, blockJSON []byte) []byte {
	h := sha256.New()
	h.Write(prevSig)
	h.Write(blockJSON)
	return ed25519.Sign(s.priv, h.Sum(nil))
}

// serialize marshals an envelope behind the domain-separation prefix.
func serializeStdlibEnvelope(env stdlibEnvelope) ([]byte, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("mint: marshal stdlib token: %w", err)
	}
	return append([]byte(stdlibTokenPrefix), body...), nil
}

// Mint signs the base-token claim set into a one-block stdlib chain (depth 0).
func (s *stdlibSigner) Mint(claims SessionTokenClaims) ([]byte, [][]byte, error) {
	blockJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, nil, fmt.Errorf("mint: marshal stdlib claims: %w", err)
	}
	sig := s.signBlock(nil, blockJSON)
	env := stdlibEnvelope{Blocks: [][]byte{blockJSON}, Sigs: [][]byte{sig}}
	tok, err := serializeStdlibEnvelope(env)
	if err != nil {
		return nil, nil, err
	}
	return tok, [][]byte{sig}, nil
}

// parseAndVerify decodes + verifies the full chain against the third-context
// public key. Every block's signature must check against its chained predecessor.
func (s *stdlibSigner) parseAndVerify(token []byte) (stdlibEnvelope, error) {
	var zero stdlibEnvelope
	if len(token) < len(stdlibTokenPrefix) || string(token[:len(stdlibTokenPrefix)]) != stdlibTokenPrefix {
		return zero, errMalformedSessionToken
	}
	var env stdlibEnvelope
	if err := json.Unmarshal(token[len(stdlibTokenPrefix):], &env); err != nil {
		return zero, errMalformedSessionToken
	}
	if len(env.Blocks) == 0 || len(env.Blocks) != len(env.Sigs) {
		return zero, errMalformedSessionToken
	}
	var prevSig []byte
	for i := range env.Blocks {
		h := sha256.New()
		h.Write(prevSig)
		h.Write(env.Blocks[i])
		if !ed25519.Verify(s.pub, h.Sum(nil), env.Sigs[i]) {
			return zero, errSessionTokenSignature
		}
		prevSig = env.Sigs[i]
	}
	return env, nil
}

// Verify checks the chain signature and returns the EFFECTIVE (deepest) claim set
// plus the attenuation depth. Signature only — liveness/grants are Validate's
// (doc 19 §5).
func (s *stdlibSigner) Verify(token []byte) (SessionTokenClaims, int, error) {
	var zero SessionTokenClaims
	env, err := s.parseAndVerify(token)
	if err != nil {
		return zero, 0, err
	}
	deepest := len(env.Blocks) - 1
	var claims SessionTokenClaims
	if err := json.Unmarshal(env.Blocks[deepest], &claims); err != nil {
		return zero, 0, errMalformedSessionToken
	}
	return claims, deepest, nil
}

// Attenuate appends a strictly-narrower next block OFFLINE (no mint round-trip,
// doc 19 §4). Monotonic: a widening request fails closed (errSessionTokenScope).
func (s *stdlibSigner) Attenuate(parent []byte, narrow SessionTokenAttenuation) ([]byte, [][]byte, error) {
	env, err := s.parseAndVerify(parent)
	if err != nil {
		return nil, nil, err
	}
	var parentClaims SessionTokenClaims
	if err := json.Unmarshal(env.Blocks[len(env.Blocks)-1], &parentClaims); err != nil {
		return nil, nil, errMalformedSessionToken
	}
	child := parentClaims
	if narrow.ChildSessionUUID != "" {
		child.ParentSession = parentClaims.SessionUUID
		child.SessionUUID = narrow.ChildSessionUUID
	}
	applyRootPin(&child, parentClaims, narrow)
	if narrow.TaskRef != "" {
		child.TaskRef = narrow.TaskRef
	}
	if narrow.Services != nil {
		if !subsetOf(narrow.Services, parentClaims.Services) {
			return nil, nil, errSessionTokenScope
		}
		child.Services = append([]string(nil), narrow.Services...)
	}
	// scope narrowing: the D127 scope set must be ⊆ the parent's (monotonic, doc
	// 23 §6 / doc 19 §4). Same subsetOf guard as the biscuit signer: an empty
	// scope set is the FLOOR (fail-closed at the D22 seam), NOT an unrestricted
	// wildcard — so a non-empty child narrow against an empty parent is a widening
	// and is rejected; a holder can only REMOVE scopes at a fan-out hop.
	if narrow.Scopes != nil {
		if !subsetOf(narrow.Scopes, parentClaims.Scopes) {
			return nil, nil, errSessionTokenScope
		}
		child.Scopes = append([]string(nil), narrow.Scopes...)
	}
	if !narrow.Expiry.IsZero() {
		if !parentClaims.Expiry.IsZero() && narrow.Expiry.After(parentClaims.Expiry) {
			return nil, nil, errSessionTokenScope
		}
		child.Expiry = narrow.Expiry
	}
	blockJSON, err := json.Marshal(child)
	if err != nil {
		return nil, nil, fmt.Errorf("mint: marshal stdlib attenuation: %w", err)
	}
	prevSig := env.Sigs[len(env.Sigs)-1]
	sig := s.signBlock(prevSig, blockJSON)
	env.Blocks = append(env.Blocks, blockJSON)
	env.Sigs = append(env.Sigs, sig)
	tok, err := serializeStdlibEnvelope(env)
	if err != nil {
		return nil, nil, err
	}
	return tok, append([][]byte(nil), env.Sigs...), nil
}

// compile-time assertion: the fallback signer satisfies the substrate seam.
var _ SubstrateSigner = (*stdlibSigner)(nil)
