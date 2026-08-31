// SPDX-License-Identifier: Apache-2.0

// The Biscuit substrate signer for the scoped session token (doc 19 §6, D98).
//
// Biscuit is the doc 19 ratified PRIMARY substrate (D98): a public-key-verifiable
// bearer token with offline append-only attenuation (doc 19 §4) and native
// per-block revocation identifiers (doc 19 §7). The M1 flip-trigger spike (tasks
// 01KTWJ72WR / 01KTWJ73W0) recorded that no §6 flip trigger fires — core
// block-append attenuation parity holds in biscuit-go v2.2.0, verify cost sits
// far under the sync swap-path budget, and revocation IDs serve the §7 fleet list
// — so the default lands here, not on the macaroon fallback.
//
// THE THIRD SIGNING CONTEXT (D99, doc 19 §3): the signer owns a fresh Ed25519
// keypair generated in-process (synthetic, D50). It is a DIFFERENT cryptosystem
// (Ed25519 over a Biscuit chain) than the ECDSA/P-256 X.509 roots both D82
// hierarchies use, so a session-token signature is structurally un-parseable as
// workload identity or interception material — the doc 19 §13 separation, proved
// in sessiontoken_test.go.
//
// D52 DISCIPLINE (doc 19 §4): claims ride as TYPED Biscuit facts built
// programmatically (biscuit.Fact / Predicate / Term) — never hand-authored
// Datalog parser strings. The per-claim record is carried as one canonical
// `session_token_claims(depth, payload)` fact per block; attenuation appends a
// strictly-narrower next-depth fact (the chain's identity-lineage hop, doc 19
// §9). The Biscuit machinery — Ed25519 chain signatures, append-only
// attenuation, revocation IDs — is genuinely exercised; the typed payload is the
// term value of a real fact, not a faked wire format.
package mint

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	biscuit "github.com/biscuit-auth/biscuit-go/v2"
)

// substrateName identifies the default substrate in audit (doc 19 §6).
const substrateName = "biscuit-v2"

// claimsFactName is the single typed fact each block carries (D52, doc 19 §4):
// session_token_claims(depth, payload). depth is the attenuation depth (0 =
// base, doc 19 §3); payload is the JSON-encoded SessionTokenClaims for that hop.
// The DEEPEST depth's payload is the effective claim set, so attenuation is a
// strict append of a narrower record (monotonic narrowing, doc 19 §4).
const claimsFactName = "session_token_claims"

// biscuitSigner is the default SubstrateSigner: a Biscuit issuer holding the
// third-context Ed25519 keypair (doc 19 §3). It is PURE w.r.t. the shim's
// session store — it owns only the signing context, never session liveness or
// grants (those resolve at the D22 seam, doc 19 §5).
type biscuitSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// newBiscuitSigner mints a fresh third-context Ed25519 keypair (synthetic, D50).
func newBiscuitSigner() (*biscuitSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint: generate session-token signing key: %w", err)
	}
	return &biscuitSigner{priv: priv, pub: pub}, nil
}

// Name reports the substrate (doc 19 §6).
func (s *biscuitSigner) Name() string { return substrateName }

// PublicKeyDER returns the third-context Ed25519 verification key bytes. Exposed
// so the isolation tests can prove it is neither D82 root and that a session
// token never validates as workload identity / interception material.
func (s *biscuitSigner) PublicKeyDER() []byte {
	return append([]byte(nil), s.pub...)
}

// claimPayloadEnc is the base64url alphabet the claim payload rides in. Encoding
// the JSON keeps the term value free of quotes/braces, so it is unambiguous both
// through the authority Query path AND through the appended-block Code() render
// (biscuit-go's debug renderer does not escape inner quotes; base64url's
// [A-Za-z0-9_-] alphabet sidesteps that entirely).
var claimPayloadEnc = base64.RawURLEncoding

// claimsTermRe extracts the (depth, base64-payload) pair from a rendered
// appended block's session_token_claims fact (the Code() path). The payload
// group is base64url, so the match is unambiguous.
var claimsTermRe = regexp.MustCompile(claimsFactName + `\((\d+), "([A-Za-z0-9_-]+)"\)`)

// claimsFact builds the typed session_token_claims(depth, payload) fact for a
// claim record — programmatic, no parser strings (D52, doc 19 §4). The payload is
// the base64url-encoded JSON claim record.
func claimsFact(depth int, claims SessionTokenClaims) (biscuit.Fact, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return biscuit.Fact{}, fmt.Errorf("mint: marshal session-token claims: %w", err)
	}
	return biscuit.Fact{Predicate: biscuit.Predicate{
		Name: claimsFactName,
		IDs:  []biscuit.Term{biscuit.Integer(depth), biscuit.String(claimPayloadEnc.EncodeToString(raw))},
	}}, nil
}

// decodeClaimPayload turns a base64url payload term back into the claim record.
func decodeClaimPayload(payload string) (SessionTokenClaims, error) {
	var zero SessionTokenClaims
	raw, err := claimPayloadEnc.DecodeString(payload)
	if err != nil {
		return zero, errMalformedSessionToken
	}
	var claims SessionTokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return zero, errMalformedSessionToken
	}
	return claims, nil
}

// Mint signs the base-token claim set into a serialized Biscuit (depth 0). The
// claim record rides as one typed authority fact (D52). Returns the per-block
// revocation IDs (doc 19 §7).
func (s *biscuitSigner) Mint(claims SessionTokenClaims) ([]byte, [][]byte, error) {
	fact, err := claimsFact(0, claims)
	if err != nil {
		return nil, nil, err
	}
	builder := biscuit.NewBuilder(s.priv)
	if err := builder.AddAuthorityFact(fact); err != nil {
		return nil, nil, fmt.Errorf("mint: add session-token authority fact: %w", err)
	}
	tok, err := builder.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("mint: build session token: %w", err)
	}
	serialized, err := tok.Serialize()
	if err != nil {
		return nil, nil, fmt.Errorf("mint: serialize session token: %w", err)
	}
	return serialized, tok.RevocationIds(), nil
}

// Verify checks the Biscuit chain signature against the third-context public key
// and returns the EFFECTIVE (deepest-depth) claim set plus the attenuation depth.
// It performs SIGNATURE verification only — never session liveness or grants,
// which Validate owns (doc 19 §5). A token signed by any other key (a forged or
// foreign token) fails the chain check and is rejected here.
func (s *biscuitSigner) Verify(token []byte) (SessionTokenClaims, int, error) {
	var zero SessionTokenClaims
	b, err := biscuit.Unmarshal(token)
	if err != nil {
		return zero, 0, errMalformedSessionToken
	}
	// Authorizer(pub) verifies the full Ed25519 block chain against the third
	// context — the load-bearing public-key signature check (doc 19 §6). A token
	// signed by any other key (forged/foreign) fails HERE.
	authorizer, err := b.Authorizer(s.pub)
	if err != nil {
		return zero, 0, errSessionTokenSignature
	}

	// The EFFECTIVE claim set is the DEEPEST block's record (the attenuation chain
	// narrows by appending, doc 19 §4): the last appended block if any, else the
	// authority block. biscuit-go surfaces appended blocks via Code() but only the
	// authority block via the Query path, so each is read through its own surface.
	if n := b.BlockCount(); n > 0 {
		code := b.Code()
		if len(code) != n {
			return zero, 0, errMalformedSessionToken
		}
		m := claimsTermRe.FindStringSubmatch(code[n-1])
		if m == nil {
			return zero, 0, errMalformedSessionToken
		}
		claims, err := decodeClaimPayload(m[2])
		if err != nil {
			return zero, 0, err
		}
		return claims, n, nil
	}

	// Base token (depth 0): read the authority fact through the Datalog Query
	// path (programmatic rule, no parser strings — D52). DefaultAllowPolicy +
	// Authorize seed the world with the authority facts before the query.
	authorizer.AddPolicy(biscuit.DefaultAllowPolicy)
	if err := authorizer.Authorize(); err != nil {
		return zero, 0, errMalformedSessionToken
	}
	rule := biscuit.Rule{
		Head: biscuit.Predicate{Name: "data", IDs: []biscuit.Term{biscuit.Variable("d"), biscuit.Variable("p")}},
		Body: []biscuit.Predicate{{
			Name: claimsFactName,
			IDs:  []biscuit.Term{biscuit.Variable("d"), biscuit.Variable("p")},
		}},
	}
	facts, err := authorizer.Query(rule)
	if err != nil {
		return zero, 0, errMalformedSessionToken
	}
	for _, f := range facts {
		if len(f.IDs) != 2 {
			continue
		}
		if _, ok := f.IDs[0].(biscuit.Integer); !ok {
			continue
		}
		p, ok := f.IDs[1].(biscuit.String)
		if !ok {
			continue
		}
		claims, err := decodeClaimPayload(string(p))
		if err != nil {
			return zero, 0, err
		}
		return claims, 0, nil
	}
	return zero, 0, errMalformedSessionToken
}

// Attenuate derives a strictly-narrower child OFFLINE (no mint round-trip, doc 19
// §4): it appends a next-depth claims block whose service set is ⊆ the parent's,
// whose expiry is shorter-or-equal, and whose parent_session is the parent's
// session (the appended identity-lineage hop, doc 19 §9). Monotonic: a widening
// request fails closed (errSessionTokenScope) — a holder can only REMOVE
// authority.
func (s *biscuitSigner) Attenuate(parent []byte, narrow SessionTokenAttenuation) ([]byte, [][]byte, error) {
	parentClaims, parentDepth, err := s.Verify(parent)
	if err != nil {
		return nil, nil, err
	}
	child := parentClaims
	// session scope: the child's session_uuid becomes its new session scope, the
	// parent's session_uuid is recorded as the parent_session hop (doc 19 §4/§9),
	// and the chain's ORIGINATING root is pinned/inherited so Validate can fail the
	// whole chain on a root revoke (doc 19 §7).
	if narrow.ChildSessionUUID != "" {
		child.ParentSession = parentClaims.SessionUUID
		child.SessionUUID = narrow.ChildSessionUUID
	}
	applyRootPin(&child, parentClaims, narrow)
	if narrow.TaskRef != "" {
		child.TaskRef = narrow.TaskRef
	}
	// service scope: must be ⊆ the parent's (monotonic narrowing, doc 19 §4). An
	// empty parent scope is "unrestricted", so any child set narrows it; a
	// non-empty parent scope is a ceiling the child must stay within.
	if narrow.Services != nil {
		if !subsetOf(narrow.Services, parentClaims.Services) {
			return nil, nil, errSessionTokenScope
		}
		child.Services = append([]string(nil), narrow.Services...)
	}
	// scope narrowing: the D127 scope set must be ⊆ the parent's (monotonic, doc
	// 23 §6 / doc 19 §4). UNLIKE the service scope above, an empty scope set is
	// NOT "unrestricted" — the D22 seam fails closed on it (empty ds_scopes cover
	// no demanded scope, scopesCovered returns false for any non-empty demand). So
	// an empty parent is the FLOOR, not a wildcard: a non-empty child narrow is a
	// widening and is rejected here; only a nil narrow (inherit) or an empty
	// narrow keeps the child within the parent. A non-empty parent is a ceiling
	// the child stays within. A holder can only ever REMOVE scopes at a fan-out.
	if narrow.Scopes != nil {
		if !subsetOf(narrow.Scopes, parentClaims.Scopes) {
			return nil, nil, errSessionTokenScope
		}
		child.Scopes = append([]string(nil), narrow.Scopes...)
	}
	// expiry: shorter-or-equal only (doc 19 §4). A later expiry is a widening.
	if !narrow.Expiry.IsZero() {
		if !parentClaims.Expiry.IsZero() && narrow.Expiry.After(parentClaims.Expiry) {
			return nil, nil, errSessionTokenScope
		}
		child.Expiry = narrow.Expiry
	}

	b, err := biscuit.Unmarshal(parent)
	if err != nil {
		return nil, nil, errMalformedSessionToken
	}
	childFact, err := claimsFact(parentDepth+1, child)
	if err != nil {
		return nil, nil, err
	}
	bb := b.CreateBlock()
	if err := bb.AddFact(childFact); err != nil {
		return nil, nil, fmt.Errorf("mint: add attenuation fact: %w", err)
	}
	appended, err := b.Append(rand.Reader, bb.Build())
	if err != nil {
		return nil, nil, fmt.Errorf("mint: append attenuation block: %w", err)
	}
	serialized, err := appended.Serialize()
	if err != nil {
		return nil, nil, fmt.Errorf("mint: serialize attenuated token: %w", err)
	}
	return serialized, appended.RevocationIds(), nil
}

// biscuitRevocationIDHexLen is the hex length of a Biscuit native per-block
// revocation id: each id is the block's Ed25519 signature (64 bytes) → 128
// lower-hex characters. Recorded here as the empirically-verified constant
// behind the OQ6 resolution (doc 19 §7 item 6): it is exactly the fleetreg
// revocation-artifact block-id bound (fleetreg.blockIDHexMaxLen == 128), so a
// native id keys a revocation entry's BlockID DIRECTLY with no truncation.
const biscuitRevocationIDHexLen = ed25519.SignatureSize * 2 // 64-byte block signature → 128 hex

// RevocationBlockID resolves OQ6 (doc 19 §7 item 6: "whether Biscuit's per-block
// revocation IDs serve §7's fleet list directly"). DETERMINATION — YES, directly:
// a Biscuit revocation id (as returned by Mint / Attenuate's RevocationIds) is
// the block's Ed25519 signature, a globally-unique 64-byte value that is public
// verification material, NOT token-secret bytes. It is therefore safe to publish
// in a revocation artifact and can key fleetreg.FleetRevocationEntry.BlockID
// directly, with no SHA-256 fingerprint reduction: this function simply
// lower-hex-encodes it into the bounded (128-hex) identifier the
// fleetreg.RevocationEntryFromBlockID constructor accepts.
//
// PREFERRED CONSTRUCTOR (doc 19 §7): for a Biscuit token, the emergency fleet
// kill-switch keys entries via RevocationEntryFromBlockID(RevocationBlockID(id))
// — the native path. The SHA-256 fingerprint path
// (fleetreg.FingerprintToken → RevocationEntryFromFingerprint, D124) remains the
// FALLBACK for a substrate WITHOUT native per-block ids (the doc 19 §6 macaroon
// alternative), so both constructors stay live behind the format-opaque seam.
//
// This helper never touches the token bytes: it encodes only the already-derived
// public revocation id, so nothing secret ever crosses into the artifact
// (doc 19 §7/§9, the no-token-bytes invariant).
func RevocationBlockID(revocationID []byte) string {
	return hex.EncodeToString(revocationID)
}

// subsetOf reports whether every element of want is present in have (the
// monotonic-narrowing check, doc 19 §4).
func subsetOf(want, have []string) bool {
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

var (
	errMalformedSessionToken = errors.New("mint: malformed session token")
	errSessionTokenSignature = errors.New("mint: session token signature invalid")
)

// compile-time assertion: the default signer satisfies the substrate seam.
var _ SubstrateSigner = (*biscuitSigner)(nil)
