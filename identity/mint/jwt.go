// SPDX-License-Identifier: Apache-2.0

// The parallel JWT presentation of the workload identity (doc 16 §3.1).
//
// §3.1 adopts "X.509 certificate with a SPIFFE-compatible URI SAN ... plus a
// PARALLEL JWT presentation for header-carried use". This file emits that JWT as
// a compact ES256 JWS (RFC 7515), signed with the SAME workload-identity key the
// X.509 leaf carries, so the cert and the token are two presentations of one
// identity. The claim set is exactly §3.1:
//
//	session_uuid, launching_user, org, repo/branch, runtime, parent_session,
//	and the RESERVED service_principal marker (the D16 persistent face,
//	authority designed at M4 — reserved now so the schema doesn't break).
//
// NO JWT LIBRARY (the wave constraint): Go stdlib (crypto/ecdsa, crypto/sha256,
// encoding/base64, encoding/json) is sufficient for the compact JWS the shim
// emits and verifies. This is M0 substrate — JWS format is owned here, free
// per doc 16 §12 ("cert library; renewal mechanics" are free behind the seam).
package mint

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// jwtClaims is the §3.1 claim set. The JSON keys are the SPIFFE/JWT-SVID-shaped
// names; `sub` carries the SPIFFE URI so the JWT and the X.509 SAN name the same
// identity. service_principal is the RESERVED D16 marker (§3.1) — emitted as a
// boolean that is always false at M0 (the agent face), reserved so the M4
// persistent-face schema lands without a break.
type jwtClaims struct {
	// Standard JWS registered claims.
	Subject   string `json:"sub"` // the SPIFFE URI spiffe://<org>/session/<uuid>
	Issuer    string `json:"iss"` // the M0 mint shim
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"` // TTL = session lifetime (§3.1)

	// The §3.1 identity claim set.
	SessionUUID      string `json:"session_uuid"`
	LaunchingUser    string `json:"launching_user"` // IdP subject (doc 04 §5 attribution)
	Org              string `json:"org"`
	RepoBranch       string `json:"repo_branch"`
	Runtime          string `json:"runtime"`
	ParentSession    string `json:"parent_session,omitempty"` // subagent attribution chain
	ServicePrincipal bool   `json:"service_principal"`        // RESERVED D16 marker (always false at M0)
}

// jwtHeader is the fixed ES256 JWS header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// b64url is RawURLEncoding (no padding), the JWS base64url.
var b64url = base64.RawURLEncoding

// signJWT produces a compact ES256 JWS over the claim set, signed with key.
func signJWT(key *ecdsa.PrivateKey, claims jwtClaims) (string, error) {
	hdrJSON, err := json.Marshal(jwtHeader{Alg: "ES256", Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("mint: marshal jwt header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("mint: marshal jwt claims: %w", err)
	}
	signingInput := b64url.EncodeToString(hdrJSON) + "." + b64url.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("mint: sign jwt: %w", err)
	}
	// JWS ES256 signature is the fixed-width R||S concatenation (RFC 7518 §3.4):
	// each of R and S is left-padded to the curve's byte size (32 for P-256).
	const p256Bytes = 32
	sig := make([]byte, 2*p256Bytes)
	r.FillBytes(sig[:p256Bytes])
	s.FillBytes(sig[p256Bytes:])
	return signingInput + "." + b64url.EncodeToString(sig), nil
}

var (
	errMalformedJWT = errors.New("mint: malformed jwt")
	errJWTSignature = errors.New("mint: jwt signature invalid")
)

// verifyJWT parses a compact ES256 JWS, checks the signature against pub, and
// returns the decoded claims. Used by the §13 isolation tests to prove a token
// minted under one identity never verifies against another's key.
func verifyJWT(pub *ecdsa.PublicKey, token string) (jwtClaims, error) {
	var out jwtClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return out, errMalformedJWT
	}
	sig, err := b64url.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return out, errMalformedJWT
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return out, errJWTSignature
	}
	claimsJSON, err := b64url.DecodeString(parts[1])
	if err != nil {
		return out, errMalformedJWT
	}
	if err := json.Unmarshal(claimsJSON, &out); err != nil {
		return out, errMalformedJWT
	}
	return out, nil
}

// spiffeURI builds the §3.1 SPIFFE-compatible identity name. The naming scheme
// is spiffe://<org>/session/<session_uuid>; using it now is what makes the M3
// SPIRE migration a pure substrate swap (doc 16 §3.1). It delegates to the typed
// SpiffeID model's Build (spiffeid.go) so the M1 own-CA name and any swapped-in
// SPIRE-backed name are produced by the SAME helper — byte-for-byte identical by
// construction, the correspondence the swap relies on.
func spiffeURI(org, sessionUUID string) string {
	return Build(org, sessionUUID)
}

// jwtUnixNow is indirected so tests can pin time without a clock package.
func toUnix(t time.Time) int64 { return t.Unix() }
