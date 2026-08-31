// SPDX-License-Identifier: Apache-2.0

// JWT minting and validation for the D125 user auth token (doc 23 §5).
//
// The user auth token is a compact ES256 JWS (header.payload.signature, RFC 7515)
// carrying the D125 claim set. It is the THIRD signing context in the platform:
//   - D82 CA-mint ECDSA hierarchies (workload identity)
//   - D99 biscuit-signer Ed25519 (session tokens)
//   - D125 this package — ECDSA P-256 for human-principal user auth tokens
//
// NO JWT LIBRARY (same judgment as identity/mint and identity/idp): Go stdlib
// (crypto/ecdsa, crypto/sha256, encoding/base64, encoding/json) is sufficient
// for the compact JWS minted and verified here.
package token

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// b64url is RawURLEncoding (no padding), the JWS base64url alphabet.
var b64url = base64.RawURLEncoding

// Claims is the D125 user auth token claim set (doc 23 §5).
type Claims struct {
	Issuer    string   // "iss" — platform issuer identifier
	Subject   string   // "sub" — IdP subject (from OIDC sub or SAML nameID)
	Audience  string   // "aud" — ds platform audience
	IssuedAt  int64    // "iat" — unix seconds
	Expiry    int64    // "exp" — unix seconds (D125: 15 min from IssuedAt)
	JWTID     string   // "jti" — unique token ID for revocation
	DSRole    string   // "ds_role" — platform role from IdP groups
	DSScopes  []string // "ds_scopes" — D127 scope strings
	DSSession string   // "ds_session_ref" — bound session UUID
}

// rawClaims is the JSON wire shape for Claims. Fields are the JWT registered
// claim names plus the ds_ private claim names.
type rawClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	Expiry    int64    `json:"exp"`
	JWTID     string   `json:"jti"`
	DSRole    string   `json:"ds_role"`
	DSScopes  []string `json:"ds_scopes"`
	DSSession string   `json:"ds_session_ref"`
}

// jwtHeader is the ES256 JWS protected header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// MintToken produces a compact ES256 JWS for claims signed with key.
//
// Header: {"alg":"ES256","typ":"JWT","kid":"<key.Kid()>"}
// Signature: ECDSA P-256, digest = SHA-256(base64url(header)+"."+base64url(payload)),
// encoded as the fixed-width R||S concatenation (RFC 7518 §3.4: 32 bytes each).
func MintToken(key *KeyPair, claims Claims) (string, error) {
	hdrJSON, err := json.Marshal(jwtHeader{Alg: "ES256", Typ: "JWT", Kid: key.kid})
	if err != nil {
		return "", fmt.Errorf("token: marshal jwt header: %w", err)
	}
	rc := rawClaims{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		IssuedAt:  claims.IssuedAt,
		Expiry:    claims.Expiry,
		JWTID:     claims.JWTID,
		DSRole:    claims.DSRole,
		DSScopes:  claims.DSScopes,
		DSSession: claims.DSSession,
	}
	payloadJSON, err := json.Marshal(rc)
	if err != nil {
		return "", fmt.Errorf("token: marshal jwt payload: %w", err)
	}

	signingInput := b64url.EncodeToString(hdrJSON) + "." + b64url.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, key.priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("token: sign jwt: %w", err)
	}
	// JWS ES256 signature is the fixed-width R||S (RFC 7518 §3.4):
	// each of R and S left-padded to the P-256 field size (32 bytes).
	const p256Bytes = 32
	sig := make([]byte, 2*p256Bytes)
	r.FillBytes(sig[:p256Bytes])
	s.FillBytes(sig[p256Bytes:])

	return signingInput + "." + b64url.EncodeToString(sig), nil
}

// ValidateToken parses and validates a compact ES256 JWS produced by MintToken.
// It checks:
//   - compact JWS structure (3 parts)
//   - header alg == "ES256"
//   - ES256 signature against pub (SHA-256 of "header.payload", R||S 64-byte sig)
//   - exp > nowUnix (ErrToken if expired)
//   - aud == expectedAud (ErrToken on mismatch)
//
// On success it returns the decoded Claims.
func ValidateToken(token string, pub *ecdsa.PublicKey, expectedAud string, nowUnix int64) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: token is not a compact JWS (got %d segments)", ErrToken, len(parts))
	}

	hdrBytes, err := b64url.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: header decode: %v", ErrToken, err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return Claims{}, fmt.Errorf("%w: header parse: %v", ErrToken, err)
	}
	if hdr.Alg != "ES256" {
		return Claims{}, fmt.Errorf("%w: unsupported signing alg %q (only ES256)", ErrToken, hdr.Alg)
	}

	sig, err := b64url.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature decode: %v", ErrToken, err)
	}
	if len(sig) != 64 {
		return Claims{}, fmt.Errorf("%w: ES256 signature length %d != 64", ErrToken, len(sig))
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return Claims{}, fmt.Errorf("%w: ES256 signature invalid", ErrToken)
	}

	payloadBytes, err := b64url.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: payload decode: %v", ErrToken, err)
	}
	var rc rawClaims
	if err := json.Unmarshal(payloadBytes, &rc); err != nil {
		return Claims{}, fmt.Errorf("%w: payload parse: %v", ErrToken, err)
	}

	if rc.Expiry <= nowUnix {
		return Claims{}, fmt.Errorf("%w: token expired (exp %d, now %d)", ErrToken, rc.Expiry, nowUnix)
	}
	if rc.Audience != expectedAud {
		return Claims{}, fmt.Errorf("%w: audience %q != expected %q", ErrToken, rc.Audience, expectedAud)
	}

	return Claims{
		Issuer:    rc.Issuer,
		Subject:   rc.Subject,
		Audience:  rc.Audience,
		IssuedAt:  rc.IssuedAt,
		Expiry:    rc.Expiry,
		JWTID:     rc.JWTID,
		DSRole:    rc.DSRole,
		DSScopes:  rc.DSScopes,
		DSSession: rc.DSSession,
	}, nil
}
