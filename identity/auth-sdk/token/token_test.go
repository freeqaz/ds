// SPDX-License-Identifier: Apache-2.0

// Tests for the D125 user auth token package (doc 23 §5).
//
// All fixtures are synthetic (D50): no real keys, no real IdP subjects, no
// production credentials. The clock is pinned to synthNow so expiry branches
// are deterministic.
package token

import (
	"errors"
	"strings"
	"testing"
)

// synthNow is the pinned synthetic "now" for all tests (D50).
const synthNow = int64(1_700_000_000)

// synthTTL is the D125 short-lived token lifetime (15 min in unix seconds).
const synthTTL = int64(15 * 60)

// synthClaims returns a deterministic synthetic Claims value for testing (D50).
// The Issuer, Subject, Audience, and DSSession values are synthetic labels,
// never drawn from a real IdP or session store.
func synthClaims(aud string) Claims {
	return Claims{
		Issuer:    "ds-test-issuer",
		Subject:   "idp|synth-subject-001",
		Audience:  aud,
		IssuedAt:  synthNow,
		Expiry:    synthNow + synthTTL,
		JWTID:     "jti-synth-00000001",
		DSRole:    "developer",
		DSScopes:  []string{ScopeCodeRead, ScopeCodeWrite},
		DSSession: "00000000-0000-0000-0000-000000000001",
	}
}

// TestGenerateKeyPair verifies that GenerateKeyPair returns a non-nil KeyPair
// with a non-empty kid.
func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp == nil {
		t.Fatal("GenerateKeyPair returned nil KeyPair")
	}
	if kp.Kid() == "" {
		t.Fatal("GenerateKeyPair returned KeyPair with empty kid")
	}
}

// TestMintToken_CompactJWS verifies that MintToken produces a 3-part compact JWS
// (header.payload.signature) with no empty parts.
func TestMintToken_CompactJWS(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	tok, err := MintToken(kp, synthClaims("ds-test-aud"))
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("MintToken produced %d parts, want 3", len(parts))
	}
	for i, p := range parts {
		if p == "" {
			t.Fatalf("MintToken part %d is empty", i)
		}
	}
}

// TestValidateToken_RoundTrip verifies that ValidateToken(MintToken(k, claims), ...)
// returns the original claims with no error when the token is fresh and the
// audience matches.
func TestValidateToken_RoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	const aud = "ds-test-aud"
	want := synthClaims(aud)
	tok, err := MintToken(kp, want)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	// nowUnix is one second after IssuedAt — the token is fresh (exp = synthNow+900).
	got, err := ValidateToken(tok, kp.pub, aud, synthNow+1)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if got.Issuer != want.Issuer {
		t.Errorf("Issuer: got %q, want %q", got.Issuer, want.Issuer)
	}
	if got.Subject != want.Subject {
		t.Errorf("Subject: got %q, want %q", got.Subject, want.Subject)
	}
	if got.Audience != want.Audience {
		t.Errorf("Audience: got %q, want %q", got.Audience, want.Audience)
	}
	if got.JWTID != want.JWTID {
		t.Errorf("JWTID: got %q, want %q", got.JWTID, want.JWTID)
	}
	if got.DSRole != want.DSRole {
		t.Errorf("DSRole: got %q, want %q", got.DSRole, want.DSRole)
	}
	if len(got.DSScopes) != len(want.DSScopes) {
		t.Errorf("DSScopes len: got %d, want %d", len(got.DSScopes), len(want.DSScopes))
	}
	if got.DSSession != want.DSSession {
		t.Errorf("DSSession: got %q, want %q", got.DSSession, want.DSSession)
	}
}

// TestValidateToken_Expired verifies that a token presented after its exp
// returns ErrToken.
func TestValidateToken_Expired(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	const aud = "ds-test-aud"
	tok, err := MintToken(kp, synthClaims(aud))
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	// nowUnix is one second past expiry (exp = synthNow+900).
	_, err = ValidateToken(tok, kp.pub, aud, synthNow+synthTTL+1)
	if !errors.Is(err, ErrToken) {
		t.Fatalf("ValidateToken with expired token: got %v, want ErrToken", err)
	}
}

// TestValidateToken_WrongAud verifies that a token presented with a non-matching
// audience returns ErrToken.
func TestValidateToken_WrongAud(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	tok, err := MintToken(kp, synthClaims("ds-test-aud"))
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	_, err = ValidateToken(tok, kp.pub, "ds-other-aud", synthNow+1)
	if !errors.Is(err, ErrToken) {
		t.Fatalf("ValidateToken with wrong aud: got %v, want ErrToken", err)
	}
}

// TestValidateToken_WrongKey verifies that a token signed with one key fails
// validation against a different key's public key (cross-key isolation, D50
// synthetic pair).
func TestValidateToken_WrongKey(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair kp1: %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair kp2: %v", err)
	}
	const aud = "ds-test-aud"
	tok, err := MintToken(kp1, synthClaims(aud))
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	_, err = ValidateToken(tok, kp2.pub, aud, synthNow+1)
	if !errors.Is(err, ErrToken) {
		t.Fatalf("ValidateToken with wrong key: got %v, want ErrToken", err)
	}
}
