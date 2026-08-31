// SPDX-License-Identifier: Apache-2.0
package oidc

// PKCE (RFC 7636) helpers for the authorization-code flow.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateCodeVerifier creates a cryptographically random PKCE code_verifier.
// Length is 32 bytes of entropy → 43 base64url chars (within 43-128 char RFC range).
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: generate code_verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CodeChallenge derives the S256 code_challenge from a code_verifier.
func CodeChallenge(verifier string) string {
	s := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(s[:])
}
