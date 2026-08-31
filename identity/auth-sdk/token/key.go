// SPDX-License-Identifier: Apache-2.0
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// KeyPair holds an ECDSA P-256 signing keypair (D125: "ECDSA P-256, short-lived JWT").
// This is the THIRD signing context for user auth tokens, distinct from:
//   - D82 CA-mint ECDSA hierarchies (workload identity)
//   - D99 biscuit-signer Ed25519 (session tokens)
type KeyPair struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	kid  string // key ID for JWKS
}

func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("token: generate P-256 key: %w", err)
	}
	// kid is the base64url of the uncompressed public key bytes (stable, opaque).
	pub := &priv.PublicKey
	raw := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	kid := base64.RawURLEncoding.EncodeToString(raw[:16]) // first 16 bytes = 22 chars
	return &KeyPair{priv: priv, pub: pub, kid: kid}, nil
}

func (k *KeyPair) Kid() string { return k.kid }

// PublicKey returns the ECDSA P-256 public key for external validators (e.g. token.ValidateToken).
func (k *KeyPair) PublicKey() *ecdsa.PublicKey { return k.pub }

// JWKSKey returns the public key as a JSON Web Key (RFC 7517).
func (k *KeyPair) JWKSKey() map[string]any {
	xBytes := k.pub.X.Bytes()
	yBytes := k.pub.Y.Bytes()
	// Pad to 32 bytes (P-256 field size).
	padded := func(b []byte) string {
		if len(b) < 32 {
			buf := make([]byte, 32)
			copy(buf[32-len(b):], b)
			b = buf
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": k.kid,
		"use": "sig",
		"alg": "ES256",
		"x":   padded(xBytes),
		"y":   padded(yBytes),
	}
}

// JWKSDocument returns the JWKS JSON bytes for HTTP serving.
func JWKSDocument(keys ...*KeyPair) ([]byte, error) {
	ks := make([]map[string]any, len(keys))
	for i, k := range keys {
		ks[i] = k.JWKSKey()
	}
	return json.Marshal(map[string]any{"keys": ks})
}

// PublicKeyFromJWK parses an EC P-256 key from a JWK map (for validators).
func PublicKeyFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	xS, _ := jwk["x"].(string)
	yS, _ := jwk["y"].(string)
	if kty != "EC" || crv != "P-256" {
		return nil, fmt.Errorf("token: unsupported JWK kty/crv %q/%q", kty, crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xS)
	if err != nil {
		return nil, fmt.Errorf("token: JWK x decode: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yS)
	if err != nil {
		return nil, fmt.Errorf("token: JWK y decode: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
