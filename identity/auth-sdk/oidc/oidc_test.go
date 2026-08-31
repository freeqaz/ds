// SPDX-License-Identifier: Apache-2.0
package oidc_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/oidc"
)

// oidc_test.go drives the auth-sdk OIDC package against a fake OIDC server
// (httptest pattern, synthetic ECDSA P-256 key, no real IdP — D50).

// --- fake OIDC server ---

// fakeOIDC is a minimal test-double OIDC IdP. It signs ID tokens with a
// synthetic ES256 (ECDSA P-256) key, publishes the matching JWKS, and scripts
// the device-authorization + token endpoints.
type fakeOIDC struct {
	t      *testing.T
	server *httptest.Server
	ecKey  *ecdsa.PrivateKey
	kid    string
	issuer string

	// device-code script: device_code → pending/approved
	pending map[string]bool
	claims  map[string]map[string]any
}

var b64url = base64.RawURLEncoding

func newFakeOIDC(t *testing.T, clientID string) *fakeOIDC {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	f := &fakeOIDC{
		t:       t,
		ecKey:   k,
		kid:     "test-kid-1",
		pending: map[string]bool{},
		claims:  map[string]map[string]any{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/device", f.handleDevice)
	mux.HandleFunc("/token", f.handleToken)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	f.server = httptest.NewServer(mux)
	f.issuer = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeOIDC) config(orgID, clientID string) oidc.Config {
	return oidc.Config{
		OrgID:    orgID,
		Issuer:   f.issuer,
		ClientID: clientID,
	}
}

func (f *fakeOIDC) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"issuer":                        f.issuer,
		"authorization_endpoint":        f.issuer + "/authorize",
		"token_endpoint":                f.issuer + "/token",
		"device_authorization_endpoint": f.issuer + "/device",
		"jwks_uri":                      f.issuer + "/jwks",
	})
}

func (f *fakeOIDC) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := f.ecKey.Public().(*ecdsa.PublicKey)
	key := map[string]string{
		"kty": "EC",
		"kid": f.kid,
		"alg": "ES256",
		"use": "sig",
		"crv": "P-256",
		"x":   b64url.EncodeToString(pub.X.Bytes()),
		"y":   b64url.EncodeToString(pub.Y.Bytes()),
	}
	writeJSON(w, map[string]any{"keys": []any{key}})
}

// scriptDevice registers a device code as pending, to be approved later.
func (f *fakeOIDC) scriptDevice(deviceCode string, clms map[string]any) {
	f.pending[deviceCode] = true
	f.claims[deviceCode] = clms
}

// approveDevice marks the device code as approved (human completed auth).
func (f *fakeOIDC) approveDevice(deviceCode string) {
	f.pending[deviceCode] = false
}

func (f *fakeOIDC) handleDevice(w http.ResponseWriter, _ *http.Request) {
	// Return the first scripted device code.
	var dc string
	for code := range f.claims {
		dc = code
		break
	}
	writeJSON(w, map[string]any{
		"device_code":      dc,
		"user_code":        "WDJB-MJHT",
		"verification_uri": f.issuer + "/activate",
		"expires_in":       600,
		"interval":         1,
	})
}

func (f *fakeOIDC) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		writeJSON(w, map[string]string{"error": "invalid_request"})
		return
	}
	grant := r.Form.Get("grant_type")
	switch grant {
	case "urn:ietf:params:oauth:grant-type:device_code":
		dc := r.Form.Get("device_code")
		pending, known := f.pending[dc]
		if !known {
			w.WriteHeader(400)
			writeJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		if pending {
			w.WriteHeader(400)
			writeJSON(w, map[string]string{"error": "authorization_pending"})
			return
		}
		idToken := f.signToken(f.claims[dc])
		writeJSON(w, map[string]any{"id_token": idToken, "token_type": "Bearer", "expires_in": 3600})
	case "authorization_code":
		// Minimal: return a valid token for any code presented.
		idToken := f.signToken(map[string]any{"sub": "test-sub"})
		writeJSON(w, map[string]any{"id_token": idToken, "token_type": "Bearer", "expires_in": 3600})
	default:
		w.WriteHeader(400)
		writeJSON(w, map[string]string{"error": "unsupported_grant_type"})
	}
}

// signToken mints a compact-JWS ID token signed with ES256. Default iss/aud/exp
// are filled in from the fake's config unless the claims override them.
func (f *fakeOIDC) signToken(clms map[string]any) string {
	f.t.Helper()
	c := map[string]any{}
	for k, v := range clms {
		c[k] = v
	}
	if _, ok := c["iss"]; !ok {
		c["iss"] = f.issuer
	}
	if _, ok := c["aud"]; !ok {
		c["aud"] = "test-client"
	}
	if _, ok := c["exp"]; !ok {
		c["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := c["iat"]; !ok {
		c["iat"] = time.Now().Unix()
	}

	header := map[string]any{"alg": "ES256", "kid": f.kid, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(c)
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, f.ecKey, digest[:])
	if err != nil {
		f.t.Fatalf("sign ES256: %v", err)
	}
	sig := append(padTo32(r.Bytes()), padTo32(s.Bytes())...)
	return signingInput + "." + b64url.EncodeToString(sig)
}

// padTo32 left-pads a big-endian integer to 32 bytes (ES256 R/S width).
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// providerForFake constructs a Provider pointed at the fake IdP with an
// injected HTTP client and a fixed clock anchored at now.
func providerForFake(t *testing.T, f *fakeOIDC, cfg oidc.Config, now time.Time) *oidc.Provider {
	t.Helper()
	p, err := oidc.NewProvider(cfg,
		oidc.WithHTTPClient(f.server.Client()),
		oidc.WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// --- PKCE tests ---

func TestGenerateCodeVerifier(t *testing.T) {
	v, err := oidc.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier: %v", err)
	}
	if v == "" {
		t.Fatal("GenerateCodeVerifier returned empty string")
	}
	// Base64url-no-padding: 32 bytes → 43 chars.
	if len(v) != 43 {
		t.Errorf("verifier length = %d, want 43", len(v))
	}
	// Two calls must produce distinct verifiers.
	v2, _ := oidc.GenerateCodeVerifier()
	if v == v2 {
		t.Error("two GenerateCodeVerifier calls returned the same value")
	}
}

func TestCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// S256(verifier) = base64url(SHA-256(ASCII(verifier)))
	h := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(h[:])
	got := oidc.CodeChallenge(verifier)
	if got != want {
		t.Errorf("CodeChallenge(%q) = %q, want %q", verifier, got, want)
	}
}

func TestCodeChallengeDifferentInputsDifferentOutputs(t *testing.T) {
	v1 := "verifier-one"
	v2 := "verifier-two"
	if oidc.CodeChallenge(v1) == oidc.CodeChallenge(v2) {
		t.Error("CodeChallenge of two different verifiers must differ")
	}
}

// --- StartAuthzCode tests ---

func TestStartAuthzCode_URLShape(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	authzURL, pending, err := oidc.StartAuthzCode(context.Background(), p, "https://platform.example/callback")
	if err != nil {
		t.Fatalf("StartAuthzCode: %v", err)
	}

	// The URL must contain the required PKCE and OAuth2 parameters.
	for _, want := range []string{
		"response_type=code",
		"client_id=test-client",
		"code_challenge_method=S256",
		"code_challenge=",
		"state=",
		"redirect_uri=",
	} {
		if !strings.Contains(authzURL, want) {
			t.Errorf("authzURL missing %q: %s", want, authzURL)
		}
	}

	// PendingState must be populated.
	if pending.OrgID != "acme" {
		t.Errorf("PendingState.OrgID = %q, want acme", pending.OrgID)
	}
	if pending.State == "" {
		t.Error("PendingState.State is empty")
	}
	if pending.CodeVerifier == "" {
		t.Error("PendingState.CodeVerifier is empty")
	}
	if pending.RedirectURI != "https://platform.example/callback" {
		t.Errorf("PendingState.RedirectURI = %q", pending.RedirectURI)
	}

	// The code_challenge in the URL must equal S256(CodeVerifier).
	expectedChallenge := oidc.CodeChallenge(pending.CodeVerifier)
	if !strings.Contains(authzURL, "code_challenge="+expectedChallenge) {
		t.Errorf("code_challenge in URL does not match S256(verifier); url=%s challenge=%s", authzURL, expectedChallenge)
	}
}

func TestStartAuthzCode_UniqueStateEachCall(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	_, p1, _ := oidc.StartAuthzCode(context.Background(), p, "https://platform.example/callback")
	_, p2, _ := oidc.StartAuthzCode(context.Background(), p, "https://platform.example/callback")
	if p1.State == p2.State {
		t.Error("two StartAuthzCode calls returned the same state")
	}
	if p1.CodeVerifier == p2.CodeVerifier {
		t.Error("two StartAuthzCode calls returned the same code_verifier")
	}
}

// --- device-code round-trip test ---

// TestDeviceCode_RoundTrip drives a full StartDeviceCode → PollDeviceToken
// round trip against the fake OIDC server.
func TestDeviceCode_RoundTrip(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	f.scriptDevice("dev-code-1", map[string]any{
		"sub":   "oidc|alice",
		"email": "alice@acme.example",
	})

	dar, err := oidc.StartDeviceCode(context.Background(), p)
	if err != nil {
		t.Fatalf("StartDeviceCode: %v", err)
	}
	if dar.DeviceCode == "" {
		t.Fatal("DeviceAuthResponse.DeviceCode is empty")
	}
	if dar.UserCode == "" {
		t.Fatal("DeviceAuthResponse.UserCode is empty")
	}
	if dar.VerificationURI == "" {
		t.Fatal("DeviceAuthResponse.VerificationURI is empty")
	}

	// First poll: still pending.
	_, err = oidc.PollDeviceToken(context.Background(), p, dar.DeviceCode)
	if err == nil || !strings.Contains(err.Error(), "authorization_pending") {
		t.Fatalf("first poll should return authorization_pending error, got %v", err)
	}

	// Approve on the fake IdP (simulates the human completing browser auth).
	f.approveDevice(dar.DeviceCode)

	// Second poll: should succeed and carry an id_token.
	tok, err := oidc.PollDeviceToken(context.Background(), p, dar.DeviceCode)
	if err != nil {
		t.Fatalf("second poll after approval: %v", err)
	}
	if tok.IDToken == "" {
		t.Fatal("TokenResponse.IDToken is empty after approval")
	}

	// Validate the returned ID token to confirm it is well-formed and signed.
	claims, err := p.ValidateIDToken(context.Background(), tok.IDToken, "")
	if err != nil {
		t.Fatalf("ValidateIDToken on polled token: %v", err)
	}
	if claims.Subject != "oidc|alice" {
		t.Errorf("Subject = %q, want oidc|alice", claims.Subject)
	}
	if claims.Email != "alice@acme.example" {
		t.Errorf("Email = %q, want alice@acme.example", claims.Email)
	}
}

// TestDeviceCode_InvalidDeviceCode checks that polling with an unknown device code
// surfaces an error.
func TestDeviceCode_InvalidDeviceCode(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	_, err := oidc.PollDeviceToken(context.Background(), p, "nonexistent-code")
	if err == nil {
		t.Fatal("polling unknown device code should error")
	}
}

// --- ValidateIDToken tests (ES256, synthetic key) ---

func TestValidateIDToken_ES256_Valid(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	token := f.signToken(map[string]any{"sub": "oidc|grace"})
	claims, err := p.ValidateIDToken(context.Background(), token, "")
	if err != nil {
		t.Fatalf("ValidateIDToken ES256: %v", err)
	}
	if claims.Subject != "oidc|grace" {
		t.Errorf("Subject = %q, want oidc|grace", claims.Subject)
	}
}

func TestValidateIDToken_NonceMismatch(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	token := f.signToken(map[string]any{"sub": "oidc|grace", "nonce": "n-correct"})
	if _, err := p.ValidateIDToken(context.Background(), token, "n-correct"); err != nil {
		t.Fatalf("matching nonce should validate: %v", err)
	}
	if _, err := p.ValidateIDToken(context.Background(), token, "n-wrong"); err == nil {
		t.Fatal("nonce mismatch should error")
	}
}

func TestValidateIDToken_Expired(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	// Clock far in the future so the token is expired.
	future := time.Now().Add(48 * time.Hour)
	p := providerForFake(t, f, cfg, future)

	token := f.signToken(map[string]any{
		"sub": "oidc|grace",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := p.ValidateIDToken(context.Background(), token, ""); err == nil {
		t.Fatal("expired token should error")
	}
}

func TestValidateIDToken_WrongIssuer(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	token := f.signToken(map[string]any{"sub": "oidc|grace", "iss": "https://evil.example"})
	if _, err := p.ValidateIDToken(context.Background(), token, ""); err == nil {
		t.Fatal("wrong issuer should error")
	}
}

func TestValidateIDToken_TamperedSignature(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	token := f.signToken(map[string]any{"sub": "oidc|grace"})
	// Flip a byte in the signature segment.
	dot := strings.LastIndex(token, ".")
	mid := dot + 1 + (len(token)-dot-1)/2
	b := []byte(token)
	if b[mid] == 'A' {
		b[mid] = 'B'
	} else {
		b[mid] = 'A'
	}
	if _, err := p.ValidateIDToken(context.Background(), string(b), ""); err == nil {
		t.Fatal("tampered signature should error")
	}
}

func TestValidateIDToken_MissingSubject(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	// No sub claim: rejected.
	token := f.signToken(map[string]any{"email": "alice@acme.example"})
	if _, err := p.ValidateIDToken(context.Background(), token, ""); err == nil {
		t.Fatal("missing sub should error")
	}
}

func TestValidateIDToken_Malformed(t *testing.T) {
	f := newFakeOIDC(t, "test-client")
	cfg := f.config("acme", "test-client")
	p := providerForFake(t, f, cfg, time.Now())

	if _, err := p.ValidateIDToken(context.Background(), "not-a-jws", ""); err == nil {
		t.Fatal("malformed token should error")
	}
	// Two-segment token (missing signature) is not a compact JWS.
	token := f.signToken(map[string]any{"sub": "oidc|grace"})
	twoSeg := token[:strings.LastIndex(token, ".")]
	if _, err := p.ValidateIDToken(context.Background(), twoSeg, ""); err == nil {
		t.Fatal("truncated token should error")
	}
}

// --- Config.Validate tests ---

func TestConfig_Validate(t *testing.T) {
	bad := []struct {
		name string
		cfg  oidc.Config
	}{
		{"no org_id", oidc.Config{Issuer: "https://i", ClientID: "c"}},
		{"no issuer", oidc.Config{OrgID: "acme", ClientID: "c"}},
		{"no client_id", oidc.Config{OrgID: "acme", Issuer: "https://i"}},
	}
	for _, tc := range bad {
		if err := tc.cfg.Validate(); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
	ok := oidc.Config{OrgID: "acme", Issuer: "https://i", ClientID: "c"}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

// Ensure the test file imports crypto for the padTo32 helper (ES256 signing).
var _ = crypto.SHA256
