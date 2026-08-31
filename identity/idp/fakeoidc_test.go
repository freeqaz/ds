// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeoidc_test.go stands up a FAKE OIDC server (httptest) with synthetic keys
// generated IN-TEST (D50: synthetic fixtures only, no real IdP, no real key
// material). It serves the discovery document, JWKS, the device-authorization
// endpoint, and the token endpoint, and mints OIDC ID tokens signed with the
// in-test key — so the device-code flow, the redirect flow, and ID-token
// validation are all driven end to end without a live network or live IdP.

// fakeOIDC is the test double for an OIDC IdP. It signs ID tokens with either an
// RSA (RS256) or EC P-256 (ES256) in-test key, publishes the matching JWKS, and
// scripts the device-authorization + token endpoints.
type fakeOIDC struct {
	t      *testing.T
	server *httptest.Server

	kid string
	alg string

	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey

	clientID string
	issuer   string // set to server.URL after construction

	mu sync.Mutex
	// device-code script: device_code → pending until ready, then the token to issue
	devicePending map[string]bool
	deviceClaims  map[string]map[string]any // device_code → claims to mint on success
	deviceHeader  map[string]map[string]any // device_code → CUSTOM protected header (else the legit alg/kid/typ:JWT)
	deviceDenied  map[string]bool           // device_code → human denied consent
	// authorization-code script: code → claims to mint on exchange
	authCodes map[string]map[string]any
}

// b64url is the JWKS/JWS base64url alphabet (no padding).
var b64url = base64.RawURLEncoding

// newFakeOIDC starts a fake IdP signing with the given alg ("RS256" or "ES256").
func newFakeOIDC(t *testing.T, alg, clientID string) *fakeOIDC {
	t.Helper()
	f := &fakeOIDC{
		t:             t,
		kid:           "test-kid-1",
		alg:           alg,
		clientID:      clientID,
		devicePending: map[string]bool{},
		deviceClaims:  map[string]map[string]any{},
		deviceHeader:  map[string]map[string]any{},
		deviceDenied:  map[string]bool{},
		authCodes:     map[string]map[string]any{},
	}
	switch alg {
	case "RS256":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		f.rsaKey = k
	case "ES256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate EC key: %v", err)
		}
		f.ecKey = k
	default:
		t.Fatalf("unsupported test alg %q", alg)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/device", f.handleDeviceAuth)
	mux.HandleFunc("/token", f.handleToken)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	f.server = httptest.NewServer(mux)
	f.issuer = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

// config returns a relying-party Config pointed at this fake IdP.
func (f *fakeOIDC) config(org string, groupRoleMap map[string]PlatformRole) Config {
	return Config{
		Org:          org,
		Issuer:       f.issuer,
		ClientID:     f.clientID,
		GroupRoleMap: groupRoleMap,
	}
}

func (f *fakeOIDC) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, Discovery{
		Issuer:                      f.issuer,
		AuthorizationEndpoint:       f.issuer + "/authorize",
		TokenEndpoint:               f.issuer + "/token",
		DeviceAuthorizationEndpoint: f.issuer + "/device",
		JWKSURI:                     f.issuer + "/jwks",
	})
}

func (f *fakeOIDC) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	var key jsonWebKey
	switch f.alg {
	case "RS256":
		pub := f.rsaKey.Public().(*rsa.PublicKey)
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		key = jsonWebKey{
			Kty: "RSA", Kid: f.kid, Alg: "RS256", Use: "sig",
			N: b64url.EncodeToString(pub.N.Bytes()),
			E: b64url.EncodeToString(eBytes),
		}
	case "ES256":
		pub := f.ecKey.Public().(*ecdsa.PublicKey)
		key = jsonWebKey{
			Kty: "EC", Kid: f.kid, Alg: "ES256", Use: "sig", Crv: "P-256",
			X: b64url.EncodeToString(pub.X.Bytes()),
			Y: b64url.EncodeToString(pub.Y.Bytes()),
		}
	}
	writeJSON(w, jwksDoc{Keys: []jsonWebKey{key}})
}

// scriptDevice registers a device code that starts PENDING (the human has not
// yet completed browser auth) and mints an ID token with claims once approved.
func (f *fakeOIDC) scriptDevice(deviceCode string, claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devicePending[deviceCode] = true
	f.deviceClaims[deviceCode] = claims
}

// scriptDeviceWithHeader is scriptDevice plus a CUSTOM protected header the token
// endpoint mints on success — so an integrated device-code test can drive a hostile
// header member (a wrong typ, a self-declared x5t/x5c/jku) all the way through the
// real DeviceFlow.Authenticate → ValidateIDToken path, not only the unit confuser.
func (f *fakeOIDC) scriptDeviceWithHeader(deviceCode string, header, claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devicePending[deviceCode] = true
	f.deviceClaims[deviceCode] = claims
	f.deviceHeader[deviceCode] = header
}

// approveDevice flips a scripted device code from pending to authorized (the
// human completed auth in the browser).
func (f *fakeOIDC) approveDevice(deviceCode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devicePending[deviceCode] = false
}

// denyDevice marks a scripted device code as access_denied (the human declined
// consent in the browser — RFC 8628 §3.5 terminal).
func (f *fakeOIDC) denyDevice(deviceCode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deviceDenied[deviceCode] = true
}

// scriptAuthCode registers an authorization code that mints an ID token with
// claims on exchange (the redirect flow).
func (f *fakeOIDC) scriptAuthCode(code string, claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authCodes[code] = claims
}

func (f *fakeOIDC) handleDeviceAuth(w http.ResponseWriter, _ *http.Request) {
	// Return the single scripted device code (tests script exactly one).
	f.mu.Lock()
	var dc string
	for code := range f.deviceClaims {
		dc = code
		break
	}
	f.mu.Unlock()
	uc := "WDJB-MJHT"
	writeJSON(w, deviceAuthResponse{
		DeviceCode:              dc,
		UserCode:                uc,
		VerificationURI:         f.issuer + "/activate",
		VerificationURIComplete: f.issuer + "/activate?user_code=" + uc,
		ExpiresIn:               600,
		Interval:                1,
	})
}

func (f *fakeOIDC) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		writeJSON(w, tokenResponse{Error: "invalid_request"})
		return
	}
	grant := r.Form.Get("grant_type")
	switch grant {
	case "urn:ietf:params:oauth:grant-type:device_code":
		dc := r.Form.Get("device_code")
		f.mu.Lock()
		pending, known := f.devicePending[dc]
		denied := f.deviceDenied[dc]
		claims := f.deviceClaims[dc]
		header := f.deviceHeader[dc]
		f.mu.Unlock()
		if !known {
			w.WriteHeader(400)
			writeJSON(w, tokenResponse{Error: "invalid_grant"})
			return
		}
		if denied {
			w.WriteHeader(400)
			writeJSON(w, tokenResponse{Error: "access_denied"})
			return
		}
		if pending {
			w.WriteHeader(400)
			writeJSON(w, tokenResponse{Error: "authorization_pending"})
			return
		}
		idToken := f.signToken(claims)
		if header != nil {
			idToken = f.signTokenWithHeader(header, claims)
		}
		writeJSON(w, tokenResponse{IDToken: idToken, TokenType: "Bearer", ExpiresIn: 3600})
	case "authorization_code":
		code := r.Form.Get("code")
		f.mu.Lock()
		claims, ok := f.authCodes[code]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(400)
			writeJSON(w, tokenResponse{Error: "invalid_grant"})
			return
		}
		writeJSON(w, tokenResponse{IDToken: f.signToken(claims), TokenType: "Bearer", ExpiresIn: 3600})
	default:
		w.WriteHeader(400)
		writeJSON(w, tokenResponse{Error: "unsupported_grant_type"})
	}
}

// signToken mints a compact-JWS ID token with the fake's signing key and the
// legitimate ID-token header (alg/kid + typ:"JWT"). Default iss/aud/exp are filled
// in from the config unless the claims override them, so a test can deliberately
// mint a bad-issuer / expired token.
func (f *fakeOIDC) signToken(claims map[string]any) string {
	f.t.Helper()
	return f.signTokenWithHeader(map[string]any{"alg": f.alg, "kid": f.kid, "typ": "JWT"}, claims)
}

// signTokenWithHeader mints a compact-JWS ID token with a CALLER-SUPPLIED protected
// header, signed with the fake's real key, so an integrated flow test can inject a
// hostile header member (a wrong typ like "at+jwt", or a self-declared x5t/x5u/jku)
// onto a genuinely-signed token and prove the §11.2 header-member contract refuses
// it on the real device-code / redirect validation path — not only in the unit-level
// confuser. The signature is always valid for the given header bytes; the alg the
// signing key uses (f.alg) is what the body is signed under regardless of any "alg"
// the caller put in the map, so the header drives parse-stage policy while the
// signature remains genuine. Default iss/aud/exp/iat are filled from the config
// unless overridden (same as signToken).
func (f *fakeOIDC) signTokenWithHeader(header, claims map[string]any) string {
	f.t.Helper()
	c := map[string]any{}
	for k, v := range claims {
		c[k] = v
	}
	if _, ok := c["iss"]; !ok {
		c["iss"] = f.issuer
	}
	if _, ok := c["aud"]; !ok {
		c["aud"] = f.clientID
	}
	if _, ok := c["exp"]; !ok {
		c["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := c["iat"]; !ok {
		c["iat"] = time.Now().Unix()
	}

	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(c)
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signingInput))

	var sig []byte
	switch f.alg {
	case "RS256":
		s, err := rsa.SignPKCS1v15(rand.Reader, f.rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			f.t.Fatalf("sign RS256: %v", err)
		}
		sig = s
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, f.ecKey, digest[:])
		if err != nil {
			f.t.Fatalf("sign ES256: %v", err)
		}
		sig = append(padTo32(r.Bytes()), padTo32(s.Bytes())...)
	}
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

// providerForFake builds a Provider over the fake IdP, using the server's HTTP
// client and a controllable clock anchored at now.
func providerForFake(t *testing.T, f *fakeOIDC, cfg Config, now time.Time) *Provider {
	t.Helper()
	p, err := NewProvider(cfg,
		WithHTTPClient(f.server.Client()),
		WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}
