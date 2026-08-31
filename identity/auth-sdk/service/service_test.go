// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
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

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/attenuation"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/oidc"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/service"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/token"

	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
)

// synthNow is kept as a named constant for readability in assertions, but the
// fake OIDC tokens are issued relative to time.Now() so the OIDC provider's
// live clock accepts them. The SessionServer and AttenuationServer are pinned
// to the same live-ish instant via the injected clock.
const synthNow = int64(1_700_000_000)

// --- fake OIDC server (same pattern as oidc/oidc_test.go) ---

var b64url = base64.RawURLEncoding

type fakeOIDC struct {
	t      *testing.T
	server *httptest.Server
	ecKey  *ecdsa.PrivateKey
	kid    string
	issuer string

	pending map[string]bool
	claims  map[string]map[string]any
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	f := &fakeOIDC{
		t:       t,
		ecKey:   k,
		kid:     "svc-test-kid-1",
		pending: map[string]bool{},
		claims:  map[string]map[string]any{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/device_authorization", f.handleDevice)
	mux.HandleFunc("/token", f.handleToken)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	f.server = httptest.NewServer(mux)
	f.issuer = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeOIDC) oidcConfig(orgID, clientID string) oidc.Config {
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
		"device_authorization_endpoint": f.issuer + "/device_authorization",
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
		"x":   b64url.EncodeToString(padTo32(pub.X.Bytes())),
		"y":   b64url.EncodeToString(padTo32(pub.Y.Bytes())),
	}
	writeJSON(w, map[string]any{"keys": []any{key}})
}

func (f *fakeOIDC) scriptDevice(deviceCode string, clms map[string]any) {
	f.pending[deviceCode] = true
	f.claims[deviceCode] = clms
}

func (f *fakeOIDC) approveDevice(deviceCode string) {
	f.pending[deviceCode] = false
}

func (f *fakeOIDC) handleDevice(w http.ResponseWriter, _ *http.Request) {
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
	if grant != "urn:ietf:params:oauth:grant-type:device_code" {
		w.WriteHeader(400)
		writeJSON(w, map[string]string{"error": "unsupported_grant_type"})
		return
	}
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
}

// signToken mints a compact-JWS ID token signed with ES256.
// Default exp/iat are anchored at time.Now() so the OIDC provider's live-clock
// validation accepts the token; callers may override them in clms.
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
		c["aud"] = "svc-test-client"
	}
	now := time.Now().Unix()
	if _, ok := c["exp"]; !ok {
		c["exp"] = now + 3600
	}
	if _, ok := c["iat"]; !ok {
		c["iat"] = now
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

// --- integration test ---

// TestE2E_DeviceCode_DeriveAgentToken drives the full end-to-end flow:
//
//  1. Fake OIDC server (synthetic ES256 key) serves device-code and token endpoints.
//  2. SessionServer.InitiateOIDC(device_code) → DeviceCodeChallenge
//  3. SessionServer.CompleteOIDC(device_code) → user auth JWT
//  4. AttenuationServer.DeriveAgentToken(JWT) → Biscuit bytes
//  5. attenuation.VerifyAgentToken → AgentClaims.Scopes ⊆ parent scopes
//  6. derived_jti != parent jti (D126 hierarchy separation)
//  7. ListDerivedTokens → derived record present
func TestE2E_DeviceCode_DeriveAgentToken(t *testing.T) {
	ctx := context.Background()
	const orgID = "synthetic-org"
	const clientID = "svc-test-client"
	const deviceCode = "synth-dev-code-0001"
	const sub = "test-user-synthetic-0001"

	// ── 1. Stand up fake OIDC server ──────────────────────────────────────────

	f := newFakeOIDC(t)
	// Script the device code. exp/iat are defaulted to time.Now()-relative in
	// signToken so the OIDC provider's live clock accepts them.
	f.scriptDevice(deviceCode, map[string]any{
		"sub": sub,
		"iss": f.issuer,
		"aud": clientID,
	})

	// ── 2. Build SessionServer ────────────────────────────────────────────────

	kp, err := token.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rev := token.NewRevocationSet()
	reg := service.NewRegistry()
	if err := reg.RegisterOIDC(orgID, f.oidcConfig(orgID, clientID)); err != nil {
		t.Fatalf("RegisterOIDC: %v", err)
	}

	// Use the fake httptest server's own client so TLS (if any) is handled.
	// The OIDC provider inside CompleteOIDC validates exp with time.Now(), so we
	// do NOT pin the SessionServer clock; the fake tokens already have live exp.
	sess := service.NewSessionServer(reg, kp, rev,
		service.WithHTTPClient(f.server.Client()),
	)

	// ── 3. InitiateOIDC → device-code challenge ───────────────────────────────

	initiateResp, err := sess.InitiateOIDC(ctx, &authv1.InitiateOIDCRequest{
		OrgId:    orgID,
		FlowType: authv1.OIDCFlowType_OIDC_FLOW_TYPE_DEVICE_CODE,
	})
	if err != nil {
		t.Fatalf("InitiateOIDC: %v", err)
	}
	dcChallenge := initiateResp.GetDeviceCode()
	if dcChallenge == nil {
		t.Fatal("InitiateOIDC: expected DeviceCode response, got nil")
	}
	if dcChallenge.GetDeviceCode() == "" {
		t.Fatal("InitiateOIDC: DeviceCode is empty")
	}

	// ── 4. Simulate user completing browser auth, then CompleteOIDC ───────────

	f.approveDevice(dcChallenge.GetDeviceCode())

	completeResp, err := sess.CompleteOIDC(ctx, &authv1.CompleteOIDCRequest{
		OrgId: orgID,
		Completion: &authv1.CompleteOIDCRequest_DeviceCode{
			DeviceCode: dcChallenge.GetDeviceCode(),
		},
	})
	if err != nil {
		t.Fatalf("CompleteOIDC: %v", err)
	}
	userAuthJWT := completeResp.GetUserAuthToken()
	if userAuthJWT == "" {
		t.Fatal("CompleteOIDC: UserAuthToken is empty")
	}
	// Sanity-check the returned scopes.
	if len(completeResp.GetScopes()) == 0 {
		t.Fatal("CompleteOIDC: Scopes is empty")
	}

	// Confirm the JWT is valid and carries the expected subject.
	parentClaims, err := token.ValidateToken(userAuthJWT, kp.PublicKey(), "dreamserpent.platform", time.Now().Unix())
	if err != nil {
		t.Fatalf("ValidateToken on user auth JWT: %v", err)
	}
	if parentClaims.Subject != sub {
		t.Errorf("parentClaims.Subject = %q, want %q", parentClaims.Subject, sub)
	}
	if parentClaims.JWTID == "" {
		t.Fatal("parent JWTID is empty")
	}

	// ── 5. Build AttenuationServer and derive an agent sub-token ─────────────

	att, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator: %v", err)
	}
	lin := attenuation.NewLineageStore()
	attSrv := service.NewAttenuationServer(kp, att, lin)

	// Request a strict subset of the parent scopes.
	requestedScopes := []string{token.ScopeCodeRead, token.ScopeNetEgress}
	deriveResp, err := attSrv.DeriveAgentToken(ctx, &authv1.DeriveAgentTokenRequest{
		ParentUserAuthToken: userAuthJWT,
		HostSessionIndex:    1,
		RequestedScopes:     requestedScopes,
		LifetimeSeconds:     300,
	})
	if err != nil {
		t.Fatalf("DeriveAgentToken: %v", err)
	}
	agentBytes := deriveResp.GetAgentToken()
	if len(agentBytes) == 0 {
		t.Fatal("DeriveAgentToken: AgentToken bytes are empty")
	}
	derivedJTI := deriveResp.GetDerivedJti()
	if derivedJTI == "" {
		t.Fatal("DeriveAgentToken: DerivedJti is empty")
	}

	// ── 6. Verify Biscuit sub-token and check scope narrowing ─────────────────

	agentClaims, err := att.VerifyAgentToken(agentBytes)
	if err != nil {
		t.Fatalf("VerifyAgentToken: %v", err)
	}

	// AgentClaims.Scopes ⊆ parent scopes (D126 monotonicity).
	parentScopeSet := make(map[string]struct{}, len(parentClaims.DSScopes))
	for _, s := range parentClaims.DSScopes {
		parentScopeSet[s] = struct{}{}
	}
	for _, s := range agentClaims.Scopes {
		if _, ok := parentScopeSet[s]; !ok {
			t.Errorf("agent scope %q not in parent scopes (D126 monotonicity violation)", s)
		}
	}
	if len(agentClaims.Scopes) == 0 {
		t.Fatal("VerifyAgentToken: Scopes is empty")
	}
	for _, want := range requestedScopes {
		found := false
		for _, got := range agentClaims.Scopes {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("requested scope %q missing from AgentClaims.Scopes", want)
		}
	}

	// ── 7. D126 hierarchy separation: derived_jti != parent jti ───────────────

	if derivedJTI == parentClaims.JWTID {
		t.Errorf("derived_jti == parent jti (%q): D126 requires distinct token identifiers", derivedJTI)
	}
	if agentClaims.DerivedJTI != derivedJTI {
		t.Errorf("agentClaims.DerivedJTI %q != DeriveAgentTokenResponse.DerivedJti %q",
			agentClaims.DerivedJTI, derivedJTI)
	}
	if agentClaims.ParentJTI != parentClaims.JWTID {
		t.Errorf("agentClaims.ParentJTI %q != parent JWTID %q",
			agentClaims.ParentJTI, parentClaims.JWTID)
	}

	// ── 8. ListDerivedTokens → derived record present ─────────────────────────

	listResp, err := attSrv.ListDerivedTokens(ctx, &authv1.ListDerivedTokensRequest{
		ParentJti:      parentClaims.JWTID,
		IncludeExpired: true,
	})
	if err != nil {
		t.Fatalf("ListDerivedTokens: %v", err)
	}
	found := false
	for _, rec := range listResp.GetTokens() {
		if rec.GetDerivedJti() == derivedJTI {
			found = true
			// Confirm scopes match.
			if len(rec.GetScopes()) == 0 {
				t.Error("ListDerivedTokens record has empty scopes")
			}
			break
		}
	}
	if !found {
		t.Errorf("ListDerivedTokens: derived record %q not found in list (got %d records)",
			derivedJTI, len(listResp.GetTokens()))
	}

	// ── 9. Scope widening is rejected (guard D126 monotonicity) ──────────────

	// Attempting to request a scope not in the parent token must fail.
	_, wideErr := attSrv.DeriveAgentToken(ctx, &authv1.DeriveAgentTokenRequest{
		ParentUserAuthToken: userAuthJWT,
		HostSessionIndex:    2,
		RequestedScopes:     []string{"v1:code:read", "v1:forbidden:write"},
		LifetimeSeconds:     60,
	})
	if wideErr == nil {
		t.Error("DeriveAgentToken with out-of-parent scope should fail (D126), but succeeded")
	}
	if !strings.Contains(wideErr.Error(), "scopes") {
		t.Errorf("scope-widening error should mention scopes, got: %v", wideErr)
	}
}
