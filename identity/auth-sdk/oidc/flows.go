// SPDX-License-Identifier: Apache-2.0
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PendingState is the server-side state for an in-flight authz-code flow.
// Short-lived; must be verified within MaxStateAge.
type PendingState struct {
	OrgID        string
	State        string
	CodeVerifier string
	RedirectURI  string
	IssuedAt     time.Time
}

// StartAuthzCode initiates the PKCE authorization-code flow.
// Returns the authorization URL and the pending state record to store server-side.
func StartAuthzCode(ctx context.Context, p *Provider, redirectURI string) (authzURL string, pending PendingState, err error) {
	disco, err := p.Discovery(ctx)
	if err != nil {
		return "", PendingState{}, err
	}

	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return "", PendingState{}, err
	}

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", PendingState{}, err
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"code_challenge":        {CodeChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	authzURL = disco.AuthorizationEndpoint + "?" + params.Encode()
	pending = PendingState{
		OrgID:        p.cfg.OrgID,
		State:        state,
		CodeVerifier: verifier,
		RedirectURI:  redirectURI,
		IssuedAt:     p.now(),
	}
	return authzURL, pending, nil
}

// TokenResponse is the OAuth2 token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// ExchangeCode exchanges an authorization code for tokens (PKCE, RFC 7636).
func ExchangeCode(ctx context.Context, p *Provider, code, verifier, redirectURI string) (TokenResponse, error) {
	disco, err := p.Discovery(ctx)
	if err != nil {
		return TokenResponse{}, err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {p.cfg.ClientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disco.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.http.Do(req)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("oidc: token exchange: %w", err)
	}
	defer resp.Body.Close()

	var tok TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return TokenResponse{}, fmt.Errorf("oidc: decode token response: %w", err)
	}
	if tok.Error != "" {
		return TokenResponse{}, fmt.Errorf("oidc: token exchange error %q: %s", tok.Error, tok.ErrorDesc)
	}
	return tok, nil
}

// DeviceAuthResponse is the RFC 8628 device authorization response.
type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// StartDeviceCode initiates the RFC 8628 device authorization grant.
func StartDeviceCode(ctx context.Context, p *Provider) (DeviceAuthResponse, error) {
	disco, err := p.Discovery(ctx)
	if err != nil {
		return DeviceAuthResponse{}, err
	}

	form := url.Values{"client_id": {p.cfg.ClientID}, "scope": {"openid email profile"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disco.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceAuthResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.http.Do(req)
	if err != nil {
		return DeviceAuthResponse{}, fmt.Errorf("oidc: device auth: %w", err)
	}
	defer resp.Body.Close()

	var dar DeviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&dar); err != nil {
		return DeviceAuthResponse{}, fmt.Errorf("oidc: decode device auth response: %w", err)
	}
	return dar, nil
}

// PollDeviceToken polls the token endpoint for a device-code grant (RFC 8628).
// Returns the token response when the user completes authorization.
// Returns an error with "authorization_pending" or "slow_down" in the message for non-fatal states.
func PollDeviceToken(ctx context.Context, p *Provider, deviceCode string) (TokenResponse, error) {
	disco, err := p.Discovery(ctx)
	if err != nil {
		return TokenResponse{}, err
	}

	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {p.cfg.ClientID},
		"device_code": {deviceCode},
	}
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disco.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.http.Do(req)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("oidc: poll device token: %w", err)
	}
	defer resp.Body.Close()

	var tok TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return TokenResponse{}, fmt.Errorf("oidc: decode device token response: %w", err)
	}
	if tok.Error != "" {
		return TokenResponse{}, fmt.Errorf("oidc: device token error %q: %s", tok.Error, tok.ErrorDesc)
	}
	return tok, nil
}
