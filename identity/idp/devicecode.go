// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This file carries the two mint-time human-authentication entry flows of doc 16
// §11.2 and the single AuthResult they BOTH converge on:
//
//   - CLI: the OAuth 2.0 device-authorization grant (RFC 8628) — the CLI has no
//     browser and no redirect listener, so it requests a device+user code,
//     prints a verification URL + user code, and polls the token endpoint until
//     the human completes auth+MFA in any browser (§11.2 steps 1–4).
//   - Web client: the OIDC authorization-code flow with PKCE — the D18 web
//     client has a browser context. The web client itself is a separate epic;
//     this file EXPOSES THE SEAM (the redirect URL builder + the code exchange)
//     so that epic plugs in without re-deriving the OIDC shape.
//
// Both flows end identically: validate the ID token (oidc.go), extract the
// §11.2 claim mapping, and return an AuthResult. "The minted identity is
// indistinguishable downstream regardless of entry flow" (§11.2). The PRINCIPAL
// upsert that turns an AuthResult into a stored principal is the
// orchestrator/internal/auth side — this module never imports the store.

// ErrAuth is returned when an auth flow fails for a reason that is neither a bad
// token (ErrToken) nor a discovery/availability fault (ErrDiscovery): the human
// denied consent, the device code expired before completion, or the IdP returned
// an OAuth error. It maps to "launch refused, no principal" on the auth side.
var ErrAuth = errors.New("idp: authentication failed")

// AuthResult is the validated outcome of EITHER mint-time flow (doc 16 §11.2).
// It is the DATA the orchestrator/internal/auth side upserts into a store
// principal — the subject becomes the §3.2 IdP-subject key and the launching_user
// claim value, the roles are the §11.2 group→role mapping result, and
// Email/Name are display metadata only (never the identity key). It carries no
// IdP handle and no token — the IdP's job ends here; the per-request hot path is
// the D22 seam, never the IdP (the §11.2 mint-time-only boundary).
type AuthResult struct {
	Org      string         // the org the subject is asserted within (Config.Org)
	Subject  string         // the OIDC `sub` — the §3.2 identity key / launching_user value
	Email    string         // display metadata only (never the identity key)
	Name     string         // display metadata only
	Groups   []string       // the raw asserted groups (audit / re-check input)
	Roles    []PlatformRole // the §11.2 group→role mapping result (derived, not stored as ACL)
	Expiry   time.Time      // the ID token expiry (drives the §11.2 re-auth cadence)
	IssuedAt time.Time
}

// deviceAuthResponse is the RFC 8628 §3.2 device-authorization response.
type deviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	// Okta and others return verification_uri_complete (URL with the code
	// pre-filled); the CLI prefers it when present.
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// tokenResponse is the OAuth/OIDC token-endpoint response. id_token carries the
// OIDC claims this package validates; refresh_token (where the IdP issues one)
// drives the §11.2 re-auth-at-policy-cadence story (carried, not used to widen
// scope here).
type tokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	// error fields (RFC 8628 §3.5 polling, RFC 6749 §5.2)
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// DeviceFlow runs the RFC 8628 device-authorization grant. It is the CLI's
// mint-time human-auth entry (doc 16 §11.2 "CLI (device-code flow)").
type DeviceFlow struct {
	p     *Provider
	sleep func(time.Duration) // injectable for deterministic polling tests
}

// NewDeviceFlow constructs the device-code flow over a Provider.
func NewDeviceFlow(p *Provider) *DeviceFlow {
	return &DeviceFlow{p: p, sleep: time.Sleep}
}

// withSleep injects the poll-interval sleep (test seam).
func (f *DeviceFlow) withSleep(s func(time.Duration)) *DeviceFlow {
	f.sleep = s
	return f
}

// DevicePrompt is what the CLI shows the human (RFC 8628 step 2): the
// verification URL and user code to enter in any browser. The CLI prints these;
// the human completes auth+MFA against their own Okta tenant (doc 16 §11.2).
type DevicePrompt struct {
	UserCode        string
	VerificationURI string
	// VerificationURIComplete (when the IdP provides it) has the user code
	// pre-filled — the CLI prints it as the one-click path.
	VerificationURIComplete string
	ExpiresAt               time.Time
}

// deviceHandle is the internal poll state: the device code to redeem and the
// interval/expiry the IdP set.
type deviceHandle struct {
	deviceCode string
	interval   time.Duration
	expiresAt  time.Time
}

// Begin runs RFC 8628 step 1: it requests a device+user code from the IdP's
// device-authorization endpoint (resolved from discovery) and returns the prompt
// to show the human plus an opaque handle to poll with. nonce is echoed in the
// ID token and checked at validation (replay defense).
func (f *DeviceFlow) Begin(ctx context.Context) (DevicePrompt, deviceHandle, error) {
	d, err := f.p.Discovery(ctx)
	if err != nil {
		return DevicePrompt{}, deviceHandle{}, err
	}
	if d.DeviceAuthorizationEndpoint == "" {
		return DevicePrompt{}, deviceHandle{}, fmt.Errorf("%w: IdP discovery has no device_authorization_endpoint", ErrDiscovery)
	}

	form := url.Values{}
	form.Set("client_id", f.p.cfg.ClientID)
	form.Set("scope", strings.Join(f.p.cfg.scopes(), " "))

	var dar deviceAuthResponse
	if err := f.p.postForm(ctx, d.DeviceAuthorizationEndpoint, form, &dar); err != nil {
		return DevicePrompt{}, deviceHandle{}, fmt.Errorf("%w: device-authorization request: %v", ErrAuth, err)
	}
	if dar.DeviceCode == "" {
		return DevicePrompt{}, deviceHandle{}, fmt.Errorf("%w: device-authorization response carried no device_code", ErrAuth)
	}

	interval := time.Duration(dar.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second // RFC 8628 §3.5 default
	}
	expiresAt := f.p.now().Add(time.Duration(dar.ExpiresIn) * time.Second)

	prompt := DevicePrompt{
		UserCode:                dar.UserCode,
		VerificationURI:         dar.VerificationURI,
		VerificationURIComplete: dar.VerificationURIComplete,
		ExpiresAt:               expiresAt,
	}
	handle := deviceHandle{deviceCode: dar.DeviceCode, interval: interval, expiresAt: expiresAt}
	return prompt, handle, nil
}

// Poll runs RFC 8628 step 3: it polls the token endpoint at the IdP-specified
// interval until the human completes auth (returns the validated AuthResult),
// denies/expires (ErrAuth), or ctx is cancelled. It honors the RFC 8628 §3.5
// polling protocol: authorization_pending and slow_down keep polling (slow_down
// widens the interval); access_denied / expired_token are terminal.
//
// The device-authorization grant has NO nonce round-trip (nonce is an
// authorization-REQUEST parameter the device flow cannot carry), so the ID token
// is validated with no nonce check — its replay binding is the one-shot
// device_code the IdP issued, not a nonce. The redirect flow, which CAN carry a
// nonce, checks it (RedirectFlow.Exchange via AuthRequest.Nonce).
func (f *DeviceFlow) Poll(ctx context.Context, h deviceHandle) (AuthResult, error) {
	d, err := f.p.Discovery(ctx)
	if err != nil {
		return AuthResult{}, err
	}
	interval := h.interval
	for {
		if ctx.Err() != nil {
			return AuthResult{}, ctx.Err()
		}
		if !h.expiresAt.IsZero() && f.p.now().After(h.expiresAt) {
			return AuthResult{}, fmt.Errorf("%w: device code expired before authorization", ErrAuth)
		}
		f.sleep(interval)

		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		form.Set("device_code", h.deviceCode)
		form.Set("client_id", f.p.cfg.ClientID)
		if f.p.cfg.ClientSecret != "" {
			form.Set("client_secret", f.p.cfg.ClientSecret)
		}

		var tr tokenResponse
		if err := f.p.postForm(ctx, d.TokenEndpoint, form, &tr); err != nil {
			return AuthResult{}, fmt.Errorf("%w: token poll: %v", ErrAuth, err)
		}
		switch tr.Error {
		case "":
			// success — validate the ID token and converge on AuthResult. No
			// nonce check: the device grant has no nonce round-trip (above).
			return f.p.resultFromToken(ctx, tr, "")
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second // RFC 8628 §3.5
			continue
		case "access_denied":
			return AuthResult{}, fmt.Errorf("%w: user denied the authorization", ErrAuth)
		case "expired_token":
			return AuthResult{}, fmt.Errorf("%w: device code expired", ErrAuth)
		default:
			return AuthResult{}, fmt.Errorf("%w: token endpoint error %q: %s", ErrAuth, tr.Error, tr.ErrorDescription)
		}
	}
}

// Authenticate is the convenience driver: Begin, hand the prompt to show, then
// Poll to completion. show is how the CLI renders the verification URL + user
// code (doc 16 §11.2 step 2) — injectable so a test asserts on the prompt.
func (f *DeviceFlow) Authenticate(ctx context.Context, show func(DevicePrompt)) (AuthResult, error) {
	prompt, handle, err := f.Begin(ctx)
	if err != nil {
		return AuthResult{}, err
	}
	if show != nil {
		show(prompt)
	}
	return f.Poll(ctx, handle)
}

// --- web redirect flow (seam only; the D18 web client is a separate epic) ---

// RedirectFlow exposes the OIDC authorization-code-with-PKCE seam for the D18
// web client (doc 16 §11.2 "web client (redirect flow)"). The web client itself
// is another epic; this type is the SEAM it plugs into: AuthURL builds the
// redirect to the IdP authorization endpoint, and Exchange completes the
// callback by swapping the code for an ID token and converging on the SAME
// AuthResult + claim mapping as the device flow (§11.2: "both flows converge on
// the same validated principal record and the same claim mapping").
type RedirectFlow struct {
	p *Provider
}

// NewRedirectFlow constructs the web redirect-flow seam over a Provider.
func NewRedirectFlow(p *Provider) *RedirectFlow { return &RedirectFlow{p: p} }

// AuthRequest is the per-login state the web client must persist across the
// redirect (the PKCE verifier, the state/nonce it generated). The web epic owns
// generating these; this seam consumes them so the OIDC discipline (PKCE,
// state, nonce) is enforced here rather than re-implemented in the client.
type AuthRequest struct {
	RedirectURI   string // the platform's registered callback URI
	State         string // CSRF state, echoed in the callback
	Nonce         string // replay nonce, checked in the ID token
	CodeChallenge string // S256(code_verifier), base64url — PKCE
}

// AuthURL builds the authorization-endpoint redirect URL the web client sends
// the human's browser to (doc 16 §11.2 redirect-flow step 1). It uses
// response_type=code with PKCE (code_challenge_method=S256). The web client
// holds the matching code_verifier and presents it at Exchange.
func (rf *RedirectFlow) AuthURL(ctx context.Context, ar AuthRequest) (string, error) {
	d, err := rf.p.Discovery(ctx)
	if err != nil {
		return "", err
	}
	if d.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("%w: IdP discovery has no authorization_endpoint", ErrDiscovery)
	}
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("%w: authorization_endpoint parse: %v", ErrDiscovery, err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", rf.p.cfg.ClientID)
	q.Set("redirect_uri", ar.RedirectURI)
	q.Set("scope", strings.Join(rf.p.cfg.scopes(), " "))
	q.Set("state", ar.State)
	q.Set("nonce", ar.Nonce)
	if ar.CodeChallenge != "" {
		q.Set("code_challenge", ar.CodeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange completes the redirect flow's callback (doc 16 §11.2 redirect-flow
// steps 2–4): it swaps the authorization code for an ID token at the token
// endpoint (presenting the PKCE code_verifier) and runs the IDENTICAL validation
// + claim extraction as the device flow, returning the same AuthResult shape.
// The caller is responsible for having already verified the `state` parameter
// against AuthRequest.State (CSRF) before calling Exchange.
func (rf *RedirectFlow) Exchange(ctx context.Context, ar AuthRequest, code, codeVerifier string) (AuthResult, error) {
	d, err := rf.p.Discovery(ctx)
	if err != nil {
		return AuthResult{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", ar.RedirectURI)
	form.Set("client_id", rf.p.cfg.ClientID)
	if rf.p.cfg.ClientSecret != "" {
		form.Set("client_secret", rf.p.cfg.ClientSecret)
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	var tr tokenResponse
	if err := rf.p.postForm(ctx, d.TokenEndpoint, form, &tr); err != nil {
		return AuthResult{}, fmt.Errorf("%w: code exchange: %v", ErrAuth, err)
	}
	if tr.Error != "" {
		return AuthResult{}, fmt.Errorf("%w: token endpoint error %q: %s", ErrAuth, tr.Error, tr.ErrorDescription)
	}
	return rf.p.resultFromToken(ctx, tr, ar.Nonce)
}

// --- shared token → AuthResult convergence ---

// resultFromToken validates the token response's ID token and projects the
// §11.2 claim mapping onto an AuthResult. It is the single convergence point for
// both flows: the device-flow Poll and the redirect-flow Exchange both call it,
// so "the minted identity is indistinguishable downstream regardless of entry
// flow" (§11.2) is true by construction, not by parallel code.
func (p *Provider) resultFromToken(ctx context.Context, tr tokenResponse, nonce string) (AuthResult, error) {
	if tr.IDToken == "" {
		return AuthResult{}, fmt.Errorf("%w: token response carried no id_token", ErrAuth)
	}
	claims, err := p.ValidateIDToken(ctx, tr.IDToken, nonce)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{
		Org:      p.cfg.Org,
		Subject:  claims.Subject,
		Email:    claims.Email,
		Name:     claims.Name,
		Groups:   claims.Groups,
		Roles:    p.cfg.MapGroups(claims.Groups),
		Expiry:   claims.Expiry,
		IssuedAt: claims.IssuedAt,
	}, nil
}

// postForm POSTs a form-urlencoded body and decodes the JSON response into v.
// The token and device-authorization endpoints both take form bodies (OAuth).
func (p *Provider) postForm(ctx context.Context, endpoint string, form url.Values, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// OAuth error responses are JSON too (RFC 6749 §5.2), carried on 400; decode
	// the body regardless of status so the caller can read the error field.
	return decodeJSON(resp, v)
}
