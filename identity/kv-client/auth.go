// SPDX-License-Identifier: Apache-2.0

// Platform-to-Vault authentication (doc 16 §11.3, the bootstrap-circularity
// answer; D55/D85).
//
// This file authenticates THE PLATFORM SERVICE to the customer's Vault/OpenBao,
// NOT a session. The store holds the long-lived credentials a session has not
// yet been granted (D39); if Vault access were gated on a session-issued
// credential, a session would need a credential from the store before it could
// read the store — the circularity. So the platform service authenticates once
// (its OWN workload identity, the SPIFFE-compatible substrate the mint service
// issues — §3.1), receives a short-lived renewable Vault token, and the
// grant-fetch path reads designated paths on the session's behalf.
//
// Two methods, in preference order (§11.3):
//   - JWT/OIDC (default): present the platform's workload-identity JWT to
//     Vault's jwt/oidc auth backend, bound to a customer Vault role scoped to
//     exactly the D84-designated KV mounts.
//   - AppRole (fallback): where no usable JWT/OIDC backend exists (older /
//     air-gapped deployments), present a platform-service RoleID/SecretID pair
//     custodied in the D39 trust zone. Same principal, same role scoping; only
//     the credential SHAPE changes. AppRole is the compatibility floor, not a
//     parallel design.
//
// Either way the authenticated principal is the platform service and the token
// returned is short-lived and renewable (§11.3). This file performs LOGIN ONLY
// — it never reads or writes a secret; that is client.go's KV-v2 read surface.
package kvclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrAuthFailed is returned when a login attempt is rejected by the store (bad
// JWT, unbound role, wrong RoleID/SecretID). It is a definitive deny — distinct
// from a transport/availability failure, which surfaces as the underlying error.
var ErrAuthFailed = errors.New("kvclient: vault authentication failed")

// ErrNoToken is returned when a login response is shaped like a success (HTTP
// 200) but carries no client token — a malformed/unexpected auth backend reply.
var ErrNoToken = errors.New("kvclient: auth response carried no client token")

// Authenticator logs the PLATFORM SERVICE into the store and yields a
// short-lived Vault token. It is the §11.3 bootstrap-circularity seam: the two
// implementations (JWTOIDCAuth default, AppRoleAuth fallback) authenticate the
// SAME principal — the platform service — and differ only in credential shape.
//
// Login is READ-ADJACENT but writes nothing of consequence to the store: a
// Vault login mints a token for the caller; it creates no secret and no lease
// the client manages. The read-only posture (no dynamic engines, no lease
// lifecycle) is the client's, enforced in client.go by construction.
type Authenticator interface {
	// Login authenticates the platform service and returns the Vault token to
	// carry on subsequent KV-v2 reads. Implementations POST to the auth
	// backend's login endpoint and extract auth.client_token.
	Login(ctx context.Context, doer httpDoer, addr string) (string, error)
}

// httpDoer is the minimal *http.Client surface the auth + read paths need. It
// is an interface so tests inject an httptest-backed client (D50) without a live
// store; production passes a real *http.Client over HTTPS (the Vault API is
// plain JSON over TLS).
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// JWTOIDCAuth is the DEFAULT auth method (§11.3): present the platform's
// workload-identity JWT to Vault's jwt/oidc auth backend. The customer binds
// Role to a Vault role scoped to exactly the D84-designated mounts — designation
// and auth-scope are the same boundary, so the client cannot read outside what
// was designated even if asked.
type JWTOIDCAuth struct {
	// Role is the Vault role the customer bound to the platform service's JWT,
	// scoped to the D84-designated KV mounts. Required.
	Role string
	// JWT is the platform service's own workload-identity token (NOT a session's
	// spiffe://<org>/session/<uuid> credential — §11.3). Required.
	JWT string
	// MountPath is the Vault auth mount the jwt/oidc backend is enabled at,
	// without surrounding slashes. Defaults to "jwt" when empty (Vault's
	// conventional jwt/oidc mount). Free per §12, bounded by OpenBao compat.
	MountPath string
}

// Login posts {role, jwt} to auth/<mount>/login and returns the client token.
func (a JWTOIDCAuth) Login(ctx context.Context, doer httpDoer, addr string) (string, error) {
	if strings.TrimSpace(a.Role) == "" {
		return "", fmt.Errorf("%w: jwt/oidc role is empty", ErrAuthFailed)
	}
	if strings.TrimSpace(a.JWT) == "" {
		return "", fmt.Errorf("%w: jwt/oidc assertion is empty", ErrAuthFailed)
	}
	mount := a.MountPath
	if mount == "" {
		mount = "jwt"
	}
	body := map[string]string{"role": a.Role, "jwt": a.JWT}
	return loginPost(ctx, doer, addr, "auth/"+mount+"/login", body)
}

// AppRoleAuth is the FALLBACK auth method (§11.3): present a platform-service
// RoleID/SecretID pair where no usable JWT/OIDC backend exists. Same principal
// (the platform service), same Vault-role scoping; only the credential shape
// differs. The SecretID is custodied in the D39 trust zone, never on the
// virtual-metal host (§11.3); this struct just carries it for the login POST.
type AppRoleAuth struct {
	// RoleID identifies the platform-service AppRole. Required.
	RoleID string
	// SecretID is the AppRole secret half, custodied off-host (§11.3). Required.
	SecretID string
	// MountPath is the Vault auth mount the approle backend is enabled at.
	// Defaults to "approle" when empty (Vault's conventional mount).
	MountPath string
}

// Login posts {role_id, secret_id} to auth/<mount>/login and returns the token.
func (a AppRoleAuth) Login(ctx context.Context, doer httpDoer, addr string) (string, error) {
	if strings.TrimSpace(a.RoleID) == "" {
		return "", fmt.Errorf("%w: approle role_id is empty", ErrAuthFailed)
	}
	if strings.TrimSpace(a.SecretID) == "" {
		return "", fmt.Errorf("%w: approle secret_id is empty", ErrAuthFailed)
	}
	mount := a.MountPath
	if mount == "" {
		mount = "approle"
	}
	body := map[string]string{"role_id": a.RoleID, "secret_id": a.SecretID}
	return loginPost(ctx, doer, addr, "auth/"+mount+"/login", body)
}

// loginResponse models the subset of a Vault login reply this client reads:
// auth.client_token is the short-lived renewable token (§11.3). Other fields
// (lease, metadata, policies) are intentionally ignored — the client manages no
// lease lifecycle (read-only posture, §11.3).
type loginResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// loginPost performs the shared login POST against an auth backend's login
// endpoint and extracts auth.client_token. It is the one place that talks to an
// auth mount, so both methods share identical error semantics.
func loginPost(ctx context.Context, doer httpDoer, addr, apiPath string, body map[string]string) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("kvclient: marshal login body: %w", err)
	}
	u, err := joinAPI(addr, apiPath)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("kvclient: build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := doer.Do(req)
	if err != nil {
		return "", fmt.Errorf("kvclient: login transport: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("kvclient: read login response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status %d: %s", ErrAuthFailed, resp.StatusCode, vaultErrors(payload))
	}
	var lr loginResponse
	if err := json.Unmarshal(payload, &lr); err != nil {
		return "", fmt.Errorf("kvclient: decode login response: %w", err)
	}
	if lr.Auth.ClientToken == "" {
		return "", ErrNoToken
	}
	return lr.Auth.ClientToken, nil
}
