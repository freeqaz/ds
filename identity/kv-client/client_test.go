// SPDX-License-Identifier: Apache-2.0

// Tests for the OpenBao-compatible KV-v2 READ-ONLY client — against an httptest
// FAKE OpenBao/Vault server ONLY (D50: synthetic fixtures, NO live store this
// wave). The fake speaks the documented Vault wire shapes: auth/<mount>/login
// returns {"auth":{"client_token":...}}, <mount>/data/<path> returns the KV-v2
// {"data":{"data":...,"metadata":{"version":...}}} envelope, and
// <mount>/metadata/<path>?list=true returns {"data":{"keys":[...]}}.
//
// The synthetic fixtures use the ds-synth-* naming the wave standardizes on.
package kvclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// fakeVault is a synthetic OpenBao/Vault server (D50). It exercises exactly the
// auth + KV-v2 read/list surface this client uses — nothing more — and records
// what it was asked to do so tests can assert posture (e.g. NO write verb ever
// reaches it, because the client has no write method).
type fakeVault struct {
	srv *httptest.Server

	// expectedJWT / expectedRole gate the jwt login; expectedRoleID/SecretID
	// gate the approle login. The minted token is returned on success.
	expectedJWT      string
	expectedRole     string
	expectedRoleID   string
	expectedSecretID string
	mintToken        string

	// secrets keyed by "<mount>/<path>" -> KV-v2 data; listing keyed by
	// "<mount>/<prefix>" -> child keys.
	secrets map[string]map[string]any
	listing map[string][]string

	// requireToken, when set, makes data/metadata reads 403 unless the request
	// carries it in X-Vault-Token — models a scoped/expired token.
	requireToken string

	// seenMethods records every HTTP method the fake received: the read-only
	// posture means tests should only ever see GET and POST(login).
	seenMethods map[string]int
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	f := &fakeVault{
		mintToken:   "ds-synth-vault-token-7f3a",
		secrets:     map[string]map[string]any{},
		listing:     map[string][]string{},
		seenMethods: map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	f.seenMethods[r.Method]++
	// All API paths are under /v1/.
	p := strings.TrimPrefix(r.URL.Path, "/v1/")

	switch {
	case strings.HasPrefix(p, "auth/") && strings.HasSuffix(p, "/login"):
		f.handleLogin(w, r, p)
	case strings.Contains(p, "/data/"):
		f.handleRead(w, r, p)
	case strings.Contains(p, "/metadata/") || strings.HasSuffix(p, "/metadata"):
		f.handleList(w, r, p)
	default:
		writeVaultError(w, http.StatusNotFound, "unsupported path: "+p)
	}
}

func (f *fakeVault) handleLogin(w http.ResponseWriter, r *http.Request, p string) {
	if r.Method != http.MethodPost {
		writeVaultError(w, http.StatusMethodNotAllowed, "login is POST")
		return
	}
	var body map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeVaultError(w, http.StatusBadRequest, "bad login body")
		return
	}
	switch {
	case strings.HasPrefix(p, "auth/jwt/"):
		if body["jwt"] != f.expectedJWT || body["role"] != f.expectedRole {
			writeVaultError(w, http.StatusBadRequest, "invalid jwt/role")
			return
		}
	case strings.HasPrefix(p, "auth/approle/"):
		if body["role_id"] != f.expectedRoleID || body["secret_id"] != f.expectedSecretID {
			writeVaultError(w, http.StatusBadRequest, "invalid role_id/secret_id")
			return
		}
	default:
		writeVaultError(w, http.StatusNotFound, "unknown auth mount")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{
			"client_token":   f.mintToken,
			"lease_duration": 3600,
			"renewable":      true,
		},
	})
}

func (f *fakeVault) handleRead(w http.ResponseWriter, r *http.Request, p string) {
	if r.Method != http.MethodGet {
		writeVaultError(w, http.StatusMethodNotAllowed, "read is GET")
		return
	}
	if f.requireToken != "" && r.Header.Get("X-Vault-Token") != f.requireToken {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	key := strings.Replace(p, "/data/", "/", 1)
	data, ok := f.secrets[key]
	if !ok {
		writeVaultError(w, http.StatusNotFound, "no secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"data":     data,
			"metadata": map[string]any{"version": 1},
		},
	})
}

func (f *fakeVault) handleList(w http.ResponseWriter, r *http.Request, p string) {
	if r.Method != http.MethodGet || r.URL.Query().Get("list") != "true" {
		writeVaultError(w, http.StatusMethodNotAllowed, "list is GET ?list=true")
		return
	}
	if f.requireToken != "" && r.Header.Get("X-Vault-Token") != f.requireToken {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	key := strings.Replace(p, "/metadata/", "/", 1)
	key = strings.TrimSuffix(key, "/metadata")
	keys, ok := f.listing[key]
	if !ok {
		writeVaultError(w, http.StatusNotFound, "no tree")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"keys": keys}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeVaultError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"errors": []string{msg}})
}

// --- tests ---

func TestReadSecret_JWTOIDC(t *testing.T) {
	f := newFakeVault(t)
	f.expectedRole = "ds-synth-platform-role"
	f.expectedJWT = "ds-synth-platform-jwt"
	f.secrets["secret/dreamserpent/github-pat"] = map[string]any{"token": "ds-synth-ghp-abc123"}

	auth := JWTOIDCAuth{Role: f.expectedRole, JWT: f.expectedJWT}
	c, err := New(f.srv.URL, "secret", auth, WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sec, err := c.ReadSecret(context.Background(), "dreamserpent/github-pat")
	if err != nil {
		t.Fatalf("ReadSecret: %v", err)
	}
	if got := sec.Data["token"]; got != "ds-synth-ghp-abc123" {
		t.Fatalf("token = %v, want ds-synth-ghp-abc123", got)
	}
	if sec.Version != 1 {
		t.Fatalf("version = %d, want 1", sec.Version)
	}
	// Posture: the fake only ever saw GET (read) + POST (login) — never a write
	// verb, because the client has no write method.
	for m := range f.seenMethods {
		if m != http.MethodGet && m != http.MethodPost {
			t.Fatalf("fake saw unexpected method %q — read-only posture broken", m)
		}
	}
	if f.seenMethods[http.MethodPost] != 1 {
		t.Fatalf("expected exactly 1 login POST, saw %d", f.seenMethods[http.MethodPost])
	}
}

func TestReadSecret_AppRoleFallback(t *testing.T) {
	f := newFakeVault(t)
	f.expectedRoleID = "ds-synth-roleid"
	f.expectedSecretID = "ds-synth-secretid"
	f.secrets["kv/dreamserpent/aws"] = map[string]any{"access_key": "ds-synth-AKIA"}

	auth := AppRoleAuth{RoleID: f.expectedRoleID, SecretID: f.expectedSecretID}
	c, err := New(f.srv.URL, "kv", auth, WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sec, err := c.ReadSecret(context.Background(), "dreamserpent/aws")
	if err != nil {
		t.Fatalf("ReadSecret(approle): %v", err)
	}
	if got := sec.Data["access_key"]; got != "ds-synth-AKIA" {
		t.Fatalf("access_key = %v", got)
	}
}

func TestListKeys_DigestTreeWalk(t *testing.T) {
	f := newFakeVault(t)
	f.expectedRole = "r"
	f.expectedJWT = "j"
	f.listing["secret/dreamserpent"] = []string{"github-pat", "aws", "sub/"}

	c, err := New(f.srv.URL, "secret", JWTOIDCAuth{Role: "r", JWT: "j"}, WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	keys, err := c.ListKeys(context.Background(), "dreamserpent")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	want := []string{"github-pat", "aws", "sub/"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
}

func TestReadSecret_NotFound(t *testing.T) {
	f := newFakeVault(t)
	f.expectedRole, f.expectedJWT = "r", "j"
	c, _ := New(f.srv.URL, "secret", JWTOIDCAuth{Role: "r", JWT: "j"}, WithHTTPClient(f.srv.Client()))
	_, err := c.ReadSecret(context.Background(), "nope")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("err = %v, want ErrSecretNotFound", err)
	}
}

func TestReadSecret_PermissionDeniedOutsideScope(t *testing.T) {
	// Model a path outside the D84-designated scope: the store 403s for any
	// token. Both the initial read and the post-reauth retry get 403, so the
	// client must surface ErrPermission (fail closed).
	f := newFakeVault(t)
	f.expectedRole, f.expectedJWT = "r", "j"
	f.requireToken = "a-token-the-client-will-never-hold"
	f.secrets["secret/forbidden"] = map[string]any{"x": "y"}
	c, _ := New(f.srv.URL, "secret", JWTOIDCAuth{Role: "r", JWT: "j"}, WithHTTPClient(f.srv.Client()))
	_, err := c.ReadSecret(context.Background(), "forbidden")
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("err = %v, want ErrPermission", err)
	}
}

func TestReauthOn403(t *testing.T) {
	// The fake requires the minted token. The client's first read carries the
	// freshly minted token and succeeds — but to prove the reauth path works we
	// pre-seed a stale token and confirm the 403 -> relogin -> success cycle.
	f := newFakeVault(t)
	f.expectedRole, f.expectedJWT = "r", "j"
	f.requireToken = f.mintToken
	f.secrets["secret/s"] = map[string]any{"k": "v"}
	c, _ := New(f.srv.URL, "secret", JWTOIDCAuth{Role: "r", JWT: "j"}, WithHTTPClient(f.srv.Client()))
	// Inject a stale token so the first read 403s and forces a relogin.
	c.token = "ds-synth-stale-token"
	sec, err := c.ReadSecret(context.Background(), "s")
	if err != nil {
		t.Fatalf("ReadSecret after stale token: %v", err)
	}
	if sec.Data["k"] != "v" {
		t.Fatalf("data = %v", sec.Data)
	}
	if f.seenMethods[http.MethodPost] != 1 {
		t.Fatalf("expected exactly 1 relogin POST, saw %d", f.seenMethods[http.MethodPost])
	}
}

func TestAuthFailure(t *testing.T) {
	f := newFakeVault(t)
	f.expectedRole, f.expectedJWT = "r", "j"
	// Wrong JWT -> login 400 -> ErrAuthFailed.
	c, _ := New(f.srv.URL, "secret", JWTOIDCAuth{Role: "r", JWT: "WRONG"}, WithHTTPClient(f.srv.Client()))
	_, err := c.ReadSecret(context.Background(), "whatever")
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
}

func TestEmptyAuthCredsRejected(t *testing.T) {
	if _, err := (JWTOIDCAuth{}).Login(context.Background(), http.DefaultClient, "http://x"); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("empty jwt auth err = %v, want ErrAuthFailed", err)
	}
	if _, err := (AppRoleAuth{}).Login(context.Background(), http.DefaultClient, "http://x"); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("empty approle auth err = %v, want ErrAuthFailed", err)
	}
}

func TestNewValidatesArgs(t *testing.T) {
	if _, err := New("", "secret", JWTOIDCAuth{Role: "r", JWT: "j"}); err == nil {
		t.Fatal("empty addr should error")
	}
	if _, err := New("http://x", "", JWTOIDCAuth{Role: "r", JWT: "j"}); err == nil {
		t.Fatal("empty mount should error")
	}
	if _, err := New("http://x", "secret", nil); err == nil {
		t.Fatal("nil auth should error")
	}
}

// TestReadOnlyPostureIsStructural is the acceptance assertion: the read-only
// posture (§11.3) is enforced BY CONSTRUCTION. It reflects over *Client's method
// set and fails if ANY mutating method name (Write/Put/Set/Delete/Create/Lease/
// Renew/Dynamic) is present. The client surface is read-only because no such
// method EXISTS — this test makes that a regression-guarded property.
func TestReadOnlyPostureIsStructural(t *testing.T) {
	forbidden := []string{"write", "put", "set", "delete", "create", "lease", "renew", "revoke", "dynamic", "mint"}
	ct := reflect.TypeOf(&Client{})
	for i := 0; i < ct.NumMethod(); i++ {
		name := strings.ToLower(ct.Method(i).Name)
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Fatalf("Client exposes mutating method %q — read-only posture is NOT structural", ct.Method(i).Name)
			}
		}
	}
	// Sanity: the read surface IS present.
	if _, ok := ct.MethodByName("ReadSecret"); !ok {
		t.Fatal("ReadSecret missing")
	}
	if _, ok := ct.MethodByName("ListKeys"); !ok {
		t.Fatal("ListKeys missing")
	}
}
