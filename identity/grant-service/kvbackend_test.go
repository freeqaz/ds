// SPDX-License-Identifier: Apache-2.0

// Tests for the OpenBao-compatible KV-v2 Backend adapter (doc 16 §9, §11.3;
// D39/D55/D85) — driven against an httptest FAKE OpenBao/Vault server ONLY (D50:
// synthetic fixtures, NO live store this wave). The fake speaks the documented
// Vault KV-v2 wire shapes (auth/<mount>/login -> {"auth":{"client_token":...}},
// <mount>/data/<path> -> {"data":{"data":...,"metadata":{"version":...}}}); the
// adapter wires the REAL ../kv-client/ *Client over it (consumed as a dependency,
// not edited) and we assert the four Backend mappings:
//
//	KV-v2 read    -> Credential{Secret, Location}
//	store down    -> ErrStoreUnavailable
//	KV-v2 404     -> ErrGrantNotFound
//	permission/auth deny -> ErrStoreUnavailable (fail closed, never a wrong cred)
//
// plus that the adapter is selectable BESIDE FileKVBackend behind the same seam
// (a tier swap is a backend swap, never a grant-service rewrite) and never issues
// a write verb (read-only posture, §11.3). Synthetic ds-synth-* fixtures only.
package grantservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kvclient "github.com/dream-serpent/dream-serpent/identity/kv-client"
)

// fakeOpenBao is a synthetic OpenBao/Vault server (D50) speaking exactly the auth
// + KV-v2 read surface the kv-client uses. It records every HTTP method so a test
// can assert the read-only posture (only GET reads + POST login ever arrive — no
// write verb, because neither the kv-client nor this adapter has a write path).
type fakeOpenBao struct {
	srv *httptest.Server

	expectedRole string
	expectedJWT  string
	mintToken    string

	// secrets keyed by "<mount>/<path>" -> KV-v2 data payload.
	secrets map[string]map[string]any

	// down, when set, makes the server refuse connections by being closed; see
	// newClosedFakeOpenBao. requireToken 403s reads lacking the scoped token.
	requireToken string

	seenMethods map[string]int
}

func newFakeOpenBao(t *testing.T) *fakeOpenBao {
	t.Helper()
	f := &fakeOpenBao{
		expectedRole: "ds-synth-platform-role",
		expectedJWT:  "ds-synth-platform-jwt",
		mintToken:    "ds-synth-vault-token-9c1d",
		secrets:      map[string]map[string]any{},
		seenMethods:  map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOpenBao) handle(w http.ResponseWriter, r *http.Request) {
	f.seenMethods[r.Method]++
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case strings.HasPrefix(p, "auth/") && strings.HasSuffix(p, "/login"):
		f.handleLogin(w, r, p)
	case strings.Contains(p, "/data/"):
		f.handleRead(w, r, p)
	default:
		writeVaultErr(w, http.StatusNotFound, "unsupported path: "+p)
	}
}

func (f *fakeOpenBao) handleLogin(w http.ResponseWriter, r *http.Request, p string) {
	if r.Method != http.MethodPost {
		writeVaultErr(w, http.StatusMethodNotAllowed, "login is POST")
		return
	}
	var body map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeVaultErr(w, http.StatusBadRequest, "bad login body")
		return
	}
	if body["jwt"] != f.expectedJWT || body["role"] != f.expectedRole {
		writeVaultErr(w, http.StatusBadRequest, "invalid jwt/role")
		return
	}
	writeVaultJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{"client_token": f.mintToken, "lease_duration": 3600, "renewable": true},
	})
}

func (f *fakeOpenBao) handleRead(w http.ResponseWriter, r *http.Request, p string) {
	if r.Method != http.MethodGet {
		writeVaultErr(w, http.StatusMethodNotAllowed, "read is GET")
		return
	}
	if f.requireToken != "" && r.Header.Get("X-Vault-Token") != f.requireToken {
		writeVaultErr(w, http.StatusForbidden, "permission denied")
		return
	}
	key := strings.Replace(p, "/data/", "/", 1)
	data, ok := f.secrets[key]
	if !ok {
		writeVaultErr(w, http.StatusNotFound, "no secret")
		return
	}
	writeVaultJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}},
	})
}

func writeVaultJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeVaultErr(w http.ResponseWriter, status int, msg string) {
	writeVaultJSON(w, status, map[string]any{"errors": []string{msg}})
}

// newKVBackendOverFake wires the REAL kv-client *Client over the fake and returns
// a KVBackend adapter with the default config. The synthetic session×service used
// by every test is fixed so the grant_ref and the stored KV path line up.
const (
	synthSession = "00000000-0000-4000-8000-00000000abcd"
	synthService = "github"
)

func synthGrantRef() string { return FormatGrantRef(synthSession, synthService) }

// synthKVPath is the path defaultKVPath derives for the synthetic grant_ref.
func synthKVPath() string { return "grants/" + synthSession + "/" + synthService }

func newKVBackendOverFake(t *testing.T, f *fakeOpenBao) *KVBackend {
	t.Helper()
	client, err := kvclient.New(
		f.srv.URL, "secret",
		kvclient.JWTOIDCAuth{Role: f.expectedRole, JWT: f.expectedJWT},
		kvclient.WithHTTPClient(f.srv.Client()),
	)
	if err != nil {
		t.Fatalf("kvclient.New: %v", err)
	}
	be, err := NewKVBackend(client, KVBackendConfig{})
	if err != nil {
		t.Fatalf("NewKVBackend: %v", err)
	}
	return be
}

// TestKVBackend_FetchMapsReadToCredential is the happy path: a KV-v2 read of the
// grant's designated path maps to Credential{Secret, Location} (§9). The stored
// {secret, location} fields mirror FileKVBackend's on-disk shape.
func TestKVBackend_FetchMapsReadToCredential(t *testing.T) {
	f := newFakeOpenBao(t)
	f.secrets["secret/"+synthKVPath()] = map[string]any{
		"secret":   "ds-synth-ghp-do-not-use",
		"location": "Authorization",
	}
	be := newKVBackendOverFake(t, f)

	cred, err := be.Fetch(synthGrantRef())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(cred.Secret) != "ds-synth-ghp-do-not-use" {
		t.Fatalf("Secret = %q, want ds-synth-ghp-do-not-use", cred.Secret)
	}
	if cred.Location != "Authorization" {
		t.Fatalf("Location = %q, want Authorization", cred.Location)
	}

	// Read-only posture (§11.3): the fake only ever saw GET (read) + POST (login),
	// never a write verb — the adapter and the kv-client both lack a write path.
	for m := range f.seenMethods {
		if m != http.MethodGet && m != http.MethodPost {
			t.Fatalf("fake saw unexpected method %q — read-only posture broken", m)
		}
	}
}

// TestKVBackend_DefaultLocationFallback: a stored secret with no location field
// falls back to the frozen generic Authorization-header swap seam (D83).
func TestKVBackend_DefaultLocationFallback(t *testing.T) {
	f := newFakeOpenBao(t)
	f.secrets["secret/"+synthKVPath()] = map[string]any{"secret": "ds-synth-token"}
	be := newKVBackendOverFake(t, f)

	cred, err := be.Fetch(synthGrantRef())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if cred.Location != "Authorization" {
		t.Fatalf("Location = %q, want default Authorization", cred.Location)
	}
}

// TestKVBackend_MissingKeyIsGrantNotFound: a KV-v2 404 (no secret at the grant's
// path) is a DEFINITIVE deny -> ErrGrantNotFound, distinct from an outage stall.
func TestKVBackend_MissingKeyIsGrantNotFound(t *testing.T) {
	f := newFakeOpenBao(t)
	// No secret seeded at the path -> the fake 404s.
	be := newKVBackendOverFake(t, f)

	_, err := be.Fetch(synthGrantRef())
	if !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("err = %v, want ErrGrantNotFound", err)
	}
}

// TestKVBackend_StoreUnreachableIsStoreUnavailable: a closed/unreachable store
// (transport failure on login) maps to ErrStoreUnavailable — the §5.1
// availability stall, NOT ErrGrantNotFound.
func TestKVBackend_StoreUnreachableIsStoreUnavailable(t *testing.T) {
	f := newFakeOpenBao(t)
	client, err := kvclient.New(
		f.srv.URL, "secret",
		kvclient.JWTOIDCAuth{Role: f.expectedRole, JWT: f.expectedJWT},
		kvclient.WithHTTPClient(f.srv.Client()),
	)
	if err != nil {
		t.Fatalf("kvclient.New: %v", err)
	}
	be, err := NewKVBackend(client, KVBackendConfig{})
	if err != nil {
		t.Fatalf("NewKVBackend: %v", err)
	}
	// Close the fake BEFORE the fetch: the login POST hits a dead listener and the
	// transport errors out (store unreachable, the D39 availability dependency).
	f.srv.Close()

	_, err = be.Fetch(synthGrantRef())
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable", err)
	}
	if errors.Is(err, ErrGrantNotFound) {
		t.Fatal("unreachable store must NOT be reported as ErrGrantNotFound (would be a wrong definitive deny)")
	}
}

// TestKVBackend_PermissionDenyIsStoreUnavailable: the store is reachable but the
// platform role is unscoped (Vault 403 on read, and again after re-auth). This is
// NOT a confirmed absence, so it fails closed to ErrStoreUnavailable rather than
// being mistaken for a missing grant.
func TestKVBackend_PermissionDenyIsStoreUnavailable(t *testing.T) {
	f := newFakeOpenBao(t)
	// A secret exists, but every read demands a token the client never holds -> 403.
	f.requireToken = "a-token-the-client-will-never-hold"
	f.secrets["secret/"+synthKVPath()] = map[string]any{"secret": "ds-synth"}
	be := newKVBackendOverFake(t, f)

	_, err := be.Fetch(synthGrantRef())
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable", err)
	}
	if errors.Is(err, ErrGrantNotFound) {
		t.Fatal("permission deny must NOT be reported as ErrGrantNotFound")
	}
}

// TestKVBackend_AuthFailureIsStoreUnavailable: a login rejection (wrong JWT) is an
// availability/auth failure, not a missing grant -> ErrStoreUnavailable.
func TestKVBackend_AuthFailureIsStoreUnavailable(t *testing.T) {
	f := newFakeOpenBao(t)
	f.secrets["secret/"+synthKVPath()] = map[string]any{"secret": "ds-synth"}
	client, err := kvclient.New(
		f.srv.URL, "secret",
		kvclient.JWTOIDCAuth{Role: f.expectedRole, JWT: "WRONG-JWT"}, // login will 400
		kvclient.WithHTTPClient(f.srv.Client()),
	)
	if err != nil {
		t.Fatalf("kvclient.New: %v", err)
	}
	be, err := NewKVBackend(client, KVBackendConfig{})
	if err != nil {
		t.Fatalf("NewKVBackend: %v", err)
	}
	_, err = be.Fetch(synthGrantRef())
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("err = %v, want ErrStoreUnavailable", err)
	}
}

// TestKVBackend_UnparseableRefIsGrantNotFound: a grant_ref the §9 contract does
// not produce names no stored credential — the adapter fails closed to
// ErrGrantNotFound without ever touching the store (no login, no read).
func TestKVBackend_UnparseableRefIsGrantNotFound(t *testing.T) {
	f := newFakeOpenBao(t)
	be := newKVBackendOverFake(t, f)

	_, err := be.Fetch("not-a-grant-ref")
	if !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("err = %v, want ErrGrantNotFound", err)
	}
	// Fail-closed BEFORE any store I/O: no login POST, no read GET reached the fake.
	if len(f.seenMethods) != 0 {
		t.Fatalf("unparseable ref must not touch the store; saw methods %v", f.seenMethods)
	}
}

// TestKVBackend_MalformedSecretIsGrantNotFound: a stored secret missing the
// designated credential field is a malformed payload for this grant -> a
// definitive miss (ErrGrantNotFound), not a stall.
func TestKVBackend_MalformedSecretIsGrantNotFound(t *testing.T) {
	f := newFakeOpenBao(t)
	// Secret present but with no "secret" field (only an unrelated key).
	f.secrets["secret/"+synthKVPath()] = map[string]any{"unrelated": "x"}
	be := newKVBackendOverFake(t, f)

	_, err := be.Fetch(synthGrantRef())
	if !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("err = %v, want ErrGrantNotFound", err)
	}
}

// TestKVBackend_ConfigurableFieldsAndPath: the path layout and field names are
// FREE (§12), so a deployment can map a grant_ref to its own KV layout and read
// custom field names. Proves the adapter does not hard-code the OSS file fake's
// shape.
func TestKVBackend_ConfigurableFieldsAndPath(t *testing.T) {
	f := newFakeOpenBao(t)
	f.secrets["secret/custom/layout/github"] = map[string]any{
		"pat":    "ds-synth-custom-pat",
		"header": "X-Custom-Auth",
	}
	client, err := kvclient.New(
		f.srv.URL, "secret",
		kvclient.JWTOIDCAuth{Role: f.expectedRole, JWT: f.expectedJWT},
		kvclient.WithHTTPClient(f.srv.Client()),
	)
	if err != nil {
		t.Fatalf("kvclient.New: %v", err)
	}
	be, err := NewKVBackend(client, KVBackendConfig{
		PathFor: func(ref string) (string, bool) {
			_, service, ok := ParseGrantRef(ref)
			if !ok {
				return "", false
			}
			return "custom/layout/" + service, true
		},
		SecretField:   "pat",
		LocationField: "header",
	})
	if err != nil {
		t.Fatalf("NewKVBackend: %v", err)
	}
	cred, err := be.Fetch(synthGrantRef())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(cred.Secret) != "ds-synth-custom-pat" {
		t.Fatalf("Secret = %q", cred.Secret)
	}
	if cred.Location != "X-Custom-Auth" {
		t.Fatalf("Location = %q, want X-Custom-Auth", cred.Location)
	}
}

// TestKVBackend_NilReaderRejected: construction fails closed on a nil reader.
func TestKVBackend_NilReaderRejected(t *testing.T) {
	if _, err := NewKVBackend(nil, KVBackendConfig{}); err == nil {
		t.Fatal("nil reader should error")
	}
}

// TestKVBackend_SelectableBesideFileKVBackend is the load-bearing seam assertion:
// a KVBackend is a drop-in Backend, so Service.New takes it exactly where it takes
// FileKVBackend — a tier swap is a BACKEND swap, never a grant-service rewrite
// (backend.go's invariant). The SAME per-session protocol (§9) runs over both: a
// fetch resolves the credential, a second fetch is served from cache (the backend
// is consulted exactly once), and the credential matches what the OpenBao fake
// holds.
func TestKVBackend_SelectableBesideFileKVBackend(t *testing.T) {
	f := newFakeOpenBao(t)
	f.secrets["secret/"+synthKVPath()] = map[string]any{
		"secret":   "ds-synth-swap-cred",
		"location": "Authorization",
	}
	be := newKVBackendOverFake(t, f)

	// Drive the REAL grant-fetch protocol over the OpenBao-backed Backend — the
	// exact call shape service_test.go uses against FileKVBackend.
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	svc := New(be, WithClock(func() time.Time { return now }))
	svc.RegisterSession(synthSession, now.Add(time.Hour))

	cred, err := svc.Fetch(synthSession, synthService, synthGrantRef(), now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("Service.Fetch (miss): %v", err)
	}
	if string(cred.Secret) != "ds-synth-swap-cred" {
		t.Fatalf("Secret = %q, want ds-synth-swap-cred", cred.Secret)
	}

	loginsAfterFirst := f.seenMethods[http.MethodPost]
	getsAfterFirst := f.seenMethods[http.MethodGet]

	// Per-session, never per-request (§9): a second fetch is a cache HIT and does
	// NOT consult the backend again — so no further reads or logins reach the fake.
	cred2, err := svc.Fetch(synthSession, synthService, synthGrantRef(), now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("Service.Fetch (hit): %v", err)
	}
	if string(cred2.Secret) != "ds-synth-swap-cred" {
		t.Fatalf("cached Secret = %q", cred2.Secret)
	}
	if f.seenMethods[http.MethodGet] != getsAfterFirst {
		t.Fatalf("cache HIT must not re-read the store: GETs %d -> %d", getsAfterFirst, f.seenMethods[http.MethodGet])
	}
	if f.seenMethods[http.MethodPost] != loginsAfterFirst {
		t.Fatalf("cache HIT must not re-login: POSTs %d -> %d", loginsAfterFirst, f.seenMethods[http.MethodPost])
	}
}

// staticReader is a kvReader that records the context it was handed, so the
// NewContext config hook can be asserted without a live store.
type staticReader struct {
	sec     kvclient.Secret
	err     error
	gotCtx  context.Context
	gotPath string
}

func (r *staticReader) ReadSecret(ctx context.Context, path string) (kvclient.Secret, error) {
	r.gotCtx = ctx
	r.gotPath = path
	return r.sec, r.err
}

// TestKVBackend_NewContextHookUsed: the per-fetch context hook is honored (a
// deployment can wrap a deadline/cancel around the context-free Backend.Fetch).
func TestKVBackend_NewContextHookUsed(t *testing.T) {
	type ctxKey struct{}
	want := context.WithValue(context.Background(), ctxKey{}, "ds-synth-ctx")
	r := &staticReader{sec: kvclient.Secret{Data: map[string]any{"secret": "v"}}}
	be, err := NewKVBackend(r, KVBackendConfig{NewContext: func() context.Context { return want }})
	if err != nil {
		t.Fatalf("NewKVBackend: %v", err)
	}
	if _, err := be.Fetch(synthGrantRef()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if r.gotCtx == nil || r.gotCtx.Value(ctxKey{}) != "ds-synth-ctx" {
		t.Fatalf("adapter did not use the configured context (got %v)", r.gotCtx)
	}
	if r.gotPath != synthKVPath() {
		t.Fatalf("path = %q, want %q", r.gotPath, synthKVPath())
	}
}
