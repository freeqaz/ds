// SPDX-License-Identifier: Apache-2.0

// Tests for the config-driven Backend selector (doc 16 §9, §11.3; D19/D26/D51/D85)
// — the deploy-time factory that picks the OSS file/KV fake vs the
// OpenBao-compatible KV store BEHIND the same Backend seam. Driven against the OSS
// file fake (a synthetic JSON fixture, D50) and the in-package httptest fake
// OpenBao/Vault (kvbackend_test.go's fakeOpenBao) — NO live store anywhere (D50).
// The load-bearing assertions:
//
//	empty/file mode -> *FileKVBackend, the same Backend service.go takes today
//	kv mode         -> *KVBackend over the REAL kv-client, drop-in BESIDE the fake
//	a tier swap is a CONFIG change (same New(SelectBackend(cfg)...) wiring), §11.3
//	read-only posture preserved: kv mode only ever drives ReadSecret (GET+login)
//	fail-closed: an ambiguous config selects NO backend (ErrInvalidConfig)
//
// Synthetic ds-synth-* fixtures only; no secret bytes are logged or recorded.
package grantservice

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kvclient "github.com/dream-serpent/dream-serpent/identity/kv-client"
)

// newApproleFakeOpenBao builds an approle-speaking fake (D50) that mints a token on
// an AppRole login (role_id + secret_id) rather than JWT/OIDC, so the AppRole-auth
// branch of the selector can be exercised. It reuses the in-package fakeOpenBao's
// KV-v2 read surface (handleRead) and only swaps the login handler. NO live store:
// presents a non-empty role_id + secret_id mints the synthetic token; KV-v2 reads
// then carry it. The read surface is identical to fakeOpenBao's.
func newApproleFakeOpenBao(t *testing.T) *fakeOpenBao {
	t.Helper()
	f := &fakeOpenBao{
		mintToken:   "ds-synth-vault-token-approle",
		secrets:     map[string]map[string]any{},
		seenMethods: map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.seenMethods[r.Method]++
		p := strings.TrimPrefix(r.URL.Path, "/v1/")
		switch {
		case strings.HasPrefix(p, "auth/") && strings.HasSuffix(p, "/login"):
			if r.Method != http.MethodPost {
				writeVaultErr(w, http.StatusMethodNotAllowed, "login is POST")
				return
			}
			var body map[string]string
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				writeVaultErr(w, http.StatusBadRequest, "bad login body")
				return
			}
			if body["role_id"] == "" || body["secret_id"] == "" {
				writeVaultErr(w, http.StatusBadRequest, "invalid role_id/secret_id")
				return
			}
			writeVaultJSON(w, http.StatusOK, map[string]any{
				"auth": map[string]any{"client_token": f.mintToken, "lease_duration": 3600, "renewable": true},
			})
		case strings.Contains(p, "/data/"):
			f.handleRead(w, r, p)
		default:
			writeVaultErr(w, http.StatusNotFound, "unsupported path: "+p)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// writeSyntheticFixture writes a synthetic grant_ref -> {secret, location} JSON
// fixture (D50) to a temp file and returns its path. The single seeded grant_ref
// is the same synthSession×synthService the kv-mode fake uses, so both modes
// resolve the same logical grant.
func writeSyntheticFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grants.json")
	body := `{"` + synthGrantRef() + `":{"secret":"ds-synth-file-cred","location":"Authorization"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestSelector_EmptyModeSelectsFileBackend: the zero/empty Mode is the OSS file
// tier (the default you get with no extra wiring). With a valid fixture path the
// selector returns a *FileKVBackend — the exact Backend service.go takes today.
func TestSelector_EmptyModeSelectsFileBackend(t *testing.T) {
	path := writeSyntheticFixture(t)
	be, err := SelectBackend(SelectorConfig{FilePath: path}) // Mode unset -> file
	if err != nil {
		t.Fatalf("SelectBackend(file): %v", err)
	}
	if _, ok := be.(*FileKVBackend); !ok {
		t.Fatalf("empty mode selected %T, want *FileKVBackend", be)
	}
	cred, err := be.Fetch(synthGrantRef())
	if err != nil {
		t.Fatalf("file backend Fetch: %v", err)
	}
	if string(cred.Secret) != "ds-synth-file-cred" {
		t.Fatalf("Secret = %q, want ds-synth-file-cred", cred.Secret)
	}
}

// TestSelector_FileModeWiresService: file mode is selectable end to end —
// New(SelectBackend(cfg)...) runs the per-session protocol over the OSS fake with
// no grant-service change. This is the OSS-tier half of "a tier swap is a backend
// swap" (D19/D51).
func TestSelector_FileModeWiresService(t *testing.T) {
	path := writeSyntheticFixture(t)
	be, err := SelectBackend(SelectorConfig{Mode: ModeFile, FilePath: path})
	if err != nil {
		t.Fatalf("SelectBackend(file): %v", err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := New(be, WithClock(func() time.Time { return now }))
	svc.RegisterSession(synthSession, now.Add(time.Hour))
	cred, err := svc.Fetch(synthSession, synthService, synthGrantRef(), now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("Service.Fetch over file backend: %v", err)
	}
	if string(cred.Secret) != "ds-synth-file-cred" {
		t.Fatalf("Secret = %q, want ds-synth-file-cred", cred.Secret)
	}
}

// TestSelector_KVModeSelectsKVBackend: kv mode constructs the ../kv-client
// transport (addr+mount+auth) and a *KVBackend over it — the OpenBao tier, chosen
// purely by config. Driven against the httptest fake (D50), the SAME synthetic
// session×service so it parallels the file-mode test.
func TestSelector_KVModeSelectsKVBackend(t *testing.T) {
	f := newFakeOpenBao(t)
	f.secrets["secret/"+synthKVPath()] = map[string]any{
		"secret":   "ds-synth-kv-cred",
		"location": "Authorization",
	}
	cfg := SelectorConfig{
		Mode:  ModeKV,
		Addr:  f.srv.URL,
		Mount: "secret",
		Auth:  AuthJWTOIDC,
		Role:  f.expectedRole,
		JWT:   f.expectedJWT,
	}
	be, err := SelectBackend(cfg, kvclient.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatalf("SelectBackend(kv): %v", err)
	}
	if _, ok := be.(*KVBackend); !ok {
		t.Fatalf("kv mode selected %T, want *KVBackend", be)
	}
	cred, err := be.Fetch(synthGrantRef())
	if err != nil {
		t.Fatalf("kv backend Fetch: %v", err)
	}
	if string(cred.Secret) != "ds-synth-kv-cred" {
		t.Fatalf("Secret = %q, want ds-synth-kv-cred", cred.Secret)
	}
	// Read-only posture (§11.3): only GET (read) + POST (login) ever reached the
	// store — the selector wires no write surface.
	for m := range f.seenMethods {
		if m != http.MethodGet && m != http.MethodPost {
			t.Fatalf("fake saw unexpected method %q — read-only posture broken", m)
		}
	}
}

// TestSelector_KVModeWiresServiceAsTierSwap is the load-bearing seam assertion:
// the SAME New(SelectBackend(cfg)...) wiring that runs the OSS file tier runs the
// OpenBao tier when only cfg.Mode flips to kv — a tier swap is a CONFIG change, the
// grant-service protocol is untouched (D19/D51; backend.go's invariant). The
// per-session protocol resolves the credential and a second fetch is a cache HIT
// (the backend is consulted exactly once).
func TestSelector_KVModeWiresServiceAsTierSwap(t *testing.T) {
	f := newFakeOpenBao(t)
	f.secrets["secret/"+synthKVPath()] = map[string]any{
		"secret":   "ds-synth-swap-cred",
		"location": "Authorization",
	}
	be, err := SelectBackend(SelectorConfig{
		Mode: ModeKV, Addr: f.srv.URL, Mount: "secret",
		Role: f.expectedRole, JWT: f.expectedJWT, // Auth unset -> jwt default
	}, kvclient.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatalf("SelectBackend(kv): %v", err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := New(be, WithClock(func() time.Time { return now }))
	svc.RegisterSession(synthSession, now.Add(time.Hour))

	cred, err := svc.Fetch(synthSession, synthService, synthGrantRef(), now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("Service.Fetch (miss): %v", err)
	}
	if string(cred.Secret) != "ds-synth-swap-cred" {
		t.Fatalf("Secret = %q, want ds-synth-swap-cred", cred.Secret)
	}
	getsAfterFirst := f.seenMethods[http.MethodGet]
	loginsAfterFirst := f.seenMethods[http.MethodPost]
	if _, err := svc.Fetch(synthSession, synthService, synthGrantRef(), now.Add(30*time.Minute)); err != nil {
		t.Fatalf("Service.Fetch (hit): %v", err)
	}
	if f.seenMethods[http.MethodGet] != getsAfterFirst {
		t.Fatalf("cache HIT must not re-read the store: GETs %d -> %d", getsAfterFirst, f.seenMethods[http.MethodGet])
	}
	if f.seenMethods[http.MethodPost] != loginsAfterFirst {
		t.Fatalf("cache HIT must not re-login: POSTs %d -> %d", loginsAfterFirst, f.seenMethods[http.MethodPost])
	}
}

// TestSelector_KVModeAppRoleAuth: the AppRole fallback (§11.3) is selectable by
// config — same principal, same store, only the credential shape differs. The fake
// accepts the synthetic platform JWT, so we drive AppRole against a fake that
// mints on any approle login.
func TestSelector_KVModeAppRoleAuth(t *testing.T) {
	f := newApproleFakeOpenBao(t)
	f.secrets["secret/"+synthKVPath()] = map[string]any{"secret": "ds-synth-approle-cred"}
	be, err := SelectBackend(SelectorConfig{
		Mode: ModeKV, Addr: f.srv.URL, Mount: "secret",
		Auth: AuthAppRole, RoleID: "ds-synth-role-id", SecretID: "ds-synth-secret-id",
	}, kvclient.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatalf("SelectBackend(kv approle): %v", err)
	}
	cred, err := be.Fetch(synthGrantRef())
	if err != nil {
		t.Fatalf("approle backend Fetch: %v", err)
	}
	if string(cred.Secret) != "ds-synth-approle-cred" {
		t.Fatalf("Secret = %q, want ds-synth-approle-cred", cred.Secret)
	}
}

// TestSelector_ConfigurableKVFields: SecretField/LocationField from config flow
// through to the KVBackend adapter (the §12-free KV layout), so a deployment maps
// its own KV payload shape without a code change.
func TestSelector_ConfigurableKVFields(t *testing.T) {
	f := newFakeOpenBao(t)
	f.secrets["secret/"+synthKVPath()] = map[string]any{
		"pat":    "ds-synth-custom-pat",
		"header": "X-Custom-Auth",
	}
	be, err := SelectBackend(SelectorConfig{
		Mode: ModeKV, Addr: f.srv.URL, Mount: "secret",
		Role: f.expectedRole, JWT: f.expectedJWT,
		SecretField: "pat", LocationField: "header",
	}, kvclient.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatalf("SelectBackend(kv custom fields): %v", err)
	}
	cred, err := be.Fetch(synthGrantRef())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(cred.Secret) != "ds-synth-custom-pat" || cred.Location != "X-Custom-Auth" {
		t.Fatalf("cred = {%q,%q}, want {ds-synth-custom-pat, X-Custom-Auth}", cred.Secret, cred.Location)
	}
}

// TestSelector_InvalidConfigsFailClosed: every ambiguous/incomplete config selects
// NO backend (ErrInvalidConfig) — fail-closed, never a partial or silently-wrong
// backend. Construction does no network I/O, so these never touch a store.
func TestSelector_InvalidConfigsFailClosed(t *testing.T) {
	cases := []struct {
		name string
		cfg  SelectorConfig
	}{
		{"file mode without a path", SelectorConfig{Mode: ModeFile}},
		{"zero config (file mode, empty path)", SelectorConfig{}},
		{"kv mode without an addr", SelectorConfig{Mode: ModeKV, Mount: "secret", Role: "r", JWT: "j"}},
		{"kv mode without a mount", SelectorConfig{Mode: ModeKV, Addr: "https://x:8200", Role: "r", JWT: "j"}},
		{"kv jwt auth without a role", SelectorConfig{Mode: ModeKV, Addr: "https://x:8200", Mount: "secret", JWT: "j"}},
		{"kv jwt auth without a jwt", SelectorConfig{Mode: ModeKV, Addr: "https://x:8200", Mount: "secret", Role: "r"}},
		{"kv approle without a role_id", SelectorConfig{Mode: ModeKV, Addr: "https://x:8200", Mount: "secret", Auth: AuthAppRole, SecretID: "s"}},
		{"kv approle without a secret_id", SelectorConfig{Mode: ModeKV, Addr: "https://x:8200", Mount: "secret", Auth: AuthAppRole, RoleID: "r"}},
		{"unknown mode", SelectorConfig{Mode: BackendMode("dynamo")}},
		{"unknown auth", SelectorConfig{Mode: ModeKV, Addr: "https://x:8200", Mount: "secret", Auth: AuthMode("ldap")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be, err := SelectBackend(tc.cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
			if be != nil {
				t.Fatalf("a rejected config must select NO backend, got %T", be)
			}
		})
	}
}

// TestSelector_LoadConfigEnv: the GRANT_BACKEND_* environment maps onto a
// SelectorConfig, the way a deployment wires the service without flags. Secret
// material is read into the config but never logged here.
func TestSelector_LoadConfigEnv(t *testing.T) {
	t.Setenv("GRANT_BACKEND_MODE", "kv")
	t.Setenv("GRANT_BACKEND_ADDR", "https://vault.synth:8200")
	t.Setenv("GRANT_BACKEND_MOUNT", "secret")
	t.Setenv("GRANT_BACKEND_AUTH", "approle")
	t.Setenv("GRANT_BACKEND_ROLE_ID", "ds-synth-role-id")
	t.Setenv("GRANT_BACKEND_SECRET_ID", "ds-synth-secret-id")
	t.Setenv("GRANT_BACKEND_SECRET_FIELD", "pat")
	cfg := LoadConfigEnv()
	if cfg.Mode != ModeKV || cfg.Addr != "https://vault.synth:8200" || cfg.Mount != "secret" {
		t.Fatalf("env -> cfg core fields wrong: %+v", cfg)
	}
	if cfg.Auth != AuthAppRole || cfg.RoleID != "ds-synth-role-id" || cfg.SecretID != "ds-synth-secret-id" {
		t.Fatalf("env -> cfg auth fields wrong: %+v", cfg)
	}
	if cfg.SecretField != "pat" {
		t.Fatalf("env -> cfg SecretField = %q, want pat", cfg.SecretField)
	}
}

// TestSelector_BindFlagsOverrideEnv: env seeds defaults, a flag overrides — the
// documented env+flag layering. The finalize hook folds the string mode/auth
// flags back into the typed config.
func TestSelector_BindFlagsOverrideEnv(t *testing.T) {
	t.Setenv("GRANT_BACKEND_MODE", "file")
	t.Setenv("GRANT_BACKEND_FILE_PATH", "/seeded/from/env.json")
	cfg := LoadConfigEnv()
	if cfg.Mode != ModeFile || cfg.FilePath != "/seeded/from/env.json" {
		t.Fatalf("env seed wrong: %+v", cfg)
	}
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	finalize := BindFlags(fs, &cfg)
	if err := fs.Parse([]string{
		"-grant-backend-mode=kv",
		"-grant-backend-addr=https://override:8200",
		"-grant-backend-mount=kv2",
		"-grant-backend-role=r", "-grant-backend-jwt=j",
	}); err != nil {
		t.Fatalf("fs.Parse: %v", err)
	}
	finalize()
	if cfg.Mode != ModeKV {
		t.Fatalf("flag did not override Mode: %q", cfg.Mode)
	}
	if cfg.Addr != "https://override:8200" || cfg.Mount != "kv2" {
		t.Fatalf("flag override of addr/mount failed: %+v", cfg)
	}
	// Env-seeded value the flag did not touch is preserved.
	if cfg.FilePath != "/seeded/from/env.json" {
		t.Fatalf("untouched env value lost: %q", cfg.FilePath)
	}
}

// TestSelector_FileFixtureMissingFailsLoud: file mode surfaces a missing/garbled
// fixture as a construction error (NewFileKVBackend's os.ReadFile error), never a
// silent empty backend.
func TestSelector_FileFixtureMissingFailsLoud(t *testing.T) {
	_, err := SelectBackend(SelectorConfig{Mode: ModeFile, FilePath: filepath.Join(t.TempDir(), "does-not-exist.json")})
	if err == nil {
		t.Fatal("missing fixture should error at construction")
	}
}
