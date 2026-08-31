// SPDX-License-Identifier: Apache-2.0

// The config-driven Backend selector (doc 16 §9, §11.3; D19/D26/D51/D55/D85).
//
// This is the runnable FACTORY that makes the D39 key-store choice selectable at
// DEPLOY time, completing the "a tier swap is a BACKEND swap, never a
// grant-service rewrite" story (backend.go / kvbackend.go) end to end:
//
//   - the OSS hosted tier runs the LOCAL file/KV fake (FileKVBackend, backend.go),
//   - bring-compute/on-prem points at the customer's OpenBao-compatible KV
//     (KVBackend over ../kv-client/, kvbackend.go),
//
// and a deployment picks between them with CONFIG, not a code change. Both sit
// behind the same Backend seam, so New(SelectBackend(cfg)...) takes either — the
// selector only ever CONSTRUCTS a backend, it adds no new fetch behavior.
//
// READ-ONLY by construction (§11.3): the KV path here wires the kv-client (which
// exposes ReadSecret only — no write/lease/dynamic method anywhere) and the
// read-only KVBackend adapter; the selector introduces no write surface. The
// D19/D51 tier boundary is a SERVICE/BACKEND boundary (D80: never a flag inside a
// binary that toggles privileged behavior) — here it is literally a different
// Backend implementation chosen by config.
//
// No live store anywhere (D50): the file mode reads a synthetic JSON fixture; the
// kv mode is exercised against an httptest fake OpenBao/Vault in selector_test.go.
// No real key material is ever held by the selector — it constructs, it does not
// fetch.
package grantservice

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	kvclient "github.com/dream-serpent/dream-serpent/identity/kv-client"
)

// BackendMode names which Backend a deployment wants behind the grant-fetch seam.
// The empty string is the OSS default (file mode) so a zero Config selects the
// hosted file/KV fake — the tier you get with no extra wiring.
type BackendMode string

const (
	// ModeFile selects the OSS local file/KV fake (FileKVBackend, backend.go): a
	// synthetic JSON grant_ref -> {secret, location} fixture loaded from disk
	// (D50/D85). The default when SelectorConfig.Mode is empty.
	ModeFile BackendMode = "file"
	// ModeKV selects the OpenBao-compatible KV-v2 store (KVBackend over
	// ../kv-client/, kvbackend.go): the bring-compute/on-prem tier where the
	// customer's Vault/OpenBao IS the D39 store (§11.3). READ-ONLY (ReadSecret only).
	ModeKV BackendMode = "kv"
)

// AuthMode names how the KV-v2 transport authenticates the PLATFORM SERVICE to
// the store (kv-client/auth.go, §11.3): JWT/OIDC by default, AppRole as the
// compatibility fallback. Ignored in file mode.
type AuthMode string

const (
	// AuthJWTOIDC is the DEFAULT platform auth (§11.3): present the platform's
	// workload-identity JWT to Vault's jwt/oidc backend, bound to a customer role
	// scoped to the D84-designated mounts.
	AuthJWTOIDC AuthMode = "jwt"
	// AuthAppRole is the FALLBACK (§11.3): a platform-service RoleID/SecretID pair
	// where no usable JWT/OIDC backend exists. Same principal, same role scoping;
	// only the credential shape differs.
	AuthAppRole AuthMode = "approle"
)

// ErrInvalidConfig is returned by SelectBackend when the resolved config cannot
// name a Backend — an empty file path in file mode, a missing addr/mount in kv
// mode, or an incomplete auth credential. Fail-closed: an ambiguous config
// selects NO backend, never a silently-wrong one.
var ErrInvalidConfig = errors.New("grantservice: invalid backend selector config")

// SelectorConfig is the deploy-time backend choice, read from env (LoadConfigEnv)
// or flags (BindFlags). The zero value selects the OSS file mode — but with an
// empty FilePath, which SelectBackend rejects as ErrInvalidConfig, so a real
// deployment must always name a fixture path or switch to kv mode.
type SelectorConfig struct {
	// Mode picks the Backend: ModeFile (default, the OSS file/KV fake) or ModeKV
	// (the OpenBao-compatible store). An empty Mode is treated as ModeFile.
	Mode BackendMode

	// FilePath is the synthetic JSON fixture (grant_ref -> {secret, location})
	// loaded in file mode (D50). Required in file mode; ignored in kv mode.
	FilePath string

	// --- kv mode (the OpenBao-compatible KV-v2 transport) ---

	// Addr is the store base address, e.g. "https://vault.example.com:8200".
	// Required in kv mode.
	Addr string
	// Mount is the KV-v2 secrets-engine mount, e.g. "secret". Required in kv mode.
	Mount string

	// Auth selects the platform-service auth method (AuthJWTOIDC default,
	// AuthAppRole fallback). Empty is treated as AuthJWTOIDC.
	Auth AuthMode
	// AuthMount is the Vault auth mount the auth backend is enabled at (e.g. "jwt"
	// or "approle"). Empty selects the kv-client's per-method default.
	AuthMount string

	// JWT-mode credentials (§11.3): the platform-service workload-identity JWT and
	// the customer-bound Vault role.
	Role string
	JWT  string

	// AppRole-mode credentials (§11.3): the platform-service RoleID/SecretID pair.
	RoleID   string
	SecretID string

	// --- KV path layout (FREE per §12, bounded by OpenBao compatibility) ---

	// SecretField overrides the KV-v2 payload key holding the credential material.
	// Empty selects the KVBackend default ("secret").
	SecretField string
	// LocationField overrides the KV-v2 payload key holding the swap location (the
	// D83 header name). Empty selects the KVBackend default ("location").
	LocationField string
}

// resolvedMode returns the effective mode, treating the empty string as ModeFile
// (the OSS default tier).
func (c SelectorConfig) resolvedMode() BackendMode {
	if c.Mode == "" {
		return ModeFile
	}
	return c.Mode
}

// resolvedAuth returns the effective auth method, treating the empty string as
// AuthJWTOIDC (the §11.3 default).
func (c SelectorConfig) resolvedAuth() AuthMode {
	if c.Auth == "" {
		return AuthJWTOIDC
	}
	return c.Auth
}

// LoadConfigEnv reads a SelectorConfig from the GRANT_BACKEND_* environment, the
// way a deployment wires the grant service without flags. Unset variables leave
// the zero value (so an all-unset environment yields file mode with an empty path
// — which SelectBackend then rejects, forcing an explicit choice). The env keys:
//
//	GRANT_BACKEND_MODE         file | kv            (default file)
//	GRANT_BACKEND_FILE_PATH    synthetic fixture path (file mode)
//	GRANT_BACKEND_ADDR         store base address     (kv mode)
//	GRANT_BACKEND_MOUNT        KV-v2 mount            (kv mode)
//	GRANT_BACKEND_AUTH         jwt | approle          (default jwt)
//	GRANT_BACKEND_AUTH_MOUNT   auth backend mount     (kv mode, optional)
//	GRANT_BACKEND_ROLE         vault role             (jwt auth)
//	GRANT_BACKEND_JWT          platform workload JWT  (jwt auth)
//	GRANT_BACKEND_ROLE_ID      approle RoleID         (approle auth)
//	GRANT_BACKEND_SECRET_ID    approle SecretID       (approle auth)
//	GRANT_BACKEND_SECRET_FIELD KV payload secret key  (kv mode, optional)
//	GRANT_BACKEND_LOCATION_FIELD KV payload location key (kv mode, optional)
//
// Secret material (JWT/SecretID) is read from the environment into the returned
// config and never logged here; the selector constructs the auth value and hands
// it to the kv-client. No value is recorded in any Observation (D50).
func LoadConfigEnv() SelectorConfig {
	return SelectorConfig{
		Mode:          BackendMode(strings.TrimSpace(os.Getenv("GRANT_BACKEND_MODE"))),
		FilePath:      os.Getenv("GRANT_BACKEND_FILE_PATH"),
		Addr:          os.Getenv("GRANT_BACKEND_ADDR"),
		Mount:         os.Getenv("GRANT_BACKEND_MOUNT"),
		Auth:          AuthMode(strings.TrimSpace(os.Getenv("GRANT_BACKEND_AUTH"))),
		AuthMount:     os.Getenv("GRANT_BACKEND_AUTH_MOUNT"),
		Role:          os.Getenv("GRANT_BACKEND_ROLE"),
		JWT:           os.Getenv("GRANT_BACKEND_JWT"),
		RoleID:        os.Getenv("GRANT_BACKEND_ROLE_ID"),
		SecretID:      os.Getenv("GRANT_BACKEND_SECRET_ID"),
		SecretField:   os.Getenv("GRANT_BACKEND_SECRET_FIELD"),
		LocationField: os.Getenv("GRANT_BACKEND_LOCATION_FIELD"),
	}
}

// BindFlags registers the GRANT_BACKEND_* surface as -grant-backend-* flags on fs,
// writing into cfg, and returns a finalize func the caller runs AFTER fs.Parse to
// fold the string-valued mode/auth flags back into cfg's typed fields. A
// deployment can combine env + flags: seed cfg from LoadConfigEnv, BindFlags(fs,
// &cfg), fs.Parse(args), then finalize() — so the env is the default and a flag is
// the override. Mode/auth are string flags (Go's flag package has no enum), so the
// finalize step is what makes a -grant-backend-mode override actually land on
// cfg.Mode. Secret-valued flags (jwt, secret-id) are accepted for completeness;
// production wiring prefers the environment so a secret never lands in a process
// argv (and is never recorded in any Observation, D50).
func BindFlags(fs *flag.FlagSet, cfg *SelectorConfig) (finalize func()) {
	mode := string(cfg.Mode)
	auth := string(cfg.Auth)
	fs.StringVar(&mode, "grant-backend-mode", mode, "grant backend mode: file | kv (default file)")
	fs.StringVar(&cfg.FilePath, "grant-backend-file-path", cfg.FilePath, "synthetic JSON fixture path (file mode)")
	fs.StringVar(&cfg.Addr, "grant-backend-addr", cfg.Addr, "store base address (kv mode)")
	fs.StringVar(&cfg.Mount, "grant-backend-mount", cfg.Mount, "KV-v2 secrets-engine mount (kv mode)")
	fs.StringVar(&auth, "grant-backend-auth", auth, "platform auth: jwt | approle (default jwt)")
	fs.StringVar(&cfg.AuthMount, "grant-backend-auth-mount", cfg.AuthMount, "auth backend mount (kv mode, optional)")
	fs.StringVar(&cfg.Role, "grant-backend-role", cfg.Role, "vault role (jwt auth)")
	fs.StringVar(&cfg.JWT, "grant-backend-jwt", cfg.JWT, "platform workload-identity JWT (jwt auth; prefer env)")
	fs.StringVar(&cfg.RoleID, "grant-backend-role-id", cfg.RoleID, "approle RoleID (approle auth)")
	fs.StringVar(&cfg.SecretID, "grant-backend-secret-id", cfg.SecretID, "approle SecretID (approle auth; prefer env)")
	fs.StringVar(&cfg.SecretField, "grant-backend-secret-field", cfg.SecretField, "KV-v2 payload secret key (kv mode, optional)")
	fs.StringVar(&cfg.LocationField, "grant-backend-location-field", cfg.LocationField, "KV-v2 payload location key (kv mode, optional)")
	return func() {
		cfg.Mode = BackendMode(mode)
		cfg.Auth = AuthMode(auth)
	}
}

// SelectBackend constructs the Backend named by cfg — the config-driven factory at
// the heart of the tier swap (D19/D51). It NEVER fetches; it only builds:
//
//   - file mode  -> NewFileKVBackend(FilePath)            (the OSS file/KV fake)
//   - kv mode    -> kv-client transport (Addr+Mount+Auth) -> NewKVBackend(reader, cfg)
//
// The returned value is a plain Backend, so New(SelectBackend(cfg)...) wires the
// grant service identically regardless of tier (the seam invariant). httpOpts are
// forwarded to the kv-client in kv mode — tests pass kvclient.WithHTTPClient over
// an httptest fake (D50); production passes nothing and the client uses HTTPS.
//
// Fail-closed: a config that cannot name a backend (empty path / missing addr or
// mount / incomplete auth) returns ErrInvalidConfig — never a partial or
// silently-wrong backend.
func SelectBackend(cfg SelectorConfig, httpOpts ...kvclient.Option) (Backend, error) {
	switch cfg.resolvedMode() {
	case ModeFile:
		if strings.TrimSpace(cfg.FilePath) == "" {
			return nil, fmt.Errorf("%w: file mode requires a fixture path", ErrInvalidConfig)
		}
		// The OSS local file/KV fake: a synthetic JSON fixture (D50). NewFileKVBackend
		// surfaces a read/parse error directly so a missing/garbled fixture fails loud
		// at construction, never at fetch time.
		return NewFileKVBackend(cfg.FilePath)

	case ModeKV:
		auth, err := buildAuthenticator(cfg)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(cfg.Addr) == "" {
			return nil, fmt.Errorf("%w: kv mode requires a store address", ErrInvalidConfig)
		}
		if strings.TrimSpace(cfg.Mount) == "" {
			return nil, fmt.Errorf("%w: kv mode requires a kv mount", ErrInvalidConfig)
		}
		// The OpenBao-compatible KV-v2 READ-ONLY transport (../kv-client/). It exposes
		// ReadSecret only — no write/lease/dynamic method — so the §11.3 read-only
		// posture holds across the seam. Construction does NO network I/O (login is
		// lazy on first read), so the selector never blocks on store availability.
		client, err := kvclient.New(cfg.Addr, cfg.Mount, auth, httpOpts...)
		if err != nil {
			// A construction error here is a config problem (empty addr/mount/auth),
			// already guarded above; wrap it as invalid config for a uniform caller.
			return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
		}
		// The KVBackend adapter only ever calls ReadSecret (read-only posture, §11.3).
		return NewKVBackend(client, KVBackendConfig{
			SecretField:   cfg.SecretField,
			LocationField: cfg.LocationField,
		})

	default:
		return nil, fmt.Errorf("%w: unknown backend mode %q (want file|kv)", ErrInvalidConfig, cfg.Mode)
	}
}

// buildAuthenticator constructs the platform-service Authenticator for kv mode
// (kv-client/auth.go, §11.3). JWT/OIDC is the default; AppRole is the fallback.
// Required credentials are validated here so an incomplete auth config fails
// closed as ErrInvalidConfig before any store wiring.
func buildAuthenticator(cfg SelectorConfig) (kvclient.Authenticator, error) {
	switch cfg.resolvedAuth() {
	case AuthJWTOIDC:
		if strings.TrimSpace(cfg.Role) == "" || strings.TrimSpace(cfg.JWT) == "" {
			return nil, fmt.Errorf("%w: jwt auth requires a role and a jwt", ErrInvalidConfig)
		}
		return kvclient.JWTOIDCAuth{Role: cfg.Role, JWT: cfg.JWT, MountPath: cfg.AuthMount}, nil
	case AuthAppRole:
		if strings.TrimSpace(cfg.RoleID) == "" || strings.TrimSpace(cfg.SecretID) == "" {
			return nil, fmt.Errorf("%w: approle auth requires a role_id and a secret_id", ErrInvalidConfig)
		}
		return kvclient.AppRoleAuth{RoleID: cfg.RoleID, SecretID: cfg.SecretID, MountPath: cfg.AuthMount}, nil
	default:
		return nil, fmt.Errorf("%w: unknown auth mode %q (want jwt|approle)", ErrInvalidConfig, cfg.Auth)
	}
}
