// SPDX-License-Identifier: Apache-2.0

// The OpenBao-compatible KV-v2 Backend impl (doc 16 §9, §11.3; D39/D55/D85).
//
// This is the HIGHER-TIER sibling of FileKVBackend (backend.go): at
// bring-compute/on-prem the customer's Vault/OpenBao IS the D39 store (§11.3), and
// this adapter fronts it behind the SAME Backend seam — so a tier swap is a
// BACKEND swap, never a grant-service rewrite (backend.go's stated invariant). The
// per-session fetch/cache protocol in service.go is unchanged; only the substrate
// behind Backend.Fetch differs.
//
// The actual store transport is the standalone ../kv-client/ module — the generic
// OpenBao-compatible KV-v2 READ-ONLY client (consumed here as a dependency via
// go.mod require + replace; NOT edited here). This file is the thin ADAPTER that
// maps that client's surface onto the Backend contract:
//
//   - a KV-v2 read of the grant's designated path -> Credential{Secret, Location}
//   - the store unreachable / a login failure / a permission deny / any other
//     non-200 -> ErrStoreUnavailable (the §5.1 availability-dependency stall: a
//     NEW fetch fails, an in-flight session rides its cache in service.go)
//   - a definitive miss (KV-v2 404) -> ErrGrantNotFound (a missing grant is a
//     deny, not a stall)
//
// READ-ONLY by construction: the kv-client exposes no write/lease/dynamic method
// (its TestReadOnlyPostureIsStructural pins that), and this adapter only calls
// ReadSecret — so the §11.3 "KV v2 read-only in v0" posture holds across the seam.
//
// No live store anywhere: the regression suite (kvbackend_test.go) drives this
// against an httptest fake OpenBao/Vault server speaking the documented KV-v2 wire
// shapes (D50: synthetic fixtures only; NO live OpenBao this wave). The fetched
// material is held in memory ≤ session by service.go (the bounded D76 exposure);
// it never enters the VM and never sits on the virtual-metal host (D8/D39).
package grantservice

import (
	"context"
	"errors"
	"fmt"

	kvclient "github.com/dream-serpent/dream-serpent/identity/kv-client"
)

// Field names this adapter reads out of a KV-v2 secret payload by default. They
// mirror FileKVBackend's on-disk {secret, location} shape (backend.go's
// fileEntry) so the OSS file fake and the OpenBao-backed store agree on the
// stored-credential layout — a tier swap reads the same fields. Both are FREE per
// §12 (path/layout conventions are free, bounded by OpenBao compatibility) and
// overridable via KVBackendConfig.
const (
	defaultSecretField   = "secret"
	defaultLocationField = "location"
	// defaultLocation is the frozen generic Authorization-header swap seam (D83):
	// when a stored secret carries no explicit location field, the swap executor
	// substitutes into Authorization. Matches Credential.Location's default.
	defaultLocation = "Authorization"
)

// kvReader is the minimal read surface this adapter needs from the kv-client. It
// is satisfied by *kvclient.Client (ReadSecret, the §5.1/§5.2 swap-class fetch).
// Declaring it as an interface keeps the adapter unit-testable against the real
// client over an httptest fake (no live store, D50) AND documents that the
// adapter touches ONLY the read path — never a write/lease/dynamic method, which
// the kv-client does not expose anyway (its read-only-by-construction posture).
type kvReader interface {
	ReadSecret(ctx context.Context, path string) (kvclient.Secret, error)
}

// KVPathFunc maps a grant_ref to the logical KV-v2 path (under the kv-client's
// configured mount) where the store holds that grant's credential. KV path/layout
// conventions are FREE (§12, bounded by OpenBao compatibility), so the mapping is
// injectable; defaultKVPath derives a deterministic, secret-free path from the
// grant_ref's parsed (session, service) axes. ok is false for a grant_ref that
// does not parse — the adapter turns that into ErrGrantNotFound (fail-closed: an
// unparseable ref names no stored credential, never a silently-wrong lookup).
type KVPathFunc func(grantRef string) (path string, ok bool)

// defaultKVPath maps grant:<session>:<service> -> "grants/<session>/<service>",
// a deterministic, secret-free layout under the kv-client's mount. The grant_ref
// is the §9 contract handle (grantref.go); a ref that does not parse names no
// credential.
func defaultKVPath(grantRef string) (string, bool) {
	session, service, ok := ParseGrantRef(grantRef)
	if !ok {
		return "", false
	}
	return "grants/" + session + "/" + service, true
}

// KVBackendConfig tunes the KV-v2 adapter. The zero value is usable: an empty
// config selects the default path layout, the default {secret, location} field
// names, and a background context per fetch.
type KVBackendConfig struct {
	// PathFor maps a grant_ref to the logical KV-v2 path. nil selects
	// defaultKVPath (grants/<session>/<service>).
	PathFor KVPathFunc
	// SecretField is the key under the KV-v2 secret payload that holds the
	// credential material. Empty selects defaultSecretField ("secret").
	SecretField string
	// LocationField is the key that holds the swap location (the D83 header
	// name). Empty selects defaultLocationField ("location"); a stored secret
	// that omits it falls back to defaultLocation ("Authorization").
	LocationField string
	// NewContext supplies the per-fetch context for the kv-client read (the
	// Backend.Fetch contract is context-free, so the adapter owns context
	// creation — a deployment can wrap a deadline/cancel here). nil selects
	// context.Background.
	NewContext func() context.Context
}

// KVBackend adapts the OpenBao-compatible KV-v2 client (../kv-client/) to the
// Backend seam (backend.go). It is selectable BESIDE FileKVBackend: both satisfy
// Backend, so New(backend) takes either — the hosted/OSS file fake or the
// customer's OpenBao store — with no change to service.go's per-session protocol.
type KVBackend struct {
	reader        kvReader
	pathFor       KVPathFunc
	secretField   string
	locationField string
	newContext    func() context.Context
}

// compile-time assertion: KVBackend satisfies the Backend seam, so a tier swap is
// a constructor swap (New(NewKVBackend(...)) vs New(NewFileKVBackend(...))).
var _ Backend = (*KVBackend)(nil)

// NewKVBackend builds a KV-v2-backed Backend over an existing kv-client
// (*kvclient.Client, the production OpenBao-compatible transport — or any
// kvReader, e.g. an httptest-backed client in tests, D50). reader must be
// non-nil. The config's zero value is usable (default path layout + field names +
// background context).
func NewKVBackend(reader kvReader, cfg KVBackendConfig) (*KVBackend, error) {
	if reader == nil {
		return nil, errors.New("grantservice: kv reader is nil")
	}
	b := &KVBackend{
		reader:        reader,
		pathFor:       cfg.PathFor,
		secretField:   cfg.SecretField,
		locationField: cfg.LocationField,
		newContext:    cfg.NewContext,
	}
	if b.pathFor == nil {
		b.pathFor = defaultKVPath
	}
	if b.secretField == "" {
		b.secretField = defaultSecretField
	}
	if b.locationField == "" {
		b.locationField = defaultLocationField
	}
	if b.newContext == nil {
		b.newContext = context.Background
	}
	return b, nil
}

// Fetch implements Backend against the OpenBao-compatible KV-v2 store. It maps the
// grant_ref to its designated KV path, READS the secret (the only verb this
// adapter ever issues — read-only posture, §11.3), and translates the result into
// the Backend contract:
//
//   - parse/lookup miss (unparseable ref, or KV-v2 404) -> ErrGrantNotFound
//     (a definitive deny, never a stall)
//   - store unreachable / login failure / permission deny / any other non-200 ->
//     ErrStoreUnavailable (the §5.1 availability-dependency stall; a NEW fetch
//     fails while in-flight sessions ride their cache in service.go)
//   - success -> Credential{Secret, Location}
func (b *KVBackend) Fetch(grantRef string) (Credential, error) {
	path, ok := b.pathFor(grantRef)
	if !ok {
		// An unparseable grant_ref names no stored credential — a definitive miss,
		// not a store problem. Fail closed as ErrGrantNotFound (the Fetch caller in
		// service.go already rejects a ref that does not match the session/service
		// binding via ErrGrantRefMismatch; this is the backend-side belt).
		return Credential{}, ErrGrantNotFound
	}

	sec, err := b.reader.ReadSecret(b.newContext(), path)
	if err != nil {
		// KV-v2 404 is a definitive miss: no credential stored for this grant_ref.
		if errors.Is(err, kvclient.ErrSecretNotFound) {
			return Credential{}, ErrGrantNotFound
		}
		// Everything else — transport/availability failure, login failure, a
		// permission deny (store reachable but the platform role is unscoped), or
		// any other non-200 — is NOT a confirmed absence. Fail closed to the §5.1
		// availability stall: a NEW fetch fails, never a silently-wrong credential.
		// The underlying error is wrapped for diagnostics; errors.Is still resolves
		// to ErrStoreUnavailable for the caller's outage handling.
		return Credential{}, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}

	secret, ok := stringField(sec.Data, b.secretField)
	if !ok {
		// The store returned a secret with no credential material under the
		// designated field — a malformed/unexpected payload for this grant. Treat
		// it as a definitive miss (the grant has no usable credential), not a stall.
		return Credential{}, ErrGrantNotFound
	}
	location, ok := stringField(sec.Data, b.locationField)
	if !ok || location == "" {
		// No explicit location -> the frozen generic Authorization-header seam (D83).
		location = defaultLocation
	}
	return Credential{Secret: []byte(secret), Location: location}, nil
}

// stringField extracts a string value for key from a KV-v2 secret payload. The
// payload is map[string]any (JSON-decoded), so a stored string surfaces as a Go
// string; a missing key or a non-string value is a non-match (ok=false). The
// adapter decides nothing about the bytes beyond this shape check — Credential is
// credential-type-agnostic (D83).
func stringField(data map[string]any, key string) (string, bool) {
	if data == nil {
		return "", false
	}
	v, ok := data[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
