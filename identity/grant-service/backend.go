// SPDX-License-Identifier: Apache-2.0

// The D39 key-store backend seam + the OSS local file/KV fake (doc 16 §9, §11.3;
// D39/D85).
//
// The grant service fronts the D39 key store. At the hosted tier WE run the
// store; at bring-compute/on-prem the customer's OpenBao-compatible KV IS the
// store (§11.3) — both sit behind the SAME Backend seam, so a tier swap is a
// backend swap, never a grant-service rewrite. This file ships the OSS substrate
// (D85): a LOCAL file/KV fake. It is never a live Vault/OpenBao (D50: synthetic
// fixtures only); the OpenBao-compatible client is the sibling ../kv-client/
// behind this same seam.
//
// The store holds the REAL swap-class credential keyed by grant_ref. The grant
// service reads it per-session and caches it ≤ session (§5.1) — the credential
// never enters the VM and never sits on the virtual-metal host (D8/D39); only
// the off-host grant service holds it, in memory, for at most the session.
//
// THE RECORD REPOINT. The grant_ref the Backend keys on is the frozen
// identityv1.Grant.GrantRef field — the grant RECORD (identity × service × scope ×
// TTL) defined in doc 16 §5.1 and frozen in grants.pb.go alongside the §9 fetch
// reply (wire.go). grantref.go aliases that frozen record as GrantRecord; this
// file's FetchForGrant lets the Backend seam be driven by a record rather than a
// bare string, so the whole grant model speaks the frozen contract: a record's
// grant_ref IS the store key, and the credential the store returns is the secret
// that record references. Behavior is unchanged — FetchForGrant is a thin
// record-keyed adapter over Fetch (same string key, same outage/not-found
// semantics); Credential and Backend are untouched.
package grantservice

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// ErrStoreUnavailable is what a Backend returns when the store is unreachable —
// the AVAILABILITY DEPENDENCY of D39. The fetcher translates it into the
// "outage stalls NEW fetches only" semantics (§5.1): a cached grant is served
// without consulting the backend, so an in-flight session rides its cache.
var ErrStoreUnavailable = errors.New("grantservice: key store unavailable")

// ErrGrantNotFound is returned when no credential is stored for a grant_ref —
// distinct from an outage: a missing grant is a definitive deny, not a stall.
var ErrGrantNotFound = errors.New("grantservice: no credential for grant_ref")

// Backend is the D39 key-store seam: fetch the real credential for a grant_ref.
// The contract is deliberately minimal (read-only, KV v2 read-only posture per
// §11.3): one method, no lease lifecycle, no write path. Implementations are the
// local file/KV fake (this file) and — at higher tiers — the OpenBao-compatible
// KV client (../kv-client/, not built here). The grant_ref it keys on is the
// frozen identityv1.Grant.GrantRef field (grantref.go's GrantRecord) — the seam
// is string-keyed so a store never needs to know the record's shape, but the key
// IS a grant record's key.
type Backend interface {
	// Fetch returns the real swap-class credential stored for grant_ref. It
	// returns ErrStoreUnavailable on a transient outage (the §5.1 availability
	// dependency) and ErrGrantNotFound when the grant has no stored credential.
	Fetch(grantRef string) (Credential, error)
}

// FetchForGrant fetches the real credential a grant RECORD references, keying the
// Backend on the record's own grant_ref (the §5.1 record × §9 store seam, made
// explicit on the frozen contract). It is a thin record-keyed adapter over a
// Backend's Fetch — same string key, same ErrStoreUnavailable/ErrGrantNotFound
// semantics — so a caller holding a frozen identityv1.Grant resolves its secret
// without re-deriving the key. A nil record (or one with no grant_ref) keys the
// empty string, which the store treats as a definitive ErrGrantNotFound
// (fail-closed). Behavior-preserving: this adds a record-shaped entry point, never
// a new fetch path.
func FetchForGrant(b Backend, g *GrantRecord) (Credential, error) {
	return b.Fetch(grantRecordRef(g))
}

// Credential is the real swap-class credential the store holds for a grant_ref —
// the secret a grant RECORD (grantref.go's GrantRecord, frozen
// identityv1.Grant) references via its GrantRef key but NEVER carries itself (the
// record holds a reference, the store holds the secret; D8/D39). The grant service
// caches it ≤ session and hands it to the swap executor for the D83
// Authorization-header substitution; it never enters the VM (D8). On the §9 fetch
// wire it maps field-for-field onto identityv1.FetchedCredential (wire.go). The
// value is opaque bytes — the seam is credential-type-agnostic (D83). Synthetic
// only here (D50).
type Credential struct {
	// Secret is the credential material (e.g. a PAT). Opaque to the grant
	// service — the swap executor substitutes it verbatim into the header.
	Secret []byte
	// Location names where the swap substitutes it ("Authorization" by default,
	// the frozen generic header seam, D83). Carried for the executor's
	// convenience; the grant service does not interpret it.
	Location string
}

// FileKVBackend is the OSS local file/KV fake (D85). It loads a JSON map of
// grant_ref → credential from disk once at construction (an immutable snapshot,
// the way a read-only KV mount behaves) and can be flipped UNAVAILABLE to model
// a store outage for the §5.1 "outage stalls new fetches only" test. Synthetic
// fixtures only — never a live store (D50).
type FileKVBackend struct {
	mu        sync.RWMutex
	creds     map[string]Credential
	available bool
}

// fileEntry is the on-disk JSON shape: a grant_ref keyed map of base64-free
// synthetic secrets. Stdlib encoding/json only.
type fileEntry struct {
	Secret   string `json:"secret"`
	Location string `json:"location"`
}

// NewFileKVBackend loads the local fake store from a JSON file mapping grant_ref
// → {secret, location}. The file is a synthetic fixture (D50). The backend
// starts AVAILABLE.
func NewFileKVBackend(path string) (*FileKVBackend, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries map[string]fileEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	creds := make(map[string]Credential, len(entries))
	for ref, e := range entries {
		creds[ref] = Credential{Secret: []byte(e.Secret), Location: e.Location}
	}
	return &FileKVBackend{creds: creds, available: true}, nil
}

// NewInMemoryBackend builds the local fake from an in-memory map — the same
// substrate as the file backend without a fixture file, for tests. Synthetic
// (D50). Starts available.
func NewInMemoryBackend(creds map[string]Credential) *FileKVBackend {
	cp := make(map[string]Credential, len(creds))
	for k, v := range creds {
		cp[k] = v
	}
	return &FileKVBackend{creds: cp, available: true}
}

// SetAvailable flips the store's availability — the test lever for the §5.1
// outage semantics. When false, Fetch returns ErrStoreUnavailable, modeling the
// store outage that must stall NEW fetches only.
func (b *FileKVBackend) SetAvailable(up bool) {
	b.mu.Lock()
	b.available = up
	b.mu.Unlock()
}

// Fetch implements Backend against the local fake. It returns
// ErrStoreUnavailable while the store is flipped down (the outage), and
// ErrGrantNotFound for an unknown grant_ref.
func (b *FileKVBackend) Fetch(grantRef string) (Credential, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.available {
		return Credential{}, ErrStoreUnavailable
	}
	cred, ok := b.creds[grantRef]
	if !ok {
		return Credential{}, ErrGrantNotFound
	}
	// Defensive copy so a caller can never mutate the store's secret.
	out := Credential{Secret: append([]byte(nil), cred.Secret...), Location: cred.Location}
	return out, nil
}
