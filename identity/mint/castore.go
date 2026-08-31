// SPDX-License-Identifier: Apache-2.0

// The M1 own-minimal-CA secret store (doc 16 §2 / §4 / §5.1; D39/D82/D85/D33).
//
// M1 SUBSTRATE SWAP (D22): the M0 shim minted both D82 root hierarchies in-memory
// at construction and threw them away with the process (doc 16 §2). M1 swaps in an
// OWN MINIMAL CA whose roots PERSIST in the D39 secret-store trust zone — loaded at
// startup, NOT regenerated per-process — so a restart re-attaches to the same trust
// material rather than orphaning every live session's chains. This file is the OSS
// substrate of that store (D85): a LOCAL FILE-backed key store, the same posture as
// the grant service's local file/KV fake (identity/grant-service/backend.go). It is
// the OSS substitute behind the SAME internal CAStore interface, so the higher-tier
// customer Vault/OpenBao store (D55 window) drops in later as a different CAStore
// implementation — never a mint-service rewrite (the D39 "tier swap is a backend
// swap" property).
//
// CUSTODY (D39 / doc 16 §4 "both roots live off-host in the secret-store trust
// zone"): the root SIGNING KEYS are the crown jewels — a leaked interception root
// is a fleet-wide MITM capability, a leaked workload root forges any attribution.
// So the on-disk key files are written 0600 (owner read/write only) and the store
// directory 0700; a world- or group-readable key file is REFUSED on load (fail
// closed), never silently tolerated. No real key material ever lands here (D50):
// every key the store persists is synthetic, minted by this process.
//
// STDLIB ONLY: crypto/x509 + crypto/ecdsa + encoding/json + encoding/pem cover the
// persistence; no new dependency (the wave constraint). The own-CA internals
// (PKCS#8 + PEM on disk, ECDSA P-256, the serial/profile choices in ca.go) are the
// D12-frozen-seam "free" space — bounded by D39 custody + hierarchy separation
// (doc 16 §12).
package mint

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CAStore is the D39 secret-store seam for the two persistent D82 root hierarchies.
// It is deliberately minimal: load-or-mint the named root, idempotently. The OSS
// implementation is fileCAStore (local file/KV, D85); the higher-tier customer
// Vault/OpenBao store (D55 window) is a DIFFERENT CAStore behind this SAME seam, so
// a tier swap is a store swap, never a mint rewrite (the D39 property). DEFERRED:
// the Vault-backed CAStore is NOT built here (see the package note + the M1 wave
// report) — fileCAStore is its OSS stand-in behind this interface.
type CAStore interface {
	// LoadOrMintRoot returns the persisted root hierarchy named `name`, minting and
	// persisting a fresh synthetic one (D50) on first run via `mint`. The returned
	// hierarchy is stable across process restarts: a second call in a later process
	// loads the SAME key+cert from the store rather than regenerating (the M1
	// persistence property, doc 16 §2). leafUsages/isCAIssuing are applied to the
	// loaded hierarchy so the in-memory verify profile matches the M0 shim exactly.
	LoadOrMintRoot(name string, leafUsages []x509.ExtKeyUsage, isCAIssuing bool, mint rootMinter) (*rootHierarchy, error)
}

// rootMinter mints a fresh synthetic root hierarchy (the newRootHierarchy closure),
// injected so the store owns only persistence, never key-generation policy.
type rootMinter func() (*rootHierarchy, error)

// errKeyPermsTooOpen is returned when a persisted root key file is group- or
// world-accessible — a custody violation (D39). Loading fails CLOSED rather than
// trusting a key anyone on the box could have read.
var errKeyPermsTooOpen = errors.New("mint: persisted CA key file is not 0600 (custody violation, D39)")

// fileCAStore is the OSS local-file CAStore (D85). Each root hierarchy persists as
// two sibling files under dir: `<name>-root.crt.pem` (the self-signed root cert,
// 0644 — a cert is public) and `<name>-root.key.pem` (the PKCS#8 ECDSA signing key,
// 0600 — the custody-critical secret). The directory itself is 0700. Mirrors the
// grant service's local file/KV fake (identity/grant-service/backend.go): stdlib
// only, synthetic fixtures only (D50).
type fileCAStore struct {
	dir string
}

// NewFileCAStore opens (creating if absent) a local-file CA secret store rooted at
// dir. The directory is created 0700; an existing directory's mode is NOT widened
// (we never loosen custody). This is the OSS tier (D85); higher tiers swap a
// Vault-backed CAStore behind the same seam.
func NewFileCAStore(dir string) (*fileCAStore, error) {
	if dir == "" {
		return nil, errors.New("mint: empty CA store dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mint: create CA store dir: %w", err)
	}
	return &fileCAStore{dir: dir}, nil
}

func (s *fileCAStore) certPath(name string) string { return filepath.Join(s.dir, name+"-root.crt.pem") }
func (s *fileCAStore) keyPath(name string) string  { return filepath.Join(s.dir, name+"-root.key.pem") }

// LoadOrMintRoot implements CAStore against the local files. First run mints +
// persists; every later run loads the SAME material. The mint+persist is the
// only write path; loads are read-only.
func (s *fileCAStore) LoadOrMintRoot(name string, leafUsages []x509.ExtKeyUsage, isCAIssuing bool, mint rootMinter) (*rootHierarchy, error) {
	certPath, keyPath := s.certPath(name), s.keyPath(name)

	// FAST PATH: both files present => load the persisted root (no regeneration).
	if fileExists(certPath) && fileExists(keyPath) {
		return s.loadRoot(name, leafUsages, isCAIssuing)
	}

	// FIRST RUN: mint a fresh synthetic root (D50) and persist it before returning,
	// so the next process loads it. If only one of the two files exists the store is
	// corrupt/half-written — fail CLOSED rather than minting a NEW root that would
	// orphan whatever chained to the persisted half.
	if fileExists(certPath) != fileExists(keyPath) {
		return nil, fmt.Errorf("mint: CA store half-written for %q (cert=%v key=%v) — refusing to regenerate", name, fileExists(certPath), fileExists(keyPath))
	}
	h, err := mint()
	if err != nil {
		return nil, err
	}
	if err := s.persistRoot(h); err != nil {
		return nil, err
	}
	// Re-apply the caller's in-memory verify profile to the freshly minted root.
	h.leafUsages = leafUsages
	h.isCAIssuing = isCAIssuing
	return h, nil
}

// persistRoot writes the root's key (0600) then cert (0644) PEM files. The key is
// written FIRST, with O_EXCL through a 0600-moded create, so (a) it is NEVER
// momentarily group/world-readable (no chmod-after-write race) and (b) the
// custody-critical create is the disk-touching mutual-exclusion primitive — a
// concurrent first-run on the same fresh dir has exactly one O_EXCL winner.
// Synthetic key material only (D50).
func (s *fileCAStore) persistRoot(h *rootHierarchy) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(h.key)
	if err != nil {
		return fmt.Errorf("mint: marshal %s root key: %w", h.name, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// O_CREATE|O_EXCL with mode 0600: the file is born owner-only; no window where
	// the key is broader than 0600 (the custody-critical write, D39).
	f, err := os.OpenFile(s.keyPath(h.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("mint: create %s root key file: %w", h.name, err)
	}
	if _, err := f.Write(keyPEM); err != nil {
		f.Close()
		return fmt.Errorf("mint: write %s root key: %w", h.name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("mint: close %s root key file: %w", h.name, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.certDER})
	if err := os.WriteFile(s.certPath(h.name), certPEM, 0o644); err != nil {
		return fmt.Errorf("mint: persist %s root cert: %w", h.name, err)
	}
	return nil
}

// loadRoot reads the persisted cert+key for `name` and rebuilds the in-memory
// rootHierarchy (key, cert, certDER, a single-root verify pool, and the caller's
// leaf-usage/CA-issuing profile). It REFUSES a key file that is group- or
// world-accessible (custody violation, D39) — fail closed.
func (s *fileCAStore) loadRoot(name string, leafUsages []x509.ExtKeyUsage, isCAIssuing bool) (*rootHierarchy, error) {
	keyPath := s.keyPath(name)
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("mint: stat %s root key: %w", name, err)
	}
	// 0600 custody check: any group/other permission bit set is a violation.
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s mode is %#o", errKeyPermsTooOpen, keyPath, info.Mode().Perm())
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("mint: read %s root key: %w", name, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("mint: %s root key is not a PRIVATE KEY PEM block", name)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mint: parse %s root key: %w", name, err)
	}
	key, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("mint: %s root key is not ECDSA", name)
	}

	certPEM, err := os.ReadFile(s.certPath(name))
	if err != nil {
		return nil, fmt.Errorf("mint: read %s root cert: %w", name, err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("mint: %s root cert is not a CERTIFICATE PEM block", name)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mint: parse %s root cert: %w", name, err)
	}
	// The persisted cert's public key must match the persisted private key — a
	// mismatched pair is a corrupt/tampered store, fail closed.
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("mint: %s root key/cert mismatch in store", name)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &rootHierarchy{
		name:        name,
		key:         key,
		cert:        cert,
		certDER:     certBlock.Bytes,
		pool:        pool,
		leafUsages:  leafUsages,
		isCAIssuing: isCAIssuing,
	}, nil
}

// fileExists reports whether path names an existing file (any non-stat error is
// treated as "absent" for the load/mint decision; the subsequent open surfaces the
// real error).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
