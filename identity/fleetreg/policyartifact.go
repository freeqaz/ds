// SPDX-License-Identifier: Apache-2.0

package fleetreg

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/dream-serpent/dream-serpent/identity/digest"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// Manager is the D84 registration API surface (doc 16 §6.4 / §9 fleet-digest
// registration row). It owns the consent Registry, enforces the authority
// defaults, and turns each register/revoke into a FLEET-scope digest artifact
// that rides the EXISTING policy_log/PolicySink seam (D72) — it appends NOTHING
// of its own to any wire surface, it only drives identity/digest's
// PublishFleetPolicy / RevokeFleetPolicy. It introduces no proto and no RPC.
//
// The Manager is the single entrypoint the CLI drives and the only place the
// authority check, the consent-surface mutation, the plaintext read, and the
// policy_log append are sequenced together — so a registration that fails
// authorization writes nothing, and a path the Registry does not Cover is never
// read.
type Manager struct {
	reg    *Registry
	auth   Authorizer
	prod   *digest.Producer
	src    DigestSource
	sink   digest.PolicySink
	nowFn  func() time.Time
	expiry time.Duration // 0 ⇒ no expiry stamped on entries
}

// Config configures a Manager. The Producer (the HMAC key + truncation, doc 16
// §6.3), the DigestSource (the kv-client read seam), and the PolicySink (the
// policy_log append seam) are required; the Registry defaults to a fresh
// default-none one (doc 16 §11.3 step 1).
type Config struct {
	// Registry is the consent surface; nil ⇒ a fresh default-none Registry.
	Registry *Registry
	// Producer holds the fleet HMAC key the digests are computed under
	// (identity/digest). Required.
	Producer *digest.Producer
	// Source is the read seam onto credential plaintext (kv-client). Required.
	Source DigestSource
	// Sink is the policy_log append seam (identity/digest.PolicySink). Required.
	Sink digest.PolicySink
	// Now is the clock for entry expiry; nil ⇒ time.Now.
	Now func() time.Time
	// EntryExpiry, if non-zero, stamps each digest entry's expiry at
	// Now()+EntryExpiry (the credential-TTL track, doc 14 §7). 0 ⇒ no expiry.
	EntryExpiry time.Duration
}

// NewManager builds a Manager from Config. Fail-closed: a nil Producer, Source,
// or Sink is rejected — every one is load-bearing for the register path, and a
// nil sink would silently no-op a registration the security team believes landed.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Producer == nil {
		return nil, errors.New("fleetreg: nil producer (fail-closed: cannot compute fleet digests)")
	}
	if cfg.Source == nil {
		return nil, errors.New("fleetreg: nil digest source (fail-closed: cannot read designated trees)")
	}
	if cfg.Sink == nil {
		return nil, errors.New("fleetreg: nil policy sink (fail-closed: a registration must reach policy_log)")
	}
	reg := cfg.Registry
	if reg == nil {
		reg = NewRegistry()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		reg:    reg,
		prod:   cfg.Producer,
		src:    cfg.Source,
		sink:   cfg.Sink,
		nowFn:  now,
		expiry: cfg.EntryExpiry,
	}, nil
}

// Registry exposes the consent surface for read-only inspection (the CLI `list`
// surface, doc 16 §6.4). Mutations go through the authority-gated Manager verbs.
func (m *Manager) Registry() *Registry { return m.reg }

// RegisterResult reports the outcome of a register/revoke as a policy artifact.
// It echoes the digest layer's FleetPolicyResult (the assigned policy_log seq +
// commit state — the POL-4 bar's provenance) plus the registration provenance
// the CLI prints: which paths were covered and how.
type RegisterResult struct {
	// Fleet is the underlying policy-artifact result (seq, committed, key, batch).
	Fleet digest.FleetPolicyResult
	// Coverage is how the registered target was scoped (prefix vs escape-hatch).
	Coverage Coverage
	// Paths are the canonical leaf paths whose plaintext was digested into the
	// artifact (provenance only — never any plaintext).
	Paths []string
}

// DesignatePrefix records a D84 prefix designation and digests every leaf
// currently under it as ONE fleet-scope policy artifact (doc 16 §11.3 steps
// 2–3). Authority is checked first (the prefix's ownership/owner); on refusal
// NOTHING is recorded and NOTHING is appended. Inheritance (step 4) is a
// property of the recorded designation: a later Sync re-digests newly-written
// leaves under the prefix without re-designation.
//
// batchID correlates the append with its ack (doc 16 §6.5). The plaintext of
// each covered leaf is read through the DigestSource, HMAC'd by the Producer,
// and dropped — no plaintext is retained or returned.
func (m *Manager) DesignatePrefix(ctx context.Context, actor Principal, d Designation, batchID string) (RegisterResult, error) {
	if err := m.auth.Authorize(actor, d.Ownership, d.Owner); err != nil {
		return RegisterResult{}, err
	}
	if err := m.reg.Designate(d); err != nil {
		return RegisterResult{}, err
	}
	res, err := m.publishCovered(ctx, d.Mount, d.Prefix, batchID)
	if err != nil {
		// The designation is recorded (consent given) but the initial digest push
		// failed; surface the error so the caller retries the push (a Sync) — the
		// consent decision itself is not rolled back, matching the producer's
		// fail-closed "artifact not applied" semantics on the digest side.
		return RegisterResult{Coverage: CoveragePrefix}, err
	}
	res.Coverage = CoveragePrefix
	return res, nil
}

// RegisterSecret records a per-secret escape-hatch registration and digests that
// one secret as a fleet-scope policy artifact (doc 16 §11.3 step 5). Authority
// is checked first against the secret's ownership/owner; on refusal nothing is
// recorded and nothing is appended.
func (m *Manager) RegisterSecret(ctx context.Context, actor Principal, s Secret, batchID string) (RegisterResult, error) {
	if err := m.auth.Authorize(actor, s.Ownership, s.Owner); err != nil {
		return RegisterResult{}, err
	}
	if err := m.reg.RegisterSecret(s); err != nil {
		return RegisterResult{}, err
	}
	creds, paths, err := m.readOne(ctx, s.Mount, s.Path)
	if err != nil {
		return RegisterResult{Coverage: CoverageEscapeHatch}, err
	}
	fr, err := digest.PublishFleetPolicy(ctx, m.sink, m.prod, creds, batchID)
	if err != nil {
		return RegisterResult{Coverage: CoverageEscapeHatch, Paths: paths}, err
	}
	return RegisterResult{Fleet: fr, Coverage: CoverageEscapeHatch, Paths: paths}, nil
}

// Revoke retires a previously-registered target (prefix designation or
// escape-hatch secret) from the consent surface AND retires its fleet digests
// over the policy stream (doc 16 §6.2, the POL-4 revocation bar). Authority is
// checked against the recorded entry's ownership/owner — so the same D84 rule
// gates revocation as gates registration. The retire is a single host-wide
// policy_log append (digest.RevokeFleetPolicy, empty-entry artifact under the
// producer's key id). Fail-closed: an unauthorized actor or an absent target
// removes nothing and appends nothing.
//
// The retire rides the producer's CURRENT key id (the key under which the
// to-be-retired entries were last published); a fleet re-key is the digest
// layer's LiveRekeyFleet concern, not this surface's.
func (m *Manager) Revoke(ctx context.Context, actor Principal, mount, path, batchID string) (digest.FleetPolicyResult, error) {
	// EXACT-target match: a revoke retires a registered UNIT (a designated prefix
	// or a per-secret escape hatch), never an arbitrary leaf that merely falls
	// under a prefix. CoverageOf would say "prefix" for such a leaf (inheritance),
	// but the leaf was never independently registered — so revoking it would
	// silently no-op the removal yet still append a host-wide retire artifact,
	// telling the operator a leaf was retired when the designation is untouched.
	// ExactTarget forces the caller to name the prefix (or the exact secret).
	cov, d, s := m.reg.ExactTarget(mount, path)
	if cov == CoverageNone {
		return digest.FleetPolicyResult{}, fmt.Errorf("fleetreg: nothing registered at %s (revoke names a designated prefix or a registered secret exactly; default-none / already revoked)", canonPath(mount, path))
	}
	ownership, owner := d.Ownership, d.Owner
	if cov == CoverageEscapeHatch {
		ownership, owner = s.Ownership, s.Owner
	}
	if err := m.auth.Authorize(actor, ownership, owner); err != nil {
		return digest.FleetPolicyResult{}, err
	}
	// Remove from the consent surface BEFORE appending the retire artifact, and
	// only append if the removal actually landed — so a retire artifact is never
	// emitted for a target that was not in fact retired (fail-closed symmetry with
	// the no-row-on-refusal register path).
	var removed bool
	switch cov {
	case CoveragePrefix:
		removed = m.reg.RemoveDesignation(mount, path)
	case CoverageEscapeHatch:
		removed = m.reg.RemoveSecret(mount, path)
	}
	if !removed {
		return digest.FleetPolicyResult{}, fmt.Errorf("fleetreg: nothing removed at %s (concurrent revoke?); no retire appended", canonPath(mount, path))
	}
	fr, err := digest.RevokeFleetPolicy(ctx, m.sink, m.prod.KeyID(), batchID)
	if err != nil {
		return fr, err
	}
	return fr, nil
}

// Sync re-digests every covered leaf and re-publishes the full fleet-scope set
// as one policy artifact — the inheritance mechanism (doc 16 §11.3 step 4): a
// secret newly written under a designated prefix is picked up here without
// re-designation. It walks every designated prefix plus every escape-hatch
// secret, reads the union (each path is Covers-approved by construction), and
// publishes one artifact. Authority is NOT re-checked: Sync is the producer-side
// refresh of an already-consented surface, run by the platform service, not an
// actor-initiated registration. Fail-closed: a read or append failure surfaces
// and the artifact is treated as not-applied.
func (m *Manager) Sync(ctx context.Context, batchID string) (RegisterResult, error) {
	creds, paths, err := m.collectCovered(ctx)
	if err != nil {
		return RegisterResult{}, err
	}
	if len(creds) == 0 {
		// Default-none (or everything revoked): nothing to publish. Not an error —
		// an unconfigured surface designates nothing (doc 16 §11.3 step 1).
		return RegisterResult{Paths: paths}, nil
	}
	fr, err := digest.PublishFleetPolicy(ctx, m.sink, m.prod, creds, batchID)
	if err != nil {
		return RegisterResult{Paths: paths}, err
	}
	return RegisterResult{Fleet: fr, Paths: paths}, nil
}

// publishCovered reads every leaf under (mount, prefix) and publishes them as one
// fleet artifact. Used by DesignatePrefix; the leaves are covered by the
// just-recorded designation.
func (m *Manager) publishCovered(ctx context.Context, mount, prefix, batchID string) (RegisterResult, error) {
	leaves, err := m.src.ListLeaves(ctx, mount, prefix)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("fleetreg: list designated tree %s: %w", canonPath(mount, prefix), err)
	}
	sort.Strings(leaves)
	var creds []digest.Credential
	var paths []string
	for _, leaf := range leaves {
		// Defense in depth: only read leaves the consent surface actually covers.
		if !m.reg.Covers(mount, leaf) {
			continue
		}
		c, err := m.readCred(ctx, mount, leaf)
		if err != nil {
			return RegisterResult{}, err
		}
		creds = append(creds, c)
		paths = append(paths, canonPath(mount, leaf))
	}
	if len(creds) == 0 {
		// A designated-but-empty tree: the consent decision stands, but there is
		// nothing to digest yet — inheritance will pick up future writes on Sync.
		return RegisterResult{Paths: paths}, nil
	}
	fr, err := digest.PublishFleetPolicy(ctx, m.sink, m.prod, creds, batchID)
	if err != nil {
		return RegisterResult{Paths: paths}, err
	}
	return RegisterResult{Fleet: fr, Paths: paths}, nil
}

// readOne reads a single covered secret into a one-element credential slice.
func (m *Manager) readOne(ctx context.Context, mount, path string) ([]digest.Credential, []string, error) {
	if !m.reg.Covers(mount, path) {
		return nil, nil, fmt.Errorf("fleetreg: %s not covered (refusing to read plaintext outside the consent surface, D84)", canonPath(mount, path))
	}
	c, err := m.readCred(ctx, mount, path)
	if err != nil {
		return nil, nil, err
	}
	return []digest.Credential{c}, []string{canonPath(mount, path)}, nil
}

// collectCovered reads the union of every covered leaf across all designated
// prefixes and escape-hatch secrets — the full fleet set Sync republishes.
func (m *Manager) collectCovered(ctx context.Context) ([]digest.Credential, []string, error) {
	seen := make(map[string]struct{})
	var creds []digest.Credential
	var paths []string

	add := func(mount, path string) error {
		key := canonPath(mount, path)
		if _, dup := seen[key]; dup {
			return nil
		}
		if !m.reg.Covers(mount, path) {
			return nil
		}
		c, err := m.readCred(ctx, mount, path)
		if err != nil {
			return err
		}
		seen[key] = struct{}{}
		creds = append(creds, c)
		paths = append(paths, key)
		return nil
	}

	for _, d := range m.reg.Designations() {
		leaves, err := m.src.ListLeaves(ctx, d.Mount, d.Prefix)
		if err != nil {
			return nil, nil, fmt.Errorf("fleetreg: list %s: %w", d.canonical(), err)
		}
		sort.Strings(leaves)
		for _, leaf := range leaves {
			if err := add(d.Mount, leaf); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, s := range m.reg.Secrets() {
		if err := add(s.Mount, s.Path); err != nil {
			return nil, nil, err
		}
	}
	sort.Strings(paths)
	return creds, paths, nil
}

// readCred reads one secret's plaintext through the DigestSource and wraps it as
// a FLEET-scope FORBIDDEN credential (the fleet-digest class, doc 16 §6.2 / §7
// keyed-forbidden) the Producer digests. The plaintext is held only across the
// digest computation in identity/digest and is never retained here.
func (m *Manager) readCred(ctx context.Context, mount, path string) (digest.Credential, error) {
	pt, err := m.src.ReadSecret(ctx, mount, path)
	if err != nil {
		return digest.Credential{}, fmt.Errorf("fleetreg: read %s: %w", canonPath(mount, path), err)
	}
	if len(pt) == 0 {
		return digest.Credential{}, fmt.Errorf("fleetreg: empty plaintext at %s (fail-closed)", canonPath(mount, path))
	}
	var expiry time.Time
	if m.expiry > 0 {
		expiry = m.nowFn().Add(m.expiry)
	}
	return digest.Credential{
		Plaintext: pt,
		CredClass: digest.Forbidden(),
		Scope:     identityv1.DigestScope_DIGEST_SCOPE_FLEET,
		Expiry:    expiry,
	}, nil
}
