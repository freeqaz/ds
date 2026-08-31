// SPDX-License-Identifier: Apache-2.0

package fleetreg

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Ownership is the D84 authority class of a credential: who may register or
// revoke it (doc 16 §6.4 / §11.3 step 5). The default authority rule is "org
// admin for org credentials, any developer for credentials they own".
type Ownership int

const (
	// OwnershipUnspecified is the zero value — fail-closed: an entry with no
	// declared ownership is treated as org-owned (org-admin only), never as a
	// default-allow. It is surfaced so a miswired caller is caught, not silently
	// granted the most-permissive class.
	OwnershipUnspecified Ownership = iota
	// OwnershipOrg marks an organization credential: only an org admin may
	// register or revoke it (D84 authority default).
	OwnershipOrg
	// OwnershipDeveloper marks a credential a specific developer owns: that
	// developer (its Owner) may register or revoke it; an org admin may too
	// (an org admin is authorized over org credentials and, by superset, over
	// owned ones — the broad-approver class, bounded by audit, doc 16 §2).
	OwnershipDeveloper
)

func (o Ownership) String() string {
	switch o {
	case OwnershipOrg:
		return "org"
	case OwnershipDeveloper:
		return "developer"
	default:
		return "unspecified"
	}
}

// Role is the §3.2 principal role relevant to registration authority. Only the
// org-admin bit matters for D84 authority; the rest are carried so a caller can
// pass a principal's full role set without projecting it down first.
type Role string

const (
	// RoleOrgAdmin is the D45 org-admin role — authorized over org credentials
	// (and, by superset, over any owned credential).
	RoleOrgAdmin Role = "org_admin"
	// RoleDeveloper is the launcher/developer role — authorized only over
	// credentials it owns.
	RoleDeveloper Role = "developer"
)

// Principal is the actor attempting a registration/revocation — the §3.2 human
// principal projected to what D84 authority needs: a stable IdP-subject id and
// the role set. It is data only; this module never authenticates it (that is the
// §11.2 IdP front-end's job) — it only authorizes an already-authenticated one.
type Principal struct {
	// Subject is the stable IdP-subject id (the §3.2 identity key, never the
	// reassignable email). It is matched against an owned credential's Owner.
	Subject string
	// Roles is the principal's role set (org-admin is the only D84-relevant bit).
	Roles []Role
}

// IsOrgAdmin reports whether the principal carries the org-admin role.
func (p Principal) IsOrgAdmin() bool {
	for _, r := range p.Roles {
		if r == RoleOrgAdmin {
			return true
		}
	}
	return false
}

// Coverage is how a Vault path came to be in the producer's read scope: under a
// designated PREFIX (auto-covered, inherits) or via a per-secret ESCAPE-HATCH
// registration. It is the provenance the registration artifact and the CLI
// `list` surface report.
type Coverage int

const (
	// CoverageNone means the path is NOT in the producer's read scope — the
	// default-none posture before any designation (doc 16 §11.3 step 1).
	CoverageNone Coverage = iota
	// CoveragePrefix means the path falls under a designated prefix and is
	// digested automatically; a newly-written secret under the prefix inherits
	// this without re-designation (doc 16 §11.3 steps 3–4).
	CoveragePrefix
	// CoverageEscapeHatch means the path was explicitly per-secret registered
	// because it lives OUTSIDE any designated prefix (doc 16 §11.3 step 5).
	CoverageEscapeHatch
)

func (c Coverage) String() string {
	switch c {
	case CoveragePrefix:
		return "prefix"
	case CoverageEscapeHatch:
		return "escape-hatch"
	default:
		return "none"
	}
}

// Designation is one D84 prefix designation — the single auditable 2c scoping
// decision (doc 16 §11.3 step 2). Everything under Prefix is digested
// automatically and new secrets inherit (steps 3–4).
type Designation struct {
	// Mount is the Vault KV-v2 mount the prefix lives under (e.g. "secret").
	Mount string
	// Prefix is the path prefix within the mount (e.g.
	// "data/dreamserpent" → covers data/dreamserpent/*). Empty Prefix designates
	// the whole mount.
	Prefix string
	// Ownership is the authority class for credentials under this prefix.
	Ownership Ownership
	// Owner is the IdP-subject of the owning developer when Ownership is
	// OwnershipDeveloper (ignored for org). It bounds who may register/revoke a
	// secret that falls under this prefix as the escape hatch / revocation target.
	Owner string
}

// canonical returns the mount-qualified prefix, slash-normalized, used for
// containment tests. A designation with empty Prefix canonicalizes to the bare
// mount (covers the whole mount).
func (d Designation) canonical() string {
	return canonPath(d.Mount, d.Prefix)
}

// Secret is one per-secret escape-hatch registration — an explicit single path
// joined to the feed without designating its whole tree (doc 16 §11.3 step 5).
type Secret struct {
	// Mount is the Vault KV-v2 mount.
	Mount string
	// Path is the exact logical path of the one secret (e.g.
	// "data/teams/ci/deploy-token").
	Path string
	// Ownership is the authority class.
	Ownership Ownership
	// Owner is the IdP-subject of the owning developer when Ownership is
	// OwnershipDeveloper.
	Owner string
}

func (s Secret) canonical() string {
	return canonPath(s.Mount, s.Path)
}

// Registry is the in-memory consent surface (doc 16 §6.4): the set of designated
// prefixes plus per-secret escape-hatch registrations that bound the producer's
// read scope. The zero Registry is the DEFAULT-NONE posture — it covers nothing,
// so an unconfigured surface designates nothing (doc 16 §11.3 step 1). It is the
// in-process analogue of the Vault-role scoping that bounds the platform-service
// auth: [Registry.Covers] is the single predicate "may the producer read this
// plaintext?".
//
// It is NOT concurrency-safe; the control-plane caller serializes mutations
// (registration/revocation ride the serialized policy_log append anyway, D72).
type Registry struct {
	prefixes map[string]Designation // canonical prefix → designation
	secrets  map[string]Secret      // canonical path → escape-hatch registration
}

// NewRegistry returns an empty Registry — the explicit default-none posture
// (doc 16 §11.3 step 1).
func NewRegistry() *Registry {
	return &Registry{
		prefixes: make(map[string]Designation),
		secrets:  make(map[string]Secret),
	}
}

// Designate records a D84 prefix designation (doc 16 §11.3 step 2). It is
// idempotent on the canonical prefix: re-designating the same prefix replaces
// its ownership/owner. Fail-closed: an empty mount is rejected (a designation
// must name a tree to scope; the empty-everything case is not designable here —
// it would invert the default-none posture).
func (r *Registry) Designate(d Designation) error {
	if r.prefixes == nil {
		r.prefixes = make(map[string]Designation)
	}
	if strings.TrimSpace(d.Mount) == "" {
		return errors.New("fleetreg: designation needs a mount (default-none: an empty designation scopes nothing)")
	}
	if d.Ownership == OwnershipDeveloper && strings.TrimSpace(d.Owner) == "" {
		return errors.New("fleetreg: developer-owned designation needs an owner subject")
	}
	r.prefixes[d.canonical()] = d
	return nil
}

// RegisterSecret records a per-secret escape-hatch registration (doc 16 §11.3
// step 5). Fail-closed on a missing mount/path. Note: this only records the
// escape-hatch in the consent surface; the AUTHORITY check and the policy_log
// append are [Manager.Register]'s — this is the model layer the Manager drives.
func (r *Registry) RegisterSecret(s Secret) error {
	if r.secrets == nil {
		r.secrets = make(map[string]Secret)
	}
	if strings.TrimSpace(s.Mount) == "" || strings.TrimSpace(s.Path) == "" {
		return errors.New("fleetreg: escape-hatch registration needs a mount and a path")
	}
	if s.Ownership == OwnershipDeveloper && strings.TrimSpace(s.Owner) == "" {
		return errors.New("fleetreg: developer-owned secret needs an owner subject")
	}
	r.secrets[s.canonical()] = s
	return nil
}

// RemoveSecret drops a per-secret escape-hatch registration from the consent
// surface (the model side of a revoke). It reports whether the secret was
// present.
func (r *Registry) RemoveSecret(mount, path string) bool {
	key := canonPath(mount, path)
	_, ok := r.secrets[key]
	if ok {
		delete(r.secrets, key)
	}
	return ok
}

// RemoveDesignation drops a prefix designation from the consent surface. It
// reports whether the prefix was present. Secrets that were auto-covered ONLY by
// this prefix lose coverage (the producer stops reading them) — escape-hatch
// registrations are unaffected.
func (r *Registry) RemoveDesignation(mount, prefix string) bool {
	key := canonPath(mount, prefix)
	_, ok := r.prefixes[key]
	if ok {
		delete(r.prefixes, key)
	}
	return ok
}

// CoverageOf reports HOW a path is in the producer's read scope (doc 16 §6.4).
// Precedence: a prefix designation wins (auto-covered + inherits) over an
// escape-hatch; if neither matches, CoverageNone — the default-none answer. The
// returned Designation/Secret carry the authority class governing the path; for
// CoverageNone both are zero values.
func (r *Registry) CoverageOf(mount, path string) (Coverage, Designation, Secret) {
	cp := canonPath(mount, path)
	// Prefix wins: a newly-written secret under a designated prefix inherits
	// protection (doc 16 §11.3 step 4) — it is covered even with no per-secret row.
	if d, ok := r.bestPrefix(cp); ok {
		return CoveragePrefix, d, Secret{}
	}
	if s, ok := r.secrets[cp]; ok {
		return CoverageEscapeHatch, Designation{}, s
	}
	return CoverageNone, Designation{}, Secret{}
}

// Covers is the consent predicate: may the producer read this path's plaintext?
// True iff the path is under a designated prefix OR per-secret registered (doc 16
// §6.4 — "the producer touches plaintext only for designated trees", D84). The
// default-none Registry covers nothing.
func (r *Registry) Covers(mount, path string) bool {
	c, _, _ := r.CoverageOf(mount, path)
	return c != CoverageNone
}

// ExactTarget resolves a registered target by EXACT identity — the unit a revoke
// retires (doc 16 §11.3: revoke a designated PREFIX or a registered SECRET).
// Unlike [Registry.CoverageOf] (which answers the read-consent question for any
// LEAF that falls under a prefix, inheritance included), this matches only an
// entry whose own canonical key equals (mount, path): a prefix designation
// recorded at exactly that prefix, or a per-secret escape hatch at exactly that
// path. It returns CoverageNone for a leaf that is merely contained by a prefix —
// such a leaf was never independently registered, so there is nothing of its own
// to retire (revoking it would have to retire the whole prefix, which is the
// caller's explicit decision, not an implicit one). Escape-hatch wins a tie: a
// path registered as a secret AND coincidentally equal to a designated prefix is
// retired as the secret, leaving the broader designation intact.
func (r *Registry) ExactTarget(mount, path string) (Coverage, Designation, Secret) {
	key := canonPath(mount, path)
	if s, ok := r.secrets[key]; ok {
		return CoverageEscapeHatch, Designation{}, s
	}
	if d, ok := r.prefixes[key]; ok {
		return CoveragePrefix, d, Secret{}
	}
	return CoverageNone, Designation{}, Secret{}
}

// bestPrefix returns the longest designated prefix that contains the canonical
// path (longest-match, so a sub-prefix designation overrides a broader one's
// ownership). A designation of the bare mount contains every path under it.
func (r *Registry) bestPrefix(canonicalPath string) (Designation, bool) {
	var best Designation
	bestLen := -1
	for key, d := range r.prefixes {
		if prefixContains(key, canonicalPath) && len(key) > bestLen {
			best, bestLen = d, len(key)
		}
	}
	return best, bestLen >= 0
}

// Designations returns the recorded prefix designations, sorted by canonical
// prefix — the stable order the CLI `list` surface renders.
func (r *Registry) Designations() []Designation {
	out := make([]Designation, 0, len(r.prefixes))
	for _, d := range r.prefixes {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].canonical() < out[j].canonical() })
	return out
}

// Secrets returns the recorded per-secret escape-hatch registrations, sorted by
// canonical path.
func (r *Registry) Secrets() []Secret {
	out := make([]Secret, 0, len(r.secrets))
	for _, s := range r.secrets {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].canonical() < out[j].canonical() })
	return out
}

// Empty reports the default-none posture: no designation and no escape-hatch
// registration — an unconfigured surface designates nothing (doc 16 §11.3 step 1).
func (r *Registry) Empty() bool {
	return len(r.prefixes) == 0 && len(r.secrets) == 0
}

// ----- authority (D84) -----------------------------------------------------

// Authorizer enforces the D84 authority defaults at the registration entrypoint
// (doc 16 §6.4): org admin for org credentials, any developer for credentials
// they own. It is a value type carrying no state — the rule is the default; an
// org may tighten it via POL-4 later (out of scope here).
type Authorizer struct{}

// ErrUnauthorized is returned by Authorize when the principal may not
// register/revoke the credential under the D84 authority default. It is the
// fail-closed signal the Manager turns into "nothing appended to policy_log".
var ErrUnauthorized = errors.New("fleetreg: unauthorized for this credential (D84: org-admin for org credentials, owner for owned)")

// Authorize checks whether actor may register/revoke a credential of the given
// ownership/owner (doc 16 §6.4 authority default):
//
//   - org credential → org admin only;
//   - developer-owned credential → its owner (by IdP-subject) OR an org admin;
//   - unspecified ownership → org admin only (fail-closed: never default-allow).
//
// It returns ErrUnauthorized on denial so the caller writes NOTHING — the same
// no-row-on-refusal shape the orchestrator's ask-approval gate uses (doc 16 §8.2).
func (Authorizer) Authorize(actor Principal, ownership Ownership, owner string) error {
	if actor.IsOrgAdmin() {
		// Org admin is authorized over org credentials and, by superset, owned ones.
		return nil
	}
	if ownership == OwnershipDeveloper && actor.Subject != "" && actor.Subject == owner {
		return nil
	}
	return fmt.Errorf("%w: actor=%q ownership=%s owner=%q", ErrUnauthorized, actor.Subject, ownership, owner)
}

// ----- DigestSource seam (the kv-client read surface, §6.4/§11.3) ----------

// DigestSource is the seam onto the credential plaintext the producer digests —
// the read side of doc 16 §6.4, satisfied in production by
// identity/kv-client.Client (List the designated tree, Read each leaf) and by an
// in-process fake in tests (D50). It exposes ONLY reads (the §11.3 read-only
// posture is structural: no write/lease method exists), and the Manager calls it
// ONLY for paths [Registry.Covers] approves — so "the producer touches plaintext
// only for designated trees" (D84) is enforced at the Manager, not by source
// convention.
//
// It is intentionally narrower than kv-client.Client (which speaks Vault HTTP):
// the Manager needs only "list the leaves under a prefix" and "read one secret's
// bytes", so an adapter projects kv-client.Client onto this seam without this
// module importing the HTTP transport. A trailing "/" on a List result denotes a
// sub-prefix (the Vault list convention) — ListLeaves resolves those to leaf
// paths so the Manager need not re-walk.
type DigestSource interface {
	// ListLeaves returns the full leaf paths (recursive, no trailing-"/" sub-
	// prefixes) under the prefix within the mount — the tree the producer would
	// digest. It returns plaintext-free path names only.
	ListLeaves(ctx context.Context, mount, prefix string) ([]string, error)
	// ReadSecret returns the secret bytes at the exact logical path within the
	// mount — the plaintext the producer HMACs and drops. The Manager only ever
	// calls this for a Covers-approved path.
	ReadSecret(ctx context.Context, mount, path string) ([]byte, error)
}

// ----- path canonicalization ----------------------------------------------

// canonPath joins a mount and a path/prefix into a single slash-normalized key
// of the form "mount/segment/segment". Leading/trailing slashes are trimmed and
// internal empty segments collapsed so "secret/", "/secret", and "secret" all
// canonicalize identically. An empty prefix yields the bare mount.
func canonPath(mount, path string) string {
	m := strings.Trim(strings.TrimSpace(mount), "/")
	p := strings.Trim(strings.TrimSpace(path), "/")
	if p == "" {
		return m
	}
	if m == "" {
		return p
	}
	return m + "/" + p
}

// prefixContains reports whether canonical prefix contains canonical path —
// equal, or path is under prefix at a SEGMENT boundary (so "secret/data" does
// NOT contain "secret/database/x"). The bare-mount prefix contains every path
// under that mount.
func prefixContains(prefix, path string) bool {
	if prefix == path {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

// ----- full-rotation ordering (the redeploy seam; doc 16 §6.2/§6.3) ---------
//
// A key rotation/re-key rolls BOTH digest cadences: the SESSION digests over
// DigestFeedService and the FLEET-scope digests this package registers over the
// policy stream. The identity-side choreographer that orders them —
// [github.com/dream-serpent/dream-serpent/identity/digest.KeyManager.FullRotation]
// — runs the session leg (LiveRekey) FIRST and the fleet leg (LiveRekeyFleet)
// SECOND over the SHARED retiring key. This surface (the fleet-registration side)
// carries the ordering statement so an operator reading the registration API sees
// where the fleet leg sits in a full rotation, and — critically — what the fleet
// cadence's no-gap guarantee actually IS.
//
// THE FLEET NO-GAP PROOF IS THE POLICY-LOG RETIRE APPEND, NOT THE SHARED-SET
// DROP. The session and fleet legs share the KeyManager's `retiring` lifecycle
// set, and the session leg may drop the shared key id first. The fleet leg
// tolerates that (a benign "not retiring" on the shared drop) and proves ITS
// cadence gap-free a different way: the RevokeFleetPolicy append on the
// policy_log — the new-key fleet artifact applied BEFORE the old-key retire
// artifact. So the fleet cadence's gap-free property is the policy-stream
// register-before-retire ordering, NOT the shared retiring-set bookkeeping.
// Reading digest.FleetRekeyResult.OldKeyRetired as "the shared lifecycle key was
// dropped" would misread the fleet guarantee; it means "the fleet artifact retire
// committed on the policy stream". [Manager.Revoke] rides the same
// RevokeFleetPolicy append, so a fleet revocation issued through this surface has
// the identical policy-log proof.
//
// This is a DOCUMENTATION seam only: fleet registration/revocation flows through
// [Manager]'s authority-gated verbs and the identity/digest policy-stream verbs
// as before. FullRotationOrdering renders the ordering + no-gap-proof clause the
// operator/auditor runbook cites (proposed for docs/16 §6.2/§6.3), so the
// statement is single-sourced from the code that enforces it rather than restated
// in prose that can drift.

// RotationLeg names one cadence in a full rotation, in the order FullRotation
// runs them: the session leg first, the fleet leg second.
type RotationLeg int

const (
	// RotationLegSession is the session-digest cadence over DigestFeedService
	// (digest.KeyManager.LiveRekey). It runs FIRST and drops the SHARED retiring
	// key id on success.
	RotationLegSession RotationLeg = iota
	// RotationLegFleet is the fleet-scope-digest cadence over the policy stream
	// (digest.KeyManager.LiveRekeyFleet) — the cadence THIS package registers on.
	// It runs SECOND, tolerating the session leg's shared-key drop, and proves its
	// no-gap via the policy-log retire append.
	RotationLegFleet
)

func (l RotationLeg) String() string {
	switch l {
	case RotationLegSession:
		return "session"
	case RotationLegFleet:
		return "fleet"
	default:
		return "unknown"
	}
}

// FullRotationOrder is the fixed leg order a full rotation runs: session then
// fleet (doc 16 §6.2/§6.3). It mirrors the sequencing in
// digest.KeyManager.FullRotation from the registration surface so a caller that
// drives the legs by hand (or an operator runbook) reads the authoritative order
// here rather than restating it.
func FullRotationOrder() []RotationLeg {
	return []RotationLeg{RotationLegSession, RotationLegFleet}
}

// FullRotationOrdering renders the one-line ordering + fleet no-gap-proof clause
// for the operator/auditor runbook (proposed for docs/16 §6.2/§6.3). It states
// the leg order AND that the fleet cadence's gap-free guarantee is the policy-log
// retire append, never the shared retiring-set drop — the statement that keeps
// the shared-set bookkeeping from being misread as the fleet guarantee.
func FullRotationOrdering() string {
	return "full rotation: session leg (DigestFeedService LiveRekey) first, dropping the shared retiring key; " +
		"fleet leg (policy-stream LiveRekeyFleet) second, tolerating that drop. " +
		"The fleet no-gap proof is the policy_log retire APPEND (new-key artifact before old-key retire), " +
		"NOT the shared retiring-set drop."
}
