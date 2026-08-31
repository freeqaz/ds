// SPDX-License-Identifier: Apache-2.0

// The grant model + MintGrants + placeholder-token surface (doc 16 §5.1; D7,
// D22, D39, D52, D83).
//
// A GRANT is a typed record — identity × service × scope × TTL (§5.1 verbatim).
// It is issued at MINT TIME from the session's env spec (D7) intersected with
// the org `services[]` registry: the registry defines *capability* (which swaps
// exist), the env spec names which of those the session asked for, and the grant
// binds the capability to one identity. The grant decision is a DETERMINISTIC
// LOOKUP, never a policy evaluation — no Cedar, no expression language in v0
// (D52). Revisit at M4 when grant conditions become relational (§5.1).
//
// The grant-record proto is NOT frozen in identity.v1 (ca_mint.proto carries
// MintGrants as a RESERVED-only comment, no message body), so this file models
// grants as INTERNAL GO TYPES mirroring the §5.1 shape. Promoting them to a
// frozen proto is a follow-up routed through proto/FREEZE.md (the rider filed by
// this wave as a PROPOSED follow-up; never landed here — no .proto edits).
//
// What the agent holds is a per-service short-lived PLACEHOLDER TOKEN minted
// with the session (§5.1, brief gap 9): the presented value validates at the D22
// Validate seam, but a placeholder must NEVER validate as workload identity (it
// is not a JWS over the workload key) nor as interception material — only as the
// opaque grant-presentation it is. The `ISSUED{service_id}` digest tag is
// DERIVED from the grant record (§5.1/§6): a digest's intended service is a grant
// fact.
package mint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// GrantScope is the §5.1 scope axis of a grant. v0 carries the two scopes the
// digest feed already classifies (doc 14 §7 / §6.2): SESSION-scoped grants are
// session-lifecycle data (the D72-exempt class), FLEET-scoped grants are policy
// artifacts. The grant model is the source of the cred_class scope on the digest
// feed (§6), so the axis is named here even though M0 issuance is session-scoped.
type GrantScope int

const (
	// ScopeSession is the default: the grant lives and dies with the session
	// (the D17 CA / D22 grant lifecycle class, §6.2).
	ScopeSession GrantScope = iota
	// ScopeFleet marks a grant whose digest rides the fleet policy cadence
	// (§6.2). No M0 issuance path mints fleet grants; the axis is reserved so the
	// digest-tag derivation (§6) can carry it without a model change.
	ScopeFleet
)

// String renders the scope as the digest-feed token (doc 14 §7 scope field).
func (s GrantScope) String() string {
	switch s {
	case ScopeFleet:
		return "FLEET"
	default:
		return "SESSION"
	}
}

// Grant is one typed grant record — the §5.1 shape verbatim: identity × service
// × scope × TTL. It is the deterministic binding the swap executor resolves at
// Validate (§4) and the fact the `ISSUED{service_id}` digest tag derives from
// (§6). No expression language anywhere on the record (D52): every field is a
// concrete value, the decision a map read.
type Grant struct {
	// Identity is the session identity the grant binds the capability TO — the
	// SPIFFE-compatible workload identity name (§3.1, spiffe://<org>/session/...).
	// This is the "identity" axis of the §5.1 tuple.
	Identity string
	// ServiceID is the `services[]` registry key the grant authorizes (the
	// "service" axis). It is what `Validate(presented, session, service_id)` keys
	// the grant lookup on (§4) and what the digest tag names (§6).
	ServiceID string
	// Scope is the §5.1 scope axis (SESSION default; see GrantScope).
	Scope GrantScope
	// IssuedAt / Expiry bound the grant's TTL (the "TTL" axis). TTL ≤ session
	// lifetime (D39 cache ceiling). Expiry is checked at Validate freshness.
	IssuedAt time.Time
	Expiry   time.Time
	// GrantRef is the opaque handle the swap executor presents to the grant
	// service to fetch the real credential (§9 grant-fetch row); it never carries
	// secret material, only a reference. Deterministic from identity×service so a
	// re-issue for the same binding is stable.
	GrantRef string
}

// expired reports whether the grant is past its TTL at instant now.
func (g Grant) expired(now time.Time) bool {
	return !g.Expiry.IsZero() && !now.Before(g.Expiry)
}

// ServiceRegistryEntry is one row of the org `services[]` registry (§5.1 / §7):
// it declares a *capability* — which swap exists and where the credential is
// carried — independent of any identity. Grants bind these entries to an
// identity; credential-class rules (§7) express limits on top. Registry content
// is POL-1 value ownership (§9), supplied by the org, not minted here.
type ServiceRegistryEntry struct {
	// ServiceID is the registry key (e.g. "github"). Grants and the digest tag
	// reference it.
	ServiceID string
	// Destinations are the hosts this service's credential is expected on — the
	// destination-scope the `ISSUED{service_id}` digest enforces (§11.1
	// wrong-destination block). Informational on the grant model; the boundary
	// enforces.
	Destinations []string
	// CredentialLocation names where the swap substitutes the credential (the
	// frozen generic Authorization-header seam, D83 — "Authorization" by default,
	// doc 13 §3). Free per §12 beyond the header default.
	CredentialLocation string
	// DefaultTTL is the registry-default grant lifetime when the env spec names
	// no override. Bounded by the session lifetime at issuance.
	DefaultTTL time.Duration
}

// ServiceRegistry is the org `services[]` registry — the capability catalog.
// Lookup is a deterministic map read (no Cedar, D52).
type ServiceRegistry struct {
	entries map[string]ServiceRegistryEntry
}

// NewServiceRegistry builds a registry from the given capability rows. A
// duplicate service_id is rejected — the registry is a set keyed by service_id.
func NewServiceRegistry(entries ...ServiceRegistryEntry) (*ServiceRegistry, error) {
	r := &ServiceRegistry{entries: make(map[string]ServiceRegistryEntry, len(entries))}
	for _, e := range entries {
		if e.ServiceID == "" {
			return nil, errors.New("mint: registry entry with empty service_id")
		}
		if _, dup := r.entries[e.ServiceID]; dup {
			return nil, fmt.Errorf("mint: duplicate service_id %q in registry", e.ServiceID)
		}
		r.entries[e.ServiceID] = e
	}
	return r, nil
}

// Lookup returns the capability row for a service_id (deterministic, D52).
func (r *ServiceRegistry) Lookup(serviceID string) (ServiceRegistryEntry, bool) {
	e, ok := r.entries[serviceID]
	return e, ok
}

// EnvSpec is the session's env config (D7) — the per-session request for which
// registry capabilities this session should be granted. The env spec NAMES
// services; the registry DEFINES them; issuance is the deterministic
// intersection (§5.1: "issued at mint time from the session's env spec + the org
// services[] registry").
type EnvSpec struct {
	// Services are the service_ids this session requests. A request for a service
	// not in the registry confers no grant (fail-closed: absence is denial,
	// §11.2 unmapped-groups discipline applied to capabilities).
	Services []string
	// TTLOverrides optionally shortens a service's grant TTL below the registry
	// default (never lengthens past the session lifetime). Keyed by service_id.
	TTLOverrides map[string]time.Duration
}

var errNoRegistry = errors.New("mint: no service registry configured")

// WithServiceRegistry installs the org services[] registry on the shim, so
// IssueGrants can resolve env-spec service requests against capabilities.
func WithServiceRegistry(r *ServiceRegistry) Option {
	return func(s *Shim) { s.registry = r }
}

// IssueGrants is the deterministic grant-issuance leg (§5.1). It intersects the
// session's env spec (D7) with the org services[] registry: for each requested
// service that the registry defines, it mints a Grant binding that capability to
// the session identity, with a TTL bounded by the registry default (or the env
// override) and the session lifetime. The issuance is a pure lookup — no Cedar,
// no expression evaluation (D52) — so it is fully table-testable.
//
// Requested services absent from the registry are SKIPPED (fail-closed: no
// capability ⇒ no grant ⇒ the later Validate finds no grant and DENYs
// out_of_grant, §11.1 step 1). The grants are recorded on the session record so
// the existing Validate grant lookup (validate.go) resolves them, and returned
// so the caller (the mint sub-sequence, §6.1) can hand them to the digest
// producer for `ISSUED{service_id}` derivation.
//
// sessionUUID must already have a minted workload identity (MintWorkloadIdentity
// ran), so the grant's Identity axis is the session's SPIFFE name and the grant
// TTL can be clamped to the session expiry.
func (s *Shim) IssueGrants(sessionUUID string, env EnvSpec) ([]Grant, error) {
	if sessionUUID == "" {
		return nil, errEmptySession
	}
	if s.registry == nil {
		return nil, errNoRegistry
	}
	now := s.now()

	s.mu.Lock()
	rec := s.sessions[sessionUUID]
	if rec == nil {
		rec = &sessionRecord{grants: make(map[string]string)}
		s.sessions[sessionUUID] = rec
	}
	identity := spiffeURIForRecord(rec, sessionUUID)
	sessionExpiry := rec.expiry
	if rec.grantRecords == nil {
		rec.grantRecords = make(map[string]Grant)
	}

	// Deterministic order: sort the requested services so the issued slice and
	// any derived digests are stable across runs (table-test friendliness, and a
	// stable GrantRef ordering).
	requested := append([]string(nil), env.Services...)
	sort.Strings(requested)

	var issued []Grant
	for _, svc := range requested {
		entry, ok := s.registry.Lookup(svc)
		if !ok {
			// No capability in the registry ⇒ no grant (fail-closed, §11.1 step 1).
			continue
		}
		ttl := entry.DefaultTTL
		if env.TTLOverrides != nil {
			if ov, has := env.TTLOverrides[svc]; has && ov > 0 && ov < ttl {
				ttl = ov
			}
		}
		if ttl <= 0 {
			ttl = defaultSessionTTL
		}
		expiry := now.Add(ttl)
		// Clamp to the session lifetime (TTL ≤ session, D39 cache ceiling).
		if !sessionExpiry.IsZero() && expiry.After(sessionExpiry) {
			expiry = sessionExpiry
		}
		g := Grant{
			Identity:  identity,
			ServiceID: svc,
			Scope:     ScopeSession,
			IssuedAt:  now,
			Expiry:    expiry,
			GrantRef:  grantRef(sessionUUID, svc),
		}
		rec.grants[svc] = g.GrantRef // keep the existing Validate lookup working
		rec.grantRecords[svc] = g    // the typed record for digest derivation
		issued = append(issued, g)
	}
	s.mu.Unlock()
	return issued, nil
}

// GrantRecord returns the typed grant record for a session×service binding, or
// false if no grant was issued. Read-only accessor; mints nothing. Exposed so
// the digest producer can derive the `ISSUED{service_id}` tag from the grant
// fact (§6) and the swap executor can read the grant's TTL.
func (s *Shim) GrantRecord(sessionUUID, serviceID string) (Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.sessions[sessionUUID]
	if rec == nil || rec.grantRecords == nil {
		return Grant{}, false
	}
	g, ok := rec.grantRecords[serviceID]
	return g, ok
}

// IssuedDigestTag derives the `cred_class` digest tag from a grant record (§5.1
// / §6): a digest's intended service is a grant FACT, so the tag is computed
// FROM the grant, never asserted independently. The shape mirrors the doc 14 §7
// cred_class field: ISSUED{service_id} for a session-issued credential. This is
// the single place the tag is derived, so the §11.1 step-7 invariant ("the tag
// is derived from the grant record") is structurally true, not coincidental.
func IssuedDigestTag(g Grant) string {
	return "ISSUED{" + g.ServiceID + "}"
}

// --- the per-service placeholder token (§5.1, MintGrants) --------------------

// placeholderToken is the per-service short-lived placeholder minted with the
// session (§5.1). It is a compact opaque value the agent holds; its presented
// form validates at the D22 seam but NEVER as workload identity (it is not a JWS
// over the workload key) nor as interception material. The HMAC over a fixed
// domain-separation prefix with a per-shim placeholder key is what makes a
// placeholder structurally NOT a JWS: it has the wrong number of segments and no
// ECDSA signature, so verifyJWT rejects it outright (the negative test).
const placeholderPrefix = "dsph1." // domain-separation tag; "ds placeholder v1"

// MintGrantsRequest is the MintGrants input (§5.1): a session and its env spec.
// The org registry is shim-wide (WithServiceRegistry).
type MintGrantsRequest struct {
	SessionUUID string
	Env         EnvSpec
}

// PlaceholderToken pairs an issued grant with the opaque per-service token the
// agent presents for it (§5.1 brief gap 9). The token is NOT a credential — it
// carries no secret — it is the presentation the swap executor hands to Validate
// so the grant lookup runs.
type PlaceholderToken struct {
	ServiceID string
	Grant     Grant
	// Token is the opaque presented value (placeholderPrefix || base64(hmac)).
	Token string
}

// GrantSet is the MintGrants output (§5.1 "GrantSet"): the issued grants plus
// the per-service placeholder tokens the agent holds.
type GrantSet struct {
	Grants       []Grant
	Placeholders []PlaceholderToken
}

// MintGrants is the §5.1 MintGrants surface: it issues the deterministic grant
// set from the env spec + registry (IssueGrants) and mints a per-service
// short-lived placeholder token for each issued grant. Native Go — MintGrants is
// RESERVED-only in the proto (ca_mint.proto), so there is no generated server;
// the freeze rider that promotes it is a proposed follow-up routed through
// proto/FREEZE.md (never this wave).
//
// Each placeholder is registered on the session record under its service_id, so
// the existing Validate seam (validate.go) accepts the placeholder presentation
// for that service and NOTHING else: a placeholder for "github" never validates
// for "npm", and a placeholder never validates as the workload JWT (different
// structure entirely).
func (s *Shim) MintGrants(req MintGrantsRequest) (*GrantSet, error) {
	grants, err := s.IssueGrants(req.SessionUUID, req.Env)
	if err != nil {
		return nil, err
	}
	// The placeholder mint is shared with MintGrantsScoped (roletemplate_consume.go)
	// so the scoped and unscoped surfaces never drift — a placeholder is registered
	// under its service_id, accepted at Validate for that service and nothing else.
	return s.mintPlaceholdersFor(req.SessionUUID, grants), nil
}

// mintPlaceholder builds the opaque per-service placeholder: a domain-separated
// HMAC over session_uuid|service_id|grant_ref|expiry, base64url-encoded behind
// the placeholderPrefix. It is deterministic per binding (stable across re-mint)
// and structurally NOT a JWS (one HMAC segment behind a literal prefix, never
// header.claims.sig).
func mintPlaceholder(key []byte, sessionUUID string, g Grant) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(sessionUUID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(g.ServiceID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(g.GrantRef))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(fmt.Sprintf("%d", g.Expiry.Unix())))
	return placeholderPrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// IsPlaceholder reports whether a presented value is structurally a placeholder
// (has the placeholderPrefix). Used by Validate to route the placeholder branch
// and — critically — to refuse to treat a placeholder as a workload JWT.
func IsPlaceholder(presented []byte) bool {
	return strings.HasPrefix(string(presented), placeholderPrefix)
}

// validatePlaceholder is the placeholder leg of the Validate seam: it accepts a
// presented placeholder iff it matches the placeholder the shim minted for THIS
// session × service AND the grant is unexpired. It NEVER falls through to the
// workload-JWT path, so a placeholder can only ever validate as the grant
// presentation it is — never as workload identity, never as interception
// material. Returns the grant_ref on success.
func (s *Shim) validatePlaceholder(presented []byte, sessionUUID, serviceID string, now time.Time) ValidateResult {
	s.mu.Lock()
	rec := s.sessions[sessionUUID]
	var (
		want   string
		hasPH  bool
		g      Grant
		hasG   bool
		state  sessionState
		expiry time.Time
		reason string
		known  = rec != nil
	)
	if rec != nil {
		want, hasPH = rec.placeholders[serviceID]
		g, hasG = rec.grantRecords[serviceID]
		state = rec.state
		expiry = rec.expiry
		reason = rec.revokeReason
	}
	s.mu.Unlock()

	if !known {
		return deny(ReasonUnknownSession)
	}
	if state == sessionRevoked {
		if reason == "" {
			reason = ReasonSessionRevoked
		}
		return deny(reason)
	}
	if !expiry.IsZero() && now.After(expiry) {
		return deny(ReasonSessionExpired)
	}
	if !hasPH || !hasG {
		return deny(ReasonOutOfGrant)
	}
	// Constant-time compare of the presented placeholder against the minted one
	// (a presented value for the wrong service won't match this service's token).
	if !hmac.Equal(presented, []byte(want)) {
		return deny(ReasonSignatureInvalid)
	}
	if g.expired(now) {
		return deny(ReasonCredentialStale)
	}
	return ValidateResult{Verdict: VerdictAllow, GrantRef: g.GrantRef, Expiry: g.Expiry}
}

// --- the GrantRef contract (the cross-module seam, §9 grant-fetch row) --------
//
// grant_ref is the ONLY string both this module and the standalone
// identity/grant-service module agree on: this side WRITES it (grantRef →
// GrantSet → RegisterSession), the grant-service side READS it (Service.Fetch
// keys the D39 store lookup on the exact same string). The two modules are
// separate GOWORK=off Go modules with no compile- or test-time link, so a
// unilateral format change on either side would silently break the per-session
// fetch with no build error.
//
// The CONTRACT MECHANISM is a committed golden round-trip fixture
// (testdata/grantref-golden.json) carried IDENTICALLY in both modules: this side
// is exercised by grants_test.go (the WRITER must produce exactly the golden
// ref), the grant-service side by its own test (the READER must parse the golden
// ref back to exactly the golden session×service). If either side edits its
// format/parse functions unilaterally, ITS OWN suite fails against the shared
// golden — the drift breaks loudly at test time instead of silently at fetch
// time. The golden is the single source of truth; FormatGrantRef/ParseGrantRef
// are the two halves of one round trip and MUST stay inverses.
const (
	// grantRefPrefix + grantRefSep define the wire shape "grant:<session>:<service>".
	// Changing either changes the contract — and breaks the golden round trip.
	grantRefPrefix = "grant:"
	grantRefSep    = ":"
)

// FormatGrantRef builds the deterministic, secret-free grant handle for a
// session×service binding (the §9 grant-fetch key). It is the WRITER half of the
// GrantRef contract; ParseGrantRef is its inverse. Stable across re-issue so a
// fetch caches predictably; never contains credential material. The committed
// golden fixture pins its output, so a unilateral change to this function fails
// the mint test suite.
func FormatGrantRef(sessionUUID, serviceID string) string {
	return grantRefPrefix + sessionUUID + grantRefSep + serviceID
}

// ParseGrantRef is the inverse of FormatGrantRef: it splits a grant_ref back into
// its session and service axes. It is carried here (and identically on the
// grant-service side) so the round trip is exercised by the golden fixture on
// both sides of the seam. ok is false for any string that is not a well-formed
// grant_ref (wrong prefix, wrong field count, empty axis) — fail-closed parsing.
func ParseGrantRef(ref string) (sessionUUID, serviceID string, ok bool) {
	if !strings.HasPrefix(ref, grantRefPrefix) {
		return "", "", false
	}
	body := ref[len(grantRefPrefix):]
	sep := strings.Index(body, grantRefSep)
	if sep < 0 {
		return "", "", false
	}
	sessionUUID = body[:sep]
	serviceID = body[sep+len(grantRefSep):]
	if sessionUUID == "" || serviceID == "" {
		return "", "", false
	}
	// A service_id that itself contains the separator would re-split ambiguously;
	// the golden axes never do, but guard so a malformed ref fails closed.
	if strings.Contains(serviceID, grantRefSep) {
		return "", "", false
	}
	return sessionUUID, serviceID, true
}

// grantRef is the internal writer used by IssueGrants; it delegates to the
// exported FormatGrantRef so the format lives in exactly one place.
func grantRef(sessionUUID, serviceID string) string {
	return FormatGrantRef(sessionUUID, serviceID)
}

// spiffeURIForRecord resolves the grant's Identity axis. The record does not
// store the org, so when a workload identity was minted the SPIFFE name is
// reconstructable only from the session; the M0 grant binds to the session-scoped
// SPIFFE path tail when the org is unknown. Callers that minted a workload
// identity first get the full name via the session's bundle; here we fall back
// to the session-scoped identity reference, which is sufficient for the
// deterministic binding (the identity axis distinguishes sessions, D50 synthetic).
func spiffeURIForRecord(rec *sessionRecord, sessionUUID string) string {
	if rec != nil && rec.identity != "" {
		return rec.identity
	}
	return "session/" + sessionUUID
}
