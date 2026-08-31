// SPDX-License-Identifier: Apache-2.0

// Package idp is the Identity IdP front end: Okta-via-generic-OIDC launch-time
// HUMAN authentication and principal-claim resolution (doc 16 §11.2; doc 07
// §2c). It authenticates the launching human at mint time and resolves the OIDC
// subject to the `launching_user` claim VALUE the workload identity carries
// (doc 16 §3.1/§3.2), mapping IdP groups to platform roles (D45/D56/D57).
//
// THE MINT-TIME-ONLY BOUNDARY (doc 16 §11.2, load-bearing). The IdP participates
// ONLY at mint time — it authenticates the human and asserts group claims when a
// principal is established. It is NEVER consulted on the per-request hot path:
// every egress request's credential is validated at the D22 `Validate` seam
// (identity/mint), with NO call to the IdP. This package therefore holds NO
// per-request validation logic; it ends at the validated, claim-bearing
// AuthResult. Putting the IdP on the request path would break the §5.1
// "fetch per-grant, never per-request" latency story and re-introduce the
// availability dependency the D22 seam is designed to keep off the hot path.
//
// GENERIC OIDC, NOT OKTA-PROPRIETARY (D55 — "IdP #2 becomes config, not code").
// Okta is implemented as generic OIDC: the platform holds an OIDC relying-party
// Config per org (issuer/discovery, client id/secret, the device + auth
// endpoints from discovery, and the claim/group mappings). A second IdP (Entra
// ID, Google Workspace, any OIDC provider) is a new Config row, not new code.
package idp

import (
	"errors"
	"fmt"
	"strings"
)

// ErrConfig is returned when a relying-party Config is structurally invalid
// (missing issuer/client id, or a group→role mapping naming a role outside the
// platform vocabulary). It is a configuration fault, surfaced loudly rather than
// silently degrading to default-allow (the §11.2 fail-closed posture).
var ErrConfig = errors.New("idp: invalid relying-party config")

// PlatformRole is the platform role an IdP group maps to (doc 16 §3.2 role
// vocabulary, D45/D56/D57). It is the STRING the group→role table yields; the
// orchestrator/internal/auth side maps these onto the store's PrincipalRole
// values when it upserts the principal. The vocabulary is carried here as
// strings (not the store's typed PrincipalRole) on purpose: identity/idp is a
// standalone module that must not import the orchestrator's store package — the
// resolved roles cross the boundary as DATA, exactly like the launching_user
// claim crosses the proto seam as data (the §3.1 / mintrequest.go discipline).
//
// The five values mirror the doc 16 §3.2 set token-for-token; the auth-side
// mapping rejects any token outside this set, so a config typo fails closed
// (an unmapped/misspelled role confers nothing, never a default).
type PlatformRole string

const (
	RoleLauncher  PlatformRole = "launcher"   // may launch sessions (default human authority)
	RoleViewer    PlatformRole = "viewer"     // read-only spectate (D57; never attended per D78)
	RoleApprover  PlatformRole = "approver"   // may approve ask-a-human requests (D45)
	RoleOrgAdmin  PlatformRole = "org-admin"  // org administration (D45 allow-always, D56 enrollment)
	RoleRepoAdmin PlatformRole = "repo-admin" // repo-scoped administration (D56 enrollment posture)
)

// platformRoles is the legal role set in doc 16 §3.2 reading order. It is the
// single source the validateRole guard checks a configured mapping against.
var platformRoles = []PlatformRole{
	RoleLauncher, RoleViewer, RoleApprover, RoleOrgAdmin, RoleRepoAdmin,
}

// valid reports whether r is one of the five §3.2 roles (the mapping guard).
func (r PlatformRole) valid() bool {
	for _, have := range platformRoles {
		if r == have {
			return true
		}
	}
	return false
}

// Config is the per-org OIDC relying-party configuration (doc 16 §11.2). It is
// the WHOLE of what makes Okta "config, not code" (D55): a second IdP is a new
// Config value. Endpoints are resolved from the OIDC discovery document
// (DiscoveryURL) at use time; the explicit endpoint fields below are the
// resolved cache / test-injection seam, not a parallel source of truth.
type Config struct {
	// Org is the org this relying-party config belongs to. The same IdP subject
	// in two orgs is two principals (doc 16 §3.2), so the org is part of the
	// principal business key the auth side upserts against.
	Org string

	// Issuer is the OIDC issuer identifier (the `iss` claim the ID token must
	// carry). DiscoveryURL defaults to Issuer + "/.well-known/openid-configuration"
	// when empty (the standard discovery location).
	Issuer       string
	DiscoveryURL string

	// ClientID / ClientSecret are the relying-party credentials registered with
	// the IdP. ClientSecret is empty for public clients (the CLI device-code flow
	// can run as a public client; the web redirect flow uses PKCE).
	ClientID     string
	ClientSecret string

	// Scopes requested at authorization. "openid" is always included; "profile"
	// and the groups scope are added by default so the subject + groups claims
	// are present. An empty slice means the package defaults are used.
	Scopes []string

	// GroupsClaim is the claim NAME the groups list is read from. IdPs differ
	// ("groups" for Okta, "roles"/"wids" for others), so it is config. Defaults
	// to "groups" when empty.
	GroupsClaim string

	// GroupRoleMap is the org-level group→role table (doc 16 §11.2 "Groups →
	// platform roles"). It is ONE auditable org config, the same shape as the
	// D84 prefix-designation decision. A group with no mapping confers NO role
	// (fail-closed: absence of a mapping is denial, not a default-allow).
	GroupRoleMap map[string]PlatformRole

	// Audience is the expected `aud` claim. Defaults to ClientID when empty (the
	// standard OIDC convention: the ID token's audience is the relying party).
	Audience string
}

// DefaultGroupsClaim is the claim name groups are read from when GroupsClaim is
// unset. IdPs differ, so it is config; Okta's default is "groups".
const DefaultGroupsClaim = "groups"

// defaultScopes are requested when Config.Scopes is empty: openid is mandatory,
// profile/email carry display metadata (never the identity key — §11.2), and
// the groups scope makes the §11.2 group claim present.
var defaultScopes = []string{"openid", "profile", "email", "groups"}

// Validate checks the Config's structural invariants and returns ErrConfig on
// the first violation. It is called by every flow constructor so a malformed
// relying-party config fails loudly at setup, not silently at auth time. A nil /
// empty GroupRoleMap is LEGAL (an org may map no groups yet — every principal is
// then a roleless record until its groups are mapped); a mapping naming a role
// outside the §3.2 vocabulary is NOT legal (a config typo must fail closed).
func (c Config) Validate() error {
	if strings.TrimSpace(c.Org) == "" {
		return fmt.Errorf("%w: org is required", ErrConfig)
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("%w: issuer is required", ErrConfig)
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("%w: client_id is required", ErrConfig)
	}
	for group, role := range c.GroupRoleMap {
		if !role.valid() {
			return fmt.Errorf("%w: group %q maps to unknown role %q", ErrConfig, group, role)
		}
	}
	return nil
}

// discoveryURL returns the OIDC discovery document URL: the explicit
// DiscoveryURL when set, else the standard issuer-relative well-known location.
func (c Config) discoveryURL() string {
	if c.DiscoveryURL != "" {
		return c.DiscoveryURL
	}
	return strings.TrimRight(c.Issuer, "/") + "/.well-known/openid-configuration"
}

// groupsClaim returns the configured groups claim name, or the default.
func (c Config) groupsClaim() string {
	if c.GroupsClaim != "" {
		return c.GroupsClaim
	}
	return DefaultGroupsClaim
}

// audience returns the expected ID-token audience: the explicit Audience, else
// the ClientID (the standard OIDC convention).
func (c Config) audience() string {
	if c.Audience != "" {
		return c.Audience
	}
	return c.ClientID
}

// scopes returns the requested scopes (configured or default), guaranteeing
// "openid" is present (it is mandatory for an OIDC ID token to be issued).
func (c Config) scopes() []string {
	src := c.Scopes
	if len(src) == 0 {
		src = defaultScopes
	}
	out := make([]string, 0, len(src)+1)
	hasOpenID := false
	for _, s := range src {
		if s == "openid" {
			hasOpenID = true
		}
		out = append(out, s)
	}
	if !hasOpenID {
		out = append([]string{"openid"}, out...)
	}
	return out
}

// MapGroups maps an asserted group list to the platform role set via the
// org-level GroupRoleMap (doc 16 §11.2). Roles are DERIVED from the asserted
// groups, never stored as a parallel ACL the IdP can drift from: a group removed
// at the IdP drops its role at the next claim re-check (the offboarding ladder).
//
// Fail-closed semantics (doc 16 §11.2): a group with no mapping confers NO role.
// The result is de-duplicated and returned in §3.2 vocabulary order so the role
// set is stable for upsert idempotency (the auth side compares role sets to
// decide whether a re-auth changed anything). An empty input or no matches
// yields an empty (non-nil) slice — a valid, roleless principal.
func (c Config) MapGroups(groups []string) []PlatformRole {
	seen := make(map[PlatformRole]bool)
	for _, g := range groups {
		if role, ok := c.GroupRoleMap[g]; ok {
			seen[role] = true
		}
	}
	out := make([]PlatformRole, 0, len(seen))
	for _, role := range platformRoles { // stable §3.2 order
		if seen[role] {
			out = append(out, role)
		}
	}
	return out
}
