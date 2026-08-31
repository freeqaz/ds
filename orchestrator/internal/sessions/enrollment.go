package sessions

// enrollment.go is the D56 control-plane ENROLLMENT model — the FIRST key's WRITE
// side and its PERMISSION model. twokey.go reads "is this repo enrolled?" through the
// EnrollmentResolver seam at create step 1; THIS file is what answers that with a real,
// flippable control-plane setting (not the v0 open-pool stub), and enforces WHO may
// flip it:
//
//	D56, verbatim: "Repo opt-in is two-key: control-plane enrollment (repo admins by
//	  default; org-owner restrictable) answers *whether* … neither alone activates a
//	  repo." (doc 04 §6 D56; doc 07 OQ4, resolved 2026-06-11.)
//
// The control plane answers WHETHER. That answer is a stored EnrollmentSetting per repo
// — enrolled/disabled, plus the audit fact of who flipped it and the org-restriction
// posture in force. Flipping it is a PERMISSIONED act (the D56 permission model):
//   - DEFAULT: a repo admin (RoleRepoAdmin) may enroll/disable their own repo, and an
//     org admin (RoleOrgAdmin) may too (org admin is strictly broader authority).
//   - ORG-OWNER RESTRICTABLE: an org owner may restrict enrollment authority to org
//     admins only; under that restriction a repo admin may NOT flip enrollment — only
//     an org admin may. This mirrors the GitHub-App "select repositories" + push-ruleset
//     model doc 07 OQ4 cites: repo admins self-serve by default, org owners can centralize.
//
// WHAT THIS OWNS vs WHAT IT DOES NOT:
//   - OWNS: the EnrollmentSetting model, the in-package EnrollmentRegistry (a writable
//     store that satisfies the EnrollmentResolver twokey.go reads), the flip PERMISSION
//     check (CanFlipEnrollment), and the audit-stamped Flip verb. It is the real backing
//     the v0 open-pool resolver stands in for, constructible + unit-tested against
//     synthetic fixtures (D50).
//   - DOES NOT OWN: a proto/RPC surface for enrollment (the M2 authoring surface, doc 15
//     §10 — out of scope; no contract change here), nor the IdP resolution of WHICH org
//     owner set the restriction (the org-policy posture is supplied to the registry; how
//     an org owner sets it is the M2 multi-org band's). It is the control-plane model the
//     enrollment RPC will drive when it lands, leaving the EnrollmentResolver seam shape
//     twokey.go consumes unchanged.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// ErrEnrollmentForbidden is the D56 PERMISSION refusal: a principal attempted to flip a
// repo's enrollment without the authority the org policy admits (a non-admin, or a
// repo admin under an org-owner restriction that narrowed authority to org admins). It
// is fail-closed — the same posture as the two-key refusal — so an unauthorized flip is
// refused and the enrollment setting is unchanged. It is DISTINCT from the create-path
// two-key refusal (ErrTwoKeyRefused): this is "you may not change WHETHER", that is
// "WHETHER is currently no".
var ErrEnrollmentForbidden = errors.New("sessions: enrollment flip forbidden (D56: repo admins may flip by default; org owners may restrict to org admins only)")

// ErrEnrollmentInvalid is the structural refusal of a malformed flip request: an empty
// repo, or a flip by an unidentified principal (an empty principal ID — there is no
// actor to attribute the control-plane act to). It is distinct from ErrEnrollmentForbidden
// (a well-formed request by an unauthorized actor) — a malformed request never reaches the
// authority check.
var ErrEnrollmentInvalid = errors.New("sessions: enrollment flip invalid (a repo and an identified flipping principal are required)")

// FlipActor is the principal attempting to flip a repo's enrollment, plus the role the
// authority check evaluates. It is the in-package projection of the IdP-resolved
// principal the enrollment RPC will carry — the actor's stable ID (for the audit fact)
// and the role set (the D56 authority). The registry verifies the role authority; it
// does not re-resolve the principal (the RPC boundary resolves the IdP subject → roles,
// the same way the launch gate resolves launching_user).
type FlipActor struct {
	// PrincipalID is the stable handle of the flipping principal (recorded on the
	// EnrollmentSetting as the audit fact of who last flipped it). Required.
	PrincipalID string
	// Roles is the actor's role set (D56 authority): RoleRepoAdmin flips by default,
	// RoleOrgAdmin flips under any posture. A principal may hold several roles; the
	// check passes if ANY held role is sufficient under the posture in force.
	Roles []store.PrincipalRole
}

// hasRole reports whether the actor holds role r (the membership test the authority
// check shares with store.Principal.HasRole, kept local so the FlipActor projection does
// not require a full store.Principal).
func (a FlipActor) hasRole(r store.PrincipalRole) bool {
	for _, have := range a.Roles {
		if have == r {
			return true
		}
	}
	return false
}

// CanFlipEnrollment is the D56 PERMISSION predicate — the single source of the "who may
// flip enrollment" rule, exposed so the enrollment RPC and the registry share ONE
// authority check (no open-coded role scan at the call site).
//
// The rule (D56: "repo admins by default; org-owner restrictable"):
//   - org admin (RoleOrgAdmin) may ALWAYS flip — org admin is strictly broader authority
//     than repo admin, so an org-owner restriction (which narrows TO org admins) never
//     excludes them.
//   - repo admin (RoleRepoAdmin) may flip ONLY when the org has NOT restricted enrollment
//     authority (orgRestricted == false) — the default. Under an org-owner restriction
//     (orgRestricted == true) a repo admin may NOT flip; only an org admin may.
//   - any other role (launcher/viewer/approver) may NEVER flip — enrollment is an admin
//     act, never self-serve by a launcher.
func CanFlipEnrollment(actor FlipActor, orgRestricted bool) bool {
	if actor.hasRole(store.RoleOrgAdmin) {
		return true // org admin flips under any posture (broader authority than repo admin).
	}
	if actor.hasRole(store.RoleRepoAdmin) {
		return !orgRestricted // repo admin flips ONLY when not org-restricted (the default).
	}
	return false // launcher/viewer/approver are not enrollment authorities (D56).
}

// EnrollmentSetting is the stored control-plane enrollment FACT for a repo (the D56
// first key's persisted shape). It records WHETHER the repo is enrolled (Enabled), who
// last flipped it and with what role (the audit fact + the authority the recorded act
// carried), the org-owner restriction posture in force at flip time, and when. It is the
// model the EnrollmentRegistry holds and projects onto the Enrollment value twokey.go
// reads at create step 1.
type EnrollmentSetting struct {
	// RepoID is the enrolled repo (the join key with the env config's RepoRef and the
	// create's RepoID). Required.
	RepoID string
	// Enabled is the D56 "whether" answer: true = the repo may run sessions (the first
	// key is present), false = enrollment was flipped OFF (the record is retained for the
	// audit trail of who enrolled it, but the first key reads as absent).
	Enabled bool
	// FlippedByPrincipal is the stable ID of the principal who last flipped this setting
	// (the audit fact; the actor whose authority the flip checked).
	FlippedByPrincipal string
	// FlippedByRole is the role the flipping principal exercised (RoleRepoAdmin or
	// RoleOrgAdmin — the D56 authority). Recorded so twokey.go's enrollment-authority
	// check reads the role the control-plane act actually carried, never re-derives it.
	FlippedByRole store.PrincipalRole
	// OrgRestricted is the org-owner restriction posture in force (D56 "org-owner
	// restrictable"): true = the org has narrowed enrollment authority to org admins.
	// Recorded on the setting so the create-time authority check (twokey.go) applies the
	// same posture the flip was made under.
	OrgRestricted bool
	// UpdatedAt is the wall-clock instant of the last flip (audit).
	UpdatedAt time.Time
}

// toEnrollment projects the stored setting onto the Enrollment value the
// EnrollmentResolver seam yields to twokey.go at create step 1. The Disabled field is
// the NEGATIVE of Enabled (zero-value enabled), and the authority fields carry the
// recorded flip role + restriction so the create-time check applies the posture the flip
// was made under.
func (s EnrollmentSetting) toEnrollment() Enrollment {
	return Enrollment{
		RepoID:              s.RepoID,
		EnrolledByPrincipal: s.FlippedByPrincipal,
		EnrolledByRole:      s.FlippedByRole,
		OrgRestricted:       s.OrgRestricted,
		Disabled:            !s.Enabled,
	}
}

// OrgRestrictionSource reports the org-owner enrollment-restriction posture for a repo's
// org (D56 "org-owner restrictable"). It is the seam the registry consults to learn
// whether an org owner has narrowed enrollment authority to org admins — supplied by the
// deployment (the v0 single-org posture is a constant; the M2 multi-org band resolves it
// per org through the IdP/org-policy boundary). A nil source is the default (unrestricted):
// repo admins may flip, the GitHub-App "select repositories" default.
type OrgRestrictionSource interface {
	// OrgRestrictsEnrollment reports whether the org owning repoID has restricted
	// enrollment authority to org admins only (true) or left it at the repo-admin default
	// (false). A fault is surfaced so the registry fails closed (it does NOT flip on an
	// unknown restriction posture — the authority check cannot be skipped).
	OrgRestrictsEnrollment(ctx context.Context, repoID string) (bool, error)
}

// unrestrictedOrg is the default OrgRestrictionSource: no org restricts enrollment (the
// repo-admin-by-default posture, the GitHub-App "select repositories" default). It is
// installed when the registry is constructed without an explicit source.
type unrestrictedOrg struct{}

func (unrestrictedOrg) OrgRestrictsEnrollment(context.Context, string) (bool, error) {
	return false, nil
}

// EnrollmentRegistry is the in-package WRITABLE enrollment model (the D56 first key's
// store): it holds the per-repo EnrollmentSetting, satisfies the EnrollmentResolver seam
// twokey.go reads at create step 1, and enforces the D56 flip permission on writes. It is
// the real backing the v0 open-pool resolver stands in for — a deployment wires this (or
// a future dialed M2 enrollment client) behind the same EnrollmentResolver seam, with no
// change to twokey.go. It is concurrency-safe (a control plane serves concurrent creates
// + the occasional flip).
type EnrollmentRegistry struct {
	mu       sync.RWMutex
	byRepo   map[string]EnrollmentSetting
	orgRules OrgRestrictionSource
	clock    func() time.Time
}

// NewEnrollmentRegistry builds an empty registry over an org-restriction source and a
// clock. A nil source defaults to unrestrictedOrg (repo-admin-by-default); a nil clock
// defaults to time.Now. An empty registry refuses every create's first key (no repo is
// enrolled until a flip enrolls it) — the fail-closed default the v0 open-pool stub
// deliberately relaxes for single-org deployments.
func NewEnrollmentRegistry(orgRules OrgRestrictionSource, clock func() time.Time) *EnrollmentRegistry {
	if orgRules == nil {
		orgRules = unrestrictedOrg{}
	}
	if clock == nil {
		clock = time.Now
	}
	return &EnrollmentRegistry{
		byRepo:   make(map[string]EnrollmentSetting),
		orgRules: orgRules,
		clock:    clock,
	}
}

// ResolveEnrollment satisfies the EnrollmentResolver seam (twokey.go's first key): it
// returns the stored setting projected onto an Enrollment, with ok=true when a setting
// exists for the repo (enrolled OR explicitly disabled — the create-time check reads the
// Disabled field), ok=false when no setting was ever recorded (never enrolled). A repo
// with no setting is the "not enrolled" first-key absence; a repo whose setting is
// disabled is also a first-key absence, but its record is retained for the audit trail.
func (r *EnrollmentRegistry) ResolveEnrollment(_ context.Context, repoID string) (Enrollment, bool, error) {
	repo := strings.TrimSpace(repoID)
	if repo == "" {
		return Enrollment{}, false, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byRepo[repo]
	if !ok {
		return Enrollment{}, false, nil
	}
	return s.toEnrollment(), true, nil
}

// Flip is the D56 permissioned ENROLLMENT write: an authorized actor sets a repo's
// enrollment to enabled (enroll) or disabled. It is the control-plane act that answers
// WHETHER, gated by the D56 permission model:
//
//  1. VALIDATE — a non-empty repo and an identified flipping principal, else
//     ErrEnrollmentInvalid (a malformed request never reaches the authority check).
//  2. RESTRICTION POSTURE — read the org's enrollment-restriction posture (the
//     OrgRestrictionSource). A fault here fails the flip closed (the authority check
//     cannot be evaluated against an unknown posture, so the flip is refused, surfaced
//     verbatim — NOT ErrEnrollmentForbidden, which is a decided "no").
//  3. AUTHORITY — CanFlipEnrollment(actor, restricted). An unauthorized actor is refused
//     ErrEnrollmentForbidden and the setting is UNCHANGED (fail-closed).
//  4. WRITE — persist the EnrollmentSetting with the audit fact (who flipped, with what
//     role, under which restriction posture, when). The recorded role is the SUFFICIENT
//     role the actor exercised (org-admin if held, else repo-admin) so the create-time
//     authority check reads the authority the act actually carried.
//
// It returns the resulting setting so the caller (the RPC handler / a test) can confirm
// the recorded state and audit fact.
func (r *EnrollmentRegistry) Flip(ctx context.Context, repoID string, actor FlipActor, enabled bool) (EnrollmentSetting, error) {
	repo := strings.TrimSpace(repoID)
	if repo == "" {
		return EnrollmentSetting{}, fmt.Errorf("%w: empty repo", ErrEnrollmentInvalid)
	}
	if strings.TrimSpace(actor.PrincipalID) == "" {
		return EnrollmentSetting{}, fmt.Errorf("%w: empty flipping principal (no actor to attribute the control-plane act to)", ErrEnrollmentInvalid)
	}

	// (2) RESTRICTION POSTURE — fail closed on an unknown posture.
	restricted, err := r.orgRules.OrgRestrictsEnrollment(ctx, repo)
	if err != nil {
		return EnrollmentSetting{}, fmt.Errorf("sessions: EnrollmentRegistry.Flip: resolve org restriction for repo %q: %w", repo, err)
	}

	// (3) AUTHORITY — fail closed on an unauthorized actor; the setting is unchanged.
	if !CanFlipEnrollment(actor, restricted) {
		return EnrollmentSetting{}, fmt.Errorf("%w: principal %q (roles %v) may not flip repo %q (org-restricted=%t)",
			ErrEnrollmentForbidden, actor.PrincipalID, actor.Roles, repo, restricted)
	}

	// (4) WRITE — record the SUFFICIENT role the actor exercised so the create-time
	// authority check reads the authority the act actually carried (org-admin is recorded
	// when held even outside a restriction, because it is the stronger authority).
	role := store.RoleRepoAdmin
	if actor.hasRole(store.RoleOrgAdmin) {
		role = store.RoleOrgAdmin
	}
	setting := EnrollmentSetting{
		RepoID:             repo,
		Enabled:            enabled,
		FlippedByPrincipal: strings.TrimSpace(actor.PrincipalID),
		FlippedByRole:      role,
		OrgRestricted:      restricted,
		UpdatedAt:          r.clock().UTC(),
	}
	r.mu.Lock()
	r.byRepo[repo] = setting
	r.mu.Unlock()
	return setting, nil
}

// Get returns the stored setting for a repo (ok=false when none recorded). It is the
// read-only inspection counterpart of Flip, for an RPC "is this repo enrolled?" query or
// a test assertion — distinct from ResolveEnrollment (the create-step-1 seam shape).
func (r *EnrollmentRegistry) Get(repoID string) (EnrollmentSetting, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byRepo[strings.TrimSpace(repoID)]
	return s, ok
}

// Compile-time proof the registry satisfies the create-step-1 first-key seam.
var _ EnrollmentResolver = (*EnrollmentRegistry)(nil)
