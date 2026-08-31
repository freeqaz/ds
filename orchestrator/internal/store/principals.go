package store

import "time"

// This file carries the minimal human-principal record and its role vocabulary
// (doc 16 §3.2, D45/D56/D57). A Principal is the control-plane row a workload
// identity's `launching_user` claim resolves to — the doc 04 §5 attribution
// promise ("per-workload identity, attributed to the launching user") given a
// persisted referent. It is DELIBERATELY MINIMAL: the full seat/viewer billing
// taxonomy lives with billing/multiplayer (D57/D61). This record reserves only
// what M4 multiplayer needs so it is not retrofitted onto an agent-only model —
// the IdP subject, the org, and the role set — plus the linkage shape (the
// session→principal reference) so attribution has somewhere to land.
//
// Out of scope here (residual, NOT implemented): MintWorkloadIdentity resolving
// launching_user from a Principal (the identity mint shim is a separate task)
// and ask-event approver attribution (the ask path is not built). This file is
// the STORAGE layer those consumers will read once they land.

// PrincipalRole is one role in the doc 16 §3.2 minimal role vocabulary
// (D45/D56/D57). It is the Go mirror of the 0006_principals.sql role CHECK; the
// store rejects writes of any role outside this set (ErrInvalid), the same way
// SuspendReason rejects an out-of-taxonomy suspend reason (records.go) and
// SessionState rejects an out-of-vocabulary lifecycle state (types.go).
//
// The vocabulary is exactly the five §3.2 roles. Editing this set without the
// matching §3.2 + 0006 CHECK change reopens the role contract (D45/D56/D57);
// the conformance suite's role-CHECK-parity case is what forbids the drift
// (in-memory Valid() must agree with the SQL CHECK token-for-token).
type PrincipalRole string

const (
	// RoleLauncher may launch sessions (the default human authority; the
	// `launching_user` claim resolves to a principal that holds this role).
	RoleLauncher PrincipalRole = "launcher"
	// RoleViewer is read-only spectate (D61 N-reader; never counts as attended).
	RoleViewer PrincipalRole = "viewer"
	// RoleApprover may approve ask-a-human requests (D45 approver attribution on
	// ask events — the consuming attribution path is out of scope here).
	RoleApprover PrincipalRole = "approver"
	// RoleOrgAdmin is org-level administration (D45 allow-always escalation,
	// D56 two-key enrollment, D84 org-credential registration authority).
	RoleOrgAdmin PrincipalRole = "org-admin"
	// RoleRepoAdmin is repo-scoped administration (D56 enrollment posture).
	RoleRepoAdmin PrincipalRole = "repo-admin"
)

// principalRoles is the package copy of the legal role set, in §3.2 reading
// order. It is the single source the SQL CHECK in 0006 mirrors; the conformance
// suite asserts membership parity in both directions.
var principalRoles = []PrincipalRole{
	RoleLauncher,
	RoleViewer,
	RoleApprover,
	RoleOrgAdmin,
	RoleRepoAdmin,
}

// PrincipalRoles returns the store's legal role vocabulary as a fresh slice
// (callers may not mutate the package copy).
func PrincipalRoles() []PrincipalRole {
	out := make([]PrincipalRole, len(principalRoles))
	copy(out, principalRoles)
	return out
}

// Valid reports whether r is one of the five §3.2 roles. It is the exact Go
// mirror of the 0006_principals.sql per-role CHECK — the same membership the
// SQL `role IN (...)` constraint enforces — so an out-of-vocabulary role is
// rejected identically at the in-memory layer and at the database layer.
func (r PrincipalRole) Valid() bool {
	switch r {
	case RoleLauncher, RoleViewer, RoleApprover, RoleOrgAdmin, RoleRepoAdmin:
		return true
	default:
		return false
	}
}

// Principal is the doc 16 §3.2 minimal human-principal record. The IdP subject +
// org pair is the unique business key (a single human, asserted by the org's
// IdP, is one principal in that org — the §11.2 "OIDC subject → launching_user"
// mapping); the same IdP subject in two orgs is two principals. Roles is the
// principal's role SET — a human can hold several roles at once (launcher +
// approver is the common pair), so roles are a set, not a single column. The
// record carries no seat/viewer billing fields (D57/D61, out of scope) by
// design — adding them is a billing/multiplayer migration, not a change here.
type Principal struct {
	ID         string          // stable handle; the session linkage references this
	IdPSubject string          // the OIDC subject claim (doc 16 §11.2)
	Org        string          // the org the subject is asserted within
	Roles      []PrincipalRole // the role set (D45/D56/D57); each must be Valid()

	DisplayName string // optional human-readable label (audit/UI convenience)

	CreatedAt time.Time
	UpdatedAt time.Time
}

// clonePrincipal deep-copies a Principal so the store never hands out an alias
// of its own Roles slice (mirrors cloneSession / clonePolicy in helpers.go).
func clonePrincipal(p Principal) Principal {
	p.Roles = cloneRoles(p.Roles)
	return p
}

func cloneRoles(r []PrincipalRole) []PrincipalRole {
	if r == nil {
		return nil
	}
	out := make([]PrincipalRole, len(r))
	copy(out, r)
	return out
}

// rolesEqual reports whether two role sets are identical as ORDERED sequences
// (the idempotent-re-create check; the create path stores the caller's order
// verbatim, so order-sensitive equality is the right idempotency test).
func rolesEqual(a, b []PrincipalRole) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// validateRoles checks every role in the set against the §3.2 vocabulary and
// reports the first out-of-vocabulary role as ErrInvalid (the create/role-update
// guard, mirrored by the SQL CHECK). An empty set is legal — a principal with no
// roles yet is a valid record (roles are granted after creation).
func validateRoles(roles []PrincipalRole) error {
	for _, role := range roles {
		if !role.Valid() {
			return wrap(ErrInvalid, "unknown principal role %q", role)
		}
	}
	return nil
}
