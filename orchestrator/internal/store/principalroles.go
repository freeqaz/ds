package store

// This file carries the ask-event APPROVER-ATTRIBUTION shape (doc 16 §8/§9, D45)
// and the small role-authorization predicates the principal record's §3.2 role
// vocabulary (principals.go) exists to answer. It is ADDITIVE over the existing
// policy_log / ask-grant shapes (records.go: PolicyKindAskGrant rows under the
// single seq namespace, D36) — it adds NO column and NO table: an approved ask is
// still a PolicyKindAskGrant policy_log row whose Actor is the approver. This
// file names that mapping so the approver attribution is a typed value the ask
// path constructs, not an ad-hoc Actor string, and reserves the D119 consent-class
// field shape (round-4 packet §6) so retention policy can bind later without a
// proto or schema change.
//
// Scope: this confirms/extends the SHAPE only. The ask ROUTING and the ApproveAsk
// RPC live with doc 15 §4.3 / the policy service (out of scope here); this file is
// the storage-shape contract those consumers build the approver row against.

// MayApprove reports whether a principal is authorized to approve an ask-a-human
// request (doc 16 §8 approver-authorization). The default approver is the
// launching user (RoleLauncher), and RoleApprover is the dedicated approval role;
// RoleOrgAdmin may also approve, since allow-always escalation lands on org-admin
// acceptance per D45. A principal holding none of these roles may not approve.
//
// This is the role-gate the ask path checks before stamping a principal as the
// approver of a grant; it is deliberately a pure predicate over the §3.2 role set
// (no store round-trip) so the ask path can authorize against an already-resolved
// principal. The D61 team-level routing seam (M4) is reserved, not decided here.
func (p Principal) MayApprove() bool {
	for _, r := range p.Roles {
		switch r {
		case RoleLauncher, RoleApprover, RoleOrgAdmin:
			return true
		}
	}
	return false
}

// HasRole reports whether the principal holds role r. It is the membership test
// the role-gated paths (approval, enrollment, org administration) share, so role
// checks are one predicate rather than open-coded slice scans.
func (p Principal) HasRole(r PrincipalRole) bool {
	for _, have := range p.Roles {
		if have == r {
			return true
		}
	}
	return false
}

// ConsentClass tags an ask event with its D60/D119 consent class (round-4 packet
// §6, ratified 2026-06-12 as D119): ask events "carry a D60 consent-class field
// from the Stage-0 freeze, so retention policy can bind later without a proto
// change." This is the RESERVED field shape — the vocabulary is intentionally
// open here (the canonical D60 class set is owned elsewhere); the store records
// whatever class the ask path stamps, defaulting to unspecified, so the column
// exists from the start and a later retention policy binds against a field that
// was always present.
type ConsentClass string

// ConsentClassUnspecified is the zero value: no consent class stamped yet. It is
// the default an ask-grant carries until the ask path classifies it.
const ConsentClassUnspecified ConsentClass = ""

// AskApproval is the doc 16 §9 approver-attribution shape for an APPROVED ask:
// the approver principal that accepted the ask, the session the grant is scoped
// to, the matched allow target (D45 grant scope), and the reserved D119
// consent class. It is the typed value the ask path builds an ask-grant
// policy_log row from — NOT a new persisted record. AskGrantRow turns it into the
// PolicyKindAskGrant row that already carries approver attribution via Actor.
//
// RESERVED (M4, D61): a single approver per grant (the approval is one
// accept-event). Team-level routing — multiple eligible approvers, escalation
// chains — is the D61 M4 seam, reserved not designed; this shape stays 1:approver
// so that seam extends it additively.
type AskApproval struct {
	ApproverPrincipalID string       // the principal that approved (→ row Actor)
	SessionUUID         string       // the session the grant is scoped to (§4.3)
	Rule                string       // the allow target / matched rule (D45 scope)
	ExpiresAt           OptTime      // the grant TTL; the grant dies with the session
	Consent             ConsentClass // reserved D119 consent class (defaults unspecified)
}

// AskGrantRow projects an AskApproval onto the policy_log ask-grant row that
// records it (records.go PolicyLogRow / PolicyKindAskGrant). The APPROVER lands in
// Actor — the existing per-row attribution column (D36: actor recorded on every
// row) — so approver attribution rides the shape the audit trail already carries,
// with NO schema change. payload carries the grant body the ask path composed
// (the matched rule, scope, and the reserved consent class are the caller's to
// encode there); this projection wires the attribution + TTL + session-scope onto
// the row, and the seq is assigned by AppendPolicy.
//
// The reserved Consent class is carried on the AskApproval value (and into the
// grant body the ask path encodes); it is NOT a separate policy_log column in v0,
// so this stays additive over the frozen 0002_policy_log.sql shape. When a later
// retention policy needs the class as a first-class column, that is an additive
// migration against a field that was always present on the value shape.
func (a AskApproval) AskGrantRow(payload []byte) PolicyLogRow {
	row := PolicyLogRow{
		Kind:        PolicyKindAskGrant,
		Actor:       a.ApproverPrincipalID, // approver attribution via the audit Actor
		SessionUUID: a.SessionUUID,
		Payload:     payload,
	}
	if a.ExpiresAt.V != nil {
		t := *a.ExpiresAt.V
		row.ExpiresAt = &t
	}
	return row
}
