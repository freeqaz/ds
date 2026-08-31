// SPDX-License-Identifier: Apache-2.0

package policylog

// This file PROJECTS a resolved ask onto the identity-plane LOG-1 ask events
// (doc 16 §9, D45/D77): identityv1.AskIssued / AskApproved / AskDenied. It is the
// ATTRIBUTION half of the ask-routing surface — the routing entry (askroute_resolve.go)
// resolves WHO approves and WHERE the ask is dispatched; this stamps that approver
// onto the identity events so the audit/dashboard plane (ds-flowlog, LOG-5) sees
// the launching-user-or-org-admin attribution the §8.2 routing computed.
//
// It CONSUMES the FROZEN generated event types ONLY (identityv1.Ask*; boundaryv1.SessionRef
// is the join key per the frozen log_events shape) and NEVER edits proto. The events
// are projections, not a new contract:
//
//   - AskIssued — the ask was raised (no approver yet): SessionRef + the
//     resource kind/name the ask is about + the reserved D60 consent class.
//   - AskApproved — an approval, carrying ApproverPrincipal (doc 16 §8.2 "+approver"):
//     the launching user (allow-once) or the org-admin acceptor (allow-always, D45).
//   - AskDenied — a denial, carrying the denying ApproverPrincipal AND the D77
//     MachineReadableReason so retries fast-fail (the session-scoped deny memo,
//     D118 — this event underpins it; the memo's policy_log landing is RouteAskDecision's
//     deny leg, not re-declared here).
//
// fingerprint-only / metadata-only: these events carry the session join key, the
// resource metadata, the approver principal (an IdP-subject handle, never a
// credential), and a reason string — never any credential material (doc 16 §9).

import (
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// AskConsentClass returns the identity-plane consent-class tag for the boundary-side
// ask consent class. It maps boundaryv1.AskConsentClass (the reserved D60 tag the
// frozen AskUserRequest carries) onto identityv1.ConsentClass — the two mirror each
// other value-for-value (doc 14 §2b / doc 16 §9 OQ5, D60/D119). RESERVE/TAG ONLY:
// no population behavior is frozen; an unrecognized value maps to UNSPECIFIED so the
// projection never panics on a future tag.
func askConsentClass(c boundaryv1.AskConsentClass) identityv1.ConsentClass {
	switch c {
	case boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_METADATA:
		return identityv1.ConsentClass_CONSENT_CLASS_METADATA
	case boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_SESSION:
		return identityv1.ConsentClass_CONSENT_CLASS_SESSION
	case boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_WORKLOAD:
		return identityv1.ConsentClass_CONSENT_CLASS_WORKLOAD
	default:
		return identityv1.ConsentClass_CONSENT_CLASS_UNSPECIFIED
	}
}

// sessionRef builds the boundaryv1.SessionRef join key the identity events carry
// (the frozen log_events shape references the canonical boundary SessionRef). A
// resolved ask always carries a non-empty session (ResolveAskRouting fails closed on
// a missing one), so this is the single place the projection materializes the ref.
func sessionRef(sessionUUID string) *boundaryv1.SessionRef {
	return &boundaryv1.SessionRef{SessionUuid: sessionUUID}
}

// ProjectAskIssued projects a resolved ask onto identityv1.AskIssued (doc 16 §9):
// the ask was raised. It carries the session join key and the resource kind/name the
// ask is about (the boundary-side payload the identity plane tags, §8.2), plus the
// reserved D60 consent class. No approver is stamped — issuance precedes the decision.
func ProjectAskIssued(res AskResolution, consent boundaryv1.AskConsentClass) *identityv1.AskIssued {
	return &identityv1.AskIssued{
		SessionRef:   sessionRef(res.SessionUUID),
		ResourceKind: res.ResourceKind,
		ResourceName: res.ResourceName,
		ConsentClass: askConsentClass(consent),
	}
}

// ProjectAskApproved projects a resolved ask onto identityv1.AskApproved (doc 16
// §8.2 "+approver", §9): an approval STAMPED with the approver principal — the
// launching user for allow-once, the org-admin acceptor for allow-always (D45). The
// ApproverPrincipal is the IdP-subject handle the routing resolved
// (res.ApproverPrincipalID); the session join key and reserved D60 consent class
// ride along.
func ProjectAskApproved(res AskResolution, consent boundaryv1.AskConsentClass) *identityv1.AskApproved {
	return &identityv1.AskApproved{
		SessionRef:        sessionRef(res.SessionUUID),
		ApproverPrincipal: res.ApproverPrincipalID,
		ConsentClass:      askConsentClass(consent),
	}
}

// ProjectAskDenied projects a resolved ask onto identityv1.AskDenied (doc 16 §8.2,
// §9): a denial STAMPED with the denying approver principal AND the D77
// machine-readable reason, so retries fast-fail against the session-scoped deny memo
// (D118) without a re-prompt storm. The reason is a metadata string (never credential
// material); the session join key and reserved D60 consent class ride along.
func ProjectAskDenied(res AskResolution, machineReadableReason string, consent boundaryv1.AskConsentClass) *identityv1.AskDenied {
	return &identityv1.AskDenied{
		SessionRef:            sessionRef(res.SessionUUID),
		ApproverPrincipal:     res.ApproverPrincipalID,
		MachineReadableReason: machineReadableReason,
		ConsentClass:          askConsentClass(consent),
	}
}
