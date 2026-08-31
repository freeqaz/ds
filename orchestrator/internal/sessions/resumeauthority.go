// SPDX-License-Identifier: Apache-2.0

// Resume-authority enforcement for SUSPENDED(reason) (doc 15 §3 note 3 + §4.3;
// doc 16 §8.2). This file is the PRODUCTION decision the credfu6 e2e smoke (LEG
// B, assurance/e2e/lifecycle_smoke_test.go) proved only in-process: the §3 split
// resume authorities, enforced fail-closed before the orchestrator drives a
// SUSPENDED─►RESUMING edge.
//
// THE GAP THIS CLOSES. transition_table.go models the §3 state GRAPH only — its
// header puts the SUSPENDED reason taxonomy (user|policy_breach|rebalance, D35/
// D77) and the resume authority that taxonomy carries explicitly OUT OF SCOPE
// (reason/host are field-borne refinements, not separate state nodes). The
// reconciler that drives Resume therefore had nothing keying the resume edge on
// the suspension's reason: a policy_breach (BIC) park could auto-traverse
// SUSPENDED─►RESUMING with no human in the loop. This file supplies the missing
// production gate — a PURE decision keyed on the FROZEN attach.v1.SuspendReason
// — that a Resume driver consults before traversing the edge.
//
// THE CONTRACT (consume, never re-declare):
//   - The reason enum is the FROZEN attach.v1.SuspendReason — SUSPEND_REASON_USER
//     (1) | SUSPEND_REASON_POLICY_BREACH (2) | SUSPEND_REASON_REBALANCE (3),
//     consumed via proto/gen/go (the one legal cross-tree import, D80). This file
//     does NOT introduce a parallel reason type.
//   - doc 15 §3 note 3: "split resume authorities (user → user; policy_breach →
//     human approval; rebalance → scheduler)" — policy_breach NARROWED to D77's
//     genuine-threat classes (the genuine rung-2 BIC suspension).
//   - doc 16 §8.2: "resume authority for BIC suspensions is human approval
//     (SUSPENDED(reason), D35)" — a parked genuine rung-2 ask resumes ON ANSWER,
//     never timing out into allow or kill. THE KEY ASSERTION: a policy_breach
//     suspension must NOT auto-traverse the §3 SUSPENDED─►RESUMING edge without a
//     LANDED rung-2 human approval (an ApproveAsk-style allow grant on the
//     policy_log seam, doc 15 §4.3 ask-grant resume-on-answer gate).
//
// SHAPE (mirrors the orch8 ApproveAsk/store read-interface seam pattern). The
// authorization itself is a PURE function — given (reason, the authority the
// resume requestor presents, and whether a landed human-approval grant exists for
// the policy_breach arm) it returns permit/deny. The one piece that must touch
// the world — "has a rung-2 approval LANDED for this session?" — is
// DEPENDENCY-INJECTED behind a NARROW read interface (ApprovalPresence), exactly
// as policylog.ApproveAsk injects its append seam and store.PolicyHead composes a
// one-method read slice. A Resume driver wires the real policy_log read (a
// PolicyKindAskGrant lookup over store.ListPolicy); tests wire a synthetic fake
// (D50). No live host / boundary / KVM / OpenBao dependency; the decision is
// in-process and offline.
//
// FAIL-CLOSED. The default for an unrecognized / UNSPECIFIED reason confers NO
// authority (a resume can never be admitted), and a policy_breach with no landed
// approval is DENIED — never a silent allow. An approval-presence read ERROR is
// also a denial (the gate cannot prove the approval landed, so it refuses),
// surfaced to the caller so the driver can distinguish a refusal from a fault.
//
// ADDITIVE / NEW FILE ONLY. This adds no state, edge, or contract surface: it
// consumes the frozen enum and the existing policy_log ask-grant shape, and it
// does not edit transition_table.go or any other sessions file.

package sessions

import (
	"context"
	"errors"
	"fmt"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// ResumeAuthority is WHO may carry a SUSPENDED(reason) session back across the §3
// SUSPENDED─►RESUMING edge — the doc 15 §3 note 3 split, modeled as a small
// closed set so a resume attempt by the WRONG authority is a structural refusal
// (the policy_breach key assertion). It is the production sibling of the e2e
// smoke's in-process resumeAuthority; it is NOT a wire type and NOT a
// re-declaration of any frozen proto enum — it is the orchestrator's local model
// of resume authority, derived FROM the frozen attach.v1.SuspendReason.
type ResumeAuthority int

const (
	// ResumeAuthorityNone is the fail-closed default: no authority can carry the
	// resume. It is what an UNSPECIFIED / unrecognized reason maps to (a SUSPENDED
	// state never legally carries UNSPECIFIED), so an unmapped reason can never be
	// resumed rather than silently allowed.
	ResumeAuthorityNone ResumeAuthority = iota
	// ResumeAuthorityUser is the launching user — the authority a user-reason
	// (SUSPEND_REASON_USER) suspension resumes on.
	ResumeAuthorityUser
	// ResumeAuthorityHumanApproval is a genuine rung-2 human approval — the
	// authority a policy_breach (BIC, SUSPEND_REASON_POLICY_BREACH) suspension
	// resumes on (doc 16 §8.2). It additionally requires a LANDED ask-grant.
	ResumeAuthorityHumanApproval
	// ResumeAuthorityScheduler is the fleet scheduler — the authority a rebalance
	// (SUSPEND_REASON_REBALANCE) suspension resumes on.
	ResumeAuthorityScheduler
)

// String renders a ResumeAuthority for traces and refusal messages. The zero
// value renders "none" (the fail-closed default).
func (a ResumeAuthority) String() string {
	switch a {
	case ResumeAuthorityUser:
		return "user"
	case ResumeAuthorityHumanApproval:
		return "human-approval"
	case ResumeAuthorityScheduler:
		return "scheduler"
	default:
		return "none"
	}
}

// RequiredResumeAuthority maps a FROZEN attach.v1.SuspendReason to the resume
// authority doc 15 §3 note 3 assigns it: user → user; policy_breach → human
// approval (the §8.2 BIC contract); rebalance → scheduler. An UNSPECIFIED reason
// (the proto3 enum zero value, never a legal SUSPENDED state) and any unrecognized
// value confer NO authority — a fail-closed default rather than a silent allow.
// This is a PURE function over the frozen enum; it stores no parallel reason field
// that could drift.
func RequiredResumeAuthority(reason attachv1.SuspendReason) ResumeAuthority {
	switch reason {
	case attachv1.SuspendReason_SUSPEND_REASON_USER:
		return ResumeAuthorityUser
	case attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH:
		return ResumeAuthorityHumanApproval
	case attachv1.SuspendReason_SUSPEND_REASON_REBALANCE:
		return ResumeAuthorityScheduler
	default:
		return ResumeAuthorityNone
	}
}

// ApprovalPresence is the NARROW read seam the policy_breach arm depends on: does
// a LANDED rung-2 human-approval ask-grant exist for this session? It is the
// production-side equivalent of the e2e smoke's suspension.approved gate, made a
// dependency-injected read so the decision stays pure and offline-testable.
//
// It is declared here (one method, session-scoped) so the gate adds no method to
// any store interface — mirroring store.PolicyHeadSource (a one-method read slice
// over the existing ListPolicy) and the policylog.ApproveAsk seam. A Resume driver
// wires the real policy_log read: a PolicyKindAskGrant lookup over the session's
// scope (store.ListPolicy filtered to the session's ask-grant rows, TTL-checked).
// Tests wire a synthetic fake (D50). HasLandedApproval reports TRUE only when a
// genuine, currently-valid (un-expired) approval grant has LANDED — the §8.2
// "resume on answer" event — and an error when the read itself fails (which the
// decision treats as a denial: the gate cannot prove the approval landed).
type ApprovalPresence interface {
	HasLandedApproval(ctx context.Context, sessionUUID string) (bool, error)
}

// ResumeRequest is the input to a resume-authorization decision: the suspension's
// FROZEN reason, the authority the resume requestor presents, and the session the
// resume is scoped to (the key the policy_breach arm checks for a landed approval).
// The required authority is DERIVED from Reason — never carried as a separate field
// that could drift from it.
type ResumeRequest struct {
	// Reason is the frozen attach.v1.SuspendReason the session was suspended under.
	Reason attachv1.SuspendReason
	// PresentedAuthority is who is attempting the resume (user / human-approval /
	// scheduler). It must match the authority the reason demands.
	PresentedAuthority ResumeAuthority
	// SessionUUID scopes the policy_breach arm's landed-approval lookup. It is
	// required for the policy_breach arm (the gate refuses an empty key there) and
	// ignored for the other arms.
	SessionUUID string
}

// ResumeDecision is the outcome of AuthorizeResume: whether the resume is permitted
// to traverse the §3 SUSPENDED─►RESUMING edge, the authority the suspension's reason
// required, and (on a denial) a human-readable reason. Permitted == false leaves the
// session parked at §3 SUSPENDED with no edge traversed.
type ResumeDecision struct {
	// Permitted reports whether the resume may traverse SUSPENDED─►RESUMING.
	Permitted bool
	// Required is the authority the suspension's frozen reason demanded (derived,
	// for the caller's audit/trace).
	Required ResumeAuthority
	// Reason is a human-readable denial explanation when Permitted is false; empty
	// when permitted.
	Reason string
}

// ErrResumeApprovalReadFailed wraps an ApprovalPresence read error: the gate could
// not prove a landed approval, so it DENIES (fail-closed). It is surfaced so a
// Resume driver can distinguish a policy refusal (Permitted=false, nil error) from
// an infrastructure fault (this error) and retry/escalate accordingly.
var ErrResumeApprovalReadFailed = fmt.Errorf("sessions: resume-authority gate: landed-approval read failed (fail-closed deny)")

// AuthorizeResume is the production resume-authorization gate (doc 15 §3 note 3 +
// §4.3; doc 16 §8.2). It is a PURE decision over the request plus the injected
// ApprovalPresence read; it traverses NO §3 edge and mutates no state — a Resume
// driver consults it and, only on Permitted, drives SUSPENDED─►RESUMING.
//
// The rules, fail-closed:
//
//  1. AUTHORITY MATCH. The presented authority must be the one the suspension's
//     frozen reason demands (RequiredResumeAuthority). A mismatch — or an
//     UNSPECIFIED / unrecognized reason, which demands ResumeAuthorityNone that no
//     requestor can present — is a denial.
//  2. POLICY_BREACH HUMAN-APPROVAL GATE. When the required authority is
//     human-approval (the policy_breach / BIC arm), a genuine rung-2 approval must
//     have LANDED for the session — the §8.2 "resume on answer" gate. The injected
//     ApprovalPresence is consulted; a missing approval is a denial, and a read
//     ERROR is a denial wrapping ErrResumeApprovalReadFailed (the gate cannot prove
//     the approval, so it refuses). The lookup requires a non-empty SessionUUID;
//     an empty key is a denial (the gate cannot scope the approval check).
//
// The other arms (user, scheduler) admit on the authority match alone — their
// authority IS the gate; no landed-approval read is performed for them (so a nil
// ApprovalPresence is safe for a non-policy_breach request).
//
// THE KEY ASSERTION: a policy_breach suspension resumed with anything other than a
// LANDED human approval returns Permitted=false — the §3 SUSPENDED─►RESUMING edge
// does not auto-traverse without the §8.2 human-approval authority.
func AuthorizeResume(ctx context.Context, in ResumeRequest, approvals ApprovalPresence) (ResumeDecision, error) {
	required := RequiredResumeAuthority(in.Reason)
	dec := ResumeDecision{Required: required}

	// (1) An unmapped / UNSPECIFIED reason demands ResumeAuthorityNone — no
	// authority can satisfy it, so the resume can never be admitted (fail-closed).
	if required == ResumeAuthorityNone {
		dec.Reason = fmt.Sprintf("no resume authority for suspend reason %v (fail-closed: a SUSPENDED state never legally carries an unspecified reason)", in.Reason)
		return dec, nil
	}

	// (1) Authority match: the presented authority must be exactly the one the
	// frozen reason demands. A mismatch parks the session at SUSPENDED.
	if in.PresentedAuthority != required {
		dec.Reason = fmt.Sprintf("resume authority mismatch: reason %v requires %s, requestor presented %s", in.Reason, required, in.PresentedAuthority)
		return dec, nil
	}

	// (2) The policy_breach (BIC) arm additionally requires a LANDED rung-2 human
	// approval (doc 16 §8.2 resume-on-answer gate). The other arms admit on the
	// authority match alone.
	if required == ResumeAuthorityHumanApproval {
		if in.SessionUUID == "" {
			dec.Reason = "policy_breach resume requires a session-scoped landed human approval, but no session UUID was provided (fail-closed)"
			return dec, nil
		}
		if approvals == nil {
			dec.Reason = "policy_breach resume requires a landed human approval, but no approval-presence reader was wired (fail-closed)"
			return dec, nil
		}
		landed, err := approvals.HasLandedApproval(ctx, in.SessionUUID)
		if err != nil {
			dec.Reason = fmt.Sprintf("policy_breach resume: landed-approval read failed for session %s (fail-closed deny)", in.SessionUUID)
			// Wrap BOTH the sentinel (so a driver can classify a fault vs a policy
			// refusal via errors.Is(err, ErrResumeApprovalReadFailed)) AND the
			// underlying read error (so the original cause stays in the chain).
			return dec, errors.Join(
				fmt.Errorf("%w: session %s", ErrResumeApprovalReadFailed, in.SessionUUID),
				err,
			)
		}
		if !landed {
			dec.Reason = fmt.Sprintf("policy_breach resume denied: no landed rung-2 human approval for session %s (doc 16 §8.2: BIC resume on answer only)", in.SessionUUID)
			return dec, nil
		}
	}

	dec.Permitted = true
	return dec, nil
}
