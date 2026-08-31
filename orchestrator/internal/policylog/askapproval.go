package policylog

// This file is the ORCHESTRATOR-SIDE CALLER of the approver-attribution seam
// (store.Principal.MayApprove + store.AskApproval.AskGrantRow, doc 16 §8.2/§9,
// D45). The ask-grant write path (doc 15 §4.3) lands an approved ask as a
// session-scoped TTL'd allow grant on policy_log; this caller is the gate +
// attribution stamp around that append:
//
//  1. AUTHORIZE: refuse a principal that is not a permitted approver
//     (Principal.MayApprove — the §3.2 role-gate: launcher / approver / org-admin
//     per D45). A non-approver never reaches the append.
//  2. ATTRIBUTE: build the ask-grant policy_log row from a store.AskApproval so
//     the approver lands in the row Actor (the existing per-row attribution
//     column, D36 — no new column, additive over the frozen ask-grant shape),
//     carrying the session scope, matched rule, and TTL.
//
// It adds NO contract surface: approvals still ride the existing
// PolicyKindAskGrant append (records.go), the same machinery the POL-5 allow
// path uses. This is the gate+attribution the ask routing (doc 15 §4.3 / the
// policy service) wraps the append in; the ask ROUTING itself is out of scope.

import (
	"context"
	"fmt"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// policyAppender is the narrow append-seam this caller needs: the policy_log
// append (store.Repository.AppendPolicy). Dependency-injected as an interface so
// the ask-approval path depends only on the one method it consumes, and either
// store impl or a test fake satisfies it.
type policyAppender interface {
	AppendPolicy(ctx context.Context, row store.PolicyLogRow) (store.PolicyLogRow, error)
}

// ErrNotApprover is returned by ApproveAsk when the principal presenting the
// approval is not authorized to approve (store.Principal.MayApprove == false).
// It is the role-gate refusal: the ask path rejects the approval before any
// policy_log row is written, so a non-approver never produces an ask-grant.
var ErrNotApprover = fmt.Errorf("policylog: principal may not approve ask-a-human requests (D45 approver-authorization)")

// ApproveAsk is the ask-approval write path (doc 15 §4.3): given the approver
// PRINCIPAL, the session the grant is scoped to, the matched allow rule (D45
// scope), and the grant TTL + reserved consent class, it GATES on the
// approver's role and, if authorized, appends the attributed ask-grant row to
// policy_log.
//
// Authorization (step 1): approver.MayApprove() is the §3.2 role-gate — only a
// launcher / approver / org-admin may approve (D45). A principal holding none of
// those roles is refused with ErrNotApprover and NO row is written.
//
// Attribution (step 2): the approved ask is projected through
// store.AskApproval.AskGrantRow, which stamps the approver's principal ID into
// the row Actor (the audit attribution column, D36) and carries the session
// scope + TTL. The append assigns the seq (the single policy version namespace);
// the returned row carries it. payload is the grant body the ask path composed
// (matched rule + scope + reserved consent class encoded there, the caller's to
// fill); this path wires the attribution onto it.
func ApproveAsk(
	ctx context.Context,
	appender policyAppender,
	approver store.Principal,
	sessionUUID string,
	rule string,
	expiresAt store.OptTime,
	consent store.ConsentClass,
	payload []byte,
) (store.PolicyLogRow, error) {
	if !approver.MayApprove() {
		return store.PolicyLogRow{}, ErrNotApprover
	}
	approval := store.AskApproval{
		ApproverPrincipalID: approver.ID,
		SessionUUID:         sessionUUID,
		Rule:                rule,
		ExpiresAt:           expiresAt,
		Consent:             consent,
	}
	row := approval.AskGrantRow(payload)
	appended, err := appender.AppendPolicy(ctx, row)
	if err != nil {
		return store.PolicyLogRow{}, fmt.Errorf("append ask-grant for session %s: %w", sessionUUID, err)
	}
	return appended, nil
}
