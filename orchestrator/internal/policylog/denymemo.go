// SPDX-License-Identifier: Apache-2.0

package policylog

// This file is the DENY-MEMO WRITE+READ path (doc 16 §8.2 deny semantics, D118,
// round-4 ratification packet §6.4): the SYMMETRIC counterpart to the ask-grant
// ALLOW path in askapproval.go. Where ApproveAsk lands an APPROVED ask as a
// session-scoped TTL'd allow grant on policy_log, DenyAsk lands a DENIED ask as a
// session-scoped TTL'd DENY MEMO on the SAME policy_log under the SAME seq
// namespace (D36) so a retry FAST-FAILS against the recorded decision instead of
// triggering a re-prompt storm.
//
// It is the exact mirror of ApproveAsk's two steps:
//
//  1. AUTHORIZE: refuse a principal that is not a permitted denier
//     (store.Principal.MayApprove — the §3.2 role-gate, D45; the same role that
//     authorizes an approval authorizes a denial — both are the human's recorded
//     ask DECISION). A non-approver never reaches the append, so a stray principal
//     can neither grant nor record a deny on the policy stream.
//  2. ATTRIBUTE: build the deny-memo policy_log row from a store.DenyMemo so the
//     DENIER lands in the row Actor (the existing per-row attribution column, D36
//     — no new column, additive over the frozen policy_log shape), carrying the
//     session scope, matched rule, the D77 machine-readable reason (in the
//     payload), and the TTL (the memo dies with the session, D72 sweep).
//
// It adds NO contract surface: the deny memo rides the existing AppendPolicy verb
// and the existing PolicyKindDenyMemo policy_log row — the same machinery the
// POL-5 allow path uses. The READ direction (a retry consulting the live memo to
// fast-fail) is LiveDenyMemo here, reading the concrete store's LiveDenyMemos.

import (
	"context"
	"fmt"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// ErrDeniedByMemo is the D77 machine-readable fast-fail a retry hits when a live
// session-scoped deny memo already records the decision (D118). It wraps the
// stored reason so a retry path can branch on the sentinel (errors.Is) AND
// surface the reason — the deny is recorded once and every retry fast-fails on it
// rather than re-prompting the human.
var ErrDeniedByMemo = fmt.Errorf("policylog: ask denied by a live session-scoped deny memo (D118 fast-fail)")

// denyMemoReader is the narrow read-seam the fast-fail check needs: the
// concrete-store live-deny-memo read (store.(*Memory|*Postgres).LiveDenyMemos).
// Dependency-injected as an interface so the read path depends only on the one
// method it consumes, and either concrete store impl or a test fake satisfies it.
// It is deliberately NOT the frozen store.Repository surface (LiveDenyMemos is a
// concrete additive method, not a Repository member), so consuming it reopens
// nothing.
type denyMemoReader interface {
	LiveDenyMemos(ctx context.Context, sessionUUID string, now time.Time) ([]store.PolicyLogRow, error)
}

// DenyAsk is the deny-memo write path (doc 16 §8.2, D118): given the DENIER
// PRINCIPAL, the session the memo is scoped to, the matched rule the denial
// targets (D45 scope), the D77 machine-readable reason, and the memo TTL, it
// GATES on the denier's role and, if authorized, appends the attributed deny-memo
// row to policy_log. It is the exact mirror of ApproveAsk.
//
// Authorization (step 1): denier.MayApprove() is the §3.2 role-gate (D45) — the
// SAME gate the allow path uses, since a deny is the same human ask-DECISION
// authority. A principal holding none of the approver roles is refused with
// ErrNotApprover and NO row is written (symmetric with the allow refusal: a
// stray principal records neither an allow nor a deny on the policy stream).
//
// Attribution (step 2): the denial is projected through store.DenyMemo.DenyMemoRow,
// which stamps the denier's principal ID into the row Actor (the audit
// attribution column, D36) and carries the session scope + TTL. The append
// assigns the seq (the single policy version namespace); the returned row carries
// it. payload is the deny body the deny path composed (the matched rule + the D77
// machine-readable reason encoded there, the caller's to fill); this path wires
// the attribution onto it.
func DenyAsk(
	ctx context.Context,
	appender policyAppender,
	denier store.Principal,
	sessionUUID string,
	rule string,
	reason string,
	expiresAt store.OptTime,
	payload []byte,
) (store.PolicyLogRow, error) {
	if !denier.MayApprove() {
		// Symmetric with the allow refusal: a non-approver records no decision —
		// neither an allow grant nor a deny memo — on the policy stream.
		return store.PolicyLogRow{}, ErrNotApprover
	}
	memo := store.DenyMemo{
		DenierPrincipalID: denier.ID,
		SessionUUID:       sessionUUID,
		Rule:              rule,
		Reason:            reason,
		ExpiresAt:         expiresAt,
	}
	row := memo.DenyMemoRow(payload)
	appended, err := appender.AppendPolicy(ctx, row)
	if err != nil {
		return store.PolicyLogRow{}, fmt.Errorf("append deny-memo for session %s: %w", sessionUUID, err)
	}
	return appended, nil
}

// LiveDenyMemo is the deny-memo READ path (D118 fast-fail): it surfaces a live
// session-scoped deny memo so a retry FAST-FAILS with the D77 machine-readable
// reason instead of re-prompting the human. It reads the concrete store's
// LiveDenyMemos (the memo-derived-state read) as of now and:
//
//   - returns (zeroRow, false, nil) when NO live memo exists — the retry is free
//     to proceed to a fresh ask;
//   - returns (memoRow, true, ErrDeniedByMemo-wrapping-the-reason) when a live
//     memo exists — the retry fast-fails on the recorded denial, carrying the row
//     (for attribution/seq) and the machine-readable reason. The error wraps
//     ErrDeniedByMemo so a caller can branch on the sentinel via errors.Is.
//
// When several live memos exist for the session (successive denials), the LAST
// (highest-seq, latest decision) is surfaced — the most recent recorded denial
// governs the fast-fail.
func LiveDenyMemo(ctx context.Context, r denyMemoReader, sessionUUID string, now time.Time) (store.PolicyLogRow, bool, error) {
	memos, err := r.LiveDenyMemos(ctx, sessionUUID, now)
	if err != nil {
		return store.PolicyLogRow{}, false, fmt.Errorf("read live deny memos for session %s: %w", sessionUUID, err)
	}
	if len(memos) == 0 {
		return store.PolicyLogRow{}, false, nil
	}
	memo := memos[len(memos)-1] // latest recorded denial governs
	return memo, true, fmt.Errorf("%w: %s", ErrDeniedByMemo, denyMemoReason(memo))
}

// denyMemoReason extracts the D77 machine-readable reason a retry fast-fails on.
// The reason rides the row payload (the deny body the deny path composed); when
// the payload is empty the memo still fast-fails, just without a reason string.
func denyMemoReason(row store.PolicyLogRow) string {
	return string(row.Payload)
}
