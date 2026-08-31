// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"time"
)

// This file carries the D118 DENY-MEMO storage shape (doc 16 §8.2 deny
// semantics, round-4 ratification packet §6.4). It is the SYMMETRIC counterpart
// to the POL-5 ask-grant ALLOW shape in principalroles.go: where an APPROVED ask
// lands a session-scoped TTL'd allow grant on policy_log (AskApproval →
// AskGrantRow → PolicyKindAskGrant), a DENIED ask lands a session-scoped TTL'd
// DENY MEMO on the SAME policy_log under the SAME single seq namespace (D36) so a
// retry FAST-FAILS against the recorded decision instead of triggering a
// re-prompt storm (D77: the deny carries a machine-readable reason, in-band).
//
// It is ADDITIVE over the frozen store shapes (mirroring the principalroles.go
// additive precedent) and needs NO migration: PolicyKindDenyMemo rows ride the
// existing 0002_policy_log.sql columns (kind, actor, session_uuid, expires_at,
// payload). It adds NO column, NO table, and NO new SQL — LiveDenyMemos reuses
// the existing sqlLiveGrants query parameterized on the deny-memo kind.
//
// Lifecycle (D72/D73): the deny memo is DERIVED state. It is swept by the D72
// sweep and DIES WITH THE SESSION on the ask-grant flush — it does NOT take the
// D72/D73 session-lifecycle exemption that long-lived control rows carry. It is
// session-scoped and TTL'd exactly like the ask-grant it mirrors.
//
// Scope: this is the storage SHAPE + the two concrete read methods only. The
// deny WRITE path (gate on the denier's MayApprove, then append) lives with the
// ask routing in internal/policylog (denymemo.go there); this file is the
// storage-shape contract that write path builds the deny-memo row against.

// PolicyKindDenyMemo tags a session-scoped deny artifact on policy_log (D118).
// It rides the single seq namespace (D36) exactly like PolicyKindAskGrant; the
// only difference is the kind tag and that it records a DENIAL (the D77
// machine-readable reason rides the payload), never an allow. It is additive
// over the records.go PolicyKind set — no schema change.
const PolicyKindDenyMemo PolicyKind = "deny_memo"

// DenyMemo is the doc 16 §8.2 deny-decision shape: the denier principal that
// rejected the ask (→ row Actor, the D36 audit attribution column), the session
// the memo is scoped to, the matched rule the denial targets (the D45 scope, the
// same field the allow path records), the D77 machine-readable reason a retry
// fast-fails on, and the TTL (the memo dies with the session). It is the typed
// value the deny path builds a deny-memo policy_log row from — NOT a new
// persisted record. DenyMemoRow projects it onto the PolicyKindDenyMemo row that
// already carries denier attribution via Actor.
//
// It is the SYMMETRIC counterpart of AskApproval (principalroles.go): same write
// path, same per-row attribution column, same session-scope + TTL fields; the
// reason is the deny-specific addition and rides the existing payload, so the
// shape stays additive over the frozen policy_log columns.
//
// RESERVED (M4, D61): a single denier per memo (the denial is one reject-event),
// mirroring AskApproval's 1:approver shape so the D61 team-routing seam extends
// both additively.
type DenyMemo struct {
	DenierPrincipalID string  // the principal that denied (→ row Actor, D36 audit column)
	SessionUUID       string  // the session the memo is scoped to (§4.3, dies with the session)
	Rule              string  // the matched rule the denial targets (D45 scope)
	Reason            string  // the D77 machine-readable reason a retry fast-fails on
	ExpiresAt         OptTime // the memo TTL; the memo dies with the session (D72 sweep)
}

// DenyMemoRow projects a DenyMemo onto the policy_log deny-memo row that records
// it (records.go PolicyLogRow / PolicyKindDenyMemo). The DENIER lands in Actor —
// the existing per-row attribution column (D36: actor recorded on every row) —
// so denier attribution rides the shape the audit trail already carries, with NO
// schema change, exactly as AskApproval.AskGrantRow stamps the approver.
//
// The D77 machine-readable reason rides the payload the caller passes (the deny
// path encodes the rule + reason there); this projection wires the attribution +
// TTL + session-scope onto the row, and the seq is assigned by AppendPolicy. The
// TTL is COPIED, never aliased, so a later mutation of the caller's OptTime
// cannot retroactively change a written row (mirrors AskGrantRow).
func (d DenyMemo) DenyMemoRow(payload []byte) PolicyLogRow {
	row := PolicyLogRow{
		Kind:        PolicyKindDenyMemo,
		Actor:       d.DenierPrincipalID, // denier attribution via the audit Actor (D36)
		SessionUUID: d.SessionUUID,
		Payload:     payload,
	}
	if d.ExpiresAt.V != nil {
		t := *d.ExpiresAt.V
		row.ExpiresAt = &t
	}
	return row
}

// LiveDenyMemos returns the non-expired deny-memo rows for a session as of now,
// in seq order — the read a retry consults to FAST-FAIL against a recorded
// denial (D118) without re-prompting. It is the SYMMETRIC counterpart of
// LiveGrants: same predicate (session-scoped, not-yet-expired), parameterized on
// PolicyKindDenyMemo instead of PolicyKindAskGrant. An expired memo is excluded
// exactly like an expired ask-grant — the memo dies with the session (D72).
//
// It is a concrete additive method on *Memory (NOT a new Repository interface
// member): the deny path reads it through the concrete store, so adding it does
// not reopen the frozen Repository surface.
func (m *Memory) LiveDenyMemos(ctx context.Context, sessionUUID string, now time.Time) ([]PolicyLogRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PolicyLogRow, 0)
	for _, r := range m.policy {
		if r.Kind != PolicyKindDenyMemo || r.SessionUUID != sessionUUID {
			continue
		}
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue // expired — the memo died with (or before) the session
		}
		out = append(out, clonePolicy(r))
	}
	return out, nil
}

// LiveDenyMemos is the Postgres leg of the deny-memo read, SYMMETRIC with
// (*Postgres).LiveGrants and REUSING the existing sqlLiveGrants query: that query
// already parameterizes the kind on $2, so the deny-memo read is the same SQL
// with PolicyKindDenyMemo passed instead of PolicyKindAskGrant — no new SQL const
// (no edit to postgres_sql.go), no new table, no migration. The session-scope +
// not-yet-expired predicate and the seq ordering are identical to the ask-grant
// read; only the kind tag differs.
func (p *Postgres) LiveDenyMemos(ctx context.Context, sessionUUID string, now time.Time) ([]PolicyLogRow, error) {
	rows, err := p.db.QueryContext(ctx, sqlLiveGrants, sessionUUID, string(PolicyKindDenyMemo), now)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	return scanPolicyRows(rows)
}
