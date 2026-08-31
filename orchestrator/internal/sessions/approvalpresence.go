// SPDX-License-Identifier: Apache-2.0

// Production ApprovalPresence for the resume-authority gate (resumeauthority.go;
// doc 15 §3 note 3 + §4.3, doc 16 §8.2). resumeauthority.go declared the NARROW
// read seam the policy_breach (BIC) arm depends on — ApprovalPresence: "has a
// rung-2 human approval LANDED for this session?" — but left only a SYNTHETIC
// fake behind it. This file supplies the PRODUCTION read so a Resume driver can
// wire the policy_breach arm to real policy_log state instead of a test double.
//
// THE READ (consume the existing shape, declare nothing new). A landed rung-2
// human approval IS, on the policy_log seam, a session-scoped TTL'd ask-grant —
// a store.PolicyKindAskGrant row whose Actor is the approver (doc 15 §4.3
// ask-grant resume-on-answer gate; store/principalroles.go: "an approved ask is
// still a PolicyKindAskGrant policy_log row whose Actor is the approver"). So the
// production ApprovalPresence is exactly: does a CURRENTLY-VALID (un-expired as of
// now) PolicyKindAskGrant row exist for this session? That is the same liveness
// the policylog composer applies when it folds grants into a snapshot
// (composer.go ComposeAt: a grant gates new flows only while r.ExpiresAt.After(
// now)) and the same filter store.LiveGrants already implements.
//
// SHAPE (mirrors the orch8 narrow-read-interface + DI pattern, exactly as
// resumeauthority.go's header prescribes). The store package is FROZEN; this
// file adds no store method, column, or table. It depends on a one-method read
// SLICE of the existing store — liveGrantReader (just LiveGrants) — which both
// *store.Memory and *store.Postgres already satisfy, mirroring
// store.PolicyHeadSource composing a one-method slice over the existing
// ListPolicy. Time is dependency-injected behind a clock so the TTL check is
// pure and offline-testable; tests wire a synthetic fake reader + a fixed clock
// (D50), no live host / boundary / KVM / OpenBao dependency.
//
// FAIL-CLOSED / FAITHFUL-TO-THE-GATE. The gate (AuthorizeResume) treats a read
// ERROR as a denial (it cannot prove the approval landed) and a FALSE as a
// denial. This reader holds to that contract: it surfaces the store read error
// VERBATIM (never swallowing it into a false "no approval"), so the gate can
// distinguish a policy refusal from an infrastructure fault, and it reports a
// landed approval ONLY when at least one live (un-expired) ask-grant exists for
// the session. An expired grant is NOT a landed approval — the §8.2 resume is on
// a CURRENT answer, never a stale one.
//
// ADDITIVE / NEW FILE ONLY. This consumes the frozen attach-derived gate seam and
// the existing policy_log ask-grant shape; it edits no other sessions file and no
// store file.
//
// SELF-APPROVAL GUARD (01KV62D1KC; doc 16 §8.2). A live PolicyKindAskGrant row's
// Actor IS the approver's principal ID (store/principalroles.go: "an approved ask
// is still a PolicyKindAskGrant policy_log row whose Actor is the approver"). The
// liveness read above proves an approval is CURRENT, but not WHO approved — so on
// its own it would count a launching user (or a prompt-injected agent acting as
// that launching principal) approving its OWN policy_breach (BIC) park as a landed
// approval. doc 16 §8.2 makes the launching user the DEFAULT approver, so the role
// gate alone (Principal.MayApprove, which RoleLauncher satisfies) cannot close that
// gap. The §8.2 BIC resume is a rung-2 HUMAN-in-the-loop event: the approver must
// be a rung-2 approver (MayApprove) AND DISTINCT from the session's requestor /
// launching_user. This file enforces both, ADDITIVELY, via a NEW NARROW resolver
// seam (ApproverRankResolver) injected into LiveGrantApprovalPresence — maintainer approved
// the new-seam route over reopening the FROZEN store/principalroles.go (no store
// column, table, or method added; the resolver is backed in production by the
// existing exported store reads GetPrincipal+GetSessionLaunchingPrincipal, but is
// DEFINED here as the minimum surface the guard needs). When NO resolver is wired,
// the presence read keeps its prior behavior (a live grant counts) so the existing
// distinct-rung-2 presence contract stays green; a wired resolver TIGHTENS it.

package sessions

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// liveGrantReader is the NARROW read slice the production ApprovalPresence
// composes: just LiveGrants, the EXISTING store method that returns the
// non-expired (TTL-checked) PolicyKindAskGrant rows for a session as of a given
// instant (store/repository.go). Both *store.Memory and *store.Postgres satisfy
// it via the method they already export — the store package stays FROZEN, no
// method added — exactly as store.PolicyHeadSource is a one-method slice over the
// existing ListPolicy. Declaring the slice HERE (not threading the full
// store.Repository) keeps the policy_breach arm depending on the minimum surface
// it needs, the same discipline as twokey.go's envConfigReader and
// resumeauthority.go's ApprovalPresence.
type liveGrantReader interface {
	LiveGrants(ctx context.Context, sessionUUID string, now time.Time) ([]store.PolicyLogRow, error)
}

// ApproverRankResolver is the NEW NARROW seam the self-approval guard composes: it
// answers the two facts the §8.2 rung-2-human check needs about a live ask-grant —
// (1) does the grant's Actor (the approver principal ID, store/principalroles.go)
// resolve to a rung-2 human authorized to approve (Principal.MayApprove)? and (2)
// who is the session's requestor / launching_user the approver must be DISTINCT
// from? It is declared HERE (two small reads), not threaded as a store method, so
// the guard depends on the minimum surface it needs and the FROZEN store package
// stays untouched — the same discipline as liveGrantReader above and twokey.go's
// envConfigReader. In production both reads are the existing exported store reads
// (GetPrincipal → Principal.MayApprove for ApproverMayApprove; GetSessionLaunching-
// Principal for SessionRequestor), which *store.Memory and *store.Postgres already
// satisfy; tests wire a synthetic fake (D50).
//
// FAIL-CLOSED. Either read returning an error is surfaced VERBATIM by the guard
// (the gate cannot prove a DISTINCT rung-2 human approved, so it refuses and lets
// AuthorizeResume classify the fault) — never swallowed into a false "no approval"
// nor into a permissive "approved".
type ApproverRankResolver interface {
	// ApproverMayApprove reports whether actorPrincipalID resolves to a principal
	// authorized to approve an ask (Principal.MayApprove — rung-2 human: launcher /
	// approver / org-admin per D45). An unknown principal is NOT an approver
	// (mayApprove == false, nil error); an infrastructure fault is returned as err.
	ApproverMayApprove(ctx context.Context, actorPrincipalID string) (mayApprove bool, err error)
	// SessionRequestor returns the principal ID of the session's requestor /
	// launching_user (doc 16 §3.1/§3.2) — the identity the approver must be DISTINCT
	// from. An empty string means the session has no linked launching principal
	// (the nullable case); an infrastructure fault is returned as err.
	SessionRequestor(ctx context.Context, sessionUUID string) (requestorPrincipalID string, err error)
}

// principalRankStore is the NARROW read slice of the FROZEN store that the
// production ApproverRankResolver composes — the two EXISTING exported reads, no
// store method added: GetPrincipal (→ Principal.MayApprove, the rung-2 role gate
// in principalroles.go) and GetSessionLaunchingPrincipal (the §3.2 requestor
// link). Both *store.Memory and *store.Postgres already satisfy it, mirroring how
// liveGrantReader is a one-method slice over the existing LiveGrants.
type principalRankStore interface {
	GetPrincipal(ctx context.Context, id string) (store.Principal, error)
	GetSessionLaunchingPrincipal(ctx context.Context, sessionUUID string) (string, error)
}

// StoreApproverRankResolver is the PRODUCTION ApproverRankResolver over the frozen
// store reads. It backs the §8.2 self-approval guard with the real principal-role
// and launching_user lookups WITHOUT touching store/principalroles.go: the rung-2
// check is the EXISTING Principal.MayApprove predicate (D45 launcher / approver /
// org-admin), and the requestor is the EXISTING session → launching_principal link.
// Tests use a synthetic fake (D50) instead; this is the production wiring a Resume
// driver hands NewLiveGrantApprovalPresenceWithRank.
type StoreApproverRankResolver struct {
	store principalRankStore
}

// NewStoreApproverRankResolver builds the production resolver over a store slice
// (*store.Memory or *store.Postgres both satisfy it).
func NewStoreApproverRankResolver(s principalRankStore) *StoreApproverRankResolver {
	return &StoreApproverRankResolver{store: s}
}

// ensure the production resolver satisfies the guard's narrow seam.
var _ ApproverRankResolver = (*StoreApproverRankResolver)(nil)

// ApproverMayApprove resolves actorPrincipalID through the frozen GetPrincipal read
// and applies the EXISTING Principal.MayApprove role gate (principalroles.go). An
// UNKNOWN principal (store.ErrNotFound) is NOT an approver — false, nil error (the
// guard simply does not count that grant); any OTHER read fault is surfaced so the
// guard stays fail-closed.
func (r *StoreApproverRankResolver) ApproverMayApprove(ctx context.Context, actorPrincipalID string) (bool, error) {
	if r == nil || r.store == nil {
		return false, fmt.Errorf("sessions: ApproverRankResolver: no principal store wired (fail-closed)")
	}
	p, err := r.store.GetPrincipal(ctx, actorPrincipalID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil // unknown principal is not a rung-2 approver
		}
		return false, fmt.Errorf("sessions: ApproverRankResolver: principal lookup %s: %w", actorPrincipalID, err)
	}
	return p.MayApprove(), nil
}

// SessionRequestor returns the session's launching_user via the frozen
// GetSessionLaunchingPrincipal read ("" = the nullable no-link case). A read fault
// is surfaced so the guard stays fail-closed.
func (r *StoreApproverRankResolver) SessionRequestor(ctx context.Context, sessionUUID string) (string, error) {
	if r == nil || r.store == nil {
		return "", fmt.Errorf("sessions: ApproverRankResolver: no principal store wired (fail-closed)")
	}
	id, err := r.store.GetSessionLaunchingPrincipal(ctx, sessionUUID)
	if err != nil {
		return "", fmt.Errorf("sessions: ApproverRankResolver: launching-principal lookup for session %s: %w", sessionUUID, err)
	}
	return id, nil
}

// LiveGrantApprovalPresence is the PRODUCTION ApprovalPresence (resumeauthority.go)
// over the policy_log live-grant read. It answers "has a landed rung-2 human
// approval landed for this session?" as "does a currently-valid PolicyKindAskGrant
// row exist for it?", reading through the narrow liveGrantReader slice of the
// store and gating liveness on an injected clock. It satisfies sessions.Approval-
// Presence, so a Resume driver wires it straight into AuthorizeResume's approvals
// argument for the policy_breach (BIC) arm.
type LiveGrantApprovalPresence struct {
	reader liveGrantReader
	now    func() time.Time
	// ranks, when non-nil, TIGHTENS HasLandedApproval with the §8.2 self-approval
	// guard: a live ask-grant counts ONLY when its Actor (the approver) is a rung-2
	// human (MayApprove) DISTINCT from the session's requestor / launching_user. A
	// nil ranks preserves the prior behavior (any live grant counts), so this is
	// strictly additive over the original presence contract.
	ranks ApproverRankResolver
}

// NewLiveGrantApprovalPresence builds the production ApprovalPresence over a
// liveGrantReader (the existing store.LiveGrants read; *store.Memory and
// *store.Postgres both satisfy it) and a clock. A nil clock defaults to
// time.Now, so a production wiring need only hand the store. The reader is
// REQUIRED — a nil reader cannot prove any approval landed; rather than panic at
// read time, it is reported as a read fault (fail-closed) on every call.
func NewLiveGrantApprovalPresence(reader liveGrantReader, now func() time.Time) *LiveGrantApprovalPresence {
	if now == nil {
		now = time.Now
	}
	return &LiveGrantApprovalPresence{reader: reader, now: now}
}

// NewLiveGrantApprovalPresenceWithRank builds the production ApprovalPresence with
// the §8.2 self-approval guard ENGAGED: in addition to the live-grant read, the
// injected ApproverRankResolver is consulted so a live ask-grant counts as a landed
// approval ONLY when its Actor (the approver) is a rung-2 human (MayApprove)
// DISTINCT from the session's requestor / launching_user. This is the production
// wiring that closes the self-approval gap (a launching user / prompt-injected
// agent approving its own policy_breach park). It is additive over
// NewLiveGrantApprovalPresence — passing a nil ranks yields the same object that
// constructor builds (the guard is skipped, prior behavior preserved). Time is the
// same injected clock; a nil clock defaults to time.Now.
func NewLiveGrantApprovalPresenceWithRank(reader liveGrantReader, ranks ApproverRankResolver, now func() time.Time) *LiveGrantApprovalPresence {
	p := NewLiveGrantApprovalPresence(reader, now)
	p.ranks = ranks
	return p
}

// ensure the production reader satisfies the gate's narrow seam.
var _ ApprovalPresence = (*LiveGrantApprovalPresence)(nil)

// HasLandedApproval reports whether a genuine, currently-valid rung-2 human
// approval has LANDED for the session — the doc 16 §8.2 "resume on answer" event
// — by asking the policy_log for the session's live (non-expired as of now)
// PolicyKindAskGrant rows. TRUE iff at least one such grant exists; a store read
// error is surfaced VERBATIM (the gate treats it as a fail-closed denial and
// classifies it as a fault, distinct from a policy refusal). An empty session
// key cannot scope an approval — it is refused fail-closed as a read fault rather
// than silently asking the store for "the empty session", and a nil reader is the
// same: the presence of an approval cannot be proven, so it is reported as a
// fault, never a false "no approval".
//
// store.LiveGrants already applies BOTH filters this read needs — Kind ==
// PolicyKindAskGrant && SessionUUID == this session && (ExpiresAt == nil ||
// ExpiresAt.After(now)) — the same liveness the policylog composer's ComposeAt
// uses to fold grants. So an EXPIRED grant never counts (the §8.2 resume is on a
// current answer, not a stale one), and this reader adds no parallel filter that
// could drift from the composer.
//
// SELF-APPROVAL GUARD. When an ApproverRankResolver is wired (the production
// NewLiveGrantApprovalPresenceWithRank path), presence of a live grant is NOT
// enough: at least one live grant must have an Actor (the approver, per
// principalroles.go) that is a rung-2 human (ApproverMayApprove) DISTINCT from the
// session's requestor / launching_user (SessionRequestor). This closes the §8.2
// self-approval gap — a launching user, or a prompt-injected agent acting as the
// launching principal, cannot approve its own policy_breach park. A resolver read
// error is surfaced VERBATIM (fail-closed). With NO resolver wired, the prior
// contract holds unchanged (any live grant counts).
func (p *LiveGrantApprovalPresence) HasLandedApproval(ctx context.Context, sessionUUID string) (bool, error) {
	if p == nil || p.reader == nil {
		return false, fmt.Errorf("sessions: ApprovalPresence: no policy_log reader wired (fail-closed: cannot prove a landed approval)")
	}
	if sessionUUID == "" {
		return false, fmt.Errorf("sessions: ApprovalPresence: empty session UUID (fail-closed: cannot scope a landed-approval read)")
	}
	grants, err := p.reader.LiveGrants(ctx, sessionUUID, p.now())
	if err != nil {
		// Surface the store fault verbatim — the gate (AuthorizeResume) wraps it in
		// ErrResumeApprovalReadFailed so a driver can classify a fault vs a refusal.
		return false, fmt.Errorf("sessions: ApprovalPresence: live ask-grant read for session %s: %w", sessionUUID, err)
	}
	// A landed rung-2 approval IS a live PolicyKindAskGrant row (principalroles.go);
	// LiveGrants already TTL-filters, so any returned row is a currently-valid
	// approval. With no rank resolver wired, presence is enough — the original
	// contract: one live grant counts (the gate needs presence, not a count).
	if p.ranks == nil {
		return len(grants) > 0, nil
	}
	// SELF-APPROVAL GUARD: a live grant counts only when its Actor (the approver) is
	// a rung-2 human DISTINCT from the session's requestor / launching_user.
	return p.hasDistinctRungTwoApprover(ctx, sessionUUID, grants)
}

// hasDistinctRungTwoApprover reports whether any of the session's live ask-grants
// was approved by a rung-2 human (ApproverMayApprove) DISTINCT from the session's
// requestor / launching_user — the doc 16 §8.2 self-approval guard. It is reached
// only when a resolver is wired. The requestor is resolved ONCE (a session has one
// launching_user); each live grant's Actor is then rank-checked until a qualifying
// approver is found. A resolver read error is surfaced VERBATIM so the gate stays
// fail-closed (it cannot prove a distinct rung-2 human approved).
//
// A grant whose Actor is empty cannot be attributed to an approver, so it never
// satisfies the guard (fail-closed). An approver Actor equal to the requestor is a
// SELF-approval and is skipped; an Actor that does not resolve to a MayApprove
// principal is not rung-2 and is skipped. Only a DISTINCT-and-MayApprove Actor
// counts.
func (p *LiveGrantApprovalPresence) hasDistinctRungTwoApprover(ctx context.Context, sessionUUID string, grants []store.PolicyLogRow) (bool, error) {
	requestor, err := p.ranks.SessionRequestor(ctx, sessionUUID)
	if err != nil {
		return false, fmt.Errorf("sessions: ApprovalPresence: requestor resolve for session %s: %w", sessionUUID, err)
	}
	for _, g := range grants {
		approver := g.Actor
		if approver == "" {
			continue // unattributed grant — cannot prove a rung-2 human approved
		}
		if requestor != "" && approver == requestor {
			continue // self-approval — the launching user approving its own park
		}
		mayApprove, err := p.ranks.ApproverMayApprove(ctx, approver)
		if err != nil {
			return false, fmt.Errorf("sessions: ApprovalPresence: approver-rank resolve for %s (session %s): %w", approver, sessionUUID, err)
		}
		if mayApprove {
			return true, nil // a rung-2 human DISTINCT from the requestor approved
		}
	}
	return false, nil
}
