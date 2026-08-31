// SPDX-License-Identifier: Apache-2.0

// Tests for the production ApprovalPresence (approvalpresence.go): the policy_log
// live ask-grant read behind the resume-authority gate's policy_breach (BIC) arm
// (resumeauthority.go; doc 15 §4.3, doc 16 §8.2). A landed rung-2 human approval
// IS a currently-valid PolicyKindAskGrant row for the session; these prove the
// reader reports presence on a live grant, FALSE on none / only-expired, and a
// VERBATIM fault on a store read error — and that it composes with AuthorizeResume
// end to end. The store read is dependency-injected behind a SYNTHETIC fake (D50);
// no live host / boundary / KVM / OpenBao dependency.

package sessions

import (
	"context"
	"errors"
	"testing"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// fakeLiveGrantReader is the SYNTHETIC liveGrantReader (D50): an in-process
// fixture of session → ask-grant rows, plus an optional injected read error. It
// applies the SAME TTL filter store.LiveGrants applies (Kind == PolicyKindAskGrant,
// SessionUUID matches, non-expired as of now) so the production reader is exercised
// against a faithful stand-in for the real store without touching any store. It
// records the (session, now) it was asked for so a test can assert the clock and
// scope key the reader passed down.
type fakeLiveGrantReader struct {
	rows map[string][]store.PolicyLogRow // session UUID → its ask-grant rows
	err  error
	// calls records each (session, now) the production reader asked about.
	calls []liveGrantCall
}

type liveGrantCall struct {
	session string
	now     time.Time
}

func (f *fakeLiveGrantReader) LiveGrants(_ context.Context, sessionUUID string, now time.Time) ([]store.PolicyLogRow, error) {
	f.calls = append(f.calls, liveGrantCall{session: sessionUUID, now: now})
	if f.err != nil {
		return nil, f.err
	}
	var out []store.PolicyLogRow
	for _, r := range f.rows[sessionUUID] {
		if r.Kind != store.PolicyKindAskGrant {
			continue
		}
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue // expired — never a landed approval (doc 16 §8.2: resume on a CURRENT answer)
		}
		out = append(out, r)
	}
	return out, nil
}

// askGrant builds a PolicyKindAskGrant row for a session expiring at exp (nil =
// no TTL, always live).
func askGrant(session string, exp *time.Time) store.PolicyLogRow {
	return store.PolicyLogRow{
		Kind:        store.PolicyKindAskGrant,
		Actor:       "approver@org",
		SessionUUID: session,
		ExpiresAt:   exp,
	}
}

// askGrantBy is askGrant with an explicit approver Actor — used by the §8.2
// self-approval-guard tests to set WHO approved the grant.
func askGrantBy(session, approver string, exp *time.Time) store.PolicyLogRow {
	g := askGrant(session, exp)
	g.Actor = approver
	return g
}

// fakeApproverRankResolver is the SYNTHETIC ApproverRankResolver (D50): an
// in-process fixture mapping principal IDs to whether they MayApprove (rung-2
// human) and sessions to their requestor / launching_user, plus optional injected
// read errors. It stands in for the production reads (GetPrincipal →
// Principal.MayApprove; GetSessionLaunchingPrincipal) with NO store dependency.
type fakeApproverRankResolver struct {
	mayApprove    map[string]bool   // principal ID → MayApprove (absent ⇒ false / not an approver)
	requestor     map[string]string // session UUID → requestor principal ID (absent ⇒ "")
	mayApproveErr error
	requestorErr  error
}

func (f *fakeApproverRankResolver) ApproverMayApprove(_ context.Context, actorPrincipalID string) (bool, error) {
	if f.mayApproveErr != nil {
		return false, f.mayApproveErr
	}
	return f.mayApprove[actorPrincipalID], nil
}

func (f *fakeApproverRankResolver) SessionRequestor(_ context.Context, sessionUUID string) (string, error) {
	if f.requestorErr != nil {
		return "", f.requestorErr
	}
	return f.requestor[sessionUUID], nil
}

func clockAt(t time.Time) func() time.Time { return func() time.Time { return t } }

// TestLiveGrantApprovalPresence_LandedWhenLiveGrant: a currently-valid ask-grant
// for the session IS a landed approval.
func TestLiveGrantApprovalPresence_LandedWhenLiveGrant(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrant("sess-bic", &exp)},
	}}
	p := NewLiveGrantApprovalPresence(reader, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if !landed {
		t.Fatal("expected a live ask-grant to count as a landed approval")
	}
	if len(reader.calls) != 1 || reader.calls[0].session != "sess-bic" {
		t.Fatalf("expected one read scoped to sess-bic, got %+v", reader.calls)
	}
	if !reader.calls[0].now.Equal(now) {
		t.Fatalf("reader must be asked at the injected clock %v, got %v", now, reader.calls[0].now)
	}
}

// TestLiveGrantApprovalPresence_NotLandedWhenNoGrant: no ask-grant for the
// session is NOT a landed approval (fail-closed false, nil error).
func TestLiveGrantApprovalPresence_NotLandedWhenNoGrant(t *testing.T) {
	now := time.Unix(1000, 0)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{}}
	p := NewLiveGrantApprovalPresence(reader, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if landed {
		t.Fatal("expected no ask-grant to mean no landed approval")
	}
}

// TestLiveGrantApprovalPresence_ExpiredGrantNotLanded: an EXPIRED ask-grant is
// not a landed approval — the §8.2 resume is on a CURRENT answer, mirroring the
// composer's ExpiresAt.After(now) liveness gate.
func TestLiveGrantApprovalPresence_ExpiredGrantNotLanded(t *testing.T) {
	now := time.Unix(1000, 0)
	expired := now.Add(-time.Minute) // already past
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrant("sess-bic", &expired)},
	}}
	p := NewLiveGrantApprovalPresence(reader, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if landed {
		t.Fatal("expected an expired ask-grant to NOT count as a landed approval")
	}
}

// TestLiveGrantApprovalPresence_NowGatesLiveness: the SAME grant flips from landed
// to not-landed as the injected clock crosses its TTL — the reader's liveness is
// gated by now, not baked in.
func TestLiveGrantApprovalPresence_NowGatesLiveness(t *testing.T) {
	exp := time.Unix(1000, 0)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrant("sess-bic", &exp)},
	}}

	before := NewLiveGrantApprovalPresence(reader, clockAt(exp.Add(-time.Second)))
	landed, err := before.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("before TTL: %v", err)
	}
	if !landed {
		t.Fatal("expected grant live just before its TTL")
	}

	after := NewLiveGrantApprovalPresence(reader, clockAt(exp.Add(time.Second)))
	landed, err = after.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("after TTL: %v", err)
	}
	if landed {
		t.Fatal("expected grant dead just after its TTL")
	}
}

// TestLiveGrantApprovalPresence_OtherSessionGrantIgnored: a live grant for a
// DIFFERENT session does not satisfy this session — the read is session-scoped.
func TestLiveGrantApprovalPresence_OtherSessionGrantIgnored(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-other": {askGrant("sess-other", &exp)},
	}}
	p := NewLiveGrantApprovalPresence(reader, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if landed {
		t.Fatal("a grant for another session must not count for this one")
	}
}

// TestLiveGrantApprovalPresence_ReadErrorSurfaced: a store read fault is surfaced
// VERBATIM (wrapped, not swallowed into a false) so the gate can classify it as a
// fault rather than a refusal.
func TestLiveGrantApprovalPresence_ReadErrorSurfaced(t *testing.T) {
	now := time.Unix(1000, 0)
	wantErr := errors.New("policy_log unreachable")
	reader := &fakeLiveGrantReader{err: wantErr}
	p := NewLiveGrantApprovalPresence(reader, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err == nil {
		t.Fatal("expected a read fault to be surfaced, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the underlying read error in the chain, got %v", err)
	}
	if landed {
		t.Fatal("a read fault must report landed=false (fail-closed)")
	}
}

// TestLiveGrantApprovalPresence_EmptySessionFault: an empty session key cannot
// scope an approval — it is a fail-closed fault, never a silent store read for the
// empty session.
func TestLiveGrantApprovalPresence_EmptySessionFault(t *testing.T) {
	now := time.Unix(1000, 0)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{}}
	p := NewLiveGrantApprovalPresence(reader, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "")
	if err == nil {
		t.Fatal("expected an empty session key to be a fault, got nil")
	}
	if landed {
		t.Fatal("empty session must report landed=false (fail-closed)")
	}
	if len(reader.calls) != 0 {
		t.Fatalf("an empty session must not hit the store, got %d calls", len(reader.calls))
	}
}

// TestLiveGrantApprovalPresence_NilReaderFault: a nil reader cannot prove a landed
// approval — it is a fail-closed fault on every call, never a panic or a false.
func TestLiveGrantApprovalPresence_NilReaderFault(t *testing.T) {
	p := NewLiveGrantApprovalPresence(nil, clockAt(time.Unix(1000, 0)))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err == nil {
		t.Fatal("expected a nil reader to be a fault, got nil")
	}
	if landed {
		t.Fatal("a nil reader must report landed=false (fail-closed)")
	}
}

// TestLiveGrantApprovalPresence_NilClockDefaultsToNow: a nil clock defaults to
// time.Now so a production wiring need only hand the store. A grant with no TTL is
// always live, so this is deterministic without pinning the wall clock.
func TestLiveGrantApprovalPresence_NilClockDefaultsToNow(t *testing.T) {
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrant("sess-bic", nil)}, // no TTL: always live
	}}
	p := NewLiveGrantApprovalPresence(reader, nil)

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if !landed {
		t.Fatal("a no-TTL grant must be live under the default clock")
	}
	if len(reader.calls) != 1 {
		t.Fatalf("expected one read, got %d", len(reader.calls))
	}
	if reader.calls[0].now.IsZero() {
		t.Fatal("default clock must pass a real time, not the zero value")
	}
}

// TestLiveGrantApprovalPresence_SatisfiesGateInterface pins that the production
// reader is a drop-in ApprovalPresence for the resume-authority gate (the seam
// resumeauthority.go declared) — both as a static assignment and end to end
// through AuthorizeResume's policy_breach arm.
func TestLiveGrantApprovalPresence_SatisfiesGateInterface(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrant("sess-bic", &exp)},
	}}
	var approvals ApprovalPresence = NewLiveGrantApprovalPresence(reader, clockAt(now))

	// A policy_breach resume with a live landed approval traverses the gate.
	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "sess-bic",
	}, approvals)
	if err != nil {
		t.Fatalf("AuthorizeResume: unexpected error: %v", err)
	}
	if !dec.Permitted {
		t.Fatalf("expected the policy_breach resume permitted with a live approval, got denial: %s", dec.Reason)
	}
}

// TestLiveGrantApprovalPresence_GateDeniesWithoutLandedApproval: end to end, a
// policy_breach resume with NO live approval is denied by the gate (Permitted=false,
// nil error) — the production reader wires the real fail-closed behavior.
func TestLiveGrantApprovalPresence_GateDeniesWithoutLandedApproval(t *testing.T) {
	now := time.Unix(1000, 0)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{}} // none landed
	approvals := NewLiveGrantApprovalPresence(reader, clockAt(now))

	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "sess-bic",
	}, approvals)
	if err != nil {
		t.Fatalf("AuthorizeResume: unexpected error: %v", err)
	}
	if dec.Permitted {
		t.Fatal("expected denial with no landed approval")
	}
}

// TestLiveGrantApprovalPresence_GateClassifiesReadFault: end to end, a store read
// fault propagates through the gate as ErrResumeApprovalReadFailed (a fault, not a
// plain refusal) — the production reader surfaces it for the driver to classify.
func TestLiveGrantApprovalPresence_GateClassifiesReadFault(t *testing.T) {
	now := time.Unix(1000, 0)
	reader := &fakeLiveGrantReader{err: errors.New("policy_log unreachable")}
	approvals := NewLiveGrantApprovalPresence(reader, clockAt(now))

	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "sess-bic",
	}, approvals)
	if err == nil {
		t.Fatal("expected the read fault to surface through the gate, got nil")
	}
	if !errors.Is(err, ErrResumeApprovalReadFailed) {
		t.Fatalf("expected ErrResumeApprovalReadFailed in the chain, got %v", err)
	}
	if dec.Permitted {
		t.Fatal("a read fault must leave the resume denied (fail-closed)")
	}
}

// TestLiveGrantApprovalPresence_RealMemoryStore wires the production reader over a
// REAL *store.Memory (not a fake) to prove it composes with the actual LiveGrants
// implementation: appended live ask-grant ⇒ landed; only-expired ⇒ not landed.
func TestLiveGrantApprovalPresence_RealMemoryStore(t *testing.T) {
	now := time.Unix(1000, 0)
	mem := store.NewMemoryClock(func() time.Time { return now })
	ctx := context.Background()

	exp := now.Add(time.Hour)
	if _, err := mem.AppendPolicy(ctx, askGrant("sess-real", &exp)); err != nil {
		t.Fatalf("AppendPolicy: %v", err)
	}

	p := NewLiveGrantApprovalPresence(mem, clockAt(now))
	landed, err := p.HasLandedApproval(ctx, "sess-real")
	if err != nil {
		t.Fatalf("HasLandedApproval: %v", err)
	}
	if !landed {
		t.Fatal("expected a live ask-grant in *store.Memory to count as landed")
	}

	// Past the TTL, the same row is no longer a landed approval.
	pastTTL := NewLiveGrantApprovalPresence(mem, clockAt(exp.Add(time.Second)))
	landed, err = pastTTL.HasLandedApproval(ctx, "sess-real")
	if err != nil {
		t.Fatalf("HasLandedApproval past TTL: %v", err)
	}
	if landed {
		t.Fatal("expected the expired ask-grant to NOT count as landed")
	}
}

// ============================================================================
// §8.2 self-approval guard (01KV62D1KC): with an ApproverRankResolver wired, a
// live ask-grant counts as a landed approval ONLY when its Actor (the approver) is
// a rung-2 human (MayApprove) DISTINCT from the session's requestor /
// launching_user. These tests prove self-approval is rejected, a distinct rung-2
// human is accepted, and a distinct non-approver is rejected. The non-rank
// constructor's contract (any live grant counts) is preserved by every test above.
// ============================================================================

// TestApproverRankGuard_SelfApprovalRejected: a live ask-grant whose Actor IS the
// session's requestor / launching_user is a SELF-approval and does NOT count as a
// landed approval — closing the gap where a launching user (or a prompt-injected
// agent acting as that principal) approves its own policy_breach park. The launcher
// MayApprove (doc 16 §8.2 default approver), so the role gate alone would admit it;
// the distinctness guard is what rejects it.
func TestApproverRankGuard_SelfApprovalRejected(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "launcher@org", &exp)},
	}}
	ranks := &fakeApproverRankResolver{
		mayApprove: map[string]bool{"launcher@org": true}, // launcher MayApprove (§8.2)
		requestor:  map[string]string{"sess-bic": "launcher@org"},
	}
	p := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if landed {
		t.Fatal("a self-approval (approver == requestor) must NOT count as a landed approval")
	}
}

// TestApproverRankGuard_DistinctRungTwoAccepted: a live ask-grant whose Actor is a
// rung-2 human (MayApprove) DISTINCT from the requestor DOES count — the legitimate
// approval path stays green.
func TestApproverRankGuard_DistinctRungTwoAccepted(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "approver@org", &exp)},
	}}
	ranks := &fakeApproverRankResolver{
		mayApprove: map[string]bool{"approver@org": true},
		requestor:  map[string]string{"sess-bic": "launcher@org"}, // distinct from approver
	}
	p := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if !landed {
		t.Fatal("a distinct rung-2 human approval must count as a landed approval")
	}
}

// TestApproverRankGuard_DistinctNonApproverRejected: a live ask-grant whose Actor
// is DISTINCT from the requestor but does NOT MayApprove (not a rung-2 human) does
// NOT count — distinctness alone is insufficient; the approver must also be rung-2.
func TestApproverRankGuard_DistinctNonApproverRejected(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "viewer@org", &exp)},
	}}
	ranks := &fakeApproverRankResolver{
		mayApprove: map[string]bool{"viewer@org": false}, // distinct but not an approver
		requestor:  map[string]string{"sess-bic": "launcher@org"},
	}
	p := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if landed {
		t.Fatal("a distinct NON-approver (no MayApprove) must NOT count as a landed approval")
	}
}

// TestApproverRankGuard_DistinctRungTwoAmongSelfGrants: when multiple live grants
// exist — a self-approval AND a distinct rung-2 approval — the distinct rung-2
// grant satisfies the guard (the self-approval is skipped, not fatal). One genuine
// distinct approver is enough.
func TestApproverRankGuard_DistinctRungTwoAmongSelfGrants(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {
			askGrantBy("sess-bic", "launcher@org", &exp), // self-approval (skipped)
			askGrantBy("sess-bic", "approver@org", &exp), // distinct rung-2 (accepted)
		},
	}}
	ranks := &fakeApproverRankResolver{
		mayApprove: map[string]bool{"launcher@org": true, "approver@org": true},
		requestor:  map[string]string{"sess-bic": "launcher@org"},
	}
	p := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if !landed {
		t.Fatal("a distinct rung-2 approval alongside a self-approval must count")
	}
}

// TestApproverRankGuard_EmptyActorRejected: a live grant with no Actor cannot be
// attributed to an approver — it never satisfies the guard (fail-closed).
func TestApproverRankGuard_EmptyActorRejected(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "", &exp)},
	}}
	ranks := &fakeApproverRankResolver{
		requestor: map[string]string{"sess-bic": "launcher@org"},
	}
	p := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if landed {
		t.Fatal("an unattributed grant (empty Actor) must NOT count as a landed approval")
	}
}

// TestApproverRankGuard_NilRequestorDistinctApproverAccepted: when a session has no
// linked launching_user (the nullable case, requestor == ""), a rung-2 approver is
// trivially distinct and a genuine approval still counts — the guard does not fail
// closed merely because the requestor link is absent.
func TestApproverRankGuard_NilRequestorDistinctApproverAccepted(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "approver@org", &exp)},
	}}
	ranks := &fakeApproverRankResolver{
		mayApprove: map[string]bool{"approver@org": true},
		requestor:  map[string]string{}, // no launching_user link
	}
	p := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if !landed {
		t.Fatal("a rung-2 approval on a session with no launching_user link must count")
	}
}

// TestApproverRankGuard_RequestorReadErrorSurfaced: a SessionRequestor read fault is
// surfaced VERBATIM (fail-closed) — the gate cannot prove a distinct approver.
func TestApproverRankGuard_RequestorReadErrorSurfaced(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	wantErr := errors.New("principals table unreachable")
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "approver@org", &exp)},
	}}
	ranks := &fakeApproverRankResolver{requestorErr: wantErr}
	p := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err == nil {
		t.Fatal("expected a requestor-resolve fault to surface, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the underlying requestor read error in the chain, got %v", err)
	}
	if landed {
		t.Fatal("a requestor-resolve fault must report landed=false (fail-closed)")
	}
}

// TestApproverRankGuard_RankReadErrorSurfaced: an ApproverMayApprove read fault is
// surfaced VERBATIM (fail-closed) — the gate cannot prove the approver is rung-2.
func TestApproverRankGuard_RankReadErrorSurfaced(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	wantErr := errors.New("principal lookup unreachable")
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "approver@org", &exp)},
	}}
	ranks := &fakeApproverRankResolver{
		mayApproveErr: wantErr,
		requestor:     map[string]string{"sess-bic": "launcher@org"},
	}
	p := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err == nil {
		t.Fatal("expected an approver-rank resolve fault to surface, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the underlying rank read error in the chain, got %v", err)
	}
	if landed {
		t.Fatal("an approver-rank resolve fault must report landed=false (fail-closed)")
	}
}

// TestApproverRankGuard_NilResolverPreservesPriorBehavior: the non-rank constructor
// (nil resolver) keeps the original contract — any live grant counts — even when
// the grant is a would-be self-approval. This pins that the guard is STRICTLY
// ADDITIVE: only a wired resolver tightens the read.
func TestApproverRankGuard_NilResolverPreservesPriorBehavior(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "launcher@org", &exp)},
	}}
	// No resolver: the original presence behavior.
	p := NewLiveGrantApprovalPresence(reader, clockAt(now))

	landed, err := p.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval: unexpected error: %v", err)
	}
	if !landed {
		t.Fatal("with no resolver wired, any live grant must still count (prior contract preserved)")
	}

	// And the WithRank constructor with a nil resolver is equivalent.
	pNil := NewLiveGrantApprovalPresenceWithRank(reader, nil, clockAt(now))
	landed, err = pNil.HasLandedApproval(context.Background(), "sess-bic")
	if err != nil {
		t.Fatalf("HasLandedApproval (WithRank nil resolver): unexpected error: %v", err)
	}
	if !landed {
		t.Fatal("WithRank(nil) must behave identically to the non-rank constructor")
	}
}

// TestApproverRankGuard_GateRejectsSelfApprovalEndToEnd: end to end through
// AuthorizeResume, a policy_breach resume backed by ONLY a self-approval is DENIED
// (Permitted=false, nil error) — the self-approval gap does not resume a BIC park.
func TestApproverRankGuard_GateRejectsSelfApprovalEndToEnd(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "launcher@org", &exp)},
	}}
	ranks := &fakeApproverRankResolver{
		mayApprove: map[string]bool{"launcher@org": true},
		requestor:  map[string]string{"sess-bic": "launcher@org"},
	}
	approvals := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "sess-bic",
	}, approvals)
	if err != nil {
		t.Fatalf("AuthorizeResume: unexpected error: %v", err)
	}
	if dec.Permitted {
		t.Fatal("a policy_breach resume backed only by a self-approval must be denied")
	}
}

// TestApproverRankGuard_GatePermitsDistinctRungTwoEndToEnd: end to end, a
// policy_breach resume backed by a distinct rung-2 approval is PERMITTED — the
// legitimate path traverses the gate with the guard engaged.
func TestApproverRankGuard_GatePermitsDistinctRungTwoEndToEnd(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-bic": {askGrantBy("sess-bic", "approver@org", &exp)},
	}}
	ranks := &fakeApproverRankResolver{
		mayApprove: map[string]bool{"approver@org": true},
		requestor:  map[string]string{"sess-bic": "launcher@org"},
	}
	approvals := NewLiveGrantApprovalPresenceWithRank(reader, ranks, clockAt(now))

	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "sess-bic",
	}, approvals)
	if err != nil {
		t.Fatalf("AuthorizeResume: unexpected error: %v", err)
	}
	if !dec.Permitted {
		t.Fatalf("a policy_breach resume backed by a distinct rung-2 approval must be permitted, got: %s", dec.Reason)
	}
}

// TestStoreApproverRankResolver_RealMemoryStore wires the PRODUCTION resolver
// (StoreApproverRankResolver) over a REAL *store.Memory to prove the seam is backed
// by the existing frozen reads (GetPrincipal → MayApprove; GetSessionLaunching-
// Principal) — NOT just a fake. A distinct rung-2 approver counts; the launching
// user self-approving does not; an unknown approver does not.
func TestStoreApproverRankResolver_RealMemoryStore(t *testing.T) {
	now := time.Unix(1000, 0)
	mem := store.NewMemoryClock(func() time.Time { return now })
	ctx := context.Background()

	// A launching user (RoleLauncher — MayApprove true per §8.2) and a distinct
	// approver (RoleApprover).
	if _, err := mem.CreatePrincipal(ctx, store.Principal{
		ID: "launcher@org", IdPSubject: "sub-launcher", Org: "org",
		Roles: []store.PrincipalRole{store.RoleLauncher},
	}); err != nil {
		t.Fatalf("CreatePrincipal launcher: %v", err)
	}
	if _, err := mem.CreatePrincipal(ctx, store.Principal{
		ID: "approver@org", IdPSubject: "sub-approver", Org: "org",
		Roles: []store.PrincipalRole{store.RoleApprover},
	}); err != nil {
		t.Fatalf("CreatePrincipal approver: %v", err)
	}
	// A viewer is a real principal but NOT an approver (MayApprove false).
	if _, err := mem.CreatePrincipal(ctx, store.Principal{
		ID: "viewer@org", IdPSubject: "sub-viewer", Org: "org",
		Roles: []store.PrincipalRole{store.RoleViewer},
	}); err != nil {
		t.Fatalf("CreatePrincipal viewer: %v", err)
	}

	// A session launched by launcher@org.
	if _, err := mem.CreateSession(ctx, store.Session{
		Ref: store.SessionRef{SessionUUID: "sess-real", HostID: "host-1", HostSessionIndex: 1, TapName: "dstap-1"},
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := mem.SetSessionLaunchingPrincipal(ctx, "sess-real", "launcher@org"); err != nil {
		t.Fatalf("SetSessionLaunchingPrincipal: %v", err)
	}

	resolver := NewStoreApproverRankResolver(mem)
	exp := now.Add(time.Hour)

	// Distinct rung-2 approver (approver@org ≠ launcher@org) ⇒ landed.
	distinct := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-real": {askGrantBy("sess-real", "approver@org", &exp)},
	}}
	p := NewLiveGrantApprovalPresenceWithRank(distinct, resolver, clockAt(now))
	landed, err := p.HasLandedApproval(ctx, "sess-real")
	if err != nil {
		t.Fatalf("distinct approver: %v", err)
	}
	if !landed {
		t.Fatal("a distinct rung-2 approver over the real store must count as landed")
	}

	// Self-approval by the launching user ⇒ NOT landed.
	self := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-real": {askGrantBy("sess-real", "launcher@org", &exp)},
	}}
	pSelf := NewLiveGrantApprovalPresenceWithRank(self, resolver, clockAt(now))
	landed, err = pSelf.HasLandedApproval(ctx, "sess-real")
	if err != nil {
		t.Fatalf("self approval: %v", err)
	}
	if landed {
		t.Fatal("a self-approval over the real store must NOT count as landed")
	}

	// Distinct but non-approver (viewer@org) ⇒ NOT landed.
	nonApprover := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-real": {askGrantBy("sess-real", "viewer@org", &exp)},
	}}
	pNon := NewLiveGrantApprovalPresenceWithRank(nonApprover, resolver, clockAt(now))
	landed, err = pNon.HasLandedApproval(ctx, "sess-real")
	if err != nil {
		t.Fatalf("non-approver: %v", err)
	}
	if landed {
		t.Fatal("a distinct non-approver over the real store must NOT count as landed")
	}

	// Unknown approver principal (no such row) ⇒ NOT landed, no error (ErrNotFound
	// maps to mayApprove=false in the production resolver).
	unknown := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"sess-real": {askGrantBy("sess-real", "ghost@org", &exp)},
	}}
	pGhost := NewLiveGrantApprovalPresenceWithRank(unknown, resolver, clockAt(now))
	landed, err = pGhost.HasLandedApproval(ctx, "sess-real")
	if err != nil {
		t.Fatalf("unknown approver: %v", err)
	}
	if landed {
		t.Fatal("an unknown approver principal must NOT count as landed (ErrNotFound ⇒ not an approver)")
	}
}
