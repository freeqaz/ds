// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// These tests prove the production wiring in resumedriver.go threads the REAL
// LiveGrantApprovalPresence (approvalpresence.go) into the suspend/park/resume
// driver's policy_breach (BIC) arm, so the resume decision (AuthorizeResume,
// resumeauthority.go) consults a live PolicyKindAskGrant lookup over the store
// rather than the nil placeholder (which denies every policy_breach resume). They
// run entirely offline against *store.Memory + synthetic seams (D50) — no live host,
// boundary, KVM, or OpenBao dependency.
//
// Naming note: this file shares the sessions package with parkresume_test.go, which
// already defines prResumer/seedSession/mustDriver and a prApprovals fake. These
// tests reuse seedSession and prResumer (the real host Resume verb is not exercised
// on the deny paths and is a no-op fake on the permit path) but build the driver via
// the production NewParkResumeDriverWithLiveApprovals so the wiring under test is the
// thing being proven.

const rgpTestNow = int64(1_700_000_000) // a fixed wall instant for the driver + approval clock

func rgpClock() func() time.Time {
	return func() time.Time { return time.Unix(rgpTestNow, 0) }
}

// landAskGrant appends a session-scoped PolicyKindAskGrant row (the policy_log shape
// a landed rung-2 human approval IS, principalroles.go) directly through the store,
// optionally TTL'd. A nil expiresAt is a grant with no TTL (always live);
// store.LiveGrants is what the production presence reads back.
func landAskGrant(t *testing.T, repo *store.Memory, sessionUUID string, expiresAt *time.Time) {
	t.Helper()
	row := store.PolicyLogRow{
		Kind:        store.PolicyKindAskGrant,
		Actor:       "approver-principal", // approver attribution via the audit Actor (D36)
		SessionUUID: sessionUUID,
		ExpiresAt:   expiresAt,
	}
	if _, err := repo.AppendPolicy(context.Background(), row); err != nil {
		t.Fatalf("land ask-grant: %v", err)
	}
}

// TestResumeDriverLiveApprovals_PolicyBreachDeniedWithoutLandedApproval proves that
// with the production presence wired but NO ask-grant landed, a policy_breach resume
// is DENIED by the authority gate — the BIC arm read real policy_log state (found
// none) rather than ignoring the seam. The session stays SUSPENDED; the host Resume
// verb is never driven.
func TestResumeDriverLiveApprovals_PolicyBreachDeniedWithoutLandedApproval(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)

	resumer := &prResumer{}
	d, err := NewParkResumeDriverWithLiveApprovals(
		ParkResumeSeams{Store: repo, Resumer: resumer},
		repo, // the store is the liveGrantReader (store.LiveGrants)
		rgpClock(),
		rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithLiveApprovals: %v", err)
	}

	_, err = d.Resume(ctx, "s1", ResumeAuthorityHumanApproval)
	var denied *ErrResumeDenied
	if !errors.As(err, &denied) {
		t.Fatalf("policy_breach resume without a landed approval: want ErrResumeDenied, got %v", err)
	}
	if resumer.calls != 0 {
		t.Fatalf("host Resume verb must not be driven on a denied resume; got %d calls", resumer.calls)
	}
	rec, _ := repo.GetSession(ctx, "s1")
	if rec.State != store.SessionSuspended {
		t.Fatalf("denied resume must stay SUSPENDED; got %s", rec.State)
	}
}

// TestResumeDriverLiveApprovals_PolicyBreachPermittedWithLandedApproval proves the
// happy path: a currently-valid (un-expired) ask-grant landed for the session means
// the production presence reports the approval, so the BIC arm PERMITS the resume —
// the host Resume verb runs and the record advances SUSPENDED→RESUMING→WORKING.
func TestResumeDriverLiveApprovals_PolicyBreachPermittedWithLandedApproval(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	// A grant that expires AFTER the fixed approval clock instant → live.
	future := time.Unix(rgpTestNow+3600, 0)
	landAskGrant(t, repo, "s1", &future)

	resumer := &prResumer{}
	d, err := NewParkResumeDriverWithLiveApprovals(
		ParkResumeSeams{Store: repo, Resumer: resumer},
		repo,
		rgpClock(),
		rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithLiveApprovals: %v", err)
	}

	rec, err := d.Resume(ctx, "s1", ResumeAuthorityHumanApproval)
	if err != nil {
		t.Fatalf("policy_breach resume WITH a landed approval: want permit, got %v", err)
	}
	if resumer.calls != 1 {
		t.Fatalf("permitted resume must drive the host Resume verb exactly once; got %d", resumer.calls)
	}
	if rec.State != store.SessionWorking {
		t.Fatalf("permitted resume must advance to WORKING; got %s", rec.State)
	}
}

// TestResumeDriverLiveApprovals_ExpiredGrantDenied proves the TTL liveness the BIC
// arm depends on: an ask-grant that has EXPIRED as of the approval clock is NOT a
// landed approval (doc 16 §8.2 resumes on a CURRENT answer, not a stale one), so the
// resume is denied even though a grant row exists.
func TestResumeDriverLiveApprovals_ExpiredGrantDenied(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	// A grant that expired BEFORE the fixed approval clock instant → stale.
	past := time.Unix(rgpTestNow-3600, 0)
	landAskGrant(t, repo, "s1", &past)

	resumer := &prResumer{}
	d, err := NewParkResumeDriverWithLiveApprovals(
		ParkResumeSeams{Store: repo, Resumer: resumer},
		repo,
		rgpClock(),
		rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithLiveApprovals: %v", err)
	}

	_, err = d.Resume(ctx, "s1", ResumeAuthorityHumanApproval)
	var denied *ErrResumeDenied
	if !errors.As(err, &denied) {
		t.Fatalf("policy_breach resume with an EXPIRED grant: want ErrResumeDenied, got %v", err)
	}
	if resumer.calls != 0 {
		t.Fatalf("expired grant must not drive the host Resume verb; got %d calls", resumer.calls)
	}
}

// TestResumeDriverLiveApprovals_ApprovalScopedToSession proves the grant is
// SESSION-SCOPED: a live grant landed for ANOTHER session does not authorize THIS
// session's policy_breach resume. The production presence reads via store.LiveGrants,
// which filters on SessionUUID, so the wiring inherits that scoping.
func TestResumeDriverLiveApprovals_ApprovalScopedToSession(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	// A live grant — but for a DIFFERENT session.
	future := time.Unix(rgpTestNow+3600, 0)
	landAskGrant(t, repo, "other-session", &future)

	resumer := &prResumer{}
	d, err := NewParkResumeDriverWithLiveApprovals(
		ParkResumeSeams{Store: repo, Resumer: resumer},
		repo,
		rgpClock(),
		rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithLiveApprovals: %v", err)
	}

	_, err = d.Resume(ctx, "s1", ResumeAuthorityHumanApproval)
	var denied *ErrResumeDenied
	if !errors.As(err, &denied) {
		t.Fatalf("policy_breach resume with a grant for another session: want ErrResumeDenied, got %v", err)
	}
	if resumer.calls != 0 {
		t.Fatalf("a grant for another session must not drive the host Resume verb; got %d calls", resumer.calls)
	}
}

// TestResumeDriverLiveApprovals_NilReaderFailsClosed proves the wiring is fail-closed
// even when mis-built: a nil liveGrantReader still constructs, and the production
// presence reports a read FAULT on every call (never a false "no approval"), so a
// policy_breach resume denies with a fault surfaced via ErrResumeApprovalReadFailed —
// it never silently allows. The session stays SUSPENDED.
func TestResumeDriverLiveApprovals_NilReaderFailsClosed(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)

	resumer := &prResumer{}
	d, err := NewParkResumeDriverWithLiveApprovals(
		ParkResumeSeams{Store: repo, Resumer: resumer},
		nil, // mis-wired reader
		rgpClock(),
		rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithLiveApprovals (nil reader still constructs): %v", err)
	}

	_, err = d.Resume(ctx, "s1", ResumeAuthorityHumanApproval)
	if !errors.Is(err, ErrResumeApprovalReadFailed) {
		t.Fatalf("nil reader policy_breach resume: want ErrResumeApprovalReadFailed (fail-closed), got %v", err)
	}
	if resumer.calls != 0 {
		t.Fatalf("a read fault must not drive the host Resume verb; got %d calls", resumer.calls)
	}
	rec, _ := repo.GetSession(ctx, "s1")
	if rec.State != store.SessionSuspended {
		t.Fatalf("a fail-closed deny must stay SUSPENDED; got %s", rec.State)
	}
}

// TestResumeDriverLiveApprovals_UserArmUnaffected proves the production wiring only
// governs the policy_breach arm: a USER-reason suspension resumes on the authority
// match alone (no landed-approval read), so wiring the live presence (with no grant
// landed) does not block a legitimate user resume.
func TestResumeDriverLiveApprovals_UserArmUnaffected(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)

	resumer := &prResumer{}
	d, err := NewParkResumeDriverWithLiveApprovals(
		ParkResumeSeams{Store: repo, Resumer: resumer},
		repo, // a real reader, but no grant landed
		rgpClock(),
		rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithLiveApprovals: %v", err)
	}

	rec, err := d.Resume(ctx, "s1", ResumeAuthorityUser)
	if err != nil {
		t.Fatalf("user-reason resume must admit on authority match alone; got %v", err)
	}
	if rec.State != store.SessionWorking {
		t.Fatalf("user resume must advance to WORKING; got %s", rec.State)
	}
	if resumer.calls != 1 {
		t.Fatalf("user resume must drive the host Resume verb once; got %d", resumer.calls)
	}
}

// TestWithLiveGrantApprovals_OverwritesAndPreservesOtherSeams proves the builder
// installs the production presence into Approvals (overwriting any caller-supplied
// reader — the whole point is to wire the REAL one) while leaving every other seam
// exactly as supplied.
func TestWithLiveGrantApprovals_OverwritesAndPreservesOtherSeams(t *testing.T) {
	repo := store.NewMemory()
	resumer := &prResumer{}
	snap := &prSnapshotter{}
	in := ParkResumeSeams{
		Store:       repo,
		Resumer:     resumer,
		Snapshotter: snap,
		Approvals:   prApprovals{landed: true}, // a caller-supplied fake that must be overwritten
	}

	out := WithLiveGrantApprovals(in, repo, rgpClock())

	if _, ok := out.Approvals.(*LiveGrantApprovalPresence); !ok {
		t.Fatalf("WithLiveGrantApprovals must install the production LiveGrantApprovalPresence; got %T", out.Approvals)
	}
	if out.Store != repo {
		t.Fatalf("Store seam must be preserved")
	}
	if out.Resumer != resumer {
		t.Fatalf("Resumer seam must be preserved")
	}
	if out.Snapshotter != snap {
		t.Fatalf("Snapshotter seam must be preserved")
	}
	// The input must not be mutated (value-copy semantics).
	if _, ok := in.Approvals.(prApprovals); !ok {
		t.Fatalf("WithLiveGrantApprovals must not mutate the caller's seams in place")
	}
}

// TestWithLiveGrantApprovals_NilClockDefaults proves a nil clock is accepted (the
// production presence defaults it to time.Now) and the resulting presence still
// reads a live grant correctly — the builder hands the BIC arm a working reader with
// the minimal call (store only).
func TestWithLiveGrantApprovals_NilClockDefaults(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	// A grant with NO TTL is always live regardless of which clock the presence uses.
	landAskGrant(t, repo, "s1", nil)

	seams := WithLiveGrantApprovals(ParkResumeSeams{Store: repo}, repo, nil)
	presence, ok := seams.Approvals.(*LiveGrantApprovalPresence)
	if !ok {
		t.Fatalf("want production presence, got %T", seams.Approvals)
	}
	landed, err := presence.HasLandedApproval(ctx, "s1")
	if err != nil {
		t.Fatalf("HasLandedApproval with default clock: %v", err)
	}
	if !landed {
		t.Fatalf("a no-TTL ask-grant must read as a landed approval under the default clock")
	}
}

// ============================================================================
// §8.2 SELF-APPROVAL GUARD on the GUARDED park-resume builder (01KVMBXH31).
// These prove the guarded builders in resumedriver.go
// (WithLiveGrantApprovalsAndRank / NewParkResumeDriverWithGuardedApprovals) thread
// the ApproverRankResolver into the policy_breach (BIC) arm so a self-approval — a
// live ask-grant whose Actor IS the session's launching_user — does NOT resume a BIC
// park, while a DISTINCT rung-2 (MayApprove) approval DOES, end to end through
// ParkResumeDriver.Resume AND ResumeFromPark. They run offline against synthetic
// fakes (a fake liveGrantReader + a fake principalRankStore) + a fixed clock (D50).
// The un-guarded contract (approvalpresence_test.go / the tests above) stays green.
// ============================================================================

// fakeRankStore is the SYNTHETIC principalRankStore (D50) the guarded builder wraps
// into the production StoreApproverRankResolver: an in-process map of principal ID →
// Principal (for the GetPrincipal → MayApprove rung-2 gate) and session → requestor /
// launching_user (for GetSessionLaunchingPrincipal), plus optional injected read
// faults. An unknown principal returns store.ErrNotFound (the production resolver maps
// that to "not an approver"), faithfully standing in for the real store reads with NO
// store dependency.
type fakeRankStore struct {
	principals map[string]store.Principal // principal ID → Principal (absent ⇒ ErrNotFound)
	requestor  map[string]string          // session UUID → launching_user (absent ⇒ "")
	getErr     error
	launchErr  error
}

func (f *fakeRankStore) GetPrincipal(_ context.Context, id string) (store.Principal, error) {
	if f.getErr != nil {
		return store.Principal{}, f.getErr
	}
	p, ok := f.principals[id]
	if !ok {
		return store.Principal{}, store.ErrNotFound
	}
	return p, nil
}

func (f *fakeRankStore) GetSessionLaunchingPrincipal(_ context.Context, sessionUUID string) (string, error) {
	if f.launchErr != nil {
		return "", f.launchErr
	}
	return f.requestor[sessionUUID], nil
}

// rgpApprover builds a principal that MayApprove (RoleApprover — rung-2, D45).
func rgpApprover(id string) store.Principal {
	return store.Principal{ID: id, Roles: []store.PrincipalRole{store.RoleApprover}}
}

// rgpLauncher builds the launching user (RoleLauncher — MayApprove true per §8.2, the
// default approver whose SELF-approval the distinctness guard must still reject).
func rgpLauncher(id string) store.Principal {
	return store.Principal{ID: id, Roles: []store.PrincipalRole{store.RoleLauncher}}
}

// TestResumeDriverGuarded_SelfApprovalDeniedResume: end to end through Resume, a
// policy_breach resume backed ONLY by a self-approval (the live ask-grant's Actor IS
// the session's launching_user, who MayApprove per §8.2) is DENIED by the guarded
// builder — the distinctness guard closes the self-approval gap. The session stays
// SUSPENDED; the host Resume verb is never driven.
func TestResumeDriverGuarded_SelfApprovalDeniedResume(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	future := time.Unix(rgpTestNow+3600, 0)

	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"s1": {askGrantBy("s1", "launcher@org", &future)}, // approver == launching_user
	}}
	ranks := &fakeRankStore{
		principals: map[string]store.Principal{"launcher@org": rgpLauncher("launcher@org")},
		requestor:  map[string]string{"s1": "launcher@org"},
	}
	resumer := &prResumer{}
	d, err := NewParkResumeDriverWithGuardedApprovals(
		ParkResumeSeams{Store: repo, Resumer: resumer},
		reader, ranks, rgpClock(), rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithGuardedApprovals: %v", err)
	}

	_, err = d.Resume(ctx, "s1", ResumeAuthorityHumanApproval)
	var denied *ErrResumeDenied
	if !errors.As(err, &denied) {
		t.Fatalf("self-approval policy_breach resume: want ErrResumeDenied, got %v", err)
	}
	if resumer.calls != 0 {
		t.Fatalf("a denied self-approval must not drive the host Resume verb; got %d calls", resumer.calls)
	}
	rec, _ := repo.GetSession(ctx, "s1")
	if rec.State != store.SessionSuspended {
		t.Fatalf("denied self-approval must stay SUSPENDED; got %s", rec.State)
	}
}

// TestResumeDriverGuarded_DistinctRungTwoPermittedResume: end to end through Resume, a
// policy_breach resume backed by a DISTINCT rung-2 approval (approver@org ≠
// launcher@org, MayApprove) is PERMITTED by the guarded builder — the legitimate path
// stays green with the guard engaged: host Resume runs, record advances to WORKING.
func TestResumeDriverGuarded_DistinctRungTwoPermittedResume(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	future := time.Unix(rgpTestNow+3600, 0)

	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"s1": {askGrantBy("s1", "approver@org", &future)}, // distinct rung-2 approver
	}}
	ranks := &fakeRankStore{
		principals: map[string]store.Principal{
			"approver@org": rgpApprover("approver@org"),
			"launcher@org": rgpLauncher("launcher@org"),
		},
		requestor: map[string]string{"s1": "launcher@org"},
	}
	resumer := &prResumer{}
	d, err := NewParkResumeDriverWithGuardedApprovals(
		ParkResumeSeams{Store: repo, Resumer: resumer},
		reader, ranks, rgpClock(), rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithGuardedApprovals: %v", err)
	}

	rec, err := d.Resume(ctx, "s1", ResumeAuthorityHumanApproval)
	if err != nil {
		t.Fatalf("distinct rung-2 policy_breach resume: want permit, got %v", err)
	}
	if resumer.calls != 1 {
		t.Fatalf("a permitted distinct rung-2 resume must drive the host Resume verb once; got %d", resumer.calls)
	}
	if rec.State != store.SessionWorking {
		t.Fatalf("permitted resume must advance to WORKING; got %s", rec.State)
	}
}

// TestResumeDriverGuarded_SelfApprovalDeniedResumeFromPark: end to end through
// ResumeFromPark, a policy_breach re-place backed ONLY by a self-approval is DENIED —
// the session stays PARKED and no re-place/re-mint occurs. This proves the guard bites
// on the PARKED→re-place path (the D46/D77 untimed-park resume-on-answer arm) too, not
// just the in-place Resume.
func TestResumeDriverGuarded_SelfApprovalDeniedResumeFromPark(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionParked, store.SuspendReasonNone)
	future := time.Unix(rgpTestNow+3600, 0)

	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"s1": {askGrantBy("s1", "launcher@org", &future)}, // self-approval
	}}
	ranks := &fakeRankStore{
		principals: map[string]store.Principal{"launcher@org": rgpLauncher("launcher@org")},
		requestor:  map[string]string{"s1": "launcher@org"},
	}
	placer := &prPlacer{hostID: "host-b"}
	alloc := &prAlloc{idx: 7, tap: "dstap-7"}
	minter := &prMinter{idRef: "id-2", caRef: "ca-2"}
	d, err := NewParkResumeDriverWithGuardedApprovals(
		ParkResumeSeams{Store: repo, Placer: placer, HostAllocator: alloc, Minter: minter},
		reader, ranks, rgpClock(), rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithGuardedApprovals: %v", err)
	}

	_, err = d.ResumeFromPark(ctx, "s1", ResumeAuthorityHumanApproval, attachReasonPolicyBreach)
	var denied *ErrResumeDenied
	if !errors.As(err, &denied) {
		t.Fatalf("self-approval policy_breach re-place: want ErrResumeDenied, got %v", err)
	}
	if minter.calls != 0 {
		t.Fatal("a denied self-approval re-place must not re-mint or re-place")
	}
	rec, _ := repo.GetSession(ctx, "s1")
	if rec.State != store.SessionParked {
		t.Fatalf("denied self-approval re-place must stay PARKED; got %s", rec.State)
	}
}

// TestResumeDriverGuarded_DistinctRungTwoPermittedResumeFromPark: end to end through
// ResumeFromPark, a policy_breach re-place backed by a DISTINCT rung-2 approval is
// PERMITTED — the session re-places (PARKED→CREATING@host') with a re-mint, proving the
// legitimate untimed-park resume-on-answer path stays green with the guard engaged.
func TestResumeDriverGuarded_DistinctRungTwoPermittedResumeFromPark(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionParked, store.SuspendReasonNone)
	future := time.Unix(rgpTestNow+3600, 0)

	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"s1": {askGrantBy("s1", "approver@org", &future)}, // distinct rung-2 approver
	}}
	ranks := &fakeRankStore{
		principals: map[string]store.Principal{
			"approver@org": rgpApprover("approver@org"),
			"launcher@org": rgpLauncher("launcher@org"),
		},
		requestor: map[string]string{"s1": "launcher@org"},
	}
	placer := &prPlacer{hostID: "host-b", appliedSeq: 99}
	alloc := &prAlloc{idx: 7, tap: "dstap-7"}
	minter := &prMinter{idRef: "id-2", caRef: "ca-2"}
	d, err := NewParkResumeDriverWithGuardedApprovals(
		ParkResumeSeams{Store: repo, Placer: placer, HostAllocator: alloc, Minter: minter},
		reader, ranks, rgpClock(), rgpClock(),
	)
	if err != nil {
		t.Fatalf("NewParkResumeDriverWithGuardedApprovals: %v", err)
	}

	rec, err := d.ResumeFromPark(ctx, "s1", ResumeAuthorityHumanApproval, attachReasonPolicyBreach)
	if err != nil {
		t.Fatalf("distinct rung-2 policy_breach re-place: want permit, got %v", err)
	}
	if minter.calls != 1 {
		t.Fatalf("a permitted re-place must re-mint exactly once; got %d", minter.calls)
	}
	if rec.State != store.SessionCreating {
		t.Fatalf("permitted re-place must advance to CREATING@host'; got %s", rec.State)
	}
}

// TestWithLiveGrantApprovalsAndRank_InstallsGuardedPresence proves the guarded builder
// installs a LiveGrantApprovalPresence with the resolver ENGAGED: a self-approval reads
// as NOT landed through the installed presence (the guard is live), while every other
// seam is preserved and the caller's seams are not mutated in place.
func TestWithLiveGrantApprovalsAndRank_InstallsGuardedPresence(t *testing.T) {
	ctx := context.Background()
	future := time.Unix(rgpTestNow+3600, 0)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"s1": {askGrantBy("s1", "launcher@org", &future)},
	}}
	ranks := &fakeRankStore{
		principals: map[string]store.Principal{"launcher@org": rgpLauncher("launcher@org")},
		requestor:  map[string]string{"s1": "launcher@org"},
	}
	repo := store.NewMemory()
	resumer := &prResumer{}
	in := ParkResumeSeams{Store: repo, Resumer: resumer, Approvals: prApprovals{landed: true}}

	out := WithLiveGrantApprovalsAndRank(in, reader, ranks, rgpClock())

	presence, ok := out.Approvals.(*LiveGrantApprovalPresence)
	if !ok {
		t.Fatalf("guarded builder must install the production LiveGrantApprovalPresence; got %T", out.Approvals)
	}
	landed, err := presence.HasLandedApproval(ctx, "s1")
	if err != nil {
		t.Fatalf("HasLandedApproval: %v", err)
	}
	if landed {
		t.Fatal("the guarded presence must reject a self-approval (guard engaged)")
	}
	if out.Store != repo || out.Resumer != resumer {
		t.Fatal("guarded builder must preserve every other seam")
	}
	if _, ok := in.Approvals.(prApprovals); !ok {
		t.Fatal("guarded builder must not mutate the caller's seams in place")
	}
}

// TestWithLiveGrantApprovalsAndRank_NilRankStoreFallsBack proves a nil principalRankStore
// falls back to the UN-guarded production presence (behavior-preserving): with no resolver
// to tighten the read, any live grant — even a would-be self-approval — still counts, the
// prior contract. This pins the guarded builder as strictly additive.
func TestWithLiveGrantApprovalsAndRank_NilRankStoreFallsBack(t *testing.T) {
	ctx := context.Background()
	future := time.Unix(rgpTestNow+3600, 0)
	reader := &fakeLiveGrantReader{rows: map[string][]store.PolicyLogRow{
		"s1": {askGrantBy("s1", "launcher@org", &future)},
	}}
	repo := store.NewMemory()

	out := WithLiveGrantApprovalsAndRank(ParkResumeSeams{Store: repo}, reader, nil, rgpClock())
	presence, ok := out.Approvals.(*LiveGrantApprovalPresence)
	if !ok {
		t.Fatalf("nil rank store must still install the production presence; got %T", out.Approvals)
	}
	landed, err := presence.HasLandedApproval(ctx, "s1")
	if err != nil {
		t.Fatalf("HasLandedApproval: %v", err)
	}
	if !landed {
		t.Fatal("with a nil rank store the un-guarded contract holds: any live grant counts")
	}
}
