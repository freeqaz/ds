// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// --- synthetic seams for the park/resume driver (pr-prefixed to avoid collisions
//     with the sessioncreate_test fakes in the same package) ---

type prSuspender struct {
	calls []*hypervisorv1.SuspendRequest
	err   error
}

func (s *prSuspender) Suspend(_ context.Context, _ string, req *hypervisorv1.SuspendRequest) error {
	s.calls = append(s.calls, req)
	return s.err
}

type prResumer struct {
	calls int
	err   error
}

func (r *prResumer) Resume(_ context.Context, _, _ string) error { r.calls++; return r.err }

type prSnapshotter struct {
	calls int
	err   error
}

func (s *prSnapshotter) Snapshot(_ context.Context, _, _ string) error { s.calls++; return s.err }

type prPlacer struct {
	hostID     string
	appliedSeq int64
	err        error
}

func (p *prPlacer) Place(_ context.Context, _ string, _ PlacementRequest) (Placement, error) {
	if p.err != nil {
		return Placement{}, p.err
	}
	return Placement{HostID: p.hostID, AppliedSeq: p.appliedSeq}, nil
}
func (p *prPlacer) CurrentFreshness(_ context.Context, _ string) (int64, error) {
	return 0, ErrFreshnessUnknown
}

type prAlloc struct {
	idx     uint64
	tap     string
	err     error
	gotHost string
}

func (a *prAlloc) AllocateAndDefine(_ context.Context, hostID string, _ *hypervisorv1.VmSpec) (HostAllocation, error) {
	a.gotHost = hostID
	if a.err != nil {
		return HostAllocation{}, a.err
	}
	return HostAllocation{HostSessionIndex: a.idx, TapName: a.tap, GuestIPFamily: store.IPFamilyV4}, nil
}

type prMinter struct {
	idRef string
	caRef string
	err   error
	calls int
}

func (m *prMinter) Mint(_ context.Context, _ MintWorkloadIdentityClaims, _ string) (MintResult, error) {
	m.calls++
	if m.err != nil {
		return MintResult{}, m.err
	}
	return MintResult{IdentityRef: m.idRef, CARef: m.caRef}, nil
}

type prApprovals struct {
	landed bool
	err    error
}

func (a prApprovals) HasLandedApproval(_ context.Context, _ string) (bool, error) {
	return a.landed, a.err
}

// seedSession writes a session record at the given state directly through the store
// (bypassing the create choreography). It seeds via CreateSession at WORKING-adjacent
// initial state then advances — the store does not gate transition legality, so we set
// the desired state with an UpdateSession (suspend reason set iff SUSPENDED).
func seedSession(t *testing.T, repo *store.Memory, uuid, hostID string, idx uint64, state store.SessionState, reason store.SuspendReason) store.Session {
	t.Helper()
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, store.Session{
		Ref:     store.SessionRef{SessionUUID: uuid, HostID: hostID, HostSessionIndex: idx, TapName: "dstap-1"},
		ImageID: "img-1",
		State:   store.SessionWorking,
		RolePin: store.RolePin{Name: "default", Version: "v1", ContentHash: "h"},
	})
	if err != nil {
		t.Fatalf("seed CreateSession: %v", err)
	}
	if state != store.SessionWorking {
		u := store.SessionUpdate{State: &state}
		if reason != store.SuspendReasonNone {
			u.SuspendReason = &reason
		}
		if _, err := repo.UpdateSession(ctx, uuid, u); err != nil {
			t.Fatalf("seed advance to %s: %v", state, err)
		}
	}
	got, _ := repo.GetSession(ctx, uuid)
	return got
}

func mustDriver(t *testing.T, seams ParkResumeSeams) *ParkResumeDriver {
	t.Helper()
	d, err := NewParkResumeDriver(seams, func() time.Time { return time.Unix(1_700_000_000, 0) })
	if err != nil {
		t.Fatalf("NewParkResumeDriver: %v", err)
	}
	return d
}

// TestSuspendWorkingToSuspended drives WORKING→SUSPENDED, validates the host verb was
// driven, and advances the record with the mapped reason.
func TestSuspendWorkingToSuspended(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionWorking, store.SuspendReasonNone)
	susp := &prSuspender{}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Suspender: susp})

	req := &hypervisorv1.SuspendRequest{
		SessionUuid: "s1",
		Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
	}
	rec, err := d.Suspend(context.Background(), req)
	if err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if rec.State != store.SessionSuspended || rec.SuspendReason != store.SuspendReasonPolicyBreach {
		t.Fatalf("record=%s/%s, want SUSPENDED/policy_breach", rec.State, rec.SuspendReason)
	}
	if len(susp.calls) != 1 {
		t.Fatalf("host Suspend driven %d times, want 1", len(susp.calls))
	}
}

// TestSuspendIdempotent: re-suspending an already-SUSPENDED session under the same
// reason is a no-op (no second host verb).
func TestSuspendIdempotent(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	susp := &prSuspender{}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Suspender: susp})

	req := &hypervisorv1.SuspendRequest{SessionUuid: "s1", Reason: hypervisorv1.SuspendReason_SUSPEND_REASON_USER}
	if _, err := d.Suspend(context.Background(), req); err != nil {
		t.Fatalf("idempotent Suspend: %v", err)
	}
	if len(susp.calls) != 0 {
		t.Fatalf("idempotent re-suspend must not re-drive the host verb, got %d calls", len(susp.calls))
	}
}

// TestSuspendIllegalFromDestroying: a non-WORKING/non-SUSPENDED origin is rejected.
func TestSuspendIllegalFromDestroying(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionDestroying, store.SuspendReasonNone)
	d := mustDriver(t, ParkResumeSeams{Store: repo, Suspender: &prSuspender{}})
	_, err := d.Suspend(context.Background(), &hypervisorv1.SuspendRequest{SessionUuid: "s1", Reason: hypervisorv1.SuspendReason_SUSPEND_REASON_USER})
	var illegal *ErrIllegalTransition
	if !errors.As(err, &illegal) {
		t.Fatalf("expected ErrIllegalTransition, got %v", err)
	}
}

// TestResumeUserAuthority: a user-reason suspension resumes on the user authority,
// driving SUSPENDED→RESUMING→WORKING.
func TestResumeUserAuthority(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	res := &prResumer{}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res})

	rec, err := d.Resume(context.Background(), "s1", ResumeAuthorityUser)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if rec.State != store.SessionWorking {
		t.Fatalf("record=%s, want WORKING", rec.State)
	}
	if res.calls != 1 {
		t.Fatalf("host Resume driven %d times, want 1", res.calls)
	}
}

// TestResumePolicyBreachDeniedWithoutApproval: a policy_breach suspension resumed
// WITHOUT a landed human approval is DENIED — stays at SUSPENDED, no host verb. THE
// KEY ASSERTION (resumeauthority.go contract enforced at the driver).
func TestResumePolicyBreachDeniedWithoutApproval(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	res := &prResumer{}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res, Approvals: prApprovals{landed: false}})

	_, err := d.Resume(context.Background(), "s1", ResumeAuthorityHumanApproval)
	var denied *ErrResumeDenied
	if !errors.As(err, &denied) {
		t.Fatalf("expected ErrResumeDenied, got %v", err)
	}
	if res.calls != 0 {
		t.Fatal("a denied resume must not drive the host Resume verb")
	}
	got, _ := repo.GetSession(context.Background(), "s1")
	if got.State != store.SessionSuspended {
		t.Fatalf("denied resume must stay at SUSPENDED, got %s", got.State)
	}
}

// TestResumePolicyBreachPermittedWithApproval: with a landed approval, the policy_breach
// resume traverses to WORKING.
func TestResumePolicyBreachPermittedWithApproval(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	res := &prResumer{}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res, Approvals: prApprovals{landed: true}})

	rec, err := d.Resume(context.Background(), "s1", ResumeAuthorityHumanApproval)
	if err != nil {
		t.Fatalf("Resume with landed approval: %v", err)
	}
	if rec.State != store.SessionWorking || res.calls != 1 {
		t.Fatalf("permitted resume: state=%s calls=%d", rec.State, res.calls)
	}
}

// TestResumeWrongAuthority: presenting the scheduler authority for a user suspension is
// a mismatch denial.
func TestResumeWrongAuthority(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: &prResumer{}})
	_, err := d.Resume(context.Background(), "s1", ResumeAuthorityScheduler)
	var denied *ErrResumeDenied
	if !errors.As(err, &denied) {
		t.Fatalf("expected ErrResumeDenied for authority mismatch, got %v", err)
	}
}

// TestResumeApprovalReadFaultIsFailClosed: an approval-presence read fault surfaces as
// a fail-closed error (ErrResumeApprovalReadFailed), distinct from a policy refusal.
func TestResumeApprovalReadFaultIsFailClosed(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: &prResumer{}, Approvals: prApprovals{err: errors.New("db down")}})
	_, err := d.Resume(context.Background(), "s1", ResumeAuthorityHumanApproval)
	if !errors.Is(err, ErrResumeApprovalReadFailed) {
		t.Fatalf("expected ErrResumeApprovalReadFailed, got %v", err)
	}
}

// TestEscalateToParkReleasesSlot: WORKING→SNAPSHOTTING→PARKED; the host Snapshot was
// driven; the record reaches PARKED with no suspend reason (no transparency claim).
func TestEscalateToParkReleasesSlot(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionWorking, store.SuspendReasonNone)
	snap := &prSnapshotter{}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Snapshotter: snap})

	rec, err := d.EscalateToPark(context.Background(), "s1")
	if err != nil {
		t.Fatalf("EscalateToPark: %v", err)
	}
	if rec.State != store.SessionParked {
		t.Fatalf("record=%s, want PARKED", rec.State)
	}
	if rec.SuspendReason != store.SuspendReasonNone {
		t.Fatalf("PARKED carries no suspend reason, got %q", rec.SuspendReason)
	}
	if snap.calls != 1 {
		t.Fatalf("host Snapshot driven %d times, want 1", snap.calls)
	}
}

// TestEscalateToParkIdempotent: a session already PARKED is a no-op.
func TestEscalateToParkIdempotent(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionParked, store.SuspendReasonNone)
	snap := &prSnapshotter{}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Snapshotter: snap})
	if _, err := d.EscalateToPark(context.Background(), "s1"); err != nil {
		t.Fatalf("idempotent EscalateToPark: %v", err)
	}
	if snap.calls != 0 {
		t.Fatal("idempotent park must not re-snapshot")
	}
}

// TestEscalateSuspendedReconvergesToPark drives the D46 >15-min escalation on a
// still-SUSPENDED session: EscalateToPark re-converges along the LEGAL FROZEN chain
// SUSPENDED→RESUMING→WORKING→SNAPSHOTTING→PARKED (escalateReconverge), reaching PARKED with
// no suspend reason and the host Snapshot driven — and NO host Resume verb driven (this is a
// FORCED escalation park, not a resume for use). This closes the >15-min escalate-tier gap
// (the case that MUST PARK, never time out) using only existing legal §3 edges.
func TestEscalateSuspendedReconvergesToPark(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	snap := &prSnapshotter{}
	res := &prResumer{}
	// Wire BOTH a Resumer and Snapshotter so the test can prove the forced re-converge does
	// NOT drive the host Resume verb (it only walks the record states to a snapshot-able WORKING).
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res, Snapshotter: snap})

	rec, err := d.EscalateToPark(context.Background(), "s1")
	if err != nil {
		t.Fatalf("EscalateToPark from SUSPENDED: %v", err)
	}
	if rec.State != store.SessionParked {
		t.Fatalf("record=%s, want PARKED via the legal SUSPENDED→RESUMING→WORKING→SNAPSHOTTING→PARKED re-converge", rec.State)
	}
	if rec.SuspendReason != store.SuspendReasonNone {
		t.Fatalf("PARKED carries no suspend reason, got %q", rec.SuspendReason)
	}
	if snap.calls != 1 {
		t.Fatalf("host Snapshot driven %d times, want 1", snap.calls)
	}
	if res.calls != 0 {
		t.Fatalf("forced escalation park must NOT drive the host Resume verb (it is not a resume for use), got %d calls", res.calls)
	}
}

// TestEscalateSuspendedPolicyBreachParksWithoutApproval is the load-bearing D77 / doc 15 §3
// note 2 assertion: an unanswered genuine rung-2 policy_breach suspension that outruns the
// 15-min escalate tier PARKS via the legal re-converge WITHOUT a landed human approval (it
// must park and never time out into allow or kill). The forced escalation park does NOT
// consult the resume-authority gate, so NO ApprovalPresence reader is wired — and it still
// reaches PARKED.
func TestEscalateSuspendedPolicyBreachParksWithoutApproval(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	snap := &prSnapshotter{}
	// NO Approvals reader wired: the forced park must not depend on the resume-authority gate.
	d := mustDriver(t, ParkResumeSeams{Store: repo, Snapshotter: snap})

	rec, err := d.EscalateToPark(context.Background(), "s1")
	if err != nil {
		t.Fatalf("policy_breach EscalateToPark from SUSPENDED must park without an approval, got: %v", err)
	}
	if rec.State != store.SessionParked {
		t.Fatalf("record=%s, want PARKED (the unanswered genuine rung-2 ask parks, never times out)", rec.State)
	}
	if snap.calls != 1 {
		t.Fatalf("host Snapshot driven %d times, want 1", snap.calls)
	}
}

// TestDirectSuspendedToSnapshottingStillIllegal pins the §3 freeze (01KTWJ3PG0): there is NO
// direct SUSPENDED→SNAPSHOTTING edge in the FROZEN transition table — the re-converge added
// here reaches PARKED via the legal chain, it does NOT introduce a shortcut edge. The frozen
// IsTransition must still reject the direct jump.
func TestDirectSuspendedToSnapshottingStillIllegal(t *testing.T) {
	if IsTransition(StateSuspended, StateSnapshotting) {
		t.Fatal("the frozen §3 graph must NOT contain a direct SUSPENDED→SNAPSHOTTING edge (01KTWJ3PG0); the re-converge goes through RESUMING→WORKING, it adds no shortcut")
	}
	// And the legal re-converge edges DO all exist (the chain the escalation walks).
	for _, e := range []Edge{
		{StateSuspended, StateResuming},
		{StateResuming, StateWorking},
		{StateWorking, StateSnapshotting},
		{StateSnapshotting, StateParked},
	} {
		if !IsTransition(e.From, e.To) {
			t.Fatalf("legal re-converge edge %s→%s is missing from the frozen §3 graph", e.From, e.To)
		}
	}
}

// TestEscalateReconvergeIdempotentFromPartialState proves the level-triggered re-drive (D35):
// a re-converge that already advanced the record partway (to RESUMING or WORKING) re-converges
// from wherever it stalled to PARKED on the next EscalateToPark — never re-failing on the
// intermediate state.
func TestEscalateReconvergeIdempotentFromPartialState(t *testing.T) {
	for _, partial := range []store.SessionState{store.SessionResuming, store.SessionWorking} {
		t.Run(string(partial), func(t *testing.T) {
			repo := store.NewMemory()
			seedSession(t, repo, "s1", "host-a", 1, partial, store.SuspendReasonNone)
			snap := &prSnapshotter{}
			d := mustDriver(t, ParkResumeSeams{Store: repo, Snapshotter: snap})

			rec, err := d.EscalateToPark(context.Background(), "s1")
			if err != nil {
				t.Fatalf("EscalateToPark from partial %s: %v", partial, err)
			}
			if rec.State != store.SessionParked {
				t.Fatalf("record=%s, want PARKED from partial re-converge state %s", rec.State, partial)
			}
			if snap.calls != 1 {
				t.Fatalf("host Snapshot driven %d times, want 1", snap.calls)
			}
		})
	}
}

// TestResumeFromParkReplacesSameUUIDNewIndex: PARKED→CREATING@host', same session UUID,
// a NEW host index/tap on the target (index history kept), re-mint driven.
func TestResumeFromParkReplacesSameUUIDNewIndex(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionParked, store.SuspendReasonNone)
	placer := &prPlacer{hostID: "host-b", appliedSeq: 99}
	alloc := &prAlloc{idx: 7, tap: "dstap-7"}
	minter := &prMinter{idRef: "id-2", caRef: "ca-2"}
	d := mustDriver(t, ParkResumeSeams{
		Store: repo, Placer: placer, HostAllocator: alloc, Minter: minter,
		Approvals: prApprovals{landed: true},
	})

	rec, err := d.ResumeFromPark(context.Background(), "s1", ResumeAuthorityUser, attachReasonUser)
	if err != nil {
		t.Fatalf("ResumeFromPark: %v", err)
	}
	if rec.State != store.SessionCreating {
		t.Fatalf("record=%s, want CREATING@host'", rec.State)
	}
	// Same UUID, new host/index/tap on the target.
	if rec.Ref.SessionUUID != "s1" {
		t.Fatalf("session UUID must survive the re-place, got %q", rec.Ref.SessionUUID)
	}
	if rec.Ref.HostID != "host-b" || rec.Ref.HostSessionIndex != 7 || rec.Ref.TapName != "dstap-7" {
		t.Fatalf("re-place did not rebind to the target: %+v", rec.Ref)
	}
	// Index history kept (the prior epoch on host-a + the new epoch on host-b).
	if len(rec.IndexHistory) != 2 {
		t.Fatalf("index history should keep the prior epoch, got %d epochs", len(rec.IndexHistory))
	}
	if alloc.gotHost != "host-b" {
		t.Fatalf("host allocate hit %q, want the re-place target host-b", alloc.gotHost)
	}
	if minter.calls != 1 {
		t.Fatalf("re-mint driven %d times, want 1 (expired credential re-mints on resume)", minter.calls)
	}
	if rec.IdentityRef != "id-2" || rec.CARef != "ca-2" {
		t.Fatalf("re-minted identity/CA not recorded: %s/%s", rec.IdentityRef, rec.CARef)
	}
	if rec.PolicyAppliedSeq != 99 {
		t.Fatalf("placement applied_seq not recorded: %d", rec.PolicyAppliedSeq)
	}
}

// TestResumeFromParkPolicyBreachDeniedWithoutApproval: an unanswered genuine rung-2 ask
// PARKED under policy_breach never re-places without a landed approval (it parks and
// resumes ONLY on answer — never times out into allow or kill).
func TestResumeFromParkPolicyBreachDeniedWithoutApproval(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionParked, store.SuspendReasonNone)
	placer := &prPlacer{hostID: "host-b"}
	alloc := &prAlloc{idx: 7, tap: "dstap-7"}
	minter := &prMinter{idRef: "id-2", caRef: "ca-2"}
	d := mustDriver(t, ParkResumeSeams{
		Store: repo, Placer: placer, HostAllocator: alloc, Minter: minter,
		Approvals: prApprovals{landed: false},
	})

	_, err := d.ResumeFromPark(context.Background(), "s1", ResumeAuthorityHumanApproval, attachReasonPolicyBreach)
	var denied *ErrResumeDenied
	if !errors.As(err, &denied) {
		t.Fatalf("expected ErrResumeDenied for a policy_breach park without approval, got %v", err)
	}
	if minter.calls != 0 {
		t.Fatal("a denied re-place must not re-mint or re-place")
	}
	got, _ := repo.GetSession(context.Background(), "s1")
	if got.State != store.SessionParked {
		t.Fatalf("denied re-place must stay PARKED, got %s", got.State)
	}
}

// TestParkResumeUnknownSession: an operation on an unknown session surfaces
// ErrParkResumeNoSession.
func TestParkResumeUnknownSession(t *testing.T) {
	repo := store.NewMemory()
	d := mustDriver(t, ParkResumeSeams{Store: repo, Suspender: &prSuspender{}})
	_, err := d.Suspend(context.Background(), &hypervisorv1.SuspendRequest{SessionUuid: "ghost", Reason: hypervisorv1.SuspendReason_SUSPEND_REASON_USER})
	if !errors.Is(err, ErrParkResumeNoSession) {
		t.Fatalf("expected ErrParkResumeNoSession, got %v", err)
	}
}

// TestNewParkResumeDriverRequiresStore: a nil store is a construction error.
func TestNewParkResumeDriverRequiresStore(t *testing.T) {
	if _, err := NewParkResumeDriver(ParkResumeSeams{}, nil); err == nil {
		t.Fatal("expected construction error for nil Store")
	}
}
