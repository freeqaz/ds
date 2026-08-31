package sessions

// sessioncreate_test.go drives the doc 15 §4.1 ten-step create coordinator
// (sessioncreate.go) against synthetic fixtures + a real *store.Memory + the real
// launch gate (behind the spine's data seam). It proves:
//   - the HAPPY PATH runs all ten steps in the FROZEN precedence order, ending
//     ATTACHED with the binding + identity/CA + digest-ack + role pin all recorded;
//   - the FROZEN PRECEDENCE is enforced (an ordered recorder asserts
//     `1 ≺ 2 ≺ 3 ≺ {6,7,8}; 5 ≺ 6; 5 ≺ 7-injection; 7 ≺ 8; {3,6} ≺ 9 ≺ 10`);
//   - the ROLLBACK-FROM-EACH-STEP matrix compensates (the §4.2 destroy path from the
//     failing step) and satisfies the doc 06 (b) clean-teardown checklist (host
//     destroy + identity/CA revoke + record finalize);
//   - a failed step-4 index is BURNED, never recycled (a retry that re-allocates it
//     is refused by the store);
//   - create is RETRYABLE by session UUID;
//   - the structural GATES refuse fail-closed (D56 two-key, D73 digest-not-acked,
//     D72 freshness re-check, D17/D29 CA injection).
//
// Discipline (D50): NO live VM/host-agent/podman. The host-side steps are driven
// through the package-owned seams, satisfied by synthetic fakes that RECORD the verbs
// and SCRIPT faults — the createstep5 / childsession pattern.

import (
	"bytes"
	"context"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/auth"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// ----- synthetic seam fakes (record verbs + script faults) -----

// twoKeyFake is a synthetic TwoKeyChecker: by default it passes; set err to refuse.
type twoKeyFake struct {
	err    error
	called bool
}

func (f *twoKeyFake) Check(context.Context, TwoKeyRequest) (TwoKeyResult, error) {
	f.called = true
	return TwoKeyResult{}, f.err
}

// placerFake scripts the §4.1 step-3 placement: it returns a fixed Placement or err.
// It also scripts the §4.1 step-9 LIVE freshness probe (CurrentFreshness): by default
// the probe is UNAVAILABLE (freshErr = ErrFreshnessUnknown) so the routable gate
// degrades to the recorded re-check exactly as before the probe existed (the default
// keeps every pre-existing test green); a test that exercises the live re-check sets
// freshSeq (the host's CURRENT applied_seq) + clears freshErr.
type placerFake struct {
	placement Placement
	err       error
	called    bool
	// freshSeq is the host's CURRENT applied_seq the live probe reports (step 9); used
	// only when freshErr is nil.
	freshSeq int64
	// freshErr scripts the probe outcome: ErrFreshnessUnknown (the default) makes the
	// gate degrade to the recorded re-check; nil makes it use freshSeq.
	freshErr     error
	freshCalled  bool
	freshGotHost string
}

func (f *placerFake) Place(context.Context, string, PlacementRequest) (Placement, error) {
	f.called = true
	return f.placement, f.err
}

func (f *placerFake) CurrentFreshness(_ context.Context, hostID string) (int64, error) {
	f.freshCalled = true
	f.freshGotHost = hostID
	if f.freshErr != nil {
		return 0, f.freshErr
	}
	return f.freshSeq, nil
}

// hostAllocFake scripts §4.1 step 4: it returns a fixed binding or err, and records
// the host it was driven on (so placement → allocation routing can be asserted).
type hostAllocFake struct {
	alloc   HostAllocation
	err     error
	gotHost string
	gotSpec *hypervisorv1.VmSpec
}

func (f *hostAllocFake) AllocateAndDefine(_ context.Context, hostID string, spec *hypervisorv1.VmSpec) (HostAllocation, error) {
	f.gotHost = hostID
	f.gotSpec = spec
	return f.alloc, f.err
}

// minterFake scripts §4.1 step 5: returns fixed refs or err, records the claims it saw.
type minterFake struct {
	result     MintResult
	err        error
	gotClaims  MintWorkloadIdentityClaims
	gotRoleRef string
}

func (f *minterFake) Mint(_ context.Context, claims MintWorkloadIdentityClaims, roleRef string) (MintResult, error) {
	f.gotClaims = claims
	f.gotRoleRef = roleRef
	return f.result, f.err
}

// digestFake scripts §4.1 step 6: returns a fixed DigestResult or err.
type digestFake struct {
	result DigestResult
	err    error
	gotCA  string
}

func (f *digestFake) WriteAndAck(_ context.Context, _, _, caRef string) (DigestResult, error) {
	f.gotCA = caRef
	return f.result, f.err
}

// injectorFake scripts §4.1 step 7: nil err = injected; set err to fail-closed.
type injectorFake struct {
	err   error
	gotCA string
}

func (f *injectorFake) InjectCA(_ context.Context, _, _, caRef string) error {
	f.gotCA = caRef
	return f.err
}

// booterFake scripts §4.1 step 8.
type booterFake struct{ err error }

func (f *booterFake) Boot(context.Context, string, string) error { return f.err }

// attachFake scripts §4.1 step 10: returns the issued seat or err.
type attachFake struct {
	role store.AttachRole
	err  error
}

func (f *attachFake) IssueAttach(_ context.Context, _, _ string, role store.AttachRole) (AttachIssued, error) {
	if f.err != nil {
		return AttachIssued{}, f.err
	}
	out := f.role
	if out == store.RoleNone {
		out = role
	}
	return AttachIssued{Role: out}, nil
}

// destroyerFake records the compensating §4.2 destroy verb (the clean-teardown
// checklist's host half) and can script a fault.
type destroyerFake struct {
	calls []string // session UUIDs destroyed
	err   error
}

func (f *destroyerFake) Destroy(_ context.Context, _, sessionUUID string) error {
	f.calls = append(f.calls, sessionUUID)
	return f.err
}

// revokerFake records the §4.1 step-5/6 identity/CA revocation (the clean-teardown
// checklist's "no leftover minted identity" half) and can script a fault.
type revokerFake struct {
	calls []string // session UUIDs revoked
	err   error
}

func (f *revokerFake) Revoke(_ context.Context, sessionUUID, _, _ string) error {
	f.calls = append(f.calls, sessionUUID)
	return f.err
}

// ----- a recording wrapper set that proves the FROZEN PRECEDENCE ordering -----

// orderRec records the §4.1 step labels in the order the coordinator drives them, so
// the frozen precedence can be asserted as a happens-before relation.
type orderRec struct{ steps []CreateStep }

func (o *orderRec) mark(s CreateStep) { o.steps = append(o.steps, s) }

// before reports whether step a was driven strictly before step b in the recorded
// order. A step that never ran is treated as "not before" (fail the assertion loudly).
func (o *orderRec) before(a, b CreateStep) bool {
	ia, ib := -1, -1
	for i, s := range o.steps {
		if s == a && ia < 0 {
			ia = i
		}
		if s == b && ib < 0 {
			ib = i
		}
	}
	return ia >= 0 && ib >= 0 && ia < ib
}

// ----- happy-path harness -----

type creatorHarness struct {
	repo      *store.Memory
	seams     CreateSeams
	twoKey    *twoKeyFake
	placer    *placerFake
	alloc     *hostAllocFake
	minter    *minterFake
	digest    *digestFake
	inject    *injectorFake
	boot      *booterFake
	attach    *attachFake
	destroyer *destroyerFake
	revoker   *revokerFake
	order     *orderRec
}

// newHarness wires a coordinator over a real *store.Memory + the real launch gate
// (so the step-2 record + the spine's link write + the role pin persist for real)
// and synthetic host-side seams. All seams record into a shared orderRec so the
// frozen precedence is observable. happyDigestAcked controls the step-6 ack.
func newHarness(t *testing.T, happyDigestAcked bool) *creatorHarness {
	t.Helper()
	repo := store.NewMemory()
	order := &orderRec{}

	twoKey := &twoKeyFake{}
	// freshErr defaults to ErrFreshnessUnknown so the step-9 live probe is UNAVAILABLE
	// by default — the routable gate degrades to the recorded re-check, the pre-probe
	// behavior every existing test asserts. The live-probe test sets freshSeq + clears
	// freshErr to exercise CurrentFreshness.
	placer := &placerFake{placement: Placement{HostID: "host-a", AppliedSeq: 7}, freshErr: ErrFreshnessUnknown}
	alloc := &hostAllocFake{alloc: HostAllocation{
		HostSessionIndex: 42, TapName: "dstap-42",
		GuestIP: []byte{10, 0, 0, 42}, GuestIPFamily: store.IPFamilyV4,
		OverlayPath: "/overlays/sess.qcow2",
	}}
	minter := &minterFake{result: MintResult{IdentityRef: "id-ref", CARef: "ca-ref"}}
	digest := &digestFake{result: DigestResult{DigestRef: "digest-ref", Acked: happyDigestAcked}}
	inject := &injectorFake{}
	boot := &booterFake{}
	attach := &attachFake{}
	destroyer := &destroyerFake{}
	revoker := &revokerFake{}

	// Order-recording wrappers around the synthetic seams.
	gate := orderGate{inner: realGateAdapter{gate: auth.NewLaunchGate(
		auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}, o: order}
	roleR := &spineRoleResolver{dflt: recordedDefault()}

	seams := CreateSeams{
		TwoKey:          orderTwoKey{inner: twoKey, o: order},
		Store:           repo,
		Gate:            gate,
		RoleResolver:    roleR,
		MintResolver:    repo,
		PinWriter:       repo,
		Placer:          orderPlacer{inner: placer, o: order},
		HostAllocator:   orderAlloc{inner: alloc, o: order},
		Minter:          orderMinter{inner: minter, o: order},
		DigestWriter:    orderDigest{inner: digest, o: order},
		Injector:        orderInject{inner: inject, o: order},
		Booter:          orderBoot{inner: boot, o: order},
		AttachIssuer:    orderAttach{inner: attach, o: order},
		HostDestroyer:   destroyer,
		IdentityRevoker: revoker,
	}
	return &creatorHarness{
		repo: repo, seams: seams, twoKey: twoKey, placer: placer, alloc: alloc,
		minter: minter, digest: digest, inject: inject, boot: boot, attach: attach,
		destroyer: destroyer, revoker: revoker, order: order,
	}
}

func (h *creatorHarness) creator(t *testing.T) *SessionCreator {
	t.Helper()
	c, err := NewSessionCreator(h.seams, 0, nil)
	if err != nil {
		t.Fatalf("NewSessionCreator: %v", err)
	}
	c.clock = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	return c
}

func authedReq(uuid string) CreateRequest {
	return CreateRequest{
		SessionUUID:         uuid,
		RepoID:              "repo-x",
		EnvConfigRef:        "env-ref",
		ImageID:             "img-1",
		Auth:                &LaunchInput{Org: "acme", Subject: "okta|ada", Roles: []string{string(store.RoleLauncher)}},
		RoleRef:             "",
		EntrypointConfigRef: "entry-1",
	}
}

// ----- order-recording seam wrappers -----

type orderTwoKey struct {
	inner TwoKeyChecker
	o     *orderRec
}

func (w orderTwoKey) Check(ctx context.Context, r TwoKeyRequest) (TwoKeyResult, error) {
	w.o.mark(StepTwoKey)
	return w.inner.Check(ctx, r)
}

type orderGate struct {
	inner launchGate
	o     *orderRec
}

func (w orderGate) AuthorizeLaunch(ctx context.Context, s string, in *LaunchInput) (LaunchOutcome, error) {
	w.o.mark(StepRecord) // the launch gate runs in the steps-1–2 cluster, at the record boundary
	return w.inner.AuthorizeLaunch(ctx, s, in)
}

type orderPlacer struct {
	inner Placer
	o     *orderRec
}

func (w orderPlacer) Place(ctx context.Context, s string, r PlacementRequest) (Placement, error) {
	w.o.mark(StepPlacement)
	return w.inner.Place(ctx, s, r)
}

// CurrentFreshness threads the §4.1 step-9 LIVE freshness probe through the wrapper
// (no order mark — the probe runs inside the step-9 routable gate, which already
// orders after boot via the StepRoutable/StepAttach happens-before checks).
func (w orderPlacer) CurrentFreshness(ctx context.Context, hostID string) (int64, error) {
	return w.inner.CurrentFreshness(ctx, hostID)
}

type orderAlloc struct {
	inner HostAllocator
	o     *orderRec
}

func (w orderAlloc) AllocateAndDefine(ctx context.Context, h string, spec *hypervisorv1.VmSpec) (HostAllocation, error) {
	w.o.mark(StepHostAlloc)
	return w.inner.AllocateAndDefine(ctx, h, spec)
}

type orderMinter struct {
	inner Minter
	o     *orderRec
}

func (w orderMinter) Mint(ctx context.Context, c MintWorkloadIdentityClaims, r string) (MintResult, error) {
	w.o.mark(StepMint)
	return w.inner.Mint(ctx, c, r)
}

type orderDigest struct {
	inner DigestWriter
	o     *orderRec
}

func (w orderDigest) WriteAndAck(ctx context.Context, s, h, ca string) (DigestResult, error) {
	w.o.mark(StepDigest)
	return w.inner.WriteAndAck(ctx, s, h, ca)
}

type orderInject struct {
	inner Injector
	o     *orderRec
}

func (w orderInject) InjectCA(ctx context.Context, s, o, ca string) error {
	w.o.mark(StepInject)
	return w.inner.InjectCA(ctx, s, o, ca)
}

type orderBoot struct {
	inner Booter
	o     *orderRec
}

func (w orderBoot) Boot(ctx context.Context, s, e string) error {
	w.o.mark(StepBoot)
	return w.inner.Boot(ctx, s, e)
}

type orderAttach struct {
	inner AttachIssuer
	o     *orderRec
}

func (w orderAttach) IssueAttach(ctx context.Context, s, h string, r store.AttachRole) (AttachIssued, error) {
	w.o.mark(StepAttach)
	return w.inner.IssueAttach(ctx, s, h, r)
}

// ----- HAPPY PATH -----

// TestCreate_HappyPath_AllTenStepsInFrozenOrder is the headline acceptance: an
// authenticated create runs all ten §4.1 steps, ends ATTACHED with every binding
// recorded, and the recorded order honors the FROZEN precedence.
func TestCreate_HappyPath_AllTenStepsInFrozenOrder(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	c := h.creator(t)

	final, err := c.Create(ctx, authedReq("sess-1"))
	if err != nil {
		t.Fatalf("Create happy path: %v", err)
	}

	// Ended ATTACHED with the launching WRITER seat.
	if final.State != store.SessionAttached {
		t.Errorf("final state = %q, want ATTACHED", final.State)
	}
	if final.AttachState != store.RoleWriter {
		t.Errorf("attach seat = %q, want WRITER (D61 launching writer seat)", final.AttachState)
	}

	// The binding (step 4) + identity/CA (step 5) + digest ack (step 6) + role pin
	// (steps 1–2) all landed on the record.
	rec, err := h.repo.GetSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if rec.Ref.HostSessionIndex != 42 || rec.Ref.TapName != "dstap-42" {
		t.Errorf("binding not recorded: index=%d tap=%q", rec.Ref.HostSessionIndex, rec.Ref.TapName)
	}
	if rec.IdentityRef != "id-ref" || rec.CARef != "ca-ref" {
		t.Errorf("identity/CA not recorded: id=%q ca=%q", rec.IdentityRef, rec.CARef)
	}
	if rec.DigestRef != "digest-ref" || !rec.DigestAcked {
		t.Errorf("digest/ack not recorded: ref=%q acked=%v", rec.DigestRef, rec.DigestAcked)
	}
	if rec.PolicyAppliedSeq != 7 {
		t.Errorf("placement applied_seq not recorded: %d", rec.PolicyAppliedSeq)
	}
	if !rec.RolePin.Pinned() || rec.RolePin.Name != "default" {
		t.Errorf("role pin not persisted: %+v", rec.RolePin)
	}
	if rec.ReadyAt == nil || rec.AttachedAt == nil {
		t.Error("ReadyAt/AttachedAt timestamps not stamped")
	}

	// The mint claims carried the IdP-backed launching_user (the gate ran before the
	// step-5 resolver) and the pinned role_ref.
	if !h.minter.gotClaims.HasLaunchingUser || h.minter.gotClaims.LaunchingUser != "okta|ada" {
		t.Errorf("step-5 mint claims missing IdP launching_user: %+v", h.minter.gotClaims)
	}
	if h.minter.gotRoleRef != "default@2026.06.11-v1" {
		t.Errorf("step-5 role_ref = %q, want the pinned default", h.minter.gotRoleRef)
	}
	// The CA the digest write (step 6) and the injection (step 7) keyed on is the
	// minted CA (step 5).
	if h.digest.gotCA != "ca-ref" || h.inject.gotCA != "ca-ref" {
		t.Errorf("digest/inject CA mismatch: digest=%q inject=%q", h.digest.gotCA, h.inject.gotCA)
	}
	// The allocation was driven on the PLACED host with the right VmSpec.
	if h.alloc.gotHost != "host-a" || h.alloc.gotSpec.GetSessionUuid() != "sess-1" || h.alloc.gotSpec.GetImageId() != "img-1" {
		t.Errorf("allocation routing/spec wrong: host=%q spec=%+v", h.alloc.gotHost, h.alloc.gotSpec)
	}

	// FROZEN PRECEDENCE: 1 ≺ 2 ≺ 3 ≺ {6,7,8}; 5 ≺ 6; 5 ≺ 7; 7 ≺ 8; {3,6} ≺ 9 ≺ 10.
	o := h.order
	checks := []struct {
		a, b CreateStep
		why  string
	}{
		{StepTwoKey, StepRecord, "1 ≺ 2"},
		{StepRecord, StepPlacement, "2 ≺ 3"},
		{StepPlacement, StepDigest, "3 ≺ 6"},
		{StepPlacement, StepInject, "3 ≺ 7"},
		{StepPlacement, StepBoot, "3 ≺ 8"},
		{StepMint, StepDigest, "5 ≺ 6"},
		{StepMint, StepInject, "5 ≺ 7-injection"},
		{StepInject, StepBoot, "7 ≺ 8"},
		{StepPlacement, StepAttach, "3 ≺ 9 ≺ 10 (placement before attach)"},
		{StepDigest, StepAttach, "6 ≺ 9 ≺ 10 (digest before attach)"},
		{StepBoot, StepAttach, "8 ≺ 9 ≺ 10 (boot before attach)"},
	}
	for _, ck := range checks {
		if !o.before(ck.a, ck.b) {
			t.Errorf("frozen precedence violated (%s): %s did not run before %s; order=%v", ck.why, ck.a, ck.b, o.steps)
		}
	}
}

// ----- ROLLBACK-FROM-EACH-STEP MATRIX -----

// TestCreate_RollbackFromEachStep is the from-each-step rollback matrix: a fault
// injected at each §4.1 step compensates correctly (host destroy + identity/CA
// revoke + record finalize as the step demands) and surfaces a clean *CreateError.
func TestCreate_RollbackFromEachStep(t *testing.T) {
	ctx := context.Background()

	type expect struct {
		step            CreateStep
		wantHostDestroy bool // the §4.2 host destroy ran (host-side state existed)
		wantRevoke      bool // identity/CA revocation ran (minted at step 5+)
		noRollback      bool // a step-1 refusal needs NO rollback (nothing host-side, no record)
		sentinel        error
	}
	cases := []struct {
		name   string
		mutate func(h *creatorHarness)
		expect expect
	}{
		{
			name:   "step1-two-key-refusal",
			mutate: func(h *creatorHarness) { h.twoKey.err = fmt.Errorf("%w: x", ErrTwoKeyRefused) },
			expect: expect{step: StepTwoKey, noRollback: true, sentinel: ErrTwoKeyRefused},
		},
		{
			name:   "step3-placement-stale",
			mutate: func(h *creatorHarness) { h.placer.err = ErrPolicyStale },
			expect: expect{step: StepPlacement, sentinel: ErrPolicyStale},
		},
		{
			name:   "step4-host-alloc-fault",
			mutate: func(h *creatorHarness) { h.alloc.err = errors.New("clone failed") },
			expect: expect{step: StepHostAlloc, wantHostDestroy: true},
		},
		{
			name:   "step5-mint-fault",
			mutate: func(h *creatorHarness) { h.minter.err = errors.New("mint failed") },
			// mint failed → nothing minted yet → no revoke, but host-side step 4 unwinds.
			expect: expect{step: StepMint, wantHostDestroy: true, wantRevoke: false},
		},
		{
			name:   "step6-digest-fault",
			mutate: func(h *creatorHarness) { h.digest.err = errors.New("digest write failed") },
			// identity/CA minted at step 5 → revoke; host-side state → destroy.
			expect: expect{step: StepDigest, wantHostDestroy: true, wantRevoke: true},
		},
		{
			name:   "step7-ca-injection-failclosed",
			mutate: func(h *creatorHarness) { h.inject.err = errors.New("trust store write failed") },
			expect: expect{step: StepInject, wantHostDestroy: true, wantRevoke: true, sentinel: ErrCAInjection},
		},
		{
			name:   "step8-boot-fault",
			mutate: func(h *creatorHarness) { h.boot.err = errors.New("boot failed") },
			expect: expect{step: StepBoot, wantHostDestroy: true, wantRevoke: true},
		},
		{
			name:   "step9-digest-not-acked",
			mutate: func(h *creatorHarness) { h.digest.result.Acked = false },
			expect: expect{step: StepRoutable, wantHostDestroy: true, wantRevoke: true, sentinel: ErrDigestNotAcked},
		},
		{
			name:   "step10-attach-fault",
			mutate: func(h *creatorHarness) { h.attach.err = errors.New("attach failed") },
			expect: expect{step: StepAttach, wantHostDestroy: true, wantRevoke: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, true)
			tc.mutate(h)
			c := h.creator(t)

			_, err := c.Create(ctx, authedReq("sess-"+tc.name))
			var ce *CreateError
			if !errors.As(err, &ce) {
				t.Fatalf("want *CreateError, got %T: %v", err, err)
			}
			if ce.Step != tc.expect.step {
				t.Errorf("failed step = %s, want %s", ce.Step, tc.expect.step)
			}
			if tc.expect.noRollback {
				// A step-1 refusal needs no rollback: nothing host-side exists and no
				// record was written, so RolledBack=false is the correct "nothing to
				// compensate" outcome (and RollbackErr stays nil).
				if ce.RolledBack {
					t.Error("a step-1 refusal should report RolledBack=false (nothing to compensate)")
				}
			} else if !ce.RolledBack {
				t.Errorf("rollback did not complete cleanly: RollbackErr=%v", ce.RollbackErr)
			}
			if ce.RollbackErr != nil {
				t.Errorf("clean rollback must have nil RollbackErr, got %v", ce.RollbackErr)
			}
			if tc.expect.sentinel != nil && !errors.Is(err, tc.expect.sentinel) {
				t.Errorf("error must classify as %v, got %v", tc.expect.sentinel, err)
			}

			gotDestroy := len(h.destroyer.calls) > 0
			if gotDestroy != tc.expect.wantHostDestroy {
				t.Errorf("host destroy ran=%v, want %v", gotDestroy, tc.expect.wantHostDestroy)
			}
			gotRevoke := len(h.revoker.calls) > 0
			if gotRevoke != tc.expect.wantRevoke {
				t.Errorf("identity/CA revoke ran=%v, want %v", gotRevoke, tc.expect.wantRevoke)
			}

			// Every rollback finalizes the record DESTROYED + retained (D66) — except a
			// step-1 refusal, where no record was ever written (nothing to finalize).
			rec, getErr := h.repo.GetSession(ctx, "sess-"+tc.name)
			if tc.expect.step == StepTwoKey {
				if getErr == nil {
					t.Error("a step-1 two-key refusal must leave no session record")
				}
				return
			}
			if getErr != nil {
				t.Fatalf("post-rollback GetSession: %v", getErr)
			}
			if rec.State != store.SessionDestroyed {
				t.Errorf("post-rollback record state = %q, want DESTROYED (retained, D66)", rec.State)
			}
			if rec.DestroyedAt == nil {
				t.Error("post-rollback record must carry a DestroyedAt finalize timestamp")
			}
		})
	}
}

// TestCreate_BurnedStep4IndexNeverRecycled proves the §4.1 step-4 burn: an index
// recorded onto the record (AppendIndexEpoch) is BURNED, so a later create that
// re-allocates the SAME index on the SAME host is refused by the store (ErrInvalid)
// — the index is never recycled across creates.
func TestCreate_BurnedStep4IndexNeverRecycled(t *testing.T) {
	ctx := context.Background()

	// First create fails at step 8 (boot) AFTER the index binding was recorded — so
	// index 42 on host-a is burned.
	h1 := newHarness(t, true)
	h1.boot.err = errors.New("boot failed")
	c1 := h1.creator(t)
	if _, err := c1.Create(ctx, authedReq("sess-burn-1")); err == nil {
		t.Fatal("first create must fail at step 8")
	}
	rec, _ := h1.repo.GetSession(ctx, "sess-burn-1")
	if rec.Ref.HostSessionIndex != 42 {
		t.Fatalf("precondition: index 42 must have been recorded (burned), got %d", rec.Ref.HostSessionIndex)
	}

	// Second create on the SAME store re-allocates index 42 on host-a — the store must
	// REFUSE the recycle at AppendIndexEpoch (the burn is permanent), so the create
	// fails at step 4 with ErrInvalid.
	c2, err := NewSessionCreator(h1.seams, 0, nil)
	if err != nil {
		t.Fatalf("NewSessionCreator: %v", err)
	}
	c2.clock = h1.creator(t).clock
	_, err = c2.Create(ctx, authedReq("sess-burn-2"))
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError on recycled index, got %T: %v", err, err)
	}
	if ce.Step != StepHostAlloc {
		t.Errorf("recycled index must fail at step 4, got %s", ce.Step)
	}
	if !errors.Is(err, store.ErrInvalid) {
		t.Errorf("recycled index must surface store.ErrInvalid (burn refused), got %v", err)
	}
}

// TestCreate_RetryableByUUID proves the §4.1 "create is retryable by session UUID":
// a create that failed BEFORE the host binding (step 3) can be retried under the same
// UUID once the transient clears, reaching ATTACHED. (The first attempt finalized the
// record DESTROYED; the retry re-drives from a fresh creator over a fresh store —
// modeling the idempotent-by-UUID retry the reconciler/RPC re-issues.)
func TestCreate_RetryableByUUID(t *testing.T) {
	ctx := context.Background()

	// Attempt 1: placement stale → fails at step 3, finalizes the record.
	h1 := newHarness(t, true)
	h1.placer.err = ErrPolicyStale
	c1 := h1.creator(t)
	if _, err := c1.Create(ctx, authedReq("sess-retry")); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("attempt 1 must fail stale, got %v", err)
	}

	// Attempt 2: the SAME UUID on a fresh coherent store (the transient cleared) runs
	// to completion. Idempotent on session_uuid — a retry by UUID succeeds.
	h2 := newHarness(t, true)
	c2 := h2.creator(t)
	final, err := c2.Create(ctx, authedReq("sess-retry"))
	if err != nil {
		t.Fatalf("retry by UUID must succeed, got %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("retry final state = %q, want ATTACHED", final.State)
	}
}

// TestCreate_UnauthenticatedLaunchRefused proves the launch-gate refusal (doc 16
// §11.2) threads through the coordinator: a nil Auth is refused fail-closed and the
// host-side seams never run.
func TestCreate_UnauthenticatedLaunchRefused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	c := h.creator(t)

	req := authedReq("sess-anon")
	req.Auth = nil // unauthenticated

	_, err := c.Create(ctx, req)
	if !errors.Is(err, ErrLaunchRefused) {
		t.Fatalf("unauthenticated launch must be refused (ErrLaunchRefused), got %v", err)
	}
	if h.placer.called {
		t.Error("a refused launch must never reach placement (step 3)")
	}
	if len(h.destroyer.calls) != 0 {
		t.Error("a pre-host refusal needs no host destroy")
	}
}

// TestCreate_RollbackGapWhenDestroyerMissing proves the honest rollback-gap surface:
// a host-side failure on a coordinator with NO HostDestroyer wired surfaces
// RolledBack=false + a RollbackErr (the reconciler is the backstop), never a silent
// clean claim.
func TestCreate_RollbackGapWhenDestroyerMissing(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	h.seams.HostDestroyer = nil // no destroyer wired
	h.alloc.err = errors.New("clone failed")
	c := h.creator(t)

	_, err := c.Create(ctx, authedReq("sess-gap"))
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %T: %v", err, err)
	}
	if ce.RolledBack {
		t.Error("a host-side rollback with no HostDestroyer must report RolledBack=false")
	}
	if ce.RollbackErr == nil {
		t.Error("a rollback gap must surface a RollbackErr (reconciler backstop), never a silent clean claim")
	}
}

// TestCreate_RollbackErrSurfacedWhenDestroyFaults proves a FAULTING compensation
// surfaces honestly: the host destroy itself fails → RolledBack=false + RollbackErr.
func TestCreate_RollbackErrSurfacedWhenDestroyFaults(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	h.boot.err = errors.New("boot failed")
	h.destroyer.err = errors.New("destroy faulted")
	c := h.creator(t)

	_, err := c.Create(ctx, authedReq("sess-rbfault"))
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %T: %v", err, err)
	}
	if ce.RolledBack {
		t.Error("a faulting destroy must report RolledBack=false")
	}
	if ce.RollbackErr == nil || !errors.Is(ce.RollbackErr, h.destroyer.err) {
		t.Errorf("RollbackErr must carry the destroy fault, got %v", ce.RollbackErr)
	}
}

// TestNewSessionCreator_RefusesMissingSeams proves the construction-time fail-closed:
// a wiring missing a required seam is refused at NewSessionCreator, never at the first
// create.
func TestNewSessionCreator_RefusesMissingSeams(t *testing.T) {
	_, err := NewSessionCreator(CreateSeams{}, 0, nil)
	if err == nil {
		t.Fatal("an empty seam bundle must be refused at construction")
	}
	// A bundle missing only the Booter is also refused.
	h := newHarness(t, true)
	h.seams.Booter = nil
	if _, err := NewSessionCreator(h.seams, 0, nil); err == nil {
		t.Fatal("a bundle missing Booter must be refused at construction")
	}
}

// TestCreate_FreshnessRecheckRefusesStaleHost proves the §4.1 step-9 D72 re-check:
// if the recorded applied_seq has fallen behind the placement seq by more than the
// staleness budget (a host that went stale after placement), the routable gate
// refuses (ErrPolicyStale) and the create rolls back — never waved through to READY.
func TestCreate_FreshnessRecheckRefusesStaleHost(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	// Placement records applied_seq 7; simulate the host going stale by having the
	// digest step rewrite the recorded applied_seq lower than placement (drift > 0).
	h.digest.result = DigestResult{DigestRef: "d", Acked: true}
	c := h.creator(t)
	// Budget 0 (exact match required). Drive a stale drift by pre-lowering the record
	// after placement via a staleness-injecting store wrapper.
	c.seams.Store = staleAfterPlacement{inner: h.repo, lowerTo: 3}

	_, err := c.Create(ctx, authedReq("sess-stale9"))
	if !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("step-9 freshness re-check must refuse a stale host (ErrPolicyStale), got %v", err)
	}
	var ce *CreateError
	if errors.As(err, &ce) && ce.Step != StepRoutable {
		t.Errorf("stale re-check must fail at step 9 (routable), got %s", ce.Step)
	}
}

// TestCreate_RetryAgainstDestroyedRecordRefused proves the §4.1 step-2 retry-vs-
// resurrection guard (D66): a same-store create retry by session UUID, after a
// previous attempt FINALIZED the record DESTROYED, is REFUSED (ErrSessionFinalized) at
// step 2 — the create coordinator never lets the idempotent CreateSession hand back a
// terminal row that the next step would silently resurrect (DESTROYED→CREATING). The
// retry needs a FRESH session UUID; the finalized row stays DESTROYED, untouched.
func TestCreate_RetryAgainstDestroyedRecordRefused(t *testing.T) {
	ctx := context.Background()

	// Attempt 1 on a shared store fails at step 3 (placement stale), finalizing the
	// record DESTROYED via the §4.1 1–3 rollback.
	h := newHarness(t, true)
	h.placer.err = ErrPolicyStale
	c1 := h.creator(t)
	if _, err := c1.Create(ctx, authedReq("sess-resurrect")); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("attempt 1 must fail stale, got %v", err)
	}
	rec, err := h.repo.GetSession(ctx, "sess-resurrect")
	if err != nil {
		t.Fatalf("post-attempt-1 GetSession: %v", err)
	}
	if rec.State != store.SessionDestroyed {
		t.Fatalf("precondition: attempt 1 must finalize the record DESTROYED, got %q", rec.State)
	}

	// Attempt 2 — SAME UUID on the SAME store (the transient cleared). The store's
	// idempotent CreateSession hands back the finalized DESTROYED row; the coordinator
	// must REFUSE rather than resurrect it.
	h.placer.err = nil // the stale transient cleared
	c2 := h.creator(t)
	_, err = c2.Create(ctx, authedReq("sess-resurrect"))
	if !errors.Is(err, ErrSessionFinalized) {
		t.Fatalf("a retry against a DESTROYED record must be refused (ErrSessionFinalized), got %v", err)
	}
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError, got %T: %v", err, err)
	}
	if ce.Step != StepRecord {
		t.Errorf("resurrection refusal must be stamped at step 2 (record), got %s", ce.Step)
	}
	if ce.RolledBack {
		t.Error("a resurrection refusal needs no rollback (the finalized row stays as-is)")
	}

	// The finalized record was NOT resurrected — it is still DESTROYED, and placement
	// never ran on attempt 2 (refused before step 3).
	rec2, err := h.repo.GetSession(ctx, "sess-resurrect")
	if err != nil {
		t.Fatalf("post-attempt-2 GetSession: %v", err)
	}
	if rec2.State != store.SessionDestroyed {
		t.Errorf("the finalized record must stay DESTROYED (no resurrection), got %q", rec2.State)
	}
}

// TestCreate_RetryAgainstInFlightRecordIdempotent proves the §4.1 step-2 guard does
// NOT over-fire: a retry by UUID against a STILL-LIVE in-flight record (a non-terminal
// state — here PENDING, the step-2 record an earlier attempt wrote but never finalized,
// e.g. a crash before rollback) is the legitimate idempotent-retry case and proceeds to
// completion, NOT a resurrection. Only a finalized (terminal DESTROYED) record is
// refused.
func TestCreate_RetryAgainstInFlightRecordIdempotent(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)

	// Seed a still-live in-flight record under the SAME unbound sentinel the create
	// path uses (a step-2 record an earlier attempt wrote, left non-terminal — no
	// finalize). The retry's CreatePreBindingSession returns it idempotently.
	if _, err := store.CreatePreBindingSession(ctx, h.repo, store.Session{
		Ref:          store.SessionRef{SessionUUID: "sess-inflight"},
		EnvConfigRef: "env-ref",
		ImageID:      "img-1",
		State:        store.SessionPending, // non-terminal — a legitimate in-flight retry
	}); err != nil {
		t.Fatalf("seed in-flight record: %v", err)
	}

	c := h.creator(t)
	final, err := c.Create(ctx, authedReq("sess-inflight"))
	if err != nil {
		t.Fatalf("a retry against a still-live in-flight record must be idempotent (proceed), got %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("idempotent retry final state = %q, want ATTACHED", final.State)
	}
}

// TestCreate_Step9LiveProbeRefusesFellBehindHost proves the §4.1 step-9 LIVE freshness
// re-check (D72): a host whose RECORDED applied_seq still looks fresh (it equals the
// placement seq — the reconciler never re-marked it) but whose CURRENT applied_seq has
// fallen behind in the placement→step-9 window is REFUSED by the live probe
// (ErrPolicyStale) at the routable gate — the residual D72 window the recorded-only
// re-check misses. This is the probe's window-closing catch: the recorded re-check (a)
// passes, the live re-check (b) fails.
func TestCreate_Step9LiveProbeRefusesFellBehindHost(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	// Placement records applied_seq 7; the record is NEVER lowered, so the recorded
	// re-check sees a fresh host. But the LIVE probe reports the host's CURRENT
	// applied_seq has fallen to 3 (it lagged after placement with no record write) —
	// drift 4 > budget 0 → ErrPolicyStale.
	h.placer.freshErr = nil // the live probe IS wired for this test
	h.placer.freshSeq = 3   // CURRENT applied_seq fell behind the placement seq (7)
	c := h.creator(t)

	_, err := c.Create(ctx, authedReq("sess-fellbehind"))
	if !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("step-9 live probe must refuse a fell-behind host (ErrPolicyStale), got %v", err)
	}
	var ce *CreateError
	if errors.As(err, &ce) && ce.Step != StepRoutable {
		t.Errorf("live-probe staleness must fail at step 9 (routable), got %s", ce.Step)
	}
	if !h.placer.freshCalled || h.placer.freshGotHost != "host-a" {
		t.Errorf("the live probe must be called on the placed host (host-a), got called=%v host=%q",
			h.placer.freshCalled, h.placer.freshGotHost)
	}
}

// TestCreate_Step9LiveProbeDegradesWhenUnavailable proves the §4.1 step-9 live probe is
// BACKWARDS COMPATIBLE: when no live-freshness probe is wired (CurrentFreshness returns
// ErrFreshnessUnknown), the routable gate DEGRADES to the recorded re-check alone (the
// pre-probe behavior) and a fresh-recorded host reaches READY/ATTACHED — an unavailable
// probe never hard-fails a create the recorded signal vouches for.
func TestCreate_Step9LiveProbeDegradesWhenUnavailable(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true) // freshErr defaults to ErrFreshnessUnknown (probe unavailable)
	c := h.creator(t)

	final, err := c.Create(ctx, authedReq("sess-degrade"))
	if err != nil {
		t.Fatalf("an unavailable live probe must degrade to the recorded re-check, not fail; got %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("degraded path final state = %q, want ATTACHED", final.State)
	}
	if !h.placer.freshCalled {
		t.Error("the step-9 gate must still consult the live probe (which reports unavailable)")
	}
}

// TestCreate_Step9DegradeEmitsObservable proves the §4.1 step-9 degrade-on-
// ErrFreshnessUnknown branch is OBSERVABLE (D72): when the live probe is unavailable and
// the gate degrades to the recorded re-check, it emits a log/metric so an unprobeable
// host admitted via the recorded re-check is never SILENT in production. We build the
// coordinator over a buffer-backed slog logger (not the nil → slog.Default path the
// other tests use) and assert the degrade record lands with the session + host fields.
func TestCreate_Step9DegradeEmitsObservable(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true) // freshErr defaults to ErrFreshnessUnknown (probe unavailable)

	var logBuf bytes.Buffer
	// Capture every level so the WARN degrade record is observable here.
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c, err := NewSessionCreator(h.seams, 0, logger)
	if err != nil {
		t.Fatalf("NewSessionCreator: %v", err)
	}
	c.clock = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	final, err := c.Create(ctx, authedReq("sess-degrade-obs"))
	if err != nil {
		t.Fatalf("an unavailable live probe must degrade to the recorded re-check, not fail; got %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("degraded path final state = %q, want ATTACHED", final.State)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "degrading to the recorded re-check") {
		t.Errorf("step-9 degrade branch must emit an observable degrade log; got logs:\n%s", logs)
	}
	if !strings.Contains(logs, "sess-degrade-obs") {
		t.Errorf("degrade log must name the session (sess-degrade-obs); got logs:\n%s", logs)
	}
	if !strings.Contains(logs, "host-a") {
		t.Errorf("degrade log must name the unprobeable host (host-a); got logs:\n%s", logs)
	}
}

// TestCreate_Step9DegradeIncrementsCounter proves the §4.1 step-9 degrade-on-
// ErrFreshnessUnknown branch increments the AGGREGATABLE freshness-degrade counter
// (D72) — the companion to the WARN log. A WARN line alone is not graphable/alertable;
// the counter makes the degrade RATE queryable. We capture the counter via the package
// metric seam (step9FreshnessDegradeCount, reading the expvar.Int's value) before and
// after a degrading create and assert it advanced by exactly one. The counter is a
// process-global expvar, so we assert on the DELTA (never the absolute value) to stay
// independent of any other test that took the same branch.
func TestCreate_Step9DegradeIncrementsCounter(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true) // freshErr defaults to ErrFreshnessUnknown (probe unavailable)
	c := h.creator(t)

	before := step9FreshnessDegradeCount()
	final, err := c.Create(ctx, authedReq("sess-degrade-counter"))
	if err != nil {
		t.Fatalf("an unavailable live probe must degrade to the recorded re-check, not fail; got %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("degraded path final state = %q, want ATTACHED", final.State)
	}
	if !h.placer.freshCalled {
		t.Error("the step-9 gate must still consult the live probe (which reports unavailable)")
	}
	if got := step9FreshnessDegradeCount() - before; got != 1 {
		t.Errorf("step-9 degrade branch must increment the freshness-degrade counter by exactly 1; delta = %d", got)
	}
}

// TestCreate_Step9NoDegradeLeavesCounterUnchanged proves the freshness-degrade counter
// only moves on the DEGRADE branch: when the live probe IS wired and answers with a
// fresh CURRENT seq (no ErrFreshnessUnknown), the gate runs the live re-check and the
// counter must NOT advance — the metric measures unprobeable-host admissions, not every
// routable gate. This pins the increment to the exact degrade branch (no over-count).
func TestCreate_Step9NoDegradeLeavesCounterUnchanged(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	// Wire the live probe: it answers with the SAME seq placement recorded (7), so the
	// live re-check passes and the gate never takes the degrade branch.
	h.placer.freshErr = nil
	h.placer.freshSeq = 7
	c := h.creator(t)

	before := step9FreshnessDegradeCount()
	final, err := c.Create(ctx, authedReq("sess-no-degrade-counter"))
	if err != nil {
		t.Fatalf("a fresh live probe must reach READY/ATTACHED, not fail; got %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("live-probe-fresh path final state = %q, want ATTACHED", final.State)
	}
	if got := step9FreshnessDegradeCount() - before; got != 0 {
		t.Errorf("the non-degrade (live probe answered) path must NOT increment the freshness-degrade counter; delta = %d", got)
	}
}

// TestCreate_Step9FreshnessFaultRefusesAndDoesNotDegrade proves the SESSIONS side of the
// D72 freshness asymmetry END-TO-END at the §4.1 step-9 routable gate: when the live
// probe (Placer.CurrentFreshness) returns a FAULT — a transport/feed error that is NOT
// ErrFreshnessUnknown — the routable gate HARD-FAILS the create (refuse, fail-closed) and
// does NOT bump the freshness-degrade counter. A fault is NOT a degrade: the degrade
// counter (and its WARN) is reserved for the ErrFreshnessUnknown "no live signal, fall
// back to the recorded re-check" path; a genuine probe fault has no recorded re-check to
// vouch for it (the probe answered with an ERROR, not "unknown"), so the gate must refuse
// rather than silently degrade-to-READY. This mirrors orch27's scheduler-side pin (a probe
// FAULT yields a non-ErrFreshnessUnknown error; only host-absent → ErrFreshnessUnknown →
// degrade) on the sessions create-gate side. It is paired with the absent-host degrade
// case below (TestCreate_Step9DegradeIncrementsCounter / ...PerHostKey: ErrFreshnessUnknown
// → degrade + counter++), so the two outcomes are pinned together: fault → refuse + NO
// counter bump; absent → degrade + counter++.
func TestCreate_Step9FreshnessFaultRefusesAndDoesNotDegrade(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	// Script a FAULT: the live probe answers with a transport/feed error that is NOT the
	// ErrFreshnessUnknown "no live signal" sentinel. This is the fault leg of the D72
	// asymmetry — the probe is wired and reachable enough to ERROR, but the error is not
	// the degrade-eligible "unknown" verdict.
	probeFault := errors.New("freshness feed transport error: connection reset")
	h.placer.freshErr = probeFault
	c := h.creator(t)

	before := step9FreshnessDegradeCount()
	beforeHost := step9FreshnessDegradeHostCount("host-a")
	_, err := c.Create(ctx, authedReq("sess-fresh-fault"))

	// (a) The create is REFUSED (fail-closed) — never a silent degrade-to-READY. The fault
	// propagates verbatim through the routable gate, stamped at step 9.
	if err == nil {
		t.Fatal("a freshness PROBE FAULT at step 9 must REFUSE the create (fail-closed), got nil error")
	}
	if !errors.Is(err, probeFault) {
		t.Fatalf("the create must fail with the underlying probe fault (fail-closed), got %v", err)
	}
	// A genuine probe fault is NOT the ErrFreshnessUnknown degrade verdict — assert the gate
	// did not misclassify it as the (degrade-eligible) unknown sentinel.
	if errors.Is(err, ErrFreshnessUnknown) {
		t.Fatalf("a probe FAULT must not be classified as ErrFreshnessUnknown (the degrade sentinel), got %v", err)
	}
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want a *CreateError, got %T: %v", err, err)
	}
	if ce.Step != StepRoutable {
		t.Errorf("a step-9 freshness fault must be stamped at step 9 (routable), got %s", ce.Step)
	}
	// The create rolled back cleanly (the fault is a normal create failure, not a teardown
	// fault) — the session never reached READY.
	if !ce.RolledBack {
		t.Errorf("a step-9 freshness-fault refusal must roll back cleanly, got RolledBack=false (RollbackErr=%v)", ce.RollbackErr)
	}
	rec, gerr := h.repo.GetSession(ctx, "sess-fresh-fault")
	if gerr != nil {
		t.Fatalf("post-refusal GetSession: %v", gerr)
	}
	if rec.State == store.SessionReady || rec.State == store.SessionAttached {
		t.Errorf("a refused create must NOT reach READY/ATTACHED; record state = %q", rec.State)
	}

	// (b) The degrade counter is NOT incremented — a fault is not a degrade. Assert on the
	// DELTA (the counters are process-global expvars) for both the flat fleet total and the
	// placed host's per-host key.
	if got := step9FreshnessDegradeCount() - before; got != 0 {
		t.Errorf("a freshness FAULT must NOT bump the freshness-degrade counter (a fault is not a degrade); delta = %d", got)
	}
	if got := step9FreshnessDegradeHostCount("host-a") - beforeHost; got != 0 {
		t.Errorf("a freshness FAULT must NOT bump the placed host's per-host degrade key; delta = %d", got)
	}
	// The probe WAS consulted on the placed host (the gate reached the live re-check and the
	// fault came from there, not from an earlier step).
	if !h.placer.freshCalled || h.placer.freshGotHost != "host-a" {
		t.Errorf("the live probe must have been called on the placed host (host-a) before the fault refused; called=%v host=%q",
			h.placer.freshCalled, h.placer.freshGotHost)
	}
}

// TestCreate_Step9AbsentHostDegradesAndBumpsCounter is the DEGRADE half of the D72
// asymmetry, pinned alongside the fault-refuses case above: when the live probe is
// UNAVAILABLE (ErrFreshnessUnknown — the host-absent / no-live-seam verdict), the routable
// gate DEGRADES to the recorded re-check (reaching READY/ATTACHED) AND bumps the freshness-
// degrade counter by exactly one. The pairing makes the two outcomes legible in one place:
// fault → refuse + NO counter bump (above); absent → degrade + counter++ (here).
func TestCreate_Step9AbsentHostDegradesAndBumpsCounter(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true) // freshErr defaults to ErrFreshnessUnknown (probe unavailable)
	c := h.creator(t)

	before := step9FreshnessDegradeCount()
	beforeHost := step9FreshnessDegradeHostCount("host-a")
	final, err := c.Create(ctx, authedReq("sess-absent-degrade"))
	if err != nil {
		t.Fatalf("an UNAVAILABLE (ErrFreshnessUnknown) probe must DEGRADE to the recorded re-check, not fail; got %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("the degrade path must reach ATTACHED; final state = %q", final.State)
	}
	if got := step9FreshnessDegradeCount() - before; got != 1 {
		t.Errorf("the degrade (ErrFreshnessUnknown) branch must bump the freshness-degrade counter by exactly 1; delta = %d", got)
	}
	if got := step9FreshnessDegradeHostCount("host-a") - beforeHost; got != 1 {
		t.Errorf("the degrade branch must bump the placed host's per-host key by exactly 1; delta = %d", got)
	}
}

// TestCreate_Step9DegradeIncrementsPerHostKey proves the §4.1 step-9 degrade-on-
// ErrFreshnessUnknown branch increments the PER-HOST expvar.Map keyed by the PLACED
// host_id (D72) — the companion to the flat fleet total. The flat total answers "how
// often does the fleet degrade?"; this per-host split answers WHICH host degraded, so an
// operator can tell a single host falling behind (one hot key) from a systemic outage
// (many keys climbing). We degrade a create placed on a uniquely-named host and assert
// (a) that host's key advanced by exactly one AND (b) the flat total advanced too (the
// pre-existing observable stays unbroken). The map is a process-global expvar, so we
// assert on the DELTA of the placed host's key (never the absolute value).
func TestCreate_Step9DegradeIncrementsPerHostKey(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true) // freshErr defaults to ErrFreshnessUnknown (probe unavailable)
	// Place on a uniquely-named host so the per-host key is unambiguous across the
	// process-global expvar.Map (no collision with another test's host key).
	const host = "host-perhost-degrade"
	h.placer.placement = Placement{HostID: host, AppliedSeq: 7}
	c := h.creator(t)

	beforeHost := step9FreshnessDegradeHostCount(host)
	beforeTotal := step9FreshnessDegradeCount()
	final, err := c.Create(ctx, authedReq("sess-perhost-degrade"))
	if err != nil {
		t.Fatalf("an unavailable live probe must degrade to the recorded re-check, not fail; got %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("degraded path final state = %q, want ATTACHED", final.State)
	}
	if h.placer.freshGotHost != host {
		t.Errorf("the live probe must run on the placed host %q, got %q", host, h.placer.freshGotHost)
	}
	if got := step9FreshnessDegradeHostCount(host) - beforeHost; got != 1 {
		t.Errorf("the step-9 degrade branch must increment the per-host key %q by exactly 1; delta = %d", host, got)
	}
	if got := step9FreshnessDegradeCount() - beforeTotal; got != 1 {
		t.Errorf("the flat fleet total must still advance by 1 alongside the per-host key (unbroken observable); delta = %d", got)
	}
}

// TestCreate_Step9DegradeTwoHostsDistinctKeys proves two DIFFERENT hosts degrading
// produce two DISTINCT per-host keys (D72): the whole point of the split is that an
// operator reads host-X and host-Y independently. We degrade one create on each of two
// uniquely-named hosts and assert each host's key advanced by exactly one while the
// OTHER host's key is untouched by that create — the keys never cross-contaminate.
func TestCreate_Step9DegradeTwoHostsDistinctKeys(t *testing.T) {
	ctx := context.Background()
	const hostX = "host-distinct-x"
	const hostY = "host-distinct-y"

	beforeX := step9FreshnessDegradeHostCount(hostX)
	beforeY := step9FreshnessDegradeHostCount(hostY)

	// Degrade a create placed on host X.
	hx := newHarness(t, true) // freshErr defaults to ErrFreshnessUnknown
	hx.placer.placement = Placement{HostID: hostX, AppliedSeq: 7}
	cx := hx.creator(t)
	if _, err := cx.Create(ctx, authedReq("sess-distinct-x")); err != nil {
		t.Fatalf("host X degrade create must succeed; got %v", err)
	}
	// After only host X degraded, X's key advanced, Y's is untouched.
	if got := step9FreshnessDegradeHostCount(hostX) - beforeX; got != 1 {
		t.Errorf("host X key must advance by 1 after its degrade; delta = %d", got)
	}
	if got := step9FreshnessDegradeHostCount(hostY) - beforeY; got != 0 {
		t.Errorf("host Y key must be UNTOUCHED by host X's degrade (distinct keys); delta = %d", got)
	}

	// Degrade a separate create placed on host Y.
	hy := newHarness(t, true)
	hy.placer.placement = Placement{HostID: hostY, AppliedSeq: 7}
	cy := hy.creator(t)
	if _, err := cy.Create(ctx, authedReq("sess-distinct-y")); err != nil {
		t.Fatalf("host Y degrade create must succeed; got %v", err)
	}
	// Now both keys reflect exactly their own single degrade — two distinct keys.
	if got := step9FreshnessDegradeHostCount(hostX) - beforeX; got != 1 {
		t.Errorf("host X key must stay at its single degrade after host Y degrades; delta = %d", got)
	}
	if got := step9FreshnessDegradeHostCount(hostY) - beforeY; got != 1 {
		t.Errorf("host Y key must advance by 1 after its own degrade; delta = %d", got)
	}
}

// staleAfterPlacement wraps the store to simulate a host falling behind AFTER
// placement: it lowers the recorded PolicyAppliedSeq on GetSession (the step-9
// re-check's read) so drift = placement.AppliedSeq - recorded exceeds the budget.
type staleAfterPlacement struct {
	inner   SessionRecordStore
	lowerTo int64
}

func (s staleAfterPlacement) CreateSession(ctx context.Context, x store.Session) (store.Session, error) {
	return s.inner.CreateSession(ctx, x)
}

func (s staleAfterPlacement) GetSession(ctx context.Context, u string) (store.Session, error) {
	rec, err := s.inner.GetSession(ctx, u)
	if err == nil {
		rec.PolicyAppliedSeq = s.lowerTo // the host fell behind after placement
	}
	return rec, err
}

func (s staleAfterPlacement) UpdateSession(ctx context.Context, u string, x store.SessionUpdate) (store.Session, error) {
	return s.inner.UpdateSession(ctx, u, x)
}

func (s staleAfterPlacement) AppendIndexEpoch(ctx context.Context, u string, e store.IndexEpoch) (store.Session, error) {
	return s.inner.AppendIndexEpoch(ctx, u, e)
}

// ----- §4.1 step-9 per-host degrade-map CARDINALITY GUARD (D72) -----

// mapKeyCount counts the live keys on an expvar.Map (via Do), so a test can assert the
// per-host degrade map's DISTINCT-key count stays bounded under the LRU guard.
func mapKeyCount(m *expvar.Map) int {
	n := 0
	m.Do(func(expvar.KeyValue) { n++ })
	return n
}

// mapKeyValue reads a single key's expvar.Int value off an expvar.Map (0 when the key is
// absent), so a test can assert exact per-host and overflow-bucket counts.
func mapKeyValue(m *expvar.Map, key string) int64 {
	if iv, ok := m.Get(key).(*expvar.Int); ok {
		return iv.Value()
	}
	return 0
}

// TestDegradeHostGuard_BoundedPastCap proves the cardinality guard (D72) bounds the
// per-host degrade map's DISTINCT-key count: past the cap, a NEW host evicts the
// LEAST-recently-degraded host (its accumulated count folded into the "__other__"
// overflow bucket) so the map size never exceeds cap+1 (the active set plus the overflow
// bucket). WITHIN the cap, every per-host key is EXACT. We drive a fresh guard over a
// fresh expvar.Map (isolated from the process-global degrade map) so the assertion is
// deterministic regardless of any other test.
func TestDegradeHostGuard_BoundedPastCap(t *testing.T) {
	m := expvar.NewMap("test_degrade_guard_bounded_" + t.Name())
	const cap = 3
	g := newDegradeHostGuard(m, cap)

	// Fill the active set exactly to the cap: host-0..host-2, each degraded once.
	for i := 0; i < cap; i++ {
		g.recordDegradeByHost(fmt.Sprintf("host-%d", i))
	}
	if got := mapKeyCount(m); got != cap {
		t.Fatalf("within the cap the map holds exactly one key per host; key count = %d, want %d", got, cap)
	}
	if mapKeyValue(m, degradeOverflowKey) != 0 {
		t.Errorf("no host should have overflowed yet; overflow bucket = %d, want 0", mapKeyValue(m, degradeOverflowKey))
	}
	for i := 0; i < cap; i++ {
		host := fmt.Sprintf("host-%d", i)
		if got := mapKeyValue(m, host); got != 1 {
			t.Errorf("within-cap per-host key %q must be exact; got %d, want 1", host, got)
		}
	}

	// Now degrade a host PAST the cap. host-0 is the least-recently-degraded (LRU), so it
	// is evicted and its count (1) folds into the overflow bucket; host-3 is admitted.
	g.recordDegradeByHost("host-3")
	if got := mapKeyCount(m); got != cap+1 {
		t.Fatalf("past the cap the map is bounded at cap+1 (active set + overflow); key count = %d, want %d", got, cap+1)
	}
	if mapKeyValue(m, "host-0") != 0 {
		t.Errorf("the LRU host (host-0) must be EVICTED (key removed); still present with %d", mapKeyValue(m, "host-0"))
	}
	if got := mapKeyValue(m, degradeOverflowKey); got != 1 {
		t.Errorf("the evicted host's count (1) must fold into the overflow bucket; overflow = %d, want 1", got)
	}
	if got := mapKeyValue(m, "host-3"); got != 1 {
		t.Errorf("the newly admitted host-3 must hold its own exact count; got %d, want 1", got)
	}
	// host-1 and host-2 (still in the active set) stay exact.
	if got := mapKeyValue(m, "host-1"); got != 1 {
		t.Errorf("retained host-1 must stay exact; got %d, want 1", got)
	}
	if got := mapKeyValue(m, "host-2"); got != 1 {
		t.Errorf("retained host-2 must stay exact; got %d, want 1", got)
	}

	// Drive MANY more distinct hosts: the map size must NEVER exceed cap+1, and every
	// evicted degrade must accumulate in the overflow bucket (no degrade lost).
	const extra = 50
	for i := 0; i < extra; i++ {
		g.recordDegradeByHost(fmt.Sprintf("churn-%d", i))
		if got := mapKeyCount(m); got > cap+1 {
			t.Fatalf("the map must stay bounded at cap+1 under churn; key count = %d after churn-%d", got, i)
		}
	}
	if got := mapKeyCount(m); got != cap+1 {
		t.Errorf("after sustained churn the map settles at exactly cap+1 keys; got %d, want %d", got, cap+1)
	}
	// Accounting: every degrade lands somewhere. Total degrades = cap (initial) + 1
	// (host-3) + extra (churn). Sum of all per-host keys + overflow must equal that.
	wantTotal := int64(cap + 1 + extra)
	var sum int64
	m.Do(func(kv expvar.KeyValue) {
		if iv, ok := kv.Value.(*expvar.Int); ok {
			sum += iv.Value()
		}
	})
	if sum != wantTotal {
		t.Errorf("no degrade may be lost: sum of all keys (incl. overflow) = %d, want %d", sum, wantTotal)
	}
}

// TestDegradeHostGuard_RepeatBumpRefreshesRecency proves that a repeated degrade of a
// host already in the active set (a) bumps its key EXACTLY (no over/under count) and
// (b) refreshes its LRU recency so it survives a later eviction that drops a host
// degraded LESS recently. This pins the "active set" semantics: a host that keeps
// degrading stays an exact key; a host that went quiet is the eviction candidate.
func TestDegradeHostGuard_RepeatBumpRefreshesRecency(t *testing.T) {
	m := expvar.NewMap("test_degrade_guard_recency_" + t.Name())
	const cap = 2
	g := newDegradeHostGuard(m, cap)

	g.recordDegradeByHost("host-a") // a: tick 1
	g.recordDegradeByHost("host-b") // b: tick 2 (active set full: {a,b})
	g.recordDegradeByHost("host-a") // a: tick 3 — a is now MORE recent than b; a's key = 2

	if got := mapKeyValue(m, "host-a"); got != 2 {
		t.Errorf("a repeated degrade must bump the live key exactly; host-a = %d, want 2", got)
	}

	// Admit a new host: b (least recently degraded, tick 2) must be the eviction victim,
	// NOT a (refreshed to tick 3). b's count (1) folds into overflow.
	g.recordDegradeByHost("host-c")
	if mapKeyValue(m, "host-b") != 0 {
		t.Errorf("the less-recently-degraded host-b must be evicted; still present with %d", mapKeyValue(m, "host-b"))
	}
	if got := mapKeyValue(m, "host-a"); got != 2 {
		t.Errorf("the recently-refreshed host-a must SURVIVE eviction with its exact count; got %d, want 2", got)
	}
	if got := mapKeyValue(m, degradeOverflowKey); got != 1 {
		t.Errorf("evicted host-b's count must fold into overflow; overflow = %d, want 1", got)
	}
	if got := mapKeyValue(m, "host-c"); got != 1 {
		t.Errorf("newly admitted host-c must hold its exact count; got %d, want 1", got)
	}
}

// TestDegradeHostGuard_OverflowKeyFoldsAdditively proves the reserved overflow key is
// ITSELF foldable: a degrade recorded directly against degradeOverflowKey (a host
// literally named "__other__", or a re-fold) is additive and consumes NO active-set slot,
// so the cap accounting is never thrown off by the bucket key. This is the defensive
// no-collision property the guard documents.
func TestDegradeHostGuard_OverflowKeyFoldsAdditively(t *testing.T) {
	m := expvar.NewMap("test_degrade_guard_overflow_" + t.Name())
	const cap = 2
	g := newDegradeHostGuard(m, cap)

	g.recordDegradeByHost(degradeOverflowKey) // overflow = 1, no active-set slot consumed
	g.recordDegradeByHost("host-a")           // active set: {a}
	g.recordDegradeByHost("host-b")           // active set: {a,b} — full
	g.recordDegradeByHost(degradeOverflowKey) // overflow = 2, STILL no eviction (not an active host)

	if got := mapKeyValue(m, degradeOverflowKey); got != 2 {
		t.Errorf("overflow-key degrades must fold additively; overflow = %d, want 2", got)
	}
	if got := mapKeyValue(m, "host-a"); got != 1 {
		t.Errorf("host-a must be untouched by the overflow-key folds; got %d, want 1", got)
	}
	if got := mapKeyValue(m, "host-b"); got != 1 {
		t.Errorf("host-b must be untouched (no eviction triggered by the overflow key); got %d, want 1", got)
	}
	// The active set is {a,b} (2) plus the overflow bucket — 3 keys total, NOT over cap+1.
	if got := mapKeyCount(m); got != cap+1 {
		t.Errorf("the overflow key never consumes an active-set slot; key count = %d, want %d", got, cap+1)
	}
}

// TestDegradeHostGuard_NonPositiveCapClamped proves the guard can never be configured
// into an unbounded state: a non-positive cap is clamped to 1 (the map holds at most the
// single most-recent host plus the overflow bucket), so a misconfiguration degrades to
// the strictest bound rather than disabling the guard.
func TestDegradeHostGuard_NonPositiveCapClamped(t *testing.T) {
	m := expvar.NewMap("test_degrade_guard_clamp_" + t.Name())
	g := newDegradeHostGuard(m, 0) // clamped to 1

	g.recordDegradeByHost("host-a")
	g.recordDegradeByHost("host-b") // evicts host-a → overflow
	g.recordDegradeByHost("host-c") // evicts host-b → overflow

	if got := mapKeyCount(m); got != 2 { // 1 active + overflow
		t.Errorf("a non-positive cap clamps to 1; key count = %d, want 2 (1 active + overflow)", got)
	}
	if got := mapKeyValue(m, "host-c"); got != 1 {
		t.Errorf("the single active slot holds the most-recent host-c; got %d, want 1", got)
	}
	if got := mapKeyValue(m, degradeOverflowKey); got != 2 {
		t.Errorf("the two evicted hosts fold into overflow; overflow = %d, want 2", got)
	}
}

// TestCreate_Step9DegradeFlatTotalUnaffectedByGuard proves the cardinality guard does NOT
// perturb the flat fleet total (D72): routing the per-host bump through the guard at the
// real step-9 degrade branch leaves step9FreshnessDegradeTotal counting EVERY degrade,
// exactly as before the guard existed. We drive two degrading creates (distinct hosts)
// through the FULL Create path (the process-global guard) and assert the flat total
// advanced by exactly 2 — the guard's eviction/overflow bookkeeping never touches it.
func TestCreate_Step9DegradeFlatTotalUnaffectedByGuard(t *testing.T) {
	ctx := context.Background()
	beforeTotal := step9FreshnessDegradeCount()

	h1 := newHarness(t, true) // freshErr defaults to ErrFreshnessUnknown (degrade branch)
	h1.placer.placement = Placement{HostID: "host-guard-total-1", AppliedSeq: 7}
	if _, err := h1.creator(t).Create(ctx, authedReq("sess-guard-total-1")); err != nil {
		t.Fatalf("degrade create 1 must succeed; got %v", err)
	}
	h2 := newHarness(t, true)
	h2.placer.placement = Placement{HostID: "host-guard-total-2", AppliedSeq: 7}
	if _, err := h2.creator(t).Create(ctx, authedReq("sess-guard-total-2")); err != nil {
		t.Fatalf("degrade create 2 must succeed; got %v", err)
	}

	if got := step9FreshnessDegradeCount() - beforeTotal; got != 2 {
		t.Errorf("the flat fleet total must count EVERY degrade, guard-untouched; delta = %d, want 2", got)
	}
}

// ----- §4.1 STEP-5 MINTED-CREDENTIAL EXPIRY CONSUMER LEG (D22/D82, doc 16 §5.4) -----

// TestCreate_MintExpiryThreadedOntoState proves the CONSUMER leg: a Minter that returns a
// NON-ZERO MintResult.Expiry threads that expiry out of the §4.1 step-5 seam call onto the
// create-coordinator session state, and hands it (with the session UUID) to the
// routable-window / teardown-re-mint bookkeeping sink (onMintExpiry) so a session whose
// minted credential expires is tracked for the routable window + teardown/re-mint (doc 16
// §5.4). orch24 added MintReply.Expiry to the controlplane MintClient seam result and orch28
// wired the producer leg; this asserts the consumer leg carries it forward (D22/D82). The
// hook is the in-package routable-window/teardown seam point until the §5.6 record grows a
// MintExpiry column.
func TestCreate_MintExpiryThreadedOntoState(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)

	wantExpiry := time.Unix(1_700_086_400, 0).UTC() // a real (non-zero) mint/CA TTL horizon
	h.minter.result = MintResult{IdentityRef: "id-ref", CARef: "ca-ref", Expiry: wantExpiry}

	c := h.creator(t)
	var gotSession string
	var gotExpiry time.Time
	var hookCalls int
	c.onMintExpiry = func(sessionUUID string, expiry time.Time) {
		hookCalls++
		gotSession, gotExpiry = sessionUUID, expiry
	}

	final, err := c.Create(ctx, authedReq("sess-expiry"))
	if err != nil {
		t.Fatalf("Create with a minted-credential expiry: %v", err)
	}
	// The create still completes normally (the expiry is additive bookkeeping, not a gate).
	if final.State != store.SessionAttached {
		t.Errorf("final state = %q, want ATTACHED (expiry threading must not perturb the create)", final.State)
	}
	// The expiry was handed to the routable-window / teardown bookkeeping EXACTLY ONCE,
	// for THIS session, with the value the Minter surfaced.
	if hookCalls != 1 {
		t.Fatalf("onMintExpiry called %d times, want exactly 1 (a non-zero expiry registers a TTL once)", hookCalls)
	}
	if gotSession != "sess-expiry" {
		t.Errorf("onMintExpiry session = %q, want sess-expiry", gotSession)
	}
	if !gotExpiry.Equal(wantExpiry) {
		t.Errorf("onMintExpiry expiry = %v, want %v (the minted-credential TTL threaded out of MintResult.Expiry)", gotExpiry, wantExpiry)
	}
	// The record shape stays frozen this leg — the expiry is carried on the in-package
	// coordinator state, not (yet) persisted as a §5.6 column. Identity/CA still landed.
	rec, err := h.repo.GetSession(ctx, "sess-expiry")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if rec.IdentityRef != "id-ref" || rec.CARef != "ca-ref" {
		t.Errorf("identity/CA not recorded alongside the expiry threading: id=%q ca=%q", rec.IdentityRef, rec.CARef)
	}
}

// TestCreate_ZeroMintExpiryTracksNoTeardown proves the ZERO/ABSENT expiry path: a Minter
// that returns MintResult with a ZERO Expiry (the not-set case a bare MintClient or a
// TTL-less proto produces) tracks NO TTL — the routable-window/teardown sink is NEVER
// called, so a session with no minted-credential TTL never schedules a spurious immediate
// teardown (doc 16 §5.4). The create still reaches ATTACHED exactly as before this field
// existed (backwards compatible — a Minter that never sets Expiry is unchanged).
func TestCreate_ZeroMintExpiryTracksNoTeardown(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	// The default minter (newHarness) returns MintResult with a ZERO Expiry — assert it
	// is indeed zero so the test pins the not-set case, not an accidental value.
	if !h.minter.result.Expiry.IsZero() {
		t.Fatalf("test setup: default minter expiry must be zero (the not-set case); got %v", h.minter.result.Expiry)
	}

	c := h.creator(t)
	var hookCalls int
	c.onMintExpiry = func(string, time.Time) { hookCalls++ }

	final, err := c.Create(ctx, authedReq("sess-no-expiry"))
	if err != nil {
		t.Fatalf("Create with a zero/absent minted-credential expiry: %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("final state = %q, want ATTACHED (a zero expiry must not perturb the create)", final.State)
	}
	// A zero expiry is the not-set case: NO TTL to track, so the teardown sink is never
	// called — no spurious immediate teardown for a session with no minted-credential TTL.
	if hookCalls != 0 {
		t.Errorf("onMintExpiry called %d times for a ZERO expiry, want 0 (no TTL to track, no spurious teardown)", hookCalls)
	}
}

// recordingMintExpirySink is a synthetic MintExpirySink (the constructor-injected
// teardown/re-mint seam): it RECORDS each (session, expiry) registration so a test can
// assert the routable-window/teardown sink fired (or did not) for a given session.
type recordingMintExpirySink struct {
	calls    []string // session UUIDs registered, in fire order
	lastWhen time.Time
}

func (s *recordingMintExpirySink) OnMintExpiry(sessionUUID string, expiry time.Time) {
	s.calls = append(s.calls, sessionUUID)
	s.lastWhen = expiry
}

// TestCreate_MintExpirySinkSeamFiresOnceWhenReady proves the REAL constructor-injected
// teardown/re-mint sink (CreateSeams.OnMintExpiry, D22/D82, doc 16 §5.4): a session
// whose mint surfaces a NON-ZERO expiry and whose create COMPLETES (durably READY +
// ATTACHED — past every rollback point) hands the routable-window/teardown bookkeeping
// the session UUID + the expiry horizon EXACTLY ONCE, via the seam wired at
// construction (not the test-only field). It is the routable gate: an expired credential
// re-mints on resume (doc 16 §5.4).
func TestCreate_MintExpirySinkSeamFiresOnceWhenReady(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)

	wantExpiry := time.Unix(1_700_086_400, 0).UTC()
	h.minter.result = MintResult{IdentityRef: "id-ref", CARef: "ca-ref", Expiry: wantExpiry}

	// Wire the REAL sink through the seam bundle (the production injection point), NOT the
	// test-only field — this proves CreateSeams.OnMintExpiry reaches the fire path.
	sink := &recordingMintExpirySink{}
	h.seams.OnMintExpiry = sink
	c := h.creator(t)

	final, err := c.Create(ctx, authedReq("sess-ready-expiry"))
	if err != nil {
		t.Fatalf("Create with a wired mint-expiry sink: %v", err)
	}
	if final.State != store.SessionAttached {
		t.Fatalf("final state = %q, want ATTACHED (the sink fires only for a COMPLETED create)", final.State)
	}
	// The teardown/re-mint sink registered the TTL exactly once, for THIS session, with
	// the minted-credential horizon the Minter surfaced.
	if len(sink.calls) != 1 {
		t.Fatalf("sink fired %d times, want exactly 1 (a non-zero expiry on a READY session registers a TTL once): %v", len(sink.calls), sink.calls)
	}
	if sink.calls[0] != "sess-ready-expiry" {
		t.Errorf("sink session = %q, want sess-ready-expiry", sink.calls[0])
	}
	if !sink.lastWhen.Equal(wantExpiry) {
		t.Errorf("sink expiry = %v, want %v (the minted-credential TTL threaded out of MintResult.Expiry)", sink.lastWhen, wantExpiry)
	}
}

// TestCreate_MintExpirySinkUnsetDefaultsNoOp proves the BACKWARDS-COMPATIBLE default: a
// coordinator wired with NO OnMintExpiry seam (CreateSeams.OnMintExpiry nil) installs
// the safe no-op sink — a create with a non-zero mint expiry completes ATTACHED without
// panicking and without any external teardown registration. A wiring that does not (yet)
// supply a teardown scheduler is unchanged from before this seam existed.
func TestCreate_MintExpirySinkUnsetDefaultsNoOp(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	h.minter.result = MintResult{IdentityRef: "id-ref", CARef: "ca-ref", Expiry: time.Unix(1_700_086_400, 0).UTC()}

	// No h.seams.OnMintExpiry wired — NewSessionCreator must fill the safe no-op so the
	// post-commit fire path never nil-checks. (h.creator does NOT install the test field.)
	if h.seams.OnMintExpiry != nil {
		t.Fatalf("test setup: OnMintExpiry must be nil to exercise the default no-op")
	}
	c := h.creator(t)

	final, err := c.Create(ctx, authedReq("sess-noop-sink"))
	if err != nil {
		t.Fatalf("Create with an unset (default no-op) mint-expiry sink: %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("final state = %q, want ATTACHED (the default no-op must not perturb the create)", final.State)
	}
}

// TestCreate_MintExpirySinkSkippedOnPostStep5Rollback is the IDEMPOTENCY-vs-ROLLBACK
// proof (D22/D82, doc 16 §5.4): a session whose mint (step 5) surfaced a non-zero expiry
// but whose create ROLLS BACK after step 5 (here a step-8 boot fault — post-mint, pre-
// READY) is DESTROYED, and the teardown/re-mint sink must NOT fire — there is no live
// session to expire, and the §4.2 step-5 rollback already revoked the identity/CA. A
// spurious teardown/re-mint for an already-destroyed session is exactly the footgun the
// post-commit fire point closes. The destroyer + revoker DID run (the real teardown), so
// the test pins that the session truly tore down while the expiry sink stayed silent.
func TestCreate_MintExpirySinkSkippedOnPostStep5Rollback(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true)
	h.minter.result = MintResult{IdentityRef: "id-ref", CARef: "ca-ref", Expiry: time.Unix(1_700_086_400, 0).UTC()}
	// Force a POST-step-5 fault: step 8 (boot) fails after the mint (step 5) landed, so
	// the create rolls back from a point where the credential WAS minted (and carries an
	// expiry) but the session never reached READY.
	h.boot.err = errors.New("boot failed")

	sink := &recordingMintExpirySink{}
	h.seams.OnMintExpiry = sink
	c := h.creator(t)

	_, err := c.Create(ctx, authedReq("sess-rollback-expiry"))
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError from a step-8 boot fault, got %T: %v", err, err)
	}
	if ce.Step != StepBoot {
		t.Fatalf("rolled back from step %s, want %s (the post-step-5 boot fault)", ce.Step, StepBoot)
	}
	if !ce.RolledBack {
		t.Fatalf("rollback did not complete cleanly: %v", ce.RollbackErr)
	}
	// The REAL teardown ran (the session was destroyed): host destroy + identity/CA
	// revoke both fired for this session.
	if len(h.destroyer.calls) != 1 || h.destroyer.calls[0] != "sess-rollback-expiry" {
		t.Errorf("host destroy = %v, want one destroy of sess-rollback-expiry (the §4.2 teardown)", h.destroyer.calls)
	}
	if len(h.revoker.calls) != 1 || h.revoker.calls[0] != "sess-rollback-expiry" {
		t.Errorf("identity/CA revoke = %v, want one revoke of sess-rollback-expiry (no leftover minted identity)", h.revoker.calls)
	}
	// The session was destroyed before READY — the teardown/re-mint sink must NOT have
	// fired (no spurious expiry teardown for an already-destroyed session). This is the
	// idempotency-vs-rollback contract.
	if len(sink.calls) != 0 {
		t.Fatalf("sink fired %d times for a rolled-back session, want 0 (no spurious teardown for a destroyed session): %v", len(sink.calls), sink.calls)
	}
	// And the record is finalized DESTROYED (the audit trail), confirming the session did
	// not survive — so a sink fire would have been for a dead session.
	rec, err := h.repo.GetSession(ctx, "sess-rollback-expiry")
	if err != nil {
		t.Fatalf("GetSession after rollback: %v", err)
	}
	if rec.State != store.SessionDestroyed {
		t.Errorf("record state = %q, want DESTROYED (the rolled-back session must not be live)", rec.State)
	}
}

// ----- §6.1 DIGEST-PUBLISH coordinator-level fail-closed gate (D73/D84) -----

// coordinatorDigestPubFake is a synthetic digestPublisher (the §6.1 mint-before-attach
// seam CreateSeams.DigestPublisher carries into the spine): it RECORDS the session it was
// driven for and returns a SCRIPTED outcome/error so a test can pin the coordinator-level
// routable gate. Routable controls the committed-ack bit; err scripts a transport-style
// fault. It is the coordinator-level counterpart of createspine_digest_test.go's spine-level
// fake — proving the gate holds through SessionCreator.Create, not only RunCreateSpine (D50).
type coordinatorDigestPubFake struct {
	routable bool
	err      error
	calls    []string // session UUIDs the coordinator drove the publish for
}

func (f *coordinatorDigestPubFake) PublishSessionDigests(_ context.Context, sessionUUID string) (DigestPublishOutcome, error) {
	f.calls = append(f.calls, sessionUUID)
	if f.err != nil {
		return DigestPublishOutcome{}, f.err
	}
	return DigestPublishOutcome{Routable: f.routable, ConsumerID: "consumer-a", BatchID: "batch-a"}, nil
}

// TestCreate_DigestPublishArmed_RoutableFalseWithholdsRoutable is the headline acceptance:
// with the §6.1 digest-publish step ARMED (DS_ORCH_DIGEST_PUBLISH_WIRE=1) and the
// coordinator's CreateSeams.DigestPublisher returning an UNCOMMITTED ack (Routable=false),
// SessionCreator.Create fails CLOSED — the routable seat is WITHHELD at the coordinator
// level (not just at the spine level createspine_test.go pins). The failure is attributed to
// the DIGEST step (ErrDigestNotRoutable), the record is finalized (never READY/ATTACHED), and
// the publisher WAS driven for this session (the seam threaded CreateSeams → CreateSpineRequest).
func TestCreate_DigestPublishArmed_RoutableFalseWithholdsRoutable(t *testing.T) {
	t.Setenv(DigestPublishWireFlag, "1") // ARM the §6.1 mint-before-attach gate
	ctx := context.Background()
	h := newHarness(t, true)
	pub := &coordinatorDigestPubFake{routable: false} // UNCOMMITTED ack — must fail closed
	h.seams.DigestPublisher = pub
	c := h.creator(t)

	final, err := c.Create(ctx, authedReq("sess-digest-unroutable"))

	// The create fails closed — no routable session is returned.
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError from an uncommitted digest ack, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrDigestNotRoutable) {
		t.Errorf("error = %v, want ErrDigestNotRoutable (the §6.1 fail-closed routable gate)", err)
	}
	if ce.Step != StepDigest {
		t.Errorf("failed at step %s, want %s (the digest-publish routable gate is attributed to the digest step)", ce.Step, StepDigest)
	}
	if final.State == store.SessionAttached || final.State == store.SessionReady {
		t.Errorf("returned session state = %q, want the routable seat WITHHELD (not READY/ATTACHED)", final.State)
	}

	// The coordinator drove the publish exactly once, for THIS session — proving the seam
	// threaded from CreateSeams.DigestPublisher into the spine's CreateSpineRequest.
	if len(pub.calls) != 1 || pub.calls[0] != "sess-digest-unroutable" {
		t.Fatalf("digest publisher calls = %v, want exactly one for sess-digest-unroutable", pub.calls)
	}

	// The record never became routable: it was finalized (the §4.1 1–3 record-only rollback),
	// so no session reached READY on an un-acked digest (mint-before-attach, doc 16 §6.1).
	rec, gerr := h.repo.GetSession(ctx, "sess-digest-unroutable")
	if gerr != nil {
		t.Fatalf("GetSession: %v", gerr)
	}
	if rec.State == store.SessionReady || rec.State == store.SessionAttached {
		t.Errorf("record state = %q, want NOT routable (finalized, never READY/ATTACHED)", rec.State)
	}
}

// TestCreate_DigestPublishArmed_RoutableTrueProceeds is the positive companion: ARMED with a
// COMMITTED ack (Routable=true), the digest gate is SATISFIED and the create proceeds through
// all ten steps to ATTACHED — the publisher does not stall a create whose digests landed.
func TestCreate_DigestPublishArmed_RoutableTrueProceeds(t *testing.T) {
	t.Setenv(DigestPublishWireFlag, "1") // ARM the §6.1 gate
	ctx := context.Background()
	h := newHarness(t, true)
	pub := &coordinatorDigestPubFake{routable: true} // COMMITTED ack — the gate passes
	h.seams.DigestPublisher = pub
	c := h.creator(t)

	final, err := c.Create(ctx, authedReq("sess-digest-routable"))
	if err != nil {
		t.Fatalf("Create with a committed digest ack: %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("final state = %q, want ATTACHED (a committed digest ack lets the create proceed)", final.State)
	}
	if len(pub.calls) != 1 || pub.calls[0] != "sess-digest-routable" {
		t.Fatalf("digest publisher calls = %v, want exactly one for sess-digest-routable", pub.calls)
	}
}

// TestCreate_DigestPublishArmed_TransportErrorFailsClosed proves the transport-fault leg: an
// ARMED publish that returns a plain ERROR (a transient transport fault, NOT the attributable
// uncommitted-ack verdict) also fails the create closed — a push that did not land never marks
// the session routable. Unlike the uncommitted-ack case, a transport fault is deliberately NOT
// classified as an ErrDigestNotRoutable verdict (digestpublish.go: the classifier distinguishes
// "the digests did not land" from "a transient transport fault"), so it surfaces at the generic
// spine-failure position — the load-bearing assertion is that the routable seat is WITHHELD.
func TestCreate_DigestPublishArmed_TransportErrorFailsClosed(t *testing.T) {
	t.Setenv(DigestPublishWireFlag, "1")
	ctx := context.Background()
	h := newHarness(t, true)
	pub := &coordinatorDigestPubFake{err: errors.New("digest feed unreachable")}
	h.seams.DigestPublisher = pub
	c := h.creator(t)

	final, err := c.Create(ctx, authedReq("sess-digest-transport"))
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CreateError from a digest transport fault, got %T: %v", err, err)
	}
	// A transport fault is NOT the attributable digest-not-routable verdict.
	if ErrIsDigestNotRoutable(err) {
		t.Errorf("ErrIsDigestNotRoutable(err) = true, want false (a transient transport fault is not the landed-gate verdict)")
	}
	// The routable seat is withheld all the same — the create never reached READY/ATTACHED.
	if final.State == store.SessionAttached || final.State == store.SessionReady {
		t.Errorf("returned session state = %q, want the routable seat WITHHELD on a digest transport fault", final.State)
	}
	if len(pub.calls) != 1 {
		t.Fatalf("digest publisher calls = %v, want exactly one (the armed step drove the publish)", pub.calls)
	}
}

// TestCreate_DigestPublishArmed_NilPublisherFailsClosed proves the armed-but-unwired leg at
// the COORDINATOR level: with the flag ARMED but CreateSeams.DigestPublisher left nil, the
// mint-before-attach gate cannot be satisfied, so the create fails closed
// (ErrDigestPublisherUnwired) rather than silently skipping the gate — the fail-closed posture
// the composition root (armDigestPublishWire) surfaces until a publisher is threaded.
func TestCreate_DigestPublishArmed_NilPublisherFailsClosed(t *testing.T) {
	t.Setenv(DigestPublishWireFlag, "1")
	ctx := context.Background()
	h := newHarness(t, true)
	// h.seams.DigestPublisher deliberately left nil (armed but unwired).
	c := h.creator(t)

	_, err := c.Create(ctx, authedReq("sess-digest-unwired"))
	if !errors.Is(err, ErrDigestPublisherUnwired) {
		t.Fatalf("error = %v, want ErrDigestPublisherUnwired (armed + nil publisher fails closed)", err)
	}
	if !ErrIsDigestNotRoutable(err) {
		t.Errorf("ErrIsDigestNotRoutable(err) = false, want true (the unwired gate is a digest fail-closed verdict)")
	}
}

// TestCreate_DigestPublishDisarmed_ByteIdenticalSkipsPublisher is the D50 default-off proof: with
// the flag UNSET (the wave default) the spine SKIPS the digest-publish step, so even a wired
// CreateSeams.DigestPublisher that would fail closed (Routable=false) is NEVER driven and the
// create completes exactly as the pre-wire happy path — byte-identical when off.
func TestCreate_DigestPublishDisarmed_ByteIdenticalSkipsPublisher(t *testing.T) {
	// Flag intentionally NOT set (default off).
	ctx := context.Background()
	h := newHarness(t, true)
	pub := &coordinatorDigestPubFake{routable: false} // would fail closed IF the step ran
	h.seams.DigestPublisher = pub
	c := h.creator(t)

	final, err := c.Create(ctx, authedReq("sess-digest-off"))
	if err != nil {
		t.Fatalf("Create with the digest-publish step disarmed: %v", err)
	}
	if final.State != store.SessionAttached {
		t.Errorf("final state = %q, want ATTACHED (disarmed create is the pre-wire happy path)", final.State)
	}
	if len(pub.calls) != 0 {
		t.Fatalf("digest publisher was driven %d times while disarmed, want 0 (the step is skipped, byte-identical D50): %v", len(pub.calls), pub.calls)
	}
}

// Compile-time proof the coordinator-level fake satisfies the §6.1 digest-publish seam the
// spine drives (the same interface the production DigestFeedPublisher implements).
var _ digestPublisher = (*coordinatorDigestPubFake)(nil)
