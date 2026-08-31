// SPDX-License-Identifier: Apache-2.0

package controlplane

// suspendwire_integration_test.go is the suspendwire wave's DS_ORCH_LIVE-gated end-to-end
// integration test (deliverable: "drives one suspend->resume and one golden create->attach
// end-to-end through the wired loop against the GENERATED fakes + synthetic fixtures").
//
// FENCED PER D50 — NO LIVE KVM / METAL / IDENTITY DIAL. The test is gated on DS_ORCH_LIVE
// purely to mark it the integration tier the wave's acceptance names; it runs ENTIRELY
// against the generated hypervisor.v1 fake + synthetic in-memory fakes (the same fixtures
// the unit tests use). CI gate-OFF SKIPS it (so the CI suite stays green via the in-process
// fakes — the unit tests already exercise every wired component), and gate-ON runs it
// against the fakes (never a live boundary/VM/cloud). The boundary SuspendSignal feed, the
// host Resume/Snapshot verbs, and the ApprovalPresence policy_log read are ALL satisfied by
// fakes here — the real-feed path stays exercised by fakes, exactly the wave constraint.

import (
	"context"
	"os"
	"testing"
	"time"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// fakeResumer satisfies sessions.Resumer (the in-place SUSPENDED->RESUMING->WORKING host
// Resume verb) — the verb the narrow production DriverClient seam does not carry, wired here
// as a recording fake (D50). It records the (host, session) it was driven for.
type fakeResumer struct {
	calls []struct{ host, session string }
	err   error
}

func (r *fakeResumer) Resume(_ context.Context, hostID, sessionUUID string) error {
	r.calls = append(r.calls, struct{ host, session string }{hostID, sessionUUID})
	return r.err
}

// fakeSnapshotter satisfies sessions.Snapshotter (the SNAPSHOTTING step of the >15-min D46
// escalation) as a recording fake (D50).
type fakeSnapshotter struct {
	calls []struct{ host, session string }
	err   error
}

func (s *fakeSnapshotter) Snapshot(_ context.Context, hostID, sessionUUID string) error {
	s.calls = append(s.calls, struct{ host, session string }{hostID, sessionUUID})
	return s.err
}

// suspendDeps builds a fully-wired Deps over the synthetic fakes WITH the suspend host verbs
// (Resumer/Snapshotter) + the boundary coordination sink + a permissive Approvals reader
// wired — so the suspend->resume path runs end-to-end. It mirrors newFixture's bundle (the
// production wiring path) and adds the suspend seams the in-place resume needs. D50 only.
func suspendDeps(t *testing.T, clock func() time.Time, resumer sessions.Resumer, snap sessions.Snapshotter, emitter SuspendCoordEmitter, approvals sessions.ApprovalPresence) (Deps, *store.Memory) {
	t.Helper()
	st := store.NewMemoryClock(clock)
	if _, err := st.PutEnvConfig(context.Background(), store.EnvConfig{
		Ref:     testEnvRef,
		RepoRef: testRepoID,
		ImageID: testImageID,
	}); err != nil {
		t.Fatalf("seed env config: %v", err)
	}
	heartbeats := NewHeartbeatStore(clock)
	heartbeats.Record(freshHeartbeat(testHostID, 0, 1))
	roleCatalog, rcErr := NewRoleCatalogServiceFromDir(testRolesDir, nil)
	if rcErr != nil {
		t.Fatalf("load role catalog: %v", rcErr)
	}
	return Deps{
		Store:          cpStore{st},
		Drivers:        fakeRegistry{host: testHostID, drv: newDriverFake()},
		Heartbeats:     heartbeats,
		Mint:           &fakeMint{},
		Digest:         &fakeDigest{acked: true},
		Inject:         &fakeInject{},
		Boot:           &fakeBoot{},
		Revoke:         &fakeRevoke{},
		Enrollment:     fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:          sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
		RoleCatalog:    roleCatalog,
		DefaultOrg:     testOrg,
		Clock:          clock,
		ResyncInterval: time.Hour,
		// the suspend wiring seams (the fenced components' production callers, fed by fakes here):
		Resumer:        resumer,
		Snapshotter:    snap,
		SuspendEmitter: emitter,
		Approvals:      approvals,
	}, st
}

// TestSuspendWire_Integration_SuspendResume_And_GoldenCreateAttach is the wave's end-to-end
// integration test: it drives (1) one boundary-signal suspend -> in-place resume and (2) one
// golden-image create -> attach, BOTH through the wired ControlPlane the production
// NewControlPlane assembles, against the generated fakes (D50, no live KVM/metal/Identity).
func TestSuspendWire_Integration_SuspendResume_And_GoldenCreateAttach(t *testing.T) {
	if os.Getenv("DS_ORCH_LIVE") != "1" {
		t.Skip("suspendwire integration test is DS_ORCH_LIVE-gated (runs against fakes, no live KVM); CI gate-off is covered by the unit tests")
	}
	ctx := context.Background()
	clock := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	resumer := &fakeResumer{}
	snap := &fakeSnapshotter{}
	emitter := &recordingEmitter{}
	approvals := permissiveApprovals{} // the policy_breach arm admits (a landed approval present)

	deps, st := suspendDeps(t, clock, resumer, snap, emitter, approvals)
	cp, err := NewControlPlane(deps)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	cp.Sessions.SetSessionUUIDGen(func() string { return "sess-int-1" })

	// Prove the fenced components got production callers (the acceptance grep, at the type level).
	if cp.ParkResume == nil || cp.Escalation == nil || cp.SuspendTerminator == nil || cp.SuspendCoord == nil || cp.FastStarter == nil {
		t.Fatal("NewControlPlane did not construct the wired suspend/instant-start components")
	}

	// ---- (1) GOLDEN CREATE -> ATTACH through the wired CreateSession handler (the FastStarter) ----
	resp, err := cp.Sessions.CreateSession(ctx, validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession (golden create->attach): %v", err)
	}
	sessUUID := resp.GetSession().GetSessionUuid()
	rec, err := st.GetSession(ctx, sessUUID)
	if err != nil {
		t.Fatalf("GetSession after create: %v", err)
	}
	if rec.State != store.SessionAttached {
		t.Fatalf("golden create left state %q, want ATTACHED", rec.State)
	}
	// The §8 create->attach timing trend recorded a per-create server span (measure-not-gate):
	if trend := cp.CreateTimingTrend(); trend.Count != 1 {
		t.Fatalf("CreateTimingTrend().Count = %d, want 1 (the golden create's §8 server span folded into the trend)", trend.Count)
	}

	// Advance ATTACHED -> WORKING (the legal §3 edge) so the session is suspendable.
	working := store.SessionWorking
	if _, err := st.UpdateSession(ctx, sessUUID, store.SessionUpdate{State: &working}); err != nil {
		t.Fatalf("advance to WORKING: %v", err)
	}

	// ---- (2) SUSPEND (terminate a boundary signal) -> in-place RESUME through cp.ParkResume ----
	sig := &boundaryv1.SuspendSignal{
		Session:       &boundaryv1.SessionRef{SessionUuid: sessUUID, HostId: testHostID},
		ReasonClass:   boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_BLOCKLIST_HIT,
		MatchedRuleId: "rule-int-1",
		PolicyLayer:   "org",
		PolicyVersion: 7,
		DedupKey:      "dedup-int-1",
	}
	acc, err := cp.SuspendTerminator.Accept(sig)
	if err != nil {
		t.Fatalf("SuspendTerminator.Accept: %v", err)
	}
	if acc.Request == nil {
		t.Fatal("first signal delivery must yield a SuspendRequest to drive")
	}
	if _, err := cp.ParkResume.Suspend(ctx, acc.Request); err != nil {
		t.Fatalf("ParkResume.Suspend: %v", err)
	}
	suspended, _ := st.GetSession(ctx, sessUUID)
	if suspended.State != store.SessionSuspended {
		t.Fatalf("after Suspend state = %q, want SUSPENDED", suspended.State)
	}
	if suspended.SuspendReason != store.SuspendReasonPolicyBreach {
		t.Fatalf("after Suspend reason = %q, want policy_breach (D77 BLOCKLIST_HIT->POLICY_BREACH)", suspended.SuspendReason)
	}

	// A re-delivery of the SAME dedup key is the idempotent no-op (Duplicate, no request).
	dupAcc, err := cp.SuspendTerminator.Accept(sig)
	if err != nil {
		t.Fatalf("SuspendTerminator.Accept (dup): %v", err)
	}
	if !dupAcc.Ack.Duplicate || dupAcc.Request != nil {
		t.Fatal("a re-delivered dedup key must be a deduped no-op (Duplicate, nil request)")
	}

	// In-place RESUME: the policy_breach arm admits via the permissive Approvals; the session
	// walks SUSPENDED -> RESUMING -> WORKING through the wired ParkResume + the fake Resumer.
	resumed, err := cp.ParkResume.Resume(ctx, sessUUID, sessions.ResumeAuthorityHumanApproval)
	if err != nil {
		t.Fatalf("ParkResume.Resume: %v", err)
	}
	if resumed.State != store.SessionWorking {
		t.Fatalf("after Resume state = %q, want WORKING", resumed.State)
	}
	if len(resumer.calls) != 1 || resumer.calls[0].session != sessUUID {
		t.Fatalf("Resumer drove %v, want one Resume for %s on its host", resumer.calls, sessUUID)
	}

	// ---- (3) the D46 escalation leg's HOLD coordination runs on the loop (no live boundary) ----
	// Re-suspend (a fresh dedup key) and drive one escalation sweep: the pause is at-instant
	// (the frozen clock), so it classifies TRANSPARENT and emits a HOLD_BEGIN coordination.
	sig2 := &boundaryv1.SuspendSignal{
		Session:       &boundaryv1.SessionRef{SessionUuid: sessUUID, HostId: testHostID},
		ReasonClass:   boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_ACTION_SUSPEND_RULE,
		MatchedRuleId: "rule-int-2",
		DedupKey:      "dedup-int-2",
	}
	acc2, err := cp.SuspendTerminator.Accept(sig2)
	if err != nil || acc2.Request == nil {
		t.Fatalf("SuspendTerminator.Accept (re-suspend): acc=%+v err=%v", acc2, err)
	}
	if _, err := cp.ParkResume.Suspend(ctx, acc2.Request); err != nil {
		t.Fatalf("ParkResume.Suspend (re-suspend): %v", err)
	}
	cp.Reconcile.escalateNow(ctx) // one escalation sweep on the loop's seam
	if len(emitter.updates) == 0 {
		t.Fatal("escalation sweep must emit a HOLD_BEGIN coordination for the transparent-tier SUSPENDED session")
	}
	last := emitter.updates[len(emitter.updates)-1]
	if last.GetSessionUuid() != sessUUID {
		t.Fatalf("HOLD_BEGIN session = %q, want %s", last.GetSessionUuid(), sessUUID)
	}
	if got := last.GetSuspendCoord().GetPhase(); got.String() == "" || !isHoldBegin(got) {
		t.Fatalf("escalation sweep emitted phase %v, want HOLD_BEGIN", got)
	}

	_ = snap // the snapshotter is wired (constructible) but the legal escalate-to-park drive is
	// not exercised here: the >15-min escalate tier from SUSPENDED has no legal frozen §3 path
	// (see reconcileloop.go escalateSweep — a §3-freeze decision, surfaced for a human ruling).
	_ = hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH
}

// permissiveApprovals is the test ApprovalPresence whose landed-approval read always
// admits — the policy_breach resume arm's "a genuine rung-2 approval landed" fixture (D50).
type permissiveApprovals struct{}

func (permissiveApprovals) HasLandedApproval(_ context.Context, _ string) (bool, error) {
	return true, nil
}

// isHoldBegin reports whether the phase is the HOLD_BEGIN coordination phase (named via the
// hostagent.v1 enum string to avoid importing the proto enum constant into this assertion).
func isHoldBegin(p interface{ String() string }) bool {
	return p.String() == "SUSPEND_COORD_PHASE_HOLD_BEGIN"
}
