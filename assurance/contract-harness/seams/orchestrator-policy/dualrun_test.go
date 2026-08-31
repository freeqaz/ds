// SPDX-License-Identifier: Apache-2.0

package orchestratorpolicy_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	orchestratorpolicy "github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/orchestrator-policy"

	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"
)

// TestSeam_RealVsGeneratedFake is the per-commit gate for the orchestrator.v1
// PolicyService seam (doc 15 §5.3 / §11, doc 06 §2.1): the seam's conformance
// suite runs against BOTH the real reference implementation AND the generated
// programmable fake, and the seam is green only if every scenario observes the
// same thing on both. The suite exercises all three verbs (AppendPolicy,
// WatchPolicies, ApproveAsk) and the properties the policy_log seam turns on —
// the monotonic gap-free bigserial seq as THE single policy version namespace,
// WatchPolicies(from_seq) snapshot-then-delta serving, resumability from an
// arbitrary cursor, the empty past-the-tail catch-up, and the (seq, content_hash,
// document) snapshot identity shape.
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := orchestratorpolicy.Suite().Run(context.Background(), orchestratorpolicy.RealDialer(), orchestratorpolicy.FakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("orchestrator<->policy seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_HarnessCatchesADriftedFake is the negative proof: a fake that drifts
// from the contract — here, a WatchPolicies that SKIPS a seq in its catch-up,
// violating the gap-free monotonic bigserial invariant the policy version
// namespace depends on (doc 15 §5.3, D72) — must fail the seam. Without this, a
// green dual-run would be meaningless: it could be passing because the gate never
// fires. The drift is injected only in this test's local fake, never in the
// committed generated fake.
func TestSeam_HarnessCatchesADriftedFake(t *testing.T) {
	res, err := orchestratorpolicy.Suite().Run(context.Background(), orchestratorpolicy.RealDialer(), driftedSeqSkipFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a drifted fake passed the seam — the dual-run gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or fake error, got report:\n%s", res.Report())
	}
}

// TestSeq_RecordedViaFakeAccessors asserts the policy_log audit-trail contract
// directly against the generated fake's per-verb *Recorded() call-capture
// accessors (doc 15 §5.3, D36): every AppendPolicy / ApproveAsk that hits the
// fake is recorded with its actor, and the assigned seqs are monotonic and
// gap-free across the SHARED bigserial namespace (an org-edit followed by an
// ask-grant advance the same log by one each). This is the assertion the dual-run
// alone cannot make: the dual-run compares end-observable outcomes; the
// recorded-call surface is what lets a downstream consumer verify "the log was
// appended to in this order, by these actors".
func TestSeq_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()
	f := orchestratorv1fake.NewPolicyServiceFake()

	mirror := orchestratorpolicy.NewRefImpl()
	f.AppendPolicyResponder = mirror.AppendPolicy
	f.ApproveAskResponder = mirror.ApproveAsk

	const actorOrg = "actor-synthetic-org-admin"
	const actorAppr = "actor-synthetic-approver"

	edit, err := f.AppendPolicy(ctx, &orchestratorv1.AppendPolicyRequest{Actor: actorOrg, Scope: "org/synthetic", Document: []byte("layer-synthetic-1")})
	if err != nil {
		t.Fatalf("AppendPolicy: %v", err)
	}
	grant, err := f.ApproveAsk(ctx, &orchestratorv1.ApproveAskRequest{
		Actor:       actorAppr,
		SessionUuid: "ses-9ra919ra-0000-4000-8000-aaaaaaaaaaaa",
		ToolUseId:   "toolu-synthetic-cafef00d",
		GrantScope:  "allow-once:synthetic-domain",
		TtlSeconds:  300,
	})
	if err != nil {
		t.Fatalf("ApproveAsk: %v", err)
	}

	// The grant rides the SAME bigserial namespace: its seq is the edit's + 1
	// (gap-free, monotonic — doc 15 §4.3).
	if grant.GetRow().GetSeq() != edit.GetRow().GetSeq()+1 {
		t.Fatalf("ask-grant seq not gap-free on the shared log: edit=%d grant=%d",
			edit.GetRow().GetSeq(), grant.GetRow().GetSeq())
	}
	if got := grant.GetRow().GetKind(); got != orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ASK_GRANT {
		t.Fatalf("ask-grant row kind = %v, want ASK_GRANT", got)
	}

	// The recorder captured both calls, each carrying its actor.
	appendCalls := f.AppendPolicyRecorded()
	if len(appendCalls) != 1 {
		t.Fatalf("AppendPolicyRecorded: want 1, got %d", len(appendCalls))
	}
	if got := appendCalls[0].Req.GetActor(); got != actorOrg {
		t.Fatalf("AppendPolicyRecorded[0].actor = %q, want %q", got, actorOrg)
	}
	grantCalls := f.ApproveAskRecorded()
	if len(grantCalls) != 1 {
		t.Fatalf("ApproveAskRecorded: want 1, got %d", len(grantCalls))
	}
	if got := grantCalls[0].Req.GetActor(); got != actorAppr {
		t.Fatalf("ApproveAskRecorded[0].actor = %q, want %q", got, actorAppr)
	}
}

// driftedSeqSkipFakeDialer programs the generated fake with an honest
// AppendPolicy / ApproveAsk but a deliberately wrong WatchPolicies responder that
// DROPS the first frame of its catch-up — so the delivered seqs are no longer
// gap-free (they start at seq 2, skipping seq 1). All other verbs are programmed
// honestly so the divergence is attributable to the injected seq-skip drift.
func driftedSeqSkipFakeDialer() dualrun.Dialer {
	f := orchestratorv1fake.NewPolicyServiceFake()
	mirror := orchestratorpolicy.NewRefImpl()
	orchestratorpolicy.SeedLog(mirror)

	f.AppendPolicyResponder = mirror.AppendPolicy
	f.ApproveAskResponder = mirror.ApproveAsk
	f.WatchPoliciesResponder = func(_ context.Context, req *orchestratorv1.WatchPoliciesRequest) ([]*orchestratorv1.WatchPoliciesResponse, error) {
		// Honest in EVERY respect except the injected seq-skip: the host_id
		// validation is mirrored too (the honest FakeDialer refuses an empty
		// host_id, D72), so the ONLY divergence this drifted fake produces is the
		// gap-free violation — the negative test isolates exactly one defect.
		if req.GetHostId() == "" {
			return nil, status.Error(codes.InvalidArgument, "WatchPoliciesRequest.host_id is required (EXACTLY ONE subscriber per host, D72)")
		}
		frames := orchestratorpolicy.WrapSnapshots(mirror.SnapshotsFrom(req.GetFromSeq()))
		// DRIFT: drop the first catch-up frame — the gap-free monotonic seq
		// invariant the policy version namespace depends on is now broken.
		if len(frames) > 0 {
			frames = frames[1:]
		}
		return frames, nil
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		orchestratorv1fake.RegisterPolicyService(s, f)
	})
}
