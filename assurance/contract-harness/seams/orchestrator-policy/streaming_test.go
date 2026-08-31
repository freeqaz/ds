// SPDX-License-Identifier: Apache-2.0

package orchestratorpolicy_test

import (
	"context"
	"testing"

	orchestratorpolicy "github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/orchestrator-policy"
)

// TestStreamingCancelLifecycle_RealVsFake is the per-commit gate for the
// WatchPolicies cancel + deadline lifecycle (the dimensions the content-shape
// scenarios in Suite() leave untested): the cancel/deadline scenarios — wired
// through the SHARED dualrun streaming affordance (dualrun.CancelAfterFrames /
// DeadlineAfterFrames) — run against BOTH the honest "real" end and the honest
// "fake" end, and the seam is green only if both honor cancellation identically
// (read exactly k frames, ZERO after, a context-cancellation terminal).
func TestStreamingCancelLifecycle_RealVsFake(t *testing.T) {
	res, err := orchestratorpolicy.StreamingCancelSuite().Run(context.Background(),
		orchestratorpolicy.LifecycleCancelHonestRealDialer(), orchestratorpolicy.LifecycleCancelHonestFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("WatchPolicies cancel-lifecycle seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero cancel-lifecycle scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestStreamingBackPressureLifecycle_RealVsFake is the per-commit gate for the
// WatchPolicies slow-consumer back-pressure lifecycle: the slow-consumer scenario
// (dualrun.SlowConsumer) runs real-vs-fake and is green only if both ends deliver
// the whole snapshot tail, in order, exactly once, to a clean EOF under a stalled
// consumer.
func TestStreamingBackPressureLifecycle_RealVsFake(t *testing.T) {
	res, err := orchestratorpolicy.StreamingBackPressureSuite().Run(context.Background(),
		orchestratorpolicy.LifecycleSlowHonestRealDialer(), orchestratorpolicy.LifecycleSlowHonestFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("WatchPolicies back-pressure-lifecycle seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero back-pressure-lifecycle scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestStreamingCancelLifecycle_HarnessCatchesACancelSwallowingStream is the negative
// proof for the cancel + deadline scenarios: a server that DEFEATS cancellation — it
// drains to a clean completion ignoring the client's cancelled context, so the
// client observes a clean OK terminal instead of the contracted context-cancellation
// — must fail the seam. Without this, a green cancel/deadline dual-run could be
// meaningless (the gate never fires on a non-conforming stream). The honest end
// surfaces Canceled; the swallowing end surfaces OK, so the dual-run DIVERGES on
// EVERY cancel/deadline scenario.
func TestStreamingCancelLifecycle_HarnessCatchesACancelSwallowingStream(t *testing.T) {
	res, err := orchestratorpolicy.StreamingCancelSuite().Run(context.Background(),
		orchestratorpolicy.LifecycleCancelHonestRealDialer(), orchestratorpolicy.LifecycleCancelDriftedDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a cancellation-swallowing stream passed the seam — the cancel/deadline gate is not firing")
	}
	diverged := map[string]bool{}
	for _, d := range res.Divergences {
		diverged[d.Scenario] = true
	}
	if !diverged["watch-policies/cancel-after-frames-stops-stream"] {
		t.Fatalf("expected the cancel scenario to diverge against the cancel-swallowing stream, report:\n%s", res.Report())
	}
	if !diverged["watch-policies/deadline-after-frames-stops-stream"] {
		t.Fatalf("expected the deadline scenario to diverge against the cancel-swallowing stream, report:\n%s", res.Report())
	}
}

// TestStreamingBackPressureLifecycle_HarnessCatchesABackPressureDefeatingStream is the
// negative proof for the slow-consumer scenario: a server that drops a mid-tail
// snapshot (so the delivered sequence is no longer gap-free and the count is short)
// must fail the seam on the slow-consumer scenario. Without this, a green
// slow-consumer dual-run could be passing merely because the gate never fires.
func TestStreamingBackPressureLifecycle_HarnessCatchesABackPressureDefeatingStream(t *testing.T) {
	res, err := orchestratorpolicy.StreamingBackPressureSuite().Run(context.Background(),
		orchestratorpolicy.LifecycleSlowHonestRealDialer(), orchestratorpolicy.LifecycleSlowDriftedDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a snapshot-dropping stream passed the seam — the slow-consumer gate is not firing")
	}
	diverged := map[string]bool{}
	for _, d := range res.Divergences {
		diverged[d.Scenario] = true
	}
	if !diverged["watch-policies/slow-consumer-honors-flow-control"] {
		t.Fatalf("expected the slow-consumer scenario to diverge against the dropping stream, report:\n%s", res.Report())
	}
}
