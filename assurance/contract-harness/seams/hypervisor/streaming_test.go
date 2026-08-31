// SPDX-License-Identifier: Apache-2.0

package hypervisor_test

import (
	"context"
	"testing"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/hypervisor"
)

// TestStreamingCancelLifecycle_RealVsFake is the per-commit gate for the
// ExportDiskDelta cancel + deadline lifecycle (the dimensions the content-shape
// scenarios in Suite() leave untested): the cancel/deadline scenarios — wired
// through the SHARED dualrun streaming affordance (dualrun.CancelAfterFrames /
// DeadlineAfterFrames) — run against BOTH the honest "real" end and the honest
// "fake" end, and the seam is green only if both honor cancellation identically
// (read exactly k frames, ZERO after, a context-cancellation terminal).
func TestStreamingCancelLifecycle_RealVsFake(t *testing.T) {
	res, err := hypervisor.StreamingCancelSuite().Run(context.Background(),
		hypervisor.LifecycleCancelHonestRealDialer(), hypervisor.LifecycleCancelHonestFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("ExportDiskDelta cancel-lifecycle seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero cancel-lifecycle scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestStreamingBackPressureLifecycle_RealVsFake is the per-commit gate for the
// ExportDiskDelta slow-consumer back-pressure lifecycle: the slow-consumer scenario
// (dualrun.SlowConsumer) runs real-vs-fake and is green only if both ends deliver
// the whole tail, in order, exactly once, to a clean EOF under a stalled consumer.
func TestStreamingBackPressureLifecycle_RealVsFake(t *testing.T) {
	res, err := hypervisor.StreamingBackPressureSuite().Run(context.Background(),
		hypervisor.LifecycleSlowHonestRealDialer(), hypervisor.LifecycleSlowHonestFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("ExportDiskDelta back-pressure-lifecycle seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero back-pressure-lifecycle scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestStreamingCancelLifecycle_HarnessCatchesAFloodingStream is the negative proof
// for the cancel + deadline scenarios: a server that DEFEATS cancellation — it
// ignores the client's cancelled context and keeps flooding frames — must fail the
// seam. Without this, a green cancel/deadline dual-run could be meaningless (the gate
// never fires on a non-conforming stream). The honest end stops on cancel; the flood
// end keeps sending, so the dual-run DIVERGES on EVERY cancel/deadline scenario.
func TestStreamingCancelLifecycle_HarnessCatchesAFloodingStream(t *testing.T) {
	res, err := hypervisor.StreamingCancelSuite().Run(context.Background(),
		hypervisor.LifecycleCancelHonestRealDialer(), hypervisor.LifecycleCancelDriftedDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a cancellation-ignoring flood passed the seam — the cancel/deadline gate is not firing")
	}
	diverged := map[string]bool{}
	for _, d := range res.Divergences {
		diverged[d.Scenario] = true
	}
	if !diverged["export-disk-delta/cancel-after-frames-stops-stream"] {
		t.Fatalf("expected the cancel scenario to diverge against the flooding stream, report:\n%s", res.Report())
	}
	if !diverged["export-disk-delta/deadline-after-frames-stops-stream"] {
		t.Fatalf("expected the deadline scenario to diverge against the flooding stream, report:\n%s", res.Report())
	}
}

// TestStreamingBackPressureLifecycle_HarnessCatchesADroppingStream is the negative
// proof for the slow-consumer scenario: a server that drops a mid-tail frame (so the
// delivered sequence is no longer gap-free and the count is short) must fail the
// seam on the slow-consumer scenario. Without this, a green slow-consumer dual-run
// could be passing merely because the gate never fires.
func TestStreamingBackPressureLifecycle_HarnessCatchesADroppingStream(t *testing.T) {
	res, err := hypervisor.StreamingBackPressureSuite().Run(context.Background(),
		hypervisor.LifecycleSlowHonestRealDialer(), hypervisor.LifecycleSlowDriftedDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a frame-dropping stream passed the seam — the slow-consumer gate is not firing")
	}
	diverged := map[string]bool{}
	for _, d := range res.Divergences {
		diverged[d.Scenario] = true
	}
	if !diverged["export-disk-delta/slow-consumer-honors-flow-control"] {
		t.Fatalf("expected the slow-consumer scenario to diverge against the dropping stream, report:\n%s", res.Report())
	}
}

// TestStreamingBackPressureLifecycle_HarnessCatchesAReorderingStream is the in-order
// sibling of the dropping negative proof: a server that delivers the SAME total set of
// frames but PERMUTES their order (emits frame i+1 before i) must fail the seam on the
// slow-consumer scenario via the drained_in_order observation — even though
// frames_total is UNCHANGED. Without this, the slow-consumer gate's in-order check is
// only proven jointly with its count check (the dropping drift trips both at once); a
// buffer-reordering fake that keeps the count correct would slip through. This proves
// the in-order observation bites INDEPENDENTLY of the count observation.
func TestStreamingBackPressureLifecycle_HarnessCatchesAReorderingStream(t *testing.T) {
	res, err := hypervisor.StreamingBackPressureSuite().Run(context.Background(),
		hypervisor.LifecycleSlowHonestRealDialer(), hypervisor.LifecycleSlowReorderDriftedDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a frame-reordering stream passed the seam — the slow-consumer in-order gate is not firing")
	}
	var slow *dualrun.Divergence
	for i := range res.Divergences {
		if res.Divergences[i].Scenario == "export-disk-delta/slow-consumer-honors-flow-control" {
			slow = &res.Divergences[i]
		}
	}
	if slow == nil {
		t.Fatalf("expected the slow-consumer scenario to diverge against the reordering stream, report:\n%s", res.Report())
	}
	// The reorder is isolated to the in-order observation: of the slow-consumer
	// observation keys, ONLY drained_in_order may differ between the honest (real) and
	// reordering (fake) ends. frames_total and frames_total_matches_expected (the count
	// observations) MUST agree — proving the in-order observation bites on its own, not
	// as a side effect of a short count (which is what the dropping drift trips).
	real, fake := dualrun.ParseObs(slow.Real), dualrun.ParseObs(slow.Fake)
	differing := dualrun.DifferingKeys(real, fake)
	if len(differing) != 1 || differing[0] != "drained_in_order" {
		t.Fatalf("reorder must isolate the in-order observation: expected ONLY drained_in_order to differ, got %v\n  real: %s\n  fake: %s", differing, slow.Real, slow.Fake)
	}
	if real["drained_in_order"] != "true" || fake["drained_in_order"] != "false" {
		t.Fatalf("expected honest drained_in_order=true vs reorder drained_in_order=false, got real=%q fake=%q", real["drained_in_order"], fake["drained_in_order"])
	}
	if real["frames_total"] != fake["frames_total"] {
		t.Fatalf("reorder must keep frames_total UNCHANGED, but real=%q fake=%q", real["frames_total"], fake["frames_total"])
	}
	if real["frames_total_matches_expected"] != fake["frames_total_matches_expected"] {
		t.Fatalf("reorder must keep frames_total_matches_expected UNCHANGED, but real=%q fake=%q", real["frames_total_matches_expected"], fake["frames_total_matches_expected"])
	}
}

// TestStreamingBackPressureLifecycle_HarnessCatchesADuplicatingStream is the
// count-over sibling of the dropping (count-short) and reordering (count-correct)
// negative proofs — the third corner of the exactly-once back-pressure contract: a
// server that delivers every frame in order but RE-EMITS one mid-tail frame (so the
// delivered count is expected+1) must fail the seam on the slow-consumer scenario via
// the frames_total / frames_total_matches_expected observation. Without this, the
// over-count direction of the count check is never exercised in isolation — the
// dropping drift only proves the SHORT direction. The repeated frame also breaks the
// strictly-increasing order, so drained_in_order flips too; the load-bearing,
// uniquely-duplicate signal is the OVER count.
func TestStreamingBackPressureLifecycle_HarnessCatchesADuplicatingStream(t *testing.T) {
	res, err := hypervisor.StreamingBackPressureSuite().Run(context.Background(),
		hypervisor.LifecycleSlowHonestRealDialer(), hypervisor.LifecycleSlowDuplicateDriftedDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a frame-duplicating stream passed the seam — the slow-consumer count gate is not firing")
	}
	var slow *dualrun.Divergence
	for i := range res.Divergences {
		if res.Divergences[i].Scenario == "export-disk-delta/slow-consumer-honors-flow-control" {
			slow = &res.Divergences[i]
		}
	}
	if slow == nil {
		t.Fatalf("expected the slow-consumer scenario to diverge against the duplicating stream, report:\n%s", res.Report())
	}
	// The duplicate trips the count-over observation: frames_total is OVER by one and
	// frames_total_matches_expected flips to false. Assert the count is the honest
	// total plus exactly one (the over-by-one signature), and that the honest end's
	// count DID match expected while the duplicating end's does not.
	real, fake := dualrun.ParseObs(slow.Real), dualrun.ParseObs(slow.Fake)
	if real["frames_total_matches_expected"] != "true" {
		t.Fatalf("expected honest frames_total_matches_expected=true, got %q", real["frames_total_matches_expected"])
	}
	if fake["frames_total_matches_expected"] != "false" {
		t.Fatalf("expected duplicating frames_total_matches_expected=false, got %q", fake["frames_total_matches_expected"])
	}
	realN, fakeN := dualrun.AtoiObs(t, real["frames_total"]), dualrun.AtoiObs(t, fake["frames_total"])
	if fakeN != realN+1 {
		t.Fatalf("duplicate must deliver frames_total OVER by exactly one: honest=%d duplicating=%d", realN, fakeN)
	}
}
