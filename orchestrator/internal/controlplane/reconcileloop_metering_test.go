// SPDX-License-Identifier: Apache-2.0

package controlplane

// reconcileloop_metering_test.go pins the metering-wire insertions the reconcile loop
// hosts: the D81 create-timing recorder fold (RecordCreateTiming → the (b)-row
// ServerSpanTrend with client RTT EXCLUDED) and the meteringSink() seam the heartbeat
// ingest probes to arm its D37 sample fan-out. All synthetic; no live host (D50).

import (
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
)

// fullStack returns a complete synthetic §8 stack decomposition (all eight
// trigger-eligible segments), summing to a known server span.
func fullStack() (map[createtiming.Segment]time.Duration, time.Duration) {
	stack := map[createtiming.Segment]time.Duration{
		createtiming.SegPlacement:        1 * time.Millisecond,
		createtiming.SegOverlayClone:     2 * time.Millisecond,
		createtiming.SegTapNFT:           3 * time.Millisecond,
		createtiming.SegIdentityCADigest: 4 * time.Millisecond,
		createtiming.SegBootEntrypoint:   5 * time.Millisecond,
		createtiming.SegPolicyReady:      6 * time.Millisecond,
		createtiming.SegRoutable:         7 * time.Millisecond,
		createtiming.SegAttachHandshake:  8 * time.Millisecond,
	}
	return stack, 36 * time.Millisecond // 1+2+…+8
}

// TestReconcileLoop_CreateTimingFoldExcludesRTT is the headline createtiming metering-wire
// acceptance: with DS_ORCH_CREATETIMING_WIRE=1, folding one create's complete §8
// decomposition PLUS a large client RTT yields a server-span trend that EXCLUDES the RTT
// (the venue can never inflate the trigger-eligible stack span, doc 15 §8). The
// decomposition is asserted COMPLETE (no missing stack segment — the D81 existence bar).
func TestReconcileLoop_CreateTimingFoldExcludesRTT(t *testing.T) {
	t.Setenv(CreateTimingWireFlag, "1")

	loop := newReconcileLoop(nil, nil, 0, nil)
	if loop.createTiming == nil || !loop.createTiming.Enabled() {
		t.Fatal("flag-on loop did not self-arm the create-timing recorder")
	}

	stack, wantSpan := fullStack()
	// A client RTT far larger than the whole stack — if it leaked into the server span it
	// would dominate; the invariant is that it NEVER does.
	const clientRTT = 500 * time.Millisecond

	trend, missing, err := loop.RecordCreateTiming("sess-ct", stack, clientRTT)
	if err != nil {
		t.Fatalf("RecordCreateTiming: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("decomposition missing %v, want complete (all eight §8 stack segments)", missing)
	}
	if trend.Count != 1 {
		t.Fatalf("server-span trend Count = %d, want 1 (one folded create)", trend.Count)
	}
	// The recorded server span is the sum of the eight STACK segments ONLY — the 500ms
	// client RTT is excluded (doc 15 §8: RTT never enters ServerSpan/TriggerSpan).
	if got := trend.Max(); got != wantSpan {
		t.Errorf("server span = %v, want %v (the eight stack segments, client RTT excluded)", got, wantSpan)
	}
	if got := trend.Max(); got >= clientRTT {
		t.Errorf("server span %v absorbed the client RTT %v — RTT must be excluded from the trigger-eligible span", got, clientRTT)
	}
}

// TestReconcileLoop_CreateTimingFlagOffIsInert pins the default-off invariant: with the
// flag unset, RecordCreateTiming folds nothing and the server-span trend stays empty —
// byte-for-byte the pre-wire behavior.
func TestReconcileLoop_CreateTimingFlagOffIsInert(t *testing.T) {
	t.Setenv(CreateTimingWireFlag, "0")

	loop := newReconcileLoop(nil, nil, 0, nil)
	if loop.createTiming.Enabled() {
		t.Fatal("flag-off loop armed the create-timing recorder; want inert")
	}
	stack, _ := fullStack()
	trend, missing, err := loop.RecordCreateTiming("sess-off", stack, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("RecordCreateTiming(flag off): %v", err)
	}
	if missing != nil {
		t.Errorf("disabled fold reported missing %v, want nil (no decomposition folded)", missing)
	}
	if trend.Count != 0 {
		t.Errorf("disabled fold produced a trend with Count %d, want 0", trend.Count)
	}
	if loop.CreateTimingServerSpanTrend().Count != 0 {
		t.Error("disabled loop reported a non-empty server-span trend")
	}
}

// TestReconcileLoop_CreateTimingTrendAccumulates proves the recorder folds ACROSS creates
// (the "trends are recorded" half of D81): two folded creates yield a two-count
// server-span trend.
func TestReconcileLoop_CreateTimingTrendAccumulates(t *testing.T) {
	t.Setenv(CreateTimingWireFlag, "1")
	loop := newReconcileLoop(nil, nil, 0, nil)
	stack, _ := fullStack()

	if _, _, err := loop.RecordCreateTiming("sess-1", stack, 0); err != nil {
		t.Fatalf("RecordCreateTiming sess-1: %v", err)
	}
	if _, _, err := loop.RecordCreateTiming("sess-2", stack, 0); err != nil {
		t.Fatalf("RecordCreateTiming sess-2: %v", err)
	}
	if got := loop.CreateTimingServerSpanTrend().Count; got != 2 {
		t.Errorf("server-span trend Count = %d after two folds, want 2", got)
	}
}

// TestReconcileLoop_MeteringSinkFromEscalationLister proves the meteringSink() seam the
// heartbeat ingest probes: a control-plane loop wired the way NewControlPlane wires it
// (installEscalation with the single backing store as its lister) exposes that store as a
// metering.Sink, so the ingest can arm its D37 sample fan-out over the same store. A loop
// with no escalation leg installed exposes no sink (the not-yet-wired / gate-off posture).
func TestReconcileLoop_MeteringSinkFromEscalationLister(t *testing.T) {
	// A fixture builds the loop through NewControlPlane, which installs the escalation leg
	// with the single backing store as the lister (wiring.go).
	f := newFixture(t, fixtureOpts{})
	if f.cp.Reconcile.meteringSink() == nil {
		t.Fatal("a control-plane loop must expose its backing store as a metering sink (the ingest's D37 fan-out seam)")
	}

	// A bare loop with no escalation leg installed exposes no sink.
	bare := newReconcileLoop(nil, nil, 0, nil)
	if bare.meteringSink() != nil {
		t.Error("a loop with no escalation leg installed must expose no metering sink")
	}
}
