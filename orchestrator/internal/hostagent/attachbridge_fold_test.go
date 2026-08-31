// SPDX-License-Identifier: Apache-2.0

package hostagent

// attachbridge_fold_test.go pins the createtiming-serving-wire deliverable: the host attach-leg
// producer (FoldAttachSegment) threads its measured SegAttachHandshake §8 segment (via
// AttachSegmentStack) into the create-side RecordCreateTiming fold. It proves the folded timing
// carries a NON-ZERO attach segment when the wire is armed, and the default-off byte-identical
// no-op (nothing measured ⇒ no fold, sink untouched). No live process (D50) — the offline
// no-launch path carries the measurement exactly as the live path would.

import (
	"context"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// fakeFoldSink captures the last stack handed to RecordCreateTiming so the test asserts the
// folded attach segment. It satisfies createTimingFoldSink by structure (the same shape the
// control-plane reconcile loop satisfies natively) without importing the control-plane package.
type fakeFoldSink struct {
	calls      int
	lastUUID   string
	lastStack  map[createtiming.Segment]time.Duration
	lastRTT    time.Duration
	returnErr  error
	trendCount int
}

func (f *fakeFoldSink) RecordCreateTiming(sessionUUID string, stack map[createtiming.Segment]time.Duration, clientRTT time.Duration) (createtiming.Trend, []createtiming.Segment, error) {
	f.calls++
	f.lastUUID = sessionUUID
	f.lastStack = stack
	f.lastRTT = clientRTT
	if f.returnErr != nil {
		return createtiming.Trend{}, nil, f.returnErr
	}
	f.trendCount++
	return createtiming.Trend{Segment: createtiming.SegAttachHandshake, Count: f.trendCount}, nil, nil
}

// TestAttachBridge_FoldAttachSegment_FlagOnCarriesNonZeroSegment is the headline: with
// DS_ORCH_CREATETIMING_WIRE=1, a served session's measured attach-leg segment folds into the
// sink's RecordCreateTiming as a non-zero SegAttachHandshake stack entry, with the client RTT
// carried separately (excluded from the stack, doc 15 §8).
func TestAttachBridge_FoldAttachSegment_FlagOnCarriesNonZeroSegment(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "") // offline no-launch (measurement is substrate-independent)
	t.Setenv(createTimingWireFlag, "1")    // create-timing wire ON

	b := NewAttachBridge(AttachBridgeConfig{SocketDir: "/run/ds/attach"})
	const sess = "sess-fold-on"

	if _, err := b.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured); err != nil {
		t.Fatalf("Serve (flag on): %v", err)
	}

	sink := &fakeFoldSink{}
	const rtt = 7 * time.Millisecond
	trend, ok, err := b.FoldAttachSegment(sink, sess, rtt)
	if err != nil {
		t.Fatalf("FoldAttachSegment: %v", err)
	}
	if !ok {
		t.Fatal("FoldAttachSegment reported ok=false, want a folded attach segment")
	}
	if sink.calls != 1 {
		t.Fatalf("sink RecordCreateTiming called %d times, want 1", sink.calls)
	}
	if sink.lastUUID != sess {
		t.Errorf("folded session = %q, want %q", sink.lastUUID, sess)
	}
	if sink.lastRTT != rtt {
		t.Errorf("folded client RTT = %v, want %v (carried separately, RTT excluded from stack)", sink.lastRTT, rtt)
	}
	d, present := sink.lastStack[createtiming.SegAttachHandshake]
	if !present {
		t.Fatalf("folded stack missing SegAttachHandshake, got %v", sink.lastStack)
	}
	if d <= 0 {
		t.Errorf("folded attach segment duration = %v, want a non-zero measured span", d)
	}
	// The stack the host reports is exactly its single attach-leg fragment (RTT never enters it).
	if _, rttInStack := sink.lastStack[createtiming.SegClientRTT]; rttInStack {
		t.Error("folded stack contains SegClientRTT, want it carried separately (RTT excluded)")
	}
	if trend.Count == 0 {
		t.Error("folded trend Count = 0, want the recorder to have folded the attach segment")
	}
}

// TestAttachBridge_FoldAttachSegment_DefaultOffNoOp is the byte-identical default-off pin: with
// the wire UNSET, nothing was measured, so FoldAttachSegment never touches the sink and reports
// ok=false — the fold is inert on the flag.
func TestAttachBridge_FoldAttachSegment_DefaultOffNoOp(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "")
	t.Setenv(createTimingWireFlag, "") // create-timing wire OFF (the default)

	b := NewAttachBridge(AttachBridgeConfig{SocketDir: "/run/ds/attach"})
	const sess = "sess-fold-off"

	if _, err := b.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured); err != nil {
		t.Fatalf("offline Serve: %v", err)
	}

	sink := &fakeFoldSink{}
	trend, ok, err := b.FoldAttachSegment(sink, sess, 3*time.Millisecond)
	if err != nil {
		t.Fatalf("FoldAttachSegment (flag off): %v", err)
	}
	if ok {
		t.Error("FoldAttachSegment reported ok=true with the wire off, want no fold")
	}
	if sink.calls != 0 {
		t.Errorf("sink RecordCreateTiming called %d times with the wire off, want 0 (fold inert)", sink.calls)
	}
	if trend.Count != 0 {
		t.Errorf("flag-off fold trend Count = %d, want 0", trend.Count)
	}
}

// TestAttachBridge_FoldAttachSegment_NilSink is the fail-open pin: a nil sink (the fold leg
// unwired) is a clean no-op even with a measured segment present — the host never panics on an
// unserved observability leg.
func TestAttachBridge_FoldAttachSegment_NilSink(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "")
	t.Setenv(createTimingWireFlag, "1")

	b := NewAttachBridge(AttachBridgeConfig{SocketDir: "/run/ds/attach"})
	const sess = "sess-fold-nilsink"
	if _, err := b.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	trend, ok, err := b.FoldAttachSegment(nil, sess, 0)
	if err != nil {
		t.Fatalf("FoldAttachSegment(nil sink): %v", err)
	}
	if ok {
		t.Error("FoldAttachSegment(nil sink) reported ok=true, want no fold")
	}
	if trend.Count != 0 {
		t.Errorf("nil-sink fold trend Count = %d, want 0", trend.Count)
	}
}
