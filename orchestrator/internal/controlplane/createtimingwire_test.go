// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
)

// recordAllStackSegments records a uniform per-segment duration across the eight
// §8 stack segments, returning the handle for the caller to Observe.
func recordAllStackSegments(t *testing.T, w *CreateTimingWire, sessionUUID string, d time.Duration) *CreateTimingHandle {
	t.Helper()
	h := w.Begin(sessionUUID)
	for _, seg := range createtiming.StackSegments() {
		if err := h.Record(seg, d); err != nil {
			t.Fatalf("record segment %q: %v", seg, err)
		}
	}
	return h
}

func TestCreateTimingWireDisabledIsInert(t *testing.T) {
	w := NewCreateTimingWire(false)
	if w.Enabled() {
		t.Fatal("disabled wire reported Enabled")
	}
	h := recordAllStackSegments(t, w, "sess-1", 5*time.Millisecond)
	if got := h.MissingSegments(); got != nil {
		t.Fatalf("disabled-handle MissingSegments = %v, want nil", got)
	}
	h.Observe(context.Background())
	if got := w.ServerSpanTrend().Count; got != 0 {
		t.Fatalf("disabled wire recorded %d server spans, want 0", got)
	}
}

func TestCreateTimingWireObservesServerSpan(t *testing.T) {
	w := NewCreateTimingWire(true)
	// Eight segments at 10ms each → a 80ms server span.
	h := recordAllStackSegments(t, w, "sess-1", 10*time.Millisecond)
	if miss := h.MissingSegments(); len(miss) != 0 {
		t.Fatalf("complete create reported missing segments %v", miss)
	}
	h.Observe(context.Background())
	tr := w.ServerSpanTrend()
	if tr.Count != 1 {
		t.Fatalf("ServerSpanTrend count = %d, want 1", tr.Count)
	}
	if got := tr.Max(); got != 80*time.Millisecond {
		t.Fatalf("server span = %v, want 80ms", got)
	}
}

func TestCreateTimingWireExcludesClientRTT(t *testing.T) {
	w := NewCreateTimingWire(true)
	h := recordAllStackSegments(t, w, "sess-1", 10*time.Millisecond)
	// A large client RTT must NOT inflate the trigger-eligible server span (doc 15 §8).
	if err := h.Record(createtiming.SegClientRTT, 500*time.Millisecond); err != nil {
		t.Fatalf("record client RTT: %v", err)
	}
	h.Observe(context.Background())
	if got := w.ServerSpanTrend().Max(); got != 80*time.Millisecond {
		t.Fatalf("server span = %v with RTT recorded, want 80ms (RTT excluded)", got)
	}
}

func TestCreateTimingWireMissingSegmentsAssertion(t *testing.T) {
	w := NewCreateTimingWire(true)
	h := w.Begin("sess-incomplete")
	// Record only one segment: the decomposition is incomplete.
	if err := h.Record(createtiming.SegPlacement, time.Millisecond); err != nil {
		t.Fatalf("record placement: %v", err)
	}
	miss := h.MissingSegments()
	if len(miss) != len(createtiming.StackSegments())-1 {
		t.Fatalf("incomplete create missing %d segments, want %d", len(miss), len(createtiming.StackSegments())-1)
	}
}

func TestCreateTimingWireRecordSince(t *testing.T) {
	w := NewCreateTimingWire(true)
	h := w.Begin("sess-since")
	start := time.Unix(1000, 0)
	now := start.Add(25 * time.Millisecond)
	if err := h.RecordSince(createtiming.SegOverlayClone, start, now); err != nil {
		t.Fatalf("RecordSince: %v", err)
	}
	h.Observe(context.Background())
	if got := w.SegmentTrend(createtiming.SegOverlayClone).Max(); got != 25*time.Millisecond {
		t.Fatalf("overlay_clone trend = %v, want 25ms", got)
	}
}

func TestCreateTimingWireRecordSinceRejectsBackwardsClock(t *testing.T) {
	w := NewCreateTimingWire(true)
	h := w.Begin("sess-back")
	start := time.Unix(1000, 0)
	now := start.Add(-time.Millisecond) // a clock ran backwards
	if err := h.RecordSince(createtiming.SegPlacement, start, now); err == nil {
		t.Fatal("RecordSince accepted a negative duration; want rejected")
	}
}

func TestCreateTimingWireConcurrentObserveNoRace(t *testing.T) {
	w := NewCreateTimingWire(true)
	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			h := w.Begin("sess-concurrent")
			for _, seg := range createtiming.StackSegments() {
				_ = h.Record(seg, time.Millisecond)
			}
			h.Observe(context.Background())
		}()
	}
	wg.Wait()
	if got := w.ServerSpanTrend().Count; got != n {
		t.Fatalf("concurrent Observe recorded %d server spans, want %d", got, n)
	}
}
