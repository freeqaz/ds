package createtiming_test

import (
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
)

// completeSynthetic builds a CreateTiming with all eight §8 stack segments set,
// plus a client RTT — the synthetic decomposition fixture (D50). seg→ms maps a
// segment to its millisecond duration.
func completeSynthetic(uuid string, rttMs int) *createtiming.CreateTiming {
	c := createtiming.NewCreateTiming(uuid)
	durs := map[createtiming.Segment]int{
		createtiming.SegPlacement:        10,
		createtiming.SegOverlayClone:     200,
		createtiming.SegTapNFT:           15,
		createtiming.SegIdentityCADigest: 40,
		createtiming.SegBootEntrypoint:   800,
		createtiming.SegPolicyReady:      5,
		createtiming.SegRoutable:         3,
		createtiming.SegAttachHandshake:  12,
	}
	for seg, ms := range durs {
		_ = c.Record(seg, time.Duration(ms)*time.Millisecond)
	}
	_ = c.Record(createtiming.SegClientRTT, time.Duration(rttMs)*time.Millisecond)
	return c
}

// TestDecompositionExists is the core D81 instrument-first assertion: a complete
// create records all eight §8 stack segments — the decomposition EXISTS. This is
// the existence assertion, NOT a duration gate.
func TestDecompositionExists(t *testing.T) {
	c := completeSynthetic("sess-1", 50)
	if !c.Complete() {
		t.Fatalf("complete decomposition reported incomplete; missing=%v", c.MissingSegments())
	}
	if got := c.MissingSegments(); len(got) != 0 {
		t.Fatalf("MissingSegments = %v, want none", got)
	}
	// Exactly eight stack segments are defined, and SegClientRTT is not one.
	stack := createtiming.StackSegments()
	if len(stack) != 8 {
		t.Fatalf("StackSegments len = %d, want 8", len(stack))
	}
	for _, s := range stack {
		if s == createtiming.SegClientRTT {
			t.Fatalf("SegClientRTT must NOT be a stack segment (it is the excluded venue measurement)")
		}
		if !createtiming.IsStackSegment(s) {
			t.Fatalf("IsStackSegment(%q) = false for a declared stack segment", s)
		}
	}
	if createtiming.IsStackSegment(createtiming.SegClientRTT) {
		t.Fatalf("IsStackSegment(SegClientRTT) = true; RTT is not a stack segment")
	}
}

// TestMissingSegmentsSurfacesIncomplete proves the existence assertion catches an
// incomplete decomposition — a create that skipped a segment is detectable
// (instrument-first means the decomposition's COMPLETENESS is what we assert).
func TestMissingSegmentsSurfacesIncomplete(t *testing.T) {
	c := createtiming.NewCreateTiming("sess-partial")
	_ = c.Record(createtiming.SegPlacement, time.Millisecond)
	_ = c.Record(createtiming.SegBootEntrypoint, time.Second)
	if c.Complete() {
		t.Fatal("partial decomposition reported complete")
	}
	missing := c.MissingSegments()
	if len(missing) != 6 {
		t.Fatalf("MissingSegments = %v (len %d), want 6", missing, len(missing))
	}
	// SegClientRTT is never reported missing even though it is absent.
	for _, m := range missing {
		if m == createtiming.SegClientRTT {
			t.Fatal("SegClientRTT reported missing; it is optional and excluded")
		}
	}
}

// TestRTTExcludedFromTriggers is the load-bearing D81 §8 invariant: client RTT is
// EXCLUDED from the trigger-evaluation span. Two creates with identical stack
// segments but wildly different RTTs must have IDENTICAL TriggerSpan — so a venue
// problem can never masquerade as a stack regression.
func TestRTTExcludedFromTriggers(t *testing.T) {
	low := completeSynthetic("sess-low", 5)
	high := completeSynthetic("sess-high", 5000) // a 5s venue problem

	if low.TriggerSpan() != high.TriggerSpan() {
		t.Fatalf("RTT leaked into TriggerSpan: low=%v high=%v", low.TriggerSpan(), high.TriggerSpan())
	}
	if low.ServerSpan() != high.ServerSpan() {
		t.Fatalf("RTT leaked into ServerSpan: low=%v high=%v", low.ServerSpan(), high.ServerSpan())
	}
	// TriggerSpan is exactly ServerSpan (the trigger evaluates the stack only).
	if low.TriggerSpan() != low.ServerSpan() {
		t.Fatalf("TriggerSpan (%v) != ServerSpan (%v)", low.TriggerSpan(), low.ServerSpan())
	}
	// The sum of the eight stack segments, RTT excluded.
	wantStack := (10 + 200 + 15 + 40 + 800 + 5 + 3 + 12) * time.Millisecond
	if low.ServerSpan() != wantStack {
		t.Fatalf("ServerSpan = %v, want %v (eight stack segments, RTT excluded)", low.ServerSpan(), wantStack)
	}
	// RTT is still observable, just never in the trigger span.
	if high.ClientRTT() != 5000*time.Millisecond {
		t.Fatalf("ClientRTT = %v, want 5s (observable, not gated)", high.ClientRTT())
	}
	if low.ClientRTT() == high.ClientRTT() {
		t.Fatal("ClientRTT must differ between the two fixtures (the venue does differ)")
	}
}

// TestTrendsRecordedNotGated proves the trend-recording half of D81
// instrument-first: the Recorder accumulates per-segment AND server-span trends
// (counts, percentiles) WITHOUT any verdict/gate. There is no Pass/Fail and no
// threshold comparison — the strawmen are planning aids only.
func TestTrendsRecordedNotGated(t *testing.T) {
	r := createtiming.NewRecorder()
	// Observe a spread of creates with varying boot times so a percentile is
	// meaningful.
	for i, bootMs := range []int{500, 700, 800, 900, 5000} {
		c := completeSynthetic("sess-"+string(rune('a'+i)), 10*(i+1))
		_ = c.Record(createtiming.SegBootEntrypoint, time.Duration(bootMs)*time.Millisecond)
		r.Observe(c)
	}

	boot := r.Trend(createtiming.SegBootEntrypoint)
	if boot.Count != 5 {
		t.Fatalf("boot trend count = %d, want 5", boot.Count)
	}
	if boot.Max() != 5000*time.Millisecond {
		t.Fatalf("boot trend max = %v, want 5s", boot.Max())
	}
	// p95 is reported for visibility (nearest-rank over 5 samples → the top
	// sample), NOT compared to a gate.
	if got := boot.P(0.95); got != 5000*time.Millisecond {
		t.Fatalf("boot p95 = %v, want 5s (reported, never gated)", got)
	}
	// The server-span trend is a true per-create distribution.
	span := r.ServerSpanTrend()
	if span.Count != 5 {
		t.Fatalf("server-span trend count = %d, want 5", span.Count)
	}
	// RTT must not be in the server-span trend: the largest RTT (50ms on the last
	// fixture) cannot inflate the span beyond the stack sum at its boot of 5000ms.
	// Stack sum for the last fixture = 10+200+15+40+5000+5+3+12 = 5285ms.
	wantMaxSpan := (10 + 200 + 15 + 40 + 5000 + 5 + 3 + 12) * time.Millisecond
	if span.Max() != wantMaxSpan {
		t.Fatalf("server-span trend max = %v, want %v (RTT excluded)", span.Max(), wantMaxSpan)
	}

	// An unobserved segment yields an empty trend (count zero), not a panic.
	empty := r.Trend(createtiming.Segment("nonexistent"))
	if empty.Count != 0 || empty.Max() != 0 || empty.P(0.5) != 0 {
		t.Fatalf("unobserved trend not empty: %+v", empty)
	}
}

// TestServerSpanTrendExcludesRTT pins the RTT-exclusion all the way through the
// recorder: a fixture with a huge RTT and a tiny stack has a SMALL server-span
// trend entry — the venue never inflates the recorded stack distribution.
func TestServerSpanTrendExcludesRTT(t *testing.T) {
	r := createtiming.NewRecorder()
	c := createtiming.NewCreateTiming("sess-rtt")
	for _, seg := range createtiming.StackSegments() {
		_ = c.Record(seg, time.Millisecond) // 8ms stack total
	}
	_ = c.Record(createtiming.SegClientRTT, 10*time.Second) // huge venue latency
	r.Observe(c)

	span := r.ServerSpanTrend()
	if span.Count != 1 {
		t.Fatalf("server-span trend count = %d, want 1", span.Count)
	}
	if span.Max() != 8*time.Millisecond {
		t.Fatalf("server-span trend = %v, want 8ms (the 10s RTT is excluded)", span.Max())
	}
}

// TestRecordNegativeRejected proves a backwards clock is rejected rather than
// recorded as a negative span that could corrupt a trend.
func TestRecordNegativeRejected(t *testing.T) {
	c := createtiming.NewCreateTiming("sess-neg")
	if err := c.Record(createtiming.SegPlacement, -time.Second); err == nil {
		t.Fatal("negative duration accepted; want an error")
	}
	if _, ok := c.Segments[createtiming.SegPlacement]; ok {
		t.Fatal("rejected negative duration was still recorded")
	}
}
