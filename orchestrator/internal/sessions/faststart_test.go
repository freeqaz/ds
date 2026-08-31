// SPDX-License-Identifier: Apache-2.0

package sessions

// faststart_test.go drives the M2 golden-image instant-start fast path
// (faststart.go) over the EXISTING ten-step create harness (newHarness /
// authedReq, sessioncreate_test.go) + synthetic seam fakes (D50, no live
// VM/host-agent/podman/KVM). It proves:
//   - a golden-image fast-path create reaches ATTACHED through the clone→boot→
//     attach seams;
//   - the create→attach decomposition is COMPLETE (all eight §8 stack segments
//     recorded) for a golden create — the D81 instrument-first existence
//     assertion;
//   - SegClientRTT is EXCLUDED from ServerSpan/TriggerSpan (the venue/stack split);
//   - a create RECORDS a timing but is NEVER gated/refused on the span (the
//     no-unarmed-budget posture, D81/D32) — even a pathologically large span
//     reaches ATTACHED;
//   - the resolver fails fast on an empty image (fail-closed), and golden vs base
//     is an image-resolution annotation, not a create branch;
//   - the §8 trend Recorder is fed.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// stepClock is a deterministic monotonic clock that advances a fixed step on each
// read, so every instrumented span has a known POSITIVE duration (one tick of
// `start` then `end` = `step`). It makes the §8 segment durations exact under test.
type stepClock struct {
	now  time.Time
	step time.Duration
}

func newStepClock(step time.Duration) *stepClock {
	return &stepClock{now: time.Unix(1_700_000_000, 0).UTC(), step: step}
}

func (c *stepClock) tick() time.Time {
	t := c.now
	c.now = c.now.Add(c.step)
	return t
}

// fastStarterFor builds a FastStarter over the harness's coordinator with a
// deterministic span clock and a fresh recorder.
func fastStarterFor(t *testing.T, h *creatorHarness, span time.Duration) *FastStarter {
	t.Helper()
	c := h.creator(t)
	rec := createtiming.NewRecorder()
	clk := newStepClock(span)
	fs, err := NewFastStarter(c, PrebakedGoldenResolver{}, rec, clk.tick)
	if err != nil {
		t.Fatalf("NewFastStarter: %v", err)
	}
	return fs
}

// TestFastStart_ReachesAttached proves the golden-image fast path drives the
// existing ten-step create to ATTACHED through the clone→boot→attach seams, and
// resolves the image as GOLDEN.
func TestFastStart_ReachesAttached(t *testing.T) {
	h := newHarness(t, true) // digest acked → routable
	fs := fastStarterFor(t, h, time.Millisecond)

	res, err := fs.FastStart(context.Background(), authedReq("sess-fast-1"))
	if err != nil {
		t.Fatalf("FastStart: %v", err)
	}
	if res.Session.State != store.SessionAttached {
		t.Fatalf("state = %v, want ATTACHED", res.Session.State)
	}
	if !res.Image.IsGolden() {
		t.Fatalf("image class = %q, want golden", res.Image.Class)
	}
	if res.Image.ImageID != "img-1" {
		t.Fatalf("resolved image = %q, want the requested content-address", res.Image.ImageID)
	}
}

// TestFastStart_DecompositionComplete is the D81 instrument-first EXISTENCE
// assertion: a successful golden-image fast-path create records ALL EIGHT §8 stack
// segments (Complete()/MissingSegments() empty). It is the (b)-row core.
func TestFastStart_DecompositionComplete(t *testing.T) {
	h := newHarness(t, true)
	fs := fastStarterFor(t, h, time.Millisecond)

	res, err := fs.FastStart(context.Background(), authedReq("sess-fast-2"))
	if err != nil {
		t.Fatalf("FastStart: %v", err)
	}
	if !res.Timing.Complete() {
		t.Fatalf("decomposition INCOMPLETE, missing %v — the existence assertion failed", res.Timing.MissingSegments())
	}
	// Every one of the eight stack segments must be present by name.
	for _, seg := range createtiming.StackSegments() {
		if _, ok := res.Timing.Segments[seg]; !ok {
			t.Fatalf("segment %q not recorded", seg)
		}
	}
}

// TestFastStart_RTTExcludedFromServerSpan pins the venue/stack split: SegClientRTT
// never enters ServerSpan/TriggerSpan. We record a client RTT directly on the
// timing and assert ServerSpan is the sum of the eight stack segments ONLY.
func TestFastStart_RTTExcludedFromServerSpan(t *testing.T) {
	h := newHarness(t, true)
	fs := fastStarterFor(t, h, 2*time.Millisecond)

	res, err := fs.FastStart(context.Background(), authedReq("sess-fast-3"))
	if err != nil {
		t.Fatalf("FastStart: %v", err)
	}
	serverBefore := res.Timing.ServerSpan()
	// Inject a large client RTT — the venue measurement that must NOT inflate the
	// stack span the (future) trigger would evaluate.
	if err := res.Timing.Record(createtiming.SegClientRTT, time.Hour); err != nil {
		t.Fatalf("Record RTT: %v", err)
	}
	if got := res.Timing.ServerSpan(); got != serverBefore {
		t.Fatalf("ServerSpan changed after recording client RTT: %v -> %v (RTT must be excluded)", serverBefore, got)
	}
	if res.Timing.TriggerSpan() != res.Timing.ServerSpan() {
		t.Fatal("TriggerSpan must equal ServerSpan (RTT excluded by definition)")
	}
	if res.Timing.ClientRTT() != time.Hour {
		t.Fatalf("ClientRTT = %v, want the recorded venue value", res.Timing.ClientRTT())
	}
	// The decomposition is still COMPLETE — RTT is not a stack segment, so it is
	// never "missing".
	if !res.Timing.Complete() {
		t.Fatalf("decomposition incomplete after RTT record: %v", res.Timing.MissingSegments())
	}
}

// TestFastStart_MeasureNotGate is the D81/D32 no-unarmed-budget assertion: a create
// with a PATHOLOGICALLY LARGE per-step span (an hour each) still reaches ATTACHED.
// There is NO threshold, NO verdict, NO release-block on the span — the create is
// MEASURED, never gated.
func TestFastStart_MeasureNotGate(t *testing.T) {
	h := newHarness(t, true)
	// One hour per step span — far past any conceivable budget strawman (doc 15 §8).
	fs := fastStarterFor(t, h, time.Hour)

	res, err := fs.FastStart(context.Background(), authedReq("sess-fast-slow"))
	if err != nil {
		t.Fatalf("a slow create must NOT be gated/refused on the span (D81/D32): %v", err)
	}
	if res.Session.State != store.SessionAttached {
		t.Fatalf("state = %v, want ATTACHED — a slow create still completes", res.Session.State)
	}
	// The large span IS recorded (measured), it just never gates.
	if res.Timing.ServerSpan() < time.Hour {
		t.Fatalf("ServerSpan = %v, want the large measured span recorded", res.Timing.ServerSpan())
	}
	if !res.Timing.Complete() {
		t.Fatalf("a slow create still records a complete decomposition, missing %v", res.Timing.MissingSegments())
	}
}

// TestFastStart_FeedsRecorder proves the §8 trend Recorder is fed: after N golden
// creates the server-span trend carries N samples (the "trends are recorded" half
// of D81 instrument-first). The Recorder carries NO gate — it is a pure
// distribution.
func TestFastStart_FeedsRecorder(t *testing.T) {
	// One SHARED recorder across N creates. Each create runs on a FRESH harness so
	// the per-host never-recycled index (the harness's fixed index 42) is not
	// re-burned across creates (the §4.1 step-4 burn invariant); the recorder is the
	// shared §8 trend sink the production wiring keeps process-wide.
	rec := createtiming.NewRecorder()
	const n = 4
	for i := 0; i < n; i++ {
		h := newHarness(t, true)
		clk := newStepClock(time.Millisecond)
		fs, err := NewFastStarter(h.creator(t), PrebakedGoldenResolver{}, rec, clk.tick)
		if err != nil {
			t.Fatalf("NewFastStarter #%d: %v", i, err)
		}
		if _, err := fs.FastStart(context.Background(), authedReq(uuidN("rec", i))); err != nil {
			t.Fatalf("FastStart #%d: %v", i, err)
		}
	}
	trend := rec.ServerSpanTrend()
	if trend.Count != n {
		t.Fatalf("server-span trend count = %d, want %d", trend.Count, n)
	}
	// A per-segment trend is also recorded (the placement segment, here).
	if got := rec.Trend(createtiming.SegPlacement).Count; got != n {
		t.Fatalf("placement trend count = %d, want %d", got, n)
	}
}

// TestFastStart_GateRefusalIsNotATimingGate proves the ONLY refusals come from the
// SessionCreator's own structural gates (here: D73 digest-not-acked), NOT from the
// timing: the create fails with the coordinator's CreateError, and a partial timing
// is NOT folded into the trend (a failed-early create skews nothing).
func TestFastStart_GateRefusalIsNotATimingGate(t *testing.T) {
	h := newHarness(t, false) // digest NOT acked → step-9 routable refusal (D73)
	fs := fastStarterFor(t, h, time.Millisecond)

	res, err := fs.FastStart(context.Background(), authedReq("sess-fast-unacked"))
	if err == nil {
		t.Fatal("want a D73 digest-not-acked refusal")
	}
	// The refusal is the coordinator's structural gate, NOT a timing/budget error.
	if !errors.Is(err, ErrDigestNotAcked) {
		t.Fatalf("err = %v, want ErrDigestNotAcked (a structural gate, not a timing gate)", err)
	}
	if errors.Is(err, ErrTimingIncomplete) {
		t.Fatal("a structural-gate refusal must NOT be reported as a timing-incomplete error")
	}
	// A failed create did not reach ATTACHED.
	if res.Session.State == store.SessionAttached {
		t.Fatal("a refused create must not be ATTACHED")
	}
	// The decomposition is incomplete (boot/attach never ran) and was NOT folded
	// into the trend.
	if fs.Recorder().ServerSpanTrend().Count != 0 {
		t.Fatal("a failed-early create must NOT be folded into the §8 trend")
	}
}

// TestFastStart_ResolverRefusesEmptyImage proves the §4.1 step-7 resolution is
// fail-closed: an empty content-address is ErrNoGoldenImage, refused BEFORE any
// host-side work (no session record touched).
func TestFastStart_ResolverRefusesEmptyImage(t *testing.T) {
	h := newHarness(t, true)
	fs := fastStarterFor(t, h, time.Millisecond)

	req := authedReq("sess-fast-noimg")
	req.ImageID = ""
	_, err := fs.FastStart(context.Background(), req)
	if !errors.Is(err, ErrNoGoldenImage) {
		t.Fatalf("err = %v, want ErrNoGoldenImage", err)
	}
	// No host-side seam ran (the allocator was never driven).
	if h.alloc.gotHost != "" {
		t.Fatalf("host allocator ran (%q) on an unresolved image — resolution must gate first", h.alloc.gotHost)
	}
}

// TestFastStart_ImageThreadedToPlacement proves the resolved golden ImageID flows
// into the §7 image-cache-locality placement input (PlacementRequest.ImageID) and
// the step-4 VmSpec.image_id — the M2 seconds-to-start lever, threaded WITHOUT the
// fast path re-implementing placement.
func TestFastStart_ImageThreadedToPlacement(t *testing.T) {
	h := newHarness(t, true)
	fs := fastStarterFor(t, h, time.Millisecond)

	if _, err := fs.FastStart(context.Background(), authedReq("sess-fast-img")); err != nil {
		t.Fatalf("FastStart: %v", err)
	}
	// The step-4 VmSpec carried the resolved content-address (the overlay clone keys
	// on it); the placement filter read the SAME ImageID via the placer (the §7
	// image-cache-locality preference). We assert the VmSpec the allocator saw.
	if h.alloc.gotSpec == nil || h.alloc.gotSpec.GetImageId() != "img-1" {
		t.Fatalf("step-4 VmSpec image_id = %v, want the resolved golden content-address", h.alloc.gotSpec)
	}
}

// TestNewFastStarter_NilCreator proves the construction-time fail-closed: a nil
// SessionCreator is refused at NewFastStarter, never at the first create.
func TestNewFastStarter_NilCreator(t *testing.T) {
	if _, err := NewFastStarter(nil, nil, nil, nil); err == nil {
		t.Fatal("NewFastStarter(nil creator): want a construction error")
	}
}

// TestNewFastStarter_Defaults proves the optional args default safely: a nil
// resolver/recorder/clock are filled (PrebakedGoldenResolver, a fresh Recorder,
// time.Now), so a minimal wiring still drives a complete create.
func TestNewFastStarter_Defaults(t *testing.T) {
	h := newHarness(t, true)
	fs, err := NewFastStarter(h.creator(t), nil, nil, nil)
	if err != nil {
		t.Fatalf("NewFastStarter: %v", err)
	}
	res, err := fs.FastStart(context.Background(), authedReq("sess-fast-def"))
	if err != nil {
		t.Fatalf("FastStart with defaults: %v", err)
	}
	if !res.Timing.Complete() {
		t.Fatalf("defaults must still record a complete decomposition, missing %v", res.Timing.MissingSegments())
	}
}

// TestResolvedImage_IsGolden pins the golden-vs-base image-resolution annotation
// (NOT a create branch): an explicit base class is not golden; an unset class
// defaults to golden.
func TestResolvedImage_IsGolden(t *testing.T) {
	if !(ResolvedImage{Class: ClassGolden}).IsGolden() {
		t.Fatal("ClassGolden must be golden")
	}
	if !(ResolvedImage{}).IsGolden() {
		t.Fatal("unset class must default to golden")
	}
	if (ResolvedImage{Class: ClassBase}).IsGolden() {
		t.Fatal("ClassBase must NOT be golden")
	}
}

// uuidN builds a distinct session UUID for the N-create trend test.
func uuidN(prefix string, i int) string {
	return prefix + "-" + string(rune('a'+i))
}
