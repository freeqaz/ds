package createtiming

import (
	"fmt"
	"sort"
	"time"
)

// Segment is one stage of the D81 §8 create→attach decomposition. The eight
// stack segments map onto the §4.1 ten-step create; ClientRTT is the SEPARATE
// network-venue measurement that is EXCLUDED from any trigger evaluation (doc 15
// §8), so it is named here but never enters ServerSpan / TriggerSpan.
type Segment string

const (
	SegPlacement        Segment = "placement"          // §4.1 step 3: scheduler placement decision
	SegOverlayClone     Segment = "overlay_clone"      // §4.1 step 7: CloneFromImage qcow2 overlay
	SegTapNFT           Segment = "tap_nft"            // §4.1 step 4: tap-create + per-session NFT objects
	SegIdentityCADigest Segment = "identity_ca_digest" // §4.1 steps 5–6: mint + digest write/ack
	SegBootEntrypoint   Segment = "boot_entrypoint"    // §4.1 step 8: boot to frozen entrypoint
	SegPolicyReady      Segment = "policy_ready"       // §4.1 step 9: host policy-freshness gate
	SegRoutable         Segment = "routable"           // §4.1 step 9: first-egress-byte gate
	SegAttachHandshake  Segment = "attach_handshake"   // §4.1 step 10: attach handle issue

	// SegClientRTT is the client↔control-plane network venue. It is measured
	// SEPARATELY and EXCLUDED from trigger evaluation (doc 15 §8): it never
	// enters ServerSpan / TriggerSpan, so a venue problem and a stack regression
	// stay distinguishable.
	SegClientRTT Segment = "client_rtt"
)

// stackSegments is the ordered §8 stack decomposition — the eight segments that
// compose the trigger-eligible server span, in §4.1 create order. SegClientRTT
// is deliberately absent: it is the excluded venue measurement.
var stackSegments = []Segment{
	SegPlacement,
	SegOverlayClone,
	SegTapNFT,
	SegIdentityCADigest,
	SegBootEntrypoint,
	SegPolicyReady,
	SegRoutable,
	SegAttachHandshake,
}

// StackSegments returns the ordered §8 stack decomposition as a fresh slice
// (callers may not mutate the package copy). SegClientRTT is NOT included — it
// is the separately-measured, trigger-excluded venue segment.
func StackSegments() []Segment {
	out := make([]Segment, len(stackSegments))
	copy(out, stackSegments)
	return out
}

// IsStackSegment reports whether s is one of the eight trigger-eligible §8 stack
// segments (i.e. not SegClientRTT and not an unknown name).
func IsStackSegment(s Segment) bool {
	for _, v := range stackSegments {
		if v == s {
			return true
		}
	}
	return false
}

// CreateTiming is the per-create §8 decomposition: the duration of each segment
// of one create. It is a pure data record built from synthetic fixtures (D50) —
// the decomposition the (b)-row suite asserts EXISTS (D81 instrument-first). It
// carries NO verdict and NO threshold: gating arms at M2 (doc 15 §8), not here.
type CreateTiming struct {
	SessionUUID string
	// Segments is the measured duration of each segment. A complete create
	// carries all eight stack segments; SegClientRTT is OPTIONAL and, when
	// present, is excluded from ServerSpan / TriggerSpan.
	Segments map[Segment]time.Duration
}

// NewCreateTiming builds an empty decomposition for a session.
func NewCreateTiming(sessionUUID string) *CreateTiming {
	return &CreateTiming{SessionUUID: sessionUUID, Segments: make(map[Segment]time.Duration)}
}

// Record sets one segment's measured duration. A negative duration is a
// programming error (a clock ran backwards) and is rejected; callers measure
// monotonic spans.
func (c *CreateTiming) Record(seg Segment, d time.Duration) error {
	if d < 0 {
		return fmt.Errorf("createtiming: negative duration %v for segment %q", d, seg)
	}
	if c.Segments == nil {
		c.Segments = make(map[Segment]time.Duration)
	}
	c.Segments[seg] = d
	return nil
}

// ServerSpan is the trigger-eligible create→attach total: the sum of the eight
// §8 STACK segments ONLY. Client RTT is EXCLUDED (doc 15 §8) — a present
// SegClientRTT never contributes — so a network-venue problem can never inflate
// the stack span the trigger (eventually, from M2) evaluates. A missing segment
// contributes zero; use MissingSegments to assert the decomposition is complete.
func (c *CreateTiming) ServerSpan() time.Duration {
	var total time.Duration
	for _, seg := range stackSegments {
		total += c.Segments[seg]
	}
	return total
}

// TriggerSpan is the duration a (future, M2+) trigger would evaluate. It is
// EXACTLY ServerSpan: by definition it excludes SegClientRTT, so the venue and
// the stack stay distinguishable. It is named separately from ServerSpan to make
// the "RTT-excluded-from-triggers" invariant explicit at the call site and in
// the test that pins it.
func (c *CreateTiming) TriggerSpan() time.Duration {
	return c.ServerSpan()
}

// ClientRTT returns the separately-measured client↔control-plane venue latency
// (zero if not recorded). It is observability-only: it is NEVER part of
// TriggerSpan.
func (c *CreateTiming) ClientRTT() time.Duration {
	return c.Segments[SegClientRTT]
}

// MissingSegments reports which of the eight §8 stack segments were NOT recorded
// — the EXISTENCE assertion at the heart of D81 instrument-first: the suite
// asserts the decomposition EXISTS (every stack segment present), it does NOT
// gate on the durations. An empty result means the decomposition is complete.
// SegClientRTT is never reported missing (it is optional and excluded).
func (c *CreateTiming) MissingSegments() []Segment {
	var missing []Segment
	for _, seg := range stackSegments {
		if _, ok := c.Segments[seg]; !ok {
			missing = append(missing, seg)
		}
	}
	return missing
}

// Complete reports whether all eight §8 stack segments were recorded — the
// boolean form of the existence assertion (MissingSegments is empty).
func (c *CreateTiming) Complete() bool {
	return len(c.MissingSegments()) == 0
}

// Trend is the recorded distribution of one segment's durations across creates —
// the "trends are recorded" half of D81 instrument-first (doc 15 §8). It is a
// pure summary (count + percentiles), NOT a gate: no threshold, no verdict. The
// p95 strawmen (doc 15 §8) are planning aids, never asserted here.
type Trend struct {
	Segment Segment
	Count   int
	samples []time.Duration // sorted ascending
}

// P returns the q-quantile (0 ≤ q ≤ 1) of the recorded samples via
// nearest-rank, or zero if empty. P(0.95) is the p95 the strawmen reference —
// reported for trend visibility, never compared to a gate here.
func (t Trend) P(q float64) time.Duration {
	if len(t.samples) == 0 {
		return 0
	}
	if q <= 0 {
		return t.samples[0]
	}
	if q >= 1 {
		return t.samples[len(t.samples)-1]
	}
	// Nearest-rank: rank = ceil(q*N), 1-indexed.
	rank := int(q*float64(len(t.samples)) + 0.999999)
	if rank < 1 {
		rank = 1
	}
	if rank > len(t.samples) {
		rank = len(t.samples)
	}
	return t.samples[rank-1]
}

// Max returns the largest recorded sample (zero if empty).
func (t Trend) Max() time.Duration {
	if len(t.samples) == 0 {
		return 0
	}
	return t.samples[len(t.samples)-1]
}

// Recorder accumulates per-segment trends across creates — the trend-recording
// instrument (D81). It is in-process and pure (no expvar global, no store, no
// gate), so it composes cleanly in tests and never blocks a release. A
// production wiring task may later relay these trends to the (d) rig; that is a
// separate concern (this package is not wired into main.go).
type Recorder struct {
	perSegment map[Segment][]time.Duration
}

// NewRecorder builds an empty trend recorder.
func NewRecorder() *Recorder {
	return &Recorder{perSegment: make(map[Segment][]time.Duration)}
}

// Observe folds one create's decomposition into the running trends. SegClientRTT
// is recorded as its own trend (so the venue is observable) but, like
// everywhere else, never enters any server-span trend. Observing the same create
// twice double-counts — Observe is a stream fold, not idempotent; the metering
// stream owns idempotency, the timing rig owns trend distribution.
func (r *Recorder) Observe(c *CreateTiming) {
	if r.perSegment == nil {
		r.perSegment = make(map[Segment][]time.Duration)
	}
	for seg, d := range c.Segments {
		r.perSegment[seg] = append(r.perSegment[seg], d)
	}
	// Fold the per-create trigger-eligible server span (RTT excluded) under a
	// dedicated key so ServerSpanTrend reports a TRUE per-create distribution
	// rather than a flattened per-segment one.
	r.perSegment[segServerSpan] = append(r.perSegment[segServerSpan], c.ServerSpan())
}

// Trend returns the recorded trend for one segment (Count zero if unobserved).
func (r *Recorder) Trend(seg Segment) Trend {
	src := r.perSegment[seg]
	cp := make([]time.Duration, len(src))
	copy(cp, src)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return Trend{Segment: seg, Count: len(cp), samples: cp}
}

// ServerSpanTrend returns the trend of the trigger-eligible server span across
// every observed create — the per-create sum of the eight stack segments, with
// client RTT excluded. This is the (b)-row trend the M2 budget will eventually
// be set against (doc 15 §8); recorded now, gated never (before M2).
func (r *Recorder) ServerSpanTrend() Trend {
	// Reconstruct per-create server spans from the recorded per-segment samples
	// is not possible (samples are flattened per segment), so the server-span
	// trend is recorded explicitly via the synthetic SegServerSpan key folded by
	// Observe below. To keep the recorder a pure per-segment fold without a
	// hidden join, ServerSpanTrend reads the dedicated key.
	src := r.perSegment[segServerSpan]
	cp := make([]time.Duration, len(src))
	copy(cp, src)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return Trend{Segment: segServerSpan, Count: len(cp), samples: cp}
}

// segServerSpan is an internal trend key carrying the per-create server-span
// sum, folded by Observe so ServerSpanTrend reports a true per-create
// distribution (not a flattened per-segment one). It is never a §8 stack
// segment and is excluded from StackSegments / MissingSegments.
const segServerSpan Segment = "__server_span__"
