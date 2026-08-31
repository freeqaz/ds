package sessions

import (
	"testing"
	"time"
)

// fakeClock returns a now() that advances by a fixed step on each call, so
// time-to-first-session spans are deterministic.
func fakeClock(start time.Time, step time.Duration) func() time.Time {
	cur := start
	return func() time.Time {
		t := cur
		cur = cur.Add(step)
		return t
	}
}

// clearPartner drives a partner through both D54 signals so it CLEARS: high draft-
// acceptance and a fast first session. drafts/accepts shape the rate; the gate's clock
// must produce a sub-day span (caller sets the clock step).
func clearPartner(g *PromotionGate, id string, accepts, total int) {
	g.RecordOnboardStart(id)
	for i := 0; i < total; i++ {
		g.RecordDraftDecision(id, i < accepts)
	}
	g.RecordFirstSession(id)
}

// TestPromotionGate_NotEvaluableBelowWindow proves D54's "the gate is unevaluable"
// floor: with fewer than two consecutive partners, the verdict is not-evaluable (NOT
// a false "closed").
func TestPromotionGate_NotEvaluableBelowWindow(t *testing.T) {
	g := NewPromotionGate(fakeClock(time.Unix(0, 0), time.Hour))
	v := g.Evaluate()
	if v.Open || v.Evaluable {
		t.Errorf("zero partners must be not-evaluable, got %+v", v)
	}
	clearPartner(g, "partner-1", 5, 5)
	v = g.Evaluate()
	if v.Open || v.Evaluable {
		t.Errorf("one partner must be not-evaluable (D54 needs the trailing two), got %+v", v)
	}
}

// TestPromotionGate_OpensWhenTrailingTwoClear proves the D54 gate opens when the two
// most-recent partners BOTH clear BOTH thresholds.
func TestPromotionGate_OpensWhenTrailingTwoClear(t *testing.T) {
	// 1-hour step ⇒ each onboard→first-session span is 1h (< 1 day).
	g := NewPromotionGate(fakeClock(time.Unix(0, 0), time.Hour))
	clearPartner(g, "partner-1", 9, 10) // 90%
	clearPartner(g, "partner-2", 8, 10) // 80% exactly (≥ floor)
	v := g.Evaluate()
	if !v.Evaluable {
		t.Fatalf("two measured partners must be evaluable, got %+v", v)
	}
	if !v.Open {
		t.Errorf("trailing two both clearing must OPEN the gate, got %+v (%s)", v, v.Reason)
	}
	if len(v.ConsideredPartners) != 2 {
		t.Errorf("verdict must range over the trailing two, got %v", v.ConsideredPartners)
	}
}

// TestPromotionGate_ClosedOnDraftAcceptance proves the draft-acceptance threshold
// gates the verdict: a trailing partner below 80% closes the gate, attributably.
func TestPromotionGate_ClosedOnDraftAcceptance(t *testing.T) {
	g := NewPromotionGate(fakeClock(time.Unix(0, 0), time.Hour))
	clearPartner(g, "partner-1", 9, 10) // 90%
	clearPartner(g, "partner-2", 7, 10) // 70% < floor
	v := g.Evaluate()
	if v.Open {
		t.Errorf("a sub-80%% trailing partner must close the gate, got %+v", v)
	}
	if !v.Evaluable {
		t.Errorf("the gate is evaluable (it just fails the threshold), got %+v", v)
	}
}

// TestPromotionGate_ClosedOnTimeToFirstSession proves the time-to-first-session
// threshold gates the verdict: a trailing partner over 1 day closes the gate.
func TestPromotionGate_ClosedOnTimeToFirstSession(t *testing.T) {
	g := NewPromotionGate(fakeClock(time.Unix(0, 0), 48*time.Hour)) // 48h step ⇒ 2-day spans
	clearPartner(g, "partner-1", 10, 10)
	clearPartner(g, "partner-2", 10, 10)
	v := g.Evaluate()
	if v.Open {
		t.Errorf("a >1-day time-to-first-session must close the gate, got %+v", v)
	}
}

// TestPromotionGate_NoFirstSessionFailsClosed proves a partner with no first session
// (nil span) does NOT clear — not-yet-measured is never a spurious pass.
func TestPromotionGate_NoFirstSessionFailsClosed(t *testing.T) {
	g := NewPromotionGate(fakeClock(time.Unix(0, 0), time.Hour))
	clearPartner(g, "partner-1", 10, 10)
	// partner-2 has perfect drafts but never reaches a first session.
	g.RecordOnboardStart("partner-2")
	g.RecordDraftDecision("partner-2", true)
	v := g.Evaluate()
	if v.Open {
		t.Errorf("a partner with no first session must not open the gate, got %+v", v)
	}
}

// TestPromotionGate_TrailingWindowMoves proves "two CONSECUTIVE" is the trailing two:
// a third partner that fails closes a gate the first two would have opened.
func TestPromotionGate_TrailingWindowMoves(t *testing.T) {
	g := NewPromotionGate(fakeClock(time.Unix(0, 0), time.Hour))
	clearPartner(g, "partner-1", 10, 10)
	clearPartner(g, "partner-2", 10, 10)
	if v := g.Evaluate(); !v.Open {
		t.Fatalf("first two clearing must open, got %+v", v)
	}
	// A third partner fails draft-acceptance — the trailing two are now {2,3}.
	clearPartner(g, "partner-3", 1, 10) // 10%
	v := g.Evaluate()
	if v.Open {
		t.Errorf("a failing trailing partner must close the gate, got %+v", v)
	}
	if len(v.ConsideredPartners) == 2 && v.ConsideredPartners[1] != "partner-3" {
		t.Errorf("trailing window must include the newest partner, got %v", v.ConsideredPartners)
	}
}

// TestPromotionGate_FirstSessionIdempotent proves only the FIRST session sets the span
// ("time to FIRST session") and RecordOnboardStart does not reset the clock.
func TestPromotionGate_FirstSessionIdempotent(t *testing.T) {
	g := NewPromotionGate(fakeClock(time.Unix(0, 0), time.Hour))
	g.RecordOnboardStart("p")
	g.RecordOnboardStart("p") // must not reset the clock
	g.RecordFirstSession("p")
	first := g.Snapshot()[0].TimeToFirstSession
	g.RecordFirstSession("p") // must not change the span
	second := g.Snapshot()[0].TimeToFirstSession
	if first == nil || second == nil || *first != *second {
		t.Errorf("only the FIRST session sets the span; got first=%v second=%v", first, second)
	}
}
