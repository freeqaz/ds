package sessions

// promotiongate.go is the doc 15 §9 D54 PROMOTION-GATE INSTRUMENTATION — the
// control-plane-side measurement that makes the D54 self-serve front-door gate
// EVALUABLE. Doc 15 §9: "D54 promotion-gate instrumentation (draft-acceptance,
// time-to-first-session) is control-plane-measured from M0/M1 OR THE GATE IS
// UNEVALUABLE." This is that measurement: the two D54 signals, recorded per
// onboarding partner, aggregated into the gate verdict.
//
// D54, verbatim: "the CI-autodetect agent shadow-runs on every design-partner
// onboarding from M0/M1; it becomes the default front door only at draft-acceptance
// ≥ 80% over two consecutive partners PLUS unassisted onboard-to-first-session < 1
// day". The two thresholds:
//   - DRAFT-ACCEPTANCE ≥ 80% over TWO CONSECUTIVE partners (the env-spec draft the
//     onboarding agent PRs is accepted — merged as-drafted or with minor edits — vs
//     rejected/rewritten). "Two consecutive" is the load-bearing window: the gate
//     opens only when the two MOST RECENT partners both clear 80%.
//   - TIME-TO-FIRST-SESSION (unassisted onboard → first session) < 1 day, per partner.
//
// WHAT THIS STAGE OWNS. It is the CONTROL-PLANE MEASUREMENT and the gate VERDICT —
// the accumulator the orchestrator feeds onboarding events into (a drafted env spec
// was accepted/rejected; a partner reached their first session N after onboarding
// began) and the Evaluate that reads the D54 thresholds off the accumulated per-
// partner samples. It does NOT FLIP the front door: D54's "becomes the default front
// door" is a product/operations decision an operator takes when Evaluate reports the
// gate open — this stage REPORTS evaluability, it never auto-promotes (the D74-style
// "human review, never auto-promoted" discipline applied to the front-door flip).
//
// WHY HERE (not just a metrics sink). The instrumentation is doc-15-§9-owned because
// the two signals are control-plane facts: draft-acceptance is observed at the env-
// config record/merge path (envconfig.go's surface), and time-to-first-session is the
// span from enrollment (the D56 first key, twokey.go) to the session record's first
// READY (§4.1 step 9). Both are joins this component already holds; this stage is the
// per-partner accumulator over them. Persistence (which store table holds the samples)
// is the metering/instrumentation surface that freezes with the M2 product band (doc
// 15 §10 row) — until then the accumulator is the honest in-memory shape, fed from the
// same events that table will carry.

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// D54 gate thresholds (doc 04 §6 D54). Recorded as named constants so the gate verdict
// reads the decision's numbers, not magic literals.
const (
	// d54DraftAcceptanceFloor is the ≥ 80% draft-acceptance threshold.
	d54DraftAcceptanceFloor = 0.80
	// d54ConsecutivePartners is the "two consecutive partners" window — the gate opens
	// only when the two MOST RECENT partners BOTH clear the acceptance floor.
	d54ConsecutivePartners = 2
	// d54MaxTimeToFirstSession is the unassisted onboard-to-first-session "< 1 day"
	// ceiling.
	d54MaxTimeToFirstSession = 24 * time.Hour
)

// PartnerSample is one design partner's accumulated D54 signals (doc 15 §9). It is the
// per-partner row the gate aggregates: the draft-acceptance numerator/denominator (the
// env-spec drafts the onboarding agent PR'd, accepted vs total) and the unassisted
// onboard-to-first-session span. A partner with no sessions yet has a nil
// TimeToFirstSession (not yet measurable — the gate treats it as not-yet-clearing,
// fail-closed, never as a zero that spuriously clears).
type PartnerSample struct {
	// PartnerID is the design partner (the org/account onboarding). The accumulation key.
	PartnerID string
	// DraftsAccepted / DraftsTotal are the draft-acceptance counts (D54): a drafted
	// env spec ACCEPTED (merged as-drafted or with minor edits) increments both;
	// a REJECTED/rewritten draft increments only DraftsTotal. Acceptance rate is
	// Accepted/Total (a partner with zero drafts has an undefined rate — treated as
	// not-clearing, fail-closed).
	DraftsAccepted int
	DraftsTotal    int
	// TimeToFirstSession is the unassisted onboard → first-session span (D54 "< 1 day").
	// Nil until the partner reaches a first session (not-yet-measured ≠ zero).
	TimeToFirstSession *time.Duration
	// OnboardStartedAt is when unassisted onboarding began for this partner — the
	// start of the time-to-first-session span, retained so a later first-session event
	// can compute the span. Zero until onboarding starts.
	OnboardStartedAt time.Time
	// FirstSessionAt is when the partner reached their first session — the end of the
	// span. Zero until it happens.
	FirstSessionAt time.Time
	// Sequence is a monotonic recording order so "two CONSECUTIVE partners" is
	// well-defined (the two most-recently-onboarded partners, by onboarding order). It
	// is assigned by the accumulator on first sight of a partner.
	Sequence int
}

// AcceptanceRate is the partner's draft-acceptance rate (D54), or (0,false) when the
// partner has no drafts yet (an undefined rate the gate must NOT read as clearing).
func (p PartnerSample) AcceptanceRate() (float64, bool) {
	if p.DraftsTotal <= 0 {
		return 0, false
	}
	return float64(p.DraftsAccepted) / float64(p.DraftsTotal), true
}

// clearsDraftAcceptance reports whether the partner's draft-acceptance meets the D54
// floor. A partner with no drafts (undefined rate) does NOT clear — fail-closed.
func (p PartnerSample) clearsDraftAcceptance() bool {
	rate, ok := p.AcceptanceRate()
	return ok && rate >= d54DraftAcceptanceFloor
}

// clearsTimeToFirstSession reports whether the partner's unassisted onboard-to-first-
// session span is under the D54 ceiling. A partner not yet at a first session (nil
// span) does NOT clear — fail-closed (not-yet-measured is never a spurious pass).
func (p PartnerSample) clearsTimeToFirstSession() bool {
	return p.TimeToFirstSession != nil && *p.TimeToFirstSession < d54MaxTimeToFirstSession
}

// PromotionGate is the D54 instrumentation accumulator (doc 15 §9): it records the two
// D54 signals per design partner from M0/M1 and evaluates the front-door gate over the
// accumulated samples. It is concurrency-safe (onboarding events arrive from multiple
// control-plane paths) and holds the samples in onboarding order so "two consecutive
// partners" is well-defined. Persistence freezes with the M2 product band (doc 15
// §10); this is the in-memory accumulator feeding the same events.
type PromotionGate struct {
	mu       sync.Mutex
	now      func() time.Time
	nextSeq  int
	partners map[string]*PartnerSample
}

// NewPromotionGate constructs the D54 accumulator. now defaults to time.Now (override
// in tests for deterministic time-to-first-session spans).
func NewPromotionGate(now func() time.Time) *PromotionGate {
	if now == nil {
		now = time.Now
	}
	return &PromotionGate{
		now:      now,
		partners: make(map[string]*PartnerSample),
	}
}

// partnerLocked returns (creating if absent) the partner's sample. Caller holds mu.
func (g *PromotionGate) partnerLocked(partnerID string) *PartnerSample {
	p, ok := g.partners[partnerID]
	if !ok {
		g.nextSeq++
		p = &PartnerSample{PartnerID: partnerID, Sequence: g.nextSeq}
		g.partners[partnerID] = p
	}
	return p
}

// RecordOnboardStart marks the start of a partner's unassisted onboarding — the start
// of the D54 time-to-first-session span. Idempotent on the FIRST start (a re-call does
// not reset the clock; the first unassisted onboard is the span's origin).
func (g *PromotionGate) RecordOnboardStart(partnerID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.partnerLocked(partnerID)
	if p.OnboardStartedAt.IsZero() {
		p.OnboardStartedAt = g.now()
	}
}

// RecordDraftDecision records one env-spec-draft acceptance decision for a partner
// (D54 draft-acceptance): accepted=true for a draft merged as-drafted or with minor
// edits, accepted=false for a rejected/rewritten draft. Both increment DraftsTotal;
// only an accepted draft increments DraftsAccepted.
func (g *PromotionGate) RecordDraftDecision(partnerID string, accepted bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.partnerLocked(partnerID)
	p.DraftsTotal++
	if accepted {
		p.DraftsAccepted++
	}
}

// RecordFirstSession marks the partner reaching their first session — the end of the
// D54 time-to-first-session span. The span is FirstSessionAt − OnboardStartedAt; if
// onboarding never started (no RecordOnboardStart), the span is unmeasurable and is
// left nil (fail-closed: the gate treats it as not-clearing, never as a zero). Only the
// FIRST session is recorded (a re-call is a no-op — "time to FIRST session").
func (g *PromotionGate) RecordFirstSession(partnerID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.partnerLocked(partnerID)
	if !p.FirstSessionAt.IsZero() {
		return // already recorded; this is the FIRST session only.
	}
	if p.OnboardStartedAt.IsZero() {
		// No onboarding start recorded — the span is unmeasurable. Record the session
		// time but leave the span nil so the gate fails closed on this partner rather
		// than reading a bogus zero/negative span as a pass.
		p.FirstSessionAt = g.now()
		return
	}
	p.FirstSessionAt = g.now()
	span := p.FirstSessionAt.Sub(p.OnboardStartedAt)
	p.TimeToFirstSession = &span
}

// GateVerdict is the D54 evaluation result (doc 15 §9). Open is the gate verdict — the
// front door MAY flip to self-serve (an OPERATOR acts on this; the gate never
// auto-promotes). The fields below are the EVIDENCE: which partners were considered,
// and which threshold(s) gate the verdict so the reason is auditable.
type GateVerdict struct {
	// Open is true iff the two most-recent consecutive partners BOTH clear BOTH D54
	// thresholds (draft-acceptance ≥ 80% AND time-to-first-session < 1 day). It is the
	// "evaluable AND passing" verdict — an operator promotes on it, never the gate.
	Open bool
	// Evaluable is true iff there are at least d54ConsecutivePartners partners with
	// measurable signals to evaluate over. When false, Open is false and the verdict is
	// "not yet evaluable" (D54: the gate is unevaluable without the instrumentation —
	// here, without enough measured partners), NOT "failed".
	Evaluable bool
	// ConsideredPartners are the partner IDs the verdict ranged over (the two most
	// recent, in onboarding order), for the audit trail.
	ConsideredPartners []string
	// Reason is a human-readable explanation of the verdict (which threshold gated it,
	// or that it is not yet evaluable) — recorded so a closed gate is attributable to a
	// specific failing signal, not an opaque false.
	Reason string
}

// Evaluate computes the D54 front-door gate verdict over the two most-recently-
// onboarded partners (doc 15 §9 / D54). The gate is OPEN iff BOTH of the two most
// recent partners clear BOTH thresholds; it is NOT-EVALUABLE with fewer than two
// measured partners (the D54 "two consecutive" window has not filled). The verdict
// carries the evidence (considered partners + reason) so a closed/unevaluable gate is
// attributable.
//
// "Two CONSECUTIVE partners" is the two HIGHEST-sequence partners (the two most
// recently onboarded), by the accumulator's onboarding order — D54's window is the
// trailing two, so a third partner clearing does not retro-open a gate the trailing
// two close.
func (g *PromotionGate) Evaluate() GateVerdict {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Snapshot the samples in onboarding order (by Sequence).
	samples := make([]*PartnerSample, 0, len(g.partners))
	for _, p := range g.partners {
		samples = append(samples, p)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].Sequence < samples[j].Sequence })

	if len(samples) < d54ConsecutivePartners {
		return GateVerdict{
			Open:      false,
			Evaluable: false,
			Reason: fmt.Sprintf("not yet evaluable: %d of %d consecutive partners onboarded (D54 needs the trailing %d)",
				len(samples), d54ConsecutivePartners, d54ConsecutivePartners),
		}
	}

	// The trailing window: the d54ConsecutivePartners most-recent partners.
	window := samples[len(samples)-d54ConsecutivePartners:]
	considered := make([]string, 0, len(window))
	for _, p := range window {
		considered = append(considered, p.PartnerID)
	}

	for _, p := range window {
		if !p.clearsDraftAcceptance() {
			rate, ok := p.AcceptanceRate()
			detail := "no drafts recorded"
			if ok {
				detail = fmt.Sprintf("%.0f%% < %.0f%%", rate*100, d54DraftAcceptanceFloor*100)
			}
			return GateVerdict{
				Open: false, Evaluable: true, ConsideredPartners: considered,
				Reason: fmt.Sprintf("closed: partner %q draft-acceptance %s", p.PartnerID, detail),
			}
		}
		if !p.clearsTimeToFirstSession() {
			detail := "no first session yet"
			if p.TimeToFirstSession != nil {
				detail = fmt.Sprintf("%s ≥ %s", p.TimeToFirstSession.Round(time.Second), d54MaxTimeToFirstSession)
			}
			return GateVerdict{
				Open: false, Evaluable: true, ConsideredPartners: considered,
				Reason: fmt.Sprintf("closed: partner %q time-to-first-session %s", p.PartnerID, detail),
			}
		}
	}

	return GateVerdict{
		Open: true, Evaluable: true, ConsideredPartners: considered,
		Reason: fmt.Sprintf("open: trailing %d partners both clear draft-acceptance ≥ %.0f%% and time-to-first-session < %s",
			d54ConsecutivePartners, d54DraftAcceptanceFloor*100, d54MaxTimeToFirstSession),
	}
}

// Snapshot returns a copy of the accumulated per-partner samples in onboarding order —
// the control-plane-measured D54 evidence (doc 15 §9), for export to the metering/
// instrumentation surface (freezes M2, doc 15 §10) or for an operator reviewing the
// gate. The returned samples are copies (the caller cannot mutate the accumulator).
func (g *PromotionGate) Snapshot() []PartnerSample {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]PartnerSample, 0, len(g.partners))
	for _, p := range g.partners {
		c := *p
		if p.TimeToFirstSession != nil {
			d := *p.TimeToFirstSession
			c.TimeToFirstSession = &d
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}
