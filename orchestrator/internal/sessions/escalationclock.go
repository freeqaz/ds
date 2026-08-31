// SPDX-License-Identifier: Apache-2.0

// The D46 escalation clock (doc 15 §4.3): a PURE, clock-injected decision over
// the elapsed wall-clock time since a session was suspended, classifying the
// pause into one of the three D46 tiers and emitting the verdict the park/resume
// driver (parkresume.go) and the boundary coordination (suspendcoord.go) act on.
//
// THE D46 CONTRACT (doc 15 §3 note 2 + §4.3, and sessions/05 cross-reference):
//   - ≤5 min   FULLY TRANSPARENT — the proxy holds/buffers the VM-leg sockets;
//     the guest wall clock is resynced on resume (the ≤5-min transparency
//     invariant — an unpaused VM with an uncorrected clock violates it).
//   - 5–15 min  BEST-EFFORT — the hold is still attempted but transparency is no
//     longer guaranteed (sockets may have dropped); resume is best-effort.
//   - >15 min   ESCALATE — snapshot + park (→ PARKED); the host slot is released,
//     there is NO transparency claim, and resume re-places through the normal
//     scheduler (parkresume.go drives the SNAPSHOTTING→PARKED edge).
//
// THE TIERS ARE THE D46 CONTRACT; the 5/15-minute boundaries are the STRAWMAN
// DEFAULTS and are rig-tuned/free (doc 15 §3 "the latency strawmen below stay
// free", the §10 frozen/free split). A Config carries the two boundaries so a rig
// can re-tune them without touching the tier semantics. Altering the THREE-TIER
// SHAPE (adding/removing a tier, or changing which tier maps to transparent /
// best-effort / escalate) reopens D46 — it is not a Config knob.
//
// PURE + CLOCK-INJECTED. The decision takes the suspend instant and reads "now"
// through an injected now func() time.Time, exactly the clock-injection
// discipline the rest of internal/sessions uses (SessionCreator.now). No global
// time.Now, no I/O, no state — the same (suspendedAt, now) inputs always yield
// the same verdict, so the boundary instants (exactly 5 min, exactly 15 min) are
// pinned in tests against a frozen clock.
//
// EMIT, NEVER GATE A RELEASE (D81/D32). This clock emits a verdict; it does not
// arm any M2 release-budget gate. The create-to-attach budget is INSTRUMENTATION-
// ONLY until dogfood data arms it later — this file measures and classifies, it
// does not block.
//
// ADDITIVE / NEW FILE ONLY. It adds no §3 state, edge, or reason; it consumes no
// proto and edits no other sessions file. The tier verdict is mapped onto the
// frozen SuspendCoordPhase / the SNAPSHOTTING→PARKED edge by the consumers
// (suspendcoord.go, parkresume.go), never re-declared here.

package sessions

import (
	"fmt"
	"time"
)

// EscalationTier is the D46 classification of an in-progress suspend by elapsed
// time. The three tiers are the D46 contract (doc 15 §3 note 2 + §4.3); the zero
// value is the most-transparent tier (TierTransparent) so an at-instant (elapsed
// 0) suspend classifies transparent without a separate "unset" sentinel.
type EscalationTier int

const (
	// TierTransparent is the ≤5-min tier: FULLY TRANSPARENT. The proxy holds and
	// buffers the VM-leg sockets and the guest wall clock is resynced on resume.
	// This is the zero value — an at-instant suspend is transparent.
	TierTransparent EscalationTier = iota
	// TierBestEffort is the 5–15-min tier: BEST-EFFORT. The hold is still attempted
	// but transparency is no longer guaranteed; resume is best-effort.
	TierBestEffort
	// TierEscalate is the >15-min tier: ESCALATE to snapshot + park (→ PARKED). The
	// host slot is released, there is NO transparency claim, and resume re-places
	// through the normal scheduler (parkresume.go).
	TierEscalate
)

// String renders an EscalationTier for traces and verdict logging.
func (t EscalationTier) String() string {
	switch t {
	case TierTransparent:
		return "transparent"
	case TierBestEffort:
		return "best-effort"
	case TierEscalate:
		return "escalate"
	default:
		return fmt.Sprintf("EscalationTier(%d)", int(t))
	}
}

// Transparent reports whether this tier carries the ≤5-min full-transparency
// claim (the only tier on which RESUME_RESYNCED's resume_with_clock_resync is
// honored as a transparency guarantee). Convenience for the consumers.
func (t EscalationTier) Transparent() bool { return t == TierTransparent }

// EscalatesToPark reports whether this tier escalates to snapshot+park (the
// >15-min tier that drives the §3 SNAPSHOTTING→PARKED edge). Convenience for
// parkresume.go's tier gate.
func (t EscalationTier) EscalatesToPark() bool { return t == TierEscalate }

// EscalationConfig carries the two D46 tier boundaries. The BOUNDARIES are
// rig-tuned/free (the strawman defaults are 5 min and 15 min); the THREE-TIER
// SHAPE they partition is the D46 contract. Construct via NewEscalationConfig
// (which fills and validates the strawman defaults) — the zero value is not
// usable (a zero TransparentMax/BestEffortMax would collapse the tiers).
type EscalationConfig struct {
	// TransparentMax is the inclusive upper bound of the FULLY-TRANSPARENT tier:
	// elapsed ≤ TransparentMax is transparent. Strawman default 5 min.
	TransparentMax time.Duration
	// BestEffortMax is the inclusive upper bound of the BEST-EFFORT tier: elapsed in
	// (TransparentMax, BestEffortMax] is best-effort; elapsed > BestEffortMax
	// escalates. Strawman default 15 min.
	BestEffortMax time.Duration
}

// Strawman default tier boundaries (doc 15 §3 note 2 + §4.3). Free/rig-tuned —
// the three-tier shape they partition is the D46 contract.
const (
	// DefaultTransparentMax is the ≤5-min FULLY-TRANSPARENT strawman boundary.
	DefaultTransparentMax = 5 * time.Minute
	// DefaultBestEffortMax is the 15-min BEST-EFFORT/ESCALATE strawman boundary.
	DefaultBestEffortMax = 15 * time.Minute
)

// NewEscalationConfig returns the strawman-default D46 boundaries (5 min / 15 min).
// Use WithBoundaries to rig-tune; the result is always validated.
func NewEscalationConfig() EscalationConfig {
	return EscalationConfig{
		TransparentMax: DefaultTransparentMax,
		BestEffortMax:  DefaultBestEffortMax,
	}
}

// ErrEscalationConfig is returned by Validate when the boundaries are not a
// strictly-ordered positive partition (which would collapse or invert the three
// D46 tiers).
type ErrEscalationConfig struct{ msg string }

func (e *ErrEscalationConfig) Error() string {
	return "sessions: invalid D46 escalation config: " + e.msg
}

// Validate enforces that the two boundaries form a valid three-tier partition:
// 0 < TransparentMax < BestEffortMax. A non-positive or non-increasing pair would
// collapse a tier (e.g. TransparentMax == BestEffortMax erases best-effort) or
// invert the order, so it is a construction error rather than a silent mis-tier.
func (c EscalationConfig) Validate() error {
	if c.TransparentMax <= 0 {
		return &ErrEscalationConfig{msg: fmt.Sprintf("TransparentMax must be > 0, got %s", c.TransparentMax)}
	}
	if c.BestEffortMax <= c.TransparentMax {
		return &ErrEscalationConfig{msg: fmt.Sprintf("BestEffortMax (%s) must be > TransparentMax (%s)", c.BestEffortMax, c.TransparentMax)}
	}
	return nil
}

// WithBoundaries returns a copy of the config with the two boundaries set (a
// rig-tune). The caller validates with Validate (or constructs the clock with
// NewEscalationClock, which validates).
func (c EscalationConfig) WithBoundaries(transparentMax, bestEffortMax time.Duration) EscalationConfig {
	c.TransparentMax = transparentMax
	c.BestEffortMax = bestEffortMax
	return c
}

// EscalationVerdict is the emitted decision: the tier the elapsed time falls in,
// the elapsed duration it was computed from, and the absolute deadline of the
// CURRENT tier (the instant at which the next escalation fires) — the value the
// SuspendCoord tier_deadline_unix_sec carries to the proxy (doc 12 §12: the proxy
// bounds its buffering against an authoritative deadline, it does not recompute).
type EscalationVerdict struct {
	// Tier is the D46 classification of the elapsed time.
	Tier EscalationTier
	// Elapsed is the wall-clock duration since the suspend instant (now - suspendedAt).
	// Never negative — a now before the suspend instant clamps to 0 (TierTransparent).
	Elapsed time.Duration
	// TierDeadline is the absolute instant the CURRENT tier expires and the next
	// escalation fires: for Transparent it is suspendedAt+TransparentMax; for
	// BestEffort it is suspendedAt+BestEffortMax; for Escalate it is the zero Time
	// (escalate is terminal — there is no further tier, the session parks). The
	// boundary consumer converts it to tier_deadline_unix_sec.
	TierDeadline time.Time
}

// HasDeadline reports whether the verdict carries a meaningful tier deadline (true
// for Transparent/BestEffort; false for the terminal Escalate tier).
func (v EscalationVerdict) HasDeadline() bool { return !v.TierDeadline.IsZero() }

// EscalationClock is the D46 escalation decision component: a validated Config
// plus an injected clock. It is PURE — Classify is a function of (suspendedAt,
// now()) with no I/O or mutable state — and is safe for concurrent use.
type EscalationClock struct {
	cfg EscalationConfig
	now func() time.Time
}

// NewEscalationClock constructs the clock with the given (validated) boundaries
// and injected clock. A nil now defaults to time.Now (production); tests inject a
// frozen clock to pin the boundary instants. An invalid config is a construction
// error (the tiers would collapse) — never silently corrected.
func NewEscalationClock(cfg EscalationConfig, now func() time.Time) (*EscalationClock, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &EscalationClock{cfg: cfg, now: now}, nil
}

// Config returns the clock's resolved (validated) boundaries — for traces and the
// boundary consumer that needs the tier widths.
func (c *EscalationClock) Config() EscalationConfig { return c.cfg }

// Classify is the D46 verdict over a suspend instant: it reads now() through the
// injected clock, computes the elapsed time, and classifies it into the three D46
// tiers against the configured boundaries. The boundaries are INCLUSIVE upper
// bounds — at EXACTLY TransparentMax the verdict is still Transparent, and at
// EXACTLY BestEffortMax it is still BestEffort; one tick past each is the next
// tier. (The pinned-instant semantics the test asserts: 5:00 transparent,
// 5:00.000000001 best-effort; 15:00 best-effort, 15:00.000000001 escalate.)
//
// A now before suspendedAt (a clock skew / out-of-order observation) clamps the
// elapsed to 0 — Transparent — rather than producing a negative elapsed; the
// clock never escalates on a backwards skew.
func (c *EscalationClock) Classify(suspendedAt time.Time) EscalationVerdict {
	elapsed := c.now().Sub(suspendedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	switch {
	case elapsed <= c.cfg.TransparentMax:
		return EscalationVerdict{
			Tier:         TierTransparent,
			Elapsed:      elapsed,
			TierDeadline: suspendedAt.Add(c.cfg.TransparentMax),
		}
	case elapsed <= c.cfg.BestEffortMax:
		return EscalationVerdict{
			Tier:         TierBestEffort,
			Elapsed:      elapsed,
			TierDeadline: suspendedAt.Add(c.cfg.BestEffortMax),
		}
	default:
		return EscalationVerdict{
			Tier:         TierEscalate,
			Elapsed:      elapsed,
			TierDeadline: time.Time{}, // terminal: no further tier
		}
	}
}
