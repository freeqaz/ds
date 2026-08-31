// SPDX-License-Identifier: Apache-2.0

package askhold

// park.go owns the D46 PARK/RESUME state machine for a GENUINE rung-2 ask
// (a blocklist hit or an explicitly `action: suspend` rule, D77). The
// load-bearing invariant: a parked ask NEVER times out into allow or kill — it
// stays PARKED until a human answer arrives (doc 16 §8.2 / D46). This is the
// deliberate asymmetry with a TLS-1 socket-hold (hold.go): a socket-hold is a
// SHORT (30-60 s) window whose timeout closes the connection block+log, whereas
// a rung-2 park has NO allow/kill timeout at all — the D46 tiered pause budget
// governs the pause TRANSPARENCY, not a deadline that resolves the ask.
//
// The park->resume state machine joins a parked SESSION to its pending QUESTION.
// The durable record of that join is an orchestrator-doc seam (doc 16 §8.2 "the
// ask-routing record ... is an orchestrator-doc seam"), so it is consumed here
// as an INJECTED interface (ParkRecorder) — this package decides the state
// transitions, it does not build the record store.

import "time"

// ParkPhase is the closed set of states a parked rung-2 ask can be in. Critically
// there is NO "allowed-on-timeout" and NO "killed-on-timeout" phase: the only
// terminal transitions are Resume (a human answer arrived) and an explicit
// human-authorized cancel — never a clock.
type ParkPhase int

const (
	// ParkPhaseUnspecified is the zero value; a well-formed Parked is never in it.
	ParkPhaseUnspecified ParkPhase = iota

	// ParkPhaseParked: the genuine rung-2 ask is parked, awaiting a human answer.
	// The session is suspended (SUSPENDED(reason), D35); resume authority is human
	// approval (doc 16 §8.2). It stays here indefinitely — a budget tier elapsing
	// NEVER moves it to allow or kill.
	ParkPhaseParked

	// ParkPhaseResumed: a human answer arrived and the parked ask resumed. This is
	// the ONLY way a park leaves ParkPhaseParked other than an explicit
	// human-authorized cancel. The resume carries the answer's verdict
	// (ResumeVerdict) — allow or deny — sourced from the out-of-band policy-stream
	// grant, never synthesized by a timeout.
	ParkPhaseResumed
)

func (p ParkPhase) String() string {
	switch p {
	case ParkPhaseParked:
		return "PARKED"
	case ParkPhaseResumed:
		return "RESUMED"
	default:
		return "UNSPECIFIED"
	}
}

// PauseTier mirrors the D46 tiered pause budget as a tiny value type (the budget
// is a consumed contract — doc 16 §10 "Suspend signal ... D46 park budget").
// The tier classifies a park's elapsed pause for TRANSPARENCY accounting; it is
// NOT a deadline. Crossing into a higher tier changes the transparency CLAIM
// (transparent -> best-effort -> snapshot+park), never the ask's outcome.
type PauseTier int

const (
	// TierTransparent: <= the fully-transparent budget (D46 strawman <= 5 min) —
	// proxy holds and buffers both sides; guest wall clock resynced on resume.
	TierTransparent PauseTier = iota

	// TierBestEffort: between the transparent and snapshot budgets (D46 strawman
	// 5-15 min) — tuned retransmit on VM-facing sockets; upstream reconnect where
	// safe.
	TierBestEffort

	// TierSnapshotPark: beyond the best-effort budget (D46 strawman > 15 min) —
	// escalates to snapshot+park with no transparency claim. The ask is STILL
	// parked (never allowed, never killed); only the transparency promise drops.
	TierSnapshotPark
)

func (t PauseTier) String() string {
	switch t {
	case TierTransparent:
		return "TRANSPARENT"
	case TierBestEffort:
		return "BEST_EFFORT"
	case TierSnapshotPark:
		return "SNAPSHOT_PARK"
	default:
		return "TRANSPARENT"
	}
}

// PauseBudget carries the D46 tier thresholds as INJECTED POL-1 values — never
// hardcoded constants (the strawman is 5 min / 15 min; doc 16 §10 / D46). Tier
// classifies elapsed pause against these; both are durations a deployment tunes.
type PauseBudget struct {
	// Transparent is the upper bound of the fully-transparent tier (strawman
	// 5 min). Elapsed pause at or below this is TierTransparent.
	Transparent time.Duration

	// BestEffort is the upper bound of the best-effort tier (strawman 15 min).
	// Elapsed pause above Transparent and at or below this is TierBestEffort;
	// above this is TierSnapshotPark.
	BestEffort time.Duration
}

// Tier classifies an elapsed pause duration against the injected budget. It is
// pure and total. Note it returns a transparency tier ONLY — there is no
// "expired" return, because a park has no allow/kill expiry (D46).
func (b PauseBudget) Tier(elapsed time.Duration) PauseTier {
	switch {
	case elapsed <= b.Transparent:
		return TierTransparent
	case elapsed <= b.BestEffort:
		return TierBestEffort
	default:
		return TierSnapshotPark
	}
}

// ResumeVerdict is the human answer that ends a park. It is sourced from the
// out-of-band policy-stream grant (allow) or the D118 session-scoped deny
// artifact (deny) — never synthesized by a timeout. The closed set deliberately
// has no "timed-out" member.
type ResumeVerdict int

const (
	// ResumeVerdictUnspecified is the zero value; Resume rejects it.
	ResumeVerdictUnspecified ResumeVerdict = iota

	// ResumeVerdictAllow: the human approved. The resume carries the allow grant's
	// SCOPE opaquely (Resumed.GrantScope); allow-always escalation to org-admin
	// acceptance (D45) is decided elsewhere and rides in as that scope value — this
	// package never decides D45.
	ResumeVerdictAllow

	// ResumeVerdictDeny: the human denied. The resume carries the D77 machine-
	// readable deny reason so a retry fast-fails (the D118 deny-memo shape).
	ResumeVerdictDeny
)

func (v ResumeVerdict) String() string {
	switch v {
	case ResumeVerdictAllow:
		return "ALLOW"
	case ResumeVerdictDeny:
		return "DENY"
	default:
		return "UNSPECIFIED"
	}
}

// ParkRecorder is the INJECTED orchestrator-doc seam that joins a parked session
// to its pending question (doc 16 §8.2). This package decides the transitions
// and calls these hooks; it does not build the durable record. The methods are
// effecting hooks (record the park / clear it on resume) — they return an error
// the state machine surfaces, never deciding the park outcome themselves. A nil
// recorder is tolerated (the decision still happens; only the record is skipped),
// so the state machine is unit-testable with no fake at all and with a recording
// fake.
type ParkRecorder interface {
	// RecordParked is called when an ask enters ParkPhaseParked: persist the
	// session<->question join. Returning an error does NOT un-park the ask (the
	// ask is still parked, the safe state); it surfaces so the caller can retry
	// the record.
	RecordParked(p Parked) error

	// ClearParked is called when a park resumes (ParkPhaseResumed): clear the
	// pending-question join. Returning an error does NOT re-park; it surfaces for
	// retry.
	ClearParked(p Parked) error
}

// Parked is the state of one parked rung-2 ask: the question (Ask), the session
// it belongs to, when it parked, and its phase. On resume it also carries the
// human answer's verdict and the opaque allow-grant scope / deny reason. It
// NEVER carries a timeout-derived allow or kill — the type has no field that
// could express one.
type Parked struct {
	// SessionUUID is the parked session's id (the join key to the pending
	// question). Sourced from the ask's SessionRef by the caller; carried as a
	// plain string so this package needs no proto session type.
	SessionUUID string

	// Ask is the pending question (the genuine rung-2 ask).
	Ask Ask

	// ParkedAt is when the ask parked (the D46 pause clock origin). Elapsed pause
	// = now - ParkedAt, classified by PauseBudget.Tier — for transparency only.
	ParkedAt time.Time

	// Phase is the current state: ParkPhaseParked or ParkPhaseResumed.
	Phase ParkPhase

	// ResumedAt is when a human answer resumed the park (zero while parked).
	ResumedAt time.Time

	// Verdict is the human answer that resumed the park (ResumeVerdictUnspecified
	// while parked). Allow or deny — never a timeout.
	Verdict ResumeVerdict

	// GrantScope carries the allow grant's scope OPAQUELY on a ResumeVerdictAllow
	// (e.g. allow-once domain-scoped session-TTL, or an allow-always proposal
	// pending org-admin acceptance per D45). This package never interprets it; it
	// rides through from the out-of-band policy-stream grant.
	GrantScope string

	// DenyReason carries the D77 machine-readable reason on a ResumeVerdictDeny so
	// a retry fast-fails (the D118 deny-memo shape). Empty otherwise.
	DenyReason DenyReason
}

// NewParked parks a GENUINE rung-2 ask and records the session<->question join
// via the injected recorder. It is the rung-2 counterpart to hold.Decide's
// socket-hold: where Decide opens a short timed window, NewParked enters an
// untimed park. It refuses a non-rung-2 ask (those socket-hold; routing them
// here would be a caller bug) by returning an error and an unparked zero Parked.
//
// A nil recorder is tolerated (the park decision still stands; only the durable
// record is skipped). A recorder error surfaces but the returned Parked is STILL
// PARKED — failing to record never un-parks (the safe state), so a record retry
// can follow without losing the park.
func NewParked(recorder ParkRecorder, sessionUUID string, ask Ask, now time.Time) (Parked, error) {
	if !ask.Rung2 {
		return Parked{}, errNotRung2
	}
	p := Parked{
		SessionUUID: sessionUUID,
		Ask:         ask,
		ParkedAt:    now,
		Phase:       ParkPhaseParked,
	}
	if recorder != nil {
		if err := recorder.RecordParked(p); err != nil {
			// The ask is parked regardless; surface the record error for retry.
			return p, err
		}
	}
	return p, nil
}

// Tier classifies the park's elapsed pause at `now` against the injected budget
// (D46) — transparency accounting only. It NEVER resolves the ask: a park in
// TierSnapshotPark is still parked, awaiting a human answer. Returns
// TierTransparent for a not-yet-parked (zero ParkedAt) or already-resumed state,
// where the pause clock does not apply.
func (p Parked) Tier(budget PauseBudget, now time.Time) PauseTier {
	if p.Phase != ParkPhaseParked || p.ParkedAt.IsZero() {
		return TierTransparent
	}
	return budget.Tier(now.Sub(p.ParkedAt))
}

// Resume ends a park because a HUMAN ANSWER arrived (out-of-band, on the policy
// stream — never a timeout). It transitions ParkPhaseParked -> ParkPhaseResumed
// carrying the answer's verdict, and clears the session<->question join via the
// injected recorder. It is the ONLY non-cancel exit from a park, and it is
// driven exclusively by an answer: there is no time-based exit anywhere in this
// file.
//
// It refuses to resume an ask that is not currently parked (double-resume or a
// never-parked state) and refuses an unspecified verdict — a resume must carry a
// real human answer. On an allow it stamps GrantScope; on a deny it stamps the
// machine-readable DenyReason (the D118 fast-fail memo). A recorder ClearParked
// error surfaces but the resume STILL stands (the ask is resumed; only the
// record-clear can be retried).
func (p Parked) Resume(recorder ParkRecorder, verdict ResumeVerdict, scope string, reason DenyReason, now time.Time) (Parked, error) {
	if p.Phase != ParkPhaseParked {
		return p, errNotParked
	}
	if verdict == ResumeVerdictUnspecified {
		return p, errNoVerdict
	}
	p.Phase = ParkPhaseResumed
	p.ResumedAt = now
	p.Verdict = verdict
	switch verdict {
	case ResumeVerdictAllow:
		p.GrantScope = scope
	case ResumeVerdictDeny:
		p.DenyReason = reason
	}
	if recorder != nil {
		if err := recorder.ClearParked(p); err != nil {
			return p, err
		}
	}
	return p, nil
}

// parkError is the package's small sentinel error type so callers can match on
// the cause without a third-party errors package (stdlib-only). Values are
// declared below.
type parkError string

func (e parkError) Error() string { return string(e) }

const (
	// errNotRung2: NewParked was handed a non-rung-2 ask (those socket-hold via
	// hold.Decide, not park here).
	errNotRung2 parkError = "askhold: park requires a genuine rung-2 ask"

	// errNotParked: Resume was called on an ask not currently in ParkPhaseParked
	// (a double-resume or never-parked state).
	errNotParked parkError = "askhold: resume requires a currently-parked ask"

	// errNoVerdict: Resume was called with ResumeVerdictUnspecified — a resume
	// must carry a real human answer (never a synthesized timeout verdict).
	errNoVerdict parkError = "askhold: resume requires an allow or deny verdict"
)
