// SPDX-License-Identifier: Apache-2.0

package askhold

// hold.go owns the TLS-1 socket-hold decision and the D78 mid-hold rules
// (doc 16 §8.2). It is a pure function over (1) the ask, (2) the injected D78
// attendedness verdict, and (3) the injected POL-1 Window budget, plus the
// server clock the caller stamps. No IO, no sockets, no ambient clock — the
// boundary owns the socket-hold MECHANICS; this decides whether to open one,
// how long it runs, and what its expiry means.
//
// The three forks this file implements, verbatim from doc 16 §8.2 / D77 / D78:
//
//   - ATTENDED unknown-domain ask  -> open the TLS-1 socket-hold window; the VM
//     keeps running while the human is notified. Approval lands out-of-band on
//     the policy stream (no second response contract); a window timeout closes
//     the connection BLOCK+LOG — never allow.
//   - UNATTENDED-FROM-THE-START ask -> immediate block+log; no window is opened.
//   - IN-FLIGHT hold + attendedness DROPS mid-hold (D78) -> the hold RUNS TO ITS
//     TIMEOUT; it is never retroactively killed and never converted to an
//     immediate block. Only NEW asks downgrade. When the in-flight window times
//     out it closes BLOCK+LOG, exactly like any other window expiry.

import "time"

// Attendedness mirrors the D78 attendedness verdict as a tiny value type, so
// this package depends on the VERDICT, not on orchestrator/internal/attendedness
// or internal/store (no import coupling — the same pattern internal/attendedness
// uses to mirror the seat class). The caller projects a computed
// attendedness.Signal onto this at the package boundary: Attended <- Signal.Attended,
// AsOf <- the server clock the signal was stamped at.
type Attendedness struct {
	// Attended is the D78 boolean: true iff a human holds the one writer seat
	// (and, once input-activity events land, produced input within T). Spectators
	// and readers never make this true (doc 16 §8.1). It is the ONLY input that
	// forks attended vs. unattended here.
	Attended bool

	// AsOf is the server-side freshness instant the verdict was stamped at
	// (attendedness.Signal.AttendedAt). Carried so a caller can reason about
	// staleness; the decision logic here treats the verdict as authoritative at
	// `now` and does not itself re-derive freshness (that is the consumer's
	// few-seconds budget, doc 16 §8.1).
	AsOf time.Time
}

// Window is the TLS-1 socket-hold budget, carried as INJECTED POL-1 values —
// never hardcoded constants (doc 16 §8.2). The total hold the proxy keeps a
// connection open for is Notify + Decision + Commit; the strawman to test at
// the edges is notify <= 5 s + decision <= 40 s + commit <= 5 s (doc 16 §8.2),
// which sums to the doc's 30-60 s socket-hold range with 10 s the outer ceiling
// the commit barrier tolerates. A deployment tunes each leg via POL-1; this
// package reads them, it does not own them.
type Window struct {
	// Notify is the notification-delivery leg: how long the human has to be
	// notified via the ask-user seam (strawman <= 5 s).
	Notify time.Duration

	// Decision is the human-decision leg: how long the human has to answer once
	// notified (strawman <= 40 s).
	Decision time.Duration

	// Commit is the approval->enforced leg through the D72 two-phase barrier
	// (strawman <= 5 s; doc 15 §4.3 owns the number, 10 s the outer ceiling).
	Commit time.Duration
}

// Total is the full socket-hold duration the proxy keeps the connection open
// for: the sum of the three injected legs. It is the only place the legs are
// composed, so a deployment that tunes any leg via POL-1 changes the hold
// length here with no other edit.
func (w Window) Total() time.Duration {
	return w.Notify + w.Decision + w.Commit
}

// Outcome is the decision verb for an ask, BEFORE any timeout has fired. It is
// deliberately a closed set that contains NO "allow" and NO "kill": an allow
// only ever arrives out-of-band as a policy-stream grant (Resume in park.go),
// and a kill is a boundary-integrity response that ask-holds never produce
// (doc 16 §8.2 — unanswered asks "never timing out into allow or kill").
type Outcome int

const (
	// OutcomeUnspecified is the zero value; a well-formed Decide never returns it.
	OutcomeUnspecified Outcome = iota

	// OutcomeHold opens the TLS-1 socket-hold window: the proxy holds the TCP
	// connection and the VM keeps running while the human is notified (attended
	// unknown-domain, doc 16 §8.2). The window length is Decision.HoldFor.
	OutcomeHold

	// OutcomeBlockLog is immediate block+log: the connection is refused now with
	// the D77 machine-readable reason. It is the unattended-from-the-start
	// downgrade AND the terminal verb a timed-out hold resolves into — never
	// allow (doc 16 §8.2 / D77).
	OutcomeBlockLog
)

func (o Outcome) String() string {
	switch o {
	case OutcomeHold:
		return "HOLD"
	case OutcomeBlockLog:
		return "BLOCK_LOG"
	default:
		return "UNSPECIFIED"
	}
}

// Decision is the result of Decide: the verb, the hold window (when a hold is
// opened), and — when the verb is block+log — the machine-readable deny reason
// the D77 channel carries so retries fast-fail. A Decision NEVER carries an
// allow or a kill; that invariant is asserted in the tests.
type Decision struct {
	// Outcome is the verb: OutcomeHold or OutcomeBlockLog (never allow, never
	// kill).
	Outcome Outcome

	// HoldFor is the socket-hold duration when Outcome == OutcomeHold (== the
	// injected Window.Total). Zero for a block+log.
	HoldFor time.Duration

	// Deadline is the absolute instant a held connection's window expires, when
	// Outcome == OutcomeHold (== now + HoldFor). At/after this instant
	// ResolveTimeout closes the hold block+log. Zero for a block+log.
	Deadline time.Time

	// Reason is the D77 machine-readable deny reason carried on the densest
	// available channel (a structured 403/429 naming the matched rule), populated
	// when Outcome == OutcomeBlockLog so a retry fast-fails instead of looping.
	// Empty for a hold (no denial yet). This is the D77 deny-memo reason shape
	// (the session-scoped deny artifact, doc 16 §8.2 option (a) / D118) — this
	// package implements the shape and ratifies nothing.
	Reason DenyReason
}

// DenyReason is the machine-readable deny memo (D77 / D118 deny artifact). It names
// the matched rule and the cause so a retry fast-fails with no re-prompt storm
// (doc 16 §8.2 deny semantics). It is a value, never a free-text string, so the
// agent-visible 403/429 body and the session-scoped deny memo are the same data.
type DenyReason struct {
	// Code is the stable machine-readable cause. The two ask-hold causes are
	// DenyUnattended (unattended-from-the-start downgrade) and DenyHoldTimeout
	// (a socket-hold window expired with no in-window approval).
	Code DenyCode

	// MatchedRuleID echoes the POL-3 matched-rule id from the ask (AskUserRequest
	// .matched_rule_id) so the denial names "why was this asked?" (POL-3).
	MatchedRuleID string

	// ResourceKind / ResourceName echo the asked-about resource (the domain /
	// service id) from the ask, so the deny memo is self-describing for the
	// session-scoped fast-fail lookup.
	ResourceKind string
	ResourceName string
}

// DenyCode is the stable machine-readable cause set for an ask-hold denial.
type DenyCode string

const (
	// DenyUnattended: the ask was UNATTENDED from the start, so it downgraded to
	// immediate block+log (D77) — no hold window was ever opened.
	DenyUnattended DenyCode = "ASK_UNATTENDED"

	// DenyHoldTimeout: a TLS-1 socket-hold window expired with no in-window
	// approval, so the held connection closed block+log (D77). This is the
	// terminal verb of BOTH a normally-expired hold AND a D78 in-flight hold
	// whose attendedness dropped mid-window and then ran to timeout — never an
	// allow, never a kill.
	DenyHoldTimeout DenyCode = "ASK_HOLD_TIMEOUT"
)

// Ask is the minimal projection of the boundary's one-way AskUserRequest this
// decision needs: the asked-about resource and the POL-3 matched-rule id. It is
// a tiny value type the caller fills from the generated boundary/v1.AskUserRequest
// via FromProto, so the decision logic is testable with synthetic asks and never
// reaches for live IO (D50). Whether the ask is a "genuine rung-2 ask" (which
// PARKS, park.go) versus an ordinary unknown-domain ask (which socket-holds) is
// carried by the caller in Rung2.
type Ask struct {
	ResourceKind  string
	ResourceName  string
	MatchedRuleID string

	// Rung2 marks a GENUINE rung-2 ask (a blocklist hit or an explicitly
	// `action: suspend` rule, D77) — the class that PARKS per the D46 budget
	// rather than taking the TLS-1 socket-hold. Decide refuses to socket-hold a
	// rung-2 ask (see Decide); routing a rung-2 ask is park.go's job. Ordinary
	// unknown-domain asks leave this false.
	Rung2 bool
}

// FromProto projects the FROZEN one-way boundary AskUserRequest onto the local
// Ask value type. It consumes the generated proto read-only (the resource
// triple + the POL-3 matched-rule id) and NEVER re-declares or mutates it. The
// rung-2 classification is not on the ask wire shape, so the caller passes it
// explicitly. A nil request yields a zero Ask (defensive; the caller should not
// pass nil).
func FromProto(req askRequest, rung2 bool) Ask {
	if req == nil {
		return Ask{Rung2: rung2}
	}
	return Ask{
		ResourceKind:  req.GetResourceKind(),
		ResourceName:  req.GetResourceName(),
		MatchedRuleID: req.GetMatchedRuleId(),
		Rung2:         rung2,
	}
}

// askRequest is the read-only view of the generated boundary/v1.AskUserRequest
// FromProto consumes. It is the exact getter subset of the frozen message, so
// the generated *AskUserRequest satisfies it without any re-declaration of the
// proto type — the package depends on the GENERATED accessors, not a copy of
// the message body.
type askRequest interface {
	GetResourceKind() string
	GetResourceName() string
	GetMatchedRuleId() string
}

// Decide is the entry point: given an ask, the injected D78 attendedness
// verdict, the injected POL-1 Window, and the server clock `now`, it returns the
// hold-or-block decision for a NEW ask. It is pure: same inputs -> same output.
//
// The forks (doc 16 §8.2, D77/D78):
//
//   - A GENUINE rung-2 ask is NOT socket-held here — it parks (park.go). Decide
//     refuses it with OutcomeBlockLog only if mis-routed; the caller routes
//     rung-2 asks to NewParked. (We surface that as a block+log with the
//     unattended-class reason rather than inventing a verb, because a rung-2 ask
//     must never silently turn into a non-parking hold.) In practice the caller
//     checks ask.Rung2 and calls NewParked; Decide stays total for safety.
//   - ATTENDED, non-rung-2  -> OutcomeHold for Window.Total, Deadline = now+Total.
//   - UNATTENDED from the start -> OutcomeBlockLog with DenyUnattended.
//
// Decide concerns only the START of an ask's life. The D78 mid-hold rule
// (attendedness drops while a hold is in flight) is ResolveTimeout/OnAttendednessDrop,
// not Decide — a hold, once opened, is governed by its Deadline, not by a fresh
// Decide call.
func Decide(ask Ask, att Attendedness, win Window, now time.Time) Decision {
	// A genuine rung-2 ask never takes the socket-hold path; it parks. If a
	// caller routes one here anyway, fail closed to block+log (never a hold,
	// never allow) so a rung-2 ask can never become an unparked silent hold.
	if ask.Rung2 {
		return blockLog(ask, DenyUnattended, now)
	}

	if !att.Attended {
		// UNATTENDED FROM THE START -> immediate block+log (D77). No window opens.
		return blockLog(ask, DenyUnattended, now)
	}

	// ATTENDED unknown-domain -> open the TLS-1 socket-hold window. The VM keeps
	// running; the human is notified; approval arrives out-of-band on the policy
	// stream. The window length is the injected POL-1 budget — never a constant.
	total := win.Total()
	return Decision{
		Outcome:  OutcomeHold,
		HoldFor:  total,
		Deadline: now.Add(total),
	}
}

// HoldState is the live state of a socket-hold opened by Decide, threaded
// through the D78 mid-hold rules. It is the minimal carry the orchestrator
// keeps for an in-flight hold: when it expires, and whether attendedness has
// dropped since it opened. Approval is NOT modeled here — an approval ends the
// hold out-of-band via the policy stream (no second response contract), so this
// state only ever resolves to a block+log timeout or is discarded when the
// grant lands.
type HoldState struct {
	Ask      Ask
	Deadline time.Time

	// AttendednessDropped records the D78 transition: attendedness dropped while
	// THIS hold was in flight. Per D78 the hold still RUNS TO ITS TIMEOUT — this
	// flag never shortens the deadline and never converts the hold to an immediate
	// block; it is carried only so the timeout's log can attribute the drop. Only
	// NEW asks downgrade (that is Decide's unattended branch), never an in-flight
	// hold.
	AttendednessDropped bool
}

// NewHoldState builds the in-flight hold state from a hold Decision. The caller
// invokes it only when d.Outcome == OutcomeHold; for any other outcome it
// returns the zero HoldState (no hold to track).
func NewHoldState(ask Ask, d Decision) HoldState {
	if d.Outcome != OutcomeHold {
		return HoldState{}
	}
	return HoldState{Ask: ask, Deadline: d.Deadline}
}

// OnAttendednessDrop applies the D78 detach-mid-hold rule to an in-flight hold:
// attendedness dropped while this hold was running. Per D78 the hold RUNS TO ITS
// TIMEOUT — so this does NOT change the deadline and does NOT block immediately;
// it only marks the drop for the timeout's log. It returns the updated state.
// This is the one place the "in-flight holds run to timeout when attendedness
// drops; only new asks downgrade" rule lives.
func (h HoldState) OnAttendednessDrop() HoldState {
	h.AttendednessDropped = true
	return h
}

// Expired reports whether the in-flight hold has reached its timeout at `now`
// (now is at or after the deadline). It is the gate the caller polls to decide
// whether to call ResolveTimeout. A zero-deadline (no hold) state is never
// expired.
func (h HoldState) Expired(now time.Time) bool {
	if h.Deadline.IsZero() {
		return false
	}
	return !now.Before(h.Deadline)
}

// ResolveTimeout produces the TERMINAL decision for an in-flight hold whose
// window has expired with no in-window approval. The result is ALWAYS
// OutcomeBlockLog with DenyHoldTimeout — NEVER allow, NEVER kill (doc 16 §8.2 /
// D77). This holds identically whether the hold expired normally or whether
// attendedness dropped mid-hold and it ran to timeout (D78): a dropped-then-
// expired hold and a never-dropped expired hold resolve to the same block+log.
func (h HoldState) ResolveTimeout(now time.Time) Decision {
	return blockLog(h.Ask, DenyHoldTimeout, now)
}

// blockLog builds an immediate-block+log Decision carrying the D77 machine-
// readable deny reason projected from the ask (the D118 deny-memo shape).
// It is the single constructor for every block+log this file emits, so the
// "block+log never allows, never kills" invariant is structural: Decision has
// no allow/kill verb to set.
func blockLog(ask Ask, code DenyCode, now time.Time) Decision {
	_ = now // now is accepted for symmetry/extension; the block verb is timeless.
	return Decision{
		Outcome: OutcomeBlockLog,
		Reason: DenyReason{
			Code:          code,
			MatchedRuleID: ask.MatchedRuleID,
			ResourceKind:  ask.ResourceKind,
			ResourceName:  ask.ResourceName,
		},
	}
}
