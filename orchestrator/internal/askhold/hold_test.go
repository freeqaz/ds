// SPDX-License-Identifier: Apache-2.0

package askhold

import (
	"testing"
	"time"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// strawmanWindow is the doc 16 §8.2 strawman socket-hold budget, built here as
// INJECTED POL-1 values to prove the decision reads them rather than baking
// constants in. notify <= 5s + decision <= 40s + commit <= 5s == 50s total
// (inside the 30-60s socket-hold range; 10s is the outer ceiling the commit leg
// tolerates). The tests vary these to prove HoldFor/Deadline track the injected
// values, never a hardcoded number.
func strawmanWindow() Window {
	return Window{
		Notify:   5 * time.Second,
		Decision: 40 * time.Second,
		Commit:   5 * time.Second,
	}
}

func TestWindowTotal_SumsInjectedLegs(t *testing.T) {
	cases := []struct {
		name string
		win  Window
		want time.Duration
	}{
		{"strawman 50s", strawmanWindow(), 50 * time.Second},
		{"tuned tighter 30s", Window{Notify: 3 * time.Second, Decision: 25 * time.Second, Commit: 2 * time.Second}, 30 * time.Second},
		{"tuned wider 60s", Window{Notify: 5 * time.Second, Decision: 50 * time.Second, Commit: 5 * time.Second}, 60 * time.Second},
		{"zero", Window{}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.win.Total(); got != tc.want {
				t.Fatalf("Total() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDecide_AttendedUnknownDomain_OpensHoldWindow: the headline TLS-1 path.
// Attended unknown-domain -> socket-hold for the INJECTED window, VM keeps
// running (we model that as "no kill, no block, a hold with a future deadline").
func TestDecide_AttendedUnknownDomain_OpensHoldWindow(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	win := strawmanWindow()
	ask := Ask{ResourceKind: "domain", ResourceName: "pkg.example.dev", MatchedRuleID: "rule-unknown-domain"}
	att := Attendedness{Attended: true, AsOf: now}

	d := Decide(ask, att, win, now)

	if d.Outcome != OutcomeHold {
		t.Fatalf("Outcome = %v, want OutcomeHold (attended unknown-domain gets the socket-hold)", d.Outcome)
	}
	if d.HoldFor != win.Total() {
		t.Fatalf("HoldFor = %v, want injected Total %v (window must be injected, not hardcoded)", d.HoldFor, win.Total())
	}
	if !d.Deadline.Equal(now.Add(win.Total())) {
		t.Fatalf("Deadline = %v, want now+Total %v", d.Deadline, now.Add(win.Total()))
	}
	// VM keeps running: a hold is neither a block nor (structurally) a kill.
	if d.Reason.Code != "" {
		t.Fatalf("a fresh hold must carry no deny reason yet, got %q", d.Reason.Code)
	}
	assertNeverAllowNeverKill(t, d)
}

// TestDecide_HoldFor_TracksInjectedWindow proves the window is injected, not a
// constant: a different POL-1 budget yields a different hold length.
func TestDecide_HoldFor_TracksInjectedWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	ask := Ask{ResourceKind: "domain", ResourceName: "x.example", MatchedRuleID: "r1"}
	att := Attendedness{Attended: true, AsOf: now}

	for _, win := range []Window{
		{Notify: 1 * time.Second, Decision: 10 * time.Second, Commit: 1 * time.Second}, // 12s
		{Notify: 5 * time.Second, Decision: 40 * time.Second, Commit: 5 * time.Second}, // 50s
		{Notify: 2 * time.Second, Decision: 53 * time.Second, Commit: 5 * time.Second}, // 60s
	} {
		d := Decide(ask, att, win, now)
		if d.HoldFor != win.Total() {
			t.Fatalf("HoldFor = %v, want %v for window %+v", d.HoldFor, win.Total(), win)
		}
		if !d.Deadline.Equal(now.Add(win.Total())) {
			t.Fatalf("Deadline = %v, want %v for window %+v", d.Deadline, now.Add(win.Total()), win)
		}
	}
}

// TestDecide_UnattendedFromStart_ImmediateBlockLog: D77 downgrade. Unattended ->
// immediate block+log with the machine-readable reason; NO window opened.
func TestDecide_UnattendedFromStart_ImmediateBlockLog(t *testing.T) {
	now := time.Date(2026, 6, 15, 3, 0, 0, 0, time.UTC)
	win := strawmanWindow()
	ask := Ask{ResourceKind: "domain", ResourceName: "unknown.example", MatchedRuleID: "rule-7"}
	att := Attendedness{Attended: false, AsOf: now}

	d := Decide(ask, att, win, now)

	if d.Outcome != OutcomeBlockLog {
		t.Fatalf("Outcome = %v, want OutcomeBlockLog (unattended-from-start downgrades)", d.Outcome)
	}
	if d.HoldFor != 0 || !d.Deadline.IsZero() {
		t.Fatalf("unattended block+log must open NO window: HoldFor=%v Deadline=%v", d.HoldFor, d.Deadline)
	}
	if d.Reason.Code != DenyUnattended {
		t.Fatalf("Reason.Code = %q, want %q", d.Reason.Code, DenyUnattended)
	}
	// The deny memo must be self-describing (D77 machine-readable reason).
	if d.Reason.MatchedRuleID != "rule-7" || d.Reason.ResourceName != "unknown.example" || d.Reason.ResourceKind != "domain" {
		t.Fatalf("deny reason must echo the ask payload, got %+v", d.Reason)
	}
	assertNeverAllowNeverKill(t, d)
}

// TestDecide_Rung2_NeverSocketHeld: a genuine rung-2 ask must never become a
// non-parking hold even if mis-routed to Decide; it fails closed to block+log.
func TestDecide_Rung2_NeverSocketHeld(t *testing.T) {
	now := time.Now().UTC()
	win := strawmanWindow()
	ask := Ask{ResourceKind: "service", ResourceName: "bulk-delete", MatchedRuleID: "rule-suspend", Rung2: true}
	// Even attended, a rung-2 ask is not socket-held.
	att := Attendedness{Attended: true, AsOf: now}

	d := Decide(ask, att, win, now)

	if d.Outcome == OutcomeHold {
		t.Fatalf("a rung-2 ask must NEVER socket-hold via Decide; got %v", d.Outcome)
	}
	if d.Outcome != OutcomeBlockLog {
		t.Fatalf("mis-routed rung-2 must fail closed to block+log, got %v", d.Outcome)
	}
	assertNeverAllowNeverKill(t, d)
}

// TestHold_AttendednessDropMidHold_RunsToTimeout: the D78 invariant. A hold
// already in flight when attendedness drops RUNS TO ITS TIMEOUT — deadline
// unchanged, not blocked immediately, and the timeout resolves block+log (never
// allow, never kill).
func TestHold_AttendednessDropMidHold_RunsToTimeout(t *testing.T) {
	now := time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC)
	win := strawmanWindow()
	ask := Ask{ResourceKind: "domain", ResourceName: "midhold.example", MatchedRuleID: "rule-mid"}
	att := Attendedness{Attended: true, AsOf: now}

	d := Decide(ask, att, win, now)
	if d.Outcome != OutcomeHold {
		t.Fatalf("setup: expected OutcomeHold, got %v", d.Outcome)
	}
	hs := NewHoldState(ask, d)
	originalDeadline := hs.Deadline

	// Attendedness drops mid-hold (D78). The hold must run to timeout.
	dropped := hs.OnAttendednessDrop()

	if !dropped.AttendednessDropped {
		t.Fatalf("OnAttendednessDrop must mark the drop")
	}
	if !dropped.Deadline.Equal(originalDeadline) {
		t.Fatalf("D78: a drop must NOT shorten the deadline: got %v, want %v", dropped.Deadline, originalDeadline)
	}

	// Midway through the window (after the drop): NOT yet expired -> no resolution.
	mid := now.Add(win.Total() / 2)
	if dropped.Expired(mid) {
		t.Fatalf("D78: a dropped hold must keep running until its deadline, not block immediately at %v", mid)
	}

	// At the deadline: it times out and resolves block+log — never allow, never kill.
	atDeadline := originalDeadline
	if !dropped.Expired(atDeadline) {
		t.Fatalf("hold must be expired at its deadline %v", atDeadline)
	}
	timeout := dropped.ResolveTimeout(atDeadline)
	if timeout.Outcome != OutcomeBlockLog {
		t.Fatalf("a timed-out hold must resolve OutcomeBlockLog, got %v", timeout.Outcome)
	}
	if timeout.Reason.Code != DenyHoldTimeout {
		t.Fatalf("Reason.Code = %q, want %q", timeout.Reason.Code, DenyHoldTimeout)
	}
	assertNeverAllowNeverKill(t, timeout)
}

// TestHold_NormalTimeout_BlockLogNeverAllow: a hold whose window expires with NO
// approval and NO drop closes block+log — the no-timeout-into-allow invariant.
func TestHold_NormalTimeout_BlockLogNeverAllow(t *testing.T) {
	now := time.Unix(1_781_000_000, 0).UTC()
	win := strawmanWindow()
	ask := Ask{ResourceKind: "domain", ResourceName: "normal.example", MatchedRuleID: "rule-n"}
	att := Attendedness{Attended: true, AsOf: now}

	d := Decide(ask, att, win, now)
	hs := NewHoldState(ask, d)

	// Before the deadline: not expired.
	if hs.Expired(now.Add(win.Total() - time.Second)) {
		t.Fatalf("hold must not be expired one second before its deadline")
	}
	// At/after the deadline: expired, resolves block+log.
	after := hs.Deadline.Add(time.Nanosecond)
	if !hs.Expired(after) {
		t.Fatalf("hold must be expired after its deadline")
	}
	timeout := hs.ResolveTimeout(after)
	if timeout.Outcome != OutcomeBlockLog || timeout.Reason.Code != DenyHoldTimeout {
		t.Fatalf("normal timeout must be block+log/%s, got %v/%s", DenyHoldTimeout, timeout.Outcome, timeout.Reason.Code)
	}
	assertNeverAllowNeverKill(t, timeout)
}

// TestNewHoldState_NonHoldDecision_ZeroState: a block+log decision yields no
// in-flight hold to track.
func TestNewHoldState_NonHoldDecision_ZeroState(t *testing.T) {
	now := time.Now().UTC()
	d := Decide(Ask{MatchedRuleID: "r"}, Attendedness{Attended: false, AsOf: now}, strawmanWindow(), now)
	hs := NewHoldState(Ask{}, d)
	if !hs.Deadline.IsZero() {
		t.Fatalf("a non-hold decision must yield a zero HoldState, got deadline %v", hs.Deadline)
	}
	if hs.Expired(now.Add(time.Hour)) {
		t.Fatalf("a zero HoldState must never be Expired")
	}
}

// TestFromProto_ConsumesFrozenAskUserRequest proves the package consumes the
// REAL generated boundary/v1.AskUserRequest read-only (the resource triple +
// POL-3 matched-rule id), never re-declaring it. The rung-2 bit is not on the
// wire shape, so it is passed explicitly.
func TestFromProto_ConsumesFrozenAskUserRequest(t *testing.T) {
	req := &boundaryv1.AskUserRequest{
		Session:       &boundaryv1.SessionRef{SessionUuid: "sess-1"},
		ResourceKind:  "domain",
		ResourceName:  "from-proto.example",
		MatchedRuleId: "rule-proto",
		PolicyLayer:   "org",
		PolicyVersion: 42,
	}

	ask := FromProto(req, false)
	if ask.ResourceKind != "domain" || ask.ResourceName != "from-proto.example" || ask.MatchedRuleID != "rule-proto" {
		t.Fatalf("FromProto must project the frozen ask payload, got %+v", ask)
	}
	if ask.Rung2 {
		t.Fatalf("rung-2 must come from the explicit arg, not the wire shape")
	}

	// And the projected ask drives a real decision end-to-end.
	now := time.Now().UTC()
	d := Decide(ask, Attendedness{Attended: true, AsOf: now}, strawmanWindow(), now)
	if d.Outcome != OutcomeHold {
		t.Fatalf("attended proto-sourced unknown-domain ask should hold, got %v", d.Outcome)
	}

	// rung-2 projection routes away from a socket-hold.
	rung2 := FromProto(req, true)
	if !rung2.Rung2 {
		t.Fatalf("FromProto must carry the explicit rung-2 bit")
	}

	// nil request is tolerated defensively.
	if got := FromProto(nil, true); got.ResourceKind != "" || !got.Rung2 {
		t.Fatalf("FromProto(nil) must yield a zero ask carrying only the rung-2 bit, got %+v", got)
	}
}

// TestOutcome_String covers the human-readable verbs (vet/coverage hygiene).
func TestOutcome_String(t *testing.T) {
	cases := map[Outcome]string{
		OutcomeUnspecified: "UNSPECIFIED",
		OutcomeHold:        "HOLD",
		OutcomeBlockLog:    "BLOCK_LOG",
	}
	for o, want := range cases {
		if got := o.String(); got != want {
			t.Fatalf("Outcome(%d).String() = %q, want %q", o, got, want)
		}
	}
}

// assertNeverAllowNeverKill is the load-bearing invariant guard reused across
// every decision-producing test: a Decision's Outcome is ALWAYS one of the
// closed {Hold, BlockLog} verbs and NEVER an allow or a kill. Because Outcome is
// a closed enum with no allow/kill member, this is enforced structurally; the
// assertion documents and pins it so any future widening of the enum that added
// such a verb would have to consciously break these tests.
func assertNeverAllowNeverKill(t *testing.T, d Decision) {
	t.Helper()
	switch d.Outcome {
	case OutcomeHold, OutcomeBlockLog:
		// ok — neither allow nor kill exists in the verb set.
	default:
		t.Fatalf("Decision yielded a verb outside {HOLD, BLOCK_LOG}: %v — a timeout/decision must NEVER allow or kill", d.Outcome)
	}
}
