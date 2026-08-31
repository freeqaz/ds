// SPDX-License-Identifier: Apache-2.0

package askhold

import (
	"errors"
	"testing"
	"time"
)

// recordingRecorder is a synthetic in-process fake of the injected
// orchestrator-doc ParkRecorder seam (D50 — no live IO). It records the
// session<->question joins and resume-clears so tests can assert the state
// machine drives the seam; an optional injected error exercises the
// record-failure-does-not-un-park path.
type recordingRecorder struct {
	parked  []Parked
	cleared []Parked
	recErr  error
	clrErr  error
}

func (r *recordingRecorder) RecordParked(p Parked) error {
	r.parked = append(r.parked, p)
	return r.recErr
}

func (r *recordingRecorder) ClearParked(p Parked) error {
	r.cleared = append(r.cleared, p)
	return r.clrErr
}

func rung2Ask() Ask {
	return Ask{ResourceKind: "service", ResourceName: "bulk-delete", MatchedRuleID: "rule-suspend", Rung2: true}
}

func strawmanBudget() PauseBudget {
	// D46 strawman tiers as INJECTED POL-1 values, not constants: <=5min
	// transparent, <=15min best-effort, >15min snapshot+park.
	return PauseBudget{Transparent: 5 * time.Minute, BestEffort: 15 * time.Minute}
}

// TestNewParked_Rung2_Parks: a genuine rung-2 ask PARKS (not a socket-hold) and
// the session<->question join is recorded via the injected seam.
func TestNewParked_Rung2_Parks(t *testing.T) {
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	rec := &recordingRecorder{}

	p, err := NewParked(rec, "sess-42", rung2Ask(), now)
	if err != nil {
		t.Fatalf("NewParked error: %v", err)
	}
	if p.Phase != ParkPhaseParked {
		t.Fatalf("Phase = %v, want ParkPhaseParked", p.Phase)
	}
	if p.SessionUUID != "sess-42" || !p.ParkedAt.Equal(now) {
		t.Fatalf("parked state not stamped: %+v", p)
	}
	if len(rec.parked) != 1 || rec.parked[0].SessionUUID != "sess-42" {
		t.Fatalf("RecordParked must be called once with the join, got %+v", rec.parked)
	}
	if len(rec.cleared) != 0 {
		t.Fatalf("no clear should happen on park")
	}
}

// TestNewParked_NonRung2_Refused: only genuine rung-2 asks park; an ordinary
// (socket-hold) ask is refused here.
func TestNewParked_NonRung2_Refused(t *testing.T) {
	rec := &recordingRecorder{}
	_, err := NewParked(rec, "sess-1", Ask{ResourceName: "x.example"}, time.Now())
	if !errors.Is(err, errNotRung2) {
		t.Fatalf("NewParked of a non-rung-2 ask must be refused, got %v", err)
	}
	if len(rec.parked) != 0 {
		t.Fatalf("a refused park must record nothing, got %+v", rec.parked)
	}
}

// TestNewParked_NilRecorder_StillParks: the recorder is optional — the decision
// stands with no seam at all (unit-testable in isolation).
func TestNewParked_NilRecorder_StillParks(t *testing.T) {
	now := time.Now().UTC()
	p, err := NewParked(nil, "sess-9", rung2Ask(), now)
	if err != nil {
		t.Fatalf("nil recorder must be tolerated, got %v", err)
	}
	if p.Phase != ParkPhaseParked {
		t.Fatalf("Phase = %v, want ParkPhaseParked", p.Phase)
	}
}

// TestNewParked_RecordError_StillParked: a record failure does NOT un-park —
// the ask stays in the safe (parked) state and the error surfaces for retry.
func TestNewParked_RecordError_StillParked(t *testing.T) {
	now := time.Now().UTC()
	wantErr := errors.New("record backend down")
	rec := &recordingRecorder{recErr: wantErr}

	p, err := NewParked(rec, "sess-7", rung2Ask(), now)
	if !errors.Is(err, wantErr) {
		t.Fatalf("record error must surface, got %v", err)
	}
	if p.Phase != ParkPhaseParked {
		t.Fatalf("a record failure must NOT un-park; phase = %v", p.Phase)
	}
}

// TestParked_BudgetTier_NeverResolves: the D46 tiered budget classifies elapsed
// pause for TRANSPARENCY only — crossing every tier (incl. >15min snapshot+park)
// leaves the ask PARKED. This is the rung-2-park-not-timeout invariant: the
// clock never resolves the ask.
func TestParked_BudgetTier_NeverResolves(t *testing.T) {
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	budget := strawmanBudget()
	p, err := NewParked(nil, "sess-1", rung2Ask(), now)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	cases := []struct {
		name    string
		elapsed time.Duration
		want    PauseTier
	}{
		{"fresh", 0, TierTransparent},
		{"4m transparent", 4 * time.Minute, TierTransparent},
		{"5m boundary transparent", 5 * time.Minute, TierTransparent},
		{"10m best-effort", 10 * time.Minute, TierBestEffort},
		{"15m boundary best-effort", 15 * time.Minute, TierBestEffort},
		{"30m snapshot+park", 30 * time.Minute, TierSnapshotPark},
		{"1 day snapshot+park", 24 * time.Hour, TierSnapshotPark},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := now.Add(tc.elapsed)
			if got := p.Tier(budget, at); got != tc.want {
				t.Fatalf("Tier(%v) = %v, want %v", tc.elapsed, got, tc.want)
			}
			// CRUCIAL: regardless of tier, the ask is still PARKED — no
			// time-based transition to allow or kill exists. The park type
			// carries no verdict until a human answers.
			if p.Phase != ParkPhaseParked {
				t.Fatalf("a budget tier must NEVER resolve the park; phase=%v after %v", p.Phase, tc.elapsed)
			}
			if p.Verdict != ResumeVerdictUnspecified {
				t.Fatalf("a parked ask must carry NO verdict from a timeout; got %v", p.Verdict)
			}
		})
	}
}

// TestParked_BudgetTier_TracksInjectedValues proves the tiers are injected POL-1
// values, not constants: a tighter budget reclassifies the same elapsed pause.
func TestParked_BudgetTier_TracksInjectedValues(t *testing.T) {
	tight := PauseBudget{Transparent: 30 * time.Second, BestEffort: 90 * time.Second}
	cases := []struct {
		elapsed time.Duration
		want    PauseTier
	}{
		{10 * time.Second, TierTransparent},
		{60 * time.Second, TierBestEffort},
		{120 * time.Second, TierSnapshotPark},
	}
	for _, tc := range cases {
		if got := tight.Tier(tc.elapsed); got != tc.want {
			t.Fatalf("tight.Tier(%v) = %v, want %v (tiers must be injected)", tc.elapsed, got, tc.want)
		}
	}
}

// TestParked_ResumeOnAnswer_Allow: a human ALLOW answer (arriving out-of-band on
// the policy stream) resumes the park, carries the opaque grant scope, and
// clears the join via the injected seam.
func TestParked_ResumeOnAnswer_Allow(t *testing.T) {
	now := time.Date(2026, 6, 15, 11, 0, 0, 0, time.UTC)
	rec := &recordingRecorder{}
	p, err := NewParked(rec, "sess-3", rung2Ask(), now)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	later := now.Add(7 * time.Minute) // well past the transparent tier — still parked until answered.
	resumed, err := p.Resume(rec, ResumeVerdictAllow, "allow-once:service/bulk-delete;ttl=session", DenyReason{}, later)
	if err != nil {
		t.Fatalf("Resume error: %v", err)
	}
	if resumed.Phase != ParkPhaseResumed {
		t.Fatalf("Phase = %v, want ParkPhaseResumed", resumed.Phase)
	}
	if resumed.Verdict != ResumeVerdictAllow {
		t.Fatalf("Verdict = %v, want ResumeVerdictAllow", resumed.Verdict)
	}
	if resumed.GrantScope == "" {
		t.Fatalf("an allow resume must carry the opaque grant scope")
	}
	if !resumed.ResumedAt.Equal(later) {
		t.Fatalf("ResumedAt = %v, want %v", resumed.ResumedAt, later)
	}
	if len(rec.cleared) != 1 || rec.cleared[0].SessionUUID != "sess-3" {
		t.Fatalf("Resume must ClearParked the join once, got %+v", rec.cleared)
	}
}

// TestParked_ResumeOnAnswer_Deny: a human DENY answer resumes the park carrying
// the D77 machine-readable deny reason so a retry fast-fails (D118 deny-memo
// shape) — still NOT a kill.
func TestParked_ResumeOnAnswer_Deny(t *testing.T) {
	now := time.Now().UTC()
	rec := &recordingRecorder{}
	p, _ := NewParked(rec, "sess-5", rung2Ask(), now)

	reason := DenyReason{Code: DenyUnattended, MatchedRuleID: "rule-suspend", ResourceKind: "service", ResourceName: "bulk-delete"}
	resumed, err := p.Resume(rec, ResumeVerdictDeny, "", reason, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Resume error: %v", err)
	}
	if resumed.Verdict != ResumeVerdictDeny {
		t.Fatalf("Verdict = %v, want ResumeVerdictDeny", resumed.Verdict)
	}
	if resumed.DenyReason.MatchedRuleID != "rule-suspend" {
		t.Fatalf("a deny resume must carry the machine-readable reason, got %+v", resumed.DenyReason)
	}
	if resumed.GrantScope != "" {
		t.Fatalf("a deny resume must carry NO grant scope, got %q", resumed.GrantScope)
	}
}

// TestParked_Resume_RequiresParkedAndVerdict: a resume must come from an actual
// human answer on a currently-parked ask — never a synthesized timeout verdict,
// never a double-resume.
func TestParked_Resume_RequiresParkedAndVerdict(t *testing.T) {
	now := time.Now().UTC()
	p, _ := NewParked(nil, "sess-1", rung2Ask(), now)

	// Unspecified verdict is rejected — a resume needs a real answer.
	if _, err := p.Resume(nil, ResumeVerdictUnspecified, "", DenyReason{}, now); !errors.Is(err, errNoVerdict) {
		t.Fatalf("unspecified verdict must be rejected, got %v", err)
	}

	// First resume succeeds.
	resumed, err := p.Resume(nil, ResumeVerdictAllow, "scope", DenyReason{}, now)
	if err != nil {
		t.Fatalf("first resume: %v", err)
	}
	// Double-resume is rejected (already resolved, not parked).
	if _, err := resumed.Resume(nil, ResumeVerdictDeny, "", DenyReason{}, now); !errors.Is(err, errNotParked) {
		t.Fatalf("double-resume must be rejected, got %v", err)
	}
}

// TestParked_Resume_ClearError_StillResumed: a ClearParked seam failure does NOT
// re-park — the resume stands and the error surfaces for retry.
func TestParked_Resume_ClearError_StillResumed(t *testing.T) {
	now := time.Now().UTC()
	wantErr := errors.New("clear backend down")
	rec := &recordingRecorder{clrErr: wantErr}
	p, _ := NewParked(rec, "sess-8", rung2Ask(), now)

	resumed, err := p.Resume(rec, ResumeVerdictAllow, "scope", DenyReason{}, now.Add(time.Second))
	if !errors.Is(err, wantErr) {
		t.Fatalf("clear error must surface, got %v", err)
	}
	if resumed.Phase != ParkPhaseResumed {
		t.Fatalf("a clear failure must NOT re-park; phase = %v", resumed.Phase)
	}
}

// TestPark_NeverTimesOutIntoAllowOrKill is the headline D46/D77 invariant for
// parks: there is NO clock-driven exit from a park anywhere. We assert it
// structurally — the only transition out of ParkPhaseParked is Resume (an
// answer), and the ParkPhase/ResumeVerdict sets contain no allow-on-timeout /
// kill member. Driving the budget arbitrarily far never changes Phase or
// Verdict; only an explicit human answer does.
func TestPark_NeverTimesOutIntoAllowOrKill(t *testing.T) {
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	budget := strawmanBudget()
	p, _ := NewParked(nil, "sess-1", rung2Ask(), now)

	// Advance the pause clock by a year — far past every D46 tier.
	for _, elapsed := range []time.Duration{time.Hour, 24 * time.Hour, 365 * 24 * time.Hour} {
		at := now.Add(elapsed)
		_ = p.Tier(budget, at) // classifying transparency never mutates the park.
		if p.Phase != ParkPhaseParked {
			t.Fatalf("after %v the ask must still be PARKED (never timed out into allow/kill); phase=%v", elapsed, p.Phase)
		}
		if p.Verdict != ResumeVerdictUnspecified {
			t.Fatalf("after %v the ask must carry NO verdict (no timeout-allow/kill); verdict=%v", elapsed, p.Verdict)
		}
	}

	// The ONLY exit is an explicit human answer.
	resumed, err := p.Resume(nil, ResumeVerdictAllow, "scope", DenyReason{}, now.Add(400*24*time.Hour))
	if err != nil {
		t.Fatalf("resume on answer must succeed regardless of elapsed pause: %v", err)
	}
	if resumed.Phase != ParkPhaseResumed || resumed.Verdict != ResumeVerdictAllow {
		t.Fatalf("the only park exit is a human answer; got phase=%v verdict=%v", resumed.Phase, resumed.Verdict)
	}
}

// TestPhaseAndVerdictAndTier_String covers the stringers (vet/coverage hygiene)
// and pins that the closed sets contain no allow-on-timeout/kill member.
func TestPhaseAndVerdictAndTier_String(t *testing.T) {
	if ParkPhaseParked.String() != "PARKED" || ParkPhaseResumed.String() != "RESUMED" || ParkPhaseUnspecified.String() != "UNSPECIFIED" {
		t.Fatalf("ParkPhase stringer mismatch")
	}
	if ResumeVerdictAllow.String() != "ALLOW" || ResumeVerdictDeny.String() != "DENY" || ResumeVerdictUnspecified.String() != "UNSPECIFIED" {
		t.Fatalf("ResumeVerdict stringer mismatch")
	}
	if TierTransparent.String() != "TRANSPARENT" || TierBestEffort.String() != "BEST_EFFORT" || TierSnapshotPark.String() != "SNAPSHOT_PARK" {
		t.Fatalf("PauseTier stringer mismatch")
	}
}
