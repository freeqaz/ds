// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"testing"
	"time"
)

// frozenClock returns a now func() time.Time pinned at t — the clock-injection the
// escalation clock is built on, so the D46 tier boundaries are deterministic.
func frozenClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestEscalationConfigValidate(t *testing.T) {
	if err := NewEscalationConfig().Validate(); err != nil {
		t.Fatalf("strawman default config must be valid: %v", err)
	}
	cases := []struct {
		name    string
		cfg     EscalationConfig
		wantErr bool
	}{
		{"strawman", NewEscalationConfig(), false},
		{"rig-tuned ordered", EscalationConfig{TransparentMax: 2 * time.Minute, BestEffortMax: 10 * time.Minute}, false},
		{"zero transparent", EscalationConfig{TransparentMax: 0, BestEffortMax: 10 * time.Minute}, true},
		{"negative transparent", EscalationConfig{TransparentMax: -1, BestEffortMax: 10 * time.Minute}, true},
		{"besteffort == transparent (tier collapse)", EscalationConfig{TransparentMax: 5 * time.Minute, BestEffortMax: 5 * time.Minute}, true},
		{"besteffort < transparent (inverted)", EscalationConfig{TransparentMax: 15 * time.Minute, BestEffortMax: 5 * time.Minute}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate()=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestNewEscalationClockRejectsInvalidConfig(t *testing.T) {
	if _, err := NewEscalationClock(EscalationConfig{TransparentMax: 5 * time.Minute, BestEffortMax: 5 * time.Minute}, frozenClock(time.Now())); err == nil {
		t.Fatal("expected construction error for a tier-collapsing config")
	}
	if _, err := NewEscalationClock(NewEscalationConfig(), nil); err != nil {
		t.Fatalf("nil now should default to time.Now, got error: %v", err)
	}
}

// TestEscalationTiersAtBoundaryInstants pins the THREE D46 tier verdicts at the
// boundary instants — the load-bearing acceptance check. The boundaries are
// INCLUSIVE upper bounds: exactly 5:00 is transparent, one tick past is best-effort;
// exactly 15:00 is best-effort, one tick past escalates.
func TestEscalationTiersAtBoundaryInstants(t *testing.T) {
	suspendedAt := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	cfg := NewEscalationConfig() // 5 min / 15 min strawman

	cases := []struct {
		name     string
		elapsed  time.Duration
		wantTier EscalationTier
	}{
		{"at instant (0)", 0, TierTransparent},
		{"mid transparent", 2 * time.Minute, TierTransparent},
		{"exactly 5:00 inclusive transparent", 5 * time.Minute, TierTransparent},
		{"5:00 + 1ns best-effort", 5*time.Minute + time.Nanosecond, TierBestEffort},
		{"mid best-effort", 10 * time.Minute, TierBestEffort},
		{"exactly 15:00 inclusive best-effort", 15 * time.Minute, TierBestEffort},
		{"15:00 + 1ns escalate", 15*time.Minute + time.Nanosecond, TierEscalate},
		{"well past escalate", time.Hour, TierEscalate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk, err := NewEscalationClock(cfg, frozenClock(suspendedAt.Add(tc.elapsed)))
			if err != nil {
				t.Fatalf("NewEscalationClock: %v", err)
			}
			v := clk.Classify(suspendedAt)
			if v.Tier != tc.wantTier {
				t.Fatalf("elapsed %s: tier=%s, want %s", tc.elapsed, v.Tier, tc.wantTier)
			}
			if v.Elapsed != tc.elapsed {
				t.Fatalf("elapsed recorded %s, want %s", v.Elapsed, tc.elapsed)
			}
			// Deadline contract: hold tiers carry a deadline; escalate is terminal.
			switch tc.wantTier {
			case TierTransparent:
				if !v.HasDeadline() || !v.TierDeadline.Equal(suspendedAt.Add(cfg.TransparentMax)) {
					t.Fatalf("transparent deadline=%v, want %v", v.TierDeadline, suspendedAt.Add(cfg.TransparentMax))
				}
				if !v.Tier.Transparent() {
					t.Fatal("transparent tier must report Transparent()=true")
				}
			case TierBestEffort:
				if !v.HasDeadline() || !v.TierDeadline.Equal(suspendedAt.Add(cfg.BestEffortMax)) {
					t.Fatalf("best-effort deadline=%v, want %v", v.TierDeadline, suspendedAt.Add(cfg.BestEffortMax))
				}
				if v.Tier.Transparent() {
					t.Fatal("best-effort tier must report Transparent()=false")
				}
			case TierEscalate:
				if v.HasDeadline() {
					t.Fatalf("escalate tier must be terminal (no deadline), got %v", v.TierDeadline)
				}
				if !v.Tier.EscalatesToPark() {
					t.Fatal("escalate tier must report EscalatesToPark()=true")
				}
			}
		})
	}
}

// TestEscalationClampsBackwardsSkew: a now BEFORE the suspend instant (clock skew)
// clamps elapsed to 0 — the clock never escalates on a backwards observation.
func TestEscalationClampsBackwardsSkew(t *testing.T) {
	suspendedAt := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	clk, err := NewEscalationClock(NewEscalationConfig(), frozenClock(suspendedAt.Add(-time.Hour)))
	if err != nil {
		t.Fatalf("NewEscalationClock: %v", err)
	}
	v := clk.Classify(suspendedAt)
	if v.Tier != TierTransparent || v.Elapsed != 0 {
		t.Fatalf("backwards skew should clamp to transparent/0, got tier=%s elapsed=%s", v.Tier, v.Elapsed)
	}
}

// TestEscalationRigTunedBoundaries: the boundaries are rig-tuned/free while the
// three-tier shape is the contract — a tighter rig re-tiers the same elapsed values.
func TestEscalationRigTunedBoundaries(t *testing.T) {
	suspendedAt := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	cfg := NewEscalationConfig().WithBoundaries(1*time.Minute, 3*time.Minute)
	clk, err := NewEscalationClock(cfg, frozenClock(suspendedAt.Add(2*time.Minute)))
	if err != nil {
		t.Fatalf("NewEscalationClock: %v", err)
	}
	// 2 min is transparent under the strawman 5-min boundary but best-effort under the
	// rig-tuned 1-min boundary — the tiers moved, the shape did not.
	if got := clk.Classify(suspendedAt).Tier; got != TierBestEffort {
		t.Fatalf("rig-tuned 1m/3m at 2m elapsed: tier=%s, want best-effort", got)
	}
	if clk.Config().TransparentMax != time.Minute {
		t.Fatalf("Config did not reflect the rig tune: %v", clk.Config())
	}
}

func TestEscalationTierString(t *testing.T) {
	for tier, want := range map[EscalationTier]string{
		TierTransparent: "transparent",
		TierBestEffort:  "best-effort",
		TierEscalate:    "escalate",
	} {
		if got := tier.String(); got != want {
			t.Fatalf("%d.String()=%q, want %q", int(tier), got, want)
		}
	}
}
