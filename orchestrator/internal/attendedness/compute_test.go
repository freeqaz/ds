package attendedness

import (
	"testing"
	"time"
)

// fixedClock is a synthetic, deterministic clock (D50 synthetic fixtures): no wall
// clock enters these tests, so AttendedAt is exactly predictable.
var fixedClock = time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)

// TestCompute_WriterHeldByHumanIsAttended proves the M0/M1 interim core: a human
// holding the one writer seat makes the session attended (doc 15 §5.5, D78).
func TestCompute_WriterHeldByHumanIsAttended(t *testing.T) {
	sig := Compute(
		SeatView{Role: RoleWriter, Holder: "writer-a"},
		Input{}, // interim: no input signal
		Policy{},
		fixedClock,
	)
	if !sig.Attended {
		t.Fatalf("attended = false, want true when a human holds the writer seat")
	}
	if sig.AttendedAt != uint64(fixedClock.Unix()) {
		t.Fatalf("attended_at = %d, want server clock %d", sig.AttendedAt, fixedClock.Unix())
	}
}

// TestCompute_NoWriterSeatIsUnattended proves the writer-less record (the
// post-detach state, where attach.ReleaseWriter cleared the seat to RoleNone) is
// NOT attended — the signal tracks the record honestly across detach (D78).
func TestCompute_NoWriterSeatIsUnattended(t *testing.T) {
	sig := Compute(
		SeatView{Role: RoleNone, Holder: ""},
		Input{},
		Policy{},
		fixedClock,
	)
	if sig.Attended {
		t.Fatalf("attended = true, want false when no writer holds the seat")
	}
	// The freshness clock is stamped even on an UNATTENDED verdict so the
	// consumer's few-seconds budget is always measurable (§5.5/D78).
	if sig.AttendedAt != uint64(fixedClock.Unix()) {
		t.Fatalf("attended_at = %d, want server clock %d stamped even when unattended", sig.AttendedAt, fixedClock.Unix())
	}
}

// TestCompute_ReadersNeverCount proves spectators / readers / canvas viewers NEVER
// make a session attended (doc 15 §5.5) — only the WRITER seat holder counts.
func TestCompute_ReadersNeverCount(t *testing.T) {
	sig := Compute(
		SeatView{Role: RoleReader, Holder: "spectator-1"},
		Input{},
		Policy{},
		fixedClock,
	)
	if sig.Attended {
		t.Fatalf("attended = true for a READER seat; spectators/readers/canvas viewers must never count (§5.5)")
	}
}

// TestCompute_WriterRoleWithoutHolderIsUnattended proves a half-cleared / anonymous
// writer role (RoleWriter but empty Holder) is NOT attended — the computation
// refuses to claim a human on the seat without attribution (D61).
func TestCompute_WriterRoleWithoutHolderIsUnattended(t *testing.T) {
	sig := Compute(
		SeatView{Role: RoleWriter, Holder: ""},
		Input{},
		Policy{},
		fixedClock,
	)
	if sig.Attended {
		t.Fatalf("attended = true for a writer role with no holder; an anonymous seat is not a human on the seat")
	}
}

// TestCompute_AttendedAtIsServerClock proves attended_at is the SERVER-stamped
// freshness clock passed in (§5.5/D78), not a wall clock — moving the clock moves
// the stamp deterministically.
func TestCompute_AttendedAtIsServerClock(t *testing.T) {
	later := fixedClock.Add(37 * time.Second)
	sig := Compute(SeatView{Role: RoleWriter, Holder: "writer-a"}, Input{}, Policy{}, later)
	if sig.AttendedAt != uint64(later.Unix()) {
		t.Fatalf("attended_at = %d, want %d (the server clock handed to Compute)", sig.AttendedAt, later.Unix())
	}
}

// TestCompute_InterimIgnoresRecentInputWindow proves the M0/M1 interim is
// WRITER-ATTACHED-ONLY: with no input signal exposed (Input.HasInputSignal ==
// false), the recent-input window does NOT downgrade an attended-by-seat session,
// even when the policy window is set and any plausible last-input would be stale.
// This pins that the recent-input refinement is correctly DEFERRED (doc 15 §5.5,
// §6.1 row 7).
func TestCompute_InterimIgnoresRecentInputWindow(t *testing.T) {
	policy := Policy{RecentInputWindow: 10 * time.Minute}
	sig := Compute(
		SeatView{Role: RoleWriter, Holder: "writer-a"},
		Input{HasInputSignal: false, LastInputAt: fixedClock.Add(-time.Hour)}, // stale, but no signal
		policy,
		fixedClock,
	)
	if !sig.Attended {
		t.Fatalf("attended = false; interim must be writer-attached-only and ignore the recent-input window without an input signal")
	}
}

// TestCompute_RecentInputGateTightensWhenSignalPresent proves the structure for the
// FUTURE refinement (not active in the interim): once input-activity events land
// and the caller threads a real last-input timestamp (HasInputSignal == true),
// stale input downgrades an attended-by-seat session, and fresh input keeps it
// attended. This proves T is honored as a policy VALUE, not hardcoded.
func TestCompute_RecentInputGateTightensWhenSignalPresent(t *testing.T) {
	policy := Policy{RecentInputWindow: 10 * time.Minute}

	stale := Compute(
		SeatView{Role: RoleWriter, Holder: "writer-a"},
		Input{HasInputSignal: true, LastInputAt: fixedClock.Add(-11 * time.Minute)},
		policy,
		fixedClock,
	)
	if stale.Attended {
		t.Fatalf("attended = true with input older than T; the recent-input gate must downgrade when a signal exists")
	}

	fresh := Compute(
		SeatView{Role: RoleWriter, Holder: "writer-a"},
		Input{HasInputSignal: true, LastInputAt: fixedClock.Add(-1 * time.Minute)},
		policy,
		fixedClock,
	)
	if !fresh.Attended {
		t.Fatalf("attended = false with input within T; fresh writer input must keep the session attended")
	}
}
