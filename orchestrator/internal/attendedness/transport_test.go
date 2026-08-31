package attendedness

import (
	"context"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// seedSession creates a minimal PENDING session record so the real attach seat
// arbitration (attach.AcquireWriter/AcquireReader/ReleaseWriter) has a record to
// mutate, matching the seat_test.go fixture (D50 synthetic).
func seedSession(t *testing.T, repo *store.Memory, uuid string) {
	t.Helper()
	_, err := repo.CreateSession(context.Background(), store.Session{
		Ref: store.SessionRef{
			SessionUUID:      uuid,
			HostID:           "host-a",
			HostSessionIndex: 1,
			TapName:          "tap-" + uuid,
		},
		State: store.SessionPending,
	})
	if err != nil {
		t.Fatalf("CreateSession(%s): %v", uuid, err)
	}
}

// signalFromRecord runs the real read path: read the authoritative record, project
// its writer seat, and compute the attendedness signal at `now`. This is exactly
// the control-plane-side computation the lifecycle leg performs.
func signalFromRecord(t *testing.T, repo *store.Memory, uuid string, now time.Time) Signal {
	t.Helper()
	s, err := repo.GetSession(context.Background(), uuid)
	if err != nil {
		t.Fatalf("GetSession(%s): %v", uuid, err)
	}
	return Compute(SeatViewFromRecord(s), Input{}, Policy{}, now)
}

// TestLifecycle_AttendedTrueWhenHumanHoldsWriterSeat drives the REAL seat
// arbitration: a human acquiring the one writer seat makes the session attended,
// and BuildLifecycleUpdate folds it onto the frozen SessionLifecycleUpdate.attended
// / .attended_at slots so it rides the existing host-ward lifecycle channel
// (transport, no new contract).
func TestLifecycle_AttendedTrueWhenHumanHoldsWriterSeat(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1")

	if _, err := attach.AcquireWriter(ctx, repo, "sess-1", "human-writer", false); err != nil {
		t.Fatalf("AcquireWriter: %v", err)
	}

	sig := signalFromRecord(t, repo, "sess-1", fixedClock)
	if !sig.Attended {
		t.Fatalf("attended = false after a human took the writer seat, want true")
	}

	upd := BuildLifecycleUpdate("sess-1", sig)
	if upd.GetSessionUuid() != "sess-1" {
		t.Fatalf("lifecycle update session_uuid = %q, want sess-1", upd.GetSessionUuid())
	}
	if !upd.GetAttended() {
		t.Fatalf("SessionLifecycleUpdate.attended = false, want true (the signal must populate the frozen field-4 slot)")
	}
	if upd.GetAttendedAt() != uint64(fixedClock.Unix()) {
		t.Fatalf("SessionLifecycleUpdate.attended_at = %d, want %d (field-5 freshness stamp)", upd.GetAttendedAt(), fixedClock.Unix())
	}
}

// TestLifecycle_DetachFlipsAttendedFalseGoingForward proves the D78 detach
// semantics at the SIGNAL level: releasing the writer seat (a detach) flips
// attended → false going forward. The signal is reported HONESTLY across the
// transition; the in-flight-hold grace (holds run to their 30–60 s timeout) is the
// CONSUMER's enforcement, not this computation's — this leg never retroactively
// lies about the seat.
func TestLifecycle_DetachFlipsAttendedFalseGoingForward(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1")

	if _, err := attach.AcquireWriter(ctx, repo, "sess-1", "human-writer", false); err != nil {
		t.Fatalf("AcquireWriter: %v", err)
	}
	// Before detach: attended.
	before := signalFromRecord(t, repo, "sess-1", fixedClock)
	if !before.Attended {
		t.Fatalf("pre-detach attended = false, want true")
	}

	// Detach: the holder releases the writer seat (clears the record's seat).
	if err := attach.ReleaseWriter(ctx, repo, "sess-1", "human-writer"); err != nil {
		t.Fatalf("ReleaseWriter: %v", err)
	}

	// After detach: a NEW computation reports unattended going forward.
	after := signalFromRecord(t, repo, "sess-1", fixedClock.Add(time.Second))
	if after.Attended {
		t.Fatalf("post-detach attended = true, want false going forward (D78)")
	}
	upd := BuildLifecycleUpdate("sess-1", after)
	if upd.GetAttended() {
		t.Fatalf("post-detach SessionLifecycleUpdate.attended = true, want false")
	}
	// attended_at is still stamped on the unattended frame so the consumer's
	// freshness budget remains measurable across the transition.
	if upd.GetAttendedAt() != uint64(fixedClock.Add(time.Second).Unix()) {
		t.Fatalf("post-detach attended_at = %d, want the new server stamp %d", upd.GetAttendedAt(), fixedClock.Add(time.Second).Unix())
	}
}

// TestLifecycle_InFlightHoldComputedBeforeDetachSurvivesTransition proves the D78
// detach-mid-hold guarantee at the boundary this leg owns: a Signal computed WHILE
// the writer held the seat keeps attended == true — a later detach does NOT
// retroactively mutate an already-built lifecycle frame. The signal honestly
// reflects the seat at the instant it was stamped; an in-flight hold opened off
// the earlier attended==true frame is never invalidated by this computation (the
// consumer runs it to its 30–60 s timeout). NEW computations after the detach
// report false (the downgrade for NEW asks).
func TestLifecycle_InFlightHoldComputedBeforeDetachSurvivesTransition(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1")

	if _, err := attach.AcquireWriter(ctx, repo, "sess-1", "human-writer", false); err != nil {
		t.Fatalf("AcquireWriter: %v", err)
	}

	// The frame the in-flight hold was admitted against, stamped while attended.
	inFlight := BuildLifecycleUpdate("sess-1", signalFromRecord(t, repo, "sess-1", fixedClock))
	if !inFlight.GetAttended() {
		t.Fatalf("in-flight frame attended = false, want true")
	}

	// Detach happens after the in-flight frame was built.
	if err := attach.ReleaseWriter(ctx, repo, "sess-1", "human-writer"); err != nil {
		t.Fatalf("ReleaseWriter: %v", err)
	}

	// The ALREADY-BUILT in-flight frame is unchanged — never retroactively killed.
	if !inFlight.GetAttended() {
		t.Fatalf("the already-built in-flight frame was retroactively flipped to unattended; D78 forbids a retroactive kill")
	}

	// A NEW computation after the detach is the downgrade path (new asks block).
	next := BuildLifecycleUpdate("sess-1", signalFromRecord(t, repo, "sess-1", fixedClock.Add(2*time.Second)))
	if next.GetAttended() {
		t.Fatalf("new post-detach frame attended = true, want false (new asks downgrade)")
	}
}

// TestLifecycle_SpectatorsDoNotCount proves the SAME real-arbitration end-to-end:
// many readers attach (canvas / console / spectators), the writer seat stays empty,
// and the session is NOT attended. A reader can never make a session count.
func TestLifecycle_SpectatorsDoNotCount(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1")

	// No writer ever acquires; only readers attach.
	for i := 0; i < 5; i++ {
		if _, err := attach.AcquireReader(ctx, repo, "sess-1"); err != nil {
			t.Fatalf("AcquireReader #%d: %v", i, err)
		}
	}

	sig := signalFromRecord(t, repo, "sess-1", fixedClock)
	if sig.Attended {
		t.Fatalf("attended = true with only readers attached; spectators/readers/canvas viewers must never count (§5.5)")
	}
	if BuildLifecycleUpdate("sess-1", sig).GetAttended() {
		t.Fatalf("lifecycle update attended = true with only readers; the frozen slot must reflect unattended")
	}
}

// TestLifecycle_ReadersDoNotDisplaceAttendedWriter proves the combined case: a
// human holds the writer seat AND spectators are watching — the readers do not
// pull attended down. Only the writer seat governs attendedness.
func TestLifecycle_ReadersDoNotDisplaceAttendedWriter(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1")

	if _, err := attach.AcquireWriter(ctx, repo, "sess-1", "human-writer", false); err != nil {
		t.Fatalf("AcquireWriter: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := attach.AcquireReader(ctx, repo, "sess-1"); err != nil {
			t.Fatalf("AcquireReader #%d: %v", i, err)
		}
	}

	sig := signalFromRecord(t, repo, "sess-1", fixedClock)
	if !sig.Attended {
		t.Fatalf("attended = false with a human writer present alongside spectators, want true")
	}
}

// TestStampAttendedness_PreservesSiblingLegContributions proves the additive
// transport path: stamping attendedness onto a frame another lifecycle leg already
// started (digest-ack, grants, suspend-coord) touches ONLY the attended /
// attended_at slots and never clears a sibling leg's contribution.
func TestStampAttendedness_PreservesSiblingLegContributions(t *testing.T) {
	// A frame a sibling leg already populated (digest-ack relay + grant refs).
	frame := BuildLifecycleUpdate("sess-1", Signal{})
	frame.AppliedDigestSetVersion = "digest-v7"
	frame.GrantRefs = []string{"grant-a", "grant-b"}

	StampAttendedness(frame, Signal{Attended: true, AttendedAt: uint64(fixedClock.Unix())})

	if !frame.GetAttended() || frame.GetAttendedAt() != uint64(fixedClock.Unix()) {
		t.Fatalf("StampAttendedness did not fold the signal onto the frame: %+v", frame)
	}
	if frame.GetAppliedDigestSetVersion() != "digest-v7" {
		t.Fatalf("StampAttendedness clobbered the digest-ack relay: %q", frame.GetAppliedDigestSetVersion())
	}
	if got := frame.GetGrantRefs(); len(got) != 2 || got[0] != "grant-a" || got[1] != "grant-b" {
		t.Fatalf("StampAttendedness clobbered the grant refs: %v", got)
	}
}

// TestStampAttendedness_NilFrameIsNoOp proves a nil frame is a safe no-op (no
// panic) — the additive stamp is defensive at the lifecycle assembler boundary.
func TestStampAttendedness_NilFrameIsNoOp(t *testing.T) {
	StampAttendedness(nil, Signal{Attended: true})
}
