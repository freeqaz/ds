// SPDX-License-Identifier: Apache-2.0

package parkstore

import (
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
)

// rung2Ask is a synthetic genuine rung-2 ask (the class that PARKS per D46),
// the only ask askhold.NewParked accepts. Synthetic only (D50): no live IO.
func rung2Ask() askhold.Ask {
	return askhold.Ask{
		ResourceKind:  "service",
		ResourceName:  "bulk-delete",
		MatchedRuleID: "rule-suspend",
		Rung2:         true,
	}
}

// TestMemory_SatisfiesParkRecorderSeam pins the seam contract structurally: a
// *Memory is both a parkstore.Store and the askhold.ParkRecorder askhold
// injects. If askhold's seam shape drifts, this stops compiling.
func TestMemory_SatisfiesParkRecorderSeam(t *testing.T) {
	var _ Store = NewMemory()
	var _ askhold.ParkRecorder = NewMemory()
}

// TestRecordParked_PersistsJoin: driving askhold.NewParked THROUGH this backing
// records the session<->question join, re-readable by Lookup. This is the
// in-memory backing exercising the askhold.ParkRecorder Record path.
func TestRecordParked_PersistsJoin(t *testing.T) {
	now := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	st := NewMemory()

	parked, err := askhold.NewParked(st, "sess-42", rung2Ask(), now)
	if err != nil {
		t.Fatalf("NewParked through parkstore: %v", err)
	}
	if parked.Phase != askhold.ParkPhaseParked {
		t.Fatalf("Phase = %v, want PARKED", parked.Phase)
	}

	got, ok, err := st.Lookup("sess-42")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatalf("the join must be durably recorded and re-readable by Lookup")
	}
	if got.SessionUUID != "sess-42" || got.Ask.ResourceName != "bulk-delete" {
		t.Fatalf("recorded join mismatch: %+v", got)
	}
	if got.Phase != askhold.ParkPhaseParked || !got.ParkedAt.Equal(now) {
		t.Fatalf("recorded park state not faithful: %+v", got)
	}

	list, err := st.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].SessionUUID != "sess-42" {
		t.Fatalf("List must enumerate the one outstanding park, got %+v", list)
	}
}

// TestRecordRestartResume_SurvivesAndResumesOnAnswer is the headline
// restart-survival assertion: a rung-2 ask is PARKED and recorded, then the
// control plane "restarts" (we drop every in-memory handle except the durable
// backing), RE-READS the join from that same backing, and RESUMES on a human
// answer — never timing out into allow or kill. After the resume the join is
// cleared, so a second restart re-read no longer sees it.
func TestRecordRestartResume_SurvivesAndResumesOnAnswer(t *testing.T) {
	parkedAt := time.Date(2026, 6, 16, 9, 0, 0, 0, time.UTC)

	// --- control-plane epoch #1: park the ask through the durable backing. ---
	backing := NewMemory()
	if _, err := askhold.NewParked(backing, "sess-7", rung2Ask(), parkedAt); err != nil {
		t.Fatalf("epoch#1 NewParked: %v", err)
	}

	// --- CONTROL-PLANE RESTART: every transient handle is gone; only `backing`
	// (the durable store, stand-in for a row that outlives the process)
	// survives. The resume path re-reads the join from that SAME backing. ---
	reread, ok, err := backing.Lookup("sess-7")
	if err != nil {
		t.Fatalf("post-restart Lookup: %v", err)
	}
	if !ok {
		t.Fatalf("a parked ask MUST survive a restart — the join was not re-readable")
	}
	if reread.Phase != askhold.ParkPhaseParked {
		t.Fatalf("re-read ask must still be PARKED (never timed out into allow/kill); phase=%v", reread.Phase)
	}
	if reread.Verdict != askhold.ResumeVerdictUnspecified {
		t.Fatalf("a survived park must carry NO verdict (no timeout-allow/kill); verdict=%v", reread.Verdict)
	}

	// --- The human answer finally arrives (out-of-band on the policy stream).
	// We resume the RE-READ park through the SAME backing — proving the resume
	// is driven by the recovered join, not a transient one held across the
	// "restart". A long pause before the answer changes nothing. ---
	answeredAt := parkedAt.Add(3 * time.Hour)
	resumed, err := reread.Resume(backing, askhold.ResumeVerdictAllow, "allow-once:service/bulk-delete;ttl=session", askhold.DenyReason{}, answeredAt)
	if err != nil {
		t.Fatalf("resume of the re-read park: %v", err)
	}
	if resumed.Phase != askhold.ParkPhaseResumed || resumed.Verdict != askhold.ResumeVerdictAllow {
		t.Fatalf("resume must carry the human ALLOW answer; phase=%v verdict=%v", resumed.Phase, resumed.Verdict)
	}

	// --- after the resume the join is cleared: a SECOND restart re-read finds
	// nothing (the ask resolved on an answer, not a timeout). ---
	if _, ok, err := backing.Lookup("sess-7"); err != nil {
		t.Fatalf("post-resume Lookup: %v", err)
	} else if ok {
		t.Fatalf("a resumed park must be cleared from the durable join")
	}
	if list, err := backing.List(); err != nil {
		t.Fatalf("post-resume List: %v", err)
	} else if len(list) != 0 {
		t.Fatalf("no outstanding parks should remain after resume, got %+v", list)
	}
}

// TestList_OutstandingOnly_DeterministicOrder: List enumerates ONLY still-parked
// joins (a cleared one drops out) in a stable session-UUID order, the bulk
// restart-survival re-adoption read.
func TestList_OutstandingOnly_DeterministicOrder(t *testing.T) {
	now := time.Date(2026, 6, 16, 8, 0, 0, 0, time.UTC)
	st := NewMemory()

	for _, sid := range []string{"sess-c", "sess-a", "sess-b"} {
		if _, err := askhold.NewParked(st, sid, rung2Ask(), now); err != nil {
			t.Fatalf("park %s: %v", sid, err)
		}
	}
	// Resume one — it must drop out of the outstanding set.
	mid, ok, err := st.Lookup("sess-b")
	if err != nil || !ok {
		t.Fatalf("setup lookup sess-b: ok=%v err=%v", ok, err)
	}
	if _, err := mid.Resume(st, askhold.ResumeVerdictDeny, "", askhold.DenyReason{Code: askhold.DenyUnattended}, now.Add(time.Minute)); err != nil {
		t.Fatalf("resume sess-b: %v", err)
	}

	list, err := st.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List must contain only the 2 outstanding parks, got %d: %+v", len(list), list)
	}
	if list[0].SessionUUID != "sess-a" || list[1].SessionUUID != "sess-c" {
		t.Fatalf("List must be session-UUID ordered, got [%s %s]", list[0].SessionUUID, list[1].SessionUUID)
	}
}

// TestRecordFault_NeverUnparks: a RecordParked fault (empty session UUID, the
// reference impl's write-shape fault) surfaces for retry WITHOUT un-parking —
// askhold has already entered the safe PARKED state and the returned Parked
// stays parked. ADDITIVE: the store performs no compensating un-park.
func TestRecordFault_NeverUnparks(t *testing.T) {
	now := time.Date(2026, 6, 16, 7, 0, 0, 0, time.UTC)
	st := NewMemory()

	// askhold.NewParked surfaces the recorder's error but keeps the ask PARKED.
	parked, err := askhold.NewParked(st, "", rung2Ask(), now)
	if !errors.Is(err, errEmptySession) {
		t.Fatalf("a record fault must surface for retry, got %v", err)
	}
	if parked.Phase != askhold.ParkPhaseParked {
		t.Fatalf("a record fault must NOT un-park (askhold's safe state); phase=%v", parked.Phase)
	}
	// Nothing was recorded — the faulted write did not land, so a retry is clean.
	if list, err := st.List(); err != nil {
		t.Fatalf("List: %v", err)
	} else if len(list) != 0 {
		t.Fatalf("a faulted record must persist nothing, got %+v", list)
	}
}

// TestClearFault_NeverReparks: a ClearParked fault surfaces for retry WITHOUT
// re-parking — askhold has already entered the RESUMED state. We drive Resume
// through a wrapper whose ClearParked rejects, and assert the resume stands.
func TestClearFault_NeverReparks(t *testing.T) {
	now := time.Date(2026, 6, 16, 6, 0, 0, 0, time.UTC)
	clearErr := errors.New("backing clear fault")
	st := &faultyClear{Memory: NewMemory(), clrErr: clearErr}

	parked, err := askhold.NewParked(st, "sess-9", rung2Ask(), now)
	if err != nil {
		t.Fatalf("NewParked: %v", err)
	}
	resumed, err := parked.Resume(st, askhold.ResumeVerdictAllow, "scope", askhold.DenyReason{}, now.Add(time.Second))
	if !errors.Is(err, clearErr) {
		t.Fatalf("a clear fault must surface for retry, got %v", err)
	}
	if resumed.Phase != askhold.ParkPhaseResumed {
		t.Fatalf("a clear fault must NOT re-park (askhold's safe state); phase=%v", resumed.Phase)
	}
}

// faultyClear wraps Memory to inject a ClearParked fault, exercising the
// "clear fault surfaces but never re-parks" path through the real seam.
type faultyClear struct {
	*Memory
	clrErr error
}

func (f *faultyClear) ClearParked(p askhold.Parked) error {
	if err := f.Memory.ClearParked(p); err != nil {
		return err
	}
	return f.clrErr
}

// TestClearParked_Idempotent: clearing an absent (already-cleared / never-parked)
// join is a no-op success, so a re-driven clear after a partial write is
// retry-safe.
func TestClearParked_Idempotent(t *testing.T) {
	st := NewMemory()
	if err := st.ClearParked(askhold.Parked{SessionUUID: "ghost"}); err != nil {
		t.Fatalf("clearing an absent join must be a no-op success, got %v", err)
	}
}

// TestLookup_AbsentAndEmpty: a never-recorded session is absent (no error); an
// empty session UUID is a write-shape fault.
func TestLookup_AbsentAndEmpty(t *testing.T) {
	st := NewMemory()
	if _, ok, err := st.Lookup("nope"); err != nil || ok {
		t.Fatalf("absent lookup: want (_, false, nil), got ok=%v err=%v", ok, err)
	}
	if _, _, err := st.Lookup(""); !errors.Is(err, errEmptySession) {
		t.Fatalf("empty-UUID lookup must fault, got %v", err)
	}
}

// TestList_CopyIsolation: the slice List returns is a fresh copy — mutating it
// never corrupts the backing's outstanding set.
func TestList_CopyIsolation(t *testing.T) {
	now := time.Date(2026, 6, 16, 5, 0, 0, 0, time.UTC)
	st := NewMemory()
	if _, err := askhold.NewParked(st, "sess-1", rung2Ask(), now); err != nil {
		t.Fatalf("park: %v", err)
	}
	list, err := st.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	list[0].SessionUUID = "tampered"
	again, err := st.List()
	if err != nil {
		t.Fatalf("List again: %v", err)
	}
	if again[0].SessionUUID != "sess-1" {
		t.Fatalf("mutating the returned slice must not corrupt the backing, got %q", again[0].SessionUUID)
	}
}
