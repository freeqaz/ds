// SPDX-License-Identifier: Apache-2.0
package controlplane

import "testing"

// TestSessionToProto_HasWriter proves the Session.has_writer wire projection
// (the U-WRITERCOL additive rider): sessionToProto reports the SAME writer-seat
// verdict the idle reaper and the W2 steal gate read (attendedness.Compute over
// the authoritative record seat), and it is a pure function of the record (no
// clock) in the writer-attached-only interim.
func TestSessionToProto_HasWriter(t *testing.T) {
	writerless := runningWriterlessSession("sess-writerless", "host-a")
	attended := withWriter(runningWriterlessSession("sess-attended", "host-a"), "driver@org")

	if got := sessionToProto(writerless); got.GetHasWriter() {
		t.Errorf("writer-less session: has_writer = true, want false")
	}
	if got := sessionToProto(attended); !got.GetHasWriter() {
		t.Errorf("writer-held session: has_writer = false, want true")
	}

	// Purity: the projection is deterministic — the same record projects the same
	// verdict every call (no time.Now() folded in), so the wire face is stable.
	if a, b := sessionToProto(attended).GetHasWriter(), sessionToProto(attended).GetHasWriter(); a != b {
		t.Errorf("has_writer projection not deterministic: %v then %v", a, b)
	}

	// The verdict agrees with the reaper's hasWriter (the single-source guarantee:
	// a session the reaper would treat as writer-less projects has_writer=false, so
	// the WRITER column and the reaper can never disagree about who's a candidate).
	if sessionHasWriter(writerless) != sessionToProto(writerless).GetHasWriter() {
		t.Errorf("sessionToProto.has_writer disagrees with sessionHasWriter for the writer-less record")
	}
}
