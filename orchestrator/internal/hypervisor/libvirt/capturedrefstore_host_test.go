// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// fakeInnerRecoverer is a synthetic SessionRecoverer (D50, no libvirt): it returns a
// fixed RecoveredSession set with EMPTY SnapshotRefs — exactly what the live inner
// recoverer produces (the domain XML / SessionRecord never carried the captured
// refs). The captured-ref decorator is what must populate SnapshotRefs from the
// durable store.
type fakeInnerRecoverer struct {
	sessions []RecoveredSession
	err      error
}

func (f fakeInnerRecoverer) RecoverSessions(_ context.Context, _ string) ([]RecoveredSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	// Return copies so the decorator's in-place SnapshotRefs write cannot mutate the
	// fixture (the live recoverer likewise returns freshly-built values).
	out := make([]RecoveredSession, len(f.sessions))
	copy(out, f.sessions)
	return out, nil
}

// TestFileCapturedRefStoreRoundTrip pins the store's durable set semantics: record is
// a set-insert, CapturedRefs reads the set back, the empty case is (nil,nil), and
// RemoveCapturedRefs purges it.
func TestFileCapturedRefStoreRoundTrip(t *testing.T) {
	base := t.TempDir()
	store, err := NewFileCapturedRefStore(base)
	if err != nil {
		t.Fatalf("NewFileCapturedRefStore: %v", err)
	}
	ctx := context.Background()

	// Fresh session: empty set, fail-closed (nil, nil).
	got, err := store.CapturedRefs(ctx, "sess-a")
	if err != nil {
		t.Fatalf("CapturedRefs(fresh): %v", err)
	}
	if got != nil {
		t.Errorf("CapturedRefs(fresh) = %v, want nil (empty set)", got)
	}

	// Record two refs; re-record one (set-insert idempotency).
	for _, ref := range []string{"snap-1", "snap-2", "snap-1"} {
		if err := store.RecordCapturedRef(ctx, "sess-a", ref); err != nil {
			t.Fatalf("RecordCapturedRef(%q): %v", ref, err)
		}
	}
	got, err = store.CapturedRefs(ctx, "sess-a")
	if err != nil {
		t.Fatalf("CapturedRefs(after record): %v", err)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "snap-1" || got[1] != "snap-2" {
		t.Errorf("CapturedRefs = %v, want [snap-1 snap-2]", got)
	}

	// A different session is isolated.
	other, err := store.CapturedRefs(ctx, "sess-b")
	if err != nil {
		t.Fatalf("CapturedRefs(sess-b): %v", err)
	}
	if other != nil {
		t.Errorf("CapturedRefs(sess-b) = %v, want nil", other)
	}

	// Empty session/ref are programming errors, rejected.
	if err := store.RecordCapturedRef(ctx, "", "snap-x"); err == nil {
		t.Error("RecordCapturedRef with empty session uuid must fail")
	}
	if err := store.RecordCapturedRef(ctx, "sess-a", ""); err == nil {
		t.Error("RecordCapturedRef with empty snapshot ref must fail")
	}

	// The set file lives beside a SessionRecord in .ds-sessions with a distinct leaf.
	wantPath := filepath.Join(trustpath.SessionRecordsSubdirPath(base), trustpath.Sanitize("sess-a")+capturedRefsFileExt)
	if _, statErr := os.Stat(wantPath); statErr != nil {
		t.Errorf("captured-ref set file not at %q: %v", wantPath, statErr)
	}
	// It must NOT collide with the record store's <sanitize>.json leaf.
	recPath := filepath.Join(trustpath.SessionRecordsSubdirPath(base), trustpath.SessionRecordFilename("sess-a"))
	if wantPath == recPath {
		t.Errorf("captured-ref leaf %q collides with SessionRecord leaf %q", wantPath, recPath)
	}

	// Remove purges; a second remove is an idempotent no-op.
	if err := store.RemoveCapturedRefs(ctx, "sess-a"); err != nil {
		t.Fatalf("RemoveCapturedRefs: %v", err)
	}
	if err := store.RemoveCapturedRefs(ctx, "sess-a"); err != nil {
		t.Fatalf("RemoveCapturedRefs (second): %v", err)
	}
	got, err = store.CapturedRefs(ctx, "sess-a")
	if err != nil {
		t.Fatalf("CapturedRefs(after remove): %v", err)
	}
	if got != nil {
		t.Errorf("CapturedRefs(after remove) = %v, want nil", got)
	}
}

// TestCapturedRefRecovererPopulatesSnapshotRefs is the offline/synthetic proof (D50,
// no live libvirt) of the producer arc's read side: a live-daemon-shaped recoverer
// built from the file-backed store over NewSessionRecovererWithCapturedRefs populates
// RecoveredSession.SnapshotRefs from what the store durably holds — the exact defect
// the seam closes (bare NewLiveSessionRecoverer leaves SnapshotRefs empty).
func TestCapturedRefRecovererPopulatesSnapshotRefs(t *testing.T) {
	base := t.TempDir()
	store, err := NewFileCapturedRefStore(base)
	if err != nil {
		t.Fatalf("NewFileCapturedRefStore: %v", err)
	}
	ctx := context.Background()

	// The producer (Snapshot's durable-write) recorded two refs for one session and
	// none for another — the shape a restart re-observes.
	if err := store.RecordCapturedRef(ctx, "sess-with-refs", "snap-a"); err != nil {
		t.Fatalf("RecordCapturedRef: %v", err)
	}
	if err := store.RecordCapturedRef(ctx, "sess-with-refs", "snap-b"); err != nil {
		t.Fatalf("RecordCapturedRef: %v", err)
	}

	// The inner recoverer re-observes both resident sessions with EMPTY SnapshotRefs.
	inner := fakeInnerRecoverer{sessions: []RecoveredSession{
		{SessionUUID: "sess-with-refs", DomainUUID: "dom-1"},
		{SessionUUID: "sess-no-refs", DomainUUID: "dom-2"},
	}}

	rec, err := NewSessionRecovererWithCapturedRefs(inner, store)
	if err != nil {
		t.Fatalf("NewSessionRecovererWithCapturedRefs: %v", err)
	}

	recovered, err := rec.RecoverSessions(ctx, "host-1")
	if err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}
	if len(recovered) != 2 {
		t.Fatalf("recovered %d sessions, want 2", len(recovered))
	}

	byUUID := map[string][]string{}
	for _, rs := range recovered {
		refs := append([]string(nil), rs.SnapshotRefs...)
		sort.Strings(refs)
		byUUID[rs.SessionUUID] = refs
	}
	if got := byUUID["sess-with-refs"]; len(got) != 2 || got[0] != "snap-a" || got[1] != "snap-b" {
		t.Errorf("sess-with-refs SnapshotRefs = %v, want [snap-a snap-b] populated from the durable store", got)
	}
	if got := byUUID["sess-no-refs"]; len(got) != 0 {
		t.Errorf("sess-no-refs SnapshotRefs = %v, want empty (no durable refs)", got)
	}
}

// TestNewCapturedRefStoreDefaultOff pins the default-off posture: with DS_HOSTAGENT_LIVE
// unset, NewCapturedRefStore returns (nil, nil) so the DriverService's durable-write is
// skipped and construction is byte-identical to the in-memory-only posture.
func TestNewCapturedRefStoreDefaultOff(t *testing.T) {
	if LiveEnabled() {
		t.Skip("DS_HOSTAGENT_LIVE set in env; default-off posture not exercised")
	}
	store, err := NewCapturedRefStore(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewCapturedRefStore (default off): %v", err)
	}
	if store != nil {
		t.Errorf("NewCapturedRefStore off the gate = %T, want nil (byte-identical default)", store)
	}
}
