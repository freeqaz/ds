// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestFileSessionModeStore_PutModeFor asserts the file store round-trips a persisted
// resolved mode — the single-source read-back the U-HOST-SERVE serving leg + minter
// consume agrees with what the producer wrote.
func TestFileSessionModeStore_PutModeFor(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileSessionModeStore(dir)
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	ctx := context.Background()

	for _, mode := range []SessionMode{SessionModeStructured, SessionModeTerminal} {
		uuid := "sess-" + mode.String()
		if err := s.PutMode(ctx, uuid, mode); err != nil {
			t.Fatalf("PutMode(%v): %v", mode, err)
		}
		got, found, err := s.ModeFor(ctx, uuid)
		if err != nil {
			t.Fatalf("ModeFor(%s): %v", uuid, err)
		}
		if !found {
			t.Fatalf("ModeFor(%s): found=false, want true after PutMode", uuid)
		}
		if got != mode {
			t.Errorf("ModeFor(%s) = %v, want %v", uuid, got, mode)
		}
	}
}

// TestFileSessionModeStore_AbsentIsStructuredDefault asserts an absent marker reads as
// the structured default with found=false (a pre-existing / never-persisted session
// attaches structured) — NOT an error.
func TestFileSessionModeStore_AbsentIsStructuredDefault(t *testing.T) {
	s, err := NewFileSessionModeStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	got, found, err := s.ModeFor(context.Background(), "never-written")
	if err != nil {
		t.Fatalf("ModeFor(absent): unexpected err %v", err)
	}
	if found {
		t.Error("ModeFor(absent): found=true, want false")
	}
	if got != SessionModeStructured {
		t.Errorf("ModeFor(absent) = %v, want structured default", got)
	}
}

// TestFileSessionModeStore_CorruptMarkerFailsLoud asserts a present-but-garbage marker
// is fail-loud (an error) — a corrupt marker must not silently downgrade a terminal
// session to structured and mis-route its handle.
func TestFileSessionModeStore_CorruptMarkerFailsLoud(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileSessionModeStore(dir)
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	// Write a garbage marker directly into the store dir (sanitized path == the uuid).
	bad := filepath.Join(dir, sessionModeSubdir, "sess-garbage")
	if err := os.WriteFile(bad, []byte("not-a-mode"), 0o600); err != nil {
		t.Fatalf("seed garbage marker: %v", err)
	}
	if _, _, err := s.ModeFor(context.Background(), "sess-garbage"); err == nil {
		t.Fatal("ModeFor(corrupt) must fail loud, got nil err")
	}
}

// TestFileSessionModeStore_Idempotent asserts a re-PutMode (a retried create)
// overwrites cleanly with the same value.
func TestFileSessionModeStore_Idempotent(t *testing.T) {
	s, err := NewFileSessionModeStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.PutMode(ctx, "sess-retry", SessionModeTerminal); err != nil {
			t.Fatalf("PutMode retry %d: %v", i, err)
		}
	}
	got, found, err := s.ModeFor(ctx, "sess-retry")
	if err != nil || !found || got != SessionModeTerminal {
		t.Fatalf("ModeFor after retries = (%v, %v, %v), want (terminal, true, nil)", got, found, err)
	}
}

// TestNewSessionModeStore_OfflineNil asserts the gate-aware constructor returns a nil
// store off DS_HOSTAGENT_LIVE (the offline default — the producer persists nothing).
func TestNewSessionModeStore_OfflineNil(t *testing.T) {
	if LiveEnabled() {
		t.Skip("DS_HOSTAGENT_LIVE is set; this asserts the offline path")
	}
	s, err := NewSessionModeStore(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSessionModeStore (offline): %v", err)
	}
	if s != nil {
		t.Errorf("NewSessionModeStore (offline) = %v, want nil", s)
	}
}

// ── §4.2 teardown purge (SessionModeStore.RemoveMode) ────────────────────────

// TestFileSessionModeStore_RemoveModePurgesTheMarker asserts the §4.2 teardown drops the
// torn-down session's marker (doc 15 §4.2) — the SessionRecordStore.Remove contract
// mirrored onto the same class of host-internal per-session state. Before this every
// destroyed session left a marker under <OverlayDir>/.ds-session-mode forever. A sibling
// session's marker is untouched (the purge is session-scoped).
func TestFileSessionModeStore_RemoveModePurgesTheMarker(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileSessionModeStore(dir)
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	ctx := context.Background()
	if err := s.PutMode(ctx, "sess-gone", SessionModeTerminal); err != nil {
		t.Fatalf("PutMode: %v", err)
	}
	if err := s.PutMode(ctx, "sess-live", SessionModeTerminal); err != nil {
		t.Fatalf("PutMode (sibling): %v", err)
	}

	if err := s.RemoveMode(ctx, "sess-gone"); err != nil {
		t.Fatalf("RemoveMode: %v", err)
	}
	if _, err := os.Stat(s.modePath("sess-gone")); !os.IsNotExist(err) {
		t.Fatalf("the destroyed session's marker must be gone, stat err = %v", err)
	}
	// The read-back degrades to the historical absent-marker default, NOT an error.
	got, found, err := s.ModeFor(ctx, "sess-gone")
	if err != nil || found || got != SessionModeStructured {
		t.Fatalf("ModeFor after purge = (%v, %v, %v), want (structured, false, nil)", got, found, err)
	}
	if _, found, err := s.ModeFor(ctx, "sess-live"); err != nil || !found {
		t.Fatalf("a sibling session's marker must survive the purge (found=%v err=%v)", found, err)
	}
}

// TestFileSessionModeStore_RemoveModeAbsentIsCleanNoOp: an ABSENT marker is a clean
// success — a session whose producer never resolved a mode, and a §4.2 re-drive over an
// already-purged session, both converge (the sessionrecord.go Remove idempotency).
func TestFileSessionModeStore_RemoveModeAbsentIsCleanNoOp(t *testing.T) {
	s, err := NewFileSessionModeStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	ctx := context.Background()
	if err := s.RemoveMode(ctx, "never-written"); err != nil {
		t.Fatalf("RemoveMode(absent) = %v, want a clean no-op success", err)
	}
	if err := s.PutMode(ctx, "sess-r", SessionModeStructured); err != nil {
		t.Fatalf("PutMode: %v", err)
	}
	if err := s.RemoveMode(ctx, "sess-r"); err != nil {
		t.Fatalf("RemoveMode: %v", err)
	}
	if err := s.RemoveMode(ctx, "sess-r"); err != nil {
		t.Fatalf("RemoveMode (re-drive) = %v, want a clean no-op success", err)
	}
}

// TestFileSessionModeStore_RemoveModeFaultPropagates: a genuine store fault surfaces (the
// service then LOGS it — the marker purge is best-effort AT THE SERVICE, never at the
// store, which must always report the truth). Staged as a NON-EMPTY DIRECTORY at the
// marker path so os.Remove fails with ENOTEMPTY rather than ENOENT.
func TestFileSessionModeStore_RemoveModeFaultPropagates(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileSessionModeStore(dir)
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(s.modePath("sess-wedged"), "occupied"), 0o700); err != nil {
		t.Fatalf("stage the un-removable marker path: %v", err)
	}
	if err := s.RemoveMode(context.Background(), "sess-wedged"); err == nil {
		t.Fatal("a genuine remove fault must propagate, never a swallowed clean success")
	}
}

// TestFileSessionModeStore_RemoveModeEmptySessionIsRejected: trustpath.Sanitize maps ""
// onto the literal "session" leaf, so a blind purge would delete an unrelated marker.
func TestFileSessionModeStore_RemoveModeEmptySessionIsRejected(t *testing.T) {
	s, err := NewFileSessionModeStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileSessionModeStore: %v", err)
	}
	victim := s.modePath("")
	if err := os.WriteFile(victim, []byte(SessionModeTerminal.String()), 0o600); err != nil {
		t.Fatalf("seed the sanitize-collision leaf: %v", err)
	}
	if err := s.RemoveMode(context.Background(), ""); err == nil {
		t.Fatal("an empty session uuid must be a caller error")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("an empty session uuid must touch nothing, stat = %v", err)
	}
}
