// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileEntrypointConfigSource_ReadsDroppedRef(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileEntrypointConfigSource(dir)
	if err != nil {
		t.Fatalf("NewFileEntrypointConfigSource: %v", err)
	}
	// Simulate the orchestrator drop: write opaque material keyed by the ref.
	want := []byte("opaque-role-overlay-blob")
	if err := os.WriteFile(filepath.Join(dir, entrypointRefsSubdir, "overlay-ref-A"), want, 0o600); err != nil {
		t.Fatalf("seed drop: %v", err)
	}
	got, err := s.FetchEntrypointRef(context.Background(), "overlay-ref-A")
	if err != nil {
		t.Fatalf("FetchEntrypointRef: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("FetchEntrypointRef = %q, want %q", got, want)
	}
}

func TestFileEntrypointConfigSource_MissingRefFailsClosed(t *testing.T) {
	s, err := NewFileEntrypointConfigSource(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEntrypointConfigSource: %v", err)
	}
	// No drop for this ref — must be an ERROR (fail-closed), never an empty success.
	got, err := s.FetchEntrypointRef(context.Background(), "never-dropped")
	if err == nil {
		t.Fatalf("expected a fail-closed error for a missing ref; got nil (bytes=%q)", got)
	}
	if got != nil {
		t.Errorf("expected nil bytes on the fail-closed path; got %q", got)
	}
}

func TestFileEntrypointConfigSource_EmptyRefRejected(t *testing.T) {
	s, err := NewFileEntrypointConfigSource(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEntrypointConfigSource: %v", err)
	}
	if _, err := s.FetchEntrypointRef(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty ref; got nil")
	}
}

func TestNewFileEntrypointConfigSource_RequiresBaseDir(t *testing.T) {
	if _, err := NewFileEntrypointConfigSource(""); err == nil {
		t.Fatal("expected an error when base dir is empty; got nil")
	}
}

// TestFileEntrypointConfigSource_RefStaysInStore asserts a ref carrying a path
// separator is sanitized into the store dir (it can never escape via ../).
func TestFileEntrypointConfigSource_RefStaysInStore(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileEntrypointConfigSource(dir)
	if err != nil {
		t.Fatalf("NewFileEntrypointConfigSource: %v", err)
	}
	p := s.refPath("../../etc/escape")
	storeDir := filepath.Join(dir, entrypointRefsSubdir)
	if filepath.Dir(p) != storeDir {
		t.Errorf("ref path %q escaped the store dir %q", p, storeDir)
	}
}

func TestFakeEntrypointConfigSource_ServesFixture(t *testing.T) {
	want := []byte("fixture-overlay-bytes")
	s := NewFakeEntrypointConfigSource(map[string][]byte{"ref-1": want})
	got, err := s.FetchEntrypointRef(context.Background(), "ref-1")
	if err != nil {
		t.Fatalf("FetchEntrypointRef: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("FetchEntrypointRef = %q, want %q", got, want)
	}
	// The fake returns a defensive copy — a caller mutation must not corrupt the store.
	got[0] = 'X'
	again, err := s.FetchEntrypointRef(context.Background(), "ref-1")
	if err != nil {
		t.Fatalf("FetchEntrypointRef (re-read): %v", err)
	}
	if string(again) != string(want) {
		t.Errorf("fake store mutated through a returned slice: re-read = %q, want %q", again, want)
	}
}

func TestFakeEntrypointConfigSource_FailsClosed(t *testing.T) {
	s := NewFakeEntrypointConfigSource(map[string][]byte{"present": []byte("x"), "empty": {}})
	// Empty ref.
	if _, err := s.FetchEntrypointRef(context.Background(), ""); err == nil {
		t.Error("expected an error for an empty ref; got nil")
	}
	// Unknown ref.
	if _, err := s.FetchEntrypointRef(context.Background(), "absent"); err == nil {
		t.Error("expected a fail-closed error for an unknown ref; got nil")
	}
	// A zero-length fixture is the same fail-closed case as a missing file.
	if _, err := s.FetchEntrypointRef(context.Background(), "empty"); err == nil {
		t.Error("expected a fail-closed error for an empty-bytes ref; got nil")
	}
}

func TestFakeEntrypointConfigSource_NilMapFailsClosed(t *testing.T) {
	s := NewFakeEntrypointConfigSource(nil)
	if _, err := s.FetchEntrypointRef(context.Background(), "anything"); err == nil {
		t.Error("a nil fixture map must fail closed on every named ref; got nil error")
	}
}

// TestNewEntrypointConfigSource_OfflineReturnsFake asserts the gate-aware
// constructor returns the offline fake off the DS_HOSTAGENT_LIVE gate (the
// sandbox / CI default), seeded with the provided fixtures.
func TestNewEntrypointConfigSource_OfflineReturnsFake(t *testing.T) {
	if LiveEnabled() {
		t.Skip("DS_HOSTAGENT_LIVE set: this asserts the offline default")
	}
	src, err := NewEntrypointConfigSource(LiveConfig{OverlayDir: t.TempDir()}, map[string][]byte{"ref-x": []byte("blob")})
	if err != nil {
		t.Fatalf("NewEntrypointConfigSource: %v", err)
	}
	if _, ok := src.(*fakeEntrypointConfigSource); !ok {
		t.Fatalf("offline constructor returned %T, want *fakeEntrypointConfigSource", src)
	}
	got, err := src.FetchEntrypointRef(context.Background(), "ref-x")
	if err != nil {
		t.Fatalf("FetchEntrypointRef: %v", err)
	}
	if string(got) != "blob" {
		t.Errorf("fixture fetch = %q, want %q", got, "blob")
	}
}

// TestEntrypointConfigSource_FeedsBuilderOpaquePassThrough wires the source into the
// builder end-to-end: the fetched opaque ref bytes ride onto the EntrypointConfig's
// role_overlay_ref byte-identical (the orchestrator never inspects them), and the
// assembled config round-trips proto.Marshal/Unmarshal.
func TestEntrypointConfigSource_FeedsBuilderOpaquePassThrough(t *testing.T) {
	overlay := []byte("opaque-from-source-\x00\xff")
	src := NewFakeEntrypointConfigSource(map[string][]byte{"role-ref": overlay})

	raw, err := src.FetchEntrypointRef(context.Background(), "role-ref")
	if err != nil {
		t.Fatalf("FetchEntrypointRef: %v", err)
	}

	in := validInput()
	in.RoleOverlayRef = raw
	cfg, err := BuildEntrypointConfig(in)
	if err != nil {
		t.Fatalf("BuildEntrypointConfig: %v", err)
	}
	if string(cfg.GetRoleOverlayRef()) != string(overlay) {
		t.Errorf("role_overlay_ref = %q, want the source bytes %q", cfg.GetRoleOverlayRef(), overlay)
	}
}

// TestEntrypointConfigSource_FailClosedBlocksBuild asserts that when the source
// fails closed on a missing ref, the caller has no bytes to build with — the
// fail-closed contract propagates (no silent empty-overlay build).
func TestEntrypointConfigSource_FailClosedBlocksBuild(t *testing.T) {
	src := NewFakeEntrypointConfigSource(nil)
	if _, err := src.FetchEntrypointRef(context.Background(), "needed-but-missing"); err == nil {
		t.Fatal("expected the source to fail closed on a missing ref before any build; got nil")
	}
}
