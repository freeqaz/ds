// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── PURE arg-construction (always runs; touches no substrate) ────────────────

func TestSnapshotCreateArgs(t *testing.T) {
	snapFile := "/ovl/sess-1.ds-snap-sess-1-tag"
	name, args := snapshotCreateArgs("virsh", "sess-1", "ds-snap-sess-1-tag", snapFile)
	want := "snapshot-create-as ds-sess-1 --name ds-snap-sess-1-tag --disk-only --atomic --no-metadata --diskspec vda,snapshot=external,file=" + snapFile
	if name != "virsh" || strings.Join(args, " ") != want {
		t.Fatalf("snapshot-create-as args = %q %q, want virsh %s", name, args, want)
	}
}

// TestSnapshotFilePathDeterministic: the snapshot file path is a pure function of
// (overlayDir, session, snapName) — the same inputs re-derive the SAME path (the
// idempotency probe + the explicit --diskspec file= agree on exactly one path).
func TestSnapshotFilePathDeterministic(t *testing.T) {
	a := snapshotFilePath("/ovl", "sess-1", "ds-snap-sess-1-v1")
	b := snapshotFilePath("/ovl", "sess-1", "ds-snap-sess-1-v1")
	if a != b || a != "/ovl/sess-1.ds-snap-sess-1-v1" {
		t.Fatalf("snapshot file path = %q (b=%q), want /ovl/sess-1.ds-snap-sess-1-v1 deterministic", a, b)
	}
}

// TestSnapshotNameDeterministicOnSessionAndLabel: the snapshot name is derived
// purely from (session, label) — the same inputs re-derive the SAME name (the
// idempotency key), a different label derives a DISTINCT name (a distinct
// point-in-time), and an empty label maps to a stable unlabeled sentinel.
func TestSnapshotNameDeterministicOnSessionAndLabel(t *testing.T) {
	if a, b := snapshotName("sess-1", "v1"), snapshotName("sess-1", "v1"); a != b {
		t.Fatalf("same (session,label) gave different names: %q vs %q", a, b)
	}
	if a, b := snapshotName("sess-1", "v1"), snapshotName("sess-1", "v2"); a == b {
		t.Fatalf("different labels collided on the same name: %q", a)
	}
	if a, b := snapshotName("sess-1", ""), snapshotName("sess-1", ""); a != b {
		t.Fatalf("empty label not deterministic: %q vs %q", a, b)
	}
	if got := snapshotName("sess-1", ""); !strings.Contains(got, "unlabeled") {
		t.Fatalf("empty-label name = %q, want a stable unlabeled sentinel", got)
	}
	if got := snapshotName("sess-1", "a b/--x"); strings.ContainsAny(got, " /") {
		t.Fatalf("unsafe label not sanitized into snapshot name: %q", got)
	}
}

// ── liveSnapshotStore behavior via the fake runner + a real overlay temp dir ──
//
// These drive the REAL liveSnapshotStore code path over the package
// recordingRunner (live_test.go) — NO subprocess, no virsh, no qcow2, no KVM. The
// idempotency probe is an os.Stat of the deterministic snapshot file, so the
// store runs against a REAL temp overlay dir; a test pre-creates the snapshot file
// to exercise the already-present branch. The actual snapshot-create-as leg is the
// DEFERRED operator step on the DS_HOSTAGENT_LIVE box.

// newTestSnapshotStore builds a store over a recordingRunner with a REAL temp
// overlay dir (the os.Stat probe needs a real path); returns the dir so a test
// can pre-create a snapshot file to drive the present branch.
func newTestSnapshotStore(t *testing.T, rr *recordingRunner) (*liveSnapshotStore, string) {
	t.Helper()
	dir := t.TempDir()
	return &liveSnapshotStore{virshBin: "virsh", overlayDir: dir, run: rr}, dir
}

// assertOpaqueRef fails if the snapshot_ref leaks any libvirt/qcow2 internal
// (D29/D30 zero-leakage): no qcow2 path, no host path, no snapshot-XML.
func assertOpaqueRef(t *testing.T, ref string) {
	t.Helper()
	if ref == "" {
		t.Fatal("snapshot_ref is empty")
	}
	if !strings.HasPrefix(ref, "ds-snap://") {
		t.Fatalf("snapshot_ref %q is not the opaque ds-snap:// handle", ref)
	}
	for _, leak := range []string{".qcow2", "/var/", "<domainsnapshot", "<disk", "snapshot-create-as"} {
		if strings.Contains(ref, leak) {
			t.Fatalf("snapshot_ref %q leaks a driver internal (%q) — D29/D30 zero-leakage violation", ref, leak)
		}
	}
}

// TestCreateSnapshotFreshSessionLabel: an ABSENT snapshot file (fresh temp dir) →
// snapshot-create-as is driven (1 exec, with the explicit --diskspec file=) → an
// OPAQUE ref is returned.
func TestCreateSnapshotFreshSessionLabel(t *testing.T) {
	rr := &recordingRunner{outputs: []string{""}}
	s, dir := newTestSnapshotStore(t, rr)

	ref, err := s.CreateSnapshot(context.Background(), "sess-5", "v1")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	assertOpaqueRef(t, ref)
	if ref != "ds-snap://sess-5/v1" {
		t.Fatalf("ref = %q, want ds-snap://sess-5/v1", ref)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("expected 1 exec (snapshot-create-as), got %d: %v", len(rr.calls), rr.calls)
	}
	snapFile := filepath.Join(dir, "sess-5.ds-snap-sess-5-v1")
	want := "virsh snapshot-create-as ds-sess-5 --name ds-snap-sess-5-v1 --disk-only --atomic --no-metadata --diskspec vda,snapshot=external,file=" + snapFile
	if strings.Join(rr.calls[0], " ") != want {
		t.Fatalf("capture = %q, want %q", strings.Join(rr.calls[0], " "), want)
	}
}

// TestCreateSnapshotIdempotentRetry: the deterministic snapshot FILE already
// exists → CreateSnapshot returns the SAME opaque ref with NO snapshot-create-as
// call (the idempotent no-op-on-repeat contract — never a second durable snapshot,
// never the file-already-exists error a blind re-create hits).
func TestCreateSnapshotIdempotentRetry(t *testing.T) {
	rr := &recordingRunner{}
	s, dir := newTestSnapshotStore(t, rr)
	// Pre-create the snapshot file the prior capture would have written.
	if err := os.WriteFile(filepath.Join(dir, "sess-5.ds-snap-sess-5-v1"), []byte("snap"), 0o644); err != nil {
		t.Fatal(err)
	}

	ref, err := s.CreateSnapshot(context.Background(), "sess-5", "v1")
	if err != nil {
		t.Fatalf("CreateSnapshot (retry): %v", err)
	}
	assertOpaqueRef(t, ref)
	if ref != "ds-snap://sess-5/v1" {
		t.Fatalf("retry ref = %q, want the same ds-snap://sess-5/v1", ref)
	}
	if len(rr.calls) != 0 {
		t.Fatalf("expected 0 execs (snapshot file present, no recreate), got %d: %v", len(rr.calls), rr.calls)
	}
}

// TestCreateSnapshotDifferentLabelDistinctRef: with the v1 snapshot file present,
// a DIFFERENT label (v2) is ABSENT → its distinct snapshot is captured → a
// DISTINCT opaque ref.
func TestCreateSnapshotDifferentLabelDistinctRef(t *testing.T) {
	rr := &recordingRunner{outputs: []string{""}}
	s, dir := newTestSnapshotStore(t, rr)
	if err := os.WriteFile(filepath.Join(dir, "sess-5.ds-snap-sess-5-v1"), []byte("snap"), 0o644); err != nil {
		t.Fatal(err)
	}

	ref, err := s.CreateSnapshot(context.Background(), "sess-5", "v2")
	if err != nil {
		t.Fatalf("CreateSnapshot (different label): %v", err)
	}
	assertOpaqueRef(t, ref)
	if ref != "ds-snap://sess-5/v2" {
		t.Fatalf("ref = %q, want a DISTINCT ds-snap://sess-5/v2", ref)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("expected 1 exec (create) for the distinct label, got %d: %v", len(rr.calls), rr.calls)
	}
	if !strings.Contains(strings.Join(rr.calls[0], " "), "--name ds-snap-sess-5-v2") {
		t.Fatalf("distinct-label capture did not name the v2 snapshot: %v", rr.calls[0])
	}
}

// TestCreateSnapshotEmptyLabelDeterministic: an EMPTY label is the unlabeled-
// capture case — deterministic on the session (a retry re-derives the same name +
// file and no-ops) and its ref is OPAQUE.
func TestCreateSnapshotEmptyLabelDeterministic(t *testing.T) {
	rr := &recordingRunner{outputs: []string{""}}
	s, dir := newTestSnapshotStore(t, rr)

	ref, err := s.CreateSnapshot(context.Background(), "sess-8", "")
	if err != nil {
		t.Fatalf("CreateSnapshot (empty label): %v", err)
	}
	assertOpaqueRef(t, ref)
	if ref != "ds-snap://sess-8/" {
		t.Fatalf("empty-label ref = %q, want ds-snap://sess-8/", ref)
	}
	if len(rr.calls) != 1 || !strings.Contains(strings.Join(rr.calls[0], " "), "--name ds-snap-sess-8-unlabeled") {
		t.Fatalf("empty-label capture did not use the deterministic unlabeled name: %v", rr.calls)
	}

	// Retry: the unlabeled snapshot file now exists → no recreate, same ref, no new call.
	if err := os.WriteFile(filepath.Join(dir, "sess-8.ds-snap-sess-8-unlabeled"), []byte("snap"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref2, err := s.CreateSnapshot(context.Background(), "sess-8", "")
	if err != nil {
		t.Fatalf("CreateSnapshot (empty label retry): %v", err)
	}
	if ref2 != ref {
		t.Fatalf("empty-label retry ref = %q, want the same %q", ref2, ref)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("empty-label retry should no-op (still 1 total call), got %d: %v", len(rr.calls), rr.calls)
	}
}

// TestCreateSnapshotCaptureFailureSurfacesError: with the snapshot file absent, a
// snapshot-create-as write failure is a genuine host fault surfaced non-nil (NEVER
// swallowed).
func TestCreateSnapshotCaptureFailureSurfacesError(t *testing.T) {
	rr := &recordingRunner{
		outputs: []string{""},
		errs:    []error{errors.New("error: operation failed: domain is not running")},
	}
	s, _ := newTestSnapshotStore(t, rr)
	if _, err := s.CreateSnapshot(context.Background(), "sess-9", "v1"); err == nil {
		t.Fatal("expected CreateSnapshot to surface the snapshot-create-as write failure")
	}
}

// TestCreateSnapshotRejectsEmptySession: a missing session uuid is an input fault,
// never a virsh call.
func TestCreateSnapshotRejectsEmptySession(t *testing.T) {
	rr := &recordingRunner{}
	s, _ := newTestSnapshotStore(t, rr)
	if _, err := s.CreateSnapshot(context.Background(), "", "v1"); err == nil {
		t.Fatal("expected CreateSnapshot to reject an empty session uuid")
	}
	if len(rr.calls) != 0 {
		t.Fatalf("empty-session call must not reach virsh: %v", rr.calls)
	}
}

// TestSnapshotRefNeverLeaksInternals: across labels (including a qcow2-shaped label
// and a path-shaped label), the returned ref stays the opaque ds-snap:// handle
// and never carries a qcow2 path / snapshot-XML (D29/D30).
func TestSnapshotRefNeverLeaksInternals(t *testing.T) {
	for _, label := range []string{"v1", "", "looks.qcow2", "/var/lib/evil"} {
		rr := &recordingRunner{outputs: []string{""}}
		s, _ := newTestSnapshotStore(t, rr)
		ref, err := s.CreateSnapshot(context.Background(), "sess-leak", label)
		if err != nil {
			t.Fatalf("CreateSnapshot(label=%q): %v", label, err)
		}
		if !strings.HasPrefix(ref, "ds-snap://sess-leak/") {
			t.Fatalf("ref %q lost the opaque ds-snap:// shape", ref)
		}
		if strings.Contains(ref, "<domainsnapshot") || strings.Contains(ref, "snapshot-create-as") {
			t.Fatalf("ref %q leaked a libvirt internal", ref)
		}
	}
}

// TestNewLiveSnapshotStoreMirrorsBooterConstructor: the constructor satisfies the
// seam, defaults the virsh bin, carries the overlay dir, and installs the
// production runner (mirroring NewLiveBooter / NewLiveSuspender).
func TestNewLiveSnapshotStoreMirrorsBooterConstructor(t *testing.T) {
	store, err := NewLiveSnapshotStore(LiveConfig{OverlayDir: "/var/lib/ds/overlays"})
	if err != nil {
		t.Fatalf("NewLiveSnapshotStore: %v", err)
	}
	ls, ok := store.(*liveSnapshotStore)
	if !ok {
		t.Fatalf("NewLiveSnapshotStore returned %T, want *liveSnapshotStore", store)
	}
	if ls.virshBin != "virsh" {
		t.Fatalf("default virsh bin = %q, want virsh", ls.virshBin)
	}
	if ls.overlayDir != "/var/lib/ds/overlays" {
		t.Fatalf("overlay dir = %q, want /var/lib/ds/overlays", ls.overlayDir)
	}
	if _, ok := ls.run.(execRunner); !ok {
		t.Fatalf("production runner = %T, want execRunner", ls.run)
	}
	store2, _ := NewLiveSnapshotStore(LiveConfig{VirshBin: "/usr/bin/virsh"})
	if store2.(*liveSnapshotStore).virshBin != "/usr/bin/virsh" {
		t.Fatalf("configured virsh bin not honored: %q", store2.(*liveSnapshotStore).virshBin)
	}
}
