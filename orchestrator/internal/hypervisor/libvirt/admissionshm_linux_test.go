// SPDX-License-Identifier: Apache-2.0

//go:build linux

package libvirt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uniqueShmName builds a per-test POSIX shm name (/-prefixed, no embedded slash) so
// parallel test runs never collide and a stale leftover never bleeds in — mirroring the
// e2e's unique_segment_name. The caller is responsible for cleanup; the tests below
// shm_unlink via the seam (and a t.Cleanup belt-and-suspenders).
func uniqueShmName(t *testing.T, tag string) string {
	t.Helper()
	return "/ds-admission-gotest-" + tag + "-" + strings.ReplaceAll(t.Name(), "/", "_")
}

// shmDevPath maps a /name POSIX shm name to its /dev/shm/<name> file (the same mapping
// the live seam uses) so the test can stat the kernel object directly.
func shmDevPath(name string) string {
	return filepath.Join("/dev/shm", strings.TrimPrefix(name, "/"))
}

// shmExists reports whether the named POSIX shm object is present under /dev/shm.
func shmExists(name string) bool {
	_, err := os.Stat(shmDevPath(name))
	return err == nil
}

// requireDevShm skips if /dev/shm is absent (POSIX shm unavailable); on the production
// substrate (and this box) it is present, so the test runs by default.
func requireDevShm(t *testing.T) {
	t.Helper()
	if fi, err := os.Stat("/dev/shm"); err != nil || !fi.IsDir() {
		t.Skip("POSIX shm unavailable (/dev/shm missing); skipping live shm lifecycle test")
	}
}

// TestAdmissionSegmentLiveCreateThenUnlink is the LIVE acceptance proof: under
// DS_HOSTAGENT_LIVE the host creates the named shm object at Create (it exists on
// /dev/shm), Create is idempotent (a second Create converges), Unlink removes it, and
// Unlink is idempotent on an already-absent object. This exercises the real
// shm_open(O_CREAT)/shm_unlink path the ds-dnsgate writer then attaches over.
func TestAdmissionSegmentLiveCreateThenUnlink(t *testing.T) {
	requireDevShm(t)
	t.Setenv(EnvHostAgentLive, "1") // gate ON
	name := uniqueShmName(t, "lifecycle")
	t.Setenv(EnvAdmissionShmName, name)
	// Belt-and-suspenders cleanup so a failed assertion never leaks a /dev/shm object.
	t.Cleanup(func() { _ = os.Remove(shmDevPath(name)) })

	seg, err := NewAdmissionSegment(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("gate on: NewAdmissionSegment: %v", err)
	}
	if _, ok := seg.(*liveAdmissionSegment); !ok {
		t.Fatalf("gate on must return the live seam, got %T", seg)
	}

	if shmExists(name) {
		t.Fatalf("pre-condition: shm object %q must not exist before Create", name)
	}

	// LIVE create: the named object exists on /dev/shm after Create.
	if err := seg.Create(context.Background()); err != nil {
		t.Fatalf("live Create: %v", err)
	}
	if !shmExists(name) {
		t.Fatalf("after Create the shm object %q must exist on /dev/shm", name)
	}

	// Create is IDEMPOTENT: a second Create on an existing object converges (no O_EXCL),
	// never double-fails — the idempotent bring-up the acceptance asks for.
	if err := seg.Create(context.Background()); err != nil {
		t.Fatalf("second Create must converge (idempotent), got: %v", err)
	}
	if !shmExists(name) {
		t.Fatalf("after the idempotent second Create the object %q must still exist", name)
	}

	// LIVE teardown unlinks: the named object is gone after Unlink.
	if err := seg.Unlink(context.Background()); err != nil {
		t.Fatalf("live Unlink: %v", err)
	}
	if shmExists(name) {
		t.Fatalf("after Unlink the shm object %q must be gone from /dev/shm", name)
	}

	// Unlink is IDEMPOTENT on an already-absent object (ENOENT is a no-op success — the
	// no-op-on-absent contract every host-agent teardown seam holds).
	if err := seg.Unlink(context.Background()); err != nil {
		t.Fatalf("second Unlink on an absent object must be a no-op success, got: %v", err)
	}
}

// TestAdmissionSegmentGateOffCreatesNothingOnDevShm asserts the FAIL-CLOSED default on
// Linux at the kernel level: off DS_HOSTAGENT_LIVE the no-touch seam's Create makes NO
// /dev/shm object — the gate-off path is byte-identical to today, no segment is created.
func TestAdmissionSegmentGateOffCreatesNothingOnDevShm(t *testing.T) {
	requireDevShm(t)
	t.Setenv(EnvHostAgentLive, "") // gate OFF
	name := uniqueShmName(t, "gateoff")
	t.Setenv(EnvAdmissionShmName, name)
	t.Cleanup(func() { _ = os.Remove(shmDevPath(name)) })

	seg, err := NewAdmissionSegment(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("gate off: NewAdmissionSegment: %v", err)
	}
	if err := seg.Create(context.Background()); err != nil {
		t.Fatalf("gate off: Create must be a no-op success: %v", err)
	}
	if shmExists(name) {
		t.Fatalf("gate off: Create must create NO /dev/shm object, but %q exists", name)
	}
	// Unlink off the gate is also a no-op (and must not error even with no object).
	if err := seg.Unlink(context.Background()); err != nil {
		t.Fatalf("gate off: Unlink must be a no-op success: %v", err)
	}
}

// TestAdmissionSegmentLiveCreateErrorFailsClosed forces a Create-time error under the
// gate (a valid-SHAPED but kernel-rejected name — over NAME_MAX, so shm_open returns
// ENAMETOOLONG) and asserts Create propagates the error. The composition root maps this
// to a FATAL bring-up refusal (run() returns it), satisfying docs/sessions/13
// §Rollout-ordering line 34 — a create failure is fail-closed, never a silent
// no-segment continue. (The construction-time malformed-name fail-closed is covered in
// the platform-independent test; this is the Create-time fault leg.)
func TestAdmissionSegmentLiveCreateErrorFailsClosed(t *testing.T) {
	requireDevShm(t)
	t.Setenv(EnvHostAgentLive, "1") // gate ON
	// A "/name" with no embedded slash (so it passes the POSIX shape validation) but
	// far longer than NAME_MAX (255): the kernel rejects the open with ENAMETOOLONG, so
	// Create must surface the error rather than silently proceed.
	tooLong := "/" + strings.Repeat("a", 300)
	t.Setenv(EnvAdmissionShmName, tooLong)
	t.Cleanup(func() { _ = os.Remove(shmDevPath(tooLong)) })

	seg, err := NewAdmissionSegment(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		// Some platforms might reject the over-long name at construction; that is also a
		// fail-closed outcome — the live path is refused. Either is acceptable.
		return
	}
	if err := seg.Create(context.Background()); err == nil {
		t.Fatal("live Create with a kernel-rejected (over-long) name must fail closed, got nil error")
	}
}
