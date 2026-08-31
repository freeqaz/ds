// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"testing"
)

// TestAdmissionShmNameSingleSourcesTheContract asserts the Go-side name resolver
// mirrors the Rust contract ds_contracts::dns_admission::admission_shm_name() EXACTLY
// (dns_admission.rs:433-450): the DS_ADMISSION_SHM_NAME override when set and
// non-empty, else the /ds-admission default, with an EMPTY override treated as unset.
// This is the host/writer/reader rendezvous guard — a drift here silently breaks the
// segment the three agree on.
func TestAdmissionShmNameSingleSourcesTheContract(t *testing.T) {
	// The override env var name + the default match the documented contract literals.
	if EnvAdmissionShmName != "DS_ADMISSION_SHM_NAME" {
		t.Fatalf("env var name drifted from the Rust contract: got %q", EnvAdmissionShmName)
	}
	if DefaultAdmissionShmName != "/ds-admission" {
		t.Fatalf("default shm name drifted from the Rust contract: got %q", DefaultAdmissionShmName)
	}

	// Unset → the default.
	t.Setenv(EnvAdmissionShmName, "")
	// t.Setenv with "" sets the var to empty; AdmissionShmName must treat empty as unset.
	if got := AdmissionShmName(); got != DefaultAdmissionShmName {
		t.Fatalf("empty override must fall back to the default: got %q want %q", got, DefaultAdmissionShmName)
	}

	// Set + non-empty → the override verbatim.
	t.Setenv(EnvAdmissionShmName, "/ds-admission-test-override")
	if got := AdmissionShmName(); got != "/ds-admission-test-override" {
		t.Fatalf("non-empty override must be returned verbatim: got %q", got)
	}
}

// TestNewAdmissionSegmentGateOffIsNoTouch asserts that with DS_HOSTAGENT_LIVE UNSET the
// factory returns the no-touch stand-in: Create/Unlink touch NOTHING and succeed, so
// the daemon's behavior off the gate is byte-identical to today (no /dev/shm object is
// created). This is the FAIL-CLOSED-default preservation check (gate-off path).
func TestNewAdmissionSegmentGateOffIsNoTouch(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "") // gate OFF (the default offline substrate)
	// Even with a name override configured, the gate-off seam never touches it.
	t.Setenv(EnvAdmissionShmName, "/ds-admission-gateoff-should-not-exist")

	seg, err := NewAdmissionSegment(LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("gate off: NewAdmissionSegment must succeed: %v", err)
	}
	if seg == nil {
		t.Fatal("gate off: NewAdmissionSegment must return a non-nil no-touch seam")
	}
	if _, ok := seg.(noTouchAdmissionSegment); !ok {
		t.Fatalf("gate off must return the no-touch stand-in, got %T", seg)
	}
	// Create + Unlink are no-op successes; they create no object (asserted on Linux in
	// the build-tagged test that it never appears under /dev/shm).
	if err := seg.Create(context.Background()); err != nil {
		t.Fatalf("gate off: Create must be a no-op success: %v", err)
	}
	if err := seg.Unlink(context.Background()); err != nil {
		t.Fatalf("gate off: Unlink must be a no-op success: %v", err)
	}
}

// TestNewAdmissionSegmentGateOnMalformedNameFailsClosed asserts that under
// DS_HOSTAGENT_LIVE a malformed DS_ADMISSION_SHM_NAME override (an illegal POSIX shm
// name) makes the factory FAIL CLOSED at construction rather than producing a seam that
// would create a surprising path. The daemon's composition root surfaces this as a
// FATAL bring-up error (docs/sessions/13 §Rollout-ordering: a create/attach failure is
// fail-closed — never a silent no-segment continue). On a non-Linux build the live path
// is unsupported, so NewAdmissionSegment also errors here — both are the fail-closed
// posture this test asserts.
func TestNewAdmissionSegmentGateOnMalformedNameFailsClosed(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "1") // gate ON
	// An embedded-slash name is an illegal POSIX shm name (shm_open(3)); the resolver
	// returns it verbatim and the live constructor must reject it (or the non-Linux stub
	// rejects the whole live path) — never silently rewrite it.
	t.Setenv(EnvAdmissionShmName, "/ds-admission/illegal")

	if _, err := NewAdmissionSegment(LiveConfig{OverlayDir: t.TempDir()}); err == nil {
		t.Fatal("gate on with a malformed shm name must fail closed at construction, got nil error")
	}
}
