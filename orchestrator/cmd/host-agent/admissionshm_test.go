// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// TestNewAdmissionSegmentSelectorGateOffNoTouch asserts the composition-root selector
// returns the no-touch stand-in off DS_HOSTAGENT_LIVE (Create/Unlink touch nothing), so
// the daemon's gate-off behavior is byte-identical to today — the FAIL-CLOSED default
// preservation at the seam-selection layer.
func TestNewAdmissionSegmentSelectorGateOffNoTouch(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate OFF
	t.Setenv("DS_ADMISSION_SHM_NAME", "/ds-admission-cmd-gateoff")

	seg, err := newAdmissionSegment(libvirt.LiveConfig{OverlayDir: t.TempDir()})
	if err != nil {
		t.Fatalf("gate off: newAdmissionSegment: %v", err)
	}
	if seg == nil {
		t.Fatal("gate off: newAdmissionSegment must return a non-nil no-touch seam")
	}
	// Create/Unlink are no-op successes off the gate (the libvirt-package test asserts
	// no /dev/shm object appears; here we assert the selector wires the no-op).
	if err := seg.Create(context.Background()); err != nil {
		t.Fatalf("gate off: Create must be a no-op success: %v", err)
	}
	if err := seg.Unlink(context.Background()); err != nil {
		t.Fatalf("gate off: Unlink must be a no-op success: %v", err)
	}
}

// TestBuildDriverServiceReturnsAdmissionSegment asserts the composition root always
// returns a non-nil host-owned admission segment (the run() lifecycle owner) — off the
// gate it is the no-touch stand-in, so run() can call Create/defer Unlink without a nil
// guard. This pins the wiring that threads the seam out of buildDriverServiceWithBridge.
func TestBuildDriverServiceReturnsAdmissionSegment(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate OFF (the default offline substrate)

	_, _, _, _, admissionSeg, err := buildDriverServiceWithBridge(defaultTestConfig(), newSessionCIDRegistry())
	if err != nil {
		t.Fatalf("buildDriverServiceWithBridge: %v", err)
	}
	if admissionSeg == nil {
		t.Fatal("buildDriverServiceWithBridge must return a non-nil admission segment (run() drives Create/Unlink on it)")
	}
	// Off the gate the segment's lifecycle is a no-op (the create-at-bring-up run() drives
	// must not fail offline).
	if err := admissionSeg.Create(context.Background()); err != nil {
		t.Fatalf("gate off: admission segment Create must be a no-op success: %v", err)
	}
	if err := admissionSeg.Unlink(context.Background()); err != nil {
		t.Fatalf("gate off: admission segment Unlink must be a no-op success: %v", err)
	}
}

// TestBuildDriverServiceGateOnMalformedShmNameFailsClosed asserts that under
// DS_HOSTAGENT_LIVE a malformed DS_ADMISSION_SHM_NAME override makes the composition
// root FAIL CLOSED at assembly — the daemon refuses the live path rather than bringing
// up with no host-owned segment (docs/sessions/13 §Rollout-ordering, fail-closed). run()
// surfaces this assembly error as a FATAL bring-up refusal. The rest of the live config
// is left minimal: the admission-segment construction is reached before the live config
// validate would matter, and a malformed name is rejected regardless.
func TestBuildDriverServiceGateOnMalformedShmNameFailsClosed(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "1") // gate ON
	t.Setenv("DS_ADMISSION_SHM_NAME", "/ds-admission/illegal-embedded-slash")

	cfg := defaultTestConfig()
	// Supply the live-substrate facts so assembly reaches the admission-segment seam
	// (the live overlay/booter/etc. validate the same LiveConfig); a TempDir overlay dir
	// + placeholder script/base keep the earlier live constructors from failing first, so
	// the malformed-name fail-closed is the assertion under test.
	cfg.overlayDir = t.TempDir()
	cfg.overlayCreateScript = "/bin/true"
	cfg.baseImage = "/dev/null"

	if _, _, _, _, _, err := buildDriverServiceWithBridge(cfg, newSessionCIDRegistry()); err == nil {
		t.Fatal("gate on with a malformed admission shm name must fail closed at assembly, got nil error")
	}
}
