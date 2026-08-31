package controlplane

// destroydurability_test.go pins the controlplane half of the two destroy-path durability
// fixes (D29/D35/D72, doc 15 §4.1 step 4/7 + §4.2) against synthetic fixtures (D50 — no live
// VM/host-agent/podman):
//
//   (1) the per-session CoW overlay path persisted on the §5.6 record is threaded into
//       the §4.2 DestroyRequest (destroyRequestFromRecord), so a destroy after a restart
//       disposes the REAL overlay instead of OverlayPath="";
//   (2) NewControlPlane WIRES the DestroyRedriver — the §4.2 convergence backstop for a
//       session left DESTROYING by a teardown fault. The end-to-end convergence behavior is
//       pinned at the reconciler-component level (reconciler/destroyredrive_test.go) against
//       a fake destroyer; here we pin that the production wiring constructs it.

import (
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestDestroyRequestFromRecord_CarriesPersistedOverlay proves the overlay path recorded
// on the open IndexEpoch flows into BOTH the libvirt binding and the top-level
// DestroyRequest.OverlayPath — so the §4.2 teardown disposes the real CoW overlay
// resolved purely from the persisted record (the post-restart path). Before the fix the
// loop never read an overlay and always drove OverlayPath="".
func TestDestroyRequestFromRecord_CarriesPersistedOverlay(t *testing.T) {
	end := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	rec := store.Session{
		Ref: store.SessionRef{SessionUUID: "sess-1", HostID: "host-a", HostSessionIndex: 5, TapName: "dstap-5"},
		IndexHistory: []store.IndexEpoch{
			// A prior (closed) epoch on the SAME host — a migrated binding already unwound;
			// its overlay must NOT be the one disposed.
			{HostID: "host-a", HostSessionIndex: 2, TapName: "dstap-2", OverlayPath: "/overlays/old.qcow2", EndedAt: &end},
			// The open (current) epoch carries the live overlay to dispose.
			{HostID: "host-a", HostSessionIndex: 5, TapName: "dstap-5", GuestIP: []byte{10, 0, 0, 5}, GuestIPFamily: store.IPFamilyV4, OverlayPath: "/overlays/live.qcow2"},
		},
	}

	req := destroyRequestFromRecord(rec)
	if !req.HasBinding {
		t.Fatalf("a record with a host binding must drive HasBinding=true")
	}
	if req.OverlayPath != "/overlays/live.qcow2" {
		t.Fatalf("DestroyRequest.OverlayPath: got %q, want the open epoch's /overlays/live.qcow2", req.OverlayPath)
	}
	if req.Binding.OverlayPath != "/overlays/live.qcow2" {
		t.Fatalf("Binding.OverlayPath: got %q, want /overlays/live.qcow2", req.Binding.OverlayPath)
	}
	if req.Binding.HostSessionIndex != 5 || req.Binding.TapName != "dstap-5" {
		t.Fatalf("open-epoch binding lost: idx=%d tap=%q", req.Binding.HostSessionIndex, req.Binding.TapName)
	}
}

// TestNewControlPlane_WiresDestroyReDriver proves the production wiring constructs the
// §4.2 destroy-path convergence backstop (the DestroyRedriver) — without it a session left
// DESTROYING by a transient teardown fault would strand forever (the §3 conflict rules
// deliberately do not reap DESTROYING). The component's convergence behavior is pinned in
// reconciler/destroyredrive_test.go; this is the controlplane-level construction pin.
func TestNewControlPlane_WiresDestroyReDriver(t *testing.T) {
	cp, err := NewControlPlane(depsWithStalenessBudget(t, 0))
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	if cp.DestroyReDriver == nil {
		t.Fatalf("NewControlPlane must wire a non-nil DestroyReDriver (the §4.2 convergence backstop)")
	}
}
