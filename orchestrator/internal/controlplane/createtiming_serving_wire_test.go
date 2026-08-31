// SPDX-License-Identifier: Apache-2.0

package controlplane

// createtiming_serving_wire_test.go pins the createtiming-serving-wire deliverable at the
// composition root: NewControlPlane calls SetCreateTimingServing(cp.Reconcile), so the create
// path's D81 §8 fold sink is NON-NIL post-construction and folds onto the SAME reconcile-loop
// recorder the (b)-row read surface (CreateTimingServerSpanTrend) reads. Synthetic fakes only,
// no live VM/host-agent (D50).
//
// It ALSO pins the foldattach-carriage deliverable: the host→control-plane carriage call-site
// controlplane.ControlPlane.FoldHostAttachSegment threads the host-agent AttachBridge's measured
// doc 15 §8 attach-leg segment (SegAttachHandshake) into the SAME reconcile-loop recorder, so the
// host's attach-leg contribution reaches the shared trend even though it originates on the
// host-agent seam. Both the fold and the AttachBridge's measurement are armed by the SAME single
// flag (DS_ORCH_CREATETIMING_WIRE), so gate-off the carriage is a byte-identical no-op. Synthetic
// fakes only, offline no-launch AttachBridge (DS_HOSTAGENT_LIVE unset), no live VM (D50).

import (
	"context"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// TestNewControlPlane_InstallsCreateTimingSink proves the deferred composition-root wire is now
// live: after NewControlPlane the SessionService's create-timing fold sink is installed
// (non-nil), and it is the SAME reconcile loop exposed as cp.Reconcile — so the create fold and
// the (b)-row read share one recorder. Absent the wire the sink would be nil and the fold leg
// dead at runtime.
func TestNewControlPlane_InstallsCreateTimingSink(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	if f.cp.Sessions.createTiming == nil {
		t.Fatal("NewControlPlane left the create-timing fold sink nil — SetCreateTimingServing(cp.Reconcile) was not wired (the fold leg is dead at runtime)")
	}
	// The installed sink IS the reconcile loop (cp.Reconcile), not a second recorder — the fold
	// lands on the SAME trend the (b)-row instrument reads.
	if f.cp.Sessions.createTiming != createTimingSink(f.cp.Reconcile) {
		t.Fatal("create-timing sink is not cp.Reconcile — the fold must land on the reconcile loop's recorder, not a separate one")
	}
}

// TestNewControlPlane_CreateTimingReadLegServed proves the wired sink serves the (b)-row read
// surface: CreateTimingServerSpanTrend returns without panicking (an empty trend when no create
// has folded, never a nil-sink fault) — the sink is genuinely installed, not left refusing.
func TestNewControlPlane_CreateTimingReadLegServed(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	trend := f.cp.Sessions.CreateTimingServerSpanTrend()
	if trend.Count != 0 {
		t.Errorf("fresh control plane CreateTimingServerSpanTrend Count = %d, want 0 (no create folded yet)", trend.Count)
	}
}

// TestFoldHostAttachSegment_FoldsAttachLegIntoSharedTrend is the foldattach-carriage headline:
// with the wire ARMED, the host→control-plane carriage call-site FoldHostAttachSegment threads a
// host-agent AttachBridge's measured §8 attach-leg segment into the SAME reconcile-loop recorder
// the (b)-row read surface reports — so the host's attach-leg contribution reaches the shared
// trend. It runs the AttachBridge OFFLINE (DS_HOSTAGENT_LIVE unset ⇒ Serve launches nothing) yet
// still measures the segment (the flag-gated measurement wraps the offline no-launch path), so
// the whole cross-seam flow is exercised with NO live VM/host-agent (D50).
//
// If the call-site were removed (FoldHostAttachSegment stopped invoking the bridge's
// FoldAttachSegment onto cp.Reconcile), the loop's trend would stay empty and this test would
// fail — the acceptance guard.
func TestFoldHostAttachSegment_FoldsAttachLegIntoSharedTrend(t *testing.T) {
	// Arm BOTH the loop's create-timing wire (read at NewControlPlane inside newFixture) and the
	// AttachBridge's attach-leg measurement (read at NewAttachBridge) from the SAME single flag.
	t.Setenv(CreateTimingWireFlag, "1")
	// Keep the bridge OFFLINE so Serve launches no ds-hostbridge child (no live substrate, D50).
	t.Setenv(libvirt.EnvHostAgentLive, "0")

	f := newFixture(t, fixtureOpts{})

	// The reconcile loop the fold lands on must have its own wire armed (same flag, read once at
	// construction) — else the fold would no-op even with a measured segment.
	if !f.cp.Reconcile.createTiming.Enabled() {
		t.Fatal("reconcile loop create-timing wire is not armed under DS_ORCH_CREATETIMING_WIRE=1 (the fold would no-op)")
	}

	bridge := hostagent.NewAttachBridge(hostagent.AttachBridgeConfig{})
	const sessionUUID = "sess-foldattach-1"

	// Serve stands up (offline: renders) the per-session leg; the armed measurement records the
	// SegAttachHandshake segment on every path, including this no-launch return.
	out, err := bridge.Serve(context.Background(), sessionUUID, 0 /*offline: CID unused*/, libvirt.SessionModeStructured)
	if err != nil {
		t.Fatalf("AttachBridge.Serve (offline): %v", err)
	}
	if out.Launched {
		t.Fatalf("AttachBridge.Serve launched a child off DS_HOSTAGENT_LIVE (want offline no-launch)")
	}
	if got := bridge.AttachSegmentStack(sessionUUID); len(got) != 1 {
		t.Fatalf("armed AttachBridge measured %d attach-leg segments after Serve, want 1 (the producer the carriage folds)", len(got))
	}

	// The carriage call-site: fold the host's attach-leg segment into cp.Reconcile's shared trend.
	const clientRTT = 7 * time.Millisecond
	trend, ok, err := f.cp.FoldHostAttachSegment(bridge, sessionUUID, clientRTT)
	if err != nil {
		t.Fatalf("FoldHostAttachSegment: %v", err)
	}
	if !ok {
		t.Fatal("FoldHostAttachSegment reported ok=false with the wire armed and a measured segment (nothing folded — the call-site did not reach the bridge producer)")
	}
	if trend.Count != 1 {
		t.Fatalf("folded server-span trend Count = %d, want 1 (the one attach-leg create folded)", trend.Count)
	}

	// The fold landed on the SAME reconcile-loop recorder the (b)-row read surface reports — no
	// second recorder. The attach_handshake segment is present with its measured sample.
	if got := f.cp.Reconcile.CreateTimingServerSpanTrend().Count; got != 1 {
		t.Fatalf("reconcile-loop server-span trend Count = %d after carriage fold, want 1 (the host segment must land on the shared trend)", got)
	}
	if got := f.cp.Reconcile.createTiming.SegmentTrend(createtiming.SegAttachHandshake).Count; got != 1 {
		t.Fatalf("attach_handshake segment trend Count = %d after carriage fold, want 1 (the folded segment must be the host attach-leg segment)", got)
	}
}

// TestFoldHostAttachSegment_DirectSeamAgainstConcreteReconcileLoop proves the cross-seam type
// agreement the carriage relies on: the concrete *reconcileLoop NewControlPlane wires (cp.Reconcile)
// satisfies the host-agent's createTimingFoldSink NATIVELY — bridge.FoldAttachSegment accepts it
// directly, with no adapter. It compiles ONLY because *reconcileLoop's RecordCreateTiming matches
// the sink shape (the D80 structure-mirrored seam, no reverse import), and folds a measured segment
// straight onto the loop's recorder.
func TestFoldHostAttachSegment_DirectSeamAgainstConcreteReconcileLoop(t *testing.T) {
	t.Setenv(CreateTimingWireFlag, "1")
	t.Setenv(libvirt.EnvHostAgentLive, "0")

	f := newFixture(t, fixtureOpts{})
	bridge := hostagent.NewAttachBridge(hostagent.AttachBridgeConfig{})
	const sessionUUID = "sess-foldattach-direct"

	if _, err := bridge.Serve(context.Background(), sessionUUID, 0, libvirt.SessionModeStructured); err != nil {
		t.Fatalf("AttachBridge.Serve (offline): %v", err)
	}

	// The concrete *reconcileLoop is handed straight in as the fold sink — the compile-time
	// cross-seam proof (no import cycle, no adapter).
	trend, ok, err := bridge.FoldAttachSegment(f.cp.Reconcile, sessionUUID, 0)
	if err != nil {
		t.Fatalf("FoldAttachSegment against concrete *reconcileLoop: %v", err)
	}
	if !ok || trend.Count != 1 {
		t.Fatalf("FoldAttachSegment onto *reconcileLoop: ok=%v Count=%d, want ok=true Count=1", ok, trend.Count)
	}
}

// TestFoldHostAttachSegment_GateOffFoldsNothing pins the default-off byte-identical contract: with
// DS_ORCH_CREATETIMING_WIRE unset, the AttachBridge measures no segment, FoldHostAttachSegment
// returns before touching the bridge or the loop, and the reconcile-loop trend stays empty — the
// carriage is inert, exactly the pre-wire behavior.
func TestFoldHostAttachSegment_GateOffFoldsNothing(t *testing.T) {
	// Force the flag OFF (an unset-or-any-other value is off; "0" is the explicit form).
	t.Setenv(CreateTimingWireFlag, "0")
	t.Setenv(libvirt.EnvHostAgentLive, "0")

	f := newFixture(t, fixtureOpts{})
	if f.cp.Reconcile.createTiming.Enabled() {
		t.Fatal("reconcile loop create-timing wire is armed with the flag off (default-off contract broken)")
	}

	bridge := hostagent.NewAttachBridge(hostagent.AttachBridgeConfig{})
	const sessionUUID = "sess-foldattach-off"
	if _, err := bridge.Serve(context.Background(), sessionUUID, 0, libvirt.SessionModeStructured); err != nil {
		t.Fatalf("AttachBridge.Serve (offline): %v", err)
	}
	if got := bridge.AttachSegmentStack(sessionUUID); got != nil {
		t.Fatalf("AttachBridge measured a segment with the wire off: %v (want nil — nothing measured)", got)
	}

	trend, ok, err := f.cp.FoldHostAttachSegment(bridge, sessionUUID, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("FoldHostAttachSegment (gate off): %v", err)
	}
	if ok {
		t.Fatal("FoldHostAttachSegment reported ok=true with the wire off (it folded something — not byte-identical)")
	}
	if trend.Count != 0 {
		t.Fatalf("gate-off fold returned trend Count = %d, want 0", trend.Count)
	}
	if got := f.cp.Reconcile.CreateTimingServerSpanTrend().Count; got != 0 {
		t.Fatalf("reconcile-loop trend Count = %d with the wire off, want 0 (the carriage must be inert)", got)
	}
}
