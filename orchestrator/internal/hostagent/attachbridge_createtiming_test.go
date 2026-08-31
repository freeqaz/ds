// SPDX-License-Identifier: Apache-2.0

package hostagent

// attachbridge_createtiming_test.go pins the createtiming-feed attach-leg measurement the
// gap-3 serving-child manager hosts: the FLAG-GATED (DS_ORCH_CREATETIMING_WIRE) §8
// SegAttachHandshake measurement around Serve, its default-off inertness (byte-identical
// offline path), and the AttachSegment / AttachSegmentStack read surface a caller folds into
// the control-plane RecordCreateTiming trend. No live process (D50) — the offline no-launch
// path carries the measurement just as the live path would.

import (
	"context"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// TestAttachBridge_CreateTiming_DefaultOffInert is the byte-identical default-off pin: with
// DS_ORCH_CREATETIMING_WIRE UNSET, Serve records NO attach-leg segment — AttachSegment reports
// absent and AttachSegmentStack is nil, while the ServeOutcome is unchanged. The measurement is
// inert on the flag.
func TestAttachBridge_CreateTiming_DefaultOffInert(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "") // gate OFF (offline no-launch)
	t.Setenv(createTimingWireFlag, "")     // create-timing wire OFF (the default)

	b := NewAttachBridge(AttachBridgeConfig{SocketDir: "/run/ds/attach"})
	const sess = "sess-ct-off"

	out, err := b.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured)
	if err != nil {
		t.Fatalf("offline Serve: %v", err)
	}
	if out.Launched {
		t.Error("offline Serve reported Launched=true, want false")
	}

	if _, _, ok := b.AttachSegment(sess); ok {
		t.Error("flag-off Serve recorded an attach-leg segment, want none (measurement inert)")
	}
	if stack := b.AttachSegmentStack(sess); stack != nil {
		t.Errorf("flag-off AttachSegmentStack = %v, want nil (nothing measured)", stack)
	}
}

// TestAttachBridge_CreateTiming_FlagOnMeasuresAttachLeg is the headline attach-leg acceptance:
// with DS_ORCH_CREATETIMING_WIRE=1, Serve measures its own wall time and records it as the
// SegAttachHandshake §8 stack segment — read back via AttachSegment (the segment id + a
// non-negative duration) and AttachSegmentStack (a single-entry stack fragment ready to fold via
// the control-plane RecordCreateTiming). The measurement rides the offline no-launch path (no
// live process, D50) and never changes the ServeOutcome.
func TestAttachBridge_CreateTiming_FlagOnMeasuresAttachLeg(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "") // gate OFF — still offline, the measurement is substrate-independent
	t.Setenv(createTimingWireFlag, "1")    // create-timing wire ON

	b := NewAttachBridge(AttachBridgeConfig{SocketDir: "/run/ds/attach"})
	const sess = "sess-ct-on"

	out, err := b.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured)
	if err != nil {
		t.Fatalf("Serve (flag on): %v", err)
	}
	// The ServeOutcome is unchanged by the measurement (measure-not-gate, D81/D32).
	if out.Launched {
		t.Error("flag-on offline Serve reported Launched=true, want false (measurement never launches)")
	}
	if b.ServingCount() != 0 {
		t.Errorf("flag-on offline Serve launched %d children, want 0", b.ServingCount())
	}

	seg, d, ok := b.AttachSegment(sess)
	if !ok {
		t.Fatal("flag-on Serve recorded no attach-leg segment, want SegAttachHandshake")
	}
	if seg != createtiming.SegAttachHandshake {
		t.Errorf("attach-leg segment = %q, want %q", seg, createtiming.SegAttachHandshake)
	}
	if d < 0 {
		t.Errorf("attach-leg duration = %v, want a non-negative measured span", d)
	}

	// The stack fragment is a single-entry {SegAttachHandshake: d} map, foldable via
	// RecordCreateTiming (which asserts the segment IS a §8 stack segment).
	stack := b.AttachSegmentStack(sess)
	if len(stack) != 1 {
		t.Fatalf("AttachSegmentStack has %d entries, want 1 (the attach-leg segment)", len(stack))
	}
	got, ok := stack[createtiming.SegAttachHandshake]
	if !ok {
		t.Fatal("AttachSegmentStack missing SegAttachHandshake")
	}
	if got != d {
		t.Errorf("AttachSegmentStack duration = %v, want %v (same measured span as AttachSegment)", got, d)
	}
	// The measured segment is a real §8 stack segment (RTT excluded) — the fold's precondition.
	if !createtiming.IsStackSegment(seg) {
		t.Errorf("attach-leg segment %q is not a §8 stack segment", seg)
	}
	if seg == createtiming.SegClientRTT {
		t.Error("attach-leg segment is SegClientRTT, want the trigger-eligible SegAttachHandshake (RTT excluded)")
	}
}

// TestAttachBridge_CreateTiming_DestroyDropsSegment is the §4.2 teardown pin for the ONE
// piece of per-session state this manager keeps outside the children map. Before it, every
// armed Serve added an attachSegments entry and NO teardown removed one, so a long-lived
// daemon grew the map without bound (keyed on a never-recycled session UUID, D66) and a
// post-destroy AttachSegment read still answered ok=true for a session that no longer
// exists. Destroy now drops the entry — session-scoped (a sibling's measurement survives)
// and idempotent (a second Destroy is a clean no-op).
func TestAttachBridge_CreateTiming_DestroyDropsSegment(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "") // gate OFF — the offline no-launch path still measures
	t.Setenv(createTimingWireFlag, "1")    // create-timing wire ON

	b := NewAttachBridge(AttachBridgeConfig{SocketDir: "/run/ds/attach"})
	const gone, live = "sess-ct-destroyed", "sess-ct-kept"
	ctx := context.Background()
	for _, s := range []string{gone, live} {
		if _, err := b.Serve(ctx, s, 0, libvirt.SessionModeStructured); err != nil {
			t.Fatalf("Serve(%s): %v", s, err)
		}
		if _, _, ok := b.AttachSegment(s); !ok {
			t.Fatalf("precondition: %s must have a measured segment before the teardown", s)
		}
	}

	b.Destroy(gone)

	if _, _, ok := b.AttachSegment(gone); ok {
		t.Error("Destroy must drop the torn-down session's measured attach segment")
	}
	if stack := b.AttachSegmentStack(gone); stack != nil {
		t.Errorf("AttachSegmentStack after Destroy = %v, want nil", stack)
	}
	if _, _, ok := b.AttachSegment(live); !ok {
		t.Error("Destroy must not drop a SIBLING session's measured attach segment")
	}
	// Idempotent: a re-driven teardown over the already-dropped session is a clean no-op.
	b.Destroy(gone)
}

// TestAttachBridge_CreateTiming_DestroyFlagOffIsInert: with the wire OFF the segment map is
// never allocated, so the teardown drop is a no-op on a nil map (legal, allocates nothing) —
// the default path stays byte-identical, and Shutdown (which reaps every child THROUGH
// Destroy) inherits the same inertness.
func TestAttachBridge_CreateTiming_DestroyFlagOffIsInert(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "")
	t.Setenv(createTimingWireFlag, "")

	b := NewAttachBridge(AttachBridgeConfig{SocketDir: "/run/ds/attach"})
	const sess = "sess-ct-off-destroy"
	if _, err := b.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured); err != nil {
		t.Fatalf("offline Serve: %v", err)
	}
	b.Destroy(sess)
	b.Shutdown()
	if _, _, ok := b.AttachSegment(sess); ok {
		t.Error("flag-off teardown must leave the measurement inert (nothing recorded, nothing to drop)")
	}
}
