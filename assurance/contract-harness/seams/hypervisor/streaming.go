// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// --- ExportDiskDelta server-streaming lifecycle hardening --------------------
//
// ExportDiskDelta is genuine server-streaming: the capable driver streams the D29
// overlay delta frame-by-frame (refimpl.ExportDiskDelta loops stream.Send over the
// frames; the generated fake's responder loops stream.Send over its eager slice).
// Suite()'s export-disk-delta scenarios prove the delta CONTENT shape (frame count,
// total bytes, NotFound / InvalidArgument / capability-refusal statuses). They do
// NOT exercise the STREAM LIFECYCLE — what happens when the consumer cancels
// mid-stream, lets its deadline expire, or reads slowly. This file wires that
// lifecycle through the SHARED dualrun streaming affordance (dualrun.StreamOpener +
// CancelAfterFrames / DeadlineAfterFrames / SlowConsumer), consuming ONLY the
// affordance's existing exported API.
//
// The lifecycle is driven against matched pairs of honest streaming ends keyed on
// the REAL ExportDiskDelta method and REAL hypervisor.v1 wire types — one stands in
// for the real driver, one for the generated fake — so every lifecycle scenario is
// green real-vs-fake; a drifted end DIVERGES (the bite). Two honest end SHAPES are
// needed because the cancel/deadline scenarios and the slow-consumer scenario impose
// different determinism requirements (this mirrors the affordance self-test, which
// pairs a bounded-park responder with the cancel scenarios and an eager-complete
// responder with the slow-consumer one):
//
//   - cancel/deadline: the consumer reads exactly k frames, cancels, then asserts
//     ZERO frames after and a context-cancellation terminal. For that to be a
//     DETERMINISTIC real-vs-fake fact (not a cross-transport buffering race), the
//     honest producer must deliver exactly k frames then PARK awaiting the cancel —
//     no (k+1)th frame in flight to race the teardown. -> dualrun.BoundedParkPlan.
//   - slow-consumer: the consumer stalls, then drains the WHOLE tail to a clean EOF.
//     The honest producer streams every frame, in order, completing — flow control
//     holds it back under the stall, it does not drop/reorder. -> dualrun.EagerCompletePlan.
//
// Both shapes are the SAME deltaStreamServer parameterized by a different
// dualrun.BackPressurePlan; the producer logic is single-sourced in
// dualrun.RunBackPressureStream (this seam only adapts it to the ExportDiskDelta RPC
// signature + frame builder).
//
// Synthetic frames only (D50). NOTE: identity-digestfeed (DigestPublish /
// DigestRevoke) is UNARY — no server-streaming verb — and is explicitly EXCLUDED
// from this hardening. ExportDiskDelta is the hypervisor seam's only server-
// streaming RPC.

// lifecycleFrameBytes sizes each synthetic delta frame so a small number of frames
// overflows the HTTP/2 stream flow-control window (~64 KiB) and the in-process pipe
// buffer — that overflow is what forces a faithful producer to BLOCK on Send under a
// slow/cancelled consumer (back-pressure) rather than racing the whole stream ahead.
// 16 KiB/frame: a handful overflow. This rides a seam-specific proto field, so it
// stays local; the index plan + frame COUNTS are single-sourced in the shared
// dualrun back-pressure fixture (dualrun.Lifecycle* / dualrun.*Plan). Synthetic
// deterministic padding (D50).
const lifecycleFrameBytes = 16 << 10

// openExportDiskDelta is the dualrun.StreamOpener for ExportDiskDelta: it opens the
// server-streaming RPC against the dialed conn, threading the affordance's
// cancellable ctx into the call so a cancel/deadline propagates to the server. It
// is keyed on the lifecycle session the lifecycle dialers stream for. This is the
// per-RPC opener the affordance's CancelAfterFrames / DeadlineAfterFrames /
// SlowConsumer scenarios drive.
func openExportDiskDelta(ctx context.Context, conn *grpc.ClientConn) (grpc.ServerStreamingClient[hypervisorv1.ExportDiskDeltaResponse], error) {
	cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
	return cl.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: synthSessDelta})
}

// deltaSeqOf extracts the per-frame monotonic key the SlowConsumer scenario uses
// for its in-order / exactly-once check. The lifecycle frames carry a 1-based
// consecutive offset (frame i has Offset i), so a faithful in-order delivery reads
// 1,2,3,… — a stall that reorders or drops diverges.
func deltaSeqOf(r *hypervisorv1.ExportDiskDeltaResponse) uint64 { return r.GetOffset() }

// StreamingCancelSuite hardens the ExportDiskDelta cancel + deadline lifecycle: a
// consumer that cancels (or whose deadline expires) after k frames must see the
// server STOP — zero frames after, a context-cancellation terminal. Run it
// real-vs-fake (LifecycleCancelHonestRealDialer / LifecycleCancelHonestFakeDialer)
// like the seam's other suites.
func StreamingCancelSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam: "orchestrator<->hypervisor(ExportDiskDelta-cancel)",
		Scenarios: []dualrun.Scenario{
			dualrun.CancelAfterFrames("export-disk-delta/cancel-after-frames-stops-stream", dualrun.LifecycleCancelK, openExportDiskDelta),
			dualrun.DeadlineAfterFrames("export-disk-delta/deadline-after-frames-stops-stream", dualrun.LifecycleCancelK, openExportDiskDelta),
		},
	}
}

// --- back-pressure observation matrix ----------------------------------------
//
// The slow-consumer scenario (dualrun.SlowConsumer) records three exactly-once
// observation keys; each back-pressure drift corner trips a DISTINCT key, so the
// negative-proof tests can assert each corner bites in isolation. The matrix below
// maps each corner to the drifted end that injects it and the observation key it
// trips (the others stay equal to the honest end — that is what makes the bite
// isolatable):
//
//	corner       drift end (LifecycleSlow*Dialer)  delivered count  trips (vs honest)
//	──────────── ──────────────────────────────── ──────────────── ─────────────────────────────
//	honest       …HonestReal/…HonestFake (par.)    expected         nothing (green real-vs-fake)
//	SHORT        …DriftedDialer (DroppingPlan)     expected−1       frames_total (short) +
//	  (dropping)                                                     frames_total_matches_expected=false
//	                                                                 (and drained_in_order, jointly)
//	OUT-OF-ORDER …ReorderDriftedDialer (reorder)   expected         drained_in_order ALONE
//	  (reorder)                                     (UNCHANGED)      (count keys stay equal)
//	DUPLICATE    …DuplicateDriftedDialer (dup)      expected+1       frames_total (over) +
//	  (over-count)                                                   frames_total_matches_expected=false
//	                                                                 (drained_in_order flips too;
//	                                                                  the over count is the unique signal)
//
// The reorder corner is the load-bearing one: it isolates drained_in_order with the
// count keys UNCHANGED, proving the in-order observation bites on its own and not as
// a side effect of a short/over count. The terminal_status key (the cancel/deadline
// corner of StreamingCancelSuite, NOT a back-pressure corner) is orthogonal: it
// trips only on a cancel-swallowing end, never on these three.

// StreamingBackPressureSuite hardens the ExportDiskDelta slow-consumer back-pressure
// lifecycle: a stalled consumer must still receive every frame, in order, exactly
// once, to a clean EOF — the producer is held by flow control, it does not drop or
// reorder. Run it real-vs-fake (LifecycleSlowHonestRealDialer /
// LifecycleSlowHonestFakeDialer). The observation-matrix comment above maps each
// drift corner to the observation key it trips.
func StreamingBackPressureSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam: "orchestrator<->hypervisor(ExportDiskDelta-backpressure)",
		Scenarios: []dualrun.Scenario{
			dualrun.SlowConsumer("export-disk-delta/slow-consumer-honors-flow-control", dualrun.LifecycleSlowFrames, dualrun.LifecycleStall, openExportDiskDelta, deltaSeqOf),
		},
	}
}

// --- honest + drifted streaming ends -----------------------------------------

// deltaCapsServer embeds the unimplemented base and answers GetCapabilities with a
// delta-export-capable profile — shared boilerplate for the lifecycle ends, none of
// which the suite calls beyond ExportDiskDelta.
type deltaCapsServer struct {
	hypervisorv1.UnimplementedHypervisorDriverServiceServer
}

func (deltaCapsServer) GetCapabilities(_ context.Context, _ *hypervisorv1.GetCapabilitiesRequest) (*hypervisorv1.GetCapabilitiesResponse, error) {
	return &hypervisorv1.GetCapabilitiesResponse{Capabilities: &hypervisorv1.Capabilities{SupportsDiskDeltaExport: true}}, nil
}

// deltaStreamServer is the ONE ExportDiskDelta lifecycle end: it runs a
// dualrun.BackPressurePlan (which encodes the honest/drifted variant — bounded-park,
// cancel-swallow, eager-complete, drop, reorder, duplicate) through the shared
// dualrun.RunBackPressureStream driver, threading the seam's ExportDiskDelta frame
// builder. The producer LOGIC (which frames, in what order, park-or-complete) lives
// once in the shared fixture; this method only adapts it to the hypervisor.v1 RPC
// signature.
type deltaStreamServer struct {
	deltaCapsServer
	plan dualrun.BackPressurePlan
}

func (s *deltaStreamServer) ExportDiskDelta(req *hypervisorv1.ExportDiskDeltaRequest, stream grpc.ServerStreamingServer[hypervisorv1.ExportDiskDeltaResponse]) error {
	if req.GetSessionUuid() == "" {
		return invalidSession()
	}
	return dualrun.RunBackPressureStream(stream.Context(), s.plan, func(i int) error {
		return stream.Send(lifecycleFrame(i))
	})
}

// --- lifecycle dialers -------------------------------------------------------

func registerDelta(plan dualrun.BackPressurePlan) dualrun.Dialer {
	srv := &deltaStreamServer{plan: plan}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hypervisorv1.RegisterHypervisorDriverServiceServer(s, srv)
	})
}

// LifecycleCancelHonestRealDialer / LifecycleCancelHonestFakeDialer are the matched
// honest pair StreamingCancelSuite runs real-vs-fake: both serve the identical
// bounded-park ExportDiskDelta stream (one stands in for the real driver, one for the
// generated fake), so the cancel + deadline scenarios are green real-vs-fake.
func LifecycleCancelHonestRealDialer() dualrun.Dialer {
	return registerDelta(dualrun.BoundedParkPlan(dualrun.LifecycleCancelK))
}

func LifecycleCancelHonestFakeDialer() dualrun.Dialer {
	return registerDelta(dualrun.BoundedParkPlan(dualrun.LifecycleCancelK))
}

// LifecycleCancelDriftedDialer is the drifted end for the cancel/deadline negative
// gate: it sends exactly k frames then completes cleanly (io.EOF), swallowing the
// client's cancel instead of surfacing the context-cancellation terminal. Run it as
// the "fake" end against LifecycleCancelHonestRealDialer to prove the cancel +
// deadline scenarios bite (the divergence is on terminal_status: OK vs Canceled, a
// deterministic fact that does not depend on a post-cancel framing race).
func LifecycleCancelDriftedDialer() dualrun.Dialer {
	return registerDelta(dualrun.CancelSwallowingPlan(dualrun.LifecycleCancelK))
}

// LifecycleSlowHonestRealDialer / LifecycleSlowHonestFakeDialer are the matched
// honest pair StreamingBackPressureSuite runs real-vs-fake: both serve the identical
// eager-complete ExportDiskDelta stream, so the slow-consumer scenario is green
// real-vs-fake.
func LifecycleSlowHonestRealDialer() dualrun.Dialer {
	return registerDelta(dualrun.EagerCompletePlan(dualrun.LifecycleSlowFrames))
}

func LifecycleSlowHonestFakeDialer() dualrun.Dialer {
	return registerDelta(dualrun.EagerCompletePlan(dualrun.LifecycleSlowFrames))
}

// LifecycleSlowDriftedDialer is the drifted end for the slow-consumer negative gate:
// it drops a mid-tail frame so the delivered sequence is no longer gap-free. Run it
// as the "fake" end against LifecycleSlowHonestRealDialer to prove the slow-consumer
// scenario bites.
func LifecycleSlowDriftedDialer() dualrun.Dialer {
	return registerDelta(dualrun.DroppingPlan(dualrun.LifecycleSlowFrames, dualrun.LifecycleDropFrame))
}

// LifecycleSlowReorderDriftedDialer is the reorder sibling of
// LifecycleSlowDriftedDialer — the second drifted end for the slow-consumer negative
// gate: it delivers the SAME total set of frames but PERMUTES their order (frame
// swap+1 before swap). Run it as the "fake" end against LifecycleSlowHonestRealDialer
// to prove the slow-consumer scenario bites via drained_in_order=false with
// frames_total UNCHANGED — isolating the in-order observation from the count
// observation. lifecycleReorderFrame < lifecycleSlowFrames, so the transposed pair
// stays in range and no frame is dropped or duplicated.
func LifecycleSlowReorderDriftedDialer() dualrun.Dialer {
	return registerDelta(dualrun.ReorderingPlan(dualrun.LifecycleSlowFrames, dualrun.LifecycleReorderFrame))
}

// LifecycleSlowDuplicateDriftedDialer is the count-over sibling of
// LifecycleSlowDriftedDialer (count-short) and LifecycleSlowReorderDriftedDialer
// (count-correct) — the third drifted end for the slow-consumer negative gate: it
// delivers every frame in order but RE-EMITS one mid-tail frame, so the delivered
// count is expected+1. Run it as the "fake" end against LifecycleSlowHonestRealDialer
// to prove the slow-consumer scenario bites via frames_total OVER by one
// (frames_total_matches_expected=false) — the count-over corner of the exactly-once
// contract. lifecycleDuplicateFrame < lifecycleSlowFrames, so the re-emitted frame is
// strictly mid-tail.
func LifecycleSlowDuplicateDriftedDialer() dualrun.Dialer {
	return registerDelta(dualrun.DuplicatingPlan(dualrun.LifecycleSlowFrames, dualrun.LifecycleDuplicateFrame))
}

// --- synthetic frame derivation (D50) ----------------------------------------

// lifecycleFrame builds the synthetic delta frame for a 1-based index: Offset is the
// consecutive 1-based sequence (the SlowConsumer in-order key) and Data is
// deterministic synthetic padding sized to overflow the flow-control window (D50).
func lifecycleFrame(i int) *hypervisorv1.ExportDiskDeltaResponse {
	return &hypervisorv1.ExportDiskDeltaResponse{
		Offset: uint64(i),
		Data:   lifecyclePad(i),
	}
}

// lifecyclePad returns deterministic synthetic padding of lifecycleFrameBytes,
// salted by index so consecutive frames differ. Synthetic, deterministic (D50).
func lifecyclePad(i int) []byte {
	b := make([]byte, lifecycleFrameBytes)
	for j := range b {
		b[j] = byte('a' + (i+j)%26)
	}
	return b
}

func invalidSession() error {
	return status.Error(codes.InvalidArgument, "ExportDiskDeltaRequest.session_uuid is required")
}
