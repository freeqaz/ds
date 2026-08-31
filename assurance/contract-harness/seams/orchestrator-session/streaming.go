// SPDX-License-Identifier: Apache-2.0

package orchestratorsession

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// --- WatchSession server-streaming lifecycle hardening -----------------------
//
// WatchSession is genuine server-streaming: the D18 session-event fan-out leg
// streams attach.v1.SessionEvent frames (refimpl.WatchSession loops stream.Send over
// the event leg; the generated fake's responder loops stream.Send over its eager
// slice). Suite()'s watch-session scenarios prove the event CONTENT shape (per-event
// seq / type / state, the from_seq replay cursor). They do NOT exercise the STREAM
// LIFECYCLE — what happens when the console consumer cancels mid-stream, lets its
// deadline expire, or reads slowly (the watch is a long-lived subscription, the most
// streaming-shaped seam of the two). This file wires that lifecycle through the
// SHARED dualrun streaming affordance (dualrun.StreamOpener + CancelAfterFrames /
// DeadlineAfterFrames / SlowConsumer), consuming ONLY the affordance's existing
// exported API.
//
// The lifecycle is driven against matched pairs of honest streaming ends keyed on
// the REAL WatchSession method and REAL orchestrator.v1 / attach.v1 wire types — one
// stands in for the real control plane, one for the generated fake — so every
// lifecycle scenario is green real-vs-fake; a drifted end DIVERGES (the bite). Two
// honest end SHAPES are needed because the cancel/deadline scenarios and the
// slow-consumer scenario impose different determinism requirements (this mirrors the
// affordance self-test, which pairs a bounded-park responder with the cancel
// scenarios and an eager-complete responder with the slow-consumer one):
//
//   - cancel/deadline: the consumer reads exactly k events, cancels, then asserts
//     ZERO events after and a context-cancellation terminal. For that to be a
//     DETERMINISTIC real-vs-fake fact (not a cross-transport buffering race), the
//     honest producer must deliver exactly k events then PARK awaiting the cancel —
//     no (k+1)th event in flight to race the teardown. This is also the natural
//     model of a live watch: it replays the k pending events then parks awaiting the
//     next lifecycle transition. -> dualrun.BoundedParkPlan.
//   - slow-consumer: the consumer stalls, then drains the WHOLE event tail to a clean
//     EOF. The honest producer streams every event, in order, completing — flow
//     control holds it back under the stall, it does not drop/reorder.
//     -> dualrun.EagerCompletePlan.
//
// Both shapes are the SAME watchStreamSession parameterized by a different
// dualrun.BackPressurePlan; the producer logic is single-sourced in
// dualrun.RunBackPressureStream (this seam only adapts it to the WatchSession RPC
// signature + event builder).
//
// Synthetic events only (D50). NOTE: identity-digestfeed (DigestPublish /
// DigestRevoke) is UNARY — no server-streaming verb — and is explicitly EXCLUDED
// from this hardening. WatchSession is the orchestrator-session seam's only server-
// streaming RPC.

// lifecycleEventBytes sizes each synthetic event so a small number of frames
// overflows the HTTP/2 stream flow-control window (~64 KiB) and the in-process pipe
// buffer — that overflow is what forces a faithful producer to BLOCK on Send under a
// slow/cancelled consumer (back-pressure) rather than racing the whole stream ahead.
// The padding rides SessionEvent.source (a []string the contract already carries) so
// the frame stays a well-formed SessionEvent. This rides a seam-specific proto field,
// so it stays local; the index plan + frame COUNTS are single-sourced in the shared
// dualrun back-pressure fixture (dualrun.Lifecycle* / dualrun.*Plan). Synthetic
// deterministic padding (D50).
const lifecycleEventBytes = 16 << 10

// openWatchSession is the dualrun.StreamOpener for WatchSession: it opens the
// server-streaming RPC against the dialed conn, threading the affordance's
// cancellable ctx into the call so a cancel/deadline propagates to the server. It is
// keyed on the seeded lifecycle session the lifecycle dialers stream for. This is the
// per-RPC opener the affordance's CancelAfterFrames / DeadlineAfterFrames /
// SlowConsumer scenarios drive.
func openWatchSession(ctx context.Context, conn *grpc.ClientConn) (grpc.ServerStreamingClient[orchestratorv1.WatchSessionResponse], error) {
	cl := orchestratorv1.NewSessionServiceClient(conn)
	return cl.WatchSession(ctx, &orchestratorv1.WatchSessionRequest{SessionUuid: synthSeededA})
}

// eventSeqOf extracts the per-event monotonic key the SlowConsumer scenario uses for
// its in-order / exactly-once check — the attach.v1.SessionEvent.seq the contract
// stamps on every event (D79). The lifecycle events carry consecutive seqs (event i
// has Seq i), so a faithful in-order delivery reads 1,2,3,… — a stall that reorders
// or drops diverges.
func eventSeqOf(r *orchestratorv1.WatchSessionResponse) uint64 { return r.GetEvent().GetSeq() }

// StreamingCancelSuite hardens the WatchSession cancel + deadline lifecycle: a
// console consumer that cancels (or whose deadline expires) after k events must see
// the server STOP — zero events after, a context-cancellation terminal. Run it
// real-vs-fake (LifecycleCancelHonestRealDialer / LifecycleCancelHonestFakeDialer).
func StreamingCancelSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam: "client/console<->orchestrator(WatchSession-cancel)",
		Scenarios: []dualrun.Scenario{
			dualrun.CancelAfterFrames("watch-session/cancel-after-frames-stops-stream", dualrun.LifecycleCancelK, openWatchSession),
			dualrun.DeadlineAfterFrames("watch-session/deadline-after-frames-stops-stream", dualrun.LifecycleCancelK, openWatchSession),
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

// StreamingBackPressureSuite hardens the WatchSession slow-consumer back-pressure
// lifecycle: a stalled console must still receive every event, in order, exactly
// once, to a clean EOF — the producer is held by flow control, it does not drop or
// reorder. Run it real-vs-fake (LifecycleSlowHonestRealDialer /
// LifecycleSlowHonestFakeDialer). The observation-matrix comment above maps each
// drift corner to the observation key it trips.
func StreamingBackPressureSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam: "client/console<->orchestrator(WatchSession-backpressure)",
		Scenarios: []dualrun.Scenario{
			dualrun.SlowConsumer("watch-session/slow-consumer-honors-flow-control", dualrun.LifecycleSlowFrames, dualrun.LifecycleStall, openWatchSession, eventSeqOf),
		},
	}
}

// --- honest + drifted streaming ends -----------------------------------------

// sessionStreamBase embeds the unimplemented base — shared boilerplate for the
// lifecycle ends, none of which the lifecycle suites call beyond WatchSession.
type sessionStreamBase struct {
	orchestratorv1.UnimplementedSessionServiceServer
}

// watchStreamSession is the ONE WatchSession lifecycle end: it runs a
// dualrun.BackPressurePlan (which encodes the honest/drifted variant — bounded-park,
// cancel-swallow, eager-complete, drop, reorder, duplicate) through the shared
// dualrun.RunBackPressureStream driver, threading the seam's WatchSession event
// builder (keyed on the request's session uuid). The producer LOGIC (which events, in
// what order, park-or-complete) lives once in the shared fixture; this method only
// adapts it to the orchestrator.v1 RPC signature.
type watchStreamSession struct {
	sessionStreamBase
	plan dualrun.BackPressurePlan
}

func (s *watchStreamSession) WatchSession(req *orchestratorv1.WatchSessionRequest, stream grpc.ServerStreamingServer[orchestratorv1.WatchSessionResponse]) error {
	if req.GetSessionUuid() == "" {
		return invalidWatch()
	}
	uuid := req.GetSessionUuid()
	return dualrun.RunBackPressureStream(stream.Context(), s.plan, func(i int) error {
		return stream.Send(lifecycleEvent(uuid, i))
	})
}

// --- lifecycle dialers -------------------------------------------------------

func registerSession(plan dualrun.BackPressurePlan) dualrun.Dialer {
	srv := &watchStreamSession{plan: plan}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		orchestratorv1.RegisterSessionServiceServer(s, srv)
	})
}

// LifecycleCancelHonestRealDialer / LifecycleCancelHonestFakeDialer are the matched
// honest pair StreamingCancelSuite runs real-vs-fake: both serve the identical
// bounded-park WatchSession stream (one stands in for the real control plane, one for
// the generated fake), so the cancel + deadline scenarios are green real-vs-fake.
func LifecycleCancelHonestRealDialer() dualrun.Dialer {
	return registerSession(dualrun.BoundedParkPlan(dualrun.LifecycleCancelK))
}

func LifecycleCancelHonestFakeDialer() dualrun.Dialer {
	return registerSession(dualrun.BoundedParkPlan(dualrun.LifecycleCancelK))
}

// LifecycleCancelDriftedDialer is the drifted end for the cancel/deadline negative
// gate: it sends exactly k events then completes cleanly (io.EOF), swallowing the
// client's cancel instead of surfacing the context-cancellation terminal. Run it as
// the "fake" end against LifecycleCancelHonestRealDialer to prove the cancel +
// deadline scenarios bite (the divergence is on terminal_status: OK vs Canceled, a
// deterministic fact that does not depend on a post-cancel framing race).
func LifecycleCancelDriftedDialer() dualrun.Dialer {
	return registerSession(dualrun.CancelSwallowingPlan(dualrun.LifecycleCancelK))
}

// LifecycleSlowHonestRealDialer / LifecycleSlowHonestFakeDialer are the matched
// honest pair StreamingBackPressureSuite runs real-vs-fake: both serve the identical
// eager-complete WatchSession stream, so the slow-consumer scenario is green
// real-vs-fake.
func LifecycleSlowHonestRealDialer() dualrun.Dialer {
	return registerSession(dualrun.EagerCompletePlan(dualrun.LifecycleSlowFrames))
}

func LifecycleSlowHonestFakeDialer() dualrun.Dialer {
	return registerSession(dualrun.EagerCompletePlan(dualrun.LifecycleSlowFrames))
}

// LifecycleSlowDriftedDialer is the drifted end for the slow-consumer negative gate:
// it drops a mid-tail event so the delivered sequence is no longer gap-free. Run it
// as the "fake" end against LifecycleSlowHonestRealDialer to prove the slow-consumer
// scenario bites.
func LifecycleSlowDriftedDialer() dualrun.Dialer {
	return registerSession(dualrun.DroppingPlan(dualrun.LifecycleSlowFrames, dualrun.LifecycleDropFrame))
}

// LifecycleSlowReorderDriftedDialer is the reorder sibling of
// LifecycleSlowDriftedDialer — the second drifted end for the slow-consumer negative
// gate: it delivers the SAME total set of events but PERMUTES their order (event
// swap+1 before swap). Run it as the "fake" end against LifecycleSlowHonestRealDialer
// to prove the slow-consumer scenario bites via drained_in_order=false with
// frames_total UNCHANGED — isolating the in-order observation from the count
// observation. lifecycleReorderFrame < lifecycleSlowFrames, so the transposed pair
// stays in range and no event is dropped or duplicated.
func LifecycleSlowReorderDriftedDialer() dualrun.Dialer {
	return registerSession(dualrun.ReorderingPlan(dualrun.LifecycleSlowFrames, dualrun.LifecycleReorderFrame))
}

// LifecycleSlowDuplicateDriftedDialer is the count-over sibling of
// LifecycleSlowDriftedDialer (count-short) and LifecycleSlowReorderDriftedDialer
// (count-correct) — the third drifted end for the slow-consumer negative gate: it
// delivers every event in order but RE-EMITS one mid-tail event, so the delivered
// count is expected+1. Run it as the "fake" end against LifecycleSlowHonestRealDialer
// to prove the slow-consumer scenario bites via frames_total OVER by one
// (frames_total_matches_expected=false) — the count-over corner of the exactly-once
// contract. lifecycleDuplicateFrame < lifecycleSlowFrames, so the re-emitted event is
// strictly mid-tail.
func LifecycleSlowDuplicateDriftedDialer() dualrun.Dialer {
	return registerSession(dualrun.DuplicatingPlan(dualrun.LifecycleSlowFrames, dualrun.LifecycleDuplicateFrame))
}

// --- synthetic event derivation (D50) ----------------------------------------

// lifecycleEvent builds the synthetic WatchSession event for a 1-based index: Seq is
// the consecutive 1-based sequence (the SlowConsumer in-order key, the D79 per-event
// seq) and the event carries deterministic synthetic padding (on the source []string
// the contract already carries) sized to overflow the flow-control window (D50). It
// is a SESSION_STATE event, mirroring the seam's existing watchEvents shape.
func lifecycleEvent(uuid string, i int) *orchestratorv1.WatchSessionResponse {
	return &orchestratorv1.WatchSessionResponse{
		Event: &attachv1.SessionEvent{
			Seq:       uint64(i),
			SessionId: uuid,
			Type:      attachv1.EventType_EVENT_TYPE_SESSION_STATE,
			Source:    []string{lifecyclePad(i)},
			Payload: &attachv1.SessionEvent_SessionState{
				SessionState: &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_WORKING},
			},
		},
	}
}

// lifecyclePad returns a deterministic synthetic string of lifecycleEventBytes,
// salted by index so consecutive events differ. Synthetic, deterministic (D50).
func lifecyclePad(i int) string {
	var b strings.Builder
	b.Grow(lifecycleEventBytes)
	b.WriteString("ds-synthetic-watch-event-")
	for b.Len() < lifecycleEventBytes {
		b.WriteByte(byte('a' + (i+b.Len())%26))
	}
	return b.String()[:lifecycleEventBytes]
}

func invalidWatch() error {
	return status.Error(codes.InvalidArgument, "WatchSessionRequest.session_uuid is required")
}
