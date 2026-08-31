// SPDX-License-Identifier: Apache-2.0

package boundarypolicystream

import (
	"context"
	"crypto/sha256"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// --- WatchPolicies server-streaming lifecycle hardening, folded onto the shared affordance ---
//
// WatchPolicies is genuine server-streaming: a host agent drains it
// Recv-until-io.EOF (D36/D72). Suite()'s seeded-log scenarios prove the catch-up
// CONTENT shape (monotonic, gap-free, resumable, the snapshot identity, the ack
// round-trip). They do NOT exercise the STREAM LIFECYCLE — what happens when the
// host-agent consumer cancels mid-stream, lets its deadline expire, or reads slowly
// (they drain a tiny finite log that fits inside the pipe + window, so they never
// back-pressure and a mid-stream cancel just races the server to EOF). This file
// wires that lifecycle through the SHARED dualrun streaming affordance
// (dualrun.StreamOpener + CancelAfterFrames / DeadlineAfterFrames / SlowConsumer),
// consuming ONLY the affordance's existing exported API — exactly like the
// hypervisor and orchestrator-session seams. It REPLACES the bespoke
// reserved-cursor probe machinery (recvKMonotonicGapFree / drainAfterCancel that
// used to live in suite.go, and the lazy streamBackPressureProbe in refimpl.go):
// every seam now shares one tested driver.
//
// The lifecycle is driven against matched pairs of honest streaming ends keyed on
// the REAL WatchPolicies method and REAL boundary.v1 wire types — one stands in for
// the real policy-stream server, one for the generated fake — so every lifecycle
// scenario is green real-vs-fake; a drifted end DIVERGES (the bite). Two honest end
// SHAPES are needed because the cancel/deadline scenarios and the slow-consumer
// scenario impose different determinism requirements (this mirrors the affordance
// self-test, which pairs a bounded-park responder with the cancel scenarios and an
// eager-complete responder with the slow-consumer one):
//
//   - cancel/deadline: the consumer reads exactly k frames, cancels, then asserts
//     ZERO frames after and a context-cancellation terminal. For that to be a
//     DETERMINISTIC real-vs-fake fact (not a cross-transport buffering race), the
//     honest producer must deliver exactly k frames then PARK awaiting the cancel —
//     no (k+1)th frame in flight to race the teardown. This is also the natural
//     model of a live policy subscription: it replays the k pending snapshots then
//     parks awaiting the next policy_log append. -> boundedParkStream.
//   - slow-consumer: the consumer stalls, then drains the WHOLE snapshot tail to a
//     clean EOF. The honest producer streams every frame, in order, completing —
//     flow control holds it back under the stall, it does not drop/reorder.
//     -> eagerCompleteStream.
//
// Synthetic snapshots only (D50). WatchPolicies is the policy-stream seam's only
// server-streaming RPC (AckPolicy is UNARY and is excluded from this hardening).

const (
	// lifecycleFrameBytes sizes each synthetic snapshot's document so a small number
	// of frames overflows the HTTP/2 stream flow-control window (~64 KiB) and the
	// in-process pipe buffer — that overflow is what forces a faithful producer to
	// BLOCK on Send under a slow/cancelled consumer (back-pressure) rather than
	// racing the whole stream ahead. 16 KiB/frame: a handful overflow. Synthetic
	// deterministic padding (D50).
	lifecycleFrameBytes = 16 << 10
	// lifecycleCancelK is the number of frames the consumer reads before cancelling
	// (or letting its deadline expire). The bounded-park honest end sends exactly
	// this many then parks, so the cancel observation is race-free.
	lifecycleCancelK = 3
	// lifecycleSlowFrames is the total frame count the slow-consumer scenario drains
	// to a clean EOF; large enough that, under the stall, a faithful producer is held
	// by flow control rather than racing ahead, yet small enough to stay fast.
	lifecycleSlowFrames = 24
	// lifecycleStall is how long the slow-consumer scenario holds off reading so the
	// producer must apply back-pressure (block on Send) rather than race ahead.
	lifecycleStall = 25 * time.Millisecond
	// lifecycleDropFrame is the mid-tail frame the dropping drift skips so the
	// delivered slow-consumer sequence is no longer gap-free (the integrity bite).
	lifecycleDropFrame = lifecycleSlowFrames / 2
)

// openWatchPoliciesLifecycle is the dualrun.StreamOpener for the WatchPolicies
// lifecycle: it opens the server-streaming RPC against the dialed conn, threading
// the affordance's cancellable ctx into the call so a cancel/deadline propagates to
// the server. The lifecycle dialers serve their synthetic frame run regardless of
// from_seq, so a plain from-zero open drives them. This is the per-RPC opener the
// affordance's CancelAfterFrames / DeadlineAfterFrames / SlowConsumer scenarios
// drive.
func openWatchPoliciesLifecycle(ctx context.Context, conn *grpc.ClientConn) (grpc.ServerStreamingClient[boundaryv1.WatchPoliciesResponse], error) {
	cl := boundaryv1.NewPolicyStreamServiceClient(conn)
	return cl.WatchPolicies(ctx, &boundaryv1.WatchPoliciesRequest{FromSeq: 0})
}

// snapshotSeqOf extracts the per-frame monotonic key the SlowConsumer scenario uses
// for its in-order / exactly-once check — the PolicySnapshot.seq the contract
// stamps on every frame. The lifecycle frames carry consecutive seqs (frame i has
// Seq i), so a faithful in-order delivery reads 1,2,3,… — a stall that reorders or
// drops diverges.
func snapshotSeqOf(r *boundaryv1.WatchPoliciesResponse) uint64 { return r.GetSnapshot().GetSeq() }

// StreamingCancelSuite hardens the WatchPolicies cancel + deadline lifecycle: a
// host-agent consumer that cancels (or whose deadline expires) after k frames must
// see the server STOP — zero frames after, a context-cancellation terminal. Run it
// real-vs-fake (LifecycleCancelHonestRealDialer / LifecycleCancelHonestFakeDialer).
func StreamingCancelSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam: "boundary<->orchestrator(WatchPolicies-cancel)",
		Scenarios: []dualrun.Scenario{
			dualrun.CancelAfterFrames("watch-policies/cancel-after-frames-stops-stream", lifecycleCancelK, openWatchPoliciesLifecycle),
			dualrun.DeadlineAfterFrames("watch-policies/deadline-after-frames-stops-stream", lifecycleCancelK, openWatchPoliciesLifecycle),
		},
	}
}

// StreamingBackPressureSuite hardens the WatchPolicies slow-consumer back-pressure
// lifecycle: a stalled host agent must still receive every snapshot, in order,
// exactly once, to a clean EOF — the producer is held by flow control, it does not
// drop or reorder. Run it real-vs-fake (LifecycleSlowHonestRealDialer /
// LifecycleSlowHonestFakeDialer).
func StreamingBackPressureSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam: "boundary<->orchestrator(WatchPolicies-backpressure)",
		Scenarios: []dualrun.Scenario{
			dualrun.SlowConsumer("watch-policies/slow-consumer-honors-flow-control", lifecycleSlowFrames, lifecycleStall, openWatchPoliciesLifecycle, snapshotSeqOf),
		},
	}
}

// --- honest + drifted streaming ends -----------------------------------------

// boundedParkStream is the contract-faithful cancel/deadline honest end: it sends
// exactly k large snapshots then PARKS on ctx.Done(), returning the
// context-cancellation status. Because there is no (k+1)th frame to race, the
// cancel/deadline scenarios observe exactly k frames before and ZERO after,
// deterministically and identically on both ends. It models a live policy
// subscription that has replayed its k pending snapshots and is parked awaiting the
// next policy_log append (or the consumer walking away).
type boundedParkStream struct {
	boundaryv1.UnimplementedPolicyStreamServiceServer
	k int
}

func (s *boundedParkStream) WatchPolicies(_ *boundaryv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[boundaryv1.WatchPoliciesResponse]) error {
	ctx := stream.Context()
	for i := 1; i <= s.k; i++ {
		if ctx.Err() != nil {
			return status.FromContextError(ctx.Err()).Err()
		}
		if err := stream.Send(lifecycleSnapshotFrame(i)); err != nil {
			return err
		}
	}
	// Drained: park until the consumer walks away (cancel / deadline).
	<-ctx.Done()
	return status.FromContextError(ctx.Err()).Err()
}

// cancelSwallowingStream is the cancel/deadline VIOLATION: it sends exactly k frames
// then COMPLETES CLEANLY (returns nil → io.EOF), never honouring the client's
// cancel/deadline — it "drains to completion ignoring cancel". A faithful end stays
// parked and surfaces the context-cancellation terminal; this drift's stream is
// already done when the client cancels, so the client observes a clean OK terminal
// instead of Canceled. The divergence is on terminal_status (OK vs the contracted
// context-cancellation), a DETERMINISTIC fact — it does not depend on how many
// post-cancel frames the transport happened to buffer (that count races; the
// terminal does not). honest-vs-cancel-swallowing DIVERGES on every cancel/deadline
// scenario — the bite.
type cancelSwallowingStream struct {
	boundaryv1.UnimplementedPolicyStreamServiceServer
	k int
}

func (s *cancelSwallowingStream) WatchPolicies(_ *boundaryv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[boundaryv1.WatchPoliciesResponse]) error {
	for i := 1; i <= s.k; i++ {
		if err := stream.Send(lifecycleSnapshotFrame(i)); err != nil {
			return err
		}
	}
	return nil // DRIFT: complete cleanly, swallowing the consumer's cancel.
}

// eagerCompleteStream is the contract-faithful slow-consumer honest end: it streams
// all `total` large snapshots in order to a clean EOF. Under the slow consumer the
// bounded in-process pipe holds it back on Send (back-pressure) rather than racing
// ahead; it never drops or reorders. The slow-consumer scenario reads every frame,
// in order, exactly once, completing — green real-vs-fake.
type eagerCompleteStream struct {
	boundaryv1.UnimplementedPolicyStreamServiceServer
	total int
}

func (s *eagerCompleteStream) WatchPolicies(_ *boundaryv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[boundaryv1.WatchPoliciesResponse]) error {
	ctx := stream.Context()
	for i := 1; i <= s.total; i++ {
		if ctx.Err() != nil {
			return status.FromContextError(ctx.Err()).Err()
		}
		if err := stream.Send(lifecycleSnapshotFrame(i)); err != nil {
			return err
		}
	}
	return nil
}

// droppingStream is the slow-consumer VIOLATION: it SKIPS a mid-tail frame, so the
// delivered sequence is no longer in-order/gap-free and the frame count is short.
// honest-vs-dropping DIVERGES on the slow-consumer scenario's drained_in_order /
// frames_total observation — the back-pressure-integrity bite, deterministic and
// cancel-free.
type droppingStream struct {
	boundaryv1.UnimplementedPolicyStreamServiceServer
	total int
	drop  int
}

func (s *droppingStream) WatchPolicies(_ *boundaryv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[boundaryv1.WatchPoliciesResponse]) error {
	ctx := stream.Context()
	for i := 1; i <= s.total; i++ {
		if i == s.drop {
			continue // DRIFT: skip a frame — the delivered tail is no longer gap-free.
		}
		if ctx.Err() != nil {
			return status.FromContextError(ctx.Err()).Err()
		}
		if err := stream.Send(lifecycleSnapshotFrame(i)); err != nil {
			return err
		}
	}
	return nil
}

// --- lifecycle dialers -------------------------------------------------------

func registerStream(srv boundaryv1.PolicyStreamServiceServer) dualrun.Dialer {
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		boundaryv1.RegisterPolicyStreamServiceServer(s, srv)
	})
}

// LifecycleCancelHonestRealDialer / LifecycleCancelHonestFakeDialer are the matched
// honest pair StreamingCancelSuite runs real-vs-fake: both serve the identical
// bounded-park WatchPolicies stream (one stands in for the real policy-stream
// server, one for the generated fake), so the cancel + deadline scenarios are green
// real-vs-fake.
func LifecycleCancelHonestRealDialer() dualrun.Dialer {
	return registerStream(&boundedParkStream{k: lifecycleCancelK})
}

func LifecycleCancelHonestFakeDialer() dualrun.Dialer {
	return registerStream(&boundedParkStream{k: lifecycleCancelK})
}

// LifecycleCancelDriftedDialer is the drifted end for the cancel/deadline negative
// gate: it sends exactly k frames then completes cleanly (io.EOF), swallowing the
// client's cancel instead of surfacing the context-cancellation terminal. Run it as
// the "fake" end against LifecycleCancelHonestRealDialer to prove the cancel +
// deadline scenarios bite (the divergence is on terminal_status: OK vs Canceled, a
// deterministic fact that does not depend on a post-cancel framing race).
func LifecycleCancelDriftedDialer() dualrun.Dialer {
	return registerStream(&cancelSwallowingStream{k: lifecycleCancelK})
}

// LifecycleSlowHonestRealDialer / LifecycleSlowHonestFakeDialer are the matched
// honest pair StreamingBackPressureSuite runs real-vs-fake: both serve the identical
// eager-complete WatchPolicies stream, so the slow-consumer scenario is green
// real-vs-fake.
func LifecycleSlowHonestRealDialer() dualrun.Dialer {
	return registerStream(&eagerCompleteStream{total: lifecycleSlowFrames})
}

func LifecycleSlowHonestFakeDialer() dualrun.Dialer {
	return registerStream(&eagerCompleteStream{total: lifecycleSlowFrames})
}

// LifecycleSlowDriftedDialer is the drifted end for the slow-consumer negative gate:
// it drops a mid-tail frame so the delivered sequence is no longer gap-free. Run it
// as the "fake" end against LifecycleSlowHonestRealDialer to prove the slow-consumer
// scenario bites.
func LifecycleSlowDriftedDialer() dualrun.Dialer {
	return registerStream(&droppingStream{total: lifecycleSlowFrames, drop: lifecycleDropFrame})
}

// --- synthetic frame derivation (D50) ----------------------------------------

// lifecycleSnapshotFrame builds the synthetic WatchPolicies frame for a 1-based
// index: Seq is the consecutive 1-based sequence (the SlowConsumer in-order key),
// ContentHash is the SHA-256 over the padded document, and Document is deterministic
// synthetic padding sized to overflow the flow-control window (D50). It is a
// well-formed PolicySnapshot mirroring the seam's frozen (seq, content_hash,
// document) identity.
func lifecycleSnapshotFrame(i int) *boundaryv1.WatchPoliciesResponse {
	doc := lifecyclePad(i)
	hash := sha256.Sum256(doc)
	return &boundaryv1.WatchPoliciesResponse{
		Snapshot: &boundaryv1.PolicySnapshot{
			Seq:         uint64(i),
			ContentHash: hash[:],
			Document:    doc,
		},
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
