// SPDX-License-Identifier: Apache-2.0

package orchestratorpolicy

import (
	"context"
	"crypto/sha256"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// --- WatchPolicies server-streaming lifecycle hardening, folded onto the shared affordance ---
//
// WatchPolicies is genuine server-streaming: the host agent opens ONE subscription
// per host (D72) and drains snapshot frames Recv-until-io.EOF. Suite()'s scenarios
// prove the catch-up CONTENT shape (monotonic, gap-free, resumable, the snapshot
// identity). They do NOT exercise the STREAM LIFECYCLE — what happens when the host
// agent cancels mid-stream, lets its deadline expire, or reads slowly. This file
// wires that lifecycle through the SHARED dualrun streaming affordance
// (dualrun.StreamOpener + CancelAfterFrames / DeadlineAfterFrames / SlowConsumer),
// consuming ONLY the affordance's existing exported API — exactly like the
// hypervisor and orchestrator-session seams. It REPLACES the bespoke
// seed-a-large-tail driving (readPrefix / streamTornDown / drainFullOrdered /
// seedBackPressureTail) this file used to hold: every seam now shares one tested
// driver.
//
// The lifecycle is driven against matched pairs of honest streaming ends keyed on
// the REAL WatchPolicies method and REAL orchestrator.v1 wire types — one stands in
// for the real control plane, one for the generated fake — so every lifecycle
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
//     model of a live host subscription: it replays the k pending snapshots then
//     parks awaiting the next policy_log append. -> boundedParkWatch.
//   - slow-consumer: the consumer stalls, then drains the WHOLE snapshot tail to a
//     clean EOF. The honest producer streams every frame, in order, completing —
//     flow control holds it back under the stall, it does not drop/reorder.
//     -> eagerCompleteWatch.
//
// Synthetic snapshots only (D50); the watch is keyed on synthHostID (EXACTLY ONE
// subscriber per host, D72). WatchPolicies is the seam's only server-streaming RPC.

const (
	// lifecycleFrameBytes sizes each synthetic snapshot's document so a small number
	// of frames overflows the HTTP/2 stream flow-control window (~64 KiB) and the
	// in-process pipe buffer — that overflow forces a faithful producer to BLOCK on
	// Send under a slow/cancelled consumer (back-pressure) rather than racing the
	// whole stream ahead. 16 KiB/frame: a handful overflow. Synthetic padding (D50).
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
// the server. It is keyed on synthHostID (EXACTLY ONE subscriber per host, D72) so
// the lifecycle ends' host_id validation matches the seam contract. This is the
// per-RPC opener the affordance's CancelAfterFrames / DeadlineAfterFrames /
// SlowConsumer scenarios drive.
func openWatchPoliciesLifecycle(ctx context.Context, conn *grpc.ClientConn) (grpc.ServerStreamingClient[orchestratorv1.WatchPoliciesResponse], error) {
	cl := orchestratorv1.NewPolicyServiceClient(conn)
	return cl.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{FromSeq: 0, HostId: synthHostID})
}

// snapshotSeqOf extracts the per-frame monotonic key the SlowConsumer scenario uses
// for its in-order / exactly-once check — the PolicySnapshot.seq the contract stamps
// on every frame. The lifecycle frames carry consecutive seqs (frame i has Seq i),
// so a faithful in-order delivery reads 1,2,3,… — a stall that reorders or drops
// diverges.
func snapshotSeqOf(r *orchestratorv1.WatchPoliciesResponse) uint64 { return r.GetSnapshot().GetSeq() }

// StreamingCancelSuite hardens the WatchPolicies cancel + deadline lifecycle: a host
// agent that cancels (or whose deadline expires) after k frames must see the server
// STOP — zero frames after, a context-cancellation terminal. Run it real-vs-fake
// (LifecycleCancelHonestRealDialer / LifecycleCancelHonestFakeDialer).
func StreamingCancelSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam: "orchestrator<->hostagent(WatchPolicies-cancel)",
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
		Seam: "orchestrator<->hostagent(WatchPolicies-backpressure)",
		Scenarios: []dualrun.Scenario{
			dualrun.SlowConsumer("watch-policies/slow-consumer-honors-flow-control", lifecycleSlowFrames, lifecycleStall, openWatchPoliciesLifecycle, snapshotSeqOf),
		},
	}
}

// --- honest + drifted streaming ends -----------------------------------------

// boundedParkWatch is the contract-faithful cancel/deadline honest end: it sends
// exactly k large snapshots then PARKS on ctx.Done(), returning the
// context-cancellation status. Because there is no (k+1)th frame to race, the
// cancel/deadline scenarios observe exactly k frames before and ZERO after,
// deterministically and identically on both ends. It models a live host subscription
// that has replayed its k pending snapshots and is parked awaiting the next
// policy_log append (or the consumer walking away). It mirrors the seam's host_id
// validation (D72).
type boundedParkWatch struct {
	orchestratorv1.UnimplementedPolicyServiceServer
	k int
}

func (s *boundedParkWatch) WatchPolicies(req *orchestratorv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[orchestratorv1.WatchPoliciesResponse]) error {
	if req.GetHostId() == "" {
		return missingHostID()
	}
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

// cancelSwallowingWatch is the cancel/deadline VIOLATION: it sends exactly k frames
// then COMPLETES CLEANLY (returns nil → io.EOF), never honouring the client's
// cancel/deadline — it "drains to completion ignoring cancel". A faithful end stays
// parked and surfaces the context-cancellation terminal; this drift's stream is
// already done when the client cancels, so the client observes a clean OK terminal
// instead of Canceled. The divergence is on terminal_status (OK vs the contracted
// context-cancellation), a DETERMINISTIC fact — it does not depend on how many
// post-cancel frames the transport happened to buffer (that count races; the terminal
// does not). honest-vs-cancel-swallowing DIVERGES on every cancel/deadline scenario.
type cancelSwallowingWatch struct {
	orchestratorv1.UnimplementedPolicyServiceServer
	k int
}

func (s *cancelSwallowingWatch) WatchPolicies(req *orchestratorv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[orchestratorv1.WatchPoliciesResponse]) error {
	if req.GetHostId() == "" {
		return missingHostID()
	}
	for i := 1; i <= s.k; i++ {
		if err := stream.Send(lifecycleSnapshotFrame(i)); err != nil {
			return err
		}
	}
	return nil // DRIFT: complete cleanly, swallowing the consumer's cancel.
}

// eagerCompleteWatch is the contract-faithful slow-consumer honest end: it streams
// all `total` large snapshots in order to a clean EOF. Under the slow consumer the
// bounded in-process pipe holds it back on Send (back-pressure) rather than racing
// ahead; it never drops or reorders. The slow-consumer scenario reads every frame,
// in order, exactly once, completing — green real-vs-fake.
type eagerCompleteWatch struct {
	orchestratorv1.UnimplementedPolicyServiceServer
	total int
}

func (s *eagerCompleteWatch) WatchPolicies(req *orchestratorv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[orchestratorv1.WatchPoliciesResponse]) error {
	if req.GetHostId() == "" {
		return missingHostID()
	}
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

// droppingWatch is the slow-consumer VIOLATION: it SKIPS a mid-tail frame, so the
// delivered sequence is no longer in-order/gap-free and the frame count is short.
// honest-vs-dropping DIVERGES on the slow-consumer scenario's drained_in_order /
// frames_total observation — the back-pressure-integrity bite, deterministic and
// cancel-free.
type droppingWatch struct {
	orchestratorv1.UnimplementedPolicyServiceServer
	total int
	drop  int
}

func (s *droppingWatch) WatchPolicies(req *orchestratorv1.WatchPoliciesRequest, stream grpc.ServerStreamingServer[orchestratorv1.WatchPoliciesResponse]) error {
	if req.GetHostId() == "" {
		return missingHostID()
	}
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

func registerWatch(srv orchestratorv1.PolicyServiceServer) dualrun.Dialer {
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		orchestratorv1.RegisterPolicyServiceServer(s, srv)
	})
}

// LifecycleCancelHonestRealDialer / LifecycleCancelHonestFakeDialer are the matched
// honest pair StreamingCancelSuite runs real-vs-fake: both serve the identical
// bounded-park WatchPolicies stream (one stands in for the real control plane, one
// for the generated fake), so the cancel + deadline scenarios are green real-vs-fake.
func LifecycleCancelHonestRealDialer() dualrun.Dialer {
	return registerWatch(&boundedParkWatch{k: lifecycleCancelK})
}

func LifecycleCancelHonestFakeDialer() dualrun.Dialer {
	return registerWatch(&boundedParkWatch{k: lifecycleCancelK})
}

// LifecycleCancelDriftedDialer is the drifted end for the cancel/deadline negative
// gate: it sends exactly k frames then completes cleanly (io.EOF), swallowing the
// client's cancel instead of surfacing the context-cancellation terminal. Run it as
// the "fake" end against LifecycleCancelHonestRealDialer to prove the cancel +
// deadline scenarios bite (the divergence is on terminal_status: OK vs Canceled).
func LifecycleCancelDriftedDialer() dualrun.Dialer {
	return registerWatch(&cancelSwallowingWatch{k: lifecycleCancelK})
}

// LifecycleSlowHonestRealDialer / LifecycleSlowHonestFakeDialer are the matched
// honest pair StreamingBackPressureSuite runs real-vs-fake: both serve the identical
// eager-complete WatchPolicies stream, so the slow-consumer scenario is green
// real-vs-fake.
func LifecycleSlowHonestRealDialer() dualrun.Dialer {
	return registerWatch(&eagerCompleteWatch{total: lifecycleSlowFrames})
}

func LifecycleSlowHonestFakeDialer() dualrun.Dialer {
	return registerWatch(&eagerCompleteWatch{total: lifecycleSlowFrames})
}

// LifecycleSlowDriftedDialer is the drifted end for the slow-consumer negative gate:
// it drops a mid-tail frame so the delivered sequence is no longer gap-free. Run it
// as the "fake" end against LifecycleSlowHonestRealDialer to prove the slow-consumer
// scenario bites.
func LifecycleSlowDriftedDialer() dualrun.Dialer {
	return registerWatch(&droppingWatch{total: lifecycleSlowFrames, drop: lifecycleDropFrame})
}

// --- synthetic frame derivation (D50) ----------------------------------------

// lifecycleSnapshotFrame builds the synthetic WatchPolicies frame for a 1-based
// index: Seq is the consecutive 1-based sequence (the SlowConsumer in-order key),
// ContentHash is the SHA-256 over the padded document, and Document is deterministic
// synthetic padding sized to overflow the flow-control window (D50). It is a
// well-formed PolicySnapshot mirroring the seam's frozen (seq, content_hash,
// document) identity.
func lifecycleSnapshotFrame(i int) *orchestratorv1.WatchPoliciesResponse {
	doc := lifecyclePad(i)
	hash := sha256.Sum256(doc)
	return &orchestratorv1.WatchPoliciesResponse{
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

func missingHostID() error {
	return status.Error(codes.InvalidArgument, "WatchPoliciesRequest.host_id is required (EXACTLY ONE subscriber per host, D72)")
}
