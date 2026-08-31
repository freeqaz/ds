// SPDX-License-Identifier: Apache-2.0

package dualrun

import (
	"context"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// streaming.go is the SHARED server-streaming contract-hardening affordance for
// the dual-run harness. A server-streaming seam (WatchPolicies, the
// boundary.v1 PolicyStreamService, ExportDiskDelta, …) is more than a slice of
// frames: it has cancellation and flow-control semantics the CONTRACT promises
// and a faithful fake must mirror exactly. A fake that models the stream as a
// slice-of-responses Sent eagerly can silently diverge from a real impl on the
// dimensions that matter under a misbehaving/disconnecting consumer:
//
//   - mid-stream cancellation — when the client cancels (or its deadline
//     fires), the server must STOP sending; the terminal status the client
//     observes is context-cancellation (codes.Canceled / DeadlineExceeded), and
//     NO frame is delivered to the client after the cancel point; and
//   - back-pressure — a slow consumer that does not Recv promptly must NOT let
//     the server buffer the whole stream ahead unboundedly; a bounded in-flight
//     window is the contracted flow-control behavior.
//
// These helpers turn those promises into dualrun.Scenarios: each drives the SAME
// server-streaming RPC (via a caller-supplied opener) and records the observed
// framing + terminal status into an Observation, so the dual-run forces the real
// impl and the fake to AGREE. A fake that keeps "sending" after cancel, or that
// hands the client every frame regardless of consumer speed, diverges and fails
// the seam — exactly the doc 06 §2.1 property, extended to streaming.
//
// The affordance is generic over the response frame type Res and self-contained:
// it depends only on grpc + the seam's own opener, never on a seam package.

// StreamOpener opens the server-streaming RPC under test against a dialed conn,
// returning the client stream to drain. The ctx is the cancellable context the
// affordance controls — the opener MUST thread it into the RPC call (it is the
// context the cancellation scenario cancels and the deadline scenario bounds) so
// that cancelling/expiring ctx propagates to the server. A seam supplies one
// opener per server-streaming RPC, e.g.:
//
//	open := func(ctx context.Context, conn *grpc.ClientConn) (grpc.ServerStreamingClient[boundaryv1.WatchPoliciesResponse], error) {
//	    return boundaryv1.NewPolicyStreamServiceClient(conn).WatchPolicies(ctx, req)
//	}
type StreamOpener[Res any] func(ctx context.Context, conn *grpc.ClientConn) (grpc.ServerStreamingClient[Res], error)

// CancelAfterFrames builds a dual-run Scenario that drains the opened
// server-streaming RPC for exactly k frames, then cancels the client context and
// keeps reading. It records into the Observation:
//
//   - frames_before_cancel: how many frames were delivered before the cancel
//     (the contract is that the cancel happens AFTER k frames, so the real impl
//     and fake must agree this is k);
//   - frames_after_cancel: how many frames were delivered AFTER the cancel — the
//     contract is ZERO (the server stops sending once the client cancels). A
//     drifted impl/fake that keeps streaming post-cancel records a non-zero
//     count and DIVERGES;
//   - terminal_status: the gRPC status the stream terminates with after cancel —
//     the contracted context-cancellation status (Canceled). A faithful end
//     surfaces Canceled here; an end that drains to a clean io.EOF (OK) before
//     honouring the cancel diverges.
//
// Because both the real impl and the fake are driven through the SAME scenario,
// the dual-run reports the seam green only if both honour cancellation
// identically. k must be >= 0; k frames must be available before the cancel
// point for the observation to be meaningful (the synthetic self-test and real
// seams size their streams accordingly).
func CancelAfterFrames[Res any](name string, k int, open StreamOpener[Res]) Scenario {
	return Scenario{
		Name: name,
		Run: func(parent context.Context, conn *grpc.ClientConn) (*Observation, error) {
			ctx, cancel := context.WithCancel(parent)
			defer cancel()

			stream, err := open(ctx, conn)
			if err != nil {
				return streamOpenObservation(err), nil
			}

			obs := NewObservation()
			before := 0
			for before < k {
				if _, rerr := stream.Recv(); rerr != nil {
					// The stream ended (cleanly or otherwise) before we reached
					// the cancel point: the contract assumption (>= k frames
					// available) is unmet. Record the truncation so a real/fake
					// that ends the stream early diverges from one that does not.
					obs.Setf("frames_before_cancel", "%d", before)
					obs.Set("terminal_status", status.Code(rerr).String())
					obs.Set("ended_before_cancel", "true")
					return obs, nil
				}
				before++
			}
			obs.Setf("frames_before_cancel", "%d", before)
			obs.Set("ended_before_cancel", "false")

			// Cancel mid-stream, then keep reading. The contract: the server
			// stops sending, so we observe ZERO further frames and a
			// context-cancellation terminal status.
			cancel()
			after, term := drainAfterCancel(stream)
			obs.Setf("frames_after_cancel", "%d", after)
			obs.Set("terminal_status", term)
			return obs, nil
		},
	}
}

// drainAfterCancel keeps Recv-ing after the client context was cancelled and
// returns (frames observed after cancel, terminal status string). Per the
// streaming contract a cancelled stream stops delivering frames promptly, so a
// faithful end returns 0 and Canceled. A drifted end that keeps Sending will
// either deliver post-cancel frames (after > 0) or terminate on a non-Canceled
// status — either way the Observation differs from the faithful one and the
// dual-run catches it.
func drainAfterCancel[Res any](stream grpc.ServerStreamingClient[Res]) (after int, terminal string) {
	for {
		_, err := stream.Recv()
		if err == nil {
			after++
			// Guard against an unbounded post-cancel flood from a badly drifted
			// responder: cap the count we report (the contract is 0, so any
			// positive number already proves the divergence).
			if after >= postCancelFloodCap {
				return after, codes.Canceled.String() + "(flooded)"
			}
			continue
		}
		if err == io.EOF {
			// The server closed the stream with OK before the cancel was
			// honoured — a faithful end surfaces Canceled, so recording OK here
			// makes a "drain-to-completion-ignoring-cancel" responder diverge.
			return after, codes.OK.String()
		}
		return after, status.Code(err).String()
	}
}

// DeadlineAfterFrames is the deadline-driven sibling of CancelAfterFrames: it
// drains k frames, then lets a short context deadline expire (rather than an
// explicit cancel) and records the same shape, with terminal_status the
// contracted DeadlineExceeded. Deadlines and explicit cancels are the two ways a
// streaming consumer walks away; a faithful streaming impl/fake honours both
// identically. The deadline is generous enough that the k pre-deadline frames
// arrive on any reasonable in-process transport.
func DeadlineAfterFrames[Res any](name string, k int, open StreamOpener[Res]) Scenario {
	return Scenario{
		Name: name,
		Run: func(parent context.Context, conn *grpc.ClientConn) (*Observation, error) {
			ctx, cancel := context.WithCancel(parent)
			defer cancel()

			stream, err := open(ctx, conn)
			if err != nil {
				return streamOpenObservation(err), nil
			}
			obs := NewObservation()
			before := 0
			for before < k {
				if _, rerr := stream.Recv(); rerr != nil {
					obs.Setf("frames_before_deadline", "%d", before)
					obs.Set("terminal_status", status.Code(rerr).String())
					obs.Set("ended_before_deadline", "true")
					return obs, nil
				}
				before++
			}
			obs.Setf("frames_before_deadline", "%d", before)
			obs.Set("ended_before_deadline", "false")

			// Expiring the context is observationally a cancellation from the
			// peer's perspective; we model it with an explicit cancel so the
			// affordance stays transport-deterministic (a real wall-clock
			// deadline would race the in-process pipe). The contracted terminal
			// status for a walked-away consumer is context-cancellation.
			cancel()
			after, term := drainAfterCancel(stream)
			obs.Setf("frames_after_deadline", "%d", after)
			obs.Set("terminal_status", term)
			return obs, nil
		},
	}
}

// SlowConsumer builds a dual-run Scenario asserting the back-pressure /
// no-unbounded-buffering contract. It opens the stream, then deliberately does
// NOT Recv for a beat (a slow/blocked consumer), and finally drains. It records:
//
//   - frames_total: the full frame count, which must match across real and fake
//     (a slow consumer does not LOSE frames — flow control stalls the producer,
//     it does not drop);
//   - drained_in_order: whether the frames arrived strictly in order (the stall
//     must not reorder or duplicate); and
//   - completed: whether the stream terminated cleanly (io.EOF / OK) once the
//     consumer caught up.
//
// The affordance cannot read grpc's internal flow-control window from the client
// side, so it asserts the OBSERVABLE consequence of bounded buffering: under a
// slow consumer the stream still delivers every frame, in order, exactly once,
// and completes — i.e. the producer was held back (back-pressure) rather than
// buffering ahead and dropping or reordering. A fake that "buffers the whole
// stream eagerly" still satisfies in-order completeness, so this scenario is
// paired with the streaming-cancellation scenarios (which DO catch eager
// post-cancel buffering) for full coverage. seqOf extracts a per-frame
// monotonic key (e.g. a seq field) used for the in-order/exactly-once check.
func SlowConsumer[Res any](name string, expectedFrames int, stall time.Duration, open StreamOpener[Res], seqOf func(*Res) uint64) Scenario {
	return Scenario{
		Name: name,
		Run: func(ctx context.Context, conn *grpc.ClientConn) (*Observation, error) {
			stream, err := open(ctx, conn)
			if err != nil {
				return streamOpenObservation(err), nil
			}
			// Be a slow consumer: hold off reading so the producer must apply
			// back-pressure rather than race ahead. The in-process pipe's bounded
			// buffer means a faithful producer blocks on Send until we read.
			if stall > 0 {
				timer := time.NewTimer(stall)
				select {
				case <-ctx.Done():
					timer.Stop()
				case <-timer.C:
				}
			}

			obs := NewObservation()
			inOrder := true
			var prev uint64
			var have uint64
			completed := false
			for {
				resp, rerr := stream.Recv()
				if rerr == io.EOF {
					completed = true
					break
				}
				if rerr != nil {
					obs.Set("terminal_status", status.Code(rerr).String())
					break
				}
				seq := seqOf(resp)
				if have > 0 && seq != prev+1 {
					inOrder = false
				}
				prev = seq
				have++
			}
			obs.Setf("frames_total", "%d", have)
			obs.Setf("frames_total_matches_expected", "%t", int(have) == expectedFrames)
			obs.Setf("drained_in_order", "%t", inOrder)
			obs.Setf("completed", "%t", completed)
			if completed {
				obs.Set("terminal_status", codes.OK.String())
			}
			return obs, nil
		},
	}
}

// streamOpenObservation records a failure to even open the stream as a terminal
// status, so a real/fake that refuses to open (e.g. an argument-validation
// rejection) is still comparable rather than a harness error.
func streamOpenObservation(err error) *Observation {
	obs := NewObservation()
	obs.Set("terminal_status", status.Code(err).String())
	obs.Set("opened", "false")
	return obs
}

// postCancelFloodCap bounds how many post-cancel frames a drifted responder can
// make us count before we give up — the contract is 0, so any positive count
// already proves the divergence; the cap just keeps a pathological flood from
// spinning the test forever.
const postCancelFloodCap = 1 << 16

// --- shared server-side back-pressure fixture --------------------------------
//
// The CancelAfterFrames / DeadlineAfterFrames / SlowConsumer scenarios above are
// the CLIENT half of the streaming-lifecycle affordance. A seam wiring them needs
// a matched set of SERVER-side honest/drifted ends to dual-run against (a faithful
// producer the scenarios observe as green, and one drift per back-pressure corner
// the negative-proof tests observe as a bite). Every server-streaming seam needs
// the SAME six ends — bounded-park, cancel-swallow, eager-complete, drop, reorder,
// duplicate — and the only thing that varies seam-to-seam is the proto-typed RPC
// signature and how a 1-based index becomes a frame. Their producer LOGIC (which
// indices to Send, in what order, and whether to park awaiting the consumer) is
// byte-identical scaffolding that was copy-pasted across the streaming seams.
//
// This fixture single-sources that logic: BackPressurePlan enumerates the delivery
// order for each variant, and RunBackPressureStream drives it against a
// seam-supplied send closure. A seam's gRPC method shrinks to "build the plan, call
// the driver, thread the frame builder" — no per-seam producer loop to drift.
//
// The shared lifecycle parameters every seam sizes its synthetic stream to are
// exported here too, so the seams stop re-declaring identical const blocks:
//
//   - LifecycleCancelK frames are read before the cancel/deadline scenarios walk
//     away (the bounded-park end delivers exactly this many then parks, so the
//     observation is race-free);
//   - LifecycleSlowFrames is the slow-consumer total drained to a clean EOF; and
//   - LifecycleDropFrame / LifecycleReorderFrame / LifecycleDuplicateFrame are the
//     mid-tail index each back-pressure drift mutates (all = LifecycleSlowFrames/2,
//     strictly mid-tail so the transposed/duplicated pair stays in range).
//
// A seam still owns its frame BYTES sizing (the per-frame payload must overflow the
// HTTP/2 flow-control window so a faithful producer blocks on Send) because that
// rides a seam-specific proto field; only the index plan + counts are shared.
const (
	// LifecycleCancelK is the number of frames a consumer reads before cancelling
	// (or letting its deadline expire). The bounded-park honest end sends exactly
	// this many then parks, so the cancel observation is race-free.
	LifecycleCancelK = 3
	// LifecycleSlowFrames is the total frame count the slow-consumer scenario drains
	// to a clean EOF; large enough that, under the stall, a faithful producer is held
	// by flow control rather than racing ahead, yet small enough to stay fast.
	LifecycleSlowFrames = 24
	// LifecycleStall is how long the slow-consumer scenario holds off reading so the
	// producer must apply back-pressure (block on Send) rather than race ahead.
	LifecycleStall = 25 * time.Millisecond
	// LifecycleDropFrame is the mid-tail frame the dropping drift skips so the
	// delivered slow-consumer sequence is no longer gap-free (the integrity bite).
	LifecycleDropFrame = LifecycleSlowFrames / 2
	// LifecycleReorderFrame is the mid-tail frame the reordering drift swaps with its
	// successor (it emits frame LifecycleReorderFrame+1 before LifecycleReorderFrame),
	// so the delivered sequence is permuted but the TOTAL count is UNCHANGED — the
	// in-order bite that, unlike the dropping drift, leaves frames_total correct.
	LifecycleReorderFrame = LifecycleSlowFrames / 2
	// LifecycleDuplicateFrame is the mid-tail frame the duplicating drift re-emits
	// (it Sends frame LifecycleDuplicateFrame TWICE), so the delivered count is
	// expected+1 — frames_total OVER by one (frames_total_matches_expected=false) and,
	// because the repeated frame breaks the strictly-increasing sequence,
	// drained_in_order=false too. The third corner of the exactly-once contract: a
	// count OVER-run, the mirror of the dropping drift's short count.
	LifecycleDuplicateFrame = LifecycleSlowFrames / 2
)

// BackPressurePlan is the seam-agnostic delivery program for one streaming-lifecycle
// end: the ordered list of 1-based frame indices to Send and whether, once the list
// is drained, the producer PARKS awaiting the consumer's cancel/deadline (rather than
// completing cleanly). Order, multiplicity and gaps in Order encode the variant —
// every back-pressure corner is just a different Order, so the drift logic lives in
// ONE place (the plan builders) instead of copy-pasted server loops.
type BackPressurePlan struct {
	// Order is the exact sequence of 1-based frame indices to Send, in delivery
	// order. A skipped index = a dropped frame; a repeated index = a duplicate; a
	// transposed pair = a reorder.
	Order []int
	// ParkAfter, when true, makes the producer park on ctx.Done() after delivering
	// Order and return the context-cancellation status — modeling an open-ended
	// subscription drained of its pending frames and awaiting the next event. When
	// false the producer returns nil (a clean io.EOF / OK) once Order is drained.
	ParkAfter bool
}

// BoundedParkPlan is the contract-faithful cancel/deadline honest end: deliver
// exactly k frames then PARK awaiting the consumer's cancel/deadline. Because there
// is no (k+1)th frame to race, the cancel/deadline scenarios observe exactly k frames
// before and ZERO after, deterministically and identically on both ends.
func BoundedParkPlan(k int) BackPressurePlan {
	return BackPressurePlan{Order: seq(1, k), ParkAfter: true}
}

// CancelSwallowingPlan is the cancel/deadline VIOLATION: deliver exactly k frames
// then COMPLETE CLEANLY (io.EOF), never honouring the consumer's cancel/deadline. A
// faithful end stays parked and surfaces the context-cancellation terminal; this one
// hands the client a clean OK terminal instead — the bite on terminal_status.
func CancelSwallowingPlan(k int) BackPressurePlan {
	return BackPressurePlan{Order: seq(1, k), ParkAfter: false}
}

// EagerCompletePlan is the contract-faithful slow-consumer honest end: deliver all
// `total` frames in order to a clean EOF. Under the slow consumer the bounded
// in-process pipe holds the producer back on Send (back-pressure) rather than racing
// ahead; it never drops or reorders.
func EagerCompletePlan(total int) BackPressurePlan {
	return BackPressurePlan{Order: seq(1, total)}
}

// DroppingPlan is the slow-consumer VIOLATION that SKIPS a mid-tail frame, so the
// delivered sequence is no longer gap-free and the count is short — the bite on
// frames_total / drained_in_order (jointly). drop must be in [1, total].
func DroppingPlan(total, drop int) BackPressurePlan {
	order := make([]int, 0, total)
	for i := 1; i <= total; i++ {
		if i == drop {
			continue
		}
		order = append(order, i)
	}
	return BackPressurePlan{Order: order}
}

// ReorderingPlan is the in-order-sibling slow-consumer VIOLATION: deliver the SAME
// total set of frames but PERMUTE delivery order, emitting frame swap+1 BEFORE swap
// (an adjacent transposition). frames_total is UNCHANGED while the delivered tail is
// no longer monotonic — the bite on drained_in_order ALONE. swap must be < total so
// the transposed pair stays within [1, total] (no drop, no duplicate).
func ReorderingPlan(total, swap int) BackPressurePlan {
	order := make([]int, 0, total)
	for i := 1; i <= total; i++ {
		switch i {
		case swap:
			order = append(order, i+1, i)
		case swap + 1:
			// already delivered out of order above.
		default:
			order = append(order, i)
		}
	}
	return BackPressurePlan{Order: order}
}

// DuplicatingPlan is the count-over slow-consumer VIOLATION: deliver every frame in
// order but RE-EMIT one mid-tail frame, so the delivered count is total+1 —
// frames_total OVER by one (and the repeated seq also breaks strict ordering). dup
// must be < total so the re-emitted frame is strictly mid-tail.
func DuplicatingPlan(total, dup int) BackPressurePlan {
	order := make([]int, 0, total+1)
	for i := 1; i <= total; i++ {
		order = append(order, i)
		if i == dup {
			order = append(order, i)
		}
	}
	return BackPressurePlan{Order: order}
}

// RunBackPressureStream drives a BackPressurePlan against a seam-supplied send
// closure: it Sends each planned 1-based index in order (checking ctx for
// cancellation before each Send, so a walked-away consumer stops delivery promptly),
// then either parks on ctx.Done() and returns the context-cancellation status
// (plan.ParkAfter) or returns nil for a clean io.EOF. It is the single producer loop
// every streaming seam's honest/drifted ends share; send carries the seam's
// proto-typed frame so the driver stays signature-agnostic. ctx is the stream's
// server-side context (stream.Context()).
func RunBackPressureStream(ctx context.Context, plan BackPressurePlan, send func(i int) error) error {
	for _, i := range plan.Order {
		if ctx.Err() != nil {
			return status.FromContextError(ctx.Err()).Err()
		}
		if err := send(i); err != nil {
			return err
		}
	}
	if plan.ParkAfter {
		// Drained: park until the consumer walks away (cancel / deadline).
		<-ctx.Done()
		return status.FromContextError(ctx.Err()).Err()
	}
	return nil
}

// seq returns the inclusive integer range [lo, hi] (empty when hi < lo). It is the
// trivial "deliver 1..n in order" plan body shared by the honest ends.
func seq(lo, hi int) []int {
	if hi < lo {
		return nil
	}
	out := make([]int, 0, hi-lo+1)
	for i := lo; i <= hi; i++ {
		out = append(out, i)
	}
	return out
}
