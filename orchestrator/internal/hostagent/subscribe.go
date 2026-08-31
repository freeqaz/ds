package hostagent

// subscribe.go is the host-agent half of the POL-4 policy stream (D36/D72; doc
// 13 §5, doc 15 §5.3): the long-lived server-streaming subscription to the
// orchestrator's PolicyService.WatchPolicies(from_seq).
//
// Distribution topology (D72): EXACTLY ONE WatchPolicies subscriber per host —
// THIS host agent. ds-dnsgate, ds-tlsproxy, and the NFTables programmer NEVER
// open this control-plane stream; they read the host-local snapshot fan-out the
// agent serves downstream of this seam. The D36 policy_log bigserial seq is THE
// single policy version end to end — there is no per-service version namespace.
//
// Subscribe opens the RPC on a dedicated goroutine that feeds a channel, so the
// stream NEVER blocks the host-agent event loop. Each received
// orchestratorv1.WatchPoliciesResponse wraps exactly one
// boundaryv1.PolicySnapshot (the composed (seq, content_hash, document)
// identity); the goroutine unwraps it and forwards the snapshot to the returned
// channel for the snapshot-store seam to verify and persist (POL-4 part 1).
//
// REPLAY CURSOR (D36 catch-up; D72 idempotent replay). On (re)subscribe the host
// agent passes its last persisted applied seq as fromSeq so the stream catches
// up from there. The server replays from from_seq, but the subscriber is the
// authority on idempotence: it DROPS any frame whose seq is not strictly greater
// than the highest seq it has already forwarded (seeded from fromSeq). So a
// reconnect from a persisted seq skips already-seen snapshots even if the server
// re-sends them — the host never re-applies a snapshot it already applied
// (idempotent replay, D72).
//
// FAIL-CLOSED on the channel: the channel CLOSES cleanly on context cancel or
// RPC close/error. A closed channel is the subscriber's only signal that the
// stream ended; it never delivers a partial or fabricated snapshot. Verification
// (content_hash / schema) and the NACK-and-abort-host-wide decision live in the
// snapshot-store seam downstream (this client only delivers what the server
// streamed, in order, deduplicated by seq) — this file deliberately does no
// policy evaluation (the one-evaluator rule, doc 13 §1 rule 1).
//
// Transport is free (docs/12 §9, docs/13 §6); the caller hands in the
// grpc.ClientConnInterface (a host-local UDS gRPC dial in production, a bufconn
// in tests). NEVER-LOG-THE-SECRET: this path logs nothing — the composed
// document is opaque bytes forwarded untouched.

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// SubscribeChannelBuffer is the buffer depth of the channel Subscribe returns. A
// small buffer lets the receive goroutine stay ahead of a momentarily-busy
// snapshot-store consumer without unbounded memory; it is a rig-tuned value (doc
// 15 §10), never frozen. Policy snapshots are low-rate (org edits + fleet blocks
// + ask grants — trivial volume, doc 15 §5.3 / orchestrator/v1 policy.proto), so
// a depth of one is ample headroom; the goroutine still blocks rather than drops
// when the consumer is slow (a snapshot is NEVER discarded silently — a dropped
// snapshot would be a missed policy version, breaking the monotone cursor the
// applied_seq min depends on).
const SubscribeChannelBuffer = 1

// Subscribe opens the host agent's single WatchPolicies subscription to the
// orchestrator's PolicyService (D36/D72) over conn and returns a channel of the
// composed snapshots, in seq order, deduplicated against fromSeq.
//
// fromSeq is the replay cursor: the last applied seq the host persisted, passed
// so the server catches up from there (from_seq = 0 requests the current
// snapshot from the start). The subscriber additionally drops any frame whose
// seq is not strictly greater than fromSeq (or than the highest seq already
// forwarded), so a reconnect skips already-seen snapshots idempotently even if
// the server re-streams them.
//
// The RPC runs on a DEDICATED goroutine feeding the returned channel, so the
// subscription never blocks the host-agent event loop. The channel CLOSES
// cleanly when:
//   - ctx is cancelled (graceful host drain or shutdown), or
//   - the server closes the stream (io.EOF), or
//   - the stream fails (any Recv error) — the host agent's reconnect policy then
//     re-dials and re-subscribes from its persisted seq (the caller's policy,
//     rig-tuned).
//
// In every case the channel close is the sole end-of-stream signal; the channel
// never delivers a partial frame. Verification and persistence are the
// snapshot-store seam's job downstream — Subscribe forwards the composed
// snapshot bytes untouched (no re-serialization, no logging).
//
// An error is returned (and no channel) ONLY if the initial stream OPEN fails
// synchronously — at that point there is no goroutine and nothing to close. Once
// the stream is open, all subsequent termination is signalled by the channel
// closing, never by a second error return.
func Subscribe(ctx context.Context, conn grpc.ClientConnInterface, fromSeq uint64) (<-chan *boundaryv1.PolicySnapshot, error) {
	if conn == nil {
		return nil, fmt.Errorf("hostagent: subscribe: nil grpc conn")
	}

	client := orchestratorv1.NewPolicyServiceClient(conn)
	stream, err := client.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{
		FromSeq: fromSeq,
	})
	if err != nil {
		return nil, fmt.Errorf("hostagent: open WatchPolicies(from_seq=%d): %w", fromSeq, err)
	}

	out := make(chan *boundaryv1.PolicySnapshot, SubscribeChannelBuffer)
	go pump(ctx, stream, fromSeq, out)
	return out, nil
}

// snapshotStream is the receive side of the WatchPolicies server stream. The
// generated grpc.ServerStreamingClient[orchestratorv1.WatchPoliciesResponse]
// satisfies it natively (the compile-time assertion at the bottom of this file
// proves it), so pump is driven by the real client in production and is
// directly unit-testable with a fake stream — no live dial required.
type snapshotStream interface {
	Recv() (*orchestratorv1.WatchPoliciesResponse, error)
}

// pump is the dedicated receive goroutine: it reads WatchPolicies frames, drops
// snapshots at or below the replay cursor (idempotent replay, D72), forwards the
// rest in order to out, and CLOSES out when the stream ends (ctx cancel, EOF, or
// any Recv error). It never panics on a malformed frame — a nil snapshot is
// skipped, not forwarded — and it never logs the composed document.
func pump(ctx context.Context, stream snapshotStream, fromSeq uint64, out chan<- *boundaryv1.PolicySnapshot) {
	// Closing out is the sole end-of-stream signal to the consumer; defer it so
	// EVERY exit path (EOF, error, ctx cancel mid-send) closes cleanly.
	defer close(out)

	// lastSeq is the replay cursor: the highest seq already forwarded, seeded
	// from fromSeq so a reconnect drops everything the host already saw. A frame
	// is forwarded ONLY if its seq is strictly greater — enforcing the monotone,
	// dedup'd, idempotent delivery the applied_seq min depends on.
	lastSeq := fromSeq

	for {
		resp, err := stream.Recv()
		if err != nil {
			// EOF (clean server close) or any transport/RPC error: the stream is
			// over. Close out (deferred) — the caller re-dials per its reconnect
			// policy. ctx cancel surfaces here as a Canceled Recv error too.
			return
		}

		snap := resp.GetSnapshot()
		if snap == nil {
			// A frame with no snapshot carries no policy version — skip it rather
			// than forward a nil the snapshot store would have to special-case.
			continue
		}

		// Idempotent replay (D72): drop anything not strictly newer than the
		// cursor. A server that re-streams from from_seq on reconnect is handled
		// here — already-seen seqs are dropped, never re-delivered.
		if snap.GetSeq() <= lastSeq {
			continue
		}
		lastSeq = snap.GetSeq()

		// Forward, but honor ctx cancel even while a slow consumer is blocking the
		// send — so a drain mid-send still closes the channel promptly instead of
		// wedging the goroutine forever.
		select {
		case out <- snap:
		case <-ctx.Done():
			return
		}
	}
}

// Compile-time proof that the GENERATED WatchPolicies client stream satisfies
// the snapshotStream seam pump consumes: the production client and a test fake
// stream are therefore interchangeable behind pump. If a proto/grpc regen ever
// changed the stream shape, this assertion fails the build rather than letting
// the production wiring rot silently.
var _ snapshotStream = grpc.ServerStreamingClient[orchestratorv1.WatchPoliciesResponse](nil)
