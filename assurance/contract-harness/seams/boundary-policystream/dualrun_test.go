// SPDX-License-Identifier: Apache-2.0

package boundarypolicystream_test

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	boundarypolicystream "github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/boundary-policystream"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1/boundaryv1fake"
)

// TestSeam_RealVsGeneratedFake is the per-commit gate for the boundary.v1
// PolicyStreamService seam (doc 14 §2b, doc 15 §6, doc 06 §2.1): the seam's
// conformance suite runs against BOTH the real reference implementation AND the
// generated programmable fake, and the seam is green only if every scenario
// observes the same thing on both. The suite exercises BOTH verbs (WatchPolicies
// server-streaming, AckPolicy unary) and the properties the policy-stream seam
// turns on — the monotonic gap-free bigserial seq as THE single policy version
// namespace, WatchPolicies(from_seq) snapshot-then-delta serving, resumability
// from an arbitrary cursor, the empty past-the-tail catch-up, the (seq,
// content_hash, document) snapshot identity shape, and the AckPolicy round-trip
// with its dishonest-ack refusals.
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := boundarypolicystream.Suite().Run(context.Background(), boundarypolicystream.RealDialer(), boundarypolicystream.FakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("boundary<->policy_stream seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_HarnessCatchesADriftedFake is the negative proof: a fake that drifts
// from the contract — here, a WatchPolicies that SKIPS a seq in its catch-up,
// violating the gap-free monotonic bigserial invariant the policy version
// namespace depends on (doc 14 §2b, D72) — must fail the seam. Without this, a
// green dual-run would be meaningless: it could be passing because the gate never
// fires. The drift is injected only in this test's local fake, never in the
// committed generated fake.
func TestSeam_HarnessCatchesADriftedFake(t *testing.T) {
	res, err := boundarypolicystream.Suite().Run(context.Background(), boundarypolicystream.RealDialer(), driftedSeqSkipFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a drifted fake passed the seam — the dual-run gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or fake error, got report:\n%s", res.Report())
	}
}

// TestAck_RecordedViaFakeAccessors asserts the consumer-ack contract directly
// against the generated fake's per-verb *Recorded() call-capture accessors (doc
// 13 §5): every WatchPolicies / AckPolicy that hits the fake is recorded with its
// request, the streamed snapshot identity is what the consumer acks back, and an
// honest round-trip succeeds. This is the assertion the dual-run alone cannot
// make: the dual-run compares end-observable outcomes; the recorded-call surface
// is what lets a downstream consumer verify "the watch opened from this cursor,
// and the ack carried exactly this (seq, content_hash)".
func TestAck_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()
	f := boundaryv1fake.NewPolicyStreamServiceFake()

	mirror := boundarypolicystream.NewRefImpl()
	boundarypolicystream.SeedLog(mirror)
	f.AckPolicyResponder = mirror.AckPolicy
	f.WatchPoliciesResponder = func(_ context.Context, req *boundaryv1.WatchPoliciesRequest) ([]*boundaryv1.WatchPoliciesResponse, error) {
		return boundarypolicystream.WrapSnapshots(mirror.SnapshotsFrom(req.GetFromSeq())), nil
	}

	// The tail snapshot the consumer would ack — sourced from the mirror so the
	// (seq, content_hash) is exactly what WatchPolicies streams.
	tail := mirror.SnapshotAt(mirror.CurrentSeq())
	if tail == nil {
		t.Fatal("seeded log produced no tail snapshot")
	}

	// An honest ack of the streamed tail round-trips.
	if _, err := f.AckPolicy(ctx, &boundaryv1.AckPolicyRequest{Seq: tail.GetSeq(), ContentHash: tail.GetContentHash()}); err != nil {
		t.Fatalf("AckPolicy of the streamed tail snapshot: %v", err)
	}
	// An ack whose hash does not match the streamed snapshot is refused — the
	// ack must PROVE the consumer verified exactly this snapshot (doc 13 §5).
	if _, err := f.AckPolicy(ctx, &boundaryv1.AckPolicyRequest{Seq: tail.GetSeq(), ContentHash: []byte("ds-synthetic-not-the-real-hash")}); err == nil {
		t.Fatal("AckPolicy accepted a mismatched content_hash — the ack-honesty check is not firing")
	}

	// The recorder captured both ack calls, each carrying its request.
	ackCalls := f.AckPolicyRecorded()
	if len(ackCalls) != 2 {
		t.Fatalf("AckPolicyRecorded: want 2, got %d", len(ackCalls))
	}
	if got := ackCalls[0].Req.GetSeq(); got != tail.GetSeq() {
		t.Fatalf("AckPolicyRecorded[0].seq = %d, want %d", got, tail.GetSeq())
	}
	if got := len(ackCalls[0].Req.GetContentHash()); got != 32 {
		t.Fatalf("AckPolicyRecorded[0].content_hash len = %d, want 32", got)
	}
}

// TestWatch_CursorRecordedViaFakeAccessors closes the round-trip story the
// AckPolicy recorder opens (doc 13 §5): it asserts the consumer-WATCH contract
// directly against the generated fake's WatchPoliciesRecorded() call-capture
// accessor, paired with AckPolicyRecorded(). A host agent reconnecting from its
// last persisted applied seq (D36 catch-up; D72 one-subscriber-per-host) opens
// WatchPolicies(from_seq) at successive cursors; the recorder must show the watch
// opened from THIS from_seq each time (monotonic cursor advance / correct resume),
// and the ack must carry exactly the (seq, content_hash) the resumed stream
// delivered — closing the "the watch opened from this cursor, and the ack carried
// exactly this (seq, content_hash)" loop the dual-run alone cannot make.
func TestWatch_CursorRecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()
	f := boundaryv1fake.NewPolicyStreamServiceFake()

	mirror := boundarypolicystream.NewRefImpl()
	boundarypolicystream.SeedLog(mirror)
	f.AckPolicyResponder = mirror.AckPolicy
	f.WatchPoliciesResponder = func(_ context.Context, req *boundaryv1.WatchPoliciesRequest) ([]*boundaryv1.WatchPoliciesResponse, error) {
		return boundarypolicystream.WrapSnapshots(mirror.SnapshotsFrom(req.GetFromSeq())), nil
	}

	tail := mirror.CurrentSeq()
	if tail == 0 {
		t.Fatal("seeded log produced no tail")
	}

	// Drive WatchPolicies at a sequence of resume cursors a reconnecting host agent
	// would walk: from-zero (whole-log catch-up), then resuming from each applied
	// seq up to the tail (each resume advances the cursor by one). Every open is
	// routed THROUGH the fake's recorded WatchPolicies entrypoint so the from_seq
	// cursor is captured by WatchPoliciesRecorded(); the frames the fake Sends are
	// collected on a minimal in-test server-stream shim. The drain proves the
	// resumed stream delivered exactly the rows past the cursor; the ack at the end
	// carries the (seq, content_hash) the last resumed stream delivered.
	openWatch := func(fromSeq uint64) []*boundaryv1.PolicySnapshot {
		t.Helper()
		stream := &discardWatchStream{ctx: ctx}
		if err := f.WatchPolicies(&boundaryv1.WatchPoliciesRequest{FromSeq: fromSeq}, stream); err != nil {
			t.Fatalf("WatchPolicies(from_seq=%d): %v", fromSeq, err)
		}
		out := make([]*boundaryv1.PolicySnapshot, 0, len(stream.sent))
		for _, r := range stream.sent {
			out = append(out, r.GetSnapshot())
		}
		return out
	}

	wantCursors := []uint64{0}
	for c := uint64(0); c < tail; c++ {
		wantCursors = append(wantCursors, c)
	}
	var lastResumeTail *boundaryv1.PolicySnapshot
	for _, cursor := range wantCursors {
		snaps := openWatch(cursor)
		// The resumed stream delivers exactly the rows strictly past the cursor,
		// monotonic and gap-free; nothing already-applied is replayed.
		var prev uint64
		for i, s := range snaps {
			if i == 0 && s.GetSeq() != cursor+1 {
				t.Fatalf("resume from_seq=%d: first delivered seq=%d, want cursor+1=%d", cursor, s.GetSeq(), cursor+1)
			}
			if i > 0 && s.GetSeq() != prev+1 {
				t.Fatalf("resume from_seq=%d: seq gap at %d (prev %d)", cursor, s.GetSeq(), prev)
			}
			if s.GetSeq() <= cursor {
				t.Fatalf("resume from_seq=%d: replayed an already-applied seq=%d", cursor, s.GetSeq())
			}
			prev = s.GetSeq()
		}
		if len(snaps) > 0 {
			lastResumeTail = snaps[len(snaps)-1]
		}
	}
	if lastResumeTail == nil {
		t.Fatal("no resume cursor delivered a tail snapshot to ack")
	}

	// The recorder captured a WatchPolicies open at every cursor, IN ORDER — the
	// monotonic cursor-advance / correct-resume story.
	watchCalls := f.WatchPoliciesRecorded()
	if len(watchCalls) != len(wantCursors) {
		t.Fatalf("WatchPoliciesRecorded: want %d opens, got %d", len(wantCursors), len(watchCalls))
	}
	for i, want := range wantCursors {
		if got := watchCalls[i].Req.GetFromSeq(); got != want {
			t.Fatalf("WatchPoliciesRecorded[%d].from_seq = %d, want %d", i, got, want)
		}
	}

	// Close the loop: the ack carries EXACTLY the (seq, content_hash) the last
	// resumed stream delivered — the watch opened from this cursor, and the ack
	// proves verification of exactly that snapshot (doc 13 §5).
	if _, err := f.AckPolicy(ctx, &boundaryv1.AckPolicyRequest{Seq: lastResumeTail.GetSeq(), ContentHash: lastResumeTail.GetContentHash()}); err != nil {
		t.Fatalf("AckPolicy of the resumed tail snapshot: %v", err)
	}
	ackCalls := f.AckPolicyRecorded()
	if len(ackCalls) != 1 {
		t.Fatalf("AckPolicyRecorded: want 1, got %d", len(ackCalls))
	}
	if got := ackCalls[0].Req.GetSeq(); got != lastResumeTail.GetSeq() {
		t.Fatalf("AckPolicyRecorded[0].seq = %d, want resumed-tail seq %d", got, lastResumeTail.GetSeq())
	}
	if !bytes.Equal(ackCalls[0].Req.GetContentHash(), lastResumeTail.GetContentHash()) {
		t.Fatal("AckPolicyRecorded[0].content_hash != the resumed tail snapshot's content_hash — the ack did not carry exactly the streamed snapshot")
	}
}

// discardWatchStream is a minimal in-test grpc.ServerStreamingServer that collects
// the frames the fake Sends — just enough to drive the fake's WatchPolicies method
// (which records the request, then Sends the responder's frames) without a live
// transport. The embedded grpc.ServerStream is nil and never used: the fake only
// calls Context() and Send(), both overridden. Synthetic only.
type discardWatchStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*boundaryv1.WatchPoliciesResponse
}

func (s *discardWatchStream) Context() context.Context { return s.ctx }
func (s *discardWatchStream) Send(r *boundaryv1.WatchPoliciesResponse) error {
	s.sent = append(s.sent, r)
	return nil
}

// driftedSeqSkipFakeDialer programs the generated fake with an honest AckPolicy
// but a deliberately wrong WatchPolicies responder that DROPS the first frame of
// its catch-up — so the delivered seqs are no longer gap-free (they start at seq
// 2, skipping seq 1). AckPolicy is programmed honestly so the divergence is
// attributable to the injected seq-skip drift.
func driftedSeqSkipFakeDialer() dualrun.Dialer {
	f := boundaryv1fake.NewPolicyStreamServiceFake()
	mirror := boundarypolicystream.NewRefImpl()
	boundarypolicystream.SeedLog(mirror)

	f.AckPolicyResponder = mirror.AckPolicy
	f.WatchPoliciesResponder = func(_ context.Context, req *boundaryv1.WatchPoliciesRequest) ([]*boundaryv1.WatchPoliciesResponse, error) {
		frames := boundarypolicystream.WrapSnapshots(mirror.SnapshotsFrom(req.GetFromSeq()))
		// DRIFT: drop the first catch-up frame — the gap-free monotonic seq
		// invariant the policy version namespace depends on is now broken.
		if len(frames) > 0 {
			frames = frames[1:]
		}
		return frames, nil
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		boundaryv1fake.RegisterPolicyStreamService(s, f)
	})
}
