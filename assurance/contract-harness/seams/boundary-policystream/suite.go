// SPDX-License-Identifier: Apache-2.0

package boundarypolicystream

import (
	"bytes"
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1/boundaryv1fake"
)

// Synthetic fixtures (D50). Every layer body is obviously-synthetic — no real
// policy bodies, actors, hosts, or sessions. The SEEDED rows are installed
// identically on BOTH dialers (the "pre-existing policy_log" a WatchPolicies
// catch-up replays); NO scenario depends on absolute seq values that differ
// across ends — both ends start from the same seeded log and every scenario
// runs in the same declaration order against both, so the policy_log evolves
// identically on each end. Scenarios record contract-observable INVARIANTS
// (monotone, gap-free, snapshot identity shape, ack round-trip) plus the
// seeded-tail facts that are stable by construction.
const (
	// system-baseline, org-edit, fleet-block, AND a POL-5 ask-grant-with-TTL row
	// (doc 16 §8.2: a returned approval delivered ON the policy stream as composed
	// deny-wins content) — the pre-existing log. The ask-grant row is the TAIL so
	// it is the snapshot a consumer would ack, and its TTL/expiry grant body rides
	// inside the opaque `document` payload the stream carries.
	seededRowCount   = uint64(4)
	contentHashBytes = 32 // SHA-256 digest length (snapshot content_hash)
)

// Suite is the boundary.v1 PolicyStreamService seam's single conformance suite
// (doc 06 §3a: one suite, run against real + fake). Every scenario is stated
// purely in terms of the frozen PolicyStreamService contract (doc 14 §2b, doc 15
// §6, D36/D72) so the same suite is meaningful against any faithful
// implementation: the policy_log's monotonic gap-free bigserial seq is THE single
// policy version namespace end to end, WatchPolicies(from_seq) serves the
// composed snapshot tail resumable from an arbitrary cursor, and AckPolicy is the
// consumer acknowledgement that proves it verified exactly the streamed snapshot.
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "boundary<->orchestrator(policy_stream)",
		Scenarios: scenarios(),
	}
}

func scenarios() []dualrun.Scenario {
	base := []dualrun.Scenario{
		{
			// The seeded log tail catch-up: from_seq=0 replays the WHOLE log
			// (snapshot-then-delta from the start). The seqs delivered must be
			// monotonic, gap-free, and 1..N over the seeded rows.
			Name: "watch-policies/from-zero-replays-whole-log-monotonic-gap-free",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := boundaryv1.NewPolicyStreamServiceClient(conn)
				stream, err := cl.WatchPolicies(ctx, &boundaryv1.WatchPoliciesRequest{FromSeq: 0})
				if err != nil {
					return errObservation(err), nil
				}
				return snapshotStreamObservation(stream), nil
			},
		},
		{
			// Snapshot identity SHAPE (doc 13 §5): every delivered frame carries
			// (seq, content_hash, document); content_hash is the 32-byte SHA-256
			// over the composed document and is non-empty; the composed document
			// grows with the composed log. Recorded over the SEEDED tail (stable
			// on both ends because the seed is installed identically).
			Name: "watch-policies/snapshot-then-delta-identity-shape",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := boundaryv1.NewPolicyStreamServiceClient(conn)
				stream, err := cl.WatchPolicies(ctx, &boundaryv1.WatchPoliciesRequest{FromSeq: 0})
				if err != nil {
					return errObservation(err), nil
				}
				return seededPrefixObservation(stream), nil
			},
		},
		{
			// POL-5 ask-grant-with-TTL grant-delivery vehicle (doc 16 §8.2,
			// D18/D45/D53): an approval returns as a session-scoped TTL'd allow
			// grant delivered ON the policy stream as composed deny-wins content —
			// there is NO second response contract; the boundary never grows an
			// approval UI. This scenario asserts the SYNTHETIC ask-grant-with-TTL
			// body (its TTL/expiry shape) embedded inside the deny-wins
			// composed-document payload SURVIVES end to end on the stream, so the
			// grant-delivery vehicle is contract-checked — not merely the
			// (seq, content_hash, document) envelope. It is asserted real-vs-fake
			// (the dual-run compares this observation across both ends), so a fake
			// that dropped or mangled the grant body would diverge.
			//
			// NOTE: this pins only that the grant's TTL/expiry shape rides as opaque
			// composed-document content — the document SCHEMA specifics (field
			// names/order/encoding) bind only once the deny-wins composed-document
			// schema is fixed (POL-1 v0, doc 13 §3, never in this proto package).
			Name: "watch-policies/ask-grant-with-ttl-rides-composed-document",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := boundaryv1.NewPolicyStreamServiceClient(conn)
				tailSnap, err := lastStreamedSnapshot(ctx, cl)
				if err != nil {
					return errObservation(err), nil
				}
				doc := tailSnap.GetDocument()
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				// The ask-grant row is the seeded tail (delivered ON the stream).
				obs.Setf("grant_seq_is_tail", "%t", tailSnap.GetSeq() == seededRowCount)
				// The grant body rides INSIDE the opaque composed-document payload —
				// the POL-5 delivery vehicle, not a side channel.
				obs.Setf("grant_marker_in_document", "%t", bytes.Contains(doc, []byte(AskGrantMarker)))
				// The TTL/expiry shape an allow-once grant carries survives end to end.
				obs.Setf("grant_has_ttl_field", "%t", bytes.Contains(doc, []byte("ttl_s=")))
				obs.Setf("grant_has_expiry_field", "%t", bytes.Contains(doc, []byte("expiry=")))
				obs.Setf("grant_has_allow_once_posture", "%t", bytes.Contains(doc, []byte("posture=allow-once")))
				// Deny ALWAYS wins over the allow in composition (doc 13 §1 rule 2):
				// the grant rides inside — never replaces — the deny-wins document,
				// so the upstream fleet-block layer's content is still present.
				obs.Setf("deny_wins_layer_still_present", "%t", bytes.Contains(doc, []byte("seed-fleet-block-synthetic")))
				return obs, nil
			},
		},
		{
			// Resumability from an ARBITRARY from_seq: open a watch at exactly the
			// seeded tail, capture the tail, then re-open from the captured cursor
			// — the catch-up delivers EXACTLY the rows past the cursor (here zero,
			// since no new rows were appended), monotonic and gap-free, and NOTHING
			// already-applied. This is the host-agent reconnect path (D36). The
			// seeded log is immutable across scenarios (no append verb on this
			// seam), so the resume cursor = seeded tail and the catch-up is empty —
			// the "already current" observation, stable on both ends.
			Name: "watch-policies/resumable-from-arbitrary-from-seq",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := boundaryv1.NewPolicyStreamServiceClient(conn)
				// Establish the resume cursor = current tail (drain a from-zero
				// watch and take its last seq; gap-free so last = count).
				baseStream, err := cl.WatchPolicies(ctx, &boundaryv1.WatchPoliciesRequest{FromSeq: 0})
				if err != nil {
					return errObservation(err), nil
				}
				base := drainSeqs(baseStream)
				if base.err != nil {
					return errObservation(base.err), nil
				}
				cursor := base.last
				// Re-open from a mid-log cursor (cursor-1): the catch-up is exactly
				// the single tail row (seq = cursor), monotonic and gap-free, and
				// nothing at or below the from_seq is replayed.
				midCursor := cursor - 1
				resumeStream, err := cl.WatchPolicies(ctx, &boundaryv1.WatchPoliciesRequest{FromSeq: midCursor})
				if err != nil {
					return errObservation(err), nil
				}
				resume := drainSeqs(resumeStream)
				if resume.err != nil {
					return errObservation(resume.err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("catch_up_frame_count", "%d", resume.count)
				obs.Setf("catch_up_monotonic_gap_free", "%t", resume.monotonicGapFree)
				obs.Setf("first_caught_up_seq_is_cursor_plus_one", "%t", resume.first == midCursor+1)
				obs.Setf("last_caught_up_seq_is_tail", "%t", resume.last == cursor)
				obs.Setf("no_already_applied_replayed", "%t", resume.count == 0 || resume.first > midCursor)
				return obs, nil
			},
		},
		{
			// from_seq PAST the tail yields an EMPTY catch-up — the host agent is
			// already current, there is nothing newer to apply. from_seq = tail and
			// from_seq far past the tail both close cleanly (io.EOF -> OK), zero
			// frames.
			Name: "watch-policies/from-seq-past-tail-yields-empty-catch-up",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := boundaryv1.NewPolicyStreamServiceClient(conn)
				// Discover the tail via a from-zero drain (gap-free: count=tail).
				baseStream, err := cl.WatchPolicies(ctx, &boundaryv1.WatchPoliciesRequest{FromSeq: 0})
				if err != nil {
					return errObservation(err), nil
				}
				base := drainSeqs(baseStream)
				if base.err != nil {
					return errObservation(base.err), nil
				}
				atTail, err := cl.WatchPolicies(ctx, &boundaryv1.WatchPoliciesRequest{FromSeq: base.last})
				if err != nil {
					return errObservation(err), nil
				}
				atTailDrain := drainSeqs(atTail)
				pastTail, err := cl.WatchPolicies(ctx, &boundaryv1.WatchPoliciesRequest{FromSeq: base.last + 1000})
				if err != nil {
					return errObservation(err), nil
				}
				pastTailDrain := drainSeqs(pastTail)
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("at_tail_frame_count", "%d", atTailDrain.count)
				obs.Setf("at_tail_status", "%s", drainStatus(atTailDrain))
				obs.Setf("past_tail_frame_count", "%d", pastTailDrain.count)
				obs.Setf("past_tail_status", "%s", drainStatus(pastTailDrain))
				return obs, nil
			},
		},
		{
			// The AckPolicy round-trip (doc 13 §5): the consumer streams the tail
			// snapshot, then ACKs its EXACT (seq, content_hash). The ack proves the
			// consumer verified exactly that snapshot before flipping to it — an
			// honest ack returns the empty AckPolicyResponse with status OK. The
			// acked seq/hash are sourced from the SAME stream frame, so the ack is
			// the genuine round-trip a host consumer performs.
			Name: "ack-policy/honest-ack-of-streamed-snapshot-round-trips",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := boundaryv1.NewPolicyStreamServiceClient(conn)
				tailSnap, err := lastStreamedSnapshot(ctx, cl)
				if err != nil {
					return errObservation(err), nil
				}
				_, ackErr := cl.AckPolicy(ctx, &boundaryv1.AckPolicyRequest{
					Seq:         tailSnap.GetSeq(),
					ContentHash: tailSnap.GetContentHash(),
				})
				obs := dualrun.NewObservation()
				obs.Set("ack_status", status.Code(ackErr).String())
				obs.Setf("acked_seq_is_tail", "%t", tailSnap.GetSeq() == seededRowCount)
				obs.Setf("acked_hash_len", "%d", len(tailSnap.GetContentHash()))
				return obs, nil
			},
		},
		{
			// Ack honesty is part of the contract surface a faithful fake must
			// mirror (doc 13 §5: the ack PROVES the consumer verified exactly this
			// snapshot). Three dishonest acks are refused: a seq=0 ack (no snapshot
			// to verify), an ack for a seq the log never streamed (past the tail),
			// and an ack whose content_hash does not match the snapshot at that seq
			// (a lying consumer claiming it verified a snapshot it did not). Each
			// surfaces a distinct, machine-readable refusal status.
			Name: "ack-policy/dishonest-ack-refused",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := boundaryv1.NewPolicyStreamServiceClient(conn)
				tailSnap, err := lastStreamedSnapshot(ctx, cl)
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				// seq=0: nothing to acknowledge.
				_, zeroErr := cl.AckPolicy(ctx, &boundaryv1.AckPolicyRequest{Seq: 0, ContentHash: tailSnap.GetContentHash()})
				obs.Set("ack_seq_zero_status", status.Code(zeroErr).String())
				// seq past the tail: the snapshot was never streamed.
				_, pastErr := cl.AckPolicy(ctx, &boundaryv1.AckPolicyRequest{Seq: tailSnap.GetSeq() + 1000, ContentHash: tailSnap.GetContentHash()})
				obs.Set("ack_past_tail_status", status.Code(pastErr).String())
				// right seq, wrong hash: a lying consumer.
				_, hashErr := cl.AckPolicy(ctx, &boundaryv1.AckPolicyRequest{Seq: tailSnap.GetSeq(), ContentHash: []byte("ds-synthetic-not-the-real-hash")})
				obs.Set("ack_wrong_hash_status", status.Code(hashErr).String())
				return obs, nil
			},
		},
	}
	// The WatchPolicies stream-LIFECYCLE scenarios (mid-stream cancel, deadline,
	// and slow-consumer back-pressure) no longer live in this content suite: they
	// are driven through the SHARED dualrun streaming affordance in their own
	// dedicated suites (streaming.go: StreamingCancelSuite / StreamingBackPressureSuite),
	// the same fold the hypervisor and orchestrator-session seams use. The reserved
	// back-pressure probe machinery they used to need (recvKMonotonicGapFree /
	// drainAfterCancel) is deleted; the affordance is the one tested driver now.
	return base
}

// --- observation builders ----------------------------------------------------

func errObservation(err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", status.Code(err).String())
	return obs
}

// lastStreamedSnapshot opens a from-zero watch, drains it to io.EOF, and returns
// the LAST snapshot frame — the current tail snapshot a consumer would ack. It
// surfaces a transport error so the caller records it identically on both ends.
func lastStreamedSnapshot(ctx context.Context, cl boundaryv1.PolicyStreamServiceClient) (*boundaryv1.PolicySnapshot, error) {
	stream, err := cl.WatchPolicies(ctx, &boundaryv1.WatchPoliciesRequest{FromSeq: 0})
	if err != nil {
		return nil, err
	}
	var last *boundaryv1.PolicySnapshot
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		last = resp.GetSnapshot()
	}
	if last == nil {
		return nil, status.Error(codes.Internal, "WatchPolicies streamed no frames over the seeded log")
	}
	return last, nil
}

// snapshotStreamObservation drains a WatchPolicies stream and records the
// catch-up shape: the frame count, the monotonic-gap-free invariant over the
// delivered seqs, the first/last seq, and the final status. This is the
// server-streaming drain pattern the hypervisor seam uses for ExportDiskDelta —
// Recv until io.EOF.
func snapshotStreamObservation(stream grpc.ServerStreamingClient[boundaryv1.WatchPoliciesResponse]) *dualrun.Observation {
	d := drainSeqs(stream)
	obs := dualrun.NewObservation()
	if d.err != nil {
		obs.Set("status", status.Code(d.err).String())
		return obs
	}
	obs.Set("status", codes.OK.String())
	obs.Setf("frame_count", "%d", d.count)
	obs.Setf("monotonic_gap_free", "%t", d.monotonicGapFree)
	// The seeded log is replayed whole from from_seq=0: gap-free means the first
	// seq is 1 and the last seq equals the frame count.
	obs.Setf("first_seq_is_one", "%t", d.count == 0 || d.first == 1)
	obs.Setf("last_seq_equals_count", "%t", d.count == 0 || d.last == d.count)
	obs.Setf("frame_count_is_seeded_rows", "%t", d.count == seededRowCount)
	return obs
}

// seededPrefixObservation drains a from-zero watch and records the snapshot
// IDENTITY shape over the first seededRowCount frames only, so the observation is
// independent of cross-scenario state. Each frame must carry a monotonic seq, a
// 32-byte content_hash, and a non-empty composed document; the composed document
// is strictly longer at each higher seq (the deny-wins composition grows as rows
// accumulate).
func seededPrefixObservation(stream grpc.ServerStreamingClient[boundaryv1.WatchPoliciesResponse]) *dualrun.Observation {
	obs := dualrun.NewObservation()
	var prevSeq uint64
	var prevDocLen int
	var seen uint64
	seqMonotonic := true
	hashWellFormed := true
	docGrows := true
	for seen < seededRowCount {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			obs.Set("status", status.Code(err).String())
			return obs
		}
		snap := resp.GetSnapshot()
		seen++
		if seen > 1 && snap.GetSeq() != prevSeq+1 {
			seqMonotonic = false
		}
		if len(snap.GetContentHash()) != contentHashBytes {
			hashWellFormed = false
		}
		if len(snap.GetDocument()) == 0 {
			hashWellFormed = false
		}
		if seen > 1 && len(snap.GetDocument()) <= prevDocLen {
			docGrows = false
		}
		prevSeq = snap.GetSeq()
		prevDocLen = len(snap.GetDocument())
	}
	obs.Set("status", codes.OK.String())
	obs.Setf("prefix_frames", "%d", seen)
	obs.Setf("seq_monotonic", "%t", seqMonotonic)
	obs.Setf("content_hash_well_formed", "%t", hashWellFormed)
	obs.Setf("composed_document_grows", "%t", docGrows)
	return obs
}

// drainResult is the outcome of draining a WatchPolicies stream's seqs.
type drainResult struct {
	count            uint64
	first            uint64
	last             uint64
	monotonicGapFree bool
	err              error
}

// drainSeqs Recv-drains a WatchPolicies stream to io.EOF, recording the frame
// count, first/last seq, and whether the delivered seqs are strictly increasing
// by exactly one each (the gap-free, monotonic bigserial invariant, D72). A
// transport/contract error short-circuits into err.
func drainSeqs(stream grpc.ServerStreamingClient[boundaryv1.WatchPoliciesResponse]) drainResult {
	res := drainResult{monotonicGapFree: true}
	var prev uint64
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			res.err = err
			return res
		}
		seq := resp.GetSnapshot().GetSeq()
		res.count++
		if res.count == 1 {
			res.first = seq
		} else if seq != prev+1 {
			res.monotonicGapFree = false
		}
		prev = seq
		res.last = seq
	}
	return res
}

func drainStatus(d drainResult) string {
	if d.err != nil {
		return status.Code(d.err).String()
	}
	return codes.OK.String()
}

// --- dialers: real reference impl AND the generated fake --------------------
//
// Both dialers seed the SAME synthetic policy_log history (so the snapshot tail a
// WatchPolicies(from_seq) catch-up replays is stable on each end) and then expose
// the SAME contract behavior — the only thing that varies across the two dual-run
// passes is which server is registered.

// SeedLog installs the pre-existing policy_log on a reference impl: seededRowCount
// synthetic rows under monotonic seqs 1..N. It is exported so the external _test
// package can seed a mirror identically (the negative drift-gate dialer).
// Synthetic fixtures only (D50).
func SeedLog(impl *RefImpl) {
	impl.SeedRow([]byte("seed-layer-system-baseline"))
	impl.SeedRow([]byte("seed-layer-org-synthetic"))
	impl.SeedRow([]byte("seed-fleet-block-synthetic"))
	// The POL-5 ask-grant-with-TTL row is the TAIL (doc 16 §8.2): a returned
	// approval composed into the deny-wins document and delivered on the policy
	// stream — the grant-delivery vehicle this seam owns. It rides inside the
	// opaque `document` payload of the snapshot, asserted real-vs-fake by the
	// watch-policies/ask-grant-with-ttl-rides-composed-document scenario.
	impl.SeedAskGrantRow()
}

// RealDialer returns the dual-run Dialer for the reference impl, pre-seeded with
// the synthetic policy_log history.
func RealDialer() dualrun.Dialer {
	impl := NewRefImpl()
	SeedLog(impl)
	return dualrun.InProcess(impl.Register)
}

// FakeDialer returns the dual-run Dialer for the GENERATED programmable fake,
// programmed to the same contract by routing its per-verb responders at a mirror
// RefImpl seeded identically — so the fake and the real impl share one honest
// behavior definition (the monotonic gap-free seq log, the snapshot-then-delta
// serving, the ack round-trip and its honesty checks). The dual-run proves the
// fake is observationally identical to the real impl on every scenario.
func FakeDialer() dualrun.Dialer {
	f := programmedFake(SeedLog)
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		boundaryv1fake.RegisterPolicyStreamService(s, f)
	})
}

// programmedFake programs the generated PolicyStreamServiceFake at a mirror
// RefImpl (seeded by the given seeder) so the fake's canned responders ARE the
// honest reference behavior, driven only through the fake's responder surface
// (doc 06 §2.1). The WatchPolicies responder returns the ordered snapshot frames
// the fake's generated streaming responder then sends — exactly the
// ExportDiskDelta-style slice-of-responses shape the fake codegen emits; the
// AckPolicy responder routes straight at the mirror so the ack-honesty checks
// match the real impl.
func programmedFake(seed func(*RefImpl)) *boundaryv1fake.PolicyStreamServiceFake {
	f := boundaryv1fake.NewPolicyStreamServiceFake()
	mirror := NewRefImpl()
	seed(mirror)

	f.AckPolicyResponder = mirror.AckPolicy
	f.WatchPoliciesResponder = func(_ context.Context, req *boundaryv1.WatchPoliciesRequest) ([]*boundaryv1.WatchPoliciesResponse, error) {
		return WrapSnapshots(mirror.SnapshotsFrom(req.GetFromSeq())), nil
	}
	return f
}

// WrapSnapshots wraps composed snapshots in the per-RPC WatchPolicies response
// frame the streaming responder sends. It is exported so the negative drift-gate
// dialer (external _test) can build the same frame slice before injecting its
// drift.
func WrapSnapshots(snaps []*boundaryv1.PolicySnapshot) []*boundaryv1.WatchPoliciesResponse {
	out := make([]*boundaryv1.WatchPoliciesResponse, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, &boundaryv1.WatchPoliciesResponse{Snapshot: s})
	}
	return out
}
