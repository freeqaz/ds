// SPDX-License-Identifier: Apache-2.0

package orchestratorpolicy

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"
)

// Synthetic fixtures (D50). Every identifier is obviously-synthetic — no real
// actors, hosts, sessions, or policy bodies. The SEEDED rows are installed
// identically on BOTH dialers (the "pre-existing policy_log" a WatchPolicies
// catch-up replays); NO scenario depends on absolute seq values that differ
// across ends — both ends start from the same seeded log and every mutating
// scenario runs in the same declaration order against both, so the policy_log
// evolves identically on each end. Scenarios record contract-observable
// INVARIANTS (monotone, gap-free, snapshot identity shape) plus the seeded-tail
// facts that are stable by construction.
const (
	synthHostID      = "host-synthetic-policy-01"
	synthActorOrg    = "actor-synthetic-org-admin"
	synthActorAppr   = "actor-synthetic-approver"
	synthSessGrant   = "ses-9ra919ra-0000-4000-8000-aaaaaaaaaaaa"
	synthToolUseID   = "toolu-synthetic-cafef00d"
	synthGrantScope  = "allow-once:synthetic-domain"
	seededRowCount   = uint64(3) // org-edit, fleet-block, org-edit — the pre-existing log
	contentHashBytes = 32        // SHA-256 digest length (snapshot content_hash)
)

// Suite is the orchestrator.v1 PolicyService seam's single conformance suite (doc
// 06 §3a: one suite, run against real + fake). Every scenario is stated purely in
// terms of the frozen PolicyService contract (doc 15 §5.3, D36/D72) so the same
// suite is meaningful against any faithful implementation: the policy_log's
// monotonic gap-free bigserial seq is THE single policy version namespace, and
// WatchPolicies(from_seq) serves the composed snapshot-then-delta tail, resumable
// from an arbitrary cursor.
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "orchestrator<->hostagent(policy_log)",
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
				cl := orchestratorv1.NewPolicyServiceClient(conn)
				stream, err := cl.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{
					FromSeq: 0,
					HostId:  synthHostID,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return snapshotStreamObservation(stream), nil
			},
		},
		{
			// AppendPolicy assigns the NEXT monotonic seq (= tail+1, gap-free).
			// Two appends advance the single version namespace by exactly one
			// each; the returned rows record the actor (the log IS the audit
			// trail, D36).
			Name: "append-policy/assigns-next-monotonic-gap-free-seq",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewPolicyServiceClient(conn)
				first, err := cl.AppendPolicy(ctx, &orchestratorv1.AppendPolicyRequest{
					Actor:    synthActorOrg,
					Scope:    "org/synthetic",
					Document: []byte("layer-synthetic-A"),
				})
				if err != nil {
					return errObservation(err), nil
				}
				second, err := cl.AppendPolicy(ctx, &orchestratorv1.AppendPolicyRequest{
					Actor:    synthActorOrg,
					Scope:    "org/synthetic",
					Document: []byte("layer-synthetic-B"),
				})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("first_actor", first.GetRow().GetActor())
				obs.Set("first_kind", first.GetRow().GetKind().String())
				// The delta between consecutive appends is exactly 1 (gap-free,
				// monotonic) — recorded as the contract fact, not the absolute
				// seq (which depends on cross-scenario log growth).
				obs.Setf("seq_delta_is_one", "%t", second.GetRow().GetSeq() == first.GetRow().GetSeq()+1)
				obs.Setf("second_after_first", "%t", second.GetRow().GetSeq() > first.GetRow().GetSeq())
				obs.Setf("content_hash_len", "%d", len(second.GetRow().GetContentHash()))
				return obs, nil
			},
		},
		{
			// ApproveAsk appends an ask-grant under the SAME monotonic seq log
			// (ask-grants are policy artifacts under the policy_log seq, doc 15
			// §4.3) — NOT a second namespace. The returned row carries the
			// ASK_GRANT kind and the approver actor.
			Name: "approve-ask/grant-rides-same-seq-namespace",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewPolicyServiceClient(conn)
				// Append one policy row, then a grant: the grant's seq must be
				// the policy row's seq + 1 (one shared bigserial namespace).
				edit, err := cl.AppendPolicy(ctx, &orchestratorv1.AppendPolicyRequest{
					Actor:    synthActorOrg,
					Scope:    "org/synthetic",
					Document: []byte("layer-synthetic-C"),
				})
				if err != nil {
					return errObservation(err), nil
				}
				grant, err := cl.ApproveAsk(ctx, &orchestratorv1.ApproveAskRequest{
					Actor:       synthActorAppr,
					SessionUuid: synthSessGrant,
					ToolUseId:   synthToolUseID,
					GrantScope:  synthGrantScope,
					TtlSeconds:  300,
				})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("grant_actor", grant.GetRow().GetActor())
				obs.Set("grant_kind", grant.GetRow().GetKind().String())
				obs.Setf("grant_seq_follows_edit", "%t", grant.GetRow().GetSeq() == edit.GetRow().GetSeq()+1)
				obs.Setf("content_hash_len", "%d", len(grant.GetRow().GetContentHash()))
				return obs, nil
			},
		},
		{
			// Resumability from an ARBITRARY from_seq: open a watch at exactly
			// the seeded tail, capture the new tail, append two rows, then
			// re-open the watch from the captured cursor — the catch-up delivers
			// EXACTLY the two new seqs, monotonic and gap-free, and NOTHING
			// already-applied. This is the host-agent reconnect path (D36).
			Name: "watch-policies/resumable-from-arbitrary-from-seq",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewPolicyServiceClient(conn)
				// Establish the resume cursor = current tail (drain a from-zero
				// watch and take its last seq; gap-free so last = count).
				baseStream, err := cl.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{FromSeq: 0, HostId: synthHostID})
				if err != nil {
					return errObservation(err), nil
				}
				base := drainSeqs(baseStream)
				if base.err != nil {
					return errObservation(base.err), nil
				}
				cursor := base.last
				// Append exactly two new rows past the cursor.
				if _, err := cl.AppendPolicy(ctx, &orchestratorv1.AppendPolicyRequest{Actor: synthActorOrg, Scope: "org/synthetic", Document: []byte("resume-layer-1")}); err != nil {
					return errObservation(err), nil
				}
				if _, err := cl.AppendPolicy(ctx, &orchestratorv1.AppendPolicyRequest{Actor: synthActorOrg, Scope: "org/synthetic", Document: []byte("resume-layer-2")}); err != nil {
					return errObservation(err), nil
				}
				// Re-open from the cursor: the catch-up is exactly the two new
				// seqs (cursor+1, cursor+2), monotonic and gap-free.
				resumeStream, err := cl.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{FromSeq: cursor, HostId: synthHostID})
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
				obs.Setf("first_caught_up_seq_is_cursor_plus_one", "%t", resume.first == cursor+1)
				obs.Setf("last_caught_up_seq_is_cursor_plus_count", "%t", resume.last == cursor+resume.count)
				obs.Setf("no_already_applied_replayed", "%t", resume.first > cursor)
				return obs, nil
			},
		},
		{
			// from_seq PAST the tail yields an EMPTY catch-up — the host agent is
			// already current, there is nothing newer to apply. The stream still
			// closes cleanly (io.EOF -> OK), zero frames.
			Name: "watch-policies/from-seq-past-tail-yields-empty-catch-up",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewPolicyServiceClient(conn)
				// Discover the tail via a from-zero drain (gap-free: count=tail).
				baseStream, err := cl.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{FromSeq: 0, HostId: synthHostID})
				if err != nil {
					return errObservation(err), nil
				}
				base := drainSeqs(baseStream)
				if base.err != nil {
					return errObservation(base.err), nil
				}
				// from_seq = tail (and tail+far) are both already-current.
				atTail, err := cl.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{FromSeq: base.last, HostId: synthHostID})
				if err != nil {
					return errObservation(err), nil
				}
				atTailDrain := drainSeqs(atTail)
				pastTail, err := cl.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{FromSeq: base.last + 1000, HostId: synthHostID})
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
			// Snapshot identity SHAPE (doc 13 §5): every delivered frame carries
			// (seq, content_hash, document); content_hash is the 32-byte SHA-256
			// over the composed document and is non-empty; the document grows
			// with the composed log. Recorded over the SEEDED tail (stable on
			// both ends because the seed is installed identically).
			Name: "watch-policies/snapshot-then-delta-identity-shape",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewPolicyServiceClient(conn)
				// Replay only the first `seededRowCount` rows so the observation
				// is independent of cross-scenario appends: from_seq=0 then take
				// the first seededRowCount frames.
				stream, err := cl.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{FromSeq: 0, HostId: synthHostID})
				if err != nil {
					return errObservation(err), nil
				}
				return seededPrefixObservation(stream), nil
			},
		},
		{
			// Argument validation is part of the contract surface a faithful fake
			// must mirror: a watch with no host_id is refused (EXACTLY ONE
			// subscriber per host is keyed on host identity, D72), and an append
			// with no actor is refused (the log IS the audit trail, D36).
			Name: "validation/missing-host-id-and-actor-refused",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewPolicyServiceClient(conn)
				watchStream, err := cl.WatchPolicies(ctx, &orchestratorv1.WatchPoliciesRequest{FromSeq: 0})
				obs := dualrun.NewObservation()
				if err != nil {
					obs.Set("watch_no_host_status", status.Code(err).String())
				} else {
					_, recvErr := watchStream.Recv()
					obs.Set("watch_no_host_status", status.Code(recvErr).String())
				}
				_, appendErr := cl.AppendPolicy(ctx, &orchestratorv1.AppendPolicyRequest{Scope: "org/synthetic", Document: []byte("no-actor")})
				obs.Set("append_no_actor_status", status.Code(appendErr).String())
				_, grantErr := cl.ApproveAsk(ctx, &orchestratorv1.ApproveAskRequest{SessionUuid: synthSessGrant, GrantScope: synthGrantScope})
				obs.Set("approve_no_actor_status", status.Code(grantErr).String())
				return obs, nil
			},
		},
	}
	// The WatchPolicies stream-LIFECYCLE scenarios (mid-stream cancel, deadline,
	// slow-consumer back-pressure) no longer live in this content suite: they are
	// driven through the SHARED dualrun streaming affordance in their own dedicated
	// suites (streaming.go: StreamingCancelSuite / StreamingBackPressureSuite), the
	// same fold the hypervisor and orchestrator-session seams use. The bespoke
	// seed-a-large-tail / readPrefix / streamTornDown / drainFullOrdered machinery is
	// deleted; the affordance is the one tested driver now.
	return base
}

// --- observation builders ----------------------------------------------------

func errObservation(err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", status.Code(err).String())
	return obs
}

// snapshotStreamObservation drains a WatchPolicies stream and records the
// catch-up shape: the frame count, the monotonic-gap-free invariant over the
// delivered seqs, the first/last seq, and the final status. This is the
// server-streaming drain pattern the hypervisor seam uses for ExportDiskDelta —
// Recv until io.EOF.
func snapshotStreamObservation(stream grpc.ServerStreamingClient[orchestratorv1.WatchPoliciesResponse]) *dualrun.Observation {
	d := drainSeqs(stream)
	obs := dualrun.NewObservation()
	if d.err != nil {
		obs.Set("status", status.Code(d.err).String())
		return obs
	}
	obs.Set("status", codes.OK.String())
	obs.Setf("frame_count", "%d", d.count)
	obs.Setf("monotonic_gap_free", "%t", d.monotonicGapFree)
	// The seeded log is replayed whole from from_seq=0: gap-free means the
	// first seq is 1 and the last seq equals the frame count.
	obs.Setf("first_seq_is_one", "%t", d.count == 0 || d.first == 1)
	obs.Setf("last_seq_equals_count", "%t", d.count == 0 || d.last == d.count)
	obs.Setf("at_least_seeded_rows", "%t", d.count >= seededRowCount)
	return obs
}

// seededPrefixObservation drains a from-zero watch and records the snapshot
// IDENTITY shape over the first seededRowCount frames only, so the observation is
// independent of cross-scenario appends. Each frame must carry a monotonic seq,
// a 32-byte content_hash, and a non-empty composed document; the composed
// document is strictly longer at each higher seq (the deny-wins composition grows
// as rows accumulate).
func seededPrefixObservation(stream grpc.ServerStreamingClient[orchestratorv1.WatchPoliciesResponse]) *dualrun.Observation {
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
func drainSeqs(stream grpc.ServerStreamingClient[orchestratorv1.WatchPoliciesResponse]) drainResult {
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

// SeedLog installs the pre-existing policy_log on a reference impl:
// seededRowCount synthetic rows under monotonic seqs 1..N. It is exported so the
// external _test package can seed a mirror identically (the negative drift-gate
// dialer). Synthetic fixtures only (D50).
func SeedLog(impl *RefImpl) {
	impl.SeedRow(synthActorOrg, orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ORG_EDIT, []byte("seed-layer-system-baseline"))
	impl.SeedRow(synthActorOrg, orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_FLEET_BLOCK, []byte("seed-fleet-block-synthetic"))
	impl.SeedRow(synthActorOrg, orchestratorv1.PolicyRowKind_POLICY_ROW_KIND_ORG_EDIT, []byte("seed-layer-org-synthetic"))
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
// serving, the validation refusals). The dual-run proves the fake is
// observationally identical to the real impl on every scenario.
func FakeDialer() dualrun.Dialer {
	f := programmedFake(SeedLog)
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		orchestratorv1fake.RegisterPolicyService(s, f)
	})
}

// programmedFake programs the generated PolicyServiceFake at a mirror RefImpl
// (seeded by the given seeder) so the fake's canned responders ARE the honest
// reference behavior, driven only through the fake's responder surface (doc 06
// §2.1). The WatchPolicies responder returns the ordered snapshot frames the
// fake's generated streaming responder then sends — exactly the
// ExportDiskDelta-style slice-of-responses shape the fake codegen emits.
func programmedFake(seed func(*RefImpl)) *orchestratorv1fake.PolicyServiceFake {
	f := orchestratorv1fake.NewPolicyServiceFake()
	mirror := NewRefImpl()
	seed(mirror)

	f.AppendPolicyResponder = mirror.AppendPolicy
	f.ApproveAskResponder = mirror.ApproveAsk
	f.WatchPoliciesResponder = func(_ context.Context, req *orchestratorv1.WatchPoliciesRequest) ([]*orchestratorv1.WatchPoliciesResponse, error) {
		if req.GetHostId() == "" {
			return nil, status.Error(codes.InvalidArgument, "WatchPoliciesRequest.host_id is required (EXACTLY ONE subscriber per host, D72)")
		}
		return WrapSnapshots(mirror.SnapshotsFrom(req.GetFromSeq())), nil
	}
	return f
}

// WrapSnapshots wraps composed snapshots in the per-RPC WatchPolicies response
// frame the streaming responder sends. It is exported so the negative drift-gate
// dialer (external _test) can build the same frame slice before injecting its
// drift.
func WrapSnapshots(snaps []*boundaryv1.PolicySnapshot) []*orchestratorv1.WatchPoliciesResponse {
	out := make([]*orchestratorv1.WatchPoliciesResponse, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, &orchestratorv1.WatchPoliciesResponse{Snapshot: s})
	}
	return out
}
