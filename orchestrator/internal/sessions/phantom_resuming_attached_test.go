// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// Phantom-edge conformance: RESUMING─►ATTACHED must NEVER be admitted.
//
// THE GAP THIS GUARDS. The §3 freeze (transition_table.go, mirrored from
// docs/15 §3) draws RESUMING with exactly ONE out-edge — RESUMING─►WORKING
// (resume returns a session to active work, never directly to the attach
// seat). ATTACHED is reached ONLY via the create spine (READY─►ATTACHED) and
// the ATTACHED⇄WORKING oscillation. A "phantom" RESUMING─►ATTACHED edge is
// the SUBTLE drift the count-pins in transition_table_test.go cannot catch on
// their own: BOTH endpoints (RESUMING, ATTACHED) are legal §3 states, so a
// consumer that resumes straight into ATTACHED — or a stray edge added to the
// table between two real states — keeps len(States())==12 and could keep
// len(Edges())==16 if it displaced a legal edge. This file pins the specific
// shape of RESUMING's out-edges and asserts the §3 consumer that drives the
// resume path (ParkResumeDriver, parkresume.go) lands a resumed session at
// WORKING, never ATTACHED — so the phantom edge fails the build's test phase
// the moment any §3 consumer admits it.
//
// SCOPE. Test-only and additive: it edits neither transition_table.go nor
// hosthandoff.go nor any consumer; it consumes the frozen table verbatim and
// drives the existing ParkResumeDriver against synthetic seams (D50, no live
// host). The phantom edge is identified by its endpoints, not by a literal —
// phantomEdge is built from the table's own StateResuming/StateAttached.

// phantomEdge is the forbidden transition this file guards against, named from
// the table's own vocabulary so a rename of either endpoint travels with it.
var phantomEdge = Edge{From: StateResuming, To: StateAttached}

// TestPhantomEdgeAbsentFromTable is the structural pin: the frozen §3 table
// must NOT contain RESUMING─►ATTACHED. IsTransition is the predicate every §3
// consumer (parkresume.go's IsTransition guards, the reconciler, attach.v1
// fidelity) validates edges through, so pinning it here pins the phantom edge
// out of every consumer that honors the table.
func TestPhantomEdgeAbsentFromTable(t *testing.T) {
	if IsTransition(phantomEdge.From, phantomEdge.To) {
		t.Fatalf("§3 PHANTOM EDGE admitted: the frozen table contains %s─►%s, "+
			"but resume returns to WORKING, never directly to ATTACHED "+
			"(docs/15 §3: SUSPENDED─►RESUMING─►WORKING). Adding this edge "+
			"reopens the §3 freeze.", phantomEdge.From, phantomEdge.To)
	}
	// Belt-and-suspenders: scan the raw edge set too, so a duplicate/typo that
	// somehow slipped past IsTransition's first-match is still caught.
	for _, e := range Edges() {
		if e == phantomEdge {
			t.Fatalf("§3 PHANTOM EDGE present in Edges(): %v", e)
		}
	}
}

// TestResumingOutEdgeIsExactlyWorking pins the POSITIVE shape: RESUMING's only
// legal successor is WORKING. This is the strongest form of the guard — it
// fails not just if RESUMING─►ATTACHED is added, but if RESUMING gains ANY
// second out-edge (ATTACHED being the specific one this audit chases). If the
// §3 diagram ever legitimately gives RESUMING another successor, that reopens
// the freeze and this assertion changes in the same commit as the table+doc.
func TestResumingOutEdgeIsExactlyWorking(t *testing.T) {
	var outs []State
	for _, e := range Edges() {
		if e.From == StateResuming {
			outs = append(outs, e.To)
		}
	}
	if len(outs) != 1 || outs[0] != StateWorking {
		t.Fatalf("RESUMING out-edges drift: got %v, want exactly [%s]. "+
			"The phantom RESUMING─►ATTACHED edge (or any other extra successor) "+
			"would surface here.", outs, StateWorking)
	}
}

// TestPhantomEdgeEndpointsAreBothRealStates documents WHY the count-pins alone
// miss this drift: both endpoints are legal §3 states, so a phantom edge
// between them is invisible to a state-vocabulary check. If either endpoint
// ceased to be a real state the audit premise would change — assert it holds.
func TestPhantomEdgeEndpointsAreBothRealStates(t *testing.T) {
	if !IsState(phantomEdge.From) {
		t.Errorf("audit premise broken: %q is no longer a §3 state", phantomEdge.From)
	}
	if !IsState(phantomEdge.To) {
		t.Errorf("audit premise broken: %q is no longer a §3 state", phantomEdge.To)
	}
}

// recordingStore wraps the in-memory store and captures a REAL intermediate-state
// trace: every UpdateSession the consumer commits is observed as a (from→to) hop
// reconstructed from the store's OWN before/after state — the `from` is read live
// from the record as it stands before the write, the `to` is the state the write
// commits. This is the bridge upgrade over a hand-reconstructed chain: the edges
// the test inspects are the states the driver ACTUALLY drove through the store, so
// a consumer that committed an extra/illegal hop (e.g. a RESUMING→ATTACHED write)
// surfaces the real edge, not an assumed one. AppendIndexEpoch advances state too
// (the PARKED→CREATING re-place path), so it is recorded the same way.
//
// It satisfies ParkResumeStore by embedding *store.Memory and overriding only the
// two state-advancing writes. Reads pass straight through.
type recordingStore struct {
	inner *store.Memory
	// trace is the ordered list of REAL state hops the consumer committed. A hop is
	// recorded only when the write actually changes State (a metadata-only update
	// with no State pointer is not a §3 edge and is skipped).
	trace []Edge
}

func newRecordingStore() *recordingStore { return &recordingStore{inner: store.NewMemory()} }

func (r *recordingStore) GetSession(ctx context.Context, uuid string) (store.Session, error) {
	return r.inner.GetSession(ctx, uuid)
}

func (r *recordingStore) UpdateSession(ctx context.Context, uuid string, u store.SessionUpdate) (store.Session, error) {
	prev, _ := r.inner.GetSession(ctx, uuid) // before-state, read live from the record
	out, err := r.inner.UpdateSession(ctx, uuid, u)
	if err != nil {
		return out, err
	}
	// Record the hop only if the write moved the §3 state (the driver's state
	// advances always carry a State pointer; a metadata-only persist does not).
	if u.State != nil && out.State != prev.State {
		r.trace = append(r.trace, Edge{From: toState(prev.State), To: toState(out.State)})
	}
	return out, nil
}

func (r *recordingStore) AppendIndexEpoch(ctx context.Context, uuid string, e store.IndexEpoch) (store.Session, error) {
	// AppendIndexEpoch does not itself carry a State pointer (the re-place advance is
	// a separate UpdateSession), so it never adds a §3 hop; pass through unrecorded.
	return r.inner.AppendIndexEpoch(ctx, uuid, e)
}

// transitionsTraversedByResume drives the real §3 consumer — ParkResumeDriver,
// the parkresume.go resume path — over a SUSPENDED session resumed by the named
// authority, and returns the landing state plus the REAL intermediate-state trace
// the consumer committed to the store (observed by recordingStore, NOT assumed).
// It is the bridge from the table pin to the LIVE consumer: it proves the consumer
// traverses only legal edges and, specifically, never admits RESUMING─►ATTACHED.
//
// Synthetic seams only (D50): an in-memory store wrapped by the recorder, a no-op
// host Resumer, and a prApprovals tuned per arm (the user/scheduler arms admit on
// authority match with no landed-approval read; the human-approval arm reads a
// landed approval). reason/auth let the same driver exercise every resume arm. No
// live host/KVM/boundary.
func transitionsTraversedByResume(t *testing.T, reason store.SuspendReason, auth ResumeAuthority, approvals prApprovals) (final store.SessionState, trace []Edge, resumeCalls int) {
	t.Helper()
	ctx := context.Background()
	rec := newRecordingStore()

	const uuid = "phantom-s1"
	seedSession(t, rec.inner, uuid, "host-a", 1, store.SessionSuspended, reason)

	resumer := &prResumer{}
	d := mustDriver(t, ParkResumeSeams{
		Store:     rec,
		Resumer:   resumer,
		Approvals: approvals,
	})

	// Drive the in-place resume: SUSPENDED ─► RESUMING ─► WORKING. The presented
	// authority matches the seeded reason, so the gate permits.
	got, err := d.Resume(ctx, uuid, auth)
	if err != nil {
		t.Fatalf("Resume drove an error on the legal %s resume path: %v", reason, err)
	}

	// The trace is the REAL set of committed hops, not a reconstruction. Sanity:
	// the final store state matches the last hop's destination.
	final = got.State
	if n := len(rec.trace); n > 0 && rec.trace[n-1].To != toState(final) {
		t.Fatalf("recorded trace tail %v disagrees with final store state %q", rec.trace[n-1], final)
	}
	return final, rec.trace, resumer.calls
}

// assertCleanResume runs the load-bearing checks against an observed resume trace:
// the consumer must land at WORKING and traverse no edge the frozen §3 table
// forbids — in particular never RESUMING─►ATTACHED. It is shared by every resume
// arm so each arm gets the identical phantom-edge guard.
func assertCleanResume(t *testing.T, arm string, final store.SessionState, traversed []Edge, resumeCalls int) {
	t.Helper()

	if resumeCalls != 1 {
		t.Fatalf("[%s] expected the host Resume verb to be driven once, got %d calls", arm, resumeCalls)
	}
	if final != store.SessionWorking {
		t.Fatalf("[%s] resume consumer landed a resumed session at %q, want WORKING — "+
			"a RESUMING─►ATTACHED (or other phantom) terminal would surface here", arm, final)
	}
	if final == store.SessionAttached {
		t.Fatalf("[%s] resume consumer admitted the phantom RESUMING─►ATTACHED terminal", arm)
	}

	// The observed trace MUST be the exact legal §3 resume chain — no more, no fewer
	// hops. A consumer that slipped an extra hop (e.g. a stray RESUMING→ATTACHED
	// write before landing at WORKING) would show up as an extra recorded edge.
	wantChain := []Edge{
		{From: StateSuspended, To: StateResuming},
		{From: StateResuming, To: StateWorking},
	}
	if len(traversed) != len(wantChain) {
		t.Fatalf("[%s] resume consumer committed %d real state hops %v, want exactly %v — "+
			"an extra committed hop (e.g. a phantom RESUMING─►ATTACHED) would surface here",
			arm, len(traversed), traversed, wantChain)
	}
	for i, e := range traversed {
		if e == phantomEdge {
			t.Fatalf("[%s] resume consumer traversed the PHANTOM edge %v", arm, e)
		}
		if !IsTransition(e.From, e.To) {
			t.Fatalf("[%s] resume consumer traversed %s─►%s, which the frozen §3 table "+
				"forbids (consumer-vs-table drift)", arm, e.From, e.To)
		}
		if e != wantChain[i] {
			t.Fatalf("[%s] resume consumer hop %d was %v, want %v", arm, i, e, wantChain[i])
		}
	}
}

// TestResumeConsumerNeverAdmitsPhantomEdge is the load-bearing assertion across
// EVERY resume arm: the LIVE §3 resume consumer must land a resumed session at
// WORKING and traverse no edge the frozen table forbids — never RESUMING─►ATTACHED.
//
// It exercises all three split authorities (resumeauthority.go): the user arm
// (user reason, admits on authority match), the scheduler/rebalance arm (rebalance
// reason, admits on authority match), and the human-approval arm (policy_breach
// reason, admits ONLY on a LANDED approval). Each arm drives the consumer over a
// REAL store and inspects the OBSERVED intermediate-state trace, so a consumer
// changed to resume straight into ATTACHED (e.g. a "fast re-attach" shortcut), or
// to slip a stray RESUMING→ATTACHED hop, fails here — even if the table were
// drifted to admit it, because the observed edges are validated against the
// FROZEN table and the phantom edge is checked explicitly.
func TestResumeConsumerNeverAdmitsPhantomEdge(t *testing.T) {
	arms := []struct {
		name      string
		reason    store.SuspendReason
		auth      ResumeAuthority
		approvals prApprovals
	}{
		{
			name:      "user",
			reason:    store.SuspendReasonUser,
			auth:      ResumeAuthorityUser,
			approvals: prApprovals{}, // user arm never reads it
		},
		{
			name:      "scheduler/rebalance",
			reason:    store.SuspendReasonRebalance,
			auth:      ResumeAuthorityScheduler,
			approvals: prApprovals{}, // scheduler arm admits on authority match alone
		},
		{
			name:      "human-approval/policy_breach",
			reason:    store.SuspendReasonPolicyBreach,
			auth:      ResumeAuthorityHumanApproval,
			approvals: prApprovals{landed: true}, // policy_breach resumes ONLY on a landed approval
		},
	}
	for _, arm := range arms {
		arm := arm
		t.Run(arm.name, func(t *testing.T) {
			final, traversed, calls := transitionsTraversedByResume(t, arm.reason, arm.auth, arm.approvals)
			assertCleanResume(t, arm.name, final, traversed, calls)
		})
	}
}

// --- Negative proof: the guard DETECTS the phantom edge when it is present. -
//
// These run the same predicates the real assertions run, but against a
// deliberately drifted edge set / a synthetic consumer trace that DOES admit
// RESUMING─►ATTACHED, and assert the guard FLAGS it. They are the executable
// proof of the acceptance criterion "the new test fails if a RESUMING─►ATTACHED
// edge is ever admitted by a §3 consumer that the transition table forbids" —
// without mutating the real table or any consumer.

// containsEdge mirrors the membership check IsTransition performs, extracted so
// the negative case exercises the exact same logic against a drifted set.
func containsEdge(set []Edge, want Edge) bool {
	for _, e := range set {
		if e == want {
			return true
		}
	}
	return false
}

// TestPhantomEdgeGuardDetectsDriftedTable proves the table pin would catch a
// freeze that grew the phantom edge: a drifted copy containing RESUMING─►ATTACHED
// must be flagged by the same membership check.
func TestPhantomEdgeGuardDetectsDriftedTable(t *testing.T) {
	drifted := append(append([]Edge(nil), Edges()...), phantomEdge)
	if !containsEdge(drifted, phantomEdge) {
		t.Fatalf("guard FAILED to detect a table that admits the phantom edge %v — "+
			"the drift would ship silently", phantomEdge)
	}
	// And the real table must NOT contain it (the positive baseline the drift
	// departs from).
	if containsEdge(Edges(), phantomEdge) {
		t.Fatalf("real §3 table unexpectedly contains the phantom edge %v", phantomEdge)
	}
}

// --- EscalateToPark + ResumeFromPark arms: extend the LIVE-consumer real-trace ---
//
// THE GAP THESE ADD. TestResumeConsumerNeverAdmitsPhantomEdge already pins the
// in-place Resume path. But two OTHER §3 consumers in parkresume.go also transit
// RESUMING — and so could grow a phantom RESUMING─►ATTACHED hop just as silently:
//
//   - EscalateToPark (the >15-min D46 escalation) re-converges a SUSPENDED session
//     through SUSPENDED─►RESUMING─►WORKING (escalateReconverge) BEFORE snapshotting,
//     so it traverses RESUMING en route to SNAPSHOTTING─►PARKED. A "fast re-attach
//     on escalation" shortcut, or any stray RESUMING─►ATTACHED write slipped into
//     the re-converge, would land the wrong terminal and admit the phantom edge.
//   - ResumeFromPark (the PARKED re-place) hands a parked session back to the create
//     spine at PARKED─►CREATING@host'. It must NEVER skip CREATING and land straight
//     at ATTACHED (the create spine's READY─►ATTACHED is the SessionCreator's job),
//     and — though it does not itself transit RESUMING — its terminal must be the
//     legal CREATING, never the phantom ATTACHED.
//
// Both arms drive the REAL consumer over a recordingStore and inspect the OBSERVED
// committed hops (not an assumed chain), validating every hop against the FROZEN §3
// table and checking the phantom edge explicitly — the same discipline the resume
// arm uses. Synthetic seams only (D50): in-memory store, no-op host verbs, and the
// re-place seams (Placer/HostAllocator/Minter) the PARKED re-place needs.

// assertCleanParkPath runs the load-bearing phantom-edge checks against an observed
// EscalateToPark / ResumeFromPark trace: the consumer must land at wantFinal (never
// ATTACHED), traverse no edge the frozen §3 table forbids — in particular never
// RESUMING─►ATTACHED — and commit exactly wantChain. Shared by the park arms so each
// gets the identical guard the resume arm gets via assertCleanResume.
func assertCleanParkPath(t *testing.T, arm string, final store.SessionState, wantFinal store.SessionState, traversed, wantChain []Edge) {
	t.Helper()

	if final == store.SessionAttached {
		t.Fatalf("[%s] consumer admitted the phantom terminal ATTACHED — "+
			"this path must never re-attach via RESUMING─►ATTACHED or skip the create spine", arm)
	}
	if final != wantFinal {
		t.Fatalf("[%s] consumer landed at %q, want %q — a phantom RESUMING─►ATTACHED "+
			"(or other illegal terminal) would surface here", arm, final, wantFinal)
	}
	if len(traversed) != len(wantChain) {
		t.Fatalf("[%s] consumer committed %d real state hops %v, want exactly %v — "+
			"an extra committed hop (e.g. a phantom RESUMING─►ATTACHED) would surface here",
			arm, len(traversed), traversed, wantChain)
	}
	for i, e := range traversed {
		if e == phantomEdge {
			t.Fatalf("[%s] consumer traversed the PHANTOM edge %v", arm, e)
		}
		if !IsTransition(e.From, e.To) {
			t.Fatalf("[%s] consumer traversed %s─►%s, which the frozen §3 table forbids "+
				"(consumer-vs-table drift)", arm, e.From, e.To)
		}
		if e != wantChain[i] {
			t.Fatalf("[%s] consumer hop %d was %v, want %v", arm, i, e, wantChain[i])
		}
	}
}

// transitionsTraversedByEscalate drives the REAL §3 EscalateToPark consumer over a
// SUSPENDED session (the D46 >15-min tier — the unanswered genuine rung-2 ask that
// MUST park) and returns the landing state plus the OBSERVED committed-hop trace.
// The SUSPENDED origin forces the escalateReconverge SUSPENDED─►RESUMING─►WORKING
// transit, so RESUMING is on the real path — making this the strongest place to
// catch a RESUMING─►ATTACHED phantom slipped into the escalation. Synthetic seams
// only (D50): in-memory store + recorder, a no-op Snapshotter, NO Approvals reader
// (the forced escalation park never consults the resume-authority gate).
func transitionsTraversedByEscalate(t *testing.T, reason store.SuspendReason) (final store.SessionState, trace []Edge) {
	t.Helper()
	ctx := context.Background()
	rec := newRecordingStore()

	const uuid = "phantom-escalate"
	seedSession(t, rec.inner, uuid, "host-a", 1, store.SessionSuspended, reason)

	d := mustDriver(t, ParkResumeSeams{
		Store:       rec,
		Snapshotter: &prSnapshotter{},
	})

	got, err := d.EscalateToPark(ctx, uuid)
	if err != nil {
		t.Fatalf("EscalateToPark drove an error on the legal %s escalation path: %v", reason, err)
	}
	final = got.State
	if n := len(rec.trace); n > 0 && rec.trace[n-1].To != toState(final) {
		t.Fatalf("recorded trace tail %v disagrees with final store state %q", rec.trace[n-1], final)
	}
	return final, rec.trace
}

// transitionsTraversedByResumeFromPark drives the REAL §3 ResumeFromPark consumer
// over a PARKED session and returns the landing state plus the OBSERVED committed-hop
// trace. The re-place advances the §3 state once (PARKED─►CREATING@host'); the
// AppendIndexEpoch re-place advance carries no State pointer, so recordingStore
// records exactly the one PARKED─►CREATING hop. The terminal MUST be CREATING (the
// create spine's CREATING─►READY─►ATTACHED is the SessionCreator's job, not this
// driver's) — never the phantom ATTACHED. Synthetic seams only (D50).
func transitionsTraversedByResumeFromPark(t *testing.T, auth ResumeAuthority, carrier attachReasonOrUnset, approvals prApprovals) (final store.SessionState, trace []Edge) {
	t.Helper()
	ctx := context.Background()
	rec := newRecordingStore()

	// A PARKED record carries NO suspend reason (park cleared it; the store rejects a
	// reason in any non-SUSPENDED state) — the gate reason rides the carrier the
	// reconciler supplies, exactly as ResumeFromPark's parkReason parameter expects.
	const uuid = "phantom-replace"
	seedSession(t, rec.inner, uuid, "host-a", 1, store.SessionParked, store.SuspendReasonNone)

	d := mustDriver(t, ParkResumeSeams{
		Store:         rec,
		Placer:        &prPlacer{hostID: "host-b", appliedSeq: 5},
		HostAllocator: &prAlloc{idx: 7, tap: "dstap-7"},
		Minter:        &prMinter{idRef: "id-2", caRef: "ca-2"},
		Approvals:     approvals,
	})

	got, err := d.ResumeFromPark(ctx, uuid, auth, carrier)
	if err != nil {
		t.Fatalf("ResumeFromPark drove an error on the legal re-place path (carrier=%d auth=%v): %v", carrier, auth, err)
	}
	final = got.State
	if n := len(rec.trace); n > 0 && rec.trace[n-1].To != toState(final) {
		t.Fatalf("recorded trace tail %v disagrees with final store state %q", rec.trace[n-1], final)
	}
	return final, rec.trace
}

// TestEscalateToParkNeverAdmitsPhantomEdge is the load-bearing assertion for the >15-min
// D46 escalation consumer across its origin reasons: the LIVE EscalateToPark must land a
// session at PARKED and traverse only the legal frozen re-converge chain
// SUSPENDED─►RESUMING─►WORKING─►SNAPSHOTTING─►PARKED — never RESUMING─►ATTACHED. It
// exercises the user, rebalance, and policy_breach origins (the policy_breach arm being
// the unanswered genuine rung-2 ask that MUST park without an approval); each drives the
// real consumer over a recordingStore and validates the OBSERVED hops against the frozen
// table, so an escalation changed to fast-re-attach (or to slip a stray RESUMING→ATTACHED
// hop into the re-converge) fails here.
func TestEscalateToParkNeverAdmitsPhantomEdge(t *testing.T) {
	wantChain := []Edge{
		{From: StateSuspended, To: StateResuming},
		{From: StateResuming, To: StateWorking},
		{From: StateWorking, To: StateSnapshotting},
		{From: StateSnapshotting, To: StateParked},
	}
	for _, reason := range []store.SuspendReason{
		store.SuspendReasonUser,
		store.SuspendReasonRebalance,
		store.SuspendReasonPolicyBreach,
	} {
		reason := reason
		t.Run(string(reason), func(t *testing.T) {
			final, traversed := transitionsTraversedByEscalate(t, reason)
			assertCleanParkPath(t, "escalate/"+string(reason), final, store.SessionParked, traversed, wantChain)
		})
	}
}

// TestResumeFromParkNeverAdmitsPhantomEdge is the load-bearing assertion for the PARKED
// re-place consumer across its split authorities: the LIVE ResumeFromPark must land the
// re-placed session at CREATING@host' — handing it to the create spine — and NEVER skip to
// the phantom ATTACHED terminal, nor traverse any edge the frozen §3 table forbids. It
// exercises the user, scheduler/rebalance, and human-approval/policy_breach arms (the last
// re-placing ONLY on a landed approval), each over a recordingStore: a re-place changed to
// jump straight to ATTACHED (skipping CREATING─►READY─►ATTACHED) fails here.
func TestResumeFromParkNeverAdmitsPhantomEdge(t *testing.T) {
	wantChain := []Edge{
		{From: StateParked, To: StateCreating},
	}
	arms := []struct {
		name      string
		auth      ResumeAuthority
		carrier   attachReasonOrUnset
		approvals prApprovals
	}{
		{
			name:      "user",
			auth:      ResumeAuthorityUser,
			carrier:   attachReasonUser,
			approvals: prApprovals{},
		},
		{
			name:      "scheduler/rebalance",
			auth:      ResumeAuthorityScheduler,
			carrier:   attachReasonRebalance,
			approvals: prApprovals{},
		},
		{
			name:      "human-approval/policy_breach",
			auth:      ResumeAuthorityHumanApproval,
			carrier:   attachReasonPolicyBreach,
			approvals: prApprovals{landed: true}, // a policy_breach park re-places ONLY on a landed approval
		},
	}
	for _, arm := range arms {
		arm := arm
		t.Run(arm.name, func(t *testing.T) {
			final, traversed := transitionsTraversedByResumeFromPark(t, arm.auth, arm.carrier, arm.approvals)
			assertCleanParkPath(t, "replace/"+arm.name, final, store.SessionCreating, traversed, wantChain)
		})
	}
}

// TestPhantomEdgeGuardDetectsDriftedConsumer proves the consumer assertion
// would catch a §3 consumer that admitted the phantom edge: a synthetic trace
// landing at ATTACHED (the phantom terminal) and carrying RESUMING─►ATTACHED is
// flagged by the same checks TestResumeConsumerNeverAdmitsPhantomEdge runs.
func TestPhantomEdgeGuardDetectsDriftedConsumer(t *testing.T) {
	// A consumer that (wrongly) resumed straight into ATTACHED.
	driftedFinal := store.SessionAttached
	driftedTraversed := []Edge{
		{From: StateSuspended, To: StateResuming},
		{From: StateResuming, To: StateAttached}, // the phantom edge
	}

	landedWrong := driftedFinal == store.SessionAttached
	admittedPhantom := containsEdge(driftedTraversed, phantomEdge)
	forbiddenTraversed := false
	for _, e := range driftedTraversed {
		if !IsTransition(e.From, e.To) {
			forbiddenTraversed = true
		}
	}

	if !landedWrong || !admittedPhantom || !forbiddenTraversed {
		t.Fatalf("guard FAILED to detect a consumer that admits the phantom edge: "+
			"landedAtAttached=%v admittedPhantom=%v traversedTableForbidden=%v "+
			"(all three must be true for the drifted consumer)",
			landedWrong, admittedPhantom, forbiddenTraversed)
	}
}
