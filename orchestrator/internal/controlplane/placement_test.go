package controlplane

// placement_test.go drives the scheduler adapter (leg c): the orch18 scheduler.Adapter
// is injected as the SessionCreator's Placer (doc 15 §4.1 step 3), and it places against
// synthetic heartbeat candidates from the live feed. The create flow (TestCreateSession)
// already exercises the adapter end-to-end (a create places on the seeded host); these
// tests focus the placement leg: the right host wins, and a stale-policy host is refused
// (D72) and surfaced as the FailedPrecondition the handler maps ErrPolicyStale onto.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/scheduler"
)

// TestPlacement_PicksFreshCandidate proves the injected scheduler.Adapter places a
// create on a candidate the live heartbeat feed reports — the §4.1 step-3 policy-fresh
// placement (D72) running through the orch18 adapter as the coordinator's Placer. The
// create's recorded host is the placed candidate.
func TestPlacement_PicksFreshCandidate(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// The fixture seeds one fresh candidate (testHostID, applied_seq 0 == the empty-log
	// policy head). A create places on it.
	resp, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if got := resp.GetSession().GetHostId(); got != testHostID {
		t.Fatalf("placed host = %q, want %q (the one fresh candidate)", got, testHostID)
	}
}

// TestPlacement_RefusesStaleHost proves the D72 staleness filter: when the only
// candidate's applied_seq lags the current policy head beyond the budget, placement
// refuses with sessions.ErrPolicyStale, which the handler maps onto FailedPrecondition
// (the create is unplaceable, not retryable as-is on this host). It drives the adapter's
// staleness path through the real scheduler filter chain.
func TestPlacement_RefusesStaleHost(t *testing.T) {
	// MaxStalenessGap 0 = the host must be exactly current. Seed a policy head > the
	// host's applied_seq so the only candidate is stale.
	f := newFixture(t, fixtureOpts{schedConfig: scheduler.Config{MaxStalenessGap: 0}})

	// Advance the policy head past the candidate's applied_seq: append a policy row so
	// the head is 1, while the seeded heartbeat reports applied_seq 0 (stale by 1).
	if _, err := f.st.AppendPolicy(context.Background(), policyRow("admin-1")); err != nil {
		t.Fatalf("seed policy head: %v", err)
	}
	// Re-record the host's heartbeat at applied_seq 0 (it has NOT applied the new policy).
	f.cp.Heartbeats.Record(freshHeartbeat(testHostID, 0, 1))

	_, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err == nil {
		t.Fatal("CreateSession: expected an ErrPolicyStale refusal for a stale host")
	}
	if st, _ := status.FromError(err); st.Code() != codes.FailedPrecondition {
		t.Fatalf("CreateSession error code = %v, want FailedPrecondition; err=%v", st.Code(), err)
	}
	// No host-side work happened (placement is step 3, before the host clone/mint at 4/5).
	if len(f.drv.CloneFromImageRecorded()) != 0 {
		t.Errorf("stale-host create did host clone: %d, want 0", len(f.drv.CloneFromImageRecorded()))
	}
}

// TestPlacement_NoCandidateRefuses proves a create against an EMPTY heartbeat feed (no
// host reported in scope) is refused — the adapter maps the scheduler's no-candidates
// Unschedulable onto a placement shortage the create surfaces, with NO host-side work.
// The fixture is built with an empty feed so the wired adapter sees no candidate.
func TestPlacement_NoCandidateRefuses(t *testing.T) {
	f := newFixtureEmptyFeed(t)

	_, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err == nil {
		t.Fatal("CreateSession: expected a placement refusal with no candidate hosts")
	}
	// No host-side work happened — placement (step 3) failed before the clone (step 4).
	if len(f.drv.CloneFromImageRecorded()) != 0 {
		t.Errorf("no-candidate create did host clone: %d, want 0", len(f.drv.CloneFromImageRecorded()))
	}
}
