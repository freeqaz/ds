// SPDX-License-Identifier: Apache-2.0

// Full-rotation ordering-clause tests (doc 16 §6.2/§6.3): the fleet-registration
// surface carries the ordering statement (session leg first, fleet leg second)
// and the fleet no-gap-proof clause (the policy-log retire append, NOT the shared
// retiring-set drop). These pin that documentation seam so the clause the
// operator/auditor runbook cites is single-sourced from code and cannot drift.
// Pure in-process assertions — no live boundary (the wave rule); SYNTHETIC ONLY
// (D50).
package fleetreg

import (
	"strings"
	"testing"
)

// TestFullRotationOrderIsSessionThenFleet pins the fixed leg order a full
// rotation runs: session first, fleet second (mirroring
// digest.KeyManager.FullRotation).
func TestFullRotationOrderIsSessionThenFleet(t *testing.T) {
	order := FullRotationOrder()
	if len(order) != 2 {
		t.Fatalf("FullRotationOrder has %d legs, want 2 (session then fleet)", len(order))
	}
	if order[0] != RotationLegSession {
		t.Errorf("first leg %v, want session", order[0])
	}
	if order[1] != RotationLegFleet {
		t.Errorf("second leg %v, want fleet", order[1])
	}
}

// TestRotationLegString pins the human-readable leg names the runbook renders.
func TestRotationLegString(t *testing.T) {
	cases := []struct {
		leg  RotationLeg
		want string
	}{
		{RotationLegSession, "session"},
		{RotationLegFleet, "fleet"},
		{RotationLeg(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.leg.String(); got != c.want {
			t.Errorf("RotationLeg(%d).String() = %q, want %q", c.leg, got, c.want)
		}
	}
}

// TestFullRotationOrderingClauseStatesTheFleetNoGapProof is the load-bearing
// assertion: the rendered clause states the leg ORDER and — critically — that the
// fleet no-gap proof is the policy-log retire APPEND, NOT the shared retiring-set
// drop. This is exactly the statement the task requires so the shared-set
// bookkeeping is never misread as the fleet guarantee.
func TestFullRotationOrderingClauseStatesTheFleetNoGapProof(t *testing.T) {
	clause := FullRotationOrdering()

	// The ordering: session leg first, fleet leg second.
	if !strings.Contains(clause, "session leg") || !strings.Contains(clause, "first") {
		t.Errorf("ordering clause does not state the session leg runs first: %q", clause)
	}
	if !strings.Contains(clause, "fleet leg") || !strings.Contains(clause, "second") {
		t.Errorf("ordering clause does not state the fleet leg runs second: %q", clause)
	}
	// The fleet no-gap proof IS the policy_log retire append.
	if !strings.Contains(clause, "policy_log retire APPEND") {
		t.Errorf("ordering clause does not name the policy_log retire append as the fleet no-gap proof: %q", clause)
	}
	// And it EXPLICITLY denies the shared retiring-set drop is the proof.
	if !strings.Contains(clause, "NOT the shared retiring-set drop") {
		t.Errorf("ordering clause does not explicitly exclude the shared retiring-set drop as the fleet proof: %q", clause)
	}
}
