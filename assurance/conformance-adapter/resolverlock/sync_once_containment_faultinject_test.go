// SPDX-License-Identifier: Apache-2.0

//go:build resolverlock_faultinject

// Build-tagged fault-injection double for the sync.Once CONTAINMENT arm.
//
// The complementarity guard (TestSyncOnceScanComplementaritySuperset in
// drift_corpus_test.go) asserts syntactic ⊆ type-resolved: every syntactically-declared
// sync.Once guard MUST also appear in the type-resolved scan. Today every package-level
// sync.Once is a no-initializer value-form guard, so the two scans return EQUAL sets and
// the CONTAINMENT arm is LATENT — it has never been exercised on a real violation, so a
// future refactor could silently weaken the predicate and nothing would notice.
//
// This file closes that gap WITHOUT polluting the normal build: it is compiled ONLY under
// the `resolverlock_faultinject` build tag (a CI fault-injection lane), so the default
// `go test ./resolverlock/...` gate never sees it and stays green. Under the tag it drives
// the SAME pure predicate the real guard calls — syncOnceContainmentViolations — over a
// SYNTHETIC diverging (syntactic, type-resolved) pair where the syntactic set carries a
// guard the type-resolved set is MISSING, and asserts the predicate REDDENS by naming
// exactly that injected offender. That makes the containment arm's bite PROVEN rather than
// merely code-read: if a future edit weakened syncOnceContainmentViolations so a syntactic
// guard missing from the type-resolved set no longer surfaced, THIS test (run in the
// fault-injection lane: `go test -tags resolverlock_faultinject ./resolverlock/...`) would
// fail loudly.
//
// Test-only/additive (D50): it touches no corpus byte, no production crate, and no
// real scan — it feeds the pure predicate synthetic name sets in-process and offline.

package resolverlock

import (
	"sort"
	"testing"
)

// TestSyncOnceContainmentArmBites proves the CONTAINMENT (syntactic ⊆ type-resolved) arm of
// TestSyncOnceScanComplementaritySuperset actually BITES. The real scans are equal today so
// the arm is latent; here we INJECT a divergence — a syntactic guard absent from the
// type-resolved set — and assert syncOnceContainmentViolations flags exactly it. It also
// pins the no-false-positive direction: an equal pair (the real-world shape) yields zero
// violations.
func TestSyncOnceContainmentArmBites(t *testing.T) {
	// The known-good anchor plus an INJECTED syntactic-only guard the type-resolved scan
	// "went blind to" — the exact regression the containment arm must catch.
	const anchor = "exportedErrorVarsOnce"
	const injected = "faultInjectedSyntacticOnlyOnce"

	declared := []string{anchor, injected}       // SYNTACTIC: carries the injected extra.
	resolvedSet := map[string]bool{anchor: true} // TYPE-RESOLVED: MISSING the injected guard.

	violations := syncOnceContainmentViolations(declared, resolvedSet)

	if len(violations) != 1 || violations[0] != injected {
		t.Fatalf("the CONTAINMENT arm did NOT bite the injected divergence: "+
			"syncOnceContainmentViolations(%v, %v) = %v, want exactly [%q]. The arm MUST flag a "+
			"syntactically-declared guard missing from the type-resolved set — if this regressed, a "+
			"guard could satisfy the syntactic registry arm while ESCAPING the type-resolved arm and "+
			"the complementarity claim would be hollow.", declared, resolvedSet, violations, injected)
	}

	// NO FALSE POSITIVE: an equal pair (the real-world shape, syntactic == type-resolved) must
	// yield ZERO containment violations, so the live guard does not spuriously redden.
	equalDeclared := []string{anchor}
	equalResolved := map[string]bool{anchor: true}
	if clean := syncOnceContainmentViolations(equalDeclared, equalResolved); len(clean) != 0 {
		sort.Strings(clean)
		t.Fatalf("an EQUAL (syntactic == type-resolved) pair must produce NO containment violations "+
			"(no false positive), got: %v", clean)
	}
}
