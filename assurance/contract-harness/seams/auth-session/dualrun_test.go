// SPDX-License-Identifier: Apache-2.0

package authsession_test

import (
	"context"
	"testing"

	authsession "github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/auth-session"
)

// TestSeam_RealVsGeneratedFake is the per-commit gate for the
// orchestrator(fan-out)<->auth TokenAttenuationService seam (D126/D129, doc 23
// §9, doc 06 §2.1): the seam's conformance suite runs against BOTH the real
// reference implementation AND the generated programmable fake, and the seam is
// green only if every scenario observes the same outcome on both.  The suite
// exercises DeriveAgentToken and ListDerivedTokens across the three invariants:
// token-narrowing-monotonicity, token-chain-revocation, and
// token-hierarchy-separation.
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := authsession.Suite().Run(
		context.Background(),
		authsession.RealDialer(),
		authsession.FakeDialer(),
	)
	if err != nil {
		t.Fatalf("dual-run harness error: %v", err)
	}
	if !res.OK() {
		t.Fatalf("TokenAttenuation seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}
