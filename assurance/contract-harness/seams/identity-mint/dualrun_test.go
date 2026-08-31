// SPDX-License-Identifier: Apache-2.0

package identitymint_test

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	identitymint "github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/identity-mint"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
)

// TestSeam_RealVsGeneratedFake is the per-commit gate for the
// orchestrator/ds-tlsproxy <-> identity MintInterceptionCA seam (doc 16 §4/§9,
// doc 06 §2.1): the seam's conformance suite runs against BOTH the real
// reference implementation AND the generated programmable fake, and the seam is
// green only if every scenario observes the same thing on both. The suite
// exercises the ONLY verb the proto exposes — MintInterceptionCA — plus
// idempotency on the session key, the D82 interception-vs-workload root
// separation where observable, and the honest InvalidArgument refusal.
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := identitymint.Suite().Run(context.Background(), identitymint.RealDialer(), identitymint.FakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("identity MintInterceptionCA seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_HarnessCatchesADriftedFake is the negative proof: a fake that drifts
// from the contract (here, a MintInterceptionCA that mints a FRESH second CA on
// the idempotent re-issue instead of returning the same per-session material —
// the doc 16 §4 per-session-lifecycle violation) must fail the seam. Without
// this, a green dual-run would be meaningless — it could be passing because the
// gate never fires. The drift is injected only in this test's local fake, never
// in the committed generated fake.
func TestSeam_HarnessCatchesADriftedFake(t *testing.T) {
	res, err := identitymint.Suite().Run(context.Background(), identitymint.RealDialer(), driftedMintFakeDialer())
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

// TestIdempotencyAndSeparation_RecordedViaFakeAccessors asserts the contract
// directly against the generated fake's MintInterceptionCARecorded() call-capture
// accessor (doc 16 §4 / §9). Re-issuing MintInterceptionCA with the same session
// key is observably a no-op on the RESULT (same per-session CA material), the
// minted material is interception-rooted and carries NO workload-root material
// (the D82 separation), AND the fake records EVERY call — so the test proves the
// recorder sees both mint issues while the contract collapses them to one
// per-session CA. This is the assertion the dual-run alone cannot make: the
// dual-run compares end-observable outcomes; the recorded-call surface is what
// lets a downstream consumer verify "the mint was asked twice and minted once".
func TestIdempotencyAndSeparation_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()
	f := identityv1fake.NewIdentityMintServiceFake()

	// Program just enough honest behavior to observe the contract: a stable
	// per-session CA, minted under the interception root, idempotent on the key.
	cas := map[string]*identityv1.MintInterceptionCAResponse{}
	f.MintInterceptionCAResponder = func(_ context.Context, req *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
		uuid := req.GetSessionRef().GetSessionUuid()
		if rec, ok := cas[uuid]; ok {
			return rec, nil // idempotent re-issue -> same per-session material
		}
		rec := identitymint.MintedCAFor(uuid)
		cas[uuid] = rec
		return rec, nil
	}

	const synthUUID = "ses-synthetic-recorded-dddd3333"
	req := &identityv1.MintInterceptionCARequest{SessionRef: identitymint.SessionRef(synthUUID)}

	first, err := f.MintInterceptionCA(ctx, req)
	if err != nil {
		t.Fatalf("first MintInterceptionCA: %v", err)
	}
	second, err := f.MintInterceptionCA(ctx, req)
	if err != nil {
		t.Fatalf("second MintInterceptionCA: %v", err)
	}

	// Idempotent on the session key: same per-session material both times.
	if !bytes.Equal(first.GetCaCertificate(), second.GetCaCertificate()) ||
		!bytes.Equal(first.GetCaPrivateKey(), second.GetCaPrivateKey()) ||
		first.GetExpiryUnixSeconds() != second.GetExpiryUnixSeconds() {
		t.Fatalf("MintInterceptionCA not idempotent on session key: %v vs %v", first, second)
	}

	// D82 separation, where observable: interception-rooted, never workload-rooted.
	interceptionTag := []byte("root=" + identitymint.InterceptionRootID())
	workloadTag := []byte("root=" + identitymint.WorkloadRootID())
	if !bytes.Contains(first.GetCaCertificate(), interceptionTag) {
		t.Fatalf("minted CA cert is not interception-rooted (D82): %q", first.GetCaCertificate())
	}
	if bytes.Contains(first.GetCaCertificate(), workloadTag) {
		t.Fatalf("minted CA cert carries WORKLOAD-root material — the D82 separation is broken: %q", first.GetCaCertificate())
	}
	if bytes.Contains(first.GetCaPrivateKey(), workloadTag) {
		t.Fatalf("minted CA key carries WORKLOAD-root material — the D82 separation is broken: %q", first.GetCaPrivateKey())
	}

	// The recorder must have captured BOTH issues, each carrying the same key.
	calls := f.MintInterceptionCARecorded()
	if len(calls) != 2 {
		t.Fatalf("MintInterceptionCARecorded: want 2 captured calls, got %d", len(calls))
	}
	for i, c := range calls {
		if got := c.Req.GetSessionRef().GetSessionUuid(); got != synthUUID {
			t.Fatalf("MintInterceptionCARecorded[%d].session_uuid = %q, want %q", i, got, synthUUID)
		}
	}
}

// driftedMintFakeDialer programs the generated fake with a deliberately wrong
// MintInterceptionCA responder (mints a FRESH second CA on the idempotent
// re-issue instead of returning the same per-session material, breaking the
// doc 16 §4 per-session-lifecycle contract) to prove the gate bites. The drift
// is visible to the suite via the idempotent_material observation diverging.
func driftedMintFakeDialer() dualrun.Dialer {
	f := identityv1fake.NewIdentityMintServiceFake()
	mirror := identitymint.NewRefImpl()

	var mintCount int
	f.MintInterceptionCAResponder = func(ctx context.Context, req *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
		mintCount++
		if mintCount > 1 && req.GetSessionRef().GetSessionUuid() != "" {
			// DRIFT: a re-issue must return the SAME per-session CA; this mints a
			// fresh second CA (different expiry), violating doc 16 §4.
			resp := identitymint.MintedCAFor(req.GetSessionRef().GetSessionUuid())
			resp.ExpiryUnixSeconds++ // a freshly-allocated, divergent CA
			return resp, nil
		}
		return mirror.MintInterceptionCA(ctx, req)
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		identityv1fake.RegisterIdentityMintService(s, f)
	})
}
