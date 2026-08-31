// SPDX-License-Identifier: Apache-2.0

package identitydigestfeed_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	identitydigestfeed "github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/identity-digestfeed"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
)

// --- recorder-layer cancel-masking guard (PREVENTIVE) ------------------------
//
// The dual-run gate (TestSeam_RealVsGeneratedFake) proves real and fake AGREE on
// every scenario's Observation. For a CLIENT-STREAMING cancel scenario that
// agreement is VACUOUS: if the client cancels mid-stream and the scenario folds
// the terminal status away (records nothing, or records a constant), then a real
// impl that SWALLOWS the cancellation and returns OK and a fake that also returns
// OK observe identically — the seam stays green while cancellation was silently
// masked. The recorder layer, not the diff, is where Canceled must be kept
// distinct from a spurious OK.
//
// The DigestFeedService is entirely UNARY today: DigestPublish and DigestRevoke
// are unary verbs, so the service has no streams at all (Streams is empty —
// ClientStreams is false everywhere; see
// TestRecorderCancelMaskGuard_NoClientStreamingVerbYet). So this is a STANDING
// TRIP-WIRE: it asserts the recorder convention the seam already uses
// (statusObservation-style "status"=status.Code(err).String()) DOES distinguish
// Canceled from OK, and it fails the instant a client-streaming verb is added to
// the contract without a cancel scenario whose Observation makes that
// distinction. Synthetic codes only (D50); no real client-streaming verb is added
// (that would touch .proto / a CORE tree — forbidden for this unit).

// recorderCancelMaskRecorder is the recorder-layer contract a future
// client-streaming cancel scenario MUST satisfy: given the stream's terminal
// error, fold it into the comparable Observation the dual-run will diff. The seam
// already records terminal status exactly this way (obs.Set("status",
// status.Code(err).String())); a cancel scenario reuses the same convention so a
// masked cancel diverges loudly.
type recorderCancelMaskRecorder func(terminalErr error) *dualrun.Observation

// seamTerminalStatusRecorder mirrors the seam's own terminal-status recording
// convention: record ONLY the observable gRPC status code under "status". It is
// the recorder a client-streaming cancel scenario should fold its stream outcome
// through. Kept here (test-local) so this guard is self-contained and does not
// depend on any shared affordance landing first.
func seamTerminalStatusRecorder(terminalErr error) *dualrun.Observation {
	return dualrun.NewObservation().Set("status", status.Code(terminalErr).String())
}

// assertCancelNotMaskedAtRecorder is the load-bearing invariant: a recorder is
// cancel-mask-SAFE iff the Observation it produces for a Canceled terminal status
// is canonically DISTINCT from the one it produces for a spurious OK (a swallowed
// cancel surfacing as success). If the two canonical forms are equal, the
// recorder masks cancellation — dual-run agreement on it proves nothing.
func assertCancelNotMaskedAtRecorder(t *testing.T, name string, rec recorderCancelMaskRecorder) {
	t.Helper()
	canceledObs := rec(status.Error(codes.Canceled, "synthetic: client canceled mid-stream"))
	// A spurious OK is what a masking impl reports: the stream "completed" with no
	// error even though the client canceled. status.Code(nil) == codes.OK.
	spuriousOKObs := rec(nil)
	if canceledObs.Canonical() == spuriousOKObs.Canonical() {
		t.Fatalf("recorder %q MASKS cancellation: Canceled and a spurious OK record the same Observation %q — "+
			"a client-streaming cancel scenario folded through it would let a swallowed cancel pass the dual-run as green",
			name, canceledObs.Canonical())
	}
}

// TestRecorderCancelMaskGuard asserts the seam's terminal-status recorder
// convention keeps Canceled distinct from a spurious OK. This is the recorder a
// client-streaming cancel scenario must fold through; proving it here means the
// moment such a scenario is wired through the convention, a masked cancel
// (recorded OK) diverges from a true cancel rather than silently agreeing.
func TestRecorderCancelMaskGuard(t *testing.T) {
	assertCancelNotMaskedAtRecorder(t, "identitydigestfeed/seamTerminalStatusRecorder", seamTerminalStatusRecorder)
}

// TestRecorderCancelMaskGuard_NoClientStreamingVerbYet is the trip-wire: it
// asserts the DigestFeedService contract has NO client-streaming verb, so the
// cancel-masking risk is latent, not live. The instant a .proto change adds one
// (regenerating the ServiceDesc with ClientStreams=true), this guard FAILS and
// forces the adder to wire a client-streaming cancel scenario whose Observation
// distinguishes Canceled from OK (via assertCancelNotMaskedAtRecorder against
// that scenario's recorder) before the build can go green again. The dual-run's
// cancel gate cannot be silently vacuous.
func TestRecorderCancelMaskGuard_NoClientStreamingVerbYet(t *testing.T) {
	desc := identityv1.DigestFeedService_ServiceDesc
	for _, sd := range desc.Streams {
		if sd.ClientStreams {
			t.Fatalf("%s grew a client-streaming verb %q: wire a client-streaming cancel scenario whose "+
				"Observation distinguishes codes.Canceled from a spurious OK (fold its terminal status through a "+
				"recorder and assert it via assertCancelNotMaskedAtRecorder), then update this guard — dual-run "+
				"agreement alone is vacuous for client-streaming cancel",
				desc.ServiceName, sd.StreamName)
		}
	}
}

// TestSeam_RealVsGeneratedFake is the per-commit gate for the identity.v1
// DigestFeedService secret-digest feed seam (doc 16 §6.6/§9, doc 14 §7, doc 06
// §2.1): the seam's conformance suite runs against BOTH the real reference
// implementation AND the generated programmable fake, and the seam is green only
// if every scenario observes the same thing on both. The suite exercises the two
// UNARY verbs' success paths (DigestPublish, DigestRevoke), the doc 14 §7 frozen
// entry shape (issued + forbidden cred classes, all four variant tags), the
// publish→revoke ordering + idempotency (mint-before-attach / teardown flush),
// and the honest error paths (under-specified batch, missing session, fleet-scope
// refusal).
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := identitydigestfeed.Suite().Run(context.Background(), identitydigestfeed.RealDialer(), identitydigestfeed.FakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("identity DigestFeedService seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_HarnessCatchesADriftedFake is the negative proof: a fake that drifts
// from the contract (here, a DigestRevoke that errors NotFound when revoking an
// already-gone key id instead of succeeding committed — the doc 16 §6.2 idempotent
// teardown-flush violation) must fail the seam. Without this, a green dual-run
// would be meaningless — it could be passing because the gate never fires. The
// drift is injected only in this test's local fake, never in the committed
// generated fake.
func TestSeam_HarnessCatchesADriftedFake(t *testing.T) {
	res, err := identitydigestfeed.Suite().Run(context.Background(), identitydigestfeed.RealDialer(), driftedRevokeFakeDialer())
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

// TestPublishRevoke_RecordedViaFakeAccessors asserts the publish/revoke contract
// directly against the generated fake's per-verb *Recorded() call-capture
// accessors (doc 14 §7, doc 16 §6.1/§6.2). It proves the recorder captures the
// digest SHAPE the producer pushed — the key id, the cred-class oneof (ISSUED vs
// FORBIDDEN), the variant tag, and that NO plaintext field rides the seam — plus
// that re-issuing a publish is idempotent on the result while the recorder still
// sees BOTH issues. This is the assertion the dual-run alone cannot make: the
// dual-run compares end-observable outcomes; the recorded-call surface is what
// lets a downstream consumer verify "the feed was asked to publish exactly this
// digest set, twice".
func TestPublishRevoke_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()
	f := identityv1fake.NewDigestFeedServiceFake()

	// Program just enough honest behavior to observe the contract: every publish
	// acks committed and echoes the batch id; every revoke acks committed.
	f.DigestPublishResponder = func(_ context.Context, req *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
		return &identityv1.DigestPublishResponse{
			BatchId:    req.GetBatchId(),
			Session:    &identityv1.DigestSessionRef{SessionUuid: req.GetSession().GetSessionUuid()},
			ConsumerId: "consumer-synthetic-recorded",
			Committed:  true,
		}, nil
	}
	f.DigestRevokeResponder = func(_ context.Context, req *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
		return &identityv1.DigestRevokeResponse{
			Session:    &identityv1.DigestSessionRef{SessionUuid: req.GetSession().GetSessionUuid()},
			ConsumerId: "consumer-synthetic-recorded",
			Committed:  true,
		}, nil // idempotent: always succeeds
	}

	const (
		session   = "ses-digest-recorded-0000-4000-8000-000000000000"
		keyIssued = "hmackey-synthetic-recorded-issued"
		keyForbid = "hmackey-synthetic-recorded-forbid"
		serviceID = "svc-synthetic-recorded"
		batchID   = "batch-synthetic-recorded"
	)

	pubReq := &identityv1.DigestPublishRequest{
		Session: &identityv1.DigestSessionRef{SessionUuid: session},
		BatchId: batchID,
		Entries: []*identityv1.DigestEntry{
			{
				KeyId:      keyIssued,
				Algo:       &identityv1.DigestAlgo{Family: identityv1.DigestAlgo_FAMILY_HMAC_SHA256, TruncationLenBytes: 16},
				Digest:     []byte("synthetic-digest-recorded-issued"),
				CredClass:  &identityv1.DigestCredClass{Class: &identityv1.DigestCredClass_Issued_{Issued: &identityv1.DigestCredClass_Issued{ServiceId: serviceID}}},
				Scope:      identityv1.DigestScope_DIGEST_SCOPE_SESSION,
				VariantTag: identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW,
			},
			{
				KeyId:      keyForbid,
				Algo:       &identityv1.DigestAlgo{Family: identityv1.DigestAlgo_FAMILY_HMAC_SHA256, TruncationLenBytes: 16},
				Digest:     []byte("synthetic-digest-recorded-forbid"),
				CredClass:  &identityv1.DigestCredClass{Class: &identityv1.DigestCredClass_Forbidden_{Forbidden: &identityv1.DigestCredClass_Forbidden{}}},
				Scope:      identityv1.DigestScope_DIGEST_SCOPE_SESSION,
				VariantTag: identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX,
			},
		},
	}

	first, err := f.DigestPublish(ctx, pubReq)
	if err != nil {
		t.Fatalf("first DigestPublish: %v", err)
	}
	second, err := f.DigestPublish(ctx, pubReq)
	if err != nil {
		t.Fatalf("second DigestPublish: %v", err)
	}
	// Idempotent on the result: re-issue acks the same committed batch.
	if !first.GetCommitted() || !second.GetCommitted() ||
		first.GetBatchId() != second.GetBatchId() ||
		first.GetSession().GetSessionUuid() != second.GetSession().GetSessionUuid() {
		t.Fatalf("DigestPublish not idempotent on the ack: %v vs %v", first, second)
	}

	// The recorder must have captured BOTH publishes, each carrying the full
	// digest shape: key id, cred-class oneof, variant tag — and NO plaintext.
	pubCalls := f.DigestPublishRecorded()
	if len(pubCalls) != 2 {
		t.Fatalf("DigestPublishRecorded: want 2 captured calls, got %d", len(pubCalls))
	}
	for i, c := range pubCalls {
		if got := c.Req.GetBatchId(); got != batchID {
			t.Fatalf("DigestPublishRecorded[%d].batch_id = %q, want %q", i, got, batchID)
		}
		ents := c.Req.GetEntries()
		if len(ents) != 2 {
			t.Fatalf("DigestPublishRecorded[%d]: want 2 entries, got %d", i, len(ents))
		}
		// Entry 0: ISSUED{service_id}, RAW variant.
		if ents[0].GetKeyId() != keyIssued {
			t.Fatalf("DigestPublishRecorded[%d].entries[0].key_id = %q, want %q", i, ents[0].GetKeyId(), keyIssued)
		}
		if ents[0].GetCredClass().GetIssued().GetServiceId() != serviceID {
			t.Fatalf("DigestPublishRecorded[%d].entries[0] issued service_id = %q, want %q", i, ents[0].GetCredClass().GetIssued().GetServiceId(), serviceID)
		}
		if ents[0].GetVariantTag() != identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW {
			t.Fatalf("DigestPublishRecorded[%d].entries[0].variant_tag = %v, want RAW", i, ents[0].GetVariantTag())
		}
		// Entry 1: FORBIDDEN canary, HEX variant — the cred-class oneof carries
		// the forbidden marker with no payload.
		if ents[1].GetCredClass().GetForbidden() == nil {
			t.Fatalf("DigestPublishRecorded[%d].entries[1] cred_class is not FORBIDDEN", i)
		}
		if ents[1].GetCredClass().GetIssued() != nil {
			t.Fatalf("DigestPublishRecorded[%d].entries[1] cred_class must not also be ISSUED", i)
		}
		// The digest is keyed-hash bytes, never a plaintext: a non-empty digest is
		// the only credential-derived value on the entry.
		if len(ents[1].GetDigest()) == 0 {
			t.Fatalf("DigestPublishRecorded[%d].entries[1].digest is empty", i)
		}
	}

	// Revoke: the idempotent teardown flush succeeds; the recorder captures it
	// with the key ids and the session scope.
	revReq := &identityv1.DigestRevokeRequest{
		Session: &identityv1.DigestSessionRef{SessionUuid: session},
		KeyIds:  []string{keyIssued, keyForbid},
		Scope:   identityv1.DigestScope_DIGEST_SCOPE_SESSION,
	}
	if _, err := f.DigestRevoke(ctx, revReq); err != nil {
		t.Fatalf("first DigestRevoke: %v", err)
	}
	if _, err := f.DigestRevoke(ctx, revReq); err != nil {
		t.Fatalf("idempotent DigestRevoke retry must succeed, got: %v", err)
	}
	revCalls := f.DigestRevokeRecorded()
	if len(revCalls) != 2 {
		t.Fatalf("DigestRevokeRecorded: want 2, got %d", len(revCalls))
	}
	for i, c := range revCalls {
		if c.Req.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_SESSION {
			t.Fatalf("DigestRevokeRecorded[%d].scope = %v, want SESSION", i, c.Req.GetScope())
		}
		if len(c.Req.GetKeyIds()) != 2 {
			t.Fatalf("DigestRevokeRecorded[%d]: want 2 key ids, got %d", i, len(c.Req.GetKeyIds()))
		}
	}
}

// driftedRevokeFakeDialer programs the generated fake with a deliberately wrong
// DigestRevoke responder (errors NotFound when no live digest set exists for the
// session, breaking the doc 16 §6.2 idempotent teardown-flush contract) to prove
// the gate bites. DigestPublish is programmed honestly (via a mirror RefImpl) so
// the divergence is attributable to the injected revoke drift, which surfaces on
// the revoke/idempotent-on-already-gone-key-id scenario.
func driftedRevokeFakeDialer() dualrun.Dialer {
	f := identityv1fake.NewDigestFeedServiceFake()
	mirror := identitydigestfeed.NewRefImpl()
	f.DigestPublishResponder = mirror.DigestPublish
	f.DigestRevokeResponder = func(ctx context.Context, req *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
		if len(mirror.Registered(req.GetSession().GetSessionUuid())) == 0 {
			// DRIFT: an idempotent revoke of already-gone (or never-published) key
			// ids must SUCCEED committed, not error NotFound.
			return nil, status.Error(codes.NotFound, "no such digest set")
		}
		return mirror.DigestRevoke(ctx, req)
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		identityv1fake.RegisterDigestFeedService(s, f)
	})
}
