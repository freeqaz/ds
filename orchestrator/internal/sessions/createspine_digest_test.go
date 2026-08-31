// SPDX-License-Identifier: Apache-2.0

package sessions

// createspine_digest_test.go pins the digest-publish insertion on the LIVE create
// spine (doc 16 §6.1 mint-before-attach, D73): RunCreateSpine now drives the FLAG-GATED
// digest-publish step (digestpublish.go) BETWEEN step-5 cred-mint and mark-routable.
// The headline acceptance is the security gate: a failed OR uncommitted OR unwired
// publish PROVABLY prevents the spine's success result (so the caller never marks the
// session routable), while a committed publish carries Routable=true onto the result.
// The flag-off default is byte-for-byte the pre-wire spine (the step is skipped, the
// publisher is never called). All synthetic; no live boundary (D50). D80: the spine and
// its production adapter speak only proto/gen/go — no identity/* import.

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/auth"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"google.golang.org/grpc"
)

// digestPublisherFake is a synthetic digestPublisher: it scripts the outcome/err the
// spine's step-6 sees and RECORDS whether PublishSessionDigests was called (so the
// flag-off skip — the publisher must NEVER be called — can be asserted).
type digestPublisherFake struct {
	out    DigestPublishOutcome
	err    error
	called bool
	gotID  string
}

func (f *digestPublisherFake) PublishSessionDigests(_ context.Context, sessionUUID string) (DigestPublishOutcome, error) {
	f.called = true
	f.gotID = sessionUUID
	return f.out, f.err
}

// spineWithGate is the shared setup: a memory store, the real launch-gate adapter, a
// seeded session record, and the default role resolver — the same wiring the metering
// spine tests use, so these cases exercise the full steps-1–2 + step-5 cluster before
// the digest step.
func spineWithGate(t *testing.T, uuid string, idx uint64) (*store.Memory, launchGate, RoleResolver) {
	t.Helper()
	repo := store.NewMemory()
	gate := realGateAdapter{gate: auth.NewLaunchGate(auth.NewResolver(repo, auth.WithIDGen(seqIDLocal("p"))), repo)}
	seedSpineSession(t, repo, uuid, idx)
	roleR := &spineRoleResolver{dflt: recordedDefault()}
	return repo, gate, roleR
}

func spineAuth() *LaunchInput {
	return &LaunchInput{Org: "acme", Subject: "okta|digest", Roles: []string{string(store.RoleLauncher)}}
}

// TestRunCreateSpine_DigestFlagOffSkipsPublish pins the byte-identical default: with the
// flag unset, the spine SKIPS the digest step — the publisher is never called and the
// result carries the zero (non-routable) DigestPublish outcome, exactly as before the
// step existed.
func TestRunCreateSpine_DigestFlagOffSkipsPublish(t *testing.T) {
	t.Setenv(DigestPublishWireFlag, "0")
	ctx := context.Background()
	repo, gate, roleR := spineWithGate(t, "sess-off", 41)

	pub := &digestPublisherFake{out: DigestPublishOutcome{Routable: true}}
	out, err := RunCreateSpine(ctx, gate, roleR, repo, repo, CreateSpineRequest{
		SessionUUID:     "sess-off",
		Auth:            spineAuth(),
		DigestPublisher: pub,
	}, nil)
	if err != nil {
		t.Fatalf("RunCreateSpine(flag off): %v", err)
	}
	if pub.called {
		t.Fatal("flag-off spine called the digest publisher — the step must be skipped (byte-identical)")
	}
	if out.DigestPublish.Routable {
		t.Errorf("flag-off result DigestPublish.Routable = true, want false (step skipped)")
	}
}

// TestRunCreateSpine_DigestFlagOnSuccessMarksRoutable is the success-path acceptance:
// armed, a committed publish returns nil error (so the caller proceeds to mark the
// session routable) and carries Routable=true + the ack provenance onto the result.
func TestRunCreateSpine_DigestFlagOnSuccessMarksRoutable(t *testing.T) {
	t.Setenv(DigestPublishWireFlag, "1")
	ctx := context.Background()
	repo, gate, roleR := spineWithGate(t, "sess-ok", 42)

	pub := &digestPublisherFake{out: DigestPublishOutcome{Routable: true, ConsumerID: "host-agent-1", BatchID: "b-ok"}}
	out, err := RunCreateSpine(ctx, gate, roleR, repo, repo, CreateSpineRequest{
		SessionUUID:     "sess-ok",
		Auth:            spineAuth(),
		DigestPublisher: pub,
	}, nil)
	if err != nil {
		t.Fatalf("RunCreateSpine(flag on, committed): %v", err)
	}
	if !pub.called || pub.gotID != "sess-ok" {
		t.Fatalf("digest publisher not called with the session uuid (called=%v id=%q)", pub.called, pub.gotID)
	}
	if !out.DigestPublish.Routable {
		t.Errorf("committed publish left DigestPublish.Routable = false, want true")
	}
	if out.DigestPublish.ConsumerID != "host-agent-1" || out.DigestPublish.BatchID != "b-ok" {
		t.Errorf("ack provenance not carried: %+v", out.DigestPublish)
	}
}

// TestRunCreateSpine_DigestPublishErrorFailsClosed proves a transport/publish ERROR
// stalls the create: the spine returns an error (so the caller never marks the session
// routable). This is the headline fail-closed acceptance.
func TestRunCreateSpine_DigestPublishErrorFailsClosed(t *testing.T) {
	t.Setenv(DigestPublishWireFlag, "1")
	ctx := context.Background()
	repo, gate, roleR := spineWithGate(t, "sess-err", 43)

	wantErr := errors.New("boundary unreachable")
	pub := &digestPublisherFake{err: wantErr}
	out, err := RunCreateSpine(ctx, gate, roleR, repo, repo, CreateSpineRequest{
		SessionUUID:     "sess-err",
		Auth:            spineAuth(),
		DigestPublisher: pub,
	}, nil)
	if err == nil {
		t.Fatal("RunCreateSpine did NOT fail on a digest publish error — the session would be marked routable (fail-open)")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error does not wrap the publish error: %v", err)
	}
	if out.DigestPublish.Routable {
		t.Errorf("failed publish left Routable=true: %+v", out.DigestPublish)
	}
}

// TestRunCreateSpine_DigestUncommittedFailsClosed proves an UNCOMMITTED ack (the
// publisher returned nil error but Routable=false) still stalls the create — the
// defence-in-depth arm of the routable gate.
func TestRunCreateSpine_DigestUncommittedFailsClosed(t *testing.T) {
	t.Setenv(DigestPublishWireFlag, "1")
	ctx := context.Background()
	repo, gate, roleR := spineWithGate(t, "sess-unc", 44)

	pub := &digestPublisherFake{out: DigestPublishOutcome{Routable: false, ConsumerID: "host-agent-2", BatchID: "b-unc"}}
	_, err := RunCreateSpine(ctx, gate, roleR, repo, repo, CreateSpineRequest{
		SessionUUID:     "sess-unc",
		Auth:            spineAuth(),
		DigestPublisher: pub,
	}, nil)
	if err == nil {
		t.Fatal("RunCreateSpine did NOT fail on an uncommitted ack — the session would be marked routable")
	}
	if !ErrIsDigestNotRoutable(err) {
		t.Errorf("uncommitted ack not classified as digest-not-routable: %v", err)
	}
}

// TestRunCreateSpine_DigestArmedNilPublisherFailsClosed proves an ARMED create with NO
// publisher wired fails closed (ErrDigestPublisherUnwired) — a mint-before-attach gate
// that cannot run must not silently pass, so the session is never marked routable.
func TestRunCreateSpine_DigestArmedNilPublisherFailsClosed(t *testing.T) {
	t.Setenv(DigestPublishWireFlag, "1")
	ctx := context.Background()
	repo, gate, roleR := spineWithGate(t, "sess-unwired", 45)

	_, err := RunCreateSpine(ctx, gate, roleR, repo, repo, CreateSpineRequest{
		SessionUUID:     "sess-unwired",
		Auth:            spineAuth(),
		DigestPublisher: nil, // armed but unwired
	}, nil)
	if err == nil {
		t.Fatal("RunCreateSpine did NOT fail on an armed-but-unwired publisher")
	}
	if !errors.Is(err, ErrDigestPublisherUnwired) {
		t.Errorf("armed nil publisher not classified as unwired: %v", err)
	}
	if !ErrIsDigestNotRoutable(err) {
		t.Errorf("unwired publisher not classified fail-closed by ErrIsDigestNotRoutable: %v", err)
	}
}

// ---- production adapter (DigestFeedPublisher) over the frozen client ---------------

// fakeDigestFeedClient is a programmable in-test identityv1.DigestFeedServiceClient: it
// scripts the DigestPublish response/err and records the request, so the production
// adapter can be exercised against the FROZEN client interface without a live boundary
// (D50). It satisfies the generated DigestFeedServiceClient (proto/gen/go) — the same
// interface the production wiring dials — proving the adapter speaks the real seam.
type fakeDigestFeedClient struct {
	resp   *identityv1.DigestPublishResponse
	err    error
	gotReq *identityv1.DigestPublishRequest
}

func (c *fakeDigestFeedClient) DigestPublish(_ context.Context, in *identityv1.DigestPublishRequest, _ ...grpc.CallOption) (*identityv1.DigestPublishResponse, error) {
	c.gotReq = in
	return c.resp, c.err
}

func (c *fakeDigestFeedClient) DigestRevoke(_ context.Context, _ *identityv1.DigestRevokeRequest, _ ...grpc.CallOption) (*identityv1.DigestRevokeResponse, error) {
	return &identityv1.DigestRevokeResponse{}, nil
}

func sampleEntries() []*identityv1.DigestEntry {
	return []*identityv1.DigestEntry{{
		KeyId:      "ds-dk-host1-e0-g0",
		Algo:       &identityv1.DigestAlgo{Family: identityv1.DigestAlgo_FAMILY_HMAC_SHA256, TruncationLenBytes: 16},
		Digest:     []byte{0xde, 0xad, 0xbe, 0xef},
		Scope:      identityv1.DigestScope_DIGEST_SCOPE_SESSION,
		VariantTag: identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW,
	}}
}

// TestDigestFeedPublisher_CommittedRoutable proves the adapter maps a committed ack to
// a routable outcome and drives the frozen DigestPublish with the session-scoped
// request shape (session uuid + entries + batch id).
func TestDigestFeedPublisher_CommittedRoutable(t *testing.T) {
	ctx := context.Background()
	client := &fakeDigestFeedClient{resp: &identityv1.DigestPublishResponse{
		BatchId:    "b-1",
		ConsumerId: "host-agent-1",
		Committed:  true,
	}}
	pub := NewDigestFeedPublisher(client, sampleEntries(), "b-1")

	out, err := pub.PublishSessionDigests(ctx, "sess-A")
	if err != nil {
		t.Fatalf("PublishSessionDigests(committed): %v", err)
	}
	if !out.Routable {
		t.Errorf("committed ack -> Routable=false, want true")
	}
	if client.gotReq == nil || client.gotReq.GetSession().GetSessionUuid() != "sess-A" {
		t.Fatalf("adapter did not send the session-scoped request: %+v", client.gotReq)
	}
	if len(client.gotReq.GetEntries()) != 1 || client.gotReq.GetBatchId() != "b-1" {
		t.Errorf("adapter request shape wrong: entries=%d batch=%q", len(client.gotReq.GetEntries()), client.gotReq.GetBatchId())
	}
}

// TestDigestFeedPublisher_UncommittedFailsClosed proves the adapter fails closed on a
// committed=false ack (the frozen fail-closed invariant of doc 14 §7).
func TestDigestFeedPublisher_UncommittedFailsClosed(t *testing.T) {
	ctx := context.Background()
	client := &fakeDigestFeedClient{resp: &identityv1.DigestPublishResponse{
		ConsumerId: "host-agent-1",
		Committed:  false,
	}}
	pub := NewDigestFeedPublisher(client, sampleEntries(), "b-2")

	out, err := pub.PublishSessionDigests(ctx, "sess-B")
	if err == nil {
		t.Fatal("adapter did NOT fail on an uncommitted ack (fail-open)")
	}
	if !ErrIsDigestNotRoutable(err) {
		t.Errorf("uncommitted ack not classified digest-not-routable: %v", err)
	}
	if out.Routable {
		t.Errorf("uncommitted ack -> Routable=true, want false")
	}
}

// TestDigestFeedPublisher_TransportErrorFailsClosed proves a transport error fails
// closed and wraps the underlying error.
func TestDigestFeedPublisher_TransportErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("rpc: connection refused")
	client := &fakeDigestFeedClient{err: wantErr}
	pub := NewDigestFeedPublisher(client, sampleEntries(), "b-3")

	_, err := pub.PublishSessionDigests(ctx, "sess-C")
	if err == nil {
		t.Fatal("adapter did NOT fail on a transport error (fail-open)")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("adapter error does not wrap the transport error: %v", err)
	}
}

// TestDigestFeedPublisher_NilClientAndEmptyEntriesFailClosed proves the construction-
// tolerant nil client and an empty entry set both fail closed at publish time (a
// half-wired deployment fails the create rather than routing a session with no digests).
func TestDigestFeedPublisher_NilClientAndEmptyEntriesFailClosed(t *testing.T) {
	ctx := context.Background()

	nilClient := NewDigestFeedPublisher(nil, sampleEntries(), "b-4")
	if _, err := nilClient.PublishSessionDigests(ctx, "sess-D"); err == nil {
		t.Error("nil client did not fail closed")
	}

	noEntries := NewDigestFeedPublisher(&fakeDigestFeedClient{resp: &identityv1.DigestPublishResponse{Committed: true}}, nil, "b-5")
	if _, err := noEntries.PublishSessionDigests(ctx, "sess-E"); err == nil {
		t.Error("empty entry set did not fail closed")
	}

	emptyUUID := NewDigestFeedPublisher(&fakeDigestFeedClient{resp: &identityv1.DigestPublishResponse{Committed: true}}, sampleEntries(), "b-6")
	if _, err := emptyUUID.PublishSessionDigests(ctx, ""); err == nil {
		t.Error("empty session uuid did not fail closed")
	}
}

// static assertions: the production adapter satisfies the spine seam AND the test
// client satisfies the FROZEN generated client interface (so the adapter is proven to
// speak the real seam, not a bespoke shape).
var (
	_ digestPublisher                    = (*DigestFeedPublisher)(nil)
	_ identityv1.DigestFeedServiceClient = (*fakeDigestFeedClient)(nil)
)
