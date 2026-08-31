// SPDX-License-Identifier: Apache-2.0

// End-to-end over the FROZEN dreamserpent.identity.v1.DigestFeedService seam:
// the production producer publishes a synthetic session's digest set to an
// in-process consumer (the shape the D109 host-agent ack-er serves), the
// consumer acks committed, and the published digests are matchable before the
// session would be marked routable (round2/08 test 6). The fail-closed legs
// (transport error, uncommitted ack) are proven to keep the session NOT
// routable. SYNTHETIC ONLY (D50).
package digest

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// recordingConsumer is the host-side consumer the producer publishes to. It
// records the batch (so the test can load it into a Matcher) and acks per the
// configured behavior. It is the in-process stand-in for the D109 host-agent
// ack-er — no live boundary, no live claude (the wave rule).
type recordingConsumer struct {
	identityv1.UnimplementedDigestFeedServiceServer
	published *identityv1.DigestPublishRequest
	revoked   *identityv1.DigestRevokeRequest
	commit    bool  // ack committed?
	pubErr    error // transport-level failure to inject
}

func (c *recordingConsumer) DigestPublish(_ context.Context, req *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
	if c.pubErr != nil {
		return nil, c.pubErr
	}
	c.published = req
	return &identityv1.DigestPublishResponse{
		BatchId:    req.GetBatchId(),
		Session:    req.GetSession(),
		ConsumerId: "synth-host-agent", // the D109 ack-er role
		Committed:  c.commit,
	}, nil
}

func (c *recordingConsumer) DigestRevoke(_ context.Context, req *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
	c.revoked = req
	return &identityv1.DigestRevokeResponse{
		Session:    req.GetSession(),
		ConsumerId: "synth-host-agent",
		Committed:  true,
	}, nil
}

// dialConsumer stands up an in-process gRPC server for the given consumer and
// returns a connected client, tearing both down via t.Cleanup. The transport
// is an in-memory bufconn.Listener (no real socket bind), so the e2e is a true
// in-process gRPC round-trip that runs in a hardened CI sandbox with no network
// namespace — never touching loopback TCP.
func dialConsumer(t *testing.T, c identityv1.DigestFeedServiceServer) identityv1.DigestFeedServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	identityv1.RegisterDigestFeedServiceServer(srv, c)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return identityv1.NewDigestFeedServiceClient(conn)
}

func sessionCreds() []Credential {
	exp := time.Now().Add(15 * time.Minute)
	return []Credential{
		{Plaintext: []byte("ds-synth-issued-github-pat"), CredClass: Issued("github"), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION, Expiry: exp},
		{Plaintext: []byte("ds-synth-forbidden-canary"), CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION, Expiry: exp},
	}
}

func TestPublishSession_HappyPath_MatchableBeforeRoutable(t *testing.T) {
	consumer := &recordingConsumer{commit: true}
	client := dialConsumer(t, consumer)
	prod, err := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	const sessionUUID = "00000000-0000-4000-8000-0000000000aa"

	creds := sessionCreds()
	res, err := PublishSession(context.Background(), client, prod, sessionUUID, creds, "synth-batch-0001")
	if err != nil {
		t.Fatalf("PublishSession: %v", err)
	}
	if !res.Routable {
		t.Fatal("happy path: session not routable after committed ack")
	}
	if res.ConsumerID != "synth-host-agent" {
		t.Errorf("consumer id %q, want synth-host-agent", res.ConsumerID)
	}

	// The consumer received exactly the 4-variant set per credential, all
	// session-scoped — and they are matchable BEFORE we would mark routable.
	got := consumer.published.GetEntries()
	if want := len(creds) * len(AllVariants); len(got) != want {
		t.Fatalf("consumer saw %d entries, want %d", len(got), want)
	}
	for _, e := range got {
		if e.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_SESSION {
			t.Fatalf("non-session scope on the session path: %v", e.GetScope())
		}
	}
	matcher, _ := MatcherFromProducer(prod)
	matcher.Load(got)
	// Each credential's RAW form is matchable now (pre-egress) — round2/08 test 6.
	for _, c := range creds {
		if res := matcher.Match(c.Plaintext); !res.Matched {
			t.Fatalf("credential not matchable pre-egress: %q", c.Plaintext)
		}
	}
}

func TestPublishSession_UncommittedAck_NotRoutable(t *testing.T) {
	consumer := &recordingConsumer{commit: false} // ack returns committed=false
	client := dialConsumer(t, consumer)
	prod, _ := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)

	res, err := PublishSession(context.Background(), client, prod, "00000000-0000-4000-8000-0000000000bb", sessionCreds(), "synth-batch-0002")
	if err == nil {
		t.Fatal("uncommitted ack: want error (fail-closed)")
	}
	if res.Routable {
		t.Fatal("uncommitted ack: session must NOT be routable")
	}
}

func TestPublishSession_TransportError_NotRoutable(t *testing.T) {
	consumer := &recordingConsumer{commit: true, pubErr: status.Error(14, "synthetic unavailable")}
	client := dialConsumer(t, consumer)
	prod, _ := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)

	res, err := PublishSession(context.Background(), client, prod, "00000000-0000-4000-8000-0000000000cc", sessionCreds(), "synth-batch-0003")
	if err == nil {
		t.Fatal("transport error: want error (fail-closed)")
	}
	if res.Routable {
		t.Fatal("transport error: session must NOT be routable")
	}
}

func TestPublishSession_NilAndEmptyInputsFailClosed(t *testing.T) {
	prod, _ := NewProducer(synthKeyID, synthKey, DefaultTruncationLenBytes)
	consumer := &recordingConsumer{commit: true}
	client := dialConsumer(t, consumer)
	ctx := context.Background()

	if _, err := PublishSession(ctx, nil, prod, "s", sessionCreds(), "b"); err == nil {
		t.Error("nil client: want error")
	}
	if _, err := PublishSession(ctx, client, nil, "s", sessionCreds(), "b"); err == nil {
		t.Error("nil producer: want error")
	}
	if _, err := PublishSession(ctx, client, prod, "", sessionCreds(), "b"); err == nil {
		t.Error("empty session uuid: want error")
	}
	if _, err := PublishSession(ctx, client, prod, "s", nil, "b"); err == nil {
		t.Error("no creds: want error (no entries)")
	}
	// A credential that fails to digest fails the publish before any RPC.
	bad := []Credential{{Plaintext: nil, CredClass: Issued("x"), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION}}
	if _, err := PublishSession(ctx, client, prod, "s", bad, "b"); err == nil {
		t.Error("bad credential: want error (fail-closed)")
	}
}

func TestRevokeSession_TeardownFlush(t *testing.T) {
	consumer := &recordingConsumer{commit: true}
	client := dialConsumer(t, consumer)
	const sessionUUID = "00000000-0000-4000-8000-0000000000dd"

	if err := RevokeSession(context.Background(), client, sessionUUID, []string{synthKeyID}); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if consumer.revoked.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_SESSION {
		t.Errorf("revoke scope %v, want SESSION", consumer.revoked.GetScope())
	}
	if got := consumer.revoked.GetKeyIds(); len(got) != 1 || got[0] != synthKeyID {
		t.Errorf("revoke key ids %v, want [%s]", got, synthKeyID)
	}

	// Fail-closed inputs.
	if err := RevokeSession(context.Background(), nil, sessionUUID, []string{synthKeyID}); err == nil {
		t.Error("nil client: want error")
	}
	if err := RevokeSession(context.Background(), client, "", []string{synthKeyID}); err == nil {
		t.Error("empty session: want error")
	}
	if err := RevokeSession(context.Background(), client, sessionUUID, nil); err == nil {
		t.Error("no key ids: want error")
	}
}

// TestRevokeUncommittedFailsClosed proves an uncommitted revoke ack surfaces as
// an error (a teardown that didn't actually clear the digests is not silent).
func TestRevokeUncommittedFailsClosed(t *testing.T) {
	client := dialConsumer(t, &uncommittedRevokeConsumer{})
	if err := RevokeSession(context.Background(), client, "s", []string{synthKeyID}); err == nil {
		t.Error("uncommitted revoke ack: want error")
	}
}

type uncommittedRevokeConsumer struct {
	identityv1.UnimplementedDigestFeedServiceServer
}

func (uncommittedRevokeConsumer) DigestRevoke(_ context.Context, req *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
	return &identityv1.DigestRevokeResponse{Session: req.GetSession(), ConsumerId: "synth-host-agent", Committed: false}, nil
}
