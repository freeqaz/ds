// SPDX-License-Identifier: Apache-2.0

// End-to-end proof the fake publisher speaks the frozen seam: an in-process
// gRPC consumer (the shape the D109 host-agent ack-er serves) receives the
// publish, verifies the synthetic batch, and acks committed; the revoke leg
// covers the teardown-flush scenario. Everything here is synthetic (D50).
package main

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

type fakeConsumer struct {
	identityv1.UnimplementedDigestFeedServiceServer
	published *identityv1.DigestPublishRequest
	revoked   *identityv1.DigestRevokeRequest
}

func (f *fakeConsumer) DigestPublish(_ context.Context, req *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
	f.published = req
	return &identityv1.DigestPublishResponse{
		BatchId:    req.GetBatchId(),
		Session:    req.GetSession(),
		ConsumerId: "fake-host-agent", // the D109 ack-er role
		Committed:  true,
	}, nil
}

func (f *fakeConsumer) DigestRevoke(_ context.Context, req *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
	f.revoked = req
	return &identityv1.DigestRevokeResponse{
		Session:    req.GetSession(),
		ConsumerId: "fake-host-agent",
		Committed:  true,
	}, nil
}

func TestPublishAndRevokeAgainstInProcessConsumer(t *testing.T) {
	// In-memory bufconn pipe: no real socket bind, never loopback TCP, so the
	// in-process gRPC round-trip runs in a hardened CI sandbox with no network
	// namespace.
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	consumer := &fakeConsumer{}
	identityv1.RegisterDigestFeedServiceServer(srv, consumer)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecureCreds()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := identityv1.NewDigestFeedServiceClient(conn)
	session := &identityv1.DigestSessionRef{SessionUuid: "00000000-0000-4000-8000-00000000fake"}

	pub, err := client.DigestPublish(context.Background(), &identityv1.DigestPublishRequest{
		Session: session,
		Entries: entries(session.GetSessionUuid()),
		BatchId: "t-batch",
	})
	if err != nil || !pub.GetCommitted() {
		t.Fatalf("publish: err=%v committed=%v", err, pub.GetCommitted())
	}
	if got := len(consumer.published.GetEntries()); got != 3 {
		t.Fatalf("consumer saw %d entries, want 3", got)
	}
	for _, e := range consumer.published.GetEntries() {
		if e.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_SESSION {
			t.Fatalf("non-session scope on the session path: %v", e.GetScope())
		}
		if len(e.GetDigest()) != 16 {
			t.Fatalf("digest not truncated to 16 bytes: %d", len(e.GetDigest()))
		}
	}

	rev, err := client.DigestRevoke(context.Background(), &identityv1.DigestRevokeRequest{
		Session: session,
		KeyIds:  []string{"ds-fake-key-0001"},
		Scope:   identityv1.DigestScope_DIGEST_SCOPE_SESSION,
	})
	if err != nil || !rev.GetCommitted() {
		t.Fatalf("revoke: err=%v committed=%v", err, rev.GetCommitted())
	}
	if consumer.revoked.GetKeyIds()[0] != "ds-fake-key-0001" {
		t.Fatalf("revoke key id lost: %v", consumer.revoked.GetKeyIds())
	}
}

func insecureCreds() credentials.TransportCredentials {
	return insecure.NewCredentials()
}
