package hostagent

// subscribe_test.go drives the host-agent WatchPolicies subscription (POL-4 part
// 1, D36/D72) over an in-memory bufconn against the generated orchestrator.v1
// PolicyService FAKE — a real gRPC client dialing a real gRPC server, no live
// socket / port bind (the D50 no-live-socket convention the control-plane tests
// use). The fake streams the responder's ordered WatchPoliciesResponse frames;
// the subscriber's job — in-order delivery, clean close on ctx cancel/RPC close,
// and idempotent skip-on-replay from a persisted seq — is what these tests pin.

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"
)

// serveFakePolicy stands the orchestrator.v1 PolicyService fake up on an
// in-memory bufconn gRPC server and returns a client conn dialed over the wire.
// The responder is the per-call programmable hook the fake streams back — the
// test programs it to emit the snapshots (and to observe the from_seq the
// subscriber sent). Server + conn are torn down on cleanup.
func serveFakePolicy(t *testing.T, fake *orchestratorv1fake.PolicyServiceFake) grpc.ClientConnInterface {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	orchestratorv1fake.RegisterPolicyService(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// snapshotResp wraps a (seq, content_hash, document) into the WatchPolicies
// stream frame the fake streams. Distinct document bytes per seq let a test
// prove it received the RIGHT snapshot for each seq, not just the right count.
func snapshotResp(seq uint64, hash, doc []byte) *orchestratorv1.WatchPoliciesResponse {
	return &orchestratorv1.WatchPoliciesResponse{
		Snapshot: &boundaryv1.PolicySnapshot{
			Seq:         seq,
			ContentHash: hash,
			Document:    doc,
		},
	}
}

// recvWithin reads one snapshot from ch or fails the test if none arrives within
// the deadline — so a wedged subscriber surfaces as a test failure, not a hang.
func recvWithin(t *testing.T, ch <-chan *boundaryv1.PolicySnapshot, d time.Duration) (*boundaryv1.PolicySnapshot, bool) {
	t.Helper()
	select {
	case snap, ok := <-ch:
		return snap, ok
	case <-time.After(d):
		t.Fatalf("timed out after %s waiting for a snapshot", d)
		return nil, false
	}
}

// TestWatchPoliciesSubscribe is the acceptance test (POL-4 part 1): the host
// opens a subscription, the orchestrator fake streams 3 snapshots with
// monotonically increasing seqs, the subscriber receives them IN ORDER via the
// returned channel, a context cancel cleanly closes the channel, and a reconnect
// from a persisted seq skips already-seen snapshots. Each leg is a subtest so a
// failure localizes; all run against the orchestrator.v1 fake over a bufconn.
func TestWatchPoliciesSubscribe(t *testing.T) {
	t.Run("ThreeSnapshotsInOrder", func(t *testing.T) {
		fake := orchestratorv1fake.NewPolicyServiceFake()
		fake.WatchPoliciesResponder = func(_ context.Context, _ *orchestratorv1.WatchPoliciesRequest) ([]*orchestratorv1.WatchPoliciesResponse, error) {
			return []*orchestratorv1.WatchPoliciesResponse{
				snapshotResp(1, []byte("h1"), []byte("doc-1")),
				snapshotResp(2, []byte("h2"), []byte("doc-2")),
				snapshotResp(3, []byte("h3"), []byte("doc-3")),
			}, nil
		}
		conn := serveFakePolicy(t, fake)

		ch, err := Subscribe(context.Background(), conn, 0)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}

		for _, want := range []struct {
			seq uint64
			doc string
		}{{1, "doc-1"}, {2, "doc-2"}, {3, "doc-3"}} {
			snap, ok := recvWithin(t, ch, time.Second)
			if !ok {
				t.Fatalf("channel closed before seq %d", want.seq)
			}
			if snap.GetSeq() != want.seq {
				t.Fatalf("out-of-order: got seq %d, want %d", snap.GetSeq(), want.seq)
			}
			if string(snap.GetDocument()) != want.doc {
				t.Fatalf("seq %d carried document %q, want %q", want.seq,
					snap.GetDocument(), want.doc)
			}
		}

		// After the 3 frames the server closes the stream; the channel must close
		// cleanly (the sole end-of-stream signal), never deliver a 4th.
		if snap, ok := recvWithin(t, ch, time.Second); ok {
			t.Fatalf("expected clean close after 3 snapshots, got extra seq %d", snap.GetSeq())
		}

		// The subscription opened exactly one WatchPolicies stream (one subscriber
		// per host, D72) and carried the replay cursor it was given.
		calls := fake.WatchPoliciesRecorded()
		if len(calls) != 1 {
			t.Fatalf("WatchPolicies opened %d times, want exactly 1 (one subscriber per host, D72)", len(calls))
		}
		if got := calls[0].Req.GetFromSeq(); got != 0 {
			t.Fatalf("from_seq = %d, want 0 (fresh subscription)", got)
		}
	})

	t.Run("ContextCancelClosesChannel", func(t *testing.T) {
		// A responder that blocks until its own context (the server stream ctx,
		// which the client ctx cancel propagates to) is done — so the stream is
		// genuinely live with nothing buffered when the test cancels.
		fake := orchestratorv1fake.NewPolicyServiceFake()
		fake.WatchPoliciesResponder = func(rctx context.Context, _ *orchestratorv1.WatchPoliciesRequest) ([]*orchestratorv1.WatchPoliciesResponse, error) {
			<-rctx.Done()
			return nil, rctx.Err()
		}
		conn := serveFakePolicy(t, fake)

		ctx, cancel := context.WithCancel(context.Background())
		ch, err := Subscribe(ctx, conn, 0)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}

		// Cancel the subscription context; the channel must then close cleanly.
		cancel()
		select {
		case snap, ok := <-ch:
			if ok {
				t.Fatalf("expected closed channel after cancel, got snapshot seq %d", snap.GetSeq())
			}
			// ok == false: clean close, the expected outcome.
		case <-time.After(time.Second):
			t.Fatal("channel did not close within 1s of context cancel")
		}
	})

	t.Run("ReconnectFromPersistedSeqSkipsSeen", func(t *testing.T) {
		// On reconnect the host passes its last persisted applied seq (2). A server
		// that re-streams from the start (seqs 1..4) must NOT cause the subscriber
		// to re-deliver 1 or 2 — idempotent replay (D72): only 3 and 4 survive.
		fake := orchestratorv1fake.NewPolicyServiceFake()
		fake.WatchPoliciesResponder = func(_ context.Context, _ *orchestratorv1.WatchPoliciesRequest) ([]*orchestratorv1.WatchPoliciesResponse, error) {
			return []*orchestratorv1.WatchPoliciesResponse{
				snapshotResp(1, []byte("h1"), []byte("doc-1")),
				snapshotResp(2, []byte("h2"), []byte("doc-2")),
				snapshotResp(3, []byte("h3"), []byte("doc-3")),
				snapshotResp(4, []byte("h4"), []byte("doc-4")),
			}, nil
		}
		conn := serveFakePolicy(t, fake)

		const persisted = uint64(2)
		ch, err := Subscribe(context.Background(), conn, persisted)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}

		for _, wantSeq := range []uint64{3, 4} {
			snap, ok := recvWithin(t, ch, time.Second)
			if !ok {
				t.Fatalf("channel closed before seq %d", wantSeq)
			}
			if snap.GetSeq() != wantSeq {
				t.Fatalf("post-reconnect got seq %d, want %d (already-seen <= %d must be skipped)",
					snap.GetSeq(), wantSeq, persisted)
			}
		}
		if snap, ok := recvWithin(t, ch, time.Second); ok {
			t.Fatalf("expected clean close after seqs 3,4; got extra seq %d", snap.GetSeq())
		}

		// The persisted cursor was carried to the server as the from_seq replay
		// request (server-side catch-up, D36) in addition to the client-side skip.
		calls := fake.WatchPoliciesRecorded()
		if len(calls) != 1 {
			t.Fatalf("WatchPolicies opened %d times, want 1", len(calls))
		}
		if got := calls[0].Req.GetFromSeq(); got != persisted {
			t.Fatalf("from_seq = %d, want %d (the persisted replay cursor)", got, persisted)
		}
	})
}

// TestSubscribeNilConn pins the only synchronous-error path: a nil conn returns
// an error and NO channel (there is no goroutine to close), distinct from the
// open-then-close-the-channel termination every live stream takes.
func TestSubscribeNilConn(t *testing.T) {
	ch, err := Subscribe(context.Background(), nil, 0)
	if err == nil {
		t.Fatal("Subscribe(nil conn) = nil error, want a synchronous error")
	}
	if ch != nil {
		t.Fatal("Subscribe(nil conn) returned a non-nil channel; want nil on synchronous error")
	}
}
