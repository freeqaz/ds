package watch

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// fakeWatchServer is an IN-PROCESS orchestrator.v1 SessionService whose
// WatchSession serves a scripted event log honoring from_seq (resume), and can
// be told to DROP the stream mid-send (Unavailable) so the resilient subscriber's
// reconnect+resume path is exercised offline — NO live orchestrator/VM.
type fakeWatchServer struct {
	orchestratorv1.UnimplementedSessionServiceServer

	mu sync.Mutex
	// log is the full event history keyed by seq (seq starts at 1, contiguous).
	log []*attachv1.SessionEvent
	// dropAfter, when > 0, makes WatchSession send events up to (and including)
	// that absolute seq, then return Unavailable (a transport drop) ONCE. After
	// the first drop it is cleared so the resume reconnect runs to completion.
	dropAfter uint64
	// subscribes records each (fromSeq) the server received, so the test asserts
	// the resume token advanced on reconnect.
	subscribes []uint64
}

func (s *fakeWatchServer) WatchSession(req *orchestratorv1.WatchSessionRequest, stream orchestratorv1.SessionService_WatchSessionServer) error {
	s.mu.Lock()
	s.subscribes = append(s.subscribes, req.GetFromSeq())
	drop := s.dropAfter
	log := append([]*attachv1.SessionEvent(nil), s.log...)
	s.mu.Unlock()

	from := req.GetFromSeq()
	for _, ev := range log {
		if ev.GetSeq() <= from {
			continue // resume: skip the already-delivered prefix
		}
		if err := stream.Send(&orchestratorv1.WatchSessionResponse{Event: ev}); err != nil {
			return err
		}
		if drop > 0 && ev.GetSeq() == drop {
			s.mu.Lock()
			s.dropAfter = 0 // one drop only; the resume reconnect runs clean
			s.mu.Unlock()
			return status.Error(codes.Unavailable, "fake: transport drop")
		}
	}
	return nil // clean end-of-stream
}

func stateEvent(seq uint64) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Seq:     seq,
		Type:    attachv1.EventType_EVENT_TYPE_SESSION_STATE,
		Payload: &attachv1.SessionEvent_SessionState{SessionState: &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_WORKING}},
	}
}

// dialFake starts the fake server on an in-process bufconn listener and returns a
// real orchestrator.v1 SessionServiceClient dialing it (which satisfies Starter).
func dialFake(t *testing.T, srv *fakeWatchServer) Starter {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	orchestratorv1.RegisterSessionServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial fake: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return orchestratorv1.NewSessionServiceClient(conn)
}

// noSleep is a fake clock that advances backoff instantly (no real wall-clock
// sleep) while still honoring ctx cancellation — the deterministic, fast
// reconnect-test seam.
func noSleep(ctx context.Context, _ time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// collectModel folds delivered seqs in arrival order; LastSeq is the resume token.
type collectModel struct {
	mu   sync.Mutex
	seqs []uint64
}

func (c *collectModel) last() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seqs) == 0 {
		return 0
	}
	return c.seqs[len(c.seqs)-1]
}

func (c *collectModel) onEvent(ev *attachv1.SessionEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Enforce strict monotonicity (the subscriber must never deliver an event at
	// or below the last applied — resume must not double-apply, D79).
	if len(c.seqs) > 0 && ev.GetSeq() <= c.seqs[len(c.seqs)-1] {
		return status.Errorf(codes.Internal, "duplicate/out-of-order seq %d after %d", ev.GetSeq(), c.seqs[len(c.seqs)-1])
	}
	c.seqs = append(c.seqs, ev.GetSeq())
	return nil
}

// TestCleanStreamDeliversAll proves the subscriber delivers every event in seq
// order and stops cleanly on the server's clean end-of-stream.
func TestCleanStreamDeliversAll(t *testing.T) {
	srv := &fakeWatchServer{log: []*attachv1.SessionEvent{stateEvent(1), stateEvent(2), stateEvent(3)}}
	c := dialFake(t, srv)

	cm := &collectModel{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, c, "sess", cm.last, cm.onEvent, BackoffPolicy{}, Options{Sleep: noSleep, Deterministic: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := cm.seqs; len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Fatalf("delivered seqs = %v, want [1 2 3]", got)
	}
}

// TestReconnectResumesFromLastSeq proves a mid-stream transport DROP triggers a
// reconnect that RESUMES from the last applied seq (from_seq), so every event is
// delivered EXACTLY ONCE in order (no gap, no double-apply — D79).
func TestReconnectResumesFromLastSeq(t *testing.T) {
	srv := &fakeWatchServer{
		log:       []*attachv1.SessionEvent{stateEvent(1), stateEvent(2), stateEvent(3), stateEvent(4), stateEvent(5)},
		dropAfter: 2, // send 1,2 then drop Unavailable once
	}
	c := dialFake(t, srv)

	cm := &collectModel{}
	var reconnects int
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, c, "sess", cm.last, cm.onEvent, BackoffPolicy{},
		Options{Sleep: noSleep, Deterministic: true, OnReconnect: func(_ int, _ time.Duration, _ uint64) { reconnects++ }})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Exactly-once, in-order, no gap: 1..5 delivered once.
	want := []uint64{1, 2, 3, 4, 5}
	if len(cm.seqs) != len(want) {
		t.Fatalf("delivered seqs = %v, want %v", cm.seqs, want)
	}
	for i, s := range want {
		if cm.seqs[i] != s {
			t.Fatalf("delivered seqs = %v, want %v", cm.seqs, want)
		}
	}
	if reconnects == 0 {
		t.Fatalf("expected at least one reconnect after the transport drop")
	}
	// The reconnect resumed from seq 2 (the last applied before the drop).
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.subscribes) < 2 || srv.subscribes[0] != 0 || srv.subscribes[1] != 2 {
		t.Fatalf("subscribe from_seqs = %v, want first 0 then 2 (resume token)", srv.subscribes)
	}
}

// TestTerminalStatusStopsWithoutRetry proves a TERMINAL status (OutOfRange — the
// from_seq-aged-out re-attach signal) stops the subscriber without reconnecting
// (a retry would loop on the same refusal).
func TestTerminalStatusStopsWithoutRetry(t *testing.T) {
	srv := &terminalServer{code: codes.OutOfRange}
	c := dialTerminal(t, srv)

	cm := &collectModel{}
	var reconnects int
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, c, "sess", cm.last, cm.onEvent, BackoffPolicy{},
		Options{Sleep: noSleep, Deterministic: true, OnReconnect: func(_ int, _ time.Duration, _ uint64) { reconnects++ }})
	if status.Code(err) != codes.OutOfRange {
		t.Fatalf("Run err = %v, want OutOfRange (terminal, no retry)", err)
	}
	if reconnects != 0 {
		t.Fatalf("terminal status should NOT reconnect, got %d reconnects", reconnects)
	}
}

// TestCtxCancelStopsClean proves ctx cancellation stops the subscriber cleanly.
func TestCtxCancelStopsClean(t *testing.T) {
	// A server that blocks forever after sending one event, so only ctx cancel
	// ends the run.
	srv := &blockingServer{first: stateEvent(1)}
	c := dialBlocking(t, srv)

	cm := &collectModel{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, c, "sess", cm.last, cm.onEvent, BackoffPolicy{}, Options{Sleep: noSleep, Deterministic: true})
	}()
	// Wait until the first event lands, then cancel.
	deadline := time.After(3 * time.Second)
	for cm.last() == 0 {
		select {
		case <-deadline:
			t.Fatal("first event never delivered")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if status.Code(err) != codes.Canceled && err != context.Canceled {
			t.Fatalf("Run err = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop on ctx cancel")
	}
}

// --- additional fakes for terminal/blocking cases ----------------------------

type terminalServer struct {
	orchestratorv1.UnimplementedSessionServiceServer
	code codes.Code
}

func (s *terminalServer) WatchSession(req *orchestratorv1.WatchSessionRequest, _ orchestratorv1.SessionService_WatchSessionServer) error {
	return status.Error(s.code, "fake: terminal refusal")
}

func dialTerminal(t *testing.T, srv *terminalServer) Starter {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	orchestratorv1.RegisterSessionServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial terminal: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return orchestratorv1.NewSessionServiceClient(conn)
}

type blockingServer struct {
	orchestratorv1.UnimplementedSessionServiceServer
	first *attachv1.SessionEvent
}

func (s *blockingServer) WatchSession(req *orchestratorv1.WatchSessionRequest, stream orchestratorv1.SessionService_WatchSessionServer) error {
	if err := stream.Send(&orchestratorv1.WatchSessionResponse{Event: s.first}); err != nil {
		return err
	}
	<-stream.Context().Done() // block until the client (ctx) goes away
	return stream.Context().Err()
}

func dialBlocking(t *testing.T, srv *blockingServer) Starter {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	orchestratorv1.RegisterSessionServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial blocking: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return orchestratorv1.NewSessionServiceClient(conn)
}
