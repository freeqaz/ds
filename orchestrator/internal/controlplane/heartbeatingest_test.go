package controlplane

// heartbeatingest_test.go unit-tests leg (c)'s routing in isolation: the ingest's
// ReportHeartbeat drains a stream and routes EACH frame's Heartbeat through the Observe
// seam (the reconcile loop's record-feed + reconcile-submit entrypoint). It drives the
// ingest with a fake client-streaming server + a recording observer double — no gRPC
// transport, no live host-agent (D50) — asserting every well-formed frame reaches Observe
// and a malformed frame is skipped. The over-the-wire end-to-end (feed + Observe through a
// real bufconn) lives in serve_test.go; this pins the routing contract directly.

import (
	"context"
	"io"
	"sync"
	"testing"

	"google.golang.org/grpc"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// recordingObserver is a heartbeatObserver double that records every Heartbeat it is
// handed (the ingest's Observe submit target). It stands in for the reconcileLoop so the
// ingest's routing is asserted without driving the whole loop.
type recordingObserver struct {
	mu   sync.Mutex
	seen []*hostagentv1.Heartbeat
}

func (o *recordingObserver) Observe(_ context.Context, hb *hostagentv1.Heartbeat) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, hb)
	return nil
}

func (o *recordingObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.seen)
}

// fakeIngestStream is an in-memory grpc.ClientStreamingServer for ReportHeartbeat: it
// hands the ingest a programmed sequence of frames (Recv pops them, then returns io.EOF)
// and captures the close-path response (SendAndClose). It is the no-transport driver for
// the ingest's drain loop (D50).
type fakeIngestStream struct {
	grpc.ServerStream
	ctx    context.Context
	frames []*hostagentv1.ReportHeartbeatRequest
	idx    int
	resp   *hostagentv1.ReportHeartbeatResponse
}

func (s *fakeIngestStream) Context() context.Context { return s.ctx }

func (s *fakeIngestStream) Recv() (*hostagentv1.ReportHeartbeatRequest, error) {
	if s.idx >= len(s.frames) {
		return nil, io.EOF
	}
	f := s.frames[s.idx]
	s.idx++
	return f, nil
}

func (s *fakeIngestStream) SendAndClose(resp *hostagentv1.ReportHeartbeatResponse) error {
	s.resp = resp
	return nil
}

// TestHeartbeatIngest_RoutesEveryFrameToObserve proves the ingest routes each well-formed
// frame's Heartbeat through Observe and counts every frame in the close-path response.
func TestHeartbeatIngest_RoutesEveryFrameToObserve(t *testing.T) {
	obs := &recordingObserver{}
	ingest := newHeartbeatIngest(obs, nil)

	stream := &fakeIngestStream{
		ctx: context.Background(),
		frames: []*hostagentv1.ReportHeartbeatRequest{
			{Heartbeat: freshHeartbeat("host-a", 0, 1)},
			{Heartbeat: freshHeartbeat("host-b", 1, 2)},
		},
	}
	if err := ingest.ReportHeartbeat(stream); err != nil {
		t.Fatalf("ReportHeartbeat: %v", err)
	}
	if obs.count() != 2 {
		t.Errorf("Observe reached %d times, want 2 (every well-formed frame routed)", obs.count())
	}
	if stream.resp.GetBeatsReceived() != 2 {
		t.Errorf("close-path beats_received = %d, want 2", stream.resp.GetBeatsReceived())
	}
}

// TestHeartbeatIngest_SkipsMalformedFrame proves a frame with a nil heartbeat or an empty
// host_id is counted (the host emitted it) but never routed to Observe — a malformed feed
// entry is never a reconcile input.
func TestHeartbeatIngest_SkipsMalformedFrame(t *testing.T) {
	obs := &recordingObserver{}
	ingest := newHeartbeatIngest(obs, nil)

	stream := &fakeIngestStream{
		ctx: context.Background(),
		frames: []*hostagentv1.ReportHeartbeatRequest{
			{Heartbeat: freshHeartbeat("host-a", 0, 1)}, // well-formed
			{},                                    // nil heartbeat
			{Heartbeat: &hostagentv1.Heartbeat{}}, // empty host_id
		},
	}
	if err := ingest.ReportHeartbeat(stream); err != nil {
		t.Fatalf("ReportHeartbeat: %v", err)
	}
	if obs.count() != 1 {
		t.Errorf("Observe reached %d times, want 1 (only the well-formed frame routed)", obs.count())
	}
	if stream.resp.GetBeatsReceived() != 3 {
		t.Errorf("close-path beats_received = %d, want 3 (all frames counted, malformed skipped)", stream.resp.GetBeatsReceived())
	}
}
