// SPDX-License-Identifier: Apache-2.0

package hostagent_test

import (
	"context"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/hostagent"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1/hostagentv1fake"
)

// TestSeam_RealVsGeneratedFake is the per-commit gate for the orchestrator <->
// host agent seam (doc 15 §11, doc 06 §2.1): the seam's single conformance suite
// runs against BOTH the real reference implementation AND the generated
// programmable fake, and the seam is green only if every scenario observes the
// same thing on both. This is the end-to-end proof of the fake-generation +
// dual-run pipeline on the first real seam.
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := hostagent.Suite().Run(context.Background(), hostagent.RealDialer(), hostagent.FakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("orchestrator<->hostagent seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_HarnessCatchesADriftedFake is the negative proof: a fake that drifts
// from the contract (here, miscounting beats) must fail the seam. Without this,
// a green dual-run would be meaningless — it could be passing because the gate
// never fires. The drift is injected only in this test's local fake, never in
// the committed generated fake.
func TestSeam_HarnessCatchesADriftedFake(t *testing.T) {
	drifted := driftedFakeDialer()
	res, err := hostagent.Suite().Run(context.Background(), hostagent.RealDialer(), drifted)
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a drifted fake passed the seam — the dual-run gate is not firing")
	}
	if len(res.Divergences) == 0 {
		t.Fatalf("expected at least one divergence, got report:\n%s", res.Report())
	}
}

// driftedFakeDialer programs the generated fake with a deliberately wrong
// responder (off-by-one beat count) to prove the gate bites.
func driftedFakeDialer() dualrun.Dialer {
	f := hostagentv1fake.NewHostAgentServiceFake()
	f.ReportHeartbeatResponder = func(_ context.Context, reqs []*hostagentv1.ReportHeartbeatRequest) (*hostagentv1.ReportHeartbeatResponse, error) {
		for _, frame := range reqs {
			hb := frame.GetHeartbeat()
			if hb == nil || hb.GetHostId() == "" {
				return nil, status.Error(codes.InvalidArgument, "invalid heartbeat")
			}
		}
		// DRIFT: report one more beat than received.
		return &hostagentv1.ReportHeartbeatResponse{BeatsReceived: uint64(len(reqs)) + 1}, nil
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hostagentv1fake.RegisterHostAgentService(s, f)
	})
}

// TestSeam_CancelDriftBites is the bite proof for the mid-stream cancellation
// scenario. gRPC enforces cancellation at the client transport, so a drifted
// SERVER cannot leak a spurious OK to the client — the protection that matters
// is the recording one: the dual-run is only meaningful if the cancel
// Observation actually distinguishes the contracted Canceled-terminal /
// no-response outcome from a fabricated success. Here we drive the same
// mid-stream-cancel sequence as the suite scenario and assert that an honest
// recording (Canceled, response_present=false) and a drifted recording (one
// that treats a canceled stream as a zero-value success) produce DIFFERENT
// canonical Observations — i.e. a recorder that masked cancel as OK would
// diverge and fail the seam, exactly as the negative drift test demands.
func TestSeam_CancelDriftBites(t *testing.T) {
	conn, stop, err := hostagent.RealDialer().Dial(context.Background())
	if err != nil {
		t.Fatalf("dial real: %v", err)
	}
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	cl := hostagentv1.NewHostAgentServiceClient(conn)
	stream, err := cl.ReportHeartbeat(ctx)
	if err != nil {
		cancel()
		t.Fatalf("open stream: %v", err)
	}
	for i := 0; i < 3; i++ {
		_ = stream.Send(&hostagentv1.ReportHeartbeatRequest{
			Heartbeat: &hostagentv1.Heartbeat{HostId: "host-a", AppliedSeq: uint64(i)},
		})
	}
	cancel()
	resp, recvErr := stream.CloseAndRecv()

	// The contract: a mid-stream cancel terminates with codes.Canceled and no
	// response. If the harness ever observed otherwise (a spurious OK / a
	// non-nil zero-value tally), the seam is broken — fail loudly.
	if status.Code(recvErr) != codes.Canceled {
		t.Fatalf("mid-stream cancel did not surface Canceled: code=%v err=%v", status.Code(recvErr), recvErr)
	}
	if resp != nil {
		t.Fatalf("mid-stream cancel returned a spurious response: %v", resp)
	}

	// honest records the contracted terminal status; drifted is the bug a
	// faithful seam must reject — masking cancel as a zero-value success.
	honest := dualrun.NewObservation().
		Set("terminal_status", status.Code(recvErr).String()).
		Set("response_present", "false")
	drifted := dualrun.NewObservation().
		Set("terminal_status", codes.OK.String()).
		Set("response_present", "true")
	if honest.Canonical() == drifted.Canonical() {
		t.Fatal("cancel Observation does not distinguish Canceled from a spurious OK — the gate cannot bite")
	}
}

// slowDrainServer is a synthetic HostAgentService that does NOT drain the client
// stream until its context is done — modelling a stalled reconciler. It is the
// scratch mutation that proves the back-pressure contract: against a server that
// never Recv()s, a faithful client-streaming send path applies back-pressure by
// BLOCKING once the flow-control window fills, so the client cannot push the
// whole burst into an unbounded buffer. Synthetic-only (D50). HostAgentService is
// CLIENT-streaming, so its send-path back-pressure is NOT one of the server-streaming
// shapes the shared dualrun streaming affordance covers (CancelAfterFrames /
// DeadlineAfterFrames / SlowConsumer are all server-streaming) — the assertion below
// stays bespoke. What IS folded onto the shared affordance is the in-process
// transport STANDUP: dualrun.InProcess stands the synthetic server up on a 1 MiB
// bufconn and dials a client at it, exactly the bufconn + grpc.NewServer +
// grpc.NewClient plumbing this test used to hand-roll.
func slowDrainDialer() dualrun.Dialer {
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hostagentv1.RegisterHostAgentServiceServer(s, &slowDrainServer{})
	})
}

type slowDrainServer struct {
	hostagentv1.UnimplementedHostAgentServiceServer
}

func (s *slowDrainServer) ReportHeartbeat(stream grpc.ClientStreamingServer[hostagentv1.ReportHeartbeatRequest, hostagentv1.ReportHeartbeatResponse]) error {
	// Stall: do not drain until the stream's deadline/cancel fires. Then drain
	// whatever is buffered and close, so the server goroutine exits cleanly.
	<-stream.Context().Done()
	for {
		if _, err := stream.Recv(); err == io.EOF {
			return stream.SendAndClose(&hostagentv1.ReportHeartbeatResponse{})
		} else if err != nil {
			return err
		}
	}
}

// TestHeartbeat_SlowDrainBackpressure is the slow-drain back-pressure assertion
// on the send path. It stands up the synthetic non-draining server (through the
// shared dualrun.InProcess transport standup), then tries to Send a burst far
// larger than any flow-control window. The contracted behavior: the client does
// NOT buffer the whole burst — back-pressure blocks the send path once the
// in-flight window fills, and the per-RPC deadline then resolves the call as
// DeadlineExceeded. We assert the client got nowhere near pushing the whole burst
// (back-pressure bit) while still flowing some frames (the window is non-zero), and
// that the stall surfaces a deadline status, not a spurious success.
func TestHeartbeat_SlowDrainBackpressure(t *testing.T) {
	conn, stop, err := slowDrainDialer().Dial(context.Background())
	if err != nil {
		t.Fatalf("dial slow-drain: %v", err)
	}
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	cl := hostagentv1.NewHostAgentServiceClient(conn)
	stream, err := cl.ReportHeartbeat(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// A burst far larger than any plausible flow-control window; if the client
	// buffered unboundedly it would accept all of these before CloseAndRecv.
	const burst = 1 << 20
	// windowCeiling bounds how many frames a FAITHFUL send path may admit against
	// a server that never Recv()s: only what the in-flight HTTP/2 flow-control
	// window (+ the small bufconn pipe) can hold before the sender BLOCKS. It sits
	// deliberately between the observed window (single-digit thousands of
	// 16-byte frames) and what a *draining* server would admit in the same
	// deadline (hundreds of thousands). That separation is what makes the bite
	// deterministic rather than throughput-sensitive: removing the stall (a
	// server that drains) pushes the admitted count above this ceiling and the
	// assertion fires, while the genuine flow-control block stays well under it.
	const windowCeiling = burst / 8 // 131072
	start := time.Now()
	sent := 0
	for i := 0; i < burst; i++ {
		if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{
			Heartbeat: &hostagentv1.Heartbeat{HostId: "host-a", AppliedSeq: uint64(i)},
		}); err != nil {
			break // send path resolved (deadline/cancel) — back-pressure capped us
		}
		sent++
	}
	blockedFor := time.Since(start)

	if sent >= windowCeiling {
		t.Fatalf("send path admitted %d of %d frames against a non-draining server (ceiling %d) — back-pressure did not block at the flow-control window", sent, burst, windowCeiling)
	}
	if sent == 0 {
		t.Fatal("send path accepted zero frames — flow-control window should admit at least one in-flight frame")
	}
	// The faithful path does not return from the send loop until the window
	// blocks and the deadline fires: it spends most of the 500ms budget blocked,
	// not spinning through frames. A send path that errored out immediately
	// (no real back-pressure block) would fall well short of the deadline.
	if blockedFor < 250*time.Millisecond {
		t.Fatalf("send loop returned after only %v — back-pressure did not block the sender until the deadline", blockedFor)
	}

	_, recvErr := stream.CloseAndRecv()
	if status.Code(recvErr) != codes.DeadlineExceeded {
		t.Fatalf("stalled back-pressured stream did not resolve as DeadlineExceeded: code=%v err=%v", status.Code(recvErr), recvErr)
	}
	t.Logf("back-pressure: client admitted %d of %d frames (ceiling %d) then blocked for %v until the deadline fired", sent, burst, windowCeiling, blockedFor)
}
