// SPDX-License-Identifier: Apache-2.0

package hostagent

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1/hostagentv1fake"
)

// backpressureBurst is the frame count for the back-pressure scenario: a burst
// large enough that a naive unbounded client buffer would be observable, yet
// small enough to drain promptly against the steady-state servers. The point of
// the scenario is that against a server that DOES drain, every frame is accepted
// on the (flow-controlled) send path and the exact tally returns — real and fake
// agree. The complementary slow-drain proof (a server that does NOT drain bounds
// the client's in-flight sends rather than buffering unboundedly) lives in
// dualrun_test.go, where a synthetic non-draining server can be stood up.
const backpressureBurst = 4096

// Suite is the host agent seam's single conformance suite (doc 06 §3a: one
// suite, run against real + fake). Every scenario is stated purely in terms of
// the frozen hostagent.v1 contract so the same suite is meaningful against any
// faithful implementation.
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "orchestrator<->hostagent",
		Scenarios: scenarios(),
	}
}

func scenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "steady-state/three-beats-then-graceful-close",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hostagentv1.NewHostAgentServiceClient(conn)
				stream, err := cl.ReportHeartbeat(ctx)
				if err != nil {
					return nil, err
				}
				for i := 0; i < 3; i++ {
					if err := stream.Send(beat("host-a", uint64(i))); err != nil {
						return nil, err
					}
				}
				resp, err := stream.CloseAndRecv()
				return closeObservation(resp, err), nil
			},
		},
		{
			Name: "empty-stream/immediate-close-counts-zero",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hostagentv1.NewHostAgentServiceClient(conn)
				stream, err := cl.ReportHeartbeat(ctx)
				if err != nil {
					return nil, err
				}
				resp, err := stream.CloseAndRecv()
				return closeObservation(resp, err), nil
			},
		},
		{
			Name: "invalid/frame-without-heartbeat-is-rejected",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hostagentv1.NewHostAgentServiceClient(conn)
				stream, err := cl.ReportHeartbeat(ctx)
				if err != nil {
					return nil, err
				}
				// A frame with no Heartbeat — the contract carries exactly one
				// Heartbeat per frame (doc 15 §5.2). The server must reject it.
				if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{}); err != nil {
					// A send error after server-side rejection is contract-legal;
					// the resolving Recv below carries the status.
					_ = err
				}
				resp, err := stream.CloseAndRecv()
				return closeObservation(resp, err), nil
			},
		},
		{
			Name: "invalid/heartbeat-missing-host-id-is-rejected",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hostagentv1.NewHostAgentServiceClient(conn)
				stream, err := cl.ReportHeartbeat(ctx)
				if err != nil {
					return nil, err
				}
				if err := stream.Send(beat("", 0)); err != nil {
					_ = err
				}
				resp, err := stream.CloseAndRecv()
				return closeObservation(resp, err), nil
			},
		},
		{
			// Mid-stream cancellation. ReportHeartbeat is CLIENT-streaming
			// (heartbeat.pb.go: ClientStreams:true; no server-streaming verb on
			// HostAgentService), so the "server stops sending after cancel"
			// framing is adapted to the real verb: the host opens the stream,
			// emits K beats, then the client context is canceled MID-STREAM —
			// before the graceful CloseAndRecv. The contract (doc 15 §5.2: the
			// response returns only on graceful drain) means a canceled stream
			// MUST surface a context-cancellation terminal status from the
			// resolving CloseAndRecv, and MUST NOT yield a success / zero-value
			// tally. gRPC enforces this at the client transport, so any faithful
			// server end — refimpl or fake — is observed identically: Canceled,
			// no response. cancelObservation records exactly that, and the
			// dual-run requires real and fake to AGREE.
			Name: "cancel/mid-stream-cancel-yields-canceled-no-spurious-response",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cancelCtx, cancel := context.WithCancel(ctx)
				cl := hostagentv1.NewHostAgentServiceClient(conn)
				stream, err := cl.ReportHeartbeat(cancelCtx)
				if err != nil {
					cancel()
					return nil, err
				}
				// K beats stream up before the host is interrupted.
				const k = 3
				for i := 0; i < k; i++ {
					if err := stream.Send(beat("host-a", uint64(i))); err != nil {
						// A send racing the in-flight cancel is contract-legal;
						// the resolving CloseAndRecv below carries the terminal
						// status, which is what the Observation records.
						_ = err
					}
				}
				// Interrupt mid-stream, BEFORE graceful close.
				cancel()
				resp, recvErr := stream.CloseAndRecv()
				return cancelObservation(resp, recvErr), nil
			},
		},
		{
			// Back-pressure on the send path. A burst far larger than a single
			// cadence tick is streamed up; the client-streaming send path is
			// flow-controlled, so back-pressure is applied by BLOCKING the
			// sender (never by dropping frames or erroring), and against a
			// server that drains, every frame is accepted and the EXACT tally
			// returns on close. This is the dual-run-comparable face of the
			// flow-control contract: no loss, no spurious error, real and fake
			// drain identically. (The slow-drain proof — that a server which
			// does NOT drain bounds the client's in-flight sends rather than
			// letting it buffer the whole burst — needs a synthetic
			// non-draining server and lives in dualrun_test.go.)
			Name: "backpressure/large-burst-fully-drained-in-order",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hostagentv1.NewHostAgentServiceClient(conn)
				stream, err := cl.ReportHeartbeat(ctx)
				if err != nil {
					return nil, err
				}
				sendErrs := 0
				for i := 0; i < backpressureBurst; i++ {
					if err := stream.Send(beat("host-a", uint64(i))); err != nil {
						sendErrs++
					}
				}
				resp, recvErr := stream.CloseAndRecv()
				obs := closeObservation(resp, recvErr)
				// Record that the flow-controlled send path accepted the whole
				// burst with no errors — back-pressure stayed a block, not a
				// drop. Both ends must agree on this and on the exact tally.
				obs.Setf("frames_sent", "%d", backpressureBurst)
				obs.Setf("send_errors", "%d", sendErrs)
				return obs, nil
			},
		},
	}
}

func beat(hostID string, seq uint64) *hostagentv1.ReportHeartbeatRequest {
	return &hostagentv1.ReportHeartbeatRequest{
		Heartbeat: &hostagentv1.Heartbeat{HostId: hostID, AppliedSeq: seq},
	}
}

// closeObservation renders the contract-observable result of closing the
// heartbeat stream: the gRPC status code, and on success the returned beat tally.
func closeObservation(resp *hostagentv1.ReportHeartbeatResponse, err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	if err != nil {
		obs.Set("status", status.Code(err).String())
		return obs
	}
	obs.Set("status", codes.OK.String())
	obs.Setf("beats_received", "%d", resp.GetBeatsReceived())
	return obs
}

// cancelObservation renders the contract-observable result of a mid-stream
// cancellation: the terminal gRPC status the resolving CloseAndRecv surfaced,
// and — critically — whether ANY response was handed back. A canceled
// client-streaming RPC must terminate with a context-cancellation status
// (codes.Canceled) and MUST NOT yield a success / zero-value ReportHeartbeatResponse
// (doc 15 §5.2: the tally returns only on graceful drain). Recording
// response_present (rather than the beat count, which is meaningless on a
// canceled stream) is what lets the dual-run catch a drift that fabricates a
// spurious zero-value success after cancel: such a recorder would report
// terminal_status=OK / response_present=true and diverge from this honest one.
func cancelObservation(resp *hostagentv1.ReportHeartbeatResponse, err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	if err != nil {
		obs.Set("terminal_status", status.Code(err).String())
		obs.Set("response_present", "false")
		return obs
	}
	// No error after a mid-stream cancel is itself a contract violation — a
	// spurious success. Record it faithfully so the dual-run surfaces it
	// instead of masking it.
	obs.Set("terminal_status", codes.OK.String())
	obs.Set("response_present", "true")
	return obs
}

// RealDialer returns the dual-run Dialer for the real reference implementation.
func RealDialer() dualrun.Dialer {
	impl := NewRefImpl()
	return dualrun.InProcess(impl.Register)
}

// FakeDialer returns the dual-run Dialer for the GENERATED programmable fake,
// programmed to the same contract the suite asserts. Programming the fake to the
// contract — rather than wiring a hand-written second implementation — is the
// point: the dual-run proves the generated fake, driven only through its
// canned-response surface, is observationally identical to the real impl on
// every scenario. If a future contract change makes the two diverge, the gate
// (dualrun_test.go) fails.
func FakeDialer() dualrun.Dialer {
	f := hostagentv1fake.NewHostAgentServiceFake()
	f.ReportHeartbeatResponder = func(_ context.Context, reqs []*hostagentv1.ReportHeartbeatRequest) (*hostagentv1.ReportHeartbeatResponse, error) {
		var beats uint64
		for _, frame := range reqs {
			hb := frame.GetHeartbeat()
			if hb == nil {
				return nil, status.Error(codes.InvalidArgument, "ReportHeartbeatRequest carries no Heartbeat")
			}
			if hb.GetHostId() == "" {
				return nil, status.Error(codes.InvalidArgument, "Heartbeat.host_id is required")
			}
			beats++
		}
		return &hostagentv1.ReportHeartbeatResponse{BeatsReceived: beats}, nil
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hostagentv1fake.RegisterHostAgentService(s, f)
	})
}
