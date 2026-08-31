// SPDX-License-Identifier: Apache-2.0

package hostagent

import (
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// RefImpl is a minimal honest reference implementation of HostAgentService — the
// "real implementation" side of the dual-run. It implements exactly the doc 15
// §5.2 contract for ReportHeartbeat: the host opens one stream and emits a
// Heartbeat per cadence; the reconciler consumes the stream; the response is
// returned on graceful close carrying the number of beats received. A frame
// missing its Heartbeat (or a Heartbeat missing host_id) is an
// InvalidArgument — the contract carries exactly one Heartbeat per frame and the
// reconciler keys observed state by host_id.
//
// This is the M0 stand-in until the production host-agent reporting server lands
// (orchestrator/internal/reconciler consumes this seam). When that lands, it
// replaces RefImpl as the "real" end and the conformance suite is unchanged —
// which is the whole point: the suite is the contract, not the implementation.
type RefImpl struct {
	hostagentv1.UnimplementedHostAgentServiceServer
}

// NewRefImpl returns a reference HostAgentService server.
func NewRefImpl() *RefImpl { return &RefImpl{} }

// ReportHeartbeat consumes the client-streamed heartbeats and returns the count
// on close (doc 15 §5.2). Steady-state observed state rides the stream; only the
// tally returns in the response.
func (s *RefImpl) ReportHeartbeat(stream grpc.ClientStreamingServer[hostagentv1.ReportHeartbeatRequest, hostagentv1.ReportHeartbeatResponse]) error {
	var beats uint64
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&hostagentv1.ReportHeartbeatResponse{BeatsReceived: beats})
		}
		if err != nil {
			return err
		}
		hb := frame.GetHeartbeat()
		if hb == nil {
			return status.Error(codes.InvalidArgument, "ReportHeartbeatRequest carries no Heartbeat")
		}
		if hb.GetHostId() == "" {
			return status.Error(codes.InvalidArgument, "Heartbeat.host_id is required (reconciler keys observed state by host)")
		}
		beats++
	}
}

// Register registers the reference impl on a grpc.ServiceRegistrar.
func (s *RefImpl) Register(reg grpc.ServiceRegistrar) {
	hostagentv1.RegisterHostAgentServiceServer(reg, s)
}
