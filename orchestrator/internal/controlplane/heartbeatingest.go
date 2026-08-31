package controlplane

// heartbeatingest.go is LEG (c) of the live-edge fill: the HostAgent-FACING heartbeat
// intake. It is the orchestrator SERVER side of the frozen hostagent.v1
// HostAgentService.ReportHeartbeat client-streaming RPC (doc 15 §5.2: the host agent
// opens one long-lived stream and emits a ReportHeartbeatRequest carrying one Heartbeat
// per cadence interval; the response is returned at stream close). Each inbound
// Heartbeat is fed into the orch19 reconcile loop's Observe path — the single-goroutine
// submit (reconcileloop.go) — so a heartbeat both (1) RECORDS into the live HeartbeatStore
// feed the scheduler reads for placement candidates AND (2) SUBMITS a reconcile, with the
// level-triggered drop-on-full-buffer semantics preserved (a dropped submit is recovered
// by the next heartbeat / the periodic resync — reconcileLoop.Observe owns both).
//
// CLIENT-STREAMING SHAPE (frozen). hostagent.v1 froze ReportHeartbeat as CLIENT-STREAMING
// (heartbeat_grpc.pb.go): the host agent streams frames UP and the orchestrator returns
// ONE ReportHeartbeatResponse at stream close (a beats-received count — steady-state
// observed state rides the stream, not the response, per the frozen comment). So this
// server loops grpc.ClientStreamingServer.Recv until io.EOF (graceful host drain) or a
// context cancel (the connection closed), routing every frame's Heartbeat through
// Observe, then SendAndClose's the close-path response. The Recv loop is per-connection
// (one goroutine per host stream); Observe is safe to call from many such goroutines (it
// submits onto the loop's channel — the reconcileLoop's single-goroutine contract holds).
//
// WHY THE INGEST IS DECOUPLED FROM THE RECONCILER (the Observe seam). The ingest does NOT
// touch the reconciler's mutable lastBeat map directly — it calls reconcileLoop.Observe,
// which records the feed and submits onto the loop's inbound channel. Only the loop's Run
// goroutine touches the reconciler. So this server can be registered on the gRPC server
// alongside the SessionService and serve concurrent host streams without racing the
// reconciler (reconcileloop.go's serialization). D50: no live host-agent — the tests
// drive synthetic Heartbeats through a bufconn ReportHeartbeat stream (or call the
// server's stream handler with a fake stream), asserting both the feed and Observe.

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"google.golang.org/grpc"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/metering"
)

// meteringSinkProvider is the OPTIONAL probe the ingest uses to arm its D37
// heartbeat-sample metering fan-out WITHOUT threading a new constructor parameter
// through serve.go's newHeartbeatIngest call (which this unit does not own). The
// live observer is the reconcile loop (reconcileloop.go), which exposes meteringSink()
// over the SAME backing store the rest of the control plane is wired from (its
// escalation lister). A relay/observer that does not expose a sink (the WatchSession
// attachrelay path, or a bare test double) simply leaves the metering wire unarmed —
// the fan-out then stays a no-op, byte-for-byte the prior ingest behavior.
type meteringSinkProvider interface {
	meteringSink() metering.Sink
}

// heartbeatObserver is the narrow submit seam the ingest routes each inbound Heartbeat
// through — exactly reconcileLoop.Observe (reconcileloop.go). Declared narrow here so the
// ingest depends only on the one method (the level-triggered record-feed + submit-reconcile
// entrypoint), interchangeable with a test double that records what it was handed.
type heartbeatObserver interface {
	Observe(ctx context.Context, hb *hostagentv1.Heartbeat) error
}

// heartbeatIngest is the orchestrator-side hostagent.v1 HostAgentService server. It
// implements the frozen client-streaming ReportHeartbeat by routing each inbound frame's
// Heartbeat through the reconcile loop's Observe (the live-feed record + reconcile submit).
// Construct with newHeartbeatIngest (via the serve bootstrap); register it on the gRPC
// server with RegisterHostAgentServiceServer. It embeds the frozen
// UnimplementedHostAgentServiceServer for forward compatibility (a v2 RPC stays
// unimplemented until its wiring lands).
type heartbeatIngest struct {
	hostagentv1.UnimplementedHostAgentServiceServer

	observer heartbeatObserver
	logger   *slog.Logger

	// metering is the OPTIONAL flag-gated D37 heartbeat-sample metering fan-out
	// (metering-wire): when armed, ReportHeartbeat appends each inbound frame's
	// RSS/CPU/IO SessionSamples into the landed metering stream (meteringwire.go's
	// EmitHeartbeatSamples). It is NIL by default — arming requires BOTH the
	// DS_ORCH_METERING_WIRE flag AND an observer that exposes a metering sink
	// (meteringSinkProvider). A nil wire leaves the ingest byte-for-byte unchanged,
	// so a non-live/gate-off run never appends a sample row.
	metering *MeteringWire
}

// newHeartbeatIngest builds the ingest server over the reconcile loop's Observe seam.
// observer is the reconcileLoop (its Observe records the feed + submits the reconcile).
//
// It self-arms the OPTIONAL D37 heartbeat-sample metering fan-out (metering-wire): when
// DS_ORCH_METERING_WIRE is set AND the observer exposes a metering sink (the reconcile
// loop does, over its escalation-installed store), it builds an armed control-plane
// MeteringWire so each inbound heartbeat's samples flow into the metering stream. Gate
// OFF — the default — or an observer with no sink leaves metering nil and the ingest
// byte-for-byte unchanged. The env read happens ONCE at construction (registration
// time), never on the per-frame hot path.
func newHeartbeatIngest(observer heartbeatObserver, logger *slog.Logger) *heartbeatIngest {
	if logger == nil {
		logger = slog.Default()
	}
	ing := &heartbeatIngest{observer: observer, logger: logger}
	if MeteringWireEnabled() {
		if p, ok := observer.(meteringSinkProvider); ok {
			if sink := p.meteringSink(); sink != nil {
				ing.metering = NewMeteringWire(sink, true)
			}
		}
	}
	return ing
}

// ReportHeartbeat is the frozen hostagent.v1 client-streaming server method (doc 15 §5.2):
// it drains the host's long-lived heartbeat stream, routing each frame's Heartbeat through
// the reconcile loop's Observe (recording the live feed + submitting a reconcile), and
// SendAndClose's the close-path response (a beats-received count) at graceful drain.
//
// The Recv loop ends on io.EOF (the host closed the stream — a graceful drain) with a
// clean response, or on a context cancel / transport error (surfaced to the host so it
// re-dials). A nil-or-empty frame is counted but skipped (a malformed feed entry is never
// a reconcile input — Observe also ignores a nil heartbeat, defense in depth). A frame
// whose Observe submit drops (the reconcile buffer full) is still counted and recorded
// (the feed update is unconditional; the level-triggered model recovers a dropped submit
// on the next frame / resync — reconcileLoop.Observe's contract).
func (s *heartbeatIngest) ReportHeartbeat(stream grpc.ClientStreamingServer[hostagentv1.ReportHeartbeatRequest, hostagentv1.ReportHeartbeatResponse]) error {
	ctx := stream.Context()
	var received uint64
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			// Graceful host drain: close the stream with the beats-received count.
			return stream.SendAndClose(&hostagentv1.ReportHeartbeatResponse{BeatsReceived: received})
		}
		if err != nil {
			// A transport error or a context cancel (the connection closed). Surface it so
			// the host re-dials; the feed already holds the latest recorded snapshot and the
			// periodic resync re-converges (the level-triggered property).
			return err
		}
		received++
		hb := req.GetHeartbeat()
		if hb == nil || hb.GetHostId() == "" {
			// A malformed frame: counted (the host emitted it) but not routed (no reconcile
			// key / placement target). Observe also drops a nil heartbeat; skipping here keeps
			// the warn local to the ingest.
			s.logger.WarnContext(ctx, "heartbeat ingest: dropped malformed frame (nil heartbeat or empty host_id)")
			continue
		}
		// FLAG-GATED D37 HEARTBEAT-SAMPLE METERING (metering-wire): fan the frame's
		// per-session RSS/CPU/IO SessionSamples into the landed metering stream (§5.2/§5.6).
		// Each sample is idempotent on (session_uuid, sampled_at) — a re-ingested
		// duplicate heartbeat is a no-op at the store — and a frame with no samples is a
		// clean no-op. A metering append fault is LOGGED and the stream CONTINUES: samples
		// are short-retention (d)-rig rollup, never billing accruals (they carry no §3
		// state), so a sample-append hiccup must never tear down a live host stream. When
		// the wire is nil (gate off, or an observer with no sink — the default) this block
		// is skipped, so the ingest is byte-for-byte its prior behavior.
		if s.metering != nil {
			if merr := s.metering.EmitHeartbeatSamples(ctx, hb); merr != nil {
				s.logger.WarnContext(ctx, "heartbeat ingest: D37 sample metering append failed (continuing; idempotent re-ingest recovers)",
					slog.String("host", hb.GetHostId()), slog.Any("err", merr))
			}
		}
		// Route the frame's Heartbeat through the reconcile loop's Observe: it RECORDS the
		// live feed (the scheduler's candidate input) AND SUBMITS a reconcile (the
		// single-goroutine drop-on-full-buffer submit). A submit-path context cancel ends
		// the stream; a buffer-full drop is absorbed by Observe (feed updated, submit
		// dropped, resync re-converges) and returns nil — never a stream-killing error.
		if oerr := s.observer.Observe(ctx, hb); oerr != nil {
			if ctx.Err() != nil {
				// The stream's context was cancelled (the host disconnected mid-submit) — end
				// the stream cleanly with the count so far.
				return oerr
			}
			// A non-cancel Observe fault is logged and the stream continues (the
			// level-triggered loop re-converges); never tear down a live host stream on a
			// transient submit fault.
			s.logger.WarnContext(ctx, "heartbeat ingest: Observe fault (continuing; level-triggered re-converges)",
				slog.String("host", hb.GetHostId()), slog.Any("err", oerr))
		}
	}
}

// Compile-time proof the ingest satisfies the frozen hostagent.v1 server interface — so
// the serve bootstrap registers it with RegisterHostAgentServiceServer alongside the
// SessionService.
var _ hostagentv1.HostAgentServiceServer = (*heartbeatIngest)(nil)
