// SPDX-License-Identifier: Apache-2.0

package controlplane

// heartbeatingest_metering_test.go pins the metering-wire insertion on the LIVE heartbeat
// ingest: newHeartbeatIngest self-arms the landed control-plane MeteringWire behind
// DS_ORCH_METERING_WIRE when its observer exposes a metering sink (meteringSinkProvider),
// so a flag-on ReportHeartbeat fans each frame's D37 RSS/CPU/IO samples into the metering
// stream. Flag-off — or an observer with no sink — stays byte-for-byte the prior ingest
// (no sample row). All synthetic; no gRPC transport, no live host (D50).

import (
	"context"
	"testing"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/metering"
)

// sinkProvidingObserver is a heartbeatObserver that ALSO exposes a metering sink via
// meteringSink() — the shape the reconcile loop presents to the ingest. It stands in for
// the loop so the ingest's self-arm + sample fan-out is asserted without building the
// whole control plane.
type sinkProvidingObserver struct {
	recordingObserver
	sink *meteringSinkFake
}

func (o *sinkProvidingObserver) meteringSink() metering.Sink { return o.sink }

func sampleFrame(hostID string, samples ...*hostagentv1.SessionSample) *hostagentv1.ReportHeartbeatRequest {
	return &hostagentv1.ReportHeartbeatRequest{Heartbeat: sampleHB(hostID, samples...)}
}

// TestHeartbeatIngest_FlagOnFansSamples is the headline heartbeat metering-wire
// acceptance: with the flag on and a sink-providing observer, ReportHeartbeat appends the
// D37 samples carried on each frame into the metering stream — the insertion the ingest
// previously never made. Each sample rides the stream as a KindSample event (never a
// billing accrual — empty §3 state).
func TestHeartbeatIngest_FlagOnFansSamples(t *testing.T) {
	t.Setenv(MeteringWireFlag, "1")

	obs := &sinkProvidingObserver{sink: newMeteringSinkFake()}
	ingest := newHeartbeatIngest(obs, nil)
	if ingest.metering == nil {
		t.Fatal("flag-on ingest with a sink-providing observer did not self-arm the metering wire")
	}

	stream := &fakeIngestStream{
		ctx: context.Background(),
		frames: []*hostagentv1.ReportHeartbeatRequest{
			sampleFrame("host-a",
				&hostagentv1.SessionSample{SessionUuid: "s1", SampledAt: 10, RssBytes: 111},
				&hostagentv1.SessionSample{SessionUuid: "s2", SampledAt: 11, CpuNanos: 222},
			),
			sampleFrame("host-a",
				&hostagentv1.SessionSample{SessionUuid: "s1", SampledAt: 20, RssBytes: 333},
			),
		},
	}
	if err := ingest.ReportHeartbeat(stream); err != nil {
		t.Fatalf("ReportHeartbeat: %v", err)
	}
	// Both frames still routed to Observe (the metering fan-out is purely additive on top
	// of the unchanged reconcile path).
	if obs.count() != 2 {
		t.Errorf("Observe reached %d times, want 2 (fan-out additive on the reconcile path)", obs.count())
	}
	// Three distinct samples appended (s1@10, s2@11, s1@20).
	if len(obs.sink.seq) != 3 {
		t.Fatalf("flag-on ingest appended %d sample events, want 3", len(obs.sink.seq))
	}
	for _, e := range obs.sink.seq {
		if e.Kind != metering.KindSample {
			t.Errorf("appended event kind = %q, want %q (samples never bill)", e.Kind, metering.KindSample)
		}
		if e.State != "" {
			t.Errorf("sample event carried a §3 state %q, want empty (never a billing accrual)", e.State)
		}
	}
}

// TestHeartbeatIngest_FlagOnReIngestIsIdempotent proves the §5.6 idempotency rides the
// ingest: re-ingesting the SAME heartbeat sample (same session_uuid + sampled_at) is a
// no-op at the store — the metering stream never double-counts a duplicated frame.
func TestHeartbeatIngest_FlagOnReIngestIsIdempotent(t *testing.T) {
	t.Setenv(MeteringWireFlag, "1")

	obs := &sinkProvidingObserver{sink: newMeteringSinkFake()}
	ingest := newHeartbeatIngest(obs, nil)

	dup := &hostagentv1.SessionSample{SessionUuid: "s1", SampledAt: 10, RssBytes: 111}
	stream := &fakeIngestStream{
		ctx: context.Background(),
		frames: []*hostagentv1.ReportHeartbeatRequest{
			sampleFrame("host-a", dup),
			sampleFrame("host-a", dup), // duplicate frame
		},
	}
	if err := ingest.ReportHeartbeat(stream); err != nil {
		t.Fatalf("ReportHeartbeat: %v", err)
	}
	if len(obs.sink.seq) != 1 {
		t.Fatalf("re-ingesting a duplicated sample appended %d rows, want 1 (idempotent)", len(obs.sink.seq))
	}
}

// TestHeartbeatIngest_FlagOffStaysInert pins the default-off invariant: with the flag
// unset, the ingest does NOT arm the metering wire even when the observer exposes a sink,
// so ReportHeartbeat appends no sample — byte-for-byte the prior ingest behavior.
func TestHeartbeatIngest_FlagOffStaysInert(t *testing.T) {
	t.Setenv(MeteringWireFlag, "0")

	obs := &sinkProvidingObserver{sink: newMeteringSinkFake()}
	ingest := newHeartbeatIngest(obs, nil)
	if ingest.metering != nil {
		t.Fatal("flag-off ingest armed the metering wire; want nil (byte-identical when off)")
	}

	stream := &fakeIngestStream{
		ctx: context.Background(),
		frames: []*hostagentv1.ReportHeartbeatRequest{
			sampleFrame("host-a", &hostagentv1.SessionSample{SessionUuid: "s1", SampledAt: 10, RssBytes: 1}),
		},
	}
	if err := ingest.ReportHeartbeat(stream); err != nil {
		t.Fatalf("ReportHeartbeat: %v", err)
	}
	if obs.count() != 1 {
		t.Errorf("Observe reached %d times, want 1 (reconcile path unchanged)", obs.count())
	}
	if len(obs.sink.seq) != 0 {
		t.Fatalf("flag-off ingest appended %d sample events, want 0", len(obs.sink.seq))
	}
}

// TestHeartbeatIngest_FlagOnNoSinkObserverStaysInert proves the arming requires BOTH the
// flag AND a sink-exposing observer: with the flag on but an observer that does not
// provide a sink (a bare recordingObserver — the WatchSession attachrelay path, or a test
// double), the ingest leaves the wire unarmed and appends nothing.
func TestHeartbeatIngest_FlagOnNoSinkObserverStaysInert(t *testing.T) {
	t.Setenv(MeteringWireFlag, "1")

	obs := &recordingObserver{}
	ingest := newHeartbeatIngest(obs, nil)
	if ingest.metering != nil {
		t.Fatal("ingest armed the metering wire without a sink-providing observer; want nil")
	}
	stream := &fakeIngestStream{
		ctx:    context.Background(),
		frames: []*hostagentv1.ReportHeartbeatRequest{sampleFrame("host-a", &hostagentv1.SessionSample{SessionUuid: "s1", SampledAt: 10})},
	}
	if err := ingest.ReportHeartbeat(stream); err != nil {
		t.Fatalf("ReportHeartbeat: %v", err)
	}
	if obs.count() != 1 {
		t.Errorf("Observe reached %d times, want 1", obs.count())
	}
}
