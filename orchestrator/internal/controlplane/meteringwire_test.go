// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"testing"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// meteringSinkFake is a synthetic metering.Sink recording every appended event,
// collapsing by EventID exactly as the real store does (identical body under the
// same key = idempotent no-op; differing body = conflict) — so the test asserts
// the idempotent re-ingest property with no live store (D50).
type meteringSinkFake struct {
	byID map[string]store.MeteringEvent
	seq  []store.MeteringEvent
}

func newMeteringSinkFake() *meteringSinkFake {
	return &meteringSinkFake{byID: make(map[string]store.MeteringEvent)}
}

func (s *meteringSinkFake) AppendMeteringEvent(_ context.Context, e store.MeteringEvent) error {
	if prior, ok := s.byID[e.EventID]; ok {
		if prior.SessionUUID != e.SessionUUID || string(prior.Payload) != string(e.Payload) {
			return store.ErrConflict
		}
		return nil
	}
	s.byID[e.EventID] = e
	s.seq = append(s.seq, e)
	return nil
}

func sampleHB(hostID string, samples ...*hostagentv1.SessionSample) *hostagentv1.Heartbeat {
	return &hostagentv1.Heartbeat{HostId: hostID, Samples: samples}
}

func TestCPMeteringWireDisabledIsInert(t *testing.T) {
	sink := newMeteringSinkFake()
	w := NewMeteringWire(sink, false)
	if w.Enabled() {
		t.Fatal("disabled wire reported Enabled")
	}
	hb := sampleHB("host-1", &hostagentv1.SessionSample{SessionUuid: "s1", SampledAt: 10, RssBytes: 1})
	if err := w.EmitHeartbeatSamples(context.Background(), hb); err != nil {
		t.Fatalf("disabled EmitHeartbeatSamples: %v", err)
	}
	if err := w.EmitStateTransition(context.Background(), "s1", store.SessionWorking, time.Unix(1, 0)); err != nil {
		t.Fatalf("disabled EmitStateTransition: %v", err)
	}
	if len(sink.seq) != 0 {
		t.Fatalf("disabled wire appended %d events, want 0", len(sink.seq))
	}
}

func TestCPMeteringWireHeartbeatSamplesFanOut(t *testing.T) {
	sink := newMeteringSinkFake()
	w := NewMeteringWire(sink, true)
	hb := sampleHB("host-1",
		&hostagentv1.SessionSample{SessionUuid: "s1", SampledAt: 10, RssBytes: 100},
		&hostagentv1.SessionSample{SessionUuid: "s2", SampledAt: 11, CpuNanos: 200},
	)
	if err := w.EmitHeartbeatSamples(context.Background(), hb); err != nil {
		t.Fatalf("EmitHeartbeatSamples: %v", err)
	}
	if len(sink.seq) != 2 {
		t.Fatalf("appended %d sample events, want 2", len(sink.seq))
	}
	for _, e := range sink.seq {
		if e.Kind != "sample" {
			t.Fatalf("heartbeat sample event kind = %q, want sample", e.Kind)
		}
		if e.State != "" {
			t.Fatalf("sample event carried a §3 state %q; a sample enters no state", e.State)
		}
		if len(e.Payload) == 0 {
			t.Fatal("sample event carried an empty payload; want the encoded D37 sample")
		}
	}
}

func TestCPMeteringWireHeartbeatReIngestIdempotent(t *testing.T) {
	sink := newMeteringSinkFake()
	w := NewMeteringWire(sink, true)
	hb := sampleHB("host-1", &hostagentv1.SessionSample{SessionUuid: "s1", SampledAt: 10, RssBytes: 100})
	for i := 0; i < 3; i++ {
		if err := w.EmitHeartbeatSamples(context.Background(), hb); err != nil {
			t.Fatalf("re-ingest %d: %v", i, err)
		}
	}
	if len(sink.seq) != 1 {
		t.Fatalf("re-ingesting one heartbeat appended %d rows, want 1 (idempotent)", len(sink.seq))
	}
}

func TestCPMeteringWireNilAndEmptyHeartbeatNoOp(t *testing.T) {
	sink := newMeteringSinkFake()
	w := NewMeteringWire(sink, true)
	if err := w.EmitHeartbeatSamples(context.Background(), nil); err != nil {
		t.Fatalf("nil heartbeat: %v", err)
	}
	if err := w.EmitHeartbeatSamples(context.Background(), sampleHB("host-1")); err != nil {
		t.Fatalf("no-sample heartbeat: %v", err)
	}
	if len(sink.seq) != 0 {
		t.Fatalf("nil/empty heartbeat appended %d rows, want 0", len(sink.seq))
	}
}

func TestCPMeteringWireStateTransitionEmits(t *testing.T) {
	sink := newMeteringSinkFake()
	w := NewMeteringWire(sink, true)
	if err := w.EmitStateTransition(context.Background(), "s1", store.SessionWorking, time.Unix(1000, 0)); err != nil {
		t.Fatalf("EmitStateTransition: %v", err)
	}
	if len(sink.seq) != 1 || sink.seq[0].State != store.SessionWorking || sink.seq[0].Kind != "state_transition" {
		t.Fatalf("transition event mismatch: %+v", sink.seq)
	}
}
