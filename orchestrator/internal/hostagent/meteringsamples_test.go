// SPDX-License-Identifier: Apache-2.0

package hostagent

import (
	"testing"
)

func sampleMetrics() []SessionMetrics {
	return []SessionMetrics{
		{SessionUUID: "s1", RSSBytes: 100, CPUNanos: 200, IOReadBytes: 1, IOWriteBytes: 2, SampledAt: 10},
		{SessionUUID: "s2", RSSBytes: 300, CPUNanos: 400, SampledAt: 11},
	}
}

func TestSampleEmitterDisabledEmitsNothing(t *testing.T) {
	e := NewSampleEmitter(false)
	if e.Enabled() {
		t.Fatal("disabled emitter reported Enabled")
	}
	if got := e.Emit(sampleMetrics()); got != nil {
		t.Fatalf("disabled Emit returned %d samples, want nil", len(got))
	}
}

func TestSampleEmitterDisabledLeavesStateUnchanged(t *testing.T) {
	e := NewSampleEmitter(false)
	state := HostState{HostID: "host-1"}
	got := e.AttachToState(state, sampleMetrics())
	if got.Samples != nil {
		t.Fatalf("disabled AttachToState added %d samples, want none", len(got.Samples))
	}
}

func TestSampleEmitterArmedBuildsWireSamples(t *testing.T) {
	e := NewSampleEmitter(true)
	samples := e.Emit(sampleMetrics())
	if len(samples) != 2 {
		t.Fatalf("armed Emit returned %d samples, want 2", len(samples))
	}
	if samples[0].GetSessionUuid() != "s1" || samples[0].GetRssBytes() != 100 || samples[0].GetSampledAt() != 10 {
		t.Fatalf("sample[0] mismatch: %+v", samples[0])
	}
	if samples[1].GetCpuNanos() != 400 {
		t.Fatalf("sample[1] cpu_nanos = %d, want 400", samples[1].GetCpuNanos())
	}
}

func TestSampleEmitterSkipsEmptyUUID(t *testing.T) {
	e := NewSampleEmitter(true)
	got := e.Emit([]SessionMetrics{{SessionUUID: "", RSSBytes: 1, SampledAt: 1}})
	if got != nil {
		t.Fatalf("empty-uuid metric produced %d samples, want nil", len(got))
	}
}

func TestSampleEmitterAttachToStateFoldsSamples(t *testing.T) {
	e := NewSampleEmitter(true)
	state := HostState{HostID: "host-1"}
	got := e.AttachToState(state, sampleMetrics())
	if len(got.Samples) != 2 {
		t.Fatalf("AttachToState folded %d samples, want 2", len(got.Samples))
	}
	// The folded samples must survive into the assembled frame.
	frame := BuildHeartbeat(got)
	if len(frame.GetSamples()) != 2 {
		t.Fatalf("heartbeat frame carried %d samples, want 2", len(frame.GetSamples()))
	}
}

func TestEncodedPayloadIsDeterministic(t *testing.T) {
	e := NewSampleEmitter(true)
	samples := e.Emit(sampleMetrics())
	a := EncodedPayload(samples[0])
	b := EncodedPayload(samples[0])
	if len(a) == 0 {
		t.Fatal("EncodedPayload returned empty bytes")
	}
	if string(a) != string(b) {
		t.Fatalf("EncodedPayload not deterministic: %q vs %q", a, b)
	}
	// A distinct sample must encode to distinct bytes (no payload collision).
	if string(a) == string(EncodedPayload(samples[1])) {
		t.Fatal("distinct samples produced identical payloads")
	}
}

func TestPreviewEventIDIdempotentOnSessionAndTime(t *testing.T) {
	e := NewSampleEmitter(true)
	samples := e.Emit(sampleMetrics())
	id1 := PreviewEventID(samples[0])
	// Re-emit the SAME session at the SAME instant (different RSS) — the sample
	// EventID keys on (session, sampled_at), so the preview key is stable.
	resampled := e.Emit([]SessionMetrics{{SessionUUID: "s1", RSSBytes: 999, SampledAt: 10}})
	id2 := PreviewEventID(resampled[0])
	if id1 != id2 {
		t.Fatalf("PreviewEventID drifted for same (session, sampled_at): %q vs %q", id1, id2)
	}
	// A different instant yields a different key.
	other := e.Emit([]SessionMetrics{{SessionUUID: "s1", SampledAt: 99}})
	if PreviewEventID(other[0]) == id1 {
		t.Fatal("PreviewEventID collided across distinct sampled_at")
	}
}
