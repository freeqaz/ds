// SPDX-License-Identifier: Apache-2.0

package hostagent

// meteringsamples.go is the FLAG-GATED host-side D37 sample emission for the
// heartbeat: it builds the per-session RSS/CPU/IO SessionSamples (doc 15 §5.2 /
// §5.6) the host agent folds into a HostState before BuildHeartbeat assembles the
// frame, so the orchestrator's metering stream has a live producer for the
// short-retention (d)-rig rollup — behind a flag, default off.
//
// WHY A NEW FILE, NOT AN EDIT (the wave-1 boundary). internal/metering is frozen
// wave-1 surface: this file IMPORTS it (metering.EncodeSample / metering.SampleEvent)
// and never edits it. The heartbeat assembly (heartbeat.go) is also untouched —
// BuildHeartbeat already carries HostState.Samples through to the frame; this file
// only PRODUCES those samples (the emission half) behind a flag and exposes the
// EXACT opaque payload bytes (via metering.EncodeSample) that will ride to the
// orchestrator's metering sample event, so a host operator can log/verify the
// host→orchestrator sample identity without a live orchestrator.
//
// FLAG-GATED, DEFAULT OFF (D50). Emission arms only when the deployment opts in
// (MeteringSamplesEnabled, env DS_ORCH_METERING_WIRE=1 — the SAME flag the
// orchestrator-side metering call-sites read, so one switch arms the whole sample
// path end to end). Off — the wave default — Emit returns nil and the heartbeat
// carries no samples, exactly its prior behavior. The builder takes the enabled
// bool EXPLICITLY so a test arms it without process env.
//
// SAMPLES NEVER BILL (§5.6). A D37 sample is short-retention rollup data, NOT a
// billing accrual: the orchestrator records it under KindSample with an empty §3
// state, so the billing roll-up (which reads only Active state transitions) never
// sees it. This file only shapes the host-side metrics into the frozen
// SessionSample wire type; the accrual posture lives entirely on the §3 state
// transitions, not here.

import (
	"os"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/metering"
)

// MeteringSamplesFlag is the env var that arms host-side D37 sample emission
// (DS_ORCH_METERING_WIRE=1) — the SAME flag the orchestrator-side metering wiring
// reads, so a deployment arms the host→orchestrator sample path with one switch.
// OFF by default: an unset/any-other value emits no samples (the prior behavior).
const MeteringSamplesFlag = "DS_ORCH_METERING_WIRE"

// MeteringSamplesEnabled reports whether host-side sample emission is armed via the
// process environment (DS_ORCH_METERING_WIRE=1). The live host-agent wiring site
// passes this into NewSampleEmitter; tests arm the emitter explicitly.
func MeteringSamplesEnabled() bool {
	return os.Getenv(MeteringSamplesFlag) == "1"
}

// SessionMetrics is one session's raw host-observed D37 metrics at one sample
// instant — the in-package shape the host agent's self-observation produces (the
// cgroup/process read), before it is folded into the frozen wire SessionSample.
// SampledAt is unix seconds (the SessionSample timestamp domain). The values are
// host-observed cumulative counters (CPU nanos, IO bytes) and an instantaneous RSS.
type SessionMetrics struct {
	SessionUUID  string
	RSSBytes     uint64
	CPUNanos     uint64
	IOReadBytes  uint64
	IOWriteBytes uint64
	SampledAt    uint64 // unix seconds
}

// sample renders one SessionMetrics into the frozen wire SessionSample (doc 15
// §5.2). It is a pure field projection — no clock, no I/O — so the emission stays
// deterministic and unit-testable.
func (m SessionMetrics) sample() *hostagentv1.SessionSample {
	return &hostagentv1.SessionSample{
		SessionUuid:  m.SessionUUID,
		RssBytes:     m.RSSBytes,
		CpuNanos:     m.CPUNanos,
		IoReadBytes:  m.IOReadBytes,
		IoWriteBytes: m.IOWriteBytes,
		SampledAt:    m.SampledAt,
	}
}

// SampleEmitter is the flag-gated host-side D37 sample producer. When armed it
// renders a batch of SessionMetrics into the frozen SessionSamples the heartbeat
// carries; when disabled it emits nothing (the heartbeat's prior no-sample
// behavior). It is pure (no clock, no host read) — the host agent's
// self-observation supplies the metrics; this only shapes them.
type SampleEmitter struct {
	enabled bool
}

// NewSampleEmitter builds the host-side sample emitter. The enabled bool is taken
// EXPLICITLY (the live site passes MeteringSamplesEnabled(); tests pass a literal).
func NewSampleEmitter(enabled bool) *SampleEmitter {
	return &SampleEmitter{enabled: enabled}
}

// Enabled reports whether the emitter will produce samples (armed by the flag).
func (e *SampleEmitter) Enabled() bool { return e != nil && e.enabled }

// Emit renders the per-session metrics into the heartbeat's SessionSamples. It is
// a no-op (nil) when disabled — the wave default — so the heartbeat carries no
// samples and its prior behavior is unchanged. A metric with an empty session UUID
// is skipped (a sample with no session has no rollup key); a nil/empty input
// yields nil. The order of the input is preserved.
func (e *SampleEmitter) Emit(metrics []SessionMetrics) []*hostagentv1.SessionSample {
	if !e.Enabled() || len(metrics) == 0 {
		return nil
	}
	out := make([]*hostagentv1.SessionSample, 0, len(metrics))
	for _, m := range metrics {
		if m.SessionUUID == "" {
			continue
		}
		out = append(out, m.sample())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// AttachToState folds the emitted samples onto a HostState before BuildHeartbeat
// assembles the frame — the call-site the host agent's per-tick snapshot uses to
// arm the sample feed. When disabled it returns the state unchanged (no samples
// added). It REPLACES HostState.Samples with the freshly emitted batch (the host's
// current-tick samples), matching the per-cadence frame model (each frame carries
// this tick's samples, §5.2).
func (e *SampleEmitter) AttachToState(state HostState, metrics []SessionMetrics) HostState {
	if samples := e.Emit(metrics); samples != nil {
		state.Samples = samples
	}
	return state
}

// EncodedPayload returns the EXACT opaque D37 payload bytes the orchestrator's
// metering stream will record for one host-emitted sample (metering.EncodeSample —
// the deterministic RSS|CPU|IO encoding). It lets a host operator log/verify the
// host→orchestrator sample identity (the bytes that ride to the store's idempotent
// sample event) WITHOUT a live orchestrator, keeping the producer (host) and the
// consumer (orchestrator metering stream) reading one encoding (§5.6).
func EncodedPayload(s *hostagentv1.SessionSample) []byte {
	return metering.EncodeSample(s)
}

// PreviewEventID returns the deterministic metering sample EventID the orchestrator
// will key one host-emitted sample under (metering.SampleEvent's idempotency key,
// a function of session UUID + sampled-at). It is a host-side PREVIEW — the host
// never writes the metering store — so a duplicated heartbeat sample collapses to
// the same key the orchestrator already holds (the §5.6 idempotent re-ingest the
// operator can verify locally).
func PreviewEventID(s *hostagentv1.SessionSample) string {
	return metering.SampleEvent(s).EventID
}
