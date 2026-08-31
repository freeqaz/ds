// SPDX-License-Identifier: Apache-2.0

package controlplane

// createtimingwire.go is the FLAG-GATED createtiming call-site wiring on the
// orchestrator control-plane create path: it records the D81 §8 create→attach
// segment decomposition for each create and folds it into the landed
// internal/createtiming Recorder, so the (b)-row "the decomposition EXISTS and its
// trends are recorded" instrument has a live producer behind a flag.
//
// WHY A NEW FILE, NOT AN EDIT (the wave-1 boundary). internal/createtiming is
// frozen wave-1 surface: this file IMPORTS it and never edits it. The createtiming
// package owns the §8 stack-segment vocabulary, the RTT-excluded ServerSpan /
// TriggerSpan invariant, the completeness assertion (MissingSegments), and the
// trend recorder. This file owns only the control-plane CALL-SITE: behind a flag,
// it opens a per-create timing, records each segment as the create coordinator
// crosses it, and (on completion) observes the decomposition into the shared
// recorder.
//
// FLAG-GATED, DEFAULT OFF (D50). The wire arms only when the deployment opts in
// (CreateTimingWireEnabled, env DS_ORCH_CREATETIMING_WIRE=1). Off — the wave
// default — every method is an inert no-op: Begin returns a nil-backed handle
// whose Record / Observe do nothing, so the create path is byte-for-byte unchanged
// and the recorder stays empty. The constructor takes the enabled bool EXPLICITLY
// so a test arms it without process env; the live site passes
// CreateTimingWireEnabled().
//
// PURE, OBSERVABILITY-ONLY (D81, D50). createtiming carries NO verdict and NO
// threshold — gating arms at M2, not here. This wire only RECORDS: it never gates
// a create, never blocks the hot path, and never reads a live host. The tests
// drive synthetic per-segment durations and assert the recorded trend + the
// default-off inertness.

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
)

// CreateTimingWireFlag is the env var that arms the create-timing call-site wiring
// (DS_ORCH_CREATETIMING_WIRE=1). OFF by default: an unset/any-other value leaves
// the wire inert, so the create path is unchanged and the recorder stays empty.
const CreateTimingWireFlag = "DS_ORCH_CREATETIMING_WIRE"

// CreateTimingWireEnabled reports whether the create-timing wiring is armed via
// the process environment (DS_ORCH_CREATETIMING_WIRE=1). The live wiring site
// passes this into NewCreateTimingWire; tests arm the wire explicitly.
func CreateTimingWireEnabled() bool {
	return os.Getenv(CreateTimingWireFlag) == "1"
}

// CreateTimingWire is the flag-gated create-timing call-site. When armed it folds
// each completed create's §8 decomposition into an internal/createtiming.Recorder
// (the shared trend instrument); when disabled it is an inert no-op. The recorder
// is concurrency-safe behind a mutex here (the create path runs many concurrent
// creates; createtiming.Recorder is not itself synchronized), so Observe from
// several create goroutines does not race.
type CreateTimingWire struct {
	enabled  bool
	mu       sync.Mutex
	recorder *createtiming.Recorder
}

// NewCreateTimingWire builds the create-timing wire. The enabled bool is taken
// EXPLICITLY (the live site passes CreateTimingWireEnabled(); tests pass a
// literal). A disabled wire still constructs (its recorder is unused) so the
// call-site never branches on nil.
func NewCreateTimingWire(enabled bool) *CreateTimingWire {
	return &CreateTimingWire{enabled: enabled, recorder: createtiming.NewRecorder()}
}

// Enabled reports whether the wire records (armed by the flag). A disabled wire's
// Begin/Record/Observe are all no-ops.
func (w *CreateTimingWire) Enabled() bool {
	return w != nil && w.enabled
}

// Begin opens a per-create timing handle for sessionUUID. When the wire is
// disabled it returns a handle whose methods are no-ops (so the create coordinator
// records segments unconditionally without branching on the flag). The handle is
// NOT safe for concurrent use by itself, but DISTINCT creates each get their own
// handle, and Observe (the fold into the shared recorder) is synchronized.
func (w *CreateTimingWire) Begin(sessionUUID string) *CreateTimingHandle {
	if !w.Enabled() {
		return &CreateTimingHandle{} // inert: nil wire + nil timing
	}
	return &CreateTimingHandle{wire: w, timing: createtiming.NewCreateTiming(sessionUUID)}
}

// ServerSpanTrend returns the recorded trigger-eligible server-span trend across
// every observed create (RTT excluded) — the (b)-row instrument's read side. On a
// disabled wire it is an empty trend (Count 0). It is observability-only; it gates
// nothing (D81: gating arms at M2).
func (w *CreateTimingWire) ServerSpanTrend() createtiming.Trend {
	if !w.Enabled() {
		return createtiming.Trend{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.recorder.ServerSpanTrend()
}

// SegmentTrend returns the recorded trend for one §8 segment across every observed
// create (Count 0 on a disabled wire or an unobserved segment).
func (w *CreateTimingWire) SegmentTrend(seg createtiming.Segment) createtiming.Trend {
	if !w.Enabled() {
		return createtiming.Trend{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.recorder.Trend(seg)
}

// observe folds one completed create's decomposition into the shared recorder
// under the mutex. It is unexported — the handle's Observe is the call-site.
func (w *CreateTimingWire) observe(c *createtiming.CreateTiming) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.recorder.Observe(c)
}

// CreateTimingHandle is one create's in-flight §8 decomposition. The create
// coordinator records each segment's measured duration as it crosses it, then
// calls Observe on completion to fold the decomposition into the shared trend
// recorder. A handle from a DISABLED wire has a nil timing: every method is a
// no-op, so the call-site is flag-free.
type CreateTimingHandle struct {
	wire   *CreateTimingWire
	timing *createtiming.CreateTiming
}

// Record sets one §8 segment's measured duration. A no-op on a disabled-wire
// handle. A negative duration is rejected by the underlying createtiming.Record (a
// clock ran backwards) — surfaced so the caller never folds a negative span.
func (h *CreateTimingHandle) Record(seg createtiming.Segment, d time.Duration) error {
	if h == nil || h.timing == nil {
		return nil
	}
	return h.timing.Record(seg, d)
}

// RecordSince records a segment's duration as the elapsed time from `start` to
// now (the create coordinator stamps `start` when it enters the segment). A no-op
// on a disabled-wire handle. now is taken from the supplied clock instant so tests
// stay deterministic; the live site passes time.Now().
func (h *CreateTimingHandle) RecordSince(seg createtiming.Segment, start, now time.Time) error {
	if h == nil || h.timing == nil {
		return nil
	}
	return h.Record(seg, now.Sub(start))
}

// MissingSegments reports which of the eight §8 stack segments this create has not
// yet recorded — the D81 existence assertion. Empty on a complete decomposition;
// the full eight-segment list on a disabled-wire handle (nothing recorded) is
// reported via the underlying createtiming, but a disabled handle has no timing so
// it returns nil (no decomposition to assert).
func (h *CreateTimingHandle) MissingSegments() []createtiming.Segment {
	if h == nil || h.timing == nil {
		return nil
	}
	return h.timing.MissingSegments()
}

// Observe folds this create's decomposition into the shared trend recorder (the
// (b)-row trend producer). A no-op on a disabled-wire handle. It does NOT require
// a complete decomposition — an incomplete create still contributes its recorded
// segments and its (partial) server span; MissingSegments is the separate
// existence assertion the suite reads. ctx is accepted for call-site symmetry with
// the metering wire; the fold itself is pure and does not block on it.
func (h *CreateTimingHandle) Observe(_ context.Context) {
	if h == nil || h.timing == nil || h.wire == nil {
		return
	}
	h.wire.observe(h.timing)
}
