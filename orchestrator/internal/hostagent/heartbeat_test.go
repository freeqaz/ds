package hostagent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

func health(name string, state hostagentv1.HealthState, seq uint64) *hostagentv1.ServiceHealth {
	return &hostagentv1.ServiceHealth{Name: name, State: state, AppliedSeq: seq}
}

// TestAppliedSeq_MinOverThree pins the FROZEN D72 semantics: the top-level
// applied_seq is the MIN over the three NAMED host-side consumers, a non-HEALTHY
// consumer is clamped to 0 (fail-closed) so it drags the min down rather than
// inflating it, and a MISSING named consumer is clamped to 0 EXACTLY like a
// non-HEALTHY one (the missing-consumer clamp — a 2-of-3 list must return 0,
// never the min over the present subset).
func TestAppliedSeq_MinOverThree(t *testing.T) {
	cases := []struct {
		name     string
		boundary []*hostagentv1.ServiceHealth
		want     uint64
	}{
		{
			name:     "no consumers means nothing applied",
			boundary: nil,
			want:     0,
		},
		{
			name: "min over three healthy consumers",
			boundary: []*hostagentv1.ServiceHealth{
				health(BoundaryDNSGate, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 42),
				health(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 40),
				health(BoundaryNFTWriter, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 41),
			},
			want: 40,
		},
		{
			name: "all equal",
			boundary: []*hostagentv1.ServiceHealth{
				health(BoundaryDNSGate, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 7),
				health(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 7),
				health(BoundaryNFTWriter, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 7),
			},
			want: 7,
		},
		{
			name: "a DEGRADED consumer is clamped to 0 (fail-closed), dragging the min down",
			boundary: []*hostagentv1.ServiceHealth{
				health(BoundaryDNSGate, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 100),
				health(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_DEGRADED, 99),
				health(BoundaryNFTWriter, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 100),
			},
			want: 0,
		},
		{
			name: "a DOWN consumer with a high stale seq cannot inflate the min",
			boundary: []*hostagentv1.ServiceHealth{
				health(BoundaryDNSGate, hostagentv1.HealthState_HEALTH_STATE_DOWN, 9999),
				health(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 50),
				health(BoundaryNFTWriter, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 50),
			},
			want: 0,
		},
		{
			name: "an UNSPECIFIED consumer is not HEALTHY, so it is clamped to 0",
			boundary: []*hostagentv1.ServiceHealth{
				health(BoundaryDNSGate, hostagentv1.HealthState_HEALTH_STATE_UNSPECIFIED, 5),
				health(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 5),
				health(BoundaryNFTWriter, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 5),
			},
			want: 0,
		},
		{
			// (a) Only two of the three named consumers are present, both HEALTHY
			// with high seqs. The absent third (BoundaryNFTWriter) has proven
			// NOTHING, so its missing-consumer clamp is 0 and drags the min to 0 —
			// NOT the min over the present 2-of-3 subset (which would be 200).
			name: "two-of-three present HEALTHY: the missing third clamps the min to 0",
			boundary: []*hostagentv1.ServiceHealth{
				health(BoundaryDNSGate, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 200),
				health(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 250),
			},
			want: 0,
		},
		{
			// (b) All three named consumers present and HEALTHY, plus an
			// unrecognized-name extra entry (with a LOW seq that would lower a
			// naive min). The unknown name is ignored for the min, so the result
			// is unchanged: the min over the three named consumers (= 30).
			name: "all three HEALTHY plus an unknown-name entry: unknown ignored, min over the three",
			boundary: []*hostagentv1.ServiceHealth{
				health(BoundaryDNSGate, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 30),
				health(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 31),
				health(BoundaryNFTWriter, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 32),
				health("some-other-consumer", hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 1),
			},
			want: 30,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AppliedSeq(tc.boundary); got != tc.want {
				t.Fatalf("AppliedSeq() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestBuildHeartbeat_DerivesAppliedSeqFromBoundary checks that BuildHeartbeat
// never lets the top-level applied_seq drift from the per-consumer list: it is
// always recomputed from Boundary, regardless of any caller intent.
func TestBuildHeartbeat_DerivesAppliedSeqFromBoundary(t *testing.T) {
	state := HostState{
		HostID: "host-A",
		Boundary: []*hostagentv1.ServiceHealth{
			health(BoundaryDNSGate, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 12),
			health(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 11),
			health(BoundaryNFTWriter, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, 13),
		},
		HostBaselineVersion: "baseline-2026.06",
		ImageCacheDigest:    "sha256:cafe",
	}
	hb := BuildHeartbeat(state)
	if hb.GetHostId() != "host-A" {
		t.Fatalf("HostId = %q, want host-A", hb.GetHostId())
	}
	if hb.GetAppliedSeq() != 11 {
		t.Fatalf("AppliedSeq = %d, want 11 (min over three)", hb.GetAppliedSeq())
	}
	if hb.GetHostBaselineVersion() != "baseline-2026.06" {
		t.Fatalf("HostBaselineVersion = %q", hb.GetHostBaselineVersion())
	}
	if hb.GetImageCacheDigest() != "sha256:cafe" {
		t.Fatalf("ImageCacheDigest = %q", hb.GetImageCacheDigest())
	}
	if len(hb.GetBoundary()) != 3 {
		t.Fatalf("Boundary len = %d, want 3", len(hb.GetBoundary()))
	}
}

func TestBuildHeartbeat_CarriesObservedAndSamples(t *testing.T) {
	state := HostState{
		HostID: "host-B",
		Observed: []*hypervisorv1.ObservedSession{
			{SessionUuid: "s1", HostSessionIndex: 3, TapName: "dstap-3"},
		},
		Samples: []*hostagentv1.SessionSample{
			{SessionUuid: "s1", RssBytes: 1 << 20, CpuNanos: 500},
		},
		Capacity: &hostagentv1.HostCapacity{AllocatableVcpu: 8, RunningSessions: 1},
	}
	hb := BuildHeartbeat(state)
	if len(hb.GetObserved()) != 1 || hb.GetObserved()[0].GetSessionUuid() != "s1" {
		t.Fatalf("Observed not carried through: %+v", hb.GetObserved())
	}
	if len(hb.GetSamples()) != 1 || hb.GetSamples()[0].GetRssBytes() != 1<<20 {
		t.Fatalf("Samples not carried through: %+v", hb.GetSamples())
	}
	if hb.GetCapacity().GetAllocatableVcpu() != 8 {
		t.Fatalf("Capacity not carried through: %+v", hb.GetCapacity())
	}
}

// --- streaming-loop fakes ---

// fakeSender is an in-memory HeartbeatSender: it records every frame and the
// close, with no grpc dial.
//
// To catch the close-after-cancel bug the real grpc client exhibits (cancelling
// the ctx the stream was OPENED on kills the RPC, so CloseAndRecv fails
// Canceled), CloseAndRecv FAILS if openCtx is already Done — modelling the real
// client. A correct Stream opens the RPC on a context detached from its drain
// signal, so on graceful drain openCtx is still alive when CloseAndRecv runs.
type fakeSender struct {
	mu       sync.Mutex
	frames   []*hostagentv1.ReportHeartbeatRequest
	closed   bool
	sendErr  error
	closeErr error
	// openCtx is the context the stream was opened on (recorded by fakeDialer).
	// CloseAndRecv treats a Done openCtx as a dead RPC, mirroring the generated
	// grpc client.
	openCtx context.Context
}

func (f *fakeSender) Send(req *hostagentv1.ReportHeartbeatRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.frames = append(f.frames, req)
	return nil
}

func (f *fakeSender) CloseAndRecv() (*hostagentv1.ReportHeartbeatResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	// Mirror the generated grpc client: if the ctx the stream was opened on is
	// already cancelled, the RPC is gone and CloseAndRecv cannot read the response.
	// This is what catches a Stream that opens the RPC on its own drain signal.
	if f.openCtx != nil {
		if err := f.openCtx.Err(); err != nil {
			return nil, err
		}
	}
	if f.closeErr != nil {
		return nil, f.closeErr
	}
	return &hostagentv1.ReportHeartbeatResponse{BeatsReceived: uint64(len(f.frames))}, nil
}

func (f *fakeSender) frameCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frames)
}

func (f *fakeSender) setOpenCtx(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openCtx = ctx
}

type fakeDialer struct {
	sender *fakeSender
	err    error
}

func (d *fakeDialer) OpenHeartbeat(ctx context.Context) (HeartbeatSender, error) {
	if d.err != nil {
		return nil, d.err
	}
	// Record the ctx the stream was opened on, so CloseAndRecv can reject a close
	// attempted after that ctx was cancelled (the real grpc close-after-cancel
	// bug).
	d.sender.setOpenCtx(ctx)
	return d.sender, nil
}

// fakeSource returns a fixed snapshot; failEach makes EVERY snapshot fail.
type fakeSource struct {
	mu       sync.Mutex
	state    HostState
	calls    int
	failEach bool
}

func (s *fakeSource) Snapshot(context.Context) (HostState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failEach {
		return HostState{}, errors.New("cannot observe host this tick")
	}
	return s.state, nil
}

// TestStream_EmitsImmediatelyAndClosesOnContext verifies the loop emits a frame
// the moment the stream opens (no full-cadence silence) and, on ctx cancel,
// gracefully closes and returns the close-path response.
func TestStream_EmitsImmediatelyAndClosesOnContext(t *testing.T) {
	sender := &fakeSender{}
	dialer := &fakeDialer{sender: sender}
	src := &fakeSource{state: HostState{HostID: "host-C"}}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel right away: the immediate emit still fires before the loop observes
	// the cancel, so we get exactly one frame and a clean close.
	cancel()

	resp, err := Stream(ctx, dialer, src, StreamConfig{Cadence: time.Hour})
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
	if sender.frameCount() != 1 {
		t.Fatalf("frame count = %d, want 1 (the immediate emit)", sender.frameCount())
	}
	if !sender.closed {
		t.Fatal("stream was not closed on ctx cancel")
	}
	if resp.GetBeatsReceived() != 1 {
		t.Fatalf("BeatsReceived = %d, want 1", resp.GetBeatsReceived())
	}
}

// TestStream_TicksEmitMultipleFrames drives several cadence ticks and checks
// each produces a frame.
func TestStream_TicksEmitMultipleFrames(t *testing.T) {
	sender := &fakeSender{}
	dialer := &fakeDialer{sender: sender}
	src := &fakeSource{state: HostState{HostID: "host-D"}}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Let a handful of ticks fire, then drain.
		time.Sleep(55 * time.Millisecond)
		cancel()
	}()

	resp, err := Stream(ctx, dialer, src, StreamConfig{Cadence: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
	// 1 immediate + ~5 ticks; timing is loose, so assert "more than just the
	// immediate emit" rather than an exact count.
	if got := sender.frameCount(); got < 2 {
		t.Fatalf("frame count = %d, want >= 2 (immediate + ticks)", got)
	}
	if resp.GetBeatsReceived() != uint64(sender.frameCount()) {
		t.Fatalf("BeatsReceived = %d, want %d", resp.GetBeatsReceived(), sender.frameCount())
	}
}

// TestStream_SnapshotErrorSkipsTick verifies a self-observation failure is a
// MISSED BEAT (skipped tick), not a torn stream or a fabricated empty frame.
func TestStream_SnapshotErrorSkipsTick(t *testing.T) {
	sender := &fakeSender{}
	dialer := &fakeDialer{sender: sender}
	src := &fakeSource{failEach: true}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(35 * time.Millisecond)
		cancel()
	}()

	resp, err := Stream(ctx, dialer, src, StreamConfig{Cadence: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("Stream returned error (a missed beat must not tear the stream): %v", err)
	}
	if sender.frameCount() != 0 {
		t.Fatalf("frame count = %d, want 0 (every snapshot failed, so no fabricated frames)", sender.frameCount())
	}
	if resp.GetBeatsReceived() != 0 {
		t.Fatalf("BeatsReceived = %d, want 0", resp.GetBeatsReceived())
	}
	if src.calls < 1 {
		t.Fatal("Snapshot was never attempted")
	}
}

func TestStream_OpenErrorIsReturned(t *testing.T) {
	dialer := &fakeDialer{err: errors.New("dial refused")}
	src := &fakeSource{}
	_, err := Stream(context.Background(), dialer, src, StreamConfig{})
	if err == nil {
		t.Fatal("Stream did not return the open error")
	}
}

// TestStream_SendErrorEndsLoop verifies a broken send tears the loop down (the
// stream is broken; the caller re-dials).
func TestStream_SendErrorEndsLoop(t *testing.T) {
	sender := &fakeSender{sendErr: errors.New("stream broken")}
	dialer := &fakeDialer{sender: sender}
	src := &fakeSource{state: HostState{HostID: "host-E"}}
	_, err := Stream(context.Background(), dialer, src, StreamConfig{Cadence: time.Hour})
	if err == nil {
		t.Fatal("Stream did not surface the send error")
	}
}

func TestStream_ZeroCadenceUsesDefault(t *testing.T) {
	// A zero cadence must not divide-by-zero or busy-spin; it falls back to
	// DefaultCadence. We cancel immediately so only the immediate emit runs.
	sender := &fakeSender{}
	dialer := &fakeDialer{sender: sender}
	src := &fakeSource{state: HostState{HostID: "host-F"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Stream(ctx, dialer, src, StreamConfig{Cadence: 0}); err != nil {
		t.Fatalf("Stream with zero cadence errored: %v", err)
	}
	if sender.frameCount() != 1 {
		t.Fatalf("frame count = %d, want 1", sender.frameCount())
	}
}
