// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// recordingEmitter is the synthetic host-ward sink (D50): it records the
// SessionLifecycleUpdates the coordinator hands it, standing in for the
// boundary-owned host-local channel ds-tlsproxy reads.
type recordingEmitter struct {
	updates []*hostagentv1.SessionLifecycleUpdate
	err     error
}

func (e *recordingEmitter) EmitSuspendCoord(_ context.Context, u *hostagentv1.SessionLifecycleUpdate) error {
	e.updates = append(e.updates, u)
	return e.err
}

func verdictFor(t *testing.T, elapsed time.Duration) sessions.EscalationVerdict {
	t.Helper()
	suspendedAt := time.Unix(1_700_000_000, 0)
	clk, err := sessions.NewEscalationClock(sessions.NewEscalationConfig(), func() time.Time { return suspendedAt.Add(elapsed) })
	if err != nil {
		t.Fatalf("NewEscalationClock: %v", err)
	}
	return clk.Classify(suspendedAt)
}

func TestNewSuspendCoordinatorRequiresEmitter(t *testing.T) {
	if _, err := NewSuspendCoordinator(nil); err == nil {
		t.Fatal("expected construction error for nil emitter")
	}
}

// TestEmitHoldBeginTransparentTier: a transparent-tier pause emits HOLD_BEGIN with the
// tier deadline + dedup key carried on the suspend_coord slot of a SessionLifecycleUpdate.
func TestEmitHoldBeginTransparentTier(t *testing.T) {
	em := &recordingEmitter{}
	c, err := NewSuspendCoordinator(em)
	if err != nil {
		t.Fatalf("NewSuspendCoordinator: %v", err)
	}
	v := verdictFor(t, 2*time.Minute) // transparent
	if err := c.EmitHoldBegin(context.Background(), "s1", v, "dedup-1"); err != nil {
		t.Fatalf("EmitHoldBegin: %v", err)
	}
	if len(em.updates) != 1 {
		t.Fatalf("emitted %d updates, want 1", len(em.updates))
	}
	u := em.updates[0]
	if u.GetSessionUuid() != "s1" {
		t.Fatalf("update session=%q, want s1", u.GetSessionUuid())
	}
	coord := u.GetSuspendCoord()
	if coord == nil {
		t.Fatal("update must carry a suspend_coord slot")
	}
	if coord.GetPhase() != hostagentv1.SuspendCoordPhase_SUSPEND_COORD_PHASE_HOLD_BEGIN {
		t.Fatalf("phase=%v, want HOLD_BEGIN", coord.GetPhase())
	}
	if coord.GetDedupKey() != "dedup-1" {
		t.Fatalf("dedup_key=%q", coord.GetDedupKey())
	}
	wantDeadline := uint64(v.TierDeadline.Unix())
	if coord.GetTierDeadlineUnixSec() != wantDeadline {
		t.Fatalf("tier_deadline_unix_sec=%d, want %d", coord.GetTierDeadlineUnixSec(), wantDeadline)
	}
	if coord.GetResumeWithClockResync() {
		t.Fatal("HOLD_BEGIN must not set resume_with_clock_resync")
	}
}

// TestEmitHoldBeginBestEffortTier: a best-effort pause emits HOLD_BEGIN with the
// best-effort deadline.
func TestEmitHoldBeginBestEffortTier(t *testing.T) {
	em := &recordingEmitter{}
	c, _ := NewSuspendCoordinator(em)
	v := verdictFor(t, 10*time.Minute) // best-effort
	if err := c.EmitHoldBegin(context.Background(), "s1", v, "dedup-1"); err != nil {
		t.Fatalf("EmitHoldBegin: %v", err)
	}
	coord := em.updates[0].GetSuspendCoord()
	if coord.GetPhase() != hostagentv1.SuspendCoordPhase_SUSPEND_COORD_PHASE_HOLD_BEGIN {
		t.Fatalf("phase=%v, want HOLD_BEGIN", coord.GetPhase())
	}
	if coord.GetTierDeadlineUnixSec() != uint64(v.TierDeadline.Unix()) {
		t.Fatal("best-effort tier deadline not carried")
	}
}

// TestEmitHoldBeginEscalateTierNoEmit: the >15-min escalate tier emits NOTHING — it
// parks (no transparency claim), so there is no hold for the proxy to honor.
func TestEmitHoldBeginEscalateTierNoEmit(t *testing.T) {
	em := &recordingEmitter{}
	c, _ := NewSuspendCoordinator(em)
	v := verdictFor(t, 20*time.Minute) // escalate
	if err := c.EmitHoldBegin(context.Background(), "s1", v, "dedup-1"); err != nil {
		t.Fatalf("EmitHoldBegin (escalate): %v", err)
	}
	if len(em.updates) != 0 {
		t.Fatalf("escalate tier must emit no HOLD_BEGIN, got %d updates", len(em.updates))
	}
}

// TestEmitResumeResynced: a resume emits RESUME_RESYNCED with resume_with_clock_resync
// = true ONLY after the guest clock has been resynced.
func TestEmitResumeResynced(t *testing.T) {
	em := &recordingEmitter{}
	c, _ := NewSuspendCoordinator(em)
	if err := c.EmitResumeResynced(context.Background(), "s1", "dedup-1", true); err != nil {
		t.Fatalf("EmitResumeResynced: %v", err)
	}
	coord := em.updates[0].GetSuspendCoord()
	if coord.GetPhase() != hostagentv1.SuspendCoordPhase_SUSPEND_COORD_PHASE_RESUME_RESYNCED {
		t.Fatalf("phase=%v, want RESUME_RESYNCED", coord.GetPhase())
	}
	if !coord.GetResumeWithClockResync() {
		t.Fatal("RESUME_RESYNCED must set resume_with_clock_resync=true")
	}
	if coord.GetDedupKey() != "dedup-1" {
		t.Fatalf("dedup_key=%q, want correlation to HOLD_BEGIN", coord.GetDedupKey())
	}
}

// TestEmitResumeResyncedRefusesWithoutResync: a RESUME_RESYNCED without an asserted
// clock resync is fail-closed (ErrNoClockResync) — the proxy never sees a resume it
// would honor before the ≤5-min transparency invariant holds.
func TestEmitResumeResyncedRefusesWithoutResync(t *testing.T) {
	em := &recordingEmitter{}
	c, _ := NewSuspendCoordinator(em)
	err := c.EmitResumeResynced(context.Background(), "s1", "dedup-1", false)
	if !errors.Is(err, ErrNoClockResync) {
		t.Fatalf("expected ErrNoClockResync, got %v", err)
	}
	if len(em.updates) != 0 {
		t.Fatal("a refused RESUME_RESYNCED must emit nothing")
	}
}

// TestBuildHoldBeginRejectsEmptyDedup + TestBuildResumeResyncedRejectsEmptyDedup: the
// dedup key is mandatory for both phases (the proxy deduplicates / correlates on it).
func TestBuildHoldBeginRejectsEmptyDedup(t *testing.T) {
	if _, err := BuildHoldBegin(verdictFor(t, 2*time.Minute), ""); err == nil {
		t.Fatal("expected error for empty dedup_key on HOLD_BEGIN")
	}
}

func TestBuildResumeResyncedRejectsEmptyDedup(t *testing.T) {
	if _, err := BuildResumeResynced("", true); err == nil {
		t.Fatal("expected error for empty dedup_key on RESUME_RESYNCED")
	}
}

// TestEmitPropagatesSinkError: a sink fault surfaces to the caller (the coordination
// signal did not land).
func TestEmitPropagatesSinkError(t *testing.T) {
	em := &recordingEmitter{err: errors.New("channel down")}
	c, _ := NewSuspendCoordinator(em)
	if err := c.EmitHoldBegin(context.Background(), "s1", verdictFor(t, 2*time.Minute), "dedup-1"); err == nil {
		t.Fatal("expected sink error to surface")
	}
}

// TestEmitRejectsEmptySession: an empty session UUID is rejected (the proxy must scope
// the coordination to a session's VM-leg sockets).
func TestEmitRejectsEmptySession(t *testing.T) {
	em := &recordingEmitter{}
	c, _ := NewSuspendCoordinator(em)
	if err := c.EmitHoldBegin(context.Background(), "", verdictFor(t, 2*time.Minute), "dedup-1"); err == nil {
		t.Fatal("expected error for empty session_uuid on HOLD_BEGIN")
	}
	if err := c.EmitResumeResynced(context.Background(), "", "dedup-1", true); err == nil {
		t.Fatal("expected error for empty session_uuid on RESUME_RESYNCED")
	}
}
