// SPDX-License-Identifier: Apache-2.0

// The OQ7→D110 orchestrator→ds-tlsproxy pause/resume COORDINATION over the FROZEN
// hostagent.v1.SuspendCoord slot (doc 15 §4.3, doc 12 §12, sessions/round4/03).
// This is the orchestrator side of the D46 hold/buffer tiers: when the escalation
// clock (sessions.EscalationClock) classifies a pause as a HOLD tier, the
// orchestrator EMITS a HOLD_BEGIN SuspendCoord carrying the tier deadline the proxy
// bounds its buffering against; on resume, AFTER the guest wall clock has been
// resynced, it emits a RESUME_RESYNCED with resume_with_clock_resync=true so the
// proxy resumes forwarding only once the ≤5-min transparency invariant holds.
//
// THE SETTLED SEAM (D110, ratified 2026-06-12): the coordination is the RESERVED
// hostagent.v1.SessionLifecycleUpdate.suspend_coord slot — a host-WARD,
// boundary-owned channel ds-tlsproxy reads WITHOUT opening a control-plane stream
// (doc 15 §2.1). This file CONSUMES the seam — it builds the FROZEN
// hostagent.v1.SuspendCoord message and hands it to an injected emit sink — and does
// NOT edit ds-tlsproxy (the data-plane consumer) or the proto. The wiring of the
// real host-local channel behind the sink is a separate concern (the slot's
// "implementation before Stage 2 / TLS-1"); a synthetic recording sink wires it in
// tests (D50, no live boundary).
//
// THE PHASES (consume the FROZEN SuspendCoordPhase verbatim):
//   - HOLD_BEGIN (1) — emitted on PAUSE for the HOLD tiers (transparent ≤5-min and
//     best-effort 5–15-min). Carries tier_deadline_unix_sec (the absolute deadline
//     the proxy bounds its VM-leg socket timers against) + the dedup_key (a
//     redelivered HOLD_BEGIN with the same key is a safe no-op at the proxy). The
//     >15-min ESCALATE tier does NOT emit HOLD_BEGIN — it parks (no transparency
//     claim), so there is no hold for the proxy to honor.
//   - RESUME_RESYNCED (2) — emitted on RESUME, with resume_with_clock_resync=true,
//     ONLY AFTER the guest clock correction has completed (the caller asserts the
//     resync landed; this builder refuses to emit RESUME_RESYNCED without that
//     assertion — an unpaused VM with an uncorrected clock violates the invariant).
//
// EMIT, NEVER GATE A RELEASE (D81/D32). This emits a coordination signal; it arms no
// M2 release budget. Instant-start budgets stay instrumentation-only.
//
// ADDITIVE / NEW FILE ONLY. It consumes the frozen hostagent.v1 slot + the
// sessions.EscalationTier verdict; it edits no proto, no ds-tlsproxy, and no other
// controlplane file. The only legal cross-tree import is proto/gen/go (D80).

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// SuspendCoordEmitter is the NARROW host-ward EMIT seam: it delivers one built
// SuspendCoord (wrapped in a SessionLifecycleUpdate addressed to the session) onto
// the boundary-owned host-local channel ds-tlsproxy reads (D110; doc 15 §2.1). The
// orchestrator CONSUMES this seam — it never opens a control-plane stream to the
// proxy. A production wiring delivers onto the real channel; a synthetic recording
// sink satisfies it in tests (D50). The update carries the session UUID so the proxy
// scopes the coordination to the right session's VM-leg sockets.
type SuspendCoordEmitter interface {
	EmitSuspendCoord(ctx context.Context, update *hostagentv1.SessionLifecycleUpdate) error
}

// ErrNoClockResync is returned when an EmitResumeResynced is attempted WITHOUT the
// caller asserting the guest clock correction completed. The seam refuses to emit a
// RESUME_RESYNCED that the proxy would honor as "safe to resume forwarding" before
// the ≤5-min transparency invariant actually holds — a fail-closed guard against an
// uncorrected-clock resume.
var ErrNoClockResync = errors.New("controlplane: suspend-coord: refusing to emit RESUME_RESYNCED without an asserted guest-clock resync (the ≤5-min transparency invariant is not satisfiable, fail-closed)")

// SuspendCoordinator builds and emits the D110 SuspendCoord coordination signals over
// the frozen hostagent.v1 slot. It holds the injected emit sink; it is otherwise
// pure (the tier deadline is computed from the escalation verdict the caller passes).
// Construct via NewSuspendCoordinator.
type SuspendCoordinator struct {
	emitter SuspendCoordEmitter
}

// NewSuspendCoordinator constructs the coordinator over the given emit sink. A nil
// emitter is a construction error (the coordinator's whole job is to emit).
func NewSuspendCoordinator(emitter SuspendCoordEmitter) (*SuspendCoordinator, error) {
	if emitter == nil {
		return nil, errors.New("controlplane: NewSuspendCoordinator: emitter seam is required")
	}
	return &SuspendCoordinator{emitter: emitter}, nil
}

// BuildHoldBegin constructs the HOLD_BEGIN SuspendCoord for a pause classified in a
// HOLD tier (transparent or best-effort). It carries the tier deadline (as an absolute
// unix-second value the proxy bounds its buffering against — authoritative at the
// proxy, never recomputed) and the dedup key. It returns (nil, nil) WITHOUT error for
// the >15-min ESCALATE tier — that tier parks and makes no transparency claim, so
// there is no hold to emit (the caller drives EscalateToPark instead). A verdict with
// no tier deadline in a hold tier is a construction defect (the escalation clock
// always supplies a deadline for the hold tiers) and is surfaced.
func BuildHoldBegin(verdict sessions.EscalationVerdict, dedupKey string) (*hostagentv1.SuspendCoord, error) {
	if dedupKey == "" {
		return nil, errors.New("controlplane: suspend-coord BuildHoldBegin: empty dedup_key (a HOLD_BEGIN must be deduplicable at the proxy)")
	}
	if verdict.Tier.EscalatesToPark() {
		// The >15-min tier parks; there is no hold to coordinate.
		return nil, nil
	}
	if !verdict.HasDeadline() {
		return nil, fmt.Errorf("controlplane: suspend-coord BuildHoldBegin: hold tier %s carries no tier deadline (escalation clock defect)", verdict.Tier)
	}
	return &hostagentv1.SuspendCoord{
		Phase:               hostagentv1.SuspendCoordPhase_SUSPEND_COORD_PHASE_HOLD_BEGIN,
		TierDeadlineUnixSec: toUnixSec(verdict.TierDeadline),
		DedupKey:            dedupKey,
	}, nil
}

// BuildResumeResynced constructs the RESUME_RESYNCED SuspendCoord, with
// resume_with_clock_resync set to clockResynced. The caller MUST pass clockResynced ==
// true (it asserts the guest clock correction completed); a false assertion returns
// ErrNoClockResync (the seam refuses to emit a resume the proxy would honor before the
// invariant holds). The dedup key correlates the resume to its HOLD_BEGIN.
func BuildResumeResynced(dedupKey string, clockResynced bool) (*hostagentv1.SuspendCoord, error) {
	if dedupKey == "" {
		return nil, errors.New("controlplane: suspend-coord BuildResumeResynced: empty dedup_key (a RESUME_RESYNCED must correlate to its HOLD_BEGIN)")
	}
	if !clockResynced {
		return nil, ErrNoClockResync
	}
	return &hostagentv1.SuspendCoord{
		Phase:                 hostagentv1.SuspendCoordPhase_SUSPEND_COORD_PHASE_RESUME_RESYNCED,
		ResumeWithClockResync: true,
		DedupKey:              dedupKey,
	}, nil
}

// EmitHoldBegin builds (BuildHoldBegin) and emits a HOLD_BEGIN for the session. It is a
// no-op (returns nil) for the >15-min ESCALATE tier (BuildHoldBegin returns no message
// — the session parks). On the hold tiers it wraps the SuspendCoord in a
// SessionLifecycleUpdate addressed to sessionUUID and hands it to the emit sink.
func (c *SuspendCoordinator) EmitHoldBegin(ctx context.Context, sessionUUID string, verdict sessions.EscalationVerdict, dedupKey string) error {
	if sessionUUID == "" {
		return errors.New("controlplane: suspend-coord EmitHoldBegin: empty session_uuid")
	}
	coord, err := BuildHoldBegin(verdict, dedupKey)
	if err != nil {
		return err
	}
	if coord == nil {
		// ESCALATE tier: no hold to coordinate (the session parks).
		return nil
	}
	return c.emit(ctx, sessionUUID, coord)
}

// EmitResumeResynced builds (BuildResumeResynced) and emits a RESUME_RESYNCED for the
// session. clockResynced MUST be true (the guest clock correction completed); a false
// assertion surfaces ErrNoClockResync without emitting (the proxy never sees a resume
// it would honor before the invariant holds).
func (c *SuspendCoordinator) EmitResumeResynced(ctx context.Context, sessionUUID, dedupKey string, clockResynced bool) error {
	if sessionUUID == "" {
		return errors.New("controlplane: suspend-coord EmitResumeResynced: empty session_uuid")
	}
	coord, err := BuildResumeResynced(dedupKey, clockResynced)
	if err != nil {
		return err
	}
	return c.emit(ctx, sessionUUID, coord)
}

// emit wraps the SuspendCoord in a SessionLifecycleUpdate addressed to the session and
// hands it to the injected sink (the host-ward, boundary-owned channel). The update
// carries ONLY the suspend_coord slot — this is the session-lifecycle class, never a
// second policy/digest namespace (doc 15 §5.2).
func (c *SuspendCoordinator) emit(ctx context.Context, sessionUUID string, coord *hostagentv1.SuspendCoord) error {
	update := &hostagentv1.SessionLifecycleUpdate{
		SessionUuid:  sessionUUID,
		SuspendCoord: coord,
	}
	if err := c.emitter.EmitSuspendCoord(ctx, update); err != nil {
		return fmt.Errorf("controlplane: suspend-coord: emit phase %s for session %s failed: %w", coord.GetPhase(), sessionUUID, err)
	}
	return nil
}

// toUnixSec converts an absolute Time to the uint64 unix-second the SuspendCoord slot
// carries (tier_deadline_unix_sec). A zero/negative instant clamps to 0 (the slot's
// "unset" value).
func toUnixSec(t time.Time) uint64 {
	s := t.Unix()
	if s < 0 {
		return 0
	}
	return uint64(s)
}
