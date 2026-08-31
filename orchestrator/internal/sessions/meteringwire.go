// SPDX-License-Identifier: Apache-2.0

package sessions

// meteringwire.go is the FLAG-GATED metering call-site wiring on the create /
// state-transition side of the sessions package. It is the bridge that turns a
// §3 SessionState ENTRY (the create spine driving a session through PENDING →
// CREATING → READY → WORKING, and the suspend/park/teardown edges) into one D57
// idempotent metering Transition, appended through the landed internal/metering
// stream (metering.Emit → metering.Sink.AppendMeteringEvent).
//
// WHY A NEW FILE, NOT AN EDIT (the wave-1 boundary). The internal/metering
// package is frozen wave-1 surface: this file IMPORTS it and never edits it — the
// metering stream owns the deterministic EventID, the idempotent at-rest collapse
// (re-emitting the same logical transition is a no-op success), and the
// Active/Free accrual classification. This file owns only the CALL-SITE: deciding
// (behind a flag) WHEN to hand a transition to the stream, and shaping a session's
// state entry into a metering.Transition.
//
// FLAG-GATED, DEFAULT OFF (D50). Wiring arms only when the deployment opts in
// (MeteringWireEnabled, env DS_ORCH_METERING_WIRE=1). Off — the wave's default —
// the wire is INERT: EmitStateTransition is a no-op success, so a non-live run is
// byte-for-byte unchanged and never appends a metering row. The constructor takes
// the enabled bool EXPLICITLY (NewMeteringWire) so a test arms the wire without
// touching process env, and the live wiring site passes MeteringWireEnabled().
//
// SYNTHETIC ONLY (D50). No live host, no VM: a transition is pure data (session
// UUID + entered state + occurred-at). The tests drive synthetic transitions
// through a fake metering.Sink that records what it was handed, asserting the
// idempotent re-emit collapse and the default-off inertness.

import (
	"context"
	"os"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/metering"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// MeteringWireFlag is the env var that arms the create-side metering call-site
// wiring (DS_ORCH_METERING_WIRE=1). It is OFF by default: an unset/any-other value
// leaves the wire inert, so the wave's default build never appends a metering row
// and a non-live run is unchanged (D50).
const MeteringWireFlag = "DS_ORCH_METERING_WIRE"

// MeteringWireEnabled reports whether the create-side metering wiring is armed via
// the process environment (DS_ORCH_METERING_WIRE=1). The live wiring site passes
// this into NewMeteringWire; tests arm the wire explicitly and never read env.
func MeteringWireEnabled() bool {
	return os.Getenv(MeteringWireFlag) == "1"
}

// MeteringWire is the flag-gated create-side metering call-site: it appends a D57
// state-transition event through the internal/metering stream when armed, and is
// an inert no-op when disabled (or when no sink is wired). It holds the narrow
// metering.Sink seam (satisfied by *store.Memory / *store.Postgres via the landed
// AppendMeteringEvent method) — never the whole repository.
type MeteringWire struct {
	sink    metering.Sink
	enabled bool
}

// NewMeteringWire builds the create-side metering wire over a metering.Sink. The
// enabled bool is taken EXPLICITLY (the live site passes MeteringWireEnabled();
// tests pass a literal) so arming is decoupled from process env. A nil sink with
// enabled=true is tolerated and stays inert — the wire reports Enabled()==false so
// a half-wired deployment never panics on the create hot path; arming requires
// BOTH a sink and the flag.
func NewMeteringWire(sink metering.Sink, enabled bool) *MeteringWire {
	return &MeteringWire{sink: sink, enabled: enabled}
}

// Enabled reports whether the wire will actually append: armed by the flag AND
// holding a sink. A flag-on-but-sink-nil wire is reported disabled so the caller's
// arming check and the append path agree.
func (w *MeteringWire) Enabled() bool {
	return w != nil && w.enabled && w.sink != nil
}

// EmitStateTransition appends one §3 state-entry metering event for a session that
// entered `state` at `occurredAt`. It is idempotent end-to-end (the metering
// EventID is deterministic on session UUID + entered state + occurred-at, so
// re-driving the same logical transition is a no-op success at the store), and a
// no-op success when the wire is disabled (the default) — a non-live run never
// appends. An empty session UUID is a programming error the caller should not
// reach; it is treated as a disabled no-op rather than appending an unkeyed row.
func (w *MeteringWire) EmitStateTransition(ctx context.Context, sessionUUID string, state store.SessionState, occurredAt time.Time) error {
	if !w.Enabled() || sessionUUID == "" {
		return nil
	}
	return metering.Emit(ctx, w.sink, metering.Transition{
		SessionUUID: sessionUUID,
		State:       state,
		OccurredAt:  occurredAt,
	})
}

// EmitSessionEntry is the record-shaped convenience over EmitStateTransition: it
// reads the entered state from a persisted session record (the spine has the
// record in hand after a create/update), stamping the supplied entry instant. It
// is the same idempotent, default-off no-op as EmitStateTransition.
func (w *MeteringWire) EmitSessionEntry(ctx context.Context, rec store.Session, occurredAt time.Time) error {
	return w.EmitStateTransition(ctx, rec.Ref.SessionUUID, rec.State, occurredAt)
}
