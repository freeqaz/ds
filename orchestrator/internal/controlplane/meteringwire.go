// SPDX-License-Identifier: Apache-2.0

package controlplane

// meteringwire.go is the FLAG-GATED metering call-site wiring on the orchestrator
// control-plane side: it bridges the two live D57 metering inputs the control
// plane owns into the landed internal/metering stream —
//
//   - CREATE / state-transition path: a session entering a §3 state (the
//     reconcile loop / create coordinator drives the session through its states)
//     is appended as one idempotent metering Transition.
//   - HEARTBEAT path: the D37 RSS/CPU/IO samples carried on an inbound
//     hostagent.v1 Heartbeat (the ReportHeartbeat ingest, heartbeatingest.go) are
//     appended as short-retention sample events (NOT billing accruals — §5.6).
//
// WHY A NEW FILE, NOT AN EDIT (the wave-1 boundary). internal/metering is frozen
// wave-1 surface: this file IMPORTS it and never edits it. The metering package
// owns the deterministic EventIDs, the idempotent at-rest collapse, and the
// sample-vs-transition domain separation; this file owns only the control-plane
// CALL-SITE — deciding (behind a flag) WHEN to feed the stream, and adapting the
// heartbeat / transition shapes the ingest already has in hand.
//
// FLAG-GATED, DEFAULT OFF (D50). The wire arms only when the deployment opts in
// (MeteringWireEnabled, env DS_ORCH_METERING_WIRE=1). Off — the wave default — the
// wire is INERT: every Emit is a no-op success, so the ReportHeartbeat ingest and
// the create path are byte-for-byte unchanged and never append a metering row.
// The constructor takes the enabled bool EXPLICITLY so a test arms it without
// touching process env; the live wiring site passes MeteringWireEnabled().
//
// SYNTHETIC ONLY (D50). No live host: the tests drive synthetic heartbeats and
// transitions through a fake metering.Sink, asserting the heartbeat sample
// fan-out, the idempotent re-emit collapse, and the default-off inertness.

import (
	"context"
	"os"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/metering"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// MeteringWireFlag is the env var that arms the control-plane metering call-site
// wiring (DS_ORCH_METERING_WIRE=1) — the SAME flag the sessions-side wiring reads,
// so a deployment arms the create + heartbeat metering path with one switch. OFF
// by default: an unset/any-other value leaves both call-sites inert (D50).
const MeteringWireFlag = "DS_ORCH_METERING_WIRE"

// MeteringWireEnabled reports whether the control-plane metering wiring is armed
// via the process environment (DS_ORCH_METERING_WIRE=1). The live wiring site
// passes this into NewMeteringWire; tests arm the wire explicitly, never via env.
func MeteringWireEnabled() bool {
	return os.Getenv(MeteringWireFlag) == "1"
}

// MeteringWire is the flag-gated control-plane metering call-site: it appends D57
// state-transition events (create path) and D37 sample events (heartbeat path)
// through the internal/metering stream when armed, and is an inert no-op when
// disabled (or when no sink is wired). It holds the narrow metering.Sink seam
// (satisfied by *store.Memory / *store.Postgres) — never the whole repository.
type MeteringWire struct {
	sink    metering.Sink
	enabled bool
}

// NewMeteringWire builds the control-plane metering wire over a metering.Sink. The
// enabled bool is taken EXPLICITLY (the live site passes MeteringWireEnabled();
// tests pass a literal). A nil sink with enabled=true is tolerated and stays inert
// (Enabled()==false) so a half-wired deployment never panics on the heartbeat
// ingest hot path; arming requires BOTH a sink and the flag.
func NewMeteringWire(sink metering.Sink, enabled bool) *MeteringWire {
	return &MeteringWire{sink: sink, enabled: enabled}
}

// Enabled reports whether the wire will actually append: armed by the flag AND
// holding a sink. A flag-on-but-sink-nil wire is reported disabled so the caller's
// arming check and the append path agree.
func (w *MeteringWire) Enabled() bool {
	return w != nil && w.enabled && w.sink != nil
}

// EmitStateTransition appends one §3 state-entry metering event (the create /
// reconcile transition path). Idempotent on the deterministic metering EventID
// (re-driving the same logical transition is a no-op success at the store) and a
// no-op success when disabled. An empty session UUID is treated as a disabled
// no-op (never an unkeyed row).
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

// EmitHeartbeatSamples appends the D37 RSS/CPU/IO sample events carried on one
// inbound hostagent.v1 Heartbeat (the ReportHeartbeat ingest's per-frame
// Heartbeat). Each sample is idempotent on (session_uuid, sampled_at), so
// re-ingesting a duplicated heartbeat is a no-op; a heartbeat with no samples is a
// clean no-op. Disabled (the default) — a no-op success, so the ingest is
// unchanged. A nil heartbeat is a defensive no-op (the ingest already drops nil
// frames before Observe; this mirrors that defense at the metering call-site).
//
// Samples are short-retention rollup data (KindSample, empty State), NOT billing
// accruals — the billing roll-up reads only Active state transitions and never
// sees these (§5.6). So this never moves the meter; it feeds the (d) rig.
func (w *MeteringWire) EmitHeartbeatSamples(ctx context.Context, hb *hostagentv1.Heartbeat) error {
	if !w.Enabled() || hb == nil {
		return nil
	}
	return metering.EmitHeartbeatSamples(ctx, w.sink, hb)
}
