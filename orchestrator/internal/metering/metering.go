package metering

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// Event kinds carried on the D57 stream (the migrations/0005 `kind` column).
const (
	// KindStateTransition is a billing-relevant §3 state-entry event. Whether it
	// accrues is decided by Accrual(state), not by the kind.
	KindStateTransition = "state_transition"
	// KindSample is a D37 RSS/CPU/IO sample: a short-retention rollup datum
	// feeding the (d) rig, NOT a billing accrual. It rides the same idempotent
	// stream with the opaque sample in the payload (doc 15 §5.2/§5.6).
	KindSample = "sample"
)

// Accrual is how a §3 state contributes to billing time (D57). It is the pure,
// frozen-vocabulary classification at the center of metering: a session billed
// for the wall-clock time it spends in ACTIVE states; FREE states cost nothing.
type Accrual int

const (
	// Free states do not accrue billable time: SUSPENDED and PARKED ≈ free
	// (doc 15 §3 item 2, §5.6). Also the pre-activation states and the terminal
	// teardown states — nothing is billed before the session is live or after it
	// is gone.
	Free Accrual = iota
	// Active states accrue billable time per second (doc 15 §5.6). The 30–60 s
	// socket-hold is NOT a state here (§3 item 4) — the VM stays in WORKING, an
	// active state — so socket-hold time counts active by construction.
	Active
)

func (a Accrual) String() string {
	switch a {
	case Active:
		return "active"
	case Free:
		return "free"
	default:
		return fmt.Sprintf("Accrual(%d)", int(a))
	}
}

// ClassifyAccrual classifies a frozen §3 SessionState into its D57 billing
// posture.
//
// Active (accrues per second): READY, ATTACHED, WORKING, SNAPSHOTTING,
// MIGRATING, RESUMING — the session is live and consuming compute (the
// socket-hold's 30–60 s lives inside WORKING, §3 item 4, so it counts active
// without a state of its own).
//
// Free (no accrual): PENDING, CREATING (pre-activation — no meter before the
// session is live; "no meter at bring-compute" and nothing billable until live),
// SUSPENDED and PARKED (≈ free, §3 item 2 / §5.6), DESTROYING, DESTROYED
// (teardown — metering closes at §4.2 step 6).
//
// An unknown state (outside the frozen §3 vocabulary) is Free and reported via
// ok=false: an unrecognized state must never silently bill, and the §3 freeze
// forbids new states anyway (a new state is a contract-set change, not a code
// edit) — ok=false is the assertion seam a test uses to catch vocabulary drift.
func ClassifyAccrual(s store.SessionState) (Accrual, bool) {
	switch s {
	case store.SessionReady,
		store.SessionAttached,
		store.SessionWorking,
		store.SessionSnapshotting,
		store.SessionMigrating,
		store.SessionResuming:
		return Active, true
	case store.SessionPending,
		store.SessionCreating,
		store.SessionSuspended,
		store.SessionParked,
		store.SessionDestroying,
		store.SessionDestroyed:
		return Free, true
	default:
		return Free, false
	}
}

// Transition is a synthetic §3 state-record transition: the session entered
// State at OccurredAt. It is the pure input the billing stream derives from —
// no live host, no VM (D50). SUSPENDED carries no reason here because the
// accrual posture of SUSPENDED is reason-independent (all reasons ≈ free); the
// reason lives on the session record, not the meter.
type Transition struct {
	SessionUUID string
	State       store.SessionState
	OccurredAt  time.Time
}

// EventID is the deterministic idempotency key for a state-transition event
// (the migrations/0005 PRIMARY KEY). It is a function of (session_uuid,
// entered-state, occurred_at) ONLY, so re-deriving the same logical transition
// yields the same EventID — appending it again is a no-op at the store (D57:
// "Re-emitting the same event_id is a no-op"). The timestamp is rendered in
// UTC at nanosecond precision so two clocks that agree on the instant agree on
// the key.
func (t Transition) EventID() string {
	h := sha256.Sum256([]byte(fmt.Sprintf(
		"state_transition\x00%s\x00%s\x00%d",
		t.SessionUUID, t.State, t.OccurredAt.UTC().UnixNano(),
	)))
	return "mev_" + hex.EncodeToString(h[:16])
}

// Event derives the store.MeteringEvent for this transition. The event always
// records the entered state (the (d)-rig and billing roll-up both read it); the
// accrual posture is computed from the state via ClassifyAccrual at read time,
// not stamped here, so a re-classification never strands historical rows under
// a stale posture.
func (t Transition) Event() store.MeteringEvent {
	return store.MeteringEvent{
		EventID:     t.EventID(),
		SessionUUID: t.SessionUUID,
		Kind:        KindStateTransition,
		State:       t.State,
		OccurredAt:  t.OccurredAt,
	}
}

// Sink is the NARROW package-local persistence seam the billing stream writes
// through. Both *store.Memory and *store.Postgres satisfy it via the landed
// AppendMeteringEvent method — this package adds NO Repository method and edits
// NO shared store file (doc 15 §5.6: the metering stream consumes the
// migrations/0005 shape, it does not widen it). The store owns the at-rest
// idempotency collapse: an identical body under the same EventID is a no-op
// success, a differing body under the same key is store.ErrConflict.
type Sink interface {
	AppendMeteringEvent(ctx context.Context, e store.MeteringEvent) error
}

// Emit appends one transition's event to the sink. It is idempotent end-to-end:
// the EventID is deterministic, so Emit-ing the same logical transition twice is
// a no-op success at the store. A nil sink is a programming error and panics
// (a metering stream with no sink would silently drop billing) — callers gate
// wiring, not this function.
func Emit(ctx context.Context, sink Sink, t Transition) error {
	return sink.AppendMeteringEvent(ctx, t.Event())
}

// EmitTransitions appends a batch of transitions in order, stopping at the first
// error. Re-running an overlapping batch is safe: each event is idempotent on
// its EventID.
func EmitTransitions(ctx context.Context, sink Sink, ts []Transition) error {
	for _, t := range ts {
		if err := Emit(ctx, sink, t); err != nil {
			return fmt.Errorf("metering: emit transition %s→%s: %w", t.SessionUUID, t.State, err)
		}
	}
	return nil
}

// BillableDuration sums the ACTIVE wall-clock time over an ordered run of one
// session's transitions, closed at `until`. It is the pure D57 accrual: each
// segment [t_i, t_{i+1}) bills iff t_i's state is Active; SUSPENDED/PARKED
// segments contribute zero. Transitions for other sessions and out-of-order or
// pre-`until` entries are ignored / clamped. This is the planning-side roll-up
// (the same posture the store stream persists); it does NOT itself gate or
// bill — it is the readable derivation a test and the (d) rig assert against.
//
// `until` clamps the final open segment (the session has not yet left its last
// state). A transition at or after `until` is dropped from the window.
func BillableDuration(ts []Transition, sessionUUID string, until time.Time) time.Duration {
	var seq []Transition
	for _, t := range ts {
		if t.SessionUUID != sessionUUID {
			continue
		}
		if t.OccurredAt.After(until) {
			continue
		}
		seq = append(seq, t)
	}
	if len(seq) == 0 {
		return 0
	}
	var total time.Duration
	for i, t := range seq {
		end := until
		if i+1 < len(seq) {
			end = seq[i+1].OccurredAt
		}
		if end.Before(t.OccurredAt) {
			// Out-of-order input: clamp the segment to zero rather than bill
			// negative time.
			continue
		}
		if a, _ := ClassifyAccrual(t.State); a == Active {
			total += end.Sub(t.OccurredAt)
		}
	}
	return total
}

// SampleEventID is the deterministic idempotency key for a D37 sample event. It
// is a function of (session_uuid, sampled_at) so re-ingesting the same heartbeat
// sample is a no-op at the store. Distinct from a transition EventID by its
// domain-separation prefix, so a sample and a transition can never collide.
func SampleEventID(sessionUUID string, sampledAt time.Time) string {
	h := sha256.Sum256([]byte(fmt.Sprintf(
		"sample\x00%s\x00%d",
		sessionUUID, sampledAt.UTC().UnixNano(),
	)))
	return "msv_" + hex.EncodeToString(h[:16])
}

// SampleEvent derives the store.MeteringEvent for one D37 RSS/CPU/IO sample
// piggybacked on a hostagent.v1 heartbeat (doc 15 §5.2/§5.6). The sample is the
// (d)-rig short-retention rollup, NOT a billing accrual: the event's Kind is
// KindSample and its State is empty (a sample enters no §3 state), so the
// billing roll-up (which reads only Active states) never sees it. The opaque
// sample bytes ride the payload — the migrations/0005 `payload bytea` — exactly
// as D57 frames it ("payload carries the opaque sample").
//
// The payload is the deterministic RSS|CPU|IO encoding from EncodeSample, so a
// re-emitted sample with identical metrics produces an identical body (the
// store's identical-body-is-a-no-op idempotency holds), while a different metric
// under the same key surfaces store.ErrConflict.
func SampleEvent(s *hostagentv1.SessionSample) store.MeteringEvent {
	sampledAt := time.Unix(int64(s.GetSampledAt()), 0).UTC()
	return store.MeteringEvent{
		EventID:     SampleEventID(s.GetSessionUuid(), sampledAt),
		SessionUUID: s.GetSessionUuid(),
		Kind:        KindSample,
		State:       "", // a sample enters no §3 state; it never bills
		OccurredAt:  sampledAt,
		Payload:     EncodeSample(s),
	}
}

// EncodeSample renders the opaque short-retention payload for a D37 sample. The
// encoding is deterministic (fixed field order, no map iteration) so re-encoding
// an identical sample yields identical bytes — the precondition for the store's
// idempotent collapse. The control plane treats the payload as opaque (the
// migrations/0005 comment: "the D37 RSS/CPU/IO sample, opaque"); only the (d)
// rig that owns the rollup decodes it.
func EncodeSample(s *hostagentv1.SessionSample) []byte {
	return []byte(fmt.Sprintf(
		"d37v1 rss=%d cpu_nanos=%d io_read=%d io_write=%d at=%d",
		s.GetRssBytes(), s.GetCpuNanos(), s.GetIoReadBytes(), s.GetIoWriteBytes(), s.GetSampledAt(),
	))
}

// EmitHeartbeatSamples derives and appends the D37 sample events carried on one
// hostagent.v1 heartbeat (the heartbeat's `samples` field, §5.2). Each is
// idempotent on (session_uuid, sampled_at), so re-ingesting a duplicated
// heartbeat is a no-op. A heartbeat with no samples is a clean no-op (no error).
func EmitHeartbeatSamples(ctx context.Context, sink Sink, hb *hostagentv1.Heartbeat) error {
	for _, s := range hb.GetSamples() {
		if err := sink.AppendMeteringEvent(ctx, SampleEvent(s)); err != nil {
			return fmt.Errorf("metering: emit sample %s@%d: %w", s.GetSessionUuid(), s.GetSampledAt(), err)
		}
	}
	return nil
}
