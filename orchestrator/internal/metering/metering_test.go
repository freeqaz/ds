package metering_test

import (
	"context"
	"errors"
	"testing"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/metering"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestAccrualClassification pins the D57 per-state billing posture over the
// frozen §3 vocabulary (doc 15 §3/§5.6): active states accrue, SUSPENDED/PARKED
// ≈ free, pre-activation and teardown states free. The socket-hold is NOT a
// state (§3 item 4) so it needs no row — WORKING being active is what makes
// socket-hold time count active.
func TestAccrualClassification(t *testing.T) {
	cases := []struct {
		state store.SessionState
		want  metering.Accrual
	}{
		{store.SessionPending, metering.Free},    // pre-activation: no meter at bring-compute
		{store.SessionCreating, metering.Free},   // pre-activation
		{store.SessionReady, metering.Active},    // live
		{store.SessionAttached, metering.Active}, // live
		{store.SessionWorking, metering.Active},  // live; socket-hold lives here (§3 item 4)
		{store.SessionSnapshotting, metering.Active},
		{store.SessionMigrating, metering.Active},
		{store.SessionParked, metering.Free},     // ≈ free (§3 item 2)
		{store.SessionSuspended, metering.Free},  // ≈ free (§5.6)
		{store.SessionResuming, metering.Active}, // live
		{store.SessionDestroying, metering.Free}, // teardown
		{store.SessionDestroyed, metering.Free},  // terminal; metering closes
	}
	for _, c := range cases {
		got, ok := metering.ClassifyAccrual(c.state)
		if !ok {
			t.Errorf("ClassifyAccrual(%q): ok=false, want a known §3 state", c.state)
		}
		if got != c.want {
			t.Errorf("ClassifyAccrual(%q) = %v, want %v", c.state, got, c.want)
		}
	}
}

// TestAccrualCoversEveryFrozenState is the §3-vocabulary drift guard: every
// state store.SessionStates() reports must classify (ok=true). A new §3 state
// landed without a metering posture would surface here, forcing the
// classification decision rather than silently billing free.
func TestAccrualCoversEveryFrozenState(t *testing.T) {
	for _, s := range store.SessionStates() {
		if _, ok := metering.ClassifyAccrual(s); !ok {
			t.Errorf("frozen §3 state %q has no metering accrual posture (ok=false)", s)
		}
	}
}

// TestAccrualUnknownStateIsFreeNotOK proves an out-of-vocabulary state never
// silently bills: it classifies Free with ok=false (the assertion seam).
func TestAccrualUnknownStateIsFreeNotOK(t *testing.T) {
	got, ok := metering.ClassifyAccrual(store.SessionState("BOGUS"))
	if ok {
		t.Fatalf("unknown state reported ok=true")
	}
	if got != metering.Free {
		t.Fatalf("unknown state accrual = %v, want Free (never silently bill)", got)
	}
}

// TestEventIDDeterministic proves the idempotency key is a pure function of
// (session, state, instant): the same logical transition always yields the same
// EventID, while a differing dimension yields a different one.
func TestEventIDDeterministic(t *testing.T) {
	at := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	base := metering.Transition{SessionUUID: "sess-a", State: store.SessionWorking, OccurredAt: at}

	if base.EventID() != base.EventID() {
		t.Fatal("EventID not deterministic for identical input")
	}
	// A timezone-shifted but instant-identical clock agrees on the key.
	shifted := base
	shifted.OccurredAt = at.In(time.FixedZone("x", 3600))
	if base.EventID() != shifted.EventID() {
		t.Fatalf("EventID differs across equal instants: %s vs %s", base.EventID(), shifted.EventID())
	}
	// Differing dimensions diverge.
	for _, mut := range []metering.Transition{
		{SessionUUID: "sess-b", State: store.SessionWorking, OccurredAt: at},
		{SessionUUID: "sess-a", State: store.SessionReady, OccurredAt: at},
		{SessionUUID: "sess-a", State: store.SessionWorking, OccurredAt: at.Add(time.Second)},
	} {
		if mut.EventID() == base.EventID() {
			t.Errorf("EventID collision: %+v shares a key with the base transition", mut)
		}
	}
}

// TestEmitIdempotent proves the end-to-end D57 idempotency against the REAL
// store: re-emitting the same logical transition is a no-op success (one row),
// per the landed AppendMeteringEvent contract.
func TestEmitIdempotent(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	at := time.Date(2026, 6, 14, 9, 0, 0, 0, time.UTC)
	tr := metering.Transition{SessionUUID: "sess-1", State: store.SessionWorking, OccurredAt: at}

	for i := 0; i < 3; i++ {
		if err := metering.Emit(ctx, mem, tr); err != nil {
			t.Fatalf("Emit #%d: %v", i, err)
		}
	}
	got, err := mem.ListMeteringEvents(ctx, "sess-1")
	if err != nil {
		t.Fatalf("ListMeteringEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("re-emit produced %d rows, want 1 (idempotent on EventID)", len(got))
	}
	if got[0].Kind != metering.KindStateTransition || got[0].State != store.SessionWorking {
		t.Fatalf("event body unexpected: %+v", got[0])
	}
}

// TestEmitConflictOnDifferingBody proves the idempotency key is a real
// collision guard: a forged event reusing a transition's EventID with a
// different body is store.ErrConflict, not a silent overwrite.
func TestEmitConflictOnDifferingBody(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	at := time.Date(2026, 6, 14, 9, 0, 0, 0, time.UTC)
	tr := metering.Transition{SessionUUID: "sess-2", State: store.SessionReady, OccurredAt: at}
	if err := metering.Emit(ctx, mem, tr); err != nil {
		t.Fatalf("seed Emit: %v", err)
	}
	forged := tr.Event()
	forged.State = store.SessionParked // same key, different body
	if err := mem.AppendMeteringEvent(ctx, forged); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("differing body under same EventID: got %v, want ErrConflict", err)
	}
}

// TestBillableDuration proves the accrual roll-up: only ACTIVE segments bill;
// SUSPENDED/PARKED segments are free; the open final segment is clamped to
// `until`.
func TestBillableDuration(t *testing.T) {
	t0 := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	min := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Minute) }
	ts := []metering.Transition{
		{SessionUUID: "s", State: store.SessionCreating, OccurredAt: min(0)},   // free 0–10
		{SessionUUID: "s", State: store.SessionWorking, OccurredAt: min(10)},   // active 10–25 (15m)
		{SessionUUID: "s", State: store.SessionSuspended, OccurredAt: min(25)}, // free 25–40
		{SessionUUID: "s", State: store.SessionResuming, OccurredAt: min(40)},  // active 40–45 (5m)
		{SessionUUID: "s", State: store.SessionWorking, OccurredAt: min(45)},   // active 45–until
		// Another session's transition must not leak in.
		{SessionUUID: "other", State: store.SessionWorking, OccurredAt: min(5)},
	}
	until := min(55) // final WORKING segment is 45–55 (10m)
	got := metering.BillableDuration(ts, "s", until)
	want := 30 * time.Minute // 15 + 5 + 10
	if got != want {
		t.Fatalf("BillableDuration = %v, want %v", got, want)
	}

	// No transitions for the session ⇒ zero.
	if d := metering.BillableDuration(ts, "absent", until); d != 0 {
		t.Fatalf("BillableDuration(absent) = %v, want 0", d)
	}
}

// TestSampleEventNeverBills proves the D37 sample class rides the SAME idempotent
// stream as a short-retention rollup but is NOT a billing accrual: kind=sample,
// empty State (so the billing roll-up never sees it), opaque payload carried.
func TestSampleEventNeverBills(t *testing.T) {
	s := &hostagentv1.SessionSample{
		SessionUuid:  "sess-3",
		RssBytes:     4096,
		CpuNanos:     1_000_000,
		IoReadBytes:  10,
		IoWriteBytes: 20,
		SampledAt:    1_700_000_000,
	}
	ev := metering.SampleEvent(s)
	if ev.Kind != metering.KindSample {
		t.Fatalf("sample event kind = %q, want %q", ev.Kind, metering.KindSample)
	}
	if ev.State != "" {
		t.Fatalf("sample event State = %q, want empty (a sample enters no §3 state)", ev.State)
	}
	if a, ok := metering.ClassifyAccrual(ev.State); ok || a == metering.Active {
		t.Fatalf("empty sample state classified active/known (%v,%v) — a sample must never bill", a, ok)
	}
	if len(ev.Payload) == 0 {
		t.Fatal("sample payload empty; the opaque D37 sample must be carried")
	}
}

// TestSampleIdempotent proves a re-ingested heartbeat sample is a no-op at the
// store (idempotent on (session, sampled_at)) and that identical metrics produce
// an identical body.
func TestSampleIdempotent(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	hb := &hostagentv1.Heartbeat{
		HostId: "host-x",
		Samples: []*hostagentv1.SessionSample{
			{SessionUuid: "sess-4", RssBytes: 8, CpuNanos: 9, SampledAt: 1_700_000_100},
		},
	}
	for i := 0; i < 2; i++ {
		if err := metering.EmitHeartbeatSamples(ctx, mem, hb); err != nil {
			t.Fatalf("EmitHeartbeatSamples #%d: %v", i, err)
		}
	}
	got, err := mem.ListMeteringEvents(ctx, "sess-4")
	if err != nil {
		t.Fatalf("ListMeteringEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("re-ingested sample produced %d rows, want 1", len(got))
	}

	// A sample with DIFFERING metrics under the same key is a conflict.
	forgedSample := &hostagentv1.SessionSample{SessionUuid: "sess-4", RssBytes: 99, SampledAt: 1_700_000_100}
	if err := mem.AppendMeteringEvent(ctx, metering.SampleEvent(forgedSample)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("differing sample body under same key: got %v, want ErrConflict", err)
	}

	// An empty heartbeat is a clean no-op.
	if err := metering.EmitHeartbeatSamples(ctx, mem, &hostagentv1.Heartbeat{}); err != nil {
		t.Fatalf("empty heartbeat: %v", err)
	}
}

// TestEmitTransitionsBatchIdempotent proves a re-run overlapping batch is safe.
func TestEmitTransitionsBatchIdempotent(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	t0 := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	batch := []metering.Transition{
		{SessionUUID: "s", State: store.SessionCreating, OccurredAt: t0},
		{SessionUUID: "s", State: store.SessionReady, OccurredAt: t0.Add(time.Minute)},
		{SessionUUID: "s", State: store.SessionWorking, OccurredAt: t0.Add(2 * time.Minute)},
	}
	if err := metering.EmitTransitions(ctx, mem, batch); err != nil {
		t.Fatalf("first batch: %v", err)
	}
	if err := metering.EmitTransitions(ctx, mem, batch); err != nil {
		t.Fatalf("re-run batch: %v", err)
	}
	got, err := mem.ListMeteringEvents(ctx, "s")
	if err != nil {
		t.Fatalf("ListMeteringEvents: %v", err)
	}
	if len(got) != len(batch) {
		t.Fatalf("re-run batch produced %d rows, want %d", len(got), len(batch))
	}
}
