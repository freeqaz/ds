package reconciler

// Tests for every crash-matrix cell the reconciler owns (doc 15 §3), one focused
// test per cell:
//
//   host-agent crash  → AdoptRecovered converges the re-observed set (TestHostAgentCrash_*).
//   replica  crash    → stateless: a fresh reconciler converges identically (TestReplicaCrash_*).
//   Postgres down     → degraded: stall, never destroy/quarantine (TestPostgresDown_*).
//   3 missed beats    → UNKNOWN, never auto-destroyed (TestMissedBeats_*).
//   host crash        → LOST at v0 (non-claim): never auto-destroyed (TestHostCrash_*).

import (
	"context"
	"testing"
	"time"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// CELL: host-agent crash → RecoverSessions re-adoption. AdoptRecovered takes the
// re-observed set and converges it EXACTLY like a heartbeat — a record whose VM
// re-appears in the re-adopted set is left intact, and a record whose VM is NOT
// re-adopted is reaped by rule b. No RPC replay anywhere.
func TestHostAgentCrash_AdoptRecovered_Converges(t *testing.T) {
	r, st, drv, rd, al, _ := newTestReconciler(t)
	// Two records on host-1. After the agent restart, RecoverSessions re-adopts
	// only sess-survivor; sess-gone is not re-adopted (its VM did not come back).
	seedRecord(t, st, "sess-survivor", "host-1", 1, store.SessionWorking)
	seedRecord(t, st, "sess-gone", "host-1", 2, store.SessionReady)

	resp := &hypervisorv1.RecoverSessionsResponse{
		Sessions: []*hypervisorv1.ObservedSession{
			observedSession("sess-survivor", "dom-1", 1, store.SessionWorking),
		},
	}
	if err := r.AdoptRecovered(context.Background(), "host-1", resp); err != nil {
		t.Fatalf("AdoptRecovered: %v", err)
	}

	// sess-survivor re-adopted → intact, no re-drive, no destroy.
	surv, _ := st.GetSession(context.Background(), "sess-survivor")
	if surv.State != store.SessionWorking {
		t.Fatalf("re-adopted session must be left intact; got %v", surv.State)
	}
	// sess-gone not re-adopted → rule b re-drives it.
	if rd.count() != 1 || rd.redrives[0] != "sess-gone" {
		t.Fatalf("un-re-adopted record must be re-driven; redrives=%v", rd.redrives)
	}
	// Re-adoption NEVER destroys or quarantines a re-adopted survivor.
	if drv.destroyCount() != 0 {
		t.Fatalf("re-adoption must not destroy; got %d", drv.destroyCount())
	}
	if drv.suspendCount() != 0 {
		t.Fatalf("re-adopted survivor must not be quarantined; got %d suspends", drv.suspendCount())
	}
	_ = al
}

// host-agent crash + an orphan in the re-adopted set (a domain the host is running
// that has no control-plane record) → quarantine, never destroy.
func TestHostAgentCrash_ReadoptedOrphan_Quarantined(t *testing.T) {
	r, _, drv, _, al, _ := newTestReconciler(t)
	resp := &hypervisorv1.RecoverSessionsResponse{
		Sessions: []*hypervisorv1.ObservedSession{
			observedSession("sess-orphan", "dom-7", 7, store.SessionWorking),
		},
	}
	if err := r.AdoptRecovered(context.Background(), "host-1", resp); err != nil {
		t.Fatalf("AdoptRecovered: %v", err)
	}
	if drv.suspendCount() != 1 || drv.destroyCount() != 0 {
		t.Fatalf("re-adopted orphan must be quarantined not destroyed; suspends=%d destroys=%d", drv.suspendCount(), drv.destroyCount())
	}
	if !al.has(AlarmQuarantine) {
		t.Fatalf("expected quarantine alarm on re-adopted orphan")
	}
}

func TestHostAgentCrash_EmptyHostID_Rejected(t *testing.T) {
	r, _, _, _, _, _ := newTestReconciler(t)
	if err := r.AdoptRecovered(context.Background(), "", &hypervisorv1.RecoverSessionsResponse{}); err == nil {
		t.Fatalf("AdoptRecovered with empty host_id must error")
	}
}

// CELL: replica crash → STATELESS. A reconciler's only mutable state (lastBeat) is
// rebuildable by re-observing: a FRESH reconciler over the SAME store + same
// heartbeat converges to the SAME outcome as one that had been running. So a
// replica crash is a no-op.
func TestReplicaCrash_Stateless_FreshReplicaConvergesIdentically(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking) // VM will be missing → rule b

	hb := heartbeat("host-1") // no observed sessions

	// Replica A processes the heartbeat.
	drvA := &recordingDriver{}
	rdA := &recordingRedriver{}
	rA, _ := New(st, drvA, rdA, &recordingAlarmer{}, clk.now, Config{})
	if err := rA.Observe(context.Background(), hb); err != nil {
		t.Fatalf("replica A Observe: %v", err)
	}

	// Replica A "crashes". A brand-new replica B (empty lastBeat) processes the
	// SAME heartbeat against the SAME store and must converge identically.
	drvB := &recordingDriver{}
	rdB := &recordingRedriver{}
	rB, _ := New(st, drvB, rdB, &recordingAlarmer{}, clk.now, Config{})
	if err := rB.Observe(context.Background(), hb); err != nil {
		t.Fatalf("replica B Observe: %v", err)
	}

	if rdA.count() != 1 || rdB.count() != 1 {
		t.Fatalf("both replicas must re-drive the missing-VM record identically; A=%d B=%d", rdA.count(), rdB.count())
	}
	if drvA.destroyCount() != 0 || drvB.destroyCount() != 0 {
		t.Fatalf("neither replica may destroy; A=%d B=%d", drvA.destroyCount(), drvB.destroyCount())
	}
}

// CELL: Postgres down → DEGRADED. The record read returns ErrUnavailable; the
// reconcile STALLS — no driver verb, no state write — running sessions continue.
// The reconciler must NOT quarantine the host's VMs as orphans just because the
// records are unreadable, nor destroy anything.
func TestPostgresDown_DegradedMode_Stalls(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	inner := store.NewMemoryClock(clk.now)
	deg := &degradedStore{inner: inner, failList: true}
	drv := &recordingDriver{}
	al := &recordingAlarmer{}
	r, _ := New(deg, drv, &recordingRedriver{}, al, clk.now, Config{})

	// A heartbeat carrying observed VMs arrives while Postgres is down.
	hb := heartbeat("host-1", observedSession("sess-1", "dom-1", 1, store.SessionWorking))
	err := r.Observe(context.Background(), hb)
	if err == nil {
		t.Fatalf("degraded reconcile must surface the store-unavailable error")
	}
	if !degraded(err) {
		t.Fatalf("error must be the degraded ErrUnavailable signal; got %v", err)
	}
	// STALL: no quarantine, no destroy — the records are merely unreadable, the
	// VMs are not orphans.
	if drv.suspendCount() != 0 {
		t.Fatalf("degraded mode must NOT quarantine; got %d suspends", drv.suspendCount())
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("degraded mode must NOT destroy; got %d destroys", drv.destroyCount())
	}
	if !al.has(AlarmDegraded) {
		t.Fatalf("degraded mode must raise the degraded alarm")
	}
}

// Postgres down on the WRITE leg (the fail-to-DESTROYED finalize) → the write
// stalls, the record is left intact for retry, never half-written.
func TestPostgresDown_FailToDestroyedWrite_Stalls(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	inner := store.NewMemoryClock(clk.now)
	seedRecord(t, inner, "sess-1", "host-1", 1, store.SessionReady)
	// List works (so rule b reaches the finalize), but the Update fails.
	deg := &degradedStore{inner: inner, failUpdate: true}
	drv := &recordingDriver{}
	al := &recordingAlarmer{}
	r, _ := New(deg, drv, nil /* no redriver → straight to fail-to-DESTROYED */, al, clk.now, Config{})

	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe should absorb the per-session write fault, not return: %v", err)
	}
	// Record must NOT be DESTROYED — the write stalled.
	got, _ := inner.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionReady {
		t.Fatalf("stalled finalize must leave the record intact; got %v", got.State)
	}
	if !al.has(AlarmDegraded) {
		t.Fatalf("a degraded write must raise the degraded alarm")
	}
}

// A NON-degraded write fault on the fail-to-DESTROYED finalize is alarmed (so the
// stuck record is visible) and left intact for retry — never half-written.
func TestRuleB_FailToDestroyedWriteFault_AlarmedAndRetained(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	inner := store.NewMemoryClock(clk.now)
	seedRecord(t, inner, "sess-1", "host-1", 1, store.SessionReady)
	deg := &degradedStore{inner: inner, updateErr: context.DeadlineExceeded}
	al := &recordingAlarmer{}
	r, _ := New(deg, &recordingDriver{}, nil, al, clk.now, Config{})

	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe should absorb the per-session write fault: %v", err)
	}
	got, _ := inner.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionReady {
		t.Fatalf("a failed finalize must leave the record intact; got %v", got.State)
	}
	if !al.has(AlarmFailedToDestroyed) {
		t.Fatalf("a failed finalize must alarm so the stuck record is visible")
	}
}

// CELL: 3 missed heartbeats → sessions UNKNOWN, never auto-destroyed. After the
// silence window passes with no heartbeat, a resync sweep marks the host's
// sessions UNKNOWN (an alarm) WITHOUT mutating any record state.
func TestMissedBeats_SessionsUnknown_NeverDestroyed(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	drv := &recordingDriver{}
	al := &recordingAlarmer{}
	r, _ := New(st, drv, &recordingRedriver{}, al, clk.now, Config{})

	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)

	// Host reports once, then goes silent.
	if err := r.Observe(context.Background(), heartbeat("host-1", observedSession("sess-1", "dom-1", 1, store.SessionWorking))); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	// Advance past the missed-beat window (3 * 5s default = 15s) with no heartbeat.
	clk.advance(20 * time.Second)
	if err := r.Resync(context.Background(), map[string][]*hypervisorv1.ObservedSession{}); err != nil {
		t.Fatalf("Resync: %v", err)
	}

	if !al.has(AlarmHostUnknown) {
		t.Fatalf("silent host past the window must mark its sessions UNKNOWN")
	}
	// INVARIANT: never auto-destroyed, record state untouched.
	if drv.destroyCount() != 0 {
		t.Fatalf("missed-beat host must NEVER be auto-destroyed; got %d destroys", drv.destroyCount())
	}
	got, _ := st.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionWorking {
		t.Fatalf("UNKNOWN is a liveness annotation, NOT a state change; record state changed to %v", got.State)
	}
}

// A host that reports a LIVE observed set in this resync cycle must NOT be marked
// UNKNOWN, even if its lastBeat is stale/absent — a resync-carried observed set is
// itself a fresh observation (the §3 missed-beat sweep is for hosts that reported
// NOTHING this cycle, never for a host demonstrably alive in observedByHost). Guards
// the spurious-UNKNOWN regression on a system running purely on periodic resync.
func TestMissedBeats_ResyncReportingHost_NotMarkedUnknown(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	drv := &recordingDriver{}
	al := &recordingAlarmer{}
	r, _ := New(st, drv, &recordingRedriver{}, al, clk.now, Config{})

	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)

	// First resync: host-1 reports a live observed set; lastBeat was never set via
	// Observe (pure periodic-resync operation). It must converge clean, NOT UNKNOWN.
	obs := map[string][]*hypervisorv1.ObservedSession{
		"host-1": {observedSession("sess-1", "dom-1", 1, store.SessionWorking)},
	}
	if err := r.Resync(context.Background(), obs); err != nil {
		t.Fatalf("Resync (reporting): %v", err)
	}
	if al.has(AlarmHostUnknown) {
		t.Fatalf("a host reporting a live observed set this cycle must NOT be marked UNKNOWN")
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("a reporting host must never be destroyed; got %d", drv.destroyCount())
	}

	// Now the host goes silent past the window: a later resync with it ABSENT from
	// observedByHost must mark it UNKNOWN (the lastBeat stamped on the prior resync
	// is what makes the window measurable).
	clk.advance(20 * time.Second)
	if err := r.Resync(context.Background(), map[string][]*hypervisorv1.ObservedSession{}); err != nil {
		t.Fatalf("Resync (silent): %v", err)
	}
	if !al.has(AlarmHostUnknown) {
		t.Fatalf("a host that stopped reporting past the window must be marked UNKNOWN")
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("UNKNOWN host must never be auto-destroyed; got %d", drv.destroyCount())
	}
}

// A host still WITHIN the silence window is not marked UNKNOWN.
func TestMissedBeats_WithinWindow_NotMarked(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	al := &recordingAlarmer{}
	r, _ := New(st, &recordingDriver{}, &recordingRedriver{}, al, clk.now, Config{})

	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)
	if err := r.Observe(context.Background(), heartbeat("host-1", observedSession("sess-1", "dom-1", 1, store.SessionWorking))); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	clk.advance(5 * time.Second) // well within the 15s window
	if err := r.Resync(context.Background(), map[string][]*hypervisorv1.ObservedSession{}); err != nil {
		t.Fatalf("Resync: %v", err)
	}
	if al.has(AlarmHostUnknown) {
		t.Fatalf("host within the silence window must not be marked UNKNOWN")
	}
}

// A custom missed-beat threshold/cadence is honored (the rig-tuned values, free).
func TestMissedBeats_CustomThreshold(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	al := &recordingAlarmer{}
	// 2 missed beats of 1s = 2s window.
	r, _ := New(st, &recordingDriver{}, &recordingRedriver{}, al, clk.now, Config{MissedBeatThreshold: 2, Cadence: time.Second})

	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)
	if err := r.Observe(context.Background(), heartbeat("host-1", observedSession("sess-1", "dom-1", 1, store.SessionWorking))); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	clk.advance(3 * time.Second) // past the 2s window
	if err := r.Resync(context.Background(), map[string][]*hypervisorv1.ObservedSession{}); err != nil {
		t.Fatalf("Resync: %v", err)
	}
	if !al.has(AlarmHostUnknown) {
		t.Fatalf("custom threshold window must mark the host UNKNOWN")
	}
}

// CELL: host crash → sessions LOST at v0 (the explicit §3 non-claim). The
// reconciler does NOT auto-destroy a crashed host's records; it marks them
// UNKNOWN (the same missed-beat path) and leaves the LOST disposition to the
// operator / the named M3 durability-stream path. This is the same code as the
// missed-beat cell asserted from the host-crash framing: a host that vanishes
// entirely (never re-observed) must not have its sessions torn down.
func TestHostCrash_SessionsLost_NeverAutoDestroyed(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	drv := &recordingDriver{}
	al := &recordingAlarmer{}
	r, _ := New(st, drv, &recordingRedriver{}, al, clk.now, Config{})

	// A working session on a host that then crashes hard and is NEVER heard from.
	seedRecord(t, st, "sess-1", "host-crashed", 1, store.SessionWorking)

	// Multiple resync cycles with the host absent from every observed set.
	for i := 0; i < 3; i++ {
		clk.advance(20 * time.Second)
		if err := r.Resync(context.Background(), map[string][]*hypervisorv1.ObservedSession{}); err != nil {
			t.Fatalf("Resync %d: %v", i, err)
		}
	}

	// LOST, never destroyed: no destroy verb, record state untouched.
	if drv.destroyCount() != 0 {
		t.Fatalf("crashed host's sessions are LOST not destroyed (§3 non-claim); got %d destroys", drv.destroyCount())
	}
	got, _ := st.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionWorking {
		t.Fatalf("crashed host's record must not be auto-mutated; got %v", got.State)
	}
	if !al.has(AlarmHostUnknown) {
		t.Fatalf("crashed host's sessions must be marked UNKNOWN")
	}
}
