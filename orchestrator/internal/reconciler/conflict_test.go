package reconciler

// Tests for the three frozen §3 conflict rules (doc 15 §3), one focused test per
// rule plus the two load-bearing invariants (quarantine-not-destroy,
// re-converge-not-regress) and the event-driven vs. periodic-resync trigger parity.

import (
	"context"
	"sync"
	"testing"
	"time"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// newTestReconciler wires a Reconciler over a real *store.Memory plus the
// recording fakes, on a fixed clock. Returns the pieces a test asserts on.
func newTestReconciler(t *testing.T) (*Reconciler, *store.Memory, *recordingDriver, *recordingRedriver, *recordingAlarmer, *fixedClock) {
	t.Helper()
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	drv := &recordingDriver{}
	rd := &recordingRedriver{}
	al := &recordingAlarmer{}
	r, err := New(st, drv, rd, al, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r, st, drv, rd, al, clk
}

// Rule (a): an observed VM with NO record is QUARANTINED (suspended) with an
// alarm, NEVER auto-destroyed.
func TestRuleA_OrphanVM_Quarantined_NeverDestroyed(t *testing.T) {
	r, _, drv, _, al, _ := newTestReconciler(t)
	// No record seeded — the observed VM is an orphan.
	hb := heartbeat("host-1", observedSession("sess-orphan", "dom-1", 1, store.SessionWorking))
	if err := r.Observe(context.Background(), hb); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	if drv.suspendCount() != 1 {
		t.Fatalf("orphan must be suspended into quarantine; got %d suspends", drv.suspendCount())
	}
	// INVARIANT: never auto-destroyed.
	if drv.destroyCount() != 0 {
		t.Fatalf("orphan VM must NEVER be auto-destroyed (§3 rule a); got %d destroys", drv.destroyCount())
	}
	sus := drv.lastSuspend()
	if sus.GetSessionUuid() != "sess-orphan" {
		t.Fatalf("suspend targeted wrong session: %q", sus.GetSessionUuid())
	}
	if sus.GetReason() != hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH {
		t.Fatalf("quarantine suspend must carry POLICY_BREACH reason; got %v", sus.GetReason())
	}
	if sus.GetProvenance() == nil || sus.GetProvenance().GetRuleId() == "" {
		t.Fatalf("POLICY_BREACH suspend must carry provenance (§5.1); got %+v", sus.GetProvenance())
	}
	if !al.has(AlarmQuarantine) {
		t.Fatalf("quarantine must raise the operator alarm")
	}
}

// Rule (a) with an observed element that has no session UUID — still quarantined,
// never destroyed (the un-joinable-VM orphan path).
func TestRuleA_ObservedNoUUID_Quarantined(t *testing.T) {
	r, _, drv, _, al, _ := newTestReconciler(t)
	bad := &hypervisorv1.ObservedSession{DomainUuid: "dom-x"} // no session uuid
	if err := r.Observe(context.Background(), heartbeat("host-1", bad)); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if drv.suspendCount() != 1 || drv.destroyCount() != 0 {
		t.Fatalf("un-joinable VM must be quarantined not destroyed; suspends=%d destroys=%d", drv.suspendCount(), drv.destroyCount())
	}
	if !al.has(AlarmQuarantine) {
		t.Fatalf("expected quarantine alarm")
	}
}

// Rule (a) is idempotent: re-observing the same orphan re-issues Suspend (a no-op
// driver-side, idempotent on session_uuid) and still never destroys.
func TestRuleA_Idempotent_AcrossTicks(t *testing.T) {
	r, _, drv, _, _, _ := newTestReconciler(t)
	hb := heartbeat("host-1", observedSession("sess-orphan", "dom-1", 1, store.SessionWorking))
	for i := 0; i < 3; i++ {
		if err := r.Observe(context.Background(), hb); err != nil {
			t.Fatalf("Observe tick %d: %v", i, err)
		}
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("orphan must never be destroyed across ticks; got %d", drv.destroyCount())
	}
	if drv.suspendCount() != 3 {
		t.Fatalf("each tick re-issues the idempotent quarantine suspend; got %d", drv.suspendCount())
	}
}

// Rule (a): even when the quarantine SUSPEND DRIVE FAILS, the orphan is alarmed
// (never silently left un-flagged) and NEVER escalated to Destroy.
func TestRuleA_QuarantineDriveFails_StillAlarmed_NeverDestroyed(t *testing.T) {
	r, _, drv, _, al, _ := newTestReconciler(t)
	drv.suspendErr = context.DeadlineExceeded
	hb := heartbeat("host-1", observedSession("sess-orphan", "dom-1", 1, store.SessionWorking))
	if err := r.Observe(context.Background(), hb); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("a failed quarantine must NEVER escalate to destroy; got %d", drv.destroyCount())
	}
	if !al.has(AlarmQuarantine) {
		t.Fatalf("a failed quarantine must still raise the alarm")
	}
}

// Observe guards: a nil heartbeat and an empty host_id are rejected.
func TestObserve_Guards(t *testing.T) {
	r, _, _, _, _, _ := newTestReconciler(t)
	if err := r.Observe(context.Background(), nil); err == nil {
		t.Fatalf("nil heartbeat must error")
	}
	if err := r.Observe(context.Background(), heartbeat("")); err == nil {
		t.Fatalf("empty host_id must error")
	}
}

// New guards: nil store / nil driver are rejected; nil redriver/alarm/clock are
// accepted (the documented optional collaborators).
func TestNew_Guards(t *testing.T) {
	drv := &recordingDriver{}
	st := store.NewMemory()
	if _, err := New(nil, drv, nil, nil, nil, Config{}); err == nil {
		t.Fatalf("nil store must error")
	}
	if _, err := New(st, nil, nil, nil, nil, Config{}); err == nil {
		t.Fatalf("nil driver must error")
	}
	if _, err := New(st, drv, nil, nil, nil, Config{}); err != nil {
		t.Fatalf("nil redriver/alarm/clock must be accepted: %v", err)
	}
}

// Rule (b): a record with no VM, in a HOST-RESIDENT state, is re-driven toward
// desired.
func TestRuleB_MissingVM_Redriven(t *testing.T) {
	r, st, drv, rd, _, _ := newTestReconciler(t)
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)
	// Heartbeat with NO observed sessions → the record's VM is missing.
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if rd.count() != 1 {
		t.Fatalf("missing-VM record must be re-driven; got %d redrives", rd.count())
	}
	// Re-drive path must NOT destroy the record or drive any driver verb.
	if drv.destroyCount() != 0 {
		t.Fatalf("re-drive must not destroy; got %d destroys", drv.destroyCount())
	}
	got, _ := st.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionWorking {
		t.Fatalf("re-drive leaves desired state intact; got %v", got.State)
	}
}

// Rule (b) alternative arm: re-drive UNAVAILABLE (nil redriver) → the no-VM record
// is FAILED to DESTROYED with an audit event.
func TestRuleB_MissingVM_NoRedriver_FailedToDestroyed(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	drv := &recordingDriver{}
	al := &recordingAlarmer{}
	r, err := New(st, drv, nil /* no redriver */, al, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionReady)
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	got, _ := st.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionDestroyed {
		t.Fatalf("no-VM record with no re-drive must be failed to DESTROYED; got %v", got.State)
	}
	if got.DestroyedAt == nil {
		t.Fatalf("fail-to-DESTROYED must stamp DestroyedAt (§4.2)")
	}
	if !al.has(AlarmFailedToDestroyed) {
		t.Fatalf("fail-to-DESTROYED must raise the audit event (§3 rule b)")
	}
}

// Rule (b) alternative arm: re-drive FAILS → fall through to fail-to-DESTROYED.
func TestRuleB_MissingVM_RedriveFails_FailedToDestroyed(t *testing.T) {
	r, st, _, rd, al, _ := newTestReconciler(t)
	rd.err = context.DeadlineExceeded // re-drive request fails
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionAttached)
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	got, _ := st.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionDestroyed {
		t.Fatalf("failed re-drive must fall through to DESTROYED; got %v", got.State)
	}
	if !al.has(AlarmFailedToDestroyed) {
		t.Fatalf("expected fail-to-DESTROYED audit")
	}
}

// Rule (b) must NOT fire for states that legitimately have no host VM (PARKED,
// SUSPENDED, PENDING, terminal): absence there is expected, not a fault.
func TestRuleB_NonHostResidentStates_NotReaped(t *testing.T) {
	for _, st := range []store.SessionState{
		store.SessionParked,
		store.SessionSuspended,
		store.SessionPending,
		store.SessionDestroying,
		store.SessionDestroyed,
	} {
		t.Run(string(st), func(t *testing.T) {
			r, mem, drv, rd, al, _ := newTestReconciler(t)
			seedRecord(t, mem, "sess-1", "host-1", 1, st)
			if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
				t.Fatalf("Observe: %v", err)
			}
			if rd.count() != 0 {
				t.Fatalf("%v must not be re-driven on missing VM", st)
			}
			if drv.destroyCount() != 0 {
				t.Fatalf("%v must not be destroyed on missing VM", st)
			}
			if al.has(AlarmFailedToDestroyed) {
				t.Fatalf("%v must not be failed to DESTROYED on missing VM", st)
			}
			got, _ := mem.GetSession(context.Background(), "sess-1")
			if got.State != st {
				t.Fatalf("%v record state must be untouched; got %v", st, got.State)
			}
		})
	}
}

// Rule (c): a state regression (observed state is BEHIND desired) re-converges
// toward desired — the record's desired state is NOT regressed to match the VM.
func TestRuleC_StateRegression_ReconvergesTowardDesired(t *testing.T) {
	r, st, drv, rd, al, _ := newTestReconciler(t)
	// Desired = WORKING; the VM is observed slipped back to READY (a state the
	// record already progressed past: READY → ATTACHED → WORKING).
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)
	hb := heartbeat("host-1", observedSession("sess-1", "dom-1", 1, store.SessionReady))
	if err := r.Observe(context.Background(), hb); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !al.has(AlarmReconverge) {
		t.Fatalf("state regression must raise the re-converge alarm (§3 rule c)")
	}
	if rd.count() != 1 {
		t.Fatalf("regression must request a re-drive toward desired; got %d", rd.count())
	}
	// The record's DESIRED state must stay WORKING — never regressed to match the VM.
	got, _ := st.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionWorking {
		t.Fatalf("desired state must NOT be regressed to the slipped VM state; got %v", got.State)
	}
	// Convergence must not destroy.
	if drv.destroyCount() != 0 {
		t.Fatalf("regression re-converge must not destroy; got %d", drv.destroyCount())
	}
}

// A legal in-flight transition (WORKING observed against a SNAPSHOTTING desired,
// or an ATTACHED⇄WORKING oscillation) is NOT a regression — no re-converge fires.
func TestRuleC_LegalInFlight_NotRegression(t *testing.T) {
	cases := []struct {
		name              string
		desired, observed store.SessionState
	}{
		{"working-while-snapshotting-desired", store.SessionSnapshotting, store.SessionWorking},
		{"attached-while-working-desired", store.SessionWorking, store.SessionAttached},
		{"working-while-attached-desired", store.SessionAttached, store.SessionWorking},
		{"exact-match", store.SessionWorking, store.SessionWorking},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, st, _, rd, al, _ := newTestReconciler(t)
			seedRecord(t, st, "sess-1", "host-1", 1, tc.desired)
			hb := heartbeat("host-1", observedSession("sess-1", "dom-1", 1, tc.observed))
			if err := r.Observe(context.Background(), hb); err != nil {
				t.Fatalf("Observe: %v", err)
			}
			if al.has(AlarmReconverge) {
				t.Fatalf("%s must NOT be a regression", tc.name)
			}
			if rd.count() != 0 {
				t.Fatalf("%s must not request a re-drive", tc.name)
			}
		})
	}
}

// An un-pin-downable observed state (UNSPECIFIED) is NOT a regression and does not
// thrash the record — it is left for a later pin-downable beat.
func TestRuleC_UnpinnableObserved_NotRegression(t *testing.T) {
	r, st, _, rd, al, _ := newTestReconciler(t)
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)
	hb := heartbeat("host-1", observedSessionNoState("sess-1"))
	if err := r.Observe(context.Background(), hb); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if al.has(AlarmReconverge) {
		t.Fatalf("un-pin-downable observation must not be treated as a regression")
	}
	if rd.count() != 0 {
		t.Fatalf("un-pin-downable observation must not request a re-drive")
	}
	got, _ := st.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionWorking {
		t.Fatalf("record left intact; got %v", got.State)
	}
}

// hostFanoutDriver is a host-targeting recording Driver fake (D50, no live VM): it
// reads the OPTIONAL reporting-host hint the reconciler stamps onto the Suspend context
// (WithQuarantineHostHint, seams.go) and records the Suspend under THAT host — exactly
// what the production registryDriver does once it honors the hint (the documented bridge
// clause). An UNHINTED Suspend (no host on the context) is recorded under the broadcast
// sentinel "<broadcast>", standing in for the fleet-wide fan-out the fast path avoids. The
// test then COUNTS per-host fan-out: a hinted orphan quarantine must hit ONLY the reporting
// host and never the broadcast bucket.
type hostFanoutDriver struct {
	mu             sync.Mutex
	suspendsByHost map[string]int // reporting host_id (or "<broadcast>") → Suspend count
	destroys       []*hypervisorv1.DestroyRequest
}

// broadcastSentinel is the per-host key an UNHINTED Suspend lands under — it stands in for
// the O(fleet) broadcast the host-hint fast path collapses. A targeted (hinted) Suspend must
// NEVER fall into this bucket.
const broadcastSentinel = "<broadcast>"

func newHostFanoutDriver() *hostFanoutDriver {
	return &hostFanoutDriver{suspendsByHost: make(map[string]int)}
}

func (d *hostFanoutDriver) Suspend(ctx context.Context, _ *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	host, ok := QuarantineHostHint(ctx)
	if !ok {
		host = broadcastSentinel
	}
	d.suspendsByHost[host]++
	return &hypervisorv1.SuspendResponse{}, nil
}

func (d *hostFanoutDriver) Destroy(_ context.Context, req *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.destroys = append(d.destroys, req)
	return &hypervisorv1.DestroyResponse{}, nil
}

func (d *hostFanoutDriver) suspendsOn(host string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.suspendsByHost[host]
}

func (d *hostFanoutDriver) totalSuspends() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, c := range d.suspendsByHost {
		n += c
	}
	return n
}

// Compile-time proof the host-fanout fake satisfies the reconciler's Driver seam, so the
// reconciler drives it exactly as it drives the production registryDriver.
var _ Driver = (*hostFanoutDriver)(nil)

// TestRuleA_OrphanQuarantine_TargetsReportingHostOnly is the unit's CORE acceptance: the
// §3 rule-a orphan quarantine Suspend targets ONLY the host that reported the orphan (the
// host_id reconcileHost holds from the heartbeat, doc 15 §4.2), never fanning out across
// the fleet (D35 per-host driver, D66 host/index binding — avoid the ~500-host broadcast
// the D37 v0 density model sizes for). Asserted by counting per-host verb fan-out: exactly
// one Suspend, under the reporting host, ZERO under the broadcast sentinel.
func TestRuleA_OrphanQuarantine_TargetsReportingHostOnly(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	drv := newHostFanoutDriver()
	al := &recordingAlarmer{}
	r, err := New(st, drv, nil, al, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// host-reporter observes an orphan VM (no record) — rule a → quarantine.
	hb := heartbeat("host-reporter", observedSession("sess-orphan", "dom-1", 1, store.SessionWorking))
	if err := r.Observe(context.Background(), hb); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	if got := drv.totalSuspends(); got != 1 {
		t.Fatalf("orphan quarantine must Suspend exactly once; got %d total", got)
	}
	if got := drv.suspendsOn("host-reporter"); got != 1 {
		t.Fatalf("quarantine Suspend must target the reporting host; got %d on host-reporter", got)
	}
	// INVARIANT: the hinted verb must NOT land in the broadcast bucket (no fleet fan-out).
	if got := drv.suspendsOn(broadcastSentinel); got != 0 {
		t.Fatalf("hinted orphan quarantine must NOT broadcast fleet-wide; got %d broadcast Suspends", got)
	}
	if !al.has(AlarmQuarantine) {
		t.Fatalf("quarantine must raise the operator alarm")
	}
}

// TestRuleA_OrphanQuarantine_ResyncTargetsReportingHost proves the host-targeting holds on
// the PERIODIC FULL RESYNC leg too (trigger parity, doc 15 §3): an orphan surfaced by a
// host's resync observed-set is quarantined on THAT host only, never broadcast.
func TestRuleA_OrphanQuarantine_ResyncTargetsReportingHost(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	drv := newHostFanoutDriver()
	al := &recordingAlarmer{}
	r, err := New(st, drv, nil, al, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	observedByHost := map[string][]*hypervisorv1.ObservedSession{
		"host-reporter": {observedSession("sess-orphan", "dom-9", 9, store.SessionWorking)},
	}
	if err := r.Resync(context.Background(), observedByHost); err != nil {
		t.Fatalf("Resync: %v", err)
	}
	if got := drv.suspendsOn("host-reporter"); got != 1 {
		t.Fatalf("resync quarantine must target the reporting host; got %d on host-reporter", got)
	}
	if got := drv.suspendsOn(broadcastSentinel); got != 0 {
		t.Fatalf("resync quarantine must NOT broadcast; got %d broadcast Suspends", got)
	}
}

// TestRuleA_UnjoinableOrphan_TargetsReportingHost proves the un-joinable orphan (an observed
// element with NO session UUID, which still quarantines per rule a) is ALSO host-targeted —
// the reporting host is threaded regardless of whether the orphan carries a session UUID.
func TestRuleA_UnjoinableOrphan_TargetsReportingHost(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	drv := newHostFanoutDriver()
	al := &recordingAlarmer{}
	r, err := New(st, drv, nil, al, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bad := &hypervisorv1.ObservedSession{DomainUuid: "dom-x"} // no session uuid
	if err := r.Observe(context.Background(), heartbeat("host-reporter", bad)); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if got := drv.suspendsOn("host-reporter"); got != 1 {
		t.Fatalf("un-joinable orphan quarantine must target the reporting host; got %d on host-reporter", got)
	}
	if got := drv.suspendsOn(broadcastSentinel); got != 0 {
		t.Fatalf("un-joinable orphan quarantine must NOT broadcast; got %d broadcast Suspends", got)
	}
}

// TestWithQuarantineHostHint_EmptyIsNoHint proves WithQuarantineHostHint("") is a no-op so
// quarantineOrphan can stamp the reporting host unconditionally: an empty host leaves the
// context unchanged (no hint), and QuarantineHostHint reads nothing — the absent-hint
// (record-resolve / broadcast) behavior is preserved. A non-empty host round-trips.
func TestWithQuarantineHostHint_EmptyIsNoHint(t *testing.T) {
	base := context.Background()
	if got := WithQuarantineHostHint(base, ""); got != base {
		t.Fatalf("empty host must return the context unchanged (no hint)")
	}
	if _, ok := QuarantineHostHint(WithQuarantineHostHint(base, "")); ok {
		t.Fatalf("empty host must read back as no hint")
	}
	if _, ok := QuarantineHostHint(base); ok {
		t.Fatalf("a bare context carries no hint")
	}
	if host, ok := QuarantineHostHint(WithQuarantineHostHint(base, "host-reporter")); !ok || host != "host-reporter" {
		t.Fatalf("a stamped host must round-trip; got (%q,%v)", host, ok)
	}
	if _, ok := QuarantineHostHint(nil); ok { //nolint:staticcheck // explicitly exercising the nil-ctx guard
		t.Fatalf("a nil context must read back as no hint")
	}
}

// The orphan reap (rules a/b) runs on the PERIODIC FULL RESYNC leg identically to
// the event-driven leg — trigger parity (doc 15 §3: event-driven + periodic).
func TestResync_OrphanAndMissingVM_SameRules(t *testing.T) {
	r, st, drv, rd, al, _ := newTestReconciler(t)
	// host-1 has a record whose VM is missing (rule b → re-drive).
	seedRecord(t, st, "sess-present-record", "host-1", 1, store.SessionWorking)
	// host-1 also reports an orphan VM (rule a → quarantine).
	observedByHost := map[string][]*hypervisorv1.ObservedSession{
		"host-1": {observedSession("sess-orphan", "dom-9", 9, store.SessionWorking)},
	}
	if err := r.Resync(context.Background(), observedByHost); err != nil {
		t.Fatalf("Resync: %v", err)
	}
	if drv.suspendCount() != 1 {
		t.Fatalf("resync must quarantine the orphan; got %d suspends", drv.suspendCount())
	}
	if rd.count() != 1 {
		t.Fatalf("resync must re-drive the missing-VM record; got %d redrives", rd.count())
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("resync must not destroy the orphan; got %d", drv.destroyCount())
	}
	if !al.has(AlarmQuarantine) {
		t.Fatalf("resync must raise the quarantine alarm")
	}
}
