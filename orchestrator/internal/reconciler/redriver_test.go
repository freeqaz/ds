package reconciler

// Tests for the CONCRETE Redriver (redriver.go): the §3 rule-b/rule-c
// convergence-loop closer that re-asserts desired state through the SAME create
// spine the CreateSession RPC runs. The headline acceptances:
//
//   - rule-b re-drive RE-ASSERTS (routes through the spine), never audit-only;
//   - rule-c regression RE-CONVERGES through the spine;
//   - quarantine-not-destroy is preserved when the concrete Redriver is wired;
//   - the re-drive routes through the spine (asserted via a SPY spine — the task's
//     "assert via a spy/fake spine"), and a host-side continuation runs through the
//     SAME coordinator seam;
//   - the single-goroutine lastBeat contract is preserved (the concrete Redriver
//     holds no mutable state; the reconciler's only state stays lastBeat).
//
// D50: synthetic record fixtures + a spy spine; zero live VM/host-agent/podman.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// spySpine is the synthetic SpineRunner: it RECORDS every record routed through it
// (proving the re-drive went through the shared create spine, not a reconciler-side
// copy) and scripts the spine's outcome (success, the nullable/system-session
// sentinel, or a transient fault).
type spySpine struct {
	mu       sync.Mutex
	reasrted []store.Session // every record ReassertDesired was called with
	result   sessions.CreateSpineResult
	err      error
}

func (s *spySpine) ReassertDesired(_ context.Context, rec store.Session) (sessions.CreateSpineResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reasrted = append(s.reasrted, rec)
	if s.err != nil {
		return sessions.CreateSpineResult{}, s.err
	}
	return s.result, nil
}

func (s *spySpine) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.reasrted) }
func (s *spySpine) last() (store.Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reasrted) == 0 {
		return store.Session{}, false
	}
	return s.reasrted[len(s.reasrted)-1], true
}

// spyContinuation records the host-side re-create hand-off (the §4.1 steps 3–4,
// 6–10 continuation over the shared ten-step coordinator) and scripts its outcome.
type spyContinuation struct {
	mu       sync.Mutex
	driven   []store.Session
	gotSpine []sessions.CreateSpineResult
	err      error
}

func (c *spyContinuation) ContinueHostReCreate(_ context.Context, rec store.Session, spine sessions.CreateSpineResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.driven = append(c.driven, rec)
	c.gotSpine = append(c.gotSpine, spine)
	return c.err
}

func (c *spyContinuation) count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.driven) }

// newConcreteRedriverReconciler wires a Reconciler over a real *store.Memory with
// the CONCRETE Redriver (over the spy spine + optional continuation) in place of
// the bare recordingRedriver — so the §3 rules re-drive/re-converge through the
// shared spine.
func newConcreteRedriverReconciler(t *testing.T, spine SpineRunner, cont SpineContinuation) (*Reconciler, *store.Memory, *recordingDriver, *recordingAlarmer, *fixedClock) {
	t.Helper()
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	drv := &recordingDriver{}
	al := &recordingAlarmer{}
	cr, err := NewConcreteRedriver(spine, cont, nil)
	if err != nil {
		t.Fatalf("NewConcreteRedriver: %v", err)
	}
	r, err := New(st, drv, cr, al, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r, st, drv, al, clk
}

// NewConcreteRedriver guards: a nil spine is refused (a redriver with no spine
// cannot re-assert); a nil continuation/logger is accepted (the documented optional
// collaborators).
func TestNewConcreteRedriver_Guards(t *testing.T) {
	if _, err := NewConcreteRedriver(nil, nil, nil); err == nil {
		t.Fatalf("nil spine runner must error")
	}
	if _, err := NewConcreteRedriver(&spySpine{}, nil, nil); err != nil {
		t.Fatalf("nil continuation/logger must be accepted: %v", err)
	}
}

// Rule (b): a host-resident record whose VM is missing is RE-ASSERTED through the
// SHARED create spine — not failed to DESTROYED, not audit-only. The spy spine
// proves the record routed through the spine, and the record's desired state stays
// intact (the re-drive does not regress it).
func TestRuleB_MissingVM_ReassertsThroughSpine(t *testing.T) {
	spine := &spySpine{}
	r, st, drv, al, _ := newConcreteRedriverReconciler(t, spine, nil)
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)

	// Heartbeat with NO observed sessions → the record's VM is missing (rule b).
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// The re-drive ROUTED THROUGH THE SPINE (re-assert, not audit-only).
	if spine.count() != 1 {
		t.Fatalf("missing-VM record must re-assert through the spine; got %d spine re-asserts", spine.count())
	}
	got, ok := spine.last()
	if !ok || got.Ref.SessionUUID != "sess-1" {
		t.Fatalf("the spine must be handed the missing-VM record; got %+v", got)
	}
	// It did NOT fail to DESTROYED and did NOT drive any destroy verb.
	rec, _ := st.GetSession(context.Background(), "sess-1")
	if rec.State != store.SessionWorking {
		t.Fatalf("a successful re-assert leaves the desired state intact; got %v", rec.State)
	}
	if al.has(AlarmFailedToDestroyed) {
		t.Fatalf("a successful re-assert must NOT fail the record to DESTROYED (§3 rule b)")
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("re-drive must not destroy; got %d destroys", drv.destroyCount())
	}
}

// Rule (c): a state regression (observed BEHIND desired) RE-CONVERGES through the
// SHARED create spine — the spy proves the regressed record routed through it, and
// the record's desired state is NOT regressed to match the slipped VM.
func TestRuleC_Regression_ReconvergesThroughSpine(t *testing.T) {
	spine := &spySpine{}
	r, st, drv, al, _ := newConcreteRedriverReconciler(t, spine, nil)
	// Desired = WORKING; the VM slipped back to READY (a state already passed
	// through: READY → ATTACHED → WORKING).
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)
	hb := heartbeat("host-1", observedSession("sess-1", "dom-1", 1, store.SessionReady))
	if err := r.Observe(context.Background(), hb); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	if !al.has(AlarmReconverge) {
		t.Fatalf("a regression must raise the re-converge alarm (§3 rule c)")
	}
	if spine.count() != 1 {
		t.Fatalf("a regression must re-converge through the spine; got %d spine re-asserts", spine.count())
	}
	got, _ := spine.last()
	if got.Ref.SessionUUID != "sess-1" {
		t.Fatalf("the spine must be handed the regressed record; got %+v", got)
	}
	// The DESIRED state must stay WORKING — never regressed to the slipped VM state.
	rec, _ := st.GetSession(context.Background(), "sess-1")
	if rec.State != store.SessionWorking {
		t.Fatalf("desired state must NOT be regressed to the slipped VM; got %v", rec.State)
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("re-converge must not destroy; got %d", drv.destroyCount())
	}
}

// QUARANTINE-NOT-DESTROY is preserved with the concrete Redriver wired: an orphan
// VM (no record) is still quarantined (suspended) and NEVER auto-destroyed, and the
// re-drive spine is NOT consulted for an orphan (the orphan has no record to
// re-assert — rule a, not rule b).
func TestQuarantineNotDestroy_PreservedWithConcreteRedriver(t *testing.T) {
	spine := &spySpine{}
	r, _, drv, al, _ := newConcreteRedriverReconciler(t, spine, nil)
	hb := heartbeat("host-1", observedSession("sess-orphan", "dom-1", 1, store.SessionWorking))
	if err := r.Observe(context.Background(), hb); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if drv.suspendCount() != 1 {
		t.Fatalf("orphan must be quarantined (suspended); got %d", drv.suspendCount())
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("orphan VM must NEVER be auto-destroyed (§3 rule a); got %d", drv.destroyCount())
	}
	if spine.count() != 0 {
		t.Fatalf("an orphan VM has no record to re-assert — the spine must NOT be consulted; got %d", spine.count())
	}
	if !al.has(AlarmQuarantine) {
		t.Fatalf("orphan must raise the quarantine alarm")
	}
}

// Rule (b) fallback: when the spine reports the NULLABLE / system-session sentinel
// (the record has no linked launching principal), the re-drive cannot be honestly
// re-asserted — the reconciler takes the fail-to-DESTROYED-with-audit arm rather
// than minting a placeholder.
func TestRuleB_SpineNoLaunchingUser_FailsToDestroyed(t *testing.T) {
	spine := &spySpine{err: sessions.ErrRedriveNoLaunchingUser}
	r, st, drv, al, _ := newConcreteRedriverReconciler(t, spine, nil)
	seedRecord(t, st, "sess-sys", "host-1", 1, store.SessionReady)
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if spine.count() != 1 {
		t.Fatalf("the spine must be consulted before the fallback; got %d", spine.count())
	}
	got, _ := st.GetSession(context.Background(), "sess-sys")
	if got.State != store.SessionDestroyed {
		t.Fatalf("an un-re-assertable record must fall through to DESTROYED (§3 rule b); got %v", got.State)
	}
	if !al.has(AlarmFailedToDestroyed) {
		t.Fatalf("the fail-to-DESTROYED audit must be raised")
	}
	if drv.destroyCount() != 0 {
		t.Fatalf("there is no VM to destroy — the record is finalized, never a destroy verb; got %d", drv.destroyCount())
	}
}

// Rule (b) fallback: a TRANSIENT spine fault (resolver/store) also falls through to
// fail-to-DESTROYED on this tick (the §3 rule-b alternative arm: re-drive failed),
// and the next tick re-drives — the re-drive is idempotent.
func TestRuleB_SpineTransientFault_FailsToDestroyed(t *testing.T) {
	spine := &spySpine{err: context.DeadlineExceeded}
	r, st, _, al, _ := newConcreteRedriverReconciler(t, spine, nil)
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionAttached)
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	got, _ := st.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionDestroyed {
		t.Fatalf("a failed re-drive must fall through to DESTROYED (§3 rule b); got %v", got.State)
	}
	if !al.has(AlarmFailedToDestroyed) {
		t.Fatalf("expected the fail-to-DESTROYED audit")
	}
}

// The host-side CONTINUATION runs through the SAME coordinator seam: when wired, a
// rule-b re-drive re-asserts the spine cluster AND drives the host re-create
// through the continuation, carrying the spine result forward.
func TestRuleB_ReassertDrivesHostContinuation(t *testing.T) {
	spine := &spySpine{result: sessions.CreateSpineResult{
		Launch: sessions.LaunchOutcome{PrincipalID: "p-1", Subject: "ada@example.com", Linked: true},
	}}
	cont := &spyContinuation{}
	r, st, _, _, _ := newConcreteRedriverReconciler(t, spine, cont)
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if spine.count() != 1 {
		t.Fatalf("the spine must re-assert; got %d", spine.count())
	}
	if cont.count() != 1 {
		t.Fatalf("the host-side continuation must drive the re-create through the shared coordinator; got %d", cont.count())
	}
	// The continuation received the spine's re-asserted result (carried forward).
	if len(cont.gotSpine) != 1 || cont.gotSpine[0].Launch.Subject != "ada@example.com" {
		t.Fatalf("the continuation must carry the spine result forward; got %+v", cont.gotSpine)
	}
}

// A continuation FAULT makes the re-drive fail on this tick → the reconciler takes
// the fail-to-DESTROYED arm (rule b) — the re-drive did not complete, so it is not
// claimed converged.
func TestRuleB_ContinuationFault_FailsToDestroyed(t *testing.T) {
	spine := &spySpine{}
	cont := &spyContinuation{err: errors.New("host agent unreachable")}
	r, st, _, al, _ := newConcreteRedriverReconciler(t, spine, cont)
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if cont.count() != 1 {
		t.Fatalf("the continuation must be attempted; got %d", cont.count())
	}
	got, _ := st.GetSession(context.Background(), "sess-1")
	if got.State != store.SessionDestroyed {
		t.Fatalf("a failed host re-create must fall through to DESTROYED (§3 rule b); got %v", got.State)
	}
	if !al.has(AlarmFailedToDestroyed) {
		t.Fatalf("expected the fail-to-DESTROYED audit")
	}
}

// RedriveSession guards: an empty-UUID record is rejected (cannot key the spine).
func TestConcreteRedriver_EmptyUUIDGuard(t *testing.T) {
	cr, err := NewConcreteRedriver(&spySpine{}, nil, nil)
	if err != nil {
		t.Fatalf("NewConcreteRedriver: %v", err)
	}
	if err := cr.RedriveSession(context.Background(), store.Session{}); err == nil {
		t.Fatalf("an empty-UUID record must be rejected")
	}
}

// The concrete Redriver routes through the spine on the PERIODIC RESYNC leg too —
// trigger parity (the conflict rules are the same code on Observe and Resync). A
// host that reports a missing-VM observed set this cycle re-asserts through the
// spine exactly as the event-driven leg does.
func TestResync_ReassertsThroughSpine(t *testing.T) {
	spine := &spySpine{}
	r, st, _, _, _ := newConcreteRedriverReconciler(t, spine, nil)
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)
	// host-1 reports an empty observed set this cycle → the record's VM is missing.
	if err := r.Resync(context.Background(), map[string][]*hypervisorv1.ObservedSession{
		"host-1": {},
	}); err != nil {
		t.Fatalf("Resync: %v", err)
	}
	if spine.count() != 1 {
		t.Fatalf("resync must re-assert the missing-VM record through the spine; got %d", spine.count())
	}
}
