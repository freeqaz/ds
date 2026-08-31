package reconciler

// destroyredrive_test.go pins the §4.2 destroy-path convergence backstop (the
// DestroyRedriver): a session STUCK in DESTROYING (a transient host-teardown fault left
// it there) is re-driven FORWARD to DESTROYED via the §4.2 teardown. The §3 conflict rules
// deliberately exclude DESTROYING from the rule-b missing-VM reap (a teardown-in-flight
// record is not a no-VM fault — TestRuleB_NonHostResidentStates_NotReaped), so this is the
// missing arm that closes the destroy loop. D50: synthetic fixtures + a fake destroyer over
// the real *store.Memory desired-state store — no live VM/host-agent/podman.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// memDestroyAdapters cuts the three DestroyRedriver seams from a real *store.Memory:
// ListDestroying (filter State=DESTROYING) and FinalizeDestroyed (the §3-terminal write).
type memDestroyLister struct{ mem *store.Memory }

func (l memDestroyLister) ListDestroying(ctx context.Context) ([]store.Session, error) {
	return l.mem.ListSessions(ctx, store.SessionFilter{State: store.SessionDestroying})
}

type memDestroyFinalizer struct {
	mem   *store.Memory
	clock func() time.Time
}

func (f memDestroyFinalizer) FinalizeDestroyed(ctx context.Context, sessionUUID string) (store.Session, error) {
	destroyed := store.SessionDestroyed
	return f.mem.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		State:       &destroyed,
		DestroyedAt: store.SetTime(f.clock()),
	})
}

// fakeDestroyDriver records the §4.2 drives and can fault a fixed number of times before
// succeeding — modeling a transient teardown fault that leaves the record DESTROYING.
type fakeDestroyDriver struct {
	failsLeft int
	calls     int
	lastHost  string
	lastUUID  string
}

func (d *fakeDestroyDriver) Destroy(_ context.Context, hostID, sessionUUID string) error {
	d.calls++
	d.lastHost, d.lastUUID = hostID, sessionUUID
	if d.failsLeft > 0 {
		d.failsLeft--
		return errors.New("transient §4.2 teardown fault")
	}
	return nil
}

// seedDestroying builds a Memory store with one session flipped to DESTROYING (the in-flight
// teardown marker DestroySession leaves on a teardown fault) and returns the wired re-driver.
func seedDestroying(t *testing.T, destroyer *fakeDestroyDriver) (*DestroyRedriver, *store.Memory) {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	mem := store.NewMemoryClock(clock)
	ctx := context.Background()
	if _, err := mem.CreateSession(ctx, store.Session{
		Ref:          store.SessionRef{SessionUUID: "sess-stuck", HostID: "host-a", HostSessionIndex: 1, TapName: "dstap-1"},
		State:        store.SessionPending,
		EnvConfigRef: "env-1",
		ImageID:      "sha256:img",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	destroying := store.SessionDestroying
	if _, err := mem.UpdateSession(ctx, "sess-stuck", store.SessionUpdate{State: &destroying}); err != nil {
		t.Fatalf("flip DESTROYING: %v", err)
	}
	dr, err := NewDestroyRedriver(memDestroyLister{mem}, destroyer, memDestroyFinalizer{mem, clock}, nil)
	if err != nil {
		t.Fatalf("NewDestroyRedriver: %v", err)
	}
	return dr, mem
}

func TestDestroyRedriver_Guards(t *testing.T) {
	d := &fakeDestroyDriver{}
	mem := store.NewMemory()
	if _, err := NewDestroyRedriver(nil, d, memDestroyFinalizer{mem, time.Now}, nil); err == nil {
		t.Fatal("nil lister must be rejected")
	}
	if _, err := NewDestroyRedriver(memDestroyLister{mem}, nil, memDestroyFinalizer{mem, time.Now}, nil); err == nil {
		t.Fatal("nil destroyer must be rejected")
	}
	if _, err := NewDestroyRedriver(memDestroyLister{mem}, d, nil, nil); err == nil {
		t.Fatal("nil finalizer must be rejected")
	}
}

// TestDestroyRedriver_StuckDestroying_ConvergesToDestroyed is the acceptance scenario:
// a session left DESTROYING by a teardown fault is re-driven to DESTROYED.
func TestDestroyRedriver_StuckDestroying_ConvergesToDestroyed(t *testing.T) {
	destroyer := &fakeDestroyDriver{}
	dr, mem := seedDestroying(t, destroyer)
	ctx := context.Background()

	n, err := dr.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("finalized %d, want 1", n)
	}
	if destroyer.calls != 1 || destroyer.lastUUID != "sess-stuck" || destroyer.lastHost != "host-a" {
		t.Fatalf("§4.2 drive: calls=%d host=%q uuid=%q", destroyer.calls, destroyer.lastHost, destroyer.lastUUID)
	}
	got, _ := mem.GetSession(ctx, "sess-stuck")
	if got.State != store.SessionDestroyed {
		t.Fatalf("state: got %q, want DESTROYED", got.State)
	}
	if got.DestroyedAt == nil {
		t.Fatalf("the §3-terminal finalize must stamp DestroyedAt (§4.2 step 6)")
	}
}

// TestDestroyRedriver_TransientFault_LeavesDestroyingThenConverges pins the level-triggered
// contract: a transient teardown fault leaves the record DESTROYING (never a spurious
// DESTROYED on an un-torn-down session); the next sweep — the idempotent no-op teardown —
// converges it.
func TestDestroyRedriver_TransientFault_LeavesDestroyingThenConverges(t *testing.T) {
	destroyer := &fakeDestroyDriver{failsLeft: 1}
	dr, mem := seedDestroying(t, destroyer)
	ctx := context.Background()

	if n, err := dr.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("first sweep: n=%d err=%v, want 0,nil", n, err)
	}
	if got, _ := mem.GetSession(ctx, "sess-stuck"); got.State != store.SessionDestroying {
		t.Fatalf("a faulting teardown must leave the record DESTROYING, got %q", got.State)
	}
	if n, err := dr.Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("second sweep: n=%d err=%v, want 1,nil", n, err)
	}
	if got, _ := mem.GetSession(ctx, "sess-stuck"); got.State != store.SessionDestroyed || got.DestroyedAt == nil {
		t.Fatalf("second sweep must converge to DESTROYED with DestroyedAt; got %q / %v", got.State, got.DestroyedAt)
	}
}

// TestDestroyRedriver_FinalizeFault_LeavesDestroying proves a clean teardown but a FAILED
// finalize leaves the record DESTROYING (not silently dropped) for the next sweep.
func TestDestroyRedriver_FinalizeFault_LeavesDestroying(t *testing.T) {
	destroyer := &fakeDestroyDriver{}
	clock := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	mem := store.NewMemoryClock(clock)
	ctx := context.Background()
	if _, err := mem.CreateSession(ctx, store.Session{
		Ref:          store.SessionRef{SessionUUID: "sess-x", HostID: "host-a", HostSessionIndex: 1, TapName: "dstap-1"},
		State:        store.SessionPending,
		EnvConfigRef: "env-1", ImageID: "sha256:img",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	destroying := store.SessionDestroying
	if _, err := mem.UpdateSession(ctx, "sess-x", store.SessionUpdate{State: &destroying}); err != nil {
		t.Fatalf("flip: %v", err)
	}
	dr, err := NewDestroyRedriver(memDestroyLister{mem}, destroyer, faultyFinalizer{}, nil)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if n, err := dr.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("sweep with a faulty finalizer: n=%d err=%v, want 0,nil", n, err)
	}
	if destroyer.calls != 1 {
		t.Fatalf("the §4.2 teardown must still have been driven once; calls=%d", destroyer.calls)
	}
	if got, _ := mem.GetSession(ctx, "sess-x"); got.State != store.SessionDestroying {
		t.Fatalf("a failed finalize must leave the record DESTROYING, got %q", got.State)
	}
}

type faultyFinalizer struct{}

func (faultyFinalizer) FinalizeDestroyed(context.Context, string) (store.Session, error) {
	return store.Session{}, errors.New("finalize write fault")
}

// TestDestroyRedriver_ListFault_Stalls proves a degraded-mode list fault stalls the sweep
// (returned to the caller) rather than fabricating an empty DESTROYING set.
func TestDestroyRedriver_ListFault_Stalls(t *testing.T) {
	dr, err := NewDestroyRedriver(faultyLister{}, &fakeDestroyDriver{}, faultyFinalizer{}, nil)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if _, err := dr.Sweep(context.Background()); err == nil {
		t.Fatal("a list fault must stall the sweep (returned error)")
	}
}

type faultyLister struct{}

func (faultyLister) ListDestroying(context.Context) ([]store.Session, error) {
	return nil, store.ErrUnavailable
}
