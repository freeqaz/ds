// SPDX-License-Identifier: Apache-2.0

package reconciler

// redriver_destroy_itest_test.go is the reconciler-package INTEGRATION test for the
// §4.2 destroy-path convergence backstop (DestroyRedriver.Sweep) driven through a real
// host-keyed DestroyDriver REGISTRY over several distinct per-host recording fakes —
// the no-broadcast invariant the destroy path must hold. Where destroyredrive_test.go
// pins Sweep against a SINGLE fakeDestroyDriver (the unit-level convergence/fault
// contract), this test pins the FLEET-shape invariant: when a record is stuck DESTROYING
// on exactly ONE host, Sweep's §4.2 teardown must target ONLY that host's driver carrying
// the stuck session uuid — every OTHER host's driver sees ZERO Destroys (no fleet-wide
// fan-out). It mirrors the controlplane multiHostRegistry/recordingDriver shape (a
// per-host driver fake + a host-keyed registry that dispatches by hostID) but is wholly
// reconciler-package-LOCAL — it does NOT touch controlplane/seams_test.go (wave-1-owned),
// and it adapts to the reconciler's host-folded DestroyDriver seam
// (Destroy(ctx, hostID, sessionUUID) error), not controlplane's DriverRegistry/DriverFor.
//
// WHY THE NO-BROADCAST ASSERTION MATTERS. DestroyRedriver.redriveOne drives
// dr.destroyer.Destroy(ctx, rec.Ref.HostID, sessionUUID) — keyed on the RECORDED host of
// the stuck record. A regression that dropped the hostID (or fanned the teardown out to
// every known host) would still converge the record to DESTROYED and pass the
// single-driver unit tests, while in production it would tear down — or attempt to tear
// down — sessions on UNRELATED hosts. This integration test closes that gap exactly as the
// controlplane Suspend/Destroy integration does for the reap path: it routes Sweep through
// a registry of >=3 hosts and asserts the recorded host got exactly one targeted Destroy
// and all others got zero.
//
// D50: synthetic fixtures only — a real *store.Memory desired-state store, an in-package
// host-keyed registry over recording per-host fakes, and a fake finalize writer. No live
// VM / host-agent / podman / network.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// itestDestroyHost is a per-host DestroyDriver fake (D50): it records the (hostID,
// sessionUUID) pairs it was asked to tear down, so a test can assert WHICH host's driver
// fired and with which stuck session uuid. failsLeft injects a fixed number of transient
// teardown faults before succeeding (the negative fault-on-target arm). It is the reconciler
// -package analogue of controlplane's recordingDriver, adapted to the host-folded Destroy
// verb (no hypervisorv1 request type — the reconciler's seam is (hostID, sessionUUID)).
type itestDestroyHost struct {
	mu        sync.Mutex
	host      string
	calls     []string // session uuids this host was asked to Destroy, in order
	failsLeft int
}

func (h *itestDestroyHost) destroy(sessionUUID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, sessionUUID)
	if h.failsLeft > 0 {
		h.failsLeft--
		return errors.New("transient §4.2 teardown fault on host " + h.host)
	}
	return nil
}

func (h *itestDestroyHost) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls)
}

func (h *itestDestroyHost) last() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.calls) == 0 {
		return ""
	}
	return h.calls[len(h.calls)-1]
}

// itestHostKeyedDestroyRegistry is a host-keyed DestroyDriver over several distinct per-host
// recording fakes — the reconciler-package-local mirror of controlplane's multiHostRegistry,
// satisfying the reconciler's DestroyDriver seam. Its Destroy dispatches the §4.2 teardown to
// the named host's driver (keyed on hostID), or returns ErrNoItestDriverForHost for an
// unregistered host (the analogue of ErrNoDriverForHost: an unknown host must surface an error,
// NEVER silently widen to a broadcast). This is what proves Sweep tears down only the recorded
// host: a regression that lost the hostID would land on the wrong (or no) driver here.
type itestHostKeyedDestroyRegistry struct {
	drivers map[string]*itestDestroyHost
}

// ErrNoItestDriverForHost is the reconciler-test-local sentinel for "no driver registered for
// this host" — modeling controlplane's ErrNoDriverForHost without importing controlplane.
var errNoItestDriverForHost = errors.New("reconciler itest: no destroy driver for host")

func newItestHostKeyedDestroyRegistry(hosts ...string) *itestHostKeyedDestroyRegistry {
	r := &itestHostKeyedDestroyRegistry{drivers: make(map[string]*itestDestroyHost, len(hosts))}
	for _, h := range hosts {
		r.drivers[h] = &itestDestroyHost{host: h}
	}
	return r
}

// Destroy satisfies the reconciler DestroyDriver seam: it dispatches the host-folded §4.2
// teardown to the recorded host's driver. An unknown host surfaces an error rather than
// broadcasting — the registry never widens a single-host teardown to the fleet.
func (r *itestHostKeyedDestroyRegistry) Destroy(_ context.Context, hostID, sessionUUID string) error {
	d, ok := r.drivers[hostID]
	if !ok {
		return errNoItestDriverForHost
	}
	return d.destroy(sessionUUID)
}

// totalDestroys sums the Destroys across every registered host — a fleet-wide regression
// (broadcast) shows up as more than one host with a non-zero count.
func (r *itestHostKeyedDestroyRegistry) totalDestroys() int {
	total := 0
	for _, d := range r.drivers {
		total += d.count()
	}
	return total
}

// assertOnlyHostFired asserts the named target host saw exactly ONE Destroy carrying
// wantUUID and EVERY other registered host saw zero — the no-broadcast invariant.
func (r *itestHostKeyedDestroyRegistry) assertOnlyHostFired(t *testing.T, targetHost, wantUUID string) {
	t.Helper()
	for host, d := range r.drivers {
		if host == targetHost {
			if d.count() != 1 {
				t.Fatalf("target host %q: want exactly 1 Destroy, got %d (calls=%v)", host, d.count(), d.calls)
			}
			if got := d.last(); got != wantUUID {
				t.Fatalf("target host %q: Destroy carried uuid %q, want the stuck session uuid %q", host, got, wantUUID)
			}
			continue
		}
		if d.count() != 0 {
			t.Fatalf("non-target host %q: want 0 Destroys (no fleet broadcast), got %d (calls=%v)", host, d.count(), d.calls)
		}
	}
}

// itestDestroyLister cuts the DestroyingLister seam from a real *store.Memory (filter
// State=DESTROYING) — the same narrow read the production wiring uses (store.ListSessions
// filtered to DESTROYING), so the sweep operates over genuinely-persisted desired state.
type itestDestroyLister struct{ mem *store.Memory }

func (l itestDestroyLister) ListDestroying(ctx context.Context) ([]store.Session, error) {
	return l.mem.ListSessions(ctx, store.SessionFilter{State: store.SessionDestroying})
}

// itestDestroyFinalizer cuts the DestroyFinalizer seam from a real *store.Memory (the
// §3-terminal DESTROYING→DESTROYED write, stamping DestroyedAt) — so a clean teardown lands
// the real terminal transition the test reads back.
type itestDestroyFinalizer struct {
	mem   *store.Memory
	clock func() time.Time
}

func (f itestDestroyFinalizer) FinalizeDestroyed(ctx context.Context, sessionUUID string) (store.Session, error) {
	destroyed := store.SessionDestroyed
	return f.mem.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		State:       &destroyed,
		DestroyedAt: store.SetTime(f.clock()),
	})
}

// seedItestFleet builds a real *store.Memory holding records on several distinct hosts, with
// EXACTLY ONE flipped to DESTROYING (the in-flight teardown marker DestroySession leaves on a
// teardown fault) on the named stuck host; the other hosts hold non-DESTROYING records (so the
// DESTROYING filter genuinely selects one record on one host). It returns the wired
// DestroyRedriver, the host-keyed registry, the store, and the stuck session uuid.
func seedItestFleet(t *testing.T, stuckHost string, registry *itestHostKeyedDestroyRegistry) (*DestroyRedriver, *store.Memory, string) {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC) }
	mem := store.NewMemoryClock(clock)
	ctx := context.Background()

	// A non-DESTROYING record on every NON-stuck host — these must NEVER be touched by the
	// sweep (they are not DESTROYING and not on the stuck host).
	idx := uint64(1)
	for host := range registry.drivers {
		if host == stuckHost {
			continue
		}
		if _, err := mem.CreateSession(ctx, store.Session{
			Ref:          store.SessionRef{SessionUUID: "live-" + host, HostID: host, HostSessionIndex: idx, TapName: "dstap-1"},
			State:        store.SessionReady,
			EnvConfigRef: "env-live",
			ImageID:      "sha256:img",
		}); err != nil {
			t.Fatalf("seed live record on %s: %v", host, err)
		}
		idx++
	}

	// The ONE stuck-DESTROYING record on the stuck host (created PENDING, then flipped to
	// DESTROYING — the legal §3 path the store enforces).
	const stuckUUID = "sess-stuck-on-target"
	if _, err := mem.CreateSession(ctx, store.Session{
		Ref:          store.SessionRef{SessionUUID: stuckUUID, HostID: stuckHost, HostSessionIndex: 99, TapName: "dstap-99"},
		State:        store.SessionPending,
		EnvConfigRef: "env-stuck",
		ImageID:      "sha256:img",
	}); err != nil {
		t.Fatalf("seed stuck record: %v", err)
	}
	destroying := store.SessionDestroying
	if _, err := mem.UpdateSession(ctx, stuckUUID, store.SessionUpdate{State: &destroying}); err != nil {
		t.Fatalf("flip stuck record DESTROYING: %v", err)
	}

	dr, err := NewDestroyRedriver(itestDestroyLister{mem}, registry, itestDestroyFinalizer{mem, clock}, nil)
	if err != nil {
		t.Fatalf("NewDestroyRedriver: %v", err)
	}
	return dr, mem, stuckUUID
}

// TestDestroyRedriverItest_Sweep_TargetsOnlyRecordedHost is the positive integration
// scenario: a session stuck DESTROYING on exactly one host of a >=3-host fleet is re-driven
// to DESTROYED, and the §4.2 teardown fires on ONLY that host's driver carrying the stuck
// session uuid — every other host's driver sees ZERO Destroys (no fleet broadcast). Sweep
// returns finalized==1 and the record reads back DESTROYED with DestroyedAt stamped.
func TestDestroyRedriverItest_Sweep_TargetsOnlyRecordedHost(t *testing.T) {
	const targetHost = "host-b"
	registry := newItestHostKeyedDestroyRegistry("host-a", targetHost, "host-c", "host-d")
	dr, mem, stuckUUID := seedItestFleet(t, targetHost, registry)
	ctx := context.Background()

	finalized, err := dr.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if finalized != 1 {
		t.Fatalf("sweep finalized %d records, want exactly 1", finalized)
	}

	// Exactly ONE host's driver fired, carrying the stuck uuid; all other hosts saw zero.
	registry.assertOnlyHostFired(t, targetHost, stuckUUID)
	if total := registry.totalDestroys(); total != 1 {
		t.Fatalf("fleet-wide Destroy count = %d, want 1 (a >1 count is a broadcast regression)", total)
	}

	// The record finalized to the §3-terminal DESTROYED with DestroyedAt stamped (the row is
	// RETAINED — D66; we read it back through IncludeDestroyed).
	got, err := mem.GetSession(ctx, stuckUUID)
	if err != nil {
		t.Fatalf("read back stuck record: %v", err)
	}
	if got.State != store.SessionDestroyed {
		t.Fatalf("stuck record state: got %q, want DESTROYED", got.State)
	}
	if got.DestroyedAt == nil {
		t.Fatalf("a clean §4.2 teardown must finalize with DestroyedAt stamped")
	}
}

// TestDestroyRedriverItest_Sweep_FaultOnTarget_NoBroadcast is the NEGATIVE integration
// scenario: a teardown FAULT on the targeted host leaves the record DESTROYING (Sweep returns
// finalized==0, never a spurious DESTROYED on an un-torn-down session) AND still drives the
// §4.2 teardown on ONLY the targeted host — no other host's driver is touched. The fault must
// not be "compensated" by a fleet broadcast.
func TestDestroyRedriverItest_Sweep_FaultOnTarget_NoBroadcast(t *testing.T) {
	const targetHost = "host-c"
	registry := newItestHostKeyedDestroyRegistry("host-a", "host-b", targetHost)
	// Fault the targeted host's teardown once — the transient §4.2 fault DestroySession's
	// "reconciler will re-drive" comment models.
	registry.drivers[targetHost].failsLeft = 1
	dr, mem, stuckUUID := seedItestFleet(t, targetHost, registry)
	ctx := context.Background()

	finalized, err := dr.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep (fault arm) must not return a sweep-level error: %v", err)
	}
	if finalized != 0 {
		t.Fatalf("a faulting teardown must finalize 0 records, got %d", finalized)
	}

	// The §4.2 teardown was attempted on ONLY the targeted host (carrying the stuck uuid);
	// the fault did NOT widen to a fleet broadcast.
	registry.assertOnlyHostFired(t, targetHost, stuckUUID)
	if total := registry.totalDestroys(); total != 1 {
		t.Fatalf("fleet-wide Destroy count = %d on the fault arm, want 1 (a fault must not broadcast)", total)
	}

	// The record is LEFT DESTROYING (never finalized to DESTROYED on an un-torn-down session).
	got, err := mem.GetSession(ctx, stuckUUID)
	if err != nil {
		t.Fatalf("read back stuck record: %v", err)
	}
	if got.State != store.SessionDestroying {
		t.Fatalf("a faulting teardown must leave the record DESTROYING, got %q", got.State)
	}
	if got.DestroyedAt != nil {
		t.Fatalf("a faulting teardown must NOT stamp DestroyedAt; got %v", got.DestroyedAt)
	}

	// And the level-triggered contract: the NEXT sweep (the now-clean idempotent teardown)
	// converges it — still targeting only the recorded host (count climbs to 2 on the target,
	// stays 0 elsewhere).
	finalized2, err := dr.Sweep(ctx)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if finalized2 != 1 {
		t.Fatalf("the second (clean) sweep must converge the record, finalized=%d want 1", finalized2)
	}
	if got := registry.drivers[targetHost].count(); got != 2 {
		t.Fatalf("target host saw %d Destroys across two sweeps, want 2", got)
	}
	for host, d := range registry.drivers {
		if host == targetHost {
			continue
		}
		if d.count() != 0 {
			t.Fatalf("non-target host %q saw %d Destroys across two sweeps, want 0 (no broadcast)", host, d.count())
		}
	}
	conv, _ := mem.GetSession(ctx, stuckUUID)
	if conv.State != store.SessionDestroyed || conv.DestroyedAt == nil {
		t.Fatalf("the second sweep must converge to DESTROYED with DestroyedAt; got %q / %v", conv.State, conv.DestroyedAt)
	}
}
