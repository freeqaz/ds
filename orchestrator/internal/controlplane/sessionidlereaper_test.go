package controlplane

// sessionidlereaper_test.go drives the writer-less-RUNNING idle reaper against a FAKE CLOCK,
// a FAKE session lister, and a RECORDING fake destroyer — no live VM / host-agent / store
// (D50). The behaviors the unit pins:
//
//   - a writer-less RUNNING session left writer-less for longer than the TTL is destroyed
//     EXACTLY ONCE (via the §4.2 destroyer seam), and not before the TTL elapses;
//   - an ATTENDED (writer-held) RUNNING session is NEVER destroyed, however long it runs;
//   - a RECENTLY-detached session (writer-less for < TTL) is NOT destroyed (the conservative
//     window: a brief detach-and-reattach is reaped-immune; a re-attach RESETS the clock);
//   - a SUSPENDED (or any non-RUNNING) session is NEVER touched;
//   - TTL = 0 DISABLES the reaper (newSessionIdleReaper yields nil; Run runs no sweep).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// --- fakes -----------------------------------------------------------------

// fakeClock is a manually-advanced clock so a test pins "writer-less for > TTL" deterministically.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeSessionLister is a settable in-memory ListSessions: a test sets the record set the next
// sweep observes (it can be mutated between sweeps to model a writer detach / re-attach / a
// session leaving RUNNING). It honors the SessionFilter.State / IncludeDestroyed narrowing the
// reaper relies on (the reaper passes a zero filter, so all non-destroyed records are returned).
type fakeSessionLister struct {
	mu   sync.Mutex
	recs []store.Session
	err  error // when set, ListSessions returns it (the degraded-list path)
}

func (l *fakeSessionLister) set(recs ...store.Session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = recs
}

func (l *fakeSessionLister) ListSessions(_ context.Context, f store.SessionFilter) ([]store.Session, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	out := make([]store.Session, 0, len(l.recs))
	for _, r := range l.recs {
		if f.State != "" && r.State != f.State {
			continue
		}
		if !f.IncludeDestroyed && r.State == store.SessionDestroyed {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// recordingDestroyer satisfies sessions.HostDestroyer (the SAME seam DestroySession drives) and
// records every (hostID, sessionUUID) Destroy it is asked to run, so a test asserts WHICH
// sessions were reaped and HOW MANY times. An optional failUUIDs set models a transient teardown
// fault so the reaper's re-drive-on-next-tick behavior is exercised.
type recordingDestroyer struct {
	mu        sync.Mutex
	calls     []destroyCall
	failUUIDs map[string]error
}

type destroyCall struct{ hostID, sessionUUID string }

func newRecordingDestroyer() *recordingDestroyer {
	return &recordingDestroyer{failUUIDs: map[string]error{}}
}

func (d *recordingDestroyer) Destroy(_ context.Context, hostID, sessionUUID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, destroyCall{hostID: hostID, sessionUUID: sessionUUID})
	if err, bad := d.failUUIDs[sessionUUID]; bad {
		return err
	}
	return nil
}

func (d *recordingDestroyer) countFor(uuid string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, c := range d.calls {
		if c.sessionUUID == uuid {
			n++
		}
	}
	return n
}

func (d *recordingDestroyer) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

// --- record builders -------------------------------------------------------

// runningSession builds a RUNNING (WORKING) session record with NO writer (writer-less).
func runningWriterlessSession(uuid, host string) store.Session {
	return store.Session{
		Ref:        store.SessionRef{SessionUUID: uuid, HostID: host},
		State:      store.SessionWorking,
		WriterRole: store.RoleNone,
		WriterSeat: "",
	}
}

// withWriter returns a copy of rec with a human holding the one writer seat (ATTENDED).
func withWriter(rec store.Session, holder string) store.Session {
	rec.WriterRole = store.RoleWriter
	rec.WriterSeat = holder
	rec.Attended = true
	return rec
}

// withState returns a copy of rec in a different lifecycle state.
func withState(rec store.Session, s store.SessionState) store.Session {
	rec.State = s
	return rec
}

const testIdleTTL = 30 * time.Minute

// --- tests -----------------------------------------------------------------

// TestReaper_WriterlessRunningPastTTL_DestroyedExactlyOnce: a session observed RUNNING +
// writer-less continuously past the TTL is destroyed exactly once via the §4.2 destroyer.
func TestReaper_WriterlessRunningPastTTL_DestroyedExactlyOnce(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC))
	lister := &fakeSessionLister{}
	dest := newRecordingDestroyer()
	reaper := newSessionIdleReaper(lister, dest, testIdleTTL, clk.Now, nil)
	if reaper == nil {
		t.Fatal("reaper should be constructed for a positive TTL")
	}
	ctx := context.Background()

	lister.set(runningWriterlessSession("s-1", "host-a"))

	// Sweep 1: first observation — stamps the writer-less clock, does NOT reap.
	reaper.Sweep(ctx)
	if got := dest.total(); got != 0 {
		t.Fatalf("first sweep must not reap (stamps the clock); got %d destroy calls", got)
	}

	// Advance to exactly the TTL: still not PAST it (the predicate is strictly > TTL).
	clk.advance(testIdleTTL)
	reaper.Sweep(ctx)
	if got := dest.total(); got != 0 {
		t.Fatalf("writer-less for exactly TTL must not reap (strictly > TTL); got %d destroy calls", got)
	}

	// One tick past the TTL: now reaped.
	clk.advance(time.Second)
	reaper.Sweep(ctx)
	if got := dest.countFor("s-1"); got != 1 {
		t.Fatalf("writer-less past TTL must reap exactly once; got %d destroy calls for s-1", got)
	}
	if got := dest.calls[0].hostID; got != "host-a" {
		t.Fatalf("destroy must target the record's bound host; got hostID %q", got)
	}

	// The destroyer flips the record toward DESTROYED; model that by removing it from RUNNING.
	// A further sweep must NOT re-reap (exactly once).
	lister.set(withState(runningWriterlessSession("s-1", "host-a"), store.SessionDestroying))
	clk.advance(testIdleTTL)
	reaper.Sweep(ctx)
	if got := dest.countFor("s-1"); got != 1 {
		t.Fatalf("a DESTROYING (no longer RUNNING) session must not be re-reaped; got %d total for s-1", got)
	}
}

// TestReaper_Attended_NeverDestroyed: a RUNNING session with a writer on the seat is never
// reaped, no matter how long it runs.
func TestReaper_Attended_NeverDestroyed(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC))
	lister := &fakeSessionLister{}
	dest := newRecordingDestroyer()
	reaper := newSessionIdleReaper(lister, dest, testIdleTTL, clk.Now, nil)
	ctx := context.Background()

	lister.set(withWriter(runningWriterlessSession("s-att", "host-a"), "alice"))

	for i := 0; i < 4; i++ {
		reaper.Sweep(ctx)
		clk.advance(testIdleTTL + time.Hour)
	}
	if got := dest.total(); got != 0 {
		t.Fatalf("an attended RUNNING session must never be reaped; got %d destroy calls", got)
	}
}

// TestReaper_RecentlyDetached_NotDestroyed_AndReattachResetsClock: a session writer-less for
// LESS than the TTL is not reaped (the conservative window); and a writer re-attaching RESETS
// the writer-less clock, so a subsequent detach gets a fresh full window.
func TestReaper_RecentlyDetached_NotDestroyed_AndReattachResetsClock(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC))
	lister := &fakeSessionLister{}
	dest := newRecordingDestroyer()
	reaper := newSessionIdleReaper(lister, dest, testIdleTTL, clk.Now, nil)
	ctx := context.Background()

	// Writer-less, first observed now.
	lister.set(runningWriterlessSession("s-2", "host-a"))
	reaper.Sweep(ctx) // stamp

	// Half the TTL later, still writer-less: not yet reaped.
	clk.advance(testIdleTTL / 2)
	reaper.Sweep(ctx)
	if got := dest.total(); got != 0 {
		t.Fatalf("writer-less for < TTL must not reap; got %d destroy calls", got)
	}

	// The writer RE-ATTACHES: the clock must reset on this attended observation.
	lister.set(withWriter(runningWriterlessSession("s-2", "host-a"), "bob"))
	reaper.Sweep(ctx)

	// Detach again. The clock starts FRESH here — so even though MORE than a TTL has elapsed
	// since the ORIGINAL writer-less observation, the session is not reaped until a fresh full
	// window passes from the re-detach.
	lister.set(runningWriterlessSession("s-2", "host-a"))
	reaper.Sweep(ctx) // fresh stamp
	clk.advance(testIdleTTL / 2)
	reaper.Sweep(ctx)
	if got := dest.total(); got != 0 {
		t.Fatalf("a re-attach must reset the writer-less clock; got %d destroy calls before a fresh full TTL", got)
	}

	// Now past the fresh window: reaped.
	clk.advance(testIdleTTL)
	reaper.Sweep(ctx)
	if got := dest.countFor("s-2"); got != 1 {
		t.Fatalf("writer-less past the fresh TTL window must reap once; got %d for s-2", got)
	}
}

// TestReaper_NonRunningStates_NeverTouched: a SUSPENDED / PARKED / SNAPSHOTTING / etc. session
// is never reaped — even writer-less and arbitrarily old. Only {READY, ATTACHED, WORKING} are
// reapable.
func TestReaper_NonRunningStates_NeverTouched(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC))
	lister := &fakeSessionLister{}
	dest := newRecordingDestroyer()
	reaper := newSessionIdleReaper(lister, dest, testIdleTTL, clk.Now, nil)
	ctx := context.Background()

	neverReaped := []store.SessionState{
		store.SessionPending,
		store.SessionCreating,
		store.SessionSnapshotting,
		store.SessionMigrating,
		store.SessionParked,
		store.SessionResuming,
		store.SessionDestroying,
	}
	base := runningWriterlessSession("s-x", "host-a")
	for _, st := range neverReaped {
		rec := withState(base, st)
		rec.Ref.SessionUUID = "s-" + string(st)
		lister.set(rec)
		reaper.Sweep(ctx)
		clk.advance(testIdleTTL * 3)
		reaper.Sweep(ctx)
	}

	// A SUSPENDED session with a reason set (the valid SUSPENDED shape), writer-less and old.
	susp := withState(runningWriterlessSession("s-susp", "host-a"), store.SessionSuspended)
	susp.SuspendReason = store.SuspendReasonUser
	lister.set(susp)
	reaper.Sweep(ctx)
	clk.advance(testIdleTTL * 3)
	reaper.Sweep(ctx)

	if got := dest.total(); got != 0 {
		t.Fatalf("no non-RUNNING state may ever be reaped; got %d destroy calls", got)
	}
}

// TestReaper_ReadyAndAttachedAreReapable: the other two RUNNING states (READY, ATTACHED), not
// just WORKING, are reaped when writer-less past the TTL.
func TestReaper_ReadyAndAttachedAreReapable(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC))
	lister := &fakeSessionLister{}
	dest := newRecordingDestroyer()
	reaper := newSessionIdleReaper(lister, dest, testIdleTTL, clk.Now, nil)
	ctx := context.Background()

	ready := withState(runningWriterlessSession("s-ready", "host-a"), store.SessionReady)
	attached := withState(runningWriterlessSession("s-attached", "host-b"), store.SessionAttached)
	lister.set(ready, attached)

	reaper.Sweep(ctx) // stamp both
	clk.advance(testIdleTTL + time.Minute)
	reaper.Sweep(ctx)

	if got := dest.countFor("s-ready"); got != 1 {
		t.Fatalf("a writer-less READY session past TTL must be reaped once; got %d", got)
	}
	if got := dest.countFor("s-attached"); got != 1 {
		t.Fatalf("a writer-less ATTACHED session past TTL must be reaped once; got %d", got)
	}
}

// TestReaper_DestroyFault_RetriedNextTick: a transient Destroy fault leaves the clock stamp so
// the next tick re-drives (level-triggered; Destroy idempotent on session_uuid).
func TestReaper_DestroyFault_RetriedNextTick(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC))
	lister := &fakeSessionLister{}
	dest := newRecordingDestroyer()
	dest.failUUIDs["s-flaky"] = context.DeadlineExceeded // a transient teardown fault
	reaper := newSessionIdleReaper(lister, dest, testIdleTTL, clk.Now, nil)
	ctx := context.Background()

	lister.set(runningWriterlessSession("s-flaky", "host-a"))
	reaper.Sweep(ctx) // stamp
	clk.advance(testIdleTTL + time.Minute)
	reaper.Sweep(ctx) // first reap attempt — faults
	if got := dest.countFor("s-flaky"); got != 1 {
		t.Fatalf("first over-TTL sweep must attempt the destroy once; got %d", got)
	}

	// The fault healed; the next tick re-drives (the stamp was retained).
	delete(dest.failUUIDs, "s-flaky")
	clk.advance(time.Minute)
	reaper.Sweep(ctx)
	if got := dest.countFor("s-flaky"); got != 2 {
		t.Fatalf("a transient destroy fault must be re-driven on the next tick; got %d total", got)
	}
}

// TestReaper_TTLZeroDisables: a TTL ≤ 0 yields a nil reaper (disabled), and a nil reaper's Run
// runs no sweep (it blocks until ctx is cancelled).
func TestReaper_TTLZeroDisables(t *testing.T) {
	lister := &fakeSessionLister{}
	dest := newRecordingDestroyer()

	if r := newSessionIdleReaper(lister, dest, 0, time.Now, nil); r != nil {
		t.Fatal("TTL=0 must disable the reaper (newSessionIdleReaper should return nil)")
	}
	if r := newSessionIdleReaper(lister, dest, -5*time.Minute, time.Now, nil); r != nil {
		t.Fatal("a negative TTL must disable the reaper (nil)")
	}

	// A nil reaper's Sweep is a no-op, and Run blocks until ctx done then returns ctx.Err().
	var nilReaper *sessionIdleReaper
	nilReaper.Sweep(context.Background()) // must not panic
	lister.set(runningWriterlessSession("s-z", "host-a"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- nilReaper.Run(ctx, time.Millisecond) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("nil reaper Run should return ctx.Err() on cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nil reaper Run did not return after ctx cancel")
	}
	if got := dest.total(); got != 0 {
		t.Fatalf("a disabled reaper must run no sweep; got %d destroy calls", got)
	}
}

// TestReaper_MisconstructionYieldsNil: a nil lister or destroyer (a misconstruction) yields a
// nil reaper rather than a half-wired one — it can never be started into the run loop.
func TestReaper_MisconstructionYieldsNil(t *testing.T) {
	dest := newRecordingDestroyer()
	if r := newSessionIdleReaper(nil, dest, testIdleTTL, time.Now, nil); r != nil {
		t.Fatal("a nil lister must yield a nil reaper")
	}
	if r := newSessionIdleReaper(&fakeSessionLister{}, nil, testIdleTTL, time.Now, nil); r != nil {
		t.Fatal("a nil destroyer must yield a nil reaper")
	}
}

// TestReaper_RunTicksAndStops: the Run ticker drives sweeps and stops cleanly on ctx cancel.
func TestReaper_RunTicksAndStops(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC))
	lister := &fakeSessionLister{}
	dest := newRecordingDestroyer()
	reaper := newSessionIdleReaper(lister, dest, testIdleTTL, clk.Now, nil)

	// Pre-stamp the session as writer-less PAST the TTL by stamping then advancing the clock,
	// so the first ticker-driven sweep that runs after the stamp reaps it.
	lister.set(runningWriterlessSession("s-tick", "host-a"))
	reaper.Sweep(context.Background()) // stamp
	clk.advance(testIdleTTL + time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reaper.Run(ctx, time.Millisecond) }()

	// Wait until the ticker has driven at least one reaping sweep.
	deadline := time.After(2 * time.Second)
	for dest.countFor("s-tick") == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("Run ticker did not drive a reaping sweep")
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run should return ctx.Err() on cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}
