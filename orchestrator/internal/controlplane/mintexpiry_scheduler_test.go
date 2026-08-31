package controlplane

// mintexpiry_scheduler_test.go exercises the production §4.1 step-5 minted-credential
// EXPIRY teardown/re-mint sink (mintExpiryScheduler, wiring.go; D22/D82, doc 16 §5.4)
// against the in-memory store + a synthetic mint, proving the three load-bearing
// contracts the task's acceptance calls out: the sink fires post-READY and RE-MINTS
// (reading the PERSISTED §5.6 MintExpiry horizon), is IDEMPOTENT across a post-step-5
// rollback (a destroyed session re-mints nothing — the destroy supersedes the
// registration, no leaked re-mint), and is NON-BLOCKING on the create hot path (a slow
// sink never slows OnMintExpiry). No live VM/host-agent/podman (D50).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// expiryMint is a synthetic MintClient that ALSO satisfies MintExpiryClient, so the
// scheduler's mintReply lifts a FRESH expiry off it on re-mint. Each Mint advances a
// counter and returns a horizon a fixed step past the injected clock's now, so a test can
// assert the re-mint landed a new, later horizon. A gate channel lets a test make the mint
// arbitrarily slow to prove the create hot path (OnMintExpiry) is non-blocking.
type expiryMint struct {
	mu    sync.Mutex
	calls int
	now   func() time.Time
	step  time.Duration
	block chan struct{} // when non-nil, MintWithExpiry waits on it (the slow-sink case)
	err   error
}

func (m *expiryMint) Mint(ctx context.Context, claims sessions.MintWorkloadIdentityClaims, roleRef string) (string, string, error) {
	r, err := m.MintWithExpiry(ctx, claims, roleRef)
	return r.IdentityRef, r.CARef, err
}

func (m *expiryMint) MintWithExpiry(_ context.Context, _ sessions.MintWorkloadIdentityClaims, _ string) (MintReply, error) {
	if m.block != nil {
		<-m.block
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return MintReply{}, m.err
	}
	return MintReply{IdentityRef: "id-remint", CARef: "ca-remint", Expiry: m.now().Add(m.step)}, nil
}

func (m *expiryMint) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

var _ MintExpiryClient = (*expiryMint)(nil)

// seedReadySession writes a READY record carrying a persisted MintExpiry horizon (the
// state the create coordinator leaves before firing OnMintExpiry).
func seedReadySession(t *testing.T, mem *store.Memory, uuid string, horizon time.Time) {
	t.Helper()
	ctx := context.Background()
	_, err := mem.CreateSession(ctx, store.Session{
		Ref:        store.SessionRef{SessionUUID: uuid, HostID: "host-a", HostSessionIndex: 1, TapName: "dstap-1"},
		State:      store.SessionReady,
		MintExpiry: horizon,
	})
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

// TestMintExpirySchedulerReMints proves a session that reaches its horizon re-mints: the
// timer fires, the scheduler reads the PERSISTED horizon, mints a fresh credential, and
// persists the new identity/CA + horizon onto the durable record (doc 16 §5.4).
func TestMintExpirySchedulerReMints(t *testing.T) {
	mem := store.NewMemory()
	now := time.Now
	mint := &expiryMint{now: now, step: time.Hour}
	sched := newMintExpiryScheduler(mem, mint, mem, now, nil)
	defer sched.Stop()

	const uuid = "sess-remint"
	seedReadySession(t, mem, uuid, now().Add(20*time.Millisecond))

	// Fire post-READY at the (near) horizon — the coordinator's once-per-create fire.
	sched.OnMintExpiry(uuid, now().Add(20*time.Millisecond))

	// The re-mint fires off the timer goroutine; poll the durable record for the fresh
	// identity ref the synthetic mint stamps.
	waitFor(t, time.Second, func() bool {
		rec, err := mem.GetSession(context.Background(), uuid)
		return err == nil && rec.IdentityRef == "id-remint"
	}, "re-mint to persist the fresh identity ref")

	if got := mint.callCount(); got < 1 {
		t.Fatalf("mint was never called on expiry: calls=%d", got)
	}
	rec, err := mem.GetSession(context.Background(), uuid)
	if err != nil {
		t.Fatalf("get after re-mint: %v", err)
	}
	if rec.CARef != "ca-remint" {
		t.Fatalf("re-minted CA ref not persisted: %q", rec.CARef)
	}
	if rec.MintExpiry.IsZero() || !rec.MintExpiry.After(now()) {
		t.Fatalf("fresh horizon not persisted/advanced: %v", rec.MintExpiry)
	}
}

// TestMintExpirySchedulerIdempotentAcrossRollback proves the destroy supersedes the
// registration: a session torn down (DESTROYED) before the timer fires re-mints NOTHING
// (no leaked re-mint for a session that no longer exists — the post-step-5 rollback
// idempotency contract).
func TestMintExpirySchedulerIdempotentAcrossRollback(t *testing.T) {
	mem := store.NewMemory()
	now := time.Now
	mint := &expiryMint{now: now, step: time.Hour}
	sched := newMintExpiryScheduler(mem, mint, mem, now, nil)
	defer sched.Stop()

	const uuid = "sess-rolledback"
	seedReadySession(t, mem, uuid, now().Add(10*time.Millisecond))
	sched.OnMintExpiry(uuid, now().Add(10*time.Millisecond))

	// Simulate the §4.2 destroy that supersedes the registration BEFORE the timer fires.
	destroyed := store.SessionDestroyed
	if _, err := mem.UpdateSession(context.Background(), uuid, store.SessionUpdate{State: &destroyed, DestroyedAt: store.SetTime(now())}); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	// Give the timer time to fire and observe the terminal record.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := mint.callCount(); got != 0 {
		t.Fatalf("re-mint fired for a destroyed session (leaked re-mint): calls=%d", got)
	}
	rec, err := mem.GetSession(context.Background(), uuid)
	if err != nil {
		t.Fatalf("get after drop: %v", err)
	}
	if rec.IdentityRef == "id-remint" {
		t.Fatalf("destroyed session was re-minted (identity churned): %q", rec.IdentityRef)
	}
}

// TestMintExpirySchedulerNonBlocking proves OnMintExpiry returns promptly even when the
// mint seam is arbitrarily slow — the create hot path's latency is unaffected by a
// slow/faulty sink (the re-mint runs later on the timer goroutine, never inline).
func TestMintExpirySchedulerNonBlocking(t *testing.T) {
	mem := store.NewMemory()
	now := time.Now
	block := make(chan struct{})
	mint := &expiryMint{now: now, step: time.Hour, block: block}
	sched := newMintExpiryScheduler(mem, mint, mem, now, nil)
	defer sched.Stop()
	defer close(block) // unblock any pending fire on teardown

	const uuid = "sess-slow"
	seedReadySession(t, mem, uuid, now().Add(time.Hour))

	start := time.Now()
	sched.OnMintExpiry(uuid, now().Add(time.Hour))
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("OnMintExpiry blocked on the slow sink (%v) — the create hot path must not block", elapsed)
	}
	if sched.armedCount() != 1 {
		t.Fatalf("expected exactly one armed timer, got %d", sched.armedCount())
	}
}

// TestMintExpirySchedulerSupersedeOnReArm proves re-arming the same UUID never leaves two
// pending timers (the no-leaked-timer contract): a second OnMintExpiry swaps the first.
func TestMintExpirySchedulerSupersedeOnReArm(t *testing.T) {
	mem := store.NewMemory()
	now := time.Now
	mint := &expiryMint{now: now, step: time.Hour}
	sched := newMintExpiryScheduler(mem, mint, mem, now, nil)
	defer sched.Stop()

	const uuid = "sess-rearm"
	seedReadySession(t, mem, uuid, now().Add(time.Hour))
	sched.OnMintExpiry(uuid, now().Add(time.Hour))
	sched.OnMintExpiry(uuid, now().Add(2*time.Hour))
	if got := sched.armedCount(); got != 1 {
		t.Fatalf("re-arm left more than one timer for the same UUID: %d", got)
	}
}

// TestMintExpirySchedulerZeroAndStop proves a zero horizon never arms (the coordinator's
// no-track guard mirrored here) and Stop makes the sink inert.
func TestMintExpirySchedulerZeroAndStop(t *testing.T) {
	mem := store.NewMemory()
	now := time.Now
	mint := &expiryMint{now: now, step: time.Hour}
	sched := newMintExpiryScheduler(mem, mint, mem, now, nil)

	sched.OnMintExpiry("sess-zero", time.Time{})
	if got := sched.armedCount(); got != 0 {
		t.Fatalf("zero horizon armed a timer: %d", got)
	}
	seedReadySession(t, mem, "sess-live", now().Add(time.Hour))
	sched.OnMintExpiry("sess-live", now().Add(time.Hour))
	if got := sched.armedCount(); got != 1 {
		t.Fatalf("live horizon failed to arm: %d", got)
	}
	sched.Stop()
	if got := sched.armedCount(); got != 0 {
		t.Fatalf("Stop did not clear armed timers: %d", got)
	}
	// After Stop the sink is inert — a late fire arms nothing.
	sched.OnMintExpiry("sess-live", now().Add(time.Hour))
	if got := sched.armedCount(); got != 0 {
		t.Fatalf("OnMintExpiry armed after Stop: %d", got)
	}
}

// TestNewControlPlaneWiresRealMintExpirySink proves the production wiring installs a real
// (non-nil) mintExpiryScheduler behind CreateSeams.OnMintExpiry — the leg is wired, not a
// no-op. It is the wiring counterpart to the unit tests above.
func TestNewControlPlaneWiresRealMintExpirySink(t *testing.T) {
	cp, err := NewControlPlane(depsWithStalenessBudget(t, 0))
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	if cp.MintExpiry == nil {
		t.Fatal("control plane wired a nil mint-expiry sink — the teardown/re-mint leg is not constructed")
	}
	// The sink satisfies the create coordinator's seam (compile + run-time proof).
	var _ sessions.MintExpirySink = cp.MintExpiry
	cp.MintExpiry.Stop()
}

// seedSessionState writes a record in the given §3 state carrying a persisted MintExpiry
// horizon — the boot re-arm sweep / mid-teardown-drop fixtures need a record in a
// non-READY state (DESTROYING) the seedReadySession helper cannot express. idx is the
// per-host session index (the store burns it uniquely per host, so a multi-session test
// must give each a distinct index).
func seedSessionState(t *testing.T, mem *store.Memory, uuid string, idx uint64, state store.SessionState, horizon time.Time) {
	t.Helper()
	_, err := mem.CreateSession(context.Background(), store.Session{
		Ref:        store.SessionRef{SessionUUID: uuid, HostID: "host-a", HostSessionIndex: idx, TapName: "dstap-" + uuid},
		State:      state,
		MintExpiry: horizon,
	})
	if err != nil {
		t.Fatalf("seed %s session %q: %v", state, uuid, err)
	}
}

// recordingRearmSink records every (uuid, horizon) the boot re-arm sweep arms, so a test can
// assert the sweep re-armed EXACTLY the live-with-horizon set (and nothing terminal or
// not-set). It satisfies mintExpiryRearmSink.
type recordingRearmSink struct {
	mu    sync.Mutex
	armed map[string]time.Time
}

func (r *recordingRearmSink) OnMintExpiry(uuid string, expiry time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.armed == nil {
		r.armed = make(map[string]time.Time)
	}
	r.armed[uuid] = expiry
}

func (r *recordingRearmSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.armed)
}

var _ mintExpiryRearmSink = (*recordingRearmSink)(nil)

// TestReArmMintExpirySweepArmsLiveWithHorizon proves the boot re-arm sweep (mintexpiry_rearm.go)
// re-arms EXACTLY the live (non-terminal) sessions that carry a non-zero persisted MintExpiry
// horizon: a DESTROYED record is omitted, a live record with NO horizon (zero MintExpiry) is
// skipped, and a DESTROYING record (still non-terminal) IS re-armed (fire()'s tightened drop is
// what protects it — not the sweep). It uses a recording sink so the assertion is on the set
// the sweep ARMS, independent of any timer firing.
func TestReArmMintExpirySweepArmsLiveWithHorizon(t *testing.T) {
	mem := store.NewMemory()
	now := time.Now()

	// Live + carries a horizon → re-armed.
	seedSessionState(t, mem, "live-with-horizon-1", 1, store.SessionReady, now.Add(time.Hour))
	seedSessionState(t, mem, "live-with-horizon-2", 2, store.SessionReady, now.Add(2*time.Hour))
	// Live, mid-teardown (DESTROYING), carries a horizon → still re-armed (non-terminal); the
	// fire() drop is the teardown guard, not the sweep.
	seedSessionState(t, mem, "destroying-with-horizon", 3, store.SessionDestroying, now.Add(time.Hour))
	// Live but NO horizon (zero MintExpiry) → skipped (the no-TTL posture).
	seedSessionState(t, mem, "live-no-horizon", 4, store.SessionReady, time.Time{})
	// Terminal (DESTROYED) → omitted by the IncludeDestroyed=false list.
	seedSessionState(t, mem, "destroyed-with-horizon", 5, store.SessionDestroyed, now.Add(time.Hour))

	sink := &recordingRearmSink{}
	got := reArmMintExpiry(context.Background(), mem, sink, nil)

	const wantLiveWithHorizon = 3 // the two READY + the DESTROYING, all carrying a horizon
	if got != wantLiveWithHorizon {
		t.Fatalf("reArmMintExpiry re-armed %d, want %d (live, non-terminal, non-zero horizon)", got, wantLiveWithHorizon)
	}
	if sink.count() != wantLiveWithHorizon {
		t.Fatalf("sink armed %d sessions, want %d", sink.count(), wantLiveWithHorizon)
	}
	for _, uuid := range []string{"live-with-horizon-1", "live-with-horizon-2", "destroying-with-horizon"} {
		if _, ok := sink.armed[uuid]; !ok {
			t.Fatalf("sweep did not re-arm live-with-horizon session %q", uuid)
		}
	}
	if _, ok := sink.armed["live-no-horizon"]; ok {
		t.Fatal("sweep re-armed a session with no persisted horizon (the no-TTL posture must be skipped)")
	}
	if _, ok := sink.armed["destroyed-with-horizon"]; ok {
		t.Fatal("sweep re-armed a DESTROYED (terminal) session — it must be omitted")
	}
}

// TestMintExpiryRestartRecoveryReMintsPastHorizon proves the durable record is the system of
// record across a restart (doc 16 §5.4): a session persisted with a PAST horizon, recovered by
// a FRESH scheduler (the restart — no in-process timers survived) + the boot re-arm sweep, is
// re-armed at delay=0 and re-mints PROMPTLY. armedCount() after the sweep matches the
// live-with-horizon count, and the past-horizon session re-mints (a fresh identity persisted).
func TestMintExpiryRestartRecoveryReMintsPastHorizon(t *testing.T) {
	mem := store.NewMemory()
	now := time.Now
	mint := &expiryMint{now: now, step: time.Hour}

	// Simulate the pre-restart durable state: one session whose horizon is already in the PAST
	// (the restart window elapsed past it) and one whose horizon is still in the future. Both
	// are live (READY) and carry a persisted horizon — both must re-arm.
	seedSessionState(t, mem, "past-horizon", 1, store.SessionReady, now().Add(-time.Minute))
	seedSessionState(t, mem, "future-horizon", 2, store.SessionReady, now().Add(time.Hour))
	// A terminal record must NOT count toward the armed set.
	seedSessionState(t, mem, "gone", 3, store.SessionDestroyed, now().Add(time.Hour))

	// THE RESTART: a brand-new scheduler with an EMPTY timer map (every pre-restart timer was
	// lost). The boot re-arm sweep rebuilds the timers from the durable records.
	sched := newMintExpiryScheduler(mem, mint, mem, now, nil)
	defer sched.Stop()

	const wantLiveWithHorizon = 2
	if got := reArmMintExpiry(context.Background(), mem, sched, nil); got != wantLiveWithHorizon {
		t.Fatalf("boot re-arm swept %d sessions, want %d (the live-with-horizon count)", got, wantLiveWithHorizon)
	}

	// The PAST horizon armed delay=0 → it fires promptly and re-mints. Poll the durable record
	// for the fresh identity ref the synthetic mint stamps.
	waitFor(t, time.Second, func() bool {
		rec, err := mem.GetSession(context.Background(), "past-horizon")
		return err == nil && rec.IdentityRef == "id-remint"
	}, "the past-horizon session to re-mint after a simulated restart + boot re-arm")

	if got := mint.callCount(); got < 1 {
		t.Fatalf("re-mint never fired for the past-horizon session after restart: calls=%d", got)
	}
	rec, err := mem.GetSession(context.Background(), "past-horizon")
	if err != nil {
		t.Fatalf("get past-horizon after re-mint: %v", err)
	}
	if rec.MintExpiry.IsZero() || !rec.MintExpiry.After(now()) {
		t.Fatalf("past-horizon fresh horizon not persisted/advanced after restart: %v", rec.MintExpiry)
	}

	// The FUTURE-horizon session was re-armed but must NOT have re-minted (its timer is still
	// pending far out); only the past-horizon credential churns.
	fut, err := mem.GetSession(context.Background(), "future-horizon")
	if err != nil {
		t.Fatalf("get future-horizon: %v", err)
	}
	if fut.IdentityRef == "id-remint" {
		t.Fatal("future-horizon session re-minted prematurely after restart (its timer should still be pending)")
	}
}

// TestMintExpiryFireDropsDestroyingSession proves the tightened idempotent drop (wiring.go
// fire()): a session in the DESTROYING (mid-teardown) state when the timer fires re-mints
// NOTHING — no identity churn and no UpdateSession during teardown. It mirrors the
// DESTROYED-rollback test but for the mid-teardown state the wave widens the drop to cover.
func TestMintExpiryFireDropsDestroyingSession(t *testing.T) {
	mem := store.NewMemory()
	now := time.Now
	mint := &expiryMint{now: now, step: time.Hour}
	sched := newMintExpiryScheduler(mem, mint, mem, now, nil)
	defer sched.Stop()

	const uuid = "sess-destroying"
	// Seed a READY session, arm its timer, THEN move it to DESTROYING before the timer fires
	// (the teardown choreography is in flight while a re-mint timer is pending).
	seedReadySession(t, mem, uuid, now().Add(10*time.Millisecond))
	sched.OnMintExpiry(uuid, now().Add(10*time.Millisecond))

	destroying := store.SessionDestroying
	if _, err := mem.UpdateSession(context.Background(), uuid, store.SessionUpdate{State: &destroying}); err != nil {
		t.Fatalf("transition to DESTROYING: %v", err)
	}

	// Record the identity ref the teardown transition left, so we can prove the fire did NOT
	// overwrite it with a re-mint.
	before, err := mem.GetSession(context.Background(), uuid)
	if err != nil {
		t.Fatalf("get before fire: %v", err)
	}

	// Give the timer time to fire and observe the DESTROYING record.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if got := mint.callCount(); got != 0 {
		t.Fatalf("re-mint fired for a DESTROYING session (identity churned mid-teardown): calls=%d", got)
	}
	after, err := mem.GetSession(context.Background(), uuid)
	if err != nil {
		t.Fatalf("get after fire: %v", err)
	}
	if after.IdentityRef == "id-remint" {
		t.Fatalf("DESTROYING session was re-minted (identity churned): %q", after.IdentityRef)
	}
	if after.IdentityRef != before.IdentityRef || after.CARef != before.CARef {
		t.Fatalf("DESTROYING session record mutated by the re-mint path (no UpdateSession expected): before=%q/%q after=%q/%q",
			before.IdentityRef, before.CARef, after.IdentityRef, after.CARef)
	}
	if after.State != store.SessionDestroying {
		t.Fatalf("DESTROYING session state changed by the dropped re-mint: %q", after.State)
	}
}

// waitFor polls cond until it returns true or the deadline elapses.
func waitFor(t *testing.T, within time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", within, what)
}
