package controlplane

// reconcileloop_test.go drives the reconciler loop (leg b): the loop Observes a synthetic
// hostagent.v1.Heartbeat and, for a host-resident record whose VM is MISSING from the
// observed set (§3 rule b), re-drives it through the WIRED ConcreteRedriver — which routes
// the re-assert through the SAME create spine the CreateSession RPC runs
// (RedriveSpine → RunCreateSpine) and re-creates host-side through the SAME ten-step
// coordinator (the SpineContinuationFunc). All inputs are synthetic; no live
// VM/host-agent/podman (D50).

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/parkstore"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestReconcileLoop_RedrivesMissingVM proves the §3 rule-b re-drive runs through the
// wired Redriver to RunCreateSpine + the coordinator. It first CREATES a session (so the
// record is ATTACHED, bound to the host, and its launching principal is linked — the
// re-drive's premise), then Observes a heartbeat from that host whose observed set is
// EMPTY (the VM is gone). The loop must re-drive: the SpineRunner re-asserts the spine
// (re-mint), and the continuation re-creates host-side (another CloneFromImage).
func TestReconcileLoop_RedrivesMissingVM(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()

	// (1) Create a session — it reaches ATTACHED, bound to testHostID, principal linked.
	resp, err := f.cp.Sessions.CreateSession(ctx, validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sessionUUID := resp.GetSession().GetSessionUuid()

	clonesAfterCreate := len(f.drv.CloneFromImageRecorded())
	mintsAfterCreate := f.mint.calls
	if clonesAfterCreate != 1 || mintsAfterCreate != 1 {
		t.Fatalf("post-create: clones=%d mints=%d, want 1 each", clonesAfterCreate, mintsAfterCreate)
	}

	// (2) Observe a heartbeat from the host whose observed set is EMPTY — the record is
	// ATTACHED (expects a host VM) but no VM is observed → §3 rule b re-drive.
	hb := heartbeatWithObserved(testHostID, 0 /* no observed sessions */)
	if err := f.cp.Reconcile.observeNow(ctx, hb); err != nil {
		t.Fatalf("reconcile Observe: %v", err)
	}

	// The wired Redriver re-asserted desired state through the SAME create spine: the
	// SpineRunner re-ran RedriveSpine (re-mint) AND the continuation re-created host-side
	// (another CloneFromImage). Both counts advanced past the create's.
	if got := f.mint.calls; got <= mintsAfterCreate {
		t.Errorf("re-drive did not re-assert the spine: mint calls = %d, want > %d", got, mintsAfterCreate)
	}
	if got := len(f.drv.CloneFromImageRecorded()); got <= clonesAfterCreate {
		t.Errorf("re-drive did not re-create host-side: clone calls = %d, want > %d", got, clonesAfterCreate)
	}

	// The record is NOT failed-to-DESTROYED — the re-drive succeeded, so the record stays
	// in its desired (ATTACHED) state for the next observed cycle to confirm.
	rec, gerr := f.st.GetSession(ctx, sessionUUID)
	if gerr != nil {
		t.Fatalf("GetSession: %v", gerr)
	}
	if rec.State == store.SessionDestroyed {
		t.Errorf("record failed to DESTROYED despite a successful re-drive; state = %q", rec.State)
	}
}

// TestReconcileLoop_QuarantinesOrphanVM proves §3 rule a: an observed VM with NO record
// is quarantined (Suspend, POLICY_BREACH), never auto-destroyed. The loop Observes a
// heartbeat carrying an orphan observed session; the fleet Driver broadcasts the Suspend
// to the host's driver.
func TestReconcileLoop_QuarantinesOrphanVM(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()

	// A heartbeat observing a session that has NO record (an orphan VM).
	orphan := &hypervisorv1.ObservedSession{
		SessionUuid: "orphan-sess-1",
		DomainUuid:  "dom-orphan-1",
	}
	hb := heartbeatWithObserved(testHostID, 0, orphan)
	if err := f.cp.Reconcile.observeNow(ctx, hb); err != nil {
		t.Fatalf("reconcile Observe: %v", err)
	}

	// The orphan was quarantined via Suspend (never Destroyed — §3 rule a).
	suspends := f.drv.SuspendRecorded()
	if len(suspends) != 1 {
		t.Fatalf("orphan quarantine Suspend calls = %d, want 1", len(suspends))
	}
	if suspends[0].Req.GetReason() != hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH {
		t.Errorf("quarantine reason = %v, want POLICY_BREACH", suspends[0].Req.GetReason())
	}
	if got := suspends[0].Req.GetSessionUuid(); got != "orphan-sess-1" {
		t.Errorf("quarantined session = %q, want orphan-sess-1", got)
	}
	// NEVER auto-destroyed.
	if len(f.drv.DestroyRecorded()) != 0 {
		t.Errorf("orphan was auto-destroyed (forbidden, §3 rule a): destroy calls = %d", len(f.drv.DestroyRecorded()))
	}
}

// TestReconcileLoop_RunDrivesObserveAndResync proves the driving goroutine (Run)
// serializes Observe (per heartbeat submitted via the channel) and Resync (per ticker)
// onto one goroutine. It submits a heartbeat via Observe, then cancels — asserting Run
// returns the context error cleanly and the feed recorded the heartbeat (the scheduler's
// candidate input).
func TestReconcileLoop_RunDrivesObserveAndResync(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx, cancel := context.WithCancel(context.Background())

	// Submit a heartbeat through the public Observe (records the feed + submits to Run).
	hb := freshHeartbeat(testHostID, 0, 2)
	if err := f.cp.Reconcile.Observe(ctx, hb); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	// The feed recorded it (placement candidate input).
	snaps, _ := f.cp.Heartbeats.LatestSnapshots(ctx, "any")
	if len(snaps) != 1 || snaps[0].HostID != testHostID {
		t.Fatalf("feed snapshots = %+v, want one for %s", snaps, testHostID)
	}

	// Run drains the inbound channel on its goroutine; cancel and assert a clean return.
	done := make(chan error, 1)
	go func() { done <- f.cp.Reconcile.Run(ctx) }()
	cancel()
	if err := <-done; err == nil {
		t.Fatal("Run returned nil on cancellation, want the context error")
	}
}

// TestReconcileLoop_HealthSnapshot_RaceCleanWhileRunDrives is the capstone race test: it
// proves the LOOP-SERIALIZED HealthSnapshot() seam reads the reconciler's lastBeat WITHOUT
// racing the reconcile loop's concurrent Observe/Resync writes. While Run drives the loop
// on its own goroutine — fed a stream of Observe submissions (the lastBeat writer) from a
// second goroutine and the periodic resync — a third goroutine hammers HealthSnapshot()
// through the loop-marshalled query channel. Under `go test -race` the read marshals onto
// Run's goroutine (the sole lastBeat owner), so there is no data race, no second writer, and
// no bare cross-goroutine read of lastBeat. (D50: synthetic heartbeats, a cancellable
// context, no live VM/host-agent/podman.)
func TestReconcileLoop_HealthSnapshot_RaceCleanWhileRunDrives(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx, cancel := context.WithCancel(context.Background())

	loop := f.cp.Reconcile
	runDone := make(chan error, 1)
	go func() { runDone <- loop.Run(ctx) }()

	var wg sync.WaitGroup

	// Writer goroutine: a burst of Observe submissions — each records the feed and submits
	// onto the loop's inbound channel, so Run's goroutine writes lastBeat repeatedly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = loop.Observe(ctx, freshHeartbeat(testHostID, 0, 1))
		}
	}()

	// Reader goroutine: hammer the loop-serialized HealthSnapshot() concurrently. The read
	// is marshalled onto Run's goroutine, so under -race it never races the Observe writes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = loop.HealthSnapshot(ctx)
		}
	}()

	wg.Wait()

	// A final loop-serialized snapshot must report the host the writer fed (recorded inside
	// the fixed-clock silence window → LIVE), proving the seam reads the SAME lastBeat the
	// loop writes — not a stale or empty view.
	snap := loop.HealthSnapshot(ctx)
	if !hasHost(snap, testHostID) {
		t.Fatalf("HealthSnapshot did not report the observed host %q; snap=%+v", testHostID, snap)
	}

	// Clean shutdown: cancel and assert Run returns the context error and a post-stop query
	// returns promptly (a nil view) rather than deadlocking on the reply channel.
	cancel()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil on cancellation, want the context error")
	}
	if snap := loop.HealthSnapshot(context.Background()); snap != nil {
		t.Errorf("HealthSnapshot after loop stop = %+v, want nil (no deadlock, prompt empty)", snap)
	}
}

// hasHost reports whether the loop-serialized snapshot carries an entry for hostID.
func hasHost(snap []reconciler.HostHealth, hostID string) bool {
	_, ok := findHost(snap, hostID)
	return ok
}

// findHost returns the snapshot entry for hostID (and whether it was present).
func findHost(snap []reconciler.HostHealth, hostID string) (reconciler.HostHealth, bool) {
	for _, h := range snap {
		if h.HostID == hostID {
			return h, true
		}
	}
	return reconciler.HostHealth{}, false
}

// TestReconcileLoop_HealthSnapshotIncluding_SurfacesExpectedSilentHost proves the OPT-IN
// loop-serialized variant routes reconciler.HealthSnapshotIncluding(expected) through the SAME
// healthReq channel onto Run's goroutine: an EXPECTED host the loop has NEVER heard from
// renders EverSeen=false / UNKNOWN rather than being ABSENT, while a heard-from host still
// renders LIVE, AND the bare HealthSnapshot() path is unchanged (omits the never-seen host).
// The read marshals onto Run's goroutine while Run drives Observe, so it is race-clean under
// `go test -race`. (D50: synthetic heartbeats, a cancellable context, no live
// VM/host-agent/podman.)
func TestReconcileLoop_HealthSnapshotIncluding_SurfacesExpectedSilentHost(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loop := f.cp.Reconcile
	runDone := make(chan error, 1)
	go func() { runDone <- loop.Run(ctx) }()

	// Heard-from host: a single Observe submission records lastBeat at the fixed clock, so it
	// is within the silence window → LIVE.
	if err := loop.Observe(ctx, freshHeartbeat(testHostID, 0, 1)); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	const expectedSilent = "host-expected-silent"

	// Drain the Observe so the heard-from host is in lastBeat before we query (a bare
	// loop-serialized snapshot that already reports it proves the submit was drained — the
	// query marshals behind the Observe on the same goroutine).
	for {
		bare := loop.HealthSnapshot(ctx)
		if hasHost(bare, testHostID) {
			// The bare heard-from path must NOT carry the never-seen expected host.
			if hasHost(bare, expectedSilent) {
				t.Fatalf("bare HealthSnapshot leaked never-seen expected host %q; snap=%+v", expectedSilent, bare)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("ctx cancelled before the Observe drained")
		default:
		}
	}

	// The OPT-IN variant folds in the expected set: the heard-from host stays LIVE, the
	// expected-but-never-heard-from host appears as a zero-LastBeat EverSeen=false UNKNOWN row.
	snap := loop.HealthSnapshotIncluding(ctx, []string{expectedSilent})

	live, ok := findHost(snap, testHostID)
	if !ok {
		t.Fatalf("HealthSnapshotIncluding dropped the heard-from host %q; snap=%+v", testHostID, snap)
	}
	if live.Liveness != reconciler.HostLive || !live.EverSeen {
		t.Errorf("heard-from host = %+v, want LIVE / EverSeen=true", live)
	}

	silent, ok := findHost(snap, expectedSilent)
	if !ok {
		t.Fatalf("HealthSnapshotIncluding did not surface the expected-but-silent host %q; snap=%+v", expectedSilent, snap)
	}
	if silent.Liveness != reconciler.HostUnknown {
		t.Errorf("expected-but-silent host liveness = %q, want UNKNOWN", silent.Liveness)
	}
	if silent.EverSeen {
		t.Errorf("expected-but-silent host EverSeen = true, want false (never heard from)")
	}
	if !silent.LastBeat.IsZero() || silent.SinceLastBeat != 0 {
		t.Errorf("expected-but-silent host carried a non-zero beat: LastBeat=%v Since=%v, want zero", silent.LastBeat, silent.SinceLastBeat)
	}

	// A nil expected set makes the variant identical to the bare heard-from snapshot — the
	// never-seen host is gone again.
	if got := loop.HealthSnapshotIncluding(ctx, nil); hasHost(got, expectedSilent) {
		t.Errorf("HealthSnapshotIncluding(nil) leaked the never-seen host %q; snap=%+v", expectedSilent, got)
	}

	cancel()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil on cancellation, want the context error")
	}
}

// TestReconcileLoop_HealthSnapshotIncluding_RaceCleanWhileRunDrives proves the OPT-IN
// expected-host variant honors the lastBeat single-goroutine contract under contention: while
// Run drives the loop, a writer goroutine streams Observe submissions (the lastBeat writer) and
// a reader goroutine hammers HealthSnapshotIncluding(expected) through the loop-marshalled query
// channel. Under `go test -race` the read marshals onto Run's goroutine (the sole lastBeat
// owner), so there is no data race and no bare cross-goroutine read — exactly as the bare
// HealthSnapshot race test, now with the expected set threaded through.
func TestReconcileLoop_HealthSnapshotIncluding_RaceCleanWhileRunDrives(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx, cancel := context.WithCancel(context.Background())

	loop := f.cp.Reconcile
	runDone := make(chan error, 1)
	go func() { runDone <- loop.Run(ctx) }()

	expected := []string{"host-expected-silent", testHostID}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = loop.Observe(ctx, freshHeartbeat(testHostID, 0, 1))
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = loop.HealthSnapshotIncluding(ctx, expected)
		}
	}()
	wg.Wait()

	// A final variant snapshot reports the heard-from host (LIVE) AND the expected-but-silent
	// host (UNKNOWN) — proving the seam reads the live lastBeat and folds in the expected set.
	snap := loop.HealthSnapshotIncluding(ctx, expected)
	if !hasHost(snap, testHostID) {
		t.Fatalf("HealthSnapshotIncluding did not report the observed host %q; snap=%+v", testHostID, snap)
	}
	if silent, ok := findHost(snap, "host-expected-silent"); !ok || silent.Liveness != reconciler.HostUnknown || silent.EverSeen {
		t.Fatalf("expected-but-silent host = %+v ok=%v, want UNKNOWN / EverSeen=false", silent, ok)
	}

	cancel()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil on cancellation, want the context error")
	}
	// Post-stop the variant returns promptly (nil), same bounded discipline as HealthSnapshot.
	if snap := loop.HealthSnapshotIncluding(context.Background(), expected); snap != nil {
		t.Errorf("HealthSnapshotIncluding after loop stop = %+v, want nil (no deadlock)", snap)
	}
}

// TestReconcileLoop_HealthSnapshotIncluding_CtxCancelDoesNotBlock proves the OPT-IN variant
// shares HealthSnapshot's bail-out discipline: with the loop NOT running (nothing drains the
// query channel), a HealthSnapshotIncluding whose ctx is already cancelled returns promptly
// (a nil view) rather than blocking forever.
func TestReconcileLoop_HealthSnapshotIncluding_CtxCancelDoesNotBlock(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	loop := f.cp.Reconcile

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan []reconciler.HostHealth, 1)
	go func() { done <- loop.HealthSnapshotIncluding(ctx, []string{"host-expected-silent"}) }()
	select {
	case snap := <-done:
		if snap != nil {
			t.Errorf("HealthSnapshotIncluding(cancelled ctx) = %+v, want nil", snap)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HealthSnapshotIncluding(cancelled ctx) blocked; the query must be ctx-bounded")
	}
}

// TestLivenessSnapshotterIncluding_SuppliesExpectedSet proves the serve.go LivenessSnapshotter
// path supplies the expected set so the admin readout renders an expected-but-silent host
// UNKNOWN rather than absent — and the BARE LivenessSnapshotter stays heard-from-only. The
// supplier is evaluated per HealthSnapshot() call (the deferred wiring point; here a synthetic
// closure, no store dependency on the loop). Run drives the loop so the read is loop-serialized.
func TestLivenessSnapshotterIncluding_SuppliesExpectedSet(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loop := f.cp.Reconcile
	runDone := make(chan error, 1)
	go func() { runDone <- loop.Run(ctx) }()

	if err := loop.Observe(ctx, freshHeartbeat(testHostID, 0, 1)); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	// Drain the Observe via the bare adapter before asserting.
	bare := f.cp.LivenessSnapshotter(ctx)
	for !hasHost(bare.HealthSnapshot(), testHostID) {
		select {
		case <-ctx.Done():
			t.Fatal("ctx cancelled before the Observe drained")
		default:
		}
	}

	const expectedSilent = "host-expected-silent"

	// The bare LivenessSnapshotter (no supplier) is heard-from-only: the never-seen host is
	// absent.
	if hasHost(bare.HealthSnapshot(), expectedSilent) {
		t.Fatalf("bare LivenessSnapshotter leaked never-seen host %q", expectedSilent)
	}

	// The Including path supplies the expected set: the never-seen host surfaces as UNKNOWN.
	supplied := f.cp.LivenessSnapshotterIncluding(ctx, func() []string { return []string{expectedSilent} })
	view := supplied.HealthSnapshot()
	if !hasHost(view, testHostID) {
		t.Errorf("supplied snapshotter dropped the heard-from host %q; view=%+v", testHostID, view)
	}
	silent, ok := findHost(view, expectedSilent)
	if !ok {
		t.Fatalf("supplied snapshotter did not surface expected-but-silent host %q; view=%+v", expectedSilent, view)
	}
	if silent.Liveness != reconciler.HostUnknown || silent.EverSeen {
		t.Errorf("expected-but-silent host = %+v, want UNKNOWN / EverSeen=false", silent)
	}

	// A nil supplier degrades to the heard-from-only view (identical to the bare path).
	if got := f.cp.LivenessSnapshotterIncluding(ctx, nil).HealthSnapshot(); hasHost(got, expectedSilent) {
		t.Errorf("LivenessSnapshotterIncluding(nil supplier) leaked never-seen host %q; view=%+v", expectedSilent, got)
	}

	// nil-safe: a nil ControlPlane yields an empty view.
	if got := (*ControlPlane)(nil).LivenessSnapshotterIncluding(ctx, func() []string { return []string{expectedSilent} }).HealthSnapshot(); len(got) != 0 {
		t.Errorf("nil ControlPlane LivenessSnapshotterIncluding = %+v, want empty", got)
	}

	cancel()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil on cancellation, want the context error")
	}
}

// TestReconcileLoop_ResolveParkAnswer_DrivesParkMachineResume proves the ask-resume call-site
// (park-resume-wire): a HUMAN PARK-ANSWER handed to the loop's ResolveParkAnswer is driven into
// the WIRED ask-a-human park machine's Resume, ending the session's untimed park on the human
// verdict (never a timeout into allow or kill — D46/D77). It parks a genuine rung-2 ask in a
// durable-backed park machine, installs that SAME machine on a loop, then resolves a human ALLOW
// answer through the loop's call-site — asserting the resumed Parked carries the verdict, the
// running machine drained, and the durable join cleared. Without the Resume wiring (the call-site
// not driving machine.Resume) the park would still be tracked and this FAILS. (D50: synthetic
// ask + in-process backing, no live VM/host-agent/podman.)
func TestReconcileLoop_ResolveParkAnswer_DrivesParkMachineResume(t *testing.T) {
	parkedAt := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)

	backing := parkstore.NewMemory()
	machine := newParkMachine(backing)
	if _, err := machine.Park("sess-answer", rung2Ask(), parkedAt); err != nil {
		t.Fatalf("seed park: %v", err)
	}
	if machine.Len() != 1 {
		t.Fatalf("the park machine must track the outstanding park, len=%d", machine.Len())
	}

	// A loop with the SAME park machine installed on its ask-resume leg. The loop needs no
	// reconciler/feed for this call-site (it touches no lastBeat state).
	loop := newReconcileLoop(nil, nil, 0, nil)
	loop.installAskResume(machine)

	answer := ParkAnswer{
		SessionUUID: "sess-answer",
		Verdict:     askhold.ResumeVerdictAllow,
		Scope:       "allow-once:service/bulk-delete;ttl=session",
		Now:         parkedAt.Add(90 * time.Minute),
	}
	resumed, err := loop.ResolveParkAnswer(answer)
	if err != nil {
		t.Fatalf("ResolveParkAnswer: %v", err)
	}
	if resumed.Phase != askhold.ParkPhaseResumed || resumed.Verdict != askhold.ResumeVerdictAllow {
		t.Fatalf("the call-site must resume on the human ALLOW answer; phase=%v verdict=%v", resumed.Phase, resumed.Verdict)
	}
	if resumed.SessionUUID != "sess-answer" {
		t.Errorf("resumed park = %q, want sess-answer", resumed.SessionUUID)
	}
	if machine.Len() != 0 {
		t.Fatalf("a resolved answer must drain the running machine, len=%d", machine.Len())
	}
	if _, ok := machine.Lookup("sess-answer"); ok {
		t.Errorf("a resolved park must be absent from the running machine")
	}
	// The durable join cleared too (ClearParked was driven through the backing) — so a restart
	// re-adopts nothing for this session.
	if durable, derr := backing.List(); derr != nil {
		t.Fatalf("backing List: %v", derr)
	} else if len(durable) != 0 {
		t.Fatalf("a resolved answer must clear the durable join, got %+v", durable)
	}
}

// TestReconcileLoop_ResolveParkAnswer_DenyArm proves the DENY arm of the ask-resume call-site:
// a human DENY answer carrying the D77 machine-readable reason resumes the park (never a
// timeout), and the running machine drains.
func TestReconcileLoop_ResolveParkAnswer_DenyArm(t *testing.T) {
	parkedAt := time.Date(2026, 6, 16, 11, 0, 0, 0, time.UTC)
	machine := newParkMachine(parkstore.NewMemory())
	if _, err := machine.Park("sess-deny-answer", rung2Ask(), parkedAt); err != nil {
		t.Fatalf("seed park: %v", err)
	}

	loop := newReconcileLoop(nil, nil, 0, nil)
	loop.installAskResume(machine)

	reason := askhold.DenyReason{Code: askhold.DenyUnattended, MatchedRuleID: "rule-suspend", ResourceKind: "service", ResourceName: "bulk-delete"}
	resumed, err := loop.ResolveParkAnswer(ParkAnswer{
		SessionUUID: "sess-deny-answer",
		Verdict:     askhold.ResumeVerdictDeny,
		Reason:      reason,
		Now:         parkedAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("ResolveParkAnswer(deny): %v", err)
	}
	if resumed.Verdict != askhold.ResumeVerdictDeny || resumed.DenyReason.Code != askhold.DenyUnattended {
		t.Fatalf("the call-site must carry the human DENY answer + reason; %+v", resumed)
	}
	if machine.Len() != 0 {
		t.Fatalf("a denied answer must drain the running machine, len=%d", machine.Len())
	}
}

// TestReconcileLoop_ResolveParkAnswer_NotWiredRefused proves the gate-off posture: a loop with
// NO ask-resume park machine installed refuses a human answer with errAskResumeNotWired rather
// than silently dropping it — a mis-wired build surfaces the missing wiring loudly.
func TestReconcileLoop_ResolveParkAnswer_NotWiredRefused(t *testing.T) {
	loop := newReconcileLoop(nil, nil, 0, nil)
	_, err := loop.ResolveParkAnswer(ParkAnswer{SessionUUID: "sess-x", Verdict: askhold.ResumeVerdictAllow, Now: time.Now()})
	if !errors.Is(err, errAskResumeNotWired) {
		t.Fatalf("an un-wired ask-resume call-site must refuse with errAskResumeNotWired, got %v", err)
	}
}

// TestReconcileLoop_ResolveParkAnswer_UnknownSessionRefused proves the call-site surfaces the
// park machine's own guard: a human answer for a session not currently parked (a double-answer
// / never-parked session) is refused with errNotParkedInMachine — there is no park to resolve.
func TestReconcileLoop_ResolveParkAnswer_UnknownSessionRefused(t *testing.T) {
	loop := newReconcileLoop(nil, nil, 0, nil)
	loop.installAskResume(newParkMachine(parkstore.NewMemory()))
	_, err := loop.ResolveParkAnswer(ParkAnswer{SessionUUID: "ghost", Verdict: askhold.ResumeVerdictAllow, Now: time.Now()})
	if !errors.Is(err, errNotParkedInMachine) {
		t.Fatalf("an answer for an unparked session must be refused with errNotParkedInMachine, got %v", err)
	}
}

// TestReconcileLoop_HealthSnapshot_CtxCancelDoesNotBlock proves the query is bounded: with
// the loop NOT running (Run never started, so nothing drains the query channel), a
// HealthSnapshot() whose ctx is already cancelled returns promptly (a nil view) rather than
// blocking forever on a reply that will never come.
func TestReconcileLoop_HealthSnapshot_CtxCancelDoesNotBlock(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	loop := f.cp.Reconcile

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE the query so the submit/await selects take the ctx.Done arm.

	done := make(chan []reconciler.HostHealth, 1)
	go func() { done <- loop.HealthSnapshot(ctx) }()
	select {
	case snap := <-done:
		if snap != nil {
			t.Errorf("HealthSnapshot(cancelled ctx) = %+v, want nil", snap)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HealthSnapshot(cancelled ctx) blocked; the query must be ctx-bounded")
	}
}
