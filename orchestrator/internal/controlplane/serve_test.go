package controlplane

// serve_test.go drives legs (b) + (c) over an in-memory bufconn gRPC server (D50: NO
// live socket / port bind / live host-agent):
//
//   (b) Register puts the orchestrator.v1 SessionService AND the hostagent.v1 heartbeat
//       ingest on the server; a CreateSession over the WIRE (a real gRPC client dialing
//       the bufconn) drives the §4.1 spine to ATTACHED — registration + the transport
//       round-trip, not just an in-process handler call.
//
//   (c) a ReportHeartbeat client-stream (the host-agent face) over the wire routes each
//       inbound Heartbeat through the reconcile loop's Observe: the HeartbeatStore feed
//       is updated (the scheduler's candidate input) AND the reconciler Observed it (the
//       reconcile submit), with the stream's close-path response carried back.
//
// Serve's full lifecycle (graceful stop on ctx cancel) is covered by serving over a
// bufconn listener and cancelling — the server drains and Serve returns nil.

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// dialBufconn dials an in-memory bufconn listener over a real gRPC client (the
// context-dialer + insecure transport) — the no-socket transport the serve tests drive
// the control plane through (D50). The connection is closed on cleanup.
func dialBufconn(t *testing.T, lis *bufconn.Listener) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestRegister_CreateSessionOverWireDrivesSpine proves leg (b): the SessionService is
// registered on the server and a CreateSession over the WIRE (a real gRPC client) drives
// the §4.1 spine to ATTACHED. This is the registration + transport assertion the task
// pins: not an in-process handler call, a round-trip over the bufconn.
func TestRegister_CreateSessionOverWireDrivesSpine(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	f.cp.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	client := orchestratorv1.NewSessionServiceClient(dialBufconn(t, lis))
	resp, err := client.CreateSession(ctx, validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession over the wire: %v", err)
	}
	sess := resp.GetSession()
	if sess.GetState().GetName() != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Fatalf("over-the-wire create state = %v, want ATTACHED", sess.GetState().GetName())
	}
	if sess.GetHostId() != testHostID {
		t.Errorf("over-the-wire create host_id = %q, want %q", sess.GetHostId(), testHostID)
	}
	// The spine ran end to end through the registered handler: the host driver was driven.
	if len(f.drv.CloneFromImageRecorded()) != 1 {
		t.Errorf("CloneFromImage calls = %d, want 1 (the wired handler drove the spine)", len(f.drv.CloneFromImageRecorded()))
	}
}

// TestHeartbeatIngest_OverWireReachesFeedAndObserve proves leg (c): a ReportHeartbeat
// client-stream (the host-agent face) over the WIRE routes each inbound Heartbeat through
// the reconcile loop's Observe — the HeartbeatStore feed is updated (the scheduler's
// candidate input) AND the reconciler Observed it. The stream's close-path response
// carries the beats-received count back.
func TestHeartbeatIngest_OverWireReachesFeedAndObserve(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	f.cp.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	client := hostagentv1.NewHostAgentServiceClient(dialBufconn(t, lis))
	stream, err := client.ReportHeartbeat(ctx)
	if err != nil {
		t.Fatalf("open ReportHeartbeat stream: %v", err)
	}

	// Emit two synthetic frames for the placement host, then close the stream.
	hb := freshHeartbeat(testHostID, 0, 3)
	if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{Heartbeat: hb}); err != nil {
		t.Fatalf("Send heartbeat frame 1: %v", err)
	}
	if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{Heartbeat: freshHeartbeat(testHostID, 0, 4)}); err != nil {
		t.Fatalf("Send heartbeat frame 2: %v", err)
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}
	if resp.GetBeatsReceived() != 2 {
		t.Errorf("close-path beats_received = %d, want 2", resp.GetBeatsReceived())
	}

	// The feed recorded the host's latest snapshot (the scheduler's placement candidate
	// input) — Observe records the feed before submitting the reconcile.
	snaps, _ := f.cp.Heartbeats.LatestSnapshots(ctx, "any")
	if len(snaps) != 1 || snaps[0].HostID != testHostID {
		t.Fatalf("feed snapshots after ingest = %+v, want one for %s", snaps, testHostID)
	}
}

// TestHeartbeatIngest_MalformedFrameSkipped proves a frame with a nil/empty heartbeat is
// counted but never routed (no feed write, no reconcile submit) — a malformed feed entry
// is never a placement target / convergence input, defense in depth with Observe's own
// nil-drop.
func TestHeartbeatIngest_MalformedFrameSkipped(t *testing.T) {
	// An empty-feed fixture (no seeded placement heartbeat) so the only thing that could
	// land in the feed is an ingested frame — and a malformed frame must land NOTHING.
	f := newFixtureEmptyFeed(t)
	ctx := context.Background()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	f.cp.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	client := hostagentv1.NewHostAgentServiceClient(dialBufconn(t, lis))
	stream, err := client.ReportHeartbeat(ctx)
	if err != nil {
		t.Fatalf("open ReportHeartbeat stream: %v", err)
	}
	// A frame with no heartbeat, then one with an empty host_id — both malformed.
	if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{}); err != nil {
		t.Fatalf("Send nil-heartbeat frame: %v", err)
	}
	if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{Heartbeat: &hostagentv1.Heartbeat{}}); err != nil {
		t.Fatalf("Send empty-host frame: %v", err)
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}
	if resp.GetBeatsReceived() != 2 {
		t.Errorf("close-path beats_received = %d, want 2 (counted even when skipped)", resp.GetBeatsReceived())
	}
	// Nothing reached the feed (both frames were malformed).
	snaps, _ := f.cp.Heartbeats.LatestSnapshots(ctx, "any")
	if len(snaps) != 0 {
		t.Errorf("feed snapshots after malformed-only ingest = %d, want 0", len(snaps))
	}
}

// TestServe_FatalListenerErrorTearsDownLoopAndReturns proves the fatal-serve-error path:
// when the listener dies (here: closed out from under the server) BEFORE a shutdown
// signal — the parent context still live — Serve must cancel the reconcile loop itself
// and return promptly (the surfaced serve error, never a hang). This is the path the
// loopCtx child cancel guards: the loop's Run returns only on a cancelled context, so a
// fatal serve error with a live parent ctx must cancel the loop or the join blocks forever.
func TestServe_FatalListenerErrorTearsDownLoopAndReturns(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background() // parent ctx stays LIVE — only the listener fails.

	lis := bufconn.Listen(1 << 20)
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, f.cp, lis) }()

	// Close the listener so srv.Serve(lis) returns a fatal error before any ctx cancel.
	// (A brief settle so Serve has entered its select on a live listener first.)
	time.Sleep(20 * time.Millisecond)
	_ = lis.Close()

	select {
	case <-served:
		// Returned (error or nil): the point is it did NOT hang on the loop join with a
		// live parent context — the loopCtx cancel tore the reconcile loop down.
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of a fatal listener error (loop join hung on a live parent ctx)")
	}
}

// TestServe_GracefulStopOnContextCancel proves Serve's lifecycle: it serves over a
// bufconn listener, a CreateSession round-trips, then a context cancel graceful-stops the
// server and Serve returns nil (a clean shutdown, not a serve error). The reconcile loop
// returns on the same cancelled context.
func TestServe_GracefulStopOnContextCancel(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx, cancel := context.WithCancel(context.Background())

	lis := bufconn.Listen(1 << 20)
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, f.cp, lis) }()

	// A create round-trips while serving (the server is up + the spine is wired).
	client := orchestratorv1.NewSessionServiceClient(dialBufconn(t, lis))
	if _, err := client.CreateSession(ctx, validCreateReq()); err != nil {
		t.Fatalf("CreateSession while serving: %v", err)
	}

	// Cancel → graceful stop → Serve returns nil.
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v on a clean context-cancel shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of context cancel (graceful stop hung)")
	}
}

// TestLivenessSnapshotter_RendersLiveHostThroughLoopServedSeam proves the seam main.go arms
// startAdminServer with: cp.LivenessSnapshotter(ctx).HealthSnapshot() renders the per-host
// LIVE/UNKNOWN view by reading the reconciler's lastBeat ON the reconcile-loop goroutine —
// race-clean while Serve's Run concurrently drives Observe over the wire. A heartbeat
// ingested over the bufconn (leg c) is recorded into lastBeat by the loop; the loop-served
// snapshotter then reports that host LIVE (the fixed-clock beat is inside the silence window),
// proving the readout tracks the live reconciler, not a stub (D35/D72; D50: no live edge).
func TestLivenessSnapshotter_RendersLiveHostThroughLoopServedSeam(t *testing.T) {
	f := newFixtureEmptyFeed(t) // empty feed so the only lastBeat entry is the ingested beat.
	ctx, cancel := context.WithCancel(context.Background())

	lis := bufconn.Listen(1 << 20)
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, f.cp, lis) }()

	// The loop-serialized snapshotter the admin surface renders /debug/liveness from.
	snapshotter := f.cp.LivenessSnapshotter(ctx)
	var _ HealthSnapshotterSeam = snapshotter // it satisfies the admin HealthSnapshotter shape.

	// Ingest a heartbeat over the wire (leg c) so Run Observes it and writes lastBeat.
	client := hostagentv1.NewHostAgentServiceClient(dialBufconn(t, lis))
	stream, err := client.ReportHeartbeat(ctx)
	if err != nil {
		t.Fatalf("open ReportHeartbeat stream: %v", err)
	}
	if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{Heartbeat: freshHeartbeat(testHostID, 0, 1)}); err != nil {
		t.Fatalf("Send heartbeat: %v", err)
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}

	// Poll the loop-served snapshotter until the ingested host appears (the Observe submit is
	// async: the ingest returns once the feed is recorded, the reconcile/lastBeat write lands
	// on the loop goroutine just after). The read is loop-serialized, so this is race-clean.
	var live bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, h := range snapshotter.HealthSnapshot() {
			if h.HostID == testHostID {
				if string(h.Liveness) != "LIVE" {
					t.Fatalf("ingested host liveness = %q, want LIVE (beat inside the silence window)", h.Liveness)
				}
				if !h.EverSeen {
					t.Fatalf("ingested host EverSeen = false, want true")
				}
				live = true
			}
		}
		if live {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !live {
		t.Fatalf("loop-served snapshotter never reported the ingested host %q LIVE", testHostID)
	}

	// Clean shutdown: cancel, and a snapshot taken after Serve returns must not deadlock.
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v on clean shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of cancel")
	}
	// Post-shutdown query (the bootstrap ctx is cancelled) returns promptly, no hang.
	done := make(chan struct{})
	go func() { _ = snapshotter.HealthSnapshot(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("post-shutdown HealthSnapshot blocked; the loop-served query must be bounded")
	}
}

// HealthSnapshotterSeam mirrors the cmd/orchestrator HealthSnapshotter interface (which lives
// in package main and so cannot be imported here): the no-arg HealthSnapshot accessor the
// admin surface renders the per-host liveness view from. The compile-time assertion above
// pins that loopLivenessSnapshotter satisfies exactly that shape, so main.go can thread it
// straight into startAdminServer.
type HealthSnapshotterSeam interface {
	HealthSnapshot() []reconciler.HostHealth
}

// TestLivenessSnapshotter_NilSafe proves the seam is inert (an empty view, never a panic)
// for a nil ControlPlane and for a control plane whose loop is nil — so a never-wired or
// partially-wired surface degrades cleanly rather than crashing the admin render.
func TestLivenessSnapshotter_NilSafe(t *testing.T) {
	var nilCP *ControlPlane
	if got := nilCP.LivenessSnapshotter(context.Background()).HealthSnapshot(); len(got) != 0 {
		t.Errorf("nil ControlPlane snapshotter = %+v, want empty view", got)
	}
	emptyCP := &ControlPlane{} // Reconcile nil.
	if got := emptyCP.LivenessSnapshotter(context.Background()).HealthSnapshot(); len(got) != 0 {
		t.Errorf("unwired-loop snapshotter = %+v, want empty view", got)
	}
	// The never-seen variant is equally nil-safe (a nil ControlPlane, even with a supplier).
	if got := nilCP.LivenessSnapshotterIncluding(context.Background(), func() []string { return []string{"ghost"} }).HealthSnapshot(); len(got) != 0 {
		t.Errorf("nil ControlPlane including-snapshotter = %+v, want empty view", got)
	}
}

// findHostHealth returns the snapshot entry for hostID and whether it was present.
func findHostHealth(snap []reconciler.HostHealth, hostID string) (reconciler.HostHealth, bool) {
	for _, h := range snap {
		if h.HostID == hostID {
			return h, true
		}
	}
	return reconciler.HostHealth{}, false
}

// TestLivenessSnapshotterIncluding_ExpectedSilentHostRendersUnknownOverLoopServedSeam is the
// e2e never-seen pin (subtasks 4): the OPT-IN cp.LivenessSnapshotterIncluding — the seam
// main.go arms startAdminServer with under DS_ORCH_LIVE — surfaces an EXPECTED-but-silent host
// (one the supplier names but that has NEVER heartbeated) as EverSeen=false / UNKNOWN over the
// SAME loop-serialized admin render path, while a host that DID beat over the wire still renders
// LIVE. This is the property an operator depends on: a placed host that never came up is VISIBLE
// on /debug/liveness, not silently absent (doc 15 §3/§5.2; D35/D72; D50: no live edge).
func TestLivenessSnapshotterIncluding_ExpectedSilentHostRendersUnknownOverLoopServedSeam(t *testing.T) {
	f := newFixtureEmptyFeed(t) // empty feed so the only heard-from host is the ingested beat.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lis := bufconn.Listen(1 << 20)
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, f.cp, lis) }()

	const expectedSilentHost = "host-never-heard-from"
	// The store-backed supplier the admin surface threads: it names BOTH the host that will
	// beat (testHostID, also heard-from) AND an expected host that never beats — so the
	// snapshot must fold the silent one in while reporting the beating one from its real beat.
	supplier := func() []string { return []string{expectedSilentHost, testHostID} }
	snapshotter := f.cp.LivenessSnapshotterIncluding(ctx, supplier)
	var _ HealthSnapshotterSeam = snapshotter // it satisfies the admin HealthSnapshotter shape.

	// Ingest a heartbeat for testHostID over the wire (leg c) so Run Observes it → LIVE.
	client := hostagentv1.NewHostAgentServiceClient(dialBufconn(t, lis))
	stream, err := client.ReportHeartbeat(ctx)
	if err != nil {
		t.Fatalf("open ReportHeartbeat stream: %v", err)
	}
	if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{Heartbeat: freshHeartbeat(testHostID, 0, 1)}); err != nil {
		t.Fatalf("Send heartbeat: %v", err)
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}

	// Poll the loop-served including-snapshotter until the beating host lands (its Observe is
	// async). The read is loop-serialized so this is race-clean.
	var live, foundSilent bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snap := snapshotter.HealthSnapshot()
		// The expected-but-silent host is folded in EVERY snapshot (it comes from the
		// supplier, not the wire), as a never-seen UNKNOWN.
		silent, ok := findHostHealth(snap, expectedSilentHost)
		if ok {
			foundSilent = true
			if silent.EverSeen {
				t.Fatalf("expected-silent host EverSeen = true, want false (never heartbeated)")
			}
			if string(silent.Liveness) != "UNKNOWN" {
				t.Fatalf("expected-silent host liveness = %q, want UNKNOWN", silent.Liveness)
			}
			if !silent.LastBeat.IsZero() {
				t.Fatalf("expected-silent host LastBeat = %v, want zero", silent.LastBeat)
			}
		}
		if beating, ok := findHostHealth(snap, testHostID); ok {
			if string(beating.Liveness) != "LIVE" {
				t.Fatalf("ingested host liveness = %q, want LIVE", beating.Liveness)
			}
			if !beating.EverSeen {
				t.Fatalf("ingested host EverSeen = false, want true")
			}
			live = true
		}
		if live && foundSilent {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !foundSilent {
		t.Fatalf("loop-served including-snapshotter never folded in the expected-silent host %q", expectedSilentHost)
	}
	if !live {
		t.Fatalf("loop-served including-snapshotter never reported the ingested host %q LIVE", testHostID)
	}
}

// TestLivenessSnapshotterIncluding_SupplierContract_NonBlockingFreshSlice pins the two
// load-bearing ExpectedHostSupplier obligations the loop-serialized snapshotter relies on
// (subtask 3), with a synthetic supplier:
//
//   - FRESH-SLICE: the snapshotter folds in EXACTLY the host_ids the supplier returns for
//     THIS call; mutating a slice the supplier returned on a PRIOR call never leaks into a
//     later snapshot (the loop reads the supplier's return, never stores it).
//   - NON-BLOCKING / re-evaluated per call: the supplier is invoked once per HealthSnapshot
//     (so the view tracks the CURRENT expected fleet), and a supplier returning nil degrades
//     the snapshot to the heard-from-only view byte-for-byte (additive).
//
// Driven over a live Serve (the loop running) so the read is the production loop-serialized
// path (D50: synthetic supplier, no live edge).
func TestLivenessSnapshotterIncluding_SupplierContract_NonBlockingFreshSlice(t *testing.T) {
	f := newFixtureEmptyFeed(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lis := bufconn.Listen(1 << 20)
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, f.cp, lis) }()

	// A supplier whose returned set is swappable per call. It returns a FRESH slice each
	// call (the contract); a counter proves it is re-evaluated per HealthSnapshot.
	var (
		muSup   sync.Mutex
		current []string
		callN   int
	)
	setExpected := func(hosts ...string) {
		muSup.Lock()
		current = append([]string(nil), hosts...)
		muSup.Unlock()
	}
	supplier := func() []string {
		muSup.Lock()
		defer muSup.Unlock()
		callN++
		return append([]string(nil), current...) // a fresh, caller-owned slice each call.
	}

	snap := f.cp.LivenessSnapshotterIncluding(ctx, supplier)

	// (a) Re-evaluated per call: with one expected host, it appears; swap the expected set and
	// the NEXT snapshot reflects the new host (the supplier is not memoized at wiring time).
	setExpected("ghost-a")
	if _, ok := findHostHealth(snap.HealthSnapshot(), "ghost-a"); !ok {
		t.Fatalf("expected host ghost-a absent from the first including-snapshot")
	}
	beforeSwapCalls := callN
	setExpected("ghost-b")
	view := snap.HealthSnapshot()
	if _, ok := findHostHealth(view, "ghost-b"); !ok {
		t.Fatalf("post-swap snapshot must reflect the new expected host ghost-b")
	}
	if _, ok := findHostHealth(view, "ghost-a"); ok {
		t.Fatalf("post-swap snapshot must NOT carry the stale expected host ghost-a")
	}
	if callN <= beforeSwapCalls {
		t.Fatalf("supplier must be re-evaluated per HealthSnapshot; call count did not advance (%d <= %d)", callN, beforeSwapCalls)
	}

	// (b) Fresh-slice: a returned slice mutated by the CALLER after the fact must not corrupt a
	// later snapshot. Grab a returned slice, scribble on it, and confirm the next snapshot is
	// unaffected (the loop derived its view from the bytes at call time, holding no alias).
	leaked := supplier() // a fresh slice carrying ghost-b.
	if len(leaked) > 0 {
		leaked[0] = "CORRUPTED"
	}
	if _, ok := findHostHealth(snap.HealthSnapshot(), "CORRUPTED"); ok {
		t.Fatalf("a caller-side mutation of a prior supplier slice leaked into a later snapshot")
	}

	// (c) Nil/empty supplier return degrades to the heard-from-only view (additive). With no
	// heard-from host (empty feed) and no expected host, the snapshot is empty.
	setExpected() // empty.
	if got := snap.HealthSnapshot(); len(got) != 0 {
		t.Fatalf("empty expected set with no heard-from host must yield an empty view; got %+v", got)
	}
}

// --- convergence-sweep launch fakes (the destroy re-drive seams) ------------
//
// The idle reaper's fakes (fakeClock, fakeSessionLister, recordingDestroyer, the record
// builders) already live in sessionidlereaper_test.go (same package); these two add the
// remaining DestroyRedriver seams so a Serve-level test can wire BOTH sweeps over fakes.

// settableDestroyingLister is a settable reconciler.DestroyingLister: a test seeds the
// DESTROYING records the next re-drive sweep observes. Concurrency-safe because Serve's
// sweep goroutine reads it while the test seeds/inspects from the test goroutine.
type settableDestroyingLister struct {
	mu   sync.Mutex
	recs []store.Session
}

func (l *settableDestroyingLister) set(recs ...store.Session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = recs
}

func (l *settableDestroyingLister) ListDestroying(_ context.Context) ([]store.Session, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]store.Session, len(l.recs))
	copy(out, l.recs)
	return out, nil
}

// recordingFinalizer records the §3-terminal DESTROYING→DESTROYED finalize the re-driver
// runs after a clean teardown, so a test asserts the stuck record was driven to DESTROYED.
type recordingFinalizer struct {
	mu        sync.Mutex
	finalized []string
}

func (f *recordingFinalizer) FinalizeDestroyed(_ context.Context, sessionUUID string) (store.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalized = append(f.finalized, sessionUUID)
	return store.Session{Ref: store.SessionRef{SessionUUID: sessionUUID}, State: store.SessionDestroyed}, nil
}

func (f *recordingFinalizer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.finalized)
}

// withServeSweepIntervals drives Serve's two convergence-sweep cadences FAST for the duration
// of a test (the package vars default to 0 → the production TTL/30s cadence) and restores them
// on cleanup. It lets a Serve-level test observe a sweep tick in milliseconds, not minutes.
func withServeSweepIntervals(t *testing.T, idle, reDrive time.Duration) {
	t.Helper()
	savedIdle, savedReDrive := serveIdleReapInterval, serveDestroyReDriveInterval
	serveIdleReapInterval, serveDestroyReDriveInterval = idle, reDrive
	t.Cleanup(func() { serveIdleReapInterval, serveDestroyReDriveInterval = savedIdle, savedReDrive })
}

// TestServe_LaunchesBothConvergenceSweeps proves the unit: Serve starts BOTH cp.RunSessionIdleReap
// and cp.RunDestroyReDrive as background goroutines off the same loopCtx the reconcile loop runs
// under — so the previously-dead idle reaper and destroy re-drive sweeps actually run in the live
// daemon — and BOTH stop cleanly on ctx cancel (Serve returns nil, no goroutine hang).
//
// The two sweeps are wired over the package's existing fakes (a fake clock + lister + recording
// destroyer for the reaper; a settable DESTROYING lister + recording finalizer for the re-driver),
// substituted onto the fixture's ControlPlane so the cadence + record set are deterministic and
// the real (slow, 30m/30s) production cadences are not waited on. Serve drives them at a fast tick.
func TestServe_LaunchesBothConvergenceSweeps(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// REAPER over fakes: a real-time clock + a sub-millisecond TTL so successive fast ticks see a
	// writer-less span past the TTL and reap (the first tick stamps the writer-less clock, a later
	// tick reaps). The session is RUNNING + writer-less so it is reapable.
	reapLister := &fakeSessionLister{}
	reapLister.set(runningWriterlessSession("s-idle", "host-a"))
	reapDest := newRecordingDestroyer()
	const shortTTL = 100 * time.Microsecond
	reaper := newSessionIdleReaper(reapLister, reapDest, shortTTL, time.Now, nil)
	if reaper == nil {
		t.Fatal("reaper must be constructed for a positive TTL")
	}
	f.cp.SessionIdleReaper = reaper

	// DESTROY RE-DRIVER over fakes: one record STUCK in DESTROYING the sweep must re-drive forward
	// to DESTROYED (a clean teardown via the recording destroyer, then a finalize).
	redLister := &settableDestroyingLister{}
	redLister.set(withState(runningWriterlessSession("s-stuck", "host-a"), store.SessionDestroying))
	redDest := newRecordingDestroyer()
	redFinal := &recordingFinalizer{}
	reDriver, err := reconciler.NewDestroyRedriver(redLister, redDest, redFinal, nil)
	if err != nil {
		t.Fatalf("NewDestroyRedriver: %v", err)
	}
	f.cp.DestroyReDriver = reDriver

	// Drive both sweeps fast (a tick every ms) so the test observes them within a short deadline.
	withServeSweepIntervals(t, time.Millisecond, time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	lis := bufconn.Listen(1 << 20)
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, f.cp, lis) }()

	// Wait until BOTH sweeps have driven at least once: the reaper destroyed the idle session and
	// the re-driver finalized the stuck one. (The reaper's first tick only stamps; a later tick
	// past the short TTL reaps — both happen within the deadline at a 1ms cadence.)
	deadline := time.After(5 * time.Second)
	for reapDest.countFor("s-idle") == 0 || redFinal.count() == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatalf("sweeps did not both drive: idle-reap destroys=%d, destroy-redrive finalizes=%d (want both ≥1)",
				reapDest.countFor("s-idle"), redFinal.count())
		case err := <-served:
			t.Fatalf("Serve returned early (%v) before both sweeps drove", err)
		case <-time.After(2 * time.Millisecond):
		}
	}

	// The re-driver drove the §4.2 teardown of the stuck record before finalizing it.
	if got := redDest.countFor("s-stuck"); got == 0 {
		t.Errorf("destroy re-drive must drive the §4.2 teardown of the stuck record; got %d Destroy calls", got)
	}

	// Both sweeps stop cleanly on ctx cancel (graceful stop): Serve returns nil, no goroutine hang.
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v on clean shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of cancel (a sweep goroutine join hung)")
	}
}

// TestServe_IdleReaperDormantWhenDisabled proves the TTL ≤ 0 dormant case end to end through
// Serve: when the reaper is disabled (DS_ORCH_SESSION_IDLE_TTL ≤ 0 ⇒ cp.SessionIdleReaper nil),
// Serve still launches RunSessionIdleReap unconditionally — and it runs NO sweep (blocks until
// cancel), so a writer-less-past-TTL session is NEVER destroyed by the idle leg — while the
// destroy re-drive sweep still runs. Serve returns cleanly on cancel (the dormant reaper
// goroutine joins, no leak).
func TestServe_IdleReaperDormantWhenDisabled(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	// Disabled reaper (nil) — the env-gated opt-out: Serve must still join its goroutine cleanly.
	if r := newSessionIdleReaper(&fakeSessionLister{}, newRecordingDestroyer(), 0, time.Now, nil); r != nil {
		t.Fatal("TTL=0 must yield a nil (disabled) reaper")
	}
	f.cp.SessionIdleReaper = nil

	// A re-driver over fakes whose sweep we can observe ticking, to prove the OTHER sweep still
	// runs while the reaper is dormant.
	redLister := &settableDestroyingLister{}
	redLister.set(withState(runningWriterlessSession("s-stuck2", "host-a"), store.SessionDestroying))
	redDest := newRecordingDestroyer()
	redFinal := &recordingFinalizer{}
	reDriver, err := reconciler.NewDestroyRedriver(redLister, redDest, redFinal, nil)
	if err != nil {
		t.Fatalf("NewDestroyRedriver: %v", err)
	}
	f.cp.DestroyReDriver = reDriver

	withServeSweepIntervals(t, time.Millisecond, time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	lis := bufconn.Listen(1 << 20)
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, f.cp, lis) }()

	// The destroy re-drive sweep drives (proving Serve launched the sweeps and they tick), while
	// the dormant reaper runs nothing.
	deadline := time.After(5 * time.Second)
	for redFinal.count() == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("destroy re-drive sweep never drove (Serve did not launch the sweeps)")
		case err := <-served:
			cancel()
			t.Fatalf("Serve returned early (%v)", err)
		case <-time.After(2 * time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v on clean shutdown with a dormant reaper, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of cancel (the dormant reaper goroutine hung)")
	}
}

// ---------------------------------------------------------------------------
// orchgroom leg (1)/(2)/(3) enrollment pins — the three wave-1 control-plane seams
// wired into wiring.go behind DS_ORCH_LIVE (off by default; the gated arms SKIP clean
// unarmed). D50: NO live VM/host-agent/podman — synthetic fakes + in-memory store only.
// ---------------------------------------------------------------------------

// recordingTTLAlarm is a recording reconciler.Alarmer (D50): the credential-TTL backstop
// raises AlarmCredentialTTLReconverge for every stale persisted-horizon record it drives,
// so a test asserts the backstop FIRED by observing this alarm. It is concurrency-safe so a
// test can read it while the RunMintExpiry sweep goroutine raises into it.
type recordingTTLAlarm struct {
	mu     sync.Mutex
	alarms []reconciler.Alarm
}

func (a *recordingTTLAlarm) Alarm(_ context.Context, al reconciler.Alarm) {
	a.mu.Lock()
	a.alarms = append(a.alarms, al)
	a.mu.Unlock()
}

func (a *recordingTTLAlarm) has(kind reconciler.AlarmKind) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, al := range a.alarms {
		if al.Kind == kind {
			return true
		}
	}
	return false
}

// enrollDeps builds a fully-wired Deps over the synthetic fakes (the production wiring
// path, mirroring newFixture's bundle) with a caller-supplied Alarm + Resumer and NO
// Deps.Approvals — so leg (2)'s LIVE grant-approvals reader is the ONLY thing that can
// admit a policy_breach resume, and leg (1)'s backstop alarm is observable. The real-time
// clock lets the RunMintExpiry sweep fire promptly under a short interval. D50 only.
func enrollDeps(t *testing.T, alarm reconciler.Alarmer, resumer sessions.Resumer) (Deps, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	if _, err := st.PutEnvConfig(context.Background(), store.EnvConfig{
		Ref:     testEnvRef,
		RepoRef: testRepoID,
		ImageID: testImageID,
	}); err != nil {
		t.Fatalf("seed env config: %v", err)
	}
	heartbeats := NewHeartbeatStore(time.Now)
	heartbeats.Record(freshHeartbeat(testHostID, 0, 1))
	return Deps{
		Store:          cpStore{st},
		Drivers:        fakeRegistry{host: testHostID, drv: newDriverFake()},
		Heartbeats:     heartbeats,
		Mint:           &fakeMint{},
		Digest:         &fakeDigest{acked: true},
		Inject:         &fakeInject{},
		Boot:           &fakeBoot{},
		Revoke:         &fakeRevoke{},
		Enrollment:     fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:          sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
		DefaultOrg:     testOrg,
		ResyncInterval: time.Hour,
		Alarm:          alarm,
		Resumer:        resumer,
		// Approvals deliberately LEFT NIL: gate-on, leg (2) must thread the LIVE store reader;
		// gate-off, a policy_breach resume must deny fail-closed (nil Approvals).
	}, st
}

// seedSuspendedPolicyBreach writes a SUSPENDED policy_breach record straight into the store
// (the state a boundary-signal suspension leaves) so leg (2)'s policy_breach resume arm can be
// exercised without driving the full create→suspend choreography.
func seedSuspendedPolicyBreach(t *testing.T, st *store.Memory, uuid string) {
	t.Helper()
	if _, err := st.CreateSession(context.Background(), store.Session{
		Ref:           store.SessionRef{SessionUUID: uuid, HostID: testHostID, HostSessionIndex: 1, TapName: "dstap-1"},
		State:         store.SessionSuspended,
		SuspendReason: store.SuspendReasonPolicyBreach,
	}); err != nil {
		t.Fatalf("seed suspended policy_breach session: %v", err)
	}
}

// TestEnroll_CredTTLBackstopFiresOnResyncTick proves leg (1): under DS_ORCH_LIVE the wiring
// installs the credttl.go MintReconverger (WithMintReconverger), so the reconcile-cadence
// backstop (cp.RunMintExpiry, the periodic Resync-cadence arm) re-converges a LIVE record whose
// persisted §5.6 MintExpiry horizon is already past — raising AlarmCredentialTTLReconverge. The
// gate-OFF companion proves the no-seam no-op: the SAME sweep over the SAME stale record raises
// NO such alarm (the in-process timer / boot sweep stays the sole credential-TTL mechanism,
// fully backwards-compatible). DS_ORCH_LIVE is OFF by default, so this gated arm SKIPS clean
// unarmed. D50: synthetic fakes, no live mint/VM.
func TestEnroll_CredTTLBackstopFiresOnResyncTick(t *testing.T) {
	if os.Getenv("DS_ORCH_LIVE") != "1" {
		t.Skip("credential-TTL backstop enrollment is DS_ORCH_LIVE-gated (leg 1); CI gate-off skips clean unarmed")
	}
	alarm := &recordingTTLAlarm{}
	deps, st := enrollDeps(t, alarm, &fakeResumer{})
	cp, err := NewControlPlane(deps)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	// A LIVE (READY) record carrying a persisted horizon already in the PAST — the durable
	// footprint of the two miss windows credttl.go documents (no in-process timer driving it).
	if _, err := st.CreateSession(context.Background(), store.Session{
		Ref:        store.SessionRef{SessionUUID: "s-stale", HostID: testHostID, HostSessionIndex: 1, TapName: "dstap-1"},
		State:      store.SessionReady,
		MintExpiry: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed stale-horizon session: %v", err)
	}

	// Drive the credential-TTL backstop on a fast cadence (the periodic Resync-cadence arm) and
	// wait for the backstop to fire (the alarm raised) within a short deadline.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cp.RunMintExpiry(ctx, time.Millisecond) }()

	deadline := time.After(5 * time.Second)
	for !alarm.has(reconciler.AlarmCredentialTTLReconverge) {
		select {
		case <-deadline:
			cancel()
			t.Fatal("credential-TTL backstop never fired on a Resync-cadence tick (leg 1 not enrolled?)")
		case err := <-done:
			t.Fatalf("RunMintExpiry returned early: %v", err)
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunMintExpiry returned %v on cancel, want context.Canceled", err)
	}
}

// TestEnroll_CredTTLBackstopNoOpWhenGateOff proves the backwards-compatible no-seam posture:
// with DS_ORCH_LIVE OFF the wiring installs NO MintReconverger, so cp.RunMintExpiry's
// ReconcileMintExpiry pass is a documented no-op — the SAME stale-horizon record raises NO
// AlarmCredentialTTLReconverge. This is the always-on (un-gated) proof that the enrollment is
// additive: gate-off behavior is unchanged.
func TestEnroll_CredTTLBackstopNoOpWhenGateOff(t *testing.T) {
	if os.Getenv("DS_ORCH_LIVE") == "1" {
		t.Skip("this pins the GATE-OFF no-op; DS_ORCH_LIVE is set")
	}
	alarm := &recordingTTLAlarm{}
	deps, st := enrollDeps(t, alarm, &fakeResumer{})
	cp, err := NewControlPlane(deps)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	if _, err := st.CreateSession(context.Background(), store.Session{
		Ref:        store.SessionRef{SessionUUID: "s-stale", HostID: testHostID, HostSessionIndex: 1, TapName: "dstap-1"},
		State:      store.SessionReady,
		MintExpiry: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed stale-horizon session: %v", err)
	}

	// Run a handful of synchronous passes — with no reconverger wired ReconcileMintExpiry no-ops
	// (it does not even list), so no alarm is ever raised.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = cp.RunMintExpiry(ctx, time.Millisecond) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if alarm.has(reconciler.AlarmCredentialTTLReconverge) {
		t.Fatal("gate-off credential-TTL backstop must be a no-op (no AlarmCredentialTTLReconverge); leg 1 fired without DS_ORCH_LIVE")
	}
	// The gate-off AskParkRouter must be nil too (leg 3 is gated), proving the gate fences all
	// three legs uniformly.
	if cp.AskParkRouter != nil {
		t.Fatal("gate-off AskParkRouter must be nil (leg 3 is DS_ORCH_LIVE-gated)")
	}
}

// TestEnroll_AskParkRouterAndLiveApprovalsNonNil proves legs (2) + (3) under DS_ORCH_LIVE:
//
//   - leg (3): cp.AskParkRouter is NON-NIL after NewControlPlane — the *parkMachine is enrolled
//     as the policylog ask-routing park router, so a live RouteAsk site enters a genuine rung-2
//     ask into the durable D46 park end to end.
//   - leg (2): ParkResumeSeams.Approvals is the LIVE grant reader — proven BEHAVIORALLY (the
//     driver hides the seam): with Deps.Approvals NIL, a policy_breach resume can ONLY be admitted
//     if the wiring threaded the live store-backed LiveGrantApprovalPresence. A landed ask-grant
//     for the session ⇒ the resume is PERMITTED (walks SUSPENDED→RESUMING→WORKING). Without leg (2)
//     the nil Approvals would deny fail-closed.
//
// DS_ORCH_LIVE is OFF by default, so this gated arm SKIPS clean unarmed. D50: synthetic fakes.
func TestEnroll_AskParkRouterAndLiveApprovalsNonNil(t *testing.T) {
	if os.Getenv("DS_ORCH_LIVE") != "1" {
		t.Skip("ask-park-router + live-approvals enrollment is DS_ORCH_LIVE-gated (legs 2/3); CI gate-off skips clean unarmed")
	}
	resumer := &fakeResumer{}
	deps, st := enrollDeps(t, &recordingTTLAlarm{}, resumer)
	cp, err := NewControlPlane(deps)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}

	// leg (3): the *parkMachine is enrolled as the live ask-park router.
	if cp.AskParkRouter == nil {
		t.Fatal("leg (3): cp.AskParkRouter must be non-nil under DS_ORCH_LIVE (the *parkMachine enrolled as the policylog askParkRouter)")
	}
	if cp.AskParkRouter != AskParkRouter(cp.ParkMachine) {
		t.Fatal("leg (3): the enrolled AskParkRouter must be the SAME *parkMachine the boot re-adoption + escalation drive (one durable park machine)")
	}

	// leg (2): a landed, currently-valid ask-grant for the session — the policy_log shape a landed
	// rung-2 human approval IS. With Deps.Approvals nil, ONLY the threaded live reader can find it.
	const uuid = "s-bic"
	seedSuspendedPolicyBreach(t, st, uuid)
	future := time.Now().Add(time.Hour)
	if _, err := st.AppendPolicy(context.Background(), store.PolicyLogRow{
		Kind:        store.PolicyKindAskGrant,
		Actor:       "approver-principal",
		SessionUUID: uuid,
		ExpiresAt:   &future,
	}); err != nil {
		t.Fatalf("land ask-grant: %v", err)
	}

	resumed, err := cp.ParkResume.Resume(context.Background(), uuid, sessions.ResumeAuthorityHumanApproval)
	if err != nil {
		t.Fatalf("leg (2): policy_breach resume WITH a landed grant must be PERMITTED by the threaded live reader; got %v", err)
	}
	if resumed.State != store.SessionWorking {
		t.Fatalf("leg (2): a permitted policy_breach resume must advance to WORKING; got %s", resumed.State)
	}
	if len(resumer.calls) != 1 || resumer.calls[0].session != uuid {
		t.Fatalf("leg (2): a permitted resume must drive the host Resume verb once for %s; got %v", uuid, resumer.calls)
	}
}

// TestEnroll_PolicyBreachDeniedWhenGateOff proves leg (2)'s gate-off fail-closed posture: with
// DS_ORCH_LIVE OFF the wiring leaves ParkResumeSeams.Approvals as Deps.Approvals supplied (nil
// here), so a policy_breach resume — EVEN with a live grant landed in the store — is DENIED
// fail-closed (no approval-presence reader wired). This pins that the live reader is the ENROLLED
// thing, not an always-on default. Always-on (un-gated) proof. D50.
func TestEnroll_PolicyBreachDeniedWhenGateOff(t *testing.T) {
	if os.Getenv("DS_ORCH_LIVE") == "1" {
		t.Skip("this pins the GATE-OFF fail-closed deny; DS_ORCH_LIVE is set")
	}
	resumer := &fakeResumer{}
	deps, st := enrollDeps(t, &recordingTTLAlarm{}, resumer)
	cp, err := NewControlPlane(deps)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	const uuid = "s-bic-off"
	seedSuspendedPolicyBreach(t, st, uuid)
	future := time.Now().Add(time.Hour)
	if _, err := st.AppendPolicy(context.Background(), store.PolicyLogRow{
		Kind:        store.PolicyKindAskGrant,
		Actor:       "approver-principal",
		SessionUUID: uuid,
		ExpiresAt:   &future,
	}); err != nil {
		t.Fatalf("land ask-grant: %v", err)
	}

	// Gate off ⇒ Approvals nil ⇒ AuthorizeResume denies fail-closed (no reader wired), so the
	// live grant in the store is NEVER consulted and the host Resume verb is never driven.
	_, err = cp.ParkResume.Resume(context.Background(), uuid, sessions.ResumeAuthorityHumanApproval)
	if err == nil {
		t.Fatal("gate-off policy_breach resume must DENY fail-closed (nil Approvals), even with a grant landed")
	}
	if len(resumer.calls) != 0 {
		t.Fatalf("a denied resume must not drive the host Resume verb; got %v", resumer.calls)
	}
}
