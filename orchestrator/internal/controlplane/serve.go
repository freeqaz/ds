package controlplane

// serve.go is LEG (b) of the live-edge fill: the gRPC SERVE bootstrap. It constructs the
// grpc.Server, registers the orch19 CreateSession handler (cp.Sessions) AND the
// leg-(c) heartbeat ingest (routing inbound hostagent.v1 heartbeats to cp.Reconcile.Observe)
// on it, starts the single-goroutine reconcile loop (cp.Reconcile.Run), listens on the
// configured address, and maps lifecycle (a context cancel → graceful stop). main.go is a
// thin bootstrap that resolves the listen address + the live backends and calls Serve;
// the real serve logic lives HERE so it is unit-tested over a bufconn listener with NO
// live socket (D50).
//
// WHY THE SERVE LOGIC IS IN THE PACKAGE (not main.go). The task pins main.go as a thin
// bootstrap: the load-bearing wiring (server construction, service registration, the
// reconcile-loop start, the graceful-stop mapping) is package logic exercised without a
// live backend. So Serve takes an already-built ControlPlane + a net.Listener: a test
// passes a bufconn listener (an in-memory pipe — no port bind) and dials it over the same
// bufconn, asserting a CreateSession over the wire drives the spine and a ReportHeartbeat
// frame reaches Observe. main.go passes a real net.Listen("tcp", addr) under DS_ORCH_LIVE=1.
//
// GRACEFUL LIFECYCLE. Serve starts the reconcile loop and the gRPC server, then blocks
// until the context is cancelled (a SIGINT/SIGTERM the bootstrap relays) — at which point
// it GracefulStop's the server (drains in-flight RPCs, stops accepting new ones) and lets
// the reconcile loop's Run return on the same cancelled context. A server-side serve error
// (the listener died) is surfaced; a clean context-cancel shutdown returns nil.
//
// CONVERGENCE SWEEPS. Alongside the reconcile loop, Serve ALSO launches the cadence sweeps
// that were previously defined-but-never-started (so they were dead code in the live daemon):
// cp.RunSessionIdleReap (the writer-less-RUNNING idle-TTL reaper, sessionidlereaper.go),
// cp.RunDestroyReDrive (the §4.2 destroy-path convergence backstop, wiring.go), and
// cp.RunMintExpiry (the §4.1 step-5 CREDENTIAL-TTL backstop, leg 1 — doc 16 §5.4). All three
// are driven off the SAME loopCtx Serve cancels on every exit path and joined on both shutdown
// branches, so they stop cleanly with the reconcile loop and never leak a goroutine. All three
// are nil-safe / self-disabling — RunSessionIdleReap blocks-until-cancel when the reaper is
// disabled (DS_ORCH_SESSION_IDLE_TTL ≤ 0), RunDestroyReDrive derives its own cadence, and
// RunMintExpiry's ReconcileMintExpiry pass is a DOCUMENTED NO-OP unless a MintReconverger is
// installed (WithMintReconverger, gated on DS_ORCH_LIVE) — so launching them UNCONDITIONALLY is
// safe; a non-positive interval lets each derive its own cadence (the reaper from its TTL, the
// re-driver from DefaultDestroyReDriveInterval, the credential-TTL backstop from the reconcile
// loop's full-resync cadence). The credential-TTL backstop runs concurrently with the reconcile
// loop SAFELY because ReconcileMintExpiry touches NO mutable reconciler state (it never reads or
// writes lastBeat — credttl.go).

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	rolesv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/roles/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
)

// LivenessSnapshotter returns the LOOP-SERIALIZED per-host liveness query seam for this
// control plane: a reader whose HealthSnapshot() marshals onto the reconcile loop's single
// goroutine (the sole lastBeat owner) and returns the reconciler's current LIVE/UNKNOWN view
// (doc 15 §3/§5.2; D35/D72). It is the production source the orchestrator's admin surface
// renders /debug/liveness + the orchestrator_host_liveness expvar var from WITHOUT racing
// the reconcile loop's lastBeat writes — main.go arms startAdminServer with it (replacing
// the deferred nil snapshotter) under DS_ORCH_LIVE.
//
// The returned reader is bound to ctx: its HealthSnapshot() submits the query with ctx, so a
// cancelled ctx (the run shutting down) makes the query return promptly (an empty view)
// rather than blocking on a loop that is stopping. It is purely additive — a read-only
// query that adds no lastBeat writer, no §3 state name, and no record mutation. nil-safe: a
// nil ControlPlane or an unwired Reconcile returns a reader whose HealthSnapshot() is an
// empty view.
func (cp *ControlPlane) LivenessSnapshotter(ctx context.Context) loopLivenessSnapshotter {
	if cp == nil {
		return loopLivenessSnapshotter{}
	}
	return loopLivenessSnapshotter{loop: cp.Reconcile, ctx: ctx}
}

// ExpectedHostSupplier supplies the EXPECTED host_id set for the never-seen liveness
// enrichment (doc 15 §3 / §5.2; D35/D72): the hosts the caller knows SHOULD be reporting
// (e.g. enumerated from the record store at the call site) so an expected-but-NEVER-heard-from
// host renders EverSeen=false / UNKNOWN through the loop-serialized snapshot instead of being
// ABSENT. It is an OPT-IN seam — supplied to LivenessSnapshotterIncluding, never required by
// the bare LivenessSnapshotter path — and stays purely ADDITIVE: where the expected set comes
// from in production is a DEFERRED wiring detail (a supplier defaulting to empty /
// heard-from-only keeps today's behavior). It is the caller's responsibility to keep the
// supplier non-blocking and to return a fresh, caller-owned slice; the loop only READS it on
// the reconcile-loop goroutine and never stores it.
//
// A nil supplier (or one returning nil/empty) makes LivenessSnapshotterIncluding behave
// identically to the bare LivenessSnapshotter — the heard-from set only. This does NOT couple
// the loop to the store: the supplier is a separate, caller-furnished function, so wiring a
// real store-backed source (the deferred manual step) never touches the reconcile loop.
type ExpectedHostSupplier func() []string

// LivenessSnapshotterIncluding is the OPT-IN companion to LivenessSnapshotter: it returns the
// same loop-serialized per-host liveness reader, but threads an ExpectedHostSupplier so the
// rendered view folds in EXPECTED-but-silent hosts as EverSeen=false / UNKNOWN rather than
// omitting them (doc 15 §3 / §5.2; D35/D72). The returned reader still satisfies the admin
// surface's HealthSnapshotter seam (HealthSnapshot() []reconciler.HostHealth, no ctx) and is
// drop-in where LivenessSnapshotter is used today — main.go can arm startAdminServer with it
// (the deferred wiring of a real expected-host source), under DS_ORCH_LIVE, without any change
// to the bare path.
//
// It is purely additive and store-free: the expected set arrives via the caller-furnished
// supplier (evaluated lazily per HealthSnapshot call so it always reflects the current
// expected fleet), NOT from a store dependency on the loop; the underlying read remains the
// loop-serialized, ctx-bounded HealthSnapshotIncluding — no new lastBeat writer, no §3 state
// name, no record mutation. A nil supplier degrades to the heard-from-only view (identical to
// LivenessSnapshotter). nil-safe: a nil ControlPlane returns a reader whose HealthSnapshot()
// is an empty view.
func (cp *ControlPlane) LivenessSnapshotterIncluding(ctx context.Context, expected ExpectedHostSupplier) loopLivenessSnapshotter {
	if cp == nil {
		return loopLivenessSnapshotter{}
	}
	return loopLivenessSnapshotter{loop: cp.Reconcile, ctx: ctx, expected: expected}
}

// loopLivenessSnapshotter adapts the reconcile loop's ctx-taking HealthSnapshot onto the
// admin surface's HealthSnapshotter seam (HealthSnapshot() []reconciler.HostHealth, no ctx):
// it pins the run-scoped ctx the query is submitted under, so the admin handler can call the
// no-arg form while the loop-serialized, ctx-bounded read happens underneath. A zero value
// (nil loop) yields an empty view, so a never-wired surface is inert rather than panicking.
//
// expected is the OPT-IN never-seen supplier (set by LivenessSnapshotterIncluding, nil for the
// bare LivenessSnapshotter): when present its HealthSnapshot() routes the loop-serialized
// HealthSnapshotIncluding(supplier()) so expected-but-silent hosts render EverSeen=false /
// UNKNOWN; when nil it routes the bare heard-from HealthSnapshot, byte-for-byte as before.
type loopLivenessSnapshotter struct {
	loop     *reconcileLoop
	ctx      context.Context
	expected ExpectedHostSupplier
}

// HealthSnapshot satisfies the admin HealthSnapshotter seam by delegating to the loop's
// loop-serialized read under the pinned ctx. A nil loop returns an empty (non-nil) slice so
// the rendered liveness view is simply empty rather than nil-panicking.
//
// When an expected supplier is wired (LivenessSnapshotterIncluding) it is evaluated here — per
// call, so the view always reflects the current expected fleet — and the read routes through
// the loop-serialized HealthSnapshotIncluding so expected-but-silent hosts surface as
// EverSeen=false / UNKNOWN. With no supplier (the bare LivenessSnapshotter) it routes the
// heard-from-only HealthSnapshot exactly as before. Both forms run the SAME loop-serialized,
// ctx-bounded read on the reconcile-loop goroutine — no new lastBeat writer, no bare
// cross-goroutine read.
func (s loopLivenessSnapshotter) HealthSnapshot() []reconciler.HostHealth {
	if s.loop == nil {
		return []reconciler.HostHealth{}
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if s.expected == nil {
		return s.loop.HealthSnapshot(ctx)
	}
	return s.loop.HealthSnapshotIncluding(ctx, s.expected())
}

// Register installs the control plane's two server-side gRPC services onto a
// grpc.ServiceRegistrar (a *grpc.Server, or a bufconn-backed one in tests): the frozen
// orchestrator.v1 SessionService (the orch19 CreateSession handler, cp.Sessions) and the
// frozen hostagent.v1 HostAgentService (the leg-(c) heartbeat ingest routing inbound
// heartbeats to cp.Reconcile.Observe). It is the registration step factored out of Serve
// so a test can assert registration on a bufconn server WITHOUT a live socket (D50) and
// drive a CreateSession / ReportHeartbeat over the in-memory pipe. The heartbeat ingest is
// built fresh here over cp.Reconcile (the loop's Observe is the live-feed-record +
// reconcile-submit entrypoint).
func (cp *ControlPlane) Register(s grpc.ServiceRegistrar) {
	orchestratorv1.RegisterSessionServiceServer(s, cp.Sessions)
	// The heartbeat ingest routes each inbound frame through an observer (the reconcile
	// loop's Observe). When the WatchSession fan-out is being served (cp.Fanout wired), the
	// observer is the host-agent → orchestrator RELAY (attachrelay.go): it Publishes the
	// frame's host-ward observed-session §3 state EDGES into the Fanout (so WatchSession
	// serves them, doc 15 §5.2/§5.3) and THEN delegates to the reconcile loop's Observe — the
	// fan-out feed is purely additive on top of the unchanged reconcile path. With no Fanout
	// the ingest routes straight to the loop (today's behavior, byte-for-byte).
	observer := heartbeatObserver(cp.Reconcile)
	if cp.Fanout != nil {
		// The state-edge relay ALSO drives the content-leg lifecycle (contentrelay.go): a
		// session's CC-content pump is started on its first live-state edge and stopped on
		// DESTROYED, off this SAME observed-session set. withContent is a no-op when no
		// ContentRelay was wired (no ContentSource) — the fan-out then carries the control
		// edges only, byte-for-byte as before.
		relay := newAttachRelay(cp.Fanout, cp.Reconcile)
		if cp.ContentRelay != nil {
			relay = relay.withContent(cp.ContentRelay)
		}
		observer = relay
	}
	hostagentv1.RegisterHostAgentServiceServer(s, newHeartbeatIngest(observer, cp.logger))
	// The W2 attach.v1.WriterRelayService (the D137 browser writer-seat WRITE leg,
	// sessions/10 §2.1; D61/D138), registered alongside SessionService so arbitration
	// (RequestWriterSeat/YieldWriterSeat) and the read fan-out (WatchSession) are served
	// from one control plane: the seat the WriterRelayService arbitrates emits its
	// observable WRITER_SEAT_CHANGED handoff on the SAME Fanout WatchSession serves.
	// DriveSession is W3 (Unimplemented). Always wired by NewControlPlane; a test-narrowed
	// control plane that leaves it nil simply does not register the write leg.
	if cp.WriterRelay != nil {
		attachv1.RegisterWriterRelayServiceServer(s, cp.WriterRelay)
	}
	// The roles.v1 RoleCatalogService READ path (ListRoles / GetRole, doc 18 §6),
	// registered alongside SessionService so the catalog read API serves wherever
	// CreateSession is — incl. orchestrator-lite, the OSS single-host all-in-one
	// (D80, doc 18 §4 point 3). Registered only when a catalog was wired
	// (Deps.RoleCatalog); a nil catalog leaves the read API unregistered (the create
	// path is unaffected — it resolves+pins through the separate RoleResolver seam).
	if cp.RoleCatalog != nil {
		rolesv1.RegisterRoleCatalogServiceServer(s, cp.RoleCatalog)
	}
}

// Serve is the gRPC transport bootstrap (leg b). It constructs a grpc.Server, registers
// the SessionService + the heartbeat ingest on it (cp.Register), starts the reconcile
// loop's single-goroutine Run, and serves on lis until ctx is cancelled — then
// GracefulStop's the server (drain in-flight RPCs) and returns. It is reachable on a live
// run (main.go passes a net.Listen under DS_ORCH_LIVE=1) AND in tests (a bufconn listener,
// no port bind) — the load-bearing serve logic is the same, only the listener differs (D50).
//
// LIFECYCLE. Run starts on a goroutine (the loop owns the single reconcile goroutine);
// grpc.Serve(lis) starts on another (it blocks until the server stops). The main goroutine
// blocks on ctx.Done, then GracefulStop's the server (in-flight CreateSession / heartbeat
// streams drain, no new RPCs accepted) and waits for grpc.Serve to return. A serve error
// (the listener died unexpectedly) short-circuits and is surfaced; a clean context-cancel
// shutdown returns nil. The reconcile loop's Run is driven off a child context Serve cancels
// on EVERY exit path (it returns only on a cancelled context), so the fatal-serve-error
// branch — the parent ctx still live — tears the loop down rather than blocking on its join.
func Serve(ctx context.Context, cp *ControlPlane, lis net.Listener, opts ...grpc.ServerOption) error {
	logger := cp.logger
	if logger == nil {
		logger = slog.Default()
	}
	srv := grpc.NewServer(opts...)
	cp.Register(srv)

	// Drive the reconcile loop off a child context Serve cancels on EVERY exit path. The
	// loop's Run returns only on a cancelled context, so the fatal-serve-error branch below
	// (the listener died before a shutdown signal, while the parent ctx is still live) must
	// cancel the loop itself — otherwise the `<-loopDone` join there would block forever.
	// On the graceful path the parent ctx is already cancelled; this cancel is then a no-op.
	loopCtx, stopLoop := context.WithCancel(ctx)
	defer stopLoop()

	// Start the reconcile loop's single-goroutine owner (Observe per heartbeat + Resync on
	// cadence). It returns on the cancelled context at shutdown.
	loopDone := make(chan error, 1)
	go func() { loopDone <- cp.Reconcile.Run(loopCtx) }()

	// Start the CONVERGENCE SWEEPS off the SAME loopCtx so they share the reconcile loop's
	// lifecycle (cancelled on every Serve exit, joined below). All are nil-safe / self-disabling
	// — RunSessionIdleReap blocks-until-cancel when the reaper is disabled (TTL ≤ 0),
	// RunDestroyReDrive derives DefaultDestroyReDriveInterval, and RunMintExpiry's pass no-ops
	// without a MintReconverger (gate off) — so launching them unconditionally is safe. The
	// cadences are resolved SYNCHRONOUSLY here (on the calling goroutine, before any sweep
	// goroutine is spawned) so a test's cadence override is read once at Serve entry, never
	// concurrently from a spawned goroutine. A non-positive interval lets each sweep derive its own
	// cadence (the reaper from its TTL, the re-driver from DefaultDestroyReDriveInterval, the
	// credential-TTL backstop from the reconcile loop's full-resync cadence).
	idleReapInterval, destroyReDriveInterval, mintExpiryInterval := serveIdleReapInterval, serveDestroyReDriveInterval, serveMintExpiryInterval
	reapDone := make(chan error, 1)
	go func() { reapDone <- cp.RunSessionIdleReap(loopCtx, idleReapInterval) }()
	reDriveDone := make(chan error, 1)
	go func() { reDriveDone <- cp.RunDestroyReDrive(loopCtx, destroyReDriveInterval) }()
	// The §4.1 step-5 CREDENTIAL-TTL backstop (leg 1, doc 16 §5.4): re-arm / re-mint every live
	// record whose persisted §5.6 MintExpiry horizon is already past, through the installed
	// MintReconverger. UNCONDITIONAL launch is safe — with no reconverger wired (gate off) each
	// ReconcileMintExpiry pass is a documented no-op that does not even list (credttl.go), so a
	// non-live run still carries the uniform start-in-a-goroutine lifecycle and joins cleanly.
	mintExpiryDone := make(chan error, 1)
	go func() { mintExpiryDone <- cp.RunMintExpiry(loopCtx, mintExpiryInterval) }()

	// ARM the production read-stream content relay's pump lifetime off the SAME loopCtx (so
	// every per-session content pump is cancelled at shutdown). Start only records the base
	// context; the per-session pumps are started/stopped by the state-edge relay's ensure/
	// stop off the observed-session set (Register). A nil ContentRelay (no ContentSource
	// wired) is a clean no-op — the fan-out carries the control edges only.
	if cp.ContentRelay != nil {
		cp.ContentRelay.Start(loopCtx)
	}

	// Start the gRPC server on its own goroutine; grpc.Serve blocks until the server stops
	// (a GracefulStop or a fatal listener error).
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(lis) }()

	logger.InfoContext(ctx, "control plane serving",
		slog.String("addr", lis.Addr().String()))

	// joinSweeps drains the reconcile loop + the three convergence sweeps. They all run off
	// loopCtx, which is cancelled before this is reached on BOTH exit branches (the graceful
	// path's parent ctx is already cancelled; the fatal path cancels it via stopLoop), so each
	// returns ctx.Err() promptly — no goroutine leak on Serve return.
	joinSweeps := func() {
		<-loopDone       // the reconcile loop returns ctx.Err() on the cancelled context.
		<-reapDone       // the idle reaper returns ctx.Err() (or never sweeps when disabled).
		<-reDriveDone    // the destroy re-drive sweep returns ctx.Err().
		<-mintExpiryDone // the credential-TTL backstop returns ctx.Err() (no-op pass when unarmed).
	}

	select {
	case <-ctx.Done():
		// A shutdown signal: drain in-flight RPCs, stop accepting new ones, let the loop +
		// sweeps return on the same cancelled context. GracefulStop blocks until Serve returns.
		logger.InfoContext(ctx, "control plane shutting down (graceful stop)")
		srv.GracefulStop()
		<-serveDone // grpc.Serve returns nil after GracefulStop.
		joinSweeps()
		return nil
	case err := <-serveDone:
		// The server stopped on its own (a fatal listener error) before a shutdown signal —
		// surface it and tear down the reconcile loop + the sweeps. The parent ctx is still live
		// here, so their Run will not return on their own: cancel loopCtx to make them return,
		// THEN join (without this cancel the joins below would block forever). A nil err here
		// (an external Stop) is a clean stop.
		srv.Stop()
		stopLoop()
		joinSweeps()
		if err != nil {
			return fmt.Errorf("controlplane: gRPC serve: %w", err)
		}
		return nil
	}
}

// serveIdleReapInterval, serveDestroyReDriveInterval, and serveMintExpiryInterval are the
// cadences Serve drives the three convergence sweeps at. They default to 0 so each sweep derives
// its OWN production cadence (the idle reaper from its TTL, the destroy re-driver from
// DefaultDestroyReDriveInterval, the credential-TTL backstop from the reconcile loop's full-resync
// cadence) — Serve does NOT hard-code a cadence. They exist solely as a test seam so a Serve-level
// test can drive the sweeps FAST (a short tick) instead of waiting a 30-second / 30-minute real
// cadence; production never sets them (the zero value is the production path). Serve reads them
// ONCE, synchronously, at entry (into locals, before spawning any sweep goroutine) — and the
// package tests run sequentially — so a test setting them never races a concurrently-spawned sweep
// goroutine.
var (
	serveIdleReapInterval       time.Duration
	serveDestroyReDriveInterval time.Duration
	serveMintExpiryInterval     time.Duration
)
