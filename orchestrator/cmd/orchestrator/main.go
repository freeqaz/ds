// Command orchestrator is the stateless control-plane orchestrator:
// API replicas over external Postgres (D6), one of the two D35 services.
//
// It assembles (doc 15 §2) the three constructible control-plane components —
// the §4.1 session-create coordinator (internal/sessions), the level-triggered
// reconciler (internal/reconciler), and the §7 scheduler (internal/scheduler) —
// plus the orch18 scheduler.Adapter and the concrete Redriver, into a RUNNABLE
// control plane via internal/controlplane.NewControlPlane. This file is the THIN
// BOOTSTRAP (doc 15 §3/§4.1 "wired into main.go"): it constructs the backends,
// builds the ControlPlane, registers the orchestrator.v1 SessionService, starts
// the reconcile loop, and serves — the wiring logic lives in internal/controlplane
// so it is unit-tested without a live backend (D50).
//
// LIVE BACKENDS ARE ENV-GATED (D50). The host-agent hypervisor.v1 driver dials,
// the Identity (D22/D82) mint/digest/revoke service, the boundary CA-inject + boot
// verbs (host-folded into the host agent's CloneFromImage path), and the external
// Postgres store (D6) are REAL external backends. This bootstrap constructs the
// ControlPlane over them ONLY when DS_ORCH_LIVE=1; otherwise it prints the wiring it
// WOULD build and exits non-zero, so a CI/dev run never dials a live
// VM/host-agent/Identity service. The full live path now CLOSES end-to-end under
// DS_ORCH_LIVE=1 (dial → serve → CreateSession → reconcile): liveDeps resolves every
// deployment-input edge (the dialing host-driver registry, the dialed Identity clients,
// the external-Postgres-or-in-memory store) and NewControlPlane assembles them. The
// control-plane wiring itself (the three components + the adapter + the redriver) is
// fully assembled and unit-tested in internal/controlplane regardless — this gate only
// fences the live network edges.
//
// Never here: MintIdentity (a deliberately SEPARATE service, D22/D82 —
// identity/mint/), runtime-specific knowledge (D38/D20), long-lived
// credentials (D39), host bootstrap config over the policy stream (doc 14 §11).
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/parkstore"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/policylog"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

func main() {
	if os.Getenv("DS_ORCH_LIVE") != "1" {
		// Not a live run: the control-plane wiring is fully constructible (and unit-
		// tested in internal/controlplane), but the live network edges — the host-agent
		// hypervisor.v1 driver dials, the Identity D22/D82 mint/digest/revoke service,
		// and the boundary CA-inject + boot verbs — are real external services this
		// bootstrap will not dial without DS_ORCH_LIVE=1 and configured endpoints (D50:
		// no live VM/host-agent/Identity dial outside an explicit live run). Print the
		// wiring this bootstrap assembles and exit non-zero.
		fmt.Fprintln(os.Stderr, "ds orchestrator: control-plane wiring assembled (internal/controlplane.NewControlPlane):")
		fmt.Fprintln(os.Stderr, "  (a) orchestrator.v1 SessionService.CreateSession -> sessions.SessionCreator (§4.1 ten-step)")
		fmt.Fprintln(os.Stderr, "  (b) reconciler driving loop -> Observe(heartbeat)/Resync(cadence), ConcreteRedriver wired (§3)")
		fmt.Fprintln(os.Stderr, "  (c) scheduler.Adapter injected as the SessionCreator Placer (§4.1 step 3 / §7)")
		fmt.Fprintln(os.Stderr, "the full live path closes end-to-end (dial -> serve -> CreateSession -> reconcile); set DS_ORCH_LIVE=1 to run it")
		fmt.Fprintln(os.Stderr, "  env: DS_ORCH_LISTEN, DS_ORCH_HOST_DRIVERS (host_id=addr,...), DS_ORCH_IDENTITY_ENDPOINT, DS_ORCH_PG_DSN (+ DS_PG_DRIVER; unset => in-memory store)")
		os.Exit(2)
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ds orchestrator: %v\n", err)
		os.Exit(1)
	}
}

// run is the live bootstrap: it builds the ControlPlane over the configured live
// backends, registers the SessionService, starts the reconcile loop, and serves until
// a shutdown signal. It is reachable ONLY under DS_ORCH_LIVE=1 — the backends it needs
// (a configured DriverRegistry over dialed host drivers, the Identity D22/D82 clients,
// the boundary inject/boot verbs, the external Postgres) are live services, so a
// non-live run never reaches here (D50). The deployment-input edges (the store +
// Identity clients) are now resolved by liveDeps; their connections are closed at
// shutdown via the returned closer so a graceful stop tears the live edges down.
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	deps, closeEdges, err := liveDeps(ctx)
	if err != nil {
		return fmt.Errorf("resolve live backends: %w", err)
	}
	defer func() {
		if cerr := closeEdges(); cerr != nil {
			fmt.Fprintf(os.Stderr, "ds orchestrator: close live edges: %v\n", cerr)
		}
	}()

	cp, err := controlplane.NewControlPlane(deps)
	if err != nil {
		return fmt.Errorf("build control plane: %w", err)
	}

	// Mount the expvar /debug/vars admin surface so the §4.1 step-9 freshness-degrade
	// observables (D72) are READABLE in production (the runbook's curl target). Concretely,
	// the `orchestrator_sessions_step9_freshness_degrade_total` counter (and its per-host
	// map + resolved cap) that internal/sessions registers on the process-global stdlib
	// expvar registry has no other server — startAdminServer's expvar.Handler() mount at
	// /debug/vars is the one socket that renders it. It is armed only when DS_ORCH_ADMIN_ADDR
	// is set — and reachable only under this DS_ORCH_LIVE=1 bootstrap (D50) — so a non-live
	// run and an unset addr bind no admin socket. The returned closer graceful-stops the
	// admin server as part of the run() shutdown path (it drains on its own bounded context,
	// so it stays correct even after the bootstrap ctx has cancelled).
	//
	// LIVENESS READOUT WIRING (D35/D72). The admin surface ALSO renders the per-host
	// LIVE/UNKNOWN view from reconciler.HealthSnapshot() (the queryable form of the §3 /
	// §5.2 missed-beat UNKNOWN annotation an operator otherwise scrapes the alarm log for).
	// The reconciler's HealthSnapshot() is a SINGLE-GOROUTINE reader of lastBeat that the
	// reconcile loop writes concurrently (health.go / reconciler.go: no mutex; the loop owns
	// the one goroutine), so rendering a RAW live reconciler from the admin HTTP goroutine
	// would be a data race. The surface is therefore armed with the LOOP-SERIALIZED
	// snapshotter: its HealthSnapshot() marshals the read onto the reconcile-loop goroutine
	// (the sole lastBeat owner) — no second writer, no bare cross-goroutine read — so
	// /debug/liveness and the orchestrator_host_liveness expvar var render real LIVE/UNKNOWN.
	// It is bound to the bootstrap ctx so a query around shutdown returns promptly instead of
	// blocking on the stopping loop. The admin server is started AFTER NewControlPlane so the
	// loop the snapshotter queries exists; its closer is a deferred LIFO stop on the run()
	// shutdown path.
	//
	// NEVER-SEEN ENRICHMENT (the wired-here arm of the landed-but-inert seam, doc 15 §3/§5.2).
	// The bare cp.LivenessSnapshotter only renders the hosts the reconciler has HEARD from, so
	// a host that has a placed session but has NEVER heartbeated is ABSENT from /debug/liveness
	// — invisible exactly when an operator most needs it (a host that silently never came up).
	// We arm the OPT-IN cp.LivenessSnapshotterIncluding instead, threading a store-backed
	// ExpectedHostSupplier (storeExpectedHosts over deps.Store): per snapshot it enumerates the
	// distinct host_ids of the live (non-DESTROYED) session records — the hosts that SHOULD be
	// reporting — so the loop-serialized HealthSnapshotIncluding folds an expected-but-silent
	// host in as EverSeen=false / UNKNOWN rather than omitting it. The supplier is evaluated on
	// the reconcile-loop goroutine, so it MUST be non-blocking and return a fresh caller-owned
	// slice (the contract serve_test.go pins); storeExpectedHosts satisfies both — a fast
	// in-memory ListSessions over the live store, returning a new slice each call. It stays
	// purely additive: a supplier returning empty (no live sessions) degrades to today's
	// heard-from-only view byte-for-byte. Reached ONLY under this DS_ORCH_LIVE=1 bootstrap (D50).
	liveness := cp.LivenessSnapshotterIncluding(ctx, storeExpectedHosts(deps.Store))
	_, closeAdmin, err := startAdminServer(adminAddr(), liveness)
	if err != nil {
		return fmt.Errorf("start admin surface: %w", err)
	}
	defer func() {
		if cerr := closeAdmin(); cerr != nil {
			fmt.Fprintf(os.Stderr, "ds orchestrator: close admin surface: %v\n", cerr)
		}
	}()

	// REAL boundary.v1.SuspendSignal FEED TERMINATION (suspendwire — doc 15 §4.3, doc 09 §8).
	// The boundary pushes the frozen SuspendSignal stream; the orchestrator terminates it via
	// cp.SuspendTerminator (validate+map+dedup → hypervisor.v1.SuspendRequest) and drives the
	// request on cp.ParkResume.Suspend. The feed is a LIVE boundary push edge this orchestrator
	// does NOT own the transport for (the boundary's Stage-0 freeze), so its consumer loop is a
	// DEFERRED live step fenced behind DS_ORCH_SUSPEND_FEED: unset (the default even under
	// DS_ORCH_LIVE) it is inert and the suspend termination path is exercised only by the
	// in-memory cp.SuspendTerminator + fakes in tests (D50 — never a live boundary dial in CI);
	// set, the deployment supplies the boundary feed dial and arms the consumer (the dial impl
	// is the deferred boundary-transport step, refused with a clear message until it lands).
	if err := startSuspendFeed(ctx, cp); err != nil {
		return fmt.Errorf("suspend-signal feed: %w", err)
	}

	// REAL INBOUND-ASK ROUTING FEED (askwire — doc 15 §4.3 / §6.2 step 4, doc 16 §8.2; D46).
	// The boundary raises the frozen one-way boundary.v1.AskUserRequest; the orchestrator routes
	// it through policylog.Service.RouteAsk, which on a GENUINE rung-2 ask enters it into the
	// DURABLE D46 park via cp.AskParkRouter (the *parkMachine) — never a timeout into allow or
	// kill. startAskFeed constructs the live policylog.Service and hands cp.AskParkRouter to its
	// RouteAsk dispatch, but the live inbound-ask gRPC TRANSPORT (the boundary AskUser push edge,
	// a stream the boundary owns) is NOT this orchestrator's to stand up — it exceeds one PR — so
	// the consumer loop is a DEFERRED live step fenced behind DS_ORCH_ASK_FEED (mirroring the
	// suspend feed). Gate-off / unset it is inert (RouteAsk + the park enrollment are exercised by
	// the in-memory live-smoke + synthetic fakes, never a live boundary dial — D50). The full
	// follow-up note for the real transport rides startAskFeed's header.
	if err := startAskFeed(ctx, cp, deps.Store); err != nil {
		return fmt.Errorf("inbound-ask routing feed: %w", err)
	}

	// Start the reconcile loop (the single-goroutine convergence owner) and serve the
	// SessionService over gRPC. With the deployment-input edges resolved above the live
	// path now closes end-to-end: dial (the host-driver registry + the Identity dial) →
	// serve (controlplane.Serve registers SessionService + the heartbeat ingest, starts
	// the reconcile loop) → CreateSession (the §4.1 spine over the live store + seams) →
	// reconcile (the level-triggered loop over the live store + driver registry).
	return serve(ctx, cp)
}

// startSuspendFeed arms the DEFERRED boundary.v1.SuspendSignal feed consumer (suspendwire).
// It is fenced behind DS_ORCH_SUSPEND_FEED: unset it is a no-op (the suspend termination is
// exercised by cp.SuspendTerminator + fakes in tests, never a live boundary dial — D50);
// set, the boundary feed transport dial is the deferred step the boundary owns (doc 15 §2.1
// / doc 09 §8 Stage-0 freeze), refused here with a clear message until a deployment supplies
// it. When wired, the consumer hands each pushed signal to cp.SuspendTerminator.Accept and,
// on Accepted, drives the resulting hypervisor.v1.SuspendRequest on cp.ParkResume.Suspend —
// the orchestrator side of the D77 termination, all over the components NewControlPlane built.
func startSuspendFeed(_ context.Context, cp *controlplane.ControlPlane) error {
	if os.Getenv("DS_ORCH_SUSPEND_FEED") != "1" {
		slog.Default().Info("ds orchestrator: boundary.v1.SuspendSignal feed consumer NOT armed (DS_ORCH_SUSPEND_FEED unset) — suspend termination wired (cp.SuspendTerminator → cp.ParkResume) but no live boundary feed; the live feed dial is the deferred boundary-transport step (doc 15 §2.1)")
		return nil
	}
	if cp.SuspendTerminator == nil || cp.ParkResume == nil {
		return fmt.Errorf("control plane did not build the suspend termination components (terminator/park-resume)")
	}
	return fmt.Errorf("live boundary.v1.SuspendSignal feed dial is the deferred boundary-transport step (doc 15 §2.1 / doc 09 §8) — not implemented in this binary; unset DS_ORCH_SUSPEND_FEED to run without it")
}

// startAskFeed arms the DEFERRED boundary.v1.AskUserRequest inbound-ask routing feed (askwire,
// doc 15 §4.3 / §6.2 step 4, doc 16 §8.2; D46). It CONSTRUCTS the live policylog.Service over the
// live policy_log store and is the call-site that hands cp.AskParkRouter to the Service's RouteAsk
// dispatch — so a GENUINE rung-2 ask enters the DURABLE D46 park (cp.ParkMachine) end to end via
// the *parkMachine, never timing out into allow or kill (the load-bearing D46/D77 invariant).
//
// It is fenced behind DS_ORCH_ASK_FEED (mirroring DS_ORCH_SUSPEND_FEED): unset it is a no-op (the
// RouteAsk park dispatch is exercised by the in-memory live-smoke + synthetic fakes, never a live
// boundary dial — D50); set, the boundary's inbound-ask gRPC transport dial is the deferred step
// the boundary owns (a stream the boundary pushes, doc 15 §2.1 / doc 09 §8), refused here with a
// clear message until a deployment supplies it. We construct the Service even on the no-op path so
// the wiring is proven constructible (the live store satisfies the policy_log seam) and the
// cp.AskParkRouter hand-off is structural — NOT a half-wired unbounded transport.
//
// FULLY-SPECIFIED FOLLOW-UP (the real inbound-ask transport leg, deferred). When the boundary's
// AskUser push edge lands, the armed branch wires a consumer that, per pushed
// boundaryv1.AskUserRequest: (1) computes RouteAskParams (the human Decision class, the D78
// Attended signal the orchestrator derives, the Rung2 classification off the matched POL-3 rule,
// the injected POL-1 askhold.Window, the consent class, and the composed GrantBody); (2) calls
// svc.RouteAsk(ctx, router=<live store as askRouteRouter>, resolver=<live store as
// askApproverResolver>, sink=<the LOG-1 AskEventSink>, park=cp.AskParkRouter, ask, params); and
// (3) returns the AskFlowResult to the boundary. A rung-2 ask then lands in cp.ParkMachine via the
// injected park router exactly as the live-smoke asserts. The transport dial + the LOG-1 sink
// wiring are the only remaining pieces; the routing core (RouteAsk + the park enrollment) is live
// now and exercised end-to-end by the DS_ORCH_LIVE-gated live-smoke (D50).
func startAskFeed(_ context.Context, cp *controlplane.ControlPlane, st controlplane.ControlPlaneStore) error {
	// Construct the live policylog.Service over the live policy_log store. The live store
	// (*store.Memory / *store.Postgres) satisfies the policy_log read/write seam natively; a
	// test-narrowed store that does not exposes the inbound-ask feed as unavailable rather than
	// failing the whole live run (the create + reconcile paths are unaffected). The composer is
	// the watch-path seam RouteAsk never touches (it is the WatchPolicies compose, not the
	// ask-routing dispatch), wired here as a fail-closed default so the Service is complete.
	plStore, ok := st.(policyLogStore)
	if !ok {
		slog.Default().Warn("ds orchestrator: inbound-ask routing feed NOT armed — the live store does not expose the policy_log ask-routing seam (AppendPolicy/ListPolicy/LiveGrants); RouteAsk park enrollment unavailable (create/reconcile paths unaffected)")
		return nil
	}
	svc := policylog.NewService(plStore, askFeedComposer{})

	if os.Getenv("DS_ORCH_ASK_FEED") != "1" {
		slog.Default().Info("ds orchestrator: boundary.v1.AskUserRequest inbound-ask feed consumer NOT armed (DS_ORCH_ASK_FEED unset) — policylog.Service constructed and cp.AskParkRouter is the live RouteAsk park dispatch (a rung-2 ask enters the durable D46 park, doc 16 §8.2), but no live boundary feed; the live feed dial is the deferred boundary-transport step (doc 15 §2.1)",
			"ask_park_router_armed", cp.AskParkRouter != nil)
		_ = svc // constructed to prove the wiring; the consumer loop is the deferred transport step.
		return nil
	}
	if cp.AskParkRouter == nil {
		// Gate-off (DS_ORCH_LIVE) leaves AskParkRouter nil; an armed feed without it would route no
		// durable park — refuse loudly rather than silently dropping rung-2 parks.
		return fmt.Errorf("inbound-ask feed armed (DS_ORCH_ASK_FEED=1) but cp.AskParkRouter is nil — the *parkMachine ask-park router is DS_ORCH_LIVE-gated (leg 3); a rung-2 ask would enter no durable D46 park")
	}
	return fmt.Errorf("live boundary.v1.AskUserRequest inbound-ask feed dial is the deferred boundary-transport step (doc 15 §2.1 / doc 09 §8) — not implemented in this binary; the routing core (policylog.Service.RouteAsk handing cp.AskParkRouter the rung-2 park) is live and exercised by the DS_ORCH_LIVE live-smoke; unset DS_ORCH_ASK_FEED to run without it")
}

// policyLogStore is the NARROW policy_log read/write seam policylog.NewService consumes (the
// ask-routing WRITE + deny-memo read + replay list). It mirrors policylog's own (unexported)
// policyStore shape so startAskFeed can type-assert the live store (narrowed to
// controlplane.ControlPlaneStore) onto it WITHOUT widening ControlPlaneStore — *store.Memory and
// *store.Postgres satisfy it natively (the store package stays frozen). Declared here (a slice of
// the existing reads/writes) so the inbound-ask feed depends on exactly the surface it uses, the
// same discipline liveGrantReader follows above.
type policyLogStore interface {
	AppendPolicy(ctx context.Context, row store.PolicyLogRow) (store.PolicyLogRow, error)
	ListPolicy(ctx context.Context, fromSeq int64, limit int) ([]store.PolicyLogRow, error)
	LiveGrants(ctx context.Context, sessionUUID string, now time.Time) ([]store.PolicyLogRow, error)
}

// askFeedComposer is the fail-closed default SnapshotComposer the inbound-ask policylog.Service is
// constructed with. The ask-routing dispatch (RouteAsk → cp.AskParkRouter park enrollment) NEVER
// invokes the composer — it is the WatchPolicies compose seam (doc 13 §5), a SEPARATE leg whose
// real POL-1 layer/grant decoders live in ds-contracts (doc 13 §3). The inbound-ask feed binary
// does not serve WatchPolicies, so this composer is never reached; it is a fail-closed stand-in
// (an empty snapshot) so the Service is complete and the ask-routing wiring is provable without
// pulling the ds-contracts decoders into this bootstrap.
type askFeedComposer struct{}

func (askFeedComposer) ComposeAt(_ context.Context, seq int64, _ []store.PolicyLogRow, _ time.Time) (policylog.Snapshot, error) {
	return policylog.Snapshot{Seq: seq}, nil
}

// liveDeps resolves the live backends NewControlPlane needs and returns a closer that
// tears down the live connections at shutdown (the dialed Identity conn + the Postgres
// pool). ALL edges are now FILLED, each still env-gated behind this DS_ORCH_LIVE=1 run
// (D50 — a non-live run never reaches here):
//
//   - leg (a) host-driver dial: the per-host hypervisor.v1 DriverRegistry is the dialing,
//     caching controlplane.NewDialRegistry over the DS_ORCH_HOST_DRIVERS endpoint map
//     (host_id=addr pairs, each dialed client wrapped in a controlplane.ClientShim).
//   - external Postgres store (D6): controlplane.NewPostgresStore opens *store.Postgres
//     from DS_ORCH_PG_DSN (driver DS_PG_DRIVER, default "postgres" — the operator
//     registers a Postgres driver at the binary boundary, D33). Absent a DSN the live run
//     uses *store.Memory (the single-binary in-memory posture) so a dev live run closes
//     without an external DB; a configured DSN selects Postgres.
//   - Identity D22/D82 mint/digest/revoke clients: controlplane.NewIdentityClients dials
//     the identity.v1 mint + digest faces at DS_ORCH_IDENTITY_ENDPOINT, plus the
//     host-folded CA-inject + boot verbs (steps 7–8, executed host-side in CloneFromImage).
//     The dial defaults to the internal, network-isolated insecure link (doc 15 §2); a
//     deployment fronting the edge with mTLS supplies the SAME DS_ORCH_TLS_CERT/KEY/CA
//     triplet the host-driver dial reads, which liveDialOpts turns into the
//     transport-credentials DialOption threaded onto NewIdentityClients's variadic tail —
//     the SAME tail (resolved once) the host-driver registry dial carries.
//
// The control-plane wiring (NewControlPlane) that consumes these is complete and
// unit-tested in internal/controlplane; this function is the thin live-edge resolver.
func liveDeps(_ context.Context) (controlplane.Deps, func() error, error) {
	closers := newCloserChain()

	endpoints, err := parseHostDrivers(os.Getenv("DS_ORCH_HOST_DRIVERS"))
	if err != nil {
		return controlplane.Deps{}, closers.close, err
	}
	// Resolve the mTLS dial-option tail ONCE, here, and share it across BOTH live dial legs
	// below (the host-driver registry dial AND the Identity dial). Both edges front the same
	// internal, network-isolated D35 control-plane fabric (doc 15 §2) with the SAME env triplet
	// (DS_ORCH_TLS_CERT/KEY/CA), so they MUST carry one transport posture: liveDialOpts is the
	// single transport-neutral composition point that turns that triplet into the variadic
	// DialOption tail. With the env unset the tail is empty and each constructor keeps its
	// insecure default unchanged; a half-configured triplet fails loudly here rather than at the
	// first dial. Sharing the one resolved slice makes the "same posture for both edges"
	// invariant structural — the two legs cannot silently diverge.
	dialOpts, err := liveDialOpts()
	if err != nil {
		return controlplane.Deps{}, closers.close, fmt.Errorf("orchestrator live dial mTLS transport: %w", err)
	}

	// Leg (a): the per-host HypervisorDriver registry. Its dial DIRECTION is the D19
	// deployment tier (doc 15 §2.1; resolveDriverRegistry):
	//   - HOSTED (the default): controlplane.NewDialRegistry over the configured
	//     DS_ORCH_HOST_DRIVERS endpoints — the orchestrator dials each host agent OUTBOUND,
	//     carrying the shared mTLS tail (or the insecure default for the network-isolated
	//     internal link). Cached connections close at shutdown.
	//   - BRING-COMPUTE (DS_ORCH_BRING_COMPUTE=1): the customer's NAT'd host agent dials OUT
	//     to the orchestrator's listener (D19 outbound-only mTLS, no inbound holes) and the
	//     orchestrator routes the HypervisorDriver verbs back over that inbound-established
	//     connection — controlplane.NewInboundDriverRegistry. The host-agent-initiated
	//     connection-accept transport (identify the dialing host, capture its *grpc.ClientConn,
	//     Register it) is the deferred-manual reverse-link step the customer's bring-compute
	//     dialer pairs with (resolveDriverRegistry env-gates + documents it). Either registry
	//     satisfies controlplane.DriverRegistry, so NewControlPlane consumes it identically.
	drivers, driverClose, err := resolveDriverRegistry(endpoints, dialOpts...)
	if err != nil {
		return controlplane.Deps{}, closers.close, err
	}
	closers.add(driverClose)

	// External Postgres (D6) when DS_ORCH_PG_DSN is set, else the in-memory store (the
	// single-binary posture) — so a dev live run closes the path without an external DB.
	// resolveStore ALSO surfaces the raw *sql.DB it opened for the Postgres path (nil for the
	// in-memory path) so the durable D46 park backing below can be fronted by parkstore.SQL
	// over the SAME pool the store reads — one connection, one driver registration, closed once.
	store, storeDB, storeClose, err := resolveStore()
	if err != nil {
		return controlplane.Deps{}, closers.close, err
	}
	closers.add(storeClose)

	// Seed the §4.1 step-1 env config (D56) into the in-memory store when
	// DS_ORCH_SEED_ENV_CONFIG is set, so a fresh single-binary live run can complete
	// CreateSession before the env-spec write RPC lands (no-op when unset; refuses on the
	// Postgres path, which seeds via the DB). MUST run after resolveStore (it needs the
	// resolved store) and before NewControlPlane reads it.
	if err := seedEnvConfig(store); err != nil {
		return controlplane.Deps{}, closers.close, fmt.Errorf("seed env config: %w", err)
	}

	// Identity D22/D82 mint/digest/revoke + the host-folded inject/boot (steps 7–8). The
	// orchestrator→Identity link is the internal D35 control-plane fabric (doc 15 §2); by
	// default it keeps NewIdentityClients's network-isolated insecure transport. A deployment
	// fronting the edge with mTLS supplies the SAME DS_ORCH_TLS_CERT/KEY/CA triplet the
	// host-driver dial reads — so this leg threads the SAME dialOpts tail resolved once above
	// (liveDialOpts), not an independently re-derived one: both live edges provably draw from
	// one mTLS source. With the env unset the tail is empty and the insecure default applies
	// unchanged; a half-configured triplet already failed loudly at the shared resolve above.
	// MVP NO-AUTH posture (DS_ORCH_FAKE_IDENTITY=1, maintainer-approved, single-box): an in-process
	// loopback identity backend replaces the real Identity dial so a fresh `serpent claude`
	// -> orchestrator -> KVM-VM run completes CreateSession without a deployed identity.v1
	// service (the VM runs SLIRP-direct egress with the OAuth token injected, so the
	// per-session interception CA the mint produces is never load-bearing here). With the
	// gate UNSET the production path is unchanged — a real Identity endpoint is dialed and an
	// empty DS_ORCH_IDENTITY_ENDPOINT still fails loudly. Reached ONLY here under DS_ORCH_LIVE
	// (D50). The fake's mint drops a throwaway CA bundle under the host overlay dir so the
	// co-located host-agent's step-7 inject consumer resolves it (see AttachCABundleStore below).
	var identity *controlplane.IdentityClients
	if os.Getenv("DS_ORCH_FAKE_IDENTITY") == "1" {
		identity = newFakeIdentityClients(slog.Default())
		slog.Default().Warn("ds orchestrator: DS_ORCH_FAKE_IDENTITY=1 — using the IN-PROCESS NO-AUTH loopback identity backend (MVP, single-box). NO real credential is minted; do NOT use outside a contained dev box")
	} else {
		identity, err = controlplane.NewIdentityClients(os.Getenv("DS_ORCH_IDENTITY_ENDPOINT"), nil, dialOpts...)
		if err != nil {
			return controlplane.Deps{}, closers.close, fmt.Errorf("identity backends: %w", err)
		}
	}
	closers.add(identity.Close)

	// HOST-READABLE CA-BUNDLE PRODUCER (option A, D17/D82): drop the minted CA cert PEM under
	// <overlay-dir>/.ds-ca-bundles/<caRef>.pem so the co-located host-agent's §4.1 step-7
	// FetchCABundle consumer resolves it (de-stubbing the placeholder PEM) — closing the loop
	// so a real CreateSession injects the orchestrator-minted CA with no hand-seeded store. It
	// is opt-in behind DS_ORCH_OVERLAY_DIR (the SAME dir the host-agent's -overlay-dir uses on
	// this box); unset, the Mint seam keeps its bare no-drop posture (a deployment with a
	// pre-seeded host store, or a non-co-located host, is unaffected). It rebinds only the
	// production liveMint seam (the fake mint is liveMint-backed via NewIdentityClientsFromWire,
	// so the throwaway CA is dropped too — exactly what the MVP host-agent needs to inject).
	// attachModeReader is the OPTIONAL per-session resolved-mode source the attach endpoint
	// resolver reads to TAG the issued endpoint's transport (RAW_TERMINAL vs DIRECT). It is
	// the SAME <overlay-dir>/.ds-session-mode marker store the co-located host-agent's
	// EntrypointProducer wrote (libvirt.NewFileSessionModeStore), so in the single-box MVP —
	// where THIS control-plane resolver (not the host-agent minter) answers serpent-tui's
	// Attach — a terminal session's handle carries a RAW_TERMINAL candidate and
	// `serpent claude --vm --raw on` takes the terminal path instead of the structured
	// fallback (the U-CPWIRE live-found bug). Left nil unless DS_ORCH_OVERLAY_DIR is set (the
	// fail-safe default: no overlay dir ⇒ no marker to read ⇒ every session tags DIRECT,
	// byte-identical to before). It is a host-resolved DELIVERY TAG, not a runtime semantic —
	// the orchestrator stays D38-runtime-ignorant.
	var attachModeReader libvirt.SessionModeStore
	// writerAttachAuth is the W2 D39 attach-auth seam (Deps.WriterAttachAuth): the
	// production adapter over the host-side fileAttachTokenStore the IssueAttachHandle
	// minter issues from (writerauth_live.go), so a RequestWriterSeat's attach_auth is
	// validated against the SAME per-session token file the handle carried. It is built
	// ONLY inside the DS_ORCH_OVERLAY_DIR block below (the store lives under the overlay
	// dir); left nil otherwise ⇒ the WriterRelayService refuses PermissionDenied
	// (fail-closed — the seat requires a valid attach, D39).
	var writerAttachAuth controlplane.AttachAuthValidator
	if overlayDir := os.Getenv("DS_ORCH_OVERLAY_DIR"); overlayDir != "" {
		if err := identity.AttachCABundleStore(overlayDir); err != nil {
			return controlplane.Deps{}, closers.close, fmt.Errorf("attach CA-bundle producer over %q: %w", overlayDir, err)
		}
		modeStore, mErr := libvirt.NewFileSessionModeStore(overlayDir)
		if mErr != nil {
			return controlplane.Deps{}, closers.close, fmt.Errorf("attach session-mode reader over %q: %w", overlayDir, mErr)
		}
		attachModeReader = modeStore
		attachAuth, aErr := newAttachTokenAuthValidatorForOverlay(overlayDir)
		if aErr != nil {
			return controlplane.Deps{}, closers.close, fmt.Errorf("writer attach-auth validator over %q: %w", overlayDir, aErr)
		}
		writerAttachAuth = attachAuth
		slog.Default().Info("ds orchestrator: host-readable CA-bundle producer + per-session mode reader + W2 attach-auth validator attached — minted CA certs drop and the .ds-session-mode markers are read under the host overlay dir for the co-located host-agent (DS_ORCH_OVERLAY_DIR); the attach resolver tags RAW_TERMINAL for terminal sessions; RequestWriterSeat validates attach_auth against the host-agent's per-session attach-token store (D39)",
			"overlay_dir", overlayDir)
	}

	// W2 D22/D55 human-identity seam (Deps.WriterIdentity): resolves a RequestWriterSeat's
	// identity_assertion to the driver_identity that becomes the seat attribution (doc 15
	// §5.4). The REAL D55/SSO identity face is the dialed validator in writerauth_live.go
	// (selected by DS_ORCH_SSO_ISSUER, armed by DS_ORCH_SSO_LIVE): it verifies the assertion
	// by OIDC discovery + JWKS signature verification, standard-library only (no importable
	// SSO client — the orchestrator may not import the identity/SSO module, D80). In the
	// single-box MVP the web/SSO tier has already verified the principal, so — fenced behind
	// the SAME DS_ORCH_FAKE_IDENTITY gate that selects the no-auth mint (fakeidentity.go) —
	// the in-process MVP validator (writerauth_live.go) resolves that pre-verified assertion:
	// passthrough by default (any non-empty assertion → itself), or a CLOSED fixture set
	// when DS_ORCH_MVP_IDENTITY pins assertion=driver pairs. Left nil when neither gate is
	// set ⇒ the WriterRelayService refuses Unauthenticated (fail-closed — no seat without a
	// wired human-identity check). The gate → validator resolution lives in
	// resolveWriterIdentityValidator (writerauth_live.go) so the wiring slice is
	// offline-testable: gates off ⇒ a nil seam here; malformed DS_ORCH_MVP_IDENTITY ⇒ a
	// loud construction error.
	writerIdentity, identityMode, wiErr := resolveWriterIdentityValidator(os.Getenv)
	if wiErr != nil {
		return controlplane.Deps{}, closers.close, wiErr
	}
	// Dispatch the loud dev-box warning vs the production-SSO note on the TYPED mode enum
	// (not a string prefix) so a mode-label edit can never silently suppress the warning.
	switch identityMode {
	case writerIdentityDialedSSO:
		// DS_ORCH_SSO_ISSUER selected the PRODUCTION dialed SSO/OIDC validator — the real
		// D55 identity face slotted onto the seam. It verifies the assertion by OIDC
		// discovery + JWKS signature verification and fails CLOSED on every fault; until
		// DS_ORCH_SSO_LIVE arms the handshake it grants no seat on an unverified assertion.
		slog.Default().Info("ds orchestrator: W2 RequestWriterSeat identity_assertion validated by the DIALED D55/SSO identity validator (OIDC discovery + JWKS verify; fail-closed on dial/verify faults; armed by DS_ORCH_SSO_LIVE)",
			"mode", identityMode.String())
	case writerIdentityMVPPassthrough, writerIdentityMVPAllowMap:
		slog.Default().Warn("ds orchestrator: DS_ORCH_FAKE_IDENTITY=1 — W2 RequestWriterSeat identity_assertion validated by the IN-PROCESS no-auth MVP validator (single-box; the web/SSO tier pre-verifies the principal). NO real SSO check; set DS_ORCH_SSO_ISSUER to select the dialed D55/SSO validator instead. Do NOT use outside a contained dev box",
			"mode", identityMode.String())
	}

	// W3 host-agent relay seam (Deps.WriterDriveSink): the OUTBOUND write leg that forwards
	// an ADMITTED DriveInput onto the host-agent's per-session bridge over the framed-UDS
	// RELAY carrier (drivesink_live.go). It is gated on DS_ORCH_OVERLAY_DIR (the host-agent's
	// per-session attach-token store home the relay attach authenticates against): unset ⇒ a
	// nil seam here and DriveSession refuses Unavailable fail-closed (no live relay ⇒ an
	// admitted frame is never silently dropped); set ⇒ the live sink over the overlay token
	// store + the attach socket dir. The resolution lives in resolveWriterDriveSink so the
	// wiring slice is offline-testable; a construction fault (an unreadable token store) is a
	// loud error. The sink's Close (tears down cached per-session writer conns) rides the
	// closer chain.
	writerDriveSink, driveSinkClose, wdErr := resolveWriterDriveSink(os.Getenv)
	if wdErr != nil {
		return controlplane.Deps{}, closers.close, fmt.Errorf("writer drive sink: %w", wdErr)
	}
	// The sink's closer joins the chain BEFORE any later seam resolution can error out, so a
	// fault below (e.g. the content source) still tears the sink down via the returned close.
	closers.add(driveSinkClose)
	if writerDriveSink != nil {
		slog.Default().Info("ds orchestrator: W3 DriveSession write leg attached — an admitted DriveInput is forwarded onto the host-agent's per-session bridge over the framed-UDS RELAY carrier (DS_ORCH_OVERLAY_DIR token store; DS_ORCH_ATTACH_SOCKET_DIR dial dir)")
	}

	// READ-STREAM content seam (Deps.ContentSource): the INBOUND read leg that attaches to
	// the host-agent's per-session bridge as a D61 READER over the SAME framed-UDS RELAY
	// carrier, decodes the bridge's frameEvent stream, and feeds each decoded CC content
	// event into the WatchSession fan-out (contentsource_live.go — the read-ward twin of the
	// W3 write leg). It is gated on the SAME DS_ORCH_OVERLAY_DIR token store: unset ⇒ a nil
	// source and NewControlPlane leaves the content relay unconstructed (the fan-out carries
	// only the control edges — the documented degrade, doc 15 §5.3); set ⇒ the live source
	// over the overlay token store + the attach socket dir. The resolution lives in
	// resolveContentSource so the wiring slice is offline-testable; a construction fault (an
	// unreadable token store) is a loud error. No closer: the source caches no state (each
	// per-session pump is owned by the relay's serve-lifetime context, cancelled at shutdown).
	contentSource, csErr := resolveContentSource(os.Getenv)
	if csErr != nil {
		return controlplane.Deps{}, closers.close, fmt.Errorf("content source: %w", csErr)
	}
	if contentSource != nil {
		slog.Default().Info("ds orchestrator: read-stream content relay attached — CC's projected content is read from the host-agent's per-session bridge as a D61 READER over the framed-UDS RELAY carrier and fanned out to every N-reader (DS_ORCH_OVERLAY_DIR token store; DS_ORCH_ATTACH_SOCKET_DIR dial dir)")
	}

	// SHARED live heartbeat feed (D72 step-9). Own ONE *HeartbeatStore here and supply it
	// as Deps.Heartbeats so the scheduler's candidate feed (StoreCandidateSource) and the
	// §4.1 step-9 LIVE freshness probe (the scheduler.Adapter's HostFreshness seam) read the
	// SAME latest-per-host feed — a placement and its step-9 re-check then agree on what a
	// host last reported. Absent this, NewControlPlane installs a fresh in-process feed for
	// candidates and the step-9 probe has none, so the residual D72 window stays open (the
	// recorded-only re-check). The reconcile loop records every inbound heartbeat into this
	// feed (controlplane.Serve), so both readers see the live host state. The HostFreshness
	// seam over this feed is constructed by liveFreshness below.
	heartbeats := controlplane.NewHeartbeatStore(nil)

	// roles.v1 RoleCatalogService READ path (ListRoles / GetRole, doc 18 §6; D89–D96),
	// backed by the checked-in roles/ catalog (the built-in four, D50/D93). Served
	// wherever CreateSession is (incl. orchestrator-lite, D80) via controlplane.Register.
	// A load fault (the roles/ tree is unreadable) leaves the read API unregistered
	// rather than failing the whole live run — the create path is unaffected.
	roleCatalog, rcErr := controlplane.NewRoleCatalogServiceFromDir(rolesCatalogDir(), slog.Default())
	if rcErr != nil {
		slog.Default().Warn("ds orchestrator: roles.v1 RoleCatalogService NOT served — role catalog load failed (read API unregistered; create path unaffected)",
			"dir", rolesCatalogDir(), "err", rcErr)
		roleCatalog = nil
	}

	deps := controlplane.Deps{
		Store:       store,
		Drivers:     drivers,
		Heartbeats:  heartbeats,
		Mint:        identity.Mint,
		Digest:      identity.Digest,
		Inject:      identity.Inject,
		Boot:        identity.Boot,
		Revoke:      identity.Revoke,
		Enrollment:  enrollmentResolver(),
		Roles:       roleResolver(),
		RoleCatalog: roleCatalog,
		DefaultOrg:  os.Getenv("DS_ORCH_DEFAULT_ORG"),
		// AttachSocketDir advertises the SAME host-local UDS directory the host-agent serves
		// the per-session writer-seat attach socket under (its -attach-socket-dir). The
		// endpoint resolver builds the DIRECT EndpointCandidate as <dir>/<uuid>.sock, so this
		// MUST match the host-agent's dir or serpent-tui dials a non-existent UDS and silently
		// degrades to reader-only. Empty falls back to defaultAttachSocketDir (unchanged
		// behavior); set DS_ORCH_ATTACH_SOCKET_DIR only when the host-agent overrides the dir
		// (the rootless MVP runs both under ~/tmp).
		AttachSocketDir: os.Getenv("DS_ORCH_ATTACH_SOCKET_DIR"),
		// AttachModeReader tags the issued attach endpoint's transport (RAW_TERMINAL for a
		// terminal session) from the SAME host-written .ds-session-mode marker the host-agent
		// EntrypointProducer persisted (built above iff DS_ORCH_OVERLAY_DIR is set; nil ⇒
		// every session tags DIRECT, fail-safe). This is what flips serpent-tui's terminal
		// path on in the single-box MVP where the control-plane resolver answers Attach.
		AttachModeReader: attachModeReader,
		// WriterIdentity / WriterAttachAuth are the W2 writer-seat auth seams (D22/D55
		// human identity + D39 attach token). Both fail-closed when nil: WriterIdentity is
		// the in-process MVP validator only under DS_ORCH_FAKE_IDENTITY (else nil ⇒
		// RequestWriterSeat refuses Unauthenticated — the real SSO edge is deferred);
		// WriterAttachAuth is the fileAttachTokenStore adapter only under
		// DS_ORCH_OVERLAY_DIR (else nil ⇒ refuses PermissionDenied). A live single-box MVP
		// sets both gates, so RequestWriterSeat can grant; production without SSO stays
		// fail-closed on identity by construction.
		WriterIdentity:   writerIdentity,
		WriterAttachAuth: writerAttachAuth,
		// WriterDriveSink is the W3 host-agent relay write leg (drivesink_live.go). Nil unless
		// DS_ORCH_OVERLAY_DIR is set ⇒ DriveSession refuses Unavailable fail-closed (no relay
		// configured); set ⇒ an admitted DriveInput is forwarded onto the host-agent's per-
		// session bridge over the framed-UDS RELAY carrier.
		WriterDriveSink: writerDriveSink,
		// ContentSource is the read-stream content leg (contentsource_live.go). Nil unless
		// DS_ORCH_OVERLAY_DIR is set ⇒ NewControlPlane leaves the content relay unconstructed and
		// the fan-out carries only the control edges (the documented degrade, doc 15 §5.3); set ⇒
		// CC's projected content is read as a D61 READER over the framed-UDS RELAY carrier and
		// fanned out to every N-reader.
		ContentSource: contentSource,
	}

	// DURABLE D46 PARK BACKING (parkstore.SQL — doc 16 §8.2 / doc 15 §3 RecoverSessions).
	// NewControlPlane defaults Deps.ParkRecorder to a fresh in-process parkstore.NewMemory()
	// (durable only WITHIN the process), so a genuine control-plane restart re-adopts from a
	// Memory it just lost. Front the database/sql twin parkstore.SQL over the SAME *sql.DB the
	// Postgres store opened above — so the session<->question join lives in the external
	// Postgres (migration 0012_park_join.sql) and a rung-2 ask parked before a restart is
	// re-adopted on boot and still resolves on a human answer (NEVER timing out into allow or
	// kill, the load-bearing D46/D77 invariant). It is wired ONLY when a DSN configured the
	// Postgres path (storeDB != nil); with no DSN (the in-memory store posture) Deps.ParkRecorder
	// is LEFT UNSET so NewControlPlane's in-process Memory default stands — a dev live run closes
	// the path without an external DB, exactly as before. The pool is owned/closed by the store
	// (storeClose), so this adds no second closer (one connection, one registration). Reached
	// ONLY here under DS_ORCH_LIVE=1 (a non-live run never resolves liveDeps, D50): gate-off
	// leaves the in-process Memory default entirely untouched.
	if storeDB != nil {
		deps.ParkRecorder = parkstore.NewSQL(storeDB)
		slog.Default().Info("ds orchestrator: D46 park backing fronted by parkstore.SQL over the external Postgres pool — the session<->question join is durable across a control-plane restart (cross-restart re-adoption, doc 16 §8.2)")
	}

	// SUSPEND / PARK / RESUME LIVE EDGES (suspendwire — D46/D110/doc 15 §4.3), all reached
	// ONLY here under DS_ORCH_LIVE=1 (a non-live run never resolves liveDeps, D50), so
	// gate-off keeps NewControlPlane's in-process defaults unchanged: the registry-backed
	// Suspender, a nil Resumer/Snapshotter (lazily validated), a nil Approvals (safe for the
	// user/scheduler arms), and the in-process DROP SuspendCoord sink. Gate-on wires the real
	// ones below.
	//
	//  (a) ApprovalPresence — the §8.2 resume-on-answer policy_log read (resumeauthority.go's
	//      policy_breach arm): a session resumes from a policy_breach pause ONLY on a LANDED,
	//      currently-valid rung-2 human approval. The production reader is
	//      sessions.NewLiveGrantApprovalPresence over the store's LiveGrants read (the same
	//      live-grant filter the policy composer uses). *store.Memory / *store.Postgres both
	//      satisfy the reader; the live store is narrowed to ControlPlaneStore here, so this
	//      type-asserts it to the reader shape and wires the gate when present (else leaves
	//      Approvals nil — the policy_breach resume then denies fail-closed, which is the
	//      correct posture for a store that cannot answer "did an approval land?").
	if reader, ok := store.(liveGrantReader); ok {
		deps.Approvals = sessions.NewLiveGrantApprovalPresence(reader, nil)
	} else {
		slog.Default().Warn("ds orchestrator: live store does not expose the LiveGrants read — policy_breach resume DENIES fail-closed (no ApprovalPresence wired); user/scheduler resume arms are unaffected")
	}

	//  (b) SuspendCoordEmitter — the host-local channel ds-tlsproxy reads the D110 SuspendCoord
	//      coordination off (doc 15 §2.1). The boundary owns the real channel; this binary
	//      delivers onto it through the host-local emit endpoint DS_ORCH_SUSPENDCOORD_SOCK
	//      names. The real socket/channel write is the boundary's "slot implementation before
	//      Stage 2 / TLS-1" — a live host-local edge this orchestrator does NOT own — so it is
	//      scaffolded behind the env: when the endpoint is set, a host-local emitter is wired
	//      (the deferred live write is fenced inside it); unset, the in-process DROP sink stays
	//      (NewControlPlane's default), so a dev live run closes the path without a boundary
	//      channel. Either way no live boundary is dialed in CI (the write is the deferred step).
	if sock := os.Getenv("DS_ORCH_SUSPENDCOORD_SOCK"); sock != "" {
		deps.SuspendEmitter = newHostLocalSuspendCoordEmitter(sock)
		slog.Default().Info("ds orchestrator: D110 SuspendCoord host-local emitter wired (the boundary-owned channel ds-tlsproxy reads); the live host-local write is the deferred boundary slot impl (DS_ORCH_SUSPENDCOORD_SOCK)",
			"endpoint", sock)
	}

	//  (c) the REAL boundary.v1.SuspendSignal feed termination — the orchestrator consumes the
	//      frozen boundary feed, hands each delivered signal to the SuspendSignalTerminator
	//      (NewControlPlane builds it: cp.SuspendTerminator), and drives the resulting
	//      hypervisor.v1.SuspendRequest on cp.ParkResume. The feed is a LIVE boundary edge (a
	//      stream the boundary pushes), so its consumer loop is a deferred live step scaffolded
	//      in serve() behind DS_ORCH_SUSPEND_FEED — gate-off / unset it is inert (the suspend
	//      path is exercised by the in-memory terminator + fakes in tests, never a live dial).
	// Arm the §4.1 step-9 LIVE freshness probe (D72/D106) over the SHARED feed: construct the
	// production HostFreshness seam that resolves a placed host's CURRENT applied_seq O(1)
	// from the same latest-per-host feed StoreCandidateSource places against, closing the
	// residual placement→step-9 window the recorded-only re-check misses. It is constructed
	// ONLY here (under DS_ORCH_LIVE — a non-live run never reaches liveDeps, D50), so gate-off
	// behavior is unchanged: no seam, the probe stays inert and the gate degrades to the
	// recorded-only re-check (backwards-compatible).
	liveFreshness(deps.Heartbeats)

	// D18 FAN-OUT SUB-TOKEN LEG (subtoken.go / subtokenwiring.go, doc 23 §5; D126) — the
	// LIVE auth-SDK edge. The frozen dreamserpent.auth.v1 TokenAttenuationService derives ONE
	// narrowed agent sub-token per launched VM at fan-out; NewControlPlane wires the
	// fileSubTokenSink + the injector when Deps.SubTokenAttenuator is set. The dial is a LIVE
	// network edge (a real gRPC connection to the auth SDK), so it is reached ONLY here under
	// DS_ORCH_LIVE=1 AND behind the DS_AUTHSDK_ENDPOINT sub-gate: with the endpoint unset (the
	// default even under DS_ORCH_LIVE — the v0 posture before the auth SDK is deployed) the
	// attenuator is LEFT UNSET, so NewControlPlane leaves the sub-token leg unwired and
	// CreateSession fans out no sub-token (a clean degrade, additive). Set the endpoint to
	// wire it: the dial threads the SAME shared dialOpts the host-driver + Identity edges
	// read (one mTLS posture across all live edges), and the dialed connection's Close joins
	// the closer chain. CI NEVER opens this connection — a non-live run never resolves
	// liveDeps, and even a live run without DS_AUTHSDK_ENDPOINT never dials (D50).
	if endpoint := os.Getenv("DS_AUTHSDK_ENDPOINT"); endpoint != "" {
		attClient, err := controlplane.NewTokenAttenuatorClient(endpoint, dialOpts...)
		if err != nil {
			return controlplane.Deps{}, closers.close, fmt.Errorf("auth-sdk TokenAttenuationService backend: %w", err)
		}
		closers.add(attClient.Close)
		deps.SubTokenAttenuator = attClient.Attenuator
		// SubTokenAuthority resolves the D125 parent user auth token + the requested-scope
		// SUBSET of its ds_scopes from the create request (doc 23 §5; §5 rules 1/3). The
		// frozen CreateSessionRequest carries the launching_user subject, NOT the token/scopes
		// — those ride the IdP claim the M2 multi-org band threads structurally (doc 16 §3.2).
		// Until that boundary lands, no parent authority is resolvable from the wire, so the
		// authority is LEFT UNSET (nil) — the injector then skips the derive (nothing to
		// attenuate) and the create is unaffected. Wiring a real authority is the deferred M2
		// step; the leg's mount path + derive call are live now, exercised end-to-end by the
		// synthetic seam tests (D50).
		slog.Default().Info("ds orchestrator: D18 fan-out sub-token leg wired to the auth-SDK TokenAttenuationService (doc 23 §5); the parent-authority resolver is the deferred M2 IdP-boundary step (no parent authority on the frozen CreateSessionRequest wire — derive is skipped until then)",
			"endpoint", endpoint)
	}

	return deps, closers.close, nil
}

// liveFreshness constructs the production §4.1 step-9 HostFreshness seam (D72) over the
// shared live heartbeat feed and reports it armed. It is the host-keyed live freshness
// probe (controlplane.NewHostFreshness): it resolves a placed host's CURRENT applied_seq
// O(1) from the SAME latest-per-host feed StoreCandidateSource places against, so the
// step-9 routable gate re-validates the placed host against its present freshness — not
// the value recorded at placement — closing the residual D72 window the recorded-only
// re-check misses. Reached ONLY under DS_ORCH_LIVE (a non-live run never resolves
// liveDeps, D50); with the gate off the probe stays inert and the gate degrades to the
// recorded re-check, so the behavior is unchanged (backwards-compatible).
//
// The seam reads the feed handed to Deps.Heartbeats, so a placement and its step-9
// re-check share one view of a host. The final injection assigns this seam to the
// scheduler.Adapter's optional Freshness field at the NewControlPlane placer-construction
// site (controlplane/wiring.go) — the one capstone wiring line that flips the probe from
// armed to live; the seam + the shared feed it reads are resolved and ready here.
func liveFreshness(feed *controlplane.HeartbeatStore) {
	probe := controlplane.NewHostFreshness(feed)
	slog.Default().Info("ds orchestrator: §4.1 step-9 live freshness probe armed over the shared heartbeat feed (D72) — re-validates a placed host's current applied_seq, closing the residual placement->step-9 window",
		"probe", fmt.Sprintf("%T", probe))
}

// seedEnvConfig registers the §4.1 step-1 second key (D56) into the in-memory store so a
// fresh single-binary live run can complete CreateSession without an env-config-write RPC
// (none exists yet — the two-key env-spec write is the deferred control-plane enrollment
// service, doc 15 §9). It is opt-in behind DS_ORCH_SEED_ENV_CONFIG="<ref>=<image-id>" and
// is a no-op when unset, so a Postgres-backed live run (which seeds the env config via the
// DB) is untouched. It is supported ONLY on the in-memory store: the Postgres path is the
// production posture where the env config is written through the durable store, so an
// attempt to seed against it is a loud misconfiguration rather than a silent no-op. The
// resolved image_id is a logical handle — the host-agent boots its own configured image
// (DS_KERNEL_PATH/-base-image) regardless — so any non-empty value satisfies the create.
// RepoRef rides DS_ORCH_SEED_REPO_ID (empty = inline-style, the create's explicit pairing
// satisfies the same-repo join; set it to the create's --repo for a repo-referenced env).
func seedEnvConfig(st controlplane.ControlPlaneStore) error {
	raw := strings.TrimSpace(os.Getenv("DS_ORCH_SEED_ENV_CONFIG"))
	if raw == "" {
		return nil
	}
	ref, imageID, ok := strings.Cut(raw, "=")
	ref, imageID = strings.TrimSpace(ref), strings.TrimSpace(imageID)
	if !ok || ref == "" || imageID == "" {
		return fmt.Errorf("malformed DS_ORCH_SEED_ENV_CONFIG %q (want ref=image-id)", raw)
	}
	m, ok := st.(*store.Memory)
	if !ok {
		return fmt.Errorf("DS_ORCH_SEED_ENV_CONFIG is only supported on the in-memory store (a Postgres run seeds the env config through the DB)")
	}
	_, err := m.PutEnvConfig(context.Background(), store.EnvConfig{
		Ref:     ref,
		ImageID: imageID,
		RepoRef: strings.TrimSpace(os.Getenv("DS_ORCH_SEED_REPO_ID")),
	})
	if err != nil {
		return fmt.Errorf("seed env config %q: %w", ref, err)
	}
	slog.Default().Info("ds orchestrator: seeded the §4.1 step-1 env config (D56) into the in-memory store so a fresh single-binary live run can complete CreateSession (DS_ORCH_SEED_ENV_CONFIG)",
		"ref", ref, "image_id", imageID, "repo_ref", os.Getenv("DS_ORCH_SEED_REPO_ID"))
	return nil
}

// resolveStore picks the live store: external Postgres (D6) when DS_ORCH_PG_DSN is set,
// else the in-memory store (the single-binary posture, so a dev live run closes the path
// without an external DB). The Postgres path opens *store.Postgres via
// controlplane.NewPostgresStore (the operator registers a Postgres driver at the binary
// boundary, D33; driver name from DS_PG_DRIVER); the in-memory path needs no closer.
//
// It ALSO SURFACES the raw *sql.DB the Postgres path opened (nil on the in-memory path) so
// the durable D46 park backing (parkstore.SQL) can be fronted over the SAME pool — one
// connection, one driver registration. The handle is the pool *store.Postgres holds, exposed
// here only to thread it into parkstore.NewSQL; the returned closer (db.Close) still owns the
// pool's lifecycle, so a caller MUST NOT close the surfaced handle itself.
//
// The pool is opened through controlplane.OpenPostgresPool — the SAME single-source open
// NewPostgresStore uses — so the driver default, the D33 unregistered-driver error shape, and
// any future pool tuning are guaranteed identical to the store's own open (no second copy of
// the sql.Open block to drift). resolveStore surfaces the raw pool the constructor hides
// behind *store.Postgres so the SAME *sql.DB backs both the store reads and the durable D46
// park join; the wrap into *store.Postgres is the only remaining local step.
func resolveStore() (controlplane.ControlPlaneStore, *sql.DB, func() error, error) {
	dsn := os.Getenv("DS_ORCH_PG_DSN")
	if dsn == "" {
		return store.NewMemory(), nil, func() error { return nil }, nil
	}
	db, err := controlplane.OpenPostgresPool(dsn, os.Getenv("DS_PG_DRIVER"))
	if err != nil {
		return nil, nil, func() error { return nil }, fmt.Errorf("external postgres store: %w", err)
	}
	return store.NewPostgres(db), db, db.Close, nil
}

// expectedHostLister is the narrow read storeExpectedHosts needs to enumerate the hosts a
// live fleet SHOULD be reporting: the session records (their host_id). The
// controlplane.ControlPlaneStore satisfies it via ListSessions; declared narrow here so the
// never-seen liveness supplier depends on exactly the read it uses and nothing wider, and so
// a test can drive it with a tiny fake.
type expectedHostLister interface {
	ListSessions(ctx context.Context, f store.SessionFilter) ([]store.Session, error)
}

// storeExpectedHosts builds the production controlplane.ExpectedHostSupplier for the
// never-seen liveness enrichment (doc 15 §3/§5.2; D35/D72): each call enumerates the DISTINCT
// host_ids of the live (non-DESTROYED) session records — the hosts that SHOULD be heartbeating
// because a session is placed on them — so the loop-serialized snapshotter folds an
// expected-but-NEVER-heard-from host into /debug/liveness + the orchestrator_host_liveness
// expvar as EverSeen=false / UNKNOWN instead of omitting it.
//
// The supplier honors the ExpectedHostSupplier contract: it is NON-BLOCKING (a single
// in-memory ListSessions over the live store, no network dial) and returns a FRESH,
// caller-owned slice each call (a new slice built per invocation, so the loop never aliases
// shared state). It is evaluated on the reconcile-loop goroutine per snapshot, so it always
// reflects the CURRENT placed-session fleet. It is purely additive: a nil store, a list fault,
// or an empty fleet all degrade to the empty expected set (the heard-from-only view, today's
// behavior) rather than failing the read — a never-seen enrichment that cannot enumerate is
// simply silent, never an error on the admin render path.
//
// The host_id filter is IncludeDestroyed:false (the SessionFilter default), so a DESTROYED
// session's host is not treated as expected — a torn-down host that stops heartbeating is not
// a never-seen anomaly. A short-lived background ctx bounds the per-call enumeration so a wedged
// store read cannot hang the snapshot (the read is in-memory under the live store, but the
// bound keeps the contract honest for a slower backing store).
func storeExpectedHosts(st expectedHostLister) controlplane.ExpectedHostSupplier {
	if st == nil {
		return nil
	}
	return func() []string {
		ctx, cancel := context.WithTimeout(context.Background(), expectedHostsListBudget)
		defer cancel()
		sessions, err := st.ListSessions(ctx, store.SessionFilter{})
		if err != nil {
			slog.Default().Warn("ds orchestrator: never-seen liveness enrichment could not enumerate expected hosts — /debug/liveness degrades to the heard-from-only view this snapshot (additive: no error on the admin render path)",
				"err", err)
			return nil
		}
		seen := make(map[string]struct{}, len(sessions))
		out := make([]string, 0, len(sessions))
		for _, s := range sessions {
			hostID := s.Ref.HostID
			if hostID == "" {
				continue // a pre-placement record has no host yet; not expected to beat.
			}
			if _, dup := seen[hostID]; dup {
				continue
			}
			seen[hostID] = struct{}{}
			out = append(out, hostID)
		}
		return out
	}
}

// expectedHostsListBudget bounds the per-snapshot expected-host enumeration so the
// never-seen liveness supplier cannot hang the admin render on a slow store read. The live
// store read is in-memory (or a fast indexed Postgres scan), so this is generous headroom,
// never the steady-state cost.
const expectedHostsListBudget = 2 * time.Second

// enrollmentResolver / roleResolver supply the create-time resolvers (§4.1 steps 1–2).
// The role resolver is the M0 ORG-CATALOG-backed CatalogRoleResolver (doc 18 §4/§7):
// it resolves a requested role_ref against the SAME checked-in roles/ catalog the
// roles.v1 READ path (RoleCatalogService) serves — so the create path resolves every
// built-in role (default/developer/researcher/security-engineer) and pins each role's
// CANONICAL role_content_hash (roles/SCHEMA.md rule 5), the SAME bytes the read path's
// Role.content_hash and Session.pinned_role_content_hash carry. The enrollment resolver
// is the store-backed first-key resolver the deployment supplies. Until the control-plane
// enrollment service (D56) lands its own dialed client, the enrollment resolver is the
// open-pool resolver: every repo is considered enrolled (the v0 single-org posture — the
// M2 band threads a real enrollment authority through the IdP boundary). Neither is a live
// network edge — both are deployment inputs constructed here directly rather than dialed.
//
// FAIL-SAFE FALLBACK (D50). The catalog resolver loads the checked-in roles/ tree at
// construction; a load fault (the roles/ tree is unreadable in this deployment) DEGRADES
// to the v0 default-only DefaultRoleResolver pinned to the deployment's role-vocabulary
// version + content hash (DS_ORCH_ROLE_VERSION / DS_ORCH_ROLE_HASH) so the create path
// still resolves the recorded default rather than the whole live run failing to start.
// The fallback's content hash is a v0 MARKER, NOT the canonical catalog hash — it is the
// degraded posture only, surfaced as a WARN so the catalog/pin hash disagreement is visible.
func roleResolver() sessions.RoleResolver {
	resolver, err := sessions.NewCatalogRoleResolverFromDir(rolesCatalogDir())
	if err != nil {
		slog.Default().Warn("ds orchestrator: create-path role catalog load failed — DEGRADING to the v0 default-only resolver (non-default role_ref will refuse; the pinned default hash is a v0 marker, NOT the canonical catalog hash, doc 18 §6/§7)",
			"dir", rolesCatalogDir(), "err", err)
		return sessions.DefaultRoleResolver{
			CurrentVersion: envOr("DS_ORCH_ROLE_VERSION", "2026.06.11-v1"),
			ContentHash:    envOr("DS_ORCH_ROLE_HASH", "default-role-hash-v0"),
		}
	}
	return resolver
}

// rolesCatalogDir is the directory the roles.v1 read-path catalog loads the
// built-in roles/*.yaml from (doc 18 §5/§6; D93). It is a deployment input
// (DS_ORCH_ROLES_DIR), defaulting to the repo's top-level `roles/` tree — the OSS
// catalog that ships with the all-in-one (D80). It is not a live network edge, so
// it is resolved here directly.
func rolesCatalogDir() string { return envOr("DS_ORCH_ROLES_DIR", "roles") }

func enrollmentResolver() sessions.EnrollmentResolver { return openPoolEnrollment{} }

// openPoolEnrollment is the v0 open-pool first-key resolver (D56): every repo is enrolled
// by the deployment org-admin (the single-org posture). A real enrollment authority (the
// M2 control-plane enrollment service) replaces it with a dialed resolver, leaving the
// sessions.EnrollmentResolver seam unchanged.
type openPoolEnrollment struct{}

func (openPoolEnrollment) ResolveEnrollment(_ context.Context, repoID string) (sessions.Enrollment, bool, error) {
	return sessions.Enrollment{
		RepoID:              repoID,
		EnrolledByPrincipal: "deployment-org-admin",
		EnrolledByRole:      store.RoleOrgAdmin,
	}, true, nil
}

// envOr returns os.Getenv(key) or def when the var is empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// liveGrantReader is the narrow policy_log live-grant read the production ApprovalPresence
// (sessions.NewLiveGrantApprovalPresence) consumes — the §8.2 resume-on-answer
// currently-valid PolicyKindAskGrant lookup for a session. It mirrors the unexported
// liveGrantReader the sessions package declares (approvalpresence.go); declared here so
// liveDeps can type-assert the live store (narrowed to controlplane.ControlPlaneStore) onto
// it WITHOUT widening ControlPlaneStore. *store.Memory and *store.Postgres satisfy it
// natively (the store stays frozen).
type liveGrantReader interface {
	LiveGrants(ctx context.Context, sessionUUID string, now time.Time) ([]store.PolicyLogRow, error)
}

// hostLocalSuspendCoordEmitter is the production-side D110 SuspendCoord emit sink (doc 15
// §2.1; suspendcoord.go's SuspendCoordEmitter): it delivers the SessionLifecycleUpdate
// (carrying the suspend_coord slot) onto the boundary-owned HOST-LOCAL channel ds-tlsproxy
// reads, named by the host-local endpoint (a unix socket / shared channel). The REAL
// host-local write is the boundary's "slot implementation before Stage 2 / TLS-1" — a live
// edge this orchestrator does NOT own (it consumes the seam, doc 15 §2.1) — so it is FENCED
// behind DS_ORCH_LIVE here AND behind the DS_ORCH_SUSPENDCOORD_LIVE_WRITE sub-gate: with the
// sub-gate unset (the default even under DS_ORCH_LIVE) the emitter LOGS the would-be delivery
// and returns nil (a measured no-op, never a live host-local dial in CI); flipping the
// sub-gate is the operator step that arms the real write once the boundary slot lands. This
// keeps the wiring complete and unit-testable while never dialing a live boundary channel
// from CI/dev (D50).
type hostLocalSuspendCoordEmitter struct {
	endpoint string
}

// newHostLocalSuspendCoordEmitter builds the host-local emitter over the configured
// endpoint. The endpoint is recorded for the (deferred) live write; construction never
// dials it (the dial is the fenced live step).
func newHostLocalSuspendCoordEmitter(endpoint string) hostLocalSuspendCoordEmitter {
	return hostLocalSuspendCoordEmitter{endpoint: endpoint}
}

// EmitSuspendCoord delivers the update onto the boundary-owned host-local channel. The
// actual host-local write is FENCED behind the DS_ORCH_SUSPENDCOORD_LIVE_WRITE sub-gate (the
// deferred boundary slot impl); with it unset the delivery is a logged no-op so no live
// boundary channel is dialed in CI/dev (D50). It never fails on the no-op path (a measured
// drop cannot fail); the armed path's write error would surface to the SuspendCoordinator.
func (e hostLocalSuspendCoordEmitter) EmitSuspendCoord(ctx context.Context, update *hostagentv1.SessionLifecycleUpdate) error {
	if os.Getenv("DS_ORCH_SUSPENDCOORD_LIVE_WRITE") != "1" {
		slog.Default().InfoContext(ctx, "ds orchestrator: D110 SuspendCoord delivery (measured no-op — DS_ORCH_SUSPENDCOORD_LIVE_WRITE unset; the live host-local write is the deferred boundary slot impl)",
			"endpoint", e.endpoint, "session", update.GetSessionUuid(), "phase", update.GetSuspendCoord().GetPhase().String())
		return nil
	}
	// DEFERRED LIVE STEP (DS_ORCH_SUSPENDCOORD_LIVE_WRITE=1): write the update onto the real
	// host-local channel at e.endpoint. This is the boundary's slot implementation (doc 15
	// §2.1) the orchestrator does NOT own; it is intentionally NOT dialed from this binary in
	// CI/dev. A deployment whose boundary exposes the channel arms this and supplies the host-
	// local writer. Until then the armed path is unreachable in CI and surfaces a clear refusal.
	return fmt.Errorf("ds orchestrator: D110 SuspendCoord live host-local write to %q is the deferred boundary slot impl (doc 15 §2.1) — not implemented in this binary; unset DS_ORCH_SUSPENDCOORD_LIVE_WRITE for the measured no-op", e.endpoint)
}

// Compile-time proof the host-local emitter satisfies the controlplane emit seam.
var _ controlplane.SuspendCoordEmitter = hostLocalSuspendCoordEmitter{}

// closerChain accumulates shutdown closers (the dialed conns + the Postgres pool) and
// runs them in REVERSE order, returning the first error (the rest are still attempted) so
// a partial liveDeps build still tears down what it opened.
type closerChain struct{ fns []func() error }

func newCloserChain() *closerChain { return &closerChain{} }

func (c *closerChain) add(fn func() error) {
	if fn != nil {
		c.fns = append(c.fns, fn)
	}
}

func (c *closerChain) close() error {
	var firstErr error
	for i := len(c.fns) - 1; i >= 0; i-- {
		if err := c.fns[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// parseHostDrivers parses the DS_ORCH_HOST_DRIVERS env var — a comma-separated list of
// host_id=addr pairs (e.g. "host-a=10.0.0.1:9000,host-b=10.0.0.2:9000") — into the
// per-host driver endpoint map the dialing registry resolves. An empty value is accepted
// (an empty registry; every placement then misses with an attributable
// no-driver-for-host, never a nil panic); a malformed pair is an error so a misconfigured
// live run fails loudly.
func parseHostDrivers(raw string) (controlplane.HostEndpoints, error) {
	endpoints := controlplane.HostEndpoints{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		host, addr, ok := strings.Cut(pair, "=")
		host, addr = strings.TrimSpace(host), strings.TrimSpace(addr)
		if !ok || host == "" || addr == "" {
			return nil, fmt.Errorf("malformed DS_ORCH_HOST_DRIVERS pair %q (want host_id=addr)", pair)
		}
		endpoints[host] = addr
	}
	return endpoints, nil
}

// resolveDriverRegistry selects the per-host HypervisorDriver registry by the D19 deployment
// tier (doc 15 §2.1), returning the chosen controlplane.DriverRegistry and its shutdown
// closer. The two production registries differ ONLY in the control-link dial DIRECTION; both
// resolve a host to the SAME frozen hypervisor.v1 ClientShim driver, so NewControlPlane
// consumes either identically. Reached ONLY from liveDeps under DS_ORCH_LIVE=1 (D50 — a
// non-live run never resolves the registry).
//
//   - HOSTED (the default — DS_ORCH_BRING_COMPUTE unset): the orchestrator dials each host
//     agent OUTBOUND over the configured DS_ORCH_HOST_DRIVERS endpoints
//     (controlplane.NewDialRegistry), carrying the shared mTLS dial-option tail.
//
//   - BRING-COMPUTE (DS_ORCH_BRING_COMPUTE=1): the customer's NAT'd host agent dials OUT to
//     the orchestrator's listener (D19 outbound-only mTLS, no inbound holes), and the
//     orchestrator routes the HypervisorDriver verbs back over that inbound-established
//     connection (controlplane.NewInboundDriverRegistry). The registry starts EMPTY and fills
//     as each host agent dials in: the orchestrator's connection-accept path identifies the
//     dialing host (host_id from its D22 mTLS peer identity) and Registers the established
//     *grpc.ClientConn. That host-agent-initiated connection-accept + host-identification +
//     ClientConn-capture leg is the DEFERRED-MANUAL reverse-link transport step the customer's
//     bring-compute outbound dialer pairs with (a stream the host agent OPENS to the
//     orchestrator, the host agent's own D35 service — not this binary's to stand up): it is
//     fenced behind DS_ORCH_BRING_COMPUTE_ACCEPT here, refused with a clear message until a
//     deployment supplies the accept-loop, so a live bring-compute orchestrator builds the
//     registry + serves its listener but does not fabricate an inbound transport. The registry
//     and the inbound verb routing it performs are exercised end-to-end over a bufconn-backed
//     InboundConn in internal/controlplane (dialregistry_test.go, D50 — no live host-agent and
//     no inbound hole opened in a test); DS_ORCH_HOST_DRIVERS is ignored at this tier (the
//     orchestrator opens no outbound dial to a host).
func resolveDriverRegistry(endpoints controlplane.HostEndpoints, dialOpts ...controlplane.DialOption) (controlplane.DriverRegistry, func() error, error) {
	if os.Getenv("DS_ORCH_BRING_COMPUTE") != "1" {
		// Hosted tier (default): orchestrator-dials-host OUTBOUND.
		reg := controlplane.NewDialRegistry(endpoints, dialOpts...)
		return reg, reg.Close, nil
	}

	// Bring-compute tier: host-agent-dials-OUT; the orchestrator routes the verbs back over
	// the inbound connection. The registry starts empty and fills as hosts dial in.
	reg := controlplane.NewInboundDriverRegistry()
	if len(endpoints) > 0 {
		// A bring-compute deployment never dials the host, so DS_ORCH_HOST_DRIVERS is inert at
		// this tier — surface it so a stray hosted-tier env on a bring-compute run is visible.
		slog.Default().Warn("ds orchestrator: DS_ORCH_BRING_COMPUTE=1 (host-agent-dials-OUT) — DS_ORCH_HOST_DRIVERS is IGNORED at the bring-compute tier (the orchestrator opens no outbound dial to a host; verbs route over the inbound connection, doc 15 §2.1)",
			"ignored_endpoints", len(endpoints))
	}
	if err := startBringComputeAccept(reg); err != nil {
		return nil, reg.Close, err
	}
	slog.Default().Info("ds orchestrator: bring-compute driver registry built (host-agent-dials-OUT; HypervisorDriver verbs route over the inbound connection, doc 15 §2.1, D19 outbound-only mTLS, no inbound holes) — hosts resolvable as they dial the orchestrator's DS_ORCH_LISTEN listener and Register")
	return reg, reg.Close, nil
}

// startBringComputeAccept arms the DEFERRED host-agent-initiated connection-accept leg of the
// bring-compute tier (doc 15 §2.1; D19). The customer's host agent dials OUT to the
// orchestrator's listener; the accept path must identify the dialing host (host_id from its
// D22 mTLS peer identity), capture the established *grpc.ClientConn, and Register it on the
// inbound driver registry so the HypervisorDriver verbs route back over that link. That accept
// loop + host-identification is the reverse-link transport step the host agent's own outbound
// bring-compute dialer pairs with — NOT this binary's to stand up (it exceeds one PR and the
// host agent owns the dialer side, doc 15 §2 D35) — so it is FENCED behind
// DS_ORCH_BRING_COMPUTE_ACCEPT: unset (the default even under DS_ORCH_BRING_COMPUTE) the
// registry is built and the listener serves, but no inbound connection is captured (the
// registry resolves ErrNoDriverForHost until a deployment wires Register), exercised by the
// bufconn InboundConn tests (D50 — never a live host-agent); set, the live accept transport
// is the deferred step refused here with a clear message until it lands. Either way no live
// host-agent connection is fabricated from CI/dev (the accept is the deferred step).
func startBringComputeAccept(reg controlplane.DriverRegistry) error {
	if os.Getenv("DS_ORCH_BRING_COMPUTE_ACCEPT") != "1" {
		slog.Default().Info("ds orchestrator: bring-compute connection-accept loop NOT armed (DS_ORCH_BRING_COMPUTE_ACCEPT unset) — the inbound driver registry is built and DriverFor resolves over Registered host links, but no live host-agent connection is captured; the accept+identify+Register transport is the deferred reverse-link step (doc 15 §2.1, the host agent's outbound dialer side)",
			"registry", fmt.Sprintf("%T", reg))
		return nil
	}
	return fmt.Errorf("ds orchestrator: live bring-compute connection-accept loop (identify the dialing host, capture its *grpc.ClientConn, Register it on the inbound driver registry) is the deferred reverse-link transport step (doc 15 §2.1, D19) — not implemented in this binary; the inbound verb routing it feeds is exercised over bufconn in internal/controlplane; unset DS_ORCH_BRING_COMPUTE_ACCEPT to build the registry without it")
}

// serve is the gRPC transport bootstrap: bind a TCP listener on DS_ORCH_LISTEN and hand it
// to controlplane.Serve, which constructs the grpc.Server, registers cp.Sessions
// (orchestrator.v1 SessionService) + the hostagent.v1 heartbeat ingest (routing inbound
// heartbeats to cp.Reconcile.Observe), starts cp.Reconcile.Run, serves, and graceful-stops
// on ctx cancel. The load-bearing serve logic lives in internal/controlplane (unit-tested
// over a bufconn, D50); this bootstrap only resolves the listen address and binds the real
// socket (the live edge). An empty DS_ORCH_LISTEN defaults to the documented strawman.
func serve(ctx context.Context, cp *controlplane.ControlPlane) error {
	addr := os.Getenv("DS_ORCH_LISTEN")
	if addr == "" {
		addr = defaultListenAddr
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind DS_ORCH_LISTEN %q: %w", addr, err)
	}
	return controlplane.Serve(ctx, cp, lis)
}

// defaultListenAddr is the strawman gRPC listen address when DS_ORCH_LISTEN is unset (a
// rig-tuned value, free per doc 15 §10 — only the listen mechanism is load-bearing).
const defaultListenAddr = ":9090"
