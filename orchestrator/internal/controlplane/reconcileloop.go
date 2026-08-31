package controlplane

// reconcileloop.go is the reconciler DRIVING GOROUTINE — leg (b) of the control-plane
// capstone (doc 15 §3). The reconciler (internal/reconciler) is a constructible
// component with two triggers — Observe (event-driven, one hostagent.v1.Heartbeat) and
// Resync (periodic full resync over every host) — but it is NOT a running loop: it
// holds the single-goroutine lastBeat contract ("safe to call from one goroutine; the
// driving loop owns concurrency", reconciler.go). This loop is that owner: it serializes
// every Observe and Resync onto ONE goroutine, so the reconciler's mutable lastBeat map
// is never touched concurrently.
//
// THE SERIALIZATION (the lastBeat single-goroutine contract). Inbound heartbeats arrive
// concurrently (the gRPC ingest handler runs per-connection), and the periodic resync
// fires on a ticker. If both touched the reconciler directly they would race lastBeat.
// So the loop funnels BOTH onto one channel-served goroutine: Observe submits a
// heartbeat onto the loop's inbound channel (the ingest handler returns immediately,
// the loop drains it), and Run's ticker fires Resync on the SAME goroutine between
// drains. One goroutine, one lastBeat owner — the contract holds by construction.
//
// THE HEARTBEAT FEED COUPLING. Each inbound heartbeat is RECORDED into the live feed
// (HeartbeatStore) before it is reconciled, so the scheduler's placement candidates and
// the reconciler's resync observed-set both read the SAME latest-per-host snapshot
// (heartbeatstore.go). The loop is the single writer of the feed, so the feed and the
// reconciler converge on one view of the fleet.
//
// D50: no live VM/host-agent/podman — the loop is driven by SYNTHETIC heartbeats in
// tests (Observe a hand-built Heartbeat; Run with a cancellable context). The reconciler
// it drives is the same constructible component its own tests exercise against fakes.

import (
	"context"
	"log/slog"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/metering"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// reconcileLoop is the single-goroutine driving owner of a Reconciler. Construct with
// newReconcileLoop; drive it with Observe (per inbound heartbeat) and Run (the periodic
// resync goroutine). Observe is safe to call from many goroutines (it submits onto the
// loop's channel); Run owns the one goroutine that touches the reconciler.
type reconcileLoop struct {
	rec        *reconciler.Reconciler
	feed       *HeartbeatStore
	interval   time.Duration
	logger     *slog.Logger
	inbound    chan *hostagentv1.Heartbeat
	inboundCap int
	// health is the LOOP-SERIALIZED query channel: HealthSnapshot submits a healthReq
	// onto it and Run drains it ON THE SAME goroutine that drives Observe/Resync, so the
	// reconciler's lastBeat map is read by its single owner — never a second writer, never
	// a bare cross-goroutine read (the lastBeat single-goroutine contract, reconciler.go /
	// health.go). It is buffered so a query does not block on the loop being mid-drain.
	health chan healthReq
	// done is closed by Run when it returns (a clean ctx cancel). HealthSnapshot selects on
	// it so a query submitted to a stopped/never-started loop returns immediately (a nil
	// snapshot) instead of blocking forever on a reply that will never come.
	done chan struct{}

	// --- the D46 escalation leg (suspendwire) ---
	//
	// esc is the OPTIONAL D46 escalation classifier+driver bundle (installEscalation). When
	// installed, Run fires a SECOND ticker (escTicker) on the SAME single-goroutine loop —
	// alongside the resync ticker — that sweeps the SUSPENDED sessions, classifies each via
	// the EscalationClock, and drives the boundary HOLD coordination (the hold tiers) on the
	// loop goroutine. It NEVER spawns a goroutine racing the loop's lastBeat owner: the
	// escalation work runs in the SAME select as Observe/Resync, honoring the single-goroutine
	// serialization contract. Nil leaves the escalation leg OFF (the loop runs exactly as before
	// — fully backwards-compatible).
	esc         *escalationLeg
	escInterval time.Duration

	// --- the D46 ask-a-human RESUME leg (park-resume-wire) ---
	//
	// askResume is the OPTIONAL D46 ASK-A-HUMAN PARK MACHINE (parkadoption.go) the loop's
	// ask-resume call-site drives a HUMAN PARK-ANSWER into (installAskResume). It is the SAME
	// *parkMachine the boot re-adoption sweep re-reads and the live ask-routing site parks
	// into (wiring.go), so the running set, the durable join, and BOTH the park and the
	// resume call-sites converge on one machine. When installed, ResolveParkAnswer routes an
	// out-of-band human answer (verdict + opaque grant scope / machine-readable deny reason)
	// into machine.Resume — ENDING the untimed park on the answer, NEVER a timeout into allow
	// or kill (the load-bearing D46/D77 invariant; doc 15 §3 / doc 16 §8.2). Nil leaves the
	// ask-resume leg OFF (a ResolveParkAnswer is refused with errAskResumeNotWired rather than
	// silently dropping a human answer) — exactly the nil-tolerant gate-off posture the
	// escalation leg takes. The park machine is itself concurrency-safe (its own mutex), so a
	// human answer is driven straight through and needs NO loop-goroutine serialization (it
	// touches no lastBeat state).
	askResume *parkMachine

	// --- the D81 create-timing recorder (metering-wire) ---
	//
	// createTiming is the control-plane home of the landed CreateTimingWire (createtimingwire.go):
	// the flag-gated §8 create→attach segment-decomposition trend recorder (the (b)-row
	// "the decomposition EXISTS and its trends are recorded" instrument). newReconcileLoop
	// constructs it self-armed from CreateTimingWireEnabled(), so it is a genuine armed
	// producer on the control-plane spine when DS_ORCH_CREATETIMING_WIRE=1 and an inert
	// no-op otherwise (default off → RecordCreateTiming folds nothing, ServerSpanTrend is
	// empty). The recorder is concurrency-safe (the wire guards its Recorder with a mutex),
	// so RecordCreateTiming is safe to call from the create path off the loop goroutine.
	//
	// FOLDING THE PER-CREATE DECOMPOSITION. A create driver hands one create's measured §8
	// segments (plus the trigger-EXCLUDED client RTT) to RecordCreateTiming, which opens a
	// per-create handle, records each segment, and Observe's it into the shared trend
	// recorder — the fold the (b)-row read (ServerSpanTrend, RTT excluded) reports across
	// creates. The full ten-step create coordinator (sessioncreate.go / faststart.go) owns
	// crossing all eight live segments; wiring that live per-segment feed into this fold is
	// a deferred call-site (it lives outside this unit's three owned files). This unit
	// lands the armed recorder + the fold surface on the spine so the producer EXISTS and
	// is default-off byte-identical; the synthetic-decomposition fold is proven by the
	// flag-on test (D50 — no live VM crosses the segments).
	createTiming *CreateTimingWire
}

// escalationLeg bundles the D46 escalation components the loop's escalation ticker leg
// drives ON the single Run goroutine: the pure clock that classifies a pause into the
// transparent/best-effort/escalate tiers (escalationclock.go, its own injected now), the
// suspend/park/resume driver the escalate tier re-converges through (parkresume.go —
// EscalateToPark walks a SUSPENDED origin along the LEGAL frozen chain
// SUSPENDED→RESUMING→WORKING→SNAPSHOTTING→PARKED, a FORCED park NOT gated by resume-authority,
// adding NO new §3 edge — see escalateSweep), the D110 boundary coordination emitter for the
// hold tiers (suspendcoord.go), and the narrow session lister it sweeps the SUSPENDED records
// from. It is constructed by installEscalation and read only on the Run goroutine.
type escalationLeg struct {
	clock  *sessions.EscalationClock
	driver *sessions.ParkResumeDriver
	coord  *SuspendCoordinator
	lister suspendedLister
}

// suspendedLister is the narrow read the escalation sweep needs: the SUSPENDED session
// records (their suspend instant + reason) to classify per tick. The ControlPlaneStore
// satisfies it via ListSessions; declared narrow so the loop adds no store method.
type suspendedLister interface {
	ListSessions(ctx context.Context, f store.SessionFilter) ([]store.Session, error)
}

// installEscalation wires the D46 escalation leg onto the loop (suspendwire): it is driven
// on a SECOND ticker inside Run's single goroutine — alongside the resync ticker, under the
// SAME lastBeat single-goroutine serialization contract (NO new goroutine races the loop).
// The escalation interval reuses the resync cadence (the same level-triggered sweep rhythm);
// a future rig may split them, but one cadence keeps the loop's two periodic legs in lockstep.
// It must be called BEFORE Run (the construction-time wiring in NewControlPlane); calling it
// after Run has started is a programming error (the leg is read on the Run goroutine without
// a barrier). A nil clock/driver/coord/lister leaves the leg uninstalled (the loop runs unchanged).
func (l *reconcileLoop) installEscalation(clock *sessions.EscalationClock, driver *sessions.ParkResumeDriver, coord *SuspendCoordinator, lister suspendedLister) {
	if clock == nil || driver == nil || coord == nil || lister == nil {
		return
	}
	l.esc = &escalationLeg{clock: clock, driver: driver, coord: coord, lister: lister}
	l.escInterval = l.interval
}

// installAskResume wires the D46 ask-a-human RESUME leg onto the loop (park-resume-wire): it
// hands the loop the SAME control-plane *parkMachine the boot re-adoption populated and the
// live ask-routing site parks into, so the loop's ask-resume call-site (ResolveParkAnswer)
// can drive an out-of-band human answer into machine.Resume. It must be called BEFORE Run
// (the construction-time wiring in NewControlPlane), mirroring installEscalation. A nil
// machine leaves the leg uninstalled (the loop's ResolveParkAnswer then refuses with
// errAskResumeNotWired — the gate-off posture, no human answer silently dropped). The leg
// adds NO goroutine and NO loop-serialized state: the park machine is concurrency-safe, so
// ResolveParkAnswer drives it directly without touching the lastBeat single-goroutine owner.
func (l *reconcileLoop) installAskResume(machine *parkMachine) {
	if machine == nil {
		return
	}
	l.askResume = machine
}

// ParkAnswer is one OUT-OF-BAND HUMAN ANSWER to a parked GENUINE rung-2 ask (doc 15 §3 /
// doc 16 §8.2 / D46/D77): the verdict (ALLOW/DENY) a human returned on the policy stream for
// the session's outstanding untimed park, plus the opaque grant Scope (the ALLOW arm) or the
// machine-readable Reason (the DENY arm), stamped with the answer instant (Now — the caller
// stamps the clock; the leg keeps none of its own, D50). It is the input the reconcile
// ask-resume call-site drives into the park machine's Resume. It is NEVER a timeout: a park
// resolves ONLY on this answer (the load-bearing D46/D77 invariant — a parked ask never times
// out into allow or kill).
type ParkAnswer struct {
	SessionUUID string
	Verdict     askhold.ResumeVerdict
	Scope       string
	Reason      askhold.DenyReason
	Now         time.Time
}

// ResolveParkAnswer is the RECONCILE / ASK-RESUME CALL-SITE (park-resume-wire): it drives a
// HUMAN PARK-ANSWER into the wired ask-a-human park machine's Resume, ending the session's
// untimed park on the human verdict — NEVER a timeout into allow or kill (D46/D77; doc 15 §3
// / doc 16 §8.2). The boundary ask-resume terminator (the out-of-band policy-stream answer
// feed, DS_ORCH_LIVE) hands each delivered answer here; it returns the resumed askhold.Parked
// (carrying the verdict + opaque grant scope / deny reason) and any recorder error from the
// durable ClearParked (the resume STILL stands on a clear fault — askhold's asymmetry — only
// the durable clear can be retried).
//
// A loop with NO ask-resume leg installed (installAskResume not called — the gate-off
// posture) refuses with errAskResumeNotWired rather than silently dropping a human answer, so
// a mis-wired build surfaces the missing wiring instead of letting a genuine rung-2 ask hang
// parked forever. A session not currently parked in the machine (a double-answer / never-
// parked / already-resumed session) is refused by the machine's own guard
// (errNotParkedInMachine), surfaced unchanged. The park machine is concurrency-safe, so the
// answer is driven directly — it needs no loop-goroutine serialization (it touches no
// lastBeat state), and is safe to call from the boundary terminator's goroutine.
func (l *reconcileLoop) ResolveParkAnswer(answer ParkAnswer) (askhold.Parked, error) {
	if l.askResume == nil {
		return askhold.Parked{}, errAskResumeNotWired
	}
	return l.askResume.Resume(answer.SessionUUID, answer.Verdict, answer.Scope, answer.Reason, answer.Now)
}

// errAskResumeNotWired is returned by ResolveParkAnswer when no ask-a-human park machine has
// been installed on the loop (installAskResume not called — the gate-off posture). It mirrors
// the park machine's own parkError sentinel (parkadoption.go) so a missing wiring surfaces
// loudly rather than dropping a human answer to a genuine rung-2 ask.
var errAskResumeNotWired = parkError("controlplane: reconcile ask-resume call-site has no park machine wired (installAskResume)")

// healthReq is one loop-serialized HealthSnapshot query: Run reads the reconciler's
// per-host liveness on its own goroutine and sends the result on reply. reply is buffered
// (cap 1) so Run never blocks delivering it even if the caller has already abandoned the
// wait (its ctx cancelled) — the send completes into the buffer and is discarded.
//
// expected carries the OPT-IN expected-host set for the never-seen enrichment: when it is
// nil/empty Run serves the query as the bare heard-from snapshot (reconciler.HealthSnapshot,
// reached as HealthSnapshotIncluding(nil), which is byte-for-byte that set); when it carries
// host_ids Run serves reconciler.HealthSnapshotIncluding(expected) so an expected-but-silent
// host renders EverSeen=false / UNKNOWN rather than being absent. It is CALLER-OWNED input
// the loop only READS on its goroutine — it is never stored on the loop and never written, so
// it adds no second lastBeat writer and no shared mutable state across goroutines.
type healthReq struct {
	reply    chan []reconciler.HostHealth
	expected []string
}

// newReconcileLoop builds the loop over a constructed reconciler, the live heartbeat
// feed, and the periodic-resync interval. The inbound channel is buffered so a burst of
// heartbeats does not block the ingest handlers while the loop drains them.
func newReconcileLoop(rec *reconciler.Reconciler, feed *HeartbeatStore, interval time.Duration, logger *slog.Logger) *reconcileLoop {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = DefaultResyncInterval
	}
	const inboundCap = 256
	const healthCap = 8
	return &reconcileLoop{
		rec:        rec,
		feed:       feed,
		interval:   interval,
		logger:     logger,
		inbound:    make(chan *hostagentv1.Heartbeat, inboundCap),
		inboundCap: inboundCap,
		health:     make(chan healthReq, healthCap),
		done:       make(chan struct{}),
		// Self-arm the D81 create-timing recorder from the process flag (metering-wire).
		// CreateTimingWireEnabled() is read ONCE at construction; a disabled wire's fold is
		// an inert no-op, so a gate-off loop is byte-for-byte its prior behavior.
		createTiming: NewCreateTimingWire(CreateTimingWireEnabled()),
	}
}

// meteringSink exposes the loop's backing store as a metering.Sink for the heartbeat
// ingest's OPTIONAL D37 sample fan-out (metering-wire): the ingest probes its observer
// (this loop) for meteringSinkProvider and, when armed, appends heartbeat samples through
// this sink. The sink is the SAME single backing store the rest of the control plane is
// wired from — reached here via the escalation lister that NewControlPlane installs
// (installEscalation's d.Store, which both *store.Memory and *store.Postgres implement,
// including AppendMeteringEvent). It returns nil until the escalation leg is installed (or
// if the lister does not satisfy the sink), leaving the ingest's fan-out unarmed — the
// gate-off / not-yet-wired posture. It reads no lastBeat state, so it is safe from any
// goroutine.
func (l *reconcileLoop) meteringSink() metering.Sink {
	if l == nil || l.esc == nil {
		return nil
	}
	if s, ok := l.esc.lister.(metering.Sink); ok {
		return s
	}
	return nil
}

// RecordCreateTiming folds one create's §8 create→attach decomposition into the loop's
// D81 trend recorder (metering-wire): it opens a per-create CreateTimingHandle, records
// each measured STACK segment plus the OPTIONAL trigger-excluded client RTT, and Observe's
// the decomposition into the shared recorder — the (b)-row "trends are recorded" producer.
// The returned Trend is the trigger-eligible server-span trend across every observed
// create so far (client RTT EXCLUDED, doc 15 §8), the read side the (b)-row instrument
// reports; missing is the set of §8 stack segments this create did not record (the D81
// existence assertion — empty on a complete decomposition).
//
// It is a no-op on a disabled wire (default off): stack/rtt are ignored, missing is nil,
// and the returned Trend is empty (Count 0), so a gate-off create records nothing. The
// wire's Recorder is mutex-guarded, so this is safe to call concurrently from many create
// goroutines. clientRTT ≤ 0 records no RTT segment (RTT is optional and, when present,
// never enters the server span). A segment with a negative duration is rejected by the
// underlying handle and surfaced as an error (a clock ran backwards) without folding.
func (l *reconcileLoop) RecordCreateTiming(sessionUUID string, stack map[createtiming.Segment]time.Duration, clientRTT time.Duration) (trend createtiming.Trend, missing []createtiming.Segment, err error) {
	if l == nil || l.createTiming == nil || !l.createTiming.Enabled() {
		return createtiming.Trend{}, nil, nil
	}
	h := l.createTiming.Begin(sessionUUID)
	for seg, d := range stack {
		if rerr := h.Record(seg, d); rerr != nil {
			return createtiming.Trend{}, nil, rerr
		}
	}
	if clientRTT > 0 {
		if rerr := h.Record(createtiming.SegClientRTT, clientRTT); rerr != nil {
			return createtiming.Trend{}, nil, rerr
		}
	}
	missing = h.MissingSegments()
	h.Observe(context.Background())
	return l.createTiming.ServerSpanTrend(), missing, nil
}

// CreateTimingServerSpanTrend returns the loop's recorded trigger-eligible server-span
// trend across every observed create (client RTT excluded) — the (b)-row instrument's
// read side, exposed for the admin/observability surface. Empty (Count 0) on a disabled
// wire or before any create has been folded.
func (l *reconcileLoop) CreateTimingServerSpanTrend() createtiming.Trend {
	if l == nil || l.createTiming == nil {
		return createtiming.Trend{}
	}
	return l.createTiming.ServerSpanTrend()
}

// Observe is the EVENT-DRIVEN ingest entrypoint (doc 15 §3): the gRPC heartbeat handler
// calls it per inbound heartbeat. It RECORDS the heartbeat into the live feed (so
// placement + resync see the current snapshot) and SUBMITS it to the loop goroutine for
// reconciliation, returning immediately. Submitting (not reconciling inline) is what
// keeps the lastBeat single-goroutine contract: only Run's goroutine touches the
// reconciler. If the loop is not running (Run not yet called or already returned) or the
// inbound buffer is full, Observe records the feed and drops the reconcile submission
// rather than blocking the ingest path — the next heartbeat / the periodic resync
// re-converges (the level-triggered model: a dropped Observe is recovered by re-observing).
//
// ctx scopes the submission (a cancelled ctx — the ingest connection closed — abandons
// the submit). It returns nil on a recorded+submitted (or recorded+dropped) heartbeat;
// a nil heartbeat is ignored.
func (l *reconcileLoop) Observe(ctx context.Context, hb *hostagentv1.Heartbeat) error {
	if hb == nil {
		return nil
	}
	// Record into the live feed first — the scheduler's candidates and the resync
	// observed-set read this. The feed is concurrency-safe; this is the only place the
	// loop writes it.
	l.feed.Record(hb)

	select {
	case l.inbound <- hb:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// The reconcile buffer is full (a burst, or Run not draining). The feed is
		// already updated; drop the reconcile submission — the periodic resync re-runs
		// convergence over the recorded snapshot (the dropped Observe is recovered by
		// re-observing, the level-triggered property). Logged so a sustained drop is
		// visible.
		l.logger.WarnContext(ctx, "reconcile loop: inbound buffer full; dropped Observe submission (feed updated; resync re-converges)",
			slog.String("host", hb.GetHostId()))
		return nil
	}
}

// Run is the single driving goroutine (doc 15 §3): it serializes every reconcile —
// draining the inbound heartbeats (Observe) and firing the periodic full resync on the
// interval ticker — onto ONE goroutine, so the reconciler's lastBeat map is never
// touched concurrently. It runs until ctx is cancelled (a clean shutdown), then returns
// ctx.Err(). main.go starts it in a goroutine; tests run it with a cancellable context
// and assert convergence.
//
// On each inbound heartbeat it calls reconciler.Observe (the event-driven leg); on each
// ticker tick it calls reconciler.Resync over the feed's latest observed-set-per-host
// (the periodic full-resync leg). A degraded-mode error (Postgres down) from either is
// logged and the loop continues — the reconciler already raised the degraded alarm and
// stalled the converging writes; the loop never crashes the control plane on a store
// outage.
func (l *reconcileLoop) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()

	// SECOND TICKER LEG: the D46 escalation sweep (suspendwire). It fires on its OWN ticker
	// but is drained in the SAME select below — ON THIS ONE goroutine, alongside Observe and
	// Resync — so it shares the loop's single-goroutine serialization contract and never
	// races the reconciler's lastBeat owner. When no escalation leg is installed
	// (l.esc == nil) the ticker is a never-firing stopped channel, so the loop runs EXACTLY
	// as before (fully backwards-compatible — no escalation, no behavior change).
	var escC <-chan time.Time
	if l.esc != nil {
		escInterval := l.escInterval
		if escInterval <= 0 {
			escInterval = l.interval
		}
		escTicker := time.NewTicker(escInterval)
		defer escTicker.Stop()
		escC = escTicker.C
	}

	// Signal HealthSnapshot waiters that the loop has stopped so a query submitted around
	// shutdown returns immediately rather than blocking on a reply Run will never send.
	defer close(l.done)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case hb := <-l.inbound:
			if err := l.rec.Observe(ctx, hb); err != nil {
				l.logger.WarnContext(ctx, "reconcile loop: Observe converge fault (continuing; level-triggered re-converges)",
					slog.String("host", hb.GetHostId()), slog.Any("err", err))
			}
		case <-ticker.C:
			if err := l.rec.Resync(ctx, l.feed.ObservedByHost()); err != nil {
				l.logger.WarnContext(ctx, "reconcile loop: Resync converge fault (continuing; level-triggered re-converges)",
					slog.Any("err", err))
			}
		case <-escC:
			// The D46 escalation sweep runs ON THIS goroutine (never a racing goroutine),
			// between Observe/Resync drains, so it honors the lastBeat single-goroutine
			// contract. A sweep fault is logged and the loop continues (the next tick
			// re-sweeps — the level-triggered property).
			l.escalateSweep(ctx)
		case req := <-l.health:
			// LOOP-SERIALIZED liveness read: the lastBeat read runs ON THIS goroutine,
			// the sole lastBeat owner, between Observe/Resync drains — so it honors the
			// single-goroutine contract with NO second writer and NO bare cross-goroutine
			// read of lastBeat (reconciler.go / health.go). reply is buffered (cap 1) so
			// this send never blocks the loop even if the caller already gave up its wait.
			//
			// HealthSnapshotIncluding is the single read for BOTH variants: with a nil/empty
			// req.expected it returns exactly reconciler.HealthSnapshot() (the heard-from
			// set), so the bare HealthSnapshot() path is behavior-preserved; with an expected
			// set it folds in the never-seen expected hosts as EverSeen=false / UNKNOWN. The
			// expected slice is caller-owned input we only read here on the loop goroutine.
			req.reply <- l.rec.HealthSnapshotIncluding(req.expected)
		}
	}
}

// escalateSweep is the D46 escalation pass (suspendwire), run ON the single Run goroutine
// per escalation tick. It lists the SUSPENDED sessions, classifies each pause via the
// EscalationClock against the record's suspend instant (the §3 suspend time, taken as the
// record's UpdatedAt — the last state-mutation instant, which for an un-touched SUSPENDED
// record IS when it entered SUSPENDED), and drives the BOUNDARY HOLD COORDINATION (D110) for
// the hold tiers:
//
//   - TRANSPARENT / BEST-EFFORT (≤15 min) — emit a HOLD_BEGIN SuspendCoord (suspendcoord.go)
//     carrying the tier deadline the proxy bounds its buffering against (the dedup key is the
//     session UUID + suspend instant, so a re-emitted HOLD_BEGIN for the same pause is a safe
//     no-op at the proxy). NO §3 state edge is traversed — a hold is a coordination signal,
//     not a transition.
//   - ESCALATE (>15 min) — the D46 >15-min tier escalates to snapshot+park (→ PARKED),
//     INCLUDING the unanswered genuine rung-2 ask that MUST park and never time out into
//     allow or kill (doc 15 §3 note 2 / D53 / D77). The FROZEN §3 graph (transition_table.go,
//     01KTWJ3PG0) has NO direct SUSPENDED→SNAPSHOTTING edge, but it DOES carry the legal
//     chain SUSPENDED→RESUMING→WORKING→SNAPSHOTTING→PARKED. ParkResumeDriver.EscalateToPark
//     re-converges a SUSPENDED origin along exactly that legal chain (escalateReconverge) —
//     a FORCED escalation park that transits RESUMING/WORKING only as legal waypoints and is
//     therefore NOT gated by the resume-authority (which governs returning a session to
//     WORK; the genuine rung-2 ask parks precisely because no human answered, parkresume.go).
//     NO new §3 edge is added — the §3 freeze stays intact (01KTWJ3PG0). The sweep drives
//     EscalateToPark on the loop goroutine; a drive fault is logged and the next tick
//     re-drives (the level-triggered property; EscalateToPark is idempotent on the record
//     state, so a partial re-converge re-converges from where it stalled).
//
// The sweep is best-effort and idempotent: a hold re-emit is deduped at the proxy, an
// escalate re-drive re-converges from the record's current state, and a store/emit/drive
// fault on one session is logged and the sweep continues to the next (the next tick
// re-sweeps — the level-triggered property). The hold tiers mutate NO §3 state; the
// escalate tier traverses ONLY legal frozen edges.
func (l *reconcileLoop) escalateSweep(ctx context.Context) {
	if l.esc == nil {
		return
	}
	recs, err := l.esc.lister.ListSessions(ctx, store.SessionFilter{State: store.SessionSuspended})
	if err != nil {
		l.logger.WarnContext(ctx, "reconcile loop: escalation sweep list failed (continuing; next tick re-sweeps)", slog.Any("err", err))
		return
	}
	for _, rec := range recs {
		if rec.State != store.SessionSuspended {
			continue // defensive: the filter already narrows, but never act on a non-SUSPENDED record
		}
		suspendedAt := rec.UpdatedAt // the last state-mutation instant == when it entered SUSPENDED
		verdict := l.esc.clock.Classify(suspendedAt)
		// The dedup key correlates a HOLD_BEGIN to its pause so a re-emit (a later tick on the
		// same still-suspended session) is a safe no-op at the proxy: session UUID + the
		// suspend instant uniquely names this pause.
		dedupKey := rec.Ref.SessionUUID + "@" + suspendedAt.UTC().Format(time.RFC3339Nano)
		if verdict.Tier.EscalatesToPark() {
			// >15-min escalate tier — snapshot+park (→ PARKED), incl. the unanswered genuine
			// rung-2 ask that MUST park and never time out (doc 15 §3 note 2 / D53 / D77). Drive
			// EscalateToPark on the LOOP GOROUTINE: it re-converges the SUSPENDED origin along the
			// LEGAL frozen chain SUSPENDED→RESUMING→WORKING→SNAPSHOTTING→PARKED (escalateReconverge,
			// a FORCED park NOT gated by resume-authority) — NO new §3 edge, the §3 freeze stays
			// intact (01KTWJ3PG0). It is idempotent on the record state, so a re-drive after a
			// partial re-converge resumes from where it stalled. A drive fault is logged and the
			// next tick re-drives (the level-triggered property); the sweep continues to the next
			// session rather than aborting the pass.
			if _, err := l.esc.driver.EscalateToPark(ctx, rec.Ref.SessionUUID); err != nil {
				l.logger.WarnContext(ctx, "reconcile loop: D46 escalate-to-park drive failed (continuing; next tick re-drives — EscalateToPark is idempotent on record state)",
					slog.String("session", rec.Ref.SessionUUID), slog.String("reason", string(rec.SuspendReason)), slog.Duration("elapsed", verdict.Elapsed), slog.Any("err", err))
			}
			continue
		}
		// Hold tiers (transparent / best-effort): emit the D110 HOLD_BEGIN coordination so the
		// proxy bounds its VM-leg buffering against the tier deadline. A nil coord cannot
		// happen (installEscalation refuses it); an emit fault is logged and the sweep continues.
		if err := l.esc.coord.EmitHoldBegin(ctx, rec.Ref.SessionUUID, verdict, dedupKey); err != nil {
			l.logger.WarnContext(ctx, "reconcile loop: D46 HOLD_BEGIN emit failed (continuing; next tick re-emits, deduped at the proxy)",
				slog.String("session", rec.Ref.SessionUUID), slog.Any("err", err))
		}
	}
}

// escalateNow runs one escalation sweep synchronously — a test seam so a test can force an
// escalation pass without waiting for the ticker. Like resyncNow/observeNow it must run on
// the loop's goroutine (or before Run starts), never concurrently with Run, to honor the
// single-goroutine contract.
func (l *reconcileLoop) escalateNow(ctx context.Context) { l.escalateSweep(ctx) }

// HealthSnapshot returns the reconciler's current per-host LIVE/UNKNOWN view, read ON the
// reconcile-loop goroutine (the sole lastBeat owner) so the read is race-clean with the
// concurrent Observe/Resync writes — it is the LOOP-SERIALIZED query seam the admin surface
// renders /debug/liveness + the orchestrator_host_liveness expvar from (admin.go
// HealthSnapshotter; doc 15 §3/§5.2; D35/D72). It submits a healthReq onto the loop's
// buffered query channel and waits for Run to read lastBeat and reply on its own goroutine.
// It adds NO new lastBeat writer and never reads lastBeat directly from the caller's
// goroutine; the snapshot is a pure non-state liveness annotation (no §3 state name, no
// record mutation).
//
// It is safe to call from any goroutine (the admin HTTP handler). It NEVER blocks
// indefinitely: it abandons the wait if ctx is cancelled (returning a nil snapshot) or if
// the loop has stopped (Run returned — l.done closed), so a query around shutdown or to a
// never-started loop returns promptly rather than deadlocking the reply channel. A nil
// return renders as an empty liveness view (no hosts), the same as a fleet that has never
// been heard from.
func (l *reconcileLoop) HealthSnapshot(ctx context.Context) []reconciler.HostHealth {
	return l.healthSnapshot(ctx, nil)
}

// HealthSnapshotIncluding is the OPT-IN companion to HealthSnapshot: it routes the SAME
// loop-serialized query through the SAME healthReq channel, but carries an expected-host set
// so the loop serves reconciler.HealthSnapshotIncluding(expected) — the UNION of every
// heard-from host AND every expected host_id (doc 15 §3 / §5.2; D35/D72; health.go). An
// expected host the reconciler has NEVER heard from renders as a zero-LastBeat EverSeen=false
// UNKNOWN entry rather than being ABSENT, so the admin /debug/liveness readout can surface an
// expected-but-silent host instead of silently omitting it. A nil/empty expected set makes
// this byte-for-byte identical to HealthSnapshot (the heard-from set).
//
// It shares HealthSnapshot's ENTIRE concurrency + bail-out discipline (it is the same private
// path with the expected set threaded onto the healthReq): the lastBeat read runs ON the Run
// goroutine — the sole lastBeat owner — so there is NO new lastBeat writer and NO bare
// cross-goroutine read (the single-goroutine contract holds); the expected slice is
// caller-owned READ-ONLY input the loop never stores or mutates; the snapshot is a pure
// non-state liveness annotation (no §3 state name, no record mutation). It is safe to call
// from any goroutine and NEVER blocks indefinitely — it abandons the wait (nil snapshot) on
// ctx-cancel or loop-stop (l.done), exactly as HealthSnapshot does.
func (l *reconcileLoop) HealthSnapshotIncluding(ctx context.Context, expected []string) []reconciler.HostHealth {
	return l.healthSnapshot(ctx, expected)
}

// healthSnapshot is the shared loop-serialized query body for both HealthSnapshot (expected
// nil) and HealthSnapshotIncluding (expected set). It submits one healthReq carrying the
// expected set onto the loop's buffered query channel and waits for Run to compute the read on
// its own goroutine and reply — honoring ctx-cancel and loop-stop on BOTH the submit and the
// await so the query is always bounded. expected is caller-owned; it is only read on the Run
// goroutine inside the loop's HealthSnapshotIncluding call, never stored on the loop.
func (l *reconcileLoop) healthSnapshot(ctx context.Context, expected []string) []reconciler.HostHealth {
	reply := make(chan []reconciler.HostHealth, 1)
	req := healthReq{reply: reply, expected: expected}
	// Submit the query. Bail out (nil snapshot) if the caller's ctx cancels or the loop has
	// already stopped, rather than blocking on a channel the loop will never drain.
	select {
	case l.health <- req:
	case <-ctx.Done():
		return nil
	case <-l.done:
		return nil
	}
	// Await the loop's reply, still honoring ctx-cancel and loop-stop so the wait is bounded.
	// The reply channel is buffered (cap 1), so if Run is mid-select when we give up here,
	// its later send completes into the buffer and is harmlessly discarded — Run never blocks.
	select {
	case snap := <-reply:
		return snap
	case <-ctx.Done():
		return nil
	case <-l.done:
		// Drain a reply that may have been sent just before close(l.done) so a snapshot
		// already computed on the loop goroutine is not dropped; otherwise return nil.
		select {
		case snap := <-reply:
			return snap
		default:
			return nil
		}
	}
}

// resyncNow runs one Resync synchronously over the feed's current observed set — a test
// seam so a test can force a periodic-resync pass without waiting for the ticker. It is
// NOT called from Run (which owns the ticker); a test calls it on the loop's goroutine
// (or before Run starts) to drive the resync leg deterministically. It honors the same
// single-goroutine contract: a test must not call it concurrently with Run.
func (l *reconcileLoop) resyncNow(ctx context.Context) error {
	return l.rec.Resync(ctx, l.feed.ObservedByHost())
}

// observeNow runs one Observe synchronously (bypassing the inbound channel) — a test
// seam to drive the event-driven leg deterministically on the calling goroutine. Like
// resyncNow it must not run concurrently with Run; a test uses it to assert convergence
// without the channel hop.
func (l *reconcileLoop) observeNow(ctx context.Context, hb *hostagentv1.Heartbeat) error {
	if hb != nil {
		l.feed.Record(hb)
	}
	return l.rec.Observe(ctx, hb)
}
