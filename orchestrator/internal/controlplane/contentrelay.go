package controlplane

// contentrelay.go is the PRODUCTION READ-STREAM content relay (D61/D79, doc 15
// §5.3/§5.5): it relays Claude Code's projected attach.v1 CONTENT (chat, tool-use,
// subagent-tree, ask, plan-delta, accounting …) through the orchestrator's
// WatchSession fan-out (attach.Fanout.Publish) so N READERS — the web client and
// every spectator — observe CC's output, not only the one WRITER.
//
// THE GAP THIS CLOSES. On the single-box MVP the only content path was the writer
// seat's own SocketConn.Events() channel, folded straight into serpent-tui's loop:
// only the writer saw CC output, because the control-plane WatchSession fan-out
// carried ONLY the D3/§3 lifecycle STATE edges (attachrelay.go, from heartbeats),
// the WRITER_SEAT_CHANGED handoff (the SeatArbiter), and the InputActivity write
// projection (writerrelay.go DriveSession). CC's *content* never joined the fan-out,
// so a non-writer reader saw seat/state edges but no chat/tool output. This relay is
// the missing leg: it feeds CC content into the SAME Fanout every N-reader already
// subscribes to (doc 15 §5.3), at the SAME single ordering point (the Fanout stamps
// the per-event seq — the orchestrator is the seq authority, watch.go).
//
// THE SYMMETRIC TWIN OF THE WRITE LEG. writerrelay.go's DriveSink carries an ADMITTED
// write frame host-ward to CC stdin (the RELAY transport, attach_handle.proto
// ENDPOINT_TRANSPORT_RELAY). This is the read-ward mirror: the ContentSource seam
// reads CC's projected content events host-ward (the host-agent per-session bridge's
// Events() ring, relayed control-plane-ward over the SAME RELAY carrier) and this
// relay Publishes each into the Fanout. Like DriveSink it is a NARROW seam the
// orchestrator declares (the orchestrator may not import client/hostbridge — the only
// legal cross-tree import is proto/gen/go, D40/D67): the live wiring adapts the host-
// agent bridge onto it behind DS_ORCH_LIVE in the cmd/orchestrator composition root; a
// nil source DISABLES the relay (a clean degrade — the fan-out simply carries no
// content, exactly today's behavior), and tests supply a fake source.
//
// READERS STAY PROVABLY READ-ONLY (D136 spectators). The relay ONLY Publishes into
// the Fanout; a WatchSession subscriber ONLY Subscribes (watch.go). The relay
// additionally ENFORCES the read-only content boundary at the seam: it publishes ONLY
// genuine CC CONTENT event types (isContentEvent) and DROPS anything else. The three
// control-plane-authoritative event classes — SESSION_STATE (attachrelay.go, off the
// §3 heartbeat), WRITER_SEAT_CHANGED (the SeatArbiter), INPUT_ACTIVITY (DriveSession)
// — have their OWN authoritative producers and are never re-originated through the
// content leg, so a buggy or compromised content source cannot inject a forged seat
// handoff, a fake lifecycle edge, or a spurious write-activity event onto the read
// stream. The content leg carries content; the control edges keep their own single
// producers.
//
// LIFECYCLE (best-effort, purely additive). A per-session pump goroutine is started
// (ensure) the first time the session is observed in a live §3 state on the SAME
// heartbeat path attachrelay.go already runs, and stopped (stop) when the session
// reaches DESTROYED. Each pump opens the ContentSource stream and re-opens it after a
// transient host-side drop, with a bounded backoff, until its context is cancelled. A
// content-pump fault NEVER disturbs the reconcile path or the state-edge relay — the
// content feed is additive on top of an unchanged control plane. The pumps run off the
// serve lifetime context (Start), so they outlive any single heartbeat stream and are
// all cancelled at shutdown.
//
// Governing decisions: D61 (the one-writer/N-reader seat this serves the reader half
// of), D79 (the per-event seqs the Fanout stamps), D136 (spectators are read-only),
// D38 (the VM-local socket terminates host-side; this is the control-plane side of
// that seam), D40/D67 (no cross-tree import — a narrow seam). Primary doc:
// docs/15-orchestrator-design.md §5.3, §5.5.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// ContentSource is the NARROW host-agent read seam the content relay pumps into the
// Fanout: it opens a READ-ONLY stream of a session's projected attach.v1 CONTENT events
// (the host-agent per-session bridge's Events() ring, relayed control-plane-ward over
// the RELAY carrier — the symmetric twin of the DriveSink write leg). It is declared
// narrow here because the orchestrator may not import the host-agent runtime directly
// (the only legal cross-tree Go import is proto/gen/go, D40/D67): the cmd/orchestrator
// composition root adapts the live host-agent bridge onto it behind DS_ORCH_LIVE, tests
// supply a fake. A nil ContentSource DISABLES the content relay (a clean degrade).
type ContentSource interface {
	// OpenContent opens a read-only subscription to CC's projected attach.v1 content
	// events for sessionUUID and returns a channel yielding them in host-side order. The
	// channel is CLOSED when the host-side stream ends (CC exited, or the bridge dropped)
	// or when ctx is cancelled; the relay re-opens after a transient close while its pump
	// context is live. A non-nil err is a dial/attach fault (no stream opened — the relay
	// logs it and retries with backoff until its context is cancelled). The source
	// ORIGINATES no control edges: it yields CC content; the relay additionally filters to
	// the content event set (isContentEvent) so a misbehaving source cannot inject one.
	OpenContent(ctx context.Context, sessionUUID string) (<-chan *attachv1.SessionEvent, error)
}

// contentFanout is the narrow publish seam the content relay drives — exactly
// attach.Fanout.Publish (watch.go): stamp-seq + record-ring + fan-to-subscribers. It is
// the SAME publish the state-edge relay (attachrelay.go) and the seat arbiter use, so CC
// content shares the one per-session seq authority with the control edges (one ordering
// point every reader recovers by). Declared narrow so the relay depends only on the one
// method and a test double records what was published without standing up the Fanout.
type contentFanout interface {
	Publish(ctx context.Context, sessionUUID string, ev *attachv1.SessionEvent) uint64
}

const (
	// contentReopenBackoffMin is the initial re-open backoff after a dial fault or a
	// transient host-side stream close: the pump waits this long before re-opening the
	// ContentSource (so a not-yet-ready bridge, or a momentary drop, does not spin).
	contentReopenBackoffMin = 200 * time.Millisecond
	// contentReopenBackoffMax caps the exponential re-open backoff so a persistently
	// unreachable source settles to a slow, bounded retry rather than an unbounded delay.
	contentReopenBackoffMax = 5 * time.Second
)

// contentRelay manages the per-session content pumps that feed CC's projected content
// into the WatchSession Fanout. Construct with newContentRelay; arm the pump lifetime
// with Start(serveCtx). ensure/stop are driven off the heartbeat observed-session set
// (attachrelay.go) — a live-state edge starts a session's pump, a DESTROYED edge stops
// it. A nil relay (no ContentSource wired) is never constructed; the callers guard on
// nil so the whole leg is a clean no-op when disabled.
type contentRelay struct {
	source ContentSource
	fanout contentFanout
	logger *slog.Logger

	// mu guards base/started and the pumps map. ensure/stop are called from the heartbeat
	// ingest's Recv-loop goroutine(s) (one per host stream), so the pump registry must be
	// safe across concurrent session observations.
	mu      sync.Mutex
	base    context.Context // the serve lifetime context (Start); nil until armed.
	started bool
	pumps   map[string]*contentPump // session_uuid → running pump
}

// contentPump is one session's running relay goroutine: its cancel closes the pump's
// context (stop, or Start-context cancel at shutdown). The pointer identity is the
// registry key's value so a pump's self-cleanup (on exit) deletes ONLY its own entry,
// never a newer pump a stop→ensure race installed.
type contentPump struct {
	cancel context.CancelFunc
}

// newContentRelay builds the relay over the host-agent content source and the Fanout
// publish seam. It is constructed by NewControlPlane ONLY when a ContentSource is wired
// (Deps.ContentSource non-nil); a nil source means no relay (the caller leaves the
// ControlPlane field nil and every ensure/stop site guards on it).
func newContentRelay(source ContentSource, fanout contentFanout, logger *slog.Logger) *contentRelay {
	if logger == nil {
		logger = slog.Default()
	}
	return &contentRelay{
		source: source,
		fanout: fanout,
		logger: logger,
		pumps:  make(map[string]*contentPump),
	}
}

// Start arms the relay with the serve lifetime context: the per-session pumps derive
// their context from it, so they outlive any single heartbeat stream and are ALL
// cancelled when the serve context is cancelled (shutdown). ensure is a no-op until
// Start is called (no pump can outlive a context that does not yet exist). Idempotent.
func (r *contentRelay) Start(ctx context.Context) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.base = ctx
	r.started = true
}

// ensure starts sessionUUID's content pump if the relay is armed (Start) and no pump is
// already running for it. Idempotent: a repeat ensure for a live session is a no-op, so
// the caller may drive it off every live-state observation without churning the pump.
// A nil relay or an un-armed relay (Start not yet called) is a clean no-op.
func (r *contentRelay) ensure(sessionUUID string) {
	if r == nil || sessionUUID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started || r.base == nil {
		return // not armed yet — a pump cannot outlive a context that does not exist.
	}
	if _, running := r.pumps[sessionUUID]; running {
		return // already pumping this session (idempotent).
	}
	ctx, cancel := context.WithCancel(r.base)
	pump := &contentPump{cancel: cancel}
	r.pumps[sessionUUID] = pump
	go r.run(ctx, sessionUUID, pump)
}

// stop cancels sessionUUID's content pump (the DESTROYED edge, or an explicit teardown)
// and forgets it. Idempotent: stopping a session with no live pump is a clean no-op.
func (r *contentRelay) stop(sessionUUID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	pump := r.pumps[sessionUUID]
	if pump != nil {
		delete(r.pumps, sessionUUID)
	}
	r.mu.Unlock()
	if pump != nil {
		pump.cancel()
	}
}

// forget removes the pump's own registry entry on exit, but ONLY if it is still the
// current pump for the session (pointer identity). A stop→ensure race that installed a
// newer pump for the same session leaves that newer pump untouched.
func (r *contentRelay) forget(sessionUUID string, self *contentPump) {
	r.mu.Lock()
	if r.pumps[sessionUUID] == self {
		delete(r.pumps, sessionUUID)
	}
	r.mu.Unlock()
}

// run is one session's content pump: it opens the ContentSource stream, Publishes every
// CC content event into the Fanout, and re-opens after a transient host-side close — with
// a bounded exponential backoff on a dial fault — until ctx is cancelled (stop, or the
// serve context at shutdown). It is best-effort and additive: it never touches the
// reconcile path or the state-edge relay, so a persistently unreachable source degrades
// to a slow retry that a live reader simply sees no content on, not a broken control plane.
func (r *contentRelay) run(ctx context.Context, sessionUUID string, self *contentPump) {
	defer self.cancel() // release the pump's context on every exit path.
	defer r.forget(sessionUUID, self)

	backoff := contentReopenBackoffMin
	for {
		if ctx.Err() != nil {
			return
		}
		ch, err := r.source.OpenContent(ctx, sessionUUID)
		if err != nil {
			// A dial/attach fault: the bridge is not (yet) reachable. Log at debug (a
			// not-yet-ready bridge during CREATING is expected, not an error), back off,
			// and retry until the pump context is cancelled.
			r.logger.DebugContext(ctx, "content relay: open content stream failed, will retry",
				slog.String("session_uuid", sessionUUID), slog.Any("err", err))
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = contentReopenBackoffMin // reset on a successful open.
		r.drain(ctx, sessionUUID, ch)
		// The stream closed. If the pump context is still live, this was a transient
		// host-side drop (CC restart, bridge reconnect) — re-open after a short wait; a
		// real teardown cancels ctx (stop on DESTROYED / shutdown) and we return.
		if ctx.Err() != nil {
			return
		}
		if !sleepCtx(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

// drain Publishes every CC CONTENT event from one open stream into the Fanout until the
// channel closes or ctx is cancelled. It ENFORCES the read-only content boundary (D136):
// only genuine content event types are published; a non-content event (a control edge a
// misbehaving source tried to inject) is DROPPED — the state/seat/activity edges keep
// their own authoritative producers. The Fanout stamps the per-event seq + session_id
// (the seq authority, watch.go), so a source-supplied seq/session_id is irrelevant here.
func (r *contentRelay) drain(ctx context.Context, sessionUUID string, ch <-chan *attachv1.SessionEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return // the host-side stream closed.
			}
			if ev == nil {
				continue
			}
			if !isContentEvent(ev.GetType()) {
				// Read-only content boundary: the content leg carries ONLY CC content. A
				// SESSION_STATE / WRITER_SEAT_CHANGED / INPUT_ACTIVITY (or UNSPECIFIED)
				// event has its own single authoritative producer and is dropped here, so
				// the content source cannot forge a control edge onto the read stream.
				r.logger.DebugContext(ctx, "content relay: dropped non-content event from source",
					slog.String("session_uuid", sessionUUID), slog.String("type", ev.GetType().String()))
				continue
			}
			r.fanout.Publish(ctx, sessionUUID, ev)
		}
	}
}

// isContentEvent reports whether t is a genuine CC CONTENT event type — the events a
// reader wants to SEE (chat, tool-use, subagent tree, ask prompts, plan deltas, quota,
// session init/accounting). It is the read-only allowlist the content relay enforces at
// the seam: the three control-plane-authoritative classes (SESSION_STATE,
// WRITER_SEAT_CHANGED, INPUT_ACTIVITY) and UNSPECIFIED are NOT content and never enter
// the fan-out through the content leg (they have their own single producers). A new
// additive content event type must be added here to be relayed (fail-closed: an unknown
// type is treated as non-content and dropped).
func isContentEvent(t attachv1.EventType) bool {
	switch t {
	case attachv1.EventType_EVENT_TYPE_SESSION_INIT,
		attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE,
		attachv1.EventType_EVENT_TYPE_CHAT_DELTA,
		attachv1.EventType_EVENT_TYPE_TOOL_INVOKED,
		attachv1.EventType_EVENT_TYPE_TOOL_COMPLETED,
		attachv1.EventType_EVENT_TYPE_SUBAGENT_SPAWNED,
		attachv1.EventType_EVENT_TYPE_SUBAGENT_PROGRESS,
		attachv1.EventType_EVENT_TYPE_SUBAGENT_COMPLETED,
		attachv1.EventType_EVENT_TYPE_SUBAGENT_ACCOUNTED,
		attachv1.EventType_EVENT_TYPE_ASK_REQUESTED,
		attachv1.EventType_EVENT_TYPE_ASK_RESOLVED,
		attachv1.EventType_EVENT_TYPE_QUOTA_UPDATED,
		attachv1.EventType_EVENT_TYPE_SESSION_ACCOUNTED,
		attachv1.EventType_EVENT_TYPE_PLAN_DELTA:
		return true
	default:
		// EVENT_TYPE_UNSPECIFIED, EVENT_TYPE_SESSION_STATE,
		// EVENT_TYPE_INPUT_ACTIVITY, EVENT_TYPE_WRITER_SEAT_CHANGED — control edges with
		// their own producers, never relayed as content (fail-closed on anything unknown).
		return false
	}
}

// nextBackoff doubles the current backoff, capped at contentReopenBackoffMax.
func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > contentReopenBackoffMax {
		return contentReopenBackoffMax
	}
	return next
}

// sleepCtx waits d, returning true if the wait completed and false if ctx was cancelled
// first (so the caller stops its retry loop promptly at shutdown).
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// contentLifecycle is the narrow start/stop seam the state-edge relay (attachrelay.go)
// drives off the heartbeat observed-session set: a live-state edge ensures the session's
// content pump, a DESTROYED edge stops it. *contentRelay satisfies it; a nil lifecycle
// leaves the state-edge relay unchanged (no content leg wired).
type contentLifecycle interface {
	ensure(sessionUUID string)
	stop(sessionUUID string)
}

// Compile-time proofs: the relay satisfies the lifecycle seam the state-edge relay drives,
// and the production attach.Fanout satisfies the narrow content-publish seam (so it drops
// straight in as the relay's publish target).
var (
	_ contentLifecycle = (*contentRelay)(nil)
	_ contentFanout    = (*attach.Fanout)(nil)
)
