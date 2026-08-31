package controlplane

// attachrelay.go is the HOST-AGENT → ORCHESTRATOR RELAY that FEEDS the control-plane
// WatchSession fan-out (attach.Fanout.Publish). It is the seam the attach package's
// doc.go calls out: the host agent's hostbridge ring (client/hostbridge, the VM-side
// fan-out behind the D38 socket) and the orchestrator-side attach.Fanout are DISTINCT
// rings by design — this file is the bridge between them on the control-plane side.
//
// WHERE THE HOST-WARD EVENTS ENTER (doc 15 §5.2 → §5.3). The orchestrator's ONLY live
// view of a host is the inbound hostagent.v1 Heartbeat (heartbeatingest.go): each frame
// carries the host's observed-session set (hypervisor.v1.ObservedSession, each with the
// §3 ObservedState). The session-LIFECYCLE class signal the WatchSession clients care
// about — a session's §3 state transitioning (CREATING → READY → ATTACHED → … →
// DESTROYED) — rides exactly this heartbeat (doc 15 §5.5: "session-lifecycle data via
// the host agent's lifecycle channel (§5.2)"). So the relay sits ON the heartbeat ingest
// path: it OBSERVES every inbound heartbeat (as a heartbeatObserver decorator wrapping
// the reconcile loop's Observe), projects each observed session whose §3 state CHANGED
// into an attach.v1.SessionEvent of type SESSION_STATE, and Publishes it into the Fanout
// — where the WatchSession handler (sessionservice.go) fans it to the one WRITER + the N
// READERs. This is the path by which Fanout.Publish gains its first production caller.
//
// WHY A STATE-CHANGE PROJECTION, NOT A FRAME-FOR-FRAME REPUBLISH. The heartbeat is a
// LEVEL-TRIGGERED steady-state report (doc 15 §3 / hostagent/doc.go): a host re-emits
// every observed session every cadence tick, the SAME state, so a frame-for-frame
// republish would flood the fan-out and the resume ring with duplicate SESSION_STATE
// events. The relay keeps a per-session last-published §3 state and publishes ONLY on a
// transition (or first observation) — the EDGE off the level signal — so each WatchSession
// subscriber sees one event per real lifecycle transition, seq-stamped by the Fanout
// (the orchestrator is the seq authority, watch.go). The dedup map is the relay's only
// state; it is pruned when a session reaches a terminal DESTROYED projection.
//
// DECOUPLING (the decorator shape). The relay does NOT replace the reconcile path: it
// WRAPS the loop's Observe (the heartbeatObserver seam heartbeatingest.go already routes
// through), publishing the host-ward state edges into the Fanout and THEN delegating to
// the wrapped observer (the reconcile submit). So the heartbeat ingest is unchanged — it
// still drives convergence — and the fan-out feed is purely additive: a relay publish
// failure never disturbs the reconcile path, and the level-triggered drop-on-full-buffer
// reconcile semantics (reconcileLoop.Observe) are preserved verbatim.
//
// Governing decisions: D18 (the fan-out leg this feeds), D79 (the per-event seqs the
// Fanout stamps), D38 (the VM-local socket terminates host-side; this is the control-plane
// side of that seam), D35 (the level-triggered heartbeat the edge is taken off). Primary
// doc: docs/15-orchestrator-design.md §5.2, §5.3, §5.5.

import (
	"context"
	"sync"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// attachRelay is the host-agent → orchestrator relay: a heartbeatObserver decorator that
// projects host-ward observed-session §3 state EDGES into the control-plane WatchSession
// fan-out (attach.Fanout.Publish) and then delegates to the wrapped observer (the
// reconcile loop's Observe). Construct with newAttachRelay; the serve bootstrap wraps the
// reconcile loop in it when the SessionService is serving the attach legs (a wired Fanout).
type attachRelay struct {
	fanout heartbeatFanout
	next   heartbeatObserver

	// content is the OPTIONAL content-relay lifecycle seam (contentrelay.go): the relay
	// starts a session's CC-content pump on its FIRST live-state edge and stops it on the
	// DESTROYED edge, so the SAME heartbeat observed-session set that drives the §3 state
	// edges also drives the content leg's per-session lifecycle. Nil leaves the state-edge
	// relay byte-for-byte unchanged (no content leg wired). Installed via withContent.
	content contentLifecycle

	// mu guards lastState. The heartbeat ingest serves one Recv-loop goroutine per host
	// stream (heartbeatingest.go), so several hosts' frames reach Observe concurrently;
	// the relay's per-session edge dedup must be safe across them.
	mu sync.Mutex
	// lastState is the per-session last-PUBLISHED §3 state name (the edge dedup): a
	// heartbeat that re-reports a session in the SAME state publishes nothing (the
	// level-triggered steady state), only a transition (or a first observation) is an
	// edge the relay fans. Keyed by session_uuid.
	lastState map[string]attachv1.SessionStateName
}

// heartbeatFanout is the narrow publish seam the relay drives — exactly
// attach.Fanout.Publish (watch.go). Declared narrow here so the relay depends only on the
// one method (stamp-seq + record-ring + fan-to-subscribers) and a test double can record
// what was published without standing up the whole Fanout.
type heartbeatFanout interface {
	Publish(ctx context.Context, sessionUUID string, ev *attachv1.SessionEvent) uint64
}

// newAttachRelay builds the relay over the Fanout publish seam and the wrapped observer
// (the reconcile loop's Observe). A nil fanout makes the relay a pass-through (it just
// delegates to next) so a deployment not serving the attach legs is a clean degrade; a
// nil next is tolerated (the relay then only publishes, useful in a focused test).
func newAttachRelay(fanout heartbeatFanout, next heartbeatObserver) *attachRelay {
	return &attachRelay{
		fanout:    fanout,
		next:      next,
		lastState: make(map[string]attachv1.SessionStateName),
	}
}

// withContent installs the content-relay lifecycle seam so the relay drives a session's
// CC-content pump off the SAME §3 state edges it already fans (ensure on a live edge,
// stop on DESTROYED). A nil lifecycle is a no-op (the content leg stays unwired). Returns
// the relay for a fluent one-line wire in the serve bootstrap. Called once at wiring
// time, before the relay observes any frame.
func (r *attachRelay) withContent(content contentLifecycle) *attachRelay {
	if content != nil {
		r.content = content
	}
	return r
}

// Observe is the heartbeatObserver entrypoint (the seam heartbeatingest.go routes each
// inbound frame through). It FIRST projects the heartbeat's observed-session §3 state
// edges into the Fanout (the WatchSession feed), THEN delegates to the wrapped observer
// (the reconcile submit). The fan-out projection is best-effort and additive: it never
// fails the Observe (a publish has no error to surface — Fanout.Publish drops a broken
// subscriber independently, watch.go), so the reconcile path is byte-for-byte unchanged.
//
// A nil heartbeat short-circuits to the wrapped observer (which also ignores nil — defense
// in depth). The edge dedup (lastState) means a steady-state re-report of an unchanged
// session publishes nothing; only a §3 transition (or a first observation) is fanned.
func (r *attachRelay) Observe(ctx context.Context, hb *hostagentv1.Heartbeat) error {
	if hb != nil && r.fanout != nil {
		r.publishStateEdges(ctx, hb)
	}
	if r.next == nil {
		return nil
	}
	return r.next.Observe(ctx, hb)
}

// publishStateEdges projects the heartbeat's observed-session set into the Fanout: for
// each observed session whose §3 state DIFFERS from the relay's last-published state for
// that session (an edge), it Publishes a SESSION_STATE event carrying the new §3 state.
// The Fanout stamps the per-event seq + session_id (watch.go is the seq authority), so
// the relay leaves Seq/SessionId zero and lets Publish assign them. A session that reaches
// DESTROYED is published once then pruned from the dedup map (no live session to fan past
// teardown — the Fanout.Close on DESTROYED, watch.go, drops the stream regardless).
func (r *attachRelay) publishStateEdges(ctx context.Context, hb *hostagentv1.Heartbeat) {
	for _, obs := range hb.GetObserved() {
		sessionUUID := obs.GetSessionUuid()
		if sessionUUID == "" {
			continue // an observed entry with no session key is not a fan-out target.
		}
		st := obs.GetObservedState().GetName()
		if st == attachv1.SessionStateName_SESSION_STATE_NAME_UNSPECIFIED {
			// An observed session with no §3 state is not a lifecycle edge — the host has
			// not reported a state worth fanning (defense in depth; ObservedState is the
			// §3 vocabulary source and a real frame carries it).
			continue
		}

		r.mu.Lock()
		prev, seen := r.lastState[sessionUUID]
		if seen && prev == st {
			r.mu.Unlock()
			continue // steady-state re-report of an unchanged session: no edge, no publish.
		}
		if st == attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED {
			// Terminal: publish the DESTROYED edge once, then forget the session so the
			// dedup map does not grow without bound as sessions churn.
			delete(r.lastState, sessionUUID)
		} else {
			r.lastState[sessionUUID] = st
		}
		r.mu.Unlock()

		// Drive the content-leg lifecycle off the SAME §3 edge (outside r.mu — the seam
		// takes its own lock and may spawn a pump goroutine). A live edge ENSURES the
		// session's CC-content pump (idempotent — a repeat live edge is a no-op); the
		// DESTROYED edge STOPS it (the content stream is torn down with the session). This
		// is best-effort and additive: a nil content seam leaves the relay unchanged.
		if r.content != nil {
			if st == attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED {
				r.content.stop(sessionUUID)
			} else {
				r.content.ensure(sessionUUID)
			}
		}

		// Build the §3 SESSION_STATE event off the SAME observed §3 state the reconciler
		// reads (one vocabulary, doc 15 §3) and Publish it. Seq + SessionId are stamped by
		// the Fanout (the seq authority), so they are left zero here. ObservedAt is left
		// zero: the host frame carries no per-session observed-at on ObservedSession, and
		// the adapter-clock field is reserved for the replay-deterministic timeline the
		// host-side projection owns (the control-plane seq is the WatchSession ordering).
		ev := &attachv1.SessionEvent{
			Type: attachv1.EventType_EVENT_TYPE_SESSION_STATE,
			Payload: &attachv1.SessionEvent_SessionState{
				SessionState: &attachv1.SessionState{Name: st},
			},
			Source: []string{obs.GetDomainUuid()}, // the runtime record uuid the projection came from
		}
		r.fanout.Publish(ctx, sessionUUID, ev)
	}
}

// Compile-time proof the relay satisfies the heartbeatObserver seam (so the serve
// bootstrap can install it as the heartbeat ingest's observer, wrapping the reconcile
// loop) and that attach.Fanout satisfies the narrow publish seam (so the production
// Fanout drops straight in as the relay's publish target).
var (
	_ heartbeatObserver = (*attachRelay)(nil)
	_ heartbeatFanout   = (*attach.Fanout)(nil)
)
