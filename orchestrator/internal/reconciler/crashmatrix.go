package reconciler

// The crash-matrix cells the reconciler OWNS (doc 15 §3), each a distinct method
// so the unit tests can drive one cell at a time:
//
//   host-agent crash  → RecoverSessions re-adoption seeds the observed set; the
//                        reconciler then converges it exactly like a steady-state
//                        heartbeat (AdoptRecovered below is the seam that turns a
//                        RecoverSessionsResponse into an Observe-equivalent diff).
//   replica  crash    → STATELESS: the reconciler's only state (lastBeat) is
//                        rebuildable by re-observing, so a fresh replica converges
//                        identically — a no-op (asserted by tests, no method).
//   Postgres down     → DEGRADED mode: store calls return ErrUnavailable; the
//                        reconciler stalls converging writes (degraded()/
//                        AlarmDegraded), running sessions continue, host agents
//                        stay autonomous (handled inline on every store path).
//   3 missed beats    → sessions UNKNOWN, NEVER auto-destroyed (markMissedBeats).
//   host crash        → sessions LOST at v0 (explicit §3 non-claim) — the
//                        durability-stream restore is the named M3 path; the
//                        reconciler does NOT auto-destroy a crashed host's records,
//                        it marks them UNKNOWN (the same missed-beat path) and
//                        leaves the LOST disposition to the operator / M3.

import (
	"context"
	"time"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// markMissedBeats implements the crash-matrix cell "3 missed heartbeats →
// sessions UNKNOWN, never auto-destroyed" (doc 15 §3 / §5.2). For every host the
// reconciler knows about (knownHosts ∪ hosts reconciled this cycle) that has gone
// SILENT past the missed-beat window (silenceWindow), it raises AlarmHostUnknown
// for the host's host-resident sessions.
//
// "UNKNOWN" is a LIVENESS ANNOTATION, NOT a §3 state: the §3 machine has no
// UNKNOWN state (the 12 frozen states do not include it), and a missed beat must
// NEVER mutate the record's lifecycle state — least of all to DESTROYED. So this
// path writes NOTHING to the record's State; it raises the operator alarm and
// leaves the desired state intact, so the moment heartbeats resume the normal
// diff re-converges. This is the load-bearing invariant: a transient network
// partition or a slow host can never cause a session to be torn down.
//
// A host that never appears in knownHosts (no records reference it) is not swept
// — there is nothing to mark UNKNOWN.
func (r *Reconciler) markMissedBeats(ctx context.Context, hosts map[string]bool) {
	now := r.now()
	window := r.silenceWindow()
	for hostID := range hosts {
		last, seen := r.lastBeat[hostID]
		if seen && now.Sub(last) <= window {
			continue // within the window — host is live, nothing to mark.
		}
		// Either never heard from, or silent past the window → its sessions go
		// UNKNOWN (annotation only; never auto-destroyed). We do NOT touch any
		// record state here.
		r.markHostUnknown(ctx, hostID, seen, last, now, window)
	}
}

// markHostUnknown raises the UNKNOWN liveness annotation for one silent host's
// host-resident sessions WITHOUT mutating any record state (the never-auto-destroy
// invariant). It reads the host's records to scope the per-session alarms; a
// store outage here is itself the degraded mode, surfaced and skipped (a host we
// cannot enumerate during a Postgres outage is not destroyed — it is simply not
// annotated this cycle).
func (r *Reconciler) markHostUnknown(ctx context.Context, hostID string, seen bool, last, now time.Time, window time.Duration) {
	recs, err := r.store.ListSessions(ctx, store.SessionFilter{HostID: hostID, IncludeDestroyed: false})
	if err != nil {
		if degraded(err) {
			r.raise(ctx, AlarmDegraded, "", hostID,
				"missed-beat sweep stalled: store unavailable; host not annotated this cycle (sessions never auto-destroyed)")
			return
		}
		// Non-degraded read fault: still emit the host-level UNKNOWN so the silent
		// host is visible; per-session annotations are skipped this cycle.
		r.raise(ctx, AlarmHostUnknown, "", hostID,
			"host silent past missed-beat window; sessions marked UNKNOWN (never auto-destroyed); record enumeration failed: "+err.Error())
		return
	}
	detail := silenceDetail(seen, last, now, window)
	emittedSession := false
	for _, rec := range recs {
		if !expectsHostVM(rec.State) {
			continue // PARKED/SUSPENDED/PENDING/terminal — not a live host VM to lose track of.
		}
		r.raise(ctx, AlarmHostUnknown, rec.Ref.SessionUUID, hostID,
			"session UNKNOWN: "+detail+"; never auto-destroyed (§3 / §5.2)")
		emittedSession = true
	}
	if !emittedSession {
		// Still surface the silent host even when it has no host-resident sessions,
		// so the operator sees the partition (host-scoped alarm, no session).
		r.raise(ctx, AlarmHostUnknown, "", hostID,
			"host UNKNOWN: "+detail+"; no host-resident sessions; never auto-destroyed")
	}
}

// silenceDetail renders the human reason a host is being marked UNKNOWN.
func silenceDetail(seen bool, last, now time.Time, window time.Duration) string {
	if !seen {
		return "no heartbeat ever observed (silence window " + window.String() + ")"
	}
	return "silent for " + now.Sub(last).String() + " (> missed-beat window " + window.String() + ")"
}

// AdoptRecovered implements the host-agent-crash cell (doc 15 §3): a restarted
// host agent RE-OBSERVES via RecoverSessions (the frozen hypervisor.v1 verb,
// satisfied host-side by internal/hostagent.RecoverSessions) and hands the
// reconciler the re-adopted ObservedSession set. The reconciler converges that
// set against the records EXACTLY like a steady-state heartbeat — re-adoption is
// just another observation, never an RPC replay (the level-triggered contract,
// doc.go). It also records the host as freshly heard-from, so the just-recovered
// host is not immediately swept as missed-beat.
//
// resp is the RecoverSessionsResponse the host agent's RecoverSessions returns
// (its Sessions field is the re-adopted observed set). hostID scopes the diff —
// the response carries per-session identity but not the host id, so the caller
// (which dialed this host) supplies it.
func (r *Reconciler) AdoptRecovered(ctx context.Context, hostID string, resp *hypervisorv1.RecoverSessionsResponse) error {
	if hostID == "" {
		return fail("adopt recovered", errEmptyHostID)
	}
	var observed []*hypervisorv1.ObservedSession
	if resp != nil {
		observed = resp.GetSessions()
	}
	// Re-adoption is a fresh observation: stamp the host as heard-from so the
	// missed-beat sweep does not immediately flag a host that just came back, then
	// run the same conflict-rule diff as a heartbeat.
	r.lastBeat[hostID] = r.now()
	return r.reconcileHost(ctx, hostID, observed)
}
