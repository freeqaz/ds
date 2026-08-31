package reconciler

// This file is the reconciler's read of the frozen §3 session state machine
// (docs/15-orchestrator-design.md §3): the observed-vs-desired vocabulary
// translation and the two §3-derived classifications the conflict rules turn on
// — "should this record have a live VM on its host right now?" and "is this
// observed→desired move a regression?".
//
// It NEVER re-declares a state name or a transition. The state vocabulary comes
// from internal/store.SessionState (the persisted §3 set, vocabpin'd to the
// sessions transition table) and the legal-transition graph comes from
// internal/sessions (the authoritative §3 table). The reconciler only COMPOSES
// those two frozen artifacts; a §3 edit reopens the freeze (D35/D46/D72/D73/D77)
// and flows through both, not through this file.

import (
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// stateNameToStore maps the attach.v1 wire SessionStateName (carried on every
// heartbeat ObservedSession, §5.1/§5.2) to the persisted store.SessionState. It
// is the ONE place the observed wire vocabulary crosses into the record
// vocabulary — both are the §3 twelve-state set, joined token-for-token, so the
// map cannot silently disagree with §3 (a missing name returns ok=false and the
// reconciler treats the observation as un-pin-downable, never as a fabricated
// state).
var stateNameToStore = map[attachv1.SessionStateName]store.SessionState{
	attachv1.SessionStateName_SESSION_STATE_NAME_PENDING:      store.SessionPending,
	attachv1.SessionStateName_SESSION_STATE_NAME_CREATING:     store.SessionCreating,
	attachv1.SessionStateName_SESSION_STATE_NAME_READY:        store.SessionReady,
	attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED:     store.SessionAttached,
	attachv1.SessionStateName_SESSION_STATE_NAME_WORKING:      store.SessionWorking,
	attachv1.SessionStateName_SESSION_STATE_NAME_SNAPSHOTTING: store.SessionSnapshotting,
	attachv1.SessionStateName_SESSION_STATE_NAME_MIGRATING:    store.SessionMigrating,
	attachv1.SessionStateName_SESSION_STATE_NAME_PARKED:       store.SessionParked,
	attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED:    store.SessionSuspended,
	attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING:     store.SessionResuming,
	attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYING:   store.SessionDestroying,
	attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED:    store.SessionDestroyed,
}

// observedState translates an ObservedSession's wire state into a store state.
// ok=false means the host could not pin the state down (UNSPECIFIED, or a value
// the §3 vocabulary does not contain). The reconciler treats an un-pin-downable
// observation as a quarantine candidate per §3 — it never coerces UNSPECIFIED
// into a real state.
func observedState(s *attachv1.SessionState) (store.SessionState, bool) {
	if s == nil {
		return "", false
	}
	st, ok := stateNameToStore[s.GetName()]
	return st, ok
}

// hostResidentStates are the §3 states in which a record's session is EXPECTED to
// have a live VM on the host it is bound to right now. This is the predicate the
// "record with no VM" conflict rule (§3 rule b) keys on: a record in one of these
// states whose VM is absent from the host's observed set is a genuine
// no-VM-where-one-should-be, to be re-driven or failed to DESTROYED — whereas a
// record that is PARKED (host slot RELEASED, §3 refinement 2), SUSPENDED (the VM
// is paused but the agent still reports it — handled by the observed-vs-desired
// diff, not as a missing VM), or terminal (DESTROYED) legitimately need not show
// a VM, and absence there is never a no-VM fault.
//
// Derivation from §3 (not a second vocabulary): the host-resident set is the
// running/attached/working spine plus the in-flight create and the transient
// snapshot/migrate/resume states — every state where the host is actively
// holding a domain. PARKED is excluded by the "host slot released" rule (§3
// refinement 2 / §4.3 >15-min tier); the terminal DESTROYED is excluded; PENDING
// is excluded (no host bound yet — placement has not run, §4.1 step 3).
var hostResidentStates = map[store.SessionState]bool{
	store.SessionCreating:     true, // host allocating/booting the domain (§4.1 steps 4-9)
	store.SessionReady:        true, // domain up, routable (§4.1 step 9)
	store.SessionAttached:     true, // domain up, attached (§4.1 step 10)
	store.SessionWorking:      true, // domain running
	store.SessionSnapshotting: true, // domain present, being snapshotted (§4.3)
	store.SessionMigrating:    true, // domain present on source until cutover (§7)
	store.SessionResuming:     true, // domain being un-paused (§4.3)
	// Deliberately ABSENT (a missing VM here is NOT a no-VM fault):
	//   PENDING    — not placed yet (§4.1 step 3); no host bound.
	//   PARKED     — host slot released (§3 refinement 2); no VM by design.
	//   SUSPENDED  — VM paused; the agent still reports it, so the diff sees it.
	//   DESTROYING — teardown in flight; the VM is being removed (§4.2).
	//   DESTROYED  — terminal; no VM by definition (store.SessionState.IsTerminal).
}

// expectsHostVM reports whether a record in state s should have a live VM on its
// bound host right now (the §3 rule-b predicate above).
func expectsHostVM(s store.SessionState) bool {
	return hostResidentStates[s]
}

// isRegression reports whether the observed state is a BACKSLIDE on the §3
// host-resident progression spine relative to the desired state — the §3 rule
// "state regression → re-converge toward desired" (rule c) fires on this.
//
// Definition (derived from the frozen §3 transition graph in internal/sessions,
// never re-declared), all three conditions must hold:
//
//  1. The observed state is itself a host-resident progression state
//     (CREATING/READY/ATTACHED/WORKING/SNAPSHOTTING/MIGRATING/RESUMING). A VM
//     observed in a PAUSE or TERMINAL branch (PARKED/SUSPENDED/DESTROYING/
//     DESTROYED) is NOT a regression — those are legitimate lateral/forward moves
//     the pause/teardown choreography drives, and converging the record to follow
//     them (or recognizing an orchestrator-driven pause) is a different concern
//     than re-driving a backslid VM.
//  2. There is NO legal direct §3 edge observed → desired. A direct edge means the
//     VM is exactly ONE sanctioned forward step behind desired — an IN-FLIGHT LAG
//     the machine is about to close (e.g. desired SNAPSHOTTING, observed WORKING
//     with the legal WORKING→SNAPSHOTTING edge; or desired ATTACHED, observed
//     READY with READY→ATTACHED) — never a backslide. This also covers the
//     ATTACHED⇄WORKING oscillation (both directions are legal edges).
//  3. The observed state is forward-reachable FROM the desired state — i.e. the
//     record had to pass THROUGH the observed state to reach desired, so seeing
//     the VM there now means it slipped back.
//
// The net effect: the reconciler re-converges only a genuine backslide on the
// running spine (e.g. desired WORKING, observed READY), and never thrashes on a
// single-step in-flight lag or a legitimate pause.
func isRegression(desired, observed store.SessionState) bool {
	if desired == observed {
		return false
	}
	// (1) Only a backslide INTO a host-resident progression state counts.
	if !expectsHostVM(observed) {
		return false
	}
	d := sessions.State(string(desired))
	o := sessions.State(string(observed))
	// (2) A legal direct edge observed → desired is a one-step in-flight lag, not a
	// backslide.
	if sessions.IsTransition(o, d) {
		return false
	}
	// (3) Regression iff the desired state was reached THROUGH the observed state
	// (observed is forward-reachable from desired).
	return reachableForward(d, o)
}

// reachableForward reports whether `to` is reachable from `from` by following
// legal §3 forward edges (a BFS over the frozen transition graph). It is the
// "the record already progressed past this observed state" half of isRegression.
func reachableForward(from, to sessions.State) bool {
	if from == to {
		return true
	}
	edges := sessions.Edges()
	seen := map[sessions.State]bool{from: true}
	queue := []sessions.State{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range edges {
			if e.From != cur || seen[e.To] {
				continue
			}
			if e.To == to {
				return true
			}
			seen[e.To] = true
			queue = append(queue, e.To)
		}
	}
	return false
}
