// Package sessions: §3 state machine as enforced data.
//
// This file is the machine-readable mirror of the frozen §3 session state
// machine in docs/15-orchestrator-design.md — the diagram's legal states
// and legal edges transcribed verbatim, plus a table-driven conformance
// test (transition_table_test.go) that fails whenever a vocabulary
// consumer drifts from this table. The live proof this guards against:
// this wave shipped a 10-state enum against a 12-state freeze with a green
// build, caught only by a manual gate grep. The table turns that into a
// compile-and-test invariant.
//
// ALTERING A STATE OR EDGE HERE REOPENS THE §3 FREEZE (D35/D46/D72/D73/
// D77). The doc is normative; this table is its non-normative mirror, and
// the conformance test asserts the two never diverge from their consumers.
// Edits that change the machine belong in the doc, ratified as a decision.
//
// Consumers the conformance test wires TODAY:
//   - orchestrator/internal/store SessionState — vocabulary equality plus
//     Valid() agreement with States() (validation, never re-declaration;
//     the table is the single source, the store mirrors it).
//
// Consumers that MUST wire into this table when they land (each is §3's
// "full state-transition fidelity" obligation, doc 15 §6.1 row 3):
//   - the dreamserpent.orchestrator.v1 SessionState proto enum (§5.6;
//     ObservedSession.observed_state §5.2; the M0 attach-schema freeze)
//   - the reconciler conflict rules (§3): observed-without-record →
//     QUARANTINE/suspend, record-without-VM in a non-terminal state →
//     re-drive or DESTROYED, state regression → re-converge — every rule
//     names states from this vocabulary
//   - the attach.v1 event vocabulary (doc 15 §6.1 row 3 — full §3 state
//     vocabulary incl. SUSPENDED(reason)/PARKED + the D77 reason taxonomy,
//     every §3 transition representable)
//
// Out of scope here on purpose: the SUSPENDED reason taxonomy
// (user|policy_breach|rebalance, D35/D77) and the MIGRATING/PARKED host
// retarget (READY@host', CREATING@host') are state *refinements* carried
// by the proto reason/host fields, not separate states in this vocabulary
// — the table models the state graph, not the reason or host dimensions.
package sessions

// State is one node of the §3 session state machine. The string values are
// the verbatim §3 vocabulary tokens; consumers compare against these.
type State string

// The twelve legal states of the §3 machine, transcribed from the diagram
// in docs/15-orchestrator-design.md §3. The count is load-bearing: the
// freeze is 12 states, and the conformance test pins len(States()) so a
// dropped or added state fails the build's test phase.
const (
	StatePending      State = "PENDING"
	StateCreating     State = "CREATING"
	StateReady        State = "READY"
	StateAttached     State = "ATTACHED"
	StateWorking      State = "WORKING"
	StateSnapshotting State = "SNAPSHOTTING"
	StateMigrating    State = "MIGRATING"
	StateParked       State = "PARKED"
	StateSuspended    State = "SUSPENDED"
	StateResuming     State = "RESUMING"
	StateDestroying   State = "DESTROYING"
	StateDestroyed    State = "DESTROYED"
)

// states is the authoritative ordered set of legal states. Order is the
// §3 reading order (left-to-right, top-to-bottom of the diagram) and is
// not semantically significant; membership and count are.
var states = []State{
	StatePending,
	StateCreating,
	StateReady,
	StateAttached,
	StateWorking,
	StateSnapshotting,
	StateMigrating,
	StateParked,
	StateSuspended,
	StateResuming,
	StateDestroying,
	StateDestroyed,
}

// Edge is one directed legal transition From → To of the §3 machine.
type Edge struct {
	From State
	To   State
}

// edges is the authoritative set of legal transitions, transcribed
// verbatim from the §3 diagram in docs/15-orchestrator-design.md.
//
// Diagram column map (col positions confirmed against the source):
//   - PENDING ─► CREATING ─► READY ─► ATTACHED ⇄ WORKING        (top row)
//   - the col-14 spine descends from CREATING to DESTROYING      (teardown)
//   - the col-37 spine descends from WORKING into SNAPSHOTTING
//     and SUSPENDED                                              (pause/snap)
//   - SNAPSHOTTING ─► (READY | MIGRATING ─► READY@host' | PARKED)
//   - SUSPENDED └─► RESUMING ─► WORKING                          (resume)
//   - PARKED ──(scheduler re-place, D46 >15 min tier)─► CREATING@host'
//   - the col-25 ▲ carries SNAPSHOTTING/MIGRATING back up into READY
//
// READY@host' is READY on a new host; CREATING@host' is CREATING on a new
// host — same state vocabulary, the host dimension lives in the record,
// not the state token (see package doc).
var edges = []Edge{
	{StatePending, StateCreating},       // PENDING ─► CREATING
	{StateCreating, StateReady},         // CREATING ─► READY
	{StateCreating, StateDestroying},    // col-14 spine: create rollback (§4.1/§4.2)
	{StateReady, StateAttached},         // READY ─► ATTACHED
	{StateAttached, StateWorking},       // ATTACHED ⇄ WORKING (forward)
	{StateWorking, StateAttached},       // ATTACHED ⇄ WORKING (back)
	{StateWorking, StateSnapshotting},   // col-37 spine ─► SNAPSHOTTING
	{StateWorking, StateSuspended},      // col-37 spine ─► SUSPENDED(reason)
	{StateSnapshotting, StateReady},     // SNAPSHOTTING ─► READY (col-25 ▲)
	{StateSnapshotting, StateMigrating}, // SNAPSHOTTING ─► MIGRATING
	{StateSnapshotting, StateParked},    // SNAPSHOTTING ─► PARKED (D46)
	{StateMigrating, StateReady},        // MIGRATING ─► READY@host' (col-25 ▲)
	{StateSuspended, StateResuming},     // SUSPENDED └─► RESUMING
	{StateResuming, StateWorking},       // RESUMING ─► WORKING
	{StateParked, StateCreating},        // PARKED ─► CREATING@host' (D46 >15 min re-place)
	{StateDestroying, StateDestroyed},   // DESTROYING ─► DESTROYED (doc 06 §3b)
}

// States returns the authoritative legal §3 state vocabulary as a fresh
// slice (callers may not mutate the package's copy). Consumers validate
// their own vocabulary against this set.
func States() []State {
	out := make([]State, len(states))
	copy(out, states)
	return out
}

// Edges returns the authoritative legal §3 transition set as a fresh
// slice. Consumers that model transitions (reconciler, attach.v1 event
// fidelity) validate against this set.
func Edges() []Edge {
	out := make([]Edge, len(edges))
	copy(out, edges)
	return out
}

// IsState reports whether s is a legal §3 state.
func IsState(s State) bool {
	for _, v := range states {
		if v == s {
			return true
		}
	}
	return false
}

// IsTransition reports whether from → to is a legal §3 transition.
func IsTransition(from, to State) bool {
	for _, e := range edges {
		if e.From == from && e.To == to {
			return true
		}
	}
	return false
}
