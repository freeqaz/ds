package store

// SessionState is the persisted lifecycle state of a session record (the
// §5.6 record, doc 15). Its vocabulary is the frozen §3 session state
// machine — the same machine the sessions package mirrors as data.
//
// This declaration is deliberately standalone (the store does not import
// internal/sessions): the store owns its own persistence-layer vocabulary,
// and the shared conformance test in internal/sessions asserts the two
// agree — vocabulary equality plus Valid() agreement with the table. Drift
// is a test failure, not a silent split. Editing a value here without the
// matching §3 + sessions-table change reopens the freeze (D35/D46/D72/D73/
// D77); that is what the conformance test forbids.
type SessionState string

// The twelve §3 states, persisted verbatim. The reason refinement on
// SUSPENDED (user|policy_breach|rebalance, D35/D77) and the host retarget
// on MIGRATING/PARKED (READY@host'/CREATING@host') are separate record
// columns, not extra states — the state vocabulary is exactly these twelve.
const (
	SessionPending      SessionState = "PENDING"
	SessionCreating     SessionState = "CREATING"
	SessionReady        SessionState = "READY"
	SessionAttached     SessionState = "ATTACHED"
	SessionWorking      SessionState = "WORKING"
	SessionSnapshotting SessionState = "SNAPSHOTTING"
	SessionMigrating    SessionState = "MIGRATING"
	SessionParked       SessionState = "PARKED"
	SessionSuspended    SessionState = "SUSPENDED"
	SessionResuming     SessionState = "RESUMING"
	SessionDestroying   SessionState = "DESTROYING"
	SessionDestroyed    SessionState = "DESTROYED"
)

// sessionStates is the persistence-layer copy of the legal state set, kept
// in §3 reading order. The conformance test in internal/sessions checks
// this set, surfaced via SessionStates(), against the authoritative table.
var sessionStates = []SessionState{
	SessionPending,
	SessionCreating,
	SessionReady,
	SessionAttached,
	SessionWorking,
	SessionSnapshotting,
	SessionMigrating,
	SessionParked,
	SessionSuspended,
	SessionResuming,
	SessionDestroying,
	SessionDestroyed,
}

// SessionStates returns the store's legal SessionState vocabulary as a
// fresh slice (callers may not mutate the package copy). The shared
// conformance test compares this against the sessions transition table.
func SessionStates() []SessionState {
	out := make([]SessionState, len(sessionStates))
	copy(out, sessionStates)
	return out
}

// Valid reports whether s is a legal persisted SessionState. The repository
// rejects writes of any state outside the §3 vocabulary; the conformance
// test asserts Valid() agrees with the sessions table on every state and
// rejects every non-state.
func (s SessionState) Valid() bool {
	for _, v := range sessionStates {
		if v == s {
			return true
		}
	}
	return false
}

// IsTerminal reports whether s is a terminal state (no legal successor in
// the §3 machine). DESTROYED is the sole terminal node; the reconciler's
// "record with no VM in a non-terminal state → re-drive" rule (§3) reads
// this. Kept here with the vocabulary so the persistence layer and the
// reconciler share one definition of terminal.
func (s SessionState) IsTerminal() bool {
	return s == SessionDestroyed
}
