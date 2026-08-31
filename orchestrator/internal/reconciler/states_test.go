package reconciler

// Unit tests for the §3-derived classifications in states.go — the predicates the
// conflict rules turn on. They pin the vocabulary join (observed wire ↔ store
// state) against the FROZEN store state set and the regression detector against
// the FROZEN sessions transition graph, so a §3 freeze edit that drifts either
// breaks here, not silently in convergence.

import (
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// The observed-wire ↔ store-state map must cover EVERY one of the 12 frozen §3
// store states (and only legal ones), so no observed state silently falls through
// to "un-pin-downable".
func TestStateNameToStore_CoversAll12FrozenStates(t *testing.T) {
	want := store.SessionStates()
	if len(want) != 12 {
		t.Fatalf("§3 freeze is 12 states; store reports %d", len(want))
	}
	seen := make(map[store.SessionState]bool)
	for _, v := range stateNameToStore {
		if !v.Valid() {
			t.Fatalf("map produced a non-§3 store state %q", v)
		}
		seen[v] = true
	}
	for _, s := range want {
		if !seen[s] {
			t.Fatalf("store state %q has no observed-wire mapping (vocabulary drift)", s)
		}
	}
	if len(seen) != 12 {
		t.Fatalf("map must hit exactly 12 distinct store states; got %d", len(seen))
	}
}

// UNSPECIFIED / nil observed state is un-pin-downable (ok=false), never coerced.
func TestObservedState_UnspecifiedIsUnpinnable(t *testing.T) {
	if _, ok := observedState(nil); ok {
		t.Fatalf("nil observed state must be un-pin-downable")
	}
	un := &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_UNSPECIFIED}
	if _, ok := observedState(un); ok {
		t.Fatalf("UNSPECIFIED observed state must be un-pin-downable")
	}
	ok := &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_WORKING}
	if st, pinned := observedState(ok); !pinned || st != store.SessionWorking {
		t.Fatalf("WORKING must pin to store.SessionWorking; got %v pinned=%v", st, pinned)
	}
}

// expectsHostVM must exactly match the host-resident spine and exclude
// PARKED/SUSPENDED/PENDING/terminal — the rule-b predicate.
func TestExpectsHostVM_MatchesHostResidentSpine(t *testing.T) {
	resident := map[store.SessionState]bool{
		store.SessionCreating:     true,
		store.SessionReady:        true,
		store.SessionAttached:     true,
		store.SessionWorking:      true,
		store.SessionSnapshotting: true,
		store.SessionMigrating:    true,
		store.SessionResuming:     true,
	}
	for _, s := range store.SessionStates() {
		got := expectsHostVM(s)
		want := resident[s]
		if got != want {
			t.Fatalf("expectsHostVM(%q)=%v, want %v", s, got, want)
		}
	}
	// Terminal DESTROYED never expects a VM (cross-check with IsTerminal).
	if expectsHostVM(store.SessionDestroyed) {
		t.Fatalf("terminal DESTROYED must not be host-resident")
	}
}

// isRegression: forward / legal-edge moves are NOT regressions; backward moves
// past which the record progressed ARE.
func TestIsRegression(t *testing.T) {
	cases := []struct {
		name              string
		desired, observed store.SessionState
		want              bool
	}{
		// Genuine backslides on the running spine — desired reached THROUGH the
		// observed state, and no direct edge observed→desired (more than one step
		// behind).
		{"working-back-to-ready", store.SessionWorking, store.SessionReady, true},
		{"working-back-to-creating", store.SessionWorking, store.SessionCreating, true},
		// One-step in-flight lags: a direct legal edge observed→desired exists, so
		// the VM is exactly one sanctioned forward step behind desired — NOT a
		// backslide (READY→ATTACHED, CREATING→READY are legal forward edges).
		{"attached-desired-ready-observed-inflight", store.SessionAttached, store.SessionReady, false},
		{"ready-desired-creating-observed-inflight", store.SessionReady, store.SessionCreating, false},
		// Legal direct edges / oscillation — not regressions.
		{"attached-working-oscillation", store.SessionWorking, store.SessionAttached, false},
		{"working-attached-oscillation", store.SessionAttached, store.SessionWorking, false},
		// Observed is a PAUSE state — never a regression (handled by other rules).
		{"resuming-vs-suspended-pause", store.SessionResuming, store.SessionSuspended, false},
		{"working-vs-parked-pause", store.SessionWorking, store.SessionParked, false},
		// Forward, not behind — not a regression.
		{"snapshotting-while-working-desired", store.SessionSnapshotting, store.SessionWorking, false},
		// Same state — not a regression.
		{"identity", store.SessionWorking, store.SessionWorking, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRegression(tc.desired, tc.observed); got != tc.want {
				t.Fatalf("isRegression(%q,%q)=%v want %v", tc.desired, tc.observed, got, tc.want)
			}
		})
	}
}

// reachableForward agrees with the frozen sessions transition graph on a couple
// of anchor reachabilities (guards against the BFS rotting if edges change).
func TestReachableForward_AnchorsAgainstFrozenGraph(t *testing.T) {
	// PENDING reaches every state in the connected machine.
	if !reachableForward(sessions.StatePending, sessions.StateDestroyed) {
		t.Fatalf("PENDING must reach DESTROYED in the §3 graph")
	}
	if !reachableForward(sessions.StateCreating, sessions.StateWorking) {
		t.Fatalf("CREATING must reach WORKING")
	}
	// DESTROYED is terminal — reaches nothing but itself.
	if reachableForward(sessions.StateDestroyed, sessions.StateWorking) {
		t.Fatalf("terminal DESTROYED must reach nothing forward")
	}
}
