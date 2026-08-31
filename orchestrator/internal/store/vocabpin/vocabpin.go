// Package vocabpin ties the store's persisted state vocabulary to the frozen §3
// transition table in internal/sessions and turns vocabulary drift into a BUILD
// failure, not a review grep. The live failure it guards against is on record: a
// 10-state SessionState enum once shipped GREEN against the 12-state §3 freeze
// (MIGRATING + RESUMING dropped), caught only by a manual gate. By importing
// BOTH the store's persisted vocabulary and the §3 table and pinning them
// token-for-token, that class of drift now refuses to compile.
//
// Why a dedicated leaf package and not a tie inside package store: the
// internal/sessions conformance TEST imports package store to assert the two
// vocabularies agree (it deliberately keeps store independent of sessions so
// THAT direction works). Were package store to import internal/sessions
// directly, the sessions test would form a test-scope import cycle
// (sessions[test] → store → sessions). This leaf package depends on both
// without sitting in either's import graph, so `go build ./...` compiles it —
// and trips on drift — while neither package's tests cycle. It is the store
// tree's own build-time tie to §3, complementing the sessions cross-test.
package vocabpin

import (
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// Per-token compile-time length pins. For each of the twelve §3 states, the two
// array lengths below are (storeLen - sessLen) and its negation; both are the
// legal length 0 exactly when the persisted token and the §3 token share a
// length, and one is negative — an illegal array length, a `go build` error —
// otherwise. len() of a typed string CONSTANT is itself a compile-time constant,
// so the compiler checks these, not the runtime. The entries ARE the twelve §3
// states, incl. MIGRATING and RESUMING — the two the rejected wave dropped; the
// store tree cannot build without both present in §3 and in the store's set.
var (
	_ [len(store.SessionPending) - len(sessions.StatePending)]struct{}
	_ [len(sessions.StatePending) - len(store.SessionPending)]struct{}

	_ [len(store.SessionCreating) - len(sessions.StateCreating)]struct{}
	_ [len(sessions.StateCreating) - len(store.SessionCreating)]struct{}

	_ [len(store.SessionReady) - len(sessions.StateReady)]struct{}
	_ [len(sessions.StateReady) - len(store.SessionReady)]struct{}

	_ [len(store.SessionAttached) - len(sessions.StateAttached)]struct{}
	_ [len(sessions.StateAttached) - len(store.SessionAttached)]struct{}

	_ [len(store.SessionWorking) - len(sessions.StateWorking)]struct{}
	_ [len(sessions.StateWorking) - len(store.SessionWorking)]struct{}

	_ [len(store.SessionSnapshotting) - len(sessions.StateSnapshotting)]struct{}
	_ [len(sessions.StateSnapshotting) - len(store.SessionSnapshotting)]struct{}

	_ [len(store.SessionMigrating) - len(sessions.StateMigrating)]struct{}
	_ [len(sessions.StateMigrating) - len(store.SessionMigrating)]struct{}

	_ [len(store.SessionParked) - len(sessions.StateParked)]struct{}
	_ [len(sessions.StateParked) - len(store.SessionParked)]struct{}

	_ [len(store.SessionSuspended) - len(sessions.StateSuspended)]struct{}
	_ [len(sessions.StateSuspended) - len(store.SessionSuspended)]struct{}

	_ [len(store.SessionResuming) - len(sessions.StateResuming)]struct{}
	_ [len(sessions.StateResuming) - len(store.SessionResuming)]struct{}

	_ [len(store.SessionDestroying) - len(sessions.StateDestroying)]struct{}
	_ [len(sessions.StateDestroying) - len(store.SessionDestroying)]struct{}

	_ [len(store.SessionDestroyed) - len(sessions.StateDestroyed)]struct{}
	_ [len(sessions.StateDestroyed) - len(store.SessionDestroyed)]struct{}
)

// init pins the store's persisted vocabulary to the §3 table by COUNT and by
// MEMBERSHIP (token-for-token) at package load — the count belt the per-token
// length braces above cannot express (len of a slice value is not a compile-time
// constant), surfaced deterministically by any build that links this package
// (e.g. vocabpin_test.go). It catches an added, dropped, or same-length-renamed
// state — exactly the MIGRATING/RESUMING omission.
func init() {
	table := sessions.States()
	got := store.SessionStates()
	if len(got) != len(table) {
		panic("vocabpin: store SessionState vocabulary size drifted from the §3 transition table (internal/sessions); a dropped or added state reopens the §3 freeze")
	}
	want := make(map[string]struct{}, len(table))
	for _, s := range table {
		want[string(s)] = struct{}{}
	}
	for _, s := range got {
		if _, ok := want[string(s)]; !ok {
			panic("vocabpin: persisted SessionState " + string(s) + " is not a §3 state (internal/sessions); vocabulary drift reopens the §3 freeze")
		}
	}
}
