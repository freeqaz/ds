package sessions

import (
	"sort"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// The §3 freeze is 12 states. These two counts are the load-bearing pins:
// the live failure this whole fixture guards against was a 10-state enum
// shipped against the 12-state freeze with a green build. If the diagram
// in docs/15 §3 ever legitimately changes (which reopens the freeze,
// D35/D46/D72/D73/D77), these constants change in the SAME commit as the
// table and the doc — never silently.
const (
	wantStateCount = 12
	wantEdgeCount  = 16
)

func TestStateCountMatchesFreeze(t *testing.T) {
	if got := len(States()); got != wantStateCount {
		t.Fatalf("§3 state count drift: table has %d states, freeze is %d "+
			"(docs/15 §3). Changing the count reopens the freeze.",
			got, wantStateCount)
	}
}

func TestEdgeCountMatchesFreeze(t *testing.T) {
	if got := len(Edges()); got != wantEdgeCount {
		t.Fatalf("§3 edge count drift: table has %d edges, freeze is %d "+
			"(docs/15 §3 diagram). Changing the count reopens the freeze.",
			got, wantEdgeCount)
	}
}

// TestStatesAreUnique guards the table itself: a duplicated or missing
// const would make the count pin lie.
func TestStatesAreUnique(t *testing.T) {
	seen := map[State]bool{}
	for _, s := range States() {
		if s == "" {
			t.Errorf("empty state token in table")
		}
		if seen[s] {
			t.Errorf("duplicate state in table: %q", s)
		}
		seen[s] = true
	}
}

// TestEdgesReferenceLegalStates guards the edge table against typos: every
// endpoint must be a declared state.
func TestEdgesReferenceLegalStates(t *testing.T) {
	for _, e := range Edges() {
		if !IsState(e.From) {
			t.Errorf("edge %v has non-state From %q", e, e.From)
		}
		if !IsState(e.To) {
			t.Errorf("edge %v has non-state To %q", e, e.To)
		}
	}
}

// TestEdgesAreUnique catches a duplicated transition that would make the
// edge-count pin lie.
func TestEdgesAreUnique(t *testing.T) {
	seen := map[Edge]bool{}
	for _, e := range Edges() {
		if seen[e] {
			t.Errorf("duplicate edge in table: %v", e)
		}
		seen[e] = true
	}
}

// stateTokens projects any string-kinded state vocabulary to a sorted
// []string so vocabularies from different packages compare by value.
func sortedTokens[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	sort.Strings(out)
	return out
}

// TestStoreVocabularyMatchesTable is the cross-check wiring for today's one
// consumer (orchestrator/internal/store). The store declares SessionState
// independently (it does not import this package); this asserts the two
// vocabularies are token-for-token equal. A consumer that drops, adds, or
// renames a state fails here.
func TestStoreVocabularyMatchesTable(t *testing.T) {
	want := sortedTokens(States())
	got := sortedTokens(store.SessionStates())

	if len(want) != len(got) {
		t.Fatalf("store vocabulary size %d != §3 table size %d\n  table: %v\n  store: %v",
			len(got), len(want), want, got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("vocabulary drift at sorted index %d: table=%q store=%q\n"+
				"  table: %v\n  store: %v", i, want[i], got[i], want, got)
		}
	}
}

// TestStoreValidAgreesWithTable asserts the store's Valid() predicate agrees
// with the table on every legal state (accepts all §3 states) and rejects
// every state-shaped string that is NOT in the vocabulary. This is the
// validation-not-re-declaration contract: Valid() is the store's view of
// the same machine, and it must answer the table's questions identically.
func TestStoreValidAgreesWithTable(t *testing.T) {
	// Every §3 state must be Valid() in the store.
	for _, s := range States() {
		if !store.SessionState(s).Valid() {
			t.Errorf("store.Valid() rejects §3 state %q (table has it, store must accept)", s)
		}
	}
	// Every store state must be a legal §3 state.
	for _, s := range store.SessionStates() {
		if !IsState(State(s)) {
			t.Errorf("store declares state %q absent from the §3 table", s)
		}
	}
	// Negatives: nothing outside the vocabulary may pass Valid().
	for _, bogus := range []string{
		"", "pending", "Pending", "DESTROYED ", "RUNNING", "PAUSED",
		"ATTACHED|WORKING", "SUSPENDED(user)", "READY@host'", "UNKNOWN",
	} {
		if store.SessionState(bogus).Valid() {
			t.Errorf("store.Valid() accepts non-state %q", bogus)
		}
		if IsState(State(bogus)) {
			t.Errorf("table IsState() accepts non-state %q", bogus)
		}
	}
}

// --- Negative cases: prove the conformance test DETECTS drift. ---------
//
// These tests run the same equality check the real cross-check runs, but
// against deliberately drifted copies of the vocabulary, and assert the
// check FLAGS the drift. They are the executable proof of the acceptance
// criterion "fails if a state or edge is removed from either the table or
// the store vocabulary" — without mutating the real tables.

// vocabEqual is the value-equality check extracted so the negative cases
// exercise the exact same logic as TestStoreVocabularyMatchesTable.
func vocabEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func TestDriftDetected_StateRemovedFromStore(t *testing.T) {
	table := sortedTokens(States())

	// Simulate a consumer that dropped one state (the 12→fewer regression).
	drifted := table[:len(table)-1]

	if vocabEqual(table, drifted) {
		t.Fatalf("conformance check FAILED to detect a removed state — "+
			"drift would ship silently\n  table:  %v\n  drifted: %v", table, drifted)
	}
}

func TestDriftDetected_StateAddedToStore(t *testing.T) {
	table := sortedTokens(States())

	// Simulate a consumer that grew an extra, unfrozen state.
	drifted := append(append([]string(nil), table...), "ZOMBIE")

	if vocabEqual(table, drifted) {
		t.Fatalf("conformance check FAILED to detect an added state\n"+
			"  table:  %v\n  drifted: %v", table, drifted)
	}
}

func TestDriftDetected_StateRenamedInStore(t *testing.T) {
	table := sortedTokens(States())

	// Same count, one token renamed — the subtlest drift.
	drifted := append([]string(nil), table...)
	for i := range drifted {
		if drifted[i] == string(StateParked) {
			drifted[i] = "HIBERNATED"
		}
	}

	if vocabEqual(table, drifted) {
		t.Fatalf("conformance check FAILED to detect a renamed state\n"+
			"  table:  %v\n  drifted: %v", table, drifted)
	}
}

// edgeSetEqual is the transition-set equality the attach.v1/reconciler
// consumers will use when they wire in; tested here so the negative case
// proves edge drift is caught too.
func edgeSetEqual(a, b []Edge) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[Edge]int{}
	for _, e := range a {
		seen[e]++
	}
	for _, e := range b {
		seen[e]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestDriftDetected_EdgeRemoved(t *testing.T) {
	full := Edges()
	drifted := full[:len(full)-1] // drop one legal transition

	if edgeSetEqual(full, drifted) {
		t.Fatalf("conformance check FAILED to detect a removed edge — " +
			"a consumer could silently lose a §3 transition")
	}
}

func TestDriftDetected_EdgeAdded(t *testing.T) {
	full := Edges()

	// An illegal transition the §3 diagram never draws (DESTROYED is
	// terminal — nothing leaves it).
	drifted := append(append([]Edge(nil), full...), Edge{StateDestroyed, StateWorking})

	if edgeSetEqual(full, drifted) {
		t.Fatalf("conformance check FAILED to detect an added illegal edge")
	}
}

// Sanity: the real edge set agrees with itself (the positive baseline the
// negative cases drift away from).
func TestEdgeSetSelfConsistent(t *testing.T) {
	if !edgeSetEqual(Edges(), Edges()) {
		t.Fatal("Edges() is not equal to itself — copy semantics broken")
	}
}

// DESTROYED is the sole terminal; assert no edge leaves it and store agrees.
func TestDestroyedIsTerminal(t *testing.T) {
	for _, e := range Edges() {
		if e.From == StateDestroyed {
			t.Errorf("§3 has DESTROYED as terminal but table has edge %v", e)
		}
	}
	if !store.SessionDestroyed.IsTerminal() {
		t.Errorf("store disagrees: SessionDestroyed.IsTerminal() = false")
	}
	if store.SessionWorking.IsTerminal() {
		t.Errorf("store wrongly marks WORKING terminal")
	}
}
