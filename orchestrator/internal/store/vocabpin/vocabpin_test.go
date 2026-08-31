package vocabpin

import (
	"sort"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// tokens projects any ~string vocabulary to a sorted []string so the two sides
// compare by value regardless of declaration order.
func tokens[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	sort.Strings(out)
	return out
}

// TestStoreVocabularyEqualsFreeze is the store tree's own token-for-token pin to
// the §3 transition table (the sessions cross-test holds the same equality from
// the sessions side). Linking this test forces vocabpin.init()'s count and
// membership checks to run, and the package's per-token compile-time length pins
// (vocabpin.go) already had to compile to reach here. Together: a renamed,
// dropped (incl. MIGRATING/RESUMING), or added state fails the build pipeline.
func TestStoreVocabularyEqualsFreeze(t *testing.T) {
	want := tokens(sessions.States())
	got := tokens(store.SessionStates())

	if len(want) != len(got) {
		t.Fatalf("store vocabulary size %d != §3 table size %d\n  table: %v\n  store: %v",
			len(got), len(want), want, got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("vocabulary drift at sorted index %d: table=%q store=%q\n"+
				"  table: %v\n  store: %v", i, want[i], got[i], want, got)
		}
	}
}

// TestFreezeIsTwelveStates pins the count load-bearingly here too: the §3 freeze
// is twelve states, and the store must persist exactly those twelve. Dropping
// the two states the rejected wave omitted (MIGRATING, RESUMING) would trip this
// and the membership check above.
func TestFreezeIsTwelveStates(t *testing.T) {
	const wantStateCount = 12
	if got := len(store.SessionStates()); got != wantStateCount {
		t.Fatalf("store persists %d states, §3 freeze is %d", got, wantStateCount)
	}
	if got := len(sessions.States()); got != wantStateCount {
		t.Fatalf("§3 table has %d states, freeze is %d", got, wantStateCount)
	}
}
