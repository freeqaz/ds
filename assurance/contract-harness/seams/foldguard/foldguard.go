// SPDX-License-Identifier: Apache-2.0

// Package foldguard is the SHARED, exported fold-completeness guard the
// contract-harness seam tests use to turn a per-fold completeness check from a
// bare cell COUNT into a cell-NAME-SET equality plus a serial-execution pin.
//
// ORIGIN + WHY SHARED. The guard was first built inline in the identity-validate
// seam (seams/identity-validate/dualrun_test.go, as the unexported
// foldCompletenessTracker), where two fold matrices drive both honest callers and
// every negative dialer over a canonical reason matrix. A bare
// `cellsExercised == len(cells)` count catches a DROPPED cell but is VACUOUS to a
// SWAP — a fold that exercises one cell TWICE and skips another nets the same
// total and slips past — and it silently assumes the per-cell subtests ran
// SERIALLY against a single shared fleet/client. Every other seam fold sitting on
// a bare cell COUNT carries the same two holes. Rather than hand-copy the
// strengthened guard per seam (where the copies could drift apart), this package
// FACTORS it once, exported, so every seam consumes the SAME proven guard.
//
// WHAT IT GUARDS, two independent ways:
//
//   - NAME SET: Enter(name) records the EXACT name each cell subtest drives;
//     Verify asserts the recorded REACH set equals the caller's canonical name set
//     (CanonicalNameSet). A duplicate visit, a skip, or a foreign name each fails
//     LOUDLY — the swap a bare count waves through is caught. MarkAsserted(name),
//     recorded at the per-cell assert site, adds a second axis: a cell that ENTERS
//     then short-circuits BEFORE its load-bearing assertion records reach but not
//     an assert, so Verify FLAGS it instead of counting it as covered by reach
//     alone. This turns reach-coverage into PROOF-OF-ASSERTION coverage.
//   - SERIAL EXECUTION: the count's (and the name set's) correctness silently
//     depends on the per-cell subtests running serially against the ONE shared
//     fleet/client. Verify pins this two ways. (1) It is handed the count the
//     caller captured SYNCHRONOUSLY at loop exit (settledAtReturn) and asserts it
//     already equals the full canonical size — a t.Parallel()'d cell is PAUSED by
//     Go until its parent returns, so at Verify time it has NOT yet run and the
//     synchronous count is short (the primary, timing-robust pin). (2) Enter/Exit
//     bracket each cell with an atomic in-flight counter whose MAX overlap Verify
//     asserts never exceeded 1 — a belt-and-suspenders that catches a hand-rolled
//     goroutine fan-out (which, unlike t.Parallel, is NOT deferred past the
//     parent). The counters are atomic so the detector is -race-clean even when it
//     is the thing catching the race.
//
// Test-only support code (synthetic fixtures only, D50). It is an ordinary
// (non-_test) package so any seam's `_test.go` — in its own `<seam>_test`
// package — can import and share it; it pulls in nothing but the stdlib.
package foldguard

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

// FatalReporter is the narrow {Helper, Fatalf} subset of *testing.T that Verify
// uses. Verify is typed against it (not *testing.T concretely) so a negative
// meta-test can drive Verify with a fatal-CAPTURING recorder — observing that the
// guard fires WITHOUT failing the meta-test — while real seam tests pass their
// *testing.T (which satisfies this interface), so their assertions are unchanged.
// The variadic uses any to match testing.T.Fatalf exactly.
type FatalReporter interface {
	Helper()
	Fatalf(format string, args ...any)
}

// CanonicalNameSet derives the canonical cell-NAME SET a fold must drive its
// callers/dialers over — no duplicate, no skip, no foreign cell — from the ordered
// list of cell names the fold declares. It is the yardstick Verify measures the
// EXERCISED set against: a name-set equality (not a bare count) catches a fold that
// visits one cell TWICE and skips another for the same total. It also rejects a
// MALFORMED canonical declaration (a duplicate name in the source list itself), so
// the yardstick cannot silently be the wrong shape. Test-only; synthetic fixtures
// only (D50).
func CanonicalNameSet(t FatalReporter, names []string) map[string]struct{} {
	t.Helper()
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		if _, dup := set[n]; dup {
			t.Fatalf("foldguard: the canonical cell list declares the name %q twice — the canonical matrix must be a SET (each name appears once)", n)
		}
		set[n] = struct{}{}
	}
	return set
}

// Tracker strengthens a per-fold completeness guard from a bare cell COUNT to a
// cell-NAME-SET equality AND pins the serial-execution invariant the fold relies
// on. Reused by every seam fold so the strengthened guard is declared once and
// cannot drift between seams. Test-only; synthetic fixtures only (D50).
type Tracker struct {
	mu        sync.Mutex
	exercised map[string]int // cell name -> times REACHED (Enter() at top; catches a double-visit)
	asserted  map[string]int // cell name -> times its agreement/invariant ASSERT FIRED (MarkAsserted() at the assert site)
	inFlight  int64          // cells currently inside their subtest body (atomic)
	maxInFly  int64          // high-water mark of concurrent cells (atomic)
}

// New returns a fresh Tracker with empty reach/assert sets.
func New() *Tracker {
	return &Tracker{exercised: make(map[string]int), asserted: make(map[string]int)}
}

// Enter is called at the TOP of each cell subtest, before any branch/early return,
// so it counts REACH not outcome. It records the cell name (so Verify can compare
// the exercised SET against the canonical set) and bumps the in-flight overlap
// counter; the returned func must be deferred to release it.
func (ft *Tracker) Enter(name string) (done func()) {
	ft.mu.Lock()
	ft.exercised[name]++
	ft.mu.Unlock()

	n := atomic.AddInt64(&ft.inFlight, 1)
	for {
		hi := atomic.LoadInt64(&ft.maxInFly)
		if n <= hi || atomic.CompareAndSwapInt64(&ft.maxInFly, hi, n) {
			break
		}
	}
	return func() { atomic.AddInt64(&ft.inFlight, -1) }
}

// MarkAsserted is called at the ASSERT SITE — right AFTER a cell's agreement /
// invariant assertion block has run (the point past which the verdict has been
// checked), on EVERY path the assertion is reachable by (including a path that
// returns early once it has asserted). It records that the cell's load-bearing
// assertion ACTUALLY FIRED, as distinct from Enter()'s REACH (recorded at the top
// of the subtest, before any branch). Verify then requires the asserted SET to
// equal the canonical set in ADDITION to the reach set: a cell whose body
// short-circuits AFTER Enter() but BEFORE its assert records reach without
// recording an assert, so Verify flags it instead of silently counting it as
// covered. Keying on the cell name (not a bare count) catches a cell asserted TWICE
// while another never asserts — the same swap the reach name-set guards against,
// now on the assert-fired axis.
func (ft *Tracker) MarkAsserted(name string) {
	ft.mu.Lock()
	ft.asserted[name]++
	ft.mu.Unlock()
}

// nameSetMessages carries the three per-axis fatal-message builders the
// sorted-split-pass name-set walk needs, so the reach (a) and assert (a') axes can
// share ONE implementation (verifyNameSetSortedSplitPass) while keeping their
// distinct diagnostics. Each builder returns the FULLY-FORMATTED fatal string
// (label and all directives already interpolated); the shared walk emits it
// verbatim via t.Fatalf("%s", msg).
//   - foreign: a sorted key not in the canonical set (FOREIGN pass), given the offending name.
//   - double:  a sorted key whose count != 1 (COUNT pass), given the name and its count.
//   - length:  the post-loop LENGTH mismatch, given have, want, and the sorted missing names.
type nameSetMessages struct {
	foreign func(name string) string
	double  func(name string, n int) string
	length  func(have, want int, missing []string) string
}

// verifyNameSetSortedSplitPass is the ONE shared sorted-split-pass name-set walk
// the reach (a) and assert (a') axes of Verify both call, so the two axes share a
// single implementation and cannot silently desync. It collects counts' keys,
// sort.Strings them, runs the FOREIGN-membership pass over every key FIRST, then
// the n != 1 COUNT pass — so a FOREIGN cell and a (distinct) DOUBLED cell present
// at once fire the foreign guard first, deterministically and independent of
// map-iteration order — then the POST-loop LENGTH check (missing names collected
// and sort.Strings'd before emission). Caller holds ft.mu. Test-only; synthetic
// fixtures only (D50).
func verifyNameSetSortedSplitPass(t FatalReporter, counts map[string]int, canonical map[string]struct{}, msgs nameSetMessages) {
	t.Helper()
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := canonical[name]; !ok {
			t.Fatalf("%s", msgs.foreign(name))
		}
	}
	for _, name := range names {
		if n := counts[name]; n != 1 {
			t.Fatalf("%s", msgs.double(name, n))
		}
	}
	if len(counts) != len(canonical) {
		missing := make([]string, 0)
		for name := range canonical {
			if _, ok := counts[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		t.Fatalf("%s", msgs.length(len(counts), len(canonical), missing))
	}
}

// Verify is called after the cell loop. settledAtReturn is the count the caller
// captured SYNCHRONOUSLY right after the loop, used to pin serial execution: under
// serial subtests it already equals len(canonical), but a t.Parallel()'d cell is
// paused until the parent returns so it would NOT have run yet here, leaving the
// synchronous count short. Verify asserts (a) the EXACT set of REACHED cell names
// equals the canonical name set — no duplicate visit, no skip, no foreign cell;
// (a') the EXACT set of cell names whose agreement/invariant ASSERTION FIRED
// (MarkAsserted at the assert site) also equals the canonical set — so a cell whose
// body short-circuits AFTER Enter() but BEFORE its assert is FLAGGED, not silently
// counted as covered by reach alone; and (b) the serial-execution invariant held
// (every cell settled before the parent returned AND no two cell subtests were ever
// in flight at once). label names the fold for a self-locating failure.
func (ft *Tracker) Verify(t FatalReporter, label string, canonical map[string]struct{}, settledAtReturn int) {
	t.Helper()

	// (b.1) SERIAL EXECUTION — primary, timing-robust pin: every cell must have run
	// SYNCHRONOUSLY (settled before the parent returned). A t.Parallel() inside a
	// cell defers it past the parent, so the synchronously-captured count would be
	// short here even though the cell will eventually run.
	if settledAtReturn != len(canonical) {
		t.Fatalf("%s serial-execution invariant VIOLATED: only %d of %d cells had settled synchronously when the loop returned — a cell subtest deferred its body past the parent (a t.Parallel() against the shared fleet?), so the post-loop fold-completeness counters are not yet settled and the shared client is no longer single-threaded",
			label, settledAtReturn, len(canonical))
	}

	// (b.2) SERIAL EXECUTION — belt-and-suspenders: a hand-rolled goroutine fan-out
	// (not deferred past the parent like t.Parallel) would let cells overlap and race
	// the shared fleet; the high-water mark proves none did.
	if hi := atomic.LoadInt64(&ft.maxInFly); hi > 1 {
		t.Fatalf("%s serial-execution invariant VIOLATED: up to %d cell subtests ran concurrently — the per-cell loop must stay serial against the shared fleet (no t.Parallel, no goroutine fan-out), or the fold-completeness counters race and the shared client is no longer single-threaded",
			label, hi)
	}

	// (a) REACH NAME SET: dup / skip / foreign all fail here. The exercised keys are
	// walked in SORTED order (not Go's randomized map iteration) so the per-name guards
	// fire deterministically, and the two per-name checks are SPLIT into two sequential
	// sorted passes — FOREIGN-membership for every key FIRST, then the n != 1
	// double-visit check — so that when a FOREIGN cell and a (distinct) DOUBLED cell are
	// BOTH present, the foreign guard ALWAYS wins regardless of which name sorts first.
	ft.mu.Lock()
	defer ft.mu.Unlock()
	verifyNameSetSortedSplitPass(t, ft.exercised, canonical, nameSetMessages{
		foreign: func(name string) string {
			return fmt.Sprintf("%s fold-completeness: exercised FOREIGN cell %q not in the canonical matrix — the fold drifted off the canonical cell set", label, name)
		},
		double: func(name string, n int) string {
			return fmt.Sprintf("%s fold-completeness: cell %q was exercised %d times, want exactly once — a double-visit (which, paired with a skip, a bare count would wave through) breaks the name-set fold", label, name, n)
		},
		length: func(have, want int, missing []string) string {
			return fmt.Sprintf("%s fold-completeness: exercised %d distinct cells but the canonical matrix has %d — SKIPPED cells %v never had their per-cell fold assertion fire, a vacuous pass this name-set guard turns into a LOUD failure",
				label, have, want, missing)
		},
	})

	// (a') ASSERT-FIRED NAME SET: reach (above) proves each cell's subtest BODY was
	// entered; this proves each cell's agreement/invariant ASSERTION ACTUALLY RAN.
	// MarkAsserted is recorded at the assert site (after the verdict has been
	// checked), so a cell that enters then short-circuits BEFORE asserting — a body
	// that early-returns or skips past its agreement/invariant block — records reach
	// but NOT an assert, and is FLAGGED here instead of being silently counted as
	// covered by reach alone. A foreign assert, a double-assert (paired with a
	// never-asserted cell), or a never-asserted cell each fails LOUDLY — the
	// assert-fired analogue of the reach name-set guard above.
	verifyNameSetSortedSplitPass(t, ft.asserted, canonical, nameSetMessages{
		foreign: func(name string) string {
			return fmt.Sprintf("%s fold-completeness: asserted FOREIGN cell %q not in the canonical matrix — MarkAsserted fired for a cell off the canonical set", label, name)
		},
		double: func(name string, n int) string {
			return fmt.Sprintf("%s fold-completeness: cell %q recorded its assert-fired marker %d times, want exactly once — a double-assert (paired with a never-asserted cell) breaks the assert-fired fold", label, name, n)
		},
		length: func(have, want int, missing []string) string {
			return fmt.Sprintf("%s fold-completeness: %d of %d cells fired their agreement/invariant assertion — cells %v were REACHED but short-circuited BEFORE their assert (MarkAsserted never ran), so coverage was by NAME, not by assert-fired; this guard turns that vacuous pass into a LOUD failure",
				label, have, want, missing)
		},
	})
}
