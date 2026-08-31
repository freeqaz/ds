// SPDX-License-Identifier: Apache-2.0

package foldguard_test

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/foldguard"
)

// canonicalNames is the synthetic three-cell canonical set every negative case
// below measures a deliberately-malformed Tracker against. Synthetic fixtures only
// (D50): no seam fixture, no production code, no live edge.
var canonicalNames = []string{"alpha", "beta", "gamma"}

// fatalCapture is a foldguard.FatalReporter that records the FIRST Fatalf as a
// fired guard and then unwinds via runtime.Goexit — exactly as *testing.T.Fatalf
// does — so the code under test (Verify) stops at the fatal site just as it would
// under a real test. It is driven on its OWN goroutine (runVerifyExpectingFatal) so
// the Goexit unwinds only that goroutine; the parent meta-test goroutine observes
// the captured message and stays green when the guard fires as expected. Helper is
// a no-op (no line attribution needed for a capture).
type fatalCapture struct {
	fired bool
	msg   string
}

func (c *fatalCapture) Helper() {}

func (c *fatalCapture) Fatalf(format string, args ...any) {
	c.fired = true
	c.msg = fmt.Sprintf(format, args...)
	runtime.Goexit() // unwind the capture goroutine, mirroring *testing.T.Fatalf
}

// runVerifyExpectingFatal drives Tracker.Verify on a dedicated goroutine against a
// fatalCapture and returns the capture once that goroutine has settled. If Verify's
// guard fires, Fatalf records the message and Goexit unwinds the goroutine
// (fired stays true); if Verify returns cleanly, the goroutine completes normally
// (fired stays false). Either way the parent meta-test goroutine is untouched, so an
// EXPECTED fatal does not fail the meta-test.
func runVerifyExpectingFatal(ft *foldguard.Tracker, label string, canonical map[string]struct{}, settledAtReturn int) *fatalCapture {
	fc := &fatalCapture{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ft.Verify(fc, label, canonical, settledAtReturn)
	}()
	<-done
	return fc
}

// healthyTracker enters AND asserts each canonical name exactly once, the shape a
// well-formed fold produces. The negative cases below each perturb ONE axis off
// this baseline so the perturbed axis is what trips, in isolation.
func healthyTracker() *foldguard.Tracker {
	ft := foldguard.New()
	for _, n := range canonicalNames {
		done := ft.Enter(n)
		ft.MarkAsserted(n)
		done()
	}
	return ft
}

// TestVerify_PassesOnAWellFormedFold is the POSITIVE control: a Tracker that
// entered and asserted every canonical name exactly once, captured synchronously,
// must NOT fire. Without this the negative cases could pass merely because Verify
// fires unconditionally.
func TestVerify_PassesOnAWellFormedFold(t *testing.T) {
	ft := healthyTracker()
	canonical := foldguard.CanonicalNameSet(t, canonicalNames)
	got := runVerifyExpectingFatal(ft, "control", canonical, len(canonicalNames))
	if got.fired {
		t.Fatalf("Verify fired on a WELL-FORMED fold (every cell entered+asserted once, settled synchronously): %s — the guard must pass clean here or every negative case is meaningless", got.msg)
	}
}

// TestVerify_FlagsADoubleVisitPlusSkip is THE load-bearing non-vacuous proof: a
// fold that exercises one cell TWICE and skips another nets the SAME total a bare
// count would wave through (settledAtReturn still == len(canonical)), but the
// name-set reach guard MUST fail it.
func TestVerify_FlagsADoubleVisitPlusSkip(t *testing.T) {
	ft := foldguard.New()
	// Visit "alpha" twice, "beta" once, SKIP "gamma": 3 reaches total, same count as
	// a healthy fold, but the SET is wrong.
	for _, n := range []string{"alpha", "alpha", "beta"} {
		done := ft.Enter(n)
		ft.MarkAsserted(n)
		done()
	}
	canonical := foldguard.CanonicalNameSet(t, canonicalNames)
	// settledAtReturn == len(canonical): the count axis is SATISFIED, so only the
	// name-set axis can catch the swap. This is the exact hole the guard closes.
	got := runVerifyExpectingFatal(ft, "double-visit", canonical, len(canonicalNames))
	if !got.fired {
		t.Fatalf("Verify did NOT fire on a double-visit+skip swap (alpha x2, gamma skipped, total count unchanged) — a bare cell COUNT waves this through; the name-set guard is supposed to catch it")
	}
	if !strings.Contains(got.msg, "exercised") || !strings.Contains(got.msg, "alpha") {
		t.Fatalf("double-visit fatal did not name the doubled cell: %q", got.msg)
	}
}

// TestVerify_FlagsAForeignCell proves a cell name OUTSIDE the canonical set fails
// the reach name-set guard (the fold drifted off the canonical cells).
func TestVerify_FlagsAForeignCell(t *testing.T) {
	ft := foldguard.New()
	for _, n := range []string{"alpha", "beta", "intruder"} {
		done := ft.Enter(n)
		ft.MarkAsserted(n)
		done()
	}
	canonical := foldguard.CanonicalNameSet(t, canonicalNames)
	got := runVerifyExpectingFatal(ft, "foreign", canonical, len(canonicalNames))
	if !got.fired {
		t.Fatalf("Verify did NOT fire on a FOREIGN cell %q outside the canonical set", "intruder")
	}
	if !strings.Contains(got.msg, "FOREIGN") || !strings.Contains(got.msg, "intruder") {
		t.Fatalf("foreign fatal did not name the foreign cell: %q", got.msg)
	}
}

// TestVerify_FlagsASkippedCell proves a strictly-short reach set (a dropped cell,
// with the count also short) fails the LENGTH guard.
func TestVerify_FlagsASkippedCell(t *testing.T) {
	ft := foldguard.New()
	for _, n := range []string{"alpha", "beta"} { // gamma dropped
		done := ft.Enter(n)
		ft.MarkAsserted(n)
		done()
	}
	canonical := foldguard.CanonicalNameSet(t, canonicalNames)
	// Pass the FULL canonical size as settledAtReturn so the serial-execution pin is
	// SATISFIED and does not pre-empt the name-set LENGTH guard — we want to prove the
	// SET guard itself bites on a dropped cell, in isolation.
	got := runVerifyExpectingFatal(ft, "skip", canonical, len(canonicalNames))
	if !got.fired {
		t.Fatalf("Verify did NOT fire on a SKIPPED cell (gamma never entered)")
	}
	if !strings.Contains(got.msg, "SKIPPED") || !strings.Contains(got.msg, "gamma") {
		t.Fatalf("skip fatal did not name the skipped cell: %q", got.msg)
	}
}

// TestVerify_FlagsAReachedButUnassertedCell proves the assert-fired axis: a cell
// that ENTERS (reach is complete) but never calls MarkAsserted — a body that
// short-circuits BEFORE its load-bearing assertion — is FLAGGED, not counted as
// covered by reach alone.
func TestVerify_FlagsAReachedButUnassertedCell(t *testing.T) {
	ft := foldguard.New()
	for _, n := range canonicalNames {
		done := ft.Enter(n)
		if n != "gamma" { // gamma reached but its assert never fires
			ft.MarkAsserted(n)
		}
		done()
	}
	canonical := foldguard.CanonicalNameSet(t, canonicalNames)
	got := runVerifyExpectingFatal(ft, "unasserted", canonical, len(canonicalNames))
	if !got.fired {
		t.Fatalf("Verify did NOT fire on a REACHED-but-UNASSERTED cell (gamma entered, MarkAsserted never ran) — reach coverage must not pass for assert coverage")
	}
	if !strings.Contains(got.msg, "assertion") || !strings.Contains(got.msg, "gamma") {
		t.Fatalf("unasserted fatal did not name the reached-but-unasserted cell: %q", got.msg)
	}
}

// TestVerify_FlagsAShortSynchronousCount proves the PRIMARY serial-execution pin: a
// fold whose reach/assert SETS are complete but whose settledAtReturn is short — the
// fingerprint of a t.Parallel()'d cell paused past the parent — fails LOUDLY.
func TestVerify_FlagsAShortSynchronousCount(t *testing.T) {
	ft := healthyTracker() // sets are complete
	canonical := foldguard.CanonicalNameSet(t, canonicalNames)
	// Simulate a parallelized cell: it WILL eventually run (the set is complete here)
	// but had NOT settled synchronously at loop exit, so settledAtReturn is short.
	got := runVerifyExpectingFatal(ft, "parallel", canonical, len(canonicalNames)-1)
	if !got.fired {
		t.Fatalf("Verify did NOT fire on a SHORT synchronous count (settledAtReturn < len(canonical)) — a t.Parallel()'d cell is paused past the parent and must trip the serial-execution pin")
	}
	if !strings.Contains(got.msg, "serial-execution invariant VIOLATED") {
		t.Fatalf("short-count fatal was not the serial-execution diagnostic: %q", got.msg)
	}
}

// TestVerify_FlagsConcurrentOverlap proves the BELT-AND-SUSPENDERS serial pin: a
// hand-rolled goroutine fan-out (NOT deferred past the parent like t.Parallel, so
// the synchronous count is FULL) is caught by the atomic in-flight high-water mark.
// Two cells are held in flight SIMULTANEOUSLY — each enters, then blocks on a barrier
// until BOTH have entered, so maxInFly is forced to 2 — before either releases. The
// reach/assert sets and the synchronous count all complete cleanly, so ONLY the
// in-flight high-water guard can catch the overlap.
func TestVerify_FlagsConcurrentOverlap(t *testing.T) {
	ft := foldguard.New()
	bothEntered := make(chan struct{})
	enteredA := make(chan struct{})
	enteredB := make(chan struct{})

	go func() {
		done := ft.Enter("alpha")
		ft.MarkAsserted("alpha")
		close(enteredA)
		<-bothEntered // hold alpha in flight until beta has also entered
		done()
	}()
	go func() {
		done := ft.Enter("beta")
		ft.MarkAsserted("beta")
		close(enteredB)
		<-bothEntered // hold beta in flight until alpha has also entered
		done()
	}()
	<-enteredA
	<-enteredB
	close(bothEntered) // both were in flight at once -> maxInFly == 2

	// gamma serially to complete the canonical set.
	doneG := ft.Enter("gamma")
	ft.MarkAsserted("gamma")
	doneG()

	canonical := foldguard.CanonicalNameSet(t, canonicalNames)
	got := runVerifyExpectingFatal(ft, "overlap", canonical, len(canonicalNames))
	if !got.fired {
		t.Fatalf("Verify did NOT fire on CONCURRENT cell overlap (maxInFly reached 2) — a goroutine fan-out must trip the in-flight high-water guard")
	}
	if !strings.Contains(got.msg, "ran concurrently") {
		t.Fatalf("overlap fatal was not the concurrency diagnostic: %q", got.msg)
	}
}

// TestCanonicalNameSet_RejectsADuplicateDeclaration proves the yardstick itself
// cannot silently be the wrong shape: a canonical LIST with a repeated name (a
// malformed declaration) fails LOUDLY rather than collapsing to a smaller set.
func TestCanonicalNameSet_RejectsADuplicateDeclaration(t *testing.T) {
	got := captureCanonical(func(fr foldguard.FatalReporter) {
		foldguard.CanonicalNameSet(fr, []string{"alpha", "beta", "alpha"})
	})
	if !got.fired {
		t.Fatalf("CanonicalNameSet did NOT fire on a duplicate name in the canonical declaration — a malformed yardstick must fail, not silently shrink")
	}
	if !strings.Contains(got.msg, "twice") {
		t.Fatalf("duplicate-declaration fatal did not flag the repeat: %q", got.msg)
	}
}

// captureCanonical runs fn (a CanonicalNameSet call) on its own goroutine against a
// fatalCapture so a Fatalf+Goexit is observed without failing the meta-test.
func captureCanonical(fn func(foldguard.FatalReporter)) *fatalCapture {
	fc := &fatalCapture{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(fc)
	}()
	<-done
	return fc
}

// TestCanonicalNameSet_BuildsTheExpectedSet is a sanity control: a well-formed list
// yields a set with exactly those names.
func TestCanonicalNameSet_BuildsTheExpectedSet(t *testing.T) {
	set := foldguard.CanonicalNameSet(t, canonicalNames)
	if len(set) != len(canonicalNames) {
		t.Fatalf("CanonicalNameSet produced %d names, want %d", len(set), len(canonicalNames))
	}
	got := make([]string, 0, len(set))
	for n := range set {
		got = append(got, n)
	}
	sort.Strings(got)
	want := append([]string(nil), canonicalNames...)
	sort.Strings(want)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CanonicalNameSet set = %v, want %v", got, want)
		}
	}
}
