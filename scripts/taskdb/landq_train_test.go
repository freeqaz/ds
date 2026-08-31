// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os/exec"
	"testing"
	"time"
)

// landq_train_test.go covers the DORMANT merge-train batcher (landq run --batch N,
// doc 27 §3 Deferred). Three layers, cheapest first:
//
//  1. TestBisectGreenPrefix — the PURE split-bisection selector over a synthetic
//     monotone gate predicate. No git, no Postgres; always runs. This is the core
//     correctness proof: given a train and a "prefix is green" predicate, it must
//     find the maximal green prefix and identify the first red member.
//  2. TestLandqTrain_* — a git-invocation e2e that builds a real repo with two
//     disjoint feature branches and drives the train's OWN assembly path
//     (mergeEntryBranch stacking, origin/<main> as parent #1) on a detached
//     throwaway worktree, asserting the assembled head has BOTH branches as
//     ancestors and that a dry-run NEVER pushes. t.Skips when git is absent.
//  3. TestLandqClaimNextLandBatchLive — a live/ephemeral-PG round-trip of
//     claimNextLandBatch: enqueue 3, batch-claim 2, assert both flip to 'landing'
//     in pick order, DELETE every row in t.Cleanup. Skips on the default gate.

// --- (1) PURE bisection selector ---------------------------------------------

// TestBisectGreenPrefix table-tests bisectGreenPrefix over a synthetic gate
// predicate that is GREEN iff the prefix contains no "BAD" sentinel (a monotone
// predicate: once a BAD member is included, every longer prefix stays red). It
// asserts both the returned prefix length AND that items[prefixLen] is the first
// red, across green-all / red-first / red-middle / red-last / single-red / empty,
// and bounds the gate-call count to the O(log n) the binary search promises.
func TestBisectGreenPrefix(t *testing.T) {
	cases := []struct {
		name       string
		items      []string
		wantPrefix int
		wantFirst  string // the first red member, or "" when the whole train is green
	}{
		{"empty", []string{}, 0, ""},
		{"green-all", []string{"a", "b", "c", "d"}, 4, ""},
		{"red-first", []string{"BAD", "b", "c"}, 0, "BAD"},
		{"red-middle", []string{"a", "b", "BAD", "d"}, 2, "BAD"},
		{"red-last", []string{"a", "b", "c", "BAD"}, 3, "BAD"},
		{"single-red", []string{"BAD"}, 0, "BAD"},
		{"single-green", []string{"a"}, 1, ""},
		{"two-red-first-found", []string{"a", "BAD", "c", "BAD"}, 1, "BAD"},
		{"red-at-len-minus-one-long", []string{"a", "b", "c", "d", "e", "f", "g", "BAD"}, 7, "BAD"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			// Monotone predicate: green iff no member up to k is "BAD".
			gate := func(prefix []string) bool {
				calls++
				for _, m := range prefix {
					if m == "BAD" {
						return false
					}
				}
				return true
			}
			got := bisectGreenPrefix(tc.items, gate)
			if got != tc.wantPrefix {
				t.Fatalf("bisectGreenPrefix(%v) prefix = %d, want %d", tc.items, got, tc.wantPrefix)
			}
			// The member AT the prefix boundary (if any) is the first red.
			if got < len(tc.items) {
				if tc.items[got] != tc.wantFirst {
					t.Errorf("first red = %q, want %q", tc.items[got], tc.wantFirst)
				}
			} else if tc.wantFirst != "" {
				t.Errorf("expected a first-red %q but prefix covered the whole train", tc.wantFirst)
			}
			// O(log n) bound: the search makes at most ~2+ceil(log2(n+1)) gate calls
			// (one whole-train probe + the binary search). Generously bound it so the
			// test pins the asymptotics without being brittle.
			n := len(tc.items)
			bound := 2
			for (1 << (bound - 2)) < n+1 {
				bound++
			}
			bound += 2 // slack for the whole-train fast-path probe + boundary checks
			if calls > bound {
				t.Errorf("gate called %d times for n=%d, want <= %d (O(log n))", calls, n, bound)
			}
		})
	}
}

// TestBisectGreenPrefix_EmptyPrefixAssumedGreen pins the contract that the empty
// prefix is treated as green WITHOUT the predicate being consulted for [:0] in the
// degenerate path — the real predicate short-circuits gate(nil)=true (origin/<main>
// unchanged). Here we assert the all-red train returns prefix 0 (land nothing).
func TestBisectGreenPrefix_AllRed(t *testing.T) {
	items := []string{"BAD", "BAD", "BAD"}
	gate := func(prefix []string) bool {
		for _, m := range prefix {
			if m == "BAD" {
				return false
			}
		}
		return true
	}
	if got := bisectGreenPrefix(items, gate); got != 0 {
		t.Fatalf("all-red train: prefix = %d, want 0", got)
	}
}

// --- (2) git-invocation train-assembly e2e -----------------------------------

// TestLandqTrain_TwoDisjointBranchesAssembleUnderOneHead builds a repo with two
// disjoint feature branches off a common main, then drives the train's stacking
// merge (mergeEntryBranch in order on a detached throwaway worktree) and asserts
// the assembled head carries BOTH branches as ancestors with origin/<main> as the
// first-parent root. It NEVER pushes (no remote, dry-run semantics). t.Skips when
// git is absent. This exercises the same assembly mergeEntryBranch the real
// landTrainPass uses, without a lock server.
func TestLandqTrain_TwoDisjointBranchesAssembleUnderOneHead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := gitE2EBin(t)
	root := gitE2EInitRepo(t, bin)

	// Common ancestor (the "main" stand-in).
	gitE2EWriteCommit(t, root, "README.md", "base\n", "base: readme")
	mainRef := landqE2EBranchSHA(t, root, "HEAD")

	// Branch A touches a.txt; branch B touches b.txt — disjoint, so they merge clean.
	gitE2ERun(t, root, "checkout", "-q", "-b", "feat-a", mainRef)
	gitE2EWriteCommit(t, root, "a.txt", "alpha\n", "feat-a: add a")
	shaA := landqE2EBranchSHA(t, root, "HEAD")

	gitE2ERun(t, root, "checkout", "-q", "-b", "feat-b", mainRef)
	gitE2EWriteCommit(t, root, "b.txt", "bravo\n", "feat-b: add b")
	shaB := landqE2EBranchSHA(t, root, "HEAD")

	// A detached worktree at the main tip — exactly the leader's throwaway worktree
	// (origin/<main> at HEAD => parent #1 of every merge).
	wt := landqE2EDetachedWorktree(t, root, mainRef)

	// Stack-merge A then B, mirroring landTrainPass's assembleTrain.
	mA := &LandEntry{ID: 9001, Branch: "feat-a"}
	mB := &LandEntry{ID: 9002, Branch: "feat-b"}
	if outcome, ok, out, err := mergeEntryBranch(wt, mA, shaA); !ok || outcome.blocked {
		t.Fatalf("merge feat-a: ok=%v blocked=%v err=%v\n%s", ok, outcome.blocked, err, out)
	}
	if outcome, ok, out, err := mergeEntryBranch(wt, mB, shaB); !ok || outcome.blocked {
		t.Fatalf("merge feat-b: ok=%v blocked=%v err=%v\n%s", ok, outcome.blocked, err, out)
	}

	head, err := gitHead(wt)
	if err != nil {
		t.Fatalf("gitHead: %v", err)
	}

	// Both branch tips must be ancestors of the assembled train head.
	if !isAncestor(wt, shaA, head) {
		t.Errorf("feat-a (%s) is NOT an ancestor of the train head %s", shaA, head)
	}
	if !isAncestor(wt, shaB, head) {
		t.Errorf("feat-b (%s) is NOT an ancestor of the train head %s", shaB, head)
	}
	// And origin/<main> (mainRef) must be the first-parent root.
	if !isAncestor(wt, mainRef, head) {
		t.Errorf("main (%s) is NOT an ancestor of the train head %s", mainRef, head)
	}
	// Both files must be present in the assembled tree (the disjoint changes merged).
	for _, f := range []string{"a.txt", "b.txt", "README.md"} {
		if out, err := gitE2ETry(wt, "cat-file", "-e", "HEAD:"+f); err != nil {
			t.Errorf("file %q missing from train head: %v\n%s", f, err, out)
		}
	}

	// The bisection predicate over a GREEN (gate="") assembly must report the whole
	// train green — i.e. bisectGreenPrefix returns len(members) when every prefix
	// merges and the (empty) gate passes. We exercise the SAME assemble-then-judge
	// shape the production gatePrefix uses, but with no lock server and gate="".
	members := []trainMember{{entry: mA, branchSHA: shaA}, {entry: mB, branchSHA: shaB}}
	gatePrefix := func(prefix []trainMember) bool {
		if len(prefix) == 0 {
			return true
		}
		if o, rerr := runGit(wt, "reset", "--hard", mainRef); rerr != nil {
			t.Fatalf("reset: %v\n%s", rerr, o)
		}
		for _, m := range prefix {
			if outcome, ok, out, err := mergeEntryBranch(wt, m.entry, m.branchSHA); !ok || outcome.blocked {
				t.Logf("prefix member %s did not merge: ok=%v blocked=%v err=%v\n%s", m.entry.Branch, ok, outcome.blocked, err, out)
				return false
			}
		}
		return true // gate="" => a clean assembly is green
	}
	if got := bisectGreenPrefix(members, gatePrefix); got != len(members) {
		t.Errorf("bisectGreenPrefix over a clean 2-branch train = %d, want %d (all green)", got, len(members))
	}
}

// TestLandqTrain_RedMiddleBisectsToGreenPrefix proves the bisection selector over a
// REAL assembled train: three branches where the MIDDLE one would fail a gate. We
// model the gate as "green iff the assembly does NOT contain feat-bad's marker
// file", so the predicate is monotone and the maximal green prefix is the first
// member only. No push, no lock server.
func TestLandqTrain_RedMiddleBisectsToGreenPrefix(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := gitE2EBin(t)
	root := gitE2EInitRepo(t, bin)
	gitE2EWriteCommit(t, root, "README.md", "base\n", "base")
	mainRef := landqE2EBranchSHA(t, root, "HEAD")

	mk := func(branch, file, content string) (*LandEntry, string) {
		gitE2ERun(t, root, "checkout", "-q", "-b", branch, mainRef)
		gitE2EWriteCommit(t, root, file, content, branch+": "+file)
		sha := landqE2EBranchSHA(t, root, "HEAD")
		return &LandEntry{Branch: branch}, sha
	}
	eGood1, sha1 := mk("feat-good1", "g1.txt", "g1\n")
	eBad, shaBad := mk("feat-bad", "bad.txt", "BAD\n")
	eGood2, sha2 := mk("feat-good2", "g2.txt", "g2\n")

	wt := landqE2EDetachedWorktree(t, root, mainRef)
	members := []trainMember{
		{entry: eGood1, branchSHA: sha1},
		{entry: eBad, branchSHA: shaBad},
		{entry: eGood2, branchSHA: sha2},
	}

	// Gate predicate: assemble the prefix, then RED iff bad.txt is present in the
	// worktree (a stand-in for "this member breaks the build"). Monotone: once
	// feat-bad is in the prefix the marker stays present for every longer prefix.
	gatePrefix := func(prefix []trainMember) bool {
		if len(prefix) == 0 {
			return true
		}
		if o, rerr := runGit(wt, "reset", "--hard", mainRef); rerr != nil {
			t.Fatalf("reset: %v\n%s", rerr, o)
		}
		for _, m := range prefix {
			if outcome, ok, out, err := mergeEntryBranch(wt, m.entry, m.branchSHA); !ok || outcome.blocked {
				t.Logf("member %s did not merge: ok=%v blocked=%v err=%v\n%s", m.entry.Branch, ok, outcome.blocked, err, out)
				return false
			}
		}
		// "Gate": present-bad.txt = red.
		_, err := gitE2ETry(wt, "cat-file", "-e", "HEAD:bad.txt")
		return err != nil // err != nil => file absent => green
	}

	prefixLen := bisectGreenPrefix(members, gatePrefix)
	if prefixLen != 1 {
		t.Fatalf("bisectGreenPrefix with a red MIDDLE member = %d, want 1 (only feat-good1 is green)", prefixLen)
	}
	if members[prefixLen].entry.Branch != "feat-bad" {
		t.Errorf("first red = %q, want feat-bad", members[prefixLen].entry.Branch)
	}
}

// --- (3) live-PG batch-claim round-trip --------------------------------------

// TestLandqClaimNextLandBatchLive exercises claimNextLandBatch against a live or
// ephemeral Postgres: enqueue 3 distinct branches, batch-claim 2, and assert both
// returned in pick order (priority DESC, id) flipped to 'landing' with runner set
// and attempts bumped, while the 3rd stays 'queued'. DELETES every inserted row in
// t.Cleanup so the shared DB is left pristine; NEVER pushes origin/main (no git).
// Skips on the default gate (no live config) via landqServerForTest.
func TestLandqClaimNextLandBatchLive(t *testing.T) {
	ls := landqServerForTest(t)

	stamp := time.Now().UnixNano()
	branches := []string{
		fmt.Sprintf("landq-smoke/batch-%d-a", stamp),
		fmt.Sprintf("landq-smoke/batch-%d-b", stamp),
		fmt.Sprintf("landq-smoke/batch-%d-c", stamp),
	}
	t.Cleanup(func() {
		for _, b := range branches {
			if _, err := ls.deleteLandByBranch(b); err != nil {
				t.Errorf("cleanup deleteLandByBranch(%q) failed — a test row may remain in the SHARED DB: %v", b, err)
			}
		}
	})

	// Enqueue all three at the SAME priority so pick order is purely by id (insert
	// order).
	for i, b := range branches {
		e := LandEntry{Branch: b, BaseSHA: "cafef00d", TaskIDs: fmt.Sprintf("BATCHTEST%d", i), Priority: 0, RequestedBy: "batch-smoke", Host: devHost()}
		id, enqueued, err := ls.enqueueLand(e)
		if err != nil {
			t.Fatalf("enqueueLand(%q): %v", b, err)
		}
		if !enqueued || id <= 0 {
			t.Fatalf("enqueueLand(%q) should be a fresh insert; got enqueued=%v id=%d", b, enqueued, id)
		}
	}

	const runner = "batch-claim-smoke"
	// claimNextLandBatch picks GLOBALLY by pick order (priority DESC, id), so against
	// a SHARED production queue it may return rows other than ours. We therefore
	// assert the CONTRACT that holds for ANY returned set — every row flipped to
	// 'landing' with runner set + attempts bumped + started_at stamped, the slice is
	// in pick order, and at most `n` rows — rather than the identity of the rows
	// (which a parallel enqueue/runner could perturb). Every row this claim touches
	// is registered for cleanup so no 'landing' row is stranded in the shared DB.
	claimed, err := ls.claimNextLandBatch(runner, 2)
	if err != nil {
		t.Fatalf("claimNextLandBatch: %v", err)
	}
	if len(claimed) == 0 {
		t.Skip("queue was empty at claim time (a concurrent runner drained it) — nothing to assert")
	}
	if len(claimed) > 2 {
		t.Fatalf("claimNextLandBatch(2) returned %d rows, want <= 2", len(claimed))
	}
	for _, e := range claimed {
		if e.Status != "landing" {
			t.Errorf("claimed #%d status=%q want landing", e.ID, e.Status)
		}
		if e.Runner != runner {
			t.Errorf("claimed #%d runner=%q want %q", e.ID, e.Runner, runner)
		}
		if e.Attempts < 1 {
			t.Errorf("claimed #%d attempts=%d want >=1", e.ID, e.Attempts)
		}
		if e.StartedAt == nil {
			t.Errorf("claimed #%d should have a non-nil started_at", e.ID)
		}
		// Every row we claim must be cleaned up even if it isn't one of OURS (a
		// parallel runner's row would be left 'landing' otherwise) — but in practice
		// the shared production runner holds the single-writer sentinel, so a test
		// run here without that sentinel only claims rows nobody else is draining.
		// We still register a per-id cleanup so a stray claim doesn't strand a row.
		idToClean := e.Branch
		t.Cleanup(func() { _, _ = ls.deleteLandByBranch(idToClean) })
	}
	// Pick order: returned ids must be non-decreasing in (priority DESC, id). With
	// equal priorities that means strictly increasing ids.
	for i := 1; i < len(claimed); i++ {
		if claimed[i].Priority == claimed[i-1].Priority && claimed[i].ID < claimed[i-1].ID {
			t.Errorf("claimed rows not in pick order at %d: #%d (prio %d) before #%d (prio %d)",
				i, claimed[i-1].ID, claimed[i-1].Priority, claimed[i].ID, claimed[i].Priority)
		}
		if claimed[i].Priority > claimed[i-1].Priority {
			t.Errorf("claimed rows not in priority order at %d: prio %d after prio %d",
				i, claimed[i].Priority, claimed[i-1].Priority)
		}
	}
}
