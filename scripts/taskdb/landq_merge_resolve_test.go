// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// landq_merge_resolve_test.go is the GIT-INVOCATION e2e proof of the leader's
// tasks/-only merge-conflict auto-resolution (the production seed: #4375->#4376,
// #4385->#4387 relands). It reuses the same real-temp-git-repo machinery as
// mergedriver_git_e2e_test.go (a repo with the tasks/*.json merge=taskdb driver
// wired to the hermetically built binary), then drives the leader's OWN
// mergeEntryBranch / resolveTasksOnlyConflict path — NOT a bare `git merge` — and
// asserts:
//
//   - a tasks/-ONLY modify/delete conflict (a task pruned on main, still edited on
//     the branch) AUTO-RESOLVES: the merge commit completes, the file stays
//     deleted (main's prune honored), and the land may proceed; and
//   - a conflict touching a NON-tasks/ path still BLOCKS (mergeEntryBranch returns
//     outcome.blocked=true) so a real code conflict is never auto-landed.
//
// These call the leader functions directly (no lock server, no Postgres) on a
// throwaway detached worktree, mirroring how landOnePass runs after a failed
// `git merge --no-ff`. Hermetic; t.Skips when git is unavailable.

// landqE2EDetachedWorktree creates a detached worktree of root at ref (origin/<main>
// stand-in) so HEAD == ref is the FIRST parent of the merge, exactly as
// makeThrowawayWorktree does in production. Returns the worktree path.
func landqE2EDetachedWorktree(t *testing.T, root, ref string) string {
	t.Helper()
	wt := filepath.Join(t.TempDir(), "merge-wt")
	if out, err := gitE2ETry(root, "worktree", "add", "--detach", wt, ref); err != nil {
		t.Fatalf("git worktree add --detach %s %s: %v\n%s", wt, ref, err, out)
	}
	t.Cleanup(func() { _, _ = gitE2ETry(root, "worktree", "remove", "--force", wt) })
	return wt
}

// landqE2EBranchSHA resolves a branch ref to its tip sha in root.
func landqE2EBranchSHA(t *testing.T, root, ref string) string {
	t.Helper()
	out, err := gitE2ETry(root, "rev-parse", ref)
	if err != nil {
		t.Fatalf("git rev-parse %s: %v\n%s", ref, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestLandqMergeResolve_TasksOnlyModifyDeleteAutoResolves is the positive proof of
// the seed fix: a task JSON the BRANCH still modifies but MAIN deleted is a
// tree-level modify/delete the union driver structurally cannot reach. The leader
// must auto-resolve it (honor main's deletion), complete the merge, and leave the
// land landable — not bail to [conflict].
func TestLandqMergeResolve_TasksOnlyModifyDeleteAutoResolves(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := gitE2EBin(t)
	root := gitE2EInitRepo(t, bin)
	const rel = "tasks/task-01PRUNE.json"

	// Common ancestor on the default branch: the task exists.
	gitE2EWriteCommit(t, root, rel,
		`{"id":"01PRUNE","title":"base","status":"open","priority":2,"created_at":"2026-06-15T01:00:00Z","updated_at":"2026-06-15T01:00:00Z"}`,
		"base: task present")
	mainRef := landqE2EBranchSHA(t, root, "HEAD")

	// Branch off the base and MODIFY the task (a status edit a wave carries).
	gitE2ERun(t, root, "checkout", "-q", "-b", "feature")
	gitE2EWriteCommit(t, root, rel,
		`{"id":"01PRUNE","title":"base","status":"done","priority":2,"created_at":"2026-06-15T01:00:00Z","updated_at":"2026-06-15T02:00:00Z"}`,
		"feature: edit status (the moot edit)")
	branchSHA := landqE2EBranchSHA(t, root, "HEAD")

	// Back on main: a parallel session PRUNES the task (git rm). This is the race.
	gitE2ERun(t, root, "checkout", "-q", mainRef)
	gitE2ERun(t, root, "checkout", "-q", "-B", "mainline")
	gitE2EWriteCommit(t, root, rel, "", "mainline: prune the task")
	mainTip := landqE2EBranchSHA(t, root, "mainline")

	// A detached worktree at the pruned mainline tip (origin/<main> stand-in), so
	// mainline is parent #1 of the merge — exactly the leader's throwaway worktree.
	wt := landqE2EDetachedWorktree(t, root, mainTip)

	// Drive the LEADER's merge+resolve path on the explicit branch sha.
	entry := &LandEntry{ID: 4375, Branch: "feature"}
	outcome, ok, mergeOut, err := mergeEntryBranch(wt, entry, branchSHA)
	if !ok {
		t.Fatalf("mergeEntryBranch ok=false (unenumerable) err=%v\n%s", err, mergeOut)
	}
	if outcome.blocked {
		t.Fatalf("tasks/-only modify/delete was BLOCKED (%s); want auto-resolve", outcome.blockDetail)
	}
	if len(outcome.autoResolved) != 1 || outcome.autoResolved[0] != rel {
		t.Fatalf("autoResolved = %v, want exactly [%s]", outcome.autoResolved, rel)
	}

	// The merge commit must exist (HEAD has TWO parents) and the pruned file must
	// STAY deleted (main's intentional drop honored).
	if parents, perr := gitE2ETry(wt, "rev-list", "--parents", "-n", "1", "HEAD"); perr != nil {
		t.Fatalf("rev-list parents: %v\n%s", perr, parents)
	} else if n := len(strings.Fields(string(parents))); n != 3 { // commit + 2 parents
		t.Fatalf("merge HEAD has %d fields (want 3: commit + 2 parents) — not a merge commit:\n%s", n, parents)
	}
	if _, statErr := os.Stat(filepath.Join(wt, rel)); !os.IsNotExist(statErr) {
		t.Fatalf("%s still present after auto-resolve — main's prune was NOT honored (stat err=%v)", rel, statErr)
	}
	// And the worktree must be clean (no unmerged paths left behind).
	if u, uerr := unmergedPaths(wt); uerr != nil || len(u) != 0 {
		t.Fatalf("unmergedPaths after auto-resolve = %v (err %v), want empty", u, uerr)
	}
}

// TestLandqMergeResolve_NonTasksConflictStillBlocks is the negative guard: a
// conflict on ANY non-tasks/ path is a real code conflict that must NOT be
// auto-resolved. mergeEntryBranch must return outcome.blocked=true with a detail
// that names the real clashing path, and must NOT complete a merge commit.
func TestLandqMergeResolve_NonTasksConflictStillBlocks(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := gitE2EBin(t)
	root := gitE2EInitRepo(t, bin)
	const code = "main.go"
	const taskRel = "tasks/task-01MIX.json"

	// Base: a code file + a task file both present.
	gitE2EWriteCommit(t, root, code, "package main\n\nfunc main() {}\n", "base: code")
	gitE2EWriteCommit(t, root, taskRel,
		`{"id":"01MIX","title":"base","status":"open","priority":2,"created_at":"2026-06-15T01:00:00Z","updated_at":"2026-06-15T01:00:00Z"}`,
		"base: task")
	mainRef := landqE2EBranchSHA(t, root, "HEAD")

	// Branch: change the code one way AND edit the task.
	gitE2ERun(t, root, "checkout", "-q", "-b", "feature")
	gitE2EWriteCommit(t, root, code, "package main\n\nfunc main() { println(\"branch\") }\n", "feature: code")
	gitE2EWriteCommit(t, root, taskRel,
		`{"id":"01MIX","title":"base","status":"done","priority":2,"created_at":"2026-06-15T01:00:00Z","updated_at":"2026-06-15T02:00:00Z"}`,
		"feature: task edit")
	branchSHA := landqE2EBranchSHA(t, root, "HEAD")

	// Mainline: change the SAME code line a DIFFERENT way (a real conflict) and
	// prune the task (so a tasks/-only path would otherwise be auto-resolvable).
	gitE2ERun(t, root, "checkout", "-q", mainRef)
	gitE2ERun(t, root, "checkout", "-q", "-B", "mainline")
	gitE2EWriteCommit(t, root, code, "package main\n\nfunc main() { println(\"mainline\") }\n", "mainline: code")
	gitE2EWriteCommit(t, root, taskRel, "", "mainline: prune task")
	mainTip := landqE2EBranchSHA(t, root, "mainline")

	wt := landqE2EDetachedWorktree(t, root, mainTip)
	entry := &LandEntry{ID: 4385, Branch: "feature"}
	outcome, ok, _, err := mergeEntryBranch(wt, entry, branchSHA)
	if !ok {
		t.Fatalf("mergeEntryBranch ok=false err=%v", err)
	}
	if !outcome.blocked {
		t.Fatalf("mixed code+tasks/ conflict was NOT blocked (autoResolved=%v) — a real code conflict must still bail", outcome.autoResolved)
	}
	if !strings.Contains(outcome.blockDetail, "code conflict") || !strings.Contains(outcome.blockDetail, code) {
		t.Errorf("blockDetail = %q, want it to name the real %q clash", outcome.blockDetail, code)
	}
	// The merge must have been ABORTED — there must be no unmerged paths left.
	if u, uerr := unmergedPaths(wt); uerr != nil {
		t.Fatalf("unmergedPaths after blocked merge: %v", uerr)
	} else if len(u) != 0 {
		t.Errorf("merge left %d unmerged path(s) after a blocked conflict; want abort to clean them: %v", len(u), u)
	}
}
