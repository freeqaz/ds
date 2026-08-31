// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// isolateDBPathEnv clears the explicit DB-path overrides so repoRoot()/dbPath()
// resolution is not skewed by an ambient TASKDB_DB/TASKDB_DBPATH (e.g. a
// wave-sandbox snapshot) and clears TASKDB_WORKTREE_LOCAL to a known-off state.
func isolateDBPathEnv(t *testing.T) {
	t.Helper()
	for _, ev := range dbPathEnvVars {
		t.Setenv(ev, "")
	}
	t.Setenv("TASKDB_WORKTREE_LOCAL", "")
}

// evalSym resolves symlinks so comparisons hold up on platforms where t.TempDir
// lives under a symlinked root (os.Getwd / git absolute paths come back
// resolved, the raw temp path may not).
func evalSym(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", p, err)
	}
	return r
}

// setupPrimaryAndWorktree builds a real primary checkout with a tasks/ dir and a
// linked git worktree, then chdirs into the worktree (so .git there is a FILE
// pointing at the primary, exactly as in production). It returns the
// symlink-resolved primary and worktree roots.
func setupPrimaryAndWorktree(t *testing.T) (primary, worktree string) {
	t.Helper()
	primary = evalSym(t, t.TempDir())
	gitStage(t, primary, "init", "-q")
	if err := os.Mkdir(filepath.Join(primary, "tasks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, "tasks", ".gitkeep"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	gitStage(t, primary, "add", "-A")
	gitStage(t, primary, "commit", "-q", "-m", "init")

	worktree = filepath.Join(evalSym(t, t.TempDir()), "wt")
	gitStage(t, primary, "worktree", "add", "-q", "-b", "wt-branch", worktree, "HEAD")

	// Confirm the worktree's .git is a FILE (the linked-worktree pointer), not a
	// dir — that is the branch repoRoot()'s redirect/opt-out logic keys on.
	fi, err := os.Stat(filepath.Join(worktree, ".git"))
	if err != nil {
		t.Fatalf("stat worktree .git: %v", err)
	}
	if fi.IsDir() {
		t.Fatalf("worktree .git is a directory; expected the linked-worktree pointer FILE")
	}

	prev, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(prev) })
	if err := os.Chdir(worktree); err != nil {
		t.Fatalf("chdir worktree: %v", err)
	}
	return primary, worktree
}

// TestWorktreeLocalDefaultRedirectsToPrimary pins D130: with the flag UNSET, a
// linked worktree's repoRoot()/dbPath()/tasksDir() all resolve to the PRIMARY
// checkout (the shared live DB), not the worktree's own root.
func TestWorktreeLocalDefaultRedirectsToPrimary(t *testing.T) {
	isolateDBPathEnv(t) // flag explicitly off (default)
	primary, worktree := setupPrimaryAndWorktree(t)

	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	if evalSym(t, root) != primary {
		t.Fatalf("default repoRoot = %q, want PRIMARY %q (D130 redirect regressed)", root, primary)
	}
	if evalSym(t, root) == worktree {
		t.Fatalf("default repoRoot resolved to the WORKTREE %q — D130 redirect lost", worktree)
	}

	dbp, err := dbPath()
	if err != nil {
		t.Fatalf("dbPath: %v", err)
	}
	if got, want := evalSym(t, filepath.Dir(dbp)), primary; got != want {
		t.Fatalf("default dbPath dir = %q, want PRIMARY %q", got, want)
	}
	if filepath.Base(dbp) != "taskdb.sqlite" {
		t.Fatalf("default dbPath base = %q, want taskdb.sqlite", filepath.Base(dbp))
	}

	td, err := tasksDir()
	if err != nil {
		t.Fatalf("tasksDir: %v", err)
	}
	if got, want := evalSym(t, td), filepath.Join(primary, "tasks"); got != want {
		t.Fatalf("default tasksDir = %q, want PRIMARY %q", got, want)
	}
}

// TestWorktreeLocalOptInResolvesToOwnRoot: with TASKDB_WORKTREE_LOCAL=1 the
// linked worktree resolves to its OWN root (own taskdb.sqlite + tasks/).
func TestWorktreeLocalOptInResolvesToOwnRoot(t *testing.T) {
	isolateDBPathEnv(t)
	t.Setenv("TASKDB_WORKTREE_LOCAL", "1") // opt in
	primary, worktree := setupPrimaryAndWorktree(t)

	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	if evalSym(t, root) != worktree {
		t.Fatalf("opt-in repoRoot = %q, want WORKTREE %q", root, worktree)
	}
	if evalSym(t, root) == primary {
		t.Fatalf("opt-in repoRoot resolved to the PRIMARY %q — opt-out not honored", primary)
	}

	dbp, err := dbPath()
	if err != nil {
		t.Fatalf("dbPath: %v", err)
	}
	if got, want := evalSym(t, filepath.Dir(dbp)), worktree; got != want {
		t.Fatalf("opt-in dbPath dir = %q, want WORKTREE %q", got, want)
	}

	td, err := tasksDir()
	if err != nil {
		t.Fatalf("tasksDir: %v", err)
	}
	if got, want := evalSym(t, filepath.Dir(td)), worktree; got != want {
		t.Fatalf("opt-in tasksDir parent = %q, want WORKTREE %q", got, want)
	}
}

// TestWorktreeLocalExplicitDBStillWins: the explicit TASKDB_DB override beats the
// flag — dbPath() returns the override verbatim, ahead of repoRoot() entirely.
func TestWorktreeLocalExplicitDBStillWins(t *testing.T) {
	isolateDBPathEnv(t)
	t.Setenv("TASKDB_WORKTREE_LOCAL", "1") // flag set...
	setupPrimaryAndWorktree(t)

	override := filepath.Join(t.TempDir(), "explicit.sqlite")
	t.Setenv("TASKDB_DB", override) // ...but the explicit override wins

	dbp, err := dbPath()
	if err != nil {
		t.Fatalf("dbPath: %v", err)
	}
	if dbp != override {
		t.Fatalf("dbPath = %q, want explicit override %q (TASKDB_DB precedence regressed)", dbp, override)
	}
}

// TestWorktreeLocalEnabledParsing pins the ALLOW-list parsing table: only
// 1/true/yes/on (any case, surrounding space tolerated) enable; everything else
// — including garbage — is OFF.
func TestWorktreeLocalEnabledParsing(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"yes", true},
		{"on", true},
		{"TRUE", true},
		{"On", true},
		{" yes ", true},
		{"", false},
		{"0", false},
		{"false", false},
		{"no", false},
		{"off", false},
		{"garbage", false},
		{"2", false},
		{"  ", false},
	}
	for _, c := range cases {
		t.Setenv("TASKDB_WORKTREE_LOCAL", c.val)
		if got := worktreeLocalEnabled(); got != c.want {
			t.Errorf("worktreeLocalEnabled() with %q = %v, want %v", c.val, got, c.want)
		}
	}
}
