// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gitStage runs git in dir with a hermetic identity/config (no user/global/system
// config, no hooks) and fails the test on error.
func gitStage(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// TestStageOwnedIntoCommit pins the tasks-on-branch land discipline (doc 27 Lever
// 3): `stage-owned --into <worktree> --commit <msg>` freezes the owned task from
// THIS (canonical) live DB and commits it onto the branch checked out in the
// linked worktree — NOT onto the primary checkout — so the integration branch is
// self-contained for the serialized landing-queue leader to FF-merge.
func TestStageOwnedIntoCommit(t *testing.T) {
	for _, ev := range dbPathEnvVars { // isolate openDB() from ambient snapshot overrides
		t.Setenv(ev, "")
	}
	t.Setenv("TASKDB_LOCK_DISABLE", "1")

	// cmdStageOwned spawns `git commit` inheriting THIS process's environment
	// (not gitStage's per-call cmd.Env), so give the whole test a hermetic git
	// identity here too — otherwise the commit fails with "empty ident name" on
	// CI runners that carry no global/system git config.
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@t")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@t")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")

	root := t.TempDir()
	gitStage(t, root, "init", "-q")
	if err := os.Mkdir(filepath.Join(root, "tasks"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tasks", ".gitkeep"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	gitStage(t, root, "add", "-A")
	gitStage(t, root, "commit", "-q", "-m", "init")
	base := strings.TrimSpace(gitStage(t, root, "rev-parse", "--abbrev-ref", "HEAD"))

	// chdir into the primary so openDB()/tasksDir() resolve repo-local.
	prev, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(prev) })
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	now := timeToMs(time.Now().UTC())
	const id = "01STAGEOWNEDINTO00000000AA"
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		id, "demo", "", "done", 0, now, now,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// A linked worktree on a fresh integration branch (shares the primary $GIT_DIR).
	wt := filepath.Join(t.TempDir(), "integ")
	gitStage(t, root, "worktree", "add", "-q", "-b", "feat", wt, "HEAD")

	if err := cmdStageOwned(db, []string{"--into", wt, "--commit", "tasks: feat statuses", id}); err != nil {
		t.Fatalf("stage-owned --into --commit: %v", err)
	}

	jsonPath := "tasks/task-" + id + ".json"

	// The owned task is committed on `feat` in the worktree, carrying status done.
	show := gitStage(t, wt, "show", "feat:"+jsonPath)
	if !strings.Contains(show, "done") {
		t.Fatalf("feat commit missing done status:\n%s", show)
	}
	if logFeat := gitStage(t, wt, "log", "--oneline", "-1", "feat"); !strings.Contains(logFeat, "feat statuses") {
		t.Fatalf("commit not on feat: %s", logFeat)
	}

	// It must NOT have landed on the primary branch, and the primary working tree
	// must not carry the frozen json (no leak onto main / drift in the primary).
	if logBase := gitStage(t, root, "log", "--oneline", base); strings.Contains(logBase, "feat statuses") {
		t.Fatalf("statuses leaked onto %s: %s", base, logBase)
	}
	if _, err := os.Stat(filepath.Join(root, jsonPath)); err == nil {
		t.Fatalf("task json written into the PRIMARY tasks/ (expected only in --into worktree)")
	}
}
