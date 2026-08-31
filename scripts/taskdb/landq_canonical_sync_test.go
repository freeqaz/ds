// SPDX-License-Identifier: Apache-2.0
package main

// landq_canonical_sync_test.go covers syncCanonicalToOrigin — the post-land
// fast-forward of THIS box's canonical checkout to origin/<main> (the manual
// reconcile, codified into the leader). It is pure git (a bare "origin" + a clone),
// no Postgres, so it runs in the standard `go test ./scripts/taskdb/...`. The cases
// pin the safety contract: pure FF only, never thaw (hooks suppressed), preserve
// local-only untracked drift, set aside landed untracked collisions, and SKIP rather
// than rewrite/discard on divergence or a conflicting local tracked edit.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_NOSYSTEM=1", "HOME="+dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFileT(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFileT(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// setupCanonicalSyncRepos builds a bare origin seeded with one commit and a canonical
// clone of it (on main), and points DS_WT_ROOT at a temp dir so the sync's set-aside
// + no-hooks scratch dirs land under the test sandbox.
func setupCanonicalSyncRepos(t *testing.T) (canonical, origin string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("DS_WT_ROOT", filepath.Join(root, "wt"))
	origin = filepath.Join(root, "origin.git")
	gitT(t, root, "init", "--bare", "-b", "main", origin)

	seed := filepath.Join(root, "seed")
	gitT(t, root, "clone", origin, seed)
	writeFileT(t, seed, "README.md", "base\n")
	writeFileT(t, seed, "tasks/task-keep.json", `{"id":"keep","status":"open"}`+"\n")
	gitT(t, seed, "add", "-A")
	gitT(t, seed, "commit", "-m", "base")
	gitT(t, seed, "push", "origin", "main")

	canonical = filepath.Join(root, "canonical")
	gitT(t, root, "clone", origin, canonical)
	return canonical, origin
}

// advanceOrigin lands one commit onto origin/main via a throwaway clone.
func advanceOrigin(t *testing.T, origin string, mutate func(wc string)) {
	t.Helper()
	wc := filepath.Join(t.TempDir(), "adv")
	gitT(t, filepath.Dir(wc), "clone", origin, wc)
	mutate(wc)
	gitT(t, wc, "add", "-A")
	gitT(t, wc, "commit", "-m", "advance")
	gitT(t, wc, "push", "origin", "main")
}

func headOf(t *testing.T, dir, ref string) string { return gitT(t, dir, "rev-parse", ref) }

func TestSyncCanonical_FastForwardCleanBehind(t *testing.T) {
	canonical, origin := setupCanonicalSyncRepos(t)
	advanceOrigin(t, origin, func(wc string) { writeFileT(t, wc, "NEWFILE.md", "new\n") })

	before := headOf(t, canonical, "main")
	syncCanonicalToOrigin(canonical, "main")

	if got, want := headOf(t, canonical, "main"), headOf(t, canonical, "origin/main"); got != want {
		t.Fatalf("main not advanced to origin/main: %s vs %s", got, want)
	}
	if headOf(t, canonical, "main") == before {
		t.Fatalf("main should have advanced from %s", before)
	}
	if _, err := os.Stat(filepath.Join(canonical, "NEWFILE.md")); err != nil {
		t.Fatalf("FF did not bring origin's new file: %v", err)
	}
}

func TestSyncCanonical_UntrackedCollisionSetAside_LocalOnlyPreserved(t *testing.T) {
	canonical, origin := setupCanonicalSyncRepos(t)
	advanceOrigin(t, origin, func(wc string) {
		writeFileT(t, wc, "tasks/task-shared.json", `{"id":"shared","status":"done"}`+"\n")
	})
	// canonical: a STALE untracked copy of the now-landed task, plus a genuinely
	// local-only untracked task that origin has never seen.
	writeFileT(t, canonical, "tasks/task-shared.json", `{"id":"shared","status":"open"}`+"\n")
	writeFileT(t, canonical, "tasks/task-localonly.json", `{"id":"localonly"}`+"\n")

	syncCanonicalToOrigin(canonical, "main")

	if got, want := headOf(t, canonical, "main"), headOf(t, canonical, "origin/main"); got != want {
		t.Fatalf("main not FF'd: %s vs %s", got, want)
	}
	// origin's landed copy won, and it is tracked now.
	if got := readFileT(t, canonical, "tasks/task-shared.json"); !strings.Contains(got, `"done"`) {
		t.Errorf("task-shared.json should be origin's done version, got %q", got)
	}
	if gitT(t, canonical, "ls-files", "tasks/task-shared.json") == "" {
		t.Error("task-shared.json should be tracked after the FF")
	}
	// local-only drift preserved AND still untracked.
	if _, err := os.Stat(filepath.Join(canonical, "tasks/task-localonly.json")); err != nil {
		t.Errorf("local-only task was lost: %v", err)
	}
	if gitT(t, canonical, "ls-files", "--others", "--exclude-standard", "tasks/task-localonly.json") == "" {
		t.Error("local-only task should remain untracked drift")
	}
	// the stale collision was backed up, not deleted.
	wt := os.Getenv("DS_WT_ROOT")
	matches, _ := filepath.Glob(filepath.Join(wt, "ds-canonical-sync-*", "*"))
	if len(matches) == 0 {
		t.Error("expected the set-aside untracked collision to be backed up under DS_WT_ROOT")
	}
}

func TestSyncCanonical_DivergedLocalCommit_Skips(t *testing.T) {
	canonical, origin := setupCanonicalSyncRepos(t)
	advanceOrigin(t, origin, func(wc string) { writeFileT(t, wc, "O.md", "o\n") })
	// a local commit origin does not have → diverged.
	writeFileT(t, canonical, "LOCAL.md", "local\n")
	gitT(t, canonical, "add", "-A")
	gitT(t, canonical, "commit", "-m", "local-only commit")

	before := headOf(t, canonical, "main")
	syncCanonicalToOrigin(canonical, "main")
	if after := headOf(t, canonical, "main"); after != before {
		t.Fatalf("diverged branch must NOT be moved: %s -> %s", before, after)
	}
}

func TestSyncCanonical_ConflictingLocalEdit_Skips(t *testing.T) {
	canonical, origin := setupCanonicalSyncRepos(t)
	advanceOrigin(t, origin, func(wc string) { writeFileT(t, wc, "README.md", "origin-version\n") })
	// uncommitted local edit to a file origin also changed, with DIFFERENT content.
	writeFileT(t, canonical, "README.md", "local-edit\n")

	before := headOf(t, canonical, "main")
	syncCanonicalToOrigin(canonical, "main")
	if after := headOf(t, canonical, "main"); after != before {
		t.Fatalf("conflicting local tracked edit must block the FF: %s -> %s", before, after)
	}
	if got := readFileT(t, canonical, "README.md"); got != "local-edit\n" {
		t.Errorf("local edit must be preserved, got %q", got)
	}
}

func TestSyncCanonical_StaleButLandedEdit_ResetsThenFF(t *testing.T) {
	canonical, origin := setupCanonicalSyncRepos(t)
	advanceOrigin(t, origin, func(wc string) { writeFileT(t, wc, "README.md", "origin-version\n") })
	// uncommitted local edit whose content already EQUALS origin's incoming version
	// (a stale edit that landed via a branch): safe to reset; the FF re-applies it.
	writeFileT(t, canonical, "README.md", "origin-version\n")

	syncCanonicalToOrigin(canonical, "main")
	if got, want := headOf(t, canonical, "main"), headOf(t, canonical, "origin/main"); got != want {
		t.Fatalf("should FF over a stale-but-identical edit: %s vs %s", got, want)
	}
	if got := readFileT(t, canonical, "README.md"); got != "origin-version\n" {
		t.Errorf("README should be origin's version, got %q", got)
	}
}

func TestSyncCanonical_AlreadyCurrent_NoOp(t *testing.T) {
	canonical, _ := setupCanonicalSyncRepos(t)
	before := headOf(t, canonical, "main")
	syncCanonicalToOrigin(canonical, "main") // origin == local
	if after := headOf(t, canonical, "main"); after != before {
		t.Fatalf("no-op expected when already current: %s -> %s", before, after)
	}
}

func TestSyncCanonical_NeverThaws_HooksSuppressed(t *testing.T) {
	canonical, origin := setupCanonicalSyncRepos(t)
	advanceOrigin(t, origin, func(wc string) { writeFileT(t, wc, "X.md", "x\n") })
	// Install a post-merge hook (stand-in for the taskdb thaw). If the sync runs it,
	// the no-thaw guarantee is broken.
	hookDir := filepath.Join(canonical, ".git", "hooks")
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(canonical, "HOOK_RAN")
	if err := os.WriteFile(filepath.Join(hookDir, "post-merge"),
		[]byte("#!/bin/sh\ntouch "+sentinel+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	syncCanonicalToOrigin(canonical, "main")

	if _, err := os.Stat(sentinel); err == nil {
		t.Error("post-merge hook RAN — the live-DB thaw was NOT suppressed")
	}
	if got, want := headOf(t, canonical, "main"), headOf(t, canonical, "origin/main"); got != want {
		t.Fatalf("sync should still FF with hooks suppressed: %s vs %s", got, want)
	}
}
