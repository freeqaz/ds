// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScrubGateEnv pins the gate-env hardening (#14): the DENYLIST drops the SSH
// agent-forwarding handles so an untrusted gate build can't reach the operator's
// ssh-agent, while RETAINING everything the egress-gateway module fetch needs.
// This is deliberately NOT an allowlist (see scrubGateEnv's doc): the build's
// go/cargo must keep PATH/HOME and the proxy/SSL/toolchain env.
func TestScrubGateEnv(t *testing.T) {
	in := []string{
		"SSH_AUTH_SOCK=/tmp/agent.sock",
		"SSH_AGENT_PID=4321",
		"PATH=/usr/bin:/bin",
		"HOME=/home/agent",
		"HTTPS_PROXY=http://127.0.0.1:18080",
		"HTTP_PROXY=http://127.0.0.1:18080",
		"SSL_CERT_FILE=/etc/ssl/egress.pem",
		"GOPROXY=https://proxy.example",
		"GOFLAGS=-mod=mod",
		"CARGO_HOME=/home/agent/.cargo",
		"SSH_AUTH_SOCK_NOT_REALLY=keepme", // a prefix match must NOT be dropped
	}
	got := scrubGateEnv(in)
	gotSet := map[string]bool{}
	for _, kv := range got {
		gotSet[kv] = true
	}

	for _, dropped := range []string{"SSH_AUTH_SOCK=/tmp/agent.sock", "SSH_AGENT_PID=4321"} {
		if gotSet[dropped] {
			t.Errorf("scrubGateEnv did NOT drop %q", dropped)
		}
	}
	mustKeep := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/agent",
		"HTTPS_PROXY=http://127.0.0.1:18080",
		"HTTP_PROXY=http://127.0.0.1:18080",
		"SSL_CERT_FILE=/etc/ssl/egress.pem",
		"GOPROXY=https://proxy.example",
		"GOFLAGS=-mod=mod",
		"CARGO_HOME=/home/agent/.cargo",
		"SSH_AUTH_SOCK_NOT_REALLY=keepme",
	}
	for _, k := range mustKeep {
		if !gotSet[k] {
			t.Errorf("scrubGateEnv dropped %q but should have kept it (denylist, not allowlist)", k)
		}
	}
	// Exactly the two denied vars are removed; nothing else.
	if len(got) != len(in)-2 {
		t.Errorf("scrubGateEnv returned %d vars, want %d (only the 2 SSH handles removed)", len(got), len(in)-2)
	}
}

// TestSweepStaleMergeWorktrees pins the leaked-worktree sweep (#15): orphan
// ds-landq-merge-* dirs from a crashed prior runner are removed, a currently-
// REGISTERED worktree is left alone, and unrelated dirs are untouched.
func TestSweepStaleMergeWorktrees(t *testing.T) {
	repo := gitInitRepo(t)
	// A first commit so `git worktree add --detach HEAD` has something to point at.
	writeFile(t, filepath.Join(repo, "seed.txt"), "seed")
	gitMust(t, repo, "add", "seed.txt")
	gitMust(t, repo, "commit", "-q", "-m", "seed")

	// Point the merge-worktree root at a private temp dir (mergeWorktreeRoot reads
	// DS_WT_ROOT). All ds-landq-merge-* dirs and the live worktree live here.
	root := t.TempDir()
	t.Setenv("DS_WT_ROOT", root)

	// Two ORPHAN merge dirs (a crashed runner's leftovers — plain dirs, not git
	// worktrees), one with a stray file to prove RemoveAll handles a non-empty dir.
	orphanA := filepath.Join(root, mergeWorktreePrefix+"AAAA")
	orphanB := filepath.Join(root, mergeWorktreePrefix+"BBBB")
	mustMkdir(t, orphanA)
	mustMkdir(t, orphanB)
	writeFile(t, filepath.Join(orphanB, "leftover.txt"), "junk")

	// An UNRELATED dir under the same root that must survive (wrong prefix).
	keepDir := filepath.Join(root, "not-a-merge-dir")
	mustMkdir(t, keepDir)

	// A LIVE, currently-registered merge worktree that must survive the sweep.
	live := filepath.Join(root, mergeWorktreePrefix+"LIVE")
	gitMust(t, repo, "worktree", "add", "--detach", live, "HEAD")

	n, err := sweepStaleMergeWorktrees(repo)
	if err != nil {
		t.Fatalf("sweepStaleMergeWorktrees: %v", err)
	}
	if n != 2 {
		t.Errorf("swept %d, want 2 (the two orphan merge dirs)", n)
	}
	if dirExists(orphanA) {
		t.Errorf("orphan %s was NOT removed", orphanA)
	}
	if dirExists(orphanB) {
		t.Errorf("orphan %s was NOT removed", orphanB)
	}
	if !dirExists(live) {
		t.Errorf("LIVE registered worktree %s was wrongly removed", live)
	}
	if !dirExists(keepDir) {
		t.Errorf("unrelated dir %s (wrong prefix) was wrongly removed", keepDir)
	}

	// The live worktree must still be registered with git after the sweep.
	reg, rerr := registeredWorktreePaths(repo)
	if rerr != nil {
		t.Fatalf("registeredWorktreePaths after sweep: %v", rerr)
	}
	if !reg[filepath.Clean(live)] {
		t.Errorf("live worktree %s lost its git registration", live)
	}
}

// TestSweepStaleMergeWorktreesNoRoot: a non-existent root is "no orphans", not an
// error — the sweep must never block landing on a fresh box.
func TestSweepStaleMergeWorktreesNoRoot(t *testing.T) {
	repo := gitInitRepo(t)
	t.Setenv("DS_WT_ROOT", filepath.Join(t.TempDir(), "does-not-exist"))
	n, err := sweepStaleMergeWorktrees(repo)
	if err != nil {
		t.Fatalf("sweepStaleMergeWorktrees on a missing root should be nil error, got %v", err)
	}
	if n != 0 {
		t.Errorf("swept %d on a missing root, want 0", n)
	}
}

// TestIsAncestor pins the idempotent-land predicate (#16): a branch tip that is
// already an ancestor of main reports true (→ short-circuit to 'landed'); a
// divergent branch reports false (→ normal merge/gate/push); a bad ref reports
// false (→ proceed normally, never wrongly skip).
func TestIsAncestor(t *testing.T) {
	repo := gitInitRepo(t)
	writeFile(t, filepath.Join(repo, "f.txt"), "one")
	gitMust(t, repo, "add", "f.txt")
	gitMust(t, repo, "commit", "-q", "-m", "c1")
	c1 := revParse(t, repo, "HEAD")

	// c2 on main, on top of c1.
	writeFile(t, filepath.Join(repo, "f.txt"), "two")
	gitMust(t, repo, "add", "f.txt")
	gitMust(t, repo, "commit", "-q", "-m", "c2")
	c2 := revParse(t, repo, "HEAD")

	// A divergent branch off c1 with its own commit (NOT an ancestor of HEAD/c2).
	gitMust(t, repo, "checkout", "-q", "-b", "feature", c1)
	writeFile(t, filepath.Join(repo, "g.txt"), "feat")
	gitMust(t, repo, "add", "g.txt")
	gitMust(t, repo, "commit", "-q", "-m", "feat")
	feat := revParse(t, repo, "HEAD")

	if !isAncestor(repo, c1, c2) {
		t.Errorf("isAncestor(c1, c2) = false, want true (c1 is an ancestor of c2)")
	}
	if !isAncestor(repo, c2, c2) {
		t.Errorf("isAncestor(c2, c2) = false, want true (a commit is its own ancestor)")
	}
	if isAncestor(repo, feat, c2) {
		t.Errorf("isAncestor(feat, c2) = true, want false (feature diverged from main)")
	}
	if isAncestor(repo, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", c2) {
		t.Errorf("isAncestor(bogus, c2) = true, want false (a bad ref must read as not-ancestor)")
	}
}

// --- small test-only git helpers (default-gate; no Postgres, no lock server) ---

func gitMust(t *testing.T, repo string, args ...string) {
	t.Helper()
	out, err := runGit(repo, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func revParse(t *testing.T, repo, ref string) string {
	t.Helper()
	out, err := runGit(repo, "rev-parse", ref)
	if err != nil {
		t.Fatalf("git rev-parse %s: %v\n%s", ref, err, out)
	}
	return strings.TrimSpace(out)
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
