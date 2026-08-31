// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// installHooks self-heals core.hooksPath toward the tracked scripts/hooks dir
// without ever clobbering a deliberate operator override. These pin the
// branches, with focus on the repo-default carve-out (the bug that left
// freeze/thaw silently OFF and refused to repair):
//
//   - unset            → installed
//   - == scripts/hooks → already ours (idempotent)
//   - == repo default  → installed (default path is functionally unset)
//   - custom path      → conflict, left untouched
//   - undetermined     → left untouched, reported softly (transient git failure;
//     hooksPathIsRepoDefault's determined=false must NOT masquerade as a conflict)

func TestInstallHooksInstallsWhenUnset(t *testing.T) {
	root := gitInitRepo(t)
	if st := installHooks(root); st.kind != hookInstalled {
		t.Fatalf("installHooks(unset) = %v, want hookInstalled", st.kind)
	}
	if got, _, _ := gitConfigGet(root, "core.hooksPath"); got != hooksPathValue {
		t.Fatalf("core.hooksPath = %q, want %q", got, hooksPathValue)
	}
	// Idempotent: second call recognizes its own value.
	if st := installHooks(root); st.kind != hookAlreadyOurs {
		t.Fatalf("installHooks(ours) = %v, want hookAlreadyOurs", st.kind)
	}
}

// The regression this fix targets: core.hooksPath pinned to the repo's own
// $GIT_DIR/hooks (absolute OR relative) is functionally unset, so installHooks
// must repoint it rather than mis-report a conflict.
func TestInstallHooksRepointsRepoDefault(t *testing.T) {
	for _, tc := range []struct {
		name string
		// value computes the core.hooksPath to seed, given the repo root.
		value func(root string) string
	}{
		{"absolute", func(root string) string { return filepath.Join(root, ".git", "hooks") }},
		{"relative", func(_ string) string { return ".git/hooks" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := gitInitRepo(t)
			seed := tc.value(root)
			if err := exec.Command("git", "-C", root, "config", "core.hooksPath", seed).Run(); err != nil {
				t.Fatalf("seed core.hooksPath=%q: %v", seed, err)
			}
			if d, ok := hooksPathIsRepoDefault(root, seed); !ok || !d {
				t.Fatalf("hooksPathIsRepoDefault(%q) = (isDefault=%v, determined=%v), want (true, true)", seed, d, ok)
			}
			if st := installHooks(root); st.kind != hookInstalled {
				t.Fatalf("installHooks(repo-default %q) = %v, want hookInstalled", seed, st.kind)
			}
			if got, _, _ := gitConfigGet(root, "core.hooksPath"); got != hooksPathValue {
				t.Fatalf("core.hooksPath after repair = %q, want %q", got, hooksPathValue)
			}
		})
	}
}

// TestHooksPathIsRepoDefaultLinkedWorktree covers the topology that is all over
// a real box but was previously untested: in a LINKED worktree
// `git rev-parse --git-common-dir` returns the ABSOLUTE shared .git (not the
// relative ".git" a standalone repo gives), so the absolute-common-dir branch in
// hooksPathIsRepoDefault must still recognize the shared hooks dir as the default.
func TestHooksPathIsRepoDefaultLinkedWorktree(t *testing.T) {
	main := gitInitRepo(t)
	// `git worktree add` requires a resolvable HEAD.
	mustGit(t, main, "commit", "--allow-empty", "-q", "-m", "init")
	linked := filepath.Join(t.TempDir(), "wt")
	mustGit(t, main, "worktree", "add", "-q", linked, "HEAD")

	common, ok := gitCommonDir(linked)
	if !ok {
		t.Fatal("gitCommonDir(linked worktree) failed")
	}
	if !filepath.IsAbs(common) {
		t.Fatalf("--git-common-dir for a linked worktree = %q, want absolute (else this test wouldn't exercise the abs-path branch)", common)
	}
	shared := filepath.Join(common, "hooks")
	if d, det := hooksPathIsRepoDefault(linked, shared); !det || !d {
		t.Fatalf("hooksPathIsRepoDefault(linked, %q) = (isDefault=%v, determined=%v), want (true, true)", shared, d, det)
	}
	// A genuinely custom path in the linked worktree is still NOT the default.
	if d, det := hooksPathIsRepoDefault(linked, ".husky"); !det {
		t.Fatalf("hooksPathIsRepoDefault(linked, .husky): determined=false, want determined")
	} else if d {
		t.Fatalf("hooksPathIsRepoDefault(linked, .husky) = true, want false (custom)")
	}
}

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestInstallHooksRespectsCustomOverride(t *testing.T) {
	root := gitInitRepo(t)
	custom := ".husky"
	if err := exec.Command("git", "-C", root, "config", "core.hooksPath", custom).Run(); err != nil {
		t.Fatalf("seed override: %v", err)
	}
	if d, ok := hooksPathIsRepoDefault(root, custom); !ok {
		t.Fatalf("hooksPathIsRepoDefault(%q): determined=false, want determined for a working repo", custom)
	} else if d {
		t.Fatalf("hooksPathIsRepoDefault(%q) = true, want false (custom path)", custom)
	}
	st := installHooks(root)
	if st.kind != hookConflict {
		t.Fatalf("installHooks(custom) = %v, want hookConflict", st.kind)
	}
	if st.current != custom {
		t.Fatalf("reported current = %q, want %q", st.current, custom)
	}
	// Left untouched.
	if got, _, _ := gitConfigGet(root, "core.hooksPath"); got != custom {
		t.Fatalf("core.hooksPath was clobbered to %q, want %q", got, custom)
	}
}
