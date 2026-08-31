// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os/exec"
	"testing"
)

// ensureMergeDriver is the every-invocation self-heal for the tasks/*.json merge
// driver, closing the gap where repoNudge self-healed hooks but NOT the merge
// driver — so a clone (or `git clone --local` worktree) that never ran `taskdb
// setup` silently fell back to line-based conflict markers on concurrent task
// edits. These pin the three branches:
//
//   - unset      → registered, reported mergeInstalled (the fresh-clone case)
//   - already us → no write, mergeAlreadyOurs (steady state is silent)
//   - overridden → left untouched, mergeConflict (respect an operator's choice)

func gitInitRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@example.com"},
		{"config", "user.name", "t"},
	} {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return root
}

func TestEnsureMergeDriverRegistersWhenUnset(t *testing.T) {
	root := gitInitRepo(t)

	if _, set, err := gitConfigGet(root, "merge.taskdb.driver"); err != nil || set {
		t.Fatalf("precondition: driver should be unset (set=%v err=%v)", set, err)
	}

	k, _ := ensureMergeDriver(root)
	if k != mergeInstalled {
		t.Fatalf("first ensure = %v, want mergeInstalled", k)
	}
	got, set, err := gitConfigGet(root, "merge.taskdb.driver")
	if err != nil || !set || got != mergeDriverValue {
		t.Fatalf("driver after install = %q (set=%v err=%v), want %q", got, set, err, mergeDriverValue)
	}
	if name, _, _ := gitConfigGet(root, "merge.taskdb.name"); name != mergeDriverName {
		t.Fatalf("name after install = %q, want %q", name, mergeDriverName)
	}

	// Idempotent + silent in steady state: a second call recognizes its own value.
	if k2, _ := ensureMergeDriver(root); k2 != mergeAlreadyOurs {
		t.Fatalf("second ensure = %v, want mergeAlreadyOurs", k2)
	}
}

func TestEnsureMergeDriverRespectsOverride(t *testing.T) {
	root := gitInitRepo(t)
	custom := "my-own-merge-tool %O %A %B"
	if err := exec.Command("git", "-C", root, "config", "merge.taskdb.driver", custom).Run(); err != nil {
		t.Fatalf("seed override: %v", err)
	}

	k, cur := ensureMergeDriver(root)
	if k != mergeConflict {
		t.Fatalf("ensure over override = %v, want mergeConflict", k)
	}
	if cur != custom {
		t.Fatalf("reported current = %q, want %q", cur, custom)
	}
	// Left untouched.
	if got, _, _ := gitConfigGet(root, "merge.taskdb.driver"); got != custom {
		t.Fatalf("driver was clobbered to %q, want %q", got, custom)
	}
}
