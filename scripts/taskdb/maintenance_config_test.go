// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os/exec"
	"testing"
)

// ensureMaintenanceConfig is the every-invocation self-heal that disables git's
// background maintenance scheduler (the packed-refs.lock racer under concurrent
// linked worktrees, docs/24 §2). These pin: it sets when unset, is idempotent +
// silent once set, and does not churn over an equivalent falsey value.

func gitGet(t *testing.T, root, key string) string {
	t.Helper()
	v, _, err := gitConfigGet(root, key)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	return v
}

func TestEnsureMaintenanceConfigSetsWhenUnset(t *testing.T) {
	root := gitInitRepo(t) // helper from mergedriver_selfheal_test.go

	if _, set, _ := gitConfigGet(root, "maintenance.auto"); set {
		t.Fatalf("precondition: maintenance.auto should be unset")
	}
	if changed := ensureMaintenanceConfig(root); !changed {
		t.Fatalf("first call should report changed=true")
	}
	if got := gitGet(t, root, "maintenance.auto"); got != "false" {
		t.Fatalf("maintenance.auto = %q, want false", got)
	}
	if got := gitGet(t, root, "gc.auto"); got != "0" {
		t.Fatalf("gc.auto = %q, want 0", got)
	}
	// Idempotent + silent in steady state.
	if changed := ensureMaintenanceConfig(root); changed {
		t.Fatalf("second call should report changed=false (steady state)")
	}
}

func TestEnsureMaintenanceConfigNoChurnOnEquivalent(t *testing.T) {
	root := gitInitRepo(t)
	// Operator set a falsey-equivalent / already-zero by hand.
	if err := exec.Command("git", "-C", root, "config", "maintenance.auto", "off").Run(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := exec.Command("git", "-C", root, "config", "gc.auto", "0").Run(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if changed := ensureMaintenanceConfig(root); changed {
		t.Fatalf("'off'/'0' are already-off; should not churn (changed=false)")
	}
	// 'off' must be left untouched (canonical-rewrite would be needless churn).
	if got := gitGet(t, root, "maintenance.auto"); got != "off" {
		t.Fatalf("maintenance.auto churned to %q, want left as off", got)
	}
}

func TestGitIsFalse(t *testing.T) {
	for _, s := range []string{"false", "0", "no", "off", "FALSE", " Off ", ""} {
		if !gitIsFalse(s) {
			t.Errorf("gitIsFalse(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"true", "1", "yes", "on", "auto"} {
		if gitIsFalse(s) {
			t.Errorf("gitIsFalse(%q) = true, want false", s)
		}
	}
}
