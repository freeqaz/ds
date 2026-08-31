// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"testing"
)

// TestResolveSession pins the lock-holder precedence the four holder verbs
// (task lock/unlock/claim/release) share: an explicit --session flag wins, else
// the TASKDB_SESSION env var the wave provisioner exports from the worktree's
// `.taskdb-session` file (scripts/wave_worktree.sh), else EMPTY.
//
// The empty case is the load-bearing one. resolveSession deliberately has NO
// synthetic `cc-<user>-<pid>` fallback (unlike mcpSession in cmd_mcp.go): a
// manufactured identity here would write a lock row that other machines read as
// a real ownership claim by nobody. Resolving to "" is what keeps the callers'
// "session required" errors firing.
//
// t.Setenv scopes every case's env to its own subtest, so nothing leaks between
// cases or out to the rest of the package.
func TestResolveSession(t *testing.T) {
	const envKey = "TASKDB_SESSION"

	cases := []struct {
		name   string
		flag   string
		env    string
		setEnv bool // false => TASKDB_SESSION is genuinely unset for this case
		want   string
	}{
		{
			name:   "flag only",
			flag:   "explicit-session",
			setEnv: false,
			want:   "explicit-session",
		},
		{
			name:   "env only",
			flag:   "",
			env:    "host-wt-wave-key",
			setEnv: true,
			want:   "host-wt-wave-key",
		},
		{
			name:   "flag wins over env",
			flag:   "explicit-session",
			env:    "host-wt-wave-key",
			setEnv: true,
			want:   "explicit-session",
		},
		{
			// No flag, no env => empty, so the caller's "session required"
			// error still fires. Never a manufactured identity.
			name:   "neither set resolves empty",
			flag:   "",
			setEnv: false,
			want:   "",
		},
		{
			// An explicitly-passed `--session ""` is not a value; the env still
			// wins. (Same precedence branch as "env only", asserted through the
			// explicit-empty-flag path callers actually hit.)
			name:   "empty flag falls through to env",
			flag:   "",
			env:    "host-wt-wave-key",
			setEnv: true,
			want:   "host-wt-wave-key",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// t.Setenv first in BOTH arms so the testing package registers the
			// restore-on-cleanup for this subtest; the unset arm then clears it
			// (an empty-but-set var is a different state than an absent one, and
			// the absent one is what a bare CLI invocation actually sees).
			t.Setenv(envKey, c.env)
			if !c.setEnv {
				if err := os.Unsetenv(envKey); err != nil {
					t.Fatalf("unset %s: %v", envKey, err)
				}
			}
			if got := resolveSession(c.flag); got != c.want {
				t.Fatalf("resolveSession(%q) with %s=%q (set=%v) = %q, want %q",
					c.flag, envKey, c.env, c.setEnv, got, c.want)
			}
		})
	}
}

// TestResolveSessionNoSyntheticFallback is the explicit anti-regression guard
// for the safety property: with neither flag nor env, resolveSession must not
// invent a `cc-<user>-<pid>`-style identity the way mcpSession does. Anything
// non-empty here would be a false lock claim.
func TestResolveSessionNoSyntheticFallback(t *testing.T) {
	t.Setenv("TASKDB_SESSION", "")
	if err := os.Unsetenv("TASKDB_SESSION"); err != nil {
		t.Fatalf("unset TASKDB_SESSION: %v", err)
	}
	if got := resolveSession(""); got != "" {
		t.Fatalf("resolveSession(\"\") with TASKDB_SESSION unset = %q, want \"\" (no synthetic fallback)", got)
	}
}
