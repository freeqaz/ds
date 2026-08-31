// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
)

// TestLockserverReap_SessionFlagWired proves `lockserver reap --session <id>` is
// a recognized flag (it parses cleanly and reaches the lock-server step) rather
// than being rejected as an unknown flag. With locks disabled it stops at
// mustLockServer with the "disabled" error — which is exactly the path a
// no-tunnel wave-boundary reap takes — proving the wiring without needing a live
// Postgres. The exact-match DELETE itself is exercised end-to-end against the
// live shared server (see the safe-session-reap spec).
func TestLockserverReap_SessionFlagWired(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	err := lockserverReap(nil, []string{"--session", "host-wt-wave9-keyA"})
	if err == nil {
		t.Fatal("expected an error (lock server disabled), got nil")
	}
	if strings.Contains(err.Error(), "flag provided but not defined") ||
		strings.Contains(err.Error(), "unknown") {
		t.Fatalf("--session was not wired into lockserver reap: %v", err)
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected the disabled-lock-server error (the wave-boundary no-tunnel path), got: %v", err)
	}
}

// TestLockserverReap_RejectsUnknownFlag is the footgun guard: a typo'd flag is
// still rejected, so the new --session does not loosen flag validation.
func TestLockserverReap_RejectsUnknownFlag(t *testing.T) {
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	if err := lockserverReap(nil, []string{"--bogus"}); err == nil {
		t.Fatal("expected an error for an unknown flag, got nil")
	}
}
