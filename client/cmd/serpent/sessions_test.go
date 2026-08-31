// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSessionsListExecsSerpentTui: `serpent sessions list --orchestrator A` resolves the
// serpent-tui sibling (explicit --serpent-tui-bin) and EXECs it with `sessions list` + the
// forwarded --orchestrator. A fake serpent-tui (the stand-in dial site — it is the "fake
// client") records its argv and exits 0, proving the dispatcher hits the orchestrator's
// ListSessions read leg through the D80 grpc seam without any grpc in this stdlib module.
func TestSessionsListExecsSerpentTui(t *testing.T) {
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	if got := cmdSessions([]string{"list", "--serpent-tui-bin", fake, "--orchestrator", "x:1"}); got != 0 {
		t.Fatalf("cmdSessions list = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "sessions\nlist\n--orchestrator\nx:1\n"
	if string(out) != want {
		t.Errorf("serpent-tui argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestSessionsListForwardsLimitAndAll: `serpent sessions list --limit N --all` forwards BOTH
// paging flags verbatim through the D80 EXEC seam to `serpent-tui sessions list … --limit N --all`
// (serpent-tui owns their parse; this stdlib wrapper neither interprets nor reorders them). The
// fake records the argv carrying --limit/--all in order, proving the passthrough.
func TestSessionsListForwardsLimitAndAll(t *testing.T) {
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	if got := cmdSessions([]string{"list", "--serpent-tui-bin", fake, "--orchestrator", "x:1", "--limit", "5", "--all"}); got != 0 {
		t.Fatalf("cmdSessions list --limit 5 --all = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "sessions\nlist\n--orchestrator\nx:1\n--limit\n5\n--all\n"
	if string(out) != want {
		t.Errorf("serpent-tui argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestSessionsListNoFlagDefaultArgvUnchanged: a bare `serpent sessions list` (no --limit/--all,
// only the peeled --serpent-tui-bin) forwards exactly `sessions list` — the wrapper injects
// nothing on the default path, so adding the paging flags above did not perturb the no-flag argv.
func TestSessionsListNoFlagDefaultArgvUnchanged(t *testing.T) {
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	if got := cmdSessions([]string{"list", "--serpent-tui-bin", fake}); got != 0 {
		t.Fatalf("cmdSessions list (no flags) = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "sessions\nlist\n"
	if string(out) != want {
		t.Errorf("serpent-tui default argv =\n%q\nwant\n%q (no-flag path must be unchanged)", string(out), want)
	}
}

// TestSessionsDestroyExecsSerpentTuiWithUUID: `serpent sessions destroy <uuid>` forwards the
// uuid (and --orchestrator) to `serpent-tui sessions destroy <uuid>` — i.e. the dispatcher
// drives DestroySession(uuid). The fake records the argv carrying the exact uuid.
func TestSessionsDestroyExecsSerpentTuiWithUUID(t *testing.T) {
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	if got := cmdSessions([]string{"destroy", "--serpent-tui-bin", fake, "sess-abc123", "--orchestrator", "x:1"}); got != 0 {
		t.Fatalf("cmdSessions destroy = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "sessions\ndestroy\nsess-abc123\n--orchestrator\nx:1\n"
	if string(out) != want {
		t.Errorf("serpent-tui argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestSessionsForwardsChildExitCode: the dispatcher surfaces the serpent-tui child's exit code
// (so a failed DestroySession / ListSessions propagates), mirroring the up/claude dispatchers.
func TestSessionsForwardsChildExitCode(t *testing.T) {
	fake := fakeSerpentTuiBin(t, "exit 7\n")
	if got := cmdSessions([]string{"destroy", "--serpent-tui-bin", fake, "sess-x"}); got != 7 {
		t.Fatalf("cmdSessions destroy exit = %d, want 7 (child exit surfaced)", got)
	}
}

// TestSessionsUnknownSubcommand: a verb that is neither list nor destroy is a usage error (2),
// without EXEC-ing serpent-tui.
func TestSessionsUnknownSubcommand(t *testing.T) {
	if got := cmdSessions([]string{"frobnicate"}); got != 2 {
		t.Errorf("cmdSessions frobnicate = %d, want 2 (usage error)", got)
	}
}

// TestSessionsNoSubcommand: a bare `serpent sessions` prints usage and returns 2.
func TestSessionsNoSubcommand(t *testing.T) {
	if got := cmdSessions(nil); got != 2 {
		t.Errorf("cmdSessions (no args) = %d, want 2 (usage)", got)
	}
}

// TestSessionsHelp: `serpent sessions -h` prints usage and returns 0 (a help request, not an
// error), without EXEC-ing serpent-tui.
func TestSessionsHelp(t *testing.T) {
	for _, h := range []string{"-h", "--help", "help"} {
		if got := cmdSessions([]string{h}); got != 0 {
			t.Errorf("cmdSessions %q = %d, want 0", h, got)
		}
	}
}

// TestSessionsRefusesWithoutBin: with no resolvable serpent-tui (no explicit bin, env cleared,
// empty PATH), a valid verb fails (1) with the resolution error rather than EXEC-ing nothing.
func TestSessionsRefusesWithoutBin(t *testing.T) {
	t.Setenv("DS_SERPENT_TUI_BIN", "")
	t.Setenv("PATH", t.TempDir())
	if got := cmdSessions([]string{"list", "--orchestrator", "x:1"}); got != 1 {
		t.Errorf("cmdSessions list with no serpent-tui = %d, want 1 (resolution error)", got)
	}
}

// TestSessionsRouting: `serpent sessions …` is routed by the top-level dispatcher to
// cmdSessions (an unknown serpent-tui resolution → exit 1 proves the route reached cmdSessions
// rather than the unknown-command path, which would be exit 2 with a different message).
func TestSessionsRouting(t *testing.T) {
	t.Setenv("DS_SERPENT_TUI_BIN", "")
	t.Setenv("PATH", t.TempDir())
	if got := run([]string{"sessions", "list"}); got != 1 {
		t.Errorf("run([sessions list]) = %d, want 1 (routed to cmdSessions, serpent-tui unresolved)", got)
	}
}
