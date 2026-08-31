// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/e2e"
)

// TestRunDispatch covers the bare dispatcher: usage, unknown command, help.
// (It must not invoke `claude`/`drive`, which would launch a gateway.)
func TestRunDispatch(t *testing.T) {
	if got := run(nil); got != 2 {
		t.Errorf("run(nil) = %d, want 2 (usage)", got)
	}
	if got := run([]string{"bogus"}); got != 2 {
		t.Errorf("run(unknown) = %d, want 2", got)
	}
	if got := run([]string{"help"}); got != 0 {
		t.Errorf("run(help) = %d, want 0", got)
	}
}

// TestDriveGateUnsetLaunchesNothing is the safety contract for the gated tier:
// with DS_E2E_LIVE unset, `serpent drive` refuses (exit 1) BEFORE resolving
// ds-capture or launching any gateway/container.
func TestDriveGateUnsetLaunchesNothing(t *testing.T) {
	t.Setenv(e2e.LiveGateEnv, "") // disarmed
	if got := cmdDrive([]string{"--prompt", "hi"}); got != 1 {
		t.Errorf("cmdDrive gate-unset = %d, want 1 (friendly refusal, no launch)", got)
	}
}

// TestRefusesProtectedPort: an explicit --port 18080 is rejected before anything
// is launched, on BOTH subcommands (the port guard precedes resolution/launch).
func TestRefusesProtectedPort(t *testing.T) {
	if got := cmdClaude([]string{"--port", "18080"}); got != 2 {
		t.Errorf("cmdClaude --port 18080 = %d, want 2 (refuses the protected monitor)", got)
	}
	t.Setenv(e2e.LiveGateEnv, "1")
	if got := cmdDrive([]string{"--port", "18080"}); got != 2 {
		t.Errorf("cmdDrive --port 18080 = %d, want 2 (refuses the protected monitor)", got)
	}
}

// TestResolveCaptureBin: an explicit executable is returned; a non-executable
// path is a clear error.
func TestResolveCaptureBin(t *testing.T) {
	dir := t.TempDir()
	nonExec := filepath.Join(dir, "notexec")
	if err := os.WriteFile(nonExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCaptureBin(nonExec); err == nil {
		t.Error("a non-executable --capture-bin should error")
	}
	exe := filepath.Join(dir, "ds-capture")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveCaptureBin(exe); err != nil || got != exe {
		t.Errorf("resolveCaptureBin(%q) = %q, %v; want it returned", exe, got, err)
	}
}

// TestResolveSerpentTuiBin mirrors TestResolveCaptureBin: an explicit executable
// is returned; a non-executable explicit path is a clear error; $DS_SERPENT_TUI_BIN
// is the env fallback; and a bogus name with nothing on PATH / no sibling errors.
func TestResolveSerpentTuiBin(t *testing.T) {
	dir := t.TempDir()

	// non-executable explicit path → error
	nonExec := filepath.Join(dir, "notexec")
	if err := os.WriteFile(nonExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSerpentTuiBin(nonExec); err == nil {
		t.Error("a non-executable explicit serpent-tui bin should error")
	}

	// explicit executable → returned verbatim
	exe := filepath.Join(dir, "serpent-tui")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveSerpentTuiBin(exe); err != nil || got != exe {
		t.Errorf("resolveSerpentTuiBin(%q) = %q, %v; want it returned", exe, got, err)
	}

	// env fallback ($DS_SERPENT_TUI_BIN) when no explicit value is given
	envExe := filepath.Join(t.TempDir(), "serpent-tui")
	if err := os.WriteFile(envExe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DS_SERPENT_TUI_BIN", envExe)
	if got, err := resolveSerpentTuiBin(""); err != nil || got != envExe {
		t.Errorf("resolveSerpentTuiBin via env = %q, %v; want %q", got, err, envExe)
	}

	// nothing resolvable → error. Clear the env and ensure no serpent-tui on PATH
	// (point PATH at an empty dir; os.Executable's sibling won't be a serpent-tui).
	t.Setenv("DS_SERPENT_TUI_BIN", "")
	t.Setenv("PATH", t.TempDir())
	if _, err := resolveSerpentTuiBin(""); err == nil {
		t.Error("resolveSerpentTuiBin should error when nothing is resolvable")
	}
}

// TestPeelSerpentTuiBin: a leading --serpent-tui-bin (spaced or =) is consumed by
// serpent and the rest is forwarded; without it, all args forward verbatim.
func TestPeelSerpentTuiBin(t *testing.T) {
	cases := []struct {
		name     string
		in       []string
		wantBin  string
		wantRest []string
	}{
		{"none", []string{"--orchestrator", "x:1"}, "", []string{"--orchestrator", "x:1"}},
		{"spaced", []string{"--serpent-tui-bin", "/b/st", "--repo", "r"}, "/b/st", []string{"--repo", "r"}},
		{"equals", []string{"--serpent-tui-bin=/b/st", "--repo", "r"}, "/b/st", []string{"--repo", "r"}},
		{"empty", nil, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, rest := peelSerpentTuiBin(tc.in)
			if bin != tc.wantBin {
				t.Errorf("bin = %q, want %q", bin, tc.wantBin)
			}
			if len(rest) != len(tc.wantRest) {
				t.Fatalf("rest = %v, want %v", rest, tc.wantRest)
			}
			for i := range rest {
				if rest[i] != tc.wantRest[i] {
					t.Errorf("rest[%d] = %q, want %q", i, rest[i], tc.wantRest[i])
				}
			}
		})
	}
}

// TestUpRefusesWithoutBin: `serpent up` with no resolvable serpent-tui binary
// refuses cleanly (exit 1) and execs nothing. PATH is pointed at an empty dir and
// the env override cleared so resolution fails deterministically.
func TestUpRefusesWithoutBin(t *testing.T) {
	t.Setenv("DS_SERPENT_TUI_BIN", "")
	t.Setenv("PATH", t.TempDir())
	if got := cmdUp([]string{"--orchestrator", "x:1", "--repo", "r"}); got != 1 {
		t.Errorf("cmdUp with no serpent-tui bin = %d, want 1 (clean refusal, no exec)", got)
	}
}

// TestUpDispatchExecsSibling: a fake serpent-tui records its argv; `serpent up`
// resolves it (explicit --serpent-tui-bin) and EXECs it with `up` + the forwarded
// flags, surfacing its exit code. No live orchestrator/VM — the fake just writes
// its args and exits 0.
func TestUpDispatchExecsSibling(t *testing.T) {
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	// The fake prints all args (after $0) one per line into argvFile, then exits 0.
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	if got := cmdUp([]string{"--serpent-tui-bin", fake, "--orchestrator", "x:1", "--repo", "r", "--env-config-ref", "e"}); got != 0 {
		t.Fatalf("cmdUp dispatch = %d, want 0", got)
	}
	got, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "up\n--orchestrator\nx:1\n--repo\nr\n--env-config-ref\ne\n"
	if string(got) != want {
		t.Errorf("serpent-tui argv =\n%q\nwant\n%q", string(got), want)
	}
}

// TestUpForwardsChildExitCode: serpent surfaces the serpent-tui child's exit code.
func TestUpForwardsChildExitCode(t *testing.T) {
	fake := fakeSerpentTuiBin(t, "exit 7\n")
	if got := cmdUp([]string{"--serpent-tui-bin", fake, "--repo", "r"}); got != 7 {
		t.Errorf("cmdUp child-exit passthrough = %d, want 7", got)
	}
}

// TestClaudeVMDispatchExecsSerpentTui: `serpent claude --vm` resolves serpent-tui
// (explicit --serpent-tui-bin) and EXECs it with `up` + the forwarded provisioning
// flags, surfacing its exit code — mirroring TestUpDispatchExecsSibling. No live
// orchestrator/VM; the fake records its argv and exits 0. This proves the everyday
// command can hit the running orchestrator (the VM-backed interactive path).
func TestClaudeVMDispatchExecsSerpentTui(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "") // ensure the env trigger is not what routes us
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	got := cmdClaude([]string{
		"--vm", "--serpent-tui-bin", fake,
		"--orchestrator", "x:1", "--repo", "r", "--env-config-ref", "e", "--launching-user", "u",
	})
	if got != 0 {
		t.Fatalf("cmdClaude --vm dispatch = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "up\n--orchestrator\nx:1\n--repo\nr\n--env-config-ref\ne\n--launching-user\nu\n"
	if string(out) != want {
		t.Errorf("serpent-tui argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestClaudeVMEnvTriggerExecsSerpentTui: DS_ORCHESTRATOR set (without --vm) ALSO
// routes `serpent claude` into the VM path, taking the orchestrator endpoint from the
// env when --orchestrator is not given.
func TestClaudeVMEnvTriggerExecsSerpentTui(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "env-host:9090")
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	if got := cmdClaude([]string{"--serpent-tui-bin", fake, "--repo", "r", "--env-config-ref", "e", "--launching-user", "u"}); got != 0 {
		t.Fatalf("cmdClaude env-trigger dispatch = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "up\n--orchestrator\nenv-host:9090\n--repo\nr\n--env-config-ref\ne\n--launching-user\nu\n"
	if string(out) != want {
		t.Errorf("serpent-tui argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestClaudeVMAttachSession: `serpent claude --vm --session S` attaches to an existing
// session (EXECs serpent-tui attach) instead of provisioning a new one with up.
func TestClaudeVMAttachSession(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	if got := cmdClaude([]string{"--vm", "--serpent-tui-bin", fake, "--orchestrator", "x:1", "--session", "sess-123"}); got != 0 {
		t.Fatalf("cmdClaude --vm --session dispatch = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "attach\n--orchestrator\nx:1\n--session\nsess-123\n"
	if string(out) != want {
		t.Errorf("serpent-tui argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestClaudeVMForwardsRawFlagsToUp: --raw/--detach-key/--no-alt-screen set on
// `serpent claude --vm` (the provision path) are forwarded verbatim to
// `serpent-tui up` (a stdlib relay; the surface decision lives in serpent-tui,
// D80). The raw tail comes AFTER the provisioning flags.
func TestClaudeVMForwardsRawFlagsToUp(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	got := cmdClaude([]string{
		"--vm", "--serpent-tui-bin", fake,
		"--orchestrator", "x:1", "--repo", "r", "--env-config-ref", "e", "--launching-user", "u",
		"--raw", "on", "--detach-key", "ctrl-^", "--no-alt-screen",
	})
	if got != 0 {
		t.Fatalf("cmdClaude --vm with raw flags = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "up\n--orchestrator\nx:1\n--repo\nr\n--env-config-ref\ne\n--launching-user\nu\n--raw\non\n--detach-key\nctrl-^\n--no-alt-screen\n"
	if string(out) != want {
		t.Errorf("serpent-tui up argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestClaudeVMForwardsRawFlagsToAttach: the raw flags are forwarded to
// `serpent-tui attach` on the --session path too.
func TestClaudeVMForwardsRawFlagsToAttach(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	got := cmdClaude([]string{
		"--vm", "--serpent-tui-bin", fake, "--orchestrator", "x:1", "--session", "sess-123",
		"--raw", "off",
	})
	if got != 0 {
		t.Fatalf("cmdClaude --vm --session with raw = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "attach\n--orchestrator\nx:1\n--session\nsess-123\n--raw\noff\n"
	if string(out) != want {
		t.Errorf("serpent-tui attach argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestClaudeVMUnsetRawFlagsForwardNothing: with no raw flags set, the --vm argv is
// byte-identical to today — the raw passthrough adds NOTHING (so the default UX is
// unchanged, the no-op-by-default property at the serpent layer).
func TestClaudeVMUnsetRawFlagsForwardNothing(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	if got := cmdClaude([]string{"--vm", "--serpent-tui-bin", fake, "--orchestrator", "x:1", "--repo", "r", "--env-config-ref", "e", "--launching-user", "u"}); got != 0 {
		t.Fatalf("cmdClaude --vm = %d, want 0", got)
	}
	out, _ := os.ReadFile(argvFile)
	want := "up\n--orchestrator\nx:1\n--repo\nr\n--env-config-ref\ne\n--launching-user\nu\n"
	if string(out) != want {
		t.Errorf("serpent-tui argv with no raw flags =\n%q\nwant\n%q (no raw tail)", string(out), want)
	}
}

// TestRawPassthrough: only the set flags are forwarded; empty strings / false
// forward nothing (so serpent-tui keeps its own defaults).
func TestRawPassthrough(t *testing.T) {
	cases := []struct {
		name        string
		rawMode     string
		detachKey   string
		noAltScreen bool
		want        []string
	}{
		{"none", "", "", false, nil},
		{"raw only", "on", "", false, []string{"--raw", "on"}},
		{"detach only", "", "ctrl-]", false, []string{"--detach-key", "ctrl-]"}},
		{"alt only", "", "", true, []string{"--no-alt-screen"}},
		{"all", "auto", "^x", true, []string{"--raw", "auto", "--detach-key", "^x", "--no-alt-screen"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rawPassthrough(c.rawMode, c.detachKey, c.noAltScreen)
			if len(got) != len(c.want) {
				t.Fatalf("rawPassthrough(%q,%q,%v) = %v, want %v", c.rawMode, c.detachKey, c.noAltScreen, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("rawPassthrough[%d] = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestClaudeVMForwardsRmToUp: --rm set on `serpent claude --vm` (the provision
// path) is forwarded to `serpent-tui up --rm` so the provisioned session is
// destroyed on exit. --rm rides BEFORE the raw tail and AFTER the provisioning
// flags (the same ordering as --raw), and is a bare flag (no value).
func TestClaudeVMForwardsRmToUp(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	got := cmdClaude([]string{
		"--vm", "--serpent-tui-bin", fake,
		"--orchestrator", "x:1", "--repo", "r", "--env-config-ref", "e", "--launching-user", "u", "--rm",
	})
	if got != 0 {
		t.Fatalf("cmdClaude --vm --rm = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "up\n--orchestrator\nx:1\n--repo\nr\n--env-config-ref\ne\n--launching-user\nu\n--rm\n"
	if string(out) != want {
		t.Errorf("serpent-tui up argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestClaudeVMRmWithRawFlags: --rm and the raw flags compose — --rm comes first
// (it is part of the provisioning argv), then the raw passthrough tail.
func TestClaudeVMRmWithRawFlags(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	got := cmdClaude([]string{
		"--vm", "--serpent-tui-bin", fake,
		"--orchestrator", "x:1", "--repo", "r", "--env-config-ref", "e", "--launching-user", "u",
		"--rm", "--raw", "on",
	})
	if got != 0 {
		t.Fatalf("cmdClaude --vm --rm --raw on = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "up\n--orchestrator\nx:1\n--repo\nr\n--env-config-ref\ne\n--launching-user\nu\n--rm\n--raw\non\n"
	if string(out) != want {
		t.Errorf("serpent-tui up argv =\n%q\nwant\n%q", string(out), want)
	}
}

// TestClaudeVMRmNotForwardedToAttach: --rm is IGNORED on the --session attach path
// (serpent did not provision that session, so it must never reap it). The forwarded
// attach argv carries NO --rm.
func TestClaudeVMRmNotForwardedToAttach(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	got := cmdClaude([]string{
		"--vm", "--serpent-tui-bin", fake, "--orchestrator", "x:1", "--session", "sess-123", "--rm",
	})
	if got != 0 {
		t.Fatalf("cmdClaude --vm --session --rm = %d, want 0", got)
	}
	out, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	want := "attach\n--orchestrator\nx:1\n--session\nsess-123\n"
	if string(out) != want {
		t.Errorf("serpent-tui attach argv =\n%q\nwant\n%q (no --rm on the attach path)", string(out), want)
	}
}

// TestClaudeVMNoRmForwardsNothing: without --rm the up argv carries no --rm — the
// default persist behavior (D61) is forwarded unchanged.
func TestClaudeVMNoRmForwardsNothing(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	fake := fakeSerpentTuiBin(t, "printf '%s\\n' \"$@\" > "+argvFile+"\nexit 0\n")

	if got := cmdClaude([]string{"--vm", "--serpent-tui-bin", fake, "--orchestrator", "x:1", "--repo", "r", "--env-config-ref", "e", "--launching-user", "u"}); got != 0 {
		t.Fatalf("cmdClaude --vm (no --rm) = %d, want 0", got)
	}
	out, _ := os.ReadFile(argvFile)
	want := "up\n--orchestrator\nx:1\n--repo\nr\n--env-config-ref\ne\n--launching-user\nu\n"
	if string(out) != want {
		t.Errorf("serpent-tui argv without --rm =\n%q\nwant\n%q (no --rm tail)", string(out), want)
	}
}

// TestClaudeVMForwardsChildExitCode: the --vm branch surfaces the serpent-tui child's
// exit code (the same passthrough cmdUp guarantees).
func TestClaudeVMForwardsChildExitCode(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	fake := fakeSerpentTuiBin(t, "exit 7\n")
	if got := cmdClaude([]string{"--vm", "--serpent-tui-bin", fake, "--repo", "r"}); got != 7 {
		t.Errorf("cmdClaude --vm child-exit passthrough = %d, want 7", got)
	}
}

// TestClaudeNoVMNoEnvStaysLocal: with neither --vm nor DS_ORCHESTRATOR, cmdClaude does
// NOT take the serpent-tui VM path. We prove this by pointing serpent-tui resolution at
// nothing (empty PATH, no env, no sibling) AND giving an unresolvable ds-capture bin:
// the local-CC path is taken, which fails at ds-capture resolution (exit 1) rather than
// dispatching to serpent-tui — and crucially never resolves/execs serpent-tui. (A VM
// dispatch would have errored on the serpent-tui bin instead.) This keeps the default
// local-CC path intact.
func TestClaudeNoVMNoEnvStaysLocal(t *testing.T) {
	t.Setenv("DS_ORCHESTRATOR", "")
	t.Setenv("DS_SERPENT_TUI_BIN", "")
	t.Setenv("DS_CAPTURE_BIN", "")
	t.Setenv("PATH", t.TempDir()) // nothing resolvable on PATH
	// No --vm, no DS_ORCHESTRATOR ⇒ local-CC branch. ds-capture is unresolvable ⇒ exit 1,
	// and serpent-tui is never consulted (proving we did NOT take the VM path).
	if got := cmdClaude([]string{"--capture-bin", "/definitely/not/here/ds-capture"}); got != 1 {
		t.Errorf("cmdClaude default (no --vm/env) = %d, want 1 (local-CC path, ds-capture unresolved)", got)
	}
}

// fakeSerpentTuiBin writes an executable shell script standing in for serpent-tui
// and returns its path. body is the script body after the shebang.
func fakeSerpentTuiBin(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "serpent-tui")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestResolveClaudeBin: an explicit executable path is returned; a bogus name
// that is neither a path nor on PATH errors.
func TestResolveClaudeBin(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "claude")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveClaudeBin(exe); err != nil || got != exe {
		t.Errorf("resolveClaudeBin(%q) = %q, %v; want it returned", exe, got, err)
	}
	if _, err := resolveClaudeBin("definitely-not-a-real-binary-xyzzy"); err == nil {
		t.Error("a bogus claude binary name should error")
	}
}

// TestFreePort returns a usable, non-protected loopback port.
func TestFreePort(t *testing.T) {
	p, err := freePort()
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	if p <= 0 || p == protectedMonitorPort {
		t.Errorf("freePort = %d, want a free port that is not :%d", p, protectedMonitorPort)
	}
}

// fakeCaptureBin writes an executable shell script standing in for ds-capture and
// returns its path. body is the script body after the shebang.
func fakeCaptureBin(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ds-capture")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSetupGatewayEarlyExit is the regression for the gateway-lifecycle race: a
// gateway child that exits IMMEDIATELY (e.g. the port was already bound) must
// make setupGateway return an error PROMPTLY — waitReady drains the child's exit
// off done, and the error-path stop() must not then deadlock waiting for a value
// that waitReady already consumed. A regression here manifests as a hang, so we
// bound it with a timeout and fail if it does not return in time.
func TestSetupGatewayEarlyExit(t *testing.T) {
	bin := fakeCaptureBin(t, "exit 1\n") // exits before binding the port / writing the CA
	done := make(chan error, 1)
	go func() {
		_, _, err := setupGateway(bin, 0, "", false)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("setupGateway with an early-exiting gateway should return an error")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("setupGateway did not return for an early-exiting gateway — the stop()/waitReady done-channel race regressed (deadlock)")
	}
}

// TestGatewayStopIdempotent: stop() may be called more than once (the defer
// cleanup path and the error paths can overlap) and after the child has already
// exited; it must not panic, double-close, or block.
func TestGatewayStopIdempotent(t *testing.T) {
	bin := fakeCaptureBin(t, "exit 0\n")
	logPath := filepath.Join(t.TempDir(), "gw.log")
	g, err := startGateway(bin, 0, "cassette", "ca", logPath)
	if err != nil {
		t.Fatalf("startGateway: %v", err)
	}
	done := make(chan struct{})
	go func() {
		g.stop()
		g.stop() // second call must be a no-op, not a hang/panic.
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("gateway.stop() blocked — idempotency regressed")
	}
}
