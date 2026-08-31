// SPDX-License-Identifier: Apache-2.0

// Package hostbringup_test is a host-safe smoke check over stack-up.sh: it runs
// the script's DEFAULT (--dry-run) mode and asserts it prints every ordered
// STEP marker without executing anything, and that live mode is ALWAYS refused
// with a nonzero exit.
//
// The live refusal is no longer a ratification hold (D148 ratified the wiring
// 2026-07-30) — it is a SEPARATION-OF-CONCERNS rule: this script is the
// reviewable narrative of the privileged posture, while applying it belongs to
// install-ds-nethelper.sh (install + setcap + verify) and
// scripts/host-bringup/stack-up-host.sh (the real bring-up). Two copies of the
// install posture is exactly the drift this refusal prevents.
//
// It shells out to `bash stack-up.sh` — no host mutation (dry-run runs nothing;
// live mode is refused before any privileged step). Skips cleanly if bash is
// unavailable.
package hostbringup_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scriptPath resolves stack-up.sh relative to this test file's directory.
func scriptPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	p := filepath.Join(wd, "stack-up.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("stack-up.sh not found at %s: %v", p, err)
	}
	return p
}

// runScript runs `bash <script> [args...]` with the given extra env, returning
// combined stdout, stderr, and the process exit code.
func runScript(t *testing.T, script string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var so, se strings.Builder
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()
	code = 0
	if err != nil {
		var ee *exec.ExitError
		if ok := asExit(err, &ee); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return so.String(), se.String(), code
}

// asExit narrows err to *exec.ExitError without importing errors in the caller.
func asExit(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func TestDryRunExitsZeroAndEmitsEveryStep(t *testing.T) {
	script := scriptPath(t)

	tests := []struct {
		name string
		args []string
	}{
		{name: "default (no arg) is dry-run", args: nil},
		{name: "explicit --dry-run", args: []string{"--dry-run"}},
	}

	// The stack-up narrative has exactly 8 ordered steps (the six build/install/
	// probe steps + the per-session CREATE step + the teardown-trio step); every
	// one must print, in order.
	wantMarkers := []string{
		"STEP 1: build the ds-nft privileged staticlib",
		"STEP 2: build ds-nethelper WITH the privileged backend",
		"STEP 3: build host-agent WITHOUT the tag",
		"STEP 4: install the helper 0750 root:",
		"STEP 5: setcap the helper — cap_net_admin+eip",
		"STEP 6: probe the installed helper",
		"STEP 7: per-session CREATE ops",
		"STEP 8: per-session ROLLBACK/TEARDOWN trio",
	}
	// Load-bearing content the dry run MUST render for the gate review. Each
	// helper invocation ends in "<verb>\n" (argv is [verb] only), so match the
	// verb followed by newline rather than surrounding spaces.
	wantContent := []string{
		"cargo build -p ds-nft --release",
		"go build -tags nftgatelive",
		"setcap cap_net_admin+eip", // +eip, NOT +ep
		"+eip, NOT +ep",
		"PR_CAP_AMBIENT_RAISE",
		// The probe step must render the THREE-field posture (the +ep-only
		// half-configuration is distinguishable) and the Ready predicate — not
		// only the legacy coarse cap_net_admin alias.
		`"cap_net_admin_effective":true`,
		`"ambient_raise_ok":true`,
		"ProbeReady",
		"ds-nethelper probe\n",
		"ds-nethelper create-tap\n",
		"ds-nethelper instantiate-session\n",
		"ds-nethelper flush-session\n",
		"ds-nethelper teardown-session\n",
		"ds-nethelper delete-tap\n",
		"0 executed", // proves nothing ran
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runScript(t, script, nil, tc.args...)
			if code != 0 {
				t.Fatalf("dry-run exit=%d, want 0\nstderr:\n%s", code, stderr)
			}
			for _, m := range wantMarkers {
				if !strings.Contains(stdout, m) {
					t.Errorf("dry-run output missing step marker %q\n---\n%s", m, stdout)
				}
			}
			for _, c := range wantContent {
				if !strings.Contains(stdout, c) {
					t.Errorf("dry-run output missing required content %q", c)
				}
			}
			// A dry run must NOT emit any host-mutating command prefixed as
			// actually-run; we assert the guard line is present instead.
			if !strings.Contains(stdout, "nothing below is executed") {
				t.Errorf("dry-run missing the 'nothing executed' banner")
			}
		})
	}
}

func TestLiveModeRefusedNonzero(t *testing.T) {
	script := scriptPath(t)

	tests := []struct {
		name string
		env  []string
		args []string
	}{
		{name: "live without DS_NETHELPER_APPLY", env: nil, args: []string{"live"}},
		{name: "live WITH DS_NETHELPER_APPLY still refused (that env arms install-ds-nethelper.sh, never this script)", env: []string{"DS_NETHELPER_APPLY=1"}, args: []string{"live"}},
		{name: "--apply alias refused", env: nil, args: []string{"--apply"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runScript(t, script, tc.env, tc.args...)
			if code == 0 {
				t.Fatalf("live mode exited 0, want nonzero (must refuse)\nstdout:\n%s", stdout)
			}
			if !strings.Contains(stderr, "REFUSING live bring-up") {
				t.Errorf("live refusal missing the REFUSING banner\nstderr:\n%s", stderr)
			}
			// The refusal must state the CURRENT reason (D148 is ratified; this
			// script is the narrative, not the apply tool) and REDIRECT the
			// operator to the two scripts that do apply it — otherwise a reader
			// concludes the live wiring is still unratified.
			if !strings.Contains(stderr, "D148") {
				t.Errorf("live refusal must cite D148 (the ratified wiring), not a deferred gate\nstderr:\n%s", stderr)
			}
			for _, want := range []string{"install-ds-nethelper.sh", "stack-up-host.sh"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("live refusal must redirect the operator to %s\nstderr:\n%s", want, stderr)
				}
			}
			// Live mode must NOT print the dry-run narrative.
			if strings.Contains(stdout, "STEP 1:") {
				t.Errorf("live mode leaked the dry-run narrative to stdout")
			}
		})
	}
}

func TestUnknownArgIsUsageError(t *testing.T) {
	script := scriptPath(t)
	stdout, stderr, code := runScript(t, script, nil, "--bogus")
	if code != 2 {
		t.Fatalf("unknown arg exit=%d, want 2\nstdout:%s\nstderr:%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("unknown arg should print usage\nstderr:\n%s", stderr)
	}
}
