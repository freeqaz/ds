// SPDX-License-Identifier: Apache-2.0

// Package installscript_test is a host-safe smoke check over
// install-ds-nethelper.sh. It NEVER arms the installer (DS_NETHELPER_APPLY is
// never set to 1), so no install/setcap/sudo ever runs; it exercises only the
// refusal, usage, and READ-ONLY `verify` legs.
//
// The load-bearing case is TestInstallerVerifyFailsOnCaplessBinary: it builds
// the real (cgo-free stub) helper into a temp dir — a file that by construction
// carries NO capability xattr, exactly like a freshly rebuilt binary — and
// asserts verify refuses it and NAMES the missing capability field. That is the
// rebuilt-binary-loses-xattr footgun caught as a test.
package installscript_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scriptPath resolves install-ds-nethelper.sh relative to this test file's dir.
func scriptPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	p := filepath.Join(wd, "install-ds-nethelper.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("install-ds-nethelper.sh not found at %s: %v", p, err)
	}
	return p
}

// runScript runs `bash <script> [args...]` with extra env, returning combined
// stdout, stderr, and the exit code.
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
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return so.String(), se.String(), code
}

// TestInstallerRefusesUnarmed: the privileged install leg must never run
// without the operator explicitly arming it.
func TestInstallerRefusesUnarmed(t *testing.T) {
	script := scriptPath(t)
	stdout, stderr, code := runScript(t, script, nil, "/nonexistent/ds-nethelper")
	if code != 3 {
		t.Fatalf("unarmed install exit=%d, want 3 (refusal)\nstdout:%s\nstderr:%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "REFUSING") {
		t.Errorf("unarmed install must print the REFUSING banner\nstderr:\n%s", stderr)
	}
	if strings.Contains(stdout, "installing ") {
		t.Errorf("unarmed run reached the install step\nstdout:\n%s", stdout)
	}
}

// TestInstallerUsageWithoutSrc: armed but with no source binary is a usage
// error (exit 2) — it must NOT fall through to install/setcap.
func TestInstallerUsageWithoutSrc(t *testing.T) {
	script := scriptPath(t)
	stdout, stderr, code := runScript(t, script, []string{"DS_NETHELPER_APPLY=1"})
	if code != 2 {
		t.Fatalf("armed-without-src exit=%d, want 2 (usage)\nstdout:%s\nstderr:%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("missing usage output\nstderr:\n%s", stderr)
	}
	if strings.Contains(stdout, "setcap") {
		t.Errorf("armed-without-src reached the setcap step\nstdout:\n%s", stdout)
	}
}

// TestInstallerVerifyUsageWithoutPath: `verify` with no path is a usage error,
// never a vacuous pass.
func TestInstallerVerifyUsageWithoutPath(t *testing.T) {
	script := scriptPath(t)
	_, stderr, code := runScript(t, script, nil, "verify")
	if code != 2 {
		t.Fatalf("verify-without-path exit=%d, want 2 (usage)\nstderr:%s", code, stderr)
	}
}

// TestInstallerVerifyFailsOnCaplessBinary builds the real helper (the cgo-free
// stub build) into a temp dir and verifies it. A freshly built file carries NO
// capability xattr — the exact state a rebuild/recopy leaves behind — so verify
// MUST refuse and must NAME the missing capability field so the operator knows
// setcap is what is missing.
func TestInstallerVerifyFailsOnCaplessBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the helper; skipped under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	script := scriptPath(t)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	pkgDir := filepath.Join(wd, "..") // orchestrator/cmd/ds-nethelper
	bin := filepath.Join(t.TempDir(), "ds-nethelper")

	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = pkgDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}

	stdout, stderr, code := runScript(t, script, nil, "verify", bin)
	if code == 0 {
		t.Fatalf("verify PASSED a cap-less freshly-built helper; the rebuilt-binary footgun would go undetected\nstdout:%s", stdout)
	}
	all := stdout + stderr
	if !strings.Contains(all, "cap_net_admin_effective") {
		t.Errorf("verify failure must name the missing cap_net_admin_effective field\n%s", all)
	}
	if !strings.Contains(all, "setcap cap_net_admin+eip") {
		t.Errorf("verify failure must carry the setcap remedy (+eip, not +ep)\n%s", all)
	}
	if !strings.Contains(all, "VERIFY FAILED") {
		t.Errorf("verify failure must print the VERIFY FAILED banner\n%s", all)
	}
}
