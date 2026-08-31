// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/e2e"
)

// TestRunGateUnsetDialsNothing proves the OFFLINE default — the only path any CI /
// sandbox / wave-gate run takes: with DS_KVM_LIVE unset, run() resolves nothing,
// DIALS NOTHING, and returns ErrKVMLiveGateUnset (through the exported e2e wrapper
// DriveKVMScriptedFromEnv, which this exercises end to end). No writer-seat socket
// is ever opened.
func TestRunGateUnsetDialsNothing(t *testing.T) {
	t.Setenv("DS_KVM_LIVE", "")            // explicitly unarm the gate
	t.Setenv("DS_KVM_LIVE_ATTACH_UDS", "") // ensure no stray env leaks a dial target
	t.Setenv("DS_KVM_LIVE_SESSION", "")
	t.Setenv("DS_KVM_LIVE_TOKEN", "")

	// run() writes to *os.File handles; a closed pipe-less devnull keeps the test
	// quiet without depending on os.Stdout being writable in the harness.
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open devnull: %v", err)
	}
	defer devnull.Close()

	err = run(nil, devnull, devnull)
	if !errors.Is(err, e2e.ErrKVMLiveGateUnset) {
		t.Fatalf("run() with DS_KVM_LIVE unset = %v, want ErrKVMLiveGateUnset (the harness must dial nothing unarmed)", err)
	}
}

// TestRunGateUnsetWithProofStillDialsNothing proves that even the -proof side-effect
// path is gated: building the proof turn must not provoke a dial when the gate is
// unset. The token NEVER appears in any output.
func TestRunGateUnsetWithProofStillDialsNothing(t *testing.T) {
	t.Setenv("DS_KVM_LIVE", "")

	var out, errOut bytes.Buffer
	stdout, stderr := mustTempFile(t), mustTempFile(t)
	defer stdout.Close()
	defer stderr.Close()

	err := run([]string{"-proof", "DS-SEAT-PROOF-TOKEN", "-proof-file", "p.txt"}, stdout, stderr)
	if !errors.Is(err, e2e.ErrKVMLiveGateUnset) {
		t.Fatalf("run(-proof…) with DS_KVM_LIVE unset = %v, want ErrKVMLiveGateUnset", err)
	}

	// Sanity: the gate aborts BEFORE any drive output, so the proof token must not
	// have been printed anywhere (it is a marker, not a credential, but the harness
	// prints no turn content regardless).
	readInto(t, stdout, &out)
	readInto(t, stderr, &errOut)
	if strings.Contains(out.String(), "DS-SEAT-PROOF-TOKEN") {
		t.Errorf("the proof turn instruction must not be printed on the gate-unset path; stdout=%q", out.String())
	}
}

// TestRunEmptyPromptRejected proves an empty -prompt is a loud caller error (a turn
// must drive something), independent of the gate.
func TestRunEmptyPromptRejected(t *testing.T) {
	t.Setenv("DS_KVM_LIVE", "1") // arm the gate so the empty-prompt check is reached first

	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open devnull: %v", err)
	}
	defer devnull.Close()

	err = run([]string{"-prompt", "   "}, devnull, devnull)
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("run(-prompt '   ') = %v, want an empty-prompt error", err)
	}
}

func mustTempFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ds-seat-drive-out-")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	return f
}

func readInto(t *testing.T, f *os.File, buf *bytes.Buffer) {
	t.Helper()
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	if _, err := buf.ReadFrom(f); err != nil {
		t.Fatalf("read: %v", err)
	}
}
