// SPDX-License-Identifier: Apache-2.0

package hostagent

// attachbridge_test.go proves the gap-3 host-agent serving-child manager
// (attachbridge.go) WITHOUT any live process (D50): the live exec + the
// GuestIP:4242 relay are DS_HOSTAGENT_LIVE-gated and operator-validated at N7, so
// the offline path here LAUNCHES NOTHING and the live-path coverage is limited to
// the pre-exec validation (token-store fail-closed, guest-IP required) that runs
// before any subprocess. No VM/container/claude/cia/qemu/network is ever touched.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// testVsockCID is a valid (past the three reserved AF_VSOCK ids) derived guest CID for the
// Serve tests — the host→guest carriage target the serving child would dial.
const testVsockCID uint32 = 7

// TestAttachBridge_OfflineServeLaunchesNothing is the ACCEPTANCE test: off the
// DS_HOSTAGENT_LIVE gate (the default / only sandbox/CI path), Serve renders the
// per-session UDS path but launches NO child — no exec, no socket, no guest TCP dial.
func TestAttachBridge_OfflineServeLaunchesNothing(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "") // gate OFF (the default)

	b := NewAttachBridge(AttachBridgeConfig{SocketDir: "/run/ds/attach"})
	const sess = "sess-offline-1"

	// A guest vsock CID is irrelevant off the gate (no relay is dialed); pass the
	// not-yet-derived sentinel (0) to prove the offline path never reaches the CID
	// requirement.
	out, err := b.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured)
	if err != nil {
		t.Fatalf("offline Serve: %v", err)
	}
	if out.Launched {
		t.Error("offline Serve reported Launched=true, want false (no live process)")
	}
	if want := "/run/ds/attach/" + sess + ".sock"; out.UDSPath != want {
		t.Errorf("offline Serve UDS path = %q, want %q", out.UDSPath, want)
	}
	if b.ServingCount() != 0 {
		t.Errorf("offline Serve launched %d children, want 0", b.ServingCount())
	}
	// Destroy + Shutdown are clean no-ops with nothing launched.
	b.Destroy(sess)
	b.Shutdown()
	if b.ServingCount() != 0 {
		t.Errorf("after Destroy/Shutdown: %d children, want 0", b.ServingCount())
	}
}

// TestAttachBridge_DestroyDropsServingCountByOne proves the §4.2 destroy seam's payload:
// Destroy(sessionUUID) reaps the named session's serving child and ServingCount drops by
// exactly one (the other session's child is untouched), and the per-session UDS is
// unlinked. The live exec is DS_HOSTAGENT_LIVE-gated and operator-validated at N7, so this
// registers a child with a non-started command (Process == nil) — Destroy skips the
// signal/reap of a non-existent process but still drops the registration and unlinks the
// socket, exercising the count-decrement + cleanup the daemon's post-destroy hook drives.
func TestAttachBridge_DestroyDropsServingCountByOne(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "")
	dir := t.TempDir()
	b := NewAttachBridge(AttachBridgeConfig{SocketDir: dir})

	// Register two per-session children directly (the live exec is gated; this exercises
	// the lifecycle map the daemon's destroy hook reaps without launching a process). Each
	// has a non-started *exec.Cmd (Process == nil) so Destroy skips the SIGINT/reap path
	// and falls through to the registration drop + socket unlink.
	const sessA, sessB = "sess-reap-A", "sess-reap-B"
	udsA := b.socketPathFor(sessA)
	udsB := b.socketPathFor(sessB)
	for _, uds := range []string{udsA, udsB} {
		if err := os.WriteFile(uds, nil, 0o600); err != nil { // stand-in for a bound socket file
			t.Fatalf("seed socket %q: %v", uds, err)
		}
	}
	b.mu.Lock()
	b.children[sessA] = &servingChild{cmd: &exec.Cmd{}, udsPath: udsA, done: make(chan error, 1)}
	b.children[sessB] = &servingChild{cmd: &exec.Cmd{}, udsPath: udsB, done: make(chan error, 1)}
	b.mu.Unlock()

	if b.ServingCount() != 2 {
		t.Fatalf("seeded ServingCount = %d, want 2", b.ServingCount())
	}

	// The §4.2 destroy seam reaps exactly the named session.
	b.Destroy(sessA)

	if got := b.ServingCount(); got != 1 {
		t.Errorf("after Destroy(%s): ServingCount = %d, want 1 (dropped by exactly one)", sessA, got)
	}
	if _, err := os.Stat(udsA); !os.IsNotExist(err) {
		t.Errorf("Destroy(%s) must unlink its UDS %q (stat err = %v)", sessA, udsA, err)
	}
	// The other session's child + socket are untouched.
	if _, ok := b.children[sessB]; !ok {
		t.Errorf("Destroy(%s) wrongly reaped the unrelated session %s", sessA, sessB)
	}
	if _, err := os.Stat(udsB); err != nil {
		t.Errorf("unrelated session %s socket %q must survive: %v", sessB, udsB, err)
	}

	// Destroying the same session again is an idempotent no-op (count does not go negative).
	b.Destroy(sessA)
	if got := b.ServingCount(); got != 1 {
		t.Errorf("re-Destroy(%s): ServingCount = %d, want 1 (idempotent)", sessA, got)
	}
}

// TestAttachBridge_PathKeyingMatchesResolver proves the manager's rendered UDS path keys
// on the session UUID the SAME way the orchestrator endpoint resolver advertises it (same
// default dir, same .sock suffix, same sanitized component) — so the advertised candidate
// and the served socket name the SAME path.
func TestAttachBridge_PathKeyingMatchesResolver(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "")
	b := NewAttachBridge(AttachBridgeConfig{}) // empty dir → DefaultAttachSocketDir
	const sess = "sess-keying"

	out, err := b.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	want := DefaultAttachSocketDir + "/" + sess + attachSocketSuffix
	if out.UDSPath != want {
		t.Errorf("UDS path = %q, want %q (must match the orchestrator's advertised candidate)", out.UDSPath, want)
	}
}

// TestAttachBridge_DefaultPort proves an unset VsockPort falls back to the shared
// libvirt.DefaultAttachPort (so the offline module never hardcodes a wire port; the host
// serve leg, the ds-hostbridge vsock dial, and the in-guest forwarder reuse that value).
func TestAttachBridge_DefaultPort(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "")
	b := NewAttachBridge(AttachBridgeConfig{})
	if b.cfg.VsockPort != libvirt.DefaultAttachPort {
		t.Errorf("default VsockPort = %d, want %d", b.cfg.VsockPort, libvirt.DefaultAttachPort)
	}
}

// TestAttachBridge_EmptySessionRefused proves an empty session UUID is refused before any
// path render (a misconfigured serve must never stand up an anonymous session).
func TestAttachBridge_EmptySessionRefused(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "")
	b := NewAttachBridge(AttachBridgeConfig{})
	if _, err := b.Serve(context.Background(), "", testVsockCID, libvirt.SessionModeStructured); err == nil {
		t.Fatal("Serve with empty session uuid: expected an error")
	}
}

// TestAttachBridge_LiveRequiresVsockCID proves the LIVE path validates fail-closed BEFORE
// any exec: the not-yet-derived CID sentinel (0) is refused (no carriage target). This
// exercises the gated branch without launching a process (the validation precedes the exec).
func TestAttachBridge_LiveRequiresVsockCID(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "1") // gate ON — but the validation refuses pre-exec
	b := NewAttachBridge(AttachBridgeConfig{SocketDir: t.TempDir(), OverlayDir: t.TempDir()})

	_, err := b.Serve(context.Background(), "sess-live-nocid", 0, libvirt.SessionModeStructured) // not-yet-derived CID sentinel
	if err == nil {
		t.Fatal("live Serve with zero vsock CID: expected a fail-closed error (no carriage target)")
	}
	if !strings.Contains(err.Error(), "vsock CID") {
		t.Errorf("error = %v, want it to name the missing vsock CID", err)
	}
	if b.ServingCount() != 0 {
		t.Errorf("a refused live serve launched %d children, want 0", b.ServingCount())
	}
}

// TestAttachBridge_LiveTokenStoreFailClosed proves the LIVE path refuses fail-closed when
// the minter's token store file is absent (no authenticatable session) — again BEFORE any
// exec (the stat precedes the sibling-bin resolve + exec).
func TestAttachBridge_LiveTokenStoreFailClosed(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "1")
	b := NewAttachBridge(AttachBridgeConfig{SocketDir: t.TempDir(), OverlayDir: t.TempDir()})

	_, err := b.Serve(context.Background(), "sess-live-notoken", testVsockCID, libvirt.SessionModeStructured)
	if err == nil {
		t.Fatal("live Serve with no token store: expected a fail-closed error")
	}
	if !strings.Contains(err.Error(), "token store") {
		t.Errorf("error = %v, want it to name the absent token store", err)
	}
	if b.ServingCount() != 0 {
		t.Errorf("a refused live serve launched %d children, want 0", b.ServingCount())
	}
}

// TestAttachBridge_LiveRequiresOverlayDir proves the LIVE path refuses when no overlay/state
// dir is configured for the token store (DS_HOSTAGENT_LIVE) — pre-exec.
func TestAttachBridge_LiveRequiresOverlayDir(t *testing.T) {
	t.Setenv(libvirt.EnvHostAgentLive, "1")
	b := NewAttachBridge(AttachBridgeConfig{SocketDir: t.TempDir()}) // no OverlayDir

	_, err := b.Serve(context.Background(), "sess-live-nooverlay", testVsockCID, libvirt.SessionModeStructured)
	if err == nil {
		t.Fatal("live Serve with no overlay dir: expected a fail-closed error")
	}
	if !strings.Contains(err.Error(), "overlay") {
		t.Errorf("error = %v, want it to name the missing overlay/state dir", err)
	}
}

// TestServingChildArgs_TerminalAddsModeFlag proves the serving-child argv carries
// `--mode terminal` for a TERMINAL session (so the child serves the raw pty byte duplex)
// and the base flags are otherwise unchanged. The mode is the single-source resolution
// the caller read from SessionModeStore.ModeFor (U-HOST-SERVE).
func TestServingChildArgs_TerminalAddsModeFlag(t *testing.T) {
	args := servingChildArgs("/run/ds/attach/s.sock", 7, libvirt.DefaultAttachPort,
		"/state/.ds-attach-tokens/s.json", "sess-term", libvirt.SessionModeTerminal)
	joined := strings.Join(args, " ")
	// The base flags are present and unchanged.
	for _, want := range []string{
		"--serve-uds /run/ds/attach/s.sock",
		"--guest-vsock-cid 7",
		"--session-token-file /state/.ds-attach-tokens/s.json",
		"--session-uuid sess-term",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("terminal serving argv %q missing base flag %q", joined, want)
		}
	}
	// The terminal-only flag is present, exactly `--mode terminal`.
	if !strings.Contains(joined, "--mode terminal") {
		t.Errorf("terminal serving argv %q missing `--mode terminal`", joined)
	}
}

// TestServingChildArgs_StructuredIsByteIdenticalNoModeFlag proves a STRUCTURED session's
// serving-child argv carries NO --mode flag — byte-identical to the pre-terminal child
// (the default-path-unchanged invariant): the child defaults to structured.
func TestServingChildArgs_StructuredIsByteIdenticalNoModeFlag(t *testing.T) {
	args := servingChildArgs("/run/ds/attach/s.sock", 7, libvirt.DefaultAttachPort,
		"/state/.ds-attach-tokens/s.json", "sess-struct", libvirt.SessionModeStructured)
	want := []string{
		"--serve-uds", "/run/ds/attach/s.sock",
		"--guest-vsock-cid", "7",
		"--guest-vsock-port", "4242",
		"--session-token-file", "/state/.ds-attach-tokens/s.json",
		"--session-uuid", "sess-struct",
	}
	if len(args) != len(want) {
		t.Fatalf("structured serving argv = %v (len %d), want the %d base flags with NO --mode", args, len(args), len(want))
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("structured serving argv[%d] = %q, want %q", i, args[i], want[i])
		}
	}
	for _, a := range args {
		if a == "--mode" {
			t.Errorf("structured serving argv leaked a --mode flag: %v (must be byte-identical to today)", args)
		}
	}
}

// TestResolveHostbridgeBin_ExplicitNonExecutable proves an explicit/env bin that is not
// executable is a hard error (never a silent fall-through to a different one on PATH).
func TestResolveHostbridgeBin_ExplicitNonExecutable(t *testing.T) {
	// A plain (non-exec) file in a tmpdir.
	f := filepath.Join(t.TempDir(), "ds-hostbridge")
	if err := os.WriteFile(f, []byte("not a binary"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := resolveHostbridgeBin(f); err == nil {
		t.Fatal("resolveHostbridgeBin(non-executable): expected an error")
	}
}

// TestResolveHostbridgeBin_ExplicitExecutable proves an explicit executable path resolves.
func TestResolveHostbridgeBin_ExplicitExecutable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "ds-hostbridge")
	if err := os.WriteFile(f, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := resolveHostbridgeBin(f)
	if err != nil {
		t.Fatalf("resolveHostbridgeBin(executable): %v", err)
	}
	if got != f {
		t.Errorf("resolved = %q, want %q", got, f)
	}
}

// TestSanitizeAttachComponent proves separators/traversal bytes are reduced to a single
// safe path component (so a rendered path can never escape its dir).
func TestSanitizeAttachComponent(t *testing.T) {
	// '.' is a permitted filename byte (so the only traversal risk, a '/' separator, is
	// replaced); '..' alone is harmless inside a single filename component.
	cases := map[string]string{
		"sess-abc_123": "sess-abc_123",
		"../../etc":    ".._.._etc",
		"a/b":          "a_b",
		"a.b-c":        "a.b-c",
		"":             "_",
		"with space":   "with_space",
	}
	for in, want := range cases {
		got := sanitizeAttachComponent(in)
		if got != want {
			t.Errorf("sanitizeAttachComponent(%q) = %q, want %q", in, got, want)
		}
		// The load-bearing safety property: NO separator survives, so a rendered path is a
		// single component that cannot escape its dir.
		if strings.Contains(got, "/") {
			t.Errorf("sanitizeAttachComponent(%q) leaked a separator: %q", in, got)
		}
	}
}
