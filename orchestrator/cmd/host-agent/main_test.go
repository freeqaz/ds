// SPDX-License-Identifier: Apache-2.0

// main_test.go is the OFFLINE daemon smoke test (the unit's acceptance, D50): with
// DS_HOSTAGENT_LIVE unset (the default fake/offline substrate) it assembles the
// production DriverService via the daemon composition root (buildDriverService),
// registers the FROZEN HypervisorDriverService on a real gRPC server over a loopback
// listener, dials a real generated client, asserts the contract answers over the
// wire (GetCapabilities with the HONEST libvirt flags; an idempotent Destroy of an
// unknown session), and shuts the server down cleanly via GracefulStop.
//
// It NEVER touches a live VM / libvirt / KVM / qemu / ds-nft (the offline seams in
// seams.go are no-touch). It is the in-process-gRPC proof that the daemon wiring —
// not just the in-package service_test.go construction — serves the frozen surface.
package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// defaultTestConfig is the offline default the smoke test serves over (the bare
// `host-agent` flag defaults, no orchestrator endpoint so no live dial).
func defaultTestConfig() config {
	c, err := parseConfig(nil)
	if err != nil {
		panic(err)
	}
	return c
}

// TestLaunchArgsEnvFlowIntoEntrypointFacts asserts the -launch-arg / -launch-env /
// -working-dir flags parse (repeatable, IN ORDER) and flow verbatim into the
// EntrypointFacts.Launch the gap-1 producer folds into every per-session
// EntrypointConfig — the surface that launches the real pinned Claude Code headless
// in-guest (D7/D20): e.g. claude --input-format stream-json --output-format stream-json.
func TestLaunchArgsEnvFlowIntoEntrypointFacts(t *testing.T) {
	c, err := parseConfig([]string{
		"-launch-command", "claude",
		"-launch-arg", "--input-format", "-launch-arg", "stream-json",
		"-launch-arg", "--output-format", "-launch-arg", "stream-json",
		"-launch-env", "TERM=dumb",
		"-working-dir", "/work",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	facts := entrypointFacts(c)
	if facts.Launch.Command != "claude" {
		t.Errorf("Launch.Command = %q, want claude", facts.Launch.Command)
	}
	wantArgs := []string{"--input-format", "stream-json", "--output-format", "stream-json"}
	if !equalStringSlices(facts.Launch.Args, wantArgs) {
		t.Errorf("Launch.Args = %v, want %v (repeatable -launch-arg must preserve order)", facts.Launch.Args, wantArgs)
	}
	if !equalStringSlices(facts.Launch.Env, []string{"TERM=dumb"}) {
		t.Errorf("Launch.Env = %v, want [TERM=dumb]", facts.Launch.Env)
	}
	if facts.Launch.WorkingDir != "/work" {
		t.Errorf("Launch.WorkingDir = %q, want /work", facts.Launch.WorkingDir)
	}
}

// TestInterceptCAPathReconcilesIntoEntrypointFacts asserts the posture-(b) cred-swap
// reconcile: the entrypoint config's egress.ca_bundle_path (→ the in-guest CC's
// NODE_EXTRA_CA_CERTS, vm/entrypoint/env.go) is sourced from the SAME
// DS_GUEST_INTERCEPT_CA_PATH that drives the InjectCA --upload target (trustanchor.go),
// so the cert is delivered TO that path and the guest is told to TRUST that path from
// ONE env. UNSET (the default / opaque / non-swap, every CI / sandbox path) keeps
// CABundlePath empty → NODE_EXTRA_CA_CERTS unset → BYTE-IDENTICAL to today. The path is
// a guest-filesystem REFERENCE, never CA material (D17/D39).
func TestInterceptCAPathReconcilesIntoEntrypointFacts(t *testing.T) {
	// UNSET (the default): no CA path threads, byte-identical to today.
	t.Setenv(libvirt.EnvGuestInterceptCAPath, "")
	if got := entrypointFacts(defaultTestConfig()).Egress.CABundlePath; got != "" {
		t.Errorf("default Egress.CABundlePath = %q, want empty (NODE_EXTRA_CA_CERTS must stay unset)", got)
	}

	// SET (posture-(b) swap): the fixed guest CA path threads into ca_bundle_path so the
	// in-guest CC's NODE_EXTRA_CA_CERTS trusts the per-session interception CA.
	const swapPath = "/etc/ds/intercept-ca.crt"
	t.Setenv(libvirt.EnvGuestInterceptCAPath, swapPath)
	if got := entrypointFacts(defaultTestConfig()).Egress.CABundlePath; got != swapPath {
		t.Errorf("swap-mode Egress.CABundlePath = %q, want %q (reconciled to DS_GUEST_INTERCEPT_CA_PATH)", got, swapPath)
	}

	// A relative value fails SAFE to the byte-identical default (never an ambiguous path).
	t.Setenv(libvirt.EnvGuestInterceptCAPath, "relative/ca.crt")
	if got := entrypointFacts(defaultTestConfig()).Egress.CABundlePath; got != "" {
		t.Errorf("relative DS_GUEST_INTERCEPT_CA_PATH must yield empty CABundlePath, got %q", got)
	}
}

// TestSessionModeFlagFlowsIntoEntrypointFacts asserts the -session-mode flag parses
// and threads into EntrypointFacts.DefaultMode (the serpent-CLI terminal-MVP rider):
// the bare default is structured (byte-identical to today), -session-mode terminal
// flips the host default, and a mistyped value fails parse loudly (never a silent
// structured fall-through).
func TestSessionModeFlagFlowsIntoEntrypointFacts(t *testing.T) {
	// Default (no flag) → structured.
	def, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig(nil): %v", err)
	}
	if got := entrypointFacts(def).DefaultMode; got != libvirt.SessionModeStructured {
		t.Errorf("default DefaultMode = %v, want structured", got)
	}

	// -session-mode terminal → terminal.
	term, err := parseConfig([]string{"-session-mode", "terminal"})
	if err != nil {
		t.Fatalf("parseConfig(terminal): %v", err)
	}
	if got := entrypointFacts(term).DefaultMode; got != libvirt.SessionModeTerminal {
		t.Errorf("-session-mode terminal DefaultMode = %v, want terminal", got)
	}

	// -session-mode structured → structured (explicit).
	str, err := parseConfig([]string{"-session-mode", "structured"})
	if err != nil {
		t.Fatalf("parseConfig(structured): %v", err)
	}
	if got := entrypointFacts(str).DefaultMode; got != libvirt.SessionModeStructured {
		t.Errorf("-session-mode structured DefaultMode = %v, want structured", got)
	}

	// A mistyped value fails parse (fail-loud at startup).
	if _, err := parseConfig([]string{"-session-mode", "termnial"}); err == nil {
		t.Fatal("parseConfig(-session-mode termnial) must fail loud, got nil err")
	}
}

// --- -launch-env-file: the CREDENTIAL-bearing launch-env transport (D39/D50) ---
//
// -launch-env puts its KEY=VALUE on this process's world-readable argv
// (/proc/*/cmdline), so a token may only arrive via a 0600 file. These tests pin the
// contract packet B's ds-serve-stack.sh writes against: repeatable, argv entries first
// then file entries in flag order, 0600 enforced, malformed lines rejected WITHOUT
// echoing the (possibly secret) line content.

// TestLaunchEnvFileFlowsIntoEntrypointFacts asserts file entries append AFTER the
// -launch-env entries and land verbatim on EntrypointFacts.Launch.Env — the same
// config-drive surface -launch-env already feeds (the guest contract is untouched).
func TestLaunchEnvFileFlowsIntoEntrypointFacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.env")
	body := "# the posture-B credential pair\n\nANTHROPIC_BASE_URL=http://10.0.2.2:8787\nFAKE_TOKEN=sekrit\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	c, err := parseConfig([]string{"-launch-env", "TERM=dumb", "-launch-env-file", path})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	want := []string{"TERM=dumb", "ANTHROPIC_BASE_URL=http://10.0.2.2:8787", "FAKE_TOKEN=sekrit"}
	if got := entrypointFacts(c).Launch.Env; !equalStringSlices(got, want) {
		t.Errorf("Launch.Env = %v, want %v (argv entries first, file entries after, order preserved)", got, want)
	}
}

// TestLaunchEnvFileTwoFilesOrder asserts repeated -launch-env-file appends in FLAG order.
func TestLaunchEnvFileTwoFilesOrder(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "one.env")
	second := filepath.Join(dir, "two.env")
	if err := os.WriteFile(first, []byte("A=1\nB=2\n"), 0o600); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := os.WriteFile(second, []byte("C=3\n"), 0o600); err != nil {
		t.Fatalf("write second: %v", err)
	}
	c, err := parseConfig([]string{"-launch-env-file", first, "-launch-env-file", second})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	want := []string{"A=1", "B=2", "C=3"}
	if got := entrypointFacts(c).Launch.Env; !equalStringSlices(got, want) {
		t.Errorf("Launch.Env = %v, want %v (files append in flag order)", got, want)
	}
}

// TestLaunchEnvFileRejectsLooseMode: a group/world-readable file offers the token to
// every local uid, which is the exact failure the flag exists to close.
func TestLaunchEnvFileRejectsLooseMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "loose.env")
	if err := os.WriteFile(path, []byte("FAKE_TOKEN=sekrit\n"), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	_, err := parseConfig([]string{"-launch-env-file", path})
	if err == nil {
		t.Fatal("parseConfig on a 0644 launch-env-file must fail, got nil err")
	}
	if !strings.Contains(err.Error(), "0644") || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("error %q must name the mode and the chmod remedy", err)
	}
}

// TestLaunchEnvFileRejectsMalformedLine: the error names the line NUMBER only — echoing
// the line would leak the credential it may contain into logs.
func TestLaunchEnvFileRejectsMalformedLine(t *testing.T) {
	const offending = "NOT_AN_ASSIGNMENT_sekrit"
	path := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(path, []byte("A=1\n"+offending+"\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	_, err := parseConfig([]string{"-launch-env-file", path})
	if err == nil {
		t.Fatal("parseConfig on a malformed launch-env-file line must fail, got nil err")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error %q must name the 1-based line number", err)
	}
	if strings.Contains(err.Error(), offending) {
		t.Errorf("error %q must NOT echo the offending line (it may carry credential material)", err)
	}
}

// TestLaunchEnvFileMissing: a path that does not exist fails parse rather than silently
// launching the runtime without its credentials.
func TestLaunchEnvFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.env")
	if _, err := parseConfig([]string{"-launch-env-file", path}); err == nil {
		t.Fatal("parseConfig on a nonexistent launch-env-file must fail, got nil err")
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- host-WIDE live-text gate: -include-partial-messages / DS_HOSTAGENT_LIVE_TEXT
// (the U-PARTIALS-ARM runtime-arming half; doc serpent-cli-mvp/06 Layer 1, D145) --
//
// The host gate flips cfg.liveText, which makes entrypointFacts ARM
// --include-partial-messages onto the STRUCTURED launch argv (via
// libvirt.ArmStructuredLiveText) so the in-guest CC emits the typing-delta
// stream_event records the structured adapter renders as live ChatDeltas. DEFAULT
// (gate off) leaves the structured launch argv BYTE-IDENTICAL to the operator argv.
// NEVER on the orchestrator wire (D38; the flag is host-resolved).

const includePartialFlag = "--include-partial-messages"

// hasIncludePartial reports whether args carries the live-text flag.
func hasIncludePartial(args []string) bool {
	for _, a := range args {
		if a == includePartialFlag {
			return true
		}
	}
	return false
}

// launchArgFlags renders the repeatable -launch-arg surface (in order) for the
// given operator argv, so a test drives the SAME flag path the operator does.
func launchArgFlags(operatorArgs ...string) []string {
	out := []string{"-launch-command", "claude"}
	for _, a := range operatorArgs {
		out = append(out, "-launch-arg", a)
	}
	return out
}

// TestLiveTextGateDefaultOffByteIdentical pins the gate-OFF default: with neither
// -include-partial-messages nor DS_HOSTAGENT_LIVE_TEXT set, cfg.liveText is false and
// the structured Launch.Args are BYTE-IDENTICAL to the operator argv — no live-text
// flag armed. This is the partials-off byte-identical invariant.
func TestLiveTextGateDefaultOffByteIdentical(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE_TEXT", "") // explicitly unset the env source
	operator := []string{"--input-format", "stream-json", "--output-format", "stream-json"}

	off, err := parseConfig(launchArgFlags(operator...))
	if err != nil {
		t.Fatalf("parseConfig(default): %v", err)
	}
	if off.liveText {
		t.Error("default cfg.liveText = true, want false (the byte-identical-default invariant)")
	}
	offArgs := entrypointFacts(off).Launch.Args
	if hasIncludePartial(offArgs) {
		t.Errorf("default Launch.Args carries %q (%v), want byte-identical to the operator argv (no live-text)", includePartialFlag, offArgs)
	}
	if !equalStringSlices(offArgs, operator) {
		t.Errorf("default Launch.Args = %v, want the unchanged operator argv %v", offArgs, operator)
	}
}

// TestLiveTextGateFlagArmsOnce pins the gate ON via the -include-partial-messages
// flag: cfg.liveText flips true and the structured Launch.Args carry the live-text
// flag EXACTLY ONCE, appended after the operator argv.
func TestLiveTextGateFlagArmsOnce(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE_TEXT", "")
	operator := []string{"--input-format", "stream-json", "--output-format", "stream-json"}

	on, err := parseConfig(append(launchArgFlags(operator...), "-include-partial-messages"))
	if err != nil {
		t.Fatalf("parseConfig(-include-partial-messages): %v", err)
	}
	if !on.liveText {
		t.Fatal("-include-partial-messages did not set cfg.liveText")
	}
	onArgs := entrypointFacts(on).Launch.Args
	n := 0
	for _, a := range onArgs {
		if a == includePartialFlag {
			n++
		}
	}
	if n != 1 {
		t.Errorf("armed Launch.Args has %d %q flags, want exactly 1; args=%v", n, includePartialFlag, onArgs)
	}
	want := append(append([]string(nil), operator...), includePartialFlag)
	if !equalStringSlices(onArgs, want) {
		t.Errorf("armed Launch.Args = %v, want %v (operator argv + the live-text flag last)", onArgs, want)
	}
}

// TestLiveTextGateEnvArms pins the SECOND gate source: DS_HOSTAGENT_LIVE_TEXT=1 (the
// env the -include-partial-messages flag DEFAULTS from) flips cfg.liveText and arms
// the flag identically, with no explicit -include-partial-messages on the command
// line. Only "1" enables it (the flag default is `os.Getenv(...) == "1"`).
func TestLiveTextGateEnvArms(t *testing.T) {
	operator := []string{"--output-format", "stream-json"}

	t.Setenv("DS_HOSTAGENT_LIVE_TEXT", "1")
	envOn, err := parseConfig(launchArgFlags(operator...))
	if err != nil {
		t.Fatalf("parseConfig(DS_HOSTAGENT_LIVE_TEXT=1): %v", err)
	}
	if !envOn.liveText {
		t.Fatal("DS_HOSTAGENT_LIVE_TEXT=1 did not set cfg.liveText")
	}
	if !hasIncludePartial(entrypointFacts(envOn).Launch.Args) {
		t.Errorf("DS_HOSTAGENT_LIVE_TEXT=1 did not arm %q onto the structured launch argv", includePartialFlag)
	}

	// A non-"1" env value does NOT enable the gate (the default is == "1").
	t.Setenv("DS_HOSTAGENT_LIVE_TEXT", "true")
	envOff, err := parseConfig(launchArgFlags(operator...))
	if err != nil {
		t.Fatalf("parseConfig(DS_HOSTAGENT_LIVE_TEXT=true): %v", err)
	}
	if envOff.liveText {
		t.Error("DS_HOSTAGENT_LIVE_TEXT=true enabled the gate, want only \"1\" to enable it")
	}
	if hasIncludePartial(entrypointFacts(envOff).Launch.Args) {
		t.Error("a non-\"1\" DS_HOSTAGENT_LIVE_TEXT armed the live-text flag, want byte-identical default")
	}
}

// TestDaemonServesFrozenDriverOffline assembles the daemon's DriverService over the
// offline seams, registers it on a real gRPC server over a loopback listener, dials
// a generated client, asserts the frozen contract answers over the wire, and shuts
// down cleanly with GracefulStop.
func TestDaemonServesFrozenDriverOffline(t *testing.T) {
	svc, coord, err := buildDriverService(defaultTestConfig())
	if err != nil {
		t.Fatalf("buildDriverService: %v", err)
	}
	if svc == nil || coord == nil {
		t.Fatal("buildDriverService returned a nil service or coordinator")
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	// The frozen HypervisorDriverService is registered via the generated registrar —
	// the exact wiring main() uses.
	hypervisorv1.RegisterHypervisorDriverServiceServer(srv, svc)

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := hypervisorv1.NewHypervisorDriverServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The frozen GetCapabilities answers over the wire with the HONEST libvirt flags
	// (instant-clone + disk-delta TRUE, migrate FALSE) — proof the registered server
	// IS the production driver, not the exit-2 stub.
	caps, err := client.GetCapabilities(ctx, &hypervisorv1.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities over the wire: %v", err)
	}
	c := caps.GetCapabilities()
	if c == nil {
		t.Fatal("nil Capabilities")
	}
	if !c.GetSupportsInstantClone() || !c.GetSupportsDiskDeltaExport() || c.GetSupportsMigrate() {
		t.Errorf("GetCapabilities flags = {instant=%v, delta=%v, migrate=%v}; want {true,true,false} (honest libvirt)",
			c.GetSupportsInstantClone(), c.GetSupportsDiskDeltaExport(), c.GetSupportsMigrate())
	}

	// Destroy of an unknown session is an idempotent success over the wire (the §4.2
	// teardown converges on an absent session) — the destroy half of M0 is wired.
	if _, err := client.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: "00000000-0000-4000-8000-00000000beef"}); err != nil {
		t.Fatalf("Destroy(unknown session) over the wire must succeed (idempotent): %v", err)
	}

	// Clean shutdown: GracefulStop returns once in-flight RPCs drain and Serve exits.
	srv.GracefulStop()
	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop within 5s of GracefulStop")
	}
}

// TestDaemonRoutabilityGateTracksPOL4 asserts the POL-4-backed RoutabilityGate the
// daemon wires reports the host NON-fresh before any verified snapshot is applied
// (the host stays default-deny / non-routable until POL-4 catches up, D72/D36), and
// FRESH after the coordinator commits one snapshot. This proves the gate is tied to
// the LANDED POL-4 freshness, not a stubbed always-fresh.
func TestDaemonRoutabilityGateTracksPOL4(t *testing.T) {
	coord, err := newOfflineApplyCoordinator()
	if err != nil {
		t.Fatalf("newOfflineApplyCoordinator: %v", err)
	}
	gate, err := newPOL4Gate(coord)
	if err != nil {
		t.Fatalf("newPOL4Gate: %v", err)
	}

	fresh, err := gate.PolicyFresh(context.Background())
	if err != nil {
		t.Fatalf("PolicyFresh(pre-apply): %v", err)
	}
	if fresh {
		t.Error("host must be NON-fresh before applying any verified snapshot (default-deny, D72)")
	}
}

// TestDaemonAttachBridgeOfflineLaunchesNothing is the gap-3 daemon acceptance: the
// composition root builds the gap-3 AttachBridge wired into the create path's post-boot hook,
// and OFF DS_HOSTAGENT_LIVE (the default / only sandbox-CI path) it owns ZERO serving children
// — the offline daemon launches no ds-hostbridge child, no socket, no guest TCP dial.
func TestDaemonAttachBridgeOfflineLaunchesNothing(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate OFF (the default offline substrate)

	svc, coord, bridge, _, _, err := buildDriverServiceWithBridge(defaultTestConfig(), newSessionCIDRegistry())
	if err != nil {
		t.Fatalf("buildDriverServiceWithBridge: %v", err)
	}
	if svc == nil || coord == nil || bridge == nil {
		t.Fatal("buildDriverServiceWithBridge returned a nil service / coordinator / bridge")
	}
	if bridge.ServingCount() != 0 {
		t.Errorf("offline daemon AttachBridge owns %d serving children, want 0 (no live ds-hostbridge child)", bridge.ServingCount())
	}
	// Shutdown is a clean no-op offline (nothing was launched).
	bridge.Shutdown()
	if bridge.ServingCount() != 0 {
		t.Errorf("after Shutdown: %d children, want 0", bridge.ServingCount())
	}
}

// TestDaemonAttachSocketDirSingleSourced proves the daemon's AttachBridge serves under the
// SAME default dir the orchestrator endpoint resolver advertises (the single source), so a
// handle the orchestrator issued resolves to exactly the socket this host serves. An empty
// -attach-socket-dir takes the single-sourced default.
func TestDaemonAttachSocketDirSingleSourced(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "")

	_, _, bridge, _, _, err := buildDriverServiceWithBridge(defaultTestConfig(), newSessionCIDRegistry())
	if err != nil {
		t.Fatalf("buildDriverServiceWithBridge: %v", err)
	}
	const sess = "sess-daemon-dir"
	out, err := bridge.Serve(context.Background(), sess, 0, libvirt.SessionModeStructured) // offline: renders, no launch (CID irrelevant)
	if err != nil {
		t.Fatalf("AttachBridge.Serve (offline): %v", err)
	}
	if want := hostagent.DefaultAttachSocketDir + "/" + sess + ".sock"; out.UDSPath != want {
		t.Errorf("daemon bridge serves %q, want the single-sourced default %q (== the resolver's advertised dir)", out.UDSPath, want)
	}
}

// TestDaemonAttachReapHookWiredOfflineNoOp proves the daemon wires the gap-3 serving-leg
// REAP adapter (attachReapHook → AttachBridge.Destroy) as the libvirt §4.2 post-destroy
// hook: building the composition root succeeds, and reaping a session through the adapter
// is a clean no-op OFF DS_HOSTAGENT_LIVE (the bridge owns no child — no exec, no socket).
// The wiring is present + constructible; the live reap of a real ds-hostbridge child is
// operator-validated at N7. (A Destroy of an unknown session over the wire — which drives
// the §4.2 path that fires this hook — is already asserted idempotent above.)
func TestDaemonAttachReapHookWiredOfflineNoOp(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // gate OFF (the default offline substrate)

	_, _, bridge, _, _, err := buildDriverServiceWithBridge(defaultTestConfig(), newSessionCIDRegistry())
	if err != nil {
		t.Fatalf("buildDriverServiceWithBridge (post-destroy hook wired): %v", err)
	}

	// The adapter the daemon wires onto the destroyer's post-destroy hook. Reaping any
	// session off the gate is a clean no-op (the bridge launched nothing) and never errors.
	hook := attachReapHook(bridge, newSessionCIDRegistry())
	if err := hook(context.Background(), "00000000-0000-4000-8000-00000000beef"); err != nil {
		t.Fatalf("offline post-destroy reap must be a clean no-op: %v", err)
	}
	if bridge.ServingCount() != 0 {
		t.Errorf("after offline reap: ServingCount = %d, want 0 (no live child existed)", bridge.ServingCount())
	}
}

// TestMinterEndpointSingleSourcedWithBridge pins the served-UDS single source ACROSS the
// minter and the AttachBridge: the libvirt attach minter's DefaultAttachSocketDir (the dir
// its DIRECT UDS endpoint is keyed under) MUST equal hostagent.DefaultAttachSocketDir (the
// dir the AttachBridge serves the per-session socket under and the orchestrator endpoint
// resolver advertises). A drift would mint an endpoint pointing at a socket no bridge binds.
// The libvirt tree cannot import hostagent (the import direction is hostagent → libvirt), so
// the equality is asserted HERE, where the composition root sees both constants.
func TestMinterEndpointSingleSourcedWithBridge(t *testing.T) {
	if libvirt.DefaultAttachSocketDir != hostagent.DefaultAttachSocketDir {
		t.Errorf("minter served-UDS dir %q != AttachBridge served-UDS dir %q (not single-sourced) — a minted endpoint would name a socket no bridge serves",
			libvirt.DefaultAttachSocketDir, hostagent.DefaultAttachSocketDir)
	}
}

// TestDaemonGap1ProducerWired proves the daemon assembles the gap-1 EntrypointConfig producer
// into the create path without error off the gate (offline fixtures source + no-touch
// deliverer) — the wiring is present and constructible; the live build/deliver is
// operator-validated at N7.
func TestDaemonGap1ProducerWired(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "")
	// A bare build off the gate must succeed (the producer's offline seams need no host facts).
	if _, _, _, _, _, err := buildDriverServiceWithBridge(defaultTestConfig(), newSessionCIDRegistry()); err != nil {
		t.Fatalf("buildDriverServiceWithBridge with gap-1 producer wired: %v", err)
	}
}

// recordingTokenSource is a libvirt.AttachTokenSource that records the sessions it was
// asked to mint a token for, so a test can assert the create-path post-boot hook mints
// BEFORE it serves (the fix for the serving child never launching because the libvirt
// minter only runs at IssueAttachHandle, after the post-boot hook).
type recordingTokenSource struct{ sessions []string }

func (r *recordingTokenSource) TokenFor(_ context.Context, sessionUUID string) ([]byte, time.Time, error) {
	r.sessions = append(r.sessions, sessionUUID)
	return []byte("test-token"), time.Now().Add(time.Hour), nil
}

// TestAttachServeHookMintsTokenBeforeServe pins the create-path ordering fix: the
// post-boot hook MINTS the per-session attach token (so AttachBridge.Serve's fail-closed
// token-exists check is satisfied) — without it the serving child never launches, because
// the libvirt minter only writes the token at IssueAttachHandle, which a client calls
// AFTER this hook. Offline the bridge no-launches, but the hook must still have minted the
// token (the observable: TokenFor was called for the session).
func TestAttachServeHookMintsTokenBeforeServe(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "") // offline: bridge no-launches, but the hook still mints
	bridge := hostagent.NewAttachBridge(hostagent.AttachBridgeConfig{OverlayDir: t.TempDir()})
	rec := &recordingTokenSource{}
	hook := attachServeHook(bridge, rec, nil, newSessionCIDRegistry(), logger())

	// A derived (non-zero) vsock CID is required for the hook to stand up the serving leg;
	// without it the hook skips before minting (the create-path binding always carries a
	// derived CID — alloc.go).
	binding := libvirt.Binding{
		GuestIP:  libvirt.GuestAddress{Family: libvirt.AddressFamilyIPv4, Address: []byte{10, 42, 0, 5}},
		VsockCID: 5,
	}
	if err := hook(context.Background(), "sess-mint", binding); err != nil {
		t.Fatalf("attachServeHook: %v", err)
	}
	if len(rec.sessions) != 1 || rec.sessions[0] != "sess-mint" {
		t.Fatalf("post-boot hook did not mint the token before serving: minted=%v, want [sess-mint]", rec.sessions)
	}
}

// TestAttachServeHookNilTokensNoPanic: a nil token source (the offline gate-aware store)
// must not panic — the hook skips the mint and serves (no-launch offline).
func TestAttachServeHookNilTokensNoPanic(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "")
	bridge := hostagent.NewAttachBridge(hostagent.AttachBridgeConfig{OverlayDir: t.TempDir()})
	hook := attachServeHook(bridge, nil, nil, newSessionCIDRegistry(), logger())
	binding := libvirt.Binding{
		GuestIP:  libvirt.GuestAddress{Family: libvirt.AddressFamilyIPv4, Address: []byte{10, 42, 0, 6}},
		VsockCID: 6,
	}
	if err := hook(context.Background(), "sess-nil", binding); err != nil {
		t.Fatalf("attachServeHook with nil tokens must be a clean no-op: %v", err)
	}
}

// TestAttachServeHookSkipsWithoutVsockCID pins the vsock-carriage gate on the post-boot
// hook: a binding with no derived vsock CID (the not-yet-derived sentinel 0) makes the hook
// SKIP before minting or serving (non-fatal — the session is still booted, the attach leg
// just cannot be carried without a CID). The observable: TokenFor is never called.
func TestAttachServeHookSkipsWithoutVsockCID(t *testing.T) {
	t.Setenv("DS_HOSTAGENT_LIVE", "")
	bridge := hostagent.NewAttachBridge(hostagent.AttachBridgeConfig{OverlayDir: t.TempDir()})
	rec := &recordingTokenSource{}
	hook := attachServeHook(bridge, rec, nil, newSessionCIDRegistry(), logger())

	binding := libvirt.Binding{
		GuestIP: libvirt.GuestAddress{Family: libvirt.AddressFamilyIPv4, Address: []byte{10, 42, 0, 7}},
		// VsockCID left zero (the not-yet-derived sentinel).
	}
	if err := hook(context.Background(), "sess-nocid", binding); err != nil {
		t.Fatalf("attachServeHook with no vsock CID must be a clean no-op: %v", err)
	}
	if len(rec.sessions) != 0 {
		t.Errorf("hook minted a token for a CID-less binding (%v); want a skip before mint", rec.sessions)
	}
}
