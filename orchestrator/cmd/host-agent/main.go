// SPDX-License-Identifier: Apache-2.0

// Command host-agent is the per-host agent — the second D35 service, running on
// every virtual-metal host (D31) beside the boundary services.
//
// Responsibilities (doc 15 §2 diagram, §4, §5.1/§5.2/§3):
//   - HypervisorDriver v1 server: the libvirt driver lives HERE
//     (internal/hypervisor/libvirt, doc 15 §5.1 — not in vm/). This daemon is the
//     composition root: it assembles the §4.1 create choreography + §4.2 destroy
//     ordering behind the frozen 10-verb HypervisorDriverService and serves it.
//   - the ONE WatchPolicies subscriber per host (D72, POL-4): verified-snapshot
//     fan-out to ds-dnsgate / ds-tlsproxy / the nft writer in admitter-last commit
//     order, applied_seq advancing post-sweep (internal/hostagent).
//   - heartbeat: applied_seq, observed sessions, capacity, samples,
//     host_baseline_version (dreamserpent.hostagent.v1, doc 15 §5.2).
//   - host-local never-recycled session-index allocation from a persistent
//     monotonic counter; dstap-<idx> + per-session guest IP derived
//     deterministically (D44/D66); invoker of the Boundary-owned tap-create
//     primitive (doc 14 §1; the ds-nft staticlib edge, still deferred).
//   - unconditional flush_session + NFT-6 teardown ordering at destroy
//     (doc 15 §4.2), invoked through the Destroyer (the ds-nft edge, deferred).
//
// LIVE-GATING (DS_HOSTAGENT_LIVE, additive + default-path-unchanged): the
// real-substrate ops (overlay-create.sh clone + virsh boot + the §4.2 virsh domain
// destroy) land behind the libvirt.NewOverlayStore / NewBooter / NewDomainDestroyer
// gate (live.go/destroyer_libvirt.go/offline.go). With the env UNSET (the default,
// and the only path in the sandbox / CI / unit tests) the daemon serves over the
// no-touch offline bindings — no libvirt/KVM/qemu/ds-nft is ever touched, so the
// conformance suite + unit tests stay green with fakes (D50).
//
// STILL DEFERRED (offline stubs in seams.go, documented as host-side / ds-nft
// staticlib): the AttachPrimitive (tap/NFT) real body, the identity-D22 CA fetch +
// libguestfs overlay trust-store write, and the crash-matrix RecoverSessions
// re-adoption (host-side, NOT in M0 scope). The frozen contract is satisfied
// throughout; only the substrate bodies are pending.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nethelper/nethelperclient"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ds host-agent: %v\n", err)
		os.Exit(1)
	}
}

// config is the daemon's bring-up configuration, sourced from flags (doc 13 §4:
// the guest subnet / overlay paths / host id are host-bring-up FACTS, not frozen
// ds-contracts literals). Defaults keep the OFFLINE smoke path turnkey: a bare
// `host-agent` binds an ephemeral port, runs the offline substrate, and skips the
// orchestrator-dialing legs (heartbeat + POL-4) until their endpoint is given.
// repeatedString is a flag.Value that accumulates a repeated string flag (e.g.
// -launch-arg A -launch-arg B) into an ordered slice — the flag stdlib has no
// repeated-value type. Append preserves order, matching the runtime's arg order.
type repeatedString []string

func (r *repeatedString) String() string     { return fmt.Sprint([]string(*r)) }
func (r *repeatedString) Set(v string) error { *r = append(*r, v); return nil }

type config struct {
	listenAddr string // gRPC listen address for the HypervisorDriverService
	hostID     string // this host's identity (the heartbeat / recover key)

	// guest address plan (doc 13 §4) — the per-session guest subnet + reserved low
	// addresses; the index→guest-IP derivation rule is the contract.
	guestSubnet string
	hostOffset  uint64

	// live-substrate facts (only consulted under DS_HOSTAGENT_LIVE, live.go).
	overlayDir          string
	overlayCreateScript string
	baseImage           string
	virshBin            string

	// direct-kernel boot facts (ADDITIVE + GATED, DEFAULT empty ⇒ historical
	// disk-boot `<os>`; live.go LiveConfig.KernelPath/InitrdPath/KernelCmdline,
	// also env-sourced DS_KERNEL_PATH/DS_INITRD_PATH/DS_KERNEL_CMDLINE). Set
	// kernelPath to boot a ROOTLESS (grub-less) M0 overlay via libvirt direct-kernel
	// (the kernel mounts the same vda overlay as root); zero value keeps the
	// canonical grub-image path byte-identical. NewLiveBooter ORs the env into these.
	kernelPath    string
	initrdPath    string
	kernelCmdline string

	// routedTap reports whether this host runs the per-session ROUTED TAP egress
	// path (the nft4 keystone) rather than the M0-minimal usermode SLIRP NIC
	// (LiveConfig.RoutedTap / EntrypointFacts.RoutedTap, DEFAULT false). When set the
	// EntrypointConfig producer ALSO renders the per-session guest static net config
	// (ds-net.env) onto the config-drive so the guest addresses its routed tap (U4);
	// when unset (the default) NO net config is rendered and the SLIRP boot path is
	// byte-identical to before. It gates ONLY the net-config emission; the tap + the
	// per-session gateway are U3 / the dataplane lane, not this daemon.
	routedTap bool

	// gap-1 / gap-3 host-resolved facts (doc 13 §4; consumed by the EntrypointConfig
	// producer + the AttachBridge). attachSocketDir is the host-local dir the per-session
	// attach UDS is served under — SINGLE-SOURCED with the orchestrator resolver
	// (hostagent.DefaultAttachSocketDir, the ONE home the controlplane resolver also reads);
	// empty takes that default so the two sides agree. launchCommand is the runtime entrypoint the structured
	// EntrypointConfig launches (D7/D20); eventSocketPath is the guest-local attach event UDS
	// (D38, absolute); the proxy/no-proxy/session-token endpoints are the egress + token
	// references (addresses only, never material, D17/D39).
	attachSocketDir string
	launchCommand   string
	launchArgs      repeatedString // ordered args for the runtime command (-launch-arg, repeatable)
	launchEnv       repeatedString // KEY=VALUE env entries for the runtime (-launch-env, repeatable; non-secret)
	// launchEnvFiles are paths to 0600 KEY=VALUE files whose entries APPEND to launchEnv
	// (-launch-env-file, repeatable, in flag order, after the -launch-env entries). It is
	// the transport for CREDENTIAL-bearing entries (the MVP OAuth token),
	// which must NEVER ride -launch-env: this process's argv is world-readable via
	// /proc/*/cmdline (D39/D50). The file PATH on argv is fine; the material is not. The
	// guest-side contract is unchanged — the entries land on the config drive exactly as
	// -launch-env entries do.
	launchEnvFiles       repeatedString
	workingDir           string // working dir the runtime execs in (empty => runtime default)
	eventSocketPath      string
	httpProxy            string
	httpsProxy           string
	sessionTokenEndpoint string

	// session-token shim (U5, D22/D39, hardened by the U5 authz fix). The shim now
	// serves over AF_VSOCK and authorizes by the connecting guest's (unforgeable) peer
	// CID, NOT by a session UUID on the wire. sessionTokenVsockPort is the well-known
	// AF_VSOCK PORT the host-local D22 token shim listens on (host side,
	// VMADDR_CID_HOST); sessionTokenEndpoint (above) is the vsock://host:<port>/token
	// REFERENCE the GUEST is told to dial (reference only, never the token value).
	// identityMintAddr is the gRPC dial endpoint of the identity mint the LIVE source
	// dials (empty => the live source fails closed; the offline source needs none). The
	// shim is stood up only when sessionTokenEndpoint is set.
	sessionTokenVsockPort uint
	identityMintAddr      string

	// hostbridgeBin is an explicit path to the ds-hostbridge serving binary the gap-3
	// AttachBridge execs per session on the live path (empty falls back to the resolution
	// order: DS_HOSTBRIDGE_BIN, PATH, sibling-of-this-binary). Consumed only on the live path.
	hostbridgeBin string

	// nethelperPath is the ABSOLUTE path of the installed, setcap'd `ds-nethelper`
	// privileged helper this (unprivileged) daemon forks once per privileged tap/nft
	// action — the ROOT-HELPER model ratified as D148. Also sourced from
	// DS_NETHELPER_PATH; the install default is /usr/local/libexec/ds-nethelper.
	//
	// EMPTY means "no privileged edge configured": the AttachPrimitive and the
	// boundary-readiness gate both stay the no-touch deferred stand-ins. That is NOT an
	// error even under DS_HOSTAGENT_LIVE — the live MVP flows (SLIRP-direct egress) run
	// the deferred no-touch attach today, so making an empty path fatal would break them.
	// Fatality is scoped to "path SET but the helper's bring-up probe is not Ready"
	// (verifyHelperReady): a half-armed helper must fail LOUD, an absent one must not.
	nethelperPath string

	// sessionMode is the per-host DEFAULT session launch mode (the serpent-CLI
	// terminal-MVP rider; libvirt.SessionMode via -session-mode). "structured" (the
	// default, and the zero value) is the historical headless stream-json path — a host
	// that never sets it is byte-identical to today. "terminal" launches the in-guest
	// runtime under a PTY (the interactive CC TUI), strips the stream-json argv, sets
	// LaunchSpec.stdio=PTY + an initial window, and (U-HOST-SERVE) mints a RAW_TERMINAL
	// handle. A per-session overlay hint (DS_SESSION_MODE= in the opaque overlay)
	// overrides this default. NEVER on the orchestrator wire (D38).
	sessionMode string

	// liveText is the host-WIDE live-text (typing-delta) gate for the STRUCTURED
	// stream-json launch surface (the U-PARTIALS-ARM runtime-arming half;
	// docs/serpent-cli-mvp/06 Layer 1, D145). When set, the structured launch argv the
	// EntrypointConfig producer builds carries --include-partial-messages, so the in-guest
	// CC emits the stream_event typing deltas the structured adapter projects as render-only
	// ChatDeltas (the matching adapter half is built WithPartials in the hostbridge serving
	// leg). DEFAULT false ⇒ the structured launch argv is BYTE-IDENTICAL to today. NEVER
	// armed for a SessionModeTerminal session (the PTY surface has the real terminal; the
	// flag is stripped by the terminal launch-mode transform). A CC-ism that stays in the
	// host-side launch-argv shaping (libvirt.ArmStructuredLiveText), NEVER on the
	// orchestrator wire (D38 runtime-ignorance). Also sourced from DS_HOSTAGENT_LIVE_TEXT.
	liveText bool

	// orchestrator dial endpoint for the POL-4 WatchPolicies subscription + the
	// heartbeat stream. Empty ⇒ those legs are RESERVED (logged + skipped) so the
	// offline daemon can serve the driver without a live control plane.
	orchestratorAddr string

	// dnsGateAddr is the TCP address the host-WIDE boundary-readiness gate dials to
	// prove ds-dnsgate answers (D63; the pre-step-4 admission precondition). It is the
	// ONE new operator-facing input this gate adds — there is no ds-dnsgate listener
	// address in config today (only httpProxy for ds-tlsproxy). LIVE-ONLY and ADDITIVE:
	// it must target tcp (prefer tcp/53 — a UDP "dial" never refuses), and on the live
	// path an EMPTY value FAILS construction CLOSED (newBoundaryReadiness) rather than
	// vacuously passing the dnsgate half. Off DS_HOSTAGENT_LIVE the gate is the deferred
	// no-op, so this is unread there. Also sourced from DS_DNSGATE_PROBE_ADDR.
	dnsGateAddr string

	// tlsProxyProbeAddr is the TCP address the boundary-readiness gate dials to prove
	// ds-tlsproxy answers (D63), DISTINCT from httpProxy (the runtime's HTTP_PROXY). A
	// transparent-redirect deployment (the nested cred-swap testbed) runs ds-tlsproxy
	// WITHOUT an explicit guest proxy, so the readiness probe needs its own dial target
	// that never enters the guest env. Empty falls back to httpProxy. Also sourced from
	// DS_TLSPROXY_PROBE_ADDR. LIVE-ONLY; unread off DS_HOSTAGENT_LIVE.
	tlsProxyProbeAddr string

	// feedDir is the host-local committed-snapshot feed directory the POL-4 producer
	// (internal/hostagent FeedWriter) fans each committed version out into as a
	// "<seq:020>.snapshot" file + the applied_seq cursor, behind the prepare/commit
	// barrier (doc 11 §5.3, doc 13 §5). It is the CROSS-PROCESS contract the dataplane
	// consumer (ds-dnsgate HostLocalFeedSource) reads, so it MUST resolve to the SAME
	// path the consumer's DS_DNSGATE_HOST_AGENT_FEED resolves to — empty defaults to
	// hostagent.DefaultHostAgentFeedDir (/run/ds-dnsgate/policy-feed), the single
	// cross-process default both halves honor. The fan-out runs on EVERY committed
	// apply (offline included) — it is the on-disk producer, not a live-gated leg — so
	// a deployment that does not run the dataplane consumer simply leaves the files
	// unread.
	feedDir string

	// feedProducers is the SINGLE bound POL-4 fan-out producer set (hostagent.FeedProducers)
	// run() pre-builds via buildFeedProducers so it can BOTH hand fp.Sweeper() to the
	// ApplyCoordinator AND call fp.Start(ctx) to bring up the live WatchPolicies carrier
	// serve loop (behind DS_DNSGATE_HOST_AGENT_FEED=uds:). It is NOT a flag — it is the
	// composition-root handoff from run() into buildDriverServiceWithBridge. nil on the
	// in-package smoke / unit-test path (those callers never Start), where
	// newFeedWritingApplyCoordinator builds the gate-aware default itself; with both fan-out
	// gates unset that default binds EXACTLY [FeedWriter] — byte-identical to today.
	feedProducers *hostagent.FeedProducers

	// reasonTracker is the host-ward FeedWriter drop-reason latch (the reason-routing
	// seam): run() creates it, installs it on feedProducers via SetReasonHook so the
	// file feed records each committed version's SnapshotReason onto it, AND hands it to
	// the heartbeat's coordStateSource so DetailFor(seq) surfaces on the fed consumer's
	// free-text ServiceHealth.Detail (heartbeat.go). It is NOT a flag — it is a
	// composition-root handoff from run(). nil on the in-package smoke / unit-test path
	// (those callers do not route reasons host-ward) — coordStateSource is nil-safe, so
	// an unset tracker leaves every Detail empty (byte-identical to today).
	reasonTracker *reasonTracker
}

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("host-agent", flag.ContinueOnError)
	var c config
	fs.StringVar(&c.listenAddr, "listen", "127.0.0.1:0", "gRPC listen address for the HypervisorDriverService (host-local; 127.0.0.1:0 picks an ephemeral port)")
	fs.StringVar(&c.hostID, "host-id", "host-local", "this host's identity (the heartbeat / recover key)")
	fs.StringVar(&c.guestSubnet, "guest-subnet", "10.42.0.0/16", "per-session guest subnet (doc 13 §4 host-bring-up fact); governs the SLIRP/offline guest-IP derivation (base+host-offset+index). INERT under -routed-tap, which pins the index-keyed 10.77.<idx>.1/31 scheme (U10)")
	fs.Uint64Var(&c.hostOffset, "host-offset", 2, "low addresses reserved before the first guest IP (network + per-session gateway); SLIRP path only, INERT under -routed-tap")
	fs.StringVar(&c.overlayDir, "overlay-dir", "/var/lib/ds/overlays", "directory per-session qcow2 overlays are written into")
	fs.StringVar(&c.overlayCreateScript, "overlay-create-script", "", "absolute path to vm/cow/overlay-create.sh (live substrate only)")
	fs.StringVar(&c.baseImage, "base-image", "", "read-only raw golden base image the overlay backs onto (live substrate only)")
	fs.StringVar(&c.virshBin, "virsh-bin", "", "virsh binary the live Booter drives (default PATH lookup)")
	fs.StringVar(&c.kernelPath, "kernel-path", "", "absolute path to the bzImage/vmlinuz for DIRECT-KERNEL boot of a ROOTLESS (grub-less) M0 image (live substrate only; also DS_KERNEL_PATH). EMPTY (default) keeps the historical disk-boot <os> (the canonical grub-image path); set it to render <os><kernel>/<initrd>/<cmdline></os> and boot the same vda overlay as root")
	fs.StringVar(&c.initrdPath, "initrd-path", "", "absolute path to the initrd/initramfs for direct-kernel boot (also DS_INITRD_PATH); consumed only with -kernel-path")
	fs.StringVar(&c.kernelCmdline, "kernel-cmdline", "", "kernel command line for direct-kernel boot (also DS_KERNEL_CMDLINE); empty with -kernel-path set falls back to libvirt.DefaultKernelCmdline (root=LABEL=DS_M0ROOT console=ttyS0,115200 rw)")
	fs.BoolVar(&c.routedTap, "routed-tap", false, "this host runs the per-session ROUTED TAP egress path (nft4 keystone), not the M0-minimal usermode SLIRP NIC: render the per-session guest static net config (ds-net.env, 10.77.<idx>.1/31 via 10.77.<idx>.0) onto the config-drive so the guest addresses its tap (U4). DEFAULT false keeps the SLIRP boot path byte-identical; the tap + the per-session gateway themselves are U3/the dataplane lane, not this daemon")
	fs.StringVar(&c.attachSocketDir, "attach-socket-dir", "", "host-local dir the per-session attach UDS is served under (single-sourced with the orchestrator resolver; empty => hostagent.DefaultAttachSocketDir)")
	fs.StringVar(&c.launchCommand, "launch-command", "", "runtime entrypoint command the structured EntrypointConfig launches in-guest (D7/D20; live substrate only)")
	fs.Var(&c.launchArgs, "launch-arg", "an argument for the in-guest runtime command, repeatable IN ORDER (e.g. real CC headless: -launch-arg --input-format -launch-arg stream-json -launch-arg --output-format -launch-arg stream-json); D7/D20")
	fs.Var(&c.launchEnv, "launch-env", "a KEY=VALUE env entry for the in-guest runtime, repeatable; non-secret references ONLY (no credential material, D7/D39)")
	fs.Var(&c.launchEnvFiles, "launch-env-file", "path to a KEY=VALUE file of env entries for the in-guest runtime, repeatable; entries append AFTER the -launch-env entries, files in flag order. This is how CREDENTIAL-bearing entries (e.g. the MVP OAuth token) reach the runtime without appearing on this process's world-readable argv (/proc/*/cmdline); the file must be mode 0600 (no group/other access) or parsing fails. Blank lines and #-comments are skipped")
	fs.StringVar(&c.workingDir, "working-dir", "", "working dir the in-guest runtime execs in (e.g. the repo clone root); empty => runtime default")
	fs.StringVar(&c.eventSocketPath, "event-socket-path", "", "guest-local attach event UDS the runtime emits onto (D38, absolute; live substrate only)")
	fs.StringVar(&c.httpProxy, "http-proxy", "", "HTTP_PROXY the runtime sets (the ds-tlsproxy egress gateway; address only)")
	fs.StringVar(&c.httpsProxy, "https-proxy", "", "HTTPS_PROXY the runtime sets (the same egress gateway; address only)")
	fs.StringVar(&c.sessionTokenEndpoint, "session-token-endpoint", "", "the vsock REFERENCE the GUEST is told to dial to reach the host-local D22 session-token shim (e.g. vsock://host:8200/token — the host listens on VMADDR_CID_HOST(2) at the well-known token port; the guest dials it and is authorized by its OWN unforgeable AF_VSOCK CID, never by a session UUID on the wire). Reference only, never the token value (D39); threaded into EntrypointFacts.SessionTokenEndpoint. Empty => the shim is not stood up")
	fs.UintVar(&c.sessionTokenVsockPort, "session-token-listen-port", uint(defaultSessionTokenVsockPort), "well-known AF_VSOCK PORT the D22 session-token shim listens on (host side, VMADDR_CID_HOST). The guest dials host-CID:<port> and is authorized by its connecting CID -> session (network-independent; no secret enters the VM). Distinct from the attach carriage port 4242. Only consulted when -session-token-endpoint is set")
	fs.StringVar(&c.identityMintAddr, "identity-mint-addr", "", "gRPC dial endpoint of the identity mint the LIVE session-token source dials to mint the short-lived D22 token (host-bring-up fact). Empty => the live source fails closed; the offline source (DS_HOSTAGENT_LIVE unset) needs none")
	fs.StringVar(&c.hostbridgeBin, "hostbridge-bin", "", "explicit path to the ds-hostbridge serving binary the gap-3 AttachBridge execs (empty => DS_HOSTBRIDGE_BIN, PATH, sibling-of-this-binary)")
	fs.StringVar(&c.nethelperPath, "nethelper-path", os.Getenv("DS_NETHELPER_PATH"), "ABSOLUTE path to the installed setcap'd ds-nethelper privileged helper this unprivileged daemon forks per privileged tap/nft op (ROOT-HELPER model, D148; install default /usr/local/libexec/ds-nethelper; also DS_NETHELPER_PATH). LIVE-ONLY. EMPTY keeps the no-touch deferred AttachPrimitive + always-ready boundary gate (the SLIRP-direct live MVP posture) — NOT an error. When SET under DS_HOSTAGENT_LIVE the helper's read-only probe must report built + cap_net_admin effective + ambient-raisable (a `cap_net_admin+eip` install), else bring-up is REFUSED: a half-armed `+ep` helper fails loud here instead of stranding every ip/nft child mid-create")
	fs.StringVar(&c.sessionMode, "session-mode", "structured", "default in-guest launch mode for sessions on this host when the per-session entrypoint overlay carries no DS_SESSION_MODE hint: \"structured\" (the historical headless stream-json path; the config-drive is byte-identical to today when unset) or \"terminal\" (the serpent-CLI terminal MVP: launch the runtime under a PTY for the interactive CC TUI, strip the stream-json argv, set LaunchSpec.stdio=PTY + a seeded window). NEVER on the orchestrator wire (D38, host-resolved); a per-session overlay hint overrides it")
	fs.BoolVar(&c.liveText, "include-partial-messages", os.Getenv("DS_HOSTAGENT_LIVE_TEXT") == "1", "host-WIDE live-text gate: arm --include-partial-messages on the STRUCTURED stream-json launch argv so the in-guest CC emits the typing deltas the structured adapter renders as live ChatDeltas (the serpent-CLI live-text MVP; the hostbridge adapter is built WithPartials in lockstep). DEFAULT false keeps the structured launch argv BYTE-IDENTICAL to today. NEVER armed for a terminal (PTY) session — the flag is stripped there. Also DS_HOSTAGENT_LIVE_TEXT=1. NEVER on the orchestrator wire (D38, host-resolved CC-ism)")
	fs.StringVar(&c.orchestratorAddr, "orchestrator-addr", "", "orchestrator dial endpoint for the POL-4 WatchPolicies subscription + heartbeat stream (empty => those legs reserved/skipped)")
	fs.StringVar(&c.dnsGateAddr, "dns-gate-addr", os.Getenv("DS_DNSGATE_PROBE_ADDR"), "TCP address the host-WIDE boundary-readiness gate dials to prove ds-dnsgate answers (D63; pre-step-4 admission precondition; also DS_DNSGATE_PROBE_ADDR). MUST be tcp (prefer tcp/53 — a UDP dial never refuses). LIVE-ONLY: empty FAILS construction CLOSED on the live cgo path rather than vacuously passing the dnsgate half; unread off DS_HOSTAGENT_LIVE (the gate is the deferred no-op)")
	fs.StringVar(&c.feedDir, "policy-feed-dir", os.Getenv("DS_HOSTAGENT_POLICY_FEED_DIR"), "host-local committed-snapshot feed directory the POL-4 producer fans each committed version out into (\"<seq:020>.snapshot\" + applied_seq cursor), behind the prepare/commit barrier (doc 11 §5.3; also DS_HOSTAGENT_POLICY_FEED_DIR). CROSS-PROCESS: MUST resolve to the same path the dataplane ds-dnsgate consumer's DS_DNSGATE_HOST_AGENT_FEED resolves to; empty => hostagent.DefaultHostAgentFeedDir (/run/ds-dnsgate/policy-feed), the single default both halves honor")
	fs.StringVar(&c.tlsProxyProbeAddr, "tls-proxy-probe-addr", os.Getenv("DS_TLSPROXY_PROBE_ADDR"), "TCP address the host-WIDE boundary-readiness gate dials to prove ds-tlsproxy answers (D63), DISTINCT from -http-proxy so a transparent-redirect deployment can probe ds-tlsproxy without injecting an HTTP_PROXY into the guest; also DS_TLSPROXY_PROBE_ADDR. Empty falls back to -http-proxy (the explicit-egress-proxy deployments). LIVE-ONLY")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	// Fail-loud at startup on a mistyped -session-mode (never a silent fall-through to
	// structured — an operator who typed "termnial" must learn it). The parsed mode is
	// re-derived in entrypointFacts via the same ParseSessionMode; validating here surfaces
	// the error at parse time with the rest of the flag validation.
	if _, err := libvirt.ParseSessionMode(c.sessionMode); err != nil {
		return config{}, fmt.Errorf("-session-mode: %w", err)
	}
	for _, path := range c.launchEnvFiles {
		entries, err := loadLaunchEnvFile(path)
		if err != nil {
			return config{}, err
		}
		c.launchEnv = append(c.launchEnv, entries...)
	}
	return c, nil
}

// loadLaunchEnvFile reads a 0600 KEY=VALUE file into ordered launch-env entries. The
// mode check is the whole point of the flag: the file carries credential material that
// -launch-env cannot (world-readable argv, D39/D50), so a group/other-accessible file
// fails parse rather than silently offering the secret to every local uid. Errors name
// the path and the 1-based line number ONLY — never the line content, which may be the
// secret itself; no entry value is logged anywhere.
func loadLaunchEnvFile(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("launch-env-file: %w", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("launch-env-file %s is group/world-accessible (mode %04o) — chmod 600; it carries credential material (D39/D50)", path, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("launch-env-file: %w", err)
	}
	var entries []string
	for i, line := range strings.Split(string(raw), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("launch-env-file %s line %d: not KEY=VALUE (no '=')", path, i+1)
		}
		if key == "" {
			return nil, fmt.Errorf("launch-env-file %s line %d: empty key", path, i+1)
		}
		if strings.ContainsAny(key, " \t\v\f\r\n") {
			return nil, fmt.Errorf("launch-env-file %s line %d: key contains whitespace", path, i+1)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// run is the daemon composition root (doc 15 §5.1: "the libvirt driver lives HERE
// ... wired into main.go"). It MIRRORS service_test.go's newTestDriverService
// construction but with PRODUCTION seams, registers the frozen
// HypervisorDriverService on a gRPC server, starts the heartbeat reporter + the
// POL-4 WatchPolicies consumer (when an orchestrator endpoint is configured), and
// serves until a shutdown signal — then drains gracefully.
func run(args []string) error {
	cfg, err := parseConfig(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// ── POL-4 host-local fan-out PRODUCERS (BindFeedProducers + the real revocation engine) ──
	// Build the SINGLE bound producer set ONCE here so run() can BOTH hand fp.Sweeper() to the
	// ApplyCoordinator (via cfg.feedProducers → buildDriverServiceWithBridge) AND fp.Start the
	// live WatchPolicies carrier serve loop below. With BOTH fan-out gates unset (every default
	// / CI / unit-test path) this binds EXACTLY [FeedWriter] and Start is a no-op — byte-identical
	// to today. DS_REVOCATION_FEED_LIVE composes the real RevocationProducer (over the vN→vN+1
	// diff engine) FIRST; DS_DNSGATE_HOST_AGENT_FEED=uds: adds the live carrier (Started below).
	feedProducers, err := buildFeedProducers(cfg.feedDir)
	if err != nil {
		return fmt.Errorf("build feed producers: %w", err)
	}
	cfg.feedProducers = feedProducers

	// ── host-ward FeedWriter drop-reason routing (the reason-routing seam) ──
	// Install a reason tracker onto the bound producer set's file feed (SetReasonHook):
	// the writer INSIDE fp.chain — the SAME writer the carrier/nft legs fan out beside,
	// never a substituted fresh writer — records each committed version's SnapshotReason
	// (SchemaFailure / ContentHashMismatch / clean) onto the tracker as it sweeps. The
	// heartbeat's coordStateSource reads DetailFor(seq) off the SAME tracker onto the fed
	// consumer's free-text ServiceHealth.Detail (heartbeat.go), so an operator querying the
	// boundary health sees a withheld version's separable cause end to end (and a clean
	// apply clears any stale token). State stays HEALTHY — the Detail is a diagnostic (doc
	// 13 §5.1), not a health-state transition. No proto enum widened. Threading the hook
	// onto the authoritative fp.Sweeper() chain is the carrier/nft-preserving restore: the
	// daemon routes the reason WITHOUT dropping the live carrier + nft fan-out legs.
	reasons := newReasonTracker()
	feedProducers.SetReasonHook(reasons.Record)
	cfg.reasonTracker = reasons

	logger.Info("POL-4 fan-out producers bound",
		"feed_dir", feedProducers.FeedDir(),
		"revocation_live", hostagent.RevocationFeedLiveEnabled(),
		"live_carrier", feedProducers.LiveCarrier(),
		"carrier_endpoint", feedProducers.CarrierEndpoint(),
	)

	// The ONE peer-CID -> session registry, shared between the session-token shim's
	// accept loop (the authz resolver — Lookup) and the create/destroy hooks (Bind at
	// post-boot once Binding.VsockCID is known; UnbindSession at destroy). It is the
	// keystone of the U5 authz hardening: a guest is served ONLY its own session's
	// token, authorized by its unforgeable connecting CID. Threaded the same way the
	// AttachBridge is.
	cidRegistry := newSessionCIDRegistry()

	svc, coord, bridge, recoverer, admissionSeg, err := buildDriverServiceWithBridge(cfg, cidRegistry)
	if err != nil {
		return fmt.Errorf("assemble hypervisor driver: %w", err)
	}

	// ── host-owned DNS-2b shm admission-map segment (T4, D131) ────────────────
	// CREATE the host-wide named POSIX shm segment at bring-up, BEFORE the ds-dnsgate
	// writer (a co-host process, gated on DS_ADMISSION_SHM_LIVE) attaches to it — so the
	// segment outlives the writer cleanly across a host-orchestrated restart. A create
	// failure under DS_HOSTAGENT_LIVE is FATAL: the daemon refuses the live path rather
	// than serving with no host-owned segment (docs/sessions/13 §Rollout-ordering,
	// fail-closed — never a silent no-segment continue). Off DS_HOSTAGENT_LIVE the seam is
	// the no-touch stand-in and Create touches nothing (byte-identical to today). The shm
	// read/write PATH stays independently gated by DS_ADMISSION_SHM_LIVE (writer) /
	// DS_TLS1_LIVE (reader), so with those off the services still use the in-process
	// fail-closed default; this only owns the SEGMENT's birth/death.
	if err := admissionSeg.Create(context.Background()); err != nil {
		return fmt.Errorf("create host-owned admission shm segment: %w", err)
	}
	// UNLINK the segment on host-orchestrated teardown (the graceful drain, NFT-6-aligned)
	// so it does not outlive the host. Idempotent on an already-absent object; off the
	// gate this is a no-op. Deferred alongside bridge.Shutdown so a host stop tears down
	// the segment it created.
	defer func() {
		if err := admissionSeg.Unlink(context.Background()); err != nil {
			logger.Warn("admission shm segment unlink", "err", err)
		}
	}()

	// The heartbeat's observed-session seam (nil off the live gate): the host's honest
	// self-observation, sourced from the SAME SessionRecoverer the crash-matrix re-adoption
	// reads — it enumerates the resident ds-domains and joins them to their persisted records,
	// projected onto the SHARED hypervisor.v1.ObservedSession the heartbeat carries (§5.2). The
	// reconciler diffs this against the placed records: a session PRESENT in the observed set is
	// joined to its VM and left alone; an empty observed set makes every placed record look like
	// a missing VM and triggers the §3 rule-b re-drive (re-mint+re-clone+re-boot) every cadence,
	// tearing a live attach stream. The element carries a nil ObservedState (un-pin-downable):
	// the reconciler treats it as "present, state unknown" — no re-drive (rule b), no regression
	// re-converge (rule c). A nil recoverer (offline) leaves this nil → no observed sessions.
	var observed observedSessionsFunc
	if recoverer != nil {
		observed = recoveredObservedSessions(recoverer, cfg.hostID)
	}
	// The gap-3 attach serving children (the per-session ds-hostbridge processes the
	// AttachBridge owns) are torn down at daemon stop. Offline (DS_HOSTAGENT_LIVE unset) the
	// bridge launched nothing, so this is a clean no-op; on the live path it SIGINTs + reaps
	// every live serving child as part of the graceful drain.
	defer bridge.Shutdown()

	lis, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.listenAddr, err)
	}

	srv := grpc.NewServer()
	hypervisorv1.RegisterHypervisorDriverServiceServer(srv, svc)
	logger.Info("hypervisor driver registered",
		"addr", lis.Addr().String(),
		"host_id", cfg.hostID,
		"substrate", substrateMode(),
	)

	// Root context cancelled on the first SIGINT/SIGTERM — the graceful-drain signal
	// for the heartbeat loop and the POL-4 consumer.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	// ── live WatchPolicies carrier serve loop (DS_DNSGATE_HOST_AGENT_FEED=uds:) ──
	// Bring up the POL-4 host-local carrier's UDS serve loop when the "uds:" gate selected it
	// (feedProducers.LiveCarrier()). fp.Start binds the carrier UDS + serves WatchPolicies(from_seq)
	// to a dialing dataplane consumer on a goroutine, draining when ctx is cancelled. It is a clean
	// NO-OP (nil channel, no socket, no goroutine) off the "uds:" gate — every default / CI /
	// unit-test path — so the gate-unset daemon is byte-identical. A bind failure under the gate is
	// FATAL: the daemon refuses to serve a carrier it advertised but could not bind (fail-closed,
	// like the admission-segment Create above). The returned channel delivers the serve loop's
	// terminal error; it is joined on the drain below (a clean ctx-cancel returns context.Canceled,
	// not a fault).
	//
	// DEFERRED-MANUAL (the cross-process live dial): a real ds-dnsgate consumer dialing the carrier
	// at DS_DNSGATE_HOST_AGENT_FEED=uds:<same path> is the live leg an operator runs end to end; the
	// serve loop itself is unit-proven in-process (dnsfeed_carrier_test.go).
	carrierErr, err := feedProducers.Start(ctx)
	if err != nil {
		return fmt.Errorf("start live policy-feed carrier: %w", err)
	}
	if feedProducers.LiveCarrier() {
		logger.Info("POL-4 live WatchPolicies carrier serving (host-local UDS)",
			"carrier_endpoint", feedProducers.CarrierEndpoint())
	}

	// ── host-local D22 session-token shim (U5, D22/D39; AF_VSOCK peer-CID authz) ──
	// The in-guest runtime fetches its short-lived session token from this host-side
	// server at boot. Stood up ONLY when -session-token-endpoint is set (the vsock
	// reference the guest is told to dial — reference only). The shim serves over
	// AF_VSOCK (host listens on VMADDR_CID_HOST:<port>) and authorizes by the
	// CONNECTING GUEST'S unforgeable peer CID via the shared cidRegistry: a guest is
	// served ONLY its own session's token, and a cross-session ask is structurally
	// impossible (the caller can only present its OWN CID). Gate-aware exactly like
	// every other live binding: under DS_HOSTAGENT_LIVE the source dials the identity
	// mint; offline it serves a clearly-marked NON-SECRET placeholder (D50) so the
	// daemon serves offline. The token VALUE never enters config (D39).
	var tokenShim *sessionTokenShim
	// shimErr carries the shim goroutine's serve result; it stays a nil channel when
	// no shim runs (a select on a nil channel blocks forever, so the shutdown cases
	// below are inert without a shim). Hoisted to run() scope so the drain can READ
	// it — an unread shimErr silently swallowed a bind fault (fail-open) before.
	var shimErr chan error
	if cfg.sessionTokenEndpoint != "" {
		tokenShim = newSessionTokenShim(newGatedSessionTokenSource(cfg.identityMintAddr), cidRegistry)
		shimErr = make(chan error, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Serve returns nil on a clean Shutdown (the listener-closed path is folded
			// inside Serve); any other error is a bind/accept fault surfaced loudly.
			shimErr <- tokenShim.Serve(uint32(cfg.sessionTokenVsockPort))
		}()
		// The shim is drained EXPLICITLY before wg.Wait below (NOT in a trailing defer:
		// that fired after wg.Wait, which deadlocked — the serve goroutine blocks in
		// Serve() until Shutdown() is called, so wg.Wait() never returned).
		logger.Info("D22 session-token shim serving (AF_VSOCK, peer-CID authz)",
			"vsock_port", cfg.sessionTokenVsockPort,
			"guest_endpoint", cfg.sessionTokenEndpoint,
			"substrate", substrateMode(),
		)
	} else {
		logger.Info("D22 session-token shim RESERVED (no -session-token-endpoint); guest is told no token endpoint")
	}

	// The HypervisorDriverService server runs until GracefulStop (below). A Serve
	// error after stop is the expected ErrServerStopped; surface anything else.
	serveErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.Serve(lis)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	// The orchestrator-dialing legs (POL-4 WatchPolicies consumer + heartbeat
	// reporter) come up ONLY when an endpoint is configured; otherwise they are
	// RESERVED so the offline daemon can serve the driver without a live control
	// plane (the M0 offline smoke path). Both legs reuse ALREADY-LANDED units —
	// internal/hostagent Subscribe -> SnapshotStore -> ApplyCoordinator (POL-4) and
	// internal/hostagent Stream (heartbeat) — driven over a dialed orchestrator conn.
	if cfg.orchestratorAddr == "" {
		logger.Info("POL-4 WatchPolicies consumer + heartbeat reporter RESERVED (no -orchestrator-addr); serving driver offline",
			"pol4", "internal/hostagent Subscribe -> SnapshotStore -> ApplyCoordinator (landed)",
			"heartbeat", "internal/hostagent Stream (landed)")
	} else {
		startPolicyAndHeartbeat(ctx, &wg, cfg, coord, observed, logger)
	}

	// Block until a shutdown signal, then drain: stop accepting new RPCs and let
	// in-flight ones finish, and let the heartbeat loop close its stream cleanly
	// (its ctx is already cancelled by NotifyContext).
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received; draining")
	case err := <-serveErr:
		// The server stopped on its own (a listener fault) — tear down and report.
		stop()
		if err != nil {
			return fmt.Errorf("hypervisor driver serve: %w", err)
		}
	case err := <-shimErr:
		// The session-token shim's listener faulted (e.g. bind failed) — a guest
		// would be advertised an endpoint that serves nothing, so fail the daemon
		// loudly rather than swallow it. A nil shimErr channel makes this case inert
		// (no shim configured), so this never fires on the no-shim path.
		stop()
		if err != nil {
			return fmt.Errorf("session-token shim serve: %w", err)
		}
	}

	srv.GracefulStop()
	// Stop the session-token shim BEFORE wg.Wait so its serve goroutine can return
	// (Serve blocks until Shutdown — the deadlock the trailing defer caused). A nil
	// tokenShim (no shim configured) is skipped.
	if tokenShim != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := tokenShim.Shutdown(shutCtx); err != nil {
			logger.Warn("session-token shim shutdown", "err", err)
		}
		cancel()
	}
	wg.Wait()

	// Surface a late serve fault if one raced the drain.
	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("hypervisor driver serve: %w", err)
		}
	default:
	}
	// Drain the shim's serve result (nil on a clean Shutdown); surface a late fault.
	// A nil shimErr (no shim) takes the default.
	select {
	case err := <-shimErr:
		if err != nil {
			return fmt.Errorf("session-token shim serve: %w", err)
		}
	default:
	}
	// Join the live policy-feed carrier serve loop (off the "uds:" gate carrierErr is a nil
	// channel — the default case is inert). A clean ctx-cancel shutdown returns
	// context.Canceled (the carrier's documented drain), NOT a fault; anything else is a serve
	// error surfaced loudly. The serve loop already drained on the cancelled root ctx above.
	select {
	case err := <-carrierErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("live policy-feed carrier serve: %w", err)
		}
	default:
	}
	logger.Info("host-agent stopped cleanly")
	return nil
}

// buildDriverService assembles the production DriverService over the M0 seams,
// MIRRORING service_test.go's newTestDriverService construction with PRODUCTION
// bindings: a persistent never-recycled monotonic counter + the host AddressPlan
// into NewAllocator; the gate-aware libvirt.NewOverlayStore / NewBooter (the u3
// bindings — real under DS_HOSTAGENT_LIVE, offline otherwise); the cainject.go
// production CAInjector over its fetch/write seams; the gate-aware
// libvirt.NewDomainDestroyer (§4.2 step 1 — the real virsh destroy under the gate,
// the no-touch offline stand-in otherwise) beside the deferred AttachPrimitive
// offline stub (seams.go); and the POL-4-backed RoutabilityGate
// over the landed ApplyCoordinator. It returns the service AND the coordinator so
// the POL-4 consumer can drive the same coordinator the gate reads from.
//
// Construction order mirrors the canonical pattern: NewAllocator -> NewHostAgent
// -> NewDestroyer -> NewDriverServiceWithDestroyResolver (the full-fan-in
// constructor, service.go; the §4.2 destroy-durability resolver is gate-aware over
// the SessionRecordStore — see below). The lifecycle seams Suspend/
// Resume (NewSuspender), Snapshot (NewSnapshotStore), and ExportDiskDelta
// (NewDiskDeltaExporter) are wired GATE-AWARE: real virsh/qemu-img bindings under
// DS_HOSTAGENT_LIVE, nil (honest codes.Unimplemented) off the gate. RecoverSessions
// and IssueAttachHandle stay deferred — no real SessionRecoverer/AttachHandleMinter
// has landed, so the recoverer/counter/minter are nil and those verbs answer an
// honest codes.Unimplemented (service.go).
func buildDriverService(cfg config) (*libvirt.DriverService, *hostagent.ApplyCoordinator, error) {
	// The in-package smoke test path does not exercise the session-token shim, so it
	// passes a throwaway registry — the hooks Bind/UnbindSession into it harmlessly. The
	// host-owned admission shm segment is discarded here (the smoke path neither creates
	// nor unlinks it; run() owns that lifecycle).
	svc, coord, _, _, _, err := buildDriverServiceWithBridge(cfg, newSessionCIDRegistry())
	return svc, coord, err
}

// newFeedWritingApplyCoordinator builds the landed POL-4 ApplyCoordinator over the
// three M0 offline barriers in FIXED admitter-last commit order (the same set
// newOfflineApplyCoordinator wires) with the bound POL-4 FAN-OUT PRODUCERS
// (hostagent.FeedProducers) as its POST-COMMIT sweeper, so each committed version is
// fanned out EXACTLY behind the prepare/commit barrier — the coordinator invokes the
// sweeper only after the admitter-LAST commit (doc 11 §5.3, doc 13 §5.2).
//
// THE SWEEPER IS fp.Sweeper() — the BindFeedProducers chain (buildFeedProducers,
// policy.go): the REAL post-commit RevocationProducer (over the vN→vN+1 diff engine,
// FIRST, behind DS_REVOCATION_FEED_LIVE so the host sweeps onto vN+1 before any fan-out,
// D72), then the always-bound on-disk FeedWriter, then the live WatchPolicies carrier
// (behind DS_DNSGATE_HOST_AGENT_FEED=uds:). With BOTH gates UNSET (every default / CI /
// unit-test path) the chain is EXACTLY [FeedWriter] — behaviorally IDENTICAL to the prior
// bare-FeedWriter sweeper (a single-member SweeperChain is a pass-through), so the
// default-OFF launch is byte-identical.
//
// fp is the SINGLE bound producer set: when run() pre-built it (so it can also Start the
// live carrier) it is threaded in via cfg.feedProducers; the in-package smoke / unit-test
// callers pass a nil cfg.feedProducers, so this builds the gate-aware default itself
// (buildFeedProducers, which on those paths binds EXACTLY [FeedWriter]). The two cases
// resolve the SAME chain — the only difference is WHO calls fp.Start (run, on the live
// carrier path; the test callers never Start, and off the "uds:" gate Start is a no-op).
//
// feedDir empty => hostagent.DefaultHostAgentFeedDir (/run/ds-dnsgate/policy-feed), the
// single cross-process default the dataplane ds-dnsgate consumer also resolves; a
// deployment that relocates the feed passes a matching -policy-feed-dir AND
// DS_DNSGATE_HOST_AGENT_FEED so the producer and consumer stay single-sourced.
func newFeedWritingApplyCoordinator(cfg config) (*hostagent.ApplyCoordinator, *hostagent.FeedProducers, error) {
	fp := cfg.feedProducers
	if fp == nil {
		// The in-package smoke / unit-test path (cfg.feedProducers unset): build the
		// gate-aware producer set here. With both gates unset this binds EXACTLY [FeedWriter]
		// (byte-identical); the test callers never Start it (off the "uds:" gate Start is a
		// no-op anyway).
		built, err := buildFeedProducers(cfg.feedDir)
		if err != nil {
			return nil, nil, fmt.Errorf("build feed producers: %w", err)
		}
		fp = built
	}
	coord, err := newFeedWritingApplyCoordinatorFor(fp)
	if err != nil {
		return nil, nil, err
	}
	return coord, fp, nil
}

// newFeedWritingApplyCoordinatorFor builds the landed POL-4 ApplyCoordinator over the
// three M0 offline barriers (admitter-LAST commit order, D72) with the ALREADY-BOUND
// producer set fp's authoritative chain (fp.Sweeper()) as its post-commit sweeper. It is
// the seam newFeedWritingApplyCoordinator delegates to once it has resolved fp, and the
// one a caller (or a carrier-ON test) uses to drive the SAME coordinator over a producer
// set it configured itself — the carrier + nft legs (WithNftProgrammer) and the reason
// hook (SetReasonHook) already composed in. The sweeper is fp.Sweeper() (never a
// substituted fresh writer), so the live carrier + nft-writer fan-out legs stay in the
// swept chain — the carrier/nft-preserving restore.
func newFeedWritingApplyCoordinatorFor(fp *hostagent.FeedProducers) (*hostagent.ApplyCoordinator, error) {
	order := []hostagent.ConsumerBarrier{
		offlineBarrier{name: hostagent.BoundaryTLSProxy},
		offlineBarrier{name: hostagent.BoundaryNFTWriter},
		offlineBarrier{name: hostagent.BoundaryDNSGate}, // admitter LAST (D72)
	}
	return hostagent.NewApplyCoordinator(order, fp.Sweeper())
}

// buildDriverServiceWithBridge is buildDriverService plus the gap-3 AttachBridge it returns
// so the daemon's drain path (run) can tear down the per-session serving children at stop.
// It is the real composition root; buildDriverService is the thin (svc, coord) wrapper the
// in-package smoke test consumes. It additionally wires the gap-1 EntrypointConfig producer
// into the create path and the gap-3 per-session serving-leg stand-up as the HostAgent
// post-boot hook — both gate-aware (offline fakes / no-launch off DS_HOSTAGENT_LIVE; the real
// host store + iso9660 writer + ds-hostbridge child exec on). The AttachBridge's served-UDS
// dir is SINGLE-SOURCED with the orchestrator endpoint resolver (hostagent.DefaultAttachSocketDir,
// the ONE home the controlplane resolver also reads) so a handle the orchestrator issued
// resolves to exactly the socket this host serves.
//
// It additionally returns the gate-aware SessionRecoverer (nil off DS_HOSTAGENT_LIVE):
// the heartbeat leg uses it to report the host's resident sessions in the §3 observed
// set, so the reconciler joins each placed record to its running VM instead of
// re-driving it as a missing VM every cadence (which would tear a live attach stream).
//
// It additionally returns the host-owned DNS-2b shm admission-map segment (T4, D131):
// the real POSIX-shm create/unlink lifecycle under DS_HOSTAGENT_LIVE, the no-touch
// stand-in off the gate (never nil — the seam is always returned so run() can call
// Create at bring-up + defer Unlink without a nil guard). A construction error under
// the gate (a malformed shm-name override, or a non-Linux host) is FATAL here.
func buildDriverServiceWithBridge(cfg config, cidRegistry *sessionCIDRegistry) (*libvirt.DriverService, *hostagent.ApplyCoordinator, *hostagent.AttachBridge, libvirt.SessionRecoverer, libvirt.AdmissionSegment, error) {
	subnet, err := netip.ParsePrefix(cfg.guestSubnet)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("parse guest subnet %q: %w", cfg.guestSubnet, err)
	}
	// The address plan gates the per-session guest-IP scheme on the routed-tap posture
	// (U10): under RoutedTap the allocator records the routed-tap /31 guest end
	// 10.77.<idx>.1 (the SINGLE source netconfig.go derives), so the recorded
	// Binding.GuestIP agrees with the U4 ds-net.env the guest applies and the ds-nft tap
	// link; off the gate it keeps the historical Subnet+HostOffset 10.42.x derivation
	// byte-identical. OR the DS_ROUTED_TAP env in so this allocation gate reads the SAME
	// posture as the entrypoint net-config render (RoutedTapEnabled at main.go:609) and the
	// booter (NewLiveBooter, live.go) — the -routed-tap flag OR the env flips all three in
	// lockstep, so the binding and the guest's net config can never disagree.
	plan := libvirt.AddressPlan{
		Subnet:     subnet,
		HostOffset: cfg.hostOffset,
		RoutedTap:  cfg.routedTap || libvirt.RoutedTapEnabled(),
	}

	// The gate-aware overlay + boot + lifecycle bindings: real overlay-create.sh
	// clone + virsh under DS_HOSTAGENT_LIVE, no-touch offline default otherwise.
	liveCfg := libvirt.LiveConfig{
		OverlayCreateScript: cfg.overlayCreateScript,
		OverlayDir:          cfg.overlayDir,
		BaseImage:           cfg.baseImage,
		VirshBin:            cfg.virshBin,
		RoutedTap:           cfg.routedTap,
		// Direct-kernel boot facts (ADDITIVE, DEFAULT empty ⇒ historical disk-boot
		// `<os>`). NewLiveBooter ORs the DS_KERNEL_PATH/DS_INITRD_PATH/DS_KERNEL_CMDLINE
		// env into these and defaults the cmdline when a kernel path is set, exactly
		// like RoutedTap/VirshBin, so EITHER the flag or the env enables direct-kernel.
		KernelPath:    cfg.kernelPath,
		InitrdPath:    cfg.initrdPath,
		KernelCmdline: cfg.kernelCmdline,
		// GenisoimageBin lets a host with no genisoimage on PATH point the config-drive
		// build at an alternate iso9660 packer (DS_HOSTAGENT_GENISOIMAGE_BIN). Empty ⇒
		// "genisoimage" via PATH (configdrive.go), the production default. On a box without
		// the tool (and no sudo to install it) this is set to a wrapper that runs the same
		// genisoimage invocation inside a throwaway podman container (the proven manual path),
		// so the host-agent's create choreography needs no host iso tool — the args
		// (-output/-volid/-input-charset/-rational-rock/-joliet/<staging>) are passed through
		// verbatim and the wrapper mounts the overlay dir so the host paths resolve in-container.
		GenisoimageBin: os.Getenv("DS_HOSTAGENT_GENISOIMAGE_BIN"),
	}

	// The never-recycled monotonic index counter (D66): under DS_HOSTAGENT_LIVE the
	// crash-safe file-backed durable counter (so a host-agent restart RESUMES past
	// every resident session's index, never re-handing a live index); off the gate
	// the process-local in-memory counter (the sandbox/CI default). This replaces
	// the old non-durable persistentCounter stub.
	counter, err := libvirt.NewIndexCounter(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new index counter: %w", err)
	}
	alloc, err := libvirt.NewAllocator(counter, plan)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new allocator: %w", err)
	}
	overlay, err := libvirt.NewOverlayStore(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new overlay store: %w", err)
	}
	booter, err := libvirt.NewBooter(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new booter: %w", err)
	}

	// The host-owned DNS-2b shm admission-map segment lifecycle (T4, D131): the real
	// POSIX-shm create/unlink under DS_HOSTAGENT_LIVE, the no-touch stand-in off the gate
	// (never nil). Constructed here from the SAME single EnvHostAgentLive source of truth
	// as the overlay/boot bindings; run() drives Create at bring-up + defer Unlink at the
	// graceful drain. A construction error under the gate (a malformed DS_ADMISSION_SHM_NAME
	// override, or a non-Linux host where POSIX shm is unsupported) is FATAL — the daemon
	// refuses the live path rather than serving with no host-owned segment (fail-closed,
	// docs/sessions/13 §Rollout-ordering).
	admissionSeg, err := newAdmissionSegment(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new admission shm segment: %w", err)
	}

	// The cainject.go PRODUCTION CAInjector over its fetch + write seams, gate-aware
	// and SOURCE+WRITER-IN-LOCKSTEP: under DS_HOSTAGENT_LIVE both go real together —
	// the host-readable per-session CA store (fileCABundleSource: the orchestrator
	// drops the minted interception-CA PEM keyed by caBundleRef; the host-agent reads
	// it, never re-mints) + the libguestfs overlay trust-store write
	// (NewLiveTrustStoreWriter). Off the gate the offline stand-ins (seams.go) keep
	// the fail-closed step-7 contract provable against fakes (D50). Never a real writer
	// with a placeholder source — that would virt-customize a fake CA into a real
	// overlay (a guest trusting a non-existent root).
	ca, err := newGatedCAInjector(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new CA injector: %w", err)
	}

	// The POL-4 ApplyCoordinator (the landed two-phase barrier) backs the
	// RoutabilityGate's PolicyFresh: a host that has not applied a verified snapshot
	// is non-routable (D72/D36). The three consumer barriers are the host-local
	// boundary-service integrations; M0 wires them as deferred offline barriers so
	// the coordinator is constructible and the gate has a real applied pointer.
	//
	// The coordinator's POST-COMMIT sweeper is the POL-4 host-local FEED PRODUCER
	// (internal/hostagent FeedWriter): the coordinator invokes it ONLY after the
	// admitter-LAST commit (all three consumers flipped vN+1), which is EXACTLY the
	// prepare/commit barrier point the host-local feed must be written behind (doc 11
	// §5.3, doc 13 §5.2). It fans the just-committed version out as a
	// "<seq:020>.snapshot" file + the applied_seq cursor under cfg.feedDir (the
	// cross-process directory the dataplane ds-dnsgate consumer reads), so a version
	// never reaches the on-disk feed before the host is serving it. apply_seq advances
	// post-fan-out (Sweeper contract). The real revocation sweep, when the consumer
	// integrations land, composes BEFORE the feed writer via hostagent.SweeperChain so
	// the host both sweeps AND fans out post-commit.
	// The coordinator's POST-COMMIT sweeper is the bound POL-4 fan-out producer chain
	// (fp.Sweeper()): the real RevocationProducer (behind DS_REVOCATION_FEED_LIVE) + the
	// file feed + the live carrier (behind DS_DNSGATE_HOST_AGENT_FEED=uds:). run() pre-built
	// the producer set so it can ALSO fp.Start the live carrier serve loop; it threads that
	// SAME instance in via cfg.feedProducers. The in-package smoke / unit-test callers pass a
	// nil cfg.feedProducers, so newFeedWritingApplyCoordinator builds the gate-aware default
	// itself (EXACTLY [FeedWriter] off the gates — byte-identical). fp is discarded HERE (the
	// builder's 6-value signature is pinned by the in-package tests); run() owns the fp it
	// pre-built and Starts.
	coord, _, err := newFeedWritingApplyCoordinator(cfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new apply coordinator: %w", err)
	}
	gate, err := newPOL4Gate(coord)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new routability gate: %w", err)
	}

	// Gate-aware crash re-adoption (D66, doc 15 §4): the durable session-record
	// store persists each booted session's binding (the domain XML carries only the
	// session UUID), and the SessionRecoverer re-observes resident domains + reads
	// those records on a restart. nil off the gate (no durable recovery there).
	records, err := libvirt.NewSessionRecordStore(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new session record store: %w", err)
	}
	recoverer, err := libvirt.NewSessionRecoverer(liveCfg, records)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new session recoverer: %w", err)
	}

	// ── gap-3 AttachBridge (per-session serving-leg manager) ─────────────────
	// The host-local served-UDS dir is SINGLE-SOURCED with the orchestrator endpoint
	// resolver: an empty -attach-socket-dir takes hostagent.DefaultAttachSocketDir (the one
	// home the controlplane resolver's defaultAttachSocketDir also reads), so the
	// candidate the orchestrator advertises resolves to exactly the socket this bridge
	// serves. Off DS_HOSTAGENT_LIVE the bridge launches NOTHING (the offline no-launch path).
	bridge := hostagent.NewAttachBridge(hostagent.AttachBridgeConfig{
		HostbridgeBin: cfg.hostbridgeBin,
		SocketDir:     cfg.attachSocketDir, // empty => the single-sourced default
		OverlayDir:    cfg.overlayDir,
		// VsockPort left zero => libvirt.DefaultAttachPort (the offline module never
		// hardcodes a wire port; the host serve leg, the ds-hostbridge vsock dial, and
		// the in-guest forwarder all reuse that one cross-module value).
	})

	// ── gap-1 EntrypointConfig producer (create-path build+deliver) ──────────
	// Gate-aware: the offline fixture source + no-touch deliverer off DS_HOSTAGENT_LIVE (so
	// the create choreography drives build+deliver entirely offline against fixtures, D50);
	// the real host store + iso9660 config-drive writer on. The host-resolved facts are the
	// daemon bring-up inputs (the launch command, the egress/proxy refs, the event-socket
	// path, the session-token endpoint). The offline fixtures map is empty — the offline
	// create path runs only when a VmSpec carries a ref the host store can resolve; an
	// offline daemon with no drop never invokes Produce (the create path is ref-gated).
	entrypoint, err := libvirt.NewGatedEntrypointProducer(liveCfg, entrypointFacts(cfg), nil)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new entrypoint producer: %w", err)
	}

	// The SHARED per-session attach token store (gate-aware): the ONE store the
	// create-path serving-leg mint writes AND the IssueAttachHandle minter (below) reads
	// — so the token minted at create (so the serving child has something to validate
	// against) is the SAME token a client later receives from IssueAttachHandle (TokenFor
	// is idempotent within the TTL). nil off DS_HOSTAGENT_LIVE.
	attachTokens, err := libvirt.NewAttachTokenStore(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new attach token store: %w", err)
	}

	// The SHARED per-session resolved-mode store (gate-aware): the SINGLE source the
	// EntrypointProducer WROTE the resolved mode to (sessionmodestore.go), read back by
	// BOTH the post-boot serve hook (to pass the serving child --mode terminal) AND the
	// IssueAttachHandle minter (to tag the endpoint RAW_TERMINAL) — so the handle
	// transport, the serving child's --mode, and the LaunchSpec.stdio all derive from ONE
	// resolution and cannot drift (doc 04 §5). It is a host-readable file store under the
	// SAME OverlayDir the producer's store wrote, so a second instance reads the same
	// markers. nil off DS_HOSTAGENT_LIVE (the offline serve no-launches; the minter is
	// Unimplemented), so the structured/offline path is byte-identical.
	modeStore, err := libvirt.NewSessionModeStore(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new session mode store: %w", err)
	}

	// The post-boot hook stands up the per-session attach serving leg once a session has
	// booted (best-effort/non-fatal — a serve fault never unwinds a booted session). The
	// adapter derives the per-session guest IP from the recorded binding (the host alone
	// knows it; the orchestrator stays runtime-ignorant), MINTS the per-session attach
	// token (so the post-boot Serve's fail-closed token-exists check is satisfied — the
	// libvirt minter otherwise only runs at IssueAttachHandle, AFTER this hook, so without
	// a create-time mint the serving child would never launch), READS the resolved mode
	// from the shared store to serve the right surface, and owns its own logging.
	postBoot := attachServeHook(bridge, attachTokens, modeStore, cidRegistry, logger())

	// ── the ds-nethelper privileged-helper client (ROOT-HELPER model, D148) ──
	// This daemon runs FULLY UNPRIVILEGED and forks the setcap'd `ds-nethelper`
	// binary once per privileged tap/nft action; the capability lives on the helper
	// file, never on this process (the agent no longer links the ds-nft cgo edge at
	// all — see nftgatelive_refuse.go). The client is constructed ONLY on the live
	// path AND only when a helper path was configured; nil means "no privileged edge",
	// which the seam selectors read as the no-touch deferred stand-ins.
	//
	// An EMPTY -nethelper-path under DS_HOSTAGENT_LIVE is deliberately NOT fatal: the
	// live MVP flows (SLIRP-direct egress) legitimately run the deferred no-touch
	// attach. What IS fatal is a path that is SET but whose helper is not fully armed
	// — verifyHelperReady refuses bring-up on a stub build, a missing setcap, or the
	// `+ep` half-configuration whose ip/nft children would be stranded unprivileged.
	// nethelperclient.New itself rejects a relative path (resolving the privileged
	// binary through a caller-controlled cwd/PATH would be a substitution hole).
	var nethelper *nethelperclient.Client
	if libvirt.LiveEnabled() && cfg.nethelperPath != "" {
		nethelper, err = nethelperclient.New(cfg.nethelperPath)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("ds-nethelper client: %w", err)
		}
		if err := verifyHelperReady(context.Background(), nethelper); err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("ds-nethelper bring-up refused: %w", err)
		}
	}

	// The Boundary-owned tap/NFT primitive: the real helper-backed helperAttach when
	// the host is live AND a ds-nethelper client was constructed; otherwise the
	// no-touch deferredAttach. The SAME primitive drives create (CreateTap +
	// InstantiateSessionNFT, create.go step 4) and destroy (FlushSession, NFT-6).
	attachPrim := newAttachPrimitive(nethelper)

	// ── host-WIDE boundary-readiness gate (pre-step-4 admission, D63/D69/D70) ─
	// The real live probe (the three boundary nft tables present via a read-only `nft
	// list` + ds-dnsgate/ds-tlsproxy answering via a TCP dial) ONLY when the host is
	// live AND a ds-nethelper client was constructed; the no-touch deferredReadiness
	// (always-ready) otherwise — mirroring newAttachPrimitive. On the live path the
	// gate is ADDITIONALLY fronted by the helper's own read-only probe per admission
	// (helperProbeReadiness), so a helper that loses its capability xattr mid-run (a
	// rebuild/recopy) refuses the NEXT admission instead of failing mid-create. The
	// ds-tlsproxy probe target is the already-parsed -http-proxy egress-gateway address
	// (cfg.httpProxy); the ds-dnsgate target is the NEW -dns-gate-addr (also
	// DS_DNSGATE_PROBE_ADDR) — there is no ds-dnsgate listener address in config today.
	// The required table set is single-sourced via libvirt.RequiredBoundaryTables() so
	// the probe and the ds-nft-bootstrap unit never drift. A construction error under
	// the gate (an empty dnsgate/tlsproxy addr or empty table set) is FATAL — the daemon
	// refuses the live path rather than serving with a vacuously-passing gate
	// (fail-closed; never a silently always-ready live gate). Off the gate this is the
	// deferred no-op, so the offline composition is byte-identical.
	// The ds-tlsproxy readiness probe target prefers the dedicated -tls-proxy-probe-addr
	// (also DS_TLSPROXY_PROBE_ADDR): a TRANSPARENT-REDIRECT deployment (the nested
	// cred-swap testbed) runs ds-tlsproxy WITHOUT handing the guest an explicit proxy, so
	// the readiness dial needs its own target that does NOT leak into the guest's
	// HTTP_PROXY env. It falls back to -http-proxy for the explicit-egress-proxy
	// deployments where the probe target and the runtime proxy coincide (the historical
	// behavior — byte-identical when -tls-proxy-probe-addr is unset).
	tlsProxyProbeAddr := cfg.tlsProxyProbeAddr
	if tlsProxyProbeAddr == "" {
		tlsProxyProbeAddr = cfg.httpProxy
	}
	readiness, err := newBoundaryReadiness(libvirt.LiveReadinessConfig{
		TablesRequired: libvirt.RequiredBoundaryTables(),
		DNSGateAddr:    cfg.dnsGateAddr,
		TLSProxyAddr:   tlsProxyProbeAddr,
		ProbeTimeout:   libvirt.DefaultProbeTimeout,
	}, nethelper)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new boundary-readiness gate: %w", err)
	}

	// The DURABLE out-of-band sink for a swallowed best-effort hook fault — installed on BOTH
	// the Creator (post-boot serving-leg stand-up) and the Destroyer (post-destroy serving-leg
	// reap) so a fault swallowed FROM EITHER verdict is surfaced structurally through the
	// daemon's slog logger (hook / session / err) instead of the libvirt default's bare
	// log.Printf line. It NEVER re-enters a verdict — a create still returns its routable verdict
	// and a Destroy still returns its §4.2 result; the sink is observability only.
	faultSink := hookFaultSink(logger())

	host, err := libvirt.NewHostAgentWithReadiness(alloc, attachPrim, overlay, ca, booter, gate, records, entrypoint, postBoot, readiness)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new host agent: %w", err)
	}
	// Route the create-path post-boot serving-leg stand-up fault (best-effort, swallowed from
	// the create verdict) into the durable sink so a silently-failed attach leg is observable.
	host.WithHookFaultObserver(faultSink)

	// §4.2 step 1 (guest VM destroy), gate-aware over the SAME single EnvHostAgentLive
	// source of truth as the overlay/boot bindings: the real `virsh destroy ds-<uuid>`
	// (destroyer_libvirt.go) under DS_HOSTAGENT_LIVE, the no-touch offline stand-in
	// otherwise. Unlike the OPTIONAL lifecycle seams it is REQUIRED (NewDestroyer rejects
	// a nil domain destroyer), so both paths yield a non-nil step 1 and the offline
	// composition stays byte-identical.
	domainDestroyer, err := libvirt.NewDomainDestroyer(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new domain destroyer: %w", err)
	}
	destroyer, err := libvirt.NewDestroyer(domainDestroyer, attachPrim, overlay, deferredDurability{}, deferredFlowBytes{})
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new destroyer: %w", err)
	}
	// The post-destroy hook REAPS the per-session attach serving leg at session DESTROY
	// (the same child the create-path post-boot hook stood up), so a torn-down session's
	// ds-hostbridge child is reaped on §4.2 teardown, not only at daemon Shutdown. The
	// adapter — NOT the libvirt tree — calls AttachBridge.Destroy, keeping the import
	// direction hostagent → libvirt; off DS_HOSTAGENT_LIVE the bridge owns nothing so the
	// reap is a clean no-op.
	destroyer.WithPostDestroyHook(attachReapHook(bridge, cidRegistry))
	// Route the post-destroy serving-leg REAP fault (best-effort, swallowed from the §4.2
	// verdict) into the SAME durable sink as the Creator, completing the wave-1 create-path arc:
	// a serving-child reap that silently failed at teardown is now observable out-of-band without
	// changing the Destroy result.
	destroyer.WithHookFaultObserver(faultSink)

	// Gate-aware lifecycle seams: real virsh/qemu-img bindings under
	// DS_HOSTAGENT_LIVE, nil (honest Unimplemented) off the gate — same single
	// EnvHostAgentLive source of truth as the overlay/boot bindings above.
	suspender, err := libvirt.NewSuspender(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new suspender: %w", err)
	}
	snapshots, err := libvirt.NewSnapshotStore(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new snapshot store: %w", err)
	}
	exporter, err := libvirt.NewDiskDeltaExporter(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new disk-delta exporter: %w", err)
	}

	// Gate-aware attach-handle minter (D79, doc 15 §5.4): under DS_HOSTAGENT_LIVE the
	// real M0 minter — the DIRECT EndpointCandidate is the host-local SERVED UDS path (the
	// socket the AttachBridge binds; serpent-tui's DIRECT→TransportUnix carrier dials it),
	// keyed under the SAME single-sourced attach socket dir the AttachBridge serves under
	// (cfg.attachSocketDir, empty => the shared default), plus a short-lived session-scoped
	// token from the host-readable per-session token store (D39); nil off the gate
	// (IssueAttachHandle answers honest Unimplemented — no served socket offline).
	minter, err := libvirt.NewAttachHandleMinterFromTokens(liveCfg, attachTokens, cfg.attachSocketDir, modeStore)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new attach handle minter: %w", err)
	}

	// The recovery re-seed handle wires in LOCKSTEP with the recoverer (both or
	// neither, D66): on the live path the SAME counter the Allocator draws from
	// (the durable counter implements ReseedableCounter), so RecoverSessions
	// re-seeds the one monotonic index source past the highest recovered index; nil
	// off the gate (recoverer nil → RecoverSessions Unimplemented).
	var reseed libvirt.ReseedableCounter
	if recoverer != nil {
		rc, ok := counter.(libvirt.ReseedableCounter)
		if !ok {
			return nil, nil, nil, nil, nil, fmt.Errorf("recovery-wired host requires a reseedable index counter, got %T", counter)
		}
		reseed = rc
	}

	// §4.2 DESTROY-DURABILITY RESOLVER (D29/D66, doc 15 §4.2) — the gate-aware bridge from
	// the durable SessionRecordStore the create path persists into the service's OPTIONAL
	// DestroyResolver. The frozen DestroyRequest carries ONLY the session_uuid, so a gRPC
	// Destroy of a session this PROCESS never cloned (the post-restart case: the in-memory
	// clone cache is empty) has no host-side teardown state to unwind — the DomainUUID (step
	// 1) and, on that cache miss, the per-session OverlayPath + Binding (step 3) — and would
	// leak the per-session overlay past the teardown. This resolver reads them back from the
	// record the create path Put at boot, so a post-restart Destroy disposes the real overlay.
	//
	// OFF-by-default-safe: it is wired ONLY when the gate-aware record store is present
	// (records != nil, i.e. DS_HOSTAGENT_LIVE — the SAME store the recoverer reads). Off the
	// gate records is nil, so no resolver is wired and the construction degrades to the
	// historical session_uuid-driven domain destroy (service.go: a nil resolver == today's
	// behavior, byte-identical), keeping the offline/CI composition unchanged.
	var destroyResolver libvirt.DestroyResolver
	if records != nil {
		destroyResolver = recordDestroyResolver{records: records}
	}

	// DURABLE CAPTURED-REF STORE (D29/D30, the PRODUCER/host write side) — the file-backed
	// half of the in-memory snapshotRefs registry, wired so Snapshot's captured refs survive
	// a driver restart. It is the SAME durable set the recoverer (NewSessionRecoverer above)
	// reads back into RecoveredSession.SnapshotRefs; both sides point at <OverlayDir>/.ds-sessions,
	// so the DriverService's Snapshot write and the recoverer's read-back agree on one on-disk
	// set. OFF-by-default-safe: nil off the gate (DS_HOSTAGENT_LIVE unset), so the construction
	// degrades to the in-memory-only posture and NewDriverServiceWithCapturedRefStore(..., nil) is
	// byte-identical to the prior NewDriverServiceWithDestroyResolver call.
	capturedRefs, err := libvirt.NewCapturedRefStore(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new captured-ref store: %w", err)
	}

	// Full-fan-in DriverService. recoverer/reseed carry the gate-aware crash
	// re-adoption (live); minter carries the gate-aware attach-handle mint so the live
	// path serves IssueAttachHandle (the M0 DIRECT endpoint + per-session token);
	// suspender/snapshots/exporter the lifecycle seams; destroyResolver the gate-aware
	// §4.2 destroy-durability resolver (nil off the gate ⇒ today's session_uuid-driven
	// destroy); capturedRefs the gate-aware durable captured-ref producer store (nil off the
	// gate ⇒ in-memory-only, byte-identical) — so the live path serves the full DriverService
	// over real libvirt/qemu-img.
	svc, err := libvirt.NewDriverServiceWithCapturedRefStore(host, destroyer, recoverer, reseed, minter, suspender, snapshots, exporter, destroyResolver, capturedRefs)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new driver service: %w", err)
	}
	// §4.2 DURABLE-RECORD PURGE — the SAME SessionRecordStore the create path Puts through
	// (NewHostAgentWithReadiness above) and the recoverer/destroyResolver read back, handed to
	// the service so a CONVERGED Destroy removes the torn-down session's record. Without it a
	// destroyed session's record outlives its domain and the recoverer re-adopts it on the next
	// restart (a session with no VM, which the reconciler then orphan-quarantines). nil off the
	// gate (no record was ever written), so the offline composition is byte-identical.
	svc.WithSessionRecordStore(records)
	// §4.2 PER-SESSION HOST-STATE PURGE (doc 15 §4.2; doc 06 §(b) clean teardown) — the
	// four artifacts the create path (or its orchestrator-side producer) writes BESIDE the
	// substrate the §4.2 ordering unwinds, none of which any destroy step owned, so each
	// survived every teardown:
	//
	//   - the attach TOKEN (<OverlayDir>/.ds-attach-tokens/<uuid>.json): the SAME store the
	//     post-boot serve hook mints into and the IssueAttachHandle minter reads, handed to the
	//     service in its teardown role so one on-disk token is minted, validated, and purged. Its
	//     TTL is the store's only revocation mechanism (doc 19 §7), so before this a destroyed
	//     session's D39 bearer credential stayed valid on disk for up to 15 minutes;
	//   - the CONFIG DRIVE (<OverlayDir>/<uuid>.config.iso + <uuid>.config.d): the read-only
	//     image and the staging dir holding config.pb at 0400 — the rendered EntrypointConfig
	//     with the session's injected env credentials — previously reclaimed ONLY by an operator
	//     running `ds-serve-stack.sh down --purge`;
	//   - the resolved-mode MARKER (<OverlayDir>/.ds-session-mode/<uuid>): the SAME store the
	//     EntrypointProducer wrote and the serve hook + minter read back;
	//   - the CA BUNDLE (<OverlayDir>/.ds-ca-bundles/<sanitize(ref)>.pem + .key.pem): the
	//     per-session interception CA cert AND the proxy-bound PKCS#8 PRIVATE KEY the
	//     orchestrator-side producer dropped (controlplane/liveedges.go), previously deleted by
	//     NOTHING — not even `ds-serve-stack.sh down --purge`, whose sweep predates the store.
	//     Disposed FAIL-LOUD like the token and the config drive: the residue is live
	//     interception key material, and D82 is that the CA dies at teardown.
	//
	// The token and the mode store are nil off DS_HOSTAGENT_LIVE (nothing was ever written), so
	// wiring them is byte-identical offline. The config-drive disposer is NON-nil on both sides
	// (its offline value is the no-touch no-op, the NewDomainDestroyer posture), so it is wired
	// unconditionally and still makes no filesystem call off the gate. The CA-bundle disposer is
	// the gate-aware shape (nil off DS_HOSTAGENT_LIVE, which the service treats as unwired), so
	// the offline composition is likewise byte-identical.
	//
	// The attach token is upgraded to its teardown role by TYPE ASSERTION (the
	// MintClient→MintExpiryClient posture in identityseams.go) rather than by widening
	// AttachTokenSource, so every existing token-source consumer and fake stays untouched; a nil
	// store (off the gate) asserts to a nil disposer, which the service treats as unwired.
	if disposer, ok := attachTokens.(libvirt.AttachTokenDisposer); ok {
		svc.WithAttachTokenDisposer(disposer)
	}
	svc.WithSessionModeStore(modeStore)
	configDrives, err := libvirt.NewConfigDriveDisposer(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new config drive disposer: %w", err)
	}
	svc.WithConfigDriveDisposer(configDrives)
	caBundles, err := libvirt.NewCABundleDisposer(liveCfg)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("new CA bundle disposer: %w", err)
	}
	svc.WithCABundleDisposer(caBundles)
	// MVP no-CA-inject default (DS_HOSTAGENT_SKIP_CA_INJECT=1): the canonical §4.1 spine mints
	// the per-session CA at step 5 (AFTER the step-4 CloneFromImage), so a single-box MVP create
	// arrives with NO ca_bundle_ref. Under the skip gate (where newGatedCAInjector uses the
	// SYNTHETIC CA source that resolves any ref), default an absent ref to the deterministic
	// "ca:<uuid>" so the fail-closed step-7 validate has a stable join key. OFF the gate this is
	// NOT installed, so the production fail-closed posture (absent ref => InvalidArgument, D17)
	// is unchanged. The default never overrides a ref the caller DID set.
	if os.Getenv("DS_HOSTAGENT_SKIP_CA_INJECT") == "1" {
		svc.SetCARefDefault(func(sessionUUID string) string { return "ca:" + sessionUUID })
	}
	return svc, coord, bridge, recoverer, admissionSeg, nil
}

// recordDestroyResolver adapts the durable SessionRecordStore the create path persists onto
// the libvirt.DestroyResolver the DriverService consults for a §4.2 Destroy whose host-side
// teardown state is NOT in the in-memory clone cache (the post-restart case — this process
// never cloned the session, so its DomainUUID / OverlayPath / Binding live only in the record
// the create path Put at boot). It is the composition-root bridge the import-cycle constraint
// mandates here: the libvirt driver owns the DestroyResolver seam + the SessionRecordStore
// (sessionrecord.go), and this thin daemon-root adapter joins them without the driver reaching
// for its own record store at destroy time (the resolver stays an injected seam, fakeable in
// service_test.go).
//
// The mapping mirrors what the create path wrote: SessionRecord.DomainUUID → DestroyState
// .DomainUUID (the booted libvirt domain id the wire CloneFromImageResponse never carries, so
// step 1 needs it from here), SessionRecord.Binding → DestroyState.Binding, the binding's
// OverlayPath → DestroyState.OverlayPath (the per-session qcow2 overlay step 3 disposes), and
// SessionRecord.CABundleRef → DestroyState.CABundleRef (the interception-CA bundle ref the
// §4.2 CA-bundle purge disposes — the DestroyRequest carries only the session_uuid and the
// clone cache is empty post-restart, so the record is the ref's last durable carrier at
// destroy time).
type recordDestroyResolver struct {
	records libvirt.SessionRecordStore
}

// ResolveDestroy reads the durable record for sessionUUID and lowers it into the DestroyState
// the §4.2 ordering unwinds. A MISSING record is (zero, false, nil) — a clean no-op
// convergence for an already-gone / never-recorded session (the unconditional flush still
// runs); a genuine read FAULT (a corrupt/unreadable record) is surfaced as a non-nil error so
// a teardown never silently skips disposal of a real overlay (the seam's fail-loud contract).
func (r recordDestroyResolver) ResolveDestroy(ctx context.Context, sessionUUID string) (libvirt.DestroyState, bool, error) {
	rec, found, err := r.records.Get(ctx, sessionUUID)
	if err != nil {
		return libvirt.DestroyState{}, false, fmt.Errorf("resolve destroy state for %s: %w", sessionUUID, err)
	}
	if !found {
		return libvirt.DestroyState{}, false, nil
	}
	return libvirt.DestroyState{
		DomainUUID:  rec.DomainUUID,
		OverlayPath: rec.Binding.OverlayPath,
		Binding:     rec.Binding,
		CABundleRef: rec.CABundleRef,
	}, true, nil
}

// Compile-time proof the daemon-root adapter satisfies the libvirt driver's destroy-durability
// resolver seam — so buildDriverServiceWithBridge can inject it via
// NewDriverServiceWithDestroyResolver under DS_HOSTAGENT_LIVE.
var _ libvirt.DestroyResolver = recordDestroyResolver{}

// recoveredObservedSessions builds the heartbeat's observed-session seam over the live
// SessionRecoverer: each cadence the heartbeat StateSource calls the returned func, which
// re-observes the host's resident ds-domains (virsh list) joined to their persisted session
// records and projects them onto the SHARED hypervisor.v1.ObservedSession the reconciler diffs
// against the placed records (doc 15 §5.2). This is the SAME read the crash-matrix re-adoption
// (RecoverSessions) performs — re-used here so the steady-state heartbeat and re-adoption can
// never project a resident session two different ways.
//
// Each element carries the recovered three-keys-agree binding (host index / tap / overlay) and
// a nil ObservedState. The nil state is deliberate: the recoverer is READ-ONLY re-observation
// and does not probe a domain's §3 state, so the host reports the session as "present, state
// unknown" — which the reconciler treats as neither a missing-VM re-drive (rule b — the VM IS
// in the observed set) nor a regression re-converge (rule c short-circuits on an un-pin-downable
// observation). That is exactly the no-touch convergence a live, attached session needs.
//
// A recoverer fault (e.g. virsh unreachable) is returned to the caller, which logs it and
// reports an EMPTY observed set for that one beat without failing the whole heartbeat.
func recoveredObservedSessions(recoverer libvirt.SessionRecoverer, hostID string) observedSessionsFunc {
	return func(ctx context.Context) ([]*hypervisorv1.ObservedSession, error) {
		recovered, err := recoverer.RecoverSessions(ctx, hostID)
		if err != nil {
			return nil, err
		}
		out := make([]*hypervisorv1.ObservedSession, 0, len(recovered))
		for _, rs := range recovered {
			out = append(out, &hypervisorv1.ObservedSession{
				SessionUuid:      rs.SessionUUID,
				DomainUuid:       rs.DomainUUID,
				HostSessionIndex: rs.Binding.HostSessionIndex,
				TapName:          rs.Binding.TapName,
				OverlayPath:      rs.Binding.OverlayPath,
				// ObservedState left nil: re-observation does not probe the §3 state, so the
				// session is reported "present, state unknown" — present (no rule-b re-drive),
				// un-pin-downable (no rule-c regression). See the doc comment above.
			})
		}
		return out, nil
	}
}

// entrypointFacts lifts the daemon's host-resolved bring-up config into the
// session-independent EntrypointFacts the gap-1 producer folds into every per-session
// EntrypointConfig (the host identity + the launch/egress/event-socket/token references). The
// per-session bits (the session UUID, the recorded Binding, the fetched opaque role-overlay
// bytes) are filled by the producer per create. References only, never material (D17/D39).
func entrypointFacts(cfg config) libvirt.EntrypointFacts {
	// The default mode is re-derived from the validated flag string (parseConfig already
	// fail-louded a bad value, so this never errors here — the empty/garbage cases are
	// caught at parse time). The zero value (structured) is the historical default.
	defaultMode, _ := libvirt.ParseSessionMode(cfg.sessionMode)
	return libvirt.EntrypointFacts{
		HostID: cfg.hostID,
		Launch: libvirt.LaunchSpecInput{
			Command: cfg.launchCommand,
			// ARM live-text on the STRUCTURED launch argv when the host live-text gate is set:
			// append --include-partial-messages so the in-guest CC emits the typing-delta
			// stream_event records the structured adapter renders as live ChatDeltas (the
			// U-PARTIALS-ARM runtime-arming half; doc serpent-cli-mvp/06 Layer 1, D145). The
			// flag is a CC-ism that stays in the host-side launch-argv shaping, NEVER on the
			// orchestrator wire (D38). DEFAULT (cfg.liveText false) returns the args UNCHANGED,
			// so the structured launch argv is BYTE-IDENTICAL to today. A session a per-session
			// overlay hint resolves to SessionModeTerminal has this flag STRIPPED by the terminal
			// launch-mode transform (applyLaunchMode → stripStreamJSONArgs), so the flag is NEVER
			// present in a terminal (PTY) argv — the per-session resolved-mode contract.
			Args:       libvirt.ArmStructuredLiveText([]string(cfg.launchArgs), cfg.liveText),
			Env:        []string(cfg.launchEnv),
			WorkingDir: cfg.workingDir,
		},
		// The per-host DEFAULT session launch mode (the -session-mode flag). A per-session
		// overlay hint (DS_SESSION_MODE=) overrides it (resolved host-side in the producer,
		// D38). InitialWindow is left zero so a terminal session uses the 80x24 default
		// (libvirt.DefaultInitialWindow); a host that needs a different geometry sets it here.
		DefaultMode: defaultMode,
		// The daemon-pinned FALLBACK posture (doc 13 §2). A concrete posture is REQUIRED by the
		// builder (UNSPECIFIED is rejected), so the M0 daemon pins the LOCKED default-deny here as
		// the session-INDEPENDENT host fallback. The orchestrator-resolved PER-SESSION posture now
		// rides the create as data (CreateRequest.Posture, threaded through the gap-1 producer's
		// ProduceConfig) and WINS over this pin when concrete; an UNSPECIFIED per-create posture
		// ("none supplied") falls back to THIS LOCKED pin — so a create that supplies no posture is
		// byte-identical to today, preserving M0 default-deny. No new flag: the per-session posture
		// is per-create request data, not a host bring-up fact.
		Posture:         runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED,
		EventSocketPath: cfg.eventSocketPath,
		// Egress references only, never material (D17/D39). CABundlePath is the
		// posture-(b) cred-swap RECONCILE: it is the guest-filesystem PATH the in-guest
		// ds-entrypoint writes the runtime's NODE_EXTRA_CA_CERTS/SSL_CERT_FILE to
		// (vm/entrypoint/env.go ownedProxyEnv), so the launched CC's Node TLS stack trusts
		// the per-session interception CA the egress gateway terminates with. It is sourced
		// from the SAME DS_GUEST_INTERCEPT_CA_PATH that drives the InjectCA --upload target
		// (trustanchor.go): the cert is DELIVERED to this path and the guest is told to
		// TRUST this path from ONE env, so producer (the InjectCA write) and consumer
		// (NODE_EXTRA_CA_CERTS) can never name two different files. UNSET (the default /
		// opaque / fat / m0 non-swap, and every CI / sandbox / unit-test path) ⇒ empty ⇒
		// NODE_EXTRA_CA_CERTS unset ⇒ BYTE-IDENTICAL to today. The fixed path's cert is
		// injected fail-closed BEFORE boot (cainject.go step 7 ≺ step 8), so the runtime
		// never starts pointing NODE_EXTRA_CA_CERTS at an absent file. References only — the
		// CA private key never enters the guest and is never in this path (a PATH, not material).
		Egress: libvirt.EgressWiringInput{
			HTTPProxy:    cfg.httpProxy,
			HTTPSProxy:   cfg.httpsProxy,
			CABundlePath: libvirt.GuestInterceptCAPathFromEnv(),
		},
		SessionTokenEndpoint: cfg.sessionTokenEndpoint,
		// Routed-tap posture: when set, the producer ALSO renders the per-session guest
		// static net config (ds-net.env) onto the config-drive so the guest addresses its
		// routed tap (U4). DEFAULT false keeps the SLIRP/offline boot path byte-identical.
		// OR the DS_ROUTED_TAP env in so this net-config gate agrees with the booter's
		// render gate (NewLiveBooter does the same flag-OR-env), i.e. the -routed-tap flag
		// OR the env enables BOTH in lockstep.
		RoutedTap: cfg.routedTap || libvirt.RoutedTapEnabled(),
	}
}

// attachServeHook adapts the gap-3 AttachBridge into the libvirt create path's post-boot
// hook (libvirt.PostBootHook): after a successful boot it reads the per-session AF_VSOCK
// guest CID from the recorded binding (Binding.VsockCID, derived in alloc.go — the host
// alone knows it; the orchestrator stays runtime-ignorant) and stands up the per-session
// serving leg over vsock (off DS_HOSTAGENT_LIVE this launches nothing). It is BEST-EFFORT:
// a serve fault is logged and swallowed (the booted session stands; the attach leg can be
// retried), so wiring it never changes the create's boot failure semantics. The adapter —
// NOT the libvirt tree — is where AttachBridge.Serve is called, so the import direction
// stays hostagent → libvirt.
func attachServeHook(bridge *hostagent.AttachBridge, tokens libvirt.AttachTokenSource, modes libvirt.SessionModeStore, cidRegistry *sessionCIDRegistry, log *slog.Logger) libvirt.PostBootHook {
	return func(ctx context.Context, sessionUUID string, binding libvirt.Binding) error {
		if binding.VsockCID == 0 {
			// A booted session whose binding has no derived vsock CID cannot have a serving
			// leg stood up — log and skip (non-fatal; the session is still booted). The
			// allocator derives the CID at create (alloc.go); a zero here is a pre-Allocate /
			// legacy binding, not a live one.
			log.Warn("attach serving leg NOT stood up: recorded binding has no derived vsock CID",
				"session", sessionUUID)
			return nil
		}
		// U5 authz: register this session's unforgeable peer CID -> session so the D22
		// session-token shim authorizes the guest's boot-time token fetch by its
		// connecting CID (and serves ONLY this session's token). Done at post-boot,
		// before the guest's ds-entrypoint dials the shim, so a legitimate same-session
		// fetch resolves; UnbindSession (the destroy hook) removes it at teardown. Bind
		// is independent of the offline/live attach-serve gate below — the token shim
		// runs even when the attach serving leg no-launches offline. Idempotent on a
		// retried create (the CID re-derives the SAME value).
		cidRegistry.Bind(binding.VsockCID, sessionUUID)
		// Mint the per-session attach token BEFORE serving. AttachBridge.Serve fail-closes
		// if the token store is absent (the ds-hostbridge child validates against it), but
		// the libvirt minter only writes the token at IssueAttachHandle — which a client
		// calls AFTER this post-boot hook. Without a create-time mint the serving child
		// would never launch. The mint is idempotent (TokenFor writes-or-returns the same
		// token within the TTL over the SHARED store), so IssueAttachHandle hands the client
		// the SAME token the serving child validates against. Off DS_HOSTAGENT_LIVE tokens is
		// nil and Serve no-launches anyway, so the mint is skipped.
		if tokens != nil {
			if _, _, err := tokens.TokenFor(ctx, sessionUUID); err != nil {
				log.Warn("attach serving leg NOT stood up: per-session token mint failed",
					"session", sessionUUID, "err", err)
				return nil
			}
		}
		// Read the RESOLVED mode the EntrypointProducer persisted (the SINGLE source the
		// IssueAttachHandle minter also reads), so the serving child serves the SAME
		// surface the handle transport tag advertises (doc 04 §5 drift guard). An absent
		// marker / nil store reads structured (the byte-identical default — no --mode flag
		// on the child). A CORRUPT marker is fail-loud: skip the serve (better no attach
		// leg than a structured child for a pty session the handle will tag RAW_TERMINAL).
		mode := libvirt.SessionModeStructured
		if modes != nil {
			resolved, _, err := modes.ModeFor(ctx, sessionUUID)
			if err != nil {
				log.Warn("attach serving leg NOT stood up: resolved-mode read failed",
					"session", sessionUUID, "err", err)
				return nil
			}
			mode = resolved
		}
		out, err := bridge.Serve(ctx, sessionUUID, binding.VsockCID, mode)
		if err != nil {
			log.Warn("attach serving leg stand-up failed (non-fatal; session booted, attach leg can be retried)",
				"session", sessionUUID, "err", err)
			return nil
		}
		log.Info("attach serving leg",
			"session", sessionUUID, "uds", out.UDSPath, "launched", out.Launched, "mode", mode.String())
		return nil
	}
}

// attachReapHook adapts the gap-3 AttachBridge into the libvirt §4.2 destroy path's
// post-destroy hook (libvirt.PostDestroyHook): after a session's host-local objects are
// torn down it REAPS that session's serving child (AttachBridge.Destroy — SIGINT + reap the
// ds-hostbridge process, unlink the per-session UDS). Off DS_HOSTAGENT_LIVE the bridge owns
// no child, so this is a clean no-op. The reap is best-effort: AttachBridge.Destroy is
// idempotent and infallible (it returns nothing), so this adapter returns nil — a torn-down
// session's serving leg is reaped at DESTROY, not left dangling until daemon Shutdown. The
// adapter — NOT the libvirt tree — calls AttachBridge.Destroy, so the import direction stays
// hostagent → libvirt (the attachServeHook posture mirrored on the teardown side).
func attachReapHook(bridge *hostagent.AttachBridge, cidRegistry *sessionCIDRegistry) libvirt.PostDestroyHook {
	return func(_ context.Context, sessionUUID string) error {
		// U5 authz: drop this session's peer CID -> session mapping so the D22
		// session-token shim fail-closes any connection from the (now-defunct) CID
		// after teardown — a torn-down session's CID stops resolving. CIDs are never
		// recycled (alloc.go's never-recycled monotonic index), so this is
		// belt-and-suspenders, but it keeps the resolvable set to LIVE sessions only.
		// Best-effort + idempotent (an unknown session is a no-op), matching Destroy.
		cidRegistry.UnbindSession(sessionUUID)
		bridge.Destroy(sessionUUID)
		return nil
	}
}

// hookFaultSink is the daemon composition root's DURABLE out-of-band sink for a swallowed
// best-effort hook fault (libvirt.HookFaultObserver). It routes a swallowed create-path
// post-boot serving-leg stand-up fault (HookPostBoot) OR a swallowed §4.2 post-destroy
// serving-leg reap fault (HookPostDestroy) through the daemon's STRUCTURED slog logger at WARN
// with attributed fields (hook / session / err), instead of the libvirt default's bare
// log.Printf line — so an operator's log pipeline can index a silently-swallowed serving-leg
// fault by hook + session. It NEVER re-enters the verdict: a create still returns its routable
// verdict and a Destroy still returns its §4.2 result — a hook fault is observability, not a
// gate. Installed on BOTH the Creator (HostAgent.WithHookFaultObserver) and the Destroyer
// (Destroyer.WithHookFaultObserver) so both directions' swallowed faults land in one sink.
func hookFaultSink(log *slog.Logger) libvirt.HookFaultObserver {
	return func(obs libvirt.HookFault) {
		log.Warn("serving-leg hook fault (swallowed from the verdict, surfaced out-of-band)",
			"hook", obs.Hook.String(), "session", obs.SessionUUID, "err", obs.Err)
	}
}

// logger builds the daemon's structured logger (the same handler run uses), so the
// composition-root adapters (the post-boot hook) have a logger without threading run's one
// through every constructor.
func logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// substrateMode names the active substrate for the bring-up log line.
func substrateMode() string {
	if libvirt.LiveEnabled() {
		return "LIVE (overlay-create.sh + virsh, DS_HOSTAGENT_LIVE=1)"
	}
	return "offline (no-touch; DS_HOSTAGENT_LIVE unset)"
}
