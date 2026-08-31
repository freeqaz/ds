// Command ds-hostbridge is the minimal host-agent transport bridge binary (M0,
// direct client→host-agent, no relay). It wraps a Claude Code process's stdin/
// stdout — the stream-json wire — projects CC stdout through the wrapper adapter
// into attach.v1 deltas served over a WatchSession-style event stream, and
// accepts writer-seat input + ask-response grants back through the wrapper driver
// onto CC stdin. It exercises the D79 AttachHandle seam (DRIVE-PROTOCOL.md tier
// 2; docs/15 §5.3-5.4; D38/D61/D79).
//
// OSS (D15/D25): the CLI/host-agent surface is open. Stdlib-only (client/go.mod).
//
// SYNTHETIC vs LIVE. The default mode (--self-check) wires the bridge to an
// in-process loopback transport and a fixture-fed synthetic CC stdout (a static
// stream-json sample), proving the seam end to end without any live process —
// the same posture client/goldentrace/e2e holds. The real-container path (a CC
// process inside scripts/cc_sandbox.sh, stdio bridged across the container
// boundary to a client outside) is the DEFERRED MANUAL STEP, armed only behind
// DS_E2E_LIVE=1 (hostbridge.RunLiveBridge). No live podman/claude/cia is ever
// launched by this binary unless an operator sets that gate.
//
// SERVE MODE (gap-3 carrier, the host-agent serving leg). --serve-uds stands up
// the production carriage: the host agent serves a HOST-LOCAL UDS (the address
// the client's SocketTransport.Dial opens — serpent-tui maps the proto DIRECT
// endpoint to hostbridge.TransportUnix), validates the presented attach token
// against the SAME <OverlayDir>/.ds-attach-tokens/<uuid>.json store the libvirt
// attach-handle minter writes (mint there, validate here, one shared store), and
// BRIDGES the served session's CC stdio to the guest over AF_VSOCK
// (--guest-vsock-cid:--guest-vsock-port) — the host→guest carriage. The control
// channel rides virtio-vsock (m1-live-session-transport spike): no tap, no guest
// IP, no nft on the attach path (those stay the parallel nft4 egress lane). The
// AF_VSOCK dial is a RAW SYSCALL connect (vsockdial_linux.go) — client/ is
// stdlib-only (D80), so there is no x/sys or third-party vsock package. The
// Server's D61 writer-seat arbitration is enforced unchanged. The real in-guest
// vsock listener (the guest-side ds-attachfwd forwarder onto the in-VM event
// socket) is U5/U6 / DS_HOSTAGENT_LIVE / operator-validated; this binary only
// dials the guest CID and never launches a VM, container, claude, or cia. The
// serve_test.go battery drives the whole mode against an in-process FAKE guest
// conn feeding a synthetic stream-json — zero live process, no real vsock — so the
// seam is proven the way the rest of hostbridge was.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// selfCheckStream is a minimal static stream-json sample standing in for a CC
// process's stdout in --self-check mode — NOT a fixture (this binary lives under
// cmd/, which has no read path to client/fixtures/ at runtime, and must not
// depend on test-only assets). It is the smallest stream that drives the adapter
// through init + an assistant turn + a result, proving the loopback seam without
// any live process. Synthetic by construction (D50): no real ids, paths, or
// creds.
const selfCheckStream = `{"type":"system","subtype":"init","session_id":"00000000-0000-4000-8000-0000000000aa","uuid":"00000000-0000-4000-8000-0000000000a0","cwd":"/work","claude_code_version":"2.1.173","model":"claude-sonnet-4-6","permissionMode":"default","apiKeySource":"none","tools":["Bash"],"agents":[],"slash_commands":[],"skills":[]}
{"type":"assistant","session_id":"00000000-0000-4000-8000-0000000000aa","uuid":"00000000-0000-4000-8000-0000000000a1","parent_tool_use_id":null,"request_id":"req_selfcheck_0001","message":{"id":"msg_selfcheck_0001","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"hello from the synthetic self-check stream"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":8}}}
{"type":"result","subtype":"success","session_id":"00000000-0000-4000-8000-0000000000aa","uuid":"00000000-0000-4000-8000-0000000000a2","is_error":false,"num_turns":1,"duration_ms":120,"total_cost_usd":0.0001,"result":"done"}`

// serveLiveText is the serve-UDS live-text gate the --include-partial-messages flag
// sets in main(): when true, runServeUDS builds the bridge's default adapter WithPartials
// so the runtime's typing deltas project as live ChatDeltas (the serpent-CLI live-text
// MVP, paired with the host arming --include-partial-messages on the structured launch
// argv). It is a package var (not a runServeUDS parameter) so runServeUDS keeps its
// 5-arg signature — the offline arg-validation test drives it unchanged. DEFAULT false ⇒
// the serve-UDS adapter construction is byte-identical to today.
var serveLiveText bool

func main() {
	fs := flag.NewFlagSet("ds-hostbridge", flag.ExitOnError)
	selfCheck := fs.Bool("self-check", false,
		"run the synthetic loopback seam end to end (no live process) and exit")
	socketCheck := fs.Bool("socket-self-check", false,
		"run the synthetic FRAMED-UDS seam end to end over a real socket in a tmpdir (no live process) and exit")
	live := fs.Bool("live", false,
		"run the real-container tier-2 attach path (deferred manual step; requires DS_E2E_LIVE=1)")
	sessionUUID := fs.String("session-uuid", "self-check-session", "session UUID the bridge serves")
	endpoint := fs.String("endpoint", "loopback://self-check",
		"endpoint address the AttachHandle advertises (direct transport)")
	driveText := fs.String("drive", "", "optional: drive this text as a writer-seat DriveInput in --self-check / --socket-self-check")
	serveUDS := fs.String("serve-uds", "",
		"SERVE MODE: host-local UDS path to serve the attach.v1 seam on (the address the client's SocketTransport dials)")
	guestVsockCID := fs.Uint("guest-vsock-cid", 0,
		"SERVE MODE: the in-guest AF_VSOCK context id (Binding.VsockCID) the served session's CC stdio is bridged to")
	guestVsockPort := fs.Uint("guest-vsock-port", 0,
		"SERVE MODE: the in-guest AF_VSOCK attach port (the carriage the in-guest forwarder listens on; e.g. 4242)")
	sessionTokenFile := fs.String("session-token-file", "",
		"SERVE MODE: path to the minter's <OverlayDir>/.ds-attach-tokens/<uuid>.json the presented attach token is validated against")
	mode := fs.String("mode", "structured",
		"SERVE MODE surface: structured (attach.v1 event stream, the default — UNCHANGED) | terminal (raw pty byte duplex + resize for serpent claude --vm)")
	liveText := fs.Bool("include-partial-messages", os.Getenv("DS_HOSTBRIDGE_LIVE_TEXT") == "1",
		"SERVE MODE: build the structured adapter WithPartials so the runtime's typing deltas project as live ChatDeltas (the serpent-CLI live-text MVP; paired with the host arming --include-partial-messages on the structured launch argv). DEFAULT false keeps the adapter construction BYTE-IDENTICAL to today. Ignored for --mode terminal (the raw pty surface). Also DS_HOSTBRIDGE_LIVE_TEXT=1")
	_ = fs.Parse(os.Args[1:])

	switch {
	case *serveUDS != "":
		// The serving surface is the RESOLVED session mode the host agent passes through
		// (single-sourced from the libvirt SessionModeStore — the SAME resolution the handle
		// transport tag and LaunchSpec.stdio derive from, so the three cannot drift). An
		// unrecognized --mode is a hard config error (never a silent default to structured).
		serveMode, perr := parseServeMode(*mode)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "ds-hostbridge: %v\n", perr)
			os.Exit(1)
		}
		switch serveMode {
		case serveModeTerminal:
			if err := runServeTerminalUDS(*sessionUUID, *serveUDS, uint32(*guestVsockCID), uint32(*guestVsockPort), *sessionTokenFile); err != nil {
				fmt.Fprintf(os.Stderr, "ds-hostbridge: serve-uds (terminal) failed: %v\n", err)
				os.Exit(1)
			}
		default:
			// Fold the --include-partial-messages flag (default DS_HOSTBRIDGE_LIVE_TEXT)
			// onto the serve-UDS path so the default adapter is built WithPartials. It rides a
			// package var the flag sets — runServeUDS keeps its 5-arg signature so the offline
			// arg-validation test (which probes the fail-closed argument checks before any
			// bridge build) drives it unchanged. DEFAULT false ⇒ adapter construction
			// byte-identical to today.
			serveLiveText = *liveText
			if err := runServeUDS(*sessionUUID, *serveUDS, uint32(*guestVsockCID), uint32(*guestVsockPort), *sessionTokenFile); err != nil {
				fmt.Fprintf(os.Stderr, "ds-hostbridge: serve-uds failed: %v\n", err)
				os.Exit(1)
			}
		}
	case *live:
		if err := runLive(*sessionUUID, *endpoint); err != nil {
			fmt.Fprintf(os.Stderr, "ds-hostbridge: %v\n", err)
			os.Exit(1)
		}
	case *socketCheck:
		if err := runSocketSelfCheck(*sessionUUID, *driveText); err != nil {
			fmt.Fprintf(os.Stderr, "ds-hostbridge: socket-self-check failed: %v\n", err)
			os.Exit(1)
		}
	case *selfCheck:
		if err := runSelfCheck(*sessionUUID, *endpoint, *driveText); err != nil {
			fmt.Fprintf(os.Stderr, "ds-hostbridge: self-check failed: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "ds-hostbridge — minimal host-agent transport bridge (M0)")
		fmt.Fprintln(os.Stderr, "  --self-check         synthetic loopback seam (no live process)")
		fmt.Fprintln(os.Stderr, "  --socket-self-check  synthetic framed-UDS seam over a real socket (no live process)")
		fmt.Fprintln(os.Stderr, "  --serve-uds PATH     SERVE MODE: serve the attach seam on a host-local UDS, bridged to the guest over")
		fmt.Fprintln(os.Stderr, "                       AF_VSOCK --guest-vsock-cid:--guest-vsock-port,")
		fmt.Fprintln(os.Stderr, "                       validating the attach token against --session-token-file")
		fmt.Fprintln(os.Stderr, "  --mode SURFACE       SERVE MODE surface: structured (attach.v1, default) | terminal (raw pty + resize)")
		fmt.Fprintln(os.Stderr, "  --live               real-container path (deferred; needs DS_E2E_LIVE=1)")
		fmt.Fprintln(os.Stderr, "see client/hostbridge/README.md")
		os.Exit(2)
	}
}

// runLive is the gated real-container path. Without DS_E2E_LIVE=1 it returns
// hostbridge.ErrLiveGateUnset and launches nothing — the live wiring is the
// deferred manual step (DRIVE-PROTOCOL.md tier 2).
func runLive(sessionUUID, endpoint string) error {
	return hostbridge.RunLiveBridge(context.Background(), hostbridge.LiveConfig{
		SessionUUID: sessionUUID,
		Endpoint:    endpoint,
	})
}

// --- serve mode: host-local UDS bridged to the GuestIP:4242 TCP leg -----------

// persistedAttachToken is the on-disk shape the libvirt attach-handle minter
// writes (orchestrator/internal/hypervisor/libvirt/attachminter.go: one JSON file
// per session at <OverlayDir>/.ds-attach-tokens/<uuid>.json). The serving leg
// reads the SAME shape to validate an attach against the minted token — mint
// there, validate here, one shared store (D80: NON-test code never imports the
// libvirt tree; this is the documented file contract replicated at the seam, the
// same posture cabundlesource's ref→bytes store holds). The hex Token is the
// AuthMaterial.Token a client presents on the wire.
type persistedAttachToken struct {
	Token     string `json:"token"`      // hex-encoded opaque bearer material (D39)
	ExpiresAt int64  `json:"expires_at"` // unix seconds; credential expiry
}

// readSessionToken reads + validates the minter's token file. It fails CLOSED:
// a missing/unreadable/undecodable file, an empty token, or non-hex material is
// an ERROR (never a silent empty token that would attach anything) — the serving
// leg refuses to stand up a session it cannot authenticate. The hex string is
// returned verbatim as the session's AuthMaterial token (the client presents the
// same hex string); the bytes are validated as hex so a corrupt file fails here,
// not at the first attach.
func readSessionToken(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("serve-uds requires --session-token-file (the minter's .ds-attach-tokens/<uuid>.json)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read session token file %q: %w", path, err)
	}
	var tok persistedAttachToken
	if err := json.Unmarshal(data, &tok); err != nil {
		return "", fmt.Errorf("decode session token file %q: %w", path, err)
	}
	if tok.Token == "" {
		return "", fmt.Errorf("session token file %q carries an empty token (fail-closed)", path)
	}
	if _, err := hex.DecodeString(tok.Token); err != nil {
		return "", fmt.Errorf("session token file %q token is not hex (corrupt store): %w", path, err)
	}
	return tok.Token, nil
}

// serveUDSConfig parameterizes the serve-UDS core so the CLI entrypoint and the
// offline test drive the SAME helper. dialGuest is the host→guest carriage resolver:
// production dials AF_VSOCK guestCID:port (dialVsock, vsockdial_linux.go); a test
// injects an in-process fake guest conn through the same dialGuest seam (a real
// socketpair, zero live process, no real vsock). When dialGuest is nil the helper falls
// back to net.Dial("tcp", guestAddr) — the in-process FAKE-TCP-listener path the existing
// serve_test.go drives (a real loopback socket, still no live process); production NEVER
// sets guestAddr (it always wires dialGuest = the vsock dial). adapterClock pins the
// projection clock when set (test determinism); nil ⇒ the adapter's wall clock.
type serveUDSConfig struct {
	sessionUUID string
	dialGuest   func() (net.Conn, error) // host→guest carriage dial (vsock in production; a fake conn in tests)
	// guestAddr is the legacy in-process fake-TCP-listener address the offline serve_test.go
	// dials when dialGuest is unset (a real loopback socketpair, no live process). It is
	// NOT a production path — the live carriage is always the AF_VSOCK dialGuest above.
	guestAddr    string
	udsPath      string
	sessionToken string // the minter's hex token; the session's AuthMaterial token
	adapterClock func() time.Time
	// liveText builds the bridge's DEFAULT adapter WithPartials so the runtime's typing
	// deltas project as live ChatDeltas (the serpent-CLI live-text MVP, paired with the
	// host arming --include-partial-messages on the structured launch argv). DEFAULT false
	// keeps the adapter construction byte-identical to today. Honored ONLY when adapterClock
	// is unset (the production path that lets NewBridge build the default adapter); a test
	// that pins adapterClock injects its OWN adapter and controls WithPartials itself.
	liveText bool
}

// runServeUDS is the serve-mode CLI entrypoint: it reads + validates the token
// file, then stands up the host-local UDS attach server bridged to the AF_VSOCK
// guestCID:port carriage leg, blocking until the bridged session ends (guest EOF /
// pump error) or the process is signalled. It launches NO VM/container/claude/cia
// — it only dials AF_VSOCK guestCID:port (a raw-syscall connect, vsockdial_linux.go;
// the in-guest forwarder is the operator / DS_HOSTAGENT_LIVE leg, U5/U6).
func runServeUDS(sessionUUID, udsPath string, guestVsockCID, guestVsockPort uint32, sessionTokenFile string) error {
	if udsPath == "" {
		return fmt.Errorf("serve-uds requires a non-empty --serve-uds path")
	}
	if guestVsockCID == 0 {
		return fmt.Errorf("serve-uds requires --guest-vsock-cid (the in-guest AF_VSOCK context id; the derived per-session CID)")
	}
	if guestVsockPort == 0 {
		return fmt.Errorf("serve-uds requires --guest-vsock-port (the in-guest AF_VSOCK attach port)")
	}
	token, err := readSessionToken(sessionTokenFile)
	if err != nil {
		return err
	}
	cfg := serveUDSConfig{
		sessionUUID: sessionUUID,
		// Production carriage: dial the guest over AF_VSOCK (raw syscall; linux-only). The
		// real connect reaches a live guest only on the KVM box (DS_HOSTAGENT_LIVE); the
		// offline test injects a fake conn through this same seam, so no real vsock is dialed
		// in a test.
		dialGuest:    func() (net.Conn, error) { return dialVsock(guestVsockCID, guestVsockPort) },
		udsPath:      udsPath,
		sessionToken: token,
		// serveLiveText is the package-level --include-partial-messages gate the CLI set; it
		// builds the default adapter WithPartials. DEFAULT false ⇒ byte-identical to today.
		liveText: serveLiveText,
	}
	return serveUDS(context.Background(), cfg)
}

// serveUDS is the offline-testable core of serve mode. It:
//
//  1. dials the host→guest carriage (cfg.dialGuest — AF_VSOCK guestCID:port in
//     production); the single bidirectional stream carries the guest CC's stdout
//     (stream-json, read by Pump) and the writer-seat input (CC stdin, written by
//     the bridge);
//  2. builds the Bridge over that conn (ccStdin = the guest conn write side),
//     registers the session on a Server whose AuthMaterial token is PINNED to the
//     minter's file token (WithTokenMinter), so the SAME store mint validates here;
//  3. serves the host-local UDS with hostbridge.ServeBridge (the framed-UDS
//     carrier the client's SocketTransport dials), enforcing the D61 writer-seat
//     arbitration the Server already implements;
//  4. pumps the guest's stdout through the bridge — projecting CC stdout into
//     attach.v1 deltas fanned to every attached client — until the guest carriage
//     leg EOFs or ctx is cancelled, then tears the UDS server down.
//
// No re-encoding, no second history ring, no NFT rule, no overlay mutation: the
// bridge/Server/SocketTransport are reused verbatim; this helper only wires the
// UDS↔guest-vsock carriage and the token-file-backed Server.
// guestCarriageDialDeadline bounds how long dialGuestWithRetry retries the
// host→guest carriage connect before failing closed. A package var so offline
// tests can shrink it to fail fast on a synthetic dial fault.
var guestCarriageDialDeadline = 30 * time.Second

// dialGuestWithRetry calls dial repeatedly with a short backoff until it succeeds
// or guestCarriageDialDeadline elapses (or ctx is cancelled) — absorbing the boot
// race where the in-guest forwarder is not yet listening when the host-agent
// stands the serving leg up.
func dialGuestWithRetry(ctx context.Context, dial func() (net.Conn, error)) (net.Conn, error) {
	dl := time.Now().Add(guestCarriageDialDeadline)
	for attempt := 1; ; attempt++ {
		conn, err := dial()
		if err == nil {
			return conn, nil
		}
		if time.Now().After(dl) {
			return nil, fmt.Errorf("after %s, %d attempts: %w", guestCarriageDialDeadline, attempt, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func serveUDS(ctx context.Context, cfg serveUDSConfig) error {
	if cfg.sessionToken == "" {
		// Defence in depth: runServeUDS already fails closed on an empty token, but
		// a direct caller must never stand up an un-authenticated session.
		return fmt.Errorf("serve-uds: empty session token (fail-closed)")
	}

	// (1) Dial the host→guest carriage. In production this is the AF_VSOCK guestCID:port
	// dial (dialGuest = dialVsock, a raw-syscall connect); the in-guest forwarder is the
	// operator / DS_HOSTAGENT_LIVE leg (U5/U6). When dialGuest is unset the helper falls
	// back to the legacy fake-TCP-listener path (net.Dial("tcp", guestAddr)) the offline
	// serve_test.go drives — an in-process socketpair, no live process, no live vsock — so
	// the same core is proven offline.
	dial := cfg.dialGuest
	if dial == nil {
		if cfg.guestAddr == "" {
			return fmt.Errorf("serve-uds: no guest carriage dialer and no fallback address (fail-closed)")
		}
		dial = func() (net.Conn, error) { return net.Dial("tcp", cfg.guestAddr) }
	}
	// BOOT-RACE RETRY (live-found 2026-06-16): the in-guest ds-attachfwd forwarder
	// is started by systemd at guest boot and may not yet be LISTENING on its vsock
	// carriage when the host-agent stands the serving leg up right after clone — a
	// single dial then times out and the per-session UDS is never served. Retry the
	// carriage dial with a short backoff up to guestCarriageDialDeadline; only then
	// fail closed.
	guest, err := dialGuestWithRetry(ctx, dial)
	if err != nil {
		return fmt.Errorf("serve-uds: dial guest attach carriage: %w", err)
	}
	defer guest.Close()

	// (2) Bridge over the guest conn + a token-pinned Server. The bridge's ccStdin
	// is the guest conn (writer-seat input lands on the guest CC's stdin over the
	// TCP leg); Pump (4) reads the guest CC's stdout from the same conn.
	// LiveText arms the DEFAULT adapter WithPartials so the runtime's typing deltas project
	// as live ChatDeltas (paired with the host --include-partial-messages on the structured
	// launch argv). DEFAULT false keeps the adapter construction byte-identical to today.
	// NewBridge honors LiveText only on the Adapter==nil default path, so a test that pins
	// adapterClock (injecting its own clock-pinned adapter) is unaffected.
	bcfg := hostbridge.BridgeConfig{LiveText: cfg.liveText}
	if cfg.adapterClock != nil {
		bcfg.Adapter = claudecode.New(claudecode.WithClock(cfg.adapterClock))
	}
	bridge := hostbridge.NewBridge(guest, bcfg)
	// MVP NO-AUTH posture (DS_HOSTBRIDGE_NO_AUTH=1): accept any presented attach token.
	// On the single-box MVP the orchestrator's attach.Issuer mints the handle token with
	// crypto/rand (a SOURCE different from this serving leg's per-session token store), so
	// the constant-time match would always fail ("invalid attach auth material") even
	// though both legs are correct in isolation — single-sourcing that credential across
	// the orchestrator issuer + the host-agent token store is the deferred real-auth phase.
	// The gate is OFF by default (the fail-closed token check is the production behavior);
	// the writer-seat arbitration + every other handle check still run unchanged.
	noAuth := os.Getenv("DS_HOSTBRIDGE_NO_AUTH") == "1"
	srv := hostbridge.NewServer(
		// Pin the session's AuthMaterial token to the minter's file token so an
		// attach is accepted iff its token matches the shared store (Server.validate
		// compares in constant time). A wrong token is ErrAuthInvalid — rejected
		// before any seat is granted. Bypassed under the MVP no-auth gate above.
		hostbridge.WithTokenMinter(func() string { return cfg.sessionToken }),
		hostbridge.WithNoAuth(noAuth),
	)
	srv.AddSession(cfg.sessionUUID, bridge)

	// (3) Serve the host-local UDS. ServeBridge binds the UDS and runs the framed
	// accept loop until ctx is cancelled or the listener errors; run it alongside
	// the pump so a guest-EOF (4) can tear it down.
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hostbridge.ServeBridge(serveCtx, cfg.udsPath, srv) }()
	if err := waitForSocket(cfg.udsPath, 5*time.Second); err != nil {
		return err
	}

	// (4) Pump the guest CC's stdout through the bridge until the guest TCP leg
	// EOFs (session end) or ctx is cancelled. On return the UDS server is torn down.
	pumpErr := bridge.Pump(ctx, guest)
	cancelServe()
	if se := <-serveErr; se != nil && !isExpectedServeShutdown(se) {
		// A genuine bind/serve fault (e.g. UDS path unusable) outranks a clean pump
		// end; surface it. A clean listener close on teardown is expected, not an error.
		return fmt.Errorf("serve-uds: serve UDS %q: %w", cfg.udsPath, se)
	}
	if pumpErr != nil && !errors.Is(pumpErr, context.Canceled) {
		return fmt.Errorf("serve-uds: pump guest stream: %w", pumpErr)
	}
	return nil
}

// isExpectedServeShutdown reports whether a ServeBridge return is the ordinary
// listener-closed teardown (ctx cancel closes the UDS, Accept returns
// net.ErrClosed) rather than a real bind/serve fault. The expected shutdown must
// not mask a clean pump end with a spurious error.
func isExpectedServeShutdown(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// captureWriter records the bytes the bridge writes to CC stdin so --self-check
// can report what landed on the wire (it has no real CC to consume them).
type captureWriter struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *captureWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.WriteString(string(p))
}

func (c *captureWriter) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// runSelfCheck stands the bridge up over the synthetic stream + an in-process
// loopback transport, attaches a WRITER, drives the static CC stdout through, and
// (optionally) drives a DriveInput back through the writer seat — printing the
// projected deltas and the bytes the driver wrote to CC stdin. It is the
// always-safe, no-live-process proof of the seam.
func runSelfCheck(sessionUUID, endpoint, driveText string) error {
	var ccStdin captureWriter
	bridge := hostbridge.NewBridge(&ccStdin, hostbridge.BridgeConfig{
		// Pin the adapter clock so the self-check output is deterministic.
		Adapter: claudecode.New(claudecode.WithClock(deterministicClock())),
	})
	srv := hostbridge.NewServer()
	srv.AddSession(sessionUUID, bridge)

	handle, err := srv.IssueHandle(sessionUUID, hostbridge.RoleWriter, endpoint, time.Hour)
	if err != nil {
		return fmt.Errorf("issue handle: %w", err)
	}
	conn, err := hostbridge.NewLoopbackTransport(srv).Dial(handle)
	if err != nil {
		return fmt.Errorf("dial writer handle: %w", err)
	}
	defer conn.Close()

	// Drive a writer-seat input first if requested (it lands on CC stdin via the
	// existing driver; with no real CC consuming it, captureWriter records it).
	if driveText != "" {
		if err := conn.DriveInput(hostbridge.DriveInput{Text: driveText}); err != nil {
			return fmt.Errorf("drive input: %w", err)
		}
	}

	var deltas []attach.Event
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range conn.Events() {
			deltas = append(deltas, ev)
		}
	}()

	if err := bridge.Pump(context.Background(), strings.NewReader(selfCheckStream)); err != nil {
		return fmt.Errorf("pump synthetic stream: %w", err)
	}
	wg.Wait()

	fmt.Printf("ds-hostbridge self-check: %d attach.v1 deltas projected from the synthetic CC stream\n", len(deltas))
	for _, ev := range deltas {
		fmt.Printf("  seq=%d type=%s session=%s\n", ev.Seq, ev.Type, ev.SessionID)
	}
	if w := ccStdin.String(); w != "" {
		fmt.Printf("ds-hostbridge self-check: driver wrote %d bytes to CC stdin (writer seat):\n%s",
			len(w), w)
	}
	if len(deltas) == 0 {
		return fmt.Errorf("no deltas projected (the seam did not produce events)")
	}
	if w := bridge.Warnings(); len(w) > 0 {
		fmt.Printf("ds-hostbridge self-check: %d adapter warnings (drift, non-fatal): %v\n", len(w), w)
	}
	return nil
}

// runSocketSelfCheck stands the bridge up over the synthetic stream and serves it
// on a real framed UDS (under a tmpdir), then dials that socket as a WRITER with
// the SocketTransport, drives the static CC stdout through, and (optionally)
// drives a DriveInput back through the writer seat over the wire — printing the
// projected deltas and the bytes the driver wrote to CC stdin. It is the
// always-safe, no-live-process proof of the FRAMED-UDS seam (the cross-process
// twin of --self-check): a real socket, a synthetic CC stream, zero live
// claude/cia/podman.
func runSocketSelfCheck(sessionUUID, driveText string) error {
	var ccStdin captureWriter
	bridge := hostbridge.NewBridge(&ccStdin, hostbridge.BridgeConfig{
		Adapter: claudecode.New(claudecode.WithClock(deterministicClock())),
	})
	srv := hostbridge.NewServer()
	srv.AddSession(sessionUUID, bridge)

	// Bind a UDS under a tmpdir and serve the framed transport over it.
	dir, err := os.MkdirTemp("", "ds-hostbridge-selfcheck-")
	if err != nil {
		return fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "attach.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hostbridge.ServeBridge(ctx, sock, srv) }()
	if err := waitForSocket(sock, 5*time.Second); err != nil {
		return err
	}

	handle, err := srv.IssueHandleFor(sessionUUID, hostbridge.RoleWriter, hostbridge.TransportUnix, sock, time.Hour)
	if err != nil {
		return fmt.Errorf("issue unix handle: %w", err)
	}
	conn, err := hostbridge.NewSocketTransport().Dial(handle)
	if err != nil {
		return fmt.Errorf("dial writer handle over UDS: %w", err)
	}
	defer conn.Close()

	// Drive a writer-seat input first if requested (it crosses the wire to the
	// server's drive reader, which forwards to the existing driver; captureWriter
	// records the bytes that land on CC stdin).
	if driveText != "" {
		if err := conn.DriveInput(hostbridge.DriveInput{Text: driveText}); err != nil {
			return fmt.Errorf("drive input over UDS: %w", err)
		}
	}

	var deltas []attach.Event
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range conn.Events() {
			deltas = append(deltas, ev)
		}
	}()

	if err := bridge.Pump(ctx, strings.NewReader(selfCheckStream)); err != nil {
		return fmt.Errorf("pump synthetic stream: %w", err)
	}
	wg.Wait()

	fmt.Printf("ds-hostbridge socket-self-check: %d attach.v1 deltas projected over the framed UDS at %s\n", len(deltas), sock)
	for _, ev := range deltas {
		fmt.Printf("  seq=%d type=%s session=%s\n", ev.Seq, ev.Type, ev.SessionID)
	}
	if w := ccStdin.String(); w != "" {
		fmt.Printf("ds-hostbridge socket-self-check: driver wrote %d bytes to CC stdin (writer seat, over the wire):\n%s",
			len(w), w)
	}
	if len(deltas) == 0 {
		return fmt.Errorf("no deltas projected over the UDS (the seam did not produce events)")
	}
	if w := bridge.Warnings(); len(w) > 0 {
		fmt.Printf("ds-hostbridge socket-self-check: %d adapter warnings (drift, non-fatal): %v\n", len(w), w)
	}
	return nil
}

// waitForSocket polls until the UDS path exists (ServeBridge bound it) or the
// timeout passes.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("socket %s never appeared within %s", path, timeout)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// deterministicClock pins the adapter clock for reproducible self-check output
// (one second per call from a fixed base) — the same determinism replay uses.
func deterministicClock() func() time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := 0
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}
