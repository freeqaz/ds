// SPDX-License-Identifier: Apache-2.0

// attachbridge.go is the gap-3 host-agent serving-child manager (doc 15 §5.4, D79).
// It is the host-side counterpart of the orchestrator's attach EndpointResolver
// (controlplane/attachendpoint.go): the orchestrator advertises a per-session
// HOST-LOCAL UDS DIRECT candidate in the issued attach handle, and this manager makes
// that socket real on the host by EXEC'ing the client/cmd/ds-hostbridge serving child
// (the U3 serving leg, --serve-uds) per session. The child:
//
//   - serves the host-local UDS the orchestrator advertised (the client's serpent-tui
//     maps the proto DIRECT candidate to its TransportUnix carrier and dials it),
//   - validates the presented attach token against the SAME
//     <OverlayDir>/.ds-attach-tokens/<uuid>.json store the libvirt attach minter writes
//     (attachminter.go: mint there, validate in the child, one shared store), and
//   - BRIDGES that UDS ⇄ AF_VSOCK guestCID:4242 ⇄ the in-guest event socket (the
//     host→guest carriage leg the child owns).
//
// VSOCK CONTROL CHANNEL (m1-live-session-transport spike, 2026-06-16). The host→guest
// carriage moved off the routed-tap TCP (GuestIP:4242) onto virtio-vsock: the child
// dials the session's deterministic per-session guest CID (Binding.VsockCID, derived in
// alloc.go) on the fixed vsock attach port — no tap, no guest IP, no nft rule on the
// attach path (those stay the parallel nft4/Boundary egress lane). So this manager
// passes the CID + port (NOT a GuestIP:port) to the serving child.
//
// COMPOSE BY EXEC, NOT IMPORT (the maintainer default, honoring D80). The serving binary
// is the EXISTING ds-hostbridge command, resolved like serpent resolves ds-capture (an
// explicit path, then an env override, then PATH, then a sibling of this binary) and
// EXEC'd as a child — never imported (ds-hostbridge lives under client/, a different
// tree; the host agent composes it as a subprocess, the same posture serpent holds for
// ds-capture / serpent-tui). The child owns the relay leg (the UDS↔guest-TCP pump); this
// manager owns the child's LIFECYCLE (start on serve, reap on destroy).
//
// LIVE-GATED, OFFLINE NO-LAUNCH (additive, default-path-unchanged). The real exec + the
// guestCID:4242 vsock relay are reachable ONLY under DS_HOSTAGENT_LIVE=1 (the
// operator-host posture, the SAME single gate live.go / attachminter.go read). With the
// env unset (the default — and the ONLY path in the sandbox / CI / unit tests) Serve
// LAUNCHES NOTHING: it returns a no-op outcome (a record that the session would serve at
// the rendered UDS path, but no child, no socket, no vsock dial), so the whole package
// stays green against no live process (D50). The real config-drive mount, the per-session
// ds-hostbridge child exec, and the guestCID:4242 vsock relay are all DS_HOSTAGENT_LIVE-
// gated and operator-validated at N7 (U6). This binary never launches a VM/container/claude/cia.
//
// STDLIB-ONLY (the package posture): os/exec for the sibling-exec, sync for the
// per-session child map. No cgo, no libvirt-go, no client-tree import.

package hostagent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// createTimingWireFlag is the env var that arms the flag-gated attach-leg §8 segment
// measurement (DS_ORCH_CREATETIMING_WIRE=1) — the SAME single flag the control-plane
// create-timing fold reads (controlplane.CreateTimingWireFlag). It is REPLICATED here (not
// imported — the control-plane package imports THIS one for DefaultAttachSocketDir, so a reverse
// import would cycle; the seam-replication posture the attachSocketSuffix constant already takes,
// D80). OFF by default: an unset/any-other value leaves the attach-leg measurement inert, so
// Serve is byte-for-byte unchanged and no segment is recorded.
const createTimingWireFlag = "DS_ORCH_CREATETIMING_WIRE"

// createTimingWireEnabled reports whether the attach-leg §8 segment measurement is armed via the
// process environment (DS_ORCH_CREATETIMING_WIRE=1). Read ONCE at NewAttachBridge (the live.go
// single-gate posture) so a process either measures or does not for its whole lifetime.
func createTimingWireEnabled() bool { return os.Getenv(createTimingWireFlag) == "1" }

// attachSocketSuffix is the per-session UDS filename suffix the manager serves under (the
// SAME suffix the orchestrator's endpoint resolver advertises — one shared path).
const attachSocketSuffix = ".sock"

// childShutdownGrace bounds how long Destroy waits for a SIGINT'd serving child to reap
// before it is killed. The child writes nothing on the way out (it only tears the UDS
// down), so a short grace is ample; a wedged child is force-killed rather than leaking.
const childShutdownGrace = 5 * time.Second

// AttachBridgeConfig carries the host-side facts the live serving-child exec needs. The
// daemon composition root (cmd/host-agent) fills it on the operator host from host
// bring-up facts (doc 13 §4); tests leave it zero (the offline no-launch path needs no
// host facts).
type AttachBridgeConfig struct {
	// HostbridgeBin is an explicit path to the ds-hostbridge serving binary. Empty falls
	// back to the resolution order (DS_HOSTBRIDGE_BIN, then PATH, then a sibling of this
	// process) — exactly how serpent resolves ds-capture.
	HostbridgeBin string
	// SocketDir is the host-local directory the per-session attach UDS is served under —
	// the SAME dir the orchestrator's endpoint resolver advertises the DIRECT candidate
	// under (controlplane attachendpoint.go defaultAttachSocketDir). Empty takes
	// DefaultAttachSocketDir so the two sides agree on the path by construction.
	SocketDir string
	// OverlayDir is the per-session host state area; the attach token store lives at
	// <OverlayDir>/.ds-attach-tokens/<uuid>.json (the libvirt minter writes it there).
	// Required on the live path (the child validates the token against this file).
	OverlayDir string
	// VsockPort is the in-guest AF_VSOCK attach port the served UDS is bridged to (the
	// guestCID:VsockPort leg over virtio-vsock; the in-guest forwarder listens on it). 0
	// falls back to libvirt.DefaultAttachPort — the SAME constant the orchestrator's TCP
	// fallback used and the cross-module vsock port agreement names (a comment in
	// attachminter.go pins the agreement), so the host serve leg, the ds-hostbridge dial,
	// and the in-guest forwarder all reuse one value without hardcoding it here.
	VsockPort uint16
}

// DefaultAttachSocketDir is the host-local directory the gap-3 serving leg serves the
// per-session attach UDS under when the config supplies no override. A host bring-up FACT
// (doc 13 §4); the daemon root overrides it per host.
//
// THE SINGLE SOURCE OF THE SERVED-UDS DIR. The orchestrator endpoint resolver advertises
// its DIRECT candidate under the SAME directory by referencing THIS constant
// (controlplane.defaultAttachSocketDir = hostagent.DefaultAttachSocketDir), so a handle the
// orchestrator issued with the default dir resolves to exactly the socket this manager
// serves. Defining it ONCE here (and letting the resolver consume it) makes that agreement
// structural — the two sides cannot drift to two different default dirs (which would point a
// client at a socket no bridge binds). The daemon composition root overrides BOTH from one
// per-host config value (cmd/host-agent passes the same dir to the AttachBridge and to the
// resolver), keeping the runtime override single-sourced too.
const DefaultAttachSocketDir = "/run/ds/attach"

// servingChild is one live ds-hostbridge serving-child the manager owns: the running
// command, the UDS path it serves, and a done channel a single goroutine publishes the
// child's exit on (so Destroy can reap without racing Wait).
type servingChild struct {
	cmd     *exec.Cmd
	udsPath string
	done    chan error
}

// ServeOutcome is what Serve reports back: the host-local UDS path the session is (or
// would be) served on and whether a live serving child was actually launched. Off the
// DS_HOSTAGENT_LIVE gate Launched is false (the offline no-launch path): the path is
// rendered (so a caller can log/assert it matches the orchestrator's advertised
// candidate) but no child, socket, or TCP dial exists.
type ServeOutcome struct {
	SessionUUID string
	UDSPath     string
	Launched    bool
}

// AttachBridge is the per-session serving-child manager: it execs the ds-hostbridge
// serving child per session on the live path, owns the child lifecycle, and tears it down
// on destroy. It is constructed once per host agent (NewAttachBridge) and serves every
// session; the per-session children live in a UUID-keyed map under a mutex (the standard
// per-session manager pattern, sibling to the host-agent's other per-session state).
type AttachBridge struct {
	cfg  AttachBridgeConfig
	live bool // DS_HOSTAGENT_LIVE — read ONCE at construction (live.go's single-gate posture)

	mu       sync.Mutex
	children map[string]*servingChild // session UUID → owned serving child (live only)

	// createTiming arms the flag-gated §8 attach-leg segment measurement
	// (DS_ORCH_CREATETIMING_WIRE — read ONCE here). OFF (the default) leaves Serve byte-for-byte
	// unchanged: no clock read, no map write, no exposed segment. ON, Serve measures the wall
	// time it spends standing up (or, offline, rendering) the per-session serving leg and records
	// it as the SegAttachHandshake §8 stack segment — the host-side attach-leg contribution to
	// the create→attach stack (RTT excluded), read back via AttachSegment / AttachSegmentStack so
	// a caller folds it into the control-plane RecordCreateTiming trend. MEASURE, NOT GATE
	// (D81/D32): the measurement never changes what Serve does or returns.
	createTiming bool
	segMu        sync.Mutex
	// attachSegments is the most-recent measured SegAttachHandshake duration per session (keyed
	// by session UUID). Populated only when createTiming is armed; nil-lazily allocated on the
	// first record so the off path allocates nothing.
	attachSegments map[string]time.Duration
}

// NewAttachBridge constructs the manager. The live gate is read ONCE here (so a process
// either serves live or offline for its whole lifetime — never a per-call flip that could
// split a session's serving leg across substrates), exactly the live.go posture. The
// offline default (gate unset) is the tested no-launch path; only DS_HOSTAGENT_LIVE=1
// reaches the real exec + relay.
func NewAttachBridge(cfg AttachBridgeConfig) *AttachBridge {
	if cfg.SocketDir == "" {
		cfg.SocketDir = DefaultAttachSocketDir
	}
	if cfg.VsockPort == 0 {
		cfg.VsockPort = libvirt.DefaultAttachPort
	}
	return &AttachBridge{
		cfg:          cfg,
		live:         libvirt.LiveEnabled(),
		children:     make(map[string]*servingChild),
		createTiming: createTimingWireEnabled(),
	}
}

// socketPathFor renders the deterministic host-local UDS path for a session — the SAME
// keying the orchestrator's endpoint resolver advertises (a per-session socket under the
// socket dir, keyed on the sanitized session UUID), so the advertised candidate and the
// served socket name the SAME path.
func (b *AttachBridge) socketPathFor(sessionUUID string) string {
	return filepath.Join(b.cfg.SocketDir, sanitizeAttachComponent(sessionUUID)+attachSocketSuffix)
}

// tokenFilePath renders the attach token file path for a session — the SAME file the
// libvirt minter writes and the ds-hostbridge serving child validates against (mint
// there, validate in the child, one shared store). It derives the path through
// trustpath.AttachTokenPath — the ONE canonical <OverlayDir>/.ds-attach-tokens/
// <sanitize(uuid)>.json transform the libvirt minter also writes through — so the
// served-token path can never drift from the minted-token path (one path-derivation
// function on both sides, not an inline subdir+sanitize+".json" copy).
func (b *AttachBridge) tokenFilePath(sessionUUID string) string {
	return trustpath.AttachTokenPath(b.cfg.OverlayDir, sessionUUID)
}

// Serve stands up (or, offline, no-ops) the per-session serving leg. vsockCID is the
// session's deterministic per-session AF_VSOCK guest context id (Binding.VsockCID,
// derived in alloc.go — the host→guest carriage target guestCID:VsockPort over
// virtio-vsock); the host agent alone knows it (from the recorded binding) — the
// orchestrator stays runtime-ignorant. On the live path it:
//
//  1. asserts the token store file exists fail-closed (the child validates against it; a
//     missing token means the minter has not run — refuse to serve a session that cannot
//     be authenticated);
//  2. resolves the ds-hostbridge serving binary (sibling-exec, like serpent→ds-capture);
//  3. execs `ds-hostbridge --serve-uds <uds> --guest-vsock-cid <cid>
//     --guest-vsock-port <port> --session-token-file <tokenfile> --session-uuid <uuid>`
//     as an owned child and registers it for teardown.
//
// mode is the RESOLVED per-session launch mode (libvirt.SessionMode, read by the
// caller from the single-source SessionModeStore.ModeFor — the SAME resolution the
// handle transport tag and the LaunchSpec.stdio derive from, so the three cannot drift,
// doc 04 §5). It selects the serving child's surface: SessionModeStructured (the
// default) passes today's argv UNCHANGED (the structured attach.v1 frame pump);
// SessionModeTerminal adds `--mode terminal` so the child serves the raw pty byte
// duplex + resize. Off the gate it LAUNCHES NOTHING: it returns the rendered UDS path
// with Launched=false (so a caller can assert the path matches the orchestrator's
// advertised candidate) without an exec, a socket, or a guest vsock dial. Serving a
// session already served is idempotent (the live child is left running; the offline
// path is a pure render).
func (b *AttachBridge) Serve(ctx context.Context, sessionUUID string, vsockCID uint32, mode libvirt.SessionMode) (ServeOutcome, error) {
	if sessionUUID == "" {
		return ServeOutcome{}, fmt.Errorf("attach bridge: empty session uuid")
	}

	// FLAG-GATED §8 attach-leg measurement (createtiming-feed, DS_ORCH_CREATETIMING_WIRE). When
	// armed, measure the wall time this Serve spends standing up (or, offline, rendering) the
	// per-session serving leg and record it as the SegAttachHandshake §8 stack segment — the
	// host-side attach-leg contribution to the create→attach stack (RTT excluded). The deferred
	// record wraps the WHOLE method (including the offline no-launch early return below) so the
	// segment is measured on every path. OFF (the default) this branch is skipped entirely: no
	// clock read, no defer, no map write — Serve is byte-for-byte unchanged. It never alters the
	// returned outcome (measure-not-gate, D81/D32).
	if b.createTiming {
		start := time.Now()
		defer func() { b.recordAttachSegment(sessionUUID, time.Since(start)) }()
	}

	udsPath := b.socketPathFor(sessionUUID)

	// OFFLINE NO-LAUNCH (the default, and the only sandbox/CI/test path). Render the path
	// the session would serve on, launch nothing. This is the documented degrade: the
	// serving leg's real exec + relay are DS_HOSTAGENT_LIVE-gated, operator-validated at N7.
	if !b.live {
		return ServeOutcome{SessionUUID: sessionUUID, UDSPath: udsPath, Launched: false}, nil
	}

	// A derived guest CID lands past the three reserved AF_VSOCK ids (0/1/2); 0 is the
	// not-yet-derived sentinel (alloc.go vsockCID). Refuse fail-closed on the sentinel — a
	// serve to an unassigned CID has no real guest to carry to (the recorded binding's own
	// validate() already enforced the reserved-range floor on a non-zero CID).
	if vsockCID == 0 {
		return ServeOutcome{}, fmt.Errorf("attach bridge: serve session %s requires a derived guest vsock CID (non-zero; the host→guest carriage target)", sessionUUID)
	}
	if b.cfg.OverlayDir == "" {
		return ServeOutcome{}, fmt.Errorf("attach bridge: serve session %s requires an overlay/state dir for the token store (DS_HOSTAGENT_LIVE)", sessionUUID)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	// Idempotent on session UUID: a serve for a session already served leaves the live
	// child running (a retried serve must converge, not double-launch).
	if _, ok := b.children[sessionUUID]; ok {
		return ServeOutcome{SessionUUID: sessionUUID, UDSPath: udsPath, Launched: true}, nil
	}

	// (1) Token store must be present — fail-closed (the child validates the presented
	// attach token against it; no token, no authenticatable session).
	tokenFile := b.tokenFilePath(sessionUUID)
	if _, err := os.Stat(tokenFile); err != nil {
		return ServeOutcome{}, fmt.Errorf("attach bridge: session %s token store %q absent (minter has not run) — fail-closed (D39): %w", sessionUUID, tokenFile, err)
	}

	// (2) Resolve the ds-hostbridge serving binary (sibling-exec, like serpent→ds-capture).
	bin, err := resolveHostbridgeBin(b.cfg.HostbridgeBin)
	if err != nil {
		return ServeOutcome{}, fmt.Errorf("attach bridge: session %s: %w", sessionUUID, err)
	}

	// Ensure the socket dir exists so the child can bind the UDS (a host that has not yet
	// served any session still gets a well-formed dir).
	if err := os.MkdirAll(b.cfg.SocketDir, 0o700); err != nil {
		return ServeOutcome{}, fmt.Errorf("attach bridge: session %s: mkdir socket dir %q: %w", sessionUUID, b.cfg.SocketDir, err)
	}

	// (3) Exec the serving child bound to the served UDS + the guestCID:port vsock carriage
	// target. DETACH the child from the caller's context cancellation: Serve runs as the
	// libvirt create path's post-boot hook, so ctx is the CreateSession RPC context — gRPC
	// cancels it when CloneFromImage returns, which would KILL the just-exec'd child (it
	// would launch then die the instant the create RPC completes, leaving no UDS and no
	// relay). The serving child must outlive the create RPC: it serves for the SESSION's
	// lifetime, and the bridge owns its lifecycle EXPLICITLY (Destroy at session teardown,
	// Shutdown at daemon stop). context.WithoutCancel keeps ctx's values (deadlines/tracing)
	// while detaching the cancellation, so the child lives until the bridge reaps it.
	args := servingChildArgs(udsPath, vsockCID, b.cfg.VsockPort, tokenFile, sessionUUID, mode)
	cmd := exec.CommandContext(context.WithoutCancel(ctx), bin, args...)
	cmd.Stdout = os.Stderr // the child's progress/diagnostics ride the host agent's stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return ServeOutcome{}, fmt.Errorf("attach bridge: session %s: start ds-hostbridge serving child: %w", sessionUUID, err)
	}

	child := &servingChild{cmd: cmd, udsPath: udsPath, done: make(chan error, 1)}
	// A single goroutine owns Wait so Destroy can reap without racing it.
	go func() { child.done <- cmd.Wait() }()
	b.children[sessionUUID] = child

	return ServeOutcome{SessionUUID: sessionUUID, UDSPath: udsPath, Launched: true}, nil
}

// Destroy tears the per-session serving leg down: it SIGINTs the owned child (which tears
// the UDS down), reaps it (force-killing a wedged one after childShutdownGrace), removes
// the per-session socket, and drops the registration. It is idempotent and safe for a
// session never served (offline, or a destroy racing a serve that no-launched): a session
// with no live child is a clean no-op (the offline socket render owns no file to remove,
// but a best-effort socket unlink covers a live child the manager lost track of). It never
// errors on the teardown of a child that already exited.
//
// It also drops the session's measured §8 attach segment (createtiming-feed). That map is the
// one piece of per-session state this manager keeps OUTSIDE the children map, and before this it
// was never pruned: under DS_ORCH_CREATETIMING_WIRE=1 every Serve added an entry and no teardown
// removed it, so a long-lived daemon accumulated one entry per session ever served — an
// unbounded in-memory leak keyed on a never-recycled session UUID (D66), and a post-destroy
// AttachSegment read that still answered ok=true for a session that no longer exists. The drop
// is unconditional and idempotent (deleting an absent key is a no-op), so it is correct on the
// flag-OFF path too (the map is nil there — a delete on a nil map is legal and does nothing, so
// the default path allocates nothing and behaves identically), for a session never served, and
// for a repeated Destroy. Shutdown reaps every child THROUGH this method, so the daemon-stop
// path prunes the map as well and needs no separate sweep. It is bookkeeping only — the
// measurement is measure-not-gate (D81/D32), and the fold call site (FoldAttachSegment) runs on
// the create/attach flow, long before teardown.
func (b *AttachBridge) Destroy(sessionUUID string) {
	if sessionUUID == "" {
		return
	}
	// Drop the measured §8 segment under the segment mutex (the recordAttachSegment /
	// AttachSegment discipline) — a separate lock from mu, taken and released before the child
	// reap so the reap's bounded grace never holds it.
	b.segMu.Lock()
	delete(b.attachSegments, sessionUUID)
	b.segMu.Unlock()

	b.mu.Lock()
	child, ok := b.children[sessionUUID]
	if ok {
		delete(b.children, sessionUUID)
	}
	b.mu.Unlock()

	if ok && child.cmd.Process != nil {
		_ = child.cmd.Process.Signal(syscall.SIGINT)
		select {
		case <-child.done:
		case <-time.After(childShutdownGrace):
			_ = child.cmd.Process.Kill()
			<-child.done
		}
		// Remove the served socket (the child unlinks on a clean exit, but a killed child
		// may leave it — best-effort cleanup so a re-serve binds fresh).
		_ = os.Remove(child.udsPath)
		return
	}
	// No live child (offline no-launch, or already reaped): best-effort socket cleanup at
	// the rendered path. Off the gate this removes nothing (no socket was ever bound).
	_ = os.Remove(b.socketPathFor(sessionUUID))
}

// Shutdown tears down EVERY live serving child (the host agent stopping). It is idempotent
// and bounded by the per-child grace; a process either serves live or offline, so off the
// gate this is a clean no-op (no children were ever launched).
func (b *AttachBridge) Shutdown() {
	b.mu.Lock()
	uuids := make([]string, 0, len(b.children))
	for u := range b.children {
		uuids = append(uuids, u)
	}
	b.mu.Unlock()
	for _, u := range uuids {
		b.Destroy(u)
	}
}

// ServingCount reports how many live serving children the manager owns. It exists so the
// test can assert the offline path launched ZERO children (and the live path's idempotent
// serve did not double-launch) without reaching into the unexported map.
func (b *AttachBridge) ServingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.children)
}

// recordAttachSegment stores the measured attach-leg §8 segment (SegAttachHandshake) duration for
// a session under the segment mutex (createtiming-feed). A negative span (a clock ran backwards —
// createtiming.Record would reject it) is clamped to zero so the recorded stack fragment is always
// foldable. The map is lazily allocated so the flag-off path (which never calls this) allocates
// nothing.
func (b *AttachBridge) recordAttachSegment(sessionUUID string, d time.Duration) {
	if d < 0 {
		d = 0
	}
	b.segMu.Lock()
	if b.attachSegments == nil {
		b.attachSegments = make(map[string]time.Duration)
	}
	b.attachSegments[sessionUUID] = d
	b.segMu.Unlock()
}

// AttachSegment returns the attach-leg §8 segment measured for a session under
// DS_ORCH_CREATETIMING_WIRE (createtiming-feed): the SegAttachHandshake stack segment and its
// measured duration — the host-side attach-leg contribution to the create→attach stack (RTT
// excluded, doc 15 §8). ok is false when the wire is off (nothing measured) or the session's
// attach leg has not been served/measured. It is a PURE read — it never gates or mutates the
// serving leg (measure-not-gate, D81/D32).
func (b *AttachBridge) AttachSegment(sessionUUID string) (createtiming.Segment, time.Duration, bool) {
	b.segMu.Lock()
	defer b.segMu.Unlock()
	d, ok := b.attachSegments[sessionUUID]
	if !ok {
		return "", 0, false
	}
	return createtiming.SegAttachHandshake, d, true
}

// AttachSegmentStack returns the session's measured attach-leg contribution as a partial §8 stack
// fragment (createtiming-feed): a single-entry {SegAttachHandshake: duration} map ready to hand
// into the control-plane RecordCreateTiming fold (the host reports its attach-leg segment; the
// control plane folds it into the shared trend). It returns nil when the wire is off or the
// session has not been served/measured — a nil stack folds to nothing, so a caller unconditionally
// merges it. The carriage of this fragment from the host agent to the control-plane fold is the
// create/attach flow call-site controlplane.ControlPlane.FoldHostAttachSegment (it crosses the
// host→control-plane seam, in the control-plane tree — controlplane imports THIS package, not the
// reverse); this method is the host-side producer that call-site's fold consumes.
func (b *AttachBridge) AttachSegmentStack(sessionUUID string) map[createtiming.Segment]time.Duration {
	seg, d, ok := b.AttachSegment(sessionUUID)
	if !ok {
		return nil
	}
	return map[createtiming.Segment]time.Duration{seg: d}
}

// createTimingFoldSink is the narrow control-plane fold seam the host agent's attach-leg producer
// hands its measured §8 segment into (createtiming-feed): RecordCreateTiming folds one create's
// stack decomposition (client RTT excluded from the server span, doc 15 §8) into the shared trend
// recorder. It MIRRORS the control-plane createTimingSink by STRUCTURE, not by import — the
// control-plane package imports THIS one (for DefaultAttachSocketDir), so a reverse import would
// cycle; this is the SAME seam-replication posture createTimingWireFlag / attachTokensSubdir take
// (D80). The concrete *reconcileLoop the control-plane wires satisfies it natively, so the host's
// attach-leg segment lands on the SAME trend the (b)-row instrument reads.
type createTimingFoldSink interface {
	RecordCreateTiming(sessionUUID string, stack map[createtiming.Segment]time.Duration, clientRTT time.Duration) (createtiming.Trend, []createtiming.Segment, error)
}

// FoldAttachSegment threads this host agent's measured attach-leg §8 segment (SegAttachHandshake,
// via AttachSegmentStack) into the create-side RecordCreateTiming fold — the host→control-plane
// carriage AttachSegmentStack's doc names, driven from the create/attach flow call-site
// controlplane.ControlPlane.FoldHostAttachSegment (createtiming-feed). It reads the
// session's measured single-entry stack fragment and hands it, plus the trigger-EXCLUDED client
// RTT, to the sink's RecordCreateTiming, so the host's attach-leg contribution lands in the SAME
// shared trend the control-plane fold and the (b)-row read consume. It returns the recorded trend
// and ok=true when a segment was folded.
//
// FLAG-GATED / FAIL-OPEN (default-off byte-identical, D50). With DS_ORCH_CREATETIMING_WIRE off the
// attach segment was never measured, so AttachSegmentStack is nil and this returns
// (empty-trend, false, nil) WITHOUT touching the sink — no fold, byte-for-byte unchanged. A nil
// sink (the fold leg unwired — a deployment that does not serve the observability leg) is likewise
// a clean no-op. It is a PURE producer-side call: it never gates or mutates the serving leg
// (measure-not-gate, D81/D32); a sink fold error surfaces to the caller with ok=false and is the
// caller's to log-and-swallow (the session is already served).
func (b *AttachBridge) FoldAttachSegment(sink createTimingFoldSink, sessionUUID string, clientRTT time.Duration) (createtiming.Trend, bool, error) {
	stack := b.AttachSegmentStack(sessionUUID)
	if sink == nil || len(stack) == 0 {
		return createtiming.Trend{}, false, nil
	}
	trend, _, err := sink.RecordCreateTiming(sessionUUID, stack, clientRTT)
	if err != nil {
		return createtiming.Trend{}, false, err
	}
	return trend, true, nil
}

// servingChildArgs renders the ds-hostbridge serving-child argv for a session — a PURE
// function so the test asserts the exact flags (the `--mode terminal` add for a TERMINAL
// session; its ABSENCE for a STRUCTURED session) without launching a process. The
// structured argv is byte-identical to today: the four base flags + the session UUID,
// NO --mode (the child defaults to structured). A TERMINAL session appends `--mode
// terminal` so the child serves the raw pty byte duplex; the base flags are unchanged.
// The mode is the single-source resolution the caller read from SessionModeStore.ModeFor.
func servingChildArgs(udsPath string, vsockCID uint32, vsockPort uint16, tokenFile, sessionUUID string, mode libvirt.SessionMode) []string {
	args := []string{
		"--serve-uds", udsPath,
		"--guest-vsock-cid", strconv.FormatUint(uint64(vsockCID), 10),
		"--guest-vsock-port", strconv.Itoa(int(vsockPort)),
		"--session-token-file", tokenFile,
		"--session-uuid", sessionUUID,
	}
	if mode == libvirt.SessionModeTerminal {
		args = append(args, "--mode", "terminal")
	}
	return args
}

// resolveHostbridgeBin finds the ds-hostbridge serving binary: an explicit path, then
// $DS_HOSTBRIDGE_BIN, then PATH, then a sibling of THIS process (the .bin/ layout) —
// EXACTLY the resolution order serpent uses for ds-capture (compose by exec, not import;
// D80). A non-empty explicit/env path that is not executable is a hard error (a
// misconfigured bin must not silently fall through to a different one on PATH).
func resolveHostbridgeBin(explicit string) (string, error) {
	for _, c := range []string{explicit, os.Getenv("DS_HOSTBRIDGE_BIN")} {
		if c == "" {
			continue
		}
		if isExecutableFile(c) {
			return c, nil
		}
		return "", fmt.Errorf("ds-hostbridge binary %q is not executable", c)
	}
	if p, err := exec.LookPath("ds-hostbridge"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "ds-hostbridge")
		if isExecutableFile(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("ds-hostbridge not found — build it and put it on PATH or pass HostbridgeBin:\n" +
		"    go build -o .bin/ds-hostbridge ./client/cmd/ds-hostbridge   (then PATH=.bin:$PATH)")
}

// isExecutableFile reports whether path is a regular file with an executable bit set (the
// sibling-exec resolution's guard — a dir or a non-exec file is not the binary).
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// sanitizeAttachComponent reduces a session UUID to a single safe path component for the
// socket / token filenames: any byte outside [A-Za-z0-9._-] is replaced with '_' so a
// rendered path can never escape its dir (defense in depth — session UUIDs are
// orchestrator-minted, but the manager renders filesystem paths from one). It mirrors the
// orchestrator endpoint resolver's sanitizeSocketComponent so the two sides key on the
// SAME sanitized component (one shared path).
func sanitizeAttachComponent(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '-' || c == '_' || c == '.':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "_"
	}
	return string(out)
}
