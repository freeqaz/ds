// live.go — the DS_E2E_LIVE-gated real-container attach path scaffold.
//
// The fleet NEVER runs a live container, claude, or cia (unit charter; the same
// rule client/goldentrace/e2e holds). Tier-2 of DRIVE-PROTOCOL.md — "CC in the
// container with stdio bridged to a minimal host-agent exposing the D79
// AttachHandle; the thin client attaches from outside and drives in" — is a
// DEFERRED MANUAL STEP, armed only when DS_E2E_LIVE=1, exactly mirroring how the
// cc_sandbox / live-tier work was landed (client/goldentrace/e2e/harness.go +
// scripts/cc_sandbox.sh).
//
// With the gate unset — the default and every CI / go test run — RunLiveBridge
// never launches anything: it returns ErrLiveGateUnset. The synthetic loopback
// path (loopback.go + a fixture-fed CC fake) is what the tests exercise; this
// file is the documented seam where an operator wires the real container.
package hostbridge

import (
	"context"
	"errors"
	"os"
)

// LiveGateEnv is the single live gate, shared with client/goldentrace/e2e
// (DS_E2E_LIVE=1). Unset ⇒ no container is ever launched. There is exactly one
// gate name across the drive-direction work (e2e/README.md "One gate story").
const LiveGateEnv = "DS_E2E_LIVE"

// ErrLiveGateUnset is returned by RunLiveBridge when DS_E2E_LIVE != "1". A caller
// that forgets the gate gets a clear, non-panicking signal — never a silent
// no-op and never an accidental container launch. Tests assert on this without
// ever spawning a process.
var ErrLiveGateUnset = errors.New(
	"hostbridge: DS_E2E_LIVE != 1; the real-container tier-2 attach path is gated " +
		"(set DS_E2E_LIVE=1 to arm; this is the deferred manual live step)")

// liveGateArmed reports whether the single live gate is set.
func liveGateArmed() bool { return os.Getenv(LiveGateEnv) == "1" }

// LiveConfig describes the deferred real-container bridge run. It is the seam an
// operator fills to bridge a CC process running inside the cc_sandbox container
// (DRIVE-PROTOCOL.md tier 2): the container exposes CC's stdin/stdout, this host
// agent fronts them with a Server + Bridge, issues an AttachHandle, and the thin
// client attaches over the chosen endpoint and drives in.
//
// At M0 the only realized transport is loopback (in-process); the socket / UDS
// transport that a cross-container client would dial is the M0→M2 implementation
// work the EndpointCandidate list already admits. This struct names the inputs so
// the deferred step is documented, not invented later.
type LiveConfig struct {
	// SessionUUID is the session the bridge serves.
	SessionUUID string
	// Endpoint is the address the AttachHandle advertises for the direct
	// transport (e.g. a host-loopback UDS path the client outside the container
	// dials). Opaque to the bridge.
	Endpoint string
	// CCStdin / CCStdout are the wrapped CC process's standard streams as exposed
	// across the container boundary. In the deferred manual step these come from
	// the cc_sandbox launcher's stdio pipes (the same pipes
	// client/goldentrace/e2e.DriveLive wires); here they are the seam, supplied
	// by the operator's wiring, never opened by the fleet.
	CCStdin  interface{ Write([]byte) (int, error) }
	CCStdout interface{ Read([]byte) (int, error) }
}

// RunLiveBridge is the tier-2 entry point: it stands up a Server + Bridge over a
// CC process in the cc_sandbox container and serves the AttachHandle seam to a
// client outside the container. It is GATED: with DS_E2E_LIVE unset it does NOT
// touch the container and returns ErrLiveGateUnset, so no test path ever launches
// anything. The live wiring (resolving cfg.CCStdin/CCStdout from the container's
// stdio, dialing the cross-container transport) is the deferred manual step —
// scaffolded here behind the gate, exercised by an operator, never by the fleet.
//
// The synthetic, always-run path is the loopback transport (loopback.go), driven
// by the fixture-fed CC fake in the tests — that is where the seam is verified.
func RunLiveBridge(ctx context.Context, cfg LiveConfig) error {
	if !liveGateArmed() {
		return ErrLiveGateUnset
	}
	// DEFERRED MANUAL STEP (no fleet run reaches here). The wiring an operator
	// completes with DS_E2E_LIVE=1, mirroring DRIVE-PROTOCOL.md tier 2 and the
	// cc_sandbox topology:
	//
	//   1. Launch the wrapped CC inside scripts/cc_sandbox.sh (the gated launcher;
	//      its own G1–G7 + in-container assert gate the podman exec), obtaining its
	//      stdin/stdout pipes → cfg.CCStdin / cfg.CCStdout.
	//   2. b := NewBridge(cfg.CCStdin, BridgeConfig{}); srv := NewServer();
	//      sess := srv.AddSession(cfg.SessionUUID, b).
	//   3. go b.Pump(ctx, cfg.CCStdout)  // project CC stdout → attach.v1 deltas.
	//   4. Serve the cross-container transport on cfg.Endpoint (a UDS the client
	//      outside the container dials) — the socket realization of the same seam
	//      LoopbackTransport implements in-process. Issue a WRITER handle to the
	//      driving client and READER handles to spectators (srv.IssueHandle).
	//   5. The client Dials the handle, ranges over Events, and DriveInput/
	//      DriveGrant back through the writer seat — end to end across the boundary.
	//
	// This is intentionally not implemented in-fleet: the socket transport + the
	// container launch are operator-driven, and the synthetic loopback path proves
	// the seam without either.
	return errors.New(
		"hostbridge: RunLiveBridge live wiring is the deferred manual step " +
			"(see the step list in live.go and DRIVE-PROTOCOL.md tier 2); " +
			"the synthetic loopback path is what the fleet/tests exercise")
}
