// SPDX-License-Identifier: Apache-2.0

package entrypoint

// runtimev1_bridge.go is the SINGLE proto-bound file in this package (D38, the
// D20 runtime seam). Every reference to the FROZEN dreamserpent.runtime.v1
// generated code lives here: the rest of the package operates on the plain Go
// structs in this file, which carry NO protobuf machinery, NO CC-isms, and NO
// dependency on the wire shape. If the delivery encoding (OQ-C: how the host
// agent transports EntrypointConfig into the guest) ever changes, only this
// file and config.go move.
//
// This keeps the supervise/transport/notify state machine runtime-AGNOSTIC: it
// launches a LaunchSpec (command/args/env/working_dir), wires stdio onto a UDS,
// and reports readiness/exit. Nothing downstream of fromProto names a runtime.

import (
	"context"
	"fmt"
	"time"

	v1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// insecureLocalCreds is transport security for the GUEST-LOCAL EntrypointService
// dial. The call never crosses the egress boundary — it is a guest-internal UDS
// to the host agent (doc 15 §5.4) — so TLS adds nothing here; the per-session CA
// and the TLS-terminating egress gateway guard the EXTERNAL path, not this local
// hop.
func insecureLocalCreds() grpc.DialOption {
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

// decodeConfig is the SINGLE place the on-disk delivery encoding meets the
// frozen wire shape. The freeze pins the message SHAPE only; the delivery
// encoding stays FREE (OQ-C). This implementation reads the host-agent-dropped
// config as a binary-serialized runtimev1.EntrypointConfig (protobuf wire
// format) — the natural carriage of the frozen shape, no second schema invented.
// If the host agent ever switches carriage (a vsock frame, a JSON blob), only
// this function changes; nothing downstream of fromProto is touched.
//
// Fail-closed: a malformed blob is an error, never a partial config.
func decodeConfig(raw []byte) (entrypointConfig, error) {
	var pb runtimev1.EntrypointConfig
	if err := proto.Unmarshal(raw, &pb); err != nil {
		return entrypointConfig{}, fmt.Errorf("decode entrypoint config: %w", err)
	}
	return fromProto(&pb)
}

// permissionPosture mirrors runtimev1.PermissionPosture without binding the rest
// of the package to the generated enum. It is a runtime-FACING input only (D42:
// the boundary is the authority; a runtime that ignores this changes nothing the
// boundary enforces).
type permissionPosture int

const (
	posturePermissionUnspecified permissionPosture = iota
	posturePermissionLocked
	posturePermissionStandard
	posturePermissionOpen
)

func (p permissionPosture) String() string {
	switch p {
	case posturePermissionLocked:
		return "locked"
	case posturePermissionStandard:
		return "standard"
	case posturePermissionOpen:
		return "open"
	default:
		return "unspecified"
	}
}

// launchSpec is the runtime-agnostic exec/supervise surface (LaunchSpec): how to
// start the agent runtime inside the guest. Generic process-launch fields only.
//
// stdio + initialWinsize are the additive terminal-MVP rider (LaunchSpec.stdio /
// LaunchSpec.initial_window, docs/serpent-cli-mvp/10-build-decisions §A3 res. 7):
// stdio selects the wiring (pipes vs pty) and initialWinsize seeds the pty window
// on launch. They carry NO protobuf machinery here — fromProto projects the frozen
// enum/message onto these proto-free types; the supervisor reads only these.
type launchSpec struct {
	command        string
	args           []string
	env            []string
	workingDir     string
	stdio          stdioDisposition
	initialWinsize winsize
}

// budget is the runtime-facing, self-limiting envelope (Budget). NOT a guardrail
// and NOT the billing meter (doc 15 §5.6); carried for the runtime to surface.
type budget struct {
	wallClockSeconds uint64
	tokenMicroUnits  uint64
}

// attachWiring names the guest-local event-socket UDS (AttachWiring) the runtime
// wrapper emits onto; the host agent terminates the other end (doc 15 §5.4).
type attachWiring struct {
	eventSocketPath string
}

// egressWiring is the runtime's view of the TLS-terminating egress gateway and
// the per-session CA — REFERENCES ONLY (D17/D39/D8): proxy addresses and a
// bundle PATH, never key/cert material.
type egressWiring struct {
	httpProxy    string
	httpsProxy   string
	noProxy      []string
	caBundlePath string
}

// sessionRef is the shared join quartet (boundary.v1.SessionRef) the guest echoes
// back through EntrypointService so the host agent joins readiness/exit to the
// authoritative session record.
type sessionRef struct {
	sessionUUID      string
	hostID           string
	hostSessionIndex uint64
	tapName          string
}

// entrypointConfig is the internal, proto-free projection of
// runtimev1.EntrypointConfig the rest of the package operates on. role_overlay_ref
// is carried as opaque bytes and NEVER inspected here (it is applied by the
// runtime/adapter inside the guest, opaque to the control plane the whole way).
type entrypointConfig struct {
	session              sessionRef
	launch               launchSpec
	posture              permissionPosture
	budget               budget
	attach               attachWiring
	egress               egressWiring
	roleOverlayRef       []byte
	sessionTokenEndpoint string
}

// fromProto projects a FROZEN runtimev1.EntrypointConfig onto the internal,
// proto-free config struct. It performs NO validation beyond the proto shape —
// TOTAL validation is config.go's job (validate), so the validation rules read
// in one place independent of the wire format. fromProto only translates and
// rejects a nil message (the one shape error visible at translation time).
//
// CREDENTIALS ARE NEVER CARRIED (D17/D39/D50): only proxy/CA REFERENCES and the
// session-token FETCH endpoint cross here; no token value, key, or PEM body
// exists on this wire to translate.
func fromProto(pb *runtimev1.EntrypointConfig) (entrypointConfig, error) {
	if pb == nil {
		return entrypointConfig{}, fmt.Errorf("entrypoint config: nil proto message")
	}

	cfg := entrypointConfig{
		posture:              posture(pb.GetPosture()),
		roleOverlayRef:       pb.GetRoleOverlayRef(),
		sessionTokenEndpoint: pb.GetSessionTokenEndpoint(),
	}

	if s := pb.GetSessionRef(); s != nil {
		cfg.session = sessionRef{
			sessionUUID:      s.GetSessionUuid(),
			hostID:           s.GetHostId(),
			hostSessionIndex: s.GetHostSessionIndex(),
			tapName:          s.GetTapName(),
		}
	}
	if l := pb.GetLaunch(); l != nil {
		cfg.launch = launchSpec{
			command:        l.GetCommand(),
			args:           append([]string(nil), l.GetArgs()...),
			env:            append([]string(nil), l.GetEnv()...),
			workingDir:     l.GetWorkingDir(),
			stdio:          stdioFromProto(l.GetStdio()),
			initialWinsize: winsizeFromProto(l.GetInitialWindow()),
		}
	}
	if b := pb.GetBudget(); b != nil {
		cfg.budget = budget{
			wallClockSeconds: b.GetWallClockSeconds(),
			tokenMicroUnits:  b.GetTokenMicroUnits(),
		}
	}
	if a := pb.GetAttach(); a != nil {
		cfg.attach = attachWiring{eventSocketPath: a.GetEventSocketPath()}
	}
	if e := pb.GetEgress(); e != nil {
		cfg.egress = egressWiring{
			httpProxy:    e.GetHttpProxy(),
			httpsProxy:   e.GetHttpsProxy(),
			noProxy:      append([]string(nil), e.GetNoProxy()...),
			caBundlePath: e.GetCaBundlePath(),
		}
	}
	return cfg, nil
}

// stdioFromProto projects the frozen runtime.v1 StdioDisposition onto the
// proto-free stdioDisposition. ONLY an explicit PTY maps to stdioPTY; PIPES,
// UNSPECIFIED, and an absent launch mode all map to stdioPipes (the historical
// disposition / zero value), so a config that predates the terminal-MVP rider
// keeps the byte-identical pipes path (additive, D38).
func stdioFromProto(s runtimev1.StdioDisposition) stdioDisposition {
	switch s {
	case runtimev1.StdioDisposition_STDIO_DISPOSITION_PTY:
		return stdioPTY
	default:
		// PIPES / UNSPECIFIED / unknown => the historical pipes disposition.
		return stdioPipes
	}
}

// winsizeFromProto projects the frozen runtime.v1 TerminalSize onto the proto-free
// winsize. The proto carries uint32 cols/rows; the kernel's TIOCSWINSZ takes
// uint16, so each axis is clamped/saturated into uint16 (clampUint16). A nil
// message (no initial_window) yields the zero winsize, which winsize.resolved()
// later defaults to 80x24 AT USE — never an error, never a literal 0x0 window.
func winsizeFromProto(t *runtimev1.TerminalSize) winsize {
	if t == nil {
		return winsize{}
	}
	return winsize{
		cols: clampUint16(t.GetCols()),
		rows: clampUint16(t.GetRows()),
	}
}

// clampUint16 saturates a proto uint32 axis into the kernel's uint16 winsize
// field: a value above the uint16 max is clamped to the max (a terminal that wide
// or tall is a non-event for the seed; saturating is safer than a wraparound).
func clampUint16(v uint32) uint16 {
	const maxUint16 = uint32(^uint16(0))
	if v > maxUint16 {
		return ^uint16(0)
	}
	return uint16(v)
}

// posture maps the generated enum onto the internal posture without leaking the
// proto type past this file.
func posture(p runtimev1.PermissionPosture) permissionPosture {
	switch p {
	case runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED:
		return posturePermissionLocked
	case runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD:
		return posturePermissionStandard
	case runtimev1.PermissionPosture_PERMISSION_POSTURE_OPEN:
		return posturePermissionOpen
	default:
		return posturePermissionUnspecified
	}
}

// exitReason mirrors runtimev1.ExitReason for the internal teardown path; mapped
// back to the generated enum by the bridge when an EntrypointService report is
// emitted. Observability taxonomy only (the §3 state machine owns the verdict).
type exitReason int

const (
	exitReasonUnspecified exitReason = iota
	exitReasonCompleted
	exitReasonError
	exitReasonTerminated
)

func (r exitReason) String() string {
	switch r {
	case exitReasonCompleted:
		return "completed"
	case exitReasonError:
		return "error"
	case exitReasonTerminated:
		return "terminated"
	default:
		return "unspecified"
	}
}

// toProtoExitReason maps the internal reason back to the frozen enum for an
// EntrypointService.ReportExit call.
func toProtoExitReason(r exitReason) runtimev1.ExitReason {
	switch r {
	case exitReasonCompleted:
		return runtimev1.ExitReason_EXIT_REASON_COMPLETED
	case exitReasonError:
		return runtimev1.ExitReason_EXIT_REASON_ERROR
	case exitReasonTerminated:
		return runtimev1.ExitReason_EXIT_REASON_TERMINATED
	default:
		return runtimev1.ExitReason_EXIT_REASON_UNSPECIFIED
	}
}

// toProtoSessionRef rebuilds the boundary.v1.SessionRef the guest echoes back
// through EntrypointService so the host agent joins the report to the session
// record by the one join key (D66/D44).
func toProtoSessionRef(s sessionRef) *v1.SessionRef {
	return &v1.SessionRef{
		SessionUuid:      s.sessionUUID,
		HostId:           s.hostID,
		HostSessionIndex: s.hostSessionIndex,
		TapName:          s.tapName,
	}
}

// entrypointServiceReporter is the BEST-EFFORT runtime/v1 EntrypointService
// reporter (the guest -> host-agent application report; the host agent is the
// server, doc 15 §4.1 step 8). It is the only place outside fromProto/decode
// that touches the generated service client. It is NOT the load-bearing
// readiness signal — sd_notify is (see notify.go). Failures here are surfaced as
// best-effort, never fatal: the §3 state machine + D46 clock are the lifecycle
// authority, not this call (D20/D38, doc 16 §12).
type entrypointServiceReporter struct {
	client  runtimev1.EntrypointServiceClient
	session sessionRef
	// timeout bounds each RPC so a wedged host-agent terminator can never stall
	// the supervisor's teardown.
	timeout time.Duration
	now     func() time.Time
}

// newEntrypointServiceReporter wraps an EntrypointServiceClient (dialed by the
// caller over the guest-local transport, which is FREE under OQ-C). Returns nil
// when no client is available, which the multiReporter treats as "no best-effort
// reporter".
func newEntrypointServiceReporter(client runtimev1.EntrypointServiceClient, session sessionRef) *entrypointServiceReporter {
	if client == nil {
		return nil
	}
	return &entrypointServiceReporter{
		client:  client,
		session: session,
		timeout: 5 * time.Second,
		now:     time.Now,
	}
}

func (r *entrypointServiceReporter) ReportReady() error {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	_, err := r.client.ReportReady(ctx, &runtimev1.ReportReadyRequest{
		SessionRef: toProtoSessionRef(r.session),
		ReadyAt:    uint64(r.now().Unix()),
	})
	if err != nil {
		return fmt.Errorf("EntrypointService.ReportReady: %w", err)
	}
	return nil
}

func (r *entrypointServiceReporter) ReportExit(reason exitReason, code int, detail string) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	_, err := r.client.ReportExit(ctx, &runtimev1.ReportExitRequest{
		SessionRef: toProtoSessionRef(r.session),
		Reason:     toProtoExitReason(reason),
		ExitCode:   int32(code),
		ExitedAt:   uint64(r.now().Unix()),
		Detail:     detail,
	})
	if err != nil {
		return fmt.Errorf("EntrypointService.ReportExit: %w", err)
	}
	return nil
}

// dialEntrypointService dials the host-agent EntrypointService terminator over a
// guest-local UDS (the OQ-C-free transport). Best-effort: a dial failure returns
// an error the caller treats as "no app reporter", never fatal.
func dialEntrypointService(socketPath string) (runtimev1.EntrypointServiceClient, func() error, error) {
	// Use gRPC's built-in unix: name resolver to dial the path — do NOT supply a
	// custom WithContextDialer. With a custom dialer, gRPC hands the FULL target
	// URI ("unix:/<path>") to the dialer, so net.Dial("unix", "unix:/<path>")
	// fails (no such file) and the channel sits in TRANSIENT_FAILURE, killing the
	// whole guest->host-agent runtime/v1 app-report leg. The built-in resolver
	// strips the scheme and dials the bare path.
	conn, err := grpc.NewClient(
		"unix:"+socketPath,
		insecureLocalCreds(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial EntrypointService %q: %w", socketPath, err)
	}
	return runtimev1.NewEntrypointServiceClient(conn), conn.Close, nil
}
