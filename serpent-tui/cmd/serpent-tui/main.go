// SPDX-License-Identifier: Apache-2.0
//
// Command serpent-tui is the human-in-the-loop attach entrypoint. It dials the
// orchestrator's SessionService over gRPC and drives a VM-hosted Claude Code
// session over attach.v1 from the writer seat (D18/D61/D79). Two subcommands:
//
//	serpent-tui attach --orchestrator <addr> --session <uuid>
//	    Attach to an EXISTING session: take the writer seat and stream events.
//
//	serpent-tui up --orchestrator <addr> --repo <id> --env-config-ref <ref> [--image <id>]
//	    PROVISION (CreateSession) then drop straight into the same interactive
//	    attach — provision + attach in one command (the operator front door).
//
// LIVE WIRING (the N7 gate, now OPEN). Both paths build the real production
// legs that serpenttui.Config binds against:
//
//   - Starter: orchestratorv1.NewSessionServiceClient over a real gRPC dial —
//     the SAME client serpent-tui/internal/watch already uses for WatchSession.
//   - Seat: driver.SeatFromSocket over a hostbridge.SocketTransport.Dial of the
//     AttachHandle's direct endpoint (the framed UDS carrier the host agent
//     serves; docs/15 §5.4). A reader-only attach (no servable direct endpoint
//     yet) runs without a seat — input is refused, the seat is arbitrated
//     server-side and never fabricated (D61).
//
// The AttachHandle is resolved from the session: `attach` issues the Attach RPC
// for an existing --session; `up` first CreateSession's, then Attach's the
// freshly-minted session. The interactive loop, the attach.v1->client/tui
// mapping, the writer-seat drive, and the WatchSession subscriber (resume /
// reconnect) are exercised OFFLINE by the package + cmd tests against an
// in-process fake SessionService (orchestratorv1fake / a scripted server) with
// no live orchestrator or VM — the live dial itself is operator-validated at N7.
//
// REMAINING FOR A LIVE SESSION (gaps 1 + 3, landed by the N4 host-agent
// keystone, NOT this unit): (1) the host agent must inject the session's
// EntrypointConfig so a real CC actually launches in the VM, and (3) the Attach
// handler must MINT a servable direct endpoint (a real UDS the SocketTransport
// can dial) onto the returned AttachHandle. Until gap 3 lands, an Attach reply
// with no servable direct endpoint yields a reader-only attach here (no seat);
// the code already consumes the directEndpoint the moment the handle carries one.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"

	serpenttui "github.com/dream-serpent/dream-serpent/serpent-tui"
	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/driver"
	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/rawterm"
)

// orchestratorEnv is the env fallback for the --orchestrator endpoint flag.
const orchestratorEnv = "DS_ORCHESTRATOR"

// scriptedPromptEnv, when set, makes the interactive loop submit that ONE prompt
// deterministically (the non-TTY verification path) — without changing the
// interactive UX when it is unset. See serpenttui.Config.ScriptedPrompt.
const scriptedPromptEnv = "DS_SERPENT_SCRIPTED_PROMPT"

// stdin / stdout are the TTY I/O the interactive loop reads keystrokes from and
// renders to. They are package vars (defaulting to the real terminal) only so
// the offline cmd tests inject a non-TTY EOF input + a discard output and drive
// the live attach path headless — no TTY, no live orchestrator. Production
// leaves them as os.Stdin/os.Stdout.
var (
	stdin  io.Reader = os.Stdin
	stdout io.Writer = os.Stdout
)

func main() { os.Exit(run(os.Args[1:])) }

// run is the testable dispatcher (main only adds os.Exit). It returns the
// process exit code.
func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "attach":
		return cmdAttach(args[1:])
	case "up":
		return cmdUp(args[1:])
	case "sessions":
		return cmdSessions(args[1:])
	case "spectate":
		return cmdSpectate(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "serpent-tui: unknown command %q\n", args[0])
		usage()
		return 2
	}
}

// dialer constructs a SessionServiceClient over endpoint. It is a package var so
// the cmd tests inject an in-process fake (bufconn) client without a live dial;
// production leaves it as the real insecure-loopback gRPC dial (the orchestrator
// terminator is reached over an already-secured transport; TLS to the
// terminator is the M1+ identity-seam concern, not this client leg).
var dialer = dialSessionService

// sessionClient is the slice of orchestrator.v1 SessionService this binary
// drives: WatchSession (the READ leg, via watch.Starter), Attach (resolve the
// AttachHandle), CreateSession (provision in `up`), DestroySession (the opt-in
// --rm ephemeral teardown in `up` AND the `sessions destroy` management verb),
// and ListSessions (the `sessions list` management verb). Narrowing to these
// keeps the live surface legible and lets the cmd tests satisfy it with the
// generated client over an in-process fake server.
type sessionClient interface {
	WatchSession(ctx context.Context, in *orchestratorv1.WatchSessionRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[orchestratorv1.WatchSessionResponse], error)
	Attach(ctx context.Context, in *orchestratorv1.AttachRequest, opts ...grpc.CallOption) (*orchestratorv1.AttachResponse, error)
	CreateSession(ctx context.Context, in *orchestratorv1.CreateSessionRequest, opts ...grpc.CallOption) (*orchestratorv1.CreateSessionResponse, error)
	DestroySession(ctx context.Context, in *orchestratorv1.DestroySessionRequest, opts ...grpc.CallOption) (*orchestratorv1.DestroySessionResponse, error)
	ListSessions(ctx context.Context, in *orchestratorv1.ListSessionsRequest, opts ...grpc.CallOption) (*orchestratorv1.ListSessionsResponse, error)
}

// dialSessionService dials endpoint and returns the generated SessionService
// client plus a closer. The generated orchestratorv1.SessionServiceClient
// satisfies sessionClient directly.
func dialSessionService(endpoint string) (sessionClient, func() error, error) {
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("dial orchestrator %q: %w", endpoint, err)
	}
	return orchestratorv1.NewSessionServiceClient(conn), conn.Close, nil
}

// cmdAttach attaches to an EXISTING session: resolve the writer-seat AttachHandle
// via the Attach RPC, build the live Config, and run the interactive loop.
func cmdAttach(args []string) int {
	fs := flag.NewFlagSet("serpent-tui attach", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	orchestrator := fs.String("orchestrator", os.Getenv(orchestratorEnv), "orchestrator SessionService endpoint (host:port; env "+orchestratorEnv+")")
	session := fs.String("session", "", "session UUID to attach to")
	color := fs.Bool("color", true, "use the styled ANSI renderer (false = plain surface)")
	raw := registerRawFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: serpent-tui attach --orchestrator <addr> --session <uuid> [--color=false] [--raw=auto|on|off] [--detach-key K] [--no-alt-screen]")
		fmt.Fprintln(os.Stderr, "  attach to an existing session: take the writer seat and drive it over attach.v1.")
		fmt.Fprintln(os.Stderr, "  In a VM with a raw-terminal endpoint, your terminal becomes the in-VM Claude Code;")
		fmt.Fprintln(os.Stderr, "  Ctrl-C interrupts CC, the detach key detaches (the VM session keeps running).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *orchestrator == "" {
		fmt.Fprintf(os.Stderr, "serpent-tui: --orchestrator <addr> is required (or set %s)\n", orchestratorEnv)
		fs.Usage()
		return 2
	}
	if *session == "" {
		fmt.Fprintln(os.Stderr, "serpent-tui: --session <uuid> is required")
		fs.Usage()
		return 2
	}

	c, closeConn, err := dialer(*orchestrator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: %v\n", err)
		return 1
	}
	defer func() { _ = closeConn() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := attachSession(ctx, c, *session, *color, raw.resolve()); err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: attach failed: %v\n", err)
		return 1
	}
	return 0
}

// cmdUp PROVISIONS a session (CreateSession) then drops straight into the same
// interactive attach as `attach`, bound to the freshly-minted session UUID —
// provision + attach in one command.
func cmdUp(args []string) int {
	fs := flag.NewFlagSet("serpent-tui up", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	orchestrator := fs.String("orchestrator", os.Getenv(orchestratorEnv), "orchestrator SessionService endpoint (host:port; env "+orchestratorEnv+")")
	repo := fs.String("repo", "", "repo / target the session works on (CreateSession repo_id, D56)")
	envConfigRef := fs.String("env-config-ref", "", "checked-in env-spec reference (CreateSession env_config_ref, D7/D56)")
	launchingUser := fs.String("launching-user", "", "user the session is created on behalf of (CreateSession launching_user, D99)")
	roleRef := fs.String("role-ref", "", "optional session role reference (CreateSession role_ref, doc 18 §6)")
	color := fs.Bool("color", true, "use the styled ANSI renderer (false = plain surface)")
	timeout := fs.Duration("provision-timeout", 60*time.Second, "deadline for the CreateSession + Attach provisioning handshake")
	// --rm makes the session EPHEMERAL: on exit (any exit — a clean CC-exit OR a
	// detach) DestroySession tears the VM down. Without --rm the default D61
	// persist-on-detach behavior is unchanged (the session keeps running, re-attach
	// with `attach --session`). --rm applies ONLY to `up` (this command provisioned
	// the session, so it owns the teardown), never to `attach`.
	rm := fs.Bool("rm", false, "destroy the VM session on exit instead of leaving it running for re-attach (ephemeral; D61 persist is the default)")
	raw := registerRawFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: serpent-tui up --orchestrator <addr> --repo <id> --env-config-ref <ref> [--launching-user U] [--role-ref R] [--rm] [--color=false] [--raw=auto|on|off] [--detach-key K] [--no-alt-screen]")
		fmt.Fprintln(os.Stderr, "  provision a session (CreateSession) then attach to it in one command.")
		fmt.Fprintln(os.Stderr, "  In a VM with a raw-terminal endpoint, your terminal becomes the in-VM Claude Code;")
		fmt.Fprintln(os.Stderr, "  Ctrl-C interrupts CC, the detach key detaches (the VM session keeps running).")
		fmt.Fprintln(os.Stderr, "  With --rm the session is destroyed on exit instead (ephemeral, no re-attach).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *orchestrator == "" {
		fmt.Fprintf(os.Stderr, "serpent-tui: --orchestrator <addr> is required (or set %s)\n", orchestratorEnv)
		fs.Usage()
		return 2
	}
	if *repo == "" || *envConfigRef == "" {
		fmt.Fprintln(os.Stderr, "serpent-tui: --repo and --env-config-ref are both required (the D56 two-key create)")
		fs.Usage()
		return 2
	}

	c, closeConn, err := dialer(*orchestrator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: %v\n", err)
		return 1
	}
	defer func() { _ = closeConn() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Provision under a bounded deadline so a wedged control plane fails fast
	// rather than hanging the operator before the interactive loop even starts.
	provCtx, cancel := context.WithTimeout(ctx, *timeout)
	uuid, err := createSession(provCtx, c, *repo, *envConfigRef, *launchingUser, *roleRef)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: provision failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "serpent-tui: provisioned session %s — attaching…\n", uuid)

	// --rm makes this `up`-provisioned session EPHEMERAL: tear the VM down on exit,
	// however the attach loop returns (a clean CC-exit OR a detach OR even an attach
	// failure — `up` provisioned the session, so it owns the teardown). Best-effort:
	// log on error, never mask the original exit code (a failed destroy must not flip
	// a clean session to a failure, nor a real attach failure to a success). Without
	// --rm the default D61 persist-on-detach behavior is unchanged.
	if *rm {
		defer destroyOnExit(c, uuid)
	}

	if err := attachSession(ctx, c, uuid, *color, raw.resolve()); err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: attach failed: %v\n", err)
		return 1
	}
	return 0
}

// destroyOnExit best-effort tears down an --rm ephemeral session provisioned by
// `up`. It runs on EVERY exit path (deferred), on a FRESH bounded context — never
// the run ctx, which is already SIGINT/SIGTERM-cancelled the moment the operator
// Ctrl-C'd out, so reusing it would cancel the teardown RPC before it lands. A
// destroy failure is logged and swallowed: --rm is a convenience, and a failed
// reap must not mask the session's real exit (D61 persist stays the default, so a
// leaked VM on a destroy error is the conservative outcome, not data loss).
func destroyOnExit(c sessionClient, uuid string) {
	ctx, cancel := context.WithTimeout(context.Background(), destroyTimeout)
	defer cancel()
	if _, err := c.DestroySession(ctx, &orchestratorv1.DestroySessionRequest{SessionUuid: uuid}); err != nil {
		fmt.Fprintf(os.Stderr, "serpent-tui: --rm: destroy session %s failed (the VM may still be running, reap it with the orchestrator): %v\n", uuid, err)
		return
	}
	fmt.Fprintf(os.Stderr, "serpent-tui: --rm: destroyed session %s\n", uuid)
}

// destroyTimeout bounds the --rm best-effort DestroySession on exit so a wedged
// control plane cannot hang the operator's shell after they have already left the
// session.
const destroyTimeout = 30 * time.Second

// createSession runs the §4.1 canonical CreateSession and returns the new
// session UUID. The D56 two-key refusal is enforced control-plane side; this
// just carries the references.
func createSession(ctx context.Context, c sessionClient, repo, envConfigRef, launchingUser, roleRef string) (string, error) {
	resp, err := c.CreateSession(ctx, &orchestratorv1.CreateSessionRequest{
		RepoId:        repo,
		EnvConfigRef:  envConfigRef,
		LaunchingUser: launchingUser,
		RoleRef:       roleRef,
	})
	if err != nil {
		return "", err
	}
	uuid := resp.GetSession().GetSessionUuid()
	if uuid == "" {
		return "", errors.New("CreateSession returned no session_uuid")
	}
	return uuid, nil
}

// attachSession resolves the writer-seat AttachHandle for sessionUUID (the
// Attach RPC) and then picks the writer SURFACE (docs/serpent-cli-mvp/03 §2.2):
// if the handle advertises a RAW_TERMINAL endpoint AND we hold the writer seat AND
// stdin/stdout are a TTY (and --raw is not off), it drops into the termios raw-pty
// passthrough (runRaw) — the dev's terminal IS the in-VM CC. Otherwise it runs the
// existing bubbletea structured loop UNCHANGED (the land-dark default: until the
// orchestrator mints the raw tag, rawEndpoint is always false ⇒ always structured).
func attachSession(ctx context.Context, c sessionClient, sessionUUID string, color bool, raw rawOptions) error {
	handle, err := resolveWriterHandle(ctx, c, sessionUUID)
	if err != nil {
		return err
	}

	switch selectMode(handle, raw.pref, isTTY(stdin), isTTY(stdout)) {
	case modeRaw:
		return runRaw(ctx, handle, raw)
	default:
		return attachSessionStructured(ctx, c, sessionUUID, color, handle)
	}
}

// runRaw dials the handle's RAW_TERMINAL endpoint (SocketTransport.DialTerminal →
// a *hostbridge.TerminalConn) and runs the termios raw-pty passthrough
// (rawterm.Run) over the real stdin/stdout. The TerminalConn satisfies
// rawterm.Conn verbatim (RawOut/Write/SendResize/Done/Close). On a clean detach or
// session end Run returns nil; a transport fault surfaces the cause. The terminal
// is restored on EVERY exit path by Run's deferred guard (§2.6).
//
// selectMode already guaranteed a raw endpoint + writer seat + TTY, but rawEndpoint
// is re-resolved here for the dial handle (and a missing endpoint after the guard
// is an internal error, never reached in practice). The os.File assertion on
// stdin/stdout holds in production (they default to os.Stdin/os.Stdout); a test
// that reaches this path injects a TTY-ish *os.File.
func runRaw(ctx context.Context, handle *attachv1.AttachHandle, raw rawOptions) error {
	local, ok := rawEndpoint(handle)
	if !ok {
		// selectMode said raw, so a raw endpoint must exist; defence-in-depth fall
		// back to structured rather than crashing if the handle changed under us.
		return errors.New("serpent-tui: raw mode selected but the handle carries no raw-terminal endpoint")
	}
	// Dial with the SAME bounded retry as the structured seat (seatFromHandle): the
	// per-session terminal serving leg binds the UDS in the host-agent's POST-BOOT hook,
	// which can land a beat after CreateSession returns, so a single dial loses to a UDS
	// that does not yet exist ("connect: no such file or directory"). Wait for the server
	// to come up — the endpoint is the one the handle advertised (a liveness wait, not a
	// fabrication), mirroring seatFromHandle's structured-path retry exactly.
	var conn *hostbridge.TerminalConn
	var err error
	deadline := time.Now().Add(writerSeatDialTimeout)
	for {
		conn, err = (&hostbridge.SocketTransport{}).DialTerminal(local)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("dial raw-terminal endpoint (waited %s for the post-boot serving leg): %w", writerSeatDialTimeout, err)
		}
		time.Sleep(writerSeatDialRetryInterval)
	}
	defer func() { _ = conn.Close() }()

	in, inOK := stdin.(*os.File)
	out, outOK := stdout.(*os.File)
	if !inOK || !outOK {
		return errors.New("serpent-tui: raw mode requires a real terminal stdin/stdout")
	}
	fmt.Fprintln(os.Stderr, "serpent-tui: entering the in-VM Claude Code terminal — Ctrl-C interrupts CC; press the detach key to detach (the VM session keeps running, re-attach with --session).")
	return rawterm.Run(ctx, conn, in, out, raw.runtime())
}

// attachSessionStructured is the existing structured-loop attach (the renamed
// original attachSession body): it wires the live serpenttui.Config (Starter over
// the dialed SessionService, Seat over the AttachHandle's servable direct endpoint
// if one is present) and runs the bubbletea interactive loop until the stream ends
// or the operator quits. A nil seat (no servable direct endpoint yet — gap 3) is a
// reader-only attach, not an error: input is refused locally, never fabricated
// (D61). This body is byte-identical to today; raw mode is strictly additive.
// The handle is resolved once by the caller (attachSession) and passed in, so the
// mode decision does not cost a second Attach RPC.
func attachSessionStructured(ctx context.Context, c sessionClient, sessionUUID string, color bool, handle *attachv1.AttachHandle) error {
	seat, events, closeSeat, err := seatFromHandle(handle)
	if err != nil {
		return err
	}
	if closeSeat != nil {
		defer closeSeat()
	}

	scriptedPrompt := os.Getenv(scriptedPromptEnv)
	// Non-interactive verification: when DS_SERPENT_SCRIPTED_PROMPT is set, the loop submits
	// that ONE prompt through the writer seat the moment it is running (the robust
	// keystroke→submit path, not a piped-stdin EOF that can race teardown). In that mode we
	// pass NO TTY input (In=nil) so bubbletea does not open a keyboard reader — a non-TTY
	// stdin otherwise makes its cancelreader fail to epoll and aborts the attach. Unset (the
	// default) keeps In=stdin and the interactive UX completely unchanged.
	in := stdin
	if scriptedPrompt != "" {
		in = nil
	}
	return serpenttui.Run(ctx, serpenttui.Config{
		SessionUUID: sessionUUID,
		Starter:     c,
		Seat:        seat,
		Color:       color,
		In:          in,
		Out:         stdout,
		// EventStream is the writer-seat SocketConn's attach.Event stream — the read path
		// the loop folds. On the single-box MVP the orchestrator's WatchSession fan-out
		// carries only §3 state edges (the heartbeat relay), NOT CC's content, so the CC
		// response only reaches the client over THIS direct stream (the same one the proven
		// goldentrace drive harness reads). Nil for a reader-only attach (no servable
		// endpoint) → the loop falls back to the WatchSession subscriber.
		EventStream:    events,
		ScriptedPrompt: scriptedPrompt,
	})
}

// resolveWriterHandle issues the Attach RPC for sessionUUID requesting the WRITER
// seat (D61 one-writer/N-reader; arbitrated server-side) and returns the
// resolved attach.v1 AttachHandle. The handle carries the endpoint candidates
// the writer-seat transport dials.
func resolveWriterHandle(ctx context.Context, c sessionClient, sessionUUID string) (*attachv1.AttachHandle, error) {
	resp, err := c.Attach(ctx, &orchestratorv1.AttachRequest{
		SessionUuid: sessionUUID,
		Role:        attachv1.Role_ROLE_WRITER,
	})
	if err != nil {
		return nil, fmt.Errorf("attach session %q: %w", sessionUUID, err)
	}
	h := resp.GetHandle()
	if h == nil {
		return nil, errors.New("Attach returned no handle")
	}
	return h, nil
}

// seatFromHandle builds the writer-seat WriterSeat from the AttachHandle's
// SERVABLE direct endpoint: it maps the frozen proto handle onto the local
// hostbridge.AttachHandle, dials the framed UDS carrier (SocketTransport.Dial,
// which selects the handle's servable direct endpoint), and adapts the live
// SocketConn through driver.SeatFromSocket — the production wiring the offline
// tests substitute an in-process fake seat for.
//
// gap 3: until the Attach handler mints a servable direct endpoint onto the
// handle, there is no carrier to dial; that is NOT an error — it is a
// reader-only attach (nil seat). The moment the handle carries a servable direct
// endpoint, this dials it and returns the writer seat. The returned closer (nil
// for a reader-only attach) releases the socket on loop exit.
// It ALSO returns the SocketConn's Events() channel (the attach.Event read stream the
// loop folds): on the single-box MVP the orchestrator's WatchSession carries only §3 state
// edges, so CC's response reaches the client over THIS direct stream. Nil events for a
// reader-only attach (no servable endpoint).
func seatFromHandle(h *attachv1.AttachHandle) (driver.WriterSeat, <-chan attach.Event, func(), error) {
	local, ok := localHandle(h)
	if !ok {
		// No servable direct endpoint yet (gap 3): reader-only attach.
		fmt.Fprintln(os.Stderr, "serpent-tui: handle carries no servable direct endpoint — attaching READER-ONLY (input refused).")
		fmt.Fprintln(os.Stderr, "serpent-tui: (the host-agent direct-endpoint mint is the N4 keystone, gap 3 — see the package doc.)")
		return nil, nil, nil, nil
	}
	// Dial with a bounded retry to absorb the post-boot serving-leg race: the
	// orchestrator's Attach reply carries the host-agent's direct UDS endpoint, but the
	// host-agent stands the per-session serving leg up in its POST-BOOT hook — which can
	// land a beat AFTER CreateSession returns. A single dial then loses to a UDS that does
	// not yet exist ("connect: no such file or directory"). The serving leg binds within ~1-2s
	// of boot, so retry briefly before giving up; a still-absent socket after the window is the
	// real error. This is a transport-level liveness wait, not a fabrication — the endpoint is
	// the one the handle advertised; we only wait for its server to come up.
	var conn *hostbridge.SocketConn
	var err error
	deadline := time.Now().Add(writerSeatDialTimeout)
	for {
		conn, err = (&hostbridge.SocketTransport{}).Dial(local)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, nil, nil, fmt.Errorf("dial writer-seat direct endpoint (waited %s for the post-boot serving leg): %w", writerSeatDialTimeout, err)
		}
		time.Sleep(writerSeatDialRetryInterval)
	}
	return driver.SeatFromSocket(conn), conn.Events(), func() { _ = conn.Close() }, nil
}

// writerSeatDialTimeout / writerSeatDialRetryInterval bound the seatFromHandle dial
// retry that absorbs the post-boot serving-leg race (the host-agent binds the per-session
// attach UDS in its post-boot hook, which can land just after CreateSession returns).
const (
	writerSeatDialTimeout       = 20 * time.Second
	writerSeatDialRetryInterval = 250 * time.Millisecond
)

// localHandle maps the frozen proto attach.v1.AttachHandle onto the local
// hostbridge.AttachHandle the SocketTransport dials. The endpoint candidates are
// mapped transport-tag-for-transport-tag; only a servable direct candidate (the
// framed-UDS "unix" carrier the SocketTransport serves) makes the handle
// dialable here. Returns the local handle and whether a servable direct endpoint
// is present — false ⇒ reader-only (gap 3 not yet landed, or a relay-only
// handle, M2).
func localHandle(h *attachv1.AttachHandle) (hostbridge.AttachHandle, bool) {
	out := hostbridge.AttachHandle{
		SessionUUID: h.GetSessionUuid(),
		Auth:        hostbridge.AuthMaterial{Token: string(h.GetAuth().GetToken())},
		Role:        roleFromProto(h.GetRole()),
		ExpiresAt:   expiresAt(h.GetExpiresAt()),
	}
	servable := false
	for _, ep := range h.GetEndpoints() {
		t := transportFromProto(ep.GetTransport())
		out.Endpoints = append(out.Endpoints, hostbridge.EndpointCandidate{
			Transport: t,
			Address:   ep.GetAddress(),
		})
		// The SocketTransport dials TransportUnix (the realized framed-UDS direct
		// carrier); a handle with a servable unix endpoint is dialable here.
		if t == hostbridge.TransportUnix && ep.GetAddress() != "" {
			servable = true
		}
	}
	return out, servable
}

// roleFromProto maps the frozen attach.v1 Role enum onto the local hostbridge
// Role. An unspecified/unknown role maps to RoleReader (fail closed: never
// fabricate a writer seat the server did not grant, D61).
func roleFromProto(r attachv1.Role) hostbridge.Role {
	switch r {
	case attachv1.Role_ROLE_WRITER:
		return hostbridge.RoleWriter
	case attachv1.Role_ROLE_READER:
		return hostbridge.RoleReader
	default:
		return hostbridge.RoleReader
	}
}

// transportFromProto maps the frozen attach.v1 EndpointTransport enum onto the
// local hostbridge EndpointTransport. The realized DIRECT carrier the
// SocketTransport serves is the framed UDS (TransportUnix); the proto's DIRECT
// transport class maps to it so a direct endpoint is dialable. RELAY is the M2
// web-client carrier (not servable here); RAW_TERMINAL is the serpent claude --vm
// raw-pty surface (10-build-decisions §A3) — mapped to its own local tag so the
// candidate list is faithful (rawEndpoint then resolves it for the terminal dial);
// UNSPECIFIED maps to the direct class so a bare endpoint is still attempted
// rather than silently dropped.
func transportFromProto(t attachv1.EndpointTransport) hostbridge.EndpointTransport {
	switch t {
	case attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RELAY:
		return hostbridge.TransportRelay
	case attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL:
		return hostbridge.TransportRawTerminal
	default:
		// DIRECT (and UNSPECIFIED): the realized direct carrier is the framed UDS.
		return hostbridge.TransportUnix
	}
}

// expiresAt reconstructs the handle expiry from proto unix seconds (0 ⇒ the zero
// Time, i.e. no expiry pinned on the wire).
func expiresAt(secs uint64) time.Time {
	if secs == 0 {
		return time.Time{}
	}
	return time.Unix(int64(secs), 0).UTC()
}

func usage() {
	fmt.Fprintln(os.Stderr, "serpent-tui — human-in-the-loop attach to a VM-hosted Claude Code session (attach.v1)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  serpent-tui attach --orchestrator <addr> --session <uuid> [--color=false]")
	fmt.Fprintln(os.Stderr, "      attach to an existing session and drive it from the writer seat.")
	fmt.Fprintln(os.Stderr, "  serpent-tui up --orchestrator <addr> --repo <id> --env-config-ref <ref> [--role-ref R] [--color=false]")
	fmt.Fprintln(os.Stderr, "      provision a session (CreateSession) then attach to it in one command.")
	fmt.Fprintln(os.Stderr, "  serpent-tui spectate --emit-frames --session <uuid> [--orchestrator <addr>] [--from-seq N]")
	fmt.Fprintln(os.Stderr, "      subscribe as a READER and emit the raw attach.v1 frame stream (for `serpent spectate --stdin`).")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "  --orchestrator may be omitted if %s is set.\n", orchestratorEnv)
}
