// SPDX-License-Identifier: Apache-2.0
//
// Command serpent is the friendly operator front-end for running Claude Code
// against the Dream Serpent backend.
//
//	serpent claude                 # the real interactive Claude Code TUI, egress via our gateway
//	serpent claude -- -p "hi"      # pass args through to claude
//	serpent claude --vm --repo R … # the interactive session INSIDE a VM via the running orchestrator
//	serpent drive  --prompt "…"    # headless: drive one prompt through the attach.v1 thin-client tier
//	serpent up     --repo R …      # provision (CreateSession) + attach to a VM session in one command
//	serpent sessions list          # enumerate VM sessions (ListSessions) via the orchestrator
//	serpent sessions destroy <id>  # tear a VM session down (DestroySession) via the orchestrator
//
// `serpent claude` WRAPS the real Claude Code TUI: it stands up the first-party
// ds-capture egress gateway on a free local port (never the protected :18080
// monitor), runs the real `claude` binary with its stdio inherited (so the full
// terminal UI works), routes its API egress through the gateway (HTTPS_PROXY +
// the gateway-minted CA + NODE_USE_ENV_PROXY=1 — the undici proxy switch), and
// tears the gateway down on exit. It is just `claude` + a local egress gateway,
// so it needs no container and no gate.
//
// `serpent claude --vm` (or the env trigger DS_ORCHESTRATOR set) instead routes the
// interactive session INTO a per-session VM via the running orchestrator: it EXECs the
// serpent-tui sibling (`up` to provision-then-attach, or `attach --session` for an
// existing one), exactly like `serpent up`, so the interactive loop IS the Claude Code
// running inside the VM (drive + render over attach.v1). gRPC never enters this
// stdlib-only client module (D80) — it is an exec of the sibling. The default (no --vm,
// no DS_ORCHESTRATOR) stays the local-CC-over-gateway path above.
//
// `serpent drive` is the gated (DS_E2E_LIVE=1) headless tier: it launches a real
// Claude Code in a rootless podman container fronted by the host-agent transport
// bridge and drives a single prompt over attach.v1, printing the projected event
// stream. It reuses client/goldentrace/e2e.DriveLivePrompt verbatim.
//
// `serpent up` is the friendly front door to the one-command provision-then-attach
// path: it EXECs the serpent-tui sibling binary (resolved exactly like ds-capture)
// and forwards the provisioning flags, so the operator has a single entry point
// without gRPC/bubbletea ever entering this stdlib-only client module (D80 module
// boundary — serpent-tui is the ONLY place grpc + orchestratorv1 may live). The
// child owns the interactive terminal; serpent passes signals through and
// surfaces its exit code.
//
// OSS (D15/D25): part of the open client tooling. Raw captures are raw-class
// (D50): they stay under the job dir and are removed on exit unless --keep.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/e2e"
	"github.com/dream-serpent/dream-serpent/client/tui"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

const protectedMonitorPort = 18080

const rootUsage = `serpent — run Claude Code against the Dream Serpent backend

usage: serpent <command> [flags]

commands:
  claude    Run the real interactive Claude Code TUI with its API egress routed
            through the first-party ds-capture gateway. The everyday command.
            Anything after '--' is passed through to claude. With --vm (or
            DS_ORCHESTRATOR set), the session runs INSIDE a VM via the running
            orchestrator instead (EXECs serpent-tui up/attach).
  drive     Headless: launch a real Claude Code in the podman backend fronted by
            the host-agent bridge and drive one prompt over attach.v1, printing
            the projected event stream. GATED on DS_E2E_LIVE=1.
  up        Provision a VM session (CreateSession) and attach to it in one
            command, by EXEC-ing the serpent-tui sibling binary. Flags are
            forwarded to serpent-tui up (--orchestrator/--repo/--env-config-ref…).
  sessions  Manage VM sessions over the running orchestrator (by EXEC-ing the
            serpent-tui sibling): 'sessions list' enumerates sessions
            (ListSessions, tabular); 'sessions destroy <uuid>' tears one down
            (DestroySession). Forwards --orchestrator (default: $DS_ORCHESTRATOR).
  spectate  Read-only spectator (D136): render a session's CHAT/TOOL/ASK/PLAN/
            QUOTA content frames off WatchSession. Never sends input. Renders a
            captured (--replay) or piped (--stdin) frame stream offline, or the
            LIVE stream (--session, DS_ORCH_LIVE-gated, via the serpent-tui
            sibling). Complements the webclient's state/seat read surface.

Run 'serpent <command> -h' for that command's flags.
See client/hostbridge/LIVE-VALIDATION.md for the full operator runbook.
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, rootUsage)
		return 2
	}
	switch args[0] {
	case "claude":
		return cmdClaude(args[1:])
	case "drive":
		return cmdDrive(args[1:])
	case "up":
		return cmdUp(args[1:])
	case "sessions":
		return cmdSessions(args[1:])
	case "spectate":
		return cmdSpectate(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, rootUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "serpent: unknown command %q\n\n%s", args[0], rootUsage)
		return 2
	}
}

// cmdClaude runs the real interactive Claude Code TUI. By default it runs LOCAL CC
// through the ds-capture egress gateway: stdio is inherited so the terminal UI works
// unchanged, and the only thing serpent injects is the proxy env that points CC's API
// egress at the gateway. No container, no DS_E2E_LIVE gate.
//
// With --vm (or the env trigger DS_ORCHESTRATOR set), the interactive session runs
// INSIDE a per-session VM via the running orchestrator instead: serpent EXECs
// `serpent-tui up` (CreateSession → the orchestrator boots the VM via the host-agent →
// Attach(WRITER) → the interactive loop that IS the CC inside the VM, over attach.v1).
// The local-CC path stays the default; --vm/DS_ORCHESTRATOR is the opt-in to the service.
func cmdClaude(args []string) int {
	fs := flag.NewFlagSet("claude", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	port := fs.Int("port", 0, "ds-capture egress-gateway port (0 = auto-pick a free port; never :18080)")
	captureBin := fs.String("capture-bin", "", "path to the ds-capture binary (default: $DS_CAPTURE_BIN, then PATH, then a sibling of this binary)")
	claudeBin := fs.String("claude", "", "claude binary to run (default: $CLAUDE_BIN, then `claude` on PATH)")
	scratch := fs.String("scratch", "", "job dir for the gateway CA + cassette (default: a temp dir under ~/tmp)")
	keep := fs.Bool("keep", false, "keep the raw-class job dir (cassette + CA) instead of removing it on exit (D50)")
	// --vm and friends route the session INTO a VM via the running orchestrator
	// (serpent-tui up/attach) instead of local CC. They are consulted ONLY on the
	// --vm / DS_ORCHESTRATOR branch; the default local-CC path ignores them.
	vm := fs.Bool("vm", false, "run the interactive session INSIDE a VM via the running orchestrator (serpent-tui up) instead of local CC")
	orchestrator := fs.String("orchestrator", "", "orchestrator SessionService endpoint host:port for --vm (default: $DS_ORCHESTRATOR)")
	repo := fs.String("repo", "", "repo / target the VM session works on (--vm; serpent-tui up --repo)")
	envConfigRef := fs.String("env-config-ref", "", "checked-in env-spec reference for the VM session (--vm; serpent-tui up --env-config-ref)")
	launchingUser := fs.String("launching-user", "", "user the VM session is created on behalf of (--vm; must be non-empty to pass the launch gate)")
	session := fs.String("session", "", "attach to this existing VM session instead of provisioning a new one (--vm; serpent-tui attach --session)")
	// --rm (--vm provision path only): make the VM session EPHEMERAL — destroy it on
	// exit instead of leaving it running for re-attach. Forwarded to `serpent-tui up
	// --rm`; it applies ONLY when we provision (the up path), never to --session attach
	// (we did not provision that one, so we never reap it). Without --rm the default
	// persist-on-detach behavior (D61) is unchanged.
	rm := fs.Bool("rm", false, "--vm: destroy the VM session on exit instead of leaving it running for re-attach (only when provisioning; ignored with --session)")
	serpentTuiBin := fs.String("serpent-tui-bin", "", "path to the serpent-tui binary for --vm (default: $DS_SERPENT_TUI_BIN, then PATH, then a sibling of this binary)")
	// Raw-terminal passthrough flags (--vm only): forwarded VERBATIM to serpent-tui
	// up/attach, where the raw-vs-structured surface decision lives (D80 — no gRPC
	// here, just a stdlib flag relay). When the VM's handle carries a raw-terminal
	// endpoint, the dev's terminal becomes the in-VM Claude Code; otherwise these
	// are inert (the structured loop is unchanged). They default to the serpent-tui
	// defaults, so an unset flag forwards nothing.
	rawMode := fs.String("raw", "", "--vm raw-terminal surface: auto|on|off (default auto in serpent-tui; raw iff the VM offers it + a TTY)")
	detachKey := fs.String("detach-key", "", "--vm local detach escape that leaves CC running (default ctrl-] in serpent-tui)")
	noAltScreen := fs.Bool("no-alt-screen", false, "--vm raw mode: stay on the main screen buffer (no alt-screen)")
	// Phase-2 structured-render toggles (--vm structured surface only): plumbed to
	// the in-VM interactive loop via the DS_TUI_* env gate (renderEnv), so the
	// serpent-tui loop renders RenderRich without coupling serpent-tui's app/cmd to
	// the options. They DEFAULT OFF — unset, the loop renders byte-identically to
	// today. They are inert on the local-CC path (the real claude TUI owns its own
	// rendering) and on the raw-terminal surface (it forwards real terminal bytes).
	render := registerRenderFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: serpent claude [--port N] [--capture-bin PATH] [--claude PATH] [--keep] [-- <claude args>]")
		fmt.Fprintln(os.Stderr, "       serpent claude --vm [--orchestrator host:port] --repo R --env-config-ref E --launching-user U [--rm] [--raw auto|on|off] [--detach-key K] [--no-alt-screen]")
		fmt.Fprintln(os.Stderr, "\nDefault: runs the real interactive Claude Code TUI with API egress routed through the")
		fmt.Fprintln(os.Stderr, "first-party ds-capture gateway. Args after '--' are passed through to claude.")
		fmt.Fprintln(os.Stderr, "With --vm (or DS_ORCHESTRATOR set): runs the session INSIDE a VM via the running")
		fmt.Fprintln(os.Stderr, "orchestrator (EXECs serpent-tui up/attach) — the interactive loop IS the CC in the VM.")
		fmt.Fprintln(os.Stderr, "In a VM with a raw-terminal endpoint your terminal becomes the in-VM Claude Code:")
		fmt.Fprintln(os.Stderr, "Ctrl-C interrupts CC, Ctrl-] detaches (the VM session keeps running — re-attach with --session).")
		fmt.Fprintln(os.Stderr, "With --panels the in-VM loop adds a fold affordance: Ctrl-O folds/unfolds the focused tool")
		fmt.Fprintln(os.Stderr, "panel ([+]/[-]), Ctrl-P / Ctrl-N move the focus across panels (Layer 5, doc 06).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// --vm / DS_ORCHESTRATOR routes the session INTO a VM via the running orchestrator:
	// EXEC serpent-tui up (provision-then-attach) or attach (an existing session) and
	// drop into its interactive loop, which IS the CC running inside the VM. The local-CC
	// body below stays the DEFAULT (no --vm, no DS_ORCHESTRATOR).
	if *vm || os.Getenv("DS_ORCHESTRATOR") != "" {
		binPath, err := resolveSerpentTuiBin(*serpentTuiBin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "serpent: %v\n", err)
			return 1
		}
		orch := *orchestrator
		if orch == "" {
			orch = os.Getenv("DS_ORCHESTRATOR")
		}
		// Raw-terminal flags forwarded verbatim to serpent-tui (a stdlib relay; the
		// raw-vs-structured decision lives in serpent-tui, D80). Only forwarded when
		// the operator set them, so an unset flag keeps serpent-tui's own defaults.
		rawArgs := rawPassthrough(*rawMode, *detachKey, *noAltScreen)
		// Phase-2 structured-render toggles ride the DS_TUI_* env gate (NOT serpent-tui
		// flags — serpent-tui's cmd does not parse them; the loop reads the env). The
		// exec inherits os.Environ() PLUS this slice, so the in-VM interactive loop
		// renders RenderRich per the toggles. Empty when no toggle is set ⇒ no env added
		// ⇒ the loop renders byte-identically to today.
		renderEnvArgs := render.env()
		if *session != "" {
			// Attach to an already-provisioned session rather than creating a new one.
			attachArgs := append([]string{"attach", "--orchestrator", orch, "--session", *session}, rawArgs...)
			return execSerpentTuiEnv(binPath, renderEnvArgs, attachArgs...)
		}
		upArgs := []string{"up", "--orchestrator", orch, "--repo", *repo, "--env-config-ref", *envConfigRef}
		if *launchingUser != "" {
			upArgs = append(upArgs, "--launching-user", *launchingUser)
		}
		// --rm rides ONLY the provision (up) path: serpent-tui up provisioned the
		// session, so it owns the ephemeral teardown on exit. The --session attach
		// branch above never reaps a session it did not provision.
		if *rm {
			upArgs = append(upArgs, "--rm")
		}
		upArgs = append(upArgs, rawArgs...)
		return execSerpentTuiEnv(binPath, renderEnvArgs, upArgs...)
	}

	if *port == protectedMonitorPort {
		fmt.Fprintf(os.Stderr, "serpent: refusing :%d — the protected shared monitor; omit --port to auto-pick a free one\n", protectedMonitorPort)
		return 2
	}
	captureBinPath, err := resolveCaptureBin(*captureBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent: %v\n", err)
		return 1
	}
	claudePath, err := resolveClaudeBin(*claudeBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent: %v\n", err)
		return 1
	}

	sess, cleanup, err := setupGateway(captureBinPath, *port, *scratch, *keep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent: %v\n", err)
		return 1
	}
	defer cleanup()
	fmt.Fprintf(os.Stderr, "serpent: egress gateway up on :%d — launching %s (Ctrl-C / exit to stop)\n", sess.port, claudePath)

	// The interactive claude shares our terminal's foreground process group, so a
	// Ctrl-C (SIGINT) — and a SIGTERM — is delivered to BOTH claude and serpent.
	// claude is the TUI: let IT own the signal (interrupt the turn / exit). serpent
	// must NOT die on that signal, or its deferred cleanup() (reap the gateway,
	// remove the raw-class job dir) would be skipped and the child + cassette
	// leaked. So we hold the signals here for the duration of the child run and
	// drain them; serpent survives until claude exits and cleanup runs. We stop
	// notifying (restoring default disposition) the moment claude returns.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for range sigCh {
		}
	}()

	// Run the real claude with its stdio INHERITED so the TUI works, and the
	// proxy env injected so its API egress flows through our gateway.
	cl := exec.Command(claudePath, fs.Args()...)
	cl.Stdin = os.Stdin
	cl.Stdout = os.Stdout
	cl.Stderr = os.Stderr
	cl.Env = append(os.Environ(), proxyEnv(sess.port, sess.caFile)...)
	runErr := cl.Run()
	signal.Stop(sigCh)
	close(sigCh)
	<-drainDone

	if *keep {
		fmt.Fprintf(os.Stderr, "serpent: gateway cassette kept at %s — scrub before any promotion (D50):\n", sess.cassette)
		fmt.Fprintf(os.Stderr, "    ds-capture scrub %q --out <synthetic> --provenance synthetic\n", sess.cassette)
	}
	return exitCodeOf(runErr)
}

// cmdDrive is the gated headless tier: drive one prompt through a real Claude
// Code in the podman backend over attach.v1 and print the projected event
// stream. It reuses e2e.DriveLivePrompt verbatim.
func cmdDrive(args []string) int {
	fs := flag.NewFlagSet("drive", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	prompt := fs.String("prompt", "Briefly introduce yourself in one sentence.", "the prompt to drive into the session")
	deny := fs.Bool("deny", false, "deny a native tool ask instead of allowing it")
	port := fs.Int("port", 0, "ds-capture egress-gateway port (0 = auto-pick a free port; never :18080)")
	captureBin := fs.String("capture-bin", "", "path to the ds-capture binary (default: $DS_CAPTURE_BIN, then PATH, then a sibling of this binary)")
	scratch := fs.String("scratch", "", "job dir for the staged CA, UDS, and raw capture (default: a temp dir under ~/tmp)")
	keep := fs.Bool("keep", false, "keep the raw-class job dir instead of removing it on exit (D50)")
	timeout := fs.Duration("timeout", 4*time.Minute, "overall deadline for the drive")
	// Phase-2 structured-render toggles for the projected-event view. Headless drive
	// prints the seq/type summary by default; when ANY of these is set it ALSO folds
	// the projected attach.v1 events into the client/tui Model and renders the
	// structured surface (RenderRich, or RenderPlain for --no-color). Default OFF ⇒
	// the summary-only output is byte-identical to today.
	render := registerRenderFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: serpent drive [--prompt TEXT] [--deny] [--port N] [--capture-bin PATH] [--keep] [--diffs] [--highlight] [--panels] [--expanded] [--no-color]")
		fmt.Fprintln(os.Stderr, "\nHeadless: drives a prompt through a real Claude Code in the podman backend over")
		fmt.Fprintln(os.Stderr, "attach.v1 and prints the projection. GATED on DS_E2E_LIVE=1.")
		fmt.Fprintln(os.Stderr, "With a render toggle it also renders the structured surface (Phase-2, doc 06).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *port == protectedMonitorPort {
		fmt.Fprintf(os.Stderr, "serpent: refusing :%d — the protected shared monitor; omit --port to auto-pick a free one\n", protectedMonitorPort)
		return 2
	}
	if os.Getenv(e2e.LiveGateEnv) != "1" {
		fmt.Fprintf(os.Stderr, "serpent drive is the LIVE tier: it launches a real Claude Code container and spends API budget.\n")
		fmt.Fprintf(os.Stderr, "Arm it explicitly:  DS_E2E_LIVE=1 serpent drive --prompt %q\n", *prompt)
		fmt.Fprintf(os.Stderr, "(unset, nothing is launched — see client/hostbridge/LIVE-VALIDATION.md)\n")
		return 1
	}
	captureBinPath, err := resolveCaptureBin(*captureBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	driveCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	sess, cleanup, err := setupGateway(captureBinPath, *port, *scratch, *keep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent: %v\n", err)
		return 1
	}
	defer cleanup()
	fmt.Fprintf(os.Stderr, "serpent: egress gateway up on :%d (job dir: %s)\n", sess.port, sess.jobDir)

	cfg := e2e.LiveDriveConfigDefaults()
	cfg.ProxyPort = sess.port
	cfg.PodmanNetwork = fmt.Sprintf("pasta:-T,%d", sess.port)
	cfg.CAHost = sess.caFile
	cfg.ScratchDir = filepath.Join(sess.jobDir, "live")
	if err := os.MkdirAll(cfg.ScratchDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "serpent: live scratch: %v\n", err)
		return 1
	}

	sessionUUID := fmt.Sprintf("serpent-%d", time.Now().Unix())
	fmt.Fprintf(os.Stderr, "serpent: driving Claude Code (Sonnet) — prompt: %q\n", *prompt)
	res, err := e2e.DriveLivePrompt(driveCtx, cfg, sessionUUID, *prompt, !*deny)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent: drive failed: %v\n", err)
		return 1
	}
	fmt.Printf("\nserpent: projected %d attach.v1 events from live Claude Code:\n", len(res.Events))
	for _, ev := range res.Events {
		fmt.Printf("  seq=%-2d %s\n", ev.Seq, ev.Type)
	}
	// Optional Phase-2 structured render of the projected events (doc 06). Default
	// OFF — only when a render toggle is set; the summary above is unchanged. Errors
	// here are non-fatal (the drive already succeeded): the render is a convenience.
	if render.any() {
		if err := renderDriveProjection(os.Stdout, res.Events, render); err != nil {
			fmt.Fprintf(os.Stderr, "serpent: structured render of projection failed (non-fatal): %v\n", err)
		}
	}
	if res.AskAnswered {
		verb := "allowed"
		if *deny {
			verb = "denied"
		}
		fmt.Printf("serpent: a native tool ask was %s on the grant path (route=%v)\n", verb, res.GrantRoute)
	}
	if len(res.Warnings) > 0 {
		fmt.Printf("serpent: %d adapter warnings (drift, non-fatal): %v\n", len(res.Warnings), res.Warnings)
	}
	fmt.Fprintf(os.Stderr, "serpent: raw capture (raw-class, D50): %s\n", res.RawCapturePath)
	return 0
}

// cmdUp is the friendly front end to the one-command provision-then-attach path:
// it resolves the serpent-tui sibling binary and EXECs `serpent-tui up` with the
// provisioning flags forwarded verbatim. gRPC + the orchestrator client live in
// serpent-tui (out of go.work), NOT here — this module stays stdlib-only, so the
// only coupling is an exec of a sibling binary (exactly how cmdClaude reaches
// ds-capture). The child is the interactive TUI; serpent inherits its stdio,
// holds SIGINT/SIGTERM for the child's lifetime so the child (not serpent) owns
// the signal, and surfaces the child's exit code.
//
// All flags/args after `up` are passed straight through to serpent-tui (so
// `serpent up -h` prints serpent-tui's own up usage); the only serpent-side flag
// is --serpent-tui-bin, peeled off the front if present, to point at an explicit
// binary (default: $DS_SERPENT_TUI_BIN, then PATH, then a sibling of this binary).
func cmdUp(args []string) int {
	explicitBin, rest := peelSerpentTuiBin(args)
	binPath, err := resolveSerpentTuiBin(explicitBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent: %v\n", err)
		return 1
	}
	return execSerpentTui(binPath, append([]string{"up"}, rest...)...)
}

// execSerpentTui runs the serpent-tui sibling binary with the given argv (the
// leading verb — `up` or `attach` — and its forwarded flags), inheriting serpent's
// stdio so the interactive TUI works, and returns its exit code. It holds the
// foreground signals for the child's lifetime: the interactive serpent-tui shares
// our process group, so a Ctrl-C reaches BOTH. Let the child own it (interrupt/quit
// the TUI); serpent must survive so it can surface the child's exit code rather than
// dying mid-signal. Shared by `serpent up` and the `serpent claude --vm` branch.
func execSerpentTui(binPath string, args ...string) int {
	return execSerpentTuiEnv(binPath, nil, args...)
}

// execSerpentTuiEnv is execSerpentTui plus extra environment entries (the
// DS_TUI_* structured-render gate the `serpent claude --vm` path sets so the
// in-VM interactive loop renders RenderRich). The child inherits os.Environ()
// THEN extraEnv (later entries win), so an empty extraEnv leaves the environment
// exactly as inherited — the default-off, byte-identical case.
func execSerpentTuiEnv(binPath string, extraEnv []string, args ...string) int {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for range sigCh {
		}
	}()

	cmd := exec.Command(binPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), extraEnv...)
	runErr := cmd.Run()

	signal.Stop(sigCh)
	close(sigCh)
	<-drainDone
	return exitCodeOf(runErr)
}

// peelSerpentTuiBin pulls a leading `--serpent-tui-bin PATH` (or
// `--serpent-tui-bin=PATH`) off the front of args so it is consumed by serpent
// and NOT forwarded to serpent-tui. Everything else is forwarded verbatim. Only
// a LEADING occurrence is peeled (the dispatcher contract: serpent flags precede
// the forwarded provisioning flags); anything after the first non-matching token
// is the child's to parse.
func peelSerpentTuiBin(args []string) (bin string, rest []string) {
	if len(args) == 0 {
		return "", nil
	}
	switch {
	case args[0] == "--serpent-tui-bin" && len(args) >= 2:
		return args[1], args[2:]
	case strings.HasPrefix(args[0], "--serpent-tui-bin="):
		return strings.TrimPrefix(args[0], "--serpent-tui-bin="), args[1:]
	default:
		return "", args
	}
}

// rawPassthrough builds the serpent-tui raw-terminal argv tail from the serpent
// --vm raw flags, forwarding ONLY the ones the operator set (an empty --raw /
// --detach-key and an unset --no-alt-screen forward nothing, so serpent-tui keeps
// its own defaults). It is a pure stdlib string relay — no gRPC, no proto (D80):
// the raw-vs-structured surface decision lives entirely in serpent-tui.
func rawPassthrough(rawMode, detachKey string, noAltScreen bool) []string {
	var args []string
	if rawMode != "" {
		args = append(args, "--raw", rawMode)
	}
	if detachKey != "" {
		args = append(args, "--detach-key", detachKey)
	}
	if noAltScreen {
		args = append(args, "--no-alt-screen")
	}
	return args
}

// --- Phase-2 structured-render flags (the DS_TUI_* env gate) -----------------

// DS_TUI_* are the structured-render gate names the serpent-tui interactive loop
// reads (serpent-tui/internal/loop/renderopts.go). serpent sets them on the
// exec'd serpent-tui so the `--diffs/--highlight/--panels/--expanded/--no-color`
// toggles reach the in-VM loop WITHOUT serpent-tui's cmd parsing them — the loop
// reads the environment, keeping the two flagsets disjoint. Each is OFF when the
// flag is unset, so the loop renders byte-identically to today by default.
const (
	envTUIDiffs         = "DS_TUI_DIFFS"
	envTUIHighlight     = "DS_TUI_HIGHLIGHT"
	envTUIPanels        = "DS_TUI_PANELS"
	envTUIExpanded      = "DS_TUI_EXPANDED"
	envTUIContextRadius = "DS_TUI_CONTEXT_RADIUS"
	envTUINoColor       = "DS_TUI_NO_COLOR"
)

// renderFlags holds the Phase-2 structured-render toggles parsed off a command
// flagset. They are forwarded to the in-VM interactive loop as the DS_TUI_* env
// gate (env), never as serpent-tui flags — the structured-render decision lives
// in the loop (D80: serpent stays a stdlib flag/env relay).
type renderFlags struct {
	diffs         *bool
	highlight     *bool
	panels        *bool
	expanded      *bool
	contextRadius *int
	noColor       *bool
}

// registerRenderFlags registers
// --diffs/--highlight/--panels/--expanded/--context-radius/--no-color on fs and
// returns their bound values. All DEFAULT OFF (and --context-radius defaults 0 ⇒
// diffview's default), so an unset flag forwards nothing and the loop's default
// render is unchanged.
func registerRenderFlags(fs *flag.FlagSet) renderFlags {
	return renderFlags{
		diffs:         fs.Bool("diffs", false, "--vm structured surface: reconstruct unified diffs for file-edit tools (Layer 2)"),
		highlight:     fs.Bool("highlight", false, "--vm structured surface: ANSI syntax highlighting (Layer 3)"),
		panels:        fs.Bool("panels", false, "--vm structured surface: collapse tool I/O into foldable panels (Layer 5; Ctrl-O folds the focused panel, Ctrl-P/Ctrl-N move focus)"),
		expanded:      fs.Bool("expanded", false, "--vm structured surface: start tool panels expanded (only with --panels)"),
		contextRadius: fs.Int("context-radius", 0, "--vm structured surface: unchanged context lines kept on each side of a diff hunk (0 = diffview default 3; only with --diffs)"),
		noColor:       fs.Bool("no-color", false, "--vm structured surface: the byte-stable plain surface (no color, no enrichment)"),
	}
}

// env renders the toggles as the DS_TUI_* env entries to pass to the exec'd
// serpent-tui. Only the SET toggles emit an entry (each as `NAME=1`), so an
// all-default invocation returns nil — the child inherits an unmodified
// environment and the loop renders byte-identically to today. --context-radius is
// an INT and emits `DS_TUI_CONTEXT_RADIUS=N` ONLY when set positive: a 0 (the
// default) means "use diffview's default", so it adds no entry and the env stays
// the unmodified default-off case.
func (r renderFlags) env() []string {
	var env []string
	add := func(name string, on *bool) {
		if on != nil && *on {
			env = append(env, name+"=1")
		}
	}
	add(envTUIDiffs, r.diffs)
	add(envTUIHighlight, r.highlight)
	add(envTUIPanels, r.panels)
	add(envTUIExpanded, r.expanded)
	if r.contextRadius != nil && *r.contextRadius > 0 {
		env = append(env, fmt.Sprintf("%s=%d", envTUIContextRadius, *r.contextRadius))
	}
	add(envTUINoColor, r.noColor)
	return env
}

// any reports whether ANY render toggle is set (including --no-color). It gates
// the optional structured render of the drive projection — false ⇒ the
// summary-only output is unchanged.
func (r renderFlags) any() bool {
	return on(r.diffs) || on(r.highlight) || on(r.panels) || on(r.expanded) || on(r.noColor)
}

// opts builds the tui.RenderOpts for the enrichment toggles (excluding
// --no-color, which is a color decision routed separately). All-off yields the
// zero RenderOpts (byte-identical baseline). --context-radius threads in as
// ContextRadius; it is NOT an enrichment toggle (a 0 resolves to diffview's default
// and isZero() ignores it), so a bare --context-radius still routes to RenderPlain.
func (r renderFlags) opts() tui.RenderOpts {
	return tui.RenderOpts{Diffs: on(r.diffs), Highlight: on(r.highlight), Panels: on(r.panels), Expanded: on(r.expanded), ContextRadius: radius(r.contextRadius)}
}

// noColorSet reports whether --no-color was requested (route to RenderPlain).
func (r renderFlags) noColorSet() bool { return on(r.noColor) }

// on safely dereferences a bound *bool flag (nil ⇒ false).
func on(b *bool) bool { return b != nil && *b }

// radius safely dereferences a bound *int flag (nil or negative ⇒ 0, which
// RenderOpts treats as diffview's default 3). It clamps below at 0 so a stray
// negative never widens the diff window.
func radius(n *int) int {
	if n == nil || *n < 0 {
		return 0
	}
	return *n
}

// renderDriveProjection folds the projected attach.v1 events into the client/tui
// Model and renders the Phase-2 structured surface: --no-color routes to the
// byte-stable RenderPlain, a zero opts to RenderPlain too (the default-off
// baseline), and any selected enrichment to RenderRich. A fold error (an
// out-of-order seq, P10/D79) is returned to the caller, which treats it as
// non-fatal — the drive already succeeded; the render is a convenience view.
func renderDriveProjection(w io.Writer, events []attach.Event, render renderFlags) error {
	m := tui.NewModel()
	for _, ev := range events {
		if err := m.Apply(ev); err != nil {
			return err
		}
	}
	opts := render.opts()
	fmt.Fprintln(w, "\nserpent: structured render (Phase-2, doc 06):")
	if render.noColorSet() || opts == (tui.RenderOpts{}) {
		return tui.RenderPlain(w, m)
	}
	return tui.RenderRich(w, m, opts)
}

// --- gateway lifecycle (shared by claude + drive) ----------------------------

// gatewaySession is a started ds-capture gateway plus its job-dir paths.
type gatewaySession struct {
	jobDir, caFile, cassette string
	port                     int
	gw                       *gateway
}

// setupGateway picks a port (if 0), creates the job dir, starts ds-capture, and
// waits for it to be ready. The returned cleanup stops the gateway and (unless
// keep) removes the raw-class job dir.
func setupGateway(captureBin string, port int, scratch string, keep bool) (*gatewaySession, func(), error) {
	if port == 0 {
		p, err := freePort()
		if err != nil {
			return nil, nil, fmt.Errorf("pick free port: %w", err)
		}
		port = p
	}
	jobDir := scratch
	if jobDir == "" {
		d, err := os.MkdirTemp(scratchRoot(), "serpent-")
		if err != nil {
			return nil, nil, fmt.Errorf("job dir: %w", err)
		}
		jobDir = d
	} else if err := os.MkdirAll(jobDir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("job dir: %w", err)
	}
	cassette := filepath.Join(jobDir, "gateway-cassette.json")
	caDir := filepath.Join(jobDir, "ca")
	caFile := filepath.Join(caDir, "ds-capture-ca.pem")
	gwLog := filepath.Join(jobDir, "gateway.log")

	gw, err := startGateway(captureBin, port, cassette, caDir, gwLog)
	if err != nil {
		if !keep {
			os.RemoveAll(jobDir)
		}
		return nil, nil, fmt.Errorf("%v (see %s)", err, gwLog)
	}
	if err := gw.waitReady(port, caFile, 15*time.Second); err != nil {
		gw.stop()
		if !keep {
			os.RemoveAll(jobDir)
		}
		return nil, nil, fmt.Errorf("%v (see %s)", err, gwLog)
	}
	sess := &gatewaySession{jobDir: jobDir, caFile: caFile, cassette: cassette, port: port, gw: gw}
	cleanup := func() {
		gw.stop()
		if !keep {
			os.RemoveAll(jobDir)
		}
	}
	return sess, cleanup, nil
}

// proxyEnv is the env that points a child's API egress at the local gateway.
func proxyEnv(port int, caFile string) []string {
	p := fmt.Sprintf("http://127.0.0.1:%d", port)
	return []string{
		"HTTPS_PROXY=" + p,
		"HTTP_PROXY=" + p,
		"NODE_USE_ENV_PROXY=1", // undici honours the proxy env only with this (PHASE2 P6)
		"NODE_EXTRA_CA_CERTS=" + caFile,
	}
}

type gateway struct {
	cmd     *exec.Cmd
	done    chan error    // carries the child's exit (cmd.Wait), then is CLOSED
	stopped chan struct{} // closed once stop() has run, so stop is idempotent
}

// startGateway launches `ds-capture record` as a child, with its output to log.
// A single goroutine owns cmd.Wait(): it publishes the exit on done and then
// CLOSES done, so done is readable any number of times by both waitReady and
// stop (the first read gets the exit error; later reads get nil from the closed
// channel). That makes the lifecycle observable without racing on Wait and
// without either reader stealing the one value the other needs.
func startGateway(bin string, port int, cassette, caDir, logPath string) (*gateway, error) {
	lf, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("gateway log: %w", err)
	}
	cmd := exec.Command(bin, "record",
		"--port", fmt.Sprint(port), "--cassette", cassette, "--ca-dir", caDir)
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		return nil, fmt.Errorf("start ds-capture gateway: %w", err)
	}
	g := &gateway{cmd: cmd, done: make(chan error, 1), stopped: make(chan struct{})}
	go func() {
		g.done <- cmd.Wait()
		close(g.done)
		lf.Close()
	}()
	return g, nil
}

// stop SIGINTs the gateway (it writes the cassette on the way out) and reaps it.
// It is idempotent (cleanup may run via defer AND the error paths in
// setupGateway) and safe to call after the child has already exited — done is a
// closed channel by then, so every receive returns immediately.
func (g *gateway) stop() {
	if g == nil || g.cmd == nil || g.cmd.Process == nil {
		return
	}
	select {
	case <-g.stopped: // already stopped — the child is already reaped.
		return
	default:
		close(g.stopped)
	}
	_ = g.cmd.Process.Signal(syscall.SIGINT)
	select {
	case <-g.done:
	case <-time.After(5 * time.Second):
		_ = g.cmd.Process.Kill()
		<-g.done
	}
}

// waitReady blocks until OUR gateway child is accepting connections on port AND
// has written its CA — or fails fast if the child exits early (e.g. the port was
// already bound). It checks child liveness FIRST each iteration so a STALE
// process answering the same port cannot masquerade as ours.
func (g *gateway) waitReady(port int, caFile string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for {
		select {
		case err := <-g.done:
			return fmt.Errorf("ds-capture gateway exited before it was ready (%v) — is :%d already in use?", err, port)
		default:
		}
		if _, statErr := os.Stat(caFile); statErr == nil {
			if c, dErr := net.DialTimeout("tcp", addr, 200*time.Millisecond); dErr == nil {
				_ = c.Close()
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ds-capture gateway did not come up on :%d within %s", port, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// --- resolution helpers ------------------------------------------------------

// resolveCaptureBin finds the ds-capture binary: an explicit flag, then
// $DS_CAPTURE_BIN, then PATH, then a sibling of this binary (the .bin/ layout).
func resolveCaptureBin(explicit string) (string, error) {
	for _, c := range []string{explicit, os.Getenv("DS_CAPTURE_BIN")} {
		if c == "" {
			continue
		}
		if isExecutable(c) {
			return c, nil
		}
		return "", fmt.Errorf("ds-capture binary %q is not executable", c)
	}
	if p, err := exec.LookPath("ds-capture"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "ds-capture")
		if isExecutable(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("ds-capture not found — build it and put it on PATH:\n" +
		"    go build -o .bin/ds-capture ./client/cmd/ds-capture   (then PATH=.bin:$PATH, or pass --capture-bin)")
}

// resolveSerpentTuiBin finds the serpent-tui binary: an explicit value, then
// $DS_SERPENT_TUI_BIN, then PATH, then a sibling of this binary (the .bin/
// layout) — exactly the resolution order resolveCaptureBin uses for ds-capture.
func resolveSerpentTuiBin(explicit string) (string, error) {
	for _, c := range []string{explicit, os.Getenv("DS_SERPENT_TUI_BIN")} {
		if c == "" {
			continue
		}
		if isExecutable(c) {
			return c, nil
		}
		return "", fmt.Errorf("serpent-tui binary %q is not executable", c)
	}
	if p, err := exec.LookPath("serpent-tui"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "serpent-tui")
		if isExecutable(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("serpent-tui not found — build it and put it on PATH:\n" +
		"    (cd serpent-tui && GOWORK=off go build -o ../.bin/serpent-tui ./cmd/serpent-tui)   (then PATH=.bin:$PATH, or pass --serpent-tui-bin)")
}

// resolveClaudeBin finds the claude binary: an explicit flag (path or name),
// then $CLAUDE_BIN, then `claude` on PATH.
func resolveClaudeBin(explicit string) (string, error) {
	for _, c := range []string{explicit, os.Getenv("CLAUDE_BIN")} {
		if c == "" {
			continue
		}
		if isExecutable(c) {
			return c, nil
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("claude binary %q not found or not executable", c)
	}
	if p, err := exec.LookPath("claude"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("claude not found on PATH (pass --claude PATH or set CLAUDE_BIN)")
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

// exitCodeOf maps a child exec error to a process exit code.
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 1
}

// freePort asks the kernel for an unused loopback TCP port.
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// scratchRoot picks ~/tmp (btrfs/reflink, not tmpfs), honoring DS_WT_ROOT; falls
// back to the system temp root only when home is unavailable.
func scratchRoot() string {
	if r := os.Getenv("DS_WT_ROOT"); r != "" {
		_ = os.MkdirAll(r, 0o755)
		return r
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		r := filepath.Join(home, "tmp")
		if os.MkdirAll(r, 0o755) == nil {
			return r
		}
	}
	return "" // os.MkdirTemp falls back to TMPDIR
}
