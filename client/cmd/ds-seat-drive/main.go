// SPDX-License-Identifier: Apache-2.0
//
// Command ds-seat-drive is the HEADLESS writer-seat drive harness: the structured,
// runnable-from-a-script analogue of the DS_KVM_LIVE-gated goldentrace KVM-tier
// test (e2e.TestScriptedDriveKVMVMSideEffectReal). It drives ONE scripted Claude
// Code turn over a LIVE per-session KVM writer seat — the SAME e2e.DriveKVMScripted
// engine, the SAME e2e.DriveScriptScenario stepping, the SAME attach.v1 thin-client
// surface — but as a tiny standalone binary that can run INSIDE the L1 nested
// testbed, where the writer-seat UDS lives and there is NO Go toolchain to run
// `go test`. build-dataplane-debian.sh builds it (CGO_ENABLED=0) into the 9p bin/
// and boot-l1.sh stages it into the share, so the in-L1 orchestrator-boot-l2.sh can
// drive the per-session seat the live host-agent advertises.
//
// OSS (D15/D25): the operator drive surface is open. Stdlib + the client module's
// own e2e/hostbridge packages only (client/go.mod is stdlib-only externally).
//
// WHAT IT DOES NOT DO. It launches NO container, NO claude, NO cia, NO VM: it is a
// pure attach.v1 thin client that DIALS a writer seat a live ds-hostbridge serving
// child already advertises (resolved at runtime from DS_KVM_LIVE_*). The CC process
// lifecycle + the per-session token validation live behind the seat, in the
// host-agent — this harness touches neither.
//
// GATING (the offline default, the only path any build/test sees). The whole drive
// is behind DS_KVM_LIVE=1 (the KVM-tier live gate, distinct from DS_E2E_LIVE). With
// it UNSET — every CI / sandbox / `go build` + `go vet` run — the harness resolves
// nothing, DIALS NOTHING, and exits non-zero with the precise ErrKVMLiveGateUnset
// diagnostic ("this is the M1 deferred manual live step: there must be a live VM
// serving the session"). The live drive itself is the operator post-land step
// (LIVE-VALIDATION.md tier D), armed only by an operator who has a live VM serving
// the session and the DS_KVM_LIVE_* writer-seat knobs exported.
//
// CREDENTIALS (D50/raw-class). This harness NEVER reads, prints, or commits a
// credential: the short-lived session-scoped attach token is resolved by the e2e
// package from DS_KVM_LIVE_TOKEN (or a file via DS_KVM_LIVE_TOKEN_FILE) at runtime
// and held in memory only. ds-seat-drive itself names no token.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/e2e"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		// A gate-unset run is the expected offline default, not a crash: report it
		// distinctly (exit 2) so a caller can tell "the tier is not armed" apart from
		// "the live drive failed" (exit 1).
		if errors.Is(err, e2e.ErrKVMLiveGateUnset) {
			fmt.Fprintf(os.Stderr, "ds-seat-drive: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "ds-seat-drive: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("ds-seat-drive", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		prompt = fs.String("prompt", defaultPrompt,
			"the single user turn to drive into the live writer seat (attach.v1 input)")
		proof = fs.String("proof", "",
			"optional VM-side-effect proof token: when set, the turn instructs CC to write this token to -proof-file under /work and the run asserts the projected ask round-trip (the file readback is the operator's manual check on the guest /work share)")
		proofFile = fs.String("proof-file", "ds-seat-drive-proof.txt",
			"the proof file path (relative to the guest /work cwd) the -proof turn instructs CC to write")
		timeout = fs.Duration("timeout", 2*time.Minute,
			"per-turn deadline bounding the wait for the turn's result")
		allow = fs.Bool("allow", true,
			"answer any tool ask the turn provokes with allow (true) or deny (false) on the attach.v1 grant path")
		dumpEvents = fs.String("dump-events", "",
			"OPERATOR DIAGNOSTIC: write the projected attach.v1 event stream as JSON lines to this path ('-' for stdout). OFF by default because these events carry the runtime's VERBATIM text and tool output, which is exactly what the structured summary deliberately withholds; only turn it on when you are debugging a gated session on a host you own.")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, `ds-seat-drive — headless KVM writer-seat drive (the structured analogue of the
DS_KVM_LIVE-gated goldentrace KVM-tier test).

It drives ONE scripted Claude Code turn over the LIVE per-session writer seat the
host-agent serving child advertises, resolved at runtime from the environment:

  DS_KVM_LIVE=1           arm the tier (UNSET => dial nothing, exit 2)
  DS_KVM_LIVE_ATTACH_UDS  the host-local writer-seat the serving child advertises
  DS_KVM_LIVE_SESSION     the live session UUID the AttachHandle joins
  DS_KVM_LIVE_TOKEN       the short-lived session-scoped attach token, OR
  DS_KVM_LIVE_TOKEN_FILE  a file the token is read from
  DS_KVM_LIVE_TRANSPORT   optional carrier override (default "unix")

Usage:
  ds-seat-drive [flags]

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*prompt) == "" {
		return errors.New("-prompt must not be empty (a turn must drive something)")
	}

	// Build the single-turn scenario. With -proof set, instruct CC to write the
	// token to the proof file under /work and attach the VM-side-effect expectation
	// (the projected ask round-trip is asserted by the scenario; the file readback
	// is the operator's manual check on the guest /work share, per the KVM-tier test).
	turn := e2e.Turn{Prompt: *prompt, Allow: *allow}
	if strings.TrimSpace(*proof) != "" {
		if strings.TrimSpace(*proofFile) == "" {
			return errors.New("-proof set but -proof-file is empty")
		}
		// Compose a deterministic write instruction the same shape as the committed
		// proof.jsonl fixture: a Bash printf of the token to the proof file under /work.
		turn.Prompt = fmt.Sprintf(
			"Using the Bash tool, run exactly: printf '%%s' '%s' > /work/%s — then stop.",
			*proof, *proofFile)
		turn.Allow = true // a side-effect proof must allow the gated write
		turn.Assert = &e2e.TurnAssert{File: *proofFile, Contains: *proof}
	}

	// Honor SIGINT/SIGTERM so an operator can Ctrl-C a stuck live drive; the seat is
	// released on conn close (the host-agent owns the CC lifecycle, never reaped here).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	// Drive the scenario over the live writer seat resolved from DS_KVM_LIVE_* — the
	// SAME e2e.DriveKVMScripted engine the gated KVM-tier test uses, behind the SAME
	// DS_KVM_LIVE gate. Unset ⇒ ErrKVMLiveGateUnset, dialing nothing.
	res, err := e2e.DriveKVMScriptedFromEnv(ctx, e2e.DriveScriptScenario([]e2e.Turn{turn}, *timeout))
	if err != nil {
		return err
	}

	// Print the structured outcome an operator (and the in-L1 driver script) reads:
	// the projected attach.v1 event count, whether an ask was answered, and the
	// accounted-turn signal. No CC text and no credential is ever printed.
	// The event dump, when the operator asked for it. Written BEFORE the accounted-turn
	// check below, so a turn that FAILED to reach a result — the case you actually need
	// to debug — still yields its stream instead of being swallowed by the error return.
	if strings.TrimSpace(*dumpEvents) != "" {
		if err := writeEventDump(*dumpEvents, res.Events, stdout); err != nil {
			fmt.Fprintf(stderr, "ds-seat-drive: -dump-events: %v\n", err)
		}
	}

	results := countAccounted(res.Events)
	fmt.Fprintf(stdout, "ds-seat-drive: drove 1 turn over the live KVM writer seat\n")
	fmt.Fprintf(stdout, "  attach.v1 events : %d\n", len(res.Events))
	fmt.Fprintf(stdout, "  ask answered     : %t\n", res.AskAnswered)
	fmt.Fprintf(stdout, "  accounted turns  : %d\n", results)
	if turn.Assert != nil {
		fmt.Fprintf(stdout, "  proof (manual)   : inspect the guest /work share for %q containing the token (the host↔guest share mechanism is not assumed by this harness)\n", turn.Assert.File)
	}

	// Fail non-zero if the turn never reached an accounted result (the drive did not
	// close), so a caller can gate on a real round-trip, not just a clean dial.
	if results < 1 {
		return fmt.Errorf("the drive projected %d attach.v1 events but no accounted turn — the turn did not reach a result", len(res.Events))
	}
	return nil
}

// defaultPrompt is a PONG-style no-tool prompt: it reaches a result without
// provoking a tool ask, so a bare `ds-seat-drive` (no -proof) proves the live
// writer-seat round-trip with the lightest possible turn.
const defaultPrompt = "Reply with exactly the single word PONG and nothing else."

// countAccounted counts the session.accounted (turn-complete) events in the
// projected attach.v1 stream — the safe "the turn reached a result" signal the
// thin client advances on.
func countAccounted(evs []attach.Event) int {
	n := 0
	for _, ev := range evs {
		if ev.Type == attach.TypeSessionAccounted {
			n++
		}
	}
	return n
}

// writeEventDump serializes the projected attach.v1 events as JSON lines for an
// operator debugging a live gated session. It is deliberately NOT part of the normal
// output: the events carry the runtime's verbatim text and tool results, and the
// default summary withholds those on purpose.
func writeEventDump(path string, evs []attach.Event, stdout *os.File) error {
	w := stdout
	if path != "-" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	for i := range evs {
		if err := enc.Encode(&evs[i]); err != nil {
			return err
		}
	}
	return nil
}
