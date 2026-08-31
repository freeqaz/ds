// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/protobuf/proto"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// cmdSpectate is `serpent spectate` — the READER-side (D136 spectator) view of a
// session's CONTENT stream. The control plane fans WatchSession out to N readers
// (D61 one-writer/N-reader, doc 15 §5.3); this command consumes the CONTENT
// frames off that stream — chat, tool activity, approval asks, plan deltas, and
// quota — and renders them STRICTLY READ-ONLY. A spectator has no seat and no
// input path: this command opens exactly zero write RPCs (the frozen
// orchestrator.v1 has none), so it can never drive, approve, or perturb the
// session. It only reads and prints.
//
//	serpent spectate --replay <file>              # render a captured WatchSession frame dump
//	serpent spectate --stdin                      # render frames piped on stdin
//	serpent spectate --session <uuid> [--orchestrator A]   # LIVE (DS_ORCH_LIVE-gated)
//
// SURFACE SPLIT (documented in paid/webclient/README.md). The webclient read leg
// renders the STATE/SEAT edges of a session (lifecycle state, the writer-seat
// holder — paid/webclient/attach folds those proto events into its own read-only
// model). `serpent spectate` is the complementary surface: the CONTENT frames
// (CHAT/TOOL/ASK/PLAN/QUOTA) a spectator watches. Together they cover the D61
// N-reader UX; neither writes.
//
// D80 MODULE FENCE. This client module is stdlib-only + proto/gen/go (the sole
// cross-tree import). It therefore never dials gRPC itself: the WatchSession
// server-streaming subscription is the serpent-tui sibling's job (the one module
// that may import google.golang.org/grpc + orchestratorv1 — where watch.go and
// eventmap.go already live). The LIVE leg here is the render half: serpent-tui
// emits the raw frozen attach.v1.SessionEvent frames (length-delimited, the
// codec below), and THIS command decodes and renders them read-only. The
// OFFLINE legs (--replay / --stdin) exercise the exact same renderer against a
// captured or piped frame stream, so the projection is fully unit-testable with
// no gRPC and no orchestrator in this module.
//
// OSS (D15/D25): part of the open client tooling.
func cmdSpectate(args []string) int {
	fs := flag.NewFlagSet("spectate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	replay := fs.String("replay", "", "render a captured WatchSession frame dump (length-delimited attach.v1.SessionEvent) from this file")
	fromStdin := fs.Bool("stdin", false, "read the length-delimited attach.v1.SessionEvent frame stream from stdin")
	session := fs.String("session", "", "session UUID to spectate LIVE (requires DS_ORCH_LIVE=1; dials via the serpent-tui sibling)")
	orchestrator := fs.String("orchestrator", "", "orchestrator WatchSession endpoint host:port for the LIVE leg (default: $DS_ORCHESTRATOR)")
	fromSeq := fs.Uint64("from-seq", 0, "resume the LIVE subscription from this per-event seq (0 = the current frontier; D61 slow-reader recovery)")
	serpentTuiBin := fs.String("serpent-tui-bin", "", "path to the serpent-tui binary for the LIVE leg (default: $DS_SERPENT_TUI_BIN, then PATH, then a sibling)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: serpent spectate (--replay FILE | --stdin | --session UUID [--orchestrator A] [--from-seq N])")
		fmt.Fprintln(os.Stderr, "\nRead-only spectator (D136): renders a session's CHAT/TOOL/ASK/PLAN/QUOTA content")
		fmt.Fprintln(os.Stderr, "frames off WatchSession. Never sends input. The LIVE leg is GATED on DS_ORCH_LIVE=1.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Exactly one source. --replay and --stdin are the offline renderers; a
	// --session picks the live leg. Reject an ambiguous combination up front so the
	// read-only contract stays legible (there is only ever one frame source).
	sources := 0
	if *replay != "" {
		sources++
	}
	if *fromStdin {
		sources++
	}
	if *session != "" {
		sources++
	}
	if sources == 0 {
		fmt.Fprint(os.Stderr, spectateUsageHint)
		return 2
	}
	if sources > 1 {
		fmt.Fprintln(os.Stderr, "serpent spectate: choose exactly one frame source — --replay, --stdin, or --session")
		return 2
	}

	switch {
	case *replay != "":
		f, err := os.Open(*replay)
		if err != nil {
			fmt.Fprintf(os.Stderr, "serpent spectate: %v\n", err)
			return 1
		}
		defer f.Close()
		return spectateFrom(os.Stdout, f)
	case *fromStdin:
		return spectateFrom(os.Stdout, os.Stdin)
	default:
		return spectateLive(*session, *orchestrator, *fromSeq, *serpentTuiBin)
	}
}

const spectateUsageHint = `serpent spectate: pick a frame source
  --replay FILE      render a captured WatchSession frame dump
  --stdin            render frames piped on stdin
  --session UUID     spectate LIVE (DS_ORCH_LIVE=1; via the serpent-tui sibling)

serpent spectate is a READ-ONLY spectator (D136): it renders CHAT/TOOL/ASK/PLAN/QUOTA
content frames and never sends input. Run 'serpent spectate -h' for all flags.
`

// spectateFrom decodes the length-delimited attach.v1.SessionEvent frame stream
// on r and renders each CONTENT frame read-only to w. It is the shared offline
// AND live renderer (the live leg pipes the serpent-tui sibling's stdout in
// here), so one code path covers replay files, stdin, and the live subscription.
// A clean end-of-stream (io.EOF at a frame boundary) is success; a truncated or
// malformed frame is an error.
func spectateFrom(w io.Writer, r io.Reader) int {
	if _, err := renderSpectateStream(w, r); err != nil {
		fmt.Fprintf(os.Stderr, "serpent spectate: %v\n", err)
		return 1
	}
	return 0
}

// renderSpectateStream reads every length-delimited frame off r, renders the
// CONTENT frames to w, and returns the count of frames RENDERED (content frames;
// state/seat/accounting frames are skipped — those are the webclient's surface).
// Non-content frames are counted as skipped, never rendered.
func renderSpectateStream(w io.Writer, r io.Reader) (rendered int, err error) {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	defer func() {
		if ferr := bw.Flush(); ferr != nil && err == nil {
			err = ferr
		}
	}()
	for {
		ev, derr := readDelimitedFrame(br)
		if errors.Is(derr, io.EOF) {
			return rendered, nil
		}
		if derr != nil {
			return rendered, derr
		}
		ok, rerr := renderContentFrame(bw, ev)
		if rerr != nil {
			return rendered, rerr
		}
		if ok {
			rendered++
		}
	}
}

// renderContentFrame renders ONE session event to w iff it is a CONTENT frame,
// returning whether it was rendered. The rendered classes are exactly the ones a
// spectator watches — CHAT (message + live-tail delta), TOOL (invoked +
// completed), ASK (requested + resolved), PLAN, and QUOTA. Everything else
// (SESSION_INIT/STATE, WRITER_SEAT_CHANGED, INPUT_ACTIVITY, the SUBAGENT_* and
// SESSION_ACCOUNTED accounting frames) is a STATE/SEAT/accounting edge — the
// webclient's read surface, not this one — and is skipped so the two surfaces do
// not double-render the same stream.
//
// Every line is read-only text keyed by the per-event seq; this function opens
// no RPC and mutates no session state (D136 spectator).
func renderContentFrame(w io.Writer, ev *attachv1.SessionEvent) (bool, error) {
	seq := ev.GetSeq()
	switch ev.GetType() {
	case attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE:
		m := ev.GetChatMessage()
		return true, writeLine(w, seq, "chat", fmt.Sprintf("%s: %s", roleOr(m.GetRole()), chatText(m)))
	case attachv1.EventType_EVENT_TYPE_CHAT_DELTA:
		d := ev.GetChatDelta()
		suffix := ""
		if d.GetFinal() {
			suffix = " (final)"
		}
		return true, writeLine(w, seq, "chat", fmt.Sprintf("…%s%s", oneLine(d.GetText()), suffix))
	case attachv1.EventType_EVENT_TYPE_TOOL_INVOKED:
		t := ev.GetToolInvoked()
		return true, writeLine(w, seq, "tool", fmt.Sprintf("%s invoked", toolName(t)))
	case attachv1.EventType_EVENT_TYPE_TOOL_COMPLETED:
		t := ev.GetToolCompleted()
		outcome := "ok"
		if t.GetIsError() {
			outcome = "ERROR"
		}
		msg := fmt.Sprintf("completed [%s]", outcome)
		if ex := oneLine(t.GetOutputExcerpt()); ex != "" {
			msg += " " + ex
		} else if dn := oneLine(t.GetDenialMessage()); dn != "" {
			msg += " " + dn
		}
		return true, writeLine(w, seq, "tool", msg)
	case attachv1.EventType_EVENT_TYPE_ASK_REQUESTED:
		a := ev.GetAskRequested()
		return true, writeLine(w, seq, "ask", fmt.Sprintf("%s requested (req=%s)", nameOr(a.GetToolName(), "tool"), a.GetRequestId()))
	case attachv1.EventType_EVENT_TYPE_ASK_RESOLVED:
		a := ev.GetAskResolved()
		return true, writeLine(w, seq, "ask", fmt.Sprintf("resolved %s (req=%s)", nameOr(a.GetBehavior(), "?"), a.GetRequestId()))
	case attachv1.EventType_EVENT_TYPE_PLAN_DELTA:
		p := ev.GetPlanDelta()
		kind := strings.TrimPrefix(p.GetKind().String(), "PLAN_DELTA_KIND_")
		return true, writeLine(w, seq, "plan", fmt.Sprintf("[%s] %s", strings.ToLower(kind), oneLine(p.GetPlan())))
	case attachv1.EventType_EVENT_TYPE_QUOTA_UPDATED:
		q := ev.GetQuotaUpdated()
		return true, writeLine(w, seq, "quota", strings.TrimSpace(fmt.Sprintf("%s %s", q.GetRateLimitType(), q.GetStatus())))
	default:
		// STATE/SEAT/accounting edge — the webclient's surface. Not rendered here.
		return false, nil
	}
}

// writeLine emits one read-only spectator line: `#<seq> <kind> <detail>`.
func writeLine(w io.Writer, seq uint64, kind, detail string) error {
	_, err := fmt.Fprintf(w, "#%d %s %s\n", seq, kind, detail)
	return err
}

// chatText joins the text of a chat message's blocks into a single-line summary.
// Non-text blocks (their kind != "text") contribute a `[<kind>]` marker so a
// tool_use/thinking block is visible without dumping its payload.
func chatText(m *attachv1.ChatMessage) string {
	var parts []string
	for _, b := range m.GetBlocks() {
		if t := strings.TrimSpace(b.GetText()); t != "" {
			parts = append(parts, oneLine(t))
			continue
		}
		if k := strings.TrimSpace(b.GetKind()); k != "" && k != "text" {
			parts = append(parts, "["+k+"]")
		}
	}
	return strings.Join(parts, " ")
}

// toolName picks the most human-meaningful label off a ToolInvoked: the display
// name, then the tool, then the skill; falling back to "tool" so a frame with
// none still renders an honest line.
func toolName(t *attachv1.ToolInvoked) string {
	for _, s := range []string{t.GetName(), t.GetTool(), t.GetSkill()} {
		if v := strings.TrimSpace(s); v != "" {
			return v
		}
	}
	return "tool"
}

func roleOr(role string) string { return nameOr(role, "?") }

func nameOr(v, fallback string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return fallback
}

// oneLine collapses a possibly-multiline excerpt into a single line so one frame
// is always one spectator line (a chat message or tool excerpt never breaks the
// #seq framing).
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.Join(strings.Fields(s), " ")
}

// --- length-delimited frame codec ------------------------------------------
//
// The frame stream (a WatchSession capture, the sibling's live pipe, or a test
// fixture) is a sequence of [uvarint length][marshaled attach.v1.SessionEvent]
// records. This is the same framing serpent-tui's raw emitter writes; keeping
// the codec here lets the offline renderers and their tests round-trip frames
// with no gRPC.

const maxSpectateFrame = 8 << 20 // 8 MiB guard against a bogus length prefix.

// readDelimitedFrame reads one length-delimited SessionEvent off br. It returns
// io.EOF exactly at a clean frame boundary (no partial frame); a length prefix
// with a truncated body is io.ErrUnexpectedEOF.
func readDelimitedFrame(br *bufio.Reader) (*attachv1.SessionEvent, error) {
	n, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, err // io.EOF at a boundary; anything else propagates.
	}
	if n > maxSpectateFrame {
		return nil, fmt.Errorf("frame length %d exceeds cap %d", n, maxSpectateFrame)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	ev := &attachv1.SessionEvent{}
	if err := proto.Unmarshal(buf, ev); err != nil {
		return nil, fmt.Errorf("decode frame: %w", err)
	}
	return ev, nil
}

// writeDelimitedFrame writes one length-delimited SessionEvent to w (the encode
// half of the codec; used by tests and any capture writer).
func writeDelimitedFrame(w io.Writer, ev *attachv1.SessionEvent) error {
	body, err := proto.Marshal(ev)
	if err != nil {
		return err
	}
	var hdr [binary.MaxVarintLen64]byte
	m := binary.PutUvarint(hdr[:], uint64(len(body)))
	if _, err := w.Write(hdr[:m]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// spectateLive is the LIVE leg: DS_ORCH_LIVE-gated (like `serpent drive`'s
// DS_E2E_LIVE gate), it dials WatchSession THROUGH the serpent-tui sibling — the
// only module that may import gRPC + orchestratorv1 (D80). The sibling emits the
// raw length-delimited attach.v1.SessionEvent frames on its stdout; this command
// pipes them into renderSpectateStream and renders read-only. Disarmed, it
// prints the offline alternatives and fails closed WITHOUT dialing anything, so
// no live orchestrator is ever contacted in an offline/CI run.
//
// The sibling verb (`serpent-tui spectate --emit-frames`) is the D80 grpc site;
// its live wiring + the bufconn-against-the-real-handler test belong in
// serpent-tui and are recorded as the deferred live-validation follow-up. This
// leg is the fail-closed render half.
func spectateLive(session, orchestrator string, fromSeq uint64, serpentTuiBin string) int {
	if os.Getenv(orchLiveGateEnv) != "1" {
		fmt.Fprintf(os.Stderr, "serpent spectate --session is the LIVE tier: it subscribes to a running orchestrator's WatchSession.\n")
		fmt.Fprintf(os.Stderr, "Arm it explicitly:  DS_ORCH_LIVE=1 serpent spectate --session %s\n", session)
		fmt.Fprintf(os.Stderr, "Offline, render a captured or piped frame stream instead:\n")
		fmt.Fprintf(os.Stderr, "  serpent spectate --replay <watchsession-dump>\n")
		fmt.Fprintf(os.Stderr, "  serpent-tui spectate --emit-frames --session %s | serpent spectate --stdin\n", session)
		return 1
	}
	binPath, err := resolveSerpentTuiBin(serpentTuiBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent spectate: %v\n", err)
		return 1
	}
	// Live wiring: EXEC the sibling's raw-frame emitter and render its stdout. The
	// child owns the gRPC dial (D80); we own the read-only render.
	childArgs := []string{"spectate", "--emit-frames", "--session", session}
	if orchestrator != "" {
		childArgs = append(childArgs, "--orchestrator", orchestrator)
	}
	if fromSeq != 0 {
		childArgs = append(childArgs, "--from-seq", fmt.Sprintf("%d", fromSeq))
	}
	return pipeSerpentTuiFrames(os.Stdout, binPath, childArgs...)
}

// orchLiveGateEnv arms the LIVE spectate leg. It mirrors the DS_E2E_LIVE gate
// `serpent drive` uses: unset, nothing dials a real orchestrator.
const orchLiveGateEnv = "DS_ORCH_LIVE"

// pipeSerpentTuiFrames runs the serpent-tui sibling with its stdout piped into
// the read-only frame renderer (renderSpectateStream), inheriting stdin (unused
// — a spectator sends no input) and stderr (the child's dial diagnostics). It is
// the live analogue of execSerpentTui, except the child's stdout is CONSUMED as
// the frame stream rather than passed through to the terminal. SIGINT/SIGTERM
// are drained while the child runs so a Ctrl-C tears the subscription down
// cleanly. The exit code is the child's on a non-zero child exit, else 0/1 on
// the render outcome.
func pipeSerpentTuiFrames(w io.Writer, binPath string, args ...string) int {
	cmd := exec.Command(binPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent spectate: %v\n", err)
		return 1
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for range sigCh {
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
		<-drainDone
	}()

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "serpent spectate: %v\n", err)
		return 1
	}
	_, renderErr := renderSpectateStream(w, stdout)
	if renderErr != nil {
		fmt.Fprintf(os.Stderr, "serpent spectate: %v\n", renderErr)
		// The renderer stopped reading (malformed frame): close the read end so a
		// child still streaming takes EPIPE and exits, instead of blocking forever
		// on a full pipe — cmd.Wait only returns after the child exits.
		stdout.Close()
	}
	waitErr := cmd.Wait()
	if waitErr != nil {
		// A child failure (bad dial, missing verb) is the authoritative exit code.
		return exitCodeOf(waitErr)
	}
	if renderErr != nil {
		return 1
	}
	return 0
}
