// Package e2e is the live drive-conformance harness for the CC wire side
// (DRIVE-PROTOCOL.md "The e2e harness, in tiers"). It drives a real Claude Code
// process — record or replay — through scripts/cc_sandbox.sh and projects the
// stdout back to attach.v1, closing the wrapper↔CC↔driver loop.
//
// Runtime-ignorance (D38). This package contains NO CC-isms: no "claude" record
// names, no toolu_/task_id vocabulary, no runtime flag strings. The one runtime
// fact it encodes is the SandboxArgv contract — the flag set of the launcher
// script it shells out to — which is a script-CLI contract, not a CC wire fact.
// The actual stdout→attach.v1 projection is delegated to a Projector the caller
// supplies (the claude-code adapter, wired in by the live tier only); the pump
// itself is a generic concurrent stdin-drive / stdout-project loop.
//
// The live launch is gated behind DS_E2E_LIVE=1 (the single documented gate;
// see scripts/cc_sandbox.sh and e2e/README.md). With it unset — the default and
// every CI/test run — DriveLive never shells out: tests exercise the pump
// against in-memory pipes via driveStreams, which is the deadlock-safe core.
//
// Stdlib-only (client/go.mod). Concurrency follows DRIVE-PROTOCOL.md's
// goroutine-per-stream model: a writer goroutine drives stdin and closes it
// after the final input; a reader goroutine projects stdout concurrently, so a
// CC that emits output only after consuming a large input (filling the OS pipe
// buffer) cannot deadlock the harness.
package e2e

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// SandboxArgv is the structural mirror of scripts/cc_sandbox.sh's drive CLI —
// the SandboxArgv contract DRIVE-PROTOCOL.md names. It is the single source of
// truth for the flag set the harness passes to the launcher; the argv-contract
// test (harness_test.go) asserts these fields round-trip to exactly the flags
// the script documents, so the two cannot drift apart silently.
//
// Mode is "record" or "replay". In record the launcher wires CC to the capture
// tool's egress-gateway proxy (the first-party ds-capture, default :18099,
// cred-bearing, budget-capped); in replay it keeps zero external egress. Exactly
// one of BudgetUSD / NoEgress is meaningful per mode: BudgetUSD caps cost in
// record; NoEgress forces the zero-egress network.
//
// Capture-binary flag — the --cia → --captool migration (CAPTURE-TOOL-DESIGN.md
// §4, taskdb 01KTXKJYYW). The first-party `ds-capture` replaces the external
// `../cia` (Python/mitmproxy) recorder; the SandboxArgv contract names it via
// the new --captool leg, defaulting its egress-gateway proxy to the free :18099
// (NEVER the protected :18080 monitor). The two-flag overlap is intentional and
// bounded: during the migration the contract accepts BOTH --captool (the
// first-party tool, CapToolBin) and the DEPRECATED --cia (CIABin); --captool
// wins if both are set. Once every consumer is off --cia, CIABin, the --cia
// leg, and the :18080 default are deleted in the terminal retire step.
type SandboxArgv struct {
	// CapToolBin is the first-party capture/instrumentation binary (--captool):
	// `ds-capture`, whose egress-gateway proxy defaults to the free :18099. This
	// is the carry-side replacement for the deprecated CIABin (--cia). When both
	// are set, CapToolBin wins (the deprecation overlap).
	CapToolBin string
	// CIABin is the DEPRECATED external CIA recorder/replayer binary (--cia).
	// Retained only for the bounded two-flag migration overlap
	// (CAPTURE-TOOL-DESIGN.md §4); prefer CapToolBin. Its legacy proxy was
	// :18080 (the protected monitor's port) — the first-party tool defaults to
	// the free :18099 instead. Deleted in the terminal retire step once no
	// consumer drives --cia.
	CIABin string
	// Mode is "record" or "replay" (--mode).
	Mode string
	// Cassette is the API-response cassette path (--cassette): written in
	// record, read in replay.
	Cassette string
	// BudgetUSD is the per-run cost cap (--budget-usd), record mode only. Empty
	// ⇒ the script default (0.60).
	BudgetUSD string
	// NoEgress forces --no-egress (the zero-egress network) even in record.
	// Replay is always zero-egress regardless.
	NoEgress bool
}

// captureBin returns the capture binary the argv drives and the flag it renders
// under, honouring the --captool → --cia deprecation overlap: the first-party
// CapToolBin (--captool) wins, falling back to the deprecated CIABin (--cia).
// Returns an empty bin when neither is set (Validate rejects that).
func (a SandboxArgv) captureBin() (flag, bin string) {
	if a.CapToolBin != "" {
		return FlagCapTool, a.CapToolBin
	}
	return FlagCIA, a.CIABin
}

// Mode values, mirrored from the script.
const (
	ModeRecord = "record"
	ModeReplay = "replay"
)

// Args renders the SandboxArgv as the exact flag slice scripts/cc_sandbox.sh
// accepts — the argv-contract the structural test pins. The action (e.g.
// --gate-then-plan) is the caller's prefix; this returns only the drive flags so
// the same rendering serves both the live launch and the dry-run plan.
func (a SandboxArgv) Args() []string {
	capFlag, capBin := a.captureBin()
	args := []string{
		capFlag, capBin,
		FlagMode, a.Mode,
		FlagCassette, a.Cassette,
	}
	// --budget-usd and --no-egress are mutually-exclusive-ish per the script
	// usage ("[--budget-usd X | --no-egress]"); render whichever is set.
	if a.NoEgress {
		args = append(args, FlagNoEgress)
	} else if a.BudgetUSD != "" {
		args = append(args, FlagBudgetUSD, a.BudgetUSD)
	}
	return args
}

// The drive-CLI flag names. These are the load-bearing strings the argv-contract
// test ties to the script's documented usage; keeping them as named constants
// makes the contract a single edit point.
const (
	// FlagCapTool names the first-party capture binary (ds-capture); it is the
	// carry-side successor to FlagCIA (CAPTURE-TOOL-DESIGN.md §4).
	FlagCapTool = "--captool"
	// FlagCIA is the DEPRECATED external-CIA leg, kept only for the bounded
	// two-flag migration overlap; --captool wins when both are present.
	FlagCIA       = "--cia"
	FlagMode      = "--mode"
	FlagCassette  = "--cassette"
	FlagBudgetUSD = "--budget-usd"
	FlagNoEgress  = "--no-egress"

	// Actions the launcher accepts (gate-then-launch semantics). The harness
	// uses GateThenPlan for the always-safe dry run.
	ActionGate         = "--gate"
	ActionPlan         = "--plan"
	ActionGateThenPlan = "--gate-then-plan"
	ActionSelfCheck    = "--self-check"

	// SandboxScript is the launcher path, relative to the repo root.
	SandboxScript = "scripts/cc_sandbox.sh"
	// LiveGateEnv is the single live gate (DS_E2E_LIVE=1). Unset ⇒ no launch.
	LiveGateEnv = "DS_E2E_LIVE"
)

// Validate reports whether the argv is well-formed against the script contract,
// matching the script's own G0 checks so the harness can reject a bad argv
// before ever shelling out.
func (a SandboxArgv) Validate() error {
	if a.CapToolBin == "" && a.CIABin == "" {
		return errors.New("e2e: a capture binary is required: set CapToolBin (--captool, the first-party ds-capture) or the deprecated CIABin (--cia)")
	}
	switch a.Mode {
	case ModeRecord, ModeReplay:
	case "":
		return errors.New("e2e: SandboxArgv.Mode (--mode) is required")
	default:
		return errors.New("e2e: SandboxArgv.Mode must be record or replay, got " + a.Mode)
	}
	if a.Cassette == "" {
		return errors.New("e2e: SandboxArgv.Cassette (--cassette) is required")
	}
	if a.Mode == ModeRecord && a.NoEgress && a.BudgetUSD != "" {
		// not an error in the script (no-egress just overrides the network),
		// but BudgetUSD is meaningless without egress — flag it so the caller
		// does not think a cap is in force.
		return errors.New("e2e: --no-egress record run ignores --budget-usd (no API is reached)")
	}
	return nil
}

// Projector consumes one line of runtime stdout and advances its internal
// projection. It is the seam that keeps this package runtime-ignorant: the live
// tier supplies a Projector backed by the claude-code adapter, but the pump and
// its tests depend only on this interface. Project is called once per stdout
// line, in arrival order (the topological order DRIVE-PROTOCOL/PHASE3 P10 rely
// on); it returns an error only on an unrecoverable projection fault.
type Projector interface {
	Project(line []byte) error
}

// ProjectorFunc adapts a function to Projector.
type ProjectorFunc func(line []byte) error

// Project implements Projector.
func (f ProjectorFunc) Project(line []byte) error { return f(line) }

// driveStreams is the deadlock-safe core of the live drive loop, factored to run
// against arbitrary in-memory streams so it is testable without a real CC
// process. It implements DRIVE-PROTOCOL.md's goroutine-per-stream model:
//
//   - a WRITER goroutine drives each input to stdin and closes stdin after the
//     final input (signalling end-of-conversation to CC);
//   - the CALLER goroutine reads stdout concurrently and projects every line.
//
// Because the two run concurrently, a CC that emits output only after consuming
// input larger than the OS pipe buffer cannot deadlock: the reader drains stdout
// while the writer is still feeding stdin. (The old sequential write-all-then-
// project shape deadlocks exactly there — the regression test proves it.)
//
// stdin is the writer's sink (the process's standard input); stdout is the
// reader's source (its standard output). inputs are driven verbatim, in order;
// each is followed by a newline (the stream-json record delimiter). Error
// aggregation preserves firstErr semantics: the first non-nil error from either
// goroutine (or a ctx cancellation) is returned; later errors are subordinate.
// ctx cancellation aborts the drive promptly.
func driveStreams(ctx context.Context, stdin io.WriteCloser, stdout io.Reader, inputs [][]byte, p Projector) error {
	// Both pumps run as goroutines so the join can honour ctx even while a pump
	// is blocked on a pipe read/write. Buffered channels so neither goroutine
	// leaks-by-blocking on send after we have already returned on ctx.
	writeErrc := make(chan error, 1)
	readErrc := make(chan error, 1)

	go func() { writeErrc <- driveStdin(ctx, stdin, inputs) }()
	go func() { readErrc <- projectStdout(ctx, stdout, p) }()

	// unblockOnCancel closes the streams when ctx fires, to break a pump blocked
	// on a pipe read/write (the per-Scan-iteration select cannot interrupt a
	// blocked read). The real exec stdout pipe and io.PipeReader are both
	// Closers; a plain io.Reader test stub without Close just waits for natural
	// EOF. We close stdin too so a blocked writer unblocks. Idempotent via once.
	var closeOnce sync.Once
	unblock := func() {
		closeOnce.Do(func() {
			if c, ok := stdout.(io.Closer); ok {
				_ = c.Close()
			}
			_ = stdin.Close()
		})
	}

	var readErr, writeErr error
	gotRead, gotWrite := false, false

	// Wait for both pumps, but return early on ctx cancellation so a stuck pump
	// cannot hang the caller past the deadline.
	for !gotRead || !gotWrite {
		select {
		case err := <-readErrc:
			readErr, gotRead = err, true
		case err := <-writeErrc:
			writeErr, gotWrite = err, true
		case <-ctx.Done():
			// Force the blocked pumps to unblock by closing the streams, then
			// report the ctx error (it dominates firstErr). We do not wait for the
			// pumps to drain — they will return promptly once the streams close,
			// and their channels are buffered so they never leak-by-blocking.
			unblock()
			return ctx.Err()
		}
	}

	// firstErr semantics: a ctx error dominates, then the reader error (the
	// projection is the conformance signal), then the writer error.
	if err := ctx.Err(); err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	return writeErr
}

// driveStdin writes each input followed by a newline, honouring ctx, and closes
// stdin after the final input (or on the first write error / cancellation). The
// close is what tells CC the conversation's input is complete.
func driveStdin(ctx context.Context, stdin io.WriteCloser, inputs [][]byte) (err error) {
	// Ensure stdin is always closed exactly once, capturing a close error only
	// if no earlier error already won (firstErr).
	defer func() {
		cerr := stdin.Close()
		if err == nil {
			err = cerr
		}
	}()

	w := bufio.NewWriter(stdin)
	for _, in := range inputs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if _, werr := w.Write(in); werr != nil {
			return werr
		}
		if werr := w.WriteByte('\n'); werr != nil {
			return werr
		}
		// Flush per input so a reader waiting on the first record is unblocked
		// immediately (latency, and the backpressure interleave the test needs).
		if ferr := w.Flush(); ferr != nil {
			return ferr
		}
	}
	return w.Flush()
}

// projectStdout reads stdout line by line and projects each, honouring ctx. It
// returns the projector's first error, or io scan error, or ctx error; a clean
// EOF (CC closed stdout) is success.
func projectStdout(ctx context.Context, stdout io.Reader, p Projector) error {
	sc := bufio.NewScanner(stdout)
	// CC stream-json lines can be large (full message objects); raise the cap
	// well above the 64KiB default so a fat record never silently truncates.
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// Copy the line: Scanner reuses its buffer, and a Projector may retain
		// the slice past the next Scan.
		line := append([]byte(nil), sc.Bytes()...)
		if err := p.Project(line); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return ctx.Err()
}

// maxLineBytes caps a single stdout line. Generous: a full assistant message
// object with a large tool input can run to a few hundred KiB.
const maxLineBytes = 4 * 1024 * 1024

// --- Progressive-receipt assertion (the live-progressive-smoke motivation) ---
//
// The streaming tee is proven offline by channel synchronization (the bounded-pipe
// backpressure test above). The live progressive path it models — a LONG real-CC
// turn streamed through the egress gateway on :18099 WITHOUT a client idle-timeout,
// where the harness receives the first teed bytes well BEFORE the stream ends — is
// the rewrite's actual motivation (DRIVE-PROTOCOL.md "Determinism via record-replay";
// CAPTURE-TOOL-DESIGN.md §4). It stays the deferred manual validation behind the
// DS_E2E_LIVE fence; the assertion below is the structural teeth that an operator's
// armed run (and an offline ticking-stream unit test) both run.
//
// The contract this asserts is INCREMENTAL DELIVERY, not throughput or latency:
// per DRIVE-PROTOCOL.md the harness must never assert on TTFT / tok-s (they are not
// reproducible under replay). It asserts only happens-before — the first chunk is
// received strictly before the stream completes, by a margin — which proves the tee
// streams chunk-by-chunk rather than buffering until EOF (the failure mode an idle
// client timeout would mask). No wall-clock absolute is pinned; only relative order
// and a relative margin within the single run.

// ProgressiveReceipt records the arrival order and (monotonic) arrival instants of
// the chunks teed/projected during a single drive, so an incremental-delivery
// assertion can be made WITHOUT pinning any absolute latency. It is a Projector, so
// it composes in front of the real projection in the live pump: wrap the
// runtime-adapter Projector with Tee and the receipt is captured for free as the
// stdout is projected. It is safe for the concurrent pump (the reader goroutine is
// the only caller of Project, but the accessors lock so an asserting goroutine can
// read mid-flight).
type ProgressiveReceipt struct {
	now  func() time.Time // injectable clock; defaults to time.Now (monotonic).
	mu   sync.Mutex
	at   []time.Time // at[i] is when chunk i was received.
	next Projector   // optional downstream projector (nil ⇒ receipt-only).
}

// NewProgressiveReceipt returns a receipt recorder using the real monotonic clock.
func NewProgressiveReceipt() *ProgressiveReceipt {
	return &ProgressiveReceipt{now: time.Now}
}

// ReceiptFromOffsets builds a ProgressiveReceipt whose arrival timeline is a fixed
// base instant plus each offset, in order — a DETERMINISTIC reconstruction with no
// real clock and no sleeps. It serves two callers: the offline ticking-stream unit
// test (synthetic offsets) and the live receipt-sidecar loader (the per-chunk
// monotonic offsets an armed `ds-capture record` run wrote, raw-class under
// DS_LIVE_SCRATCH). Both then run the SAME AssertProgressiveReceipt, so the live
// assertion is exactly the one CI exercises. Only the relative offsets matter; the
// base is arbitrary (no absolute wall-clock is pinned — DRIVE-PROTOCOL.md).
func ReceiptFromOffsets(offsets []time.Duration) *ProgressiveReceipt {
	// A fixed, arbitrary base; relative spans are all the assertion reads.
	base := time.Unix(0, 0)
	at := make([]time.Time, len(offsets))
	for i, off := range offsets {
		at[i] = base.Add(off)
	}
	return &ProgressiveReceipt{now: time.Now, at: at}
}

// Tee returns a ProgressiveReceipt that records receipt AND forwards each chunk to
// next (the runtime-adapter Projector). Use it to instrument the live pump: the
// receipt timeline is captured as a side effect of the normal projection, so the
// progressive assertion needs no second stream. A nil next records receipt only.
func Tee(next Projector) *ProgressiveReceipt {
	return &ProgressiveReceipt{now: time.Now, next: next}
}

// Project records the arrival instant of one chunk, then forwards to the downstream
// projector if any. It satisfies Projector so it drops into the existing pump.
func (r *ProgressiveReceipt) Project(line []byte) error {
	r.mu.Lock()
	r.at = append(r.at, r.now())
	r.mu.Unlock()
	if r.next != nil {
		return r.next.Project(line)
	}
	return nil
}

// Count is the number of chunks received so far.
func (r *ProgressiveReceipt) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.at)
}

// instants returns a copy of the recorded arrival timeline.
func (r *ProgressiveReceipt) instants() []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.at...)
}

// ProgressiveResult is the structured outcome of the incremental-delivery check.
// FirstAt/LastAt are the first and last chunk arrival instants; FirstToLast is the
// span between them (the incremental window). Incremental is the verdict.
type ProgressiveResult struct {
	Chunks      int           // total chunks received.
	FirstToLast time.Duration // span from first chunk receipt to last.
	Incremental bool          // first-byte-well-before-end verdict.
	Reason      string        // empty when Incremental; else why it failed.
}

// AssertProgressiveReceipt checks that the teed stream was delivered INCREMENTALLY:
// at least minChunks chunks arrived, and the first arrived at least minSpan before
// the last (the "first teed bytes well before stream end" property). It asserts
// ONLY relative order and a relative margin within this single run — never an
// absolute latency, throughput, or TTFT (DRIVE-PROTOCOL.md forbids those under
// replay). A buffer-until-EOF tee (the failure an idle-client-timeout masks) lands
// every chunk in the same instant, so FirstToLast collapses below minSpan and the
// verdict is false.
//
// minSpan may be zero to assert only strict ordering (first strictly before last),
// which is the right bound for a synthetic ticking stream whose ticks are tiny but
// monotonically increasing.
func (r *ProgressiveReceipt) AssertProgressiveReceipt(minChunks int, minSpan time.Duration) ProgressiveResult {
	ts := r.instants()
	res := ProgressiveResult{Chunks: len(ts)}
	if len(ts) < minChunks {
		res.Reason = fmt.Sprintf("received %d chunks, want at least %d (the stream never delivered enough to prove incremental receipt)", len(ts), minChunks)
		return res
	}
	if len(ts) < 2 {
		// minChunks<2 and a single chunk: there is no "before end" to observe, so
		// incremental delivery is undefined — treat as not-incremental, explicitly.
		res.Reason = "only one chunk received: cannot observe first-byte-before-end (need at least 2 chunks for an incremental window)"
		return res
	}
	first, last := ts[0], ts[len(ts)-1]
	res.FirstToLast = last.Sub(first)
	if res.FirstToLast < minSpan {
		res.Reason = fmt.Sprintf("first chunk received %s before the last, want at least %s: the tee delivered in a burst at EOF rather than incrementally (an idle-client-timeout would mask this)", res.FirstToLast, minSpan)
		return res
	}
	if minSpan == 0 && !last.After(first) {
		res.Reason = "first and last chunk share an instant: no incremental window observed"
		return res
	}
	res.Incremental = true
	return res
}

// ErrLiveGateUnset is returned by DriveLive when DS_E2E_LIVE is not "1". It is
// the harness's half of the single-gate story: the live launch is opt-in, and a
// caller that forgets the gate gets a clear, non-panicking signal — never a
// silent no-op and never an accidental launch. Tests assert on this without
// ever shelling out.
var ErrLiveGateUnset = errors.New("e2e: DS_E2E_LIVE != 1; live drive tier is gated (set DS_E2E_LIVE=1 to arm; this is the deferred manual live step)")

// liveGateArmed reports whether the single live gate is set. The harness and the
// launcher script agree on exactly one gate name (LiveGateEnv); CC_SANDBOX_LIVE
// is retired and arms nothing here.
func liveGateArmed() bool { return os.Getenv(LiveGateEnv) == "1" }

// DriveLive is the live tier entry point (DRIVE-PROTOCOL.md tier 1). It launches
// scripts/cc_sandbox.sh with the SandboxArgv flags, wires the process's stdin
// and stdout to the deadlock-safe concurrent pump (driveStreams), and projects
// stdout through p. It is gated: with DS_E2E_LIVE unset it does NOT launch and
// returns ErrLiveGateUnset, so no test path ever spawns a real process. The live
// launch is the deferred manual step.
//
// repoRoot is the directory scripts/cc_sandbox.sh is resolved against; argv is
// the SandboxArgv contract; inputs are the stream-json records to drive; p
// projects the runtime stdout (the live tier passes a claude-code-adapter-backed
// Projector — the one place a runtime adapter is named).
func DriveLive(ctx context.Context, repoRoot string, argv SandboxArgv, inputs [][]byte, p Projector) error {
	if !liveGateArmed() {
		return ErrLiveGateUnset
	}
	if err := argv.Validate(); err != nil {
		return err
	}

	// The launcher itself gates again (G1–G7 + the in-container assert) and only
	// execs podman when DS_E2E_LIVE=1; this is belt-and-suspenders. We launch
	// the bare drive invocation (no action flag) so the script runs
	// gate-then-launch.
	scriptArgs := append([]string{SandboxScript}, argv.Args()...)
	cmd := exec.CommandContext(ctx, "sh", scriptArgs...)
	cmd.Dir = repoRoot
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	driveErr := driveStreams(ctx, stdin, stdout, inputs, p)

	// Always reap the process so it cannot leak; the drive error wins over a
	// non-zero wait status (firstErr).
	waitErr := cmd.Wait()
	if driveErr != nil {
		return driveErr
	}
	return waitErr
}
