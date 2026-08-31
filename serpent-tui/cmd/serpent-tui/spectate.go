// SPDX-License-Identifier: Apache-2.0
//
// `serpent-tui spectate --emit-frames` is the D80 gRPC site behind the OSS
// client's `serpent spectate --session` LIVE leg. The client module is
// stdlib-only + proto/gen/go (it may not import google.golang.org/grpc), so it
// EXECs this sibling to dial the orchestrator's WatchSession server-streaming RPC
// and pipe the raw frame stream back:
//
//	serpent-tui spectate --emit-frames --session <uuid> [--orchestrator A] [--from-seq N]
//
// This verb subscribes as a READER (D61 one-writer/N-reader) via the same
// serpent-tui/internal/watch subscriber `attach` already uses — resume-from-seq +
// transparent reconnect (D61 slow-reader recovery, D79 per-event seqs) — and
// writes each frozen attach.v1.SessionEvent to stdout as a length-delimited frame
// ([uvarint length][marshaled SessionEvent]). That framing is BYTE-IDENTICAL to
// the codec `serpent spectate` reads (client/cmd/serpent/spectate.go), so the
// client decodes and renders the stream read-only with no gRPC of its own.
//
// READ-ONLY. WatchSession is the fan-out READ leg; this verb only Recv()s and
// prints. It opens no write RPC (the frozen orchestrator.v1 has none), so a
// spectator can never drive, approve, or perturb the session. Live use against a
// real orchestrator is operator-gated (the OSS leg arms it with DS_ORCH_LIVE=1);
// the subscribe + emit path here is exercised OFFLINE against an in-process fake
// SessionService (spectate_test.go), no live orchestrator or VM.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/watch"
)

// cmdSpectate is the `spectate` verb: the raw attach.v1.SessionEvent frame
// emitter the OSS `serpent spectate --session` LIVE leg execs. Only the
// --emit-frames mode exists (the client always passes it); the flag is explicit
// so the invocation is self-documenting and a bare `serpent-tui spectate` fails
// legibly rather than dialing.
func cmdSpectate(args []string) int {
	fs := flag.NewFlagSet("serpent-tui spectate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	emit := fs.Bool("emit-frames", false, "emit the raw length-delimited attach.v1.SessionEvent frame stream on stdout (the only mode; consumed by `serpent spectate --stdin`)")
	orchestrator := fs.String("orchestrator", os.Getenv(orchestratorEnv), "orchestrator SessionService endpoint (host:port; env "+orchestratorEnv+")")
	session := fs.String("session", "", "session UUID to spectate")
	fromSeq := fs.Uint64("from-seq", 0, "resume the subscription from this per-event seq (0 = the current frontier; D61 slow-reader recovery)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: serpent-tui spectate --emit-frames --session <uuid> [--orchestrator <addr>] [--from-seq N]")
		fmt.Fprintln(os.Stderr, "  Subscribe to a session's WatchSession fan-out as a READER and emit the raw")
		fmt.Fprintln(os.Stderr, "  length-delimited attach.v1.SessionEvent frame stream on stdout. Read-only: it")
		fmt.Fprintln(os.Stderr, "  never sends input. Pipe it into `serpent spectate --stdin` to render.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*emit {
		fmt.Fprintln(os.Stderr, "serpent-tui spectate: only --emit-frames mode is supported (the raw attach.v1 frame emitter behind `serpent spectate --session`)")
		fs.Usage()
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

	// sessionClient satisfies watch.Starter (WatchSession is the sole method the
	// subscriber needs); pass it straight through. Production backoff/reconnect.
	return emitFrames(ctx, c, *session, *fromSeq, stdout, os.Stderr, watch.Options{})
}

// emitFrames subscribes to sessionUUID's WatchSession fan-out (resuming from
// fromSeq) and writes every delivered attach.v1.SessionEvent to out as a
// length-delimited frame, flushing per frame so the piped `serpent spectate`
// reader sees each frame promptly. The resume token is the last EMITTED seq, so a
// transparent reconnect resubscribes strictly after the last frame handed off (no
// gap, no double-emit — D79). opts injects the clock/jitter for deterministic
// tests; production passes the zero value (real backoff). A clean end-of-stream
// or a SIGINT/SIGTERM ctx cancel is exit 0; a terminal transport error is exit 1.
// Terminal errors are reported on errOut (production passes os.Stderr); the
// from_seq-aged-out OutOfRange terminal is surfaced with its documented operator
// remedy rather than the raw gRPC status.
func emitFrames(ctx context.Context, c watch.Starter, sessionUUID string, fromSeq uint64, out, errOut io.Writer, opts watch.Options) int {
	bw := bufio.NewWriter(out)
	// lastSeq is read (as the resume token) and written only from watch.Run's own
	// goroutine — Run calls lastSeq() and onEvent synchronously in its read loop —
	// so no synchronization is needed.
	lastSeq := fromSeq
	onEvent := func(ev *attachv1.SessionEvent) error {
		if err := writeDelimitedFrame(bw, ev); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
		if s := ev.GetSeq(); s > lastSeq {
			lastSeq = s
		}
		return nil
	}
	runErr := watch.Run(ctx, c, sessionUUID, func() uint64 { return lastSeq }, onEvent, watch.BackoffPolicy{}, opts)
	if ferr := bw.Flush(); ferr != nil && runErr == nil {
		runErr = ferr
	}
	if runErr == nil {
		return 0
	}
	// A SIGINT/SIGTERM tears the subscription down via ctx cancel — a clean
	// operator exit, not a failure.
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) || status.Code(runErr) == codes.Canceled {
		return 0
	}
	// OutOfRange is watch.Run's terminal for a from_seq that aged out of the
	// session's bounded resume ring (D61 slow-reader recovery has a FINITE window;
	// the control plane returns OutOfRange, not a transport blip, so Run stops
	// without reconnecting). Surface the documented operator remedy — re-attach from
	// the current frontier — instead of the raw gRPC status, so a spectator whose
	// resume point fell too far behind knows exactly what to do. Still exit 1: this
	// run cannot resume itself from the requested seq. The seq reported is lastSeq —
	// the resume token the server actually refused (== the --from-seq flag on the
	// initial subscribe, but the last EMITTED seq when a mid-run reconnect aged
	// out); reading it here is safe because watch.Run has returned (same goroutine).
	if status.Code(runErr) == codes.OutOfRange {
		fmt.Fprintf(errOut, "serpent-tui spectate: resume from seq %d aged out of the session's replay window (the reader fell too far behind); re-run with --from-seq 0 to re-attach from the current frontier\n", lastSeq)
		return 1
	}
	fmt.Fprintf(errOut, "serpent-tui spectate: %v\n", runErr)
	return 1
}

// --- length-delimited frame codec -------------------------------------------
//
// [uvarint length][marshaled attach.v1.SessionEvent] per frame — byte-identical
// to the codec client/cmd/serpent/spectate.go reads (readDelimitedFrame). This
// is the one wire contract crossing the D80 module boundary: this binary writes
// it, the stdlib-only client decodes it. Keeping the encoder here (not shared,
// D80) is deliberate — the two sides re-derive the identical trivial framing.

// writeDelimitedFrame writes one length-delimited SessionEvent to w.
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
