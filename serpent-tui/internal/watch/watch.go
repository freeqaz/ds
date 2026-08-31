// Package watch is serpent-tui's WatchSession gRPC subscriber: it dials the
// orchestrator's SessionService.WatchSession server-streaming RPC (the N5
// handler, now on origin/main) as a SUBSCRIBER and delivers each frozen
// attach.v1.SessionEvent, with resume-from-LastSeq and transparent reconnect on
// a transport drop (D61 slow-reader recovery + D79 per-event seqs).
//
// READ LEG ONLY. WatchSession is the D18 fan-out leg — server-streaming, the
// subscriber sends exactly one WatchSessionRequest{session_uuid, from_seq} and
// thereafter only Recv()s. The WRITER seat input path is NOT WatchSession (the
// frozen orchestrator.v1 has no write RPC); it is the direct client->host-agent
// endpoint the AttachHandle carries, driven through client/hostbridge (the
// serpent-tui driver package). This package never sends session input.
//
// PATTERN REUSE. The dial/role/backoff/resume shape mirrors the existing
// reader-only live subscriber paid/webclient/attach/live.go (DialWatchSession +
// RunResilient): same retryable-vs-terminal gRPC status classification, same
// capped-exponential-with-full-jitter backoff, same resume-from-the-last-applied
// -seq on every reconnect. serpent-tui re-derives it here (it cannot import the
// paid tree, D80) but the semantics are identical, and unlike the webclient leg
// this subscriber feeds the client/tui Model that the WRITER seat also drives.
package watch

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// Starter is the minimal slice of the orchestrator.v1 SessionServiceClient this
// subscriber needs: just the WatchSession server-streaming RPC. Narrowing the
// dependency to one method keeps the read-only nature legible (no lifecycle or
// write verb is even reachable) and lets the in-process fake server satisfy it
// directly in tests (orchestratorv1.NewSessionServiceClient over a bufconn dial
// already satisfies it). It is exactly the WatchSessionStarter shape the
// webclient leg uses.
type Starter interface {
	WatchSession(ctx context.Context, in *orchestratorv1.WatchSessionRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[orchestratorv1.WatchSessionResponse], error)
}

// Subscribe opens a single WatchSession subscription for sessionUUID resuming
// from fromSeq (0 = the current frontier; the per-session resume ring backfills
// the in-window tail server-side). It issues the one subscribe request; from
// there the returned stream is Recv-only. It is the one-shot dial the resilient
// Run wraps.
func Subscribe(ctx context.Context, c Starter, sessionUUID string, fromSeq uint64) (grpc.ServerStreamingClient[orchestratorv1.WatchSessionResponse], error) {
	if sessionUUID == "" {
		return nil, errors.New("watch: WatchSession requires a session_uuid")
	}
	return c.WatchSession(ctx, &orchestratorv1.WatchSessionRequest{
		SessionUuid: sessionUUID,
		FromSeq:     fromSeq,
	})
}

// recv adapts a WatchSession server-stream Recv() into (event, nil) | (nil, nil)
// on clean EOF | (nil, err) otherwise — the same adaptation the webclient
// LiveStream.Recv makes. A frame with a nil Event is a contract violation
// (WatchSessionResponse always carries exactly one event, doc 15 §5.3) surfaced
// as an error rather than misread as a clean EOF.
func recv(stream grpc.ServerStreamingClient[orchestratorv1.WatchSessionResponse]) (*attachv1.SessionEvent, error) {
	resp, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil // clean end-of-stream
		}
		return nil, err
	}
	ev := resp.GetEvent()
	if ev == nil {
		return nil, errors.New("watch: WatchSession frame carried no event (doc 15 §5.3 invariant violated)")
	}
	return ev, nil
}

// BackoffPolicy tunes the reconnect schedule: capped exponential with full
// jitter so a fleet of subscribers re-attaching after a terminator bounce does
// not thunder-herd it. The zero value is the production posture (DefaultBackoff).
// It mirrors the webclient leg's policy field-for-field.
type BackoffPolicy struct {
	Base        time.Duration
	Max         time.Duration
	Factor      float64
	MaxAttempts int // 0 ⇒ retry indefinitely until ctx is cancelled or a terminal status
}

// DefaultBackoff is the schedule Run uses when a policy's zero-value fields are
// left unset: 200ms base, doubling, capped at 30s, retrying indefinitely.
var DefaultBackoff = BackoffPolicy{
	Base:        200 * time.Millisecond,
	Max:         30 * time.Second,
	Factor:      2.0,
	MaxAttempts: 0,
}

func (p BackoffPolicy) normalized() BackoffPolicy {
	if p.Base <= 0 {
		p.Base = DefaultBackoff.Base
	}
	if p.Max <= 0 {
		p.Max = DefaultBackoff.Max
	}
	if p.Factor < 1 {
		p.Factor = DefaultBackoff.Factor
	}
	return p
}

// delayFor computes the (jittered) sleep before reconnect attempt n (1-based).
// Capped exponential with full jitter in [0, capped]. rng may be nil (no jitter,
// for deterministic tests).
func (p BackoffPolicy) delayFor(n int, rng *rand.Rand) time.Duration {
	d := float64(p.Base)
	for i := 1; i < n; i++ {
		d *= p.Factor
		if d >= float64(p.Max) {
			d = float64(p.Max)
			break
		}
	}
	if d > float64(p.Max) {
		d = float64(p.Max)
	}
	capped := time.Duration(d)
	if rng == nil || capped <= 0 {
		return capped
	}
	return time.Duration(rng.Int63n(int64(capped) + 1))
}

// Options injects the clock/jitter/observability seams so tests drive the
// reconnect loop deterministically and fast (no real sleeps). Production leaves
// it zero: a real ctx-aware sleep + a seeded jitter source.
type Options struct {
	// Sleep waits d honoring ctx, returning ctx.Err() if ctx is cancelled first.
	// Nil ⇒ the default ctx-aware time-based sleep.
	Sleep func(ctx context.Context, d time.Duration) error
	// RNG provides backoff jitter. Nil ⇒ a real seeded source (production) UNLESS
	// Deterministic is set, in which case backoff is jitter-free.
	RNG *rand.Rand
	// Deterministic disables the default seeded jitter so a nil RNG yields exact
	// capped-exponential delays (tests asserting the schedule).
	Deterministic bool
	// OnReconnect, if set, is invoked before each reconnect attempt with the
	// 1-based attempt number, the delay slept, and the fromSeq the new
	// subscription resumes at. Tests assert resume-from-LastSeq; production logs.
	OnReconnect func(attempt int, delay time.Duration, fromSeq uint64)
}

// LastSeqFunc reports the highest event seq the consumer has DURABLY applied —
// the resume token. Run reads it on every (re)connect so the resubscribe asks
// the writer for events strictly after it: no gap, no overlap (D79). The
// client/tui Model.LastSeq satisfies this directly.
type LastSeqFunc func() uint64

// Run subscribes and delivers every attach.v1.SessionEvent to onEvent in seq
// order, transparently reconnecting on a TRANSPORT drop with backoff and
// RESUMING from lastSeq() so no event is missed or double-applied. onEvent is
// the fold sink (the loop folds into the client/tui Model and re-renders); a
// non-nil error it returns stops Run (a model contract violation — out-of-order
// seq — is not a transport blip and must not be retried).
//
// RECONNECT VS STOP (the webclient classification, mirrored):
//   - a RETRYABLE transport error (Unavailable / DeadlineExceeded / Aborted /
//     ResourceExhausted, or a clean mid-session stream end before ctx is done)
//     triggers a backoff + resume reconnect;
//   - a TERMINAL gRPC status (PermissionDenied, FailedPrecondition,
//     Unauthenticated, InvalidArgument, NotFound, OutOfRange, Unimplemented, …)
//     stops cleanly without reconnecting (a refused/aged-out subscription is a
//     signal, not a blip — OutOfRange is the from_seq-aged-out re-attach case the
//     caller lifts into a fresh-from-frontier subscribe);
//   - ctx cancellation stops cleanly, returning ctx.Err();
//   - an onEvent error (a fold/ordering violation) stops — never retried.
func Run(ctx context.Context, c Starter, sessionUUID string, lastSeq LastSeqFunc, onEvent func(ev *attachv1.SessionEvent) error, policy BackoffPolicy, opts Options) error {
	if c == nil {
		return errors.New("watch: Run needs a Starter")
	}
	if sessionUUID == "" {
		return errors.New("watch: Run requires a session_uuid")
	}
	if lastSeq == nil {
		lastSeq = func() uint64 { return 0 }
	}
	pol := policy.normalized()
	sleep := opts.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	rng := opts.RNG
	if rng == nil && !opts.Deterministic {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	attempt := 0 // consecutive failed (re)connect attempts; reset on progress
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		fromSeq := lastSeq()

		stream, err := Subscribe(ctx, c, sessionUUID, fromSeq)
		if err != nil {
			if d, retry := classify(ctx, err, &attempt, pol, rng); retry {
				if opts.OnReconnect != nil {
					opts.OnReconnect(attempt, d, fromSeq)
				}
				if serr := sleep(ctx, d); serr != nil {
					return serr
				}
				continue
			}
			return err
		}

		progressed := false
		runErr := drain(ctx, stream, func(ev *attachv1.SessionEvent) error {
			progressed = true
			attempt = 0 // forward progress resets backoff
			return onEvent(ev)
		})

		if runErr == nil {
			// Clean end-of-stream.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A clean end that delivered NO new events means the stream genuinely
			// drained (the writer has nothing after lastSeq): stop cleanly rather
			// than re-probing forever. A clean end that DID deliver events is a
			// mid-session handoff (e.g. a relay closing a served prefix) — re-attach
			// from lastSeq to pick up the rest.
			if !progressed {
				return nil
			}
			d := pol.delayFor(attempt+1, rng)
			attempt++
			if pol.MaxAttempts > 0 && attempt > pol.MaxAttempts {
				return errors.New("watch: WatchSession reconnect gave up after the clean mid-session end attempt cap")
			}
			if opts.OnReconnect != nil {
				opts.OnReconnect(attempt, d, lastSeq())
			}
			if serr := sleep(ctx, d); serr != nil {
				return serr
			}
			continue
		}

		d, retry := classify(ctx, runErr, &attempt, pol, rng)
		if !retry {
			return runErr
		}
		if opts.OnReconnect != nil {
			opts.OnReconnect(attempt, d, lastSeq())
		}
		if serr := sleep(ctx, d); serr != nil {
			return serr
		}
	}
}

// drain Recv()s the stream and feeds each event to onEvent until a clean EOF
// (nil event, nil error → returns nil), a Recv error, ctx cancellation, or an
// onEvent error. It is the inner read loop one subscription runs.
func drain(ctx context.Context, stream grpc.ServerStreamingClient[orchestratorv1.WatchSessionResponse], onEvent func(ev *attachv1.SessionEvent) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ev, err := recv(stream)
		if err != nil {
			return err
		}
		if ev == nil {
			return nil // clean end-of-stream
		}
		if err := onEvent(ev); err != nil {
			return err
		}
	}
}

// classify decides whether err warrants a backoff reconnect and, if so, the
// delay to sleep (advancing attempt). retry=false for ctx cancellation, terminal
// gRPC statuses, the MaxAttempts cap, and non-transport (fold/ordering) errors.
func classify(ctx context.Context, err error, attempt *int, pol BackoffPolicy, rng *rand.Rand) (time.Duration, bool) {
	if ctx.Err() != nil {
		return 0, false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 0, false
	}
	if !isRetryableStatus(err) {
		return 0, false
	}
	*attempt++
	if pol.MaxAttempts > 0 && *attempt > pol.MaxAttempts {
		return 0, false
	}
	return pol.delayFor(*attempt, rng), true
}

// isRetryableStatus classifies a stream/dial error as a transient transport drop
// the subscriber should reconnect through. Only a known-transient gRPC status is
// retryable; a fold/ordering violation (a plain error, no gRPC status) is NOT
// retried — re-attaching cannot fix a writer/ordering bug (D79).
func isRetryableStatus(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Aborted, codes.ResourceExhausted:
		return true
	default:
		// PermissionDenied, FailedPrecondition, Unauthenticated, InvalidArgument,
		// NotFound, OutOfRange (from_seq aged out), Unimplemented, Internal,
		// Canceled (server-sourced), Unknown, … — terminal.
		return false
	}
}

// sleepCtx waits d, returning early with ctx.Err() if ctx is cancelled first. It
// is the production sleep Run uses; tests inject a fake clock via Options.Sleep.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
