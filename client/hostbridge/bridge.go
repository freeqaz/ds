// Package hostbridge is the host-agent-side transport bridge (M0, direct
// client→host-agent, no relay): it runs beside a wrapped Claude Code process,
// projects CC's stdout through the EXISTING wrapper adapter into attach.v1
// deltas served over a WatchSession-style event stream, and accepts writer-seat
// input + ask-response grants back through the EXISTING driver onto CC's stdin.
// It exercises the D79 transport-ambivalent AttachHandle for real across the
// container boundary (DRIVE-PROTOCOL.md tier 2; docs/15 §5.3-5.4; D38/D61/D79).
//
// IMPORT, DON'T DUPLICATE. The read half (CC stdout → attach.Event) and the
// write half (DriveInput/DriveGrant → CC stdin) already ship and are reused
// verbatim, never re-derived:
//
//   - the read projection is the wrapper adapter claudecode.Adapter
//     (claudecode.New / WithClock / Feed / ProcessStream / Warnings);
//   - the attach event model is client/wrapper/attach (attach.Event &c.);
//   - the write encoding is the wrapper driver claudecode.Driver
//     (NewDriver / EncodeInput / EncodeGrant / EncodeGrantPromptTool) and its
//     DriveInput / DriveGrant shapes.
//
// This package adds only what is genuinely new: the server-side WRITER/READER
// seat arbitration at the WatchSession terminator (the server half of the seam
// whose client half already lives in the TUI, 01KTWJ23Q0; docs/15 §5.3 / freeze
// row 2), the locally-declared D79 AttachHandle/auth/expiry validation
// (handle.go), the stdio pump that joins CC ⇄ adapter/driver ⇄ subscribers, two
// transport realizations of the AttachHandle seam (the in-process loopback,
// loopback.go, and the framed UDS/socket carrier that crosses a real process
// boundary, socket.go — both reusing the same Server.Attach arbitration), and the
// resume-from-seq recovery layer (this file's bounded history ring + ReplayFrom;
// loopback.go's Conn.Resume / Dropped / Gap) that lets a slow READER recover the
// events it dropped past its bounded delivery buffer rather than being silently
// gapped.
//
// Runtime ignorance (D38): the bridge core names no CC-isms. Every CC fact is
// reached through the adapter/driver seam — the bridge speaks attach.Event out
// and DriveInput/DriveGrant in, and the claudecode package is the only thing it
// imports that knows the runtime. Stdlib-only (client/go.mod).
//
// Concurrency follows DRIVE-PROTOCOL.md's goroutine-per-stream model (the same
// model client/goldentrace/e2e proved deadlock-safe): a reader goroutine drains
// CC stdout and fans the projected deltas to subscribers; writer input is
// serialized onto CC stdin under a mutex so two encoded records never interleave
// on the wire.
package hostbridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// maxLineBytes bounds one CC stdout NDJSON line, matching the adapter and the
// e2e harness (a full assistant message with a large tool input can run to a few
// hundred KiB).
const maxLineBytes = 10 << 20

// GrantRoute selects which proven driver encoding a DriveGrant takes onto CC
// stdin. v0's default is the PROVEN-live --permission-prompt-tool route
// (EncodeGrantPromptTool); the native control_response route (EncodeGrant) is
// structured-but-not-yet-live-verified (driver.go) and selectable for the
// keystone live-capture spike. The bridge does not decide protocol fidelity — it
// only forwards the caller's chosen route to the existing driver.
type GrantRoute int

const (
	// GrantRoutePromptTool encodes via Driver.EncodeGrantPromptTool — the PROVEN
	// route (P8 AVENUE-a), v0 default. Joins on DriveGrant.ToolUseID.
	GrantRoutePromptTool GrantRoute = iota
	// GrantRouteNativeControl encodes via Driver.EncodeGrant — the native
	// control_response route, documented-not-yet-live-verified (driver.go). Joins
	// on DriveGrant.RequestID.
	GrantRouteNativeControl
)

// DriveInput and DriveGrant are the wrapper driver's write-side shapes, reused
// verbatim (NOT redeclared): the thin client emits a DriveInput, the policy
// stream emits a DriveGrant, and the bridge hands both to the existing driver.
// Aliased here only so callers of this package need not import the claudecode
// package directly to name the inbound write events — the types ARE the
// driver's, by alias, so there is exactly one definition (driver.go).
type (
	DriveInput = claudecode.DriveInput
	DriveGrant = claudecode.DriveGrant
)

// SPDX-License-Identifier: Apache-2.0
//
// AttachDigestMatcher and DigestMatch are the wrapper's attach-seam keyed-secret-
// digest matcher and its fingerprint-only match EVENT, reused verbatim (NOT
// redeclared) so this package wires the EXISTING consumer (driver.go) onto the
// live stdin-drive path rather than re-deriving it. The match event carries
// fingerprint metadata ONLY — by construction it has no field that can hold the
// inspected plaintext (D73; doc 12 §10). Aliased here so DigestMatchSink callers
// need not import the claudecode package directly to name the value they receive.
type (
	AttachDigestMatcher = claudecode.AttachDigestMatcher
	DigestMatch         = claudecode.DigestMatch
)

// DigestMatchSink receives the fingerprint-only match events the configured
// AttachDigestMatcher produces for a DriveInput about to enter CC stdin — the
// attach-seam analogue of the proxy plane's verdict-routing sink (doc 12 §10).
//
// FINGERPRINT-ONLY (D73): a sink is handed ONLY []DigestMatch values, each of
// which is incapable of carrying the inspected plaintext, a slice of the prompt,
// or the matched credential by construction (driver.go DigestMatch has no such
// field). A sink therefore cannot leak the secret no matter how it logs/spools
// what it receives — the NEVER-LOG-THE-SECRET invariant holds at the seam, not by
// the sink's discipline.
//
// FAIL-CLOSED-WHEN-KEYED: a non-nil error return makes DriveInput refuse the
// write and return ErrDigestSinkFailed (wrapping the cause) — the input is NEVER
// driven onto CC stdin past a sink that could not record the match. A sink is
// invoked only when MatchInput returned at least one match; an empty match set
// drives unchanged with no sink call.
type DigestMatchSink interface {
	// OnDigestMatches is called BEFORE the input is encoded onto CC stdin, with the
	// non-empty fingerprint-only match set the matcher produced. Returning an error
	// fails the DriveInput closed (ErrDigestSinkFailed).
	OnDigestMatches(matches []DigestMatch) error
}

// DigestMatchSinkFunc adapts a plain func to a DigestMatchSink.
type DigestMatchSinkFunc func(matches []DigestMatch) error

// OnDigestMatches implements DigestMatchSink.
func (f DigestMatchSinkFunc) OnDigestMatches(matches []DigestMatch) error { return f(matches) }

// Subscriber receives attach.v1 deltas projected from the CC session. It is the
// WatchSession fan-out leg (docs/15 §5.4): every attached client (the one WRITER
// and the N READERs) is a Subscriber. OnEvent is called once per projected
// attach.Event in emission order; it must not block the pump for long (the
// loopback transport drains to a buffered channel). OnClose is called once when
// the session stream ends (CC stdout EOF or bridge shutdown), carrying the
// terminal error if any.
type Subscriber interface {
	OnEvent(ev attach.Event)
	OnClose(err error)
}

// SubscriberFunc adapts a plain function to a Subscriber whose OnClose is a
// no-op — convenient for callers that only consume events.
type SubscriberFunc func(ev attach.Event)

// OnEvent implements Subscriber.
func (f SubscriberFunc) OnEvent(ev attach.Event) { f(ev) }

// OnClose implements Subscriber (no-op).
func (f SubscriberFunc) OnClose(error) {}

// Bridge joins one wrapped CC process to its attached clients: it pumps CC
// stdout through the adapter to its subscribers and serializes driver-encoded
// input/grants onto CC stdin. One Bridge serves one session; the Server (below)
// owns seat arbitration and handle validation and delegates the actual byte
// movement and write-encoding here.
//
// A Bridge holds NO approval state (D18/D45/D53), inheriting that invariant from
// the adapter and the stateless driver: it projects asks outward and encodes
// grants inward, never storing either.
type Bridge struct {
	adapter *claudecode.Adapter
	driver  *claudecode.Driver

	// matcher and matchSink wire the EXISTING attach-seam keyed-secret-digest
	// matcher onto the live DriveInput path (BridgeConfig.AttachMatcher /
	// DigestMatchSink). Both nil ⇒ matcher off ⇒ DriveInput unchanged from today.
	// When matcher!=nil, DriveInput offers each input to MatchInput before
	// writeRecord and routes any matches to matchSink (fingerprint-only; fail-
	// closed-when-keyed on a sink error). They never carry plaintext (D73).
	matcher   *AttachDigestMatcher
	matchSink DigestMatchSink

	// ccStdin is the wrapped CC process's standard input (driver records land
	// here). Writes are serialized by stdinMu so two encoded records never
	// interleave on the wire.
	ccStdin   io.Writer
	stdinMu   sync.Mutex
	stdinDone bool // set after the final input; further writes fail closed.

	// subscribers is the WatchSession fan-out set. subsMu guards it and the
	// closed flag.
	subsMu      sync.Mutex
	subscribers []Subscriber
	closed      bool
	closeErr    error

	// --- resume-from-seq recovery state (loopback.go Conn.Resume) ------------
	// historyMu guards the seq-indexed history ring and lastSeq, which a slow
	// READER's Resume / ReplayFrom reads to recover events it dropped past its
	// bounded delivery buffer. It is a SEPARATE mutex from subsMu so a Resume
	// (which snapshots the ring) never contends with the pump's fanout lock.
	historyMu   sync.Mutex
	historySize int            // retained ring depth (>=1; defaulted in NewBridge)
	ring        []attach.Event // oldest-first, bounded to historySize; sorted by Seq (Pump fans in Seq order)
	lastSeq     uint64         // highest Seq ever fanned (0 before the first event)
}

// DefaultHistorySize is the BridgeConfig.HistorySize default: the number of
// most-recent attach.Events the fan-out's seq-indexed history ring retains for
// resume (loopback.go Conn.Resume / ReplayFrom). It is deliberately a few
// multiples of the per-Conn delivery buffer (eventBuffer) so a reader that
// overruns its delivery buffer by a bounded margin can still resume from the
// ring; a reader further behind than this aged-out window must re-attach
// (ErrResumeWindowExceeded).
const DefaultHistorySize = 1024

// BridgeConfig configures NewBridge. Adapter and Driver default to fresh
// instances; tests inject a clock-pinned adapter for deterministic deltas (the
// same WithClock determinism client/goldentrace/replay relies on).
type BridgeConfig struct {
	// Adapter projects CC stdout → attach.Event. Nil ⇒ claudecode.New(). Pass a
	// WithClock-configured adapter for deterministic replay.
	Adapter *claudecode.Adapter
	// Driver encodes DriveInput/DriveGrant → CC stdin records. Nil ⇒
	// claudecode.NewDriver() (stateless; a shared instance is safe).
	Driver *claudecode.Driver
	// LiveText opts the DEFAULT adapter into projecting the runtime's typing deltas
	// as render-only attach.ChatDeltas (claudecode.WithPartials; doc
	// serpent-cli-mvp/06 Layer 1, D145) — the client half of the U-PARTIALS-ARM
	// live-text path, paired with the host arming --include-partial-messages on the
	// structured launch argv. It is honored ONLY on the Adapter==nil default path: an
	// injected Adapter (the clock-pinned replay/test adapters) is used VERBATIM, so a
	// caller that builds its own adapter controls WithPartials itself and this flag is
	// ignored for it. DEFAULT false ⇒ the default adapter is claudecode.New() exactly
	// as today (the byte-identical / partials-off invariant); the runtime never emits
	// stream_event records without the host flag, so an armed adapter against an
	// un-armed runtime is simply a no-op (no deltas to project).
	LiveText bool
	// HistorySize is the maximum number of most-recent fanned events the
	// seq-indexed history ring retains for resume. <=0 ⇒ DefaultHistorySize. A
	// slow READER that dropped events past its bounded delivery buffer recovers
	// them by replaying from the ring (Conn.Resume / ReplayFrom); a reader whose
	// last-good Seq has aged out of the ring fails loud with
	// ErrResumeWindowExceeded and must full re-attach (loopback.go N-reader
	// independence; docs/15 §5.4; attach.v1 README §6.1 row 1).
	HistorySize int

	// AttachMatcher, when non-nil, is the EXISTING wrapper attach-seam keyed-secret-
	// digest matcher (claudecode.AttachDigestMatcher, built from the SAME frozen
	// identity.v1.DigestEntry feed ds-tlsproxy consumes) invoked on the LIVE stdin-
	// drive path: every DriveInput is offered to MatchInput BEFORE its bytes are
	// encoded onto CC stdin, so a user-PASTED swap-class token — which never
	// traverses ds-tlsproxy (it goes client wrapper → CC stdin directly) — is
	// matched + evented at runtime. This closes the doc 20 §4 canary residual AT
	// RUNTIME, not only as test-covered machinery (D73; doc 12 §10).
	//
	// FINGERPRINT-ONLY (D73): the matcher computes candidate keyed hashes and
	// returns DigestMatch values that carry fingerprint metadata exclusively — no
	// field can hold the pasted plaintext. The inspected bytes are NEVER logged,
	// spooled, or copied into any event by this seam.
	//
	// DEFAULT nil ⇒ matcher OFF ⇒ DriveInput is byte-identical to today (additive,
	// behavior-preserving): no MatchInput call, no sink call, no new failure mode.
	AttachMatcher *AttachDigestMatcher

	// DigestMatchSink, when non-nil, receives the fingerprint-only match set the
	// AttachMatcher produces for a DriveInput (routed BEFORE the input is encoded
	// onto CC stdin). Honored only alongside a non-nil AttachMatcher.
	//
	// FAIL-CLOSED-WHEN-KEYED: when an AttachMatcher IS configured, a sink error
	// makes DriveInput refuse the write and return ErrDigestSinkFailed — the input
	// is never driven past a failed inspection, mirroring the proxy's mint-before-
	// attach posture and the Rust SecretMatcher Holds fail-closed. With a matcher
	// but a NIL sink, matches are computed and dropped (no routing target) and the
	// input still drives — a matcher with no sink is an inspection with nowhere to
	// report, never a fail-closed; configure a sink to gate.
	DigestMatchSink DigestMatchSink
}

// NewBridge constructs a Bridge over a wrapped CC process's stdin. ccStdin is
// where driver-encoded records are written (the process's standard input). The
// stdout side is driven by Pump.
func NewBridge(ccStdin io.Writer, cfg BridgeConfig) *Bridge {
	a := cfg.Adapter
	if a == nil {
		// Default adapter: arm WithPartials when the session enabled live-text so the
		// adapter projects the runtime's typing deltas as render-only ChatDeltas (the
		// client half of U-PARTIALS-ARM). cfg.LiveText=false (the default) builds a bare
		// claudecode.New() — byte-identical to today. The injected-Adapter path above is
		// left untouched, so tests' clock-pinned adapters are unaffected.
		var opts []claudecode.Option
		if cfg.LiveText {
			opts = append(opts, claudecode.WithPartials())
		}
		a = claudecode.New(opts...)
	}
	d := cfg.Driver
	if d == nil {
		d = claudecode.NewDriver()
	}
	hs := cfg.HistorySize
	if hs <= 0 {
		hs = DefaultHistorySize
	}
	return &Bridge{
		adapter:     a,
		driver:      d,
		ccStdin:     ccStdin,
		matcher:     cfg.AttachMatcher,
		matchSink:   cfg.DigestMatchSink,
		historySize: hs,
		ring:        make([]attach.Event, 0, hs),
	}
}

// Subscribe registers s for the WatchSession fan-out. If the stream has already
// closed, s.OnClose is invoked immediately with the terminal error and the
// subscriber is not retained. Returns an unsubscribe func that detaches s
// (idempotent).
func (b *Bridge) Subscribe(s Subscriber) (unsubscribe func()) {
	b.subsMu.Lock()
	if b.closed {
		err := b.closeErr
		b.subsMu.Unlock()
		s.OnClose(err)
		return func() {}
	}
	b.subscribers = append(b.subscribers, s)
	b.subsMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			b.subsMu.Lock()
			defer b.subsMu.Unlock()
			for i, cur := range b.subscribers {
				if cur == s {
					b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
					return
				}
			}
		})
	}
}

// Pump drives CC stdout through the adapter and fans every projected attach.Event
// to subscribers, until EOF, an unrecoverable adapter error, or ctx cancellation.
// It is the reader half of the goroutine-per-stream model: run it in its own
// goroutine. It closes the fan-out on return (every subscriber's OnClose fires
// once with the terminal error). Returns the terminal error (nil on clean EOF).
//
// ccStdout is the wrapped CC process's standard output (the stream-json wire the
// adapter parses). The adapter's per-line Feed is reused verbatim — this is the
// EXISTING read half, not a re-implementation.
func (b *Bridge) Pump(ctx context.Context, ccStdout io.Reader) error {
	sc := bufio.NewScanner(ccStdout)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	var termErr error
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			termErr = err
			break
		}
		// Copy the line: Scanner reuses its buffer and the adapter may retain
		// slices (json.RawMessage) past the next Scan.
		line := append([]byte(nil), sc.Bytes()...)
		evs, err := b.adapter.Feed(line)
		if err != nil {
			termErr = fmt.Errorf("hostbridge: adapter feed: %w", err)
			break
		}
		for _, ev := range evs {
			b.fanout(ev)
		}
	}
	if termErr == nil {
		if err := sc.Err(); err != nil {
			termErr = fmt.Errorf("hostbridge: cc stdout scan: %w", err)
		} else if err := ctx.Err(); err != nil {
			termErr = err
		}
	}
	b.closeFanout(termErr)
	return termErr
}

// fanout delivers ev to every current subscriber, in registration order, holding
// the subscriber lock only to snapshot the slice so a slow OnEvent cannot block
// Subscribe/unsubscribe. Before delivery it records ev into the seq-indexed
// history ring so a slow READER that drops ev past its bounded delivery buffer
// can recover it via Conn.Resume / ReplayFrom (the resume-from-seq layer).
func (b *Bridge) fanout(ev attach.Event) {
	b.recordHistory(ev)
	b.subsMu.Lock()
	subs := append([]Subscriber(nil), b.subscribers...)
	b.subsMu.Unlock()
	for _, s := range subs {
		s.OnEvent(ev)
	}
}

// recordHistory appends ev to the bounded, oldest-first history ring, evicting
// the oldest once historySize is exceeded, and advances lastSeq. attach.Event.Seq
// is strictly monotonic from 1 (the adapter is the ordering authority, P10; the
// goldentrace golden suite asserts it), so the ring stays Seq-sorted by
// construction and is the exact resume key on which replayFromLocked's binary
// search depends. The defensive guard below keeps lastSeq from going backwards on
// a Seq the adapter should never emit (a duplicate or out-of-order event), so the
// pump never rejects an adapter-projected event mid-session; the ring's
// Seq-sorted invariant is supplied by the monotonic-Seq contract, not re-asserted
// here (a genuinely lower Seq would be appended at the tail, which only the
// upstream contract rules out).
func (b *Bridge) recordHistory(ev attach.Event) {
	b.historyMu.Lock()
	defer b.historyMu.Unlock()
	if ev.Seq > b.lastSeq {
		b.lastSeq = ev.Seq
	}
	if len(b.ring) == b.historySize {
		// Evict the oldest, keeping the ring oldest-first and bounded.
		copy(b.ring, b.ring[1:])
		b.ring[len(b.ring)-1] = ev
		return
	}
	b.ring = append(b.ring, ev)
}

// closeFanout marks the stream closed and fires OnClose on every subscriber
// once. Idempotent: a second call (e.g. Close after Pump) is a no-op.
func (b *Bridge) closeFanout(err error) {
	b.subsMu.Lock()
	if b.closed {
		b.subsMu.Unlock()
		return
	}
	b.closed = true
	b.closeErr = err
	subs := b.subscribers
	b.subscribers = nil
	b.subsMu.Unlock()
	for _, s := range subs {
		s.OnClose(err)
	}
}

// Warnings returns the adapter's accumulated skip/integrity warnings (drift is a
// recorded warning, never a crash — the adapter contract). Surfaced here so a
// bridge operator can see protocol drift without reaching into the adapter.
func (b *Bridge) Warnings() []string { return b.adapter.Warnings() }

// errSentinels for the write path.
var (
	// ErrInputClosed is returned by DriveInput/DriveGrant after the input side
	// has been closed (CloseInput, or a write error). The conversation's input is
	// complete; no further records may be driven.
	ErrInputClosed = errors.New("hostbridge: cc stdin already closed")
)

// DriveInput encodes in through the EXISTING driver (Driver.EncodeInput) and
// writes the resulting CC stream-json user-input record onto CC stdin, framed
// with a trailing newline (the stream-json record delimiter). Writes are
// serialized: a concurrent DriveGrant cannot interleave bytes on the wire.
//
// This is the writer-seat write path; the Server gates it on the caller holding
// the WRITER seat (a READER's write is refused before it reaches here). The
// driver does the encoding — the bridge never hand-rolls the CC envelope.
//
// ATTACH-SEAM DIGEST MATCH (D73; doc 20 §4 canary residual; doc 12 §10). When a
// keyed AttachDigestMatcher is configured (BridgeConfig.AttachMatcher), the input
// is offered to the matcher BEFORE it is encoded onto CC stdin: a user-PASTED
// swap-class token — which never traverses ds-tlsproxy, since the wrapper drives
// it straight onto the session's stdin — is matched + evented at runtime. The
// matcher is FINGERPRINT-ONLY (its DigestMatch results carry no inspected
// plaintext, D73) and is invoked on the live drive path, not only in tests. With
// no matcher configured (the default), this path is byte-identical to before.
//
// FAIL-CLOSED-WHEN-KEYED: with a matcher configured, if routing the matches to
// the DigestMatchSink fails, DriveInput REFUSES the write and returns
// ErrDigestSinkFailed — the input is never driven past a failed inspection
// (mirroring the proxy's mint-before-attach posture / the Rust SecretMatcher
// Holds fail-closed). The matcher's own MatchInput is total and cannot error.
func (b *Bridge) DriveInput(in DriveInput) error {
	if b.matcher != nil {
		// Offer the candidate bytes to the matcher BEFORE encoding. MatchInput is
		// total (no error path); it returns the fingerprint-only match set — never
		// any plaintext. The inspected bytes never escape the matcher (driver.go).
		if matches := b.matcher.MatchInput(in); len(matches) > 0 && b.matchSink != nil {
			if err := b.matchSink.OnDigestMatches(matches); err != nil {
				// Fail closed: a configured keyed inspection that cannot record its
				// match must HOLD the input, not let it through unscanned. The wrapped
				// cause carries zero inspected bytes (the sink saw only DigestMatch).
				return fmt.Errorf("%w: %v", ErrDigestSinkFailed, err)
			}
		}
	}
	rec, err := b.driver.EncodeInput(in)
	if err != nil {
		return err
	}
	return b.writeRecord(rec)
}

// DriveGrant encodes grant through the EXISTING driver and writes the resulting
// CC record onto CC stdin. route selects the proven encoding: GrantRoutePromptTool
// (Driver.EncodeGrantPromptTool, v0 default, joins on ToolUseID) or
// GrantRouteNativeControl (Driver.EncodeGrant, native control_response, joins on
// RequestID). The bridge forwards to the existing driver and never re-encodes a
// grant itself.
func (b *Bridge) DriveGrant(grant DriveGrant, route GrantRoute) error {
	var (
		rec []byte
		err error
	)
	switch route {
	case GrantRouteNativeControl:
		rec, err = b.driver.EncodeGrant(grant)
	case GrantRoutePromptTool:
		rec, err = b.driver.EncodeGrantPromptTool(grant)
	default:
		return fmt.Errorf("hostbridge: unknown grant route %d", route)
	}
	if err != nil {
		return err
	}
	return b.writeRecord(rec)
}

// writeRecord serializes rec + '\n' onto CC stdin under stdinMu so two encoded
// records never interleave. Fails closed once the input side is closed.
func (b *Bridge) writeRecord(rec []byte) error {
	b.stdinMu.Lock()
	defer b.stdinMu.Unlock()
	if b.stdinDone {
		return ErrInputClosed
	}
	if _, err := b.ccStdin.Write(rec); err != nil {
		return fmt.Errorf("hostbridge: write cc stdin: %w", err)
	}
	if _, err := b.ccStdin.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("hostbridge: write cc stdin newline: %w", err)
	}
	return nil
}

// CloseInput marks the input side complete: no further DriveInput/DriveGrant may
// be driven (signalling end-of-conversation to CC, the same semantics the e2e
// pump's stdin-close carries). If ccStdin is an io.Closer it is closed. Pump
// (the stdout side) is unaffected and runs until CC's own stdout EOF.
func (b *Bridge) CloseInput() error {
	b.stdinMu.Lock()
	defer b.stdinMu.Unlock()
	if b.stdinDone {
		return nil
	}
	b.stdinDone = true
	if c, ok := b.ccStdin.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Close shuts the bridge's fan-out down (firing OnClose on any remaining
// subscriber) and closes the input side. It is the bridge's half of session
// teardown; idempotent. The terminal error reported to late subscribers is
// context.Canceled-class — a caller with the real CC EOF error should let Pump
// report it instead.
func (b *Bridge) Close() error {
	b.closeFanout(errBridgeClosed)
	return b.CloseInput()
}

var errBridgeClosed = errors.New("hostbridge: bridge closed")

// --- resume-from-seq recovery primitives -------------------------------------
//
// A slow READER over the bounded fan-out drops events past its delivery buffer
// rather than stalling the shared pump (loopback.go: docs/15 §5.4 N-reader
// independence). The drop leaves a Seq discontinuity in that reader's stream.
// attach.Event.Seq is strictly monotonic from 1, so it is the exact resume key:
// the reader detects the gap (the Gap helper, loopback.go) and replays the
// missing span from the Bridge's bounded history ring — exactly once, in order,
// PROVIDED it is still retained. A reader further behind than the ring fails
// LOUD with ErrResumeWindowExceeded and must full re-attach; a silently gapped
// stream is never produced.

// ErrResumeWindowExceeded is returned by ReplayFrom / Conn.Resume when the
// requested afterSeq is older than the oldest Seq the bounded history ring still
// retains: the events the caller missed have aged out and CANNOT be replayed.
// It is the fail-loud boundary of the recovery layer — the consumer must fall
// back to a full re-attach (a fresh Subscribe + snapshot), never accept a
// silently gapped stream. ReplayFrom returns it with a nil slice (all-or-
// nothing). Match it with errors.Is.
var ErrResumeWindowExceeded = errors.New("hostbridge: resume beyond retained history window")

// ReplayFrom returns the retained events whose Seq is STRICTLY GREATER than
// afterSeq, in ascending Seq order. It is the exported, Conn-independent resume
// primitive: Conn.Resume is a thin splice over it, and a consumer managing its
// own delivery can call it directly.
//
// Contract (exactly-once, in-order, fail-loud):
//
//   - afterSeq == 0 means "from the beginning of what is retained" — the
//     late-joiner / fresh-attach backfill. It NEVER fails loud: the caller holds
//     no prior position to be contiguous with, so it returns whatever the ring
//     still has (possibly a window-truncated prefix).
//   - afterSeq >= LastSeq returns an empty (non-nil) slice and no error: caught up.
//   - For a RESUME (afterSeq > 0): if events past afterSeq have aged out (the
//     ring's oldest retained Seq is greater than afterSeq+1), returns
//     ErrResumeWindowExceeded and a nil slice — all-or-nothing, never a partial
//     backfill. The boundary case afterSeq+1 == oldestRetained is contiguous and
//     succeeds (no event between afterSeq and the ring was lost).
//
// The returned slice is a fresh copy the caller owns.
func (b *Bridge) ReplayFrom(afterSeq uint64) ([]attach.Event, error) {
	b.historyMu.Lock()
	defer b.historyMu.Unlock()
	return b.replayFromLocked(afterSeq)
}

// replayFromLocked is the core resume computation; caller holds historyMu so
// Conn.Resume can splice atomically with respect to the pump's recordHistory.
func (b *Bridge) replayFromLocked(afterSeq uint64) ([]attach.Event, error) {
	if afterSeq >= b.lastSeq {
		// Already caught up (covers the empty-ring lastSeq==0 case).
		return []attach.Event{}, nil
	}
	if afterSeq > 0 && len(b.ring) > 0 {
		// The caller wants (afterSeq, lastSeq]. Serve it iff every Seq in that
		// open-closed interval is still in the ring, i.e. the ring's oldest
		// retained Seq is <= afterSeq+1; otherwise at least one missing event
		// aged out — fail loud.
		if b.ring[0].Seq > afterSeq+1 {
			return nil, ErrResumeWindowExceeded
		}
	}
	// Binary search for the first ring entry with Seq > afterSeq (ring is
	// Seq-sorted because recordHistory fans in Seq order).
	i := sort.Search(len(b.ring), func(i int) bool { return b.ring[i].Seq > afterSeq })
	out := make([]attach.Event, len(b.ring)-i)
	copy(out, b.ring[i:])
	return out, nil
}

// LastSeq is the highest Seq the pump has fanned (0 before the first event). The
// gap between a reader's last-good Seq and LastSeq is its tail gap to resume.
func (b *Bridge) LastSeq() uint64 {
	b.historyMu.Lock()
	defer b.historyMu.Unlock()
	return b.lastSeq
}

// OldestRetainedSeq is the smallest Seq still in the history ring (0 when empty).
// A resume with afterSeq < OldestRetainedSeq-1 is the ErrResumeWindowExceeded
// case; exposed so a consumer can decide "resume vs full re-attach" before
// calling Resume.
func (b *Bridge) OldestRetainedSeq() uint64 {
	b.historyMu.Lock()
	defer b.historyMu.Unlock()
	if len(b.ring) == 0 {
		return 0
	}
	return b.ring[0].Seq
}

// nowFunc is the bridge package's clock seam, overridable in tests for handle
// expiry. Defaults to time.Now.
var nowFunc = time.Now
