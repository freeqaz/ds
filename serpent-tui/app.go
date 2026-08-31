// Package serpenttui wires serpent-tui's three legs into one runnable attach: the
// WatchSession gRPC subscriber (the READ stream, internal/watch), the writer-seat
// driver (the WRITE leg, internal/driver), and the bubbletea interactive loop
// (internal/loop) folding+rendering through the OSS client/tui Model.
//
// MAINTAINER-RATIFIED OPTION C. This module is OUT of the root go.work and is the
// ONLY place bubbletea enters the tree; client/ stays stdlib-only. The real
// human-in-the-loop CC experience runs here: keystrokes drive the writer seat, a
// session served by the orchestrator's WatchSession (the N5 handlers on
// origin/main) streams attach.v1 events that fold into the structured surface,
// and approvals render client-side as TTL'd grants (D45/D53), never a second
// proxy channel.
//
// LIVE IS N7-GATED. Run binds against ANY watch.Starter + driver.WriterSeat: in
// production the Starter is orchestratorv1.NewSessionServiceClient over a real
// dial and the seat is a client/hostbridge SocketConn over the AttachHandle's
// direct endpoint; offline (and in tests) both are in-process fakes. This package
// performs NO live dial itself — it is unit-testable against an in-process fake
// WatchSession server (app_test.go) with no orchestrator or VM.
package serpenttui

import (
	"context"
	"errors"
	"io"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/driver"
	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/eventmap"
	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/loop"
	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/watch"
)

// scriptedPromptSettle is how long the scripted-prompt leg waits before submitting,
// so the bubbletea Program is running (prog.Send is safe after Run starts) and the
// WatchSession read stream + writer seat have settled. A rig-tuned value, not
// load-bearing; a package var only so the same-package test can shorten it.
var scriptedPromptSettle = 2 * time.Second

// Config wires one attach run. SessionUUID and Starter are required; Seat is the
// writer-seat input leg (nil ⇒ a reader-only run — input/answers are refused, the
// seat is arbitrated server-side and never fabricated, D61). In/Out are the TTY
// I/O for bubbletea (nil ⇒ os.Stdin/os.Stdout via the program options the cmd
// entrypoint sets). Color selects the styled renderer.
type Config struct {
	SessionUUID string
	Starter     watch.Starter
	Seat        driver.WriterSeat
	In          io.Reader
	Out         io.Writer
	Color       bool

	// Backoff / WatchOptions tune the subscriber's reconnect schedule; the zero
	// values are the production posture (watch.DefaultBackoff, real clock+jitter).
	Backoff      watch.BackoffPolicy
	WatchOptions watch.Options

	// EventStream, when non-nil, is the READ STREAM the loop folds — used INSTEAD of
	// the orchestrator's WatchSession gRPC subscriber. It is the writer-seat
	// hostbridge.SocketConn's Events() channel (the SAME attach.Event stream the proven
	// goldentrace drive harness reads): CC's stdout is projected to attach.v1 deltas by
	// the host-agent serving leg and fanned to this attachment, so the events CC emits
	// (session.init, chat.message, tool.invoked, …) arrive HERE. On the single-box MVP
	// the orchestrator's WatchSession fan-out is fed only by the heartbeat relay (§3 state
	// EDGES), NOT CC's content — so without this the loop renders no CC response and seq
	// stays 0. When set, Run folds this channel and does NOT start the WatchSession
	// subscriber (Starter is still required for the Attach/seat resolution upstream, but
	// is not subscribed). Nil keeps the WatchSession read path unchanged.
	EventStream <-chan attach.Event

	// GrantRoute selects the ask-answer encoding (the proven prompt-tool route by
	// default). ResolveAsk maps a tui ask id to the (toolUseID, requestID) join
	// pair; nil ⇒ the ask id is the tool_use_id (the prompt-tool default).
	GrantRoute hostbridgeGrantRoute
	ResolveAsk func(askID string) (toolUseID, requestID string)

	// ScriptedPrompt, when non-empty, drives ONE deterministic prompt through the
	// writer seat the moment the interactive loop is running — without relying on a
	// TTY or on piped-stdin EOF semantics (a `printf 'p\n' | serpent` can tear the
	// bubbletea program down on EOF before the Enter/submit event lands, so the
	// DriveInput never reaches the seat). It is the NON-INTERACTIVE verification
	// entry point: the cmd binary sets it from an env so a CI/operator smoke can
	// submit a known prompt and assert the in-VM CC's response renders back. It
	// injects the prompt's runes followed by a real Enter key into the running
	// program (the SAME keystroke→SubmitInput→DriveInput path a human drives), then
	// leaves the loop running so the streamed response folds and renders. Empty (the
	// default) is a no-op — the interactive UX is completely unchanged.
	ScriptedPrompt string

	// programOptions are extra bubbletea options (tests inject tea.WithoutRenderer
	// so the Program runs headless with no TTY); production leaves it nil.
	programOptions []tea.ProgramOption
	// onProgram, if set, is called with the constructed *tea.Program before Run
	// blocks — the seam a same-package test uses to inject deterministic
	// keystrokes (prog.Send(tea.KeyMsg{...})) without parsing a TTY. Production
	// leaves it nil; keystrokes arrive off the real terminal input.
	onProgram func(*tea.Program)
	// onState, if set, is called with the loop State before Run blocks — a
	// same-package test reads Parked()/PendingAsks() through it to gate keystroke
	// injection deterministically (the State is concurrency-safe). Production nil.
	onState func(*loop.State)
}

// hostbridgeGrantRoute aliases the hostbridge GrantRoute so a Config caller does
// not have to import client/hostbridge just to set the default. driver.Writer
// re-exports the concrete type; the alias keeps the public Config surface from
// leaking the OSS import while staying type-identical.
type hostbridgeGrantRoute = driver.GrantRoute

// Run builds the loop State (over the writer seat), starts the WatchSession
// subscriber in a goroutine pushing mapped events into the bubbletea Program, and
// runs the Program until the stream ends, a fatal fold error, or the operator
// quits (Ctrl+C). It returns the terminal cause (nil on a clean end). It is the
// single entry point the cmd binary and the tests both drive.
//
// The subscriber resumes from the loop's LastSeq on every reconnect (D79) — the
// loop State's Model is the seq authority shared between the fold (Update) and the
// resume token (the subscriber goroutine's lastSeq()). A fold error surfaced
// through the program is the terminal cause; the subscriber is torn down by ctx
// cancel when the program quits.
func Run(ctx context.Context, cfg Config) error {
	if cfg.SessionUUID == "" {
		return errors.New("serpent-tui: Run requires a SessionUUID")
	}
	if cfg.Starter == nil {
		return errors.New("serpent-tui: Run requires a WatchSession Starter")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var w *driver.Writer
	if cfg.Seat != nil {
		w = &driver.Writer{Seat: cfg.Seat, Route: cfg.GrantRoute, ResolveAsk: cfg.ResolveAsk}
	}
	// A nil *driver.Writer must be passed to loop.New as an untyped-nil tui.Writer
	// (a typed nil would be a non-nil interface and the loop would try to drive a
	// nil seat). Build the interface explicitly.
	st := newLoopState(w)
	if cfg.onState != nil {
		cfg.onState(st)
	}

	model := loop.NewModel(st, cfg.Color)

	opts := []tea.ProgramOption{tea.WithContext(ctx)}
	switch {
	case cfg.In != nil:
		opts = append(opts, tea.WithInput(cfg.In))
	case cfg.ScriptedPrompt != "":
		// Scripted (non-interactive) verification: DISABLE bubbletea's TTY input reader.
		// The prompt is injected via prog.Send (driveScriptedPrompt), so no keyboard reader
		// is needed — and a non-TTY stdin (a CI/script context) makes bubbletea's cancelreader
		// fail to epoll ("error creating cancel reader: add reader to epoll interest list"),
		// which previously aborted the attach before any prompt was driven. WithInput(nil)
		// runs the program with no input reader, so the scripted keystrokes are the only input.
		opts = append(opts, tea.WithInput(nil))
	}
	if cfg.Out != nil {
		opts = append(opts, tea.WithOutput(cfg.Out))
	}
	opts = append(opts, cfg.programOptions...)
	prog := tea.NewProgram(model, opts...)
	if cfg.onProgram != nil {
		cfg.onProgram(prog)
	}

	// Scripted-prompt verification leg: drive ONE deterministic prompt through the
	// running program's keystroke path, then leave the loop running so the response
	// renders. We submit from a goroutine that settles briefly first, so the program
	// is running (prog.Send is safe once Run has started) and the writer seat is
	// live. This is the SAME path a human drives (per-rune KeyRunes then KeyEnter →
	// SubmitInput → DriveInput), so it exercises the real submit, not a piped-stdin
	// EOF that can race the program teardown. Empty ScriptedPrompt is a no-op.
	if cfg.ScriptedPrompt != "" {
		go driveScriptedPrompt(ctx, prog, cfg.ScriptedPrompt)
	}

	// Subscriber goroutine: drain WatchSession, map each frozen proto event onto
	// the client/tui Event model, and FOLD IT SYNCHRONOUSLY here (under State's
	// lock, concurrency-safe against the Update goroutine's keystroke edits). The
	// fold must be synchronous so st.LastSeq() is accurate at RESUME time — the
	// subscriber resumes from it on every reconnect (D79), and a deferred fold
	// would let a clean-end reconnect re-request an already-in-flight prefix and
	// double-apply (the out-of-order-seq contract violation). After folding, a
	// redraw message wakes the bubbletea Program to re-render; the Program's
	// Update never mutates the seq-ordered Model, so the fold has exactly one
	// writer. A fold error (P10/D79) propagates as the subscriber's terminal cause.
	go func() {
		var err error
		if cfg.EventStream != nil {
			// DIRECT writer-seat event stream (the single-box MVP read path): fold the
			// hostbridge.SocketConn's already-projected attach.Event deltas straight into
			// the loop State — no proto conversion (the channel yields the SAME
			// client/wrapper/attach.Event type st.Apply consumes), no WatchSession
			// subscriber. The events CC emits arrive on THIS channel (the host-agent
			// serving leg fans CC's projected stdout to this attachment), so this is what
			// advances seq + renders CC's response. A fold error is the terminal cause.
			err = foldEventStream(ctx, cfg.EventStream, st, prog)
		} else {
			// WatchSession gRPC read path (the orchestrator fan-out): map each frozen
			// proto event onto the client/tui Event model and FOLD IT SYNCHRONOUSLY here
			// (under State's lock, concurrency-safe against the Update goroutine's
			// keystroke edits). The fold must be synchronous so st.LastSeq() is accurate at
			// RESUME time — the subscriber resumes from it on every reconnect (D79), and a
			// deferred fold would let a clean-end reconnect re-request an already-in-flight
			// prefix and double-apply (the out-of-order-seq contract violation).
			err = watch.Run(ctx, cfg.Starter, cfg.SessionUUID, st.LastSeq,
				func(ev *attachv1.SessionEvent) error {
					if ferr := st.Apply(eventmap.FromProto(ev)); ferr != nil {
						return ferr
					}
					prog.Send(loop.RedrawMsg{})
					return nil
				}, cfg.Backoff, cfg.WatchOptions)
		}
		// Signal the program the stream ended (clean drain, ctx cancel, or a
		// terminal status). A ctx.Canceled here means the program already quit
		// (operator Ctrl+C) — report it as a clean end.
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		prog.Send(loop.StreamEndMsg{Err: err})
	}()

	finalModel, runErr := prog.Run()
	if runErr != nil {
		return runErr
	}
	if fm, ok := finalModel.(*loop.Model); ok {
		return fm.FinalErr()
	}
	return nil
}

// foldEventStream folds a direct attach.Event read stream (the writer-seat
// hostbridge.SocketConn's Events() channel) into the loop State, waking the bubbletea
// Program to re-render after each event. It is the single-box MVP read path: CC's
// stdout is projected to attach.v1 deltas by the host-agent serving leg and fanned to
// this attachment, so ranging this channel is what advances the rendered seq + shows
// CC's response (the orchestrator's WatchSession carries only §3 state edges here).
// It returns nil on a clean channel close (session end) or ctx cancel, and the fold
// error on an out-of-order/contract violation (the terminal cause, like WatchSession's).
func foldEventStream(ctx context.Context, events <-chan attach.Event, st *loop.State, prog *tea.Program) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				return nil // the writer-seat stream closed (session end) — a clean drain
			}
			if ferr := st.Apply(ev); ferr != nil {
				return ferr
			}
			prog.Send(loop.RedrawMsg{})
		}
	}
}

// newLoopState builds a loop.State, passing an UNTYPED-nil writer when w is nil
// (so a reader-only run does not carry a typed-nil *driver.Writer that would
// present as a non-nil tui.Writer interface and attempt to drive a nil seat).
func newLoopState(w *driver.Writer) *loop.State {
	if w == nil {
		return loop.New(nil)
	}
	return loop.New(w)
}

// driveScriptedPrompt injects one prompt into the running bubbletea Program via the
// SAME keystroke path a human drives — per-rune KeyRunes messages followed by a real
// KeyEnter (→ Model.Update → State.SubmitInput → writer-seat DriveInput). It settles
// briefly first so the Program is running and the seat is live, and bails cleanly on
// ctx cancel (the loop ended / operator quit) so a teardown never blocks on it. It does
// NOT quit the program: the response must stream back and render, which the loop's
// subscriber goroutine folds. Spaces are sent as KeySpace and newlines are dropped so a
// multi-line prompt submits as one line (SubmitInput trims trailing CR/LF anyway).
func driveScriptedPrompt(ctx context.Context, prog *tea.Program, prompt string) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(scriptedPromptSettle):
	}
	for _, r := range prompt {
		if ctx.Err() != nil {
			return
		}
		switch r {
		case '\n', '\r':
			continue // newlines do not compose; the prompt submits as one line
		case ' ':
			prog.Send(tea.KeyMsg(tea.Key{Type: tea.KeySpace}))
		default:
			prog.Send(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune{r}}))
		}
	}
	if ctx.Err() != nil {
		return
	}
	prog.Send(tea.KeyMsg(tea.Key{Type: tea.KeyEnter}))
}
