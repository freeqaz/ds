// Package loop is serpent-tui's interactive writer-seat loop: it folds the
// incoming attach.v1 SessionEvent stream into the OSS client/tui Model, renders
// the structured surface via client/tui's Render/RenderPlain, and turns operator
// keystrokes into writer-seat input (and ask answers into grants) through the
// driver (D18 — input to the runtime's stdin via the wrapper, never frames).
//
// TESTABILITY-FIRST SPLIT. The state machine (State, below) is a PURE,
// bubbletea-free unit: every transition — fold one event, accept a keystroke,
// submit the composed line, answer a pending ask — is a plain method with no I/O
// and no TTY. The bubbletea Model (model.go) is a thin adapter that wires
// keystrokes and streamed events onto State and renders State.View(). This is why
// the interactive loop is unit-testable offline (state_test.go drives State
// directly; the bubbletea program is exercised only at the cmd entrypoint against
// the in-process fake server).
//
// SEQ + ORDERING. State folds through the client/tui Model, which is the ordering
// authority (it asserts strict per-event seq monotonicity, P10/D79) and exposes
// LastSeq — the resume token the watch subscriber resumes from on a reconnect.
// A fold error (out-of-order/duplicate seq) is surfaced, never swallowed.
package loop

import (
	"strings"
	"sync"

	"github.com/dream-serpent/dream-serpent/client/tui"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// State is the pure interactive-loop state: the folded client/tui Model, the
// in-progress operator input line (the composer), and the writer seat to drive.
// It is safe for concurrent use — the bubbletea Update goroutine folds events and
// handles keys under one mutex — so the watch subscriber (a separate goroutine)
// can deliver events while the operator types.
type State struct {
	mu      sync.Mutex
	model   *tui.Model
	writer  tui.Writer // nil ⇒ reader-only (no writer seat); input/answers are refused
	compose []rune     // the in-progress operator input line (the composer buffer)

	// lastErr records the most recent non-fatal forwarding error (a DriveInput /
	// DriveGrant failure) so the surface can show it without tearing the loop
	// down; a FOLD error is fatal and returned from Apply instead.
	lastErr error
}

// New constructs a loop State over a fresh client/tui Model and the given writer
// seat. A nil writer is a reader-only loop: SubmitInput / AnswerPending refuse
// (the loop never fabricates a writer seat — the seat is arbitrated server-side,
// D61). The writer is the serpent-tui driver.Writer (adapting the hostbridge
// SocketConn) in production, or a fake in tests.
func New(writer tui.Writer) *State {
	return &State{model: tui.NewModel(), writer: writer}
}

// Model returns the underlying client/tui Model (the ordering authority + the
// render source). Callers read it under the loop's lock via the State methods;
// it is exposed for the watch subscriber's LastSeq resume token.
func (s *State) Model() *tui.Model { return s.model }

// LastSeq is the highest event seq folded — the resume token the watch
// subscriber passes as from_seq on a reconnect (doc 15 §6.1 row 1 / D79). It is
// taken under the loop lock so it is consistent with a concurrent fold.
func (s *State) LastSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model.LastSeq()
}

// Apply folds one attach.v1 event (already mapped from proto by eventmap) into
// the Model in seq order. A fold error (out-of-order/duplicate seq — a writer/
// ordering contract violation, P10/D79) is FATAL and returned: it is not a
// transport blip and the caller stops the subscription. It is safe to call from
// the watch subscriber goroutine.
func (s *State) Apply(ev attach.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model.Apply(ev)
}

// --- the composer: keystroke -> writer-seat input ----------------------------

// TypeRune appends a printable rune to the in-progress input line. It is the
// per-keystroke composer edit; nothing is sent until SubmitInput (Enter). A
// reader-only loop still composes locally (the refusal is at submit time) so the
// surface behaves identically until the operator tries to send.
func (s *State) TypeRune(r rune) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.compose = append(s.compose, r)
}

// Backspace deletes the last composed rune (no-op on an empty buffer).
func (s *State) Backspace() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.compose) > 0 {
		s.compose = s.compose[:len(s.compose)-1]
	}
}

// Compose returns the current in-progress input line (for rendering the
// composer). It is a snapshot copy, safe to read concurrently with edits.
func (s *State) Compose() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.compose)
}

// SubmitInput forwards the composed line to the writer seat (the runtime's stdin
// via the wrapper, D18) and clears the composer. A whitespace-only line is a
// no-op (nothing to drive). Returns (sent, err): sent is false when there was
// nothing to send or the loop is reader-only; err is a forwarding failure (also
// recorded on lastErr so the surface can show it). The loop NEVER blocks on the
// seat — DriveInput is a single framed write.
func (s *State) SubmitInput() (sent bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := strings.TrimRight(string(s.compose), "\r\n")
	if strings.TrimSpace(line) == "" {
		s.compose = s.compose[:0]
		return false, nil
	}
	if s.writer == nil {
		s.lastErr = errReaderOnly
		return false, errReaderOnly
	}
	if err := s.writer.SendInput(line); err != nil {
		s.lastErr = err
		return false, err
	}
	s.compose = s.compose[:0]
	return true, nil
}

// --- approvals: ask answer -> TTL'd grant (D45/D53), never a second channel ---

// PendingAsks returns the open asks the surface prompts on (a parked session,
// D53). It is a snapshot through the Model's PendingAsks under the loop lock.
func (s *State) PendingAsks() []*tui.Ask {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model.PendingAsks()
}

// Parked reports whether the session is PARKED on an unanswered ask (D53/D77):
// the human is being awaited; the session never times out into allow or kill.
func (s *State) Parked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model.Parked()
}

// AnswerPending answers the OLDEST pending ask with decision d: it records the
// human's choice on the Model (no stored grant, D45) and forwards it through the
// writer seat as a grant (the TTL'd-grant path, never a second proxy channel,
// D45/D53). Returns (answered, err): answered is false when there is no pending
// ask or the loop is reader-only. A forward failure is recorded on lastErr and
// returned. allow-always is forwarded as a PROPOSAL — the client stores nothing.
func (s *State) AnswerPending(d tui.Decision) (answered bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := s.model.PendingAsks()
	if len(pending) == 0 {
		return false, nil
	}
	ask := pending[0]
	if s.writer == nil {
		s.lastErr = errReaderOnly
		return false, errReaderOnly
	}
	// Record on the model first (moves the ask to answered; stores no grant). A
	// model error here (the ask vanished between snapshot and answer) is surfaced.
	if _, merr := s.model.AnswerAsk(ask.AskID, d); merr != nil {
		s.lastErr = merr
		return false, merr
	}
	if ferr := s.writer.AnswerAsk(ask.AskID, d); ferr != nil {
		s.lastErr = ferr
		return false, ferr
	}
	return true, nil
}

// AnswerAsk answers a SPECIFIC ask by id (the same record-then-forward path as
// AnswerPending). It is the id-addressed variant a richer surface uses; the
// keystroke loop uses AnswerPending (answer the one the session is parked on).
func (s *State) AnswerAsk(askID string, d tui.Decision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer == nil {
		s.lastErr = errReaderOnly
		return errReaderOnly
	}
	if _, merr := s.model.AnswerAsk(askID, d); merr != nil {
		s.lastErr = merr
		return merr
	}
	if ferr := s.writer.AnswerAsk(askID, d); ferr != nil {
		s.lastErr = ferr
		return ferr
	}
	return nil
}

// LastError returns the most recent non-fatal forwarding error (or nil). The
// surface shows it as a status line; it does not stop the loop.
func (s *State) LastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}
