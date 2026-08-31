package loop

import (
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	"github.com/dream-serpent/dream-serpent/client/tui"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"

	"github.com/dream-serpent/dream-serpent/serpent-tui/internal/driver"
)

// fakeSeat is an in-process driver.WriterSeat recording everything driven — the
// offline writer seat the interactive loop drives instead of a live host agent.
type fakeSeat struct {
	inputs []string
	grants []hostbridge.DriveGrant
	routes []hostbridge.GrantRoute
	failOn string // if non-empty, DriveInput with this text returns an error
}

func (f *fakeSeat) DriveInput(in hostbridge.DriveInput) error {
	if f.failOn != "" && in.Text == f.failOn {
		return errors.New("seat: forced drive failure")
	}
	f.inputs = append(f.inputs, in.Text)
	return nil
}

func (f *fakeSeat) DriveGrant(g hostbridge.DriveGrant, route hostbridge.GrantRoute) error {
	f.grants = append(f.grants, g)
	f.routes = append(f.routes, route)
	return nil
}

func newWriter(seat driver.WriterSeat) *driver.Writer {
	return &driver.Writer{Seat: seat, Route: driver.GrantRoutePromptTool}
}

// TestKeystrokeComposeAndSubmit proves the per-keystroke composer accumulates
// runes and SubmitInput drives the composed line to the writer seat (the runtime
// stdin via the wrapper, D18), then clears the composer.
func TestKeystrokeComposeAndSubmit(t *testing.T) {
	seat := &fakeSeat{}
	st := New(newWriter(seat))

	for _, r := range "hello" {
		st.TypeRune(r)
	}
	st.TypeRune(' ')
	for _, r := range "world" {
		st.TypeRune(r)
	}
	if got := st.Compose(); got != "hello world" {
		t.Fatalf("compose = %q, want %q", got, "hello world")
	}

	sent, err := st.SubmitInput()
	if err != nil || !sent {
		t.Fatalf("SubmitInput = (%v, %v), want (true, nil)", sent, err)
	}
	if len(seat.inputs) != 1 || seat.inputs[0] != "hello world" {
		t.Fatalf("driven inputs = %v, want [hello world]", seat.inputs)
	}
	if st.Compose() != "" {
		t.Fatalf("composer not cleared after submit: %q", st.Compose())
	}
}

// TestBackspaceAndEmptySubmit proves Backspace edits the composer and a blank/
// whitespace-only submit is a no-op (nothing driven).
func TestBackspaceAndEmptySubmit(t *testing.T) {
	seat := &fakeSeat{}
	st := New(newWriter(seat))

	for _, r := range "abc" {
		st.TypeRune(r)
	}
	st.Backspace()
	if st.Compose() != "ab" {
		t.Fatalf("compose after backspace = %q, want ab", st.Compose())
	}

	// Whitespace-only submit: no-op, no drive, composer cleared.
	st2 := New(newWriter(seat))
	st2.TypeRune(' ')
	st2.TypeRune('\t')
	sent, err := st2.SubmitInput()
	if err != nil || sent {
		t.Fatalf("blank SubmitInput = (%v, %v), want (false, nil)", sent, err)
	}
	if len(seat.inputs) != 0 {
		t.Fatalf("blank submit drove input: %v", seat.inputs)
	}
}

// TestAnswerPendingForwardsGrant proves answering the parked ask records the
// human decision on the Model (no stored grant, D45) and forwards it as a
// DriveGrant on the prompt-tool route joined on the tool_use_id (the ask id).
func TestAnswerPendingForwardsGrant(t *testing.T) {
	seat := &fakeSeat{}
	st := New(newWriter(seat))

	// Fold an ask so the session is parked.
	mustApply(t, st, askEvent(1, "tu-1", "Bash"))
	if !st.Parked() {
		t.Fatalf("session should be parked on the pending ask")
	}

	answered, err := st.AnswerPending(tui.DecisionAllowOnce)
	if err != nil || !answered {
		t.Fatalf("AnswerPending = (%v, %v), want (true, nil)", answered, err)
	}
	if len(seat.grants) != 1 {
		t.Fatalf("grants driven = %d, want 1", len(seat.grants))
	}
	g := seat.grants[0]
	if !g.Allow {
		t.Errorf("allow-once should drive Allow=true, got %v", g.Allow)
	}
	if g.ToolUseID != "tu-1" {
		t.Errorf("grant tool_use_id = %q, want tu-1 (prompt-tool join key)", g.ToolUseID)
	}
	if seat.routes[0] != driver.GrantRoutePromptTool {
		t.Errorf("grant route = %v, want prompt-tool (the proven default)", seat.routes[0])
	}
	// The ask moved to answered; the session is no longer parked, and NO standing
	// grant is stored (D45): the Model's ask is answered, not a rule.
	if st.Parked() {
		t.Errorf("session still parked after answering")
	}
}

// TestAllowAlwaysIsProposalNotASecondChannel proves allow-always forwards an
// ALLOW for this one ask (the proposal's standing effect is org-side) and the
// client stores nothing — the only memory of an approval lives org-side, never
// here (D45/D53). Deny forwards Allow=false.
func TestAllowAlwaysAndDeny(t *testing.T) {
	seat := &fakeSeat{}
	st := New(newWriter(seat))
	mustApply(t, st, askEvent(1, "tu-A", "Write"))
	if _, err := st.AnswerPending(tui.DecisionAllowAlways); err != nil {
		t.Fatalf("answer allow-always: %v", err)
	}
	if !seat.grants[0].Allow {
		t.Errorf("allow-always should forward Allow=true for this ask")
	}

	seat2 := &fakeSeat{}
	st2 := New(newWriter(seat2))
	mustApply(t, st2, askEvent(1, "tu-D", "Bash"))
	if _, err := st2.AnswerPending(tui.DecisionDeny); err != nil {
		t.Fatalf("answer deny: %v", err)
	}
	if seat2.grants[0].Allow {
		t.Errorf("deny should forward Allow=false")
	}
}

// TestReaderOnlyRefusesDrive proves a loop with NO writer seat refuses to drive
// input or answer asks — the seat is arbitrated server-side and never fabricated
// (D61). Composing still works locally; only the send is refused.
func TestReaderOnlyRefusesDrive(t *testing.T) {
	st := New(nil)
	for _, r := range "hi" {
		st.TypeRune(r)
	}
	sent, err := st.SubmitInput()
	if sent || err == nil {
		t.Fatalf("reader-only SubmitInput = (%v, %v), want (false, err)", sent, err)
	}

	mustApply(t, st, askEvent(1, "tu-1", "Bash"))
	answered, err := st.AnswerPending(tui.DecisionAllowOnce)
	if answered || err == nil {
		t.Fatalf("reader-only AnswerPending = (%v, %v), want (false, err)", answered, err)
	}
}

// TestSubmitForwardErrorIsNonFatal proves a DriveInput failure surfaces as a
// returned error AND is recorded as the loop's LastError (a non-fatal status the
// surface shows), without panicking — the loop survives a flaky writer seat.
func TestSubmitForwardErrorIsNonFatal(t *testing.T) {
	seat := &fakeSeat{failOn: "boom"}
	st := New(newWriter(seat))
	for _, r := range "boom" {
		st.TypeRune(r)
	}
	sent, err := st.SubmitInput()
	if sent || err == nil {
		t.Fatalf("failing SubmitInput = (%v, %v), want (false, err)", sent, err)
	}
	if st.LastError() == nil {
		t.Fatalf("forward error not recorded as LastError")
	}
}

// TestApplyFoldErrorIsFatal proves an out-of-order seq fold is a FATAL contract
// violation surfaced from Apply (P10/D79) — never silently reordered.
func TestApplyFoldErrorIsFatal(t *testing.T) {
	st := New(nil)
	mustApply(t, st, stateEvent(5))
	// seq 3 after seq 5: out of order — a writer/ordering bug, must error.
	if err := st.Apply(stateEvent(3)); err == nil {
		t.Fatalf("out-of-order fold should error (ordering authority is the wrapper, P10)")
	}
}

// --- helpers -----------------------------------------------------------------

func mustApply(t *testing.T, st *State, ev attach.Event) {
	t.Helper()
	if err := st.Apply(ev); err != nil {
		t.Fatalf("apply seq %d: %v", ev.Seq, err)
	}
}

func askEvent(seq uint64, toolUseID, toolName string) attach.Event {
	return attach.Event{
		Seq:  seq,
		Type: attach.TypeAskRequested,
		AskRequested: &attach.AskRequested{
			AskID:    toolUseID, // eventmap collapses request_id||tool_use_id; here the ask id IS the tool_use_id
			NodeID:   toolUseID,
			ToolName: toolName,
			Source:   "control",
		},
	}
}

func stateEvent(seq uint64) attach.Event {
	return attach.Event{
		Seq:          seq,
		Type:         attach.TypeSessionState,
		SessionState: &attach.SessionState{State: "WORKING"},
	}
}
