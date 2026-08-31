package tui

import (
	"bytes"
	"strings"
	"testing"
)

// recordingSink captures forwarded writer-seat input and answers so the test
// can assert that a decision is FORWARDED through the wrapper (and that no grant
// is stored anywhere — there is no grant store to check, by construction).
type recordingSink struct {
	inputs  []string
	answers []answer
}

type answer struct {
	askID string
	d     Decision
}

func (s *recordingSink) WriteInput(line string) error {
	s.inputs = append(s.inputs, line)
	return nil
}
func (s *recordingSink) WriteAnswer(askID string, d Decision) error {
	s.answers = append(s.answers, answer{askID, d})
	return nil
}

// askControlToFirstResolve trims the ask-control golden so the stream ends at a
// pending ask (drops the resolution lines), forcing the App loop to PARK and
// prompt — the live ask-prompt flow without a wire resolution racing the human.
func askControlToFirstAsk(src string) string {
	var keep []string
	for _, ln := range strings.Split(strings.TrimSpace(src), "\n") {
		keep = append(keep, ln)
		if strings.Contains(ln, `"type":"ask.requested"`) {
			break // stop right after the first ask: now pending, session parked
		}
	}
	return strings.Join(keep, "\n") + "\n"
}

// TestAppAskPromptFlow drives the interactive App loop against the ask-control
// fixture truncated to a pending ask, feeds an operator "allow once" decision,
// and asserts the decision is recorded on the model AND forwarded through the
// wrapper Writer — with no grant stored (D45/D53). This is the brief's DONE
// gate: "the ask-prompt flow works against the ask-control fixture."
func TestAppAskPromptFlow(t *testing.T) {
	full := string(loadGolden(t, "ask-control"))
	src := askControlToFirstAsk(full)

	sink := &recordingSink{}
	var out bytes.Buffer
	app := &App{
		Transport: &LocalTransport{Reader: strings.NewReader(src), Sink: sink},
		Handle:    AttachHandle{Role: RoleWriter, Endpoints: []EndpointCandidate{{Kind: "local"}}},
		Out:       &out,
		In:        strings.NewReader("1\n"), // operator chooses [1] allow once
	}

	m, err := app.Run()
	if err != nil {
		t.Fatalf("app run: %v", err)
	}

	// The prompt must have rendered all three D45 options + the park warning.
	o := out.String()
	for _, want := range []string{
		"allow once", "allow always (PROPOSAL", "deny",
		"never times out into allow or kill",
	} {
		if !strings.Contains(o, want) {
			t.Errorf("prompt output missing %q\n--- output ---\n%s", want, o)
		}
	}

	// The decision was forwarded through the wrapper exactly once.
	if len(sink.answers) != 1 {
		t.Fatalf("expected 1 forwarded answer, got %d", len(sink.answers))
	}
	if sink.answers[0].d != DecisionAllowOnce {
		t.Errorf("forwarded decision = %s, want allow-once", sink.answers[0].d)
	}

	// The ask is recorded answered on the model; after answering the only ask
	// the session un-parks.
	if len(m.Asks) != 1 || m.Asks[0].State != AskAnswered {
		t.Fatalf("ask state = %+v, want one AskAnswered", m.Asks)
	}
	if m.Parked() {
		t.Errorf("after answering the only pending ask the session must un-park")
	}
}

// TestAppParkOnNoDecision: an operator who gives no answer (EOF) leaves the ask
// pending and the session PARKED — never timing out into allow or kill
// (D53/D77). No decision is forwarded.
func TestAppParkOnNoDecision(t *testing.T) {
	src := askControlToFirstAsk(string(loadGolden(t, "ask-control")))
	sink := &recordingSink{}
	var out bytes.Buffer
	app := &App{
		Transport: &LocalTransport{Reader: strings.NewReader(src), Sink: sink},
		Handle:    AttachHandle{Role: RoleWriter},
		Out:       &out,
		In:        strings.NewReader(""), // no input: EOF
	}
	m, err := app.Run()
	if err != nil {
		t.Fatalf("app run: %v", err)
	}
	if !m.Parked() {
		t.Errorf("no decision must leave the session PARKED, not auto-resolved")
	}
	if len(sink.answers) != 0 {
		t.Errorf("no decision must forward nothing, got %d answers", len(sink.answers))
	}
	if !strings.Contains(out.String(), "parked") {
		t.Errorf("output should report the session is parked on the ask")
	}
}

// twoPanelModel builds a Model with two completed tool panels (n1 then n2) — the
// minimal substrate for the fold-affordance tests below. The panel order is the
// first-invoked order (ToolPanels()), so n1 is the sibling and n2 is the
// most-recent (default-focused) panel.
func twoPanelModel(t *testing.T) *Model {
	t.Helper()
	m := NewModel()
	mustApply(t, m,
		toolInvoked(1, "n1", "Bash", "g1", `{"command":"echo one"}`),
		toolCompleted(2, "n1", "OUTPUT_ONE"),
		toolInvoked(3, "n2", "Bash", "g1", `{"command":"echo two"}`),
		toolCompleted(4, "n2", "OUTPUT_TWO"),
	)
	return m
}

// TestFoldAffordanceTogglesFocusedPanel is the unit's DONE gate (doc 06 Layer 5):
// a collapse keystroke on the FOCUSED panel hides that panel's body ([+]) while
// its sibling keeps its bulk-Expanded state ([-]), and the redraw goes through
// RenderRich WithCollapsed (proven by a byte-identical reference render). The
// loop maintains the FoldMap across redraws, so the focused panel stays folded.
func TestFoldAffordanceTogglesFocusedPanel(t *testing.T) {
	m := twoPanelModel(t)

	var out bytes.Buffer
	app := &App{
		Out:   &out,
		Color: true,
		// Panels on + Expanded bulk default: both panels start expanded ([-]).
		Opts: RenderOpts{Panels: true, Expanded: true},
	}

	// Baseline: before any keystroke the fold set is nil (default-OFF). A draw
	// renders both panels expanded with their bodies shown.
	if app.fold != nil {
		t.Fatalf("fold set must be nil before any keystroke, got %v", *app.fold)
	}
	if err := app.draw(m); err != nil {
		t.Fatalf("baseline draw: %v", err)
	}
	if got := strings.Count(out.String(), "[-]"); got != 2 {
		t.Fatalf("baseline: expected both panels expanded ([-]), got %d:\n%s", got, out.String())
	}

	// Fold keystroke on the focused panel. Focus is unset, so it resolves to the
	// most-recent panel (n2).
	out.Reset()
	if err := app.ToggleFocusedFold(m); err != nil {
		t.Fatalf("toggle fold: %v", err)
	}

	// The FoldMap now force-collapses exactly the focused panel (n2) and nothing
	// else — the loop holds this across redraws.
	if app.fold == nil {
		t.Fatalf("a fold keystroke must create the live FoldMap")
	}
	if !(*app.fold)["n2"] {
		t.Errorf("focused panel n2 must be force-collapsed, fold=%v", *app.fold)
	}
	if (*app.fold)["n1"] {
		t.Errorf("sibling panel n1 must NOT be folded, fold=%v", *app.fold)
	}

	// The drawn surface: n2 collapsed ([+], body hidden), n1 still expanded
	// ([-], body shown) — one panel folds while its sibling keeps its state.
	s := out.String()
	if got := strings.Count(s, "[+]"); got != 1 {
		t.Errorf("expected exactly one collapsed panel ([+]), got %d:\n%s", got, s)
	}
	if got := strings.Count(s, "[-]"); got != 1 {
		t.Errorf("expected exactly one expanded panel ([-]), got %d:\n%s", got, s)
	}
	if strings.Contains(s, "OUTPUT_TWO") || strings.Contains(s, "echo two") {
		t.Errorf("collapsed focused panel n2 must hide its body:\n%s", s)
	}
	if !strings.Contains(s, "OUTPUT_ONE") || !strings.Contains(s, "echo one") {
		t.Errorf("sibling panel n1 must keep its expanded body:\n%s", s)
	}

	// RenderRich was invoked WithCollapsed: the drawn bytes equal a direct
	// RenderRich(out, m, Opts.WithCollapsed(fold)) — the exact rich path the
	// affordance promises (not Render/RenderPlain, not a bare RenderRich).
	var ref bytes.Buffer
	if err := RenderRich(&ref, m, app.Opts.WithCollapsed(app.fold)); err != nil {
		t.Fatalf("reference render: %v", err)
	}
	if !bytes.Equal(out.Bytes(), ref.Bytes()) {
		t.Errorf("draw after toggle must equal RenderRich WithCollapsed:\n--- draw ---\n%s\n--- ref ---\n%s", out.String(), ref.String())
	}

	// A second toggle on the same focused panel un-folds it: the override is
	// dropped and the panel returns to the bulk-Expanded state ([-]).
	out.Reset()
	if err := app.ToggleFocusedFold(m); err != nil {
		t.Fatalf("toggle fold (unfold): %v", err)
	}
	if (*app.fold)["n2"] {
		t.Errorf("a second toggle must un-fold n2, fold=%v", *app.fold)
	}
	if got := strings.Count(out.String(), "[-]"); got != 2 {
		t.Errorf("after un-fold both panels must be expanded ([-]), got %d:\n%s", got, out.String())
	}
}

// TestCtrlOForceExpandsBulkCollapsedPanel is the tri-state force-expand arm (doc
// 06 Layer 5), mirroring serpent-tui's fix: under --panels with Opts.Expanded
// FALSE (bulk-collapsed), the first fold keystroke must POP the focused panel
// open — not be a visible no-op. The delete-only model dropped the override and
// fell straight back to the collapsed bulk default; the force-expand model stores
// a present+FALSE entry so panelCollapsed's ForceExpanded arm shows the body. A
// second toggle prunes the override back to the bulk-collapsed default.
func TestCtrlOForceExpandsBulkCollapsedPanel(t *testing.T) {
	m := twoPanelModel(t)

	var out bytes.Buffer
	app := &App{
		Out:   &out,
		Color: true,
		// Panels on + Expanded FALSE: both panels start bulk-COLLAPSED ([+]).
		Opts: RenderOpts{Panels: true, Expanded: false},
	}

	// Baseline: no keystroke ⇒ nil fold (default-OFF). Both panels render
	// collapsed ([+], bodies hidden) under the bulk-collapsed default.
	if app.fold != nil {
		t.Fatalf("fold set must be nil before any keystroke, got %v", *app.fold)
	}
	if err := app.draw(m); err != nil {
		t.Fatalf("baseline draw: %v", err)
	}
	if got := strings.Count(out.String(), "[+]"); got != 2 {
		t.Fatalf("baseline: expected both panels collapsed ([+]), got %d:\n%s", got, out.String())
	}
	if strings.Contains(out.String(), "OUTPUT_TWO") {
		t.Fatalf("bulk-collapsed baseline must hide panel bodies:\n%s", out.String())
	}

	// First fold keystroke on the focused (most-recent, n2) panel. This is the
	// arm the delete-only model got wrong: it must FORCE-EXPAND n2, storing a
	// present+FALSE entry — NOT delete/no-op it.
	out.Reset()
	if err := app.ToggleFocusedFold(m); err != nil {
		t.Fatalf("toggle fold: %v", err)
	}
	if app.fold == nil {
		t.Fatalf("a fold keystroke must create the live FoldMap")
	}
	// The entry must be PRESENT and FALSE (force-expand), not absent (delete).
	if v, ok := (*app.fold)["n2"]; !ok || v {
		t.Errorf("focused panel n2 must have a present+false force-expand entry, fold=%v", *app.fold)
	}
	if !app.Opts.WithCollapsed(app.fold).ForceExpanded("n2") {
		t.Errorf("n2 must resolve as force-expanded, fold=%v", *app.fold)
	}
	if (*app.fold)["n1"] {
		t.Errorf("sibling panel n1 must NOT be folded, fold=%v", *app.fold)
	}

	// The drawn surface: n2 popped OPEN ([-], body shown), n1 still bulk-collapsed
	// ([+], body hidden) — the force-expand pops exactly the focused panel.
	s := out.String()
	if got := strings.Count(s, "[-]"); got != 1 {
		t.Errorf("expected exactly one force-expanded panel ([-]), got %d:\n%s", got, s)
	}
	if got := strings.Count(s, "[+]"); got != 1 {
		t.Errorf("expected exactly one still-collapsed panel ([+]), got %d:\n%s", got, s)
	}
	if !strings.Contains(s, "OUTPUT_TWO") || !strings.Contains(s, "echo two") {
		t.Errorf("force-expanded focused panel n2 must SHOW its body:\n%s", s)
	}
	if strings.Contains(s, "OUTPUT_ONE") || strings.Contains(s, "echo one") {
		t.Errorf("sibling panel n1 must stay bulk-collapsed (body hidden):\n%s", s)
	}

	// RenderRich was invoked WithCollapsed: the drawn bytes equal a direct
	// RenderRich(out, m, Opts.WithCollapsed(fold)) — the exact rich path.
	var ref bytes.Buffer
	if err := RenderRich(&ref, m, app.Opts.WithCollapsed(app.fold)); err != nil {
		t.Fatalf("reference render: %v", err)
	}
	if !bytes.Equal(out.Bytes(), ref.Bytes()) {
		t.Errorf("draw after toggle must equal RenderRich WithCollapsed:\n--- draw ---\n%s\n--- ref ---\n%s", out.String(), ref.String())
	}

	// A second toggle re-collapses n2 to the bulk default and PRUNES the override
	// (the desired collapsed state already IS the bulk default), leaving a clean
	// empty fold set — no redundant force-collapse entry.
	out.Reset()
	if err := app.ToggleFocusedFold(m); err != nil {
		t.Fatalf("toggle fold (re-collapse): %v", err)
	}
	if _, ok := (*app.fold)["n2"]; ok {
		t.Errorf("a second toggle must PRUNE n2 back to the bulk default, fold=%v", *app.fold)
	}
	if got := strings.Count(out.String(), "[+]"); got != 2 {
		t.Errorf("after re-collapse both panels must be collapsed ([+]), got %d:\n%s", got, out.String())
	}
	if strings.Contains(out.String(), "OUTPUT_TWO") {
		t.Errorf("re-collapsed n2 must hide its body again:\n%s", out.String())
	}
}

// TestFoldFocusNavigation: FocusPrev/FocusNext pick WHICH panel a fold keystroke
// targets without changing any panel's fold state on their own, so after moving
// focus to the sibling the toggle folds THAT panel while the most-recent one
// stays expanded.
func TestFoldFocusNavigation(t *testing.T) {
	m := twoPanelModel(t)
	var out bytes.Buffer
	app := &App{Out: &out, Color: true, Opts: RenderOpts{Panels: true, Expanded: true}}

	// Move focus from the default (most-recent n2) back to the sibling n1.
	app.FocusPrev(m)
	// Focus navigation must not have created/mutated any fold state.
	if app.fold != nil {
		t.Fatalf("focus navigation must not touch fold state, got %v", *app.fold)
	}

	if err := app.ToggleFocusedFold(m); err != nil {
		t.Fatalf("toggle fold: %v", err)
	}
	if !(*app.fold)["n1"] {
		t.Errorf("after FocusPrev the toggle must fold n1, fold=%v", *app.fold)
	}
	if (*app.fold)["n2"] {
		t.Errorf("n2 must stay unfolded, fold=%v", *app.fold)
	}
	s := out.String()
	if strings.Contains(s, "OUTPUT_ONE") || strings.Contains(s, "echo one") {
		t.Errorf("collapsed n1 must hide its body:\n%s", s)
	}
	if !strings.Contains(s, "OUTPUT_TWO") {
		t.Errorf("n2 must keep its expanded body:\n%s", s)
	}
}

// TestFoldDefaultOffByteIdentical: the default-OFF contract — with no render
// enrichment and no fold keystroke, draw routes to Render BYTE-IDENTICALLY to a
// pre-affordance loop. A fold keystroke is a no-op when panels are not enabled,
// so the bulk render stays byte-unchanged.
func TestFoldDefaultOffByteIdentical(t *testing.T) {
	m := twoPanelModel(t)

	// Zero Opts (no Panels), color on: draw must equal plain Render exactly.
	var drawn, ref bytes.Buffer
	app := &App{Out: &drawn, Color: true} // zero Opts
	if err := app.draw(m); err != nil {
		t.Fatalf("draw: %v", err)
	}
	if err := Render(&ref, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.Equal(drawn.Bytes(), ref.Bytes()) {
		t.Errorf("zero-Opts draw must be byte-identical to Render:\n--- draw ---\n%s\n--- Render ---\n%s", drawn.String(), ref.String())
	}

	// A fold keystroke with panels OFF is inert: no draw, no fold set, bulk render
	// unchanged. Re-draw and confirm it still equals Render.
	if err := app.ToggleFocusedFold(m); err != nil {
		t.Fatalf("toggle with panels off: %v", err)
	}
	if app.fold != nil {
		t.Errorf("a fold keystroke with --panels off must not create a fold set, got %v", *app.fold)
	}
	drawn.Reset()
	if err := app.draw(m); err != nil {
		t.Fatalf("redraw: %v", err)
	}
	if !bytes.Equal(drawn.Bytes(), ref.Bytes()) {
		t.Errorf("after an inert fold keystroke the bulk render must stay byte-unchanged:\n%s", drawn.String())
	}
}

// TestReaderSeatHasNoWriter: a RoleReader handle gets no Writer — readers never
// forward input (D61 one-writer/N-reader; arbitration is server-side).
func TestReaderSeatHasNoWriter(t *testing.T) {
	tr := &LocalTransport{Reader: strings.NewReader("")}
	_, w, err := tr.Open(AttachHandle{Role: RoleReader}, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if w != nil {
		t.Errorf("RoleReader must not receive a Writer")
	}
	_, w, err = tr.Open(AttachHandle{Role: RoleWriter}, 0)
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	if w == nil {
		t.Errorf("RoleWriter must receive a Writer")
	}
}
