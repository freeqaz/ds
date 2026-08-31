package tui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// app.go is the interactive writer-seat loop for a LIVE attach: it consumes the
// event stream off a Transport, folds it into the Model, redraws the structured
// surface, prompts on pending asks, and forwards writer-seat input through the
// wrapper Writer (D18 — input goes to CC stdin via the wrapper, never to a
// frame buffer). The one-writer/N-reader seat is arbitrated SERVER-side (doc 15
// §5.3); this loop forwards input only when it holds a Writer (RoleWriter) and
// never arbitrates the seat itself.
//
// NOTE — live attach to a real remote CC session is the integration step that
// waits on the orchestrator (the WatchSession leg, D79/doc 15 §5.4). This loop
// is wired and unit-shaped against the local Transport; the remote leg is a
// second Transport, not a change here. It is deliberately NOT exercised
// end-to-end in the sandbox.

// App wires a Transport, a Model, and the operator I/O for an interactive
// session. Out is the render target (a TTY); In is operator keystrokes/lines.
type App struct {
	Transport Transport
	Handle    AttachHandle
	Out       io.Writer
	In        io.Reader
	// Color selects the styled renderer; false uses the plain golden surface.
	Color bool

	// Opts carries the Phase-2 structured-render enrichments (doc 06 Layers
	// 2/3/5). The ZERO value selects NO enrichment, so an App that never sets it
	// renders byte-identically to the pre-Phase-2 loop: draw routes to
	// Render/RenderPlain exactly as before unless an enrichment is requested.
	// The interactive fold affordance (below) is the ONLY thing that mutates the
	// rendered state from a keystroke, and it does so only when panels are on.
	Opts RenderOpts

	// fold is the live per-panel fold-override set the loop maintains ACROSS
	// redraws (doc 06 Layer 5): a keystroke toggles the focused panel's entry,
	// and every subsequent draw re-applies it via Opts.WithCollapsed(fold). It is
	// lazily created on the first toggle, so the default (no keystroke) is a nil
	// override == the bulk-default render — byte-unchanged. It is never persisted
	// (it is pure view state, not approval/grant state).
	fold *FoldMap

	// focus selects which tool panel a fold keystroke targets, as an index into
	// m.ToolPanels() (the stable first-invoked order). The ZERO value is the
	// "unset" sentinel that resolves to the most-recent panel (the natural focus
	// in a live transcript); the first FocusPrev/FocusNext seeds it off that
	// resolved position, after which it is an explicit 0-based index. It is inert
	// until ToolPanels() is non-empty.
	focus    int
	focusSet bool
}

// askAnswerer is the subset of Writer the ask-prompt flow needs; split out so
// the prompt loop is testable without a transport.
type askAnswerer interface {
	AnswerAsk(askID string, d Decision) error
}

// Run opens the stream and folds events until EOF, redrawing after each event
// and handling pending asks via promptAsk. It resumes at Handle's implied
// fromSeq of 0 (a re-attach would pass the last durably-rendered Seq). Input
// forwarding for free-form lines is handled by the caller's driver in a real
// terminal; Run focuses on the event fold + ask flow, the parts with contract
// semantics. Returns the final Model.
//
// The interactive [+]/[-] fold affordance (doc 06 Layer 5) is maintained ACROSS
// these redraws: a.fold (the loop's live FoldMap) is App state, so every
// a.draw(m) below re-applies it through draw → RenderRich(out, m,
// Opts.WithCollapsed(a.fold)). The fold KEYSTROKE itself is dispatched by the
// real-terminal driver, which selects between event arrival and operator keys
// and calls a.ToggleFocusedFold(m) / a.FocusPrev(m) / a.FocusNext(m) — exactly
// like free-form input forwarding, this loop owns the event fold + ask flow, not
// the raw-key multiplexing (that lives in the driver, kept out of this
// stdlib-only contract surface and not exercised end-to-end in the sandbox).
// Until a key arrives a.fold stays nil, so draw routes byte-identically to the
// pre-affordance loop (default-OFF: no keystroke ⇒ byte-unchanged bulk render).
func (a *App) Run() (*Model, error) {
	stream, writer, err := a.Transport.Open(a.Handle, 0)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	m := NewModel()
	in := bufio.NewReader(a.In)

	for {
		ev, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, err
		}
		if err := m.Apply(ev); err != nil {
			return m, err
		}
		if err := a.draw(m); err != nil {
			return m, err
		}
		// A pending ask PARKS the session (D53/D77): block here for a human
		// decision rather than continuing. Unanswered ⇒ stays parked; we never
		// time out into allow or kill.
		for _, ask := range m.PendingAsks() {
			if err := a.promptAsk(m, writer, in, ask); err != nil {
				return m, err
			}
		}
	}
	return m, a.draw(m)
}

// draw renders the current model to Out. With the default (zero) Opts and no
// fold override it routes to Render/RenderPlain EXACTLY as the pre-Phase-2 loop
// did, so a loop that never enables enrichment and receives no fold keystroke
// produces byte-identical output. Enrichment (any Opts flag) or an active fold
// override (a keystroke happened) routes through RenderRich with the loop's
// live FoldMap applied — RenderPlain is never enriched (doc 06 §4.2), so the
// plain surface ignores both Opts and the fold set.
func (a *App) draw(m *Model) error {
	if !a.Color {
		// The plain golden surface is never enriched or folded (doc 06 §4.2).
		return RenderPlain(a.Out, m)
	}
	opts := a.Opts.WithCollapsed(a.fold)
	if opts.isZero() {
		// No enrichment and no fold override ⇒ the byte-identical baseline.
		return Render(a.Out, m)
	}
	return RenderRich(a.Out, m, opts)
}

// ToggleFocusedFold flips the fold state of the FOCUSED tool panel (doc 06
// Layer 5) and re-renders. It resolves the focused panel's NodeID from
// m.ToolPanels(), flips its entry in the loop's live FoldMap (collapse<->expand,
// relative to the bulk Opts.Expanded default), and redraws via
// RenderRich(out, m, Opts.WithCollapsed(fold)) — so that one panel folds while
// its siblings keep their bulk-Expanded state. It is a no-op (and draws nothing)
// when there are no panels OR panels are not enabled: folding is a Layer-5
// affordance, so without --panels there is nothing to fold and the bulk render
// is left byte-unchanged. The real terminal driver calls this on the fold
// keystroke (Ctrl-O); the loop never folds on its own, preserving the default-OFF
// (no-keystroke ⇒ byte-unchanged) contract.
func (a *App) ToggleFocusedFold(m *Model) error {
	if !a.Opts.Panels {
		return nil // folding is a Layer-5 panel affordance; nothing to fold.
	}
	panel := a.focusedPanel(m)
	if panel == nil {
		return nil // no tool panels yet — nothing to fold.
	}
	if a.fold == nil {
		a.fold = NewFoldMap()
	}
	// Flip RELATIVE to the resolved render state, so the first keystroke always
	// changes what the operator sees: if the panel currently renders collapsed we
	// want it expanded, and vice-versa. The FoldMap is TRI-STATE (render.go): a
	// present+true entry force-COLLAPSES, a present+false entry force-EXPANDS, and
	// an absent entry INHERITS the bulk Opts.Expanded default. So a false entry IS
	// meaningful (force-expand) — this is what pops a --panels bulk-collapsed
	// (Expanded:false) panel open on the first Ctrl-O, where the delete-only model
	// was a visible no-op (dropping the override fell straight back to the
	// collapsed bulk default). We store the explicit override only when it differs
	// from the bulk default; when the desired state already IS the bulk default we
	// PRUNE the entry, so a second toggle returns the panel to the bulk render with
	// a clean (empty) override rather than a redundant one.
	resolved := a.Opts.WithCollapsed(a.fold).panelCollapsed(panel.NodeID)
	want := !resolved             // the collapsed state we want after this flip
	if want == !a.Opts.Expanded { // desired state == bulk default ⇒ no override
		delete(*a.fold, panel.NodeID)
	} else {
		(*a.fold)[panel.NodeID] = want // force-collapse (true) or force-expand (false)
	}
	return a.draw(m)
}

// FocusPrev / FocusNext move the fold focus across the tool panels (the stable
// m.ToolPanels() order), clamped to the panel range. They let the operator pick
// WHICH panel a fold keystroke targets without touching any panel's fold state,
// so they never change the rendered bytes on their own (the caller redraws only
// on an actual fold toggle). The first move seeds focus off the resolved
// position (the most-recent panel) so navigation starts where the eye is. Inert
// with no panels.
func (a *App) FocusPrev(m *Model) { a.moveFocus(m, -1) }
func (a *App) FocusNext(m *Model) { a.moveFocus(m, +1) }

func (a *App) moveFocus(m *Model, delta int) {
	n := len(m.ToolPanels())
	if n == 0 {
		return
	}
	a.focus = clampFocus(a.resolvedFocus(m)+delta, n)
	a.focusSet = true
}

// resolvedFocus is the effective focus index: the explicit focus once set,
// otherwise the most-recent panel (len-1). Callers must ensure n > 0.
func (a *App) resolvedFocus(m *Model) int {
	n := len(m.ToolPanels())
	if !a.focusSet {
		return n - 1 // unset ⇒ the most-recent panel.
	}
	return clampFocus(a.focus, n) // clamp in case panels streamed away from it.
}

// focusedPanel resolves the currently focused tool panel, defaulting to the
// most-recent panel (the natural focus in a live transcript) when focus has not
// been moved yet. Returns nil when there are no panels.
func (a *App) focusedPanel(m *Model) *toolPair {
	panels := m.ToolPanels()
	if len(panels) == 0 {
		return nil
	}
	return panels[a.resolvedFocus(m)]
}

// clampFocus keeps a focus index within [0, n).
func clampFocus(i, n int) int {
	if i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}

// promptAsk renders the approval prompt for one ask and reads the operator's
// decision. The three options are D45's escape-hatch one-offs: allow-once
// (dies with the session), allow-always (a PROPOSAL for org-admin acceptance —
// the client never stores a grant), deny. An unanswered ask (empty/closed
// input) leaves the ask pending and the session parked; it never defaults to
// allow or kill (D53/D77). The chosen decision is recorded on the model and
// forwarded through the wrapper Writer — never persisted client-side.
func (a *App) promptAsk(m *Model, writer askAnswerer, in *bufio.Reader, ask *Ask) error {
	fmt.Fprintf(a.Out, "\nASK %s — %s\n", ask.AskID, ask.ToolName)
	fmt.Fprintf(a.Out, "  [1] allow once (dies with session)\n")
	fmt.Fprintf(a.Out, "  [2] allow always (PROPOSAL — requires org-admin acceptance)\n")
	fmt.Fprintf(a.Out, "  [3] deny\n")
	fmt.Fprintf(a.Out, "  (no answer parks the session; it never times out into allow or kill)\n")
	fmt.Fprintf(a.Out, "decision> ")

	line, err := in.ReadString('\n')
	if errors.Is(err, io.EOF) && strings.TrimSpace(line) == "" {
		// No decision: session stays parked. Not an error.
		fmt.Fprintf(a.Out, "\n(no decision — session parked on ask %s)\n", ask.AskID)
		return nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	d, ok := parseDecision(strings.TrimSpace(line))
	if !ok {
		// Unrecognized: leave parked rather than guessing a grant.
		fmt.Fprintf(a.Out, "(unrecognized — session stays parked on ask %s)\n", ask.AskID)
		return nil
	}

	if _, err := m.AnswerAsk(ask.AskID, d); err != nil {
		return err
	}
	if writer != nil {
		if err := writer.AnswerAsk(ask.AskID, d); err != nil {
			return err
		}
	}
	if d.IsProposal() {
		fmt.Fprintf(a.Out, "(submitted allow-always as a proposal for org-admin acceptance — no grant stored)\n")
	}
	return nil
}

// parseDecision maps operator input to a Decision. Accepts the menu numbers
// and the decision words; anything else is unrecognized (parks).
func parseDecision(s string) (Decision, bool) {
	switch strings.ToLower(s) {
	case "1", "allow-once", "once", "allow":
		return DecisionAllowOnce, true
	case "2", "allow-always", "always", "proposal":
		return DecisionAllowAlways, true
	case "3", "deny", "no":
		return DecisionDeny, true
	default:
		return "", false
	}
}
