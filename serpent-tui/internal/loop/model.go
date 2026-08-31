package loop

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/dream-serpent/dream-serpent/client/tui"
)

// model.go is the THIN bubbletea adapter over the pure loop State. bubbletea
// enters serpent-tui ONLY here (and the cmd entrypoint) — the ratified
// Option-C boundary: client/ stays stdlib-only, the interactive runtime lives in
// this out-of-go.work module. Update routes keystrokes onto State's composer/ask
// methods and folds streamed events; View delegates to State.View. The state
// machine is bubbletea-free (state.go) and unit-tested directly; this adapter is
// exercised at the cmd entrypoint against the in-process fake server.

// RedrawMsg wakes the bubbletea Update loop to re-render after the subscriber
// goroutine has FOLDED an event into the shared loop State (the fold happens in
// the subscriber, under State's lock, so the seq-ordered Model has exactly one
// writer and st.LastSeq() is accurate at resume time, D79). Update does nothing
// but trigger a View; it never mutates the Model. A zero-field message keeps the
// wake cheap.
type RedrawMsg struct{}

// StreamEndMsg signals the WatchSession subscriber has ended (clean drain, ctx
// cancel, or a terminal status). The model quits the bubbletea program on it. Err
// is the terminal cause (nil on a clean end, or a fatal fold error P10/D79 the
// subscriber surfaced).
type StreamEndMsg struct{ Err error }

// Model is the bubbletea.Model adapter. It owns one loop.State, a Color flag, and
// the Phase-2 render enrichments (doc serpent-cli-mvp/06). Construct with NewModel.
type Model struct {
	state *State
	color bool
	// opts gates the Phase-2 RenderRich enrichments (Layer-2 diffs / Layer-3
	// highlight / Layer-5 panels, and the panel fold state). A zero RenderOpts is
	// byte-identical to the bare Render/RenderPlain surface — the enrichment is
	// strictly additive and OFF by default, so the interactive UX is unchanged
	// unless a toggle is turned on. It is seeded from the environment (the disjoint
	// wiring leg: `serpent claude --vm` sets DS_TUI_* on the exec'd serpent-tui so
	// the flags reach this loop without coupling app.go / the cmd to the options),
	// and the panel fold keys (Ctrl-O/P/N) drive its per-NodeID fold map live.
	opts tui.RenderOpts
	// focusNodeID is the NodeID of the tool panel the per-panel fold keys act on
	// (Ctrl-O toggles its collapse; Ctrl-P/Ctrl-N move the focus across the live
	// panel set). It is empty until the operator first moves focus (or the focused
	// panel scrolls out of the live set), in which case Ctrl-O degrades to the v1
	// global Expanded flip — so a session that never moves focus behaves exactly as
	// the v1 global fold did. It is render-irrelevant (only the keystroke handler
	// reads it), so it does not enter RenderOpts.
	focusNodeID string
	// finalErr is the terminal cause recorded when the program quits (a stream
	// end, a fatal fold error P10/D79, or a clean operator quit ⇒ nil); FinalErr
	// surfaces it to the caller after Program.Run.
	finalErr error
}

// NewModel wires a bubbletea Model over a loop State. color selects the styled
// renderer (an interactive TTY) vs the plain golden surface. The Phase-2 render
// enrichments default OFF and are seeded from the environment (RenderOptsFromEnv)
// so the existing NewModel(state, color) call sites stay unchanged while the
// `serpent claude --vm` flags still reach the live loop; SetRenderOpts overrides
// them for an in-process caller that builds the opts directly.
func NewModel(state *State, color bool) *Model {
	opts := RenderOptsFromEnv()
	// --no-color (DS_TUI_NO_COLOR) routes to the byte-stable plain surface: it
	// forces color off here, exactly as the cmd --color flag would.
	if envNoColor() {
		color = false
	}
	return &Model{state: state, color: color, opts: opts}
}

// SetRenderOpts overrides the Phase-2 render enrichments selected for this model
// (replacing the env-seeded defaults). It is the additive seam an in-process
// caller uses to drive RenderRich without the DS_TUI_* env relay; the cmd path
// reaches the same options through the environment. A zero RenderOpts restores
// the byte-identical baseline.
func (m *Model) SetRenderOpts(opts tui.RenderOpts) { m.opts = opts }

// RenderOpts returns the Phase-2 render enrichments currently selected (the live
// opts, including any panel fold state toggled by the fold key).
func (m *Model) RenderOpts() tui.RenderOpts { return m.opts }

// Init is the first bubbletea call — no initial command (events are pushed in by
// the subscriber goroutine via Program.Send).
func (m *Model) Init() tea.Cmd { return nil }

// Update routes one bubbletea Msg onto the loop State:
//   - RedrawMsg: the subscriber folded an event — re-render (no Model mutation
//     here; the fold already happened in the subscriber goroutine);
//   - StreamEndMsg: the subscription ended (or a fatal fold error, P10/D79) —
//     quit with its cause;
//   - KeyMsg: a keystroke — drive the composer, submit input (Enter), answer a
//     pending ask (the a/A/d keys when parked), or quit (Ctrl+C / Ctrl+D).
//
// Input/ask FORWARD failures are non-fatal (recorded on State.lastErr, shown in
// View); only a stream end / fatal fold quits.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case RedrawMsg:
		return m, nil // re-render only; the fold happened in the subscriber
	case StreamEndMsg:
		m.finalErr = msg.Err
		return m, tea.Quit
	case tea.KeyMsg:
		return m.handleKey(msg)
	default:
		return m, nil
	}
}

// handleKey maps a keystroke onto a State action. The approval keys (a/A/d) only
// act when the session is PARKED on a pending ask; otherwise every printable rune
// composes input and Enter submits it. Ctrl+C / Ctrl+D quit. The Layer-5 fold keys
// drive the per-NodeID tool-panel fold (doc 06 Layer 5): Ctrl+P / Ctrl+N move the
// focus across the live panel set, and Ctrl+O toggles the FOCUSED panel's collapse
// (degrading to the v1 global Expanded flip when no panel is focused). None of the
// fold keys are printable runes, so none can land in the input line.
func (m *Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.Type {
	case tea.KeyCtrlC, tea.KeyCtrlD:
		// A clean operator quit: finalErr stays nil (not an error).
		return m, tea.Quit
	case tea.KeyCtrlO:
		// Panel fold: toggle the FOCUSED panel's per-NodeID collapse if one is in
		// focus (and still in the live panel set), else degrade to the v1 global
		// Expanded flip. With panels off (the default) and no focus this is inert —
		// RenderRich ignores Expanded unless Panels is on — so it never disturbs a
		// session that did not opt into panels. Ctrl+O is a control key, never a
		// printable rune, so it cannot land in the input line.
		m.toggleFocusedFold()
		return m, nil
	case tea.KeyCtrlP:
		// Move the panel focus to the PREVIOUS tool panel (wraps). A no-op with no
		// panels; it never composes (Ctrl+P is a control key).
		m.moveFocus(-1)
		return m, nil
	case tea.KeyCtrlN:
		// Move the panel focus to the NEXT tool panel (wraps). A no-op with no
		// panels; it never composes (Ctrl+N is a control key).
		m.moveFocus(+1)
		return m, nil
	case tea.KeyEnter:
		_, _ = m.state.SubmitInput()
		return m, nil
	case tea.KeyBackspace:
		m.state.Backspace()
		return m, nil
	case tea.KeySpace:
		m.state.TypeRune(' ')
		return m, nil
	case tea.KeyRunes:
		// When parked on an ask, the single-key approval shortcuts take priority
		// over composing (the human is being asked to decide, D53). Otherwise the
		// runes compose the input line.
		if m.state.Parked() && len(k.Runes) == 1 {
			if d, ok := approvalKey(k.Runes[0]); ok {
				_, _ = m.state.AnswerPending(d)
				return m, nil
			}
		}
		for _, r := range k.Runes {
			m.state.TypeRune(r)
		}
		return m, nil
	default:
		return m, nil
	}
}

// panelNodeIDs returns the NodeIDs of the live tool panels in stable
// first-invoked order (the same order the renderer folds them, ToolPanels). It
// reads the folded client/tui Model UNDER the loop lock — the keystroke handler
// runs in the bubbletea Update goroutine while the watch subscriber folds events
// via State.Apply in a separate goroutine (app.go), so the read of the Model's
// tool set must hold State.mu exactly as View/PendingAsks/Parked do; reaching
// through the bare Model() accessor without the lock would race the concurrent
// fold (the documented one-writer-under-lock invariant, D79). The returned slice
// is a snapshot the handler indexes into for focus moves; with no tool panels yet
// it is empty (the keystrokes are then no-ops / the global flip).
func (m *Model) panelNodeIDs() []string {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	panels := m.state.model.ToolPanels()
	ids := make([]string, 0, len(panels))
	for _, p := range panels {
		ids = append(ids, p.NodeID)
	}
	return ids
}

// moveFocus advances the per-panel focus by delta (+1 next / -1 previous) over the
// live panel set, wrapping at the ends. With no panels it clears the focus and is a
// no-op. If the previously-focused panel has scrolled out of the live set the move
// restarts from the first (delta>0) or last (delta<0) panel, so the focus never
// points at a stale NodeID. It mutates only focusNodeID — the render is unchanged
// until Ctrl-O folds the focused panel.
func (m *Model) moveFocus(delta int) {
	ids := m.panelNodeIDs()
	if len(ids) == 0 {
		m.focusNodeID = ""
		return
	}
	cur := indexOf(ids, m.focusNodeID)
	if cur < 0 {
		// No live focus yet (or it scrolled away): step in from the appropriate end.
		if delta > 0 {
			m.focusNodeID = ids[0]
		} else {
			m.focusNodeID = ids[len(ids)-1]
		}
		return
	}
	next := ((cur+delta)%len(ids) + len(ids)) % len(ids) // wrap (Go % keeps the sign)
	m.focusNodeID = ids[next]
}

// toggleFocusedFold flips the FOCUSED panel's per-NodeID fold override when a
// live panel is in focus, else degrades to the v1 global Expanded flip. It flips
// RELATIVE to the panel's resolved render state (the tri-state override layered
// over the bulk Expanded default, doc 06 Layer 5) — so the FIRST Ctrl-O always
// changes what the operator sees, even under the common `--panels`
// (Expanded:false, bulk-collapsed) default. It takes the relative-flip idea from
// client/tui App.ToggleFocusedFold but goes BEYOND that reference: the App models
// expand only by DELETING the entry (never a false value), so it still no-ops on
// a bulk-collapsed panel — do not "re-align" this to the App without porting the
// force-expand arm there first:
//
//   - if the focused panel currently RESOLVES COLLAPSED (bulk-collapsed, or an
//     existing force-collapse override), store a FORCE-EXPAND override
//     (Collapsed[NodeID]=false) so it pops OPEN — the arm that fixes the prior
//     "only ever set true / delete" no-op on an already-folded panel;
//   - if it currently RESOLVES EXPANDED (bulk-expanded, or an existing
//     force-expand override), store a FORCE-COLLAPSE override
//     (Collapsed[NodeID]=true) so it folds.
//
// The tri-state is carried by presence+value in the FoldMap (true=force-collapse,
// false=force-expand), consumed by RenderRich via panelCollapsed. The map is
// allocated lazily behind the RenderOpts pointer (so RenderOpts stays comparable);
// any override entry that merely re-asserts the bulk default is pruned, and when
// the last override is removed the map drops back to nil — the no-override
// baseline, byte-identical to the prior global-Expanded behavior.
func (m *Model) toggleFocusedFold() {
	if m.focusNodeID == "" || indexOf(m.panelNodeIDs(), m.focusNodeID) < 0 {
		// No focused panel (or it scrolled out): the v1 global fold.
		m.opts.Expanded = !m.opts.Expanded
		return
	}
	if m.opts.Collapsed == nil {
		fm := make(tui.FoldMap)
		m.opts.Collapsed = &fm
	}
	fm := *m.opts.Collapsed
	// Resolve the effective fold BEFORE the flip: a force-collapse override
	// (IsCollapsed) or force-expand override (ForceExpanded) wins over the bulk
	// Expanded default; absent both, the panel inherits the bulk default (collapsed
	// unless Expanded). This mirrors render.go's panelCollapsed via the exported
	// accessors (panelCollapsed is unexported / cross-module).
	nodeID := m.focusNodeID
	resolvedCollapsed := m.opts.IsCollapsed(nodeID) ||
		(!m.opts.ForceExpanded(nodeID) && !m.opts.Expanded)
	if resolvedCollapsed {
		// Currently collapsed ⇒ pop it OPEN with a force-expand override, UNLESS the
		// bulk default already expands it inheriting (Expanded true would not reach
		// here) — so store false to override the collapsed default.
		fm[nodeID] = false
	} else {
		// Currently expanded ⇒ fold it with a force-collapse override.
		fm[nodeID] = true
	}
	// Prune an override that merely re-asserts the bulk default (force-collapse
	// under a bulk-collapsed default, or force-expand under a bulk-expanded
	// default): it is a redundant INHERIT, so drop it back to absence. This keeps a
	// fully-inherited session comparable to the zero RenderOpts.
	if v, ok := fm[nodeID]; ok && v == !m.opts.Expanded {
		delete(fm, nodeID)
	}
	// Drop an emptied override map back to the nil no-override baseline so a
	// fully-unfolded session compares equal to the zero RenderOpts again.
	if len(fm) == 0 {
		m.opts.Collapsed = nil
	}
}

// indexOf returns the position of id in ids, or -1 if absent.
func indexOf(ids []string, id string) int {
	for i, v := range ids {
		if v == id {
			return i
		}
	}
	return -1
}

// approvalKey maps an approval shortcut rune onto a tui.Decision (D45 escape-hatch
// one-offs): 'a' allow-once, 'A' allow-always (a PROPOSAL for org-admin
// acceptance — the client stores no grant), 'd' deny. Any other rune is not an
// approval key (it composes instead).
func approvalKey(r rune) (tui.Decision, bool) {
	switch r {
	case 'a':
		return tui.DecisionAllowOnce, true
	case 'A':
		return tui.DecisionAllowAlways, true
	case 'd':
		return tui.DecisionDeny, true
	default:
		return "", false
	}
}

// View renders the surface (delegates to State.View, passing the live Phase-2
// render options + the panel fold state).
func (m *Model) View() string { return m.state.View(m.color, m.opts) }

// FinalErr returns the terminal cause after the program has quit (nil on a clean
// end). The cmd entrypoint surfaces it as the process exit status.
func (m *Model) FinalErr() error { return m.finalErr }
