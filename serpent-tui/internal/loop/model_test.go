// SPDX-License-Identifier: Apache-2.0

package loop

import (
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/dream-serpent/dream-serpent/client/tui"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// clearTUIEnv neutralizes any ambient DS_TUI_* vars so a model built in this test
// starts from the zero RenderOpts regardless of the runner's environment (the
// per-NodeID fold assertions compare against the zero baseline). t.Setenv restores
// the prior values at test end.
func clearTUIEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{envDiffs, envHighlight, envPanels, envExpanded, envContextRadius, envNoColorVar} {
		t.Setenv(name, "")
	}
}

// toolEvent is a folded ToolInvoked — the event that surfaces a Layer-5 tool
// panel keyed on NodeID (the join key the per-NodeID fold acts on). Seq must be
// monotone across a test's apply sequence (P10/D79).
func toolEvent(seq uint64, nodeID, name string) attach.Event {
	return attach.Event{
		Seq:         seq,
		Type:        attach.TypeToolInvoked,
		ToolInvoked: &attach.ToolInvoked{NodeID: nodeID, Name: name, TurnGroup: "t1"},
	}
}

// modelWithPanels builds a Model whose folded State already has the named tool
// panels surfaced (in first-invoked order), the substrate the per-NodeID fold
// keystrokes act on. It drives the keystroke handler directly (no live run).
func modelWithPanels(t *testing.T, nodeIDs ...string) *Model {
	t.Helper()
	clearTUIEnv(t)
	m := NewModel(New(nil), true)
	for i, id := range nodeIDs {
		mustApply(t, m.state, toolEvent(uint64(i+1), id, "Edit"))
	}
	// The panels must be visible to the keystroke handler in stable order.
	if got := m.panelNodeIDs(); len(got) != len(nodeIDs) {
		t.Fatalf("panelNodeIDs() = %v, want %d panels %v", got, len(nodeIDs), nodeIDs)
	}
	return m
}

// keyCtrl drives one control keystroke through the bubbletea Update (the live
// dispatch path), returning the updated Model.
func keyCtrl(m *Model, t tea.KeyType) *Model {
	next, _ := m.Update(tea.KeyMsg{Type: t})
	return next.(*Model)
}

// TestCtrlPCtrlNMoveFocusOverPanels proves Ctrl-N / Ctrl-P move the per-panel
// focus across the live ToolPanels in stable order and wrap at the ends — the
// real collapsible-per-tool affordance reaching a live operator (not just a
// direct method call). With no prior focus, Ctrl-N steps in from the first panel
// and Ctrl-P from the last.
func TestCtrlPCtrlNMoveFocusOverPanels(t *testing.T) {
	m := modelWithPanels(t, "n1", "n2", "n3")

	// No focus yet ⇒ Ctrl-N steps in from the FIRST panel.
	m = keyCtrl(m, tea.KeyCtrlN)
	if m.focusNodeID != "n1" {
		t.Fatalf("first Ctrl-N focus = %q, want n1", m.focusNodeID)
	}
	m = keyCtrl(m, tea.KeyCtrlN)
	if m.focusNodeID != "n2" {
		t.Fatalf("Ctrl-N focus = %q, want n2", m.focusNodeID)
	}
	// Ctrl-P moves back.
	m = keyCtrl(m, tea.KeyCtrlP)
	if m.focusNodeID != "n1" {
		t.Fatalf("Ctrl-P focus = %q, want n1", m.focusNodeID)
	}
	// Ctrl-P wraps from the first panel to the LAST.
	m = keyCtrl(m, tea.KeyCtrlP)
	if m.focusNodeID != "n3" {
		t.Fatalf("Ctrl-P wrap focus = %q, want n3 (last)", m.focusNodeID)
	}
	// Ctrl-N wraps from the last panel back to the FIRST.
	m = keyCtrl(m, tea.KeyCtrlN)
	if m.focusNodeID != "n1" {
		t.Fatalf("Ctrl-N wrap focus = %q, want n1 (first)", m.focusNodeID)
	}
	// Focus moves never touch the render options or compose into the input line.
	if got := m.RenderOpts(); got != (tui.RenderOpts{}) {
		t.Errorf("focus moves changed RenderOpts = %+v, want zero (focus is render-irrelevant)", got)
	}
	if got := m.state.Compose(); got != "" {
		t.Errorf("focus keys composed into input: %q", got)
	}
}

// TestCtrlOTogglesFocusedPanelFold proves Ctrl-O flips ONLY the focused panel's
// per-NodeID fold override RELATIVE to its resolved render state, and that toggling
// it back off drops the override map to nil (the no-override baseline byte-identical
// to the prior global-Expanded behavior). Under a bulk-collapsed default
// (Expanded:false, the common --panels case) the FIRST Ctrl-O pops the panel OPEN
// via a force-expand override (Collapsed[NodeID]=false) — the arm that fixes the
// prior no-op on an already-folded panel — and a second Ctrl-O re-collapses it.
func TestCtrlOTogglesFocusedPanelFold(t *testing.T) {
	m := modelWithPanels(t, "n1", "n2")

	// Focus n2, then fold it.
	m = keyCtrl(m, tea.KeyCtrlN) // n1
	m = keyCtrl(m, tea.KeyCtrlN) // n2
	if m.focusNodeID != "n2" {
		t.Fatalf("focus = %q, want n2", m.focusNodeID)
	}
	m = keyCtrl(m, tea.KeyCtrlO)
	opts := m.RenderOpts()
	// Bulk default is collapsed (Expanded:false), so the first Ctrl-O pops n2 OPEN
	// via a FORCE-EXPAND override — not a force-collapse (which would be a no-op).
	if !opts.ForceExpanded("n2") {
		t.Errorf("first Ctrl-O on a bulk-collapsed panel should force n2 EXPANDED (Collapsed[n2]=false)")
	}
	if opts.IsCollapsed("n2") {
		t.Errorf("first Ctrl-O must not force-collapse an already-collapsed panel (the prior no-op)")
	}
	if opts.IsCollapsed("n1") || opts.ForceExpanded("n1") {
		t.Errorf("Ctrl-O must not touch the unfocused panel n1")
	}
	// The global Expanded flag is untouched — this is a per-panel override, not the
	// v1 global flip.
	if opts.Expanded {
		t.Errorf("per-panel fold must not flip the global Expanded flag")
	}

	// Toggling the same panel again re-collapses it back to the bulk default and
	// drops the map to nil, so the model compares equal to the zero RenderOpts again.
	m = keyCtrl(m, tea.KeyCtrlO)
	if got := m.RenderOpts(); got != (tui.RenderOpts{}) {
		t.Errorf("re-collapsing to the bulk default must restore the zero RenderOpts, got %+v", got)
	}
}

// TestCtrlOForceExpandsBulkCollapsedPanel is the acceptance case for the
// force-expand arm: under the common `--panels` default (Panels:true,
// Expanded:false ⇒ every panel bulk-COLLAPSED), the FIRST Ctrl-O on a focused panel
// must POP IT OPEN by storing a force-expand override (Collapsed[NodeID]=false), so
// it renders expanded against the bulk-collapsed default — instead of the prior
// behavior that only ever set true/deleted (a no-op on an already-folded panel). A
// subsequent Ctrl-O must re-COLLAPSE it back to the bulk default. This mirrors the
// relative-flip in client/tui App.ToggleFocusedFold.
func TestCtrlOForceExpandsBulkCollapsedPanel(t *testing.T) {
	m := modelWithPanels(t, "n1", "n2")
	// The common --panels default: panels ON, bulk default COLLAPSED.
	m.SetRenderOpts(tui.RenderOpts{Panels: true, Expanded: false})

	// Precondition: with no override, n2 resolves COLLAPSED (bulk default).
	if m.RenderOpts().ForceExpanded("n2") || m.RenderOpts().IsCollapsed("n2") {
		t.Fatalf("precondition: n2 should inherit the bulk-collapsed default (no override)")
	}

	// Focus n2.
	m = keyCtrl(m, tea.KeyCtrlN) // n1
	m = keyCtrl(m, tea.KeyCtrlN) // n2
	if m.focusNodeID != "n2" {
		t.Fatalf("focus = %q, want n2", m.focusNodeID)
	}

	// FIRST Ctrl-O: pops the bulk-collapsed panel OPEN via a force-expand override.
	m = keyCtrl(m, tea.KeyCtrlO)
	opts := m.RenderOpts()
	if !opts.ForceExpanded("n2") {
		t.Errorf("first Ctrl-O should store a force-expand override so n2 pops OPEN, got %+v", opts.Collapsed)
	}
	if opts.IsCollapsed("n2") {
		t.Errorf("first Ctrl-O must NOT force-collapse an already bulk-collapsed panel (the prior no-op bug)")
	}
	// The unfocused panel and the bulk flags are untouched.
	if opts.ForceExpanded("n1") || opts.IsCollapsed("n1") {
		t.Errorf("Ctrl-O must not touch the unfocused panel n1")
	}
	if opts.Expanded || !opts.Panels {
		t.Errorf("per-panel fold must not disturb the bulk Panels/Expanded flags, got Panels=%v Expanded=%v", opts.Panels, opts.Expanded)
	}

	// SECOND Ctrl-O: re-collapses n2 back to the bulk default, pruning the override.
	m = keyCtrl(m, tea.KeyCtrlO)
	opts = m.RenderOpts()
	if opts.ForceExpanded("n2") {
		t.Errorf("second Ctrl-O should re-collapse n2 (drop the force-expand override)")
	}
	if opts.IsCollapsed("n2") {
		t.Errorf("second Ctrl-O should leave n2 inheriting the bulk-collapsed default, not a force-collapse override")
	}
	// The override that merely re-asserts the bulk-collapsed default is pruned, so
	// only the bulk flags remain — no per-panel entry lingers.
	if opts.Collapsed != nil {
		t.Errorf("re-collapsing to the bulk default must prune the override map to nil, got %+v", *opts.Collapsed)
	}
	if !opts.Panels || opts.Expanded {
		t.Errorf("the bulk --panels flags must survive the round-trip, got Panels=%v Expanded=%v", opts.Panels, opts.Expanded)
	}
}

// TestCtrlODegradesToGlobalFoldWithoutFocus proves that when NO panel is focused
// Ctrl-O degrades to the v1 global Expanded flip — a session that never moves
// focus behaves exactly as the v1 global fold did (the back-compat invariant).
func TestCtrlODegradesToGlobalFoldWithoutFocus(t *testing.T) {
	m := modelWithPanels(t, "n1")
	if m.focusNodeID != "" {
		t.Fatalf("focus should start empty, got %q", m.focusNodeID)
	}
	m = keyCtrl(m, tea.KeyCtrlO)
	if !m.RenderOpts().Expanded {
		t.Errorf("Ctrl-O with no focus should set the global Expanded=true (v1 fold)")
	}
	if m.RenderOpts().IsCollapsed("n1") {
		t.Errorf("Ctrl-O with no focus must not write a per-NodeID override")
	}
	m = keyCtrl(m, tea.KeyCtrlO)
	if m.RenderOpts().Expanded {
		t.Errorf("a second Ctrl-O should clear the global Expanded again")
	}
}

// TestFocusKeysAreNoOpWithoutPanels proves the per-panel fold keys are inert when
// no tool panels exist (the default session): Ctrl-P/Ctrl-N leave focus empty and
// Ctrl-O degrades to the global flip — none disturb a session that never surfaced
// a panel.
func TestFocusKeysAreNoOpWithoutPanels(t *testing.T) {
	clearTUIEnv(t)
	m := NewModel(New(nil), true)
	m = keyCtrl(m, tea.KeyCtrlN)
	if m.focusNodeID != "" {
		t.Errorf("Ctrl-N with no panels set focus = %q, want empty", m.focusNodeID)
	}
	m = keyCtrl(m, tea.KeyCtrlP)
	if m.focusNodeID != "" {
		t.Errorf("Ctrl-P with no panels set focus = %q, want empty", m.focusNodeID)
	}
	// Ctrl-O still degrades to the global v1 flip with no panels.
	m = keyCtrl(m, tea.KeyCtrlO)
	if !m.RenderOpts().Expanded {
		t.Errorf("Ctrl-O with no panels should still flip the global Expanded (v1 fold)")
	}
}

// TestStaleFocusDegradesGracefully proves that if the focused NodeID is not in the
// live panel set (it scrolled out, or focus was never re-validated), Ctrl-O does
// NOT write an override for a stale id — it degrades to the global flip, so the
// fold never points at a panel that is not on screen.
func TestStaleFocusDegradesGracefully(t *testing.T) {
	m := modelWithPanels(t, "n1")
	// Force a stale focus directly (a NodeID not in the live set).
	m.focusNodeID = "ghost"
	m = keyCtrl(m, tea.KeyCtrlO)
	if m.RenderOpts().IsCollapsed("ghost") {
		t.Errorf("Ctrl-O must not write an override for a stale (off-screen) NodeID")
	}
	if !m.RenderOpts().Expanded {
		t.Errorf("Ctrl-O on a stale focus should degrade to the global Expanded flip")
	}
}

// TestNoKeystrokeViewByteIdenticalToBulkRender proves the default-OFF invariant:
// with NO fold keystroke the live View() over a panel-bearing session is
// byte-identical to the bulk render (a zero RenderOpts ⇒ the bare surface), so the
// per-NodeID affordance never disturbs the baseline until an operator uses it.
func TestNoKeystrokeViewByteIdenticalToBulkRender(t *testing.T) {
	m := modelWithPanels(t, "n1", "n2")

	// The reference: the same folded State rendered through the zero RenderOpts.
	ref := m.state.View(true, tui.RenderOpts{})
	// The live View with no keystroke applied must match it byte-for-byte.
	if got := m.View(); got != ref {
		t.Errorf("View with no fold keystroke must equal the zero-opts bulk render\n--- view ---\n%s\n--- ref ---\n%s", got, ref)
	}
	// And the live opts are still the zero RenderOpts (nothing toggled).
	if got := m.RenderOpts(); got != (tui.RenderOpts{}) {
		t.Errorf("RenderOpts with no keystroke = %+v, want zero", got)
	}
	// Sanity: the reference is a real render (non-empty), so the equality is meaningful.
	if strings.TrimSpace(ref) == "" {
		t.Fatalf("reference render was empty; the byte-identical assertion is vacuous")
	}
}

// TestFoldKeysRaceFreeWithConcurrentFold proves the per-NodeID fold keystrokes are
// data-race-free against the concurrent event fold: in production the bubbletea
// Update goroutine handles the fold keys (panelNodeIDs reads the Model's live tool
// set) WHILE the watch-subscriber goroutine mutates the same Model via State.Apply
// (app.go). The keystroke read must take the loop lock exactly as View does, so
// this exercises both goroutines together. It is meaningful under `go test -race`;
// without the lock the race detector flags the concurrent toolOrder/tools access.
func TestFoldKeysRaceFreeWithConcurrentFold(t *testing.T) {
	clearTUIEnv(t)
	m := NewModel(New(nil), true)

	const n = 200
	var wg sync.WaitGroup
	wg.Add(2)

	// Folder goroutine: stands in for the watch subscriber, appending tool panels
	// through State.Apply (the one writer, under the loop lock).
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			// Apply monotone-seq tool events; an out-of-order seq would be a fold
			// error, but these are strictly increasing.
			_ = m.state.Apply(toolEvent(uint64(i+1), nodeIDFor(i), "Edit"))
		}
	}()

	// Keystroke goroutine: stands in for the bubbletea Update loop, driving the
	// per-panel fold keys that read the live panel set via panelNodeIDs.
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			m.moveFocus(+1)
			m.toggleFocusedFold()
			m.moveFocus(-1)
		}
	}()

	wg.Wait()
}

// nodeIDFor builds a deterministic distinct NodeID for the i-th concurrent tool
// event (kept tiny to avoid pulling in strconv just for the stress loop).
func nodeIDFor(i int) string {
	const digits = "0123456789"
	return "n" + string(digits[i/100%10]) + string(digits[i/10%10]) + string(digits[i%10])
}
