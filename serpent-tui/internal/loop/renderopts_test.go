// SPDX-License-Identifier: Apache-2.0

package loop

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/dream-serpent/dream-serpent/client/tui"
)

// TestRenderOptsFromEnvDefaultOff proves an empty environment yields the zero
// RenderOpts (the byte-identical baseline) and envNoColor is false — the loop
// renders exactly as today unless a DS_TUI_* var is set.
func TestRenderOptsFromEnvDefaultOff(t *testing.T) {
	for _, name := range []string{envDiffs, envHighlight, envPanels, envExpanded, envNoColorVar} {
		t.Setenv(name, "")
	}
	if got := RenderOptsFromEnv(); got != (tui.RenderOpts{}) {
		t.Errorf("empty-env RenderOptsFromEnv = %+v, want zero RenderOpts", got)
	}
	if envNoColor() {
		t.Errorf("empty-env envNoColor = true, want false")
	}
}

// TestRenderOptsFromEnvAllSet proves each DS_TUI_* var maps onto the right
// RenderOpts field and that envNoColor reads its own var.
func TestRenderOptsFromEnvAllSet(t *testing.T) {
	t.Setenv(envDiffs, "1")
	t.Setenv(envHighlight, "true")
	t.Setenv(envPanels, "on") // non-bool-but-nonempty ⇒ true (presence switch)
	t.Setenv(envExpanded, "1")
	t.Setenv(envNoColorVar, "1")

	got := RenderOptsFromEnv()
	want := tui.RenderOpts{Diffs: true, Highlight: true, Panels: true, Expanded: true}
	if got != want {
		t.Errorf("RenderOptsFromEnv = %+v, want %+v", got, want)
	}
	if !envNoColor() {
		t.Errorf("envNoColor = false, want true after DS_TUI_NO_COLOR=1")
	}
}

// TestRenderOptsContextRadiusRoundTrips proves DS_TUI_CONTEXT_RADIUS parses into
// RenderOpts.ContextRadius (the diffview context window threaded from the
// --context-radius flag), so an operator's value reaches RenderRich.
func TestRenderOptsContextRadiusRoundTrips(t *testing.T) {
	t.Setenv(envContextRadius, "5")
	if got := RenderOptsFromEnv().ContextRadius; got != 5 {
		t.Errorf("DS_TUI_CONTEXT_RADIUS=5 -> ContextRadius = %d, want 5", got)
	}
}

// TestContextRadiusGarbageAndNegativeDefault proves an unset, empty, non-numeric,
// or negative DS_TUI_CONTEXT_RADIUS resolves to 0 — which RenderOpts treats as
// diffview's default (3) — rather than failing the launch (the env gate never
// hard-parses).
func TestContextRadiusGarbageAndNegativeDefault(t *testing.T) {
	for _, v := range []string{"", "abc", "-1", "3.5", "  "} {
		t.Setenv(envContextRadius, v)
		if got := RenderOptsFromEnv().ContextRadius; got != 0 {
			t.Errorf("DS_TUI_CONTEXT_RADIUS=%q -> ContextRadius = %d, want 0 (diffview default)", v, got)
		}
	}
}

// TestContextRadiusAloneStillZeroRenderOpts proves ContextRadius is NOT an
// enrichment toggle: an env that sets ONLY DS_TUI_CONTEXT_RADIUS (no diffs/
// highlight/panels) still yields a RenderOpts that selects no enrichment — so a
// bare context radius routes to the byte-identical baseline (it has no effect
// unless Diffs is on).
func TestContextRadiusAloneStillZeroRenderOpts(t *testing.T) {
	for _, name := range []string{envDiffs, envHighlight, envPanels, envExpanded} {
		t.Setenv(name, "")
	}
	t.Setenv(envContextRadius, "7")
	got := RenderOptsFromEnv()
	if got.ContextRadius != 7 {
		t.Errorf("ContextRadius = %d, want 7", got.ContextRadius)
	}
	if got.Diffs || got.Highlight || got.Panels || got.Expanded || got.IsCollapsed("") {
		t.Errorf("a bare DS_TUI_CONTEXT_RADIUS enabled an enrichment toggle: %+v", got)
	}
}

// TestEnvBoolFalsey proves an explicit false value disables a toggle (so
// DS_TUI_DIFFS=0 is off, not "present therefore on").
func TestEnvBoolFalsey(t *testing.T) {
	t.Setenv(envDiffs, "0")
	t.Setenv(envPanels, "false")
	if got := RenderOptsFromEnv(); got.Diffs || got.Panels {
		t.Errorf("falsey env enabled a toggle: %+v", got)
	}
}

// TestNewModelSeedsOptsFromEnv proves NewModel picks up the env gate and that
// SetRenderOpts overrides it.
func TestNewModelSeedsOptsFromEnv(t *testing.T) {
	t.Setenv(envPanels, "1")
	t.Setenv(envExpanded, "1")
	m := NewModel(New(nil), true)
	if got := m.RenderOpts(); got != (tui.RenderOpts{Panels: true, Expanded: true}) {
		t.Errorf("NewModel opts = %+v, want Panels+Expanded from env", got)
	}
	m.SetRenderOpts(tui.RenderOpts{Diffs: true})
	if got := m.RenderOpts(); got != (tui.RenderOpts{Diffs: true}) {
		t.Errorf("SetRenderOpts override = %+v, want Diffs only", got)
	}
}

// TestNewModelNoColorEnvForcesPlain proves DS_TUI_NO_COLOR=1 forces the model to
// the plain (no-color) surface regardless of the color arg — the View then
// renders RenderPlain (no ANSI escape codes).
func TestNewModelNoColorEnvForcesPlain(t *testing.T) {
	t.Setenv(envNoColorVar, "1")
	m := NewModel(New(nil), true /*color requested on*/)
	out := m.View()
	if strings.Contains(out, "\x1b[") {
		t.Errorf("DS_TUI_NO_COLOR must force the plain (no-escape) surface, got ANSI codes:\n%q", out)
	}
}

// TestFoldKeyTogglesExpanded proves Ctrl+O flips RenderOpts.Expanded (the global
// v1 panel fold) and does NOT compose into the input line.
func TestFoldKeyTogglesExpanded(t *testing.T) {
	m := NewModel(New(nil), true)
	if m.RenderOpts().Expanded {
		t.Fatalf("Expanded should start false")
	}
	if _, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlO}); !m.RenderOpts().Expanded {
		t.Errorf("Ctrl+O should set Expanded=true")
	}
	if _, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlO}); m.RenderOpts().Expanded {
		t.Errorf("a second Ctrl+O should clear Expanded")
	}
	// It must not have composed anything into the input line.
	if got := m.state.Compose(); got != "" {
		t.Errorf("Ctrl+O composed into input: %q", got)
	}
}

// TestViewZeroOptsByteIdenticalToRender proves View with a zero RenderOpts (color
// on) renders the SAME transcript prefix as the bare tui.Render — the enrichment
// is default-off and never disturbs the baseline surface.
func TestViewZeroOptsByteIdenticalToRender(t *testing.T) {
	st := New(nil)
	mustApply(t, st, stateEvent(1))

	var ref strings.Builder
	if err := tui.Render(&ref, st.Model()); err != nil {
		t.Fatalf("render: %v", err)
	}

	got := st.View(true, tui.RenderOpts{})
	if !strings.HasPrefix(got, ref.String()) {
		t.Errorf("View(zero opts) must start with the bare Render output\n--- view ---\n%s\n--- render ---\n%s", got, ref.String())
	}
}
