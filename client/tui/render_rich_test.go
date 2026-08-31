// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/tui/highlight"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// toolInvoked builds a ToolInvoked event with a raw JSON input.
func toolInvoked(seq uint64, nodeID, name, turnGroup string, input string) attach.Event {
	return attach.Event{
		Seq: seq, SessionID: "s", Type: attach.TypeToolInvoked,
		ToolInvoked: &attach.ToolInvoked{
			NodeID: nodeID, Name: name, TurnGroup: turnGroup,
			Input: json.RawMessage(input),
		},
	}
}

// toolCompleted builds the matching ToolCompleted event.
func toolCompleted(seq uint64, nodeID, excerpt string) attach.Event {
	return attach.Event{
		Seq: seq, SessionID: "s", Type: attach.TypeToolCompleted,
		ToolCompleted: &attach.ToolCompleted{NodeID: nodeID, OutputExcerpt: excerpt},
	}
}

func mustApply(t *testing.T, m *Model, evs ...attach.Event) {
	t.Helper()
	for _, e := range evs {
		if err := m.Apply(e); err != nil {
			t.Fatalf("apply seq %d: %v", e.Seq, err)
		}
	}
}

// TestRenderRichZeroOptsEqualsRender (baseline stability): RenderRich with a
// zero RenderOpts is byte-identical to Render — the enrichment is purely
// additive and can never regress the styled baseline.
func TestRenderRichZeroOptsEqualsRender(t *testing.T) {
	src := string(loadGolden(t, "mcp-skill-native"))
	m, _, err := BuildModel(strings.NewReader(src), RoleReader, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var base, rich bytes.Buffer
	if err := Render(&base, m); err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := RenderRich(&rich, m, RenderOpts{}); err != nil {
		t.Fatalf("renderrich: %v", err)
	}
	if !bytes.Equal(base.Bytes(), rich.Bytes()) {
		t.Errorf("RenderRich(zero opts) must equal Render\n--- render ---\n%s\n--- rich ---\n%s", base.String(), rich.String())
	}
}

// TestRenderPlainNeverEnriched (A7): the plain golden surface is byte-stable and
// carries NO ANSI escapes, NO diff hunks, and NO panel affordances, even when a
// file-edit tool with a diffable input is in the transcript. Enrichment lives
// only in the interactive path.
func TestRenderPlainNeverEnriched(t *testing.T) {
	m := NewModel()
	mustApply(t, m,
		toolInvoked(1, "n1", "Edit", "g1", `{"file_path":"/work/a.go","old_string":"foo","new_string":"bar"}`),
		toolCompleted(2, "n1", "applied edit"),
	)
	var plain bytes.Buffer
	if err := RenderPlain(&plain, m); err != nil {
		t.Fatalf("renderplain: %v", err)
	}
	out := plain.String()
	if strings.Contains(out, "\x1b[") {
		t.Errorf("RenderPlain must carry no ANSI escapes:\n%q", out)
	}
	if strings.Contains(out, "[+]") || strings.Contains(out, "[-]") {
		t.Errorf("RenderPlain must carry no panel affordance:\n%s", out)
	}
	if strings.Contains(out, "--- a/") || strings.Contains(out, "+++ b/") {
		t.Errorf("RenderPlain must carry no reconstructed diff:\n%s", out)
	}
	// And it must still contain the inline tool + result lines (un-grouped).
	if !strings.Contains(out, "$ tool Edit") || !strings.Contains(out, "applied edit") {
		t.Errorf("RenderPlain should keep the inline tool/result lines:\n%s", out)
	}
}

// TestToolPanelGroupingDeterministic (A8): ToolInvoked/ToolCompleted join by
// NodeID, group stably by TurnGroup, and the panel order is the first-invoked
// order — folding the same events twice yields byte-identical panels.
func TestToolPanelGroupingDeterministic(t *testing.T) {
	build := func() *Model {
		m := NewModel()
		mustApply(t, m,
			toolInvoked(1, "n1", "Bash", "g1", `{"command":"ls"}`),
			toolCompleted(2, "n1", "a\nb"),
			toolInvoked(3, "n2", "Write", "g1", `{"file_path":"/x","content":"hi\n"}`),
			toolCompleted(4, "n2", "wrote 1 line"),
		)
		return m
	}
	m := build()

	panels := m.ToolPanels()
	if len(panels) != 2 {
		t.Fatalf("expected 2 panels, got %d", len(panels))
	}
	// NodeID join: each panel has its own completion bound by NodeID.
	if panels[0].NodeID != "n1" || panels[0].Completed == nil || panels[0].Completed.OutputExcerpt != "a\nb" {
		t.Errorf("panel 0 mis-joined: %+v", panels[0])
	}
	if panels[1].NodeID != "n2" || panels[1].Completed == nil {
		t.Errorf("panel 1 mis-joined: %+v", panels[1])
	}
	// TurnGroup carried for stable grouping.
	if panels[0].TurnGroup != "g1" || panels[1].TurnGroup != "g1" {
		t.Errorf("turn groups not carried: %q %q", panels[0].TurnGroup, panels[1].TurnGroup)
	}
	// Order is first-invoked (n1 before n2) and stable across rebuilds.
	var a, b bytes.Buffer
	if err := RenderRich(&a, m, RenderOpts{Panels: true, Expanded: true}); err != nil {
		t.Fatalf("render a: %v", err)
	}
	if err := RenderRich(&b, build(), RenderOpts{Panels: true, Expanded: true}); err != nil {
		t.Fatalf("render b: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Errorf("panel render is non-deterministic:\n%s\n---\n%s", a.String(), b.String())
	}
}

// TestPanelFoldStates: a collapsed panel shows the [+] header only; an expanded
// panel shows [-] plus the body, and folds the inline tool + result lines.
func TestPanelFoldStates(t *testing.T) {
	m := NewModel()
	mustApply(t, m,
		toolInvoked(1, "n1", "Bash", "g1", `{"command":"echo hi"}`),
		toolCompleted(2, "n1", "hi"),
	)
	var collapsed, expanded bytes.Buffer
	if err := RenderRich(&collapsed, m, RenderOpts{Panels: true, Expanded: false}); err != nil {
		t.Fatalf("collapsed: %v", err)
	}
	if err := RenderRich(&expanded, m, RenderOpts{Panels: true, Expanded: true}); err != nil {
		t.Fatalf("expanded: %v", err)
	}
	if !strings.Contains(collapsed.String(), "[+]") {
		t.Errorf("collapsed panel should show [+]:\n%s", collapsed.String())
	}
	if !strings.Contains(expanded.String(), "[-]") {
		t.Errorf("expanded panel should show [-]:\n%s", expanded.String())
	}
	// Folded: the standalone "$ tool Bash" invoke line must not appear separately
	// from the panel (it is replaced by the panel header).
	if strings.Contains(collapsed.String(), "$ tool Bash") {
		t.Errorf("collapsed panel should fold the inline invoke line:\n%s", collapsed.String())
	}
	// Expanded body shows the input and the output excerpt.
	if !strings.Contains(expanded.String(), "input:") || !strings.Contains(expanded.String(), "hi") {
		t.Errorf("expanded panel body missing input/output:\n%s", expanded.String())
	}
}

// TestPanelPerNodeCollapse (doc 06 Layer 5): the per-NodeID Collapsed override
// folds ONE panel independently while the rest follow the bulk Expanded default.
// With Expanded:true and Collapsed{n1:true}, panel n1 shows its [+] header only
// (body folded) while panel n2 stays expanded ([-] + its body) — a real
// collapsible-per-tool affordance, not a single global flip.
func TestPanelPerNodeCollapse(t *testing.T) {
	build := func() *Model {
		m := NewModel()
		mustApply(t, m,
			toolInvoked(1, "n1", "Bash", "g1", `{"command":"echo one"}`),
			toolCompleted(2, "n1", "OUTPUT_ONE"),
			toolInvoked(3, "n2", "Bash", "g1", `{"command":"echo two"}`),
			toolCompleted(4, "n2", "OUTPUT_TWO"),
		)
		return m
	}
	m := build()

	var out bytes.Buffer
	opts := RenderOpts{Panels: true, Expanded: true}.WithCollapsed(NewFoldMap("n1"))
	if err := RenderRich(&out, m, opts); err != nil {
		t.Fatalf("render: %v", err)
	}
	s := out.String()

	// Both panels must render exactly one fold affordance each: n1 collapsed [+],
	// n2 expanded [-]. Count by glyph so we assert the resolved per-panel state.
	if got := strings.Count(s, "[+]"); got != 1 {
		t.Errorf("expected exactly one collapsed panel ([+]), got %d:\n%s", got, s)
	}
	if got := strings.Count(s, "[-]"); got != 1 {
		t.Errorf("expected exactly one expanded panel ([-]), got %d:\n%s", got, s)
	}
	// n1 is collapsed: its body (the echo-one input / OUTPUT_ONE excerpt) is folded.
	if strings.Contains(s, "OUTPUT_ONE") || strings.Contains(s, "echo one") {
		t.Errorf("collapsed panel n1 must hide its body:\n%s", s)
	}
	// n2 follows the bulk Expanded default: its body is shown.
	if !strings.Contains(s, "OUTPUT_TWO") || !strings.Contains(s, "echo two") {
		t.Errorf("expanded panel n2 must show its body:\n%s", s)
	}

	// A nil/empty Collapsed override is byte-identical to the prior global-Expanded
	// behavior: no regression vs RenderRich without the override.
	var bulk, override bytes.Buffer
	if err := RenderRich(&bulk, build(), RenderOpts{Panels: true, Expanded: true}); err != nil {
		t.Fatalf("bulk render: %v", err)
	}
	if err := RenderRich(&override, build(), RenderOpts{Panels: true, Expanded: true}.WithCollapsed(NewFoldMap())); err != nil {
		t.Fatalf("empty-override render: %v", err)
	}
	if !bytes.Equal(bulk.Bytes(), override.Bytes()) {
		t.Errorf("an empty Collapsed override must be byte-identical to bulk Expanded:\n--- bulk ---\n%s\n--- empty override ---\n%s", bulk.String(), override.String())
	}

	// And an override the OTHER way: Expanded:false with Collapsed{n1:true} is the
	// same as Expanded:false alone (Collapsed only ever forces collapse — the
	// documented one-directional rule — so folding an already-folded panel is a
	// no-op).
	var allFolded, foldedPlus bytes.Buffer
	if err := RenderRich(&allFolded, build(), RenderOpts{Panels: true, Expanded: false}); err != nil {
		t.Fatalf("all-folded render: %v", err)
	}
	if err := RenderRich(&foldedPlus, build(), RenderOpts{Panels: true, Expanded: false}.WithCollapsed(NewFoldMap("n1"))); err != nil {
		t.Fatalf("folded-plus render: %v", err)
	}
	if !bytes.Equal(allFolded.Bytes(), foldedPlus.Bytes()) {
		t.Errorf("Collapsed forcing an already-collapsed panel must be a no-op:\n--- all folded ---\n%s\n--- folded+override ---\n%s", allFolded.String(), foldedPlus.String())
	}
}

// TestDiffPanelAndFallback (A6 integration): a file-edit tool renders the
// Layer-2 diff inside its panel; a tool with an unrecognized input shape falls
// back to the output excerpt with no diff and no panic.
func TestDiffPanelAndFallback(t *testing.T) {
	m := NewModel()
	mustApply(t, m,
		// A real Edit → diffable.
		toolInvoked(1, "n1", "Edit", "g1", `{"file_path":"/work/a.go","old_string":"old","new_string":"new"}`),
		toolCompleted(2, "n1", "edit applied"),
		// An Edit with an unrecognized input → falls back to excerpt.
		toolInvoked(3, "n2", "Edit", "g1", `{"unexpected":"shape"}`),
		toolCompleted(4, "n2", "fallback excerpt"),
	)
	var out bytes.Buffer
	if err := RenderRich(&out, m, RenderOpts{Panels: true, Expanded: true, Diffs: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	s := highlight.StripANSI(out.String())
	if !strings.Contains(s, "-old") || !strings.Contains(s, "+new") {
		t.Errorf("expected reconstructed diff for n1:\n%s", s)
	}
	if !strings.Contains(s, "fallback excerpt") {
		t.Errorf("n2 (unrecognized input) should fall back to the excerpt:\n%s", s)
	}
}

// TestHighlightOnlyAddsColor (A7 integration): turning highlighting on changes
// only ANSI escapes — stripping them yields the same bytes as the un-highlighted
// rich render. Highlighting is never structural.
func TestHighlightOnlyAddsColor(t *testing.T) {
	m := NewModel()
	mustApply(t, m,
		toolInvoked(1, "n1", "Edit", "g1", `{"file_path":"/work/a.go","old_string":"old","new_string":"new"}`),
		toolCompleted(2, "n1", "ok"),
	)
	var plainRich, colorRich bytes.Buffer
	if err := RenderRich(&plainRich, m, RenderOpts{Panels: true, Expanded: true, Diffs: true}); err != nil {
		t.Fatalf("plain rich: %v", err)
	}
	if err := RenderRich(&colorRich, m, RenderOpts{Panels: true, Expanded: true, Diffs: true, Highlight: true}); err != nil {
		t.Fatalf("color rich: %v", err)
	}
	if highlight.StripANSI(colorRich.String()) != highlight.StripANSI(plainRich.String()) {
		t.Errorf("highlighting changed more than color:\n--- plain ---\n%s\n--- color(stripped) ---\n%s",
			highlight.StripANSI(plainRich.String()), highlight.StripANSI(colorRich.String()))
	}
	if !strings.Contains(colorRich.String(), "\x1b[") {
		t.Errorf("highlighted diff should carry ANSI escapes")
	}
}

// TestRichGoldenStabilityAcrossCassettes: for every replay cassette, RenderRich
// with all options on (a) does not panic and (b) strips back to the SAME bytes
// as the plain rich render (panels/diffs may add structure, but highlight must
// only add color) — a broad no-regression sweep.
func TestRichHighlightColorOnlyAcrossCassettes(t *testing.T) {
	for _, base := range []string{"baseline-chat", "mcp-skill-native", "ask-control", "subagent-spawn", "nested-spawn"} {
		t.Run(base, func(t *testing.T) {
			src := string(loadGolden(t, base))
			m, _, err := BuildModel(strings.NewReader(src), RoleReader, 0)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			optsNoColor := RenderOpts{Panels: true, Expanded: true, Diffs: true}
			optsColor := optsNoColor
			optsColor.Highlight = true
			var a, b bytes.Buffer
			if err := RenderRich(&a, m, optsNoColor); err != nil {
				t.Fatalf("render no-color: %v", err)
			}
			if err := RenderRich(&b, m, optsColor); err != nil {
				t.Fatalf("render color: %v", err)
			}
			if highlight.StripANSI(a.String()) != highlight.StripANSI(b.String()) {
				t.Errorf("highlight changed structure for %s", base)
			}
		})
	}
}
