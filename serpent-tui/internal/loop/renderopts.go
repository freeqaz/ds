// SPDX-License-Identifier: Apache-2.0

package loop

import (
	"os"
	"strconv"

	"github.com/dream-serpent/dream-serpent/client/tui"
)

// The DS_TUI_* env gate is the DISJOINT wiring leg between the serpent entrypoint
// and this interactive loop. `serpent claude --vm` parses --diffs/--highlight/
// --panels/--expanded/--no-color and EXECs serpent-tui with these env vars set;
// the loop reads them at NewModel time so the Phase-2 render enrichments (doc
// serpent-cli-mvp/06 Layers 2/3/5) reach the live surface WITHOUT coupling the
// serpent-tui app wiring or its cmd flagset to the options. Every var is OFF when
// unset, so the default behavior is byte-identical to today (a zero RenderOpts ⇒
// RenderRich == Render). They are render-only: nothing here touches the wire.
const (
	// envDiffs (DS_TUI_DIFFS) selects Layer-2 reconstructed diffs.
	envDiffs = "DS_TUI_DIFFS"
	// envHighlight (DS_TUI_HIGHLIGHT) selects Layer-3 syntax highlighting.
	envHighlight = "DS_TUI_HIGHLIGHT"
	// envPanels (DS_TUI_PANELS) selects Layer-5 collapsible tool panels.
	envPanels = "DS_TUI_PANELS"
	// envExpanded (DS_TUI_EXPANDED) sets the INITIAL panel fold state when panels
	// are on (the live fold key flips it thereafter).
	envExpanded = "DS_TUI_EXPANDED"
	// envContextRadius (DS_TUI_CONTEXT_RADIUS) tunes the Layer-2 diff context window
	// (unchanged lines kept on each side of a changed run before the far context is
	// collapsed). It is an INT, not a presence switch: an unset or non-numeric value
	// resolves to 0, which RenderOpts treats as diffview's default (3, "diff -U3"),
	// so it is byte-identical to the prior hardcoded behavior. It has no effect
	// unless Diffs is on, so it never flips a zero RenderOpts into an enriched one.
	envContextRadius = "DS_TUI_CONTEXT_RADIUS"
	// envNoColorVar (DS_TUI_NO_COLOR) routes to the byte-stable RenderPlain surface
	// (the --no-color binary mode), suppressing all enrichment.
	envNoColorVar = "DS_TUI_NO_COLOR"
)

// RenderOptsFromEnv builds a tui.RenderOpts from the DS_TUI_* env gate. An unset
// or false-y var leaves its toggle off, so an environment with none of them set
// yields the zero RenderOpts (byte-identical to Render). Expanded is honored only
// as the initial fold state — it has no effect unless Panels is on (RenderRich
// ignores Expanded without Panels). ContextRadius rides the same gate as an INT
// (0 ⇒ diffview's default), so a bare environment still yields the zero RenderOpts:
// ContextRadius is NOT an enrichment toggle (RenderOpts.isZero ignores it), so an
// env that sets ONLY DS_TUI_CONTEXT_RADIUS still routes to the byte-identical Render
// baseline.
func RenderOptsFromEnv() tui.RenderOpts {
	return tui.RenderOpts{
		Diffs:         envBool(envDiffs),
		Highlight:     envBool(envHighlight),
		Panels:        envBool(envPanels),
		Expanded:      envBool(envExpanded),
		ContextRadius: envInt(envContextRadius),
	}
}

// envNoColor reports whether DS_TUI_NO_COLOR requests the plain (no-color)
// surface. It is separate from RenderOptsFromEnv because --no-color routes to
// RenderPlain (a color decision), not to a RenderOpts toggle.
func envNoColor() bool { return envBool(envNoColorVar) }

// envBool parses a DS_TUI_* env var as a boolean. An unset var is false; a value
// strconv.ParseBool accepts ("1"/"true"/"t"/…) is honored; any other non-empty
// value is treated as TRUE (so `DS_TUI_DIFFS=on` enables it) — the env gate is a
// presence-or-truth switch, never a hard parse that could fail the launch.
func envBool(name string) bool {
	v := os.Getenv(name)
	if v == "" {
		return false
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	return true
}

// envInt parses a DS_TUI_* env var as a non-negative int (the diff context radius).
// An unset, empty, non-numeric, or negative value resolves to 0 — RenderOpts treats
// a zero ContextRadius as diffview's default (3), so a missing or malformed value is
// the byte-identical baseline rather than a launch failure (the env gate never hard-
// parses). It clamps below at 0 so a stray "-1" cannot widen into an unexpected
// window.
func envInt(name string) int {
	v := os.Getenv(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
