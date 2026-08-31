package tui

import (
	"fmt"
	"io"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/tui/diffview"
	"github.com/dream-serpent/dream-serpent/client/tui/highlight"
)

// render.go is the stdlib ANSI renderer (the framework decision recorded in
// README.md): it draws structured deltas (D18) — NEVER a forwarded terminal
// frame. The render is a pure function of the Model, so a golden test pins it
// byte-for-byte.
//
// Three render entry points share the same line glyphs:
//   - RenderPlain writes an un-colored transcript + status footer (the golden
//     surface the render tests compare; also the --no-color binary mode). It is
//     un-highlighted, un-diffed, un-grouped — ALL enrichment lives in the
//     interactive path, never here (doc serpent-cli-mvp/06 §4.2).
//   - Render writes the same with ANSI SGR styling for an interactive TTY.
//   - RenderRich (Phase-2, doc 06 Layers 2/3/5) is Render plus the independently
//     gated enrichments: Layer-2 reconstructed diffs, Layer-3 syntax
//     highlighting, and Layer-5 collapsible tool panels. With all options off it
//     is byte-identical to Render — the enrichment is purely additive.

// glyph returns the leading marker for a line kind. Glyphs are ASCII so the
// plain golden is portable and diff-friendly.
func glyph(k LineKind) string {
	switch k {
	case LineSessionInit:
		return "::"
	case LineState:
		return "--"
	case LineThinking:
		return " ~"
	case LineChat:
		return "> "
	case LineTool:
		return "$ "
	case LineToolResult:
		return "= "
	case LineSubagent:
		return "+ "
	case LineSubProgress:
		return ". "
	case LineSubComplete:
		return "* "
	case LineSubAccounted:
		return "# "
	case LineAsk:
		return "? "
	case LineAskResolved:
		return "! "
	case LinePlan:
		return "[]"
	case LineQuota:
		return "% "
	case LineAccounted:
		return "==" //
	default:
		return "  "
	}
}

// RenderPlain writes the model as an un-styled transcript followed by a status
// footer. This is the golden surface: deterministic, ASCII, no escape codes.
func RenderPlain(w io.Writer, m *Model) error {
	for _, ln := range m.Lines {
		indent := strings.Repeat("  ", ln.Depth)
		if _, err := fmt.Fprintf(w, "%s%s%s\n", indent, glyph(ln.Kind), ln.Text); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, statusFooter(m)); err != nil {
		return err
	}
	return nil
}

// statusFooter is the one-line session-status summary the writer seat always
// sees: the live state, the writer/park indicator, and the pending-ask count.
// A parked session (unanswered ask) is surfaced as PARKED, never as failed
// (D53/D77): the human is being awaited, the session has not timed out.
func statusFooter(m *Model) string {
	var b strings.Builder
	b.WriteString("[ session ")
	if m.SessionID != "" {
		b.WriteString(shortID(m.SessionID))
	} else {
		b.WriteString("?")
	}
	if m.Parked() {
		n := len(m.PendingAsks())
		fmt.Fprintf(&b, " | PARKED on %d ask(s) — awaiting human", n)
	} else if m.State != "" {
		b.WriteString(" | state ")
		b.WriteString(m.State)
	}
	if m.Accounting != nil {
		b.WriteString(" | ")
		b.WriteString(m.Accounting.Outcome)
	}
	fmt.Fprintf(&b, " | seq %d ]\n", m.LastSeq())
	return b.String()
}

// shortID trims a UUID to its last segment for the footer.
func shortID(id string) string {
	if i := strings.LastIndex(id, "-"); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}
	return id
}

// ANSI SGR codes for the interactive renderer. Kept minimal and centralized so
// the styling is one place to revisit when the framework decision is revisited.
const (
	ansiReset  = "\x1b[0m"
	ansiDim    = "\x1b[2m"
	ansiBold   = "\x1b[1m"
	ansiCyan   = "\x1b[36m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiBlue   = "\x1b[34m"
)

// styleFor returns the SGR prefix for a line kind (interactive render only).
func styleFor(k LineKind) string {
	switch k {
	case LineThinking, LineSubProgress, LineQuota:
		return ansiDim
	case LineChat:
		return ""
	case LineTool:
		return ansiBlue
	case LineToolResult:
		return ansiDim
	case LineSubagent, LineSubComplete, LineSubAccounted:
		return ansiCyan
	case LineAsk:
		return ansiYellow + ansiBold
	case LineAskResolved:
		return ansiGreen
	case LinePlan:
		return ansiCyan
	case LineSessionInit, LineAccounted:
		return ansiBold
	default:
		return ""
	}
}

// Render writes the styled interactive frame. It is RenderPlain plus SGR
// styling; structure and content are identical, so the golden stays the plain
// surface and styling is never load-bearing for correctness.
//
// It also draws the Layer-1 live tail (doc serpent-cli-mvp/06 §Layer 1): the
// in-flight typing text for chat blocks still being streamed, rendered below the
// committed transcript and replaced by the committed LineChat once the
// authoritative ChatMessage commits. The tail is empty unless the adapter ran
// WithPartials (the deltas are render-only, P11) and NEVER reaches RenderPlain,
// so the golden surface is byte-stable.
func Render(w io.Writer, m *Model) error {
	for _, ln := range m.Lines {
		indent := strings.Repeat("  ", ln.Depth)
		style := styleFor(ln.Kind)
		if style == "" {
			if _, err := fmt.Fprintf(w, "%s%s%s\n", indent, glyph(ln.Kind), ln.Text); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "%s%s%s%s%s\n", indent, style, glyph(ln.Kind), ln.Text, ansiReset); err != nil {
			return err
		}
	}
	if err := renderLiveTail(w, m); err != nil {
		return err
	}
	footerStyle := ansiBold
	if m.Parked() {
		footerStyle = ansiYellow + ansiBold
	}
	if _, err := fmt.Fprintf(w, "%s%s%s", footerStyle, statusFooter(m), ansiReset); err != nil {
		return err
	}
	return nil
}

// renderLiveTail draws the Layer-1 live-streaming-text region — the typing tail
// below the committed transcript (doc 06 §Layer 1). Each in-flight block renders
// with the same glyph/style/indent as its committed counterpart (LineChat for
// text, LineThinking for thinking) so the tail looks like the transcript "typing
// in", then is replaced by the committed line on finalization. It is a pure
// function of Model.LiveTail() (deterministic, first-seen order). With no live
// blocks (the default partials-off path) it writes nothing, so Render stays
// byte-identical to its pre-Layer-1 output. RenderPlain never calls it (the
// golden surface, doc 06 §4.2).
func renderLiveTail(w io.Writer, m *Model) error {
	for _, lb := range m.LiveTail() {
		kind := LineChat
		if lb.kind == "thinking" {
			kind = LineThinking
		}
		indent := strings.Repeat("  ", m.depthOf(lb.parentNodeID))
		style := styleFor(kind)
		text := lb.text
		if style == "" {
			if _, err := fmt.Fprintf(w, "%s%s%s\n", indent, glyph(kind), text); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "%s%s%s%s%s\n", indent, style, glyph(kind), text, ansiReset); err != nil {
			return err
		}
	}
	return nil
}

// RenderOpts gates the Phase-2 render enrichments (doc serpent-cli-mvp/06).
// Each is independent and OFF by default: a zero RenderOpts makes RenderRich
// byte-identical to Render, so the enrichment can never regress the baseline.
// None of these touches the wire — they transform events already on the frozen
// attach.v1 stream (Input/OutputExcerpt/NodeID/TurnGroup).
type RenderOpts struct {
	// Diffs (Layer 2, --diffs) reconstructs a unified diff from the structured
	// ToolInvoked.Input for the file-editing tools and renders it in place of the
	// output excerpt; an unrecognized input degrades to the excerpt with no panic.
	Diffs bool
	// Highlight (Layer 3, --highlight) applies ANSI SGR syntax coloring to fenced
	// code blocks in chat text, to the Layer-2 diff hunks, and to Bash/file tool
	// inputs. It is color-only — never structural.
	Highlight bool
	// Panels (Layer 5, --panels) collapses each ToolInvoked/ToolCompleted pair
	// (joined by NodeID, grouped by TurnGroup) into a foldable [-]/[+] panel.
	// Expanded selects the BULK default fold state when Panels is on (it governs
	// every panel that has no per-panel override in Collapsed).
	Panels   bool
	Expanded bool
	// ContextRadius (Layer 2) tunes how many unchanged lines of CONTEXT a
	// reconstructed diff keeps on each side of a changed run before the far context
	// is collapsed (doc 06 Layer 2). It is threaded into diffview at the Reconstruct
	// call site. A zero/unset value resolves to diffview's default (3, the
	// "diff -U3" convention) inside Reconstruct, so a zero RenderOpts is byte-
	// identical to the prior hardcoded-const behavior — and because it has no effect
	// unless Diffs is on (no diff is reconstructed otherwise), it is NOT an
	// enrichment toggle: isZero() ignores it, and a caller setting only
	// ContextRadius still routes to the byte-identical Render baseline. A smaller
	// radius collapses MORE surrounding context; a larger one keeps more.
	ContextRadius int
	// Collapsed is the per-panel fold override keyed on toolPair.NodeID (the same
	// NodeID that joins ToolInvoked to ToolCompleted, doc 06 Layer 5). It is the
	// real collapsible-per-tool affordance: Expanded is the bulk default, and a
	// per-NodeID entry is a TRI-STATE override of THAT one panel (doc 06 Layer 5):
	//   - no entry  => INHERIT  (the panel follows the bulk Expanded default)
	//   - entry true  => FORCE-COLLAPSE  (folded even when Expanded is set)
	//   - entry false => FORCE-EXPAND    (shown even when the bulk default is collapsed)
	// The force-expand arm is what lets a keystroke EXPAND a bulk-collapsed panel
	// (e.g. --panels with Expanded:false, then one panel popped open) — the prior
	// one-directional "Collapsed forces collapse" rule could only fold, never the
	// reverse. The tri-state is carried in a plain map[string]bool by PRESENCE +
	// VALUE, so the App keystroke loop (client/tui/app.go) keeps its existing
	// "set true to collapse / delete to inherit" idiom unchanged (it simply never
	// stores a false entry); a force-expand consumer stores false.
	//
	// A nil/empty map, AND a map whose every entry merely re-asserts the bulk
	// default (an all-inherit override is impossible since absence == inherit, but
	// an empty map is exactly that), stays byte-identical to the bulk Expanded
	// behavior: the global Expanded governs every panel, so a zero RenderOpts stays
	// byte-identical to Render. The map is consulted only by RenderRich
	// (interactive); RenderPlain is never grouped or folded (doc 06 §4.2). Reads
	// are pure lookups via the IsCollapsed / ForceExpanded accessors, so a nil
	// override is always safe.
	//
	// It is stored behind a pointer (a FoldMap value, not a bare map field) so
	// RenderOpts stays COMPARABLE with ==: a bare map[string]bool field makes the
	// struct uncomparable, which would break the existing zero-opts routing in the
	// command-line callers (`opts == tui.RenderOpts{}` in client/cmd/*). The zero
	// value is a nil *FoldMap == the no-override baseline, so a caller that never
	// sets it (the default flag path) still compares equal to the zero RenderOpts.
	Collapsed *FoldMap
}

// FoldMap is a per-NodeID fold-override set (NodeID -> tri-state fold). The bool
// value carries the tri-state by PRESENCE + VALUE: an absent key inherits the
// bulk Expanded default, a present true force-collapses that panel, and a present
// false force-expands it (doc 06 Layer 5). It is a named map type referenced
// through a pointer on RenderOpts so the option struct stays comparable;
// construct one with NewFoldMap (force-collapse seed) or NewFoldMapState /
// a composite literal and take its address (or use WithCollapsed).
type FoldMap map[string]bool

// NewFoldMap returns a *FoldMap seeded with the given force-COLLAPSED NodeIDs
// (each mapped to true). The returned pointer is ready to assign to
// RenderOpts.Collapsed. Use NewFoldMapState for force-expand entries.
func NewFoldMap(collapsed ...string) *FoldMap {
	fm := make(FoldMap, len(collapsed))
	for _, id := range collapsed {
		fm[id] = true
	}
	return &fm
}

// NewFoldMapState returns a *FoldMap seeded from an explicit NodeID -> collapsed
// map, so a caller can seed force-EXPAND overrides (value false) as well as
// force-collapse (value true). A nil/empty argument yields an empty override (the
// no-override baseline). It is the tri-state-aware constructor counterpart to
// NewFoldMap (which seeds force-collapse only).
func NewFoldMapState(state map[string]bool) *FoldMap {
	fm := make(FoldMap, len(state))
	for id, collapsed := range state {
		fm[id] = collapsed
	}
	return &fm
}

// WithCollapsed returns a copy of opts whose Collapsed override is fm. It is the
// ergonomic way for a caller (e.g. a loop keystroke handler maintaining the fold
// set) to attach a per-panel override without reaching for the pointer directly.
func (o RenderOpts) WithCollapsed(fm *FoldMap) RenderOpts {
	o.Collapsed = fm
	return o
}

// IsCollapsed reports whether NodeID is FORCE-COLLAPSED by this override set
// (a present+true entry). It nil-guards both the *FoldMap and the underlying map,
// so a zero RenderOpts (nil Collapsed) always answers false. An absent entry
// (inherit) and a present+false entry (force-expand) both answer false.
func (o RenderOpts) IsCollapsed(nodeID string) bool {
	if o.Collapsed == nil {
		return false
	}
	return (*o.Collapsed)[nodeID]
}

// ForceExpanded reports whether NodeID is FORCE-EXPANDED by this override set
// (a present+false entry). It nil-guards the pointer and the map. An absent entry
// (inherit) and a present+true entry (force-collapse) both answer false. This is
// the new tri-state arm: it lets a per-panel override show a panel the bulk
// Expanded default would otherwise collapse (doc 06 Layer 5).
func (o RenderOpts) ForceExpanded(nodeID string) bool {
	if o.Collapsed == nil {
		return false
	}
	v, ok := (*o.Collapsed)[nodeID]
	return ok && !v
}

// hasOverrides reports whether the override set holds at least one entry of
// EITHER tri-state arm (force-collapse or force-expand). A nil or empty *FoldMap
// is the no-override baseline; a present force-expand-only entry still counts so
// it routes through RenderRich rather than the byte-identical baseline.
func (o RenderOpts) hasOverrides() bool {
	return o.Collapsed != nil && len(*o.Collapsed) > 0
}

// isZero reports whether opts selects NO enrichment — the baseline case where
// RenderRich must be byte-identical to Render. It replaces the previous
// `opts == (RenderOpts{})` comparison so the zero-routing is expressed in one
// place (the struct stays comparable, but a non-nil empty *FoldMap should still
// route to the baseline). A zero RenderOpts (all flags false AND no override
// entries) is the unenriched baseline; any set flag or any per-panel override
// (force-collapse OR force-expand) means enrichment is requested. It is the
// single definition the public IsZero accessor wraps.
func (o RenderOpts) isZero() bool {
	return !o.Diffs && !o.Highlight && !o.Panels && !o.Expanded && !o.hasOverrides()
}

// IsZero reports whether opts selects no enrichment — the byte-identical baseline
// where RenderRich delegates to Render. It is the PUBLIC single-source of the
// zero-routing decision: external callers (client/cmd/ds-tui, serpent-tui's loop)
// route to the plain/baseline surface on IsZero() instead of the raw
// `opts == RenderOpts{}` comparison, which mis-routed a non-nil empty *FoldMap
// (a comparable-but-not-zero Collapsed pointer) through the enriched path. It
// wraps the unexported isZero so there is exactly one definition of the rule.
func (o RenderOpts) IsZero() bool { return o.isZero() }

// panelCollapsed resolves the effective fold for one tool panel from the
// tri-state per-NodeID override layered over the bulk default (doc 06 Layer 5).
// It returns true when the panel should render collapsed:
//   - a present FORCE-COLLAPSE override (IsCollapsed) folds it regardless of bulk;
//   - a present FORCE-EXPAND override (ForceExpanded) shows it regardless of bulk;
//   - otherwise it INHERITS the bulk default (collapsed unless opts.Expanded).
//
// A nil/empty override therefore stays byte-identical to the prior global-Expanded
// behavior (no entry => pure inherit), and the new force-expand arm lets one
// panel pop open against a bulk-collapsed (Expanded:false) default.
func (o RenderOpts) panelCollapsed(nodeID string) bool {
	if o.IsCollapsed(nodeID) {
		return true
	}
	if o.ForceExpanded(nodeID) {
		return false
	}
	return !o.Expanded
}

// RenderRich writes the interactive frame with the Phase-2 enrichments selected
// by opts. With a zero opts it delegates to Render (byte-identical baseline).
// The plain golden surface (RenderPlain) is never reachable from here — all
// enrichment is interactive-only, exactly as styling is never load-bearing for
// correctness (doc 06 §4.2).
func RenderRich(w io.Writer, m *Model, opts RenderOpts) error {
	if opts.isZero() {
		return Render(w, m)
	}

	// Layer 5: when panels are on, the matched tool lines fold into panels, so
	// suppress their inline transcript lines and emit the panel where the invoke
	// occurred (keyed by the invoke seq, preserving transcript order).
	suppress, panelAt := map[uint64]bool{}, map[uint64]*toolPair{}
	if opts.Panels {
		for _, p := range m.ToolPanels() {
			panelAt[p.Seq] = p
			suppress[p.Seq] = true // the LineTool invoke line folds into the panel
		}
		// The matching LineToolResult line shares no seq with its invoke, so pair
		// each result to the most-recent open invoke of equal depth and suppress
		// it too when that invoke has a panel.
		suppressResults(m, suppress)
	}

	for _, ln := range m.Lines {
		if suppress[ln.Seq] && (ln.Kind == LineTool || ln.Kind == LineToolResult) {
			if p, ok := panelAt[ln.Seq]; ok && ln.Kind == LineTool {
				if err := renderToolPanel(w, p, opts); err != nil {
					return err
				}
			}
			continue
		}
		if err := renderLine(w, ln, opts); err != nil {
			return err
		}
	}

	if err := renderLiveTail(w, m); err != nil {
		return err
	}

	footerStyle := ansiBold
	if m.Parked() {
		footerStyle = ansiYellow + ansiBold
	}
	if _, err := fmt.Fprintf(w, "%s%s%s", footerStyle, statusFooter(m), ansiReset); err != nil {
		return err
	}
	return nil
}

// suppressResults marks every LineToolResult that belongs to a paired tool (one
// with a panel) for suppression, by pairing each result to the most-recent
// unconsumed invoke at the same depth — the same FIFO order the fold produced
// them. Only results whose invoke seq is already suppressed (i.e. has a panel)
// are themselves suppressed; an unpaired tool keeps its inline result line.
func suppressResults(m *Model, suppress map[uint64]bool) {
	// A per-depth FIFO so a result matches the nearest open invoke of its depth
	// (subagent tool calls interleave by depth, never by seq alone).
	openByDepth := map[int][]uint64{}
	for _, ln := range m.Lines {
		switch ln.Kind {
		case LineTool:
			openByDepth[ln.Depth] = append(openByDepth[ln.Depth], ln.Seq)
		case LineToolResult:
			q := openByDepth[ln.Depth]
			if len(q) == 0 {
				continue
			}
			invokeSeq := q[0]
			openByDepth[ln.Depth] = q[1:]
			if suppress[invokeSeq] { // its invoke has a panel ⇒ fold the result in
				suppress[ln.Seq] = true
			}
		}
	}
}

// renderLine writes one transcript line with the styled glyph, applying Layer-3
// highlighting to chat text fenced code blocks when enabled. It is the styled
// per-line writer Render uses, factored so RenderRich shares it.
func renderLine(w io.Writer, ln Line, opts RenderOpts) error {
	indent := strings.Repeat("  ", ln.Depth)
	text := ln.Text
	if opts.Highlight && ln.Kind == LineChat {
		text = highlightFencedBlocks(text)
	}
	style := styleFor(ln.Kind)
	if style == "" {
		_, err := fmt.Fprintf(w, "%s%s%s\n", indent, glyph(ln.Kind), text)
		return err
	}
	_, err := fmt.Fprintf(w, "%s%s%s%s%s\n", indent, style, glyph(ln.Kind), text, ansiReset)
	return err
}

// renderToolPanel draws one collapsible Layer-5 tool panel: a header line with a
// [-]/[+] fold affordance + tool name + one-line summary, and (when expanded)
// the body — the Layer-3-highlighted input and either the Layer-2 reconstructed
// diff (for a file-edit tool) or the output excerpt.
func renderToolPanel(w io.Writer, p *toolPair, opts RenderOpts) error {
	indent := strings.Repeat("  ", p.Depth)
	// Resolve this panel's effective fold: the bulk default (opts.Expanded) with a
	// per-NodeID Collapsed override forcing collapse (doc 06 Layer 5). The header
	// affordance and the body suppression both reflect the RESOLVED state, so two
	// panels under one opts can render in opposite fold states.
	collapsed := opts.panelCollapsed(p.NodeID)
	fold := "[+]"
	if !collapsed {
		fold = "[-]"
	}
	header := panelHeader(p)
	if _, err := fmt.Fprintf(w, "%s%s%s %s%s\n", indent, ansiBlue, fold, header, ansiReset); err != nil {
		return err
	}
	if collapsed {
		return nil
	}
	body := strings.Repeat("  ", p.Depth+1)

	// Body part 1: the tool input, highlighted by language when enabled.
	if in := compactInput(p.Invoked.Input); in != "" {
		shown := in
		if opts.Highlight {
			shown = highlight.Highlight(inputLang(p.Invoked.Name), in)
		}
		if _, err := fmt.Fprintf(w, "%sinput: %s\n", body, shown); err != nil {
			return err
		}
	}

	// Body part 2: a Layer-2 diff for a file-edit tool, else the output excerpt.
	// The configurable context radius (opts.ContextRadius, 0 => diffview default)
	// is threaded in here so the diff body honors the caller's collapse window.
	if opts.Diffs {
		if d, ok := diffview.ReconstructWithRadius(p.Invoked.Name, p.Invoked.Input, opts.ContextRadius); ok {
			return renderDiff(w, d, body, opts)
		}
	}
	if p.Completed != nil {
		if _, err := fmt.Fprintf(w, "%s%s\n", body, formatToolCompleted(p.Completed)); err != nil {
			return err
		}
	}
	return nil
}

// panelHeader is the one-line panel summary: tool name + a diff/edit hint or the
// completion status. Pure function of the pair — deterministic.
func panelHeader(p *toolPair) string {
	name := p.Invoked.Name
	if d, ok := diffview.Reconstruct(p.Invoked.Name, p.Invoked.Input); ok {
		return d.Summary()
	}
	switch {
	case p.Completed == nil:
		return name + " (running)"
	case p.Completed.DenialMessage != "":
		return name + " — denied"
	case p.Completed.IsError:
		return name + " — error"
	default:
		return name + " — ok"
	}
}

// renderDiff writes a reconstructed unified diff under indent, applying Layer-3
// diff coloring when highlighting is on. The coloring is driven off the
// STRUCTURED diffview.Line Kinds (LineHeader/Add/Del/Context) — diffview already
// classified every line, so we map each Kind to its color directly instead of
// re-serializing the body and re-parsing the +/-/@@ prefixes back off the text
// (the prior path). The result is byte-identical for any well-formed diff (each
// Kind maps to the same color the prefix scanner derived) but skips the redundant
// round-trip. The line Text already carries its leading +/-/space glyph, so a
// plain (un-highlighted) render emits it verbatim.
func renderDiff(w io.Writer, d *diffview.Diff, indent string, opts RenderOpts) error {
	var body string
	if opts.Highlight {
		body = highlight.HighlightDiffLines(diffLines(d))
	} else {
		body = d.PlainText()
	}
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if _, err := fmt.Fprintf(w, "%s%s\n", indent, line); err != nil {
			return err
		}
	}
	return nil
}

// diffLines projects a reconstructed diff's structured lines onto the highlighter's
// Kind-driven DiffLine slice, mapping each diffview.LineKind to its highlight
// counterpart. This is the single Kind→Kind bridge that lets renderDiff color by
// classification instead of re-parsing prefixes; an unknown kind maps to context
// (uncolored), the safe identity.
func diffLines(d *diffview.Diff) []highlight.DiffLine {
	if d == nil {
		return nil
	}
	out := make([]highlight.DiffLine, len(d.Lines))
	for i, l := range d.Lines {
		out[i] = highlight.DiffLine{Kind: diffKind(l.Kind), Text: l.Text}
	}
	return out
}

// diffKind maps a diffview.LineKind to the highlighter's DiffLineKind.
func diffKind(k diffview.LineKind) highlight.DiffLineKind {
	switch k {
	case diffview.LineHeader:
		return highlight.DiffHeader
	case diffview.LineAdd:
		return highlight.DiffAdd
	case diffview.LineDel:
		return highlight.DiffDel
	default:
		return highlight.DiffContext
	}
}

// inputLang maps a tool name to the language its Input should be highlighted as:
// Bash inputs are shell, the file-edit tools carry a JSON input blob.
func inputLang(toolName string) highlight.Lang {
	switch toolName {
	case "Bash":
		return highlight.Bash
	default:
		return highlight.JSON
	}
}

// highlightFencedBlocks colors the contents of ```lang fenced code blocks inside
// a chat line, leaving the prose untouched. The transcript Text is a single
// pre-rendered line (newlines were collapsed by the formatter), so fences only
// appear when the upstream text preserved them; this is best-effort and
// color-only (stripping ANSI yields the original text).
func highlightFencedBlocks(text string) string {
	const fence = "```"
	if !strings.Contains(text, fence) {
		return text
	}
	parts := strings.Split(text, fence)
	// parts alternate prose / code / prose / code ...; an odd count means a
	// closed pair, an even count an unterminated fence (last part stays prose).
	var b strings.Builder
	for i, part := range parts {
		if i%2 == 0 { // prose
			b.WriteString(part)
			if i < len(parts)-1 {
				b.WriteString(fence)
			}
			continue
		}
		// code block: first token is the optional lang tag.
		lang, code := splitFenceLang(part)
		b.WriteString(highlight.Highlight(lang, code))
		if i < len(parts)-1 {
			b.WriteString(fence)
		}
	}
	return b.String()
}

// splitFenceLang separates an optional leading language tag from a fenced block
// body. "go\nx := 1" -> (Go, "\nx := 1"); a body with no tag returns Unknown and
// the body unchanged.
func splitFenceLang(block string) (highlight.Lang, string) {
	nl := strings.IndexByte(block, '\n')
	if nl < 0 {
		// Single-line fence: treat the whole thing as code with no tag.
		return highlight.Unknown, block
	}
	tag := block[:nl]
	if lang := highlight.LangFor(tag); lang != highlight.Unknown {
		return lang, block[nl:]
	}
	return highlight.Unknown, block
}
