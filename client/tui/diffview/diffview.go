// SPDX-License-Identifier: Apache-2.0

// Package diffview reconstructs a unified diff from a file-editing tool's
// structured input, a pure render-time transform over the opaque
// ToolInvoked.Input JSON already on the frozen attach.v1 wire (doc
// serpent-cli-mvp/06 Layer 2). It is STDLIB-ONLY (D80): a minimal line-by-line
// unified diff with no external diff library.
//
// The reconstruction is keyed on the CC tool name (Edit / Write / MultiEdit /
// NotebookEdit) and reads CC's documented input shape:
//   - Edit:         {"file_path","old_string","new_string",...}
//   - Write:        {"file_path","content"}
//   - MultiEdit:    {"file_path","edits":[{"old_string","new_string"},...]}
//   - NotebookEdit: {"notebook_path"|"file_path","new_source",...}
//
// This is acceptable runtime-specific knowledge BELOW the adapter boundary: the
// renderer already presents tool names verbatim (doc 06 §4.2). An unrecognized
// or malformed input shape returns ok=false so the caller falls back to the
// existing OutputExcerpt render with NO panic (doc 06 R5 / A6).
package diffview

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SupportedTools is the set of CC tool names diffview reconstructs a diff for.
// A name not in this set is not a file-edit tool and must degrade to the
// existing excerpt render (the caller's responsibility).
var SupportedTools = map[string]bool{
	"Edit":         true,
	"Write":        true,
	"MultiEdit":    true,
	"NotebookEdit": true,
}

// IsSupported reports whether a ToolInvoked.Name is one diffview reconstructs.
func IsSupported(toolName string) bool { return SupportedTools[toolName] }

// LineKind classifies one rendered diff line for downstream styling. The diff
// is plain text; the kind lets the highlighter color hunks without re-parsing.
type LineKind int

const (
	// LineContext is an unchanged context line (" " prefix).
	LineContext LineKind = iota
	// LineAdd is an inserted line ("+" prefix).
	LineAdd
	// LineDel is a removed line ("-" prefix).
	LineDel
	// LineHeader is a file/hunk header (e.g. "--- a/...", "@@ ... @@").
	LineHeader
)

// Line is one rendered unified-diff line. Text already carries the leading
// prefix glyph (" ", "+", "-", or header text), so a plain renderer can emit
// Text verbatim and a styled renderer can color by Kind.
type Line struct {
	Kind LineKind
	Text string
}

// Diff is a reconstructed unified diff for one file-editing tool call. Path is
// the edited file; Lines is the rendered hunk body (headers + context/+/-).
// Truncated is set when the diff was clamped to MaxDiffLines.
type Diff struct {
	Tool      string
	Path      string
	Lines     []Line
	Truncated bool
}

// MaxDiffLines bounds a reconstructed diff so a huge Write/Edit cannot flood
// the transcript. A clamp, not a correctness limit: the panel is render-only.
const MaxDiffLines = 200

// defaultContextRadius is how many unchanged lines of CONTEXT diffview keeps on
// each side of a changed run when the caller does not request a specific radius;
// runs of context longer than 2*radius are collapsed and a fresh
// "@@ -a,b +c,d @@" hunk header is re-emitted between the gaps. This keeps the
// actual change VISIBLE under the MaxDiffLines clamp: a 1-line edit in a
// ~2000-line block would otherwise emit ~1999 context lines and push the change
// past line 200 (doc 06 Layer 2). Radius 3 is the unified-diff default
// ("diff -U3"); it is the value a zero/unset radius resolves to so a default
// reconstruct stays byte-identical to the prior hardcoded-const behavior.
const defaultContextRadius = 3

// normalizeRadius maps a caller-supplied context radius to the value used by the
// collapse: a non-positive radius (the zero/unset case) resolves to the
// unified-diff default so a zero RenderOpts is byte-identical to the prior
// hardcoded const. A positive radius is honored verbatim.
func normalizeRadius(radius int) int {
	if radius <= 0 {
		return defaultContextRadius
	}
	return radius
}

// maxDiffInputLines bounds the TOTAL input line count (len(old)+len(new)) that
// lcsDiff will run its O(n*m) longest-common-subsequence DP over. Beyond it, a
// pathological large Write/MultiEdit would allocate an (n+1)x(m+1) int table for
// a render-only panel, so we fall back to the cheap whole-block del/add path and
// flag the diff Truncated — bounding DP cost by the same render budget the
// OUTPUT is already clamped to. Set comfortably above MaxDiffLines so a normal
// edit never trips it but a runaway input cannot pay quadratic memory.
const maxDiffInputLines = 4 * MaxDiffLines

// Reconstruct builds a unified diff from a tool name and its raw input JSON at
// the default context radius (defaultContextRadius). It returns ok=false (and a
// nil *Diff) for any tool it does not handle or any input it cannot parse into
// the expected shape — the caller then renders the existing OutputExcerpt. It
// NEVER panics on malformed input (A6). It is shorthand for
// ReconstructWithRadius(toolName, input, 0).
func Reconstruct(toolName string, input []byte) (d *Diff, ok bool) {
	return ReconstructWithRadius(toolName, input, 0)
}

// ReconstructWithRadius is Reconstruct with a caller-chosen context radius: the
// number of unchanged lines kept on each side of a changed run before the far
// context is collapsed (doc 06 Layer 2). A non-positive radius resolves to the
// unified-diff default (defaultContextRadius == 3), so passing 0 is byte-
// identical to Reconstruct. A smaller radius collapses MORE surrounding context;
// a larger one keeps more. Same ok=false fall-back and no-panic guarantees (A6).
func ReconstructWithRadius(toolName string, input []byte, radius int) (d *Diff, ok bool) {
	if !IsSupported(toolName) || len(input) == 0 {
		return nil, false
	}
	radius = normalizeRadius(radius)
	switch toolName {
	case "Edit":
		return reconstructEdit(toolName, input, radius)
	case "Write":
		return reconstructWrite(toolName, input, radius)
	case "MultiEdit":
		return reconstructMultiEdit(toolName, input, radius)
	case "NotebookEdit":
		return reconstructNotebook(toolName, input, radius)
	default:
		return nil, false
	}
}

// editInput is CC's Edit tool input shape.
type editInput struct {
	FilePath   string `json:"file_path"`
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all"`
}

func reconstructEdit(tool string, raw []byte, radius int) (*Diff, bool) {
	var in editInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, false
	}
	// A degenerate Edit (no strings at all) is not a renderable diff: fall back.
	if in.OldString == "" && in.NewString == "" {
		return nil, false
	}
	d := &Diff{Tool: tool, Path: in.FilePath}
	d.appendHeaders(in.FilePath)
	d.appendReplacement(in.OldString, in.NewString, radius)
	d.clamp()
	return d, true
}

// writeInput is CC's Write tool input shape.
type writeInput struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

func reconstructWrite(tool string, raw []byte, radius int) (*Diff, bool) {
	var in writeInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, false
	}
	// A Write with no path is not the expected shape.
	if in.FilePath == "" {
		return nil, false
	}
	d := &Diff{Tool: tool, Path: in.FilePath}
	d.appendHeaders(in.FilePath)
	// A Write is a full-file replacement: render the whole content as added
	// lines (the old side is the empty file from the renderer's view — the
	// structured input carries no prior content).
	d.appendReplacement("", in.Content, radius)
	d.clamp()
	return d, true
}

// multiEditInput is CC's MultiEdit tool input shape.
type multiEditInput struct {
	FilePath string `json:"file_path"`
	Edits    []struct {
		OldString  string `json:"old_string"`
		NewString  string `json:"new_string"`
		ReplaceAll bool   `json:"replace_all"`
	} `json:"edits"`
}

func reconstructMultiEdit(tool string, raw []byte, radius int) (*Diff, bool) {
	var in multiEditInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, false
	}
	if len(in.Edits) == 0 {
		return nil, false
	}
	d := &Diff{Tool: tool, Path: in.FilePath}
	d.appendHeaders(in.FilePath)
	for i, e := range in.Edits {
		if i > 0 {
			d.Lines = append(d.Lines, Line{Kind: LineHeader, Text: fmt.Sprintf("@@ edit %d @@", i+1)})
		}
		d.appendReplacement(e.OldString, e.NewString, radius)
	}
	d.clamp()
	return d, true
}

// notebookEditInput is CC's NotebookEdit tool input shape. The cell source may
// arrive under either "new_source" (current) or "content"; the path may arrive
// under "notebook_path" or "file_path".
type notebookEditInput struct {
	NotebookPath string `json:"notebook_path"`
	FilePath     string `json:"file_path"`
	NewSource    string `json:"new_source"`
	Content      string `json:"content"`
	OldSource    string `json:"old_source"`
	CellID       string `json:"cell_id"`
}

func reconstructNotebook(tool string, raw []byte, radius int) (*Diff, bool) {
	var in notebookEditInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, false
	}
	path := in.NotebookPath
	if path == "" {
		path = in.FilePath
	}
	newSrc := in.NewSource
	if newSrc == "" {
		newSrc = in.Content
	}
	// Need at least a path and some new source to render a meaningful diff.
	if path == "" || (newSrc == "" && in.OldSource == "") {
		return nil, false
	}
	d := &Diff{Tool: tool, Path: path}
	header := path
	if in.CellID != "" {
		header = path + " (cell " + in.CellID + ")"
	}
	d.appendHeaders(header)
	d.appendReplacement(in.OldSource, newSrc, radius)
	d.clamp()
	return d, true
}

// appendHeaders writes the "--- a/<path>" / "+++ b/<path>" file headers.
func (d *Diff) appendHeaders(path string) {
	if path == "" {
		path = "(unknown)"
	}
	d.Lines = append(d.Lines,
		Line{Kind: LineHeader, Text: "--- a/" + path},
		Line{Kind: LineHeader, Text: "+++ b/" + path},
	)
}

// appendReplacement emits a unified-diff body for old -> new at the given context
// radius. It runs a stdlib-only LCS (longest-common-subsequence) line diff so a
// small edit inside a large block keeps the unchanged surrounding lines as CONTEXT
// (a " " prefix) rather than re-rendering every line as a delete-then-add (doc 06
// Layer 2). Long runs of unchanged context are then COLLAPSED to `radius` lines on
// each side of a changed run, with a fresh "@@ -a,b +c,d @@" hunk header re-emitted
// between collapsed gaps, so the actual change stays visible under the
// MaxDiffLines clamp instead of being pushed past line 200 by a sea of context.
// The radius is supplied by the caller (default defaultContextRadius via
// normalizeRadius): a smaller radius collapses MORE surrounding context, a larger
// one keeps more. The first hunk's header keeps the package's existing
// "@@ -a,b +c,d @@" format. Styling is never load-bearing (doc 06 R5): the prefix
// glyph is carried on Text, so a plain renderer is byte-stable regardless of how a
// line is classified.
//
// INPUT GUARD: the LCS DP allocates an (n+1)x(m+1) int table over the FULL old/
// new line counts before the output is clamped. When len(old)+len(new) exceeds
// maxDiffInputLines, a render-only panel must not pay that O(n*m) memory, so we
// fall back to the cheap whole-block del/add path (every old line deleted, every
// new line added — no DP) and set Truncated. DP cost is then bounded by the same
// render budget the output already is.
//
// A whole-block replacement that shares no lines (e.g. a Write, whose old side is
// empty) degenerates to all-deletions-then-all-additions, exactly as before.
func (d *Diff) appendReplacement(oldStr, newStr string, radius int) {
	oldLines := splitKeep(oldStr)
	newLines := splitKeep(newStr)

	// Input-line budget: bound the O(n*m) DP by the render budget. Over budget,
	// skip the DP entirely and emit the cheap whole-block del/add body.
	if len(oldLines)+len(newLines) > maxDiffInputLines {
		d.Truncated = true
		d.Lines = append(d.Lines, Line{
			Kind: LineHeader,
			Text: fmt.Sprintf("@@ -1,%d +1,%d @@", len(oldLines), len(newLines)),
		})
		d.Lines = append(d.Lines, wholeBlockDiff(oldLines, newLines)...)
		return
	}

	d.Lines = append(d.Lines, collapseContext(lcsDiff(oldLines, newLines), normalizeRadius(radius))...)
}

// op is one line-level diff operation, carrying the 1-based old/new line numbers
// it occupies so collapseContext can re-emit accurate "@@ -a,b +c,d @@" headers.
type op struct {
	line   Line
	oldNum int // 1-based old-side line number, 0 for an addition
	newNum int // 1-based new-side line number, 0 for a deletion
}

// lcsDiff computes a unified-diff op stream (context / deletion / addition lines,
// each already prefixed) for oldLines -> newLines via a longest-common-subsequence
// DP. Lines common to both sides (in subsequence order) are CONTEXT; lines unique
// to the old side are deletions, unique to the new side additions, in standard
// unified-diff emission order. It is O(len(old)*len(new)) time/space — fine for
// the bounded, render-only diffs here (the input is budget-guarded by the caller
// and the output is clamped to MaxDiffLines).
//
// When the two sides share NO lines (the Write case: old is empty) this reduces
// to every old line deleted then every new line added — the prior whole-block
// behavior, preserved for that degenerate case.
func lcsDiff(oldLines, newLines []string) []op {
	n, m := len(oldLines), len(newLines)
	// lcs[i][j] = length of the LCS of oldLines[i:] and newLines[j:]. Filled
	// back-to-front so the forward walk below can greedily follow the table.
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	out := make([]op, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case oldLines[i] == newLines[j]:
			out = append(out, op{Line{LineContext, " " + oldLines[i]}, i + 1, j + 1})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, op{Line{LineDel, "-" + oldLines[i]}, i + 1, 0})
			i++
		default:
			out = append(out, op{Line{LineAdd, "+" + newLines[j]}, 0, j + 1})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, op{Line{LineDel, "-" + oldLines[i]}, i + 1, 0})
	}
	for ; j < m; j++ {
		out = append(out, op{Line{LineAdd, "+" + newLines[j]}, 0, j + 1})
	}
	return out
}

// wholeBlockDiff is the cheap, DP-free fallback: every old line deleted then
// every new line added, framed as a single hunk by the caller. Used when the
// input exceeds the line budget (no LCS table allocated).
func wholeBlockDiff(oldLines, newLines []string) []Line {
	out := make([]Line, 0, len(oldLines)+len(newLines))
	for _, l := range oldLines {
		out = append(out, Line{Kind: LineDel, Text: "-" + l})
	}
	for _, l := range newLines {
		out = append(out, Line{Kind: LineAdd, Text: "+" + l})
	}
	return out
}

// collapseContext takes a full op stream and emits a unified-diff body in which
// runs of unchanged CONTEXT longer than 2*radius are collapsed: at most radius
// context lines are kept after the previous change and radius before the next,
// and each resulting hunk is preceded by an accurate "@@ -a,b +c,d @@" header.
// This keeps changes visible under the MaxDiffLines clamp. With no change at all
// the stream is pure context and collapses to nothing (a no-op diff); each
// changed run anchors a hunk.
func collapseContext(ops []op, radius int) []Line {
	// Mark which op indices are "near" a change: a change itself, or within
	// radius of one (so they survive as surrounding context).
	keep := make([]bool, len(ops))
	for idx, o := range ops {
		if o.line.Kind == LineAdd || o.line.Kind == LineDel {
			lo := idx - radius
			if lo < 0 {
				lo = 0
			}
			hi := idx + radius
			if hi >= len(ops) {
				hi = len(ops) - 1
			}
			for k := lo; k <= hi; k++ {
				keep[k] = true
			}
		}
	}

	var out []Line
	idx := 0
	for idx < len(ops) {
		if !keep[idx] {
			idx++ // collapsed gap
			continue
		}
		// Start of a hunk: gather the contiguous kept run.
		start := idx
		for idx < len(ops) && keep[idx] {
			idx++
		}
		hunk := ops[start:idx]
		out = append(out, Line{Kind: LineHeader, Text: hunkHeader(hunk)})
		for _, o := range hunk {
			out = append(out, o.line)
		}
	}
	return out
}

// hunkHeader builds a "@@ -oldStart,oldLen +newStart,newLen @@" header for a
// contiguous run of ops, using the 1-based line numbers the ops carry. An empty
// or all-addition/all-deletion side reports start 0 length 0, matching unified
// diff. Preserves the package's existing header format.
func hunkHeader(hunk []op) string {
	oldStart, oldLen := lineSpan(hunk, func(o op) int { return o.oldNum })
	newStart, newLen := lineSpan(hunk, func(o op) int { return o.newNum })
	return fmt.Sprintf("@@ -%d,%d +%d,%d @@", oldStart, oldLen, newStart, newLen)
}

// lineSpan returns the 1-based start line and length covered by a hunk on one
// side (old or new), selected by num. A side with no lines reports (0, 0).
func lineSpan(hunk []op, num func(op) int) (start, length int) {
	for _, o := range hunk {
		if n := num(o); n != 0 {
			if start == 0 {
				start = n
			}
			length++
		}
	}
	return start, length
}

// splitKeep splits a block into lines, dropping a single trailing newline so a
// content string that ends in "\n" does not yield a spurious empty final line.
// An empty block yields no lines (nothing to render).
func splitKeep(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// clamp bounds the diff to MaxDiffLines, setting Truncated when it cuts.
func (d *Diff) clamp() {
	if len(d.Lines) <= MaxDiffLines {
		return
	}
	d.Lines = d.Lines[:MaxDiffLines]
	d.Truncated = true
}

// Summary is a one-line description of the diff for a panel header: tool, path,
// and the add/del line counts. Pure function of the reconstructed diff.
func (d *Diff) Summary() string {
	if d == nil {
		return ""
	}
	var adds, dels int
	for _, l := range d.Lines {
		switch l.Kind {
		case LineAdd:
			adds++
		case LineDel:
			dels++
		}
	}
	path := d.Path
	if path == "" {
		path = "(unknown)"
	}
	s := fmt.Sprintf("%s %s  +%d -%d", d.Tool, path, adds, dels)
	if d.Truncated {
		s += " (truncated)"
	}
	return s
}

// PlainText renders the diff body as plain text (one line per Line, no color),
// for a renderer that wants the diff without ANSI. Each line already carries
// its prefix.
func (d *Diff) PlainText() string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	for _, l := range d.Lines {
		b.WriteString(l.Text)
		b.WriteByte('\n')
	}
	return b.String()
}
