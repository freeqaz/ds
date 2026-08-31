// SPDX-License-Identifier: Apache-2.0

// Package highlight is a tiny, stdlib-only token classifier that wraps source
// text in ANSI SGR escapes for the interactive terminal renderer (doc
// serpent-cli-mvp/06 Layer 3). It is RENDER-ONLY and styling-only: it adds
// color, never structure, so it is never load-bearing for correctness and is
// applied ONLY in the interactive Render path — never in the byte-stable
// RenderPlain golden surface (doc 06 §4.2 / render.go).
//
// The charter is D80 stdlib-only: NO chroma, no external lexer. The classifier
// is deliberately minimal — keyword / string / comment / number coloring for
// Bash, Go, Python, JSON, and unified-diff. An unknown language falls through
// to Plain (the input unchanged), and any text it cannot classify is emitted
// verbatim, so highlighting can only ever ADD escapes around runs it is sure
// about — it can never corrupt the underlying characters.
package highlight

import (
	"strings"
)

// ANSI SGR codes used by the highlighter. Kept local to this package so the
// palette is one place; the tui render palette is separate (render.go).
const (
	reset     = "\x1b[0m"
	fgKey     = "\x1b[35m" // magenta  — keywords
	fgStr     = "\x1b[32m" // green    — strings
	fgNum     = "\x1b[33m" // yellow   — numbers
	fgComment = "\x1b[2m"  // dim      — comments
	fgAdd     = "\x1b[32m" // green    — diff +
	fgDel     = "\x1b[31m" // red      — diff -
	fgMeta    = "\x1b[36m" // cyan     — diff headers, JSON keys
	fgPunct   = "\x1b[34m" // blue     — JSON punctuation
)

// Lang names the supported classifiers. Unknown is the no-op identity language.
type Lang string

const (
	Unknown Lang = ""
	Bash    Lang = "bash"
	Go      Lang = "go"
	Python  Lang = "python"
	JSON    Lang = "json"
	Diff    Lang = "diff"
)

// LangFor maps a fence tag / tool hint to a supported Lang. It normalizes the
// common aliases CC emits in ```lang fences and tool names; an unrecognized tag
// returns Unknown (identity highlighting).
func LangFor(tag string) Lang {
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "bash", "sh", "shell", "zsh", "console":
		return Bash
	case "go", "golang":
		return Go
	case "python", "py", "python3":
		return Python
	case "json", "jsonc":
		return JSON
	case "diff", "patch", "udiff":
		return Diff
	default:
		return Unknown
	}
}

// Highlight wraps src in ANSI SGR escapes per the language classifier. For
// Unknown it returns src unchanged. The result always reduces to src once ANSI
// SGR escapes are stripped — highlighting only adds color (verified by
// StripANSI round-trip in the tests).
func Highlight(lang Lang, src string) string {
	switch lang {
	case Bash:
		return highlightLines(src, classifyBashLine)
	case Go:
		return highlightLines(src, lineClassifier(goKeywords, "//"))
	case Python:
		return highlightLines(src, lineClassifier(pyKeywords, "#"))
	case JSON:
		return highlightLines(src, classifyJSONLine)
	case Diff:
		return highlightLines(src, classifyDiffLine)
	default:
		return src
	}
}

// lineFn colors one line (without its trailing newline) and returns the styled
// form. It must be color-only: stripping ANSI from the result yields the input.
type lineFn func(line string) string

// highlightLines applies fn per line, preserving the exact newline structure
// (including a trailing newline or its absence) so the styled output strips
// back to the original byte-for-byte.
func highlightLines(src string, fn lineFn) string {
	if src == "" {
		return ""
	}
	hadTrailing := strings.HasSuffix(src, "\n")
	body := src
	if hadTrailing {
		body = strings.TrimSuffix(src, "\n")
	}
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		lines[i] = fn(l)
	}
	out := strings.Join(lines, "\n")
	if hadTrailing {
		out += "\n"
	}
	return out
}

// --- diff -------------------------------------------------------------------

// DiffLineKind classifies one unified-diff line for Kind-driven coloring. It
// mirrors the structural classification a diff producer already carries (header /
// add / del / context) so a caller that knows the kind can color WITHOUT
// re-parsing the +/-/@@ prefixes off the serialized text. The values intentionally
// map onto the same colors classifyDiffLine derives from prefixes, so the two
// paths are byte-identical for any well-formed diff.
type DiffLineKind int

const (
	// DiffContext is an unchanged context line (rendered without color).
	DiffContext DiffLineKind = iota
	// DiffAdd is an inserted line (green).
	DiffAdd
	// DiffDel is a removed line (red).
	DiffDel
	// DiffHeader is a file/hunk header line (cyan): "--- a/...", "+++ b/...", "@@".
	DiffHeader
)

// DiffLine is one structured diff line for HighlightDiffLines: the kind drives the
// color, the text is emitted verbatim (it already carries its leading +/-/space
// glyph). This lets a renderer that classified the diff structurally color it
// without round-tripping through serialized text + prefix re-parsing.
type DiffLine struct {
	Kind DiffLineKind
	Text string
}

// colorForDiffKind returns the SGR prefix for a diff line kind. DiffContext is
// uncolored (empty prefix), matching classifyDiffLine's default branch. The other
// kinds use the same fg* palette the prefix scanner does, so a Kind-driven render
// is byte-identical to the prefix-parse render for a well-formed diff.
func colorForDiffKind(k DiffLineKind) string {
	switch k {
	case DiffHeader:
		return fgMeta
	case DiffAdd:
		return fgAdd
	case DiffDel:
		return fgDel
	default:
		return ""
	}
}

// HighlightDiffLines colors a structured diff (a slice of kind+text lines) by Kind
// rather than by re-parsing +/-/@@ prefixes, joining the colored lines with "\n"
// and appending a trailing newline (matching the line-oriented output the prefix
// path produced from a "\n"-joined, "\n"-terminated diff body). An empty input
// yields "". It is color-only: stripping the ANSI escapes yields the input texts
// joined by newlines, exactly as the prefix path did.
func HighlightDiffLines(lines []DiffLine) string {
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	for _, l := range lines {
		if c := colorForDiffKind(l.Kind); c != "" {
			b.WriteString(c)
			b.WriteString(l.Text)
			b.WriteString(reset)
		} else {
			b.WriteString(l.Text)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// classifyDiffLine colors one already-serialized unified-diff line. It exists
// only for the legacy Highlight(Diff, src) text entry point (a caller that has a
// "\n"-joined diff body but no structured Kinds); the renderer's diff path drives
// HighlightDiffLines off diffview's structured Kinds and never re-parses prefixes.
// To keep ONE source of truth for the diff palette, the prefix scan now only maps
// a prefix to a DiffLineKind (kindForDiffPrefix) and defers the actual coloring to
// the shared colorForDiffKind helper the Kind-driven path uses — the duplicate
// prefix→color logic is retired, so the two paths can never drift in color.
func classifyDiffLine(line string) string {
	if c := colorForDiffKind(kindForDiffPrefix(line)); c != "" {
		return c + line + reset
	}
	return line
}

// kindForDiffPrefix classifies a serialized unified-diff line by its leading
// glyph: "+++"/"---"/"@@" are headers, a lone "+"/"-" is an add/del, anything
// else is context. This is the single +/-/@@ prefix scan that remains (for the
// text entry point), and it produces a Kind — never a color — so colorForDiffKind
// stays the only place a Kind becomes an SGR escape.
func kindForDiffPrefix(line string) DiffLineKind {
	switch {
	case strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "@@"):
		return DiffHeader
	case strings.HasPrefix(line, "+"):
		return DiffAdd
	case strings.HasPrefix(line, "-"):
		return DiffDel
	default:
		return DiffContext
	}
}

// --- json -------------------------------------------------------------------

// classifyJSONLine colors strings, numbers, and structural punctuation. It is a
// shallow line scanner (no full parse) — robust against malformed JSON because
// it only ever wraps recognized runs and emits everything else verbatim.
func classifyJSONLine(line string) string {
	var b strings.Builder
	runes := []rune(line)
	i := 0
	for i < len(runes) {
		c := runes[i]
		switch {
		case c == '"':
			j := scanString(runes, i)
			b.WriteString(fgStr)
			b.WriteString(string(runes[i:j]))
			b.WriteString(reset)
			i = j
		case c == '{' || c == '}' || c == '[' || c == ']' || c == ':' || c == ',':
			b.WriteString(fgPunct)
			b.WriteRune(c)
			b.WriteString(reset)
			i++
		case isDigit(c) || (c == '-' && i+1 < len(runes) && isDigit(runes[i+1])):
			j := scanNumber(runes, i)
			b.WriteString(fgNum)
			b.WriteString(string(runes[i:j]))
			b.WriteString(reset)
			i = j
		default:
			b.WriteRune(c)
			i++
		}
	}
	return b.String()
}

// --- bash -------------------------------------------------------------------

var bashKeywords = wordSet("if", "then", "else", "elif", "fi", "for", "while",
	"do", "done", "case", "esac", "in", "function", "return", "export", "local",
	"echo", "cd", "set", "sudo")

func classifyBashLine(line string) string {
	// A whole-line comment.
	if t := strings.TrimLeft(line, " \t"); strings.HasPrefix(t, "#") {
		return fgComment + line + reset
	}
	return classifyCode(line, bashKeywords, "#")
}

// --- go / python (keyword + string + line-comment) --------------------------

var goKeywords = wordSet("break", "case", "chan", "const", "continue", "default",
	"defer", "else", "fallthrough", "for", "func", "go", "goto", "if", "import",
	"interface", "map", "package", "range", "return", "select", "struct",
	"switch", "type", "var", "nil", "true", "false")

var pyKeywords = wordSet("def", "class", "import", "from", "as", "if", "elif",
	"else", "for", "while", "return", "yield", "with", "try", "except", "finally",
	"raise", "pass", "break", "continue", "lambda", "None", "True", "False",
	"and", "or", "not", "in", "is", "global", "nonlocal")

// lineClassifier builds a per-line colorizer for a keyword set + a line-comment
// marker (e.g. "//" for Go, "#" for Python).
func lineClassifier(keywords map[string]bool, commentMarker string) lineFn {
	return func(line string) string {
		return classifyCode(line, keywords, commentMarker)
	}
}

// classifyCode colors keywords, quoted strings, numbers, and a trailing
// line-comment for a keyword-based language. It splits the line at the first
// unquoted comment marker and colors only the code portion's tokens.
func classifyCode(line string, keywords map[string]bool, commentMarker string) string {
	code, comment := splitComment(line, commentMarker)
	out := colorTokens(code, keywords)
	if comment != "" {
		out += fgComment + comment + reset
	}
	return out
}

// splitComment splits a line into its code part and a trailing comment part
// (including the marker), respecting quotes so a marker inside a string is not
// treated as a comment. comment is "" when there is none.
func splitComment(line, marker string) (code, comment string) {
	if marker == "" {
		return line, ""
	}
	runes := []rune(line)
	mrunes := []rune(marker)
	inStr := rune(0)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			inStr = c
			continue
		}
		if matchAt(runes, i, mrunes) {
			return string(runes[:i]), string(runes[i:])
		}
	}
	return line, ""
}

// colorTokens colors quoted strings, numbers, and keyword identifiers in a code
// fragment; everything else is emitted verbatim.
func colorTokens(code string, keywords map[string]bool) string {
	var b strings.Builder
	runes := []rune(code)
	i := 0
	for i < len(runes) {
		c := runes[i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			j := scanQuoted(runes, i, c)
			b.WriteString(fgStr)
			b.WriteString(string(runes[i:j]))
			b.WriteString(reset)
			i = j
		case isIdentStart(c):
			j := scanIdent(runes, i)
			word := string(runes[i:j])
			if keywords[word] {
				b.WriteString(fgKey)
				b.WriteString(word)
				b.WriteString(reset)
			} else {
				b.WriteString(word)
			}
			i = j
		case isDigit(c):
			j := scanNumber(runes, i)
			b.WriteString(fgNum)
			b.WriteString(string(runes[i:j]))
			b.WriteString(reset)
			i = j
		default:
			b.WriteRune(c)
			i++
		}
	}
	return b.String()
}

// --- scanners ---------------------------------------------------------------

// scanString scans a double-quoted JSON string starting at a '"', returning the
// index just past the closing quote (or end of line on an unterminated string).
func scanString(r []rune, start int) int {
	i := start + 1
	for i < len(r) {
		if r[i] == '\\' && i+1 < len(r) {
			i += 2
			continue
		}
		if r[i] == '"' {
			return i + 1
		}
		i++
	}
	return len(r)
}

// scanQuoted scans a string opened by quote q (handles ", ', `).
func scanQuoted(r []rune, start int, q rune) int {
	i := start + 1
	for i < len(r) {
		if q != '`' && r[i] == '\\' && i+1 < len(r) {
			i += 2
			continue
		}
		if r[i] == q {
			return i + 1
		}
		i++
	}
	return len(r)
}

// scanNumber scans an integer/float/sign run, returning the index past it.
func scanNumber(r []rune, start int) int {
	i := start
	if i < len(r) && r[i] == '-' {
		i++
	}
	for i < len(r) && (isDigit(r[i]) || r[i] == '.' || r[i] == 'e' || r[i] == 'E' || r[i] == '+' || r[i] == '-') {
		i++
	}
	return i
}

// scanIdent scans an identifier run.
func scanIdent(r []rune, start int) int {
	i := start
	for i < len(r) && isIdentPart(r[i]) {
		i++
	}
	return i
}

// matchAt reports whether sub matches r at index i.
func matchAt(r []rune, i int, sub []rune) bool {
	if i+len(sub) > len(r) {
		return false
	}
	for k := range sub {
		if r[i+k] != sub[k] {
			return false
		}
	}
	return true
}

func isDigit(c rune) bool      { return c >= '0' && c <= '9' }
func isIdentStart(c rune) bool { return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isIdentPart(c rune) bool  { return isIdentStart(c) || isDigit(c) }

// wordSet builds a set from words.
func wordSet(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// StripANSI removes every CSI SGR escape (ESC [ ... m) from s. Used by tests to
// prove highlighting is color-only (strip(Highlight(x)) == x) and available to
// a caller that needs the plain length of a styled run.
func StripANSI(s string) string {
	var b strings.Builder
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		if runes[i] == '\x1b' && i+1 < len(runes) && runes[i+1] == '[' {
			j := i + 2
			for j < len(runes) && runes[j] != 'm' {
				j++
			}
			if j < len(runes) { // skip the closing 'm'
				i = j + 1
				continue
			}
		}
		b.WriteRune(runes[i])
		i++
	}
	return b.String()
}
