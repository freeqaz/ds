// SPDX-License-Identifier: Apache-2.0

package highlight

import (
	"strings"
	"testing"
)

// TestColorOnly is the load-bearing Layer-3 invariant (A7): highlighting only
// ADDS ANSI SGR escapes — stripping them yields the original source byte-for-
// byte. This is what keeps the plain golden surface safe: the renderer can
// highlight freely in Render() knowing it never mutates the underlying text.
func TestColorOnly(t *testing.T) {
	samples := map[Lang]string{
		Bash:   "if [ -f x ]; then\n  echo \"hi # not a comment\" # real comment\nfi\n",
		Go:     "func main() {\n\tx := 42 // count\n\treturn nil\n}",
		Python: "def f(n):\n    return n + 1  # add one\n",
		JSON:   "{\"file_path\": \"/a/b.go\", \"n\": -12.5, \"ok\": true}",
		Diff:   "--- a/x\n+++ b/x\n@@ -1,1 +1,2 @@\n-old\n+new1\n+new2\n",
		// An unknown language is identity.
		Unknown: "anything at all\nwith lines",
	}
	for lang, src := range samples {
		got := Highlight(lang, src)
		if stripped := StripANSI(got); stripped != src {
			t.Errorf("lang %q: strip(Highlight) != src\n got:  %q\n want: %q", lang, stripped, src)
		}
	}
}

// TestUnknownIsIdentity: an unknown language returns the source unchanged (no
// escapes at all).
func TestUnknownIsIdentity(t *testing.T) {
	src := "some := text // 123 \"q\""
	if got := Highlight(Unknown, src); got != src {
		t.Errorf("Unknown should be identity, got %q", got)
	}
	if got := Highlight(LangFor("rust"), src); got != src {
		t.Errorf("unrecognized fence tag should be identity, got %q", got)
	}
}

// TestEmptyAndNewlinePreserved: empty input and newline structure round-trip.
func TestEmptyAndNewlinePreserved(t *testing.T) {
	for _, lang := range []Lang{Bash, Go, Python, JSON, Diff} {
		if got := Highlight(lang, ""); got != "" {
			t.Errorf("lang %q: empty should stay empty, got %q", lang, got)
		}
		// No trailing newline must be preserved (not added).
		src := "x"
		if strings.HasSuffix(StripANSI(Highlight(lang, src)), "\n") {
			t.Errorf("lang %q: highlighter added a trailing newline", lang)
		}
	}
}

// TestHighlightAddsColor: a recognized token actually gets an escape (so the
// highlighter is doing something, not a silent identity for everything).
func TestHighlightAddsColor(t *testing.T) {
	if !strings.Contains(Highlight(Go, "func x"), "\x1b[") {
		t.Errorf("Go keyword should be colored")
	}
	if !strings.Contains(Highlight(JSON, `{"a":1}`), "\x1b[") {
		t.Errorf("JSON should be colored")
	}
	if !strings.Contains(Highlight(Diff, "+added"), "\x1b[") {
		t.Errorf("diff add line should be colored")
	}
}

// TestLangFor covers the alias normalization.
func TestLangFor(t *testing.T) {
	cases := map[string]Lang{
		"sh": Bash, "shell": Bash, "BASH": Bash,
		"golang": Go, "Go": Go,
		"py": Python, "python3": Python,
		"jsonc": JSON,
		"patch": Diff, "udiff": Diff,
		"":     Unknown,
		"toml": Unknown,
	}
	for tag, want := range cases {
		if got := LangFor(tag); got != want {
			t.Errorf("LangFor(%q) = %q, want %q", tag, got, want)
		}
	}
}

// TestHighlightDiffLinesMatchesPrefixPath (Kind-driven == prefix-parse golden):
// coloring a structured diff by Kind must be BYTE-IDENTICAL to running the
// prefix-scanning classifyDiffLine over the same diff serialized as text. This is
// the golden that lets renderDiff drop the re-serialize+re-parse round-trip: for
// a well-formed diff the two paths produce the same bytes.
func TestHighlightDiffLinesMatchesPrefixPath(t *testing.T) {
	// A representative unified diff: file headers, a hunk header, context, del, add.
	lines := []DiffLine{
		{DiffHeader, "--- a/x.go"},
		{DiffHeader, "+++ b/x.go"},
		{DiffHeader, "@@ -8,7 +8,7 @@"},
		{DiffContext, " line 8"},
		{DiffContext, " line 9"},
		{DiffDel, "-line 10"},
		{DiffAdd, "+line 10 CHANGED"},
		{DiffContext, " line 11"},
		{DiffHeader, "@@ edit 2 @@"}, // the MultiEdit inter-edit header
	}

	// Build the serialized body the OLD path fed to Highlight(Diff, body): each
	// line's Text + "\n" (exactly what diffview.PlainText() produces).
	var raw strings.Builder
	for _, l := range lines {
		raw.WriteString(l.Text)
		raw.WriteByte('\n')
	}
	prefixPath := Highlight(Diff, raw.String())
	kindPath := HighlightDiffLines(lines)

	if kindPath != prefixPath {
		t.Errorf("Kind-driven coloring must be byte-identical to the prefix path:\n--- kind ---\n%q\n--- prefix ---\n%q", kindPath, prefixPath)
	}
	// Color-only: stripping ANSI from the Kind path yields the original body.
	if got := StripANSI(kindPath); got != raw.String() {
		t.Errorf("HighlightDiffLines must be color-only: strip != raw\n got:  %q\n want: %q", got, raw.String())
	}
	// And it actually colors (not a silent identity).
	if !strings.Contains(kindPath, "\x1b[") {
		t.Errorf("HighlightDiffLines should add ANSI escapes for a colored diff")
	}
}

// TestHighlightDiffLinesEmpty: an empty slice yields "" (matching the empty-body
// behavior of the prefix path).
func TestHighlightDiffLinesEmpty(t *testing.T) {
	if got := HighlightDiffLines(nil); got != "" {
		t.Errorf("HighlightDiffLines(nil) = %q, want empty", got)
	}
	if got := HighlightDiffLines([]DiffLine{}); got != "" {
		t.Errorf("HighlightDiffLines(empty) = %q, want empty", got)
	}
}

// TestHighlightDiffLinesContextUncolored: a context line (no +/-/@@ prefix and
// DiffContext kind) is emitted verbatim — no escapes — matching classifyDiffLine's
// default branch.
func TestHighlightDiffLinesContextUncolored(t *testing.T) {
	got := HighlightDiffLines([]DiffLine{{DiffContext, " unchanged"}})
	if got != " unchanged\n" {
		t.Errorf("context line should be uncolored: got %q, want %q", got, " unchanged\n")
	}
}

// TestDiffPrefixScanIsKindOnly (retired-prefix-color unification): the legacy
// Highlight(Diff, src) text path now classifies a serialized line into a
// DiffLineKind via kindForDiffPrefix and defers coloring to the SAME
// colorForDiffKind the structured HighlightDiffLines path uses — there is one
// diff palette, so the two paths can never drift. This pins (a) the prefix scan
// maps each glyph to the expected Kind, and (b) a single line colored via the
// text path is byte-identical to the same line colored via the Kind path.
func TestDiffPrefixScanIsKindOnly(t *testing.T) {
	cases := []struct {
		line string
		kind DiffLineKind
	}{
		{"--- a/x.go", DiffHeader},
		{"+++ b/x.go", DiffHeader},
		{"@@ -1,1 +1,2 @@", DiffHeader},
		{"@@ edit 2 @@", DiffHeader},
		{"+added", DiffAdd},
		{"-removed", DiffDel},
		{" context", DiffContext},
		{"", DiffContext},
	}
	for _, c := range cases {
		if got := kindForDiffPrefix(c.line); got != c.kind {
			t.Errorf("kindForDiffPrefix(%q) = %v, want %v", c.line, got, c.kind)
		}
		// The single-line text path and the single-line Kind path must agree
		// byte-for-byte (same palette, no drift).
		textPath := Highlight(Diff, c.line+"\n")
		kindPath := HighlightDiffLines([]DiffLine{{c.kind, c.line}})
		if textPath != kindPath {
			t.Errorf("line %q: text path %q != kind path %q", c.line, textPath, kindPath)
		}
	}
}

// TestBashCommentInString: a '#' inside a double-quoted string is NOT treated
// as a comment (the splitComment quote-awareness), and the whole line still
// strips back to the source.
func TestBashCommentInString(t *testing.T) {
	src := `echo "color #fff here" # trailing`
	got := Highlight(Bash, src)
	if StripANSI(got) != src {
		t.Errorf("strip mismatch: %q != %q", StripANSI(got), src)
	}
}
