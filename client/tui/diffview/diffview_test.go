// SPDX-License-Identifier: Apache-2.0

package diffview

import (
	"fmt"
	"strings"
	"testing"
)

// countKinds tallies add/del/header/context lines for assertions.
func countKinds(d *Diff) (adds, dels, headers, ctx int) {
	for _, l := range d.Lines {
		switch l.Kind {
		case LineAdd:
			adds++
		case LineDel:
			dels++
		case LineHeader:
			headers++
		case LineContext:
			ctx++
		}
	}
	return
}

// TestReconstructEdit (A6): an Edit input yields a unified diff that keeps the
// shared "foo" line as CONTEXT (LCS line diff, doc 06 Layer 2) and only marks
// the genuine change — "bar" deleted, "baz"/"qux" added.
func TestReconstructEdit(t *testing.T) {
	in := `{"file_path":"/work/main.go","old_string":"foo\nbar","new_string":"foo\nbaz\nqux"}`
	d, ok := Reconstruct("Edit", []byte(in))
	if !ok {
		t.Fatalf("Edit should reconstruct, got ok=false")
	}
	if d.Path != "/work/main.go" {
		t.Errorf("path = %q, want /work/main.go", d.Path)
	}
	adds, dels, headers, ctx := countKinds(d)
	if dels != 1 {
		t.Errorf("dels = %d, want 1 (bar)", dels)
	}
	if adds != 2 {
		t.Errorf("adds = %d, want 2 (baz, qux)", adds)
	}
	if ctx != 1 {
		t.Errorf("ctx = %d, want 1 (foo retained as context)", ctx)
	}
	if headers < 3 { // --- a, +++ b, @@
		t.Errorf("headers = %d, want >= 3", headers)
	}
	pt := d.PlainText()
	if !strings.Contains(pt, " foo") {
		t.Errorf("plain text missing the shared context line ' foo':\n%s", pt)
	}
	if !strings.Contains(pt, "-bar") || !strings.Contains(pt, "+qux") {
		t.Errorf("plain text missing expected change lines:\n%s", pt)
	}
}

// TestReconstructEditContextInLargeBlock (Layer 2): a small edit inside a large
// block emits the unchanged surrounding lines as CONTEXT, NOT all-deletions then
// all-additions — and collapses the FAR context to defaultContextRadius lines on each
// side of the change, re-emitting a "@@ -a,b +c,d @@" hunk header so the actual
// change stays visible under the MaxDiffLines clamp.
func TestReconstructEditContextInLargeBlock(t *testing.T) {
	// 20 identical surrounding lines; a single middle line changes.
	var oldB, newB strings.Builder
	for i := 0; i < 20; i++ {
		line := fmt.Sprintf("line %d", i)
		oldB.WriteString(line)
		if i == 10 {
			newB.WriteString("line 10 CHANGED")
		} else {
			newB.WriteString(line)
		}
		if i < 19 {
			oldB.WriteString("\\n")
			newB.WriteString("\\n")
		}
	}
	in := `{"file_path":"/work/big.go","old_string":"` + oldB.String() + `","new_string":"` + newB.String() + `"}`
	d, ok := Reconstruct("Edit", []byte(in))
	if !ok {
		t.Fatalf("Edit should reconstruct, got ok=false")
	}
	adds, dels, _, ctx := countKinds(d)
	// Exactly the one changed line is a delete + an add.
	if dels != 1 {
		t.Errorf("dels = %d, want 1 (only the changed line removed)", dels)
	}
	if adds != 1 {
		t.Errorf("adds = %d, want 1 (only the changed line added)", adds)
	}
	// Context is collapsed to defaultContextRadius (3) lines each side of the
	// single change — NOT all 19 unchanged lines, NOT zero. This is the
	// load-bearing collapse: it bounds the body so the change survives the clamp.
	if ctx != 2*defaultContextRadius {
		t.Errorf("ctx = %d, want %d (defaultContextRadius lines each side of the change)", ctx, 2*defaultContextRadius)
	}
	// Guard against a regression to the old whole-block behavior: that would emit
	// 20 deletions + 20 additions and ZERO context lines.
	if ctx == 0 {
		t.Errorf("no context lines: regressed to whole-block replacement")
	}
	pt := d.PlainText()
	if !strings.Contains(pt, "-line 10\n") || !strings.Contains(pt, "+line 10 CHANGED\n") {
		t.Errorf("the changed line should be a del+add pair:\n%s", pt)
	}
	// The change anchors a hunk header reporting the collapsed-window span; the
	// 3-line window around line 10 (0-based index 10 => old line 11) starts at
	// old line 8 / new line 8 and spans 7 lines (3 ctx + del/add + 3 ctx,
	// where the del and add overlap one new/old line each).
	if !strings.Contains(pt, "@@ -8,7 +8,7 @@") {
		t.Errorf("expected a re-emitted hunk header for the collapsed window:\n%s", pt)
	}
	// The near context (lines 7..9, 11..13) survives; the FAR context (line 0,
	// line 19) is collapsed away.
	if !strings.Contains(pt, " line 9\n") || !strings.Contains(pt, " line 11\n") {
		t.Errorf("near context should survive (' ' prefix):\n%s", pt)
	}
	if strings.Contains(pt, " line 0\n") || strings.Contains(pt, " line 19\n") {
		t.Errorf("far context should be collapsed away, but appears:\n%s", pt)
	}
}

// TestReconstructWithRadiusCollapsesMoreContext (Layer 2, configurable radius):
// a SMALLER radius keeps FEWER context lines around a change than the default,
// and radius 0 resolves to the default — so a tuned-down radius collapses MORE
// surrounding context over the SAME input. This is the configurable-context-
// radius knob threaded through Reconstruct/RenderOpts; it must not change the
// add/del lines, only how much unchanged context survives.
func TestReconstructWithRadiusCollapsesMoreContext(t *testing.T) {
	// A single middle-line change inside a 20-line block: plenty of context on
	// each side so the radius window is the only thing bounding the context count.
	var oldB, newB strings.Builder
	for i := 0; i < 20; i++ {
		line := fmt.Sprintf("line %d", i)
		oldB.WriteString(line)
		if i == 10 {
			newB.WriteString("line 10 CHANGED")
		} else {
			newB.WriteString(line)
		}
		if i < 19 {
			oldB.WriteString("\\n")
			newB.WriteString("\\n")
		}
	}
	in := `{"file_path":"/work/r.go","old_string":"` + oldB.String() + `","new_string":"` + newB.String() + `"}`

	ctxAt := func(radius int) (ctx, adds, dels int) {
		d, ok := ReconstructWithRadius("Edit", []byte(in), radius)
		if !ok {
			t.Fatalf("radius %d: Edit should reconstruct, got ok=false", radius)
		}
		a, dl, _, c := countKinds(d)
		return c, a, dl
	}

	ctx1, adds1, dels1 := ctxAt(1)
	ctx3, adds3, dels3 := ctxAt(3)
	ctx0, _, _ := ctxAt(0) // 0 => default (3)

	// radius=1 keeps strictly FEWER context lines than radius=3 (more collapsed).
	if !(ctx1 < ctx3) {
		t.Errorf("radius=1 ctx (%d) should be < radius=3 ctx (%d): smaller radius must collapse MORE context", ctx1, ctx3)
	}
	// Exact windows: 2*radius context lines around the lone change.
	if ctx1 != 2*1 {
		t.Errorf("radius=1 ctx = %d, want %d (1 line each side)", ctx1, 2*1)
	}
	if ctx3 != 2*3 {
		t.Errorf("radius=3 ctx = %d, want %d (3 lines each side)", ctx3, 2*3)
	}
	// radius=0 is the default (== radius=3): byte-identical context count.
	if ctx0 != ctx3 {
		t.Errorf("radius=0 ctx (%d) should equal default radius=3 ctx (%d)", ctx0, ctx3)
	}
	if ctx0 != 2*defaultContextRadius {
		t.Errorf("radius=0 ctx = %d, want 2*defaultContextRadius = %d", ctx0, 2*defaultContextRadius)
	}
	// The radius never changes the actual change: same single del + single add.
	if adds1 != 1 || dels1 != 1 || adds3 != 1 || dels3 != 1 {
		t.Errorf("radius must not change the change lines: r1 %d/%d, r3 %d/%d (want 1/1)", adds1, dels1, adds3, dels3)
	}

	// The default Reconstruct (no radius arg) is byte-identical to radius=0 and to
	// radius=3 — the zero/unset radius resolves to the unified-diff default.
	dDefault, _ := Reconstruct("Edit", []byte(in))
	dZero, _ := ReconstructWithRadius("Edit", []byte(in), 0)
	if dDefault.PlainText() != dZero.PlainText() {
		t.Errorf("Reconstruct must be byte-identical to ReconstructWithRadius(..,0):\n--- default ---\n%s\n--- zero ---\n%s",
			dDefault.PlainText(), dZero.PlainText())
	}
}

// TestNegativeRadiusResolvesToDefault: a negative (nonsensical) radius is treated
// as the unset case and resolves to the default, never a panic or empty context.
func TestNegativeRadiusResolvesToDefault(t *testing.T) {
	in := `{"file_path":"/work/n.go","old_string":"a\nb\nc\nd\ne\nf\ng","new_string":"a\nb\nc\nX\ne\nf\ng"}`
	dNeg, ok := ReconstructWithRadius("Edit", []byte(in), -5)
	if !ok {
		t.Fatalf("negative radius should still reconstruct")
	}
	dDef, _ := ReconstructWithRadius("Edit", []byte(in), 0)
	if dNeg.PlainText() != dDef.PlainText() {
		t.Errorf("negative radius must resolve to the default:\n--- neg ---\n%s\n--- def ---\n%s",
			dNeg.PlainText(), dDef.PlainText())
	}
}

// TestEditStaysVisibleUnderClamp (load-bearing, doc 06 Layer 2): a 1-line edit
// in a block far larger than MaxDiffLines must NOT push the change past the
// clamp. Without context collapse the ~2000 leading context lines would clamp at
// MaxDiffLines and the actual change would be LOST; the radius-3 collapse keeps a
// small window around the change so the del/add pair survives the clamp.
func TestEditStaysVisibleUnderClamp(t *testing.T) {
	// total is comfortably over MaxDiffLines(200) so an un-collapsed body would
	// blow the clamp and lose the change, but under maxDiffInputLines so the
	// context-preserving LCS path (not the over-budget fallback) runs.
	const total = 350
	const changeAt = total / 2
	var oldB, newB strings.Builder
	for i := 0; i < total; i++ {
		line := fmt.Sprintf("line %d", i)
		oldB.WriteString(line)
		if i == changeAt {
			newB.WriteString("line CHANGED HERE")
		} else {
			newB.WriteString(line)
		}
		if i < total-1 {
			oldB.WriteString("\\n")
			newB.WriteString("\\n")
		}
	}
	in := `{"file_path":"/work/huge.go","old_string":"` + oldB.String() + `","new_string":"` + newB.String() + `"}`
	d, ok := Reconstruct("Edit", []byte(in))
	if !ok {
		t.Fatalf("Edit should reconstruct, got ok=false")
	}
	// The body stays tiny: one hunk, ~2*radius context + one del + one add.
	if len(d.Lines) > MaxDiffLines {
		t.Errorf("body not collapsed: %d lines > MaxDiffLines(%d)", len(d.Lines), MaxDiffLines)
	}
	if d.Truncated {
		t.Errorf("a collapsed 1-line edit must NOT be Truncated (it fit under the clamp)")
	}
	// The actual change is VISIBLE (not lost past line 200).
	pt := d.PlainText()
	wantDel := fmt.Sprintf("-line %d\n", changeAt)
	if !strings.Contains(pt, wantDel) || !strings.Contains(pt, "+line CHANGED HERE\n") {
		t.Errorf("the change was lost — it must survive the collapse:\n%s", pt)
	}
	adds, dels, _, ctx := countKinds(d)
	if dels != 1 || adds != 1 {
		t.Errorf("adds/dels = %d/%d, want 1/1 (only the changed line)", adds, dels)
	}
	if ctx != 2*defaultContextRadius {
		t.Errorf("ctx = %d, want %d (collapsed window around the lone change)", ctx, 2*defaultContextRadius)
	}
}

// TestOverBudgetInputBoundsDP (input guard, doc 06 Layer 2): an input whose
// total line count exceeds the budget falls back to the cheap whole-block del/add
// path (no O(n*m) LCS table allocated) and sets Truncated, bounding DP cost by the
// render budget.
func TestOverBudgetInputBoundsDP(t *testing.T) {
	// len(old)+len(new) must exceed maxDiffInputLines. Make old large with a
	// shared suffix so an LCS would otherwise find context — but the guard skips
	// the DP entirely, so we get a plain del-then-add body.
	const each = maxDiffInputLines // old=each lines, new=each lines => 2*budget
	var oldB, newB strings.Builder
	for i := 0; i < each; i++ {
		oldB.WriteString(fmt.Sprintf("old %d", i))
		newB.WriteString(fmt.Sprintf("new %d", i))
		if i < each-1 {
			oldB.WriteString("\\n")
			newB.WriteString("\\n")
		}
	}
	in := `{"file_path":"/work/path.go","old_string":"` + oldB.String() + `","new_string":"` + newB.String() + `"}`
	d, ok := Reconstruct("Edit", []byte(in))
	if !ok {
		t.Fatalf("Edit should reconstruct, got ok=false")
	}
	if !d.Truncated {
		t.Errorf("over-budget input must set Truncated (DP bounded by fallback)")
	}
	// Whole-block fallback: deletions precede additions, no context lines, single
	// hunk header — i.e. NO LCS context interleaving.
	_, _, _, ctx := countKinds(d)
	if ctx != 0 {
		t.Errorf("ctx = %d, want 0 (whole-block fallback emits no context)", ctx)
	}
	// Clamped to MaxDiffLines (the output budget) on top of the input bound.
	if len(d.Lines) > MaxDiffLines {
		t.Errorf("over-budget diff not clamped: %d > %d", len(d.Lines), MaxDiffLines)
	}
	pt := d.PlainText()
	if !strings.Contains(pt, fmt.Sprintf("@@ -1,%d +1,%d @@", each, each)) {
		t.Errorf("fallback should report the full old/new spans in the hunk header:\n%s", firstLines(pt, 3))
	}
}

// TestUnderBudgetInputUsesLCS (input guard boundary): an input AT the budget
// still runs the LCS path (context-preserving), proving the guard only trips
// strictly above the budget.
func TestUnderBudgetInputUsesLCS(t *testing.T) {
	// len(old)+len(new) == maxDiffInputLines exactly (not over) with a shared
	// prefix so the LCS keeps context. Half old, half new.
	const half = maxDiffInputLines / 2
	var oldB, newB strings.Builder
	for i := 0; i < half; i++ {
		line := fmt.Sprintf("shared %d", i)
		oldB.WriteString(line)
		// Change exactly one line on the new side.
		if i == 0 {
			newB.WriteString("shared 0 CHANGED")
		} else {
			newB.WriteString(line)
		}
		if i < half-1 {
			oldB.WriteString("\\n")
			newB.WriteString("\\n")
		}
	}
	in := `{"file_path":"/work/edge.go","old_string":"` + oldB.String() + `","new_string":"` + newB.String() + `"}`
	d, ok := Reconstruct("Edit", []byte(in))
	if !ok {
		t.Fatalf("Edit should reconstruct, got ok=false")
	}
	if d.Truncated {
		t.Errorf("at-budget input must NOT trip the input guard (only strictly over does)")
	}
	// LCS path => context lines present (the collapse keeps a window).
	_, _, _, ctx := countKinds(d)
	if ctx == 0 {
		t.Errorf("at-budget input should still run the context-preserving LCS path")
	}
}

// firstLines returns the first n lines of s, for compact failure output.
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// TestReconstructWrite (A6): a Write is a whole-file add (no old side).
func TestReconstructWrite(t *testing.T) {
	in := `{"file_path":"/work/new.txt","content":"line1\nline2\n"}`
	d, ok := Reconstruct("Write", []byte(in))
	if !ok {
		t.Fatalf("Write should reconstruct, got ok=false")
	}
	adds, dels, _, _ := countKinds(d)
	if dels != 0 {
		t.Errorf("Write should have no deletions, got %d", dels)
	}
	if adds != 2 {
		t.Errorf("adds = %d, want 2 (trailing newline dropped)", adds)
	}
}

// TestReconstructMultiEdit (A6): each edit contributes its own old/new block.
func TestReconstructMultiEdit(t *testing.T) {
	in := `{"file_path":"/work/m.go","edits":[` +
		`{"old_string":"a","new_string":"A"},` +
		`{"old_string":"b\nc","new_string":"B"}]}`
	d, ok := Reconstruct("MultiEdit", []byte(in))
	if !ok {
		t.Fatalf("MultiEdit should reconstruct, got ok=false")
	}
	adds, dels, _, _ := countKinds(d)
	if dels != 3 { // a + b + c
		t.Errorf("dels = %d, want 3", dels)
	}
	if adds != 2 { // A + B
		t.Errorf("adds = %d, want 2", adds)
	}
	if !strings.Contains(d.PlainText(), "@@ edit 2 @@") {
		t.Errorf("multi-edit should mark the second edit:\n%s", d.PlainText())
	}
}

// TestReconstructNotebook (A6): notebook source replacement reconstructs over
// either field-name spelling.
func TestReconstructNotebook(t *testing.T) {
	in := `{"notebook_path":"/work/nb.ipynb","cell_id":"c1","old_source":"x = 1","new_source":"x = 2\ny = 3"}`
	d, ok := Reconstruct("NotebookEdit", []byte(in))
	if !ok {
		t.Fatalf("NotebookEdit should reconstruct, got ok=false")
	}
	if d.Path != "/work/nb.ipynb" {
		t.Errorf("path = %q", d.Path)
	}
	if !strings.Contains(d.PlainText(), "cell c1") {
		t.Errorf("notebook header should name the cell:\n%s", d.PlainText())
	}
	adds, dels, _, _ := countKinds(d)
	if dels != 1 || adds != 2 {
		t.Errorf("adds/dels = %d/%d, want 2/1", adds, dels)
	}
}

// TestReconstructEditNoSharedLines (degenerate): when old and new share NO
// lines, the LCS diff reduces to all deletions THEN all additions in standard
// unified-diff order — exactly the prior whole-block behavior, preserved.
func TestReconstructEditNoSharedLines(t *testing.T) {
	in := `{"file_path":"/work/x.go","old_string":"alpha\nbeta","new_string":"gamma\ndelta"}`
	d, ok := Reconstruct("Edit", []byte(in))
	if !ok {
		t.Fatalf("Edit should reconstruct, got ok=false")
	}
	adds, dels, _, ctx := countKinds(d)
	if dels != 2 || adds != 2 || ctx != 0 {
		t.Errorf("adds/dels/ctx = %d/%d/%d, want 2/2/0 (no shared lines)", adds, dels, ctx)
	}
	// All deletions must precede all additions (degenerate whole-block order).
	pt := d.PlainText()
	delIdx := strings.Index(pt, "-beta")
	addIdx := strings.Index(pt, "+gamma")
	if delIdx < 0 || addIdx < 0 || delIdx > addIdx {
		t.Errorf("deletions should precede additions:\n%s", pt)
	}
}

// TestUnsupportedToolFallsBack (A6): a non-file-edit tool returns ok=false so
// the caller renders the existing excerpt.
func TestUnsupportedToolFallsBack(t *testing.T) {
	for _, tool := range []string{"Bash", "Read", "Grep", "ToolSearch", ""} {
		if _, ok := Reconstruct(tool, []byte(`{"command":"ls"}`)); ok {
			t.Errorf("tool %q should NOT reconstruct a diff", tool)
		}
	}
}

// TestMalformedInputNoPanic (A6): malformed / unexpected input shapes return
// ok=false and do NOT panic.
func TestMalformedInputNoPanic(t *testing.T) {
	cases := []struct {
		tool, input string
	}{
		{"Edit", `not json at all`},
		{"Edit", `{"file_path":"/x"}`}, // no old/new strings
		{"Edit", ``},                   // empty
		{"Write", `{"content":"x"}`},   // no path
		{"Write", `{`},                 // truncated json
		{"MultiEdit", `{"file_path":"/x","edits":[]}`},
		{"MultiEdit", `{"file_path":"/x"}`},
		{"NotebookEdit", `{"cell_id":"c1"}`}, // no path/source
		{"NotebookEdit", `[1,2,3]`},          // wrong json type
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Reconstruct(%q, %q) panicked: %v", c.tool, c.input, r)
				}
			}()
			if d, ok := Reconstruct(c.tool, []byte(c.input)); ok {
				t.Errorf("Reconstruct(%q, %q) should fall back (ok=false), got %+v", c.tool, c.input, d)
			}
		}()
	}
}

// TestSummary: the panel-header summary names the tool, path, and add/del
// counts deterministically.
func TestSummary(t *testing.T) {
	d, ok := Reconstruct("Edit", []byte(`{"file_path":"/a","old_string":"x","new_string":"y\nz"}`))
	if !ok {
		t.Fatalf("reconstruct failed")
	}
	got := d.Summary()
	if !strings.Contains(got, "Edit /a") || !strings.Contains(got, "+2 -1") {
		t.Errorf("summary = %q, want Edit /a +2 -1", got)
	}
	// Nil-safe.
	var nild *Diff
	if nild.Summary() != "" || nild.PlainText() != "" {
		t.Errorf("nil diff should render empty")
	}
}

// TestClampTruncates: a huge Write is clamped to MaxDiffLines and flagged.
func TestClampTruncates(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"file_path":"/big","content":"`)
	for i := 0; i < MaxDiffLines+50; i++ {
		b.WriteString("line\\n")
	}
	b.WriteString(`"}`)
	d, ok := Reconstruct("Write", []byte(b.String()))
	if !ok {
		t.Fatalf("reconstruct failed")
	}
	if !d.Truncated {
		t.Errorf("expected Truncated for an oversized Write")
	}
	if len(d.Lines) > MaxDiffLines {
		t.Errorf("diff not clamped: %d lines > %d", len(d.Lines), MaxDiffLines)
	}
	if !strings.Contains(d.Summary(), "truncated") {
		t.Errorf("summary should note truncation: %q", d.Summary())
	}
}
