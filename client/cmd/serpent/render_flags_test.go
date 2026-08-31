// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"flag"
	"sort"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/tui"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// parseRender registers the render flags on a fresh flagset and parses args.
func parseRender(t *testing.T, args ...string) renderFlags {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	r := registerRenderFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return r
}

// TestRenderFlagsDefaultOff proves an unset flagset yields no env entries, the
// zero RenderOpts, and any()==false — the default-off, byte-identical baseline.
func TestRenderFlagsDefaultOff(t *testing.T) {
	r := parseRender(t)
	if env := r.env(); len(env) != 0 {
		t.Errorf("default env = %v, want empty (no DS_TUI_* set when no flag given)", env)
	}
	if got := r.opts(); got != (tui.RenderOpts{}) {
		t.Errorf("default opts = %+v, want zero RenderOpts", got)
	}
	if r.any() {
		t.Errorf("default any() = true, want false")
	}
	if r.noColorSet() {
		t.Errorf("default noColorSet() = true, want false")
	}
}

// TestRenderFlagsEnvGate proves each --flag maps onto the right DS_TUI_* env
// entry (the disjoint relay the serpent-tui loop reads), and that opts() reflects
// the enrichment toggles (excluding --no-color, a color decision).
func TestRenderFlagsEnvGate(t *testing.T) {
	r := parseRender(t, "--diffs", "--highlight", "--panels", "--expanded", "--no-color")

	got := r.env()
	sort.Strings(got)
	want := []string{
		"DS_TUI_DIFFS=1",
		"DS_TUI_EXPANDED=1",
		"DS_TUI_HIGHLIGHT=1",
		"DS_TUI_NO_COLOR=1",
		"DS_TUI_PANELS=1",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("env = %v, want %v", got, want)
	}

	if opts := r.opts(); opts != (tui.RenderOpts{Diffs: true, Highlight: true, Panels: true, Expanded: true}) {
		t.Errorf("opts = %+v, want all enrichment true", opts)
	}
	if !r.noColorSet() {
		t.Errorf("noColorSet() = false, want true after --no-color")
	}
	if !r.any() {
		t.Errorf("any() = false, want true")
	}
}

// TestRenderFlagsEnvOnlySetFlags proves env() emits ONLY the flags that were set
// (a single --panels yields just its entry), so an unset toggle never leaks into
// the child environment.
func TestRenderFlagsEnvOnlySetFlags(t *testing.T) {
	r := parseRender(t, "--panels")
	got := r.env()
	if len(got) != 1 || got[0] != "DS_TUI_PANELS=1" {
		t.Errorf("env = %v, want [DS_TUI_PANELS=1] only", got)
	}
	if opts := r.opts(); opts != (tui.RenderOpts{Panels: true}) {
		t.Errorf("opts = %+v, want Panels only", opts)
	}
}

// TestContextRadiusFlagEnvRelay proves the --context-radius int flag relays as
// DS_TUI_CONTEXT_RADIUS=N ONLY when set positive: unset or 0 emits no entry (so
// the child env stays the byte-identical default-off case), a positive value emits
// the int entry, and opts() threads it into RenderOpts.ContextRadius. It is NOT an
// enrichment toggle — a bare --context-radius leaves opts otherwise zero.
func TestContextRadiusFlagEnvRelay(t *testing.T) {
	// Unset ⇒ no env entry, and opts stays the zero RenderOpts.
	if env := parseRender(t).env(); len(env) != 0 {
		t.Errorf("unset --context-radius env = %v, want empty (no DS_TUI_CONTEXT_RADIUS)", env)
	}

	// Explicit 0 ⇒ still no entry (0 means diffview's default; adds nothing).
	if env := parseRender(t, "--context-radius", "0").env(); len(env) != 0 {
		t.Errorf("--context-radius=0 env = %v, want empty (0 ⇒ diffview default, no entry)", env)
	}

	// Positive ⇒ exactly the int entry, and opts threads ContextRadius.
	r := parseRender(t, "--context-radius", "5")
	if env := r.env(); len(env) != 1 || env[0] != "DS_TUI_CONTEXT_RADIUS=5" {
		t.Errorf("--context-radius=5 env = %v, want [DS_TUI_CONTEXT_RADIUS=5] only", env)
	}
	if opts := r.opts(); opts != (tui.RenderOpts{ContextRadius: 5}) {
		t.Errorf("--context-radius=5 opts = %+v, want only ContextRadius=5 (not an enrichment toggle)", opts)
	}
	// A bare context radius does NOT request enrichment (any() is the --no-color/
	// enrichment relay; ContextRadius rides opts only).
	if r.noColorSet() {
		t.Errorf("--context-radius must not set noColorSet()")
	}

	// A negative value clamps to 0 (no entry, no widening), never a launch failure.
	if env := parseRender(t, "--context-radius", "-3").env(); len(env) != 0 {
		t.Errorf("--context-radius=-3 env = %v, want empty (clamped to 0)", env)
	}
	if opts := parseRender(t, "--context-radius", "-3").opts(); opts != (tui.RenderOpts{}) {
		t.Errorf("--context-radius=-3 opts = %+v, want zero (negative clamps to 0)", opts)
	}
}

// driveSampleEvents is a tiny projected attach.v1 stream (session.init + an Edit
// tool pair) for the drive structured-render test.
func driveSampleEvents() []attach.Event {
	return []attach.Event{
		{Seq: 1, SessionID: "s", Type: attach.TypeSessionInit, SessionInit: &attach.SessionInit{RuntimeVersion: "2.1.0", Model: "claude", CWD: "/work"}},
		{Seq: 2, SessionID: "s", Type: attach.TypeToolInvoked, ToolInvoked: &attach.ToolInvoked{
			NodeID: "n1", Name: "Edit", TurnGroup: "t1",
			Input: []byte(`{"file_path":"/work/a.go","old_string":"foo","new_string":"bar"}`),
		}},
		{Seq: 3, SessionID: "s", Type: attach.TypeToolCompleted, ToolCompleted: &attach.ToolCompleted{NodeID: "n1", OutputExcerpt: "ok"}},
	}
}

// foldPlain renders the projected events through the plain golden surface, the
// reference renderDriveProjection must match in --no-color mode.
func foldPlain(t *testing.T, events []attach.Event) string {
	t.Helper()
	m := tui.NewModel()
	for _, ev := range events {
		if err := m.Apply(ev); err != nil {
			t.Fatalf("apply seq %d: %v", ev.Seq, err)
		}
	}
	var b bytes.Buffer
	if err := tui.RenderPlain(&b, m); err != nil {
		t.Fatalf("RenderPlain: %v", err)
	}
	return b.String()
}

// TestRenderDriveProjectionNoColorIsPlain proves --no-color routes the drive
// projection render to the byte-stable RenderPlain surface (the plain golden),
// even with enrichment toggles also set.
func TestRenderDriveProjectionNoColorIsPlain(t *testing.T) {
	events := driveSampleEvents()
	wantTail := foldPlain(t, events)

	r := parseRender(t, "--no-color", "--diffs", "--panels")
	var got bytes.Buffer
	if err := renderDriveProjection(&got, events, r); err != nil {
		t.Fatalf("renderDriveProjection: %v", err)
	}
	if !strings.HasSuffix(got.String(), wantTail) {
		t.Errorf("--no-color drive render must end with the plain golden\n--- got ---\n%s\n--- want tail ---\n%s", got.String(), wantTail)
	}
}

// TestRenderDriveProjectionEnrichedDiffers proves an enriched drive render
// (--diffs --panels --expanded) differs from the plain golden (the enrichment is
// applied) and does not panic on the Edit input.
func TestRenderDriveProjectionEnrichedDiffers(t *testing.T) {
	events := driveSampleEvents()
	plainTail := foldPlain(t, events)

	r := parseRender(t, "--diffs", "--panels", "--expanded")
	var got bytes.Buffer
	if err := renderDriveProjection(&got, events, r); err != nil {
		t.Fatalf("renderDriveProjection: %v", err)
	}
	if strings.HasSuffix(got.String(), plainTail) {
		t.Errorf("enriched drive render must differ from the plain golden (enrichment not applied)\n%s", got.String())
	}
}
