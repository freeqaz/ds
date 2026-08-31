// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/tui"
)

// A tiny self-contained attach.v1 NDJSON stream: a session.init, a chat message,
// and an Edit tool-invoked/completed pair. The Edit is what the Layer-2 diff and
// Layer-5 panel enrichments reconstruct, so a --diffs/--panels render differs
// from the plain golden while a default render does not.
const sampleNDJSON = `{"seq":1,"session_id":"00000000-0000-4000-8000-000000000010","type":"session.init","session_init":{"runtime_version":"2.1.0","model":"claude","cwd":"/work","tools":["Edit"]}}
{"seq":2,"session_id":"00000000-0000-4000-8000-000000000010","type":"chat.message","chat_message":{"message_id":"m1","role":"assistant","blocks":[{"kind":"text","text":"editing"}]}}
{"seq":3,"session_id":"00000000-0000-4000-8000-000000000010","type":"tool.invoked","tool_invoked":{"node_id":"n1","name":"Edit","turn_group":"t1","input":{"file_path":"/work/a.go","old_string":"foo","new_string":"bar"}}}
{"seq":4,"session_id":"00000000-0000-4000-8000-000000000010","type":"tool.completed","tool_completed":{"node_id":"n1","output_excerpt":"ok"}}
`

func buildSample(t *testing.T) *tui.Model {
	t.Helper()
	m, _, err := tui.BuildModel(strings.NewReader(sampleNDJSON), tui.RoleReader, 0)
	if err != nil {
		t.Fatalf("BuildModel: %v", err)
	}
	return m
}

// TestOptsFromFlags proves the flag toggles map onto the right RenderOpts fields
// and that the all-default case is the zero RenderOpts (the byte-identical
// baseline contract).
func TestOptsFromFlags(t *testing.T) {
	if got := optsFrom(false, false, false, false); got != (tui.RenderOpts{}) {
		t.Errorf("all-default optsFrom = %+v, want zero RenderOpts", got)
	}
	got := optsFrom(true, true, true, true)
	want := tui.RenderOpts{Diffs: true, Highlight: true, Panels: true, Expanded: true}
	if got != want {
		t.Errorf("optsFrom(all true) = %+v, want %+v", got, want)
	}
	// Each toggle is independent.
	if got := optsFrom(true, false, false, false); !got.Diffs || got.Highlight || got.Panels || got.Expanded {
		t.Errorf("optsFrom(diffs only) = %+v, want only Diffs", got)
	}
}

// TestDefaultRenderIsByteIdenticalToPlainGolden proves the no-flag default render
// (renderModel with zero opts, color on) is byte-identical to the prior
// `tui.Replay` plain golden — default-off changes nothing.
func TestDefaultRenderIsByteIdenticalToPlainGolden(t *testing.T) {
	m := buildSample(t)

	var golden bytes.Buffer
	if err := tui.RenderPlain(&golden, m); err != nil {
		t.Fatalf("RenderPlain golden: %v", err)
	}

	var got bytes.Buffer
	if err := renderModel(&got, m, false /*noColor*/, tui.RenderOpts{}); err != nil {
		t.Fatalf("renderModel default: %v", err)
	}
	if !bytes.Equal(golden.Bytes(), got.Bytes()) {
		t.Errorf("default render must equal the plain golden\n--- golden ---\n%s\n--- got ---\n%s", golden.String(), got.String())
	}
}

// TestNoColorRoutesToRenderPlain proves --no-color renders the byte-stable plain
// surface even when enrichment toggles are ALSO set (the plain golden never
// highlights/diffs/groups, doc 06 §4.2).
func TestNoColorRoutesToRenderPlain(t *testing.T) {
	m := buildSample(t)

	var golden bytes.Buffer
	if err := tui.RenderPlain(&golden, m); err != nil {
		t.Fatalf("RenderPlain golden: %v", err)
	}

	// --no-color with every enrichment toggle set: still the plain golden.
	var got bytes.Buffer
	opts := tui.RenderOpts{Diffs: true, Highlight: true, Panels: true, Expanded: true}
	if err := renderModel(&got, m, true /*noColor*/, opts); err != nil {
		t.Fatalf("renderModel --no-color: %v", err)
	}
	if !bytes.Equal(golden.Bytes(), got.Bytes()) {
		t.Errorf("--no-color must equal the plain golden regardless of opts\n--- golden ---\n%s\n--- got ---\n%s", golden.String(), got.String())
	}
}

// TestEnrichmentRoutesToRenderRich proves a render with --diffs/--panels (color
// on) routes to RenderRich and differs from the plain golden (the enrichment is
// actually applied), without panicking.
func TestEnrichmentRoutesToRenderRich(t *testing.T) {
	m := buildSample(t)

	var plain bytes.Buffer
	if err := tui.RenderPlain(&plain, m); err != nil {
		t.Fatalf("RenderPlain: %v", err)
	}

	var rich bytes.Buffer
	opts := tui.RenderOpts{Diffs: true, Panels: true, Expanded: true}
	if err := renderModel(&rich, m, false /*noColor*/, opts); err != nil {
		t.Fatalf("renderModel enriched: %v", err)
	}

	// The enriched render must match tui.RenderRich exactly (renderModel routes to
	// it) and must DIFFER from the plain golden (the panel/diff is shown).
	var want bytes.Buffer
	if err := tui.RenderRich(&want, m, opts); err != nil {
		t.Fatalf("RenderRich: %v", err)
	}
	if !bytes.Equal(rich.Bytes(), want.Bytes()) {
		t.Errorf("renderModel(enriched) must equal RenderRich\n--- got ---\n%s\n--- want ---\n%s", rich.String(), want.String())
	}
	if bytes.Equal(rich.Bytes(), plain.Bytes()) {
		t.Errorf("enriched render must differ from the plain golden (enrichment not applied)")
	}
}
