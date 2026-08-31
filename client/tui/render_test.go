package tui

import (
	"bytes"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -update regenerates the render goldens under testdata/ — a render change is a
// reviewable golden diff, never a silent rewrite (the goldentrace insta-style
// pattern, ../goldentrace/README.md).
var update = flag.Bool("update", false, "regenerate render goldens under testdata/")

// cassettes is the source of the attach.v1 replay goldens. They are produced
// and validated by ../goldentrace/replay (the adapter projection golden); the
// TUI render tests consume them as input fixtures — the spec's at-least set
// (baseline-chat, ask-control, subagent-spawn) plus the rest for coverage.
const replayGoldenDir = "../goldentrace/replay/testdata"

// TestRenderGoldens replays every committed attach.v1 golden through the TUI
// model + plain renderer and byte-compares the structured render against its
// committed render golden. This is the deterministic render test the brief's
// DONE gate requires: the binary replays a cassette end-to-end and renders
// structured output, pinned byte-for-byte.
func TestRenderGoldens(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join(replayGoldenDir, "*.attach.ndjson"))
	if err != nil {
		t.Fatalf("glob attach goldens: %v", err)
	}
	if len(inputs) == 0 {
		t.Fatalf("no *.attach.ndjson goldens under %s", replayGoldenDir)
	}
	// Guard the spec's required set explicitly: a missing one is a real gap.
	want := map[string]bool{"baseline-chat": false, "ask-control": false, "subagent-spawn": false}

	for _, in := range inputs {
		base := strings.TrimSuffix(filepath.Base(in), ".attach.ndjson")
		if _, ok := want[base]; ok {
			want[base] = true
		}
		t.Run(base, func(t *testing.T) {
			src, err := os.ReadFile(in)
			if err != nil {
				t.Fatalf("read input %s: %v", in, err)
			}
			var got bytes.Buffer
			if _, err := Replay(bytes.NewReader(src), &got); err != nil {
				t.Fatalf("replay %s: %v", in, err)
			}

			golden := filepath.Join("testdata", base+".render.txt")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatalf("mkdir testdata: %v", err)
				}
				if err := os.WriteFile(golden, got.Bytes(), 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			wantBytes, err := os.ReadFile(golden)
			if errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("render golden %s missing; regenerate with:\n"+
					"    cd client && go test ./tui -run TestRenderGoldens -update\n"+
					"then review the new golden before committing.", golden)
			}
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if !bytes.Equal(wantBytes, got.Bytes()) {
				t.Errorf("render of %s diverges from golden %s.\n--- got ---\n%s\n--- want ---\n%s",
					in, golden, got.String(), string(wantBytes))
			}
		})
	}

	for name, seen := range want {
		if !seen {
			t.Errorf("required cassette %q not present under %s — the spec names it explicitly", name, replayGoldenDir)
		}
	}
}
