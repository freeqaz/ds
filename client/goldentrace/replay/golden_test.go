package replay

import (
	"bytes"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// -update regenerates goldens: a protocol change is a reviewable golden diff,
// never a silent rewrite (insta-style refresh, ../README.md).
var update = flag.Bool("update", false, "regenerate golden files under testdata/ instead of comparing")

const (
	cassetteSuffix = ".cc-wire.ndjson"
	goldenSuffix   = ".attach.ndjson"
)

// TestGoldens replays every committed cassette and byte-compares the
// projection against its golden. Goldens are derived artifacts and live under
// testdata/ — NOT a fixtures/ dir, which the D50 provenance gate scans.
func TestGoldens(t *testing.T) {
	cassettes, err := filepath.Glob(filepath.FromSlash("../../fixtures/*" + cassetteSuffix))
	if err != nil {
		t.Fatalf("glob cassettes: %v", err)
	}
	if len(cassettes) == 0 {
		t.Fatal("no *.cc-wire.ndjson cassettes found under client/fixtures/")
	}

	for _, cassette := range cassettes {
		base := strings.TrimSuffix(filepath.Base(cassette), cassetteSuffix)
		t.Run(base, func(t *testing.T) {
			f, err := os.Open(cassette)
			if err != nil {
				t.Fatalf("open cassette: %v", err)
			}
			defer f.Close()

			evs, err := Replay(f)
			if err != nil {
				t.Fatalf("replay %s: %v", cassette, err)
			}
			validateEvents(t, evs)

			var got bytes.Buffer
			if err := WriteNDJSON(&got, evs); err != nil {
				t.Fatalf("encode events: %v", err)
			}

			golden := filepath.Join("testdata", base+goldenSuffix)
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatalf("mkdir testdata: %v", err)
				}
				if err := os.WriteFile(golden, got.Bytes(), 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}

			want, err := os.ReadFile(golden)
			if errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("golden %s does not exist for cassette %s.\n"+
					"Generate it with:\n"+
					"    cd client && go test ./goldentrace/replay -run TestGoldens -update\n"+
					"then review the new golden like a diff before committing.", golden, cassette)
			}
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if !bytes.Equal(want, got.Bytes()) {
				t.Errorf("projection of %s diverges from golden %s.\n"+
					"If the change is intended, regenerate with -update and review the diff.\n"+
					"--- got ---\n%s\n--- want ---\n%s", cassette, golden, got.String(), want)
			}
		})
	}
}

// validateEvents asserts stream well-formedness for any []attach.Event:
// seq strictly monotonic from 1 (emission order, P10), constant session_id,
// and exactly one payload pointer non-nil per event.
func validateEvents(t *testing.T, evs []attach.Event) {
	t.Helper()
	if len(evs) == 0 {
		t.Fatal("replay produced no events")
	}
	session := evs[0].SessionID
	if session == "" {
		t.Error("first event has empty session_id")
	}
	for i, ev := range evs {
		if want := uint64(i + 1); ev.Seq != want {
			t.Errorf("event %d (%s): seq = %d, want %d (strictly monotonic from 1)", i, ev.Type, ev.Seq, want)
		}
		if ev.SessionID != session {
			t.Errorf("event %d (%s): session_id = %q, want constant %q", i, ev.Type, ev.SessionID, session)
		}
		if n := payloadCount(ev); n != 1 {
			t.Errorf("event %d (%s): %d payload pointers set, want exactly 1", i, ev.Type, n)
		}
	}
}

// payloadCount counts the non-nil payload pointers on the event envelope.
func payloadCount(ev attach.Event) int {
	v := reflect.ValueOf(ev)
	n := 0
	for i := 0; i < v.NumField(); i++ {
		if f := v.Field(i); f.Kind() == reflect.Pointer && !f.IsNil() {
			n++
		}
	}
	return n
}
