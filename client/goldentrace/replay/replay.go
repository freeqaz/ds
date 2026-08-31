// Package replay drives captured cassettes through the runtime adapter and
// returns the dreamserpent.attach.v1 projection (D49). The golden-diff
// machinery works on any []attach.Event; only Replay itself names the
// claude-code adapter, because that is the cassette dialect under test
// (client/fixtures/*.cc-wire.ndjson, synthetic-only per D50).
//
// Determinism: Replay pins the adapter clock so goldens are byte-stable
// across runs — a protocol change shows up as a reviewable golden diff, never
// a silent rewrite (the insta-style refresh flow, ../README.md).
package replay

import (
	"encoding/json"
	"io"
	"time"

	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Replay drives a CC cassette through the claude-code adapter and returns the
// attach.v1 projection. The ds_fixture header (line 1) is skipped by Feed.
// The adapter clock is deterministic: 2026-01-01T00:00:00Z plus one second
// per clock call.
func Replay(r io.Reader) ([]attach.Event, error) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := 0
	a := claudecode.New(claudecode.WithClock(func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}))
	return a.ProcessStream(r)
}

// WriteNDJSON writes one event per line via encoding/json — the golden
// serialization the byte-compare runs against.
func WriteNDJSON(w io.Writer, evs []attach.Event) error {
	enc := json.NewEncoder(w)
	for _, ev := range evs {
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	return nil
}
