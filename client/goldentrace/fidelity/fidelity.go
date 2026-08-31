// fidelity.go — the projection-equality engine and the cassette-file runner.
//
// ProjectionEqual is the assertion at the heart of the fidelity loop: two
// projections are EQUAL iff their id-relative canonical forms match line for
// line. A mismatch yields a reviewable, human-readable diff naming the first
// divergent event — a STALE cassette or genuine CC DRIFT (CIA's API-plane
// capture distinguishes which; DRIVE-PROTOCOL.md).
package fidelity

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/replay"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// ProjectStream projects one CC-wire stream (a *.cc-wire.ndjson reader) to the
// attach.v1 event slice via the SAME claude-code adapter the goldens use
// (replay.Replay) — the one place a runtime dialect is named. This is the
// projection both legs of the fidelity loop share.
func ProjectStream(r io.Reader) ([]attach.Event, error) {
	return replay.Replay(r)
}

// ProjectFile projects a cassette file by path.
func ProjectFile(path string) ([]attach.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("fidelity: open cassette %s: %w", path, err)
	}
	defer f.Close()
	evs, err := ProjectStream(f)
	if err != nil {
		return nil, fmt.Errorf("fidelity: project %s: %w", path, err)
	}
	return evs, nil
}

// Diff is the structured outcome of a projection-equality check. Equal is the
// verdict; Report is the empty string when equal, else a reviewable diff.
type Diff struct {
	Equal  bool
	Report string
}

// EqualProjections canonicalizes both projections (id-relative, timing-erased)
// and compares them line for line. The labels name the two legs in the diff
// (e.g. "synthetic" vs "live", or "synthetic" vs "recorded").
func EqualProjections(aLabel string, a []attach.Event, bLabel string, b []attach.Event) Diff {
	ca := Canonicalize(a)
	cb := Canonicalize(b)
	return compareCanon(aLabel, ca, bLabel, cb)
}

// EqualStreams projects two CC-wire streams and compares their projections
// id-relative. This is the cassette-vs-cassette form used by the always-on
// fidelity test (synthetic re-authored vs a committed recorded-equivalent).
func EqualStreams(aLabel string, a io.Reader, bLabel string, b io.Reader) (Diff, error) {
	ea, err := ProjectStream(a)
	if err != nil {
		return Diff{}, fmt.Errorf("fidelity: project %s: %w", aLabel, err)
	}
	eb, err := ProjectStream(b)
	if err != nil {
		return Diff{}, fmt.Errorf("fidelity: project %s: %w", bLabel, err)
	}
	return EqualProjections(aLabel, ea, bLabel, eb), nil
}

// EqualFiles is EqualStreams over two cassette paths.
func EqualFiles(aPath, bPath string) (Diff, error) {
	a, err := os.Open(aPath)
	if err != nil {
		return Diff{}, fmt.Errorf("fidelity: open %s: %w", aPath, err)
	}
	defer a.Close()
	b, err := os.Open(bPath)
	if err != nil {
		return Diff{}, fmt.Errorf("fidelity: open %s: %w", bPath, err)
	}
	defer b.Close()
	return EqualStreams(aPath, a, bPath, b)
}

// compareCanon does the line-for-line canon comparison and renders the diff.
func compareCanon(aLabel string, a Canon, bLabel string, b Canon) Diff {
	if len(a.Events) != len(b.Events) {
		return Diff{
			Equal: false,
			Report: fmt.Sprintf(
				"projection length diverges: %s has %d events, %s has %d.\n%s",
				aLabel, len(a.Events), bLabel, len(b.Events),
				renderSideBySide(aLabel, a, bLabel, b)),
		}
	}
	for i := range a.Events {
		if !bytes.Equal(a.Events[i], b.Events[i]) {
			return Diff{
				Equal: false,
				Report: fmt.Sprintf(
					"projection diverges at event %d (id-relative canonical form):\n"+
						"  --- %s ---\n  %s\n  --- %s ---\n  %s\n\n"+
						"This is a STALE cassette or genuine CC DRIFT. Re-record live "+
						"under cia and inspect the API-plane capture to tell which "+
						"(DRIVE-PROTOCOL.md).",
					i, aLabel, string(a.Events[i]), bLabel, string(b.Events[i])),
			}
		}
	}
	return Diff{Equal: true}
}

// renderSideBySide produces a full canon dump of both projections for the
// length-mismatch case, so a missing/extra event is locatable.
func renderSideBySide(aLabel string, a Canon, bLabel string, b Canon) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s (%d) ---\n", aLabel, len(a.Events))
	for i, e := range a.Events {
		fmt.Fprintf(&sb, "  [%d] %s\n", i, string(e))
	}
	fmt.Fprintf(&sb, "--- %s (%d) ---\n", bLabel, len(b.Events))
	for i, e := range b.Events {
		fmt.Fprintf(&sb, "  [%d] %s\n", i, string(e))
	}
	return sb.String()
}

// CanonString renders a Canon as one canonical event per line — the stable text
// a reviewer reads and a golden could pin.
func CanonString(c Canon) string {
	var sb strings.Builder
	for _, e := range c.Events {
		sb.Write(e)
		sb.WriteByte('\n')
	}
	return sb.String()
}
