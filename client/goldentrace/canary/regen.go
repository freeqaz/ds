// Package canary is the first-party capture-and-review + nightly CC-latest
// canary runner (D49). It is the "Canary" leg of goldentrace's triad
// (Capture → Replay → Canary, ../README.md): the always-on half regenerates
// fixtures BY COMMAND, offline, against the committed cassettes and turns any
// drift into a reviewable diff; the live half (CC-latest under DS_E2E_LIVE) is
// the deferred operator step the always-on lane never runs.
//
// THE THREE THINGS THIS PACKAGE OWNS (built first-party per
// CAPTURE-TOOL-DESIGN.md — no ../cia coupling; the live leg records through the
// first-party ds-capture, never the external cia):
//
//  1. REGEN-BY-COMMAND (this file). Project every committed
//     ../../fixtures/*.cc-wire.ndjson through the SAME claude-code adapter the
//     goldens use (replay.Replay) → id-relative canon (fidelity.Canonicalize) →
//     a committed per-cassette canon golden under testdata/. With -update the
//     golden is rewritten (the insta-style refresh, ../README.md §Refresh);
//     without it, a divergence is a reviewable diff naming the first divergent
//     line — a STALE cassette or, on the live tier, genuine CC DRIFT.
//
//  2. DETECTION-MACHINERY PRE-FLIGHT (preflight.go). Before the canary trusts
//     its own verdict it PROVES the detectors still bite — it invokes the
//     existing perturbation self-tests (replay.TestPerturbationDriftIsCaught,
//     fidelity.TestPerturbationCaughtAsReviewableDiff) AND runs an in-process
//     neutered-detector probe. A canary whose detector is broken fails LOUDLY
//     with a DISTINCT "detection machinery blind" outcome, never passes
//     vacuously (taskdb 01KTXRJ2RQ).
//
//  3. D50 PROVENANCE/SCRUB GATE (provenance.go). Before anything lands in
//     fixtures/, enforce: synthetic-only ds_fixture header, NO Bearer/API token,
//     raw-class captures stay in the job tmp dir (HARDENING-NOTES §2). The
//     scrub pass lives in capture.sh; this is the git-side gate.
//
// Pure stdlib (client/go.mod). No live claude/ds-capture/podman in this package
// or its tests — the only live leg is DS_E2E_LIVE-gated and documented as the
// deferred operator step (live.go).
package canary

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/fidelity"
)

// cassetteSuffix is the committed CC-wire cassette extension (mirrors the
// replay/fidelity constant; pinned equal by a test below).
const cassetteSuffix = ".cc-wire.ndjson"

// canonGoldenSuffix is the regenerated canon-golden extension under testdata/.
// One golden per committed cassette: the id-relative, timing-erased canonical
// projection a reviewer reads and the canary diffs CC-latest against.
const canonGoldenSuffix = ".canon.ndjson"

// Layout holds the paths the regen engine reads and writes, all relative to the
// client module root by default (where `go run ./goldentrace/canary/cmd/canary`
// executes), so the command and the package tests share one source of truth.
type Layout struct {
	// FixturesGlob discovers the committed synthetic cassettes to regenerate
	// from. Defaults to the package's own fixtures dir.
	FixturesGlob string
	// GoldenDir is where the regenerated canon goldens live (committed).
	GoldenDir string
}

// DefaultLayout is the layout relative to the client module root.
func DefaultLayout() Layout {
	return Layout{
		FixturesGlob: filepath.FromSlash("fixtures/*" + cassetteSuffix),
		GoldenDir:    filepath.FromSlash("goldentrace/canary/testdata"),
	}
}

// pkgLayout is the layout relative to THIS package directory (for the tests,
// which run with the cwd at goldentrace/canary).
func pkgLayout() Layout {
	return Layout{
		FixturesGlob: filepath.FromSlash("../../fixtures/*" + cassetteSuffix),
		GoldenDir:    filepath.FromSlash("testdata"),
	}
}

// CassetteCanon projects one committed cassette to its id-relative canon NDJSON
// (one canonical event per line). This is the regeneration of a single fixture
// "by command" — the projection both the always-on regen and the live canary
// run, so a drift is the same diff in both. Returns a reviewable error if the
// cassette cannot be projected (a parse error is itself a loud drift signal).
func CassetteCanon(cassettePath string) ([]byte, error) {
	evs, err := fidelity.ProjectFile(cassettePath)
	if err != nil {
		return nil, fmt.Errorf("canary: project %s: %w", cassettePath, err)
	}
	c := fidelity.Canonicalize(evs)
	return []byte(fidelity.CanonString(c)), nil
}

// goldenPath maps a cassette path to its canon-golden path under GoldenDir.
func (l Layout) goldenPath(cassettePath string) string {
	base := strings.TrimSuffix(filepath.Base(cassettePath), cassetteSuffix)
	return filepath.Join(l.GoldenDir, base+canonGoldenSuffix)
}

// discover globs the committed cassettes in stable order.
func (l Layout) discover() ([]string, error) {
	cassettes, err := filepath.Glob(l.FixturesGlob)
	if err != nil {
		return nil, fmt.Errorf("canary: glob %s: %w", l.FixturesGlob, err)
	}
	sort.Strings(cassettes)
	return cassettes, nil
}

// RegenResult is the per-cassette outcome of a regen pass.
type RegenResult struct {
	Cassette string // the committed cassette path
	Golden   string // its canon-golden path
	// Status is one of: "ok" (golden matches), "drift" (golden diverges — a
	// reviewable diff), "updated" (golden rewritten under -update), "new"
	// (golden did not exist and was written under -update), "missing" (golden
	// absent and -update not set — a drift), or "error".
	Status string
	// Report is the reviewable diff (drift) or the error text; empty on ok.
	Report string
}

// Regenerate is the always-on capture-review engine: for every committed
// cassette it projects → canon, then either COMPARES against the committed
// golden (update=false) or REWRITES the golden (update=true, the insta-style
// refresh). It returns one result per cassette and a count of divergences. A
// non-zero divergence count with update=false is a reviewable drift the canary
// surfaces; with update=true it is zero (everything is rewritten).
//
// This is offline and hermetic: it reads only committed files and writes only
// under GoldenDir. No live claude/ds-capture/podman, no network.
func Regenerate(l Layout, update bool) (results []RegenResult, drifts int, err error) {
	cassettes, err := l.discover()
	if err != nil {
		return nil, 0, err
	}
	if len(cassettes) == 0 {
		return nil, 0, fmt.Errorf("canary: no cassettes matched %s", l.FixturesGlob)
	}
	for _, cassette := range cassettes {
		r := RegenResult{Cassette: cassette, Golden: l.goldenPath(cassette)}
		got, perr := CassetteCanon(cassette)
		if perr != nil {
			r.Status = "error"
			r.Report = perr.Error()
			drifts++
			results = append(results, r)
			continue
		}

		if update {
			// Distinguish a brand-new golden from a rewritten one for the operator —
			// the stat MUST precede the write (writeGolden always creates the file, so
			// statting afterwards would report every golden as "updated").
			_, statErr := os.Stat(r.Golden)
			preexisting := statErr == nil
			if werr := writeGolden(r.Golden, got); werr != nil {
				r.Status = "error"
				r.Report = werr.Error()
				drifts++
				results = append(results, r)
				continue
			}
			if preexisting {
				r.Status = "updated"
			} else {
				r.Status = "new"
			}
			results = append(results, r)
			continue
		}

		want, rerr := os.ReadFile(r.Golden)
		if rerr != nil {
			if os.IsNotExist(rerr) {
				r.Status = "missing"
				r.Report = fmt.Sprintf(
					"canon golden %s does not exist — run `... regen -update` to author it "+
						"(this is the first regeneration of %s).",
					r.Golden, filepath.Base(cassette))
				drifts++
				results = append(results, r)
				continue
			}
			r.Status = "error"
			r.Report = rerr.Error()
			drifts++
			results = append(results, r)
			continue
		}

		if bytes.Equal(want, got) {
			r.Status = "ok"
			results = append(results, r)
			continue
		}

		// A reviewable diff: name the first divergent line so an operator
		// reviewing a red canary sees a pinpoint, not a wall of NDJSON.
		r.Status = "drift"
		r.Report = reviewableDiff(r.Golden, want, got)
		drifts++
		results = append(results, r)
	}
	return results, drifts, nil
}

// writeGolden writes a canon golden, creating GoldenDir if needed.
func writeGolden(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("canary: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("canary: write golden %s: %w", path, err)
	}
	return nil
}

// reviewableDiff renders the first divergent line between the committed golden
// (want) and the freshly regenerated canon (got) — the human-readable diff the
// insta-style review reads, pointing at stale-vs-drift triage.
func reviewableDiff(goldenPath string, want, got []byte) string {
	wl := splitLines(want)
	gl := splitLines(got)
	n := len(wl)
	if len(gl) > n {
		n = len(gl)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "canon golden %s DIVERGES from the regenerated projection\n", goldenPath)
	if len(wl) != len(gl) {
		fmt.Fprintf(&sb, "  length: golden has %d events, regenerated has %d\n", len(wl), len(gl))
	}
	for i := 0; i < n; i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			fmt.Fprintf(&sb, "  first diff at event %d:\n    golden:      %s\n    regenerated: %s\n",
				i+1, clip(w), clip(g))
			break
		}
	}
	sb.WriteString(
		"  This is a STALE cassette (re-author it) or — on the live CC-latest tier — " +
			"genuine CC DRIFT. Inspect the ds-capture API-plane capture to tell which " +
			"(DRIVE-PROTOCOL.md); refresh with `... regen -update` only after review.")
	return sb.String()
}

func splitLines(b []byte) []string {
	t := strings.TrimRight(string(b), "\n")
	if t == "" {
		return nil
	}
	return strings.Split(t, "\n")
}

// clip bounds a long canon line for a readable one-line diff; an absent line
// (one side shorter) renders as a clear marker, not an empty string.
func clip(s string) string {
	const max = 200
	if s == "" {
		return "(event absent)"
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// WriteReport renders a per-cassette PASS/DRIFT report and a summary line. It
// returns the number of divergences (mirrors the Regenerate count) so a command
// can exit non-zero on any drift.
func WriteReport(w io.Writer, results []RegenResult, drifts int) {
	for _, r := range results {
		switch r.Status {
		case "ok":
			fmt.Fprintf(w, "OK      %-22s canon golden ≡ regenerated projection\n", base(r.Cassette))
		case "updated":
			fmt.Fprintf(w, "UPDATE  %-22s canon golden rewritten (review the diff before commit)\n", base(r.Cassette))
		case "new":
			fmt.Fprintf(w, "NEW     %-22s canon golden authored\n", base(r.Cassette))
		case "drift":
			fmt.Fprintf(w, "DRIFT   %-22s\n%s\n", base(r.Cassette), r.Report)
		case "missing":
			fmt.Fprintf(w, "MISSING %-22s\n%s\n", base(r.Cassette), r.Report)
		case "skipped":
			// A live scenario the operator did not arm (its DS_CANARY_RAW_* is unset)
			// — not a drift and not an error; report it as a clear skip.
			fmt.Fprintf(w, "SKIP    %-22s %s\n", base(r.Cassette), r.Report)
		default:
			fmt.Fprintf(w, "ERROR   %-22s %s\n", base(r.Cassette), r.Report)
		}
	}
	fmt.Fprintf(w, "\ncanary regen: %d/%d cassettes faithful (%d drift)\n",
		len(results)-drifts, len(results), drifts)
}

func base(cassettePath string) string {
	return strings.TrimSuffix(filepath.Base(cassettePath), cassetteSuffix)
}
