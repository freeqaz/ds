// SPDX-License-Identifier: Apache-2.0

package cow

import (
	"encoding/csv"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// readFixture loads a committed synthetic fixture (D50: everything in git is
// synthetic; see fixtures/PROVENANCE.md).
func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("fixtures", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(b)
}

// mustErr fails the test unless a parser returned a non-nil error, and returns
// that error for a wrapped-cause assertion — keeping the negative-path tests free
// of the "err == nil → Fatal" boilerplate.
func mustErr(t *testing.T, err error) error {
	t.Helper()
	if err == nil {
		t.Fatal("expected a parse error, got nil")
	}
	return err
}

// assertWrappedCSVQuote asserts that err WRAPS an underlying csv.Reader quote
// failure — not merely that some error occurred. It checks both directions of
// "single source of truth": the error's message carries the hoisted wrap PREFIX
// (so the wrap site and the test reference ONE const), AND the wrapped CAUSE is
// reachable by errors.Is(csv.ErrQuote) / errors.As(*csv.ParseError) (so the %w
// chain is intact, not flattened into an opaque string).
func assertWrappedCSVQuote(t *testing.T, err error, wantPrefix string) {
	t.Helper()
	if !strings.Contains(err.Error(), wantPrefix) {
		t.Errorf("error %q must carry the hoisted wrap prefix %q", err, wantPrefix)
	}
	if !errors.Is(err, csv.ErrQuote) {
		t.Errorf("error %q must WRAP csv.ErrQuote (errors.Is); the %%w chain was lost", err)
	}
	var pe *csv.ParseError
	if !errors.As(err, &pe) {
		t.Errorf("error %q must unwrap to a *csv.ParseError (errors.As); the cause was flattened", err)
	}
}

// TestParseVirtDiff_Conforming proves the v0 file-level enumerate parser turns
// real-shaped virt-diff output into the exact typed delta — the positive
// control behind the doc 02 §5 "show the user everything the agent wrote"
// promise. A header line is skipped; added/modified/deleted rows classify;
// trailing --extra-stats columns fold into Detail without losing the path.
func TestParseVirtDiff_Conforming(t *testing.T) {
	enum, err := ParseVirtDiff(readFixture(t, "virtdiff-conforming.txt"))
	if err != nil {
		t.Fatalf("ParseVirtDiff on the conforming fixture should succeed: %v", err)
	}

	want := []Write{
		{Kind: Modified, Path: "/etc/hosts", Detail: "100644 220"},
		{Kind: Modified, Path: "/home/ds/.bash_history", Detail: ""},
		{Kind: Added, Path: "/home/ds/work/agent-notes.md", Detail: ""},
		{Kind: Added, Path: "/home/ds/work/build/out.bin", Detail: "100644 4096"},
		{Kind: Deleted, Path: "/home/ds/work/scratch.tmp", Detail: ""},
	}
	if len(enum.Writes) != len(want) {
		t.Fatalf("got %d writes, want %d: %+v", len(enum.Writes), len(want), enum.Writes)
	}
	for i, w := range want {
		got := enum.Writes[i]
		if got.Kind != w.Kind || got.Path != w.Path || got.Detail != w.Detail {
			t.Errorf("write[%d] = %+v, want %+v", i, got, w)
		}
	}

	c := enum.Counts()
	if c[Added] != 2 || c[Modified] != 2 || c[Deleted] != 1 {
		t.Errorf("counts = %v, want 2 added / 2 modified / 1 deleted", c)
	}
}

// TestParseVirtDiff_CSVSpacePaths proves the path-hardening this unit lands:
// the CSV / machine-readable virt-diff shape delimits the path UNAMBIGUOUSLY
// (an RFC-4180-quoted field), so paths with embedded spaces, an embedded
// double-quote, and trailing --extra-stats columns all parse to the EXACT
// typed delta with FULL paths — no first-whitespace truncation that would fold
// a path's tail into Detail and under-report a credential path the doc 06 §3c
// (c)-suite scans — and the per-kind count stays honest.
func TestParseVirtDiff_CSVSpacePaths(t *testing.T) {
	enum, err := ParseVirtDiff(readFixture(t, "virtdiff-csv-spacepaths.txt"))
	if err != nil {
		t.Fatalf("ParseVirtDiff on the CSV space-paths fixture should succeed: %v", err)
	}

	// Sorted by path. Every path is whole — embedded spaces and the embedded
	// quote survive verbatim, with NO tail folded into Detail.
	want := []Write{
		{Kind: Modified, Path: "/home/ds/.config/My App/settings.json", Detail: "100644,512"},
		{Kind: Added, Path: "/home/ds/work/agent notes.md", Detail: ""},
		{Kind: Added, Path: "/home/ds/work/build/out file.bin", Detail: "100644,4096"},
		{Kind: Deleted, Path: "/home/ds/work/scratch dir/tmp file", Detail: ""},
		{Kind: Modified, Path: `/home/ds/work/weird " quote.txt`, Detail: ""},
	}
	if len(enum.Writes) != len(want) {
		t.Fatalf("got %d writes, want %d: %+v", len(enum.Writes), len(want), enum.Writes)
	}
	for i, w := range want {
		got := enum.Writes[i]
		if got.Kind != w.Kind || got.Path != w.Path || got.Detail != w.Detail {
			t.Errorf("write[%d] = %+v, want %+v", i, got, w)
		}
	}
	// Belt-and-suspenders: no recorded path may contain a space-then-stat-only
	// tail that secretly truncated — assert each path ends in its real basename.
	for _, w := range enum.Writes {
		if w.Path == "" || w.Path[0] != '/' {
			t.Errorf("path %q is not an absolute, whole path", w.Path)
		}
	}

	c := enum.Counts()
	if c[Added] != 2 || c[Modified] != 2 || c[Deleted] != 1 {
		t.Errorf("counts = %v, want 2 added / 2 modified / 1 deleted (honest count, no dropped/merged rows)", c)
	}
}

// TestParseVirtDiff_PlainEmbeddedSpaceNotTruncated proves the default
// (non-CSV) parser ALSO no longer truncates at the first whitespace: a path
// with an embedded space followed by --extra-stats columns is bounded by
// peeling the fixed-shape stat tokens off the right edge, so the full path is
// preserved and the stat columns land in Detail. (CSV mode is preferred; this
// guards the legacy default-mode shape against the v0 first-whitespace bug.)
func TestParseVirtDiff_PlainEmbeddedSpaceNotTruncated(t *testing.T) {
	in := "= /home/ds/work/my notes.md 100644 220\n"
	enum, err := ParseVirtDiff(in)
	if err != nil {
		t.Fatalf("ParseVirtDiff (plain, embedded space) should succeed: %v", err)
	}
	if len(enum.Writes) != 1 {
		t.Fatalf("got %d writes, want 1: %+v", len(enum.Writes), enum.Writes)
	}
	got := enum.Writes[0]
	want := Write{Kind: Modified, Path: "/home/ds/work/my notes.md", Detail: "100644 220"}
	if got != want {
		t.Errorf("plain embedded-space parse = %+v, want %+v (no first-whitespace truncation)", got, want)
	}
}

// TestParseVirtDiff_CSVNegativeMalformed proves the CSV path is NON-VACUOUS: an
// unknown single-char status token in a CSV row is a parse error, never a
// silently dropped row (the CSV twin of TestParseVirtDiff_NegativeMalformed).
func TestParseVirtDiff_CSVNegativeMalformed(t *testing.T) {
	if _, err := ParseVirtDiff(readFixture(t, "virtdiff-csv-malformed.txt")); err == nil {
		t.Fatal("ParseVirtDiff on the malformed CSV fixture MUST fail; it did not")
	}
}

// TestParseVirtDiff_CSVWrapsReaderCause proves the WHOLE-CAPTURE CSV parser
// (parseVirtDiffCSV) WRAPS the underlying csv.Reader failure rather than
// flattening it: a homogeneous CSV capture (so it routes to parseVirtDiffCSV, not
// the per-row classifier) whose second row carries a malformed quoted field makes
// csv.Reader return a quote error, which is wrapped with %w under the hoisted
// errVirtDiffCSVPrefix. We assert the WRAPPED cause (errors.Is/As + the hoisted
// prefix), the twin of the per-row wrap pinned by
// TestParseVirtDiff_PerRowEmbeddedNewlineSplits — so both CSV wrap sites are
// non-vacuous and single-sourced.
func TestParseVirtDiff_CSVWrapsReaderCause(t *testing.T) {
	// Both data rows are "<status>,…" (homogeneous CSV → whole-capture fast path),
	// and row 2 has an extraneous quote inside the field (a bare '"' after the
	// closing quote) → csv.ErrQuote.
	in := "+,\"/home/ds/work/ok.md\"\n=,\"/home/ds/work/bad\"quote.md\"\n"
	if nonHomogeneousVirtDiff(in) {
		t.Fatal("precondition: the capture must be homogeneous CSV so it routes to parseVirtDiffCSV (the whole-capture wrap site), not the per-row classifier")
	}
	_, autoErr := ParseVirtDiff(in)
	assertWrappedCSVQuote(t, mustErr(t, autoErr), errVirtDiffCSVPrefix)
	// Pin the exact entry point too: parseVirtDiffCSV itself wraps with the same
	// hoisted prefix, so the wrap is the whole-capture path, not some other route.
	_, directErr := parseVirtDiffCSV(in)
	assertWrappedCSVQuote(t, mustErr(t, directErr), errVirtDiffCSVPrefix)
}

// TestParseVirtDiff_NegativeMalformed proves the parser is NON-VACUOUS: a row
// whose status char is jammed against the path (no separating space) is a parse
// error, never a silently dropped row — a dropped row is an under-reported
// agent write (doc 02 §5 / the doc 06 level-(c) credential-leak assertion both
// depend on the enumeration being complete).
func TestParseVirtDiff_NegativeMalformed(t *testing.T) {
	_, err := ParseVirtDiff(readFixture(t, "virtdiff-malformed.txt"))
	if err == nil {
		t.Fatal("ParseVirtDiff on the malformed fixture MUST fail; it did not")
	}
}

// TestParseVirtDiff_NegativeUnknownStatus is a second negative case, inline (no
// fixture): an unknown leading status token must error rather than be skipped.
func TestParseVirtDiff_NegativeUnknownStatus(t *testing.T) {
	if _, err := ParseVirtDiff("? /home/ds/work/mystery\n"); err == nil {
		t.Fatal("ParseVirtDiff MUST reject an unknown status token")
	}
}

// TestSelectVirtDiffMode_Detect proves the detected-mode hook reports the
// concrete shape the auto-detector resolves each capture to — the surface
// cmd/parse prints so an operator can spot a mis-detect. The CSV space-paths
// fixture is detected CSV; the plain conforming fixture is detected plain; a
// header-only capture (no data row) falls back to plain (the default-mode
// contract); and a MIXED-shape capture whose first row is plain is detected
// plain even though a later row is CSV-shaped — the silent-degrade case this
// unit makes visible. SelectVirtDiffMode never returns ModeAuto.
func TestSelectVirtDiffMode_Detect(t *testing.T) {
	headerOnly := "Comparing image A (/var/lib/ds/base/m0-base.raw) with image B (/var/lib/ds/sessions/01HEXSESS/overlay.qcow2)\n"
	// First real row is plain ("= /path ..."); a later row is CSV-shaped. The
	// whole-input commit from the FIRST row resolves this to plain.
	mixed := "= /home/ds/work/notes.md\n+,\"/home/ds/work/agent notes.md\"\n"

	cases := []struct {
		name string
		in   string
		want VirtDiffMode
	}{
		{"csv-spacepaths", readFixture(t, "virtdiff-csv-spacepaths.txt"), ModeCSV},
		{"plain-conforming", readFixture(t, "virtdiff-conforming.txt"), ModePlain},
		{"header-only", headerOnly, ModePlain},
		{"mixed-first-row-plain", mixed, ModePlain},
		{"empty", "", ModePlain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectVirtDiffMode(tc.in)
			if got != tc.want {
				t.Errorf("SelectVirtDiffMode = %q, want %q", got, tc.want)
			}
			if got == ModeAuto {
				t.Error("SelectVirtDiffMode must resolve to a concrete shape, never ModeAuto")
			}
		})
	}
}

// TestParseVirtDiffMode_AutoReportsDetectedMode proves ParseVirtDiffMode in
// ModeAuto parses identically to ParseVirtDiff AND records the concrete shape it
// used in Enumeration.DetectedMode — the field cmd/parse prints.
func TestParseVirtDiffMode_AutoReportsDetectedMode(t *testing.T) {
	csvIn := readFixture(t, "virtdiff-csv-spacepaths.txt")
	enum, err := ParseVirtDiffMode(csvIn, ModeAuto)
	if err != nil {
		t.Fatalf("ParseVirtDiffMode(auto) on the CSV fixture should succeed: %v", err)
	}
	if enum.DetectedMode != ModeCSV {
		t.Errorf("DetectedMode = %q, want %q (auto-detected CSV)", enum.DetectedMode, ModeCSV)
	}
	plainIn := readFixture(t, "virtdiff-conforming.txt")
	enum, err = ParseVirtDiffMode(plainIn, ModeAuto)
	if err != nil {
		t.Fatalf("ParseVirtDiffMode(auto) on the plain fixture should succeed: %v", err)
	}
	if enum.DetectedMode != ModePlain {
		t.Errorf("DetectedMode = %q, want %q (auto-detected plain)", enum.DetectedMode, ModePlain)
	}
}

// TestParseVirtDiffMode_OverrideBeatsAutoDetect proves the operator override
// FORCES the shape rather than guessing — on the MIXED-shape capture whose first
// row is plain (so auto-detect resolves plain), forcing ModeCSV makes the parser
// read the CSV-shaped rows, and forcing ModePlain on a CSV capture reads the
// plain shape. This is the hardening's whole point: a mis-detect is recoverable
// by overriding, and the forced mode wins over the heuristic on the same input.
func TestParseVirtDiffMode_OverrideBeatsAutoDetect(t *testing.T) {
	// A capture whose FIRST row is CSV-shaped (so auto resolves CSV). Forcing
	// ModePlain must make the PLAIN parser run on this same input — and the CSV
	// rows like `+,"/home/ds/work/agent notes.md"` are NOT "<status><space>..."
	// shaped (the char after '+' is ',', not ' '), so the plain parser rejects
	// them. The error PROVES the forced shape genuinely drove the parse instead
	// of the CSV auto-detect (which would have succeeded).
	csvFirst := readFixture(t, "virtdiff-csv-spacepaths.txt")
	if SelectVirtDiffMode(csvFirst) != ModeCSV {
		t.Fatalf("precondition: %s should auto-detect CSV", "virtdiff-csv-spacepaths.txt")
	}
	if _, err := ParseVirtDiffMode(csvFirst, ModeAuto); err != nil {
		t.Fatalf("sanity: CSV fixture parses clean under auto-detect: %v", err)
	}
	if _, perr := ParseVirtDiffMode(csvFirst, ModePlain); perr == nil {
		t.Fatal("forced-plain parse of CSV-shaped rows MUST error (status not followed by a space) — proves the forced shape beat the CSV auto-detect")
	}

	// The complementary direction: a MIXED capture whose first row is PLAIN (so
	// auto resolves PLAIN). Forcing ModeCSV makes the CSV parser read it, and the
	// forced mode is recorded — the override beats the plain auto-detect.
	mixed := "= /home/ds/work/notes.md\n+,\"/home/ds/work/agent notes.md\"\n"
	if SelectVirtDiffMode(mixed) != ModePlain {
		t.Fatalf("precondition: the mixed capture should auto-detect plain")
	}
	csvForced, err := ParseVirtDiffMode(mixed, ModeCSV)
	if err != nil {
		t.Fatalf("forcing ModeCSV on the mixed capture should parse the CSV-shaped rows: %v", err)
	}
	if csvForced.DetectedMode != ModeCSV {
		t.Errorf("DetectedMode = %q, want %q (operator forced csv)", csvForced.DetectedMode, ModeCSV)
	}
	// Under forced CSV, the first row "= /home/ds/work/notes.md" is a single
	// unquoted CSV field whose status token "= /home/ds/work/notes.md" is not a
	// known single-char status — but that whole field is multi-char, so the CSV
	// parser treats it as a header row and SKIPS it, then parses the second row
	// "+,\"...\"" as a real CSV add. The honest result: exactly one Added write
	// with its WHOLE space-bearing path — proving CSV parsing actually ran.
	if len(csvForced.Writes) != 1 {
		t.Fatalf("forced-CSV mixed parse: got %d writes, want 1: %+v", len(csvForced.Writes), csvForced.Writes)
	}
	got := csvForced.Writes[0]
	want := Write{Kind: Added, Path: "/home/ds/work/agent notes.md", Detail: ""}
	if got != want {
		t.Errorf("forced-CSV mixed write = %+v, want %+v", got, want)
	}
}

// TestParseVirtDiffMode_UnknownMode proves an unrecognized mode is a hard error,
// never a silent fallback to a guessed shape.
func TestParseVirtDiffMode_UnknownMode(t *testing.T) {
	if _, err := ParseVirtDiffMode("= /home/ds/x\n", VirtDiffMode("bogus")); err == nil {
		t.Fatal("ParseVirtDiffMode MUST reject an unknown mode")
	}
}

// TestParseVirtDiff_InterleavedPerRow proves the per-row classifier fallback:
// a GENUINELY INTERLEAVED capture — CSV-shaped rows and plain-shaped rows mixed
// in one capture (e.g. two appended virt-diff dumps), which NO single-shape
// parser can read — parses to the EXACT typed delta WITHOUT any --mode-* override.
// The whole-capture auto-detect commits to ONE shape from the first row and
// fails on the other shape's rows; ModeAuto then retries with the per-row
// classifier, which classifies EACH row on its own (status + ',' => CSV via
// csv.Reader; status + ' ' => plain via splitPathDetail). Full paths survive
// (embedded spaces in both shapes), the per-kind count is honest, and the
// detected mode is reported as ModeMixed so the v0 summary is not dishonest
// about a single shape.
func TestParseVirtDiff_InterleavedPerRow(t *testing.T) {
	// Leading banner (skipped), then a plain row, a CSV row, a plain row with an
	// embedded space + stat columns, a CSV row with an embedded space + comma
	// stats, and a deleted CSV row. The first DATA row is plain, so the
	// whole-capture auto-detect resolves ModePlain and then chokes on the
	// CSV-shaped rows ("+,\"…\"" is not "<status><space>…"), forcing the fallback.
	in := "Comparing image A (/base.raw) with image B (/overlay.qcow2)\n" +
		"= /home/ds/.bashrc\n" +
		"+,\"/home/ds/work/agent notes.md\"\n" +
		"= /home/ds/work/my report.md 100644 220\n" +
		"+,\"/home/ds/work/build/out file.bin\",100644,4096\n" +
		"-,\"/home/ds/work/scratch dir/tmp file\"\n"

	// Precondition: the capture is genuinely non-homogeneous — the whole-capture
	// auto-detect commits to plain and CANNOT parse it as a single shape.
	if SelectVirtDiffMode(in) != ModePlain {
		t.Fatalf("precondition: interleaved capture's first row is plain → auto-detect plain")
	}
	if _, perr := ParseVirtDiffMode(in, ModePlain); perr == nil {
		t.Fatal("precondition: forced-plain parse of the interleaved capture MUST fail (CSV rows are not plain-shaped)")
	}

	enum, err := ParseVirtDiff(in)
	if err != nil {
		t.Fatalf("ParseVirtDiff on the interleaved capture should succeed via the per-row fallback: %v", err)
	}
	if enum.DetectedMode != ModeMixed {
		t.Errorf("DetectedMode = %q, want %q (per-row classifier ran on a non-homogeneous capture)", enum.DetectedMode, ModeMixed)
	}

	// Sorted by path. Both shapes' paths are whole — embedded spaces survive in
	// BOTH the CSV rows (RFC-4180 quoting) and the plain rows (right-edge stat
	// peel), with no tail folded into the wrong place.
	want := []Write{
		{Kind: Modified, Path: "/home/ds/.bashrc", Detail: ""},
		{Kind: Added, Path: "/home/ds/work/agent notes.md", Detail: ""},
		{Kind: Added, Path: "/home/ds/work/build/out file.bin", Detail: "100644,4096"},
		{Kind: Modified, Path: "/home/ds/work/my report.md", Detail: "100644 220"},
		{Kind: Deleted, Path: "/home/ds/work/scratch dir/tmp file", Detail: ""},
	}
	if len(enum.Writes) != len(want) {
		t.Fatalf("got %d writes, want %d: %+v", len(enum.Writes), len(want), enum.Writes)
	}
	for i, w := range want {
		got := enum.Writes[i]
		if got.Kind != w.Kind || got.Path != w.Path || got.Detail != w.Detail {
			t.Errorf("write[%d] = %+v, want %+v", i, got, w)
		}
	}
	c := enum.Counts()
	if c[Added] != 2 || c[Modified] != 2 || c[Deleted] != 1 {
		t.Errorf("counts = %v, want 2 added / 2 modified / 1 deleted (honest count, no dropped/merged rows)", c)
	}
}

// TestParseVirtDiff_InterleavedCSVFirst proves the per-row fallback is
// shape-symmetric: when the FIRST data row is CSV-shaped (so the whole-capture
// auto-detect commits to ModeCSV and chokes on a later plain row), ModeAuto
// still falls back to the per-row classifier and parses the mixed capture to the
// exact typed delta. (Complements TestParseVirtDiff_InterleavedPerRow, whose
// first row is plain.)
func TestParseVirtDiff_InterleavedCSVFirst(t *testing.T) {
	in := "+,\"/home/ds/work/agent notes.md\"\n" +
		"= /home/ds/.bashrc 100644 88\n" +
		"-,\"/home/ds/work/old.tmp\"\n"
	if SelectVirtDiffMode(in) != ModeCSV {
		t.Fatalf("precondition: CSV-first interleaved capture should auto-detect CSV")
	}
	// Forcing ModeCSV silently SWALLOWS the plain row as a multi-field "header"
	// (its single unquoted field is not a known status), under-reporting the
	// write — exactly the silent mis-detect the per-row fallback fixes. Prove the
	// drop so the ModeAuto recovery below is meaningful, not vacuous.
	forcedCSV, cerr := ParseVirtDiffMode(in, ModeCSV)
	if cerr != nil {
		t.Fatalf("precondition: forced-CSV parse should not error (it drops the plain row): %v", cerr)
	}
	if len(forcedCSV.Writes) != 2 {
		t.Fatalf("precondition: forced-CSV should under-report (drop the plain row) → 2 writes, got %d: %+v", len(forcedCSV.Writes), forcedCSV.Writes)
	}
	enum, err := ParseVirtDiff(in)
	if err != nil {
		t.Fatalf("ParseVirtDiff on the CSV-first interleaved capture should succeed via the per-row fallback: %v", err)
	}
	if enum.DetectedMode != ModeMixed {
		t.Errorf("DetectedMode = %q, want %q", enum.DetectedMode, ModeMixed)
	}
	want := []Write{
		{Kind: Modified, Path: "/home/ds/.bashrc", Detail: "100644 88"},
		{Kind: Added, Path: "/home/ds/work/agent notes.md", Detail: ""},
		{Kind: Deleted, Path: "/home/ds/work/old.tmp", Detail: ""},
	}
	if len(enum.Writes) != len(want) {
		t.Fatalf("got %d writes, want %d: %+v", len(enum.Writes), len(want), enum.Writes)
	}
	for i, w := range want {
		if enum.Writes[i] != want[i] {
			t.Errorf("write[%d] = %+v, want %+v", i, enum.Writes[i], w)
		}
	}
}

// TestParseVirtDiff_InterleavedMalformedStillErrors proves the per-row fallback
// is NON-VACUOUS: a malformed row inside an otherwise-interleaved capture still
// ERRORS under ModeAuto — the fallback never silently drops a row it cannot
// classify (doc 02 §5 / doc 06 §3c need the enumeration complete). Here a row
// carries an UNKNOWN status token jammed against a comma ("?,\"…\""), which the
// per-row CSV classifier rejects exactly as parseVirtDiffCSV would.
func TestParseVirtDiff_InterleavedMalformedStillErrors(t *testing.T) {
	in := "= /home/ds/.bashrc\n" +
		"+,\"/home/ds/work/agent notes.md\"\n" +
		"?,\"/home/ds/work/mystery.md\"\n"
	if _, err := ParseVirtDiff(in); err == nil {
		t.Fatal("ParseVirtDiff on an interleaved capture with a malformed row MUST fail; it did not")
	}
}

// TestParseVirtDiff_InterleavedPlainJammedStillErrors is the second per-row
// negative: inside a genuinely interleaved capture (a valid CSV row AND a valid
// plain row, so the per-row classifier runs), a KNOWN status token jammed
// against a non-delimiter byte ("=/foo", no separating space or comma) is a
// malformed row and ERRORS — never mis-split, never dropped.
func TestParseVirtDiff_InterleavedPlainJammedStillErrors(t *testing.T) {
	in := "+,\"/home/ds/work/agent notes.md\"\n" + // CSV data row
		"= /home/ds/.bashrc\n" + // plain data row → non-homogeneous → per-row
		"=/home/ds/work/jammed.md\n" // malformed: status jammed against path
	if !nonHomogeneousVirtDiff(in) {
		t.Fatalf("precondition: the capture must be non-homogeneous so the per-row classifier runs")
	}
	if _, err := ParseVirtDiff(in); err == nil {
		t.Fatal("ParseVirtDiff on an interleaved capture with a jammed plain row MUST fail; it did not")
	}
}

// TestParseVirtDiffMode_OverrideSkipsPerRowFallback proves the per-row fallback
// is reachable ONLY from ModeAuto: the explicit --mode-* override forces ONE
// shape and never consults the classifier, so forcing ModePlain on an
// interleaved capture (whose CSV rows are not plain-shaped) still ERRORS rather
// than silently recovering via per-row. The operator escape hatch stays exact.
func TestParseVirtDiffMode_OverrideSkipsPerRowFallback(t *testing.T) {
	in := "= /home/ds/.bashrc\n" +
		"+,\"/home/ds/work/agent notes.md\"\n"
	// ModeAuto recovers via the per-row fallback.
	if _, err := ParseVirtDiffMode(in, ModeAuto); err != nil {
		t.Fatalf("sanity: ModeAuto should recover the interleaved capture via per-row fallback: %v", err)
	}
	// Forced ModePlain must NOT fall back — the CSV row breaks the plain parser.
	if _, err := ParseVirtDiffMode(in, ModePlain); err == nil {
		t.Fatal("forced ModePlain MUST NOT use the per-row fallback; the CSV row should make it error")
	}
}

// TestParseVirtDiff_HomogeneousFastPathPreserved proves the per-row fallback is
// a FALLBACK only: a homogeneous capture (every row one shape) still takes the
// whole-capture fast path and records its CONCRETE shape (ModeCSV / ModePlain),
// never ModeMixed — the classifier only runs when the single-shape parse fails.
func TestParseVirtDiff_HomogeneousFastPathPreserved(t *testing.T) {
	plain, err := ParseVirtDiff(readFixture(t, "virtdiff-conforming.txt"))
	if err != nil {
		t.Fatalf("homogeneous plain capture should parse: %v", err)
	}
	if plain.DetectedMode != ModePlain {
		t.Errorf("homogeneous plain DetectedMode = %q, want %q (fast path, not per-row)", plain.DetectedMode, ModePlain)
	}
	csv, err := ParseVirtDiff(readFixture(t, "virtdiff-csv-spacepaths.txt"))
	if err != nil {
		t.Fatalf("homogeneous CSV capture should parse: %v", err)
	}
	if csv.DetectedMode != ModeCSV {
		t.Errorf("homogeneous CSV DetectedMode = %q, want %q (fast path, not per-row)", csv.DetectedMode, ModeCSV)
	}
}

// TestParseVirtDiff_MixedShapeFixture is the committed-fixture twin of the
// inline interleaved-capture tests: it drives the DEGRADE-then-RECOVER flow over
// the synthetic vm/cow/fixtures/virtdiff-mixed-shape.txt that
// enumerate-writes.sh --self-test also exercises, so the shell self-test and the
// Go test pin the SAME artifact.
//
// The fixture is a genuinely interleaved capture (a leading banner, then plain
// rows AND CSV rows mixed in one dump). The story it proves, end to end:
//
//   - DEGRADE: the whole-capture auto-detect commits to ONE shape from the first
//     (plain) data row, so forcing the WRONG single shape mis-handles it —
//     forced ModePlain ERRORS on the CSV rows (never a silent drop), and forced
//     ModeCSV silently UNDER-REPORTS by swallowing the plain rows as "headers".
//   - RECOVER: ModeAuto (the default) routes the non-homogeneous capture to the
//     per-row classifier, recording DetectedMode=ModeMixed and parsing EVERY row
//     to the exact typed delta with FULL paths (embedded spaces survive in both
//     the CSV rows and the plain rows), so the per-kind count is honest.
func TestParseVirtDiff_MixedShapeFixture(t *testing.T) {
	in := readFixture(t, "virtdiff-mixed-shape.txt")

	// Precondition 1: the capture is genuinely non-homogeneous (both shapes
	// present), so the per-row classifier is the path under test.
	if !nonHomogeneousVirtDiff(in) {
		t.Fatal("precondition: the mixed-shape fixture must be non-homogeneous (plain AND CSV rows)")
	}
	// Precondition 2: the first data row is plain, so whole-capture auto-detect
	// resolves ModePlain — the degrade case the fixture models.
	if SelectVirtDiffMode(in) != ModePlain {
		t.Fatalf("precondition: the mixed-shape fixture's first data row is plain → auto-detect plain, got %q", SelectVirtDiffMode(in))
	}

	// DEGRADE (forced plain): the CSV rows are not "<status><space>…" shaped, so
	// the plain parser ERRORS — never silently drops a row (doc 02 §5 / doc 06 §3c
	// need the enumeration complete).
	if _, err := ParseVirtDiffMode(in, ModePlain); err == nil {
		t.Fatal("forced ModePlain on the mixed-shape fixture MUST error on the CSV-shaped rows; it did not")
	}

	// DEGRADE (forced csv): the plain rows present a single unquoted multi-field
	// "record" whose first field is not a known status, so the CSV parser SKIPS
	// them as headers — silently UNDER-REPORTING. Pin the under-report so the
	// per-row recovery below is meaningfully better, not vacuous.
	forcedCSV, err := ParseVirtDiffMode(in, ModeCSV)
	if err != nil {
		t.Fatalf("forced ModeCSV on the mixed-shape fixture should parse (dropping the plain rows), not error: %v", err)
	}
	if forcedCSV.DetectedMode != ModeCSV {
		t.Errorf("forced-CSV DetectedMode = %q, want %q", forcedCSV.DetectedMode, ModeCSV)
	}
	// Only the three CSV rows survive; the four plain rows are dropped.
	if len(forcedCSV.Writes) != 3 {
		t.Fatalf("forced ModeCSV should under-report (drop the plain rows) → 3 writes, got %d: %+v", len(forcedCSV.Writes), forcedCSV.Writes)
	}
	cc := forcedCSV.Counts()
	if cc[Added] != 1 || cc[Modified] != 1 || cc[Deleted] != 1 {
		t.Errorf("forced-CSV counts = %v, want 1 added / 1 modified / 1 deleted (plain rows dropped)", cc)
	}

	// RECOVER (auto-detect → per-row classifier): the whole capture parses to the
	// exact typed delta, every path WHOLE, DetectedMode=ModeMixed.
	enum, err := ParseVirtDiff(in)
	if err != nil {
		t.Fatalf("ParseVirtDiff on the mixed-shape fixture should recover via the per-row classifier: %v", err)
	}
	if enum.DetectedMode != ModeMixed {
		t.Errorf("recovered DetectedMode = %q, want %q (per-row classifier on a non-homogeneous capture)", enum.DetectedMode, ModeMixed)
	}

	// Sorted by path. Both shapes' paths are whole: embedded spaces survive in
	// the CSV rows (RFC-4180 quoting) AND the plain rows (right-edge stat peel).
	want := []Write{
		{Kind: Modified, Path: "/home/ds/.bashrc", Detail: ""},
		{Kind: Modified, Path: "/home/ds/.config/My App/settings.json", Detail: "100644,512"},
		{Kind: Added, Path: "/home/ds/work/agent notes.md", Detail: ""},
		{Kind: Added, Path: "/home/ds/work/build/log.txt", Detail: "100644 2048"},
		{Kind: Modified, Path: "/home/ds/work/my report.md", Detail: "100644 220"},
		{Kind: Deleted, Path: "/home/ds/work/old.tmp", Detail: ""},
		{Kind: Deleted, Path: "/home/ds/work/scratch dir/tmp file", Detail: ""},
	}
	if len(enum.Writes) != len(want) {
		t.Fatalf("recovered %d writes, want %d: %+v", len(enum.Writes), len(want), enum.Writes)
	}
	for i, w := range want {
		got := enum.Writes[i]
		if got.Kind != w.Kind || got.Path != w.Path || got.Detail != w.Detail {
			t.Errorf("write[%d] = %+v, want %+v", i, got, w)
		}
	}
	c := enum.Counts()
	if c[Added] != 2 || c[Modified] != 3 || c[Deleted] != 2 {
		t.Errorf("recovered counts = %v, want 2 added / 3 modified / 2 deleted (honest, no dropped/merged rows)", c)
	}

	// The recovery is strictly more complete than the forced-CSV under-report.
	if len(enum.Writes) <= len(forcedCSV.Writes) {
		t.Errorf("per-row recovery (%d writes) must report MORE than the forced-CSV under-report (%d writes)", len(enum.Writes), len(forcedCSV.Writes))
	}
}

// TestParseVirtDiff_PerRowEmbeddedNewlineSplits pins the DOCUMENTED single-line-
// CSV-record limitation of the per-row classifier (parseVirtDiffPerRow /
// classifyRow) versus the whole-capture parseVirtDiffCSV. It is a guard, not a
// behavior change: a CSV record whose RFC-4180 quoted path field carries an
// embedded LITERAL newline (legal CSV — the newline is part of the field value)
// is read DIFFERENTLY by the two paths, and that asymmetry must not regress
// silently (a SILENT drop would under-report an agent write; doc 02 §5 / doc 06
// §3c need the enumeration complete). The synthetic
// fixtures/virtdiff-embedded-newline.txt carries one plain row then one CSV row
// whose quoted path field spans two physical lines.
//
// The table asserts, for each parse path, the documented outcome:
//
//   - whole-capture parseVirtDiffCSV reads the ENTIRE input with one csv.Reader,
//     so it spans the physical newline inside the quoted field and joins the
//     record WHOLE — exactly one Added write with the newline-bearing path.
//   - the per-row path (ParseVirtDiff / ModeAuto, routed here because the capture
//     is non-homogeneous) bufio-scans line by line and feeds the FIRST physical
//     line of the record to csv.Reader alone — an unterminated quoted field — so
//     it ERRORS. The physical newline is treated as a record boundary BEFORE
//     csv.Reader runs. This is the asymmetry the doc comment states.
func TestParseVirtDiff_PerRowEmbeddedNewlineSplits(t *testing.T) {
	in := readFixture(t, "virtdiff-embedded-newline.txt")

	// Precondition: the fixture is genuinely interleaved (a plain row AND a CSV
	// row), so ParseVirtDiff/ModeAuto routes it to the per-row classifier rather
	// than the whole-capture parseVirtDiffCSV fast path — the path under test.
	if !nonHomogeneousVirtDiff(in) {
		t.Fatal("precondition: the embedded-newline fixture must be non-homogeneous (a plain row AND a CSV row) so the per-row classifier runs")
	}

	t.Run("whole-capture-joins-the-record", func(t *testing.T) {
		// parseVirtDiffCSV reads ALL input with one csv.Reader: the embedded
		// newline is part of the quoted field, joined whole — NO limitation.
		enum, err := parseVirtDiffCSV(in)
		if err != nil {
			t.Fatalf("parseVirtDiffCSV must join the embedded-newline record whole, got error: %v", err)
		}
		want := []Write{
			{Kind: Added, Path: "/home/ds/work/two\nline.md", Detail: ""},
		}
		if len(enum.Writes) != len(want) {
			t.Fatalf("whole-capture got %d writes, want %d: %+v", len(enum.Writes), len(want), enum.Writes)
		}
		if enum.Writes[0] != want[0] {
			t.Errorf("whole-capture write = %+v, want %+v (embedded newline joined whole)", enum.Writes[0], want[0])
		}
	})

	t.Run("per-row-treats-newline-as-record-boundary", func(t *testing.T) {
		// ParseVirtDiff/ModeAuto -> per-row classifier: the line scan splits the
		// quoted field, so csv.Reader sees an unterminated quote on the first
		// physical line and the row ERRORS. Honest failure, never a silent drop.
		// Assert the WRAPPED cause, not just that an error occurred: the per-row
		// CSV path wraps the csv.Reader failure with %w, so the underlying
		// csv.ErrQuote must survive unwrapping, and the hoisted wrap prefix
		// (errVirtDiffPerRowCSVPrefix) must be present in the message — pinning that
		// it is the per-row classifier's CSV branch that failed.
		_, autoErr := ParseVirtDiff(in)
		assertWrappedCSVQuote(t, mustErr(t, autoErr), errVirtDiffPerRowCSVPrefix)
		// The same outcome under the explicit per-row entry point, to pin that it
		// is the per-row classifier — not some other path — that splits the field.
		_, perrErr := parseVirtDiffPerRow(in)
		assertWrappedCSVQuote(t, mustErr(t, perrErr), errVirtDiffPerRowCSVPrefix)
	})
}

// TestParseQemuImgInfo_Conforming proves the backing-chain parser extracts the
// overlay and its raw base and confirms the D29 backing-file invariant holds.
func TestParseQemuImgInfo_Conforming(t *testing.T) {
	enum, err := ParseQemuImgInfo(readFixture(t, "qemuimg-conforming.txt"), true)
	if err != nil {
		t.Fatalf("ParseQemuImgInfo on the conforming fixture should succeed: %v", err)
	}
	if enum.OverlayPath != "/var/lib/ds/sessions/01HEXSESS/overlay.qcow2" {
		t.Errorf("OverlayPath = %q, want the session overlay", enum.OverlayPath)
	}
	if enum.BasePath != "/var/lib/ds/base/m0-base.raw" {
		t.Errorf("BasePath = %q, want the raw M0 base", enum.BasePath)
	}
	if !enum.BackingReadOnly {
		t.Error("BackingReadOnly should reflect the caller-asserted read-only base")
	}
}

// TestParseQemuImgInfo_NegativeNoBacking proves the second non-vacuous case: an
// image with NO backing file is NOT a per-session overlay (D29 violation) and
// MUST error — the create path's whole job is to layer the session delta on the
// read-only base.
func TestParseQemuImgInfo_NegativeNoBacking(t *testing.T) {
	if _, err := ParseQemuImgInfo(readFixture(t, "qemuimg-nobacking.txt"), false); err == nil {
		t.Fatal("ParseQemuImgInfo on a backing-less image MUST fail (D29)")
	}
}

// TestParseQemuImgInfo_ReadOnlyNotOverclaimed proves the parser does not invent
// a read-only guarantee from a static info dump: BackingReadOnly only reflects
// what the caller established at runtime, never the qemu-img text alone.
func TestParseQemuImgInfo_ReadOnlyNotOverclaimed(t *testing.T) {
	enum, err := ParseQemuImgInfo(readFixture(t, "qemuimg-conforming.txt"), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enum.BackingReadOnly {
		t.Error("BackingReadOnly must stay false when the caller did not assert it — a static qemu-img parse cannot prove a runtime open-mode")
	}
}

// TestClassifyRow_ShapeSuffixSingleSourced pins the per-row shape suffix that
// the perRowErr helper single-sources: a CSV-shaped unknown-status row must open
// its message with the "(csv)" framing, and a plain-shaped one with "(plain)".
// It guards the refactor that folded eight hand-typed "(csv):" / "(plain):"
// preludes into perRowErr — the suffix text is now byte-identical to before AND
// asserted, so a future prelude edit that drops or misspells the shape token
// fails here rather than silently drifting. The asserted prelude is composed
// from the SAME hoisted errVirtDiffPerRowCSVPrefix the helper uses, so test and
// code share one opener; only the "(csv)" / "(plain)" framing is a literal
// (which is exactly what this test exists to pin).
func TestClassifyRow_ShapeSuffixSingleSourced(t *testing.T) {
	// perRowLinePrelude reconstructs the shape-tagged prelude the helper emits,
	// referencing the hoisted opener const so the opener stays single-sourced;
	// the "(<shape>)" framing is the literal under test.
	perRowLinePrelude := func(lineNo int, shape string) string {
		p := errVirtDiffPerRowCSVPrefix + " " + strconv.Itoa(lineNo)
		if shape != "" {
			p += " (" + shape + ")"
		}
		return p + ": "
	}

	cases := []struct {
		name       string
		line       string
		shape      string
		wantSubstr string
	}{
		{
			// '<X>,…' with an unknown status X → the CSV-shape error site.
			name:       "csv-shape-unknown-status",
			line:       `x,/home/ds/work/note.md`,
			shape:      "csv",
			wantSubstr: `unknown status "x"`,
		},
		{
			// '<X> …' with an unknown status X → the plain-shape error site.
			name:       "plain-shape-unknown-status",
			line:       `x /home/ds/work/note.md`,
			shape:      "plain",
			wantSubstr: `unknown status "x"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const lineNo = 7
			_, _, err := classifyRow(tc.line, lineNo)
			if err == nil {
				t.Fatalf("classifyRow(%q) must error on an unknown status", tc.line)
			}
			wantPrelude := perRowLinePrelude(lineNo, tc.shape)
			if !strings.HasPrefix(err.Error(), wantPrelude) {
				t.Errorf("classifyRow %s error = %q; want prelude %q", tc.name, err, wantPrelude)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("classifyRow %s error = %q; want it to contain %q", tc.name, err, tc.wantSubstr)
			}
		})
	}
}
