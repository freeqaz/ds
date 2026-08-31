// SPDX-License-Identifier: Apache-2.0

// Package cow implements the host-side write-capture answer for the D29 disk
// stack: a raw golden image at rest with a per-session qcow2 overlay layered on
// top as the session's READ/WRITE delta (D5/D29/D31). After a session VM is
// destroyed its overlay is the single artifact holding "everything the agent
// wrote" (doc 02 §5); this package turns the host-side introspection tools'
// output — `virt-diff` (file-level, libguestfs) and `qemu-img info
// --backing-chain` (block-level, the backing-file invariant) — into a typed,
// testable enumeration of those writes.
//
// SCOPE (D29): the block-inspection MECHANISM is out of scope — we shell out to
// `qemu-img` / `virt-diff` and PARSE their output; this package never opens a
// qcow2 itself. The live legs that actually run those tools live in the sibling
// shell scripts (overlay-create.sh, enumerate-writes.sh) behind the DS_KVM_LIVE
// gate; this Go code is the pure parser those scripts (and the test fixtures)
// feed, so the introspection logic is unit-testable with zero qemu/libguestfs
// in CI (doc 05 §8: "even if introspection is crude").
package cow

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ChangeKind is the file-level edit class virt-diff reports for one path.
type ChangeKind string

const (
	// Added is a path present in the overlay but not the read-only base
	// (virt-diff leading "+ ").
	Added ChangeKind = "added"
	// Deleted is a path present in the base but removed in the overlay
	// (virt-diff leading "- ").
	Deleted ChangeKind = "deleted"
	// Modified is a path present in both whose content/metadata changed
	// (virt-diff leading "= ", which virt-diff emits for a changed file).
	Modified ChangeKind = "modified"
)

// Write is one file-level change the agent's session left in the overlay.
type Write struct {
	Kind ChangeKind
	Path string
	// Detail is the trailing virt-diff annotation for the row (e.g. the
	// size/mode columns), preserved verbatim for the v0 "crude" UX and for
	// the doc 06 level-(c) credential-leak assertion to scan. May be empty.
	Detail string
}

// Enumeration is the parsed result of inspecting a destroyed session's overlay.
type Enumeration struct {
	// OverlayPath / BasePath are the qcow2 overlay and its backing file as
	// reported by `qemu-img info --backing-chain` (when that output was fed
	// in); empty when only virt-diff output was parsed.
	OverlayPath string
	BasePath    string
	// BackingReadOnly records whether the backing file was asserted read-only
	// (D29 invariant: the base is NEVER written through the overlay). It is
	// only meaningful when ParseQemuImgInfo populated it.
	BackingReadOnly bool
	// DetectedMode is the concrete virt-diff shape (ModeCSV / ModePlain) the
	// writes were parsed under — the auto-detected guess, or the operator's
	// forced override. Empty for a qemu-img info parse (which has no shape).
	// Surfacing it lets the v0 summary print WHICH shape was used so a
	// mis-detect on a mixed-shape/header-only capture is visible.
	DetectedMode VirtDiffMode
	// Writes is the file-level delta, sorted by path.
	Writes []Write
}

// Counts returns the per-kind tally — the crude-but-honest v0 summary.
func (e *Enumeration) Counts() map[ChangeKind]int {
	c := map[ChangeKind]int{Added: 0, Deleted: 0, Modified: 0}
	for _, w := range e.Writes {
		c[w.Kind]++
	}
	return c
}

// VirtDiffMode names which textual shape a virt-diff capture is parsed as. The
// two real shapes are CSV (machine-readable, --csv) and Plain (the default).
// ModeAuto is not a shape but a request to auto-detect per input — it is what
// ParseVirtDiff uses and what SelectVirtDiffMode resolves AWAY from before a
// parse runs. Surfacing this type is the point of this hardening: an operator
// reviewing the crude v0 summary can see WHICH shape was detected (and spot a
// mis-detect), and can FORCE the shape rather than let the heuristic guess.
type VirtDiffMode string

const (
	// ModeAuto auto-detects the shape per input (the historical default and
	// what ParseVirtDiff does). It is a request, never a detected result:
	// SelectVirtDiffMode and ParseVirtDiffMode resolve it to ModeCSV/ModePlain.
	ModeAuto VirtDiffMode = "auto"
	// ModeCSV forces the RFC-4180 machine-readable shape (virt-diff --csv).
	ModeCSV VirtDiffMode = "csv"
	// ModePlain forces the default whitespace-delimited shape (no --csv).
	ModePlain VirtDiffMode = "plain"
	// ModeMixed is NOT a request and NEVER an operator override — it is a
	// DETECTED RESULT, recorded only in Enumeration.DetectedMode, when the
	// ModeAuto path could not commit the whole capture to one shape (the
	// homogeneous fast path failed) and fell back to the per-row classifier
	// because the capture is genuinely interleaved (some rows CSV-shaped,
	// some plain). Surfacing it keeps the crude v0 summary honest: an operator
	// sees that NO single shape described the capture and a per-row classifier
	// was used, rather than a silent mis-detect. It is never accepted as an
	// argument to ParseVirtDiffMode (passing it forces nothing — it falls
	// through to the unknown-mode error).
	ModeMixed VirtDiffMode = "mixed"
)

// errVirtDiffCSVPrefix and errVirtDiffPerRowCSVPrefix are the message PREFIXES
// the virt-diff parse paths attach to a parse failure. They are hoisted to named
// consts so a runtime caller, every emitting site, AND the tests assert against
// ONE source of truth — never a re-typed copy that could drift from the emitted
// text.
//
// errVirtDiffCSVPrefix opens the whole-capture parseVirtDiffCSV wrap, which WRAPS
// the underlying csv.Reader failure with %w (so errors.Unwrap still reaches the
// cause).
//
// errVirtDiffPerRowCSVPrefix is the SHARED opener of every per-row classifier
// error (classifyRow) — both the CSV-wrap site (which carries the line number
// then WRAPS csv.Reader's failure with %w) and the sibling per-row CSV/plain
// shape errors. classifyRow never references it directly: the perRowErr helper
// (below) composes the "<opener> <n> (<shape>): " prelude from it so the opener
// AND the "(shape)" framing are single-sourced, not seven hand-typed copies; the
// wrapped-cause tests assert against it for the %w site, and a drift in the
// opener would now break every per-row error at once rather than silently diverge.
const (
	errVirtDiffCSVPrefix       = "virt-diff csv:"
	errVirtDiffPerRowCSVPrefix = "virt-diff per-row line"
)

// perRowErr composes a classifyRow error from the SINGLE-SOURCED prelude —
// errVirtDiffPerRowCSVPrefix, the line number, and the per-row shape token
// (e.g. "csv" / "plain", or "" for a shape-less malformed-row error) — followed
// by format/args. It is the one place the "<opener> <n> (<shape>): " prelude is
// assembled, so every classifyRow site shares one prelude rather than
// hand-typing "%s %d (csv): " / "%s %d (plain): " / "%s %d: " eight times; a
// future prelude change (opener text, line-number rendering, or the "(shape)"
// framing) is now a single edit here instead of eight. The prelude carries no
// '%', so the composed format preserves any %w/%q verbs in `format` verbatim —
// a wrapped cause (fmt.Errorf %w) stays reachable by errors.Unwrap/errors.Is.
func perRowErr(lineNo int, shape, format string, args ...any) error {
	prelude := fmt.Sprintf("%s %d", errVirtDiffPerRowCSVPrefix, lineNo)
	if shape != "" {
		prelude += " (" + shape + ")"
	}
	return fmt.Errorf(prelude+": "+format, args...)
}

// NonHomogeneousVirtDiff reports whether a virt-diff capture is genuinely
// INTERLEAVED — data rows of BOTH the CSV and plain shapes in one capture — i.e.
// exactly the condition under which the ModeAuto detector falls back to the
// per-row classifier and records DetectedMode == ModeMixed. It is the EXPORTED
// single source of truth for that classification: cmd/parse consults it to decide
// whether a FORCED single-shape override (--mode-csv / --mode-plain) is masking a
// mixed capture, so the forced-path masking warning and the ModeAuto fallback
// agree by construction rather than by a re-implemented heuristic. It never
// parses or validates a row; a malformed row is still surfaced (as an error) by
// whichever parser then runs.
func NonHomogeneousVirtDiff(out string) bool {
	return nonHomogeneousVirtDiff(out)
}

// SelectVirtDiffMode reports which concrete shape the auto-detector resolves a
// virt-diff capture to — ModeCSV or ModePlain, NEVER ModeAuto. It is the
// detected-mode HOOK this unit surfaces: a caller (cmd/parse) prints the result
// so an operator reviewing the v0 summary can spot a mis-detect, and the parse
// path consults the SAME function so the printed mode is exactly what was used.
//
// The heuristic commits the WHOLE input to one shape from the first real status
// row: the CSV shape's first non-blank, non-header data row is "<status>,…" (a
// known status token immediately followed by a comma); anything else (including
// a header-only capture with no data row, or a mixed-shape capture whose first
// row is plain) resolves to ModePlain so the default-mode contract is preserved.
// That last-resort behavior is exactly why this hook exists: a mixed-shape or
// header-only capture can silently land in the wrong shape, so we make the
// guess VISIBLE and OVERRIDABLE rather than buried in looksLikeCSV.
func SelectVirtDiffMode(out string) VirtDiffMode {
	if looksLikeCSV(out) {
		return ModeCSV
	}
	return ModePlain
}

// ParseVirtDiff parses the output of `virt-diff -a <base.raw> -A <overlay.qcow2>`
// in either of the two shapes our capture leg may feed it, auto-detected per
// input. It is the back-compatible entry point: equivalent to
// ParseVirtDiffMode(out, ModeAuto).
//
//  1. CSV / machine-readable mode (virt-diff --csv, optionally --extra-stats).
//     RFC-4180 rows whose FIRST field is the status token and whose SECOND
//     field is the path; any further fields are the stat columns. The path is
//     a properly quoted CSV field, so embedded spaces, commas, and quotes are
//     delimited UNAMBIGUOUSLY — there is no whitespace truncation. This is the
//     preferred shape and is what enumerate-writes.sh requests on the live leg.
//
//  2. Default plain mode (no --csv): one line per changed path, "<status><sp>
//     <body>", where status is one of:
//
//     '+'  added in the overlay      (e.g. "+ /home/ds/work/new-file")
//     '-'  deleted in the overlay    (e.g. "- /etc/cron.d/removed")
//     '='  changed content/metadata  (e.g. "= /home/ds/.bashrc")
//
//     virt-diff does NOT quote paths in this mode, so a path with an embedded
//     space is ambiguous against the trailing --extra-stats columns. We bound
//     the path by peeling the FIXED-SHAPE stat columns off the RIGHT edge (each
//     a single whitespace-free token: octal mode, decimal size, uid/gid, …);
//     everything to their left is the path, embedded spaces included. A body
//     with no recognizable trailing stat columns is treated as a bare path
//     (the whole body), never split on its first space. This closes the v0
//     first-whitespace truncation that folded a path's tail into Detail and
//     under-reported a credential path the doc 06 §3c (c)-suite scans.
//
// In both modes: blank lines and any leading header (virt-diff's "Comparing …"
// banner, or a CSV column-name header) are skipped, and a row whose status is
// not one of the three known tokens is an ERROR — we refuse to silently drop a
// row we do not understand, because a dropped row is an under-reported agent
// write (doc 02 §5; the doc 06 §3c credential-leak assertion needs the
// enumeration to be complete AND its paths whole).
func ParseVirtDiff(out string) (*Enumeration, error) {
	return ParseVirtDiffMode(out, ModeAuto)
}

// ParseVirtDiffMode parses a virt-diff capture in the requested shape. With
// ModeAuto it resolves the shape via SelectVirtDiffMode (the historical
// behavior); with ModeCSV / ModePlain it FORCES that shape, so an operator can
// override a mis-detect (e.g. a mixed-shape or header-only capture the
// heuristic would otherwise commit to the wrong parser). An unknown mode is a
// hard error rather than a silent fallback. The Enumeration carries the
// concrete mode actually used in DetectedMode so the caller can report it.
//
// ModeAuto is layered, fast path first:
//
//  1. The WHOLE-CAPTURE auto-detect is the fast path for a HOMOGENEOUS capture
//     (every data row the same shape — the normal case, since virt-diff emits
//     one shape per invocation). nonHomogeneousVirtDiff reports whether the
//     capture carries data rows of BOTH shapes; when it does NOT, ModeAuto
//     resolves the single shape via SelectVirtDiffMode and runs that one parser,
//     preserving the EXACT historical behavior and the DetectedMode (ModeCSV /
//     ModePlain) it records.
//
//  2. FALLBACK: when the capture is genuinely INTERLEAVED — data rows of both
//     shapes mixed in one capture (e.g. two appended dumps), which no single
//     parser can faithfully read (it would either error on the other shape's
//     rows OR silently swallow them as "headers") — ModeAuto uses the per-row
//     classifier (parseVirtDiffPerRow), which classifies EACH row on its own
//     (status + ',' => a one-line CSV row; status + ' ' => a plain row) and
//     records DetectedMode = ModeMixed so the operator sees a per-row
//     classification was used rather than a dishonest single shape. A malformed
//     row still errors there — we never silently drop a row (doc 02 §5; the
//     doc 06 §3c credential-leak assertion needs the enumeration complete AND
//     its paths whole). No operator override is required for this to work.
//
// The explicit ModeCSV / ModePlain overrides are unchanged: they FORCE one shape
// and never consult the homogeneity check or the per-row fallback, so an
// operator escape hatch stays exact and predictable. ModeAuto remains a request,
// never a detected result.
func ParseVirtDiffMode(out string, mode VirtDiffMode) (*Enumeration, error) {
	if mode == ModeAuto {
		if nonHomogeneousVirtDiff(out) {
			// Genuinely interleaved — classify per row (no override needed).
			e, err := parseVirtDiffPerRow(out)
			if err != nil {
				return nil, err
			}
			e.DetectedMode = ModeMixed
			return e, nil
		}
		// Homogeneous fast path: commit to the single auto-detected shape.
		resolved := SelectVirtDiffMode(out)
		var (
			e   *Enumeration
			err error
		)
		switch resolved {
		case ModeCSV:
			e, err = parseVirtDiffCSV(out)
		default:
			e, err = parseVirtDiffPlain(out)
		}
		if err != nil {
			return nil, err
		}
		e.DetectedMode = resolved
		return e, nil
	}
	var (
		e   *Enumeration
		err error
	)
	switch mode {
	case ModeCSV:
		e, err = parseVirtDiffCSV(out)
	case ModePlain:
		e, err = parseVirtDiffPlain(out)
	default:
		return nil, fmt.Errorf("virt-diff: unknown parse mode %q (want auto|csv|plain)", mode)
	}
	if err != nil {
		return nil, err
	}
	e.DetectedMode = mode
	return e, nil
}

// nonHomogeneousVirtDiff reports whether a virt-diff capture is genuinely
// INTERLEAVED — i.e. it carries data rows of BOTH shapes (at least one
// CSV-shaped "<status>,…" row AND at least one plain-shaped "<status> …" row).
// Such a capture cannot be read faithfully by either single-shape parser, so the
// ModeAuto path routes it to the per-row classifier. A homogeneous capture (all
// data rows one shape, the normal case), a header-only capture, or an empty
// capture is NOT non-homogeneous and takes the whole-capture fast path. Only
// rows beginning with a KNOWN status token are considered data rows — a
// banner/header (any other leading byte) is ignored here exactly as the parsers
// skip it. This classifies by SHAPE only; it never validates a row, so a
// malformed row is still surfaced (as an error) by whichever parser then runs.
func nonHomogeneousVirtDiff(out string) bool {
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	sawCSV, sawPlain := false, false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if len(line) < 2 {
			continue
		}
		if _, known := kindFromStatus(line[:1]); !known {
			continue // header/banner or non-status line
		}
		switch line[1] {
		case ',':
			sawCSV = true
		case ' ':
			sawPlain = true
		}
		if sawCSV && sawPlain {
			return true
		}
	}
	return false
}

// parseVirtDiffPerRow is the ModeAuto fallback for a genuinely INTERLEAVED
// (non-homogeneous) virt-diff capture: a concatenation of CSV-shaped and
// plain-shaped runs that no single-shape parser can read. It classifies EACH
// status row on its own (classifyRow) and dispatches that ONE line to the
// matching shape:
//
//	'<status>,…'  => a one-line CSV record  -> csv.Reader on the line
//	'<status> …'  => a plain row            -> splitPathDetail on the body
//
// Blank lines and header/banner lines are skipped; a malformed row (a status
// token jammed against a non-delimiter byte, an unknown status in either shape,
// or a row with no path) is an ERROR — never silently dropped (doc 02 §5; the
// doc 06 §3c credential-leak assertion needs the enumeration complete AND its
// paths whole). The skip-vs-error decision mirrors the UNION of the two
// single-shape parsers and lives in classifyRow. Reuses kindFromStatus,
// splitPathDetail, and sortWrites so the per-row and whole-capture parsers share
// one source of truth for classification and path-boundary logic.
//
// SINGLE-LINE-CSV-RECORD LIMITATION (asymmetry vs parseVirtDiffCSV). This path
// is line-oriented: it bufio-scans the capture and hands classifyRow ONE
// physical line at a time, and classifyRow then runs csv.Reader on THAT single
// line. So a CSV record whose RFC-4180 quoted path field contains an embedded
// LITERAL newline — legal CSV, where the newline is part of the field value, not
// a record terminator — is split by the bufio scan into two physical lines
// BEFORE csv.Reader ever sees it: the first line ('+,"/home/ds/work/two') is fed
// to csv.Reader alone and is an unterminated quoted field, so the row ERRORS
// (an honest failure — never a silent drop or a mis-joined path). The
// whole-capture parseVirtDiffCSV does NOT share this limitation: it reads the
// ENTIRE input with a single csv.Reader, which spans physical newlines inside a
// quoted field and joins the record whole. The asymmetry is acceptable because
// (a) the per-row path is only reached on a genuinely INTERLEAVED capture (the
// homogeneous CSV case takes the whole-capture parseVirtDiffCSV fast path, which
// handles embedded newlines), (b) virt-diff paths are POSIX filenames, where a
// literal newline is pathological and effectively never occurs, and (c) the
// failure is loud (a parse error), so a write is never silently under-reported
// (doc 02 §5; doc 06 §3c). The fixtures/virtdiff-embedded-newline.txt fixture
// and TestParseVirtDiff_PerRowEmbeddedNewlineSplits pin this documented behavior
// so it cannot regress silently into a SILENT drop.
func parseVirtDiffPerRow(out string) (*Enumeration, error) {
	e := &Enumeration{}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		w, skip, err := classifyRow(line, lineNo)
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		e.Writes = append(e.Writes, w)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanning virt-diff output: %w", err)
	}
	sortWrites(e)
	return e, nil
}

// classifyRow classifies ONE virt-diff line, mirroring the UNION of the two
// single-shape parsers' semantics so the per-row fallback drops/errors exactly
// what they would. It returns (write, skip, err): skip=true for a header/banner
// line that is not a data row. The shape is decided by the byte after the
// first:
//
//   - '<X>,…'  is the CSV data shape. If X is a known status token it is a CSV
//     record (csv.Reader on the line); if X is some OTHER single char it is an
//     unknown CSV status and ERRORS (the parseVirtDiffCSV semantics — never a
//     silent drop). A CSV header like "type,name,…" has a MULTI-char first
//     field, so its second byte is not ',' and it does not reach here. NOTE the
//     csv.Reader runs on this ONE line: a CSV record whose quoted path field
//     carries an embedded LITERAL newline was already split by the line scan, so
//     the first physical line is an unterminated quoted field and ERRORS here —
//     the documented single-line-record asymmetry vs whole-capture
//     parseVirtDiffCSV (see parseVirtDiffPerRow's doc).
//   - '<X> …' is the plain DATA-ROW shape (a single char then a space). If X is
//     a known status it classifies (splitPathDetail bounds the path off the
//     right-edge stat columns); if X is any OTHER char it is an unknown plain
//     status and ERRORS — the parseVirtDiffPlain semantics, never a silent drop.
//     A banner ("Comparing image A …") has its second byte NON-space, so it is
//     not the data-row shape and does not reach this rule.
//   - a KNOWN status token jammed against a non-space, non-comma byte (e.g.
//     "+/foo") is a malformed plain row and ERRORS (the parseVirtDiffPlain
//     semantics).
//   - anything else (first byte not a status token, not '<X>,' and not '<X> '
//     shaped) is a header/banner line and is SKIPPED.
//
// A malformed row therefore still errors; a header is skipped; a data row of
// either shape classifies with its FULL path. lineNo is for diagnostics.
func classifyRow(line string, lineNo int) (w Write, skip bool, err error) {
	first := line[:1]
	kind, known := kindFromStatus(first)

	// CSV data shape: second byte is a comma.
	if len(line) >= 2 && line[1] == ',' {
		if !known {
			// An unknown single-char status in CSV shape — error, never drop
			// (parseVirtDiffCSV refuses an unknown single status token).
			return Write{}, false, perRowErr(lineNo, "csv", "unknown status %q in %q", first, line)
		}
		r := csv.NewReader(strings.NewReader(line))
		r.FieldsPerRecord = -1
		rec, rerr := r.Read()
		if rerr != nil {
			return Write{}, false, perRowErr(lineNo, "csv", "%w", rerr)
		}
		if len(rec) < 2 {
			return Write{}, false, perRowErr(lineNo, "csv", "status %q with no path field: %q", first, line)
		}
		path := rec[1]
		if strings.TrimSpace(path) == "" {
			return Write{}, false, perRowErr(lineNo, "csv", "empty path after status %q: %q", first, line)
		}
		return Write{Kind: kind, Path: path, Detail: strings.Join(rec[2:], ",")}, false, nil
	}

	// Plain DATA-ROW shape: second byte is a space. The status must be known or
	// it is an unknown plain status row — error (parseVirtDiffPlain refuses it),
	// never a header skip; a banner's second byte is non-space and falls through.
	if len(line) >= 2 && line[1] == ' ' {
		if !known {
			return Write{}, false, perRowErr(lineNo, "plain", "unknown status %q in %q", first, line)
		}
		rest := strings.TrimSpace(line[2:])
		if rest == "" {
			return Write{}, false, perRowErr(lineNo, "plain", "status %q with no path: %q", first, line)
		}
		path, detail := splitPathDetail(rest)
		if path == "" {
			return Write{}, false, perRowErr(lineNo, "plain", "empty path after status: %q", line)
		}
		return Write{Kind: kind, Path: path, Detail: detail}, false, nil
	}

	// Neither data-row shape. A KNOWN status token jammed against a non-space,
	// non-comma byte (e.g. "+/foo", or a bare "+") is a malformed row — error.
	if known {
		return Write{}, false, perRowErr(lineNo, "", "status %q not followed by ',' or ' ': %q", first, line)
	}
	// A non-status leading byte that is not data-row shaped is a header/banner.
	return Write{}, true, nil
}

// looksLikeCSV decides which virt-diff shape we were handed. The CSV shape's
// first non-blank, non-header data row is "<status>,…" — a known status token
// immediately followed by a comma. The plain shape is "<status> …" (a space).
// We scan for the first line that begins with a status token and inspect the
// very next byte; anything else (or no such line) is treated as plain so the
// existing default-mode contract is preserved.
func looksLikeCSV(out string) bool {
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if strings.TrimSpace(line) == "" || len(line) == 0 {
			continue
		}
		switch line[0] {
		case '+', '-', '=':
			return len(line) >= 2 && line[1] == ','
		}
		// A non-status leading char is a header/banner line in either mode;
		// keep scanning for the first real row.
	}
	return false
}

// parseVirtDiffCSV parses virt-diff --csv output. The status is field 0, the
// path is field 1 (CSV-quoted, so embedded spaces/commas/quotes survive
// intact), and any remaining fields are the --extra-stats columns, rejoined
// (comma-separated) into Detail. csv.Reader handles RFC-4180 quoting and the
// "" escape for an embedded quote, giving us the unambiguous delimiter the
// SCOPE calls for.
func parseVirtDiffCSV(out string) (*Enumeration, error) {
	e := &Enumeration{}
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1 // rows vary: 2 fields bare, more with --extra-stats
	rowNo := 0
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s %w", errVirtDiffCSVPrefix, err)
		}
		rowNo++
		if len(rec) == 0 {
			continue
		}
		status := strings.TrimSpace(rec[0])
		if status == "" {
			continue
		}
		kind, ok := kindFromStatus(status)
		if !ok {
			// A CSV header row (e.g. a leading "type,name,…") has a non-status
			// first field; skip it. A multi-char field that is not a header is
			// rejected below by the path/empty checks, but an unknown single
			// status token must still error so we never drop a real row.
			if len(status) == 1 {
				return nil, fmt.Errorf("virt-diff csv row %d: unknown status %q in %q", rowNo, status, strings.Join(rec, ","))
			}
			continue
		}
		if len(rec) < 2 {
			return nil, fmt.Errorf("virt-diff csv row %d: status %q with no path field", rowNo, status)
		}
		path := rec[1]
		if strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("virt-diff csv row %d: empty path after status %q", rowNo, status)
		}
		detail := strings.Join(rec[2:], ",")
		e.Writes = append(e.Writes, Write{Kind: kind, Path: path, Detail: detail})
	}
	sortWrites(e)
	return e, nil
}

// parseVirtDiffPlain parses default (non-CSV) virt-diff output. It bounds the
// path by peeling fixed-shape trailing stat columns off the RIGHT, so a path
// with embedded spaces is preserved whole rather than truncated at its first
// space (the v0 bug this unit closes).
func parseVirtDiffPlain(out string) (*Enumeration, error) {
	e := &Enumeration{}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		// virt-diff may print a banner / "Comparing ..." header before the
		// rows; skip any line that does not start with a known status token
		// followed by a space ONLY if it is clearly a header (no leading
		// status char at all). A leading status char with no path, or an
		// unknown leading char, is a parse error below.
		if len(line) < 2 || line[1] != ' ' {
			// Not "<char><space>..." shaped → treat as a header/noise line,
			// but reject the ambiguous case of a known status char jammed
			// against text (e.g. "+broken") so we never mis-split a real row.
			if c := line[0]; c == '+' || c == '-' || c == '=' {
				return nil, fmt.Errorf("virt-diff line %d: status %q not followed by a space: %q", lineNo, string(c), line)
			}
			continue
		}
		kind, ok := kindFromStatus(line[:1])
		if !ok {
			return nil, fmt.Errorf("virt-diff line %d: unknown status %q in %q", lineNo, string(line[0]), line)
		}
		rest := strings.TrimSpace(line[2:])
		if rest == "" {
			return nil, fmt.Errorf("virt-diff line %d: status %q with no path: %q", lineNo, string(line[0]), line)
		}
		path, detail := splitPathDetail(rest)
		if path == "" {
			return nil, fmt.Errorf("virt-diff line %d: empty path after status: %q", lineNo, line)
		}
		e.Writes = append(e.Writes, Write{Kind: kind, Path: path, Detail: detail})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanning virt-diff output: %w", err)
	}
	sortWrites(e)
	return e, nil
}

// kindFromStatus maps a virt-diff status token to its ChangeKind.
func kindFromStatus(s string) (ChangeKind, bool) {
	switch s {
	case "+":
		return Added, true
	case "-":
		return Deleted, true
	case "=":
		return Modified, true
	default:
		return "", false
	}
}

func sortWrites(e *Enumeration) {
	sort.SliceStable(e.Writes, func(i, j int) bool { return e.Writes[i].Path < e.Writes[j].Path })
}

// splitPathDetail splits a default-mode virt-diff row body into the leading
// path and any trailing --extra-stats columns, WITHOUT the first-whitespace
// truncation of v0. virt-diff's --extra-stats appends a fixed run of
// whitespace-free stat tokens (octal mode, decimal size, …) after the path;
// the path itself may contain embedded spaces and is NOT quoted in this mode.
// We therefore peel stat-shaped tokens off the RIGHT edge: starting from the
// last token, a token is a stat column iff it is a run of [0-9A-Fa-f] (octal
// mode digits, decimal size, uid/gid). The longest such trailing run is the
// Detail; everything before it is the path, embedded spaces intact. A body
// with no trailing stat run is a bare path (the whole body). This makes the
// path boundary unambiguous in plain mode without splitting on the first
// space — the CSV path (parseVirtDiffCSV) is preferred when available.
func splitPathDetail(body string) (path, detail string) {
	fields := strings.Fields(body)
	// Count the maximal trailing run of stat-shaped (whitespace-free numeric/
	// hex) tokens. virt-diff --extra-stats columns are all such tokens; a path
	// segment is not (it carries '/').
	statStart := len(fields)
	for statStart > 0 && isStatToken(fields[statStart-1]) {
		statStart--
	}
	// A path is never a stat token (it has a leading '/'), so statStart can
	// never consume the path token. If EVERY field is stat-shaped (no path),
	// the caller's empty-path guard will reject the row; keep the whole body as
	// the path here so that guard fires rather than silently dropping it.
	if statStart == 0 || statStart == len(fields) {
		return body, ""
	}
	// Reconstruct the path from the original body up to where the stat run
	// begins, preserving the path's interior whitespace verbatim. We locate the
	// stat run by trimming the joined trailing tokens off the right.
	detail = strings.Join(fields[statStart:], " ")
	path = strings.TrimRight(strings.TrimSuffix(strings.TrimRight(body, " \t"), detail), " \t")
	if path == "" {
		// Defensive: fall back to the whole body if the suffix trim degenerated.
		return body, ""
	}
	return path, detail
}

// isStatToken reports whether tok is shaped like a virt-diff --extra-stats
// column: a non-empty run of decimal/hex digits (octal mode like 100644,
// decimal size, uid/gid). A filesystem path is never such a token (it carries
// a '/' or non-digit characters), so this never mistakes a path for a stat.
func isStatToken(tok string) bool {
	if tok == "" {
		return false
	}
	for _, r := range tok {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// ParseQemuImgInfo parses `qemu-img info --backing-chain <overlay.qcow2>`
// output and asserts the D29 backing-file invariant: the overlay's backing file
// is the raw base, present, and the chain is exactly base→overlay (one backing
// level). The relevant fields per image stanza:
//
//	image: /var/lib/ds/sessions/<sid>/overlay.qcow2
//	file format: qcow2
//	backing file: /var/lib/ds/base/m0-base.raw
//	backing file format: raw
//
// The function populates OverlayPath / BasePath. It does NOT itself prove
// read-only mounting (that is a runtime property of how the base is opened —
// asserted by overlay-create.sh via the qcow2 backing-file relationship and the
// host file mode); it sets BackingReadOnly only when the caller has already
// established it and passed assumeBackingReadOnly=true. We keep that explicit so
// a static `qemu-img info` parse never overclaims a runtime guarantee.
func ParseQemuImgInfo(out string, assumeBackingReadOnly bool) (*Enumeration, error) {
	e := &Enumeration{BackingReadOnly: assumeBackingReadOnly}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	// qemu-img --backing-chain prints stanzas top-of-chain first (the overlay),
	// then each backing image. We take the FIRST "image:" as the overlay and
	// the FIRST "backing file:" as its base.
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "image:"):
			if e.OverlayPath == "" {
				e.OverlayPath = strings.TrimSpace(strings.TrimPrefix(line, "image:"))
			}
		case strings.HasPrefix(line, "backing file:"):
			if e.BasePath == "" {
				// "backing file:" may carry a trailing "(actual path: ...)"
				// annotation; take the field before any " (".
				v := strings.TrimSpace(strings.TrimPrefix(line, "backing file:"))
				if i := strings.Index(v, " ("); i >= 0 {
					v = strings.TrimSpace(v[:i])
				}
				e.BasePath = v
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanning qemu-img info output: %w", err)
	}
	if e.OverlayPath == "" {
		return nil, fmt.Errorf("qemu-img info: no `image:` line found")
	}
	if e.BasePath == "" {
		return nil, fmt.Errorf("qemu-img info: overlay %q has NO backing file — a session overlay MUST layer on the raw base (D29)", e.OverlayPath)
	}
	return e, nil
}
