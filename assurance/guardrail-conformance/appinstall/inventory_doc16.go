// SPDX-License-Identifier: Apache-2.0

package appinstall

import (
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// AnchorText is the single anchor the §13 row names: the prose label that
// precedes the §5.2 inventory table. The parser locates the table by this string
// so there is exactly ONE source of the inventory (the doc), never a hand-copied
// second table in Go.
const AnchorText = "D83 App-install permission inventory"

// doc16Excerpt is a verbatim copy of the doc 16 §5.2 anchor paragraph, inventory
// table, and closing invariant paragraph. It exists ONLY so this D51 public
// claims package stays runnable from a standalone checkout that does not carry
// the design-doc set (D51: "runnable anywhere"). It is a fallback, never a second
// source: InventoryFromDoc16 prefers the live doc whenever it is present, so the
// anti-drift property is unchanged in a checkout that has docs/.
//
//go:embed doc16-5.2-inventory.md
var doc16Excerpt string

// InventoryFromDoc16 parses the §5.2 D83 App-install permission inventory out of
// the doc 16 markdown at the default path (Doc16Path). It is the single anchor
// the manifest check diffs against — never a hand-copied table.
//
// When the design-doc set is not present in the checkout (the standalone D51
// case), it falls back to the embedded verbatim §5.2 excerpt. Any error other
// than "doc 16 absent" still fails loudly.
func InventoryFromDoc16() (Inventory, error) {
	data, err := os.ReadFile(Doc16Path())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return parseInventory(doc16Excerpt)
		}
		return Inventory{}, fmt.Errorf("reading doc 16 (%s): %w", Doc16Path(), err)
	}
	return parseInventory(string(data))
}

// parseInventory extracts the inventory table from doc-16 markdown text. It
// finds the first markdown table after the AnchorText line, then reads pipe rows
// until the table ends. Fails loudly if the anchor or a well-formed table is
// missing, so a doc restructure surfaces here rather than silently yielding an
// empty inventory (which would make every fixture "absent from inventory").
func parseInventory(doc string) (Inventory, error) {
	lines := strings.Split(doc, "\n")

	anchorIdx := -1
	for i, ln := range lines {
		if strings.Contains(ln, AnchorText) {
			anchorIdx = i
			break
		}
	}
	if anchorIdx < 0 {
		return Inventory{}, fmt.Errorf("doc 16 anchor %q not found — the §5.2 inventory "+
			"table is the single anchor this check diffs against; a doc restructure that "+
			"removed or renamed it must be reconciled here", AnchorText)
	}

	// Walk forward to the table header (the first line starting with "|" after the
	// anchor), then consume contiguous "|" rows. Skip the header row and the
	// "| --- | --- |" separator row.
	inv := Inventory{}
	inTable := false
	headerSeen := false
	separatorSeen := false
	for i := anchorIdx + 1; i < len(lines); i++ {
		ln := strings.TrimSpace(lines[i])
		isRow := strings.HasPrefix(ln, "|")
		if !isRow {
			if inTable {
				break // table ended
			}
			continue // still scanning for the table start
		}
		inTable = true
		if !headerSeen {
			headerSeen = true
			continue // the "| GitHub App permission | Access level | ... |" header
		}
		if !separatorSeen && isSeparatorRow(ln) {
			separatorSeen = true
			continue // the "| --- | --- | --- |" separator
		}
		cells := splitTableRow(ln)
		if len(cells) < 3 {
			return Inventory{}, fmt.Errorf("malformed §5.2 inventory row (need ≥3 cells): %q", ln)
		}
		row, err := parseRow(cells[0], cells[1], cells[2])
		if err != nil {
			return Inventory{}, err
		}
		inv.Rows = append(inv.Rows, row)
	}

	if !inTable || len(inv.Rows) == 0 {
		return Inventory{}, fmt.Errorf("no §5.2 inventory rows parsed after anchor %q — "+
			"expected the markdown permission table", AnchorText)
	}
	return inv, nil
}

// isSeparatorRow reports whether a pipe row is the markdown header separator
// ("| --- | --- | --- |"): every cell is only dashes/colons/spaces.
func isSeparatorRow(ln string) bool {
	for _, c := range splitTableRow(ln) {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Trim(c, "-: ") != "" {
			return false
		}
	}
	return true
}

// splitTableRow splits a markdown table row on unescaped "|", trimming the
// leading/trailing pipe and surrounding whitespace on each cell.
func splitTableRow(ln string) []string {
	ln = strings.TrimSpace(ln)
	ln = strings.TrimPrefix(ln, "|")
	ln = strings.TrimSuffix(ln, "|")
	parts := strings.Split(ln, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// parseRow interprets one inventory row's three cells.
//
// Permission cell: a concrete read permission is a single backtick-wrapped
// token (`contents:read`); a positioning row carries descriptive prose with no
// such bare token. We extract a backtick token if and only if the whole cell is
// exactly one `code` span (so the positioning rows' incidental code spans, e.g.
// quoted prose, do not get misread as a permission key).
//
// Access-level cell: starts with "read" → LevelRead; starts with "write" →
// LevelWrite; anything else (e.g. "not yet derivable") → LevelNotDerivable.
func parseRow(permCell, levelCell, flowCell string) (InventoryRow, error) {
	level := classifyLevel(levelCell)

	perm, isBareCode := soleCodeSpan(permCell)
	if level == LevelRead {
		// A read row MUST carry a concrete `*:read` permission token.
		if !isBareCode {
			return InventoryRow{}, fmt.Errorf("§5.2 read-level row has no concrete "+
				"`permission` token in its first cell: %q", permCell)
		}
		return InventoryRow{
			Permission:  perm,
			Level:       LevelRead,
			Flow:        flowCell,
			Positioning: false,
		}, nil
	}

	// Non-read row: a positioning record. Its permission key is the descriptive
	// cell text (used for "absent from inventory" matching, never as a grant). We
	// derive a stable key from the cell's leading clause so a fixture can name it
	// if a future test needs to (e.g. "CI dispatch", "Status checks",
	// "D56 enrollment flow").
	key := positioningKey(permCell)
	return InventoryRow{
		Permission:  key,
		Level:       level,
		Flow:        flowCell,
		Positioning: true,
	}, nil
}

// classifyLevel maps the access-level cell text to an AccessLevel. The match is
// on the leading word, case-insensitive, so "write (level not yet derivable)"
// classifies as write and "not yet derivable" as not-derivable.
func classifyLevel(cell string) AccessLevel {
	c := strings.ToLower(strings.TrimSpace(stripEmphasis(cell)))
	switch {
	case strings.HasPrefix(c, "read"):
		return LevelRead
	case strings.HasPrefix(c, "write"):
		return LevelWrite
	default:
		return LevelNotDerivable
	}
}

// soleCodeSpan returns (token, true) iff the cell is exactly one `code` span and
// nothing else (after trimming). Otherwise ("", false).
func soleCodeSpan(cell string) (string, bool) {
	c := strings.TrimSpace(cell)
	if len(c) < 2 || c[0] != '`' || c[len(c)-1] != '`' {
		return "", false
	}
	inner := c[1 : len(c)-1]
	if inner == "" || strings.Contains(inner, "`") {
		return "", false // empty or multiple spans
	}
	return inner, true
}

// positioningKey derives a short stable key from a positioning row's first cell:
// the text before the first em dash / " — " (the leading clause), stripped of
// markdown emphasis. e.g. "CI dispatch — exact permission/level ..." -> "CI dispatch".
func positioningKey(cell string) string {
	c := stripEmphasis(cell)
	if i := strings.Index(c, " — "); i >= 0 {
		c = c[:i]
	} else if i := strings.Index(c, " - "); i >= 0 {
		c = c[:i]
	}
	return strings.TrimSpace(c)
}

// stripEmphasis removes markdown bold/italic markers (** and *) so emphasis in a
// cell does not perturb prefix/clause matching.
func stripEmphasis(s string) string {
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "*", "")
	return s
}
