// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"fmt"
	"hash/fnv"
	"path/filepath"
	"regexp"
	"strings"
)

// docSource is one parsed citation from a task body's trailing Sources: line:
// the resolved repo-relative doc path and the raw section fragment that follows
// the doc reference ("§6", "sections 2.2, 5", "§7 edge 3", …).
type docSource struct {
	DocPath string
	Section string
}

// docSourcesLineRe matches a `Sources: …` line anywhere in a task body. The
// parser keeps only the LAST such line — task bodies cite their docs in one
// trailing Sources: line, and doc link appends there.
var docSourcesLineRe = regexp.MustCompile(`(?m)^Sources:\s*(.+)$`)

// docCitationRe pulls the doc reference off the front of a single fragment:
// either a short form ("doc 06", "docs 6") or a literal repo path
// ("docs/06-testing-and-assurance.md"). Group 1 is the literal path (when
// present), group 2 the two-or-one-digit number of the short form. Whatever
// follows on the fragment is the raw section.
var docCitationRe = regexp.MustCompile(`^\s*(?:(docs/[0-9]{2}-[^\s;]+\.md)|docs?\s*0*([0-9]{1,2}))\b`)

// parseSources extracts the doc citations from a task body. It matches the
// last Sources: line, splits the remainder on ';', and for each fragment
// resolves the leading doc reference to a real file via the docs/NN-*.md glob.
// The rest of the fragment (after the reference) is the raw section. Fragments
// whose reference resolves to no file — e.g. "D18", a decision number — are
// skipped here and surfaced by `audit dag`.
func parseSources(body string) []docSource {
	m := docSourcesLineRe.FindAllStringSubmatch(body, -1)
	if len(m) == 0 {
		return nil
	}
	line := m[len(m)-1][1] // the LAST Sources: line wins

	var out []docSource
	for _, frag := range strings.Split(line, ";") {
		frag = strings.TrimSpace(frag)
		if frag == "" {
			continue
		}
		c := docCitationRe.FindStringSubmatch(frag)
		if c == nil {
			continue // unresolvable citation (e.g. "D18"); audit dag surfaces it
		}
		path := ""
		if c[1] != "" {
			path = docSourceResolveLiteral(c[1])
		} else {
			path = docSourceResolveNumber(c[2])
		}
		if path == "" {
			continue // reference matched no docs/NN-*.md file on disk
		}
		section := strings.TrimSpace(frag[len(c[0]):])
		out = append(out, docSource{DocPath: path, Section: section})
	}
	return out
}

// docSourceResolveNumber maps a doc number ("6", "06") to its file via the
// docs/NN-*.md glob, returning "" when no such doc exists on disk.
func docSourceResolveNumber(num string) string {
	if len(num) == 1 {
		num = "0" + num
	}
	matches, err := filepath.Glob("docs/" + num + "-*.md")
	if err != nil || len(matches) == 0 {
		return ""
	}
	return filepath.ToSlash(matches[0])
}

// docSourceResolveLiteral confirms a literal docs/NN-….md citation names a
// real file (the glob proves existence and normalizes separators), returning
// "" when it does not.
func docSourceResolveLiteral(p string) string {
	p = filepath.ToSlash(p)
	matches, err := filepath.Glob(p)
	if err != nil || len(matches) == 0 {
		return ""
	}
	return filepath.ToSlash(matches[0])
}

// --- task/note chunk sourcing -----------------------------------------------
//
// The doc index walks files; tasks and notes have no file, so syncDocs also
// pulls task/note bodies straight from the DB, chunks them via the shipped
// chunkTask/chunkNote (chunk_tasknotes.go), and stores them in doc_chunks under
// a SURROGATE doc_id. The surrogate must live in a space DISJOINT from real
// docs.id (positive autoincrement starting at 1) because insertTaskNoteChunks
// DELETEs by doc_id — a collision would silently wipe a real doc's chunks.

// surrogateDocID maps a task/note synthetic path ("task://ULID" / "note://ULID")
// to a STABLE, NEGATIVE doc_chunks.doc_id that can never equal a real docs.id
// (which is a positive autoincrement). The hash is folded into the strictly
// negative range [math.MinInt64+1 .. -1] so:
//   - it is disjoint from every real doc_id (all >= 1),
//   - it is disjoint from 0 (never a valid docs.id, but also never minted here),
//   - it is deterministic per source path (a re-chunk of the same source reuses
//     the same surrogate, so insertTaskNoteChunks' DELETE-then-INSERT is the
//     idempotent re-chunk docSync expects).
//
// FNV-1a/64 over the synthetic path gives a well-distributed 64-bit value; we
// OR the sign bit and clear the all-ones degenerate case so the result is always
// a strictly-negative int64.
func surrogateDocID(syntheticPath string) int64 {
	h := fnv.New64a()
	h.Write([]byte(syntheticPath))
	v := h.Sum64()
	// Force the sign bit so the value is negative once reinterpreted as int64,
	// and avoid the all-ones pattern (-1 is reserved as a sentinel elsewhere by
	// convention; keeping the surrogate strictly < -1 leaves -1 free and is still
	// a 63-bit space, ample for collision-free ULIDs).
	v |= 1 << 63
	id := int64(v)
	if id >= -1 {
		// Defensive: the sign bit guarantees id < 0, but pin off the -1 sentinel.
		id = -2
	}
	return id
}

// taskNoteSource is one row of the task/note corpus to (re)index: its ULID, the
// chunks chunkTask/chunkNote produced, and the synthetic path they share. The
// surrogate doc_id is derived from Path via surrogateDocID.
type taskNoteSource struct {
	Path   string // synthetic URI: "task://ULID" or "note://ULID"
	Chunks []taskNoteChunk
}

// collectTaskNoteChunks reads every task and note from the DB and chunks each
// into doc_chunks-equivalent rows via the shipped chunkTask/chunkNote. The
// returned slice is one entry per source (task or note), each carrying its
// synthetic path and chunk set; the caller mints the surrogate doc_id per Path
// and inserts. Notes with an empty body are skipped (chunkNote of "" would
// index an empty chunk). Tasks always produce at least a title chunk.
func collectTaskNoteChunks(db *sql.DB) ([]taskNoteSource, error) {
	var out []taskNoteSource

	taskRows, err := db.Query(`SELECT id, title, body FROM tasks ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("scan tasks for chunking: %w", err)
	}
	for taskRows.Next() {
		var id, title, body string
		if err := taskRows.Scan(&id, &title, &body); err != nil {
			taskRows.Close()
			return nil, err
		}
		chunks := chunkTask(id, title, body)
		if len(chunks) == 0 {
			continue
		}
		out = append(out, taskNoteSource{Path: taskChunkScheme + id, Chunks: chunks})
	}
	taskRows.Close()
	if err := taskRows.Err(); err != nil {
		return nil, err
	}

	noteRows, err := db.Query(`SELECT id, body FROM notes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("scan notes for chunking: %w", err)
	}
	for noteRows.Next() {
		var id, body string
		if err := noteRows.Scan(&id, &body); err != nil {
			noteRows.Close()
			return nil, err
		}
		if strings.TrimSpace(body) == "" {
			continue // an empty note has nothing to index
		}
		ch := chunkNote(id, body)
		out = append(out, taskNoteSource{Path: noteChunkScheme + id, Chunks: []taskNoteChunk{ch}})
	}
	noteRows.Close()
	if err := noteRows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

// pruneTaskNoteChunks drops doc_chunks rows for task:// / note:// sources whose
// synthetic path is no longer in liveSet (the source was deleted, or — for notes
// — emptied). It mirrors syncDocs' file-prune branch: a vanished source must not
// leave phantom chunks in the index. Real-doc rows (path without a synthetic
// scheme) are never touched. Returns the number of distinct sources pruned.
func pruneTaskNoteChunks(db *sql.DB, liveSet map[string]bool) (int, error) {
	rows, err := db.Query(
		`SELECT DISTINCT path FROM doc_chunks WHERE path LIKE ? OR path LIKE ?`,
		taskChunkScheme+"%", noteChunkScheme+"%",
	)
	if err != nil {
		return 0, fmt.Errorf("scan task/note chunk paths: %w", err)
	}
	var stale []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return 0, err
		}
		if !liveSet[p] {
			stale = append(stale, p)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, p := range stale {
		if _, err := db.Exec(`DELETE FROM doc_chunks WHERE doc_id=?`, surrogateDocID(p)); err != nil {
			return 0, fmt.Errorf("prune task/note chunks for %s: %w", p, err)
		}
	}
	return len(stale), nil
}
