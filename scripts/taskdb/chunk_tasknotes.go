// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"fmt"
)

// chunk_tasknotes.go extends the search corpus from docs-only to
// "docs, tasks, notes" — the dedup payoff (docs/22 §8). doc sync chunks
// Markdown bodies into doc_chunks rows keyed by gitBlobSHA(chunk.body); this
// file produces the SAME row shape for task bodies and notes so a downstream
// semantic/keyword index can dedup a chunk that recurs across a doc, the task
// that cites it, and a note quoting it — they collapse to one chunk_hash.
//
// This unit is ADDITIVE and SELF-CONTAINED: the functions here take the data
// and return doc_chunks-equivalent rows; they do NOT rewire the live docSync
// entrypoint (that pipeline wiring is the documented fast-follow, and lives in
// cmd_doc.go which this unit does not touch). Derived chunks are NEVER frozen
// to git — same class as doc_chunks/embeddings.

// Synthetic path schemes. doc_chunks.path is a real file path; task/note rows
// borrow the same column with a stable URI so the corpus stays one namespace
// and the path is reconstructable from the source id. Keeping the prefix
// stable is part of the content-hash contract: a re-chunk of the same source
// must reproduce byte-identical rows.
const (
	taskChunkScheme = "task://"
	noteChunkScheme = "note://"
)

// taskNoteChunk is a doc_chunks-equivalent row: it carries every column doc
// sync writes (doc_id,path,heading,seq,body,hash) so a task/note chunk INSERTs
// into doc_chunks with the identical statement docSync uses. SourceID is the
// task/note ULID — the analogue of doc_chunks.doc_id, which for docs is the
// numeric docs.id; for tasks/notes the stable text id IS the source key, and
// the caller maps it onto whatever doc_id surrogate the pipeline assigns. It
// is carried here (not folded into doc_id) so a hermetic test can assert which
// source a chunk came from without a DB round-trip.
type taskNoteChunk struct {
	SourceID string // task or note ULID
	Path     string // synthetic URI, e.g. "task://01K…" / "note://01K…"
	Heading  string // mirrors docChunk.heading (H2 title, or "" for the preamble)
	Seq      int    // chunk ordinal within the source, 0-based (preamble = 0)
	Body     string // chunk text — the hashed payload
	Hash     string // gitBlobSHA(Body), byte-for-byte identical to doc_chunks.hash
}

// chunkTaskBody splits a task's body into doc_chunks-equivalent rows. The body
// is run through the EXACT same H2-boundary chunker doc sync uses
// (docChunkBody, defined in cmd_doc.go), so a section that appears verbatim in
// a doc and in a task body produces an identical chunk.Body and therefore an
// identical chunk.Hash — the dedup property. The hash is gitBlobSHA(body),
// matching doc_chunks exactly (cmd_doc.go inserts gitBlobSHA([]byte(ch.body))).
//
// The task title is NOT mixed into the body before chunking: doing so would
// shift every byte offset and break the doc⇄task dedup. The title is preserved
// as a standalone leading chunk only when non-empty (so a single-line task
// still indexes its title); see chunkTask.
func chunkTaskBody(taskID, body string) []taskNoteChunk {
	return wrapDocChunks(taskID, taskChunkScheme+taskID, docChunkBody(body))
}

// chunkTask is the convenience entry the pipeline will call: it indexes the
// task title as chunk 0 (a heading-only chunk, like a doc's preamble) followed
// by the body chunks, all under one synthetic path. An empty title is skipped
// so a body-only task chunks identically to chunkTaskBody. Seq is renumbered
// to stay a dense 0-based ordinal across the combined sequence.
//
// The title chunk's Body is the raw title text; its Hash is gitBlobSHA(title),
// so two tasks with the same title dedup to one title chunk just as two docs
// with the same preamble would.
func chunkTask(taskID, title, body string) []taskNoteChunk {
	var out []taskNoteChunk
	path := taskChunkScheme + taskID
	if title != "" {
		out = append(out, newTaskNoteChunk(taskID, path, "", title))
	}
	out = append(out, wrapDocChunks(taskID, path, docChunkBody(body))...)
	for i := range out {
		out[i].Seq = i
	}
	return out
}

// chunkNote turns a single note into one doc_chunks-equivalent row. A note is
// a short free-text comment with no Markdown sectioning contract, so it is a
// single chunk (seq 0, no heading) rather than H2-split — but the row shape and
// hash are identical to a doc chunk, so an identical note body dedups against a
// doc preamble or a task chunk of the same text.
func chunkNote(noteID, body string) taskNoteChunk {
	return newTaskNoteChunk(noteID, noteChunkScheme+noteID, "", body)
}

// wrapDocChunks adapts the in-package docChunk rows (from docChunkBody) to
// taskNoteChunk, computing the hash with the SAME gitBlobSHA cmd_doc.go uses on
// insert. This is the single seam that guarantees the task/note hash equals the
// doc hash for identical bodies.
func wrapDocChunks(sourceID, path string, chunks []docChunk) []taskNoteChunk {
	out := make([]taskNoteChunk, 0, len(chunks))
	for _, ch := range chunks {
		c := newTaskNoteChunk(sourceID, path, ch.heading, ch.body)
		c.Seq = ch.seq
		out = append(out, c)
	}
	return out
}

// newTaskNoteChunk builds one row with the canonical hash. Seq defaults to 0;
// callers that emit multi-chunk sequences renumber it. Centralizing the hash
// here keeps every code path on gitBlobSHA — the doc_chunks contract.
func newTaskNoteChunk(sourceID, path, heading, body string) taskNoteChunk {
	return taskNoteChunk{
		SourceID: sourceID,
		Path:     path,
		Heading:  heading,
		Seq:      0,
		Body:     body,
		Hash:     gitBlobSHA([]byte(body)),
	}
}

// insertTaskNoteChunks UPSERTs chunk rows into doc_chunks under a surrogate
// doc_id, replacing any prior rows for that source so a re-chunk is idempotent
// (mirroring docSync's DELETE-then-INSERT per doc). It is provided so a caller
// can wire the corpus without re-deriving the doc_chunks statement; the live
// pipeline wiring (which surrogate doc_id to mint per source) is the documented
// fast-follow and is NOT invoked from docSync this wave.
//
// docID is the doc_chunks.doc_id surrogate the caller assigns to this source
// (doc_chunks.doc_id is an INTEGER; tasks/notes have no numeric id, so the
// caller maps the ULID → a stable surrogate). The DELETE keys on doc_id, so the
// caller MUST use a doc_id disjoint from real docs and stable per source. The
// statement is byte-identical to docSync's insert, so the docs_ai/docs_au FTS
// triggers keep the index in step for free.
func insertTaskNoteChunks(db *sql.DB, docID int64, chunks []taskNoteChunk) error {
	if _, err := db.Exec(`DELETE FROM doc_chunks WHERE doc_id=?`, docID); err != nil {
		return fmt.Errorf("clear task/note chunks for doc_id %d: %w", docID, err)
	}
	for _, ch := range chunks {
		if _, err := db.Exec(
			`INSERT INTO doc_chunks(doc_id,path,heading,seq,body,hash) VALUES(?,?,?,?,?,?)`,
			docID, ch.Path, ch.Heading, ch.Seq, ch.Body, ch.Hash,
		); err != nil {
			return fmt.Errorf("insert task/note chunk %s seq %d: %w", ch.Path, ch.Seq, err)
		}
	}
	return nil
}
