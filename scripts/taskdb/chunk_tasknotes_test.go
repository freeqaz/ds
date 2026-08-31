// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"testing"
)

// The dedup contract: a section that appears verbatim in a doc body and in a
// task body must produce the SAME chunk hash, because both go through
// docChunkBody + gitBlobSHA. This is the whole point of the unit.
func TestTaskChunkHashMatchesDocChunkHash(t *testing.T) {
	body := "preamble line\n\n## Section A\nalpha\n\n## Section B\nbeta\n"

	docChunks := docChunkBody(body)
	taskChunks := chunkTaskBody("01TASKAAAAAAAAAAAAAAAAAAAA", body)

	if len(taskChunks) != len(docChunks) {
		t.Fatalf("chunk count mismatch: doc=%d task=%d", len(docChunks), len(taskChunks))
	}
	for i, dc := range docChunks {
		tc := taskChunks[i]
		wantHash := gitBlobSHA([]byte(dc.body))
		if tc.Hash != wantHash {
			t.Errorf("chunk %d hash: task=%s want(doc)=%s", i, tc.Hash, wantHash)
		}
		if tc.Body != dc.body {
			t.Errorf("chunk %d body: task=%q doc=%q", i, tc.Body, dc.body)
		}
		if tc.Heading != dc.heading {
			t.Errorf("chunk %d heading: task=%q doc=%q", i, tc.Heading, dc.heading)
		}
		if tc.Seq != dc.seq {
			t.Errorf("chunk %d seq: task=%d doc=%d", i, tc.Seq, dc.seq)
		}
	}
}

// Re-chunking identical content must yield identical hashes (idempotent): the
// content hash is a pure function of the body, independent of the source id.
func TestChunkIdempotentAndContentKeyed(t *testing.T) {
	body := "## Heading\nsome content\n"

	a := chunkTaskBody("01TASKAAAAAAAAAAAAAAAAAAAA", body)
	b := chunkTaskBody("01TASKAAAAAAAAAAAAAAAAAAAA", body) // re-chunk, same source
	c := chunkTaskBody("01TASKBBBBBBBBBBBBBBBBBBBB", body) // different source, same body

	if len(a) != len(b) || len(a) != len(c) {
		t.Fatalf("len mismatch: a=%d b=%d c=%d", len(a), len(b), len(c))
	}
	for i := range a {
		if a[i].Hash != b[i].Hash {
			t.Errorf("chunk %d not idempotent: %s vs %s", i, a[i].Hash, b[i].Hash)
		}
		// Same body across different sources ⇒ same hash (the dedup key).
		if a[i].Hash != c[i].Hash {
			t.Errorf("chunk %d not content-keyed: %s vs %s", i, a[i].Hash, c[i].Hash)
		}
		// …but the Path still tracks the source so rows stay attributable.
		if a[i].Path == c[i].Path {
			t.Errorf("chunk %d path should differ by source: %q", i, a[i].Path)
		}
	}
}

// A note is a single chunk (seq 0, no heading) whose hash equals a doc preamble
// of the same text — so a note quoting a doc dedups against it.
func TestNoteChunkSingleAndDedupsAgainstDoc(t *testing.T) {
	text := "this exact sentence appears in a doc preamble"

	note := chunkNote("01NOTEAAAAAAAAAAAAAAAAAAAA", text)
	if note.Seq != 0 {
		t.Errorf("note seq = %d, want 0", note.Seq)
	}
	if note.Heading != "" {
		t.Errorf("note heading = %q, want empty", note.Heading)
	}
	if note.Body != text {
		t.Errorf("note body = %q, want %q", note.Body, text)
	}

	// A doc with this text as its preamble (no H2) chunks to one chunk.
	docChunks := docChunkBody(text)
	if len(docChunks) != 1 {
		t.Fatalf("expected single doc chunk, got %d", len(docChunks))
	}
	if note.Hash != gitBlobSHA([]byte(docChunks[0].body)) {
		t.Errorf("note hash %s != doc preamble hash %s", note.Hash, gitBlobSHA([]byte(docChunks[0].body)))
	}
	if note.Path != noteChunkScheme+"01NOTEAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("note path = %q", note.Path)
	}
}

// chunkTask prepends the title as chunk 0 and renumbers seq densely; an empty
// title chunks identically to chunkTaskBody.
func TestChunkTaskTitleAndSeq(t *testing.T) {
	title := "Fix the egress gateway"
	body := "intro\n\n## Details\nmore\n"

	withTitle := chunkTask("01TASKAAAAAAAAAAAAAAAAAAAA", title, body)
	bodyOnly := chunkTaskBody("01TASKAAAAAAAAAAAAAAAAAAAA", body)

	if len(withTitle) != len(bodyOnly)+1 {
		t.Fatalf("title chunk not prepended: with=%d bodyOnly=%d", len(withTitle), len(bodyOnly))
	}
	if withTitle[0].Body != title || withTitle[0].Seq != 0 || withTitle[0].Heading != "" {
		t.Errorf("title chunk wrong: %+v", withTitle[0])
	}
	if withTitle[0].Hash != gitBlobSHA([]byte(title)) {
		t.Errorf("title hash mismatch")
	}
	// Seq is a dense 0-based ordinal across the combined sequence.
	for i, ch := range withTitle {
		if ch.Seq != i {
			t.Errorf("chunk %d has seq %d, want dense %d", i, ch.Seq, i)
		}
	}

	// Empty title ⇒ identical to body-only chunking.
	noTitle := chunkTask("01TASKAAAAAAAAAAAAAAAAAAAA", "", body)
	if len(noTitle) != len(bodyOnly) {
		t.Fatalf("empty-title task should equal body-only: %d vs %d", len(noTitle), len(bodyOnly))
	}
	for i := range noTitle {
		if noTitle[i].Hash != bodyOnly[i].Hash || noTitle[i].Seq != bodyOnly[i].Seq {
			t.Errorf("chunk %d diverged from body-only", i)
		}
	}
}

// insertTaskNoteChunks writes the same doc_chunks shape doc sync uses and is
// idempotent on re-insert (DELETE-then-INSERT keyed on the surrogate doc_id),
// driving the real FTS triggers without error.
func TestInsertTaskNoteChunksRoundTrip(t *testing.T) {
	db := openTestDB(t) // reused helper: real doc_chunks table + FTS-less minimal schema

	const docID = int64(900001) // surrogate, disjoint from real docs.id
	chunks := chunkTask("01TASKAAAAAAAAAAAAAAAAAAAA", "Title", "body\n\n## Sec\ntext\n")

	if err := insertTaskNoteChunks(db, docID, chunks); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if got := countChunks(t, db, docID); got != len(chunks) {
		t.Fatalf("after first insert: %d rows, want %d", got, len(chunks))
	}

	// Re-insert (idempotent): row count is stable, not doubled.
	if err := insertTaskNoteChunks(db, docID, chunks); err != nil {
		t.Fatalf("re-insert: %v", err)
	}
	if got := countChunks(t, db, docID); got != len(chunks) {
		t.Fatalf("after re-insert: %d rows, want %d (DELETE-then-INSERT broken)", got, len(chunks))
	}

	// Hashes persisted byte-for-byte.
	assertHashesPersisted(t, db, docID, chunks)
}

func countChunks(t *testing.T, db *sql.DB, docID int64) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM doc_chunks WHERE doc_id=?`, docID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func assertHashesPersisted(t *testing.T, db *sql.DB, docID int64, want []taskNoteChunk) {
	t.Helper()
	rows, err := db.Query(`SELECT seq, body, hash FROM doc_chunks WHERE doc_id=? ORDER BY seq`, docID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var seq int
		var body, hash string
		if err := rows.Scan(&seq, &body, &hash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if i >= len(want) {
			t.Fatalf("more rows than expected")
		}
		if hash != want[i].Hash || body != want[i].Body || seq != want[i].Seq {
			t.Errorf("row %d: db{seq=%d hash=%s} want{seq=%d hash=%s}", i, seq, hash, want[i].Seq, want[i].Hash)
		}
		i++
	}
	if i != len(want) {
		t.Fatalf("read %d rows, want %d", i, len(want))
	}
}
