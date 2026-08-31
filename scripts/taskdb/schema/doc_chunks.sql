-- SPDX-License-Identifier: Apache-2.0
-- doc_chunks.sql — the CANONICAL DDL for the doc_chunks table and its two
-- indexes (idx_doc_chunks_doc, idx_doc_chunks_hash).
--
-- SINGLE SOURCE OF TRUTH. Before this file the same DDL lived in two places —
-- the embedded schema string in scripts/taskdb/db.go (initSchema) and a Python
-- string literal (_REAL_DOC_CHUNKS_SCHEMA) in
-- scripts/taskdb/searchsvc/test_serve_backfill_provenance.py — kept in lockstep
-- only by a human's eye. This .sql is now that one source:
--
--   * scripts/taskdb/searchsvc/test_serve_backfill_provenance.py READS this file
--     directly (no Python string-literal copy remains) to build the fresh DB its
--     EXPLAIN-QUERY-PLAN tests assert against.
--   * scripts/taskdb/schema_canonical_test.go (Go drift guard) asserts db.go's
--     embedded initSchema DDL still matches this file, statement-for-statement.
--   * scripts/taskdb/searchsvc/test_serve_backfill_provenance.py ALSO asserts
--     this file matches db.go (the existing db.go drift guard, repointed at the
--     .sql), so both sides are policed against the one canonical artifact.
--
-- LOW-RISK CHOICE (documented per task 01KV58D0C3): db.go is a landed file whose
-- runtime behavior must not change, so initSchema still EMBEDS its DDL inline
-- rather than reading this file at runtime (no new file-IO / embed dependency on
-- the hot openDB path). The duplication is eliminated as a SOURCE-OF-TRUTH
-- question by the two drift guards above: any divergence between db.go and this
-- file fails a test loudly. The Python test no longer carries its own copy at
-- all — it reads this file.
--
-- KEEP IN SYNC: the canonical contract is that the CREATE TABLE doc_chunks block
-- and the CREATE INDEX idx_doc_chunks_doc / idx_doc_chunks_hash statements here
-- are byte-equivalent (modulo whitespace and `IF NOT EXISTS`) to db.go's
-- initSchema. Change one, change the other; the drift guards enforce it.

-- DERIVED: H2-boundary chunks. Chunk 0 = preamble (before the first H2).
-- chunk.hash (blob sha of chunk text) is the embeddings seam.
CREATE TABLE IF NOT EXISTS doc_chunks (
	id      INTEGER PRIMARY KEY,
	doc_id  INTEGER NOT NULL,
	path    TEXT NOT NULL,
	heading TEXT NOT NULL DEFAULT '',
	seq     INTEGER NOT NULL,
	body    TEXT NOT NULL,
	hash    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_doc_chunks_doc ON doc_chunks(doc_id);
-- hash is the embeddings/provenance seam: serve.py's heal does WHERE hash IN (...)
-- over a batch; without this it full-scans doc_chunks per batch (bgem3w9).
CREATE INDEX IF NOT EXISTS idx_doc_chunks_hash ON doc_chunks(hash);
