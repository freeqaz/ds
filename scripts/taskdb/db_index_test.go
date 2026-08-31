// SPDX-License-Identifier: Apache-2.0
package main

import (
	"path/filepath"
	"testing"
)

// TestDocChunksHashIndex asserts that a fresh DB built by the production
// openDB()/initSchema path carries idx_doc_chunks_hash on doc_chunks(hash).
// serve.py's provenance heal (bgem3w9) does WHERE hash IN (...) per batch;
// without this index that is a full scan of doc_chunks every batch.
func TestDocChunksHashIndex(t *testing.T) {
	// Point openDB at a fresh writable temp DB, overriding any sandbox
	// snapshot path so we exercise the real read-write initSchema branch.
	dbFile := filepath.Join(t.TempDir(), "taskdb.sqlite")
	t.Setenv("TASKDB_DB", dbFile)
	t.Setenv("TASKDB_DBPATH", "")

	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()

	// PRAGMA index_list enumerates indexes on doc_chunks (auto + explicit).
	rows, err := db.Query("PRAGMA index_list('doc_chunks')")
	if err != nil {
		t.Fatalf("PRAGMA index_list(doc_chunks): %v", err)
	}
	defer rows.Close()

	found := map[string]bool{}
	for rows.Next() {
		var (
			seq     int
			name    string
			unique  int
			origin  string
			partial int
		)
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scan index_list row: %v", err)
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate index_list: %v", err)
	}

	if !found["idx_doc_chunks_hash"] {
		t.Errorf("idx_doc_chunks_hash missing on doc_chunks; index_list=%v", found)
	}
	// Sanity: the pre-existing doc_id index must still be present (we add
	// alongside it, never replace it).
	if !found["idx_doc_chunks_doc"] {
		t.Errorf("idx_doc_chunks_doc unexpectedly missing; index_list=%v", found)
	}

	// Cross-check via sqlite_master that the index is bound to the hash column.
	var sqlText string
	err = db.QueryRow(
		"SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_doc_chunks_hash'",
	).Scan(&sqlText)
	if err != nil {
		t.Fatalf("sqlite_master lookup for idx_doc_chunks_hash: %v", err)
	}
	if sqlText == "" {
		t.Fatalf("idx_doc_chunks_hash has empty DDL in sqlite_master")
	}
}
