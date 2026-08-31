// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// schema_canonical_test.go — DRIFT GUARD: db.go's embedded doc_chunks DDL must
// stay byte-equivalent (modulo whitespace / IF NOT EXISTS) to the single
// canonical source scripts/taskdb/schema/doc_chunks.sql.
//
// The doc_chunks DDL used to live in two hand-copied places (db.go's initSchema
// and a Python string literal in searchsvc/test_serve_backfill_provenance.py).
// schema/doc_chunks.sql is now the canonical source: the Python test reads it
// directly, and this Go test asserts db.go's embedded copy still matches it. A
// schema change in one place that the other did not track fails LOUDLY here
// instead of silently rotting either the runtime schema or the EXPLAIN tests.
//
// db.go keeps EMBEDDING the DDL (rather than reading the .sql at runtime) so the
// hot openDB path takes on no file-IO/embed dependency; this guard makes the
// embedded copy a faithful mirror of the canonical .sql rather than an
// independent source. Read-only: this test never edits db.go or the .sql.

// canonicalSchemaPath resolves scripts/taskdb/schema/doc_chunks.sql from the
// test's own package directory (the test runs with cwd = scripts/taskdb).
func canonicalSchemaPath() string {
	return filepath.Join("schema", "doc_chunks.sql")
}

// dbGoPath resolves scripts/taskdb/db.go from the package directory.
func dbGoPath() string {
	return "db.go"
}

// normalizeDDL whitespace- and synonym-normalizes one DDL statement so that
// formatting (tabs vs spaces, column alignment, trailing newline, embedded line
// comments, `IF NOT EXISTS`) does not register as drift but any real schema
// change (columns, types, constraints, indexed expression) does. Mirrors the
// Python guard's _normalize_ddl so both sides canonicalize identically.
func normalizeDDL(sql string) string {
	// Drop `-- ...` line comments.
	sql = regexp.MustCompile(`--[^\n]*`).ReplaceAllString(sql, " ")
	sql = strings.ToLower(sql)
	// Equate the IF NOT EXISTS form with the bare form.
	sql = regexp.MustCompile(`create\s+table\s+if\s+not\s+exists`).ReplaceAllString(sql, "create table")
	sql = regexp.MustCompile(`create\s+index\s+if\s+not\s+exists`).ReplaceAllString(sql, "create index")
	// Collapse whitespace runs, then tighten around structural punctuation.
	sql = regexp.MustCompile(`\s+`).ReplaceAllString(sql, " ")
	sql = regexp.MustCompile(`\s*([(),])\s*`).ReplaceAllString(sql, "$1")
	return strings.TrimRight(strings.TrimSpace(sql), ";")
}

// extractDocChunksDDL pulls the three canonical statements (CREATE TABLE
// doc_chunks, CREATE INDEX idx_doc_chunks_doc, CREATE INDEX idx_doc_chunks_hash)
// out of arbitrary SQL/Go source. The CREATE TABLE matcher uses a balanced
// non-greedy paren scan (`\([^()]*\)`) so a future nested-paren constraint in
// the table body does not silently truncate extraction at the first `)`.
func extractDocChunksDDL(t *testing.T, label, src string) (table, idxDoc, idxHash string) {
	t.Helper()

	tableRe := regexp.MustCompile(`(?is)CREATE TABLE(?:\s+IF NOT EXISTS)?\s+doc_chunks\s*\([^()]*\)\s*;`)
	tableM := tableRe.FindString(src)
	if tableM == "" {
		t.Fatalf("%s: could not find `CREATE TABLE doc_chunks (...)` — schema moved/renamed", label)
	}

	idxDocRe := regexp.MustCompile(`(?is)CREATE INDEX(?:\s+IF NOT EXISTS)?\s+idx_doc_chunks_doc\s+ON\s+doc_chunks\s*\([^()]*\)\s*;`)
	idxDocM := idxDocRe.FindString(src)
	if idxDocM == "" {
		t.Fatalf("%s: could not find `CREATE INDEX idx_doc_chunks_doc ON doc_chunks(...)`", label)
	}

	idxHashRe := regexp.MustCompile(`(?is)CREATE INDEX(?:\s+IF NOT EXISTS)?\s+idx_doc_chunks_hash\s+ON\s+doc_chunks\s*\([^()]*\)\s*;`)
	idxHashM := idxHashRe.FindString(src)
	if idxHashM == "" {
		t.Fatalf("%s: could not find `CREATE INDEX idx_doc_chunks_hash ON doc_chunks(...)`", label)
	}
	return tableM, idxDocM, idxHashM
}

func TestDocChunksDDLMatchesCanonicalSQL(t *testing.T) {
	canonPath := canonicalSchemaPath()
	canonBytes, err := os.ReadFile(canonPath)
	if err != nil {
		t.Fatalf("read canonical schema %s: %v", canonPath, err)
	}
	dbGoBytes, err := os.ReadFile(dbGoPath())
	if err != nil {
		t.Fatalf("read db.go: %v", err)
	}

	canonTable, canonIdxDoc, canonIdxHash := extractDocChunksDDL(t, canonPath, string(canonBytes))
	goTable, goIdxDoc, goIdxHash := extractDocChunksDDL(t, "db.go", string(dbGoBytes))

	for _, tc := range []struct {
		name        string
		canon, dbGo string
	}{
		{"CREATE TABLE doc_chunks", canonTable, goTable},
		{"CREATE INDEX idx_doc_chunks_doc", canonIdxDoc, goIdxDoc},
		{"CREATE INDEX idx_doc_chunks_hash", canonIdxHash, goIdxHash},
	} {
		cn := normalizeDDL(tc.canon)
		gn := normalizeDDL(tc.dbGo)
		if cn != gn {
			t.Errorf("%s drifted between db.go and %s.\n  canonical: %s\n  db.go:     %s\n"+
				"Reconcile db.go's initSchema with the canonical %s.",
				tc.name, canonPath, cn, gn, canonPath)
		}
	}
}
