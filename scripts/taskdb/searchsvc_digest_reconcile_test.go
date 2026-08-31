// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
)

// recordIndexMeta writes the single index_meta row (id=1) the SERVICE side
// (ingest.py record_index_meta) owns, carrying the digest the service recorded
// for its resident index. The Go reconcile reads this back via readServiceDigest.
func recordIndexMeta(t *testing.T, db *sql.DB, digest string) {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS index_meta (
		id           INTEGER PRIMARY KEY CHECK (id = 1),
		model_label  TEXT    NOT NULL DEFAULT '',
		dense_dims   INTEGER NOT NULL DEFAULT 0,
		sparse_model TEXT    NOT NULL DEFAULT '',
		built_at     INTEGER NOT NULL DEFAULT 0,
		chunk_count  INTEGER NOT NULL DEFAULT 0,
		digest       TEXT    NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatalf("create index_meta: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO index_meta(id, digest) VALUES(1, ?)
		 ON CONFLICT(id) DO UPDATE SET digest=excluded.digest`, digest,
	); err != nil {
		t.Fatalf("record index_meta: %v", err)
	}
}

// --- readServiceDigest -------------------------------------------------------

// TestReadServiceDigest_AbsentTableIsEmpty asserts that a DB with no index_meta
// table (the Python maintenance layer never ran) yields ("", nil) — the safe
// "nothing to reconcile against" answer, NOT an error.
func TestReadServiceDigest_AbsentTableIsEmpty(t *testing.T) {
	db := openFullSchemaDB(t) // initSchema creates meta, NOT index_meta
	got, err := readServiceDigest(db)
	if err != nil {
		t.Fatalf("absent index_meta must not error: %v", err)
	}
	if got != "" {
		t.Fatalf("absent index_meta must read empty digest, got %q", got)
	}
}

// TestReadServiceDigest_NoRowIsEmpty asserts an existing-but-empty index_meta
// table (no id=1 row) yields ("", nil).
func TestReadServiceDigest_NoRowIsEmpty(t *testing.T) {
	db := openFullSchemaDB(t)
	if _, err := db.Exec(`CREATE TABLE index_meta (id INTEGER PRIMARY KEY, digest TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatalf("create index_meta: %v", err)
	}
	got, err := readServiceDigest(db)
	if err != nil {
		t.Fatalf("no row must not error: %v", err)
	}
	if got != "" {
		t.Fatalf("no row must read empty digest, got %q", got)
	}
}

// TestReadServiceDigest_ReadsRecorded asserts the recorded digest reads back.
func TestReadServiceDigest_ReadsRecorded(t *testing.T) {
	db := openFullSchemaDB(t)
	recordIndexMeta(t, db, "abc123")
	got, err := readServiceDigest(db)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "abc123" {
		t.Fatalf("want recorded digest abc123, got %q", got)
	}
}

// --- reconcileServiceDigest --------------------------------------------------

// TestReconcileServiceDigest_MatchedReconciles asserts a service digest equal to
// the pushed digest reconciles (true) with no banner.
func TestReconcileServiceDigest_MatchedReconciles(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")
	d, err := corpusDigest(db)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	recordIndexMeta(t, db, d) // the service recorded EXACTLY what we pushed

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	if !reconcileServiceDigest(db, d) {
		t.Fatal("matched digests must reconcile (true)")
	}
	if buf.Len() != 0 {
		t.Fatalf("a matched reconcile must not emit a banner, got: %q", buf.String())
	}
}

// TestReconcileServiceDigest_DriftBanneredAndFalse asserts a service digest that
// DIFFERS from the pushed digest is flagged: a loud banner naming both digests,
// and a false return (never an abort).
func TestReconcileServiceDigest_DriftBanneredAndFalse(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")
	pushed, err := corpusDigest(db)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	// The service recorded a DIFFERENT corpus digest (stale / wrong DB).
	recordIndexMeta(t, db, "0000000000000000000000000000000000000000000000000000000000000000")

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	if reconcileServiceDigest(db, pushed) {
		t.Fatal("a drifted service digest must NOT reconcile (false)")
	}
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("[searchsvc DIGEST DRIFT]")) {
		t.Fatalf("a drift must emit a loud DIGEST DRIFT banner, got: %q", out)
	}
	if !bytes.Contains(buf.Bytes(), []byte(pushed)) {
		t.Fatalf("the drift banner must name the pushed digest, got: %q", out)
	}
}

// TestReconcileServiceDigest_NoServiceDigestIsNotDrift asserts that when the
// service recorded NO digest (absent index_meta), reconcile returns false with
// NO banner — nothing to compare against is not a drift.
func TestReconcileServiceDigest_NoServiceDigestIsNotDrift(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")
	d, err := corpusDigest(db)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	if reconcileServiceDigest(db, d) {
		t.Fatal("no service digest must not reconcile (false)")
	}
	if buf.Len() != 0 {
		t.Fatalf("no service digest must be silent (not a drift), got: %q", buf.String())
	}
}

// --- push integration: reconcile runs at reindex time ------------------------

// TestPushChangedChunks_ReconcilesAfterReindex asserts the push sets
// Reconciled=true when the service-recorded index_meta digest matches the pushed
// digest. The recording service writes index_meta on /reindex (mirroring the real
// service's record_index_meta), so the readback after reindex matches.
func TestPushChangedChunks_ReconcilesAfterReindex(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")
	insertChunk(t, db, 2, "docs/b.md", "B", "beta")
	want, err := corpusDigest(db)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	// A service that, on /reindex, records the SAME corpus digest into index_meta
	// (what the real ingest.py record_index_meta does from the resolved DB).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/embed":
			_, _ = w.Write([]byte(`{"dense":[0.0],"sparse":{},"dense_dims":1}`))
		case "/reindex":
			recordIndexMeta(t, db, want)
			_, _ = w.Write([]byte(`{"reindexed":true}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if !res.Reindex {
		t.Fatal("reindex must have run")
	}
	if !res.Reconciled {
		t.Fatalf("matched service digest must reconcile: pushed=%q want=%q", res.Digest, want)
	}
}

// TestPushChangedChunks_ReconcileDriftIsFailOpen asserts that a service that
// records a DIFFERENT digest on /reindex makes the push report Reconciled=false
// with a loud banner — but the push itself still SUCCEEDS (fail-open: chunks
// pushed, reindex true, no error, digest still recorded).
func TestPushChangedChunks_ReconcileDriftIsFailOpen(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/embed":
			_, _ = w.Write([]byte(`{"dense":[0.0],"sparse":{},"dense_dims":1}`))
		case "/reindex":
			// Service records a WRONG digest (it indexed a different corpus).
			recordIndexMeta(t, db, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
			_, _ = w.Write([]byte(`{"reindexed":true}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("a drift must NOT error (fail open): %v", err)
	}
	if !res.Reindex || res.Pushed != 1 {
		t.Fatalf("the push must still land (reindex+pushed): %+v", res)
	}
	if res.Reconciled {
		t.Fatal("a drifted service digest must report Reconciled=false")
	}
	if !bytes.Contains(buf.Bytes(), []byte("[searchsvc DIGEST DRIFT]")) {
		t.Fatalf("a reconcile drift must emit a loud banner, got: %q", buf.String())
	}
	// Fail-open: the digest was still recorded (the push succeeded).
	stored, err := readPushedDigest(db)
	if err != nil {
		t.Fatal(err)
	}
	if stored != res.Digest {
		t.Fatalf("a successful push must record its digest even on reconcile drift: %q vs %q", stored, res.Digest)
	}
}
