// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// openFullSchemaDB opens a temp, writable sqlite with the full production schema
// (docs/doc_chunks/tasks/notes + FTS triggers) so a test can exercise syncDocs'
// task/note arm and the surrogate-doc_id disjointness end to end. Hermetic: a
// fresh temp file per test, no network, no live model.
func openFullSchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sqlite")
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema: %v", err)
	}
	return db
}

// --- /search client: hit mapping --------------------------------------------

// TestTrySearchService_MapsHitsInOrder asserts the client posts /search, decodes
// the wire results, and maps them into docSearchHit rows in the SERVICE-PROVIDED
// order (fused_score descending — the service is authoritative on order), with
// the fused score carried in Score and the kind classified from the doc_path
// scheme.
func TestTrySearchService_MapsHitsInOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search" {
			t.Errorf("expected POST to /search, got %s", r.URL.Path)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req["query"] != "default-deny" {
			t.Errorf("query not threaded: got %v", req["query"])
		}
		_ = json.NewEncoder(w).Encode(searchsvcResponse{
			Degraded: false,
			Query:    "default-deny",
			Results: []searchsvcResult{
				{ChunkHash: "h1", DocPath: "docs/04-architecture-overview.md", Heading: "§6", FusedScore: 0.91, DenseScore: 0.5, SparseScore: 0.4},
				{ChunkHash: "h2", DocPath: "task://01ABC", Heading: "", FusedScore: 0.55, DenseScore: 0.3, SparseScore: 0.2},
				{ChunkHash: "h3", DocPath: "note://01DEF", Heading: "", FusedScore: 0.22, DenseScore: 0.1, SparseScore: 0.1},
			},
		})
	}))
	defer srv.Close()

	hits, ok := trySearchService(context.Background(), srv.URL, "default-deny", 10)
	if !ok {
		t.Fatal("trySearchService returned ok=false on a healthy service")
	}
	if len(hits) != 3 {
		t.Fatalf("want 3 hits, got %d", len(hits))
	}
	// FULL ordering + field mapping, not len>0.
	wantPaths := []string{"docs/04-architecture-overview.md", "task://01ABC", "note://01DEF"}
	wantKinds := []string{"doc", "task", "note"}
	wantScores := []float64{0.91, 0.55, 0.22}
	for i, h := range hits {
		if h.Path != wantPaths[i] {
			t.Errorf("hit[%d].Path = %q, want %q", i, h.Path, wantPaths[i])
		}
		if h.Kind != wantKinds[i] {
			t.Errorf("hit[%d].Kind = %q, want %q", i, h.Kind, wantKinds[i])
		}
		if h.Score != wantScores[i] {
			t.Errorf("hit[%d].Score = %v, want %v", i, h.Score, wantScores[i])
		}
	}
	if hits[0].Heading != "§6" {
		t.Errorf("heading not mapped: %q", hits[0].Heading)
	}
}

// --- fail-open: unset URL ----------------------------------------------------

// TestTrySearchService_FailOpenOnUnset asserts an empty URL returns (nil, false)
// — the caller takes the local path — and emits NO degraded banner (there is
// nothing to degrade from).
func TestTrySearchService_FailOpenOnUnset(t *testing.T) {
	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	hits, ok := trySearchService(context.Background(), "  ", "q", 10)
	if ok {
		t.Fatal("unset URL must return ok=false")
	}
	if hits != nil {
		t.Fatalf("unset URL must return nil hits, got %v", hits)
	}
	if buf.Len() != 0 {
		t.Fatalf("unset URL must not emit a banner, got: %q", buf.String())
	}
}

// --- fail-open: service down -------------------------------------------------

// TestTrySearchService_FailOpenOnError asserts an unreachable service returns
// (nil, false) — NOT an error — and emits the loud degraded banner, so the
// caller falls back to local search. The service is closed before the call.
func TestTrySearchService_FailOpenOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now refused

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	hits, ok := trySearchService(context.Background(), url, "q", 10)
	if ok {
		t.Fatal("a dead service must return ok=false (fail open)")
	}
	if hits != nil {
		t.Fatalf("a dead service must return nil hits, got %v", hits)
	}
	if !bytes.Contains(buf.Bytes(), []byte("[searchsvc DEGRADED]")) {
		t.Fatalf("expected a loud degraded banner, got: %q", buf.String())
	}
}

// TestTrySearchService_FailOpenOnDegraded asserts a degraded=true reply (service
// up but retrieval modules not ready) fails open with a banner, so the local
// path serves real results instead of the empty degraded set.
func TestTrySearchService_FailOpenOnDegraded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(searchsvcResponse{Degraded: true, Results: []searchsvcResult{}})
	}))
	defer srv.Close()

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	hits, ok := trySearchService(context.Background(), srv.URL, "q", 10)
	if ok {
		t.Fatal("a degraded reply must return ok=false (fail open)")
	}
	if hits != nil {
		t.Fatalf("degraded reply must return nil hits, got %v", hits)
	}
	if !bytes.Contains(buf.Bytes(), []byte("[searchsvc DEGRADED]")) {
		t.Fatalf("expected a degraded banner, got: %q", buf.String())
	}
}

// TestTrySearchService_FailOpenOnNon2xx asserts a 500 fails open with a banner.
func TestTrySearchService_FailOpenOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "model exploded", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	hits, ok := trySearchService(context.Background(), srv.URL, "q", 10)
	if ok || hits != nil {
		t.Fatalf("a 500 must fail open: ok=%v hits=%v", ok, hits)
	}
	if !bytes.Contains(buf.Bytes(), []byte("[searchsvc DEGRADED]")) {
		t.Fatalf("expected a degraded banner, got: %q", buf.String())
	}
}

// --- joinSearchURL -----------------------------------------------------------

func TestJoinSearchURL(t *testing.T) {
	cases := map[string]string{
		"http://h:8099":         "http://h:8099/search",
		"http://h:8099/":        "http://h:8099/search",
		"http://h:8099/search":  "http://h:8099/search",
		"http://h:8099/search/": "http://h:8099/search",
		"  http://h:8099  ":     "http://h:8099/search",
	}
	for in, want := range cases {
		if got := joinSearchURL(in); got != want {
			t.Errorf("joinSearchURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- surrogate doc_id disjointness ------------------------------------------

// TestSurrogateDocID_AlwaysNegativeAndDisjoint asserts the surrogate doc_id for
// a task/note path is ALWAYS strictly negative (so it can never equal a real
// docs.id, which is a positive autoincrement starting at 1), is stable per path,
// and differs across paths.
func TestSurrogateDocID_AlwaysNegativeAndDisjoint(t *testing.T) {
	paths := []string{
		taskChunkScheme + "01HAAAAAAAAAAAAAAAAAAAAAAA",
		taskChunkScheme + "01HBBBBBBBBBBBBBBBBBBBBBBB",
		noteChunkScheme + "01HCCCCCCCCCCCCCCCCCCCCCCC",
		noteChunkScheme + "01HDDDDDDDDDDDDDDDDDDDDDDD",
	}
	seen := map[int64]string{}
	for _, p := range paths {
		id := surrogateDocID(p)
		if id >= 0 {
			t.Errorf("surrogateDocID(%q) = %d, must be strictly negative (disjoint from positive docs.id)", p, id)
		}
		// Stable per path.
		if id2 := surrogateDocID(p); id2 != id {
			t.Errorf("surrogateDocID(%q) not stable: %d vs %d", p, id, id2)
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("surrogate collision: %q and %q both → %d", prev, p, id)
		}
		seen[id] = p
	}
}

// TestSurrogateNeverEqualsRealDocID is the load-bearing safety property: a
// surrogate doc_id can NEVER equal the autoincrement id of a real doc, so
// insertTaskNoteChunks' DELETE-by-doc_id can never wipe a real doc's chunks.
// We sync a real doc + a task + a note through syncDocs and assert (a) the real
// doc got a positive id, (b) the task/note chunks live under negative ids, and
// (c) the real doc's chunks survive a task/note re-sync.
func TestSurrogateNeverEqualsRealDocID(t *testing.T) {
	db := openFullSchemaDB(t)

	// A real doc row (positive autoincrement id) with one chunk.
	res, err := db.Exec(`INSERT INTO docs(path,title,hash,headings,mtime,indexed_at) VALUES('docs/x.md','X','h','',0,0)`)
	if err != nil {
		t.Fatalf("insert doc: %v", err)
	}
	realID, _ := res.LastInsertId()
	if realID <= 0 {
		t.Fatalf("real doc id must be positive, got %d", realID)
	}
	if _, err := db.Exec(
		`INSERT INTO doc_chunks(doc_id,path,heading,seq,body,hash) VALUES(?,?,?,?,?,?)`,
		realID, "docs/x.md", "", 0, "real body", gitBlobSHA([]byte("real body")),
	); err != nil {
		t.Fatalf("insert real chunk: %v", err)
	}

	// A task + a note; index them via the same arm syncDocs uses.
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES('01TASKAAAAAAAAAAAAAAAAAAAA','Build the gate','default-deny first',?,0,0,0)`,
		"open",
	); err != nil {
		t.Fatalf("insert task: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO notes(id,task_id,body,author,created_at) VALUES('01NOTEAAAAAAAAAAAAAAAAAAAA','01TASKAAAAAAAAAAAAAAAAAAAA','a passing thought','me',0)`,
	); err != nil {
		t.Fatalf("insert note: %v", err)
	}

	if err := syncTaskNoteChunks(db, true); err != nil {
		t.Fatalf("syncTaskNoteChunks: %v", err)
	}

	// The real doc's chunk must survive.
	var realChunks int
	if err := db.QueryRow(`SELECT COUNT(*) FROM doc_chunks WHERE doc_id=?`, realID).Scan(&realChunks); err != nil {
		t.Fatal(err)
	}
	if realChunks != 1 {
		t.Fatalf("real doc chunk wiped by task/note sync: want 1, got %d", realChunks)
	}

	// Every task/note chunk lives under a NEGATIVE doc_id.
	rows, err := db.Query(`SELECT doc_id, path FROM doc_chunks WHERE path LIKE 'task://%' OR path LIKE 'note://%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var taskNoteRows int
	for rows.Next() {
		var docID int64
		var path string
		if err := rows.Scan(&docID, &path); err != nil {
			t.Fatal(err)
		}
		if docID >= 0 {
			t.Errorf("task/note chunk %q has non-negative doc_id %d (could collide with a real doc)", path, docID)
		}
		taskNoteRows++
	}
	if taskNoteRows == 0 {
		t.Fatal("expected at least one task/note chunk to be indexed")
	}
}

// TestSyncTaskNoteChunks_Prune asserts a vanished source's chunks are pruned on
// re-sync (mirroring syncDocs' file prune), while a surviving source keeps its
// chunks.
func TestSyncTaskNoteChunks_Prune(t *testing.T) {
	db := openFullSchemaDB(t)
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES('01TASKAAAAAAAAAAAAAAAAAAAA','keep me','body',?,0,0,0)`, "open",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,created_at,updated_at) VALUES('01TASKBBBBBBBBBBBBBBBBBBBB','drop me','body',?,0,0,0)`, "open",
	); err != nil {
		t.Fatal(err)
	}
	if err := syncTaskNoteChunks(db, true); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	var before int
	if err := db.QueryRow(`SELECT COUNT(DISTINCT path) FROM doc_chunks WHERE path LIKE 'task://%'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != 2 {
		t.Fatalf("want 2 task sources indexed, got %d", before)
	}

	// Delete the second task and re-sync: its chunks must be pruned.
	if _, err := db.Exec(`DELETE FROM tasks WHERE id='01TASKBBBBBBBBBBBBBBBBBBBB'`); err != nil {
		t.Fatal(err)
	}
	if err := syncTaskNoteChunks(db, true); err != nil {
		t.Fatalf("re-sync: %v", err)
	}
	var dropped int
	if err := db.QueryRow(`SELECT COUNT(*) FROM doc_chunks WHERE path='task://01TASKBBBBBBBBBBBBBBBBBBBB'`).Scan(&dropped); err != nil {
		t.Fatal(err)
	}
	if dropped != 0 {
		t.Errorf("deleted task's chunks not pruned: %d remain", dropped)
	}
	var kept int
	if err := db.QueryRow(`SELECT COUNT(*) FROM doc_chunks WHERE path='task://01TASKAAAAAAAAAAAAAAAAAAAA'`).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept == 0 {
		t.Error("surviving task's chunks were wrongly pruned")
	}
}

// --- embedderFromFlag selection ---------------------------------------------

// TestEmbedderFromFlag_Selection asserts the URL/cmd/both selection matrix:
// a URL builds an HTTP embedder (reporting the stable bge-m3-http label), a cmd
// builds a cmd embedder, setting BOTH is a loud error, and neither is the legacy
// loud-failure from newCmdEmbedder.
func TestEmbedderFromFlag_Selection(t *testing.T) {
	// URL only → httpEmbedder with the stable label.
	emb, err := embedderFromFlag("", "http://127.0.0.1:8099")
	if err != nil {
		t.Fatalf("url-only should succeed: %v", err)
	}
	he, ok := emb.(*httpEmbedder)
	if !ok {
		t.Fatalf("url-only should build an *httpEmbedder, got %T", emb)
	}
	if he.modelLabel != httpEmbedderModelLabel {
		t.Errorf("http embedder label = %q, want %q", he.modelLabel, httpEmbedderModelLabel)
	}

	// cmd only → cmdEmbedder (not an httpEmbedder).
	emb2, err := embedderFromFlag("python3 embed.py", "")
	if err != nil {
		t.Fatalf("cmd-only should succeed: %v", err)
	}
	if _, isHTTP := emb2.(*httpEmbedder); isHTTP {
		t.Error("cmd-only must not build an httpEmbedder")
	}

	// BOTH → loud error.
	if _, err := embedderFromFlag("python3 embed.py", "http://127.0.0.1:8099"); err == nil {
		t.Error("setting both --embedder-cmd and --embedder-url must error")
	}

	// Neither → the legacy loud-failure (empty argv rejected by newCmdEmbedder).
	if _, err := embedderFromFlag("", ""); err == nil {
		t.Error("neither flag set must be a loud failure")
	}
}
