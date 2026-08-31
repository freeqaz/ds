// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// insertChunk writes one doc_chunks row keyed on the gitBlobSHA of its body (the
// SAME identity docSync writes), so the pusher's hash diff sees it. Returns the
// hash.
func insertChunk(t *testing.T, db *sql.DB, docID int64, path, heading, body string) string {
	t.Helper()
	h := gitBlobSHA([]byte(body))
	if _, err := db.Exec(
		`INSERT INTO doc_chunks(doc_id,path,heading,seq,body,hash) VALUES(?,?,?,?,?,?)`,
		docID, path, heading, 0, body, h,
	); err != nil {
		t.Fatalf("insert chunk: %v", err)
	}
	return h
}

// recordedChunk is one posted chunk as the service observed it: text plus the
// provenance fields (doc_path/heading) the pusher threaded. Used to assert the
// per-chunk source rode the wire on both /embed and /ingest_batch.
type recordedChunk struct {
	text    string
	docPath string
	heading string
}

// recordingService is an httptest server that records the chunks it received on
// /embed AND /ingest_batch (with their provenance) and whether /reindex was hit.
// Thread-safe so the test can assert after the push returns. The default handler
// exposes /ingest_batch (the cold-push fast path); useEmbedFallback forces a 404
// on /ingest_batch so the pusher falls back to the per-chunk /embed loop, letting
// a test exercise provenance on BOTH wire shapes.
type recordingService struct {
	mu               sync.Mutex
	embeds           []string
	chunks           []recordedChunk
	reindexN         int
	useEmbedFallback bool
}

func (rs *recordingService) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		switch r.URL.Path {
		case "/embed":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			text, _ := req["text"].(string)
			docPath, _ := req["doc_path"].(string)
			heading, _ := req["heading"].(string)
			rs.embeds = append(rs.embeds, text)
			rs.chunks = append(rs.chunks, recordedChunk{text: text, docPath: docPath, heading: heading})
			_, _ = w.Write([]byte(`{"dense":[0.0],"sparse":{},"dense_dims":1}`))
		case "/ingest_batch":
			if rs.useEmbedFallback {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			var req struct {
				Chunks []struct {
					Text    string `json:"text"`
					DocPath string `json:"doc_path"`
					Heading string `json:"heading"`
				} `json:"chunks"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			for _, c := range req.Chunks {
				rs.chunks = append(rs.chunks, recordedChunk{text: c.Text, docPath: c.DocPath, heading: c.Heading})
			}
			_, _ = w.Write([]byte(`{"ingested":0,"chunk_hashes":[]}`))
		case "/reindex":
			rs.reindexN++
			_, _ = w.Write([]byte(`{"reindexed":true,"dense_chunks":0,"sparse_chunks":0,"db":""}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
}

// chunkFor returns the recorded chunk whose text matches, and whether one was
// found — so a provenance assertion is order-independent.
func (rs *recordingService) chunkFor(text string) (recordedChunk, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, c := range rs.chunks {
		if c.text == text {
			return c, true
		}
	}
	return recordedChunk{}, false
}

// --- push set ----------------------------------------------------------------

// TestPushChangedChunks_PushesLiveSetAndReindexes asserts a push POSTs every
// distinct live chunk body to /embed and triggers exactly one /reindex, and
// records the corpus digest so a second unchanged push is a no-op.
func TestPushChangedChunks_PushesLiveSetAndReindexes(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")
	insertChunk(t, db, 2, "docs/b.md", "B", "beta body")

	// Force the per-chunk /embed fallback so this test counts /embed posts.
	rs := &recordingService{useEmbedFallback: true}
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Degraded {
		t.Fatal("a healthy service must not be degraded")
	}
	if res.Pushed != 2 {
		t.Fatalf("want 2 chunks pushed, got %d", res.Pushed)
	}
	if !res.Reindex {
		t.Fatal("reindex must be triggered after a push")
	}
	rs.mu.Lock()
	gotEmbeds := len(rs.embeds)
	gotReindex := rs.reindexN
	rs.mu.Unlock()
	if gotEmbeds != 2 {
		t.Fatalf("service saw %d /embed posts, want 2", gotEmbeds)
	}
	if gotReindex != 1 {
		t.Fatalf("service saw %d /reindex posts, want 1", gotReindex)
	}

	// Second push, corpus unchanged: a no-op (digest match short-circuit).
	res2, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("second push: %v", err)
	}
	if res2.Pushed != 0 {
		t.Fatalf("unchanged corpus must push 0, got %d", res2.Pushed)
	}
	rs.mu.Lock()
	if len(rs.embeds) != 2 {
		t.Errorf("no-op push must not POST /embed again, total embeds %d", len(rs.embeds))
	}
	rs.mu.Unlock()
}

// TestPushChangedChunks_ForceRepushesUnchanged asserts force=true re-pushes even
// when the corpus is unchanged (the operator override).
func TestPushChangedChunks_ForceRepushesUnchanged(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")

	rs := &recordingService{}
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()

	if _, err := pushChangedChunks(context.Background(), db, srv.URL, false); err != nil {
		t.Fatalf("first push: %v", err)
	}
	res, err := pushChangedChunks(context.Background(), db, srv.URL, true)
	if err != nil {
		t.Fatalf("forced push: %v", err)
	}
	if res.Pushed != 1 {
		t.Fatalf("forced push must re-send 1, got %d", res.Pushed)
	}
}

// TestPushChangedChunks_CarriesProvenanceBatch asserts the /ingest_batch fast
// path carries each chunk's doc_path (the doc_chunks.path column) and heading on
// the wire, so a cold-pushed chunk lands with real provenance instead of empty
// defaults.
func TestPushChangedChunks_CarriesProvenanceBatch(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "Alpha Heading", "alpha body")
	insertChunk(t, db, 2, "docs/b.md", "Beta Heading", "beta body")

	rs := &recordingService{} // batch-capable: chunks ride /ingest_batch
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Degraded {
		t.Fatal("a healthy service must not be degraded")
	}
	if res.Pushed != 2 {
		t.Fatalf("want 2 chunks pushed, got %d", res.Pushed)
	}

	rs.mu.Lock()
	if len(rs.embeds) != 0 {
		rs.mu.Unlock()
		t.Fatalf("batch-capable service must NOT see /embed posts, got %d", len(rs.embeds))
	}
	gotChunks := len(rs.chunks)
	rs.mu.Unlock()
	if gotChunks != 2 {
		t.Fatalf("service saw %d batched chunks, want 2", gotChunks)
	}

	wantProv := map[string]recordedChunk{
		"alpha body": {text: "alpha body", docPath: "docs/a.md", heading: "Alpha Heading"},
		"beta body":  {text: "beta body", docPath: "docs/b.md", heading: "Beta Heading"},
	}
	for text, want := range wantProv {
		got, ok := rs.chunkFor(text)
		if !ok {
			t.Fatalf("chunk %q never reached the service", text)
		}
		if got.docPath != want.docPath {
			t.Errorf("chunk %q doc_path = %q, want %q", text, got.docPath, want.docPath)
		}
		if got.heading != want.heading {
			t.Errorf("chunk %q heading = %q, want %q", text, got.heading, want.heading)
		}
	}
}

// TestPushChangedChunks_CarriesProvenanceEmbedFallback asserts the per-chunk
// /embed fallback (an older service with no /ingest_batch) ALSO threads
// doc_path/heading on each request body.
func TestPushChangedChunks_CarriesProvenanceEmbedFallback(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "Alpha Heading", "alpha body")

	rs := &recordingService{useEmbedFallback: true} // 404 on batch → /embed loop
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Pushed != 1 {
		t.Fatalf("want 1 chunk pushed via /embed, got %d", res.Pushed)
	}
	rs.mu.Lock()
	if len(rs.embeds) != 1 {
		rs.mu.Unlock()
		t.Fatalf("fallback must POST /embed once, got %d", len(rs.embeds))
	}
	rs.mu.Unlock()

	got, ok := rs.chunkFor("alpha body")
	if !ok {
		t.Fatal("chunk never reached /embed")
	}
	if got.docPath != "docs/a.md" {
		t.Errorf("/embed doc_path = %q, want %q", got.docPath, "docs/a.md")
	}
	if got.heading != "Alpha Heading" {
		t.Errorf("/embed heading = %q, want %q", got.heading, "Alpha Heading")
	}
}

// --- prune -------------------------------------------------------------------

// TestPushChangedChunks_PruneCountsVanished asserts the prune count mirrors the
// Go prune path: a chunk that left the corpus since the last push is reported as
// pruned on the next push.
func TestPushChangedChunks_PruneCountsVanished(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "keep me")
	gone := insertChunk(t, db, 2, "docs/b.md", "B", "drop me")

	rs := &recordingService{}
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()

	if _, err := pushChangedChunks(context.Background(), db, srv.URL, false); err != nil {
		t.Fatalf("first push: %v", err)
	}

	// Remove the second chunk from the corpus and re-push.
	if _, err := db.Exec(`DELETE FROM doc_chunks WHERE hash=?`, gone); err != nil {
		t.Fatalf("delete chunk: %v", err)
	}
	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("second push: %v", err)
	}
	if res.Pruned != 1 {
		t.Fatalf("want 1 pruned (the vanished chunk), got %d", res.Pruned)
	}
}

// --- freshness / staleness ---------------------------------------------------

// TestFreshnessCheck_TracksCorpus asserts freshness is NOT fresh before any
// push (never-built), fresh right after a push, and stale once the corpus
// changes.
func TestFreshnessCheck_TracksCorpus(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")

	// Never pushed: not fresh, empty stored digest.
	f0, err := freshnessCheck(db)
	if err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if f0.Fresh {
		t.Fatal("a never-pushed index must report stale")
	}
	if f0.StoredDigest != "" {
		t.Fatalf("never-pushed stored digest must be empty, got %q", f0.StoredDigest)
	}

	rs := &recordingService{}
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()
	if _, err := pushChangedChunks(context.Background(), db, srv.URL, false); err != nil {
		t.Fatalf("push: %v", err)
	}

	// Right after a push: fresh, stored == current.
	f1, err := freshnessCheck(db)
	if err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if !f1.Fresh {
		t.Fatal("the index must be fresh immediately after a push")
	}
	if f1.StoredDigest != f1.CurrentDigest {
		t.Fatalf("fresh index digests must match: %q vs %q", f1.StoredDigest, f1.CurrentDigest)
	}

	// Add a chunk: the corpus digest moves → stale.
	insertChunk(t, db, 2, "docs/b.md", "B", "beta")
	f2, err := freshnessCheck(db)
	if err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if f2.Fresh {
		t.Fatal("adding a chunk must make the index stale")
	}
	if f2.StoredDigest == f2.CurrentDigest {
		t.Fatal("a changed corpus must move the current digest away from the stored one")
	}
}

// TestCorpusDigest_OrderIndependent asserts the digest is a function of the
// distinct hash SET, not row insertion order — matching ingest.py's
// sorted-hash digest so the Go and Python freshness signals agree.
func TestCorpusDigest_OrderIndependent(t *testing.T) {
	db1 := openFullSchemaDB(t)
	insertChunk(t, db1, 1, "docs/a.md", "", "alpha")
	insertChunk(t, db1, 2, "docs/b.md", "", "beta")
	d1, err := corpusDigest(db1)
	if err != nil {
		t.Fatal(err)
	}

	db2 := openFullSchemaDB(t)
	insertChunk(t, db2, 1, "docs/b.md", "", "beta")
	insertChunk(t, db2, 2, "docs/a.md", "", "alpha")
	d2, err := corpusDigest(db2)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("digest must be order-independent: %q vs %q", d1, d2)
	}
}

// multiScanFreshness recomputes the freshness verdict the way freshnessCheck did
// BEFORE the single-snapshot refactor: corpusDigest scans doc_chunks, then
// corpusDrift scans it AGAIN via liveChunkBodies. It is the oracle the
// single-scan freshnessCheck must match byte-for-byte / count-for-count.
func multiScanFreshness(t *testing.T, db *sql.DB) (digest string, drift int) {
	t.Helper()
	d, err := corpusDigest(db) // scan #1
	if err != nil {
		t.Fatalf("corpusDigest: %v", err)
	}
	dr, err := corpusDrift(db) // scan #2 (via liveChunkBodies)
	if err != nil {
		t.Fatalf("corpusDrift: %v", err)
	}
	return d, dr
}

// TestFreshnessCheck_SingleScanMatchesMultiScan asserts the single-snapshot
// freshnessCheck (one doc_chunks read shared across digest + drift) yields the
// EXACT same current digest and drift count as the prior multi-scan computation
// (corpusDigest + corpusDrift), across several corpus states: never-pushed,
// fresh-after-push, added-since-push, and pruned-since-push. A pure refactor must
// not move a single bit.
func TestFreshnessCheck_SingleScanMatchesMultiScan(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")
	insertChunk(t, db, 2, "docs/b.md", "B", "beta body")

	assertMatch := func(stage string) {
		t.Helper()
		wantDigest, wantDrift := multiScanFreshness(t, db)
		f, err := freshnessCheck(db)
		if err != nil {
			t.Fatalf("%s: freshnessCheck: %v", stage, err)
		}
		if f.CurrentDigest != wantDigest {
			t.Fatalf("%s: current digest %q != multi-scan digest %q", stage, f.CurrentDigest, wantDigest)
		}
		if f.Drift != wantDrift {
			t.Fatalf("%s: drift %d != multi-scan drift %d", stage, f.Drift, wantDrift)
		}
	}

	// 1) Never pushed: every live chunk is unabsorbed drift.
	assertMatch("never-pushed")

	rs := &recordingService{}
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()
	if _, err := pushChangedChunks(context.Background(), db, srv.URL, false); err != nil {
		t.Fatalf("push: %v", err)
	}

	// 2) Fresh right after a push: drift 0, digest matches stored.
	assertMatch("fresh-after-push")

	// 3) A chunk added since the push: digest moves, drift counts it.
	insertChunk(t, db, 3, "docs/c.md", "C", "gamma body")
	assertMatch("added-since-push")

	// 4) A chunk pruned since the push: digest moves, drift counts the loss.
	if _, err := db.Exec(`DELETE FROM doc_chunks WHERE hash=?`, gitBlobSHA([]byte("alpha body"))); err != nil {
		t.Fatalf("delete chunk: %v", err)
	}
	assertMatch("pruned-since-push")
}

// --- fail-open ---------------------------------------------------------------

// TestPushChangedChunks_FailOpenOnUnset asserts an unset --service-url is a
// silent degraded no-op: nothing pushed, no banner, no error.
func TestPushChangedChunks_FailOpenOnUnset(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	res, err := pushChangedChunks(context.Background(), db, "  ", false)
	if err != nil {
		t.Fatalf("unset URL must not error: %v", err)
	}
	if !res.Degraded {
		t.Fatal("unset URL must report degraded (no-op)")
	}
	if res.Pushed != 0 || res.Reindex {
		t.Fatalf("unset URL must push nothing and not reindex: %+v", res)
	}
	if buf.Len() != 0 {
		t.Fatalf("unset URL must not emit a banner, got: %q", buf.String())
	}
}

// TestPushChangedChunks_FailOpenOnUnreachable asserts a dead service degrades
// LOUDLY (a banner) and returns a degraded result with NO error, and does NOT
// record the digest (so a later run retries the push).
func TestPushChangedChunks_FailOpenOnUnreachable(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now refused

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	res, err := pushChangedChunks(context.Background(), db, url, false)
	if err != nil {
		t.Fatalf("a dead service must NOT error (fail open): %v", err)
	}
	if !res.Degraded {
		t.Fatal("a dead service must report degraded")
	}
	if !bytes.Contains(buf.Bytes(), []byte("[searchsvc DEGRADED]")) {
		t.Fatalf("expected a loud degraded banner, got: %q", buf.String())
	}
	// The digest must NOT have been recorded — a later push retries.
	stored, err := readPushedDigest(db)
	if err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("a failed push must not record the digest, got %q", stored)
	}
}

// TestPushChangedChunks_FailOpenOnNon2xx asserts a 500 from /embed fails open
// with a banner and no error.
func TestPushChangedChunks_FailOpenOnNon2xx(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "model exploded", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("a 500 must fail open, not error: %v", err)
	}
	if !res.Degraded {
		t.Fatal("a 500 must report degraded")
	}
	if !bytes.Contains(buf.Bytes(), []byte("[searchsvc DEGRADED]")) {
		t.Fatalf("expected a degraded banner, got: %q", buf.String())
	}
}

// --- joinReindexURL ----------------------------------------------------------

func TestJoinReindexURL(t *testing.T) {
	cases := map[string]string{
		"http://h:8099":          "http://h:8099/reindex",
		"http://h:8099/":         "http://h:8099/reindex",
		"http://h:8099/reindex":  "http://h:8099/reindex",
		"http://h:8099/reindex/": "http://h:8099/reindex",
		"  http://h:8099  ":      "http://h:8099/reindex",
	}
	for in, want := range cases {
		if got := joinReindexURL(in); got != want {
			t.Errorf("joinReindexURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- effective ingest-knob log ----------------------------------------------

// resetIngestKnobsOnce clears the one-time knob-emission latch so each test
// resolves it afresh. Reassigning the sync.Once is safe here because the
// package's tests run serially within a process; production never resets it.
func resetIngestKnobsOnce() { ingestKnobsOnce = sync.Once{} }

// TestLogEffectiveIngestKnobs_OverrideTook asserts the one-time knob line names
// the EFFECTIVE Go-side ingest knobs (the resolved hybrid weights + the resolved
// batch size) — the Go mirror of fusion.py's load-time knob log, so an operator
// can confirm an override actually bound. The weights are overridden via the
// SHARED env knob (SEARCHSVC_W_DENSE/W_SPARSE) before the latch resolves.
func TestLogEffectiveIngestKnobs_OverrideTook(t *testing.T) {
	t.Setenv(envWDense, "0.8")
	t.Setenv(envWSparse, "0.2")
	resetHybridWeights()
	t.Cleanup(resetHybridWeights)
	resetIngestKnobsOnce()
	t.Cleanup(resetIngestKnobsOnce)

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	logEffectiveIngestKnobs()

	got := buf.String()
	if !strings.Contains(got, "effective ingest knobs") {
		t.Fatalf("knob line missing its label, got: %q", got)
	}
	for _, want := range []string{"W_DENSE=0.8", "W_SPARSE=0.2", ingestBatchEnvVar + "="} {
		if !strings.Contains(got, want) {
			t.Fatalf("knob line missing %q, got: %q", want, got)
		}
	}
	// The emitted batch size must be the EFFECTIVE resolved value, not a literal.
	if !strings.Contains(got, fmt.Sprintf("%s=%d", ingestBatchEnvVar, ingestBatchSize)) {
		t.Fatalf("knob line must carry effective batch size %d, got: %q", ingestBatchSize, got)
	}
}

// TestLogEffectiveIngestKnobs_EmittedOnce asserts the knob line is emitted at
// most ONCE per process (sync.Once-guarded) no matter how many times ingest runs
// — never per-chunk. Repeated calls after the first must add nothing.
func TestLogEffectiveIngestKnobs_EmittedOnce(t *testing.T) {
	resetHybridWeights()
	t.Cleanup(resetHybridWeights)
	resetIngestKnobsOnce()
	t.Cleanup(resetIngestKnobsOnce)

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	logEffectiveIngestKnobs()
	first := buf.String()
	for i := 0; i < 5; i++ {
		logEffectiveIngestKnobs()
	}
	if buf.String() != first {
		t.Fatalf("knob line must be emitted ONCE, not per call; first=%q after-repeats=%q", first, buf.String())
	}
	if n := strings.Count(buf.String(), "effective ingest knobs"); n != 1 {
		t.Fatalf("expected exactly one knob line, got %d: %q", n, buf.String())
	}
}

// TestPushChangedChunks_EmitsKnobsOnce asserts the ingest ENTRYPOINT
// (pushChangedChunks) emits the effective-knob line exactly once at ingest start,
// not per chunk, when a real ingest runs against a (recording) service.
func TestPushChangedChunks_EmitsKnobsOnce(t *testing.T) {
	resetHybridWeights()
	t.Cleanup(resetHybridWeights)
	resetIngestKnobsOnce()
	t.Cleanup(resetIngestKnobsOnce)

	db := openFullSchemaDB(t)
	// Several chunks: a per-chunk emission would print several lines.
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha")
	insertChunk(t, db, 1, "docs/b.md", "B", "bravo")
	insertChunk(t, db, 1, "docs/c.md", "C", "charlie")

	rs := &recordingService{}
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	if _, err := pushChangedChunks(context.Background(), db, srv.URL, false); err != nil {
		t.Fatalf("push must succeed: %v", err)
	}
	if n := strings.Count(buf.String(), "effective ingest knobs"); n != 1 {
		t.Fatalf("ingest start must emit the knob line ONCE (not per-chunk), got %d: %q", n, buf.String())
	}
}
