// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// batchRecordingService records the /ingest_batch request bodies it received
// (one entry per request — each carries a LIST of chunk texts) and how many
// /reindex posts it saw. It serves /ingest_batch (the batch verb the pusher now
// uses), /reindex, and a guard on /embed: the batched pusher must NEVER fall
// back to per-chunk /embed, so a hit there fails the request loudly.
type batchRecordingService struct {
	mu        sync.Mutex
	batches   [][]string // one inner slice per /ingest_batch request
	reindexN  int
	embedHits int
}

func (rs *batchRecordingService) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		switch r.URL.Path {
		case "/ingest_batch":
			var req struct {
				Chunks []struct {
					Text    string `json:"text"`
					DocPath string `json:"doc_path"`
					Heading string `json:"heading"`
				} `json:"chunks"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			texts := make([]string, 0, len(req.Chunks))
			hashes := make([]string, 0, len(req.Chunks))
			for _, c := range req.Chunks {
				texts = append(texts, c.Text)
				hashes = append(hashes, gitBlobSHA([]byte(c.Text)))
			}
			rs.batches = append(rs.batches, texts)
			body, _ := json.Marshal(map[string]any{
				"ingested":     len(texts),
				"chunk_hashes": hashes,
			})
			_, _ = w.Write(body)
		case "/reindex":
			rs.reindexN++
			_, _ = w.Write([]byte(`{"reindexed":true,"dense_chunks":0,"sparse_chunks":0,"db":""}`))
		case "/embed":
			// The batched pusher must not use the per-chunk verb.
			rs.embedHits++
			http.Error(w, "per-chunk /embed must not be used by the batch pusher", http.StatusInternalServerError)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
}

// flatTexts returns every chunk text the service received across all batches, in
// receipt order, so a test can assert the FULL pushed set (not just a count).
func (rs *batchRecordingService) flatTexts() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var out []string
	for _, b := range rs.batches {
		out = append(out, b...)
	}
	return out
}

// TestPushChangedChunks_UsesIngestBatchVerb asserts the pusher posts the live
// corpus via /ingest_batch (NOT per-chunk /embed) and triggers exactly one
// /reindex. The full set of pushed bodies must equal the corpus bodies.
func TestPushChangedChunks_UsesIngestBatchVerb(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")
	insertChunk(t, db, 2, "docs/b.md", "B", "beta body")
	insertChunk(t, db, 3, "docs/c.md", "C", "gamma body")

	rs := &batchRecordingService{}
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Degraded {
		t.Fatal("a healthy service must not be degraded")
	}
	if res.Pushed != 3 {
		t.Fatalf("want 3 chunks pushed, got %d", res.Pushed)
	}
	if !res.Reindex {
		t.Fatal("reindex must be triggered after a push")
	}

	rs.mu.Lock()
	embedHits := rs.embedHits
	reindexN := rs.reindexN
	nBatches := len(rs.batches)
	rs.mu.Unlock()
	if embedHits != 0 {
		t.Fatalf("batched pusher must not hit per-chunk /embed, got %d hits", embedHits)
	}
	if reindexN != 1 {
		t.Fatalf("service saw %d /reindex posts, want 1", reindexN)
	}
	// Three small chunks fit in one bounded batch.
	if nBatches != 1 {
		t.Fatalf("want 3 chunks in 1 batch, got %d batch(es)", nBatches)
	}

	// The FULL pushed set must equal the corpus bodies (hashes sort the order).
	got := rs.flatTexts()
	want := []string{"alpha body", "beta body", "gamma body"}
	wantSorted := sortByGitBlobSHA(want)
	if len(got) != len(wantSorted) {
		t.Fatalf("pushed %d bodies, want %d", len(got), len(wantSorted))
	}
	for i := range wantSorted {
		if got[i] != wantSorted[i] {
			t.Fatalf("pushed body[%d]=%q, want %q (full order: got=%v want=%v)", i, got[i], wantSorted[i], got, wantSorted)
		}
	}
}

// TestPushChangedChunks_ChunksIntoBoundedBatches asserts a corpus larger than
// ingestBatchSize is split into several BOUNDED batches (ceil(N/size)) rather
// than one unbounded request, and every batch is within the bound.
func TestPushChangedChunks_ChunksIntoBoundedBatches(t *testing.T) {
	db := openFullSchemaDB(t)
	// One more than two full batches, so we expect exactly 3 batches:
	// two of ingestBatchSize and a remainder of 1.
	n := ingestBatchSize*2 + 1
	for i := 0; i < n; i++ {
		insertChunk(t, db, int64(i+1), fmt.Sprintf("docs/d%d.md", i), "H", fmt.Sprintf("unique chunk body number %d", i))
	}

	rs := &batchRecordingService{}
	srv := httptest.NewServer(rs.handler(t))
	defer srv.Close()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Pushed != n {
		t.Fatalf("want %d chunks pushed, got %d", n, res.Pushed)
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()
	wantBatches := (n + ingestBatchSize - 1) / ingestBatchSize
	if len(rs.batches) != wantBatches {
		t.Fatalf("want %d bounded batches for %d chunks (size %d), got %d", wantBatches, n, ingestBatchSize, len(rs.batches))
	}
	total := 0
	for i, b := range rs.batches {
		if len(b) == 0 {
			t.Fatalf("batch %d is empty", i)
		}
		if len(b) > ingestBatchSize {
			t.Fatalf("batch %d has %d chunks, exceeds bound %d", i, len(b), ingestBatchSize)
		}
		total += len(b)
	}
	if total != n {
		t.Fatalf("batches carried %d chunks total, want %d", total, n)
	}
	if rs.embedHits != 0 {
		t.Fatalf("batched pusher must not hit per-chunk /embed, got %d hits", rs.embedHits)
	}
	if rs.reindexN != 1 {
		t.Fatalf("want exactly 1 reindex, got %d", rs.reindexN)
	}
}

// TestPushChangedChunks_BatchFailureFailsOpen asserts a failing /ingest_batch is
// fail-open: the pusher banners once and returns a degraded result with NO
// error, never a hard failure (the embed run that called it still succeeds).
func TestPushChangedChunks_BatchFailureFailsOpen(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("a failing batch must fail OPEN, not error: %v", err)
	}
	if !res.Degraded {
		t.Fatal("a failing service must mark the result degraded")
	}
	if res.Reindex {
		t.Fatal("a failed batch must not have reached /reindex")
	}
	if buf.Len() == 0 {
		t.Fatal("a degraded push must emit a loud banner")
	}
}

// TestPushChangedChunks_FallsBackToEmbedOn404 asserts the batch verb is purely
// ADDITIVE: a service too old to expose /ingest_batch answers 404, and the pusher
// transparently falls back to the per-chunk /embed loop (the original O(N) path)
// so an older service still ingests the FULL corpus, with a single /reindex and
// no degradation. The 404 is latched once — every chunk after the first batch's
// 404 goes straight to /embed (the batch verb is not retried).
func TestPushChangedChunks_FallsBackToEmbedOn404(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")
	insertChunk(t, db, 2, "docs/b.md", "B", "beta body")
	insertChunk(t, db, 3, "docs/c.md", "C", "gamma body")

	var (
		mu          sync.Mutex
		batch404    int
		embedTexts  []string
		reindexHits int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/ingest_batch":
			// Too old to know the batch verb.
			batch404++
			http.Error(w, "not found", http.StatusNotFound)
		case "/embed":
			var req struct {
				Text string `json:"text"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			embedTexts = append(embedTexts, req.Text)
			_, _ = w.Write([]byte(`{"dense":[0.0],"sparse":{},"dense_dims":1}`))
		case "/reindex":
			reindexHits++
			_, _ = w.Write([]byte(`{"reindexed":true,"dense_chunks":0,"sparse_chunks":0,"db":""}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res, err := pushChangedChunks(context.Background(), db, srv.URL, false)
	if err != nil {
		t.Fatalf("a 404 on the batch verb must fall back, not error: %v", err)
	}
	if res.Degraded {
		t.Fatal("falling back to /embed is NOT degradation — the corpus still ingests")
	}
	if res.Pushed != 3 {
		t.Fatalf("want 3 chunks pushed via the fallback, got %d", res.Pushed)
	}
	if !res.Reindex {
		t.Fatal("reindex must still be triggered after the fallback push")
	}

	mu.Lock()
	defer mu.Unlock()
	// The batch verb is latched off after the FIRST 404: only one batch (all 3
	// small chunks) is attempted, so exactly one 404 is seen — never retried.
	if batch404 != 1 {
		t.Fatalf("batch verb must be latched off after one 404, saw %d batch hits", batch404)
	}
	if reindexHits != 1 {
		t.Fatalf("want exactly 1 reindex, got %d", reindexHits)
	}
	// Every corpus body reached /embed in stable (hash-sorted) order.
	want := sortByGitBlobSHA([]string{"alpha body", "beta body", "gamma body"})
	if len(embedTexts) != len(want) {
		t.Fatalf("fallback pushed %d bodies via /embed, want %d (got=%v)", len(embedTexts), len(want), embedTexts)
	}
	for i := range want {
		if embedTexts[i] != want[i] {
			t.Fatalf("fallback /embed body[%d]=%q, want %q (full order: got=%v want=%v)", i, embedTexts[i], want[i], embedTexts, want)
		}
	}
}

// TestJoinIngestBatchURL asserts the route join collapses trailing slashes and
// tolerates an over-specified base that already ends in /ingest_batch.
func TestJoinIngestBatchURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://x:8099", "http://x:8099/ingest_batch"},
		{"http://x:8099/", "http://x:8099/ingest_batch"},
		{"http://x:8099/ingest_batch", "http://x:8099/ingest_batch"},
		{"  http://x:8099  ", "http://x:8099/ingest_batch"},
	}
	for _, c := range cases {
		if got := joinIngestBatchURL(c.in); got != c.want {
			t.Errorf("joinIngestBatchURL(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

// sortByGitBlobSHA returns the bodies sorted by their gitBlobSHA — the SAME
// order pushChangedChunks sends them in (it sorts the distinct-hash set), so a
// test can assert the FULL pushed ordering deterministically.
func sortByGitBlobSHA(bodies []string) []string {
	type bh struct{ body, hash string }
	pairs := make([]bh, 0, len(bodies))
	for _, b := range bodies {
		pairs = append(pairs, bh{b, gitBlobSHA([]byte(b))})
	}
	// insertion sort by hash (small, deterministic, no extra import).
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0 && pairs[j].hash < pairs[j-1].hash; j-- {
			pairs[j], pairs[j-1] = pairs[j-1], pairs[j]
		}
	}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.body)
	}
	return out
}
