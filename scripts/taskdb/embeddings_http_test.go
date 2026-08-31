// SPDX-License-Identifier: Apache-2.0
package main

// Hermetic tests for the HTTP embedder (embeddings_http.go). No live searchsvc, no
// model, no network: every test drives an httptest.Server fake that speaks the EXACT
// POST /embed wire shape serve.py exposes ({"text"} in, {"dense","sparse",
// "dense_dims"} out). Fixture vectors are deterministic and keyed on the request
// text so order-preservation is assertable.
//
// Coverage maps to the unit's acceptance gate:
//   - TestHTTPEmbedderEmbedDenseSparse: Embed returns the dense vector + stable
//     model label from a fake /embed; the sparse leg is decoded on the batch path.
//   - TestHTTPEmbedderEmbedBatchOrder: EmbedBatch returns one {Dense,Sparse} per
//     input IN ORDER (a permutation would fail), with sparse int-keyed.
//   - TestHTTPEmbedderBatchDrivesIndex: wired through embedChunks the HTTP embedder
//     indexes + ranks correctly, and activeSignature's probe works (stable label).
//   - TestHTTPEmbedderServerErrorIsLoud: a 500 surfaces as an ERROR, never a silent
//     empty index (and on the batch path triggers the loud per-chunk fallback,
//     which then also errors against the dead service — never a zero vector).
//   - TestHTTPEmbedderClosedConnectionIsLoud: a refused/closed connection is an
//     ERROR, not an empty index.
//   - TestHTTPEmbedderEmptyVectorIsError / TestHTTPEmbedderDimsMismatchIsError:
//     a protocol-violating body (empty dense, dims disagreement) is rejected loudly.
//   - TestHTTPEmbedderImplementsBatch: the struct satisfies both Embedder and the
//     widened batchEmbedder, so the opt-in batch seam picks it up.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// fakeEmbedFixture is the deterministic embedding the fake /embed returns for a
// text: a dense bag-of-words vector (the same helper the rest of the suite uses, so
// identical text → identical dense vector whether it arrived via Embed or
// EmbedBatch and ranking stays meaningful) plus a small synthetic sparse map keyed
// on the text length so distinct texts get distinct sparse legs.
func fakeEmbedFixture(text string) ([]float32, map[int]float32) {
	dense := bagOfWordsVector(text)
	// A trivial deterministic sparse map: one term whose id is the text length and
	// whose weight is the rune count. Distinct-length texts get distinct sparse
	// legs; an empty text gets an empty sparse map (still a valid response).
	sparse := map[int]float32{}
	if len(text) > 0 {
		sparse[len(text)] = float32(len([]rune(text)))
	}
	return dense, sparse
}

// newFakeEmbedServer returns an httptest.Server speaking the EXACT POST /embed
// contract from serve.py: it decodes {"text": ...}, computes the fixture embedding,
// and replies {"dense":[...],"sparse":{"<tid>":w,...},"dense_dims":N} (sparse keys
// are JSON strings of decimal ids, matching serve.py's {str(tid): w}). It uses a
// mux with a per-endpoint HandlerFunc so unknown routes 404 (proving the client
// targets /embed). t.Cleanup closes it.
func newFakeEmbedServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/embed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		dense, sparse := fakeEmbedFixture(req.Text)
		// Mirror serve.py: sparse keys are STRING token ids.
		sparseStr := make(map[string]float32, len(sparse))
		for id, wt := range sparse {
			sparseStr[strconv.Itoa(id)] = wt
		}
		writeEmbedJSON(t, w, map[string]any{
			"dense":      dense,
			"sparse":     sparseStr,
			"dense_dims": len(dense),
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// writeJSON encodes payload as a JSON body, the way serve.py's FastAPI route does.
func writeEmbedJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

// TestHTTPEmbedderEmbedDenseSparse: Embed returns the dense vector and the STABLE
// model label from a fake /embed, and the dense vector matches the fixture for the
// text (so the client posted the right body and decoded the right field).
func TestHTTPEmbedderEmbedDenseSparse(t *testing.T) {
	srv := newFakeEmbedServer(t)
	emb, err := newHTTPEmbedder(srv.URL)
	if err != nil {
		t.Fatalf("newHTTPEmbedder: %v", err)
	}

	const text = "nftables firewall egress gateway proxy networking"
	vec, model, err := emb.Embed(context.Background(), text)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if model != httpEmbedderModelLabel {
		t.Errorf("model = %q, want %q (stable label for swap healing)", model, httpEmbedderModelLabel)
	}
	wantDense, _ := fakeEmbedFixture(text)
	if len(vec) != len(wantDense) {
		t.Fatalf("dense len = %d, want %d", len(vec), len(wantDense))
	}
	for i := range wantDense {
		if vec[i] != wantDense[i] {
			t.Errorf("dense[%d] = %v, want %v", i, vec[i], wantDense[i])
		}
	}
}

// TestHTTPEmbedderEmbedBatchOrder: EmbedBatch returns one {Dense,Sparse} per input
// IN ORDER, with the sparse map int-keyed (decoded from serve.py's string keys). A
// permutation would mis-key the dense vectors and fail.
func TestHTTPEmbedderEmbedBatchOrder(t *testing.T) {
	srv := newFakeEmbedServer(t)
	emb, err := newHTTPEmbedder(srv.URL)
	if err != nil {
		t.Fatalf("newHTTPEmbedder: %v", err)
	}

	texts := []string{
		"nftables firewall egress",
		"task worktree branch lock dispatch agent",
		"embedding vector cosine search index",
	}
	vecs, model, err := emb.EmbedBatch(context.Background(), texts)
	if err != nil {
		t.Fatalf("EmbedBatch: %v", err)
	}
	if model != httpEmbedderModelLabel {
		t.Errorf("model = %q, want %q", model, httpEmbedderModelLabel)
	}
	if len(vecs) != len(texts) {
		t.Fatalf("got %d vecs for %d texts (length mismatch)", len(vecs), len(texts))
	}
	for i, text := range texts {
		wantDense, wantSparse := fakeEmbedFixture(text)
		if len(vecs[i].Dense) != len(wantDense) {
			t.Fatalf("vec[%d] dense len = %d, want %d", i, len(vecs[i].Dense), len(wantDense))
		}
		for j := range wantDense {
			if vecs[i].Dense[j] != wantDense[j] {
				t.Errorf("vec[%d] dense mis-ordered at %d: got %v want %v (order not preserved)",
					i, j, vecs[i].Dense[j], wantDense[j])
			}
		}
		// Sparse decoded to int-keyed and matches the fixture.
		if len(vecs[i].Sparse) != len(wantSparse) {
			t.Fatalf("vec[%d] sparse len = %d, want %d", i, len(vecs[i].Sparse), len(wantSparse))
		}
		for id, wt := range wantSparse {
			if got := vecs[i].Sparse[id]; got != wt {
				t.Errorf("vec[%d] sparse[%d] = %v, want %v", i, id, got, wt)
			}
		}
	}
}

// TestHTTPEmbedderBatchDrivesIndex: driven through embedChunks (the real indexing
// core), the HTTP embedder builds a correct, order-preserving index and ranks it,
// and activeSignature's probe works (the stable label means the cache is keyed
// consistently and a no-change re-run skips). This is the end-to-end path the opt-in
// batch seam takes for a hybrid embedder.
func TestHTTPEmbedderBatchDrivesIndex(t *testing.T) {
	srv := newFakeEmbedServer(t)
	emb, err := newHTTPEmbedder(srv.URL)
	if err != nil {
		t.Fatalf("newHTTPEmbedder: %v", err)
	}

	db := openTestDB(t)
	seedChunk(t, db, "docs/04.md", "Networking", "nftables firewall egress gateway proxy networking")
	seedChunk(t, db, "docs/22.md", "Worktrees", "task worktree branch lock dispatch agent")
	seedChunk(t, db, "docs/08.md", "Embeddings", "embedding vector cosine search index chunk")

	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if res.Embedded != 3 || res.Skipped != 0 {
		t.Fatalf("embedded=%d skipped=%d, want 3/0", res.Embedded, res.Skipped)
	}
	if res.Model != httpEmbedderModelLabel {
		t.Errorf("active model = %q, want %q (probe used the stable label)", res.Model, httpEmbedderModelLabel)
	}

	hits, err := semanticSearch(context.Background(), db, emb, "firewall egress nftables", 10, true)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) == 0 || hits[0].Path != "docs/04.md" {
		t.Errorf("HTTP-indexed corpus ranks wrong; top = %s", hitTop(hits))
	}

	// A no-change re-run skips every chunk: the stable label means the cached rows
	// match the active signature (model-swap healing does not re-embed them).
	res2, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("re-embed: %v", err)
	}
	if res2.Skipped != 3 || res2.Embedded != 0 {
		t.Errorf("no-change re-run: skipped=%d embedded=%d, want 3/0", res2.Skipped, res2.Embedded)
	}
}

// TestHTTPEmbedderServerErrorIsLoud: a service that 500s surfaces as an ERROR from
// both Embed and EmbedBatch — never a silent empty index. Through embedChunks the
// 500 (on the probe) aborts the pass with an error rather than indexing zero rows.
func TestHTTPEmbedderServerErrorIsLoud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "model exploded", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	emb, err := newHTTPEmbedder(srv.URL)
	if err != nil {
		t.Fatalf("newHTTPEmbedder: %v", err)
	}

	if _, _, err := emb.Embed(context.Background(), "hello"); err == nil {
		t.Fatal("Embed against a 500 service returned nil error (silent empty index)")
	} else if !strings.Contains(err.Error(), "500") {
		t.Errorf("Embed error did not name the HTTP status: %v", err)
	}

	if _, _, err := emb.EmbedBatch(context.Background(), []string{"a", "b"}); err == nil {
		t.Fatal("EmbedBatch against a 500 service returned nil error")
	}

	// Driven through embedChunks: the probe hits the 500 and the pass errors out
	// rather than producing an empty index.
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "nftables firewall egress")
	if _, err := embedChunks(context.Background(), db, emb, true); err == nil {
		t.Fatal("embedChunks against a 500 service succeeded (want a loud error, not an empty index)")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM chunk_embeddings`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("cache rows = %d after a failed pass, want 0 (no partial/silent index)", n)
	}
}

// TestHTTPEmbedderClosedConnectionIsLoud: a refused/closed connection (the server
// was shut down) is an ERROR, not an empty index. We close the server before the
// call so the dial fails.
func TestHTTPEmbedderClosedConnectionIsLoud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // refuse the connection

	emb, err := newHTTPEmbedder(url)
	if err != nil {
		t.Fatalf("newHTTPEmbedder: %v", err)
	}
	if _, _, err := emb.Embed(context.Background(), "hello"); err == nil {
		t.Fatal("Embed against a closed connection returned nil error (silent empty index)")
	} else if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("closed-connection error did not announce unreachability: %v", err)
	}
}

// TestHTTPEmbedderEmptyVectorIsError: a 200 response with an empty dense vector is a
// protocol violation rejected loudly (never cached as a zero-width vector).
func TestHTTPEmbedderEmptyVectorIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEmbedJSON(t, w, map[string]any{"dense": []float32{}, "sparse": map[string]float32{}, "dense_dims": 0})
	}))
	t.Cleanup(srv.Close)

	emb, err := newHTTPEmbedder(srv.URL)
	if err != nil {
		t.Fatalf("newHTTPEmbedder: %v", err)
	}
	if _, _, err := emb.Embed(context.Background(), "hello"); err == nil {
		t.Fatal("Embed accepted an empty dense vector (want a loud error)")
	} else if !strings.Contains(err.Error(), "empty dense") {
		t.Errorf("error did not name the empty dense vector: %v", err)
	}
}

// TestHTTPEmbedderDimsMismatchIsError: a service that reports dense_dims disagreeing
// with the actual float count is rejected loudly — the silent width-drift / cosine-
// to-zero trap the seam guards against.
func TestHTTPEmbedderDimsMismatchIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEmbedJSON(t, w, map[string]any{
			"dense":      []float32{0.1, 0.2, 0.3},
			"sparse":     map[string]float32{},
			"dense_dims": 256, // lies about the width
		})
	}))
	t.Cleanup(srv.Close)

	emb, err := newHTTPEmbedder(srv.URL)
	if err != nil {
		t.Fatalf("newHTTPEmbedder: %v", err)
	}
	if _, _, err := emb.Embed(context.Background(), "hello"); err == nil {
		t.Fatal("Embed accepted a dims/length disagreement (want a loud error)")
	} else if !strings.Contains(err.Error(), "dense_dims") {
		t.Errorf("error did not name the dims disagreement: %v", err)
	}
}

// TestHTTPEmbedderImplementsBatch: the struct satisfies BOTH Embedder and the
// widened batchEmbedder, so the opt-in batch seam (embedTexts) picks it up. Also
// checks the URL joiner tolerates a trailing slash / over-specified /embed.
func TestHTTPEmbedderImplementsBatch(t *testing.T) {
	emb, err := newHTTPEmbedder("http://example.invalid:8099")
	if err != nil {
		t.Fatalf("newHTTPEmbedder: %v", err)
	}
	if _, ok := interface{}(emb).(Embedder); !ok {
		t.Error("httpEmbedder does not implement Embedder")
	}
	if _, ok := interface{}(emb).(batchEmbedder); !ok {
		t.Error("httpEmbedder does not implement the widened batchEmbedder")
	}

	// Empty URL is rejected loudly.
	if _, err := newHTTPEmbedder("   "); err == nil {
		t.Error("newHTTPEmbedder(empty) returned nil error")
	}

	// URL joining: trailing slash and over-specified /embed both resolve to one
	// ".../embed" (no doubled or missing slash).
	for _, tc := range []struct{ base, want string }{
		{"http://h:8099", "http://h:8099/embed"},
		{"http://h:8099/", "http://h:8099/embed"},
		{"http://h:8099/embed", "http://h:8099/embed"},
	} {
		if got := joinEmbedURL(tc.base); got != tc.want {
			t.Errorf("joinEmbedURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}
