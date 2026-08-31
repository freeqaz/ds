// SPDX-License-Identifier: Apache-2.0
package main

// embeddings_http.go — an HTTP embedder seam that posts chunk text to a running
// searchsvc instance (searchsvc/serve.py) and decodes its hybrid (dense + sparse)
// embedding, as an ALTERNATIVE to the default cmdEmbedder (embed.py) process-per-
// chunk path.
//
// Why this exists: cmdEmbedder spawns one subprocess per chunk and the offline
// embed.py reloads its model on every spawn — fine for a tiny corpus, but a cold
// full-index pass over a hybrid BGE-M3 model wants a resident service. searchsvc
// holds the model in memory and serves POST /embed; this embedder targets that
// service so a full re-index pays one HTTP round-trip per chunk (and, via the
// batch seam below, can be amortized further) against an already-warm model.
//
// Wire shape (the EXACT contract searchsvc/serve.py exposes — this file is the Go
// client for it, and must not drift from it):
//
//   request:  POST /embed   body {"text": "<chunk text>"}
//   response: 200 {"dense": [<float ...>],
//                  "sparse": {"<token_id>": <weight>, ...},
//                  "dense_dims": <int>}
//
// The sparse map's keys are JSON strings of decimal token ids (serve.py emits
// {str(tid): w}); they are parsed back to int so the in-process representation is
// the same int-keyed map every other seam uses (mirrors decodeBatchResponse).
//
// Contract coverage:
//   - implements Embedder.Embed (dense-only return, the legacy per-chunk contract;
//     the dense vector is what the cosine ranking is keyed on today);
//   - implements the WIDENED batchEmbedder.EmbedBatch, returning []embeddedVec
//     {Dense, Sparse} so a hybrid index pass threads both vectors through the
//     existing embedTexts/tryBatch seam. The service has no batch endpoint, so the
//     batch is fanned out over /embed one request per text IN ORDER — the saving
//     versus cmdEmbedder is the resident model + persistent connection, not a
//     single multi-text frame. Order is preserved (result[i] embeds texts[i]).
//   - reports a STABLE modelLabel ("bge-m3-http" by default) so activeSignature's
//     model-swap healing keeps working: the cache rows this embedder writes are
//     keyed to its label, and a swap to/from it is detected exactly as a cmd swap.
//
// Failure is LOUD and SAFE, matching the rest of the seam:
//   - a non-2xx status (a 500 from a broken model), a closed/refused connection,
//     an unparseable body, or an empty dense vector is returned as an ERROR. On the
//     batch path that error makes tryBatch abandon the batch and fall back to the
//     per-chunk Embed path (which, hitting the same dead service, errors out of the
//     index pass) — never a silent empty index. There is no swallow-to-zero path.
//
// This file ships ONLY the struct + its exported factory; wiring an --embedder-url
// CLI flag into cmd_doc.go/embedderFromFlag is a SEPARATE unit (it owns that file).
// The offline cmdEmbedder/embed.py path stays the default fallback.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// httpEmbedderModelLabel is the stable model identifier the HTTP embedder reports.
// It is recorded in chunk_embeddings.model so activeSignature can detect a swap
// between this embedder and any other (a cmdEmbedder reports its argv string, a
// fake reports its own label); keeping it a constant means every vector this
// embedder produces shares one cache signature regardless of the service URL.
const httpEmbedderModelLabel = "bge-m3-http"

// embedHTTPPath is the fixed route on the searchsvc instance. The base URL the
// factory takes may or may not include a trailing slash; joinEmbedURL normalizes
// it so newHTTPEmbedder("http://h:8099") and newHTTPEmbedder("http://h:8099/")
// both POST to ".../embed".
const embedHTTPPath = "/embed"

// httpEmbedder is the searchsvc HTTP client embedder. It targets a single resident
// service over POST /embed and decodes the hybrid {dense, sparse, dense_dims}
// response. It implements BOTH Embedder.Embed (dense-only, legacy contract) and the
// widened batchEmbedder.EmbedBatch (dense + sparse), so it is a drop-in for the
// cmdEmbedder seam in both the per-chunk and the opt-in batch path.
type httpEmbedder struct {
	// embedURL is the fully-resolved POST /embed endpoint (base joined with the
	// fixed route, computed once by the factory).
	embedURL string
	// modelLabel is what Embed/EmbedBatch report (httpEmbedderModelLabel by
	// default). A field rather than a constant so a caller could override it
	// (e.g. to the model the service self-reports) without re-plumbing the type.
	modelLabel string
	// client is the HTTP client used for every request. A field so a test can
	// inject an httptest.Server-backed client with a short timeout; the factory
	// installs a default with a generous-but-bounded timeout so a hung service
	// surfaces as an error rather than wedging the whole index pass.
	client *http.Client
}

// embedHTTPResponse is the decoded body of a POST /embed reply. dense_dims is read
// for cross-checking against len(Dense) (a service that disagrees with itself is a
// loud error, never a silently-truncated vector). Sparse keys are JSON strings of
// decimal token ids per serve.py's {str(tid): w} encoding.
type embedHTTPResponse struct {
	Dense     []float32          `json:"dense"`
	Sparse    map[string]float32 `json:"sparse"`
	DenseDims int                `json:"dense_dims"`
}

// newHTTPEmbedder builds an HTTP embedder targeting a running searchsvc base URL
// (e.g. "http://127.0.0.1:8099"). An empty URL is rejected so a missing
// --embedder-url fails loudly at the embed/search entry point rather than POSTing
// to nowhere. The base may carry a trailing slash or a path prefix; the fixed
// /embed route is appended via joinEmbedURL. It is the EXPORTED factory the
// (separate) CLI-wiring unit calls; this file does not itself touch cmd_doc.go.
func newHTTPEmbedder(url string) (*httpEmbedder, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil, fmt.Errorf("no embedder URL configured (pass --embedder-url)")
	}
	return &httpEmbedder{
		embedURL:   joinEmbedURL(url),
		modelLabel: httpEmbedderModelLabel,
		// A bounded timeout so a hung/slow service errors loudly instead of
		// wedging the index pass forever. Per-call cancellation still rides the
		// caller's context (CommandContext-equivalent for HTTP).
		client: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// joinEmbedURL appends the fixed /embed route to a base URL, collapsing a possible
// trailing slash so we never produce ".../embed" with a doubled or missing slash.
// A base that already ends in the route is left as-is so an over-specified
// --embedder-url (".../embed") is tolerated rather than becoming ".../embed/embed".
func joinEmbedURL(base string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasSuffix(base, embedHTTPPath) {
		return base
	}
	return base + embedHTTPPath
}

// Embed posts ONE text to /embed and returns its DENSE vector plus the model label,
// satisfying the legacy per-chunk Embedder contract (sparse is decoded but dropped
// on this path — the dense vector is the cosine-ranking payload, and Embed's
// signature is dense-only). A non-2xx status, transport failure, unparseable body,
// or empty dense vector is a LOUD error (never a zero vector), so a dead service
// fails the pass instead of silently producing an empty index.
func (e *httpEmbedder) Embed(ctx context.Context, text string) ([]float32, string, error) {
	resp, err := e.postEmbed(ctx, text)
	if err != nil {
		return nil, "", err
	}
	return resp.Dense, e.modelLabel, nil
}

// EmbedBatch satisfies the WIDENED batchEmbedder seam: it returns one embeddedVec
// {Dense, Sparse} per input IN ORDER. searchsvc has no multi-text /embed endpoint,
// so the batch is fanned out as one POST /embed per text — the win over cmdEmbedder
// is the resident model and reused HTTP connection (keep-alive), not a single
// frame. Order is preserved (vecs[i] embeds texts[i]).
//
// Any per-text failure (bad status, transport error, unparseable/empty response)
// aborts the WHOLE batch with that error: tryBatch then announces the loud fallback
// and the caller drops to the per-chunk Embed path. There is no partial/empty-vector
// batch result — the loud-fallback invariant in tryBatch (every Dense non-empty)
// holds because postEmbed already rejects an empty dense vector here.
func (e *httpEmbedder) EmbedBatch(ctx context.Context, texts []string) ([]embeddedVec, string, error) {
	vecs := make([]embeddedVec, len(texts))
	for i, t := range texts {
		resp, err := e.postEmbed(ctx, t)
		if err != nil {
			// Abort the whole batch loudly; tryBatch turns this into the per-chunk
			// fallback rather than indexing a partial/empty batch.
			return nil, "", fmt.Errorf("batch embed at index %d: %w", i, err)
		}
		vecs[i] = embeddedVec{Dense: resp.Dense, Sparse: resp.sparseInts()}
	}
	return vecs, e.modelLabel, nil
}

// postEmbed performs one POST /embed round-trip and validates the reply. It is the
// single transport+parse point both Embed and EmbedBatch funnel through, so the
// loud-error discipline (non-2xx, transport failure, unparseable body, empty dense
// vector, dims self-disagreement) is enforced in exactly one place. The caller's
// context bounds the request (a cancelled/timed-out ctx surfaces as an error).
func (e *httpEmbedder) postEmbed(ctx context.Context, text string) (*embedHTTPResponse, error) {
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return nil, fmt.Errorf("encoding embed request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.embedURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building embed request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		// Connection refused / closed / timed out: LOUD, never a silent empty index.
		return nil, fmt.Errorf("embedder service %q unreachable: %w", e.embedURL, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading embedder response from %q: %w", e.embedURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// A 500 from a broken model (or any non-2xx) is an ERROR, never a zero
		// vector. Include a snippet of the body so the failure is debuggable.
		return nil, fmt.Errorf("embedder service %q returned HTTP %d: %s",
			e.embedURL, resp.StatusCode, snippet(raw))
	}

	var out embedHTTPResponse
	if err := json.Unmarshal(bytes.TrimSpace(raw), &out); err != nil {
		return nil, fmt.Errorf("embedder service %q response is not a {dense,sparse} object: %w", e.embedURL, err)
	}
	if len(out.Dense) == 0 {
		// An empty dense vector is a protocol violation: the loud-fallback /
		// non-empty invariant rejects it here so it never reaches the cache.
		return nil, fmt.Errorf("embedder service %q returned an empty dense vector", e.embedURL)
	}
	if out.DenseDims != 0 && out.DenseDims != len(out.Dense) {
		// The service disagreed with itself about the vector width. Treat it as a
		// loud error rather than trusting a possibly-truncated vector — a silent
		// width drift is exactly the cosine-scores-to-zero trap the seam guards.
		return nil, fmt.Errorf("embedder service %q reported dense_dims=%d but sent %d floats",
			e.embedURL, out.DenseDims, len(out.Dense))
	}
	return &out, nil
}

// sparseInts converts the JSON-string-keyed sparse map (serve.py emits {str(tid): w})
// into the int-keyed map every in-process seam uses, mirroring decodeBatchResponse.
// A nil/empty sparse map decodes to nil (a dense-only result, the legacy shape) so a
// dense-only service threads through unchanged. A non-integer key is a malformed
// response surfaced as a skipped term rather than a panic — but in practice serve.py
// only ever emits decimal ids; the guard keeps a foreign producer from corrupting
// the map. We return nil (not an error) here because the dense vector is the
// ranking payload and a degenerate sparse leg must never abort an otherwise-valid
// embed; a missing/garbled sparse term simply does not contribute (scores 0), never
// NaN.
func (r *embedHTTPResponse) sparseInts() map[int]float32 {
	if len(r.Sparse) == 0 {
		return nil
	}
	m := make(map[int]float32, len(r.Sparse))
	for k, w := range r.Sparse {
		id, err := strconv.Atoi(k)
		if err != nil {
			// Skip a non-integer token id rather than poisoning the whole map; a
			// real searchsvc never emits one.
			continue
		}
		m[id] = w
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// snippet bounds an error-message body excerpt so a large HTML 500 page does not
// flood the log. It trims whitespace and caps the length, appending an ellipsis
// when truncated.
func snippet(b []byte) string {
	const max = 256
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
