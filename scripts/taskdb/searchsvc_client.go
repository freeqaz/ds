// SPDX-License-Identifier: Apache-2.0
package main

// searchsvc_client.go — a thin POST /search client for a running searchsvc
// instance (searchsvc/serve.py). It is DISTINCT from embeddings_http.go: that
// file posts /embed (one chunk → its vector); this one posts /search (one query
// → ranked, already-fused hits) and never embeds. The two share only the URL
// joining idiom (a /search analogue of joinEmbedURL), not the transport.
//
// Wire shape (the EXACT contract serve.py's /search exposes — this is the Go
// client and must not drift):
//
//   request:  POST /search  body {"query": "<text>", "top_k": <int>}
//   response: 200 {"degraded": <bool>,
//                  "results": [{"chunk_hash": "<sha>",
//                               "doc_path":   "<path|task://…|note://…>",
//                               "heading":    "<str>",
//                               "fused_score":  <float>,
//                               "dense_score":  <float>,
//                               "sparse_score": <float>}, ...],
//                  "query": "<echo>"}
//
// FAIL-OPEN discipline (the load-bearing property): a searchsvc call that errors
// — unset URL never reaches here; refused/closed/timed-out connection, a non-2xx
// status, an unparseable body, or a degraded=true reply — is NOT fatal. The
// public entry trySearchService returns (nil, false) after emitting ONE loud,
// lock-server-style "[searchsvc DEGRADED] …" banner to stderr, and the caller
// falls back to the local cosine path. The search ALWAYS returns results; the
// service is an optimization, never a hard dependency.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// searchHTTPPath is the fixed /search route on a searchsvc instance.
const searchHTTPPath = "/search"

// searchClientTimeout bounds a /search round-trip so a hung service degrades to
// the local path rather than wedging the query. Short on purpose: /search is an
// interactive verb, and the local fallback is always available.
const searchClientTimeout = 10 * time.Second

// searchWarnOut is where the degraded banner is written. A package var so a test
// can capture it (mirrors embedWarnOut); defaults to os.Stderr.
var searchWarnOut io.Writer = os.Stderr

// searchsvcResult is one row of the /search response's results array. The field
// names mirror serve.py/fusion.py exactly.
type searchsvcResult struct {
	ChunkHash   string  `json:"chunk_hash"`
	DocPath     string  `json:"doc_path"`
	Heading     string  `json:"heading"`
	FusedScore  float64 `json:"fused_score"`
	DenseScore  float64 `json:"dense_score"`
	SparseScore float64 `json:"sparse_score"`
}

// searchsvcResponse is the decoded /search reply. degraded=true means the
// service is up but its retrieval modules are not ready (serve.py's
// embed-only stub); we treat it as a fail-open trigger so the local path serves
// real ranked results instead of an empty degraded set.
type searchsvcResponse struct {
	Degraded bool              `json:"degraded"`
	Results  []searchsvcResult `json:"results"`
	Query    string            `json:"query"`
}

// joinSearchURL appends the fixed /search route to a base URL, collapsing a
// trailing slash and tolerating an over-specified base that already ends in the
// route (so ".../search" is not doubled). The /search analogue of joinEmbedURL.
func joinSearchURL(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(base, searchHTTPPath) {
		return base
	}
	return base + searchHTTPPath
}

// trySearchService posts a query to a running searchsvc /search and maps the
// reply into docSearchHit rows, best-first (the service already sorts by
// fused_score descending). It is the FAIL-OPEN entry point: on ANY failure —
// transport error, non-2xx, unparseable body, or a degraded=true reply — it
// emits one loud "[searchsvc DEGRADED]" banner and returns (nil, false), telling
// the caller to fall back to the local cosine path. (nil, false) is never an
// error to the caller: the search still succeeds via the fallback.
//
// A url of "" returns (nil, false) WITHOUT a banner — there is nothing to
// degrade from, the caller simply takes the local path. (Callers gate on a
// non-empty URL before calling, but the guard keeps the helper total.)
func trySearchService(ctx context.Context, url, query string, topK int) ([]*docSearchHit, bool) {
	if strings.TrimSpace(url) == "" {
		return nil, false
	}
	resp, err := postSearch(ctx, url, query, topK)
	if err != nil {
		searchDegraded("%v", err)
		return nil, false
	}
	if resp.Degraded {
		// The service is reachable but its retrieval modules are not ready; the
		// degraded stub returns no real hits, so fall open to the local path.
		searchDegraded("searchsvc reported degraded retrieval (modules not ready); using local search")
		return nil, false
	}
	return mapSearchResults(resp.Results), true
}

// mapSearchResults turns the wire results (already fused-score-descending) into
// docSearchHit rows. A task:///note:// synthetic doc_path is labeled with its
// kind so the renderer prints "[task]"/"[note]"; a real file path is a "doc".
// The fused score rides along in Score; chunk_hash is dropped (the CLI hit has
// no hash field — the location is path+heading).
func mapSearchResults(results []searchsvcResult) []*docSearchHit {
	hits := make([]*docSearchHit, 0, len(results))
	for _, r := range results {
		hits = append(hits, &docSearchHit{
			Kind:    searchKind(r.DocPath),
			Path:    r.DocPath,
			Heading: r.Heading,
			Score:   r.FusedScore,
		})
	}
	return hits
}

// searchKind classifies a result's doc_path by its scheme: task:// → "task",
// note:// → "note", anything else (a real file path) → "doc".
func searchKind(docPath string) string {
	switch {
	case strings.HasPrefix(docPath, taskChunkScheme):
		return "task"
	case strings.HasPrefix(docPath, noteChunkScheme):
		return "note"
	default:
		return "doc"
	}
}

// postSearch performs one POST /search round-trip and decodes the reply. It is
// the single transport+parse point trySearchService funnels through, so the
// error discipline (non-2xx, transport failure, unparseable body) lives in one
// place. The caller's context bounds the request; the client also carries a
// short timeout so a hung service degrades promptly.
func postSearch(ctx context.Context, url, query string, topK int) (*searchsvcResponse, error) {
	if topK <= 0 {
		topK = 10
	}
	body, err := json.Marshal(map[string]any{"query": query, "top_k": topK})
	if err != nil {
		return nil, fmt.Errorf("encoding search request: %w", err)
	}
	endpoint := joinSearchURL(url)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building search request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: searchClientTimeout}
	httpResp, err := client.Do(req)
	if err != nil {
		// Connection refused / closed / timed out: the degraded trigger.
		return nil, fmt.Errorf("searchsvc %q unreachable: %w", endpoint, err)
	}
	defer httpResp.Body.Close()

	raw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading searchsvc response from %q: %w", endpoint, err)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, fmt.Errorf("searchsvc %q returned HTTP %d: %s",
			endpoint, httpResp.StatusCode, snippet(raw))
	}

	var out searchsvcResponse
	if err := json.Unmarshal(bytes.TrimSpace(raw), &out); err != nil {
		return nil, fmt.Errorf("searchsvc %q response is not a {degraded,results} object: %w", endpoint, err)
	}
	return &out, nil
}

// searchDegraded writes one loud, lock-server-style banner to searchWarnOut so
// an operator sees the search ran degraded (service down → local fallback). It
// never returns an error: degradation is announced, not fatal.
func searchDegraded(format string, args ...any) {
	fmt.Fprintf(searchWarnOut, "[searchsvc DEGRADED] "+format+" — falling back to local search\n", args...)
}
