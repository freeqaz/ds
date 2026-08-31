// SPDX-License-Identifier: Apache-2.0
package main

// embeddings_batch.go — an OPT-IN batched wire mode for the docs/22 §8 embeddings
// seam (wave6f gate follow-up). cmdEmbedder spawns ONE process per chunk: fine for
// a local model over a low-hundreds corpus, but an API embedder pays a network
// round-trip per chunk on a cold full index. This file adds a batchEmbedder seam
// that amortizes that per-chunk process/HTTP cost by sending many chunks in one
// invocation, WITHOUT changing the default contract.
//
// Contract split (the key invariant):
//
//   - one-text-per-invocation stays the DEFAULT Embedder contract: stdin = UTF-8
//     text, stdout = JSON float array. Nothing about the existing seam moves.
//   - batch mode is strictly OPT-IN, exposed by an embedder that ALSO implements
//     batchEmbedder. embedChunks consults it via a minimal type assertion; an
//     embedder that does not implement it is driven exactly as before.
//
// Wire shape for batch mode (chunk bodies contain newlines, so the batch frame is
// JSON, NOT newline-delimited raw text):
//
//   - stdin  = a JSON ARRAY OF STRINGS (the chunk texts, in order)
//   - stdout = a JSON ARRAY OF EQUAL-LENGTH FLOAT ARRAYS (one vector per input,
//     order-preserving: result[i] is the embedding of input[i])
//
// Failure is LOUD and SAFE: a length mismatch (the embedder returned a different
// number of vectors than it was given), a non-array / unparseable stdout, an empty
// vector, or a process error all abandon the batch and fall back to the per-chunk
// Embed path so a misbehaving batch embedder degrades to correct (slower) output
// instead of a silently-wrong or empty index. The fallback writes one line to
// embedWarnOut (os.Stderr) so the operator sees that batching was abandoned.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
)

// maxEmbedBatch caps how many texts ride a SINGLE EmbedBatch invocation. It is the
// max-batch WINDOW size: with N>0, a to-embed set larger than N is split into
// order-preserving windows of at most N and each window is one batch invocation;
// the per-window vectors are concatenated in input order so the overall result is
// identical to an unwindowed batch, just delivered over several smaller frames.
//
// The DEFAULT is 0 = UNLIMITED (the whole set in one invocation), which preserves
// the pre-windowing contract EXACTLY — no existing caller changes behavior unless
// it opts in by setting a positive cap. A cap is the lever an operator reaches for
// when an embedder rejects an over-large request body (an API per-request token /
// item ceiling) or to bound memory on a cold full-corpus index; it trades one big
// round-trip for several bounded ones WITHOUT changing result order or content.
//
// It is an atomic so the CLI opt-in (a single set at startup) and the embed pass
// (reads) never race under the -race detector, and so a test can set/restore it
// around a case without a data-race flag. Negative values are normalized to 0
// (unlimited) by the accessor.
var maxEmbedBatch atomic.Int64

// setMaxEmbedBatch records the max-batch window size (the CLI opt-in calls this).
// A negative value is clamped to 0 (unlimited) so a malformed flag degrades to the
// safe default rather than producing zero-width windows.
func setMaxEmbedBatch(n int) {
	if n < 0 {
		n = 0
	}
	maxEmbedBatch.Store(int64(n))
}

// embedBatchWindow returns the active window size (0 = unlimited). It reads the
// atomic once so a concurrent set is observed atomically.
func embedBatchWindow() int {
	return int(maxEmbedBatch.Load())
}

// embeddedVec is one batch result: the DENSE float32 vector (always present, the
// legacy payload) plus an OPTIONAL SPARSE term-weight map (token_id -> weight) for
// a hybrid embedder (e.g. BGE-M3, which emits a dense vector AND a lexical sparse
// vector in one pass). Sparse is nil for a dense-only embedder — including every
// existing one and the offline embed.py legacy wire shape — so widening the batch
// return to carry sparse is BACKWARD COMPATIBLE: a dense-only response decodes to
// {Dense: v, Sparse: nil} and behaves exactly as before. Dense is the field the
// loud-fallback non-empty/equal-length invariant is enforced against (an empty
// Dense is the protocol violation, regardless of Sparse).
type embeddedVec struct {
	Dense  []float32
	Sparse map[int]float32
}

// batchEmbedder is the OPT-IN companion to Embedder: it embeds a SLICE of texts in
// one shot, returning one vector per input in the SAME ORDER. An embedder that
// implements it advertises that it can amortize the per-chunk cost; an embedder
// that does not is driven one-at-a-time via Embedder.Embed exactly as before.
//
// Contract on the return:
//   - len(vecs) == len(texts) (order-preserving, equal-length) — a mismatch is a
//     protocol violation the caller treats as a failure and falls back from;
//   - each vecs[i].Dense is non-empty (the loud-fallback invariant); vecs[i].Sparse
//     is OPTIONAL (nil for a dense-only embedder, the legacy shape);
//   - model is the producing embedder's label (recorded in chunk_embeddings.model,
//     identical to what Embed reports, so the cache signature is unchanged whether
//     a vector arrived via the batch or the per-chunk path);
//   - a non-nil err means the whole batch is unusable — the caller falls back.
//
// DENSE-PARITY INVARIANT (load-bearing for ranking): for the SAME input text, the
// dense vector EmbedBatch returns MUST be identical to the one Embed returns — same
// model, same width, element-for-element equal. This is not cosmetic: embedQueryHybrid
// routes a batch-capable embedder's QUERY through tryBatch (a one-element EmbedBatch)
// to recover the sparse vector, so the query's dense leg now comes from EmbedBatch
// while every CACHED chunk's dense vector may have been produced by either seam. If
// the two seams disagreed on dense for the same text, query-vs-chunk cosine would mix
// vectors from two different embedding functions and the rank would be silently wrong.
// Production embedders (httpEmbedder, cmdBatchEmbedder) are same-model by construction
// — both seams call the SAME backing model — so the invariant holds by contract; it is
// asserted directly by TestEmbedEmbedBatchDenseParity and TestEmbedQueryHybridDenseParity
// against fakes (one whose seams deliberately AGREE, one whose seams deliberately
// DIVERGE) so a future embedder that breaks parity fails loudly in test rather than
// shipping a subtly mis-ranked index.
type batchEmbedder interface {
	EmbedBatch(ctx context.Context, texts []string) (vecs []embeddedVec, model string, err error)
}

// embedTexts embeds texts in order, preferring the OPT-IN batch path when emb
// implements batchEmbedder and falling back LOUDLY to the per-chunk Embedder path
// otherwise (or when a batch attempt fails its contract). It is the single helper
// embedChunks calls instead of looping Embed itself, so the batch seam is consulted
// in exactly one place and the default per-chunk contract is preserved verbatim.
//
// Order preservation, equal-length output, per-vector width validation, and the
// loud fallback on a malformed / mismatched batch response are all enforced here
// (see tryBatch). texts is never mutated.
//
// MAX-BATCH WINDOWS: when the configured window size (embedBatchWindow) is a
// positive N smaller than the set, the texts are split into order-preserving
// windows of at most N and each window is one EmbedBatch invocation; the per-window
// results are concatenated in input order so the overall output is identical to an
// unwindowed batch. The default window 0 = UNLIMITED runs the whole set in one
// invocation (the pre-windowing behavior, verbatim). A single window that fails its
// contract falls back LOUDLY to the per-chunk path FOR THAT WINDOW ONLY — the other
// windows keep their batched vectors, so one bad frame never abandons a whole pass.
func embedTexts(ctx context.Context, emb Embedder, texts []string) (vecs []embeddedVec, model string, err error) {
	if len(texts) == 0 {
		return nil, "", nil
	}
	// OPT-IN: only attempt batching when the embedder advertises the seam AND there
	// is more than one text to amortize over (a single text has nothing to batch and
	// just pays the per-chunk path directly).
	be, ok := emb.(batchEmbedder)
	if !ok || len(texts) <= 1 {
		return embedEach(ctx, emb, texts)
	}

	out := make([]embeddedVec, 0, len(texts))
	for _, window := range windowTexts(texts, embedBatchWindow()) {
		if v, m, ok := tryBatch(ctx, be, window); ok {
			out = append(out, v...)
			model = m
			continue
		}
		// tryBatch already emitted the LOUD fallback line for this window; recover
		// just this window via the per-chunk path so the rest of the pass keeps its
		// batched vectors. A single text in a window still goes through Embed here.
		v, m, err := embedEach(ctx, emb, window)
		if err != nil {
			return nil, "", err
		}
		out = append(out, v...)
		model = m
	}
	return out, model, nil
}

// windowTexts splits texts into order-preserving contiguous windows of at most n.
// n<=0 means UNLIMITED — the whole slice is returned as a single window, so the
// default (no cap) is one batch invocation exactly as before. The returned windows
// are sub-slices of texts (no copy); callers must not mutate them. The concatenation
// of the windows is texts itself, so windowing never reorders or drops a text.
func windowTexts(texts []string, n int) [][]string {
	if n <= 0 || len(texts) <= n {
		return [][]string{texts}
	}
	windows := make([][]string, 0, (len(texts)+n-1)/n)
	for start := 0; start < len(texts); start += n {
		end := start + n
		if end > len(texts) {
			end = len(texts)
		}
		windows = append(windows, texts[start:end])
	}
	return windows
}

// embedQueryHybrid embeds a SINGLE query text and returns BOTH its dense vector and
// its OPTIONAL sparse term-weight map — the read-path companion to embedTexts, used
// by semanticSearch's hybrid leg so a query embedded by a hybrid embedder (BGE-M3)
// carries the sparse vector needed for the lexical-dot contribution. The default
// Embedder.Embed seam is dense-only by contract (it returns no sparse), so a query
// gets a sparse vector ONLY when the embedder implements the batchEmbedder seam; we
// invoke that seam with a one-element batch and take its single result. When the
// embedder is dense-only — or the batch attempt fails its contract (loud fallback) —
// the query's Sparse is nil and semanticSearch ranks dense-cosine only, exactly as
// before. The dense vector is always returned (the always-present payload); model is
// the producing embedder's label.
func embedQueryHybrid(ctx context.Context, emb Embedder, query string) (dense []float32, sparse map[int]float32, model string, err error) {
	if be, ok := emb.(batchEmbedder); ok {
		if v, m, ok := tryBatch(ctx, be, []string{query}); ok && len(v) == 1 {
			return v[0].Dense, v[0].Sparse, m, nil
		}
		// tryBatch already emitted the LOUD fallback line on a contract violation;
		// drop through to the dense-only per-chunk path.
	}
	d, m, err := emb.Embed(ctx, query)
	if err != nil {
		return nil, nil, "", err
	}
	return d, nil, m, nil
}

// tryBatch runs one batch invocation and validates its contract: equal length,
// non-empty vectors, UNIFORM per-vector width, no error. On ANY violation it writes
// a single loud line to embedWarnOut and returns ok=false so the caller falls back
// to the per-chunk path. A clean batch returns the vectors, the model label, and
// ok=true.
//
// PER-VECTOR WIDTH VALIDATION: every returned Dense vector must have the SAME width
// (the width of the first vector is taken as the expected dimension of the batch).
// A single vector of a different width is a protocol violation — a hybrid/dense
// embedder cannot emit two dense widths in one model, so a divergent width is
// either a truncated payload or a frame-misalignment that would write a ragged,
// un-cosine-able set into the cache. It is rejected LOUDLY (naming the offending
// index and the two widths) so the window degrades to the per-chunk path instead of
// poisoning the index with mismatched-width vectors.
func tryBatch(ctx context.Context, be batchEmbedder, texts []string) ([]embeddedVec, string, bool) {
	vecs, model, err := be.EmbedBatch(ctx, texts)
	if err != nil {
		warnBatchFallback(fmt.Sprintf("batch embed failed: %v", err))
		return nil, "", false
	}
	if len(vecs) != len(texts) {
		// The defining batch hazard: a non-array / mis-counted response. Loud, never
		// a silent short/long index.
		warnBatchFallback(fmt.Sprintf("batch embedder returned %d vectors for %d inputs (length mismatch)", len(vecs), len(texts)))
		return nil, "", false
	}
	expectDim := 0
	for i, v := range vecs {
		// The equal-length / non-empty invariant is enforced against DENSE — the
		// always-present payload. Sparse is optional (nil for a dense-only embedder)
		// and never gates the fallback.
		if len(v.Dense) == 0 {
			warnBatchFallback(fmt.Sprintf("batch embedder returned an empty vector at index %d", i))
			return nil, "", false
		}
		// Per-vector width validation: pin the expected dimension to the first
		// vector's width, then require every subsequent vector to match it. A
		// divergent width is a ragged batch (truncation / frame misalignment) and is
		// never written to the index.
		if expectDim == 0 {
			expectDim = len(v.Dense)
		} else if len(v.Dense) != expectDim {
			warnBatchFallback(fmt.Sprintf("batch embedder returned a width-%d vector at index %d (expected width %d) — inconsistent vector width", len(v.Dense), i, expectDim))
			return nil, "", false
		}
	}
	return vecs, model, true
}

// embedEach is the per-chunk path: one Embed call per text, order-preserving. It is
// both the DEFAULT contract for a non-batch embedder and the fallback target when a
// batch attempt is abandoned. The model label is taken from the last embed (every
// vector this pass comes from the same embedder, so the label is constant).
func embedEach(ctx context.Context, emb Embedder, texts []string) ([]embeddedVec, string, error) {
	vecs := make([]embeddedVec, len(texts))
	var model string
	for i, t := range texts {
		v, m, err := emb.Embed(ctx, t)
		if err != nil {
			return nil, "", err
		}
		// The per-chunk Embedder seam is dense-only by contract, so Sparse stays nil
		// on this path — a dense-only embedder (and the fallback target for a failed
		// batch) carries no sparse vector.
		vecs[i] = embeddedVec{Dense: v}
		model = m
	}
	return vecs, model, nil
}

// warnBatchFallback writes the single LOUD line that announces a batch attempt was
// abandoned for the per-chunk path. Goes to embedWarnOut (os.Stderr in production,
// a buffer in tests) so structured stdout output is untouched and the fallback is
// assertable.
func warnBatchFallback(reason string) {
	fmt.Fprintf(embedWarnOut,
		"taskdb: opt-in batch embedding abandoned (%s); falling back to per-chunk embedding for this pass.\n",
		reason)
}

// cmdBatchEmbedder is a cmdEmbedder that ALSO speaks the JSON batch wire shape via
// an extra invocation convention (a fixed --batch arg appended to argv). It embeds
// the EmbedBatch method on top of the inherited per-chunk Embed, so a single config
// can serve both contracts: the default path runs `argv... < text`, the batch path
// runs `argv... --batch < json-array` and reads a json-array-of-arrays back.
//
// newCmdEmbedder returns the plain (non-batch) cmdEmbedder by default; a caller
// that knows the configured embedder understands --batch wraps it with
// withBatch() to opt the index pass into batching.
type cmdBatchEmbedder struct {
	*cmdEmbedder
	// batchArg is the flag appended to argv to request batch mode (default
	// "--batch"); the embedder process keys its JSON-array wire shape off it.
	batchArg string
}

// withBatch promotes a cmdEmbedder to the batch wire shape, appending --batch to
// the child invocation. The per-chunk Embed is inherited unchanged, so the same
// process still serves the default contract when called one-at-a-time.
func withBatch(e *cmdEmbedder) *cmdBatchEmbedder {
	return &cmdBatchEmbedder{cmdEmbedder: e, batchArg: "--batch"}
}

// maybeWithBatch is the CLI opt-in adapter: `taskdb doc embed --batch-embedder`
// calls it to promote the configured embedder into batch mode for the index pass.
// It is conservative and idempotent by type:
//
//   - a plain *cmdEmbedder (the --embedder-cmd path, which is one-text-per-process
//     and does NOT implement batchEmbedder) is wrapped with withBatch() so the index
//     pass drives the child's --batch wire shape;
//   - any embedder that ALREADY implements batchEmbedder — the httpEmbedder
//     (--embedder-url) path, or an already-wrapped *cmdBatchEmbedder — is returned
//     UNCHANGED, since it can already batch (double-wrapping would be a no-op at best
//     and a re-appended --batch arg at worst);
//   - any other embedder is returned unchanged (nothing to promote).
//
// The DEFAULT (flag unset) never calls this, so the one-text-per-invocation contract
// is preserved verbatim unless an operator opts in. embedTexts still falls back
// LOUDLY per window if a wrapped child misbehaves, so the opt-in degrades to correct.
func maybeWithBatch(emb Embedder) Embedder {
	if _, ok := emb.(batchEmbedder); ok {
		// Already batch-capable (httpEmbedder, or an already-wrapped cmdBatchEmbedder):
		// promoting it again is unnecessary — return it as-is.
		return emb
	}
	if ce, ok := emb.(*cmdEmbedder); ok {
		return withBatch(ce)
	}
	return emb
}

// EmbedBatch runs the external command ONCE with --batch appended, writing a JSON
// array of strings to stdin and decoding the batch response from stdout. It
// performs only transport + parse here; the equal-length / non-empty contract is
// re-checked by tryBatch (the single enforcement point) so a direct caller of
// EmbedBatch and the embedChunks path agree on what a valid batch is. stderr is
// surfaced in the error so a failing batch is debuggable, and an undecodable stdout
// is a parse error (which tryBatch turns into the loud per-chunk fallback).
//
// BACKWARD COMPATIBILITY: the decoder (decodeBatchResponse) accepts BOTH the legacy
// dense-only shape ([[...float...], ...]) — which yields {Dense, Sparse:nil} — AND
// the hybrid shape ([{"dense":[...],"sparse":{...}}, ...]). The offline embed.py
// path and the existing dense-only embedders therefore decode unchanged.
func (e *cmdBatchEmbedder) EmbedBatch(ctx context.Context, texts []string) ([]embeddedVec, string, error) {
	in, err := json.Marshal(texts)
	if err != nil {
		return nil, "", fmt.Errorf("encoding batch input: %w", err)
	}
	argv := append(append([]string{}, e.argv...), e.batchArg)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, "", fmt.Errorf("batch embedder %q failed: %v: %s", e.argv[0], err, msg)
		}
		return nil, "", fmt.Errorf("batch embedder %q failed: %v", e.argv[0], err)
	}
	vecs, err := decodeBatchResponse(bytes.TrimSpace(stdout.Bytes()))
	if err != nil {
		return nil, "", fmt.Errorf("batch embedder %q output: %w", e.argv[0], err)
	}
	return vecs, e.modelLabel, nil
}

// decodeBatchResponse parses a batch-embedder stdout payload into []embeddedVec,
// accepting BOTH wire shapes so the seam is backward compatible:
//
//   - LEGACY dense-only:  [[0.1, 0.2, ...], ...]            → Sparse stays nil
//   - HYBRID dense+sparse: [{"dense":[...],"sparse":{...}}] → Sparse populated
//
// The shape is detected by the first non-whitespace byte of each element (peeked
// via json.RawMessage): '[' is a dense float array, '{' is a hybrid object. A mixed
// or malformed element is a parse error the caller surfaces as the loud per-chunk
// fallback. Sparse keys arrive as JSON object keys (strings of decimal token ids);
// they are parsed to int so the in-process representation is a clean int-keyed map.
func decodeBatchResponse(b []byte) ([]embeddedVec, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return nil, fmt.Errorf("is not a JSON array of embeddings: %w", err)
	}
	out := make([]embeddedVec, len(raws))
	for i, raw := range raws {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			return nil, fmt.Errorf("embedding at index %d is empty", i)
		}
		switch trimmed[0] {
		case '[':
			// Legacy dense-only float array.
			var dense []float32
			if err := json.Unmarshal(trimmed, &dense); err != nil {
				return nil, fmt.Errorf("dense embedding at index %d is not a float array: %w", i, err)
			}
			out[i] = embeddedVec{Dense: dense}
		case '{':
			// Hybrid {dense, sparse} object. sparse is OPTIONAL (an object with a
			// "dense" key but no "sparse" key decodes to Sparse:nil, identical to the
			// legacy shape).
			var obj struct {
				Dense  []float32          `json:"dense"`
				Sparse map[string]float32 `json:"sparse"`
			}
			if err := json.Unmarshal(trimmed, &obj); err != nil {
				return nil, fmt.Errorf("hybrid embedding at index %d is not a {dense,sparse} object: %w", i, err)
			}
			ev := embeddedVec{Dense: obj.Dense}
			if len(obj.Sparse) > 0 {
				sparse := make(map[int]float32, len(obj.Sparse))
				for k, w := range obj.Sparse {
					id, err := strconv.Atoi(k)
					if err != nil {
						return nil, fmt.Errorf("sparse token id %q at index %d is not an integer: %w", k, i, err)
					}
					sparse[id] = w
				}
				ev.Sparse = sparse
			}
			out[i] = ev
		default:
			return nil, fmt.Errorf("embedding at index %d is neither a dense array nor a {dense,sparse} object", i)
		}
	}
	return out, nil
}
