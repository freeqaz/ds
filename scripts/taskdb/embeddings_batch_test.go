// SPDX-License-Identifier: Apache-2.0
package main

// Hermetic tests for the OPT-IN batched embedding wire mode (embeddings_batch.go).
// No network, no model, no live API: every embedder here is an in-process Go fake.
//
// Coverage maps to the unit's acceptance gate:
//   - TestBatchEmbedderOrderAndLength: a fake batch embedder is consulted once for
//     all to-embed chunks, returns one vector per input IN ORDER, and the vectors
//     land against the right chunk hashes (order preservation + equal-length).
//   - TestBatchLengthMismatchFallsBackLoud: a batch response with the WRONG count
//     abandons the batch LOUDLY (a warning to embedWarnOut) and re-embeds via the
//     per-chunk path, producing a correct index anyway.
//   - TestBatchNonArrayFallsBackLoud: a batch embedder that errors / returns a
//     non-array also falls back loudly to per-chunk.
//   - TestBatchSingleTextUsesPerChunk: with only one to-embed chunk there is
//     nothing to amortize, so the per-chunk Embed path is used and EmbedBatch is
//     never called.
//   - TestNonBatchEmbedderUnchanged: an embedder that does NOT implement
//     batchEmbedder is driven exactly as before (the default contract is intact).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// batchCountingEmbedder is a fake that implements BOTH Embedder and batchEmbedder.
// It tallies per-chunk Embed calls (calls), batch EmbedBatch invocations
// (batchInvokes) and the total texts seen in batches (batchTexts), and embeds the
// fixed probe canary via Embed (probes) so the batch assertions stay exact. Its
// vectors are the same deterministic bag-of-words the rest of the suite uses, so
// ranking stays meaningful and identical text maps to identical vectors whether it
// came through Embed or EmbedBatch.
type batchCountingEmbedder struct {
	calls        atomic.Int64
	probes       atomic.Int64
	batchInvokes atomic.Int64
	batchTexts   atomic.Int64
}

func (e *batchCountingEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	if text == embedProbe {
		e.probes.Add(1)
	} else {
		e.calls.Add(1)
	}
	return bagOfWordsVector(text), "fake-batch-v1", nil
}

func (e *batchCountingEmbedder) EmbedBatch(_ context.Context, texts []string) ([]embeddedVec, string, error) {
	e.batchInvokes.Add(1)
	e.batchTexts.Add(int64(len(texts)))
	vecs := make([]embeddedVec, len(texts))
	for i, t := range texts {
		// Dense-only (Sparse stays nil) — this fake predates the hybrid wire shape and
		// proves the widened return still threads dense vectors unchanged.
		vecs[i] = embeddedVec{Dense: bagOfWordsVector(t)}
	}
	return vecs, "fake-batch-v1", nil
}

// brokenBatchEmbedder implements batchEmbedder but VIOLATES the contract in a way
// the test selects: it can drop a vector (length mismatch), return an error
// (modeling a non-array / process failure), or emit an empty vector. Its per-chunk
// Embed is correct, so a loud fallback yields a correct index. probes/calls let the
// test assert the fallback actually drove the per-chunk path.
type brokenBatchEmbedder struct {
	mode   string // "short", "error", "empty"
	calls  atomic.Int64
	probes atomic.Int64
	batch  atomic.Int64
}

func (e *brokenBatchEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	if text == embedProbe {
		e.probes.Add(1)
	} else {
		e.calls.Add(1)
	}
	return bagOfWordsVector(text), "broken-batch-v1", nil
}

func (e *brokenBatchEmbedder) EmbedBatch(_ context.Context, texts []string) ([]embeddedVec, string, error) {
	e.batch.Add(1)
	switch e.mode {
	case "error":
		return nil, "", fmt.Errorf("synthetic batch failure (modeling a non-array/process error)")
	case "short":
		// Return ONE FEWER vector than asked — the canonical length-mismatch hazard.
		vecs := make([]embeddedVec, 0, len(texts))
		for i, t := range texts {
			if i == len(texts)-1 {
				break
			}
			vecs = append(vecs, embeddedVec{Dense: bagOfWordsVector(t)})
		}
		return vecs, "broken-batch-v1", nil
	case "empty":
		// Equal length but one empty DENSE vector — also a protocol violation (the
		// invariant is enforced against Dense, regardless of Sparse).
		vecs := make([]embeddedVec, len(texts))
		for i, t := range texts {
			vecs[i] = embeddedVec{Dense: bagOfWordsVector(t)}
		}
		if len(vecs) > 0 {
			vecs[0] = embeddedVec{Dense: nil}
		}
		return vecs, "broken-batch-v1", nil
	default:
		return nil, "", fmt.Errorf("unknown broken mode %q", e.mode)
	}
}

// TestBatchEmbedderOrderAndLength: a batch embedder is consulted ONCE for all
// to-embed chunks, returns one vector per input in order, and the vectors are
// stored against the right chunk hashes — order preservation + equal-length end to
// end, with the resulting index ranking correctly.
func TestBatchEmbedderOrderAndLength(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/04.md", "Networking", "nftables firewall egress gateway proxy networking")
	seedChunk(t, db, "docs/22.md", "Worktrees", "task worktree branch lock dispatch agent")
	seedChunk(t, db, "docs/08.md", "Embeddings", "embedding vector cosine search index chunk")

	emb := &batchCountingEmbedder{}
	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if res.Embedded != 3 || res.Skipped != 0 {
		t.Fatalf("embedded=%d skipped=%d, want 3/0", res.Embedded, res.Skipped)
	}
	// The batch path was taken ONCE for all three chunks; the per-chunk Embed was
	// NOT used for chunk text (only the single probe canary went through Embed).
	if got := emb.batchInvokes.Load(); got != 1 {
		t.Errorf("EmbedBatch invocations = %d, want 1 (one batch for all chunks)", got)
	}
	if got := emb.batchTexts.Load(); got != 3 {
		t.Errorf("batch saw %d texts, want 3", got)
	}
	if got := emb.calls.Load(); got != 0 {
		t.Errorf("per-chunk Embed was used for chunk text (%d calls); batch should have covered it", got)
	}

	// Order preservation: each stored vector matches the bag-of-words of ITS OWN
	// chunk body (a permutation would mis-key the vectors and fail this).
	for _, c := range []struct{ path, body string }{
		{"docs/04.md", "nftables firewall egress gateway proxy networking"},
		{"docs/22.md", "task worktree branch lock dispatch agent"},
		{"docs/08.md", "embedding vector cosine search index chunk"},
	} {
		var blob []byte
		if err := db.QueryRow(
			`SELECT vector FROM chunk_embeddings WHERE chunk_hash = (SELECT hash FROM doc_chunks WHERE path=?)`,
			c.path).Scan(&blob); err != nil {
			t.Fatalf("load vector for %s: %v", c.path, err)
		}
		got, err := decodeVector(blob)
		if err != nil {
			t.Fatalf("decode %s: %v", c.path, err)
		}
		want := bagOfWordsVector(c.body)
		if len(got) != len(want) {
			t.Fatalf("%s vector len = %d, want %d", c.path, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s vector mis-ordered at dim %d: got %v want %v (order not preserved)",
					c.path, i, got[i], want[i])
			}
		}
	}

	// Ranking still works through the batched index.
	hits, err := semanticSearch(context.Background(), db, emb, "firewall egress nftables", 10, true)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) == 0 || hits[0].Path != "docs/04.md" {
		t.Errorf("batched index ranks wrong; top = %s", hitTop(hits))
	}
}

// TestBatchLengthMismatchFallsBackLoud: a batch response with the WRONG number of
// vectors is abandoned LOUDLY and re-embedded via the per-chunk path, so the index
// is still correct and complete.
func TestBatchLengthMismatchFallsBackLoud(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "nftables firewall egress gateway")
	seedChunk(t, db, "docs/b.md", "B", "task worktree branch lock")
	seedChunk(t, db, "docs/c.md", "C", "embedding vector cosine search")

	var warn strings.Builder
	restore := swapWarnOut(&warn)
	defer restore()

	emb := &brokenBatchEmbedder{mode: "short"}
	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	// The batch was attempted once, then the per-chunk path embedded all three.
	if got := emb.batch.Load(); got != 1 {
		t.Errorf("EmbedBatch attempts = %d, want 1", got)
	}
	if got := emb.calls.Load(); got != 3 {
		t.Errorf("per-chunk fallback embeds = %d, want 3 (all chunks via fallback)", got)
	}
	if res.Embedded != 3 {
		t.Errorf("embedded = %d, want 3 (complete index despite the bad batch)", res.Embedded)
	}
	// LOUD: the fallback wrote a line naming the length mismatch.
	w := warn.String()
	if w == "" {
		t.Fatal("length-mismatch batch fell back SILENTLY; want a loud warning")
	}
	if !strings.Contains(w, "mismatch") {
		t.Errorf("warning did not name the length mismatch: %q", w)
	}
	if !strings.Contains(w, "per-chunk") {
		t.Errorf("warning did not announce the per-chunk fallback: %q", w)
	}
	// All three chunks are embedded.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM chunk_embeddings`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 {
		t.Errorf("cache rows = %d, want 3 (fallback filled the whole index)", n)
	}
}

// TestBatchNonArrayFallsBackLoud: a batch embedder that errors (modeling a
// non-array / process failure) also falls back loudly to the per-chunk path.
func TestBatchNonArrayFallsBackLoud(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "nftables firewall egress gateway")
	seedChunk(t, db, "docs/b.md", "B", "task worktree branch lock")

	var warn strings.Builder
	restore := swapWarnOut(&warn)
	defer restore()

	emb := &brokenBatchEmbedder{mode: "error"}
	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if got := emb.calls.Load(); got != 2 {
		t.Errorf("per-chunk fallback embeds = %d, want 2", got)
	}
	if res.Embedded != 2 {
		t.Errorf("embedded = %d, want 2", res.Embedded)
	}
	if w := warn.String(); w == "" || !strings.Contains(w, "per-chunk") {
		t.Errorf("non-array batch did not fall back loudly: %q", w)
	}
}

// TestBatchEmptyVectorFallsBackLoud: an equal-length batch with an EMPTY vector is
// still a protocol violation and falls back loudly.
func TestBatchEmptyVectorFallsBackLoud(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "nftables firewall egress gateway")
	seedChunk(t, db, "docs/b.md", "B", "task worktree branch lock")

	var warn strings.Builder
	restore := swapWarnOut(&warn)
	defer restore()

	emb := &brokenBatchEmbedder{mode: "empty"}
	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if res.Embedded != 2 || emb.calls.Load() != 2 {
		t.Errorf("empty-vector batch did not fall back: embedded=%d calls=%d, want 2/2",
			res.Embedded, emb.calls.Load())
	}
	if w := warn.String(); w == "" || !strings.Contains(w, "empty") {
		t.Errorf("empty-vector batch did not warn about the empty vector: %q", w)
	}
}

// TestBatchSingleTextUsesPerChunk: with exactly one to-embed chunk there is nothing
// to amortize, so embedTexts uses the per-chunk Embed path and EmbedBatch is never
// called — the batch wire only earns its keep on >1 text.
func TestBatchSingleTextUsesPerChunk(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "nftables firewall egress gateway")

	emb := &batchCountingEmbedder{}
	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if res.Embedded != 1 {
		t.Fatalf("embedded = %d, want 1", res.Embedded)
	}
	if got := emb.batchInvokes.Load(); got != 0 {
		t.Errorf("EmbedBatch was called for a single chunk (%d); want the per-chunk path", got)
	}
	if got := emb.calls.Load(); got != 1 {
		t.Errorf("per-chunk Embed calls = %d, want 1", got)
	}
}

// TestNonBatchEmbedderUnchanged: an embedder WITHOUT EmbedBatch is driven exactly
// as before — the default one-text-per-invocation contract is intact and a no-op
// re-run still skips. (countingEmbedder from embeddings_test.go does NOT implement
// batchEmbedder.)
func TestNonBatchEmbedderUnchanged(t *testing.T) {
	if _, ok := interface{}(&countingEmbedder{}).(batchEmbedder); ok {
		t.Fatal("countingEmbedder unexpectedly implements batchEmbedder; the default-contract guard is void")
	}
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "nftables firewall egress gateway")
	seedChunk(t, db, "docs/b.md", "B", "task worktree branch lock dispatch agent")

	emb := &countingEmbedder{}
	res1, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("first embed: %v", err)
	}
	if res1.Embedded != 2 || emb.calls.Load() != 2 {
		t.Errorf("non-batch first pass: embedded=%d calls=%d, want 2/2", res1.Embedded, emb.calls.Load())
	}
	res2, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("second embed: %v", err)
	}
	if res2.Skipped != 2 || emb.calls.Load() != 2 {
		t.Errorf("non-batch no-change re-run: skipped=%d calls=%d, want 2/2 (no re-embed)",
			res2.Skipped, emb.calls.Load())
	}
}

// TestEmbedTextsEmptyIsNoop: embedTexts over zero texts is a clean no-op (the
// embedChunks guard around len(jobs)>0 relies on this being harmless).
func TestEmbedTextsEmptyIsNoop(t *testing.T) {
	emb := &batchCountingEmbedder{}
	vecs, model, err := embedTexts(context.Background(), emb, nil)
	if err != nil {
		t.Fatalf("embedTexts(nil): %v", err)
	}
	if len(vecs) != 0 || model != "" {
		t.Errorf("embedTexts(nil) = (%d vecs, %q), want (0, \"\")", len(vecs), model)
	}
	if emb.batchInvokes.Load() != 0 || emb.calls.Load() != 0 {
		t.Error("embedTexts(nil) invoked the embedder")
	}
}

// --- max-batch window + per-vector width validation (embed-batch-hardening) ---

// withMaxBatch sets the max-batch window for the duration of a test and restores
// the prior value on cleanup, so a case can exercise windowing without leaking the
// global into the rest of the suite (the default is 0 = unlimited).
func withMaxBatch(t *testing.T, n int) {
	t.Helper()
	prev := embedBatchWindow()
	setMaxEmbedBatch(n)
	t.Cleanup(func() { setMaxEmbedBatch(prev) })
}

// windowRecordingEmbedder records the SIZE of every EmbedBatch window it sees (in
// order) so a test can assert the exact split, and embeds each text with the shared
// deterministic bag-of-words so order preservation is verifiable end to end.
type windowRecordingEmbedder struct {
	mu      sync.Mutex
	windows []int // len(texts) of each EmbedBatch call, in call order
	calls   atomic.Int64
	probes  atomic.Int64
}

func (e *windowRecordingEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	if text == embedProbe {
		e.probes.Add(1)
	} else {
		e.calls.Add(1)
	}
	return bagOfWordsVector(text), "window-v1", nil
}

func (e *windowRecordingEmbedder) EmbedBatch(_ context.Context, texts []string) ([]embeddedVec, string, error) {
	e.mu.Lock()
	e.windows = append(e.windows, len(texts))
	e.mu.Unlock()
	vecs := make([]embeddedVec, len(texts))
	for i, t := range texts {
		vecs[i] = embeddedVec{Dense: bagOfWordsVector(t)}
	}
	return vecs, "window-v1", nil
}

func (e *windowRecordingEmbedder) windowSizes() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := append([]int(nil), e.windows...)
	return out
}

// TestEmbedTextsDefaultWindowIsUnlimited: with the default window (0) a batch
// embedder is invoked ONCE for the whole set — the pre-windowing behavior verbatim.
func TestEmbedTextsDefaultWindowIsUnlimited(t *testing.T) {
	emb := &windowRecordingEmbedder{}
	texts := []string{"alpha one", "beta two", "gamma three", "delta four", "epsilon five"}
	vecs, model, err := embedTexts(context.Background(), emb, texts)
	if err != nil {
		t.Fatalf("embedTexts: %v", err)
	}
	if model != "window-v1" {
		t.Errorf("model = %q, want window-v1", model)
	}
	if got := emb.windowSizes(); len(got) != 1 || got[0] != len(texts) {
		t.Errorf("window sizes = %v, want one window of %d (unlimited default)", got, len(texts))
	}
	assertVecsMatchTexts(t, vecs, texts)
}

// TestEmbedTextsMaxBatchWindows: a positive max-batch splits the set into
// order-preserving windows of at most N, one EmbedBatch invocation each, and the
// concatenated result is identical to an unwindowed batch.
func TestEmbedTextsMaxBatchWindows(t *testing.T) {
	withMaxBatch(t, 2)
	emb := &windowRecordingEmbedder{}
	texts := []string{"alpha one", "beta two", "gamma three", "delta four", "epsilon five"}
	vecs, _, err := embedTexts(context.Background(), emb, texts)
	if err != nil {
		t.Fatalf("embedTexts: %v", err)
	}
	// 5 texts, window 2 -> [2,2,1].
	if got := emb.windowSizes(); len(got) != 3 || got[0] != 2 || got[1] != 2 || got[2] != 1 {
		t.Errorf("window sizes = %v, want [2 2 1]", got)
	}
	if emb.calls.Load() != 0 {
		t.Errorf("per-chunk Embed used (%d) under clean windowing; want batch only", emb.calls.Load())
	}
	// Order preserved across windows: vecs[i] is the bag-of-words of texts[i].
	assertVecsMatchTexts(t, vecs, texts)
}

// TestEmbedTextsWindowEvenSplit: a set that divides evenly windows with no short
// tail (4 texts, window 2 -> [2,2]).
func TestEmbedTextsWindowEvenSplit(t *testing.T) {
	withMaxBatch(t, 2)
	emb := &windowRecordingEmbedder{}
	texts := []string{"a one", "b two", "c three", "d four"}
	vecs, _, err := embedTexts(context.Background(), emb, texts)
	if err != nil {
		t.Fatalf("embedTexts: %v", err)
	}
	if got := emb.windowSizes(); len(got) != 2 || got[0] != 2 || got[1] != 2 {
		t.Errorf("window sizes = %v, want [2 2]", got)
	}
	assertVecsMatchTexts(t, vecs, texts)
}

// TestEmbedTextsWindowLargerThanSet: a window wider than the set is a single batch
// (windowing only earns its keep when the set exceeds the cap).
func TestEmbedTextsWindowLargerThanSet(t *testing.T) {
	withMaxBatch(t, 100)
	emb := &windowRecordingEmbedder{}
	texts := []string{"a one", "b two", "c three"}
	if _, _, err := embedTexts(context.Background(), emb, texts); err != nil {
		t.Fatalf("embedTexts: %v", err)
	}
	if got := emb.windowSizes(); len(got) != 1 || got[0] != 3 {
		t.Errorf("window sizes = %v, want a single window of 3", got)
	}
}

// TestEmbedChunksWindowedPreservesOrder: end to end through embedChunks, a windowed
// batch lands the right vector against each chunk hash (order preserved across
// window boundaries) and the index ranks correctly.
func TestEmbedChunksWindowedPreservesOrder(t *testing.T) {
	withMaxBatch(t, 2)
	db := openTestDB(t)
	// All bodies are drawn from fakeVocab so dense cosine is meaningful (out-of-vocab
	// words produce zero components). Five chunks exercise the [2,2,1] window split.
	rows := []struct{ path, head, body string }{
		{"docs/04.md", "Net", "nftables firewall egress gateway proxy networking"},
		{"docs/22.md", "WT", "task worktree branch lock dispatch agent"},
		{"docs/08.md", "Emb", "embedding vector cosine search index chunk"},
		{"docs/11.md", "Idx", "index search vector chunk cosine embedding"},
		{"docs/27.md", "Lock", "lock branch worktree task agent dispatch"},
	}
	for _, r := range rows {
		seedChunk(t, db, r.path, r.head, r.body)
	}

	emb := &windowRecordingEmbedder{}
	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if res.Embedded != len(rows) {
		t.Fatalf("embedded = %d, want %d", res.Embedded, len(rows))
	}
	// 5 chunks, window 2 -> [2,2,1] (the probe canary goes through Embed, not batch).
	if got := emb.windowSizes(); len(got) != 3 || got[0] != 2 || got[1] != 2 || got[2] != 1 {
		t.Errorf("window sizes = %v, want [2 2 1]", got)
	}
	for _, r := range rows {
		var blob []byte
		if err := db.QueryRow(
			`SELECT vector FROM chunk_embeddings WHERE chunk_hash = (SELECT hash FROM doc_chunks WHERE path=?)`,
			r.path).Scan(&blob); err != nil {
			t.Fatalf("load vector for %s: %v", r.path, err)
		}
		got, err := decodeVector(blob)
		if err != nil {
			t.Fatalf("decode %s: %v", r.path, err)
		}
		want := bagOfWordsVector(r.body)
		if len(got) != len(want) {
			t.Fatalf("%s vector len = %d, want %d", r.path, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s vector mis-ordered at dim %d across window boundary: got %v want %v",
					r.path, i, got[i], want[i])
			}
		}
	}
	hits, err := semanticSearch(context.Background(), db, emb, "firewall egress nftables", 10, true)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) == 0 || hits[0].Path != "docs/04.md" {
		t.Errorf("windowed index ranks wrong; top = %s", hitTop(hits))
	}
}

// widthVaryingBatchEmbedder returns Dense vectors whose width VARIES across the
// batch (the i-th vector is padded to a different width once i hits oddAt) — the
// per-vector width-validation hazard. Its per-chunk Embed is correct so the loud
// fallback yields a correct index.
type widthVaryingBatchEmbedder struct {
	oddAt  int // index whose Dense width diverges from index 0
	calls  atomic.Int64
	probes atomic.Int64
	batch  atomic.Int64
}

func (e *widthVaryingBatchEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	if text == embedProbe {
		e.probes.Add(1)
	} else {
		e.calls.Add(1)
	}
	return bagOfWordsVector(text), "width-vary-v1", nil
}

func (e *widthVaryingBatchEmbedder) EmbedBatch(_ context.Context, texts []string) ([]embeddedVec, string, error) {
	e.batch.Add(1)
	vecs := make([]embeddedVec, len(texts))
	for i, t := range texts {
		d := bagOfWordsVector(t)
		if i == e.oddAt {
			// Diverge this vector's width — a ragged batch the validator must reject.
			d = append(append([]float32(nil), d...), 0.0, 0.0)
		}
		vecs[i] = embeddedVec{Dense: d}
	}
	return vecs, "width-vary-v1", nil
}

// TestBatchWidthMismatchFallsBackLoud: a batch with one differently-WIDTH vector is
// a protocol violation — it is rejected loudly (naming the width) and re-embedded
// via the per-chunk path, so the index is uniform-width and complete.
func TestBatchWidthMismatchFallsBackLoud(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "nftables firewall egress gateway")
	seedChunk(t, db, "docs/b.md", "B", "task worktree branch lock")
	seedChunk(t, db, "docs/c.md", "C", "embedding vector cosine search")

	var warn strings.Builder
	restore := swapWarnOut(&warn)
	defer restore()

	emb := &widthVaryingBatchEmbedder{oddAt: 1}
	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if got := emb.batch.Load(); got != 1 {
		t.Errorf("EmbedBatch attempts = %d, want 1", got)
	}
	if got := emb.calls.Load(); got != 3 {
		t.Errorf("per-chunk fallback embeds = %d, want 3 (all chunks via fallback)", got)
	}
	if res.Embedded != 3 {
		t.Errorf("embedded = %d, want 3 (complete index despite the ragged batch)", res.Embedded)
	}
	w := warn.String()
	if w == "" {
		t.Fatal("width-mismatch batch fell back SILENTLY; want a loud warning")
	}
	if !strings.Contains(w, "width") {
		t.Errorf("warning did not name the width mismatch: %q", w)
	}
	if !strings.Contains(w, "per-chunk") {
		t.Errorf("warning did not announce the per-chunk fallback: %q", w)
	}
	// The whole index is uniform width (the validator kept the ragged vectors out).
	var dims int
	if err := db.QueryRow(`SELECT COUNT(DISTINCT dims) FROM chunk_embeddings`).Scan(&dims); err != nil {
		t.Fatalf("count dims: %v", err)
	}
	if dims != 1 {
		t.Errorf("index has %d distinct vector widths, want 1 (uniform)", dims)
	}
}

// TestTryBatchWidthMismatchRejected: tryBatch directly rejects a width-divergent
// batch (the single enforcement point), without going through embedChunks.
func TestTryBatchWidthMismatchRejected(t *testing.T) {
	var warn strings.Builder
	restore := swapWarnOut(&warn)
	defer restore()

	emb := &widthVaryingBatchEmbedder{oddAt: 2}
	texts := []string{"a one", "b two", "c three", "d four"}
	_, _, ok := tryBatch(context.Background(), emb, texts)
	if ok {
		t.Fatal("tryBatch accepted a width-divergent batch; want a rejection")
	}
	if w := warn.String(); !strings.Contains(w, "width") {
		t.Errorf("tryBatch did not warn about the width mismatch: %q", w)
	}
}

// TestTryBatchUniformWidthAccepted: a uniform-width batch passes the new validation
// (the happy path stays green).
func TestTryBatchUniformWidthAccepted(t *testing.T) {
	emb := &batchCountingEmbedder{}
	texts := []string{"a one", "b two", "c three"}
	vecs, _, ok := tryBatch(context.Background(), emb, texts)
	if !ok {
		t.Fatal("tryBatch rejected a uniform-width batch")
	}
	w := len(vecs[0].Dense)
	for i, v := range vecs {
		if len(v.Dense) != w {
			t.Errorf("vec %d width = %d, want %d (uniform)", i, len(v.Dense), w)
		}
	}
}

// TestWindowTextsSplits: the pure windowing helper splits correctly and its
// concatenation is the input (no reorder, no drop), with n<=0 = single window.
func TestWindowTextsSplits(t *testing.T) {
	in := []string{"0", "1", "2", "3", "4", "5", "6"}
	for _, tc := range []struct {
		n    int
		want []int // window lengths
	}{
		{0, []int{7}},
		{-1, []int{7}},
		{1, []int{1, 1, 1, 1, 1, 1, 1}},
		{3, []int{3, 3, 1}},
		{7, []int{7}},
		{100, []int{7}},
	} {
		ws := windowTexts(in, tc.n)
		got := make([]int, len(ws))
		var flat []string
		for i, w := range ws {
			got[i] = len(w)
			flat = append(flat, w...)
		}
		if len(got) != len(tc.want) {
			t.Errorf("n=%d window count = %v, want %v", tc.n, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("n=%d window sizes = %v, want %v", tc.n, got, tc.want)
				break
			}
		}
		if strings.Join(flat, ",") != strings.Join(in, ",") {
			t.Errorf("n=%d windowing reordered/dropped: %v", tc.n, flat)
		}
	}
}

// TestSetMaxEmbedBatchClampsNegative: a negative window is clamped to 0
// (unlimited), so a malformed flag degrades to the safe default.
func TestSetMaxEmbedBatchClampsNegative(t *testing.T) {
	prev := embedBatchWindow()
	defer setMaxEmbedBatch(prev)
	setMaxEmbedBatch(-5)
	if got := embedBatchWindow(); got != 0 {
		t.Errorf("embedBatchWindow after set(-5) = %d, want 0 (clamped)", got)
	}
	setMaxEmbedBatch(4)
	if got := embedBatchWindow(); got != 4 {
		t.Errorf("embedBatchWindow after set(4) = %d, want 4", got)
	}
}

// --- CLI opt-in (--batch-embedder) wiring (embed-batch-hardening) ---

// TestMaybeWithBatchPromotesCmdEmbedder: the --batch-embedder adapter wraps a plain
// *cmdEmbedder (which does NOT implement batchEmbedder) into a batch-capable
// *cmdBatchEmbedder, so the CLI opt-in actually turns batching on for the cmd path.
func TestMaybeWithBatchPromotesCmdEmbedder(t *testing.T) {
	// A plain cmdEmbedder is one-text-per-process and is NOT batch-capable until wrapped.
	ce, err := newCmdEmbedder([]string{"true"})
	if err != nil {
		t.Fatalf("newCmdEmbedder: %v", err)
	}
	if _, ok := interface{}(ce).(batchEmbedder); ok {
		t.Fatal("a plain *cmdEmbedder unexpectedly implements batchEmbedder; the opt-in would be a no-op")
	}
	promoted := maybeWithBatch(ce)
	if _, ok := promoted.(batchEmbedder); !ok {
		t.Fatal("maybeWithBatch did not promote *cmdEmbedder to a batch-capable embedder")
	}
	if _, ok := promoted.(*cmdBatchEmbedder); !ok {
		t.Errorf("maybeWithBatch returned %T, want *cmdBatchEmbedder", promoted)
	}
}

// TestMaybeWithBatchLeavesBatchCapableUntouched: an embedder that ALREADY implements
// batchEmbedder (the httpEmbedder --embedder-url path, modeled here by an in-process
// fake; and an already-wrapped *cmdBatchEmbedder) is returned UNCHANGED — the opt-in
// never double-wraps.
func TestMaybeWithBatchLeavesBatchCapableUntouched(t *testing.T) {
	fake := &batchCountingEmbedder{}
	if got := maybeWithBatch(fake); got != Embedder(fake) {
		t.Errorf("maybeWithBatch re-wrapped an already batch-capable embedder: got %T", got)
	}
	ce, err := newCmdEmbedder([]string{"true"})
	if err != nil {
		t.Fatalf("newCmdEmbedder: %v", err)
	}
	wrapped := withBatch(ce)
	if got := maybeWithBatch(wrapped); got != Embedder(wrapped) {
		t.Errorf("maybeWithBatch double-wrapped an already-wrapped *cmdBatchEmbedder: got %T", got)
	}
}

// TestDocEmbedBatchEmbedderDrivesBatchMode is the HERMETIC integration test for the
// `taskdb doc embed --batch-embedder` opt-in: it builds the embedder exactly as
// docEmbed does (embedderFromFlag → maybeWithBatch under the flag), then drives the
// REAL index pass (embedChunks) against a REAL external embedder subprocess that
// speaks the documented wire shape. NO live model, NO network — the embedder is a
// tiny stdlib python script generated in TempDir that records each --batch
// invocation to a sentinel file, so the test can prove batch mode was actually
// driven end to end (not merely that the flag parses).
//
// The script serves BOTH contracts the pass exercises:
//   - per-chunk (the embedProbe canary embedChunks issues once): one text on stdin →
//     a JSON float array;
//   - --batch (the chunk texts): a JSON array of strings on stdin → a JSON array of
//     equal-width float arrays, order-preserving, appending one line to the sentinel.
func TestDocEmbedBatchEmbedderDrivesBatchMode(t *testing.T) {
	py, err := lookPython()
	if err != nil {
		t.Skip("python3 not available for the --batch-embedder integration test")
	}
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "batch_invocations.log")
	// A fixed-width (3-dim) deterministic embedder: the vector is [len(text), wordcount,
	// 1.0]. It detects --batch in argv (the cmdBatchEmbedder appends it) and, in that
	// mode, reads a JSON array of strings, appends a line to the sentinel, and writes a
	// JSON array of equal-width arrays in input order; otherwise it embeds the single
	// stdin text per-chunk. Uniform width keeps the new width validator happy.
	script := filepath.Join(dir, "batch_embedder.py")
	body := `import sys, json, os
SENT = ` + pyQuote(sentinel) + `
def vec(t):
    return [float(len(t)), float(len(t.split())), 1.0]
if "--batch" in sys.argv:
    texts = json.loads(sys.stdin.read())
    with open(SENT, "a") as f:
        f.write("batch:%d\n" % len(texts))
    sys.stdout.write(json.dumps([vec(t) for t in texts]))
else:
    sys.stdout.write(json.dumps(vec(sys.stdin.read())))
`
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatalf("write embedder script: %v", err)
	}

	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "nftables firewall egress gateway")
	seedChunk(t, db, "docs/b.md", "B", "task worktree branch lock dispatch")
	seedChunk(t, db, "docs/c.md", "C", "embedding vector cosine search index")

	// Build the embedder the SAME way docEmbed does, then apply the --batch-embedder
	// opt-in (the production wiring under test). embedderFromFlag splits the cmd on
	// whitespace into argv.
	emb, err := embedderFromFlag(py+" "+script, "")
	if err != nil {
		t.Fatalf("embedderFromFlag: %v", err)
	}
	emb = maybeWithBatch(emb) // what `--batch-embedder` triggers in docEmbed

	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embedChunks: %v", err)
	}
	if res.Embedded != 3 {
		t.Fatalf("embedded = %d, want 3", res.Embedded)
	}

	// PROOF that batch mode was driven: the external --batch path ran and saw all
	// three chunk texts in a single invocation (the sentinel records one "batch:3").
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("read sentinel: %v (batch mode never ran)", err)
	}
	if !strings.Contains(string(got), "batch:3") {
		t.Errorf("sentinel = %q, want a single batch invocation over 3 texts (\"batch:3\")", string(got))
	}

	// The index is complete and uniform width (the external batch wrote real vectors).
	var n, dims int
	if err := db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT dims) FROM chunk_embeddings`).Scan(&n, &dims); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 || dims != 1 {
		t.Errorf("index rows=%d distinct-dims=%d, want 3 rows / 1 width", n, dims)
	}
}

// pyQuote renders s as a Python string literal (used to embed an absolute path into
// the generated embedder script without shell/quoting hazards). It is JSON-compatible
// quoting, which Python accepts as a str literal.
func pyQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

// assertVecsMatchTexts verifies order preservation: vecs[i] is the bag-of-words of
// texts[i] (a window permutation would mis-key and fail this).
func assertVecsMatchTexts(t *testing.T, vecs []embeddedVec, texts []string) {
	t.Helper()
	if len(vecs) != len(texts) {
		t.Fatalf("got %d vecs for %d texts", len(vecs), len(texts))
	}
	for i, text := range texts {
		want := bagOfWordsVector(text)
		got := vecs[i].Dense
		if len(got) != len(want) {
			t.Fatalf("vec %d width = %d, want %d", i, len(got), len(want))
		}
		for d := range want {
			if got[d] != want[d] {
				t.Errorf("vec %d mis-ordered at dim %d: got %v want %v", i, d, got[d], want[d])
			}
		}
	}
}
