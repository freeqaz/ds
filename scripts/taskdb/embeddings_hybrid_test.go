// SPDX-License-Identifier: Apache-2.0
package main

// Hermetic tests for the hybrid-score-normalization unit (bgem3w6): the Go-side
// semanticSearch must BOUND the sparse leg so a single high-weight shared lexical
// term can no longer SWAMP a strong dense match (the bug persist-hybrid-sparse left,
// where an UNBOUNDED sparseDot was added straight onto a cosine that lives in
// [-1,1]). Plus the Embed/EmbedBatch dense-parity invariant: a single Embed and a
// batched EmbedBatch produce IDENTICAL dense vectors for the same input.
//
// No network, no model, no GPU: every embedder is an in-process Go fake and every
// assertion is on the FULL ranking order / exact byte-for-byte dense vectors.
//
// Coverage:
//   - TestSparseCosineBounded: sparseCosine lands in [0,1] for non-negative weights,
//     is invariant to a uniform weight scaling (a huge weight does NOT inflate it),
//     is symmetric, and is 0 for disjoint/empty inputs — the property that makes the
//     lexical leg comparable to dense-cosine.
//   - TestHybridScoreDenseOnlyPassthrough: hybridScore returns the dense cosine
//     UNCHANGED when either side carries no sparse vector (dense-only ranking is
//     byte-for-byte preserved).
//   - TestHighWeightSparseDoesNotSwampDense: end to end through semanticSearch — a
//     strong dense match outranks a near-zero-dense chunk that shares a HUGE-weight
//     sparse term with the query. Asserts the FULL order and that the bounded sparse
//     leg cannot exceed wSparseDefault.
//   - TestEmbedEmbedBatchDenseParity: single Embed and batched EmbedBatch produce
//     identical dense vectors for the same inputs, and EmbedBatch preserves the
//     equal-length / non-empty invariants.

import (
	"context"
	"math"
	"strings"
	"testing"
)

// TestSparseCosineBounded: the normalized lexical similarity is bounded to [0,1] for
// the non-negative term weights a lexical embedder emits, is SYMMETRIC, and — the
// load-bearing property — is INVARIANT to a uniform scaling of one side's weights, so
// a single huge-weight term can no longer inflate the leg past 1. Disjoint and empty
// inputs score exactly 0.
func TestSparseCosineBounded(t *testing.T) {
	a := map[int]float32{1: 2.0, 2: 3.0, 5: 1.0}
	b := map[int]float32{2: 4.0, 5: 0.5, 9: 7.0}

	got := sparseCosine(a, b)
	if got < 0 || got > 1 {
		t.Errorf("sparseCosine = %v, want within [0,1]", got)
	}
	// Symmetric.
	if rev := sparseCosine(b, a); math.Abs(got-rev) > 1e-9 {
		t.Errorf("sparseCosine not symmetric: %v vs %v", got, rev)
	}
	// Identical maps → cosine 1 (a vector is perfectly aligned with itself).
	if self := sparseCosine(a, a); math.Abs(self-1.0) > 1e-9 {
		t.Errorf("sparseCosine(a,a) = %v, want 1", self)
	}
	// Scale-invariance: multiplying ONE side's weights by a huge factor does NOT change
	// the cosine — this is exactly what stops a high-weight term from swamping. Under the
	// old raw sparseDot this scaling would blow the contribution up by 1e6.
	huge := map[int]float32{2: 4.0e3, 5: 0.5e3, 9: 7.0e3}
	if scaled := sparseCosine(a, huge); math.Abs(scaled-got) > 1e-6 {
		t.Errorf("sparseCosine not scale-invariant: %v (scaled) vs %v (base)", scaled, got)
	}
	// Disjoint and empty → 0.
	if v := sparseCosine(a, map[int]float32{100: 9.0}); v != 0 {
		t.Errorf("disjoint sparseCosine = %v, want 0", v)
	}
	if v := sparseCosine(a, nil); v != 0 {
		t.Errorf("nil sparseCosine = %v, want 0", v)
	}
	if v := sparseCosine(nil, nil); v != 0 {
		t.Errorf("nil/nil sparseCosine = %v, want 0", v)
	}
	// A zero-weight-only vector has zero magnitude → 0, never NaN.
	if v := sparseCosine(map[int]float32{1: 0.0}, map[int]float32{1: 0.0}); v != 0 {
		t.Errorf("zero-magnitude sparseCosine = %v, want 0 (not NaN)", v)
	}
}

// TestHybridScoreDenseOnlyPassthrough: hybridScore must return the dense cosine
// UNCHANGED whenever EITHER side carries no sparse vector, so a dense-only query or a
// dense-only chunk ranks exactly as the pre-hybrid path did. When both carry sparse,
// the score is the bounded weighted blend and stays within the dense leg's [-1,1].
func TestHybridScoreDenseOnlyPassthrough(t *testing.T) {
	const dense = 0.8
	q := map[int]float32{7: 1.0}
	c := map[int]float32{7: 1.0}

	// No query sparse → pure dense.
	if got := hybridScore(dense, nil, c); got != dense {
		t.Errorf("nil query sparse: hybridScore = %v, want dense %v", got, dense)
	}
	// No chunk sparse → pure dense.
	if got := hybridScore(dense, q, nil); got != dense {
		t.Errorf("nil chunk sparse: hybridScore = %v, want dense %v", got, dense)
	}
	// Empty (non-nil) maps → pure dense (len==0 is the gate).
	if got := hybridScore(dense, map[int]float32{}, map[int]float32{}); got != dense {
		t.Errorf("empty sparse: hybridScore = %v, want dense %v", got, dense)
	}
	// Both present + a shared term → bounded blend = 0.65*dense + 0.35*sparseCosine.
	want := wDenseDefault*dense + wSparseDefault*sparseCosine(q, c)
	if got := hybridScore(dense, q, c); math.Abs(got-want) > 1e-12 {
		t.Errorf("blended hybridScore = %v, want %v", got, want)
	}
	// The blend never escapes [-1,1] (both legs are bounded cosines, weights sum to 1).
	if got := hybridScore(1.0, q, c); got > 1.0+1e-12 {
		t.Errorf("hybridScore(1.0,...) = %v, must not exceed 1", got)
	}
}

// TestHighWeightSparseDoesNotSwampDense is the unit's headline acceptance: end to end
// through semanticSearch, a chunk with a STRONG dense match (cosine ~1) outranks a
// chunk whose dense match is ~0 but which shares a HUGE-weight sparse term with the
// query. Under the OLD unbounded sparseDot the huge weight (1e6) would add straight
// onto the [-1,1] cosine and the lexical-only chunk would rank first; with the bounded
// sparse-cosine leg the lexical contribution is capped at wSparseDefault (0.35) and the
// strong dense match (>= wDenseDefault = 0.65) leads. We assert the FULL order.
func TestHighWeightSparseDoesNotSwampDense(t *testing.T) {
	db := openTestDB(t)

	// The strong chunk shares the query's FULL ranking vocabulary → dense cosine ~1.0
	// (a trailing "strongmarker" outside fakeVocab makes its body distinct from the
	// query without moving the dense score), and carries a sparse term DISJOINT from
	// the query so its sparse leg is 0. The weak chunk shares NONE of the query's
	// ranking vocabulary → dense cosine ~0, but shares a single MASSIVE-weight sparse
	// term with the query.
	const queryText = "firewall nftables egress gateway"
	seedChunk(t, db, "docs/a-strong.md", "Strong", "firewall nftables egress gateway strongmarker")
	seedChunk(t, db, "docs/z-weak.md", "Weak", "embedding vector cosine search weakmarker")

	const (
		sharedTerm   = 555
		disjointTerm = 111
	)
	emb := &sparseControlEmbedder{
		label: "swamp-v1",
		sparseFor: func(text string) map[int]float32 {
			switch {
			case strings.Contains(text, "strongmarker"):
				// The strong chunk: a sparse term DISJOINT from the query's → no boost.
				return map[int]float32{disjointTerm: 1.0}
			case strings.Contains(text, "weakmarker"):
				// The weak chunk: a single ENORMOUS-weight shared term.
				return map[int]float32{sharedTerm: 1.0e6}
			default:
				// The query: the shared term at a modest weight.
				return map[int]float32{sharedTerm: 1.0}
			}
		},
	}
	if _, err := embedChunks(context.Background(), db, emb, true); err != nil {
		t.Fatalf("embedChunks: %v", err)
	}

	hits, err := semanticSearch(context.Background(), db, emb, queryText, 10, false)
	if err != nil {
		t.Fatalf("semanticSearch: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %d, want 2", len(hits))
	}
	// FULL order: the strong dense match leads; the huge-weight lexical-only chunk does
	// NOT swamp it.
	if hits[0].Path != "docs/a-strong.md" || hits[1].Path != "docs/z-weak.md" {
		t.Fatalf("order = [%q, %q], want [docs/a-strong.md, docs/z-weak.md] — high-weight sparse SWAMPED the strong dense match",
			hits[0].Path, hits[1].Path)
	}
	if !(hits[0].Score > hits[1].Score) {
		t.Errorf("strong dense score %v must be STRICTLY above lexical-only score %v", hits[0].Score, hits[1].Score)
	}
	// The bounded sparse leg can contribute AT MOST wSparseDefault: the weak chunk's
	// score (dense ~0) must therefore not exceed wSparseDefault even with a 1e6 weight.
	if hits[1].Score > wSparseDefault+1e-6 {
		t.Errorf("lexical-only score %v exceeds the sparse weight cap %v — the leg is not bounded",
			hits[1].Score, wSparseDefault)
	}
}

// parityEmbedder is an in-process embedder whose dense vector is identical whether a
// text is embedded one-at-a-time (Embed) or in a batch (EmbedBatch). It lets the
// parity test assert that the two seams agree byte-for-byte on dense, and that
// EmbedBatch preserves the equal-length / non-empty invariants.
type parityEmbedder struct{}

func (parityEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	return bagOfWordsVector(text), "parity-v1", nil
}

func (parityEmbedder) EmbedBatch(_ context.Context, texts []string) ([]embeddedVec, string, error) {
	out := make([]embeddedVec, len(texts))
	for i, t := range texts {
		out[i] = embeddedVec{Dense: bagOfWordsVector(t)}
	}
	return out, "parity-v1", nil
}

// TestEmbedEmbedBatchDenseParity locks the dense-parity invariant: for the SAME input,
// a single Embed and the batched EmbedBatch return identical dense vectors (same model
// label, same length, element-for-element equal). It also checks EmbedBatch's
// structural contract: one non-empty vector per input, in order.
func TestEmbedEmbedBatchDenseParity(t *testing.T) {
	emb := parityEmbedder{}
	texts := []string{
		"firewall nftables egress gateway",
		"task worktree branch lock dispatch agent",
		"embedding vector cosine search index chunk",
		"", // an empty text still embeds (the zero bag-of-words vector) — parity must hold
	}

	batch, batchModel, err := emb.EmbedBatch(context.Background(), texts)
	if err != nil {
		t.Fatalf("EmbedBatch: %v", err)
	}
	// Equal-length / order-preserving invariant.
	if len(batch) != len(texts) {
		t.Fatalf("EmbedBatch returned %d vectors for %d inputs", len(batch), len(texts))
	}

	for i, text := range texts {
		single, singleModel, err := emb.Embed(context.Background(), text)
		if err != nil {
			t.Fatalf("Embed(%q): %v", text, err)
		}
		if singleModel != batchModel {
			t.Errorf("text %d: model label mismatch — Embed %q, EmbedBatch %q", i, singleModel, batchModel)
		}
		dense := batch[i].Dense
		// The bag-of-words vector is fixed-width, so even the empty text yields a
		// non-empty (all-zero) dense vector — the non-empty invariant holds.
		if len(dense) == 0 {
			t.Errorf("text %d: EmbedBatch dense is empty (violates the non-empty invariant)", i)
		}
		if len(dense) != len(single) {
			t.Fatalf("text %d: dense width Embed=%d EmbedBatch=%d", i, len(single), len(dense))
		}
		for j := range single {
			if dense[j] != single[j] {
				t.Errorf("text %d dim %d: Embed=%v EmbedBatch=%v (dense parity broken)", i, j, single[j], dense[j])
			}
		}
	}
}

// divergentSeamEmbedder deliberately VIOLATES the dense-parity invariant: its Embed
// and EmbedBatch return DIFFERENT dense vectors for the same text (the batch seam adds
// a marker bias to dim 0). It is the adversarial fixture for the behavior shift the
// hybrid-score-normalization unit flagged — embedQueryHybrid routes a batch-capable
// embedder's query DENSE through tryBatch(1-element EmbedBatch) rather than Embed, so a
// query embedded by a divergent embedder would no longer match a chunk dense produced
// by the Embed seam. The contract (see batchEmbedder in embeddings_batch.go) forbids
// this; the test below proves the divergence is OBSERVABLE so a future embedder that
// breaks parity can be caught, and that for a CONFORMANT same-model embedder the routed
// dense leg matches Embed byte-for-byte.
type divergentSeamEmbedder struct{}

func (divergentSeamEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	return bagOfWordsVector(text), "divergent-v1", nil
}

func (divergentSeamEmbedder) EmbedBatch(_ context.Context, texts []string) ([]embeddedVec, string, error) {
	out := make([]embeddedVec, len(texts))
	for i, t := range texts {
		v := bagOfWordsVector(t)
		if len(v) > 0 {
			v[0] += 1.0 // the batch seam disagrees with Embed on dim 0
		}
		out[i] = embeddedVec{Dense: v}
	}
	return out, "divergent-v1", nil
}

// TestEmbedQueryHybridDenseParity locks the unit's part-(B) acceptance directly on the
// read path: embedQueryHybrid (which semanticSearch uses to embed the QUERY) routes a
// batch-capable embedder's dense leg through the EmbedBatch seam. For a CONFORMANT
// same-model embedder (parityEmbedder, whose two seams agree) the dense vector
// embedQueryHybrid returns MUST equal what Embed returns for the same text — element
// for element — so query-vs-chunk cosine compares vectors from one embedding function.
// The adversarial divergentSeamEmbedder then proves the invariant is real and testable:
// its query dense (from EmbedBatch) deliberately DIFFERS from Embed, which is exactly
// the silent mis-rank the contract forbids.
func TestEmbedQueryHybridDenseParity(t *testing.T) {
	ctx := context.Background()
	texts := []string{
		"firewall nftables egress gateway",
		"task worktree branch lock dispatch agent",
		"", // empty text still embeds the fixed-width zero vector
	}

	// Conformant: embedQueryHybrid's dense leg (routed through EmbedBatch) matches Embed.
	conformant := parityEmbedder{}
	for _, text := range texts {
		hybridDense, _, hybridModel, err := embedQueryHybrid(ctx, conformant, text)
		if err != nil {
			t.Fatalf("embedQueryHybrid(%q): %v", text, err)
		}
		single, singleModel, err := conformant.Embed(ctx, text)
		if err != nil {
			t.Fatalf("Embed(%q): %v", text, err)
		}
		if hybridModel != singleModel {
			t.Errorf("model mismatch for %q: embedQueryHybrid %q, Embed %q", text, hybridModel, singleModel)
		}
		if len(hybridDense) != len(single) {
			t.Fatalf("dense width mismatch for %q: embedQueryHybrid=%d Embed=%d", text, len(hybridDense), len(single))
		}
		for j := range single {
			if hybridDense[j] != single[j] {
				t.Errorf("text %q dim %d: embedQueryHybrid dense=%v, Embed dense=%v — parity broken on the query read path",
					text, j, hybridDense[j], single[j])
			}
		}
	}

	// Adversarial: a divergent embedder's query dense (from EmbedBatch via
	// embedQueryHybrid) MUST differ from Embed on dim 0 — the observable signature of a
	// parity violation. If this ever stopped differing, the divergence fixture (or the
	// routing) would be broken and the parity guarantee untestable.
	divergent := divergentSeamEmbedder{}
	const probe = "firewall nftables egress gateway"
	hybridDense, _, _, err := embedQueryHybrid(ctx, divergent, probe)
	if err != nil {
		t.Fatalf("embedQueryHybrid(divergent): %v", err)
	}
	single, _, err := divergent.Embed(ctx, probe)
	if err != nil {
		t.Fatalf("Embed(divergent): %v", err)
	}
	if len(hybridDense) == 0 || len(single) == 0 {
		t.Fatal("expected non-empty dense vectors")
	}
	if hybridDense[0] == single[0] {
		t.Errorf("divergent embedder: embedQueryHybrid dim0=%v equals Embed dim0=%v — the parity-violation fixture is not actually diverging",
			hybridDense[0], single[0])
	}
}
