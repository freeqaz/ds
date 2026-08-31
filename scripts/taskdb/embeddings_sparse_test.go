// SPDX-License-Identifier: Apache-2.0
package main

// Hermetic tests for the SPARSE vector wire shape + EmbedBatch interface widening +
// chunk_embeddings cache extension (the bgem3w1 sparse-wire-and-cache unit). No
// network, no model, no live API: every embedder here is an in-process Go fake and
// every blob is round-tripped through the pure-Go pack/unpack helpers.
//
// Coverage maps to the unit's acceptance gate:
//   - TestSparseRoundTrip: encodeSparse/decodeSparse round-trip an int-keyed map.
//   - TestDecodeSparseRejectsCorruptLength: a non-multiple-of-8 blob is rejected
//     LOUDLY (the same discipline decodeVector applies to the dense blob).
//   - TestDecodeBatchResponseLegacyDenseOnly: the widened EmbedBatch decoder accepts
//     a legacy dense-only [[...]] response with Sparse==nil — NO contract break.
//   - TestDecodeBatchResponseHybrid: it ALSO accepts a [{dense,sparse}] response and
//     populates the int-keyed Sparse map.
//   - TestDecodeBatchResponseMixedAndCorrupt: malformed elements are parse errors
//     (which the embedChunks path turns into the loud per-chunk fallback).
//   - TestCmdBatchEmbedderDecodesBothShapes: the FULL cmdBatchEmbedder seam decodes
//     both wire shapes end-to-end via a tiny inline script (no live model).
//   - TestSparseBatchEmbedderNoContractBreak: a hybrid batch embedder still satisfies
//     the equal-length / non-empty / loud-fallback invariant through embedChunks.
//   - TestEmbeddingsMigrationIdempotentWithSparseColumns: the widened
//     ensureEmbeddingsSchema is idempotent across repeated calls on a pre-existing
//     dense-only cache, and the new sparse columns are present and NULLable.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSparseRoundTrip: an int-keyed term-weight map survives encode → decode
// byte-for-byte. Includes a large token id (exercising the uint32 width) and a
// zero-weight entry (a legal sparse term).
func TestSparseRoundTrip(t *testing.T) {
	in := map[int]float32{
		0:      1.0,
		7:      0.5,
		42:     -2.25,
		1000:   3.14159,
		250101: 1e-7,
		999983: 0.0,
	}
	out, err := decodeSparse(encodeSparse(in))
	if err != nil {
		t.Fatalf("decodeSparse: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("len = %d, want %d", len(out), len(in))
	}
	for k, v := range in {
		if out[k] != v {
			t.Errorf("sparse[%d] = %v, want %v", k, out[k], v)
		}
	}

	// A nil/empty map encodes to a zero-length blob and decodes to an empty (non-nil)
	// map — a valid empty sparse vector, not an error.
	empty := encodeSparse(nil)
	if len(empty) != 0 {
		t.Errorf("encodeSparse(nil) = %d bytes, want 0", len(empty))
	}
	back, err := decodeSparse(empty)
	if err != nil {
		t.Fatalf("decodeSparse(empty): %v", err)
	}
	if back == nil || len(back) != 0 {
		t.Errorf("decodeSparse(empty) = %v, want a non-nil empty map", back)
	}
}

// TestDecodeSparseRejectsCorruptLength: a blob whose length is not a multiple of the
// 8-byte entry width is corrupt/foreign and is rejected LOUDLY rather than silently
// truncated, mirroring decodeVector's not-a-multiple-of-4 guard.
func TestDecodeSparseRejectsCorruptLength(t *testing.T) {
	// 8 bytes = one clean entry; 8+3 = corrupt.
	good := encodeSparse(map[int]float32{5: 1.0})
	if len(good) != sparseEntryBytes {
		t.Fatalf("one entry = %d bytes, want %d", len(good), sparseEntryBytes)
	}
	corrupt := append(append([]byte{}, good...), 1, 2, 3)
	if _, err := decodeSparse(corrupt); err == nil {
		t.Error("decodeSparse accepted a non-multiple-of-8 blob, want a loud error")
	}
	// A few short lengths, each not a multiple of 8.
	for _, n := range []int{1, 3, 7, 9, 15} {
		if _, err := decodeSparse(make([]byte, n)); err == nil {
			t.Errorf("decodeSparse(%d-byte blob) accepted a corrupt length, want error", n)
		}
	}
}

// TestDecodeBatchResponseLegacyDenseOnly: the widened decoder accepts the LEGACY
// bare array-of-float-arrays response (the offline embed.py / existing-embedder
// shape) and yields embeddedVec with Sparse==nil — NO contract break.
func TestDecodeBatchResponseLegacyDenseOnly(t *testing.T) {
	const legacy = `[[0.1, 0.2, 0.3], [1.0, -1.0]]`
	vecs, err := decodeBatchResponse([]byte(legacy))
	if err != nil {
		t.Fatalf("decodeBatchResponse(legacy): %v", err)
	}
	if len(vecs) != 2 {
		t.Fatalf("len = %d, want 2", len(vecs))
	}
	if len(vecs[0].Dense) != 3 || vecs[0].Dense[0] != 0.1 {
		t.Errorf("dense[0] = %v, want [0.1 0.2 0.3]", vecs[0].Dense)
	}
	for i, v := range vecs {
		if v.Sparse != nil {
			t.Errorf("legacy dense-only vec[%d].Sparse = %v, want nil", i, v.Sparse)
		}
	}
}

// TestDecodeBatchResponseHybrid: the decoder ALSO accepts the new {dense,sparse}
// object shape and populates an int-keyed Sparse map. A hybrid object with no
// "sparse" key (or an empty one) decodes to Sparse==nil, identical to the legacy
// shape.
func TestDecodeBatchResponseHybrid(t *testing.T) {
	const hybrid = `[
		{"dense": [0.1, 0.2], "sparse": {"5": 0.7, "100": 1.5}},
		{"dense": [0.3, 0.4], "sparse": {}},
		{"dense": [0.5, 0.6]}
	]`
	vecs, err := decodeBatchResponse([]byte(hybrid))
	if err != nil {
		t.Fatalf("decodeBatchResponse(hybrid): %v", err)
	}
	if len(vecs) != 3 {
		t.Fatalf("len = %d, want 3", len(vecs))
	}
	// First: dense + a populated int-keyed sparse map.
	if len(vecs[0].Dense) != 2 || vecs[0].Dense[1] != 0.2 {
		t.Errorf("dense[0] = %v, want [0.1 0.2]", vecs[0].Dense)
	}
	if vecs[0].Sparse[5] != 0.7 || vecs[0].Sparse[100] != 1.5 {
		t.Errorf("sparse[0] = %v, want {5:0.7 100:1.5}", vecs[0].Sparse)
	}
	// Second: explicit empty sparse object → Sparse nil (no terms).
	if vecs[1].Sparse != nil {
		t.Errorf("empty sparse object should decode to nil, got %v", vecs[1].Sparse)
	}
	// Third: no sparse key at all → Sparse nil, dense intact.
	if vecs[2].Sparse != nil || len(vecs[2].Dense) != 2 {
		t.Errorf("sparse-less object: dense=%v sparse=%v", vecs[2].Dense, vecs[2].Sparse)
	}
}

// TestDecodeBatchResponseMixedAndCorrupt: malformed responses are parse errors (the
// embedChunks path turns these into the loud per-chunk fallback). A non-array, a
// non-integer sparse key, and a non-object/non-array element are all rejected.
func TestDecodeBatchResponseMixedAndCorrupt(t *testing.T) {
	cases := map[string]string{
		"not an array":           `{"dense": [1]}`,
		"non-integer sparse key": `[{"dense": [1.0], "sparse": {"abc": 0.5}}]`,
		"scalar element":         `[1.0, 2.0]`,
		"null element":           `[null]`,
	}
	for name, body := range cases {
		if _, err := decodeBatchResponse([]byte(body)); err == nil {
			t.Errorf("%s: decodeBatchResponse accepted a malformed payload, want error", name)
		}
	}

	// A MIXED array (legacy dense element next to a hybrid object) is still accepted —
	// each element is shape-detected independently, so a heterogeneous response is not
	// itself an error.
	const mixed = `[[0.1, 0.2], {"dense": [0.3], "sparse": {"9": 1.0}}]`
	vecs, err := decodeBatchResponse([]byte(mixed))
	if err != nil {
		t.Fatalf("mixed legacy+hybrid: %v", err)
	}
	if len(vecs) != 2 || vecs[0].Sparse != nil || vecs[1].Sparse[9] != 1.0 {
		t.Errorf("mixed decode wrong: %+v", vecs)
	}
}

// hybridBatchEmbedder is a fake that implements batchEmbedder and returns the NEW
// {Dense,Sparse} shape directly (sparse is a deterministic single term per text), so
// the widened return threads through embedChunks without a contract break. Its
// per-chunk Embed is dense-only (the Embedder seam carries no sparse), so a fallback
// still produces a correct dense index.
type hybridBatchEmbedder struct {
	batch int
	calls int
}

func (e *hybridBatchEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	if text != embedProbe {
		e.calls++
	}
	return bagOfWordsVector(text), "hybrid-v1", nil
}

func (e *hybridBatchEmbedder) EmbedBatch(_ context.Context, texts []string) ([]embeddedVec, string, error) {
	e.batch++
	out := make([]embeddedVec, len(texts))
	for i, t := range texts {
		out[i] = embeddedVec{
			Dense:  bagOfWordsVector(t),
			Sparse: map[int]float32{len(t): 1.0}, // a deterministic single sparse term
		}
	}
	return out, "hybrid-v1", nil
}

// TestSparseBatchEmbedderNoContractBreak: a hybrid batch embedder (carrying sparse)
// still satisfies the equal-length / non-empty / loud-fallback invariant through
// embedChunks — the dense index is filled exactly once via the batch path, in order,
// and ranks correctly. The sparse payload rides along on the wire without disturbing
// the dense cache this unit persists.
func TestSparseBatchEmbedderNoContractBreak(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/04.md", "Networking", "nftables firewall egress gateway proxy networking")
	seedChunk(t, db, "docs/22.md", "Worktrees", "task worktree branch lock dispatch agent")
	seedChunk(t, db, "docs/08.md", "Embeddings", "embedding vector cosine search index chunk")

	emb := &hybridBatchEmbedder{}
	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if res.Embedded != 3 || res.Skipped != 0 {
		t.Fatalf("embedded=%d skipped=%d, want 3/0", res.Embedded, res.Skipped)
	}
	if emb.batch != 1 {
		t.Errorf("EmbedBatch invocations = %d, want 1 (one hybrid batch for all chunks)", emb.batch)
	}
	if emb.calls != 0 {
		t.Errorf("per-chunk Embed was used for chunk text (%d); the hybrid batch should have covered it", emb.calls)
	}
	// The dense index ranks correctly through the hybrid batch.
	hits, err := semanticSearch(context.Background(), db, emb, "firewall egress nftables", 10, true)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) == 0 || hits[0].Path != "docs/04.md" {
		t.Errorf("hybrid-batched index ranks wrong; top = %s", hitTop(hits))
	}
}

// TestCmdBatchEmbedderDecodesBothShapes drives the FULL external-command batch seam
// (cmdBatchEmbedder) against BOTH wire shapes via tiny inline scripts — proving the
// documented decode end to end with NO live model. The scripts are generated in the
// test's TempDir and are stdlib-only.
func TestCmdBatchEmbedderDecodesBothShapes(t *testing.T) {
	py, err := lookPython()
	if err != nil {
		t.Skip("python3 not available for the external batch-embedder seam test")
	}

	// Legacy dense-only batch emitter: --batch reads a JSON array of strings, writes a
	// JSON array of float arrays (the pre-widening shape).
	legacyScript := filepath.Join(t.TempDir(), "legacy_batch.py")
	const legacyBody = `import sys, json
texts = json.loads(sys.stdin.read())
out = [[float(len(t)), 1.0] for t in texts]
sys.stdout.write(json.dumps(out))
`
	if err := os.WriteFile(legacyScript, []byte(legacyBody), 0o644); err != nil {
		t.Fatalf("write legacy script: %v", err)
	}

	// Hybrid emitter: writes [{dense, sparse}] objects.
	hybridScript := filepath.Join(t.TempDir(), "hybrid_batch.py")
	const hybridBody = `import sys, json
texts = json.loads(sys.stdin.read())
out = [{"dense": [float(len(t)), 2.0], "sparse": {str(len(t)): 0.9}} for t in texts]
sys.stdout.write(json.dumps(out))
`
	if err := os.WriteFile(hybridScript, []byte(hybridBody), 0o644); err != nil {
		t.Fatalf("write hybrid script: %v", err)
	}

	texts := []string{"alpha", "bravo"}

	// Legacy: decodes to dense-only, Sparse nil.
	legacy, err := newCmdEmbedder([]string{py, legacyScript})
	if err != nil {
		t.Fatalf("newCmdEmbedder(legacy): %v", err)
	}
	lv, _, err := withBatch(legacy).EmbedBatch(context.Background(), texts)
	if err != nil {
		t.Fatalf("legacy EmbedBatch: %v", err)
	}
	if len(lv) != 2 || lv[0].Dense[0] != 5.0 || lv[0].Sparse != nil {
		t.Errorf("legacy batch decode wrong: %+v", lv)
	}

	// Hybrid: decodes dense + an int-keyed sparse map.
	hybrid, err := newCmdEmbedder([]string{py, hybridScript})
	if err != nil {
		t.Fatalf("newCmdEmbedder(hybrid): %v", err)
	}
	hv, _, err := withBatch(hybrid).EmbedBatch(context.Background(), texts)
	if err != nil {
		t.Fatalf("hybrid EmbedBatch: %v", err)
	}
	if len(hv) != 2 || hv[0].Dense[1] != 2.0 || hv[0].Sparse[5] != 0.9 {
		t.Errorf("hybrid batch decode wrong: %+v (sparse=%v)", hv, hv[0].Sparse)
	}
}

// TestEmbedPyBatchEmitsHybridShape exercises the offline embed.py run_batch path
// directly (NO DS_EMBED_LIVE, NO model): it must emit the new {dense,sparse} object
// shape, dense width FALLBACK_DIMS=256, sparse empty, order-preserving. This is the
// reference embedder's half of the wire contract.
func TestEmbedPyBatchEmitsHybridShape(t *testing.T) {
	py, err := lookPython()
	if err != nil {
		t.Skip("python3 not available for the embed.py batch-shape test")
	}
	script := embedPyPath(t)

	emb, err := newCmdEmbedder([]string{py, script})
	if err != nil {
		t.Fatalf("newCmdEmbedder: %v", err)
	}
	texts := []string{"nftables firewall egress", "task worktree branch lock"}
	vecs, _, err := withBatch(emb).EmbedBatch(context.Background(), texts)
	if err != nil {
		t.Fatalf("embed.py --batch: %v", err)
	}
	if len(vecs) != 2 {
		t.Fatalf("len = %d, want 2", len(vecs))
	}
	for i, v := range vecs {
		if len(v.Dense) != 256 {
			t.Errorf("vec[%d] dense width = %d, want FALLBACK_DIMS=256 (no DS_EMBED_LIVE)", i, len(v.Dense))
		}
		// The dense-only fallback emits an empty sparse object → Sparse nil here.
		if v.Sparse != nil {
			t.Errorf("vec[%d] sparse = %v, want nil (dense-only fallback)", i, v.Sparse)
		}
	}

	// Raw stdout is the new OBJECT shape, not the legacy bare array.
	out := runEmbedPyBatch(t, py, script, texts)
	var objs []map[string]json.RawMessage
	if err := json.Unmarshal(out, &objs); err != nil {
		t.Fatalf("embed.py --batch stdout is not an array of objects: %v (%s)", err, string(out))
	}
	if len(objs) != 2 {
		t.Fatalf("got %d objects, want 2", len(objs))
	}
	if _, ok := objs[0]["dense"]; !ok {
		t.Errorf("embed.py --batch object missing a \"dense\" key: %s", string(out))
	}
	if _, ok := objs[0]["sparse"]; !ok {
		t.Errorf("embed.py --batch object missing a \"sparse\" key: %s", string(out))
	}
}

// TestEmbeddingsMigrationIdempotentWithSparseColumns: ensureEmbeddingsSchema is
// idempotent across repeated calls on a DB that already holds dense-only rows, and
// the new NULLable sparse columns are present afterwards. Extends the existing
// TestEmbeddingsMigrationIdempotent with the schema-widening assertion.
func TestEmbeddingsMigrationIdempotentWithSparseColumns(t *testing.T) {
	db := openTestDB(t) // already ran ensureEmbeddingsSchema (with the ALTER) once
	seedChunk(t, db, "docs/a.md", "Net", "nftables firewall egress gateway")

	emb := &countingEmbedder{}
	if _, err := embedChunks(context.Background(), db, emb, true); err != nil {
		t.Fatalf("embedChunks: %v", err)
	}
	var before int
	if err := db.QueryRow(`SELECT COUNT(*) FROM chunk_embeddings`).Scan(&before); err != nil {
		t.Fatalf("count: %v", err)
	}
	if before != 1 {
		t.Fatalf("seeded embeddings = %d, want 1", before)
	}
	// The pre-existing dense-only row carries NULL sparse columns (it predates them).
	var nullCols int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM chunk_embeddings WHERE sparse_vector IS NULL AND sparse_model IS NULL`,
	).Scan(&nullCols); err != nil {
		t.Fatalf("sparse-null query (columns missing?): %v", err)
	}
	if nullCols != 1 {
		t.Errorf("dense-only row should have NULL sparse columns, got %d such rows", nullCols)
	}

	// Re-run the migration twice more: no error, no row loss, no duplicate-column error.
	for i := 0; i < 2; i++ {
		if err := ensureEmbeddingsSchema(db); err != nil {
			t.Fatalf("ensureEmbeddingsSchema rerun %d (duplicate column?): %v", i, err)
		}
	}
	var after int
	if err := db.QueryRow(`SELECT COUNT(*) FROM chunk_embeddings`).Scan(&after); err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != before {
		t.Errorf("migration was not a no-op: %d rows after, %d before", after, before)
	}

	// The sparse columns are queryable (proving the ALTER landed) and still NULL.
	var hash string
	var sv []byte
	var sm interface{}
	if err := db.QueryRow(
		`SELECT chunk_hash, sparse_vector, sparse_model FROM chunk_embeddings LIMIT 1`,
	).Scan(&hash, &sv, &sm); err != nil {
		t.Fatalf("select sparse columns: %v", err)
	}
	if sv != nil || sm != nil {
		t.Errorf("sparse columns should be NULL on a dense-only row, got vector=%v model=%v", sv, sm)
	}
}

// embedPyPath resolves the in-repo embed.py for the reference-embedder tests. The
// test runs from scripts/taskdb, so embed.py is at embedder/embed.py relative to the
// package dir.
func embedPyPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("embedder", "embed.py")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("embed.py not found at %s: %v", p, err)
	}
	return p
}

// runEmbedPyBatch runs `python embed.py --batch` with texts as a JSON array on stdin
// and returns its trimmed stdout, failing the test on a non-zero exit. It execs the
// command directly so the test reads the raw bytes embed.py wrote (the cmdEmbedder
// decode is asserted separately above).
func runEmbedPyBatch(t *testing.T, py, script string, texts []string) []byte {
	t.Helper()
	in, err := json.Marshal(texts)
	if err != nil {
		t.Fatalf("marshal texts: %v", err)
	}
	cmd := exec.Command(py, script, "--batch")
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("embed.py --batch failed: %v: %s", err, stderr.String())
	}
	return bytes.TrimSpace(stdout.Bytes())
}
