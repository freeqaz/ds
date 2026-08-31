// SPDX-License-Identifier: Apache-2.0
package main

// Hermetic tests for the docs/22 §8 embeddings seam. No network, no model
// download, no live API: every embedder here is either an in-process Go fake or
// a tiny inline script writing hash-derived vectors. This is the FIRST _test.go
// in the scripts/taskdb module.
//
// Coverage maps to the unit's acceptance gate:
//   - TestSemanticSearchRanksRelevantFirst: `doc search --semantic` returns the
//     on-topic chunk ahead of off-topic ones, via the external-command embedder
//     seam (a tiny inline script emitting deterministic bag-of-words vectors).
//   - TestEmbedSkipsUnchangedHashes: a no-change re-run does NOT re-invoke the
//     embedder — asserted by a call counter on the fake embedder.
//   - TestEmbeddingsMigrationIdempotent: running ensureEmbeddingsSchema twice on
//     a populated DB is a clean no-op.
//   - Plus unit checks on cosine, vector round-trip, prune, and the model label.

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	_ "modernc.org/sqlite"
)

// openTestDB opens a throwaway file-backed sqlite DB with just the doc_chunks
// table and the embeddings cache — enough to exercise the seam without the full
// initSchema/git-repo machinery. File-backed (not :memory:) so multiple
// connections in the pool see the same data.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sqlite")
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	// Minimal doc_chunks (the embeddings seam joins on hash; rowid/seq/doc_id
	// are present to match the production shape but unused here).
	if _, err := db.Exec(`CREATE TABLE doc_chunks (
		id INTEGER PRIMARY KEY, doc_id INTEGER NOT NULL, path TEXT NOT NULL,
		heading TEXT NOT NULL DEFAULT '', seq INTEGER NOT NULL,
		body TEXT NOT NULL, hash TEXT NOT NULL)`); err != nil {
		t.Fatalf("create doc_chunks: %v", err)
	}
	if err := ensureEmbeddingsSchema(db); err != nil {
		t.Fatalf("ensureEmbeddingsSchema: %v", err)
	}
	return db
}

// seedChunk inserts one chunk, blob-hashing the body exactly as syncDocs does so
// the hash is the real content-keyed cache key.
func seedChunk(t *testing.T, db *sql.DB, path, heading, body string) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO doc_chunks(doc_id, path, heading, seq, body, hash) VALUES(?,?,?,?,?,?)`,
		1, path, heading, 0, body, gitBlobSHA([]byte(body)),
	); err != nil {
		t.Fatalf("seed chunk: %v", err)
	}
}

// bagOfWordsVector is the deterministic embedding used by the fakes: a fixed
// vocabulary, one dimension per word, count of occurrences. Two texts sharing
// vocabulary point the same way (high cosine); disjoint texts are orthogonal
// (cosine 0). This makes "relevant first" a checkable property without a model.
var fakeVocab = []string{
	"networking", "firewall", "nftables", "egress", "gateway", "proxy",
	"task", "worktree", "branch", "lock", "dispatch", "agent",
	"embedding", "vector", "cosine", "search", "index", "chunk",
}

func bagOfWordsVector(text string) []float32 {
	counts := map[string]int{}
	for _, w := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !(r >= 'a' && r <= 'z')
	}) {
		counts[w]++
	}
	v := make([]float32, len(fakeVocab))
	for i, w := range fakeVocab {
		v[i] = float32(counts[w])
	}
	return v
}

// countingEmbedder is an in-process fake that records how many times Embed is
// called for ACTUAL chunk/query text — the lever for the "unchanged hashes are
// not re-embedded" assertion. Probe embeds (the fixed embedProbe canary that
// embedChunks/semanticSearch issue once per pass to learn the active model+dims)
// are tallied separately in probes, so the chunk-embed assertions stay exact and
// independent of the probe.
type countingEmbedder struct {
	calls  atomic.Int64 // embeds of real chunk/query text
	probes atomic.Int64 // embeds of the embedProbe canary
}

func (e *countingEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	if text == embedProbe {
		e.probes.Add(1)
	} else {
		e.calls.Add(1)
	}
	return bagOfWordsVector(text), "fake-bow-v1", nil
}

// swapEmbedder is a configurable fake whose model label and vector width are set
// by the test, so two instances model an embedder SWAP: a different label is a
// config change (--embedder-cmd repointed), and a different dims models a
// same-label runtime toggle (e.g. DS_EMBED_LIVE flipping a 384-dim model to a
// 256-dim fallback). The vector is a deterministic, label-independent function of
// the text resized to dims, so the bytes a swap produces genuinely differ from
// the cached ones and a re-embed is observable end to end. calls counts only real
// chunk/query embeds; probes counts the embedProbe canary.
type swapEmbedder struct {
	label  string
	dims   int
	calls  atomic.Int64
	probes atomic.Int64
}

func (e *swapEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	if text == embedProbe {
		e.probes.Add(1)
	} else {
		e.calls.Add(1)
	}
	// A length-dims vector derived from the bag-of-words counts so identical text
	// maps to identical vectors (cache determinism) while different widths give
	// genuinely different blobs.
	bow := bagOfWordsVector(text)
	v := make([]float32, e.dims)
	for i := 0; i < e.dims; i++ {
		v[i] = bow[i%len(bow)] + float32(i%3) // spread across the wider/narrower width
	}
	return v, e.label, nil
}

func TestCosineSimilarity(t *testing.T) {
	a := []float32{1, 0, 0}
	if got := cosineSimilarity(a, a); math.Abs(got-1) > 1e-9 {
		t.Errorf("self-cosine = %v, want 1", got)
	}
	orthogonal := []float32{0, 1, 0}
	if got := cosineSimilarity(a, orthogonal); math.Abs(got) > 1e-9 {
		t.Errorf("orthogonal cosine = %v, want 0", got)
	}
	// Length mismatch and zero vectors return 0, never NaN (ranking must be
	// total).
	if got := cosineSimilarity(a, []float32{1, 0}); got != 0 {
		t.Errorf("mismatched-length cosine = %v, want 0", got)
	}
	if got := cosineSimilarity(a, []float32{0, 0, 0}); got != 0 {
		t.Errorf("zero-vector cosine = %v, want 0", got)
	}
}

func TestVectorRoundTrip(t *testing.T) {
	in := []float32{0, 1.5, -2.25, 3.14159, 1e-7}
	out, err := decodeVector(encodeVector(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("len = %d, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("v[%d] = %v, want %v", i, out[i], in[i])
		}
	}
	if _, err := decodeVector([]byte{1, 2, 3}); err == nil {
		t.Error("decodeVector accepted a non-multiple-of-4 blob, want error")
	}
}

// TestEmbeddingsMigrationIdempotent: running the migration twice on a populated
// DB is a clean no-op — no error, no row loss. (Acceptance gate item.)
func TestEmbeddingsMigrationIdempotent(t *testing.T) {
	db := openTestDB(t) // already ran ensureEmbeddingsSchema once
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

	// Re-run the migration twice more; it must not error and must not touch rows.
	for i := 0; i < 2; i++ {
		if err := ensureEmbeddingsSchema(db); err != nil {
			t.Fatalf("ensureEmbeddingsSchema rerun %d: %v", i, err)
		}
	}
	var after int
	if err := db.QueryRow(`SELECT COUNT(*) FROM chunk_embeddings`).Scan(&after); err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != before {
		t.Errorf("migration was not a no-op: %d rows after, %d before", after, before)
	}
}

// TestEmbedSkipsUnchangedHashes: a second embed pass over an UNCHANGED corpus
// invokes the embedder ZERO times — the seam's defining property. (Acceptance
// gate item: assert the invocation count after a no-change re-run.)
func TestEmbedSkipsUnchangedHashes(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/net.md", "Networking", "nftables firewall egress gateway proxy")
	seedChunk(t, db, "docs/task.md", "Tasks", "task worktree branch lock dispatch agent")

	emb := &countingEmbedder{}
	res1, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("first embed: %v", err)
	}
	if res1.Embedded != 2 || res1.Skipped != 0 {
		t.Fatalf("first pass: embedded=%d skipped=%d, want 2/0", res1.Embedded, res1.Skipped)
	}
	if got := emb.calls.Load(); got != 2 {
		t.Fatalf("first pass embedder calls = %d, want 2", got)
	}

	// Re-run with NO chunk changes: zero new invocations, all skipped.
	res2, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("second embed: %v", err)
	}
	if res2.Embedded != 0 || res2.Skipped != 2 {
		t.Errorf("no-change re-run: embedded=%d skipped=%d, want 0/2", res2.Embedded, res2.Skipped)
	}
	if got := emb.calls.Load(); got != 2 {
		t.Errorf("embedder was re-invoked on unchanged chunks: total calls = %d, want still 2", got)
	}

	// Edit one chunk's body (new hash) — ONLY the changed chunk re-embeds.
	if _, err := db.Exec(`UPDATE doc_chunks SET body=?, hash=? WHERE path='docs/net.md'`,
		"embedding vector cosine search index chunk", gitBlobSHA([]byte("embedding vector cosine search index chunk"))); err != nil {
		t.Fatalf("edit chunk: %v", err)
	}
	res3, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("third embed: %v", err)
	}
	if res3.Embedded != 1 || res3.Skipped != 1 {
		t.Errorf("after one edit: embedded=%d skipped=%d, want 1/1", res3.Embedded, res3.Skipped)
	}
	if got := emb.calls.Load(); got != 3 {
		t.Errorf("after one edit, total embedder calls = %d, want 3 (only the changed chunk)", got)
	}
	// The stale embedding for the old hash was pruned (prune=true): exactly one
	// row per current chunk hash.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM chunk_embeddings`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("cache rows = %d, want 2 (stale row pruned)", n)
	}
}

// TestEmbedDeduplicatesIdenticalHashes: the same text under two chunks embeds
// once (the embedder cost tracks unique content, the doc's stated property).
func TestEmbedDeduplicatesIdenticalHashes(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "H1", "task worktree branch lock")
	seedChunk(t, db, "docs/b.md", "H2", "task worktree branch lock") // identical body

	emb := &countingEmbedder{}
	res, err := embedChunks(context.Background(), db, emb, true)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if res.Embedded != 1 {
		t.Errorf("embedded = %d, want 1 (identical bodies share a hash)", res.Embedded)
	}
	if got := emb.calls.Load(); got != 1 {
		t.Errorf("embedder calls = %d, want 1", got)
	}
}

// TestSemanticSearchRanksRelevantFirstCore drives the ranking core directly with
// a Go fake, proving relevant chunks outrank off-topic ones.
func TestSemanticSearchRanksRelevantFirstCore(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/04.md", "Networking", "nftables firewall egress gateway proxy networking")
	seedChunk(t, db, "docs/22.md", "Worktrees", "task worktree branch lock dispatch agent")
	seedChunk(t, db, "docs/08.md", "Embeddings", "embedding vector cosine search index chunk")

	emb := &countingEmbedder{}
	if _, err := embedChunks(context.Background(), db, emb, true); err != nil {
		t.Fatalf("embed: %v", err)
	}

	hits, err := semanticSearch(context.Background(), db, emb, "firewall egress nftables", 10, true)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("no hits")
	}
	if hits[0].Path != "docs/04.md" {
		t.Errorf("top hit = %s (%.3f), want docs/04.md; full ranking: %s",
			hits[0].Path, hits[0].Score, formatHits(hits))
	}
	// Scores are sorted descending.
	for i := 1; i < len(hits); i++ {
		if hits[i].Score > hits[i-1].Score {
			t.Errorf("ranking not descending at %d: %.3f > %.3f", i, hits[i].Score, hits[i-1].Score)
		}
	}
	// The on-topic chunk scores strictly above the unrelated embeddings chunk.
	if hits[0].Score <= scoreFor(hits, "docs/08.md") {
		t.Errorf("relevant chunk did not outrank unrelated: %s", formatHits(hits))
	}
}

// TestSemanticSearchViaExternalEmbedderCmd exercises the FULL external-command
// embedder seam (cmdEmbedder): a tiny inline python script that emits
// hash-derived bag-of-words vectors on stdout. This proves the documented wire
// shape (text on stdin, JSON float array on stdout) and relevant-first ranking
// end to end, with NO live model — the script is generated in the test's
// TempDir and is stdlib-only.
func TestSemanticSearchViaExternalEmbedderCmd(t *testing.T) {
	py, err := lookPython()
	if err != nil {
		t.Skip("python3 not available for the external-embedder seam test")
	}

	db := openTestDB(t)
	seedChunk(t, db, "docs/04.md", "Networking", "nftables firewall egress gateway proxy")
	seedChunk(t, db, "docs/22.md", "Worktrees", "task worktree branch lock dispatch agent")

	// A self-contained, deterministic embedder: same vocabulary as the Go fake,
	// so a query of networking words scores the networking chunk highest.
	script := filepath.Join(t.TempDir(), "fake_embed.py")
	const body = `import sys, json, re
VOCAB = ["networking","firewall","nftables","egress","gateway","proxy",
         "task","worktree","branch","lock","dispatch","agent",
         "embedding","vector","cosine","search","index","chunk"]
text = sys.stdin.read().lower()
words = re.findall(r"[a-z]+", text)
counts = {}
for w in words:
    counts[w] = counts.get(w, 0) + 1
vec = [float(counts.get(w, 0)) for w in VOCAB]
sys.stdout.write(json.dumps(vec))
`
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}

	emb, err := newCmdEmbedder([]string{py, script})
	if err != nil {
		t.Fatalf("newCmdEmbedder: %v", err)
	}
	if _, err := embedChunks(context.Background(), db, emb, true); err != nil {
		t.Fatalf("embed via cmd: %v", err)
	}
	hits, err := semanticSearch(context.Background(), db, emb, "firewall nftables egress", 10, true)
	if err != nil {
		t.Fatalf("search via cmd: %v", err)
	}
	if len(hits) == 0 || hits[0].Path != "docs/04.md" {
		t.Errorf("external-embedder ranking wrong; top = %v, full: %s",
			hitTop(hits), formatHits(hits))
	}
	// The stored model label is the argv string, so a config swap is detectable.
	var model string
	if err := db.QueryRow(`SELECT model FROM chunk_embeddings LIMIT 1`).Scan(&model); err != nil {
		t.Fatalf("model: %v", err)
	}
	if !strings.Contains(model, "fake_embed.py") {
		t.Errorf("model label = %q, want it to name the embedder command", model)
	}
}

// TestCmdEmbedderRejectsBadOutput: a command emitting non-JSON is a loud error,
// not a silent empty index.
func TestCmdEmbedderRejectsBadOutput(t *testing.T) {
	emb := &cmdEmbedder{argv: []string{"true"}, modelLabel: "true"} // emits nothing
	_, _, err := emb.Embed(context.Background(), "hello")
	if err == nil {
		t.Error("expected an error for empty/non-JSON embedder output")
	}
}

func TestNewCmdEmbedderRejectsEmpty(t *testing.T) {
	if _, err := newCmdEmbedder(nil); err == nil {
		t.Error("newCmdEmbedder(nil) should error (no --embedder-cmd)")
	}
}

// --- model-swap detection (this unit's deliverables) ---

// TestEmbedReembedsOnLabelSwap: a second pass under a DIFFERENT model label
// re-embeds every cached chunk (a config swap, --embedder-cmd repointed) and
// reports the re-embeds as model-swap-driven. The unchanged-text/unchanged-model
// no-op property must NOT fire across a label change.
func TestEmbedReembedsOnLabelSwap(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/net.md", "Networking", "nftables firewall egress gateway proxy")
	seedChunk(t, db, "docs/task.md", "Tasks", "task worktree branch lock dispatch agent")

	// Pass 1 under model "alpha".
	alpha := &swapEmbedder{label: "alpha", dims: 18}
	res1, err := embedChunks(context.Background(), db, alpha, true)
	if err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	if res1.Embedded != 2 || res1.Reembedded != 0 {
		t.Fatalf("pass 1: embedded=%d reembedded=%d, want 2/0", res1.Embedded, res1.Reembedded)
	}
	if got := alpha.calls.Load(); got != 2 {
		t.Fatalf("pass 1 chunk embeds = %d, want 2", got)
	}

	// Pass 2: SAME corpus, SAME dims, but a DIFFERENT label → full re-embed,
	// every re-embed flagged as model-swap-driven, nothing skipped.
	beta := &swapEmbedder{label: "beta", dims: 18}
	res2, err := embedChunks(context.Background(), db, beta, true)
	if err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if res2.Embedded != 2 || res2.Skipped != 0 {
		t.Errorf("label swap: embedded=%d skipped=%d, want 2/0 (all stale)", res2.Embedded, res2.Skipped)
	}
	if res2.Reembedded != 2 {
		t.Errorf("label swap: reembedded=%d, want 2 (both driven by the swap)", res2.Reembedded)
	}
	if res2.Model != "beta" || res2.Dims != 18 {
		t.Errorf("result signature = (%q,%d), want (beta,18)", res2.Model, res2.Dims)
	}
	// Every cache row is now keyed to the new label.
	var stillAlpha int
	if err := db.QueryRow(`SELECT COUNT(*) FROM chunk_embeddings WHERE model != 'beta'`).Scan(&stillAlpha); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stillAlpha != 0 {
		t.Errorf("%d cache rows still under the old model after a swap, want 0", stillAlpha)
	}

	// Pass 3: re-run under beta with NO change → clean no-op (the seam's property
	// still holds within a single embedder).
	res3, err := embedChunks(context.Background(), db, beta, true)
	if err != nil {
		t.Fatalf("pass 3: %v", err)
	}
	if res3.Embedded != 0 || res3.Skipped != 2 || res3.Reembedded != 0 {
		t.Errorf("same-model re-run: embedded=%d skipped=%d reembedded=%d, want 0/2/0",
			res3.Embedded, res3.Skipped, res3.Reembedded)
	}
}

// TestEmbedReembedsOnDimsSwap: the SAME label but a DIFFERENT vector width (the
// DS_EMBED_LIVE toggle: 384-dim model vs 256-dim fallback under one argv) is also
// a stale cache. The probe learns the active width, so every row re-embeds even
// though the label is unchanged.
func TestEmbedReembedsOnDimsSwap(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "embedding vector cosine search index chunk")
	seedChunk(t, db, "docs/b.md", "B", "task worktree branch lock dispatch agent")

	// Pass 1: label "local", width 384.
	wide := &swapEmbedder{label: "local", dims: 384}
	if _, err := embedChunks(context.Background(), db, wide, true); err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	var dims1 int
	if err := db.QueryRow(`SELECT dims FROM chunk_embeddings LIMIT 1`).Scan(&dims1); err != nil {
		t.Fatalf("dims: %v", err)
	}
	if dims1 != 384 {
		t.Fatalf("pass 1 stored dims = %d, want 384", dims1)
	}

	// Pass 2: SAME label "local", width 256 (the toggle) → full re-embed, all
	// model-swap-driven, and the stored dims move to 256.
	narrow := &swapEmbedder{label: "local", dims: 256}
	res2, err := embedChunks(context.Background(), db, narrow, true)
	if err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if res2.Embedded != 2 || res2.Skipped != 0 || res2.Reembedded != 2 {
		t.Errorf("dims swap under same label: embedded=%d skipped=%d reembedded=%d, want 2/0/2",
			res2.Embedded, res2.Skipped, res2.Reembedded)
	}
	var wideLeft int
	if err := db.QueryRow(`SELECT COUNT(*) FROM chunk_embeddings WHERE dims != 256`).Scan(&wideLeft); err != nil {
		t.Fatalf("count: %v", err)
	}
	if wideLeft != 0 {
		t.Errorf("%d rows still at the old width after a dims swap, want 0", wideLeft)
	}
}

// TestEmbedOptOutLeavesStaleVectors: the explicit OFF switch
// (reembedOnModelChange=false) preserves the pre-swap-detection behavior — a hash
// already cached under ANY model is skipped, so a swap leaves stale vectors in
// place this pass. Default-correct, opt-out only.
func TestEmbedOptOutLeavesStaleVectors(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/a.md", "A", "nftables firewall egress gateway")

	alpha := &swapEmbedder{label: "alpha", dims: 18}
	if _, err := embedChunksOpts(context.Background(), db, alpha, true, true); err != nil {
		t.Fatalf("pass 1: %v", err)
	}

	// Swap the embedder but OPT OUT of healing: the stale row survives untouched.
	beta := &swapEmbedder{label: "beta", dims: 18}
	res, err := embedChunksOpts(context.Background(), db, beta, true, false)
	if err != nil {
		t.Fatalf("pass 2 (opt-out): %v", err)
	}
	if res.Embedded != 0 || res.Skipped != 1 || res.Reembedded != 0 {
		t.Errorf("opt-out across swap: embedded=%d skipped=%d reembedded=%d, want 0/1/0",
			res.Embedded, res.Skipped, res.Reembedded)
	}
	var model string
	if err := db.QueryRow(`SELECT model FROM chunk_embeddings LIMIT 1`).Scan(&model); err != nil {
		t.Fatalf("model: %v", err)
	}
	if model != "alpha" {
		t.Errorf("opt-out should leave the stale row under %q, got %q", "alpha", model)
	}
}

// TestSemanticSearchLoudOnStaleRows: searching with an embedder DIFFERENT from
// the one that filled the cache must be LOUD (a warning to embedWarnOut naming
// the count and `taskdb doc embed`) and must EXCLUDE the stale rows from ranking
// — never the old silent cosine-0 down-rank. This is the no-silent-0 deliverable.
func TestSemanticSearchLoudOnStaleRows(t *testing.T) {
	db := openTestDB(t)
	seedChunk(t, db, "docs/net.md", "Networking", "nftables firewall egress gateway proxy")
	seedChunk(t, db, "docs/task.md", "Tasks", "task worktree branch lock dispatch agent")

	// Fill the cache under "alpha".
	alpha := &swapEmbedder{label: "alpha", dims: 18}
	if _, err := embedChunks(context.Background(), db, alpha, true); err != nil {
		t.Fatalf("embed: %v", err)
	}

	// Search under a DIFFERENT model without re-embedding first: every cached row
	// is stale relative to "beta".
	var warn strings.Builder
	restore := swapWarnOut(&warn)
	defer restore()

	beta := &swapEmbedder{label: "beta", dims: 18}
	hits, err := semanticSearch(context.Background(), db, beta, "firewall egress nftables", 10, true)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	// Stale rows are EXCLUDED, not scored 0 — so there are no phantom hits.
	if len(hits) != 0 {
		t.Errorf("stale rows surfaced as hits (%s); want them excluded from ranking", formatHits(hits))
	}
	// The warning fired, names the count, and directs to the heal command.
	w := warn.String()
	if w == "" {
		t.Fatal("semantic search over a swapped index was SILENT; want a loud stale-embedding warning")
	}
	if !strings.Contains(w, "2") {
		t.Errorf("warning did not report the stale count: %q", w)
	}
	if !strings.Contains(w, "doc embed") {
		t.Errorf("warning did not direct to `taskdb doc embed`: %q", w)
	}

	// After re-embedding under beta, the SAME search is quiet and ranks correctly.
	if _, err := embedChunks(context.Background(), db, beta, true); err != nil {
		t.Fatalf("re-embed under beta: %v", err)
	}
	warn.Reset()
	hits2, err := semanticSearch(context.Background(), db, beta, "firewall egress nftables", 10, true)
	if err != nil {
		t.Fatalf("search after heal: %v", err)
	}
	if warn.String() != "" {
		t.Errorf("search after heal still warned: %q", warn.String())
	}
	if len(hits2) == 0 || hits2[0].Path != "docs/net.md" {
		t.Errorf("healed search ranking wrong: %s", formatHits(hits2))
	}
}

// swapWarnOut redirects the loud stale-embedding warning to a buffer for the
// duration of a test and returns a restore func. (embedWarnOut is a package var
// so the warning is assertable without capturing the process's real stderr.)
func swapWarnOut(w io.Writer) func() {
	prev := embedWarnOut
	embedWarnOut = w
	return func() { embedWarnOut = prev }
}

// --- small test helpers ---

func formatHits(hits []*semanticHit) string {
	parts := make([]string, len(hits))
	for i, h := range hits {
		parts[i] = fmt.Sprintf("%s:%s=%.3f", h.Path, h.Heading, h.Score)
	}
	return strings.Join(parts, " ")
}

func hitTop(hits []*semanticHit) string {
	if len(hits) == 0 {
		return "(none)"
	}
	return hits[0].Path
}

func scoreFor(hits []*semanticHit, path string) float64 {
	for _, h := range hits {
		if h.Path == path {
			return h.Score
		}
	}
	return -1
}

// lookPython finds a python3 interpreter for the external-embedder test,
// preferring python3 then python. Returns an error if neither resolves so the
// test SKIPs (hermetic: no python on the box just means the cmd-seam test is
// skipped — the Go-fake ranking test still runs and covers the seam).
func lookPython() (string, error) {
	for _, c := range []string{"python3", "python"} {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}

// --- persist-hybrid-sparse unit: sparse persistence + hybrid rank ----------------
//
// These tests cover the bgem3w4 persist-hybrid-sparse unit: the embedChunks UPSERT
// now writes sparse_vector/sparse_model (clearing them to NULL for a dense-only
// re-embed), and semanticSearch adds a sparse-lexical-dot leg on top of dense-cosine.
// Every embedder is an in-process Go fake — no live model, network, or GPU.

// sparseControlEmbedder is a fully in-process hybrid embedder whose SPARSE output is
// driven by a per-text function the test supplies, so a test can place an exact
// lexical term on a chosen chunk (and on the query) and assert the resulting rank.
// It implements BOTH seams: Embed (dense-only — used for the embedProbe canary and
// as the per-chunk fallback) and EmbedBatch (dense + the controlled sparse). When
// denseOnly is set EmbedBatch emits Sparse:nil, modelling a dense-only re-embed that
// must CLEAR any previously-persisted sparse. Dense is the bag-of-words vector so the
// dense-cosine base score is the same deterministic property the other tests rely on.
type sparseControlEmbedder struct {
	label     string
	sparseFor func(text string) map[int]float32 // nil-safe; may return nil
	denseOnly bool                              // when true, EmbedBatch emits Sparse:nil
}

func (e *sparseControlEmbedder) modelLabel() string {
	if e.label == "" {
		return "sparse-ctl-v1"
	}
	return e.label
}

func (e *sparseControlEmbedder) Embed(_ context.Context, text string) ([]float32, string, error) {
	// Dense-only seam (probe + fallback): no sparse here by the Embedder contract.
	return bagOfWordsVector(text), e.modelLabel(), nil
}

func (e *sparseControlEmbedder) EmbedBatch(_ context.Context, texts []string) ([]embeddedVec, string, error) {
	out := make([]embeddedVec, len(texts))
	for i, t := range texts {
		ev := embeddedVec{Dense: bagOfWordsVector(t)}
		if !e.denseOnly && e.sparseFor != nil {
			ev.Sparse = e.sparseFor(t)
		}
		out[i] = ev
	}
	return out, e.modelLabel(), nil
}

// readSparse reads back the persisted (sparse_vector, sparse_model) for a hash. A
// NULL sparse_vector decodes to nil (the dense-only / cleared state); a non-NULL blob
// round-trips through decodeSparse so the assertion is on the in-process map, not raw
// bytes.
func readSparse(t *testing.T, db *sql.DB, hash string) (map[int]float32, string, bool) {
	t.Helper()
	var blob []byte
	var model sql.NullString
	err := db.QueryRow(
		`SELECT sparse_vector, sparse_model FROM chunk_embeddings WHERE chunk_hash=?`, hash,
	).Scan(&blob, &model)
	if err == sql.ErrNoRows {
		return nil, "", false
	}
	if err != nil {
		t.Fatalf("read sparse for %s: %v", hash, err)
	}
	if blob == nil {
		return nil, model.String, true
	}
	m, err := decodeSparse(blob)
	if err != nil {
		t.Fatalf("decodeSparse for %s: %v", hash, err)
	}
	return m, model.String, true
}

// TestUpsertPersistsSparseRoundTrip: a hybrid embed writes the sparse vector AND a
// sparse_model label into chunk_embeddings, and the blob round-trips byte-for-byte
// through decodeSparse back to the map the embedder produced.
func TestUpsertPersistsSparseRoundTrip(t *testing.T) {
	db := openTestDB(t)
	body := "nftables firewall egress gateway"
	seedChunk(t, db, "docs/04.md", "Net", body)
	// Sparse rides ONLY on the EmbedBatch wire (the per-chunk Embedder seam is dense-
	// only), and embedTexts batches only when there is MORE THAN ONE text to amortize.
	// Seed a second, distinct chunk so the batch path runs and sparse is produced.
	seedChunk(t, db, "docs/22.md", "Work", "task worktree branch lock dispatch agent")
	hash := gitBlobSHA([]byte(body))

	want := map[int]float32{7: 1.5, 42: 0.25, 1000: -3.0}
	emb := &sparseControlEmbedder{
		label:     "hybrid-rt",
		sparseFor: func(string) map[int]float32 { return want },
	}
	if _, err := embedChunks(context.Background(), db, emb, true); err != nil {
		t.Fatalf("embedChunks: %v", err)
	}

	got, model, ok := readSparse(t, db, hash)
	if !ok {
		t.Fatalf("no chunk_embeddings row for hash %s", hash)
	}
	if model != "hybrid-rt" {
		t.Errorf("sparse_model = %q, want %q", model, "hybrid-rt")
	}
	if len(got) != len(want) {
		t.Fatalf("sparse len = %d, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("sparse[%d] = %v, want %v", k, got[k], v)
		}
	}
}

// TestReembedWithNilSparseClearsStale: a hash first embedded WITH sparse, then
// re-embedded by a dense-only embedder (same model label so it is not treated as a
// model swap), must end with sparse_vector AND sparse_model NULL — the dense-only
// re-embed CLEARS the stale sparse rather than preserving it (the load-bearing ON
// CONFLICT-sets-NULL behavior). Dense ranking continues to work afterward.
func TestReembedWithNilSparseClearsStale(t *testing.T) {
	db := openTestDB(t)
	body := "embedding vector cosine search index chunk"
	seedChunk(t, db, "docs/08.md", "Emb", body)
	// A second distinct chunk so the EmbedBatch path runs (sparse rides only on the
	// batch wire), genuinely persisting sparse for our target hash via embedChunks.
	seedChunk(t, db, "docs/22.md", "Work", "task worktree branch lock dispatch agent")
	hash := gitBlobSHA([]byte(body))

	// Pass 1: hybrid embed populates sparse under label "stable".
	hybrid := &sparseControlEmbedder{
		label:     "stable",
		sparseFor: func(string) map[int]float32 { return map[int]float32{3: 1.0, 9: 2.0} },
	}
	if _, err := embedChunks(context.Background(), db, hybrid, true); err != nil {
		t.Fatalf("embedChunks pass 1: %v", err)
	}
	if m, model, _ := readSparse(t, db, hash); len(m) == 0 || model == "" {
		t.Fatalf("after pass 1 sparse should be populated, got map=%v model=%q", m, model)
	}

	// Pass 2: SAME label (no model swap → the hash is re-embedded only because we
	// force it), but dense-only output. To force a re-embed under the same signature
	// we drop the cached row's sparse expectation by re-running with denseOnly — the
	// signature (model,dims) is unchanged so embedChunks would SKIP it; clear the
	// dense cache first so the row is re-embedded and the UPSERT's ON CONFLICT path
	// (and its NULL-clearing) is exercised on a pre-existing row.
	denseOnly := &sparseControlEmbedder{label: "stable", denseOnly: true}
	// Re-embedding a fresh-signature hash is a no-op skip; to drive the ON CONFLICT
	// UPDATE we delete just the dense vector marker so the hash is re-embedded. The
	// cleanest hermetic way: drop the row entirely and re-embed — the UPSERT then
	// INSERTs with NULL sparse, proving the INSERT path also writes NULL. Then a
	// second dense-only re-embed over a row that STILL has stale sparse (re-inserted
	// below) proves the ON CONFLICT path clears it.
	if _, err := db.Exec(`DELETE FROM chunk_embeddings WHERE chunk_hash=?`, hash); err != nil {
		t.Fatalf("delete row: %v", err)
	}
	if _, err := embedChunks(context.Background(), db, denseOnly, true); err != nil {
		t.Fatalf("embedChunks pass 2 (INSERT path): %v", err)
	}
	if m, model, ok := readSparse(t, db, hash); !ok || len(m) != 0 || model != "" {
		t.Fatalf("INSERT path: sparse should be NULL, got ok=%v map=%v model=%q", ok, m, model)
	}

	// Now re-seed stale sparse directly so the ON CONFLICT UPDATE path is the one that
	// must clear it: hand-write a non-NULL sparse blob onto the existing row, then
	// re-embed dense-only and assert it is cleared via ON CONFLICT (not INSERT).
	if _, err := db.Exec(
		`UPDATE chunk_embeddings SET sparse_vector=?, sparse_model=? WHERE chunk_hash=?`,
		encodeSparse(map[int]float32{5: 9.0}), "stale-leftover", hash,
	); err != nil {
		t.Fatalf("re-seed stale sparse: %v", err)
	}
	if m, _, _ := readSparse(t, db, hash); len(m) == 0 {
		t.Fatalf("precondition: stale sparse should be present before the clearing re-embed")
	}
	// Force the ON CONFLICT path: the row exists with the active signature, so
	// embedChunks would skip it. Bump the cached model so it is treated as a swap and
	// re-embedded under "stable" via ON CONFLICT.
	if _, err := db.Exec(`UPDATE chunk_embeddings SET model=? WHERE chunk_hash=?`, "old-model", hash); err != nil {
		t.Fatalf("bump model: %v", err)
	}
	if _, err := embedChunks(context.Background(), db, denseOnly, true); err != nil {
		t.Fatalf("embedChunks pass 3 (ON CONFLICT path): %v", err)
	}
	m, model, ok := readSparse(t, db, hash)
	if !ok {
		t.Fatalf("row missing after ON CONFLICT re-embed")
	}
	if len(m) != 0 || model != "" {
		t.Errorf("ON CONFLICT path: stale sparse not cleared — got map=%v model=%q, want NULL/NULL", m, model)
	}
}

// TestHybridRankOrdersSparseMatchAboveDenseOnly: with TWO chunks whose dense-cosine
// scores against the query are equal, the chunk that ALSO shares a sparse term with
// the query must rank STRICTLY first via the sparse-lexical-dot leg. We assert the
// FULL order (not just len>0), and that a dense-only query (no shared sparse) leaves
// the two tied (broken only by the deterministic path tiebreak), proving the sparse
// leg is what reorders them.
func TestHybridRankOrdersSparseMatchAboveDenseOnly(t *testing.T) {
	db := openTestDB(t)

	const sharedTerm = 777
	// Two chunks with EQUAL dense-cosine to the query: both use the SAME ranking
	// vocabulary (same dense vector) and differ only in trailing filler words that are
	// OUTSIDE fakeVocab, so their content hashes differ but their dense scores tie. The
	// path tiebreak favors b-dense (b < z), so WITHOUT the sparse leg b-dense ranks
	// first; the sparse leg is the only thing that can flip the order.
	denseBody := "embedding vector cosine search index chunk filler-dense"
	sparseBody := "embedding vector cosine search index chunk filler-sparse"
	seedChunk(t, db, "docs/b-dense.md", "Dense", denseBody)
	seedChunk(t, db, "docs/z-sparse.md", "Sparse", sparseBody)

	// A hybrid embedder that gives the SPARSE chunk the shared query term and the DENSE
	// chunk a disjoint term, and the query the shared term. "filler-dense"/"filler-sparse"
	// are outside fakeVocab, so the dense-cosine of both chunks vs the query is equal.
	hybrid := &sparseControlEmbedder{
		label: "rank-v1",
		sparseFor: func(text string) map[int]float32 {
			switch {
			case strings.Contains(text, "filler-sparse"):
				return map[int]float32{sharedTerm: 2.0}
			case strings.Contains(text, "filler-dense"):
				return map[int]float32{111: 5.0} // disjoint from the query term
			default: // the query
				return map[int]float32{sharedTerm: 1.0}
			}
		},
	}
	if _, err := embedChunks(context.Background(), db, hybrid, true); err != nil {
		t.Fatalf("embedChunks (hybrid): %v", err)
	}

	// Sanity: the two chunks have EQUAL dense-cosine to the query (the sparse leg is the
	// only differentiator). Confirm via a dense-only query embedder first.
	denseQuery := &sparseControlEmbedder{label: "rank-v1", denseOnly: true}
	dh, err := semanticSearch(context.Background(), db, denseQuery, "embedding vector cosine search index chunk", 10, false)
	if err != nil {
		t.Fatalf("dense-only search: %v", err)
	}
	if len(dh) != 2 {
		t.Fatalf("dense-only search hits = %d, want 2", len(dh))
	}
	if scoreFor(dh, "docs/b-dense.md") != scoreFor(dh, "docs/z-sparse.md") {
		t.Fatalf("precondition: dense-cosine scores must be EQUAL, got b=%v z=%v",
			scoreFor(dh, "docs/b-dense.md"), scoreFor(dh, "docs/z-sparse.md"))
	}
	// WITHOUT the sparse leg, the path tiebreak puts b-dense first (b < z).
	if dh[0].Path != "docs/b-dense.md" {
		t.Fatalf("dense-only tie should break to b-dense.md first, got %q", dh[0].Path)
	}

	// WITH the hybrid query (shares term 777 with z-sparse only), z-sparse must rank
	// STRICTLY first despite the path tiebreak favoring b-dense. Assert the FULL order.
	hh, err := semanticSearch(context.Background(), db, hybrid, "embedding vector cosine search index chunk", 10, false)
	if err != nil {
		t.Fatalf("hybrid search: %v", err)
	}
	if len(hh) != 2 {
		t.Fatalf("hybrid search hits = %d, want 2", len(hh))
	}
	if hh[0].Path != "docs/z-sparse.md" || hh[1].Path != "docs/b-dense.md" {
		t.Fatalf("hybrid order = [%q, %q], want [docs/z-sparse.md, docs/b-dense.md] (sparse match first)",
			hh[0].Path, hh[1].Path)
	}
	if !(hh[0].Score > hh[1].Score) {
		t.Errorf("sparse-matching chunk score %v must be STRICTLY above dense-only %v", hh[0].Score, hh[1].Score)
	}
}

// TestSparseDotOverlapOnly: the lexical dot sums ONLY shared token ids and is
// symmetric; disjoint maps and empty maps score 0.
func TestSparseDotOverlapOnly(t *testing.T) {
	a := map[int]float32{1: 2.0, 2: 3.0, 5: 1.0}
	b := map[int]float32{2: 4.0, 5: 0.5, 9: 7.0}
	// overlap on 2 (3*4=12) and 5 (1*0.5=0.5) → 12.5
	if got := sparseDot(a, b); math.Abs(got-12.5) > 1e-9 {
		t.Errorf("sparseDot = %v, want 12.5", got)
	}
	if got := sparseDot(b, a); math.Abs(got-12.5) > 1e-9 {
		t.Errorf("sparseDot not symmetric: %v, want 12.5", got)
	}
	if got := sparseDot(a, map[int]float32{100: 1.0}); got != 0 {
		t.Errorf("disjoint sparseDot = %v, want 0", got)
	}
	if got := sparseDot(a, nil); got != 0 {
		t.Errorf("nil sparseDot = %v, want 0", got)
	}
	if got := sparseDot(nil, nil); got != 0 {
		t.Errorf("nil/nil sparseDot = %v, want 0", got)
	}
}
