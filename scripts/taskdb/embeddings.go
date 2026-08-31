// SPDX-License-Identifier: Apache-2.0
package main

// embeddings.go — the doc 22 §8 "embeddings seam (spec'd, not shipped)" made
// real, holding every property the doc commits to (decisions D9/§8):
//
//   - The cache table is keyed on doc_chunks.hash — the blob SHA-1 of the chunk
//     text (db.go gitBlobSHA), set as doc_chunks.hash at sync time. Joining on
//     content hash (not rowid) is the whole trick: a `doc sync` re-chunk wipes
//     and reinserts doc_chunks with fresh rowids, but an UNCHANGED chunk keeps
//     its hash, so its embedding stays valid and is NEVER recomputed. rowid
//     churn is irrelevant; only genuinely new/edited chunk text re-embeds.
//   - chunk_embeddings is additive `CREATE TABLE IF NOT EXISTS`, NEVER frozen
//     (freeze.go reads only tasks + notes), and its migration is idempotent —
//     running ensureEmbeddingsSchema twice on a populated DB is a no-op.
//   - Ranking is cosine similarity in PURE GO. We do NOT depend on a sqlite
//     vector extension: that would break the single-static-binary invariant
//     (modernc.org/sqlite is CGo-free; a loadable vec0 extension is not). The
//     vectors are small (doc-chunk count is in the low hundreds), so an
//     in-process linear scan with float32 dot products is more than fast enough
//     and keeps the binary self-contained.
//
// Embedder seam (pluggable, local-model-first):
//
//   The embedder is an EXTERNAL command (--embedder-cmd) that reads UTF-8 text
//   on stdin and emits a JSON float array on stdout — one vector per invocation.
//   This keeps the model out of the Go binary entirely: the PROPOSED default is
//   a local model (scripts/taskdb/embedder/embed.py, sentence-transformers
//   behind a graceful availability check), and swapping to an API embedder is a
//   pure config change (point --embedder-cmd at a thin curl/script wrapper that
//   posts to the provider and prints the returned vector). No long-lived
//   credential or network call is ever compiled into taskdb; the embedder
//   process owns that decision. (doc 22 prose for this seam belongs to the
//   watermark-retention unit; this file does not edit doc 22.)

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// embedWarnOut is where the LOUD stale-embedding warning goes. It is os.Stderr in
// production (so a semantic search over a swapped index is never silently wrong —
// the operator sees a line telling them to re-run `taskdb doc embed`), and a test
// redirects it to a buffer to assert the warning fired without capturing the
// process's real stderr.
var embedWarnOut io.Writer = os.Stderr

// embedContext returns the context the CLI embed/search paths run under. It is a
// thin wrapper around context.Background so the CLI verbs (cmd_doc.go) need not
// import context themselves — the SPDX-ratchet fence forbids edits to the top of
// existing files, and adding a context import there lands inside that fenced
// region. A future caller wanting cancellation passes its own context to the
// embedChunks/semanticSearch cores directly.
func embedContext() context.Context { return context.Background() }

// ensureEmbeddingsSchema creates the additive, never-frozen cache table keyed on
// the chunk content hash. It is idempotent (`IF NOT EXISTS`), so running it
// against an existing taskdb.sqlite — populated or empty — is a no-op that
// neither errors nor rewrites rows. The doc index tables (docs/doc_chunks) are
// owned by initSchema; this seam stays self-contained so the migration can be
// invoked lazily from the embed/search paths without widening initSchema.
func ensureEmbeddingsSchema(db *sql.DB) error {
	if _, err := db.Exec(`
-- DERIVED / EPHEMERAL: embedding cache for the semantic doc search seam
-- (docs/22 §8, D9). Keyed on doc_chunks.hash (blob SHA-1 of the chunk text), so
-- the embedding survives the rowid churn of a re-chunk and an unchanged chunk
-- is NEVER re-embedded. NEVER frozen — freeze.go serializes only tasks + notes.
-- vector is a packed little-endian float32 BLOB (see encodeVector); dims lets a
-- reader validate the length and model records which embedder produced it (a
-- model swap is detected by comparing the stored model to the active one).
CREATE TABLE IF NOT EXISTS chunk_embeddings (
	chunk_hash TEXT PRIMARY KEY,
	model      TEXT NOT NULL,
	dims       INTEGER NOT NULL,
	vector     BLOB NOT NULL
);
`); err != nil {
		return err
	}
	// Idempotent widening for the HYBRID (dense + sparse) embedder: a pre-existing
	// dense-only cache predates these columns, so ADD them only when absent. Both are
	// NULLable — a dense-only embedder leaves them NULL and the existing dense ranking
	// path is untouched. sparse_vector is a packed (uint32 token_id, float32 weight)
	// BLOB (see encodeSparse); sparse_model records which hybrid embedder produced it.
	// This unit lands the columns; a LATER unit populates and ranks on them.
	if err := addColumnIfMissing(db, "chunk_embeddings", "sparse_vector", "BLOB NULL"); err != nil {
		return err
	}
	if err := addColumnIfMissing(db, "chunk_embeddings", "sparse_model", "TEXT NULL"); err != nil {
		return err
	}
	return nil
}

// addColumnIfMissing performs an idempotent `ALTER TABLE ... ADD COLUMN`: it probes
// PRAGMA table_info first and only issues the ALTER when the column is absent, so
// running ensureEmbeddingsSchema repeatedly over an already-widened DB is a clean
// no-op (sqlite's ADD COLUMN errors on a duplicate, so the guard is required, not
// cosmetic). table and column are fixed internal identifiers (never user input), so
// the unavoidable string interpolation in the DDL is safe.
func addColumnIfMissing(db *sql.DB, table, column, decl string) error {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			dfltValue  sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dfltValue, &primaryKey); err != nil {
			return err
		}
		if name == column {
			return nil // already present — nothing to do
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, decl)); err != nil {
		return err
	}
	return nil
}

// encodeVector packs a float32 vector into a little-endian BLOB. We store
// float32 (not JSON, not float64) so the cache is compact and the cosine math
// reads back exactly what the embedder emitted, with no decimal-string round
// trips.
func encodeVector(v []float32) []byte {
	b := make([]byte, 4*len(v))
	for i, f := range v {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(f))
	}
	return b
}

// decodeVector unpacks a little-endian float32 BLOB written by encodeVector. A
// length that is not a multiple of 4 is a corrupt/foreign row and is rejected
// loudly rather than silently truncated.
func decodeVector(b []byte) ([]float32, error) {
	if len(b)%4 != 0 {
		return nil, fmt.Errorf("embedding blob length %d is not a multiple of 4", len(b))
	}
	v := make([]float32, len(b)/4)
	for i := range v {
		v[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[4*i:]))
	}
	return v, nil
}

// sparseEntryBytes is the packed width of one sparse term: a uint32 token_id
// followed by a float32 weight, both little-endian (8 bytes). A blob length that
// is not a multiple of this is corrupt and rejected loudly (see decodeSparse),
// mirroring decodeVector's not-a-multiple-of-4 guard.
const sparseEntryBytes = 8

// encodeSparse packs a sparse term-weight map (token_id -> weight) into a
// little-endian BLOB of (uint32 token_id, float32 weight) pairs, mirroring
// encodeVector. A nil/empty map encodes to a zero-length BLOB (a valid, empty
// sparse vector). Entries are written in ascending token_id order so the encoding
// is deterministic — identical maps produce byte-identical blobs, which the
// content-keyed cache and any round-trip test rely on. token_id must be a
// non-negative uint32; a key outside that range is a programming error the caller
// is responsible for not producing (a real lexical embedder's ids are small
// non-negative vocab indices).
func encodeSparse(m map[int]float32) []byte {
	if len(m) == 0 {
		return []byte{}
	}
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	b := make([]byte, sparseEntryBytes*len(ids))
	for i, id := range ids {
		off := sparseEntryBytes * i
		binary.LittleEndian.PutUint32(b[off:], uint32(id))
		binary.LittleEndian.PutUint32(b[off+4:], math.Float32bits(m[id]))
	}
	return b
}

// decodeSparse unpacks a sparse BLOB written by encodeSparse back into a
// token_id -> weight map. A length that is not a multiple of sparseEntryBytes is a
// corrupt/foreign row and is rejected LOUDLY rather than silently truncated, the
// same discipline decodeVector applies to the dense blob. A zero-length blob is a
// valid empty sparse vector and decodes to an empty (non-nil) map.
func decodeSparse(b []byte) (map[int]float32, error) {
	if len(b)%sparseEntryBytes != 0 {
		return nil, fmt.Errorf("sparse embedding blob length %d is not a multiple of %d", len(b), sparseEntryBytes)
	}
	m := make(map[int]float32, len(b)/sparseEntryBytes)
	for off := 0; off < len(b); off += sparseEntryBytes {
		id := binary.LittleEndian.Uint32(b[off:])
		w := math.Float32frombits(binary.LittleEndian.Uint32(b[off+4:]))
		m[int(id)] = w
	}
	return m, nil
}

// cosineSimilarity returns the cosine of the angle between a and b in PURE GO
// (no sqlite vector extension — the single-static-binary invariant). Length
// mismatch returns 0 (an embedding produced by a different model/dims can't be
// meaningfully compared); a zero-magnitude vector also returns 0 rather than
// NaN, so ranking stays total and deterministic.
func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		x, y := float64(a[i]), float64(b[i])
		dot += x * y
		na += x * x
		nb += y * y
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// sparseDot is the lexical contribution of the hybrid rank: the dot product of two
// sparse term-weight maps (token_id -> weight), summed over the token ids they SHARE.
// A term present in only one side contributes nothing (the missing side's weight is
// 0), so two sparse vectors with no overlap score 0 and a chunk that shares a query
// term gets a positive boost over a dense-only neighbor. We iterate the SMALLER map
// and probe the larger so the cost tracks the overlap, not the vocabulary. An empty
// map on either side yields 0 — the dense-only ranking path stays unchanged.
func sparseDot(a, b map[int]float32) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	if len(b) < len(a) {
		a, b = b, a
	}
	var dot float64
	for id, wa := range a {
		if wb, ok := b[id]; ok {
			dot += float64(wa) * float64(wb)
		}
	}
	return dot
}

// sparseCosine is the BOUNDED lexical similarity of two sparse term-weight maps:
// sparseDot normalized by the product of the two vectors' L2 magnitudes, i.e. the
// cosine of the angle between them in sparse term space. The raw sparseDot is an
// UNBOUNDED sum of arbitrary term weights — one high-weight shared term can dwarf a
// dense cosine (which lives in [-1,1]) and make the hybrid rank effectively
// lexical-only. Dividing by the magnitudes puts the lexical leg on the SAME [-1,1]
// scale as cosineSimilarity (for the non-negative term weights a lexical embedder
// emits it lands in [0,1]), so neither leg can dominate the other by raw magnitude.
//
// Mirrors cosineSimilarity's degenerate-input discipline: an empty map on either
// side, or a zero-magnitude vector, returns 0 rather than NaN, so the hybrid score
// stays total and deterministic. We reuse sparseDot for the numerator so the
// overlap-only iteration (and its share-a-term semantics) is computed in one place.
func sparseCosine(a, b map[int]float32) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	var na, nb float64
	for _, w := range a {
		na += float64(w) * float64(w)
	}
	for _, w := range b {
		nb += float64(w) * float64(w)
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return sparseDot(a, b) / (math.Sqrt(na) * math.Sqrt(nb))
}

// Hybrid-rank weights: the Go-side semanticSearch combines the dense-cosine leg and
// the BOUNDED sparse-cosine leg as wDense*dense + wSparse*sparse, mirroring the
// service-side fusion intent (searchsvc/fusion.py W_DENSE=0.65 / W_SPARSE=0.35) so
// the two ranking implementations agree on which signal leads. Both legs are now on
// the SAME [-1,1] scale (sparseCosine bounds the lexical leg), so the weights — not
// raw magnitude — decide the balance: dense is the semantic signal, sparse the
// lexical backstop. The weights are applied ONLY when both the query and the chunk
// carry a sparse vector; a dense-only query or row leaves the dense-cosine score
// untouched (see hybridScore), so dense-only ranking is byte-for-byte the prior
// behavior.
//
// SINGLE TUNING KNOB across both ranking legs (unified-ranking-knobs): the canonical
// weights below are the DEFAULTS, but an operator can override them — for BOTH the Go
// semanticSearch leg and the Python searchsvc/fusion.py leg at once — via the same
// environment variables, so the two legs can never silently diverge under tuning:
//
//	SEARCHSVC_W_DENSE   -> wDense   (canonical 0.65, mirrors fusion.py W_DENSE)
//	SEARCHSVC_W_SPARSE  -> wSparse  (canonical 0.35, mirrors fusion.py W_SPARSE)
//
// fusion.py ALSO reads SEARCHSVC_RRF_K (the Reciprocal-Rank-Fusion damping constant),
// but the Go leg ranks by a RAW-COSINE blend, not by RANK position — it has no RRF k
// to tune — so SEARCHSVC_RRF_K is intentionally NOT consumed here. Reading it would be
// a no-op knob that an operator would mistake for an effective control; fusion.py
// remains the sole consumer of SEARCHSVC_RRF_K.
//
// Resolution mirrors fusion.py._env_number discipline: parsed ONCE (sync.Once, so a
// later env mutation does not re-resolve mid-process, matching fusion.py's read at
// module-eval time), and a present-but-unparseable value LOUD-falls back to the
// canonical default (one stderr line) rather than crashing the search/embed path.
const (
	wDenseDefault  = 0.65
	wSparseDefault = 0.35
)

// Env var names — the SHARED tuning knob, byte-for-byte the names fusion.py reads
// (searchsvc/fusion.py: SEARCHSVC_W_DENSE / SEARCHSVC_W_SPARSE). Keeping the names in
// one place here is what makes "one knob, both legs" auditable.
const (
	envWDense  = "SEARCHSVC_W_DENSE"
	envWSparse = "SEARCHSVC_W_SPARSE"
)

// hybridWeights resolves the effective (wDense, wSparse) ONCE per process from the
// shared env knob, falling back to the canonical defaults. Parse-once via sync.Once
// mirrors fusion.py reading its constants at module-eval time: a process embeds/searches
// under one stable pair of weights, and a test that wants a different pair sets the env
// BEFORE the first call (the test also has resetHybridWeights to clear the latch).
var (
	hybridWeightsOnce sync.Once
	wDenseEffective   float64
	wSparseEffective  float64
)

// envFloat reads env var name as a float64, returning def when unset/empty and
// LOUD-falling back to def on a present-but-unparseable value (one stderr line on
// embedWarnOut, never a panic) — the Go mirror of fusion.py._env_number's discipline.
func envFloat(name string, def float64) float64 {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		fmt.Fprintf(embedWarnOut,
			"taskdb: ignoring invalid %s=%q (expected a float); falling back to canonical default %v\n",
			name, raw, def)
		return def
	}
	return v
}

// resolveHybridWeights latches the effective weights on first call. Subsequent calls
// return the same parsed pair — parse-once, so a mid-process env change does not shift
// ranking under a running search loop (fusion.py binds its weights at import for the
// same reason).
func resolveHybridWeights() (wDense, wSparse float64) {
	hybridWeightsOnce.Do(func() {
		wDenseEffective = envFloat(envWDense, wDenseDefault)
		wSparseEffective = envFloat(envWSparse, wSparseDefault)
	})
	return wDenseEffective, wSparseEffective
}

// hybridScore blends the dense-cosine base score with the BOUNDED sparse-cosine leg.
// When EITHER side carries no sparse vector (a dense-only query or a dense-only
// chunk), the dense cosine is returned UNCHANGED — the hybrid leg is a no-op and
// dense-only ranking is preserved exactly. When both carry sparse, the result is the
// weighted combination wDense*dense + wSparse*sparseCosine, so a high-weight shared
// lexical term boosts but never SWAMPS a strong dense match: the dense leg always
// contributes wDense of a [-1,1]-scaled score and the sparse leg at most wSparse.
// dense is already a cosine in [-1,1]; the blended score stays in that range. The
// query's and chunk's sparse maps are passed by value (read-only) so the caller's
// decoded maps are never mutated.
//
// wDense / wSparse are the EFFECTIVE weights resolved once from the shared env knob
// (SEARCHSVC_W_DENSE / SEARCHSVC_W_SPARSE — the same names fusion.py reads), defaulting
// to wDenseDefault / wSparseDefault. Sourcing both ranking legs from one knob keeps the
// Go and Python rankers from diverging under operator tuning.
func hybridScore(dense float64, qsparse, csparse map[int]float32) float64 {
	if len(qsparse) == 0 || len(csparse) == 0 {
		return dense
	}
	wDense, wSparse := resolveHybridWeights()
	return wDense*dense + wSparse*sparseCosine(qsparse, csparse)
}

// Embedder turns text into a vector. The production implementation shells out to
// an external command; tests inject a deterministic fake. Keeping this an
// interface (rather than hardcoding exec) is what makes the seam unit-testable
// WITHOUT a live model, network, or download.
type Embedder interface {
	// Embed returns the vector for text and the model identifier that produced
	// it (recorded in chunk_embeddings.model so a model swap is detectable).
	Embed(ctx context.Context, text string) (vec []float32, model string, err error)
}

// cmdEmbedder is the production seam: an external process that reads text on
// stdin and prints a JSON float array on stdout. local-model-first is the
// PROPOSED default (embedder/embed.py); an API embedder is a drop-in config swap
// by pointing the command elsewhere. The model label is the command's basename
// joined with its args so different embedder configs don't collide in the cache.
type cmdEmbedder struct {
	// argv is the command + fixed args; the chunk text is fed on stdin, never as
	// an argv element (avoids ARG_MAX limits and shell-quoting hazards on large
	// chunks).
	argv []string
	// modelLabel records which embedder produced a vector. It defaults to the
	// argv string but a caller may override it (e.g. to the model name the
	// embedder self-reports) without changing the cache-key (the key is the
	// chunk hash, not the model).
	modelLabel string
}

// newCmdEmbedder builds an external-command embedder from a shell-free argv
// slice (already split by the caller). An empty argv is rejected so a missing
// --embedder-cmd fails loudly at the search/embed entry point rather than
// spawning an empty process.
func newCmdEmbedder(argv []string) (*cmdEmbedder, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("no embedder command configured (pass --embedder-cmd)")
	}
	return &cmdEmbedder{argv: argv, modelLabel: strings.Join(argv, " ")}, nil
}

// Embed runs the external command once per chunk, writing text to its stdin and
// decoding a JSON float array from its stdout. stderr is surfaced in the error
// so a failing local model (missing dependency, bad config) is debuggable. The
// context lets a caller bound a slow/hung embedder.
func (e *cmdEmbedder) Embed(ctx context.Context, text string) ([]float32, string, error) {
	cmd := exec.CommandContext(ctx, e.argv[0], e.argv[1:]...)
	cmd.Stdin = strings.NewReader(text)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, "", fmt.Errorf("embedder %q failed: %v: %s", e.argv[0], err, msg)
		}
		return nil, "", fmt.Errorf("embedder %q failed: %v", e.argv[0], err)
	}
	var vec []float32
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &vec); err != nil {
		return nil, "", fmt.Errorf("embedder %q output is not a JSON float array: %w", e.argv[0], err)
	}
	if len(vec) == 0 {
		return nil, "", fmt.Errorf("embedder %q returned an empty vector", e.argv[0])
	}
	return vec, e.modelLabel, nil
}

// embedResult is the tally an incremental embed returns: how many distinct chunk
// hashes were newly embedded this pass, how many were already cached (skipped),
// and how many stale cache rows were pruned (hashes that no longer appear in
// doc_chunks). The skipped count is what the no-re-embed acceptance test asserts.
type embedResult struct {
	Embedded int `json:"embedded"`
	Skipped  int `json:"skipped"`
	Pruned   int `json:"pruned"`
	Total    int `json:"total"` // distinct chunk hashes currently on disk
	// Reembedded is the subset of Embedded that existed in the cache under a
	// DIFFERENT model label or vector width and was overwritten this pass — i.e.
	// re-embeds DRIVEN by an embedder swap, not by new/edited chunk text. It is
	// the observability hook for "the index just changed embedder": a nonzero
	// value on an otherwise-unchanged corpus means a model/dims swap was healed.
	Reembedded int `json:"reembedded"`
	// Model and Dims are the ACTIVE embedder's signature this pass (the basename
	// label and the probed vector width), so a caller can report which model the
	// cache is now keyed to.
	Model string `json:"model,omitempty"`
	Dims  int    `json:"dims,omitempty"`
}

// embedProbe is the fixed canary text embedded once per pass to learn the ACTIVE
// embedder's signature (its self-reported model label and the width of the vector
// it currently emits). The width is what catches a same-label dims swap — e.g. a
// local embedder that drops from a 384-dim model to a 256-dim fallback under the
// SAME argv (the DS_EMBED_LIVE toggle): the modelLabel is unchanged, but the
// probed dims move, so the cached rows are recognized as stale. The constant is
// short, ASCII, and stable so the probe vector is reproducible.
const embedProbe = "dream-serpent embedding model probe"

// activeSignature embeds the fixed canary once to discover the active embedder's
// (modelLabel, dims). Every cached row whose stored (model, dims) differs from
// this signature is STALE — it was produced by a different embedder (a config
// swap) or a different width of the same one (a runtime toggle) and must NOT be
// trusted for cosine ranking. Probing costs exactly one embed per embed/search
// pass, independent of corpus size.
func activeSignature(ctx context.Context, emb Embedder) (model string, dims int, err error) {
	vec, model, err := emb.Embed(ctx, embedProbe)
	if err != nil {
		return "", 0, fmt.Errorf("probing active embedder: %w", err)
	}
	if len(vec) == 0 {
		return "", 0, fmt.Errorf("active embedder returned an empty probe vector")
	}
	return model, len(vec), nil
}

// embedChunks is the incremental indexing core (shared by the CLI verb and any
// on-demand path). It diffs doc_chunks.hash against chunk_embeddings and embeds a
// hash when it is new, when its text changed (a fresh hash), OR — and this is the
// model-swap fix — when the cached row was produced by a DIFFERENT embedder than
// the one now active. The skip set is therefore not "every cached hash" but
// "every hash cached UNDER THE ACTIVE (model, dims) signature": a row whose stored
// model label or vector width differs is treated as stale and re-embedded via the
// existing ON CONFLICT upsert. An unchanged chunk under the SAME embedder is still
// never re-embedded (the seam's defining property holds).
//
// The active signature is learned by probing one canary embed up front (see
// activeSignature): the modelLabel a cmdEmbedder reports is its argv string, so a
// pure config swap moves the label, while a same-argv runtime toggle (e.g.
// DS_EMBED_LIVE flipping a 384-dim model to a 256-dim fallback) moves the probed
// dims — both register as stale.
//
// Distinct hashes are embedded once even when the same text appears under
// several chunks (preamble boilerplate, shared headers): the embedder cost
// tracks unique content, not chunk count.
//
// When prune is set, cache rows whose hash no longer appears in any doc_chunk
// (the chunk's text was edited or its doc deleted) are dropped, keeping the
// cache bounded without ever touching a still-valid row.
func embedChunks(ctx context.Context, db *sql.DB, emb Embedder, prune bool) (*embedResult, error) {
	// Default behavior is CORRECT, not opt-in: a cached row from a different
	// embedder is healed (re-embedded under the active model). The opt-OUT path
	// (reembedOnModelChange=false) is a deliberate escape hatch for an operator who
	// knows the swap is transient and wants to avoid the re-embed cost this pass.
	return embedChunksOpts(ctx, db, emb, prune, true)
}

// embedChunksOpts is the embedChunks core with the model-swap healing toggle made
// explicit. reembedOnModelChange=true (the default via embedChunks) re-embeds
// cached rows whose stored (model, dims) differs from the active embedder;
// =false keeps the pre-swap-detection behavior of skipping any hash that is
// already cached regardless of which embedder produced it (the explicit OFF
// switch the CLI exposes as --reembed-on-model-change=false).
func embedChunksOpts(ctx context.Context, db *sql.DB, emb Embedder, prune, reembedOnModelChange bool) (*embedResult, error) {
	if err := ensureEmbeddingsSchema(db); err != nil {
		return nil, err
	}

	// Probe the active embedder ONCE to learn the (model, dims) the cache must be
	// keyed to this pass. Any cached row not matching this signature is stale.
	activeModel, activeDims, err := activeSignature(ctx, emb)
	if err != nil {
		return nil, err
	}

	// Distinct chunk hashes currently on disk, with one representative body each
	// (identical hashes share identical bodies by construction — the hash IS the
	// blob SHA of the body — so any representative embeds the same vector).
	live := map[string]string{} // hash -> body
	rows, err := db.Query(`SELECT hash, body FROM doc_chunks`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var hash, body string
		if err := rows.Scan(&hash, &body); err != nil {
			rows.Close()
			return nil, err
		}
		if _, seen := live[hash]; !seen {
			live[hash] = body
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Cached hashes WITH their producing signature. A hash is in the skip set
	// only when its cached (model, dims) matches the active embedder; a stale row
	// (different model label or width) is NOT skipped — it is re-embedded below
	// and counted as a model-swap-driven re-embed. The whole point of the seam is
	// preserved (a fresh row is never re-sent to the embedder), now correctly
	// scoped to the embedder that produced it.
	type cachedSig struct {
		model string
		dims  int
	}
	cached := map[string]cachedSig{}
	crows, err := db.Query(`SELECT chunk_hash, model, dims FROM chunk_embeddings`)
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var h, m string
		var d int
		if err := crows.Scan(&h, &m, &d); err != nil {
			crows.Close()
			return nil, err
		}
		cached[h] = cachedSig{model: m, dims: d}
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return nil, err
	}

	res := &embedResult{Total: len(live), Model: activeModel, Dims: activeDims}
	now := timeToMs(time.Now())
	_ = now // reserved for a future indexed_at column; the cache has no timestamp today

	// Embed in a stable hash order so a partial failure is reproducible and the
	// fake-embedder invocation count in tests is deterministic.
	hashes := make([]string, 0, len(live))
	for h := range live {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)

	// First pass: split the stable-ordered hashes into the SKIP set (fresh under the
	// active signature) and the TO-EMBED set, recording for each to-embed hash
	// whether a row already existed (so a re-embed under a different (model, dims) is
	// counted as model-swap-driven). The texts are gathered in the same order so the
	// batch seam below is order-preserving.
	type embedJob struct {
		hash      string
		text      string
		preexists bool // a cache row existed (under a different signature) → a swap re-embed
	}
	jobs := make([]embedJob, 0, len(hashes))
	for _, h := range hashes {
		sig, ok := cached[h]
		fresh := ok && sig.model == activeModel && sig.dims == activeDims
		// With model-swap healing OFF, a cached row counts as fresh regardless of
		// which embedder produced it — the explicit opt-out preserves the old
		// hash-only skip behavior (stale vectors left in place this pass).
		if ok && !reembedOnModelChange {
			fresh = true
		}
		if fresh {
			res.Skipped++
			continue
		}
		jobs = append(jobs, embedJob{hash: h, text: live[h], preexists: ok})
	}

	// Embed every to-embed chunk's text. embedTexts consults the OPT-IN batch seam
	// (a single multi-text invocation) when the embedder advertises it, and falls
	// back LOUDLY to the default one-text-per-invocation path otherwise or on a
	// malformed/mismatched batch response — the order of vecs matches jobs either
	// way. The default per-chunk contract is unchanged for a non-batch embedder.
	if len(jobs) > 0 {
		texts := make([]string, len(jobs))
		for i, j := range jobs {
			texts[i] = j.text
		}
		vecs, model, err := embedTexts(ctx, emb, texts)
		if err != nil {
			return nil, fmt.Errorf("embedding chunk %s: %w", jobs[0].hash[:min(12, len(jobs[0].hash))], err)
		}
		for i, j := range jobs {
			// Dense is the cache's ranking payload AND the model-swap signature (dims +
			// vector stay keyed to the dense width, so the signature is unchanged whether
			// the embedder is dense-only or hybrid). On TOP of dense we now persist the
			// OPTIONAL sparse vector a hybrid embedder (BGE-M3) carries alongside it.
			vec := vecs[i].Dense
			// Sparse persistence (this unit): write the packed sparse blob + a sparse_model
			// label when the embedder produced one, and NULL when it did not. Writing NULL
			// for a nil/empty Sparse is LOAD-BEARING: a dense-only re-embed of a hash that
			// previously carried sparse must CLEAR the stale sparse, not preserve it — so
			// both the INSERT value and the ON CONFLICT SET must drive sparse to NULL here.
			// The sparse label mirrors the dense model label (same hybrid embedder produced
			// both), giving a non-NULL sparse_model exactly when sparse_vector is non-NULL.
			var sparseBlob any
			var sparseModel any
			if len(vecs[i].Sparse) > 0 {
				sparseBlob = encodeSparse(vecs[i].Sparse)
				sparseModel = model
			}
			if _, err := db.Exec(
				`INSERT INTO chunk_embeddings(chunk_hash, model, dims, vector, sparse_vector, sparse_model)
				 VALUES(?,?,?,?,?,?)
				 ON CONFLICT(chunk_hash) DO UPDATE SET
				   model=excluded.model, dims=excluded.dims, vector=excluded.vector,
				   sparse_vector=excluded.sparse_vector, sparse_model=excluded.sparse_model`,
				j.hash, model, len(vec), encodeVector(vec), sparseBlob, sparseModel,
			); err != nil {
				return nil, err
			}
			res.Embedded++
			if j.preexists {
				// A row existed for this hash but under a different (model, dims):
				// this re-embed was driven by an embedder swap, not new/edited text.
				res.Reembedded++
			}
		}
	}

	if prune {
		// Drop cache rows for hashes no longer on disk. We collect first (can't
		// mutate while the NOT IN subquery would re-evaluate) then delete by key.
		var stale []string
		drows, err := db.Query(`SELECT chunk_hash FROM chunk_embeddings`)
		if err != nil {
			return nil, err
		}
		for drows.Next() {
			var h string
			if err := drows.Scan(&h); err != nil {
				drows.Close()
				return nil, err
			}
			if _, ok := live[h]; !ok {
				stale = append(stale, h)
			}
		}
		drows.Close()
		if err := drows.Err(); err != nil {
			return nil, err
		}
		for _, h := range stale {
			if _, err := db.Exec(`DELETE FROM chunk_embeddings WHERE chunk_hash=?`, h); err != nil {
				return nil, err
			}
			res.Pruned++
		}
	}

	return res, nil
}

// semanticHit is one ranked chunk from a semantic search: the chunk location
// plus its cosine score against the query embedding. Body is included so a
// caller can render an excerpt without a second lookup.
type semanticHit struct {
	Path    string  `json:"path"`
	Heading string  `json:"heading,omitempty"`
	Hash    string  `json:"hash"`
	Score   float64 `json:"score"`
	Body    string  `json:"body,omitempty"`
}

// semanticSearch ranks the embedded chunks against a query by cosine similarity,
// best first, in PURE GO. It embeds the query once via the same embedder, then
// linear-scans the cache (low-hundreds of rows) — no vector extension, no index
// build. limit<=0 defaults to 10.
//
// Model-swap safety (the fix this unit lands): a cached row produced under a
// DIFFERENT embedder than the one now active is NOT silently down-ranked to a
// cosine of 0 (the old behavior, where a dims mismatch quietly scored 0 and the
// query embedded under one model was meaninglessly compared to vectors from
// another). Instead such rows are EXCLUDED from ranking and TALLIED, and when any
// exist a loud line is written to embedWarnOut (os.Stderr) directing the operator
// to re-run `taskdb doc embed` to heal the index. A search across a swap is thus
// visibly degraded, never silently wrong. Callers (docSearchSemantic) run
// embedChunks first, so in the normal CLI path the corpus is already re-embedded
// under the active model and the stale count is zero.
//
// includeBody controls whether the chunk body rides along (the CLI wants it for
// excerpts; a count-only caller does not).
func semanticSearch(ctx context.Context, db *sql.DB, emb Embedder, query string, limit int, includeBody bool) ([]*semanticHit, error) {
	if err := ensureEmbeddingsSchema(db); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 10
	}
	// Probe the active embedder once: the query is embedded under this same
	// signature, so only cache rows sharing it are comparable.
	activeModel, activeDims, err := activeSignature(ctx, emb)
	if err != nil {
		return nil, err
	}
	// Embed the query via the hybrid read path: dense ALWAYS, plus the OPTIONAL
	// sparse term-weight map a hybrid embedder (BGE-M3) emits. A dense-only embedder
	// returns qsparse==nil and the sparse leg below is a no-op, so dense-cosine
	// ranking is unchanged.
	qvec, qsparse, _, err := embedQueryHybrid(ctx, emb, query)
	if err != nil {
		return nil, fmt.Errorf("embedding query: %w", err)
	}

	// Join the cache to the live chunks: a hash with no current chunk is a stale
	// cache row (edited/deleted text) and must not surface a phantom result. The
	// join also recovers the chunk's path/heading/body for display, plus the
	// row's producing (model, dims) so we can exclude rows from a different
	// embedder. A single hash can back several chunk rows (identical text under
	// different headings); we rank each occurrence so the agent sees every place
	// the match lives.
	// sparse_vector rides along so a chunk's lexical sparse vector can add a
	// dot-product contribution to the rank (hybrid leg). It is NULL for a dense-only
	// row, scanned into a sql.NullString below and skipped when absent — dense-only
	// ranking is unaffected.
	rows, err := db.Query(`
SELECT c.path, c.heading, c.hash, e.model, e.dims, e.vector, e.sparse_vector
FROM doc_chunks c
JOIN chunk_embeddings e ON e.chunk_hash = c.hash`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hits := []*semanticHit{}
	stale := 0 // cache rows from a different embedder, excluded from ranking
	for rows.Next() {
		var path, heading, hash, model string
		var dims int
		var blob []byte
		var sparseBlob []byte // NULL → nil slice (dense-only row)
		if err := rows.Scan(&path, &heading, &hash, &model, &dims, &blob, &sparseBlob); err != nil {
			return nil, err
		}
		if model != activeModel || dims != activeDims {
			// Produced by a different embedder (config swap) or a different width
			// of the same one (runtime toggle). Comparing it to a query vector
			// from the active model is meaningless, so exclude it from ranking and
			// count it for the loud warning rather than scoring it 0 in silence.
			stale++
			continue
		}
		vec, err := decodeVector(blob)
		if err != nil {
			return nil, fmt.Errorf("chunk %s: %w", hash[:min(12, len(hash))], err)
		}
		// Dense-cosine is the base score, ALWAYS computed. The hybrid sparse leg adds a
		// BOUNDED lexical contribution ONLY when BOTH the query and this chunk carry a
		// sparse vector — a dense-only query (qsparse==nil) or a dense-only row
		// (sparseBlob==nil) leaves the dense-cosine score untouched, so dense-only
		// ranking is byte-for-byte the prior behavior. hybridScore normalizes the sparse
		// leg to the SAME [-1,1] scale as dense-cosine and blends them with the
		// 0.65/0.35 weights, so a single high-weight shared term can no longer swamp a
		// strong dense match (the bug persist-hybrid-sparse left: an UNBOUNDED sparseDot
		// added straight onto a [-1,1] cosine).
		score := cosineSimilarity(qvec, vec)
		if len(qsparse) > 0 && len(sparseBlob) > 0 {
			cs, err := decodeSparse(sparseBlob)
			if err != nil {
				return nil, fmt.Errorf("chunk %s sparse: %w", hash[:min(12, len(hash))], err)
			}
			score = hybridScore(score, qsparse, cs)
		}
		hits = append(hits, &semanticHit{
			Path:    path,
			Heading: heading,
			Hash:    hash,
			Score:   score,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if stale > 0 {
		// LOUD, never silent: tell the operator the index is keyed to a different
		// embedder than the one running, and how to heal it. Written to
		// embedWarnOut (stderr) so structured/JSON stdout output is untouched.
		fmt.Fprintf(embedWarnOut,
			"taskdb: %d cached embedding(s) were produced by a different embedder than the active one "+
				"(active model %q dims %d) and were EXCLUDED from this semantic search; "+
				"re-run `taskdb doc embed` to re-embed them under the active model.\n",
			stale, activeModel, activeDims)
	}

	// Rank by score desc; break ties on (path, heading) so ordering is total and
	// deterministic for tests and reproducible CLI output.
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		if hits[i].Path != hits[j].Path {
			return hits[i].Path < hits[j].Path
		}
		return hits[i].Heading < hits[j].Heading
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}

	if includeBody && len(hits) > 0 {
		if err := attachChunkBodies(db, hits); err != nil {
			return nil, err
		}
	}
	return hits, nil
}

// attachChunkBodies fills each hit's Body from one representative chunk row for
// its hash (identical hash ⇒ identical body). Done as a post-pass so the ranking
// scan stays lean and only the surviving top-N rows pay the body fetch.
func attachChunkBodies(db *sql.DB, hits []*semanticHit) error {
	for _, h := range hits {
		var body string
		err := db.QueryRow(`SELECT body FROM doc_chunks WHERE hash=? LIMIT 1`, h.Hash).Scan(&body)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return err
		}
		h.Body = body
	}
	return nil
}
