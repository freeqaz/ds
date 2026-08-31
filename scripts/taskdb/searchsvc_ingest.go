// SPDX-License-Identifier: Apache-2.0
package main

// searchsvc_ingest.go — the Go-side INGEST PUSHER for a running searchsvc
// instance (searchsvc/serve.py). Where searchsvc_client.go posts /search (one
// query → ranked hits) and embeddings_http.go posts /embed (one chunk → its
// vector, the embedder seam), this file is the MAINTENANCE driver: it pushes the
// CHANGED doc_chunks set to the service so its resident index (re)absorbs them,
// then asks the service to /reindex, and surfaces a FRESHNESS/STALENESS signal
// (the resident index's corpus digest vs the current corpus digest).
//
// THE CHANGED SET — reuse, do not re-fork. The push set is exactly the chunks
// whose content hash (gitBlobSHA, the SAME identity docSync writes into
// doc_chunks.hash) is NOT already recorded as pushed. We persist the last-pushed
// corpus digest in the meta table (mirroring docRebuildSources' task_sources_fp
// fingerprint), so a no-op push (corpus unchanged since the last push) costs one
// digest compare and zero HTTP round-trips. The per-chunk diff against the
// embeddings cache the embed seam already owns is the embedChunks contract; here
// the unit of work is the doc_chunks row text the service embeds resident-side.
//
// PRUNE mirrors the existing Go prune path (embeddings.go embedChunks / cmd_doc
// syncTaskNoteChunks): collect the hashes that LEFT the corpus, hand the service
// the surviving live set via /reindex (the service rebuilds from the resolved DB
// and drops vanished rows itself), and report the count that left. There is no
// per-chunk DELETE wire verb — /reindex is the service's prune, single-host.
//
// FAIL-OPEN is the load-bearing property, identical to searchsvc_client.go: an
// unset --service-url is a silent no-op (nothing to push to); a reachable-but-
// failing service (refused/closed/timed-out connection, non-2xx, unparseable
// body) emits ONE loud "[searchsvc DEGRADED]" banner and returns a degraded
// result, NEVER a hard error. An embed run that also pushes must still succeed
// when the service is down — the local cache write is authoritative, the push is
// an optimization.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// errIngestBatchUnsupported is the sentinel postIngestBatch returns when the
// service answers 404 for /ingest_batch — i.e. it is too old to expose the batch
// verb. pushChangedChunks treats this NOT as a failure but as the signal to fall
// back to the per-chunk /embed loop (the batch verb is purely additive).
var errIngestBatchUnsupported = errors.New("searchsvc: /ingest_batch not supported")

// reindexHTTPPath is the fixed /reindex route on a searchsvc instance — the
// service's own rebuild-from-resolved-DB verb (serve.py POST /reindex).
const reindexHTTPPath = "/reindex"

// ingestBatchHTTPPath is the fixed /ingest_batch route — the service's
// embed-and-ingest-a-LIST verb (serve.py POST /ingest_batch). The cold-push
// fast path: a full-corpus first push posts a HANDFUL of bounded batches here
// instead of one /embed per distinct chunk (O(N) round-trips).
const ingestBatchHTTPPath = "/ingest_batch"

// defaultIngestBatchSize bounds how many chunks ride in one /ingest_batch
// request, so a huge cold corpus is chunked into several bounded requests
// (bounded memory + request size on both ends) rather than one unbounded body.
// The push is still O(N/batch) requests — a handful for a typical corpus, vs the
// old O(N) per-chunk loop. The effective size is ingestBatchSize, resolved once
// at package init and honoring a DS_SEARCHSVC_INGEST_BATCH override.
const defaultIngestBatchSize = 128

// ingestBatchEnvVar is the env override for the /ingest_batch chunk count, for
// tuning the cold-push request size against a service's body limits without a
// rebuild. Parsed ONCE at package init (clamped to >=1); a missing/unparseable/
// non-positive value falls back LOUDLY to defaultIngestBatchSize, mirroring the
// rest of this file's fail-open-with-a-banner discipline.
const ingestBatchEnvVar = "DS_SEARCHSVC_INGEST_BATCH"

// ingestBatchSize is the effective /ingest_batch chunk count, resolved once at
// package init from DS_SEARCHSVC_INGEST_BATCH (clamped to >=1, loud fallback to
// defaultIngestBatchSize on an invalid value). A package-level int (not a const)
// so the env override binds; read-only after init, so concurrent pushes share it
// without synchronization.
var ingestBatchSize = resolveIngestBatchSize(os.Getenv(ingestBatchEnvVar))

// resolveIngestBatchSize parses a raw DS_SEARCHSVC_INGEST_BATCH value, clamping
// to >=1 and falling back loudly to defaultIngestBatchSize on any invalid input.
// Factored out so tests exercise the parse/clamp/fallback branches directly (no
// process-global init dependence). An empty value (unset) is the silent default;
// a present-but-bad value (unparseable or < 1) banners once and uses the default.
func resolveIngestBatchSize(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultIngestBatchSize
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		fmt.Fprintf(searchWarnOut,
			"[searchsvc DEGRADED] %s=%q is not an integer — using default batch size %d\n",
			ingestBatchEnvVar, raw, defaultIngestBatchSize)
		return defaultIngestBatchSize
	}
	if n < 1 {
		fmt.Fprintf(searchWarnOut,
			"[searchsvc DEGRADED] %s=%d must be >= 1 — using default batch size %d\n",
			ingestBatchEnvVar, n, defaultIngestBatchSize)
		return defaultIngestBatchSize
	}
	return n
}

// ingestClientTimeout bounds a push/reindex round-trip. A full /reindex over a
// large corpus can be slower than an interactive /search, so this is more
// generous than searchClientTimeout, but still bounded so a hung service
// degrades rather than wedging the embed run.
const ingestClientTimeout = 120 * time.Second

// metaIndexDigestKey is the meta-table key under which the last-pushed corpus
// digest is stashed (mirrors task_sources_fp). A push compares the current
// corpus digest against this value to compute the changed set and to short-
// circuit a no-op push.
const metaIndexDigestKey = "searchsvc_index_digest"

// metaIndexHashesKey stashes the newline-joined SORTED hash set of the corpus at
// the last push, so the next push can report a TRUE prune count (the hashes that
// left the corpus) — mirroring embedChunks' "drop rows whose hash is no longer
// live" tally rather than guessing from the digest alone.
const metaIndexHashesKey = "searchsvc_index_hashes"

// pushResult is the tally a push returns: how many chunks were sent to /embed,
// how many hashes left the corpus since the last push (pruned), whether a
// /reindex was triggered, and whether the run was degraded (service unset or
// unreachable — a loud, non-fatal no-op).
type pushResult struct {
	Pushed   int    `json:"pushed"`
	Pruned   int    `json:"pruned"`
	Reindex  bool   `json:"reindex"`
	Degraded bool   `json:"degraded"`
	Digest   string `json:"digest"`
	// Reconciled is true iff, after the reindex, the service-recorded index_meta
	// digest matched the digest we pushed (the cross-process digest cross-check).
	// It is false when the service recorded a different digest (drift, bannered)
	// OR no index_meta digest could be read (a never-recorded / absent table —
	// nothing to reconcile against). Always fail-open: false never aborts a push.
	Reconciled bool `json:"reconciled"`
}

// corpusDigest is the Go counterpart of ingest.py's corpus_digest: a sha256 over
// the SORTED distinct chunk hashes currently in doc_chunks. Deterministic
// regardless of row order, so an unchanged corpus digests identically and ANY
// add/remove/edit (an edit changes a hash) moves it. This is the freshness key
// the service-side index_meta digest is compared against.
func corpusDigest(db *sql.DB) (string, error) {
	rows, err := db.Query(`SELECT DISTINCT hash FROM doc_chunks`)
	if err != nil {
		return "", err
	}
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return "", err
		}
		hashes = append(hashes, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	return digestOfHashes(hashes), nil
}

// digestOfHashes is corpusDigest's pure core: the sha256 over the SORTED distinct
// chunk hashes (each followed by a "\n"). Factored out so a caller that already
// holds a doc_chunks snapshot (e.g. freshnessCheck, which reads the corpus once
// and shares it across digest + drift) derives the SAME digest without re-scanning
// the table. It sorts a copy, so the caller's slice order is untouched; passing the
// DISTINCT hash set yields a digest byte-identical to corpusDigest's.
func digestOfHashes(hashes []string) string {
	sorted := make([]string, len(hashes))
	copy(sorted, hashes)
	sort.Strings(sorted)
	sum := sha256.New()
	for _, h := range sorted {
		sum.Write([]byte(h))
		sum.Write([]byte("\n"))
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// chunkBody is one representative doc_chunks row the pusher sends: the embed text
// plus the per-chunk PROVENANCE (path → doc_path, heading) read from the same
// row. serve.py's /embed + /ingest_batch default these to "" so the wire fields
// are additive; threading them here lets cross-machine + cold-push chunks land
// with real provenance instead of waiting for a full /reindex.
type chunkBody struct {
	Text    string
	DocPath string
	Heading string
}

// liveChunkBodies returns one representative chunk per DISTINCT doc_chunks hash
// (identical hashes share identical bodies by construction — the hash IS the
// blob SHA of the body — so any representative embeds the same vector). The
// SELECT pulls path+heading alongside body so the pusher can carry the chunk's
// source into the request bodies. This is the SAME distinct-hash unit embedChunks
// works in, so the push set never re-sends duplicate content; the first row seen
// for a hash wins (a stable, deterministic representative under sorted-hash push).
func liveChunkBodies(db *sql.DB) (map[string]chunkBody, error) {
	rows, err := db.Query(`SELECT hash, body, path, heading FROM doc_chunks`)
	if err != nil {
		return nil, err
	}
	live := map[string]chunkBody{}
	for rows.Next() {
		var h, body, path, heading string
		if err := rows.Scan(&h, &body, &path, &heading); err != nil {
			rows.Close()
			return nil, err
		}
		if _, seen := live[h]; !seen {
			live[h] = chunkBody{Text: body, DocPath: path, Heading: heading}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return live, nil
}

// readPushedDigest returns the last-pushed corpus digest stashed in meta (the
// empty string when no push has happened yet — the safe default that makes the
// first push send the whole corpus).
func readPushedDigest(db *sql.DB) (string, error) {
	var d string
	err := db.QueryRow(`SELECT value FROM meta WHERE key=?`, metaIndexDigestKey).Scan(&d)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return d, nil
}

// writePushedDigest records the corpus digest just pushed so the next push can
// short-circuit (or compute the changed set) against it. Mirrors the
// task_sources_fp upsert idiom.
func writePushedDigest(db *sql.DB, digest string) error {
	_, err := db.Exec(
		`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		metaIndexDigestKey, digest,
	)
	return err
}

// readPushedHashes returns the sorted hash set stashed at the last push (empty
// when no push has happened — the first push prunes nothing).
func readPushedHashes(db *sql.DB) (map[string]bool, error) {
	var joined string
	err := db.QueryRow(`SELECT value FROM meta WHERE key=?`, metaIndexHashesKey).Scan(&joined)
	if err == sql.ErrNoRows {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, h := range strings.Split(joined, "\n") {
		if h != "" {
			out[h] = true
		}
	}
	return out, nil
}

// writePushedHashes stashes the sorted hash set just pushed so the next push can
// report a true prune count against it.
func writePushedHashes(db *sql.DB, hashes []string) error {
	_, err := db.Exec(
		`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		metaIndexHashesKey, strings.Join(hashes, "\n"),
	)
	return err
}

// ingestKnobsOnce latches the one-time effective-knob emission so the banner is
// printed at most ONCE per process (at the first real ingest), never per-chunk —
// the Go mirror of fusion.py binding + logging its knobs once at module load.
var ingestKnobsOnce sync.Once

// logEffectiveIngestKnobs emits ONE stderr line naming the EFFECTIVE Go-side
// ingest knobs — the resolved hybrid weights (SEARCHSVC_W_DENSE / W_SPARSE) and
// the resolved /ingest_batch size (DS_SEARCHSVC_INGEST_BATCH) — so an operator
// can confirm at a glance that an intended override actually took, the same
// audit-the-override discipline fusion.py._log_effective_knobs gives the Python
// fusion leg. With both legs logging, an operator sees the effective values on
// BOTH sides. sync.Once-guarded so this fires once per process (not per chunk),
// parse-once (the weights/batch size are already resolved once via their own
// latches), and FAIL-OPEN: it is a bookkeeping banner, never a gate on ingest.
func logEffectiveIngestKnobs() {
	ingestKnobsOnce.Do(func() {
		wDense, wSparse := resolveHybridWeights()
		fmt.Fprintf(searchWarnOut,
			"searchsvc/ingest: effective ingest knobs W_DENSE=%v W_SPARSE=%v %s=%d\n",
			wDense, wSparse, ingestBatchEnvVar, ingestBatchSize)
	})
}

// pushChangedChunks is the maintenance driver. It (1) computes the current corpus
// digest, (2) SHORT-CIRCUITS to a no-op when the corpus is unchanged since the
// last push (digest match) AND force is false, (3) otherwise POSTs every live
// distinct chunk body to the service's /embed (the resident accumulation path),
// (4) triggers a /reindex so the service rebuilds-and-prunes from its resolved
// DB, and (5) records the new digest + how many hashes left since the last push.
//
// FAIL-OPEN: an empty serviceURL is a silent no-op (Degraded=true, nothing to do).
// Any transport/HTTP failure emits ONE loud degraded banner and returns a
// degraded result with NO error — the embed run that called this still succeeds.
func pushChangedChunks(ctx context.Context, db *sql.DB, serviceURL string, force bool) (*pushResult, error) {
	res := &pushResult{}
	if strings.TrimSpace(serviceURL) == "" {
		// Nothing configured: a silent no-op, no banner (mirrors trySearchService
		// on an unset URL). The embed run proceeds against the local cache only.
		res.Degraded = true
		return res, nil
	}

	// Ingest start: emit the effective Go-side knobs ONCE (sync.Once), mirroring
	// fusion.py's load-time knob log so an operator sees both legs' effective values.
	logEffectiveIngestKnobs()

	digest, err := corpusDigest(db)
	if err != nil {
		return nil, err
	}
	res.Digest = digest

	prevDigest, err := readPushedDigest(db)
	if err != nil {
		return nil, err
	}
	if !force && prevDigest == digest {
		// Corpus unchanged since the last push: no chunks to send, no reindex.
		return res, nil
	}

	prevHashes, err := readPushedHashes(db)
	if err != nil {
		return nil, err
	}

	live, err := liveChunkBodies(db)
	if err != nil {
		return nil, err
	}

	// Push every distinct live chunk body to the service's resident accumulation
	// path in BOUNDED BATCHES via /ingest_batch — the cold-push fast path that
	// cuts a full-corpus first push from O(N) /embed round-trips to a handful of
	// requests. Order is stable so a partial-failure point is reproducible. The
	// first transport/HTTP failure fails OPEN: we banner once and return a
	// degraded result WITHOUT recording the digest (so the next run retries the
	// push), never a hard error.
	hashes := make([]string, 0, len(live))
	for h := range live {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)

	client := &http.Client{Timeout: ingestClientTimeout}
	// The batch verb is the fast path, but it is ADDITIVE: a service too old to
	// expose /ingest_batch answers 404, in which case we transparently fall back
	// to the per-chunk /embed loop (the original O(N) path) so an older service
	// still ingests. errIngestBatchUnsupported is the once-per-push latch for that
	// fallback — we never retry the batch verb after the first 404.
	batchUnsupported := false
	for start := 0; start < len(hashes); start += ingestBatchSize {
		end := start + ingestBatchSize
		if end > len(hashes) {
			end = len(hashes)
		}
		batchHashes := hashes[start:end]

		if !batchUnsupported {
			bodies := make([]chunkBody, 0, len(batchHashes))
			for _, h := range batchHashes {
				bodies = append(bodies, live[h])
			}
			err := postIngestBatch(ctx, client, serviceURL, bodies)
			if err == nil {
				res.Pushed += len(bodies)
				continue
			}
			if !errors.Is(err, errIngestBatchUnsupported) {
				ingestDegraded("%v", err)
				res.Degraded = true
				return res, nil
			}
			// Older service: latch the fallback and re-send THIS batch per-chunk.
			batchUnsupported = true
		}

		// Per-chunk fallback (also handles the latched batch above).
		for _, h := range batchHashes {
			if err := postEmbedIngest(ctx, client, serviceURL, live[h]); err != nil {
				ingestDegraded("%v", err)
				res.Degraded = true
				return res, nil
			}
			res.Pushed++
		}
	}

	// Ask the service to rebuild + prune from its resolved DB. A reindex failure
	// is also fail-open: the chunks were pushed into the resident index already;
	// the reindex is the prune/refresh step and its failure degrades, never fails.
	if err := postReindex(ctx, client, serviceURL); err != nil {
		ingestDegraded("%v", err)
		res.Degraded = true
		return res, nil
	}
	res.Reindex = true

	// Reconcile the digest we pushed against the digest the SERVICE recorded for
	// its just-rebuilt resident index (ingest.py record_index_meta → index_meta.
	// digest). Both derive from the SAME doc_chunks.hash identity in separate
	// processes; a mismatch means the service indexed a different corpus than we
	// pushed. FAIL-OPEN: a drift (or an unreadable index_meta) emits ONE loud
	// banner and is recorded on the result, NEVER a hard error — the push already
	// landed the chunks; this is a bookkeeping cross-check, not a gate.
	res.Reconciled = reconcileServiceDigest(db, digest)

	// Prune accounting MIRRORS the Go prune path (embeddings.go embedChunks):
	// count the hashes that were in the last-pushed corpus but are no longer live.
	// The service does the actual drop in /reindex from its resolved DB; this is
	// the observable tally of what left.
	res.Pruned = prunedSinceLastPush(prevHashes, live)

	if err := writePushedDigest(db, digest); err != nil {
		return nil, err
	}
	if err := writePushedHashes(db, hashes); err != nil {
		return nil, err
	}
	return res, nil
}

// prunedSinceLastPush counts the hashes present at the last push (prevHashes)
// that are no longer in the current live set — the chunks whose content left the
// corpus. Mirrors embedChunks' "hash no longer on disk" prune membership test.
func prunedSinceLastPush(prevHashes map[string]bool, live map[string]chunkBody) int {
	n := 0
	for h := range prevHashes {
		if _, ok := live[h]; !ok {
			n++
		}
	}
	return n
}

// freshnessCheck compares the current corpus digest against the last-pushed
// digest stashed in meta and returns whether the service's resident index is
// fresh (built from exactly the current corpus). A never-pushed index (empty
// stored digest) is reported NOT fresh — the safe default that tells a caller to
// push/reindex. This is the Go-side staleness signal surfaced alongside /search
// results.
type freshnessResult struct {
	Fresh         bool   `json:"fresh"`
	StoredDigest  string `json:"stored_digest"`
	CurrentDigest string `json:"current_digest"`
	// Drift is the COUNT of distinct chunk hashes that differ between the
	// last-pushed corpus (the hash set stashed at the last push) and the current
	// live corpus — i.e. the symmetric difference: chunks added since the push
	// PLUS chunks that left. It quantifies the staleness the digest compare only
	// reports as a yes/no bit, so the CLI banner can say "N chunks changed". A
	// fresh index (or a never-pushed one with no live chunks) has Drift 0; a
	// never-pushed index over a live corpus reports every live chunk as drifted
	// (the safe "everything is unabsorbed" reading that matches Fresh=false).
	Drift int `json:"drift"`
}

func freshnessCheck(db *sql.DB) (*freshnessResult, error) {
	// SINGLE doc_chunks snapshot: read the live distinct-hash bodies ONCE and
	// derive BOTH the current digest and the drift from it, instead of scanning
	// doc_chunks separately in corpusDigest AND in corpusDrift->liveChunkBodies.
	// The map keys are exactly the DISTINCT hash set corpusDigest digests, so the
	// digest is byte-identical; the drift uses the same snapshot's key set, so the
	// count is identical to the multi-scan version. Pure refactor, no behavior
	// change, same fail-open surface (a DB error still propagates as before).
	live, err := liveChunkBodies(db)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(live))
	for h := range live {
		hashes = append(hashes, h)
	}
	cur := digestOfHashes(hashes)

	stored, err := readPushedDigest(db)
	if err != nil {
		return nil, err
	}
	prev, err := readPushedHashes(db)
	if err != nil {
		return nil, err
	}
	drift := driftBetween(prev, live)
	return &freshnessResult{
		Fresh:         stored != "" && stored == cur,
		StoredDigest:  stored,
		CurrentDigest: cur,
		Drift:         drift,
	}, nil
}

// corpusDrift counts the distinct chunk hashes that differ between the
// last-pushed corpus (the sorted hash set stashed in meta) and the current live
// corpus — the symmetric difference: hashes the live corpus has that the push
// did NOT (added/edited since) plus hashes the push had that are no longer live
// (pruned). This is the changed-chunk COUNT that quantifies a stale verdict; it
// is 0 exactly when the two hash sets are identical (a fresh index). A
// never-pushed index has an empty stored set, so every live distinct hash counts
// as drifted — the safe "nothing absorbed yet" reading consistent with Fresh.
func corpusDrift(db *sql.DB) (int, error) {
	prev, err := readPushedHashes(db)
	if err != nil {
		return 0, err
	}
	live, err := liveChunkBodies(db)
	if err != nil {
		return 0, err
	}
	return driftBetween(prev, live), nil
}

// driftBetween is corpusDrift's pure core: the size of the symmetric difference
// between the last-pushed hash set (prev) and the current live distinct-hash set
// (the keys of live). Factored out so freshnessCheck, which already holds the
// liveChunkBodies snapshot, computes the drift WITHOUT a second doc_chunks scan —
// yielding the exact same count as the multi-scan corpusDrift on the same inputs.
func driftBetween(prev map[string]bool, live map[string]chunkBody) int {
	drift := 0
	for h := range live {
		if !prev[h] {
			drift++ // a live chunk the last push did not carry (added/edited)
		}
	}
	for h := range prev {
		if _, ok := live[h]; !ok {
			drift++ // a pushed chunk that has since left the corpus (pruned)
		}
	}
	return drift
}

// readServiceDigest reads back the digest the SERVICE recorded for its resident
// index — ingest.py record_index_meta writes a sha256-over-sorted-distinct-
// hashes digest into the single index_meta row (id=1). Returns ("", nil) when no
// index_meta row exists OR the index_meta table is absent (a bare DB the Python
// maintenance layer never wrote): both mean "no service digest to compare", the
// safe not-an-error answer that makes reconciliation a no-op rather than a drift.
// We must NOT hard-fail here — the table is owned by another process.
func readServiceDigest(db *sql.DB) (string, error) {
	var d string
	err := db.QueryRow(`SELECT digest FROM index_meta WHERE id=1`).Scan(&d)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		// An absent index_meta table surfaces as a generic error from the driver;
		// treat "no such table" as "no service digest" (a fresh DB), not a failure.
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return "", nil
		}
		return "", err
	}
	return d, nil
}

// reconcileServiceDigest cross-checks the digest we just pushed against the
// digest the service recorded for its rebuilt resident index (index_meta.digest).
// Both digests derive from the SAME doc_chunks.hash identity computed in separate
// processes, so on an in-sync corpus they are byte-for-byte equal.
//
// Returns true iff a service digest exists AND equals pushedDigest. It FAILS OPEN
// in every other case: a read error or absent digest returns false silently
// (nothing to reconcile against — not a drift), and a PRESENT-but-different
// service digest emits ONE loud "[searchsvc DIGEST DRIFT]" banner and returns
// false — NEVER an error, so a bookkeeping mismatch can never abort a push.
func reconcileServiceDigest(db *sql.DB, pushedDigest string) bool {
	svc, err := readServiceDigest(db)
	if err != nil {
		// Couldn't read the service digest: degrade quietly, nothing to reconcile.
		ingestDegraded("could not read service index_meta digest for reconcile: %v", err)
		return false
	}
	if svc == "" {
		// Service never recorded a digest (fresh / never-reindexed-by-Python):
		// nothing to compare against. Not a drift, not a banner.
		return false
	}
	if svc != pushedDigest {
		fmt.Fprintf(searchWarnOut,
			"[searchsvc DIGEST DRIFT] pushed corpus digest %s != service index_meta digest %s — the resident index was NOT built from the pushed corpus; reconcile the pusher and the service DB\n",
			pushedDigest, svc)
		return false
	}
	return true
}

// postEmbedIngest POSTs one chunk to the service's /embed route (the resident
// accumulation path serve.py exposes), discarding the echo — the push only cares
// that the chunk landed resident-side. A non-2xx status or transport failure is
// returned as an error so pushChangedChunks fails open on it. Reuses the /embed
// contract serve.py documents: request {"text": ..., "doc_path": ..., "heading":
// ...}, where doc_path/heading carry the chunk's provenance (empty defaults
// preserve text-only callers) so a streamed chunk lands with real provenance
// without waiting for a /reindex.
func postEmbedIngest(ctx context.Context, client *http.Client, serviceURL string, c chunkBody) error {
	body, err := json.Marshal(map[string]string{
		"text":     c.Text,
		"doc_path": c.DocPath,
		"heading":  c.Heading,
	})
	if err != nil {
		return fmt.Errorf("encoding embed request: %w", err)
	}
	endpoint := joinEmbedURL(serviceURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building embed request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("searchsvc %q unreachable: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("searchsvc %q returned HTTP %d: %s", endpoint, resp.StatusCode, snippet(raw))
	}
	return nil
}

// postIngestBatch POSTs a LIST of chunks to the service's /ingest_batch route
// (serve.py POST /ingest_batch) — the cold-push fast path that embeds + ingests
// many chunks in one request. The request body is {"chunks":[{"text": ...,
// "doc_path": ..., "heading": ...}, ...]}, matching serve.py's IngestChunk /
// IngestBatchRequest: each chunk carries its provenance so cold-pushed chunks
// land with real doc_path/heading (empty defaults preserve text-only callers).
// The echo (an ingested count + chunk_hashes) is not consumed beyond the status
// check — the push only needs the chunks to have landed resident-side. A non-2xx
// status or transport failure is an error so pushChangedChunks fails open on it.
func postIngestBatch(ctx context.Context, client *http.Client, serviceURL string, bodies []chunkBody) error {
	chunks := make([]map[string]string, 0, len(bodies))
	for _, c := range bodies {
		chunks = append(chunks, map[string]string{
			"text":     c.Text,
			"doc_path": c.DocPath,
			"heading":  c.Heading,
		})
	}
	body, err := json.Marshal(map[string]any{"chunks": chunks})
	if err != nil {
		return fmt.Errorf("encoding ingest_batch request: %w", err)
	}
	endpoint := joinIngestBatchURL(serviceURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building ingest_batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("searchsvc %q unreachable: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Service too old to expose the batch verb: signal the per-chunk fallback
		// rather than failing the push. (Body drained via the deferred Close.)
		return errIngestBatchUnsupported
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("searchsvc %q returned HTTP %d: %s", endpoint, resp.StatusCode, snippet(raw))
	}
	return nil
}

// joinIngestBatchURL appends the fixed /ingest_batch route to a base URL,
// collapsing a trailing slash and tolerating an over-specified base that already
// ends in the route. The /ingest_batch analogue of joinEmbedURL / joinReindexURL.
func joinIngestBatchURL(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(base, ingestBatchHTTPPath) {
		return base
	}
	return base + ingestBatchHTTPPath
}

// postReindex POSTs to the service's /reindex route, asking it to rebuild + prune
// both resident legs from its resolved DB. The response body is not consumed
// beyond the status check — the counts the service returns are its own, the push
// only needs the rebuild to have happened. A non-2xx/transport failure is an
// error so the caller fails open.
func postReindex(ctx context.Context, client *http.Client, serviceURL string) error {
	endpoint := joinReindexURL(serviceURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return fmt.Errorf("building reindex request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("searchsvc %q unreachable: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("searchsvc %q returned HTTP %d: %s", endpoint, resp.StatusCode, snippet(raw))
	}
	return nil
}

// joinReindexURL appends the fixed /reindex route to a base URL, collapsing a
// trailing slash and tolerating an over-specified base that already ends in the
// route. The /reindex analogue of joinEmbedURL / joinSearchURL.
func joinReindexURL(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(base, reindexHTTPPath) {
		return base
	}
	return base + reindexHTTPPath
}

// backfillProvenanceHTTPPath is the fixed /backfill_provenance route on a
// searchsvc instance (serve.py POST /backfill_provenance) — the TARGETED heal
// that re-resolves provenance for resident chunks that landed with EMPTY
// doc_path/heading (streamed before the provenance-pushers fix) from the index
// DB, WITHOUT a full /reindex.
const backfillProvenanceHTTPPath = "/backfill_provenance"

// backfillResult is the tally a backfill trigger returns: how many resident
// chunks were healed (provenance re-resolved), and whether the run was degraded
// (service unset or unreachable — a loud, non-fatal no-op). It mirrors the
// service-side summary so a caller can surface what the heal did.
type backfillResult struct {
	Healed   int  `json:"healed"`
	Degraded bool `json:"degraded"`
}

// triggerBackfillProvenance asks a running searchsvc to heal resident chunks
// that carry EMPTY provenance (doc_path/heading) — the chunks streamed BEFORE
// the provenance-pushers change, which would otherwise stay empty until the next
// full /reindex. It is a cheap, targeted alternative to pushChangedChunks+reindex
// when the corpus itself is unchanged but the resident metadata is stale.
//
// FAIL-OPEN, identical to pushChangedChunks: an empty serviceURL is a silent
// no-op (Degraded=true, nothing to call); any transport/HTTP failure emits ONE
// loud "[searchsvc DEGRADED]" banner and returns a degraded result with NO error
// — a backfill is an optimization, never a gate on the embed run that triggers it.
func triggerBackfillProvenance(ctx context.Context, serviceURL string) (*backfillResult, error) {
	res := &backfillResult{}
	if strings.TrimSpace(serviceURL) == "" {
		// Nothing configured: a silent no-op (mirrors pushChangedChunks).
		res.Degraded = true
		return res, nil
	}
	client := &http.Client{Timeout: ingestClientTimeout}
	healed, err := postBackfillProvenance(ctx, client, serviceURL)
	if err != nil {
		ingestDegraded("%v", err)
		res.Degraded = true
		return res, nil
	}
	res.Healed = healed
	return res, nil
}

// postBackfillProvenance POSTs to the service's /backfill_provenance route and
// returns the "healed" count the service reports. A non-2xx status or transport
// failure is returned as an error so triggerBackfillProvenance fails open on it.
// The body is parsed best-effort: a 2xx with an unreadable/healed-less body still
// succeeds (healed 0) rather than turning a successful heal into a degraded run.
func postBackfillProvenance(ctx context.Context, client *http.Client, serviceURL string) (int, error) {
	endpoint := joinBackfillProvenanceURL(serviceURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return 0, fmt.Errorf("building backfill_provenance request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("searchsvc %q unreachable: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("searchsvc %q returned HTTP %d: %s", endpoint, resp.StatusCode, snippet(raw))
	}
	var parsed struct {
		Healed int `json:"healed"`
	}
	raw, _ := io.ReadAll(resp.Body)
	// A 2xx with an unparseable body is a successful heal we just can't tally —
	// report 0 healed, not an error (the heal already ran service-side).
	_ = json.Unmarshal(raw, &parsed)
	return parsed.Healed, nil
}

// joinBackfillProvenanceURL appends the fixed /backfill_provenance route to a
// base URL, collapsing a trailing slash and tolerating an over-specified base
// that already ends in the route. The /backfill_provenance analogue of
// joinEmbedURL / joinReindexURL.
func joinBackfillProvenanceURL(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(base, backfillProvenanceHTTPPath) {
		return base
	}
	return base + backfillProvenanceHTTPPath
}

// ingestDegraded writes one loud, lock-server-style banner to searchWarnOut (the
// same sink searchsvc_client.go's searchDegraded uses), so an operator sees the
// push ran degraded (service down → local cache only). It never returns an
// error: degradation is announced, not fatal.
func ingestDegraded(format string, args ...any) {
	fmt.Fprintf(searchWarnOut, "[searchsvc DEGRADED] "+format+" — pushed nothing; local cache is authoritative\n", args...)
}
