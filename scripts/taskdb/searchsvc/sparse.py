# SPDX-License-Identifier: Apache-2.0
#
# sparse.py — searchsvc's SPARSE lexical retrieval leg (doc 22 §8, decision D9).
#
# CHARTER: implement sparse_search(query_sparse, top_k=...) — the lexical half of
# taskdb's hybrid (dense + sparse) search. serve.py's /search route ALREADY calls
#   sparse.sparse_search(query_sparse, top_k=top_k)
# via a lazy import, where query_sparse is the {token_id: weight} map produced by
# the embedder (fake_embed.fake_sparse in the hermetic path, BGE-M3's learned
# lexical-weight map on the live path). serve.py is LANDED and is NEVER edited by
# this unit — this module just appears beside it and fills in the sparse leg.
#
# SCORING: each chunk is scored as the lexical DOT PRODUCT over SHARED token-ids,
#   score(chunk) = sum_t  w_query[t] * w_chunk[t]   for t in (query ∩ chunk)
# i.e. the sum of per-token weight products over the tokens both the query and the
# chunk carry. A chunk that shares NO tokens with the query scores EXACTLY 0.0 (a
# missing leg is a clean zero, never NaN). This mirrors BGE-M3's lexical scoring
# (a sparse dot product over the lexical-weight vocab) without any model. FTS5 /
# BM25 as a *third* signal is a deferred follow-up and is intentionally NOT here.
#
# STORE: sparse_search manages its OWN store internally so it matches serve.py's
# no-store call signature (no `store` positional). The store maps
#   chunk_hash -> {token_id: weight}
# — exactly the shape the Go writer persists in chunk_embeddings.sparse_vector (a
# packed (uint32 token_id, float32 weight) blob; see embeddings.go encodeSparse).
# The default resident store is loaded lazily from the taskdb sqlite DB the first
# time it is needed; tests inject a synthetic store directly via set_store() /
# load_store(), so the scoring stays a pure, hermetic, model-free function.
#
# HYBRID-ROW GRACE: a chunk may be sparse-only, dense-only, or both. This module
# only consumes the sparse map; a chunk that is dense-only (no sparse map, or an
# empty one) simply contributes no shared tokens and scores 0 — it never crashes
# and never produces NaN. A dense-missing row is irrelevant to the sparse leg.
#
# This module imports ONLY the stdlib. It must NEVER import torch.

import os
import struct

# ---------------------------------------------------------------------------
# Resident store: chunk_hash -> {token_id(int): weight(float)}.
# ---------------------------------------------------------------------------

# The in-memory store of chunk sparse maps. None means "not yet loaded"; an empty
# dict means "loaded, but no chunks" (a valid, fully-degraded state that scores
# nothing rather than crashing). Tests replace this directly via set_store().
_STORE = None

# Packed sparse blob layout, mirroring embeddings.go: little-endian
# (uint32 token_id, float32 weight) pairs, ascending token_id. 8 bytes per term.
_SPARSE_ENTRY = struct.Struct("<If")
_SPARSE_ENTRY_BYTES = _SPARSE_ENTRY.size  # 8


def set_store(store):
    """Install a resident sparse store: {chunk_hash: {token_id: weight}}.

    Used by tests (and by an explicit reload) to inject a synthetic store so the
    scoring path is exercised hermetically with no DB, no model. Keys are chunk
    hashes (str); values are {int token_id -> float weight} maps. A None resets
    the store so the next search lazily reloads from the DB."""
    global _STORE
    if store is None:
        _STORE = None
        return
    # Normalize into the canonical {str: {int: float}} shape and defensively
    # copy so a caller mutating their dict can't corrupt the resident index.
    norm = {}
    for chunk_hash, smap in store.items():
        norm[chunk_hash] = {int(tid): float(w) for tid, w in (smap or {}).items()}
    _STORE = norm


def reset_store():
    """Drop the resident store so the next sparse_search reloads it lazily."""
    set_store(None)


def _decode_sparse_blob(blob):
    """Decode a packed (uint32 token_id, float32 weight) BLOB into a
    {token_id: weight} dict, mirroring embeddings.go decodeSparse. A nil/empty
    blob is a valid EMPTY sparse vector (-> {}). A length that is not a multiple
    of the 8-byte entry width is corrupt and rejected LOUDLY (never silently
    truncated to a wrong, lower-scoring vector)."""
    if not blob:
        return {}
    if len(blob) % _SPARSE_ENTRY_BYTES != 0:
        raise ValueError(
            "corrupt sparse_vector blob: length %d is not a multiple of %d"
            % (len(blob), _SPARSE_ENTRY_BYTES)
        )
    out = {}
    for off in range(0, len(blob), _SPARSE_ENTRY_BYTES):
        tid, weight = _SPARSE_ENTRY.unpack_from(blob, off)
        out[int(tid)] = float(weight)
    return out


def _db_path():
    """Resolve the taskdb sqlite path for the lazy DB load.

    Delegates to index_store.resolve_db_path() — the SINGLE shared resolver — so
    the sparse leg loads from the EXACT SAME DB the dense leg indexes (precedence
    SEARCHSVC_DB > TASKDB_SQLITE > TASKDB_DB > repo-root fallback). Previously this
    read ONLY TASKDB_DB and returned an existence-blind repo-root path, so the two
    legs could index different DBs; routing both through resolve_db_path() closes
    that drift. Falls back to the historical repo-root path only if the shared
    resolver finds nothing (None)."""
    import index_store

    p = index_store.resolve_db_path()
    if p:
        return p
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", "..", ".."))
    return os.path.join(repo_root, "taskdb.sqlite")


def ingest(chunk_hash, sparse_map):
    """ADDITIVELY add or replace ONE chunk's sparse map in the resident store.

    Unlike set_store (which REPLACES the whole store), this mirrors
    DenseIndex.ingest: it lazily loads the resident store if absent, then upserts
    a single chunk in place — re-ingesting a hash overwrites its map, leaving every
    other chunk untouched. `sparse_map` is normalized to {int token_id: float
    weight}; an empty/None map records an empty sparse vector for the chunk (a
    dense-only row contributes no shared tokens and simply scores 0). Used by the
    live /embed ingest path so a streamed chunk augments the store rather than
    wiping it."""
    global _STORE
    if _STORE is None:
        _ensure_store()
    _STORE[chunk_hash] = {
        int(tid): float(w) for tid, w in (sparse_map or {}).items()
    }
    return _STORE


def load_store(db_path=None):
    """Load the resident sparse store from the taskdb sqlite DB.

    Reads chunk_embeddings(chunk_hash, sparse_vector) and decodes each packed
    blob into a {token_id: weight} map. Missing DB / missing table / missing
    sparse column degrade to an EMPTY store (search returns no hits) rather than
    raising — the sparse leg stays standable before any chunks are indexed. The
    decode itself still rejects a *corrupt* (mis-sized) blob loudly.

    Returns the loaded store and installs it as the resident store."""
    import sqlite3

    path = db_path or _db_path()
    store = {}
    if os.path.exists(path):
        try:
            conn = sqlite3.connect(path)
            try:
                cur = conn.execute(
                    "SELECT chunk_hash, sparse_vector FROM chunk_embeddings"
                )
                for chunk_hash, blob in cur.fetchall():
                    smap = _decode_sparse_blob(blob)
                    if smap:
                        store[chunk_hash] = smap
            finally:
                conn.close()
        except sqlite3.Error:
            # No chunk_embeddings table / no sparse column yet -> empty store.
            store = {}
    set_store(store)
    return _STORE


def _ensure_store():
    """Return the resident store, lazily loading it from the DB on first use."""
    global _STORE
    if _STORE is None:
        load_store()
    return _STORE


# ---------------------------------------------------------------------------
# Scoring.
# ---------------------------------------------------------------------------


def sparse_score(query_sparse, chunk_sparse):
    """Lexical dot product over SHARED token-ids:
        sum_t  query[t] * chunk[t]   for t in (query ∩ chunk).

    No shared tokens -> EXACTLY 0.0 (never NaN). Iterates the SMALLER map for the
    intersection so it stays cheap regardless of which side is sparser."""
    if not query_sparse or not chunk_sparse:
        return 0.0
    # Iterate the smaller side; look the other up.
    if len(query_sparse) <= len(chunk_sparse):
        small, big = query_sparse, chunk_sparse
    else:
        small, big = chunk_sparse, query_sparse
    total = 0.0
    for tid, w in small.items():
        other = big.get(int(tid))
        if other is not None:
            total += float(w) * float(other)
    return total


def sparse_search(query_sparse, top_k=10, store=None):
    """Rank stored chunks by sparse lexical dot score against query_sparse.

    query_sparse: {token_id: weight} — the embedder's sparse lexical map for the
    query (fake_embed.fake_sparse in the hermetic path). JSON object keys arrive
    as strings on the wire, so token-ids are coerced to int defensively.

    Returns a list of (chunk_hash, sparse_score) sorted by score DESCENDING, with
    a stable, deterministic tie-break on chunk_hash (ascending) so equal-scoring
    chunks rank in a fixed order. Chunks that share no tokens score EXACTLY 0 and
    are dropped (they carry no lexical signal); if NOTHING scores > 0 the result
    is empty. top_k <= 0 returns an empty list.

    The `store` parameter is an OPTIONAL test/override hook ({chunk_hash:
    {token_id: weight}}); serve.py never passes it (it calls the no-store
    signature) and the module manages its own resident store internally."""
    if top_k is not None and top_k <= 0:
        return []

    # Coerce wire-string token-id keys to int so a JSON-decoded query still
    # intersects the int-keyed store.
    q = {int(tid): float(w) for tid, w in (query_sparse or {}).items()}

    index = store if store is not None else _ensure_store()

    scored = []
    for chunk_hash, chunk_sparse in index.items():
        s = sparse_score(q, chunk_sparse)
        if s > 0.0:
            scored.append((chunk_hash, s))

    # Descending score; ascending chunk_hash as a deterministic tie-break.
    scored.sort(key=lambda pair: (-pair[1], pair[0]))

    if top_k is None:
        return scored
    return scored[:top_k]
