# SPDX-License-Identifier: Apache-2.0
#
# index_store.py — the resident dense index for searchsvc's brute-force KNN.
#
# CHARTER: hold the dense side of the hybrid index entirely in memory as a single
# L2-normalized numpy matrix (N x D), an ordered list of chunk hashes parallel to
# the matrix rows, and a per-chunk metadata map (doc_path / heading). dense.py
# does the cosine scan over this matrix; this module owns building / refreshing it.
#
# WHERE THE ROWS COME FROM (single-host design, two complementary sources):
#   1. /embed ingests — serve.py (or any caller) pushes already-embedded chunks in
#      via DenseIndex.ingest(...). This is the live accumulation path.
#   2. local taskdb.sqlite — refresh_from_sqlite(...) reads the doc_chunks table
#      (path, heading, body, hash) and, where the chunk_embeddings cache already
#      holds a dense vector for that hash, decodes it; otherwise it embeds the
#      chunk body with the deterministic hermetic embedder (fake_embed). Both are
#      keyed on the SAME stable content hash the Go side writes (doc_chunks.hash),
#      so the two sources are row-equivalent.
#
# DISCIPLINE:
#   - Dense width = whatever the embedder emits (256 in the hermetic fake). The
#     index records dense_dims from the first row and REFUSES a later row of a
#     different width (a width drift is a model swap, never a silent mix).
#   - Every row is L2-normalized at ingest so dense.py's cosine is a single dot
#     product over the resident matrix (norms are all 1, so dot == cosine).
#   - Ordering is insertion order, deduped by chunk_hash (re-ingesting a hash
#     overwrites its row in place) — so the chunk_hash index stays a stable,
#     deterministic parallel array for tie-broken ranking downstream.
#
# PURE NUMPY. No FAISS / sqlite-vec / pgvector. No torch, no model, no GPU.

import binascii
import os
import sqlite3
import struct

import numpy as np

import fake_embed

# The packed-BLOB layout the Go side writes (see embeddings.go encodeVector /
# encodeSparse): dense is a little-endian float32 array; we only need the dense
# leg here. Sparse decoding is sparse.py's concern, not the dense index's.


def _l2_normalize(vec):
    """Return a float32 L2-normalized copy of vec. A zero vector stays zero
    (cosine against it is a well-defined 0, never a divide-by-zero NaN)."""
    arr = np.asarray(vec, dtype=np.float32)
    norm = float(np.linalg.norm(arr))
    if norm > 0.0:
        arr = arr / norm
    return arr.astype(np.float32, copy=False)


def _decode_dense_blob(blob):
    """Decode a packed little-endian float32 BLOB (encodeVector's format) into a
    list[float]. A length not a multiple of 4 is corrupt — raise loudly."""
    if blob is None:
        return None
    if len(blob) % 4 != 0:
        raise ValueError(
            "corrupt dense BLOB: length %d is not a multiple of 4" % len(blob)
        )
    count = len(blob) // 4
    return list(struct.unpack("<%df" % count, blob))


def _decode_one(blob):
    """Decode one cache row's vector BLOB to a list[float], defensively tolerating
    a hex-encoded string (Go writes raw bytes, but a sqlite roundtrip could hand
    back text). Returns None for an unusable/empty blob."""
    if isinstance(blob, str):
        try:
            blob = binascii.unhexlify(blob)
        except (binascii.Error, ValueError):
            return None
    return _decode_dense_blob(blob)


class DenseIndex:
    """In-memory dense index: an (N x D) L2-normalized matrix + a parallel
    ordered chunk_hash array + per-chunk metadata + the recorded dense_dims.

    The matrix is rebuilt lazily (matrix() / dims) from a dict keyed on
    chunk_hash so ingests dedupe and stay deterministic in insertion order."""

    def __init__(self):
        # chunk_hash -> normalized float32 row (1-D np.ndarray of width dims)
        self._rows = {}
        # chunk_hash -> {"doc_path": str, "heading": str}
        self._meta = {}
        # insertion order of chunk hashes (stable, dedup-aware)
        self._order = []
        # recorded dense width; None until the first row lands
        self._dims = None
        # cached materialized matrix + parallel hash list (invalidated on ingest)
        self._matrix = None
        self._hashes = None

    # -- introspection ------------------------------------------------------

    @property
    def dense_dims(self):
        """The recorded dense width, or None if the index is empty."""
        return self._dims

    def __len__(self):
        return len(self._order)

    def chunk_hashes(self):
        """The ordered chunk_hash array parallel to matrix() rows."""
        self._materialize()
        return list(self._hashes)

    def metadata(self, chunk_hash):
        """Per-chunk {"doc_path", "heading"} for a hash (empty dict if unknown)."""
        return dict(self._meta.get(chunk_hash, {}))

    # -- ingest -------------------------------------------------------------

    def ingest(self, chunk_hash, dense, doc_path="", heading=""):
        """Add or replace one chunk's dense row. `dense` is any length-D sequence
        of floats (it is L2-normalized here). Width must match the recorded
        dense_dims once the index is non-empty — a mismatch is a LOUD error, never
        a silently truncated/zeroed row."""
        row = _l2_normalize(dense)
        width = int(row.shape[0])
        if self._dims is None:
            self._dims = width
        elif width != self._dims:
            raise ValueError(
                "dense width mismatch on ingest of %r: row width %d != index dense_dims %d"
                % (chunk_hash, width, self._dims)
            )
        if chunk_hash not in self._rows:
            self._order.append(chunk_hash)
        self._rows[chunk_hash] = row
        self._meta[chunk_hash] = {"doc_path": doc_path, "heading": heading}
        self._invalidate()

    def ingest_text(self, chunk_hash, body, doc_path="", heading=""):
        """Embed `body` with the hermetic fake embedder and ingest its dense row.
        Used by the sqlite refresh path when the chunk has no cached vector."""
        self.ingest(chunk_hash, fake_embed.fake_dense(body), doc_path, heading)

    # -- matrix materialization --------------------------------------------

    def _invalidate(self):
        self._matrix = None
        self._hashes = None

    def _materialize(self):
        if self._matrix is not None:
            return
        if not self._order:
            self._matrix = np.zeros((0, self._dims or 0), dtype=np.float32)
            self._hashes = []
            return
        self._hashes = list(self._order)
        self._matrix = np.vstack([self._rows[h] for h in self._hashes]).astype(
            np.float32, copy=False
        )

    def matrix(self):
        """The resident (N x D) L2-normalized float32 matrix. Rows are in the
        same order as chunk_hashes(). Rebuilt lazily after any ingest."""
        self._materialize()
        return self._matrix

    # -- sqlite refresh -----------------------------------------------------

    def refresh_from_sqlite(self, db_path, limit=None):
        """Build/extend the index from a local taskdb.sqlite.

        Reads doc_chunks (path, heading, body, hash). If chunk_embeddings already
        holds a dense vector for that hash it is decoded (the live-cache fast
        path); otherwise the chunk body is embedded with the hermetic fake. Single
        host: this is a direct read of the local DB, no network. Returns the
        number of rows ingested."""
        if not os.path.exists(db_path):
            raise FileNotFoundError("taskdb.sqlite not found at %r" % db_path)
        # read-only, immutable open so a live writer is never blocked/corrupted.
        uri = "file:%s?mode=ro&immutable=1" % os.path.abspath(db_path)
        conn = sqlite3.connect(uri, uri=True)
        try:
            cached = self._load_cached_dense(conn)
            sql = "SELECT hash, path, heading, body FROM doc_chunks ORDER BY id"
            if limit is not None:
                sql += " LIMIT %d" % int(limit)
            n = 0
            for chunk_hash, path, heading, body in conn.execute(sql):
                entry = cached.get(chunk_hash)
                if entry is not None:
                    dense, recorded_dims, model = entry
                    width = len(dense)
                    # The Go writer records dims alongside the packed vector; a
                    # decoded width that disagrees with the recorded dims is a
                    # corrupt/mis-encoded cache row — raise LOUDLY (mirrors
                    # DenseIndex.ingest's width-mismatch error) rather than
                    # silently indexing a wrong-width vector.
                    if recorded_dims is not None and width != int(recorded_dims):
                        raise ValueError(
                            "dense cache width mismatch for %r (model %r): decoded "
                            "width %d != recorded dims %d"
                            % (chunk_hash, model, width, int(recorded_dims))
                        )
                    self.ingest(chunk_hash, dense, path, heading or "")
                else:
                    self.ingest_text(chunk_hash, body, path, heading or "")
                n += 1
            return n
        finally:
            conn.close()

    @staticmethod
    def _load_cached_dense(conn):
        """chunk_hash -> (decoded dense list, recorded dims, model) from
        chunk_embeddings, or {} when the cache table is absent/empty. Decodes the
        packed float32 BLOB the Go side writes (encodeVector) and also reads the
        dims + model columns the Go schema persists so refresh_from_sqlite can tie
        each row's recorded dense_dims to its producing model label and reject a
        width-vs-recorded mismatch loudly. Older/narrower caches that lack the
        dims/model columns degrade to None for those fields (no width check)."""
        try:
            cur = conn.execute(
                "SELECT chunk_hash, vector, dims, model FROM chunk_embeddings"
            )
        except sqlite3.OperationalError:
            # A pre-schema cache without dims/model columns: fall back to the
            # narrow shape (still decode the vector; no recorded-width to check).
            try:
                cur = conn.execute(
                    "SELECT chunk_hash, vector FROM chunk_embeddings"
                )
            except sqlite3.OperationalError:
                return {}
            out = {}
            for chunk_hash, blob in cur:
                decoded = _decode_one(blob)
                if decoded:
                    out[chunk_hash] = (decoded, None, None)
            return out
        out = {}
        for chunk_hash, blob, dims, model in cur:
            decoded = _decode_one(blob)
            if decoded:
                out[chunk_hash] = (decoded, dims, model)
        return out


# ---------------------------------------------------------------------------
# Module-level singleton — dense.py manages its store internally (serve.py calls
# dense_search with NO store arg), so the index is a lazily-built module global.
# ---------------------------------------------------------------------------

_INDEX = None


# ---------------------------------------------------------------------------
# Shared DB resolver — the SINGLE source of truth both the dense (this module)
# and sparse (sparse.py imports resolve_db_path) legs use, so they NEVER index
# two different DBs. Precedence (first hit wins): SEARCHSVC_DB (the dense winner —
# test_dense.test_get_index_uses_env_db monkeypatches it), then the two
# historical taskdb env aliases TASKDB_SQLITE / TASKDB_DB reconciled here, then
# the repo-root taskdb.sqlite found by walking up from this file. An env value is
# honored even if it does not exist on disk so callers see WHERE they pointed
# (the caller's own missing-DB grace handles the absent file); only the
# relative-fallback candidates are existence-gated. Returns None if nothing
# resolves.
_DB_ENV_VARS = ("SEARCHSVC_DB", "TASKDB_SQLITE", "TASKDB_DB")


def resolve_db_path():
    """Resolve the single taskdb.sqlite both retrieval legs index.

    SEARCHSVC_DB takes precedence (the dense leg's documented override), then the
    TASKDB_SQLITE / TASKDB_DB aliases, then the repo-root fallback relative to this
    file. Returns the first env var that is set (whether or not it exists on disk,
    so a typo'd path surfaces instead of silently sliding to a different DB), else
    the first existing relative fallback, else None."""
    for env in _DB_ENV_VARS:
        p = os.environ.get(env)
        if p:
            return p
    here = os.path.dirname(os.path.abspath(__file__))
    for rel in ("taskdb.sqlite", os.path.join("..", "taskdb.sqlite"),
                os.path.join("..", "..", "..", "taskdb.sqlite")):
        cand = os.path.normpath(os.path.join(here, rel))
        if os.path.exists(cand):
            return cand
    return None


def _default_db_path():
    """Locate the local taskdb.sqlite for the dense singleton build. Delegates to
    the shared resolve_db_path() (SEARCHSVC_DB-first), then drops an env path that
    does not exist so get_index() starts empty rather than raising at refresh.
    Returns None if nothing usable is found."""
    p = resolve_db_path()
    if p and os.path.exists(p):
        return p
    return None


def get_index():
    """Return the process-wide DenseIndex, building it on first use from the
    local taskdb.sqlite if one is locatable. An absent DB yields an empty index
    (searches return []), never an error — the live /embed ingest path can still
    populate it."""
    global _INDEX
    if _INDEX is None:
        idx = DenseIndex()
        db = _default_db_path()
        if db is not None:
            try:
                idx.refresh_from_sqlite(db)
            except Exception:
                # A bad/locked DB must not wedge search; start empty and let the
                # /embed ingest path fill the index.
                pass
        _INDEX = idx
    return _INDEX


def set_index(index):
    """Install a prebuilt DenseIndex as the singleton (tests / explicit refresh)."""
    global _INDEX
    _INDEX = index
    return _INDEX


def reset_index():
    """Drop the singleton so the next get_index() rebuilds (tests)."""
    global _INDEX
    _INDEX = None
