# SPDX-License-Identifier: Apache-2.0
#
# ingest.py — searchsvc's maintenance layer over the local taskdb.sqlite: the
# bookkeeping the LANDED POST /reindex route calls underneath its in-memory
# rebuild. Three concerns, all keyed on the SAME stable content hash the Go side
# writes (doc_chunks.hash == gitBlobSHA of the chunk body):
#
#   1. index_meta — a single-row table recording WHAT the resident index was
#      built from and HOW: the model label, the dense width, the sparse model,
#      the build timestamp, the chunk count, and a stable digest of the corpus.
#      /search can compare this stored digest against the current corpus digest
#      to surface a FRESHNESS/STALENESS signal (the resident index predates a
#      doc_chunks change) without re-reading every row.
#
#   2. upsert_chunk(s)_by_hash — write/refresh a doc_chunks row keyed on its
#      content hash. A re-upsert of an unchanged hash is idempotent (no churn);
#      an upsert of a NEW hash adds the row. This is the durable counterpart to
#      DenseIndex.ingest's in-memory upsert: the hash is the identity, so the
#      table never accumulates duplicate rows for the same content.
#
#   3. prune_vanished — drop doc_chunks rows whose source (a live hash set the
#      caller supplies) no longer exists. It MIRRORS the Go prune path
#      (cmd_doc.go syncDocs / embeddings.go embedChunks): collect the stale keys
#      first, then DELETE by key, never mutating while iterating.
#
# DB RESOLUTION: this module NEVER re-forks the env handling. It imports the
# unified resolver from index_store (resolve_db_path, SEARCHSVC_DB-first) so the
# maintenance layer, the dense leg, and the sparse leg all agree on WHICH DB they
# touch. A caller may also pass an explicit db_path to any function (tests, a
# single-host operator pointing at a specific file).
#
# PURE STDLIB + the shared resolver. No numpy, no torch, no model, no GPU, no
# network. The digest is a sha256 over sorted chunk hashes — deterministic and
# cheap, so freshness is a string compare, not a re-embed.

import hashlib
import sqlite3
import sys
import time

# Reuse the SINGLE source-of-truth DB resolver (SEARCHSVC_DB-first). Do NOT
# re-implement env precedence here — index_store owns it and sparse.py already
# imports it, so all three legs resolve identically.
from index_store import resolve_db_path

# index_meta is a single-row key table: id is pinned to 1 so an upsert always
# targets the same row (a fresh build OVERWRITES the prior signature rather than
# appending). The columns are the index's provenance, not the corpus itself.
_INDEX_META_DDL = """
CREATE TABLE IF NOT EXISTS index_meta (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    model_label  TEXT    NOT NULL DEFAULT '',
    dense_dims   INTEGER NOT NULL DEFAULT 0,
    sparse_model TEXT    NOT NULL DEFAULT '',
    built_at     INTEGER NOT NULL DEFAULT 0,
    chunk_count  INTEGER NOT NULL DEFAULT 0,
    digest       TEXT    NOT NULL DEFAULT ''
)
"""

# The doc_chunks shape the Go writer owns (cmd_doc.go INSERTs path/heading/seq/
# body/hash under a doc_id). We create it IF NOT EXISTS only so a fresh/throwaway
# DB (tests, a bare single-host file) can be upserted into; against the real
# taskdb.sqlite the table already exists and this DDL is a no-op.
_DOC_CHUNKS_DDL = """
CREATE TABLE IF NOT EXISTS doc_chunks (
    id      INTEGER PRIMARY KEY,
    doc_id  INTEGER NOT NULL DEFAULT 0,
    path    TEXT    NOT NULL,
    heading TEXT    NOT NULL DEFAULT '',
    seq     INTEGER NOT NULL DEFAULT 0,
    body    TEXT    NOT NULL,
    hash    TEXT    NOT NULL
)
"""


def _resolve(db_path):
    """Return the db_path to operate on: the explicit arg if given, else the
    shared SEARCHSVC_DB-first resolver. Raises if neither resolves so a caller
    never silently operates on the wrong DB."""
    p = db_path or resolve_db_path()
    if not p:
        raise RuntimeError(
            "no taskdb.sqlite resolved (set SEARCHSVC_DB or pass db_path)"
        )
    return p


def _connect(db_path):
    """Open a writable connection to db_path, ensuring the maintenance tables
    exist. The caller owns commit/close (use ensure_schema / the helpers below,
    which manage their own connection lifecycle)."""
    conn = sqlite3.connect(db_path)
    conn.execute(_DOC_CHUNKS_DDL)
    conn.execute(_INDEX_META_DDL)
    return conn


def ensure_schema(db_path=None):
    """Create the index_meta (and, for a bare DB, doc_chunks) tables if absent.
    Idempotent; returns the resolved db_path so a caller can log WHERE it wrote."""
    path = _resolve(db_path)
    conn = _connect(path)
    try:
        conn.commit()
    finally:
        conn.close()
    return path


def upsert_chunk_by_hash(path, heading, body, *, doc_id=0, seq=0,
                         chunk_hash=None, db_path=None):
    """Upsert ONE doc_chunks row keyed on its content hash.

    chunk_hash defaults to the git-blob SHA of body (the SAME identity the Go
    side writes), so an unchanged body re-upserts in place rather than adding a
    duplicate. Returns the chunk_hash written. Idempotent: re-upserting the same
    (hash, path, heading) is a no-op beyond refreshing the row's fields."""
    h = chunk_hash or git_blob_sha(body)
    path_ = _resolve(db_path)
    conn = _connect(path_)
    try:
        _upsert_one(conn, h, path, heading, body, doc_id, seq)
        conn.commit()
    finally:
        conn.close()
    return h


def upsert_chunks_by_hash(chunks, db_path=None):
    """Upsert a batch of chunks in ONE transaction. Each chunk is a mapping with
    keys path, body and optional heading/doc_id/seq/hash (hash defaults to the
    git-blob SHA of body). Returns the list of chunk hashes written, in order."""
    path_ = _resolve(db_path)
    conn = _connect(path_)
    out = []
    try:
        for ch in chunks:
            body = ch["body"]
            h = ch.get("hash") or git_blob_sha(body)
            _upsert_one(
                conn, h, ch["path"], ch.get("heading", ""), body,
                ch.get("doc_id", 0), ch.get("seq", 0),
            )
            out.append(h)
        conn.commit()
    finally:
        conn.close()
    return out


def _upsert_one(conn, chunk_hash, path, heading, body, doc_id, seq):
    """Insert-or-replace a single doc_chunks row identified by its content hash.

    doc_chunks has no UNIQUE(hash) constraint in the production schema (the same
    body can legitimately recur under several paths), so we identify the row by
    (hash, path, heading) — the chunk's logical location — and DELETE-then-INSERT
    that slot, mirroring the Go re-chunk's DELETE-by-doc_id idempotency. A pure
    INSERT would let a re-upsert duplicate the row; this keeps the table free of
    duplicate (hash, path, heading) rows."""
    conn.execute(
        "DELETE FROM doc_chunks WHERE hash=? AND path=? AND heading=?",
        (chunk_hash, path, heading),
    )
    conn.execute(
        "INSERT INTO doc_chunks(doc_id, path, heading, seq, body, hash)"
        " VALUES(?,?,?,?,?,?)",
        (doc_id, path, heading, seq, body, chunk_hash),
    )


def prune_vanished(live_hashes, db_path=None):
    """Drop doc_chunks rows whose hash is NOT in live_hashes (the caller's set of
    hashes that still exist in the source corpus). Mirrors the Go prune path:
    collect the stale keys first, then DELETE by key — never mutate while the
    membership test iterates. Returns the number of rows pruned."""
    live = set(live_hashes)
    path_ = _resolve(db_path)
    conn = _connect(path_)
    try:
        stale = [
            row[0]
            for row in conn.execute("SELECT hash FROM doc_chunks")
            if row[0] not in live
        ]
        for h in stale:
            conn.execute("DELETE FROM doc_chunks WHERE hash=?", (h,))
        conn.commit()
        return len(stale)
    finally:
        conn.close()


# The meta-table key under which the Go pusher (searchsvc_ingest.go,
# metaIndexDigestKey) stashes the corpus digest of its LAST push. It is a
# same-shape sha256-over-sorted-distinct-hashes digest computed in the Go process
# from the SAME doc_chunks.hash identity. We read it back here only to CROSS-CHECK
# it against the digest this module derives — never to recompute the wire shape.
PUSHED_DIGEST_META_KEY = "searchsvc_index_digest"


def corpus_digest(db_path=None, conn=None):
    """A stable, cheap digest of the current doc_chunks corpus: sha256 over the
    SORTED distinct chunk hashes. Deterministic regardless of row insertion order
    so an unchanged corpus always digests identically, and ANY add/remove/edit
    (an edit changes a hash) moves the digest. This is what index_meta stores and
    what the freshness check compares against — a string compare, never a
    re-embed. An empty corpus digests to the sha256 of the empty string.

    This is the SINGLE canonical digest computation for the Python side: both
    record_index_meta and the reconcile path below derive their digest from this
    one helper, and it is byte-for-byte the Go side's corpusDigest (sha256 over
    the same sorted distinct gitBlobSHA hash set), so the two processes' digests
    are directly comparable."""
    own = conn is None
    if own:
        conn = _connect(_resolve(db_path))
    try:
        hashes = sorted(
            {row[0] for row in conn.execute("SELECT hash FROM doc_chunks")}
        )
        h = hashlib.sha256()
        for ch in hashes:
            h.update(ch.encode("utf-8"))
            h.update(b"\n")
        return h.hexdigest()
    finally:
        if own:
            conn.close()


def chunk_count(db_path=None, conn=None):
    """Total doc_chunks rows currently on disk (the resident-index target size)."""
    own = conn is None
    if own:
        conn = _connect(_resolve(db_path))
    try:
        (n,) = conn.execute("SELECT COUNT(*) FROM doc_chunks").fetchone()
        return int(n)
    finally:
        if own:
            conn.close()


def record_index_meta(model_label="", dense_dims=0, sparse_model="",
                      built_at=None, db_path=None):
    """Write the single index_meta row capturing the index the caller JUST built:
    its (model_label, dense_dims, sparse_model), the build time, the current
    corpus chunk_count, and the current corpus digest. id is pinned to 1 so this
    OVERWRITES the prior signature (one resident index, one provenance row).
    Returns the meta dict that was stored."""
    if built_at is None:
        built_at = int(time.time() * 1000)
    path_ = _resolve(db_path)
    conn = _connect(path_)
    try:
        digest = corpus_digest(conn=conn)
        count = chunk_count(conn=conn)
        conn.execute(
            "INSERT INTO index_meta(id, model_label, dense_dims, sparse_model,"
            " built_at, chunk_count, digest) VALUES(1,?,?,?,?,?,?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   model_label=excluded.model_label,"
            "   dense_dims=excluded.dense_dims,"
            "   sparse_model=excluded.sparse_model,"
            "   built_at=excluded.built_at,"
            "   chunk_count=excluded.chunk_count,"
            "   digest=excluded.digest",
            (model_label, dense_dims, sparse_model, built_at, count, digest),
        )
        conn.commit()
        return {
            "model_label": model_label,
            "dense_dims": dense_dims,
            "sparse_model": sparse_model,
            "built_at": built_at,
            "chunk_count": count,
            "digest": digest,
        }
    finally:
        conn.close()


def read_index_meta(db_path=None):
    """Return the stored index_meta row as a dict, or None if no index has been
    recorded yet (a never-built index — every freshness check then reports
    stale, the safe default)."""
    path_ = _resolve(db_path)
    conn = _connect(path_)
    try:
        row = conn.execute(
            "SELECT model_label, dense_dims, sparse_model, built_at,"
            " chunk_count, digest FROM index_meta WHERE id=1"
        ).fetchone()
        if row is None:
            return None
        return {
            "model_label": row[0],
            "dense_dims": row[1],
            "sparse_model": row[2],
            "built_at": row[3],
            "chunk_count": row[4],
            "digest": row[5],
        }
    finally:
        conn.close()


def freshness(db_path=None):
    """Compare the recorded index_meta digest against the CURRENT corpus digest
    and return a small status dict:

        {"fresh": bool, "stored_digest": str|None, "current_digest": str,
         "stored_count": int|None, "current_count": int}

    fresh is True iff an index_meta row exists AND its digest matches the current
    corpus digest (the resident index was built from exactly this corpus). A
    never-built index (no meta row) is reported NOT fresh — the safe default that
    tells /search to flag staleness and prompt a /reindex."""
    path_ = _resolve(db_path)
    conn = _connect(path_)
    try:
        current_digest = corpus_digest(conn=conn)
        current_count = chunk_count(conn=conn)
        row = conn.execute(
            "SELECT chunk_count, digest FROM index_meta WHERE id=1"
        ).fetchone()
    finally:
        conn.close()
    stored_count = row[0] if row is not None else None
    stored_digest = row[1] if row is not None else None
    return {
        "fresh": stored_digest is not None and stored_digest == current_digest,
        "stored_digest": stored_digest,
        "current_digest": current_digest,
        "stored_count": stored_count,
        "current_count": current_count,
    }


def read_pushed_digest(db_path=None, conn=None):
    """Return the Go-pushed corpus digest stashed in the meta table under
    PUSHED_DIGEST_META_KEY (searchsvc_ingest.go's metaIndexDigestKey), or None if
    no push has happened yet OR the meta table does not exist (a bare/throwaway DB
    that the Go pusher never touched). A never-pushed digest is None, not "", so
    the reconcile can distinguish "nothing to compare against" from a real value."""
    own = conn is None
    if own:
        conn = _connect(_resolve(db_path))
    try:
        try:
            row = conn.execute(
                "SELECT value FROM meta WHERE key=?", (PUSHED_DIGEST_META_KEY,)
            ).fetchone()
        except sqlite3.OperationalError:
            # No meta table (a bare DB the Go pusher never created): nothing to
            # reconcile against. Not an error — the safe "unknown" answer.
            return None
        return row[0] if row is not None else None
    finally:
        if own:
            conn.close()


def reconcile_index_digest(db_path=None, conn=None, pushed_digest=None,
                           strict=False, log=None):
    """Cross-check the Go-pushed corpus digest against the digest this module
    derives, at reindex time, and surface DRIFT loudly.

    The two digests are computed in separate processes (the Go pusher's
    corpusDigest → meta.searchsvc_index_digest, and ingest.py's corpus_digest /
    the index_meta digest) but from the SAME doc_chunks.hash identity, so on an
    in-sync corpus they are byte-for-byte equal. A mismatch means the resident
    index the service just rebuilt was NOT built from the corpus the Go side
    believes it pushed — a real drift worth a loud signal.

    Returns a status dict:

        {"reconciled": bool, "pushed_digest": str|None, "current_digest": str,
         "drift": bool}

    reconciled is True iff a pushed digest exists AND equals the current canonical
    digest. A never-pushed corpus (no meta row / no meta table) reports
    reconciled=False, drift=False (nothing to compare — not a drift). A present-
    but-different pushed digest reports reconciled=False, drift=True and logs a
    LOUD line. With strict=True a true drift RAISES DigestDriftError instead of
    only logging (the assert-style caller); the default logs and returns so a
    reindex is never hard-failed by a bookkeeping mismatch.

    pushed_digest may be passed explicitly (tests / a caller that already has it);
    otherwise it is read from the meta table. log defaults to stderr."""
    own = conn is None
    if own:
        conn = _connect(_resolve(db_path))
    try:
        current = corpus_digest(conn=conn)
        pushed = (
            pushed_digest
            if pushed_digest is not None
            else read_pushed_digest(conn=conn)
        )
    finally:
        if own:
            conn.close()

    # A never-pushed corpus: nothing to reconcile against, not a drift.
    if not pushed:
        return {
            "reconciled": False,
            "pushed_digest": pushed or None,
            "current_digest": current,
            "drift": False,
        }

    drift = pushed != current
    if drift:
        msg = (
            "[searchsvc DIGEST DRIFT] Go-pushed corpus digest %s != ingest "
            "canonical digest %s — the resident index was NOT built from the "
            "pushed corpus; reconcile the pusher and the service DB"
            % (pushed, current)
        )
        if log is not None:
            log(msg)
        else:
            print(msg, file=sys.stderr)
        if strict:
            raise DigestDriftError(pushed, current)
    return {
        "reconciled": not drift,
        "pushed_digest": pushed,
        "current_digest": current,
        "drift": drift,
    }


class DigestDriftError(AssertionError):
    """Raised by reconcile_index_digest(strict=True) when the Go-pushed corpus
    digest does not match the canonical digest this module derives — i.e. the
    resident index was built from a corpus the Go pusher did not push. Subclasses
    AssertionError so it reads as the assert it is, while carrying both digests."""

    def __init__(self, pushed_digest, current_digest):
        self.pushed_digest = pushed_digest
        self.current_digest = current_digest
        super().__init__(
            "Go-pushed digest %s != ingest canonical digest %s"
            % (pushed_digest, current_digest)
        )


def git_blob_sha(body):
    """The git blob SHA-1 of body — sha1 over "blob <len>\\x00" + bytes, hex
    encoded — IDENTICAL to the Go side's gitBlobSHA (db.go). So a chunk hash this
    module computes is byte-for-byte the hash the Go writer stores for the same
    content: the upsert/prune/digest all key on one shared identity."""
    data = body.encode("utf-8") if isinstance(body, str) else body
    h = hashlib.sha1()
    h.update(b"blob %d\x00" % len(data))
    h.update(data)
    return h.hexdigest()


# Re-export the resolver under this module's namespace too, so a caller that
# imports ingest can resolve the DB without also importing index_store. This is a
# thin alias — the implementation stays the single one in index_store.
__all__ = [
    "ensure_schema",
    "upsert_chunk_by_hash",
    "upsert_chunks_by_hash",
    "prune_vanished",
    "corpus_digest",
    "chunk_count",
    "record_index_meta",
    "read_index_meta",
    "freshness",
    "read_pushed_digest",
    "reconcile_index_digest",
    "DigestDriftError",
    "PUSHED_DIGEST_META_KEY",
    "git_blob_sha",
    "resolve_db_path",
]
