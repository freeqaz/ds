#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# serve.py — searchsvc's THIN DISPATCHER for taskdb's hybrid (dense + sparse)
# semantic-search seam (doc 22 §8, decision D9).
#
# CHARTER: define the HTTP app and the two routes — POST /embed and POST
# /search — and nothing else. The actual retrieval lives in sibling modules that
# OTHER units own and that may not exist yet:
#
#   dense.py   -> dense_search(query_dense, ...) : ANN/brute-force over dense vecs
#   sparse.py  -> sparse_search(query_sparse, ...): lexical match over sparse maps
#   fusion.py  -> fuse(dense_hits, sparse_hits, ...): reciprocal-rank / weighted fuse
#
# /search ALREADY calls fuse(dense_search(...), sparse_search(...)) so NO later
# unit edits this file: the wiring is fixed here, the modules fill in behind a
# LAZY import guarded by try/except. Until they exist, /search degrades to the
# embed-only echo (sparse+dense of the query) with a "degraded" marker, so the
# route stays live and testable in the hermetic build.
#
# EMBEDDER: hermetic builds use fake_embed (deterministic, no model). The LIVE
# BGE-M3 embedder lives in serve_live.py (a SEPARATE unit) behind the EXISTING
# DS_EMBED_LIVE=1 gate with a LAZY torch import. THIS FILE NEVER IMPORTS TORCH
# at module top level (a test asserts "torch" not in sys.modules after import);
# even the live embedder is reached only through a function-local import.
#
# FRAMEWORK: built AROUND FastAPI (the preferred library choice). A stdlib
# http.server fallback (build_stdlib_app / serve_stdlib) is a defensive bonus so
# the dispatcher is still standable if FastAPI is somehow absent; the hermetic
# uv env ships FastAPI, so the FastAPI path is the one the tests exercise.

import os

import fake_embed

# ---------------------------------------------------------------------------
# Embedder selection (NEVER imports torch at module top level)
# ---------------------------------------------------------------------------


def live_enabled():
    """Live BGE-M3 path is opt-in only (it downloads weights / wants a GPU)."""
    return os.environ.get("DS_EMBED_LIVE") == "1"


def embed_text(text):
    """Embed one text -> {"dense": [...], "sparse": {tid: weight}}.

    Hermetic default is the deterministic fake. The live BGE-M3 embedder lives
    in serve_live.py and is reached ONLY through a function-local import behind
    the DS_EMBED_LIVE gate — so importing serve.py never imports torch. If the
    live module is unavailable (the common, hermetic case — torch/FlagEmbedding
    are the [live] extra, never installed), we fall back to the fake."""
    if live_enabled():
        try:
            import serve_live  # noqa: WPS433 — lazy, live-only, may import torch

            return serve_live.embed_text(text)
        except Exception:
            # Missing/broken live deps degrade to the deterministic fake rather
            # than 500, matching embed.py's loud-fallback discipline.
            pass
    return fake_embed.fake_embed(text)


# ---------------------------------------------------------------------------
# Retrieval wiring — fuse(dense_search, sparse_search) via LAZY import.
# These sibling modules belong to other units and may not exist yet.
# ---------------------------------------------------------------------------


def _run_search(query_dense, query_sparse, top_k):
    """Call fuse(dense_search(...), sparse_search(...)). The three modules are
    imported lazily so this file does not hard-depend on units that have not
    landed. Until they land, return a degraded embed-only result so /search is
    still a live, testable route."""
    try:
        import dense  # noqa: WPS433 — owned by a later unit
        import fusion  # noqa: WPS433 — owned by a later unit
        import sparse  # noqa: WPS433 — owned by a later unit
    except Exception:
        return {
            "degraded": True,
            "reason": "retrieval modules (dense/sparse/fusion) not yet present",
            "query_dense_dims": len(query_dense),
            "query_sparse_terms": len(query_sparse),
            "results": [],
        }
    dense_hits = dense.dense_search(query_dense, top_k=top_k)
    sparse_hits = sparse.sparse_search(query_sparse, top_k=top_k)
    # fusion.fuse is the SOLE canonical provenance source: it resolves each hit's
    # {doc_path, heading} from its default index (index_store.get_index()) and the
    # per-chunk metadata, so every fused dict already carries provenance. No second
    # post-fuse re-walk here — one resolution path, one source of truth.
    fused = fusion.fuse(dense_hits, sparse_hits, top_k=top_k)
    return {"degraded": False, "results": fused}


# ---------------------------------------------------------------------------
# Live ingest helpers — push a freshly-embedded chunk into the resident dense +
# sparse indexes. ALL imports here are FUNCTION-LOCAL/lazy so importing serve.py
# never pulls index_store (numpy) or sparse at module top level (the
# torch-isolation / cheap-import discipline). A best-effort chunk_hash lets
# /embed double as the live accumulation path without a separate ingest route.
# ---------------------------------------------------------------------------


def _chunk_hash(text):
    """Stable content hash for an ingested chunk (sha256 hex of the UTF-8 text).
    Deterministic and model-free; only a stable key for dedupe in the resident
    indexes."""
    import hashlib

    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _ingest_embedding(chunk_hash, emb, doc_path="", heading=""):
    """ADDITIVELY push one embedded chunk into the resident dense + sparse indexes.

    dense -> index_store.get_index().ingest(...) (in-place upsert, no wipe);
    sparse -> sparse.ingest(...) (the additive helper, NOT set_store). Lazy imports
    keep serve.py import-cheap and torch-free. Best-effort: a degraded index must
    never 500 the /embed echo, so failures are swallowed (the echo still returns)."""
    try:
        import index_store

        index_store.get_index().ingest(
            chunk_hash, emb["dense"], doc_path, heading
        )
    except Exception:
        pass
    try:
        import sparse

        sparse.ingest(chunk_hash, emb.get("sparse", {}))
    except Exception:
        pass


def _ingest_batch(chunks):
    """Embed + ADDITIVELY ingest a LIST of chunks in one call (the cold-push
    fast path that cuts the Go pusher's O(N) /embed round-trips down to a
    handful of batched requests).

    `chunks` is a list of dicts, each {"text": str, "doc_path"?: str,
    "heading"?: str}. Each is embedded with the SAME embed_text the single
    /embed route uses, then pushed into the resident dense + sparse indexes via
    the existing best-effort _ingest_embedding (so a degraded index never 500s a
    batch). Returns an ADDITIVE summary {"ingested": int, "chunk_hashes": [...]}
    — the per-chunk dense/sparse echo is intentionally NOT returned (a cold push
    over the whole corpus does not want N vectors on the wire; it only needs the
    chunks to have landed resident-side). All imports stay function-local via
    _ingest_embedding so importing serve.py remains torch-free and import-cheap.
    A malformed entry (missing/blank text) is skipped rather than aborting the
    batch, matching the loud-but-fail-open ingest discipline."""
    ingested = 0
    chunk_hashes = []
    for entry in chunks or []:
        text = (entry or {}).get("text", "") if isinstance(entry, dict) else ""
        if not text:
            continue
        emb = embed_text(text)
        ch = _chunk_hash(text)
        _ingest_embedding(
            ch,
            emb,
            (entry.get("doc_path", "") if isinstance(entry, dict) else ""),
            (entry.get("heading", "") if isinstance(entry, dict) else ""),
        )
        ingested += 1
        chunk_hashes.append(ch)
    return {"ingested": ingested, "chunk_hashes": chunk_hashes}


def _freshness_verdict():
    """Compute the index freshness/staleness verdict for the resident corpus.

    Returns an ADDITIVE summary dict attached to every /search response so a
    caller can tell whether the resident index was built from exactly the current
    corpus (fresh) or has drifted (stale → a /reindex is due):

        {"fresh": bool, "verdict": "fresh"|"stale",
         "stored_digest": str|None, "current_digest": str,
         "stored_count": int|None, "current_count": int,
         "drift": int}

    drift is current_count - (stored_count or 0): a positive value is the rough
    count of chunks the resident index has not absorbed yet (a quick "how stale").
    Reached through a FUNCTION-LOCAL import of ingest so serve.py stays import-cheap
    and torch-free at module top level. Best-effort: if the verdict cannot be
    computed (e.g. no DB yet), report a safe "stale, unknown" rather than 500 the
    /search route."""
    try:
        import ingest

        f = ingest.freshness()
    except Exception as exc:
        return {
            "fresh": False,
            "verdict": "stale",
            "stored_digest": None,
            "current_digest": "",
            "stored_count": None,
            "current_count": 0,
            "drift": 0,
            "error": str(exc),
        }
    fresh = bool(f.get("fresh"))
    stored_count = f.get("stored_count")
    current_count = f.get("current_count", 0) or 0
    drift = current_count - (stored_count or 0)
    return {
        "fresh": fresh,
        "verdict": "fresh" if fresh else "stale",
        "stored_digest": f.get("stored_digest"),
        "current_digest": f.get("current_digest", ""),
        "stored_count": stored_count,
        "current_count": current_count,
        "drift": drift,
    }


# SQLite caps a single statement's host parameters (SQLITE_MAX_VARIABLE_NUMBER,
# 999 in the historical default builds). Chunk the IN-list well under that so the
# WHERE hash IN (?,?,...) lookup never trips the limit, regardless of how many
# hashes a backfill requests.
_PROVENANCE_IN_BATCH = 900


def _resolve_provenance_from_db(db, chunk_hashes):
    """Read {chunk_hash: (path, heading)} from the index DB's doc_chunks for the
    given hashes. Best-effort + read-only: an absent DB / table / row yields no
    entry for that hash (the caller leaves it untouched), never a raise. Lazy
    sqlite3 import keeps serve.py import-cheap. The DB is opened read-only +
    immutable so a live writer is never blocked.

    Targeted lookup: a chunked ``WHERE hash IN (?,?,...)`` over ONLY the requested
    hashes (deduped), so a heal of K chunks scans O(K) rows instead of the whole
    corpus. The IN-list is batched under the SQLite host-parameter limit
    (_PROVENANCE_IN_BATCH); the per-batch results are unioned. The resolution
    result is identical to a full scan — one representative row per hash (identical
    hashes share identical provenance by construction, the hash being the blob SHA
    of the body)."""
    import sqlite3

    if not db or not os.path.exists(db) or not chunk_hashes:
        return {}
    uri = "file:%s?mode=ro&immutable=1" % os.path.abspath(db)
    out = {}
    try:
        conn = sqlite3.connect(uri, uri=True)
    except Exception:
        return {}
    try:
        # Dedupe to a stable list so each requested hash is asked for exactly once
        # across the batches (a set membership also lets us keep the first row).
        wanted = list(dict.fromkeys(chunk_hashes))
        for start in range(0, len(wanted), _PROVENANCE_IN_BATCH):
            batch = wanted[start:start + _PROVENANCE_IN_BATCH]
            placeholders = ",".join("?" * len(batch))
            sql = (
                "SELECT hash, path, heading FROM doc_chunks WHERE hash IN (%s)"
                % placeholders
            )
            for chunk_hash, path, heading in conn.execute(sql, batch):
                if chunk_hash not in out:
                    out[chunk_hash] = (path or "", heading or "")
    except Exception:
        # A bare DB without doc_chunks (or a locked read) heals nothing rather
        # than 500-ing the route — fail-open, mirroring _reindex's grace.
        return out
    finally:
        conn.close()
    return out


def _backfill_provenance():
    """TARGETED heal for resident chunks that landed with EMPTY provenance.

    Chunks streamed to a long-lived resident service BEFORE the provenance-pushers
    change carry empty doc_path/heading until a full /reindex rebuilds them from
    the resolved DB. This re-resolves provenance for ONLY those chunks (doc_path
    AND heading both empty in the resident dense metadata) from the index DB's
    doc_chunks (path/heading keyed by chunk_hash) and updates the resident metadata
    IN PLACE — avoiding a full corpus reindex.

    It writes through the SINGLE canonical resident-provenance path: DenseIndex.
    ingest(chunk_hash, dense, doc_path, heading), re-supplying the chunk's EXISTING
    dense row (read back from the resident matrix) so the vector is preserved and
    only the metadata is refreshed. fusion._metadata resolves every /search hit's
    {doc_path, heading} from exactly this metadata, so a healed chunk's next hit
    carries real provenance without a /reindex.

    Lazy imports keep serve.py torch-free and import-cheap. Best-effort: a missing
    DB / unresolvable hash leaves that chunk untouched (still empty) rather than
    500-ing. Returns an ADDITIVE summary
    {"healed": int, "scanned": int, "empty": int, "unresolved": int, "db": str|None}."""
    import index_store

    idx = index_store.get_index()
    db = index_store.resolve_db_path()

    hashes = idx.chunk_hashes()
    # The resident dense matrix, row-aligned to chunk_hashes(), so we re-ingest
    # each healed chunk with its OWN existing vector (provenance-only update).
    matrix = idx.matrix()

    # The chunks needing a heal: BOTH doc_path and heading empty/missing.
    empty = []
    for h in hashes:
        meta = idx.metadata(h)
        if not meta.get("doc_path", "") and not meta.get("heading", ""):
            empty.append(h)

    resolved = _resolve_provenance_from_db(db, empty)

    healed = 0
    unresolved = 0
    row_of = {h: i for i, h in enumerate(hashes)}
    for h in empty:
        prov = resolved.get(h)
        if not prov:
            unresolved += 1
            continue
        doc_path, heading = prov
        if not doc_path and not heading:
            # The DB row itself has no provenance — nothing to heal with.
            unresolved += 1
            continue
        # Re-ingest with the chunk's EXISTING dense row (preserve the vector,
        # refresh only the metadata) through the canonical write path.
        dense_row = matrix[row_of[h]]
        idx.ingest(h, dense_row, doc_path, heading)
        healed += 1

    return {
        "healed": healed,
        "scanned": len(hashes),
        "empty": len(empty),
        "unresolved": unresolved,
        "db": db,
    }


def _reindex():
    """Rebuild both resident legs from the local taskdb.sqlite. dense via
    index_store.get_index().refresh_from_sqlite(<resolved db>); sparse via a fresh
    load_store(). Lazy imports; returns a small status dict. Raises nothing it can
    avoid — a missing DB yields a 0-count rebuild, not a 500."""
    import index_store
    import sparse

    idx = index_store.get_index()
    db = index_store.resolve_db_path()
    dense_n = 0
    if db and os.path.exists(db):
        dense_n = idx.refresh_from_sqlite(db)
    sparse.reset_store()
    store = sparse.load_store(db) if db else sparse.load_store()
    return {
        "reindexed": True,
        "dense_chunks": len(idx),
        "dense_ingested": dense_n,
        "sparse_chunks": len(store or {}),
        "db": db,
    }


# ---------------------------------------------------------------------------
# FastAPI app (preferred). Constructed lazily so importing serve.py for the
# torch-isolation test is cheap and side-effect-free.
# ---------------------------------------------------------------------------


def build_app():
    """Construct the FastAPI app with /embed and /search. Raises if FastAPI is
    not installed — callers wanting the defensive fallback use build_stdlib_app."""
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI(title="taskdb-searchsvc", version="0.1.0")

    class EmbedRequest(BaseModel):
        text: str
        # OPTIONAL provenance: when /embed doubles as the live accumulation path,
        # the caller can thread the chunk's source so streamed chunks land with
        # real doc_path/heading (a subsequent /search hit carries provenance
        # without waiting for a full /reindex). Empty defaults preserve the
        # text-only callers.
        doc_path: str = ""
        heading: str = ""

    class IngestChunk(BaseModel):
        text: str
        doc_path: str = ""
        heading: str = ""

    class IngestBatchRequest(BaseModel):
        # A LIST of chunks embedded + ingested in ONE request — the cold-push
        # batch verb the Go pusher uses to cut O(N) /embed round-trips to a few.
        chunks: list[IngestChunk] = []

    class SearchRequest(BaseModel):
        query: str
        top_k: int = 10

    @app.post("/embed")
    def embed(req: EmbedRequest):
        """Embed req.text and ADDITIVELY ingest the chunk into the resident dense +
        sparse indexes (the live accumulation path), then return the ADDITIVE echo
        {"dense": [...256...], "sparse": {tid: weight}, "dense_dims": N}. Ingest is
        best-effort and never changes the echo shape."""
        emb = embed_text(req.text)
        _ingest_embedding(
            _chunk_hash(req.text), emb, req.doc_path, req.heading
        )
        return {
            "dense": emb["dense"],
            # JSON object keys are strings; keep the sparse map as {str(tid): w}.
            "sparse": {str(k): v for k, v in emb["sparse"].items()},
            "dense_dims": len(emb["dense"]),
        }

    @app.post("/ingest_batch")
    def ingest_batch(req: IngestBatchRequest):
        """Embed + ADDITIVELY ingest a LIST of chunks in one request (the cold-
        push fast path). Returns the ADDITIVE summary {"ingested": N,
        "chunk_hashes": [...]}; the per-chunk vectors are intentionally not
        echoed (a cold push wants chunks landed, not N vectors on the wire)."""
        chunks = [c.model_dump() for c in req.chunks]
        return _ingest_batch(chunks)

    @app.post("/reindex")
    def reindex():
        """Rebuild both resident retrieval legs from the local taskdb.sqlite.
        Returns a small status dict (counts + resolved db path)."""
        return _reindex()

    @app.post("/backfill_provenance")
    def backfill_provenance():
        """TARGETED heal: re-resolve provenance for resident chunks that landed
        with EMPTY doc_path/heading (streamed before the provenance-pushers fix)
        from the index DB's doc_chunks, updating the resident metadata in place —
        no full /reindex. Returns the ADDITIVE summary
        {"healed", "scanned", "empty", "unresolved", "db"}."""
        return _backfill_provenance()

    @app.post("/search")
    def search(req: SearchRequest):
        """Embed the query, then fuse(dense_search(...), sparse_search(...)).
        Returns degraded=True until the retrieval modules land. ADDITIVELY
        attaches the index freshness verdict (fresh|stale + digest/count summary)
        so a caller can flag a stale index without a second round-trip — the
        ranked-results shape is untouched."""
        emb = embed_text(req.query)
        out = _run_search(emb["dense"], emb["sparse"], req.top_k)
        out["query"] = req.query
        out["freshness"] = _freshness_verdict()
        return out

    return app


# ---------------------------------------------------------------------------
# Defensive bonus: stdlib http.server fallback (no third-party deps at all).
# ---------------------------------------------------------------------------


def build_stdlib_app():
    """Return a BaseHTTPRequestHandler subclass serving the same /embed +
    /search JSON contract using only the stdlib. A safety net if FastAPI is
    absent; the FastAPI path is the production one."""
    import json
    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def _read_json(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw or b"{}")

        def _send(self, code, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802 — stdlib handler API
            try:
                req = self._read_json()
            except Exception as exc:
                self._send(400, {"error": f"bad json: {exc}"})
                return
            if self.path == "/embed":
                text = req.get("text", "")
                emb = embed_text(text)
                _ingest_embedding(
                    _chunk_hash(text),
                    emb,
                    req.get("doc_path", ""),
                    req.get("heading", ""),
                )
                self._send(
                    200,
                    {
                        "dense": emb["dense"],
                        "sparse": {str(k): v for k, v in emb["sparse"].items()},
                        "dense_dims": len(emb["dense"]),
                    },
                )
            elif self.path == "/ingest_batch":
                self._send(200, _ingest_batch(req.get("chunks", [])))
            elif self.path == "/reindex":
                self._send(200, _reindex())
            elif self.path == "/backfill_provenance":
                self._send(200, _backfill_provenance())
            elif self.path == "/search":
                emb = embed_text(req.get("query", ""))
                out = _run_search(emb["dense"], emb["sparse"], req.get("top_k", 10))
                out["query"] = req.get("query", "")
                out["freshness"] = _freshness_verdict()
                self._send(200, out)
            else:
                self._send(404, {"error": "not found"})

        def log_message(self, *args):  # silence default stderr logging
            return

    return Handler


def serve_stdlib(host="127.0.0.1", port=8099):  # pragma: no cover - manual run
    from http.server import HTTPServer

    httpd = HTTPServer((host, port), build_stdlib_app())
    httpd.serve_forever()


def main(argv=None):  # pragma: no cover - manual run path
    import sys

    argv = sys.argv[1:] if argv is None else argv
    host = os.environ.get("SEARCHSVC_HOST", "127.0.0.1")
    port = int(os.environ.get("SEARCHSVC_PORT", "8099"))
    if "--stdlib" in argv:
        serve_stdlib(host, port)
        return 0
    import uvicorn

    uvicorn.run(build_app(), host=host, port=port)
    return 0


if __name__ == "__main__":  # pragma: no cover - manual run path
    raise SystemExit(main())
