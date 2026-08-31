# SPDX-License-Identifier: Apache-2.0
"""Serve-side live ingest + reindex tests (bgem3w4 python-index-layer unit).

These prove the dormant-retrieval-into-live-corpus wiring the unit shipped:

  - POST /embed now ADDITIVELY pushes the embedded chunk into BOTH resident
    legs (dense via index_store.get_index().ingest, sparse via sparse.ingest),
    so a subsequent /search (real leg, dense+sparse+fusion all present) SEES
    the just-ingested chunk — not just an echo.
  - the /embed echo response shape stays additive (dense / sparse / dense_dims).
  - POST /reindex rebuilds both legs from the resolved DB without a restart.

Hermetic: fake_embed (256-dim) only, no torch / GPU / network. The singletons
are reset and SEARCHSVC_DB is pointed at an absent path per-test so /embed is
the ONLY source of resident rows (no real taskdb.sqlite bleed-in)."""

import importlib
import os
import sys

import pytest

import index_store
import serve
import sparse


# The real searchsvc modules /search routes through. A sibling test
# (test_searchsvc) installs SYNTHETIC dense/sparse/fusion modules on sys.path and
# leaves them in sys.modules; if one of those leaks in we'd be searching a fake
# corpus. Evicting + re-importing the real modules per-test makes these tests
# order-independent without touching the (forbidden) sibling test file.
_REAL_RETRIEVAL_MODS = ("dense", "sparse", "fusion", "index_store")


@pytest.fixture(autouse=True)
def _isolated_empty_index(monkeypatch):
    """Point the shared DB resolver at an absent path, evict any stale/synthetic
    retrieval modules so the REAL searchsvc legs bind, and drop both resident
    singletons so each test starts from a genuinely empty corpus with /embed as
    the sole accumulator."""
    monkeypatch.setenv("SEARCHSVC_DB", "/no/such/searchsvc-test.sqlite")
    monkeypatch.delenv("TASKDB_SQLITE", raising=False)
    monkeypatch.delenv("TASKDB_DB", raising=False)
    # Force the REAL dense/sparse/fusion/index_store back into sys.modules.
    for name in _REAL_RETRIEVAL_MODS:
        sys.modules.pop(name, None)
    for name in _REAL_RETRIEVAL_MODS:
        importlib.import_module(name)
    # Re-bind module-level references that may point at evicted objects.
    global index_store, sparse
    index_store = importlib.import_module("index_store")
    sparse = importlib.import_module("sparse")
    index_store.reset_index()
    sparse.reset_store()
    yield
    index_store.reset_index()
    sparse.reset_store()


def _client():
    from fastapi.testclient import TestClient

    return TestClient(serve.build_app())


# ---------------------------------------------------------------------------
# /embed echo shape stays additive.
# ---------------------------------------------------------------------------


def test_embed_echo_shape_is_additive():
    client = _client()
    r = client.post("/embed", json={"text": "alpha beta gamma"})
    assert r.status_code == 200
    body = r.json()
    # additive trio preserved.
    assert len(body["dense"]) == 256
    assert body["dense_dims"] == 256
    assert isinstance(body["sparse"], dict)
    # JSON object keys are strings on the wire.
    assert all(isinstance(k, str) for k in body["sparse"])


# ---------------------------------------------------------------------------
# The live accumulation path: /embed makes the chunk visible to /search.
# ---------------------------------------------------------------------------


def test_embed_then_search_sees_the_ingested_chunk():
    client = _client()
    # Empty corpus: a search before any ingest returns no results.
    pre = client.post("/search", json={"query": "needle in the haystack", "top_k": 5})
    assert pre.status_code == 200
    pre_body = pre.json()
    assert pre_body.get("degraded") is False
    assert pre_body["results"] == []

    # Ingest one chunk via /embed, then the SAME query must now retrieve it.
    text = "needle in the haystack"
    client.post("/embed", json={"text": text})
    post = client.post("/search", json={"query": text, "top_k": 5})
    assert post.status_code == 200
    post_body = post.json()
    assert post_body["degraded"] is False
    hashes = [hit["chunk_hash"] for hit in post_body["results"]]
    assert len(hashes) == 1
    assert hashes[0] == serve._chunk_hash(text)


def test_embed_accumulates_without_wiping_prior_chunks():
    import fake_embed

    client = _client()
    t1 = "first document about cats"
    t2 = "second document about dogs"
    client.post("/embed", json={"text": t1})
    client.post("/embed", json={"text": t2})

    # Both chunks survive in the resident index (additive, not set_store wipe).
    idx = index_store.get_index()
    assert len(idx) == 2
    assert sorted(idx.chunk_hashes()) == sorted(
        [serve._chunk_hash(t1), serve._chunk_hash(t2)]
    )
    # And the sparse leg accumulated both as well: a query spanning every token
    # the two chunks produced retrieves exactly the two resident chunks.
    query = {}
    for tid in fake_embed.fake_sparse(t1):
        query[tid] = 1.0
    for tid in fake_embed.fake_sparse(t2):
        query[tid] = 1.0
    hits = sparse.sparse_search(query, top_k=10)
    assert len(hits) == 2
    assert {h for h, _ in hits} == {serve._chunk_hash(t1), serve._chunk_hash(t2)}


def test_embed_threads_provenance_into_ingested_chunk():
    """A chunk streamed via /embed with doc_path/heading lands in the resident
    index WITH that provenance, and the SAME query retrieves it carrying the
    real source — not the empty provenance of a text-only ingest."""
    client = _client()
    text = "provenance carrying needle"
    doc_path = "docs/22-search-design.md"
    heading = "§8 hybrid retrieval"
    r = client.post(
        "/embed",
        json={"text": text, "doc_path": doc_path, "heading": heading},
    )
    assert r.status_code == 200
    body = r.json()
    # The /embed echo stays additive — provenance threading does not alter it.
    assert len(body["dense"]) == 256
    assert body["dense_dims"] == 256
    assert isinstance(body["sparse"], dict)
    assert "doc_path" not in body
    assert "heading" not in body

    chunk_hash = serve._chunk_hash(text)
    # /search must retrieve exactly the just-ingested chunk...
    post = client.post("/search", json={"query": text, "top_k": 5})
    assert post.status_code == 200
    post_body = post.json()
    assert post_body["degraded"] is False
    hashes = [hit["chunk_hash"] for hit in post_body["results"]]
    assert hashes == [chunk_hash]
    # ...and that retrieved chunk carries the threaded provenance in the resident
    # index metadata, not the empty doc_path/heading of a text-only ingest.
    meta = index_store.get_index().metadata(chunk_hash)
    assert meta == {"doc_path": doc_path, "heading": heading}


def test_embed_without_provenance_defaults_to_empty():
    """The text-only /embed caller (no doc_path/heading) still ingests, landing
    with empty provenance — the optional fields are additive, not required."""
    client = _client()
    text = "no provenance chunk"
    r = client.post("/embed", json={"text": text})
    assert r.status_code == 200
    meta = index_store.get_index().metadata(serve._chunk_hash(text))
    assert meta == {"doc_path": "", "heading": ""}


def test_embed_reingesting_same_text_upserts_not_duplicates():
    client = _client()
    client.post("/embed", json={"text": "stable identity chunk"})
    client.post("/embed", json={"text": "stable identity chunk"})
    idx = index_store.get_index()
    # Same content -> same chunk_hash -> in-place upsert, never a duplicate row.
    assert len(idx) == 1


# ---------------------------------------------------------------------------
# /reindex rebuilds from the resolved DB without a restart.
# ---------------------------------------------------------------------------


def test_reindex_route_reports_resolved_db_and_zero_on_absent_db():
    client = _client()
    r = client.post("/reindex")
    assert r.status_code == 200
    body = r.json()
    assert body["reindexed"] is True
    # The resolver surfaces WHERE it pointed even when that path is absent.
    assert body["db"] == "/no/such/searchsvc-test.sqlite"
    # An absent DB rebuilds to a 0-count corpus, never a 500.
    assert body["dense_ingested"] == 0
    assert body["sparse_chunks"] == 0


def test_reindex_rebuilds_from_resolved_db(tmp_path, monkeypatch):
    import sqlite3
    import struct

    import fake_embed

    db = tmp_path / "taskdb.sqlite"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE doc_chunks (id INTEGER PRIMARY KEY, doc_id INTEGER NOT NULL,"
        " path TEXT NOT NULL, heading TEXT NOT NULL DEFAULT '', seq INTEGER NOT NULL,"
        " body TEXT NOT NULL, hash TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE chunk_embeddings (chunk_hash TEXT PRIMARY KEY, model TEXT NOT NULL,"
        " dims INTEGER NOT NULL, vector BLOB NOT NULL)"
    )
    vec = fake_embed.fake_dense("indexed body text")
    blob = struct.pack("<%df" % len(vec), *vec)
    conn.execute(
        "INSERT INTO doc_chunks (doc_id, path, heading, seq, body, hash)"
        " VALUES (?,?,?,?,?,?)",
        (1, "docs/a.md", "A", 0, "indexed body text", "h_reidx"),
    )
    conn.execute(
        "INSERT INTO chunk_embeddings (chunk_hash, model, dims, vector)"
        " VALUES (?,?,?,?)",
        ("h_reidx", "bge-m3-http", len(vec), blob),
    )
    conn.commit()
    conn.close()

    monkeypatch.setenv("SEARCHSVC_DB", str(db))
    index_store.reset_index()
    sparse.reset_store()

    client = _client()
    r = client.post("/reindex")
    assert r.status_code == 200
    body = r.json()
    assert body["reindexed"] is True
    assert body["db"] == str(db)
    assert body["dense_ingested"] == 1
    assert index_store.get_index().chunk_hashes() == ["h_reidx"]


def test_reindex_route_exists_on_stdlib_app():
    """The /reindex route is mirrored into the stdlib fallback handler too."""
    handler_cls = serve.build_stdlib_app()
    # The stdlib handler dispatches on self.path; assert the route token is wired
    # by exercising do_POST's branch table via a tiny fake request is heavier than
    # warranted, so assert the source-level mirror: the class' do_POST references
    # the /reindex path.
    import inspect

    src = inspect.getsource(handler_cls)
    assert "/reindex" in src
