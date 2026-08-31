# SPDX-License-Identifier: Apache-2.0
"""Serve-side batch-ingest tests (bgem3w6 batch-ingest-verb unit).

POST /ingest_batch embeds + ADDITIVELY ingests a LIST of chunks in ONE request
— the cold-push fast path that lets the Go pusher cut O(N) /embed round-trips to
a handful of batched requests. These prove:

  - a multi-chunk batch body ingests EVERY chunk into BOTH resident legs (dense
    via index_store, sparse via sparse.ingest), so a subsequent /search sees
    them — exactly like N separate /embed calls would, but in one request.
  - the response shape is the ADDITIVE summary {"ingested": N, "chunk_hashes":
    [...]} (no per-chunk vectors echoed).
  - per-chunk provenance (doc_path/heading) threads through.
  - the route is mirrored into the stdlib fallback handler.

Hermetic: fake_embed (256-dim) only, no torch / GPU / network. SEARCHSVC_DB is
pointed at an absent path and the singletons are reset per-test so /ingest_batch
is the ONLY source of resident rows."""

import importlib
import sys

import pytest

import index_store
import serve
import sparse

_REAL_RETRIEVAL_MODS = ("dense", "sparse", "fusion", "index_store")


@pytest.fixture(autouse=True)
def _isolated_empty_index(monkeypatch):
    """Empty, isolated resident corpus with the REAL retrieval legs bound."""
    monkeypatch.setenv("SEARCHSVC_DB", "/no/such/searchsvc-batch-test.sqlite")
    monkeypatch.delenv("TASKDB_SQLITE", raising=False)
    monkeypatch.delenv("TASKDB_DB", raising=False)
    for name in _REAL_RETRIEVAL_MODS:
        sys.modules.pop(name, None)
    for name in _REAL_RETRIEVAL_MODS:
        importlib.import_module(name)
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


def test_ingest_batch_ingests_every_chunk_and_returns_additive_summary():
    client = _client()
    texts = [
        "first batch chunk about cats",
        "second batch chunk about dogs",
        "third batch chunk about birds",
    ]
    r = client.post(
        "/ingest_batch",
        json={"chunks": [{"text": t} for t in texts]},
    )
    assert r.status_code == 200
    body = r.json()
    # ADDITIVE summary shape: a count + the chunk_hashes, no per-chunk vectors.
    assert body["ingested"] == 3
    assert "dense" not in body
    expected_hashes = [serve._chunk_hash(t) for t in texts]
    # Order is preserved (the batch is ingested in request order).
    assert body["chunk_hashes"] == expected_hashes

    # All three chunks landed in the resident dense index.
    idx = index_store.get_index()
    assert len(idx) == 3
    assert sorted(idx.chunk_hashes()) == sorted(expected_hashes)


def test_ingest_batch_then_search_sees_all_chunks():
    client = _client()
    texts = ["needle one alpha", "needle two beta", "needle three gamma"]
    client.post("/ingest_batch", json={"chunks": [{"text": t} for t in texts]})

    # Each chunk is now retrievable by its own text via the real search legs.
    for t in texts:
        post = client.post("/search", json={"query": t, "top_k": 5})
        assert post.status_code == 200
        post_body = post.json()
        assert post_body["degraded"] is False
        hashes = [hit["chunk_hash"] for hit in post_body["results"]]
        assert serve._chunk_hash(t) in hashes


def test_ingest_batch_threads_per_chunk_provenance():
    client = _client()
    chunks = [
        {
            "text": "provenance batch chunk one",
            "doc_path": "docs/22-search-design.md",
            "heading": "§8",
        },
        {
            "text": "provenance batch chunk two",
            "doc_path": "docs/21-taskdb-design.md",
            "heading": "§3",
        },
    ]
    r = client.post("/ingest_batch", json={"chunks": chunks})
    assert r.status_code == 200
    assert r.json()["ingested"] == 2

    idx = index_store.get_index()
    for c in chunks:
        meta = idx.metadata(serve._chunk_hash(c["text"]))
        assert meta == {"doc_path": c["doc_path"], "heading": c["heading"]}


def test_ingest_batch_skips_blank_text_without_aborting():
    client = _client()
    r = client.post(
        "/ingest_batch",
        json={
            "chunks": [
                {"text": "real chunk body"},
                {"text": ""},
            ]
        },
    )
    assert r.status_code == 200
    body = r.json()
    # The blank entry is skipped; only the real chunk ingests.
    assert body["ingested"] == 1
    assert body["chunk_hashes"] == [serve._chunk_hash("real chunk body")]
    assert len(index_store.get_index()) == 1


def test_ingest_batch_empty_body_is_a_zero_ingest():
    client = _client()
    r = client.post("/ingest_batch", json={"chunks": []})
    assert r.status_code == 200
    body = r.json()
    assert body["ingested"] == 0
    assert body["chunk_hashes"] == []
    assert len(index_store.get_index()) == 0


def test_ingest_batch_upserts_duplicate_text_within_a_batch():
    client = _client()
    r = client.post(
        "/ingest_batch",
        json={
            "chunks": [
                {"text": "stable identity batch chunk"},
                {"text": "stable identity batch chunk"},
            ]
        },
    )
    assert r.status_code == 200
    # Same content -> same chunk_hash -> in-place upsert: one resident row.
    assert len(index_store.get_index()) == 1


def test_ingest_batch_route_exists_on_stdlib_app():
    """The /ingest_batch route is mirrored into the stdlib fallback handler."""
    import inspect

    handler_cls = serve.build_stdlib_app()
    src = inspect.getsource(handler_cls)
    assert "/ingest_batch" in src
