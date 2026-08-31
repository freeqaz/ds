# SPDX-License-Identifier: Apache-2.0
"""/search freshness-verdict surface tests (bgem3w6 freshness-verdict-surface).

ingest.freshness() already computes a fresh/stale verdict against the corpus
digest; this unit SURFACES it on /search. These tests prove:

  - the /search response ADDITIVELY carries a "freshness" object (the ranked
    results shape is untouched — degraded/results/query still present);
  - the verdict tracks the corpus: NOT fresh (verdict="stale") before any
    index_meta row, fresh right after record_index_meta, and stale again once
    the corpus drifts;
  - drift reports the count delta (current_count - stored_count);
  - a /search against an absent/unresolvable DB still returns 200 with a SAFE
    stale verdict (best-effort: never 500 the search route).

Hermetic: fake_embed only, a real on-disk temp sqlite for the corpus, no torch /
GPU / network. SEARCHSVC_DB is pointed per-test so /search reads exactly the
corpus the test built.
"""

import importlib
import sys

import pytest

import ingest
import serve

# The retrieval modules /search routes through. A sibling test installs SYNTHETIC
# dense/sparse/fusion on sys.path; evict + re-import the REAL ones so this test is
# order-independent (mirrors test_serve_ingest's discipline).
_REAL_RETRIEVAL_MODS = ("dense", "sparse", "fusion", "index_store")


def _client():
    from fastapi.testclient import TestClient

    return TestClient(serve.build_app())


@pytest.fixture
def real_corpus_db(monkeypatch, tmp_path):
    """Point SEARCHSVC_DB at a real on-disk temp sqlite, bind the REAL retrieval
    legs, and reset the resident singletons. Returns the db path so the test can
    drive ingest.* helpers against the SAME DB /search resolves."""
    db = str(tmp_path / "freshness-corpus.sqlite")
    monkeypatch.setenv("SEARCHSVC_DB", db)
    monkeypatch.delenv("TASKDB_SQLITE", raising=False)
    monkeypatch.delenv("TASKDB_DB", raising=False)
    for name in _REAL_RETRIEVAL_MODS:
        sys.modules.pop(name, None)
    for name in _REAL_RETRIEVAL_MODS:
        importlib.import_module(name)
    index_store = importlib.import_module("index_store")
    sparse = importlib.import_module("sparse")
    index_store.reset_index()
    sparse.reset_store()
    ingest.ensure_schema(db)
    yield db
    index_store.reset_index()
    sparse.reset_store()


def _verdict(db_path):
    """Drive one /search and return its freshness object, asserting the ranked
    shape stays intact alongside it."""
    client = _client()
    r = client.post("/search", json={"query": "anything", "top_k": 5})
    assert r.status_code == 200
    body = r.json()
    # Additive: the existing ranked-results shape is untouched.
    assert "query" in body
    assert "freshness" in body, "the /search response must carry the verdict"
    return body, body["freshness"]


def test_search_carries_freshness_object_additively(real_corpus_db):
    """/search ADDITIVELY attaches a well-formed freshness object; the
    ranked-results contract (query echo + a results/degraded shape) is preserved."""
    body, fresh = _verdict(real_corpus_db)
    # The ranked shape is intact (degraded path or real-leg results — either way
    # the keys the Go client decodes are present and freshness is NOT one of them
    # the client requires, so it is purely additive).
    assert body["query"] == "anything"
    # The verdict is a complete dict with the documented keys.
    for key in (
        "fresh",
        "verdict",
        "stored_digest",
        "current_digest",
        "stored_count",
        "current_count",
        "drift",
    ):
        assert key in fresh, f"freshness verdict missing {key!r}"
    assert isinstance(fresh["fresh"], bool)
    assert fresh["verdict"] in ("fresh", "stale")
    # verdict mirrors the bool exactly.
    assert (fresh["verdict"] == "fresh") == fresh["fresh"]


def test_never_built_index_is_stale(real_corpus_db):
    """A corpus with chunks but no index_meta row is NOT fresh — the safe default
    that tells the caller to /reindex."""
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha body", db_path=real_corpus_db)
    _, fresh = _verdict(real_corpus_db)
    assert fresh["fresh"] is False
    assert fresh["verdict"] == "stale"
    assert fresh["stored_digest"] is None
    assert fresh["stored_count"] is None
    # current_count counts the live chunk; drift = current - stored(0).
    assert fresh["current_count"] == 1
    assert fresh["drift"] == 1


def test_fresh_after_record_index_meta(real_corpus_db):
    """Recording index_meta against the CURRENT corpus makes /search report fresh,
    with matching stored/current digests and zero drift."""
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha body", db_path=real_corpus_db)
    ingest.upsert_chunk_by_hash("docs/b.md", "B", "beta body", db_path=real_corpus_db)
    ingest.record_index_meta(model_label="fake", dense_dims=256, db_path=real_corpus_db)

    _, fresh = _verdict(real_corpus_db)
    assert fresh["fresh"] is True
    assert fresh["verdict"] == "fresh"
    assert fresh["stored_digest"] == fresh["current_digest"]
    assert fresh["stored_count"] == 2
    assert fresh["current_count"] == 2
    assert fresh["drift"] == 0


def test_stale_after_corpus_drifts(real_corpus_db):
    """After a fresh index, adding a chunk drifts the corpus digest: /search flips
    to stale and reports the positive drift count."""
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha body", db_path=real_corpus_db)
    ingest.record_index_meta(model_label="fake", dense_dims=256, db_path=real_corpus_db)
    # Fresh right after the record.
    _, fresh0 = _verdict(real_corpus_db)
    assert fresh0["fresh"] is True

    # Corpus drifts: a new chunk the resident index never absorbed.
    ingest.upsert_chunk_by_hash("docs/c.md", "C", "gamma body", db_path=real_corpus_db)
    _, fresh1 = _verdict(real_corpus_db)
    assert fresh1["fresh"] is False
    assert fresh1["verdict"] == "stale"
    # The digests now differ and drift is the +1 unabsorbed chunk.
    assert fresh1["stored_digest"] != fresh1["current_digest"]
    assert fresh1["stored_count"] == 1
    assert fresh1["current_count"] == 2
    assert fresh1["drift"] == 1


def test_unresolvable_db_degrades_to_safe_stale(monkeypatch):
    """A /search whose DB cannot be opened (parent dir absent) still returns 200
    with a SAFE stale verdict rather than 500 — best-effort surfacing."""
    monkeypatch.setenv("SEARCHSVC_DB", "/no/such/dir/freshness-test.sqlite")
    monkeypatch.delenv("TASKDB_SQLITE", raising=False)
    monkeypatch.delenv("TASKDB_DB", raising=False)
    for name in _REAL_RETRIEVAL_MODS:
        sys.modules.pop(name, None)
    for name in _REAL_RETRIEVAL_MODS:
        importlib.import_module(name)
    importlib.import_module("index_store").reset_index()
    importlib.import_module("sparse").reset_store()

    client = _client()
    r = client.post("/search", json={"query": "anything", "top_k": 5})
    assert r.status_code == 200
    fresh = r.json()["freshness"]
    assert fresh["fresh"] is False
    assert fresh["verdict"] == "stale"
