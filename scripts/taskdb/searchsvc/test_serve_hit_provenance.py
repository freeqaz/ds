# SPDX-License-Identifier: Apache-2.0
"""/search HIT-level provenance surface tests (bgem3w7 search-hit-provenance).

The resident index already stores per-chunk {doc_path, heading} (index_store
metadata, threaded through /embed + /ingest_batch). The freshness-verdict unit
surfaced the corpus drift; THIS unit surfaces the per-hit provenance: every
/search result that carries a chunk_hash ADDITIVELY carries the chunk's doc_path
and heading read from the resident index metadata, so a caller can render WHERE a
hit came from without a second lookup.

These tests prove:

  - a /search hit carries doc_path/heading matching the chunk it was ingested
    with (the real dense+sparse+fusion leg, hermetic fake_embed);
  - a text-only ingest (no provenance) yields empty doc_path/heading rather than
    a missing key — the surface is always present, additive;
  - multiple hits each carry their OWN provenance, with the ranked ORDER intact
    (provenance backfill never reorders or drops results);
  - the existing ranked-results contract (degraded/results/chunk_hash) is
    untouched.

Hermetic: fake_embed (256-dim) only, no torch / GPU / network. SEARCHSVC_DB is
pointed at an absent path and the resident singletons are reset per-test so
/embed is the SOLE accumulator (no real taskdb.sqlite bleed-in), mirroring
test_serve_ingest's isolation discipline.
"""

import importlib
import sys

import pytest

import serve

# The real searchsvc retrieval legs /search routes through. A sibling test
# installs SYNTHETIC dense/sparse/fusion on sys.path; evict + re-import the REAL
# ones so this test is order-independent (mirrors test_serve_ingest's discipline).
_REAL_RETRIEVAL_MODS = ("dense", "sparse", "fusion", "index_store")


@pytest.fixture(autouse=True)
def _isolated_empty_index(monkeypatch):
    """Point the DB resolver at an absent path, bind the REAL retrieval legs, and
    drop both resident singletons so /embed is the only source of resident rows."""
    monkeypatch.setenv("SEARCHSVC_DB", "/no/such/hit-provenance-test.sqlite")
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
    yield
    index_store.reset_index()
    sparse.reset_store()


def _client():
    from fastapi.testclient import TestClient

    return TestClient(serve.build_app())


def test_search_hit_carries_threaded_provenance():
    """A chunk ingested via /embed WITH doc_path/heading is retrieved by /search
    carrying that exact provenance on the hit object — additive to chunk_hash."""
    client = _client()
    text = "provenance carrying needle"
    doc_path = "docs/22-search-design.md"
    heading = "§8 hybrid retrieval"
    client.post(
        "/embed",
        json={"text": text, "doc_path": doc_path, "heading": heading},
    )

    post = client.post("/search", json={"query": text, "top_k": 5})
    assert post.status_code == 200
    body = post.json()
    assert body["degraded"] is False
    assert len(body["results"]) == 1
    hit = body["results"][0]
    # The ranked-results contract is intact: chunk_hash still identifies the hit.
    assert hit["chunk_hash"] == serve._chunk_hash(text)
    # ...and the hit ADDITIVELY carries the chunk's provenance.
    assert hit["doc_path"] == doc_path
    assert hit["heading"] == heading


def test_text_only_hit_has_empty_provenance_keys_present():
    """A text-only ingest (no provenance) still yields a hit with doc_path/heading
    PRESENT but empty — the surface is additive and always there, never a missing
    key the caller must defend against."""
    client = _client()
    text = "no provenance chunk"
    client.post("/embed", json={"text": text})

    body = client.post("/search", json={"query": text, "top_k": 5}).json()
    assert body["degraded"] is False
    assert len(body["results"]) == 1
    hit = body["results"][0]
    assert hit["chunk_hash"] == serve._chunk_hash(text)
    assert "doc_path" in hit and hit["doc_path"] == ""
    assert "heading" in hit and hit["heading"] == ""


def test_multiple_hits_each_carry_own_provenance_order_intact():
    """Two distinct chunks each carry their OWN doc_path/heading, and the ranked
    ORDER is intact — provenance backfill is purely additive, never reordering or
    dropping a result. The query is the EXACT text of the first chunk so its dense
    cosine is 1.0 and it ranks strictly above the second (a different chunk)."""
    client = _client()
    t1 = "alpha chunk about retrieval indexing"
    t2 = "beta chunk about something entirely different"
    client.post(
        "/embed",
        json={"text": t1, "doc_path": "docs/a.md", "heading": "Alpha"},
    )
    client.post(
        "/embed",
        json={"text": t2, "doc_path": "docs/b.md", "heading": "Beta"},
    )

    body = client.post("/search", json={"query": t1, "top_k": 5}).json()
    assert body["degraded"] is False
    results = body["results"]
    # Both resident chunks are retrievable; map hash -> provenance for the assert.
    by_hash = {h: serve._chunk_hash(h) for h in (t1, t2)}
    prov = {hit["chunk_hash"]: (hit["doc_path"], hit["heading"]) for hit in results}
    assert prov[by_hash[t1]] == ("docs/a.md", "Alpha")
    assert by_hash[t2] not in prov or prov[by_hash[t2]] == ("docs/b.md", "Beta")

    # FULL ordering: the exact-text chunk (t1) ranks STRICTLY first — provenance
    # backfill preserves the fused ranking it received.
    assert results[0]["chunk_hash"] == by_hash[t1]
    # The fused scores are non-increasing across the whole result list.
    scores = [hit["fused_score"] for hit in results]
    assert scores == sorted(scores, reverse=True)


def test_single_canonical_provenance_path():
    """Provenance is resolved EXACTLY ONCE — by fusion.fuse, the sole canonical
    source. serve.py no longer carries a redundant post-fuse _attach_provenance
    re-walk, so the only resolution path is fuse()'s default-index metadata lookup.

    Proven structurally: serve has no _attach_provenance helper, and the fused dict
    returned by _run_search already carries provenance with NO serve-side backfill
    in the path. fusion.fuse populates doc_path/heading on every hit it builds via
    its default idx = index_store.get_index()."""
    import inspect

    import fusion

    # serve.py owns no second provenance resolver: the redundant path is gone.
    assert not hasattr(serve, "_attach_provenance")

    # fuse() is the one source: it resolves provenance internally from its default
    # index, with NO change to the canonical CALLING shape (serve calls the
    # no-index three-arg form). Assert the required leading params are present and
    # in order — a SUBSET/prefix check, not exact list equality, so a future
    # additive tuning kwarg (e.g. a new fusion knob) does NOT break this test.
    sig = inspect.signature(fusion.fuse)
    params = list(sig.parameters)
    required_prefix = ["dense_hits", "sparse_hits", "top_k"]
    assert params[: len(required_prefix)] == required_prefix
    # The default-index lookup is still reachable: an `index` param remains.
    assert "index" in params
    # _run_search wires fuse and returns its dicts verbatim — no post-fuse re-walk.
    src = inspect.getsource(serve._run_search)
    assert "_attach_provenance" not in src
    assert "fusion.fuse(" in src
