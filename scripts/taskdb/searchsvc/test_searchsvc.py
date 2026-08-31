#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# test_searchsvc.py — hermetic tests for the searchsvc dispatcher + fake embedder.
#
# These run with NO DS_EMBED_LIVE, NO torch, NO model download, NO GPU. The
# central invariants:
#   - importing serve.py does NOT pull torch into sys.modules (even transitively)
#   - the fake embedder is deterministic: width EXACTLY 256 dense + stable sparse;
#     identical input -> identical output
#   - the FastAPI dispatcher stands up and /embed + /search answer over TestClient
#   - /search wires fuse(dense_search, sparse_search) and degrades cleanly while
#     the retrieval modules are absent

import importlib
import sys

import fake_embed


# ---------------------------------------------------------------------------
# torch-isolation: serve.py must never import torch, even transitively.
# ---------------------------------------------------------------------------


def test_importing_serve_does_not_import_torch():
    # Drop any pre-existing import so the assertion is about serve.py itself.
    sys.modules.pop("torch", None)
    sys.modules.pop("serve", None)
    import serve  # noqa: F401

    importlib.reload(serve)
    assert "torch" not in sys.modules, "serve.py must not import torch (top-level or transitively)"


def test_fake_embed_does_not_import_torch():
    sys.modules.pop("torch", None)
    importlib.reload(fake_embed)
    assert "torch" not in sys.modules


# ---------------------------------------------------------------------------
# Fake embedder: deterministic dense (width EXACTLY 256) + stable sparse.
# ---------------------------------------------------------------------------


def test_dense_width_is_exactly_256():
    vec = fake_embed.fake_dense("the quick brown fox")
    assert fake_embed.FALLBACK_DIMS == 256
    assert len(vec) == 256
    # Width is NOT the live 1024.
    assert len(vec) != 1024


def test_dense_is_l2_normalized():
    vec = fake_embed.fake_dense("default-deny egress firewall")
    norm = sum(x * x for x in vec) ** 0.5
    assert abs(norm - 1.0) < 1e-9


def test_dense_empty_text_is_zero_vector():
    vec = fake_embed.fake_dense("")
    assert len(vec) == 256
    assert all(x == 0.0 for x in vec)


def test_dense_is_deterministic():
    a = fake_embed.fake_dense("hybrid dense plus sparse retrieval")
    b = fake_embed.fake_dense("hybrid dense plus sparse retrieval")
    assert a == b


def test_sparse_is_a_map_of_int_ids_to_weights():
    sp = fake_embed.fake_sparse("alpha beta beta gamma gamma gamma")
    assert isinstance(sp, dict)
    assert all(isinstance(k, int) for k in sp)
    assert all(isinstance(v, float) for v in sp.values())
    # term counts: one distinct id per distinct token, weight = count.
    assert sorted(sp.values()) == [1.0, 2.0, 3.0]


def test_sparse_token_ids_bounded():
    sp = fake_embed.fake_sparse("alpha beta gamma delta")
    assert all(0 <= k < fake_embed.SPARSE_VOCAB for k in sp)


def test_sparse_is_deterministic():
    a = fake_embed.fake_sparse("the quick brown fox")
    b = fake_embed.fake_sparse("the quick brown fox")
    assert a == b


def test_fake_embed_combines_both_halves_deterministically():
    a = fake_embed.fake_embed("repeatable input text")
    b = fake_embed.fake_embed("repeatable input text")
    assert a == b
    assert len(a["dense"]) == 256
    assert isinstance(a["sparse"], dict)


def test_distinct_texts_differ():
    a = fake_embed.fake_embed("one kind of text")
    b = fake_embed.fake_embed("a wholly different string")
    assert a["dense"] != b["dense"]
    assert a["sparse"] != b["sparse"]


# ---------------------------------------------------------------------------
# FastAPI dispatcher: server stands up and answers /embed + /search.
# FastAPI IS present in the uv env, so these RUN (importorskip is a bonus net).
# ---------------------------------------------------------------------------


def _client():
    import importlib as _il

    pytest = _il.import_module("pytest")
    pytest.importorskip("fastapi")  # defensive bonus; present in the uv env
    from fastapi.testclient import TestClient

    import serve

    return TestClient(serve.build_app())


def test_embed_route_returns_dense_256_and_sparse():
    client = _client()
    resp = client.post("/embed", json={"text": "default-deny egress firewall"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["dense_dims"] == 256
    assert len(body["dense"]) == 256
    assert isinstance(body["sparse"], dict)
    # JSON object keys are strings on the wire.
    assert all(isinstance(k, str) for k in body["sparse"])


def test_embed_route_is_deterministic_over_http():
    client = _client()
    a = client.post("/embed", json={"text": "stable wire output"}).json()
    b = client.post("/embed", json={"text": "stable wire output"}).json()
    assert a == b


def test_search_route_degrades_cleanly_when_a_leg_is_absent(monkeypatch):
    # If a retrieval leg cannot be imported, /search must still answer 200 with a
    # degraded marker (+ the query embedding shape) rather than 500 — proving the
    # route's degrade path. The dense/sparse/fusion legs now all ship in
    # searchsvc/, so force-absent one (sys.modules[name]=None makes `import name`
    # raise) to actually exercise the degraded branch.
    monkeypatch.setitem(sys.modules, "fusion", None)
    client = _client()
    resp = client.post("/search", json={"query": "hybrid search", "top_k": 5})
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "hybrid search"
    # degraded path reports query embedding shape so the wiring is observable.
    assert body["degraded"] is True
    assert body["query_dense_dims"] == 256
    assert body["query_sparse_terms"] >= 1


def test_search_route_uses_fusion_when_modules_present(tmp_path, monkeypatch):
    # Drop synthetic dense/sparse/fusion modules on sys.path so _run_search takes
    # the real fuse(dense_search, sparse_search) branch — proving serve.py wires
    # exactly that call and no later unit needs to edit serve.py.
    import importlib as _il

    for name, src in {
        "dense": "def dense_search(q, top_k=10):\n    return [('d1', 0.9)]\n",
        "sparse": "def sparse_search(q, top_k=10):\n    return [('s1', 0.8)]\n",
        "fusion": (
            "def fuse(dense_hits, sparse_hits, top_k=10):\n"
            "    return [{'id': i, 'score': s} for i, s in dense_hits + sparse_hits]\n"
        ),
    }.items():
        (tmp_path / f"{name}.py").write_text(src)
    monkeypatch.syspath_prepend(str(tmp_path))
    for name in ("dense", "sparse", "fusion"):
        sys.modules.pop(name, None)

    pytest = _il.import_module("pytest")
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    import serve

    client = TestClient(serve.build_app())
    body = client.post("/search", json={"query": "wired", "top_k": 5}).json()
    assert body["degraded"] is False
    ids = {r["id"] for r in body["results"]}
    assert ids == {"d1", "s1"}


# ---------------------------------------------------------------------------
# Defensive bonus: the stdlib http.server handler is constructible without any
# third-party dep (does not stand a live socket here — just proves the fallback).
# ---------------------------------------------------------------------------


def test_stdlib_fallback_handler_is_constructible():
    import serve

    handler_cls = serve.build_stdlib_app()
    assert handler_cls is not None
    assert hasattr(handler_cls, "do_POST")
