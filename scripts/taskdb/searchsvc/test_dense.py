# SPDX-License-Identifier: Apache-2.0
#
# test_dense.py — hermetic tests for the dense brute-force KNN (dense.py) and the
# resident index (index_store.py). NO model, NO torch, NO GPU, NO server stand-up:
# pure-function calls over fixture chunks embedded with the deterministic fake.
#
# Invariants exercised:
#   - dense_search ranks the known-relevant chunk first (exact cosine).
#   - the result order is deterministic and tie-broken stably (ascending hash).
#   - the contract signature matches serve.py: dense_search(query_dense, top_k=...)
#     with NO store positional arg; the module manages its store internally.
#   - a query-width != index-width mismatch raises LOUDLY (never scores a silent 0).
#   - index_store builds from doc_chunks in a local sqlite AND decodes the packed
#     float32 chunk_embeddings cache BLOB the Go side writes.
#   - sub-second over ~150 fixture vectors.

import sqlite3
import struct
import time

import numpy as np
import pytest

import dense
import fake_embed
import index_store


# ---------------------------------------------------------------------------
# Fixtures: a small corpus of fixture chunks embedded with the hermetic fake.
# ---------------------------------------------------------------------------


FIXTURE_CHUNKS = [
    ("h_firewall", "docs/net.md", "Firewall", "default-deny egress firewall nftables rules"),
    ("h_dense", "docs/search.md", "Dense", "dense brute force cosine retrieval over numpy matrix"),
    ("h_sparse", "docs/search.md", "Sparse", "sparse lexical token weight dot product scoring"),
    ("h_fusion", "docs/search.md", "Fusion", "reciprocal rank fusion of dense and sparse hits"),
    ("h_vm", "docs/vm.md", "VM", "per session kvm virtual machine on bare metal hardware"),
]


def _build_index(chunks=FIXTURE_CHUNKS):
    idx = index_store.DenseIndex()
    for chunk_hash, path, heading, body in chunks:
        idx.ingest_text(chunk_hash, body, path, heading)
    return idx


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Each test starts with a clean module singleton so installing an explicit
    index never leaks across tests."""
    index_store.reset_index()
    yield
    index_store.reset_index()


# ---------------------------------------------------------------------------
# index_store basics
# ---------------------------------------------------------------------------


def test_index_records_dense_dims_from_embedder_width():
    idx = _build_index()
    assert idx.dense_dims == fake_embed.FALLBACK_DIMS == 256
    assert len(idx) == len(FIXTURE_CHUNKS)
    assert idx.matrix().shape == (len(FIXTURE_CHUNKS), 256)


def test_index_rows_are_l2_normalized():
    idx = _build_index()
    norms = np.linalg.norm(idx.matrix(), axis=1)
    # every (non-empty) row has unit norm.
    assert np.allclose(norms, 1.0, atol=1e-6)


def test_chunk_hashes_parallel_to_matrix_in_insertion_order():
    idx = _build_index()
    assert idx.chunk_hashes() == [c[0] for c in FIXTURE_CHUNKS]


def test_metadata_carries_doc_path_and_heading():
    idx = _build_index()
    meta = idx.metadata("h_dense")
    assert meta == {"doc_path": "docs/search.md", "heading": "Dense"}


def test_reingesting_a_hash_overwrites_in_place_no_duplicate_row():
    idx = index_store.DenseIndex()
    idx.ingest_text("h", "first body", "p", "H1")
    idx.ingest_text("h", "second different body", "p2", "H2")
    assert len(idx) == 1
    assert idx.chunk_hashes() == ["h"]
    assert idx.metadata("h")["heading"] == "H2"


# ---------------------------------------------------------------------------
# dense_search ranking
# ---------------------------------------------------------------------------


def test_query_ranks_its_own_chunk_first_with_self_score_one():
    idx = _build_index()
    index_store.set_index(idx)
    # The query text IS the dense chunk's body — its self-cosine is 1.0.
    q = fake_embed.fake_dense("dense brute force cosine retrieval over numpy matrix")
    hits = dense.dense_search(q, top_k=3)
    assert hits[0][0] == "h_dense"
    assert hits[0][1] == pytest.approx(1.0, abs=1e-5)
    # descending score order.
    scores = [s for _, s in hits]
    assert scores == sorted(scores, reverse=True)


def test_relevant_chunk_ranks_above_unrelated_chunk():
    idx = _build_index()
    index_store.set_index(idx)
    q = fake_embed.fake_dense("firewall egress default-deny")
    hits = dense.dense_search(q, top_k=len(FIXTURE_CHUNKS))
    rank = [h for h, _ in hits]
    assert rank.index("h_firewall") < rank.index("h_vm")


def test_uses_module_singleton_when_no_index_passed():
    # serve.py calls dense_search(query_dense, top_k=...) with NO store arg.
    idx = _build_index()
    index_store.set_index(idx)
    q = fake_embed.fake_dense("sparse lexical token weight dot product scoring")
    hits = dense.dense_search(q, top_k=2)
    assert hits[0][0] == "h_sparse"


def test_top_k_clamps_to_corpus_size():
    idx = _build_index()
    index_store.set_index(idx)
    q = fake_embed.fake_dense("anything")
    hits = dense.dense_search(q, top_k=999)
    assert len(hits) == len(FIXTURE_CHUNKS)


def test_empty_index_returns_empty_list():
    index_store.set_index(index_store.DenseIndex())
    hits = dense.dense_search([0.0] * 256, top_k=5)
    assert hits == []


# ---------------------------------------------------------------------------
# Deterministic, stable tie-breaking.
# ---------------------------------------------------------------------------


def test_ties_break_by_ascending_chunk_hash_deterministically():
    # Three chunks embedded from the SAME body -> identical vectors -> identical
    # scores against any query. Insert them out of hash order; the result must be
    # sorted ascending by hash, stable across repeated calls.
    idx = index_store.DenseIndex()
    for h in ("hc", "ha", "hb"):
        idx.ingest_text(h, "identical body text for the tie", "p", "")
    index_store.set_index(idx)
    q = fake_embed.fake_dense("identical body text for the tie")
    hits1 = dense.dense_search(q, top_k=3)
    hits2 = dense.dense_search(q, top_k=3)
    assert hits1 == hits2
    assert [h for h, _ in hits1] == ["ha", "hb", "hc"]
    # all three share the same (max) score.
    scores = {s for _, s in hits1}
    assert len(scores) == 1


# ---------------------------------------------------------------------------
# Width-mismatch guard — the loud failure, NOT a silent all-zero scoring.
# ---------------------------------------------------------------------------


def test_query_width_mismatch_raises_loudly():
    idx = _build_index()  # 256-wide index
    index_store.set_index(idx)
    short_query = [0.1] * 128  # wrong width on purpose
    with pytest.raises(ValueError) as ei:
        dense.dense_search(short_query, top_k=3)
    msg = str(ei.value)
    assert "128" in msg and "256" in msg
    assert "mismatch" in msg.lower()


def test_index_ingest_width_drift_raises_loudly():
    idx = index_store.DenseIndex()
    idx.ingest("h1", [0.0, 1.0, 0.0], "p", "")  # width 3 sets dense_dims
    with pytest.raises(ValueError) as ei:
        idx.ingest("h2", [0.0, 1.0], "p", "")    # width 2 drift
    assert "mismatch" in str(ei.value).lower()


# ---------------------------------------------------------------------------
# sqlite refresh: build from doc_chunks, and decode the packed float32 cache.
# ---------------------------------------------------------------------------


def _make_db(path, rows, cached=None):
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE doc_chunks (id INTEGER PRIMARY KEY, doc_id INTEGER NOT NULL,"
        " path TEXT NOT NULL, heading TEXT NOT NULL DEFAULT '', seq INTEGER NOT NULL,"
        " body TEXT NOT NULL, hash TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE chunk_embeddings (chunk_hash TEXT PRIMARY KEY, model TEXT NOT NULL,"
        " dims INTEGER NOT NULL, vector BLOB NOT NULL)"
    )
    for i, (chunk_hash, p, heading, body) in enumerate(rows):
        conn.execute(
            "INSERT INTO doc_chunks (doc_id, path, heading, seq, body, hash)"
            " VALUES (?,?,?,?,?,?)",
            (1, p, heading, i, body, chunk_hash),
        )
    for chunk_hash, vec in (cached or {}).items():
        blob = struct.pack("<%df" % len(vec), *vec)
        conn.execute(
            "INSERT INTO chunk_embeddings (chunk_hash, model, dims, vector)"
            " VALUES (?,?,?,?)",
            (chunk_hash, "bge-m3-http", len(vec), blob),
        )
    conn.commit()
    conn.close()


def test_refresh_from_sqlite_embeds_doc_chunk_bodies(tmp_path):
    db = tmp_path / "taskdb.sqlite"
    _make_db(db, FIXTURE_CHUNKS)
    idx = index_store.DenseIndex()
    n = idx.refresh_from_sqlite(str(db))
    assert n == len(FIXTURE_CHUNKS)
    assert idx.dense_dims == 256
    index_store.set_index(idx)
    q = fake_embed.fake_dense("dense brute force cosine retrieval over numpy matrix")
    assert dense.dense_search(q, top_k=1)[0][0] == "h_dense"
    assert idx.metadata("h_firewall")["doc_path"] == "docs/net.md"


def test_refresh_decodes_packed_float32_cache_blob(tmp_path):
    # When chunk_embeddings holds a dense vector, the refresh decodes the packed
    # little-endian float32 BLOB (Go's encodeVector format) instead of re-embedding.
    db = tmp_path / "taskdb.sqlite"
    # A deliberately distinctive cached vector: a one-hot at index 7.
    cached_vec = [0.0] * 256
    cached_vec[7] = 1.0
    rows = [("h_cached", "docs/x.md", "X", "unrelated body that would embed differently")]
    _make_db(db, rows, cached={"h_cached": cached_vec})
    idx = index_store.DenseIndex()
    idx.refresh_from_sqlite(str(db))
    index_store.set_index(idx)
    # Query the SAME one-hot vector: cosine == 1.0 proves the cached blob was used
    # (the body would have embedded to a different, non-one-hot vector).
    q = [0.0] * 256
    q[7] = 1.0
    hit = dense.dense_search(q, top_k=1)[0]
    assert hit[0] == "h_cached"
    assert hit[1] == pytest.approx(1.0, abs=1e-6)


def test_get_index_uses_env_db(tmp_path, monkeypatch):
    db = tmp_path / "taskdb.sqlite"
    _make_db(db, FIXTURE_CHUNKS)
    monkeypatch.setenv("SEARCHSVC_DB", str(db))
    index_store.reset_index()
    idx = index_store.get_index()
    assert len(idx) == len(FIXTURE_CHUNKS)


def test_missing_db_yields_empty_index_not_error(monkeypatch):
    # An unlocatable DB must not wedge search — get_index returns an empty index.
    # Force the locator to find nothing (no env DB, no relative fallback).
    monkeypatch.setattr(index_store, "_default_db_path", lambda: None)
    index_store.reset_index()
    idx = index_store.get_index()
    assert len(idx) == 0
    # an empty index searches to [] (never an error).
    assert dense.dense_search([0.0] * 256, top_k=3, index=idx) == []


def test_bad_db_path_degrades_to_empty_not_raise(tmp_path, monkeypatch):
    # A located-but-unreadable DB must degrade to an empty index, not propagate.
    bogus = tmp_path / "not-a-db.sqlite"
    bogus.write_text("this is not sqlite")
    monkeypatch.setattr(index_store, "_default_db_path", lambda: str(bogus))
    index_store.reset_index()
    idx = index_store.get_index()
    assert len(idx) == 0


# ---------------------------------------------------------------------------
# Cache-blob harden: refresh ties recorded dims to the model and raises LOUDLY
# when the decoded width disagrees with the dims column the Go writer persisted.
# ---------------------------------------------------------------------------


def _make_db_recorded_dims(path, chunk_hash, vec, recorded_dims, model="bge-m3-http"):
    """Like _make_db but writes an EXPLICIT (possibly wrong) dims column so the
    decoded width can be made to disagree with the recorded dims."""
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE doc_chunks (id INTEGER PRIMARY KEY, doc_id INTEGER NOT NULL,"
        " path TEXT NOT NULL, heading TEXT NOT NULL DEFAULT '', seq INTEGER NOT NULL,"
        " body TEXT NOT NULL, hash TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE chunk_embeddings (chunk_hash TEXT PRIMARY KEY, model TEXT NOT NULL,"
        " dims INTEGER NOT NULL, vector BLOB NOT NULL)"
    )
    conn.execute(
        "INSERT INTO doc_chunks (doc_id, path, heading, seq, body, hash)"
        " VALUES (?,?,?,?,?,?)",
        (1, "docs/x.md", "X", 0, "some body", chunk_hash),
    )
    blob = struct.pack("<%df" % len(vec), *vec)
    conn.execute(
        "INSERT INTO chunk_embeddings (chunk_hash, model, dims, vector)"
        " VALUES (?,?,?,?)",
        (chunk_hash, model, recorded_dims, blob),
    )
    conn.commit()
    conn.close()


def test_refresh_raises_on_decoded_width_vs_recorded_dims_mismatch(tmp_path):
    # The vector decodes to width 4 but the dims column claims 256 — a corrupt
    # cache row. refresh_from_sqlite must raise LOUDLY (mirrors ingest's guard),
    # never silently index a wrong-width vector.
    db = tmp_path / "taskdb.sqlite"
    _make_db_recorded_dims(db, "h_bad", [0.1, 0.2, 0.3, 0.4], recorded_dims=256)
    idx = index_store.DenseIndex()
    with pytest.raises(ValueError) as ei:
        idx.refresh_from_sqlite(str(db))
    msg = str(ei.value)
    assert "4" in msg and "256" in msg
    assert "mismatch" in msg.lower()
    # the producing model label is surfaced in the loud error.
    assert "bge-m3-http" in msg


def test_refresh_accepts_matching_recorded_dims(tmp_path):
    # A vector whose decoded width equals the recorded dims is ingested cleanly.
    db = tmp_path / "taskdb.sqlite"
    vec = [0.0] * 256
    vec[3] = 1.0
    _make_db_recorded_dims(db, "h_ok", vec, recorded_dims=256)
    idx = index_store.DenseIndex()
    n = idx.refresh_from_sqlite(str(db))
    assert n == 1
    assert idx.dense_dims == 256
    assert idx.chunk_hashes() == ["h_ok"]


# ---------------------------------------------------------------------------
# Shared DB resolver: the dense and sparse legs must resolve the SAME path so
# they never index two different DBs.
# ---------------------------------------------------------------------------


def test_dense_and_sparse_resolve_the_same_db_path(monkeypatch):
    import sparse

    monkeypatch.setenv("SEARCHSVC_DB", "/some/where/taskdb.sqlite")
    # SEARCHSVC_DB stays the dense winner AND the sparse leg follows it.
    assert index_store.resolve_db_path() == "/some/where/taskdb.sqlite"
    assert sparse._db_path() == index_store.resolve_db_path()


def test_searchsvc_db_wins_over_taskdb_aliases(monkeypatch):
    import sparse

    monkeypatch.setenv("SEARCHSVC_DB", "/winner/taskdb.sqlite")
    monkeypatch.setenv("TASKDB_SQLITE", "/loser1/taskdb.sqlite")
    monkeypatch.setenv("TASKDB_DB", "/loser2/taskdb.sqlite")
    assert index_store.resolve_db_path() == "/winner/taskdb.sqlite"
    # Both legs agree on the winner.
    assert sparse._db_path() == "/winner/taskdb.sqlite"


def test_taskdb_aliases_reconcile_to_one_path(monkeypatch):
    import sparse

    # No SEARCHSVC_DB: TASKDB_SQLITE then TASKDB_DB are the reconciled fallbacks,
    # and BOTH legs resolve to the SAME single path (the historical drift, closed).
    monkeypatch.delenv("SEARCHSVC_DB", raising=False)
    monkeypatch.setenv("TASKDB_SQLITE", "/alias/taskdb.sqlite")
    monkeypatch.setenv("TASKDB_DB", "/other/taskdb.sqlite")
    assert index_store.resolve_db_path() == "/alias/taskdb.sqlite"
    assert sparse._db_path() == index_store.resolve_db_path()


# ---------------------------------------------------------------------------
# Performance: sub-second over ~150 fixture vectors.
# ---------------------------------------------------------------------------


def test_subsecond_over_150_vectors():
    idx = index_store.DenseIndex()
    for i in range(150):
        idx.ingest_text("h%03d" % i, "fixture chunk number %d about retrieval" % i, "p", "")
    index_store.set_index(idx)
    q = fake_embed.fake_dense("fixture chunk number 42 about retrieval")
    start = time.perf_counter()
    hits = dense.dense_search(q, top_k=10)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0
    assert hits[0][0] == "h042"
