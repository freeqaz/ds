# SPDX-License-Identifier: Apache-2.0
"""ingest.py maintenance-layer tests (bgem3w5 ingest-freshness unit).

Cover the three concerns ingest.py owns over the local taskdb.sqlite:

  - upsert_chunk(s)_by_hash: a content-hash-keyed upsert that adds a NEW hash,
    is idempotent on re-upsert (no duplicate rows), and updates an existing
    logical slot in place.
  - prune_vanished: drops rows whose hash left the live set, keeps the survivors
    (mirrors the Go prune path).
  - index_meta + freshness: record_index_meta writes one provenance row; the
    digest tracks the corpus; freshness() reports fresh==True only while the
    corpus is unchanged and flips to stale on ANY add/remove/edit and for a
    never-built index.

Hermetic: a throwaway sqlite per test pointed at via SEARCHSVC_DB (the shared
resolver index_store owns), stdlib + the fake embedder only. No torch, GPU, or
network."""

import sqlite3

import pytest

import ingest


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A bare temp taskdb.sqlite resolved via SEARCHSVC_DB (the unified resolver
    ingest reuses from index_store), with the other env aliases cleared so the
    resolution is unambiguous."""
    path = tmp_path / "taskdb.sqlite"
    monkeypatch.setenv("SEARCHSVC_DB", str(path))
    monkeypatch.delenv("TASKDB_SQLITE", raising=False)
    monkeypatch.delenv("TASKDB_DB", raising=False)
    ingest.ensure_schema()
    return str(path)


def _count(db_path):
    conn = sqlite3.connect(db_path)
    try:
        (n,) = conn.execute("SELECT COUNT(*) FROM doc_chunks").fetchone()
        return n
    finally:
        conn.close()


# --- DB resolution reuse -----------------------------------------------------


def test_reuses_index_store_resolver(db):
    """ingest resolves the DB through the SAME resolver index_store exposes — not
    a re-forked env handler — so all three legs agree on the file."""
    import index_store

    assert ingest.resolve_db_path is index_store.resolve_db_path
    assert ingest.resolve_db_path() == db


# --- upsert-by-hash ----------------------------------------------------------


def test_upsert_adds_new_hash(db):
    h = ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha body")
    assert h == ingest.git_blob_sha("alpha body")
    assert _count(db) == 1


def test_upsert_is_idempotent_no_duplicate(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha body")
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha body")
    # Same (hash, path, heading): an in-place upsert, never a second row.
    assert _count(db) == 1


def test_upsert_hash_matches_go_blob_sha(db):
    # The hash ingest writes is the git-blob SHA — byte-for-byte the Go side's
    # gitBlobSHA for the same content, so the two writers share one identity.
    h = ingest.upsert_chunk_by_hash("docs/a.md", "", "real body")
    conn = sqlite3.connect(db)
    try:
        (stored,) = conn.execute(
            "SELECT hash FROM doc_chunks WHERE path='docs/a.md'"
        ).fetchone()
    finally:
        conn.close()
    assert stored == h == ingest.git_blob_sha("real body")


def test_upsert_batch_writes_all(db):
    hashes = ingest.upsert_chunks_by_hash(
        [
            {"path": "docs/a.md", "heading": "A", "body": "one"},
            {"path": "docs/b.md", "heading": "B", "body": "two"},
            {"path": "docs/c.md", "body": "three"},
        ]
    )
    assert len(hashes) == 3
    assert _count(db) == 3


# --- prune-vanished ----------------------------------------------------------


def test_prune_drops_vanished_keeps_survivors(db):
    keep = ingest.upsert_chunk_by_hash("docs/a.md", "A", "keep me")
    gone = ingest.upsert_chunk_by_hash("docs/b.md", "B", "drop me")
    assert _count(db) == 2

    pruned = ingest.prune_vanished({keep})
    assert pruned == 1
    assert _count(db) == 1

    conn = sqlite3.connect(db)
    try:
        rows = {r[0] for r in conn.execute("SELECT hash FROM doc_chunks")}
    finally:
        conn.close()
    assert rows == {keep}
    assert gone not in rows


def test_prune_noop_when_all_live(db):
    a = ingest.upsert_chunk_by_hash("docs/a.md", "A", "a")
    b = ingest.upsert_chunk_by_hash("docs/b.md", "B", "b")
    assert ingest.prune_vanished({a, b}) == 0
    assert _count(db) == 2


# --- index_meta + freshness --------------------------------------------------


def test_record_and_read_index_meta(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "a")
    ingest.upsert_chunk_by_hash("docs/b.md", "B", "b")
    meta = ingest.record_index_meta(
        model_label="bge-m3-http", dense_dims=256, sparse_model="bge-m3-http",
        built_at=1234,
    )
    assert meta["chunk_count"] == 2
    assert meta["dense_dims"] == 256

    read = ingest.read_index_meta()
    assert read["model_label"] == "bge-m3-http"
    assert read["dense_dims"] == 256
    assert read["sparse_model"] == "bge-m3-http"
    assert read["built_at"] == 1234
    assert read["chunk_count"] == 2
    assert read["digest"] == meta["digest"]


def test_index_meta_is_single_row(db):
    ingest.record_index_meta(model_label="m1", dense_dims=256)
    ingest.record_index_meta(model_label="m2", dense_dims=256)
    conn = sqlite3.connect(db)
    try:
        (rows,) = conn.execute("SELECT COUNT(*) FROM index_meta").fetchone()
    finally:
        conn.close()
    # id pinned to 1 → the second record OVERWRITES, never appends.
    assert rows == 1
    assert ingest.read_index_meta()["model_label"] == "m2"


def test_corpus_digest_order_independent(db):
    # Insert two chunks in one order, digest; a fresh DB with the SAME chunks in
    # the reverse order must digest identically (sorted-hash digest).
    ingest.upsert_chunk_by_hash("docs/a.md", "", "alpha")
    ingest.upsert_chunk_by_hash("docs/b.md", "", "beta")
    d1 = ingest.corpus_digest()

    conn = sqlite3.connect(db)
    try:
        conn.execute("DELETE FROM doc_chunks")
        conn.commit()
    finally:
        conn.close()
    ingest.upsert_chunk_by_hash("docs/b.md", "", "beta")
    ingest.upsert_chunk_by_hash("docs/a.md", "", "alpha")
    d2 = ingest.corpus_digest()
    assert d1 == d2


def test_freshness_fresh_after_record_then_stale_on_change(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "a")
    ingest.record_index_meta(model_label="m", dense_dims=256)

    f = ingest.freshness()
    assert f["fresh"] is True
    assert f["stored_digest"] == f["current_digest"]
    assert f["stored_count"] == f["current_count"] == 1

    # Add a chunk: the corpus digest moves, the index is now stale.
    ingest.upsert_chunk_by_hash("docs/b.md", "B", "b")
    f2 = ingest.freshness()
    assert f2["fresh"] is False
    assert f2["stored_digest"] != f2["current_digest"]
    assert f2["current_count"] == 2


def test_freshness_stale_on_edit(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "original")
    ingest.record_index_meta(model_label="m", dense_dims=256)
    assert ingest.freshness()["fresh"] is True

    # Editing a chunk's body changes its hash → the digest moves → stale.
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "UPDATE doc_chunks SET body=?, hash=? WHERE path='docs/a.md'",
            ("edited", ingest.git_blob_sha("edited")),
        )
        conn.commit()
    finally:
        conn.close()
    assert ingest.freshness()["fresh"] is False


def test_freshness_stale_for_never_built_index(db):
    # No index_meta row yet: freshness is the safe default (NOT fresh), prompting
    # a /reindex rather than trusting a never-built index.
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "a")
    f = ingest.freshness()
    assert f["fresh"] is False
    assert f["stored_digest"] is None
    assert f["stored_count"] is None
