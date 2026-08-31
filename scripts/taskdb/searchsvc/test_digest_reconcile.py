# SPDX-License-Identifier: Apache-2.0
"""Digest reconciliation tests (bgem3w6 digest-reconcile unit).

The Go pusher (searchsvc_ingest.go) stashes the corpus digest it pushed in the
meta table under searchsvc_index_digest, and ingest.py derives a same-shape
sha256-over-sorted-distinct-hashes digest from the SAME doc_chunks.hash identity.
These tests prove the reindex-time reconcile:

  - read_pushed_digest reads the Go-pushed digest back (None when absent / no
    meta table — the safe "nothing to compare" answer).
  - reconcile_index_digest reports reconciled=True / drift=False when the pushed
    digest equals the canonical digest, reconciled=False / drift=True (loud) when
    they differ, and reconciled=False / drift=False for a never-pushed corpus.
  - strict=True raises DigestDriftError on a real drift; the default only logs.

Hermetic: a throwaway sqlite per test via SEARCHSVC_DB, stdlib only. No torch,
GPU, or network."""

import sqlite3

import pytest

import ingest


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A bare temp taskdb.sqlite resolved via SEARCHSVC_DB, with the alias env
    cleared so resolution is unambiguous, and a meta table present (the table the
    Go pusher writes its digest into)."""
    path = tmp_path / "taskdb.sqlite"
    monkeypatch.setenv("SEARCHSVC_DB", str(path))
    monkeypatch.delenv("TASKDB_SQLITE", raising=False)
    monkeypatch.delenv("TASKDB_DB", raising=False)
    ingest.ensure_schema()
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
        )
        conn.commit()
    finally:
        conn.close()
    return str(path)


def _set_pushed_digest(db_path, value):
    """Stash a value under the Go pusher's meta key (searchsvc_index_digest)."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (ingest.PUSHED_DIGEST_META_KEY, value),
        )
        conn.commit()
    finally:
        conn.close()


# --- canonical helper is the single source -----------------------------------


def test_canonical_digest_is_corpus_digest(db):
    # The reconcile derives its "current" digest from the ONE corpus_digest
    # helper, not a re-forked computation.
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    r = ingest.reconcile_index_digest()
    assert r["current_digest"] == ingest.corpus_digest()


# --- read_pushed_digest ------------------------------------------------------


def test_read_pushed_digest_absent_is_none(db):
    # No row under the pusher key yet → None (not "" — "nothing pushed").
    assert ingest.read_pushed_digest() is None


def test_read_pushed_digest_returns_stashed_value(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    d = ingest.corpus_digest()
    _set_pushed_digest(db, d)
    assert ingest.read_pushed_digest() == d


def test_read_pushed_digest_no_meta_table_is_none(tmp_path, monkeypatch):
    # A bare DB with NO meta table (the Go pusher never ran): None, not an error.
    path = tmp_path / "bare.sqlite"
    monkeypatch.setenv("SEARCHSVC_DB", str(path))
    monkeypatch.delenv("TASKDB_SQLITE", raising=False)
    monkeypatch.delenv("TASKDB_DB", raising=False)
    ingest.ensure_schema()  # creates doc_chunks + index_meta, NOT meta
    assert ingest.read_pushed_digest() is None


# --- matched digests reconcile -----------------------------------------------


def test_matched_digests_reconcile(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    ingest.upsert_chunk_by_hash("docs/b.md", "B", "beta")
    # The Go side pushed exactly the current corpus digest.
    _set_pushed_digest(db, ingest.corpus_digest())

    r = ingest.reconcile_index_digest()
    assert r["reconciled"] is True
    assert r["drift"] is False
    assert r["pushed_digest"] == r["current_digest"] == ingest.corpus_digest()


def test_matched_via_explicit_pushed_digest(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    r = ingest.reconcile_index_digest(pushed_digest=ingest.corpus_digest())
    assert r["reconciled"] is True
    assert r["drift"] is False


# --- drifted digest is flagged loudly ----------------------------------------


def test_drifted_digest_flagged_and_logged(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    # The Go side believes it pushed a DIFFERENT corpus (stale / wrong DB).
    _set_pushed_digest(db, "deadbeef" * 8)

    logged = []
    r = ingest.reconcile_index_digest(log=logged.append)
    assert r["reconciled"] is False
    assert r["drift"] is True
    assert r["pushed_digest"] == "deadbeef" * 8
    assert r["current_digest"] == ingest.corpus_digest()
    # Loud on drift.
    assert len(logged) == 1
    assert "DIGEST DRIFT" in logged[0]
    assert r["pushed_digest"] in logged[0]
    assert r["current_digest"] in logged[0]


def test_drift_after_corpus_changes_under_a_pushed_digest(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    _set_pushed_digest(db, ingest.corpus_digest())
    # Now the corpus changes but the pushed digest is stale → drift.
    ingest.upsert_chunk_by_hash("docs/b.md", "B", "beta")
    logged = []
    r = ingest.reconcile_index_digest(log=logged.append)
    assert r["drift"] is True
    assert r["reconciled"] is False
    assert len(logged) == 1


# --- never-pushed is not a drift ---------------------------------------------


def test_never_pushed_is_not_a_drift(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    logged = []
    r = ingest.reconcile_index_digest(log=logged.append)
    assert r["reconciled"] is False
    assert r["drift"] is False
    assert r["pushed_digest"] is None
    # Silent: nothing to compare against is not a drift banner.
    assert logged == []


# --- strict mode raises on drift ---------------------------------------------


def test_strict_raises_on_drift(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    _set_pushed_digest(db, "deadbeef" * 8)
    with pytest.raises(ingest.DigestDriftError) as exc:
        ingest.reconcile_index_digest(strict=True)
    assert exc.value.pushed_digest == "deadbeef" * 8
    assert exc.value.current_digest == ingest.corpus_digest()


def test_strict_does_not_raise_when_matched(db):
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    _set_pushed_digest(db, ingest.corpus_digest())
    # Matched: strict is a no-op (returns, does not raise).
    r = ingest.reconcile_index_digest(strict=True)
    assert r["reconciled"] is True


def test_strict_does_not_raise_when_never_pushed(db):
    # Nothing pushed → nothing to assert; strict must NOT raise on absence.
    ingest.upsert_chunk_by_hash("docs/a.md", "A", "alpha")
    r = ingest.reconcile_index_digest(strict=True)
    assert r["drift"] is False
    assert r["reconciled"] is False
