# SPDX-License-Identifier: Apache-2.0
"""POST /backfill_provenance — TARGETED heal for resident chunks with EMPTY
provenance (bgem3w8 backfill-empty-provenance).

Chunks streamed to a long-lived resident searchsvc BEFORE the provenance-pushers
change land with empty doc_path/heading and stay empty until a full /reindex
rebuilds them from the resolved DB. This unit adds a targeted heal: re-resolve
provenance for ONLY the empty-provenance resident chunks from the index DB's
doc_chunks (path/heading keyed by chunk_hash) and update the resident metadata in
place — no full corpus reindex.

These tests prove:

  - a resident chunk that landed with EMPTY provenance is healed (its resident
    metadata gains the doc_path/heading from doc_chunks) WITHOUT a /reindex, and
    its dense vector is preserved (the heal writes through the canonical
    DenseIndex.ingest path, re-supplying the existing row);
  - a subsequent /search hit carries the healed provenance (fusion resolves it
    from exactly the resident metadata the heal wrote);
  - chunks that ALREADY carry provenance are left untouched (idempotent, no
    needless rewrite);
  - a chunk with no doc_chunks row stays empty and is counted unresolved (fail-
    open, never a 500);
  - the route is mirrored into the stdlib fallback handler.

Hermetic: fake_embed (256-dim) only, no torch / GPU / network. The DB resolver is
isolated per-test and the resident singletons are reset, mirroring
test_serve_ingest's isolation discipline.
"""

import importlib
import os
import re
import sqlite3
import sys

import pytest

import serve

_REAL_RETRIEVAL_MODS = ("dense", "sparse", "fusion", "index_store")


@pytest.fixture(autouse=True)
def _isolated_index(monkeypatch):
    """Bind the REAL retrieval legs and drop both resident singletons so the test
    fully controls resident state (default: DB resolver at an absent path)."""
    monkeypatch.setenv("SEARCHSVC_DB", "/no/such/backfill-test.sqlite")
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


def _make_db(tmp_path, rows):
    """Create a taskdb.sqlite with a doc_chunks table holding `rows`, each a
    (hash, path, heading, body) tuple. Returns the db path."""
    db = tmp_path / "taskdb.sqlite"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE doc_chunks (id INTEGER PRIMARY KEY, doc_id INTEGER NOT NULL,"
        " path TEXT NOT NULL, heading TEXT NOT NULL DEFAULT '', seq INTEGER NOT NULL,"
        " body TEXT NOT NULL, hash TEXT NOT NULL)"
    )
    for i, (h, path, heading, body) in enumerate(rows):
        conn.execute(
            "INSERT INTO doc_chunks (doc_id, path, heading, seq, body, hash)"
            " VALUES (?,?,?,?,?,?)",
            (1, path, heading, i, body, h),
        )
    conn.commit()
    conn.close()
    return db


def _resident_chunk(index_store, chunk_hash, body, doc_path="", heading=""):
    """Push one chunk into the resident dense index with the given (possibly
    empty) provenance — simulating a stream that landed BEFORE the provenance fix.
    Uses ingest_text so the resident vector is the fake embedding of `body` (the
    same vector a /reindex would later produce, so we can assert it is preserved)."""
    index_store.get_index().ingest_text(chunk_hash, body, doc_path, heading)


def test_backfill_heals_empty_provenance_without_reindex(tmp_path, monkeypatch):
    """A resident chunk that landed with empty provenance is healed from the index
    DB, in place, and its dense vector is preserved (no /reindex)."""
    db = _make_db(tmp_path, [("h_empty", "docs/a.md", "Heading A", "alpha body")])
    monkeypatch.setenv("SEARCHSVC_DB", str(db))
    index_store.reset_index()

    # Pre-fix stream: the chunk is resident but with EMPTY provenance.
    _resident_chunk(index_store, "h_empty", "alpha body")
    idx = index_store.get_index()
    before_vec = idx.matrix()[idx.chunk_hashes().index("h_empty")].copy()
    assert idx.metadata("h_empty") == {"doc_path": "", "heading": ""}

    client = _client()
    r = client.post("/backfill_provenance")
    assert r.status_code == 200
    body = r.json()
    assert body["healed"] == 1
    assert body["empty"] == 1
    assert body["unresolved"] == 0
    assert body["db"] == str(db)

    # Resident metadata is healed IN PLACE.
    healed = idx.metadata("h_empty")
    assert healed == {"doc_path": "docs/a.md", "heading": "Heading A"}

    # The dense vector is preserved (provenance-only update — no re-embed/reindex).
    after_vec = idx.matrix()[idx.chunk_hashes().index("h_empty")]
    assert (after_vec == before_vec).all()
    # The corpus size is unchanged — nothing added/dropped.
    assert idx.chunk_hashes() == ["h_empty"]


def test_healed_chunk_carries_provenance_on_next_search(tmp_path, monkeypatch):
    """After a heal, a /search hit for the chunk carries the healed doc_path/
    heading (fusion resolves it from exactly the resident metadata)."""
    db = _make_db(
        tmp_path, [("h_needle", "docs/needle.md", "Needle Section", "needle haystack")]
    )
    monkeypatch.setenv("SEARCHSVC_DB", str(db))
    index_store.reset_index()
    sparse.reset_store()

    # Resident WITH empty provenance, on BOTH legs (a pre-fix stream).
    _resident_chunk(index_store, "h_needle", "needle haystack")
    emb = serve.embed_text("needle haystack")
    sparse.ingest("h_needle", emb.get("sparse", {}))

    client = _client()
    # Before the heal: a hit exists but provenance is empty.
    pre = client.post("/search", json={"query": "needle haystack", "top_k": 5}).json()
    assert pre["degraded"] is False
    pre_hit = next(h for h in pre["results"] if h["chunk_hash"] == "h_needle")
    assert pre_hit["doc_path"] == ""
    assert pre_hit["heading"] == ""

    assert client.post("/backfill_provenance").json()["healed"] == 1

    post = client.post("/search", json={"query": "needle haystack", "top_k": 5}).json()
    post_hit = next(h for h in post["results"] if h["chunk_hash"] == "h_needle")
    assert post_hit["doc_path"] == "docs/needle.md"
    assert post_hit["heading"] == "Needle Section"


def test_backfill_leaves_already_provenanced_chunks_untouched(tmp_path, monkeypatch):
    """A chunk that already carries provenance is NOT scanned as empty and is left
    exactly as-is (idempotent)."""
    db = _make_db(
        tmp_path,
        [
            ("h_full", "docs/full.md", "Full", "full body"),
            ("h_empty", "docs/empty.md", "Empty", "empty body"),
        ],
    )
    monkeypatch.setenv("SEARCHSVC_DB", str(db))
    index_store.reset_index()

    _resident_chunk(index_store, "h_full", "full body", "docs/full.md", "Full")
    _resident_chunk(index_store, "h_empty", "empty body")  # empty provenance

    body = _client().post("/backfill_provenance").json()
    # Only the empty one was a heal candidate.
    assert body["empty"] == 1
    assert body["healed"] == 1
    assert body["scanned"] == 2

    idx = index_store.get_index()
    assert idx.metadata("h_full") == {"doc_path": "docs/full.md", "heading": "Full"}
    assert idx.metadata("h_empty") == {"doc_path": "docs/empty.md", "heading": "Empty"}


def test_backfill_counts_unresolved_when_no_db_row(tmp_path, monkeypatch):
    """An empty-provenance resident chunk with NO matching doc_chunks row stays
    empty and is counted unresolved — fail-open, never a 500."""
    db = _make_db(tmp_path, [("h_other", "docs/other.md", "Other", "other body")])
    monkeypatch.setenv("SEARCHSVC_DB", str(db))
    index_store.reset_index()

    _resident_chunk(index_store, "h_orphan", "orphan body")  # not in doc_chunks

    body = _client().post("/backfill_provenance").json()
    assert body["empty"] == 1
    assert body["healed"] == 0
    assert body["unresolved"] == 1
    assert index_store.get_index().metadata("h_orphan") == {
        "doc_path": "",
        "heading": "",
    }


def test_backfill_no_db_is_fail_open(monkeypatch):
    """With the DB resolver at an absent path, the heal resolves nothing and
    returns a clean summary (0 healed) rather than 500-ing."""
    # SEARCHSVC_DB is the absent path from the fixture.
    _resident_chunk(index_store, "h_x", "x body")
    body = _client().post("/backfill_provenance").json()
    assert body["healed"] == 0
    assert body["empty"] == 1
    assert body["unresolved"] == 1


def test_backfill_route_mirrored_on_stdlib_app():
    """The /backfill_provenance route is mirrored into the stdlib fallback."""
    import inspect

    src = inspect.getsource(serve.build_stdlib_app())
    assert "/backfill_provenance" in src


# ---------------------------------------------------------------------------
# _resolve_provenance_from_db — targeted chunked WHERE hash IN (...) lookup
# (bgem3w9 chunked-in-provenance-query). The resolver must read ONLY the
# requested hashes (O(K), not O(corpus)) and the IN-list must batch under the
# SQLite host-parameter limit while preserving the exact resolution result.
# ---------------------------------------------------------------------------


def test_resolve_provenance_returns_only_requested_subset(tmp_path):
    """A targeted resolve over a SUBSET of a large corpus returns exactly the
    requested hashes' provenance — and the same (path, heading) a full scan would,
    without scanning the whole table."""
    rows = [
        ("h_%04d" % i, "docs/d%04d.md" % i, "H%04d" % i, "body %d" % i)
        for i in range(50)
    ]
    db = _make_db(tmp_path, rows)

    wanted = ["h_0007", "h_0042", "h_0000"]
    resolved = serve._resolve_provenance_from_db(str(db), wanted)

    assert set(resolved) == set(wanted)
    assert resolved["h_0007"] == ("docs/d0007.md", "H0007")
    assert resolved["h_0042"] == ("docs/d0042.md", "H0042")
    assert resolved["h_0000"] == ("docs/d0000.md", "H0000")
    # A hash NOT requested is never resolved (no full-table walk leaking rows).
    assert "h_0001" not in resolved


def test_resolve_provenance_missing_hash_omitted(tmp_path):
    """A requested hash with no doc_chunks row simply has no entry (the caller
    leaves it untouched) — the present ones still resolve."""
    db = _make_db(tmp_path, [("h_present", "docs/p.md", "P", "p body")])
    resolved = serve._resolve_provenance_from_db(str(db), ["h_present", "h_absent"])
    assert resolved == {"h_present": ("docs/p.md", "P")}


def test_resolve_provenance_batches_past_param_limit(tmp_path):
    """The IN-list is chunked under the SQLite host-parameter limit: a request for
    MORE than one batch's worth of hashes (>_PROVENANCE_IN_BATCH, and well past the
    historical 999 cap) resolves every present hash via unioned batches rather than
    raising 'too many SQL variables'."""
    n = serve._PROVENANCE_IN_BATCH * 2 + 137  # spans 3 batches, > 999
    assert n > 999
    rows = [
        ("b_%05d" % i, "docs/b%05d.md" % i, "Hb%05d" % i, "body %d" % i)
        for i in range(n)
    ]
    db = _make_db(tmp_path, rows)

    wanted = ["b_%05d" % i for i in range(n)]
    resolved = serve._resolve_provenance_from_db(str(db), wanted)

    assert len(resolved) == n
    # Spot-check the boundary rows across the batch seams.
    for i in (0, serve._PROVENANCE_IN_BATCH - 1, serve._PROVENANCE_IN_BATCH,
              serve._PROVENANCE_IN_BATCH * 2, n - 1):
        assert resolved["b_%05d" % i] == ("docs/b%05d.md" % i, "Hb%05d" % i)


def test_resolve_provenance_dedupes_requested_hashes(tmp_path):
    """Duplicate requested hashes are deduped (asked once) and resolve to a single
    entry — the first/representative row, matching the full-scan semantics."""
    db = _make_db(tmp_path, [("h_dup", "docs/dup.md", "Dup", "dup body")])
    resolved = serve._resolve_provenance_from_db(
        str(db), ["h_dup", "h_dup", "h_dup"]
    )
    assert resolved == {"h_dup": ("docs/dup.md", "Dup")}


def test_resolve_provenance_empty_inputs_are_noops(tmp_path):
    """No DB / no requested hashes -> empty result, never a raise (fail-open)."""
    db = _make_db(tmp_path, [("h", "docs/x.md", "X", "x")])
    assert serve._resolve_provenance_from_db(str(db), []) == {}
    assert serve._resolve_provenance_from_db("", ["h"]) == {}
    assert serve._resolve_provenance_from_db("/no/such/db.sqlite", ["h"]) == {}


# ---------------------------------------------------------------------------
# EXPLAIN QUERY PLAN — the IN-list heal MUST ride idx_doc_chunks_hash
# (bgem3w11 provenance-heal-explain-index). bgem3w9 made the heal targeted
# (WHERE hash IN (...), O(K) not O(corpus)); bgem3w10 landed the covering
# index idx_doc_chunks_hash on doc_chunks(hash) in the real schema (db.go).
# These tests lock in that win: against a FRESH DB built by the REAL schema,
# the planner must SEARCH ... USING INDEX idx_doc_chunks_hash, never a full
# SCAN — so a future schema change that drops/renames the index regresses a
# test, not silently a heal of a large corpus back to O(corpus).
# ---------------------------------------------------------------------------

# The doc_chunks DDL + its indexes, READ from the single canonical source
# scripts/taskdb/schema/doc_chunks.sql (NOT a string-literal hand-copy — that
# copy was eliminated by task 01KV58D0C3). serve.py's heal opens an EXISTING
# index DB built by db.go's initSchema, which embeds the same canonical DDL; a Go
# drift guard (scripts/taskdb/schema_canonical_test.go) asserts db.go matches
# this .sql, and the Python guard below asserts the .sql matches db.go — so the
# plan we assert here is the plan the production heal gets. test_db_index in
# scripts/taskdb/db_index_test.go guards that the schema still emits
# idx_doc_chunks_hash; this guards that the heal's query actually USES it.
# schema/doc_chunks.sql is two levels up from this test (searchsvc/ -> taskdb/).
_CANONICAL_SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.pardir,
    "schema",
    "doc_chunks.sql",
)


def _load_canonical_schema():
    """Read the canonical doc_chunks DDL from scripts/taskdb/schema/doc_chunks.sql.

    This is the single source of truth — no Python copy of the DDL exists; the
    EXPLAIN tests build their fresh DB straight from this file's CREATE TABLE +
    CREATE INDEX statements (sqlite executescript tolerates the SPDX/comment
    preamble and `IF NOT EXISTS`)."""
    with open(_CANONICAL_SCHEMA_PATH, encoding="utf-8") as fh:
        return fh.read()


_REAL_DOC_CHUNKS_SCHEMA = _load_canonical_schema()

# The heal's SQL TEMPLATE, exactly as _resolve_provenance_from_db builds it
# (serve.py: 'SELECT hash, path, heading FROM doc_chunks WHERE hash IN (%s)').
# test_heal_sql_matches_serve_source asserts this is still serve.py's actual
# statement, so the EXPLAIN below cannot silently drift from production.
_HEAL_SQL_TEMPLATE = "SELECT hash, path, heading FROM doc_chunks WHERE hash IN (%s)"


def _explain_real_schema_db(tmp_path, n_hashes, corpus):
    """Build a fresh DB with the REAL doc_chunks schema (incl. idx_doc_chunks_hash),
    seed it with `corpus` rows so the optimizer has real cardinality to choose
    against, and return the EXPLAIN QUERY PLAN detail strings for the heal's
    WHERE hash IN (...) query over `n_hashes` placeholders.

    corpus MUST be >> n_hashes: that is the real heal condition the index exists
    for (a targeted heal of K resident chunks against a large corpus). When the
    IN-list approaches or exceeds the table size, SQLite CORRECTLY prefers a
    single full SCAN over K index probes — that is not the regression this guards
    against, so the caller keeps the corpus large relative to the batch.

    The DB filename is keyed by (corpus, width) so repeated calls under one
    tmp_path each get a fresh schema (no 'table already exists')."""
    db = tmp_path / ("taskdb_c%d_n%d.sqlite" % (corpus, n_hashes))
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript(_REAL_DOC_CHUNKS_SCHEMA)
        conn.executemany(
            "INSERT INTO doc_chunks (doc_id, path, heading, seq, body, hash)"
            " VALUES (?,?,?,?,?,?)",
            [
                (1, "docs/d%06d.md" % i, "H%06d" % i, i, "body %d" % i, "h_%06d" % i)
                for i in range(corpus)
            ],
        )
        # ANALYZE populates sqlite_stat1 so the planner's SCAN-vs-SEARCH choice is
        # cost-based and deterministic rather than a no-stats heuristic.
        conn.execute("ANALYZE")
        conn.commit()
        placeholders = ",".join("?" * n_hashes)
        sql = "EXPLAIN QUERY PLAN " + (_HEAL_SQL_TEMPLATE % placeholders)
        params = ["h_%06d" % i for i in range(n_hashes)]
        return [row[3] for row in conn.execute(sql, params)]
    finally:
        conn.close()


def test_heal_sql_matches_serve_source():
    """The SQL template this test EXPLAINs is exactly the one serve.py's
    _resolve_provenance_from_db builds — so the asserted plan cannot drift from
    the production heal without this test failing first."""
    import inspect

    src = inspect.getsource(serve._resolve_provenance_from_db)
    assert _HEAL_SQL_TEMPLATE in src, (
        "heal SQL template drifted from serve.py; update _HEAL_SQL_TEMPLATE and "
        "re-verify the EXPLAIN QUERY PLAN still rides idx_doc_chunks_hash"
    )


def test_heal_query_uses_hash_index_not_scan(tmp_path):
    """Against a FRESH DB built by the REAL schema, the heal's WHERE hash IN (...)
    query SEARCHes USING INDEX idx_doc_chunks_hash — it does NOT full-SCAN
    doc_chunks. This is the O(K)-not-O(corpus) guarantee bgem3w9/bgem3w10 won."""
    detail = "\n".join(_explain_real_schema_db(tmp_path, n_hashes=3, corpus=5000))
    assert "idx_doc_chunks_hash" in detail, (
        "heal query does not use idx_doc_chunks_hash; plan was:\n" + detail
    )
    assert "USING INDEX idx_doc_chunks_hash" in detail, (
        "expected SEARCH ... USING INDEX idx_doc_chunks_hash; plan was:\n" + detail
    )
    # The index turns the table read into a SEARCH; a bare full SCAN of the
    # corpus is exactly the O(corpus) regression this test exists to catch.
    assert "SCAN doc_chunks" not in detail, (
        "heal query full-SCANs doc_chunks (O(corpus) regression); plan was:\n"
        + detail
    )


def test_heal_query_uses_hash_index_across_batch_widths(tmp_path):
    """For a targeted heal (corpus >> batch) the index is used at EVERY IN-list
    width the heal can issue — a single hash and a full batch's worth both SEARCH
    the index rather than falling back to a full SCAN. The corpus is held an order
    of magnitude above the widest batch so the index probe is genuinely the cheaper
    plan (the realistic heal-a-few-against-a-large-corpus condition).

    Note: SQLite CORRECTLY prefers a SCAN once the IN-list approaches the table
    size (K probes cost more than one pass), so this asserts the index win only in
    the regime it actually holds — corpus >> K — which is what the heal targets."""
    corpus = serve._PROVENANCE_IN_BATCH * 10  # an order of magnitude over the cap
    for n in (1, 2, serve._PROVENANCE_IN_BATCH):
        detail = "\n".join(
            _explain_real_schema_db(tmp_path, n_hashes=n, corpus=corpus)
        )
        assert "USING INDEX idx_doc_chunks_hash" in detail, (
            "IN-list of width %d (corpus %d) did not ride idx_doc_chunks_hash; "
            "plan:\n%s" % (n, corpus, detail)
        )
        assert "SCAN doc_chunks" not in detail, (
            "IN-list of width %d (corpus %d) full-SCANs doc_chunks; plan:\n%s"
            % (n, corpus, detail)
        )


# ---------------------------------------------------------------------------
# DDL DRIFT GUARD — _REAL_DOC_CHUNKS_SCHEMA above is a hand-copy of db.go's
# CREATE TABLE doc_chunks + CREATE INDEX idx_doc_chunks_hash. It is what the
# EXPLAIN tests build their fresh DB from, so the plan they assert is only the
# plan production gets if that copy stays faithful to the real schema. Nothing
# but a human's eye couples them — a db.go column add / index drop / type
# change would leave this copy stale and the EXPLAIN tests asserting a plan no
# real DB ever produces.
#
# This guard reads the canonical DDL straight out of scripts/taskdb/db.go (as a
# read-only fixture — db.go is owned elsewhere and never edited here), pulls the
# CREATE TABLE doc_chunks block and the CREATE INDEX idx_doc_chunks_hash
# statement, and asserts the in-test copy matches each (whitespace-normalized,
# CREATE TABLE/INDEX [IF NOT EXISTS] equated). A schema change db.go makes that
# this copy did not track now fails LOUDLY here instead of silently rotting the
# EXPLAIN assertions.
# ---------------------------------------------------------------------------

# db.go is one level up from searchsvc/ (scripts/taskdb/db.go); resolve it from
# this test's own location so the guard works from any cwd.
_DB_GO_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir, "db.go"
)


def _normalize_ddl(sql):
    """Whitespace- and synonym-normalize a single SQL DDL statement for
    comparison: strip SQL line comments, equate `CREATE TABLE`/`CREATE INDEX`
    with their `IF NOT EXISTS` forms, collapse all runs of whitespace to one
    space, drop spaces around the structural punctuation `(),` and lowercase
    keywords by lowercasing the whole thing (identifiers here are already
    lowercase). The result is a canonical one-line form that is stable across
    formatting differences (tabs vs spaces, column alignment, trailing newline)
    but sensitive to any real schema change (columns, types, constraints,
    indexed expression)."""
    # Drop `-- ...` line comments (db.go interleaves them with the DDL).
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = sql.lower()
    # Equate the IF NOT EXISTS form db.go uses with the bare form the copy uses.
    sql = re.sub(r"create\s+table\s+if\s+not\s+exists", "create table", sql)
    sql = re.sub(r"create\s+index\s+if\s+not\s+exists", "create index", sql)
    # Collapse all whitespace runs, then tighten around structural punctuation so
    # `( id ...` and `(id ...` and `id ,` and `id,` all canonicalize the same.
    sql = re.sub(r"\s+", " ", sql)
    sql = re.sub(r"\s*([(),])\s*", r"\1", sql)
    return sql.strip().rstrip(";")


# A single-level-nesting paren body: any run of non-paren chars, optionally
# interleaved with balanced `(...)` groups (e.g. a future `CHECK (x > 0)` or
# `DEFAULT (0)` column constraint). HARDENED extractor (task 01KV58D0C3): the old
# `[^)]*` body stopped at the FIRST inner `)`, so a nested-paren constraint would
# silently truncate the extraction; this tolerates one level of nesting and the
# trailing `;` anchor still pins the statement's real end.
_PAREN_BODY = r"(?:[^()]|\([^()]*\))*"


def _extract_db_go_ddl():
    """Read scripts/taskdb/db.go (read-only fixture) and return the
    (create_table_doc_chunks, create_index_hash) DDL statements as raw SQL
    strings, exactly as the canonical Go schema declares them. Uses a non-greedy
    paren scan (_PAREN_BODY) so a nested-paren constraint added to the table or
    index body does not truncate the match at the first inner `)`."""
    with open(_DB_GO_PATH, encoding="utf-8") as fh:
        src = fh.read()

    table_m = re.search(
        r"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+doc_chunks\s*\(" + _PAREN_BODY + r"\)\s*;",
        src,
        re.IGNORECASE | re.DOTALL,
    )
    assert table_m, (
        "could not find `CREATE TABLE doc_chunks (...)` in %s — db.go schema "
        "moved/renamed; update this guard" % _DB_GO_PATH
    )

    index_m = re.search(
        r"CREATE INDEX(?:\s+IF NOT EXISTS)?\s+idx_doc_chunks_hash\s+ON\s+"
        r"doc_chunks\s*\(" + _PAREN_BODY + r"\)\s*;",
        src,
        re.IGNORECASE | re.DOTALL,
    )
    assert index_m, (
        "could not find `CREATE INDEX idx_doc_chunks_hash ON doc_chunks(...)` "
        "in %s — db.go index dropped/renamed; the EXPLAIN tests' "
        "idx_doc_chunks_hash assumption is now stale" % _DB_GO_PATH
    )
    return table_m.group(0), index_m.group(0)


def test_db_go_path_resolves():
    """Sanity: the read-only db.go fixture path resolves to a real file (a moved
    db.go must fail here, not silently skip the drift comparison below)."""
    assert os.path.isfile(_DB_GO_PATH), (
        "db.go fixture not found at %s" % _DB_GO_PATH
    )


def test_canonical_sql_matches_db_go_doc_chunks_ddl():
    """The canonical schema/doc_chunks.sql (which _REAL_DOC_CHUNKS_SCHEMA now
    READS, not copies) matches the CREATE TABLE doc_chunks + CREATE INDEX
    idx_doc_chunks_hash that db.go's initSchema embeds (whitespace-normalized).
    The .sql is the single source of truth; this is the Python half of the
    bidirectional drift guard (the Go half is schema_canonical_test.go). A db.go
    schema change the .sql did not track fails HERE — loudly — instead of rotting
    the EXPLAIN tests above into asserting a plan no production DB produces."""
    real_table, real_index = _extract_db_go_ddl()

    canon_norm = _normalize_ddl(_REAL_DOC_CHUNKS_SCHEMA)
    table_norm = _normalize_ddl(real_table)
    index_norm = _normalize_ddl(real_index)

    assert table_norm in canon_norm, (
        "schema/doc_chunks.sql's CREATE TABLE doc_chunks drifted from "
        "db.go.\n  db.go (normalized): %s\n  canonical .sql (normalized): %s\n"
        "Reconcile scripts/taskdb/schema/doc_chunks.sql with db.go's "
        "initSchema." % (table_norm, canon_norm)
    )
    assert index_norm in canon_norm, (
        "schema/doc_chunks.sql is missing/has drifted from db.go's "
        "idx_doc_chunks_hash index — the EXPLAIN tests build their DB without "
        "the index they then assert the plan uses.\n  db.go (normalized): %s\n"
        "  canonical .sql (normalized): %s\nReconcile the CREATE INDEX "
        "idx_doc_chunks_hash statement in scripts/taskdb/schema/doc_chunks.sql." % (
            index_norm,
            canon_norm,
        )
    )
