# SPDX-License-Identifier: Apache-2.0
#
# test_sparse.py — hermetic tests for the sparse lexical retrieval leg (sparse.py).
#
# These run with NO model, NO torch, NO GPU, NO network, NO live DB: synthetic
# sparse maps are injected directly into sparse.py's resident store via set_store,
# and the real fake_embed.fake_sparse is used to prove an exact-term query ranks
# its matching chunk first. Invariants:
#   - a query whose sparse tokens exactly match a fixture chunk ranks it first
#   - a chunk sharing NO tokens with the query scores EXACTLY 0 (and is dropped)
#   - sparse-only / dense-missing rows do not crash and never NaN
#   - the ranking is deterministic (stable tie-break) and honors top_k
#   - the packed-blob decoder round-trips and rejects a corrupt blob loudly

import math
import struct

import fake_embed
import sparse


def _reset():
    sparse.reset_store()


# ---------------------------------------------------------------------------
# Pure scoring: dot over shared token-ids; missing leg is exactly 0.
# ---------------------------------------------------------------------------


def test_score_is_dot_over_shared_tokens():
    q = {1: 2.0, 2: 3.0, 5: 1.0}
    c = {2: 4.0, 5: 0.5, 9: 7.0}  # shares tids 2 and 5
    # 3.0*4.0 + 1.0*0.5 = 12.5
    assert sparse.sparse_score(q, c) == 12.5


def test_no_shared_tokens_scores_exactly_zero():
    q = {1: 2.0, 2: 3.0}
    c = {7: 9.0, 8: 1.0}
    score = sparse.sparse_score(q, c)
    assert score == 0.0
    assert not math.isnan(score)


def test_empty_legs_score_zero_not_nan():
    assert sparse.sparse_score({}, {1: 1.0}) == 0.0
    assert sparse.sparse_score({1: 1.0}, {}) == 0.0
    assert sparse.sparse_score({}, {}) == 0.0
    for s in (
        sparse.sparse_score({}, {1: 1.0}),
        sparse.sparse_score({1: 1.0}, {}),
        sparse.sparse_score({}, {}),
    ):
        assert not math.isnan(s)


def test_score_is_symmetric_in_query_and_chunk_iteration():
    a = {1: 2.0, 2: 3.0, 3: 4.0}
    b = {2: 1.0, 3: 5.0}  # smaller map
    # Iterating either side must give the same dot: 3.0*1.0 + 4.0*5.0 = 23.0
    assert sparse.sparse_score(a, b) == 23.0
    assert sparse.sparse_score(b, a) == 23.0


# ---------------------------------------------------------------------------
# Ranking via the resident store (injected synthetic fixtures).
# ---------------------------------------------------------------------------


def test_exact_term_match_ranks_first_using_real_fake_embed():
    _reset()
    # Build a store from real fake_embed sparse maps so the test exercises the
    # production embedding shape (stable synthetic token-ids -> term counts).
    exact = fake_embed.fake_sparse("default-deny egress firewall nftables")
    partial = fake_embed.fake_sparse("default-deny networking policy")
    unrelated = fake_embed.fake_sparse("quick brown fox jumps")
    sparse.set_store(
        {
            "chunk-exact": exact,
            "chunk-partial": partial,
            "chunk-unrelated": unrelated,
        }
    )
    # Query == the exact chunk's text -> that chunk must rank first.
    query = fake_embed.fake_sparse("default-deny egress firewall nftables")
    hits = sparse.sparse_search(query, top_k=10)
    assert hits[0][0] == "chunk-exact"
    # The unrelated chunk shares no tokens -> it is dropped (score 0).
    assert all(h != "chunk-unrelated" for h, _ in hits)


def test_unrelated_chunk_is_dropped_at_score_zero():
    _reset()
    sparse.set_store(
        {
            "match": {1: 1.0, 2: 1.0},
            "none": {99: 5.0},
        }
    )
    hits = sparse.sparse_search({1: 1.0, 2: 1.0}, top_k=10)
    assert hits == [("match", 2.0)]


def test_deterministic_tie_break_on_chunk_hash():
    _reset()
    # Two chunks score identically; tie-break is ascending chunk_hash.
    sparse.set_store(
        {
            "bbb": {1: 1.0},
            "aaa": {1: 1.0},
            "ccc": {1: 1.0},
        }
    )
    hits = sparse.sparse_search({1: 1.0}, top_k=10)
    assert [h for h, _ in hits] == ["aaa", "bbb", "ccc"]
    # Repeating the call yields the identical order.
    again = sparse.sparse_search({1: 1.0}, top_k=10)
    assert again == hits


def test_top_k_truncates_after_ranking():
    _reset()
    sparse.set_store(
        {
            "high": {1: 10.0},
            "mid": {1: 5.0},
            "low": {1: 1.0},
        }
    )
    hits = sparse.sparse_search({1: 1.0}, top_k=2)
    assert [h for h, _ in hits] == ["high", "mid"]


def test_top_k_zero_or_negative_returns_empty():
    _reset()
    sparse.set_store({"a": {1: 1.0}})
    assert sparse.sparse_search({1: 1.0}, top_k=0) == []
    assert sparse.sparse_search({1: 1.0}, top_k=-3) == []


# ---------------------------------------------------------------------------
# Hybrid-row grace: sparse-only / dense-missing rows do not crash.
# ---------------------------------------------------------------------------


def test_sparse_only_and_empty_rows_do_not_crash():
    _reset()
    sparse.set_store(
        {
            "sparse-only": {1: 2.0, 2: 1.0},
            "empty-sparse": {},  # e.g. a dense-only chunk with no lexical map
        }
    )
    hits = sparse.sparse_search({1: 1.0}, top_k=10)
    # The empty-sparse chunk contributes nothing and is dropped, no crash.
    assert hits == [("sparse-only", 2.0)]
    for _, s in hits:
        assert not math.isnan(s)


def test_empty_query_returns_no_hits():
    _reset()
    sparse.set_store({"a": {1: 1.0}})
    assert sparse.sparse_search({}, top_k=10) == []


def test_empty_store_returns_no_hits():
    _reset()
    sparse.set_store({})
    assert sparse.sparse_search({1: 1.0}, top_k=10) == []


# ---------------------------------------------------------------------------
# Wire-shape: JSON object keys arrive as strings; they must still intersect.
# ---------------------------------------------------------------------------


def test_string_token_id_keys_from_wire_still_match():
    _reset()
    sparse.set_store({"c": {7: 3.0}})
    # Query keys as strings (as a JSON-decoded {tid: w} would arrive).
    hits = sparse.sparse_search({"7": 2.0}, top_k=10)
    assert hits == [("c", 6.0)]


def test_store_override_param_bypasses_resident_store():
    _reset()
    sparse.set_store({"resident": {1: 1.0}})
    override = {"injected": {1: 1.0}}
    hits = sparse.sparse_search({1: 1.0}, top_k=10, store=override)
    assert [h for h, _ in hits] == ["injected"]


# ---------------------------------------------------------------------------
# Packed-blob decode round-trip (mirrors the Go writer's encodeSparse).
# ---------------------------------------------------------------------------


def _encode_sparse(m):
    """Pack {token_id: weight} the way embeddings.go encodeSparse does: ascending
    token_id, little-endian (uint32, float32) pairs."""
    out = b""
    for tid in sorted(m):
        out += struct.pack("<If", tid, m[tid])
    return out


def test_decode_sparse_blob_round_trips():
    m = {3: 1.5, 1: 2.0, 9: 0.25}
    blob = _encode_sparse(m)
    decoded = sparse._decode_sparse_blob(blob)
    assert decoded == {1: 2.0, 3: 1.5, 9: 0.25}


def test_decode_empty_blob_is_empty_map():
    assert sparse._decode_sparse_blob(b"") == {}
    assert sparse._decode_sparse_blob(None) == {}


def test_decode_corrupt_blob_raises_loudly():
    import pytest

    # 5 bytes is not a multiple of the 8-byte entry width.
    with pytest.raises(ValueError):
        sparse._decode_sparse_blob(b"\x00\x01\x02\x03\x04")


# ---------------------------------------------------------------------------
# Additive ingest: the live /embed accumulation path must AUGMENT the resident
# store (upsert one chunk), NEVER wipe the rest the way set_store does.
# ---------------------------------------------------------------------------


def test_additive_ingest_does_not_wipe_prior_chunks():
    _reset()
    sparse.set_store({"old1": {1: 1.0}, "old2": {2: 2.0}})
    sparse.ingest("new", {1: 3.0})
    # The new chunk is present AND every prior chunk survives.
    hits = sparse.sparse_search({1: 1.0, 2: 1.0}, top_k=10)
    by_hash = dict(hits)
    assert by_hash["old1"] == 1.0
    assert by_hash["old2"] == 2.0
    assert by_hash["new"] == 3.0
    # full ascending-hash ordering at this score profile is asserted exactly.
    assert [h for h, _ in hits] == ["new", "old2", "old1"]


def test_additive_ingest_upserts_a_hash_in_place():
    _reset()
    sparse.set_store({"c": {1: 1.0}})
    sparse.ingest("c", {1: 9.0})  # replace c's map in place
    hits = sparse.sparse_search({1: 1.0}, top_k=10)
    assert hits == [("c", 9.0)]


def test_additive_ingest_on_empty_store_lazy_loads_then_adds(monkeypatch):
    # With no resident store yet, ingest lazily materializes one (from an absent
    # DB -> empty) and then adds the chunk, rather than crashing on None.
    _reset()
    monkeypatch.setattr(sparse, "_db_path", lambda: "/no/such/taskdb.sqlite")
    sparse.ingest("first", {5: 2.0})
    hits = sparse.sparse_search({5: 1.0}, top_k=10)
    assert hits == [("first", 2.0)]


def test_additive_ingest_normalizes_wire_string_keys():
    _reset()
    sparse.set_store({})
    sparse.ingest("c", {"7": 3.0})  # JSON-decoded string key
    hits = sparse.sparse_search({7: 2.0}, top_k=10)
    assert hits == [("c", 6.0)]
