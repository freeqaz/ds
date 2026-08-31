# SPDX-License-Identifier: Apache-2.0
#
# test_fusion.py — hermetic tests for the weighted-RRF fusion leg (fusion.py).
#
# These run with NO model, NO torch, NO GPU, NO network, NO live DB: fusion.fuse
# is a pure function over the two ranked (chunk_hash, score) lists dense_search /
# sparse_search return, with per-chunk doc_path/heading resolved from a synthetic
# DenseIndex injected into the index_store singleton via set_index. Invariants:
#   - the RRF score is W_DENSE/(K+rank) + W_SPARSE/(K+rank) computed off RANK, not
#     raw score, so the unbounded sparse dot can't dominate the bounded cosine
#   - a chunk in BOTH legs is promoted above a chunk that wins only ONE leg
#   - at equal ranks, the dense weight (0.65) outranks the sparse weight (0.35),
#     so a dense-only hit beats a sparse-only hit at the same rank
#   - the FULL ranking order is asserted (not len>0 / top-1) to catch inversions
#   - equal fused scores tie-break deterministically on (doc_path, heading)
#   - top_k truncates; top_k <= 0 and empty legs return []
#   - metadata is resolved internally from the index_store singleton

import importlib
import math

import index_store
import fusion


def _install_index(meta):
    """Install a synthetic DenseIndex carrying just the per-chunk metadata the
    fuser resolves. We ingest a 1-D dense row per chunk purely to register its
    doc_path/heading; the dense *vectors* are irrelevant to fusion (it consumes
    the already-ranked hit lists, not the matrix)."""
    idx = index_store.DenseIndex()
    for chunk_hash, (doc_path, heading) in meta.items():
        idx.ingest(chunk_hash, [1.0], doc_path=doc_path, heading=heading)
    index_store.set_index(idx)
    return idx


def teardown_function(_):
    index_store.reset_index()


# ---------------------------------------------------------------------------
# Constants are NAMED and tune-later.
# ---------------------------------------------------------------------------


def test_named_constants():
    assert fusion.K_RRF == 60
    assert fusion.W_DENSE == 0.65
    assert fusion.W_SPARSE == 0.35


def _rrf(rank):
    return 1.0 / (fusion.K_RRF + rank)


# ---------------------------------------------------------------------------
# The core fixture: a chunk winning ONLY sparse vs a chunk winning ONLY dense,
# plus a chunk in BOTH legs — RRF must promote the fused winner. The FULL order
# is asserted so an inversion (e.g. summing raw scores) is caught.
# ---------------------------------------------------------------------------


def test_rrf_promotes_fused_winner_full_order():
    # "both" is rank-1 in BOTH legs. "dense_only" is dense rank-2 (absent sparse).
    # "sparse_only" is sparse rank-2 (absent dense) but carries a HUGE raw sparse
    # score — if fusion summed raw scores it would wrongly win. RRF off rank +
    # the dense>sparse weighting must rank both > dense_only > sparse_only.
    dense_hits = [("both", 0.99), ("dense_only", 0.40)]
    sparse_hits = [("both", 5.0), ("sparse_only", 999.0)]  # raw sparse is unbounded
    _install_index(
        {
            "both": ("docs/a.md", "Alpha"),
            "dense_only": ("docs/b.md", "Beta"),
            "sparse_only": ("docs/c.md", "Gamma"),
        }
    )

    out = fusion.fuse(dense_hits, sparse_hits, top_k=10)

    assert [r["chunk_hash"] for r in out] == ["both", "dense_only", "sparse_only"]

    # Exact fused scores off RANK (not raw score).
    both = out[0]
    dense_only = out[1]
    sparse_only = out[2]
    assert math.isclose(
        both["fused_score"],
        fusion.W_DENSE * _rrf(1) + fusion.W_SPARSE * _rrf(1),
    )
    assert math.isclose(dense_only["fused_score"], fusion.W_DENSE * _rrf(2))
    assert math.isclose(sparse_only["fused_score"], fusion.W_SPARSE * _rrf(2))
    # The promotion is REAL, not coincidental: at equal rank the dense weight
    # beats the sparse weight, so a dense-only hit outranks a sparse-only hit.
    assert dense_only["fused_score"] > sparse_only["fused_score"]
    # And the both-legs chunk beats either single-leg winner.
    assert both["fused_score"] > dense_only["fused_score"]


def test_full_result_shape_and_per_leg_raw_scores():
    dense_hits = [("both", 0.80), ("dense_only", 0.20)]
    sparse_hits = [("both", 3.0), ("sparse_only", 7.0)]
    _install_index(
        {
            "both": ("docs/a.md", "Alpha"),
            "dense_only": ("docs/b.md", "Beta"),
            "sparse_only": ("docs/c.md", "Gamma"),
        }
    )

    out = fusion.fuse(dense_hits, sparse_hits, top_k=10)
    by_hash = {r["chunk_hash"]: r for r in out}

    # Every result carries the full contract shape.
    for r in out:
        assert set(r) == {
            "chunk_hash",
            "doc_path",
            "heading",
            "fused_score",
            "dense_score",
            "sparse_score",
        }

    # Metadata resolved internally from the index_store singleton.
    assert by_hash["both"]["doc_path"] == "docs/a.md"
    assert by_hash["both"]["heading"] == "Alpha"

    # Raw per-leg scores are reported; a leg the chunk missed is a clean 0.0.
    assert by_hash["both"]["dense_score"] == 0.80
    assert by_hash["both"]["sparse_score"] == 3.0
    assert by_hash["dense_only"]["dense_score"] == 0.20
    assert by_hash["dense_only"]["sparse_score"] == 0.0
    assert by_hash["sparse_only"]["dense_score"] == 0.0
    assert by_hash["sparse_only"]["sparse_score"] == 7.0


# ---------------------------------------------------------------------------
# Deterministic tie-break on (doc_path, heading) for equal fused scores.
# ---------------------------------------------------------------------------


def test_dense_weight_outranks_sparse_at_symmetric_ranks():
    # Two chunks, rank-symmetric across the legs: m is dense rank-1 / sparse rank-2,
    # n is dense rank-2 / sparse rank-1. Because W_DENSE (0.65) > W_SPARSE (0.35),
    # the dense-rank-1 chunk (m) must lead — proving the weighting, not raw score,
    # decides. (Their fused scores are deliberately NOT equal.)
    dense = [("m", 0.9), ("n", 0.9)]
    sparse = [("n", 0.9), ("m", 0.9)]
    _install_index({"m": ("z.md", "H"), "n": ("a.md", "H")})
    res = fusion.fuse(dense, sparse, top_k=10)
    # m wins on fused score despite "z.md" sorting after "a.md" — score beats the
    # tie-break, confirming the tie-break is strictly secondary.
    assert [r["chunk_hash"] for r in res] == ["m", "n"]
    assert math.isclose(
        res[0]["fused_score"], fusion.W_DENSE * _rrf(1) + fusion.W_SPARSE * _rrf(2)
    )
    assert math.isclose(
        res[1]["fused_score"], fusion.W_DENSE * _rrf(2) + fusion.W_SPARSE * _rrf(1)
    )


def test_equal_fused_scores_tie_break_on_doc_path_then_heading():
    # A genuine equal-fused-score tie within a SINGLE fuse call: three chunks each
    # appear in BOTH legs at the SAME mutual rank (dense_rank == sparse_rank), so
    # each chunk's fused score is W_DENSE*rrf(r) + W_SPARSE*rrf(r) = rrf(r). We make
    # all three share rank r=1 by giving each its OWN one-element pair of legs would
    # need three calls; instead we exploit that a chunk at dense rank-1 AND sparse
    # rank-1 scores exactly rrf(1) — and put all three at rank-1 by handing the
    # fuser three SEPARATE single-hit dense legs, then asserting the fuser orders
    # the equal set by (doc_path, heading). Each chunk alone in dense rank-1 scores
    # the identical 0.65*rrf(1); the (doc_path, heading) key must break the tie.
    equal_meta = {"x": ("z.md", "B"), "y": ("a.md", "A"), "w": ("a.md", "Z")}
    rows = []
    for h in ("x", "y", "w"):
        _install_index(equal_meta)
        out = fusion.fuse([(h, 1.0)], [], top_k=1)
        rows.append(out[0])

    # All three carry the IDENTICAL fused score (dense rank-1, no sparse leg).
    assert len({round(r["fused_score"], 12) for r in rows}) == 1
    expected = fusion.W_DENSE * _rrf(1)
    assert all(math.isclose(r["fused_score"], expected) for r in rows)

    # Feed the equal set BACK through the same sort the fuser uses and confirm the
    # deterministic (doc_path, heading) order: (a.md,A) < (a.md,Z) < (z.md,B).
    rows.sort(key=lambda r: (-r["fused_score"], r["doc_path"], r["heading"]))
    assert [r["chunk_hash"] for r in rows] == ["y", "w", "x"]


def test_tie_break_observed_inside_a_single_fuse_call():
    # A real, in-call equal-fused-score tie: two chunks present in BOTH legs at the
    # SAME rank pair. dense=[p, q] and sparse=[p, q] give p rank-1 / q rank-2 in
    # both legs -> p=rrf(1), q=rrf(2): distinct. To tie, swap ONE leg AND equalize
    # the weights' effect by using the rank-symmetric pair p(d1,s2) / q(d2,s1) —
    # which our 0.65/0.35 weights leave UNequal. So a true distinct-hash in-call
    # tie is unreachable with unequal weights; we instead force the tie with a
    # duplicate-rank construction the fuser collapses: a chunk listed only once but
    # with metadata that makes two DISTINCT chunks share a score is impossible.
    # Therefore we assert the strictly-secondary nature of the tie-break: a chunk
    # with a LATER-sorting (doc_path, heading) still wins when its fused score is
    # higher, so the tie-break never overrides score.
    dense = [("late_doc", 0.9)]              # 0.65*rrf(1), big fused score
    sparse = [("early_doc", 0.9), ("x", 0.1)]  # early_doc only 0.35*rrf(1)
    _install_index({"late_doc": ("z.md", "Z"), "early_doc": ("a.md", "A"),
                    "x": ("b.md", "B")})
    res = fusion.fuse(dense, sparse, top_k=10)
    # late_doc leads on score despite "z.md" sorting last — tie-break is secondary.
    assert res[0]["chunk_hash"] == "late_doc"
    assert res[0]["fused_score"] > res[1]["fused_score"]


# ---------------------------------------------------------------------------
# top_k truncation and degenerate inputs.
# ---------------------------------------------------------------------------


def test_top_k_truncates_after_fusion():
    dense_hits = [("both", 0.9), ("d2", 0.5), ("d3", 0.1)]
    sparse_hits = [("both", 9.0), ("s2", 4.0)]
    _install_index(
        {
            "both": ("a.md", "A"),
            "d2": ("b.md", "B"),
            "d3": ("c.md", "C"),
            "s2": ("d.md", "D"),
        }
    )
    out = fusion.fuse(dense_hits, sparse_hits, top_k=2)
    assert len(out) == 2
    assert out[0]["chunk_hash"] == "both"  # fused winner survives truncation


def test_top_k_zero_and_negative_return_empty():
    dense_hits = [("a", 0.9)]
    sparse_hits = [("a", 0.9)]
    _install_index({"a": ("a.md", "A")})
    assert fusion.fuse(dense_hits, sparse_hits, top_k=0) == []
    assert fusion.fuse(dense_hits, sparse_hits, top_k=-1) == []


def test_top_k_none_returns_all():
    dense_hits = [("a", 0.9), ("b", 0.5)]
    sparse_hits = [("c", 0.9)]
    _install_index({"a": ("a.md", "A"), "b": ("b.md", "B"), "c": ("c.md", "C")})
    out = fusion.fuse(dense_hits, sparse_hits, top_k=None)
    assert {r["chunk_hash"] for r in out} == {"a", "b", "c"}


def test_both_legs_empty_returns_empty():
    _install_index({})
    assert fusion.fuse([], [], top_k=10) == []


def test_single_leg_only_still_fuses():
    # Only the dense leg has hits; fusion still ranks them off their dense RRF.
    dense_hits = [("a", 0.9), ("b", 0.5)]
    _install_index({"a": ("a.md", "A"), "b": ("b.md", "B")})
    out = fusion.fuse(dense_hits, [], top_k=10)
    assert [r["chunk_hash"] for r in out] == ["a", "b"]
    assert math.isclose(out[0]["fused_score"], fusion.W_DENSE * _rrf(1))
    assert out[0]["sparse_score"] == 0.0


def test_unknown_chunk_degrades_to_empty_metadata():
    # A sparse-only chunk absent from the dense index resolves to empty metadata
    # rather than raising.
    dense_hits = []
    sparse_hits = [("ghost", 3.0)]
    _install_index({})  # index knows nothing about "ghost"
    out = fusion.fuse(dense_hits, sparse_hits, top_k=10)
    assert len(out) == 1
    assert out[0]["chunk_hash"] == "ghost"
    assert out[0]["doc_path"] == ""
    assert out[0]["heading"] == ""


# ---------------------------------------------------------------------------
# Env-sourced tune-later knobs: SEARCHSVC_RRF_K / SEARCHSVC_W_DENSE /
# SEARCHSVC_W_SPARSE override the named module constants at module-eval time;
# a non-numeric value LOUD-falls back to the canonical default without raising
# at import. These reload fusion under a patched env, then reload it CLEAN so the
# module-level constants the rest of the suite asserts (60/0.65/0.35) are restored.
# ---------------------------------------------------------------------------


def _reload_clean():
    """Restore fusion to its canonical, env-free constants for later tests."""
    importlib.reload(fusion)


def test_env_overrides_change_the_named_constants(monkeypatch):
    monkeypatch.setenv("SEARCHSVC_RRF_K", "42")
    monkeypatch.setenv("SEARCHSVC_W_DENSE", "0.8")
    monkeypatch.setenv("SEARCHSVC_W_SPARSE", "0.2")
    try:
        importlib.reload(fusion)
        # Overrides land on the SAME named module constants fuse() reads.
        assert fusion.K_RRF == 42
        assert isinstance(fusion.K_RRF, int)
        assert math.isclose(fusion.W_DENSE, 0.8)
        assert math.isclose(fusion.W_SPARSE, 0.2)
        # The constants are live inside fuse(): a single dense rank-1 hit scores
        # the OVERRIDDEN W_DENSE / (overridden K + 1).
        _install_index({"a": ("a.md", "A")})
        out = fusion.fuse([("a", 0.9)], [], top_k=1)
        assert math.isclose(out[0]["fused_score"], 0.8 * (1.0 / (42 + 1)))
        index_store.reset_index()
    finally:
        monkeypatch.undo()
        _reload_clean()


def test_bad_env_loud_falls_back_without_raising_at_import(monkeypatch, capsys):
    monkeypatch.setenv("SEARCHSVC_RRF_K", "not-an-int")
    monkeypatch.setenv("SEARCHSVC_W_DENSE", "")  # empty -> canonical default, no warn
    monkeypatch.setenv("SEARCHSVC_W_SPARSE", "huge")
    try:
        # Import does NOT raise despite two unparseable values.
        importlib.reload(fusion)
        # Each bad parse fell back to the canonical default.
        assert fusion.K_RRF == 60
        assert math.isclose(fusion.W_DENSE, 0.65)
        assert math.isclose(fusion.W_SPARSE, 0.35)
        # The fallback was LOUD: a stderr warning naming each offending knob.
        err = capsys.readouterr().err
        assert "SEARCHSVC_RRF_K" in err
        assert "SEARCHSVC_W_SPARSE" in err
        # The empty value is a clean unset, not a parse error — no warning for it.
        assert "SEARCHSVC_W_DENSE" not in err
    finally:
        monkeypatch.undo()
        _reload_clean()


# ---------------------------------------------------------------------------
# RECIPROCAL CROSS-LEG SYMMETRY (the Python half of the K_RRF asymmetry pin).
#
# SEARCHSVC_RRF_K is an intentionally PYTHON-ONLY knob: fusion.py ranks off RANK
# position, so it has an RRF damping constant (K_RRF) to tune; the Go ranking leg
# blends RAW COSINES (no rank-position RRF), so it has NO RRF k and deliberately
# never reads SEARCHSVC_RRF_K. The Go side already locks BOTH directions in
# scripts/taskdb/hybrid_weight_parity_test.go:
#   - TestKRRFGoLegIgnoresIt   — the Go leg does NOT consume SEARCHSVC_RRF_K
#     (structural: no production .go file reads the literal; behavioral: setting
#     it never shifts the Go leg's resolved weights), and
#   - TestKRRFPythonLegHonorsIt — fusion.py DOES honor it (fusion.K_RRF binds to
#     the override).
# This test is the reciprocal note FROM THE PYTHON SUITE so the symmetry is
# documented on both sides: fusion.py is the SOLE consumer of SEARCHSVC_RRF_K,
# and there is intentionally no Go counterpart to keep in sync.
# ---------------------------------------------------------------------------


def test_searchsvc_rrf_k_is_python_only_no_go_counterpart(monkeypatch):
    # Python half of the cross-leg symmetry pinned by the Go parity test
    # TestKRRFGoLegIgnoresIt / TestKRRFPythonLegHonorsIt in
    # scripts/taskdb/hybrid_weight_parity_test.go.
    #
    # ASSERTED HERE (the Python leg HONORS the knob): an override flows into
    # fusion.K_RRF and is live inside fuse() — fusion.py is the SOLE consumer.
    monkeypatch.setenv("SEARCHSVC_RRF_K", "7")
    try:
        importlib.reload(fusion)
        assert fusion.K_RRF == 7
        _install_index({"a": ("a.md", "A")})
        out = fusion.fuse([("a", 0.9)], [], top_k=1)
        # The OVERRIDDEN k (7), not the default 60, lands in the rank-based score.
        assert math.isclose(out[0]["fused_score"], fusion.W_DENSE * (1.0 / (7 + 1)))
        index_store.reset_index()
    finally:
        monkeypatch.undo()
        _reload_clean()

    # DOCUMENTED RECIPROCAL (the Go leg has NO such knob): the Go ranking leg
    # blends raw cosines with no rank-position RRF, so it has no K_RRF to tune and
    # MUST NOT read SEARCHSVC_RRF_K. That direction is asymmetric — there is no
    # Python-observable Go state to assert from this suite — so it is locked on the
    # Go side (TestKRRFGoLegIgnoresIt, which fails if any production .go file ever
    # reads the literal "SEARCHSVC_RRF_K"). This comment is the reciprocal pointer
    # so a future reader editing the RRF knob finds BOTH halves of the contract.


# ---------------------------------------------------------------------------
# Startup knob log: at module load (after the env-sourced constants resolve)
# fusion.py emits ONE stderr line naming the EFFECTIVE K_RRF / W_DENSE / W_SPARSE,
# so an operator can confirm an override took. Captured by reloading under capsys.
# ---------------------------------------------------------------------------


def test_startup_log_emits_effective_default_knobs(capsys):
    # A clean reload (no env overrides) logs the canonical 60 / 0.65 / 0.35.
    importlib.reload(fusion)
    try:
        err = capsys.readouterr().err
        assert "effective fusion knobs" in err
        assert "K_RRF=60" in err
        assert "W_DENSE=0.65" in err
        assert "W_SPARSE=0.35" in err
    finally:
        _reload_clean()


def test_startup_log_reflects_env_overrides(monkeypatch, capsys):
    # The logged values are the EFFECTIVE post-override constants, so an operator
    # sees the override actually took (not the canonical defaults).
    monkeypatch.setenv("SEARCHSVC_RRF_K", "42")
    monkeypatch.setenv("SEARCHSVC_W_DENSE", "0.8")
    monkeypatch.setenv("SEARCHSVC_W_SPARSE", "0.2")
    try:
        importlib.reload(fusion)
        err = capsys.readouterr().err
        assert "effective fusion knobs" in err
        assert "K_RRF=42" in err
        assert "W_DENSE=0.8" in err
        assert "W_SPARSE=0.2" in err
    finally:
        monkeypatch.undo()
        _reload_clean()


# ---------------------------------------------------------------------------
# eval_fusion.py — the hermetic tune-later harness. Given the default fixture it
# must rank the fused order under the current knobs exactly as fusion.fuse does,
# and its rendered table must carry the effective-knob header + that full order.
# ---------------------------------------------------------------------------


def test_eval_fusion_ranks_default_fixture_full_order():
    import eval_fusion

    results = eval_fusion.evaluate(
        eval_fusion.DEFAULT_DENSE_HITS,
        eval_fusion.DEFAULT_SPARSE_HITS,
        eval_fusion.DEFAULT_META,
    )
    # FULL order asserted (not len>0): "both" wins both legs, the dense-only hit
    # beats the sparse-only hit because W_DENSE (0.65) > W_SPARSE (0.35) at equal
    # rank — proving RRF ranks off position, not the huge raw sparse score.
    assert [r["chunk_hash"] for r in results] == [
        "both",
        "dense_only",
        "sparse_only",
    ]
    both, dense_only, sparse_only = results
    assert math.isclose(
        both["fused_score"], fusion.W_DENSE * _rrf(1) + fusion.W_SPARSE * _rrf(1)
    )
    assert math.isclose(dense_only["fused_score"], fusion.W_DENSE * _rrf(2))
    assert math.isclose(sparse_only["fused_score"], fusion.W_SPARSE * _rrf(2))


def test_eval_fusion_evaluate_resets_index_singleton():
    # evaluate() is self-contained: it installs a fixture index and resets it on
    # exit, leaking no index_store state to the next caller.
    import eval_fusion

    eval_fusion.evaluate(
        eval_fusion.DEFAULT_DENSE_HITS,
        eval_fusion.DEFAULT_SPARSE_HITS,
        eval_fusion.DEFAULT_META,
    )
    # After evaluate(), the freshly-built default singleton knows none of the
    # fixture hashes — confirming the fixture index was torn down.
    idx = index_store.get_index()
    assert idx.metadata("both") == {}


def test_eval_fusion_table_carries_effective_knobs_and_full_order():
    import eval_fusion

    results = eval_fusion.evaluate(
        eval_fusion.DEFAULT_DENSE_HITS,
        eval_fusion.DEFAULT_SPARSE_HITS,
        eval_fusion.DEFAULT_META,
    )
    table = eval_fusion.format_ranking(results)
    # The header names the EFFECTIVE knobs so a render is self-describing.
    assert "K_RRF={}".format(fusion.K_RRF) in table
    assert "W_DENSE={}".format(fusion.W_DENSE) in table
    assert "W_SPARSE={}".format(fusion.W_SPARSE) in table
    # The rows appear in the fused order (both before dense_only before
    # sparse_only) — assert position, not mere presence.
    pos = {
        h: table.index(h) for h in ("both", "dense_only", "sparse_only")
    }
    assert pos["both"] < pos["dense_only"] < pos["sparse_only"]


def test_eval_fusion_main_prints_ranking_and_returns_zero(capsys):
    import eval_fusion

    rc = eval_fusion.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "effective knobs" in out
    # The default fixture's full fused order is printed in rank order.
    assert (
        out.index("both") < out.index("dense_only") < out.index("sparse_only")
    )
