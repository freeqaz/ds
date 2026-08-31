# SPDX-License-Identifier: Apache-2.0
#
# fusion.py — searchsvc's FUSION leg: blend the dense and sparse ranked hit lists
# into one ranked /search response via weighted Reciprocal Rank Fusion (doc 22 §8,
# decision D9).
#
# CHARTER: implement fuse(dense_hits, sparse_hits, top_k=...) — the third and final
# retrieval module serve.py's /search route wires up. serve.py is LANDED and is
# NEVER edited by this unit; it already calls
#     fusion.fuse(dense_hits, sparse_hits, top_k=top_k)
# via a lazy import, where dense_hits / sparse_hits are the ranked
#     [(chunk_hash, score), ...]
# lists produced by dense.dense_search / sparse.sparse_search (descending score,
# tie-broken on chunk_hash). This module just appears beside them and fuses.
#
# WHY RRF (not raw-score blend): the dense leg's score is a cosine similarity in
# [-1, 1] and the sparse leg's is an UNBOUNDED lexical dot product — the two are on
# wholly different scales, so summing the raw numbers lets whichever leg happens to
# have the larger magnitude dominate. Reciprocal Rank Fusion sidesteps that by
# scoring each hit from its RANK POSITION, not its raw score:
#     rrf_contribution(rank) = 1 / (K_RRF + rank)          # rank is 1-based
# A constant K_RRF (=60, the canonical Cormack-Clarke-Buettcher value) damps the
# influence of the very top ranks so a single leg can't run away with the result.
# We then take a WEIGHTED sum of the two legs' contributions — dense is the trusted
# semantic signal (W_DENSE=0.65), sparse the lexical backstop (W_SPARSE=0.35):
#     fused(chunk) = W_DENSE * rrf(rank_dense) + W_SPARSE * rrf(rank_sparse)
# A chunk present in only one leg simply contributes that leg's term (the other is
# 0) — a missing leg is a clean 0, never a crash. K_RRF / W_DENSE / W_SPARSE are
# named module-level constants so they are TUNE-LATER in one obvious place.
#
# METADATA: each surviving chunk_hash's {doc_path, heading} is resolved INTERNALLY
# from the shared dense index_store singleton (index_store.get_index().metadata),
# mirroring how dense.py / sparse.py manage their stores with no `store` param —
# serve.py calls the no-store signature. A hash the index doesn't know (e.g. a
# sparse-only chunk absent from the dense index) degrades to empty doc_path/heading
# rather than failing the fuse.
#
# OUTPUT: one ranked list of dicts
#     {chunk_hash, doc_path, heading, fused_score, dense_score, sparse_score}
# sorted by fused_score DESCENDING with a stable, deterministic tie-break on
# (doc_path, heading) so equal-scoring chunks rank in a fixed order across runs,
# truncated to top_k.
#
# PURE PYTHON. No numpy, no model, no GPU, no torch.

import os
import sys

import index_store

# --- tune-later constants (env-sourced defaults) --------------------------
# K_RRF / W_DENSE / W_SPARSE remain NAMED module-level constants read ONCE at
# module-eval time (before fuse() ever runs), so every reference below and in
# the tests stays valid. Each takes its canonical value unless the matching
# SEARCHSVC_* env var supplies an override; a non-numeric override LOUD-falls
# back to the canonical default (warning to stderr) rather than crashing import.
# These are the one obvious place to tune fusion behavior — see OPERATOR.md.
#
# SHARED TUNING KNOB (cross-leg): SEARCHSVC_W_DENSE / SEARCHSVC_W_SPARSE are read
# by the Go ranking leg too (scripts/taskdb/embeddings.go: envWDense / envWSparse,
# same names, same 0.65 / 0.35 defaults, same parse-once + loud-fallback discipline)
# so an operator tuning the dense/sparse balance moves BOTH rankers at once and they
# never silently diverge. SEARCHSVC_RRF_K stays Python-only — the Go leg blends raw
# cosines, not rank positions, so it has no RRF damping constant to tune. Contract
# here is UNCHANGED; this is a cross-reference comment only.

# Canonical RRF damping constant (Cormack/Clarke/Buettcher 2009). Larger K
# flattens the rank curve (top ranks matter less); 60 is the field default.
_K_RRF_DEFAULT = 60
# Per-leg fusion weights. Dense (semantic) is the trusted signal; sparse
# (lexical) is the backstop. They need not sum to 1 — the weighting is relative.
_W_DENSE_DEFAULT = 0.65
_W_SPARSE_DEFAULT = 0.35


def _env_number(name, default, cast):
    """Read env var ``name`` and parse it with ``cast`` (int/float), returning
    ``default`` if unset. A present-but-unparseable value LOUD-falls back to the
    default — it warns to stderr and never raises, so a typo'd knob can never
    crash module import."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return cast(raw)
    except (ValueError, TypeError):
        print(
            "searchsvc/fusion: ignoring invalid {}={!r} "
            "(expected {}); falling back to canonical default {!r}".format(
                name, raw, cast.__name__, default
            ),
            file=sys.stderr,
        )
        return default


K_RRF = _env_number("SEARCHSVC_RRF_K", _K_RRF_DEFAULT, int)
W_DENSE = _env_number("SEARCHSVC_W_DENSE", _W_DENSE_DEFAULT, float)
W_SPARSE = _env_number("SEARCHSVC_W_SPARSE", _W_SPARSE_DEFAULT, float)


def _log_effective_knobs():
    """Emit ONE stderr line naming the EFFECTIVE K_RRF / W_DENSE / W_SPARSE the
    module bound at load (after env overrides + loud-fallback resolved), so an
    operator can confirm at a glance that an intended override actually took — the
    same loud-fallback discipline _env_number uses. Fail-open: a logging hiccup
    must never crash module import, so any error here is swallowed."""
    try:
        print(
            "searchsvc/fusion: effective fusion knobs "
            "K_RRF={} W_DENSE={} W_SPARSE={}".format(K_RRF, W_DENSE, W_SPARSE),
            file=sys.stderr,
        )
    except Exception:  # pragma: no cover - logging must never break import
        pass


# Bind-time visibility: log the effective knobs ONCE at module load so an
# override (or its absence) is auditable from the service's stderr.
_log_effective_knobs()


def _rrf_contributions(hits):
    """Map a ranked [(chunk_hash, score), ...] list to two dicts keyed on
    chunk_hash: the RRF contribution 1/(K_RRF + rank) (rank is 1-based, in list
    order) and the raw leg score. The first occurrence of a hash wins its rank
    (the lists are already deduped, but this keeps a defensive duplicate from
    inflating a score)."""
    contribution = {}
    raw_score = {}
    for rank, (chunk_hash, score) in enumerate(hits or [], start=1):
        if chunk_hash in contribution:
            continue
        contribution[chunk_hash] = 1.0 / (K_RRF + rank)
        raw_score[chunk_hash] = float(score)
    return contribution, raw_score


def _metadata(chunk_hash, index):
    """Resolve {doc_path, heading} for a chunk from the dense index_store
    singleton. An unknown hash (e.g. sparse-only, never dense-ingested) degrades
    to empty strings rather than raising."""
    meta = index.metadata(chunk_hash) if index is not None else {}
    return meta.get("doc_path", ""), meta.get("heading", "")


def fuse(dense_hits, sparse_hits, top_k=10, index=None):
    """Weighted Reciprocal Rank Fusion of the dense and sparse ranked hit lists.

    Args:
        dense_hits: ranked [(chunk_hash, dense_score), ...] from dense_search
            (descending score). May be empty.
        sparse_hits: ranked [(chunk_hash, sparse_score), ...] from sparse_search
            (descending score). May be empty.
        top_k: max number of fused results to return (clamped at 0). None means
            "no limit".
        index: optional DenseIndex override for metadata resolution; defaults to
            the process singleton (index_store.get_index()). serve.py never passes
            it — it calls the no-store signature.

    Returns:
        A ranked list of dicts
            {chunk_hash, doc_path, heading, fused_score, dense_score,
             sparse_score}
        sorted by fused_score DESCENDING, tie-broken on (doc_path, heading)
        ascending so the order is deterministic and stable across runs, truncated
        to top_k. A chunk present in only one leg contributes that leg's RRF term;
        the absent leg's raw score is reported as 0.0.
    """
    if top_k is not None and top_k <= 0:
        return []

    dense_rrf, dense_raw = _rrf_contributions(dense_hits)
    sparse_rrf, sparse_raw = _rrf_contributions(sparse_hits)

    # Union of every chunk that appeared in either leg.
    chunk_hashes = set(dense_rrf) | set(sparse_rrf)
    if not chunk_hashes:
        return []

    idx = index if index is not None else index_store.get_index()

    results = []
    for chunk_hash in chunk_hashes:
        fused_score = (
            W_DENSE * dense_rrf.get(chunk_hash, 0.0)
            + W_SPARSE * sparse_rrf.get(chunk_hash, 0.0)
        )
        doc_path, heading = _metadata(chunk_hash, idx)
        results.append(
            {
                "chunk_hash": chunk_hash,
                "doc_path": doc_path,
                "heading": heading,
                "fused_score": fused_score,
                # A leg the chunk did not appear in reports a clean 0.0 raw score.
                "dense_score": dense_raw.get(chunk_hash, 0.0),
                "sparse_score": sparse_raw.get(chunk_hash, 0.0),
            }
        )

    # Primary: fused_score descending. Secondary/tertiary: (doc_path, heading)
    # ascending — a stable, deterministic tie-break independent of dict iteration
    # order so equal-scoring chunks rank identically across runs.
    results.sort(key=lambda r: (-r["fused_score"], r["doc_path"], r["heading"]))

    if top_k is None:
        return results
    return results[:top_k]
