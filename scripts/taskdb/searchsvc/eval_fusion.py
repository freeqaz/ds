# SPDX-License-Identifier: Apache-2.0
#
# eval_fusion.py — a hermetic, tune-later evaluation harness for the RRF fusion
# leg (fusion.py). Given a small fixture of dense + sparse ranked hit lists, it
# runs them through fusion.fuse under the CURRENTLY-BOUND knobs (K_RRF / W_DENSE /
# W_SPARSE — including any env overrides) and prints the resulting fused ranking,
# so an operator can SEE how a knob change reshuffles the order WITHOUT a live
# model, GPU, network, or index.
#
# This is a tune-later tool, not a service component: serve.py never imports it.
# It exists so the 60 / 0.65 / 0.35 defaults (and any override) can be eyeballed
# against a known fixture, and so a future tuning pass has a deterministic, pure
# baseline to diff against.
#
# Run it directly to print the default-fixture ranking under whatever knobs the
# environment binds:
#     uv run python eval_fusion.py
#     SEARCHSVC_W_SPARSE=0.6 uv run python eval_fusion.py   # see lexical lean
#
# PURE PYTHON. No model, no torch, no GPU, no network, no live DB — the metadata
# the fuser resolves is supplied by a synthetic in-memory DenseIndex.

import sys

import index_store
import fusion


# A small, self-contained fixture: three chunks across the two legs. "both"
# appears in both legs, "dense_only" only in dense, "sparse_only" only in sparse
# (and carries a deliberately HUGE raw sparse score to demonstrate that RRF ranks
# off POSITION, not raw magnitude). The metadata mirrors the {doc_path, heading}
# shape the live index resolves.
DEFAULT_DENSE_HITS = [("both", 0.99), ("dense_only", 0.40)]
DEFAULT_SPARSE_HITS = [("both", 5.0), ("sparse_only", 999.0)]
DEFAULT_META = {
    "both": ("docs/a.md", "Alpha"),
    "dense_only": ("docs/b.md", "Beta"),
    "sparse_only": ("docs/c.md", "Gamma"),
}


def _install_fixture_index(meta):
    """Register a synthetic DenseIndex carrying just the per-chunk metadata the
    fuser resolves (doc_path / heading). The dense vectors are irrelevant to
    fusion — it consumes the already-ranked hit lists, not the matrix — so we
    ingest a trivial 1-D row per chunk purely to register its metadata."""
    idx = index_store.DenseIndex()
    for chunk_hash, (doc_path, heading) in meta.items():
        idx.ingest(chunk_hash, [1.0], doc_path=doc_path, heading=heading)
    index_store.set_index(idx)
    return idx


def evaluate(dense_hits, sparse_hits, meta, top_k=10):
    """Fuse one fixture under the currently-bound knobs and return the ranked
    list fusion.fuse produces. Installs (and on exit resets) a synthetic index so
    the call is fully self-contained — no live index_store state leaks in or out.
    """
    _install_fixture_index(meta)
    try:
        return fusion.fuse(dense_hits, sparse_hits, top_k=top_k)
    finally:
        index_store.reset_index()


def format_ranking(results):
    """Render a fused-ranking list as a fixed-width, human-readable table string.
    Pure formatting: no I/O, so tests can assert on the returned text."""
    lines = [
        "effective knobs: K_RRF={} W_DENSE={} W_SPARSE={}".format(
            fusion.K_RRF, fusion.W_DENSE, fusion.W_SPARSE
        ),
        "{:>4}  {:<12}  {:>11}  {:>11}  {:>11}  {}".format(
            "rank", "chunk_hash", "fused", "dense", "sparse", "doc_path#heading"
        ),
    ]
    for rank, r in enumerate(results, start=1):
        lines.append(
            "{:>4}  {:<12}  {:>11.6f}  {:>11.4f}  {:>11.4f}  {}#{}".format(
                rank,
                r["chunk_hash"],
                r["fused_score"],
                r["dense_score"],
                r["sparse_score"],
                r["doc_path"],
                r["heading"],
            )
        )
    return "\n".join(lines)


def main(argv=None):
    """Print the default fixture's fused ranking under the currently-bound knobs.
    Returns a process exit code (0). No arguments today — the fixture is the
    DEFAULT_* module constants; a future tuning pass can import evaluate() with
    its own fixture."""
    results = evaluate(DEFAULT_DENSE_HITS, DEFAULT_SPARSE_HITS, DEFAULT_META)
    print(format_ranking(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
