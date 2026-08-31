# SPDX-License-Identifier: Apache-2.0
#
# dense.py — the dense leg of searchsvc's hybrid retrieval: an EXACT brute-force
# cosine KNN over the resident L2-normalized dense matrix held by index_store.
#
# CONTRACT (fixed by the landed serve.py — do NOT change the signature):
#     dense_search(query_dense, top_k=10) -> [(chunk_hash, dense_score), ...]
# serve.py calls this with the QUERY dense vector first and top_k as a keyword,
# and with NO store argument — so this module manages its store internally via
# index_store.get_index() (a lazily-built process singleton).
#
# WHY brute force: the corpus is a few hundred to a few thousand local doc/task
# chunks on a single host (doc 22 §8) — a single numpy dot product over an
# L2-normalized resident matrix is exact and sub-millisecond at that scale, so no
# FAISS / sqlite-vec / pgvector. The matrix rows are pre-normalized at ingest, so
# cosine(query, row) == dot(normalized_query, row): one matrix-vector product.
#
# WIDTH GUARD (the cosine short-circuit-to-0 trap): if the query width does not
# match the index width, numpy's dot would either raise an opaque shape error or,
# worse, a caller could pad/zero it and every score would be a silent 0. We guard
# explicitly: a query whose width != the index dense_dims raises LOUDLY, so a
# model/embedder swap surfaces instead of degrading retrieval to noise.
#
# PURE NUMPY. No model, no GPU, no torch.

import numpy as np

import index_store


def _normalize_query(query_dense):
    """Return a float32 1-D L2-normalized query vector. A zero query stays zero
    (every score becomes a clean 0, never NaN)."""
    q = np.asarray(query_dense, dtype=np.float32).reshape(-1)
    norm = float(np.linalg.norm(q))
    if norm > 0.0:
        q = q / norm
    return q.astype(np.float32, copy=False)


def dense_search(query_dense, top_k=10, index=None):
    """Exact cosine brute-force KNN.

    Args:
        query_dense: the query's dense vector (length == index dense width).
        top_k: number of ranked hits to return (clamped to the corpus size).
        index: optional DenseIndex override; defaults to the process singleton.

    Returns:
        A list of (chunk_hash, dense_score) sorted by descending score. Ties are
        broken by ascending chunk_hash so the order is deterministic and stable
        across runs. An empty index returns [].

    Raises:
        ValueError: if the query width != the index's recorded dense_dims (the
        loud width-mismatch guard — never a silent all-zero scoring)."""
    idx = index if index is not None else index_store.get_index()

    matrix = idx.matrix()              # (N, D) L2-normalized float32
    hashes = idx.chunk_hashes()        # parallel ordered chunk_hash array
    n = matrix.shape[0]
    if n == 0:
        return []

    q = _normalize_query(query_dense)
    index_width = int(matrix.shape[1])
    if q.shape[0] != index_width:
        raise ValueError(
            "dense query width %d != index dense_dims %d — refusing to score "
            "(a width mismatch is a model/embedder swap, not a 0 result)"
            % (q.shape[0], index_width)
        )

    # Rows are pre-normalized, so dot(matrix, q) == per-row cosine similarity.
    scores = matrix.dot(q)             # (N,) float32

    k = max(0, min(int(top_k), n))
    if k == 0:
        return []

    # argpartition for the top-k cut, then a stable full sort of just those k:
    # primary key descending score, secondary key ascending chunk_hash.
    if k < n:
        cut = np.argpartition(scores, n - k)[n - k:]
    else:
        cut = np.arange(n)
    ranked = sorted(
        (int(i) for i in cut),
        key=lambda i: (-float(scores[i]), hashes[i]),
    )
    return [(hashes[i], float(scores[i])) for i in ranked]
