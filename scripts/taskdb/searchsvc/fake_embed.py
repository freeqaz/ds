#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# fake_embed.py — the deterministic, hermetic embedder for searchsvc.
#
# WHY this exists: the live path is BGE-M3 (1024-dim dense + a learned sparse
# lexical-weight map) loaded via torch/FlagEmbedding behind DS_EMBED_LIVE=1 in a
# SEPARATE unit (serve_live.py). That path downloads weights and wants a GPU, so
# it never runs in CI or the fleet. This fake gives searchsvc an embedder that
# runs ANYWHERE with no model, no download, no GPU — so the dispatcher, the
# dense/sparse search modules, and the fusion stay exercisable and the HTTP wire
# contract stays testable.
#
# DISCIPLINE (reused from scripts/taskdb/embedder/embed.py's fallback_embed):
#   - DENSE: a feature-hashing bag-of-words into a FIXED width, L2-normalized so
#     cosine similarity is well-defined. We use FALLBACK_DIMS = 256 deliberately
#     — 256 is the hermetic/fallback width; 1024 is the LIVE BGE-M3 width and
#     never appears off the live path.
#   - SPARSE: a map of STABLE synthetic integer token-ids -> term weight. Token
#     ids are a stable hash of each lexical token (NOT a real BGE-M3 vocab id),
#     and the weight is the term count. This mimics BGE-M3's sparse lexical
#     output shape (token-id -> weight) without any model.
#
# DETERMINISM: identical input text yields an identical dense vector AND an
# identical sparse map on any machine. The content-hash cache and the hermetic
# tests rely on this exactly as embed.py's fallback does.
#
# This module imports ONLY the stdlib (hashlib, re) + numpy is intentionally NOT
# required here so fake_embed stays importable in the leanest environment; the
# dense vector is a plain list[float]. It must NEVER import torch.

import hashlib
import re

# Hermetic/fallback dense width. 256 is the fallback floor shared with
# embedder/embed.py (FALLBACK_DIMS); the live BGE-M3 dense width is 1024 and is
# never produced here.
FALLBACK_DIMS = 256

# Sparse synthetic vocabulary size. Token ids are hashed into this range so the
# sparse map keys are bounded, stable small ints — a synthetic stand-in for
# BGE-M3's lexical-weight token-id space, NOT real model vocab ids.
SPARSE_VOCAB = 100_000

_WORD_RE = re.compile(r"[A-Za-z0-9]+")


def _tokens(text):
    """Lowercase alphanumeric tokens — the same tokenization embed.py uses."""
    return _WORD_RE.findall(text.lower())


def fake_dense(text):
    """Deterministic dense embedding: feature-hash each token into one of
    FALLBACK_DIMS buckets (stable sha1 of the token), sign-spread, L2-normalize.
    Identical text -> identical vector. Width is EXACTLY FALLBACK_DIMS (256).
    Returns a list[float]."""
    vec = [0.0] * FALLBACK_DIMS
    for token in _tokens(text):
        digest = hashlib.sha1(token.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "big") % FALLBACK_DIMS
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        vec[idx] += sign
    norm = sum(x * x for x in vec) ** 0.5
    if norm > 0:
        vec = [x / norm for x in vec]
    return vec


def _token_id(token):
    """Stable synthetic token-id for a lexical token. A hash into SPARSE_VOCAB —
    a deterministic stand-in for a BGE-M3 vocab id, never a real one."""
    digest = hashlib.sha1(b"sparse:" + token.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % SPARSE_VOCAB


def fake_sparse(text):
    """Deterministic sparse embedding: a {token_id: weight} map keyed on stable
    synthetic int token-ids, weight = term count (as float, mirroring BGE-M3's
    lexical-weight shape). Identical text -> identical map. Returns
    dict[int, float]."""
    counts = {}
    for token in _tokens(text):
        tid = _token_id(token)
        counts[tid] = counts.get(tid, 0.0) + 1.0
    return counts


def fake_embed(text):
    """Both halves at once: {"dense": [...256...], "sparse": {tid: weight}}.
    The shape the searchsvc dense/sparse modules + fusion consume. Deterministic
    end to end."""
    return {"dense": fake_dense(text), "sparse": fake_sparse(text)}
