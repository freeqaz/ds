#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# serve_live.py — the LIVE BGE-M3 embedder for searchsvc, operator-only.
#
# WHY this is a separate module: BGE-M3 (BAAI/bge-m3, 569M params) produces a
# 1024-dim dense vector AND a learned sparse lexical-weight map per text, loaded
# via torch + FlagEmbedding. That path downloads ~2GB of weights and wants a
# GPU, so it NEVER runs in CI or the fleet. serve.py reaches this module ONLY
# through a function-local `import serve_live` behind the DS_EMBED_LIVE=1 gate,
# so importing serve.py never imports torch even transitively (a test asserts
# "torch" not in sys.modules after importing serve.py). This file therefore
# imports torch / FlagEmbedding LAZILY, inside the model loader, never at module
# top level.
#
# CONTRACT (identical shape to fake_embed.fake_embed): embed_text(text) returns
#   {"dense": [float x1024], "sparse": {int token_id: float weight}}
# so the searchsvc dense/sparse/fusion modules and the HTTP /embed wire consume
# the live output exactly as they consume the hermetic fake — only the dense
# width (1024 vs the fake's 256) and the realness of the sparse token-ids differ.
#
# CONFIG (env, all optional):
#   DS_EMBED_MODEL       model id            (default "BAAI/bge-m3")
#   DS_EMBED_MAX_LENGTH  max tokens          (default 1024; do NOT default 8192)
#   DS_EMBED_FP16        "1" => use_fp16     (default "1" — faster on the 3090)
#   DS_EMBED_BATCH       encode batch size   (default 16)

import os
import threading

# Lazily-initialized singleton model (one per process; a second uvicorn worker
# would duplicate the weights in VRAM, so run --workers 1).
_model = None
_model_lock = threading.Lock()

_MODEL_NAME = os.environ.get("DS_EMBED_MODEL", "BAAI/bge-m3")
_MAX_LENGTH = int(os.environ.get("DS_EMBED_MAX_LENGTH", "1024"))
_USE_FP16 = os.environ.get("DS_EMBED_FP16", "1") == "1"
_BATCH = int(os.environ.get("DS_EMBED_BATCH", "16"))
# Pin a SINGLE device. FlagEmbedding spawns a multi-process encode pool when it
# sees >1 device, and that spawn deadlocks/breaks under uv-run; one device keeps
# encoding in-process (one model in VRAM, the documented "one process per GPU").
_DEVICE = os.environ.get("DS_EMBED_DEVICE", "cuda:0")

# The live BGE-M3 dense width. Asserted on first encode so a model/config drift
# that changes the width fails LOUDLY instead of silently corrupting the index.
LIVE_DIMS = 1024


def _get_model():
    """Load BGE-M3 once. torch + FlagEmbedding are imported HERE (lazy) so this
    module is import-safe without them present until an embed is actually
    requested under DS_EMBED_LIVE=1."""
    global _model
    if _model is None:
        with _model_lock:
            if _model is None:
                # Lazy, heavy, GPU-touching imports — never at module top level.
                from FlagEmbedding import BGEM3FlagModel

                _model = BGEM3FlagModel(
                    _MODEL_NAME, use_fp16=_USE_FP16, devices=_DEVICE
                )
    return _model


def _coerce_sparse(weights):
    """FlagEmbedding's lexical_weights is a {token_id: weight} mapping; token-ids
    may arrive as str or numpy ints and weights as numpy floats. Coerce to plain
    {int: float}, dropping non-positive weights (BGE-M3 emits a 0.0 for some
    tokens) so the sparse map matches fake_embed's shape."""
    out = {}
    for k, v in dict(weights).items():
        w = float(v)
        if w > 0.0:
            out[int(k)] = w
    return out


def embed_batch(texts):
    """Live BGE-M3 embed of a list of texts. Returns a list, one
    {"dense": [...1024...], "sparse": {int tid: float wt}} per input, in order."""
    if not texts:
        return []
    model = _get_model()
    res = model.encode(
        list(texts),
        batch_size=_BATCH,
        max_length=_MAX_LENGTH,
        return_dense=True,
        return_sparse=True,
        return_colbert_vecs=False,
    )
    dense = res["dense_vecs"]
    lexical = res["lexical_weights"]
    out = []
    for i in range(len(texts)):
        dvec = [float(x) for x in dense[i]]
        if len(dvec) != LIVE_DIMS:
            raise ValueError(
                f"BGE-M3 dense width {len(dvec)} != expected {LIVE_DIMS} "
                f"(model={_MODEL_NAME}); refusing to emit a mismatched vector"
            )
        out.append({"dense": dvec, "sparse": _coerce_sparse(lexical[i])})
    return out


def embed_text(text):
    """Live BGE-M3 embed of one text -> {"dense": [...1024...], "sparse": {...}}.
    The shape serve.py.embed_text and the searchsvc modules consume."""
    return embed_batch([text])[0]
