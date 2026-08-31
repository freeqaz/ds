#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# embed.py — reference embedder for taskdb's doc 22 §8 semantic-search seam.
#
# CONTRACT (the wire shape taskdb speaks, see scripts/taskdb/embeddings.go):
#
#   DEFAULT (one text per invocation):
#   - reads UTF-8 text on stdin (one chunk per invocation)
#   - writes a JSON float array (the embedding vector) on stdout
#   - exits non-zero with a diagnostic on stderr if it cannot embed
#
#   OPT-IN BATCH (invoked with --batch; amortizes the per-chunk process/HTTP cost
#   on a cold full index — chunk bodies contain newlines, so the batch frame is
#   JSON, never newline-delimited raw text):
#   - reads a JSON ARRAY OF STRINGS on stdin (the chunk texts, in order)
#   - writes a JSON ARRAY OF EQUAL-LENGTH FLOAT ARRAYS on stdout, order-preserving
#     (result[i] is the embedding of input[i])
#   - exits non-zero with a diagnostic on stderr if it cannot embed
#   taskdb treats a length mismatch / non-array response as a LOUD error and falls
#   back to the per-chunk path, so a misbehaving batch degrades to correct output.
#
# Wire it in:
#   taskdb doc embed  --embedder-cmd "python3 scripts/taskdb/embedder/embed.py"
#   taskdb doc search "<query>" --semantic \
#       --embedder-cmd "python3 scripts/taskdb/embedder/embed.py"
#
# DESIGN — local-model-first (the PROPOSED default), API-embedder as a swap:
#
#   The PROPOSED default is a LOCAL model (sentence-transformers, all-MiniLM-L6-v2):
#   no per-call cost, no credential, no data leaving the box — the right default
#   for indexing internal design docs. Loading a real model downloads weights on
#   first use, so the live path is GATED behind DS_EMBED_LIVE=1 and is a DEFERRED
#   MANUAL STEP: CI and hermetic tests never trip it (no network, no download).
#
#   Swapping to an API embedder is a pure CONFIG change, not a code change: point
#   --embedder-cmd at a thin wrapper that posts stdin to the provider and prints
#   the returned vector. taskdb compiles in no model and no credential; the
#   embedder process owns that decision. (Rationale lives here in code, not in
#   doc 22 — the doc 22 prose for this seam is the watermark-retention unit's.)
#
#   Without DS_EMBED_LIVE=1 — or if sentence-transformers is not installed — this
#   script falls back to a DETERMINISTIC, dependency-free hashing embedder. The
#   fallback is NOT semantically meaningful (it is a feature-hashing bag of
#   words); it exists so the seam is exercisable and the wire contract is
#   testable on any machine. Real semantic ranking requires the live model or an
#   API embedder.

import hashlib
import json
import os
import re
import sys

# Fallback vector width. 256 is enough spread for the hashing fallback to keep
# distinct chunks distinguishable while staying cheap to store.
FALLBACK_DIMS = 256

# The proposed local default model. Small, fast, 384-dim, widely used for
# retrieval — a sensible starting point; swap via SENTENCE_MODEL if desired.
DEFAULT_MODEL = os.environ.get("SENTENCE_MODEL", "all-MiniLM-L6-v2")

_WORD_RE = re.compile(r"[A-Za-z0-9]+")


def live_enabled() -> bool:
    """Live local-model path is opt-in only (it may download weights)."""
    return os.environ.get("DS_EMBED_LIVE") == "1"


def try_live_embed_batch(texts):
    """Embed a LIST of texts with a local sentence-transformers model, or return
    None if the library is unavailable. Any import/load failure degrades to None
    rather than crashing, so a missing optional dependency is a graceful fallback,
    not an error — the availability check the unit calls for. The single-text path
    is just a one-element batch (try_live_embed), so the live model is loaded once
    and the JSON wire shape is the only thing that differs between the two modes."""
    if not live_enabled():
        return None
    try:
        from sentence_transformers import SentenceTransformer  # noqa: F401,WPS433
    except Exception as exc:  # pragma: no cover - exercised only under DS_EMBED_LIVE=1
        print(
            f"embed.py: DS_EMBED_LIVE=1 but sentence-transformers unavailable "
            f"({exc}); falling back to the deterministic hashing embedder",
            file=sys.stderr,
        )
        return None
    try:
        model = _load_model(DEFAULT_MODEL)
        vecs = model.encode(list(texts), normalize_embeddings=True)
        return [[float(x) for x in vec] for vec in vecs]
    except Exception as exc:  # pragma: no cover - live only
        print(f"embed.py: live model '{DEFAULT_MODEL}' failed: {exc}", file=sys.stderr)
        return None


def try_live_embed(text: str):
    """Single-text live embed — a one-element batch through try_live_embed_batch.
    Returns the vector (a JSON float array's worth) or None to fall back."""
    batch = try_live_embed_batch([text])
    if batch is None:
        return None
    return batch[0]


_MODEL_CACHE = {}


def _load_model(name):  # pragma: no cover - live only
    """Cache the loaded model. taskdb spawns one process per chunk today, so the
    cache helps only if a caller batches; it is cheap insurance and harmless."""
    if name not in _MODEL_CACHE:
        from sentence_transformers import SentenceTransformer

        _MODEL_CACHE[name] = SentenceTransformer(name)
    return _MODEL_CACHE[name]


def fallback_embed(text: str):
    """Deterministic, dependency-free feature-hashing embedder. Each token bumps
    one of FALLBACK_DIMS buckets (chosen by a stable hash of the token); the
    vector is L2-normalized so cosine similarity is well-defined. Identical text
    yields an identical vector on any machine — exactly what the seam's
    content-hash cache and the hermetic tests rely on. NOT a substitute for a
    real model's semantics; it is the testable floor."""
    vec = [0.0] * FALLBACK_DIMS
    for token in _WORD_RE.findall(text.lower()):
        digest = hashlib.sha1(token.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "big") % FALLBACK_DIMS
        # Sign bit from a later digest byte spreads tokens across +/- so unrelated
        # texts are closer to orthogonal than an all-positive bag would be.
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        vec[idx] += sign
    norm = sum(x * x for x in vec) ** 0.5
    if norm > 0:
        vec = [x / norm for x in vec]
    return vec


def embed_one(text: str):
    """Embed a single text, live model first then the deterministic fallback."""
    vec = try_live_embed(text)
    if vec is None:
        vec = fallback_embed(text)
    return vec


def run_single() -> int:
    """DEFAULT contract: text on stdin → JSON float array on stdout."""
    text = sys.stdin.read()
    sys.stdout.write(json.dumps(embed_one(text)))
    return 0


def run_batch() -> int:
    """OPT-IN batch contract: a JSON array of strings on stdin → a JSON array of
    HYBRID embedding objects on stdout, order-preserving (result[i] embeds input[i]).

    WIRE SHAPE (widened for the hybrid dense+sparse embedder, e.g. BGE-M3):
        [{"dense": [float, ...], "sparse": {"<token_id>": weight, ...}}, ...]

    The DENSE vector is always present (the legacy payload); SPARSE is a token_id ->
    weight map and is OPTIONAL — the deterministic hashing FALLBACK is dense-only, so
    it emits "sparse": {} (an empty map), defaulting to FALLBACK_DIMS=256 with NO
    DS_EMBED_LIVE and no model download. taskdb's batch decoder accepts BOTH this
    object shape AND the legacy bare [[float, ...], ...] array, so an older embedder
    stays compatible. A non-array stdin is a loud error (taskdb falls back to
    per-chunk)."""
    raw = sys.stdin.read()
    try:
        texts = json.loads(raw)
    except Exception as exc:
        print(f"embed.py: --batch stdin is not valid JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
        print(
            "embed.py: --batch stdin must be a JSON array of strings",
            file=sys.stderr,
        )
        return 1
    hybrid = try_live_embed_batch_hybrid(texts)
    if hybrid is None:
        # Dense-only fallback: a {dense, sparse:{}} object per input, FALLBACK_DIMS-wide.
        hybrid = [{"dense": fallback_embed(t), "sparse": {}} for t in texts]
    # Order-preserving + equal-length by construction (one object per input).
    sys.stdout.write(json.dumps(hybrid))
    return 0


def try_live_embed_batch_hybrid(texts):
    """Embed a LIST of texts into HYBRID {dense, sparse} objects with the live
    model, or return None to fall back (DS_EMBED_LIVE unset, or the library/model
    unavailable). The dense path reuses try_live_embed_batch; sparse is left EMPTY
    here because emitting a real lexical sparse vector is the live model's job and a
    separate deferred unit owns serve_live.py — this hermetic reference embedder
    never loads a model. Wrapping the dense result keeps the wire shape uniform
    whether or not a sparse vector is available."""
    dense = try_live_embed_batch(texts)
    if dense is None:
        return None
    return [{"dense": vec, "sparse": {}} for vec in dense]


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--batch" in argv:
        return run_batch()
    return run_single()


if __name__ == "__main__":
    sys.exit(main())
