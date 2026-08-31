# searchsvc — operator runbook (live BGE-M3)

`serve_live.py` + `run-searchsvc.sh` are the **operator-only** live path. CI and
the fleet never run them — they serve the hermetic fake. This runbook stands up
the real **BGE-M3** (BAAI/bge-m3, 1024-dim dense + learned sparse lexical
weights) embedder behind `DS_EMBED_LIVE=1` on a GPU box.

Validated 2026-06-14 on an RTX 3090: model load ~6s, **~112 chunks/s**, the full
2,889-chunk taskdb corpus (605 docs + 1704 tasks + 580 notes) embedded in **24s**.

## One-time install

```sh
cd scripts/taskdb/searchsvc
SSL_CERT_FILE=$HOME/.mitmproxy/mitmproxy-ca-cert.pem uv sync --extra live
```

This pulls `torch` (CUDA build) + `FlagEmbedding`. The egress proxy CA
(`SSL_CERT_FILE`) is required for the package + model-weight fetch through
ds-tlsproxy. The BGE-M3 weights (~2.3GB `pytorch_model.bin`) download on first
model load; set `HF_HUB_OFFLINE=1` afterward to pin the cache.

## Gotchas (learned the hard way)

- **Pin ONE GPU** (`DS_EMBED_DEVICE=cuda:0`, the default). With >1 visible
  device FlagEmbedding spawns a multi-process encode pool that deadlocks /
  `BrokenPipeError`s under `uv run`. One device = in-process encode.
- **`max_length` 1024–2048**, never 8192 (encode time scales with it). Default 1024.
- **Single worker** — a second uvicorn worker duplicates the 569M model in VRAM.
- **Index DB env var: set `SEARCHSVC_DB`** to the hydrated sqlite. Both the dense
  and sparse legs read the one unified resolver now (the split where the sparse
  leg read `TASKDB_DB` was fixed bgem3w4), so a single var feeds both. `TASKDB_DB`
  is still honored as a fallback for the bare taskdb store, but you no longer need
  to set both to the same path.

## Hydrate a dedicated index DB

The service owns a **derived, rebuildable** index (the git `tasks/*.json` +
`docs/` stay the source of truth). Build one without touching the shared live
`taskdb.sqlite`:

```sh
# clean consistent snapshot
sqlite3 taskdb.sqlite "VACUUM INTO '$HOME/tmp/ds-searchsvc-index.sqlite'"
# embed the whole corpus (docs + tasks + notes) into chunk_embeddings
#   (dense LE-float32 + sparse (uint32 id, float32 wt) pairs — the Go encoding)
HF_HUB_OFFLINE=1 DS_EMBED_LIVE=1 DS_EMBED_DEVICE=cuda:0 DS_EMBED_MAX_LENGTH=512 \
  HYDRATE_DB=$HOME/tmp/ds-searchsvc-index.sqlite \
  uv run python hydrate_index.py     # the bulk hydration script
```

## Run

```sh
SEARCHSVC_DB=$HOME/tmp/ds-searchsvc-index.sqlite \
  ./run-searchsvc.sh                 # serves 127.0.0.1:8088, DS_EMBED_LIVE=1
```

`POST /embed {"text": "..."}` → `{dense:[1024], sparse:{tid:wt}, dense_dims}`.
`POST /search {"query": "...", "top_k": 10}` → dense brute-force cosine + sparse
lexical dot → server-side RRF fusion → ranked `{chunk_hash, doc_path, heading,
fused_score, dense_score, sparse_score}`.

## Fusion tuning knobs (env-sourced)

The RRF fusion leg (`fusion.py`) blends the dense and sparse ranked hit lists.
Its three constants are **env-sourced defaults read once at module load** — set
the matching env var to override, leave it unset for the canonical default. A
non-numeric value LOUD-falls back to the default (a one-line warning to stderr)
and never crashes the service.

| Env var             | Constant   | Type  | Canonical default | What it does                                                                 |
| ------------------- | ---------- | ----- | ----------------- | ---------------------------------------------------------------------------- |
| `SEARCHSVC_RRF_K`   | `K_RRF`    | int   | `60`              | RRF damping (Cormack/Clarke/Buettcher 2009). Larger flattens the rank curve. |
| `SEARCHSVC_W_DENSE` | `W_DENSE`  | float | `0.65`            | Weight of the dense (semantic) leg. Trusted signal.                          |
| `SEARCHSVC_W_SPARSE`| `W_SPARSE` | float | `0.35`            | Weight of the sparse (lexical) leg. Lexical backstop.                        |

```sh
# example: lean harder on lexical recall, soften the RRF damping
SEARCHSVC_RRF_K=40 SEARCHSVC_W_DENSE=0.55 SEARCHSVC_W_SPARSE=0.45 \
  ./run-searchsvc.sh
```

**Tune later, not now.** The canonical 60 / 0.65 / 0.35 are field defaults; the
weights need not sum to 1 (the weighting is relative). These knobs exist so the
blend can be tuned against real recall/precision on a live corpus without a code
change — leave them unset until you have measurements to tune against, then move
them in small steps. The values bind at module load, so a change takes effect on
the next service start.

**Confirm an override took.** Because the constants bind at module load, `fusion.py`
logs the EFFECTIVE values to stderr ONCE at load, e.g.

```
searchsvc/fusion: effective fusion knobs K_RRF=40 W_DENSE=0.55 W_SPARSE=0.45
```

If that line shows the canonical 60 / 0.65 / 0.35 when you meant to override, your
env var didn't reach the process (or was non-numeric and LOUD-fell back — look for
the accompanying `ignoring invalid ...` warning). This is your one-glance check
that the knobs you set are the knobs the service is using.

**Preview a knob change with `eval_fusion.py`.** Before restarting the live
service, you can see how a knob change reshuffles the ranking against a small
built-in fixture — no model, GPU, network, or index needed:

```sh
uv run python eval_fusion.py                         # default 60 / 0.65 / 0.35
SEARCHSVC_W_SPARSE=0.6 uv run python eval_fusion.py   # lean lexical, see the shuffle
```

It prints the effective-knob header and the fused ranking (chunk, fused/dense/
sparse scores, doc#heading) of the fixture, so you can eyeball the effect of a
candidate setting before committing it to a service restart. It is a tune-later
tool — `serve.py` never imports it.

## Stays localhost / out of the sandbox

v1 is single-host, no auth — do **not** expose beyond localhost. Cross-machine
access is the deferred pgvector/SSH-tunnel phase, mirroring the taskdb lock
server (central Postgres over an SSH tunnel, fail-open). The service must never
be reachable from inside the sandboxed agent VMs (default-deny by design); it is
dev-host tooling, like the lock server.
