# searchsvc — taskdb hybrid search dispatcher

**Charter.** A thin HTTP dispatcher for taskdb's hybrid (dense + sparse)
semantic search — the doc 22 §8 embeddings seam (decision **D9**). It owns the
five HTTP routes (`/embed`, `/search`, `/reindex`, `/ingest_batch`,
`/backfill_provenance` — see the wire contract below) and the embedder selection;
the actual retrieval (dense ANN, sparse lexical match, fusion) lives in sibling
modules that other units own. The model never enters the `taskdb` binary,
preserving the single-static-binary invariant — `taskdb` shells/HTTP-talks to
this process the same way it shells to `embedder/embed.py`.

**Owner.** taskdb / local dev-tooling. This is local developer tooling, NOT a
shipped OSS/paid component and NOT an agent-facing service. See the graduation
trigger below.

**Marks / decisions.** D9 (semantic-search seam; LLM-call scanning rejected as a
boundary control — search is a productivity affordance, not a guardrail). The
live local-model path is gated exactly like `embedder/embed.py`'s, behind
`DS_EMBED_LIVE=1`.

## What lives here vs. what does NOT

This unit ships the dispatcher and its hermetic test surface:

- `serve.py` — the dispatcher: the FastAPI app serving all five routes
  (`/embed`, `/search`, `/reindex`, `/ingest_batch`, `/backfill_provenance` — see
  the wire contract below), plus the equivalent stdlib `do_POST` fallback. The
  retrieval legs are reached only through function-local (lazy) imports — `/search`
  calls `fuse(dense_search(...), sparse_search(...))`, and the ingest/reindex
  routes drive the resident dense + sparse stores — so the `dense`/`sparse`/`fusion`
  modules stay other units' files and live beside `serve.py`, not inside it.
- `fake_embed.py` — the deterministic hermetic embedder (no model, no GPU).
- `test_searchsvc.py` — hermetic pytest.
- `pyproject.toml` / `uv.lock` / `.gitignore` — the uv-managed env.

What must **NOT** live here:

- **No torch / FlagEmbedding / model download / GPU code** in `serve.py` or
  `fake_embed.py`. The live BGE-M3 embedder is a **separate unit's
  `serve_live.py`**, reached only through a function-local (lazy) import behind
  `DS_EMBED_LIVE=1`. A test asserts `torch` is not in `sys.modules` after
  importing `serve.py`.
- **No retrieval logic.** `dense.py`, `sparse.py`, `fusion.py` are other units'.
- **No proto changes / no credentials / no agent-facing surface.**

## Wire contract

Five POST routes, JSON in / JSON out. The table is the index; each route's
request/response shape below is cross-checked against `serve.py` (the FastAPI
handlers and the equivalent stdlib `do_POST` branch serve the identical JSON).

| Route | Method | Request | Response | Purpose |
| --- | --- | --- | --- | --- |
| `/embed` | POST | `{text, doc_path?, heading?}` | `{dense:[...256...], sparse:{tid:w}, dense_dims}` | Embed one text and ADDITIVELY ingest the chunk into the resident dense+sparse indexes (the live accumulation path); return the per-chunk echo. |
| `/search` | POST | `{query, top_k?}` | `{degraded, results:[...], query, freshness:{...}}` | Embed the query, then `fuse(dense_search(...), sparse_search(...))`; attach the index freshness verdict. Degrades to embed-only until retrieval modules land. |
| `/ingest_batch` | POST | `{chunks:[{text, doc_path?, heading?}, ...]}` | `{ingested:int, chunk_hashes:[...]}` | Embed + ADDITIVELY ingest a LIST of chunks in one request (the cold-push fast path that collapses the Go pusher's O(N) `/embed` round-trips); no per-chunk vectors echoed. |
| `/reindex` | POST | `{}` | `{reindexed, dense_chunks, dense_ingested, sparse_chunks, db}` | Rebuild BOTH resident retrieval legs (dense + sparse) from the local `taskdb.sqlite`; a missing DB yields a 0-count rebuild, never a 500. |
| `/backfill_provenance` | POST | `{}` | `{healed, scanned, empty, unresolved, db}` | TARGETED heal: re-resolve provenance for resident chunks that landed with EMPTY `doc_path`/`heading` (streamed before the provenance-pushers fix) from the index DB's `doc_chunks`, updating resident metadata in place — no full `/reindex`. |

`top_k` defaults to `10`; `doc_path`/`heading` default to `""`. Optional request
fields are marked `?`. All bodies are JSON objects (`{}` for the no-body routes).

### `POST /embed`

Request:

```json
{ "text": "default-deny egress firewall" }
```

Response:

```json
{
  "dense": [/* FALLBACK_DIMS = 256 floats, L2-normalized */],
  "sparse": { "<token_id>": <weight>, "...": "..." },
  "dense_dims": 256
}
```

- **dense** is a fixed-width (256) feature-hashing bag-of-words, L2-normalized so
  cosine similarity is well-defined. 256 is the **hermetic/fallback** width; the
  live BGE-M3 dense width is **1024** and is produced only off the live path.
- **sparse** is a `{token_id: weight}` map — stable synthetic int token-ids
  (a hash, NOT real BGE-M3 vocab ids) → term counts. JSON object keys are
  strings on the wire.
- Identical input text yields an identical dense vector AND sparse map on any
  machine (the content-hash cache and hermetic tests rely on this).

### `POST /search`

Request:

```json
{ "query": "hybrid retrieval", "top_k": 10 }
```

The handler embeds the query, then calls
`fuse(dense_search(query_dense, ...), sparse_search(query_sparse, ...))`.

- **When `dense`/`sparse`/`fusion` are present:**
  `{ "degraded": false, "results": [...], "query": "..." }`.
- **Until they land (hermetic skeleton today):**
  `{ "degraded": true, "reason": "...", "query_dense_dims": 256,
     "query_sparse_terms": N, "results": [], "query": "..." }` — the route stays
  live and testable, and the fusion wiring is observable.

`/search` ADDITIVELY attaches a `freshness` verdict so a caller can flag a stale
resident index without a second round-trip:

```json
{ "fresh": false, "verdict": "stale",
  "stored_digest": "<hex>|null", "current_digest": "<hex>",
  "stored_count": 0, "current_count": 0, "drift": 0 }
```

`drift` is `current_count - (stored_count or 0)` — a positive value is the rough
count of chunks the resident index has not absorbed yet (a quick "how stale").

### `POST /ingest_batch`

Request:

```json
{
  "chunks": [
    { "text": "default-deny egress firewall", "doc_path": "docs/28.md", "heading": "Guardrails" },
    { "text": "another chunk", "doc_path": "", "heading": "" }
  ]
}
```

Response:

```json
{ "ingested": 2, "chunk_hashes": ["<sha256-hex>", "<sha256-hex>"] }
```

- The cold-push batch verb: each entry is embedded with the SAME `embed_text` the
  single `/embed` route uses, then pushed into the resident dense + sparse indexes
  via the best-effort ingest path (a degraded index never 500s a batch).
- Per-chunk dense/sparse vectors are intentionally NOT echoed — a cold push over
  the whole corpus wants the chunks landed resident-side, not N vectors on the
  wire. `chunk_hashes` is the sha256 hex of each chunk's UTF-8 text (the dedupe key).
- A malformed entry (missing/blank `text`) is skipped, not fatal — the batch
  continues (loud-but-fail-open ingest discipline).

### `POST /reindex`

Request: `{}` (no body needed).

Response:

```json
{ "reindexed": true, "dense_chunks": 0, "dense_ingested": 0,
  "sparse_chunks": 0, "db": "/abs/path/to/taskdb.sqlite" }
```

- Rebuilds BOTH resident legs from the resolved index DB: dense via
  `index_store.get_index().refresh_from_sqlite(<db>)`, sparse via a fresh
  `sparse.load_store()`. `db` is the resolved path (see `SEARCHSVC_DB` below).
- A missing DB yields a 0-count rebuild rather than a 500.

### `POST /backfill_provenance`

Request: `{}` (no body needed).

Response:

```json
{ "healed": 0, "scanned": 0, "empty": 0, "unresolved": 0,
  "db": "/abs/path/to/taskdb.sqlite" }
```

- TARGETED heal for resident chunks that landed with EMPTY `doc_path`/`heading`
  (streamed before the provenance-pushers fix). Re-resolves `(path, heading)`
  keyed by `chunk_hash` from the index DB's `doc_chunks` and refreshes the
  resident dense metadata IN PLACE (re-ingesting each chunk's EXISTING dense row
  so only the metadata changes) — no full `/reindex`.
- Counts: `scanned` = resident chunks examined, `empty` = those with no
  provenance, `healed` = those resolved + refreshed, `unresolved` = empty chunks
  the DB could not resolve. Best-effort: a missing DB / unresolvable hash leaves
  that chunk untouched rather than 500-ing.

## Embedder selection

| `DS_EMBED_LIVE` | path | width | needs |
| --- | --- | --- | --- |
| unset / not `1` | `fake_embed` (deterministic) | dense 256 + synthetic sparse | nothing |
| `1` | `serve_live.embed_text` (BGE-M3) — **separate unit** | dense 1024 + learned sparse | torch + FlagEmbedding + weights download (operator-only, deferred manual step) |

`serve.py` reaches the live embedder ONLY through a function-local import; the
live deps are the `[live]` extra and are never installed in the hermetic path.

## Framework: FastAPI, with a stdlib fallback

Built **around FastAPI** (`serve.build_app()`), the preferred library choice; the
uv env ships it so the server-stand-up tests actually run over `TestClient`. A
`http.server` fallback (`serve.build_stdlib_app()` / `serve.serve_stdlib()`)
serving the same JSON contract is a defensive bonus for an env without FastAPI.

## uv-managed env

```sh
cd scripts/taskdb/searchsvc
SSL_CERT_FILE=$HOME/.mitmproxy/mitmproxy-ca-cert.pem uv sync   # hermetic core only
uv run pytest
```

- Core deps (`fastapi`, `uvicorn`, `pydantic`, `numpy`, `httpx`, `pytest`) are
  the hermetic surface; `requires-python >= 3.11`.
- `torch` + `FlagEmbedding` are declared ONLY as the optional `[live]` extra and
  are NEVER installed by a plain `uv sync`.
- `uv.lock` is committed; `.venv/` and `__pycache__/` are gitignored (never
  tracked — `check-vendor-tracked` stays green).
- Any `uv sync` needs `SSL_CERT_FILE` pointed at the egress-proxy CA, or uv fails
  TLS.

## Live model (deferred manual step, operator-only)

```sh
cd scripts/taskdb/searchsvc
SSL_CERT_FILE=$HOME/.mitmproxy/mitmproxy-ca-cert.pem uv sync --extra live  # downloads torch
DS_EMBED_LIVE=1 uv run python serve.py          # uses serve_live (separate unit)
```

CI and hermetic tests never trip this (no network, no download, no GPU).

## Operator env knobs

Several overrides are discoverable only by reading source. The single reference
table below is the operator's source of truth — every name, default, and effect
is cross-checked against `fusion.py`, `embeddings.go`, `searchsvc_ingest.go`,
`index_store.py`, and `serve_live.py`. Each knob parses ONCE at module/package
load and LOUD-falls back to its default on an unset/empty/unparseable value
(never crashes).

| Env var | Read by | Default | Effect |
| --- | --- | --- | --- |
| `SEARCHSVC_W_DENSE` | Go `embeddings.go` (`resolveHybridWeights`) **and** `fusion.py` (`W_DENSE`) — same name, same default in both legs | `0.65` | Relative weight of the dense (semantic) leg in the hybrid blend. Moves BOTH rankers at once so they never silently diverge. |
| `SEARCHSVC_W_SPARSE` | Go `embeddings.go` (`resolveHybridWeights`) **and** `fusion.py` (`W_SPARSE`) — same name, same default in both legs | `0.35` | Relative weight of the sparse (lexical) leg. Weights need not sum to 1 — the balance is relative. |
| `SEARCHSVC_RRF_K` | `fusion.py` ONLY (`K_RRF`) — the Go leg blends raw cosines (no rank positions), so it has no RRF damping constant | `60` | Reciprocal Rank Fusion damping constant `1/(K_RRF + rank)`. Larger K flattens the rank curve so a single top-ranked hit can't dominate. |
| `SEARCHSVC_DB` | `index_store.py` (`resolve_db_path`); shared by the dense and sparse legs and the `ingest`/`/reindex` path | repo-root `taskdb.sqlite` (walked up from the module) | The unified index sqlite both retrieval legs read/write, so they never index two different DBs. First in the precedence chain `SEARCHSVC_DB` → `TASKDB_SQLITE` → `TASKDB_DB` → repo-root fallback; honored even if the path does not exist, so a typo surfaces instead of silently sliding to another DB. |
| `DS_SEARCHSVC_INGEST_BATCH` | Go `searchsvc_ingest.go` (`resolveIngestBatchSize`) | `128` (clamped `>= 1`) | Number of chunks per `/reindex` push batch during an embed run. A value `< 1` or unparseable banners once and reverts to `128`. |
| `DS_EMBED_LIVE` | `serve.py` (gates the function-local `import serve_live`) | unset (`fake_embed`, hermetic 256-dim) | Set to `1` to switch `/embed` to the live BGE-M3 path (`serve_live.embed_text`, dense 1024 + learned sparse). Operator-only; requires the `[live]` extra (torch + FlagEmbedding + weights download). Never set in CI/hermetic tests. |
| `DS_EMBED_DEVICE` | `serve_live.py` (`_DEVICE`) | `cuda:0` | Single torch device for the live model. Pinned to ONE device — FlagEmbedding's multi-device encode pool deadlocks under `uv run`, so keep encoding in-process. |
| `DS_EMBED_MAX_LENGTH` | `serve_live.py` (`_MAX_LENGTH`) | `1024` | Max tokens per text on the live encode path. Do NOT default to 8192. |

Related live-path knobs (also `serve_live.py`, operator-only): `DS_EMBED_MODEL`
(default `BAAI/bge-m3`), `DS_EMBED_FP16` (default `1`), `DS_EMBED_BATCH`
(default `16`). See the `serve_live.py` header for the full live config.

## Graduation trigger (the follow-up this README owes)

searchsvc is local dev tooling living as a sibling of `embedder/` inside the
`scripts/taskdb` tree. **If searchsvc ever exposes an agent-facing gRPC surface,
or graduates into its own top-level tree, it owes the full README "Adding a new
component" checklist**: pick the license side first, reserve the proto seam, wire
CODEOWNERS + a `guardrail-map.yaml` glob (unmapped paths fail closed, D47) + a
README stating charter/owner/mark/D-numbers. Until then it stays a shelled-to
external process with no proto contract and no credential, exactly like
`embedder/embed.py`.
