# taskdb reference embedder

Charter: a drop-in **embedder** for taskdb's semantic doc search — the doc 22 §8
embeddings seam (decision D9). It is an external process that taskdb shells out
to; the model never enters the `taskdb` binary, so the single-static-binary
invariant holds.

## Wire contract

There are **two** wire shapes. One-text-per-invocation is the **default**; a JSON
batch is **opt-in** and amortizes the per-chunk process/HTTP cost.

### Default — one text per invocation

- **stdin**: UTF-8 text (the chunk body, or the query)
- **stdout**: a JSON float array — the embedding vector
- **non-zero exit + stderr**: when the text cannot be embedded

`scripts/taskdb/embeddings.go` (`cmdEmbedder`) is the Go side of this contract;
the ranking is cosine similarity computed in pure Go, so no SQLite vector
extension is required.

### Opt-in batch — `--batch` (JSON array)

Chunk bodies contain newlines, so the batch frame is **JSON, not**
newline-delimited raw text. The embedder is invoked with a trailing `--batch`:

- **stdin**: a JSON **array of strings** (the chunk texts, in order)
- **stdout**: a JSON **array of equal-length float arrays**, order-preserving —
  `result[i]` is the embedding of `input[i]`
- **non-zero exit + stderr** (or a non-array / length-mismatched stdout): taskdb
  treats this as a **loud error and falls back to the per-chunk path** for that
  pass, so a misbehaving batch degrades to correct (slower) output, never a
  silently short or empty index.

`scripts/taskdb/embeddings_batch.go` (`batchEmbedder` / `cmdBatchEmbedder`) is the
Go side: `embedChunks` consults the batch seam via a type assertion when the
configured embedder advertises it and there is more than one chunk to embed,
otherwise the default one-at-a-time path runs unchanged.

#### Operator knobs — `--batch-embedder` (opt-in) and `--max-batch` (window)

Batching is **off by default** for an `--embedder-cmd`; the two `doc embed` flags
that turn it on and shape it — `--batch-embedder` and `--max-batch`
(names/defaults in the [flag reference](#doc-embed-flag-reference)) — are no-ops
unless the index pass actually batches, so the default per-chunk contract is
untouched when neither is passed.

- **`--batch-embedder`** is the opt-in that turns cmd-path batching **ON**. A plain
  `--embedder-cmd` is driven one-text-per-process (the legacy contract); with this
  flag the configured command is wrapped so the index pass sends many chunk texts in a
  single `--batch` invocation, amortizing the per-chunk spawn cost. It is a **no-op for
  an `--embedder-url`** embedder (already batch-capable) and, when absent, the
  per-chunk contract is left verbatim. A misbehaving batch child degrades **loudly to
  the per-chunk path** (per window — see `--max-batch`), so the opt-in is safe.

- **`--max-batch`** is the batch **WINDOW size**: cap how many chunk texts ride a
  single batch invocation. The default (`0`) is **unlimited** — the whole to-embed set
  in one invocation, the pre-windowing behavior verbatim. A positive `N` splits the set
  into **order-preserving** windows of at most `N` (one invocation each, results
  concatenated in input order), so the overall output is **identical** to an unwindowed
  batch — only the number of round-trips changes, never result order or content. A
  negative value is clamped to `0`. Reach for a cap when an embedder rejects an
  over-large request body (an API per-request item/token ceiling) or to bound memory on
  a cold full-corpus index. It only affects a **batch-capable** embedder; the per-chunk
  path ignores it entirely.

```sh
# Cmd-path batching, capped at 64 chunk texts per invocation:
taskdb doc embed --batch-embedder --max-batch 64 \
    --embedder-cmd "python3 scripts/taskdb/embedder/embed.py"
```

**Loud per-window fallback + per-vector width validation.** Each window's batch
response is validated before its vectors are accepted: equal length (one vector per
input), non-empty dense vectors, and a **uniform per-vector width** (the first
vector's width pins the expected dimension; a divergent-width vector is a truncated or
frame-misaligned payload). Any violation writes a single loud stderr line (naming the
offending index and, for a width mismatch, the two widths) and that **window only**
falls back to the per-chunk path — the other windows keep their batched vectors, so
one bad frame never abandons the whole pass and a ragged-width set is never written to
the index.

#### When batching pays

Batching earns its keep when the **per-invocation overhead dominates** the embed
itself — chiefly an **API embedder** paying a TLS/HTTP round-trip per chunk on a
**cold full index** (hundreds of chunks → hundreds of round-trips collapse to a
handful of requests). It buys little for the local `sentence-transformers` model
on a low-hundreds corpus, where the model load (amortized by `_MODEL_CACHE`)
dominates and the per-process cost is small; the **default one-text path stays the
right choice** there. Batch mode is therefore strictly opt-in.

## Usage

```sh
# Incrementally embed new/changed chunks (unchanged hashes are never re-embedded):
taskdb doc embed  --embedder-cmd "python3 scripts/taskdb/embedder/embed.py"

# Cosine-ranked semantic search:
taskdb doc search "default-deny egress firewall" --semantic \
    --embedder-cmd "python3 scripts/taskdb/embedder/embed.py"
```

## `doc embed` flag reference

Every `taskdb doc embed` flag, once, with its source default
(cross-checked against `scripts/taskdb/cmd_doc.go`). Names and defaults here are
authoritative; the prose sections below explain the *behavior*, not the spelling.

| Flag | Type | Default | What it does |
| --- | --- | --- | --- |
| `--embedder-cmd CMD` | string | `""` | External embedder argv (whitespace-split, no shell): reads text on stdin, prints a JSON float array. Mutually exclusive with `--embedder-url`. |
| `--embedder-url URL` | string | `""` | Running searchsvc base URL (e.g. `http://127.0.0.1:8099`); embeds via the resident HTTP model instead of spawning per-chunk. Mutually exclusive with `--embedder-cmd`. |
| `--service-url URL` | string | `""` | **Push** target: after the local embed pass writes the cache, PUSH the changed `doc_chunks` set to this running searchsvc and trigger `/reindex`. Additive to / orthogonal from `--embedder-url` (that selects *which* embedder; this selects *where* to push). Fail-open — unset is a no-op, unreachable degrades loudly, never a hard failure. |
| `--backfill-provenance` | bool | `false` (OFF) | After the push, ask `--service-url` to heal resident chunks with empty provenance via `/backfill_provenance`. Requires `--service-url` (a silent no-op without it). Fail-open like the push. |
| `--prune` | bool | `true` | Drop cache rows for chunk hashes no longer on disk. |
| `--reembed-on-model-change` | bool | `true` (ON) | Re-embed cache rows whose `(model, dims)` differ from the active embedder. Default-on healing; `--reembed-on-model-change=false` is the explicit opt-out that leaves stale vectors in place this pass. |
| `--max-batch N` | int | `0` (unlimited) | Batch **window** size: cap how many chunk texts ride a single batch invocation. `0` = the whole set in one invocation; positive `N` = order-preserving windows of at most `N`; negative is clamped to `0`. Only affects a batch-capable embedder. |
| `--batch-embedder` | bool | `false` (OFF) | Opt-in that turns cmd-path batching ON: wrap an `--embedder-cmd` to send many chunk texts per `--batch` invocation. No-op for an `--embedder-url` (already batch-capable). |
| `--json` | bool | `false` | Emit the run result as JSON instead of the human summary. |

`doc search --semantic` takes the embedder-selection pair only — `--embedder-cmd`
/ `--embedder-url` (same shapes as above) — plus `--limit`, `--scope`, `--raw`,
and `--json`; the push/reembed/batch knobs are embed-time only.

## Local-model-first (proposed default), API-embedder as a config swap

The **proposed default** is a *local* model (`sentence-transformers`,
`all-MiniLM-L6-v2`): no per-call cost, no credential, no doc text leaving the
box — the right default for indexing internal design docs.

Loading a real model downloads weights on first use, so the live path is
**gated behind `DS_EMBED_LIVE=1`** and is a **deferred manual step**. CI and the
hermetic Go tests never trip it (no network, no download). Without the gate — or
if `sentence-transformers` is not installed — `embed.py` falls back to a
deterministic, dependency-free feature-hashing embedder so the seam stays
exercisable everywhere. The fallback is **not** semantically meaningful; real
ranking needs the live model or an API embedder.

Swapping to an **API embedder** is a pure config change: point `--embedder-cmd`
at a thin wrapper that posts stdin to the provider and prints the returned
vector. `taskdb` compiles in no model and no credential — the embedder process
owns that decision.

## Live model (deferred manual step)

```sh
pip install sentence-transformers          # downloads on first model load
DS_EMBED_LIVE=1 taskdb doc embed \
    --embedder-cmd "python3 scripts/taskdb/embedder/embed.py"
# Optional: SENTENCE_MODEL=<hf-model-id> to choose a different local model.
```

## Cache properties (why re-embedding is cheap)

The cache table `chunk_embeddings(chunk_hash, model, dims, vector)` is keyed on
`doc_chunks.hash` — the git blob SHA-1 of the chunk text. Because the key is the
content hash, a `doc sync` re-chunk (which churns rowids) leaves an unchanged
chunk's embedding valid: only genuinely new or edited text — or rows produced
by a *different* embedder signature (see below) — is sent to the embedder. The
table is additive (`CREATE TABLE IF NOT EXISTS`), its migration is idempotent,
and it is **never frozen** to `tasks/*.json`.

## Model-swap detection (default-on)

Cached rows carry the producing embedder's `(model, dims)` signature.
`taskdb doc embed` probes the active embedder once (a fixed canary text) to
learn its signature and re-embeds every cached row whose stored model label
**or** vector width differs. That catches both swap shapes:

- a config swap — `--embedder-cmd` re-pointed, so the model label changes;
- a same-argv runtime flip — e.g. `DS_EMBED_LIVE` toggling the 384-dim model
  to the 256-dim fallback under one label, caught by the probed dims.

The unchanged-text/unchanged-model no-op property still holds; the CLI reports
swap-driven work as `[N model-swap re-embeds]`. The healing is default-on
(`--reembed-on-model-change`, default `true` — see the
[flag reference](#doc-embed-flag-reference)); pass
`--reembed-on-model-change=false` to opt out and defer the re-embed cost this pass.

`doc search --semantic` never silently down-ranks across a swap: rows from a
different signature are **excluded** from ranking, tallied, and reported with a
loud stderr line directing the operator to `taskdb doc embed`. A search over a
swapped index is visibly degraded, never silently wrong.
