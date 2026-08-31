<!-- SPDX-License-Identifier: Apache-2.0 -->

# `ds-capture` — first-party capture/replay tool (cia-parity core)

**Charter:** the compiled, first-party capture & instrumentation tool that
replaces the external `cia` (Python/mitmproxy) dependency, folding the
goldentrace harness's record / replay / scrub ideas into one shipped binary's
subcommands — so the drive tiers and the cassette fidelity loop run off a tool
we own, not a shell constellation plus an external interpreter. This directory
carries the **cia-parity core**: the `record` / `replay` / `scrub` / `inspect`
verbs over **API-layer** (`/v1/messages` SSE) cassettes. The cross-layer
`fidelity` / `canary` verbs are a later migration task and are not built here.

**Owner:** Attach & client.

**License:** OSS, Apache-2.0 (D15/D25). `ds-capture` is host-side
conformance/capture instrumentation — the open data plane's testing surface. It
imports only this `client` Go module's own packages and is wholly on the OSS
side of the service-boundary split; it never crosses into `paid/` (D80).

**Stdlib-only.** Standard library only (`client/go.mod` dependency policy): no
`go.mod`/`go.sum` entry is added by this tool. The TLS-terminating egress
gateway is a `net/http` + `crypto/tls` + `crypto/x509` problem the stdlib
solves; SSE is a `bufio.Scanner` job over the plaintext `event:`/`data:` stream.

See [`../../goldentrace/CAPTURE-TOOL-DESIGN.md`](../../goldentrace/CAPTURE-TOOL-DESIGN.md)
for the full design rationale (the Go pick, the capability cut-list, the
two-cassette-formats framing, and the `:18099` default).

## Decisions this tool touches

- **D15 / D25** — OSS, Apache-2.0; `ds-capture` is an explicitly open component.
- **D38** — runtime-ignorance: the tool encodes only the cassette format and the
  egress-gateway topology, never any `toolu_`/`task_id` vocabulary. The adapter
  that names a runtime stays the one place a runtime is named.
- **D49** — the canary / pinned-image cadence (faced by the later `canary` verb,
  not built here): the golden image pins prod CC; only the canary faces latest.
- **D50** — provenance / synthetic-only / zero-egress: replay is hermetic by
  construction (never dials upstream in strict mode); `scrub` enforces the
  raw-class wall; only `synthetic`-tagged cassettes may live in git.
- **D80** — the OSS/paid split runs on the service boundary, never inside this
  binary; `ds-capture` is wholly OSS.

## Subcommands

| Verb | What it does |
|---|---|
| `ds-capture record --cassette P [--port N]` | Stand up the TLS-terminating egress gateway, point CC at it, and tee `/v1/messages` SSE into the API-layer cassette `P`. Strips `Accept-Encoding` so the SSE arrives plaintext; strips auth/volatile headers before persistence. **Raw-class** output — run `scrub` before any promotion. |
| `ds-capture replay --cassette P [--port N] [--strict\|--passthrough]` | Serve the recorded SSE back **offline** — never opens an upstream connection in strict mode (hermetic, cred-free, zero-egress, D50). `--strict` (default) returns a synthetic `502 cia_replay_miss`-equivalent JSON on a miss; `--passthrough` is the documented **non-hermetic** escape hatch for incremental recording. |
| `ds-capture scrub <cassette> [--out P --provenance synthetic]` | Enforce the D50 wall: strip auth/volatile headers (keep only `content-type`), assert **no** `Bearer`/`sk-ant`/`x-api-key` token survives anywhere — fail loudly if one does — and gate provenance (`synthetic`/`dogfood`/`partner-consented`), refusing to emit a committable artifact unless `synthetic`. With `--out P` (and `--provenance synthetic`) it writes the scrubbed cassette `P`; report-only (no `--out`) writes nothing. The committed `P` still needs a hand-authored `P.provenance` sidecar to pass the fixture lint (see below). |
| `ds-capture inspect <cassette>` | Print the normalized keys / interaction count / per-interaction summary (the folded thin slice of `cia report` for debugging a replay miss — **not** the analytics product). |

Run `ds-capture <verb> -h` for that verb's flags; a bare or unknown invocation
prints usage and exits non-zero.

## The `:18099` default — never `:18080`

The egress gateway defaults to the free port **`:18099`** and **never** binds
**`:18080`**, the protected shared monitor. Binding `:18080` is refused in code
(`assertNotProtectedPort`) and asserted against in the tests. Point CC at the
gateway with the proven container topology (unchanged from the interim tool):
`--network=pasta:-T,<port>`, `NODE_USE_ENV_PROXY=1`, and
`NODE_EXTRA_CA_CERTS=<the generated CA the gateway prints>` so CC trusts the
on-the-fly leaf certs. Replay needs no egress at all.

## Cassette format (cia version:1, byte-compatible)

A cassette is a single JSON file, byte-compatible with the cia `version:1`
format, so a capture taken by either tool replays through the other:

```jsonc
{
  "version": 1,
  "interactions": [
    {
      "key": "claude-synthetic-test-1|turns=1|say hi|29962b6fce6480c1",
      "normalized": { "method": "POST", "path": "/v1/messages", "model": "…", "system": "…", "sequence": [ … ] },
      "status_code": 200,
      "headers": { "content-type": "text/event-stream" },
      "body": "event: message_start\ndata: {…}\n\n…"
    }
  ]
}
```

The match key is **tolerant**: it keys on method + path + model + system text +
the conversation sequence (ordered `(role, flattened-content)` pairs), folding
the growing history into the sequence so turn N matches regardless of how the
client re-sent prior turns; volatile ids, headers, sampling params, and the
`stream` flag are ignored. The key string is derived byte-for-byte the way cia
does it (sorted-key compact JSON, `ensure_ascii` `\uXXXX` escaping, no
HTML-escaping of `<>&`), proven by a shared-vector test against real cia.

## The D50 raw-class wall

Every live `record` is **raw-class**: its `body` carries real model output and
lives in a job tmp dir, **never** committed. Auth headers are stripped at
capture and again by `scrub`, which additionally asserts no Bearer token
survives anywhere and refuses to emit a committable artifact from a raw capture.
Only **re-authored synthetic** cassettes enter git (`testdata/` here carries
obviously-fake fixtures: a synthetic model id, no real model text, no
credentials, no real paths/costs/tokens, with a `.provenance` sidecar). The data
flow is one-directional: raw (job tmp) → re-authored synthetic → committed.

### `scrub --out` and the provenance sidecar

`scrub` enforces the D50 wall and, with `--out P` (gated behind `--provenance
synthetic`), writes the scrubbed cassette `P`. Report-only mode (no `--out`)
writes nothing — it only reports that the wall held. The provenance gate runs
**before** any write: a non-`synthetic` provenance (or a missing one) is refused
before a file is touched, so a raw-class capture can never be promoted.

A committed API-layer cassette is a single JSON document, not NDJSON, so the
fixture lint (`scripts/check-fixture-provenance.sh`) requires a **hand-authored**
`P.provenance` sidecar beside it — exactly one JSON object:

```jsonc
{"ds_fixture":{"provenance":"synthetic","seam":"…","created":"<UTC YYYY-MM-DD>","note":"…"}}
```

`scrub` does **not** mint this sidecar itself: authoring the sidecar (with its
synthetic `seam`/`created`/`note` fields) is part of the one-directional re-author
step (raw → synthetic → committed), exactly as `testdata/synthetic-basic.json`
carries its hand-written `testdata/synthetic-basic.json.provenance`. NDJSON
fixtures carry the same header inline as their first record instead of a sidecar.

The never-log-the-secret invariant holds throughout: no scrubbed or redacted
value reaches stderr or any error path — a secret match is reported only by
pattern name and a non-reversible length hint (HARDENING-NOTES.md §2.2).

## Tests

`go test ./cmd/ds-capture/...` is fully offline. `record` is exercised against an
in-process `net/http/httptest` fake upstream emitting synthetic SSE; `replay` is
proven hermetic (a test asserts strict mode never dials an upstream and a miss
returns the synthetic `502`); the cassette match-key is cross-checked against
golden vectors taken from real cia. No live `claude`/`cia`/`podman` and no real
network is ever invoked.
