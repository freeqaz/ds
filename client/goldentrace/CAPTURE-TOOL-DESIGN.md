# Capture-tool design — the first-party `ds-capture`, replacing `../cia`

**Charter:** the compiled, first-party capture & instrumentation tool that
replaces the external `../cia` (Python/mitmproxy) dependency and folds the
goldentrace harness's capture / scrub / replay / canary ideas into one binary's
subcommands — so the live drive tiers, the cassette fidelity loop, and the
nightly canary all run off a tool we ship, not a shell constellation plus an
external interpreter.
**Owner:** Attach & client · **OSS** (Apache-2.0, D15/D25) ·
**Decisions touched:** D38 (runtime-ignorance), D49 (canary + pinned image),
D50 (provenance / synthetic-only / zero-egress), D80 (OSS/paid service-boundary
split), D24/D26 (assurance levels).
**Status:** **RATIFIED (language + §6 calls) — core landed.** The §1
language pick (**Go**) and §6 calls 1/2/4/5 were ratified by the maintainers on
2026-06-12 (recorded in §1 and §6 below; deliberately *not* a D-row — the §1
counter-condition is the standing revisit trigger). The build (`01KTXKJNJ8`)
and the consumer migration (`01KTXKJYYW`) have landed as
`client/cmd/ds-capture/`; wave-2 follow-ups are in flight. The cut-list,
subcommand surface, and migration order below are the design the build
executed. taskdb `01KTXKJBER` (spike, done).

> **Proposed-vs-decided legend.** Where this doc says **DECIDED** it is citing an
> existing ratified D-row from `docs/04-architecture-overview.md` §6.
> The language pick (§1) and §6 calls 1/2/4/5 are **RATIFIED** (maintainer,
> 2026-06-12). The cut-list verdicts (§2), the subcommand surface (§3), the
> `--captool` flag (§4), and the migration order (§5) remain **PROPOSED**
> design guidance, binding nothing until the build/migration tasks land them.

---

## 0. The problem this spike answers

The live drive tiers and the cassette ground truth lean on `../cia` — an
external Python tool built on mitmproxy — for: TLS-terminating interception of
`/v1/messages` on `:18080`, SSE stream parsing, record/replay cassettes (the
`--runtime-dir` coexistence override + auto-disabled hook/otlp ports landed on
branch `cia-record-replay-coexist`), Claude Code hook + OTLP receivers, an
`fswatch` file-change subprocess, and session analytics (`cia report`). It is
~5.2k LOC of Python.

`client/wrapper/DRIVE-PROTOCOL.md` §"Language & performance" fixes the binding
constraint: **scripting may *discover* the protocol; only compiled Go/Rust may
*carry* it in the product.** CIA is, by that split, squarely on the *discover*
side — interim by construction (the README, the e2e README, and the goldentrace
README each say so). This spike designs the *carry*-side replacement.

The unification thesis (verbatim from the task and the goldentrace README): the
**API-layer cassettes** (`/v1/messages` SSE, what CIA records) and the
**app-layer cassettes** (`*.cc-wire.ndjson`, the goldentrace stdout fixtures)
**stay distinct artifacts** — but the *operations* over them (capture, scrub,
provenance per D50, the replay determinism substrate, and the nightly canary
cadence per D49) become **one tool's subcommands** instead of a shell
constellation (`capture.sh`, the `cc_sandbox.sh` launcher) plus an external
Python dependency.

---

## 1. Language pick — **Go** (RATIFIED 2026-06-12)

**Recommendation: Go.** Rationale, weighed against the genuine Rust pull:

### The case for Go (recommended)

1. **It lives in, and links, the `client` module.** The tool's whole reason to
   exist is to unify with goldentrace. The fidelity loop's id-relative canonical
   form (`fidelity/canon.go`), the projection engine (`replay/replay.go`, the
   claude-code adapter), and the `SandboxArgv` contract (`e2e/harness.go`) are
   **Go, in this module**. A Go capture tool *imports* the projection and the
   canon directly — its `fidelity` and `canary` subcommands reuse the exact
   equality engine the tests use, with no FFI and no second implementation of
   the structural-canon rules to drift. A Rust tool would re-implement the canon
   (the costliest thing to fork: a divergent canon silently breaks the n=1
   fidelity guarantee) or shell back out to a Go helper.

2. **It matches `client/` and `vm/` and the stdlib-only wrapper.** The host-agent
   (`vm/`) and the wrapper/adapter/driver (`client/wrapper/`) are Go,
   stdlib-only (`client/go.mod`). DRIVE-PROTOCOL.md §"Language & performance"
   already rules **driver + adapter + e2e harness → Go, non-negotiable**, and
   names the host-agent bridge "Go by default, Rust only if profiled." The
   capture tool is the same class of test/conformance infrastructure as the e2e
   harness — it belongs in the Go camp by that established split, not the
   data-plane camp.

3. **TLS-terminating interception is a library problem Go's stdlib solves.** The
   load-bearing core is an HTTP forward proxy that terminates TLS for
   `api.anthropic.com`, parses the SSE stream, and tees/synthesizes responses.
   `net/http` + `crypto/tls` + `crypto/x509` give an on-the-fly leaf-cert
   minting proxy (the classic `httputil.ReverseProxy` + a CA the container
   trusts via `NODE_EXTRA_CA_CERTS`) in stdlib. SSE is line-oriented
   `event:`/`data:` text (the cia record-replay doc confirms the proxy already
   strips `Accept-Encoding`, so the bytes arrive plaintext) — a `bufio.Scanner`
   job. None of this needs Rust's performance or memory model.

4. **Single-static-binary distribution, trivially.** `go build` yields one
   static binary the `cc_sandbox.sh` plan can name and the pinned Containerfile
   can `COPY` — no venv, no `pip install -e`, no interpreter in the image. This
   is the concrete win over CIA: the e2e/fidelity live steps stop requiring a
   Python toolchain beside the repo.

### The case for Rust (acknowledged, declined)

- **The ds-tlsproxy precedent.** `dataplane/` (one cargo workspace) hosts
  `ds-dnsgate` and `ds-tlsproxy` — the production **TLS-terminating
  egress-gateway** the agent can't reach (docs 09/12, read here only as
  precedent). A capture tool that *also* terminates TLS on `/v1/messages` is
  superficially the same shape, and "Rust for TLS-terminating data-plane bytes"
  is a real repo convention.
- **Why it loses here.** ds-tlsproxy is a **production, security-critical,
  agent-unreachable boundary service** on the hot egress path of every customer
  session — it earns Rust on the data-plane-bytes-are-Rust rule. The capture
  tool is **test/conformance instrumentation**: it runs in the e2e/fidelity/
  canary harnesses and the deferred manual live step, *never* in a customer's
  session egress path, never reachable by a production agent. It is latency-
  *tolerant* (replay collapses timing; DRIVE-PROTOCOL.md forbids asserting on
  TTFT/tok-s anyway), and its dominant cost is *sharing the canon/projection with
  goldentrace*, which is Go. Choosing Rust would buy the ds-tlsproxy stylistic
  match at the price of an FFI seam or a forked canon — the wrong trade for a
  test tool.

> **Verdict (RATIFIED, 2026-06-12): Go.** The decisive factor is unification, not the proxy:
> the tool's `fidelity`/`canary` value comes from reusing the Go canon and
> projection in-process; the proxy core is comfortably a Go-stdlib library
> problem; and the established split already files capture/conformance
> infrastructure under Go while reserving Rust for the production data plane.
> **Naming (PROPOSED): `ds-capture`** (binary), under the OSS `client` side.
>
> **The one ratifiable counter-condition:** if a future production need puts this
> proxy on a *customer session's* egress path (it is not, today), it crosses into
> ds-tlsproxy's charter and the Rust verdict flips — record that as the trigger,
> the same way DRIVE-PROTOCOL.md defers the byte-bridge Rust call to profiling.

---

## 2. Capability cut-list — keep / fold / drop (PROPOSED)

The record/replay TLS-terminating egress-gateway core is **load-bearing —
KEEP, non-negotiable**: it is the determinism substrate the whole drive-tier
thesis (DRIVE-PROTOCOL.md §"Determinism via record-replay") and the fidelity
loop's ground truth depend on. Everything else is rated against one question:
*does the first-party tool need it to serve the e2e / fidelity / canary
consumers, or is it CIA's analytics charter that does not ship?*

| CIA capability | Verdict | One-line justification |
|---|---|---|
| **Record/replay of `/v1/messages` SSE** (the TLS-terminating egress-gateway core, tolerant request matcher, JSON cassette) | **KEEP** | The load-bearing determinism substrate; D50 hermetic replay (zero-egress, cred-free) and the fidelity n=1 ground truth both require it. This *is* the tool. |
| **TLS termination / on-the-fly leaf cert minting** (the `NODE_EXTRA_CA_CERTS` CA the container trusts) | **KEEP** | Prerequisite to intercepting `/v1/messages` at all; the proven `pasta:-T,<port>` topology (§4) points CC's egress at it. Egress-gateway / TLS-termination, never the retired MITM vocabulary. |
| **SSE stream parsing** (TTFB/TTFT, thinking phase, cache tokens) | **KEEP the parse, DROP the metrics surface** | The parser is needed to tee/normalize the cassette body; but the *latency/thinking analytics* it computes are `cia report` territory (see analytics row). Keep `event:`/`data:` framing; do not port the timing rollups. |
| **CC hook receiver** (UserPromptSubmit / SessionStart/End / Stop / SubagentStop / PreCompact / Notification / Pre/PostToolUse on `:7171`) | **DROP** | Redundant with first-party observability: the wrapper's claude-code **adapter** already projects the same lifecycle to `attach.v1` from stdout (`subagent.spawned/completed/accounted`, `ask.requested/resolved`, `session.*`) — the load path, not a side hook port. The coexistence work already auto-disables the hook port; we never reintroduce it. |
| **OTLP receiver** (CC native cost/token/LoC telemetry on `:4318`) | **DROP** | Same reason: cost/usage already ride the API plane the proxy sees (and the adapter's accounting trailers). A second OTLP endpoint is a CIA-analytics convenience, not a drive-tier need; coexistence already auto-disables it. If first-party OTLP is ever wanted it is the orchestrator's telemetry charter, not this tool's. |
| **`fswatch` subprocess** (`~/.claude/projects/**` + `tasks` file-change events, transcript/memory diffs) | **DROP** | Pure session-analytics introspection with an external `fswatch` dependency; nothing in e2e/fidelity/canary consumes file-change events. Dropping it also removes a non-Go subprocess — a clean win for the single-static-binary goal. |
| **Session analytics** (`cia report`: turn anatomy, tool profiles, cache economics, thinking calibration, context pressure, cost attribution, throughput…) | **DROP from this tool; FOLD the cassette-inspection slice** | The rich `cia report` is a performance-analysis product orthogonal to the capture mission — it does not ship as part of the drive harness. **Fold** only the thin slice the harness needs: a `ds-capture inspect <cassette>` that prints the normalized keys / interaction count for debugging a replay miss (the cassette's `normalized` field already exists for this). The analytics product, if wanted later, is its own component with its own charter. |
| **Scrub / provenance enforcement (D50)** | **KEEP + ELEVATE to a subcommand** | Today scrub is implicit (cia strips auth headers) and provenance is enforced by goldentrace's `fixtures/` gate + `HARDENING-NOTES.md`. **Fold** both into `ds-capture scrub` / a provenance check (§3) so one tool owns the D50 bright line: strip auth, assert no Bearer token, tag `synthetic`/`dogfood`/`partner-consented`. |
| **Nightly canary cadence (D49)** | **KEEP + FOLD as a subcommand** | The canary (`01KTWJ25NG`) is "still pending" (goldentrace README) and would otherwise be more shell glue. **Fold** it: `ds-capture canary` runs the live capture against CC-latest and diffs the projection vs. the pinned golden, exiting non-zero on drift → a queued review task, not an incident (D49). |

**Net cut:** the three receiver/watcher subsystems (hook, OTLP, fswatch) and the
analytics product are **DROPPED**; the record/replay egress-gateway core,
SSE-parse-for-cassette, scrub/provenance, and the canary are **KEPT**, with scrub
and canary **ELEVATED** from implicit/shell to first-class subcommands. The
~5.2k Python LOC collapses toward a small Go binary because most of CIA's bulk is
the analytics and receiver surface we deliberately do not carry.

---

## 3. Unification with goldentrace — two cassette formats, one tool

**The cassette formats stay DISTINCT artifacts (DECIDED framing — the task and
goldentrace README state it explicitly). They are different layers of the same
loop and must not be conflated:**

| | **API-layer cassette** | **App-layer cassette** |
|---|---|---|
| **Boundary** | `/v1/messages` SSE (the model's "brain") | CC stdout stream-json (the wire side of the D38 seam) |
| **On disk** | one JSON file, `interactions[]` (cia format, `version:1`) | `*.cc-wire.ndjson` (one record per line) |
| **Who writes it** | `ds-capture record` (the egress gateway tees it) | hand-authored synthetic, re-authored from live (D50) |
| **Who reads it** | `ds-capture replay` serves it back; CC regenerates stdout | the goldentrace adapter projects it → `attach.v1` |
| **Determinism role** | freezes the *model*, so live CC becomes a function of inputs | freezes the *stdout*, so the parser is tested without a live binary |
| **Provenance** | live = **raw-class**, never committed; synthetic only in git | synthetic-only in git, `fixtures/PROVENANCE.md` header |

They are deliberately **complementary, not interchangeable**: the API cassette is
"strictly stronger" (DRIVE-PROTOCOL.md) because real CC *regenerates* the stdout —
exercising the wrapper↔CC↔driver control round-trip the app-layer cassette
cannot. The fidelity loop's entire job is to assert these two layers *agree*
(the synthetic `*.cc-wire.ndjson` projection must equal the live-captured stdout
projection, id-relative), with the API cassette as the independent ground truth
that distinguishes stale-cassette from real CC drift. **One tool, two formats —
the unification is the subcommand surface, not a merged file format.**

### Proposed subcommand surface (`ds-capture <verb>`)

This is the shell-constellation-and-Python collapse made concrete. Each verb
replaces a `cia` invocation or a `capture.sh`/`cc_sandbox.sh` step:

| Subcommand | Replaces | What it does |
|---|---|---|
| `ds-capture record --cassette P --port N` | `cia record` (+ `cia run`'s proxy leg) | Stand up the TLS-terminating egress gateway on `:N`, drive-tier points CC at it, tee `/v1/messages` SSE → API cassette `P`. Cred-bearing, budget-capped. **Never `:18080`** (the protected monitor); default a free port (the proven `:18099`). Carries the `--runtime-dir` private-socket + auto-disabled-receivers coexistence semantics natively (no protected-port collision). Records only **complete turns**: the tee streams incrementally and persists an interaction only when the upstream both closes cleanly and carries a terminal `message_stop`, so a mid-stream upstream failure is dropped (zero interactions) rather than recorded as a truncated turn that would replay as complete. A returned `Content-Encoding: gzip` (non-compliant — `Accept-Encoding` is stripped upstream) is a hard `502` from the response headers alone, never a buffer-then-relay decode, so progressive delivery cannot silently degrade. Both refusals report shape only (event count / encoding), never body bytes (never-log-the-secret). |
| `ds-capture replay --cassette P --port N [--strict]` | `cia replay` | Serve the recorded SSE back **offline** — short-circuit `/v1/messages`, never open an upstream connection. Cred-free, zero-egress (D50 hermetic by construction). `--strict` (default) returns a synthetic `502 cia_replay_miss`-equivalent on a miss; `--passthrough` is the non-hermetic incremental-record escape hatch — the one replay branch that opens an upstream connection, and even there the agent's auth/volatile headers (Authorization / x-api-key / anthropic-beta / session-correlation tells) are **stripped before the request leaves the gateway** so no credential crosses onto the upstream wire (the D50 wall, HARDENING-NOTES §2.2; the credential-less request is the intended cost of the escape hatch). Tolerant matcher (method+path+conversation-sequence, ids/headers/growing-history dropped). |
| `ds-capture inspect <cassette>` | the useful slice of `cia report` | Print the normalized keys / interaction count / per-interaction summary for debugging a replay miss. The folded analytics slice — not the full report product. |
| `ds-capture scrub <cassette> [--out P --provenance synthetic [--seam TAG --note TEXT]]` | implicit cia auth-strip + `HARDENING-NOTES` discipline | Enforce the D50 wall as an explicit step: strip auth/volatile headers (keep only `content-type`), assert **no Bearer token** anywhere, refuse to emit a committable artifact from a raw capture. The provenance gate (`synthetic`/`dogfood`/`partner-consented`, only synthetic in git) runs **before any write** (gate-then-write). Report-only with no `--out` writes nothing; with `--out P` it **mints** the `<P>.provenance` sidecar — exactly one JSON line `{"ds_fixture":{"provenance":"synthetic","seam":"<seam>","created":"<UTC YYYY-MM-DD>","note":"<note>"}}` (the sidecar the fixture-provenance gate validates for a non-NDJSON fixture) **as part of the scrub itself**, sidecar-first then cassette so neither half survives a failed write. The sidecar carries only provenance metadata — never any scrubbed/redacted credential value (never-log-the-secret, HARDENING-NOTES §2.2). The auth/volatile header set scrub strips is the single one the replay `--passthrough` scrub and the tolerant matcher's header-drop also key on (`cassette.VolatileRequestHeader`); its HARDENING-NOTES §2.2 membership (Authorization, x-api-key, anthropic-beta, X-Claude-Code-Session-Id, x-client-request-id) is pinned for completeness by a table-driven test that fails closed — naming the missing header — if any §2.2 tell is dropped, so a silent set-drift can't let a real auth header survive a scrub. |
| `ds-capture fidelity [--scenario S]` | `go run ./goldentrace/fidelity/cmd/fidcheck` | The id-relative projection-equality loop (synthetic vs. live-equiv), reusing `fidelity/canon.go` + `replay.go` **in-process** (the Go-wins argument). Exit non-zero on divergence. |
| `ds-capture canary` | the pending nightly canary (`01KTWJ25NG`) | Run the live capture against **CC-latest**, project, diff vs. the pinned-golden projection; non-zero = queued review (D49, not a production incident). The golden image pins prod CC (`2.1.173`); the canary is the only tier that intentionally faces *latest*. |

Charter boundary: `record`/`replay`/`inspect`/`scrub` operate on **API-layer**
cassettes; `fidelity`/`canary` are the **cross-layer** verbs that compare the two
projections. The adapter/projection that names a runtime stays the *one* place a
runtime is named (D38) — `ds-capture` is otherwise runtime-ignorant, exactly as
the e2e harness is (it encodes only the launcher-contract and the cassette
format, no `toolu_`/`task_id` vocabulary).

### OSS placement (D80)

`ds-capture` is **OSS** (Apache-2.0, D15/D25), beside goldentrace in the `client`
module — it is host-side conformance/capture instrumentation, the open data
plane's testing surface (D24 level-a/b, D26 the public assurance subset). It
imports only the `client` Go module's own packages and `proto/gen/go` if it ever
needs a contract type; it never crosses into `paid/`. The OSS/paid line stays a
service boundary, never a binary split — `ds-capture` is wholly on the OSS side.

---

## 4. `cc_sandbox.sh` integration — the `SandboxArgv` successor for `--cia`

Today (`client/goldentrace/e2e/README.md` + `e2e/harness.go`) the launcher's
drive CLI is the `SandboxArgv` contract, mirrored field-for-field by
`e2e.SandboxArgv` (a structural argv-contract test ties them so they cannot
drift):

```
cc_sandbox.sh --cia <bin> --mode record|replay --cassette <path> \
              [--budget-usd <X> | --no-egress]
```

The `--cia <bin>` leg (`SandboxArgv.CIABin`, proxy `:18080`) is the **interim**
hook the e2e README explicitly flags for migration: *"when [the first-party tool]
lands, this flag, `CIABin`, and the argv-contract test migrate with it."* This
section is that migration's design.

### The container egress topology (PROVEN, unchanged)

The first-party tool **inherits the proven topology verbatim** — only the binary
behind the proxy changes. The live-drive evidence (e2e README "Live run
evidence — 2026-06-12"; fidelity README "Live evidence") established and proved:

- **`--network=pasta:-T,<port>`** is the proven-live host-loopback egress: CC in
  the rootless container reaches the host-loopback capture proxy on `<port>`.
  (The keystone-era `slirp4netns:allow_host_loopback=true` +
  `host.containers.internal` form is superseded by the simpler proven `pasta:-T`
  port-forward.)
- **`NODE_USE_ENV_PROXY=1`** is mandatory (PHASE2 P6: undici honours
  `HTTPS_PROXY`/`HTTP_PROXY` only with that flag).
- **`NODE_EXTRA_CA_CERTS=<the capture CA>`** so CC trusts the egress gateway's
  on-the-fly leaf certs (the in-image npm build is broken under TLS interception;
  the host claude binary is mounted ro at `/opt/claude-code`).
- **replay / `--no-egress` → `--network=none`** — zero external egress, no proxy
  env, cred-free (D50 hermetic). Replay is always zero-egress regardless of the
  flag.

`ds-capture` changes **none** of this. It binds the same host-loopback port the
`pasta:-T,<port>` forward targets and presents the same CA. The only difference
from CIA: it must **not** default to the protected `:18080` monitor's port — it
defaults to a free port (the proven `:18099`) and carries the
`--runtime-dir`-style private-socket + auto-disabled-receiver semantics
*natively* (it has no hook/otlp/fswatch receivers to collide in the first place —
see §2 drops), so the whole class of "singleton refuses to start while a daemon
socket exists" blocker (DRIVE-FINDINGS §5) **evaporates by construction**.

### Proposed `SandboxArgv` evolution (the `--cia` → `--captool` swap)

A minimal, contract-preserving rename — the *shape* is identical, the binary and
default port change:

| Today (`--cia`) | Proposed (`--captool`) | Change |
|---|---|---|
| `--cia <bin>` → `SandboxArgv.CIABin` | `--captool <bin>` → `SandboxArgv.CapToolBin` | rename the flag + field; the bin is now the first-party `ds-capture` |
| `--mode record\|replay` → `Mode` | *(unchanged)* | record/replay verbs map to `ds-capture record`/`replay` |
| `--cassette <path>` → `Cassette` | *(unchanged)* | the API-layer cassette path, same semantics |
| `--budget-usd <X>` → `BudgetUSD` | *(unchanged)* | record-only cost cap (default `0.60`) |
| `--no-egress` → `NoEgress` | *(unchanged)* | forces the zero-egress network |
| proxy `:18080` (hard-named) | proxy default a **free** port (`:18099`), `--port` overridable | drop the `:18080` default so the tool never collides with the protected monitor |

The structural argv-contract test (`TestSandboxArgvMatchesScriptUsage`) migrates
with the rename — it keeps asserting every flag `SandboxArgv` emits appears in
the script source, that there is one live gate (`DS_E2E_LIVE=1`), and the
network tokens (`pasta:-T,<port>` / `--network=none`) match. The G-gates
(G0 argv … G7 in-container assert) are unchanged except G6 mode/network
coherence now keys on `ds-capture`'s port, and the G4 forbidden-mount scan still
forbids `~/.cia` (until CIA is fully retired, then it forbids the new tool's job
dir too).

**`cc_sandbox.sh` stays a planner, not a launcher** (DRIVE-FINDINGS §"drift 3"):
even armed it gates (G1–G7) and prints the exact podman argv; the Go e2e harness
remains the executor that re-asserts the invariants before any container starts.
`ds-capture` changes the *named binary in the plan*, not the gate-then-plan-then-
execute division of labor.

### Backward-compat during migration

The two-flag overlap is intentional and bounded: during `01KTXKJYYW` the script
accepts **both** `--cia` (deprecated, warns) and `--captool`, with `--captool`
winning if both appear. Once every consumer (next section) is off `--cia`, the
deprecated flag, `CIABin`, the `:18080` default, and the `~/.cia` references are
deleted in one commit and the external dependency is retired.

---

## 5. Consumer migration order (PROPOSED)

Migration is the **follow-up task `01KTXKJYYW`** (this spike only designs it); the
build of `ds-capture` itself is `01KTXKJNJ8`, which this spike blocks. Order the
consumers by *blast radius if it goes wrong* — least-coupled and most-hermetic
first, so a regression surfaces on a tier where it cannot reach spend or
production drift:

**0. (precondition) `ds-capture` reaches `cia` record/replay parity.** Build task
`01KTXKJNJ8`: the `record`/`replay`/`scrub`/`inspect` verbs match
`cia/docs/record-replay.md` semantics (tolerant matcher, JSON cassette
`version:1`, `--strict` miss → synthetic 502, auth-stripped bodies). The existing
`01KTXEXQAZ` (cia record/replay mode) is the **parity baseline** to test against —
a recorded cassette must replay identically through both, then through `ds-capture`
alone. Nothing migrates until parity is green offline. The match-key parity sensor
(`01KTYS878F`, hardened by `01KTYY506H`) is two-legged: an always-on offline test
pins the Go matcher's keys against shared synthetic vectors, and an env-gated
`DS_CIA_PARITY=1` manual run re-derives them against a real local cia checkout. The
opt-in must not silently degrade — `DS_CIA_PARITY=1` with a missing/stale cia
checkout fails loudly rather than skipping, so a green offline pin can never be read
as "cross-tool parity confirmed" when the manual leg never ran. The shared vectors
cover the image / multi-image / mixed `tool_result`+text derivation flagged as the
most-likely-subtle-bug surface, at zero live-run cost.

**0b. (precondition, manual) Pre-migration cia match-key drift-run.** Before the
`01KTXKJYYW` step-1 migration trusts `ds-capture replay` against cia-recorded
cassettes, run the env-gated cross-tool drift sensor once against a **local cia
checkout** and record the verdict. Per the regen recipe in the header of
`client/cmd/ds-capture/internal/cassette/cassette_test.go`, run
`DS_CIA_PARITY=1 DS_CIA_DIR=<local cia> go test ./client/cmd/ds-capture/internal/cassette/ -run TestMatchKeyCIAParityDrift -v`
— it exec's `python3` importing `cia.cassette` as a **pure-function library call**
(no network, no proxy, never `cia run`/live claude) and re-derives the match-keys.
Confirm **all shared vectors equal the pinned goldens** (`testdata/parity-vectors.json`)
and record the run: **PASS/FAIL, date, operator**. A **FAIL is a queued review (D49
spirit)** — a human re-pins the goldens *deliberately*, never auto-regen — and the
migration **does not proceed on cross-tool divergence**. This is the one manual gate
between offline parity (step 0) and the step-1 swap; it exercises the §6 item-3 drift
check, the same wave-2 follow-up (`01KTYS878F`).

**1. Cassette fidelity loop (`01KTXBGTK6`) first.** It is the **most hermetic and
the highest-value** consumer: its always-on tier is already pure-Go offline
(synthetic pairs, no live `cia` in CI) — so swapping its *live* half
(`fidelity_live_test.go`, `DS_E2E_LIVE`-gated) from `cia record --runtime-dir` to
`ds-capture record --port 18099` touches only the gated path, and the in-process
`fidelity`/`canon` reuse (the Go-wins payoff) lands here. A regression is caught
by the always-on `TestFidelityLoopIsNonVacuous` / perturbation teeth before it
reaches anything live. The `capture.sh` harness (`CIA_RECORD=1 CIA_PROXY_PORT=
18099 ./capture.sh`) becomes `ds-capture record` — the first shell→binary
collapse.

**2. e2e live tiers (`01KTXBGTJA` + the `cc_sandbox.sh` launcher) second.** Swap
the `SandboxArgv` `--cia`→`--captool` (§4) and the argv-contract test with it.
This is the broadest surface (the launcher, the gate suite, the live-drive
socket-bridge tier) but every always-on test in `e2e/` runs against a **fake-CC
helper** with no live `cia`/`podman` — so the contract rename is provable offline
(`TestSandboxArgvMatchesScriptUsage`, `…ArgsShape`, `…Validate`) and only the
single `DS_E2E_LIVE`-gated `TestLiveDriveSocketBridgeReal` ever touches a
container. Do it after fidelity so the capture binary is already battle-tested on
the hermetic tier.

**3. Nightly canary (`01KTWJ25NG`) last.** It is the **only tier that faces
CC-latest and runs unattended on a schedule**, so it has the largest blast radius
(a tooling bug here mimics or masks real upstream drift — a false canary is worse
than none). Migrate it only once `record`/`replay`/`fidelity` are proven on tiers
1–2, then fold it into `ds-capture canary` (§3). Until then it stays pending
(it is unbuilt today), so "migrate" here means **build it first-party** rather
than ever wiring it to `cia`.

**4. Retire `../cia`.** Delete the deprecated `--cia`/`CIABin`/`:18080`-default/
`~/.cia` references, drop the external Python dependency, and update the three
READMEs (goldentrace, e2e, fidelity) and DRIVE-PROTOCOL.md §"Language &
performance" corollary to point at `ds-capture`. This is the terminal step of
`01KTXKJYYW`.

```
01KTXEXQAZ (cia record/replay — parity baseline)
01KTXKJBER (THIS spike — design)
   └─▶ 01KTXKJNJ8  Build ds-capture core (record/replay/scrub/inspect, cia parity)
          └─▶ 01KTXKJYYW  Migrate consumers, retire ../cia:
                 1. fidelity loop (01KTXBGTK6)   — most hermetic, in-process canon reuse
                 2. e2e live tiers (01KTXBGTJA)  — --cia→--captool, argv-contract test
                 3. nightly canary (01KTWJ25NG)  — build first-party, largest blast radius
                 4. delete --cia / CIABin / :18080 / ~/.cia; drop the Python dep
```

### Hardening-wave status — capharden (2026-06-12)

The post-landing hardening wave closed five gaps against this design (merged on
`capharden-integration`; the per-row prose above already reflects them):

1. **Replay `--passthrough` D50 wall** — auth/volatile headers are stripped in
   `forwardUpstream` before any request leaves the gateway, so no credential
   crosses onto the upstream wire even on the non-hermetic escape hatch (§3
   replay row).
2. **Record persists only complete turns; gzip is a hard `502`** — a mid-stream
   upstream failure is dropped (zero interactions), and a non-compliant
   `Content-Encoding: gzip` is refused from the response headers alone, never a
   buffer-then-relay decode; both refusals report shape only, never body bytes
   (§3 record row).
3. **`DS_CIA_PARITY=1` fails loudly on a broken env** — a missing/stale cia
   checkout is a FAIL, never a silent skip, and the shared parity vectors now
   cover multi-image and mixed `tool_result`+text derivation (§5 step 0).
4. **Doc accuracy** — the §3 scrub row and the §5 step-0/0b pre-migration
   drift-run checklist were reconciled with the implemented behavior, against
   the ratified §6 calls.
5. **`VolatileRequestHeader` completeness pinned to HARDENING-NOTES §2.2** by a
   table-driven test that fails closed, naming the missing header, if any §2.2
   header tell is dropped from the scrub/matcher set.

Deferred to the next wave (files-overlap with the merged units; each re-scoped
as its own taskdb sub-task under the capture-tool parent `01KTXBF3YZ`): the
record-persist D50 cassette-wall test (the twin of item 1, on what `record`
writes), document/PDF + `cache_control` + thinking-block parity vectors,
progressive/bounded relay paths (record passthrough, replay forward, tee read
deadline), a structured machine-readable refusal signal for item 2's refusals,
the §5 operator-runbook consolidation, the step-0b drift-verdict artifact, and
the step-0b manual `DS_CIA_PARITY=1` drift run itself — that last one remains a
deferred manual operator gate, never an agent-run step.

---

## 6. Open questions — maintainer resolutions (2026-06-12)

1. **Language ratification — RESOLVED: Go.** Ratified by the maintainers
   2026-06-12. The §1 counter-condition stands as the recorded revisit trigger:
   if this proxy ever sits on a customer session's egress path, it crosses into
   ds-tlsproxy's charter and the Rust verdict flips.
2. **Cassette format ownership — RESOLVED: byte-compatible adoption.**
   `ds-capture` adopts *cia's* `version:1` JSON byte-compatibly (existing
   captures replay); a first-party version bump only with cause. The build's
   on-disk parity tests pin this.
3. **Tolerant-matcher fidelity — build-task action (open).** Re-implementing
   `normalize_request` in Go must match cia's key derivation exactly. In flight
   as the shared-vector parity goldens plus the env-gated cross-tool drift
   check (wave-2 follow-up `01KTYS878F`) against the `01KTXEXQAZ` parity
   baseline.
4. **`inspect`/analytics scope — RESOLVED: out of charter.** The rich
   `cia report` does not ship in this tool; only the thin cassette-inspection
   slice (`ds-capture inspect`) folds in. Analytics, if wanted, are a separate
   post-MVP component with their own charter (tracked in taskdb).
5. **Canary build vs. migrate — RESOLVED: built first-party.** The canary is
   built first-party from the start (§5 step 3), never wired to `cia`.

## 7. Residual risks

- **Canon-divergence risk if the language pick were Rust** — the very risk §1
  avoids: a second implementation of `fidelity/canon.go` silently breaks the n=1
  fidelity guarantee. The Go pick neutralizes this; if Rust is ratified instead,
  this becomes the top residual risk and needs a shared-vector conformance gate.
- **Tolerant-matcher drift** — a Go matcher that keys even slightly differently
  from cia's `match_key` turns clean replays into misses; mitigated by the
  parity baseline (`01KTXEXQAZ`) and a shared-vector test, but it is the most
  likely subtle bug.
- **`:18080` collision regressions** — a pre-existing shared monitor daemon on
  the default port must never be touched; `ds-capture` defaulting to a free port and
  carrying no receiver sockets removes the DRIVE-FINDINGS §5 singleton blocker,
  but the G4 mount scan and a never-`:18080` assertion must stay until cia is
  fully retired.
- **D50 wall during migration** — every live capture is raw-class; the `scrub`
  subcommand and the `fixtures/` provenance gate must be in place *before* the
  first live `ds-capture record` runs, or a real cassette could leak toward git.
  The wall held under cia (auth stripped, no Bearer token, raw under `~/.cia`/
  `~/tmp`); `ds-capture scrub` must reproduce it exactly.
- **Live-tier coverage stays n=small** — `ds-capture` does not change that the
  live evidence is a handful of sessions; it makes capture first-party and
  repeatable, but the fidelity loop's "is synthetic faithful to real CC" worry is
  reduced, not eliminated, and the canary remains the only continuous drift
  sensor.
- **Scope of the drops** — dropping the hook/OTLP/fswatch receivers and the
  `cia report` analytics assumes no current consumer depends on them. Confirmed
  against e2e/fidelity/canary (none consume hook/otlp/file-change events); if a
  future observability need wants them, they return as the orchestrator's
  telemetry charter, not this tool's.
```
