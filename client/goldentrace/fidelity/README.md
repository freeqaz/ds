# client/goldentrace/fidelity/ — the cassette fidelity loop

**Owner:** Attach & client · **OSS** (D15/D25) · **Decisions:** D38, D49, D50 ·
**taskdb:** `01KTXBGTK6` ("Cassette fidelity loop") under
[`../../wrapper/DRIVE-PROTOCOL.md`](../../wrapper/DRIVE-PROTOCOL.md)
§"Determinism via record-replay". Feeds the nightly canary `01KTWJ25NG`.

## What this answers

The findings keep flagging one worry: **"are our hand-authored synthetic
cassettes actually faithful to real Claude Code?"** (the n=1 / circularity
problem — we only ever checked the adapter against fixtures we authored
ourselves). This package closes it. For each scenario:

```
live-capture raw CC stream  ──┐
                              ├─▶ adapter PROJECTION ─▶ id-relative CANON ─┐
re-authored synthetic cassette┘                                            ├─ EQUAL?
                                                                            ┘
```

The adapter's projection of the **re-authored synthetic** cassette must EQUAL
its projection of the **live** CC stream — **id-relative and structural**, never
byte-for-byte (CC mints fresh random `session_id`/`uuid`/`tool_use_id`/`task_id`
per run, instant replay collapses timing, and token/cost numbers vary run to
run — DRIVE-FINDINGS §5). A divergence is either a **stale cassette** or genuine
**CC drift**; CIA's API-plane capture distinguishes which (the stdout harness
alone cannot see the transport plane).

## The id-relative canonical form (`canon.go`)

`Canonicalize([]attach.Event)` reduces a projection to its structural
fingerprint:

- **Correlation ids → placeholders, kind-keyed:** `session_id`, `source[]`,
  `message_id`, `node_id`/`parent_node_id`/`returned_to`, `ask_id`, `task_id`,
  `agent_id`, `turn_group` each become `<kind#N>` in first-seen order **per
  kind**. The same concrete id maps to the same placeholder everywhere, so the
  **correlation graph** (the spawn/ask linkage the adapter's whole job is to get
  right) is what's compared — not the random ids CC minted.
- **Timing/cost → erased:** `observed_at`, `duration_ms`, `elapsed_ms`,
  `total_cost_usd` are dropped (not reproducible under replay — DRIVE-PROTOCOL.md
  "do not assert on TTFT/tok-s").
- **Volatile magnitudes → presence-only:** `usage`/`model_usage`/`usage_raw`/
  `suggestions`/`resets_at` reduce to `<present>` — the structural fact "an
  accounting trailer was emitted" is compared, not the run-varying numbers.
- **Kept (the structural set asserted):** event type and order, role, kind,
  tool/skill/server names, behavior, outcome, `is_error`, status, ask source,
  parent_confidence, the input/text payloads, and the full placeholdered
  correlation graph.

## Running it — BY COMMAND

```sh
# as a tool (operators + the canary):
cd client && go run ./goldentrace/fidelity/cmd/fidcheck
#   PASS/FAIL per scenario; exits non-zero on any divergence.

# as a test (CI; the same id-relative equality):
cd client && go test ./goldentrace/fidelity -run TestFidelityProjectionEquality
```

The committed scenario set (`runner.go` `fidScenarios`) is three re-authored
synthetic cassette **pairs** under `../../fixtures/`: each scenario has a
canonical `drive-fid-<s>.cc-wire.ndjson` and a `-live-equiv` twin authored with
**different** ids/timing/cost (the always-on stand-in for a CIA-ground-truthed
live capture). Because the twins carry different concrete ids, **byte-equal
projections are impossible** — a green run proves the equality is genuinely
structural, not a tautology (`TestFidelityLoopIsNonVacuous` guards this).

| scenario | pins | CC-wire surface |
|---|---|---|
| `chat` | a plain single-turn assistant text + quota + terminal | the bare read path |
| `native-ask` | the native control channel allow round-trip | `can_use_tool` control_request → `control_response{allow}` → `tool_result` (gap 2, the costliest blind spot) |
| `multiturn` | sustained two-turn driving in one CC process | a fresh `system/init` per driven input (DRIVE-FINDINGS §3) |

## Perturbation catch — the loop has teeth (`perturbation_test.go`)

`TestPerturbationCaughtAsReviewableDiff` proves a deliberate CC-shape
perturbation is **caught as a reviewable diff**, not silently tolerated (the
"Done when…" bar). It mutates the live-equiv leg IN MEMORY (never on disk — no
fixture/golden write, HARDENING-NOTES §2.3 / D50) across four drift classes and
asserts the id-relative equality now FAILS with a reviewable report:

| drift | models | result |
|---|---|---|
| `chat-text-drift` | assistant content changed | caught — chat.message text diverges |
| `result-outcome-drift` | terminal subtype `success`→`error_during_execution` (P13) | caught — session.accounted outcome diverges |
| `ask-behavior-drift` | control_response `allow`→`deny` (gap 2) | caught — ask.resolved behavior diverges |
| `dropped-tool-use-drift` | a frame type renamed → an event drops | caught — projection length diverges |

A `STALE-ANCHOR GUARD` makes a no-op mutation (anchor re-authored away) itself a
hard failure, so the test cannot become vacuous.

## The live tier (`fidelity_live_test.go`, `DS_E2E_LIVE`-gated)

`TestFidelityVsLiveCapture` is the live half: it asserts the synthetic cassette's
projection equals the projection of a **real** CC stdout capture taken under
`cia record` on a **private socket** (the step-0 cia `--runtime-dir` override —
see Live evidence). It is behind `DS_E2E_LIVE=1`, the single documented gate
(`../e2e/README.md`); unset — the default and every CI/`go test` run — it SKIPS
and launches nothing (`TestLiveGateClosedByDefault` asserts the gate is closed by
default). The operator points `DS_LIVE_RAW_<scenario>` at the raw CC-stdout
ndjson their armed run produced (raw-class, under `DS_LIVE_SCRATCH`, never
committed).

## Live evidence — 2026-06-12 (`01KTXBGTK6`)

The full loop was exercised **live** against real Claude Code `2.1.173`, proving
the capture path end to end (1 live session, ~$0.02 spend, under the `--model
sonnet`, ≤$5/session, ≤4-session rails):

- **CIA coexistence proven against the live protected monitor.** A `cia record`
  daemon was started on a **free port `:18099`** with a **private control
  socket** (`--runtime-dir`, the step-0 cia override on branch
  `cia-record-replay-coexist`; hook/otlp receivers auto-disabled so they don't
  collide with the protected monitor's). It coexisted with the **protected
  `:18080` monitor** — the protected socket inode was **unchanged**
  and `:18080` stayed owned by the protected daemon throughout; the recorder
  exited cleanly on SIGINT without ever binding, stopping, or touching `:18080`
  or `~/.cia/cia.sock`.
- **Real capture path.** A real containerized `claude 2.1.173` (the proven
  `live_drive.go` recipe: rootless podman, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges`, `--network=pasta:-T,18099`,
  `NODE_USE_ENV_PROXY=1`, the host claude mounted ro, the OAuth token by env
  only) drove the `baseline` scenario; egress went **through the `:18099`
  recorder**, producing **20 lines of raw stdout** AND a **69 KB API cassette**
  (the `/v1/messages` SSE ground truth).
- **D50 wall held.** The API cassette carries **no** Bearer token (cia strips
  auth — only `content-type` is kept; no `sk-ant-oat01-…` value anywhere); the
  raw stdout + API cassette are raw-class and stay under
  `~/tmp/ds-keystone/cap/live-fid/` and `~/.cia` — **never committed**. The
  committed fixtures are clean re-authored synthetic only.
- **The loop ran against REAL CC and CAUGHT a divergence.** Projecting the live
  raw stdout (8 events) and id-relative-comparing to the `drive-fid-chat`
  synthetic (6 events) **diverged** — the live model emitted a thinking block, a
  memory-check tool call, and a greeting instead of the single "PONG", a textbook
  **model-nondeterminism / scenario drift** the loop flags and CIA's API cassette
  confirms is model behavior (not adapter drift). This is the n=1 worry made
  visible and reviewable — exactly what the loop exists to surface.

The `capture.sh` harness is wired for this: `CIA_RECORD=1 CIA_PROXY_PORT=18099
./capture.sh <scenario>` runs the claude invocation under `cia record
--runtime-dir <job>/cia-rt` (private socket) + `cia run --proxy-port 18099`,
refusing any protected/known proxy port (`18080`/`8080`) and writing the API
cassette to the raw-class job dir.

## Files

- `canon.go` — the id-relative, timing-erased canonical form.
- `fidelity.go` — `ProjectStream`/`EqualProjections`/`EqualFiles` (the equality
  engine + reviewable diff).
- `runner.go` — `DefaultPairs`/`RunEquality` (the by-command runner) + the
  canonical `fidScenarios` set.
- `cmd/fidcheck/` — the `go run`-able command.
- `fidelity_test.go` — the always-on equality loop + non-vacuity + self-equal.
- `perturbation_test.go` — the in-memory perturbation-catch (teeth).
- `fidelity_live_test.go` — the `DS_E2E_LIVE`-gated live-vs-synthetic half.

## Cross-references

- Determinism design: [`../../wrapper/DRIVE-PROTOCOL.md`](../../wrapper/DRIVE-PROTOCOL.md) §"Determinism via record-replay".
- Live capture findings: [`../../wrapper/DRIVE-FINDINGS.md`](../../wrapper/DRIVE-FINDINGS.md) §5.
- Capture hardening (D50 wall): [`../HARDENING-NOTES.md`](../HARDENING-NOTES.md).
- Fixture provenance: [`../../fixtures/PROVENANCE.md`](../../fixtures/PROVENANCE.md) (D50).
- CIA record/replay + the coexistence override: `../../../../cia/docs/record-replay.md`, branch `cia-record-replay-coexist`.
- The projection it reuses: [`../replay/replay.go`](../replay/replay.go) (the claude-code adapter — the one place a runtime is named).
