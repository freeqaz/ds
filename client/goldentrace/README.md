# client/goldentrace/ — protocol observability harness for the CC wire side

**Owner:** Attach & client · **OSS** (D15/D25) · **Decision:** D49

The observability layer that makes the *unstable* CC wire side of the D38 seam
legible — and safe to build the adapter on. The Claude Code wire format is
deliberately not a proto (doc 06 §2.2); goldentrace makes it inspectable by
pinning it to golden traces, so adapter authors build against an observed,
versioned contract instead of a moving target.

1. **Capture:** scripted Claude Code sessions → scrubbed NDJSON cassettes
   (stored in `../fixtures/`, synthetic-only per D50). These traces are the
   observable record of the protocol — per-subagent token accounting, timing,
   and spawn-tree visibility that CC does not surface to operators.
2. **Refresh:** insta-style diff review — a protocol change shows up as a
   cassette diff a human approves, never as a silent fixture rewrite.
3. **Canary:** a **nightly run against CC-latest** detects upstream drift on
   schedule. The golden image pins the production CC version (D49, see
   `../wrapper/adapters/claude-code/README.md`), so a red canary is a queued
   review task, not a production incident. The canary lane is **landed**
   (`canary/`): `RunOffline` runs the always-on, hermetic half (a
   detection-machinery pre-flight then an offline regen of every committed
   cassette → `OutcomeFaithful` / `OutcomeDriftDetected`, never a vacuous pass —
   `OutcomeMachineryBlind` is a DISTINCT outcome from `OutcomeDriftDetected`), and
   `DriftAgainstLatest` (`live.go`, `DS_E2E_LIVE`-gated) is the deferred operator
   runbook that diffs a CC-latest capture against the committed canon goldens. The
   `cmd/canary` command and the `.github/workflows/goldentrace-canary.yml` nightly
   workflow drive it.

The harness investment survives the move to our own agent loop; the CC
fixtures need not (D49 rationale). Adapter conformance tests for any new
runtime reuse this harness against that runtime's own cassette set.

**Running real CC against the gateway (operator runbook).** The hand-driven
fidelity-validation step that pairs this triad with a live capture — drive a real
Claude Code through the thin-client stack and the first-party `ds-capture` egress
gateway (`serpent claude`, one command) — is
[`../hostbridge/LIVE-VALIDATION.md`](../hostbridge/LIVE-VALIDATION.md).

**Capture-tool status — the CIA dependency is interim.** The live drive tiers
(`e2e/`, the deferred manual live step) instrument CC through the external CIA
monitor (`github.com/ahhh/cia`, Python on mitmproxy, checked out beside this
repo): TLS-terminating interception of `/v1/messages`, record/replay
cassettes, hook/OTLP receivers. By the language split in
[`../wrapper/DRIVE-PROTOCOL.md`](../wrapper/DRIVE-PROTOCOL.md) §Language &
performance, scripting may *discover* the protocol but only compiled Go/Rust
*carries* it: the tracked goal is a **first-party Rust-or-Go capture &
instrumentation tool** that replaces CIA and unifies this harness's ideas —
capture, scrub (D50), replay, and the nightly canary (D49) as one tool's
subcommands. Taskdb: `01KTXKJBER` (design spike) → `01KTXKJNJ8` (record/replay
core) → `01KTXKJYYW` (consumer migration + retirement).

Skeleton note: the replay harness (`replay/`) and its golden tests now exist —
they drive the synthetic `../fixtures/*.cc-wire.ndjson` cassettes through the
Claude Code adapter against pinned goldens under `replay/testdata/` (`-update`
refreshes them). `capture.sh` is pre-existing; the nightly canary (`canary/`)
is **landed** — its always-on lane runs a detection-machinery pre-flight before
trusting any verdict (`RunPreflight`: the in-process neutered-detector probe plus
the owned perturbation self-tests), then regenerates every committed cassette by
command and diffs it against the canon goldens under `canary/testdata/`. The
live CC-latest leg (`DriftAgainstLatest`) is the `DS_E2E_LIVE`-gated deferred
operator step the always-on lane never runs.

## The replay suite — run, regenerate, determinism, drift self-test

The `replay/` package is the conformance/regression layer of the triad above
(Capture → **Replay** → Canary). It replays the synthetic
`../fixtures/*.cc-wire.ndjson` cassettes (<!-- CASSETTE-COUNT -->20<!-- /CASSETTE-COUNT -->
at this revision — the canonical count is whatever `ls ../fixtures/*.cc-wire.ndjson`
reports, since `TestGoldens` discovers them off disk rather than from a hard-coded
list; the count marker is machine-checked against disk by
`replay/readme_counts_test.go`) through the Claude Code adapter and compares the
`attach.v1` projection against committed goldens under `replay/testdata/`. The
cassette names below are enumerated between invisible HTML-comment markers (the
CASSETTE-COUNT idiom) so the list cannot drift from `../fixtures/` unnoticed:
`replay/readme_counts_test.go` extracts every name in the marked region and
asserts set-equality with the `../fixtures/*.cc-wire.ndjson` base names, so a
fixture added without naming it here — or a name here with no fixture on disk —
fails by name. The set
<!-- CASSETTE-NAMES -->
spans the read-path cassettes (`ask-control`, `baseline-chat`, `denial-headless`,
`depth3-nested-spawn`, `mcp-skill-native`, `nested-spawn`, `parallel-fanout`,
`partial-stream`, `subagent-spawn`, `task-todo-no-subagent`, `terminal-budget`) and the
drive-direction family added with the driver and fidelity work
(the `drive-*` cassettes: `drive-multiturn`, `drive-native-allow`,
`drive-native-deny`, and the three `drive-fid-*` fidelity pairs, each a synthetic
base alongside its `-live-equiv` twin: `drive-fid-chat` / `drive-fid-chat-live-equiv`,
`drive-fid-multiturn` / `drive-fid-multiturn-live-equiv`, and
`drive-fid-native-ask` / `drive-fid-native-ask-live-equiv`).
<!-- /CASSETTE-NAMES -->
The `task-todo-no-subagent` cassette is the spawn
**negative control**: an assistant `Task` tool_use (a name in the spawn allowlist)
WITHOUT `input.subagent_type`, which `classify.go` documents as the todo-list
tool, not a spawn — so it projects as plain chat/tool flow with ZERO
`subagent.spawned` and is the read-side proof that `claudecode.IsSpawnToolUse`'s
`subagent_type` gate is the sole thing keeping an allowlisted name out of the
spawn set (`replay/spawn_test.go`, `TestTaskTodoNoSubagentIsNotASpawn`). No live
Claude Code, container, or network is involved — fixtures in, goldens out.

### Running it

```sh
cd client && go test ./goldentrace/...
```

Three layers run, all off the same `Replay()` entry point (one harness, not
forked):

- **`TestGoldens`** — replays every cassette and byte-compares the projection to
  its `testdata/*.attach.ndjson` golden. `validateEvents` additionally asserts the
  envelope invariants for any stream: `seq` strictly monotonic from 1 (emission
  order, P10), a single constant `session_id`, and exactly one payload pointer
  non-nil per event.
- **`TestSpawnPathProjections`** (`spawn_test.go`) — explicit spawn-tree
  assertions over `subagent-spawn` / `nested-spawn` / `parallel-fanout`, because
  the wrapper "slips into the middle" of subagent/workflow calls (D18) and spawn
  projection is first-class, not just chat deltas (doc 06 §2.2). Beyond the
  generic byte-compare it asserts, by name: the `subagent.spawned` events are
  present, `parent_node_id` linkage is correct (inner nested under outer; the
  fan-out siblings rooted), `parent_confidence` is `exact` at depth ≤2, the
  fan-out siblings share one `turn_group`, every spawned node id-correlates to its
  `subagent.completed` / `subagent.accounted` (and `returned_to` points back at
  the parent), and each node's spawn happens-before its terminals. The
  `depth3-nested-spawn` cassette drives the deeper branch the depth-2
  `nested-spawn` fixture cannot reach: a root → outer → middle → grand chain whose
  grandchild crosses the depth-≥3 threshold, so the adapter's `depthOf(n) >= 3`
  rule (`../wrapper/adapters/claude-code/tree.go`, OBSERVABILITY-DESIGN §2)
  downgrades its `parent_confidence` to `inferred` while the depth-≤2 ancestors
  stay `exact` — the test pins that confidence ladder by name and chains the
  `returned_to` back-edges grand → middle → outer → root. The legacy
  `subagent-spawn` cassette is the missed-`task_*`-lifecycle case: it asserts
  **zero** `subagent.spawned` and an accounting-only projection (OBSERVABILITY §2).
- **`TestPerturbationDriftIsCaught`** (`perturbation_test.go`) — the drift
  self-test, below.

The spawn-path assertions have a **write-side mirror** that lives with the driver,
not here: `../wrapper/adapters/claude-code/driver_roundtrip_test.go` pins the
golden wire bytes the `Driver` *emits* to drive the same spawn-adjacent flows
(`nested-spawn` / `parallel-fanout` driving prompts, the `ask-control`
allow/deny grants keyed on the same `creq_synthetic_0301`/`0302` request_ids this
suite decodes) and round-trips them back through `records.go`'s decode structs for
projection stability — the inverse of `TestSpawnPathProjections`, per
[`../wrapper/DRIVE-PROTOCOL.md`](../wrapper/DRIVE-PROTOCOL.md) ("the driver is the
mirror of the adapter"). It reuses the same id-relative discipline (no CC-minted
ids, no wall-clock) and stays off any live runtime.

The two sides used to enumerate their spawn scenarios **independently**, so a
spawn cassette added to `../fixtures/` could be covered on one side and silently
missed on the other. A **fixture-derived shared spawn-scenario table** now closes
that drift. The read-side canonical copy is `replay/spawn_scenarios.go`
(`SpawnScenarios` + the exported `DiscoverSpawnFixtures`); the write side mirrors
the same fixture set in `../wrapper/adapters/claude-code/spawn_scenarios_test.go`
(per-package, not a shared import — `claudecode` cannot import `replay` without an
import cycle, since goldentrace already imports the adapter). The two copies are
kept honest **not by an import but by a completeness check on each side**:
`TestSpawnScenarioTableComplete` (read) and `TestSpawnScenarioTableMirrorsDisk`
(write) re-glob `../fixtures/*.cc-wire.ndjson`, classify each cassette as
spawn-path by the **same content discriminator the adapter routes on** (an
assistant `tool_use` block whose name ∈ `{Agent, Task, TaskCreate}` —
`classify.go`'s `spawnToolNames` — carrying `input.subagent_type`), and fail **by
name** when a discovered spawn fixture is missing from that side's table (or a
table row no longer backs a fixture on disk). `depth3-nested-spawn` is pinned on
both sides as the acceptance case. Adding a spawn fixture without covering both
sides — or deleting a scenario from one side — now trips a test rather than
drifting silently.

One seam of that guard is itself still duplicated rather than shared (verified
on integration; tracked follow-up, not silent debt): the content discriminator
is **re-implemented** on each side, not imported — the structural walk
(assistant record → `content[]` → `type=="tool_use"` ∧ name ∈ set ∧
`input.subagent_type` non-empty) appears in `classify.go` (the adapter's
canonical routing), `replay/spawn_scenarios.go`, and
`spawn_scenarios_test.go`, and only the write side's name *set* is link-checked
against `spawnToolNames`. A future change to the adapter's spawn-routing signal
would leave the completeness checks classifying on a stale copy with no test
failing. Single-sourcing the classifier through one exported `classify.go`
helper is taskdb `01KTXXFS97NMZ8V9VH2Y78QQ02`, serialized behind the
literal-derivation reconciliation (`01KTXXFS8VAZKEC4X5YSPNMFGS`, blocked on a
merge conflict with this table's landing — the two must be rebuilt as one
branch on top of the integrated content).

### Regenerating goldens (`-update`, review-the-diff flow)

Goldens are derived artifacts; never hand-edit them. When an *intended* adapter
or fixture change moves a projection, regenerate and review the diff like code:

```sh
cd client && go test ./goldentrace/replay -run TestGoldens -update
git diff client/goldentrace/replay/testdata/   # review every line before committing
```

A missing golden fails `TestGoldens` with the exact `-update` command to run. The
review step is the point: a protocol change surfaces as a reviewable golden diff a
human approves (insta-style), never a silent rewrite. Goldens live under
`replay/testdata/`, **not** under `../fixtures/` — `testdata/` is excluded from the
D50 provenance gate that scans `fixtures/`, so derived artifacts never need a
provenance header while fixtures always do.

### Why replay is byte-deterministic

Two runs of the suite produce identical bytes — zero golden churn — because the
only sources of nondeterminism are pinned or relativized (DRIVE-PROTOCOL.md
"assert structurally / id-relative, never literal"):

- **Pinned adapter clock.** `Replay()` injects `WithClock` returning
  `2026-01-01T00:00:00Z` plus one second per call, so `observed_at` and any
  adapter-clock duration are a pure function of emission order, not wall time.
- **Id-relative, not literal.** The synthetic cassettes use fixed, structural ids
  (`toolu_SYNTHETIC…`, zero-padded session/uuid values); correlation in the spawn
  assertions is by the within-run id triple (`node_id` / `task_id` / `agent_id`)
  and happens-before on `seq`, never literal wall-clock order — the same rule the
  live replay tier will need when real CC mints fresh v4 uuids per run.
- **Deterministic serialization.** `WriteNDJSON` emits one event per line via
  `encoding/json` with the adapter's `omitempty` field set, so the byte form is
  stable for a given projection.

Timing-derived metrics (TTFT, tok/s) are deliberately **not** asserted — they are
not reproducible and the projection does not surface them as truth.

### The perturbation drift self-test

`TestPerturbationDriftIsCaught` is the executable form of the doc 06 §5 / D49
early-warning promise: "when Anthropic changes the format, a golden-trace test
breaks before customers do." A green golden suite alone cannot distinguish "the
format is stable" from "the harness stopped looking," so this test *proves the
suite still bites*. For each perturbation it:

1. reads a real committed cassette,
2. applies a deliberate CC-output-format mutation **in memory** (a transparent
   `bytes.ReplaceAll` of an anchored substring — no opaque mutation closures), and
3. replays **both the pristine and the mutated stream** through a fresh,
   clock-pinned claude-code adapter and asserts the mutation **bites**.

It replays pristine-vs-mutant in memory through the public adapter API
(`New`/`WithClock`/`ProcessStream`/`Warnings`) rather than diffing against the
committed golden on disk, so `replay.go` stays frozen and the row does not depend
on goldens being regenerated. A mutation bites if any of three branches fires,
tried in order: **Branch A — parse-error-as-drift** (the mutant raises a stream
error the pristine did not), **Branch B — projection-divergence** (the mutant's
`attach.v1` NDJSON differs from the pristine's, logged as a readable first-diff
line), or **Branch C — warning-as-drift** (the projection is byte-identical but
the adapter raised an integrity/correlation warning it did not raise on the
pristine — the branch the accounting-trailer and control-correlation classes lean
on). By default any one branch passes the row, and the loop logs **per-row branch
accounting** naming which of A/B/C caught it.

**Branch C now has primary realizations on both unproven-live surfaces.** Every
one of the eight visible / control-channel / accounting-trailer rows above
resolves on Branch B (projection divergence) *before* the warning branch is
reached, so until a row's *first and sole* detector is Branch C, a regression
that silenced adapter `Warnings` while leaving the projection byte-identical
would not turn the self-test red — Branch C was implemented and correctness-tested
but never primary. Two rows close that gap, one per unproven-live surface, each
with its `wantBranch` field **pinned to Branch C** so the loop asserts the earlier
branches did *not* fire (no parse error; projection asserted byte-identical, not
left incidental) and the warning branch *did*:

- `control-response-warning-only` pins it on the **control channel** — an
  injected `behavior` ask-resolution discriminator on the `drive-native-allow`
  initialize `control_response` raises the unknown-`request_id` warning with no
  event emitted.
- `accounting-corroboration-warning-only` pins it on the **accounting trailer** —
  repointing the `subagent-spawn` spawn-line `parent_tool_use_id` on that
  accounting-only (task_started-less) node trips the parent-corroboration
  integrity warning while the projection stays byte-identical (no
  `subagent.spawned` is emitted for that node, so the mutated parent reaches no
  projected field, and `returned_to` stays omitted).

So a future change that silences a `Warnings` path without moving the projection
fails these rows loudly — the exact "warnings silenced without a projection
change" regression a Branch-B row structurally cannot catch, now covered on both
DRIVE-PROTOCOL.md gap-2 (control channel) and gap-3 (accounting trailer)
surfaces. The remaining (`branchAny`) rows keep the historical
first-branch-wins behavior unchanged.

**Drift-class coverage — one drift-class superset suite.** The two prior
realizations of this self-test (the visible chat-delta / spawn-discriminator
classes, and the high-value control-channel / accounting-trailer classes) are
unified into one table here, a strict superset of both. It now carries
<!-- DRIFT-CLASS-COUNT -->10<!-- /DRIFT-CLASS-COUNT --> classes across four groups
(the count marker is machine-checked against `len(perturbations)` by
`replay/readme_counts_test.go`): the **visible** classes
(`assistant-content-type-renamed`, `chat-text-corruption`,
`task_started-subtype-renamed`, `tool-result-id-corruption`) that establish the
suite bites at all; the **control channel** classes
(`control-discriminator-mutation`, `control-correlation-corruption`) over the
`control_request{can_use_tool}` / `control_response` surface; the
**accounting trailer** classes (`accounting-trailer-agentid-mutation`,
`accounting-returned-to-mutation`) over the per-subagent `agentId` / `returned_to`
result trailer; and the **warning-only** classes — two `wantBranch: branchC`
rows, one per unproven-live surface. The first, `control-response-warning-only`,
injects a `behavior` ask-resolution discriminator into the `drive-native-allow`
initialize `control_response` — the adapter reads it as a resolution against a
`request_id` that opened no ask (P8), raises the unknown-`request_id` warning, and
emits **no event**, so the projection stays byte-identical and Branch C is the
*first and sole* detector. The second, `accounting-corroboration-warning-only`,
repoints the `subagent-spawn` cassette's spawn-line `parent_tool_use_id` on its
accounting-only (task_started-less) node: the result's return-target
corroboration disagrees with the spawn-line parent and the parent-corroboration
integrity warning fires, while the projection stays byte-identical — that node
emits no `subagent.spawned` (so the mutated parent has no projected sink) and
`returned_to` stays omitted, so Branch C is again the *first and sole* detector
(their dedicated role, above). The control-channel and accounting-trailer
surfaces are DRIVE-PROTOCOL.md's gaps 2 & 3 — binary-extracted-only, never proven
live — so a silent adapter regression there is the costliest one to miss; each
row documents inline the CC format change it would catch.

It is **inert in normal runs**: it passes precisely *because* the harness still
notices drift, touches no file under `fixtures/` (so no D50 provenance header is
needed) and rewrites no golden. It goes **red** in exactly three cases, all real
regressions worth a hard failure: the mutation no longer changes the cassette
bytes (a **stale anchor** — a cassette was re-authored out from under the row, so
the self-test can no longer simulate that drift and must never silently no-op);
the mutation bit the cassette bytes but left the projection **and** the warning
set identical (a **blind spot** — the adapter now silently tolerates the change
and the early-warning system has gone blind to that class); or a **`wantBranch`-
pinned row resolves on the wrong branch** (e.g. either warning-only row —
`control-response-warning-only` or `accounting-corroboration-warning-only` —
starts moving the projection, or its warning stops firing — the pin fails loud
rather than silently resolving earlier). A discovered blind
spot is reported up, never patched in the adapter from this owned test file. This
is distinct from the **landed** nightly canary (`canary/`, D49): the canary's
live `DriftAgainstLatest` leg catches *new, unseen* CC drift against CC-latest,
while this self-test guarantees the detection machinery itself has not regressed —
and the two are wired together, because the canary's always-on `RunOffline` runs
this perturbation self-test as its pre-flight (`RunPreflight`) before trusting any
drift verdict: a regressed self-test makes the canary abort with the DISTINCT
`OutcomeMachineryBlind`, never report a vacuous "no drift."
