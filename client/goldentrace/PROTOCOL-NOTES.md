# Claude Code subagent protocol — capture notes (D49 spike)

**Owner:** Attach & client · **Decisions:** D18, D20, D38, D49 · **Status:** spike findings (Phase 1 + Phase-2 corrections)
**Captured against:** Claude Code `2.1.173` (the version this adapter targets is pinned in the golden image, D49)
**Captured:** 2026-06-11

> **Round 2 is in [`PHASE2-FINDINGS.md`](PHASE2-FINDINGS.md)** (parallel fan-out, nested
> subagents, the stream-json input side, denial framing, and the egress-gateway proxy/pin verdict).
> This doc has been corrected inline where Phase 2 refuted a first-pass claim — the three big
> ones: subagent internals are **not** fully opaque (sub-spawns + `task_*` lifecycle surface);
> `parent_tool_use_id` is **not** the sole spine (it is `null` on results/`task_*` and flattens
> to depth 1 — correlate by ids); and concurrent sessions on one workstation run under the same
> uid, so the daemon namespace is shared (see Layer 2).

> **Round 3 is in [`PHASE3-FINDINGS.md`](PHASE3-FINDINGS.md)** (the live ask/approval record, the
> session-state vocabulary + CC→§3 mapping, MCP/Skill/native tool classification, the
> `result.subtype` closed set, the partial-message assembly contract, and the ordering verdict).
> The message-type table, the open-questions list, and the sequence-synthesis note below are
> corrected inline for round 3; the new tool-classification and partial-message assembly rules are
> added as the Phase-3 subsection ("Tool classification & partial-message assembly").

> Reproduce with [`capture.sh`](capture.sh). Raw captures contain real local paths,
> session UUIDs, costs and agent ids — they live in the job tmp dir and are **never**
> committed; only re-authored synthetic cassettes land in [`../fixtures/`](../fixtures/)
> (D50, see [`PROVENANCE.md`](../fixtures/PROVENANCE.md)).

## TL;DR — there are two different "subagent" mechanisms

Claude Code exposes two distinct things that both look like "talking to a subagent",
and the project touches both:

| | **Layer 1 — in-process subagents** | **Layer 2 — background/dispatched agents** |
|---|---|---|
| What | The `Task`/`Agent` tool the model calls mid-turn | `claude agents` — a supervisor daemon + worker processes |
| Process model | **In-process.** No subprocess, no IPC — the subagent loop runs inside the same `claude` node process and hits the Anthropic API directly | **Multi-process.** A long-lived supervisor spawns pre-warmed worker processes; each session is its own OS process |
| Wire format | NDJSON on the parent's `--output-format stream-json` stdout | Per-session **unix-domain sockets** (control + PTY), capability-token gated |
| What's observable | The **spawn event**, the `system/task_*` **lifecycle**, any **nested `Agent` sub-spawn**, and the **final result** — but a leaf subagent's own model turns and ordinary tool calls (e.g. Bash) stay opaque (Phase 2 / P2) | The full session, as a PTY byte stream + a control channel |
| Maps to | D18/D38 — what the **wrapper** parses; the spawn event is the fan-out interception point | D38 attach + the VM-isolation seam — there is already an `isolation` knob |

The single most load-bearing finding: **a `Task` subagent is not a subprocess.** You
cannot tap an OS-level channel to watch it, because there isn't one. To "fan a subagent
out into its own VM" (D18) the orchestrator must **intercept the `Agent` tool-use spawn
event and re-host the subagent itself**, not observe an existing subprocess protocol.

---

## Layer 1 — the stream-json session protocol (what the wrapper parses)

### Capture flags

```
claude -p "<prompt>" \
  --output-format stream-json --verbose \   # NDJSON; --verbose required with -p
  --include-partial-messages \              # token-level stream_event deltas (optional)
  --include-hook-events \                   # hook lifecycle (optional)
  --tools "Task" \                          # restrict toolset; gates which tools the model sees
  --agents '{"name":{...}}' \               # define ad-hoc subagents
  --permission-mode bypassPermissions \     # headless: don't block on approval prompts
  --max-budget-usd 0.60                      # cost guard (matches capture.sh BUDGET default)
```

Output is newline-delimited JSON, one object per line.

### Message envelope

Every record carries `type`, `uuid`, and `session_id`. Top-level message types seen:

| `type` (`subtype`) | Meaning |
|---|---|
| `system` / `init` | First line. Full session config — see below. The wrapper reads this on attach. |
| `system` / `status` | Per-model-round-trip pings (`{session_id, status, subtype, uuid}`; `subtype` always `"status"`). In Layer-1 print mode `.status` carries **only `requesting`** — one ping per API round-trip; `busy`/`idle`/`working`/`compacting` were never observed across 23 pings (P9), likely TUI/Layer-2-only. It is a "request in flight" signal, **not** a state enum. |
| `system` / `thinking_tokens` | Live extended-thinking token estimate (`estimated_tokens`, `…_delta`). High-frequency; ignore for the event model. |
| `system` / `task_started` | Emitted at each spawn (P1,P2). Keys **diverge by `task_type`** (`local_agent` adds `prompt`+`subagent_type`; `local_bash` omits them — `task_type ∈ {local_agent, local_bash}`, P9). Common: `task_id, tool_use_id, …`. `parent_tool_use_id` **null** — correlate via `tool_use_id` + `task_id`. |
| `system` / `task_progress` | Subagent/task liveness (P2). Keys incl. `last_tool_name, subagent_type, task_id, tool_use_id, usage`; carries **no `.status`** field (P9). |
| `system` / `task_notification` | Subagent/task completion (P1,P2). Keys: `output_file, status, summary, task_id, tool_use_id, usage`. `.status` observed **`completed` only** (24 obs); failure/abort variants unobserved (P9). |
| `rate_limit_event` | `rate_limit_info: {rateLimitType, status, resetsAt, isUsingOverage, overageStatus, overageDisabledReason}`. |
| `assistant` | A model turn. `message` is a verbatim Anthropic API message object; plus `parent_tool_use_id`, `request_id`. |
| `user` | A tool result **or** a nested subagent prompt. `message.content` holds `tool_result` (or `text`) blocks; plus `parent_tool_use_id`. |
| `result` / `success`\|… | Terminal record. Cost + usage + accounting (see below). |
| `stream_event` | Present only with `--include-partial-messages`: raw Anthropic streaming events (`message_start`, `content_block_start/delta/stop`, `message_delta/stop`). Carries `parent_tool_use_id`. **Render channel only** — the non-partial records are authoritative; subagent token deltas do **not** stream to parent stdout (P10/P11). Assembly rule: see the Phase-3 subsection. |

`parent_tool_use_id` attributes a *prompt-side* message to its subagent: `null`/absent = the
root session; set = the message belongs to the subagent spawned by that `tool_use` id.
**It is not a complete spine** (Phase 2): it is `null` on `tool_result` (results) and on every
`system/task_*` event, and it **flattens nesting to depth 1** (a grandchild's events are tagged
with the *child's* launching id, not the grandchild's). Correlate by the id triple
`(tool_use_id, task_id/agentId, message.id)`, never by stream position or `parent_tool_use_id`
alone. See [`PHASE2-FINDINGS.md`](PHASE2-FINDINGS.md) §3.

### The `init` record (session config the wrapper consumes on attach)

Fields observed:

```
type, subtype="init", session_id, uuid, cwd, claude_code_version,
model, permissionMode, apiKeySource, output_style, fast_mode_state,
tools[]        # the enabled built-in toolset, post --tools filtering
agents[]       # advertised subagent types, e.g. ["claude","Explore","general-purpose","Plan",...] + any --agents
slash_commands[], skills[], plugins[], mcp_servers[],
memory_paths{auto}, analytics_disabled, product_feedback_disabled
```

This is the attach-time snapshot the `dreamserpent.attach.v1` init/state event maps from.

### The subagent sub-protocol (the important part)

Spawn → nested prompt → result, all interleaved on the one stream and tied together by id:

1. **Spawn.** An `assistant` message emits a `tool_use` block:
   ```json
   {"type":"tool_use","id":"toolu_…","name":"Agent",
    "input":{"description":"…","subagent_type":"echoer","prompt":"…"}}
   ```
   - **Name mapping gotcha:** the tool is `Task` in the stream/`init.tools` and in `--tools`,
     but the *model* sees it as **`Agent`**, so the emitted `tool_use.name` is **`Agent`**.
     Parse on `name ∈ {Task, Agent}`. (`subagent_type` selects the agent from `init.agents`.)
   - The `Task*` family — `TaskCreate/Get/List/Update/Stop/Output` — is the **todo-list**
     tool set, unrelated to subagent spawning. Don't conflate them. (Weaker models, e.g.
     haiku, sometimes grab `TaskCreate` when asked to "launch a task"; Sonnet spawns reliably.)

2. **Nested prompt.** A `user` message appears with `parent_tool_use_id` = the spawn's
   `tool_use.id`, content `[{type:text, text:"<the prompt sent into the subagent>"}]`. The
   prompt is what the *parent model* sent, not the configured agent's system prompt (P1).

3. **Result.** A `user` message carries a `tool_result` for the spawn id. **Its top-level
   `parent_tool_use_id` is `null`** — correlate to the spawn via `content[].tool_use_id`
   (asymmetric with the nested prompt, which *does* carry `parent_tool_use_id`). On parallel
   fan-out, results arrive in **completion order (fastest first), not spawn order** (P1), so
   match by id, not position.
   Its `content` is **two** text blocks:
   - the subagent's actual output (e.g. `"ACORN"`), then
   - a **metadata trailer**:
     ```
     agentId: <hex> (use SendMessage with to: '<hex>' to continue this agent)
     <usage>subagent_tokens: 3467
     tool_uses: 0
     duration_ms: 2227</usage>
     ```
     → every subagent is **addressable** (`agentId`) and advertises a **continuation**
     path; and per-subagent **accounting** (`subagent_tokens`, `tool_uses`, `duration_ms`)
     is inlined here. These two blocks are the richest per-subagent signal on the stream.

**Subagent internals are *mostly* opaque — with one important exception (refined in Phase 2).**
A subagent's own model turns and **ordinary tool calls (Bash, Read, …) do not surface** (verified
in Phase 1: an internal Bash produced no nested `assistant`/`tool_use`/`tool_result` and no token
`stream_event`s). **But a subagent's act of spawning a *further* subagent does surface**: the
nested `Agent` `tool_use` appears as an `assistant` message tagged `parent_tool_use_id` = the
*launching* subagent's id, and the whole spawn tree is also reported out-of-band by the root-level
`system/task_started|task_progress|task_notification` events (P2). So the parent stream gives the
full **subagent spawn tree** (via `task_*` + `Agent` blocks) but not subagents' inner work —
enough to *route* fan-out (D18) but not to *mirror* a subagent's screen. For the wrapper, the
`system/task_*` events are the cleaner, depth-independent spawn-tree signal (each carries
`tool_use_id` + `task_id` + `subagent_type`); `task_progress.last_tool_name` even gives coarse
liveness.

**Continuation (`SendMessage`) is gated.** The trailer advertises
`SendMessage(to: <agentId>)`, but `SendMessage` is **not** exposable via `--tools` in
headless `-p` (passing `--tools "Task,SendMessage"` still yields `init.tools == ["Task"]`).
Multi-turn subagent continuation is an interactive/`--brief`-context capability; plain
headless runs are single-shot per subagent. Flagged as an open item below.

### Tool classification, the ask event, & partial-message assembly (round 3)

Three round-3 rules the adapter depends on (full evidence in [`PHASE3-FINDINGS.md`](PHASE3-FINDINGS.md)):

**Tool classification — by `name`+`input`, never by block keys (P14).** `init` carries two
**disjoint** registries: `init.tools[]` (callable tool names, native + `mcp__*`) and `init.agents[]`
(subagent *types*). The `tool_use` block key set is **identical** across MCP/Agent/Skill/native
(`{type, id, name, input, caller}`, `caller=={type:"direct"}`), so discriminate on `name`:
- `^mcp__<server>__<tool>` ⇒ **MCP tool** — split on `__` (double underscore) into ≥3 parts (server
  = config key with `.`/space → `_`; tool names contain single underscores, so a single-`_` split
  is wrong). `input` is the tool's own schema.
- `name ∈ {Agent, Task, TaskCreate}` ⇒ **subagent spawn** — discriminator is `input.subagent_type`
  (a value in `init.agents[]`). Sonnet emits `Agent`; haiku misfires `Task`→`TaskCreate`.
- `name == "Skill"` ⇒ **skill** — `input.skill` is a value in `init.skills[]` (not a slash-command
  record, not `mcp__`, not an `Agent`).
- otherwise native.

A namespaced MCP tool therefore can never be mistaken for an `Agent` spawn. Two riders: a freshly
wired MCP tool may be preceded by a `ToolSearch` `tool_use` whose `tool_result` carries a new
subtype **`tool_reference` `{tool_name}`** (tolerate it); and a needs-auth server's
`*__authenticate`/`*__complete_authentication` tools are injected into `init.tools[]` regardless of
`--tools`/`--allowedTools` — surface them gated, never auto-invoke.

**The ask/approval event is NOT on headless `-p` stdout (P8).** With no permission responder
registered, the engine resolves every decision internally (auto-allow, or an `is_error:true`
`tool_result` whose content is a **bare string**); a bare stream-json control channel does **not**
emit a `can_use_tool` `control_request` (structural negative). The live ask is sourced two ways
only: register an SDK `canUseTool` responder on the stream-json control channel (the native
`control_request{subtype:"can_use_tool", …}` shape, which alone carries the richer
`permission_suggestions[]`/`agent_id`/`decision_reason*`), **or** register a
`--permission-prompt-tool mcp__…` (a JSON-RPC `tools/call` with `{tool_name, input, tool_use_id}`).
Correlation key = `tool_use_id` (threads ask → `tool_use.id` → `tool_result.tool_use_id` →
`result.permission_denials[].tool_use_id`); option set = `behavior {allow|deny}` ×
`decisionClassification {user_temporary, user_permanent, user_reject}`; pending/answered/parked
state for re-attach comes from the `initialize` control_response's `pending_permission_requests[]`.
The socket-hold is simply the open `control_request` awaiting its `control_response` — carried as
ask-event payload, never a state (doc 15 §6.1 row 5).

**Partial-message assembly (P11).** `stream_event` brackets a turn as `message_start` →
(`content_block_start` → `content_block_delta`* → `content_block_stop`)* → `message_delta` →
`message_stop`, each carrying `{event, parent_tool_use_id, session_id, type, uuid}`. Buffer per
`event.index`, coalesce deltas (`text_delta`/`thinking_delta`/`input_json_delta`), and `JSON.parse`
an `input_json_delta` stream **only at `content_block_stop`** (the first delta is an empty priming
string; intermediate concatenations are invalid JSON by design). The **non-partial records are
authoritative** (partials are render-only); the non-partial `assistant` is emitted **once per
content block**, so merge by `message.id`. Non-`stream_event` records can straddle mid-envelope and
the `tool_result` position is nondeterministic — anchor on `content_block_stop`/`message_stop`,
never on `tool_result` position.

### `result` record (accounting)

```
subtype {success | error_during_execution | error_max_turns | error_max_budget_usd
         | error_max_structured_output_retries},   # closed set (P13)
is_error, num_turns, stop_reason, terminal_reason,   # terminal_reason = max_turns on
         # error_max_turns, ABSENT on error_max_budget_usd; api_error_status only on success (P9/P13)
result (final assistant text), total_cost_usd, duration_ms, duration_api_ms,
ttft_ms, ttft_stream_ms, time_to_request_ms, permission_denials[], api_error_status,
usage{input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens,
      cache_creation, iterations, server_tool_use, service_tier, speed, inference_geo},
modelUsage{<model>: {inputTokens, outputTokens, cacheReadInputTokens,
      cacheCreationInputTokens, costUSD, contextWindow, maxOutputTokens, webSearchRequests}}
```

### Implications for D18 / D38

- The adapter parses the spawn tree from `system/task_*` events + `tool_use.name ∈ {Task, Agent}`
  blocks, joined by the `(tool_use_id, task_id, message.id)` id triple — **not** by
  `parent_tool_use_id` alone (which flattens, see above). The `dreamserpent.attach.v1` per-event
  **sequence number must be synthesized by the adapter from stdout arrival order**: the CC wire
  carries no monotonic token (`uuid` is random v4; `event.index` resets per message), and arrival
  order ≠ spawn order (P1). Round 3 **verified** this synthesis is causally safe for the local
  Layer-1 single-process case — stdout arrival order is a topological sort of the spawn→complete
  DAG under single-writer serialization (PHASE3 P10, doc 15 §6.1 row 1). The only open caveat is a
  Layer-2 daemon multiplexer, which could break the single-writer guarantee.
- D18 fan-out-into-VMs is a **spawn-interception** design, not a tap: the wrapper/orchestrator
  sees the `Agent` spawn (it has `subagent_type` + `prompt` — everything needed to start a
  fresh session elsewhere) and re-hosts the subagent in its own VM, then feeds the result back
  as the `tool_result`. There is no in-process channel to mirror, which actually simplifies the
  boundary: the interception point is one message type.
- Per-subagent accounting for the TUI comes from the result trailer's `<usage>` block, not
  from any subagent-internal stream.

---

## Layer 2 — the background-agent daemon (the actual subprocess/IPC system)

`claude agents` is backed by a per-**uid** **supervisor daemon**. State lives in
`~/.claude/daemon/` (`roster.json`, `control.key`, `dispatch/`, `daemon.log`,
`daemon.status.json`) and the live sockets in `/tmp/cc-daemon-<uid>/<instance>/`.

**A dispatched worker can observe the daemon from the inside.** `daemon.log` records each spawn
(`bg spawned <short-id> (slash)`), and a dispatched worker's process env carries
`CLAUDE_CODE_CHILD_SESSION=1`. (The `CLAUDE_BG_ISOLATION=none` value lives in the session's
**dispatch descriptor** `env` block in `roster.json`, not necessarily exported into the live
process env.) So the architecture is observable from a worker.

> **Uid-keyed sharing — operational caution.** The daemon dir is keyed by **uid**, not by
> `HOME`/`CLAUDE_CONFIG_DIR`. Concurrent `claude` sessions running under one uid therefore share
> **one** instance dir `/tmp/cc-daemon-<uid>/<instance>`, whose `control.sock`/`rv`/`pty`/`spare`
> sockets are connectable by any process with that uid. A throwaway `HOME` does **not** move
> sockets to a different `/tmp/cc-daemon-*` parent — at most a different `<instance>` subdir under
> the shared `/tmp/cc-daemon-<uid>/`. Any daemon-protocol reversing must treat a pre-existing
> instance dir as untouchable and gate isolation with a fail-closed check (see
> [`PHASE2-FINDINGS.md`](PHASE2-FINDINGS.md) §5).

### Process & lifecycle model (from `daemon.log`)

- A **supervisor** (`daemon.status.json.supervisorPid`) owns the system.
- It keeps **pre-warmed "spare"** worker processes: `bg spare spawned host pid=…`.
- On demand it **claims** a spare and binds a session to it:
  `bg claimed-spare <id> (spare)` → `bg spawned <id> (slash|prompt|…)`.
- Lifecycle terminal states: `bg settled <id> (done|killed)`.
- The supervisor also centralizes **auth refresh** for all workers
  (`[supervisor] auth: proactive refresh …`).

### Socket topology (`/tmp/cc-daemon-<uid>/<instance>/`)

| Socket | Owner | Role |
|---|---|---|
| `control.sock` | supervisor pid | Main control entry point — list / dispatch / claim. The `claude agents` CLI connects here. |
| `spare/<id>.claim.sock` | spare worker | Claim a pre-warmed spare and assign it a session. |
| `spare/<id>.pty.sock` | spare worker | Pre-created PTY socket for the spare. |
| `rv/<short>.sock` | per-session helper | **Rendezvous / control** channel for a live session. |
| `pty/<short>.sock` | per-session worker | **PTY (terminal) attach** stream for a live session. |
| `auth/` | — | Capability material. |

All are listening `AF_UNIX` stream sockets, each owned by a distinct `claude` process.

### `roster.json` — the worker registry (`proto: 1`)

Per worker (keyed by short id): `pid`, `procStart` (start-ticks, for liveness),
`sessionId` (full UUID), `cliVersion`, `cwd`, `startedAt`, `attempt`, plus:

- `rendezvousSock`, `ptySock` — paths to the two sockets above.
- `rvAuth`, `ptyAuth` — 32-hex **capability tokens**, one per socket (present a token to connect).
- `decModes[]` — saved terminal DEC private modes (re-attach restores terminal state).
- `dispatch` — the **launch descriptor** (`proto:1`):
  `short`, `nonce`, `sessionId`, `createdAt`, `source` (`spare|slash|…`), `cwd`,
  `launch{mode: prompt|resume, args|flagArgs, fork}`, `env{…}`, **`isolation`** (`none|…`),
  `respawnFlags[]`, `agent`, `seed{intent}`, `cols`, `rows`.

### The isolation seam (directly relevant to us)

The dispatch descriptor already has an **`isolation`** field, and the dispatch `env` carries
**`CLAUDE_BG_ISOLATION`** (here `none`). That is precisely the hook where Dream Serpent's
VM isolation slots in: a dispatch with `isolation` ≠ `none` is where "run this session/agent
in its own boundary" would be expressed. Worth a focused follow-up — enumerate the accepted
`isolation` values and what each one changes about worker spawn.

### Implications for attach (D38)

- The native attach transport is a **raw PTY byte stream over a unix socket**, token-gated —
  not stream-json. Our `dreamserpent.attach.v1` is a *structured* event stream. Two viable
  client strategies, to decide later:
  1. **Drive headless `stream-json`** (Layer 1) for structured events, and synthesize the
     terminal view ourselves — clean event model, but no native TUI fidelity and (today)
     no subagent internals / no continuation.
  2. **Attach to the PTY socket** (Layer 2) for full-fidelity terminal, and parse the
     structured side separately — full fidelity, but the wire is terminal bytes, not events.
- The `dispatch` descriptor is a close analogue of the session-spec the orchestrator would
  mint; the `roster.json` worker entry is a close analogue of our session registry row.

---

## Open questions / next captures

Phase 2 (PHASE2-FINDINGS.md) resolved parallel fan-out (1:1, completion-order results) and the
`--replay-user-messages` input protocol (`isReplay:true`), and returned a valid negative on hooks
(`--include-hook-events` is inert with no hooks configured). **Phase 3
([`PHASE3-FINDINGS.md`](PHASE3-FINDINGS.md)) resolved** the three highest-leverage gaps plus three
closed sets:

- **Ask / approval event (freeze row 5) — RESOLVED.** The live ask is **not** on headless `-p`
  stdout; it is sourced from the control protocol — a `canUseTool` responder (native
  `control_request{subtype:"can_use_tool"}`) or a `--permission-prompt-tool`. Correlation key
  `tool_use_id`; option set `behavior`×`decisionClassification`; pending/answered/timeout from the
  `initialize` response's `pending_permission_requests[]`. (See the round-3 subsection above.)
- **Session-state vocabulary (row 3) — RESOLVED (Layer-1 half).** CC→§3 mapping delivered; only
  ATTACHED/WORKING have a CC-wire source, the rest are orchestrator-owned. `system/status.status`
  is `requesting`-only in print mode; `result.subtype` closed set enumerated. Layer-2 daemon status
  vocabulary stays deferred.
- **MCP / Skill / plugin framing — RESOLVED** (the classification rule above, P14).
- **Ordering (row 1), partial-message assembly, `result.subtype` closed set — RESOLVED** (P10/P11/P13).

Still open (full backlog in [`PHASE2-FINDINGS.md`](PHASE2-FINDINGS.md) §2):

1. **`SendMessage` continuation:** the multi-turn subagent framing where `SendMessage` is enabled
   (interactive / `--brief`) — needed for resumable subagents.
2. **Plan-delta / TodoWrite (freeze row 6 plan half):** `ExitPlanMode` approval framing and
   `TodoWrite`/`Task*` todo-list updates (the canvas-tile plan-delta fields).
3. **D78 attendedness input-activity events (row 7):** the writer-seat write event shape
   (PHASE2 P4 `isReplay` is the nearest evidence).
4. **`rate_limit_event` / overage surfacing under load** (`resetsAt`/`overageStatus` semantics).
5. **Daemon (Layer 2), deferred for safety (§5):** `isolation` value set, `control.sock` wire format,
   PTY socket framing — read-only recon can run now; the mutating reversing needs a quiesced/isolated
   window with a fail-closed gate (never touch a pre-existing `/tmp/cc-daemon-<uid>/<instance>`).

## Provenance

Raw captures for this writeup were produced by `capture.sh` into the job tmp dir and are not
committed (they contain real paths, session UUIDs, costs, agent ids). The committed cassette in
[`../fixtures/`](../fixtures/) is a hand-re-authored **synthetic** equivalent (D50).
</content>
</invoke>
