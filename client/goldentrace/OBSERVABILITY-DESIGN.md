# Operator observability — subagent spawn tree + per-subagent accounting

**Owner:** Attach & client · **Decisions:** D18, D38 · **Status:** design note (consumes the D49 capture)
**Source:** drafted by a review subagent from [`PROTOCOL-NOTES.md`](PROTOCOL-NOTES.md) + [`PHASE2-FINDINGS.md`](PHASE2-FINDINGS.md); grounded strictly in documented record shapes.

Scope: Layer-1 headless `stream-json` only. Every `dreamserpent.attach.v1` event below carries a
common envelope: `seq` (adapter-synthesized from stdout arrival order — the wire has no monotonic
token, `uuid` is random v4, and arrival order ≠ spawn order, so this synthesis rests on the
still-open P10 causal-ordering verification), `session_id`, `observed_at` (adapter clock — `task_*`
records carry no wire timestamp), and `source` (the CC record `uuid`(s) the event was projected
from, for replay/debug).

## 1. Operator-facing events and their CC sources

### `subagent.spawned`
Emitted when a node enters the tree. Sourced from the **join** of the `assistant` `tool_use` block
and `system/task_started` (either may arrive first; create provisional on first, finalize on join).

| Field | CC source |
|---|---|
| `node_id` | `tool_use.id` of the spawn block (`name ∈ {Task, Agent}` — wire name is `Agent`; never match `TaskCreate/Get/List/Update/Stop/Output` (todo tools) or `mcp__*` namespaced tools) |
| `task_id` | `system/task_started.task_id` |
| `subagent_type` | `tool_use.input.subagent_type` == `task_started.subagent_type` (cross-check) |
| `description`, `prompt_excerpt` | `tool_use.input.{description,prompt}` / `task_started.{description,prompt}` |
| `task_type` | `task_started.task_type` (observed: `local_agent`) |
| `parent_node_id` | `parent_tool_use_id` **of the assistant stream line carrying the spawn block** (null ⇒ root). NOT from `task_started`, where it is always null |
| `parent_confidence` | `"exact"` at depth ≤ 2 (P2-verified), `"inferred"` at depth ≥ 3 (see §2) |
| `turn_group` | `message.id` of the spawn line — groups parallel siblings fanned out in one logical assistant turn (P1: one message, N stream lines) |

### `subagent.progress`
1:1 from `system/task_progress`.

| Field | CC source |
|---|---|
| `node_id`, `task_id` | `task_progress.{tool_use_id, task_id}` |
| `last_tool_name` | `task_progress.last_tool_name` — the only liveness peek into a subagent's inner work (the tool calls themselves never surface) |
| `elapsed_ms` | adapter clock since the node's `task_started` arrival (not wire truth) |
| `usage_raw` | verbatim passthrough of `task_progress.usage`, flagged `uncharacterized: true` — no capture establishes what it contains; do not render as token burn |

### `subagent.completed`
1:1 from `system/task_notification`.

| Field | CC source |
|---|---|
| `node_id`, `task_id` | `task_notification.{tool_use_id, task_id}` |
| `status`, `summary`, `output_file` | `task_notification.{status, summary, output_file}` (status vocabulary unenumerated — pass through verbatim, P9 open) |

Do **not** source tokens here: `task_notification.usage.subagent_tokens` was observed `null` (P1).

### `subagent.accounted`
Emitted on the `user` `tool_result` matching the node — the authoritative accounting record.
Arrives in completion order, possibly long after `completed`; hence a separate event.

| Field | CC source |
|---|---|
| `node_id` | `tool_result` `content[].tool_use_id` (top-level `parent_tool_use_id` is null/redirected on results — never join on it) |
| `agent_id` | trailer `agentId:` line; equals `task_id` (P1) — assert equality as an integrity check |
| `subagent_tokens`, `tool_uses`, `duration_ms` | the `<usage>` trailer block in the result's second text block |
| `output_excerpt` | first text block of the result content |
| `is_error` | `tool_result.is_error` (per P5: never classify failure from result text) |
| `returned_to` | top-level `parent_tool_use_id` of the result line (the level it returns *to*; null = root) — parent corroboration, not primary join |
| `continuation` | `{agent_id, hint: "SendMessage"}` from the trailer — display-only; `SendMessage` is gated in headless `-p`, so the TUI must not present it as actionable |

### `quota.updated`
1:1 from `rate_limit_event.rate_limit_info`: `rate_limit_type`, `status`, `resets_at`,
`is_using_overage`, `overage_status`, `overage_disabled_reason`. Latest-value-wins in the TUI
status strip. Mark `semantics: "provisional"` — `resetsAt`/`overageStatus` under load is unfixed (P18).

### `session.accounted`
Terminal, from the `result` record: `total_cost_usd`, `usage{...}`, `modelUsage{...}`, `num_turns`,
`duration_ms`, `subtype`, `is_error`, `permission_denials[]`. The **only** dollar figure on the wire.

Input echoes (`isReplay: true` user records) are ACK markers, never tree nodes — skip them (P4).

## 2. Tree reconstruction under the flattening constraint

`parent_tool_use_id` cannot be the spine: it is null on all `task_*` events, null/redirected on
results, and flattens nesting to depth 1. The adapter keeps a registry keyed by `tool_use_id`,
joined across the triple:

- **`tool_use_id`** — links spawn block ↔ `task_started`/`task_progress`/`task_notification` ↔ `tool_result.content[].tool_use_id`. The node's primary key.
- **`task_id` / `agentId`** — links the `task_*` lifecycle to the result trailer's `agentId` (same hex). Second namespace; binds lifecycle to accounting even if a spawn block line was missed.
- **`message.id`** — groups N sibling `Agent` blocks (and the thinking line) of one fan-out turn that CC emits as N separate stream lines. Never assume one stream line = one logical message.

**Parent attribution.** The one place parentage is reliably written is the **spawn line itself**:
a nested `Agent` `tool_use` surfaces as an `assistant` message tagged `parent_tool_use_id` = the
launching subagent's own spawn id (P2-verified at depth 2). So:

1. `parent(node) :=` the `parent_tool_use_id` on the assistant line carrying that node's `Agent` block. Null ⇒ child of root.
2. Corroborate on result arrival via the return-target rule: the node's `tool_result` carries top-level `parent_tool_use_id` = the level it returns to. Disagreement ⇒ flag the edge, keep the spawn-line value.
3. **Grandchild (depth 2) attribution is exact** — the grandchild's spawn line is tagged with its true parent's launching id; "flattening" means the grandchild's id is never itself used as anyone's `parent_tool_use_id`, not that the grandchild's parent tag is wrong.
4. **Depth ≥ 3 is honestly uncertain** (P2 caveat untested). Mark such edges `parent_confidence: "inferred"`. Corroborating heuristic: a `task_progress` with `last_tool_name == "Agent"` on exactly one live candidate parent adjacent to the new `task_started` (how P2 independently confirmed outer spawned inner). If still ambiguous, attach to the tagged ancestor and render the edge dashed.
5. Never order by stream position: spawn-side records interleave in spawn order, `task_notification`/`tool_result` arrive in completion order (fastest first, P1). Correlate by id only.

## 3. Operator view sketch

```
SESSION 59a11afd  ·  cc 2.1.173  ·  model from init  ·  seq 4821        LIVE
------------------------------------------------------------------------------
QUOTA   status: <rate_limit_info.status>   resets: <resetsAt>
        overage: <overageStatus> (using: <isUsingOverage>)        [provisional]
------------------------------------------------------------------------------
SUBAGENTS                              tokens      tools    time       state
 root
 |- Explore      "scan boundary/"      --  (live)  Bash*    01:42^     RUN
 |   `- Explore  "grep harness"        --  (live)  Read*    00:18^     RUN
 |- Plan         "attach event model"  --  (live)  --       00:55^     RUN
 |- general-purp "fixture sweep"       3,467       4        2.2s       DONE
 `- claude       "lint pass"           1,272       1        3.4s       ERR
                                       [agentId a10a1d5a... | SendMessage gated]
------------------------------------------------------------------------------
 *  = last_tool_name from task_progress (coarse liveness; args/results opaque)
 ^  = adapter-clock elapsed since task_started arrival (wire has no timestamp)
 -- = token burn for a running subagent is NOT on the wire; appears only in the
      <usage> trailer at completion
SESSION: cost/usage pending (arrives only in terminal `result` record)
```

Row state machine per node: `RUN` (spawned/progress) → `DONE`/`ERR` on `subagent.completed`,
columns backfilled on `subagent.accounted`. Dashed tree edges where `parent_confidence: "inferred"`.

## 4. What the client cannot get from the current capture (do not invent)

- **Live token burn of a running subagent.** `subagent_tokens` exists only in the `tool_result` `<usage>` trailer at completion; `task_notification.usage.subagent_tokens` was observed null, and `task_progress.usage` contents are uncharacterized. Render `--` until completion.
- **Per-subagent dollar cost.** No per-subagent `costUSD` on the wire — only session-level `total_cost_usd` and per-*model* `modelUsage` in the terminal `result`. Any per-subagent dollar figure is a price-table estimate and must be labeled as such.
- **Live `tool_uses` count.** Only in the completion trailer; mid-run the sole activity signal is `task_progress.last_tool_name`.
- **Subagent inner work.** Model turns and ordinary tool calls (Bash, Read, …) of a leaf never surface — only spawn/result boundary crossings and `task_*` lifecycle. The view can show "what tool it last touched," never a mirrored transcript.
- **Wire timestamps on `task_*` events.** None in the key lists; all running-elapsed figures are adapter-clock, only the trailer `duration_ms` is wire truth.
- **Depth ≥ 3 parentage** — untested (P2 caveat); edges beyond depth 2 are inferred.
- **`task_notification.status` and quota semantics** — vocabularies unenumerated (P9, P18); pass through verbatim, mark provisional.
- **"Blocked on approval" state** — the ask/approval record is entirely uncaptured (P8, freeze row 5), so the view cannot show a subagent waiting on permission.
- **Actionable continuation** — `agentId` + `SendMessage` hint surface, but `SendMessage` is gated in headless mode; display-only.
</content>
