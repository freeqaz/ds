# Checklist — `subagent-spawn.cc-wire.ndjson`

The original smoke cassette (pre-dates the round-4 fixture set): a single `Agent`
spawn whose **`system/task_*` lifecycle is absent** — only the spawn `tool_use`
block and the returning `tool_result` `<usage>` trailer are on the wire. It pins
the two halves of a subagent that survive even a missed task lifecycle: the
spawn-block registration and the authoritative accounting trailer. The expected
projection is derived strictly from **OBSERVABILITY-DESIGN §1** (the event/source
tables) and §2 (the join triple); PHASE3 wins on any conflict.

The load-bearing shape: `subagent.spawned` is sourced from the **join** of the
assistant `tool_use` block and `system/task_started` (OBSERVABILITY §1
subagent.spawned: "create provisional on first, finalize on join"). This cassette
carries **no `task_started`**, so the spawn stays provisional and **no
`subagent.spawned` is emitted** — and because no task ever opens
(`Adapter.openTasks` stays empty), the WORKING latch never flips, so there is
**no `session.state` transition** either (P9: WORKING needs a `requesting` ping OR
an open `task_*`, and this cassette has neither). The `tool_result` still carries
the `<usage>` trailer, which projects `subagent.accounted` 1:1 (OBSERVABILITY §1:
the accounting record is sourced from the `user` `tool_result`, independent of the
spawn join). The nested-prompt `user` record (`…00a3`, `parent_tool_use_id` set)
is consumed for `prompt_excerpt` corroboration only — no standalone event
(OBSERVABILITY §1 final note: input echoes are not tree nodes; classify.go:
nested-prompt text records emit nothing).

Replaying through the claude-code adapter MUST produce exactly this ordered
`attach.v1` event sequence (Seq strictly monotonic from 1; SessionID constant
`"00000000-0000-4000-8000-000000000001"`; exactly one payload non-nil each):

1. **`session.init`** — `runtime_version:"2.1.173"`, `model:"claude-sonnet-4-6"`,
   `cwd:"/work"`, `permission_mode:"bypassPermissions"`, `api_key_source:"none"`,
   `tools:["Task"]`, `agent_types` from `init.agents` (includes `echoer`),
   `skills`/`slash_commands` empty, `output_style:"default"`. Source `…00a0`.
   *Rule:* OBSERVABILITY §1 (common envelope) + PROTOCOL-NOTES `init` key set;
   `init` is the attach-time snapshot.

2. **`chat.message`** — `message_id:"msg_synthetic_0001"`, `role:"assistant"`,
   `parent_node_id` empty (root), one `blocks[]` entry
   `{kind:"thinking", text:"I will launch the echoer subagent once, then report done."}`.
   Source `…00a1`.
   *Rule:* OBSERVABILITY §1 (chat is a Layer-1 assistant projection); classify.go:
   a non-partial `thinking` block ⇒ ChatMessage; the `signature` is dropped.

   *(The `Agent` spawn block `…00a2` registers the node provisionally but emits
   NOTHING — there is no `task_started` to complete the join. OBSERVABILITY §1
   subagent.spawned "finalize on join".)*

   *(The nested-prompt `user` record `…00a3` — `parent_tool_use_id=` the spawn id,
   text "hello" — produces NO standalone event: it is the subagent's prompt echo,
   consumed for `prompt_excerpt` corroboration only. OBSERVABILITY §1 closing note
   "input echoes … are ACK markers, never tree nodes".)*

3. **`subagent.accounted`** — `node_id:"toolu_SYNTHETIC000000000001"`,
   `agent_id:"agentsynth0000001"` (from the trailer `agentId:` line),
   `subagent_tokens:964`, `tool_uses:0` (omitted — zero), `duration_ms:1134`,
   `output_excerpt:"ACORN"` (first text block), `is_error:false` (omitted),
   `returned_to` empty (the result line's top-level `parent_tool_use_id` is null —
   returns to root), `continuation:{agent_id:"agentsynth0000001", hint:"SendMessage"}`
   (display-only). Source `…00a4`.
   *Rule:* OBSERVABILITY §1 subagent.accounted — sourced from the `user`
   `tool_result` matching the node by `content[].tool_use_id`; `agentId`/tokens/
   `tool_uses`/`duration_ms` from the `<usage>` trailer; `output_excerpt` = first
   text block; `returned_to` from the result line's top-level `parent_tool_use_id`;
   `continuation` display-only (§4: `SendMessage` gated in headless). The integrity
   check `agentId == task_id` is vacuous here (no `task_started`, so `task_id` is
   empty) and is skipped, not warned.

4. **`chat.message`** — `message_id:"msg_synthetic_0002"`, `role:"assistant"`,
   `parent_node_id` empty (root), one `blocks[]` entry
   `{kind:"text", text:"done"}`. Source `…00a5`.
   *Rule:* OBSERVABILITY §1 (assistant text projection); classify.go: a non-partial
   `text` block ⇒ ChatMessage.

5. **`session.accounted`** — `outcome:"success"`, `is_error:false` (omitted),
   `num_turns:2`, `duration_ms:4200`, `total_cost_usd:0` (omitted),
   `terminal_reason:"completed"`, `denial_count:0` (omitted — `permission_denials`
   empty), `usage`/`model_usage` passthrough. Source `…00a6`.
   *Rule:* OBSERVABILITY §1 session.accounted (the terminal `result`: the only
   dollar figure on the wire); outcome from the closed `result.subtype` set; branch
   on `subtype`+`is_error`, NEVER on `stop_reason`.

Notes:
- **No `subagent.spawned`, `subagent.progress`, or `subagent.completed`** — this
  cassette omits the entire `system/task_*` lifecycle, so the spawn join never
  completes and no task ever opens. The node survives only as a spawn-block
  registration plus its returning accounting trailer. This is the faithful
  projection of a missed-lifecycle spawn (OBSERVABILITY §2: `task_id`/`agentId`
  binds lifecycle to accounting *even if a spawn-block line was missed* — and the
  symmetric case, a missed `task_started`, downgrades to accounting-only).
- **No `session.state` events.** With no `requesting` ping and no open `task_*`,
  the WORKING latch never leaves its initial ATTACHED (P9). There is no transition
  to report; SessionState emits on transitions only.
- The terminal `result` carries `permission_denials:[]`, so `denial_count` is 0
  and `handleDenials` produces nothing.
- Every event's `Source` carries the uuid(s) of the CC record(s) it was projected
  from.
