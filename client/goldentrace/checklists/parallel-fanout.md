# Checklist — `parallel-fanout.cc-wire.ndjson`

Ordered `attach.v1` events this cassette MUST project when replayed through the
claude-code adapter. Each line cites the rule (PHASE-FINDINGS P-number / doc §)
that justifies it. The integrator validates the generated golden against this
list; reviewers re-validate. `seq` is adapter-synthesized from stdout arrival
order, monotonic from 1 (P10 — arrival order is a safe topological sort).

Scenario: three `Agent` spawns fanned out in one logical assistant turn
(one `message.id`, three stream lines), `task_started` ×3 in spawn order
(alpha→bravo→charlie), nested prompts, then `task_notification` + `tool_result`
in **reverse** completion order (charlie→bravo→alpha — fastest first), each with
a distinct `<usage>` trailer whose `agentId == task_id`.

Synthetic node table:

| label | node_id (tool_use.id) | task_id / agentId | subagent_tokens |
|---|---|---|---|
| alpha | `toolu_SYNTHETICPARALLEL0001` | `a1a1a1a1a1a1a1a1` | 1534 |
| bravo | `toolu_SYNTHETICPARALLEL0002` | `b2b2b2b2b2b2b2b2` | 1272 |
| charlie | `toolu_SYNTHETICPARALLEL0003` | `c3c3c3c3c3c3c3c3` | 1051 |

## Expected event sequence

1. **`session.init`** — `model="claude-sonnet-4-6"`, `permission_mode="bypassPermissions"`,
   `api_key_source="none"`, `tools=["Task"]`, `agent_types` includes
   `alpha`/`bravo`/`charlie`. Source = init uuid `…00b0`.
   *(PROTOCOL-NOTES §init key set; OBSERVABILITY §1.)*

2. **`chat.message`** — `role="assistant"`, `message_id="msg_synth_parallel_0001"`,
   `parent_node_id=""` (root), one block `{kind:"thinking"}`. Source = `…00b1`.
   *(P11: non-partial assistant emitted once per content block, merge by message.id;
   classify.go: thinking block ⇒ ChatMessage.)*

3. **`session.state`** — `state="WORKING"`, `reason` indicating an open task
   (`"task_open"`). Fires when the first `task_started` (alpha, `…00b5`) opens a
   task; no `system/status` ping exists in this cassette, so WORKING is driven by
   the open `task_*`. Source = `…00b5`.
   *(P9: WORKING on any open task_*; state.go emits SessionState only on transition.)*

4. **`subagent.spawned` ×3** — one per node, finalized on the join of the spawn
   `tool_use` block and `system/task_started` (both present for all three; either
   order, P1). Each carries `node_id`, `task_id`, `subagent_type`,
   `description`, `prompt_excerpt` (from `tool_use.input`/`task_started`),
   `task_type="local_agent"`, `parent_node_id=""` (root — spawn-line
   `parent_tool_use_id` is null), `parent_confidence="exact"` (depth 1),
   `turn_group="msg_synth_parallel_0001"` (all three share one message.id).
   Spawn blocks arrive `…00b2/…00b3/…00b4` (spawn order alpha→bravo→charlie),
   joined to `task_started` `…00b5/…00b6/…00b7`.
   *(P1: N spawns ⇒ N Agent blocks with distinct ids, grouped by message.id;
   OBSERVABILITY §1 subagent.spawned field table; §2 join triple; parent_confidence
   "exact" at depth ≤2.)*

5. **Nested prompts produce NO standalone event.** The three `user` text records
   `…00b8/…00b9/…00ba` (each `parent_tool_use_id` = the spawn id) are consumed only
   for `prompt_excerpt` corroboration.
   *(classify.go: nested-prompt text records — parent_tool_use_id set — consumed for
   the tree's prompt_excerpt, no standalone event; P1 parent→child PROMPT linkage.)*

6. **`subagent.completed` (charlie)** — `node_id=toolu_SYNTHETICPARALLEL0003`,
   `task_id=c3c3…`, `status="completed"`, `summary="charlie done"`,
   `output_file="/work/.memory/charlie.out"`. Source = `…00bb`. NO tokens here
   (`task_notification.usage.subagent_tokens` is null).
   *(OBSERVABILITY §1 subagent.completed; do not source tokens here, P1.)*

7. **`subagent.accounted` (charlie)** — `node_id=toolu_SYNTHETICPARALLEL0003`,
   `agent_id=c3c3…` (== task_id, integrity check passes), `subagent_tokens=1051`,
   `tool_uses=0`, `duration_ms=1098`, `output_excerpt="CHARLIE"`,
   `is_error=false`, `returned_to=""` (result top-level `parent_tool_use_id` null).
   Source = `…00bc` (correlated by `content[].tool_use_id`, NOT by position).
   *(P1: completion-order results, accounting in the <usage> trailer; OBSERVABILITY
   §1 subagent.accounted; §2 join on tool_use_id never position.)*

8. **`subagent.completed` (bravo)** — `task_id=b2b2…`, `status="completed"`,
   `summary="bravo done"`. Source = `…00bd`. *(as #6.)*

9. **`subagent.accounted` (bravo)** — `agent_id=b2b2…`, `subagent_tokens=1272`,
   `tool_uses=0`, `duration_ms=3447`, `output_excerpt="BRAVO"`, `is_error=false`.
   Source = `…00be`. *(as #7.)*

10. **`subagent.completed` (alpha)** — `task_id=a1a1…`, `status="completed"`,
    `summary="alpha done"`. Source = `…00bf`. *(as #6.)*

11. **`subagent.accounted` (alpha)** — `agent_id=a1a1…`, `subagent_tokens=1534`,
    `tool_uses=0`, `duration_ms=7451`, `output_excerpt="ALPHA"`, `is_error=false`.
    Source = `…00c0`. *(as #7.)*
    *(Completion/accounted pairs arrive in REVERSE spawn order — charlie→bravo→alpha
    — matched by id, proving the adapter never correlates by stream position, P1/P10.)*

12. **`chat.message`** — `role="assistant"`, `message_id="msg_synth_parallel_0002"`,
    one `{kind:"text"}` block `"all three subagents returned"`, `parent_node_id=""`.
    Source = `…00c1`. *(P11; classify.go text block ⇒ ChatMessage.)*

13. **`quota.updated`** — passthrough of `rate_limit_info`
    (`rate_limit_type="tokens"`, `status="ok"`, `resets_at`, `is_using_overage=false`,
    `overage_status="none"`), `semantics="provisional"`. Source = `…00c2`.
    *(OBSERVABILITY §1 quota.updated; P18 provisional.)*

14. **`session.accounted`** — `outcome="success"`, `is_error=false`, `num_turns=2`,
    `duration_ms=9100`, `total_cost_usd=0`, `terminal_reason="completed"`,
    `denial_count=0` (`permission_denials` empty), `usage`/`model_usage` passthrough.
    Source = `…00c3`. NEVER branch on `stop_reason`.
    *(P13: closed-set outcome; P9: never branch on stop_reason; OBSERVABILITY §1
    session.accounted.)*

15. **`session.state`** — `state="ATTACHED"`, `reason="turn_complete"`, emitted at
    the terminal `result` with no open tasks. Source = `…00c3`.
    *(P9: ATTACHED on a result with no open tasks; state.go transition-only.)*

## Invariants (well-formedness)

- `seq` strictly monotonic from 1; `session_id` constant
  (`00000000-0000-4000-8000-000000000002`) on every event; exactly one payload
  pointer non-nil per event. *(IMPLEMENTATION-SPEC validateEvents.)*
- Exactly **three** `subagent.spawned`, **three** `subagent.completed`, **three**
  `subagent.accounted` — one per node, no `tool.invoked`/`tool.completed` for the
  spawns. *(spec: Agent spawns are SubagentSpawned, NOT ToolInvoked.)*
- No event is projected from the nested-prompt `user` records. *(P1 / classify.go.)*
- Events 14 then 15 order (terminal `session.accounted` then the ATTACHED
  `session.state`) is the implemented `handleResult` emission order — accounting
  first, then the transition. Both MUST be present, projected from the same
  `result` record uuid. *(state.go handleResult; cf. baseline-chat.md note.)*
