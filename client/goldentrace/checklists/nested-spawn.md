# Checklist — `nested-spawn.cc-wire.ndjson`

Ordered `attach.v1` events this cassette MUST project when replayed through the
claude-code adapter. Each line cites the rule (PHASE-FINDINGS P-number / doc §)
that justifies it. The integrator validates the generated golden against this
list; reviewers re-validate. `seq` is adapter-synthesized from stdout arrival
order, monotonic from 1 (P10).

Scenario: an **outer** `Agent` spawn at root (`parent_tool_use_id=null`) whose
subagent itself spawns an **inner** `Agent` — the inner spawn line surfaces in
the parent stream tagged `parent_tool_use_id = outer` (P2: nesting is observable;
`parent_tool_use_id` flattens to depth 1). The inner `tool_result` returns to
`parent=outer` (`content.tool_use_id=inner`); the outer `tool_result` returns to
`parent=null` (`content.tool_use_id=outer`) — the return-target rule. Both nodes'
`system/task_*` events appear at root with no `parent_tool_use_id`; the outer
`task_progress` carries `last_tool_name="Agent"`, independent corroboration that
outer invoked `Agent` to spawn inner.

Synthetic node table:

| label | node_id (tool_use.id) | task_id / agentId | parent_node_id | tokens |
|---|---|---|---|---|
| outer | `toolu_SYNTHETICNESTEDOUTER1` | `d4d4d4d4d4d4d4d4` | `""` (root) | 1880 |
| inner | `toolu_SYNTHETICNESTEDINNER1` | `e5e5e5e5e5e5e5e5` | `toolu_SYNTHETICNESTEDOUTER1` | 712 |

## Expected event sequence

1. **`session.init`** — `model="claude-sonnet-4-6"`, `permission_mode="bypassPermissions"`,
   `api_key_source="none"`, `tools=["Task"]`, `agent_types` includes `outer`/`inner`.
   Source = `…00d0`. *(PROTOCOL-NOTES §init key set; OBSERVABILITY §1.)*

2. **`session.state`** — `state="WORKING"`, `reason="task_open"`. Fires when the
   outer `task_started` (`…00d2`) opens a task (no `system/status` ping in this
   cassette). Source = `…00d2`.
   *(P9: WORKING on any open task_*; state.go transition-only.)*

3. **`subagent.spawned` (outer)** — `node_id=toolu_SYNTHETICNESTEDOUTER1`,
   `task_id=d4d4…`, `subagent_type="outer"`, `description="Outer task"`,
   `prompt_excerpt` from `input.prompt`, `task_type="local_agent"`,
   `parent_node_id=""` (root — spawn-line `parent_tool_use_id` null),
   `parent_confidence="exact"` (depth 1), `turn_group="msg_synth_nested_0001"`.
   Finalized on the join of spawn block `…00d1` + `task_started` `…00d2`.
   *(OBSERVABILITY §1 subagent.spawned; §2 parent from spawn-line parent_tool_use_id,
   "exact" at depth ≤2; P2.)*

4. **Outer's nested prompt produces NO standalone event.** `user` record `…00d3`
   (`parent_tool_use_id=outer`, text "spawn the inner subagent then report")
   consumed only for `prompt_excerpt` corroboration.
   *(classify.go: nested-prompt text consumed, no standalone event; P1.)*

5. **`subagent.spawned` (inner)** — `node_id=toolu_SYNTHETICNESTEDINNER1`,
   `task_id=e5e5…`, `subagent_type="inner"`, `description="Inner task"`,
   `parent_node_id="toolu_SYNTHETICNESTEDOUTER1"` (the inner spawn line `…00d4` is
   tagged `parent_tool_use_id=outer`), `parent_confidence="exact"` (depth 2,
   P2-verified — the grandchild's spawn line carries its true parent's launching id),
   `turn_group="msg_synth_nested_0002"`. Finalized on the join of spawn block `…00d4`
   + `task_started` `…00d5`.
   *(P2: nested spawn surfaces tagged with launcher's id, depth-2 attribution exact;
   OBSERVABILITY §2 rule 1+3.)*

6. **`subagent.progress` (outer)** — `node_id=outer`, `task_id=d4d4…`,
   `last_tool_name="Agent"`, `usage_raw` = verbatim passthrough of
   `task_progress.usage` flagged `uncharacterized`. Source = `…00d6`. The
   `last_tool_name="Agent"` is the corroboration that outer spawned inner.
   `elapsed_ms` is omitted: the spec's binding progress field enumeration
   (IMPLEMENTATION-SPEC, "progress: last_tool_name, usage_raw …") does not list
   it, and the deterministic replay clock is an emission counter (not wall time),
   so a derived elapsed_ms would be a meaningless emission-delta — left
   unpopulated (`omitempty`) until a real adapter clock exists.
   *(OBSERVABILITY §1 subagent.progress; §2 rule 4 corroboration; P2.)*

7. **`subagent.accounted` (inner)** — `node_id=toolu_SYNTHETICNESTEDINNER1`,
   `agent_id=e5e5…` (== task_id, integrity check passes), `subagent_tokens=712`,
   `tool_uses=0`, `duration_ms=1320`, `output_excerpt="INNERWORD"`, `is_error=false`,
   `returned_to="toolu_SYNTHETICNESTEDOUTER1"` (the inner result `…00d7` carries
   top-level `parent_tool_use_id=outer` — the level it returns to; corroborates the
   parent edge, agrees with the spawn-line value). Correlated by
   `content[].tool_use_id=inner`, never by position. Source = `…00d7`.
   *(P2 return-target rule; OBSERVABILITY §1 subagent.accounted (`returned_to`);
   §2 corroborate on result, keep spawn-line value.)*

8. **`subagent.accounted` (outer)** — `node_id=toolu_SYNTHETICNESTEDOUTER1`,
   `agent_id=d4d4…`, `subagent_tokens=1880`, `tool_uses=1`, `duration_ms=3960`,
   `output_excerpt="OUTERWORD"`, `is_error=false`, `returned_to=""` (the outer
   result `…00d8` carries top-level `parent_tool_use_id=null` — returns to root).
   Correlated by `content[].tool_use_id=outer`. Source = `…00d8`.
   *(P2 return-target rule (outer→root); OBSERVABILITY §1/§2.)*

9. **`subagent.completed` (inner)** — `node_id=inner`, `task_id=e5e5…`,
   `status="completed"`, `summary="inner done"`,
   `output_file="/work/.memory/inner.out"`. Source = `…00d9`. No tokens here.
   *(OBSERVABILITY §1 subagent.completed; tokens null in task_notification, P1.)*

10. **`subagent.completed` (outer)** — `node_id=outer`, `task_id=d4d4…`,
    `status="completed"`, `summary="outer done"`,
    `output_file="/work/.memory/outer.out"`. Source = `…00da`. *(as #9.)*
    *(Note: in this cassette the `tool_result` accounting records (`…00d7/…00d8`)
    arrive BEFORE the `task_notification` completions (`…00d9/…00da`) — accounted
    precedes completed; the adapter correlates by id, never by position, P1/P10.)*

11. **`chat.message`** — `role="assistant"`, `message_id="msg_synth_nested_0003"`,
    one `{kind:"text"}` block `"nested spawn complete"`, `parent_node_id=""`.
    Source = `…00db`. *(P11; classify.go text block ⇒ ChatMessage.)*

12. **`quota.updated`** — passthrough of `rate_limit_info`
    (`rate_limit_type="tokens"`, `status="ok"`, `is_using_overage=false`,
    `overage_status="none"`), `semantics="provisional"`. Source = `…00dc`.
    *(OBSERVABILITY §1 quota.updated; P18 provisional.)*

13. **`session.accounted`** — `outcome="success"`, `is_error=false`, `num_turns=3`,
    `duration_ms=5400`, `total_cost_usd=0`, `terminal_reason="completed"`,
    `denial_count=0`, `usage`/`model_usage` passthrough. Source = `…00dd`.
    NEVER branch on `stop_reason`.
    *(P13 closed-set outcome; P9 never branch on stop_reason; OBSERVABILITY §1.)*

14. **`session.state`** — `state="ATTACHED"`, `reason="turn_complete"`, at the
    terminal `result` with no open tasks. Source = `…00dd`.
    *(P9: ATTACHED on a result with no open tasks; state.go transition-only.)*

## Invariants (well-formedness)

- `seq` strictly monotonic from 1; `session_id` constant
  (`00000000-0000-4000-8000-000000000003`) on every event; exactly one payload
  pointer non-nil per event. *(IMPLEMENTATION-SPEC validateEvents.)*
- Exactly **two** `subagent.spawned`, **two** `subagent.accounted`, **two**
  `subagent.completed`, **one** `subagent.progress` — no `tool.invoked` for the
  spawns. *(spec: Agent spawns are SubagentSpawned, NOT ToolInvoked.)*
- The inner node's `parent_node_id` is the outer node_id (depth-2 edge, exact),
  proving the adapter reconstructs nesting by chaining `tool_use_id`, NOT by
  `parent_tool_use_id` alone (which flattens to depth 1). *(P2; OBSERVABILITY §2.)*
- No event is projected from the outer nested-prompt `user` record. *(P1 / classify.go.)*
- Events 13 then 14 order (terminal `session.accounted` then the ATTACHED
  `session.state`) is the implemented `handleResult` emission order — accounting
  first, then the transition. Both MUST be present, projected from the same
  `result` record uuid. *(state.go handleResult; cf. baseline-chat.md note.)*
