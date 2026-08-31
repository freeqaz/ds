# Checklist — `ask-control.cc-wire.ndjson`

Cassette exercises the **native control-protocol ask** path (P8): a `can_use_tool`
`control_request` answered `allow` by a `control_response`, the tool then executing
(`is_error:false`), followed by a second ask answered `deny` whose `message` propagates
verbatim into the `is_error:true` bare-string `tool_result`, and a terminal `result/success`
carrying the denied `tool_use_id` in `permission_denials[]`.

Source: spec fixture table row `ask-control`; `ask.go` rules (IMPLEMENTATION-SPEC §"Package claudecode" ask hooks);
PHASE3 P8 (native ask), P9 (state), P13 (terminal/denial body), P14 (native classification).

Replaying this cassette through the claude-code adapter MUST produce exactly this ordered
`attach.v1` event sequence (Seq strictly monotonic from 1; SessionID constant; one payload non-nil each):

1. **`session.init`** — `runtime_version:"2.1.173"`, `model`, `cwd`, `permission_mode:"default"`,
   `api_key_source:"none"`, `tools:["Bash"]`, `agent_types` from `init.agents`.
   *Rule:* OBSERVABILITY §1 init table; `init` is the attach-time snapshot (PROTOCOL-NOTES `init` record).

2. **`session.state`** — `state:"WORKING"`, `reason:"requesting"`.
   *Rule:* P9 — `system/status.status=="requesting"` ⇒ WORKING; emit SessionState only on the ATTACHED→WORKING transition.

3. **`tool.invoked`** — `node_id:"toolu_SYNTHETIC000000000301"`, `name:"Bash"`, `kind:"native"`,
   `turn_group:"msg_synthetic_0301"`, `input` = the Bash input.
   *Rule:* P14 — name `Bash` is neither `^mcp__`, nor `{Agent,Task,TaskCreate}`, nor `Skill` ⇒ native; classify on name, never `caller.type`.

4. **`ask.requested`** — `ask_id:"creq_synthetic_0301"` (control `request_id`), `node_id:"toolu_SYNTHETIC000000000301"`
   (= `tool_use_id`), `tool_name:"Bash"`, `source:"control"`, `agent_id:"agentsynth0000301"`,
   `suggestions` = the `permission_suggestions[]`, `input` = the requested tool input, `pending:false`.
   *Rule:* P8 / ask.go — native `control_request{subtype:"can_use_tool"}` ⇒ AskRequested(source "control") with the suggestions/agent_id riders; correlation key `node_id` = `tool_use_id`.

5. **`ask.resolved`** — `ask_id:"creq_synthetic_0301"`, `node_id:"toolu_SYNTHETIC000000000301"`, `behavior:"allow"`.
   *Rule:* P8 / ask.go — `control_response{success…{behavior:"allow"}}` ⇒ AskResolved (full fidelity).

6. **`tool.completed`** — `node_id:"toolu_SYNTHETIC000000000301"`, `is_error:false`, `output_excerpt:"SYNTHCREATED"`;
   NO `denial_message`.
   *Rule:* P13 / classify.go — a `tool_result` for a non-subagent node ⇒ ToolCompleted; `is_error:false` is not a denial.

7. **`tool.invoked`** — `node_id:"toolu_SYNTHETIC000000000302"`, `name:"Bash"`, `kind:"native"`,
   `turn_group:"msg_synthetic_0302"`.
   *Rule:* P14 native classification (the second status `requesting` ping is already WORKING ⇒ no SessionState event, P9 "only on transition").

8. **`ask.requested`** — `ask_id:"creq_synthetic_0302"`, `node_id:"toolu_SYNTHETIC000000000302"`,
   `tool_name:"Bash"`, `source:"control"`, `agent_id:"agentsynth0000302"`, `suggestions` present, `pending:false`.
   *Rule:* P8 — second native ask.

9. **`ask.resolved`** — `ask_id:"creq_synthetic_0302"`, `node_id:"toolu_SYNTHETIC000000000302"`,
   `behavior:"deny"`, `message:"Permission to use Bash with command rm -rf /work/scratch has been denied."`.
   *Rule:* P8 / ask.go — `control_response{success…{behavior:"deny"}}` ⇒ AskResolved with the deny `message`.

10. **`tool.completed`** — `node_id:"toolu_SYNTHETIC000000000302"`, `is_error:true`,
    `denial_message:"Permission to use Bash with command rm -rf /work/scratch has been denied."`,
    `output_excerpt` = same bare string.
    *Rule:* P13/P8 — `is_error:true` `tool_result` content is a BARE STRING; this completion is a permission denial so `denial_message` is set (the answered-deny `message` propagates verbatim into the `is_error` body).

11. **`chat.message`** — `message_id:"msg_synthetic_0303"`, `role:"assistant"`, `parent_node_id` empty (root),
    one `blocks[]` entry `{kind:"text", text:"I created the scratch directory; the removal was denied so I left it in place."}`.
    *Rule:* P11 / classify.go — a non-partial assistant text block ⇒ ChatMessage (one event per content block, merge key `message_id`).

12. **`quota.updated`** — passthrough of `rate_limit_info` fields, `semantics:"provisional"` constant.
    *Rule:* OBSERVABILITY §1 QuotaUpdated; P18 (provisional).

13. **`session.state`** — `state:"ATTACHED"`, `reason:"turn_complete"`.
    *Rule:* P9 — a `result` with no open task ⇒ ATTACHED (WORKING→ATTACHED transition).

14. **`session.accounted`** — `outcome:"success"`, `is_error:false`, `num_turns:3`,
    `terminal_reason:"completed"`, `total_cost_usd:0`, `denial_count:1`, `usage`/`model_usage` passthrough.
    *Rule:* P13 — outcome from the closed `result.subtype` set; branch on `subtype`+`is_error`, NEVER `stop_reason`; `denial_count` counts `permission_denials[]`.

Notes:
- The terminal `result.permission_denials[]` carries `toolu_SYNTHETIC000000000302`, whose ask was
  ALREADY resolved (deny) at step 9 — `handleDenials` MUST NOT emit a second `ask.resolved` for an
  already-resolved node (ask.go: `permission_denials[]` drives **unresolved**-denial emission only).
- The relative order of events 13 and 14 (terminal `session.state` vs `session.accounted`) is
  adapter-internal; both MUST be present, emitted from the same `result` record.
- Every event's `Source` carries the uuid(s) of the CC record(s) it was projected from.
