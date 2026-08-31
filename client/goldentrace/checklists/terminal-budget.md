# Checklist — `terminal-budget.cc-wire.ndjson`

Cassette exercises the **budget terminal**: a turn that starts normally (a status ping, one
assistant text line, a second requesting ping while work continues) then ends in a
`result` with `subtype:"error_max_budget_usd"`. It pins the P13 budget-terminal shape —
`is_error:true`, a free-text `errors[]`, **NO `terminal_reason`** (dropped on budget), **NO `result`
field**, NO `api_error_status` — and that the adapter classifies the outcome on `subtype`+`is_error`
and **NEVER** on `stop_reason` (here deliberately `"tool_use"`, the arbitrary non-`end_turn` value
P9 warns about). Also exercises the **repeated requesting ping ⇒ no re-emit** rule (P9: SessionState
on transitions only).

Source: spec fixture table row `terminal-budget`; `state.go`/`classify.go` rules (IMPLEMENTATION-SPEC
§claudecode); PHASE3 P9 (status⇒WORKING, transitions-only; `result.subtype`/`stop_reason` value sets),
P13 (`error_max_budget_usd` drops `terminal_reason`/`result`/`api_error_status`, adds `errors[]`,
`is_error:true`), P18 (quota provisional); OBSERVABILITY §1 field tables.

Replaying this cassette through the claude-code adapter MUST produce exactly this ordered
`attach.v1` event sequence (Seq strictly monotonic from 1; SessionID constant
`"00000000-0000-4000-8000-000000000020"`; exactly one payload non-nil each):

1. **`session.init`** — `runtime_version:"2.1.173"`, `model:"claude-sonnet-4-6"`, `cwd:"/work"`,
   `permission_mode:"bypassPermissions"`, `api_key_source:"none"`, `tools:["Task","Bash"]`,
   `agent_types` from `init.agents`, `output_style:"default"`.
   *Rule:* OBSERVABILITY §1 init table; `init` is the attach-time snapshot (PROTOCOL-NOTES `init` record).

2. **`session.state`** — `state:"WORKING"`, `reason:"requesting"`.
   *Rule:* P9 — the FIRST `system/status.status=="requesting"` ping ⇒ WORKING; SessionState emits only
   on the ATTACHED→WORKING transition.

3. **`chat.message`** — `message_id:"msg_synth_budget_0001"`, `role:"assistant"`, `parent_node_id`
   empty (root), one `blocks[]` entry `{kind:"text", text:"Starting the long analysis pass now."}`.
   *Rule:* P11 / classify.go — a non-partial assistant `text` block ⇒ ChatMessage.

   *(The SECOND `requesting` status ping that follows on the wire produces NO event: the latch is
   already WORKING, and SessionState emits on transitions only — P9. This is the load-bearing
   "no re-emit on a repeated ping" assertion.)*

4. **`quota.updated`** — passthrough of `rate_limit_info`: `rate_limit_type:"five_hour"`,
   `status:"allowed_warning"`, `resets_at` raw, `is_using_overage:false`,
   `overage_status:"not_in_overage"`; `semantics:"provisional"` constant.
   *Rule:* OBSERVABILITY §1 QuotaUpdated; P18 — provisional; `resets_at` carried as raw JSON.

5. **`session.accounted`** — `outcome:"error_max_budget_usd"`, `is_error:true`, `num_turns:2`,
   `duration_ms:3300`, `total_cost_usd:0`, **`terminal_reason` ABSENT/empty** (dropped on the budget
   terminal), `errors:["Exceeded the maximum budget of $0.01 for this run."]`, `denial_count:0`
   (omitted), `usage`/`model_usage` passthrough.
   *Rule:* P13 — `error_max_budget_usd` drops `terminal_reason` and `result`; `Outcome` is
   `result.subtype` verbatim from the closed set; `Errors` passes `errors[]` through; classify on
   `subtype`+`is_error`, **NEVER** on `stop_reason` (the wire `stop_reason:"tool_use"` here is
   arbitrary and MUST NOT influence the projection — P9).

6. **`session.state`** — `state:"ATTACHED"`, `reason:"turn_complete"`.
   *Rule:* P9 — a `result` with no open task returns the loop to ATTACHED (WORKING→ATTACHED
   transition); the terminal is per-invocation, not per-session.

Notes:
- **Events 5 then 6 order** is the implemented `handleResult` emission order (state.go):
  `session.accounted` first, then — no denials here — the ATTACHED transition. Both MUST be present,
  projected from the same `result` record uuid (`…c5`).
- The budget `result` carries **no `result` field and no `terminal_reason`**: `session.accounted`
  MUST therefore omit `terminal_reason` (it is `omitempty`) and there is no chat/text projected from
  the terminal record itself. The non-zero `errors[]` is the only free-text the budget terminal adds.
- **No ask events, no tool events, no subagent events** appear: `permission_denials[]` is empty so
  `denial_count` is 0 and `handleDenials` produces nothing.
- Every event's `Source` carries the uuid(s) of the CC record(s) it was projected from.
