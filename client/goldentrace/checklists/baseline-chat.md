# Checklist — `baseline-chat.cc-wire.ndjson`

Cassette exercises the **plainest happy-path turn**: a status ping, a single assistant turn split
across **two stream lines that share one `message.id`** (a thinking line then a text line), an
inline `rate_limit_event`, and a `result/success` terminal. It pins four things — the **chat merge
key** (`message.id`: N stream lines = one logical message, P11), the **ATTACHED⇄WORKING** toggle
(P9), **quota** passthrough (P18 provisional), and **session.accounted** on a success terminal (P13).

Source: spec fixture table row `baseline-chat`; `classify.go`/`state.go` rules (IMPLEMENTATION-SPEC
§claudecode); PHASE3 P9 (status⇒WORKING / result⇒ATTACHED), P11 (non-partial assistant is
authoritative, one record per content block, merge by `message.id`), P13 (success terminal /
closed-set outcome), P18 (quota provisional); OBSERVABILITY §1 field tables.

Replaying this cassette through the claude-code adapter MUST produce exactly this ordered
`attach.v1` event sequence (Seq strictly monotonic from 1; SessionID constant
`"00000000-0000-4000-8000-000000000010"`; exactly one payload non-nil each):

1. **`session.init`** — `runtime_version:"2.1.173"`, `model:"claude-sonnet-4-6"`, `cwd:"/work"`,
   `permission_mode:"bypassPermissions"`, `api_key_source:"none"`, `tools:["Task","Bash"]`,
   `agent_types` from `init.agents`, `output_style:"default"`; `skills`/`slash_commands` empty.
   *Rule:* OBSERVABILITY §1 init table; `init` is the attach-time snapshot (PROTOCOL-NOTES `init` record).

2. **`session.state`** — `state:"WORKING"`, `reason:"requesting"`.
   *Rule:* P9 — `system/status.status=="requesting"` ⇒ WORKING; SessionState emits only on the
   ATTACHED→WORKING transition (the adapter starts ATTACHED).

3. **`chat.message`** — `message_id:"msg_synth_baseline_0001"`, `role:"assistant"`, `parent_node_id`
   empty (root), one `blocks[]` entry `{kind:"thinking", text:"The user just said hello. I will answer briefly."}`.
   *Rule:* P11 / classify.go — a non-partial assistant `thinking` block ⇒ ChatMessage (one event per
   content block); the `signature` is dropped (not a chat field).

4. **`chat.message`** — `message_id:"msg_synth_baseline_0001"` (SAME id as event 3 — the merge key),
   `role:"assistant"`, `parent_node_id` empty (root), one `blocks[]` entry
   `{kind:"text", text:"Hello! How can I help you today?"}`.
   *Rule:* P11 — the non-partial `assistant` record arrives **once per content block** so the thinking
   line and the text line are two events sharing one `message_id`; consumers merge by `message_id`,
   never assume one stream line = one logical message (OBSERVABILITY §1 line 83).

5. **`quota.updated`** — passthrough of `rate_limit_info`: `rate_limit_type:"five_hour"`,
   `status:"allowed"`, `resets_at` raw (carried verbatim, type unpinned), `is_using_overage:false`,
   `overage_status:"not_in_overage"`; `semantics:"provisional"` constant.
   *Rule:* OBSERVABILITY §1 QuotaUpdated; P18 — quota semantics under load unfixed ⇒ provisional;
   `resets_at` is raw JSON the adapter never reinterprets.

6. **`session.accounted`** — `outcome:"success"`, `is_error:false`, `num_turns:1`,
   `terminal_reason:"completed"`, `total_cost_usd:0`, `duration_ms:2100`, `denial_count:0` (omitted),
   `usage`/`model_usage` passthrough.
   *Rule:* P13 — outcome from the closed `result.subtype` set; branch on `subtype`+`is_error`, NEVER
   `stop_reason`; `terminal_reason` present (`completed`) on the success terminal.

7. **`session.state`** — `state:"ATTACHED"`, `reason:"turn_complete"`.
   *Rule:* P9 — a `result` with no open task ⇒ ATTACHED (WORKING→ATTACHED transition).

Notes:
- **Events 6 then 7 order** is the implemented `handleResult` emission order (state.go):
  `session.accounted` first (terminal accounting), then — there are no denials here — the ATTACHED
  transition. Both MUST be present, projected from the same `result` record uuid.
- **No `tool.invoked`/`tool.completed`, no subagent events, no ask events** appear: this turn is pure
  chat. `tools:["Task","Bash"]` are merely *advertised* in `init`, never called.
- Every event's `Source` carries the uuid(s) of the CC record(s) it was projected from (e.g. event 3
  from `…b2`, event 4 from `…b3`, events 6 and 7 both from the `result` uuid `…b5`).
