# Checklist — `denial-headless.cc-wire.ndjson`

Cassette exercises the **headless auto-deny** path (P5/P8/P13): plain headless `-p` with NO
permission responder registered, so there is **NO ask record on the wire**. The engine resolves
the permission internally and returns an `is_error:true` `tool_result` whose content is a
**bare string** ("…require approval…"); the terminal `result` keeps `subtype:"success"` and
records the denied `tool_use_id` in `permission_denials[]`.

Source: spec fixture table row `denial-headless`; `ask.go`/`classify.go` rules (IMPLEMENTATION-SPEC);
PHASE2 P5 (denial recipe / `permission_denials[]` shape), PHASE3 P8 (no ask on headless `-p`),
P13 (denial keeps `subtype:success`, `is_error:true` body is a bare string).

Replaying this cassette through the claude-code adapter MUST produce exactly this ordered
`attach.v1` event sequence (Seq strictly monotonic from 1; SessionID constant; one payload non-nil each):

1. **`session.init`** — `runtime_version:"2.1.173"`, `model`, `cwd`, `permission_mode:"default"`,
   `api_key_source:"none"`, `tools:["Bash"]`, `agent_types` from `init.agents`.
   *Rule:* OBSERVABILITY §1 init table; `init` is the attach-time snapshot (PROTOCOL-NOTES `init` record).

2. **`session.state`** — `state:"WORKING"`, `reason:"requesting"`.
   *Rule:* P9 — `system/status.status=="requesting"` ⇒ WORKING; emit SessionState only on the ATTACHED→WORKING transition.

3. **`tool.invoked`** — `node_id:"toolu_SYNTHETIC000000000401"`, `name:"Bash"`, `kind:"native"`,
   `turn_group:"msg_synthetic_0401"`, `input` = the Bash input.
   *Rule:* P14 — `Bash` ⇒ native; classify on name, never `caller.type`.

4. **`tool.completed`** — `node_id:"toolu_SYNTHETIC000000000401"`, `is_error:true`,
   `denial_message:"The following parts of your command require approval: writing to /work/scratch/out.txt. Re-run with the operation pre-approved to proceed."`,
   `output_excerpt` = same bare string.
   *Rule:* P13/P8 — `is_error:true` `tool_result` content is a BARE STRING; this completion IS the denial
   (`denial_message` set) — and crucially there is **NO** preceding `ask.requested`/`ask.resolved`:
   headless auto-deny has no ask on the wire (P8), so the denial surfaces as `tool.completed{denial_message}` via classify, NOT as an ask pair.

5. **`chat.message`** — `message_id:"msg_synthetic_0402"`, `role:"assistant"`, `parent_node_id` empty (root),
   one `blocks[]` entry `{kind:"text", text:"The redirect needs approval, so I did not write the file."}`.
   *Rule:* P11 / classify.go — a non-partial assistant text block ⇒ ChatMessage.

6. **`quota.updated`** — passthrough of `rate_limit_info` fields, `semantics:"provisional"` constant.
   *Rule:* OBSERVABILITY §1 QuotaUpdated; P18 (provisional).

7. **`session.state`** — `state:"ATTACHED"`, `reason:"turn_complete"`.
   *Rule:* P9 — a `result` with no open task ⇒ ATTACHED (WORKING→ATTACHED transition).

8. **`session.accounted`** — `outcome:"success"`, `is_error:false`, `num_turns:2`,
   `terminal_reason:"completed"`, `total_cost_usd:0`, `denial_count:1`, `usage`/`model_usage` passthrough.
   *Rule:* P13 — a denial KEEPS `subtype:"success"` while populating `permission_denials[]`; outcome from the
   closed `result.subtype` set; branch on `subtype`+`is_error`, NEVER `stop_reason`; `denial_count` counts `permission_denials[]`.

Notes:
- **No `ask.requested` and no `ask.resolved` events appear anywhere in this cassette** — that is the
  load-bearing negative this fixture pins (P8). `handleDenials` MUST NOT synthesize an ask/AskResolved
  for the `permission_denials[]` entry: "never invent an ask that was never on the wire" (ask.go);
  the denial is already surfaced as the `tool.completed{denial_message}` at step 4.
- The relative order of events 7 and 8 (terminal `session.state` vs `session.accounted`) is
  adapter-internal; both MUST be present, emitted from the same `result` record.
- Every event's `Source` carries the uuid(s) of the CC record(s) it was projected from.
