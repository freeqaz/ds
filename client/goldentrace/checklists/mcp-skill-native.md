# Checklist — `mcp-skill-native.cc-wire.ndjson`

Expected `dreamserpent.attach.v1` events, in emission order, when the cassette is
replayed through the claude-code adapter (`replay.Replay`). The integrator
validates the generated golden (`replay/testdata/mcp-skill-native.attach.ndjson`)
against this list; each line cites the rule (IMPLEMENTATION-SPEC / PHASE3 /
PROTOCOL-NOTES / OBSERVABILITY-DESIGN) that justifies it.

Scenario purpose: exercise **every** tool-classification branch (native, MCP,
Skill, native again) plus the `ToolSearch` deferred-tool hop, and prove the
`mcp__` decomposition splits on the **double** underscore (a single-underscore
split is wrong — `complete_authentication` keeps its inner `_`). (P14)

Cassette records (after the `ds_fixture` header): `system/init`,
`system/status:requesting`, an assistant `thinking` line, then five
`tool_use`+`tool_result` pairs (`ToolSearch`, `mcp__echotest__echo`,
`mcp__svc__complete_authentication`, `Skill`, `Bash`), a final assistant text
line, a `rate_limit_event`, and a terminal `result/success`.

Well-formedness invariants the harness also asserts (golden_test `validateEvents`):
seq strictly monotonic from 1; `session_id` constant
(`00000000-0000-4000-8000-000000000003`); exactly one payload pointer non-nil per
event; every event carries `source` = the uuid(s) of the CC record it was
projected from.

Ordered expected events:

1. `session.init` — from `system/init`. Load-bearing payload:
   `model:"claude-sonnet-4-6"`, `permission_mode:"bypassPermissions"`,
   `api_key_source:"none"`, `tools` includes
   `["Bash","ToolSearch","mcp__echotest__echo","mcp__svc__authenticate","mcp__svc__complete_authentication"]`,
   `skills:["verify"]`, `mcp_servers` lists `echotest` + `svc`.
   (SPEC "Fixtures authored": first line is `system/init` full key set; SPEC attach
   model `SessionInit` field table; PROTOCOL-NOTES `init` record key list.)
2. `session.state` — `state:"WORKING"`, `reason:"requesting"`. The
   `system/status:requesting` ping is the WORKING signal; first transition
   ATTACHED→WORKING. (PHASE3 P9: `status.status=="requesting"` ⇒ WORKING; SPEC
   state.go "Emit SessionState only on transitions".)
3. `chat.message` — `message_id:"msg_synthetic_0301"`, `role:"assistant"`,
   `parent_node_id:""` (root), one `blocks[]` entry `{kind:"thinking"}`.
   (SPEC `ChatMessage`: one event per non-partial assistant stream line carrying
   a thinking block; PHASE3 P11 non-partial authoritative.)
4. `tool.invoked` — `node_id:"toolu_SYNTH00000000000301"`, `name:"ToolSearch"`,
   `kind:"native"`, `turn_group:"msg_synthetic_0301"`, `parent_node_id:""`.
   `ToolSearch` is not `^mcp__`, not in `{Agent,Task,TaskCreate}`, not `Skill` ⇒
   native. (PHASE3 P14 classification order; SPEC classify.go.)
5. `tool.completed` — `node_id:"toolu_SYNTH00000000000301"`, `is_error:false`,
   `output_excerpt:"tool_reference"`. The `ToolSearch` `tool_result` carries the
   new subtype `tool_reference` `{tool_name:"mcp__echotest__echo"}`; the adapter
   tolerates the hop and emits a normal completion. (PHASE3 P14 deferred-tool hop /
   `tool_reference` subtype; SPEC classify.go "Tolerate a `ToolSearch` hop".)
6. `tool.invoked` — `node_id:"toolu_SYNTH00000000000302"`,
   `name:"mcp__echotest__echo"`, `kind:"mcp"`, `server:"echotest"`,
   `tool:"echo"`, `turn_group:"msg_synthetic_0302"`. `^mcp__` ⇒ MCP; split on `__`
   (double underscore) ⇒ `["echotest","echo"]`. (PHASE3 P14 `__` split, server =
   part 1, tool = join of the rest; SPEC classify.go.)
7. `tool.completed` — `node_id:"toolu_SYNTH00000000000302"`, `is_error:false`,
   `output_excerpt:"ECHO: ds-ping"`. (SPEC `ToolCompleted`; tool_result first text
   block excerpt.)
8. `tool.invoked` — `node_id:"toolu_SYNTH00000000000303"`,
   `name:"mcp__svc__complete_authentication"`, `kind:"mcp"`, `server:"svc"`,
   `tool:"complete_authentication"`, `turn_group:"msg_synthetic_0303"`. The
   load-bearing case: the `__` split yields tool `complete_authentication` with its
   single inner `_` intact — a single-`_` split would be wrong. (PHASE3 P14
   "tool names contain single underscores"; SPEC classify.go.)
9. `tool.completed` — `node_id:"toolu_SYNTH00000000000303"`, `is_error:false`,
   `output_excerpt:"authenticated"`. (SPEC `ToolCompleted`.)
10. `tool.invoked` — `node_id:"toolu_SYNTH00000000000304"`, `name:"Skill"`,
    `kind:"skill"`, `skill:"verify"`, `turn_group:"msg_synthetic_0304"`.
    `name=="Skill"` ⇒ skill; `input.skill` value is in `init.skills[]`.
    (PHASE3 P14 Skill branch; SPEC classify.go.)
11. `tool.completed` — `node_id:"toolu_SYNTH00000000000304"`, `is_error:false`,
    `output_excerpt:"verify skill loaded"`. (SPEC `ToolCompleted`.)
12. `tool.invoked` — `node_id:"toolu_SYNTH00000000000305"`, `name:"Bash"`,
    `kind:"native"`, `turn_group:"msg_synthetic_0305"`. Falls through to native.
    (PHASE3 P14 "otherwise native"; SPEC classify.go.)
13. `tool.completed` — `node_id:"toolu_SYNTH00000000000305"`, `is_error:false`,
    `output_excerpt:"done"`. (SPEC `ToolCompleted`.)
14. `chat.message` — `message_id:"msg_synthetic_0306"`, `role:"assistant"`,
    one `blocks[]` entry `{kind:"text", text:"all four tool branches exercised"}`.
    (SPEC `ChatMessage` text block.)
15. `quota.updated` — passthrough of `rate_limit_info`
    (`rate_limit_type:"session"`, `status:"allowed"`, `resets_at`,
    `is_using_overage:false`, `overage_status:"none"`), `semantics:"provisional"`.
    (OBSERVABILITY-DESIGN §1 `quota.updated`; SPEC `QuotaUpdated`.)
16. Terminal `result/success` co-emits, from the one `result` record, this pair
    (the adapter chooses their relative seq; validate payload fields + set
    membership, not the inter-order of these two):
    - `session.state` — `state:"ATTACHED"`, `reason:"turn_complete"`. A `result`
      with no open task returns the run-loop to ATTACHED (the WORKING→ATTACHED
      transition). (PHASE3 P9 / §3 mapping "result received AND no in-flight task
      ⇒ ATTACHED"; SPEC state.go.)
    - `session.accounted` — `outcome:"success"`, `is_error:false`, `num_turns:6`,
      `duration_ms:5200`, `total_cost_usd:0`, `terminal_reason:"completed"`,
      `denial_count:0`, with `usage`/`model_usage` passthrough; NOT branched on
      `stop_reason`. (PHASE3 P13 closed-set `outcome`; SPEC `SessionAccounted`
      "NEVER branch on stop_reason".)

Notes for the integrator:
- No `subagent.*`, no `ask.*` events: this cassette has no `Agent`/`Task` spawn
  and no control-protocol records. A namespaced MCP tool must NEVER be classified
  as a subagent spawn (P14 — name `^mcp__`, never `Agent`).
- `mcp__svc__authenticate`/`mcp__svc__complete_authentication` are the injected
  needs-auth tools; they are surfaced as ordinary gated tool calls, never
  auto-invoked by the adapter (P14). Only `complete_authentication` is actually
  called on the wire here.
- If the adapter does not emit a standalone `session.init` event (foundation
  owns that decision), drop event 1 and renumber — the remaining 15+1 events and
  their order are unaffected.
