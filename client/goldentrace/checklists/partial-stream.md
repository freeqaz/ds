# Checklist — `partial-stream.cc-wire.ndjson`

Expected `dreamserpent.attach.v1` events, in emission order, when the cassette is
replayed through the claude-code adapter (`replay.Replay`). The integrator
validates the generated golden (`replay/testdata/partial-stream.attach.ndjson`)
against this list; each line cites the rule (IMPLEMENTATION-SPEC / PHASE3 /
PROTOCOL-NOTES) that justifies it.

Scenario purpose: prove the **partial-message assembly contract** (P11). The
cassette carries a full `stream_event` envelope —
`message_start` → (`content_block_start`/`delta`*/`content_block_stop`) ×2
(block 0 = thinking with `thinking_delta`+`signature_delta`; block 1 = a `Bash`
`tool_use` whose `input_json_delta` opens with the empty priming delta) →
`message_delta` → `message_stop` — with a **non-`stream_event` assistant record
interleaved MID-envelope** (the non-partial thinking block, between block 0's last
delta and its `content_block_stop`), followed by the authoritative non-partial
records (the `tool_use` assistant, the `tool_result`, the final text). 

THE LOAD-BEARING INVARIANT: `stream_event` is a **render channel only** — it MUST
produce **zero** attach events. The projection is **byte-identical in content** to
the same turn replayed without partials (i.e. to a cassette with only the
non-partial `assistant`/`user`/`result` records). Canonical state is built from
the non-partial records; the deltas are a duplicate for live UI. (PHASE3 P11
"non-partial records are authoritative"; SPEC classify.go "`stream_event` ⇒
render channel ONLY: consume, never emit canonical events from it".)

Well-formedness invariants the harness also asserts (golden_test `validateEvents`):
seq strictly monotonic from 1; `session_id` constant
(`00000000-0000-4000-8000-000000000004`); exactly one payload pointer non-nil per
event; every event carries `source` = the uuid(s) of the **non-partial** CC
record(s) it was projected from (never a `stream_event` uuid).

Ordered expected events:

1. `session.init` — from `system/init`. Load-bearing payload:
   `model:"claude-sonnet-4-6"`, `permission_mode:"bypassPermissions"`,
   `api_key_source:"none"`, `tools:["Bash"]`. (SPEC "Fixtures authored": first line
   is `system/init`; SPEC `SessionInit` field table; PROTOCOL-NOTES `init` keys.)
2. `session.state` — `state:"WORKING"`, `reason:"requesting"`. From the
   `system/status:requesting` ping; first transition ATTACHED→WORKING.
   (PHASE3 P9; SPEC state.go "Emit SessionState only on transitions".)
3. `chat.message` — `message_id:"msg_synthetic_0401"`, `role:"assistant"`,
   `parent_node_id:""`, one `blocks[]` entry `{kind:"thinking",
   text:"I will run one native command."}`. Projected from the **non-partial**
   thinking `assistant` record (uuid `…00d7`) that arrives mid-envelope — NOT from
   any `stream_event`. The adapter tolerates this non-`stream_event` record
   straddling the envelope and anchors assembly on `content_block_stop`.
   (PHASE3 P11 "non-`stream_event` records can interleave mid-envelope"; SPEC
   `ChatMessage`; SPEC classify.go "tolerate non-stream records mid-envelope".)
4. `tool.invoked` — `node_id:"toolu_SYNTH00000000000401"`, `name:"Bash"`,
   `kind:"native"`, `turn_group:"msg_synthetic_0401"`, `parent_node_id:""`,
   `input:{"command":"printf hi"}`. Projected from the **non-partial** `tool_use`
   `assistant` record (uuid `…00e0`); shares `message.id` with event 3 (P11(b): the
   non-partial assistant is emitted once per content block, both blocks carrying
   one `message.id` — merge by `message_id`). The reassembled
   `input_json_delta` stream concatenates to exactly this `input`
   (`"" + "{\"command\"" + ": \"printf hi\"}"`), parsed only at
   `content_block_stop`; this equality is the proof the partial path is a faithful
   duplicate, but the event itself comes from the non-partial record.
   (PHASE3 P11 input_json_delta assembly + per-block merge by `message.id`; PHASE3
   P14 native classification.)
5. `tool.completed` — `node_id:"toolu_SYNTH00000000000401"`, `is_error:false`,
   `output_excerpt:"hi"`. From the non-partial `user` `tool_result`.
   (SPEC `ToolCompleted`.)
6. `chat.message` — `message_id:"msg_synthetic_0402"`, `role:"assistant"`,
   one `blocks[]` entry `{kind:"text", text:"hi"}`. From the final non-partial
   text `assistant` record. (SPEC `ChatMessage` text block.)
7. `quota.updated` — passthrough of `rate_limit_info` (`rate_limit_type:"session"`,
   `status:"allowed"`, `resets_at`, `is_using_overage:false`,
   `overage_status:"none"`), `semantics:"provisional"`. (OBSERVABILITY-DESIGN §1
   `quota.updated`; SPEC `QuotaUpdated`.)
8. Terminal `result/success` co-emits, from the one `result` record, this pair
   (the adapter chooses their relative seq; validate payload fields + set
   membership, not the inter-order of these two):
   - `session.state` — `state:"ATTACHED"`, `reason:"turn_complete"`
     (WORKING→ATTACHED on a `result` with no open task). (PHASE3 P9 / §3 mapping;
     SPEC state.go.)
   - `session.accounted` — `outcome:"success"`, `is_error:false`, `num_turns:2`,
     `duration_ms:3100`, `total_cost_usd:0`, `terminal_reason:"completed"`,
     `denial_count:0`, `usage`/`model_usage` passthrough; NOT branched on
     `stop_reason`. (PHASE3 P13 closed-set `outcome`; SPEC `SessionAccounted`.)

Notes for the integrator:
- **Zero events from `stream_event` records.** Every `stream_event` line
  (uuids `…00d2`–`…00df`, plus `message_start`/`message_delta`/`message_stop` and
  both blocks' `content_block_*`) MUST be consumed silently. If any `stream_event`
  projects an attach event, the render-only rule (P11) is violated and the golden
  diverges from the no-partials baseline.
- **The `input_json_delta` first delta is the empty priming string** (`""`); a
  parser that tries to `JSON.parse` before `content_block_stop` will fail on the
  intermediate concatenations by design. Only the final concatenation is valid
  JSON. (PHASE3 P11.)
- No `subagent.*` (all `stream_event.parent_tool_use_id` are null — subagent token
  deltas never stream to parent stdout, P10) and no `ask.*` events.
- If the adapter does not emit a standalone `session.init` event (foundation owns
  that decision), drop event 1 and renumber — the remaining events and the
  zero-from-`stream_event` invariant are unaffected.
