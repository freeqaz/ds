# Implementation spec — attach wrapper core + Claude Code adapter + goldentrace harness

**Owner:** Attach & client · **Decisions:** D18, D20, D38, D49, D50 · **Status:** build contract (taskdb 01KTWJ22QR)
**Role:** the binding contract the `goldentrace-adapter-build` workflow implemented against (2026-06-12).
Per-cassette expected-event checklists live in [`checklists/`](checklists/); the protocol rules cited here resolve to the findings docs.

Module: `client/` (`github.com/dream-serpent/dream-serpent/client`, Go ≥1.25, **standard library ONLY** — see client/go.mod header).
Done criterion: a captured CC session stream replays through the adapter and emits well-formed
`dreamserpent.attach.v1` deltas covering chat output, subagent-spawn, and ask events.

## Normative sources, in precedence order

1. `client/goldentrace/PHASE3-FINDINGS.md` — round-3 adapter rules (P8 ask, P9 state, P10 ordering, P11 partials, P13 terminals, P14 classification).
2. `client/goldentrace/PROTOCOL-NOTES.md` — the canonical wire map (already corrected through round 3).
3. `client/goldentrace/PHASE2-FINDINGS.md` — P1 fan-out linkage, P2 nesting/flattening, P4 isReplay, P5 denial recipe, P6.
4. `client/goldentrace/OBSERVABILITY-DESIGN.md` — the event/field tables (§1, §2). **STALE in three spots; PHASE3 wins:**
   - it says P10 ordering is "still-open" → P10 is now VERIFIED safe (seq from stdout arrival order);
   - it says the ask record is "entirely uncaptured" → P8 captured it (control protocol);
   - it says status vocabularies are unenumerated → P9/P13 enumerated the closed sets.
5. `client/wrapper/README.md`, `client/wrapper/adapters/claude-code/README.md`, `client/fixtures/PROVENANCE.md`, `proto/dreamserpent/attach/v1/README.md` — seam/charter rules.

## Hard constraints (every agent)

- **Stdlib only.** No new go.mod entries, no cross-tree imports (the only legal one, proto/gen/go, does not exist for attach yet — do NOT import it, do NOT write .proto files anywhere).
- **No CC-isms outside `client/wrapper/adapters/claude-code/`** (D38). The `attach` package and goldentrace harness must be runtime-ignorant: no CC record names, no `toolu_`/`task_id` vocabulary, no "claude" strings in `client/wrapper/attach/`. The goldentrace replay package may reference the adapter (it replays CC cassettes) but its golden-diff machinery must work for any `[]attach.Event`.
- **The wrapper holds NO approval state** (D18/D45/D53): it emits ask events; it never stores grants, never answers asks itself.
- **Fixtures are synthetic-only (D50):** every `client/fixtures/*.ndjson` starts with the `{"ds_fixture":{"provenance":"synthetic","seam":"attach.cc-wire","created":"2026-06-12","tool":"goldentrace"}}` header line; all ids are obviously synthetic (`00000000-0000-4000-8000-…` uuids, `toolu_SYNTH…`, `msg_synth_…`, hex task ids like `a1a1a1a1a1a1a1a1`); no real paths, costs that look real, or token-shaped strings (`sk-ant-…`, `Bearer …`). Must pass `scripts/check-fixture-provenance.sh`.
- **Never run the `claude` CLI, capture.sh, or any live capture.** Everything is authored from the documented shapes. Never touch `/tmp/cc-daemon-*`, `~/.claude/*`, taskdb, `docs/`, `SUMMARY/INDEX`, or git (no commits, no staging).
- Build gate per change: `cd "$REPO_ROOT/client" && go build ./... && go vet ./... && go test ./...` (also `gofmt -l .` must be empty).
- Match existing repo style: package docs cite D-numbers and doc §s the way existing READMEs/main.go do; comments state constraints, not narration.

## File map and EXCLUSIVE ownership

Phase 1 (foundation) creates every file below with compiling stubs; phase-2 agents then fully
implement ONLY the files in their own row (plus their own `*_test.go`). Never edit another row's files.

| Owner | Files |
|---|---|
| foundation | `client/wrapper/attach/attach.go` (event model, complete — not a stub), `client/wrapper/adapters/claude-code/adapter.go` (Adapter, Feed dispatch, seq/clock, record envelope decode — complete), `client/wrapper/adapters/claude-code/records.go` (wire record structs — complete), `client/goldentrace/replay/replay.go` + `client/goldentrace/replay/golden_test.go` (replay + golden plumbing — complete), stubs for the four area files below |
| impl-classify | `client/wrapper/adapters/claude-code/classify.go` — P14 classification + chat/tool events + partial/stream_event + isReplay handling |
| impl-tree | `client/wrapper/adapters/claude-code/tree.go` — subagent registry, three-key join, spawn/progress/completed/accounted |
| impl-state | `client/wrapper/adapters/claude-code/state.go` — ATTACHED⇄WORKING, terminals, session.accounted, quota |
| impl-ask | `client/wrapper/adapters/claude-code/ask.go` — control protocol, ask.requested/resolved, denials |
| integrator | may touch anything to make the whole build green; generates goldens; updates `client/goldentrace/README.md` skeleton note |

## Package `client/wrapper/attach` (runtime-ignorant event model)

Package doc: the Go shape of the `dreamserpent.attach.v1` events the wrapper emits (D18/D38).
The proto freezes at M0 in `proto/dreamserpent/attach/v1/` (README-reserved); until then this
package is the working model and must not contain a proto body. Field tables follow
`client/goldentrace/OBSERVABILITY-DESIGN.md` §1 with the PHASE3 corrections.

```go
type Type string

const (
    TypeSessionInit       Type = "session.init"
    TypeSessionState      Type = "session.state"
    TypeChatMessage       Type = "chat.message"
    TypeToolInvoked       Type = "tool.invoked"
    TypeToolCompleted     Type = "tool.completed"
    TypeSubagentSpawned   Type = "subagent.spawned"
    TypeSubagentProgress  Type = "subagent.progress"
    TypeSubagentCompleted Type = "subagent.completed"
    TypeSubagentAccounted Type = "subagent.accounted"
    TypeAskRequested      Type = "ask.requested"
    TypeAskResolved       Type = "ask.resolved"
    TypeQuotaUpdated      Type = "quota.updated"
    TypeSessionAccounted  Type = "session.accounted"
)

// Event is the envelope. Seq is adapter-synthesized from stdout arrival order —
// the wire has no monotonic token (PHASE3 P10: verified a safe topological sort
// for the local single-process case). Exactly one payload pointer is non-nil.
type Event struct {
    Seq        uint64    `json:"seq"`
    SessionID  string    `json:"session_id"`
    ObservedAt time.Time `json:"observed_at"`            // adapter clock; deterministic in replay
    Type       Type      `json:"type"`
    Source     []string  `json:"source,omitempty"`        // runtime record uuids this was projected from

    SessionInit       *SessionInit       `json:"session_init,omitempty"`
    SessionState      *SessionState      `json:"session_state,omitempty"`
    ChatMessage       *ChatMessage       `json:"chat_message,omitempty"`
    ToolInvoked       *ToolInvoked       `json:"tool_invoked,omitempty"`
    ToolCompleted     *ToolCompleted     `json:"tool_completed,omitempty"`
    SubagentSpawned   *SubagentSpawned   `json:"subagent_spawned,omitempty"`
    SubagentProgress  *SubagentProgress  `json:"subagent_progress,omitempty"`
    SubagentCompleted *SubagentCompleted `json:"subagent_completed,omitempty"`
    SubagentAccounted *SubagentAccounted `json:"subagent_accounted,omitempty"`
    AskRequested      *AskRequested      `json:"ask_requested,omitempty"`
    AskResolved       *AskResolved       `json:"ask_resolved,omitempty"`
    QuotaUpdated      *QuotaUpdated      `json:"quota_updated,omitempty"`
    SessionAccounted  *SessionAccounted  `json:"session_accounted,omitempty"`
}
```

Payload structs (field names are the JSON contract; keep them runtime-neutral):

- `SessionInit`: `runtime_version`, `model`, `cwd`, `permission_mode`, `api_key_source`,
  `tools []string`, `agent_types []string`, `skills []string`, `slash_commands []string`,
  `mcp_servers json.RawMessage`, `output_style`.
- `SessionState`: `state` (`"ATTACHED" | "WORKING"` — the ONLY two states with a wire source, P9;
  the adapter must never synthesize orchestrator-owned states), `reason` (e.g. `"requesting"`,
  `"task_open"`, `"turn_complete"`).
- `ChatMessage`: `message_id`, `role`, `parent_node_id` (empty ⇒ root), `blocks []ChatBlock`
  where `ChatBlock{kind: "text"|"thinking", text string}`. One event per non-partial assistant
  stream line that carries text/thinking blocks; consumers merge by `message_id` (P11: the
  non-partial record is authoritative and arrives once per content block).
- `ToolInvoked`: `node_id` (the tool_use id), `name`, `kind` (`"native"|"mcp"|"skill"`),
  `server`, `tool` (mcp decomposition), `skill`, `parent_node_id`, `turn_group` (message_id),
  `input json.RawMessage`. NOT emitted for subagent spawns (those are SubagentSpawned).
- `ToolCompleted`: `node_id`, `is_error bool`, `output_excerpt` (first text block, ≤256 runes),
  `denial_message` (set when this completion is a permission denial — the is_error bare-string
  body, P13/P8).
- `SubagentSpawned/Progress/Completed/Accounted`: exactly the OBSERVABILITY-DESIGN §1 tables
  (node_id, task_id, subagent_type, description, prompt_excerpt, task_type, parent_node_id,
  parent_confidence "exact"|"inferred", turn_group; progress: last_tool_name, usage_raw passthrough
  flagged uncharacterized; completed: status/summary/output_file; accounted: agent_id,
  subagent_tokens, tool_uses, duration_ms, output_excerpt, is_error, returned_to, continuation).
- `AskRequested`: `ask_id` (control request_id if present, else tool_use_id), `node_id`
  (= tool_use_id, the correlation key end-to-end, P8), `tool_name`, `input json.RawMessage`,
  `suggestions json.RawMessage` (native channel only), `agent_id`, `source`
  (`"control" | "prompt-tool" | "rearm"`), `pending bool` (true when re-armed from
  `pending_permission_requests[]`).
- `AskResolved`: `ask_id`, `node_id`, `behavior` (`"allow"|"deny"|"cancelled"`),
  `classification` (`user_temporary|user_permanent|user_reject` when known), `message`.
- `QuotaUpdated`: passthrough of `rate_limit_info` fields, plus `semantics:"provisional"` constant
  (P18 open).
- `SessionAccounted`: `outcome` (the result subtype — closed set
  `{success, error_during_execution, error_max_turns, error_max_budget_usd, error_max_structured_output_retries}`, P13),
  `is_error`, `num_turns`, `duration_ms`, `total_cost_usd`, `terminal_reason` (optional — absent on
  budget terminal), `errors []string`, `usage json.RawMessage`, `model_usage json.RawMessage`,
  `denial_count int`. NEVER branch on stop_reason (P9: nondeterministic).

## Package `claudecode` (the adapter — the ONLY runtime-specific code)

```go
type Option func(*Adapter)
func WithClock(fn func() time.Time) Option   // replay determinism
func New(opts ...Option) *Adapter

// Feed consumes one stdout NDJSON line (one CC record) and returns the attach
// events it projects, in emission order. Unknown record types are skipped with
// a recorded warning, never an error (forward-compat: drift is a cassette diff,
// not a crash). A leading {"ds_fixture":…} header line is skipped.
func (a *Adapter) Feed(line []byte) ([]attach.Event, error)
func (a *Adapter) ProcessStream(r io.Reader) ([]attach.Event, error)  // bufio scanner, 10MB max line
func (a *Adapter) Warnings() []string
```

`adapter.go` (foundation) owns: envelope decode (`type`, `subtype`, `uuid`, `session_id`,
`parent_tool_use_id`), the dispatch switch, seq assignment (monotonic uint64 from 1, in emission
order — arrival order is the verified-safe basis, P10), Source stamping, and the shared
`emit(...)` helper. It calls area hooks (methods defined in the area files):

- `classify.go`: `handleAssistant(rec)`, `handleUser(rec)`, `handleStreamEvent(rec)`.
  Rules: classify tool_use by NAME in order — `^mcp__` (split on `"__"` ⇒ ≥3 parts; server = part 1,
  tool = join of rest; single-underscore split is WRONG) ⇒ mcp; `name ∈ {Agent, Task, TaskCreate}`
  with `input.subagent_type` ⇒ subagent (delegate to tree hook); `name == "Skill"` ⇒ skill
  (`input.skill`); else native. Never classify on block keys or `caller.type` (identical across all,
  P14). Tolerate a `ToolSearch` hop whose tool_result carries subtype `tool_reference`. text/thinking
  blocks ⇒ ChatMessage. `user` records: `isReplay:true` ⇒ ACK marker, skip entirely (P4); tool_result
  blocks ⇒ route to tree (if a registered subagent node) else emit ToolCompleted (is_error content is
  a BARE STRING, P13); nested-prompt text records (parent_tool_use_id set) consumed for the tree's
  prompt_excerpt corroboration, no standalone event. `stream_event` ⇒ render channel ONLY: consume,
  never emit canonical events from it, tolerate non-stream records mid-envelope (P11).
- `tree.go`: `handleTaskStarted/Progress/Notification(rec)`, `registerSpawn(block, line)`,
  `handleSubagentResult(block, rec)`. Registry keyed by tool_use_id; join across
  `(tool_use_id, task_id/agentId, message.id)`; spawned = join of spawn block + task_started
  (provisional on first, finalize on join — either order); parent attribution per
  OBSERVABILITY-DESIGN §2 (spawn-line parent_tool_use_id; depth ≤2 "exact", ≥3 "inferred";
  corroborate on result return-target, keep spawn-line value on disagreement); accounted parses the
  `<usage>` trailer (`agentId:` line; `subagent_tokens`/`tool_uses`/`duration_ms`; assert
  agentId == task_id as integrity check → warning on mismatch); results/notifications arrive in
  completion order — correlate by id, NEVER position (P1/P10).
- `state.go`: `handleStatus(rec)`, `handleResult(rec)`, `handleRateLimit(rec)`, plus an
  `openTasks` interface the tree file maintains. WORKING on `status.status=="requesting"` OR any
  open task_*; ATTACHED on a result with no open tasks (P9). Emit SessionState only on transitions.
  `handleResult` emits SessionAccounted (closed-set outcome, optional terminal_reason, never
  stop_reason) and hands `permission_denials[]` to the ask file for unresolved-denial emission.
- `ask.go`: `handleControlRequest(rec)`, `handleControlResponse(rec)`, `resolveFromToolResult(id, isErr, msg)`,
  `handleDenials(denials)`. Native `control_request{subtype:"can_use_tool"}` ⇒ AskRequested(source
  "control", with suggestions/agent_id riders); `control_response{initialize…}` carrying
  `pending_permission_requests[]` ⇒ AskRequested(pending, source "rearm") per entry;
  `control_response{success…{behavior…}}` ⇒ AskResolved (full fidelity). Fallback when no explicit
  response record is on the stream: resolve an open ask from its correlated tool_result —
  is_error:true ⇒ deny (message = body), else allow (P8: answered-deny propagates the message
  verbatim into the is_error tool_result). EXCEPTION — granted-then-failed (#5008): this
  is_error:true ⇒ deny resolution fires ONLY for an *un-granted* ask. An ask already answered ALLOW
  on the control wire (its AskResolved{allow} already emitted by `handleControlResponse`) whose
  tool_result then carries is_error:true is granted-then-failed — the GRANTED tool erroring AT
  RUNTIME, NOT a deny: the grant stands, no second AskResolved is projected, and the failure
  surfaces solely as classify's tool.completed{is_error:true}. `resolveFromToolResult` reads the
  ask's recorded answeredBehavior to tell the two apart; only an un-granted is_error projects deny.
  Open asks left unanswered at terminal ⇒ AskResolved
  behavior "cancelled". Never invent an ask that was never on the wire (headless auto-deny has NO
  ask, P8 — that path is ToolCompleted{denial_message} via classify).

State shared across area files lives on the `Adapter` struct (foundation defines the fields; area
files use them): `registry map[string]*node`, `openTasks map[string]struct{}`, `asks map[string]*ask`,
`working bool`, `initSeen bool`, registries from init (`agentTypes`, `skills` sets for allowlist
checks → warning, not error, on unknown subagent_type).

## Package `client/goldentrace/replay` (the harness)

```go
// Replay drives a CC cassette through the claude-code adapter and returns the
// attach.v1 projection. The ds_fixture header (line 1) is skipped by Feed.
func Replay(r io.Reader) ([]attach.Event, error)
func WriteNDJSON(w io.Writer, evs []attach.Event) error   // one event per line, encoding/json
```

Determinism: `Replay` constructs the adapter with `WithClock` returning
`time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(n) * time.Second)` where n increments
per call — goldens must be byte-stable across runs.

`golden_test.go`: for every `client/fixtures/*.cc-wire.ndjson` (glob from `../../fixtures`), replay
and byte-compare against `client/goldentrace/replay/testdata/<base>.attach.ndjson`; `-update` flag
regenerates (the insta-style refresh flow from the goldentrace README: a protocol change shows up
as a reviewable golden diff, never a silent rewrite). Missing golden + no `-update` ⇒ failing test
with instructions. Also assert per cassette: seq strictly monotonic from 1, session_id constant,
exactly one payload pointer non-nil per event (well-formedness, via a shared `validateEvents` helper).
Goldens live under `replay/testdata/` (NOT a `fixtures/` dir — the D50 gate scans dirs named
`fixtures`; goldens are derived artifacts, not cassettes).

## Fixtures authored (cassette + checklist; goldens generated by the integrator)

Every cassette: header line, then `system/init` (full key set per PROTOCOL-NOTES, synthetic values,
`claude_code_version":"2.1.173"`), then the scenario, then (unless noted) `rate_limit_event` and a
terminal `result`. Shapes must match the documented key sets EXACTLY (the findings docs enumerate
them; when a doc gives a key list, reproduce every key). Each cassette has a checklist in
[`checklists/`](checklists/): the ordered list of attach events the cassette must produce, with the
doc citation justifying each — the integrator validates generated goldens against it, the reviewers
re-validate.

| Cassette (client/fixtures/) | Content |
|---|---|
| `baseline-chat.cc-wire.ndjson` | status ping → assistant thinking line + text line (one message.id, two stream lines) → result/success. Exercises: chat merge key, ATTACHED⇄WORKING toggles, quota, session.accounted. |
| `parallel-fanout.cc-wire.ndjson` | 3 Agent spawns, one message.id, 3 assistant lines (P1); task_started ×3 in spawn order; nested prompts; task_notification + tool_results in REVERSE completion order; `<usage>` trailers with distinct agentId==task_id. |
| `nested-spawn.cc-wire.ndjson` | outer Agent spawn (parent null) → inner spawn line tagged parent_tool_use_id=outer (P2); inner result (parent=outer), outer result (parent=null); task_* for both at root with null parent; task_progress with last_tool_name="Agent" on outer. |
| `ask-control.cc-wire.ndjson` | native control_request{can_use_tool, request_id, permission_suggestions, agent_id, tool_use_id} → control_response{success, behavior:"allow", updatedInput} → tool executes (is_error:false tool_result) → second ask answered deny → is_error:true tool_result (bare string, message verbatim) → result with permission_denials[] carrying that tool_use_id. |
| `denial-headless.cc-wire.ndjson` | NO ask records: assistant Bash tool_use → is_error:true tool_result bare string "…require approval…" → result subtype SUCCESS with permission_denials[] (P5/P8/P13 auto-deny path). |
| `terminal-budget.cc-wire.ndjson` | turn ends in result subtype error_max_budget_usd: is_error true, errors[] free text, NO terminal_reason, NO result field (P13); stop_reason present but arbitrary. |
| `mcp-skill-native.cc-wire.ndjson` | ToolSearch tool_use → tool_result with subtype tool_reference {tool_name}; then `mcp__echotest__echo` call+result; a `Skill` call {skill:"verify"}; a native Bash call+result. Exercises every classification branch incl. the `__` split (tool name containing a single underscore, e.g. `mcp__svc__complete_authentication`). |
| `partial-stream.cc-wire.ndjson` | full stream_event envelope (message_start → block start/delta*/stop ×2 incl. input_json_delta priming-empty first delta → message_delta/stop) with a non-stream assistant record interleaved MID-envelope (P11), followed by the authoritative non-partial records; adapter output must be identical in content to the same turn without partials. |

## Workflow notes

- Phase-2 unit tests: table-driven, in the owner's `*_test.go`, feeding hand-rolled record lines —
  do not depend on fixtures (those are integration-level, via the golden test).
- The integrator updates `client/goldentrace/README.md`'s trailing "Skeleton note" to state what
  now exists (replay harness + golden tests + fixture set; capture.sh pre-existing; nightly canary
  still pending) — 2–4 lines, matching the README's voice, no changelog.
- Excerpt fields: ≤256 runes, append "…" when truncated. Empty/absent wire fields ⇒ omitempty.
- Every emitted event carries Source = the uuid(s) of the CC record(s) that produced it.
