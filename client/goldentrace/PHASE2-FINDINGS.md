<!-- Phase 2 findings — D49 spike round 2. Produced by the cc-subagent-protocol-spike
     workflow (3 plan reviewers + 6 capture agents + 1 synthesizer; ~300k subagent tokens).
     Raw captures live in the job tmp dir and are NOT committed (synthetic-only fixtures, D50).
     Companion: PROTOCOL-NOTES.md (the canonical map, corrected inline by this round). -->

<!-- Main-loop verification notes (added on integration):
     - P2 nesting CONFIRMED against the raw capture: a subagent's nested `Agent` spawn really does
       surface as an `assistant` message tagged parent_tool_use_id=<launcher id>, and both outer's
       and inner's `system/task_*` lifecycle appear at root level. This is the verified refinement
       of Phase-1's "internals opaque" claim.
     - The CLAUDE_BG_ISOLATION provenance uncertainty in §4 is RESOLVED: the value lives in the
       session's dispatch descriptor env block in roster.json, not the live process env. PROTOCOL-NOTES
       has been corrected accordingly.
     - The P6 node-version discrepancy in §4 stands as an open caveat; re-validate the undici proxy
       behaviour on any re-run. -->

---
**Owner:** Attach & client · **Decisions:** D18, D20, D38, D49 · **Captured against:** Claude Code `2.1.173` · **Date:** 2026-06-11
---

# Phase 2 findings

D49 spike — Claude Code subagent-protocol investigation, round 2. Captured against CC `2.1.173`. Builds on the Phase-1 `PROTOCOL-NOTES.md` two-layer model (Layer 1 = in-process `Task`/`Agent` subagents as a stream-json projection; Layer 2 = `claude agents` background daemon over unix sockets). P1–P6 ran; **P7 was not run** (a blocking safety stop from the safety-and-operational-risk reviewer held it back — see §5). What follows is what each capture confirmed or refuted, the still-missing captures the reviewers surfaced, the load-bearing implications for `dreamserpent.attach.v1` (D18/D38) and ds-tlsproxy, and the negative/uncertain results.

---

## 1. What each capture confirmed or refuted

### P1 — Parallel subagent fan-out (Layer 1) — CONFIRMED, with new linkage rules

The Phase-1 expectation (open question #1) holds: **N subagents requested in one assistant turn ⇒ exactly N `Agent` `tool_use` blocks with distinct ids** (3 in → 3 blocks). Concrete rules established:

- **Spawn-block shape.** Wire tool name is `Agent` (not `Task`), input keys `{description, subagent_type, prompt}`, with a sibling top-level field `caller:{type:"direct"}` alongside the `tool_use` block in the assistant content stream line. `subagent_type` is the user-defined agent key and maps 1:1 to each `tool_use.id`. *(P1)*
- **One logical assistant message ≠ one stream line.** All 3 `Agent` blocks shared one `message.id` but were emitted as 3 separate stream-json `assistant` lines (one `tool_use` block per line), with a preceding line on the same `message.id` carrying the thinking block. **Grouping rule: group `tool_use` blocks by `message.id` to reconstruct the logical turn; do not assume one stream line = one message.** *(P1)*
- **Parent→child PROMPT linkage.** Each nested prompt is a `user` message whose `parent_tool_use_id` == the spawning `Agent` `tool_use.id`. Reliable key for attributing a subagent's input to its parent. *(P1)*
- **Child→parent RESULT linkage (asymmetric — important).** The `tool_result` comes back as a `user` message whose **top-level `parent_tool_use_id` is `null`**; you MUST correlate via `message.content[].tool_use_id` == the `Agent` block id. **Do not rely on `parent_tool_use_id` for results.** This asymmetry (prompt carries the parent, result does not) refines the Phase-1 note that `parent_tool_use_id` is "the spine of the whole thing" — it is the spine for *prompts*, not *results*. *(P1)*
- **Lifecycle events / third correlation key.** Each spawn emits `system/task_started` (keys: `description, prompt, session_id, subagent_type, task_id, task_type, tool_use_id, subtype, type, uuid`) and each completion emits `system/task_notification` (keys: `output_file, session_id, status, summary, task_id, tool_use_id, usage, subtype, type, uuid`). Both carry `tool_use_id` == the `Agent` block id; `task_id` (a distinct hex, e.g. `a10a1d5a75d7dd436`) ties the pair **and surfaces as `agentId` inside the `tool_result` metadata trailer** — a third correlation namespace `(tool_use_id, task_id/agentId)`. `parent_tool_use_id` is **absent/null** on all `task_*` events; link them by `tool_use_id`/`task_id`, never by `parent_tool_use_id`. *(P1)*
- **Ordering rule.** Spawn-side records (`tool_use` / `task_started` / nested prompt) interleave in **spawn order**; `task_notification` and `tool_result` arrive in **completion order** (fastest first — here a3→a2→a1, ordered by `duration_ms` 1098 < 3447 < 7451, the reverse of spawn order a1→a2→a3). **Correlate by id, never by stream position.** *(P1)* — This is direct evidence for the ordering question the protocol-completeness reviewer raised (see §2, P10).
- **Accounting location.** `usage.subagent_tokens` was `null` in `task_notification` but populated (1051/1272/1534) inside the `tool_result` `<usage>` trailer. Per-subagent token accounting lives in the result payload, not the notification. *(P1)*

### P2 — Nested subagents (Layer 1) — CONFIRMED nesting works, REFUTED recursive attribution

- **Nesting works and is partially observable.** A subagent (outer) can itself spawn another (inner) via the `Agent` tool, and **the spawn-and-result boundary crossings DO surface in the parent stream** — refuting the strict Phase-1 reading that "subagent internals are opaque." What stays opaque is the *leaf's own model reasoning/reply* (inner's `INNERWORD` turn never appears as a standalone message); only the tool boundary crossings (outer's `Agent`→inner call and inner's returned `tool_result`) are emitted. *(P2)*
- **CRITICAL: `parent_tool_use_id` flattens to ONE level.** Only two distinct `parent_tool_use_id` values exist in the whole stream: `null` (top-level) and `toolu_01TLw8…` (outer's launching id). Inner's own `tool_use.id` is **never** used as a `parent_tool_use_id` (0 occurrences) — inner's spawn and inner's `tool_result` are both tagged with **outer's** id, hoisting the grandchild to the child's level. **Max representable nesting depth via `parent_tool_use_id` alone = 1.** To reconstruct who-spawned-whom beyond depth 1, chain `tool_use_id` (in assistant `tool_use` blocks) ↔ `tool_result.content.tool_use_id`, NOT `parent_tool_use_id`. *(P2)*
- **Return-target rule.** A subagent's `tool_result` is tagged with the `parent_tool_use_id` of the level it returns *to*: inner's result → `parent=outer` (`content.tool_use_id=inner`); outer's result → `parent=null` (`content.tool_use_id=outer`). *(P2)*
- `task_type` observed as `local_agent`; `system/task_progress` (keys `description, last_tool_name, subagent_type, task_id, tool_use_id, usage`) showed `last_tool_name="Agent"` on the outer task — independent confirmation outer invoked Agent to spawn inner. All `task_*` events again carry `parent_tool_use_id=null`. *(P2)*
- The `tool_result` trailer again surfaced `agentId` + a `SendMessage(to: <agentId>)` continuation hint (resumable-handle pattern), consistent with Phase-1. *(P2)*
- **Caveat:** depth 3+ was not tested (inner had `tools:[]`); whether the flatten rule hoists to the *launcher* or to the *nearest emitting ancestor* at depth ≥3 is unknown. *(P2)*

### P3 — Hook lifecycle (`--include-hook-events`) — VALID NEGATIVE RESULT

- `--include-hook-events` is a real, documented flag at 2.1.173 (help: "Include all hook lifecycle events… only works with `--output-format=stream-json`"), and the run satisfied that constraint. **Zero `hook_*` / `PreToolUse` / `PostToolUse` / `Stop` / `SessionStart` records were emitted** — because **no hooks are configured anywhere** (`~/.claude/settings.json` has no `hooks` key; repo `.claude/settings.json` / `settings.local.json` absent; `init` also has no `hooks` key). The flag is **silently inert** when no hooks exist — no warning, no marker. *(P3)*
- **The hook-event schema is therefore still undocumented.** This run cannot confirm hook record shapes; a follow-up with an actual hook configured is required. The capture agent correctly did NOT edit `~/.claude/*` to provoke one (hard constraint 5). *(P3)*
- Useful side-products: full `system/init` key list at 2.1.173 (`agents, analytics_disabled, apiKeySource, claude_code_version, cwd, fast_mode_state, mcp_servers, memory_paths, model, output_style, permissionMode, plugins, product_feedback_disabled, session_id, skills, slash_commands, subtype, tools, type, uuid`), and divergent `assistant` vs `user` record keys (`user` carries `timestamp` + `tool_use_result`; `assistant` carries `request_id`). *(P3)*

### P4 — Stream-json INPUT side (`--input-format stream-json` + `--replay-user-messages`) — CONFIRMED, closes Phase-1 open item #6 (input half)

- **Accepted input envelope (the SDK-driving shape):** one NDJSON object per line, `{"type":"user","message":{"role":"user","content":[{"type":"text","text":"…"}]}}`. Minimal accepted form needs only `type` + `message{role, content[]}`; caller need not supply `uuid`/`session_id`/`parent_tool_use_id` — CC mints them. *(P4)*
- **Replay/ack framing:** with `--replay-user-messages`, the submitted message is echoed on stdout as a `type:"user"` record (no subtype) **before** the assistant turn, carrying `isReplay:true`. **`isReplay===true` is the unambiguous discriminator** for an echoed/acked input vs a genuine user/tool_result record. CC normalizes the bare input into the standard stream-json `user` envelope and stamps server-side `session_id`, `parent_tool_use_id:null`, `uuid`, and an ISO-8601 `timestamp`. *(P4)*
- **Two newly-documented fields** on the replay record not in PROTOCOL-NOTES: `isReplay` (bool) and `timestamp` (ISO string). The replay's `message` has only `{content, role}` — no `id`, no `request_id` — consistent with a client-echoed (not API-originated) message. *(P4)*
- **Linkage:** the replay has `parent_tool_use_id:null` (root-session message) and its `uuid` is never referenced as a parent by any later record. **It is an ACK marker, not a node in the spawn tree** — consumers should skip `isReplay` records when reconstructing model-visible history (or use them to confirm receipt). *(P4)*
- **Caveat:** single text-block input only; multi-block / multiple-line / image / `tool_result`-as-input grammars are uncharacterized. This run used `--permission-mode default` (the recipe omitted bypass) — acceptable since `--tools ""` left nothing to call, but it does not exercise the bypass path. *(P4)*

### P5 — Tool-denial / error framing — REFUTED as written; the denial path was NOT captured

This is the most consequential negative. **P5 did not produce a denial.** With `--tools "Bash" --permission-mode default`, the Bash `tool_use` was **ALLOWED and EXECUTED** (`tool_result` content `"NOPE"`, `is_error:false`, `result.permission_denials: []`, `subtype:"success"`). **An explicit `--tools` allowlist auto-approves the tool even under `--permission-mode default` in headless `-p`, overriding the prompt path.** *(P5)*

- **False-positive trap the client must avoid:** the model's final text was `"NOPE"` — but only because it echoed the command's stdout, *not* because it was blocked (the thinking trace confirms it knew the command succeeded). **Classifying denial on result text alone is wrong; inspect `tool_result.is_error` and `result.permission_denials[]`.** *(P5)*
- **To actually capture a denial**, the tool must NOT be pre-allowed via `--tools`. The methodology-rigor reviewer empirically verified the working recipe: `--tools "Bash" --disallowedTools 'Bash(echo*)' --permission-mode default` with a prompt that strongly compels the attempt, which yields `result.permission_denials=[{tool_name, tool_use_id, tool_input}]` AND a `tool_result` with `is_error:true`, content `"Permission to use Bash with command echo … has been denied."` The prompt wording is load-bearing — denials only populate if the model actually *attempts* the tool. *(P5 capture, methodology-rigor review)*
- **No `is_error:true` `tool_result` was produced anywhere in P5**, so the error-body content shape remains unobserved (the success shape is a bare string `"NOPE"` plus a sibling top-level `tool_use_result:{stdout,stderr,interrupted,isImage,noOutputExpected}`). *(P5)*
- Net: **the `dreamserpent.attach.v1` denial/ask event cannot be sourced from any capture in this round.** This collides directly with the protocol-completeness reviewer's row-5 gap (§2, P8).

### P6 — Proxy / cert-trust + API-call map (Layer 3) — CONFIRMED, validates the ds-tlsproxy design assumptions

**P6 answers the ds-tlsproxy design question:** can our egress gateway sit on CC's outbound path — does CC honor an env-configured proxy and trust an operator-supplied CA without cert-pinning? This is necessary design validation for ds-tlsproxy: the egress gateway can only do credential-swap and secret scanning if the client routes through it and trusts its CA. The capture answers yes on both counts.

- **CC HONORS env `HTTPS_PROXY`/`HTTP_PROXY`:** all 14 outbound flows went through `127.0.0.1:8899` (egress-gateway proxy / TLS-termination point); zero bypassed it. *(P6)*
- **CC does NOT certificate-pin:** every TLS flow was fully TLS-terminated because CC trusted the egress-gateway CA supplied via `NODE_EXTRA_CA_CERTS`. No handshake errors, no cert rejections; the run succeeded (`PONG`). **No `--dangerously*` flag and no `NODE_TLS_REJECT_UNAUTHORIZED=0` were needed** — CC trusts the OS/node CA store + `NODE_EXTRA_CA_CERTS` like an ordinary node app. This is the evidence behind D17/D74 "no baseline client cert-pins." *(P6)*
- **Two hosts:** `api.anthropic.com:443` (13 flows, all 200) and `http-intake.logs.us5.datadoghq.com:443` (1 flow, 202 — Datadog log telemetry via axios). **No statsig, no sentry hosts.** Feature-flag eval (Statsig-style payload) is served from `api.anthropic.com/api/eval/sdk-<id>`, NOT a statsig.com host — so an egress allowlist of `api.anthropic.com` + the datadog intake host covers this scenario. *(P6)*
- **Auth exposure:** the capture host was OAuth-logged-in (subscription auth), so `/v1/messages` carries `Authorization: Bearer sk-ant-oat01-…` (NOT `x-api-key`), confirmed by `anthropic-beta: oauth-2025-04-20`. **The bearer token is readable in cleartext at the TLS-termination point (env proxy + operator-supplied CA)** — the trust-boundary fact that defines ds-tlsproxy's responsibility. (An `ANTHROPIC_API_KEY` box would instead send `x-api-key`; the honor-proxy/no-pin verdict is auth-method-independent, only the header *name* differs.) *(P6)*
- **Correlation:** request header `X-Claude-Code-Session-Id` == the SDK result `session_id`, so wire flows correlate to a run; `x-client-request-id` is per-request. *(P6)*
- **Confound the reviewer flagged was NOT hit here:** the methodology reviewer warned that undici in Node 26 ignores `HTTPS_PROXY` without `NODE_USE_ENV_PROXY=1`, risking a false "pins certs" verdict. The P6 capture observed traffic *did* route through the egress-gateway proxy (14 proxied flows, runtime reported as node v24.3.0 in the X-Stainless headers), so the proxy was demonstrably honored and the "no-pin" verdict is evidence-based, not a silent bypass. *(P6, methodology-rigor review)* — see §4 uncertainty on the node-version discrepancy.

- **Trust-boundary responsibility (ds-tlsproxy):** because the OAuth bearer (or `x-api-key`) is cleartext-readable at the TLS-termination point, ds-tlsproxy — as the operator-run egress gateway — owns this credential trust boundary. This is exactly the condition the credential-swap architecture is designed for: long-lived secrets never enter the VM, only a short-lived session-scoped placeholder does, so what is visible at the TLS-termination point has minimal blast radius. *(P6)*

---

## 2. Still-missing captures (prioritized)

Folded from the protocol-completeness and methodology-rigor reviews. The protocol-completeness reviewer's framing is load-bearing: the plan's own success criterion ("enumerate every `attach.v1` event") is measured against the **doc 15 §6.1 8-row M0 freeze checklist**, and P1–P7 leave several rows without an owning capture. The freeze is one-shot, so a missed field class is a v2-package event.

**P0 — prerequisite fixes to `capture.sh` before any re-run** *(methodology-rigor, empirically confirmed):*
- Add `--no-session-persistence` to the shared `common` flag array — **currently omitted, and confirmed to leak transcripts into the shared `~/.claude/projects/*` index and `sessions-index.json`**, the same store the operator's other concurrent sessions use. This is the one methodology gap that crosses the "do not disturb" guarantee. (Note: P1/P2/P5 capture agents reported they *did* pass `--no-session-persistence` individually; the gap is in the committed `capture.sh`, which is out of sync with the per-agent invocations.)
- Add `< /dev/null` to every non-stream-json scenario (eliminates a 3s stdin-wait stall per run); do NOT add it to the stream-json input scenario (P4), which must keep stdin open.
- Stamp `claude --version` and the resolved model into each capture header so future canary drift is attributable to a version bump vs nondeterminism.
- `capture.sh` has runnable scenarios only for P1/P2-style single-spawn cases; **P3, P4, P5(working), P6, P7 have no scenario in the committed script** — plan and script are out of sync.

**Priority 1 — checklist rows with NO owning capture (do these before declaring the event model complete):**

- **P8 — ASK / APPROVAL capture (non-bypass)** — **freeze row 5, the single most load-bearing miss.** Every scenario except the no-tool baseline ran `bypassPermissions`, which *structurally suppresses the ask prompt*. P5 captured only the post-hoc `permission_denials[]` accounting, not the live interactive `can_use_tool` / `control_request` / approval-pending wire record that carries socket-hold visibility and pending/answered/timeout state. Run `--permission-mode default`/`acceptEdits`/`plan` driving a tool that needs approval, AND/OR feed a `control_request` over `--input-format stream-json` stdin. Capture: the ask record type + keys, its prompt id, the allow/deny/allow-always option set, the answered-vs-timeout/parked framing, any socket-hold field. **Without this the adapter cannot emit the attach.v1 ask event at all.** *(protocol-completeness)*
- **P9 — SESSION-STATE vocabulary enumeration** — **freeze row 3.** The adapter must map CC's own status signal onto the frozen §3 state machine (PENDING/CREATING/READY/ATTACHED/WORKING/SNAPSHOTTING/SUSPENDED/PARKED/…). No P-item enumerates the value set of `system/status.status` (busy/waiting/idle/compacting/…) and `subtype`, nor `result.subtype` error variants, nor `stop_reason`/`terminal_reason` values, nor the *second* status vocabulary on the Layer-2 daemon session (`{pid,cwd,kind,sessionId,status}` from `claude agents --json`). Deliver a CC-status → §3-state mapping table. **Today the CC→§3 mapping is a guess.** *(protocol-completeness)*
- **P14 — MCP / Skill / Plugin tool framing** — `init` advertises `mcp_servers[]`, `skills[]`, `plugins[]`, `slash_commands[]`. Capture how an MCP `tool_use` names itself on the wire (likely `mcp__<server>__<tool>` namespacing), how a Skill invocation frames (tool_use? slash_command record?), and whether these need distinct attach.v1 treatment. **The adapter must not misclassify a namespaced MCP tool as a subagent spawn** (cf. the `Agent` vs `TaskCreate` gotcha). Grounded by the observed P4/P5 surprise that `--tools ""` still left six `mcp__claude_ai_*` auth tools in `init.tools` — MCP tools are injected independently of the `--tools` filter. *(protocol-completeness, corroborated by P4/P5)*

**Priority 2 — closed sets the adapter must switch on:**

- **P13 — `result.subtype` error-variant enumeration.** PROTOCOL-NOTES lists `subtype ("success" | error variants)` with the variants *unenumerated*. Drive runs that terminate in each non-success subtype (tiny `--max-budget-usd`, `api_error_status` set, max-turns, user/tool abort) and enumerate the closed set + accompanying fields (`api_error_status`, `terminal_reason`, `is_error`). *(protocol-completeness)*
- **P12 — `tool_result` error-shape + content-shape matrix.** Capture an `is_error:true` `tool_result` (a failing Bash command) and tool_results whose content is a bare string vs an array vs non-text (image/structured) blocks. **P1 showed an array+`<usage>` trailer; P5 showed a bare string; the error-shaped body is unobserved.** The adapter parses these into distinct attach.v1 result events. *(protocol-completeness, P1/P5)*
- **P11 — partial-message (`stream_event`) assembly rules.** With `--include-partial-messages`, capture the `message_start`/`content_block_start`/`delta`/`stop`/`message_delta`/`stop` sequence and document the reassembly contract: which deltas to coalesce vs emit, how a partial stream relates to the final non-partial assistant record (duplicate vs authoritative), whether a `tool_use` block streams incrementally. *(protocol-completeness)*

**Priority 3 — remaining open freeze rows and accounting:**

- **P10 — ordering / sequence evidence** — **freeze row 1 (projection-resume).** PROTOCOL-NOTES line 143 asserts records "map cleanly to sequence-numbered events," but `uuid` is random v4 and **no monotonic ordering token is observed on the wire**. The adapter must synthesize seq from stdout arrival order, which is only safe if interleaving is causally deterministic. **P1 already supplies partial evidence**: per-agent spawn records interleave in spawn order while results arrive in completion order, so arrival order is *not* spawn order — a dedicated P10 should confirm whether `stream_event` deltas can straddle their parent assistant message and whether parallel results can arrive out of *causal* order. *(protocol-completeness, grounded by P1)*
- **P15 — plan-delta / TodoWrite events** — **freeze row 6 (canvas tile fields).** Capture `ExitPlanMode`/plan-mode approval framing and `TodoWrite`/`Task*` todo-list updates. Doc 17 §5 requires "plan deltas" and "ask pending/answered as read-only state" as canvas tile fields. No P-item touches the plan/todo stream. *(protocol-completeness)*
- **P16 — D78 input-activity / attendedness event shape** — **freeze row 7.** P4 captured the `isReplay` input echo but did not characterize the input-activity event the wrapper must emit on a writer-seat write (proposed default: "any client→session write on the writer seat"). Ground the reserved slot on the `isReplay`/user-message record shape from P4. *(protocol-completeness, builds on P4)*
- **P17 — subagent continuation (`SendMessage`) multi-turn framing** — PROTOCOL-NOTES open item #2. The headless path proved `SendMessage` is gated; capture the continuation record (a `SendMessage` call + a subsequent same-`agentId` result) in an interactive/`--brief` context. The attach.v1 subagent event model (freeze row 4) is incomplete for resumable subagents until this is observed. *(protocol-completeness, PROTOCOL-NOTES)*
- **P18 — `rate_limit_event` + overage framing.** A `rate_limit_event` line appeared inline even on trivial successful runs (P1, P5). Decide whether the adapter surfaces it as an attach.v1 event (it changes session usability) or treats it as accounting-only; capture one under load to fix the `resetsAt`/`overageStatus` semantics. *(protocol-completeness, P1/P5)*
- **P7 (re-scoped) — daemon control protocol + `isolation` value set** — deferred this round (§5). The read-only half (`claude agents --json` session list, `ls`/`stat` socket topology, reading the existing `roster.json` dispatch descriptor's `isolation` field) can run now with no mutation; the private-daemon dispatch half needs a quiesced/separate-uid window. *(safety, methodology)*

---

## 3. Load-bearing implications

### For the `dreamserpent.attach.v1` event model (D18 / D38)

- **Spawn interception (D18) is confirmed sound and now precisely specified.** The `Agent` spawn block (`name="Agent"`, input `{description, subagent_type, prompt}`) carries everything needed to re-host a subagent elsewhere; D18 fan-out-into-VMs remains a one-message-type interception, not a tap. **N-way fan-out is structurally clean** (P1), and **the orchestrator can detect a subagent-spawning-a-subagent** because that boundary crossing surfaces in the parent stream (P2) — relevant if D18 wants to fan out nested spawns too.
- **The adapter's correlation model must be three-keyed, not `parent_tool_use_id`-only.** Phase-1's "`parent_tool_use_id` is the spine" is too strong: it carries *prompt* attribution but is `null` on *results* and on all `task_*` events, and it **flattens nesting to depth 1** (P1, P2). The adapter must maintain a join across `(tool_use_id, task_id/agentId, message.id)` and correlate by id, never by stream position or by `parent_tool_use_id` alone. This is a hard requirement for representing depth ≥2 subagent trees and out-of-order results.
- **Sequencing is synthesized, and the safety of that synthesis is not yet proven** (P10, row 1). P1 shows arrival order ≠ spawn order; the adapter assigns its own monotonic seq from stdout arrival, which is the projection-resume contract — still resting on an unverified causal-ordering assumption.
- **The ask/denial event is currently un-sourceable** (P5 refuted, P8 missing, row 5 open). Because `bypassPermissions` suppresses the ask and an explicit `--tools` allowlist auto-approves, the attach.v1 ask event has no capture behind it. **This is the single biggest gap for the M0 freeze**, and the freeze is one-shot.
- **State-mapping is a guess** (P9 missing, row 3 open) — the adapter cannot yet map CC status onto the frozen §3 machine without the `system/status.status` and `result.subtype` value sets.
- **Newly nailed-down, safe to build on now:** the input envelope and `isReplay` ack discriminator (P4); the `init` snapshot key set at 2.1.173 (P3); the per-subagent `<usage>` accounting source (P1).

### For the ds-tlsproxy pin/proxy question (D17 / D74)

- **This confirms our ds-tlsproxy design assumptions, yes-with-evidence:** CC **honors env proxy** and **does not pin certs** (P6). D17/D74's "no baseline client cert-pins" is confirmed. **ds-tlsproxy does not strictly need a transparent proxy** to sit on CC's outbound path — env `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS` suffices — though the transparent design remains the safe default for apps that ignore env proxies.
- **Egress allowlist guidance:** `api.anthropic.com` + `http-intake.logs.us5.datadoghq.com` cover this scenario; **feature-flags resolve from `api.anthropic.com/api/eval/sdk-*`, not statsig** (P6), so no statsig/sentry host needs allowlisting for this path. Telemetry vendor is **Datadog (us5, via axios)** — flag this against any D17/D74 note that assumed Sentry/Statsig.
- **Trust boundary:** the OAuth bearer (or `x-api-key`) is cleartext-visible at the TLS-termination point; ds-tlsproxy, as the operator-run egress gateway, is in a position to read full credentials and owns that trust boundary. This is the condition the credential-swap architecture addresses — only a short-lived session-scoped placeholder enters the VM, so the blast radius at the TLS-termination point stays minimal (P6).

---

## 4. Negative results & uncertainties

**Confirmed negative results:**
- **P3:** `--include-hook-events` emitted zero hook records — *because no hooks are configured*, not because the flag failed. Hook-event schema remains undocumented; needs a follow-up with a hook configured (blocked by hard constraint 5 / no `~/.claude` edits). *(P3)*
- **P5:** the denial path was NOT captured — an explicit `--tools` allowlist auto-ran the tool under `default` mode (`permission_denials:[]`, `is_error:false`). The plan's P5 method is empirically wrong; the verified fix is `--disallowedTools 'Bash(echo*)'`. No `is_error:true` `tool_result` body was observed anywhere this round. *(P5)*

**Uncertainties:**
- **Single-run-as-truth.** P1/P2/P3/P4/P5/P6 are each n=1. The 1:1 fan-out count, the linkage-key rules, and the no-pin verdict are structural and expected stable; **timing/ordering (reverse completion order in P1) is workload-dependent.** Reviewers recommend running each scenario 2× and diffing the record-type + key sets before promoting any finding to a "rule." *(methodology-rigor)*
- **Model nondeterminism on spawn items.** P1/P2 depend on the model choosing to fan out / nest in one turn (a model decision, not deterministic). "Model declined to fan out" should be classed *inconclusive*, not a negative; assert structurally (count `Agent` blocks, check `parent_tool_use_id` linkage) and retry on wrong-shape turns. *(methodology-rigor)*
- **Node-runtime discrepancy in P6.** The P6 capture's X-Stainless headers report `Runtime-Version: v24.3.0`, while the methodology reviewer states the capture host runs Node v26.2.0 / undici 8.3.0 and warns undici ignores `HTTPS_PROXY` without `NODE_USE_ENV_PROXY=1`. The capture nonetheless routed all 14 flows through the egress-gateway proxy, so the proxy *was* honored here — but the runtime-version mismatch is unexplained and means the undici-proxy confound should be re-validated on any re-run; do not assume `HTTPS_PROXY` alone always routes. *(P6 vs methodology-rigor)*
- **P2 depth ≥3 untested** — whether nesting hoists to the launcher or the nearest emitting ancestor at depth 3+ is unknown.
- **P4 input grammar partial** — only single text-block input characterized; multi-block / image / `tool_result`-as-input not tested.
- **`CLAUDE_BG_ISOLATION` provenance.** PROTOCOL-NOTES claims a dispatched worker's env has `CLAUDE_BG_ISOLATION=none`; the methodology reviewer found only `CLAUDE_CODE_CHILD_SESSION=1` and `CLAUDE_JOB_DIR` in the capturing worker's env. It may be set only on daemon-dispatched workers, not slash-spawned ones — reconcile before P7's `isolation`-enumeration depends on it. *(methodology-rigor)*

---

## 5. Why P7 did not run (safety stop)

The safety-and-operational-risk reviewer set `blocking_safety_stop=true`, so per the workflow's gating P7 (Layer-2 daemon dispatch) was deferred. The reasons are load-bearing for any future P7 window and correct the plan/PROTOCOL-NOTES text:

- **The "other user" / "do-not-disturb" boundary is discipline-only, not OS-enforced.** Concurrent interactive sessions run under **the same uid** as the investigation. The plan's prohibition is the only safeguard; every P7 command is one missing/typo'd `HOME`/`CLAUDE_CONFIG_DIR` away from targeting a live shared daemon.
- **The plan's isolation premise is factually wrong.** A throwaway `HOME` does NOT land sockets in "a different `/tmp/cc-daemon-*` dir" — the path is `/tmp/cc-daemon-<uid>/<instance>` and the uid is fixed, so a private daemon still lands **inside the shared `/tmp/cc-daemon-<uid>/` parent, under a new `<instance>` subdir**. Isolation is at the instance-subdir level, not the directory level the plan claims. PROTOCOL-NOTES/plan text should be corrected to say so.
- **The capturing worker is itself attached to a live instance**, which has connectable `control.sock`/`rv`/`pty`/`spare` sockets and pre-warmed claimable spares — a stray `claim`/`dispatch` would perturb the operator's live work; the daemon also centralizes auth refresh for every concurrent session, so a supervisor collision risks cross-session auth disruption.

**Path forward for P7:** run the **read-only** half now (`claude agents --json` session list, `ls`/`stat` socket topology, read the existing `roster.json` `dispatch.isolation` field — no daemon start, no dispatch, no claim). Defer the private-daemon dispatch to a quiesced/separate-uid (ideally container) window, behind a **fail-closed mechanical gate**: assert `$HOME != <operator home>`, `$CLAUDE_CONFIG_DIR` set and its `~/.claude/daemon` empty pre-start, the printed new instance id `!=` any pre-existing instance id, no socket under a pre-existing instance changed mtime, and the new `supervisorPid != ` the live one — abort hard on any failure. Add an explicit untouchable denylist: any pre-existing `/tmp/cc-daemon-<uid>/<instance>/**` and any pid not spawned by the job. For P6 in any re-run, bind the egress-gateway proxy to a private `127.0.0.1:<high-port>`, set proxy/CA env only in the single throwaway process (never export, never write to `settings.json`), and confirm ≥1 proxied connection so a "no-pin" verdict stays evidence-based.
