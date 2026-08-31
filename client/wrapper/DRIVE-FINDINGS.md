# Drive-direction findings — live-capture record for the write path

**Owner:** Attach & client · **Decisions:** D18, D20, D38, D45, D49, D50, D53, D61, D78, D79 · **Status:** skeleton — pending live capture (`01KTXBG14J`)
**Captured against:** Claude Code `2.1.173` (target; version to be confirmed at capture time)
**Complement to:** [`DRIVE-PROTOCOL.md`](DRIVE-PROTOCOL.md) (the drive-direction design note) and [`../goldentrace/PHASE3-FINDINGS.md`](../goldentrace/PHASE3-FINDINGS.md) (read-direction round 3).
**Tracked in taskdb:** keystone spike `01KTXBG14J` ("Keystone spike: live SDK-host capture in a container"); parent `01KTXBF3YZ` ("Drive-direction thin client").

> **This document is a skeleton.** Every section marked `PENDING LIVE CAPTURE` is intentionally
> empty — the keystone spike (`01KTXBG14J`) is the sole authorized source of live-captured results
> for this document. Do not fill these sections from binary extraction, inference, or prior findings
> alone; they require a real SDK-host driving a real CC process per the
> [`DRIVE-PROTOCOL.md`](DRIVE-PROTOCOL.md) isolation and gating requirements. Fabricating results
> here would defeat the conformance purpose of the harness.

> Raw captures produced by the keystone run will live in the job tmp dir and are NOT committed.
> Only re-authored synthetic cassettes land in `../fixtures/` (D50 — see `PROVENANCE.md`).

---

## Live capture 2026-06-12 — keystone `01KTXBG14J` (summary, runbook, verdict)

**This is the live run the skeleton awaited.** A real Claude Code `2.1.173` was stood up as a
stream-json **SDK host** inside a rootless podman container and driven bidirectionally; the native
control channel was round-tripped for **both an allow and a deny**, sustained multi-turn driving was
demonstrated, and the documented driver shapes were checked against reality. Sections 1–6 and the §7
table above are filled from this run. **4 live sessions; ~$0.12 total spend; all under the
`--model sonnet`, ≤$5/session, ≤4-session rails.**

**How it ran (the as-built rig — differs from the cc_sandbox.sh *plan* in two places, both
documented below as code drift, NOT fixed here per the scope fence):**
- Isolation: rootless podman, `--cap-drop=ALL --security-opt=no-new-privileges`, fresh user
  namespace (default rootless remap: `uid_map 0 1000 1 / 1 100000 65536`), container-local
  `HOME=/home/cc` / `CLAUDE_CONFIG_DIR=/home/cc/.claude`, the in-container `cc-sandbox-entry`
  fail-closed assert **passed** before exec. No host `/tmp/cc-daemon-*` visible.
- Drive: a ~100-line Node host (`~/tmp/ds-keystone/cap/sdk_host_drive.mjs`, raw-class, uncommitted)
  spawned `claude --input-format stream-json --output-format stream-json --verbose --permission-mode
  default --permission-prompt-tool stdio --no-session-persistence --model sonnet --max-budget-usd 1.0`,
  sent the `initialize` control_request, drove input, and answered the native `can_use_tool`.
- API egress: through the box's existing `:18080` CIA monitor as a plain proxy (read-only proxy use,
  daemon never stopped/bound/killed); pasta `--network=pasta:-T,18080` + `HTTPS_PROXY=
  http://127.0.0.1:18080` + `NODE_USE_ENV_PROXY=1` + the mitmproxy CA.

**Code/plan drift discovered (WRITTEN DOWN, not fixed — owner action items):**
1. **`scripts/cc-sandbox/Containerfile` cannot build in a TLS-intercepting environment.** Its
   `RUN npm install -g @anthropic-ai/claude-code@2.1.173` fails `UNABLE_TO_VERIFY_LEAF_SIGNATURE`
   because the Containerfile passes no CA/proxy to npm; in the capture environment every egress is
   TLS-terminated by a local egress gateway. The npm-delivered native binary (an **optional** platform package
   `@anthropic-ai/claude-code-linux-x64`) also arrived **corrupted** (no `package.json`; the ELF
   **Bus-errors on `--version`**). The keystone instead ran the **host's** known-good
   `/opt/claude-code/bin/claude` (same pinned `2.1.173`) mounted read-only into the image — which
   runs cleanly in the container. Owner action: make the Containerfile build CA/proxy-aware, and
   pin/verify the native binary (digest), or vendor it.
2. **`cc_sandbox.sh`'s G1 plan requires `--userns=auto`, which is BROKEN with crun on this kernel
   (7.0.10).** `podman run --userns=auto …` fails `crun: openat /proc/self/cwd: Permission denied`
   and the container never starts. Default rootless podman **already** provides a fresh remapped
   userns (so the `cc-sandbox-entry` fresh-userns assert passes without it). Owner action: relax G1
   to accept the default rootless userns, or gate `--userns=auto` on a crun/kernel probe.
3. **`cc_sandbox.sh`'s `launch_live()` never execs podman by design** — even with `DS_E2E_LIVE=1` it
   prints the plan and `die`s ("manual live launch is operator-driven; nothing was executed
   automatically"). The actual live drive is therefore an **operator-run podman command**, which is
   what the keystone did. This is consistent with the e2e README's "deferred manual live step" — it
   is not a bug, but the doc should be explicit that the script is a planner, not a launcher.
4. **`cia record`/`cia replay` cannot run alongside the protected `:18080` daemon** (`SOCKET_PATH`
   singleton, no override) — §5 record-replay is therefore deferred. Owner action: a per-invocation
   socket-path/db override so a free-port record/replay can coexist with the monitor.

**VERDICT — does the driver's documented `EncodeGrant` shape match reality? ✅ YES, with one fixture
correction elsewhere.** The driver (`adapters/claude-code/driver.go`) emits
`control_response{response:{subtype:"success", request_id, response:{behavior, updatedInput?|message?}}}`
with camelCase `updatedInput`/`updatedPermissions`, omitempty-conditional by allow/deny, and no
top-level `uuid`/`session_id`. **CC accepted exactly this on both the allow and the deny path and
drove the correct outcome** — the documented-not-yet-live-verified `EncodeGrant` shape is
**CONFIRMED correct as-is**; flip its "documented, not-yet-live-verified" banner to verified. The
**inbound** ask decoder needs two corrections (details in §1): `permission_suggestions[]` is
`{type:"addRules", rules:[{toolName,ruleContent}], behavior, destination}` (the existing
`ask-control.cc-wire.ndjson` fixture's `{type:"rule", ruleValue:{…}}` is **wrong**), and
`agent_id`/`classifier_approvable`/`blocked_path`/`decision_reason` are **decision-conditional**
(absent on a simple ask), not always-present. The `initialize` response also carries an
**undocumented** `{commands, agents, models, output_style, available_output_styles, account, pid}`
registry block (§1a) that records.go's `controlResponseBody` does not model.

**Re-authored synthetic cassettes committed** (D50; raw stays under the job scratch dir, never
committed): `../fixtures/drive-native-allow.cc-wire.ndjson`,
`drive-native-deny.cc-wire.ndjson`, `drive-multiturn.cc-wire.ndjson` (see `../fixtures/PROVENANCE.md`).

---

## Re-pin pass — live consolidation 2026-06-12 (`01KTXXFSA4` / `01KTXRHN8T`)

A consolidation pass re-drove the two surfaces the keystone left as the highest-value
live residuals — the `initialize` registry-block shape and the cross-container
forced-drop-then-resume — against real CC `2.1.173` under the proven rails (rootless
podman, `--cap-drop=ALL --security-opt=no-new-privileges`, default rootless userns,
`--model sonnet`, `--max-budget-usd`, egress only through the `:18080` proxy as a
read-only plain proxy — the protected daemon never bound/stopped/touched). **4 live
sessions, ~$0.05 total spend, all under the ≤$5/session and ≤5-session rails.** Raw
captures are raw-class and stay under `~/tmp/ds-keystone/cap-repin/`, never committed.

**1. `initialize` control_response shape — RE-CONFIRMED LIVE.** An initialize-only SDK-host
probe (the minimal `{subtype:"initialize"}` request, no model turn → near-zero spend)
captured the real `control_response`. It **byte-for-shape reproduced** the keystone's
registry block: envelope `{request_id, response, subtype}`; inner
`{account, agents, available_output_styles, commands, models, output_style, pid}`;
`account:{tokenSource:"CLAUDE_CODE_OAUTH_TOKEN", apiProvider:"firstParty"}`; `pid` an int;
`pending_permission_requests[]` / `pending_user_dialog_requests[]` **ABSENT** (the
documented conditional-rider claim holds). The discriminator grammar
(`subtype:"success"` envelope, `request_id` echo join) is confirmed. **One synthetic-
completeness correction, NOT a wire bug:** the live `models[]` objects always carry
`{value, displayName, description, supportsEffort, supportedEffortLevels,
supportsAdaptiveThinking, supportsAutoMode}`, but the prior `drive-native-allow` cassette's
`models[]` object listed only `{value, displayName, description, supportsEffort}` — thinner
than the live shape and thinner than §1a documents. A dedicated re-pin cassette pinning the
COMPLETE registry block is **deferred to the cassette owner**: committing a new
`*.cc-wire.ndjson` under `../fixtures/` auto-requires regenerated goldens under
`../goldentrace/{replay,canary}/testdata/` (the always-on golden suites glob that directory),
which are outside this pass's file fence. The correction is recorded in
`../fixtures/PROVENANCE.md` for the owner to author the fixture + goldens in one reviewed
step; the thinner cassette is left as-is (a valid subset for its allow-path purpose). No
existing cassette byte changed. `available_output_styles` content varies by environment
(`Proactive` was present live) — content, not shape.

**2. Cross-container forced-drop-then-resume — proven over the LIVE CROSS-PROCESS topology;
true cross-CONTAINER UDS remains the documented limitation.** A harness replicating the
`live_drive.go` topology (`NewBridge` + `NewServer` + `ServeBridge` over a real framed UDS,
a thin client + a second READER dialing over the real `SocketTransport`) drove a live Bash-
ask turn end-to-end — **9 `attach.v1` events** (`session.init · chat.message · quota.updated ·
tool.invoked · ask.requested · tool.completed · ask.resolved · chat.message ·
session.accounted`), the native ask **executed live** via the grant→`control_response` path —
then exercised `SocketConn.Resume` over the **live** `frameResume`/`frameResumeReply` wire
codec against a bridge fed by **live CC stdout**: `Resume(0)` backfilled the retained ring
exactly-once-ascending (seqs 6–9 with a 4-deep ring); `Resume(1)` (a span aged out of the
small ring) returned LOUD with `errors.Is(err, ErrResumeWindowExceeded)` **across the wire**,
conn surviving; `Resume(maxSeq)` (caught up) returned an empty span, no error. This is the
first time the resume protocol round-tripped **live-projected** events across a real process
boundary (`socket_test.go` proves it only synthetically).

**What remains UNVERIFIED (documented limitation, no behavior change made):**
- **The server-side outbox OVERFLOW drop** (a slow reader exceeding `socketOutboxDepth=256`)
  was NOT triggered by live event volume — a single live turn emits ~9 events, far below 256,
  and `socketOutboxDepth` is an **unexported** package var only an in-package test can shrink
  (it is documented as such in `socket.go`). The re-pin forced the recoverable gap via the
  **history-ring window** instead (a small `BridgeConfig.HistorySize`), which exercises the
  same `Resume`→`Bridge.ReplayFrom` recovery and the same window-exceeded sentinel live, but
  the *drop trigger* itself stays proven only synthetically (`socket_test.go`
  `withSocketOutboxDepth` over a real UDS, synthetic events). Closing this live needs either an
  in-package live test that shrinks `socketOutboxDepth`, or a >256-event live drive.
- **A true cross-CONTAINER UDS** (the socket *inside* the container namespace) is NOT
  realizable without putting the host-agent inside too, which defeats the fronting design
  (`live_drive.go` topology note); the realized crossing is CC-stdio across the container
  boundary (podman `-i` pipes) + the `attach.v1` UDS across a host **process** boundary — the
  closest realizable D79 tier-2 crossing, and what was proven here.
- **The `frameResumeReply` span-codec re-profile numbers** the hostbridge README "Language
  verdict" asks for on the cross-container carrier were not measured (the recovery span here is
  small — 4 events; a representative profile needs a larger span / many spectators). Recorded
  as a residual on `01KTXXFSA4`; the README verdict edit lands separately with its owner.

**Banners flipped to live-verified this pass:** `driver.go` `EncodeGrant`
"DOCUMENTED, NOT-YET-LIVE-VERIFIED" → live-verified (the keystone confirmed it; the re-pin
re-confirmed the envelope); `records.go` `controlRequestBody` (decision-conditional
`agent_id`/`classifier_approvable`/`blocked_path`/`decision_reason`) and `controlResponseBody`
(pending_* conditional + the still-unmodelled registry block) sharpened with the live evidence.

---

## 1. Native control-channel handshake

> **LIVE — captured 2026-06-12, keystone `01KTXBG14J`.** First live exercise of the native control
> channel. A raw Node stream-json **SDK host** spawned real CC `2.1.173`
> (`--input-format stream-json --output-format stream-json --verbose --permission-mode default
> --permission-prompt-tool stdio`, NO `--allowedTools`) inside a rootless podman container, drove an
> input that compelled a Bash tool, and round-tripped **one allow and one deny** over the native
> channel. Raw captures are raw-class (`~/tmp/ds-keystone/cap/raw-{allow,deny}-GOOD.ndjson`), never
> committed; the re-authored synthetic cassettes are `client/fixtures/drive-native-{allow,deny}.cc-wire.ndjson`.

**The enabling fact (corrects the PHASE3 recon's open question).** A bare stream-json host
**cannot** trigger the native `can_use_tool` channel by sending an `initialize` alone. Two
conditions are jointly necessary: (a) the host registers as a permission responder, which CC's own
SDK does by appending **`--permission-prompt-tool stdio`** to the claude argv (extracted from the
binary: `if (canUseTool) U.push("--permission-prompt-tool","stdio")`; the binary also enforces
"canUseTool callback cannot be used with permissionPromptToolName"), and (b) the tool is **not**
pre-allowed (`--allowedTools Bash` auto-approves and suppresses the ask — PHASE2 P5, reproduced
live: an identical run **with** `--allowedTools Bash` executed Bash with **no** `can_use_tool`
frame). With `stdio` set and no allowlist, the permission decision is delivered to the host as a
`control_request{subtype:"can_use_tool"}` on the **same stdout fd** as the stream-json records, and
the host answers with a `control_response` on stdin. So `--permission-prompt-tool stdio` *is* the
native-channel switch; PHASE3 P8's `mcp__server__tool` route is an alternative delivery, not the
only one.

**`control_request{can_use_tool}` (CC→host) — live key set:**
```
{"type":"control_request","request_id":"<uuid>","request":{
   "subtype":"can_use_tool","tool_name":"Bash","display_name":"Bash",
   "input":{...the tool's full input...}, "description":"...",
   "permission_suggestions":[{"type":"addRules",
       "rules":[{"toolName":"Bash","ruleContent":"mkdir -p /work/scratch"},
                {"toolName":"Bash","ruleContent":"echo seeded *"}],
       "behavior":"allow","destination":"localSettings"}],
   "decision_reason_type":"subcommandResults",
   "tool_use_id":"toolu_…"}}
```
`request_id` is the control join key; `tool_use_id` threads ask → assistant `tool_use.id` → the
`is_error` `tool_result.tool_use_id` → `result.permission_denials[].tool_use_id` (verified
identical on both paths).

**Divergences from the binary-extracted shape (records.go) — load-bearing:**
- **`permission_suggestions[]` has a DIFFERENT shape than the prior fixture.** Live:
  `{type:"addRules", rules:[{toolName, ruleContent}], behavior, destination}`. The pre-existing
  `ask-control.cc-wire.ndjson` fixture used `{type:"rule", behavior, ruleValue:{toolName,
  ruleContent}}` — **that fixture is wrong** on this field. (The `{type:"addRules", rules:[…]}` form
  also appears verbatim in the binary as the `updatedPermissions` the allow path can return.)
- **`agent_id`, `classifier_approvable`, `blocked_path`, and `decision_reason` were ABSENT** on the
  live can_use_tool request. records.go lists them as members of `controlRequestBody`; live they are
  **conditional, not always present** — a decoder must treat them as optional (they are, in the Go
  struct, but the prose/fixtures implied always-present). Only `decision_reason_type` was present
  (value `"subcommandResults"`, not the documented `"not_allowlisted"`).
- The binary still *can* emit the richer fields (their construction is in the binary —
  `permission_suggestions:O, blocked_path:z.blockedPath, decision_reason:yW8(X), …agent_id:K.agentId`),
  so they are populated only when the underlying decision has them (e.g. a path-blocked or
  agent-scoped ask). The keystone's benign-Bash ask did not.

**`control_response` (host→CC) — live, both paths:**
```
allow:  {"type":"control_response","response":{"subtype":"success","request_id":"<uuid>",
            "response":{"behavior":"allow","updatedInput":{...echoed/rewritten input...}}}}
deny:   {"type":"control_response","response":{"subtype":"success","request_id":"<uuid>",
            "response":{"behavior":"deny","message":"<deny reason>"}}}
```
Both were **accepted by CC and drove the expected outcome** (allow → tool executed,
`tool_result.is_error:false`; deny → `tool_result.is_error:true` with the deny `message` verbatim as
content, **and** `result.permission_denials[]` populated while `result.subtype` stayed `"success"`).
The outbound envelope carries **no** top-level `uuid`/`session_id` — CC does not expect them on a
host answer. The field names are **camelCase** (`updatedInput`/`updatedPermissions`) — confirmed
correct; a separate **snake_case** `permission_response{updated_input, permission_updates}` exists in
the binary but belongs to the cloud **PermissionSync** (team) path, NOT this local stdio channel —
do not conflate them.

**`control_cancel_request` — NOT observed live** (no timeout/cancel was forced; the dialog timeout
was set high and every ask was answered promptly). From the binary it is real:
`{type:"control_cancel_request", request_id}` is sent by CC's remote-bridge path, and on dialog
timeout the request resolves as `control_response{…response:{behavior:"cancelled"}}` (the
`behavior:"cancelled"` literal is in the binary's `subtype:"success",…response:{behavior:"cancelled"}`
construction). The driver correctly treats `"cancelled"` as engine-only, unreachable from a human
grant. **Open: a live timeout→cancel round-trip was not captured** (deferred — would need a 5th
session driving the dialog timeout).

**Richer than the prompt-tool route?** On this benign ask the native channel did **not** carry the
extra `agent_id`/`classifier_approvable`/`blocked_path`/`decision_reason` fields PHASE3 P8 said are
native-only — they were simply absent (decision-conditional). So the "native is strictly richer"
claim is **decision-conditional, not unconditional**: the native channel *can* carry them, but a
simple subcommand-approval ask does not.

### 1a. `initialize` handshake and `pending_permission_requests[]`

> **LIVE — captured 2026-06-12.** The `initialize` handshake was exercised on every keystone session.

- **`initialize` IS a `control_request`/`control_response` pair**, host-initiated. The host sends
  `{"type":"control_request","request_id":"<uuid>","request":{"subtype":"initialize"}}` **first**
  (before any input); CC replies with `{"type":"control_response","response":{"subtype":"success",
  "request_id":"<same uuid>","response":{…}}}`. (The binary's full host-side init request can also
  carry `hooks, sdkMcpServers, jsonSchema, systemPrompt, appendSystemPrompt, agents, skills,
  supportedDialogKinds, …`; the minimal `{subtype:"initialize"}` the keystone sent was accepted.)
- **The `initialize` response is RICHER than records.go documents.** Live `response` key set:
  **`[account, agents, available_output_styles, commands, models, output_style, pid]`** — i.e. a
  capability/registry snapshot:
  - `commands[]` (26 entries: every slash command with `name`/`description`/`argumentHint`),
  - `agents[]` (5: subagent types with `name`/`description`/optional `model`),
  - `models[]` (4: `value`/`displayName`/`description`/`supportsEffort`/`supportedEffortLevels`/…),
  - `output_style` + `available_output_styles[]`,
  - **`account:{tokenSource:"CLAUDE_CODE_OAUTH_TOKEN", apiProvider:"firstParty"}`** (the auth source
    the SDK host can read back), and `pid`.
  records.go models the response only as `controlResponseBody{subtype, request_id, response,
  pending_permission_requests[], pending_user_dialog_requests}` — the `commands/agents/models/
  output_style/account/pid` registry block is **undocumented** and should be added if an adapter
  needs the command/agent/model registry from the handshake (it overlaps but is **not identical** to
  `system/init`'s `slash_commands`/`agents`/`tools` arrays — `init` lists *names*, the initialize
  response lists *objects with descriptions*).
- **`pending_permission_requests[]` and `pending_user_dialog_requests[]` were ABSENT** in every
  keystone init response — confirming they are **conditional riders present only on re-attach to a
  session with parked asks**, not always-present fields. (The binary builds them as
  `K.enqueue({type:"control_response",response:{subtype:"success",request_id:$,response:await
  yn9(…), pending_permission_requests:J, pending_user_dialog_requests:X}})` only on a
  pending-redelivery path; the binary comment on `pending_user_dialog_requests` states it is "Sent
  on the `initialize` response … so a client joining an already-initialized session can re-arm
  in-flight dialogs. Receivers must tolerate the same request_id also arriving as a live or replayed
  control_request frame and render it once.") **A re-attach-with-parked-ask capture was not run**
  (it needs two hosts on one session — deferred to the transport-bridge tier `01KTXBGTHF`).
- **`initialize` does NOT interlock with `system/init`.** The control handshake completes (its
  `control_response`) **before** any stream-json input is driven; `system/init` is then emitted
  **per driven `user` input** on the stdout stream (see §3 — a fresh `system/init` appears each
  turn). They are independent channels multiplexed on the same fd.
- **Socket-hold = the open `control_request` itself — CONFIRMED.** There is no separate state field;
  the ask is "held" simply by the host not yet having answered the `control_request`. The tool does
  not execute and no `tool_result` appears until the `control_response` is sent.

---

## 2. Multi-turn and multi-block input grammar

> **PARTIAL LIVE + binary — captured 2026-06-12.** The multi-turn / multi-block-text path was driven
> live; `tool_result`-as-input and images are characterized from the binary's input schema (a
> dedicated capture was not spent — see "Open" below).

- **Multi-block (text) input — ACCEPTED.** A single `user` envelope with two text blocks
  (`content:[{type:"text",text:…},{type:"text",text:…}]`) was driven and CC processed it as one turn
  with no error. The minimal P4 single-block form remains valid; multiple text blocks in one
  envelope are concatenated into the turn.
- **`tool_result`-as-input — shape from the live `tool_result` CC emits + the binary input schema.**
  The block CC *emits* on stdout after an allow is
  `{type:"tool_result", tool_use_id:"toolu_…", content:"…"|[…], is_error:bool}` with a sibling
  top-level `tool_use_result:{stdout,stderr,interrupted,isImage,noOutputExpected}` on the `user`
  record. To *feed one back* the client sends `{type:"user", message:{role:"user",
  content:[{type:"tool_result", tool_use_id:"…", content:[…]}]}}` — the same block keys CC emits
  (`tool_use_id`/`content`/`is_error`); the `tool_use_result` sidecar is CC-minted output, not a
  required input field. **Not exercised live** (no externally-supplied tool_use_id to correlate in a
  one-process drive); marked binary-derived.
- **Image input — block shape from the binary.** The accepted image block is
  `{type:"image", source:{type:"base64", media_type:"image/png", data:"<base64>"}}` (the binary's
  input zod schema carries `data`/`media_type`/`image/png` and a `text`/`image` content union; a
  `mimeType` alias also appears). **Not driven live** (no fixture image; out of the keystone's
  4-session budget).
- **Turn sequencing under an in-flight turn — NOT forced.** The keystone drove the next input only
  *after* a `result` arrived (the safe idiom, §3). Whether an input mid-turn queues vs errors was
  not probed live; the binary's input reader buffers lines, suggesting queue-not-reject, but this is
  **unverified**.
- **`isReplay` ack:** the keystone did **not** pass `--replay-user-messages`, so no `isReplay` echo
  was emitted (CC does not echo input without that flag — consistent with P4). New from the binary
  (not in P4): the replay-echo schema is
  `{uuid, session_id, isReplay: literal(true), file_attachments: array().optional()}` — the
  **`file_attachments`** field is undocumented in PHASE2 P4. A multi-block `isReplay` echo was not
  captured (flag not set).

**Open (deferred, budget):** live `tool_result`-as-input correlation, live image input + its
`isReplay`/`file_attachments` echo, and the in-flight-turn sequencing behavior. None are blockers
for the driver v0 (single-text-block + grant), but they gate the full input-grammar of a
sustained-driving client.

---

## 3. Sustained multi-turn driving

> **LIVE — captured 2026-06-12** (`client/fixtures/drive-multiturn.cc-wire.ndjson`).

- **The CC process STAYS ALIVE between `result` records.** The keystone drove **two** `user` inputs
  into **one** stream-json CC process: input #1 ("reply READY") → assistant `READY` → `result:success`;
  then input #2 ("reply DONE") → assistant `DONE` → `result:success` — **no respawn**, the same
  process served both turns. This is the core sustained-driving result: `--input-format stream-json`
  is a *persistent* SDK-host loop, not a one-shot `-p`.
- **A `result:subtype:success` leaves the session ACCEPTING further input** — it does not terminate
  the stream. The stream closes only when the host closes stdin (or interrupts).
- **The correct client idiom:** inject the next `user` message **after the previous `result`
  arrives**. Driving the next input immediately on `result` worked cleanly every time; no extra
  signal or session-state check was needed.
- **A fresh `system/init` is re-emitted PER driven input.** Each `user` input produced its own
  `system/init` record (same `session_id`, new `uuid`) before that turn's assistant output. So a
  consumer must treat `system/init` as a **per-turn** marker on the drive path, not a once-per-process
  event — an adapter keying "session start" off `init` arrival would over-count on sustained driving.
- **Non-success terminals (`error_max_turns`/`error_max_budget_usd`) — NOT reached live** (the
  prompts were trivial; budget was ample). From PHASE3 P9/P13 the terminal is **per-invocation, not
  per-process**; the binary's persistent loop here corroborates that a non-success `result` would
  end *that turn*, and (open) the client could likely drive a new turn without respawning — **not
  verified live**.
- **`--max-turns`:** not exercised. PHASE3 P9 stands — `2.1.173` has no print-mode `--max-turns`; the
  cap is a stream-json-input concern. Not probed this round.
- **`system/status` between turns:** **none observed** in the idle window between `result` and the
  next input. The only `system/status` seen across all keystone sessions was `requesting` during a
  model call (consistent with PHASE3 P9 — Layer-1 status is a thin "request in flight" ping, no idle
  signal). The idle window is **silent on the wire** — the adapter's ATTACHED⇄WORKING toggle must be
  driven by `result`/`requesting` boundaries, not an idle status (PHASE3 §2 mapping holds).

---

## 4. `SendMessage` subagent continuation (P17)

> **BINARY-CHARACTERIZED, NOT driven live — 2026-06-12.** P17 stays substantially open: a live
> `SendMessage` round-trip was **not** captured (it requires a team/swarm or multi-agent context the
> keystone's single-process Layer-1 drive does not stand up, and it would exceed the 4-session
> budget). What the keystone *did* establish, from the binary and the live `init`:

- **`SendMessage` is a first-class tool in the registry** (it appears in the `init.tools[]` /
  binary tool list alongside `Skill, TaskCreate, TaskGet, TaskUpdate, StructuredOutput`). It was
  **present in `init.tools` on the live keystone box** (the host running this capture advertises
  `Task, TaskCreate, TaskGet, TaskList, TaskOutput, TaskStop, TaskUpdate, Workflow` — a much larger
  task/agent toolset than the container CC's default, which lists only `claude/Explore/general-
  purpose/Plan/statusline-setup` agents and no SendMessage). So **`SendMessage` availability is
  environment/config-gated**, not universal — it surfaces in a **team/swarm** context (the binary
  ties it to `team-lead`/`claude-swarm`/`swarm-view` and the instruction "reply via SendMessage to
  the `from=` address").
- **Continuation addressing:** the binary uses a **`from=`/`to=` address** model — a subagent reply
  is sent "via SendMessage to the `from=` address." This is consistent with PHASE2's observation that
  the `tool_result` `<usage>` trailer surfaces an `agentId` + a `SendMessage(to: '<agentId>')` hint
  (the resumable-handle pattern). The `to:` value is the `agentId`/`from=` address verbatim. **The
  exact wire envelope a driver sends — a normal `user` input carrying a `SendMessage` `tool_use`, vs
  a control-channel frame — was NOT captured live and remains the open half of P17.**
- **Not answered live:** whether a resumed subagent retains context, the resulting stream-json
  lifecycle (`task_started`/`task_notification` vs continuation thread), and any `agentId` lifetime
  cap. These need the team/swarm context, which the keystone container CC does not have. **Carried
  forward to the driver/transport tier** (`01KTXBG15F`/`01KTXBGTHF`) where a multi-agent host exists.

**Verdict on P17:** remains **OPEN**. The keystone narrowed it (SendMessage is config/team-gated; the
`from=`/`to=` address is the `agentId`) but did not close the wire-shape capture.

---

## 5. Record-replay determinism evidence

> **DEFERRED — environmentally BLOCKED, 2026-06-12.** The CIA record→replay loop could **not** be
> run during the keystone, for a hard environmental reason, recorded here for the operator.

- **Blocker: `cia record`/`cia replay` are singletons that refuse to start while any CIA daemon
  socket exists.** `cli.py` gates both on `if SOCKET_PATH.exists(): … "A CIA daemon is already
  running. Stop it first ('cia stop')"`. The capture host had a **pre-existing shared CIA monitor
  daemon on `:18080`** that the keystone is forbidden to `cia stop`. The
  socket path (`~/.cia/cia.sock`) is global with no per-invocation override flag, so a parallel
  record/replay daemon on a free port (8099) **cannot** be started without taking down the protected
  daemon. The keystone therefore captured the **drive protocol** (the stdin/stdout control channel,
  which is what gaps 1–3 need) **directly via its own frame log**, and did not produce a CIA
  cassette.
- **What an operator must do to close §5:** in a window where the shared `:18080` daemon is
  quiesced (or on a box without it), run the documented loop from `cia/docs/record-replay.md` on a
  free port: `cia record --cassette ~/.cia/cassettes/keystone-allow.json --proxy-port 8099` paired
  with the keystone drive container pointed at `:8099`, then `cia replay … --strict` with
  `ANTHROPIC_API_KEY`/`CLAUDE_CODE_OAUTH_TOKEN` unset to prove cred-free zero-egress. The keystone's
  `sdk_host_drive.mjs` harness (under the keystone job scratch dir) is the ready driver for both legs.
- **Partial evidence the keystone *does* provide for determinism scoping:** across the four live
  sessions, `session_id`/`uuid`/`request_id`/`tool_use_id` were all fresh random per run (assert
  id-relative, never literal — confirmed necessary); `total_cost_usd` on the wire was `0` (cost is
  carried in the API plane, not stdout) while real cost was ~$0.017/session; `duration_ms`/
  `duration_api_ms` varied run-to-run (do not assert). The control-channel round-trip is
  **structurally reproducible** (same frame sequence every allow/deny run) — the piece replay would
  freeze is only the *model's choice to call the tool*, which is exactly what a recorded cassette
  pins.
- **Residual-nondeterminism inventory (for the eventual conformance suite):** fresh
  `session_id`/`uuid`/`request_id`/`tool_use_id`/`agent_id` per run; `permission_suggestions[]`
  *content* (the model/heuristic-derived rule strings can vary with the command); the model's
  decision to call a tool at all (frozen only under replay); `pid` in the init response; timing
  fields. Everything else in the control round-trip (frame types, ordering, `behavior`
  propagation, `permission_denials[]` correlation) was stable across runs.

---

## 6. Ask-event adapter rules (confirmed live)

> **LIVE — confirmed 2026-06-12.**

- **Transport: multiplexed on the SAME stdin/stdout pair as stream-json — NOT a side fd or socket.**
  The `control_request{can_use_tool}` arrived on the **same stdout** the `assistant`/`user`/`result`
  records use, interleaved between them; the host's `control_response` went on the **same stdin** the
  `user` inputs use. A single line-delimited NDJSON reader/writer pair carries both stream-json
  records and control frames; discriminate by `type` (`control_request`/`control_response` vs
  `assistant`/`user`/`system`/`result`). This is the cheapest possible transport for the adapter —
  no extra fd to manage.
- **Correlation: the native ask uses the SAME `tool_use_id` thread** as the assistant `tool_use.id`,
  the `tool_result.tool_use_id`, and `result.permission_denials[].tool_use_id` — verified identical
  end-to-end on both allow and deny. The control *envelope* additionally carries a `request_id`
  (the `control_response` join key); `tool_use_id` is the cross-record (attach.v1) correlation key,
  `request_id` is the control-channel answer key. Both are needed (the driver already separates
  them: `EncodeGrant` joins on `request_id`, bookkeeping on `tool_use_id`).
- **Unblock signal after `control_response`:** on **allow**, CC emits the tool's `tool_result`
  (`user` record, `is_error:false`) and proceeds to the next assistant turn — i.e. a **new
  `tool_result` (user) record** is the unblock signal, not a status ping. On **deny**, CC emits the
  `tool_result` with `is_error:true` + the deny `message` and the turn proceeds to the
  model's recovery text. No `system/status:requesting` was emitted *as* the unblock signal (the
  `requesting` ping precedes the model call, not the tool unblock).
- **Raising an ask pauses tool execution, not the whole stdout stream.** Between the
  `control_request` and the host's `control_response`, **no `tool_result` for that tool appears** and
  the turn cannot advance — but stdout is not globally frozen (other already-emitted records had
  already flushed). The "hold" is the open `control_request` (§1a). The adapter must answer (or the
  dialog timeout fires → `behavior:"cancelled"`) for the turn to complete.

---

## 7. Freeze-row coverage after live capture

This table will be updated by the keystone (`01KTXBG14J`) to record which doc 15 §6.1 M0 rows
the drive-direction captures close. Fields that depend on these captures are marked below; the
table starts from the PHASE3 freeze-row status (see `PHASE3-FINDINGS.md` §3).

| # | Field class | Drive-direction dependency | Status after keystone |
|---|---|---|---|
| 1 | Per-event sequence numbers | Sustained multi-turn drive (§3) — confirm single-writer guarantee holds across turns | **LIVE-confirmed** — one process, single stdout writer, control frames interleave on the same fd; per-turn `system/init`; no monotonic wire seq (PHASE3 P10 stands), arrival-order synthesis safe across turns |
| 2 | One-writer / N-reader shape | Transport bridge (`01KTXBGTHF`) — out of scope for keystone | not this capture |
| 3 | Full §3 state vocabulary | Multi-turn idle signal (§3) — what does status emit between turns? | **LIVE-confirmed (Layer-1 half)** — idle window is **silent**; only `status:requesting` during a model call; ATTACHED⇄WORKING toggles on `result`/`requesting` (PHASE3 §2 mapping holds) |
| 4 | Subagent-tree / spawn events | Already Owned in PHASE3 (read side); the drive side only re-hosts a spawn, no new wire shape | not this capture |
| 5 | Ask-prompt / approval events | Native control-channel handshake (§1/§6) — confirm over live channel | **LIVE-OWNED** — native `can_use_tool` control_request + allow/deny `control_response` round-trip captured; transport = same stdin/stdout; socket-hold = open request; correction to `permission_suggestions[]` shape (§1) |
| 6 | Canvas tile: plan deltas | Plan-delta / `ExitPlanMode` / `TodoWrite` — still open from PHASE3; keystone may close it | **still open** — ask read-only state now live (§1/§6); plan-delta/`ExitPlanMode`/`TodoWrite` half **not captured** this round |
| 7 | D78 attendedness / input-activity | Multi-turn input shape (§2) — writer-seat write event shape | **partial** — the writer-seat write event is the `user` input frame (§2/§3); multi-block accepted; `isReplay`/`file_attachments` echo shape from binary (flag not set live) |
| 8 | D79 transport-ambivalent handle | Transport bridge (`01KTXBGTHF`) — orchestrator/handle concern, not a keystone wire capture | not this capture |

---

## Wave status — drive-wave integration (2026-06-12)

What the drive-wave landed against this document, and what it still awaits. No live capture
happened this wave (hard rule: no live `claude`/`cia`/`podman` runs); everything below was built
against the documented P4/P8 wire shapes and synthetic fixtures, the way the read-side adapter was.

- **Landed — driver v0** (`01KTXBG15F`, `client/wrapper/adapters/claude-code/driver.go`): the
  inverse adapter — `attach.v1` input/grant → CC stream-json `user` input (P4 single-text-block,
  proven live in PHASE2) + native `control_response` (P8 — structured from the binary-extracted
  shapes and explicitly marked documented-not-yet-live-verified). Holds no approval state
  (D45/D53): a grant is a pure function input, never stored.
- **Landed — this skeleton** (`01KTXGP7MY`, re-land): the question set and freeze-row table above;
  every `PENDING LIVE CAPTURE` section remains intentionally empty.
- **Landed — the live-tier alignment** (`01KTXGPXSM`): `client/goldentrace/e2e/` (the
  `SandboxArgv` script-CLI contract, the deadlock-safe concurrent drive pump, offline-only tests),
  `scripts/cc_sandbox.sh` (gate-then-launch G0–G7 behind the single `DS_E2E_LIVE=1` gate;
  `CC_SANDBOX_LIVE` retired), and `scripts/cc-sandbox/` (the pinned CC `2.1.173` Containerfile +
  the in-container runtime assert). See [`../goldentrace/e2e/README.md`](../goldentrace/e2e/README.md).
- **Superseded, not lost:** the wave's original `e2e-harness` and `container-gate` branches
  (tasks `01KTXBGTJA`, `01KTXBG14J`) conflicted add/add with the alignment branch, which
  re-authors the same paths off the same base and folds their follow-ups; their content is carried
  forward by the alignment branch, and both tasks are marked blocked in taskdb with the merge
  evidence attached as notes.
- **Still pending — the captures themselves.** Sections 1–6 and the §7 freeze-row table stay
  `PENDING LIVE CAPTURE`. The keystone's live run is the deferred manual step in
  [`../goldentrace/e2e/README.md`](../goldentrace/e2e/README.md) ("The deferred manual live
  step"), armed only by an operator setting `DS_E2E_LIVE=1` — no CI or `go test` path can reach it.

---

## Wave status — drive-w2 integration (2026-06-12)

The second drive wave, built — like the first — entirely against documented wire shapes and
synthetic fixtures (hard rule: no live `claude`/`cia`/`podman` runs in the fleet). Two units
merged on `drive-w2-integration`; three are blocked on add/add merge conflicts with the merged
units (each green in isolation); three are deferred to the next loop wave. No live capture
happened this wave — sections 1–6 and the §7 freeze-row table above remain `PENDING LIVE CAPTURE`.

- **Landed — M0 host-agent transport bridge** (`01KTXBGTHF`, `client/hostbridge/` +
  `client/cmd/ds-hostbridge/`): DRIVE-PROTOCOL.md tier 2 realized synthetically. The D79
  `AttachHandle` (`session_uuid`, `endpoints`, `auth`, `role`, `expires_at`) is declared
  **locally in Go** (`handle.go`) because `attach.v1` is README-only at M0 — no proto stub
  bodies before the freeze (`proto/FREEZE.md`). Server-side D61 WRITER/READER seat arbitration
  at the `WatchSession`-style terminator (second WRITER rejected, READER writes refused, seat
  frees on detach), constant-time handle-auth + expiry validation, the goroutine-per-stream
  stdio pump with subscriber fan-out, and the loopback transport for fixture-fed tests. The
  read/write halves are **imported verbatim** from `adapters/claude-code` (Adapter/Driver) —
  no second copy of any shape. The real-container path is `DS_E2E_LIVE`-gated (`live.go`),
  a documented deferred manual step.
- **Landed — the tier-2 byte-bridge language verdict** (recorded in
  `client/hostbridge/README.md` §"Language verdict", closing DRIVE-PROTOCOL.md's "record the
  verdict when tier 2 lands"): **stays Go** at M0; the Rust escape hatch is profiling-gated,
  to be revisited with measurement, never up front.
- **Landed — goldentrace spawn-path + perturbation hardening** (`01KTWJ24P8`,
  `client/goldentrace/replay/`): `TestSpawnPathProjections` (the doc 06 §2.2 obligation that
  fixtures cover the subagent-spawn path, not just chat deltas — freeze row 4's read side),
  `TestPerturbationDriftIsCaught` (a self-test proving the goldens actually catch
  control-channel and accounting-trailer drift, so a green suite is evidence, not absence of
  assertions), and the `client/goldentrace/README.md` replay-suite/determinism documentation.
- **Blocked at merge — three add/add conflicts**, all green in isolation, all overlapping the
  merged units on files newly created off the same base (declared disjoint, weren't):
  `01KTXMASVK` (framed UDS/socket transport — a second, competing realization of
  `client/hostbridge/{README.md,live.go,loopback.go,server.go}`), `01KTXMBBZX`
  (resume-from-seq READER recovery — parallel `bridge.go`/`bridge_test.go`/`loopback.go`),
  and `01KTXMD7ZJ` (extended perturbation drift classes — a second
  `replay/perturbation_test.go`). Each needs hand reconciliation onto the merged code, not a
  re-merge; the merge evidence is attached as taskdb notes on each task.
- **Deferred to the next wave:** `01KTXMCQ` (depth-3 nested-spawn cassette +
  `parent_confidence: inferred` golden), `01KTXMC3` (the operator-run `DS_E2E_LIVE` tier-2
  validation runbook — dep-gated on the socket-transport reconciliation), `01KTXMDW`
  (mirror the read-side spawn assertions onto the driver write path).
- **What this means for the §7 table:** rows 2 (one-writer/N-reader) and 8 (D79 handle
  fields) now have an **executable synthetic realization** in `client/hostbridge` — the M0
  shapes are exercised in code, but "not this capture" stands: nothing here is live-verified,
  and the keystone (`01KTXBG14J`) remains the sole authorized source for filling sections 1–6.

---

## Cross-references

- Drive-direction design (the plan this fills): [`DRIVE-PROTOCOL.md`](DRIVE-PROTOCOL.md)
- Live-drive harness (where these captures run): [`../goldentrace/e2e/README.md`](../goldentrace/e2e/README.md)
- Read-direction rounds 1–3: [`../goldentrace/PROTOCOL-NOTES.md`](../goldentrace/PROTOCOL-NOTES.md), [`../goldentrace/PHASE2-FINDINGS.md`](../goldentrace/PHASE2-FINDINGS.md), [`../goldentrace/PHASE3-FINDINGS.md`](../goldentrace/PHASE3-FINDINGS.md)
- Keystone taskdb entry: `01KTXBG14J` ("Keystone spike: live SDK-host capture in a container")
- Parent workstream: `01KTXBF3YZ` ("Drive-direction thin client") under Client Experience
- Fixture provenance: [`../fixtures/PROVENANCE.md`](../fixtures/PROVENANCE.md) (D50 — captures stay in job tmp, only synthetic cassettes land in git)
- Freeze checklist: `docs/15-orchestrator-design.md` §6.1 (8-row M0 freeze)
- Decisions: `docs/04-architecture-overview.md` §6 (D18/D20/D38/D45/D49/D50/D53/D61/D78/D79)
