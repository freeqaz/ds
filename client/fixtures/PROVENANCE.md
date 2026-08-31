# Fixture provenance — D50

**Rule: if it is in git, it is synthetic.** No exceptions.

D50 (doc 04 §6) tags every test
fixture with a provenance class:

| Tag | Meaning | Where it may live |
|---|---|---|
| `synthetic` | Authored or generated; contains no real user/partner data, no real credentials | **Here** (version control), CI, the D26 public suite |
| `dogfood` | Recorded from internal use | Segregated internal store ONLY — never this repo |
| `partner-consented` | Recorded under design-partner consent/retention/revocation terms | Segregated internal store ONLY — never this repo |

Shipped suites run entirely on synthetic fixtures with zero data egress;
clean-by-construction beats scrub-and-hope (D50 rationale).

## Tag format

Every NDJSON cassette in this directory MUST begin with a header record as
its first line:

```
{"ds_fixture":{"provenance":"synthetic","seam":"attach.cc-wire","created":"YYYY-MM-DD","tool":"goldentrace"}}
```

- `provenance` is the D50 tag; in this directory the only legal value is
  `synthetic`.
- `seam` names what the cassette pins (e.g. `attach.cc-wire`,
  `orchestrator.watchsession`).
- Non-NDJSON fixtures carry the same JSON object in a `<name>.provenance`
  sidecar file.

CI (`.github/workflows/fixtures-provenance.yml`) scans fixture directories
and fails on a missing header or any value other than `synthetic`. Recorded
(dogfood/partner) cassettes are reviewed in the internal store and only ever
enter this repo by being *re-authored* as synthetic equivalents.

## Committed cassettes

Every cassette below is `synthetic` (re-authored, never a raw capture) and
carries the `ds_fixture` header on line 1. Each pins a distinct CC-wire shape
the goldentrace harness replays (D49):

| Cassette | What it pins |
|---|---|
| `baseline-chat` | A plain multi-turn chat with no spawns. |
| `partial-stream` | Mid-stream partial / incremental assistant blocks. |
| `denial-headless` | A headless permission denial path. |
| `ask-control` | The native control-channel ask/approval flow. |
| `mcp-skill-native` | MCP skill invocation over the native channel. |
| `terminal-budget` | A budget-terminal session outcome. |
| `subagent-spawn` | The accounting-only branch (missed task lifecycle). |
| `task-todo-no-subagent` | The spawn **negative control**: an assistant `Task` tool_use (a name in the spawn allowlist) WITHOUT `input.subagent_type` — the todo-list tool, NOT a spawn. Projects as plain chat/tool flow with ZERO `subagent.spawned`; not discovered by `DiscoverSpawnFixtures`, yet carries an allowlisted name, so `claudecode.IsSpawnToolUse`'s `subagent_type` gate is the sole exclusion (`replay/spawn_test.go`, `TestTaskTodoNoSubagentIsNotASpawn`). |
| `nested-spawn` | Depth-2 chain (root → outer → inner); parentage `exact`. |
| `depth3-nested-spawn` | Depth-3 chain (root → outer → middle → grand); the grandchild's parent linkage is `inferred`, exercising the depth-≥3 confidence downgrade (`tree.go` depthOf / OBSERVABILITY-DESIGN §2) that the depth-2 fixture cannot reach. |
| `parallel-fanout` | One turn fans out three rooted siblings (`exact`). |

## Segregated internal store

Recorded fixtures (`dogfood` and `partner-consented`) never enter this
repository. They live exclusively in a segregated internal store.

### Store location convention

The internal store is an **out-of-repo, named internal home** — not a
directory in this workspace.  The conventional name is
`ds-fixture-store/<consent-class>/` on the internal asset host, access
to which is brokered through the credential system and never exposed to
the VM boundary (D19/D50).  No infra is stood up for this store until
the first recorded fixture is needed; this convention documents the shape
so the access-control model is coherent before any data lands.

### Access control

Least-privilege per consent class:

| Consent class | Who may read | Retention |
|---|---|---|
| `dogfood` | Internal team only; no contractor or partner access | Per team policy |
| `partner-consented` | Designated reviewers for the specific partner only | 90-day raw-content retention (D60); 24 h stop / 30-day delete on revocation |

Access is granted by consent class, not by fixture; a reviewer granted
access to partner A's class cannot read partner B's recordings.

### Header format for internal-store entries

Fixtures in the internal store carry the same `ds_fixture` header object
as synthetic fixtures, but with a non-`synthetic` provenance value plus
two additional fields required by D60:

```
{"ds_fixture":{"provenance":"dogfood","seam":"attach.cc-wire","created":"YYYY-MM-DD","tool":"goldentrace"}}
{"ds_fixture":{"provenance":"partner-consented","seam":"attach.cc-wire","created":"YYYY-MM-DD","tool":"goldentrace","consent-class":"session","retention":"90d","revocation":"24h-stop/30d-delete"}}
```

- `provenance` is `dogfood` or `partner-consented`; **neither value is
  legal in this repository** — the CI gate rejects both.
- `consent-class` (partner-consented only) is one of `metadata`,
  `session`, or `workload` as defined in D60's Content Access Schedule.
- `retention` and `revocation` restate the D60 schedule terms inline so
  a fixture is self-describing with respect to its handling obligations.

### Re-authoring workflow

Recorded material enters this repository **only by being re-authored as a
synthetic equivalent** — never by scrubbing or redacting the original.
The workflow is:

1. Identify the behavioral pattern the recorded fixture exercises.
2. Author a new cassette from scratch using goldentrace (D49) with
   `provenance: synthetic`; every field value is invented, not derived
   from any real session.
3. Delete the internal-store entry from the working set once the
   synthetic equivalent is confirmed to cover the same behavior.
4. The re-authored cassette is the only artifact committed here.

Scrubbing is explicitly disallowed: clean-by-construction beats
scrub-and-hope (D50 rationale).

### Bright-line rule — on-prem tier safety (D19)

Shipped test suites contain **synthetic fixtures only**.  Because no
recorded fixture ever enters this repository or any artifact built from
it, the on-prem tier (D19) receives zero recorded user or partner data as
a side-effect of installing the platform.  This is the safety property
that makes D26 public-suite publication and D19 on-prem distribution safe
by construction: there is nothing to leak because nothing real was ever
committed.

## Drive-direction cassettes (keystone `01KTXBG14J`, 2026-06-12)

Three drive-direction cassettes were **re-authored as synthetic** from the
keystone live capture (the first live run of the native control channel — a
real CC `2.1.173` driven as a stream-json SDK host in a rootless podman
container; see `../wrapper/DRIVE-FINDINGS.md` §"Live capture 2026-06-12"). The
raw captures are raw-class and stay under `~/tmp/ds-keystone/cap/` and `~/.cia`
— they are **never** committed. These cassettes are hand-minted equivalents:
every id is a fresh synthetic ULID/UUID-shaped placeholder, no real model text
of consequence, no token of any kind. They pin the **live-verified** wire
shapes, which differ from the prior binary-extracted `ask-control` fixture in
the noted fields.

| Cassette | Seam it pins | Live-verified shapes |
|---|---|---|
| `drive-native-allow.cc-wire.ndjson` | native control channel, allow path | `initialize` control_request (host→CC) → rich `initialize` control_response (CC→host: `commands[]`/`agents[]`/`models[]`/`output_style`/`account.tokenSource`/`pid`); native `can_use_tool` control_request (CC→host); `control_response{behavior:"allow",updatedInput}` (host→CC); `tool_result` + `tool_use_result` sidecar |
| `drive-native-deny.cc-wire.ndjson` | native control channel, deny path | `control_response{behavior:"deny",message}`; the deny message propagating verbatim into the `is_error:true` `tool_result.content` and into `result.permission_denials[]`; `result.subtype` stays `success` |
| `drive-multiturn.cc-wire.ndjson` | sustained multi-turn driving | two `user` inputs driven into ONE live CC process across two `result:success` cycles (no respawn); a fresh `system/init` is re-emitted per driven input |

**Shape corrections versus the binary-extracted `ask-control.cc-wire.ndjson`**
(documented in DRIVE-FINDINGS.md §1): `permission_suggestions[]` is
`{type:"addRules", rules:[{toolName, ruleContent}], behavior, destination}`
(NOT the prior `{type:"rule", ruleValue:{…}}`); `agent_id`,
`classifier_approvable`, `blocked_path`, and `decision_reason` were **absent**
on the live ask (present only conditionally); the live `decision_reason_type`
was `"subcommandResults"`. The `control_response` driver shape (camelCase
`updatedInput`/`updatedPermissions`, `subtype:"success"` envelope, no top-level
`uuid`/`session_id`) was **confirmed correct** as-is.

## Fidelity-loop cassettes (`drive-fid-*`, taskdb `01KTXBGTK6`, 2026-06-12)

Six `drive-fid-*` cassettes feed the **cassette fidelity loop**
(`../goldentrace/fidelity/`), which asserts the adapter's projection of a
re-authored **synthetic** cassette EQUALS its projection of a **live** CC stream,
**id-relative / structural** (DRIVE-PROTOCOL.md §"Determinism via record-replay").
They come in three (canonical, `-live-equiv`) **pairs**: the canonical leg is the
hand-authored synthetic; the `-live-equiv` leg is a re-authored stand-in for a
CIA-ground-truthed live capture — authored with **deliberately different** minted
ids and timing/cost so the two project EQUAL id-relative but **never** byte-equal
(this is what proves the equality is genuinely structural, not a tautology —
`fidelity.TestFidelityLoopIsNonVacuous`). All are `synthetic` (D50): every id is
a fresh synthetic UUID/ULID-shaped placeholder, no real model text of
consequence, no token of any kind.

| Pair | Cassettes | CC-wire shape it pins |
|---|---|---|
| chat | `drive-fid-chat` + `drive-fid-chat-live-equiv` | a plain single-turn assistant text + quota + `result:success` terminal |
| native-ask | `drive-fid-native-ask` + `drive-fid-native-ask-live-equiv` | the native control channel ALLOW round-trip (`can_use_tool` control_request → `control_response{allow}` → `tool_result`) — gap 2, the costliest adapter blind spot |
| multiturn | `drive-fid-multiturn` + `drive-fid-multiturn-live-equiv` | sustained two-turn driving in ONE CC process; a fresh `system/init` re-emitted per driven input |

The fidelity loop was exercised **live** on 2026-06-12 against real CC `2.1.173`
(1 session, ~$0.02): a `cia record` daemon on a **free port `:18099`** with a
**private control socket** (the step-0 cia `--runtime-dir` override, branch
`cia-record-replay-coexist`) **coexisted** with the protected `:18080` monitor
(never bound/stopped/touched it — protected socket inode unchanged), and a real
containerized claude drove a scenario through it, producing a raw stdout capture
+ a 69 KB API cassette. Both are **raw-class** and stay under
`~/tmp/ds-keystone/cap/live-fid/` and `~/.cia` — **never committed** (the API
cassette carries no Bearer token; cia strips auth). Only the re-authored
synthetic `drive-fid-*` cassettes above land in git. See
`../goldentrace/fidelity/README.md` §"Live evidence".

## Re-pin pass — `initialize` registry-block correction (2026-06-12, `01KTXXFSA4` / `01KTXRHN8T`)

The post-keystone re-pin pass re-drove the native `initialize` handshake live
against real CC `2.1.173` (an initialize-only probe, near-zero spend, no model
turn) through the read-only `:18080` proxy (protected daemon never bound/stopped/
touched). The fresh capture **exactly reproduced** the keystone's initialize
registry block (`account.tokenSource`, `pid`, `output_style`,
`available_output_styles`, `commands[]`/`agents[]`/`models[]` object shapes) and
the conditional riders (`pending_permission_requests[]` /
`pending_user_dialog_requests[]` ABSENT). Raw captures are raw-class and stay
under `~/tmp/ds-keystone/cap-repin/`, **never committed**.

**One synthetic-completeness correction (documented, not a wire bug):** the live
`models[]` objects always carry the full key set `{value, displayName,
description, supportsEffort, supportedEffortLevels, supportsAdaptiveThinking,
supportsAutoMode}`, but `drive-native-allow.cc-wire.ndjson`'s `models[]` object
lists only `{value, displayName, description, supportsEffort}` — a valid subset
for its allow-path purpose, but thinner than the live shape and thinner than
DRIVE-FINDINGS.md §1a documents. **A dedicated re-pin cassette pinning the COMPLETE
registry block is DEFERRED to the cassette owner**: committing a new
`*.cc-wire.ndjson` under `client/fixtures/` auto-requires regenerated goldens
under `client/goldentrace/{replay,canary}/testdata/` (the always-on golden suites
glob this directory), which are outside this pass's file fence. The correction is
recorded here and in DRIVE-FINDINGS.md §"Re-pin pass" so the owner can author the
fixture + goldens in one reviewed step. No existing cassette byte changed.
