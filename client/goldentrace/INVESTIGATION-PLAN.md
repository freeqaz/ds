# CC subagent protocol — Phase 2 Protocol Analysis Plan (D49 spike)

**Owner:** Attach & client · **Decisions:** D18, D20, D38, D49 · **Status:** executed — P1–P6 done, P7 deferred (safety)
**For:** reviewers (critique methodology + safety) and capture agents (execute) · **Date:** 2026-06-11
**Companion:** [`PROTOCOL-NOTES.md`](PROTOCOL-NOTES.md) (the map) · [`PHASE2-FINDINGS.md`](PHASE2-FINDINGS.md) (results) · run via [`capture.sh`](capture.sh)

> **Outcome:** the review phase set a `blocking_safety_stop` (correctly) and **P7 was deferred**;
> P1–P6 ran and are written up in [`PHASE2-FINDINGS.md`](PHASE2-FINDINGS.md). The safety review
> also **corrected this plan's central premise** (see HARD constraints, now fixed): concurrent
> sessions on one workstation run under the same uid, not as another user, so isolation is
> discipline-only and the daemon dir is uid-shared.

## Objective

Build a reliable `client/wrapper/adapters/claude-code/` adapter (D38) that translates the unstable
CC wire side into stable `dreamserpent.attach.v1` events — and ground D18 (fan subagent calls out
into their own VMs) and D38 (attach) on real evidence rather than guesses. To do that, we continue
**mapping the observable behavior** of the protocol(s) Claude Code uses to talk to subagents:
observing the observable behavior of a tool we license, running on our own machine, so the adapter
can drive it reliably. This is **protocol mapping for interoperability**, not a study of internals
we are not meant to see.

## Established (Phase 1 — see PROTOCOL-NOTES.md)

- **Two mechanisms.** Layer 1 = in-process `Task`/`Agent` subagents (no subprocess; observable
  as a stream-json projection: spawn event + nested prompt + `tool_result` with an
  `agentId`/`<usage>` trailer + `system/task_*` lifecycle; a leaf subagent's *ordinary* internals
  stay opaque but its *sub-spawns* surface — Phase 2 / P2). Layer 2 = `claude agents` background
  daemon (real multi-process: supervisor + spare workers + per-session `rv`/`pty` unix sockets,
  token gated; dispatch descriptor carries an `isolation` field).
- The spawn tool is `Task` on the wire / `--tools`, but `Agent` to the model — parse `name ∈ {Task, Agent}`.
- `parent_tool_use_id` attributes *prompt-side* messages but is `null` on results/`task_*` and
  flattens nesting to depth 1 — correlate by `(tool_use_id, task_id, message.id)` (Phase 2).

## HARD constraints (every agent MUST obey)

1. **Do not disturb other sessions (one uid, discipline-only).** Any other live interactive
   `claude` sessions on the same workstation run under **the same uid this investigation runs
   as** — the boundary is *not* OS-enforced. They share **one** daemon instance dir
   `/tmp/cc-daemon-<uid>/<instance>`, whose sockets are connectable by any process with that uid.
   **Never** connect to, write to, signal, or `claim` any socket under `/tmp/cc-daemon-<uid>/`, and
   never `kill` a `claude`/`node` pid you did not spawn. Treat any pre-existing instance dir as an
   untouchable denylist.
2. **Daemon work uses an ISOLATED instance only — and the dir is uid-shared.** A throwaway
   `HOME`/`CLAUDE_CONFIG_DIR` does **not** move sockets to a different `/tmp/cc-daemon-*` parent
   (the path is `/tmp/cc-daemon-<uid>/<instance>` and uid is fixed) — at most a different
   `<instance>` subdir under the **shared** `/tmp/cc-daemon-<uid>/`. Any Layer-2 analysis must gate
   on a **fail-closed** check before any daemon command: assert `$HOME != <operator home>`,
   `$CLAUDE_CONFIG_DIR` set with an empty `~/.claude/daemon`, the new instance id `!=` any
   pre-existing instance id, and no socket under a pre-existing instance changed mtime — **abort
   hard on any failure**. If isolation cannot be verified, document the method and stop. (High
   risk; deferred this round.)
3. **Captures are self-contained and ephemeral.** Use `claude -p ... --no-session-persistence`
   (no session-list pollution, no write contention), `--permission-mode bypassPermissions`
   (headless, no hangs), `--max-budget-usd <cap>` (cost guard), and `--model sonnet` for anything
   that must reliably spawn a subagent (haiku mis-fires to `TaskCreate`).
4. **Provenance / git hygiene.** Raw captures go to `$CLAUDE_JOB_DIR/tmp/cap/phase2/` only —
   they contain real paths, UUIDs, costs, agent ids. **Do not** commit, and **do not** write into
   `client/fixtures/` (synthetic-only, D50; re-authoring is done in the main loop after review).
5. **No destructive ops.** Read-only inspection of disk state is fine; no edits to `~/.claude/*`,
   no daemon restarts, no config changes.

## Phase-2 analysis items

| # | Layer | Hypothesis to test | Method | Artifact | Risk |
|---|---|---|---|---|---|
| P1 | 1 | N subagents in one assistant turn ⇒ N `Agent` `tool_use` blocks, distinct ids, results interleave cleanly by `parent_tool_use_id` | `claude -p` forcing 3 parallel subagents (`--agents` defines them); jq the spawn ids + nested/result linkage | parallel-fanout schema + linkage notes | low |
| P2 | 1 | A subagent can/can't itself spawn a subagent; if so, how does `parent_tool_use_id` nest (chain vs flat)? | define an agent whose prompt tells it to launch another agent; inspect nesting | nesting model | low |
| P3 | 1 | Hook lifecycle records (`--include-hook-events`) and their framing | run with `--include-hook-events`; enumerate record types/keys | hook-event schema | low |
| P4 | 1 | The stream-json **input** (SDK driving) side: `--input-format stream-json` + `--replay-user-messages` | feed a user message as stream-json on stdin; capture echoed/ack framing | input-protocol schema | low |
| P5 | 1 | Tool-denial / error framing: `permission_denials`, `is_error` tool_results, `result` error subtypes | run a tool the policy denies (no bypass); capture the denial path | error/denial schema | low |
| P6 | 3 | Does CC make the subagent's API calls directly, to which endpoint, with what headers — **and does it pin certs / honor an HTTPS proxy?** (directly informs ds-tlsproxy, D17/D74 "no baseline pins") | egress-gateway proxy on a private port + `NODE_EXTRA_CA_CERTS` + `HTTPS_PROXY`; run one throwaway `claude -p`; record hosts/endpoints/header *shapes* (not secrets) | api-call map + pin/proxy verdict | med |
| P7 | 2 | The daemon control protocol on `control.sock` (claim/dispatch/list framing) and the `isolation` value set | **isolated daemon only** (constraint 2): start a private daemon, dispatch one `claude agents` session into it, observe its own `roster.json`/sockets/`control.key`; enumerate `dispatch.isolation` / `CLAUDE_BG_ISOLATION` values | daemon control sketch + isolation seam | high — gated |

## Workflow orchestration

One workflow, three phases (`cc-subagent-protocol-spike`):

1. **Review** — diverse reviewers (safety/operational-risk, protocol-completeness, methodology-rigor)
   read this plan + PROTOCOL-NOTES.md and return structured critiques, each with a
   `blocking_safety_stop` flag. A blocking flag from any reviewer skips the high-risk item (P7).
2. **Capture** — P1–P6 run in parallel (each its own throwaway `claude -p`, raw → tmp, structured
   findings returned). P7 runs only if no blocking stop AND the agent verifies daemon isolation.
3. **Synthesize** — one agent merges reviews + captures into an updated protocol report (prose,
   no raw data) for the main loop to fold into PROTOCOL-NOTES.md and to drive any re-authored
   synthetic fixtures.

## Success criteria

- Each P-item yields either a confirmed schema/linkage rule or a documented negative result.
- The adapter-facing event model is complete enough to enumerate every `dreamserpent.attach.v1`
  event the wrapper must emit (spawn, nested, result, ask/denial, lifecycle).
- The ds-tlsproxy-relevant question (does CC pin / honor a proxy?) gets a yes/no with evidence.
- Zero disturbance to any session/socket we did not create.

## Out of scope (this phase)

- Writing adapter or harness Go code (lands after the schema is firm).
- Touching SUMMARY/INDEX/the decision log (integrator-owned).
- Any non-synthetic fixture entering git.
