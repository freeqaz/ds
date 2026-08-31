# client/wrapper/ — smart attach wrapper

**Owner:** Attach & client · **OSS** (D15/D25) · **Decisions:** D18, D38, D20

The custom-protocol wrapper of D18: it parses the runtime's session protocol
(Claude Code's subagent protocol first) and emits **`dreamserpent.attach.v1`**
events — per-event sequence numbers, subagent-spawn events, ask-prompt /
approval events, state vocabulary incl. PARKED + D77 reasons (the consolidated
M0 freeze checklist lives in doc 15 §6;
this workstream executes it).

**The proto side is the stable side.** D38 splits the runtime seam so that
everything expected to churn (the CC wire format) is confined to one adapter
under `adapters/`, while `attach.v1` changes only via versioned freeze PRs in
`proto/`. The CC input side is deliberately **not** a proto — it is pinned by
golden traces (`../goldentrace/`, D49) and synthetic cassettes
(`../fixtures/`, D50) per doc 06 §2.2.

Routing: subagent/workflow calls fan out into their own VMs + git
worktrees (D18); the wrapper emits the spawn events, the orchestrator owns
placement. The wrapper holds no approval state — grants arrive via the policy
stream (see `../README.md`).
