# Drive-direction design — making the attach client speak CC's protocol *back*

**Owner:** Attach & client · **Decisions:** D18, D20, D38, D45, D49, D50, D53, D61, D78, D79 · **Status:** design note (drive-direction plan)
**Complement to:** [`../goldentrace/PROTOCOL-NOTES.md`](../goldentrace/PROTOCOL-NOTES.md) (the **read** direction map) and [`../goldentrace/OBSERVABILITY-DESIGN.md`](../goldentrace/OBSERVABILITY-DESIGN.md).
**Tracked in taskdb:** parent `01KTXBF3YZ` ("Drive-direction thin client") under the Client Experience workstream; the keystone spike is `01KTXBG14J`.

## What this is

The adapter that shipped with `01KTWJ22QR` is the **read path**: `CC stream-json stdout → dreamserpent.attach.v1`. It is an observer. A thin client that *drives* a Claude Code session — sends prompts, answers permission asks, sustains a multi-turn conversation, across a VM/container boundary — needs the half we have not built. This note is the drive-direction complement to `PROTOCOL-NOTES.md`: what the **write** path requires, what is already known vs. needs live capture, and the live e2e harness that proves the whole loop closes.

## The thin-client framing (resolve this first)

"Speak the same protocol" has two layers, and conflating them picks the wrong architecture:

- The **wrapper** (`client/wrapper/`, runs VM/host-agent-side) speaks CC's wire protocol — stream-json in/out **plus** the control channel. It is the protocol-termination point and the only place CC-isms live (D38).
- The **thin client** (`client/cmd/ds/`, `client/tui/`, runs on the human's machine) speaks **`attach.v1`** and nothing else. Its thinness *is* the wrapper absorbing all CC knowledge; swap the runtime and only the adapter under `wrapper/adapters/<runtime>/` changes (D18/D20/D38).

So the client never emits CC stream-json at a VM. It speaks `attach.v1` to the orchestrator's `WatchSession`; the wrapper translates inside the boundary. This is already mandated for approvals (D18/D45/D53): the client renders the ask and the human chooses, but the answer returns as a **TTL'd grant on the policy stream**, *not* as a `control_response` punched back through the proxy (`client/README.md` — the seam is a one-way `AskUserRequest`; a second proxy-side response channel is "wrong by construction"). The wrapper turns that grant into CC's `control_response` *inside* the VM.

**The key build insight: the driver is the mirror of the adapter.**

| | direction | type signature |
|---|---|---|
| Adapter (built, `01KTWJ22QR`) | read | `CC-record → attach.Event` |
| **Driver (to build, `01KTXBG15F`)** | write | `attach.Event(input/grant) → CC-record(input/control_response)` |

Same `records.go`, same `tool_use_id` correlation, inverse direction. We built one wing; the driver is the other.

## The three gaps, by how well we actually know them

| Piece | Known (observed live) | Needs live capture |
|---|---|---|
| **Input protocol** | P4: single-text-block envelope `{type:user,message:{role,content[]}}`, CC mints ids, `isReplay:true` ack discriminator | Multi-turn *sustained* driving (not one-shot `-p`); multi-block / `tool_result`-as-input; images; `SendMessage` subagent continuation (P17 open) |
| **Control channel** | P8: the `--permission-prompt-tool mcp__…` route **proven live** | The **native** `control_request{subtype:"can_use_tool"}` / `control_response` / `control_cancel_request` + the `initialize` handshake with `pending_permission_requests[]` — these were **extracted from the binary, never exercised live** |
| **Transport (D79)** | `AttachHandle` reserved: `endpoints`, `AuthMaterial`, `role WRITER\|READER`, `expires_at`; two strategies sketched (drive stream-json vs. PTY socket) | The whole thing — never crossed a boundary; one-writer/N-reader arbitration (D61), writer-seat write events (D78, freeze row 7), plan-delta stream (P15, freeze row 6) |

The load-bearing unknown is the **native control channel**, and the reason it was never captured live is the exact constraint that deferred P7: you must stand up a real SDK host and drive CC, which the investigation refused to do on a shared workstation where every session runs under one uid (PHASE2 §5).

## The unifying move: the e2e harness *is* the capture rig *is* the conformance test

To characterize the native control channel live, you must run an SDK host that drives a real CC and answers an ask. That is, definitionally, the e2e harness. Building the harness and closing the open freeze rows (P8-native, P15, P16, P17) are **one activity**. Three things de-risk it:

1. **Run it in a rootless OCI container** (podman, already installed — §isolation below). A rootless container is a separate user namespace with its own `/tmp`, so the `/tmp/cc-daemon-<uid>/` uid-shared-daemon danger that deferred P7 **evaporates** — and it is the product-faithful isolation topology, a strictly cheaper precursor to the KVM-VM prototype (`01KTWJ26MR`).
2. **`ds-capture` instruments it** (the first-party capture tool, egress-gateway proxy default `:18099`, never the protected `:18080` monitor). When the harness drives live CC, `ds-capture record` tees the API wire in parallel → independent ground-truth that validates synthetic-cassette fidelity (the n=1 worry the findings keep flagging) and catches drift on the transport plane the stdout harness can't see.
3. **There is a proven v0 path.** P8's prompt-tool route worked live, P4's single-block input worked live. A driving client can ship **v0 today** on proven pieces; the native-channel spike is the v1 fidelity upgrade, not a blocker.

## Isolation vehicle — rootless podman

`podman 5.8.2`, rootless, `crun` (debian/ubuntu/node base images) is the isolation environment for every live-drive tier until the KVM host exists.

- **Why it is safe for live driving:** rootless = separate userns + mount ns + its own `/tmp`, so a CC process inside cannot see or touch the host's `/tmp/cc-daemon-<uid>/<instance>` daemon that the host's own sessions share. Layer-1 stream-json driving is a direct child process anyway (lower-risk than the Layer-2 daemon); the container makes it airtight.
- **Fail-closed gate before any drive** (carry the PHASE2 §5 discipline): assert the process is in a fresh container namespace, `HOME`/`CLAUDE_CONFIG_DIR` are container-local, no host `/tmp/cc-daemon-*` is bind-mounted, and `--no-session-persistence` + `--max-budget-usd` caps + `--model sonnet` are set. Abort hard on any failure.
- **Captures are raw-class:** anything the container or `ds-capture` records (real paths, costs, `Authorization: Bearer …`) stays in the job dir, **never** committed; fixtures enter git only as re-authored synthetic (D50). Same wall the goldentrace `HARDENING-NOTES.md` already specifies.

## The e2e harness, in tiers

Today `goldentrace/replay/golden_test.go` replays **static synthetic cassettes** — it proves the parser is deterministic, not that cassettes match reality or that we can drive. The real harness adds the live loop in three tiers of increasing fidelity (and the same checklist/`validateEvents` assertion machinery throughout):

1. **Local SDK-host in a container** (`01KTXBG14J` keystone + `01KTXBGTJA` tier 1): spawn real `claude --input-format stream-json --output-format stream-json` as a host; the **driver** sends input + answers an ask; the **adapter** parses output → `attach.v1`; assert against the checklists — now **live**, not synthetic. `ds-capture record` tees the API plane in parallel. This tier alone closes the native-control-channel capture.
2. **Over the transport bridge** (`01KTXBGTHF` + `01KTXBGTJA` tier 2): CC in the container with stdio bridged to a minimal host-agent exposing the D79 `AttachHandle`; the thin client attaches from outside and drives in. Exercises the transport seam without full VM weight.
3. **Full KVM VM** (`01KTWJ26MR`, existing): the production topology — thin `ds`/TUI ↔ attach handle ↔ host-agent ↔ wrapper ↔ CC in a per-session VM.

The adapter+driver is a **library**, so it runs client-side in tier 1 (fast protocol-conformance loop) and VM-side in tier 3 (production thinness) — no fork to choose; structure it as a lib and both fall out.

## Determinism via record-replay (the live tier, made reproducible)

The live tiers are nondeterministic only because of CC's model API responses. Record them once and replay them, and a real CC process becomes a deterministic function of its inputs — the real binary, real stream-json, real native control channel, only its "brain" frozen. This is VCR/cassette record-replay at the `/v1/messages` boundary, and it is strictly stronger than replaying CC's stdout (goldentrace's current cassettes): real CC *regenerates* the stdout, so the wrapper↔CC↔driver loop — including the control-channel round-trip the keystone needs — is exercised end to end.

`ds-capture` is the recording half (its TLS-terminating egress gateway intercepts `/v1/messages` and tees the SSE stream to a JSON cassette; `record`/`replay` are first-party subcommands). Two modes:

- **Record** (live, gated): drive CC against the real API through `ds-capture record` (egress-gateway proxy on the free `:18099`); creds in the container volume mount; budget-capped; produces the API-response cassettes + the live stream-json / control-channel ground truth. This is the keystone (`01KTXBG14J`).
- **Replay** (deterministic, offline, cred-free): drive CC against `ds-capture replay`. No API reached → no creds, no spend, zero egress → a hermetic CI test that still drives **real CC** — D50's "synthetic fixtures, zero egress" satisfied by construction.

Rules the replay tier MUST honor:

- **Assert structurally / id-relative, never literal.** CC mints fresh random-v4 `uuid`/`session_id`/`task_id` per run, and instant replay collapses the P10 asymmetric-latency ordering — so correlate by the within-run id triple and assert happens-before, never literal ids or wall-clock order. Timing-derived metrics (TTFT, tok/s) are not reproducible under replay; do not assert on them.
- **Freeze disk, don't replay it.** Determinism of CC's file reads comes from a fixed container image + mounts, not from replaying disk events. Residual nondeterminism (uuids, time) is handled by the id-relative assertions above, not by trying to freeze CC's RNG.
- **Tolerant request-matching.** CC's `/v1/messages` bodies grow each turn and carry volatile ids/headers; the replay matcher keys on the normalized semantic request in conversation sequence, not exact bytes. Driving with a fixed input sequence (the driver's job) makes the request stream reproducible.

Where it sits: **record = Capture, replay = the deterministic conformance/regression suite, live canary = drift detection** — goldentrace's existing triad, one layer deeper. Record-replay proves we handle *previously-seen* CC behavior forever; it does not catch CC *drift* (that stays the live canary's job, `01KTWJ25NG`).

## Language & performance — compiled only, per the existing split

This is hot-path, latency-bound infrastructure (the "feels local, remote reality" thesis, doc 02 §5): per-record stream parsing, a byte-bridge across the boundary, sustained multi-turn driving. **Every shipped component is a compiled systems language — Go or Rust — never a scripting language on the hot path.** The repo already encodes the split, and this work inherits it:

- **Driver + adapter → Go**, non-negotiable. They live in `client/wrapper/adapters/claude-code/` (the D38 runtime-specific tree, the `client` Go module) and the driver reuses `records.go` and the `tool_use_id` correlation directly. Go's goroutine-per-stream model and `encoding/json` streaming are a clean fit; stdlib-only holds (`client/go.mod`).
- **e2e harness → Go.** Test/conformance infrastructure beside `goldentrace/replay/`; reuses `validateEvents` and the golden machinery. Compiled, CI-runnable, deterministic.
- **Host-agent transport bridge → Go by default, Rust if profiled.** The host-agent lives in `vm/` (a Go module). Default Go to match it. **But** the byte-bridge on the writer/PTY path is the one genuinely latency-critical surface, and the repo's convention is that perf- and security-critical data-plane bytes are **Rust** (the `dataplane/` cargo workspace: `ds-dnsgate`, `ds-tlsproxy`). If tier-2/3 profiling shows the stream bridge is the feels-local bottleneck, moving *only* that byte-path to a small Rust component is consistent with the data-plane split — decided by measurement, not up front. Record the verdict in this doc when tier 2 lands.
- **Capture/orchestration glue** (the keystone's exploratory host loop, `capture.sh`-style scripting) may stay shell — it is throwaway, off the hot path, and never ships. The *deliverable* it produces (the driver, the bridge) is compiled; the capture tool itself is now the first-party compiled `ds-capture`, not external Python.

Principle: scripting is allowed to **discover** the protocol; only compiled Go/Rust is allowed to **carry** it in the product.

**Corollary — the carry-side capture tool is the first-party `ds-capture`.** The external CIA monitor (`../../cia`) was an interim Python/mitmproxy tool on the "discover" side of the split; its carry-side replacement is the **first-party compiled Go tool `ds-capture`** (CAPTURE-TOOL-DESIGN.md), which unifies the goldentrace harness ideas — the TLS-terminating record/replay egress-gateway core (default proxy `:18099`, never the protected `:18080` monitor), cassette capture/scrub (D50), and the nightly canary cadence (D49) — into one binary's subcommands instead of a shell constellation plus an external Python dependency. Tracked under `01KTXBF3YZ`: `01KTXKJBER` (design spike — language choice and capability cut-list), `01KTXKJNJ8` (the record/replay core, cia parity), `01KTXKJYYW` (migrate `cc_sandbox.sh`, the fidelity loop, and the canary off `--cia`; retire the external dependency).

## Build sequence (the taskdb DAG under `01KTXBF3YZ`)

```
01KTWJ22QR (adapter, DONE)
   └─▶ 01KTXBG14J  Keystone spike: live SDK-host capture in a container   ← READY now
          ├─▶ 01KTXBG15F  Driver (inverse adapter) — Go
          │      ├─▶ 01KTXBGTHF  Host-agent transport bridge (D79) — Go (Rust if profiled)
          │      └─▶ 01KTXBGTJA  Live e2e drive-conformance harness ◀── also needs 01KTXBGTHF
          │             └─▶ 01KTXBGTK6  Cassette fidelity loop (CIA ground-truth) → feeds canary 01KTWJ25NG
          └─▶ 01KTXBG16B  Specify attach.v1 WRITE side (rows 6/7 of the doc 15 §6 freeze)

01KTXEXQAZE  CIA record/replay mode (../cia — interim, the parity baseline)
   └─▶ 01KTXKJNJ8  First-party capture tool core (Rust/Go, cia parity) ◀── also needs 01KTXKJBER (design spike)
          └─▶ 01KTXKJYYW  Migrate e2e/fidelity/canary consumers off ../cia, retire the external dependency
```

Start at the keystone (`01KTXBG14J`): the native control handshake and multi-turn input grammar gate the driver, the proto write-side, and the freeze — capturing them first de-risks everything, and the container makes it safe to do now.

## Open questions / deferred

- **Native control handshake shape live** — the keystone's primary unknown; binary-extracted only (P8).
- **Plan-delta / `TodoWrite` / `ExitPlanMode` stream** (freeze row 6 plan half, P15) — still uncaptured; `01KTXBG16B` closes it.
- **Writer-seat / attendedness event taxonomy** (D78, freeze row 7) — reserved, free; `01KTXBG16B`.
- **Layer-2 daemon driving** (`claude agents`, PTY socket transport) — stays deferred (PHASE2 §5); the container removes the uid-sharing hazard but the daemon-control reversing is out of scope for the Layer-1 drive path.
- **Rust-vs-Go for the byte-bridge** — decide by tier-2 profiling; default Go.

## Sources
- Read-direction map: [`../goldentrace/PROTOCOL-NOTES.md`](../goldentrace/PROTOCOL-NOTES.md), [`../goldentrace/PHASE2-FINDINGS.md`](../goldentrace/PHASE2-FINDINGS.md) (P4/P5/§5), [`../goldentrace/PHASE3-FINDINGS.md`](../goldentrace/PHASE3-FINDINGS.md) (P8), [`../goldentrace/OBSERVABILITY-DESIGN.md`](../goldentrace/OBSERVABILITY-DESIGN.md).
- Seam/charter: [`README.md`](README.md), [`adapters/claude-code/README.md`](adapters/claude-code/README.md), [`../README.md`](../README.md), [`../../proto/dreamserpent/attach/v1/README.md`](../../proto/dreamserpent/attach/v1/README.md).
- Freeze checklist: `docs/15-orchestrator-design.md` §6. Decisions: `docs/04-architecture-overview.md` §6 (D18/D38/D45/D53/D61/D78/D79).
- Instrumentation: the first-party `ds-capture` capture/instrumentation tool (record/replay/scrub/inspect/fidelity/canary subcommands; egress-gateway proxy default `:18099`, `NODE_USE_ENV_PROXY=1` mandatory, PHASE2 P6) — `client/goldentrace/CAPTURE-TOOL-DESIGN.md`, tracked work `01KTXKJBER`/`01KTXKJNJ8`/`01KTXKJYYW`. (It supersedes the retired external `../../cia` Python/mitmproxy monitor.)
