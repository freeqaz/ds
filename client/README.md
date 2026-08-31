# client/ — Attach & client

**Owner workstream:** Attach & client (doc 05 §3)
**License:** OSS (Apache-2.0, D25) — CLI/TUI/wrapper are open data plane per D15 (doc 08 §1).
**Governing decisions:** D18, D20, D38, D45, D49, D50, D53 (doc 04 §6).

## Charter

The human's end of a session: the `serpent` operator CLI (`cmd/serpent/`, with
`cmd/ds/` reserved as the OSS CLI entry point), the smart wrapper that
parses Claude Code's subagent protocol and emits stable
`dreamserpent.attach.v1` events (`wrapper/`, D18/D38), our own TUI (`tui/`),
the golden-trace harness that pins the unstable CC wire side (`goldentrace/`,
D49), and the synthetic fixture set behind it (`fixtures/`, D50). The paid web
client is **not** here — it is a surface in `paid/webclient/`, consuming the
same public protos.

## The approval surface lives HERE — never in the proxy

The doc 03 §7 question ("does the approval surface live in the proxy or the
client?") is settled: **client**. D18 makes the wrapper+TUI the interaction
surface; D45 routes runtime one-off grants through the D18 client as
allow-once / allow-always; D53 fixes the ladder rung that interrupts a human
(suspend+ask) and its defaulting principle — *interrupt only to grant new
authority or prevent an irreversible action, never to review work*. The
boundary's side of the seam is a **one-way** `AskUserRequest` (doc 15 §6):
approvals return ONLY as TTL'd grants on the policy stream, never as a
response to the proxy. Any PR that puts approval UI, approval state, or a
second response channel proxy-side is wrong by construction.

## SecretMatcher follow-on (note — deliberately NO directory)

The attach-side secret-matcher consumer (catch a planted long-lived secret at
first egress, doc 02 §6)
is a tracked follow-on **owned by this workstream**, but per
doc 16 §6.5 it runs
**orchestrator-side**: digests never leave trusted territory, so no digest
material and no matcher runtime ever lands in this tree. The matching
primitive is the `SecretMatcher` trait in `dataplane/crates/policy-core/`
(one evaluator, doc 14 §6). The skeleton design (Part 3 anti-scaffold list)
explicitly bans a `client/secretmatcher/` dir — register the consumer on the
doc 16 §6.5 distribution policy instead.

## First-party capture tool (tracked follow-on)

The goldentrace live tiers and the drive-direction harness were originally
instrumented through an external Python/mitmproxy monitor: TLS-terminating
capture of `/v1/messages` plus record/replay cassettes. That is discovery
tooling by policy (`wrapper/DRIVE-PROTOCOL.md` §Language & performance —
scripting *discovers* the protocol, only compiled Go/Rust *carries* it). The
goal is a **first-party Rust-or-Go capture & instrumentation tool** that
replaces it and unifies the goldentrace harness ideas (capture / scrub /
replay / canary, D49/D50) into one binary — `cmd/ds-capture/` is that
replacement, and migrating the remaining consumers off the external monitor is
the open follow-on.

## What must NOT live here

- **Proxy-side approvals** — see above (D18/D53; anti-scaffold list).
- **`client/secretmatcher/`** — orchestrator-side per doc 16 §6.5 (above).
- **`.proto` bodies** — `attach/v1` lives in `proto/` and is README-reserved
  until its M0 freeze; the CC wire side is golden-traced, never a proto
  (doc 06 §2.2).
- **Runtime-specific code outside `wrapper/adapters/`** — D20/D38; the
  adapter is the only sanctioned home.
- **Non-synthetic fixtures** — D50; see `fixtures/PROVENANCE.md`.
- **The web client** — `paid/webclient/` surface (D61).

## Neighbors

| Tree | Relation |
|---|---|
| `proto/dreamserpent/attach/v1/` | The stable side of the seam this tree emits; M0 freeze checklist hosted by doc 15 §6 |
| `orchestrator/` | `WatchSession` serves the attach stream (D61 one-writer/N-reader); D49 cassette-driven WatchSession fake in `orchestrator/fakes/` |
| `vm/entrypoint/` | The other D38 contract (host-agent→guest); runtime-agnostic by the same decision |
| `images/golden/` | Bakes the D49-pinned CC version the adapter and goldentrace target |
| `paid/webclient/` | Consumes the same event stream as a paid surface — shares protos, not code |
