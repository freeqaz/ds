# dreamserpent.orchestrator.v1

**Charter.** The control-plane API surface: how clients, the host agent, and paid
services create, watch, attach to, and govern sessions. Names ratified in D35; messages
freeze at **M0** except as marked (docs/15 §5.3).

**Owner workstream:** Orchestrator. **License:** [OSS] — public contract (D24/D58/D80);
`orchestrator-lite` (OSS) and the paid fleet control plane implement the *same* package
(D80). **Freeze stage:** M0 — **FROZEN 2026-06-13** ([FREEZE.md](../../../FREEZE.md), PR
`task/draft-and-land-the-three`; bodies `session.proto`/`policy.proto`, frozen as one
wave with `hypervisor.v1`/`hostagent.v1`, after `attach.v1`).

## Inventory this package WILL hold (doc 15 §5.3)

`service SessionService`:

- `CreateSession` — runs the §4.1 canonical create; D56 two-key structural refusal; carries
  an optional `role_ref` (session role, docs/18 §6
  — **proposed**, P-T2 unratified): resolved against the org catalog and pinned
  `(role_name, role_version, role_content_hash)` into the session record at create; catalog
  RPCs live in the reserved [`roles.v1`](../../roles/v1/), never here. One optional field in
  the still-open inventory — the same one-field-now-vs-v2-later argument as D79
- `DestroySession`, `SuspendSession`, `ResumeSession`, `SnapshotSession`
- `ListSessions`
- `WatchSession` → `stream SessionEvent` — the D18 fan-out leg; D61 one-writer/N-reader
  enforced server-side at this terminator; **every event carries a sequence number from
  M0** (reserved so replay/spectate add without a v2); event vocabulary = the doc 15 §3
  machine incl. PARKED + D77 reasons (gated by the consolidated attach-event checklist,
  doc 15 §6)
- `Attach` → `AttachHandle` (the D79 handle — message owned by
  [`attach.v1`](../../attach/v1/), doc 15 §5.4)
- `CreateChildSession` — **RESERVED at M0, implemented M3**: D18 wrapper callback for
  subagent/worktree sessions; carries parent link, policy posture, identity lineage,
  worktree inheritance
- `RecordEnvConfig` → `EnvConfigRef` — D7; reference shape only (the env-spec schema
  itself is UNOWNED, doc 15 OQ10)

`service PolicyService`:

- `AppendPolicy` → `PolicyLogRow` — actor recorded; the log IS the audit trail (D36)
- `WatchPolicies` → `stream PolicySnapshot` — from_seq replay, idempotent, deny-wins;
  **exactly one subscriber per host = the host agent** (D72); snapshot identity =
  (seq, content_hash, composed policy); JetStream is the pre-named substrate swap (D36)
- `ApproveAsk` → `PolicyLogRow` — §4.3 grant append; TTL'd, session-scoped (POL-5: no
  second response contract)

## Gating

Freeze PR cites: doc 15 §5.3 shapes; doc 15 OQ1 (digest ack-er) settled with Identity +
Boundary first; the doc 15 §6 consolidated attach-event checklist for WatchSession's
event vocabulary; canonical `content_hash` serialization coordination (doc 15 OQ3 /
doc 13 OQ2). Generated fakes — including the D49 cassette-driven WatchSession fake
(`orchestrator/fakes/`) — publish FIRST (doc 05 OQ3).

## What must NOT live here

- **Any Mint RPC** — `dreamserpent.orchestrator.v1` carries **no Mint RPC at all**. The
  orchestrator *fronts* the mint (doc 15 §5.3, D35) but the `IdentityMint` service and all
  its messages (`MintWorkloadIdentity`, `MintGrants`, `RevokeSession`, `MintInterceptionCA`)
  are owned exclusively by [`identity.v1`](../../identity/v1/) (D82, doc 16 §4/§9). A
  separate service on a dedicated instance is the invariant that keeps an orchestrator/KVM
  compromise from yielding signing keys (D22/D39).
- Enrollment (D56), escape-hatch catalog (D45), policy authoring, metering views (D57) —
  sketched surfaces that freeze with the M2 product band, not at M0.
- POL-1 schema fields — `ds-contracts` (doc 13 §3). The composed `PolicySnapshot`
  carries the composed document; layer schemas live there.

**Neighbors:** [`hostagent.v1`](../../hostagent/v1/) (the host-ward half),
[`hypervisor.v1`](../../hypervisor/v1/) (the driver the host agent drives),
[`planstore.v1`](../../planstore/v1/) / [`logsink.v1`](../../logsink/v1/) (reserved
siblings this doc's records would feed), and the prose-reserved fleet-directory query
API (doc 17 OQ11 — natural home beside WatchSession, doc 15 §5.6).
