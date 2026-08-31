# dreamserpent.hostagent.v1

**Charter.** The host agent ↔ orchestrator reporting seam: the streaming heartbeat that
carries observed state, `applied_seq`, capacity, and per-session samples up — and the
session-lifecycle data feed host-ward (digest ack relay, D22 grants, D78 attendedness —
the D72-exempt class). **Shape freezes at M0; field values are rig-tuned**
(docs/15 §5.2).

**Owner workstream:** Orchestrator. **License:** [OSS] public contract.
**Freeze stage:** M0 (shape) — **FROZEN 2026-06-13** ([FREEZE.md](../../../FREEZE.md),
PR `task/draft-and-land-the-three`; body `heartbeat.proto`; SHAPE frozen, field VALUES
rig-tuned per doc 15 §10; frozen as one wave with `orchestrator.v1`/`hypervisor.v1`).

## Inventory this package WILL hold (doc 15 §5.2)

`Heartbeat` (streaming; cadence strawman 5 s — free; 3 missed beats ⇒ host presumed
unreachable, sessions marked UNKNOWN, never auto-destroyed):

- `host_id`
- `applied_seq` — **frozen semantics (D72): min over the three host-side consumers,
  advancing only post-sweep**; feeds D36's unschedulable rule and terminates the
  (d)-rig push-to-enforced clock
- `observed` — repeated `ObservedSession` (shared with
  [`hypervisor.v1`](../../hypervisor/v1/) `RecoverSessions`); the reconciler's input
- `capacity` — `HostCapacity` floors-fit math for the scheduler (D37)
- `samples` — per-session RSS/CPU/IO time series, wired from M0 (D37)
- `host_baseline_version` — the doc 14 §11 artifact, versioned with the host image,
  **never pushed over the policy stream**
- `image_cache_digest` — cache-locality placement feed
- `boundary` — repeated `ServiceHealth` for ds-dnsgate / ds-tlsproxy / nft-writer

Host-ward session-lifecycle channel (same seam): digest ack relay (D73 — proposed ack-er
is the host agent itself, doc 15 OQ1, pending), D22 grant delivery, and the **D78
attendedness field, which MUST join this contract before Stage 2** (TLS-1 socket-hold
and DNS-3 consume it at per-connection-verdict time — doc 15 §5.5). Local transport to
boundary services defaults to UDS gRPC (doc 13 §6 leaves it free).

## Gating

Freeze PR cites: D72 `applied_seq` semantics; the host-ward feed slots (digest ack —
OQ1 settled first; grants; attendedness reserved or landed); D75 address-shape rule
where addresses appear. Orchestrator ↔ host agent is the contract harness's **first
real seam** (doc 15 §11, doc 06 §2.1) — fakes publish first.

## What must NOT live here

- Heartbeat cadence/staleness *values* — rig-tuned, never frozen (doc 15 §10).
- A second policy stream or digest namespace: fleet-scope digests ride `policy_log` via
  WatchPolicies (doc 14 §7); this channel carries only the session-lifecycle class.
- The host-baseline artifact contents — `dataplane/artifacts/host-baseline/`
  (doc 14 §11); only its version string is echoed here.
