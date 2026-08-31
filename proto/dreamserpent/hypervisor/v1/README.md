# dreamserpent.hypervisor.v1

**Charter.** HypervisorDriver v1 — the seam between the host agent and whatever runs
VMs. The contract leaks **zero QEMU/libvirt specifics**, so the D30 re-evaluation seam
(Cloud Hypervisor at M3) and the D29 ZFS/dm-thin alternatives stay clean substrate swaps
(docs/15 §5.1). v0 driver = libvirt inside
the virtual-metal hosts (`orchestrator/internal/hypervisor/libvirt/`); the EC2 demo
driver is the same contract over the AWS API and the first capability-flag honesty test
(D31/D32/D35).

**Owner workstream:** Orchestrator. **License:** [OSS] public contract.
**Freeze stage:** M0 (doc 05 §8) — **FROZEN 2026-06-13** ([FREEZE.md](../../../FREEZE.md),
PR `task/draft-and-land-the-three`; body `driver.proto`, frozen as one wave with
`orchestrator.v1`/`hostagent.v1`, after `attach.v1`).

## Inventory this package WILL hold (doc 15 §5.1)

`service HypervisorDriver`:

- `GetCapabilities` → `Capabilities` — D35 Nomad-style flags, reported at registration
- `CloneFromImage` → `CloneFromImageResponse`
- `IssueAttachHandle` → `AttachHandle` (D79; handle message in `attach.v1`)
- `Snapshot`, `Suspend` (reason taxonomy per D77), `Resume`
- `Destroy` — drives the doc 15 §4.2 teardown ordering
- `Migrate` — capability-gated; internals free until M3
- `ExportDiskDelta` → `stream DiskDeltaChunk` — D29 qcow2-overlay hook
- `RecoverSessions` → `RecoverSessionsResponse` — restart re-adoption

Messages:

- `Capabilities` — `supports_migrate`, `supports_instant_clone`,
  `supports_disk_delta_export` (EC2 demo answers false/false/false — D32 honesty)
- `VmSpec` — `session_uuid` (every verb idempotent on it), content-addressed `image_id`,
  `ResourceFloors` (D37 cgroup-v2 floors), opaque `entrypoint_config_ref` (D38 — the
  orchestrator stays runtime-ignorant), `SessionMaterial` (CA bundle ref for §4.1 step-7
  injection; token ref via the D22 shim)
- `CloneFromImageResponse` — `host_session_index` (never recycled within the flow-log
  retention window, D66), `tap_name` (`dstap-<idx>`, ≤15 chars IFNAMSIZ),
  `guest_ip` (family-agnostic bytes + family enum, never fixed32 — D75), `overlay_path`
  (D29). This message is the artifact the open tap-create RACI row cites (doc 15 TODOs).
- `SuspendReason` enum (`USER | POLICY_BREACH | REBALANCE`) + `SuspendRequest` carrying
  POL-3 `Provenance` — REQUIRED for `POLICY_BREACH`, which is valid only for D77
  genuine-threat classes
- `RecoverSessionsResponse` / `ObservedSession` — also the heartbeat's observed-state
  element ([`hostagent.v1`](../../hostagent/v1/))

## Gating

Freeze PR cites: full doc 15 §5.1 verb set + flags (D35); the no-QEMU/libvirt-leakage
review (D29/D30); D75 address-shape rule; D77 reason/provenance rule. Generated fakes
publish first (doc 05 OQ3).

## What must NOT live here

Driver internals of any kind — libvirt-go usage, EC2 demo mechanics — are bounded by
honest capability flags plus the conformance suite, and live in
`orchestrator/internal/hypervisor/` (doc 15 §10). No generic multi-hypervisor
abstraction layer and no Firecracker target exists or is scaffolded (D30).
