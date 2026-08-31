# vm/ — VM & runtime

**Owner workstream:** VM & runtime (doc 05 §3)
**License:** OSS (Apache-2.0, D25) — the VM runner is part of the open data plane (D15, doc 08 §1).
**Governing decisions:** D20, D29, D38 (doc 04 §6); placement per doc 15 §5.1.

## Charter

This tree holds the pieces of the per-session VM that are *not* the hypervisor:
the guest-side entrypoint that implements the `dreamserpent.runtime.v1` contract
(`entrypoint/`, D38), and the host-side disk-delta tooling around the qcow2
overlay stack (`disk/`, D29). The workstream's wider scope — golden images,
copy-on-write write-audit, the runtime entrypoint contract — is split across
trees on purpose: image *building* lives in `images/`, the runtime *contract*
lives in `proto/dreamserpent/runtime/v1/`, and this tree implements and tools.
The **one** image artifact that does live here is the carve-out below: the
**hand-built M0 base image** (`m0-image/`), this workstream's own at M0 per the
doc 05 §3 seam statement — the
`images/golden/` pipeline industrializes that same image from M1.

**This tree is thin at M0 by design.** That asymmetry was weighed and accepted
in the skeleton design (Part 4, resolution 6).

## The libvirt driver does NOT live here

Read this before adding code: **the v0 libvirt driver lives in the host agent**
— `orchestrator/internal/hypervisor/libvirt/` — per
doc 15 §5.1. The `HypervisorDriver` v1
contract deliberately leaks **no QEMU/libvirt specifics**, and D30 rules out a
generic multi-hypervisor layer (no Firecracker; Cloud Hypervisor re-evaluated
at M3 behind the same contract). Putting driver code here would split the
driver from its only caller and recreate the abstraction D30 rejected.

## OPEN: tap-create RACI row

The per-session network-object RACI row is **open** and must settle jointly
with Boundary **before the Stage-1 attachment spike**
(doc 15 TODOs). Current adjudicated
posture: the **host agent is the invoker** of the Boundary-owned tap-create
primitive (doc 14 §1 owner cell), and `CloneFromImageResponse`
(`host_session_index`, `tap_name`, `guest_ip`, `overlay_path`) is the artifact
both sides cite. Nothing in this tree may assume the final row; track it here
and update this README when it lands.

## What must NOT live here

- **Hypervisor drivers** (libvirt, ec2demo) — host agent's, doc 15 §5.1 / D30 (above).
- **`.proto` bodies** — all contracts live in `proto/` (D24); `runtime/v1` is
  README-reserved there until its M0 freeze PR.
- **Golden-image build definitions** — `images/golden/` (doc 03 §6). M0
  carve-out: the hand-built **M0 base image** is this workstream's own artifact
  (doc 05 §3 seam statement), built here in [`m0-image/`](m0-image/) — excluded
  is the CI pipeline that industrializes it from M1, not the image itself.
- **Runtime-specific (Claude Code) code** — the per-runtime adapter is the only
  runtime-specific code and it lives in `client/wrapper/adapters/` (D20/D38).
- **Tap/IP/index allocation** — host agent (doc 15 §5.6 allocation contract).

## Neighbors

| Tree | Relation |
|---|---|
| `orchestrator/` (host agent) | Launches the VM via `HypervisorDriver`, passes `entrypoint_config_ref` opaquely (D38), stays runtime-ignorant |
| `proto/dreamserpent/runtime/v1/` | The contract `entrypoint/` implements; freezes at M0 |
| `images/` | Bakes the entrypoint binary and the D49-pinned runtime into the golden image |
| `client/` | The other half of the D38 seam (attach events); adapters there, never here |
| `assurance/e2e/` | Lifecycle tests exercising clone→entrypoint→attach→destroy |
