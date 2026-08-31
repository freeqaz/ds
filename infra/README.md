# infra/ — Provisioning & substrate tooling

**Owner workstream:** Orchestrator (doc 15 §2 — the provisioning shim row of the D80 assembly table) · **OSS tooling**, listed in `oss-manifest.yaml`

## Charter

Terraform definitions and provisioning shims that stand up **virtual-metal hosts** (D31) for the orchestrator to manage — the metal/instance substrate, base bootstrap, and per-demo cloud footprints. This is deployment tooling, not product: per the D80 assembly table, the provisioning shim is "OSS tooling, deliberately throwaway" and **speaks no protos** (Terraform-side only). Doc 02 §7 set the original shape: "Terraform defines the metal instance and base images; the orchestrator owns real-time VM lifecycle state."

## Governing decisions

| D | What it pins | Doc |
|---|---|---|
| D5/D32 | Prototype on the ESXi cluster; a capped rented-metal fallback is pre-approved but trigger-gated; AWS demo footprint created per demo | doc 03 §8, D32 in doc 04 §6 |
| D31 | Hosts are virtual-metal; **no native ESXi backend ever**; the govmomi shim is the one throwaway layer | doc 15 §1 |
| D33 | Cloud-agnostic, vanilla-Linux installable — nothing here may become a hard cloud dependency | doc 04 §6 |
| D81 | The D32 rented-metal fallback trigger is evaluable only from the M2 instrumented budget — don't pre-build Hetzner | doc 15 §8 |

## What must NOT live here

- **No protos, no gRPC** — anything that needs a contract belongs to the orchestrator (`proto/dreamserpent/hypervisor/v1` etc.). Provisioning is pre-contract by design.
- **No session/VM lifecycle logic** — real-time lifecycle is the orchestrator + host agent (`orchestrator/`); this tree only delivers a booted, baseline-conformant host.
- **No host-baseline content** — the kernel/sysctl/caps baseline is a versioned artifact in `dataplane/artifacts/host-baseline/` (doc 14 §11); Terraform here *applies* it, never defines it.
- **No native-ESXi orchestrator backend, ever** (D31) — ESXi is reached only through the throwaway govmomi shim in `shims/govmomi/`.

## Layout

| Dir | What |
|---|---|
| `terraform/esxi/` | Prototype virtual-metal substrate on the existing ESXi cluster (doc 03 §8) |
| `terraform/aws-demo/` | D32 per-demo AWS footprint variant |
| `shims/govmomi/` | The one deliberately-throwaway layer (doc 15 §1) |
