# infra/shims/govmomi/ — The one deliberately-throwaway layer

**Owner workstream:** Orchestrator · **OSS tooling**

## Charter

The govmomi-based provisioning shim that lets the prototype run on ESXi (doc 03 §8) without ESXi ever entering the product: it creates/configures the **virtual-metal host VMs** that `infra/terraform/esxi/` defines, then tears them down. Doc 15 §1 names it directly: "**no native ESXi backend ever; the govmomi shim is the one throwaway layer**." It is listed in the D80 assembly table as "provisioning shim (govmomi / Hetzner / AWS variants) — OSS tooling, deliberately throwaway."

Scope is **strictly provision + destroy of a virtual-metal host** — `provision` is idempotent/repeatable, `destroy` is clean. Each provisioned VM (a) **exposes hardware-assisted virtualization to the guest** (`NestedHVEnabled=true` — the exact property that makes `/dev/kvm` appear, see `../../terraform/esxi/BRINGUP.md`) and (b) lands its disk on the **NVMe-tier datastore** (doc 03 §8), so the host agent's nested KVM/libvirt/qcow2 stack runs inside it and the rest of the platform treats it as bare metal.

## Governing decisions (pins)

- **D31** — hosts are virtual-metal; **no native ESXi backend, ever**. This shim is the only ESXi-specific code permitted; the orchestrator's HypervisorDriver contract (`proto/dreamserpent/hypervisor/v1`) must never grow ESXi fields.
- **D35** — the host stack is nested KVM/libvirt/qcow2 *inside* the provisioned VM; the shim's only job toward that is exposing nested HV + NVMe storage (it never installs or configures the in-guest stack — BRINGUP.md does).
- **D66** — the shim keeps **out of session-level networking**: the ESXi side has one ordinary non-trunk uplink port group (Reject ×3); all per-session networking happens inside the VM. This shim attaches no NICs and configures no networks.
- **D80** — OSS/paid split on service boundaries; this is OSS tooling that **speaks no protos** and **imports nothing from `go.work`**. It is a standalone Go module (`go.mod` below), built and tested with `GOWORK=off`. govmomi is a provisioning-time dependency *of this shim only* — never in `orchestrator/` or any product `go.mod`.

## Rules of the throwaway layer

- **Speaks no protos.** The moment something here wants a gRPC contract, it has escaped its charter — stop and move it.
- **No VM/session lifecycle** (host agent's, via libvirt — doc 15 §5.1), no hypervisor drivers, nothing another tree imports. When virtual metal moves off ESXi, this directory is removed wholesale.
- Sibling shims (Hetzner if the D32 fallback ever fires, AWS for `../../terraform/aws-demo/`) are new siblings, not generalizations of this one.
- **Single-operator only.** `provisionVM` does a name lookup and *then* creates, so two concurrent provisioners of the same name could both pass the lookup and both create — a benign TOCTOU window that is fine for single-operator bring-up but **not** safe to drive from a concurrent control loop. This shim is throwaway provisioning, not a reconciler; run it one operator at a time.

## Env-var / flag contract

Connection inputs default from the environment (the same `GOVC_*` names `govc` uses); every value is also overridable by flag. Placement inputs left empty resolve to the target's default datacenter / resource pool / datastore / folder.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-url` | `GOVC_URL` | — (required) | vCenter SDK endpoint; bare host or `https://host/sdk` |
| `-username` | `GOVC_USERNAME` | — | vCenter username (overrides any userinfo in `-url`) |
| `-password` | `GOVC_PASSWORD` | — | vCenter password |
| `-insecure` | `GOVC_INSECURE` | `false` | skip vCenter TLS verification (lab vCenter) |
| `-datacenter` | `GOVC_DATACENTER` | default | datacenter path |
| `-datastore` | `GOVC_DATASTORE` | default | **NVMe-tier** datastore name (doc 03 §8) |
| `-pool` | `GOVC_RESOURCE_POOL` | default | resource pool path |
| `-host` | `GOVC_HOST` | cluster default | host system path |
| `-folder` | `GOVC_FOLDER` | default | VM inventory folder path |
| `-name` | `GOVC_VM` | — (required) | virtual-metal host VM name |

`provision` only — sizing of the host VM:

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-vcpus` | `GOVC_VM_VCPUS` | `4` | guest vCPU count |
| `-memoryMB` | `GOVC_VM_MEMORY_MB` | `16384` | guest memory (MiB) |
| `-diskGB` | `GOVC_VM_DISK_GB` | `100` | primary disk (GiB) on the NVMe datastore |
| `-guest-id` | `GOVC_VM_GUEST_ID` | `otherLinux64Guest` | vSphere guest OS identifier |

## Usage

```sh
go build -o govmomi-shim .   # GOWORK=off; standalone module

export GOVC_URL='vcenter.lab.example/sdk'
export GOVC_USERNAME='administrator@vsphere.local'
export GOVC_PASSWORD='…'
export GOVC_INSECURE=1                 # lab vCenter with a self-signed cert
export GOVC_DATASTORE='nvme-ds-0'      # the NVMe-tier datastore

# Stand up a virtual-metal host (idempotent — re-running is a no-op if it exists).
./govmomi-shim provision -name ds-vmetal-0 -vcpus 16 -memoryMB 65536 -diskGB 700

# … then bring the in-guest host stack up: see ../../terraform/esxi/BRINGUP.md.

# Tear it down (clean; a no-op if already absent).
./govmomi-shim destroy -name ds-vmetal-0
```

After `provision`, the VM is powered on but bare. The in-guest nested-KVM/libvirt/qcow2 bring-up is the **next step** and lives in `../../terraform/esxi/BRINGUP.md` (the manual companion to the ESXi Terraform). This shim deliberately stops at "a booted, nested-HV-capable VM on NVMe storage."

## Tests (vcsim)

The shim is proven **exclusively against the govmomi in-process vCenter simulator** (`github.com/vmware/govmomi/simulator`, "vcsim") — no real vCenter/ESXi, no credentials, no network:

```sh
GOWORK=off go test ./...
```

`provision_test.go` drives the same `provisionVM` / `destroyVM` core the CLI calls against a simulated single-cluster datacenter: it provisions, asserts the VM exists and that its config carries `NestedHVEnabled=true` (nested virt) plus the requested disk on the requested NVMe datastore and is powered on, checks `provision` is idempotent, then destroys and asserts the VM is gone (and that a second `destroy` is a clean no-op). The adversarial tests also pin the failure paths: provisioning into a non-existent datastore or resource pool name returns the clear wrapped error (`datastore %q (NVMe tier): %w` / `resource pool %q: %w`) and **leaves no orphaned VM in inventory**, and destroying a powered-on VM exercises the `powerOffIfOn` invariant (a powered-on VM cannot be destroyed) before the teardown succeeds.
