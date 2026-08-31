// Package libvirt is the v0 HypervisorDriver: QEMU/KVM via libvirt inside
// the virtual-metal hosts (D29/D31). It lives HERE, in the host agent —
// doc 15 §5.1 places the driver with its caller; vm/ holds guest-side and
// disk tooling only (the vm/README RACI records this asymmetry).
//
// Contract: dreamserpent.hypervisor.v1 (freezes at M0, doc 05 §8) —
// GetCapabilities, CloneFromImage, IssueAttachHandle, Snapshot, Suspend,
// Resume, Destroy, Migrate (capability-gated), ExportDiskDelta (D29),
// RecoverSessions. Every verb idempotent on session_uuid.
//
// The contract leaks NO QEMU/libvirt specifics — that is the load-bearing
// property. The D30 re-evaluation seam (Cloud Hypervisor at M3) and the
// D29 ZFS/dm-thin alternatives must stay clean substrate swaps behind it.
//
// D30 ANTI-PATTERN NOTE (do not "fix" this):
//   - NO generic multi-hypervisor abstraction layer is to be built here.
//     The proto contract IS the abstraction; drivers are siblings under
//     internal/hypervisor/, not plugins under a framework.
//   - NO Firecracker driver (D30: Firecracker is out; the project's
//     faster-boot interest is tracked as the Cloud Hypervisor
//     re-evaluation at M3 — a driver swap, not a contract event,
//     doc 15 §8).
//   - NO native ESXi backend, ever (D31; the govmomi shim in
//     infra/shims/govmomi/ is the one deliberately-throwaway layer).
//
// Free (doc 15 §10): driver internals and libvirt-go usage — bounded by
// honest capability flags and the conformance suite driving wire
// behavior. The libvirt-go binding is recorded in go.mod's header as a
// pinned-later dependency; not declared until the contract freezes.
//
// CREATE PATH (doc 15 §4.1 steps 4–9, this package's HostAgent.CreateSession):
// the host-agent half of the canonical create sequence over the v0 driver.
//   - step 4: Allocator draws the never-recycled host-local index from a
//     persistent monotonic counter (IndexCounter), derives `dstap-<idx>`
//     (≤15 chars IFNAMSIZ) + the per-session guest IP deterministically from
//     the host AddressPlan (the guest subnet is a doc 13 §4 host-bring-up
//     FACT; ds-contracts owns the mark layout, not the address pool), invokes
//     the Boundary-owned tap-create primitive + per-session NFT objects
//     (empty allow{4,6}_<session> sets) through the AttachPrimitive seam, and
//     RECORDS the three-keys-agree Binding (D44/D66; the artifact
//     CloneFromImageResponse carries, doc 14 §4 RACI). The host agent is the
//     INVOKER — it never writes nft objects itself.
//   - step 6: the session-scoped digest-ack gate (mint-before-attach, D73).
//   - step 7: CloneFromImage creates the per-session qcow2 overlay (D29);
//     the per-session interception CA is injected FAIL-CLOSED before boot
//     (D17/D82) — injection failure FAILS THE CREATE.
//   - step 8: boot per the D38 entrypoint contract (event socket host-side).
//   - step 9: the structural routable gate (digest ack AND policy freshness,
//     D72) — enforced structurally, not by convention; the binding is
//     recorded before the routable verdict (the frozen §4.1 precedence).
//
// Per-step failures surface as *CreateError carrying the partial host-side
// state (binding / overlay / domain) so the sibling hostagent-destroy-teardown
// task can drive the matching compensating rollback (§4.1 Rollback). The
// boundary/identity-owned primitives are modeled as seams (seams.go) — the
// same deferred-binding posture internal/nftbridge uses for its ds-nft cgo
// edge — so the module stays stdlib-only and offline-buildable until the
// staticlib / proto-server wiring lands.
//
// Governing decisions: D17, D29, D30, D31, D35, D38, D44, D66, D72, D73,
// D75, D82. Primary doc: docs/15-orchestrator-design.md §4.1, §5.1.
package libvirt
