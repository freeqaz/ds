// SPDX-License-Identifier: Apache-2.0

// Package hypervisorcaps is the conformance adapter that drives the v0 libvirt
// HypervisorDriverService's CAPABILITY-HONESTY contract over an in-process gRPC
// wire (doc 15 §5.1 "the EC2 demo driver as the honesty test" + §10 "Frozen-vs-free,
// bounded by honest capability flags + the conformance suite driving wire behavior";
// doc 06 §2.2 proxy/seam wire-conformance + §3 (a) contract tests; D26/D51 the
// public executable spec drives wire behavior, not a cosmetic claim).
//
// # What gap this closes (01KV654J5W)
//
// GetCapabilities advertises supports_instant_clone + supports_disk_delta_export
// (proto Capabilities). The capability-honesty contract (doc 15 §5.1) says a
// DISHONEST flag must become a CAUGHT contract violation: a flag that claims a
// capability whose backing verb does not actually do the work over the wire is a
// lie the conformance suite exists to catch (the EC2 demo driver answers all flags
// FALSE precisely so it never lies). Before this adapter that closure was asserted
// only LOCALLY, inside the orchestrator package's own service_test.go. This adapter
// closes the loop the contract is designed around from OUTSIDE the owning module:
// it stands a HypervisorDriverService up on a real in-process gRPC server and
// DRIVES the wire behavior each true flag claims —
//
//   - supports_instant_clone=TRUE ⇒ CloneFromImage must return a NON-EMPTY binding
//     (a host_session_index + tap_name + family-tagged guest IP + overlay_path) —
//     the instant-clone artifact. An empty binding behind a true flag is the
//     dishonesty this exercise FAILS on.
//   - supports_disk_delta_export=TRUE ⇒ ExportDiskDelta must be REACHABLE as the
//     backing verb. The v0 driver advertises the flag TRUE (the dirty-bitmap qcow2
//     substrate exists, D29) but the streaming verb is the HONEST GAP today: a
//     driver built without a host-side DiskDeltaExporter answers ExportDiskDelta
//     with codes.Unimplemented. This adapter asserts that gap is surfaced HONESTLY
//     (codes.Unimplemented — the documented gap, NOT a silently-passed false-true
//     flag) AND that, once the backing exporter is wired, the same verb STREAMS the
//     delta over the wire (the flag becomes fully backed).
//   - supports_migrate=FALSE ⇒ Migrate is honestly Unimplemented; a false flag is
//     allowed to have no backing verb (the EC2-honesty direction), so the adapter
//     asserts only that a FALSE flag is consistent with an Unimplemented verb.
//
// # Why a faithful in-process server, not a direct import of the real DriverService
//
// The v0 libvirt DriverService lives at orchestrator/internal/hypervisor/libvirt —
// an INTERNAL package of the orchestrator module, which Go's internal-package rule
// forbids importing from this (the assurance/conformance-adapter) module, and which
// the adapter's go.mod deliberately does NOT path-replace (proto/gen/go is the one
// legal cross-tree import, D80; this module keeps its tlsproxyinspect/grantfetch
// replace set, no orchestrator edge). So this adapter cannot link the real
// *libvirt.DriverService struct. Instead it stands up an in-process
// HypervisorDriverServiceServer (capsServer, caps.go) that FAITHFULLY reproduces
// the DriverService's DOCUMENTED capability-honesty contract over the frozen
// hypervisor.v1 wire — the same honest flags, the same instant-clone binding shape,
// the same honest-Unimplemented disk-delta gap, the same once-wired streaming. The
// conformance value is in the WIRE CLOSURE the adapter drives (true-flag ⇒
// exercised-backing-verb, false-flag ⇒ Unimplemented-allowed), which is module-
// agnostic: it runs against any server registered behind the frozen contract.
//
// LIVE / DEFERRED-MANUAL SEAM: pointing this same wire closure at the ACTUAL
// orchestrator *libvirt.DriverService (rather than the faithful in-process server
// here) is a host-side / in-orchestrator-module step deferred behind the
// orchestrator package's own service_test.go (which already drives the real
// DriverService over the identical dialInProcess loopback). When the executable
// spec gains a non-internal handle to the real server (a re-export, or this adapter
// moving under the orchestrator module), Exercise* below is the ready driver — it
// asserts only the wire contract, never any libvirt/qcow2 internal.
//
// # Synthetic / in-process only (D50)
//
// The server is driven over a real loopback gRPC connection (the orchestrator
// service_test.go dialInProcess idiom: net.Listen 127.0.0.1:0 + grpc.NewServer +
// grpc.NewClient with insecure creds) — an in-memory wire, no off-box transport,
// no libvirt-go/cgo, no qcow2, no live VM/KVM/sudo. Bindings + delta bytes are
// obviously-synthetic fixtures. proto/gen/go is the one legal cross-tree import
// (D80); grpc + protobuf arrive through the module's existing require set, no
// go.mod change.
package hypervisorcaps
