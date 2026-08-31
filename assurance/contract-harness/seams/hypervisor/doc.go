// SPDX-License-Identifier: Apache-2.0

// Package hypervisor is the contract-harness seam for the orchestrator <->
// host-agent HypervisorDriver verbs (doc 06 §2.1's first proving ground for the
// fake harness; doc 15 §11). It wires the HypervisorDriverService conformance
// suite through the dual-run harness so the SAME suite runs against BOTH a real
// reference implementation AND the generated programmable fake, failing the
// build on any divergence.
//
// What this package contains:
//
//   - suite.go: the single conformance suite for the seam — scenarios stated
//     purely in terms of the frozen hypervisor.v1 contract, exercising every one
//     of the ten HypervisorDriver verbs (GetCapabilities, CloneFromImage,
//     IssueAttachHandle, Snapshot, Suspend, Resume, Destroy, Migrate,
//     ExportDiskDelta, RecoverSessions). The suite asserts the four properties
//     the contract turns on (doc 15 §5.1): (i) IDEMPOTENCY on session_uuid —
//     re-issuing the same content-addressed request is a no-op returning the
//     same binding; (ii) HONEST capability flags (D35) — a driver advertising
//     supports_migrate / supports_instant_clone / supports_disk_delta_export =
//     false REFUSES the gated verb (FailedPrecondition) rather than no-op-
//     claiming success, the EC2-style honesty test (D32); (iii) RecoverSessions
//     re-adoption after a simulated restart; and (iv) the heartbeat /
//     observed-state report shape carried by ObservedSession (the §5.2 element
//     shared with the hostagent.v1 heartbeat).
//   - refimpl.go: a minimal honest in-memory reference HypervisorDriverService
//     — the "real implementation" side of the dual-run. Honest capability flags,
//     idempotent on session_uuid, minimal but correct. This is the M0 stand-in
//     until the production libvirt driver (a skeleton today) lands; when it does
//     it replaces refimpl here and the suite is unchanged — the suite is the
//     contract, not the implementation.
//   - dualrun_test.go: the per-commit gate — runs the suite real-vs-fake over an
//     in-process bufconn and fails on divergence, plus a negative test proving
//     the gate bites on a drifted fake.
//
// Owner: Assurance. Licensing: OSS (Apache-2.0, D25/D80; in oss-manifest.yaml).
// Capability honesty is D35; any proto change to this seam runs the full (c)
// guardrail matrix (D47); fixtures are synthetic only (D50).
package hypervisor
