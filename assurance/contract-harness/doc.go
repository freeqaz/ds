// SPDX-License-Identifier: Apache-2.0

// Package contractharness is the root of the fake-generation pipeline and the
// run-the-suite-against-real-AND-fake harness (doc 06 §2.1, doc 15 §5.6/§11).
//
// Two pieces live under this module:
//
//   - fakegen/ — the codegen step. Given a proto package's compiled gRPC
//     contract (its grpc.ServiceDesc + protobuf FileDescriptor), it emits a
//     programmable in-memory fake server and a fake-client helper: canned
//     responses plus recorded calls, NOT null stubs (doc 06 §2.1). The emitted
//     fakes land under proto/gen/go (the one shared module), beside the stubs
//     they fake, never in this tree (assurance/contract-harness/README.md).
//
//   - dualrun/ — the runner. It executes one conformance suite against BOTH a
//     real implementation and the generated fake, over an in-process bufconn
//     dial, and fails per-commit on any divergence. A divergence means either
//     the fake is lying (a downstream team is coding against fiction) or the
//     implementation drifted from the contract — both caught at the seam.
//
// The orchestrator <-> host agent seam (doc 15 §11) is the harness's first
// target and proving ground; its dual-run suite lives in seams/hostagent/.
//
// Governing decisions: D24 (versioned contracts with generated fakes + dual-run
// suites), D14 (stable contracts let workstreams deepen in parallel), D47
// (proto changes fail closed to the full matrix), D50 (synthetic fixtures only).
package contractharness
