// SPDX-License-Identifier: Apache-2.0

// Package hostagent is the contract harness's FIRST real seam and proving ground
// (doc 15 §11, doc 06 §2.1): orchestrator <-> host agent. It wires the host
// agent's single conformance suite through the dual-run harness so the suite
// runs against BOTH a real reference implementation of HostAgentService AND the
// generated programmable fake, failing on any divergence.
//
// What this package contains:
//
//   - suite.go: the single conformance suite for the seam — a set of scenarios
//     stated purely in terms of the frozen hostagent.v1 contract (the streaming
//     ReportHeartbeat: a host opens one long-lived stream, emits a Heartbeat per
//     cadence, and the response returns on graceful close carrying beats_received,
//     doc 15 §5.2).
//   - refimpl.go: a minimal honest reference HostAgentService server. It is the
//     "real implementation" the suite runs against; the same suite runs against
//     the generated fake programmed to the same contract. This is the M0 stand-in
//     until the production host-agent reporting server lands in orchestrator/;
//     when it does, it replaces refimpl here and the suite is unchanged.
//   - dualrun_test.go: the per-commit gate — runs the suite real-vs-fake and
//     fails the build on divergence.
//
// Fixtures are synthetic only (D50); any proto change to this seam runs the full
// (c) matrix (D47).
package hostagent
