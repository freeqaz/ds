// SPDX-License-Identifier: Apache-2.0

// Package orchestratorpolicy is the contract-harness seam for the
// orchestrator.v1 PolicyService — the policy_log append / watch / grant surface
// the control-plane orchestrator serves (doc 15 §5.3, D36/D72; doc 06 §2.1's
// dual-run model). It wires the PolicyService conformance suite through the
// dual-run harness so the SAME suite runs against BOTH a minimal honest
// reference implementation AND the generated programmable fake
// (orchestratorv1fake.PolicyServiceFake), failing the build on any divergence.
//
// What this package contains:
//
//   - suite.go: the single conformance suite for the seam — scenarios stated
//     purely in terms of the frozen orchestrator.v1 PolicyService contract,
//     exercising all three verbs (AppendPolicy, WatchPolicies, ApproveAsk). The
//     suite asserts the properties the policy_log seam turns on (doc 15 §5.3,
//     D36/D72): (i) the bigserial seq is THE single policy version namespace —
//     AppendPolicy and ApproveAsk both assign MONOTONIC, GAP-FREE seqs from one
//     log; (ii) WatchPolicies(from_seq) serves a SNAPSHOT-THEN-DELTA stream of
//     boundary.v1.PolicySnapshot frames whose seqs are monotonic and gap-free;
//     (iii) the stream is RESUMABLE from an arbitrary from_seq (the host agent's
//     last persisted applied seq, D36 catch-up) and from_seq past the tail
//     yields an empty catch-up; (iv) snapshot identity is (seq, content_hash,
//     composed document) and content_hash tracks the document deterministically.
//     The server-streaming WatchPolicies responder is drained the way the
//     hypervisor seam drains ExportDiskDelta.
//   - refimpl.go: a minimal honest in-memory reference PolicyService — the "real
//     implementation" side of the dual-run. It keeps a single monotonic seq log
//     (the policy_log), assigns a fresh bigserial seq per appended/granted row,
//     and serves WatchPolicies(from_seq) as the composed snapshot tail from that
//     log. This is the M0 stand-in until the production orchestrator policy
//     server lands; when it does it replaces refimpl here and the suite is
//     unchanged — the suite is the contract, not the implementation.
//   - dualrun_test.go: the per-commit gate — runs the suite real-vs-fake over an
//     in-process bufconn and fails on divergence, plus a negative test proving
//     the gate bites on a drifted fake (a WatchPolicies that skips a seq, the
//     gap-free monotonicity violation).
//   - streaming.go / streaming_test.go: the WatchPolicies STREAM-LIFECYCLE
//     hardening (mid-stream cancel, deadline expiry, slow-consumer back-pressure),
//     driven through the SHARED dualrun streaming affordance (StreamOpener with
//     CancelAfterFrames / DeadlineAfterFrames / SlowConsumer) against dedicated
//     bounded-park / eager-complete honest ends — the same tested driver the
//     hypervisor and orchestrator-session seams use, replacing the bespoke
//     seed-a-large-tail probe machinery. The negative gates prove the cancel/deadline
//     scenarios bite a cancel-swallowing stream and the slow-consumer scenario bites
//     a frame-dropping stream.
//
// Owner: Assurance. Licensing: OSS (Apache-2.0, D25/D80; in oss-manifest.yaml).
// The policy_log IS the audit trail and the seq is the single version namespace
// (D36/D72); the boundary.v1.PolicySnapshot is boundary-owned and imported, never
// re-declared (doc 15 §5.3 ownership mark). Any proto change to this seam runs
// the full (c) guardrail matrix (D47); fixtures are synthetic only (D50).
package orchestratorpolicy
