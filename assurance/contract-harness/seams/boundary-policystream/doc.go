// SPDX-License-Identifier: Apache-2.0

// Package boundarypolicystream is the contract-harness seam for the
// boundary.v1 PolicyStreamService — the boundary->orchestrator policy
// distribution seam the D35 host agent subscribes to (doc 14 §2b, doc 15 §6;
// D36/D72; doc 06 §2.1's dual-run model). It wires the PolicyStreamService
// conformance suite through the dual-run harness so the SAME suite runs against
// BOTH a minimal honest reference implementation AND the generated programmable
// fake (boundaryv1fake.PolicyStreamServiceFake), failing the build on any
// divergence.
//
// The seam carries exactly two verbs:
//
//   - WatchPolicies(from_seq) — SERVER-STREAMING: the orchestrator (the D36
//     policy_log fan-out) replays the composed snapshot tail to the ONE
//     per-host subscriber (D72), resumable from from_seq. Every frame is a
//     boundary.v1.PolicySnapshot whose (seq, content_hash, document) identity is
//     the frozen shape (doc 13 §5 "Snapshot identity").
//   - AckPolicy(seq, content_hash) — UNARY: the consumer acknowledgement back to
//     the control plane. The ack proves the consumer saw and verified exactly
//     this snapshot before flipping to it; a NACK is the ABSENCE of an ack — a
//     hash/schema failure aborts the apply host-wide (doc 13 §5).
//
// What this package contains:
//
//   - suite.go: the single conformance suite for the seam — scenarios stated
//     purely in terms of the frozen boundary.v1 PolicyStreamService contract,
//     exercising BOTH verbs. The suite asserts the properties the policy-stream
//     seam turns on (doc 14 §2b, D36/D72): (i) the bigserial seq is THE single
//     monotonic policy version end to end — WatchPolicies(from_seq) replays
//     MONOTONIC, GAP-FREE seqs; (ii) the stream is RESUMABLE from an arbitrary
//     from_seq (the host agent's last persisted applied seq, D36 catch-up) and
//     from_seq past the tail yields an empty catch-up; (iii) snapshot identity is
//     (seq, content_hash, composed document) and content_hash tracks the
//     document deterministically; (iv) the AckPolicy round-trip echoes the acked
//     (seq, content_hash) and an out-of-band ack (a seq never streamed) is
//     refused honestly. The server-streaming WatchPolicies responder is drained
//     the way the hypervisor seam drains ExportDiskDelta — Recv until io.EOF.
//   - refimpl.go: a minimal honest in-memory reference PolicyStreamService — the
//     "real implementation" side of the dual-run. It keeps a single monotonic
//     seq log (the policy_log), assigns a fresh bigserial seq per appended row,
//     serves WatchPolicies(from_seq) as the composed snapshot tail from that log,
//     and validates AckPolicy against the seq/content_hash it actually streamed.
//     This is the M0 stand-in until the production orchestrator policy-stream
//     server lands; when it does it replaces refimpl here and the suite is
//     unchanged — the suite is the contract, not the implementation.
//   - dualrun_test.go: the per-commit gate — runs the suite real-vs-fake over an
//     in-process bufconn and fails on divergence, plus a negative test proving
//     the gate bites on a drifted fake (a WatchPolicies that skips a seq, the
//     gap-free monotonicity violation the policy version namespace depends on).
//   - streaming.go / streaming_test.go: the WatchPolicies STREAM-LIFECYCLE
//     hardening (mid-stream cancel, deadline expiry, slow-consumer back-pressure),
//     driven through the SHARED dualrun streaming affordance (StreamOpener with
//     CancelAfterFrames / DeadlineAfterFrames / SlowConsumer) against dedicated
//     bounded-park / eager-complete honest ends — the same tested driver the
//     hypervisor and orchestrator-session seams use, replacing the bespoke
//     reserved-cursor probe machinery. The negative gates prove the cancel/deadline
//     scenarios bite a cancel-swallowing stream and the slow-consumer scenario bites
//     a frame-dropping stream.
//
// Owner: Boundary/Assurance. Licensing: OSS (Apache-2.0, D25/D80; in
// oss-manifest.yaml). EXACTLY ONE WatchPolicies(from_seq) subscriber per host
// (D72) — the D35 host agent; the D36 policy_log bigserial seq is THE single
// policy version end to end (doc 13 §1 rule 3). The boundary.v1 PolicySnapshot /
// Ack messages are boundary-owned and imported, never re-declared. Any proto
// change to this seam runs the full (c) guardrail matrix (D47); fixtures are
// synthetic only (D50).
package boundarypolicystream
