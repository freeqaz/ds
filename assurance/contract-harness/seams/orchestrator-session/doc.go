// SPDX-License-Identifier: Apache-2.0

// Package orchestratorsession is the contract-harness seam for the
// orchestrator.v1 SessionService control-plane verbs (doc 06 §2.1's fake-harness
// proving ground; doc 15 §5.3/§11). It wires the SessionService conformance
// suite through the dual-run harness so the SAME suite runs against BOTH a real
// reference implementation AND the generated programmable fake, failing the
// build on any divergence.
//
// What this package contains:
//
//   - suite.go: the single conformance suite for the seam — scenarios stated
//     purely in terms of the frozen orchestrator.v1 SessionService contract,
//     exercising every one of the control-plane verbs (CreateSession,
//     DestroySession, SuspendSession, ResumeSession, SnapshotSession,
//     ListSessions, WatchSession, Attach, CreateChildSession, RecordEnvConfig).
//     The suite asserts the properties the contract turns on (doc 15 §5.3/§4.2):
//     (i) IDEMPOTENCY on session_uuid — re-issuing the same content-addressed
//     CreateSession returns the SAME session record (same SessionRef quartet),
//     never a freshly-allocated second one; (ii) the §4.2 DestroySession
//     teardown — the terminal DESTROYED record plus an idempotent retry that
//     SUCCEEDS rather than erroring NotFound; (iii) ListSessions enumeration of
//     the live fleet; and (iv) the WatchSession event leg — the D18 session-event
//     fan-out carrying attach.v1.SessionEvent (the §3 state vocabulary, every
//     event seq-numbered, the §6/§6.1 attach-event checklist).
//   - refimpl.go: a minimal honest in-memory reference SessionService — the
//     "real implementation" side of the dual-run. Idempotent on session_uuid,
//     keyed + mutex-guarded, minimal but correct. This is the M0 stand-in until
//     the production orchestrator control plane (a skeleton today) lands; when it
//     does it replaces refimpl here and the suite is unchanged — the suite is the
//     contract, not the implementation.
//   - dualrun_test.go: the per-commit gate — runs the suite real-vs-fake over an
//     in-process bufconn and fails on divergence, asserts CreateSession /
//     DestroySession idempotency directly against the generated fake's *Recorded()
//     call-capture accessors, plus a negative test proving the gate bites on a
//     drifted fake.
//
// Owner: Assurance. Licensing: OSS (Apache-2.0, D25/D80; in oss-manifest.yaml).
// orchestrator-lite (OSS) and the paid fleet control plane implement the SAME
// package (D80), so this seam is the shared conformance gate for both. The
// session state vocabulary the WatchSession leg carries is the frozen doc 15 §3
// machine (D35/D46/D77); any proto change to this seam runs the full (c)
// guardrail matrix (D47); fixtures are synthetic only (D50).
package orchestratorsession
