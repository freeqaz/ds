// SPDX-License-Identifier: Apache-2.0

// Package identitymint is the contract-harness seam for the identity.v1
// IdentityMintService interception-CA mint verb (doc 06 §2.1's fake-harness
// proving ground; doc 16 §4/§9). It wires the MintInterceptionCA conformance
// suite through the dual-run harness so the SAME suite runs against BOTH a real
// reference implementation AND the generated programmable fake, failing the
// build on any divergence.
//
// The seam under test is the Stage-0 freeze surface of IdentityMintService
// (D82, doc 16 §9): of the doc 16 §4 mint sketch, only MintInterceptionCA rides
// the Stage-0 flip, so it is the only verb the proto exposes today and the only
// one this seam drives. The remaining mint RPCs (MintWorkloadIdentity /
// MintGrants / MintSessionToken / RevokeSession) are reserved, not yet on the
// wire, and are NOT invented here — the suite drives exactly what the proto
// exposes.
//
// What this package contains:
//
//   - suite.go: the single conformance suite for the seam — scenarios stated
//     purely in terms of the frozen identity.v1 MintInterceptionCA contract
//     (doc 16 §4). It asserts the properties the contract turns on:
//     (i) IDEMPOTENCY on the request key (the session_ref/session_uuid) — minting
//     the interception CA for the same session twice returns the SAME per-session
//     CA material (same cert/key/expiry), never a freshly-allocated second CA,
//     because the CA is per-session-lifecycle data (the D72-exempt class, doc 16
//     §4); (ii) the D82 INTERCEPTION-VS-WORKLOAD SEPARATION where observable on
//     this seam — the minted CA carries an interception-root identifier, never a
//     workload-root one, so the egress-gateway TLS-termination capability and the
//     workload-identity attribution capability fail independently; and
//     (iii) honest error paths/codes — a mint missing the session_ref join key is
//     refused InvalidArgument before any CA is materialized.
//   - refimpl.go: a minimal honest in-memory interception-CA mint stand-in — the
//     "real implementation" side of the dual-run. Idempotent on the session key,
//     keyed + mutex-guarded, minting only under the interception root. This is
//     the M0 stand-in until the production Identity mint service lands; when it
//     does it replaces refimpl here and the suite is unchanged — the suite is the
//     contract, not the implementation.
//   - dualrun_test.go: the per-commit gate — runs the suite real-vs-fake over an
//     in-process bufconn and fails on divergence, asserts the mint behavior
//     directly against the generated fake's *Recorded() call-capture accessors,
//     plus a NEGATIVE test proving the gate bites on a drifted fake (one that
//     mints a fresh second CA on the idempotent re-issue, breaking the per-session
//     contract).
//
// Owner: Identity / Assurance. Licensing: OSS (Apache-2.0, D25/D80; in
// oss-manifest.yaml). The OSS minimal-CA mint and the higher-tier substrate
// (M3 SPIFFE/SPIRE) satisfy the SAME D24-versioned contract behind the frozen
// D22 mint seam (doc 16 §2), so this seam is the shared conformance gate for
// both. The two-root-hierarchy separation (workload-identity vs interception) is
// the D82 decision-log property the suite asserts where observable (doc 16 §4);
// any proto change to this seam runs the full (c) guardrail matrix (D47);
// fixtures are synthetic only (D50).
package identitymint
