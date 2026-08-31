// SPDX-License-Identifier: Apache-2.0

// Package identitydigestfeed is the contract-harness seam for the identity.v1
// DigestFeedService secret-digest feed — the producer→boundary seam (doc 06
// §2.1's fake-harness proving ground; doc 16 §6/§6.6/§9, doc 14 §7; D73/D84). It
// wires the DigestFeedService conformance suite through the dual-run harness so
// the SAME suite runs against BOTH a real reference implementation AND the
// generated programmable fake, failing the build on any divergence.
//
// The seam under test is the Stage-0 producer→boundary digest feed: Identity
// computes HMAC digests of every credential it mints (tagged ISSUED{service_id})
// or guards (tagged FORBIDDEN) and pushes them — plus their encoded variants — to
// the boundary host so ds-tlsproxy's SecretMatcher can block a secret at first
// egress WITHOUT ever seeing the plaintext. It is NOT a stream: it exposes the
// two UNARY verbs DigestPublish and DigestRevoke (doc 16 §6.6/§9).
//
// What this package contains:
//
//   - suite.go: the single conformance suite for the seam — scenarios stated
//     purely in terms of the frozen identity.v1 DigestFeedService contract,
//     exercising both UNARY verbs (DigestPublish, DigestRevoke). The suite asserts
//     the properties the contract turns on (doc 14 §7, doc 16 §6): (i) the FROZEN
//     ENTRY SHAPE — key id / algo / digest bytes / cred-class oneof
//     (ISSUED{service_id} | FORBIDDEN) / scope / expiry / variant tag
//     (RAW|BASE64|URLENC|HEX); (ii) the publish ACK — committed=true echoing the
//     batch id and naming the acking consumer (mint-before-attach, doc 16 §6.1;
//     the host agent acks, D109); (iii) publish→revoke ORDERING + IDEMPOTENCY —
//     a re-publish converges to the same digest set and an idempotent revoke of an
//     already-gone key id SUCCEEDS committed (teardown flush, doc 16 §6.2/§5.4);
//     and (iv) the HONEST ERROR paths — an empty batch, a missing session, an
//     under-specified entry, and a fleet-scope request on this session-lifecycle
//     seam are all refused, never silently routed open (fail-closed, doc 16 §6).
//   - refimpl.go: a minimal honest in-memory reference DigestFeedService — the
//     "real implementation" side of the dual-run. It tracks the published/revoked
//     digest set per session keyed by (session, key_id) — holding only key ids,
//     never a secret (plaintext-never-crosses is structural, doc 14 §7). This is
//     the M0 stand-in until the production Identity digest producer (a skeleton
//     today) lands; when it does it replaces refimpl here and the suite is
//     unchanged — the suite is the contract, not the implementation.
//   - dualrun_test.go: the per-commit gate — runs the suite real-vs-fake over an
//     in-process bufconn and fails on divergence, asserts the publish/revoke
//     digest shape directly against the generated fake's *Recorded() call-capture
//     accessors (the cred-class oneof, the variant tag, no plaintext), plus a
//     negative test proving the gate bites on a drifted fake (a DigestRevoke that
//     errors NotFound on the idempotent teardown flush).
//
// Owner: Identity / Assurance. Licensing: OSS (Apache-2.0, D25/D80; in
// oss-manifest.yaml). The OSS data plane includes the session digest producer
// (doc 16 §2, D85), so this seam is the shared conformance gate. The frozen entry
// shape + invariants are doc 14 §7 law (D73); the scope classification
// (SESSION on this seam, FLEET on the policy stream) is frozen per D72/D73; any
// proto change to this seam runs the full (c) guardrail matrix (D47); fixtures are
// synthetic only (D50).
//
// NOTE (follow-up): the new seam directory is not yet registered in the
// Boundary-owned guardrail-map.yaml; an unmapped path fails closed to the full
// matrix (D47), so this is safe — the registration is a tracked follow-up, not a
// blocker.
package identitydigestfeed
