// SPDX-License-Identifier: Apache-2.0

// Package identityvalidate is the contract-harness seam for the identity.v1
// IdentityValidationService.Validate verb — the D22 identity-validation seam
// (doc 16 §4 / §9; doc 06 §2.1's fake-harness proving ground). It wires the
// Validate conformance suite through the dual-run harness so the SAME suite runs
// against BOTH a real reference validator AND the generated programmable fake,
// failing the build on any divergence.
//
// The seam under test is the single unary verb ds-tlsproxy's swap executor calls
// in-line on the TLS-terminating egress gateway's swap path (doc 16 §4): one
// frozen Validate contract is what makes the Identity substrate progression — M0
// throwaway shim -> M1 minimal CA -> M3 SPIFFE/SPIRE — a substrate swap behind a
// frozen contract, not a rebuild (D22; doc 16 §2). The presented credential is
// FORMAT-OPAQUE at the seam (doc 16 §4, doc 19 §5/§6), so a substrate flip
// (Biscuit primary, macaroons the named alternative) is a Validate-internal
// property, never a contract event.
//
// What this package contains:
//
//   - suite.go: the single conformance suite for the seam — scenarios stated
//     purely in terms of the frozen identity.v1 Validate contract. It asserts the
//     properties the contract turns on (doc 16 §5.1, doc 19 §5/§8): (i)
//     GRANT-INTERSECTION evaluated AT Validate — the session's grant set is
//     intersected with the presented token's attenuated scope, so the ALLOW
//     reaches only the intersection and the returned expiry is the TIGHTER of the
//     grant TTL and the token TTL; (ii) EXPIRY rejection — a stale credential is
//     denied (TTL is the minimal-CA revocation instrument, doc 16 §5.4); (iii)
//     OVER-SCOPE refusal — a service outside the token's attenuation, or outside
//     the session's grants, is refused with an honest machine-readable reason;
//     (iv) SESSION-LIVENESS rejection — a revoked / unknown session fails closed
//     (no CRL/OCSP, so liveness is the catch, doc 16 §5.4); and (v) IDEMPOTENT
//     validation — re-presenting the same credential yields the same verdict.
//   - refimpl.go: a minimal honest in-memory reference validator — the "real
//     implementation" side of the dual-run. ALLOW iff (signature/shape +
//     freshness + session liveness + grant lookup, intersected) all hold; every
//     other outcome is an honest DENY carrying a machine-readable reason
//     (malformed / expired / not-live / out-of-grant), never a silent zero-value
//     ALLOW. This is the M0/M1 stand-in behind the frozen D22 seam; when a
//     production validator lands it replaces refimpl and the suite is unchanged —
//     the suite is the contract, not the implementation.
//   - dualrun_test.go: the per-commit gate — runs the suite real-vs-fake over an
//     in-process bufconn and fails on divergence, asserts the grant-intersection
//     / expiry / over-scope contract directly against the generated fake's
//     Validate *Recorded() call-capture accessor, plus a negative drift-gate test
//     proving the gate bites on a lying fake (a blanket-ALLOW validator that
//     ignores the intersection).
//
// Owner: Identity / Assurance. Licensing: OSS (Apache-2.0, D25/D80; in
// oss-manifest.yaml — the D26/D51 conformance, cred-never-in-VM and
// canary-never-egresses, must be runnable against any deployment, which forces
// an OSS-runnable validation path, doc 16 §2). Every substrate plus
// customer-IdP-backed identities satisfies this exact D24-versioned Validate
// contract (doc 16 §9); any proto change to this seam runs the full (c)
// guardrail matrix (D47); fixtures are synthetic only (D50).
package identityvalidate
