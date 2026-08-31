// SPDX-License-Identifier: Apache-2.0

// Package fleetreg is the D84 fleet-scope secret-digest registration surface:
// the control-plane API + CLI that decides which Vault trees the digest producer
// may read, and turns each designation / per-secret registration into a
// fleet-scope digest registration that rides the EXISTING policy_log/PolicySink
// seam — never a new proto, never a new RPC.
//
// # The D84 designation flow (doc 16 §6.4 / §11.3)
//
// The security team designates Vault mounts / path prefixes during 2c
// onboarding (doc 16 §11.3; the D23 2c motion):
//
//   - DEFAULT: none. Before any designation, the producer digests nothing —
//     the consent surface starts empty, so an unconfigured integration touches
//     ZERO plaintext (doc 16 §11.3 step 1).
//   - Prefix designation (the 2c motion). Designating a mount/path prefix is the
//     single auditable scoping decision (doc 16 §11.3 step 2); everything under it
//     is digested automatically.
//   - Inheritance. A secret newly written under a designated prefix inherits
//     protection on the next sync without re-designation (doc 16 §11.3 step 4) —
//     the property per-secret-only registration cannot give: coverage does not rot.
//   - Per-secret registration — the manual escape hatch. For credentials that
//     live OUTSIDE any designated prefix (unmanaged trees, one-off credentials),
//     explicit per-secret registration joins one path to the feed without
//     designating its whole tree (doc 16 §11.3 step 5). This is the escape hatch,
//     not the default — the prefix path is what scales.
//
// The producer's plaintext-read scope is exactly the union of designated
// prefixes plus per-secret registrations — never broader (doc 16 §6.4): "the
// producer touches plaintext only for designated trees" (D84) is enforced here
// by [Registry.Covers], the in-process analogue of the same Vault-role scoping
// that bounds the platform-service auth (doc 16 §11.3).
//
// # Authority defaults (D84)
//
// Org admin for org credentials; any developer for credentials they own (doc 16
// §6.4 / §11.3 step 5). Enforced at the registration entrypoint by
// [Authorizer.Authorize] — a non-authorized actor's registration is refused with
// nothing appended (the fail-closed shape the policy_log path already uses).
//
// # The policy_log/PolicySink artifact path (D72)
//
// Fleet-scope registration/revocation is a POLICY ARTIFACT under the policy_log
// seq (doc 16 §6.2), inheriting the POL-4 seconds-scale revocation bar (doc 16
// §6.2). It rides the SAME [github.com/dream-serpent/dream-serpent/identity/digest.PolicySink]
// seam identity/digest already uses — a Go interface onto
// orchestrator.v1.PolicyService's append path, NOT a new RPC ("two cadences, no
// third channel", D72). [Manager.Register] / [Manager.Revoke] build the
// fleet-scope credential set with the digest producer and append it via
// digest.PublishFleetPolicy / digest.RevokeFleetPolicy: plaintext is digested
// and dropped exactly as on the producer's own fleet path.
//
// # Scope fence
//
//   - The digest MATH (HMAC, variants, key lifecycle) is
//     [github.com/dream-serpent/dream-serpent/identity/digest]'s; this module only
//     decides WHICH credentials become fleet digests and drives the existing verbs.
//   - The KV READ surface (list/read designated trees) is
//     [github.com/dream-serpent/dream-serpent/identity/kv-client]'s; this module
//     consumes the [DigestSource] seam those reads satisfy, never editing it.
//   - The policy_log RPC + the per-host WatchPolicies fan-out are the
//     orchestrator's; this module appends through the PolicySink interface and an
//     in-process fake satisfies it in tests (D50, no live boundary).
//   - The AWS Secrets Manager second store and the dashboard are explicitly out
//     of scope; both slot behind the same DigestSource / registration seam later.
//
// D-numbers: D84 (mount/path-prefix opt-in, default none, escape hatch, authority
// defaults), D72 (fleet = policy artifact, no third channel), D55 (OpenBao KV
// integration / order yields to the first partner), D85 (OSS line: generic KV
// client + digest producer are OSS), D50 (synthetic fixtures only). Sources:
// doc 16 §6.4, §9 (the fleet-digest-registration owned-interface row), §11.3
// (the D84 designation flow, end to end).
package fleetreg
