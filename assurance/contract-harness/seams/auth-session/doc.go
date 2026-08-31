// SPDX-License-Identifier: Apache-2.0

// Package authsession is the contract-harness seam for dreamserpent.auth.v1.TokenAttenuationService
// (D126/D129; doc 23 §9) — the DeriveAgentToken and ListDerivedTokens verbs that the
// orchestrator fan-out path (D18) calls at sub-token derivation time.
//
// Seam identity: dreamserpent.auth.v1.TokenAttenuationService (doc 23 §9; D129).
// Contract charter: doc 23 §5–§6, D126 monotonic narrowing + cascade revocation.
//
// Dual-run harness (doc 06 §2.1): the single Suite() runs against both the
// reference implementation and the generated programmable fake. Any divergence
// is a contract bug at the seam — either the fake lies or the impl drifted.
// Scenarios are stated purely in terms of the frozen proto contract; the token
// substrate (Biscuit/JWT) is format-opaque at this seam.
//
// Three invariants under test (doc 23 §5–§6, D126/D127):
//   - token-narrowing-monotonicity: derived scopes ⊆ parent scopes
//   - token-chain-revocation: RevokeToken(parent_jti) cascades to derived tokens
//   - token-hierarchy-separation: derived_jti ≠ parent_jti, different shapes
package authsession
