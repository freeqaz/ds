// SPDX-License-Identifier: Apache-2.0

// Package appinstall holds the executable form of the doc 16 §13
// "App-install read-level subset" guardrail-conformance row (D51 public claims
// package; D83/D56; ratified 2026-06-12).
//
// THE CLAIM (doc 16 §13, verbatim in substance). The GitHub App install's
// **read** level is exactly the three `*:read` rows of the doc 16 §5.2 D83
// App-install permission inventory — `contents:read`, `actions:read`,
// `metadata:read` — and **no write scope exists at read level**. The ratified
// onboarding CI-read scope set {contents:read, actions:read, metadata:read} is a
// strict read-only subset of the access the App install is already positioned
// for (CI dispatch, status checks, the D56 enrollment flow). This is the
// credential-scope guard for the D115 read-only-draft onboarding posture
// (doc 07 OQ3): even a misbehaving onboarding agent holds no scope that could
// widen the read into a write.
//
// THE CHECK (mechanical diff). A synthetic fixture manifest of requested GitHub
// App permissions — each row {permission, access level, consuming flow} — is
// diffed against the §5.2 inventory (the single anchor, "D83 App-install
// permission inventory"). The diff FAILS on:
//
//	(a) any onboarding-path permission above read level;
//	(b) any write scope on the onboarding read path;
//	(c) any requested permission absent from the inventory.
//
// THE ANCHOR (one source, no second copy of the table). The §5.2 inventory is
// not hand-copied into Go: InventoryFromDoc16 parses the live doc 16 §5.2 table
// at test time, and a guard test asserts the parsed inventory carries exactly
// the ratified read-only triplet at read level with no write scope (so a doc
// edit that widened §5.2 would fail HERE, not silently pass). The check then
// diffs each fixture manifest against that parsed inventory.
//
// SYNTHETIC ONLY (D50). Every fixture under fixtures/ is hand-authored against
// the DOCUMENTED GitHub App permission shape and carries a `.provenance`
// sidecar (scripts/check-fixture-provenance.sh). Nothing here touches live
// GitHub, mints any grant, or holds a real credential — it records and asserts
// the §5.2 invariant, mints nothing (doc 16 §5.2 / §13).
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"). This row is
// oss-runnable: it is a static manifest-vs-inventory diff with no data-plane
// dependency, so it executes on any checkout via `go test ./...` from any cwd
// (the fixture and doc paths are anchored off runtime.Caller, not the process
// working directory).
package appinstall
