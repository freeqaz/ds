// SPDX-License-Identifier: Apache-2.0

// Package canvasboard is the contract-harness seam for the canvas.v1
// BoardService — the board-arrangement / grants / projection-pin / history
// surface the canvas serves (doc 17 §10, D86/D87; doc 06 §2.1's dual-run
// model). It wires the BoardService conformance suite through the dual-run
// harness so the SAME suite runs against BOTH a minimal honest reference
// implementation AND the generated programmable fake
// (canvasv1fake.BoardServiceFake), failing the build on any divergence (D24/D14).
//
// BoardService is all-13-verbs-unary (CreateBoard/GetBoard/UpdateBoard/
// DeleteBoard/ListBoards, GrantBoardRole/RevokeBoardRole/ListBoardGrants,
// AddProjectionPin/UpdateProjectionPin/RemoveProjectionPin/ListProjectionPins,
// ListBoardHistory — no streams), so it slots into the existing dualrun
// emitter/runner with NO machinery change, exactly like the all-unary
// orchestrator-policy reference pattern this seam follows.
//
// What this package contains:
//
//   - suite.go: the single conformance suite for the seam — scenarios stated
//     purely in terms of the frozen canvas.v1 BoardService contract (doc 17
//     §10), exercising all thirteen unary verbs and recording contract-observable
//     fields into dualrun.Observation. The properties the board seam turns on
//     (doc 17 §3.1/§5/§7/§8/§9): (i) a board is an org-scoped arrangement surface
//     and CRUD round-trips its product metadata (name/description) under org RBAC
//     (D61, no parallel ACL); (ii) role grants ride org RBAC — VIEWER is
//     read-only, EDITOR rearranges tiles but NEVER writes into a projected
//     session (the structural invariant, D86), OWNER may grant/revoke; a re-grant
//     of the same principal updates the role in place (no parallel ACL); (iii)
//     projection pins are read-only projections (SESSION_TILE / FLEET_TREE_NODE /
//     PLAN_CARD — none a writer seam, doc 17 §3.1) that add / update-position /
//     remove / list; (iv) ListBoardHistory is a product feature, NOT the audit
//     chain (doc 17 §9); (v) validation refusals (missing org_id / board_id /
//     principal_id) are part of the contract surface a faithful fake must mirror.
//   - refimpl.go: a minimal honest in-memory reference BoardService — the "real
//     implementation" side of the dual-run. It keeps deterministic in-memory
//     board / grant / pin / history maps with synthetic deterministic IDs (so a
//     fake programmed at the same RefImpl observes byte-identically across two
//     independent processes — D50), and implements exactly the doc 17 §10
//     contract. This is the M0/M2 stand-in until the production paid/canvas/
//     BoardService server lands (D87 CONTRACTS-NOW, BUILD-AT-M2); when it does it
//     replaces refimpl here and the suite is unchanged — the suite is the
//     contract, not the implementation.
//   - dualrun_test.go: the per-commit gate — runs the suite real-vs-fake over an
//     in-process bufconn and fails on divergence, plus a negative test proving
//     the gate bites on a drifted fake (a GetBoard responder that mutates the
//     returned board name, a contract-observable divergence).
//
// Owner: Assurance (the seam's dual-run suite is owned by Canvas as the seam
// owner; stewarded here per doc 06 §2.1). Licensing: OSS (Apache-2.0, D25/D80;
// the board CONTRACT is public per D58 even though paid/canvas/ implements it —
// D80: paid services implement public protos). The structural invariant holds
// here too: NO BoardService message carries session input — class-1 interactions
// are structurally impossible, not policy-forbidden (doc 17 §7). Any proto change
// to this seam runs the full (c) guardrail matrix (D47); fixtures are synthetic
// only (D50).
package canvasboard
