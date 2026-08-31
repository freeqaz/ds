// Package policylog owns the policy_log table and both ends of the
// push-to-enforced clock: the log write and the heartbeat applied_seq
// (doc 15 §1, §11).
//
// Frozen (doc 15 §10):
//   - the append-only policy_log IS the audit trail (D36) — actor recorded
//     on every row; rows persist as audit after session death
//   - the policy_log bigserial seq is THE single policy version namespace
//     end to end; pack versions (D74) and digest-set versions (D73) are
//     content identifiers, never second namespaces
//   - WatchPolicies(from_seq): replayable, idempotent, deny-wins; EXACTLY
//     ONE subscriber per host = the host agent (D72)
//   - snapshot identity = (seq, content_hash, composed policy); the
//     composed document — system-baseline → org → repo/session with
//     deny-overrides — is what the snapshot carries, never a single layer
//   - applied_seq semantics (D72): min over the three host-side consumers,
//     advancing only post-sweep; feeds D36's unschedulable rule
//
// Ask-grant write path (doc 15 §4.3): approvals append session-scoped
// TTL'd allow grants to policy_log via ApproveAsk; ask-grants are policy
// artifacts under the policy_log seq (the D72/D73 session-lifecycle
// exemption covers digests and D22 grants, NOT ask-grants); approval→
// enforced target ≤5 s, comfortably inside the 30–60 s socket hold.
//
// Pre-named substrate swap: JetStream behind the same WatchPolicies
// contract, triggered only by a missed budget at the ~500-host checkpoint
// or policy-event-rate spikes (D36).
//
// Open with doc 13 (must close before the snapshot format freezes):
// per-session composition scoping (doc 15 OQ6) and the canonical
// content_hash serialization (doc 15 OQ3 / doc 13 OQ2) — the Go↔Rust
// contract test for the latter lives in internal/nftbridge + ds-contracts.
//
// Governing decisions: D36, D72, D73, D74. Primary doc:
// docs/15-orchestrator-design.md §5.3, §4.3.
package policylog
