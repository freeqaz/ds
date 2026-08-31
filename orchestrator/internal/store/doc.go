// Package store is the repository interface over the control plane's
// external Postgres — the ONLY persistence layer (D6: control-plane state
// in external Postgres only, never on hosts).
//
// Why an interface and not bare SQL everywhere: D33 allows managed
// RDS-class Postgres wherever we operate the control plane (hosted AND
// bring-compute — the customer brings compute, we hold the control plane,
// D19), while the on-prem tier swaps in customer-run Postgres. The
// repository layer is the seam that makes the D19 tier swap a deployment
// choice instead of a code change (doc 15 §2, §10).
//
// Tables it fronts (schema lands via ../../migrations/): sessions (the
// §5.6 record incl. index history), policy_log (D36 — the audit trail),
// env configs (D7/D56), plans, metering events (D57 — idempotent event
// stream at v0).
//
// Degraded-mode contract (doc 15 §3, frozen): Postgres down ⇒ running
// sessions continue and host agents operate autonomously on the last
// verified snapshot; new creates/asks/grants/suspend-acks stall. This
// package must surface unavailability so callers stall cleanly — never
// buffer writes that fake durability.
//
// Free (doc 15 §10): schema/migration tooling and repository-layer
// design — bounded by the D19 tier swap. Metering pipeline heaviness is
// per D19 tier; v0 = Postgres.
//
// Governing decisions: D6, D19, D33, D36, D57. Primary doc:
// docs/15-orchestrator-design.md §2.
package store
