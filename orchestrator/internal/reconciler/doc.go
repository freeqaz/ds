// Package reconciler implements level-triggered reconciliation (D35):
// desired state in Postgres, observed state from host-agent heartbeats,
// a reconciler that converges the two. Crashes recover by re-observing
// (RecoverSessions re-adoption), never by replaying RPC chains.
//
// Frozen conflict rules (doc 15 §3 — contract, not convention):
//   - observed VM with no record → QUARANTINE (suspend), never
//     auto-destroy, plus alarm
//   - record with no VM in a non-terminal state → re-drive, or fail to
//     DESTROYED with an audit event
//   - state regression → re-converge toward desired
//   - host missing 3 heartbeats → sessions marked UNKNOWN, never
//     auto-destroyed
//
// Crash matrix (doc 15 §3): host-agent crash → RecoverSessions re-adopts;
// replica crash → stateless, nothing happens; Postgres down → running
// sessions continue, host agents operate autonomously on the last
// verified snapshot, new creates/asks/grants/suspend-acks stall
// (documented degraded mode); host crash → sessions LOST at v0 (explicit
// non-claim; durability-stream restore is the named M3 path, doc 15 OQ5).
//
// DESTROYING is reconciler-driven (desired = DESTROYED) and carries the
// doc 06 §3b clean-teardown assertions plus the NFT-6 N-loop
// byte-identical-ruleset done-when (doc 15 §3 item 5, §4.2).
//
// Free (rig-tuned, doc 15 §10): reconcile cadence and full-resync
// interval — bounded by the conflict rules above.
//
// Implementation shape (this package): Reconciler (reconciler.go) is a
// CONSTRUCTIBLE component — New(store, driver, redriver, alarm, now, cfg) —
// with every collaborator an injected interface this package OWNS
// (RecordStore, Driver, Redriver, Alarmer), so the whole convergence is
// unit-testable against synthetic heartbeat/record fixtures with zero live
// VM/host-agent/podman (D50). It is NOT wired into main.go (a separate
// wiring task owns that). Two triggers drive it: Observe (event-driven, one
// heartbeat) and Resync (periodic full resync over every host), both flowing
// through the SAME conflict-rule diff (conflict.go: reconcileHost). The
// crash-matrix cells live in crashmatrix.go (markMissedBeats →
// UNKNOWN-never-destroyed liveness annotation, AdoptRecovered → host-agent
// re-adoption converged as a fresh observation, degraded() → Postgres-down
// stall). The §3 observed↔record vocabulary join and the §3-derived
// "host-resident state" + "state regression" predicates live in states.go,
// composed from internal/store's frozen state set and internal/sessions's
// frozen transition table — never re-declared here.
//
// Governing decisions: D35, D72, D77. Primary doc: docs/15-orchestrator-design.md §3.
package reconciler
