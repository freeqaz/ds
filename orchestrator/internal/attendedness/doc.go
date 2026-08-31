// Package attendedness computes the D78 attendedness signal and pushes it
// host-ward. The split is deliberate: this package owns COMPUTING the
// signal and its transport; what "attended" MEANS for D77 ask routing is
// owned by Identity (doc 16) — semantics never live here (doc 15 §5.5).
//
// Frozen (doc 15 §5.5, §10):
//   - definition computed here: a human holds the one writer seat (D61)
//     AND has produced input within the last T minutes. Spectators,
//     readers, and canvas viewers NEVER count.
//   - T (≈10 min) is a POL-1 policy value, org-tunable — never code.
//   - M0/M1 interim: writer-attached-only, until the attach wrapper
//     exposes input-activity events.
//   - transport: session-lifecycle data over the host agent's lifecycle
//     channel (doc 15 §5.2) — the D72-EXEMPT class, freshness budget a
//     few seconds; the field must join the session-lifecycle contract
//     BEFORE Stage 2 (TLS-1's socket-hold and DNS-3 consume it at
//     per-connection-verdict time).
//   - detach-mid-hold: holds already in flight run to their 30–60 s
//     timeout; only NEW asks downgrade to immediate block+log; never
//     retroactively killed.
//
// Governing decisions: D78, D77, D72, D61. Primary docs:
// docs/15-orchestrator-design.md §5.5; semantics in
// docs/16-identity-and-credentials-design.md.
package attendedness
