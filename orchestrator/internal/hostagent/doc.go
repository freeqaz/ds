// Package hostagent implements the host-agent's UP-reporting half (doc 15
// §5.2): the streaming heartbeat the orchestrator reconciler consumes, and the
// RecoverSessions re-adoption a host-agent restart runs to pick its running
// sessions back up from persisted host-side handles.
//
// Two seams meet here, both frozen at M0:
//
//   - dreamserpent.hostagent.v1 (the heartbeat). The host agent opens ONE
//     long-lived client-streaming RPC and emits a Heartbeat per cadence
//     interval (strawman 5 s — a rig-tuned value, NEVER frozen, doc 15 §10);
//     3 missed beats => the host is presumed unreachable, its sessions marked
//     UNKNOWN and NEVER auto-destroyed (the reconciler's rule, internal/
//     reconciler/doc.go). The frame carries observed state, `applied_seq`,
//     capacity, per-session samples, the host-baseline version, the image-cache
//     digest, and boundary ServiceHealth.
//   - dreamserpent.hypervisor.v1 RecoverSessions (the re-adoption). On restart
//     the agent re-observes — it never replays an RPC chain (the D35 level-
//     triggered contract, internal/reconciler/doc.go): RecoverSessions
//     enumerates the sessions the host is still running from PERSISTED host-side
//     handles and reconstructs the ObservedSession list the steady-state
//     heartbeat then carries.
//
// FROZEN semantics this package must honor (contract, not convention):
//
//   - applied_seq = the MIN over the three host-side policy consumers
//     (ds-dnsgate / ds-tlsproxy / nft-writer), advancing ONLY post-sweep (D72;
//     doc 13 §1 rule 3). It is the single policy version namespace echoed
//     host-ward — never a second version namespace. AppliedSeq composes that
//     min from the per-consumer ServiceHealth.applied_seq inputs, so the
//     Heartbeat top-level value and the boundary list can never silently drift.
//   - ObservedSession is hypervisor.v1's shared observed-state element — the
//     SAME shape across RecoverSessions re-adoption and the steady-state
//     heartbeat, so the reconciler reads one type either way. The §3 state
//     vocabulary (incl. PARKED + D77 SUSPENDED(reason)) is attach.v1's
//     SessionStateName, imported, never re-declared.
//
// HOST-SIDE PERSISTENCE (the re-adoption substrate, doc 15 §5.6). The
// host_session_index is allocated from a persistent monotonic per-host counter
// that SURVIVES RESTART via persistence + RecoverSessions; the never-recycle
// window is the flow-log retention window (D66). That counter and the adopted-
// handle ledger are LOCAL HOST state — distinct from the control-plane Postgres
// store (D6: control-plane state never on hosts; internal/store fronts that).
// This package consumes them through the HandleStore seam (an interface, like
// the libvirt driver's pinned-later binding) — a test fake satisfies it
// identically; the real on-host impl is owner-landed.
//
// Free (rig-tuned, doc 15 §10): cadence, staleness, and re-adoption retry —
// bounded by the frozen applied_seq/ObservedSession semantics above and the
// reconciler's conflict rules. NOTHING in this package frozen-claims a value.
//
// Governing decisions: D35, D37, D66, D72, D77. Primary doc:
// docs/15-orchestrator-design.md §5.1, §5.2, §5.6.
package hostagent
