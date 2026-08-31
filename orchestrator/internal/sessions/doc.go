// Package sessions owns the session record and the session state machine —
// the frozen artifacts of docs/15-orchestrator-design.md §3 and §5.6.
//
// The session record is the authoritative, never-recycled index→UUID join
// key (D66/D44) that LOG-2 attribution, metering (D57), the M4 console
// hierarchy, and fleet routing all join through. Beyond the Stage-0-frozen
// SessionRef quartet (session_uuid, host_id, host_session_index, tap_name)
// it carries: env-config ref + resolved image ID (D7/D74), identity/CA/
// digest references (D22/D17/D73), policy posture + live grant list,
// attach/writer-seat/attendedness state (D18/D78), parent-session link,
// lifecycle timestamps (D57), and per-host index history (park/migration —
// flow-log joins are per-host-epoch). Records are retained, never deleted
// within the flow-log retention window (D66; 90-day strawman, tier-tunable).
//
// State machine (frozen with the M0 contract set — doc 15 §3):
// PENDING → CREATING → READY → ATTACHED ⇄ WORKING, with SNAPSHOTTING,
// SUSPENDED(reason: user|policy_breach|rebalance — D35, policy_breach
// narrowed to D77 genuine-threat classes), PARKED as first-class (D46,
// >15 min tier; ≈ free metering), and DESTROYING/DESTROYED carrying the
// doc 06 §3b teardown assertions. READY is structurally gated (D72/D73):
// applied_seq within budget AND session-scoped digest ack landed; the
// 30–60 s socket-hold is explicitly NOT a VM state (D77).
//
// Create choreography: the §4.1 canonical sequence with its frozen
// precedence constraints (two-key structural refusal D56 first; CA mint
// D82 before digest write D73 and fail-closed overlay injection D17;
// routable only after digest-ack + policy-freshness). Rollback = drive the
// §4.2 destroy path compensatingly; every verb idempotent on session UUID;
// burned indices are never recycled.
//
// Metering semantics (D57, frozen): per-second active; SUSPENDED/PARKED
// ≈ free; socket-hold counts active; viewers free; no bring-compute meter;
// guardrails never metered.
//
// Governing decisions: D35, D44, D46, D56, D57, D66, D72, D73, D77, D78,
// D79, D82. Primary doc: docs/15-orchestrator-design.md §3–§5.
package sessions
