// Package scheduler implements placement over virtual-metal hosts
// (doc 15 §7). Scheduler v0 is bin-packing on resource floors (D37):
// sum of floors ≤ host capacity, bursts share headroom, no preemption;
// floors come from the env spec with org/global defaults and
// policy-clamped maxima, expressed as cgroup v2 knobs.
//
// Frozen filter order (doc 15 §7):
//  1. policy staleness — D72 unschedulable rule: never place on a host
//     whose heartbeat applied_seq is outside the staleness budget
//  2. host-baseline version compatibility (doc 14 §11 artifact)
//  3. capacity — floors fit, from heartbeat HostCapacity (D37)
//  4. image-cache locality preference (the seconds-to-start lever at M2)
//  5. capacity ceilings from the D66 measured-uplink input + the (d)-rig
//     density knee (~75–100 streams/host strawman; thresholds metal-only
//     per D34)
//
// PARKED re-placement (D46) reuses this scheduler: same session UUID, NEW
// host index/tap on the target (the session record keeps index history).
// Migration constraints are stated in doc 15 §7 before SessionRef
// calcifies: index/tap are host-scoped, boundary derived state is rebuilt
// by re-admission on the target, never transferred; target applied_seq ≥
// source.
//
// NOT here: multi-host rebalancing, migration scheduling, and fleet
// policy — those are the paid fleet control plane, a distinct M3 service
// in paid/fleet/ speaking the same public protos (D80). KSM/tenancy
// isolation is a host-pool configuration, not a scheduler feature (D19).
//
// Governing decisions: D37, D72, D46, D66, D34, D80. Primary doc:
// docs/15-orchestrator-design.md §7.
package scheduler
