// Package metering derives the D57 idempotent billing event stream — plus the
// D37 RSS/CPU/IO sample rollup — from the frozen §3 session-record state
// vocabulary (doc 15 §3, §5.6) over the existing migrations/0005 metering_events
// shape. It is constructible and PURE: every derivation is a function over a
// synthetic §3 transition (or a synthetic hostagent.v1 heartbeat sample) into a
// store.MeteringEvent, with NO live VM / host-agent / podman / KVM (D50). It is
// NOT wired into main.go and adds NO proto edit, NO Repository-interface method,
// and NO shared-store-file edit; a writer needing a persistence seam declares a
// narrow package-local interface (Sink) that *store.Memory / *store.Postgres
// already satisfy through the landed AppendMeteringEvent method.
//
// What D57 says (doc 15 §5.6 "Metering"): billing derives from session-record
// state transitions —
//
//   - active states accrue per second;
//   - SUSPENDED / PARKED ≈ free (no accrual);
//   - the 30–60 s socket-hold time counts ACTIVE (the VM keeps running in
//     WORKING — the hold is a boundary-owned non-state, §3 item 4, never a
//     record state this machine models, so it cannot make billing "free");
//   - viewers are free, unattended agents are usage-not-seats;
//   - NO meter at bring-compute (we hold the control plane, not the compute).
//
// The stream is idempotent on EventID (the migrations/0005 PRIMARY KEY): a
// transition event's EventID is derived deterministically from
// (session_uuid, entered-state, occurred_at) so RE-EMITTING the same logical
// transition produces the same EventID — appending it again is a no-op success
// at the store (the landed AppendMeteringEvent contract: identical body = no-op,
// differing body under the same key = ErrConflict). This package owns the
// derivation and the idempotency-key construction; the at-rest collapse lives in
// the store (D57: "Re-emitting the same event_id is a no-op").
//
// The D37 series (doc 15 §5.2/§5.6): the per-session RSS/CPU/IO samples
// piggyback the hostagent.v1 heartbeat into a SHORT-RETENTION rollup feeding the
// (d) rig — it is NOT the billing meter (billing derives from state
// transitions). This package models that sample class over the SAME idempotent
// stream as kind "sample" with the opaque sample carried in the event payload,
// so the (d)-rig rollup and the billing transitions share one idempotent
// substrate without the sample ever entering an accrual.
//
// Frozen vs free fence: the §3 state vocabulary and the per-state accrual
// classification (active / free) are bounded by the ratifying D-rows
// (D35/D46/D72/D73/D77); editing the classification of a frozen state reopens
// the freeze, not just this file. The event-stream heaviness is per-D19 tier
// (v0 = Postgres). This package never re-declares a §3 state name — it consumes
// store.SessionState.
//
// Governing decisions: D57 (metering as an idempotent event stream from state
// transitions), D37 (the RSS/CPU/IO short-retention rollup), D50 (synthetic
// fixtures only), D19 (tier-scoped stream heaviness). Primary sources:
// docs/15-orchestrator-design.md §5.6 (Metering), §5.2 (SessionSample), §11
// ((d)-rig sample feed); migrations/0005_metering_events.sql (the at-rest shape).
package metering
