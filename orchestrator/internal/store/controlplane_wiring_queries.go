package store

// controlplane_wiring_queries.go is the set of ADDITIVE store queries the control-plane
// capstone wiring (internal/controlplane) needs and the frozen shared store files do
// NOT already expose. Two narrow point reads, both composed from existing surfaces with
// NO Repository method and NO shared-store edit:
//
//   - PolicyHead: the policy_log HEAD seq — the orchestrator's CURRENT swept policy
//     version (D72), which the scheduler's PolicySeqSource measures each host's heartbeat
//     applied_seq against at placement (doc 15 §7 filter 1, §4.1 step 3).
//   - HostAppliedSeq: ONE host's CURRENT heartbeat applied_seq, resolved O(1) by host_id
//     — the live policy version the host has applied right now, which the §4.1 step-9 D72
//     routable re-check re-validates the placed host against to close the residual
//     placement→step-9 freshness window the recorded-only re-check misses.
//
// WHY A NEW FILE (the disjointness fence). The shared store files (store.go,
// repository.go, records.go, session.go, memory.go, postgres.go, postgres_sql.go,
// inventory.go, the orch17/18 *_queries.go, …) are FROZEN. This file adds NO method
// to the Repository interface and edits NO shared file — it declares a NARROW seam
// (PolicyHeadSource) composed from the EXISTING exported ListPolicy method, satisfied
// identically by *Memory and *Postgres because ListPolicy already exists on both. The
// scheduler-side PolicySeqSource adapter reads the head through this seam, keeping the
// store a pure leaf and adding no new persisted shape, no new column, no shared-store
// edit — exactly the discipline scheduler_candidates_queries.go and
// sessioncreate_queries.go use.
//
// WHY THE HEAD IS A QUERY, NOT A STORED SCALAR. The single policy version namespace
// IS the policy_log bigserial seq (D36/D72): the head is whatever the latest appended
// row's Seq is. There is no separate "current seq" column to keep coherent — reading
// the last row's Seq IS the current swept version. PolicyHead computes it from the
// existing append-only log, so it can never drift from the rows the host agents
// replay over WatchPolicies.

import "context"

// PolicyHeadSource is the NARROW read slice PolicyHead composes: just ListPolicy. It
// is declared HERE (not on Repository) so the wiring adds no interface method; both
// *Memory and *Postgres satisfy it because ListPolicy already exists on both. It is
// disjoint from scheduler_candidates_queries.go's candidateSessionLister and
// sessioncreate_queries.go's preBindingCreator — three narrow slices, no overlap,
// none a frozen-store edit.
type PolicyHeadSource interface {
	ListPolicy(ctx context.Context, fromSeq int64, limit int) ([]PolicyLogRow, error)
}

// PolicyHead returns the policy_log HEAD seq — the orchestrator's current swept
// policy version (D72), the moving reference the scheduler's staleness filter
// measures each host's heartbeat applied_seq against. It is the highest Seq in the
// append-only log, or 0 when the log is empty (no policy applied yet — the
// "must-be-current-but-current-is-zero" baseline the staleness filter treats
// conservatively). It reads from fromSeq 0 with no cap; the policy_log write volume
// is trivial single-table Postgres at the ~500-host checkpoint (doc 15 §5.3), so the
// whole-log read is one round-trip in practice, and ListPolicy returns ascending Seq
// so the last row carries the head.
func PolicyHead(ctx context.Context, src PolicyHeadSource) (uint64, error) {
	rows, err := src.ListPolicy(ctx, 0, 0)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	// ListPolicy returns ascending-seq order (the WatchPolicies replay shape); the
	// last row carries the head. A negative seq is impossible (bigserial is positive),
	// but guard the conversion: a non-positive head means "no policy applied yet".
	head := rows[len(rows)-1].Seq
	if head <= 0 {
		return 0, nil
	}
	return uint64(head), nil
}

// Compile-time proof that the real control-plane stores satisfy the narrow
// PolicyHeadSource seam via their existing ListPolicy method — the wiring adds NO
// method to the Repository interface, and the in-memory and Postgres impls are
// interchangeable behind PolicyHeadSource exactly as they are behind Repository.
var (
	_ PolicyHeadSource = (*Memory)(nil)
	_ PolicyHeadSource = (*Postgres)(nil)
)

// HostAppliedSeqSource is the NARROW host-keyed point-read slice HostAppliedSeq
// composes: ONE host's most-recent heartbeat snapshot, resolved by host_id in O(1)
// (a map hit on the live latest-per-host feed, never a fleet scan). It is the
// host-keyed dual of the per-session CandidatesForSession assembler: where the
// assembler narrows the whole fleet's snapshots to a session's candidate set,
// HostAppliedSeq probes a SINGLE already-placed host's current freshness for the §4.1
// step-9 D72 live re-check. It is declared HERE (not on Repository) so the wiring adds
// no interface method and edits no shared store file — exactly the PolicyHeadSource /
// candidateSessionLister narrow-seam discipline. Heartbeats are NOT a §5.6 store record
// (the record has no heartbeat column); they are the host-agent ingest plane's
// short-retention live feed, so this seam fronts that feed (the in-process
// HeartbeatStore in the single-binary control plane), satisfied by an adapter at the
// wiring tree, never by *Memory/*Postgres — there is no heartbeat table to point-read.
type HostAppliedSeqSource interface {
	// SnapshotForHost returns the host's most-recent heartbeat snapshot and true, or a
	// zero snapshot and false when the host has no current report in the live feed. The
	// lookup is by host_id, O(1) on the latest-per-host feed (a vanished host reports
	// false, never a stale snapshot).
	SnapshotForHost(ctx context.Context, hostID string) (HeartbeatSnapshot, bool, error)
}

// HostAppliedSeq returns ONE host's CURRENT heartbeat applied_seq — the live policy
// version the host has applied right now (D72), the value the §4.1 step-9 routable gate
// re-validates against to close the residual placement→step-9 window the recorded-only
// re-check misses. It is the host-keyed point-read dual of PolicyHead: PolicyHead reads
// the orchestrator's swept policy HEAD, HostAppliedSeq reads ONE host's applied_seq, and
// the step-9 gate measures the host against the head. It resolves the host's snapshot in
// O(1) through the narrow HostAppliedSeqSource (a map hit on the live latest-per-host
// feed), returning:
//
//   - (seq, true, nil)  — the host has a current heartbeat; seq is its applied_seq.
//   - (0, false, nil)   — the host has NO current report (vanished from the live feed);
//     the caller (the HostFreshness adapter) surfaces this as ErrFreshnessUnknown so the
//     coordinator DEGRADES to the recorded re-check rather than hard-failing a create the
//     recorded signal still vouches for (the pre-probe, backwards-compatible behavior).
//
// A present snapshot with a nil Heartbeat reports applied_seq 0 (the "no policy applied
// yet" value the staleness filter treats conservatively) and true — the host IS reporting,
// it just has not applied a policy version yet, which is distinct from the host being
// absent (false). The proto applied_seq is uint64; this returns it verbatim, the
// scheduler-side adapter doing the loss-free uint64→int64 narrowing the sessions contract
// uses (placement seqs are small monotone policy versions far below the int64 ceiling).
func HostAppliedSeq(ctx context.Context, src HostAppliedSeqSource, hostID string) (uint64, bool, error) {
	snap, ok, err := src.SnapshotForHost(ctx, hostID)
	if err != nil {
		return 0, false, err
	}
	if !ok {
		return 0, false, nil
	}
	return snap.Heartbeat.GetAppliedSeq(), true, nil
}
