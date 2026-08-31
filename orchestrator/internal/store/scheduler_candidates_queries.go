package store

// scheduler_candidates_queries.go is the store-side CANDIDATE ASSEMBLER for the
// doc 15 §7 placement path: it turns the latest per-host hostagent.v1 Heartbeat
// snapshots into the host-candidate slice the scheduler's Place entrypoint consumes,
// SCOPED to one session's tenancy host-pool (D19 single-tenant isolation is a
// host-pool CONFIGURATION, not a scheduler feature — so the scoping is the store's
// concern, never a filter). It is the orch18 production-Placer pair to the orch17
// scheduler: the scheduler stays a pure function of (candidates, request); THIS file
// is the side that narrows the live fleet down to the candidates that are legal
// placement targets for a given session.
//
// WHY A NEUTRAL CANDIDATE SHAPE (HostCandidate), not scheduler.Candidate. The
// scheduler package satisfies the SESSIONS-side Placer interface from its adapter, so
// scheduler imports sessions, and sessions imports store — a store→scheduler import
// here would close the cycle (store→scheduler→sessions→store). The store therefore
// produces a NEUTRAL HostCandidate (host id + the frozen, read-only hostagent.v1
// heartbeat — proto-only, no internal import) and the scheduler-side adapter converts
// it to scheduler.Candidate at the seam (CandidateSource). The data crosses the seam
// as the frozen proto value, the same discipline the create choreography uses; no
// import cycle, and the store stays a pure leaf over the protos.
//
// FROZEN-STORE-SAFE, like sessioncreate_queries.go. The control plane does NOT
// persist heartbeats (they are the host-agent ingest plane's live, short-retention
// feed, not a §5.6 record column), so this assembler RECEIVES the latest per-host
// snapshots as DATA (HeartbeatSnapshot) — it never reads them from a table that the
// frozen store does not have. What the store DOES own is the tenancy/host-pool
// scope, and the one persisted fact this assembler needs is the D19 isolation
// guard: a host that already carries a LIVE session from a DIFFERENT tenancy is not
// a legal target for this tenancy (single-tenant isolation). That fact is read
// through the NARROW candidateSessionLister interface below — composed from the
// EXISTING exported ListSessions, defined HERE (not on Repository), satisfied
// identically by *Memory and *Postgres because ListSessions already exists on both.
// No new persisted shape, no new Repository method, no shared-store-file edit; this
// file is disjoint from sessioncreate_queries.go (which composes CreateSession).

import (
	"context"
	"sort"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// HostCandidate is ONE legal placement target the store-side assembler produced: a
// host id plus its latest read-only hostagent.v1 heartbeat. It is the NEUTRAL,
// proto-only shape that crosses the store→scheduler seam (the scheduler-side
// CandidateSource maps it to scheduler.Candidate); declaring it here keeps the store
// a pure leaf over the frozen protos with no internal import, so no import cycle.
type HostCandidate struct {
	// HostID is the candidate host (the scheduler's placement target + tiebreak key).
	HostID string
	// Heartbeat is the host's latest report (read-only; frozen hostagent.v1). A nil
	// heartbeat is carried through — the scheduler's filters treat a nil/zero capacity
	// conservatively (a host that reported nothing usable is rejected by the first
	// filter its zero value fails).
	Heartbeat *hostagentv1.Heartbeat
}

// HeartbeatSnapshot is ONE host's most-recent heartbeat as the ingest plane handed
// it to the control plane: the host id, the report timestamp the dedup keys on, and
// the read-only frozen hostagent.v1 Heartbeat the scheduler reads. The assembler is
// handed a slice of these (possibly with stale duplicates per host — a host re-emits
// on every interval); CandidatesForSession keeps only the LATEST per host (highest
// ReportedAtUnixNanos) so a placement always sees current capacity/applied_seq, the
// D72 staleness filter's premise.
type HeartbeatSnapshot struct {
	// HostID identifies the reporting host. Duplicate HostIDs in the input are
	// collapsed to the latest by ReportedAtUnixNanos.
	HostID string
	// ReportedAtUnixNanos is the ingest timestamp used ONLY to pick the latest
	// snapshot per host. It is monotone per host within the feed; the assembler does
	// not interpret it beyond max-per-host (freshness vs. policy seq is the D72
	// filter's job, on AppliedSeq, not this timestamp).
	ReportedAtUnixNanos int64
	// Heartbeat is the host's most-recent report (read-only; the frozen hostagent.v1
	// type). A nil Heartbeat is carried through to the Candidate; the scheduler's
	// filters treat a nil/zero capacity conservatively (a host that reported nothing
	// usable is rejected by the first filter its zero value fails).
	Heartbeat *hostagentv1.Heartbeat
}

// HostPool is the D19 single-tenant host-pool scope for one placement: the set of
// host ids that belong to the session's tenancy pool. Placement is confined to this
// set (single-tenant isolation is a host-pool config, not a scheduler filter). An
// EMPTY pool means "no pool restriction recorded" — every reporting host is in scope
// (the open/shared-pool deployment posture); a NON-empty pool restricts candidates
// to exactly its members. Membership is operator/inventory config, carried as DATA;
// this package does not author it.
type HostPool struct {
	// HostIDs are the hosts in the tenancy pool. When non-empty, only these hosts
	// are candidates; when empty, the pool is unrestricted.
	HostIDs []string
}

// contains reports whether the pool admits hostID. An empty pool admits every host
// (unrestricted posture); a non-empty pool admits only its declared members.
func (p HostPool) contains(hostID string) bool {
	if len(p.HostIDs) == 0 {
		return true
	}
	for _, h := range p.HostIDs {
		if h == hostID {
			return true
		}
	}
	return false
}

// candidateSessionLister is the NARROW read slice CandidatesForSession composes for
// the D19 isolation guard: just ListSessions. It is declared HERE (not on
// Repository) so the assembler adds no interface method; both *Memory and *Postgres
// satisfy it because ListSessions already exists on both. It is deliberately
// disjoint from sessioncreate_queries.go's preBindingCreator (which composes
// CreateSession): two narrow read/write slices, no overlap, neither a frozen-store
// edit.
type candidateSessionLister interface {
	ListSessions(ctx context.Context, f SessionFilter) ([]Session, error)
}

// CandidateScope is the per-placement tenancy context the assembler scopes to: the
// session being placed and its tenancy host-pool. The D19 isolation guard reads the
// LIVE sessions already resident on each candidate host (through the narrow lister)
// and drops a host that carries a session NOT belonging to this tenancy — single-
// tenant isolation, enforced at candidate assembly, never at a scheduler filter.
type CandidateScope struct {
	// Pool is the tenancy host-pool (D19). Candidates are confined to it (empty =
	// unrestricted).
	Pool HostPool
	// TenancyHostIDs is the set of hosts KNOWN to belong to this tenancy — the same
	// membership the Pool declares, used by the isolation guard to recognise a
	// foreign-tenant host. When Pool is non-empty its members ARE the tenancy hosts;
	// callers that run an unrestricted Pool but still want the isolation guard supply
	// the tenancy hosts here. Empty disables the cross-tenant guard (the guard needs
	// a notion of "this tenancy" to detect "another tenancy").
	TenancyHostIDs []string
}

// NewCandidateScope assembles a CandidateScope from a tenancy host-pool config (D19):
// the pool members candidates are confined to, and the tenancy host set the isolation
// guard recognises. It is the store-side constructor the production config-backed
// TenancyScopeSource (scheduler.ConfigTenancyScope) drives, so the CandidateScope shape
// is assembled by its OWNER (this file declares Pool/HostPool/TenancyHostIDs) rather
// than hand-built across the seam. Both slices are DEFENSIVELY COPIED into the returned
// scope, so a later caller-side mutation of poolHostIDs/tenancyHostIDs cannot mutate the
// scope (the source yields the same value per placement and must stay immutable).
//
// Empty poolHostIDs is the open/shared-pool posture (unrestricted — every reporting host
// is a candidate). tenancyHostIDs defaults via CandidateScope.tenancyHosts to the pool
// members when left empty (a restricted pool's members ARE the tenancy by construction);
// pass it explicitly to run an UNRESTRICTED pool while still arming the D19 guard. An
// empty pool AND empty tenancy disables the cross-tenant guard (no "this tenancy" to
// compare against) — the assembler then returns the pure latest-per-host, pool-open set.
func NewCandidateScope(poolHostIDs, tenancyHostIDs []string) CandidateScope {
	return CandidateScope{
		Pool:           HostPool{HostIDs: cloneHostIDs(poolHostIDs)},
		TenancyHostIDs: cloneHostIDs(tenancyHostIDs),
	}
}

// cloneHostIDs returns a defensive copy of in (nil for an empty/nil input), so a
// CandidateScope NewCandidateScope builds cannot be mutated through a slice the caller
// retained — the scope a per-placement source yields must be a stable, immutable value.
func cloneHostIDs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// tenancyHosts returns the scope's tenancy host set as a lookup, preferring the
// explicit TenancyHostIDs and falling back to the Pool members (a restricted pool's
// members ARE the tenancy by construction).
func (s CandidateScope) tenancyHosts() map[string]struct{} {
	src := s.TenancyHostIDs
	if len(src) == 0 {
		src = s.Pool.HostIDs
	}
	out := make(map[string]struct{}, len(src))
	for _, h := range src {
		out[h] = struct{}{}
	}
	return out
}

// CandidatesForSession assembles the candidate set for one placement from the latest
// per-host heartbeat snapshots, scoped to the session's tenancy host-pool (D19). It
// (1) collapses the snapshots to the LATEST per host, (2) confines them to the pool,
// (3) applies the D19 single-tenant isolation guard — dropping any host that
// currently carries a LIVE session belonging to a DIFFERENT tenancy — and (4) returns
// a deterministically ordered []HostCandidate (sorted by HostID) the scheduler-side
// adapter maps to scheduler.Candidate for Place. Ordering is irrelevant to Place (it
// sorts internally for its tiebreak); sorting here only makes the assembler's own
// output reproducible.
//
// The lister is the narrow candidateSessionLister (ListSessions); *Memory and
// *Postgres both satisfy it. When scope.tenancyHosts() is empty the cross-tenant
// guard is disabled (there is no "this tenancy" to compare against) and the result
// is purely the latest-per-host, pool-confined set. A nil lister also disables the
// guard (a caller with no occupancy view still gets a correctly-scoped, latest set).
func CandidatesForSession(
	ctx context.Context,
	lister candidateSessionLister,
	snapshots []HeartbeatSnapshot,
	scope CandidateScope,
) ([]HostCandidate, error) {
	latest := latestPerHost(snapshots)

	tenancy := scope.tenancyHosts()
	guardActive := lister != nil && len(tenancy) > 0

	out := make([]HostCandidate, 0, len(latest))
	for _, snap := range latest {
		if !scope.Pool.contains(snap.HostID) {
			continue
		}
		if guardActive {
			foreign, err := hostHasForeignTenantSession(ctx, lister, snap.HostID, tenancy)
			if err != nil {
				return nil, err
			}
			if foreign {
				continue // D19: a host carrying another tenancy's live session is off-limits
			}
		}
		out = append(out, HostCandidate{
			HostID:    snap.HostID,
			Heartbeat: snap.Heartbeat,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out, nil
}

// latestPerHost collapses possibly-duplicated snapshots to the single most-recent
// per host (highest ReportedAtUnixNanos), returned host-id-sorted for determinism.
// A host with several snapshots keeps only its newest, so placement always sees the
// host's current capacity/applied_seq — the freshness the D72 staleness filter
// assumes. Snapshots with an empty HostID are dropped (a malformed feed entry can
// never be a placement target).
func latestPerHost(snapshots []HeartbeatSnapshot) []HeartbeatSnapshot {
	best := make(map[string]HeartbeatSnapshot, len(snapshots))
	for _, s := range snapshots {
		if s.HostID == "" {
			continue
		}
		cur, ok := best[s.HostID]
		if !ok || s.ReportedAtUnixNanos >= cur.ReportedAtUnixNanos {
			best[s.HostID] = s
		}
	}
	out := make([]HeartbeatSnapshot, 0, len(best))
	for _, s := range best {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out
}

// hostHasForeignTenantSession reports whether hostID currently carries a LIVE
// (non-terminal) session that does NOT belong to the tenancy host set — the D19
// single-tenant isolation guard. It lists the host's sessions (the narrow lister)
// and returns true the moment it finds a live session whose record-bound host is
// outside the tenancy. Destroyed sessions are excluded (IncludeDestroyed left false):
// a torn-down session no longer occupies the host for isolation purposes.
//
// The tenancy is identified by host membership (the D19 pool IS the tenancy boundary
// — single-tenant isolation is a host-pool config): a session resident on a host that
// is NOT a tenancy host is, by construction, another tenancy's. This keeps the guard
// free of any new persisted tenancy column (the frozen store has none) while still
// enforcing the isolation invariant from the data the store already records.
func hostHasForeignTenantSession(
	ctx context.Context,
	lister candidateSessionLister,
	hostID string,
	tenancy map[string]struct{},
) (bool, error) {
	// A candidate host that IS a tenancy host can never host a foreign session by
	// this membership test — short-circuit without a list call.
	if _, ok := tenancy[hostID]; ok {
		return false, nil
	}
	// hostID is OUTSIDE the tenancy. If it carries ANY live (non-terminal) session,
	// that session belongs to whoever's tenancy this host serves — not ours — so the
	// host is off-limits under D19 single-tenant isolation. A torn-down (DESTROYED)
	// session no longer occupies the host and does not block it; a host outside the
	// tenancy with no live session is genuinely free and stays a candidate (the
	// open/shared-pool growth posture).
	sessions, err := lister.ListSessions(ctx, SessionFilter{HostID: hostID})
	if err != nil {
		return false, err
	}
	for _, s := range sessions {
		if !s.State.IsTerminal() {
			return true, nil
		}
	}
	return false, nil
}
