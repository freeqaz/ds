package store

import (
	"context"
	"testing"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// snap builds a HeartbeatSnapshot fixture for a host with a given report time and
// applied_seq (D50 synthetic — no live heartbeat ever authored).
func snap(hostID string, reportedAt int64, appliedSeq uint64) HeartbeatSnapshot {
	return HeartbeatSnapshot{
		HostID:              hostID,
		ReportedAtUnixNanos: reportedAt,
		Heartbeat: &hostagentv1.Heartbeat{
			HostId:     hostID,
			AppliedSeq: appliedSeq,
			Capacity:   &hostagentv1.HostCapacity{AllocatableVcpu: 64, AllocatableMemoryBytes: 1 << 40, AllocatableIoBps: 1 << 30, RunningSessions: 1},
		},
	}
}

// hostIDs flattens an assembled candidate slice to its host ids in order.
func hostIDs(cs []HostCandidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.HostID
	}
	return out
}

// TestCandidatesForSession_LatestPerHostWins proves the assembler collapses multiple
// snapshots per host to the SINGLE most-recent one (highest ReportedAtUnixNanos), so
// placement always sees current capacity/applied_seq — the freshness the D72 filter
// assumes. It also drops malformed (empty-host) feed entries.
func TestCandidatesForSession_LatestPerHostWins(t *testing.T) {
	ctx := context.Background()

	snaps := []HeartbeatSnapshot{
		snap("host-a", 100, 5),
		snap("host-a", 300, 9), // newest for host-a — its applied_seq must win
		snap("host-a", 200, 7),
		snap("host-b", 50, 4),
		{HostID: "", ReportedAtUnixNanos: 999}, // malformed: dropped
	}

	got, err := CandidatesForSession(ctx, nil, snaps, CandidateScope{})
	if err != nil {
		t.Fatalf("CandidatesForSession: %v", err)
	}
	if want := []string{"host-a", "host-b"}; !equalStrings(hostIDs(got), want) {
		t.Fatalf("candidate hosts = %v, want %v", hostIDs(got), want)
	}
	// host-a must reflect its NEWEST snapshot (applied_seq 9), not an older one.
	for _, c := range got {
		if c.HostID == "host-a" && c.Heartbeat.GetAppliedSeq() != 9 {
			t.Errorf("host-a applied_seq = %d, want 9 (latest snapshot)", c.Heartbeat.GetAppliedSeq())
		}
	}
}

// TestCandidatesForSession_PoolConfinement proves a NON-empty host-pool restricts
// candidates to exactly its members (D19 single-tenant isolation as a host-pool
// config), and an EMPTY pool is unrestricted.
func TestCandidatesForSession_PoolConfinement(t *testing.T) {
	ctx := context.Background()
	snaps := []HeartbeatSnapshot{snap("host-a", 1, 5), snap("host-b", 1, 5), snap("host-c", 1, 5)}

	// Restricted pool: only host-a and host-c are candidates.
	got, err := CandidatesForSession(ctx, nil, snaps, CandidateScope{Pool: HostPool{HostIDs: []string{"host-a", "host-c"}}})
	if err != nil {
		t.Fatalf("CandidatesForSession (restricted): %v", err)
	}
	if want := []string{"host-a", "host-c"}; !equalStrings(hostIDs(got), want) {
		t.Fatalf("restricted-pool candidates = %v, want %v", hostIDs(got), want)
	}

	// Empty pool: unrestricted — every reporting host is in scope.
	got, err = CandidatesForSession(ctx, nil, snaps, CandidateScope{})
	if err != nil {
		t.Fatalf("CandidatesForSession (open): %v", err)
	}
	if want := []string{"host-a", "host-b", "host-c"}; !equalStrings(hostIDs(got), want) {
		t.Fatalf("open-pool candidates = %v, want %v", hostIDs(got), want)
	}
}

// TestCandidatesForSession_D19IsolationGuard proves the assembler drops a candidate
// host OUTSIDE the tenancy that carries a LIVE session (it belongs to another
// tenancy — D19 single-tenant isolation), keeps a tenancy host even when occupied,
// and keeps a free non-tenancy host. The guard reads the narrow ListSessions slice
// that *Memory satisfies — no new Repository method, no frozen-store edit.
func TestCandidatesForSession_D19IsolationGuard(t *testing.T) {
	ctx := context.Background()
	repo := NewMemory()

	// host-a is a tenancy host with a live session (occupied but OURS — kept).
	mustCreate(t, repo, Session{Ref: SessionRef{SessionUUID: "ours", HostID: "host-a", HostSessionIndex: 1}, State: SessionReady})
	// host-foreign is OUTSIDE the tenancy and carries a live session (another
	// tenancy's — dropped under D19).
	mustCreate(t, repo, Session{Ref: SessionRef{SessionUUID: "theirs", HostID: "host-foreign", HostSessionIndex: 1}, State: SessionWorking})
	// host-foreign-dead is OUTSIDE the tenancy but its only session is DESTROYED
	// (torn down — no longer occupies the host; the host is free again — kept).
	mustCreate(t, repo, Session{Ref: SessionRef{SessionUUID: "gone", HostID: "host-foreign-dead", HostSessionIndex: 1}, State: SessionDestroyed})

	snaps := []HeartbeatSnapshot{
		snap("host-a", 1, 5),
		snap("host-foreign", 1, 5),
		snap("host-foreign-dead", 1, 5),
		snap("host-free", 1, 5), // outside tenancy, no sessions — free, kept
	}
	scope := CandidateScope{TenancyHostIDs: []string{"host-a"}}

	got, err := CandidatesForSession(ctx, repo, snaps, scope)
	if err != nil {
		t.Fatalf("CandidatesForSession: %v", err)
	}
	// host-foreign is dropped (foreign live session); the rest survive.
	if want := []string{"host-a", "host-foreign-dead", "host-free"}; !equalStrings(hostIDs(got), want) {
		t.Fatalf("D19-guarded candidates = %v, want %v", hostIDs(got), want)
	}
}

// TestCandidatesForSession_NilListerDisablesGuard proves a nil lister (no occupancy
// view) disables the cross-tenant guard while still returning the correctly-scoped,
// latest-per-host set — so a caller without a store handle still gets valid candidates.
func TestCandidatesForSession_NilListerDisablesGuard(t *testing.T) {
	ctx := context.Background()
	snaps := []HeartbeatSnapshot{snap("host-a", 1, 5), snap("host-foreign", 1, 5)}

	got, err := CandidatesForSession(ctx, nil, snaps, CandidateScope{TenancyHostIDs: []string{"host-a"}})
	if err != nil {
		t.Fatalf("CandidatesForSession: %v", err)
	}
	if want := []string{"host-a", "host-foreign"}; !equalStrings(hostIDs(got), want) {
		t.Fatalf("nil-lister candidates = %v, want %v (guard disabled)", hostIDs(got), want)
	}
}

// TestCandidateSessionLister_SatisfiedByConcreteStores pins that the NARROW
// candidateSessionLister (ListSessions only) is satisfied by *Memory and *Postgres —
// the same data-across-the-seam discipline sessioncreate_queries.go uses, with no new
// Repository method and no frozen-store edit.
func TestCandidateSessionLister_SatisfiedByConcreteStores(t *testing.T) {
	var _ candidateSessionLister = (*Memory)(nil)
	var _ candidateSessionLister = (*Postgres)(nil)
}

// TestNewCandidateScope_AssemblesAndDefensivelyCopies proves the store-side scope
// constructor (the home of the CandidateScope shape, driven by the production
// config-backed scheduler.ConfigTenancyScope) assembles a scope from a host-pool config
// and DEFENSIVELY COPIES both slices, so a later caller-side mutation cannot mutate the
// scope a per-placement source must yield as a stable value.
func TestNewCandidateScope_AssemblesAndDefensivelyCopies(t *testing.T) {
	pool := []string{"host-a", "host-b"}
	tenancy := []string{"host-a", "host-b", "host-c"}
	scope := NewCandidateScope(pool, tenancy)

	if !equalStrings(scope.Pool.HostIDs, []string{"host-a", "host-b"}) {
		t.Errorf("pool = %v, want [host-a host-b]", scope.Pool.HostIDs)
	}
	if !equalStrings(scope.TenancyHostIDs, []string{"host-a", "host-b", "host-c"}) {
		t.Errorf("tenancy = %v, want [host-a host-b host-c]", scope.TenancyHostIDs)
	}

	// Mutating the caller's slices after construction must not affect the scope.
	pool[0] = "MUTATED"
	tenancy[0] = "MUTATED"
	if !equalStrings(scope.Pool.HostIDs, []string{"host-a", "host-b"}) {
		t.Errorf("pool mutated through caller slice = %v (must be defensively copied)", scope.Pool.HostIDs)
	}
	if !equalStrings(scope.TenancyHostIDs, []string{"host-a", "host-b", "host-c"}) {
		t.Errorf("tenancy mutated through caller slice = %v (must be defensively copied)", scope.TenancyHostIDs)
	}
}

// TestNewCandidateScope_EmptyIsUnrestricted proves empty inputs yield the open/shared
// scope (nil pool + nil tenancy = unrestricted, guard off) — the posture the assembler
// treats as "every reporting host is a candidate".
func TestNewCandidateScope_EmptyIsUnrestricted(t *testing.T) {
	scope := NewCandidateScope(nil, nil)
	if scope.Pool.HostIDs != nil {
		t.Errorf("empty-input pool = %v, want nil (unrestricted)", scope.Pool.HostIDs)
	}
	if scope.TenancyHostIDs != nil {
		t.Errorf("empty-input tenancy = %v, want nil (guard off)", scope.TenancyHostIDs)
	}
}

// TestNewCandidateScope_DrivesAssemblerGuard proves a scope built by NewCandidateScope
// drives the assembler's D19 isolation guard exactly as a hand-built CandidateScope: a
// pool-confined, tenancy-armed scope drops a foreign-tenant host carrying a live session
// while keeping the tenancy host and a free non-tenancy host — the store-side scope
// constructor and the guard agree.
func TestNewCandidateScope_DrivesAssemblerGuard(t *testing.T) {
	ctx := context.Background()
	repo := NewMemory()
	// host-foreign is outside the tenancy and carries a live session (another tenancy's).
	mustCreate(t, repo, Session{Ref: SessionRef{SessionUUID: "theirs", HostID: "host-foreign", HostSessionIndex: 1}, State: SessionWorking})

	snaps := []HeartbeatSnapshot{
		snap("host-a", 1, 5),
		snap("host-foreign", 1, 5),
		snap("host-free", 1, 5),
	}
	// Unrestricted pool but tenancy armed (the explicit-tenancy posture): guard active.
	scope := NewCandidateScope(nil, []string{"host-a"})

	got, err := CandidatesForSession(ctx, repo, snaps, scope)
	if err != nil {
		t.Fatalf("CandidatesForSession: %v", err)
	}
	if want := []string{"host-a", "host-free"}; !equalStrings(hostIDs(got), want) {
		t.Fatalf("guarded candidates = %v, want %v (host-foreign dropped under D19)", hostIDs(got), want)
	}
}

// --- local helpers ---------------------------------------------------------

func mustCreate(t *testing.T, repo *Memory, s Session) {
	t.Helper()
	if _, err := repo.CreateSession(context.Background(), s); err != nil {
		t.Fatalf("CreateSession(%s): %v", s.Ref.SessionUUID, err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
