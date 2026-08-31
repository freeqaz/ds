package controlplane

// heartbeatstore.go is the control-plane's LIVE heartbeat ingest feed — the
// short-retention, latest-per-host snapshot plane the scheduler reads for placement
// candidates (doc 15 §7) and the missed-beat / observed-state plane the reconciler
// drives convergence from (doc 15 §3). Heartbeats are NOT a §5.6 store record (the
// record has no heartbeat column); they are the host-agent ingest plane's live feed,
// so this in-process store fronts that feed in the single-binary control plane.
//
// ONE FEED, TWO READERS (the wiring that closes the loop). An inbound
// hostagent.v1.Heartbeat is the orchestrator's only live view of a host. The
// reconcile loop (reconcileloop.go) records every heartbeat HERE before it Observes
// it, so:
//   - the SCHEDULER's StoreCandidateSource (HeartbeatFeed.LatestSnapshots) sees the
//     current capacity/applied_seq at the moment a CreateSession places a session
//     (doc 15 §4.1 step 3 / §7 floors-fit + staleness filters), and
//   - the RECONCILER's Resync can re-run convergence over the latest observed set per
//     host (doc 15 §3 periodic full resync).
// Both read the SAME latest-per-host snapshot, so a placement and a reconcile agree
// on what a host last reported.
//
// CONCURRENCY. The HTTP/gRPC heartbeat ingest is concurrent with placement reads, so
// this store is mutex-guarded. It keeps ONLY the latest snapshot per host (the
// short-retention posture — a host re-emits on every interval, doc 15 §5.2); a
// monotone reported-at timestamp picks the newest, so an out-of-order delivery never
// regresses the live view.

import (
	"context"
	"sync"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// HeartbeatStore is the in-process latest-per-host heartbeat feed. Construct with
// NewHeartbeatStore; feed it with Record (one inbound heartbeat) and read it with
// LatestSnapshots (the scheduler's candidate input), SnapshotForHost (the §4.1
// step-9 D72 freshness probe's host-keyed O(1) point read), and ObservedByHost (the
// reconciler's resync input). It is safe for concurrent Record/read.
//
// The store keys its latest-per-host set by host_id in `last`, so a single host's
// snapshot is a true O(1) map hit (SnapshotForHost) — the freshness point read on the
// create hot path never index-then-filters the whole fleet to find one host, which at
// the ~500-host virtual-metal density the D37 v0 density model sizes for keeps the
// live step-9 re-check a map lookup, not an O(fleet) scan. LatestSnapshots still walks
// the whole set for the candidate feed (the scheduler wants the fleet); SnapshotForHost
// serves the single-host probe off the SAME map, so both readers agree on what a host
// last reported.
type HeartbeatStore struct {
	mu   sync.RWMutex
	now  func() time.Time
	last map[string]heartbeatEntry
}

// heartbeatEntry is one host's latest heartbeat plus the ingest timestamp the
// latest-per-host dedup keys on.
type heartbeatEntry struct {
	hb         *hostagentv1.Heartbeat
	reportedAt time.Time
}

// NewHeartbeatStore builds the feed. now defaults to time.Now (overridable for
// deterministic snapshot timestamps under test).
func NewHeartbeatStore(now func() time.Time) *HeartbeatStore {
	if now == nil {
		now = time.Now
	}
	return &HeartbeatStore{now: now, last: make(map[string]heartbeatEntry)}
}

// Record ingests one inbound heartbeat, replacing the host's prior snapshot with it
// (latest-per-host, keyed on the ingest timestamp so an out-of-order delivery never
// regresses the live view). A nil heartbeat or one with an empty host_id is ignored
// (a malformed feed entry is never a placement target / convergence input).
func (s *HeartbeatStore) Record(hb *hostagentv1.Heartbeat) {
	if hb == nil || hb.GetHostId() == "" {
		return
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.last[hb.GetHostId()]
	if ok && now.Before(cur.reportedAt) {
		return // a stale, out-of-order delivery: keep the newer snapshot.
	}
	s.last[hb.GetHostId()] = heartbeatEntry{hb: hb, reportedAt: now}
}

// LatestSnapshots satisfies scheduler.HeartbeatFeed: it returns the latest per-host
// snapshots as the store-side assembler's input (the assembler does the tenancy /
// pool scoping). It is session-agnostic at this layer — every host's latest snapshot
// is a candidate, and the assembler narrows to the session's pool — so sessionUUID is
// accepted for the seam shape but the whole fleet's latest set is returned (the
// scope narrowing is the TenancyScopeSource + assembler's job).
func (s *HeartbeatStore) LatestSnapshots(_ context.Context, _ string) ([]store.HeartbeatSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]store.HeartbeatSnapshot, 0, len(s.last))
	for hostID, e := range s.last {
		out = append(out, store.HeartbeatSnapshot{
			HostID:              hostID,
			ReportedAtUnixNanos: e.reportedAt.UnixNano(),
			Heartbeat:           e.hb,
		})
	}
	return out, nil
}

// SnapshotForHost resolves ONE host's most-recent snapshot by host_id in O(1) — a single
// map hit on the latest-per-host set, NOT the fleet walk LatestSnapshots does. It satisfies
// the store's host-keyed HostAppliedSeqSource point-read seam directly, so the §4.1 step-9
// LIVE freshness probe (D72) reads a placed host's current applied_seq as a map lookup on the
// create hot path — the O(fleet) index-then-filter the candidate-feed read surface would force
// is avoided at the ~500-host virtual-metal density the D37 v0 density model sizes for. It returns
// the host's snapshot and true when present, or a zero snapshot and false when the host has no current
// report (it vanished from the live feed — the probe then degrades to the recorded re-check).
// It reads the SAME `last` map LatestSnapshots assembles from, under the same RLock, so a
// candidate-feed read and a freshness point read see one consistent latest-per-host view.
func (s *HeartbeatStore) SnapshotForHost(_ context.Context, hostID string) (store.HeartbeatSnapshot, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.last[hostID]
	if !ok {
		return store.HeartbeatSnapshot{}, false, nil
	}
	return store.HeartbeatSnapshot{
		HostID:              hostID,
		ReportedAtUnixNanos: e.reportedAt.UnixNano(),
		Heartbeat:           e.hb,
	}, true, nil
}

// ObservedByHost returns the latest observed-session set per host — the
// reconciler.Resync input (doc 15 §3 periodic full resync). Each host's value is its
// latest heartbeat's observed list (the §5.1/§5.2 ObservedSession elements). A host
// that has reported is present with its observed set (possibly empty); a host that
// has never reported is absent (the missed-beat sweep handles it, never a spurious
// empty observed set — Resync's contract).
func (s *HeartbeatStore) ObservedByHost() map[string][]*hypervisorv1.ObservedSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]*hypervisorv1.ObservedSession, len(s.last))
	for hostID, e := range s.last {
		out[hostID] = e.hb.GetObserved()
	}
	return out
}

// Compile-time proof the feed satisfies the scheduler's HeartbeatFeed seam (the
// candidate-feed read) and the store's host-keyed HostAppliedSeqSource point-read seam
// (the §4.1 step-9 D72 freshness probe's O(1) SnapshotForHost read) — so the production
// freshness consumer drives store.HostAppliedSeq directly over *HeartbeatStore as a map hit.
var (
	_ heartbeatFeed              = (*HeartbeatStore)(nil)
	_ store.HostAppliedSeqSource = (*HeartbeatStore)(nil)
)
