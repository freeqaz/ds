package scheduler

// placer.go is the PRODUCTION Placer adapter (doc 15 §7, orch18): the bridge from a
// sessions-side placement REQUEST to a scheduler DECISION. The create choreography
// (internal/sessions, §4.1 step 3) consumes placement through a package-owned Placer
// interface DEFINED SESSIONS-SIDE so the coordinator never imports this package (a
// production sessions→scheduler import would cycle — the scheduler reads the §3
// transition-table vocabulary from the sessions package). This adapter satisfies that
// seam FROM THIS SIDE: scheduler MAY import sessions (sessions does not import
// scheduler, so the edge is acyclic), the same data-across-the-seam discipline the
// launch gate uses. The compile-time assertion at the bottom of this file pins that
// *Adapter implements the CURRENT sessions.Placer surface verbatim.
//
// WHAT IT DOES. It does NOT re-implement any filter — it DRIVES the landed orch17
// filter chain. Place:
//   (1) assembles the live candidate set for the session's tenancy host-pool from a
//       CandidateSource (the store-side scheduler_candidates_queries.go assembler in
//       production; a fake in tests) — D19 single-tenant isolation is a host-pool
//       config applied at assembly, never a scheduler filter;
//   (2) reads the orchestrator's CURRENT swept policy seq (PolicySeqSource) — the D72
//       reference the staleness filter measures each host's applied_seq against;
//   (3) translates the sessions.PlacementRequest (image digest, env-config ref,
//       proto ResourceFloors) into the scheduler Request (cgroup-v2 floors, baseline,
//       cache-locality preference) — the floors arrive ALREADY resolved/clamped (the
//       coordinator carries them as DATA), so the adapter only re-shapes them;
//   (4) runs the FROZEN §7 filter chain via Scheduler.Place;
//   (5) maps the decision back: a Placement → sessions.Placement{HostID, AppliedSeq}
//       (AppliedSeq read from the WINNING host's heartbeat — the policy version the
//       host had applied at placement, recorded for the §4.1 step-9 D72 re-check); an
//       *Unschedulable whose rejecting filter is policy-staleness → sessions.ErrPolicyStale
//       (the D72 "no fresh host" refusal the coordinator branches on); any other
//       Unschedulable / invalid request → a structured error the coordinator surfaces.

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// CandidateSource yields the live candidate hosts for one session's placement,
// already scoped to the session's tenancy host-pool (D19). In production this is the
// store-side assembler (internal/store.CandidatesForSession bound to a session); in
// tests it is a fake returning hand-built heartbeat candidates (D50 synthetic
// fixtures). The adapter OWNS this interface so it never imports the store — the
// store produces []Candidate, the adapter consumes the interface, one-directional.
type CandidateSource interface {
	// Candidates returns the placement candidates for the given session UUID. The
	// implementation applies the tenancy/host-pool scoping and latest-per-host
	// freshness; the adapter takes the result as the §7 filter chain's input.
	Candidates(ctx context.Context, sessionUUID string) ([]Candidate, error)
}

// PolicySeqSource yields the orchestrator's CURRENT swept policy seq — the moving D72
// reference the staleness filter measures each host's heartbeat applied_seq against.
// It is read PER placement (the seq advances on every policy write), so it is a seam,
// not a constant. In production it is backed by the policy_log head; in tests a fake
// returns a fixed seq.
type PolicySeqSource interface {
	// CurrentPolicySeq returns the orchestrator's current swept policy version.
	CurrentPolicySeq(ctx context.Context) (uint64, error)
}

// HeartbeatFeed is the live latest-per-host heartbeat ingest the production
// CandidateSource reads to assemble candidates: it returns the most-recent snapshots
// for the hosts in (or eligible for) a session's tenancy pool. Heartbeats are NOT a
// store record (the §5.6 record has no heartbeat column); they are the host-agent
// ingest plane's short-retention feed, so this seam fronts that feed (in tests a fake
// returns hand-built snapshots — D50 synthetic fixtures). The store-side assembler
// (store.CandidatesForSession) does the tenancy/host-pool scoping over what this
// feed returns.
type HeartbeatFeed interface {
	// LatestSnapshots returns the latest per-host heartbeat snapshots in scope for the
	// session's placement. Duplicates per host are allowed (the assembler collapses to
	// the newest); scoping/freshness narrowing is the assembler's job.
	LatestSnapshots(ctx context.Context, sessionUUID string) ([]store.HeartbeatSnapshot, error)
}

// TenancyScopeSource yields the D19 tenancy host-pool scope for a session's placement
// (its host-pool members + the tenancy host set the isolation guard recognises). It
// is config-backed (single-tenant isolation is a host-pool configuration, D19), read
// per placement so a pool re-config takes effect without re-wiring. In tests a fake
// returns a fixed scope.
type TenancyScopeSource interface {
	// ScopeFor returns the tenancy host-pool scope for the session's placement.
	ScopeFor(ctx context.Context, sessionUUID string) (store.CandidateScope, error)
}

// StoreCandidateSource is the PRODUCTION CandidateSource: it reads the latest
// heartbeat snapshots (HeartbeatFeed) and the tenancy scope (TenancyScopeSource),
// drives the store-side assembler (store.CandidatesForSession — latest-per-host +
// pool confinement + D19 isolation guard, over the narrow ListSessions interface the
// concrete store satisfies), and maps the neutral []store.HostCandidate it returns to
// []Candidate. It is the one place store.HostCandidate becomes scheduler.Candidate —
// keeping the store a pure leaf (no scheduler import) and the conversion at the seam.
type StoreCandidateSource struct {
	// Lister is the narrow ListSessions slice the D19 isolation guard reads; the
	// concrete *store.Memory / *store.Postgres satisfy it. Nil disables the guard.
	Lister interface {
		ListSessions(ctx context.Context, f store.SessionFilter) ([]store.Session, error)
	}
	// Feed supplies the latest per-host heartbeat snapshots in scope.
	Feed HeartbeatFeed
	// Scope supplies the D19 tenancy host-pool scope.
	Scope TenancyScopeSource
}

// Candidates implements CandidateSource: it gathers the snapshots + scope for the
// session, runs the store-side assembler, and converts the neutral host candidates to
// scheduler candidates the §7 filter chain consumes.
func (s StoreCandidateSource) Candidates(ctx context.Context, sessionUUID string) ([]Candidate, error) {
	snaps, err := s.Feed.LatestSnapshots(ctx, sessionUUID)
	if err != nil {
		return nil, fmt.Errorf("scheduler: heartbeat feed for %s: %w", sessionUUID, err)
	}
	scope, err := s.Scope.ScopeFor(ctx, sessionUUID)
	if err != nil {
		return nil, fmt.Errorf("scheduler: tenancy scope for %s: %w", sessionUUID, err)
	}
	hosts, err := store.CandidatesForSession(ctx, s.Lister, snaps, scope)
	if err != nil {
		return nil, fmt.Errorf("scheduler: assembling candidates for %s: %w", sessionUUID, err)
	}
	return candidatesFromHosts(hosts), nil
}

// candidatesFromHosts maps the store-side neutral host candidates onto the scheduler's
// Candidate shape (the only place store.HostCandidate → scheduler.Candidate happens).
// The order is preserved (the assembler already returns them host-id-sorted).
func candidatesFromHosts(hosts []store.HostCandidate) []Candidate {
	out := make([]Candidate, len(hosts))
	for i, h := range hosts {
		out[i] = Candidate{HostID: h.HostID, Heartbeat: h.Heartbeat}
	}
	return out
}

// _ pins StoreCandidateSource against the CandidateSource interface at compile time.
var _ CandidateSource = StoreCandidateSource{}

// HostFreshness is the §4.1 step-9 LIVE freshness-probe seam (D72), read PER re-check:
// it returns one host's CURRENT heartbeat applied_seq (the live policy version the
// host has applied RIGHT NOW), so the routable gate can re-validate against the host's
// present freshness, not the value recorded at placement. It is the host-keyed dual of
// the per-session CandidateSource: where CandidateSource assembles the candidate set
// for a placement, HostFreshness probes ONE already-placed host's current freshness.
// In production it is backed by the same latest-per-host heartbeat feed; in tests a
// fake returns a fixed current seq (D50 synthetic fixtures). The boolean reports
// whether the host HAS a current heartbeat — false means the host vanished from the
// live feed (no current report), which the adapter surfaces as ErrFreshnessUnknown so
// the coordinator fail-closes the gate.
type HostFreshness interface {
	// CurrentAppliedSeq returns the host's current heartbeat applied_seq and true, or
	// (0, false) when the host has no current heartbeat in the live feed.
	CurrentAppliedSeq(ctx context.Context, hostID string) (uint64, bool, error)
}

// Adapter is the production Placer: it drives the §7 filter chain (the embedded
// *Scheduler) over the candidates a CandidateSource assembles, against the current
// policy seq a PolicySeqSource reports, and maps the scheduler decision onto the
// sessions-side Placement / ErrPolicyStale contract. It is immutable after
// construction and safe for concurrent Place calls (the *Scheduler is, and the
// sources are read-only seams).
type Adapter struct {
	sched      *Scheduler
	candidates CandidateSource
	policySeq  PolicySeqSource
	// Freshness backs the §4.1 step-9 LIVE re-check (Placer.CurrentFreshness). It is an
	// ADDITIVE, optional seam set AFTER construction (NewAdapter's signature stays
	// fixed so mainpkg-live-edges, which constructs the adapter, keeps compiling): a
	// production wiring assigns it the latest-per-host heartbeat feed; an adapter built
	// for placement only may leave it nil. A nil Freshness makes CurrentFreshness
	// return sessions.ErrFreshnessUnknown — the coordinator fail-closes the gate, never
	// waves a host through unprobed.
	Freshness HostFreshness
}

// NewAdapter constructs the production Placer over a Scheduler, a CandidateSource,
// and a PolicySeqSource. The Scheduler carries the rig-tuned Config (filter
// thresholds); the two sources supply the per-placement live inputs. All three are
// required — a nil argument is a wiring bug surfaced at the first Place as
// ErrPlacerMisconfigured rather than a panic. The §4.1 step-9 live-freshness seam
// (Freshness) is set ADDITIVELY on the returned adapter (this signature is fixed); an
// unset Freshness makes the step-9 live probe fail-closed.
func NewAdapter(sched *Scheduler, candidates CandidateSource, policySeq PolicySeqSource) *Adapter {
	return &Adapter{sched: sched, candidates: candidates, policySeq: policySeq}
}

// ErrPlacerMisconfigured is returned by Place when the adapter was constructed with a
// nil dependency (Scheduler, CandidateSource, or PolicySeqSource). It is a wiring bug,
// distinct from the placement-time outcomes (ErrPolicyStale / a candidate shortage).
var ErrPlacerMisconfigured = errors.New("scheduler: placer adapter misconfigured (nil dependency)")

// ErrNoPlaceableHost is the adapter's translation of an *Unschedulable whose rejecting
// filter is NOT policy-staleness: no host in the tenancy pool fit the session on
// capacity / baseline / density (or the candidate set was empty). It is distinct from
// sessions.ErrPolicyStale (which is the D72 freshness refusal the coordinator records
// against step 3/step 9) and from ErrPlacerMisconfigured. The rejecting filter and its
// detail are wrapped for diagnostics; callers branch on errors.Is, never the string.
var ErrNoPlaceableHost = errors.New("scheduler: no placeable host in tenancy pool")

// Place is the sessions.Placer entrypoint (doc 15 §4.1 step 3). It assembles the
// scoped candidates, reads the current policy seq, drives the FROZEN §7 filter chain,
// and maps the decision onto the sessions contract. A staleness rejection becomes
// sessions.ErrPolicyStale (the D72 "no fresh host" refusal); any other shortage
// becomes ErrNoPlaceableHost; a malformed request becomes a wrapped
// scheduler.ErrInvalidRequest. On success it returns the chosen host plus the
// applied_seq that host had at placement (read from the winning host's heartbeat —
// the policy version the §4.1 step-9 re-check re-validates).
func (a *Adapter) Place(ctx context.Context, sessionUUID string, req sessions.PlacementRequest) (sessions.Placement, error) {
	if a == nil || a.sched == nil || a.candidates == nil || a.policySeq == nil {
		return sessions.Placement{}, ErrPlacerMisconfigured
	}

	cands, err := a.candidates.Candidates(ctx, sessionUUID)
	if err != nil {
		return sessions.Placement{}, fmt.Errorf("scheduler: assembling candidates for %s: %w", sessionUUID, err)
	}

	curSeq, err := a.policySeq.CurrentPolicySeq(ctx)
	if err != nil {
		return sessions.Placement{}, fmt.Errorf("scheduler: reading current policy seq for %s: %w", sessionUUID, err)
	}

	placement, err := a.sched.Place(
		PlaceInput{Candidates: cands, CurrentPolicySeq: curSeq},
		requestFromPlacement(sessionUUID, req),
	)
	if err != nil {
		return sessions.Placement{}, mapPlaceError(err)
	}

	// AppliedSeq is the WINNING host's heartbeat applied_seq — the D72 policy version
	// the host had applied at placement, which the §4.1 step-9 re-check re-validates.
	// The scheduler Placement does not carry it (it is host state, not a decision
	// field), so the adapter reads it back from the winning candidate's heartbeat.
	return sessions.Placement{
		HostID:     placement.HostID,
		AppliedSeq: appliedSeqOf(cands, placement.HostID),
	}, nil
}

// CurrentFreshness is the sessions.Placer §4.1 step-9 LIVE re-check entrypoint (D72),
// ADDED additively (Place is unchanged; the constructor is unchanged). It reads the
// placed host's CURRENT heartbeat applied_seq through the optional HostFreshness seam
// — the live policy version the host has applied right now — so the routable gate can
// re-validate against present freshness, closing the residual D72 window the
// recorded-only re-check (a host that fell behind after placement with no record
// write) misses. A nil Freshness seam (no live probe wired — e.g. the current
// placement-only wiring) surfaces sessions.ErrFreshnessUnknown, which the coordinator
// DEGRADES to the recorded re-check (the pre-probe behavior is preserved). A host with
// no current heartbeat in the live feed also surfaces ErrFreshnessUnknown (host-named):
// the live feed has no present signal for it, so the gate degrades rather than hard-
// failing a create the recorded re-check still vouches for — a host that has actually
// fallen behind reports a present, lower applied_seq, which the coordinator catches.
// The proto applied_seq is uint64 and the sessions contract is int64; placement seqs
// are small monotone policy versions far below the int64 ceiling, so the conversion is
// loss-free in every real fleet (matching appliedSeqOf's recorded-side conversion).
func (a *Adapter) CurrentFreshness(ctx context.Context, hostID string) (int64, error) {
	if a == nil || a.Freshness == nil {
		return 0, sessions.ErrFreshnessUnknown
	}
	seq, ok, err := a.Freshness.CurrentAppliedSeq(ctx, hostID)
	if err != nil {
		return 0, fmt.Errorf("scheduler: reading current freshness for host %s: %w", hostID, err)
	}
	if !ok {
		// No current heartbeat for the placed host — it has no present report in the
		// live feed. Surface as ErrFreshnessUnknown (host-named): the coordinator
		// degrades to the recorded re-check rather than refuse a create the recorded
		// signal still vouches for.
		return 0, fmt.Errorf("%w: host %s has no current heartbeat", sessions.ErrFreshnessUnknown, hostID)
	}
	return int64(seq), nil
}

// requestFromPlacement translates the sessions.PlacementRequest into the scheduler
// Request the §7 filter chain reads. The proto ResourceFloors (cgroup-v2 knobs, D37)
// map onto the scheduler's three floors-fit dimensions verbatim: vcpu_floor → Vcpu,
// memory_low_bytes → MemoryBytes, io_max_bps → IoBps (the floors the host must
// guarantee; burst/weight knobs are enforcement detail the scheduler does not pack
// on). The image-cache digest doubles as the §7 filter-4 cache-locality preference
// (a host already holding the warm image starts the session fastest).
// RequiredBaselineVersion maps onto the §7 filter-2 host-baseline-compatibility
// constraint verbatim (doc 14 §11): the session's pinned >=6.12 host-kernel baseline
// floor that the scheduler's baselineVersionFilter honors as a HARD predicate, so a
// session pinned to a new kernel floor never lands on an old host. Threading it here is
// a pure carry — the adapter does not interpret it (the filter chain reads it, and an
// empty value is the no-baseline-constraint posture the filter already passes through).
// EnvConfigRef is carried for completeness; the §7 chain keys placement on image +
// floors + baseline today, so it does not feed a filter — leaving it unmapped is
// correct, not a dropped input.
func requestFromPlacement(sessionUUID string, req sessions.PlacementRequest) Request {
	f := req.Floors // *hypervisorv1.ResourceFloors; nil-safe via getters
	return Request{
		SessionUUID:               sessionUUID,
		Floors:                    ResourceFloors{Vcpu: f.GetVcpuFloor(), MemoryBytes: f.GetMemoryLowBytes(), IoBps: f.GetIoMaxBps()},
		RequiredBaselineVersion:   req.RequiredBaselineVersion,
		PreferredImageCacheDigest: req.ImageID,
	}
}

// appliedSeqOf reads the applied_seq the chosen host reported (its heartbeat's D72
// policy version at placement), returned as the sessions.Placement.AppliedSeq. The
// proto field is uint64 and the record column is int64; placement applied_seqs are
// small monotone policy versions far below the int64 ceiling, so the conversion is
// loss-free in every real fleet. A host that vanished from the candidate set between
// Place and this read (it cannot — the slice is the same) or a nil heartbeat yields 0,
// the "no policy applied yet" value the step-9 re-check treats conservatively.
func appliedSeqOf(cands []Candidate, hostID string) int64 {
	for _, c := range cands {
		if c.HostID == hostID {
			return int64(c.Heartbeat.GetAppliedSeq())
		}
	}
	return 0
}

// mapPlaceError translates a Scheduler.Place error onto the sessions-side contract.
// An *Unschedulable rejected by the policy-staleness filter is the D72 "no fresh host"
// refusal → sessions.ErrPolicyStale (the coordinator records it against §4.1 step 3 /
// re-checks at step 9). Any OTHER Unschedulable (no candidates, floors-fit, baseline,
// density) is a capacity/compat shortage → ErrNoPlaceableHost, with the rejecting
// filter + detail wrapped for diagnostics. A malformed request (ErrInvalidRequest) is
// a caller bug, surfaced wrapped. The original error is always wrapped (errors.Is /
// errors.As keep working) so callers branch on sentinels, never strings.
func mapPlaceError(err error) error {
	if u, ok := AsUnschedulable(err); ok {
		if u.Filter == FilterPolicyStaleness {
			return fmt.Errorf("%w: %s", sessions.ErrPolicyStale, u.Detail)
		}
		return fmt.Errorf("%w: filter %q: %s", ErrNoPlaceableHost, u.Filter, u.Detail)
	}
	if errors.Is(err, ErrInvalidRequest) {
		return fmt.Errorf("scheduler: invalid placement request: %w", err)
	}
	return err
}

// _ pins the production adapter against the sessions-side Placer surface at COMPILE
// time: if the sessions package ever changes the Placer method set, this assertion
// fails the build here (the adapter must track the seam verbatim). The surface is now
// {Place, CurrentFreshness} — the §4.1 step-9 live-freshness probe (D72) was added
// additively, implemented above over the optional HostFreshness seam without touching
// NewAdapter's signature, so a wiring that constructs the adapter stays compiling.
var _ sessions.Placer = (*Adapter)(nil)

// =====================================================================================
// Production HeartbeatFeed + TenancyScopeSource (orch43)
//
// placer.go declares the HeartbeatFeed and TenancyScopeSource seams the production
// CandidateSource (StoreCandidateSource) reads, but after wave-1 only test fakes
// implemented Feed/Scope — so a wired StoreCandidateSource had no real candidate set.
// The two production impls below close that gap WITHOUT touching the store-side
// assembler (it already does latest-per-host + pool confinement + the D19 guard over
// the data it receives) and WITHOUT a §5.6 store record or migration (heartbeats are
// the host-agent ingest plane's short-retention feed, doc 15 §3, never persisted).
//
// SCOPE NOTE. These are SCHEDULER-package impls built against DOCUMENTED wire shapes +
// synthetic fixtures (D50). PRODUCTION WIRING into the live control plane is a DEFERRED
// follow-up: the control plane's in-process heartbeat ingest store (which would satisfy
// RawHeartbeatSource) and the operator tenancy config (which would feed ConfigTenancyScope)
// are assigned in controlplane wiring, which this wave does NOT touch (no
// controlplane/heartbeatstore.go or wiring.go change). A live-only ingest path is gated
// behind DS_ORCH_LIVE at that wiring seam, never here (this code holds no live state).
// =====================================================================================

// RawHeartbeat is ONE host's report as the host-agent ingest plane delivered it: the
// host id, the ingest timestamp the latest-per-host dedup keys on, and the read-only
// frozen hostagent.v1 Heartbeat. It is the RAW (possibly stale, possibly duplicated —
// a host re-emits on every interval) input to LatestPerHostFeed, which collapses these
// to the newest per host before they reach the store-side assembler. It mirrors
// store.HeartbeatSnapshot's three fields so the collapse is a one-to-one shape map; it
// is declared scheduler-side so the production HeartbeatFeed reads its raw input through
// a seam this package owns (no controlplane import — the edge is one-directional, the
// control plane satisfies this interface, never the reverse).
type RawHeartbeat struct {
	// HostID identifies the reporting host. Duplicate HostIDs across reports are
	// collapsed to the latest by ReportedAtUnixNanos; an empty HostID is dropped.
	HostID string
	// ReportedAtUnixNanos is the ingest timestamp used ONLY to pick the latest report
	// per host. Freshness vs. policy seq is the D72 filter's job (on AppliedSeq), not
	// this timestamp; here it is the dedup key alone.
	ReportedAtUnixNanos int64
	// Heartbeat is the host's report (read-only; the frozen hostagent.v1 type). A nil
	// Heartbeat is carried through to the snapshot — the scheduler's filters treat a
	// nil/zero capacity conservatively (the first filter its zero value fails rejects it).
	Heartbeat *hostagentv1.Heartbeat
}

// RawHeartbeatSource is the NARROW additive seam the production HeartbeatFeed reads its
// raw heartbeat data through: it returns the ingest plane's current raw reports (the
// short-retention, in-memory buffer of what hosts have reported), which the feed then
// collapses to the latest per host. The real control-plane in-process heartbeat ingest
// store satisfies this LATER (a deferred wiring step — NOT done here); in tests a
// synthetic fake returns hand-built reports (D50). It is session-agnostic at this
// layer: every reporting host is a raw candidate, and the tenancy/pool narrowing is the
// store-side assembler's job — so RawReports ignores the session UUID for now (the
// signature carries it for the seam shape and to admit a future source that pre-narrows
// by session without a feed-side change).
type RawHeartbeatSource interface {
	// RawReports returns the ingest plane's current raw heartbeat reports (duplicates
	// per host allowed; the feed collapses to the latest). The session UUID identifies
	// the placement the reports feed but does not narrow them at this layer.
	RawReports(ctx context.Context, sessionUUID string) ([]RawHeartbeat, error)
}

// LatestPerHostFeed is the PRODUCTION HeartbeatFeed: it reads the raw ingest reports
// through a RawHeartbeatSource and collapses them to the LATEST snapshot per host
// (highest ReportedAtUnixNanos), the §3 "observed state from heartbeats" view the
// store-side assembler scopes over. It holds NO state of its own — it is a stateless
// projection over the source's current reports, so it is the SHORT-RETENTION, in-memory
// feed (no §5.6 store record, no DB table, no migration): retention lives in the source
// (the ingest plane keeps only the live latest-per-host set), and this feed only narrows
// to one report per host on each read. Construct with NewLatestPerHostFeed.
type LatestPerHostFeed struct {
	// src is the raw ingest seam. A nil src makes LatestSnapshots return
	// ErrHeartbeatFeedMisconfigured (a wiring bug, surfaced rather than panicking).
	src RawHeartbeatSource
}

// NewLatestPerHostFeed constructs the production HeartbeatFeed over a raw ingest source.
// The source supplies the live reports; the feed collapses them to the latest per host.
// A nil source is a wiring bug surfaced at the first LatestSnapshots as
// ErrHeartbeatFeedMisconfigured, never a panic.
func NewLatestPerHostFeed(src RawHeartbeatSource) *LatestPerHostFeed {
	return &LatestPerHostFeed{src: src}
}

// ErrHeartbeatFeedMisconfigured is returned by LatestSnapshots when the feed was built
// with a nil RawHeartbeatSource — a wiring bug, distinct from a source fault (which is
// wrapped and propagated).
var ErrHeartbeatFeedMisconfigured = errors.New("scheduler: heartbeat feed misconfigured (nil raw source)")

// LatestSnapshots implements HeartbeatFeed: it reads the raw reports and returns the
// latest per host (highest ReportedAtUnixNanos), each as a store.HeartbeatSnapshot the
// assembler consumes. Reports with an empty HostID are dropped (a malformed feed entry
// is never a placement target); duplicates per host are collapsed to the newest. The
// result is host-id-sorted for a reproducible feed (the assembler re-sorts anyway, so
// ordering is non-load-bearing). The session UUID is passed through to the source; the
// tenancy/pool narrowing is the assembler's job over what this feed returns.
func (f *LatestPerHostFeed) LatestSnapshots(ctx context.Context, sessionUUID string) ([]store.HeartbeatSnapshot, error) {
	if f == nil || f.src == nil {
		return nil, ErrHeartbeatFeedMisconfigured
	}
	raw, err := f.src.RawReports(ctx, sessionUUID)
	if err != nil {
		return nil, fmt.Errorf("scheduler: reading raw heartbeats for %s: %w", sessionUUID, err)
	}
	return latestSnapshotsPerHost(raw), nil
}

// latestSnapshotsPerHost collapses possibly-duplicated raw reports to the single
// most-recent per host (highest ReportedAtUnixNanos), returned host-id-sorted for
// determinism and emitted as store.HeartbeatSnapshot. A report with an empty HostID is
// dropped. On a tie in ReportedAtUnixNanos the later report in the slice wins (>=), the
// same last-writer-on-tie rule the store-side latestPerHost uses, so a feed and the
// assembler agree on which snapshot a host's duplicates collapse to.
func latestSnapshotsPerHost(raw []RawHeartbeat) []store.HeartbeatSnapshot {
	best := make(map[string]RawHeartbeat, len(raw))
	for _, r := range raw {
		if r.HostID == "" {
			continue
		}
		cur, ok := best[r.HostID]
		if !ok || r.ReportedAtUnixNanos >= cur.ReportedAtUnixNanos {
			best[r.HostID] = r
		}
	}
	out := make([]store.HeartbeatSnapshot, 0, len(best))
	for _, r := range best {
		out = append(out, store.HeartbeatSnapshot{
			HostID:              r.HostID,
			ReportedAtUnixNanos: r.ReportedAtUnixNanos,
			Heartbeat:           r.Heartbeat,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out
}

// _ pins LatestPerHostFeed against the HeartbeatFeed interface at compile time.
var _ HeartbeatFeed = (*LatestPerHostFeed)(nil)

// TenancyConfig is the operator-authored D19 single-tenant tenancy host-pool config a
// ConfigTenancyScope yields per placement. KSM-off single-tenant isolation is a
// host-POOL configuration (doc 15 §7 / D19), not a scheduler feature: the config names
// the hosts in the session's tenancy pool, and the store-side assembler's D19 isolation
// guard NARROWS over it before placement. It is plain DATA (operator/inventory config),
// carried here as a value — this package never authors it.
//
// An EMPTY config is the open/shared-pool posture: no pool restriction, no cross-tenant
// guard (every reporting host is a candidate, the unrestricted default). A NON-empty
// PoolHostIDs confines candidates to those hosts; TenancyHostIDs (defaulting to the pool
// members) is the host set the isolation guard recognises as "this tenancy" so it can
// drop a host carrying a foreign tenancy's live session.
type TenancyConfig struct {
	// PoolHostIDs are the hosts in the tenancy pool. When non-empty, only these hosts
	// are candidates; when empty, the pool is unrestricted (open/shared posture).
	PoolHostIDs []string
	// TenancyHostIDs is the host set the D19 isolation guard treats as "this tenancy"
	// (to recognise a foreign-tenant host). Empty defaults to PoolHostIDs — a restricted
	// pool's members ARE the tenancy by construction; a caller running an unrestricted
	// pool that still wants the guard sets this explicitly. Empty with an empty pool
	// disables the cross-tenant guard (no notion of "this tenancy" to compare against).
	TenancyHostIDs []string
}

// ConfigTenancyScope is the PRODUCTION TenancyScopeSource: a CONFIG-BACKED (D19)
// single-tenant tenancy host-pool scope source. It yields the SAME configured
// host-pool scope for every placement (single-tenant isolation is a host-pool
// CONFIGURATION read per placement, not a per-session scheduler decision), which the
// store-side assembler's D19 isolation guard narrows over before placement (doc 15 §7
// filter chain). It is immutable after construction and safe for concurrent ScopeFor
// calls (it holds only the read-only config). The config is captured by VALUE at
// construction with its slices copied, so a later caller-side mutation of the source
// slices cannot mutate the scope the source yields.
type ConfigTenancyScope struct {
	scope store.CandidateScope
}

// NewConfigTenancyScope builds the config-backed tenancy scope source from a
// TenancyConfig. The config's pool + tenancy host sets are assembled into the immutable
// store.CandidateScope the source yields through store.NewCandidateScope — the store
// owns the CandidateScope shape (and its defensive copy), so the returned source owns
// its own data (a later mutation of cfg's slices does not affect it). An empty config
// yields the open/shared-pool scope (the unrestricted, guard-off default).
func NewConfigTenancyScope(cfg TenancyConfig) *ConfigTenancyScope {
	return &ConfigTenancyScope{
		scope: store.NewCandidateScope(cfg.PoolHostIDs, cfg.TenancyHostIDs),
	}
}

// ScopeFor implements TenancyScopeSource: it returns the configured D19 tenancy
// host-pool scope for the session's placement. The scope is config-backed and
// session-independent (single-tenant isolation is a host-pool config, not a per-session
// feature), so the same scope is yielded for every session UUID; a pool re-config takes
// effect by re-constructing the source (re-wiring), which the deferred production wiring
// owns. It never errors — the config is in-memory and already validated as data.
func (s *ConfigTenancyScope) ScopeFor(_ context.Context, _ string) (store.CandidateScope, error) {
	if s == nil {
		return store.CandidateScope{}, nil
	}
	return s.scope, nil
}

// _ pins ConfigTenancyScope against the TenancyScopeSource interface at compile time.
var _ TenancyScopeSource = (*ConfigTenancyScope)(nil)
