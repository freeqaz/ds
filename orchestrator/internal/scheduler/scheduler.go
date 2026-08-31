package scheduler

// This file is the constructible Scheduler v0 component (doc 15 §7, D37): pure,
// deterministic placement of ONE session onto ONE host, bin-packing on resource
// FLOORS with NO preemption. The same Place entrypoint serves first placement and
// PARKED/SUSPENDED re-placement (D46) — re-placement is not a separate code path,
// it is Place called again with the session's continuity key carried through (the
// re-placement test exercises exactly that).
//
// SHAPE OF THE PROBLEM (the inputs/outputs frozen by doc 15 §7):
//   - input: the candidate hosts as their most recent heartbeat capacity snapshots
//     (the FROZEN hostagent.v1 Heartbeat/HostCapacity proto types, read-only — this
//     package never authors a heartbeat, it consumes the scheduler-relevant slice),
//     plus a Request carrying the session's cgroup-v2 FLOORS (from the env spec with
//     org/global defaults already applied and policy-clamped maxima — the clamp is
//     upstream policy; the scheduler receives the resolved floors as DATA).
//   - output: a Placement naming the chosen host, OR an Unschedulable naming the
//     FILTER that rejected the last surviving candidate (every rejection is
//     attributable to exactly one ordered filter, doc 15 §7).
//
// WHY FLOORS, NOT BURSTS (D37). A session's FLOOR is its guaranteed share —
// cpu.weight / memory.low / io.weight|io.max in cgroup-v2 terms; the host packs so
// the SUM of resident floors ≤ host capacity, and bursts above the floor share the
// remaining headroom best-effort. The heartbeat's HostCapacity.Allocatable* fields
// are already "headroom AFTER current floors" (the host subtracts resident floors
// before reporting), so floors-fit is a single comparison per dimension — the
// scheduler never tracks per-host resident sets itself (the host is the source of
// truth for its own occupancy, refreshed every heartbeat). No preemption: a session
// that does not fit is never placed by evicting another (rebalancing is M3, §7).
//
// NOT HERE (fenced to the paid M3 fleet plane, D80, and to host-pool config, D19):
// multi-host rebalancing, migration scheduling, fleet policy, and KSM/tenancy
// isolation. This component is the v0 single-shot placer those services will reuse.

import (
	"errors"
	"fmt"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// Request is the resolved placement ask for ONE session: its cgroup-v2 resource
// FLOORS plus the policy/version context the ordered filters consult. Every field
// is the OUTPUT of upstream resolution (env-spec parse, org/global defaults,
// policy clamp) — the scheduler treats it as immutable DATA and never re-derives
// or re-clamps it. The same Request shape drives first placement and re-placement;
// SessionUUID is the continuity key that ties a re-placement back to its session.
type Request struct {
	// SessionUUID is the session's continuity key (doc 15 §7): stable across a
	// PARKED→resume re-placement even though the host index/tap changes on the
	// target. The scheduler does not interpret it beyond carrying it into the
	// Placement; it exists so a re-placement decision is attributable to the same
	// session as the original. REQUIRED.
	SessionUUID string

	// Floors are the cgroup-v2 resource floors the host must guarantee — the D37
	// "sum of floors ≤ host capacity" packing unit. These are the RESOLVED floors
	// (env-spec defaults + policy clamp already applied); the scheduler compares
	// them against each host's reported allocatable headroom.
	Floors ResourceFloors

	// RequiredBaselineVersion is the host-baseline artifact version this session
	// requires (doc 14 §11; filter 2). Empty = no baseline constraint (any
	// reporting host is compatible on this axis). When set, a host whose reported
	// HostBaselineVersion is not compatible (see BaselineCompatible) is rejected by
	// the version-compatibility filter — kernel-floor changes force host-image
	// re-rolls, and a session pinned to a new floor must not land on an old host.
	RequiredBaselineVersion string

	// PreferredImageCacheDigest is the warm-image digest that would make this
	// session start fastest if a candidate already has it cached (filter 4, the
	// seconds-to-start lever at M2). This is a PREFERENCE, never a hard filter: it
	// reorders survivors, it never empties the candidate set. Empty = no
	// preference (placement falls back to the deterministic tiebreak).
	PreferredImageCacheDigest string
}

// ResourceFloors is a session's guaranteed resource share in the three dimensions
// the heartbeat reports headroom for (doc 15 §7, D37). The names mirror the
// cgroup-v2 knobs the floors are ENFORCED as on the host (cpu.weight derives from
// the vCPU floor, memory.low from the memory floor, io.weight/io.max from the io
// floor); here they are expressed as the absolute capacity the host must reserve,
// which is what floors-fit compares against HostCapacity.Allocatable*.
type ResourceFloors struct {
	// Vcpu is the guaranteed vCPU floor (enforced as cpu.weight). Compared against
	// HostCapacity.AllocatableVcpu (headroom after resident floors, D37 4:1
	// oversub posture). Zero is legal (a burst-only session with no guaranteed
	// CPU floor) and trivially fits any host on this dimension.
	Vcpu uint32
	// MemoryBytes is the guaranteed memory floor (enforced as memory.low).
	// Compared against HostCapacity.AllocatableMemoryBytes (D37 1.5:1 oversub).
	MemoryBytes uint64
	// IoBps is the guaranteed io floor (enforced as io.weight/io.max). Compared
	// against HostCapacity.AllocatableIoBps.
	IoBps uint64
}

// Candidate is one host as the scheduler sees it: the scheduler-relevant slice of
// that host's most recent heartbeat (the FROZEN hostagent.v1 types, read-only).
// The scheduler reads the snapshot; it never mutates the heartbeat and never holds
// host state between Place calls (each call is pure over the candidate set handed
// to it). A nil Heartbeat or nil Capacity is treated conservatively by the filters
// (a host that has not reported usable capacity cannot be packed onto).
type Candidate struct {
	// HostID identifies the host (doc 15 §7). Used as the placement target and as
	// the deterministic tiebreak key; must be unique within a candidate set.
	HostID string

	// Heartbeat is the host's most recent report (read-only). Its AppliedSeq feeds
	// the D72 staleness filter, HostBaselineVersion the compatibility filter,
	// Capacity the floors-fit and density filters, and ImageCacheDigest the
	// cache-locality preference.
	Heartbeat *hostagentv1.Heartbeat
}

// Placement is the scheduler's decision for a session: the chosen host plus the
// session continuity key and the reason the host won (which filter stage and
// preference put it on top). It is the same shape for first placement and
// re-placement.
type Placement struct {
	// SessionUUID echoes Request.SessionUUID — the continuity key the decision is
	// attributed to.
	SessionUUID string
	// HostID is the chosen host (Candidate.HostID).
	HostID string
	// CachePreferred reports whether the chosen host already had the session's
	// PreferredImageCacheDigest warm (filter 4 hit). Informational: it lets the
	// caller log the seconds-to-start lever; it never changes correctness.
	CachePreferred bool
}

// Unschedulable is the structured no-placement result: the FILTER that rejected
// the last surviving candidate, so the caller (and the operator) can name exactly
// why a session could not be placed. It implements error.
type Unschedulable struct {
	// SessionUUID echoes the rejected Request.
	SessionUUID string
	// Filter is the ordered filter that emptied the candidate set (its stable
	// name, e.g. "policy-staleness"). When the candidate set was empty to begin
	// with, Filter is FilterNoCandidates.
	Filter string
	// Detail is a human-readable amplification (e.g. the staleness gap, the
	// version mismatch) — diagnostic only, never parsed.
	Detail string
}

func (u *Unschedulable) Error() string {
	return fmt.Sprintf("session %s unschedulable: rejected by filter %q: %s",
		u.SessionUUID, u.Filter, u.Detail)
}

// AsUnschedulable extracts an *Unschedulable from an error returned by Place, or
// (nil, false) for any other error. It lets callers branch on "no host fit"
// (retryable / queue) versus a malformed request (ErrInvalidRequest, terminal).
func AsUnschedulable(err error) (*Unschedulable, bool) {
	var u *Unschedulable
	if errors.As(err, &u) {
		return u, true
	}
	return nil, false
}

// ErrInvalidRequest is returned by Place when the Request itself is malformed
// (e.g. no SessionUUID). It is distinct from *Unschedulable: an invalid request is
// a caller bug, not a transient capacity shortage.
var ErrInvalidRequest = errors.New("scheduler: invalid placement request")

// FilterNoCandidates is the Unschedulable.Filter value used when Place is given an
// empty candidate set — there was nothing for the ordered filters to reject.
const FilterNoCandidates = "no-candidates"

// Config holds the rig-tuned thresholds the ordered filters consult. None of these
// are frozen (doc 15 §10): they are deployment knobs with documented strawman
// defaults (DefaultConfig). A Scheduler is constructed once with a Config and is
// then a pure function of (candidates, request).
type Config struct {
	// MaxStalenessGap bounds filter 1 (D72): a host is unschedulable while its
	// heartbeat AppliedSeq lags the orchestrator's current policy seq by more than
	// this many versions. Zero means "must be exactly current"; a host that has
	// not applied the latest swept policy cannot be trusted to enforce it, so it
	// is not a placement target until it catches up (D36/D72). The current seq is
	// supplied per-call via PlaceInput.CurrentPolicySeq.
	MaxStalenessGap uint64

	// MaxStreamsPerHost bounds filter 5 (D34/D66): the (d)-rig density knee. The
	// strawman is the ~75–100 streams/host band; placing past the knee risks the
	// measured-uplink ceiling. RunningSessions ≥ this rejects a host on the
	// density axis. Thresholds are metal-only (D34): on non-metal pools the knob
	// is left zero (disabled) by the host-pool config, never hardcoded here.
	MaxStreamsPerHost uint32

	// BaselineCompatible decides filter 2: given the session's required baseline
	// version and a host's reported version, may the session land? Default
	// (nil) uses exact-match semantics via defaultBaselineCompatible. A deployment
	// can inject a range/semver policy here without touching the filter order.
	BaselineCompatible func(required, hostReported string) bool
}

// DefaultConfig is the documented strawman (doc 15 §7/§10): the (d)-rig density
// knee at the low end of the 75–100 band, exact-current policy required, and
// exact-match baseline compatibility. Deployments override per metal pool.
func DefaultConfig() Config {
	return Config{
		MaxStalenessGap:    0,
		MaxStreamsPerHost:  75,
		BaselineCompatible: defaultBaselineCompatible,
	}
}

// defaultBaselineCompatible is exact-match: a non-empty required version must equal
// the host's reported version; an empty required version accepts any host (no
// constraint on this axis).
func defaultBaselineCompatible(required, hostReported string) bool {
	if required == "" {
		return true
	}
	return required == hostReported
}

// Scheduler is the constructible v0 placer. It is immutable after construction and
// safe for concurrent Place calls (it holds no per-placement state). The filter
// chain is built once at construction in the FROZEN order (doc 15 §7) and reused.
type Scheduler struct {
	cfg     Config
	filters []filter
}

// New constructs a Scheduler from a Config, filling unset fields from
// DefaultConfig and assembling the FROZEN ordered filter chain. The order is fixed
// here and must not be reordered (doc 15 §7): staleness → baseline → floors-fit →
// cache-locality → density.
func New(cfg Config) *Scheduler {
	if cfg.BaselineCompatible == nil {
		cfg.BaselineCompatible = defaultBaselineCompatible
	}
	s := &Scheduler{cfg: cfg}
	s.filters = buildFilters()
	return s
}

// PlaceInput bundles the per-call inputs to Place that are NOT part of the session
// Request: the live candidate hosts and the orchestrator's current policy seq (the
// moving D72 reference the staleness filter measures each host against).
type PlaceInput struct {
	// Candidates are the hosts in scope for this placement (a host-pool slice the
	// caller has already narrowed, e.g. to the session's tenancy pool). Order is
	// irrelevant: Place is deterministic regardless of candidate ordering (it sorts
	// internally for the tiebreak), which the determinism test asserts.
	Candidates []Candidate
	// CurrentPolicySeq is the orchestrator's current swept policy version — the D72
	// reference the staleness filter measures each host's AppliedSeq against. It
	// moves between calls (every policy write), so it is a per-call input, not
	// Config.
	CurrentPolicySeq uint64
}

// Place runs the FROZEN ordered filter chain over the candidates for one session
// and returns the winning Placement, or an *Unschedulable naming the filter that
// emptied the set (or ErrInvalidRequest for a malformed Request). It is pure and
// deterministic: same inputs → same output, independent of candidate ordering.
//
// PARK/RESUME RE-PLACEMENT (D46) IS THIS SAME CALL. A resume re-placement is Place
// invoked again with the resuming session's Request (its SessionUUID unchanged, its
// floors re-resolved) against the current candidate set; the result carries the
// same SessionUUID and the host may differ (index/tap are host-scoped and rebuilt
// by re-admission on the target, doc 15 §7). There is no separate re-placement
// method by design — Replace below is a thin, intention-revealing alias that calls
// Place, and the re-placement test asserts byte-identical behavior.
func (s *Scheduler) Place(in PlaceInput, req Request) (*Placement, error) {
	if req.SessionUUID == "" {
		return nil, fmt.Errorf("%w: empty SessionUUID", ErrInvalidRequest)
	}

	if len(in.Candidates) == 0 {
		return nil, &Unschedulable{
			SessionUUID: req.SessionUUID,
			Filter:      FilterNoCandidates,
			Detail:      "candidate set was empty",
		}
	}

	// fctx carries the per-call references the filters read (current policy seq for
	// staleness) alongside the immutable cfg captured at construction.
	fctx := filterContext{
		cfg:              s.cfg,
		currentPolicySeq: in.CurrentPolicySeq,
	}

	// Run the chain. Each filter either keeps a candidate or attributes a rejection
	// to itself; the cache-locality filter additionally tags survivors with a
	// preference score but rejects nothing. The first filter that empties the set
	// owns the Unschedulable reason (the LAST rejection it recorded, so the Detail
	// is concrete).
	survivors := make([]scored, 0, len(in.Candidates))
	for _, c := range in.Candidates {
		survivors = append(survivors, scored{cand: c})
	}

	for _, f := range s.filters {
		next := survivors[:0:0]
		var lastReject string
		for i := range survivors {
			keep, score, reason := f.eval(fctx, req, survivors[i].cand)
			if keep {
				survivors[i].score += score
				next = append(next, survivors[i])
				continue
			}
			lastReject = reason
		}
		if len(next) == 0 {
			return nil, &Unschedulable{
				SessionUUID: req.SessionUUID,
				Filter:      f.name,
				Detail:      lastReject,
			}
		}
		survivors = next
	}

	// All filters passed at least one host. Pick the winner deterministically:
	// highest preference score first (cache-locality lever), then lowest
	// RunningSessions (spread, the bin-packing posture), then lexicographic HostID
	// (a stable, candidate-order-independent tiebreak).
	winner := pickWinner(survivors)
	return &Placement{
		SessionUUID:    req.SessionUUID,
		HostID:         winner.cand.HostID,
		CachePreferred: winner.score > 0,
	}, nil
}

// Replace is the PARKED/SUSPENDED resume re-placement entrypoint (D46). It is an
// intention-revealing alias for Place: park/resume re-placement reuses the SAME
// machinery (doc 15 §7), so there is deliberately no separate algorithm. Callers
// resuming a session call Replace to make the intent legible at the call site; the
// behavior is identical to Place, which the re-placement test asserts.
func (s *Scheduler) Replace(in PlaceInput, req Request) (*Placement, error) {
	return s.Place(in, req)
}

// scored is a candidate plus its accumulated preference score through the chain.
// Only the cache-locality filter contributes score today; the struct generalizes
// to future soft preferences without changing the filter contract.
type scored struct {
	cand  Candidate
	score int
}

// pickWinner applies the deterministic ordering to the surviving candidates and
// returns the best. The ordering is total (HostID is unique within a set), so the
// result is independent of the input candidate order.
func pickWinner(survivors []scored) scored {
	best := survivors[0]
	for _, s := range survivors[1:] {
		if betterThan(s, best) {
			best = s
		}
	}
	return best
}

// betterThan is the total winner-ordering: higher score wins; ties break to fewer
// running sessions (spread); remaining ties break to the lexicographically smaller
// HostID (stable, deterministic).
func betterThan(a, b scored) bool {
	if a.score != b.score {
		return a.score > b.score
	}
	ar, br := runningSessions(a.cand), runningSessions(b.cand)
	if ar != br {
		return ar < br
	}
	return a.cand.HostID < b.cand.HostID
}

// runningSessions reads a candidate's current session count from its heartbeat
// capacity, treating a missing heartbeat/capacity as "unknown, sort last" via a
// max sentinel so it never wins a spread tiebreak over a host that actually
// reported room.
func runningSessions(c Candidate) uint32 {
	cap := c.Heartbeat.GetCapacity()
	if cap == nil {
		return ^uint32(0)
	}
	return cap.GetRunningSessions()
}
