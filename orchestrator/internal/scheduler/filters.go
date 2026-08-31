package scheduler

// The FROZEN ordered filter chain (doc 15 §7, D37). The order is a CONTRACT and
// must not be reordered:
//
//  1. policy-staleness    — D72 unschedulable rule on heartbeat AppliedSeq
//  2. baseline-version    — doc 14 §11 host-baseline compatibility
//  3. floors-fit          — D37 bin-packing: session floors ≤ host allocatable
//  4. cache-locality       — image-cache PREFERENCE (rejects nothing; scores)
//  5. density-ceiling     — D66 uplink + (d)-rig density knee (D34 metal-only)
//
// Each filter is an independently-testable unit with a stable name. A filter's
// eval returns (keep, score, rejectReason): a hard filter sets keep=false with a
// concrete reason when it rejects (and never contributes score); the SOFT
// cache-locality filter always keeps and contributes a positive score on a hit.
// Filters reading host fields go through the proto getters so a nil heartbeat or
// nil capacity is handled as the zero value — a host that has reported nothing is
// rejected by the first filter whose threshold the zero value fails, never panics.

import (
	"fmt"
)

// Filter name constants — the stable identifiers an Unschedulable.Filter carries
// so callers and operators can attribute a rejection to exactly one stage.
const (
	FilterPolicyStaleness = "policy-staleness"
	FilterBaselineVersion = "baseline-version"
	FilterFloorsFit       = "floors-fit"
	FilterCacheLocality   = "cache-locality"
	FilterDensityCeiling  = "density-ceiling"
)

// filterContext is the per-call read-only context the filters consult: the
// immutable Config captured at Scheduler construction plus the moving D72 policy
// reference supplied per Place call.
type filterContext struct {
	cfg              Config
	currentPolicySeq uint64
}

// filter is one stage of the chain: a stable name plus an eval. eval reports
// whether to KEEP the candidate, a non-negative preference SCORE to add (only the
// soft cache filter uses it), and — when keep is false — a concrete REJECT reason
// for the Unschedulable.Detail.
type filter struct {
	name string
	eval func(fctx filterContext, req Request, c Candidate) (keep bool, score int, reject string)
}

// buildFilters assembles the FROZEN chain in order. The slice order IS the
// contract; tests assert both the names-in-order and each filter in isolation.
// Filters read their thresholds from the per-call filterContext (which carries
// Config), so the chain itself is config-independent — built once, reused.
func buildFilters() []filter {
	return []filter{
		policyStalenessFilter(),
		baselineVersionFilter(),
		floorsFitFilter(),
		cacheLocalityFilter(),
		densityCeilingFilter(),
	}
}

// FilterOrder returns the stable filter names in their FROZEN order. It exists so
// the order is assertable from tests (and loggable) without reaching into the
// unexported chain.
func (s *Scheduler) FilterOrder() []string {
	names := make([]string, len(s.filters))
	for i, f := range s.filters {
		names[i] = f.name
	}
	return names
}

// 1. policy-staleness (D72). A host is unschedulable while its heartbeat
// AppliedSeq lags the orchestrator's current swept policy seq by more than the
// configured budget. A host that has not applied the latest verified policy cannot
// be trusted to enforce it, so it is not a placement target until it catches up
// (D36/D72). A host reporting AppliedSeq AHEAD of the reference (the reference is a
// snapshot that can momentarily trail a fast host) is never penalized.
func policyStalenessFilter() filter {
	return filter{
		name: FilterPolicyStaleness,
		eval: func(fctx filterContext, _ Request, c Candidate) (bool, int, string) {
			applied := c.Heartbeat.GetAppliedSeq()
			cur := fctx.currentPolicySeq
			if applied >= cur {
				return true, 0, ""
			}
			gap := cur - applied
			if gap > fctx.cfg.MaxStalenessGap {
				return false, 0, fmt.Sprintf(
					"host %s applied_seq %d trails current policy seq %d by %d (budget %d)",
					c.HostID, applied, cur, gap, fctx.cfg.MaxStalenessGap)
			}
			return true, 0, ""
		},
	}
}

// 2. baseline-version (doc 14 §11). The session's required host-baseline artifact
// version must be compatible with the host's reported version. Kernel-floor
// changes force host-image re-rolls; a session pinned to a new floor must not land
// on an old host. Compatibility is delegated to Config.BaselineCompatible (exact
// match by default) so a deployment can adopt range/semver semantics without
// touching the filter order.
func baselineVersionFilter() filter {
	return filter{
		name: FilterBaselineVersion,
		eval: func(fctx filterContext, req Request, c Candidate) (bool, int, string) {
			hostVer := c.Heartbeat.GetHostBaselineVersion()
			if fctx.cfg.BaselineCompatible(req.RequiredBaselineVersion, hostVer) {
				return true, 0, ""
			}
			return false, 0, fmt.Sprintf(
				"host %s baseline version %q incompatible with required %q",
				c.HostID, hostVer, req.RequiredBaselineVersion)
		},
	}
}

// 3. floors-fit (D37). Bin-packing: the session's cgroup-v2 FLOORS must fit within
// the host's reported allocatable headroom on every dimension (vCPU, memory, io).
// The heartbeat reports headroom AFTER current resident floors, so this is a
// single comparison per dimension — no preemption, no per-host resident tracking
// in the scheduler. A host with no reported capacity (nil) has zero headroom and
// fails any non-zero floor.
func floorsFitFilter() filter {
	return filter{
		name: FilterFloorsFit,
		eval: func(_ filterContext, req Request, c Candidate) (bool, int, string) {
			cap := c.Heartbeat.GetCapacity()
			f := req.Floors
			if f.Vcpu > cap.GetAllocatableVcpu() {
				return false, 0, fmt.Sprintf(
					"host %s vcpu floor %d exceeds allocatable %d",
					c.HostID, f.Vcpu, cap.GetAllocatableVcpu())
			}
			if f.MemoryBytes > cap.GetAllocatableMemoryBytes() {
				return false, 0, fmt.Sprintf(
					"host %s memory floor %d exceeds allocatable %d",
					c.HostID, f.MemoryBytes, cap.GetAllocatableMemoryBytes())
			}
			if f.IoBps > cap.GetAllocatableIoBps() {
				return false, 0, fmt.Sprintf(
					"host %s io floor %d exceeds allocatable %d",
					c.HostID, f.IoBps, cap.GetAllocatableIoBps())
			}
			return true, 0, ""
		},
	}
}

// 4. cache-locality (the M2 seconds-to-start lever). SOFT preference: a host that
// already has the session's preferred warm-image digest cached gets a positive
// score, which the winner-ordering prefers. This filter REJECTS NOTHING — it never
// empties the candidate set — so it can never be the Unschedulable reason; it only
// reorders survivors. An empty preference scores every host zero (no effect).
const cacheLocalityScore = 1

func cacheLocalityFilter() filter {
	return filter{
		name: FilterCacheLocality,
		eval: func(_ filterContext, req Request, c Candidate) (bool, int, string) {
			if req.PreferredImageCacheDigest != "" &&
				c.Heartbeat.GetImageCacheDigest() == req.PreferredImageCacheDigest {
				return true, cacheLocalityScore, ""
			}
			return true, 0, ""
		},
	}
}

// 5. density-ceiling (D66 measured uplink + D34 (d)-rig density knee). A host at or
// past the per-host stream knee is rejected to protect the measured-uplink ceiling:
// past the knee, added streams degrade everyone's throughput. The knee is a
// rig-tuned strawman (~75–100 streams/host) and metal-only per D34 — on non-metal
// pools the host-pool config sets MaxStreamsPerHost to zero, which DISABLES the
// filter (zero = no ceiling), never hardcodes a metal threshold onto a pool that
// cannot honor it.
func densityCeilingFilter() filter {
	return filter{
		name: FilterDensityCeiling,
		eval: func(fctx filterContext, _ Request, c Candidate) (bool, int, string) {
			limit := fctx.cfg.MaxStreamsPerHost
			if limit == 0 {
				return true, 0, "" // disabled (non-metal pool)
			}
			running := c.Heartbeat.GetCapacity().GetRunningSessions()
			if running >= limit {
				return false, 0, fmt.Sprintf(
					"host %s running %d sessions at/over density knee %d",
					c.HostID, running, limit)
			}
			return true, 0, ""
		},
	}
}
