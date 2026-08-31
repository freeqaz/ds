package scheduler

// Synthetic-fixture unit tests for the v0 scheduler (D50: no live VM/host-agent/
// podman — every host is a hand-built hostagent.v1 Heartbeat). Coverage:
//   - each of the five filters in ISOLATION (pass + its unschedulable reason);
//   - the FROZEN filter ORDER;
//   - the FULL chain (placement + every unschedulable path);
//   - bin-packing floors-fit with NO preemption;
//   - determinism (candidate order does not change the result);
//   - park/resume re-placement reusing the SAME path (Replace == Place).

import (
	"errors"
	"testing"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// ---- fixtures -------------------------------------------------------------

// hostOpt mutates a Heartbeat fixture.
type hostOpt func(*hostagentv1.Heartbeat)

func withAppliedSeq(seq uint64) hostOpt {
	return func(h *hostagentv1.Heartbeat) { h.AppliedSeq = seq }
}
func withBaseline(v string) hostOpt {
	return func(h *hostagentv1.Heartbeat) { h.HostBaselineVersion = v }
}
func withImageDigest(d string) hostOpt {
	return func(h *hostagentv1.Heartbeat) { h.ImageCacheDigest = d }
}
func withCapacity(vcpu uint32, mem, io uint64, running uint32) hostOpt {
	return func(h *hostagentv1.Heartbeat) {
		h.Capacity = &hostagentv1.HostCapacity{
			AllocatableVcpu:        vcpu,
			AllocatableMemoryBytes: mem,
			AllocatableIoBps:       io,
			RunningSessions:        running,
		}
	}
}
func withNilCapacity() hostOpt {
	return func(h *hostagentv1.Heartbeat) { h.Capacity = nil }
}

// host builds a Candidate with a roomy default capacity, current policy, and
// matching baseline, then applies opts. Defaults pass every filter so a test only
// has to perturb the one axis it exercises.
func host(id string, opts ...hostOpt) Candidate {
	hb := &hostagentv1.Heartbeat{
		HostId:              id,
		AppliedSeq:          10,
		HostBaselineVersion: "base-v1",
		Capacity: &hostagentv1.HostCapacity{
			AllocatableVcpu:        64,
			AllocatableMemoryBytes: 256 << 30,
			AllocatableIoBps:       1 << 30,
			RunningSessions:        1,
		},
	}
	for _, o := range opts {
		o(hb)
	}
	return Candidate{HostID: id, Heartbeat: hb}
}

// req builds a modest Request that fits the default host on every dimension.
func req(uuid string, opts ...func(*Request)) Request {
	r := Request{
		SessionUUID: uuid,
		Floors:      ResourceFloors{Vcpu: 4, MemoryBytes: 8 << 30, IoBps: 1 << 20},
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func defaultInput(cands ...Candidate) PlaceInput {
	return PlaceInput{Candidates: cands, CurrentPolicySeq: 10}
}

// ---- per-filter isolation -------------------------------------------------
//
// Each filter is exercised directly via fctx so a rejection is attributable to
// that filter alone, independent of chain ordering.

func TestFilter_PolicyStaleness(t *testing.T) {
	cfg := Config{MaxStalenessGap: 2}
	f := policyStalenessFilter()

	cases := []struct {
		name     string
		applied  uint64
		current  uint64
		wantKeep bool
	}{
		{"current", 10, 10, true},
		{"within budget", 9, 10, true},
		{"at budget edge", 8, 10, true},
		{"over budget", 7, 10, false},
		{"ahead of reference", 12, 10, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fctx := filterContext{cfg: cfg, currentPolicySeq: tc.current}
			keep, _, reject := f.eval(fctx, req("s"), host("h", withAppliedSeq(tc.applied)))
			if keep != tc.wantKeep {
				t.Fatalf("keep=%v want %v (reject=%q)", keep, tc.wantKeep, reject)
			}
			if !keep && reject == "" {
				t.Fatal("rejection must carry a concrete reason")
			}
		})
	}
}

func TestFilter_BaselineVersion(t *testing.T) {
	cfg := DefaultConfig() // exact-match
	f := baselineVersionFilter()

	t.Run("match passes", func(t *testing.T) {
		fctx := filterContext{cfg: cfg}
		r := req("s", func(r *Request) { r.RequiredBaselineVersion = "base-v2" })
		keep, _, _ := f.eval(fctx, r, host("h", withBaseline("base-v2")))
		if !keep {
			t.Fatal("matching baseline must pass")
		}
	})
	t.Run("mismatch rejects with reason", func(t *testing.T) {
		fctx := filterContext{cfg: cfg}
		r := req("s", func(r *Request) { r.RequiredBaselineVersion = "base-v2" })
		keep, _, reject := f.eval(fctx, r, host("h", withBaseline("base-v1")))
		if keep || reject == "" {
			t.Fatalf("mismatch must reject with reason; keep=%v reject=%q", keep, reject)
		}
	})
	t.Run("empty requirement accepts any host", func(t *testing.T) {
		fctx := filterContext{cfg: cfg}
		keep, _, _ := f.eval(fctx, req("s"), host("h", withBaseline("anything")))
		if !keep {
			t.Fatal("empty required version must accept any host")
		}
	})
	t.Run("injected compatibility policy is honored", func(t *testing.T) {
		// A range policy that accepts base-v1 and base-v2 for a base-v2 ask.
		cfg2 := Config{BaselineCompatible: func(required, hostReported string) bool {
			return hostReported == "base-v1" || hostReported == "base-v2"
		}}
		fctx := filterContext{cfg: cfg2}
		r := req("s", func(r *Request) { r.RequiredBaselineVersion = "base-v2" })
		keep, _, _ := f.eval(fctx, r, host("h", withBaseline("base-v1")))
		if !keep {
			t.Fatal("injected compatibility policy must be honored")
		}
	})
}

func TestFilter_FloorsFit(t *testing.T) {
	f := floorsFitFilter()
	fctx := filterContext{}

	t.Run("fits", func(t *testing.T) {
		keep, _, _ := f.eval(fctx, req("s"), host("h", withCapacity(8, 16<<30, 1<<20, 0)))
		if !keep {
			t.Fatal("a request within allocatable must fit")
		}
	})
	t.Run("vcpu floor over allocatable rejects", func(t *testing.T) {
		r := req("s", func(r *Request) { r.Floors.Vcpu = 16 })
		keep, _, reject := f.eval(fctx, r, host("h", withCapacity(8, 256<<30, 1<<30, 0)))
		if keep || reject == "" {
			t.Fatalf("vcpu overflow must reject; keep=%v reject=%q", keep, reject)
		}
	})
	t.Run("memory floor over allocatable rejects", func(t *testing.T) {
		r := req("s", func(r *Request) { r.Floors.MemoryBytes = 512 << 30 })
		keep, _, reject := f.eval(fctx, r, host("h", withCapacity(64, 256<<30, 1<<30, 0)))
		if keep || reject == "" {
			t.Fatalf("memory overflow must reject; keep=%v reject=%q", keep, reject)
		}
	})
	t.Run("io floor over allocatable rejects", func(t *testing.T) {
		r := req("s", func(r *Request) { r.Floors.IoBps = 2 << 30 })
		keep, _, reject := f.eval(fctx, r, host("h", withCapacity(64, 256<<30, 1<<30, 0)))
		if keep || reject == "" {
			t.Fatalf("io overflow must reject; keep=%v reject=%q", keep, reject)
		}
	})
	t.Run("nil capacity rejects any non-zero floor", func(t *testing.T) {
		keep, _, reject := f.eval(fctx, req("s"), host("h", withNilCapacity()))
		if keep || reject == "" {
			t.Fatalf("nil capacity must reject; keep=%v reject=%q", keep, reject)
		}
	})
	t.Run("zero floors fit a nil-capacity host", func(t *testing.T) {
		r := req("s", func(r *Request) { r.Floors = ResourceFloors{} })
		keep, _, _ := f.eval(fctx, r, host("h", withNilCapacity()))
		if !keep {
			t.Fatal("a burst-only (zero-floor) session fits any host on floors-fit")
		}
	})
}

func TestFilter_CacheLocality(t *testing.T) {
	f := cacheLocalityFilter()
	fctx := filterContext{}

	t.Run("hit scores and keeps", func(t *testing.T) {
		r := req("s", func(r *Request) { r.PreferredImageCacheDigest = "sha256:warm" })
		keep, score, _ := f.eval(fctx, r, host("h", withImageDigest("sha256:warm")))
		if !keep || score <= 0 {
			t.Fatalf("cache hit must keep with positive score; keep=%v score=%d", keep, score)
		}
	})
	t.Run("miss keeps with zero score (never rejects)", func(t *testing.T) {
		r := req("s", func(r *Request) { r.PreferredImageCacheDigest = "sha256:warm" })
		keep, score, _ := f.eval(fctx, r, host("h", withImageDigest("sha256:cold")))
		if !keep || score != 0 {
			t.Fatalf("cache miss must keep with zero score; keep=%v score=%d", keep, score)
		}
	})
	t.Run("no preference keeps with zero score", func(t *testing.T) {
		keep, score, _ := f.eval(fctx, req("s"), host("h", withImageDigest("anything")))
		if !keep || score != 0 {
			t.Fatalf("no preference must keep with zero score; keep=%v score=%d", keep, score)
		}
	})
}

func TestFilter_DensityCeiling(t *testing.T) {
	f := densityCeilingFilter()

	t.Run("under knee passes", func(t *testing.T) {
		fctx := filterContext{cfg: Config{MaxStreamsPerHost: 75}}
		keep, _, _ := f.eval(fctx, req("s"), host("h", withCapacity(64, 256<<30, 1<<30, 74)))
		if !keep {
			t.Fatal("under the density knee must pass")
		}
	})
	t.Run("at knee rejects with reason", func(t *testing.T) {
		fctx := filterContext{cfg: Config{MaxStreamsPerHost: 75}}
		keep, _, reject := f.eval(fctx, req("s"), host("h", withCapacity(64, 256<<30, 1<<30, 75)))
		if keep || reject == "" {
			t.Fatalf("at the knee must reject with reason; keep=%v reject=%q", keep, reject)
		}
	})
	t.Run("disabled on non-metal pool (zero limit)", func(t *testing.T) {
		fctx := filterContext{cfg: Config{MaxStreamsPerHost: 0}}
		keep, _, _ := f.eval(fctx, req("s"), host("h", withCapacity(64, 256<<30, 1<<30, 9999)))
		if !keep {
			t.Fatal("a zero limit disables the density filter (non-metal pool)")
		}
	})
}

// ---- frozen filter order --------------------------------------------------

func TestFilterOrderIsFrozen(t *testing.T) {
	want := []string{
		FilterPolicyStaleness,
		FilterBaselineVersion,
		FilterFloorsFit,
		FilterCacheLocality,
		FilterDensityCeiling,
	}
	got := New(DefaultConfig()).FilterOrder()
	if len(got) != len(want) {
		t.Fatalf("filter count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("filter[%d] = %q, want %q (order is FROZEN, doc 15 §7)", i, got[i], want[i])
		}
	}
}

// ---- full chain: placement ------------------------------------------------

func TestPlace_HappyPath(t *testing.T) {
	s := New(DefaultConfig())
	in := defaultInput(host("h1"), host("h2"))
	p, err := s.Place(in, req("sess-1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.SessionUUID != "sess-1" {
		t.Fatalf("placement uuid = %q, want sess-1", p.SessionUUID)
	}
	if p.HostID != "h1" && p.HostID != "h2" {
		t.Fatalf("placement host = %q, want one of the candidates", p.HostID)
	}
}

func TestPlace_CacheLocalityWins(t *testing.T) {
	s := New(DefaultConfig())
	// Both hosts fit; only h2 has the warm digest. Cache preference must steer the
	// winner to h2 even though h1 is listed first.
	in := defaultInput(
		host("h1", withImageDigest("cold")),
		host("h2", withImageDigest("sha256:warm")),
	)
	r := req("sess-1", func(r *Request) { r.PreferredImageCacheDigest = "sha256:warm" })
	p, err := s.Place(in, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.HostID != "h2" {
		t.Fatalf("cache-locality must steer to h2, got %q", p.HostID)
	}
	if !p.CachePreferred {
		t.Fatal("placement should report CachePreferred on a cache hit")
	}
}

func TestPlace_SpreadTiebreakPrefersFewerSessions(t *testing.T) {
	s := New(DefaultConfig())
	// No cache preference; both fit; h2 runs fewer sessions → bin-packing spread
	// prefers it. h1 is listed first to prove order-independence of the tiebreak.
	in := defaultInput(
		host("h1", withCapacity(64, 256<<30, 1<<30, 30)),
		host("h2", withCapacity(64, 256<<30, 1<<30, 5)),
	)
	p, err := s.Place(in, req("sess-1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.HostID != "h2" {
		t.Fatalf("spread tiebreak must pick the less-loaded host h2, got %q", p.HostID)
	}
}

// ---- full chain: every unschedulable path ---------------------------------

func TestPlace_Unschedulable_NoCandidates(t *testing.T) {
	s := New(DefaultConfig())
	_, err := s.Place(PlaceInput{CurrentPolicySeq: 10}, req("sess-1"))
	assertUnschedulable(t, err, FilterNoCandidates)
}

func TestPlace_Unschedulable_PolicyStaleness(t *testing.T) {
	s := New(DefaultConfig()) // MaxStalenessGap 0 → must be exactly current
	in := PlaceInput{
		Candidates:       []Candidate{host("h1", withAppliedSeq(8)), host("h2", withAppliedSeq(9))},
		CurrentPolicySeq: 10,
	}
	assertUnschedulable(t, mustErr(s.Place(in, req("sess-1"))), FilterPolicyStaleness)
}

func TestPlace_Unschedulable_Baseline(t *testing.T) {
	s := New(DefaultConfig())
	in := defaultInput(host("h1", withBaseline("base-v1")), host("h2", withBaseline("base-v1")))
	r := req("sess-1", func(r *Request) { r.RequiredBaselineVersion = "base-v9" })
	assertUnschedulable(t, mustErr(s.Place(in, r)), FilterBaselineVersion)
}

func TestPlace_Unschedulable_FloorsFit(t *testing.T) {
	s := New(DefaultConfig())
	in := defaultInput(
		host("h1", withCapacity(2, 4<<30, 1<<20, 0)),
		host("h2", withCapacity(2, 4<<30, 1<<20, 0)),
	)
	r := req("sess-1", func(r *Request) { r.Floors = ResourceFloors{Vcpu: 32, MemoryBytes: 64 << 30} })
	assertUnschedulable(t, mustErr(s.Place(in, r)), FilterFloorsFit)
}

func TestPlace_Unschedulable_Density(t *testing.T) {
	s := New(DefaultConfig()) // knee at 75
	in := defaultInput(
		host("h1", withCapacity(64, 256<<30, 1<<30, 80)),
		host("h2", withCapacity(64, 256<<30, 1<<30, 100)),
	)
	assertUnschedulable(t, mustErr(s.Place(in, req("sess-1"))), FilterDensityCeiling)
}

func TestPlace_CacheLocalityNeverRejects(t *testing.T) {
	// Even when NO host has the preferred digest, the soft filter must not empty
	// the set — placement succeeds (the preference simply has no effect).
	s := New(DefaultConfig())
	in := defaultInput(host("h1", withImageDigest("cold-a")), host("h2", withImageDigest("cold-b")))
	r := req("sess-1", func(r *Request) { r.PreferredImageCacheDigest = "sha256:warm" })
	p, err := s.Place(in, r)
	if err != nil {
		t.Fatalf("cache-locality must never reject; got %v", err)
	}
	if p.CachePreferred {
		t.Fatal("no host had the warm digest; CachePreferred must be false")
	}
}

func TestPlace_InvalidRequest(t *testing.T) {
	s := New(DefaultConfig())
	_, err := s.Place(defaultInput(host("h1")), Request{SessionUUID: ""})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty SessionUUID must be ErrInvalidRequest, got %v", err)
	}
	if _, ok := AsUnschedulable(err); ok {
		t.Fatal("an invalid request must NOT be reported as Unschedulable")
	}
}

// ---- bin-packing: floors-fit with no preemption ---------------------------

func TestPlace_NoPreemption_TightHostStillFitsIfRoom(t *testing.T) {
	// A heavily-loaded host with just enough remaining allocatable headroom still
	// accepts a fitting session WITHOUT evicting anything — the scheduler reads the
	// reported headroom and packs; it never preempts (rebalancing is M3).
	s := New(DefaultConfig())
	in := defaultInput(host("h1", withCapacity(4, 8<<30, 2<<20, 60))) // headroom-after-floors
	r := req("sess-1", func(r *Request) {
		r.Floors = ResourceFloors{Vcpu: 4, MemoryBytes: 8 << 30, IoBps: 2 << 20} // exactly fits
	})
	p, err := s.Place(in, r)
	if err != nil {
		t.Fatalf("a session that exactly fits the reported headroom must place: %v", err)
	}
	if p.HostID != "h1" {
		t.Fatalf("host = %q, want h1", p.HostID)
	}
}

func TestPlace_NoPreemption_OverflowRejectsRatherThanEvicts(t *testing.T) {
	// One candidate, no headroom for the floors. Correct v0 behavior is to report
	// Unschedulable (the caller queues/retries), NOT to evict a resident session.
	s := New(DefaultConfig())
	in := defaultInput(host("h1", withCapacity(1, 1<<30, 1<<20, 70)))
	r := req("sess-1", func(r *Request) { r.Floors = ResourceFloors{Vcpu: 8} })
	assertUnschedulable(t, mustErr(s.Place(in, r)), FilterFloorsFit)
}

// ---- determinism ----------------------------------------------------------

func TestPlace_DeterministicAcrossCandidateOrder(t *testing.T) {
	s := New(DefaultConfig())
	r := req("sess-1")
	a := []Candidate{
		host("h1", withCapacity(64, 256<<30, 1<<30, 10)),
		host("h2", withCapacity(64, 256<<30, 1<<30, 3)),
		host("h3", withCapacity(64, 256<<30, 1<<30, 7)),
	}
	b := []Candidate{a[2], a[0], a[1]} // shuffled

	pa, errA := s.Place(PlaceInput{Candidates: a, CurrentPolicySeq: 10}, r)
	pb, errB := s.Place(PlaceInput{Candidates: b, CurrentPolicySeq: 10}, r)
	if errA != nil || errB != nil {
		t.Fatalf("unexpected errors: %v / %v", errA, errB)
	}
	if pa.HostID != pb.HostID {
		t.Fatalf("candidate order changed the result: %q vs %q", pa.HostID, pb.HostID)
	}
	if pa.HostID != "h2" {
		t.Fatalf("expected least-loaded h2 regardless of order, got %q", pa.HostID)
	}
}

func TestPlace_DeterministicTiebreakOnHostID(t *testing.T) {
	// Identical capacity/load on every axis → the lexicographic HostID tiebreak
	// must decide, deterministically, and never depend on input order.
	s := New(DefaultConfig())
	r := req("sess-1")
	cands := []Candidate{host("hC"), host("hA"), host("hB")}
	p, err := s.Place(PlaceInput{Candidates: cands, CurrentPolicySeq: 10}, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.HostID != "hA" {
		t.Fatalf("tiebreak must pick lexicographically smallest hA, got %q", p.HostID)
	}
}

// ---- park/resume re-placement reuses the same path ------------------------

func TestReplace_IsSamePathAsPlace(t *testing.T) {
	s := New(DefaultConfig())
	in := defaultInput(
		host("h1", withCapacity(64, 256<<30, 1<<30, 9)),
		host("h2", withCapacity(64, 256<<30, 1<<30, 2)),
	)
	r := req("sess-1")
	place, errP := s.Place(in, r)
	replace, errR := s.Replace(in, r)
	if errP != nil || errR != nil {
		t.Fatalf("unexpected errors: %v / %v", errP, errR)
	}
	if *place != *replace {
		t.Fatalf("Replace must be byte-identical to Place: %+v vs %+v", place, replace)
	}
}

func TestReplace_ParkResumeOntoDifferentHost(t *testing.T) {
	// A parked session resumes against a candidate set where its original host is
	// gone (drained); re-placement is the same Place call and lands it on a NEW
	// host, carrying the SAME SessionUUID (the continuity key, doc 15 §7).
	s := New(DefaultConfig())
	sess := "sess-parked-1"

	// Original placement onto h1.
	orig := defaultInput(host("h1", withCapacity(64, 256<<30, 1<<30, 1)))
	p1, err := s.Place(orig, req(sess))
	if err != nil {
		t.Fatalf("original placement failed: %v", err)
	}
	if p1.HostID != "h1" {
		t.Fatalf("original host = %q, want h1", p1.HostID)
	}

	// Resume: h1 is drained out of the pool; only h2 remains.
	resume := defaultInput(host("h2", withCapacity(64, 256<<30, 1<<30, 4)))
	p2, err := s.Replace(resume, req(sess))
	if err != nil {
		t.Fatalf("re-placement failed: %v", err)
	}
	if p2.HostID != "h2" {
		t.Fatalf("re-placement host = %q, want the new host h2", p2.HostID)
	}
	if p2.SessionUUID != sess {
		t.Fatalf("re-placement must carry the SAME session continuity key %q, got %q", sess, p2.SessionUUID)
	}
}

func TestReplace_Unschedulable_NamesFilter(t *testing.T) {
	// Re-placement that cannot fit anywhere surfaces the SAME structured
	// Unschedulable (filter-named) as a first placement would — the resume path is
	// not a special case.
	s := New(DefaultConfig())
	resume := defaultInput(host("h2", withCapacity(1, 1<<30, 1<<20, 0)))
	r := req("sess-1", func(r *Request) { r.Floors = ResourceFloors{Vcpu: 64} })
	assertUnschedulable(t, mustErr(s.Replace(resume, r)), FilterFloorsFit)
}

// ---- helpers --------------------------------------------------------------

func mustErr(_ *Placement, err error) error { return err }

func assertUnschedulable(t *testing.T, err error, wantFilter string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an unschedulable error, got nil")
	}
	u, ok := AsUnschedulable(err)
	if !ok {
		t.Fatalf("error is not *Unschedulable: %v", err)
	}
	if u.Filter != wantFilter {
		t.Fatalf("rejected by filter %q, want %q (detail: %s)", u.Filter, wantFilter, u.Detail)
	}
	if wantFilter != FilterNoCandidates && u.Detail == "" {
		t.Fatal("a filter rejection must carry a concrete Detail")
	}
}
