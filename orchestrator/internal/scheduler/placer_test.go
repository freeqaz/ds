package scheduler

// Synthetic-fixture tests for the production Placer adapter (orch18, D50: no live
// VM/host-agent/heartbeat — every candidate is a hand-built hostagent.v1 Heartbeat).
// Coverage:
//   - the adapter satisfies the CURRENT sessions-side Placer (compile-time, asserted
//     in placer.go via `var _ sessions.Placer = (*Adapter)(nil)`; behaviorally here);
//   - a successful placement maps to sessions.Placement{HostID, AppliedSeq} with
//     AppliedSeq read from the WINNING host's heartbeat;
//   - a policy-staleness rejection maps to sessions.ErrPolicyStale (D72);
//   - any other shortage (no candidates / floors-fit) maps to ErrNoPlaceableHost;
//   - a nil dependency surfaces ErrPlacerMisconfigured, never a panic;
//   - the PlacementRequest → Request translation carries floors + cache preference;
//   - the StoreCandidateSource bridge wires the store assembler to the §7 chain end
//     to end (latest-per-host + tenancy scope), reusing the orch17 filters.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// --- fakes -----------------------------------------------------------------

// fakeCandidates returns a fixed candidate set (or error).
type fakeCandidates struct {
	cands []Candidate
	err   error
}

func (f fakeCandidates) Candidates(context.Context, string) ([]Candidate, error) {
	return f.cands, f.err
}

// fakeSeq returns a fixed current policy seq (or error).
type fakeSeq struct {
	seq uint64
	err error
}

func (f fakeSeq) CurrentPolicySeq(context.Context) (uint64, error) { return f.seq, f.err }

// cand builds a roomy candidate at a given applied_seq (passes every filter by
// default unless the test perturbs the request or the policy seq).
func cand(id string, appliedSeq uint64) Candidate {
	return Candidate{
		HostID: id,
		Heartbeat: &hostagentv1.Heartbeat{
			HostId:              id,
			AppliedSeq:          appliedSeq,
			HostBaselineVersion: "base-v1",
			Capacity:            &hostagentv1.HostCapacity{AllocatableVcpu: 64, AllocatableMemoryBytes: 1 << 40, AllocatableIoBps: 1 << 30, RunningSessions: 1},
		},
	}
}

func newAdapter(cands []Candidate, seq uint64) *Adapter {
	return NewAdapter(New(DefaultConfig()), fakeCandidates{cands: cands}, fakeSeq{seq: seq})
}

// --- tests -----------------------------------------------------------------

// TestAdapter_SatisfiesSessionsPlacer is the behavioral mirror of the compile-time
// `var _ sessions.Placer = (*Adapter)(nil)` in placer.go: the adapter is usable
// wherever the create choreography wants a Placer.
func TestAdapter_SatisfiesSessionsPlacer(t *testing.T) {
	var p sessions.Placer = newAdapter([]Candidate{cand("host-a", 10)}, 10)
	if p == nil {
		t.Fatal("adapter is not assignable to sessions.Placer")
	}
}

// TestAdapter_Place_Success_MapsHostAndAppliedSeq proves a successful placement maps
// to sessions.Placement with the chosen host AND that host's heartbeat applied_seq
// (the D72 version recorded for the §4.1 step-9 re-check).
func TestAdapter_Place_Success_MapsHostAndAppliedSeq(t *testing.T) {
	ctx := context.Background()
	// Two hosts; host-b is fresher-loaded but both pass. The deterministic tiebreak
	// (fewer running, then lower host id) picks host-a; its applied_seq is 12.
	a := newAdapter([]Candidate{cand("host-a", 12), cand("host-b", 11)}, 10)

	got, err := a.Place(ctx, "sess-1", sessions.PlacementRequest{ImageID: "img-1"})
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	if got.HostID != "host-a" {
		t.Errorf("HostID = %q, want host-a (deterministic tiebreak)", got.HostID)
	}
	if got.AppliedSeq != 12 {
		t.Errorf("AppliedSeq = %d, want 12 (winning host's heartbeat applied_seq)", got.AppliedSeq)
	}
}

// TestAdapter_Place_StalenessMapsToErrPolicyStale proves a placement that the §7
// policy-staleness filter empties maps to sessions.ErrPolicyStale (the D72 "no fresh
// host" refusal the coordinator branches on at step 3 / re-checks at step 9), not the
// generic shortage error.
func TestAdapter_Place_StalenessMapsToErrPolicyStale(t *testing.T) {
	ctx := context.Background()
	// Current seq 50; both candidates are far behind (applied 1) and the default
	// staleness budget is 0 — every host is rejected by policy-staleness.
	a := newAdapter([]Candidate{cand("host-a", 1), cand("host-b", 1)}, 50)

	_, err := a.Place(ctx, "sess-stale", sessions.PlacementRequest{})
	if !errors.Is(err, sessions.ErrPolicyStale) {
		t.Fatalf("staleness rejection must map to sessions.ErrPolicyStale, got %v", err)
	}
	if errors.Is(err, ErrNoPlaceableHost) {
		t.Error("a staleness rejection must NOT be ErrNoPlaceableHost (D72 is its own outcome)")
	}
}

// TestAdapter_Place_FloorsShortageMapsToNoPlaceableHost proves a non-staleness
// shortage (floors-fit: the session's floor exceeds every host's headroom) maps to
// ErrNoPlaceableHost, distinct from ErrPolicyStale.
func TestAdapter_Place_FloorsShortageMapsToNoPlaceableHost(t *testing.T) {
	ctx := context.Background()
	a := newAdapter([]Candidate{cand("host-a", 10)}, 10)

	// A 1000-vCPU floor fits no host (each reports 64 allocatable).
	_, err := a.Place(ctx, "sess-big", sessions.PlacementRequest{
		Floors: &hypervisorv1.ResourceFloors{VcpuFloor: 1000},
	})
	if !errors.Is(err, ErrNoPlaceableHost) {
		t.Fatalf("floors shortage must map to ErrNoPlaceableHost, got %v", err)
	}
	if errors.Is(err, sessions.ErrPolicyStale) {
		t.Error("a capacity shortage must NOT be ErrPolicyStale")
	}
}

// TestAdapter_Place_NoCandidatesMapsToNoPlaceableHost proves an empty candidate set
// (the pool had no host) is a placeable-host shortage, not a staleness refusal.
func TestAdapter_Place_NoCandidatesMapsToNoPlaceableHost(t *testing.T) {
	ctx := context.Background()
	a := newAdapter(nil, 10)

	_, err := a.Place(ctx, "sess-empty", sessions.PlacementRequest{})
	if !errors.Is(err, ErrNoPlaceableHost) {
		t.Fatalf("empty candidate set must map to ErrNoPlaceableHost, got %v", err)
	}
}

// TestAdapter_Place_Misconfigured proves a nil dependency surfaces
// ErrPlacerMisconfigured rather than panicking.
func TestAdapter_Place_Misconfigured(t *testing.T) {
	ctx := context.Background()
	cases := map[string]*Adapter{
		"nil scheduler":  NewAdapter(nil, fakeCandidates{}, fakeSeq{}),
		"nil candidates": NewAdapter(New(DefaultConfig()), nil, fakeSeq{}),
		"nil policySeq":  NewAdapter(New(DefaultConfig()), fakeCandidates{}, nil),
		"nil adapter":    (*Adapter)(nil),
	}
	for name, a := range cases {
		if _, err := a.Place(ctx, "sess", sessions.PlacementRequest{}); !errors.Is(err, ErrPlacerMisconfigured) {
			t.Errorf("%s: want ErrPlacerMisconfigured, got %v", name, err)
		}
	}
}

// TestAdapter_Place_PropagatesSourceErrors proves candidate-source and policy-seq-
// source errors surface (wrapped), not swallowed as a shortage.
func TestAdapter_Place_PropagatesSourceErrors(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")

	a := NewAdapter(New(DefaultConfig()), fakeCandidates{err: boom}, fakeSeq{seq: 10})
	if _, err := a.Place(ctx, "s", sessions.PlacementRequest{}); !errors.Is(err, boom) {
		t.Errorf("candidate-source error must propagate, got %v", err)
	}

	a = NewAdapter(New(DefaultConfig()), fakeCandidates{cands: []Candidate{cand("h", 10)}}, fakeSeq{err: boom})
	if _, err := a.Place(ctx, "s", sessions.PlacementRequest{}); !errors.Is(err, boom) {
		t.Errorf("policy-seq error must propagate, got %v", err)
	}
}

// TestRequestFromPlacement_CarriesFloorsAndCachePreference proves the PlacementRequest
// → Request translation: the proto cgroup-v2 floors map onto the three floors-fit
// dimensions (vcpu_floor/memory_low_bytes/io_max_bps), the image id becomes the §7
// cache-locality preference, and a nil Floors is safe (zero floors).
func TestRequestFromPlacement_CarriesFloorsAndCachePreference(t *testing.T) {
	req := requestFromPlacement("sess-x", sessions.PlacementRequest{
		ImageID: "img-warm",
		Floors:  &hypervisorv1.ResourceFloors{VcpuFloor: 4, MemoryLowBytes: 8 << 30, IoMaxBps: 500 << 20},
	})
	if req.SessionUUID != "sess-x" {
		t.Errorf("SessionUUID = %q, want sess-x", req.SessionUUID)
	}
	if req.Floors.Vcpu != 4 || req.Floors.MemoryBytes != 8<<30 || req.Floors.IoBps != 500<<20 {
		t.Errorf("floors = %+v, want {4, 8GiB, 500MiB/s}", req.Floors)
	}
	if req.PreferredImageCacheDigest != "img-warm" {
		t.Errorf("cache preference = %q, want img-warm (the image id)", req.PreferredImageCacheDigest)
	}

	// Nil Floors → zero floors (a burst-only session), no panic.
	req = requestFromPlacement("sess-y", sessions.PlacementRequest{})
	if req.Floors != (ResourceFloors{}) {
		t.Errorf("nil Floors must yield zero floors, got %+v", req.Floors)
	}
}

// --- CurrentFreshness (§4.1 step-9 live re-check, D72) ---------------------

// fakeFreshness scripts the host-keyed live applied_seq probe.
type fakeFreshness struct {
	seq    uint64
	ok     bool
	err    error
	gotHID string
}

func (f *fakeFreshness) CurrentAppliedSeq(_ context.Context, hostID string) (uint64, bool, error) {
	f.gotHID = hostID
	return f.seq, f.ok, f.err
}

// TestAdapter_CurrentFreshness_NilSeamIsUnknown proves an adapter with no wired
// HostFreshness seam (the placement-only wiring) reports sessions.ErrFreshnessUnknown
// — the coordinator degrades to the recorded re-check, so the create path is unchanged.
func TestAdapter_CurrentFreshness_NilSeamIsUnknown(t *testing.T) {
	ctx := context.Background()
	a := newAdapter([]Candidate{cand("host-a", 10)}, 10) // Freshness left nil
	if _, err := a.CurrentFreshness(ctx, "host-a"); !errors.Is(err, sessions.ErrFreshnessUnknown) {
		t.Fatalf("nil Freshness seam must report ErrFreshnessUnknown, got %v", err)
	}
}

// TestAdapter_CurrentFreshness_ReportsLiveSeq proves a wired HostFreshness seam returns
// the host's CURRENT applied_seq (the live value the §4.1 step-9 re-check re-validates),
// keyed on the placed host.
func TestAdapter_CurrentFreshness_ReportsLiveSeq(t *testing.T) {
	ctx := context.Background()
	a := newAdapter([]Candidate{cand("host-a", 10)}, 10)
	a.Freshness = &fakeFreshness{seq: 42, ok: true}

	got, err := a.CurrentFreshness(ctx, "host-a")
	if err != nil {
		t.Fatalf("CurrentFreshness: %v", err)
	}
	if got != 42 {
		t.Errorf("current applied_seq = %d, want 42 (live heartbeat value)", got)
	}
}

// TestAdapter_CurrentFreshness_AbsentHostIsUnknown proves a wired probe that has no
// current heartbeat for the host reports ErrFreshnessUnknown (host-named): the gate
// degrades rather than hard-failing a create the recorded re-check vouches for.
func TestAdapter_CurrentFreshness_AbsentHostIsUnknown(t *testing.T) {
	ctx := context.Background()
	a := newAdapter([]Candidate{cand("host-a", 10)}, 10)
	a.Freshness = &fakeFreshness{ok: false} // host absent from the live feed

	if _, err := a.CurrentFreshness(ctx, "host-gone"); !errors.Is(err, sessions.ErrFreshnessUnknown) {
		t.Fatalf("an absent host must report ErrFreshnessUnknown, got %v", err)
	}
}

// TestAdapter_CurrentFreshness_AbsentHostPinsUnknownContract is the CONTRACT PIN (D72)
// for the orch21 step-9 degrade: recheckFreshness branches on
// errors.Is(err, sessions.ErrFreshnessUnknown) to take the OBSERVABLE DEGRADE path
// (return nil → recorded re-check) instead of the hard-fail `return err`. That branch
// is load-bearing ONLY because a host absent from the live feed surfaces an error that
// WRAPS the sentinel — a bare/generic error here would route the coordinator down the
// hard-fail path and refuse a create the recorded re-check still vouches for. This test
// LOCKS that guarantee with the three properties the degrade depends on:
//
//	(1) the absent-host error satisfies errors.Is(err, sessions.ErrFreshnessUnknown)
//	    (so recheckFreshness takes the degrade, not the hard-fail, branch);
//	(2) it is NOT a bare/generic error — it is distinguishable from an arbitrary
//	    sentinel, i.e. ONLY the freshness sentinel matches, nothing leaks through;
//	(3) it is host-named — the placed host id is carried in the cause so the degrade
//	    the coordinator emits (a log/metric) names the unprobeable host, never silent.
//
// It exercises the host-absent branch specifically (ok=false, no probe error), keeping
// the normal fresh/stale paths (TestAdapter_CurrentFreshness_ReportsLiveSeq) untouched.
func TestAdapter_CurrentFreshness_AbsentHostPinsUnknownContract(t *testing.T) {
	ctx := context.Background()
	a := newAdapter([]Candidate{cand("host-a", 10)}, 10)
	a.Freshness = &fakeFreshness{ok: false} // wired probe, host absent from the live feed

	_, err := a.CurrentFreshness(ctx, "host-vanished")
	if err == nil {
		t.Fatal("a host absent from the live feed must error, got nil")
	}

	// (1) The error WRAPS the degrade sentinel — the precondition recheckFreshness's
	// errors.Is gate keys on to take the degrade path rather than hard-failing.
	if !errors.Is(err, sessions.ErrFreshnessUnknown) {
		t.Fatalf("absent host must wrap sessions.ErrFreshnessUnknown (degrade precondition), got %v", err)
	}

	// (2) It is NOT a bare/generic error: only the freshness sentinel matches, so the
	// host-absent outcome can never be confused with another wrapped error class (a
	// generic error would mis-route the coordinator to the hard-fail branch).
	other := errors.New("some other error")
	if errors.Is(err, other) {
		t.Error("absent-host error must NOT match an unrelated sentinel (it is the freshness-unknown contract, not a bare error)")
	}

	// (3) The cause is host-named so the emitted degrade can identify the unprobeable
	// host (observable, never silent) — the host id flows into the wrapped message.
	if !strings.Contains(err.Error(), "host-vanished") {
		t.Errorf("absent-host error must name the host, got %q", err.Error())
	}
}

// TestAdapter_CurrentFreshness_PropagatesProbeError proves a probe seam fault surfaces
// wrapped (not silently swallowed as a fresh host).
func TestAdapter_CurrentFreshness_PropagatesProbeError(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("feed boom")
	a := newAdapter([]Candidate{cand("host-a", 10)}, 10)
	a.Freshness = &fakeFreshness{err: boom}

	if _, err := a.CurrentFreshness(ctx, "host-a"); !errors.Is(err, boom) {
		t.Fatalf("probe error must propagate, got %v", err)
	}
}

// TestAdapter_CurrentFreshness_FaultVsAbsentSymmetry is the FAULT-vs-ABSENT symmetry
// pin (D72): the §4.1 step-9 freshness contract has TWO distinct outcomes that the
// sessions recheckFreshness branches apart on errors.Is(err, sessions.ErrFreshnessUnknown)
// — a host ABSENT from the live feed (a clean "no current report") DEGRADES to the
// recorded re-check, while a probe FAULT (a transport/feed ERROR — the freshness of
// the host could NOT be determined) HARD-FAILS the create. The degrade is keyed
// EXCLUSIVELY on the ErrFreshnessUnknown sentinel, so the two outcomes MUST carry
// distinguishable error identities: an absent host wraps the sentinel (→ degrade), a
// fault must NOT be errors.Is(ErrFreshnessUnknown) (→ the recheckFreshness `return err`
// hard-fail), or a fault whose freshness is genuinely unknown-due-to-error would be
// silently waved through the same degrade an absent host gets — admitting a create on a
// host whose freshness could not be probed at all. orch21/orch22/orch25 pinned each
// outcome alone (absent wraps the sentinel; the fault propagates wrapped); this LOCKS
// the ASYMMETRY between them, side by side, against a regression that collapsed a fault
// into the absent-degrade path (e.g. by wrapping the sentinel on the error branch).
//
// It drives the REAL production scheduler.Adapter.CurrentFreshness on both outcomes via
// the wired HostFreshness fake (D50 synthetic fixtures, no live feed):
//
//	FAULT  (err != nil): the produced error is NOT errors.Is(ErrFreshnessUnknown) — so
//	                     the sessions step-9 degrade branch does NOT key on it and the
//	                     coordinator hard-fails — AND the fault is surfaced (wrapped) for
//	                     the caller (errors.Is(producedErr, fault)).
//	ABSENT (ok == false): the produced error IS errors.Is(ErrFreshnessUnknown) — so the
//	                     coordinator degrades to the recorded re-check.
func TestAdapter_CurrentFreshness_FaultVsAbsentSymmetry(t *testing.T) {
	ctx := context.Background()

	// FAULT: the live probe ERRORS (transport/feed fault — freshness undeterminable).
	fault := errors.New("freshness feed transport fault")
	aFault := newAdapter([]Candidate{cand("host-a", 10)}, 10)
	aFault.Freshness = &fakeFreshness{err: fault}

	_, faultErr := aFault.CurrentFreshness(ctx, "host-faulted")
	if faultErr == nil {
		t.Fatal("a probe FAULT must produce an error, got nil")
	}
	// The fault must NOT wrap the degrade sentinel: otherwise the sessions step-9 branch
	// (errors.Is(err, ErrFreshnessUnknown) → return nil) would silently DEGRADE a host
	// whose freshness could not be determined, instead of taking the hard-fail return.
	if errors.Is(faultErr, sessions.ErrFreshnessUnknown) {
		t.Fatalf("a probe FAULT must NOT be errors.Is(ErrFreshnessUnknown) — it would be "+
			"silently degraded instead of hard-failed (D72); got %v", faultErr)
	}
	// The fault is surfaced (wrapped) for the caller — not swallowed as a fresh host.
	if !errors.Is(faultErr, fault) {
		t.Fatalf("a probe FAULT must be surfaced (wrapped) for the caller, got %v", faultErr)
	}

	// ABSENT: the live probe answers cleanly that the host has NO current report.
	aAbsent := newAdapter([]Candidate{cand("host-a", 10)}, 10)
	aAbsent.Freshness = &fakeFreshness{ok: false}

	_, absentErr := aAbsent.CurrentFreshness(ctx, "host-absent")
	if absentErr == nil {
		t.Fatal("an ABSENT host must produce an error, got nil")
	}
	// The absent host DOES wrap the degrade sentinel: the coordinator degrades to the
	// recorded re-check rather than refusing a create the recorded signal still vouches
	// for. This is the OPPOSITE routing of the fault above — the asymmetry, pinned.
	if !errors.Is(absentErr, sessions.ErrFreshnessUnknown) {
		t.Fatalf("an ABSENT host must be errors.Is(ErrFreshnessUnknown) (degrade), got %v", absentErr)
	}

	// The asymmetry, asserted directly: the two outcomes are distinguishable by the very
	// sentinel the sessions degrade branch keys on — fault hard-fails, absent degrades.
	if errors.Is(faultErr, sessions.ErrFreshnessUnknown) == errors.Is(absentErr, sessions.ErrFreshnessUnknown) {
		t.Fatal("FAULT and ABSENT must route differently on errors.Is(ErrFreshnessUnknown): " +
			"fault → hard-fail (NOT the sentinel), absent → degrade (IS the sentinel)")
	}
}

// TestAdapter_CurrentFreshness_AbsentHost_EndToEndDegradeSentinel is the END-TO-END
// cross-package pin (D72): the EXACT error a scheduler-PRODUCED absent-host re-check
// emits is the EXACT sentinel the sessions §4.1 step-9 degrade branch keys on.
//
// The two halves of this contract are each pinned independently — orch22 pinned that
// the scheduler's CurrentFreshness wraps sessions.ErrFreshnessUnknown for an absent
// host (TestAdapter_CurrentFreshness_AbsentHostPinsUnknownContract, above), and the
// orch21 sessions tests pin that recheckFreshness degrades on
// errors.Is(err, ErrFreshnessUnknown) — but NOTHING locked the SEAM between them: that
// the identity the scheduler produces is the identity the sessions branch matches. A
// regression on EITHER side that broke the chain (the scheduler wrapping a different
// sentinel, or the sessions package re-homing/re-aliasing its degrade sentinel) would
// silently re-route the coordinator off the degrade path and onto the hard-fail
// `return err` — refusing a create the recorded re-check still vouches for.
//
// This test drives the REAL production scheduler.Adapter.CurrentFreshness on an absent
// host (a wired HostFreshness probe answering ok=false — D50 synthetic fixture, no live
// feed) to PRODUCE the error, then asserts errors.Is(producedErr, sessions.ErrFreshnessUnknown)
// against the sessions package's OWN exported sentinel. Because the produced error and
// the matched sentinel are resolved through the two packages' actual symbols, the pin
// fails the build the moment the chain breaks on either side. The sessions degrade
// branch itself is exercised in the sessions tests; here we lock the produced-error
// IDENTITY the branch keys on, end to end.
func TestAdapter_CurrentFreshness_AbsentHost_EndToEndDegradeSentinel(t *testing.T) {
	ctx := context.Background()
	a := newAdapter([]Candidate{cand("host-a", 10)}, 10)
	a.Freshness = &fakeFreshness{ok: false} // wired probe, host absent from the live feed

	// PRODUCE the error from the real production adapter on an absent host.
	_, producedErr := a.CurrentFreshness(ctx, "host-absent")
	if producedErr == nil {
		t.Fatal("an absent host must produce an error, got nil (the degrade chain has nothing to key on)")
	}

	// The exact error the SCHEDULER produces IS the exact sentinel the SESSIONS step-9
	// degrade branch keys on (errors.Is(err, sessions.ErrFreshnessUnknown)) — the
	// cross-package contract, locked end to end.
	if !errors.Is(producedErr, sessions.ErrFreshnessUnknown) {
		t.Fatalf("scheduler-produced absent-host error must be errors.Is sessions.ErrFreshnessUnknown "+
			"(the exact sentinel the step-9 degrade keys on), got %v", producedErr)
	}
}

// --- StoreCandidateSource end-to-end bridge --------------------------------

// fakeFeed returns fixed snapshots for any session.
type fakeFeed struct{ snaps []store.HeartbeatSnapshot }

func (f fakeFeed) LatestSnapshots(context.Context, string) ([]store.HeartbeatSnapshot, error) {
	return f.snaps, nil
}

// fakeScope returns a fixed tenancy scope for any session.
type fakeScope struct{ scope store.CandidateScope }

func (f fakeScope) ScopeFor(context.Context, string) (store.CandidateScope, error) {
	return f.scope, nil
}

// storeSnap builds a store-side heartbeat snapshot fixture.
func storeSnap(hostID string, reportedAt int64, appliedSeq uint64) store.HeartbeatSnapshot {
	return store.HeartbeatSnapshot{
		HostID:              hostID,
		ReportedAtUnixNanos: reportedAt,
		Heartbeat: &hostagentv1.Heartbeat{
			HostId:              hostID,
			AppliedSeq:          appliedSeq,
			HostBaselineVersion: "base-v1",
			Capacity:            &hostagentv1.HostCapacity{AllocatableVcpu: 64, AllocatableMemoryBytes: 1 << 40, AllocatableIoBps: 1 << 30, RunningSessions: 1},
		},
	}
}

// TestStoreCandidateSource_DrivesAssemblerEndToEnd proves the production
// CandidateSource wires the store assembler (latest-per-host + tenancy pool scope)
// into the §7 filter chain via the adapter: only the pooled host's LATEST snapshot
// reaches Place, and placement succeeds on it with that snapshot's applied_seq.
func TestStoreCandidateSource_DrivesAssemblerEndToEnd(t *testing.T) {
	ctx := context.Background()

	feed := fakeFeed{snaps: []store.HeartbeatSnapshot{
		storeSnap("host-a", 100, 5),
		storeSnap("host-a", 300, 9),   // newest for host-a — wins
		storeSnap("host-out", 100, 9), // outside the pool — excluded by scope
	}}
	scope := fakeScope{scope: store.CandidateScope{Pool: store.HostPool{HostIDs: []string{"host-a"}}}}

	src := StoreCandidateSource{Lister: store.NewMemory(), Feed: feed, Scope: scope}
	a := NewAdapter(New(DefaultConfig()), src, fakeSeq{seq: 9})

	got, err := a.Place(ctx, "sess-bridge", sessions.PlacementRequest{ImageID: "img"})
	if err != nil {
		t.Fatalf("Place via StoreCandidateSource: %v", err)
	}
	if got.HostID != "host-a" {
		t.Errorf("HostID = %q, want host-a (only pooled host)", got.HostID)
	}
	if got.AppliedSeq != 9 {
		t.Errorf("AppliedSeq = %d, want 9 (host-a's LATEST snapshot)", got.AppliedSeq)
	}
}

// --- production LatestPerHostFeed (orch43) ---------------------------------

// fakeRawSource is a synthetic RawHeartbeatSource (D50): it returns a fixed set of raw
// reports (or an error) for any session — the in-memory ingest plane a real
// control-plane heartbeat store would later satisfy this seam with.
type fakeRawSource struct {
	reports []RawHeartbeat
	err     error
	gotSess string
}

func (f *fakeRawSource) RawReports(_ context.Context, sessionUUID string) ([]RawHeartbeat, error) {
	f.gotSess = sessionUUID
	return f.reports, f.err
}

// rawHB builds a raw heartbeat report fixture (D50 synthetic — no live heartbeat).
func rawHB(hostID string, reportedAt int64, appliedSeq uint64) RawHeartbeat {
	return RawHeartbeat{
		HostID:              hostID,
		ReportedAtUnixNanos: reportedAt,
		Heartbeat: &hostagentv1.Heartbeat{
			HostId:     hostID,
			AppliedSeq: appliedSeq,
			Capacity:   &hostagentv1.HostCapacity{AllocatableVcpu: 64, AllocatableMemoryBytes: 1 << 40, AllocatableIoBps: 1 << 30, RunningSessions: 1},
		},
	}
}

// appliedSeqByHost flattens snapshots to a host_id→applied_seq lookup for assertions.
func appliedSeqByHost(snaps []store.HeartbeatSnapshot) map[string]uint64 {
	out := make(map[string]uint64, len(snaps))
	for _, s := range snaps {
		out[s.HostID] = s.Heartbeat.GetAppliedSeq()
	}
	return out
}

// TestLatestPerHostFeed_CollapsesToLatest proves the production HeartbeatFeed collapses
// the raw ingest reports to the LATEST snapshot per host (highest ReportedAtUnixNanos),
// drops malformed (empty-host) reports, and returns the result host-id-sorted — the §3
// "observed state from heartbeats" view the store-side assembler scopes over. It holds
// no state of its own (short-retention lives in the source); each read is a fresh
// projection of the source's current reports.
func TestLatestPerHostFeed_CollapsesToLatest(t *testing.T) {
	ctx := context.Background()
	src := &fakeRawSource{reports: []RawHeartbeat{
		rawHB("host-a", 100, 5),
		rawHB("host-a", 300, 9), // newest for host-a — its applied_seq must win
		rawHB("host-a", 200, 7),
		rawHB("host-b", 50, 4),
		{HostID: "", ReportedAtUnixNanos: 999}, // malformed: dropped
	}}
	feed := NewLatestPerHostFeed(src)

	snaps, err := feed.LatestSnapshots(ctx, "sess-feed")
	if err != nil {
		t.Fatalf("LatestSnapshots: %v", err)
	}

	// One snapshot per host, host-id-sorted, malformed dropped.
	gotHosts := make([]string, len(snaps))
	for i, s := range snaps {
		gotHosts[i] = s.HostID
	}
	if want := []string{"host-a", "host-b"}; !equalStrSlice(gotHosts, want) {
		t.Fatalf("collapsed hosts = %v, want %v (latest-per-host, malformed dropped)", gotHosts, want)
	}

	// host-a reflects its NEWEST report (applied_seq 9 at reported-at 300), not an older one.
	seq := appliedSeqByHost(snaps)
	if seq["host-a"] != 9 {
		t.Errorf("host-a applied_seq = %d, want 9 (latest report)", seq["host-a"])
	}
	if seq["host-b"] != 4 {
		t.Errorf("host-b applied_seq = %d, want 4", seq["host-b"])
	}

	// The reported-at timestamp the collapse keyed on is carried through (the assembler
	// re-collapses on it, so it must survive the feed's projection).
	for _, s := range snaps {
		if s.HostID == "host-a" && s.ReportedAtUnixNanos != 300 {
			t.Errorf("host-a reported-at = %d, want 300 (the latest report's timestamp)", s.ReportedAtUnixNanos)
		}
	}

	// The session UUID is passed through to the raw source.
	if src.gotSess != "sess-feed" {
		t.Errorf("source got session %q, want sess-feed", src.gotSess)
	}
}

// TestLatestPerHostFeed_TieKeepsLastWriter proves a tie in ReportedAtUnixNanos keeps the
// LATER report in the slice (>=) — the same last-writer-on-tie rule the store-side
// latestPerHost uses, so the feed and the assembler agree on which snapshot a host's
// duplicates collapse to (no disagreement on equal-timestamp reports).
func TestLatestPerHostFeed_TieKeepsLastWriter(t *testing.T) {
	ctx := context.Background()
	src := &fakeRawSource{reports: []RawHeartbeat{
		rawHB("host-a", 100, 5),
		rawHB("host-a", 100, 8), // same reported-at, later in slice — wins on the tie
	}}
	snaps, err := NewLatestPerHostFeed(src).LatestSnapshots(ctx, "s")
	if err != nil {
		t.Fatalf("LatestSnapshots: %v", err)
	}
	if got := appliedSeqByHost(snaps)["host-a"]; got != 8 {
		t.Errorf("tie applied_seq = %d, want 8 (last writer on equal reported-at)", got)
	}
}

// TestLatestPerHostFeed_NoPersistedState proves the feed holds NO state of its own — it
// is a stateless projection over the source's CURRENT reports (short-retention lives in
// the source). A source that drops a host between reads makes that host vanish from the
// feed's next result, exactly as a short-retention ingest plane behaves: there is no DB
// table or store record retaining a host the source no longer reports.
func TestLatestPerHostFeed_NoPersistedState(t *testing.T) {
	ctx := context.Background()
	src := &fakeRawSource{reports: []RawHeartbeat{rawHB("host-a", 1, 5), rawHB("host-b", 1, 5)}}
	feed := NewLatestPerHostFeed(src)

	first, err := feed.LatestSnapshots(ctx, "s")
	if err != nil {
		t.Fatalf("LatestSnapshots (first): %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("first read = %d hosts, want 2", len(first))
	}

	// The ingest plane drops host-b (it stopped reporting); the feed retains NOTHING —
	// the next read reflects only what the source currently holds.
	src.reports = []RawHeartbeat{rawHB("host-a", 2, 6)}
	second, err := feed.LatestSnapshots(ctx, "s")
	if err != nil {
		t.Fatalf("LatestSnapshots (second): %v", err)
	}
	if len(second) != 1 || second[0].HostID != "host-a" {
		t.Fatalf("second read = %v, want only host-a (no persisted state for the dropped host)", second)
	}
}

// TestLatestPerHostFeed_NilSourceMisconfigured proves a feed built with a nil raw source
// surfaces ErrHeartbeatFeedMisconfigured (a wiring bug) rather than panicking, and a nil
// receiver is handled too.
func TestLatestPerHostFeed_NilSourceMisconfigured(t *testing.T) {
	ctx := context.Background()
	if _, err := NewLatestPerHostFeed(nil).LatestSnapshots(ctx, "s"); !errors.Is(err, ErrHeartbeatFeedMisconfigured) {
		t.Errorf("nil source must surface ErrHeartbeatFeedMisconfigured, got %v", err)
	}
	var nilFeed *LatestPerHostFeed
	if _, err := nilFeed.LatestSnapshots(ctx, "s"); !errors.Is(err, ErrHeartbeatFeedMisconfigured) {
		t.Errorf("nil feed must surface ErrHeartbeatFeedMisconfigured, got %v", err)
	}
}

// TestLatestPerHostFeed_PropagatesSourceError proves a raw-source fault surfaces wrapped
// (not swallowed as an empty feed, which would silently empty the candidate set).
func TestLatestPerHostFeed_PropagatesSourceError(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("ingest boom")
	if _, err := NewLatestPerHostFeed(&fakeRawSource{err: boom}).LatestSnapshots(ctx, "s"); !errors.Is(err, boom) {
		t.Errorf("source error must propagate (wrapped), got %v", err)
	}
}

// TestLatestPerHostFeed_DrivesStoreCandidateSourceEndToEnd proves the production
// HeartbeatFeed wires into the StoreCandidateSource → §7 filter chain end to end: a raw
// ingest report set (with stale duplicates and an out-of-pool host) collapses to the
// latest per host through the feed, the tenancy scope confines it, and placement
// succeeds on the surviving host with its LATEST applied_seq — the full production
// candidate path, proven on synthetic fixtures (no live ingest).
func TestLatestPerHostFeed_DrivesStoreCandidateSourceEndToEnd(t *testing.T) {
	ctx := context.Background()

	feed := NewLatestPerHostFeed(&fakeRawSource{reports: []RawHeartbeat{
		rawHB("host-a", 100, 5),
		rawHB("host-a", 300, 9),   // newest for host-a — wins
		rawHB("host-out", 100, 9), // outside the pool — excluded by scope
	}})
	scope := NewConfigTenancyScope(TenancyConfig{PoolHostIDs: []string{"host-a"}})

	src := StoreCandidateSource{Lister: store.NewMemory(), Feed: feed, Scope: scope}
	a := NewAdapter(New(DefaultConfig()), src, fakeSeq{seq: 9})

	got, err := a.Place(ctx, "sess-prod", sessions.PlacementRequest{ImageID: "img"})
	if err != nil {
		t.Fatalf("Place via production feed + scope: %v", err)
	}
	if got.HostID != "host-a" {
		t.Errorf("HostID = %q, want host-a (only pooled host, latest snapshot)", got.HostID)
	}
	if got.AppliedSeq != 9 {
		t.Errorf("AppliedSeq = %d, want 9 (host-a's latest report)", got.AppliedSeq)
	}
}

// --- production ConfigTenancyScope (orch43) --------------------------------

// TestConfigTenancyScope_YieldsConfiguredPool proves the config-backed D19 tenancy scope
// source yields the configured host-pool scope for every session (single-tenant
// isolation is a host-pool CONFIG, session-independent): the pool members and tenancy
// host set come from config verbatim, the same scope for two different sessions.
func TestConfigTenancyScope_YieldsConfiguredPool(t *testing.T) {
	ctx := context.Background()
	src := NewConfigTenancyScope(TenancyConfig{
		PoolHostIDs:    []string{"host-a", "host-b"},
		TenancyHostIDs: []string{"host-a", "host-b", "host-c"},
	})

	for _, sess := range []string{"sess-1", "sess-2"} {
		scope, err := src.ScopeFor(ctx, sess)
		if err != nil {
			t.Fatalf("ScopeFor(%s): %v", sess, err)
		}
		if want := []string{"host-a", "host-b"}; !equalStrSlice(scope.Pool.HostIDs, want) {
			t.Errorf("%s: pool = %v, want %v (config-backed, session-independent)", sess, scope.Pool.HostIDs, want)
		}
		if want := []string{"host-a", "host-b", "host-c"}; !equalStrSlice(scope.TenancyHostIDs, want) {
			t.Errorf("%s: tenancy hosts = %v, want %v", sess, scope.TenancyHostIDs, want)
		}
	}
}

// TestConfigTenancyScope_EmptyConfigIsUnrestricted proves an empty config yields the
// open/shared-pool scope (no pool restriction, no cross-tenant guard) — the unrestricted
// default the assembler treats as "every reporting host is a candidate" (D19 guard needs
// an explicit pool/tenancy to activate).
func TestConfigTenancyScope_EmptyConfigIsUnrestricted(t *testing.T) {
	ctx := context.Background()
	scope, err := NewConfigTenancyScope(TenancyConfig{}).ScopeFor(ctx, "sess")
	if err != nil {
		t.Fatalf("ScopeFor: %v", err)
	}
	if len(scope.Pool.HostIDs) != 0 {
		t.Errorf("empty config pool = %v, want empty (unrestricted)", scope.Pool.HostIDs)
	}
	if len(scope.TenancyHostIDs) != 0 {
		t.Errorf("empty config tenancy = %v, want empty (guard off)", scope.TenancyHostIDs)
	}
}

// TestConfigTenancyScope_ConfigIsDefensivelyCopied proves the source captures the config
// by value with its slices copied: mutating the caller's config slice AFTER construction
// does not mutate the scope the source yields (the per-placement scope must be a stable,
// immutable value).
func TestConfigTenancyScope_ConfigIsDefensivelyCopied(t *testing.T) {
	ctx := context.Background()
	pool := []string{"host-a", "host-b"}
	src := NewConfigTenancyScope(TenancyConfig{PoolHostIDs: pool})

	pool[0] = "MUTATED" // caller mutates its own slice after construction

	scope, err := src.ScopeFor(ctx, "sess")
	if err != nil {
		t.Fatalf("ScopeFor: %v", err)
	}
	if want := []string{"host-a", "host-b"}; !equalStrSlice(scope.Pool.HostIDs, want) {
		t.Errorf("scope pool = %v, want %v (config must be defensively copied)", scope.Pool.HostIDs, want)
	}
}

// TestConfigTenancyScope_NilReceiverIsUnrestricted proves a nil source yields the
// unrestricted scope (defensive — a nil source is the open posture, never a panic).
func TestConfigTenancyScope_NilReceiverIsUnrestricted(t *testing.T) {
	var src *ConfigTenancyScope
	scope, err := src.ScopeFor(context.Background(), "sess")
	if err != nil {
		t.Fatalf("ScopeFor on nil source: %v", err)
	}
	if len(scope.Pool.HostIDs) != 0 || len(scope.TenancyHostIDs) != 0 {
		t.Errorf("nil source scope = %+v, want empty (unrestricted)", scope)
	}
}

// equalStrSlice compares two string slices for order-sensitive equality.
func equalStrSlice(a, b []string) bool {
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
