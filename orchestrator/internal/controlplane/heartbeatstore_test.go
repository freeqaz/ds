package controlplane

// heartbeatstore_test.go pins the latest-per-host feed's host-keyed O(1) point read
// (SnapshotForHost) and proves the §4.1 step-9 LIVE freshness consumer (D72) resolves a
// placed host's applied_seq through that O(1) accessor — a map hit on the create hot path,
// NOT the O(fleet) index-then-filter the candidate-feed read surface would force at the
// ~500-host virtual-metal density D37 (sizing); D34 (virtual-metal fidelity env) sizes for.
// Synthetic heartbeats only, no live
// host-agent / gRPC transport (D50): the store is exercised directly.

import (
	"context"
	"fmt"
	"testing"
	"time"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestSnapshotForHost_PresentAbsentAndLatest proves the host-keyed O(1) point read:
//   - a PRESENT host returns its most-recent snapshot (host_id, the ingest timestamp, the
//     frozen heartbeat) and true;
//   - an ABSENT host returns a zero snapshot and false (it has no current report — the
//     freshness probe degrades to the recorded re-check, never a stale snapshot);
//   - the LATEST report wins (a re-emit replaces the prior snapshot — the short-retention
//     latest-per-host posture, heartbeatstore.go).
func TestSnapshotForHost_PresentAbsentAndLatest(t *testing.T) {
	ctx := context.Background()

	// Deterministic clock so the ReportedAtUnixNanos assertion is exact.
	at := time.Unix(1_700_000_000, 0).UTC()
	st := NewHeartbeatStore(func() time.Time { return at })

	st.Record(freshHeartbeat("host-a", 5, 1))

	snap, ok, err := st.SnapshotForHost(ctx, "host-a")
	if err != nil {
		t.Fatalf("SnapshotForHost(host-a): %v", err)
	}
	if !ok {
		t.Fatalf("SnapshotForHost(host-a) ok = false, want true (host present)")
	}
	if snap.HostID != "host-a" {
		t.Errorf("SnapshotForHost(host-a) HostID = %q, want %q", snap.HostID, "host-a")
	}
	if snap.ReportedAtUnixNanos != at.UnixNano() {
		t.Errorf("SnapshotForHost(host-a) ReportedAtUnixNanos = %d, want %d", snap.ReportedAtUnixNanos, at.UnixNano())
	}
	if got := snap.Heartbeat.GetAppliedSeq(); got != 5 {
		t.Errorf("SnapshotForHost(host-a) applied_seq = %d, want 5", got)
	}

	// ABSENT host → (zero, false): a host that never reported has no live snapshot.
	zero, ok, err := st.SnapshotForHost(ctx, "host-gone")
	if err != nil {
		t.Fatalf("SnapshotForHost(host-gone): %v", err)
	}
	if ok {
		t.Errorf("SnapshotForHost(host-gone) ok = true, want false (host absent)")
	}
	if zero != (store.HeartbeatSnapshot{}) {
		t.Errorf("SnapshotForHost(host-gone) = %+v, want the zero snapshot", zero)
	}

	// LATEST wins: a re-emit replaces the host's prior snapshot.
	st.Record(freshHeartbeat("host-a", 9, 2))
	snap, ok, err = st.SnapshotForHost(ctx, "host-a")
	if err != nil || !ok {
		t.Fatalf("SnapshotForHost(host-a, re-emit) = (_, %v, %v), want (_, true, nil)", ok, err)
	}
	if got := snap.Heartbeat.GetAppliedSeq(); got != 9 {
		t.Errorf("SnapshotForHost(host-a, re-emit) applied_seq = %d, want 9 (latest wins)", got)
	}
}

// TestSnapshotForHost_OutOfOrderDeliveryKeepsNewer proves the point read honors the
// monotone-timestamp dedup Record enforces: an out-of-order (older-timestamped) delivery
// never regresses the host's live snapshot, so SnapshotForHost still resolves the newer one.
func TestSnapshotForHost_OutOfOrderDeliveryKeepsNewer(t *testing.T) {
	ctx := context.Background()

	clock := time.Unix(1_700_000_000, 0).UTC()
	st := NewHeartbeatStore(func() time.Time { return clock })

	st.Record(freshHeartbeat("host-a", 7, 1)) // recorded at t0

	// A LATER ingest with a higher applied_seq advances the snapshot.
	clock = clock.Add(time.Second)
	st.Record(freshHeartbeat("host-a", 8, 1)) // recorded at t0+1s

	// An OUT-OF-ORDER delivery (clock rewound) must NOT regress the live view.
	clock = clock.Add(-2 * time.Second)
	st.Record(freshHeartbeat("host-a", 3, 1)) // stale; dropped

	snap, ok, err := st.SnapshotForHost(ctx, "host-a")
	if err != nil || !ok {
		t.Fatalf("SnapshotForHost(host-a) = (_, %v, %v), want (_, true, nil)", ok, err)
	}
	if got := snap.Heartbeat.GetAppliedSeq(); got != 8 {
		t.Errorf("SnapshotForHost(host-a) applied_seq = %d, want 8 (out-of-order delivery dropped)", got)
	}
}

// TestSnapshotForHost_IgnoresMalformedRecord proves a malformed feed entry (nil heartbeat or
// empty host_id) is never recorded, so it is never a freshness target — SnapshotForHost
// reports the empty host absent.
func TestSnapshotForHost_IgnoresMalformedRecord(t *testing.T) {
	ctx := context.Background()
	st := NewHeartbeatStore(nil)

	st.Record(nil)                      // nil heartbeat — ignored
	st.Record(&hostagentv1.Heartbeat{}) // empty host_id — ignored

	if _, ok, err := st.SnapshotForHost(ctx, ""); err != nil || ok {
		t.Fatalf("SnapshotForHost(\"\") = (_, %v, %v), want (_, false, nil) — malformed never recorded", ok, err)
	}
}

// TestHeartbeatStore_SatisfiesHostAppliedSeqSource proves the store is the host-keyed
// point-read source store.HostAppliedSeq drives — directly, no fleet walk — so the production
// freshness consumer reads applied_seq O(1). The (seq,true) / (0,false) branches the §4.1
// step-9 degrade depends on are asserted through store.HostAppliedSeq over the store itself.
func TestHeartbeatStore_SatisfiesHostAppliedSeqSource(t *testing.T) {
	ctx := context.Background()
	st := NewHeartbeatStore(nil)
	st.Record(freshHeartbeat("host-a", 11, 1))

	// The store IS the HostAppliedSeqSource (compile-time proof in heartbeatstore.go); drive
	// the additive store query directly over it — the O(1) production point-read path.
	var src store.HostAppliedSeqSource = st

	seq, ok, err := store.HostAppliedSeq(ctx, src, "host-a")
	if err != nil {
		t.Fatalf("HostAppliedSeq(host-a): %v", err)
	}
	if !ok || seq != 11 {
		t.Fatalf("HostAppliedSeq(host-a) = (%d, %v), want (11, true)", seq, ok)
	}

	if seq, ok, err := store.HostAppliedSeq(ctx, src, "host-gone"); err != nil || ok || seq != 0 {
		t.Fatalf("HostAppliedSeq(host-gone) = (%d, %v, %v), want (0, false, nil)", seq, ok, err)
	}
}

// TestHeartbeatFreshness_ResolvesViaO1Accessor proves the production §4.1 step-9 freshness
// consumer (heartbeatFreshness.CurrentAppliedSeq) resolves a placed host's applied_seq
// through the store's O(1) SnapshotForHost accessor — behavior identical to the prior
// fleet-walk bridge, just the lookup path changed. The consumer's appliedSeqSource picks the
// direct O(1) path when the feed exposes SnapshotForHost (the live *HeartbeatStore does).
func TestHeartbeatFreshness_ResolvesViaO1Accessor(t *testing.T) {
	ctx := context.Background()
	st := NewHeartbeatStore(nil)
	st.Record(freshHeartbeat("host-a", 13, 1))

	probe := heartbeatFreshness{feed: st}

	// The consumer routes through the store's O(1) accessor, NOT the hostSnapshotIndex bridge.
	if _, isBridge := probe.appliedSeqSource().(hostSnapshotIndex); isBridge {
		t.Fatalf("appliedSeqSource resolved to the O(fleet) hostSnapshotIndex bridge, want the store's O(1) SnapshotForHost path")
	}
	if _, isStore := probe.appliedSeqSource().(*HeartbeatStore); !isStore {
		t.Fatalf("appliedSeqSource = %T, want the live *HeartbeatStore (the O(1) host-keyed accessor)", probe.appliedSeqSource())
	}

	// PRESENT host → live applied_seq + true (the value the step-9 gate re-validates against).
	seq, ok, err := probe.CurrentAppliedSeq(ctx, "host-a")
	if err != nil {
		t.Fatalf("CurrentAppliedSeq(host-a): %v", err)
	}
	if !ok || seq != 13 {
		t.Fatalf("CurrentAppliedSeq(host-a) = (%d, %v), want (13, true)", seq, ok)
	}

	// ABSENT host → (0, false): the placer maps it to ErrFreshnessUnknown and the coordinator
	// degrades to the recorded re-check (unchanged, backwards-compatible).
	if seq, ok, err := probe.CurrentAppliedSeq(ctx, "host-gone"); err != nil || ok || seq != 0 {
		t.Fatalf("CurrentAppliedSeq(host-gone) = (%d, %v, %v), want (0, false, nil)", seq, ok, err)
	}
}

// benchFleetHosts is the ~500-host virtual-metal density doc 15 §4.1 / D37 (sizing); D34
// (virtual-metal fidelity env) sizes for: the
// point at which the create hot-path step-9 freshness re-check must NOT pay an O(fleet) scan.
// The two benchmarks below measure the same point read at this density over the same populated
// store — the O(1) host-keyed map hit (SnapshotForHost) vs the O(fleet) index-then-filter the
// hostSnapshotIndex bridge does over the candidate-feed LatestSnapshots read — so the perf
// claim in heartbeatstore.go / seams.go is MEASURED, not asserted in prose alone.
const benchFleetHosts = 500

// benchHostID is the deterministic host_id of fleet host i (0-based), shared by the populator
// and the per-iteration query so both benchmarks probe a host that is actually present.
func benchHostID(i int) string { return fmt.Sprintf("host-%04d", i) }

// newBenchFleetStore returns a *HeartbeatStore populated to benchFleetHosts distinct hosts, each
// with one latest snapshot (synthetic heartbeats only, no live host-agent / gRPC transport, D50).
// A fixed clock keeps Record's monotone-timestamp dedup from dropping any host.
func newBenchFleetStore() *HeartbeatStore {
	at := time.Unix(1_700_000_000, 0).UTC()
	st := NewHeartbeatStore(func() time.Time { return at })
	for i := 0; i < benchFleetHosts; i++ {
		st.Record(freshHeartbeat(benchHostID(i), uint64(i), 1))
	}
	return st
}

// benchSnapshotSink defeats dead-code elimination: the result of the point read under
// measurement is stored here so the compiler cannot prove the call has no effect and drop it.
var benchSnapshotSink store.HeartbeatSnapshot

// BenchmarkSnapshotForHost measures the HeartbeatStore.SnapshotForHost O(1) host-keyed accessor
// (the production §4.1 step-9 D72 freshness path the live *HeartbeatStore takes) over a fleet at
// the ~500-host virtual-metal density. Each iteration resolves a DIFFERENT host (rotating across
// the whole fleet) so the cost is a representative map hit, not one cached key — the lookup work
// is a single map index regardless of fleet size, which is the claim under test.
func BenchmarkSnapshotForHost(b *testing.B) {
	ctx := context.Background()
	st := newBenchFleetStore()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snap, ok, err := st.SnapshotForHost(ctx, benchHostID(i%benchFleetHosts))
		if err != nil || !ok {
			b.Fatalf("SnapshotForHost(host %d) = (_, %v, %v), want (_, true, nil)", i%benchFleetHosts, ok, err)
		}
		benchSnapshotSink = snap
	}
}

// BenchmarkHostSnapshotIndex measures the hostSnapshotIndex.SnapshotForHost O(fleet) FALLBACK
// (seams.go) over the SAME ~500-host store: it index-then-filters by walking the candidate-feed
// LatestSnapshots read (a fresh fleet-wide slice assembly) and linearly scanning it for one
// host_id. This is the cost the production O(1) path avoids; benchmarking it head-to-head with
// BenchmarkSnapshotForHost proves the map hit beats the fleet walk at the density D37 (sizing);
// D34 (virtual-metal fidelity env) sizes for, rather than leaving the perf claim in prose only.
// Each iteration rotates the queried host so
// the linear scan hits varying positions (not always the first element).
func BenchmarkHostSnapshotIndex(b *testing.B) {
	ctx := context.Background()
	idx := hostSnapshotIndex{feed: newBenchFleetStore()}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snap, ok, err := idx.SnapshotForHost(ctx, benchHostID(i%benchFleetHosts))
		if err != nil || !ok {
			b.Fatalf("hostSnapshotIndex.SnapshotForHost(host %d) = (_, %v, %v), want (_, true, nil)", i%benchFleetHosts, ok, err)
		}
		benchSnapshotSink = snap
	}
}

// maxSnapshotForHostAllocsPerOp bounds the per-call heap allocations of the O(1) host-keyed
// point read. SnapshotForHost is a single map index that returns a value-typed
// store.HeartbeatSnapshot wrapping the host's *already-allocated* heartbeat pointer, so the
// accessor itself allocates NOTHING on the create hot path — zero allocs/op, independent of how
// many hosts populate the latest-per-host set. A regression to the O(fleet) index-then-filter the
// candidate-feed read surface forces (the hostSnapshotIndex bridge: a fresh fleet-wide
// LatestSnapshots slice assembled per call, seams.go) lifts the count to at least one alloc/op,
// breaching this bound — which is exactly what the gate below catches. The bound is a small
// constant, NOT a function of fleet size: that fleet-size independence IS the O(1) claim.
const maxSnapshotForHostAllocsPerOp = 0

// allocsRunsPerMeasure is the AllocsPerRun sample count. testing.AllocsPerRun reports an integral
// average over many runs (it forces a GC before measuring), so a healthy run lands on an exact
// integer; a large sample keeps a one-off scheduler hiccup from skewing the average off that
// integer. This is allocation accounting, not wall-clock timing, so the measure is deterministic
// and the gate is non-flaky (no timing threshold to race).
const allocsRunsPerMeasure = 2000

// snapshotForHostAllocsPerOp populates a store to hostCount distinct hosts, then measures the
// per-call heap allocations of SnapshotForHost over it. The queried host_ids are precomputed into
// a slice OUTSIDE the measured closure so the only allocation the measure can attribute is the
// accessor's own — building a host_id inside the closure (fmt.Sprintf) would charge that string's
// alloc to the read and mask the very signal under test. The closure rotates across the whole
// fleet (so the map index is exercised over varying keys, not one cached bucket) and stores the
// result in the package-level sink so dead-code elimination cannot drop the call.
func snapshotForHostAllocsPerOp(t *testing.T, hostCount int) float64 {
	t.Helper()

	at := time.Unix(1_700_000_000, 0).UTC()
	st := NewHeartbeatStore(func() time.Time { return at })
	ids := make([]string, hostCount)
	for i := 0; i < hostCount; i++ {
		ids[i] = benchHostID(i)
		st.Record(freshHeartbeat(ids[i], uint64(i), 1))
	}

	ctx := context.Background()
	var k int
	return testing.AllocsPerRun(allocsRunsPerMeasure, func() {
		id := ids[k%hostCount] // hoisted index read keeps the slice index out of the alloc budget.
		k++
		snap, ok, err := st.SnapshotForHost(ctx, id)
		if err != nil || !ok {
			t.Fatalf("SnapshotForHost(%s) = (_, %v, %v), want (_, true, nil)", id, ok, err)
		}
		benchSnapshotSink = snap
	})
}

// TestSnapshotForHost_O1AllocsGate is the CI-enforceable guard on the SnapshotForHost O(1) perf
// invariant the BenchmarkSnapshotForHost comparison documents for human reading only. It turns
// that claim into a gate testing.AllocsPerRun can FAIL on a regression:
//
//   - allocs/op at BOTH a small fleet and the ~500-host virtual-metal density (D37 sizing; D34
//     virtual-metal fidelity env) must be within the small constant bound
//     maxSnapshotForHostAllocsPerOp — a fleet-walk regression breaches it;
//   - allocs/op must be IDENTICAL across the two fleet sizes — the same point read costing more at
//     500 hosts than at a handful is the O(fleet) scaling this invariant forbids, so any divergence
//     (e.g. an index-then-filter whose per-call slice grows with the fleet) fails the gate even if
//     it somehow stayed under the absolute bound.
//
// It is allocation accounting, not timing, so it is deterministic and non-flaky.
func TestSnapshotForHost_O1AllocsGate(t *testing.T) {
	const smallFleet = 8 // a handful of hosts: the O(1) baseline cost with no fleet to scan.
	if benchFleetHosts <= smallFleet {
		t.Fatalf("benchFleetHosts (%d) must exceed smallFleet (%d) for the two-size comparison", benchFleetHosts, smallFleet)
	}

	small := snapshotForHostAllocsPerOp(t, smallFleet)
	large := snapshotForHostAllocsPerOp(t, benchFleetHosts) // ~500-host virtual-metal density.

	// Absolute bound: the accessor is a map hit, so it allocates the small constant at every size.
	if small > maxSnapshotForHostAllocsPerOp {
		t.Errorf("SnapshotForHost allocs/op at %d hosts = %v, want <= %d (O(1) map hit must not allocate)",
			smallFleet, small, maxSnapshotForHostAllocsPerOp)
	}
	if large > maxSnapshotForHostAllocsPerOp {
		t.Errorf("SnapshotForHost allocs/op at %d hosts = %v, want <= %d (regression to an O(fleet) scan allocates)",
			benchFleetHosts, large, maxSnapshotForHostAllocsPerOp)
	}

	// Fleet-size independence: identical cost at both sizes is the O(1) claim. AllocsPerRun returns
	// an integral average for a clean run, so an exact == is the right, non-flaky comparison here.
	if small != large {
		t.Errorf("SnapshotForHost allocs/op scaled with fleet size: %v at %d hosts vs %v at %d hosts; "+
			"the point read must cost the same regardless of populated host count (O(1), not O(fleet))",
			small, smallFleet, large, benchFleetHosts)
	}
}

// maxHostAppliedSeqAllocsPerOp bounds the per-call heap allocations of the END-TO-END §4.1
// step-9 D72 production point read store.HostAppliedSeq driven over the live *HeartbeatStore.
// HostAppliedSeq composes the O(1) SnapshotForHost map hit (which returns a value-typed
// store.HeartbeatSnapshot wrapping the host's *already-allocated* heartbeat pointer) and then
// reads snap.Heartbeat.GetAppliedSeq() — a pointer-receiver field read on that same pointer, no
// allocation. So the whole production hot path allocates NOTHING, independent of fleet size. A
// regression that wraps the direct map hit in an allocating adapter (e.g. re-deriving the point
// read from the O(fleet) hostSnapshotIndex bridge: a fresh fleet-wide LatestSnapshots slice
// assembled per call, seams.go) lifts the count to at least one alloc/op and breaches this bound.
// The bound is a small constant, NOT a function of fleet size: that fleet-size independence IS the
// O(1) claim. It mirrors maxSnapshotForHostAllocsPerOp — the accessor and its end-to-end consumer
// pay the same zero-alloc cost.
const maxHostAppliedSeqAllocsPerOp = 0

// hostAppliedSeqAllocsPerOp populates a store to hostCount distinct hosts, then measures the
// per-call heap allocations of the production store.HostAppliedSeq point read driven over the live
// *HeartbeatStore (as its HostAppliedSeqSource). It mirrors snapshotForHostAllocsPerOp: the queried
// host_ids are precomputed into a slice OUTSIDE the measured closure so the only allocation the
// measure can attribute is the point read's own — building a host_id inside the closure
// (fmt.Sprintf) would charge that string's alloc to the read and mask the very signal under test.
// The closure rotates across the whole fleet (so the map index is exercised over varying keys, not
// one cached bucket) and stores the returned seq in the package-level sink so dead-code elimination
// cannot drop the call. The store is bound to the interface variable ONCE outside the closure so the
// interface conversion is not charged per op.
func hostAppliedSeqAllocsPerOp(t *testing.T, hostCount int) float64 {
	t.Helper()

	at := time.Unix(1_700_000_000, 0).UTC()
	st := NewHeartbeatStore(func() time.Time { return at })
	ids := make([]string, hostCount)
	for i := 0; i < hostCount; i++ {
		ids[i] = benchHostID(i)
		st.Record(freshHeartbeat(ids[i], uint64(i), 1))
	}

	// Bind to the narrow point-read seam ONCE (the production driver shape), so the per-op measure
	// charges only the lookup, not the interface conversion.
	var src store.HostAppliedSeqSource = st

	ctx := context.Background()
	var k int
	return testing.AllocsPerRun(allocsRunsPerMeasure, func() {
		id := ids[k%hostCount] // hoisted index read keeps the slice index out of the alloc budget.
		k++
		seq, ok, err := store.HostAppliedSeq(ctx, src, id)
		if err != nil || !ok {
			t.Fatalf("HostAppliedSeq(%s) = (%d, %v, %v), want (_, true, nil)", id, seq, ok, err)
		}
		benchAppliedSeqSink = seq
	})
}

// benchAppliedSeqSink defeats dead-code elimination for the HostAppliedSeq measure: the resolved
// applied_seq under measurement is stored here so the compiler cannot prove the call has no effect.
var benchAppliedSeqSink uint64

// TestHostAppliedSeq_O1AllocsGate is the CI-enforceable guard on the O(1) perf invariant of the
// END-TO-END §4.1 step-9 D72 production point read store.HostAppliedSeq (applied_seq over the live
// *HeartbeatStore). SnapshotForHost has its own allocs gate (TestSnapshotForHost_O1AllocsGate); this
// gate pins the WHOLE production hot path — the accessor PLUS the applied_seq extraction the freshness
// consumer drives — so a regression that wraps the direct map hit in an allocating adapter (an
// index-then-filter bridge whose per-call slice grows with the fleet) is caught even though it bypasses
// the SnapshotForHost gate. It mirrors that gate's two-fleet-size testing.AllocsPerRun pattern:
//
//   - allocs/op at BOTH a small fleet and the ~500-host virtual-metal density (D37 sizing; D34
//     virtual-metal fidelity env) must be within the small constant bound
//     maxHostAppliedSeqAllocsPerOp — a fleet-walk regression breaches it;
//   - allocs/op must be IDENTICAL across the two fleet sizes — the same point read costing more at 500
//     hosts than at a handful is the O(fleet) scaling this invariant forbids, so any divergence fails the
//     gate even if it somehow stayed under the absolute bound.
//
// It is allocation accounting, not timing, so it is deterministic and non-flaky.
func TestHostAppliedSeq_O1AllocsGate(t *testing.T) {
	const smallFleet = 8 // a handful of hosts: the O(1) baseline cost with no fleet to scan.
	if benchFleetHosts <= smallFleet {
		t.Fatalf("benchFleetHosts (%d) must exceed smallFleet (%d) for the two-size comparison", benchFleetHosts, smallFleet)
	}

	small := hostAppliedSeqAllocsPerOp(t, smallFleet)
	large := hostAppliedSeqAllocsPerOp(t, benchFleetHosts) // ~500-host virtual-metal density.

	// Absolute bound: the point read is a map hit + a pointer field read, so it allocates the small
	// constant at every size.
	if small > maxHostAppliedSeqAllocsPerOp {
		t.Errorf("HostAppliedSeq allocs/op at %d hosts = %v, want <= %d (O(1) map hit + field read must not allocate)",
			smallFleet, small, maxHostAppliedSeqAllocsPerOp)
	}
	if large > maxHostAppliedSeqAllocsPerOp {
		t.Errorf("HostAppliedSeq allocs/op at %d hosts = %v, want <= %d (regression to an O(fleet) scan allocates)",
			benchFleetHosts, large, maxHostAppliedSeqAllocsPerOp)
	}

	// Fleet-size independence: identical cost at both sizes is the O(1) claim. AllocsPerRun returns an
	// integral average for a clean run, so an exact == is the right, non-flaky comparison here.
	if small != large {
		t.Errorf("HostAppliedSeq allocs/op scaled with fleet size: %v at %d hosts vs %v at %d hosts; "+
			"the end-to-end point read must cost the same regardless of populated host count (O(1), not O(fleet))",
			small, smallFleet, large, benchFleetHosts)
	}
}

// hostSnapshotIndexAppliedSeqAllocsPerOp is the CONTRAST measure: it drives the SAME store.HostAppliedSeq
// point read, but over the hostSnapshotIndex FALLBACK bridge (seams.go) instead of the live
// *HeartbeatStore's direct O(1) accessor. The bridge index-then-filters by assembling a FRESH fleet-wide
// LatestSnapshots slice per call (one heap alloc) and linearly scanning it for one host_id, so its per-call
// allocation COUNT is a nonzero constant (≥1 alloc/op) — distinct from the direct accessor's zero. Note
// testing.AllocsPerRun measures the NUMBER of heap allocations, not bytes: the fallback's backing slice
// grows in BYTES with the fleet but stays ONE alloc/op, so the honest distinction this contrast asserts is
// nonzero-vs-zero alloc COUNT (the regression the gate forbids on the hot path is exactly "the direct
// zero-alloc map hit replaced by a ≥1-alloc fleet-walk adapter"). Same precomputed-ids / package-sink
// discipline as the O(1) measure.
func hostSnapshotIndexAppliedSeqAllocsPerOp(t *testing.T, hostCount int) float64 {
	t.Helper()

	at := time.Unix(1_700_000_000, 0).UTC()
	st := NewHeartbeatStore(func() time.Time { return at })
	ids := make([]string, hostCount)
	for i := 0; i < hostCount; i++ {
		ids[i] = benchHostID(i)
		st.Record(freshHeartbeat(ids[i], uint64(i), 1))
	}

	// The O(fleet) fallback over the candidate-feed-only read surface — the path the production
	// consumer AVOIDS for the live store, exercised here only to contrast its scaling.
	var src store.HostAppliedSeqSource = hostSnapshotIndex{feed: st}

	ctx := context.Background()
	var k int
	return testing.AllocsPerRun(allocsRunsPerMeasure, func() {
		id := ids[k%hostCount]
		k++
		seq, ok, err := store.HostAppliedSeq(ctx, src, id)
		if err != nil || !ok {
			t.Fatalf("HostAppliedSeq(via hostSnapshotIndex, %s) = (%d, %v, %v), want (_, true, nil)", id, seq, ok, err)
		}
		benchAppliedSeqSink = seq
	})
}

// TestHostAppliedSeq_OfleetFallbackContrast self-checks the zero-vs-nonzero alloc distinction the gate
// pins. It is the negative control for TestHostAppliedSeq_O1AllocsGate: it proves the gate measures a real
// distinction by exhibiting the very regression the gate forbids — the same store.HostAppliedSeq point read
// driven over the hostSnapshotIndex fleet-walk FALLBACK instead of the direct *HeartbeatStore accessor
// genuinely allocates (a fresh LatestSnapshots slice per call), so the gate's "zero allocs/op" assertion
// is meaningful, not vacuous. It asserts the fallback's allocs/op is STRICTLY GREATER than the direct O(1)
// path's at BOTH fleet sizes (nonzero vs zero — the wrapping-in-an-allocating-adapter regression the gate
// catches), and that the fallback itself stays a flat per-op COUNT across the two sizes (its slice grows in
// bytes with the fleet, but testing.AllocsPerRun counts allocations, not bytes — so the honest invariant is
// a constant nonzero count, distinct from the direct path's constant zero).
func TestHostAppliedSeq_OfleetFallbackContrast(t *testing.T) {
	const smallFleet = 8
	if benchFleetHosts <= smallFleet {
		t.Fatalf("benchFleetHosts (%d) must exceed smallFleet (%d) for the two-size comparison", benchFleetHosts, smallFleet)
	}

	fallbackSmall := hostSnapshotIndexAppliedSeqAllocsPerOp(t, smallFleet)
	fallbackLarge := hostSnapshotIndexAppliedSeqAllocsPerOp(t, benchFleetHosts)
	directSmall := hostAppliedSeqAllocsPerOp(t, smallFleet)
	directLarge := hostAppliedSeqAllocsPerOp(t, benchFleetHosts)

	// Zero-vs-nonzero: the fallback the gate forbids on the hot path genuinely allocates (a fresh
	// fleet-wide slice per call), so it costs STRICTLY MORE allocs/op than the direct map hit — at every
	// size. This is the regression signature the O(1) gate bites on.
	if !(fallbackSmall > directSmall) {
		t.Errorf("hostSnapshotIndex HostAppliedSeq allocs/op (%v) did not exceed the direct O(1) path (%v) at %d hosts; "+
			"the fleet-walk fallback the production consumer avoids must allocate where the map hit does not",
			fallbackSmall, directSmall, smallFleet)
	}
	if !(fallbackLarge > directLarge) {
		t.Errorf("hostSnapshotIndex HostAppliedSeq allocs/op (%v) did not exceed the direct O(1) path (%v) at %d hosts; "+
			"the fleet-walk fallback the production consumer avoids must allocate where the map hit does not",
			fallbackLarge, directLarge, benchFleetHosts)
	}

	// The fallback's alloc COUNT is a flat nonzero constant across sizes (one slice per call regardless of
	// fleet) — testing.AllocsPerRun counts allocations, not bytes, so its bytes-grow-with-fleet cost shows
	// up as a constant ≥1 count here, distinct from the direct path's constant zero.
	if fallbackSmall != fallbackLarge {
		t.Errorf("hostSnapshotIndex HostAppliedSeq alloc COUNT changed with fleet size: %v at %d hosts vs %v at %d hosts; "+
			"the fallback assembles ONE LatestSnapshots slice per call at any size (bytes grow, count does not)",
			fallbackSmall, smallFleet, fallbackLarge, benchFleetHosts)
	}
}
