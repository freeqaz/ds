package reconciler

// Tests for the queryable, non-state liveness/health signal (health.go): the
// "3 missed beats → UNKNOWN" annotation (doc 15 §3 / §5.2) made queryable WITHOUT
// a §3 state name, WITHOUT a record mutation, and WITHOUT a second lastBeat writer
// (D35/D72). Synthetic heartbeat fixtures only (D50) — reuses the package's
// existing fakes (newClock, store.NewMemoryClock, heartbeat, observedSession,
// seedRecord, recordingAlarmer).

import (
	"context"
	"fmt"
	"testing"
	"time"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// newHealthReconciler builds a reconciler over a clock-driven in-memory store with
// the default missed-beat window (3 * 5s = 15s), the same construction the
// crash-matrix tests use. Returns the reconciler and the clock so a test can
// observe heartbeats then advance time.
func newHealthReconciler(t *testing.T, start time.Time) (*Reconciler, *fixedClock, *store.Memory) {
	t.Helper()
	clk := newClock(start)
	st := store.NewMemoryClock(clk.now)
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, &recordingAlarmer{}, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r, clk, st
}

// findHealth returns the snapshot entry for hostID and whether it was present.
func findHealth(snap []HostHealth, hostID string) (HostHealth, bool) {
	for _, h := range snap {
		if h.HostID == hostID {
			return h, true
		}
	}
	return HostHealth{}, false
}

// A host that beat within the silence window is reported LIVE.
func TestHealthSnapshot_LiveHost_ReportedLive(t *testing.T) {
	r, clk, _ := newHealthReconciler(t, time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))

	if err := r.Observe(context.Background(), heartbeat("host-1", observedSession("sess-1", "dom-1", 1, store.SessionWorking))); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	// Advance well within the 15s window.
	clk.advance(5 * time.Second)

	snap := r.HealthSnapshot()
	h, ok := findHealth(snap, "host-1")
	if !ok {
		t.Fatalf("host-1 must appear in the snapshot after a heartbeat")
	}
	if h.Liveness != HostLive {
		t.Fatalf("host within the silence window must be LIVE; got %q", h.Liveness)
	}
	if !h.EverSeen {
		t.Fatalf("a host that beat must report EverSeen=true")
	}
	if h.SinceLastBeat != 5*time.Second {
		t.Fatalf("SinceLastBeat = %v, want 5s", h.SinceLastBeat)
	}
	if h.SilenceWindow != 15*time.Second {
		t.Fatalf("SilenceWindow = %v, want 15s (3 * 5s default)", h.SilenceWindow)
	}
}

// A host JUST inside the window (silence == window, the boundary) is still LIVE —
// markMissedBeats keys on `now-last <= window`, so the boundary is live, not
// UNKNOWN. This pins the off-by-one with the sweep.
func TestHealthSnapshot_JustMissed_AtWindowBoundaryStillLive(t *testing.T) {
	r, clk, _ := newHealthReconciler(t, time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))

	if err := r.Observe(context.Background(), heartbeat("host-1", observedSession("sess-1", "dom-1", 1, store.SessionWorking))); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	// Exactly the silence window of silence (15s == 3*5s): the <= boundary is LIVE.
	clk.advance(15 * time.Second)

	h := r.HostHealth("host-1")
	if h.Liveness != HostLive {
		t.Fatalf("silence == window must remain LIVE (boundary is <=); got %q at %v", h.Liveness, h.SinceLastBeat)
	}

	// One tick past the window flips it to UNKNOWN.
	clk.advance(1 * time.Second)
	h = r.HostHealth("host-1")
	if h.Liveness != HostUnknown {
		t.Fatalf("silence > window must be UNKNOWN; got %q at %v", h.Liveness, h.SinceLastBeat)
	}
}

// A host silent BEYOND the silence window is reported UNKNOWN — the queryable form
// of AlarmHostUnknown — and the snapshot AGREES with the missed-beat sweep's alarm.
func TestHealthSnapshot_BeyondWindow_ReportedUnknown_AgreesWithAlarm(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	al := &recordingAlarmer{}
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, al, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seedRecord(t, st, "sess-1", "host-1", 1, store.SessionWorking)

	if err := r.Observe(context.Background(), heartbeat("host-1", observedSession("sess-1", "dom-1", 1, store.SessionWorking))); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	// Go silent past the 15s window.
	clk.advance(20 * time.Second)

	// The queried snapshot reports UNKNOWN...
	h := r.HostHealth("host-1")
	if h.Liveness != HostUnknown {
		t.Fatalf("host silent past the window must be UNKNOWN; got %q", h.Liveness)
	}
	if h.SinceLastBeat != 20*time.Second {
		t.Fatalf("SinceLastBeat = %v, want 20s", h.SinceLastBeat)
	}

	// ...and the missed-beat sweep raises AlarmHostUnknown for the SAME host: the
	// queryable signal and the alarm cannot disagree (both derive from lastBeat +
	// silenceWindow with the same predicate).
	if err := r.Resync(context.Background(), map[string][]*hypervisorv1.ObservedSession{}); err != nil {
		t.Fatalf("Resync: %v", err)
	}
	if !al.has(AlarmHostUnknown) {
		t.Fatalf("the missed-beat sweep must alarm UNKNOWN for the same host the snapshot reports UNKNOWN")
	}

	// INVARIANT: the health derivation is non-state and never mutates the record —
	// the session stays in its §3 state (the never-auto-destroy / never-mutate
	// invariant the annotation must preserve, §3 / §5.2).
	got, err := st.GetSession(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.State != store.SessionWorking {
		t.Fatalf("UNKNOWN is a non-state annotation; record state must be unchanged, got %v", got.State)
	}
}

// A host that has NEVER reported a heartbeat is UNKNOWN with EverSeen=false when
// queried explicitly, and is ABSENT from HealthSnapshot (which reports only
// heard-from hosts).
func TestHealthSnapshot_NeverSeenHost_UnknownAndAbsentFromSnapshot(t *testing.T) {
	r, _, _ := newHealthReconciler(t, time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))

	h := r.HostHealth("ghost-host")
	if h.EverSeen {
		t.Fatalf("a never-heard-from host must report EverSeen=false")
	}
	if h.Liveness != HostUnknown {
		t.Fatalf("a never-heard-from host must be UNKNOWN; got %q", h.Liveness)
	}
	if !h.LastBeat.IsZero() {
		t.Fatalf("a never-seen host must have a zero LastBeat; got %v", h.LastBeat)
	}
	if h.SinceLastBeat != 0 {
		t.Fatalf("a never-seen host must have a zero SinceLastBeat; got %v", h.SinceLastBeat)
	}

	// It is not invented into the snapshot (no lastBeat entry).
	if snap := r.HealthSnapshot(); len(snap) != 0 {
		t.Fatalf("snapshot of a reconciler that heard from no host must be empty; got %d entries", len(snap))
	}
}

// HealthSnapshot reports one entry per heard-from host, sorted by HostID, mixing
// LIVE and UNKNOWN correctly in a single point-in-time read.
func TestHealthSnapshot_MixedFleet_SortedAndClassified(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, &recordingAlarmer{}, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// host-c beats first, then goes silent for the whole run.
	if err := r.Observe(context.Background(), heartbeat("host-c")); err != nil {
		t.Fatalf("Observe host-c: %v", err)
	}
	clk.advance(20 * time.Second) // host-c now 20s silent (> 15s window) → UNKNOWN

	// host-a and host-b beat just now → LIVE.
	if err := r.Observe(context.Background(), heartbeat("host-a")); err != nil {
		t.Fatalf("Observe host-a: %v", err)
	}
	if err := r.Observe(context.Background(), heartbeat("host-b")); err != nil {
		t.Fatalf("Observe host-b: %v", err)
	}

	snap := r.HealthSnapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot must have one entry per heard-from host; got %d", len(snap))
	}
	// Sorted by HostID.
	if snap[0].HostID != "host-a" || snap[1].HostID != "host-b" || snap[2].HostID != "host-c" {
		t.Fatalf("snapshot must be sorted by HostID; got %q,%q,%q", snap[0].HostID, snap[1].HostID, snap[2].HostID)
	}
	want := map[string]HostLiveness{"host-a": HostLive, "host-b": HostLive, "host-c": HostUnknown}
	for _, h := range snap {
		if h.Liveness != want[h.HostID] {
			t.Fatalf("%s: liveness = %q, want %q", h.HostID, h.Liveness, want[h.HostID])
		}
	}
}

// A host that flipped UNKNOWN flips back to LIVE on the next heartbeat (the
// annotation is transient — the moment beats resume the host is LIVE again, never
// stuck), proving the read tracks the live lastBeat.
func TestHealthSnapshot_ResumedHeartbeat_FlipsBackToLive(t *testing.T) {
	r, clk, _ := newHealthReconciler(t, time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))

	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe (first): %v", err)
	}
	clk.advance(20 * time.Second) // silent past the window → UNKNOWN
	if h := r.HostHealth("host-1"); h.Liveness != HostUnknown {
		t.Fatalf("expected UNKNOWN after the silence; got %q", h.Liveness)
	}

	// Heartbeats resume.
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe (resumed): %v", err)
	}
	if h := r.HostHealth("host-1"); h.Liveness != HostLive {
		t.Fatalf("a host whose heartbeats resumed must flip back to LIVE; got %q", h.Liveness)
	}
}

// A custom Config (threshold/cadence) is honored: the silence window is
// MissedBeatThreshold * Cadence, and the snapshot's SilenceWindow self-reports it.
func TestHealthSnapshot_CustomConfig_WindowHonored(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	// 2 missed beats * 10s cadence = 20s window.
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, &recordingAlarmer{}, clk.now,
		Config{MissedBeatThreshold: 2, Cadence: 10 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	clk.advance(15 * time.Second) // within the 20s window → LIVE
	h := r.HostHealth("host-1")
	if h.SilenceWindow != 20*time.Second {
		t.Fatalf("SilenceWindow = %v, want 20s (2 * 10s)", h.SilenceWindow)
	}
	if h.Liveness != HostLive {
		t.Fatalf("15s silence within a 20s window must be LIVE; got %q", h.Liveness)
	}
	clk.advance(10 * time.Second) // now 25s > 20s → UNKNOWN
	if h := r.HostHealth("host-1"); h.Liveness != HostUnknown {
		t.Fatalf("25s silence past a 20s window must be UNKNOWN; got %q", h.Liveness)
	}
}

// HealthSnapshotIncluding surfaces an EXPECTED host that has NEVER beaten as an
// EverSeen=false / UNKNOWN entry, UNIONED with the heard-from hosts — the never-seen
// host that the heard-from-only HealthSnapshot deliberately omits is now visible in
// the fleet view, with the IDENTICAL UNKNOWN shape HostHealth returns.
func TestHealthSnapshotIncluding_NeverSeenExpectedHost_SurfacedUnknown(t *testing.T) {
	r, clk, _ := newHealthReconciler(t, time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))

	// host-1 beats and is LIVE; ghost-host is EXPECTED but never beats.
	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	clk.advance(5 * time.Second)

	// The heard-from-only snapshot omits the never-seen host.
	if _, ok := findHealth(r.HealthSnapshot(), "ghost-host"); ok {
		t.Fatalf("HealthSnapshot must NOT invent a never-seen host")
	}

	snap := r.HealthSnapshotIncluding([]string{"ghost-host"})
	if len(snap) != 2 {
		t.Fatalf("union must have the heard-from host plus the expected never-seen host; got %d", len(snap))
	}
	// Sorted by HostID.
	if snap[0].HostID != "ghost-host" || snap[1].HostID != "host-1" {
		t.Fatalf("union must be sorted by HostID; got %q,%q", snap[0].HostID, snap[1].HostID)
	}

	ghost, ok := findHealth(snap, "ghost-host")
	if !ok {
		t.Fatalf("the expected never-seen host must appear in the including-snapshot")
	}
	if ghost.EverSeen {
		t.Fatalf("a never-heard-from expected host must report EverSeen=false")
	}
	if ghost.Liveness != HostUnknown {
		t.Fatalf("a never-heard-from expected host must be UNKNOWN; got %q", ghost.Liveness)
	}
	if !ghost.LastBeat.IsZero() {
		t.Fatalf("a never-seen host must have a zero LastBeat; got %v", ghost.LastBeat)
	}
	if ghost.SinceLastBeat != 0 {
		t.Fatalf("a never-seen host must have a zero SinceLastBeat; got %v", ghost.SinceLastBeat)
	}
	// The never-seen entry matches the explicit HostHealth probe byte-for-byte.
	if probe := r.HostHealth("ghost-host"); probe != ghost {
		t.Fatalf("never-seen union entry must equal HostHealth probe; got %#v vs %#v", ghost, probe)
	}

	// The heard-from host is still classified from its real lastBeat.
	live, _ := findHealth(snap, "host-1")
	if live.Liveness != HostLive || !live.EverSeen {
		t.Fatalf("the heard-from host must stay LIVE/EverSeen; got %q EverSeen=%v", live.Liveness, live.EverSeen)
	}
}

// An expected host that IS actually beating is reported once, from its lastBeat
// entry (the heard-from fact wins) — never mis-reported as a never-seen UNKNOWN, and
// never duplicated even though it appears in BOTH the heard-from set and the
// expectedHostIDs list.
func TestHealthSnapshotIncluding_ExpectedAndHeardFrom_NoDuplicate_HeardFromWins(t *testing.T) {
	r, clk, _ := newHealthReconciler(t, time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))

	if err := r.Observe(context.Background(), heartbeat("host-1")); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	clk.advance(5 * time.Second)

	// host-1 is BOTH expected and heard-from; a duplicate in the expected list too.
	snap := r.HealthSnapshotIncluding([]string{"host-1", "host-1"})
	if len(snap) != 1 {
		t.Fatalf("an expected+heard-from host (even listed twice) must produce exactly one row; got %d", len(snap))
	}
	h := snap[0]
	if h.HostID != "host-1" {
		t.Fatalf("HostID = %q, want host-1", h.HostID)
	}
	if !h.EverSeen || h.Liveness != HostLive {
		t.Fatalf("the heard-from fact must win: want EverSeen=true LIVE; got EverSeen=%v %q", h.EverSeen, h.Liveness)
	}
	if h.SinceLastBeat != 5*time.Second {
		t.Fatalf("SinceLastBeat = %v, want 5s (from the real heartbeat)", h.SinceLastBeat)
	}
}

// HealthSnapshotIncluding is a strict superset of HealthSnapshot when no extra hosts
// are expected: passing the empty/nil expected set returns exactly the heard-from
// snapshot (same order, same entries), and the cheap HealthSnapshot is unaffected.
func TestHealthSnapshotIncluding_NoExpected_EqualsHealthSnapshot(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, &recordingAlarmer{}, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.Observe(context.Background(), heartbeat("host-b")); err != nil {
		t.Fatalf("Observe host-b: %v", err)
	}
	clk.advance(20 * time.Second) // host-b → UNKNOWN
	if err := r.Observe(context.Background(), heartbeat("host-a")); err != nil {
		t.Fatalf("Observe host-a: %v", err)
	}

	base := r.HealthSnapshot()
	for _, expected := range [][]string{nil, {}} {
		got := r.HealthSnapshotIncluding(expected)
		if len(got) != len(base) {
			t.Fatalf("no-expected including-snapshot must match HealthSnapshot length; got %d want %d", len(got), len(base))
		}
		for i := range base {
			if got[i] != base[i] {
				t.Fatalf("no-expected including-snapshot must equal HealthSnapshot entry %d; got %#v want %#v", i, got[i], base[i])
			}
		}
	}

	// An empty reconciler with no expected hosts returns a non-nil empty slice.
	empty := newReconcilerNoHosts(t, clk)
	if got := empty.HealthSnapshotIncluding(nil); got == nil || len(got) != 0 {
		t.Fatalf("empty union must be a non-nil empty slice; got %#v", got)
	}
}

// newReconcilerNoHosts builds a reconciler over the given clock that has heard from
// no host (for the empty-union assertion).
func newReconcilerNoHosts(t *testing.T, clk *fixedClock) *Reconciler {
	t.Helper()
	st := store.NewMemoryClock(clk.now)
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, &recordingAlarmer{}, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// A mixed fleet: heard-from LIVE/UNKNOWN hosts unioned with several never-seen
// expected hosts, all sorted and classified in one point-in-time read.
func TestHealthSnapshotIncluding_MixedFleet_UnionSortedAndClassified(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, &recordingAlarmer{}, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// host-c heard-from then silent → UNKNOWN (seen).
	if err := r.Observe(context.Background(), heartbeat("host-c")); err != nil {
		t.Fatalf("Observe host-c: %v", err)
	}
	clk.advance(20 * time.Second)
	// host-a heard-from just now → LIVE.
	if err := r.Observe(context.Background(), heartbeat("host-a")); err != nil {
		t.Fatalf("Observe host-a: %v", err)
	}

	// Expected (never-seen) hosts: host-b and host-d, plus host-a (already heard-from).
	snap := r.HealthSnapshotIncluding([]string{"host-d", "host-b", "host-a"})
	if len(snap) != 4 {
		t.Fatalf("union must be {host-a,host-b,host-c,host-d}; got %d entries", len(snap))
	}
	gotIDs := []string{snap[0].HostID, snap[1].HostID, snap[2].HostID, snap[3].HostID}
	wantIDs := []string{"host-a", "host-b", "host-c", "host-d"}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("union must be sorted by HostID; got %v want %v", gotIDs, wantIDs)
		}
	}
	type want struct {
		live HostLiveness
		seen bool
	}
	wantMap := map[string]want{
		"host-a": {HostLive, true},     // heard-from, fresh
		"host-b": {HostUnknown, false}, // expected, never seen
		"host-c": {HostUnknown, true},  // heard-from, silent
		"host-d": {HostUnknown, false}, // expected, never seen
	}
	for _, h := range snap {
		w := wantMap[h.HostID]
		if h.Liveness != w.live || h.EverSeen != w.seen {
			t.Fatalf("%s: got %q EverSeen=%v, want %q EverSeen=%v", h.HostID, h.Liveness, h.EverSeen, w.live, w.seen)
		}
	}
}

// RACE: the including-variant is a pure reader that honors the single-goroutine
// lastBeat contract — Observe and HealthSnapshotIncluding are driven on the SAME
// goroutine (serialized, as the controlplane reconcileLoop funnels them), so the
// read never races the lastBeat writes and introduces no second writer. The
// caller-supplied expected set is local input, not shared reconciler state.
func TestHealthSnapshotIncluding_SerializedWithObserve_RaceClean(t *testing.T) {
	r, clk, _ := newHealthReconciler(t, time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))

	for i := 0; i < 50; i++ {
		host := "host-" + string(rune('a'+(i%5)))
		if err := r.Observe(context.Background(), heartbeat(host)); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		// Mix heard-from and never-seen expected hosts, read on the SAME goroutine.
		_ = r.HealthSnapshotIncluding([]string{"ghost-1", "ghost-2", host})
		clk.advance(time.Second)
	}
}

// RACE: the snapshot is a pure reader that honors the single-goroutine lastBeat
// contract — Observe and HealthSnapshot are driven on the SAME goroutine
// (serialized, exactly as the controlplane reconcileLoop funnels them), so the
// read never races the lastBeat writes. Run under `go test -race` this asserts no
// data race AND no second-writer is introduced.
func TestHealthSnapshot_SerializedWithObserve_RaceClean(t *testing.T) {
	r, clk, _ := newHealthReconciler(t, time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))

	for i := 0; i < 50; i++ {
		host := "host-" + string(rune('a'+(i%5)))
		if err := r.Observe(context.Background(), heartbeat(host)); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		// Read on the SAME goroutine, interleaved with the writes (the
		// reconcile-loop single-goroutine contract). -race verifies the read and the
		// lastBeat write do not race.
		_ = r.HealthSnapshot()
		_ = r.HostHealth(host)
		clk.advance(time.Second)
	}
}

// d37HostDensity is the ~500-host fleet density the §3 reconciler is sized for (doc 15 §3;
// D37 sizing; D34 virtual-metal fidelity env): the benchmark pins HealthSnapshotIncluding at
// this scale so the never-seen enrichment
// the admin surface evaluates per /debug/liveness scrape (the union + per-host derivation +
// the stable sort) is characterized at production fleet size, not just the handful of hosts
// the unit tests use. The reconcile loop serves ONE such read per scrape, on its single
// goroutine, so the cost is the loop-time the snapshot steals from convergence — worth a
// scale pin.
const d37HostDensity = 500

// benchHostID renders a stable, zero-padded host_id so the benchmark fleet sorts and dedups
// deterministically (the same shape the union's sort.Slice orders).
func benchHostID(i int) string {
	return "host-" + fmt.Sprintf("%04d", i)
}

// BenchmarkHealthSnapshotIncluding_D37Density characterizes the never-seen liveness union at
// the D37 (sizing); D34 (virtual-metal fidelity env) ~500-host fleet density: HALF the fleet
// has heard-from heartbeats (LIVE/UNKNOWN by
// recency), the OTHER half are EXPECTED-but-never-seen (folded in as EverSeen=false UNKNOWN),
// and the full 500 host_ids are passed as the expected set every call (so the dedup of the
// already-heard-from half is exercised too). This is exactly the admin-surface shape: the
// store-backed ExpectedHostSupplier enumerates every placed host, the loop unions it with the
// heard-from set, derives per-host liveness, and stably sorts — once per scrape. The expected
// slice is rebuilt OUTSIDE the timed loop (the supplier owns that allocation in production);
// the benchmark times the union+derive+sort the loop pays per read.
func BenchmarkHealthSnapshotIncluding_D37Density(b *testing.B) {
	clk := newClock(time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, &recordingAlarmer{}, clk.now, Config{})
	if err != nil {
		b.Fatalf("New: %v", err)
	}

	// Heard-from half: even-indexed hosts beat. Stagger them across the silence window so the
	// derivation hits BOTH the LIVE and UNKNOWN arms (a realistic mixed fleet), not one branch.
	expected := make([]string, 0, d37HostDensity)
	for i := 0; i < d37HostDensity; i++ {
		host := benchHostID(i)
		expected = append(expected, host)
		if i%2 == 0 {
			if err := r.Observe(context.Background(), heartbeat(host)); err != nil {
				b.Fatalf("Observe %s: %v", host, err)
			}
			// Advance a little per heard-from host so some fall outside the 15s window → a
			// mix of LIVE (recent) and UNKNOWN (stale) heard-from entries.
			clk.advance(250 * time.Millisecond)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		snap := r.HealthSnapshotIncluding(expected)
		if len(snap) != d37HostDensity {
			b.Fatalf("union size = %d, want %d (heard-from ∪ expected, deduped)", len(snap), d37HostDensity)
		}
	}
}
