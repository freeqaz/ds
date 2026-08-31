// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"errors"
	"expvar"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/parkstore"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// readParkBootReadopted reads the current value of the published D46 boot RE-ADOPTION metric
// off the global expvar registry (the operator-visible /debug/vars surface). It fails the test
// if the counter is not published under the stable name or is not an *expvar.Int — the boot
// metric MUST be registered.
func readParkBootReadopted(t *testing.T) int64 {
	t.Helper()
	v := expvar.Get(parkBootReadoptedTotalName)
	if v == nil {
		t.Fatalf("expvar %q is not published — the D46 boot re-adoption metric must be registered", parkBootReadoptedTotalName)
	}
	iv, ok := v.(*expvar.Int)
	if !ok {
		t.Fatalf("expvar %q = %T, want *expvar.Int (the boot re-adoption counter)", parkBootReadoptedTotalName, v)
	}
	return iv.Value()
}

// rung2Ask is a synthetic genuine rung-2 ask (the class that PARKS per D46) — the
// only ask the park machine accepts. Synthetic only (D50): no live IO.
func rung2Ask() askhold.Ask {
	return askhold.Ask{
		ResourceKind:  "service",
		ResourceName:  "bulk-delete",
		MatchedRuleID: "rule-suspend",
		Rung2:         true,
	}
}

// TestParkMachine_ParkThenResume drives the in-memory machine end to end through a
// real parkstore backing: a rung-2 ask parks (RecordParked persists the durable
// join, the machine tracks it), Lookup finds it, and a human answer resumes it
// (ClearParked clears the join, the machine drops it). It never times out into
// allow or kill — the resume is driven by the verdict.
func TestParkMachine_ParkThenResume(t *testing.T) {
	parkedAt := time.Date(2026, 6, 16, 9, 0, 0, 0, time.UTC)
	backing := parkstore.NewMemory()
	m := newParkMachine(backing)

	parked, err := m.Park("sess-7", rung2Ask(), parkedAt)
	if err != nil {
		t.Fatalf("Park: %v", err)
	}
	if parked.Phase != askhold.ParkPhaseParked {
		t.Fatalf("parked ask must be PARKED, got %v", parked.Phase)
	}
	if m.Len() != 1 {
		t.Fatalf("machine must track the one outstanding park, len=%d", m.Len())
	}
	if got, ok := m.Lookup("sess-7"); !ok || got.SessionUUID != "sess-7" {
		t.Fatalf("Lookup must find the parked ask, got %+v ok=%v", got, ok)
	}
	// The park is ALSO durable in the backing (RecordParked was driven through it).
	if durable, err := backing.List(); err != nil {
		t.Fatalf("backing List: %v", err)
	} else if len(durable) != 1 || durable[0].SessionUUID != "sess-7" {
		t.Fatalf("backing must durably record the join, got %+v", durable)
	}

	answeredAt := parkedAt.Add(2 * time.Hour)
	resumed, err := m.Resume("sess-7", askhold.ResumeVerdictAllow, "allow-once:service/bulk-delete;ttl=session", askhold.DenyReason{}, answeredAt)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if resumed.Phase != askhold.ParkPhaseResumed || resumed.Verdict != askhold.ResumeVerdictAllow {
		t.Fatalf("resume must carry the human ALLOW answer; phase=%v verdict=%v", resumed.Phase, resumed.Verdict)
	}
	if m.Len() != 0 {
		t.Fatalf("a resumed park must drain the machine, len=%d", m.Len())
	}
	if _, ok := m.Lookup("sess-7"); ok {
		t.Fatalf("a resumed ask must be absent from the machine")
	}
	// The durable join is cleared too (ClearParked was driven through the backing).
	if durable, err := backing.List(); err != nil {
		t.Fatalf("post-resume backing List: %v", err)
	} else if len(durable) != 0 {
		t.Fatalf("a resumed park must clear the durable join, got %+v", durable)
	}
}

// TestParkMachine_RestartReAdoptResume is the HEADLINE restart-survival assertion
// (D46 / doc 15 §3 RecoverSessions): a rung-2 ask is parked through the durable
// backing, then the control plane "restarts" (we drop the in-memory machine but
// KEEP the durable backing, the stand-in for rows that outlive the process), the
// boot re-adoption sweep RE-READS the backing's List() into a fresh machine, and a
// human answer then resolves the re-adopted park — never timing out into allow or
// kill. After the resume the durable join is cleared.
func TestParkMachine_RestartReAdoptResume(t *testing.T) {
	parkedAt := time.Date(2026, 6, 16, 8, 0, 0, 0, time.UTC)

	// --- epoch #1: park the ask through the durable backing. ---
	backing := parkstore.NewMemory()
	epoch1 := newParkMachine(backing)
	if _, err := epoch1.Park("sess-42", rung2Ask(), parkedAt); err != nil {
		t.Fatalf("epoch#1 Park: %v", err)
	}
	if epoch1.Len() != 1 {
		t.Fatalf("epoch#1 machine must track the park, len=%d", epoch1.Len())
	}

	// --- CONTROL-PLANE RESTART: the epoch#1 machine is gone; only the durable
	// backing survives. A fresh machine is built and the boot sweep re-adopts the
	// outstanding parks from the SAME backing's List(). ---
	epoch2 := newParkMachine(backing)
	if epoch2.Len() != 0 {
		t.Fatalf("a fresh machine starts empty before re-adoption, len=%d", epoch2.Len())
	}
	adopted := reAdoptParks(backing, epoch2, nil)
	if adopted != 1 {
		t.Fatalf("boot re-adoption must re-adopt the one outstanding park, adopted=%d", adopted)
	}
	if epoch2.Len() != 1 {
		t.Fatalf("re-adopted machine must hold the park, len=%d", epoch2.Len())
	}
	reread, ok := epoch2.Lookup("sess-42")
	if !ok {
		t.Fatalf("a parked ask MUST survive a restart — the re-adopted machine has no entry")
	}
	if reread.Phase != askhold.ParkPhaseParked {
		t.Fatalf("re-adopted ask must still be PARKED (never timed out into allow/kill); phase=%v", reread.Phase)
	}
	if reread.Verdict != askhold.ResumeVerdictUnspecified {
		t.Fatalf("a survived park must carry NO verdict (no timeout-allow/kill); verdict=%v", reread.Verdict)
	}

	// --- the human answer finally arrives (out-of-band on the policy stream),
	// resolved THROUGH the re-adopted machine — proving a human answer still
	// resolves a park post-restart. A long pause before the answer changes
	// nothing. ---
	answeredAt := parkedAt.Add(3 * time.Hour)
	resumed, err := epoch2.Resume("sess-42", askhold.ResumeVerdictAllow, "allow-once:service/bulk-delete;ttl=session", askhold.DenyReason{}, answeredAt)
	if err != nil {
		t.Fatalf("resume of the re-adopted park: %v", err)
	}
	if resumed.Phase != askhold.ParkPhaseResumed || resumed.Verdict != askhold.ResumeVerdictAllow {
		t.Fatalf("resume must carry the human ALLOW answer; phase=%v verdict=%v", resumed.Phase, resumed.Verdict)
	}
	if epoch2.Len() != 0 {
		t.Fatalf("a resumed park must drain the machine, len=%d", epoch2.Len())
	}
	// The durable join is cleared, so a SECOND restart re-adopts nothing.
	if durable, err := backing.List(); err != nil {
		t.Fatalf("post-resume backing List: %v", err)
	} else if len(durable) != 0 {
		t.Fatalf("a resumed park must clear the durable join, got %+v", durable)
	}
	epoch3 := newParkMachine(backing)
	if again := reAdoptParks(backing, epoch3, nil); again != 0 {
		t.Fatalf("a second restart must re-adopt nothing after the resume, adopted=%d", again)
	}
}

// TestParkMachine_RestartReAdoptResumeDeny proves the deny arm survives a restart
// too: a re-adopted park resumes on a human DENY answer carrying the D77
// machine-readable reason (never a timeout), and the durable join clears.
func TestParkMachine_RestartReAdoptResumeDeny(t *testing.T) {
	parkedAt := time.Date(2026, 6, 16, 7, 0, 0, 0, time.UTC)
	backing := parkstore.NewMemory()
	if _, err := newParkMachine(backing).Park("sess-deny", rung2Ask(), parkedAt); err != nil {
		t.Fatalf("Park: %v", err)
	}

	// Restart: re-adopt into a fresh machine.
	m := newParkMachine(backing)
	if adopted := reAdoptParks(backing, m, nil); adopted != 1 {
		t.Fatalf("re-adoption must recover the park, adopted=%d", adopted)
	}

	reason := askhold.DenyReason{Code: askhold.DenyUnattended, MatchedRuleID: "rule-suspend", ResourceKind: "service", ResourceName: "bulk-delete"}
	resumed, err := m.Resume("sess-deny", askhold.ResumeVerdictDeny, "", reason, parkedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("Resume(deny): %v", err)
	}
	if resumed.Verdict != askhold.ResumeVerdictDeny || resumed.DenyReason.Code != askhold.DenyUnattended {
		t.Fatalf("resume must carry the human DENY answer + reason; %+v", resumed)
	}
	if m.Len() != 0 {
		t.Fatalf("a denied resume must drain the machine, len=%d", m.Len())
	}
}

// TestParkMachine_ResumeUnknownSessionRefused proves the machine's own guard: a
// human answer for a session not currently parked (a never-parked / already-
// resumed / unknown session) is refused — there is no parked ask to resolve.
func TestParkMachine_ResumeUnknownSessionRefused(t *testing.T) {
	m := newParkMachine(parkstore.NewMemory())
	_, err := m.Resume("ghost", askhold.ResumeVerdictAllow, "scope", askhold.DenyReason{}, time.Now())
	if !errors.Is(err, errNotParkedInMachine) {
		t.Fatalf("resume of an unknown session must be refused with errNotParkedInMachine, got %v", err)
	}
}

// TestParkMachine_RejectsNonRung2 proves a non-rung-2 ask (an ordinary
// unknown-domain ask, which socket-holds rather than parks) is refused by the
// machine and NOT tracked — askhold owns the rung-2 gate, the machine honors it.
func TestParkMachine_RejectsNonRung2(t *testing.T) {
	m := newParkMachine(parkstore.NewMemory())
	ask := rung2Ask()
	ask.Rung2 = false
	if _, err := m.Park("sess-ord", ask, time.Now()); err == nil {
		t.Fatalf("Park must refuse a non-rung-2 ask")
	}
	if m.Len() != 0 {
		t.Fatalf("a refused non-rung-2 ask must not be tracked, len=%d", m.Len())
	}
}

// TestParkMachine_RecordFaultStillTracks proves the askhold fault asymmetry holds
// through the machine: a RecordParked fault (here an empty session UUID, the
// recorder's empty-key guard) leaves the ask STILL PARKED and STILL TRACKED — the
// fault means only "the durable write did not land, retry it," never "un-park."
func TestParkMachine_RecordFaultStillTracks(t *testing.T) {
	backing := &faultyRecord{Memory: parkstore.NewMemory()}
	m := newParkMachine(backing)
	parked, err := m.Park("sess-fault", rung2Ask(), time.Now())
	if err == nil {
		t.Fatalf("a record fault must surface")
	}
	if parked.Phase != askhold.ParkPhaseParked {
		t.Fatalf("a record fault must NOT un-park; phase=%v", parked.Phase)
	}
	if m.Len() != 1 {
		t.Fatalf("a still-parked ask must remain tracked despite the record fault, len=%d", m.Len())
	}
}

// faultyRecord wraps a parkstore.Memory and forces RecordParked to fault, so the
// machine's fault-asymmetry handling is exercised without a live backing (D50).
type faultyRecord struct{ *parkstore.Memory }

func (f *faultyRecord) RecordParked(p askhold.Parked) error {
	return errors.New("synthetic record fault")
}

// TestReAdoptParks_BackingFaultBestEffort proves the boot sweep is best-effort: a
// backing List() fault leaves the machine empty for this cycle (the durable join is
// retained for the next assembly) and never fails the boot.
func TestReAdoptParks_BackingFaultBestEffort(t *testing.T) {
	m := newParkMachine(parkstore.NewMemory())
	if adopted := reAdoptParks(faultyList{}, m, nil); adopted != 0 {
		t.Fatalf("a backing List() fault must re-adopt nothing, adopted=%d", adopted)
	}
	if m.Len() != 0 {
		t.Fatalf("a faulted sweep must leave the machine empty, len=%d", m.Len())
	}
}

// TestReAdoptParks_SurfacesBootMetric proves the boot re-adoption COUNT surfaces as the
// operator-visible /debug/vars metric: re-adopting N outstanding durable parks raises the
// published orchestrator_park_boot_readopted_total by exactly N (cumulative, Add-not-Set), so
// an operator can confirm a restart recovered the parked rung-2 asks the backing held (doc 15
// §3 / doc 16 §8.2 / D46). It asserts the DELTA (the counter is process-global and other tests
// in this package also re-adopt), and that a no-op sweep (nothing outstanding) leaves it flat.
func TestReAdoptParks_SurfacesBootMetric(t *testing.T) {
	parkedAt := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)

	// Seed a durable backing with three outstanding parks (recorded by a prior epoch).
	backing := parkstore.NewMemory()
	seed := newParkMachine(backing)
	for _, s := range []string{"sess-m1", "sess-m2", "sess-m3"} {
		if _, err := seed.Park(s, rung2Ask(), parkedAt); err != nil {
			t.Fatalf("seed park %q: %v", s, err)
		}
	}

	before := readParkBootReadopted(t)

	// Restart: re-adopt the three outstanding parks into a fresh machine.
	machine := newParkMachine(backing)
	if adopted := reAdoptParks(backing, machine, nil); adopted != 3 {
		t.Fatalf("boot re-adoption must re-adopt the three outstanding parks, adopted=%d", adopted)
	}

	if got := readParkBootReadopted(t); got-before != 3 {
		t.Fatalf("boot metric must rise by the re-adopted count: delta=%d, want 3 (before=%d after=%d)", got-before, before, got)
	}

	// A second sweep over the SAME backing (still holding the three parks, the machine already
	// tracks them) re-adopts them again — the metric is cumulative, so it rises by another 3.
	mid := readParkBootReadopted(t)
	machine2 := newParkMachine(backing)
	if adopted := reAdoptParks(backing, machine2, nil); adopted != 3 {
		t.Fatalf("a second assembly must re-adopt the same three parks, adopted=%d", adopted)
	}
	if got := readParkBootReadopted(t); got-mid != 3 {
		t.Fatalf("the boot metric must be cumulative across assemblies: delta=%d, want 3", got-mid)
	}

	// A no-op sweep (empty backing) adds nothing — the counter only moves on a real re-adoption.
	flat := readParkBootReadopted(t)
	if adopted := reAdoptParks(parkstore.NewMemory(), newParkMachine(parkstore.NewMemory()), nil); adopted != 0 {
		t.Fatalf("an empty backing must re-adopt nothing, adopted=%d", adopted)
	}
	if got := readParkBootReadopted(t); got != flat {
		t.Fatalf("a no-op sweep must not move the boot metric: before=%d after=%d", flat, got)
	}
}

// TestReAdoptParks_NilArgsNoop proves the sweep no-ops on a nil reader or machine
// (the decision-only posture wired no durable backing — nothing to re-adopt).
func TestReAdoptParks_NilArgsNoop(t *testing.T) {
	if adopted := reAdoptParks(nil, newParkMachine(parkstore.NewMemory()), nil); adopted != 0 {
		t.Fatalf("a nil reader must re-adopt nothing, adopted=%d", adopted)
	}
	if adopted := reAdoptParks(parkstore.NewMemory(), nil, nil); adopted != 0 {
		t.Fatalf("a nil machine must re-adopt nothing, adopted=%d", adopted)
	}
}

// faultyList is a parkReadAdopter whose List() always faults, for the best-effort
// boot-sweep assertion (D50: no live backing).
type faultyList struct{}

func (faultyList) List() ([]askhold.Parked, error) {
	return nil, errors.New("synthetic backing list fault")
}

// TestNewControlPlane_WiresParkMachine proves the WIRING contract: NewControlPlane
// injects a parkstore backing as the askhold.ParkRecorder behind a non-nil park
// machine, and the boot re-adoption runs over it. Wiring an injected backing that
// ALREADY carries an outstanding park (the restart case — the durable join from a
// prior epoch) proves the assembly re-adopts it into the running machine, so a
// human answer resolves it post-restart.
func TestNewControlPlane_WiresParkMachine(t *testing.T) {
	parkedAt := time.Date(2026, 6, 16, 6, 0, 0, 0, time.UTC)

	// A durable backing that already holds an outstanding park (recorded by a prior
	// control-plane epoch before this assembly — the restart-survival input).
	backing := parkstore.NewMemory()
	if _, err := newParkMachine(backing).Park("sess-prior", rung2Ask(), parkedAt); err != nil {
		t.Fatalf("seed prior-epoch park: %v", err)
	}

	deps := baseParkDeps()
	deps.ParkRecorder = backing
	cp, err := NewControlPlane(deps)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	if cp.ParkMachine == nil {
		t.Fatalf("NewControlPlane must wire a non-nil park machine")
	}
	// The boot re-adoption re-adopted the prior-epoch park into the running machine.
	if cp.ParkMachine.Len() != 1 {
		t.Fatalf("boot re-adoption must re-adopt the prior park, len=%d", cp.ParkMachine.Len())
	}
	if _, ok := cp.ParkMachine.Lookup("sess-prior"); !ok {
		t.Fatalf("the re-adopted machine must hold the prior-epoch park")
	}

	// A human answer post-restart resolves it through the wired machine, clearing
	// the durable join.
	if _, err := cp.ParkMachine.Resume("sess-prior", askhold.ResumeVerdictAllow, "allow-once", askhold.DenyReason{}, parkedAt.Add(time.Hour)); err != nil {
		t.Fatalf("post-restart resume through the wired machine: %v", err)
	}
	if cp.ParkMachine.Len() != 0 {
		t.Fatalf("the resume must drain the wired machine, len=%d", cp.ParkMachine.Len())
	}
	if durable, err := backing.List(); err != nil {
		t.Fatalf("backing List: %v", err)
	} else if len(durable) != 0 {
		t.Fatalf("the resume must clear the durable join, got %+v", durable)
	}
}

// TestNewControlPlane_DefaultsParkRecorder proves the optional Deps.ParkRecorder
// defaults to a fresh in-process parkstore.NewMemory() when nil — the park machine
// is still wired (durable within the process), so a deployment that wires no
// backing still gets a usable, re-adoptable park machine (D50 reference posture).
func TestNewControlPlane_DefaultsParkRecorder(t *testing.T) {
	cp, err := NewControlPlane(baseParkDeps())
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	if cp.ParkMachine == nil {
		t.Fatalf("a nil Deps.ParkRecorder must still wire a (default-backed) park machine")
	}
	if cp.ParkMachine.Len() != 0 {
		t.Fatalf("a default in-process backing starts with no outstanding parks, len=%d", cp.ParkMachine.Len())
	}
	// The default-backed machine is fully usable: a park + resume round-trips.
	if _, err := cp.ParkMachine.Park("sess-new", rung2Ask(), time.Now()); err != nil {
		t.Fatalf("Park on the default-backed machine: %v", err)
	}
	if cp.ParkMachine.Len() != 1 {
		t.Fatalf("the default-backed machine must track the park, len=%d", cp.ParkMachine.Len())
	}
}

// baseParkDeps is a minimal wired Deps that satisfies NewControlPlane's required
// backends (the same fakes the wiring tests use), for the park-wiring assertions.
// It threads NO ParkRecorder so each test sets it (or leaves it nil to exercise the
// default). Synthetic fixtures + in-process fakes only (D50).
func baseParkDeps() Deps {
	return Deps{
		Store:      cpStore{store.NewMemory()},
		Drivers:    fakeRegistry{host: testHostID, drv: newDriverFake()},
		Mint:       &fakeMint{},
		Digest:     &fakeDigest{acked: true},
		Inject:     &fakeInject{},
		Boot:       &fakeBoot{},
		Revoke:     &fakeRevoke{},
		Enrollment: fakeEnrollment{repoID: testRepoID, ok: true},
		Roles:      sessions.DefaultRoleResolver{CurrentVersion: "2026.06.11-v1", ContentHash: testRoleHashSeed},
	}
}
