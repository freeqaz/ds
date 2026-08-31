// SPDX-License-Identifier: Apache-2.0

package controlplane

// parkadoption.go — the CONTROL-PLANE PARK MACHINE plus the BOOT RE-ADOPTION
// SWEEP that makes the durable parkstore the SYSTEM OF RECORD for the D46
// session<->question join across an orchestrator restart (doc 16 §8.2, doc 15
// §3/§5.6 RecoverSessions re-adoption).
//
// WHAT askhold OWNS vs WHAT THIS OWNS. askhold (park.go) owns the PARK/RESUME
// state machine: NewParked enters the untimed park and Resume ends it on a human
// answer, each driving an INJECTED askhold.ParkRecorder (RecordParked /
// ClearParked). parkstore.Store implements that recorder durably (Memory in the
// stdlib-only reference posture, SQL behind the same seam). This file owns the
// IN-MEMORY PARK MACHINE the control plane actually runs: the live set of
// outstanding asks keyed by session UUID, the recorder it drives, and the boot
// re-adoption that re-reads the durable backing so a park outlives a real
// control-plane restart.
//
// THE PROBLEM IT CLOSES (D46 restart survival). The park machine's live set is
// IN-PROCESS only (a map). An orchestrator restart loses it — but the DURABLE
// join each outstanding park wrote through the recorder SURVIVES (the parkstore
// backing). Without a boot re-adoption, a genuine rung-2 ask that parked before a
// restart would be lost from the running machine, so a later human answer would
// have no parked ask to resume — the load-bearing D46/D77 promise (a parked ask
// NEVER times out into allow or kill; it resumes on answer) would silently break
// across the restart window. The reconciler does not cover this: it converges VM
// presence, not the ask<->question join.
//
// THE FIX (doc 15 §3 RecoverSessions shape / D35). On control-plane assembly
// (NewControlPlane, right after the park/resume driver is constructed) we
// enumerate Store.List() — every outstanding (still-parked, not-yet-cleared)
// join — and RE-ADOPT each into a fresh in-memory park machine. A human answer
// arriving post-restart then finds the parked ask in the running machine and
// resolves it through Resume exactly as before, clearing the durable join. The
// sweep is purely additive to the boot path: it lists, re-adopts, and returns; it
// never mutates the durable backing (re-adoption is a READ — RecordParked is NOT
// re-driven, the join is already recorded), never blocks, and a backing read
// fault is logged and tolerated (best-effort boot bookkeeping — the durable join
// remains, so the next assembly re-reads it).
//
// SYNTHETIC ONLY (D50). The reference recorder is parkstore.Memory (a
// process-local map); restart survival is exercised in tests by re-reading the
// SAME Memory value after a recording call returns (the durable backing's
// stand-in). No live IO, no clocks of its own — the caller stamps `now`.

import (
	"expvar"
	"log/slog"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/parkstore"
)

// parkBootReadoptedTotalName is the stable /debug/vars name of the D46 BOOT RE-ADOPTION
// metric. It is exported as a const so the wiring/admin surface and the test reference the
// SAME published name rather than a duplicated string literal.
const parkBootReadoptedTotalName = "orchestrator_park_boot_readopted_total"

// parkBootReadoptedTotal is the D46 boot RE-ADOPTION COUNTER (doc 15 §3 RecoverSessions /
// doc 16 §8.2): the CUMULATIVE number of outstanding durable parks reAdoptParks has
// re-adopted into a fresh in-memory park machine across every control-plane assembly. An
// operator reads it off /debug/vars to confirm a restart recovered the parked genuine
// rung-2 asks the durable backing held (the load-bearing D46/D77 promise — a parked ask
// NEVER times out into allow or kill; it survives the restart and resumes on a human
// answer). It is REGISTERED ONCE under the stable name at package init (the same expvar
// discipline sessions.step9FreshnessDegradeTotal follows); the boot sweep only ADDS to it,
// so it monotonically reflects the fleet's re-adoptions since process start.
var parkBootReadoptedTotal = expvar.NewInt(parkBootReadoptedTotalName)

// parkReadAdopter is the NARROW read seam the boot sweep depends on: enumerate the
// outstanding durable parks so the sweep can re-adopt each into the in-memory
// machine. It is a slice of the parkstore.Store surface (List) — *parkstore.Memory
// / *parkstore.SQL satisfy it natively and tests wire a synthetic fake — so the
// sweep adds NO method to the Store seam (the same storeseams discipline the
// mint-expiry boot re-arm follows).
type parkReadAdopter interface {
	List() ([]askhold.Parked, error)
}

// ParkRecorderStore is the durable park backing the wiring injects: the
// askhold.ParkRecorder the park machine drives transitions through PLUS the
// List() read the boot re-adoption sweep needs (parkReadAdopter). It is exactly
// the slice of parkstore.Store the control-plane park path consumes — every
// parkstore.Store (Memory, the SQL twin) satisfies it natively, so a deployment
// fronts whichever backing behind this one seam. It is exported because it types
// the optional Deps.ParkRecorder field (wiring.go); the parkstore package owns the
// concrete backings.
type ParkRecorderStore interface {
	askhold.ParkRecorder
	parkReadAdopter
}

// parkMachine is the control plane's IN-MEMORY PARK MACHINE: the live set of
// outstanding rung-2 asks (askhold.Parked keyed by session UUID) plus the
// INJECTED askhold.ParkRecorder (the durable parkstore backing) every transition
// drives through. askhold owns the state DECISION (NewParked / Resume); this owns
// the running set and routes each transition through the recorder so the durable
// join stays the system of record. It is safe for concurrent use.
//
// The recorder is the askhold.ParkRecorder seam, so the machine is wired with
// whichever parkstore backing the deployment chose (Memory in the reference
// posture, SQL behind the same seam) without knowing which it got. A nil recorder
// is tolerated end to end — askhold's NewParked/Resume already tolerate it (the
// decision still stands; only the durable record is skipped) — so the machine is
// unit-testable with no backing at all, though the restart-survival path needs a
// real backing to re-adopt from.
type parkMachine struct {
	recorder askhold.ParkRecorder

	mu sync.Mutex
	// parked is the live in-memory set keyed by SessionUUID. It holds ONLY
	// outstanding (still-parked) asks — a Resume removes the entry, mirroring the
	// durable backing's clear, so the running machine and the durable join agree on
	// exactly which asks await a human answer.
	parked map[string]askhold.Parked
}

// newParkMachine constructs an empty in-memory park machine driving the given
// recorder. recorder may be nil (the decision-only posture — see parkMachine); a
// real parkstore backing makes the restart-survival path durable.
func newParkMachine(recorder askhold.ParkRecorder) *parkMachine {
	return &parkMachine{
		recorder: recorder,
		parked:   make(map[string]askhold.Parked),
	}
}

// Park enters a GENUINE rung-2 ask into the park machine: it drives askhold's
// untimed-park decision through the injected recorder (RecordParked persists the
// durable join) and tracks the resulting Parked in the live in-memory set keyed by
// session UUID. It returns the entered Parked and any recorder error.
//
// FAULT POSTURE (inherited from askhold). A recorder RecordParked fault NEVER
// un-parks the ask: askhold has already entered the PARKED (safe) state, so the
// returned Parked is STILL PARKED and the machine STILL tracks it — the error
// means only "the durable write did not land, retry it." We therefore track the
// ask on a record fault too: dropping it from the running set on a durable-write
// retry would lose a genuinely-parked ask (the asymmetry askhold guarantees). A
// non-rung-2 ask is refused by askhold (errNotRung2) and is NOT tracked.
func (m *parkMachine) Park(sessionUUID string, ask askhold.Ask, now time.Time) (askhold.Parked, error) {
	p, err := askhold.NewParked(m.recorder, sessionUUID, ask, now)
	if err != nil {
		// A non-rung-2 refusal returns a zero, unparked Parked — do NOT track it. A
		// recorder fault returns a STILL-PARKED Parked (Phase ParkPhaseParked) — track
		// it so a record retry never loses the park.
		if p.Phase != askhold.ParkPhaseParked {
			return p, err
		}
		m.track(p)
		return p, err
	}
	m.track(p)
	return p, nil
}

// Resume ends a parked ask because a HUMAN ANSWER arrived (out-of-band on the
// policy stream — never a timeout): it drives askhold's Parked.Resume through the
// injected recorder (ClearParked removes the durable join) and removes the ask
// from the live in-memory set. It returns the resumed Parked (carrying the
// verdict + opaque grant scope / deny reason) and any recorder error.
//
// It refuses a session not currently parked in the machine (a double-resume or a
// never-parked / already-resumed session) — there is no parked ask to resume. A
// recorder ClearParked fault surfaces but the resume STILL stands (askhold
// resumed the ask; only the durable clear can be retried), so the entry is
// removed from the running set regardless — the ask is resolved, not re-parked.
func (m *parkMachine) Resume(sessionUUID string, verdict askhold.ResumeVerdict, scope string, reason askhold.DenyReason, now time.Time) (askhold.Parked, error) {
	m.mu.Lock()
	current, ok := m.parked[sessionUUID]
	m.mu.Unlock()
	if !ok {
		return askhold.Parked{}, errNotParkedInMachine
	}

	resumed, err := current.Resume(m.recorder, verdict, scope, reason, now)
	if err != nil {
		// askhold refused (not-parked / no-verdict) — the in-memory state did not
		// transition, so leave the entry tracked. A nil-verdict / double-resume must
		// not silently drop the still-parked ask.
		if resumed.Phase != askhold.ParkPhaseResumed {
			return resumed, err
		}
		// A recorder ClearParked fault — askhold STILL resumed the ask; drop the entry
		// (it is resolved, not re-parked) and surface the clear error for retry.
		m.untrack(sessionUUID)
		return resumed, err
	}
	m.untrack(sessionUUID)
	return resumed, nil
}

// Lookup reports the currently-parked ask for a session in the running machine,
// and whether one is present. It reads the IN-MEMORY set (the running machine),
// not the durable backing — a resumed/never-parked session is absent. It is the
// keyed read the resume path uses to find the parked ask a human answer targets.
func (m *parkMachine) Lookup(sessionUUID string) (askhold.Parked, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.parked[sessionUUID]
	return p, ok
}

// Len reports how many asks are currently parked in the running machine. It
// exists so the wiring test can assert the boot re-adoption populated the machine
// (and a resume drained it) without reaching into the unexported map directly.
func (m *parkMachine) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.parked)
}

// track records an outstanding park in the live in-memory set under its session
// UUID. A zero/empty SessionUUID is skipped (no join key) so the map never grows a
// keyless entry — the recorder already guards the empty-key write the same way.
func (m *parkMachine) track(p askhold.Parked) {
	if p.SessionUUID == "" {
		return
	}
	m.mu.Lock()
	m.parked[p.SessionUUID] = p
	m.mu.Unlock()
}

// untrack removes a session's entry from the live in-memory set (a resume drained
// it). Removing an absent entry is a no-op.
func (m *parkMachine) untrack(sessionUUID string) {
	m.mu.Lock()
	delete(m.parked, sessionUUID)
	m.mu.Unlock()
}

// adopt re-installs an already-recorded outstanding park into the running machine
// WITHOUT re-driving the recorder (the durable join is already there — re-adoption
// is a READ). It is the boot-sweep's per-record install: it tracks the Parked the
// durable List() returned so a post-restart human answer finds it. A non-parked
// (already-resumed) or keyless record is skipped — the backing should only return
// outstanding joins, but the sweep never re-adopts a resumed/keyless one.
func (m *parkMachine) adopt(p askhold.Parked) bool {
	if p.SessionUUID == "" || p.Phase != askhold.ParkPhaseParked {
		return false
	}
	m.track(p)
	return true
}

// errNotParkedInMachine is returned by Resume for a session not currently parked
// in the running machine (a double-resume, or a never-parked / already-resumed
// session). It mirrors askhold's errNotParked but is the MACHINE's guard (the map
// has no entry) — surfaced before askhold's own decision so a human answer for an
// unknown session fails cleanly rather than transitioning a zero Parked.
var errNotParkedInMachine = parkError("controlplane: resume requires a session currently parked in the machine")

// parkError is the package-local sentinel error type for the park machine's own
// guards (stdlib-only — no third-party errors package). It mirrors askhold's
// parkError shape so the two read alike.
type parkError string

func (e parkError) Error() string { return string(e) }

// reAdoptParks is the BOOT RE-ADOPTION SWEEP (doc 15 §3 RecoverSessions shape /
// D46 restart survival). It enumerates the durable outstanding parks (Store.List())
// and re-adopts each into the in-memory park machine the restart lost — making the
// durable parkstore join the system of record across restarts. It returns the
// number of parks re-adopted (for the caller's boot log + the test's assertion).
//
// PURELY ADDITIVE / BEST-EFFORT. It LISTS (a read — RecordParked is not re-driven;
// the join is already durable) and re-adopts, never mutating the backing and never
// blocking. A nil reader or machine is a no-op (the decision-only posture wired no
// durable backing — nothing to re-adopt). A backing List() fault is logged and
// tolerated: the durable join remains, so the next assembly re-reads it and the
// reconciler is unaffected; the boot is NEVER failed on it. A record the backing
// returns that is not actually outstanding (resumed / keyless) is skipped by
// adopt() — defense in depth, since a well-behaved backing returns only
// outstanding joins.
func reAdoptParks(reader parkReadAdopter, machine *parkMachine, logger *slog.Logger) int {
	if logger == nil {
		logger = slog.Default()
	}
	if reader == nil || machine == nil {
		return 0
	}

	outstanding, err := reader.List()
	if err != nil {
		// Best-effort: a boot-time backing fault leaves the in-memory machine empty for
		// this cycle; the DURABLE join remains, so the next assembly re-reads it and a
		// human answer still resolves the ask once re-adopted. Never fail the boot on it.
		logger.Warn("controlplane: park boot re-adopt: list outstanding parks failed — machine not re-adopted this cycle (durable join retained)",
			slog.Any("err", err))
		return 0
	}

	adopted := 0
	for _, p := range outstanding {
		if machine.adopt(p) {
			adopted++
		}
	}

	if adopted > 0 {
		// Surface the re-adopted count as the operator-visible boot metric (/debug/vars):
		// a non-zero increment after a restart is the proof a parked rung-2 ask was
		// recovered from the durable backing rather than silently lost. The counter is
		// cumulative across assemblies (Add, never Set), so a second assembly that
		// re-adopts more parks raises it further.
		parkBootReadoptedTotal.Add(int64(adopted))
		logger.Info("controlplane: park boot re-adopt: re-adopted outstanding parks across restart (doc 15 §3 / D46)",
			slog.Int("adopted", adopted))
	}
	return adopted
}

// Compile-time proof *parkstore.Memory satisfies the narrow boot-sweep read seam
// (it satisfies the full parkstore.Store, of which parkReadAdopter is a slice), so
// the production wiring hands the SAME durable backing the askhold recorder writes
// through to the boot re-adoption that reads it back.
var _ parkReadAdopter = (*parkstore.Memory)(nil)
