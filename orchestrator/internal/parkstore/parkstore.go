// SPDX-License-Identifier: Apache-2.0

// Package parkstore is the DURABLE backing for the D46 session<->question join
// behind the askhold.ParkRecorder seam (doc 16 §8.2: "The ask-routing record
// joining a parked session to its pending question is an orchestrator-doc
// seam"). askhold owns the PARK/RESUME state machine and decides the
// transitions; this package owns the record store those transitions write
// through.
//
// Why this exists — restart survival. A genuine rung-2 ask PARKS and stays
// PARKED until a human answer arrives; it NEVER times out into allow or kill
// (D46/D77, askhold/doc.go). For that promise to hold across a control-plane
// restart, the session<->question join must be DURABLE: when the control plane
// comes back it re-reads the join from this backing and the ask resumes on
// answer exactly as before — it is not lost, and it does not silently degrade
// into allow/kill. This mirrors the §3 crash matrix's `RecoverSessions`
// re-adoption (doc 15 §3 / D35): the record survives the process, the process
// re-reads it on restart.
//
// The seam shape (intentionally narrow):
//
//	type Store interface {
//	    askhold.ParkRecorder // RecordParked / ClearParked
//	    Lookup(sessionUUID) (askhold.Parked, bool, error)
//	    List() ([]askhold.Parked, error)
//	}
//
// RecordParked/ClearParked are the two effecting hooks askhold calls; Lookup
// and List are the RESTART-SURVIVAL read path — the control plane re-reads the
// outstanding parks from the SAME backing on startup. Memory is the in-memory
// reference implementation (the way internal/store ships a Memory reference
// impl ahead of its database/sql twin); a database/sql implementation is
// DEFERRED behind this same Store seam (see the SQL note below) and will be
// held to the same behavior. No live IO here (D50): the reference impl is a
// process-local map, and restart-survival is exercised in tests by re-reading
// the join from the same Memory value (the durable backing's stand-in).
//
// ADDITIVE fault posture, inherited from askhold. A record/clear FAULT here
// never un-parks or re-parks the ask: askhold already guarantees the safe
// state (a record error leaves the ask PARKED, a clear error leaves it
// RESUMED — askhold/park.go), so this backing simply SURFACES the fault for the
// caller to retry. The store therefore performs no compensating write on its
// own behalf; an error return is purely "the write did not land, retry it,"
// never "the park changed."
//
// Governing decisions: D46, D77 (park-never-times-out, the record must
// survive), D35 (RecoverSessions re-adoption shape), D50 (synthetic/in-process
// only), D80 (no new third-party deps; stdlib + the orchestrator's own
// askhold). Primary doc: docs/16-identity-and-credentials-design.md §8.2.
package parkstore

import (
	"errors"
	"sort"
	"sync"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
)

// Store is the narrow durable seam for the D46 session<->question join. It
// embeds the askhold.ParkRecorder effecting contract (RecordParked /
// ClearParked) and adds the RESTART-SURVIVAL read path (Lookup / List) the
// control plane uses to re-read outstanding parks after a restart. The
// in-memory Memory below is the reference implementation; a database/sql
// implementation is DEFERRED behind this same interface and held to the same
// behavior, so a caller wires whichever backing without knowing which it got.
type Store interface {
	askhold.ParkRecorder

	// Lookup returns the durably-recorded park for a session, and whether one
	// is present. It is the keyed restart-survival read: after a control-plane
	// restart, the resume path re-fetches the join by session UUID from the same
	// backing and resumes on answer. A cleared (resumed) join is absent. The
	// bool is the presence flag; the error is reserved for a backing-store fault
	// (always nil for the in-memory reference impl).
	Lookup(sessionUUID string) (askhold.Parked, bool, error)

	// List returns every outstanding (still-parked, not-yet-cleared) join in a
	// deterministic order (by session UUID). It is the bulk restart-survival
	// read: on startup the control plane enumerates the outstanding parks to
	// re-adopt them (the §3 RecoverSessions shape, doc 15 §3). The error is
	// reserved for a backing-store fault (always nil for the reference impl).
	List() ([]askhold.Parked, error)
}

// errEmptySession is returned when a record/clear/lookup is attempted with an
// empty session UUID — the join key. It is a write-shape guard (the record is
// keyed by session), NOT a park-state change: returning it leaves the ask in
// whatever state askhold already put it (still parked, the safe state), exactly
// like any other surfaced record fault.
var errEmptySession = errors.New("parkstore: park record requires a non-empty session UUID")

// Memory is the in-memory reference implementation of Store. It is the durable
// backing's reference twin (the pattern internal/store uses: a Memory impl that
// stands in for the not-yet-built database/sql impl behind one interface). It
// is safe for concurrent use.
//
// "Durable" here means "outlives the askhold state-machine call and is re-read
// by Lookup/List" — for the reference impl that is a process-local map, and
// restart-survival is exercised in tests by re-reading the same Memory value
// after the recording call returns (the stand-in for a real backing that
// outlives the process). The database/sql twin makes the same reads hit a
// table that genuinely outlives the process; the seam is identical.
type Memory struct {
	mu sync.Mutex

	// parked is the live session<->question join keyed by SessionUUID. A
	// RecordParked inserts/overwrites; a ClearParked deletes. The map holds ONLY
	// outstanding (still-parked) joins — a resumed ask is cleared, so a restart
	// re-read sees exactly the asks that are still awaiting a human answer.
	parked map[string]askhold.Parked
}

// NewMemory returns an empty in-memory parkstore.
func NewMemory() *Memory {
	return &Memory{parked: make(map[string]askhold.Parked)}
}

// Compile-time assertions: Memory satisfies both the narrow Store seam and the
// askhold.ParkRecorder contract askhold injects.
var (
	_ Store                = (*Memory)(nil)
	_ askhold.ParkRecorder = (*Memory)(nil)
)

// RecordParked persists the session<->question join when an ask enters
// ParkPhaseParked (askhold calls this from NewParked). It records the join
// keyed by the parked session's UUID so a later Lookup/List re-reads it after a
// restart.
//
// Per the askhold contract, a record fault NEVER un-parks the ask: askhold has
// already entered the PARKED (safe) state, so an error here means only "the
// durable write did not land — retry it," and this store performs no
// compensating action. The single failure mode in the reference impl is an
// empty session UUID (no join key); a real backing would also surface its IO
// faults the same way, and the caller retries.
func (m *Memory) RecordParked(p askhold.Parked) error {
	if p.SessionUUID == "" {
		return errEmptySession
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Store a copy so a later mutation of the caller's Parked never aliases the
	// durable record (the backing owns its own copy, like a row).
	m.parked[p.SessionUUID] = p
	return nil
}

// ClearParked removes the session<->question join when a park RESUMES on answer
// (askhold calls this from Resume). After a clear the join is gone, so a
// restart re-read no longer sees it — the ask resolved on a human answer, not a
// timeout.
//
// Per the askhold contract, a clear fault NEVER re-parks the ask: askhold has
// already entered the RESUMED state, so an error here means only "the durable
// clear did not land — retry it." Clearing an absent join is a no-op success
// (idempotent retry-safe), so a re-driven clear after a partial write never
// errors. The single failure mode in the reference impl is an empty session
// UUID.
func (m *Memory) ClearParked(p askhold.Parked) error {
	if p.SessionUUID == "" {
		return errEmptySession
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.parked, p.SessionUUID)
	return nil
}

// Lookup re-reads the durable join for one session (the keyed restart-survival
// read). The bool reports presence; a cleared/never-recorded session is absent.
// The error is always nil for the in-memory reference impl (it is reserved so
// the database/sql twin can surface a query fault through the same signature).
func (m *Memory) Lookup(sessionUUID string) (askhold.Parked, bool, error) {
	if sessionUUID == "" {
		return askhold.Parked{}, false, errEmptySession
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.parked[sessionUUID]
	return p, ok, nil
}

// List enumerates every outstanding park in a deterministic order (by session
// UUID), the bulk restart-survival read: on startup the control plane re-reads
// the outstanding joins to re-adopt them. The returned slice is a fresh copy,
// so a caller iterating it never races a concurrent record/clear. The error is
// always nil for the reference impl (reserved for the SQL twin's query fault).
func (m *Memory) List() ([]askhold.Parked, error) {
	m.mu.Lock()
	out := make([]askhold.Parked, 0, len(m.parked))
	for _, p := range m.parked {
		out = append(out, p)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].SessionUUID < out[j].SessionUUID
	})
	return out, nil
}

// --- database/sql implementation: DEFERRED behind the Store seam ------------
//
// A database/sql-backed Store (the durable twin of Memory) is intentionally NOT
// built here. It is deferred behind this SAME Store interface, exactly as
// internal/store defers its Postgres impl behind the Repository interface and
// holds both to one conformance suite. When it lands it will:
//
//   - RecordParked  -> INSERT/UPSERT the (session_uuid, question, parked_at,
//                      phase) row onto an additive park-join table.
//   - ClearParked   -> DELETE the row by session_uuid (idempotent).
//   - Lookup/List   -> SELECT the outstanding rows — the genuinely durable
//                      restart-survival read that outlives the process.
//
// It surfaces its IO faults through the same error returns (never un-parking /
// re-parking — that is askhold's guaranteed safe state), so callers wired
// against Store need no change. Building it requires the frozen store-seam
// migration that adds the park-join table (the migration-0009 RolePin unfreeze
// precedent, doc 15 §5.6 / D66/D89-D96), so it is out of scope for this
// stdlib-only, synthetic-fixture unit (D50/D80). Until then Memory is the
// reference backing and the seam is ready for the twin.
