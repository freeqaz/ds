package reconciler

// Queryable liveness/health signal — the "3 missed beats → UNKNOWN" annotation
// (doc 15 §3 / §5.2) made queryable WITHOUT adding it to the frozen §3 vocabulary
// (D35/D72) and WITHOUT mutating any session record state.
//
// WHY THIS EXISTS. The missed-beat sweep (crashmatrix.go markMissedBeats) raises
// the UNKNOWN liveness annotation ONLY as an operator ALARM (AlarmHostUnknown):
// correct for paging, but an operator/UX that wants to answer "which hosts are
// UNKNOWN right now?" today has to scrape the alarm LOG. This file derives the
// SAME signal — LIVE vs UNKNOWN, per host — as a pure, point-in-time READ over the
// reconciler's existing inputs (r.lastBeat + the silence window + r.now()), so the
// annotation is queryable, not just greppable. It computes the identical predicate
// markMissedBeats keys on (now-last <= silenceWindow ⇒ live; otherwise/never-seen ⇒
// UNKNOWN), so the queried signal cannot disagree with the alarm the sweep raises.
//
// WHAT THIS IS NOT (the frozen-contract boundary — read before editing).
//   - NOT a §3 state. The doc 15 §3 machine has exactly 12 frozen states and
//     UNKNOWN is deliberately NOT one of them; its 12-state vocabulary + the
//     SUSPENDED-reason enum are the frozen contract set ratified by D35/D72, and
//     ADDING a name reopens that freeze (a proto-freeze + D47 path, not a code
//     edit). HostLiveness below is therefore a SEPARATE, non-§3 annotation
//     vocabulary (LIVE / UNKNOWN) — it intentionally shares NO token with the §3
//     state set, so it can never be mistaken for, or coerced into, a record state.
//   - NOT a record mutation. Like markMissedBeats, this path writes NOTHING — it
//     reads lastBeat and reports; the never-auto-destroy / never-mutate-on-silence
//     invariant (§3 / §5.2) is preserved because there is simply no write here.
//   - NOT a second writer to lastBeat. This is a pure READER. It adds no mutex and
//     no new synchronization primitive: it honors the EXISTING single-goroutine
//     lastBeat contract (reconciler.go: "safe to call from one goroutine"; the
//     controlplane reconcileLoop funnels every Observe/Resync onto ONE goroutine).
//     HealthSnapshot/HostHealth MUST be called on that same reconcile-loop
//     goroutine — alongside Observe/Resync, never concurrently with them (see the
//     method doc). Serialized that way the read is race-free with the lastBeat
//     writes (proven under `go test -race`), and the single-writer contract is
//     untouched.
//
// Citations: doc 15 §3 (frozen state machine / conflict rules + crash matrix),
// §5.2 (heartbeat / 3-missed-beats → UNKNOWN, never auto-destroyed), D35 (the
// reconciler/state-machine decision), D72 (the §3 freshness/contract-set freeze).
// No new D-row: this is a non-state derivation of an EXISTING annotation.

import (
	"sort"
	"time"
)

// HostLiveness is the NON-state liveness annotation a queried health snapshot
// reports per host. It is EXPLICITLY OUTSIDE the frozen §3 twelve-state vocabulary
// (doc 15 §3, D35/D72): it is an operator-facing health signal derived from
// heartbeat recency, never a session-record lifecycle state, and it shares no
// token with the §3 state set so the two can never be confused. Stringer-friendly
// (it is a typed string) for log/JSON rendering at the query surface.
type HostLiveness string

const (
	// HostLive means the host's last heartbeat is within the silence window
	// (now - lastBeat <= silenceWindow): the host is reporting and its sessions are
	// being reconciled normally. This is the exact complement of the markMissedBeats
	// "continue" arm (crashmatrix.go) — a host this snapshot reports LIVE is a host
	// the missed-beat sweep would NOT mark UNKNOWN.
	HostLive HostLiveness = "LIVE"

	// HostUnknown means the host has gone SILENT past the missed-beat window
	// (now - lastBeat > silenceWindow), OR has never been heard from at all. It is
	// the queryable form of the AlarmHostUnknown the missed-beat sweep raises (doc
	// 15 §3 / §5.2) — a LIVENESS annotation, NEVER a §3 state and NEVER a record
	// mutation: an UNKNOWN host's sessions are never auto-destroyed; the moment
	// heartbeats resume the normal diff re-converges and the next snapshot flips the
	// host back to LIVE.
	HostUnknown HostLiveness = "UNKNOWN"
)

// HostHealth is the per-host liveness signal a queried snapshot reports. It is a
// small, value-typed, non-state view — it carries NO §3 state and NO record
// identity, only the host key and the heartbeat-recency facts the LIVE/UNKNOWN
// derivation is built from, so a caller can render the reason ("silent for 18s,
// window 15s") without re-deriving it.
type HostHealth struct {
	// HostID is the host_id keying the lastBeat map (the §5.2 Heartbeat.host_id).
	HostID string

	// Liveness is the derived non-state annotation: HostLive or HostUnknown.
	Liveness HostLiveness

	// EverSeen is false for a host that has never reported a heartbeat (no lastBeat
	// entry). Such a host is reported HostUnknown with a zero LastBeat and a zero
	// SinceLastBeat — distinguishing "never heard from" from "heard from, now
	// silent" without overloading the duration.
	EverSeen bool

	// LastBeat is the time the host's most recent heartbeat was observed (the
	// lastBeat map value), or the zero Time when EverSeen is false.
	LastBeat time.Time

	// SinceLastBeat is now - LastBeat at snapshot time (how long the host has been
	// silent), or 0 when EverSeen is false. For a LIVE host this is <= SilenceWindow;
	// for a seen-then-silent UNKNOWN host it is > SilenceWindow.
	SinceLastBeat time.Duration

	// SilenceWindow is the missed-beat window the liveness was judged against
	// (MissedBeatThreshold cadences, doc 15 §5.2). Carried so the snapshot is
	// self-describing: the same value silenceWindow() feeds markMissedBeats.
	SilenceWindow time.Duration
}

// hostHealthAt derives one host's liveness from its lastBeat entry, the snapshot
// time `now`, and the silence `window`. It is the single source of the LIVE/UNKNOWN
// predicate, mirroring markMissedBeats EXACTLY (crashmatrix.go): seen AND
// now-last <= window ⇒ LIVE; never-seen OR silent past the window ⇒ UNKNOWN. Pure;
// no read of r.lastBeat, so it is trivially testable and cannot drift from the
// sweep.
func hostHealthAt(hostID string, last time.Time, seen bool, now time.Time, window time.Duration) HostHealth {
	h := HostHealth{
		HostID:        hostID,
		EverSeen:      seen,
		SilenceWindow: window,
	}
	if !seen {
		// Never heard from → UNKNOWN, with a zero LastBeat/SinceLastBeat to mark the
		// "no heartbeat ever observed" case distinctly.
		h.Liveness = HostUnknown
		return h
	}
	h.LastBeat = last
	h.SinceLastBeat = now.Sub(last)
	if h.SinceLastBeat <= window {
		h.Liveness = HostLive // within the window — same arm markMissedBeats `continue`s on.
	} else {
		h.Liveness = HostUnknown // silent past the window — the missed-beat UNKNOWN.
	}
	return h
}

// HostHealth derives the CURRENT liveness annotation for a SINGLE host as a
// read-only point-in-time signal (doc 15 §3 / §5.2; D35/D72): LIVE when the host's
// last heartbeat is within the silence window, UNKNOWN when it is silent past the
// window or has never reported. It mutates nothing — no record, no lastBeat, no §3
// state — and adds no §3 vocabulary name.
//
// CONCURRENCY: this is a pure READER of r.lastBeat and honors the existing
// single-goroutine lastBeat contract — call it on the reconcile-loop goroutine
// (alongside Observe/Resync), NEVER concurrently with them. It takes no lock and
// introduces no second writer.
func (r *Reconciler) HostHealth(hostID string) HostHealth {
	now := r.now()
	window := r.silenceWindow()
	last, seen := r.lastBeat[hostID]
	return hostHealthAt(hostID, last, seen, now, window)
}

// HealthSnapshot returns the CURRENT liveness annotation for EVERY host the
// reconciler has a heartbeat record for (every key in lastBeat), as a read-only,
// point-in-time, non-state health signal — the queryable form of the
// "3 missed beats → UNKNOWN" annotation (doc 15 §3 / §5.2) operators/UX want
// without scraping the AlarmHostUnknown log. Each entry is LIVE or UNKNOWN derived
// from lastBeat + the silence window + r.now(), using the SAME predicate
// markMissedBeats keys on, so the snapshot cannot disagree with the alarm the
// sweep raises.
//
// The result is sorted by HostID for a stable, deterministic query/render order.
// An empty reconciler (no host ever observed) returns an empty (non-nil) slice.
//
// SCOPE NOTE: HealthSnapshot reports the hosts the reconciler has HEARD from (the
// lastBeat keys). A host that has a record but has NEVER sent a heartbeat is absent
// from lastBeat and so is NOT in this snapshot — query it explicitly via
// HostHealth(hostID), which returns EverSeen=false / UNKNOWN for a never-seen host.
// (Cross-referencing lastBeat against the record store to enumerate never-seen
// hosts would require a store read; this accessor deliberately stays a pure
// in-memory derivation with no I/O, exactly like the lastBeat map it reads.)
//
// CONCURRENCY: like HostHealth, this is a pure READER of r.lastBeat and honors the
// existing single-goroutine lastBeat contract — call it on the reconcile-loop
// goroutine (alongside Observe/Resync), NEVER concurrently with them. It takes no
// lock and introduces no second writer (D35/D72; the single-writer lastBeat
// contract is untouched).
func (r *Reconciler) HealthSnapshot() []HostHealth {
	now := r.now()
	window := r.silenceWindow()
	out := make([]HostHealth, 0, len(r.lastBeat))
	for hostID, last := range r.lastBeat {
		out = append(out, hostHealthAt(hostID, last, true, now, window))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out
}

// HealthSnapshotIncluding returns the CURRENT liveness annotation for the UNION of
// (a) every host the reconciler has HEARD from (the lastBeat keys, exactly what
// HealthSnapshot reports) and (b) every host_id in expectedHostIDs — the hosts the
// CALLER knows SHOULD exist (e.g. enumerated from the record store at the call
// site). A host in (b) with no lastBeat entry has never sent a heartbeat at all and
// is reported EverSeen=false / UNKNOWN with a zero LastBeat/SinceLastBeat, surfacing
// the never-seen host that the heard-from-only HealthSnapshot deliberately omits
// (see its SCOPE NOTE). A host that is BOTH expected and heard-from is reported once,
// from its lastBeat entry (LIVE or UNKNOWN by recency) — the heard-from fact wins,
// so an expected host that is actually beating is never mis-reported as never-seen.
//
// This is an OPT-IN companion to HealthSnapshot, NOT a replacement: the cheap
// zero-I/O HealthSnapshot is byte-for-byte unchanged and keeps doing no store read.
// The never-seen enrichment is a PURE derivation — the expected host_ids are SUPPLIED
// by the caller, never read from a store here, so the Reconciler stays free of any
// record-store dependency (no constructor/field change, no I/O on this path). Each
// per-host entry is derived by the SAME hostHealthAt predicate the other accessors
// use, so a never-seen entry has the IDENTICAL UNKNOWN shape HostHealth would return.
//
// The result is sorted by HostID for a stable, deterministic query/render order; a
// duplicate or already-heard-from expectedHostIDs entry never produces a duplicate
// row. An empty union (no host heard from, none expected) returns an empty (non-nil)
// slice.
//
// CONCURRENCY: like HealthSnapshot/HostHealth this is a pure READER of r.lastBeat and
// honors the existing single-goroutine lastBeat contract — call it on the
// reconcile-loop goroutine (alongside Observe/Resync), NEVER concurrently with them.
// expectedHostIDs is caller-owned input, not shared reconciler state; the read takes
// no lock and introduces no second writer (D35/D72; the single-writer lastBeat
// contract is untouched, no §3 state name, no record mutation).
func (r *Reconciler) HealthSnapshotIncluding(expectedHostIDs []string) []HostHealth {
	now := r.now()
	window := r.silenceWindow()
	// Pre-size for the heard-from set plus, at most, the expected set; dedup keeps
	// the real count at or below this.
	out := make([]HostHealth, 0, len(r.lastBeat)+len(expectedHostIDs))
	seenInOut := make(map[string]struct{}, len(r.lastBeat)+len(expectedHostIDs))

	// (a) every heard-from host — identical to HealthSnapshot's body.
	for hostID, last := range r.lastBeat {
		out = append(out, hostHealthAt(hostID, last, true, now, window))
		seenInOut[hostID] = struct{}{}
	}
	// (b) every expected host the reconciler has NOT heard from → never-seen UNKNOWN.
	// A duplicate within expectedHostIDs, or one already emitted from lastBeat, is
	// skipped so the union has exactly one row per host_id.
	for _, hostID := range expectedHostIDs {
		if _, dup := seenInOut[hostID]; dup {
			continue
		}
		seenInOut[hostID] = struct{}{}
		out = append(out, hostHealthAt(hostID, time.Time{}, false, now, window))
	}

	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out
}
