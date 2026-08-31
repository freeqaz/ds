package store

// sessioncreate_queries.go carries the ADDITIVE store helpers the doc 15 §4.1
// ten-step create choreography (orchestrator/internal/sessions.SessionCreator)
// needs and that the FROZEN shared store files (records.go, repository.go,
// memory.go, postgres.go, …) do not already expose. Per the orch17 fence: shared
// store files stay frozen; an additive query the create coordinator needs lands
// HERE, named by the unit, never by editing a shared file and never by adding a
// Repository-interface method. These helpers compose the EXISTING exported
// Repository surface (CreateSession + AppendIndexEpoch) — they add NO new persisted
// shape and NO new interface method; both *Memory and *Postgres satisfy the narrow
// interface below identically because every method on it already exists.
//
// WHY THIS EXISTS — the unbound-record problem (doc 15 §4.1 step 2 vs step 4). §4.1
// orders the SESSION RECORD creation at step 2, BEFORE policy-fresh placement (step
// 3) and the host-side index allocation (step 4): "the binding
// `(host_session_index, tap_name, guest_ip)` is recorded in the session record" only
// at step 4. But the store's CreateSession (records.go / memory.go) BURNS
// Ref.HostSessionIndex on Ref.HostID the moment the row is written (the
// burned-never-recycled invariant, D66) — so a step-2 record created with the
// natural pre-binding placeholder `(host_id="", host_session_index=0)` would burn the
// SHARED `("", 0)` sentinel, and the SECOND unbound record on the same store
// (another replica's concurrent create, or a retry) would collide on that burn
// (ErrInvalid). That is a false collision: neither session has a real host binding
// yet. The frozen store cannot special-case the sentinel (the burn is unconditional,
// by design — a real `("", 0)` binding would be a genuine collision).
//
// THE FIX (additive, frozen-store-safe). CreatePreBindingSession writes the step-2
// record under a PER-SESSION UNBOUND host id — `unbound:<session_uuid>` — so the
// step-2 burn lands on `("unbound:<uuid>", 0)`, a token that (a) is unique per
// session (no cross-session collision), (b) can never match a REAL host id (real
// hosts are never named `unbound:*`), and (c) is harmless to burn (no real index is
// ever `0` on a real host either, but the per-session host id makes that moot). At
// step 4 the create coordinator calls AppendIndexEpoch with the REAL
// `(host_id, host_session_index, tap, guest_ip)` binding, which closes the unbound
// epoch and advances Ref to the real host — exactly the migration/re-placement path
// the store already supports (conformance testIndexEpochHistory), here used for the
// FIRST real binding. The unbound epoch stays in IndexHistory as the honest "created,
// not yet placed" record; the real binding burns the real `(host, index)` per D66.
//
// IsUnboundHost reports whether a recorded host id is the pre-binding sentinel, so a
// reader (the reconciler, a dashboard) can tell a not-yet-placed record from a placed
// one without re-deriving the convention.

import (
	"context"
	"strings"
)

// unboundHostPrefix tags the per-session pre-binding sentinel host id a step-2 record
// carries until step 4 records the real binding. It is deliberately a token no real
// host id can take (real host ids are operator/inventory-assigned, never `unbound:*`),
// so IsUnboundHost is an exact, forgeable-by-nobody discriminator.
const unboundHostPrefix = "unbound:"

// UnboundHostID is the per-session pre-binding sentinel host id for a step-2 (doc 15
// §4.1) session record that has no host binding yet. It is UNIQUE per session, so two
// concurrent pre-binding records never collide on the burned-index invariant (D66),
// and it can never match a real host id. Step 4's AppendIndexEpoch advances the
// record off it onto the real host.
func UnboundHostID(sessionUUID string) string { return unboundHostPrefix + sessionUUID }

// IsUnboundHost reports whether hostID is a pre-binding sentinel (UnboundHostID's
// output) — i.e. the session record exists (step 2) but has not yet recorded its real
// host binding (step 4). A reader uses it to distinguish a not-yet-placed record from
// a placed one. The empty string is NOT unbound here (an empty host is a malformed
// record, not the sentinel); only the `unbound:<uuid>` form is.
func IsUnboundHost(hostID string) bool {
	return strings.HasPrefix(hostID, unboundHostPrefix) && len(hostID) > len(unboundHostPrefix)
}

// preBindingCreator is the NARROW slice of the existing Repository surface
// CreatePreBindingSession composes: just CreateSession. It is declared HERE (not on
// Repository) so the helper adds no interface method; both *Memory and *Postgres
// satisfy it because CreateSession already exists on both.
type preBindingCreator interface {
	CreateSession(ctx context.Context, s Session) (Session, error)
}

// CreatePreBindingSession writes the doc 15 §4.1 STEP-2 session record for a session
// that has NO host binding yet: the desired-state row (PENDING by default) under the
// per-session unbound sentinel host (UnboundHostID), so the step-2 burn cannot
// collide with another unbound record (the §4.1 step-2-vs-step-4 ordering, D66). The
// caller fills s with the session UUID + the env/image refs + any other step-2
// fields; this helper STAMPS the unbound sentinel onto Ref.HostID (overriding
// whatever the caller left there — a step-2 record is unbound by definition) and
// leaves HostSessionIndex/TapName at their zero values (the unbound epoch). At step 4
// the coordinator calls AppendIndexEpoch with the real binding, which advances Ref
// off the sentinel.
//
// It is idempotent on the session UUID exactly as CreateSession is (re-creating the
// same unbound record returns the existing row; a conflicting Ref is ErrConflict) —
// so a create retry by UUID (doc 15 §4.1) re-issues it safely.
func CreatePreBindingSession(ctx context.Context, repo preBindingCreator, s Session) (Session, error) {
	s.Ref.HostID = UnboundHostID(s.Ref.SessionUUID)
	s.Ref.HostSessionIndex = 0
	s.Ref.TapName = ""
	if s.State == "" {
		s.State = SessionPending
	}
	return repo.CreateSession(ctx, s)
}
