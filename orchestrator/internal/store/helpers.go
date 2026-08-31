package store

import (
	"bytes"
	"fmt"
	"time"
)

// wrap formats msg and joins it to a sentinel so callers can errors.Is the
// sentinel while still seeing context. We keep the sentinel as the wrapped
// error so errors.Is(err, ErrX) holds.
func wrap(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, args...))
}

// checkSuspend enforces the §3 SUSPENDED(reason) invariant: a reason is set iff
// the state is SUSPENDED, and the reason is one of the frozen classes only. It
// is the Go mirror of the 0001_sessions.sql "reason set iff SUSPENDED" CHECK,
// so leaving SUSPENDED (e.g. SUSPENDED→RESUMING) forces the reason back to NULL.
func checkSuspend(state SessionState, reason SuspendReason) error {
	if !reason.Valid() {
		return wrap(ErrInvalid, "unknown suspend reason %q", reason)
	}
	if state == SessionSuspended {
		if reason == SuspendReasonNone {
			return wrap(ErrInvalid, "SUSPENDED requires a reason (user|policy_breach|rebalance)")
		}
		return nil
	}
	if reason != SuspendReasonNone {
		return wrap(ErrInvalid, "suspend reason %q is only valid in state SUSPENDED", reason)
	}
	return nil
}

// applyUpdate copies the set fields of u onto s. Timestamps use the *OptTime
// set/clear semantics; everything else is a plain pointer (nil = unchanged).
func applyUpdate(s *Session, u SessionUpdate) {
	if u.State != nil {
		s.State = *u.State
	}
	if u.SuspendReason != nil {
		s.SuspendReason = *u.SuspendReason
	}
	if u.EnvConfigRef != nil {
		s.EnvConfigRef = *u.EnvConfigRef
	}
	if u.ImageID != nil {
		s.ImageID = *u.ImageID
	}
	if u.IdentityRef != nil {
		s.IdentityRef = *u.IdentityRef
	}
	if u.CARef != nil {
		s.CARef = *u.CARef
	}
	if u.DigestRef != nil {
		s.DigestRef = *u.DigestRef
	}
	if u.DigestAcked != nil {
		s.DigestAcked = *u.DigestAcked
	}
	if u.PolicyAppliedSeq != nil {
		s.PolicyAppliedSeq = *u.PolicyAppliedSeq
	}
	if u.Grants != nil {
		s.Grants = cloneGrants(*u.Grants)
	}
	if u.WriterSeat != nil {
		s.WriterSeat = *u.WriterSeat
	}
	if u.WriterRole != nil {
		s.WriterRole = *u.WriterRole
	}
	if u.Attended != nil {
		s.Attended = *u.Attended
	}
	if u.AttachState != nil {
		s.AttachState = *u.AttachState
	}
	if u.RolePin != nil {
		// The pin is value-typed (strings + a bool), so a plain copy hands the
		// record its own pin — no alias into the caller's RolePin.
		s.RolePin = *u.RolePin
	}
	if u.ReadyAt != nil {
		s.ReadyAt = copyTimePtr(u.ReadyAt.V)
	}
	if u.AttachedAt != nil {
		s.AttachedAt = copyTimePtr(u.AttachedAt.V)
	}
	if u.DestroyedAt != nil {
		s.DestroyedAt = copyTimePtr(u.DestroyedAt.V)
	}
}

// matchSession applies a SessionFilter's record-pure predicates: the host/state/parent
// exact matches, the destroyed-omitted default, and the keyset PageToken cursor. The
// LaunchingUser filter is NOT applied here — it needs the store's session→principal
// linkage + principal records (cross-record state matchSession does not see), so the
// in-memory store applies it in ListSessions and the Postgres store as a SQL EXISTS.
func matchSession(s Session, f SessionFilter) bool {
	if f.HostID != "" && s.Ref.HostID != f.HostID {
		return false
	}
	if f.State != "" && s.State != f.State {
		return false
	}
	if f.ParentSessionUUID != "" && s.ParentSessionUUID != f.ParentSessionUUID {
		return false
	}
	if !f.IncludeDestroyed && s.State == SessionDestroyed {
		return false
	}
	// Keyset cursor: keep only the records that sort STRICTLY AFTER the cursor in the
	// stable newest-first order, so a paged walk resumes exactly past the previous page.
	if f.PageToken.Set && !afterSessionCursor(s, f.PageToken) {
		return false
	}
	return true
}

// afterSessionCursor reports whether s sorts STRICTLY AFTER the cursor in the stable
// newest-first session order (created_at DESC, then session_uuid DESC) — the keyset-scan
// predicate the in-memory store applies and the sqlListSessions WHERE mirrors. The
// comparison is over the FULL-precision CreatedAt the store sorts on (time.Time.After/
// Equal, matching the Postgres microsecond timestamptz), so a same-instant pair is
// ordered by session_uuid exactly as the store orders it rather than collapsed to a tie.
func afterSessionCursor(s Session, c SessionPageCursor) bool {
	if !s.CreatedAt.Equal(c.CreatedAt) {
		// Newest-first: an EARLIER instant sorts LATER in the order (so it is "after" the
		// cursor and belongs on a later page).
		return s.CreatedAt.Before(c.CreatedAt)
	}
	return s.Ref.SessionUUID < c.UUID // tie on CreatedAt: session_uuid DESC
}

// --- deep-copy helpers (the store never hands out aliases of its own state) ---

func copyTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func cloneGrants(g []Grant) []Grant {
	if g == nil {
		return nil
	}
	out := make([]Grant, len(g))
	copy(out, g)
	return out
}

func cloneEpochs(e []IndexEpoch) []IndexEpoch {
	if e == nil {
		return nil
	}
	out := make([]IndexEpoch, len(e))
	for i := range e {
		// The struct copy carries the value-typed fields (HostID, HostSessionIndex,
		// TapName, GuestIPFamily, OverlayPath, StartedAt) by value — including the
		// OverlayPath durability field (a plain string), so the persisted overlay
		// round-trips with the epoch and the §4.2 teardown reads it back after a
		// restart. Only the reference-typed fields need a deep copy below.
		out[i] = e[i]
		out[i].GuestIP = cloneBytes(e[i].GuestIP)
		out[i].EndedAt = copyTimePtr(e[i].EndedAt)
	}
	return out
}

func cloneSession(s Session) Session {
	s.Grants = cloneGrants(s.Grants)
	s.IndexHistory = cloneEpochs(s.IndexHistory)
	s.ReadyAt = copyTimePtr(s.ReadyAt)
	s.AttachedAt = copyTimePtr(s.AttachedAt)
	s.DestroyedAt = copyTimePtr(s.DestroyedAt)
	return s
}

func clonePolicy(r PolicyLogRow) PolicyLogRow {
	r.Payload = cloneBytes(r.Payload)
	r.ExpiresAt = copyTimePtr(r.ExpiresAt)
	return r
}

func cloneEnv(c EnvConfig) EnvConfig {
	c.InlineSpec = cloneBytes(c.InlineSpec)
	return c
}

func clonePlan(p Plan) Plan {
	p.Body = cloneBytes(p.Body)
	return p
}

func cloneMetering(e MeteringEvent) MeteringEvent {
	e.Payload = cloneBytes(e.Payload)
	return e
}

// meteringEqual reports whether two metering events carry the same body under a
// shared EventID (idempotency check; the EventID itself is assumed equal).
func meteringEqual(a, b MeteringEvent) bool {
	return a.SessionUUID == b.SessionUUID &&
		a.Kind == b.Kind &&
		a.State == b.State &&
		a.OccurredAt.Equal(b.OccurredAt) &&
		bytes.Equal(a.Payload, b.Payload)
}
