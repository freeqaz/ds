package attendedness

// transport.go owns the host-WARD TRANSPORT half of D78 (doc 15 §5.5/§5.2): it
// folds the computed attendedness Signal onto the FROZEN
// hostagent.v1.SessionLifecycleUpdate so the signal rides the EXISTING
// session-lifecycle channel — the D72-EXEMPT class, a few-seconds freshness budget
// (doc 15 §5.2). It invents NO new channel and NO new contract: attended /
// attended_at are the frozen field-4 / field-5 slots already present from M0
// (proto/dreamserpent/hostagent/v1/heartbeat.proto), and TLS-1's socket-hold and
// DNS-3's per-connection verdict consume them off this feed (doc 15 §5.5).
//
// The assembly is a PURE projection (like hostagent.BuildHeartbeat): no I/O, no
// clock — the clock lives in Compute (compute.go), which stamps Signal.AttendedAt.
// Keeping the freshness clock in the computation and the wire-shaping here means
// the lifecycle frame is deterministic and unit-testable, and the attended value
// and its freshness stamp can never drift from how they were computed.

import (
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// SeatViewFromRecord projects the AUTHORITATIVE writer-seat state of a session
// record (the D61 source of truth — "the writer seat lives in the session record",
// seat.go) onto the attendedness SeatView. It maps the store's AttachRole onto the
// package-local one so the computation stays decoupled from the store package
// while still reading the one true seat.
//
// A DETACH clears the record's writer seat (attach.ReleaseWriter sets
// WriterRole=RoleNone, WriterSeat=""), so a post-detach record projects to
// RoleNone and Compute reports attended == false going forward — the signal tracks
// the record honestly across the transition (D78). The in-flight-hold grace
// (holds already in flight run to their 30–60 s timeout; only NEW asks downgrade)
// is enforced by the CONSUMER (TLS-1 socket-hold), never by this projection.
func SeatViewFromRecord(s store.Session) SeatView {
	return SeatView{
		Role:   roleFromStore(s.WriterRole),
		Holder: s.WriterSeat,
	}
}

// roleFromStore maps a store.AttachRole onto the attendedness AttachRole. Only the
// writer seat matters for attendedness; reader and none both map to non-writer
// classes that never count.
func roleFromStore(r store.AttachRole) AttachRole {
	switch r {
	case store.RoleWriter:
		return RoleWriter
	case store.RoleReader:
		return RoleReader
	default:
		return RoleNone
	}
}

// BuildLifecycleUpdate assembles the host-ward SessionLifecycleUpdate frame for a
// session, folding the computed attendedness Signal onto the FROZEN attended /
// attended_at slots (doc 15 §5.5/§5.2). It is the ONE place the signal is shaped
// onto the lifecycle wire, mirroring hostagent.BuildHeartbeat: a pure projection,
// no I/O, no clock (Signal already carries the server-stamped AttendedAt).
//
// It populates ONLY the session identity and the D78 attendedness fields — the
// other lifecycle slots (the D73 digest-ack relay, the D22 grant_refs, the D110
// suspend_coord) are owned by their own legs and folded onto the SAME frame by
// their owners; this leg never fabricates them (a zero-value frame here carries an
// empty digest-set / no grants / no suspend-coord, which those legs fill). The
// frame is additive: the lifecycle assembler merges per-leg contributions onto one
// SessionLifecycleUpdate per session before it goes host-ward.
func BuildLifecycleUpdate(sessionUUID string, sig Signal) *hostagentv1.SessionLifecycleUpdate {
	return &hostagentv1.SessionLifecycleUpdate{
		SessionUuid: sessionUUID,
		Attended:    sig.Attended,
		AttendedAt:  sig.AttendedAt,
	}
}

// StampAttendedness folds the computed Signal onto an EXISTING
// SessionLifecycleUpdate frame in place (the attended / attended_at slots only),
// leaving every other lifecycle slot untouched. This is the additive path the
// lifecycle assembler uses when the D78 leg contributes to a frame another leg
// (digest-ack, grants, suspend-coord) already started — attendedness never clears
// or overwrites a sibling leg's contribution. A nil frame is a no-op.
func StampAttendedness(u *hostagentv1.SessionLifecycleUpdate, sig Signal) {
	if u == nil {
		return
	}
	u.Attended = sig.Attended
	u.AttendedAt = sig.AttendedAt
}
