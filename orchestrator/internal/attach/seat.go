package attach

// seat.go is the D61 one-writer/N-reader arbitration enforced SERVER-SIDE at the
// WatchSession terminator (doc 15 §5.3/§5.4). The single most load-bearing rule:
// the WRITER SEAT LIVES IN THE SESSION RECORD (store.Session.WriterSeat /
// WriterRole), and a D61 DRIVER HANDOFF IS A RECORD MUTATION WITH ATTRIBUTION —
// never a second seat, never client-trusted state. READERs are unbounded (the N
// of one-writer/N-reader): canvas, console, and spectators all attach as
// ordinary READERs.
//
// This leg mutates the EXISTING record fields through the EXISTING Repository
// seam (store.UpdateSession): it adds NO store schema — the WriterSeat/WriterRole
// columns landed with the store/migrations tree (doc 15 §5.6), so this is a
// caller, not a schema change.

import (
	"context"
	"errors"
	"fmt"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// ErrWriterSeatHeld is returned by AcquireWriter when the one writer seat is
// already held by a DIFFERENT seat and the caller did not request a handoff: a
// second WRITER is refused at the terminator (D61 one-writer). The current
// holder is named so the caller can decide whether to drive a handoff.
var ErrWriterSeatHeld = errors.New("attach: writer seat already held (D61 one-writer; drive a handoff to take it)")

// ErrSeatIdentityRequired is returned when a WRITER acquisition is attempted with
// an empty seat identity: the writer seat is recorded BY HOLDER (the attribution
// the record carries), so an anonymous writer is refused before the mutation.
var ErrSeatIdentityRequired = errors.New("attach: writer seat acquisition requires a non-empty seat identity (D61 attribution)")

// seatStore is the narrow persistence seam the seat arbitration consumes: read
// the current seat (GetSession) and mutate it atomically (UpdateSession). Both
// store impls (*store.Memory, *store.Postgres) satisfy it; a test fake satisfies
// it too. The arbitration depends only on the two methods it uses.
type seatStore interface {
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
	UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error)
}

// SeatGrant is the outcome of a successful seat arbitration: which seat now holds
// which role, after the record mutation landed. The handle issuance (handle.go)
// stamps this role onto the returned attach.v1.AttachHandle so the handle and the
// record never disagree.
type SeatGrant struct {
	SessionUUID string
	SeatID      string        // the holder identity (the WRITER's; "" for a READER seat)
	Role        attachv1.Role // ROLE_WRITER | ROLE_READER
	HandedOff   bool          // true when this WRITER acquisition took the seat from a prior holder
	PriorWriter string        // the seat handed off FROM (set iff HandedOff)
}

// AcquireWriter takes the one writer seat for seatID on a session (D61
// one-writer), enforced server-side by a record mutation with attribution. If
// the seat is unheld, it is granted. If it is already held by seatID, the
// acquisition is idempotent (re-attaching as the same writer is not a conflict).
// If it is held by a DIFFERENT seat:
//
//   - handoff == false: refused with ErrWriterSeatHeld (the current holder is
//     named in the error context) — a second writer never silently displaces the
//     first.
//   - handoff == true: the seat is handed off — the record is mutated to seatID
//     and the prior holder is returned in the grant (HandedOff/PriorWriter). The
//     handoff is the ONLY way a held writer seat changes hands, and it is exactly
//     a record mutation with attribution (the new holder is recorded).
//
// The mutation goes through store.UpdateSession (WriterSeat + WriterRole +
// AttachState), so the seat survives in the authoritative record, not in this
// process. An empty seatID is refused with ErrSeatIdentityRequired.
func AcquireWriter(ctx context.Context, st seatStore, sessionUUID, seatID string, handoff bool) (SeatGrant, error) {
	if seatID == "" {
		return SeatGrant{}, ErrSeatIdentityRequired
	}
	cur, err := st.GetSession(ctx, sessionUUID)
	if err != nil {
		return SeatGrant{}, fmt.Errorf("attach: read session %q for writer seat: %w", sessionUUID, err)
	}

	prior := cur.WriterSeat
	heldByWriter := cur.WriterRole == store.RoleWriter && prior != ""

	switch {
	case heldByWriter && prior == seatID:
		// Idempotent re-acquire by the same writer: ensure the record reflects the
		// WRITER seat (AttachState mirrors the last seat class issued a handle) and
		// return without changing hands.
		return commitWriterSeat(ctx, st, sessionUUID, seatID, false, "")
	case heldByWriter && prior != seatID && !handoff:
		return SeatGrant{}, fmt.Errorf("%w: held by %q", ErrWriterSeatHeld, prior)
	case heldByWriter && prior != seatID && handoff:
		// Driver handoff: the seat changes hands. The record mutation carries the
		// new holder (attribution); the prior holder is reported.
		return commitWriterSeat(ctx, st, sessionUUID, seatID, true, prior)
	default:
		// Unheld (or previously a READER-only AttachState): grant the writer seat.
		return commitWriterSeat(ctx, st, sessionUUID, seatID, false, "")
	}
}

// commitWriterSeat writes the writer seat onto the record (WriterSeat +
// WriterRole=WRITER + AttachState=WRITER) and returns the grant. This is the one
// place the seat is persisted, so every writer change is a record mutation with
// attribution.
func commitWriterSeat(ctx context.Context, st seatStore, sessionUUID, seatID string, handedOff bool, priorWriter string) (SeatGrant, error) {
	writerRole := store.RoleWriter
	if _, err := st.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		WriterSeat:  &seatID,
		WriterRole:  &writerRole,
		AttachState: &writerRole,
	}); err != nil {
		return SeatGrant{}, fmt.Errorf("attach: record writer seat %q on session %q: %w", seatID, sessionUUID, err)
	}
	return SeatGrant{
		SessionUUID: sessionUUID,
		SeatID:      seatID,
		Role:        attachv1.Role_ROLE_WRITER,
		HandedOff:   handedOff,
		PriorWriter: priorWriter,
	}, nil
}

// AcquireReader admits a READER seat (the N of one-writer/N-reader). Readers are
// UNBOUNDED and require no arbitration — canvas, console, and spectators all
// attach as ordinary READERs (doc 15 §5.4). It records the last-issued seat class
// as READER on the record (AttachState) for sweep/visibility WITHOUT touching the
// writer seat — admitting a reader never displaces the writer. The record write
// is best-effort attribution of the read attach; the reader fan-out itself is the
// WatchSession subscription (watch.go), not a seat.
func AcquireReader(ctx context.Context, st seatStore, sessionUUID string) (SeatGrant, error) {
	if _, err := st.GetSession(ctx, sessionUUID); err != nil {
		return SeatGrant{}, fmt.Errorf("attach: read session %q for reader attach: %w", sessionUUID, err)
	}
	readerRole := store.RoleReader
	if _, err := st.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		AttachState: &readerRole,
	}); err != nil {
		return SeatGrant{}, fmt.Errorf("attach: record reader attach on session %q: %w", sessionUUID, err)
	}
	return SeatGrant{
		SessionUUID: sessionUUID,
		Role:        attachv1.Role_ROLE_READER,
	}, nil
}

// ReleaseWriter clears the writer seat if it is held by seatID (the writer
// detached). A release by a NON-holder is a no-op success (the seat already
// belongs to someone else, or to no one) — release never displaces a seat it does
// not own. The record mutation clears WriterSeat + WriterRole, leaving the
// session writer-less until the next AcquireWriter; AttachState is left untouched
// (it records the last issued seat class, history not live state).
func ReleaseWriter(ctx context.Context, st seatStore, sessionUUID, seatID string) error {
	cur, err := st.GetSession(ctx, sessionUUID)
	if err != nil {
		return fmt.Errorf("attach: read session %q for writer release: %w", sessionUUID, err)
	}
	if cur.WriterSeat != seatID || cur.WriterRole != store.RoleWriter {
		return nil // not the holder: release is a no-op (never displaces another seat)
	}
	empty := ""
	none := store.RoleNone
	if _, err := st.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		WriterSeat: &empty,
		WriterRole: &none,
	}); err != nil {
		return fmt.Errorf("attach: clear writer seat on session %q: %w", sessionUUID, err)
	}
	return nil
}
