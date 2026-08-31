package attach

// writerseat.go is the W2 ARBITRATION half of the D137 browser writer seat
// (sessions/10 §3/§6 W2; D61/D136/D137/D138), enforced SERVER-SIDE at the single
// WatchSession terminator (doc 15 §5.3/§5.4). It is the ONE choke point through
// which the writer seat changes hands, so the D61 one-writer/N-reader invariant is
// STRUCTURAL, never policy-forbidden after the fact:
//
//   - EXACTLY ONE live seat per session (D61). RequestSeat serializes per-session
//     under a per-session mutex; two concurrent requests resolve to exactly ONE
//     grant and the loser is REFUSED with a typed error (never a second live seat).
//   - The seat lives in the SESSION RECORD (doc 15 §5.4), and the record is the D61
//     SOURCE OF TRUTH the arbiter reconciles against on every grant. The attributed
//     holder (driver_identity) is mirrored onto store.Session.WriterSeat +
//     WriterRole=WRITER through the EXISTING UpdateSession seam — the SAME record
//     column the D78 attendedness computation reads (attendedness.SeatViewFromRecord)
//     AND the SAME column the legacy AcquireWriter handle leg (seat.go) writes — so a
//     grant is a RECORD MUTATION WITH ATTRIBUTION and the seat the attendedness signal
//     sees never disagrees with the seat the arbiter granted. The seat-id / expiry /
//     granted_seq metadata (the short-lived token, the TTL, the handoff seq) is held
//     by this single terminator alongside the record mirror. Because the in-process
//     live-seat record is process-local (lost on restart) and is NOT the only writer
//     of the record column, currentLive READS the record (GetSession) and treats a
//     record-named holder the in-process map does not know — a seat set by the legacy
//     leg, or a durable holder that survived a restart while the map was emptied — as a
//     LIVE held seat, never as a free seat a fresh request may silently grab. This is
//     the same restart-amnesia guard the mint-expiry scheduler re-arms from the durable
//     record for (wiring.go): the record, not process memory, decides who holds the one
//     seat.
//   - A handoff is OBSERVABLE (D137: a steal cannot be silent). On every
//     grant/steal/yield the arbiter emits an attach.v1 SessionEvent of type
//     WRITER_SEAT_CHANGED on the read stream through the SAME Fanout WatchSession
//     readers subscribe to; the Fanout-stamped seq IS the granted_seq returned to
//     the new driver (and the released_seq on a yield), so the write-side caller and
//     every N-reader agree on the one ordering point the seat changed hands at.
//   - The D138 force_steal policy gate. A steal of a seat whose holder is ATTENDED
//     (recent input within T — the attendedness signal) is REFUSED by default; it
//     requires explicit policy approval. An idle / expired / yielding seat may be
//     taken without approval.
//
// The seat is SHORT-LIVED (a default TTL, renewed by re-request — never a long-lived
// cred, D39). An expired seat is treated as free: the next RequestSeat grants it
// without a steal.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// DefaultSeatTTL bounds an issued writer seat when the arbiter is built without an
// override. The seat is short-lived by construction (D39 — the driver renews it by
// re-requesting; it is NEVER a long-lived cred). The value is a strawman, not a
// frozen contract (doc 15 §10 — only the short-lived discipline is load-bearing).
const DefaultSeatTTL = 2 * time.Minute

// ErrSeatHeld is returned by RequestSeat when the one live seat is held by a
// DIFFERENT, still-live driver and the caller did not force a steal: a second
// writer is REFUSED at the terminator (D61 one-writer), never granted a second live
// seat. The handler maps it onto codes.AlreadyExists / FailedPrecondition.
var ErrSeatHeld = errors.New("attach: writer seat already held by another driver (D61 one-writer; force a steal to take it)")

// ErrStealAttended is returned when a force_steal targets a seat whose holder is
// ATTENDED (recent input within T) and no policy approval was granted: the D138
// default is to REFUSE a steal of an attended seat. The handler maps it onto
// codes.PermissionDenied.
var ErrStealAttended = errors.New("attach: refusing to steal an ATTENDED writer seat without policy approval (D138 default-refuse)")

// ErrDriverIdentityRequired is returned when a seat request carries no driver
// identity: the seat is recorded BY HOLDER (the attribution the record carries,
// D8/D55), so an anonymous driver is refused before any mutation. (seat.go's
// ErrSeatIdentityRequired is the legacy Attach-handle leg's twin; this is the W2
// writer-relay arbiter's own sentinel so the two legs map errors independently.)
var ErrDriverIdentityRequired = errors.New("attach: writer seat request requires a non-empty driver identity (D8/D55 attribution)")

// liveSeat is the in-process live-seat record the single terminator owns alongside
// the session-record mirror: {writer_seat_id, driver_identity, expires_at,
// granted_seq}. It is the seat the arbiter arbitrates against; the attributed
// holder is mirrored onto store.Session.WriterSeat so the record stays the D61
// source of truth for everything that reads it (D78 attendedness, sweep).
type liveSeat struct {
	id        string    // the seat token threaded into v1 InputActivity.writer_seat_id + required on DriveInput
	driver    string    // the D8/D55-attributed holder (mirrored onto store.Session.WriterSeat)
	expiresAt time.Time // short-lived TTL (D39); an expired seat is treated as free
	grantedAt uint64    // the WatchSession seq the seat last changed hands at (granted_seq)
}

// SeatPublisher is the narrow read-stream publish seam the arbiter emits the
// WRITER_SEAT_CHANGED event through: exactly attach.Fanout.Publish (watch.go),
// which stamps the per-session seq, records the ring, and fans to every N-reader.
// The returned seq is the granted_seq / released_seq the handoff is observable at.
// Declared narrow so the arbiter depends only on the publish it uses (a test fake
// satisfies it).
type SeatPublisher interface {
	Publish(ctx context.Context, sessionUUID string, ev *attachv1.SessionEvent) uint64
}

// AttendednessProbe answers "is the current writer-seat holder ATTENDED right now?"
// for the D138 steal gate. It is the attendedness signal (doc 15 §5.5/D78) projected
// to a single boolean: true means a human holds the seat AND (once input events land)
// produced input within T — a seat that must NOT be stolen without policy approval.
// The arbiter consults it ONLY on a force_steal of a live held seat; an idle/expired
// seat is taken without consulting it. A nil probe treats every held seat as attended
// (fail-closed: the steal then needs policy approval — the safe default when the
// signal is unavailable).
type AttendednessProbe interface {
	// Attended reports whether the session's current writer-seat holder is attended.
	Attended(ctx context.Context, sessionUUID string) (bool, error)
}

// AttendednessProbeFunc adapts a function to an AttendednessProbe.
type AttendednessProbeFunc func(ctx context.Context, sessionUUID string) (bool, error)

// Attended calls the function.
func (f AttendednessProbeFunc) Attended(ctx context.Context, sessionUUID string) (bool, error) {
	return f(ctx, sessionUUID)
}

// SeatArbiter is the single-terminator writer-seat arbitration owner (D61/D137/D138).
// It serializes seat requests per session, holds the live-seat record, mirrors the
// attributed holder onto the session record, emits the observable WRITER_SEAT_CHANGED
// read event, and enforces the D138 steal gate. A zero SeatArbiter is not usable;
// construct with NewSeatArbiter.
type SeatArbiter struct {
	store    seatStore
	pub      SeatPublisher
	attended AttendednessProbe

	ttl    time.Duration
	now    func() time.Time
	mintID func() string

	mu        sync.Mutex             // guards the maps below + serializes per-session arbitration
	seats     map[string]*liveSeat   // session_uuid → the one live seat (absent => free)
	seatIndex map[string]string      // writer_seat_id → session_uuid (the W3 drive routing index; only minted ids)
	locks     map[string]*sync.Mutex // session_uuid → per-session serialization lock
}

// SeatArbiterOption configures a SeatArbiter.
type SeatArbiterOption func(*SeatArbiter)

// WithSeatTTL overrides the short-lived seat lifetime (default DefaultSeatTTL). The
// seat stays short-lived regardless (D39).
func WithSeatTTL(d time.Duration) SeatArbiterOption {
	return func(a *SeatArbiter) {
		if d > 0 {
			a.ttl = d
		}
	}
}

// WithSeatClock overrides the arbiter clock (test seam for expiry).
func WithSeatClock(now func() time.Time) SeatArbiterOption {
	return func(a *SeatArbiter) {
		if now != nil {
			a.now = now
		}
	}
}

// WithSeatIDGen overrides the seat-token generator (test seam; the default is
// crypto/rand hex). The seat token is the opaque writer_seat_id threaded onto the
// read-leg InputActivity and required on every DriveInput.
func WithSeatIDGen(gen func() string) SeatArbiterOption {
	return func(a *SeatArbiter) {
		if gen != nil {
			a.mintID = gen
		}
	}
}

// WithAttendednessProbe wires the D138 steal-gate signal (the attendedness probe).
// Without it, a force_steal of any live held seat is treated as targeting an
// attended seat (fail-closed: it needs policy approval).
func WithAttendednessProbe(p AttendednessProbe) SeatArbiterOption {
	return func(a *SeatArbiter) { a.attended = p }
}

// NewSeatArbiter constructs the writer-seat arbiter over the session-record store
// seam (the seat lives in the record) and the read-stream publish seam (the
// WRITER_SEAT_CHANGED event rides it). The store and publisher are required.
func NewSeatArbiter(st seatStore, pub SeatPublisher, opts ...SeatArbiterOption) *SeatArbiter {
	a := &SeatArbiter{
		store:     st,
		pub:       pub,
		ttl:       DefaultSeatTTL,
		now:       time.Now,
		mintID:    randomSeatID,
		seats:     make(map[string]*liveSeat),
		seatIndex: make(map[string]string),
		locks:     make(map[string]*sync.Mutex),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// SeatRequest is the input to RequestSeat: which session, who (the D8/D55 driver
// identity), and whether to force a steal of a live held seat (D138, policy-gated).
type SeatRequest struct {
	SessionUUID    string
	DriverIdentity string // the validated D55 human identity — WHO holds the seat (attribution)
	ForceSteal     bool   // request a takeover from a live holder (POLICY-GATED on an attended seat, D138)
	StealApproved  bool   // an explicit policy approval accompanies a force_steal of an attended seat (D138)
}

// RequestSeat takes the one writer seat for the requesting driver (D61, server-
// arbitrated at the single terminator). It serializes per session so concurrent
// requests resolve to EXACTLY ONE grant:
//
//   - The seat is FREE (unheld / expired): granted. WriterSeatChange kind = GRANT.
//   - Held by the SAME driver: idempotent re-grant (the driver renews its seat with a
//     fresh id + TTL + seq). kind = GRANT (a renewal of the same driver's seat).
//   - Held by a DIFFERENT live driver, !ForceSteal: REFUSED with ErrSeatHeld (a
//     second writer never silently displaces the first).
//   - Held by a DIFFERENT live driver, ForceSteal: the D138 gate runs. If the holder
//     is ATTENDED and no StealApproved accompanies the request, REFUSED with
//     ErrStealAttended. Otherwise the seat is taken. kind = STEAL.
//
// On a grant/steal the attributed holder is mirrored onto the session record
// (WriterSeat=driver, WriterRole=WRITER) and a WRITER_SEAT_CHANGED event is emitted
// on the read stream; the Fanout-stamped seq is the returned WriterSeatGrant.granted_seq.
func (a *SeatArbiter) RequestSeat(ctx context.Context, req SeatRequest) (*attachv1.WriterSeatGrant, error) {
	if req.SessionUUID == "" {
		return nil, fmt.Errorf("attach: writer seat request requires a session_uuid")
	}
	if req.DriverIdentity == "" {
		return nil, ErrDriverIdentityRequired
	}

	unlock := a.lockSession(req.SessionUUID)
	defer unlock()

	now := a.now()
	cur, err := a.currentLive(ctx, req.SessionUUID, now)
	if err != nil {
		return nil, err
	}

	kind := attachv1.WriterSeatChangeKind_WRITER_SEAT_CHANGE_KIND_GRANT
	prevDriver := ""
	if cur != nil {
		switch {
		case cur.driver == req.DriverIdentity:
			// Idempotent renewal by the same driver — re-grant a fresh id+TTL+seq.
			kind = attachv1.WriterSeatChangeKind_WRITER_SEAT_CHANGE_KIND_GRANT
			prevDriver = cur.driver
		case !req.ForceSteal:
			// A different live driver holds it and the caller did not force a steal:
			// a second writer is refused (the holder is named for the caller).
			return nil, fmt.Errorf("%w: held by %q", ErrSeatHeld, cur.driver)
		default:
			// A force_steal of a different live driver's seat — run the D138 gate.
			if err := a.guardSteal(ctx, req, cur); err != nil {
				return nil, err
			}
			kind = attachv1.WriterSeatChangeKind_WRITER_SEAT_CHANGE_KIND_STEAL
			prevDriver = cur.driver
		}
	}

	// Mint the new short-lived seat and mirror the attributed holder onto the record
	// FIRST (the record is the D61 source of truth; the mutation lands before the
	// observable event so a reader that acts on the event sees the matching record).
	seatID := a.mintID()
	expires := now.Add(a.ttl)
	if err := a.commitHolder(ctx, req.SessionUUID, req.DriverIdentity); err != nil {
		return nil, err
	}

	// Emit the observable WRITER_SEAT_CHANGED read event; the stamped seq is granted_seq.
	seq := a.pub.Publish(ctx, req.SessionUUID, &attachv1.SessionEvent{
		Type: attachv1.EventType_EVENT_TYPE_WRITER_SEAT_CHANGED,
		Payload: &attachv1.SessionEvent_WriterSeatChange{
			WriterSeatChange: &attachv1.WriterSeatChange{
				WriterSeatId:       seatID,
				DriverIdentity:     req.DriverIdentity,
				PrevDriverIdentity: prevDriver,
				Kind:               kind,
				ExpiresAt:          uint64(expires.Unix()),
			},
		},
	})

	a.setLive(req.SessionUUID, &liveSeat{
		id:        seatID,
		driver:    req.DriverIdentity,
		expiresAt: expires,
		grantedAt: seq,
	})

	return &attachv1.WriterSeatGrant{
		WriterSeatId:   seatID,
		DriverIdentity: req.DriverIdentity,
		ExpiresAt:      uint64(expires.Unix()),
		GrantedSeq:     seq,
	}, nil
}

// YieldSeat releases the seat held under writerSeatID (the cooperative half of the
// handoff). It is idempotent: yielding a seat that is not the live grant (already
// gone, expired, or never held) is ACKNOWLEDGED, not an error — but it emits NO
// event and returns seq 0 in that case (nothing changed hands). On a real release
// the record's writer seat is cleared (WriterSeat="", WriterRole=None — so D78
// reports unattended going forward) and a WRITER_SEAT_CHANGED kind=YIELD event is
// emitted; the stamped seq is the returned released_seq.
func (a *SeatArbiter) YieldSeat(ctx context.Context, sessionUUID, writerSeatID string) (releasedSeq uint64, err error) {
	if sessionUUID == "" {
		return 0, fmt.Errorf("attach: writer seat yield requires a session_uuid")
	}

	unlock := a.lockSession(sessionUUID)
	defer unlock()

	cur, err := a.currentLive(ctx, sessionUUID, a.now())
	if err != nil {
		return 0, err
	}
	if cur == nil || cur.id != writerSeatID {
		// Not the live grant (already released / expired / never held / wrong id, or a
		// record-only holder the legacy leg seated whose seat-id this terminator never
		// minted): an idempotent no-op success — release never displaces a seat it does
		// not own. (A record-only holder carries id "", so any non-empty writerSeatID
		// cannot match it — this terminator only yields seats it minted a token for.)
		return 0, nil
	}

	// Clear the record's writer seat (the holder detached) so D78 reports unattended
	// going forward, then emit the observable YIELD on the read stream.
	if err := a.clearHolder(ctx, sessionUUID, cur.driver); err != nil {
		return 0, err
	}
	seq := a.pub.Publish(ctx, sessionUUID, &attachv1.SessionEvent{
		Type: attachv1.EventType_EVENT_TYPE_WRITER_SEAT_CHANGED,
		Payload: &attachv1.SessionEvent_WriterSeatChange{
			WriterSeatChange: &attachv1.WriterSeatChange{
				PrevDriverIdentity: cur.driver,
				Kind:               attachv1.WriterSeatChangeKind_WRITER_SEAT_CHANGE_KIND_YIELD,
			},
		},
	})
	a.clearLive(sessionUUID)
	return seq, nil
}

// guardSteal runs the D138 force_steal policy gate over a live held seat: a steal of
// an ATTENDED seat is REFUSED unless an explicit policy approval accompanies the
// request; an idle (unattended) seat may be taken. A nil probe fails CLOSED (the
// seat is treated as attended, so the steal needs approval) — the safe default when
// the attendedness signal is unavailable.
func (a *SeatArbiter) guardSteal(ctx context.Context, req SeatRequest, cur *liveSeat) error {
	attended := true // fail-closed default when no probe is wired
	if a.attended != nil {
		ok, err := a.attended.Attended(ctx, req.SessionUUID)
		if err != nil {
			return fmt.Errorf("attach: attendedness probe for steal gate on session %q: %w", req.SessionUUID, err)
		}
		attended = ok
	}
	if attended && !req.StealApproved {
		return fmt.Errorf("%w: holder %q", ErrStealAttended, cur.driver)
	}
	return nil
}

// commitHolder mirrors the attributed driver onto the session record's writer seat
// (WriterSeat=driver, WriterRole=WRITER) through the EXISTING UpdateSession seam —
// the SAME column the D78 attendedness computation reads. This is the record
// mutation with attribution (D8/D55): the seat lives in the record, and the seat the
// attendedness signal sees never disagrees with the seat the arbiter granted.
func (a *SeatArbiter) commitHolder(ctx context.Context, sessionUUID, driver string) error {
	writerRole := store.RoleWriter
	if _, err := a.store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		WriterSeat:  &driver,
		WriterRole:  &writerRole,
		AttachState: &writerRole,
	}); err != nil {
		return fmt.Errorf("attach: record writer seat holder %q on session %q: %w", driver, sessionUUID, err)
	}
	return nil
}

// clearHolder clears the session record's writer seat on a yield (WriterSeat="",
// WriterRole=None) so the record reports writer-less and D78 reports unattended
// going forward. AttachState is left untouched (it records the last issued seat
// class — history, not live state). A clear by the wrong driver cannot happen: the
// caller has already matched the live grant id under the per-session lock.
func (a *SeatArbiter) clearHolder(ctx context.Context, sessionUUID, driver string) error {
	empty := ""
	none := store.RoleNone
	if _, err := a.store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		WriterSeat: &empty,
		WriterRole: &none,
	}); err != nil {
		return fmt.Errorf("attach: clear writer seat (held by %q) on session %q: %w", driver, sessionUUID, err)
	}
	return nil
}

// currentLive returns the session's live seat reconciled against the DURABLE RECORD
// (the D61 source of truth), or nil if the seat is free. Caller holds the per-session
// lock (so the read+arbitration are one atomic step). The reconciliation:
//
//   - Read the record (GetSession). A missing record (ErrNotFound) means there is no
//     session to seat — treat as free (the grant's own commitHolder/UpdateSession then
//     surfaces the not-found if the session truly does not exist).
//   - If the record names a LIVE writer holder (WriterRole==WRITER, WriterSeat!="")
//     that the in-process map ALSO knows as the same, non-expired driver, return the
//     in-process seat (it carries the full {id, expiry, granted_seq} metadata).
//   - If the record names a LIVE writer holder (WriterRole==WRITER, WriterSeat!="")
//     that the in-process map ALSO knows as the same, non-expired driver, return the
//     in-process seat (it carries the full {id, expiry, granted_seq} metadata).
//   - If the in-process map knows that holder but its token has EXPIRED (same driver,
//     past TTL), the seat is FREE: this terminator minted that token and watched it
//     lapse, so D39 renew-by-re-request applies and the next request GRANTS without a
//     steal — even though the (expiry-less) record still names the lapsed driver.
//   - Otherwise the record names a holder this terminator has NO live token matching:
//     no in-process entry at all (a seat the legacy AcquireWriter handle leg (seat.go)
//     set, OR a durable holder that survived an orchestrator restart while the process
//     map was empty), or an in-process entry naming a DIFFERENT driver than the record
//     (the legacy leg re-seated someone else). Return a RECORD-DERIVED seat: driver =
//     the recorded holder, id = "" (this terminator never minted a token for it). It is
//     treated as a LIVE held seat, so a different driver is REFUSED (or must force a
//     steal) — never silently granted a second seat over a holder the record already
//     names (D61 one live seat). This is the restart-amnesia / cross-leg guard: process
//     memory never lets a fresh request grab a seat the durable record still holds.
//   - If the record names NO writer holder, the seat is free — even if a stale
//     in-process entry lingers (the record won the clear, e.g. a legacy ReleaseWriter).
func (a *SeatArbiter) currentLive(ctx context.Context, sessionUUID string, now time.Time) (*liveSeat, error) {
	rec, err := a.store.GetSession(ctx, sessionUUID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// No record to seat: free here. The grant path's UpdateSession is the one
			// that authoritatively refuses a non-existent session.
			return nil, nil
		}
		return nil, fmt.Errorf("attach: read session %q for writer-seat arbitration: %w", sessionUUID, err)
	}
	if rec.WriterRole != store.RoleWriter || rec.WriterSeat == "" {
		// The record (source of truth) names no writer — free, regardless of any
		// lingering in-process entry (the record won a clear, e.g. legacy ReleaseWriter).
		return nil, nil
	}

	a.mu.Lock()
	s := a.seats[sessionUUID]
	a.mu.Unlock()

	if s != nil && s.driver == rec.WriterSeat {
		// This terminator minted the token the record names. Honor its TTL: a lapsed
		// token is FREE (D39 renew-by-re-request); a live one returns full metadata.
		if !s.expiresAt.IsZero() && !now.Before(s.expiresAt) {
			return nil, nil
		}
		return s, nil
	}

	// The record names a holder this terminator has no matching live token for
	// (post-restart durable holder, a legacy-leg seat, or a different driver re-seated
	// by the legacy leg). It is LIVE by the record's authority; synthesize it (id "" —
	// no minted token, so no DriveInput can claim it and YieldSeat never matches it).
	return &liveSeat{driver: rec.WriterSeat}, nil
}

// setLive installs the session's one live seat AND maintains the writer_seat_id →
// session drive-routing index (the W3 ValidateDrive lookup): it drops the session's
// PRIOR seat-id from the index first (a renew/steal mints a fresh id, so the superseded
// id must stop routing — only the current minted token is a live grant) and indexes the
// new one. A seat with id "" (defensive — the live grant path always mints a token) is
// not indexed (no DriveInput can claim a token-less seat).
func (a *SeatArbiter) setLive(sessionUUID string, s *liveSeat) {
	a.mu.Lock()
	if prev := a.seats[sessionUUID]; prev != nil && prev.id != "" {
		delete(a.seatIndex, prev.id)
	}
	a.seats[sessionUUID] = s
	if s != nil && s.id != "" {
		a.seatIndex[s.id] = sessionUUID
	}
	a.mu.Unlock()
}

// clearLive drops the session's live seat AND its drive-routing index entry (on a
// yield: the seat went free, so its id must stop routing a DriveInput to stdin).
func (a *SeatArbiter) clearLive(sessionUUID string) {
	a.mu.Lock()
	if prev := a.seats[sessionUUID]; prev != nil && prev.id != "" {
		delete(a.seatIndex, prev.id)
	}
	delete(a.seats, sessionUUID)
	a.mu.Unlock()
}

// lockSession returns an unlock func for the per-session serialization lock,
// creating the lock on first use. Per-session locking serializes seat arbitration
// for ONE session (so concurrent requests resolve to exactly one grant) WITHOUT
// serializing disjoint sessions against each other.
func (a *SeatArbiter) lockSession(sessionUUID string) func() {
	a.mu.Lock()
	lk := a.locks[sessionUUID]
	if lk == nil {
		lk = &sync.Mutex{}
		a.locks[sessionUUID] = lk
	}
	a.mu.Unlock()
	lk.Lock()
	return lk.Unlock
}

// CurrentSeatID reports the live writer_seat_id for a session (the seat a DriveInput
// must match), or "" if the seat is free, expired, or held only in the durable record
// by a holder this terminator never minted a token for (a legacy-leg / post-restart
// seat — id ""). It is the read W3's DriveSession will validate a DriveInput.writer_
// seat_id against (the single live grant); a record-only holder has no matching token,
// so no DriveInput can claim it. Exported for the W3 drive leg + tests; takes the
// per-session lock so the read is consistent. A store read fault yields "" — fail-
// closed (no seat id matches), surfacing as a refused DriveInput rather than a panic.
func (a *SeatArbiter) CurrentSeatID(ctx context.Context, sessionUUID string) string {
	unlock := a.lockSession(sessionUUID)
	defer unlock()
	cur, err := a.currentLive(ctx, sessionUUID, a.now())
	if err != nil || cur == nil {
		return ""
	}
	return cur.id
}

// ErrSeatNotLive is returned by ValidateDrive when the presented writer_seat_id is
// NOT a session's one live grant (a stale, forged, absent, expired, or yielded seat —
// or a record-only holder this terminator minted no token for, id ""). It is the W3
// drive-leg refusal sentinel: a DriveInput carrying it reaches NO stdin and emits NO
// InputActivity (sessions/10 §5 claim 2). The handler maps it onto
// codes.PermissionDenied (the caller is not the live seat-holder).
var ErrSeatNotLive = errors.New("attach: writer_seat_id is not a live grant (only the current seat-holder may drive)")

// DriveSeat is the resolved live-seat view ValidateDrive returns for an admitted
// DriveInput: the SESSION the seat-id belongs to (the routing key for the host-agent
// relay + the read-leg InputActivity — the drive wire carries only the seat-id, so the
// terminator that minted it is the authority that resolves it to a session) and the
// attributed DRIVER (the D8/D55 holder the read-leg projection is attributed to). Both
// come from the single terminator's own minted-token state, never the (untrusted) wire.
type DriveSeat struct {
	SessionUUID    string // the session the live seat-id belongs to (the relay/InputActivity routing key)
	DriverIdentity string // the D8/D55-attributed holder (read-leg attribution)
}

// ValidateDrive is the W3 drive-leg seat-validation choke point (sessions/10 §5 claim
// 2; D61/D137): given ONLY the writer_seat_id a DriveInput carries (the drive wire
// carries no session key — the seat-id IS the routing key, and this terminator minted
// it), it answers "is this the ONE live grant right now, which session does it drive,
// and who holds it?" — the LIVE-grant validation every DriveInput passes before any
// byte reaches Claude Code's stdin.
//
// It resolves the seat-id to its session through the terminator's own minted-token
// index (no DriveInput can name a seat this terminator did not mint — a record-only /
// legacy-leg holder carries id "", so a non-empty wire id never matches it), then
// reconciles that session's seat against the DURABLE RECORD (the D61 source of truth)
// under the per-session lock exactly as RequestSeat/YieldSeat do. So a seat that
// EXPIRED or was YIELDED mid-stream stops validating the instant it lapses (currentLive
// treats a lapsed/cleared seat as free, and the index entry is dropped on yield) — the
// seat is re-checked per frame, never cached by the drive stream.
//
// On success it returns the resolved DriveSeat; otherwise ErrSeatNotLive (no stdin, no
// InputActivity). An empty writer_seat_id, an id the terminator never minted (stale/
// forged), a free/expired/yielded seat, and a record-reconcile mismatch all refuse. A
// store read fault fails CLOSED (ErrSeatNotLive — a drive over an unreadable record is
// refused, never admitted).
func (a *SeatArbiter) ValidateDrive(ctx context.Context, writerSeatID string) (DriveSeat, error) {
	if writerSeatID == "" {
		// An absent id is not a live grant (it reaches no stdin, sessions/10 §5 claim 2).
		return DriveSeat{}, ErrSeatNotLive
	}

	// Resolve the seat-id → its session through the minted-token index. A seat-id this
	// terminator did not mint (stale/forged, or a record-only/legacy holder with id "")
	// resolves to no session: not a live grant.
	a.mu.Lock()
	sessionUUID, known := a.seatIndex[writerSeatID]
	a.mu.Unlock()
	if !known {
		return DriveSeat{}, ErrSeatNotLive
	}

	// Reconcile the resolved session's seat against the durable record under the
	// per-session lock (the same atomic read+arbitration step the grant path takes).
	unlock := a.lockSession(sessionUUID)
	defer unlock()
	cur, err := a.currentLive(ctx, sessionUUID, a.now())
	if err != nil {
		// A store read fault: fail CLOSED — a drive over an unreadable record is refused,
		// never admitted (the same fail-closed posture CurrentSeatID takes).
		return DriveSeat{}, ErrSeatNotLive
	}
	if cur == nil || cur.id != writerSeatID {
		// Free / expired / yielded (cur == nil), or the live seat changed to a different
		// minted id (a steal/renew superseded this one): the presented id is not the live
		// grant. (A stale index entry for a superseded id is dropped on the next setLive.)
		return DriveSeat{}, ErrSeatNotLive
	}
	return DriveSeat{SessionUUID: sessionUUID, DriverIdentity: cur.driver}, nil
}

// randomSeatID mints the opaque short-lived seat token (D39 — never a long-lived
// cred). crypto/rand does not fail in practice; a panic here is correct — the
// orchestrator must not issue a non-random seat token.
func randomSeatID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("attach: crypto/rand failed minting writer seat id: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
