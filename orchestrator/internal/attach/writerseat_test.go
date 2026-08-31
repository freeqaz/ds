package attach

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// collectEmitter is an Emitter that records every fanned SessionEvent so a test can
// assert the WRITER_SEAT_CHANGED handoff event reached the read stream (a steal
// cannot be silent).
type collectEmitter struct {
	mu  sync.Mutex
	evs []*attachv1.SessionEvent
}

func (c *collectEmitter) Emit(_ context.Context, ev *attachv1.SessionEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, ev)
	return nil
}

func (c *collectEmitter) seatChanges() []*attachv1.WriterSeatChange {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*attachv1.WriterSeatChange
	for _, ev := range c.evs {
		if ev.GetType() == attachv1.EventType_EVENT_TYPE_WRITER_SEAT_CHANGED {
			out = append(out, ev.GetWriterSeatChange())
		}
	}
	return out
}

// newArbiterWithReader builds an arbiter over a memory store + a real Fanout, plus a
// subscribed collectEmitter so the test observes the read-stream events. The
// attendedness probe is configurable for the steal-gate tests.
func newArbiterWithReader(t *testing.T, repo *store.Memory, sessionUUID string, probe AttendednessProbe, opts ...SeatArbiterOption) (*SeatArbiter, *collectEmitter) {
	t.Helper()
	fanout := NewFanout(0)
	em := &collectEmitter{}
	unsub, err := fanout.Subscribe(context.Background(), sessionUUID, 0, em)
	if err != nil {
		t.Fatalf("subscribe reader: %v", err)
	}
	t.Cleanup(unsub)
	allOpts := append([]SeatArbiterOption{WithAttendednessProbe(probe)}, opts...)
	return NewSeatArbiter(repo, fanout, allOpts...), em
}

// TestSeatArbiter_OneSeat_LoserRefused proves the D61 one-writer invariant: under
// concurrent RequestSeat calls exactly ONE grant lands and the other is refused with
// ErrSeatHeld — never a second live seat.
func TestSeatArbiter_OneSeat_LoserRefused(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	arb, _ := newArbiterWithReader(t, repo, "sess-1", nil)

	const racers = 16
	var wg sync.WaitGroup
	grants := make([]*attachv1.WriterSeatGrant, racers)
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			grants[i], errs[i] = arb.RequestSeat(ctx, SeatRequest{
				SessionUUID:    "sess-1",
				DriverIdentity: driverName(i),
			})
		}(i)
	}
	close(start)
	wg.Wait()

	wins, held := 0, 0
	var winner string
	for i := 0; i < racers; i++ {
		switch {
		case errs[i] == nil:
			wins++
			winner = grants[i].GetDriverIdentity()
		case errors.Is(errs[i], ErrSeatHeld):
			held++
		default:
			t.Fatalf("racer %d: unexpected err %v", i, errs[i])
		}
	}
	if wins != 1 {
		t.Fatalf("exactly one grant must win the race; got %d wins, %d held-refusals", wins, held)
	}
	if held != racers-1 {
		t.Fatalf("every loser must be refused ErrSeatHeld; got %d held, want %d", held, racers-1)
	}
	// The record must name the single winner — never a second seat.
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != winner || got.WriterRole != store.RoleWriter {
		t.Fatalf("record seat = (%q,%q), want winner (%q,WRITER)", got.WriterSeat, got.WriterRole, winner)
	}
}

func driverName(i int) string {
	return "driver-" + string(rune('a'+i))
}

// TestSeatArbiter_Grant_AttributionAndGrantedSeqObservable proves a grant is
// attributed (driver_identity on the grant + mirrored onto the record) and observable
// on the read stream at granted_seq (the WRITER_SEAT_CHANGED event's envelope seq ==
// the grant's granted_seq).
func TestSeatArbiter_Grant_AttributionAndGrantedSeqObservable(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	arb, em := newArbiterWithReader(t, repo, "sess-1", nil)

	grant, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "alice@org"})
	if err != nil {
		t.Fatalf("RequestSeat: %v", err)
	}
	// Attribution: the grant names the driver; the record mirrors it (so D78 reads it).
	if grant.GetDriverIdentity() != "alice@org" {
		t.Fatalf("grant driver = %q, want alice@org", grant.GetDriverIdentity())
	}
	if grant.GetWriterSeatId() == "" {
		t.Fatalf("grant must carry a non-empty writer_seat_id")
	}
	if grant.GetGrantedSeq() == 0 {
		t.Fatalf("grant must carry a non-zero granted_seq")
	}
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "alice@org" || got.WriterRole != store.RoleWriter {
		t.Fatalf("record seat = (%q,%q), want (alice@org,WRITER)", got.WriterSeat, got.WriterRole)
	}

	// Observable: a WRITER_SEAT_CHANGED event reached the read stream, GRANT kind,
	// attributed, at the SAME seq the grant returned.
	changes := em.seatChanges()
	if len(changes) != 1 {
		t.Fatalf("read stream saw %d WriterSeatChange events, want 1", len(changes))
	}
	c := changes[0]
	if c.GetKind() != attachv1.WriterSeatChangeKind_WRITER_SEAT_CHANGE_KIND_GRANT {
		t.Fatalf("change kind = %v, want GRANT", c.GetKind())
	}
	if c.GetDriverIdentity() != "alice@org" || c.GetWriterSeatId() != grant.GetWriterSeatId() {
		t.Fatalf("change attribution/seat = (%q,%q), want (alice@org,%q)", c.GetDriverIdentity(), c.GetWriterSeatId(), grant.GetWriterSeatId())
	}
	// The envelope seq the event was published at IS the granted_seq.
	if seq := watchedSeqOf(em, attachv1.WriterSeatChangeKind_WRITER_SEAT_CHANGE_KIND_GRANT); seq != grant.GetGrantedSeq() {
		t.Fatalf("WRITER_SEAT_CHANGED envelope seq = %d, want granted_seq %d", seq, grant.GetGrantedSeq())
	}
}

// watchedSeqOf returns the envelope seq of the first WRITER_SEAT_CHANGED event with
// the given kind seen on the read stream.
func watchedSeqOf(em *collectEmitter, kind attachv1.WriterSeatChangeKind) uint64 {
	em.mu.Lock()
	defer em.mu.Unlock()
	for _, ev := range em.evs {
		if ev.GetType() == attachv1.EventType_EVENT_TYPE_WRITER_SEAT_CHANGED && ev.GetWriterSeatChange().GetKind() == kind {
			return ev.GetSeq()
		}
	}
	return 0
}

// TestSeatArbiter_StealRefusedOnAttended proves the D138 default: a force_steal of an
// ATTENDED held seat is refused (ErrStealAttended); the original holder keeps the seat.
func TestSeatArbiter_StealRefusedOnAttended(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	attendedProbe := AttendednessProbeFunc(func(context.Context, string) (bool, error) { return true, nil })
	arb, _ := newArbiterWithReader(t, repo, "sess-1", attendedProbe)

	if _, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "alice@org"}); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	_, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "bob@org", ForceSteal: true})
	if !errors.Is(err, ErrStealAttended) {
		t.Fatalf("attended steal err = %v, want ErrStealAttended", err)
	}
	// The seat must still belong to the original holder — a refused steal never mutates.
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "alice@org" {
		t.Fatalf("record seat = %q after refused steal, want alice@org", got.WriterSeat)
	}
}

// TestSeatArbiter_StealAllowedOnIdle proves an IDLE (unattended) seat may be taken via
// force_steal without approval, and the handoff is observable as a STEAL.
func TestSeatArbiter_StealAllowedOnIdle(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	idleProbe := AttendednessProbeFunc(func(context.Context, string) (bool, error) { return false, nil })
	arb, em := newArbiterWithReader(t, repo, "sess-1", idleProbe)

	if _, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "alice@org"}); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	grant, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "bob@org", ForceSteal: true})
	if err != nil {
		t.Fatalf("idle steal: %v", err)
	}
	if grant.GetDriverIdentity() != "bob@org" {
		t.Fatalf("steal grant driver = %q, want bob@org", grant.GetDriverIdentity())
	}
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "bob@org" {
		t.Fatalf("record seat = %q after idle steal, want bob@org", got.WriterSeat)
	}
	// The steal must be observable on the read stream with prev_driver_identity set.
	var steal *attachv1.WriterSeatChange
	for _, c := range em.seatChanges() {
		if c.GetKind() == attachv1.WriterSeatChangeKind_WRITER_SEAT_CHANGE_KIND_STEAL {
			steal = c
		}
	}
	if steal == nil {
		t.Fatalf("read stream saw no STEAL WriterSeatChange")
	}
	if steal.GetPrevDriverIdentity() != "alice@org" || steal.GetDriverIdentity() != "bob@org" {
		t.Fatalf("steal prev/new = (%q,%q), want (alice@org,bob@org)", steal.GetPrevDriverIdentity(), steal.GetDriverIdentity())
	}
}

// TestSeatArbiter_YieldReleasesAndReleasedSeqObservable proves a yield clears the
// record seat, returns a non-zero released_seq, and is observable on the read stream
// as a YIELD at that seq; and that a yield by a non-holder id is an idempotent no-op.
func TestSeatArbiter_YieldReleasesAndReleasedSeqObservable(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	arb, em := newArbiterWithReader(t, repo, "sess-1", nil)

	grant, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "alice@org"})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	// A yield of a NON-matching seat id is an idempotent no-op (released_seq 0).
	if seq, err := arb.YieldSeat(ctx, "sess-1", "not-the-live-seat"); err != nil || seq != 0 {
		t.Fatalf("non-holder yield = (seq %d, err %v), want (0, nil)", seq, err)
	}
	// The real yield releases and returns the released_seq.
	releasedSeq, err := arb.YieldSeat(ctx, "sess-1", grant.GetWriterSeatId())
	if err != nil {
		t.Fatalf("yield: %v", err)
	}
	if releasedSeq == 0 || releasedSeq <= grant.GetGrantedSeq() {
		t.Fatalf("released_seq = %d, want > granted_seq %d", releasedSeq, grant.GetGrantedSeq())
	}
	// The record seat is cleared (so D78 reports unattended going forward).
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "" || got.WriterRole != store.RoleNone {
		t.Fatalf("record seat = (%q,%q) after yield, want empty/None", got.WriterSeat, got.WriterRole)
	}
	// The yield is observable on the read stream at released_seq.
	if seq := watchedSeqOf(em, attachv1.WriterSeatChangeKind_WRITER_SEAT_CHANGE_KIND_YIELD); seq != releasedSeq {
		t.Fatalf("YIELD envelope seq = %d, want released_seq %d", seq, releasedSeq)
	}
	// After a yield the seat is FREE — the next request is a clean GRANT, not a steal.
	g2, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "bob@org"})
	if err != nil {
		t.Fatalf("post-yield grant: %v", err)
	}
	if g2.GetDriverIdentity() != "bob@org" {
		t.Fatalf("post-yield grant driver = %q, want bob@org", g2.GetDriverIdentity())
	}
}

// TestSeatArbiter_ExpiredSeatTreatedAsFree proves a seat past its TTL is treated as
// free: the next request GRANTS without a steal (D39 short-lived / renew-by-re-request).
func TestSeatArbiter_ExpiredSeatTreatedAsFree(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	now := time.Unix(1_000, 0)
	clock := func() time.Time { return now }
	// Attended probe would refuse a steal — but an EXPIRED seat must not even consult it.
	attendedProbe := AttendednessProbeFunc(func(context.Context, string) (bool, error) { return true, nil })
	arb, _ := newArbiterWithReader(t, repo, "sess-1", attendedProbe, WithSeatClock(clock), WithSeatTTL(30*time.Second))

	if _, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "alice@org"}); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	// Advance past the TTL; the seat is now free.
	now = now.Add(time.Minute)
	g2, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "bob@org"})
	if err != nil {
		t.Fatalf("post-expiry grant (no force_steal): %v", err)
	}
	if g2.GetDriverIdentity() != "bob@org" {
		t.Fatalf("post-expiry grant driver = %q, want bob@org", g2.GetDriverIdentity())
	}
}

// seatRecordHeldBy sets the durable record's writer seat to driver WITHOUT going
// through the arbiter's in-process map — exactly what the legacy AcquireWriter handle
// leg (seat.go) does, and what a durable record looks like after an orchestrator
// restart wiped the in-process seats map. The arbiter must treat this as a LIVE held
// seat (the record is the D61 source of truth).
func seatRecordHeldBy(t *testing.T, repo *store.Memory, uuid, driver string) {
	t.Helper()
	writerRole := store.RoleWriter
	if _, err := repo.UpdateSession(context.Background(), uuid, store.SessionUpdate{
		WriterSeat: &driver,
		WriterRole: &writerRole,
	}); err != nil {
		t.Fatalf("seatRecordHeldBy(%s,%s): %v", uuid, driver, err)
	}
}

// TestSeatArbiter_RecordHolderUnknownToMap_RefusesSecondWriter proves the D61 "one
// live seat" invariant survives the two cross-leg / restart-amnesia paths the reviewer
// flagged: the record names a live writer the in-process map has NO entry for (a seat
// set by the legacy AcquireWriter leg, or a durable holder that outlived a restart).
// A subsequent RequestSeat by a DIFFERENT driver must be REFUSED with ErrSeatHeld —
// never granted a second seat that overwrites the record.
func TestSeatArbiter_RecordHolderUnknownToMap_RefusesSecondWriter(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	// The record names alice as the live writer; the arbiter's in-process map is empty
	// (the seat was set by the other leg / before a restart).
	seatRecordHeldBy(t, repo, "sess-1", "alice@org")
	arb, _ := newArbiterWithReader(t, repo, "sess-1", nil)

	_, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "bob@org"})
	if !errors.Is(err, ErrSeatHeld) {
		t.Fatalf("second writer over a record-named holder err = %v, want ErrSeatHeld", err)
	}
	// The record must STILL name alice — the refused request never overwrote it.
	got, _ := repo.GetSession(ctx, "sess-1")
	if got.WriterSeat != "alice@org" || got.WriterRole != store.RoleWriter {
		t.Fatalf("record seat = (%q,%q) after refused second writer, want (alice@org,WRITER)", got.WriterSeat, got.WriterRole)
	}
}

// TestSeatArbiter_RecordHolderSameDriver_RenewsAndAdopts proves the same-driver request
// over a record-only holder is the idempotent renewal: the recorded driver re-requests,
// gets a freshly-minted token (this terminator now owns the seat metadata), and the
// record keeps naming that driver. This is how a post-restart driver re-arms its seat.
func TestSeatArbiter_RecordHolderSameDriver_RenewsAndAdopts(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	seatRecordHeldBy(t, repo, "sess-1", "alice@org")
	arb, _ := newArbiterWithReader(t, repo, "sess-1", nil)

	grant, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "alice@org"})
	if err != nil {
		t.Fatalf("same-driver renewal over record-only holder: %v", err)
	}
	if grant.GetDriverIdentity() != "alice@org" || grant.GetWriterSeatId() == "" {
		t.Fatalf("renewal grant = (%q,%q), want (alice@org, non-empty seat id)", grant.GetDriverIdentity(), grant.GetWriterSeatId())
	}
	// The terminator now owns the token — CurrentSeatID matches the freshly minted seat.
	if id := arb.CurrentSeatID(ctx, "sess-1"); id != grant.GetWriterSeatId() {
		t.Fatalf("CurrentSeatID = %q after renewal, want %q", id, grant.GetWriterSeatId())
	}
}

// TestSeatArbiter_RecordHolderUnknownToMap_StealGated proves a force_steal of a
// record-only holder still runs the D138 gate: an ATTENDED record-named holder is
// refused without approval, and an IDLE one may be taken — the steal path consults the
// record-derived holder exactly like an in-process one.
func TestSeatArbiter_RecordHolderUnknownToMap_StealGated(t *testing.T) {
	ctx := context.Background()

	t.Run("attended record holder refuses steal", func(t *testing.T) {
		repo := store.NewMemory()
		seedSession(t, repo, "sess-1", 1)
		seatRecordHeldBy(t, repo, "sess-1", "alice@org")
		attended := AttendednessProbeFunc(func(context.Context, string) (bool, error) { return true, nil })
		arb, _ := newArbiterWithReader(t, repo, "sess-1", attended)

		_, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "bob@org", ForceSteal: true})
		if !errors.Is(err, ErrStealAttended) {
			t.Fatalf("steal of attended record holder err = %v, want ErrStealAttended", err)
		}
		got, _ := repo.GetSession(ctx, "sess-1")
		if got.WriterSeat != "alice@org" {
			t.Fatalf("record seat = %q after refused steal, want alice@org", got.WriterSeat)
		}
	})

	t.Run("idle record holder allows steal", func(t *testing.T) {
		repo := store.NewMemory()
		seedSession(t, repo, "sess-1", 1)
		seatRecordHeldBy(t, repo, "sess-1", "alice@org")
		idle := AttendednessProbeFunc(func(context.Context, string) (bool, error) { return false, nil })
		arb, em := newArbiterWithReader(t, repo, "sess-1", idle)

		grant, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "bob@org", ForceSteal: true})
		if err != nil {
			t.Fatalf("steal of idle record holder: %v", err)
		}
		if grant.GetDriverIdentity() != "bob@org" {
			t.Fatalf("steal grant driver = %q, want bob@org", grant.GetDriverIdentity())
		}
		got, _ := repo.GetSession(ctx, "sess-1")
		if got.WriterSeat != "bob@org" {
			t.Fatalf("record seat = %q after idle steal, want bob@org", got.WriterSeat)
		}
		// The steal is observable, prev_driver = the record-named holder.
		var steal *attachv1.WriterSeatChange
		for _, c := range em.seatChanges() {
			if c.GetKind() == attachv1.WriterSeatChangeKind_WRITER_SEAT_CHANGE_KIND_STEAL {
				steal = c
			}
		}
		if steal == nil || steal.GetPrevDriverIdentity() != "alice@org" {
			t.Fatalf("steal event = %+v, want prev_driver alice@org", steal)
		}
	})
}

// TestSeatArbiter_RecordCleared_SeatIsFree proves the record (source of truth) winning a
// clear frees the seat even if a stale in-process entry lingers: after the record's
// writer is cleared out-of-band (e.g. a legacy ReleaseWriter), the next request is a
// clean GRANT, not a steal.
func TestSeatArbiter_RecordCleared_SeatIsFree(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	arb, _ := newArbiterWithReader(t, repo, "sess-1", nil)

	if _, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "alice@org"}); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	// Clear the record out-of-band (the in-process map still holds alice's live entry).
	empty := ""
	none := store.RoleNone
	if _, err := repo.UpdateSession(ctx, "sess-1", store.SessionUpdate{WriterSeat: &empty, WriterRole: &none}); err != nil {
		t.Fatalf("out-of-band clear: %v", err)
	}
	// The record won the clear: a DIFFERENT driver gets a clean GRANT (no force_steal).
	g2, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "bob@org"})
	if err != nil {
		t.Fatalf("grant after record clear (no force_steal): %v", err)
	}
	if g2.GetDriverIdentity() != "bob@org" {
		t.Fatalf("post-clear grant driver = %q, want bob@org", g2.GetDriverIdentity())
	}
}

// TestSeatArbiter_StoreReadFault_Surfaced proves a store read fault on the arbitration
// read is surfaced (the seat is not silently treated as free on a stalled record store).
func TestSeatArbiter_StoreReadFault_Surfaced(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("record store stalled")
	arb := NewSeatArbiter(faultySeatStore{err: boom}, NewFanout(0))

	_, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "alice@org"})
	if !errors.Is(err, boom) {
		t.Fatalf("RequestSeat over a faulty store err = %v, want it to wrap %v", err, boom)
	}
}

// faultySeatStore fails every GetSession with a fixed error — a stalled record store.
type faultySeatStore struct{ err error }

func (f faultySeatStore) GetSession(context.Context, string) (store.Session, error) {
	return store.Session{}, f.err
}

func (f faultySeatStore) UpdateSession(context.Context, string, store.SessionUpdate) (store.Session, error) {
	return store.Session{}, f.err
}

// TestSeatArbiter_AnonymousDriverRefused proves an empty driver identity is refused
// before any mutation (D8/D55 attribution).
func TestSeatArbiter_AnonymousDriverRefused(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	arb, _ := newArbiterWithReader(t, repo, "sess-1", nil)

	_, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: ""})
	if !errors.Is(err, ErrDriverIdentityRequired) {
		t.Fatalf("anonymous seat err = %v, want ErrDriverIdentityRequired", err)
	}
}

// TestSeatArbiter_ValidateDrive is the W3 drive-leg seat-validation choke point: it
// resolves a writer_seat_id (the only routing key on the drive wire) to its session +
// attributed driver ONLY when it is the ONE live grant — and refuses ErrSeatNotLive for
// an empty / forged / expired / yielded / stolen-over id. A second session's live seat
// proves the resolution routes by the minted token, never the (absent) wire session.
func TestSeatArbiter_ValidateDrive(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	seedSession(t, repo, "sess-1", 1)
	seedSession(t, repo, "sess-2", 2)

	now := time.Unix(1_700_000_000, 0).UTC()
	clock := func() time.Time { return now }
	arb := NewSeatArbiter(repo, NewFanout(0), WithSeatClock(clock), WithSeatTTL(time.Minute))

	g1, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-1", DriverIdentity: "alice@org"})
	if err != nil {
		t.Fatalf("grant sess-1: %v", err)
	}
	g2, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-2", DriverIdentity: "bob@org"})
	if err != nil {
		t.Fatalf("grant sess-2: %v", err)
	}

	// A live seat-id resolves to its OWN session + attributed driver (routing by the
	// minted token — the drive wire carries no session key).
	seat, err := arb.ValidateDrive(ctx, g1.GetWriterSeatId())
	if err != nil {
		t.Fatalf("ValidateDrive(live g1): %v", err)
	}
	if seat.SessionUUID != "sess-1" || seat.DriverIdentity != "alice@org" {
		t.Fatalf("ValidateDrive(g1) = %+v, want {sess-1, alice@org}", seat)
	}
	seat2, err := arb.ValidateDrive(ctx, g2.GetWriterSeatId())
	if err != nil {
		t.Fatalf("ValidateDrive(live g2): %v", err)
	}
	if seat2.SessionUUID != "sess-2" || seat2.DriverIdentity != "bob@org" {
		t.Fatalf("ValidateDrive(g2) = %+v, want {sess-2, bob@org}", seat2)
	}

	// Empty + forged ids refuse.
	for _, id := range []string{"", "deadbeefdeadbeefdeadbeefdeadbeef"} {
		if _, err := arb.ValidateDrive(ctx, id); !errors.Is(err, ErrSeatNotLive) {
			t.Fatalf("ValidateDrive(%q) err = %v, want ErrSeatNotLive", id, err)
		}
	}

	// A YIELDED seat stops resolving (its id is dropped from the drive index + the record
	// is cleared).
	if _, err := arb.YieldSeat(ctx, "sess-1", g1.GetWriterSeatId()); err != nil {
		t.Fatalf("yield g1: %v", err)
	}
	if _, err := arb.ValidateDrive(ctx, g1.GetWriterSeatId()); !errors.Is(err, ErrSeatNotLive) {
		t.Fatalf("ValidateDrive(yielded g1) err = %v, want ErrSeatNotLive", err)
	}

	// A renew SUPERSEDES the prior id: the old g2 id stops resolving, the fresh one does.
	g2b, err := arb.RequestSeat(ctx, SeatRequest{SessionUUID: "sess-2", DriverIdentity: "bob@org"})
	if err != nil {
		t.Fatalf("renew sess-2: %v", err)
	}
	if g2b.GetWriterSeatId() == g2.GetWriterSeatId() {
		t.Fatalf("renew minted the same id; expected a fresh token")
	}
	if _, err := arb.ValidateDrive(ctx, g2.GetWriterSeatId()); !errors.Is(err, ErrSeatNotLive) {
		t.Fatalf("ValidateDrive(superseded g2) err = %v, want ErrSeatNotLive", err)
	}
	if seat, err := arb.ValidateDrive(ctx, g2b.GetWriterSeatId()); err != nil || seat.SessionUUID != "sess-2" {
		t.Fatalf("ValidateDrive(renewed g2b) = (%+v, %v), want {sess-2,...}, nil", seat, err)
	}

	// An EXPIRED seat (clock past the TTL) stops resolving (re-validated against the live
	// record per call).
	now = now.Add(2 * time.Minute)
	if _, err := arb.ValidateDrive(ctx, g2b.GetWriterSeatId()); !errors.Is(err, ErrSeatNotLive) {
		t.Fatalf("ValidateDrive(expired g2b) err = %v, want ErrSeatNotLive", err)
	}
}
