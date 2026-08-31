package controlplane

// writerrelay_drive_test.go covers the W3 DriveSession leg (sessions/10 §3/§5/§6 W3;
// D78/D137/D138): the drive channel that validates a DriveInput's writer_seat_id
// against the LIVE grant at the single attach.SeatArbiter terminator, forwards the
// admitted frame to Claude Code's stdin via the host-agent relay (the DriveSink seam,
// a fake here), and emits the v1 InputActivity read-leg projection on the SAME Fanout
// the seat handoff rides — server-stamped, no input payload. The invariants under test:
//
//   - drive-with-a-valid-seat → forwarded to the (fake) sink + InputActivity emitted on
//     the read stream (server-stamped at/kind, no payload) + the ack echoes client_seq
//     and the emitted activity seq;
//   - drive-with-a-stale/forged/absent seat → REFUSED, the sink is NOT called, NO
//     InputActivity is emitted (sessions/10 §5 claim 2);
//   - a seat that EXPIRES mid-stream stops being drivable (re-checked per frame);
//   - a replayed / non-monotonic client_seq → REFUSED (at-most-once, claim 4), no stdin,
//     no InputActivity;
//   - the relay originates NO input of its own — every forwarded frame is one the arbiter
//     admitted for the live seat-holder (claim 5);
//   - a nil DriveSink FAILS CLOSED (the RPC refuses, never silently drops).

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// fakeDriveSink is a test DriveSink: it records every (session, input) the orchestrator
// forwarded to CC stdin, and can be configured to fail the forward (a transport fault).
// It is the proof surface for "the relay forwards ONLY admitted frames and originates
// nothing": the test asserts exactly which inputs reached it.
type fakeDriveSink struct {
	mu     sync.Mutex
	err    error // when non-nil, Drive fails (a relay transport fault)
	drives []driveCall
}

type driveCall struct {
	session string
	input   *attachv1.DriveInput
}

func (f *fakeDriveSink) Drive(_ context.Context, sessionUUID string, in *attachv1.DriveInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.drives = append(f.drives, driveCall{session: sessionUUID, input: in})
	return nil
}

func (f *fakeDriveSink) calls() []driveCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]driveCall, len(f.drives))
	copy(out, f.drives)
	return out
}

func (f *fakeDriveSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.drives)
}

// fakeDriveStream is a scripted bidi DriveSession server stream (D50 — no live gRPC): it
// hands the handler the queued inbound DriveSessionRequests in order (then io.EOF), and
// collects every DriveSessionResponse the handler Sends. It embeds the generated server
// interface so the unused ServerStream methods are present (never called by the handler).
type fakeDriveStream struct {
	attachv1.WriterRelayService_DriveSessionServer
	ctx context.Context

	mu   sync.Mutex
	in   []*attachv1.DriveSessionRequest
	next int
	sent []*attachv1.DriveSessionResponse
}

func (s *fakeDriveStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *fakeDriveStream) Recv() (*attachv1.DriveSessionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next >= len(s.in) {
		return nil, io.EOF
	}
	req := s.in[s.next]
	s.next++
	return req, nil
}

func (s *fakeDriveStream) Send(resp *attachv1.DriveSessionResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, resp)
	return nil
}

func (s *fakeDriveStream) responses() []*attachv1.DriveSessionResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*attachv1.DriveSessionResponse, len(s.sent))
	copy(out, s.sent)
	return out
}

func driveReq(seatID string, kind attachv1.DriveBlockKind, payload string, clientSeq uint64) *attachv1.DriveSessionRequest {
	return &attachv1.DriveSessionRequest{Input: &attachv1.DriveInput{
		WriterSeatId: seatID,
		Kind:         kind,
		Payload:      []byte(payload),
		ClientSeq:    clientSeq,
	}}
}

// readStreamRecorder is a Fanout subscriber that collects the read-stream events (the
// spectator surface): the test asserts which InputActivity events landed (and that a
// refused drive emitted none).
type readStreamRecorder struct {
	mu  sync.Mutex
	evs []*attachv1.SessionEvent
}

func (r *readStreamRecorder) Emit(_ context.Context, ev *attachv1.SessionEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *readStreamRecorder) inputActivities() []*attachv1.InputActivity {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*attachv1.InputActivity, 0)
	for _, ev := range r.evs {
		if ev.GetType() == attachv1.EventType_EVENT_TYPE_INPUT_ACTIVITY {
			out = append(out, ev.GetInputActivity())
		}
	}
	return out
}

// driveRig is a WriterRelayService wired for the W3 drive leg: a real arbiter + Fanout
// over a seeded store, a fake DriveSink, a pinned clock, and a live seat granted to
// "alice@org" (so seatID is a real minted live grant). A recording subscriber on the
// session's read stream observes the InputActivity projections.
type driveRig struct {
	svc      *WriterRelayService
	sink     *fakeDriveSink
	repo     *store.Memory
	fanout   *attach.Fanout
	arb      *attach.SeatArbiter
	seatID   string
	clockNow *time.Time
	reader   *readStreamRecorder
}

// newDriveRig builds the rig and grants a live seat. driveSink nil exercises the
// fail-closed path; otherwise the supplied fake is wired.
func newDriveRig(t *testing.T, sink *fakeDriveSink) *driveRig {
	t.Helper()
	repo := store.NewMemory()
	if _, err := repo.CreateSession(context.Background(), store.Session{
		Ref:   store.SessionRef{SessionUUID: "sess-1", HostID: "host-a", HostSessionIndex: 1, TapName: "tap-1"},
		State: store.SessionPending,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	clockNow := &now
	clock := func() time.Time { return *clockNow }

	fanout := attach.NewFanout(0)
	arb := attach.NewSeatArbiter(repo, fanout,
		attach.WithSeatClock(clock),
		attach.WithSeatTTL(2*time.Minute),
		attach.WithAttendednessProbe(writerSeatAttendedness(repo)),
	)

	// Subscribe a recording reader BEFORE the grant so it observes the WRITER_SEAT_CHANGED
	// grant event AND every later InputActivity (the spectator's read stream).
	reader := &readStreamRecorder{}
	if _, err := fanout.Subscribe(context.Background(), "sess-1", 0, reader); err != nil {
		t.Fatalf("subscribe reader: %v", err)
	}

	var driveSink DriveSink
	if sink != nil {
		driveSink = sink
	}
	svc := newWriterRelayService(arb, fanout, driveSink, nil, nil, clock)

	// Grant a live seat to alice → a real minted writer_seat_id the drive frames carry.
	grant, err := arb.RequestSeat(context.Background(), attach.SeatRequest{
		SessionUUID:    "sess-1",
		DriverIdentity: "alice@org",
	})
	if err != nil {
		t.Fatalf("grant seat: %v", err)
	}

	return &driveRig{
		svc:      svc,
		sink:     sink,
		repo:     repo,
		fanout:   fanout,
		arb:      arb,
		seatID:   grant.GetWriterSeatId(),
		clockNow: clockNow,
		reader:   reader,
	}
}

// TestDriveSession_ValidSeatForwardsAndEmits proves a DriveInput carrying the live seat
// id is FORWARDED to the (fake) sink, emits a SERVER-STAMPED v1 InputActivity on the read
// stream (no payload on the read leg), and is acked with {accepted_client_seq,
// emitted_input_activity_seq}.
func TestDriveSession_ValidSeatForwardsAndEmits(t *testing.T) {
	sink := &fakeDriveSink{}
	rig := newDriveRig(t, sink)

	stream := &fakeDriveStream{
		ctx: context.Background(),
		in: []*attachv1.DriveSessionRequest{
			driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "hello cc", 1),
		},
	}
	if err := rig.svc.DriveSession(stream); err != nil {
		t.Fatalf("DriveSession: %v", err)
	}

	// Forwarded to CC stdin via the relay — exactly once, keyed on the resolved session,
	// carrying the full payload (the body rides the WRITE leg).
	calls := sink.calls()
	if len(calls) != 1 {
		t.Fatalf("sink calls = %d, want 1 (the one admitted frame)", len(calls))
	}
	if calls[0].session != "sess-1" {
		t.Fatalf("forwarded session = %q, want sess-1 (the arbiter-resolved session)", calls[0].session)
	}
	if string(calls[0].input.GetPayload()) != "hello cc" {
		t.Fatalf("forwarded payload = %q, want %q", calls[0].input.GetPayload(), "hello cc")
	}

	// InputActivity emitted on the read stream: server-stamped at, mapped kind, the seat
	// id, NO payload on the read leg.
	acts := rig.reader.inputActivities()
	if len(acts) != 1 {
		t.Fatalf("InputActivity events = %d, want 1", len(acts))
	}
	ia := acts[0]
	if ia.GetWriterSeatId() != rig.seatID {
		t.Fatalf("InputActivity writer_seat_id = %q, want %q", ia.GetWriterSeatId(), rig.seatID)
	}
	if ia.GetSessionUuid() != "sess-1" {
		t.Fatalf("InputActivity session_uuid = %q, want sess-1", ia.GetSessionUuid())
	}
	if ia.GetKind() != attachv1.InputActivityKind_INPUT_ACTIVITY_KIND_TEXT {
		t.Fatalf("InputActivity kind = %v, want TEXT (mapped from DriveBlockKind_TEXT)", ia.GetKind())
	}
	if ia.GetAt() != uint64(rig.clockNow.Unix()) {
		t.Fatalf("InputActivity at = %d, want server-stamped %d", ia.GetAt(), rig.clockNow.Unix())
	}

	// Ack echoes client_seq and the emitted activity seq (non-zero — the input WAS made
	// observable). The activity seq is the WatchSession seq the InputActivity landed at.
	resps := stream.responses()
	if len(resps) != 1 {
		t.Fatalf("acks = %d, want 1", len(resps))
	}
	if resps[0].GetAcceptedClientSeq() != 1 {
		t.Fatalf("accepted_client_seq = %d, want 1", resps[0].GetAcceptedClientSeq())
	}
	if resps[0].GetEmittedInputActivitySeq() == 0 {
		t.Fatalf("emitted_input_activity_seq = 0, want the non-zero read-stream seq of the emitted InputActivity")
	}
}

// TestDriveSession_StaleForgedAbsentSeatRejected proves a DriveInput whose writer_seat_id
// is NOT the live grant (forged, or absent) is REFUSED: the sink is NOT called and NO
// InputActivity is emitted (sessions/10 §5 claim 2).
func TestDriveSession_StaleForgedAbsentSeatRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		seat string
	}{
		{"forged", "deadbeefdeadbeefdeadbeefdeadbeef"},
		{"absent", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &fakeDriveSink{}
			rig := newDriveRig(t, sink)

			stream := &fakeDriveStream{
				ctx: context.Background(),
				in: []*attachv1.DriveSessionRequest{
					driveReq(tc.seat, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "should not reach stdin", 1),
				},
			}
			if err := rig.svc.DriveSession(stream); err != nil {
				t.Fatalf("DriveSession: %v", err)
			}

			if sink.count() != 0 {
				t.Fatalf("sink calls = %d, want 0 — a non-live seat reaches NO stdin", sink.count())
			}
			if n := len(rig.reader.inputActivities()); n != 0 {
				t.Fatalf("InputActivity events = %d, want 0 — a non-live seat emits NO activity", n)
			}
			// The refusal is in-band (the stream is not torn): an ack with no admitted seq.
			resps := stream.responses()
			if len(resps) != 1 {
				t.Fatalf("acks = %d, want 1 (the in-band refusal ack)", len(resps))
			}
			if resps[0].GetAcceptedClientSeq() != 0 || resps[0].GetEmittedInputActivitySeq() != 0 {
				t.Fatalf("refusal ack = %+v, want both seqs 0", resps[0])
			}
		})
	}
}

// TestDriveSession_SeatExpiredMidStreamStops proves a seat that EXPIRES mid-stream stops
// being drivable: the first frame (seat live) forwards + emits; after the clock advances
// past the TTL the second frame (same seat id) is REFUSED — re-validated per frame.
func TestDriveSession_SeatExpiredMidStreamStops(t *testing.T) {
	sink := &fakeDriveSink{}
	rig := newDriveRig(t, sink)

	// Frame 1: seat live → admitted. Then expire the seat (advance past the 2-min TTL).
	// Frame 2: same seat id, now lapsed → refused. The handler drains both before EOF, so
	// to interleave the clock advance we drive them as two separate single-frame streams.
	s1 := &fakeDriveStream{ctx: context.Background(), in: []*attachv1.DriveSessionRequest{
		driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "while live", 1),
	}}
	if err := rig.svc.DriveSession(s1); err != nil {
		t.Fatalf("DriveSession (live): %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("after live frame: sink calls = %d, want 1", sink.count())
	}

	// Expire the seat mid-stream: push the shared clock past the seat's TTL.
	*rig.clockNow = rig.clockNow.Add(3 * time.Minute)

	s2 := &fakeDriveStream{ctx: context.Background(), in: []*attachv1.DriveSessionRequest{
		driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "after expiry", 2),
	}}
	if err := rig.svc.DriveSession(s2); err != nil {
		t.Fatalf("DriveSession (expired): %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("after expired frame: sink calls = %d, want still 1 (an expired seat reaches no stdin)", sink.count())
	}
	if n := len(rig.reader.inputActivities()); n != 1 {
		t.Fatalf("InputActivity events = %d, want 1 (only the live frame projected)", n)
	}
	resps := s2.responses()
	if len(resps) != 1 || resps[0].GetAcceptedClientSeq() != 0 {
		t.Fatalf("expired-frame ack = %+v, want a refusal (accepted_client_seq 0)", resps)
	}
}

// TestDriveSession_YieldMidStreamStops proves a seat YIELDED mid-stream stops being
// drivable (the same per-frame re-validation as expiry, via the cooperative release).
func TestDriveSession_YieldMidStreamStops(t *testing.T) {
	sink := &fakeDriveSink{}
	rig := newDriveRig(t, sink)

	s1 := &fakeDriveStream{ctx: context.Background(), in: []*attachv1.DriveSessionRequest{
		driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "before yield", 1),
	}}
	if err := rig.svc.DriveSession(s1); err != nil {
		t.Fatalf("DriveSession (held): %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("held frame: sink calls = %d, want 1", sink.count())
	}

	// Cooperative yield: the seat goes free, so its id must stop routing to stdin.
	if _, err := rig.arb.YieldSeat(context.Background(), "sess-1", rig.seatID); err != nil {
		t.Fatalf("YieldSeat: %v", err)
	}

	s2 := &fakeDriveStream{ctx: context.Background(), in: []*attachv1.DriveSessionRequest{
		driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "after yield", 2),
	}}
	if err := rig.svc.DriveSession(s2); err != nil {
		t.Fatalf("DriveSession (yielded): %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("yielded frame: sink calls = %d, want still 1 (a yielded seat reaches no stdin)", sink.count())
	}
}

// TestDriveSession_ReplayRejected proves a non-monotonic client_seq is REFUSED
// (at-most-once / replay rejection, claim 4): a replayed seq reaches NO stdin and emits
// NO InputActivity, but the stream continues.
func TestDriveSession_ReplayRejected(t *testing.T) {
	sink := &fakeDriveSink{}
	rig := newDriveRig(t, sink)

	stream := &fakeDriveStream{
		ctx: context.Background(),
		in: []*attachv1.DriveSessionRequest{
			driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "first", 1),  // admitted
			driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "replay", 1), // replay of seq 1 → refused
			driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "stale", 0),  // seq 0 → refused
			driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "second", 2), // monotonic → admitted
		},
	}
	if err := rig.svc.DriveSession(stream); err != nil {
		t.Fatalf("DriveSession: %v", err)
	}

	// Only the two monotonic frames (seq 1 then seq 2) reached stdin; the replay and the
	// seq-0 frame were refused.
	calls := sink.calls()
	if len(calls) != 2 {
		t.Fatalf("sink calls = %d, want 2 (only the monotonic frames)", len(calls))
	}
	if string(calls[0].input.GetPayload()) != "first" || string(calls[1].input.GetPayload()) != "second" {
		t.Fatalf("forwarded payloads = [%q, %q], want [first, second]", calls[0].input.GetPayload(), calls[1].input.GetPayload())
	}
	if n := len(rig.reader.inputActivities()); n != 2 {
		t.Fatalf("InputActivity events = %d, want 2 (one per admitted frame)", n)
	}

	resps := stream.responses()
	if len(resps) != 4 {
		t.Fatalf("acks = %d, want 4 (one per inbound frame)", len(resps))
	}
	// Frame 1 admitted; frame 2 (replay) refused; frame 3 (seq 0) refused; frame 4 admitted.
	if resps[0].GetAcceptedClientSeq() != 1 {
		t.Fatalf("frame 1 ack accepted = %d, want 1", resps[0].GetAcceptedClientSeq())
	}
	if resps[1].GetAcceptedClientSeq() != 0 || resps[2].GetAcceptedClientSeq() != 0 {
		t.Fatalf("replay/stale acks = [%d,%d], want both refused (0)", resps[1].GetAcceptedClientSeq(), resps[2].GetAcceptedClientSeq())
	}
	if resps[3].GetAcceptedClientSeq() != 2 {
		t.Fatalf("frame 4 ack accepted = %d, want 2", resps[3].GetAcceptedClientSeq())
	}
}

// TestDriveSession_NilSinkFailsClosed proves a DriveSession with NO live drive sink
// FAILS CLOSED: the whole stream refuses Unavailable rather than accept-then-drop an
// admitted frame.
func TestDriveSession_NilSinkFailsClosed(t *testing.T) {
	rig := newDriveRig(t, nil) // nil sink → fail-closed

	stream := &fakeDriveStream{ctx: context.Background(), in: []*attachv1.DriveSessionRequest{
		driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "x", 1),
	}}
	err := rig.svc.DriveSession(stream)
	wantCode(t, err, codes.Unavailable)
	// Nothing was made observable (no InputActivity) and no ack was streamed.
	if n := len(rig.reader.inputActivities()); n != 0 {
		t.Fatalf("InputActivity events = %d, want 0 (fail-closed before any admit)", n)
	}
}

// TestDriveSession_RelayFaultEmitsNoActivity proves a relay transport fault (the input
// did NOT reach stdin) emits NO InputActivity and refuses the frame in-band, but the
// stream continues so a later frame can recover.
func TestDriveSession_RelayFaultEmitsNoActivity(t *testing.T) {
	sink := &fakeDriveSink{err: io.ErrClosedPipe} // every Drive faults
	rig := newDriveRig(t, sink)

	stream := &fakeDriveStream{ctx: context.Background(), in: []*attachv1.DriveSessionRequest{
		driveReq(rig.seatID, attachv1.DriveBlockKind_DRIVE_BLOCK_KIND_TEXT, "lost", 1),
	}}
	if err := rig.svc.DriveSession(stream); err != nil {
		t.Fatalf("DriveSession: %v", err)
	}
	if n := len(rig.reader.inputActivities()); n != 0 {
		t.Fatalf("InputActivity events = %d, want 0 — an input that did not reach stdin is not projected", n)
	}
	resps := stream.responses()
	if len(resps) != 1 || resps[0].GetAcceptedClientSeq() != 0 {
		t.Fatalf("relay-fault ack = %+v, want a refusal (accepted_client_seq 0)", resps)
	}
}
