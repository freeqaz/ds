package controlplane

// attachserving_test.go drives the N5 attach-serving legs (doc 15 §5.3/§5.4, D18/D61/D79)
// against the synthetic fixtures (D50: no live host-agent/VM):
//
//   - WatchSession (leg 1a): Subscribes to the session's attach.Fanout and serves fanned
//     SessionEvents on the stream, honors resume-from-seq, refuses an aged-out from_seq
//     OutOfRange, and refuses Unavailable when the attach legs are unwired.
//   - Attach (leg 1b): runs the D61 seat arbitration and returns the AttachHandle; a second
//     WRITER is refused FailedPrecondition; an unset role is InvalidArgument; a READER is
//     always admitted.
//   - the host-agent → orchestrator relay (leg 2): a heartbeat carrying an observed-session
//     §3 state EDGE is Published into the Fanout (so WatchSession serves it), a steady-state
//     re-report publishes nothing, and the relay still delegates to the wrapped observer.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// fakeWatchStream is an in-memory orchestrator.v1 WatchSession server stream: it collects
// every WatchSessionResponse the handler Sends and exposes a cancellable context so a test
// can drive the handler to return (the client disconnecting). It is the no-transport driver
// for the streaming handler (D50). It is mutex-guarded: the handler Sends from its own
// goroutine while the test reads the collected frames.
type fakeWatchStream struct {
	orchestratorv1.SessionService_WatchSessionServer
	ctx context.Context

	mu   sync.Mutex
	sent []*orchestratorv1.WatchSessionResponse
}

func (s *fakeWatchStream) Context() context.Context { return s.ctx }

func (s *fakeWatchStream) Send(resp *orchestratorv1.WatchSessionResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, resp)
	return nil
}

func (s *fakeWatchStream) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func (s *fakeWatchStream) frames() []*orchestratorv1.WatchSessionResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*orchestratorv1.WatchSessionResponse, len(s.sent))
	copy(out, s.sent)
	return out
}

func (s *fakeWatchStream) seqs() []uint64 {
	out := make([]uint64, 0)
	for _, r := range s.frames() {
		out = append(out, r.GetEvent().GetSeq())
	}
	return out
}

// stateEvent builds a SESSION_STATE event for the fan-out tests.
func stateEvent(name attachv1.SessionStateName) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Type:    attachv1.EventType_EVENT_TYPE_SESSION_STATE,
		Payload: &attachv1.SessionEvent_SessionState{SessionState: &attachv1.SessionState{Name: name}},
	}
}

// seedSession writes a minimal READY session record so the seat arbitration (which reads
// GetSession) and the WatchSession handler have a real session to attach to.
func seedSession(t *testing.T, f *fixture, sessionUUID string) {
	t.Helper()
	if _, err := f.st.CreateSession(context.Background(), store.Session{
		Ref:   store.SessionRef{SessionUUID: sessionUUID, HostID: testHostID, HostSessionIndex: 1, TapName: "dstap-1"},
		State: store.SessionReady,
	}); err != nil {
		t.Fatalf("seed session %q: %v", sessionUUID, err)
	}
}

// TestWatchSession_FansPublishedEvents proves leg 1a: a WatchSession subscriber receives
// every event Published into the session's Fanout, seq-stamped in order, and the handler
// returns cleanly when the client disconnects (ctx cancel).
func TestWatchSession_FansPublishedEvents(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-watch-1"

	ctx, cancel := context.WithCancel(context.Background())
	stream := &fakeWatchStream{ctx: ctx}

	done := make(chan error, 1)
	go func() {
		done <- f.cp.Sessions.WatchSession(&orchestratorv1.WatchSessionRequest{SessionUuid: sess}, stream)
	}()

	// Wait until the subscription is live (the Fanout has a subscriber), then publish.
	waitForSubscriber(t, f, sess, 1)
	f.cp.Fanout.Publish(context.Background(), sess, stateEvent(attachv1.SessionStateName_SESSION_STATE_NAME_READY))
	f.cp.Fanout.Publish(context.Background(), sess, stateEvent(attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED))

	// Give the synchronous Publish→Emit (which Sends on the stream) a moment to land, then
	// disconnect and join the handler.
	waitForSent(t, stream, 2)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("WatchSession returned error on clean disconnect: %v", err)
	}

	got := stream.seqs()
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("served seqs = %v, want [1 2] (monotonic, in order)", got)
	}
	if f.cp.Fanout.SubscriberCount(sess) != 0 {
		t.Errorf("subscriber not torn down on disconnect: count = %d, want 0", f.cp.Fanout.SubscriberCount(sess))
	}
}

// TestWatchSession_ResumeFromSeqReplays proves the resume-from-LastSeq path: a from_seq
// request replays the in-window tail of the per-session ring before the live stream.
func TestWatchSession_ResumeFromSeqReplays(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-watch-resume"

	// Publish three events into the ring with NO subscriber (they land in history).
	for i := 0; i < 3; i++ {
		f.cp.Fanout.Publish(context.Background(), sess, stateEvent(attachv1.SessionStateName_SESSION_STATE_NAME_READY))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &fakeWatchStream{ctx: ctx}

	done := make(chan error, 1)
	// from_seq = 2 resumes from the second event (seqs 2,3 replay).
	go func() {
		done <- f.cp.Sessions.WatchSession(&orchestratorv1.WatchSessionRequest{SessionUuid: sess, FromSeq: 2}, stream)
	}()

	waitForSent(t, stream, 2)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("WatchSession (resume) error: %v", err)
	}

	got := stream.seqs()
	if len(got) != 2 || got[0] != 2 || got[1] != 3 {
		t.Fatalf("resume replay seqs = %v, want [2 3]", got)
	}
}

// TestWatchSession_ResumeWindowExceeded proves an aged-out from_seq is a clean OutOfRange
// refusal (re-attach-from-frontier), not a silent gap.
func TestWatchSession_ResumeWindowExceeded(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-watch-aged"

	// A tiny history ring (size 1) so a small burst ages the oldest events out.
	f.cp.Sessions.fanout = attach.NewFanout(1)
	for i := 0; i < 5; i++ {
		f.cp.Sessions.fanout.Publish(context.Background(), sess, stateEvent(attachv1.SessionStateName_SESSION_STATE_NAME_READY))
	}

	stream := &fakeWatchStream{ctx: context.Background()}
	// from_seq = 1 aged out (the ring now holds only the most-recent few).
	err := f.cp.Sessions.WatchSession(&orchestratorv1.WatchSessionRequest{SessionUuid: sess, FromSeq: 1}, stream)
	if status.Code(err) != codes.OutOfRange {
		t.Fatalf("WatchSession aged-out from_seq: code = %v, want OutOfRange (err=%v)", status.Code(err), err)
	}
}

// TestWatchSession_UnwiredRefusesUnavailable proves a handler with the attach legs unwired
// refuses Unavailable rather than serving an empty stream.
func TestWatchSession_UnwiredRefusesUnavailable(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	f.cp.Sessions.fanout = nil // simulate a deployment not serving the attach legs

	err := f.cp.Sessions.WatchSession(&orchestratorv1.WatchSessionRequest{SessionUuid: "sess-x"}, &fakeWatchStream{ctx: context.Background()})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("WatchSession unwired: code = %v, want Unavailable (err=%v)", status.Code(err), err)
	}

	if err := f.cp.Sessions.WatchSession(&orchestratorv1.WatchSessionRequest{}, &fakeWatchStream{ctx: context.Background()}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("WatchSession empty session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestAttach_IssuesWriterHandleAndTakesSeat proves leg 1b: an Attach as WRITER runs the D61
// seat arbitration (the seat lands on the record) and returns a handle with the WRITER role
// + short-lived auth.
func TestAttach_IssuesWriterHandleAndTakesSeat(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-attach-w"
	seedSession(t, f, sess)

	resp, err := f.cp.Sessions.Attach(context.Background(), &orchestratorv1.AttachRequest{
		SessionUuid: sess,
		Role:        attachv1.Role_ROLE_WRITER,
	})
	if err != nil {
		t.Fatalf("Attach WRITER: %v", err)
	}
	h := resp.GetHandle()
	if h.GetRole() != attachv1.Role_ROLE_WRITER {
		t.Errorf("handle role = %v, want WRITER", h.GetRole())
	}
	if len(h.GetAuth().GetToken()) == 0 {
		t.Error("handle carries no auth token (D39 session-scoped credential)")
	}
	if h.GetSessionUuid() != sess {
		t.Errorf("handle session_uuid = %q, want %q", h.GetSessionUuid(), sess)
	}

	// The writer seat landed on the record (a record mutation with attribution, D61).
	rec, gerr := f.st.GetSession(context.Background(), sess)
	if gerr != nil {
		t.Fatalf("GetSession: %v", gerr)
	}
	if rec.WriterRole != store.RoleWriter || rec.WriterSeat != sess {
		t.Errorf("record writer seat = (%q,%q), want (%q,WRITER)", rec.WriterSeat, rec.WriterRole, sess)
	}
}

// TestAttach_ReaderAlwaysAdmitted proves a READER attach is admitted (the unbounded N) and
// does not take the writer seat.
func TestAttach_ReaderAlwaysAdmitted(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-attach-r"
	seedSession(t, f, sess)

	resp, err := f.cp.Sessions.Attach(context.Background(), &orchestratorv1.AttachRequest{
		SessionUuid: sess,
		Role:        attachv1.Role_ROLE_READER,
	})
	if err != nil {
		t.Fatalf("Attach READER: %v", err)
	}
	if resp.GetHandle().GetRole() != attachv1.Role_ROLE_READER {
		t.Errorf("handle role = %v, want READER", resp.GetHandle().GetRole())
	}
	rec, _ := f.st.GetSession(context.Background(), sess)
	if rec.WriterSeat != "" {
		t.Errorf("READER attach took the writer seat: %q, want empty", rec.WriterSeat)
	}
}

// TestAttach_SecondWriterRefused proves D61 one-writer: a second WRITER attach (a different
// seat, no handoff) is refused FailedPrecondition rather than displacing the holder.
func TestAttach_SecondWriterRefused(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-attach-2w"
	seedSession(t, f, sess)

	// Pre-seat a DIFFERENT writer on the record so the Attach (keyed on session_uuid) is a
	// second, conflicting writer.
	held := "other-writer"
	wr := store.RoleWriter
	if _, err := f.st.UpdateSession(context.Background(), sess, store.SessionUpdate{
		WriterSeat: &held, WriterRole: &wr, AttachState: &wr,
	}); err != nil {
		t.Fatalf("pre-seat writer: %v", err)
	}

	_, err := f.cp.Sessions.Attach(context.Background(), &orchestratorv1.AttachRequest{
		SessionUuid: sess,
		Role:        attachv1.Role_ROLE_WRITER,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("second WRITER: code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
}

// TestAttach_UnsetRoleAndUnwired proves the bad-request / unwired refusals.
func TestAttach_UnsetRoleAndUnwired(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-attach-bad"
	seedSession(t, f, sess)

	// An unset role (ROLE_UNSPECIFIED on the wire) is a bad request.
	_, err := f.cp.Sessions.Attach(context.Background(), &orchestratorv1.AttachRequest{SessionUuid: sess})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unset role: code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}

	// A missing session_uuid is a bad request.
	if _, err := f.cp.Sessions.Attach(context.Background(), &orchestratorv1.AttachRequest{Role: attachv1.Role_ROLE_READER}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing session_uuid: code = %v, want InvalidArgument", status.Code(err))
	}

	// An unwired issuer refuses Unavailable.
	f.cp.Sessions.issuer = nil
	if _, err := f.cp.Sessions.Attach(context.Background(), &orchestratorv1.AttachRequest{SessionUuid: sess, Role: attachv1.Role_ROLE_READER}); status.Code(err) != codes.Unavailable {
		t.Fatalf("unwired issuer: code = %v, want Unavailable", status.Code(err))
	}
}

// TestAttach_UnknownSessionNotFound proves an Attach against a session with no record
// surfaces NotFound (the seat store is the seat authority; no record, no seat).
func TestAttach_UnknownSessionNotFound(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	_, err := f.cp.Sessions.Attach(context.Background(), &orchestratorv1.AttachRequest{
		SessionUuid: "sess-does-not-exist",
		Role:        attachv1.Role_ROLE_READER,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown session: code = %v, want NotFound (err=%v)", status.Code(err), err)
	}
}

// --- the relay (leg 2): host-agent → orchestrator ---

// recordingFanout is a heartbeatFanout double that records every published event (the
// relay's publish target) without standing up a real Fanout.
type recordingFanout struct {
	published []*attachv1.SessionEvent
	sessions  []string
	nextSeq   uint64
}

func (f *recordingFanout) Publish(_ context.Context, sessionUUID string, ev *attachv1.SessionEvent) uint64 {
	f.nextSeq++
	ev.Seq = f.nextSeq
	ev.SessionId = sessionUUID
	f.published = append(f.published, ev)
	f.sessions = append(f.sessions, sessionUUID)
	return f.nextSeq
}

// observedSession builds a hypervisor.v1.ObservedSession carrying a §3 state.
func observedSession(sessionUUID string, name attachv1.SessionStateName) *hypervisorv1.ObservedSession {
	return &hypervisorv1.ObservedSession{
		SessionUuid:   sessionUUID,
		DomainUuid:    "dom-" + sessionUUID,
		ObservedState: &attachv1.SessionState{Name: name},
	}
}

// TestRelay_PublishesStateEdgesAndDedups proves leg 2: a heartbeat carrying an observed
// session's §3 state is Published into the Fanout as a SESSION_STATE event; a steady-state
// re-report of the SAME state publishes nothing; a transition publishes again. The relay
// also delegates every frame to the wrapped observer (the reconcile submit).
func TestRelay_PublishesStateEdgesAndDedups(t *testing.T) {
	rf := &recordingFanout{}
	next := &recordingObserver{}
	relay := newAttachRelay(rf, next)
	const sess = "sess-relay-1"

	// First observation: a READY edge — published.
	_ = relay.Observe(context.Background(), heartbeatWithObserved(testHostID, 0,
		observedSession(sess, attachv1.SessionStateName_SESSION_STATE_NAME_READY)))
	// Steady-state re-report of READY: NO edge — not published.
	_ = relay.Observe(context.Background(), heartbeatWithObserved(testHostID, 0,
		observedSession(sess, attachv1.SessionStateName_SESSION_STATE_NAME_READY)))
	// Transition to ATTACHED: an edge — published.
	_ = relay.Observe(context.Background(), heartbeatWithObserved(testHostID, 0,
		observedSession(sess, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED)))

	if len(rf.published) != 2 {
		t.Fatalf("published %d events, want 2 (one per state EDGE; steady-state re-report deduped)", len(rf.published))
	}
	if got := rf.published[0].GetSessionState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_READY {
		t.Errorf("first edge state = %v, want READY", got)
	}
	if got := rf.published[1].GetSessionState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Errorf("second edge state = %v, want ATTACHED", got)
	}
	if rf.published[0].GetType() != attachv1.EventType_EVENT_TYPE_SESSION_STATE {
		t.Errorf("event type = %v, want SESSION_STATE", rf.published[0].GetType())
	}
	if rf.sessions[0] != sess {
		t.Errorf("published session = %q, want %q", rf.sessions[0], sess)
	}
	// Every frame still reached the wrapped observer (the reconcile path is unchanged).
	if next.count() != 3 {
		t.Errorf("wrapped observer saw %d frames, want 3 (every frame delegated)", next.count())
	}
}

// TestRelay_NilFanoutIsPassThrough proves a relay with no Fanout just delegates (a clean
// degrade for a deployment not serving the attach legs).
func TestRelay_NilFanoutIsPassThrough(t *testing.T) {
	next := &recordingObserver{}
	relay := newAttachRelay(nil, next)
	if err := relay.Observe(context.Background(), heartbeatWithObserved(testHostID, 0,
		observedSession("sess-x", attachv1.SessionStateName_SESSION_STATE_NAME_READY))); err != nil {
		t.Fatalf("Observe (nil fanout): %v", err)
	}
	if next.count() != 1 {
		t.Errorf("wrapped observer saw %d frames, want 1", next.count())
	}
}

// TestRelay_EndToEndThroughFanout proves the relay feeds the REAL attach.Fanout: an
// observed-session state edge relayed in reaches a live WatchSession subscriber.
func TestRelay_EndToEndThroughFanout(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-relay-e2e"
	relay := newAttachRelay(f.cp.Fanout, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &fakeWatchStream{ctx: ctx}
	done := make(chan error, 1)
	go func() {
		done <- f.cp.Sessions.WatchSession(&orchestratorv1.WatchSessionRequest{SessionUuid: sess}, stream)
	}()
	waitForSubscriber(t, f, sess, 1)

	// Relay a heartbeat carrying the session in WORKING — the subscriber should receive it.
	_ = relay.Observe(context.Background(), heartbeatWithObserved(testHostID, 0,
		observedSession(sess, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)))

	waitForSent(t, stream, 1)
	cancel()
	<-done

	frames := stream.frames()
	if len(frames) != 1 {
		t.Fatalf("subscriber received %d events, want 1", len(frames))
	}
	if got := frames[0].GetEvent().GetSessionState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_WORKING {
		t.Errorf("relayed event state = %v, want WORKING", got)
	}
	if frames[0].GetEvent().GetSessionId() != sess {
		t.Errorf("relayed event session_id = %q, want %q (the Fanout stamps it)", frames[0].GetEvent().GetSessionId(), sess)
	}
}

// --- small test helpers ---

// waitForSubscriber blocks (bounded) until the Fanout reports `want` subscribers for the
// session, so a test publishes only after the WatchSession handler has registered.
func waitForSubscriber(t *testing.T, f *fixture, sessionUUID string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.cp.Fanout.SubscriberCount(sessionUUID) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d subscriber(s) on %q (have %d)", want, sessionUUID, f.cp.Fanout.SubscriberCount(sessionUUID))
}

// waitForSent blocks (bounded) until the stream has collected `want` frames.
func waitForSent(t *testing.T, s *fakeWatchStream, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.count() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d sent frame(s) (have %d)", want, s.count())
}

// --- single-writer (concurrent-Send) regression coverage ---

// unguardedWatchStream is a WatchSession server stream whose Send is DELIBERATELY NOT
// mutex-guarded — unlike fakeWatchStream, whose mutex would mask a concurrent-Send bug. It
// proves the single-writer rule the gRPC ServerStream requires (stream.Send is unsafe for
// concurrent use): the handler must serialize every Send to one stream. Two independent
// guards make a violation a hard FAILURE rather than a silent flake:
//
//   - inFlight is an unsynchronized counter incremented on entry / decremented on exit, with
//     a brief sleep between to WIDEN the concurrency window. If two goroutines are ever inside
//     Send at once it is recorded (raced=1) AND, because inFlight is touched without a lock,
//     the -race detector fires on the data race directly.
//   - seqs records the on-wire order; the test asserts it is ascending (the replay tail's
//     low Seqs before the live events' higher Seqs — the Fanout is the Seq authority).
type unguardedWatchStream struct {
	orchestratorv1.SessionService_WatchSessionServer
	ctx context.Context

	// inFlight / raced are touched WITHOUT synchronization on purpose: a real concurrent Send
	// trips the -race detector here and sets raced via the (racy) read-modify-write.
	inFlight int
	raced    int32

	// recordMu guards ONLY the test's own bookkeeping slice (seqs) — NOT Send's body. It is
	// the test reading results safely; it does not serialize the handler's Sends (that is the
	// single-writer rule under test, which the handler must enforce itself).
	recordMu sync.Mutex
	seqs     []uint64
}

func (s *unguardedWatchStream) Context() context.Context { return s.ctx }

func (s *unguardedWatchStream) Send(resp *orchestratorv1.WatchSessionResponse) error {
	// UNGUARDED critical section: if the handler lets two goroutines in here at once, the
	// inFlight read-modify-write races (the -race detector fires) and the >1 observation is
	// recorded. The sleep widens the window so a missing lock is caught deterministically.
	s.inFlight++
	if s.inFlight > 1 {
		atomic.StoreInt32(&s.raced, 1)
	}
	time.Sleep(50 * time.Microsecond)
	s.inFlight--

	s.recordMu.Lock()
	s.seqs = append(s.seqs, resp.GetEvent().GetSeq())
	s.recordMu.Unlock()
	return nil
}

func (s *unguardedWatchStream) sawConcurrentSend() bool { return atomic.LoadInt32(&s.raced) == 1 }

func (s *unguardedWatchStream) sentSeqs() []uint64 {
	s.recordMu.Lock()
	defer s.recordMu.Unlock()
	out := make([]uint64, len(s.seqs))
	copy(out, s.seqs)
	return out
}

// TestWatchSession_SingleWriterUnderConcurrentPublish proves WatchSession honors the gRPC
// single-writer rule: it serializes the resume-replay tail (sent by the handler goroutine
// inside Fanout.Subscribe) with the LIVE events a concurrent Publisher fans the instant the
// subscriber registers — two goroutines Sending on one ServerStream is what gRPC documents
// as unsafe. With the fix the unguarded detector NEVER sees a concurrent Send and the wire
// stays ascending-Seq (replay tail first, live after). Without the fix the unguarded Send's
// inFlight read-modify-write races (the -race detector fires) and/or a high-Seq live event
// interleaves into the low-Seq replay tail.
func TestWatchSession_SingleWriterUnderConcurrentPublish(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-single-writer"

	// Pre-load the resume ring with a replay tail (seqs 1..replayN), published with NO
	// subscriber so they land only in history — the handler will replay them on Subscribe.
	const replayN = 64
	for i := 0; i < replayN; i++ {
		f.cp.Fanout.Publish(context.Background(), sess, stateEvent(attachv1.SessionStateName_SESSION_STATE_NAME_READY))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &unguardedWatchStream{ctx: ctx}

	// A publisher goroutine hammers Publish to drive LIVE events onto the SAME stream while
	// the handler is still flushing the replay tail — exactly the concurrent-Send window. It
	// stops once the handler's context is cancelled.
	const liveN = 64
	pubDone := make(chan struct{})
	go func() {
		defer close(pubDone)
		for i := 0; i < liveN; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			f.cp.Fanout.Publish(context.Background(), sess, stateEvent(attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED))
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- f.cp.Sessions.WatchSession(&orchestratorv1.WatchSessionRequest{SessionUuid: sess, FromSeq: 1}, stream)
	}()

	// Wait until the handler has Sent at least the whole replay tail plus some live events,
	// then disconnect and join.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if len(stream.sentSeqs()) >= replayN+1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	<-pubDone
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("WatchSession returned error on clean disconnect: %v", err)
	}

	if stream.sawConcurrentSend() {
		t.Fatal("two goroutines Sent on one WatchSession ServerStream concurrently (single-writer rule violated)")
	}

	// The wire must be strictly ascending Seq: the replay tail (low seqs) fully before the
	// live events (higher seqs), no interleave. Duplicates are tolerated (a live event present
	// in the ring snapshot can also replay) but order must never regress.
	got := stream.sentSeqs()
	if len(got) < replayN {
		t.Fatalf("served %d frames, want at least the %d-event replay tail", len(got), replayN)
	}
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Fatalf("served seqs not ascending at %d: %v (a live event interleaved ahead of the replay tail)", i, got)
		}
	}
}
