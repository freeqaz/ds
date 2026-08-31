package controlplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// --- test doubles ------------------------------------------------------------

// fakeContentSource is a ContentSource whose OpenContent hands back a channel the test
// pushes events onto. It records every session it was opened for and, optionally, fails
// the first N opens (a dial-fault → retry test). Concurrency-safe (the pump reads the
// channel on its own goroutine while the test writes/inspects).
type fakeContentSource struct {
	mu        sync.Mutex
	opened    []string
	chans     map[string]chan *attachv1.SessionEvent
	failFirst int   // fail the first N OpenContent calls with a dial fault
	failErr   error // the error returned while failFirst > 0
	openedCh  chan struct{}
}

func newFakeContentSource() *fakeContentSource {
	return &fakeContentSource{
		chans:    make(map[string]chan *attachv1.SessionEvent),
		openedCh: make(chan struct{}, 64),
	}
}

func (s *fakeContentSource) OpenContent(_ context.Context, sessionUUID string) (<-chan *attachv1.SessionEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failFirst > 0 {
		s.failFirst--
		err := s.failErr
		if err == nil {
			err = context.DeadlineExceeded
		}
		return nil, err
	}
	ch := make(chan *attachv1.SessionEvent, 64)
	s.chans[sessionUUID] = ch
	s.opened = append(s.opened, sessionUUID)
	select {
	case s.openedCh <- struct{}{}:
	default:
	}
	return ch, nil
}

// push sends an event onto the currently-open channel for sessionUUID (must be open).
func (s *fakeContentSource) push(sessionUUID string, ev *attachv1.SessionEvent) {
	s.mu.Lock()
	ch := s.chans[sessionUUID]
	s.mu.Unlock()
	ch <- ev
}

// closeStream closes the open channel for sessionUUID (simulate a host-side stream end).
func (s *fakeContentSource) closeStream(sessionUUID string) {
	s.mu.Lock()
	ch := s.chans[sessionUUID]
	delete(s.chans, sessionUUID)
	s.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (s *fakeContentSource) openCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.opened)
}

// waitOpened blocks until the source has been opened at least once (or the deadline).
func (s *fakeContentSource) waitOpened(t *testing.T) {
	t.Helper()
	select {
	case <-s.openedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("content source was never opened")
	}
}

// safeFanout is a concurrency-safe recording contentFanout (the pump Publishes from a
// goroutine while the test inspects). It also fronts the REAL seq-stamp semantics.
type safeFanout struct {
	mu        sync.Mutex
	published []*attachv1.SessionEvent
	sessions  []string
	nextSeq   uint64
	gotCh     chan struct{}
}

func newSafeFanout() *safeFanout {
	return &safeFanout{gotCh: make(chan struct{}, 256)}
}

func (f *safeFanout) Publish(_ context.Context, sessionUUID string, ev *attachv1.SessionEvent) uint64 {
	f.mu.Lock()
	f.nextSeq++
	seq := f.nextSeq
	ev.Seq = seq
	ev.SessionId = sessionUUID
	f.published = append(f.published, ev)
	f.sessions = append(f.sessions, sessionUUID)
	f.mu.Unlock()
	select {
	case f.gotCh <- struct{}{}:
	default:
	}
	return seq
}

func (f *safeFanout) snapshot() ([]*attachv1.SessionEvent, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	evs := make([]*attachv1.SessionEvent, len(f.published))
	copy(evs, f.published)
	ss := make([]string, len(f.sessions))
	copy(ss, f.sessions)
	return evs, ss
}

// waitPublished blocks until at least n events have been published (or the deadline).
func (f *safeFanout) waitPublished(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		f.mu.Lock()
		got := len(f.published)
		f.mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-f.gotCh:
		case <-deadline:
			t.Fatalf("waited for %d published events, got %d", n, got)
		}
	}
}

// chatEvent builds a CC CONTENT chat event.
func chatEvent(text string) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Type: attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE,
		Payload: &attachv1.SessionEvent_ChatMessage{
			ChatMessage: &attachv1.ChatMessage{
				Role:   "assistant",
				Blocks: []*attachv1.ChatBlock{{Kind: "text", Text: text}},
			},
		},
	}
}

// toolInvokedEvent builds a CC CONTENT tool-use event.
func toolInvokedEvent(name string) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Type: attachv1.EventType_EVENT_TYPE_TOOL_INVOKED,
		Payload: &attachv1.SessionEvent_ToolInvoked{
			ToolInvoked: &attachv1.ToolInvoked{NodeId: "n1", Name: name, Kind: "native"},
		},
	}
}

// --- tests -------------------------------------------------------------------

// TestContentRelay_PublishesContentIntoFanout is the acceptance test: the content relay
// pumps CC content from a fake source into the Fanout so a subscriber sees CC content
// frames (chat + tool-use), not just state/seat edges. It exercises the pump end-to-end
// (ensure → OpenContent → Publish) with the seq stamped by the Fanout.
func TestContentRelay_PublishesContentIntoFanout(t *testing.T) {
	src := newFakeContentSource()
	fan := newSafeFanout()
	cr := newContentRelay(src, fan, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr.Start(ctx)

	const sess = "sess-content-1"
	cr.ensure(sess)
	src.waitOpened(t)

	src.push(sess, chatEvent("hello from CC"))
	src.push(sess, toolInvokedEvent("Bash"))
	fan.waitPublished(t, 2)

	evs, sessions := fan.snapshot()
	if len(evs) != 2 {
		t.Fatalf("published %d content events, want 2", len(evs))
	}
	if evs[0].GetType() != attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE {
		t.Errorf("event[0] type = %v, want CHAT_MESSAGE", evs[0].GetType())
	}
	if got := evs[0].GetChatMessage().GetBlocks()[0].GetText(); got != "hello from CC" {
		t.Errorf("chat text = %q, want %q", got, "hello from CC")
	}
	if evs[1].GetType() != attachv1.EventType_EVENT_TYPE_TOOL_INVOKED {
		t.Errorf("event[1] type = %v, want TOOL_INVOKED", evs[1].GetType())
	}
	// The Fanout is the seq authority — each content event carries an ascending stamped seq
	// and the correct session id.
	if evs[0].GetSeq() != 1 || evs[1].GetSeq() != 2 {
		t.Errorf("stamped seqs = %d,%d, want 1,2", evs[0].GetSeq(), evs[1].GetSeq())
	}
	if sessions[0] != sess || sessions[1] != sess {
		t.Errorf("published sessions = %v, want both %q", sessions, sess)
	}
}

// TestContentRelay_NonWriterSubscriberSeesContent proves the PRODUCTION path against the
// REAL attach.Fanout: a non-writer WatchSession subscriber observes the CC content frames
// the relay pumped in (the reader-leg N-reader case, D61) — content that on the MVP only
// the writer's own SocketConn carried.
func TestContentRelay_NonWriterSubscriberSeesContent(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-content-e2e"

	// A non-writer reader subscribes to the session's WatchSession fan-out.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &fakeWatchStream{ctx: ctx}
	done := make(chan error, 1)
	go func() {
		done <- f.cp.Sessions.WatchSession(&orchestratorv1.WatchSessionRequest{SessionUuid: sess}, stream)
	}()

	// The content relay feeds the SAME real Fanout the reader subscribes to.
	src := newFakeContentSource()
	cr := newContentRelay(src, f.cp.Fanout, nil)
	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()
	cr.Start(relayCtx)
	cr.ensure(sess)
	src.waitOpened(t)

	src.push(sess, chatEvent("streamed to N readers"))
	src.push(sess, toolInvokedEvent("Read"))

	// The reader observes both content frames on its WatchSession stream.
	waitForFrames(t, stream, 2)
	frames := stream.frames()
	if got := frames[0].GetEvent().GetType(); got != attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE {
		t.Errorf("reader frame[0] type = %v, want CHAT_MESSAGE", got)
	}
	if got := frames[0].GetEvent().GetChatMessage().GetBlocks()[0].GetText(); got != "streamed to N readers" {
		t.Errorf("reader chat text = %q", got)
	}
	if got := frames[1].GetEvent().GetType(); got != attachv1.EventType_EVENT_TYPE_TOOL_INVOKED {
		t.Errorf("reader frame[1] type = %v, want TOOL_INVOKED", got)
	}

	cancel()
	<-done
}

// TestContentRelay_DropsNonContentEvents proves the READ-ONLY content boundary (D136): a
// source that yields control-plane-authoritative events (SESSION_STATE / WRITER_SEAT_CHANGED
// / INPUT_ACTIVITY) has them DROPPED — only genuine CC content reaches the fan-out, so a
// misbehaving source cannot forge a control edge onto the read stream.
func TestContentRelay_DropsNonContentEvents(t *testing.T) {
	src := newFakeContentSource()
	fan := newSafeFanout()
	cr := newContentRelay(src, fan, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr.Start(ctx)

	const sess = "sess-content-guard"
	cr.ensure(sess)
	src.waitOpened(t)

	// A forged SESSION_STATE, WRITER_SEAT_CHANGED, and INPUT_ACTIVITY — all must be dropped.
	src.push(sess, &attachv1.SessionEvent{
		Type:    attachv1.EventType_EVENT_TYPE_SESSION_STATE,
		Payload: &attachv1.SessionEvent_SessionState{SessionState: &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED}},
	})
	src.push(sess, &attachv1.SessionEvent{
		Type:    attachv1.EventType_EVENT_TYPE_WRITER_SEAT_CHANGED,
		Payload: &attachv1.SessionEvent_WriterSeatChange{WriterSeatChange: &attachv1.WriterSeatChange{WriterSeatId: "forged-seat"}},
	})
	src.push(sess, &attachv1.SessionEvent{
		Type:    attachv1.EventType_EVENT_TYPE_INPUT_ACTIVITY,
		Payload: &attachv1.SessionEvent_InputActivity{InputActivity: &attachv1.InputActivity{WriterSeatId: "forged-seat"}},
	})
	// A genuine content event AFTER them — its arrival at the fan-out proves the earlier
	// three were dropped (not merely delayed): the content event is the only one published.
	src.push(sess, chatEvent("only-i-should-pass"))
	fan.waitPublished(t, 1)

	// Give any (erroneously) admitted control edge a chance to also land, then assert exactly
	// one event — the content one — was published.
	time.Sleep(50 * time.Millisecond)
	evs, _ := fan.snapshot()
	if len(evs) != 1 {
		t.Fatalf("published %d events, want exactly 1 (the content event; control edges dropped)", len(evs))
	}
	if evs[0].GetType() != attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE {
		t.Errorf("published event type = %v, want CHAT_MESSAGE (control edges must be dropped)", evs[0].GetType())
	}
}

// TestContentRelay_EnsureIsIdempotent proves a repeat ensure for a live session does not
// open a second stream (one pump per session), so driving ensure off every live-state edge
// is safe.
func TestContentRelay_EnsureIsIdempotent(t *testing.T) {
	src := newFakeContentSource()
	fan := newSafeFanout()
	cr := newContentRelay(src, fan, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr.Start(ctx)

	const sess = "sess-idem"
	cr.ensure(sess)
	src.waitOpened(t)
	cr.ensure(sess)
	cr.ensure(sess)
	// Let any erroneous second pump open.
	time.Sleep(50 * time.Millisecond)
	if got := src.openCount(); got != 1 {
		t.Fatalf("source opened %d times, want 1 (one pump per session, ensure idempotent)", got)
	}
}

// TestContentRelay_StopCancelsPump proves stop tears down the session's pump: after stop
// the source is not re-opened and no further content is published.
func TestContentRelay_StopCancelsPump(t *testing.T) {
	src := newFakeContentSource()
	fan := newSafeFanout()
	cr := newContentRelay(src, fan, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr.Start(ctx)

	const sess = "sess-stop"
	cr.ensure(sess)
	src.waitOpened(t)
	src.push(sess, chatEvent("before-stop"))
	fan.waitPublished(t, 1)

	cr.stop(sess)
	// The pump entry is gone after stop.
	waitPumpGone(t, cr, sess)

	// A fresh ensure after stop starts a NEW pump (a second open) — proving stop fully
	// released the prior one.
	cr.ensure(sess)
	// waitOpened consumes one signal; the first open already drained it, so poll openCount.
	waitOpenCount(t, src, 2)
}

// TestContentRelay_ReopensAfterTransientClose proves a host-side stream close while the
// pump context is still live triggers a re-open (a transient bridge drop recovers without
// losing the session's content leg).
func TestContentRelay_ReopensAfterTransientClose(t *testing.T) {
	src := newFakeContentSource()
	fan := newSafeFanout()
	cr := newContentRelay(src, fan, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr.Start(ctx)

	const sess = "sess-reopen"
	cr.ensure(sess)
	src.waitOpened(t)
	src.push(sess, chatEvent("first-stream"))
	fan.waitPublished(t, 1)

	// The host-side stream closes (a transient drop). The pump re-opens (backoff is short).
	src.closeStream(sess)
	waitOpenCount(t, src, 2)

	// The re-opened stream carries content again.
	src.push(sess, chatEvent("second-stream"))
	fan.waitPublished(t, 2)
}

// TestContentRelay_RetriesOnDialFault proves a dial fault (OpenContent error) is retried
// with backoff until it succeeds — a not-yet-ready bridge does not kill the pump.
func TestContentRelay_RetriesOnDialFault(t *testing.T) {
	src := newFakeContentSource()
	src.failFirst = 2 // the first two opens fault; the third succeeds.
	fan := newSafeFanout()
	cr := newContentRelay(src, fan, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr.Start(ctx)

	const sess = "sess-dialfault"
	cr.ensure(sess)
	src.waitOpened(t) // eventually opens on the third try.
	src.push(sess, chatEvent("after-retry"))
	fan.waitPublished(t, 1)
}

// TestContentRelay_EnsureBeforeStartIsNoOp proves ensure before Start does not open a
// stream (no pump can outlive a context that does not yet exist) — a clean no-op.
func TestContentRelay_EnsureBeforeStartIsNoOp(t *testing.T) {
	src := newFakeContentSource()
	fan := newSafeFanout()
	cr := newContentRelay(src, fan, nil)

	cr.ensure("sess-early") // Start not called yet.
	time.Sleep(50 * time.Millisecond)
	if got := src.openCount(); got != 0 {
		t.Fatalf("source opened %d times before Start, want 0", got)
	}
}

// TestContentRelay_StartContextCancelStopsAllPumps proves cancelling the Start (serve)
// context tears down every per-session pump (the shutdown path).
func TestContentRelay_StartContextCancelStopsAllPumps(t *testing.T) {
	src := newFakeContentSource()
	fan := newSafeFanout()
	cr := newContentRelay(src, fan, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cr.Start(ctx)

	cr.ensure("sess-a")
	src.waitOpened(t)
	cr.ensure("sess-b")
	waitOpenCount(t, src, 2)

	cancel() // shutdown: every pump's derived context is cancelled.
	waitPumpGone(t, cr, "sess-a")
	waitPumpGone(t, cr, "sess-b")
}

// TestContentRelay_LifecycleDrivenByStateEdges proves the state-edge relay (attachrelay.go)
// drives the content pump lifecycle: an observed live §3 edge ENSURES the pump, a DESTROYED
// edge STOPS it — off the SAME heartbeat observed-session set, with the state-edge path
// otherwise unchanged.
func TestContentRelay_LifecycleDrivenByStateEdges(t *testing.T) {
	src := newFakeContentSource()
	fan := newSafeFanout()
	cr := newContentRelay(src, fan, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr.Start(ctx)

	// The state-edge relay wraps the content lifecycle (as serve.go wires it), publishing
	// state edges into a recording fanout and driving ensure/stop off them.
	rf := &recordingFanout{}
	next := &recordingObserver{}
	relay := newAttachRelay(rf, next).withContent(cr)

	const sess = "sess-lifecycle"
	// A live ATTACHED edge → the content pump is ensured.
	_ = relay.Observe(context.Background(), heartbeatWithObserved(testHostID, 0,
		observedSession(sess, attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED)))
	src.waitOpened(t)
	src.push(sess, chatEvent("live-content"))
	fan.waitPublished(t, 1)

	// A DESTROYED edge → the content pump is stopped.
	_ = relay.Observe(context.Background(), heartbeatWithObserved(testHostID, 0,
		observedSession(sess, attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED)))
	waitPumpGone(t, cr, sess)

	// The state-edge path itself is unchanged: both edges were published, both delegated.
	if len(rf.published) != 2 {
		t.Errorf("state relay published %d edges, want 2 (ATTACHED, DESTROYED)", len(rf.published))
	}
	if next.count() != 2 {
		t.Errorf("wrapped observer saw %d frames, want 2", next.count())
	}
}

// TestContentRelay_NilLifecycleLeavesStateRelayUnchanged proves a state-edge relay with no
// content lifecycle wired behaves exactly as before (the disabled-content-leg degrade).
func TestContentRelay_NilLifecycleLeavesStateRelayUnchanged(t *testing.T) {
	rf := &recordingFanout{}
	next := &recordingObserver{}
	relay := newAttachRelay(rf, next).withContent(nil) // nil lifecycle — no-op.
	if relay.content != nil {
		t.Fatal("withContent(nil) must not install a lifecycle")
	}
	_ = relay.Observe(context.Background(), heartbeatWithObserved(testHostID, 0,
		observedSession("sess-x", attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED)))
	if len(rf.published) != 1 || next.count() != 1 {
		t.Errorf("state relay published=%d delegated=%d, want 1,1", len(rf.published), next.count())
	}
}

// spectateGoldenFixturePath is the checked-in length-delimited attach.v1
// SessionEvent frame dump the OSS client's `serpent spectate` replay test
// renders. The REAL WatchSession handler in THIS package produces it; the fixture
// FILE is the sole artifact crossing the D80 module boundary (the client tree may
// not import this one, so the file — not a shared symbol — is the contract).
const spectateGoldenFixturePath = "../../../client/cmd/serpent/testdata/spectate_golden.frames"

// goldenToolCompleted builds a CC CONTENT tool-completion event (the one class the
// package's other helpers do not already cover).
func goldenToolCompleted(isErr bool, excerpt string) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Type: attachv1.EventType_EVENT_TYPE_TOOL_COMPLETED,
		Payload: &attachv1.SessionEvent_ToolCompleted{ToolCompleted: &attachv1.ToolCompleted{
			IsError:       isErr,
			OutputExcerpt: excerpt,
		}},
	}
}

// TestContentRelay_WritesGoldenSpectateFixture pumps a deterministic CC CHAT/TOOL
// content turn through the REAL Fanout + WatchSession handler, captures the frames
// a reader-leg (non-writer) subscriber actually receives, and pins them as the
// checked-in length-delimited fixture spectateGoldenFixturePath.
//
// This closes the "backed by the real orchestrator handler" acceptance for
// `serpent spectate` WITHOUT breaking the D80 import fence: the stdlib-only client
// module cannot import this tree, so the fixture FILE is the one artifact that
// crosses the seam. The client replays it through the spectate renderer
// (client/cmd/serpent/spectate_test.go) — same frozen frames, same codec, zero
// cross-import.
//
// The golden is regenerated on demand (DS_REGEN_SPECTATE_FIXTURE=1) and otherwise
// ASSERTED byte-for-byte against the on-disk file, so any drift in the real
// handler's wire output REDs here.
func TestContentRelay_WritesGoldenSpectateFixture(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	const sess = "sess-golden"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &fakeWatchStream{ctx: ctx}
	done := make(chan error, 1)
	go func() {
		done <- f.cp.Sessions.WatchSession(&orchestratorv1.WatchSessionRequest{SessionUuid: sess}, stream)
	}()

	// The content relay feeds the SAME real Fanout the reader subscribes to.
	src := newFakeContentSource()
	cr := newContentRelay(src, f.cp.Fanout, nil)
	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()
	cr.Start(relayCtx)
	cr.ensure(sess)
	src.waitOpened(t)

	// A small, deterministic CC turn: assistant chat, a tool invoked + completed,
	// a closing chat — the CHAT/TOOL content vocabulary a spectator watches.
	src.push(sess, chatEvent("Reading the failing test now."))
	src.push(sess, toolInvokedEvent("Bash"))
	src.push(sess, goldenToolCompleted(false, "PASS\nok  ./...  all tests pass"))
	src.push(sess, chatEvent("All green — the fix holds."))
	waitForFrames(t, stream, 4)

	frames := stream.frames()
	cancel()
	<-done

	// Encode the frames the REAL handler served as the length-delimited stream the
	// client codec reads: [uvarint length][marshaled SessionEvent] per frame.
	var wire bytes.Buffer
	for _, fr := range frames {
		ev := fr.GetEvent()
		body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(ev)
		if err != nil {
			t.Fatalf("marshal event seq=%d: %v", ev.GetSeq(), err)
		}
		var hdr [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(hdr[:], uint64(len(body)))
		wire.Write(hdr[:n])
		wire.Write(body)
	}

	path := filepath.FromSlash(spectateGoldenFixturePath)
	if os.Getenv("DS_REGEN_SPECTATE_FIXTURE") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, wire.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated golden fixture %s (%d bytes, %d frames)", path, wire.Len(), len(frames))
		return
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden fixture %s: %v (regenerate with DS_REGEN_SPECTATE_FIXTURE=1)", path, err)
	}
	if !bytes.Equal(onDisk, wire.Bytes()) {
		t.Errorf("golden fixture %s is stale vs the real WatchSession handler output (%d on-disk vs %d fresh bytes) — regenerate with DS_REGEN_SPECTATE_FIXTURE=1", path, len(onDisk), wire.Len())
	}
}

// --- helpers -----------------------------------------------------------------

func waitForFrames(t *testing.T, s *fakeWatchStream, n int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if s.count() >= n {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("waited for %d reader frames, got %d", n, s.count())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func waitOpenCount(t *testing.T, src *fakeContentSource, n int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if src.openCount() >= n {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("waited for source open count %d, got %d", n, src.openCount())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func waitPumpGone(t *testing.T, cr *contentRelay, sessionUUID string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		cr.mu.Lock()
		_, present := cr.pumps[sessionUUID]
		cr.mu.Unlock()
		if !present {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("pump for %q still present, want gone", sessionUUID)
		case <-time.After(5 * time.Millisecond):
		}
	}
}
