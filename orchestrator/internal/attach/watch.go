package attach

// watch.go is the WatchSession streaming fan-out (doc 15 §5.3, D18): the
// orchestrator-side terminator the one WRITER and the N READERs subscribe to.
// Every emitted attach.v1.SessionEvent carries a MONOTONIC per-session sequence
// number stamped HERE, from M0 (D79 — reserved so replay/spectate land without a
// v2); a `from_seq` request replays from a bounded per-session history ring (the
// slow-N-reader recovery, D61: a reader recovers what it dropped without
// re-attaching, never stalling the shared pump). This mirrors the host-side
// hostbridge fan-out (client/hostbridge): same seq-stamped, ring-backed,
// resume-from-seq shape, on the control-plane side of the D38 socket.

import (
	"context"
	"fmt"
	"sort"
	"sync"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// defaultHistorySize bounds the per-session resume ring. A slow N-reader (D61)
// recovers events it dropped by replaying from this ring; a reader that has
// fallen further behind than the ring depth gets ErrResumeWindowExceeded and
// must re-attach from the current frontier. The window is deliberately a few
// thousand events — large enough that a momentary reader stall recovers without
// re-attach, bounded so a stuck reader cannot drive an unbounded allocation (the
// same posture as the hostbridge ring, client/hostbridge/bridge.go).
const defaultHistorySize = 4096

// ErrResumeWindowExceeded is returned by WatchSession when a `from_seq` falls
// before the oldest event the per-session history ring still holds: the span
// aged out. The client lifts this into a re-attach-from-frontier (the same
// semantics as the hostbridge ErrResumeWindowExceeded, mirrored on the
// control-plane side). It is a CLEAN refusal, never a dropped fan-out.
var ErrResumeWindowExceeded = fmt.Errorf("attach: resume window exceeded (from_seq aged out of the per-session history ring)")

// Emitter is the per-frame sink WatchSession drives: one call per fanned event,
// in ascending seq order. The gRPC adapter satisfies it by sending each event on
// the SessionService.WatchSession server stream (wrapping it in
// orchestrator.v1.WatchSessionResponse); a test satisfies it by collecting
// frames. Returning an error stops the fan-out for that subscriber (its stream
// closed / it aborted) WITHOUT disturbing the other readers — independent
// reader-drop is the D61 invariant this terminator serves.
type Emitter interface {
	Emit(ctx context.Context, ev *attachv1.SessionEvent) error
}

// EmitterFunc adapts a function to an Emitter.
type EmitterFunc func(ctx context.Context, ev *attachv1.SessionEvent) error

// Emit calls the function.
func (f EmitterFunc) Emit(ctx context.Context, ev *attachv1.SessionEvent) error { return f(ctx, ev) }

// sessionStream is the per-session fan-out state: the subscriber set, the
// monotonic seq counter, and the bounded history ring resume reads from. One
// per live session; created lazily on the first Publish/Subscribe and dropped
// when the session is closed (Close).
type sessionStream struct {
	mu sync.Mutex

	// subscribers is the WatchSession fan-out set (the one WRITER + the N
	// READERs). Each is a live Emitter; an Emit error unsubscribes only that one
	// (independent reader-drop, D61), never the set.
	subscribers map[int]Emitter
	nextSubID   int

	// nextSeq is the monotonic per-session sequence the next published event is
	// stamped with (D79: EVERY event carries seq, from M0). Starts at 1 so a
	// from_seq of 0 means "from before the first event" (the late-joiner backfill
	// of whatever the ring holds), distinct from any real event's seq.
	nextSeq uint64

	// ring is the bounded resume history (oldest-first, ascending seq). A slow
	// reader recovers dropped events by replaying from it; capped at historySize.
	ring        []*attachv1.SessionEvent
	historySize int
}

// Fanout is the WatchSession terminator across all sessions (doc 15 §5.3). It
// owns the per-session streams, stamps the per-event seqs, fans events to the
// subscribers, and serves `from_seq` replay from the per-session ring. It is the
// in-process leg the SessionService.WatchSession gRPC handler adapts to
// mechanically. A zero Fanout is not usable; construct with NewFanout.
type Fanout struct {
	mu          sync.Mutex
	streams     map[string]*sessionStream // session_uuid → stream
	historySize int
}

// NewFanout constructs the WatchSession terminator. historySize bounds each
// session's resume ring; a value <= 0 uses defaultHistorySize.
func NewFanout(historySize int) *Fanout {
	if historySize <= 0 {
		historySize = defaultHistorySize
	}
	return &Fanout{
		streams:     make(map[string]*sessionStream),
		historySize: historySize,
	}
}

// stream returns the per-session stream for sessionUUID, creating it on first
// use. Caller must NOT hold s.mu of the returned stream.
func (f *Fanout) stream(sessionUUID string) *sessionStream {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.streams[sessionUUID]
	if st == nil {
		st = &sessionStream{
			subscribers: make(map[int]Emitter),
			nextSeq:     1,
			historySize: f.historySize,
		}
		f.streams[sessionUUID] = st
	}
	return st
}

// Publish stamps ev with the next per-session seq (D79 — EVERY event carries
// seq, from M0; this is the ONE place the seq is assigned, so the wire and the
// ring never disagree), records it into the resume ring, and fans it to every
// current subscriber in registration order. The session_id on the event is set
// to sessionUUID. It returns the seq stamped. A subscriber whose Emit fails is
// dropped from the set (independent reader-drop, D61) without aborting the fan —
// the other readers and the ring are unaffected.
//
// Publish is how the host-ward event feed (the D38 socket terminated at the host
// agent, relayed control-plane-ward) enters the control-plane fan-out: the host
// agent's projected attach.v1.SessionEvent is published here and fanned to the
// product surfaces. The orchestrator is the seq authority (the host-side ring
// and this control-plane ring are distinct rings; this terminator owns the seqs
// the WatchSession clients recover by).
func (f *Fanout) Publish(ctx context.Context, sessionUUID string, ev *attachv1.SessionEvent) uint64 {
	st := f.stream(sessionUUID)
	st.mu.Lock()
	seq := st.nextSeq
	st.nextSeq++
	ev.Seq = seq
	ev.SessionId = sessionUUID
	st.recordHistory(ev)
	subs := make([]struct {
		id int
		e  Emitter
	}, 0, len(st.subscribers))
	for id, e := range st.subscribers {
		subs = append(subs, struct {
			id int
			e  Emitter
		}{id, e})
	}
	st.mu.Unlock()

	// Deliver outside st.mu so a slow/blocking Emit never holds the fan-out lock
	// (the same discipline as the hostbridge pump): a subscriber recovers via
	// from_seq replay, it never back-pressures the shared seq counter. Order is
	// not guaranteed across subscribers, but each receives ascending seqs.
	for _, sub := range subs {
		if err := sub.e.Emit(ctx, ev); err != nil {
			st.unsubscribe(sub.id)
		}
	}
	return seq
}

// recordHistory appends ev to the resume ring, evicting the oldest when the ring
// is full. The ring stays ascending-by-seq because Publish stamps strictly
// increasing seqs under st.mu. Caller holds st.mu.
func (st *sessionStream) recordHistory(ev *attachv1.SessionEvent) {
	st.ring = append(st.ring, ev)
	if len(st.ring) > st.historySize {
		// Drop the oldest; keep the most-recent historySize events.
		drop := len(st.ring) - st.historySize
		st.ring = append([]*attachv1.SessionEvent(nil), st.ring[drop:]...)
	}
}

// Subscribe registers e for sessionUUID's fan-out and returns an unsubscribe
// func. If fromSeq > 0, the events still in the ring with seq >= fromSeq are
// replayed to e BEFORE registration so the reader resumes exactly where it
// dropped (D61 slow-reader recovery); fromSeq == 0 backfills whatever the ring
// holds (the late-joiner case). A fromSeq that aged out of the ring returns
// ErrResumeWindowExceeded and registers NOTHING — the caller re-attaches from
// the frontier. Replay and registration happen under st.mu so no live event is
// missed in the gap between the ring snapshot and joining the set.
func (f *Fanout) Subscribe(ctx context.Context, sessionUUID string, fromSeq uint64, e Emitter) (unsubscribe func(), err error) {
	st := f.stream(sessionUUID)
	st.mu.Lock()

	// Resume window check: a non-zero fromSeq earlier than the oldest retained
	// event aged out of the ring. (fromSeq == 0 is always admissible — backfill.)
	if fromSeq > 0 && len(st.ring) > 0 {
		oldest := st.ring[0].GetSeq()
		if fromSeq < oldest {
			st.mu.Unlock()
			return nil, ErrResumeWindowExceeded
		}
	}

	// Replay the in-window tail (ascending seq) to the new subscriber first.
	replay := make([]*attachv1.SessionEvent, 0, len(st.ring))
	for _, ev := range st.ring {
		if ev.GetSeq() >= fromSeq {
			replay = append(replay, ev)
		}
	}
	sort.Slice(replay, func(i, j int) bool { return replay[i].GetSeq() < replay[j].GetSeq() })

	id := st.nextSubID
	st.nextSubID++
	st.subscribers[id] = e
	st.mu.Unlock()

	for _, ev := range replay {
		if err := e.Emit(ctx, ev); err != nil {
			st.unsubscribe(id)
			return nil, fmt.Errorf("attach: replay from_seq %d for session %q: %w", fromSeq, sessionUUID, err)
		}
	}

	var once sync.Once
	return func() { once.Do(func() { st.unsubscribe(id) }) }, nil
}

// unsubscribe removes the subscriber id from the set (idempotent).
func (st *sessionStream) unsubscribe(id int) {
	st.mu.Lock()
	delete(st.subscribers, id)
	st.mu.Unlock()
}

// SubscriberCount reports the live subscriber count for a session (the one
// WRITER + the N READERs currently fanned to). Zero for an unknown session.
func (f *Fanout) SubscriberCount(sessionUUID string) int {
	f.mu.Lock()
	st := f.streams[sessionUUID]
	f.mu.Unlock()
	if st == nil {
		return 0
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.subscribers)
}

// Close drops a session's stream (its subscriber set and resume ring) — the
// teardown hook for DESTROYED (doc 15 §4.2): no fan-out and no retained history
// survive the session. Idempotent.
func (f *Fanout) Close(sessionUUID string) {
	f.mu.Lock()
	delete(f.streams, sessionUUID)
	f.mu.Unlock()
}
