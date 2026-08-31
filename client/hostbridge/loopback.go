// loopback.go — the in-process / loopback transport that implements the M0
// "direct client→host-agent" AttachHandle seam without a socket or a container.
//
// This is the M0 transport realized in-process: a client (the thin client's
// stand-in) presents an AttachHandle to a LoopbackTransport, the transport
// resolves it against the Server it fronts, and the resulting Conn carries the
// attach.v1 event stream OUT (over a buffered channel, the WatchSession fan-out)
// and DriveInput/DriveGrant IN (over the writer seat). It is the same seam a
// future socket transport implements — the handle in, an event stream out, a
// drive path in — so the bridge core, the seat arbitration, and the tests are
// transport-agnostic. The container path (live.go) is the OTHER realization of
// this seam, gated behind DS_E2E_LIVE.
//
// Stdlib-only: the event stream is a buffered channel, not a network socket.
package hostbridge

import (
	"sync"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// LoopbackTransport fronts a Server and resolves AttachHandles into in-process
// Conns. It is the M0 direct transport with no relay and no wire: Dial(handle)
// validates the handle through the Server (auth, expiry, seat arbitration) and
// returns a Conn whose Events channel is fed by the bridge's fan-out.
type LoopbackTransport struct {
	server *Server
}

// NewLoopbackTransport fronts srv.
func NewLoopbackTransport(srv *Server) *LoopbackTransport {
	return &LoopbackTransport{server: srv}
}

// Conn is one client's in-process attachment over the loopback transport. Events
// delivers the attach.v1 deltas (closed when the session stream ends); the drive
// methods carry input back through the writer seat (refused for a READER). It is
// the client-facing handle of the seam — a socket transport's Conn would have the
// same surface backed by a framed connection.
type Conn struct {
	attachment *Attachment
	bridge     *Bridge // the fan-out hub; the resume ring lives here
	sub        *loopbackSubscriber
	events     chan attach.Event
	done       chan struct{}
	closeOnce  sync.Once

	// unsubscribeFn detaches this Conn's subscriber from the bridge fan-out when
	// the Conn was attached directly (not via Server.Attach + Attachment, which
	// owns its own unsubscribe). Nil on the normal Dial path; set by the resume
	// recovery's direct-subscribe path.
	unsubscribeFn func()
}

// loopbackSubscriber bridges the Bridge's push-model Subscriber to the Conn's
// pull-model Events channel. A bounded buffer absorbs bursts; if a slow consumer
// fills it, further events are dropped for that Conn rather than blocking the
// shared pump (the WatchSession fan-out must not let one slow reader stall the
// others — docs/15 §5.4 N-reader independence). Dropped-event accounting is
// surfaced via Dropped so a consumer can detect it (and, with per-event sequence
// numbers from M0, resume — §6.1 row 1).
type loopbackSubscriber struct {
	conn    *Conn
	mu      sync.Mutex
	dropped uint64
}

func (l *loopbackSubscriber) OnEvent(ev attach.Event) {
	select {
	case l.conn.events <- ev:
	default:
		l.mu.Lock()
		l.dropped++
		l.mu.Unlock()
	}
}

func (l *loopbackSubscriber) OnClose(error) {
	l.conn.closeOnce.Do(func() {
		close(l.conn.events)
		close(l.conn.done)
	})
}

// droppedCount reports how many events the fan-out dropped for this subscriber
// because its bounded delivery buffer (the Conn's events channel) was full when
// they arrived. A non-zero count means this reader's live stream has at least
// one Seq hole and a Conn.Resume is needed to recover it.
func (l *loopbackSubscriber) droppedCount() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

// eventBuffer is the per-Conn fan-out buffer depth. Generous so an ordinary
// test/consumer never drops; a slow consumer that overruns it drops rather than
// stalling the shared pump.
const eventBuffer = 256

// Dial presents handle to the transport and, on success, returns a live Conn.
// All handle validation and seat arbitration happen in Server.Attach — Dial is a
// thin transport adapter, so the loopback and a future socket transport reject
// an invalid/expired/wrong-seat handle identically. Errors are the Server's
// sentinels (ErrAuthInvalid, ErrHandleExpired, ErrWriterSeatTaken, …).
func (t *LoopbackTransport) Dial(handle AttachHandle) (*Conn, error) {
	conn := &Conn{
		events: make(chan attach.Event, eventBuffer),
		done:   make(chan struct{}),
	}
	sub := &loopbackSubscriber{conn: conn}
	conn.sub = sub
	att, err := t.server.Attach(handle, sub)
	if err != nil {
		return nil, err
	}
	conn.attachment = att
	// The resume ring lives on the session's bridge; capture it so this Conn can
	// recover events it dropped past the bounded eventBuffer (Conn.Resume).
	conn.bridge = att.session.bridge
	return conn, nil
}

// Events is the attach.v1 delta stream for this attachment (the WatchSession
// fan-out leg). It is closed when the session stream ends (CC stdout EOF or
// bridge shutdown). A WRITER and every READER each get their own Events channel.
func (c *Conn) Events() <-chan attach.Event { return c.events }

// Done is closed when the event stream closes (a select-able completion signal
// for consumers that don't range over Events).
func (c *Conn) Done() <-chan struct{} { return c.done }

// Role reports whether this Conn holds the writer seat or is a reader.
func (c *Conn) Role() Role { return c.attachment.Role() }

// DriveInput drives a user-input record back through the writer seat. A READER
// Conn refuses (ErrReaderCannotWrite). The bytes that land on CC stdin are the
// EXISTING driver's EncodeInput output (the bridge forwards to it) — the
// transport adds no encoding.
func (c *Conn) DriveInput(in DriveInput) error { return c.attachment.DriveInput(in) }

// DriveGrant drives an ask-response grant back through the writer seat with the
// chosen route. A READER refuses (ErrReaderCannotWrite). The bytes on CC stdin
// are the EXISTING driver's EncodeGrant/EncodeGrantPromptTool output.
func (c *Conn) DriveGrant(grant DriveGrant, route GrantRoute) error {
	return c.attachment.DriveGrant(grant, route)
}

// Close detaches this Conn (releasing the writer seat if held, freeing it for a
// later WRITER) and unsubscribes it. Idempotent. It does NOT close the bridge —
// the session outlives one client's attachment.
func (c *Conn) Close() error {
	c.attachment.Detach()
	return nil
}

// --- resume-from-seq recovery (slow-reader recovery over the bounded fan-out) -
//
// A READER slower than the shared pump fills its bounded events buffer
// (eventBuffer); the fan-out then DROPS for this Conn rather than stalling the
// pump or its peers (loopbackSubscriber.OnEvent; docs/15 §5.4 N-reader
// independence). The drop leaves a Seq hole in this reader's Events() stream.
// Dropped() surfaces that a hole exists; Resume() recovers the missing span from
// the Bridge's bounded history ring, exactly once and in Seq order — provided it
// is still retained, else ErrResumeWindowExceeded (a silently gapped stream is
// never produced).
//
// Resume RETURNS the recovered span rather than re-injecting it into Events():
// the consumer holds "the last Seq I durably processed" and splices the returned
// span ahead of the live tail it continues reading from Events(). This keeps the
// Events() channel contract (one in-order live stream, closed at end) unchanged
// while making the dropped span recoverable — the exactly-once guarantee rests
// on the consumer resuming from the last Seq it actually consumed.

// Dropped is the number of events the fan-out dropped for this Conn because its
// bounded delivery buffer was full when they arrived. Dropped() > 0 means this
// reader's Events() stream has at least one Seq hole; Resume(lastConsumedSeq)
// recovers it. The count is cumulative across the Conn's life (a successful
// Resume fills the holes but the historical drop count is a real liveness signal
// worth keeping).
func (c *Conn) Dropped() uint64 {
	if c.sub == nil {
		return 0
	}
	return c.sub.droppedCount()
}

// Resume recovers the events this reader missed after afterSeq, returning the
// recovered span in ascending Seq order (the caller splices it ahead of the live
// tail it keeps reading from Events()). afterSeq is the last Seq the reader
// DURABLY consumed (the Gap.LastGood, or 0 to backfill the retained ring from
// its start for a late joiner). It is a thin splice over Bridge.ReplayFrom:
//
//   - afterSeq == 0 backfills whatever the ring still retains (the late-joiner
//     case; never fails the window check).
//   - a RESUME (afterSeq > 0) whose missing span has aged out of the ring returns
//     a nil slice and ErrResumeWindowExceeded (all-or-nothing) — the consumer
//     must full re-attach.
//   - already caught up (afterSeq >= LastSeq) returns an empty (non-nil) slice.
//
// EXACTLY ONCE rests on the caller passing the last Seq it actually consumed off
// Events(): the returned span is Seq > afterSeq and the still-buffered live tail
// is Seq > afterSeq too, but the consumer drains the returned span first and
// then continues the live tail from where Events() left off, so a hole is filled
// without re-delivering an event it already read.
func (c *Conn) Resume(afterSeq uint64) ([]attach.Event, error) {
	if c.bridge == nil {
		// A Conn not backed by a Bridge ring (should not happen via Dial) has
		// nothing to replay; treat as caught up.
		return []attach.Event{}, nil
	}
	return c.bridge.ReplayFrom(afterSeq)
}

// --- gap detection (consumer-side helper) ------------------------------------

// Gap is a consumer-side helper that watches a per-reader event stream for Seq
// discontinuities — the signal that the fan-out dropped events for a slow Conn.
// It is intentionally NOT wired into Conn: gap detection is the consumer's
// concern (it owns "the last Seq I durably processed"), and keeping it a
// free-standing observer lets a consumer that uses ReplayFrom directly reuse the
// exact same discontinuity logic.
//
// Usage: feed every event the reader consumes through Observe; when Observe
// returns non-zero (or LastGood lags Bridge.LastSeq, a tail gap), call
// Conn.Resume(g.LastGood()) to recover, drain the returned span through Observe
// too (the recovered events arrive as harmless dups and close the hole), then
// keep observing.
type Gap struct {
	last uint64 // highest contiguous Seq observed (0 before the first event)
}

// NewGap returns a Gap primed at afterSeq: the next event is expected to be
// afterSeq+1. Pass 0 for a fresh stream (first event expected is Seq 1, the
// adapter's strict-from-1 contract).
func NewGap(afterSeq uint64) *Gap { return &Gap{last: afterSeq} }

// Observe folds one consumed event into the watcher and returns the size of the
// Seq discontinuity it introduces:
//
//   - 0 when ev is the in-order successor (ev.Seq == last+1) — the normal case.
//   - 0 when ev.Seq <= last — a duplicate or already-seen replay event; the
//     watcher ignores it (does not move backwards) so re-feeding a resumed span
//     is harmless.
//   - n > 0 when ev.Seq > last+1 — n == ev.Seq-last-1 events are MISSING between
//     them. The caller resumes from LastGood() to recover them; the watcher
//     advances last to ev.Seq so it does not re-flag the same hole.
//
// Advancing last even on a detected gap makes the gap a one-shot edge, and the
// subsequent Resume re-delivers the missing events with Seq <= the new last,
// which Observe then treats as the harmless dup case while the reader splices
// them into place.
func (g *Gap) Observe(ev attach.Event) (missing uint64) {
	if ev.Seq <= g.last {
		return 0 // duplicate / resumed replay; ignore, don't rewind
	}
	if g.last != 0 && ev.Seq > g.last+1 {
		missing = ev.Seq - g.last - 1
	}
	g.last = ev.Seq
	return missing
}

// LastGood is the highest Seq the watcher has observed — the resume key to pass
// to Conn.Resume / Bridge.ReplayFrom when a gap (mid-stream via Observe, or a
// tail gap vs Bridge.LastSeq) is detected.
func (g *Gap) LastGood() uint64 { return g.last }
