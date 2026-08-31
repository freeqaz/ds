package hostbridge

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// resume_test.go — the slow-reader recovery battery (adapted from the blocked
// wave-2 drive-w2/hostbridge-resume-from-seq branch onto the MERGED Bridge /
// loopback Conn). A READER slower than the shared pump drops events past its
// bounded delivery buffer (the Conn.events channel of depth eventBuffer) rather
// than stalling the pump or its peers (docs/15 §5.4 N-reader independence). The
// drop leaves a Seq hole; the reader detects it (Gap), resumes from its last-good
// Seq (Conn.Resume → Bridge.ReplayFrom over the history ring), and the missing
// span is recovered exactly once, in order — or fails LOUD
// (ErrResumeWindowExceeded) when it has aged out of the ring. A silently gapped
// stream is never produced.
//
// Every event here is synthetic and constructed in-process — no cassette, no
// claude, no container (the resume layer is a pure in-memory fan-out; the live
// tiers sit above it). Seq is strictly monotonic from 1, the contract the ring
// keys resume on (the adapter is the ordering authority, P10).

// rev builds a synthetic attach.Event with the given Seq. The payload is a
// well-formed SessionState (exactly one payload pointer set); the tests assert on
// Seq, which is the whole resume contract.
func rev(seq uint64) attach.Event {
	return attach.Event{
		Seq:        seq,
		SessionID:  "sess-resume-test",
		ObservedAt: time.Unix(0, 0).UTC(),
		Type:       attach.TypeSessionState,
		SessionState: &attach.SessionState{
			State:  attach.StateWorking,
			Reason: "synthetic",
		},
	}
}

// resumeBridge builds a Bridge with a chosen history-ring size, no real CC
// process (a discard stdin), for direct fanout/ring exercise.
func resumeBridge(t *testing.T, historySize int) *Bridge {
	t.Helper()
	return NewBridge(&captureStdin{}, BridgeConfig{HistorySize: historySize})
}

// fanRange fans synthetic events [from, to] (inclusive) through the bridge's
// fan-out (the same path Pump drives, recording each into the history ring). It
// directly exercises the fan-out + ring without a CC stream.
func fanRange(b *Bridge, from, to uint64) {
	for s := from; s <= to; s++ {
		b.fanout(rev(s))
	}
}

// drainChan pulls every immediately-available event off a Conn's live Events
// channel without blocking, returning them in delivery order.
func drainChan(c *Conn) []attach.Event {
	var got []attach.Event
	for {
		select {
		case ev, ok := <-c.events:
			if !ok {
				return got
			}
			got = append(got, ev)
		default:
			return got
		}
	}
}

func resumeSeqs(evs []attach.Event) []uint64 {
	out := make([]uint64, len(evs))
	for i, e := range evs {
		out[i] = e.Seq
	}
	return out
}

func equalUint64s(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// subscribeConn attaches a Conn to a bridge via a WRITER handle over the loopback
// transport — the realized path that wires the Conn's resume ring (the same path
// Dial uses). A small per-Conn buffer is forced so the test can overrun it.
func subscribeConn(t *testing.T, b *Bridge, buf int) *Conn {
	t.Helper()
	conn := &Conn{
		events: make(chan attach.Event, buf),
		done:   make(chan struct{}),
		bridge: b,
	}
	sub := &loopbackSubscriber{conn: conn}
	conn.sub = sub
	conn.unsubscribeFn = b.Subscribe(sub)
	return conn
}

// --- clause 1: slow-reader overrun drops, and the gap is detectable -----------

func TestResumeSlowReaderOverrunDropsAndTailGapDetectable(t *testing.T) {
	b := resumeBridge(t, 64)
	c := subscribeConn(t, b, 4) // 4-deep delivery buffer
	defer c.unsubscribeFn()

	// Fan 1..10 while the reader reads NOTHING: the buffer holds 4, the other 6
	// are dropped for this Conn. The pump (fanout) must not block — proving a
	// stalled reader does not stall the pump.
	fanRange(b, 1, 10)

	if got := c.Dropped(); got != 6 {
		t.Fatalf("Dropped() = %d, want 6 (10 fanned - 4 buffered)", got)
	}

	// The reader drains what made it through: the first 4 by Seq (1..4); 5..10
	// were dropped.
	got := drainChan(c)
	if want := []uint64{1, 2, 3, 4}; !equalUint64s(resumeSeqs(got), want) {
		t.Fatalf("delivered seqs = %v, want %v", resumeSeqs(got), want)
	}

	// The Gap helper sees no gap WITHIN the contiguous prefix; the hole is at the
	// END (5..10 never arrived). The consumer detects that by comparing LastGood
	// (4) to the Bridge's LastSeq (10): a positive difference is a tail gap.
	g := NewGap(0)
	for _, e := range got {
		if miss := g.Observe(e); miss != 0 {
			t.Fatalf("unexpected gap %d within contiguous prefix at seq %d", miss, e.Seq)
		}
	}
	if g.LastGood() != 4 {
		t.Fatalf("Gap.LastGood = %d, want 4", g.LastGood())
	}
	if b.LastSeq() != 10 {
		t.Fatalf("Bridge.LastSeq = %d, want 10", b.LastSeq())
	}
	if tailGap := b.LastSeq() - g.LastGood(); tailGap != 6 {
		t.Fatalf("detectable tail gap = %d, want 6", tailGap)
	}
}

// A gap in the MIDDLE of a delivered stream is flagged by Gap.Observe at the
// discontinuity.
func TestResumeGapDetectedMidStream(t *testing.T) {
	g := NewGap(0)
	feed := []uint64{1, 2, 3, 6, 7} // 4,5 dropped
	firstGapAt := -1
	var firstGapSize uint64
	for i, s := range feed {
		if miss := g.Observe(rev(s)); miss != 0 && firstGapAt < 0 {
			firstGapAt = i
			firstGapSize = miss
		}
	}
	if firstGapAt != 3 {
		t.Fatalf("gap detected at index %d, want 3 (the jump 3->6)", firstGapAt)
	}
	if firstGapSize != 2 {
		t.Fatalf("gap size = %d, want 2 (seqs 4 and 5 missing)", firstGapSize)
	}
	if g.LastGood() != 7 {
		t.Fatalf("LastGood after feed = %d, want 7", g.LastGood())
	}
}

// --- clause 2: Resume splices the missing span exactly once, in order ---------

func TestResumeRecoversMissingExactlyOnceInOrder(t *testing.T) {
	b := resumeBridge(t, 64)
	c := subscribeConn(t, b, 4)
	defer c.unsubscribeFn()

	// Overrun: fan 1..10 with no reads. Buffer keeps 1..4; 5..10 dropped but still
	// RETAINED in the 64-deep ring.
	fanRange(b, 1, 10)
	prefix := drainChan(c)
	if want := []uint64{1, 2, 3, 4}; !equalUint64s(resumeSeqs(prefix), want) {
		t.Fatalf("live prefix = %v, want %v", resumeSeqs(prefix), want)
	}
	if c.Dropped() != 6 {
		t.Fatalf("Dropped() = %d, want 6", c.Dropped())
	}

	// The reader's last durably-consumed Seq is 4. Resume from there: the
	// recovered span (5..10) is returned, in order, exactly once.
	recovered, err := c.Resume(4)
	if err != nil {
		t.Fatalf("Resume(4): %v", err)
	}
	if want := []uint64{5, 6, 7, 8, 9, 10}; !equalUint64s(resumeSeqs(recovered), want) {
		t.Fatalf("Resume(4) recovered %v, want %v", resumeSeqs(recovered), want)
	}

	// Now fan more LIVE events; the reader keeps reading the live channel after
	// splicing the recovered span. The full reconstructed stream is the live
	// prefix, then the recovered span, then the live tail — 1..13 contiguous, no
	// duplicates.
	fanRange(b, 11, 13)
	tail := drainChan(c)
	if want := []uint64{11, 12, 13}; !equalUint64s(resumeSeqs(tail), want) {
		t.Fatalf("post-resume live tail = %v, want %v", resumeSeqs(tail), want)
	}

	full := append(append(resumeSeqs(prefix), resumeSeqs(recovered)...), resumeSeqs(tail)...)
	assertResumeContiguousFrom1(t, full, 13)
}

// The Gap-driven recovery loop: observe a gap, resume from LastGood, and the
// spliced replay events flow back through Observe as harmless dups, closing the
// hole. This is the documented consumer recipe.
func TestResumeGapThenResumeClosesHole(t *testing.T) {
	b := resumeBridge(t, 64)
	c := subscribeConn(t, b, 4)
	defer c.unsubscribeFn()

	fanRange(b, 1, 10) // 1..4 buffered, 5..10 dropped-but-retained

	g := NewGap(0)
	for _, e := range drainChan(c) {
		g.Observe(e)
	}
	if g.LastGood() != 4 {
		t.Fatalf("LastGood = %d, want 4", g.LastGood())
	}
	// LastGood 4 < LastSeq 10 => a tail gap the consumer resumes.
	recovered, err := c.Resume(g.LastGood())
	if err != nil {
		t.Fatalf("Resume(%d): %v", g.LastGood(), err)
	}
	for _, e := range recovered {
		if miss := g.Observe(e); miss != 0 {
			t.Fatalf("recovered event seq %d re-flagged a gap of %d", e.Seq, miss)
		}
	}
	if g.LastGood() != 10 {
		t.Fatalf("after recovery LastGood = %d, want 10 (hole closed)", g.LastGood())
	}
}

// --- clause 3: a Resume older than the retained window fails loud, all-or-nothing

func TestResumePastWindowFailsLoudNothingPartial(t *testing.T) {
	// Ring retains only the most recent 8 events; buffer 4.
	b := resumeBridge(t, 8)
	c := subscribeConn(t, b, 4)
	defer c.unsubscribeFn()

	// Fan 1..20. The ring now holds only 13..20 (last 8). The reader's buffer kept
	// 1..4; everything else dropped. Its last durable Seq is 4 — far older than
	// the ring's oldest (13).
	fanRange(b, 1, 20)
	prefix := drainChan(c)
	if want := []uint64{1, 2, 3, 4}; !equalUint64s(resumeSeqs(prefix), want) {
		t.Fatalf("live prefix = %v, want %v", resumeSeqs(prefix), want)
	}
	if b.OldestRetainedSeq() != 13 {
		t.Fatalf("OldestRetainedSeq = %d, want 13 (HistorySize 8 over seq 1..20)", b.OldestRetainedSeq())
	}

	recovered, err := c.Resume(4)
	if !errors.Is(err, ErrResumeWindowExceeded) {
		t.Fatalf("Resume(4) error = %v, want ErrResumeWindowExceeded", err)
	}
	if len(recovered) != 0 {
		t.Fatalf("Resume past window recovered %d events, want 0 (nothing partial)", len(recovered))
	}

	// ReplayFrom directly must agree, all-or-nothing with a nil slice.
	got, err := b.ReplayFrom(4)
	if !errors.Is(err, ErrResumeWindowExceeded) {
		t.Fatalf("ReplayFrom(4) error = %v, want ErrResumeWindowExceeded", err)
	}
	if got != nil {
		t.Fatalf("ReplayFrom past window returned %v, want nil (all-or-nothing)", resumeSeqs(got))
	}
}

// The boundary case: resuming from exactly oldestRetained-1 is contiguous (no
// event between afterSeq and the ring was lost) and SUCCEEDS.
func TestResumeAtWindowBoundarySucceeds(t *testing.T) {
	b := resumeBridge(t, 8)
	c := subscribeConn(t, b, 64)
	defer c.unsubscribeFn()

	fanRange(b, 1, 20)
	drainChan(c) // consume the live 64-deep buffer prefix

	if b.OldestRetainedSeq() != 13 {
		t.Fatalf("OldestRetainedSeq = %d, want 13", b.OldestRetainedSeq())
	}
	// afterSeq == 12 == oldestRetained-1: seqs 13..20 are exactly the ring, so the
	// (12, 20] interval is fully retained -> success.
	recovered, err := c.Resume(12)
	if err != nil {
		t.Fatalf("Resume(12) at boundary: %v", err)
	}
	if want := []uint64{13, 14, 15, 16, 17, 18, 19, 20}; !equalUint64s(resumeSeqs(recovered), want) {
		t.Fatalf("Resume(12) recovered %v, want %v", resumeSeqs(recovered), want)
	}
	// One earlier (afterSeq == 11) drops seq 12, which has aged out -> fail loud.
	if _, err := b.ReplayFrom(11); !errors.Is(err, ErrResumeWindowExceeded) {
		t.Fatalf("ReplayFrom(11) error = %v, want ErrResumeWindowExceeded", err)
	}
}

// --- clause 4: one slow reader never stalls the pump or the other readers ------

func TestResumeOneSlowReaderNeverStallsPumpOrPeers(t *testing.T) {
	b := resumeBridge(t, 256)

	slow := subscribeConn(t, b, 4)   // never reads
	fast := subscribeConn(t, b, 256) // big buffer, keeps up
	defer slow.unsubscribeFn()
	defer fast.unsubscribeFn()

	const n = 200

	// Fan from a goroutine; if a slow reader could stall the pump, this would
	// deadlock. A watchdog bounds it.
	done := make(chan struct{})
	go func() {
		fanRange(b, 1, n)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pump stalled: a slow reader blocked the fan-out (docs/15 §5.4 violated)")
	}

	// The fast reader (256 buffer) received ALL 200 events, in order, gap-free —
	// the slow peer did not cost it a single event.
	fastGot := drainChan(fast)
	if len(fastGot) != n {
		t.Fatalf("fast reader got %d events, want %d (slow peer starved it)", len(fastGot), n)
	}
	assertResumeContiguousFrom1(t, resumeSeqs(fastGot), n)

	// The slow reader dropped everything past its 4-deep buffer but is recoverable
	// from the 256-deep ring (which retains the full 1..200 here): Resume(0)
	// backfills the entire stream.
	if slow.Dropped() != n-4 {
		t.Fatalf("slow reader Dropped() = %d, want %d", slow.Dropped(), n-4)
	}
	recovered, err := slow.Resume(0)
	if err != nil {
		t.Fatalf("slow reader Resume(0): %v", err)
	}
	// Resume(0) returns the whole retained ring (1..200). The slow reader's live
	// prefix (1..4) overlaps it; the consumer dedups via Gap (Observe ignores
	// Seq <= LastGood). Here we assert the backfill is the full retained window.
	if want := uint64(n); uint64(len(recovered)) != want {
		t.Fatalf("Resume(0) backfilled %d events, want %d (full retained ring)", len(recovered), want)
	}
}

// --- ring / pump invariants ---------------------------------------------------

// ReplayFrom(afterSeq>=lastSeq) is the caught-up case: empty, non-nil, no error.
func TestReplayFromCaughtUp(t *testing.T) {
	b := resumeBridge(t, 64)
	fanRange(b, 1, 5)
	for _, after := range []uint64{5, 6, 100} {
		got, err := b.ReplayFrom(after)
		if err != nil {
			t.Fatalf("ReplayFrom(%d): %v", after, err)
		}
		if got == nil {
			t.Fatalf("ReplayFrom(%d) returned nil, want empty non-nil", after)
		}
		if len(got) != 0 {
			t.Fatalf("ReplayFrom(%d) = %v, want empty", after, resumeSeqs(got))
		}
	}
}

// ReplayFrom(0) on a populated, window-truncated ring backfills the whole
// retained window — the late-joiner path; never the window-exceeded case.
func TestReplayFromZeroBackfillsRing(t *testing.T) {
	b := resumeBridge(t, 5)
	fanRange(b, 1, 12) // ring retains last 5: 8..12
	got, err := b.ReplayFrom(0)
	if err != nil {
		t.Fatalf("ReplayFrom(0): %v", err)
	}
	if want := []uint64{8, 9, 10, 11, 12}; !equalUint64s(resumeSeqs(got), want) {
		t.Fatalf("ReplayFrom(0) = %v, want %v (last HistorySize retained)", resumeSeqs(got), want)
	}
}

// The returned slice is the caller's own copy; mutating it must not corrupt the
// ring.
func TestReplayFromReturnsCopy(t *testing.T) {
	b := resumeBridge(t, 64)
	fanRange(b, 1, 3)
	got, err := b.ReplayFrom(0)
	if err != nil {
		t.Fatalf("ReplayFrom(0): %v", err)
	}
	got[0].Seq = 999 // mutate the caller's copy
	again, err := b.ReplayFrom(0)
	if err != nil {
		t.Fatalf("ReplayFrom(0) again: %v", err)
	}
	if again[0].Seq != 1 {
		t.Fatalf("ring corrupted by caller mutation: oldest seq = %d, want 1", again[0].Seq)
	}
}

// A Conn detached from the Bridge can no longer fall behind; its already-recorded
// drops stay recoverable from the ring while it is attached, and Resume on a
// closed Bridge's pump is the caught-up case (nothing newer than lastSeq).
func TestResumeAfterFanoutClose(t *testing.T) {
	b := resumeBridge(t, 64)
	c := subscribeConn(t, b, 4)

	fanRange(b, 1, 10)
	drainChan(c)
	// Close the fan-out (CC stdout EOF). The ring is unaffected; a resume still
	// recovers the dropped span.
	b.closeFanout(nil)
	recovered, err := c.Resume(4)
	if err != nil {
		t.Fatalf("Resume(4) after fanout close: %v", err)
	}
	if want := []uint64{5, 6, 7, 8, 9, 10}; !equalUint64s(resumeSeqs(recovered), want) {
		t.Fatalf("post-close Resume recovered %v, want %v", resumeSeqs(recovered), want)
	}
}

// --- concurrency: resume races the pump safely --------------------------------

// A Resume snapshotting the ring concurrently with the pump recording into it
// must be race-free (separate historyMu) and never panic.
func TestResumeConcurrentWithPump(t *testing.T) {
	b := resumeBridge(t, 512)
	c := subscribeConn(t, b, 8)
	defer c.unsubscribeFn()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		fanRange(b, 1, 300)
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = c.Resume(0) // hammer ReplayFrom while the pump records
			_ = c.Dropped()
		}
	}()
	wg.Wait()

	if b.LastSeq() != 300 {
		t.Fatalf("LastSeq = %d after concurrent pump, want 300", b.LastSeq())
	}
}

// assertResumeContiguousFrom1 asserts seqs is exactly 1,2,...,last with no gaps
// and no duplicates — the "ends seq-contiguous / no duplicates" acceptance bar.
func assertResumeContiguousFrom1(t *testing.T, seqs []uint64, last uint64) {
	t.Helper()
	if uint64(len(seqs)) != last {
		t.Fatalf("got %d seqs, want %d (1..%d contiguous)", len(seqs), last, last)
	}
	for i, s := range seqs {
		if want := uint64(i + 1); s != want {
			t.Fatalf("seq[%d] = %d, want %d (not contiguous/exactly-once)", i, s, want)
		}
	}
}
