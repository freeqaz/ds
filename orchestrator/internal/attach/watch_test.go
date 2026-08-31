package attach

import (
	"context"
	"errors"
	"sync"
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// collector is a test Emitter that records every event it receives; failAfter > 0
// makes Emit fail once it has accepted that many events (to exercise independent
// reader-drop).
type collector struct {
	mu        sync.Mutex
	events    []*attachv1.SessionEvent
	failAfter int
}

func (c *collector) Emit(_ context.Context, ev *attachv1.SessionEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failAfter > 0 && len(c.events) >= c.failAfter {
		return errors.New("collector: stream closed")
	}
	c.events = append(c.events, ev)
	return nil
}

func (c *collector) seqs() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]uint64, len(c.events))
	for i, ev := range c.events {
		out[i] = ev.GetSeq()
	}
	return out
}

func stateEvent() *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Type: attachv1.EventType_EVENT_TYPE_SESSION_STATE,
		Payload: &attachv1.SessionEvent_SessionState{SessionState: &attachv1.SessionState{
			Name: attachv1.SessionStateName_SESSION_STATE_NAME_READY,
		}},
	}
}

func TestPublish_StampsMonotonicPerSessionSeqsFromM0(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(0)
	c := &collector{}
	unsub, err := f.Subscribe(ctx, "sess-1", 0, c)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsub()

	for i := 0; i < 4; i++ {
		seq := f.Publish(ctx, "sess-1", stateEvent())
		if seq != uint64(i+1) {
			t.Fatalf("Publish #%d seq = %d, want %d (seqs start at 1, every event carries one)", i, seq, i+1)
		}
	}
	if got, want := c.seqs(), []uint64{1, 2, 3, 4}; !eqSeqs(got, want) {
		t.Fatalf("subscriber seqs = %v, want %v", got, want)
	}
	// Every event must carry its session_id and a non-zero seq (D79: EVERY event).
	c.mu.Lock()
	for _, ev := range c.events {
		if ev.GetSeq() == 0 || ev.GetSessionId() != "sess-1" {
			t.Fatalf("event seq=%d session=%q, want non-zero seq + sess-1", ev.GetSeq(), ev.GetSessionId())
		}
	}
	c.mu.Unlock()
}

func TestPublish_FansToNReaders(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(0)
	readers := make([]*collector, 3)
	for i := range readers {
		readers[i] = &collector{}
		unsub, err := f.Subscribe(ctx, "sess-1", 0, readers[i])
		if err != nil {
			t.Fatalf("Subscribe reader %d: %v", i, err)
		}
		defer unsub()
	}
	if n := f.SubscriberCount("sess-1"); n != 3 {
		t.Fatalf("SubscriberCount = %d, want 3", n)
	}
	f.Publish(ctx, "sess-1", stateEvent())
	f.Publish(ctx, "sess-1", stateEvent())
	for i, r := range readers {
		if got, want := r.seqs(), []uint64{1, 2}; !eqSeqs(got, want) {
			t.Fatalf("reader %d seqs = %v, want %v", i, got, want)
		}
	}
}

func TestPublish_IndependentReaderDrop(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(0)
	good := &collector{}
	bad := &collector{failAfter: 1} // drops after the first event

	if _, err := f.Subscribe(ctx, "sess-1", 0, good); err != nil {
		t.Fatalf("Subscribe good: %v", err)
	}
	if _, err := f.Subscribe(ctx, "sess-1", 0, bad); err != nil {
		t.Fatalf("Subscribe bad: %v", err)
	}

	for i := 0; i < 3; i++ {
		f.Publish(ctx, "sess-1", stateEvent())
	}
	// The bad reader is dropped after its Emit error; the good reader keeps all
	// three (a dropped reader never stalls the shared fan-out, D61).
	if got, want := good.seqs(), []uint64{1, 2, 3}; !eqSeqs(got, want) {
		t.Fatalf("good reader seqs = %v, want %v (bad reader must not stall the fan)", got, want)
	}
	if n := f.SubscriberCount("sess-1"); n != 1 {
		t.Fatalf("SubscriberCount = %d after a drop, want 1", n)
	}
}

func TestSubscribe_FromSeqReplaysFromRing(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(0)
	// Publish 5 events with NO subscriber: they land in the ring.
	for i := 0; i < 5; i++ {
		f.Publish(ctx, "sess-1", stateEvent())
	}
	// A late reader resumes from seq 3: it must receive 3,4,5 (the in-window tail).
	c := &collector{}
	unsub, err := f.Subscribe(ctx, "sess-1", 3, c)
	if err != nil {
		t.Fatalf("Subscribe from_seq=3: %v", err)
	}
	defer unsub()
	if got, want := c.seqs(), []uint64{3, 4, 5}; !eqSeqs(got, want) {
		t.Fatalf("resume seqs = %v, want %v", got, want)
	}
	// A subsequent live event continues the sequence on the resumed reader.
	f.Publish(ctx, "sess-1", stateEvent())
	if got, want := c.seqs(), []uint64{3, 4, 5, 6}; !eqSeqs(got, want) {
		t.Fatalf("post-resume live seqs = %v, want %v", got, want)
	}
}

func TestSubscribe_FromSeqZeroBackfillsRing(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(0)
	for i := 0; i < 3; i++ {
		f.Publish(ctx, "sess-1", stateEvent())
	}
	c := &collector{}
	if _, err := f.Subscribe(ctx, "sess-1", 0, c); err != nil {
		t.Fatalf("Subscribe from_seq=0: %v", err)
	}
	if got, want := c.seqs(), []uint64{1, 2, 3}; !eqSeqs(got, want) {
		t.Fatalf("from_seq=0 backfill = %v, want %v (the late-joiner backfill of the ring)", got, want)
	}
}

func TestSubscribe_AgedOutResumeRefusedCleanly(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(4) // ring holds only the most-recent 4 events
	for i := 0; i < 10; i++ {
		f.Publish(ctx, "sess-1", stateEvent())
	}
	// Ring now holds seqs 7..10; a resume from seq 3 aged out.
	c := &collector{}
	_, err := f.Subscribe(ctx, "sess-1", 3, c)
	if !errors.Is(err, ErrResumeWindowExceeded) {
		t.Fatalf("aged-out resume err = %v, want ErrResumeWindowExceeded", err)
	}
	if len(c.seqs()) != 0 {
		t.Fatalf("aged-out resume delivered %d events, want 0 (a clean refusal registers nothing)", len(c.seqs()))
	}
	// The session still fans new events to a fresh frontier subscriber (the refusal
	// did not disturb the stream).
	if _, err := f.Subscribe(ctx, "sess-1", 0, &collector{}); err != nil {
		t.Fatalf("frontier Subscribe after refusal: %v", err)
	}
}

func TestUnsubscribe_StopsDelivery(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(0)
	c := &collector{}
	unsub, err := f.Subscribe(ctx, "sess-1", 0, c)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	f.Publish(ctx, "sess-1", stateEvent())
	unsub()
	f.Publish(ctx, "sess-1", stateEvent())
	if got, want := c.seqs(), []uint64{1}; !eqSeqs(got, want) {
		t.Fatalf("after unsubscribe seqs = %v, want %v", got, want)
	}
	// Unsubscribe is idempotent.
	unsub()
}

func TestClose_DropsSessionStream(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(0)
	if _, err := f.Subscribe(ctx, "sess-1", 0, &collector{}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	f.Publish(ctx, "sess-1", stateEvent())
	f.Close("sess-1")
	if n := f.SubscriberCount("sess-1"); n != 0 {
		t.Fatalf("SubscriberCount after Close = %d, want 0", n)
	}
	// A fresh subscribe after Close starts a new stream from seq 1 (no retained
	// history survives a destroyed session, doc 15 §4.2).
	c := &collector{}
	if _, err := f.Subscribe(ctx, "sess-1", 0, c); err != nil {
		t.Fatalf("Subscribe after Close: %v", err)
	}
	if seq := f.Publish(ctx, "sess-1", stateEvent()); seq != 1 {
		t.Fatalf("post-Close first seq = %d, want 1 (a destroyed session retains no history)", seq)
	}
}

func TestSessionsAreIsolated(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(0)
	a := &collector{}
	b := &collector{}
	if _, err := f.Subscribe(ctx, "sess-a", 0, a); err != nil {
		t.Fatalf("Subscribe a: %v", err)
	}
	if _, err := f.Subscribe(ctx, "sess-b", 0, b); err != nil {
		t.Fatalf("Subscribe b: %v", err)
	}
	f.Publish(ctx, "sess-a", stateEvent())
	f.Publish(ctx, "sess-a", stateEvent())
	f.Publish(ctx, "sess-b", stateEvent())
	if got, want := a.seqs(), []uint64{1, 2}; !eqSeqs(got, want) {
		t.Fatalf("sess-a seqs = %v, want %v", got, want)
	}
	if got, want := b.seqs(), []uint64{1}; !eqSeqs(got, want) {
		t.Fatalf("sess-b seqs = %v, want %v (per-session seqs are independent)", got, want)
	}
}

// TestPublish_ConcurrentFanIsRaceFree fans many publishers and a subscriber
// concurrently; it is meaningful under `go test -race`.
func TestPublish_ConcurrentFanIsRaceFree(t *testing.T) {
	ctx := context.Background()
	f := NewFanout(0)
	c := &collector{}
	if _, err := f.Subscribe(ctx, "sess-1", 0, c); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			f.Publish(ctx, "sess-1", stateEvent())
		}()
	}
	wg.Wait()
	// Seqs are unique and cover 1..n (the seq counter is the single authority).
	seen := map[uint64]bool{}
	for _, s := range c.seqs() {
		if s < 1 || s > n {
			t.Fatalf("seq %d out of range 1..%d", s, n)
		}
		if seen[s] {
			t.Fatalf("duplicate seq %d", s)
		}
		seen[s] = true
	}
	if len(seen) != n {
		t.Fatalf("delivered %d distinct seqs, want %d", len(seen), n)
	}
}

func eqSeqs(a, b []uint64) bool {
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
