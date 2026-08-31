package hostagent

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// A minimal valid composed POL-1 v0 document — enough top-level keys for the
// conservative StructuralValidator (schema_version / layer / posture). The deep
// guardrail-semantic gate is the consumers' job (ds-contracts policy-core); the
// store only confirms structural well-formedness.
const validDoc = `schema_version: pol1/v0
layer: system-baseline
posture: standard
`

// fakePersister is an in-memory SnapshotPersister: it records every Store call
// in order and can be forced to fail to exercise the fail-closed persist path.
type fakePersister struct {
	mu     sync.Mutex
	stored []*boundaryv1.PolicySnapshot
	err    error
}

func (f *fakePersister) Store(_ context.Context, snap *boundaryv1.PolicySnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.stored = append(f.stored, snap)
	return nil
}

func (f *fakePersister) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.stored)
}

// ackRecord is one (seq, content_hash) the store acked.
type ackRecord struct {
	seq  uint64
	hash []byte
}

// fakeAcker is an in-memory AckPolicySender: it records every Ack and can be
// forced to fail to exercise the failed-ack path.
type fakeAcker struct {
	mu   sync.Mutex
	acks []ackRecord
	err  error
}

func (f *fakeAcker) Ack(_ context.Context, seq uint64, hash []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.acks = append(f.acks, ackRecord{seq: seq, hash: hash})
	return nil
}

func (f *fakeAcker) records() []ackRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ackRecord, len(f.acks))
	copy(out, f.acks)
	return out
}

// snapshotFor builds a PolicySnapshot whose content_hash is the correct SHA-256
// over document, so it passes the verify gate. corruptHash flips a hash byte to
// force a NACK.
func snapshotFor(seq uint64, document string, corruptHash bool) *boundaryv1.PolicySnapshot {
	sum := sha256.Sum256([]byte(document))
	h := sum[:]
	if corruptHash {
		h = append([]byte(nil), h...)
		h[0] ^= 0xff
	}
	return &boundaryv1.PolicySnapshot{
		Seq:         seq,
		ContentHash: h,
		Document:    []byte(document),
	}
}

func newStoreForTest(t *testing.T) (*SnapshotStore, *fakePersister, *fakeAcker) {
	t.Helper()
	p := &fakePersister{}
	a := &fakeAcker{}
	store, err := NewSnapshotStore(p, a, nil) // nil → default StructuralValidator
	if err != nil {
		t.Fatalf("NewSnapshotStore: %v", err)
	}
	return store, p, a
}

// drainOne reads one snapshot off the host-local feed without blocking the test
// forever; the feed has buffer SnapshotFeedBuffer (1) so a single applied
// snapshot is readable without a concurrent reader.
func drainOne(t *testing.T, store *SnapshotStore) *boundaryv1.PolicySnapshot {
	t.Helper()
	select {
	case snap := <-store.Subscribe():
		return snap
	default:
		t.Fatalf("expected a snapshot on the host-local feed, none present")
		return nil
	}
}

func TestSnapshotStore(t *testing.T) {
	t.Run("ValidSnapshotVerifiesPersistsAcksAndFansOut", func(t *testing.T) {
		store, p, a := newStoreForTest(t)
		ctx := context.Background()

		// Before any apply, the host serves nothing beyond NFT-1 default-deny:
		// Current is not ok and AppliedSeq is 0.
		if _, _, ok := store.Current(); ok {
			t.Fatalf("Current ok=true before first apply; want false")
		}
		if got := store.AppliedSeq(); got != 0 {
			t.Fatalf("AppliedSeq=%d before first apply; want 0", got)
		}

		snap := snapshotFor(7, validDoc, false)
		applied, err := store.Apply(ctx, snap)
		if err != nil {
			t.Fatalf("Apply valid snapshot: %v", err)
		}
		if !applied {
			t.Fatalf("Apply applied=false for a valid snapshot; want true")
		}

		// Persisted exactly once.
		if got := p.count(); got != 1 {
			t.Fatalf("persisted count=%d; want 1", got)
		}
		// Acked exactly once, with the snapshot's seq + content_hash.
		acks := a.records()
		if len(acks) != 1 {
			t.Fatalf("ack count=%d; want 1", len(acks))
		}
		if acks[0].seq != 7 {
			t.Fatalf("acked seq=%d; want 7", acks[0].seq)
		}
		wantHash := sha256.Sum256([]byte(validDoc))
		if string(acks[0].hash) != string(wantHash[:]) {
			t.Fatalf("acked content_hash mismatch")
		}
		// Appears on the host-local feed.
		fed := drainOne(t, store)
		if fed.GetSeq() != 7 {
			t.Fatalf("fed snapshot seq=%d; want 7", fed.GetSeq())
		}
		// Current reads the applied snapshot + seq for the consumers.
		cur, seq, ok := store.Current()
		if !ok || seq != 7 || cur.GetSeq() != 7 {
			t.Fatalf("Current=(%v, seq=%d, ok=%v); want the applied seq-7 snapshot", cur, seq, ok)
		}
		if store.AppliedSeq() != 7 {
			t.Fatalf("AppliedSeq=%d; want 7", store.AppliedSeq())
		}
	})

	t.Run("CorruptedHashIsNackedHostStaysOnVN", func(t *testing.T) {
		store, p, a := newStoreForTest(t)
		ctx := context.Background()

		// Establish vN = seq 3.
		if applied, err := store.Apply(ctx, snapshotFor(3, validDoc, false)); err != nil || !applied {
			t.Fatalf("seed apply: applied=%v err=%v", applied, err)
		}
		_ = drainOne(t, store) // consume the seed fan-out
		persistAfterSeed := p.count()
		acksAfterSeed := len(a.records())

		// A seq-4 snapshot with a corrupted hash must NACK: not persisted, not
		// acked, applied=false with an error.
		applied, err := store.Apply(ctx, snapshotFor(4, validDoc, true))
		if applied {
			t.Fatalf("corrupted snapshot applied=true; want false (NACK)")
		}
		if err == nil {
			t.Fatalf("corrupted snapshot err=nil; want a NACK error")
		}
		if got := p.count(); got != persistAfterSeed {
			t.Fatalf("corrupted snapshot was persisted (count %d→%d); want no persist", persistAfterSeed, got)
		}
		if got := len(a.records()); got != acksAfterSeed {
			t.Fatalf("corrupted snapshot was acked (count %d→%d); want no ack (NACK)", acksAfterSeed, got)
		}
		// The host stays on vN (seq 3) and can still read the last valid snapshot.
		cur, seq, ok := store.Current()
		if !ok || seq != 3 || cur.GetSeq() != 3 {
			t.Fatalf("after NACK Current=(seq=%d, ok=%v); want host pinned at vN seq 3", seq, ok)
		}
		if store.AppliedSeq() != 3 {
			t.Fatalf("after NACK AppliedSeq=%d; want 3 (host stays on vN)", store.AppliedSeq())
		}
		// No new fan-out edge for the NACKed snapshot.
		select {
		case unexpected := <-store.Subscribe():
			t.Fatalf("NACKed snapshot was fanned out: seq %d", unexpected.GetSeq())
		default:
		}
	})

	t.Run("InvalidDocumentIsNackedHostStaysOnVN", func(t *testing.T) {
		store, p, a := newStoreForTest(t)
		ctx := context.Background()

		// Establish vN = seq 2.
		if applied, err := store.Apply(ctx, snapshotFor(2, validDoc, false)); err != nil || !applied {
			t.Fatalf("seed apply: applied=%v err=%v", applied, err)
		}
		_ = drainOne(t, store)
		persistAfterSeed := p.count()
		acksAfterSeed := len(a.records())

		// A document missing the mandatory top-level keys is structurally invalid.
		// Its hash is correct (so this isolates the schema gate, not the hash gate).
		const invalidDoc = "this is not a pol1 document\n"
		applied, err := store.Apply(ctx, snapshotFor(3, invalidDoc, false))
		if applied {
			t.Fatalf("invalid document applied=true; want false (NACK)")
		}
		if err == nil {
			t.Fatalf("invalid document err=nil; want a NACK error")
		}
		if got := p.count(); got != persistAfterSeed {
			t.Fatalf("invalid document was persisted; want no persist")
		}
		if got := len(a.records()); got != acksAfterSeed {
			t.Fatalf("invalid document was acked; want no ack (NACK)")
		}
		// Host stays on vN seq 2.
		if _, seq, ok := store.Current(); !ok || seq != 2 {
			t.Fatalf("after invalid-doc NACK Current seq=%d ok=%v; want pinned at vN seq 2", seq, ok)
		}
	})

	t.Run("DuplicateSeqIsIdempotentNoOp", func(t *testing.T) {
		store, p, a := newStoreForTest(t)
		ctx := context.Background()

		first := snapshotFor(5, validDoc, false)
		if applied, err := store.Apply(ctx, first); err != nil || !applied {
			t.Fatalf("first apply: applied=%v err=%v", applied, err)
		}
		_ = drainOne(t, store)

		// A second snapshot with the SAME seq is a dedup no-op: applied=false,
		// err=nil, no re-persist, no re-ack, no second fan-out.
		applied, err := store.Apply(ctx, snapshotFor(5, validDoc, false))
		if err != nil {
			t.Fatalf("duplicate seq err=%v; want nil (dedup no-op)", err)
		}
		if applied {
			t.Fatalf("duplicate seq applied=true; want false (dedup)")
		}
		if got := p.count(); got != 1 {
			t.Fatalf("duplicate seq re-persisted (count=%d); want 1", got)
		}
		if got := len(a.records()); got != 1 {
			t.Fatalf("duplicate seq re-acked (count=%d); want 1", got)
		}
		select {
		case unexpected := <-store.Subscribe():
			t.Fatalf("duplicate seq fanned out again: seq %d", unexpected.GetSeq())
		default:
		}

		// A STALE seq (below the applied seq) is also a dedup no-op.
		applied, err = store.Apply(ctx, snapshotFor(4, validDoc, false))
		if err != nil || applied {
			t.Fatalf("stale seq applied=%v err=%v; want a dedup no-op (false, nil)", applied, err)
		}
		if store.AppliedSeq() != 5 {
			t.Fatalf("AppliedSeq=%d after stale/dup applies; want 5", store.AppliedSeq())
		}
	})

	t.Run("PersistFailureNacksHostStaysOnVN", func(t *testing.T) {
		p := &fakePersister{err: errors.New("disk full")}
		a := &fakeAcker{}
		store, err := NewSnapshotStore(p, a, nil)
		if err != nil {
			t.Fatalf("NewSnapshotStore: %v", err)
		}
		ctx := context.Background()

		applied, err := store.Apply(ctx, snapshotFor(1, validDoc, false))
		if applied {
			t.Fatalf("persist-failure applied=true; want false")
		}
		if err == nil {
			t.Fatalf("persist-failure err=nil; want an error")
		}
		// Did not advance, did not ack, did not fan out.
		if store.AppliedSeq() != 0 {
			t.Fatalf("AppliedSeq=%d after persist failure; want 0 (host stays on vN)", store.AppliedSeq())
		}
		if len(a.records()) != 0 {
			t.Fatalf("acked despite persist failure; want no ack")
		}
		if _, _, ok := store.Current(); ok {
			t.Fatalf("Current ok=true after persist failure; want false")
		}
	})

	t.Run("AckFailureKeepsSnapshotApplied", func(t *testing.T) {
		p := &fakePersister{}
		a := &fakeAcker{err: errors.New("orchestrator unreachable")}
		store, err := NewSnapshotStore(p, a, nil)
		if err != nil {
			t.Fatalf("NewSnapshotStore: %v", err)
		}
		ctx := context.Background()

		// Ack fails, but the snapshot is already durably applied + fanned out, so
		// applied=true with the ack error surfaced (the caller may re-ack).
		applied, err := store.Apply(ctx, snapshotFor(9, validDoc, false))
		if !applied {
			t.Fatalf("ack-failure applied=false; want true (snapshot is durably applied)")
		}
		if err == nil {
			t.Fatalf("ack-failure err=nil; want the ack error surfaced")
		}
		if p.count() != 1 {
			t.Fatalf("ack-failure persisted count=%d; want 1", p.count())
		}
		if _, seq, ok := store.Current(); !ok || seq != 9 {
			t.Fatalf("after ack failure Current seq=%d ok=%v; want applied seq 9", seq, ok)
		}
		_ = drainOne(t, store)
	})

	t.Run("NilSnapshotAndConstructorGuards", func(t *testing.T) {
		store, _, _ := newStoreForTest(t)
		if applied, err := store.Apply(context.Background(), nil); applied || err == nil {
			t.Fatalf("nil snapshot Apply=(applied=%v, err=%v); want (false, error)", applied, err)
		}
		if _, err := NewSnapshotStore(nil, &fakeAcker{}, nil); err == nil {
			t.Fatalf("NewSnapshotStore(nil persister) err=nil; want error")
		}
		if _, err := NewSnapshotStore(&fakePersister{}, nil, nil); err == nil {
			t.Fatalf("NewSnapshotStore(nil acker) err=nil; want error")
		}
	})
}
