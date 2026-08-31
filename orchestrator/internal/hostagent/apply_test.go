package hostagent

import (
	"context"
	"errors"
	"sync"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// eventLog records the GLOBAL order of prepare/commit/sweep events across the
// three fake consumers, so a test can assert the D72 admitter-last commit order
// (ds-tlsproxy + nft-writer commit BEFORE ds-dnsgate) and the all-or-none
// prepare-before-any-commit invariant. It is shared by reference among the fakes
// and the sweeper, guarded by a mutex because the prepare phase runs in parallel.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) record(ev string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.events))
	copy(out, l.events)
	return out
}

// firstIndexOf returns the position of the first event equal to ev, or -1.
func firstIndexOf(events []string, ev string) int {
	for i, e := range events {
		if e == ev {
			return i
		}
	}
	return -1
}

// preparedHandle is the opaque staged-evaluator handle a fake consumer's Prepare
// returns and its own Commit asserts it receives back — so a test proves each
// consumer commits the handle ITS prepare produced (the per-consumer atomic-flip
// routing), not another consumer's.
type preparedHandle struct {
	consumer string
	seq      uint64
}

// fakeConsumer is an in-memory ConsumerBarrier that records its prepare/commit
// events on the shared eventLog and can be forced to fail in either phase. It
// asserts (via the test) that Commit only ever receives a handle this consumer's
// own Prepare returned.
type fakeConsumer struct {
	name string
	log  *eventLog

	prepareErr error
	commitErr  error

	mu         sync.Mutex
	prepareN   int
	commitN    int
	committed  []*boundaryv1.PolicySnapshot
	gotHandle  PreparedSnapshot
	preparedAt uint64
}

func (f *fakeConsumer) Name() string { return f.name }

func (f *fakeConsumer) Prepare(_ context.Context, snap *boundaryv1.PolicySnapshot) (PreparedSnapshot, error) {
	f.mu.Lock()
	f.prepareN++
	f.preparedAt = snap.GetSeq()
	f.mu.Unlock()
	f.log.record("prepare:" + f.name)
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}
	return preparedHandle{consumer: f.name, seq: snap.GetSeq()}, nil
}

func (f *fakeConsumer) Commit(_ context.Context, prepared PreparedSnapshot) error {
	f.mu.Lock()
	f.commitN++
	f.gotHandle = prepared
	f.mu.Unlock()
	f.log.record("commit:" + f.name)
	if f.commitErr != nil {
		return f.commitErr
	}
	return nil
}

func (f *fakeConsumer) prepareCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.prepareN
}

func (f *fakeConsumer) commitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.commitN
}

func (f *fakeConsumer) handle() PreparedSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotHandle
}

// fakeSweeper records the post-commit sweep on the shared log and can be forced
// to fail (apply_seq must then NOT advance, D72). On success it reports the
// snapshot's seq as the swept seq.
type fakeSweeper struct {
	log *eventLog
	err error

	mu    sync.Mutex
	swept []uint64
}

func (s *fakeSweeper) Sweep(_ context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	s.mu.Lock()
	s.swept = append(s.swept, snap.GetSeq())
	s.mu.Unlock()
	s.log.record("sweep")
	if s.err != nil {
		return 0, s.err
	}
	return snap.GetSeq(), nil
}

func (s *fakeSweeper) sweepCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.swept)
}

// threeConsumers builds the three fakes in FIXED admitter-last COMMIT order
// (ds-tlsproxy + nft-writer first, ds-dnsgate last) sharing one event log.
func threeConsumers(log *eventLog) (tls, nft, dns *fakeConsumer, order []ConsumerBarrier) {
	tls = &fakeConsumer{name: BoundaryTLSProxy, log: log}
	nft = &fakeConsumer{name: BoundaryNFTWriter, log: log}
	dns = &fakeConsumer{name: BoundaryDNSGate, log: log}
	return tls, nft, dns, []ConsumerBarrier{tls, nft, dns}
}

func TestApplyBarrier(t *testing.T) {
	t.Run("AllHealthyCommitsAdmitterLastAndAdvancesSeqPostSweep", func(t *testing.T) {
		log := &eventLog{}
		tls, nft, dns, order := threeConsumers(log)
		sw := &fakeSweeper{log: log}
		coord, err := NewApplyCoordinator(order, sw)
		if err != nil {
			t.Fatalf("NewApplyCoordinator: %v", err)
		}

		// Before any apply the host has flipped no consumer — a booting host serves
		// nothing beyond NFT-1 default-deny (D72).
		if coord.HasApplied() {
			t.Fatalf("HasApplied=true before first apply; want false")
		}
		if got := coord.AppliedSeq(); got != 0 {
			t.Fatalf("AppliedSeq=%d before first apply; want 0", got)
		}

		snap := snapshotFor(11, validDoc, false)
		out, err := coord.Apply(context.Background(), snap)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !out.Committed {
			t.Fatalf("Apply Committed=false for all-healthy; want true")
		}

		// Each consumer prepared exactly once and committed exactly once.
		for _, c := range []*fakeConsumer{tls, nft, dns} {
			if c.prepareCount() != 1 {
				t.Fatalf("%s prepareCount=%d; want 1", c.name, c.prepareCount())
			}
			if c.commitCount() != 1 {
				t.Fatalf("%s commitCount=%d; want 1", c.name, c.commitCount())
			}
		}

		// Each consumer committed the handle ITS OWN prepare produced (per-consumer
		// atomic-flip routing).
		for _, c := range []*fakeConsumer{tls, nft, dns} {
			h, ok := c.handle().(preparedHandle)
			if !ok || h.consumer != c.name || h.seq != 11 {
				t.Fatalf("%s committed handle=%#v; want its own prepared handle for seq 11", c.name, c.handle())
			}
		}

		events := log.snapshot()

		// ALL THREE prepares happen BEFORE ANY commit (all-or-none: no consumer flips
		// until every consumer staged). The first commit must come after the last
		// prepare.
		lastPrepare := -1
		firstCommit := len(events)
		for i, ev := range events {
			switch {
			case len(ev) >= 8 && ev[:8] == "prepare:":
				if i > lastPrepare {
					lastPrepare = i
				}
			case len(ev) >= 7 && ev[:7] == "commit:":
				if i < firstCommit {
					firstCommit = i
				}
			}
		}
		if !(lastPrepare < firstCommit) {
			t.Fatalf("a commit ran before all prepares finished; events=%v", events)
		}

		// ADMITTER-LAST commit order (D72 make-before-break): ds-tlsproxy AND
		// nft-writer commit BEFORE ds-dnsgate.
		commitTLS := firstIndexOf(events, "commit:"+BoundaryTLSProxy)
		commitNFT := firstIndexOf(events, "commit:"+BoundaryNFTWriter)
		commitDNS := firstIndexOf(events, "commit:"+BoundaryDNSGate)
		if commitTLS < 0 || commitNFT < 0 || commitDNS < 0 {
			t.Fatalf("missing a commit event; events=%v", events)
		}
		if !(commitTLS < commitDNS) {
			t.Fatalf("ds-tlsproxy committed AFTER ds-dnsgate (admitter-last violated); events=%v", events)
		}
		if !(commitNFT < commitDNS) {
			t.Fatalf("nft-writer committed AFTER ds-dnsgate (admitter-last violated); events=%v", events)
		}

		// The post-commit sweep ran AFTER the last commit (apply_seq advances post-
		// sweep, D72).
		sweepIdx := firstIndexOf(events, "sweep")
		if sweepIdx < 0 {
			t.Fatalf("no sweep ran; events=%v", events)
		}
		if !(sweepIdx > commitDNS) {
			t.Fatalf("sweep ran before the admitter committed; events=%v", events)
		}
		if sw.sweepCount() != 1 {
			t.Fatalf("sweepCount=%d; want 1", sw.sweepCount())
		}

		// apply_seq advanced to the swept seq, ONLY after the sweep completed.
		if !out.Swept {
			t.Fatalf("Swept=false after a successful sweep; want true")
		}
		if out.AppliedSeq != 11 {
			t.Fatalf("AppliedSeq=%d post-sweep; want 11", out.AppliedSeq)
		}
		if coord.AppliedSeq() != 11 {
			t.Fatalf("coordinator AppliedSeq=%d; want 11", coord.AppliedSeq())
		}
		if !coord.HasApplied() {
			t.Fatalf("HasApplied=false after a committed apply; want true")
		}
	})

	t.Run("SecondConsumerPrepareFailsHostStaysOnVNNoCommits", func(t *testing.T) {
		log := &eventLog{}
		tls, nft, dns, order := threeConsumers(log)
		// The SECOND consumer (nft-writer) fails to prepare.
		nft.prepareErr = errors.New("policy-core rejected the composed document")
		sw := &fakeSweeper{log: log}
		coord, err := NewApplyCoordinator(order, sw)
		if err != nil {
			t.Fatalf("NewApplyCoordinator: %v", err)
		}

		// Seed a prior applied version (vN = seq 4) via a clean apply so the rollback
		// can be observed to leave the host on vN. Use a fresh log/consumers for the
		// seed so the failing-prepare assertions are clean.
		seedLog := &eventLog{}
		stls, snftw, sdns, seedOrder := threeConsumers(seedLog)
		_ = stls
		_ = snftw
		_ = sdns
		seedCoord, err := NewApplyCoordinator(seedOrder, &fakeSweeper{log: seedLog})
		if err != nil {
			t.Fatalf("seed NewApplyCoordinator: %v", err)
		}
		if out, err := seedCoord.Apply(context.Background(), snapshotFor(4, validDoc, false)); err != nil || !out.Committed {
			t.Fatalf("seed apply: out=%+v err=%v", out, err)
		}

		// Drive the FAILING apply on the real coordinator. It has no prior applied
		// version (appliedSeq 0 = vN is "nothing beyond default-deny"); a prepare
		// failure must leave it there with NO commits.
		snap := snapshotFor(5, validDoc, false)
		out, err := coord.Apply(context.Background(), snap)
		if out.Committed {
			t.Fatalf("Committed=true despite a prepare failure; want false (host stays on vN)")
		}
		if err == nil {
			t.Fatalf("err=nil despite a prepare failure; want an abort error")
		}

		// All three received a PREPARE call (prepares run in parallel before any
		// commit decision).
		for _, c := range []*fakeConsumer{tls, nft, dns} {
			if c.prepareCount() != 1 {
				t.Fatalf("%s prepareCount=%d; want 1 (all prepared in parallel)", c.name, c.prepareCount())
			}
		}

		// NO consumer committed — all-or-none rollback (D72).
		for _, c := range []*fakeConsumer{tls, nft, dns} {
			if c.commitCount() != 0 {
				t.Fatalf("%s commitCount=%d after a prepare failure; want 0 (no commits on rollback)", c.name, c.commitCount())
			}
		}

		// No commit/sweep events at all.
		events := log.snapshot()
		if firstIndexOf(events, "commit:"+BoundaryTLSProxy) >= 0 ||
			firstIndexOf(events, "commit:"+BoundaryNFTWriter) >= 0 ||
			firstIndexOf(events, "commit:"+BoundaryDNSGate) >= 0 {
			t.Fatalf("a commit ran despite a prepare failure; events=%v", events)
		}
		if firstIndexOf(events, "sweep") >= 0 {
			t.Fatalf("a sweep ran despite a prepare failure; events=%v", events)
		}
		if sw.sweepCount() != 0 {
			t.Fatalf("sweepCount=%d after a prepare failure; want 0", sw.sweepCount())
		}

		// The host stays on its previous applied version (here, 0 — never advanced).
		// apply_seq does NOT advance.
		if out.AppliedSeq != 0 {
			t.Fatalf("AppliedSeq=%d after a prepare-failure abort; want 0 (host stays on vN)", out.AppliedSeq)
		}
		if coord.AppliedSeq() != 0 {
			t.Fatalf("coordinator AppliedSeq=%d after abort; want 0", coord.AppliedSeq())
		}
		if coord.HasApplied() {
			t.Fatalf("HasApplied=true after a prepare-failure abort; want false")
		}
	})

	t.Run("PrepareFailureAfterAPriorAppliedVersionPinsToVN", func(t *testing.T) {
		// A coordinator already on vN (seq 8); a later snapshot whose prepare fails
		// must pin it AT seq 8 (the host stays fully on vN), never advance.
		log := &eventLog{}
		tls, nft, dns, order := threeConsumers(log)
		coord, err := NewApplyCoordinator(order, &fakeSweeper{log: log})
		if err != nil {
			t.Fatalf("NewApplyCoordinator: %v", err)
		}
		if out, err := coord.Apply(context.Background(), snapshotFor(8, validDoc, false)); err != nil || !out.Committed || out.AppliedSeq != 8 {
			t.Fatalf("seed apply to vN=8: out=%+v err=%v", out, err)
		}

		// Now the admitter (ds-dnsgate) fails its prepare for seq 9.
		dns.prepareErr = errors.New("staging failed")
		out, err := coord.Apply(context.Background(), snapshotFor(9, validDoc, false))
		if out.Committed || err == nil {
			t.Fatalf("prepare-failure apply: out=%+v err=%v; want abort", out, err)
		}
		// The seq-9 round committed nothing NEW: each consumer has exactly one commit
		// (from the seq-8 seed), none from the failed seq-9 round.
		for _, c := range []*fakeConsumer{tls, nft, dns} {
			if c.commitCount() != 1 {
				t.Fatalf("%s commitCount=%d; want 1 (only the seq-8 seed committed)", c.name, c.commitCount())
			}
		}
		// Host stays pinned at vN seq 8.
		if out.AppliedSeq != 8 || coord.AppliedSeq() != 8 {
			t.Fatalf("after prepare-failure: out.AppliedSeq=%d coord.AppliedSeq=%d; want 8 (pinned to vN)", out.AppliedSeq, coord.AppliedSeq())
		}
	})

	t.Run("SweepFailureHoldsAppliedSeqAtPriorEvenThoughConsumersCommitted", func(t *testing.T) {
		// All three commit, but the post-commit sweep fails: the consumers are on
		// vN+1 (fail-closed, at-least-as-strict), but apply_seq must NOT advance past
		// the prior version until the sweep completes (D72).
		log := &eventLog{}
		tls, nft, dns, order := threeConsumers(log)
		sw := &fakeSweeper{log: log, err: errors.New("flush_session severing failed")}
		coord, err := NewApplyCoordinator(order, sw)
		if err != nil {
			t.Fatalf("NewApplyCoordinator: %v", err)
		}

		out, err := coord.Apply(context.Background(), snapshotFor(3, validDoc, false))
		if err == nil {
			t.Fatalf("sweep failure err=nil; want the sweep error surfaced")
		}
		if !out.Committed {
			t.Fatalf("Committed=false after a successful commit; want true (the commit happened)")
		}
		// All three committed (fail-closed — they stay on vN+1).
		for _, c := range []*fakeConsumer{tls, nft, dns} {
			if c.commitCount() != 1 {
				t.Fatalf("%s commitCount=%d; want 1 (committed before the sweep failed)", c.name, c.commitCount())
			}
		}
		// apply_seq HELD at the prior version (0) — it does not advance until the
		// sweep completes.
		if out.Swept {
			t.Fatalf("Swept=true after a failed sweep; want false")
		}
		if out.AppliedSeq != 0 {
			t.Fatalf("AppliedSeq=%d after a failed sweep; want 0 (held until sweep completes, D72)", out.AppliedSeq)
		}
	})

	t.Run("NoSweeperReportsCommitWithoutAdvancingPostSweep", func(t *testing.T) {
		// With no sweeper wired the caller runs sweep on its own path: Apply reports
		// the commit (AppliedSeq=snap.Seq) but Swept=false (the post-sweep advance is
		// the caller's).
		log := &eventLog{}
		_, _, _, order := threeConsumers(log)
		coord, err := NewApplyCoordinator(order, nil)
		if err != nil {
			t.Fatalf("NewApplyCoordinator(nil sweeper): %v", err)
		}
		out, err := coord.Apply(context.Background(), snapshotFor(6, validDoc, false))
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !out.Committed {
			t.Fatalf("Committed=false; want true")
		}
		if out.Swept {
			t.Fatalf("Swept=true with no sweeper; want false")
		}
		if out.AppliedSeq != 6 {
			t.Fatalf("AppliedSeq=%d; want 6 (commit done, caller sweeps)", out.AppliedSeq)
		}
		if firstIndexOf(log.snapshot(), "sweep") >= 0 {
			t.Fatalf("a sweep ran with no sweeper wired")
		}
	})

	t.Run("ConstructorRejectsMisorderedOrIncompleteConsumerSets", func(t *testing.T) {
		log := &eventLog{}
		tls := &fakeConsumer{name: BoundaryTLSProxy, log: log}
		nft := &fakeConsumer{name: BoundaryNFTWriter, log: log}
		dns := &fakeConsumer{name: BoundaryDNSGate, log: log}

		// ds-dnsgate (the admitter) NOT last → rejected (admitter-last, D72).
		if _, err := NewApplyCoordinator([]ConsumerBarrier{dns, tls, nft}, nil); err == nil {
			t.Fatalf("admitter-not-last commit order accepted; want rejected")
		}
		// Wrong count.
		if _, err := NewApplyCoordinator([]ConsumerBarrier{tls, dns}, nil); err == nil {
			t.Fatalf("2-consumer set accepted; want rejected")
		}
		// Duplicate / missing consumer (two tls, no nft) — still 3 entries but not
		// the three distinct names.
		tls2 := &fakeConsumer{name: BoundaryTLSProxy, log: log}
		if _, err := NewApplyCoordinator([]ConsumerBarrier{tls, tls2, dns}, nil); err == nil {
			t.Fatalf("duplicate-consumer set accepted; want rejected")
		}
		// Nil entry.
		if _, err := NewApplyCoordinator([]ConsumerBarrier{tls, nil, dns}, nil); err == nil {
			t.Fatalf("nil consumer accepted; want rejected")
		}
		// The correct order is accepted.
		if _, err := NewApplyCoordinator([]ConsumerBarrier{tls, nft, dns}, nil); err != nil {
			t.Fatalf("correct admitter-last order rejected: %v", err)
		}
	})

	t.Run("NilSnapshotIsRejectedWithoutTouchingConsumers", func(t *testing.T) {
		log := &eventLog{}
		tls, nft, dns, order := threeConsumers(log)
		coord, err := NewApplyCoordinator(order, &fakeSweeper{log: log})
		if err != nil {
			t.Fatalf("NewApplyCoordinator: %v", err)
		}
		out, err := coord.Apply(context.Background(), nil)
		if out.Committed || err == nil {
			t.Fatalf("nil snapshot Apply: out=%+v err=%v; want (not committed, error)", out, err)
		}
		for _, c := range []*fakeConsumer{tls, nft, dns} {
			if c.prepareCount() != 0 || c.commitCount() != 0 {
				t.Fatalf("%s touched by a nil-snapshot apply; want untouched", c.name)
			}
		}
	})
}
