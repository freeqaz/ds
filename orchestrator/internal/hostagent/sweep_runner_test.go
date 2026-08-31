package hostagent

import (
	"context"
	"errors"
	"sync"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// fakeConsumerSweep is an in-memory ConsumerSweep that records its sweep events
// on a shared eventLog (reused from apply_test.go) and reports a configurable
// swept seq, or a forced error. By default it reports the snapshot's seq as the
// swept seq (the normal "fully swept at vN+1" case).
type fakeConsumerSweep struct {
	name string
	log  *eventLog

	// reportSeq, when non-zero, overrides the reported swept seq (used to inject
	// the seq-0 sentinel or a non-monotone value); when zero, the consumer reports
	// snap.GetSeq().
	reportSeq    uint64
	useReportSeq bool
	sweepErr     error

	mu       sync.Mutex
	sweptN   int
	sweptAt  []uint64
	lastSnap *boundaryv1.PolicySnapshot
}

func (f *fakeConsumerSweep) Name() string { return f.name }

func (f *fakeConsumerSweep) SweepAndAdvance(_ context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	f.mu.Lock()
	f.sweptN++
	f.lastSnap = snap
	f.mu.Unlock()
	if f.log != nil {
		f.log.record("sweep:" + f.name)
	}
	if f.sweepErr != nil {
		return 0, f.sweepErr
	}
	if f.useReportSeq {
		f.mu.Lock()
		f.sweptAt = append(f.sweptAt, f.reportSeq)
		f.mu.Unlock()
		return f.reportSeq, nil
	}
	f.mu.Lock()
	f.sweptAt = append(f.sweptAt, snap.GetSeq())
	f.mu.Unlock()
	return snap.GetSeq(), nil
}

func (f *fakeConsumerSweep) sweepCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sweptN
}

// threeSweepers builds the three fake sweep clients sharing one event log, in an
// intentionally NON-commit order (admitter FIRST) so the test proves the runner
// re-orders into admitter-last itself.
func threeSweepers(log *eventLog) (dns, tls, nft *fakeConsumerSweep, clients []ConsumerSweep) {
	dns = &fakeConsumerSweep{name: BoundaryDNSGate, log: log}
	tls = &fakeConsumerSweep{name: BoundaryTLSProxy, log: log}
	nft = &fakeConsumerSweep{name: BoundaryNFTWriter, log: log}
	return dns, tls, nft, []ConsumerSweep{dns, tls, nft}
}

func snapAtSeq(seq uint64) *boundaryv1.PolicySnapshot {
	return &boundaryv1.PolicySnapshot{Seq: seq}
}

func TestSweepRunner(t *testing.T) {
	ctx := context.Background()

	t.Run("ConstructorRejectsBadWiring", func(t *testing.T) {
		notifier := NewSweepNotifier()
		dns, tls, nft, clients := threeSweepers(nil)

		// nil notifier
		if _, err := NewSweepRunner(nil, clients...); err == nil {
			t.Fatalf("NewSweepRunner(nil notifier): want error, got nil")
		}
		// missing consumer (only two)
		if _, err := NewSweepRunner(notifier, tls, nft); err == nil {
			t.Fatalf("NewSweepRunner(2 consumers): want error, got nil")
		}
		// duplicate consumer
		if _, err := NewSweepRunner(notifier, dns, tls, nft, dns); err == nil {
			t.Fatalf("NewSweepRunner(duplicate): want error, got nil")
		}
		// nil client
		if _, err := NewSweepRunner(notifier, dns, tls, nil); err == nil {
			t.Fatalf("NewSweepRunner(nil client): want error, got nil")
		}
		// unrecognized name
		bad := &fakeConsumerSweep{name: "ds-bogus"}
		if _, err := NewSweepRunner(notifier, dns, tls, bad); err == nil {
			t.Fatalf("NewSweepRunner(unrecognized): want error, got nil")
		}
		// the good set
		if _, err := NewSweepRunner(notifier, clients...); err != nil {
			t.Fatalf("NewSweepRunner(good set): %v", err)
		}
	})

	t.Run("AllThreeSweepInAdmitterLastOrderAndReturnMin", func(t *testing.T) {
		log := &eventLog{}
		notifier := NewSweepNotifier()
		dns, tls, nft, clients := threeSweepers(log)
		runner, err := NewSweepRunner(notifier, clients...)
		if err != nil {
			t.Fatalf("NewSweepRunner: %v", err)
		}

		got, err := runner.Sweep(ctx, snapAtSeq(7))
		if err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		if got != 7 {
			t.Fatalf("swept seq = %d; want 7 (min over three, all swept at 7)", got)
		}
		// All three passed through their sweep callbacks exactly once.
		for _, c := range []*fakeConsumerSweep{dns, tls, nft} {
			if n := c.sweepCount(); n != 1 {
				t.Fatalf("consumer %q sweepCount = %d; want 1", c.Name(), n)
			}
		}
		// FIXED admitter-last order: ds-tlsproxy + nft-writer sweep BEFORE ds-dnsgate,
		// even though the clients were passed admitter-first.
		evs := log.snapshot()
		iTLS := firstIndexOf(evs, "sweep:"+BoundaryTLSProxy)
		iNFT := firstIndexOf(evs, "sweep:"+BoundaryNFTWriter)
		iDNS := firstIndexOf(evs, "sweep:"+BoundaryDNSGate)
		if iTLS < 0 || iNFT < 0 || iDNS < 0 {
			t.Fatalf("missing sweep events: %v", evs)
		}
		if !(iTLS < iDNS && iNFT < iDNS) {
			t.Fatalf("admitter (ds-dnsgate) must sweep LAST; order = %v", evs)
		}
		// The registry now holds all three HEALTHY at 7, so the heartbeat min is 7.
		if as := notifier.AppliedSeq(); as != 7 {
			t.Fatalf("notifier.AppliedSeq = %d; want 7", as)
		}
	})

	t.Run("Seq0SentinelDragsMinToZero", func(t *testing.T) {
		// ACCEPTANCE: collects applied_seq 0 (sentinel) from a consumer — the
		// host-ward swept seq must be 0 even though the others swept at a positive
		// seq (a consumer cannot claim a swept version it never reached).
		log := &eventLog{}
		notifier := NewSweepNotifier()
		dns, tls, nft, _ := threeSweepers(log)
		// nft reports the seq-0 sentinel (its "error or no sweep" signal).
		nft.useReportSeq = true
		nft.reportSeq = 0
		runner, err := NewSweepRunner(notifier, dns, tls, nft)
		if err != nil {
			t.Fatalf("NewSweepRunner: %v", err)
		}

		got, err := runner.Sweep(ctx, snapAtSeq(9))
		if err != nil {
			t.Fatalf("Sweep (seq-0 sentinel is not an error path): %v", err)
		}
		if got != 0 {
			t.Fatalf("swept seq = %d; want 0 (nft reported the seq-0 sentinel — min clamps to 0)", got)
		}
		// nft is DOWN at 0; tls + dns are HEALTHY at 9 — the heartbeat min folds to 0.
		if as := notifier.AppliedSeq(); as != 0 {
			t.Fatalf("notifier.AppliedSeq = %d; want 0 (seq-0 sentinel clamps the min)", as)
		}
	})

	t.Run("Seq0ThenAllPositiveAdvances", func(t *testing.T) {
		// ACCEPTANCE: collects applied_seq 0 (sentinel) first, THEN seq > 0 from all
		// three in order — the host-ward swept seq rises to the new min only once all
		// three report a positive completed sweep. A consumer that swept positively in
		// round 1 advances monotonically to a HIGHER seq in round 2 (sweeps are
		// monotone per the seq cursor — a held round re-drives at the next snapshot).
		log := &eventLog{}
		notifier := NewSweepNotifier()
		dns, tls, nft, clients := threeSweepers(log)
		// Round 1: nft reports the seq-0 sentinel; the host-ward min stays 0 even
		// though tls + dns swept at 4.
		nft.useReportSeq = true
		nft.reportSeq = 0
		runner, err := NewSweepRunner(notifier, clients...)
		if err != nil {
			t.Fatalf("NewSweepRunner: %v", err)
		}
		if got, err := runner.Sweep(ctx, snapAtSeq(4)); err != nil || got != 0 {
			t.Fatalf("round 1 Sweep = (%d, %v); want (0, nil)", got, err)
		}

		// Round 2: the next snapshot (seq 5) — nft now reports a real completed sweep,
		// and the previously-healthy consumers advance monotonically to 5. The min
		// rises to 5.
		nft.useReportSeq = false
		got, err := runner.Sweep(ctx, snapAtSeq(5))
		if err != nil {
			t.Fatalf("round 2 Sweep: %v", err)
		}
		if got != 5 {
			t.Fatalf("round 2 swept seq = %d; want 5 (all three now swept at 5)", got)
		}
		_ = dns
		_ = tls
	})

	t.Run("ConsumerSweepErrorFailsHostWideAndHoldsSeq", func(t *testing.T) {
		// ACCEPTANCE / fail-closed: one consumer's sweep error fails the host-wide
		// sweep all-or-none — Sweep returns (0, err) and the failing consumer is
		// marked DOWN, clamping the heartbeat min to 0.
		log := &eventLog{}
		notifier := NewSweepNotifier()
		dns, tls, nft, clients := threeSweepers(log)
		nft.sweepErr = errors.New("flush_session severing failed")
		runner, err := NewSweepRunner(notifier, clients...)
		if err != nil {
			t.Fatalf("NewSweepRunner: %v", err)
		}

		got, err := runner.Sweep(ctx, snapAtSeq(11))
		if err == nil {
			t.Fatalf("Sweep with a consumer error: want error, got nil")
		}
		if got != 0 {
			t.Fatalf("swept seq on sweep error = %d; want 0 (host-ward seq held)", got)
		}
		// nft is DOWN; the heartbeat min is 0 regardless of tls/dns having swept.
		if as := notifier.AppliedSeq(); as != 0 {
			t.Fatalf("notifier.AppliedSeq after sweep error = %d; want 0", as)
		}
		_ = dns
		_ = tls
	})

	t.Run("NonMonotoneAdvanceRejected", func(t *testing.T) {
		// ACCEPTANCE: rejects a non-monotone advance — a consumer that already swept
		// at a higher seq and reports a lower-or-equal seq while still HEALTHY is a
		// wiring bug; the runner surfaces NotifySwept's rejection as a sweep failure.
		log := &eventLog{}
		notifier := NewSweepNotifier()
		dns, tls, nft, clients := threeSweepers(log)
		runner, err := NewSweepRunner(notifier, clients...)
		if err != nil {
			t.Fatalf("NewSweepRunner: %v", err)
		}
		// Round 1: all three sweep at 10.
		if got, err := runner.Sweep(ctx, snapAtSeq(10)); err != nil || got != 10 {
			t.Fatalf("round 1 Sweep = (%d, %v); want (10, nil)", got, err)
		}
		// Round 2: nft regresses to 5 while still HEALTHY — must be rejected.
		nft.useReportSeq = true
		nft.reportSeq = 5
		got, err := runner.Sweep(ctx, snapAtSeq(12))
		if err == nil {
			t.Fatalf("Sweep with a non-monotone consumer report: want error, got nil")
		}
		if got != 0 {
			t.Fatalf("swept seq on non-monotone report = %d; want 0", got)
		}
		_ = dns
		_ = tls
	})

	t.Run("NilSnapshotRejected", func(t *testing.T) {
		notifier := NewSweepNotifier()
		_, _, _, clients := threeSweepers(nil)
		runner, err := NewSweepRunner(notifier, clients...)
		if err != nil {
			t.Fatalf("NewSweepRunner: %v", err)
		}
		if got, err := runner.Sweep(ctx, nil); err == nil || got != 0 {
			t.Fatalf("Sweep(nil snap) = (%d, %v); want (0, err)", got, err)
		}
	})

	t.Run("SatisfiesSweeperSeamForApplyCoordinator", func(t *testing.T) {
		// ACCEPTANCE: SweepRunner returns the correct swept seq to the
		// ApplyCoordinator — wire it as the coordinator's Sweeper and prove a full
		// commit advances the reported applied seq to the post-sweep min.
		applyLog := &eventLog{}
		notifier := NewSweepNotifier()
		_, _, _, sweepClients := threeSweepers(nil)
		runner, err := NewSweepRunner(notifier, sweepClients...)
		if err != nil {
			t.Fatalf("NewSweepRunner: %v", err)
		}

		// runner must satisfy the Sweeper seam apply.go's coordinator consumes.
		var _ Sweeper = runner

		tls, nft, dns, order := threeConsumers(applyLog)
		coord, err := NewApplyCoordinator(order, runner)
		if err != nil {
			t.Fatalf("NewApplyCoordinator: %v", err)
		}

		out, err := coord.Apply(ctx, snapAtSeq(21))
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !out.Committed || !out.Swept {
			t.Fatalf("Apply outcome Committed=%v Swept=%v; want both true", out.Committed, out.Swept)
		}
		if out.AppliedSeq != 21 {
			t.Fatalf("Apply AppliedSeq = %d; want 21 (post-sweep min over three)", out.AppliedSeq)
		}
		if as := coord.AppliedSeq(); as != 21 {
			t.Fatalf("coordinator AppliedSeq = %d; want 21", as)
		}
		// The heartbeat min folded over the same registry agrees.
		if as := notifier.AppliedSeq(); as != 21 {
			t.Fatalf("notifier.AppliedSeq = %d; want 21", as)
		}
		_ = tls
		_ = nft
		_ = dns
	})

	t.Run("HeartbeatMinClampsNonHealthyToZero", func(t *testing.T) {
		// ACCEPTANCE: the heartbeat's AppliedSeq folds the registry through the frozen
		// D72 min-over-three, clamping a non-HEALTHY consumer to 0 — prove via the
		// boundary list the runner's sweeps populate.
		notifier := NewSweepNotifier()
		_, _, _, clients := threeSweepers(nil)
		runner, err := NewSweepRunner(notifier, clients...)
		if err != nil {
			t.Fatalf("NewSweepRunner: %v", err)
		}
		if _, err := runner.Sweep(ctx, snapAtSeq(15)); err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		// All three HEALTHY at 15 — the frozen AppliedSeq over the boundary list is 15.
		boundary := notifier.Boundary()
		if as := AppliedSeq(boundary); as != 15 {
			t.Fatalf("AppliedSeq(boundary) = %d; want 15", as)
		}
		// Mark one consumer DEGRADED — the frozen min clamps it to 0.
		if err := notifier.NotifyUnhealthy(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_DEGRADED, "lost connection"); err != nil {
			t.Fatalf("NotifyUnhealthy: %v", err)
		}
		if as := AppliedSeq(notifier.Boundary()); as != 0 {
			t.Fatalf("AppliedSeq with a DEGRADED consumer = %d; want 0 (clamped)", as)
		}
	})
}
