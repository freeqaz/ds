package hostagent

import (
	"context"
	"errors"
	"testing"
)

// These tests exercise SweepCoordinator (sweep_coordinator.go), the registry-free
// post-commit revocation-sweep driver. They reuse the in-memory sweep fakes and
// helpers already defined in the package's test files — fakeConsumerSweep,
// threeSweepers, snapAtSeq (sweep_runner_test.go) and eventLog, firstIndexOf
// (apply_test.go) — so nothing is redeclared here.

func TestSweepCoordinator(t *testing.T) {
	ctx := context.Background()

	t.Run("ConstructorRejectsBadWiring", func(t *testing.T) {
		dns, tls, nft, clients := threeSweepers(nil)

		// missing consumer (only two)
		if _, err := NewSweepCoordinator(tls, nft); err == nil {
			t.Fatalf("NewSweepCoordinator(2 consumers): want error, got nil")
		}
		// duplicate consumer
		if _, err := NewSweepCoordinator(dns, tls, nft, dns); err == nil {
			t.Fatalf("NewSweepCoordinator(duplicate): want error, got nil")
		}
		// nil client
		if _, err := NewSweepCoordinator(dns, tls, nil); err == nil {
			t.Fatalf("NewSweepCoordinator(nil client): want error, got nil")
		}
		// unrecognized name
		bad := &fakeConsumerSweep{name: "ds-bogus"}
		if _, err := NewSweepCoordinator(dns, tls, bad); err == nil {
			t.Fatalf("NewSweepCoordinator(unrecognized): want error, got nil")
		}
		// the good set
		if _, err := NewSweepCoordinator(clients...); err != nil {
			t.Fatalf("NewSweepCoordinator(good set): %v", err)
		}
	})

	t.Run("AllThreeSweepInAdmitterLastOrderAndReturnMin", func(t *testing.T) {
		// ACCEPTANCE core: the coordinator drives each consumer's sweep path,
		// collects the swept seqs IN ORDER, computes the min, and returns it. The
		// three report distinct seqs (7, 9, 8) so the result proves a real min, not a
		// pass-through of snap.Seq or of the first/last consumer.
		log := &eventLog{}
		dns, tls, nft, _ := threeSweepers(log)
		tls.useReportSeq, tls.reportSeq = true, 7
		nft.useReportSeq, nft.reportSeq = true, 9
		dns.useReportSeq, dns.reportSeq = true, 8
		coord, err := NewSweepCoordinator(dns, tls, nft)
		if err != nil {
			t.Fatalf("NewSweepCoordinator: %v", err)
		}

		got, err := coord.Sweep(ctx, snapAtSeq(7))
		if err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		if got != 7 {
			t.Fatalf("swept seq = %d; want 7 (min over {7,9,8})", got)
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
	})

	t.Run("AllSweptAtSnapSeqReturnsSnapSeq", func(t *testing.T) {
		// When every consumer reports the snapshot's own seq (the normal "fully swept
		// at vN+1" case), the min is snap.Seq — proving the acceptance's "all three
		// return a swept seq >= snap.Seq" on the happy path.
		_, _, _, clients := threeSweepers(nil)
		coord, err := NewSweepCoordinator(clients...)
		if err != nil {
			t.Fatalf("NewSweepCoordinator: %v", err)
		}
		got, err := coord.Sweep(ctx, snapAtSeq(42))
		if err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		if got != 42 {
			t.Fatalf("swept seq = %d; want 42 (all swept at snap.Seq)", got)
		}
	})

	t.Run("Seq0SentinelDragsMinToZeroAndStops", func(t *testing.T) {
		// The seq-0 sentinel ("error or no sweep") drags the host-ward min to 0 even
		// though the earlier consumers swept at a positive seq — and it is NOT a Go
		// error (the sentinel is a deliberate fail-closed signal). The coordinator
		// STOPS at the sentinel: the admitter (which sweeps last) is never driven.
		log := &eventLog{}
		dns, tls, nft, _ := threeSweepers(log)
		// nft sweeps SECOND (admitter-last order: tls, nft, dns) and reports the
		// seq-0 sentinel; dns (the admitter) must therefore never be driven.
		nft.useReportSeq, nft.reportSeq = true, 0
		coord, err := NewSweepCoordinator(dns, tls, nft)
		if err != nil {
			t.Fatalf("NewSweepCoordinator: %v", err)
		}

		got, err := coord.Sweep(ctx, snapAtSeq(9))
		if err != nil {
			t.Fatalf("Sweep (seq-0 sentinel is not an error path): %v", err)
		}
		if got != 0 {
			t.Fatalf("swept seq = %d; want 0 (nft reported the seq-0 sentinel — min clamps to 0)", got)
		}
		// The admitter, which sweeps after nft, was never driven (all-or-none short
		// circuit at the sentinel).
		if n := dns.sweepCount(); n != 0 {
			t.Fatalf("ds-dnsgate sweepCount = %d after a seq-0 sentinel stop; want 0 (not driven)", n)
		}
		_ = tls
	})

	t.Run("ConsumerSweepErrorFailsHostWideAndStops", func(t *testing.T) {
		// Fail-closed: one consumer's sweep ERROR fails the host-wide sweep all-or-none
		// — Sweep returns (0, err) and STOPS before driving the remaining consumers.
		log := &eventLog{}
		dns, tls, nft, _ := threeSweepers(log)
		// tls sweeps FIRST (admitter-last order) and errors; nft and dns must not run.
		tls.sweepErr = errors.New("flush_session severing failed")
		coord, err := NewSweepCoordinator(dns, tls, nft)
		if err != nil {
			t.Fatalf("NewSweepCoordinator: %v", err)
		}

		got, err := coord.Sweep(ctx, snapAtSeq(11))
		if err == nil {
			t.Fatalf("Sweep with a consumer error: want error, got nil")
		}
		if got != 0 {
			t.Fatalf("swept seq on sweep error = %d; want 0 (host-ward seq held)", got)
		}
		// The error stopped the round before the later consumers were driven.
		if n := nft.sweepCount(); n != 0 {
			t.Fatalf("nft-writer sweepCount = %d after a first-consumer error; want 0 (not driven)", n)
		}
		if n := dns.sweepCount(); n != 0 {
			t.Fatalf("ds-dnsgate sweepCount = %d after a first-consumer error; want 0 (not driven)", n)
		}
	})

	t.Run("NilSnapshotRejected", func(t *testing.T) {
		_, _, _, clients := threeSweepers(nil)
		coord, err := NewSweepCoordinator(clients...)
		if err != nil {
			t.Fatalf("NewSweepCoordinator: %v", err)
		}
		if got, err := coord.Sweep(ctx, nil); err == nil || got != 0 {
			t.Fatalf("Sweep(nil snap) = (%d, %v); want (0, err)", got, err)
		}
	})

	t.Run("SatisfiesSweeperSeamForApplyCoordinator", func(t *testing.T) {
		// ACCEPTANCE: the coordinator returns the correct swept seq to the
		// ApplyCoordinator — wire it as the coordinator's Sweeper and prove a full
		// commit advances the reported applied seq to the post-sweep min.
		applyLog := &eventLog{}
		_, _, _, sweepClients := threeSweepers(nil)
		coord, err := NewSweepCoordinator(sweepClients...)
		if err != nil {
			t.Fatalf("NewSweepCoordinator: %v", err)
		}

		// coord must satisfy the Sweeper seam apply.go's coordinator consumes.
		var _ Sweeper = coord

		tls, nft, dns, order := threeConsumers(applyLog)
		apply, err := NewApplyCoordinator(order, coord)
		if err != nil {
			t.Fatalf("NewApplyCoordinator: %v", err)
		}

		out, err := apply.Apply(ctx, snapAtSeq(21))
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !out.Committed || !out.Swept {
			t.Fatalf("Apply outcome Committed=%v Swept=%v; want both true", out.Committed, out.Swept)
		}
		if out.AppliedSeq != 21 {
			t.Fatalf("Apply AppliedSeq = %d; want 21 (post-sweep min over three)", out.AppliedSeq)
		}
		if as := apply.AppliedSeq(); as != 21 {
			t.Fatalf("coordinator AppliedSeq = %d; want 21", as)
		}
		_ = tls
		_ = nft
		_ = dns
	})

	t.Run("SweepErrorHoldsApplySeqViaApplyCoordinator", func(t *testing.T) {
		// End-to-end fail-closed: a sweep error wired through the ApplyCoordinator
		// HOLDS apply_seq at the prior version even though all three consumers
		// committed (they stay on vN+1, at-least-as-strict) — D72 all-or-none apply.
		_, _, _, sweepClients := threeSweepers(nil)
		// Force the first-swept consumer (ds-tlsproxy, admitter-last order) to error.
		for _, c := range sweepClients {
			if fc, ok := c.(*fakeConsumerSweep); ok && fc.name == BoundaryTLSProxy {
				fc.sweepErr = errors.New("flush_session severing failed")
			}
		}
		coord, err := NewSweepCoordinator(sweepClients...)
		if err != nil {
			t.Fatalf("NewSweepCoordinator: %v", err)
		}

		_, _, _, order := threeConsumers(&eventLog{})
		apply, err := NewApplyCoordinator(order, coord)
		if err != nil {
			t.Fatalf("NewApplyCoordinator: %v", err)
		}

		out, err := apply.Apply(ctx, snapAtSeq(8))
		if err == nil {
			t.Fatalf("Apply with a failing sweep: want the sweep error surfaced, got nil")
		}
		if !out.Committed {
			t.Fatalf("Committed=false after a successful commit; want true (the commit happened)")
		}
		if out.Swept {
			t.Fatalf("Swept=true after a failed sweep; want false")
		}
		if out.AppliedSeq != 0 {
			t.Fatalf("AppliedSeq=%d after a failed sweep; want 0 (held at prior version, D72)", out.AppliedSeq)
		}
	})
}
