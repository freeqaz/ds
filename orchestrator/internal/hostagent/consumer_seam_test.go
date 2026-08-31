package hostagent

import "testing"

// CommitOrder is the FIXED admitter-last sequence: the two enforcers
// (ds-tlsproxy, nft-writer) BEFORE the admitter (ds-dnsgate). It must match the
// order NewApplyCoordinator validates.
func TestCommitOrderIsAdmitterLast(t *testing.T) {
	order := CommitOrder()
	if len(order) != 3 {
		t.Fatalf("CommitOrder length = %d, want 3", len(order))
	}
	if order[0] != BoundaryTLSProxy || order[1] != BoundaryNFTWriter || order[2] != BoundaryDNSGate {
		t.Fatalf("CommitOrder = %v, want [ds-tlsproxy nft-writer ds-dnsgate]", order)
	}
	// The admitter is last.
	if !IsAdmitter(order[len(order)-1]) {
		t.Fatalf("last consumer %q is not the admitter", order[len(order)-1])
	}
	// The mutating accessor must not expose the package global.
	order[0] = "tampered"
	if CommitOrder()[0] != BoundaryTLSProxy {
		t.Fatal("CommitOrder returned a slice aliasing the package global")
	}
}

func TestIsAdmitter(t *testing.T) {
	if !IsAdmitter(BoundaryDNSGate) {
		t.Fatal("ds-dnsgate must be the admitter")
	}
	if IsAdmitter(BoundaryTLSProxy) || IsAdmitter(BoundaryNFTWriter) {
		t.Fatal("only ds-dnsgate is the admitter")
	}
}

// OrderBarriers turns an unordered set of the three barriers into the one legal
// admitter-last commit sequence, ready for NewApplyCoordinator.
func TestOrderBarriersSortsToCommitOrder(t *testing.T) {
	log := &eventLog{}
	// Hand them in a deliberately WRONG order (admitter first).
	dnsgate := &fakeConsumer{name: BoundaryDNSGate, log: log}
	tlsproxy := &fakeConsumer{name: BoundaryTLSProxy, log: log}
	nft := &fakeConsumer{name: BoundaryNFTWriter, log: log}

	ordered, err := OrderBarriers(dnsgate, tlsproxy, nft)
	if err != nil {
		t.Fatalf("OrderBarriers: unexpected error: %v", err)
	}
	got := []string{ordered[0].Name(), ordered[1].Name(), ordered[2].Name()}
	want := []string{BoundaryTLSProxy, BoundaryNFTWriter, BoundaryDNSGate}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OrderBarriers ordering = %v, want %v", got, want)
		}
	}

	// The ordered slice is directly acceptable to the coordinator (admitter last).
	if _, err := NewApplyCoordinator(ordered, nil); err != nil {
		t.Fatalf("NewApplyCoordinator(OrderBarriers(...)): %v", err)
	}
}

func TestOrderBarriersRejectsBadSets(t *testing.T) {
	log := &eventLog{}
	tlsproxy := &fakeConsumer{name: BoundaryTLSProxy, log: log}
	nft := &fakeConsumer{name: BoundaryNFTWriter, log: log}
	dnsgate := &fakeConsumer{name: BoundaryDNSGate, log: log}

	cases := []struct {
		name     string
		barriers []ConsumerBarrier
	}{
		{"missing-admitter", []ConsumerBarrier{tlsproxy, nft}},
		{"duplicate", []ConsumerBarrier{tlsproxy, tlsproxy, dnsgate}},
		{"unrecognized", []ConsumerBarrier{tlsproxy, nft, &fakeConsumer{name: "bogus", log: log}}},
		{"nil", []ConsumerBarrier{tlsproxy, nft, nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := OrderBarriers(tc.barriers...); err == nil {
				t.Fatalf("OrderBarriers(%s) = nil error, want rejection", tc.name)
			}
		})
	}
}
