package hostagent

import (
	"context"
	"crypto/sha256"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// seqByName extracts a name->applied_seq map and a name->state map from a
// rendered boundary list, so a test can assert per-consumer state without caring
// about list order.
func seqByName(boundary []*hostagentv1.ServiceHealth) (map[string]uint64, map[string]hostagentv1.HealthState) {
	seqs := map[string]uint64{}
	states := map[string]hostagentv1.HealthState{}
	for _, sh := range boundary {
		seqs[sh.GetName()] = sh.GetAppliedSeq()
		states[sh.GetName()] = sh.GetState()
	}
	return seqs, states
}

// TestSweepNotify_FailClosedBeforeAnySweep pins that a freshly-constructed
// registry — no consumer has reported a completed sweep — renders all three
// named consumers DOWN at seq 0, so the host-ward applied_seq is 0 (a booting
// host claims nothing beyond NFT-1 default-deny until its consumers sweep, D72).
func TestSweepNotify_FailClosedBeforeAnySweep(t *testing.T) {
	n := NewSweepNotifier()

	boundary := n.Boundary()
	if len(boundary) != 3 {
		t.Fatalf("boundary list: want exactly 3 named consumers, got %d", len(boundary))
	}
	seqs, states := seqByName(boundary)
	for _, name := range []string{BoundaryDNSGate, BoundaryTLSProxy, BoundaryNFTWriter} {
		if seqs[name] != 0 {
			t.Errorf("consumer %q before any sweep: want seq 0, got %d", name, seqs[name])
		}
		if states[name] == hostagentv1.HealthState_HEALTH_STATE_HEALTHY {
			t.Errorf("consumer %q before any sweep: want non-HEALTHY (fail-closed), got HEALTHY", name)
		}
	}
	if got := n.AppliedSeq(); got != 0 {
		t.Fatalf("applied_seq before any sweep: want 0 (fail-closed), got %d", got)
	}
}

// TestSweepNotify_MinOverThreeSweeps is the acceptance core: each of the three
// mock consumers reports a completed sweep with its own new applied_seq (5, 6,
// 5); the registry re-folds through the frozen AppliedSeq and the heartbeat
// reports min(5,6,5) = 5.
func TestSweepNotify_MinOverThreeSweeps(t *testing.T) {
	n := NewSweepNotifier()

	// Three mock consumers each report a completed post-commit sweep with its new
	// per-consumer applied_seq.
	if err := n.NotifySwept(BoundaryTLSProxy, 6); err != nil {
		t.Fatalf("NotifySwept ds-tlsproxy: %v", err)
	}
	if err := n.NotifySwept(BoundaryNFTWriter, 5); err != nil {
		t.Fatalf("NotifySwept nft-writer: %v", err)
	}
	if err := n.NotifySwept(BoundaryDNSGate, 5); err != nil {
		t.Fatalf("NotifySwept ds-dnsgate: %v", err)
	}

	if got := n.AppliedSeq(); got != 5 {
		t.Fatalf("applied_seq after sweeps (5,6,5): want min=5, got %d", got)
	}

	// The same value must surface through the assembled heartbeat frame.
	hb := BuildHeartbeat(HostState{HostID: "h1", Boundary: n.Boundary()})
	if hb.GetAppliedSeq() != 5 {
		t.Fatalf("heartbeat applied_seq after sweeps (5,6,5): want 5, got %d", hb.GetAppliedSeq())
	}
	// All three named consumers must ride the boundary list HEALTHY at their seq.
	seqs, states := seqByName(hb.GetBoundary())
	for name, want := range map[string]uint64{BoundaryTLSProxy: 6, BoundaryNFTWriter: 5, BoundaryDNSGate: 5} {
		if seqs[name] != want {
			t.Errorf("boundary seq for %q: want %d, got %d", name, want, seqs[name])
		}
		if states[name] != hostagentv1.HealthState_HEALTH_STATE_HEALTHY {
			t.Errorf("boundary state for %q: want HEALTHY, got %v", name, states[name])
		}
	}
}

// TestSweepNotify_SweepToZeroFailsClosed pins the acceptance's fail-closed case:
// a consumer that sweeps to seq=0 (an error or no-sweep sentinel) drags the
// heartbeat's applied_seq to 0 even when the other two swept to high seqs.
func TestSweepNotify_SweepToZeroFailsClosed(t *testing.T) {
	n := NewSweepNotifier()

	mustSweep(t, n, BoundaryTLSProxy, 100)
	mustSweep(t, n, BoundaryNFTWriter, 100)
	// ds-dnsgate reports a sweep at seq 0 — an error / no-sweep sentinel.
	if err := n.NotifySwept(BoundaryDNSGate, 0); err != nil {
		t.Fatalf("NotifySwept ds-dnsgate seq 0: %v", err)
	}

	if got := n.AppliedSeq(); got != 0 {
		t.Fatalf("applied_seq with one consumer swept to 0: want 0 (fail-closed), got %d", got)
	}
	_, states := seqByName(n.Boundary())
	if states[BoundaryDNSGate] == hostagentv1.HealthState_HEALTH_STATE_HEALTHY {
		t.Errorf("ds-dnsgate after sweep-to-0: want non-HEALTHY (fail-closed), got HEALTHY")
	}
}

// TestSweepNotify_UnhealthyConsumerDragsMinDown pins that marking a consumer
// DEGRADED/DOWN clamps its contribution to 0 (the host-ward applied_seq drops),
// and that the consumer's last-known swept seq is RETAINED on the boundary list
// for diagnostics but cannot inflate the min (a sick consumer with a high stale
// seq drags the min DOWN, never up — D72 fail-closed).
func TestSweepNotify_UnhealthyConsumerDragsMinDown(t *testing.T) {
	n := NewSweepNotifier()
	mustSweep(t, n, BoundaryTLSProxy, 50)
	mustSweep(t, n, BoundaryNFTWriter, 50)
	mustSweep(t, n, BoundaryDNSGate, 50)
	if got := n.AppliedSeq(); got != 50 {
		t.Fatalf("applied_seq all swept to 50: want 50, got %d", got)
	}

	// ds-tlsproxy loses its connection mid-flight — mark it DOWN.
	if err := n.NotifyUnhealthy(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_DOWN, "uds connection lost"); err != nil {
		t.Fatalf("NotifyUnhealthy ds-tlsproxy: %v", err)
	}
	if got := n.AppliedSeq(); got != 0 {
		t.Fatalf("applied_seq with ds-tlsproxy DOWN: want 0 (fail-closed), got %d", got)
	}
	// The stale seq is retained for diagnostics but cannot inflate the min.
	seqs, states := seqByName(n.Boundary())
	if seqs[BoundaryTLSProxy] != 50 {
		t.Errorf("ds-tlsproxy retained seq for diagnostics: want 50, got %d", seqs[BoundaryTLSProxy])
	}
	if states[BoundaryTLSProxy] != hostagentv1.HealthState_HEALTH_STATE_DOWN {
		t.Errorf("ds-tlsproxy state: want DOWN, got %v", states[BoundaryTLSProxy])
	}

	// A fresh completed sweep restores its contribution and the min recovers.
	mustSweep(t, n, BoundaryTLSProxy, 51)
	if got := n.AppliedSeq(); got != 50 {
		t.Fatalf("applied_seq after ds-tlsproxy re-sweeps to 51 (others at 50): want 50, got %d", got)
	}
}

// TestSweepNotify_RejectsUnrecognizedConsumer pins that a typo'd / non-named
// consumer is rejected at both notify seams — a silently-ignored name would mask
// a never-sweeping consumer behind the missing-consumer clamp forever.
func TestSweepNotify_RejectsUnrecognizedConsumer(t *testing.T) {
	n := NewSweepNotifier()
	if err := n.NotifySwept("ds-typo", 5); err == nil {
		t.Errorf("NotifySwept with unrecognized name: want error, got nil")
	}
	if err := n.NotifyUnhealthy("ds-typo", hostagentv1.HealthState_HEALTH_STATE_DOWN, "x"); err == nil {
		t.Errorf("NotifyUnhealthy with unrecognized name: want error, got nil")
	}
}

// TestSweepNotify_RejectsNonAdvancingAndHealthyMisuse pins two guards: a HEALTHY
// consumer that re-reports a non-advancing swept seq is rejected (sweeps are
// monotone), and NotifyUnhealthy called with HEALTHY is rejected (that is
// NotifySwept's job). The 0 sentinel is always honored as fail-closed.
func TestSweepNotify_RejectsNonAdvancingAndHealthyMisuse(t *testing.T) {
	n := NewSweepNotifier()
	mustSweep(t, n, BoundaryDNSGate, 10)

	if err := n.NotifySwept(BoundaryDNSGate, 10); err == nil {
		t.Errorf("re-report same swept seq for a HEALTHY consumer: want error (non-advancing), got nil")
	}
	if err := n.NotifySwept(BoundaryDNSGate, 9); err == nil {
		t.Errorf("report lower swept seq for a HEALTHY consumer: want error (non-advancing), got nil")
	}
	// The 0 sentinel is always honored (fail-closed), even for a HEALTHY consumer.
	if err := n.NotifySwept(BoundaryDNSGate, 0); err != nil {
		t.Errorf("0 sentinel for a HEALTHY consumer: want honored, got error %v", err)
	}
	if got := n.AppliedSeq(); got != 0 {
		t.Errorf("applied_seq after ds-dnsgate sweeps to 0: want 0, got %d", got)
	}

	if err := n.NotifyUnhealthy(BoundaryTLSProxy, hostagentv1.HealthState_HEALTH_STATE_HEALTHY, "x"); err == nil {
		t.Errorf("NotifyUnhealthy with HEALTHY: want error, got nil")
	}
}

// TestSweepNotify_FullCycle drives the full POL-4 round end to end against the
// real two-phase ApplyCoordinator: a verified snapshot is committed across the
// three mock consumers in admitter-last order, each consumer reports its
// post-commit sweep completion into the registry, and the NEXT heartbeat reports
// the correct min over the three swept seqs. This is the acceptance's full-cycle
// driver (receive snapshot -> apply barrier succeeds -> sweep signals arrive ->
// next heartbeat reports the min).
func TestSweepNotify_FullCycle(t *testing.T) {
	ctx := context.Background()
	log := &eventLog{}

	// Three mock consumers in the FIXED admitter-last commit order: the two
	// enforcers (ds-tlsproxy + nft-writer) before the admitter (ds-dnsgate).
	tlsproxy := &fakeConsumer{name: BoundaryTLSProxy, log: log}
	nft := &fakeConsumer{name: BoundaryNFTWriter, log: log}
	dnsgate := &fakeConsumer{name: BoundaryDNSGate, log: log}

	notifier := NewSweepNotifier()

	// The sweeper is the apply-barrier's post-commit hook: it drives each
	// consumer's post-commit revocation sweep and records the per-consumer swept
	// seq into the registry — the consumers report 5, 6, 5 (so the host-ward min
	// is 5). Sweep returns the HOST swept seq (snap.Seq) only after every consumer
	// has reported, modeling applied_seq advancing ONLY post-sweep (D72).
	sweptByConsumer := map[string]uint64{
		BoundaryTLSProxy:  6,
		BoundaryNFTWriter: 5,
		BoundaryDNSGate:   5,
	}
	sweeper := sweepHookFunc(func(_ context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
		for _, name := range sweepConsumerNames {
			if err := notifier.NotifySwept(name, sweptByConsumer[name]); err != nil {
				return 0, err
			}
		}
		return snap.GetSeq(), nil
	})

	coord, err := NewApplyCoordinator([]ConsumerBarrier{tlsproxy, nft, dnsgate}, sweeper)
	if err != nil {
		t.Fatalf("NewApplyCoordinator: %v", err)
	}

	// Before the apply round, the host has not swept — the heartbeat reports 0.
	if got := BuildHeartbeat(HostState{HostID: "h1", Boundary: notifier.Boundary()}).GetAppliedSeq(); got != 0 {
		t.Fatalf("pre-apply heartbeat applied_seq: want 0, got %d", got)
	}

	// Receive a verified snapshot at seq 6 and drive the full two-phase barrier.
	snap := mkSnapshot(6, "schema_version: 1\nlayer: host\nposture: enforce\n")
	outcome, err := coord.Apply(ctx, snap)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !outcome.Committed {
		t.Fatalf("Apply: want Committed, got %+v", outcome)
	}
	if !outcome.Swept {
		t.Fatalf("Apply: want Swept (sweep hook ran), got %+v", outcome)
	}

	// The NEXT heartbeat folds the per-consumer swept seqs through the frozen
	// AppliedSeq: min(6, 5, 5) = 5.
	hb := BuildHeartbeat(HostState{HostID: "h1", Boundary: notifier.Boundary()})
	if hb.GetAppliedSeq() != 5 {
		t.Fatalf("post-cycle heartbeat applied_seq: want min(6,5,5)=5, got %d", hb.GetAppliedSeq())
	}

	// Sanity: the commit ran admitter-last (ds-dnsgate commits AFTER both
	// enforcers), so the cycle exercised the real make-before-break order.
	events := log.snapshot()
	dnsCommit := firstIndexOf(events, "commit:"+BoundaryDNSGate)
	tlsCommit := firstIndexOf(events, "commit:"+BoundaryTLSProxy)
	nftCommit := firstIndexOf(events, "commit:"+BoundaryNFTWriter)
	if dnsCommit < 0 || tlsCommit < 0 || nftCommit < 0 {
		t.Fatalf("missing commit events: %v", events)
	}
	if dnsCommit < tlsCommit || dnsCommit < nftCommit {
		t.Errorf("admitter ds-dnsgate must commit LAST; events=%v", events)
	}
}

// mustSweep is a NotifySwept that fails the test on error — for the happy-path
// setup steps where a notify must succeed.
func mustSweep(t *testing.T, n *SweepNotifier, consumer string, seq uint64) {
	t.Helper()
	if err := n.NotifySwept(consumer, seq); err != nil {
		t.Fatalf("NotifySwept(%q, %d): %v", consumer, seq, err)
	}
}

// sweepHookFunc adapts a function to the apply.go Sweeper seam so the full-cycle
// test can wire the registry notification as the coordinator's post-commit sweep.
type sweepHookFunc func(ctx context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error)

func (f sweepHookFunc) Sweep(ctx context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	return f(ctx, snap)
}

// mkSnapshot builds a verified PolicySnapshot whose content_hash matches its
// document (the store's identity gate would accept it); the full-cycle test
// hands it straight to the coordinator, which trusts the store-verified bytes.
func mkSnapshot(seq uint64, document string) *boundaryv1.PolicySnapshot {
	h := sha256.Sum256([]byte(document))
	return &boundaryv1.PolicySnapshot{
		Seq:         seq,
		ContentHash: h[:],
		Document:    []byte(document),
	}
}
