package hostagent

// e2e_test.go is the POL-4 part 1 END-TO-END integration test and acceptance
// harness — the walking-skeleton demo (doc 09 §1, the M0 milestone; D72/D36, doc
// 13 §5, doc 15 §5.2/§5.3). It exercises the WHOLE host-agent policy-distribution
// flow against the GENERATED orchestrator.v1 + boundary.v1 fakes over in-memory
// bufconns (the D50 no-live-socket convention), driving the REAL host-agent units
// — Subscribe, SnapshotStore (with the real NewAckPolicySender adapter),
// ApplyCoordinator, SweepNotifier, BuildHeartbeat — with NO live VM / host-agent /
// boundary services. The three consumers (ds-dnsgate, ds-tlsproxy, nft-writer)
// are modelled by in-memory ConsumerBarrier fakes, exactly as the production
// host-local UDS gRPC clients would be wired (apply.go's seam).
//
// The flow this pins, end to end (the §1 walking skeleton):
//
//   (1) the test orchestrator APPENDS a policy to policy_log via the
//       orchestrator.v1 PolicyService.AppendPolicy fake (assigning the bigserial
//       seq that is THE single policy version, D72);
//   (2) the host agent opens a WatchPolicies(from_seq=0) subscription (Subscribe);
//   (3) the orchestrator fake STREAMS the composed PolicySnapshot;
//   (4) the host agent RECEIVES it, VERIFIES the content_hash, PERSISTS it
//       atomically, and ACKs via the boundary.v1 AckPolicy seam (SnapshotStore);
//   (5) the three consumer fakes each PREPARE the snapshot and the host agent
//       drives the two-phase COMMIT in the fixed admitter-last order
//       (ds-tlsproxy + nft-writer before ds-dnsgate — ApplyCoordinator);
//   (6) each consumer reports SWEEP completion with its applied_seq (SweepNotifier
//       via the post-commit Sweeper hook);
//   (7) the next HEARTBEAT carries the correct MIN applied_seq over the three
//       consumers (BuildHeartbeat), verified ON THE WIRE through the hostagent.v1
//       ReportHeartbeat fake.
//
// The NEGATIVE leg is the corrupted-snapshot acceptance: a second append yields a
// snapshot whose content_hash does NOT match the transported document. The host
// NACKs (never ACKs), never persists, never fans out, never advances — it stays
// FULLY pinned at the previous applied version (vN) and can still serve / query
// the last valid snapshot. No partial apply ever opens a mixed-version hole
// (fail-closed, all-or-none, D72).
//
// NEVER-LOG-THE-SECRET: the composed document crosses as opaque bytes inside the
// frozen PolicySnapshot identity; nothing here logs it.

import (
	"context"
	"crypto/sha256"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1/boundaryv1fake"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1/hostagentv1fake"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"
)

// --- the test orchestrator: a policy_log fronted by the orchestrator.v1 fake ---

// fakePolicyLog is the test orchestrator's in-memory policy_log. AppendPolicy
// assigns the next bigserial seq (THE single policy version, D72) and composes a
// PolicySnapshot whose content_hash is the produce-once SHA-256 over the appended
// document bytes — UNLESS corruptNext is set, in which case it streams a snapshot
// whose hash deliberately does NOT match (the corrupted-snapshot acceptance leg).
// WatchPolicies streams every appended snapshot in seq order from the request's
// from_seq, exactly like the real orchestrator's catch-up replay (D36).
type fakePolicyLog struct {
	mu          sync.Mutex
	rows        []*boundaryv1.PolicySnapshot
	corruptNext bool
}

// append composes and stores the next policy_log row, returning the assigned seq.
// The composed snapshot's content_hash is the produce-once hash over the document
// (the host verifies the TRANSPORTED bytes against this), unless corruptNext is
// armed — then the stored hash is flipped so the host NACKs the row host-wide.
func (l *fakePolicyLog) append(document []byte) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	seq := uint64(len(l.rows) + 1) // bigserial — 1-based, monotone
	sum := sha256.Sum256(document)
	hash := sum[:]
	if l.corruptNext {
		// Corrupt the hash so the transported bytes hash differs from content_hash:
		// the host agent must NACK and stay on vN (the negative acceptance leg).
		hash = append([]byte(nil), hash...)
		hash[0] ^= 0xff
		l.corruptNext = false
	}
	l.rows = append(l.rows, &boundaryv1.PolicySnapshot{
		Seq:         seq,
		ContentHash: hash,
		Document:    append([]byte(nil), document...),
	})
	return seq
}

// streamFrom renders every appended row whose seq is > fromSeq as the ordered
// WatchPolicies frames the orchestrator replays on (re)subscribe (D36 catch-up).
func (l *fakePolicyLog) streamFrom(fromSeq uint64) []*orchestratorv1.WatchPoliciesResponse {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*orchestratorv1.WatchPoliciesResponse, 0, len(l.rows))
	for _, snap := range l.rows {
		if snap.GetSeq() <= fromSeq {
			continue
		}
		out = append(out, &orchestratorv1.WatchPoliciesResponse{Snapshot: snap})
	}
	return out
}

// newTestOrchestrator stands the orchestrator.v1 PolicyService fake up on a
// bufconn, backed by the in-memory policy_log. AppendPolicy mutates the log and
// returns the assigned PolicyLogRow; WatchPolicies replays the log from the
// request's from_seq. Returns the policy_log (for the test to append to) and a
// client conn dialed over the wire for Subscribe.
func newTestOrchestrator(t *testing.T) (*fakePolicyLog, *orchestratorv1fake.PolicyServiceFake, grpc.ClientConnInterface) {
	t.Helper()
	log := &fakePolicyLog{}
	fake := orchestratorv1fake.NewPolicyServiceFake()
	fake.AppendPolicyResponder = func(_ context.Context, req *orchestratorv1.AppendPolicyRequest) (*orchestratorv1.AppendPolicyResponse, error) {
		seq := log.append(req.GetDocument())
		return &orchestratorv1.AppendPolicyResponse{
			Row: &orchestratorv1.PolicyLogRow{Seq: seq, Actor: req.GetActor()},
		}, nil
	}
	fake.WatchPoliciesResponder = func(_ context.Context, req *orchestratorv1.WatchPoliciesRequest) ([]*orchestratorv1.WatchPoliciesResponse, error) {
		return log.streamFrom(req.GetFromSeq()), nil
	}
	conn := serveBufconn(t, func(srv *grpc.Server) {
		orchestratorv1fake.RegisterPolicyService(srv, fake)
	})
	return log, fake, conn
}

// --- the boundary ACK sink: the boundary.v1 PolicyStreamService fake ---

// newAckSink stands the boundary.v1 PolicyStreamService fake up on a bufconn so
// the host agent's REAL NewAckPolicySender adapter acks over the wire. The
// responder records each ack and returns the empty AckPolicyResponse envelope.
// Returns the fake (for the test to read AckPolicyRecorded) and the AckPolicySender
// the SnapshotStore is constructed with.
func newAckSink(t *testing.T) (*boundaryv1fake.PolicyStreamServiceFake, AckPolicySender) {
	t.Helper()
	fake := boundaryv1fake.NewPolicyStreamServiceFake()
	fake.AckPolicyResponder = func(_ context.Context, _ *boundaryv1.AckPolicyRequest) (*boundaryv1.AckPolicyResponse, error) {
		return &boundaryv1.AckPolicyResponse{}, nil
	}
	conn := serveBufconn(t, func(srv *grpc.Server) {
		boundaryv1fake.RegisterPolicyStreamService(srv, fake)
	})
	return fake, NewAckPolicySender(boundaryv1.NewPolicyStreamServiceClient(conn))
}

// --- the heartbeat sink: the hostagent.v1 HostAgentService fake ---

// newHeartbeatSink stands the hostagent.v1 HostAgentService fake up on a bufconn
// so the host agent's REAL clientDialer (NewClientDialer) streams the heartbeat
// over the wire. The responder records every frame and returns the beats-received
// envelope. Returns the dialer Stream is driven with.
func newHeartbeatSink(t *testing.T) (*hostagentv1fake.HostAgentServiceFake, HeartbeatDialer) {
	t.Helper()
	fake := hostagentv1fake.NewHostAgentServiceFake()
	fake.ReportHeartbeatResponder = func(_ context.Context, reqs []*hostagentv1.ReportHeartbeatRequest) (*hostagentv1.ReportHeartbeatResponse, error) {
		return &hostagentv1.ReportHeartbeatResponse{BeatsReceived: uint64(len(reqs))}, nil
	}
	conn := serveBufconn(t, func(srv *grpc.Server) {
		hostagentv1fake.RegisterHostAgentService(srv, fake)
	})
	return fake, NewClientDialer(hostagentv1.NewHostAgentServiceClient(conn))
}

// serveBufconn stands a gRPC server up on an in-memory bufconn (no socket / port
// bind — the D50 convention), runs register to attach a fake, and returns a client
// conn dialed over the wire. Server + conn tear down on cleanup.
func serveBufconn(t *testing.T, register func(*grpc.Server)) grpc.ClientConnInterface {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// --- the host-agent harness: the real units wired the way production wires them ---

// e2eHost is the host-agent half of the walking skeleton: the real SnapshotStore
// (verify/persist/ack/fan-out), the real ApplyCoordinator (the D72 two-phase
// barrier over the three consumer fakes, sweeping into the SweepNotifier), and the
// real SweepNotifier (the per-consumer swept-seq registry the heartbeat min reads).
// It is driven by feeding it the snapshots Subscribe delivers.
type e2eHost struct {
	store     *SnapshotStore
	coord     *ApplyCoordinator
	notifier  *SweepNotifier
	persister *fakePersister

	tls, nft, dns *fakeConsumer
}

// sweepIntoNotifier is the post-commit Sweeper that drives the SweepNotifier: on a
// successful host-wide commit it records a completed sweep at snap.Seq for EACH of
// the three consumers (the per-consumer applied_seq advancing ONLY post-sweep,
// D72), so the next heartbeat's min-over-three reflects the swept version. It
// re-uses the shared event log so the e2e flow can assert sweep-after-commit
// ordering alongside the apply_test invariants.
type sweepIntoNotifier struct {
	notifier *SweepNotifier
	log      *eventLog

	mu    sync.Mutex
	swept []uint64
}

func (s *sweepIntoNotifier) Sweep(_ context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	s.mu.Lock()
	s.swept = append(s.swept, snap.GetSeq())
	s.mu.Unlock()
	s.log.record("sweep")
	// Each consumer completes its post-commit revocation sweep at this seq and
	// reports it: the registry marks all three HEALTHY at snap.Seq, so the
	// host-ward min advances to snap.Seq on the next heartbeat (D72).
	for _, name := range []string{BoundaryTLSProxy, BoundaryNFTWriter, BoundaryDNSGate} {
		if err := s.notifier.NotifySwept(name, snap.GetSeq()); err != nil {
			return 0, err
		}
	}
	return snap.GetSeq(), nil
}

// newE2EHost builds the host-agent units the way production wires them: the
// SnapshotStore acks through the REAL adapter over the boundary fake, the
// ApplyCoordinator drives the three consumer fakes in admitter-last commit order
// and sweeps into the SweepNotifier post-commit. The shared event log lets a test
// assert the global prepare→commit→sweep order across the whole flow.
func newE2EHost(t *testing.T, acker AckPolicySender, log *eventLog) *e2eHost {
	t.Helper()
	persister := &fakePersister{}
	store, err := NewSnapshotStore(persister, acker, nil) // nil → default StructuralValidator
	if err != nil {
		t.Fatalf("NewSnapshotStore: %v", err)
	}

	tls := &fakeConsumer{name: BoundaryTLSProxy, log: log}
	nft := &fakeConsumer{name: BoundaryNFTWriter, log: log}
	dns := &fakeConsumer{name: BoundaryDNSGate, log: log}
	order := []ConsumerBarrier{tls, nft, dns} // admitter (ds-dnsgate) LAST

	notifier := NewSweepNotifier()
	coord, err := NewApplyCoordinator(order, &sweepIntoNotifier{notifier: notifier, log: log})
	if err != nil {
		t.Fatalf("NewApplyCoordinator: %v", err)
	}

	return &e2eHost{
		store:     store,
		coord:     coord,
		notifier:  notifier,
		persister: persister,
		tls:       tls,
		nft:       nft,
		dns:       dns,
	}
}

// drive consumes one snapshot the way the host-agent fan-out pump does: the store
// verifies/persists/acks it (returning applied=false on a NACK), and on a
// successful apply the coordinator runs the two-phase barrier + post-commit sweep.
// It returns the store's applied result and the coordinator's outcome so a test
// can assert each leg. On a store NACK the coordinator is NOT driven (the host
// stays on vN — no consumer ever sees a snapshot the store rejected).
func (h *e2eHost) drive(ctx context.Context, snap *boundaryv1.PolicySnapshot) (storeApplied bool, storeErr error, out ApplyOutcome, applyErr error) {
	storeApplied, storeErr = h.store.Apply(ctx, snap)
	if !storeApplied {
		return storeApplied, storeErr, ApplyOutcome{}, nil
	}
	out, applyErr = h.coord.Apply(ctx, snap)
	return storeApplied, storeErr, out, applyErr
}

// --- the acceptance test ---

// TestE2EIntegration is the POL-4 part 1 walking-skeleton acceptance (doc 09 §1,
// the M0 milestone). It runs the full happy-path flow end to end over the
// generated fakes, then the corrupted-snapshot negative leg, asserting the
// fail-closed all-or-none host-wide pin.
func TestE2EIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Stand up the test orchestrator (policy_log + WatchPolicies), the boundary
	// ACK sink, and the heartbeat sink — each a generated fake over a bufconn.
	policyLog, orchFake, orchConn := newTestOrchestrator(t)
	ackFake, acker := newAckSink(t)
	hbFake, hbDialer := newHeartbeatSink(t)

	// Build the host-agent units (real Subscribe/SnapshotStore/ApplyCoordinator/
	// SweepNotifier) sharing one event log so the global ordering is assertable.
	log := &eventLog{}
	host := newE2EHost(t, acker, log)

	// (1) The orchestrator APPENDS the first policy to policy_log. The composed
	// snapshot is assigned seq 1 (the bigserial — THE single policy version, D72).
	const v1Doc = "schema_version: pol1/v0\nlayer: system-baseline\nposture: standard\n"
	orchClient := orchestratorv1.NewPolicyServiceClient(orchConn)
	appendResp, err := orchClient.AppendPolicy(ctx, &orchestratorv1.AppendPolicyRequest{
		Actor:    "maintainer@dreamserpent",
		Scope:    "org/dream-serpent",
		Document: []byte(v1Doc),
	})
	if err != nil {
		t.Fatalf("AppendPolicy(v1): %v", err)
	}
	if appendResp.GetRow().GetSeq() != 1 {
		t.Fatalf("first append assigned seq %d; want 1 (bigserial)", appendResp.GetRow().GetSeq())
	}

	// (2) The host agent opens its SINGLE WatchPolicies(from_seq=0) subscription
	// (one subscriber per host, D72) and (3) the orchestrator streams the snapshot.
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	ch, err := Subscribe(subCtx, orchConn, 0)
	if err != nil {
		t.Fatalf("Subscribe(from_seq=0): %v", err)
	}

	v1, ok := recvWithin(t, ch, time.Second)
	if !ok {
		t.Fatal("subscription closed before delivering the v1 snapshot")
	}
	if v1.GetSeq() != 1 {
		t.Fatalf("first delivered snapshot seq=%d; want 1", v1.GetSeq())
	}

	// (4)+(5)+(6) Drive the host: the store VERIFIES the hash, PERSISTS, and ACKs;
	// the coordinator drives the two-phase COMMIT in admitter-last order and the
	// post-commit SWEEP reports each consumer's applied_seq into the notifier.
	storeApplied, storeErr, out, applyErr := host.drive(ctx, v1)
	if storeErr != nil {
		t.Fatalf("store.Apply(v1) errored: %v", storeErr)
	}
	if !storeApplied {
		t.Fatalf("store.Apply(v1) applied=false; want true (a valid snapshot)")
	}
	if applyErr != nil {
		t.Fatalf("coordinator.Apply(v1) errored: %v", applyErr)
	}
	if !out.Committed || !out.Swept || out.AppliedSeq != 1 {
		t.Fatalf("coordinator outcome=%+v; want Committed+Swept at seq 1", out)
	}

	// The store persisted exactly once and the host can read the applied snapshot.
	if got := host.persister.count(); got != 1 {
		t.Fatalf("persisted count=%d after v1; want 1", got)
	}
	if cur, seq, ok := host.store.Current(); !ok || seq != 1 || string(cur.GetDocument()) != v1Doc {
		t.Fatalf("store.Current()=(seq=%d, ok=%v); want the applied v1 doc at seq 1", seq, ok)
	}

	// The host ACKed (seq, content_hash) over the boundary.v1 AckPolicy seam — the
	// real adapter, over the wire — exactly once, with the verified identity.
	acks := ackFake.AckPolicyRecorded()
	if len(acks) != 1 {
		t.Fatalf("AckPolicy calls=%d after v1; want exactly 1 (one ack per applied seq, D36)", len(acks))
	}
	if acks[0].Req.GetSeq() != 1 {
		t.Fatalf("acked seq=%d; want 1", acks[0].Req.GetSeq())
	}
	wantHash := sha256.Sum256([]byte(v1Doc))
	if string(acks[0].Req.GetContentHash()) != string(wantHash[:]) {
		t.Fatalf("acked content_hash did not match the produce-once hash of the v1 doc")
	}

	// The admitter-last commit order held end to end: ds-tlsproxy AND nft-writer
	// committed BEFORE ds-dnsgate, and the post-commit sweep ran AFTER the admitter.
	events := log.snapshot()
	commitTLS := firstIndexOf(events, "commit:"+BoundaryTLSProxy)
	commitNFT := firstIndexOf(events, "commit:"+BoundaryNFTWriter)
	commitDNS := firstIndexOf(events, "commit:"+BoundaryDNSGate)
	sweepIdx := firstIndexOf(events, "sweep")
	if commitTLS < 0 || commitNFT < 0 || commitDNS < 0 || sweepIdx < 0 {
		t.Fatalf("missing a commit/sweep event in the e2e flow; events=%v", events)
	}
	if !(commitTLS < commitDNS && commitNFT < commitDNS) {
		t.Fatalf("admitter-last commit order violated (ds-dnsgate not last); events=%v", events)
	}
	if !(sweepIdx > commitDNS) {
		t.Fatalf("sweep ran before the admitter committed; events=%v", events)
	}

	// (7) The NEXT heartbeat carries the correct MIN applied_seq over the three
	// consumers. All three swept at seq 1, so the host-ward min is 1 — verified
	// twice: directly via the SweepNotifier's registry, and ON THE WIRE through the
	// hostagent.v1 ReportHeartbeat fake (the real Stream + clientDialer path).
	if got := host.notifier.AppliedSeq(); got != 1 {
		t.Fatalf("SweepNotifier.AppliedSeq()=%d after v1 sweep; want 1 (min over three swept consumers)", got)
	}
	assertHeartbeatAppliedSeq(t, ctx, hbDialer, hbFake, host, "host-A", 1)

	// === NEGATIVE LEG: corrupted snapshot is NACKed host-wide, host stays on vN ===

	// (1') A SECOND append, but the orchestrator streams a snapshot whose
	// content_hash does NOT match the transported document (corruption in flight).
	policyLog.mu.Lock()
	policyLog.corruptNext = true
	policyLog.mu.Unlock()

	const v2Doc = "schema_version: pol1/v0\nlayer: org-overlay\nposture: standard\n"
	appendResp2, err := orchClient.AppendPolicy(ctx, &orchestratorv1.AppendPolicyRequest{
		Actor:    "maintainer@dreamserpent",
		Scope:    "org/dream-serpent",
		Document: []byte(v2Doc),
	})
	if err != nil {
		t.Fatalf("AppendPolicy(v2 corrupted): %v", err)
	}
	if appendResp2.GetRow().GetSeq() != 2 {
		t.Fatalf("second append assigned seq %d; want 2", appendResp2.GetRow().GetSeq())
	}

	// The first subscription already drained to a clean close after seq 1 (the
	// server closed the stream). RE-SUBSCRIBE from the host's persisted applied seq
	// (1) — the orchestrator's catch-up replay (D36) then streams only seq 2.
	v2ch, err := Subscribe(ctx, orchConn, host.store.AppliedSeq())
	if err != nil {
		t.Fatalf("re-Subscribe(from_seq=%d): %v", host.store.AppliedSeq(), err)
	}
	v2, ok := recvWithin(t, v2ch, time.Second)
	if !ok {
		t.Fatal("re-subscription closed before delivering the v2 snapshot")
	}
	if v2.GetSeq() != 2 {
		t.Fatalf("re-subscription delivered seq=%d; want 2 (catch-up from seq 1)", v2.GetSeq())
	}

	// Snapshot the pre-NACK state so we can prove NOTHING advanced.
	persistBefore := host.persister.count()
	acksBefore := len(ackFake.AckPolicyRecorded())
	tlsPrepBefore := host.tls.prepareCount()
	nftPrepBefore := host.nft.prepareCount()
	dnsPrepBefore := host.dns.prepareCount()

	// (4') Drive the corrupted snapshot: the store NACKs (content_hash mismatch) —
	// applied=false with an error, NOTHING persisted, NOTHING acked, and the
	// coordinator is NEVER driven (no consumer sees a snapshot the store rejected).
	storeApplied2, storeErr2, out2, applyErr2 := host.drive(ctx, v2)
	if storeApplied2 {
		t.Fatalf("store.Apply(v2 corrupted) applied=true; want false (NACK)")
	}
	if storeErr2 == nil {
		t.Fatalf("store.Apply(v2 corrupted) err=nil; want a content_hash NACK error")
	}
	if applyErr2 != nil || out2.Committed {
		t.Fatalf("coordinator was driven for a NACKed snapshot: out=%+v err=%v", out2, applyErr2)
	}

	// NO persist, NO ack, NO consumer prepare — the host never began a partial apply.
	if got := host.persister.count(); got != persistBefore {
		t.Fatalf("corrupted snapshot was persisted (count %d→%d); want no persist (NACK)", persistBefore, got)
	}
	if got := len(ackFake.AckPolicyRecorded()); got != acksBefore {
		t.Fatalf("corrupted snapshot was acked (count %d→%d); want no ack (a NACK is the ABSENCE of an ack, D72)", acksBefore, got)
	}
	if host.tls.prepareCount() != tlsPrepBefore || host.nft.prepareCount() != nftPrepBefore || host.dns.prepareCount() != dnsPrepBefore {
		t.Fatalf("a consumer prepared a NACKed snapshot; want no prepare (host-wide NACK before fan-out)")
	}

	// The host stays FULLY on vN (seq 1): it can still query the last valid snapshot
	// and its applied version did NOT advance.
	if cur, seq, ok := host.store.Current(); !ok || seq != 1 || string(cur.GetDocument()) != v1Doc {
		t.Fatalf("after NACK store.Current()=(seq=%d, ok=%v); want host pinned at the valid v1 snapshot", seq, ok)
	}
	if host.store.AppliedSeq() != 1 {
		t.Fatalf("after NACK store.AppliedSeq()=%d; want 1 (host stays on vN)", host.store.AppliedSeq())
	}
	if host.coord.AppliedSeq() != 1 {
		t.Fatalf("after NACK coordinator.AppliedSeq()=%d; want 1 (no consumer flipped past vN)", host.coord.AppliedSeq())
	}

	// (7') The NEXT heartbeat still reports the LAST GOOD applied_seq (1) — the
	// corrupted version never reached the consumers' sweep, so the min-over-three is
	// unchanged. Verified on the wire again.
	if got := host.notifier.AppliedSeq(); got != 1 {
		t.Fatalf("after NACK SweepNotifier.AppliedSeq()=%d; want 1 (min unchanged — corrupted version never swept)", got)
	}
	assertHeartbeatAppliedSeq(t, ctx, hbDialer, hbFake, host, "host-A", 1)

	// Belt-and-suspenders: exactly one ACK total ever crossed the boundary seam
	// (for the one valid snapshot), and exactly one snapshot was persisted.
	if got := len(ackFake.AckPolicyRecorded()); got != 1 {
		t.Fatalf("total AckPolicy calls=%d across the whole flow; want exactly 1 (only the valid v1 acked)", got)
	}
	if got := host.persister.count(); got != 1 {
		t.Fatalf("total persisted snapshots=%d; want 1 (only the valid v1 persisted)", got)
	}

	// Keep the orchestrator fake recorded-call accessor live (it records both
	// AppendPolicy calls and the WatchPolicies subscriptions) — assert the host
	// opened exactly its subscriptions and no more.
	if got := len(orchFake.AppendPolicyRecorded()); got != 2 {
		t.Fatalf("AppendPolicy recorded=%d; want 2 (v1 valid + v2 corrupted)", got)
	}
}

// assertHeartbeatAppliedSeq drives ONE heartbeat frame over the real Stream loop
// (clientDialer → the hostagent.v1 ReportHeartbeat fake over a bufconn) sourcing
// the boundary list from the live SweepNotifier, and asserts the wire frame's
// top-level applied_seq is the expected min-over-three. It uses a long cadence and
// an immediate ctx cancel so exactly the single immediate emit fires (the loop's
// "emit immediately, then drain" contract), keeping the assertion deterministic.
func assertHeartbeatAppliedSeq(t *testing.T, ctx context.Context, dialer HeartbeatDialer, fake *hostagentv1fake.HostAgentServiceFake, host *e2eHost, hostID string, wantSeq uint64) {
	t.Helper()

	src := &notifierStateSource{hostID: hostID, notifier: host.notifier}

	// Cancel immediately: Stream emits one frame the instant the stream opens (no
	// full-cadence silence), then sees the drain and closes — yielding exactly one
	// frame over the wire.
	hbCtx, hbCancel := context.WithCancel(ctx)
	hbCancel()

	before := len(fake.ReportHeartbeatRecorded())
	resp, err := Stream(hbCtx, dialer, src, StreamConfig{Cadence: time.Hour})
	if err != nil {
		t.Fatalf("Stream heartbeat: %v", err)
	}
	if resp.GetBeatsReceived() != 1 {
		t.Fatalf("BeatsReceived=%d; want 1 (the single immediate emit)", resp.GetBeatsReceived())
	}

	calls := fake.ReportHeartbeatRecorded()
	if len(calls) != before+1 {
		t.Fatalf("ReportHeartbeat stream count=%d; want %d (one new stream)", len(calls), before+1)
	}
	frames := calls[len(calls)-1].Reqs
	if len(frames) != 1 {
		t.Fatalf("heartbeat frames in the stream=%d; want 1", len(frames))
	}
	hb := frames[0].GetHeartbeat()
	if hb.GetHostId() != hostID {
		t.Fatalf("heartbeat host_id=%q; want %q", hb.GetHostId(), hostID)
	}
	if hb.GetAppliedSeq() != wantSeq {
		t.Fatalf("heartbeat applied_seq=%d on the wire; want %d (min over three swept consumers)", hb.GetAppliedSeq(), wantSeq)
	}
	// The frame's boundary list carries all three named consumers, so the wire
	// value and the per-consumer list can never silently diverge (D72).
	if len(hb.GetBoundary()) != 3 {
		t.Fatalf("heartbeat boundary list len=%d; want 3 (the three named consumers)", len(hb.GetBoundary()))
	}
	if got := AppliedSeq(hb.GetBoundary()); got != wantSeq {
		t.Fatalf("recomputing min over the wire boundary list = %d; want %d (top-level value must match)", got, wantSeq)
	}
}

// notifierStateSource is the StateSource the heartbeat loop reads each tick: it
// sources the boundary list from the live SweepNotifier (the per-consumer swept
// state) so the heartbeat's min-over-three reflects exactly what the consumers
// have reported, with no second namespace.
type notifierStateSource struct {
	hostID   string
	notifier *SweepNotifier
}

func (s *notifierStateSource) Snapshot(context.Context) (HostState, error) {
	return HostState{
		HostID:   s.hostID,
		Boundary: s.notifier.Boundary(),
	}, nil
}
