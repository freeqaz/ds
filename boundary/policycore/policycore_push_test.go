package policycore

// POL-4: live fleet-wide policy push — atomic versioned snapshots, one host
// subscriber so the services never skew, offline catch-up by sequence
// number, replay/rollback rejection, and the push-to-enforced latency and
// hot-reload churn budgets for the doc 06 (d) rig.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func pushPolicy(name, version string, posture Posture, allows []AllowRule, blocks []BlockRule) *Policy {
	return &Policy{
		SchemaVersion: SchemaV0,
		Name:          name,
		PackVersion:   version,
		Posture:       posture,
		Allow:         allows,
		Block:         blocks,
		AskDefaults:   AskDefaults{UnlistedDomain: ActionAsk, GrantTTL: 5 * time.Minute},
	}
}

func TestSnapshotApply_AtomicNoMixedVersionDecisions(t *testing.T) {
	// planRef: doc 09 §6 POL-4: atomic versioned snapshot + hot reload.
	// ADVERSARIAL: a reload mid-traffic never yields a decision blending two
	// policy versions.
	const d1, d2 = "d1.example", "d2.example"

	snapV1 := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: pushPolicy(
		"swap-v1", "1.0.0", PostureLocked,
		[]AllowRule{{ID: "alw-d1", Domain: d1}},
		[]BlockRule{{ID: "blk-d2", Domain: d2}},
	)})
	snapV1.Seq = 1
	snapV2 := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: pushPolicy(
		"swap-v2", "2.0.0", PostureLocked,
		[]AllowRule{{ID: "alw-d2", Domain: d2}},
		[]BlockRule{{ID: "blk-d1", Domain: d1}},
	)})
	snapV2.Seq = 2
	if snapV1.PolicyVersion == snapV2.PolicyVersion {
		t.Fatalf("composed snapshots share PolicyVersion %q; the swap would be unobservable", snapV1.PolicyVersion)
	}

	sub := NewHostSubscriber()
	cons := newRecordingConsumer("engine", 0)
	sub.Register(cons)
	src := newFakeSource()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- sub.Run(ctx, src) }()

	src.Push(snapV1)
	waitForReload(t, cons, 1, runErr)

	type obs struct {
		domain  string
		action  Action
		version string
		err     error
	}
	const goroutines = 16
	results := make([][]obs, goroutines)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval := NewEvaluator()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap := cons.snapshot()
				if snap == nil {
					continue
				}
				for _, domain := range []string{d1, d2} {
					dec, err := eval.Evaluate(snap, dnsReq(sessS1, domain), testT0)
					results[i] = append(results[i], obs{domain, dec.Action, dec.Provenance.PolicyVersion, err})
				}
			}
		}(i)
	}

	src.Push(snapV2)
	waitForReload(t, cons, 2, runErr)
	close(stop)
	wg.Wait()

	want := map[string]map[string]Action{
		snapV1.PolicyVersion: {d1: ActionAllow, d2: ActionDeny},
		snapV2.PolicyVersion: {d1: ActionDeny, d2: ActionAllow},
	}
	total := 0
	for i := range results {
		for _, o := range results[i] {
			total++
			if o.err != nil {
				t.Fatalf("evaluation error during the snapshot swap: %v", o.err)
			}
			table, ok := want[o.version]
			if !ok {
				t.Fatalf("decision cites unknown policy version %q — a blended decision", o.version)
			}
			if o.action != table[o.domain] {
				t.Fatalf("mixed-version decision: %s got %q under version %q, want %q",
					o.domain, o.action, o.version, table[o.domain])
			}
		}
	}
	if total == 0 {
		t.Fatalf("no decisions recorded during the swap window")
	}
}

func TestHostSubscriber_OnePerHost_ServicesNeverSkew(t *testing.T) {
	// planRef: doc 09 §6 POL-4 + OQ7: one subscription per host so
	// ds-dnsgate and ds-tlsproxy can never run different policy versions.
	src := newFakeSource()
	sub := NewHostSubscriber()
	consA := newRecordingConsumer("dnsgate", 0)
	consB := newRecordingConsumer("tlsproxy", 2*time.Millisecond) // artificially slowed
	sub.Register(consA)
	sub.Register(consB)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- sub.Run(ctx, src) }()

	for i := 1; i <= 50; i++ {
		snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: pushPolicy(
			"skew", fmt.Sprintf("1.0.%d", i), PostureOpen, nil, nil,
		)})
		snap.Seq = uint64(i)
		src.Push(snap)
		waitForReload(t, consA, uint64(i), runErr)
		waitForReload(t, consB, uint64(i), runErr)

		verA, seqA := consA.CurrentVersion()
		verB, seqB := consB.CurrentVersion()
		if verA != verB || seqA != seqB {
			t.Fatalf("quiesced skew after push %d: dnsgate=(%q,%d) tlsproxy=(%q,%d)", i, verA, seqA, verB, seqB)
		}
	}

	if got := len(src.SubscribeCalls()); got != 1 {
		t.Errorf("source saw %d Subscribe calls; the host subscriber must hold exactly 1 for its lifetime", got)
	}
}

func TestCatchUp_OfflineHostResumesBySequenceNumber(t *testing.T) {
	// planRef: doc 09 §6 POL-4: offline catch-up via snapshot + sequence
	// number — a host that missed pushes converges, in order, no gaps applied.
	src := newFakeSource()
	mkSnap := func(i int) *Snapshot {
		snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: pushPolicy(
			"catchup", fmt.Sprintf("1.0.%d", i), PostureOpen, nil, nil,
		)})
		snap.Seq = uint64(i)
		return snap
	}
	for i := 1; i <= 3; i++ {
		src.Preload(mkSnap(i))
	}

	sub := NewHostSubscriber()
	cons := newRecordingConsumer("engine", 0)
	sub.Register(cons)

	ctx1, cancel1 := context.WithCancel(context.Background())
	runErr1 := make(chan error, 1)
	go func() { runErr1 <- sub.Run(ctx1, src) }()
	waitForReload(t, cons, 3, runErr1)
	cancel1()
	select {
	case <-runErr1:
	case <-time.After(2 * time.Second):
		t.Fatalf("HostSubscriber.Run did not return after context cancellation")
	}

	// The source advances to Seq 10 while the host is offline.
	for i := 4; i <= 10; i++ {
		src.Preload(mkSnap(i))
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	runErr2 := make(chan error, 1)
	go func() { runErr2 <- sub.Run(ctx2, src) }()
	waitForReload(t, cons, 10, runErr2)

	calls := src.SubscribeCalls()
	if len(calls) != 2 {
		t.Fatalf("source saw %d Subscribe calls across the restart, want 2 (got fromSeq list %v)", len(calls), calls)
	}
	if calls[1] != 4 {
		t.Errorf("resume Subscribe fromSeq = %d, want 4 (one past the last applied Seq)", calls[1])
	}

	cur := sub.Current()
	if cur == nil || cur.Seq != 10 {
		t.Fatalf("subscriber Current() = %+v, want Seq 10", cur)
	}
	if _, seq := cons.CurrentVersion(); seq != 10 {
		t.Errorf("consumer reports Seq %d, want 10", seq)
	}

	// Never out of order, never a decrease — strictly increasing reloads.
	seqs := cons.reloadSeqs()
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatalf("reload sequence not strictly increasing: %v", seqs)
		}
	}
	if len(seqs) == 0 || seqs[len(seqs)-1] != 10 {
		t.Errorf("final reload Seq = %v, want last element 10", seqs)
	}
}

func TestPush_StaleOrReplayedSnapshotRejected(t *testing.T) {
	// planRef: doc 09 §6 POL-4 (versioned snapshot semantics). ADVERSARIAL:
	// a replayed or out-of-date snapshot cannot roll back a newer block
	// (e.g. un-block a centrally blocked malicious domain).
	blocking := func(version string) *Policy {
		return pushPolicy("stale-test", version, PostureOpen, nil,
			[]BlockRule{{ID: "blk-evil", Domain: "evil.test"}})
	}
	permissive := func(version string) *Policy {
		return pushPolicy("stale-test", version, PostureOpen, nil, nil)
	}

	snap5 := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: blocking("5.0.0")})
	snap5.Seq = 5
	snap4 := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: permissive("4.0.0")})
	snap4.Seq = 4 // predates the block
	replay5 := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: permissive("5.0.1")})
	replay5.Seq = 5 // forged duplicate Seq trying to un-block evil.test
	// Sentinel push: lets the test deterministically observe that the stale
	// injections were consumed-and-rejected rather than still in flight.
	snap6 := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: blocking("6.0.0")})
	snap6.Seq = 6

	src := newFakeSource()
	sub := NewHostSubscriber()
	cons := newRecordingConsumer("engine", 0)
	sub.Register(cons)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- sub.Run(ctx, src) }()

	src.Push(snap5)
	waitForReload(t, cons, 5, runErr)

	src.Push(snap4)   // stale: predates the block
	src.Push(replay5) // replayed/forged duplicate Seq
	src.Push(snap6)   // sentinel
	waitForReload(t, cons, 6, runErr)

	// The rejection is observable: the stale snapshots never reached Reload.
	seqs := cons.reloadSeqs()
	want := []uint64{5, 6}
	if len(seqs) != len(want) || seqs[0] != want[0] || seqs[1] != want[1] {
		t.Fatalf("consumer Reload seqs = %v, want exactly %v (stale Seq 4 and replayed Seq 5 must be refused)", seqs, want)
	}

	cur := sub.Current()
	if cur == nil || cur.Seq < 5 {
		t.Fatalf("subscriber Current() = %+v; the stale injection rolled the host back", cur)
	}

	// evil.test stays blocked — the replay never un-blocked it.
	dec := mustEvaluate(t, NewEvaluator(), cur, dnsReq(sessS1, "evil.test"), testT0)
	if dec.Action != ActionDeny {
		t.Fatalf("evil.test Action = %q after replay injection, want %q", dec.Action, ActionDeny)
	}
	if dec.Provenance.RuleID != "blk-evil" {
		t.Errorf("Provenance.RuleID = %q, want %q", dec.Provenance.RuleID, "blk-evil")
	}
}

// pushToEnforcedBudgetP99 is the budget constant the (d) rig publishes:
// a centrally pushed malicious-domain block is enforced "within seconds"
// (doc 09 §6 POL-4); strawman ≤2s in-process.
const pushToEnforcedBudgetP99 = 2 * time.Second

func TestPushToEnforced_LatencyBudget(t *testing.T) {
	// planRef: doc 09 §6 POL-4 Done-when: push-to-enforced latency has a
	// number and the (d) rig tracks it; doc 06 §3(d) policy-push fan-out row.
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}

	permissive := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: pushPolicy(
		"fanout", "1.0.0", PostureOpen, nil, nil,
	)})
	permissive.Seq = 1
	blocking := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: pushPolicy(
		"fanout", "2.0.0", PostureOpen, nil,
		[]BlockRule{{ID: "blk-evil", Domain: "evil.test"}},
	)})
	blocking.Seq = 2

	const hosts = 100
	src := newFakeSource()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cons := make([]*recordingConsumer, hosts)
	runErrs := make([]chan error, hosts)
	for i := 0; i < hosts; i++ {
		cons[i] = newRecordingConsumer(fmt.Sprintf("host-%03d", i), 0)
		s := NewHostSubscriber()
		s.Register(cons[i])
		runErrs[i] = make(chan error, 1)
		go func(s HostSubscriber, ch chan error) { ch <- s.Run(ctx, src) }(s, runErrs[i])
	}

	src.Push(permissive)
	for i := 0; i < hosts; i++ {
		waitForReload(t, cons[i], 1, runErrs[i])
	}

	// Steady-state evaluations of evil.test per host; record T1 = first Deny
	// after T0 = the central block push.
	lat := make([]time.Duration, hosts)
	var t0 time.Time
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < hosts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eval := NewEvaluator()
			req := dnsReq(sessS1, "evil.test")
			<-start
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				dec, err := eval.Evaluate(cons[i].snapshot(), req, time.Now())
				if err == nil && dec.Action == ActionDeny {
					lat[i] = time.Since(t0)
					return
				}
			}
			lat[i] = -1 // never converged
		}(i)
	}

	t0 = time.Now()
	close(start)
	src.Push(blocking)
	wg.Wait()

	converged := 0
	for _, d := range lat {
		if d >= 0 {
			converged++
		}
	}
	if converged != hosts {
		t.Fatalf("only %d/%d hosts converged to the pushed block", converged, hosts)
	}
	sorted := append([]time.Duration(nil), lat...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p99 := sorted[hosts*99/100]
	// Benchmark metric for the (d) rig dashboard.
	t.Logf("policy-push fan-out: p99(push-to-enforced) = %v across %d hosts (budget %v)", p99, hosts, pushToEnforcedBudgetP99)
	if p99 > pushToEnforcedBudgetP99 {
		t.Errorf("p99 push-to-enforced latency %v exceeds the budget %v", p99, pushToEnforcedBudgetP99)
	}
}

const (
	// evaluateStallBudget: no Evaluate call may stall behind a reload-wide
	// lock (doc 06 §3(d): the policy engine is on every request path).
	evaluateStallBudget = 100 * time.Millisecond
	// churnThroughputFloor: throughput during churn must stay >= 90% of the
	// no-churn baseline.
	churnThroughputFloor = 0.90
	churnSnapshots       = 200
	churnInterval        = 50 * time.Millisecond // 20 snapshots/s
)

func TestHotReload_NoEvaluationOutageUnderChurn(t *testing.T) {
	// planRef: doc 09 §6 POL-4 hot reload; doc 06 §3(d) proxy-tail-latency
	// concern: continuous snapshot churn never blocks or errors the decision
	// path.
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}

	mkPolicy := func(i int) *Policy {
		return pushPolicy("churn", fmt.Sprintf("1.0.%d", i), PostureStandard,
			[]AllowRule{{ID: "alw-1", Domain: "allowed.example"}},
			[]BlockRule{{ID: "blk-1", Domain: "blocked.example"}})
	}
	reqs := []Request{
		dnsReq(sessS1, "allowed.example"),
		dnsReq(sessS1, "blocked.example"),
		sniReq(sessS1, "allowed.example"),
		httpReq(sessS1, "blocked.example", "GET", "/"),
		dnsReq(sessS1, "unlisted.example"),
	}

	// measure runs 64 evaluator goroutines against snapFn until stop closes;
	// returns total ops, error count, and the max single-call latency.
	measure := func(snapFn func() *Snapshot, stop <-chan struct{}) (ops, errs int64, maxLat time.Duration) {
		var opsN, errsN, maxNs int64
		var wg sync.WaitGroup
		for g := 0; g < 64; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				eval := NewEvaluator()
				for j := g; ; j++ {
					select {
					case <-stop:
						return
					default:
					}
					snap := snapFn()
					if snap == nil {
						continue
					}
					begin := time.Now()
					_, err := eval.Evaluate(snap, reqs[j%len(reqs)], begin)
					elapsed := int64(time.Since(begin))
					atomic.AddInt64(&opsN, 1)
					for {
						cur := atomic.LoadInt64(&maxNs)
						if elapsed <= cur || atomic.CompareAndSwapInt64(&maxNs, cur, elapsed) {
							break
						}
					}
					if err != nil {
						atomic.AddInt64(&errsN, 1)
						return // fail fast: a decision-path outage
					}
				}
			}(g)
		}
		wg.Wait()
		return atomic.LoadInt64(&opsN), atomic.LoadInt64(&errsN), time.Duration(atomic.LoadInt64(&maxNs))
	}

	// Baseline: fixed snapshot, no churn, 1s window.
	base := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: mkPolicy(0)})
	base.Seq = 1
	baseStop := make(chan struct{})
	baseWindow := time.Second
	go func() {
		time.Sleep(baseWindow)
		close(baseStop)
	}()
	baseStart := time.Now()
	baseOps, baseErrs, _ := measure(func() *Snapshot { return base }, baseStop)
	baseElapsed := time.Since(baseStart)
	if baseErrs > 0 {
		t.Fatalf("%d Evaluate errors in the no-churn baseline", baseErrs)
	}
	baseRate := float64(baseOps) / baseElapsed.Seconds()

	// Churn: a live subscriber applying churnSnapshots at 20/s while the
	// same evaluation mix runs.
	src := newFakeSource()
	sub := NewHostSubscriber()
	cons := newRecordingConsumer("engine", 0)
	sub.Register(cons)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- sub.Run(ctx, src) }()

	first := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: mkPolicy(1)})
	first.Seq = 1
	src.Push(first)
	waitForReload(t, cons, 1, runErr)

	churnStop := make(chan struct{})
	var churnOps, churnErrs int64
	var churnMax time.Duration
	measureDone := make(chan struct{})
	churnStart := time.Now()
	go func() {
		churnOps, churnErrs, churnMax = measure(cons.snapshot, churnStop)
		close(measureDone)
	}()

	ticker := time.NewTicker(churnInterval)
	defer ticker.Stop()
	for i := 2; i <= churnSnapshots; i++ {
		<-ticker.C
		select {
		case err := <-runErr:
			close(churnStop)
			<-measureDone
			t.Fatalf("HostSubscriber.Run exited during churn: %v", err)
		case <-measureDone:
			t.Fatalf("evaluation pool died during churn: %d errors", atomic.LoadInt64(&churnErrs))
		default:
		}
		snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: mkPolicy(i)})
		snap.Seq = uint64(i)
		src.Push(snap)
	}
	close(churnStop)
	<-measureDone
	churnElapsed := time.Since(churnStart)

	if churnErrs > 0 {
		t.Fatalf("%d Evaluate errors under snapshot churn; the decision path had an outage", churnErrs)
	}
	if churnMax > evaluateStallBudget {
		t.Errorf("max Evaluate latency under churn = %v, exceeds stall budget %v (reload-wide lock?)", churnMax, evaluateStallBudget)
	}
	churnRate := float64(churnOps) / churnElapsed.Seconds()
	t.Logf("hot-reload churn: baseline %.0f ops/s, churn %.0f ops/s, max latency %v", baseRate, churnRate, churnMax)
	if churnRate < churnThroughputFloor*baseRate {
		t.Errorf("throughput under churn %.0f ops/s < %.0f%% of baseline %.0f ops/s",
			churnRate, churnThroughputFloor*100, baseRate)
	}
}
