package flowlog

// LOG-3 — Collect and ship: disk-bounded spool with visible overflow,
// outage recovery without loss, hosting-tier routing (D19), queryable
// off-box session story, and the Stage-5 ingest budget.

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// planRef: doc 09 §7 LOG-3 ("spools to disk-bounded local storage")
func TestSpool_DiskBoundNeverExceeded_LossIsVisible(t *testing.T) {
	const bound = int64(1 << 20) // 1 MiB budget
	dir := t.TempDir()
	spool := NewSpool(dir, bound)
	if got := spool.BoundBytes(); got != bound {
		t.Fatalf("BoundBytes() = %d, want the configured bound %d", got, bound)
	}

	refA := mkRef("sess-a")
	pad := strings.Repeat("x", 4096) // ≥4 KiB per event => 2560 events ≈ 10x the bound
	const n = 2560
	for i := 0; i < n; i++ {
		ev := validFlowRecord(refA, uint32(i), t0.Add(time.Duration(i)*time.Millisecond))
		ev.AdmittingDomain = pad
		mustAppend(t, spool, ev)
		// Property checked per-iteration: the bound is never exceeded.
		if u, b := spool.UsageBytes(), spool.BoundBytes(); u > b {
			t.Fatalf("UsageBytes %d exceeded BoundBytes %d after append #%d", u, b, i)
		}
		// "Disk-bounded" is a property of the DISK, not of the spool's
		// self-report: measure the spool dir directly. An implementation
		// writing 10x the bound while returning UsageBytes()==0 dies here.
		du := diskBytesUnder(t, dir)
		if du > bound {
			t.Fatalf("measured on-disk spool usage %d exceeded the bound %d after append #%d", du, bound, i)
		}
		if reported := spool.UsageBytes(); du > reported {
			t.Fatalf("UsageBytes() under-reports the disk: reported %d, measured %d on disk after append #%d", reported, du, i)
		}
	}
	if du := diskBytesUnder(t, dir); du == 0 {
		t.Fatalf("spool persisted nothing under %s after %d appends — the disk-bound property was never exercised", dir, n)
	}

	// Drain the surviving stream.
	var survivingSeqs []int
	dropped := 0
	overflowMarkers := 0
	for {
		batch, ack, err := spool.ReadBatch(bg, 256)
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		if len(batch) == 0 {
			break
		}
		for _, ev := range batch {
			switch e := ev.(type) {
			case FlowRecord:
				survivingSeqs = append(survivingSeqs, int(e.CtMark))
			case SpoolOverflow:
				overflowMarkers++
				dropped += e.Dropped
			default:
				t.Errorf("unexpected event type in spool: %T", ev)
			}
		}
		if ack == nil {
			t.Fatalf("ReadBatch returned nil ack")
		}
		if err := ack(); err != nil {
			t.Fatalf("ack: %v", err)
		}
	}

	if overflowMarkers == 0 || dropped <= 0 {
		t.Fatalf("shedding must be visible, not silent: want >=1 SpoolOverflow marker with a dropped-count, got %d markers / %d dropped", overflowMarkers, dropped)
	}
	if len(survivingSeqs)+dropped != n {
		t.Errorf("loss accounting broken: %d survivors + %d dropped != %d appended", len(survivingSeqs), dropped, n)
	}
	if len(survivingSeqs) == 0 {
		t.Fatalf("no events survived a 10x-bound append stream")
	}
	// Drop-oldest: survivors are the contiguous newest tail.
	for i := 1; i < len(survivingSeqs); i++ {
		if survivingSeqs[i] != survivingSeqs[i-1]+1 {
			t.Fatalf("survivors are not contiguous at index %d (%d -> %d): drop-oldest violated", i, survivingSeqs[i-1], survivingSeqs[i])
		}
	}
	if last := survivingSeqs[len(survivingSeqs)-1]; last != n-1 {
		t.Errorf("newest event (seq %d) must survive drop-oldest shedding; newest survivor is %d", n-1, last)
	}
}

// planRef: doc 09 §7 LOG-3 ("ships off-box through the log-pipeline contract")
func TestShip_SinkOutage_RecoverWithoutLossWithinBound(t *testing.T) {
	sink := &fakeSink{}
	sink.setFailing(true) // scripted: fail all Receive for a period

	spool := NewSpool(t.TempDir(), 64<<20)
	router := NewRouter(RouterConfig{Default: "primary", CustomerSide: "primary"})
	shipper := NewShipper(spool, router, map[SinkID]Sink{"primary": sink}, TierSaaS)

	refA := mkRef("sess-a")
	mk := func(i int) Event {
		return validFlowRecord(refA, uint32(i), t0.Add(time.Duration(i)*time.Millisecond))
	}

	for i := 0; i < 250; i++ {
		mustAppend(t, spool, mk(i))
	}
	_ = shipper.Ship(bg) // outage: a failed ship is tolerated, loss is not
	if got := len(sink.allEvents()); got != 0 {
		t.Fatalf("sink accepted %d events during the scripted outage", got)
	}

	sink.setFailing(false) // recovery
	for i := 250; i < 500; i++ {
		mustAppend(t, spool, mk(i))
	}
	mustShip(t, shipper)
	mustShip(t, shipper) // un-acked batches must be re-shipped until acked

	// Duplicate re-send of an already-delivered batch must be tolerated by
	// event identity (idempotent receive).
	if first := sink.firstBatch(); first != nil {
		if err := sink.Receive(bg, first); err != nil {
			t.Fatalf("duplicate Receive must be tolerated: %v", err)
		}
	}

	events := sink.allEvents()
	if len(events) != 500 {
		t.Fatalf("an outage shorter than spool capacity must lose nothing and dupes must dedupe: queryable story has %d events, want exactly 500", len(events))
	}
	for i, ev := range events {
		fr, ok := ev.(FlowRecord)
		if !ok {
			t.Fatalf("unexpected event type at %d: %T", i, ev)
		}
		if int(fr.CtMark) != i {
			t.Fatalf("delivery resumed out of ingest order at %d: got seq %d", i, fr.CtMark)
		}
	}
}

// planRef: doc 09 §7 LOG-3 ("at-least-once + ack semantics": un-acked batches are re-shipped; duplicates tolerated by event identity)
func TestShip_UnackedBatch_IsReshipped_DuplicateObservedAndDeduped(t *testing.T) {
	sink := &fakeSink{}
	// The first ack is swallowed (shipper crash between a successful
	// Sink.Receive and the ack): the delivered batch stays un-acked.
	spool := &ackDroppingSpool{Spool: NewSpool(t.TempDir(), 8<<20), dropN: 1}
	router := NewRouter(RouterConfig{Default: "primary", CustomerSide: "primary"})
	shipper := NewShipper(spool, router, map[SinkID]Sink{"primary": sink}, TierSaaS)

	refA := mkRef("sess-a")
	const n = 40
	for i := 0; i < n; i++ {
		mustAppend(t, spool, validFlowRecord(refA, uint32(i), t0.Add(time.Duration(i)*time.Millisecond)))
	}

	// First ship: Receive SUCCEEDS but the ack never lands.
	mustShip(t, shipper)
	if sink.receiveCalls() == 0 {
		t.Fatalf("first ship delivered nothing — the delivered-but-un-acked scenario was not exercised")
	}

	// Second ship: the un-acked batch MUST be re-shipped. Observed shipper
	// behavior: at least one event arrives in two distinct Receive batches.
	mustShip(t, shipper)

	occurrences := map[uint32]int{}
	for _, batch := range sink.allBatches() {
		for _, ev := range batch {
			fr, ok := ev.(FlowRecord)
			if !ok {
				t.Fatalf("unexpected event type in shipped batch: %T", ev)
			}
			occurrences[fr.CtMark]++
		}
	}
	reshipped := 0
	for seq := uint32(0); seq < n; seq++ {
		if occurrences[seq] == 0 {
			t.Errorf("event seq %d was never delivered — un-acked data was lost, not re-shipped", seq)
		}
		if occurrences[seq] > 1 {
			reshipped++
		}
	}
	if reshipped == 0 {
		t.Fatalf("no event was observed in more than one Receive batch — the un-acked batch was not re-shipped (at-least-once violated)")
	}

	// Duplicate tolerance by event identity: despite the OBSERVED duplicate
	// delivery, the queryable story holds each event exactly once, in order.
	events := sink.allEvents()
	if len(events) != n {
		t.Fatalf("queryable story has %d events, want exactly %d after identity dedupe of the re-shipped batch", len(events), n)
	}
	for i, ev := range events {
		if fr := ev.(FlowRecord); int(fr.CtMark) != i {
			t.Fatalf("re-ship broke ingest order at index %d: got seq %d", i, fr.CtMark)
		}
	}
}

// planRef: doc 09 §7 LOG-3 ("what ships where follows the hosting tier (D19) — on-prem keeps metadata customer-side") [ADVERSARIAL]
func TestRoute_OnPremTier_MetadataNeverLeavesCustomerSide(t *testing.T) {
	refA := mkRef("sess-a")
	evs := []Event{
		validFlowRecord(refA, 1, t0),
		validDnsEvent(refA, "registry.npmjs.org", t0),
		validHttpEvent(refA, "registry.npmjs.org", t0),
		validDecision(refA, VerdictAllow, "POL-2.allow.npm", "registry.npmjs.org", t0),
		validCredUse(refA, testFingerprint, t0),
	}

	// Adversarial config: the VENDOR sink is the configured global default.
	router := NewRouter(RouterConfig{Default: "vendor", CustomerSide: "customer"})

	for _, ev := range evs {
		ev := ev
		t.Run(fmt.Sprintf("onprem_routes_customer_side/%T", ev), func(t *testing.T) {
			id, err := router.Route(ev, TierOnPrem)
			if err != nil {
				t.Fatalf("Route(TierOnPrem): %v", err)
			}
			if id != "customer" {
				t.Fatalf("on-prem %T routed to %q — metadata must stay customer-side even with a vendor default", ev, id)
			}
		})
		t.Run(fmt.Sprintf("saas_follows_default/%T", ev), func(t *testing.T) {
			id, err := router.Route(ev, TierSaaS)
			if err != nil {
				t.Fatalf("Route(TierSaaS): %v", err)
			}
			if id != "vendor" {
				t.Errorf("SaaS routing must follow the configured default, got %q", id)
			}
		})
	}

	t.Run("unroutable_tier_errors_never_falls_through_to_vendor", func(t *testing.T) {
		id, err := router.Route(evs[0], HostingTier(42))
		if !errors.Is(err, ErrUnroutableTier) {
			t.Fatalf("an unroutable tier must return ErrUnroutableTier, got id=%q err=%v", id, err)
		}
		if id == "vendor" {
			t.Errorf("unroutable tier fell through to the vendor sink")
		}
	})

	t.Run("onprem_shipper_never_calls_vendor_sink", func(t *testing.T) {
		vendor := &fakeSink{}
		customer := &fakeSink{}
		spool := NewSpool(t.TempDir(), 8<<20)
		shipper := NewShipper(spool, router, map[SinkID]Sink{"vendor": vendor, "customer": customer}, TierOnPrem)
		for _, ev := range evs {
			mustAppend(t, spool, ev)
		}
		mustShip(t, shipper)
		if got := vendor.receiveCalls(); got != 0 {
			t.Fatalf("vendor sink Receive called %d times under TierOnPrem — recorded-calls must be zero for every event type", got)
		}
		if got := len(customer.allEvents()); got != len(evs) {
			t.Fatalf("customer-side sink holds %d/%d on-prem events", got, len(evs))
		}
	})
}

// planRef: doc 09 §7 LOG-3 Done-when ("a session's complete network story ... queryable off-box minutes after it happened")
func TestShip_SessionNetworkStory_QueryableOffBox(t *testing.T) {
	refA := mkRef("sess-a")
	sink := &fakeSink{}
	spool := NewSpool(t.TempDir(), 8<<20)
	col := NewCollector(spool)
	router := NewRouter(RouterConfig{Default: "story", CustomerSide: "story"})
	shipper := NewShipper(spool, router, map[SinkID]Sink{"story": sink}, TierSaaS)

	// A scripted full session, in event-time order; includes one drop, an
	// allow + a deny decision, and one credential use; then teardown.
	dns := validDnsEvent(refA, "registry.npmjs.org", t0.Add(1*time.Second))
	flowOK := validFlowRecord(refA, 1, t0.Add(2*time.Second))
	httpEv := validHttpEvent(refA, "registry.npmjs.org", t0.Add(3*time.Second))
	allowDec := validDecision(refA, VerdictAllow, "POL-2.allow.npm", "registry.npmjs.org", t0.Add(4*time.Second))
	denyDec := validDecision(refA, VerdictDeny, "POL-1.deny.default", "evil.example", t0.Add(5*time.Second))
	cred := validCredUse(refA, testFingerprint, t0.Add(6*time.Second))
	flowDrop := validFlowRecord(refA, 2, t0.Add(7*time.Second))
	flowDrop.Verdict = FlowDropped
	story := []Event{dns, flowOK, httpEv, allowDec, denyDec, cred, flowDrop}

	startWall := time.Now()
	for _, ev := range story {
		mustIngest(t, col, ev)
	}
	mustShip(t, shipper)

	got, err := sink.Query(bg, StoryQuery{SessionID: refA.SessionID, Window: Window{From: t0, To: t0.Add(time.Hour)}})
	if err != nil {
		t.Fatalf("Sink.Query: %v", err)
	}
	// Wall-clock latency is the load-category half of the Done-when: skip it
	// under -short so a starved CI runner cannot flake the contract
	// assertions below (conventions: deterministic time in contract tests).
	if !testing.Short() {
		if elapsed := time.Since(startWall); elapsed > StoryQueryLatencyBudget {
			t.Errorf("story took %v to become queryable off-box, budget %v", elapsed, StoryQueryLatencyBudget)
		}
	}
	if len(got) != len(story) {
		t.Fatalf("story incomplete or padded: got %d events, want exactly %d (no gaps, no extras)", len(got), len(story))
	}
	for i := range story {
		if !reflect.DeepEqual(got[i], story[i]) {
			t.Errorf("story out of time order or altered at index %d:\n got: %#v\nwant: %#v", i, got[i], story[i])
		}
	}

	foundDenial := false
	for _, ev := range got {
		if d, ok := ev.(PolicyDecision); ok && d.Verdict == VerdictDeny {
			foundDenial = true
			if d.RuleID == "" || d.PolicyLayer == "" || d.PolicyVersion == "" {
				t.Errorf("the denial in the story lacks rule provenance: %+v", d)
			}
		}
	}
	if !foundDenial {
		t.Errorf("the story must include the denial with its rule provenance")
	}
}

// planRef: doc 09 §7 LOG-3 + §8 Stage 5 (doc 06 §3(d) rig) [load]
func TestLoad_CollectorFanout_P99UnderBudgetNoSheddingBelowBound(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	// Pin the budget constant: the Stage-5 strawman is 5ms.
	if IngestP99Budget != 5*time.Millisecond {
		t.Fatalf("IngestP99Budget drifted from the pinned strawman 5ms: %v", IngestP99Budget)
	}

	spool := NewSpool(t.TempDir(), 256<<20)
	col := NewCollector(spool)

	const producers = 100
	const perProducer = 50

	var mu sync.Mutex
	var latencies []time.Duration
	ingestedPerSession := map[string]int{}
	errCount := 0
	var firstErr error

	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			ref := mkRef(fmt.Sprintf("sess-%03d", p))
			for i := 0; i < perProducer; i++ {
				var ev Event
				switch i % 4 { // flow-heavy mix with DNS/HTTP interleave
				case 0:
					ev = validDnsEvent(ref, "registry.npmjs.org", t0.Add(time.Duration(i)*time.Millisecond))
				case 1:
					ev = validHttpEvent(ref, "registry.npmjs.org", t0.Add(time.Duration(i)*time.Millisecond))
				default:
					ev = validFlowRecord(ref, uint32(p*perProducer+i), t0.Add(time.Duration(i)*time.Millisecond))
				}
				begin := time.Now()
				err := col.Ingest(bg, ev)
				d := time.Since(begin)
				mu.Lock()
				latencies = append(latencies, d)
				if err != nil {
					errCount++
					if firstErr == nil {
						firstErr = err
					}
				} else {
					ingestedPerSession[ref.SessionID]++
				}
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	if errCount > 0 {
		t.Fatalf("Ingest failed %d/%d times with a healthy sink and an under-bound spool: %v", errCount, producers*perProducer, firstErr)
	}

	// No shedding below the bound, and attribution holds under concurrency.
	drainedPerSession := map[string]int{}
	for {
		batch, ack, err := spool.ReadBatch(bg, 1024)
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		if len(batch) == 0 {
			break
		}
		for _, ev := range batch {
			if _, isOverflow := ev.(SpoolOverflow); isOverflow {
				t.Fatalf("SpoolOverflow marker while under the spool bound — shedding is not allowed below the bound")
			}
			drainedPerSession[ev.Ref().SessionID]++
		}
		if err := ack(); err != nil {
			t.Fatalf("ack: %v", err)
		}
	}
	if !reflect.DeepEqual(drainedPerSession, ingestedPerSession) {
		t.Errorf("attribution under load is not 100%%: drained-per-session != ingested-per-session\n got: %v\nwant: %v", drainedPerSession, ingestedPerSession)
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p99 := latencies[len(latencies)*99/100]
	if p99 > IngestP99Budget {
		t.Errorf("p99 Ingest latency %v exceeds the budget %v", p99, IngestP99Budget)
	}
}
