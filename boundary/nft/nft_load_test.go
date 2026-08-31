package nft

// NFT-L.a: allow-set churn at fleet scale — expiries stay exact, verdicts
// stay fast, accounting loses nothing.

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// evaluateP99BudgetInMemory is the declared in-memory verdict budget the
// paired benchmark records against (DNS-1 latency budget's kernel-side
// share; the (d) rig owns the real-kernel number).
const evaluateP99BudgetInMemory = 500 * time.Microsecond

// planRef: doc 09 §8 Stage 5 ('allow-set churn under the doc 06 (d) rig') + doc 06 §3(d); DNS-1 latency budget's kernel-side share
func TestLoad_AllowSetChurnManySessions_ExpiryAndAttributionComplete(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}

	const (
		nSessions       = 200
		nAdmits         = 50
		stepDur         = 10 * time.Second
		nSteps          = 94 // covers max expiry 15m30s
		evalsPerStep    = 1064
		evalGoroutines  = 4
		flowsPerStep    = 107
		totalFlowBudget = 10000
	)

	h := newHarness(t)
	rng := rand.New(rand.NewSource(0xC0FFEE))

	// Attach 200 sessions and admit 50 addrs each with randomized TTLs in
	// [60s, 15m]; record the exact expected expiry (clamp identity in-range,
	// +30s grace). TTLs are skewed off 10s multiples so no expiry collides
	// with a step boundary.
	addrs := make([]netip.Addr, nAdmits)
	for j := range addrs {
		addrs[j] = netip.AddrFrom4([4]byte{198, 51, 100, byte(j + 1)})
	}
	specs := make([]SessionSpec, nSessions)
	expiry := make([][]time.Time, nSessions) // [sess][addr]
	t0 := h.clk.Now()
	for i := range specs {
		specs[i] = SessionSpec{
			ID:     SessionID(fmt.Sprintf("churn%03d", i)),
			Iface:  fmt.Sprintf("dstap-churn%03d", i),
			VLANID: uint16(500 + i),
			VMAddr: netip.AddrFrom4([4]byte{10, 80, byte(i / 250), byte(i%250 + 2)}),
			CtMark: uint32(0x10000 + i),
		}
		h.attach(specs[i])
		expiry[i] = make([]time.Time, nAdmits)
		for j, a := range addrs {
			ttlSec := 60 + rng.Intn(840) // [60s, 899s]
			if (ttlSec+30)%10 == 0 {
				ttlSec++ // never exactly on a step boundary
			}
			ttl := time.Duration(ttlSec) * time.Second
			if err := h.writer.Admit(h.ctx, PrincipalDNSGate, specs[i].ID, FamilyIPv4, []netip.Addr{a}, ttl); err != nil {
				t.Fatalf("Admit(%s, %v): %v", specs[i].ID, a, err)
			}
			expiry[i][j] = t0.Add(ttl + graceMargin)
		}
	}

	var (
		staleAccepts   atomic.Int64 // ct-new accept after the entry's ExpiresAt
		prematureDrops atomic.Int64 // ct-new drop before the entry's ExpiresAt
		dropCount      atomic.Int64
		flowsOpened    int
		flowsClosed    int
		evalFailed     atomic.Bool
	)
	durMu := sync.Mutex{}
	var evalDurations []time.Duration

	for step := 0; step < nSteps; step++ {
		now := h.clk.Now()

		// Concurrent verdict churn (run with -race).
		var wg sync.WaitGroup
		for g := 0; g < evalGoroutines; g++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()
				r := rand.New(rand.NewSource(seed))
				local := make([]time.Duration, 0, evalsPerStep/evalGoroutines)
				for k := 0; k < evalsPerStep/evalGoroutines; k++ {
					si := r.Intn(nSessions)
					aj := r.Intn(nAdmits)
					p := Packet{
						InIface: specs[si].Iface,
						Src:     netip.AddrPortFrom(specs[si].VMAddr, uint16(1024+r.Intn(60000))),
						Dst:     netip.AddrPortFrom(addrs[aj], 443),
						Proto:   ProtoTCP,
						CtState: CtStateNew,
					}
					t1 := time.Now()
					dec, err := h.eval.Evaluate(h.ctx, p)
					local = append(local, time.Since(t1))
					if err != nil {
						if evalFailed.CompareAndSwap(false, true) {
							t.Errorf("Evaluate under churn: %v", err)
						}
						return
					}
					live := now.Before(expiry[si][aj])
					switch {
					case dec.Verdict == VerdictAcceptDirect && !live:
						staleAccepts.Add(1)
					case dec.Verdict == VerdictDrop && live:
						prematureDrops.Add(1)
					}
					if dec.Verdict == VerdictDrop {
						dropCount.Add(1)
					}
					if dec.CtMark != specs[si].CtMark {
						if evalFailed.CompareAndSwap(false, true) {
							t.Errorf("verdict mark %#x for %s, want %#x", dec.CtMark, specs[si].ID, specs[si].CtMark)
						}
						return
					}
				}
				durMu.Lock()
				evalDurations = append(evalDurations, local...)
				durMu.Unlock()
			}(int64(step*100 + g))
		}
		wg.Wait()
		if evalFailed.Load() {
			t.Fatalf("evaluation failed during churn step %d", step)
		}

		// Open/close flows against still-live entries.
		r := rand.New(rand.NewSource(int64(step)))
		for f := 0; f < flowsPerStep && flowsOpened < totalFlowBudget; f++ {
			si := r.Intn(nSessions)
			aj := r.Intn(nAdmits)
			if !now.Before(expiry[si][aj]) {
				continue // expired; live coverage only
			}
			p := Packet{
				InIface: specs[si].Iface,
				Src:     netip.AddrPortFrom(specs[si].VMAddr, uint16(1024+r.Intn(60000))),
				Dst:     netip.AddrPortFrom(addrs[aj], 443),
				Proto:   ProtoTCP,
				CtState: CtStateNew,
			}
			fid, dec, err := h.flows.OpenFlow(h.ctx, p)
			if err != nil {
				t.Fatalf("OpenFlow under churn: %v", err)
			}
			if dec.Verdict != VerdictAcceptDirect {
				t.Fatalf("live-entry OpenFlow verdict = %v at step %d, want accept-direct", dec.Verdict, step)
			}
			flowsOpened++
			if err := h.flows.CloseFlow(h.ctx, fid); err != nil {
				t.Fatalf("CloseFlow under churn: %v", err)
			}
			flowsClosed++
		}

		h.clk.Advance(stepDur)
	}

	if n := staleAccepts.Load(); n != 0 {
		t.Errorf("stale accepts (ct-new accept after ExpiresAt) = %d, want 0", n)
	}
	if n := prematureDrops.Load(); n != 0 {
		t.Errorf("premature drops (ct-new drop before ExpiresAt) = %d, want 0", n)
	}

	// Accounting loses nothing: starts==opened, stops==closed, drops==drops,
	// every event with a correct, known session mark.
	markByIface := map[string]uint32{}
	idByIface := map[string]SessionID{}
	for _, s := range specs {
		markByIface[s.Iface] = s.CtMark
		idByIface[s.Iface] = s.ID
	}
	var starts, stops, drops int
	for _, ev := range drainEvents(t, h.events) {
		wantMark, known := markByIface[ev.Iface]
		if !known || ev.CtMark == 0 || ev.CtMark != wantMark || ev.Session != idByIface[ev.Iface] {
			t.Errorf("event with wrong/unknown attribution: %+v", ev)
			continue
		}
		switch ev.Kind {
		case EventFlowStart:
			starts++
		case EventFlowStop:
			stops++
		case EventDrop:
			drops++
		}
	}
	if starts != flowsOpened || stops != flowsClosed {
		t.Errorf("flow events lost: starts=%d/opened=%d stops=%d/closed=%d", starts, flowsOpened, stops, flowsClosed)
	}
	if int64(drops) != dropCount.Load() {
		t.Errorf("drop events lost: events=%d, dropped verdicts=%d", drops, dropCount.Load())
	}

	// Verdict latency stays inside the declared in-memory budget.
	if len(evalDurations) == 0 {
		t.Fatalf("no Evaluate durations recorded")
	}
	sort.Slice(evalDurations, func(i, j int) bool { return evalDurations[i] < evalDurations[j] })
	p99 := evalDurations[len(evalDurations)*99/100]
	if p99 > evaluateP99BudgetInMemory {
		t.Errorf("Evaluate p99 = %v, budget %v", p99, evaluateP99BudgetInMemory)
	}
}

// BenchmarkEvaluate_AdmittedDirect records the in-memory verdict cost the
// NFT-L.a budget constant is checked against.
// planRef: doc 09 §8 Stage 5 + doc 06 §3(d)
func BenchmarkEvaluate_AdmittedDirect(b *testing.B) {
	h := newHarness(b)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 15*time.Minute, x)
	p := vmPkt(sessA, x+":443", ProtoTCP, CtStateNew)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.eval.Evaluate(h.ctx, p); err != nil {
			b.Fatalf("Evaluate: %v", err)
		}
	}
}
