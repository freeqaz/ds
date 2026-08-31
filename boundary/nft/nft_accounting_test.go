package nft

// NFT-5: netflow accounting — conntrack start/stop events and nflog drop
// events, all carrying the per-session ct mark keyed by iface, never src.

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// planRef: doc 09 §3 NFT-5 Done-when ('conntrack flow events… emitted carrying the per-session ct mark')
func TestAccounting_FlowStartStopEventsCarrySessionCtMark(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 15*time.Minute, x)

	fid, open := h.openFlow(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	if open.Verdict != VerdictAcceptDirect {
		t.Fatalf("setup flow verdict = %v, want accept-direct", open.Verdict)
	}
	for i := 0; i < 2; i++ {
		if _, err := h.flows.ContinueFlow(h.ctx, fid, 4096, 1<<20); err != nil {
			t.Fatalf("ContinueFlow #%d: %v", i+1, err)
		}
	}
	h.clk.Advance(90 * time.Second)
	if err := h.flows.CloseFlow(h.ctx, fid); err != nil {
		t.Fatalf("CloseFlow: %v", err)
	}

	evs := drainEvents(t, h.events)
	var starts, stops []FlowEvent
	for _, ev := range evs {
		if ev.Dst != ap(x+":443") {
			continue
		}
		switch ev.Kind {
		case EventFlowStart:
			starts = append(starts, ev)
		case EventFlowStop:
			stops = append(stops, ev)
		}
	}
	if len(starts) != 1 || len(stops) != 1 {
		t.Fatalf("want exactly one FlowStart and one FlowStop for the tuple, got %d/%d (all events: %+v)", len(starts), len(stops), evs)
	}
	stop := stops[0]
	if stop.Session != sessA.ID {
		t.Errorf("stop Session = %q, want %q", stop.Session, sessA.ID)
	}
	if stop.CtMark != sessA.CtMark {
		t.Errorf("stop CtMark = %#x, want %#x", stop.CtMark, sessA.CtMark)
	}
	if stop.Iface != sessA.Iface {
		t.Errorf("stop Iface = %q, want %q", stop.Iface, sessA.Iface)
	}
	if want := uint64(2 * (4096 + 1<<20)); stop.Bytes != want {
		t.Errorf("stop Bytes = %d, want %d (sum of both directions)", stop.Bytes, want)
	}
	if stop.Packets == 0 {
		t.Errorf("stop Packets = 0, want > 0")
	}
	if got := stop.End.Sub(stop.Start); got != 90*time.Second {
		t.Errorf("flow duration = %v, want 90s (fake-clock advance)", got)
	}
}

// planRef: doc 09 §3 NFT-5 Done-when ('nflog drop events… land in the Stage-1 local event log') + NFT-1 'drop + log'
func TestAccounting_DropEventsCarryIfaceAttributionAndRule(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)

	drops := []struct {
		name  string
		dst   string
		proto Proto
	}{
		{"default-deny", "203.0.113.50:9999", ProtoTCP},
		{"dot-853", "8.8.8.8:853", ProtoTCP},
		{"quic-udp443", "8.8.8.8:443", ProtoUDP},
	}
	for _, d := range drops {
		dec := h.mustEval(vmPkt(sessA, d.dst, d.proto, CtStateNew))
		requireDrop(t, dec, d.name)
	}

	evs := drainEvents(t, h.events)
	var dropEvents []FlowEvent
	for _, ev := range evs {
		if ev.Kind == EventDrop {
			dropEvents = append(dropEvents, ev)
		}
	}
	if len(dropEvents) != 3 {
		t.Fatalf("want 3 EventDrop events, got %d: %+v", len(dropEvents), dropEvents)
	}
	seenRules := map[string]bool{}
	seenDsts := map[netip.AddrPort]bool{}
	for _, ev := range dropEvents {
		if ev.Session != sessA.ID {
			t.Errorf("drop event Session = %q, want %q", ev.Session, sessA.ID)
		}
		if ev.Iface != sessA.Iface {
			t.Errorf("drop event Iface = %q, want %q", ev.Iface, sessA.Iface)
		}
		if ev.RuleID == "" {
			t.Errorf("drop event missing RuleID (nflog provenance): %+v", ev)
		}
		seenRules[ev.RuleID] = true
		seenDsts[ev.Dst] = true
	}
	if len(seenRules) != 3 {
		t.Errorf("want 3 distinct RuleIDs (default-deny vs DoT vs QUIC rules), got %v", seenRules)
	}
	for _, d := range drops {
		if !seenDsts[ap(d.dst)] {
			t.Errorf("no drop event recorded the original Dst %s", d.dst)
		}
	}
}

// planRef: doc 09 §3 NFT-5 + NFT-2 + LOG-2 (attribution key is the interface); §9 spoofing row's accounting half
func TestAccounting_SpoofedSourceAttributedByIfaceNotSrc(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	h.attach(sessB)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 15*time.Minute, x)

	// Allowed flow from A's iface with Src forged to B's VMAddr.
	forgedFlow := Packet{InIface: sessA.Iface, Src: netip.AddrPortFrom(sessB.VMAddr, 40000), Dst: ap(x + ":443"), Proto: ProtoTCP, CtState: CtStateNew}
	fid, open := h.openFlow(forgedFlow)
	requireAccepted(t, open, "forged-src flow on A's iface to A's admitted IP")
	if err := h.flows.CloseFlow(h.ctx, fid); err != nil {
		t.Fatalf("CloseFlow: %v", err)
	}

	// A drop with Src forged to the host's IP.
	dropPkt := Packet{InIface: sessA.Iface, Src: netip.AddrPortFrom(hostIP, 40000), Dst: ap("203.0.113.50:9999"), Proto: ProtoTCP, CtState: CtStateNew}
	requireDrop(t, h.mustEval(dropPkt), "forged-host-src drop")

	evs := drainEvents(t, h.events)

	// Completeness first: every one of the three events must actually be
	// emitted. Suppressing the drop event for forged-src packets (hiding the
	// adversarial probe from the evidence log) must not pass.
	var starts, stops, dropEvs []FlowEvent
	for _, ev := range evs {
		switch {
		case ev.Kind == EventFlowStart && ev.Dst == ap(x+":443"):
			starts = append(starts, ev)
		case ev.Kind == EventFlowStop && ev.Dst == ap(x+":443"):
			stops = append(stops, ev)
		case ev.Kind == EventDrop && ev.Dst == ap("203.0.113.50:9999"):
			dropEvs = append(dropEvs, ev)
		}
	}
	if len(starts) != 1 || len(stops) != 1 {
		t.Fatalf("want exactly one FlowStart and one FlowStop for the forged-src flow to %s:443, got %d/%d (all events: %+v)", x, len(starts), len(stops), evs)
	}
	if len(dropEvs) != 1 {
		t.Fatalf("want exactly one EventDrop for the forged-host-src probe to 203.0.113.50:9999, got %d — spoofed-src drops must be emitted, not suppressed (all events: %+v)", len(dropEvs), evs)
	}
	drop := dropEvs[0]
	if drop.Session != sessA.ID {
		t.Errorf("forged-src drop event Session = %q, want %q", drop.Session, sessA.ID)
	}
	if drop.CtMark != sessA.CtMark {
		t.Errorf("forged-src drop event CtMark = %#x, want %#x", drop.CtMark, sessA.CtMark)
	}
	if drop.RuleID == "" {
		t.Errorf("forged-src drop event missing RuleID (nflog provenance): %+v", drop)
	}

	for _, ev := range evs {
		if ev.Session != sessA.ID {
			t.Errorf("event attributed to %q, want %q — Src must never be the attribution key: %+v", ev.Session, sessA.ID, ev)
		}
		if ev.CtMark != sessA.CtMark {
			t.Errorf("event CtMark = %#x, want %#x: %+v", ev.CtMark, sessA.CtMark, ev)
		}
		if ev.Session == sessB.ID || ev.CtMark == sessB.CtMark {
			t.Errorf("event attributed to session B via forged Src: %+v", ev)
		}
	}
}

// planRef: doc 09 §3 NFT-5 ('tag each session's flows with a ct mark derived from the session') + LOG-2 100%-attribution bar
func TestAccounting_ConcurrentSessions_DistinctMarksNoCrossTalk(t *testing.T) {
	h := newHarness(t)
	sessions := []SessionSpec{sessA, sessB, sessC}
	const x = "93.184.216.34"
	for _, s := range sessions {
		h.attach(s)
		h.admit(s.ID, 15*time.Minute, x)
	}

	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func(s SessionSpec) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				p := Packet{InIface: s.Iface, Src: netip.AddrPortFrom(s.VMAddr, uint16(41000+i)), Dst: ap(x + ":443"), Proto: ProtoTCP, CtState: CtStateNew}
				fid, _, err := h.flows.OpenFlow(h.ctx, p)
				if err != nil {
					t.Errorf("OpenFlow(%s #%d): %v", s.ID, i, err)
					return
				}
				if _, err := h.flows.ContinueFlow(h.ctx, fid, 100, 200); err != nil {
					t.Errorf("ContinueFlow(%s #%d): %v", s.ID, i, err)
					return
				}
				if err := h.flows.CloseFlow(h.ctx, fid); err != nil {
					t.Errorf("CloseFlow(%s #%d): %v", s.ID, i, err)
					return
				}
				// And one drop per iteration.
				if _, err := h.eval.Evaluate(h.ctx, vmPkt(s, "203.0.113.50:9999", ProtoTCP, CtStateNew)); err != nil {
					t.Errorf("Evaluate drop (%s #%d): %v", s.ID, i, err)
					return
				}
			}
		}(s)
	}
	wg.Wait()
	if t.Failed() {
		return
	}

	markByIface := map[string]uint32{}
	idByIface := map[string]SessionID{}
	for _, s := range sessions {
		markByIface[s.Iface] = s.CtMark
		idByIface[s.Iface] = s.ID
	}

	evs := drainEvents(t, h.events)
	if len(evs) == 0 {
		t.Fatalf("no events recorded for three concurrent sessions")
	}
	for _, ev := range evs {
		wantMark, known := markByIface[ev.Iface]
		if !known {
			t.Errorf("event on unknown iface %q: %+v", ev.Iface, ev)
			continue
		}
		if ev.CtMark == 0 {
			t.Errorf("event with zero ct mark: %+v", ev)
		}
		if ev.CtMark != wantMark {
			t.Errorf("event mark %#x on iface %q, want %#x — partitions by mark and iface must coincide: %+v", ev.CtMark, ev.Iface, wantMark, ev)
		}
		if ev.Session != idByIface[ev.Iface] {
			t.Errorf("event Session %q on iface %q, want %q: %+v", ev.Session, ev.Iface, idByIface[ev.Iface], ev)
		}
	}
}
