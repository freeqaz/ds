package flowlog

// LOG-2 — Attribution: ct mark + iifname are the only attribution keys,
// the DNS-2 stream provides the admitting-domain join, unknowns are never
// guessed, and a multi-VM host attributes 100% of generated flows.

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// planRef: doc 09 §7 LOG-2 (resolves doc 03 OQ6: iifname convention + ct mark)
func TestAttribute_KernelFlow_ByCtMarkAndIface(t *testing.T) {
	reg := NewSessionRegistry()
	idx := NewAdmissionIndex()
	attr := NewAttributor(reg, idx)

	refA := mkRef("sess-a")
	refB := mkRef("sess-b")
	mustRegister(t, reg, refA, 0xA001, refA.Iface)
	mustRegister(t, reg, refB, 0xB002, refB.Iface)

	start := t0
	end := t0.Add(42 * time.Second)

	rows := []struct {
		name             string
		flow             ConntrackFlow
		want             SessionRef
		wantUnattributed bool
	}{
		{
			name: "mark_and_iface_agree_session_a",
			flow: ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "104.16.0.5:443", 4096, 1<<20, start, end),
			want: refA,
		},
		{
			name: "mark_and_iface_agree_session_b",
			flow: ctFlow(0xB002, refB.Iface, "10.40.0.3:50113", "104.16.0.5:443", 512, 2048, start, end),
			want: refB,
		},
		{
			name:             "mark_a_on_iface_b_disagree_never_coinflip",
			flow:             ctFlow(0xA001, refB.Iface, "10.40.0.3:50114", "104.16.0.5:443", 64, 128, start, end),
			wantUnattributed: true,
		},
		{
			name:             "mark_b_on_iface_a_disagree_never_coinflip",
			flow:             ctFlow(0xB002, refA.Iface, "10.40.0.2:50115", "104.16.0.5:443", 64, 128, start, end),
			wantUnattributed: true,
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			rec, err := attr.Attribute(bg, row.flow)
			if row.wantUnattributed {
				if !errors.Is(err, ErrUnattributed) {
					t.Fatalf("mark/iface disagreement must return ErrUnattributed (never a coin-flip between A and B); got err=%v rec=%+v", err, rec)
				}
				if rec.Session != (SessionRef{}) {
					t.Errorf("no SessionRef may be produced for a disagreeing flow, got %+v", rec.Session)
				}
				return
			}
			if err != nil {
				t.Fatalf("Attribute: %v", err)
			}
			if rec.Session != row.want {
				t.Errorf("attributed to %+v, want %+v", rec.Session, row.want)
			}
			if rec.BytesOut != row.flow.BytesOrig || rec.BytesIn != row.flow.BytesReply {
				t.Errorf("byte mapping wrong: got out=%d in=%d, want out=%d in=%d",
					rec.BytesOut, rec.BytesIn, row.flow.BytesOrig, row.flow.BytesReply)
			}
			if want := row.flow.End.Sub(row.flow.Start); rec.Duration != want {
				t.Errorf("duration mapping wrong: got %v want %v", rec.Duration, want)
			}
			if rec.CtMark != row.flow.CtMark {
				t.Errorf("ct mark not carried: got %#x want %#x", rec.CtMark, row.flow.CtMark)
			}
			if rec.Iface != row.flow.Iif {
				t.Errorf("iface not carried: got %q want %q", rec.Iface, row.flow.Iif)
			}
			if rec.Verdict != FlowAccepted {
				t.Errorf("conntrack flow must record Verdict=%q, got %q", FlowAccepted, rec.Verdict)
			}
			// Destination, timestamps, and protocol feed the LOG-4 reconciler
			// and the admitting-domain join — they must survive attribution.
			if rec.Dst != row.flow.Dst {
				t.Errorf("destination not carried: got %v want %v", rec.Dst, row.flow.Dst)
			}
			if !rec.Start.Equal(row.flow.Start) {
				t.Errorf("flow start not carried: got %v want %v", rec.Start, row.flow.Start)
			}
			if !rec.End.Equal(row.flow.End) {
				t.Errorf("flow end not carried: got %v want %v", rec.End, row.flow.End)
			}
			if rec.Protocol != row.flow.Protocol {
				t.Errorf("protocol not carried: got %v want %v", rec.Protocol, row.flow.Protocol)
			}
		})
	}
}

// planRef: doc 09 §7 LOG-2 + §3 NFT-2 rationale (addresses forgeable, attachment point not); doc 06 §3(c) in-VM-spoofing row [ADVERSARIAL]
func TestAttribute_ForgedSourceIP_IsIgnored(t *testing.T) {
	reg := NewSessionRegistry()
	attr := NewAttributor(reg, NewAdmissionIndex())

	refA := mkRef("sess-a")
	refB := mkRef("sess-b")
	mustRegister(t, reg, refA, 0xA001, refA.Iface)
	mustRegister(t, reg, refB, 0xB002, refB.Iface)

	// The collected story stream: B's story must come out EMPTY.
	spool := &recordingSpool{bound: 1 << 20}
	col := NewCollector(spool)

	// Session A's iface+ctMark, with Src mutated across the whole table:
	// B's address, an address belonging to no session, and A's own.
	srcs := []struct {
		name string
		src  string
	}{
		{"spoofing_session_b_address", "10.40.0.3:50000"},
		{"address_of_no_session", "192.0.2.99:50000"},
		{"own_address_control", "10.40.0.2:50000"},
	}

	var got []SessionRef
	for _, row := range srcs {
		t.Run(row.name, func(t *testing.T) {
			f := ctFlow(0xA001, refA.Iface, row.src, "104.16.0.5:443", 1024, 4096, t0, t0.Add(time.Second))
			rec, err := attr.Attribute(bg, f)
			if err != nil {
				t.Fatalf("Attribute: %v", err)
			}
			if rec.Session != refA {
				t.Fatalf("flow on A's iface+mark with Src=%s attributed to %+v, want session A — attribution must never key on source IP", row.src, rec.Session)
			}
			if rec.Session == refB {
				t.Fatalf("spoofed Src polluted session B's audit record")
			}
			mustIngest(t, col, rec)
			got = append(got, rec.Session)
		})
	}
	for i := 1; i < len(got); i++ {
		if got[i] != got[0] {
			t.Errorf("mutating Src changed the attributed SessionRef: %+v vs %+v", got[i], got[0])
		}
	}

	// Session B's flow story contains NOTHING: query the collected stream
	// directly instead of trusting the per-record assertions alone.
	aStory := 0
	for _, ev := range spool.all() {
		if ev.Ref().SessionID == refB.SessionID {
			t.Errorf("spoofed Src landed an event in session B's story: %+v", ev)
		}
		if ev.Ref().SessionID == refA.SessionID {
			aStory++
		}
	}
	if aStory != len(srcs) {
		t.Errorf("session A's story must hold all %d spoofed-source flows, got %d", len(srcs), aStory)
	}
}

// planRef: doc 09 §7 LOG-2 ("the DNS event stream (DNS-2) provides the domain that admitted the flow join")
func TestAttribute_AdmittingDomainJoin(t *testing.T) {
	reg := NewSessionRegistry()
	idx := NewAdmissionIndex()
	attr := NewAttributor(reg, idx)

	refA := mkRef("sess-a")
	mustRegister(t, reg, refA, 0xA001, refA.Iface)

	mustObserveDns(t, idx, DnsEvent{
		Session: refA, QueryName: "registry.npmjs.org",
		AdmittedIPs: []netip.Addr{netip.MustParseAddr("104.16.0.5")},
		TTL:         60 * time.Second, ExpiresAt: t0.Add(60 * time.Second),
		Decision: validDecision(refA, VerdictAllow, "DNS-2.admit.npm", "registry.npmjs.org", t0),
	})

	rec, err := attr.Attribute(bg, ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "104.16.0.5:443",
		1024, 4096, t0.Add(10*time.Second), t0.Add(20*time.Second)))
	if err != nil {
		t.Fatalf("Attribute (admitted flow): %v", err)
	}
	if rec.AdmittingDomain != "registry.npmjs.org" {
		t.Errorf("AdmittingDomain = %q, want %q", rec.AdmittingDomain, "registry.npmjs.org")
	}

	// A flow to an address never admitted for A: empty domain, flagged for
	// reconciliation (ErrNoAdmission from the index — never a fabricated join).
	rec2, err := attr.Attribute(bg, ctFlow(0xA001, refA.Iface, "10.40.0.2:50113", "198.51.100.9:443",
		512, 512, t0.Add(10*time.Second), t0.Add(12*time.Second)))
	if err != nil {
		t.Fatalf("Attribute (never-admitted dst): %v", err)
	}
	if rec2.AdmittingDomain != "" {
		t.Errorf("never-admitted dst must have empty AdmittingDomain, got %q", rec2.AdmittingDomain)
	}
	if _, derr := idx.AdmittingDomain(bg, refA, netip.MustParseAddr("198.51.100.9"), t0.Add(10*time.Second)); !errors.Is(derr, ErrNoAdmission) {
		t.Errorf("never-admitted dst must be flagged for reconciliation via ErrNoAdmission, got %v", derr)
	}
}

// planRef: doc 09 §7 LOG-2 100%-correct-session Done-when; CDN shared-IP context (doc 03 OQ1) [ADVERSARIAL]
func TestAttribute_SharedIPAcrossSessions_NoCrossJoin(t *testing.T) {
	reg := NewSessionRegistry()
	idx := NewAdmissionIndex()
	attr := NewAttributor(reg, idx)

	refA := mkRef("sess-a")
	refB := mkRef("sess-b")
	mustRegister(t, reg, refA, 0xA001, refA.Iface)
	mustRegister(t, reg, refB, 0xB002, refB.Iface)

	shared := netip.MustParseAddr("151.101.1.1")
	mustObserveDns(t, idx, DnsEvent{
		Session: refA, QueryName: "alloweda.example",
		AdmittedIPs: []netip.Addr{shared},
		TTL:         5 * time.Minute, ExpiresAt: t0.Add(5 * time.Minute),
		Decision: validDecision(refA, VerdictAllow, "DNS-2.admit.a", "alloweda.example", t0),
	})
	mustObserveDns(t, idx, DnsEvent{
		Session: refB, QueryName: "allowedb.example",
		AdmittedIPs: []netip.Addr{shared},
		TTL:         5 * time.Minute, ExpiresAt: t0.Add(5 * time.Minute),
		Decision: validDecision(refB, VerdictAllow, "DNS-2.admit.b", "allowedb.example", t0),
	})

	recA, err := attr.Attribute(bg, ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "151.101.1.1:443",
		1024, 4096, t0.Add(time.Second), t0.Add(2*time.Second)))
	if err != nil {
		t.Fatalf("Attribute A: %v", err)
	}
	recB, err := attr.Attribute(bg, ctFlow(0xB002, refB.Iface, "10.40.0.3:50113", "151.101.1.1:443",
		1024, 4096, t0.Add(time.Second), t0.Add(2*time.Second)))
	if err != nil {
		t.Fatalf("Attribute B: %v", err)
	}
	if recA.AdmittingDomain != "alloweda.example" {
		t.Errorf("A's flow joined %q, want alloweda.example", recA.AdmittingDomain)
	}
	if recB.AdmittingDomain != "allowedb.example" {
		t.Errorf("B's flow joined %q, want allowedb.example", recB.AdmittingDomain)
	}

	domA, err := idx.AdmittingDomain(bg, refA, shared, t0.Add(time.Second))
	if err != nil {
		t.Fatalf("AdmittingDomain(A): %v", err)
	}
	if domA == "allowedb.example" || domA != "alloweda.example" {
		t.Errorf("AdmittingDomain(A, shared CDN ip) = %q — must be A's own domain, never B's", domA)
	}
	domB, err := idx.AdmittingDomain(bg, refB, shared, t0.Add(time.Second))
	if err != nil {
		t.Fatalf("AdmittingDomain(B): %v", err)
	}
	if domB == "alloweda.example" || domB != "allowedb.example" {
		t.Errorf("AdmittingDomain(B, shared CDN ip) = %q — must be B's own domain, never A's", domB)
	}
}

// planRef: doc 09 §7 LOG-2 (100% attributed to the CORRECT session) feeding LOG-4 [ADVERSARIAL]
func TestAttribute_UnknownCtMark_NeverGuessed(t *testing.T) {
	reg := NewSessionRegistry()
	attr := NewAttributor(reg, NewAdmissionIndex())

	refA := mkRef("sess-a")
	mustRegister(t, reg, refA, 0xA001, refA.Iface)

	rows := []struct {
		name string
		flow ConntrackFlow
	}{
		{"unregistered_mark_on_unregistered_iface", ctFlow(0xDEAD, "dstap-ghost", "10.99.0.9:50112", "203.0.113.5:443", 64, 64, t0, t0.Add(time.Second))},
		{"registered_iface_with_zero_mark", ctFlow(0, refA.Iface, "10.40.0.2:50112", "203.0.113.5:443", 64, 64, t0, t0.Add(time.Second))},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			rec, err := attr.Attribute(bg, row.flow)
			if !errors.Is(err, ErrUnattributed) {
				t.Fatalf("unattributable flow must surface ErrUnattributed (queued for the LOG-4 reconciler), got err=%v rec=%+v", err, rec)
			}
			if rec != (FlowRecord{}) {
				t.Errorf("no FlowRecord with any registered SessionRef may be produced, got %+v", rec)
			}
		})
	}
}

// planRef: doc 09 §7 LOG-2 + §4 DNS-2b expiry lockstep; doc 09 OQ3 (resolve-once clients)
func TestAttribute_AdmissionExpiry_TimeWindowed(t *testing.T) {
	reg := NewSessionRegistry()
	idx := NewAdmissionIndex()
	attr := NewAttributor(reg, idx)

	refA := mkRef("sess-a")
	mustRegister(t, reg, refA, 0xA001, refA.Iface)

	ip := netip.MustParseAddr("104.16.0.5")
	// Admission valid [t0, t0+90s).
	mustObserveDns(t, idx, DnsEvent{
		Session: refA, QueryName: "registry.npmjs.org",
		AdmittedIPs: []netip.Addr{ip},
		TTL:         90 * time.Second, ExpiresAt: t0.Add(90 * time.Second),
		Decision: validDecision(refA, VerdictAllow, "DNS-2.admit.npm", "registry.npmjs.org", t0),
	})

	t.Run("flow_starting_in_window_keeps_domain_past_expiry", func(t *testing.T) {
		// Starts at t0+30s (in-window), ends at t0+300s — established flows
		// ride conntrack (NFT-3); expiry must not retro-strip the join.
		rec, err := attr.Attribute(bg, ctFlow(0xA001, refA.Iface, "10.40.0.2:50112", "104.16.0.5:443",
			4096, 1<<20, t0.Add(30*time.Second), t0.Add(300*time.Second)))
		if err != nil {
			t.Fatalf("Attribute: %v", err)
		}
		if rec.AdmittingDomain != "registry.npmjs.org" {
			t.Errorf("in-window flow lost its admitting domain: got %q", rec.AdmittingDomain)
		}
		if dom, derr := idx.AdmittingDomain(bg, refA, ip, t0.Add(30*time.Second)); derr != nil || dom != "registry.npmjs.org" {
			t.Errorf("AdmittingDomain at t0+30s = (%q, %v), want (registry.npmjs.org, nil)", dom, derr)
		}
	})

	t.Run("flow_starting_post_expiry_gets_no_domain", func(t *testing.T) {
		// Starts at t0+120s with no re-admission: no domain, flagged unexplained.
		rec, err := attr.Attribute(bg, ctFlow(0xA001, refA.Iface, "10.40.0.2:50113", "104.16.0.5:443",
			64, 64, t0.Add(120*time.Second), t0.Add(130*time.Second)))
		if err != nil {
			t.Fatalf("Attribute: %v", err)
		}
		if rec.AdmittingDomain != "" {
			t.Errorf("post-expiry flow must not be falsely granted a domain, got %q", rec.AdmittingDomain)
		}
		if _, derr := idx.AdmittingDomain(bg, refA, ip, t0.Add(120*time.Second)); !errors.Is(derr, ErrNoAdmission) {
			t.Errorf("post-expiry lookup must flag ErrNoAdmission (feeds reconciliation), got %v", derr)
		}
	})
}

// planRef: doc 09 §7 LOG-2/LOG-4 parenthetical (host-egress reconciliation rides on proxy events pending OQ11)
func TestAttribute_ProxyUpstreamLeg_ViaProxyEvents(t *testing.T) {
	refA := mkRef("sess-a")

	spool := &recordingSpool{bound: 1 << 20}
	col := NewCollector(spool)
	httpEv := validHttpEvent(refA, "github.com", t0.Add(time.Second))
	httpEv.ReqBytes = 2048
	httpEv.RespBytes = 8192
	mustIngest(t, col, httpEv)

	idx := newFakeAdmissionIndex()
	upstreamIP := netip.MustParseAddr("140.82.112.3")
	idx.add(refA, "github.com", upstreamIP, t0, t0.Add(5*time.Minute))

	// The proxy's own upstream leg: host egress, no VM iface, no session mark.
	upstream := ctFlow(0, "eth0", "203.0.113.50:40000", "140.82.112.3:443",
		2048, 8192, t0.Add(time.Second), t0.Add(3*time.Second))

	h := newReconcilerHarness(t, []ConntrackFlow{upstream}, []Event{httpEv}, idx, nil, 30*time.Second)
	mustRegister(t, h.reg, refA, 0xA001, refA.Iface)

	w := Window{From: t0, To: t0.Add(time.Minute)}
	h.settle(w, 30*time.Second)
	rep, err := h.rec.Reconcile(bg, w)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(rep.Unexplained) != 0 {
		t.Fatalf("proxy upstream leg left dangling as host traffic: %+v", rep.Unexplained)
	}
	if len(rep.Explained) != 1 {
		t.Fatalf("want exactly one explanation for the upstream leg, got %d", len(rep.Explained))
	}
	ex := rep.Explained[0]
	if ex.Kind != ExplanationProxySession {
		t.Errorf("upstream leg must be explained by the proxy session, got kind %v", ex.Kind)
	}
	if ex.Ref != refA {
		t.Errorf("upstream leg attributed to %+v, want originating session A", ex.Ref)
	}
	if ex.Flow != upstream {
		t.Errorf("explanation cites the wrong flow: %+v", ex.Flow)
	}
	if h.alarms.count() != 0 {
		t.Errorf("upstream leg must not raise an alarm, got %d", h.alarms.count())
	}
}

// planRef: doc 09 §7 LOG-2 Done-when ("multi-VM test host attributes 100% of generated flows — kernel- and proxy-observed — including the admitting-domain join")
func TestAttribution_MultiVM_100PercentIncludingDrops(t *testing.T) {
	reg := NewSessionRegistry()
	idx := NewAdmissionIndex()
	attr := NewAttributor(reg, idx)
	spool := &recordingSpool{bound: 64 << 20}
	col := NewCollector(spool)

	const nSessions = 20
	const flowsPer = 3
	const dropsPer = 1
	const httpPer = 2

	type script struct {
		ref    SessionRef
		mark   uint32
		domain string
		flows  []ConntrackFlow
		drops  []NflogDrop
		https  []HttpEvent
	}

	// Deterministic manifest. bytesOut is unique per (session, flow) and is
	// the exactly-once join key for kernel flows.
	scripts := make([]script, 0, nSessions)
	hostToSession := map[string]string{}
	for i := 0; i < nSessions; i++ {
		ref := mkRef(fmt.Sprintf("sess-%02d", i))
		mark := uint32(0xA000 + i)
		domain := fmt.Sprintf("pkg-%02d.example", i)
		admitted := netip.AddrFrom4([4]byte{104, 16, byte(i), 5})
		hostToSession[domain] = ref.SessionID

		mustRegister(t, reg, ref, mark, ref.Iface)
		mustObserveDns(t, idx, DnsEvent{
			Session: ref, QueryName: domain,
			AdmittedIPs: []netip.Addr{admitted},
			TTL:         10 * time.Minute, ExpiresAt: t0.Add(10 * time.Minute),
			Decision: validDecision(ref, VerdictAllow, "DNS-2.admit", domain, t0),
		})

		s := script{ref: ref, mark: mark, domain: domain}
		for j := 0; j < flowsPer; j++ {
			s.flows = append(s.flows, ctFlow(mark, ref.Iface,
				fmt.Sprintf("10.40.%d.2:%d", i, 51000+j),
				netip.AddrPortFrom(admitted, 443).String(),
				uint64(10000*i+1000*(j+1)), uint64(5000*(j+1)),
				t0.Add(time.Duration(j)*time.Second), t0.Add(time.Duration(j+2)*time.Second)))
		}
		for j := 0; j < dropsPer; j++ {
			s.drops = append(s.drops, NflogDrop{
				Iif: ref.Iface, CtMark: mark,
				Src:      netip.MustParseAddrPort(fmt.Sprintf("10.40.%d.2:52000", i)),
				Dst:      netip.MustParseAddrPort(fmt.Sprintf("203.0.113.%d:9999", i+1)),
				Protocol: ProtoTCP, At: t0.Add(5 * time.Second),
			})
		}
		for j := 0; j < httpPer; j++ {
			s.https = append(s.https, validHttpEvent(ref, domain, t0.Add(time.Duration(10+j)*time.Second)))
		}
		scripts = append(scripts, s)
	}

	// Interleave concurrently against the deterministic manifest.
	var mu sync.Mutex
	var attributed []FlowRecord
	var dropRecs []FlowRecord
	var errs []error
	var wg sync.WaitGroup
	for _, s := range scripts {
		wg.Add(1)
		go func(s script) {
			defer wg.Done()
			for _, f := range s.flows {
				rec, err := attr.Attribute(bg, f)
				mu.Lock()
				if err != nil {
					errs = append(errs, fmt.Errorf("%s flow: %w", s.ref.SessionID, err))
				} else {
					attributed = append(attributed, rec)
				}
				mu.Unlock()
			}
			for _, d := range s.drops {
				rec, err := attr.AttributeDrop(bg, d)
				mu.Lock()
				if err != nil {
					errs = append(errs, fmt.Errorf("%s drop: %w", s.ref.SessionID, err))
				} else {
					dropRecs = append(dropRecs, rec)
				}
				mu.Unlock()
			}
			for _, h := range s.https {
				if err := col.Ingest(bg, h); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("%s http ingest: %w", s.ref.SessionID, err))
					mu.Unlock()
				}
			}
		}(s)
	}
	wg.Wait()

	totalOps := nSessions * (flowsPer + dropsPer + httpPer)
	if len(errs) > 0 {
		t.Fatalf("attribution must be 100%%: %d/%d operations failed; first: %v", len(errs), totalOps, errs[0])
	}

	// Kernel flows: every manifest entry exactly once, correct session + domain.
	if len(attributed) != nSessions*flowsPer {
		t.Fatalf("attributed %d/%d kernel flows — must be 100%%", len(attributed), nSessions*flowsPer)
	}
	seenFlow := map[string]int{}
	for _, rec := range attributed {
		seenFlow[fmt.Sprintf("%#x|%d", rec.CtMark, rec.BytesOut)]++
	}
	for _, s := range scripts {
		for _, f := range s.flows {
			key := fmt.Sprintf("%#x|%d", f.CtMark, f.BytesOrig)
			if seenFlow[key] != 1 {
				t.Errorf("manifest flow %s appeared %d times in the collected stream, want exactly once", key, seenFlow[key])
			}
		}
	}
	for _, rec := range attributed {
		wantID := fmt.Sprintf("sess-%02d", int(rec.CtMark-0xA000))
		if rec.Session.SessionID != wantID {
			t.Errorf("cross-session assignment: flow mark %#x attributed to %q, want %q", rec.CtMark, rec.Session.SessionID, wantID)
		}
		if want := fmt.Sprintf("pkg-%s.example", rec.Session.SessionID[len("sess-"):]); rec.AdmittingDomain != want {
			t.Errorf("admitting-domain join wrong for %s: got %q want %q", rec.Session.SessionID, rec.AdmittingDomain, want)
		}
	}

	// nflog drops: attributed, with the dropped verdict.
	if len(dropRecs) != nSessions*dropsPer {
		t.Fatalf("attributed %d/%d nflog drops — drops count toward 100%%", len(dropRecs), nSessions*dropsPer)
	}
	for _, rec := range dropRecs {
		if rec.Verdict != FlowDropped {
			t.Errorf("nflog drop recorded as %q, want %q", rec.Verdict, FlowDropped)
		}
		wantID := fmt.Sprintf("sess-%02d", int(rec.CtMark-0xA000))
		if rec.Session.SessionID != wantID {
			t.Errorf("drop cross-session assignment: mark %#x -> %q, want %q", rec.CtMark, rec.Session.SessionID, wantID)
		}
	}

	// Proxy-observed events: collected once each, attributed natively.
	collected := spool.all()
	if len(collected) != nSessions*httpPer {
		t.Fatalf("collected %d/%d proxy events", len(collected), nSessions*httpPer)
	}
	perSession := map[string]int{}
	for _, ev := range collected {
		he, ok := ev.(HttpEvent)
		if !ok {
			t.Errorf("unexpected event type in collected stream: %T", ev)
			continue
		}
		if want := hostToSession[he.Host]; he.Ref().SessionID != want {
			t.Errorf("proxy event for %s attributed to %q, want %q", he.Host, he.Ref().SessionID, want)
		}
		perSession[he.Ref().SessionID]++
	}
	for _, s := range scripts {
		if perSession[s.ref.SessionID] != httpPer {
			t.Errorf("session %s has %d proxy events in the stream, want %d", s.ref.SessionID, perSession[s.ref.SessionID], httpPer)
		}
	}
}
