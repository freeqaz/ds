package nft

// NFT-2: interface-matched transparent redirect (iifname, never source IP).
// NFT-2b: the Stage-1-direct -> proxy-redirect cutover for tcp 80/443.

import (
	"math/rand"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// planRef: doc 09 §3 NFT-2 ('Redirect udp/tcp 53 → ds-dnsgate at Stage 1')
func TestRedirect_Port53ByIifname(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)

	for _, dst := range []string{"8.8.8.8:53", "203.0.113.99:53"} {
		for _, proto := range []Proto{ProtoUDP, ProtoTCP} {
			t.Run(proto.String()+"/"+dst, func(t *testing.T) {
				dec := h.mustEval(vmPkt(sessA, dst, proto, CtStateNew))
				if dec.Verdict != VerdictRedirectDNSGate {
					t.Errorf("verdict = %v, want redirect-dnsgate", dec.Verdict)
				}
				if dec.RedirectTarget != dnsGateAddr {
					t.Errorf("RedirectTarget = %v, want cfg.DNSGateAddr %v", dec.RedirectTarget, dnsGateAddr)
				}
				if dec.Session != sessA.ID {
					t.Errorf("Session = %q, want %q", dec.Session, sessA.ID)
				}
				if dec.CtMark != sessA.CtMark {
					t.Errorf("CtMark = %#x, want %#x", dec.CtMark, sessA.CtMark)
				}
			})
		}
	}
}

// planRef: doc 09 §3 NFT-2 + OQ4 (original-destination recovery is the redirect-path contract Pingora consumes)
func TestRedirect_PreservesOriginalDestination(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)

	dnsDst := ap("8.8.8.8:53")
	dec := h.mustEval(Packet{InIface: sessA.Iface, Src: srcOf(sessA), Dst: dnsDst, Proto: ProtoUDP, CtState: CtStateNew})
	requireRedirect(t, dec, VerdictRedirectDNSGate, dnsGateAddr, dnsDst, sessA, "udp/53 redirect")

	// Proxy mode: tcp/443 redirect must preserve the original dst too.
	h.setMode(EgressProxyRedirect)
	webDst := ap("140.82.112.3:443")
	dec = h.mustEval(Packet{InIface: sessA.Iface, Src: srcOf(sessA), Dst: webDst, Proto: ProtoTCP, CtState: CtStateNew})
	requireRedirect(t, dec, VerdictRedirectTLSProxy, tlsProxyAddr, webDst, sessA, "tcp/443 redirect")
}

// planRef: doc 09 §3 NFT-2 Done-when; §9 row 'In-VM spoofing fails (interface match)'; doc 06 §3(c) interface-match row
func TestSpoof_ForgedSourceIPStillRedirectedAndAttributed(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	h.attach(sessB)

	dst := ap("8.8.8.8:53")
	legit := h.mustEval(Packet{InIface: sessA.Iface, Src: srcOf(sessA), Dst: dst, Proto: ProtoUDP, CtState: CtStateNew})
	requireRedirect(t, legit, VerdictRedirectDNSGate, dnsGateAddr, dst, sessA, "legit-src baseline")

	forged := []struct {
		name string
		src  netip.AddrPort
	}{
		{"boundary-host-ip", netip.AddrPortFrom(hostIP, 40000)},
		{"session-B-vmaddr", netip.AddrPortFrom(sessB.VMAddr, 40000)},
		{"public-ip", ap("52.1.2.3:40000")},
		{"zero-addr", ap("0.0.0.0:40000")},
		{"baseline-resolver-ip", ap("1.1.1.1:40000")},
	}
	for _, f := range forged {
		t.Run(f.name, func(t *testing.T) {
			dec := h.mustEval(Packet{InIface: sessA.Iface, Src: f.src, Dst: dst, Proto: ProtoUDP, CtState: CtStateNew})
			if !reflect.DeepEqual(dec, legit) {
				t.Errorf("forged Src %v changed the decision:\n forged = %+v\n legit  = %+v", f.src, dec, legit)
			}
		})
	}
}

// planRef: doc 09 §3 NFT-2 ('addresses can be forged from inside the VM, the attachment point can't') + NFT-3 per-session sets
func TestSpoof_ForgedSourceCannotBorrowOtherSessionsAllowSet(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	h.attach(sessB)
	const x = "93.184.216.34"
	h.admit(sessB.ID, 5*time.Minute, x) // admitted for B only

	// From A's interface, forging B's address as Src.
	pkt := Packet{
		InIface: sessA.Iface,
		Src:     netip.AddrPortFrom(sessB.VMAddr, 44444),
		Dst:     ap(x + ":443"),
		Proto:   ProtoTCP,
		CtState: CtStateNew,
	}
	dec := h.mustEval(pkt)
	requireDrop(t, dec, "forged-src borrow of allow4_bravo from dstap-alpha")
}

// planRef: doc 09 §3 NFT-2 ('match on iifname, never on source IP'); doc 03 §3
func TestEvaluate_SourceIPNeverConsulted_PropertyTable(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 5*time.Minute, x)

	rng := rand.New(rand.NewSource(0x5EED)) // deterministic
	randSrc := func() netip.AddrPort {
		var b [4]byte
		u := rng.Uint32()
		b[0], b[1], b[2], b[3] = byte(u>>24), byte(u>>16), byte(u>>8), byte(u)
		return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(1024+rng.Intn(60000)))
	}

	classes := []struct {
		name      string
		dst       string
		proto     Proto
		proxyMode bool
	}{
		{"deny", "203.0.113.50:9999", ProtoTCP, false},
		{"dns-redirect", "8.8.8.8:53", ProtoUDP, false},
		{"direct-admitted", x + ":443", ProtoTCP, false},
		{"bypass-drop", "8.8.8.8:853", ProtoTCP, false},
		{"proxy-redirect", x + ":443", ProtoTCP, true},
	}
	flipped := false
	for _, c := range classes {
		if c.proxyMode && !flipped {
			h.setMode(EgressProxyRedirect)
			flipped = true
		}
		t.Run(c.name, func(t *testing.T) {
			var first Decision
			for i := 0; i < 8; i++ {
				pkt := Packet{InIface: sessA.Iface, Src: randSrc(), Dst: ap(c.dst), Proto: c.proto, CtState: CtStateNew}
				dec := h.mustEval(pkt)
				if i == 0 {
					first = dec
					continue
				}
				if !reflect.DeepEqual(dec, first) {
					t.Errorf("decision varied with Src (run %d):\n got  = %+v\n want = %+v", i, dec, first)
				}
			}
		})
	}
}

// planRef: doc 09 §3 NFT-2 ('dstap-<session>' convention; 'it is also the attribution key for §7') + LOG-2
func TestAttach_IfaceNamingConvention_AttributionKey(t *testing.T) {
	h := newHarness(t)

	conforming := SessionSpec{ID: "sess42", Iface: "dstap-sess42", VLANID: 142, VMAddr: ipa("10.77.142.2"), CtMark: 0x2a}
	if err := h.mgr.AttachSession(h.ctx, conforming); err != nil {
		t.Fatalf("conforming attach (dstap-sess42) must succeed: %v", err)
	}

	nonConforming := SessionSpec{ID: "sess43", Iface: "eth7", VLANID: 143, VMAddr: ipa("10.77.143.2"), CtMark: 0x2b}
	if err := h.mgr.AttachSession(h.ctx, nonConforming); err == nil {
		t.Errorf("non-conforming iface name %q must be rejected", nonConforming.Iface)
	}

	// The convention round-trips as the attribution key.
	dec := h.mustEval(Packet{InIface: "dstap-sess42", Src: ap("10.77.142.2:40000"), Dst: ap("8.8.8.8:53"), Proto: ProtoUDP, CtState: CtStateNew})
	if dec.Session != "sess42" {
		t.Errorf("Session = %q, want %q (attributed from iface)", dec.Session, "sess42")
	}
	if dec.CtMark != 0x2a {
		t.Errorf("CtMark = %#x, want 0x2a", dec.CtMark)
	}
}

// planRef: doc 09 §3 NFT-3 ('at Stage 1, direct tcp 80/443 egress') + NFT-2b interim mode; §8 Stage 1
func TestEgress_Stage1Direct_AllowSetGatedWebPorts(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 5*time.Minute, x)

	rows := []struct {
		name   string
		dst    string
		accept bool
	}{
		{"admitted-443", x + ":443", true},
		{"admitted-80", x + ":80", true},
		{"unadmitted-443", "198.51.100.7:443", false},
		{"unadmitted-80", "198.51.100.7:80", false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			dec := h.mustEval(vmPkt(sessA, r.dst, ProtoTCP, CtStateNew))
			if r.accept {
				if dec.Verdict != VerdictAcceptDirect {
					t.Errorf("verdict = %v, want accept-direct", dec.Verdict)
				}
				if dec.CtMark != sessA.CtMark {
					t.Errorf("CtMark = %#x, want %#x", dec.CtMark, sessA.CtMark)
				}
			} else {
				requireDrop(t, dec, r.name)
			}
		})
	}
}

// planRef: doc 09 §3 NFT-3 ('What they gate: at Stage 1, direct tcp 80/443') — admission must not widen beyond the gated ports
func TestEgress_Stage1Direct_AdmittedIPNonWebPortDrops(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 5*time.Minute, x)

	rows := []struct {
		name     string
		port     string
		proto    Proto
		redirect bool // udp/53 redirects to dnsgate; everything else drops
	}{
		{"tcp-22", "22", ProtoTCP, false},
		{"tcp-8443", "8443", ProtoTCP, false},
		{"tcp-853-dot", "853", ProtoTCP, false},
		{"udp-443-quic", "443", ProtoUDP, false},
		{"udp-53", "53", ProtoUDP, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			dec := h.mustEval(vmPkt(sessA, x+":"+r.port, r.proto, CtStateNew))
			if r.redirect {
				if dec.Verdict != VerdictRedirectDNSGate {
					t.Errorf("udp/53 to an admitted IP must still redirect to dnsgate, got %v", dec.Verdict)
				}
			} else {
				requireDrop(t, dec, "admitted IP on "+r.name)
			}
		})
	}
}

// planRef: doc 09 §3 NFT-2b ('flip tcp 80/443 from allow-set-gated direct egress to the ds-tlsproxy redirect')
func TestEgress_CutoverFlipsNewFlowsToProxyRedirect(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 5*time.Minute, x)

	h.setMode(EgressProxyRedirect)

	rows := []struct {
		name string
		dst  string
	}{
		{"admitted-443", x + ":443"},
		{"admitted-80", x + ":80"},
		{"unadmitted-443", "198.51.100.7:443"},
		{"unadmitted-80", "198.51.100.7:80"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			dst := ap(r.dst)
			dec := h.mustEval(Packet{InIface: sessA.Iface, Src: srcOf(sessA), Dst: dst, Proto: ProtoTCP, CtState: CtStateNew})
			requireRedirect(t, dec, VerdictRedirectTLSProxy, tlsProxyAddr, dst, sessA, r.name)
		})
	}
}

// planRef: doc 09 §3 NFT-2b Done-when ('conformance clients pass both before and after the flip')
func TestEgress_Cutover_EstablishedDirectFlowSurvivesFlip(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 5*time.Minute, x)

	// In Stage-1 mode, open a direct flow.
	fid, open := h.openFlow(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	if open.Verdict != VerdictAcceptDirect {
		t.Fatalf("pre-flip OpenFlow verdict = %v, want accept-direct", open.Verdict)
	}

	h.setMode(EgressProxyRedirect)

	// The in-flight connection rides conntrack across the flip.
	cont, err := h.flows.ContinueFlow(h.ctx, fid, 512, 512)
	if err != nil {
		t.Fatalf("ContinueFlow across cutover: %v", err)
	}
	requireAccepted(t, cont, "established flow across cutover")

	// A fresh tuple post-flip redirects to the proxy.
	freshPkt := Packet{InIface: sessA.Iface, Src: netip.AddrPortFrom(sessA.VMAddr, 40001), Dst: ap(x + ":443"), Proto: ProtoTCP, CtState: CtStateNew}
	_, fresh, err := h.flows.OpenFlow(h.ctx, freshPkt)
	if err != nil {
		t.Fatalf("post-flip OpenFlow: %v", err)
	}
	if fresh.Verdict != VerdictRedirectTLSProxy {
		t.Errorf("post-flip new flow verdict = %v, want redirect-tlsproxy", fresh.Verdict)
	}
}
