package nft

// NFT-4: resolver-bypass closure — port-53 capture to ds-dnsgate, DoT (853)
// dropped, QUIC (udp/443) dropped, host/VM resolver asymmetry.

import (
	"testing"
	"time"
)

// egressModes drives every bypass-closure table through both NFT-2b postures:
// the Stage-1 interim mode AND the permanent proxy-redirect production posture
// (NFT-2b Done-when: 'conformance clients pass both before and after the flip').
var egressModes = []struct {
	name string
	mode EgressMode
}{
	{"stage1-direct", EgressStage1Direct},
	{"proxy-redirect", EgressProxyRedirect},
}

// planRef: doc 09 §3 NFT-4 Done-when; §9 row 'Port-53/DoT/QUIC resolver bypass fails' (both NFT-2b modes); doc 06 §3(c) DoH/DoT-bypass row
func TestBypass_Port53AnyDestinationRedirectsToDNSGate(t *testing.T) {
	for _, m := range egressModes {
		t.Run(m.name, func(t *testing.T) {
			h := newHarness(t)
			h.attach(sessA)
			const admitted = "93.184.216.34"
			h.admit(sessA.ID, 5*time.Minute, admitted)
			if m.mode != EgressStage1Direct {
				h.setMode(m.mode)
			}

			dsts := []struct {
				name string
				addr string
			}{
				{"google-dns", "8.8.8.8"},
				{"cloudflare-dns", "1.1.1.1"},
				{"quad9", "9.9.9.9"},
				{"allow-set-admitted", admitted}, // admission does NOT exempt port 53
				{"vm-gateway", "10.77.101.1"},
			}
			for _, d := range dsts {
				for _, proto := range []Proto{ProtoUDP, ProtoTCP} {
					t.Run(d.name+"/"+proto.String(), func(t *testing.T) {
						dst := ap(d.addr + ":53")
						dec := h.mustEval(Packet{InIface: sessA.Iface, Src: srcOf(sessA), Dst: dst, Proto: proto, CtState: CtStateNew})
						requireRedirect(t, dec, VerdictRedirectDNSGate, dnsGateAddr, dst, sessA, "port-53 to "+d.name+" ("+m.name+")")
					})
				}
			}
		})
	}
}

// planRef: doc 09 §3 NFT-4 ('DNS-over-TLS (853) dropped'); §9 bypass row (both NFT-2b modes)
func TestBypass_DoT853Drops_EvenToAdmittedIP(t *testing.T) {
	for _, m := range egressModes {
		t.Run(m.name, func(t *testing.T) {
			h := newHarness(t)
			h.attach(sessA)
			const admitted = "1.0.0.1" // pretend a policy admitted a name resolving there
			h.admit(sessA.ID, 5*time.Minute, admitted)
			if m.mode != EgressStage1Direct {
				h.setMode(m.mode)
			}

			dsts := []struct {
				name string
				addr string
			}{
				{"admitted-resolver", admitted},
				{"google-dns", "8.8.8.8"},
				{"arbitrary", "203.0.113.66"},
			}
			for _, d := range dsts {
				for _, proto := range []Proto{ProtoTCP, ProtoUDP} {
					t.Run(d.name+"/"+proto.String(), func(t *testing.T) {
						dec := h.mustEval(Packet{InIface: sessA.Iface, Src: srcOf(sessA), Dst: ap(d.addr + ":853"), Proto: proto, CtState: CtStateNew})
						requireDrop(t, dec, "DoT 853 to "+d.name+" ("+m.name+")") // bypass-specific RuleID asserted non-empty
					})
				}
			}
		})
	}
}

// planRef: doc 09 §3 NFT-4 ('udp/443 (QUIC) dropped for now to force TCP fallback the proxy can see'); OQ5; §9 bypass row (both NFT-2b modes)
func TestBypass_QUICUdp443Drops_ForcesTCPFallback(t *testing.T) {
	for _, m := range egressModes {
		t.Run(m.name, func(t *testing.T) {
			h := newHarness(t)
			h.attach(sessA)
			const admitted = "93.184.216.34"
			h.admit(sessA.ID, 5*time.Minute, admitted)
			if m.mode != EgressStage1Direct {
				h.setMode(m.mode)
			}

			for _, d := range []struct {
				name string
				addr string
			}{
				{"admitted", admitted},
				{"unadmitted", "198.51.100.7"},
				{"dns-google", "8.8.4.4"}, // DoH3 resolver
			} {
				t.Run("quic/"+d.name, func(t *testing.T) {
					dec := h.mustEval(Packet{InIface: sessA.Iface, Src: srcOf(sessA), Dst: ap(d.addr + ":443"), Proto: ProtoUDP, CtState: CtStateNew})
					requireDrop(t, dec, "QUIC udp/443 to "+d.name+" ("+m.name+")")
				})
			}

			// Control row: the drop is QUIC-specific, not breakage — tcp/443
			// to the admitted IP gets the EXACT mode-appropriate non-drop
			// verdict: accept-direct in Stage-1, redirect-tlsproxy after the
			// NFT-2b cutover.
			ctlDst := ap(admitted + ":443")
			ctl := h.mustEval(Packet{InIface: sessA.Iface, Src: srcOf(sessA), Dst: ctlDst, Proto: ProtoTCP, CtState: CtStateNew})
			switch m.mode {
			case EgressStage1Direct:
				if ctl.Verdict != VerdictAcceptDirect {
					t.Errorf("control tcp/443 to admitted IP verdict = %v, want accept-direct (Stage-1)", ctl.Verdict)
				}
			case EgressProxyRedirect:
				requireRedirect(t, ctl, VerdictRedirectTLSProxy, tlsProxyAddr, ctlDst, sessA, "control tcp/443 (proxy mode)")
				// Default-deny also survives the cutover: the proxy redirect
				// is scoped to tcp 80/443, never a general open door.
				requireDrop(t, h.mustEval(vmPkt(sessA, "203.0.113.50:9999", ProtoTCP, CtStateNew)), "default-deny tcp/9999 post-cutover")
			}
		})
	}
}

// planRef: doc 09 §6 POL-2 resolver row ('host-side egress only; in-VM packets aimed at these addresses are still redirected') + NFT-4
func TestBypass_HostUpstreamResolverAllowed_VMRedirected_Asymmetry(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	dst := ap("1.1.1.1:53")

	// Host-iface packet egresses: not dropped, not redirected.
	host := h.mustEval(Packet{InIface: hostUplinkIface, Src: ap("192.0.2.10:55353"), Dst: dst, Proto: ProtoUDP, CtState: CtStateNew})
	if host.Verdict == VerdictDrop {
		t.Errorf("host upstream resolver egress dropped; POL-2 grants ds-dnsgate's own upstream queries")
	}
	if host.Verdict == VerdictRedirectDNSGate || host.Verdict == VerdictRedirectTLSProxy {
		t.Errorf("host upstream resolver egress redirected (%v); capture applies to VM ifaces only", host.Verdict)
	}

	// VM-iface packet to the same dst — with Src spoofed to the host's own
	// IP — is still captured. The asymmetry is keyed purely on iface.
	vm := h.mustEval(Packet{InIface: sessA.Iface, Src: ap("192.0.2.10:55353"), Dst: dst, Proto: ProtoUDP, CtState: CtStateNew})
	requireRedirect(t, vm, VerdictRedirectDNSGate, dnsGateAddr, dst, sessA, "VM packet to baseline resolver with spoofed host Src")
}
