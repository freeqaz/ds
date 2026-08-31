package nft

// NFT-1: host bootstrap ruleset — default-deny on agent interfaces,
// established/related back in, and nothing else.

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// planRef: doc 09 §3 NFT-1 Done-when; §9 row 'Default-deny outbound holds'; doc 06 §3(c) row 1
func TestBootstrap_DefaultDeny_AllTrafficFromAgentIfaceDrops(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	// No Admit calls made: a VM behind a freshly bootstrapped host can reach
	// nothing at all.

	probes := []struct {
		name  string
		proto Proto
		port  uint16
	}{
		{"tcp-443-pre-admission", ProtoTCP, 443},
		{"tcp-80-pre-admission", ProtoTCP, 80},
		{"tcp-22", ProtoTCP, 22},
		{"udp-123", ProtoUDP, 123},
		{"udp-4789", ProtoUDP, 4789},
		{"icmp-echo", ProtoICMP, 0},
		{"gre", ProtoGRE, 0},
		{"sctp-3868", ProtoSCTP, 3868},
		{"tcp-65535", ProtoTCP, 65535},
	}
	dsts := []struct {
		name string
		addr string
	}{
		{"public", "203.0.113.50"},
		{"private", "10.99.0.7"},
		{"boundary-host", "192.0.2.10"},
	}
	// Port-53 carve-out rows are asserted separately (NFT-2.a / NFT-4.a);
	// every row here must be a logged, attributed drop.
	for _, p := range probes {
		for _, d := range dsts {
			t.Run(p.name+"/"+d.name, func(t *testing.T) {
				pkt := vmPkt(sessA, fmt.Sprintf("%s:%d", d.addr, p.port), p.proto, CtStateNew)
				dec := h.mustEval(pkt)
				requireDrop(t, dec, "default-deny "+p.name+" to "+d.name)
				switch dec.Verdict {
				case VerdictRedirectDNSGate, VerdictRedirectTLSProxy, VerdictAcceptDirect, VerdictAcceptReturn:
					t.Errorf("non-53 traffic must never accept or redirect, got %v", dec.Verdict)
				}
			})
		}
	}
}

// planRef: doc 09 §3 NFT-1 ('established/related allowed back in')
func TestBootstrap_EstablishedRelatedReturnAccepted(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 5*time.Minute, x)

	// Open an allowed flow (admitted IP, Stage-1 direct tcp/443).
	fid, open := h.openFlow(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	if open.Verdict != VerdictAcceptDirect {
		t.Fatalf("OpenFlow verdict = %v, want accept-direct (Stage-1 admitted)", open.Verdict)
	}
	if open.CtMark != sessA.CtMark {
		t.Errorf("OpenFlow CtMark = %#x, want session A's %#x", open.CtMark, sessA.CtMark)
	}

	cont, err := h.flows.ContinueFlow(h.ctx, fid, 1024, 2048)
	if err != nil {
		t.Fatalf("ContinueFlow: %v", err)
	}
	requireAccepted(t, cont, "established continuation")
	if cont.CtMark != sessA.CtMark {
		t.Errorf("established CtMark = %#x, want %#x", cont.CtMark, sessA.CtMark)
	}

	// Related state on the same tuple is accepted too.
	rel := h.mustEval(vmPkt(sessA, x+":443", ProtoTCP, CtStateRelated))
	requireAccepted(t, rel, "related packet")
	if rel.CtMark != sessA.CtMark {
		t.Errorf("related CtMark = %#x, want %#x", rel.CtMark, sessA.CtMark)
	}
}

// planRef: doc 09 §3 NFT-1 ('and nothing else')
func TestBootstrap_InvalidCtStateDrops(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, clampMin, x)

	// A live admitted flow exists on the tuple…
	if _, open := h.openFlow(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew)); open.Verdict != VerdictAcceptDirect {
		t.Fatalf("setup flow not accepted: %v", open.Verdict)
	}
	// …but a conntrack-invalid packet on the same tuple never piggybacks on
	// the established exemption.
	dec := h.mustEval(vmPkt(sessA, x+":443", ProtoTCP, CtStateInvalid))
	requireDrop(t, dec, "ct-invalid on live tuple")
}

// planRef: doc 09 §3 NFT-1 + POL-2 resolver row ('host-side egress for ds-dnsgate's own upstream queries only')
func TestBootstrap_HostUplinkEgressUnaffected(t *testing.T) {
	h := newHarness(t)
	for _, dst := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		t.Run(dst, func(t *testing.T) {
			pkt := Packet{InIface: hostUplinkIface, Src: ap("192.0.2.10:53444"), Dst: ap(dst), Proto: ProtoUDP, CtState: CtStateNew}
			dec := h.mustEval(pkt)
			if dec.Verdict == VerdictDrop {
				t.Errorf("host-originated upstream resolution to %s dropped; default-deny must be scoped to agent ifaces", dst)
			}
			// Nor captured: redirecting the host's own upstream resolver
			// traffic to dnsgate would be a capture loop, and tlsproxy has no
			// business with it either — capture applies to VM ifaces only.
			if dec.Verdict == VerdictRedirectDNSGate || dec.Verdict == VerdictRedirectTLSProxy {
				t.Errorf("host-originated upstream resolution to %s redirected (%v); capture applies to VM ifaces only", dst, dec.Verdict)
			}
		})
	}
}

// planRef: doc 09 §3 NFT-1 ('versioned, declarative ruleset… a build artifact, not hand-applied state')
func TestBootstrap_Idempotent_SnapshotStable(t *testing.T) {
	h := newHarness(t)
	s1 := h.snapshot()
	if err := h.mgr.Bootstrap(h.ctx, h.cfg); err != nil {
		t.Fatalf("re-Bootstrap with identical cfg must be a no-op, got error: %v", err)
	}
	s2 := h.snapshot()
	if !s1.Equal(s2) {
		t.Errorf("re-bootstrap changed the ruleset: snapshots not Equal")
	}
	if !bytes.Equal(s1.Bytes(), s2.Bytes()) {
		t.Errorf("re-bootstrap changed the ruleset bytes:\n s1=%q\n s2=%q", s1.Bytes(), s2.Bytes())
	}
}

// planRef: §9 row 'Controls unobservable/unmodifiable from inside the VM' (NFT-1 + §2 placement); doc 06 §3(c) last row
func TestControls_BoundaryServicesUnreachableFromVM(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)

	rows := []struct {
		name  string
		dst   string
		proto Proto
	}{
		// The redirect target IP itself, aimed at directly:
		{"dnsgate-listener-direct-tcp", "192.0.2.10:10053", ProtoTCP},
		{"dnsgate-listener-direct-udp", "192.0.2.10:10053", ProtoUDP},
		{"tlsproxy-listener-direct", "192.0.2.10:10443", ProtoTCP},
		// Boundary plumbing surfaces:
		{"dnsgate-metrics", "192.0.2.10:9153", ProtoTCP},
		{"tlsproxy-admin", "192.0.2.10:9901", ProtoTCP},
		{"policy-snapshot-service", "192.0.2.10:7000", ProtoTCP},
		{"flowlog-spool", "192.0.2.10:7001", ProtoTCP},
		{"ssh-gateway", "192.0.2.10:22", ProtoTCP},
		{"netlink-shaped-udp", "192.0.2.10:9999", ProtoUDP},
		// Host IP on a gated web port (not admitted, and never admissible):
		{"host-443", "192.0.2.10:443", ProtoTCP},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			dec := h.mustEval(vmPkt(sessA, r.dst, r.proto, CtStateNew))
			requireDrop(t, dec, "boundary surface "+r.name)
		})
	}
}

// planRef: doc 09 §3 NFT-1 + NFT-2 (only attached, named sessions get rules)
func TestBootstrap_UnknownIfaceDrops(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA) // a legitimate neighbor exists; dstap-ghost was never attached

	rows := []struct {
		name  string
		dst   string
		proto Proto
	}{
		{"dns-53", "1.1.1.1:53", ProtoUDP},
		{"web-443", "203.0.113.50:443", ProtoTCP},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			pkt := Packet{InIface: "dstap-ghost", Src: ap("10.99.99.2:40000"), Dst: ap(r.dst), Proto: r.proto, CtState: CtStateNew}
			dec := h.mustEval(pkt)
			requireDrop(t, dec, "unknown iface "+r.name)
			if dec.Verdict == VerdictRedirectDNSGate {
				t.Errorf("even the DNS redirect requires a known attached session interface")
			}
		})
	}
}
