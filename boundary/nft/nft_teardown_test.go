package nft

// NFT-6: teardown hygiene — atomic, residue-free session destroy.
// ISO-1: session isolation — no path between agent VMs, shared L2 segments
// unrepresentable.

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// planRef: doc 09 §3 NFT-6 Done-when ('a create→destroy loop run N times leaves the ruleset byte-identical to bootstrap'); doc 06 §3(b) clean-teardown row
func TestTeardown_CreateDestroyLoop_RulesetByteIdentical(t *testing.T) {
	h := newHarness(t)
	s0 := h.snapshot()

	const n = 50
	ids := make([]SessionID, 0, n)
	for i := 0; i < n; i++ {
		spec := SessionSpec{
			ID:     SessionID(fmt.Sprintf("loop%02d", i)),
			Iface:  fmt.Sprintf("dstap-loop%02d", i),
			VLANID: uint16(200 + i),
			VMAddr: netip.AddrFrom4([4]byte{10, 78, byte(i), 2}),
			CtMark: uint32(0x1000 + i),
		}
		ids = append(ids, spec.ID)
		h.attach(spec)
		h.admit(spec.ID, 5*time.Minute, "198.51.100.1", "198.51.100.2", "198.51.100.3")

		// Exercise the session: an accepted flow and a logged drop.
		fid, open := h.openFlow(Packet{InIface: spec.Iface, Src: netip.AddrPortFrom(spec.VMAddr, 40000), Dst: ap("198.51.100.1:443"), Proto: ProtoTCP, CtState: CtStateNew})
		if open.Verdict != VerdictAcceptDirect {
			t.Fatalf("loop %d: flow verdict = %v, want accept-direct", i, open.Verdict)
		}
		if err := h.flows.CloseFlow(h.ctx, fid); err != nil {
			t.Fatalf("loop %d: CloseFlow: %v", i, err)
		}
		requireDrop(t, h.mustEval(Packet{InIface: spec.Iface, Src: netip.AddrPortFrom(spec.VMAddr, 40000), Dst: ap("203.0.113.50:9999"), Proto: ProtoTCP, CtState: CtStateNew}), fmt.Sprintf("loop %d drop", i))

		h.detach(spec.ID)
	}

	s1 := h.snapshot()
	if !s1.Equal(s0) {
		t.Errorf("after %d create→destroy loops the ruleset differs from bootstrap (Equal)", n)
	}
	if !bytes.Equal(s1.Bytes(), s0.Bytes()) {
		t.Errorf("after %d create→destroy loops the ruleset bytes differ:\n s0=%q\n s1=%q", n, s0.Bytes(), s1.Bytes())
	}
	for _, id := range ids {
		if _, err := h.reader.Entries(h.ctx, id, FamilyIPv4); !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("Entries(%s) after teardown: err = %v, want ErrSessionNotFound", id, err)
		}
	}
}

// planRef: doc 09 §3 NFT-6 ('removes the interface rules and named sets atomically')
func TestTeardown_Atomic_NoGhostAcceptanceAfterDestroy(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 15*time.Minute, x) // live, unexpired entries

	fid, open := h.openFlow(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	requireAccepted(t, open, "pre-detach flow")

	h.detach(sessA.ID)

	// Nothing on the dead interface flows — not even the 53 redirect.
	post := h.mustEval(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	if post.Verdict != VerdictDrop {
		t.Errorf("post-detach ct-new to previously admitted %s verdict = %v, want drop", x, post.Verdict)
	}
	dns := h.mustEval(vmPkt(sessA, "8.8.8.8:53", ProtoUDP, CtStateNew))
	if dns.Verdict != VerdictDrop {
		t.Errorf("post-detach udp/53 verdict = %v, want drop (the redirect is gone with the iface rules)", dns.Verdict)
	}

	// The session's conntrack entries are flushed at teardown: the
	// previously established flow refuses to continue.
	if _, err := h.flows.ContinueFlow(h.ctx, fid, 100, 100); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("ContinueFlow after detach: err = %v, want ErrSessionNotFound (conntrack flushed)", err)
	}
	if _, err := h.reader.Entries(h.ctx, sessA.ID, FamilyIPv4); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Entries after detach: err = %v, want ErrSessionNotFound", err)
	}
}

// planRef: doc 09 §3 NFT-6 (atomic removal scoped to one session) + doc 06 §3(b) clean-teardown
func TestTeardown_OtherSessionsUndisturbed(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	h.attach(sessB)
	const x = "93.184.216.34"
	h.admit(sessB.ID, 10*time.Minute, x)

	esBefore := h.entries(sessB.ID, FamilyIPv4)
	eBefore, ok := findEntry(esBefore, ipa(x))
	if !ok {
		t.Fatalf("B's admission missing before teardown: %+v", esBefore)
	}

	fid, open := h.openFlow(vmPkt(sessB, x+":443", ProtoTCP, CtStateNew))
	requireAccepted(t, open, "B's long-lived flow")

	h.detach(sessA.ID)

	// B's established flow continues…
	cont, err := h.flows.ContinueFlow(h.ctx, fid, 1024, 1024)
	if err != nil {
		t.Fatalf("ContinueFlow on B's flow after A's teardown: %v", err)
	}
	requireAccepted(t, cont, "B's flow after A's teardown")

	// …B's new flows are still accepted…
	freshPkt := Packet{InIface: sessB.Iface, Src: netip.AddrPortFrom(sessB.VMAddr, 40003), Dst: ap(x + ":443"), Proto: ProtoTCP, CtState: CtStateNew}
	if dec := h.mustEval(freshPkt); dec.Verdict != VerdictAcceptDirect {
		t.Errorf("B's ct-new flow after A's teardown verdict = %v, want accept-direct", dec.Verdict)
	}

	// …and B's entries are unchanged to the nanosecond.
	esAfter := h.entries(sessB.ID, FamilyIPv4)
	eAfter, ok := findEntry(esAfter, ipa(x))
	if !ok {
		t.Fatalf("B's admission vanished with A's teardown: %+v", esAfter)
	}
	if len(esAfter) != len(esBefore) {
		t.Errorf("B's entry count changed: %d -> %d", len(esBefore), len(esAfter))
	}
	if !eAfter.ExpiresAt.Equal(eBefore.ExpiresAt) {
		t.Errorf("B's ExpiresAt perturbed by A's teardown: %v -> %v", eBefore.ExpiresAt, eAfter.ExpiresAt)
	}
}

// planRef: §9 row 'Session A cannot reach session B (no L2 path between agent VMs)' (§2 placement + NFT-1); OQ1 spike checklist
func TestSessionIsolation_NoPathBetweenAgentVMs(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA) // VLAN 101
	h.attach(sessB) // VLAN 102

	bAddr := sessB.VMAddr.String()
	rows := []struct {
		name  string
		dst   string
		proto Proto
	}{
		{"tcp-443", bAddr + ":443", ProtoTCP},
		{"udp-53", bAddr + ":53", ProtoUDP}, // dropped before even the 53 redirect
		{"icmp", bAddr + ":0", ProtoICMP},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			dec := h.mustEval(vmPkt(sessA, r.dst, r.proto, CtStateNew))
			requireDrop(t, dec, "A->B "+r.name)
		})
	}

	// Adversarial: even a poisoned allow-set (simulating a DNS-4 scrub
	// failure that admitted B's VMAddr into allow4_alpha) opens no path —
	// inter-agent forwarding is denied before allow-set consultation.
	if err := h.writer.Admit(h.ctx, PrincipalDNSGate, sessA.ID, FamilyIPv4, []netip.Addr{sessB.VMAddr}, 5*time.Minute); err != nil {
		t.Fatalf("force-Admit of B's VMAddr: %v", err)
	}
	dec := h.mustEval(vmPkt(sessA, bAddr+":443", ProtoTCP, CtStateNew))
	requireDrop(t, dec, "A->B tcp/443 with poisoned allow-set")
}

// planRef: doc 09 §2 placement note ('agent VMs must never share a port group') + OQ1 ('proof that no L2 path exists between any two agent VMs')
func TestAttach_RejectsSharedL2Segment(t *testing.T) {
	h := newHarness(t)
	first := SessionSpec{ID: "alpha", Iface: "dstap-alpha", VLANID: 100, VMAddr: ipa("10.77.100.2"), CtMark: 0xA10A}
	h.attach(first)
	before := h.snapshot()

	// Same VLAN, different iface.
	dupVLAN := SessionSpec{ID: "bravo", Iface: "dstap-bravo", VLANID: 100, VMAddr: ipa("10.77.100.3"), CtMark: 0xB20B}
	if err := h.mgr.AttachSession(h.ctx, dupVLAN); !errors.Is(err, ErrSharedL2Segment) {
		t.Errorf("attach with duplicate VLANID: err = %v, want ErrSharedL2Segment", err)
	}

	// Same iface name, different VLAN.
	dupIface := SessionSpec{ID: "charlie", Iface: "dstap-alpha", VLANID: 103, VMAddr: ipa("10.77.103.2"), CtMark: 0xC30C}
	if err := h.mgr.AttachSession(h.ctx, dupIface); !errors.Is(err, ErrSharedL2Segment) {
		t.Errorf("attach reusing iface name: err = %v, want ErrSharedL2Segment", err)
	}

	// The failed attaches changed nothing.
	after := h.snapshot()
	if !before.Equal(after) || !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Errorf("rejected attaches mutated the ruleset")
	}
}
