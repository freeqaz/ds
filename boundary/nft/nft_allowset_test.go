package nft

// NFT-3: per-session allow-sets — TTL clamp + grace expiry, ct-state-new
// gating, per-session scoping, single-writer, allow6 dormancy.

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

// planRef: doc 09 §3 NFT-3 Done-when ('an entry expires on schedule'); OQ3
func TestAllowSet_ExpiryAtTTLPlusGraceBoundaries(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	t0 := h.clk.Now()
	h.admit(sessA.ID, 60*time.Second, x) // clamp(60s)=60s, +30s grace => expires t0+90s

	es := h.entries(sessA.ID, FamilyIPv4)
	e, ok := findEntry(es, ipa(x))
	if !ok {
		t.Fatalf("admitted address %s not present in allow4_%s: %+v", x, sessA.ID, es)
	}
	if want := t0.Add(90 * time.Second); !e.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v (t0+90s)", e.ExpiresAt, want)
	}

	// t0+89s: still inside TTL+grace — accepted, and the entry is still
	// readable with its original expiry (no early pruning while Evaluate
	// still accepts; the spec reads Entries at both boundary points).
	h.clk.Advance(89 * time.Second)
	dec := h.mustEval(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	if dec.Verdict != VerdictAcceptDirect {
		t.Errorf("at +89s verdict = %v, want accept-direct (no early severing)", dec.Verdict)
	}
	if e89, ok := findEntry(h.entries(sessA.ID, FamilyIPv4), ipa(x)); !ok {
		t.Errorf("entry for %s pruned early: absent from Entries at +89s while still inside TTL+grace", x)
	} else if want := t0.Add(90 * time.Second); !e89.ExpiresAt.Equal(want) {
		t.Errorf("at +89s ExpiresAt = %v, want unchanged %v", e89.ExpiresAt, want)
	}

	// t0+91s: past expiry — the identical new flow drops and the entry is gone.
	h.clk.Advance(2 * time.Second)
	dec = h.mustEval(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	requireDrop(t, dec, "ct-new at +91s (entry expired)")
	if es := h.entries(sessA.ID, FamilyIPv4); len(es) != 0 {
		t.Errorf("expired entry must be gone, Entries = %+v", es)
	}
}

// planRef: doc 09 §3 NFT-3 ('element timeout = the clamped TTL answered to the VM plus a grace margin… 60s–15min clamp') + DNS-1 clamp
func TestAllowSet_TTLClampAndGraceMath(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)

	rows := []struct {
		name    string
		ttl     time.Duration
		addr    string
		clamped time.Duration
	}{
		{"ttl-1s-floor", 1 * time.Second, "198.51.100.11", 60 * time.Second},
		{"ttl-59s-floor", 59 * time.Second, "198.51.100.12", 60 * time.Second},
		{"ttl-60s-exact", 60 * time.Second, "198.51.100.13", 60 * time.Second},
		{"ttl-5m-passthrough", 5 * time.Minute, "198.51.100.14", 5 * time.Minute},
		{"ttl-15m-exact", 15 * time.Minute, "198.51.100.15", 15 * time.Minute},
		{"ttl-24h-ceiling", 24 * time.Hour, "198.51.100.16", 15 * time.Minute},
	}
	now := h.clk.Now()
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			h.admit(sessA.ID, r.ttl, r.addr)
			es := h.entries(sessA.ID, FamilyIPv4)
			e, ok := findEntry(es, ipa(r.addr))
			if !ok {
				t.Fatalf("%s not present after Admit", r.addr)
			}
			want := now.Add(r.clamped + graceMargin)
			if !e.ExpiresAt.Equal(want) {
				t.Errorf("ExpiresAt = %v, want now + clamp(%v) + 30s = %v", e.ExpiresAt, r.ttl, want)
			}
		})
	}
}

// planRef: doc 09 §3 NFT-3 Done-when ('established ones survive'); OQ3 ('a long-lived stream crossing an element expiry')
func TestAllowSet_EstablishedFlowSurvivesElementExpiry(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 60*time.Second, x) // expires at +90s

	h.clk.Advance(10 * time.Second)
	fid, open := h.openFlow(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	if open.Verdict != VerdictAcceptDirect {
		t.Fatalf("OpenFlow at +10s verdict = %v, want accept-direct", open.Verdict)
	}

	// Far past expiry: the streaming flow keeps flowing…
	h.clk.Advance(10 * time.Minute)
	cont, err := h.flows.ContinueFlow(h.ctx, fid, 4096, 1<<20)
	if err != nil {
		t.Fatalf("ContinueFlow at +10m: %v", err)
	}
	requireAccepted(t, cont, "established stream past element expiry")

	// …while a brand-new tuple to the same (expired) address drops.
	freshPkt := Packet{InIface: sessA.Iface, Src: netip.AddrPortFrom(sessA.VMAddr, 40002), Dst: ap(x + ":443"), Proto: ProtoTCP, CtState: CtStateNew}
	_, fresh, err := h.flows.OpenFlow(h.ctx, freshPkt)
	if err != nil {
		t.Fatalf("OpenFlow fresh tuple: %v", err)
	}
	if fresh.Verdict != VerdictDrop {
		t.Errorf("new flow to expired %s verdict = %v, want drop — split exactly on ct state", x, fresh.Verdict)
	}
}

// planRef: doc 09 §3 NFT-3 + OQ3 ('the assurance tests must cover resolve-once clients'); kernel half of TLS-1's re-admission story
func TestAllowSet_ResolveOnceClient_NewFlowAfterExpiryDrops(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 60*time.Second, x)

	// A JVM-style infinite DNS cache redialing long after expiry+grace,
	// with no re-Admit.
	h.clk.Advance(5 * time.Minute)
	dec := h.mustEval(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	requireDrop(t, dec, "stale resolve-once redial")
}

// planRef: doc 09 §3 NFT-3 Done-when ('a re-resolution restores it without widening anything'); §9 row 'allow-set never silently widens' (DNS-4 + NFT-3)
func TestAllowSet_ReResolutionRestoresWithoutWidening(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const (
		x1 = "198.51.100.10" // first CDN address
		x2 = "198.51.100.20" // rotated CDN address
	)

	h.admit(sessA.ID, 60*time.Second, x1) // expires at +90s
	h.clk.Advance(2 * time.Minute)        // x1 expired

	// Re-resolution: the CDN rotated; the same domain now admits x2 only.
	h.admit(sessA.ID, 60*time.Second, x2)
	es := h.entries(sessA.ID, FamilyIPv4)
	if len(es) != 1 || es[0].Addr != ipa(x2) {
		t.Errorf("Entries = %+v, want exactly {%s} — the old address must not linger", es, x2)
	}
	if dec := h.mustEval(vmPkt(sessA, x2+":443", ProtoTCP, CtStateNew)); dec.Verdict != VerdictAcceptDirect {
		t.Errorf("flow to freshly admitted %s verdict = %v, want accept-direct", x2, dec.Verdict)
	}
	requireDrop(t, h.mustEval(vmPkt(sessA, x1+":443", ProtoTCP, CtStateNew)), "flow to stale "+x1)

	// Re-admitting x1 later does not resurrect x2: set contents always equal
	// the latest admissions still inside their own timeouts.
	h.clk.Advance(2 * time.Minute) // x2 expired
	h.admit(sessA.ID, 60*time.Second, x1)
	es = h.entries(sessA.ID, FamilyIPv4)
	if len(es) != 1 || es[0].Addr != ipa(x1) {
		t.Errorf("Entries after re-admitting %s = %+v, want exactly {%s}", x1, es, x1)
	}
}

// planRef: doc 09 §3 NFT-3 ('The sets gate new flows only (ct state new)')
func TestAllowSet_CtStateGatingTable(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const (
		expired = "198.51.100.30"
		live    = "198.51.100.40"
		never   = "198.51.100.50"
	)
	h.admit(sessA.ID, 60*time.Second, expired) // expires at +90s
	h.clk.Advance(2 * time.Minute)             // now expired
	h.admit(sessA.ID, 15*time.Minute, live)    // live for 15m30s from here

	type kind int
	const (
		accept kind = iota
		drop
	)
	addrs := []struct {
		name string
		addr string
	}{
		{"in-set", live},
		{"not-in-set", never},
		{"expired", expired},
	}
	states := []struct {
		st   CtState
		want map[string]kind // by addr name
	}{
		{CtStateNew, map[string]kind{"in-set": accept, "not-in-set": drop, "expired": drop}},
		{CtStateEstablished, map[string]kind{"in-set": accept, "not-in-set": accept, "expired": accept}},
		{CtStateRelated, map[string]kind{"in-set": accept, "not-in-set": accept, "expired": accept}},
		{CtStateInvalid, map[string]kind{"in-set": drop, "not-in-set": drop, "expired": drop}},
	}
	for _, s := range states {
		for _, a := range addrs {
			t.Run(s.st.String()+"/"+a.name, func(t *testing.T) {
				dec := h.mustEval(vmPkt(sessA, a.addr+":443", ProtoTCP, s.st))
				switch s.want[a.name] {
				case accept:
					requireAccepted(t, dec, s.st.String()+" to "+a.name)
				case drop:
					if dec.Verdict != VerdictDrop {
						t.Errorf("verdict = %v, want drop", dec.Verdict)
					}
				}
			})
		}
	}
}

// planRef: doc 09 §3 NFT-3 ('Named sets per session allow4_<session>')
func TestAllowSet_PerSessionScoping(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	h.attach(sessB)
	const x = "93.184.216.34"
	h.admit(sessA.ID, 5*time.Minute, x) // A only

	decA := h.mustEval(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew))
	if decA.Verdict != VerdictAcceptDirect {
		t.Errorf("session A's flow to its admitted IP verdict = %v, want accept-direct", decA.Verdict)
	}
	decB := h.mustEval(vmPkt(sessB, x+":443", ProtoTCP, CtStateNew))
	requireDrop(t, decB, "session B borrowing A's admission")
}

// planRef: doc 09 §3 NFT-3 ('Only ds-dnsgate writes the sets')
func TestAllowSet_OnlyDNSGatePrincipalMayWrite(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)
	const x = "93.184.216.34"

	for _, p := range []struct {
		name      string
		principal WriterPrincipal
	}{
		{"tlsproxy", PrincipalTLSProxy},
		{"unknown", PrincipalUnknown},
	} {
		err := h.writer.Admit(h.ctx, p.principal, sessA.ID, FamilyIPv4, []netip.Addr{ipa(x)}, 5*time.Minute)
		if !errors.Is(err, ErrUnauthorizedWriter) {
			t.Errorf("Admit as %s: err = %v, want ErrUnauthorizedWriter", p.name, err)
		}
	}

	// The refused writes left nothing behind.
	if es := h.entries(sessA.ID, FamilyIPv4); len(es) != 0 {
		t.Errorf("allow4_%s must remain empty after unauthorized writes, got %+v", sessA.ID, es)
	}
	requireDrop(t, h.mustEval(vmPkt(sessA, x+":443", ProtoTCP, CtStateNew)), "flow to unauthorized-write target")
}

// planRef: doc 09 §3 NFT-3 ('allow6 stays dormant until IPv6 turns on') + DNS-1 v0 posture + OQ10
func TestAllowSet_Allow6Dormant_V6DropsEvenIfAdmitted(t *testing.T) {
	h := newHarness(t)
	h.attach(sessA)

	// allow6_<session> is created at attach and is empty.
	es6 := h.entries(sessA.ID, FamilyIPv6)
	if len(es6) != 0 {
		t.Errorf("allow6_%s must be empty at attach, got %+v", sessA.ID, es6)
	}

	// Force-admit a v6 address as the authorized principal.
	v6 := ipa("2001:db8::1")
	if err := h.writer.Admit(h.ctx, PrincipalDNSGate, sessA.ID, FamilyIPv6, []netip.Addr{v6}, 5*time.Minute); err != nil {
		t.Fatalf("Admit v6: %v", err)
	}

	// The dormant set grants nothing: no rule references it.
	v6src := netip.AddrPortFrom(ipa("fd00:77::2"), 40000)
	// v6 denials are logged, attributed drops like every other denial
	// (NFT-1 'drop + log' / NFT-5) — not a silent zero-value verdict.
	web := h.mustEval(Packet{InIface: sessA.Iface, Src: v6src, Dst: netip.AddrPortFrom(v6, 443), Proto: ProtoTCP, CtState: CtStateNew})
	requireDrop(t, web, "v6 tcp/443 to force-admitted addr (allow6 dormant)")
	dns := h.mustEval(Packet{InIface: sessA.Iface, Src: v6src, Dst: ap("[2606:4700:4700::1111]:53"), Proto: ProtoUDP, CtState: CtStateNew})
	requireDrop(t, dns, "v6 udp/53 (IPv6 is a closed door in v0)")

	// The dormant set is nonetheless removed cleanly at DetachSession.
	h.detach(sessA.ID)
	_, err := h.reader.Entries(h.ctx, sessA.ID, FamilyIPv6)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Entries(v6) after detach: err = %v, want ErrSessionNotFound", err)
	}
}
