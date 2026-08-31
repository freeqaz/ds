package dnsgate

// DNS-4 — rebinding defense: dual-stack scrub tables (incl. embedded IPv4),
// end-to-end rebinding failure, full re-admission on re-resolution,
// answered ⊆ admitted as a pure property, and HTTPS/SVCB suppression.

import (
	"math/rand"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// planRef: doc 09 §4 DNS-4 rule 2 (IPv4 half) + doc 06 §3(c) rebinding row
func TestScrubAddr_IPv4Table(t *testing.T) {
	cfg := defaultScrubConfig() // HostRanges4: 198.51.100.0/24, 0.0.0.0/8, 255.255.255.255/32
	cases := []struct {
		addr       string
		wantAdmit  bool
		wantReason ScrubReason
	}{
		// Scrubbed.
		{"10.0.0.5", false, ReasonPrivate4},
		{"172.16.1.1", false, ReasonPrivate4},
		{"172.31.255.255", false, ReasonPrivate4},
		{"192.168.0.1", false, ReasonPrivate4},
		{"169.254.169.254", false, ReasonLinkLocal4},
		{"127.0.0.1", false, ReasonLoopback4},
		{"0.0.0.0", false, ReasonHostRange4},         // 0.0.0.0/8 listed as a host/boundary range
		{"255.255.255.255", false, ReasonHostRange4}, // broadcast listed as a host/boundary range
		{"198.51.100.7", false, ReasonHostRange4},    // cfg.HostRanges4 hit
		// Admitted.
		{"93.184.216.34", true, ReasonNone},
		{"8.8.8.8", true, ReasonNone},
		{"172.32.0.1", true, ReasonNone}, // just outside 172.16.0.0/12
		{"1.1.1.1", true, ReasonNone},
		// Prefix boundaries land on the right side.
		{"172.15.255.255", true, ReasonNone},
		{"172.16.0.0", false, ReasonPrivate4},
		{"10.255.255.255", false, ReasonPrivate4},
		{"11.0.0.0", true, ReasonNone},
		{"192.168.255.255", false, ReasonPrivate4},
		{"192.169.0.0", true, ReasonNone},
		{"169.253.255.255", true, ReasonNone},
		{"169.254.0.0", false, ReasonLinkLocal4},
		{"169.255.0.0", true, ReasonNone},
		{"126.255.255.255", true, ReasonNone},
		{"127.255.255.255", false, ReasonLoopback4},
		{"128.0.0.0", true, ReasonNone},
		{"198.51.101.0", true, ReasonNone}, // just outside the host range
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			admit, reason := ScrubAddr(mkAddr(tc.addr), cfg)
			if admit != tc.wantAdmit || reason != tc.wantReason {
				t.Errorf("ScrubAddr(%s) = (%v, %d), want (%v, %d)", tc.addr, admit, reason, tc.wantAdmit, tc.wantReason)
			}
		})
	}
}

// planRef: doc 09 §4 DNS-4 rule 2 (IPv6 half: ::1, fe80::/10, fc00::/7, host's own addrs)
func TestScrubAddr_IPv6Table(t *testing.T) {
	cfg := defaultScrubConfig() // HostAddrs6: 2001:db8::5
	cases := []struct {
		addr       string
		wantAdmit  bool
		wantReason ScrubReason
	}{
		{"::1", false, ReasonLoopback6},
		{"fe80::1", false, ReasonLinkLocal6},
		{"febf::1", false, ReasonLinkLocal6}, // top of fe80::/10
		{"fc00::1", false, ReasonULA6},
		{"fdff:ffff::1", false, ReasonULA6},     // top of fc00::/7
		{"2001:db8::5", false, ReasonHostAddr6}, // cfg.HostAddrs6 member
		// Public GUAs admitted (by this rule; v0 AAAA-strip is separate).
		{"2606:4700:4700::1111", true, ReasonNone},
		{"2620:fe::fe", true, ReasonNone},
		// fec0::/10 (deprecated site-local) is outside fe80::/10: admitted by
		// THIS rule.
		{"fec0::1", true, ReasonNone},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			admit, reason := ScrubAddr(mkAddr(tc.addr), cfg)
			if admit != tc.wantAdmit || reason != tc.wantReason {
				t.Errorf("ScrubAddr(%s) = (%v, %d), want (%v, %d)", tc.addr, admit, reason, tc.wantAdmit, tc.wantReason)
			}
		})
	}
}

// planRef: doc 09 §4 DNS-4 rule 2 (embedded-IPv4: ::ffff:0:0/96 and 64:ff9b::/96) + §9 'Rebinding fails (incl. IPv4-mapped IPv6)'
func TestScrubAddr_EmbeddedIPv4_MappedAndNAT64(t *testing.T) {
	cfg := defaultScrubConfig()
	cases := []struct {
		addr       string
		wantAdmit  bool
		wantReason ScrubReason
	}{
		// Private/loopback/link-local/host embeddings: extracted and re-judged
		// by the IPv4 rules → ReasonEmbedded4.
		{"::ffff:10.0.0.5", false, ReasonEmbedded4},
		{"::ffff:127.0.0.1", false, ReasonEmbedded4},
		{"::ffff:169.254.169.254", false, ReasonEmbedded4},
		{"::ffff:192.168.1.1", false, ReasonEmbedded4},
		{"64:ff9b::10.0.0.5", false, ReasonEmbedded4},   // NAT64, embeds 10.0.0.5
		{"64:ff9b::7f00:1", false, ReasonEmbedded4},     // NAT64, embeds 127.0.0.1
		{"::ffff:198.51.100.7", false, ReasonEmbedded4}, // embeds a HostRanges4 member
		// Public embeddings pass THIS rule. (v0 AAAA-strip still withholds
		// them from answers — that posture is FilterRecords', not ScrubAddr's.)
		{"::ffff:93.184.216.34", true, ReasonNone},
		{"64:ff9b::5db8:d822", true, ReasonNone}, // embeds 93.184.216.34
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			admit, reason := ScrubAddr(mkAddr(tc.addr), cfg)
			if admit != tc.wantAdmit || reason != tc.wantReason {
				t.Errorf("ScrubAddr(%s) = (%v, %d), want (%v, %d)", tc.addr, admit, reason, tc.wantAdmit, tc.wantReason)
			}
		})
	}

	// Property: the verdict for ::ffff:X always equals the verdict for plain X.
	for _, v4 := range []string{
		"10.0.0.5", "172.16.1.1", "192.168.0.1", "169.254.169.254", "127.0.0.1",
		"198.51.100.7", "93.184.216.34", "8.8.8.8", "1.1.1.1", "172.32.0.1",
	} {
		plainAdmit, _ := ScrubAddr(mkAddr(v4), cfg)
		mappedAdmit, _ := ScrubAddr(mkAddr("::ffff:"+v4), cfg)
		if plainAdmit != mappedAdmit {
			t.Errorf("verdict mismatch: ScrubAddr(%s) admit=%v but ScrubAddr(::ffff:%s) admit=%v", v4, plainAdmit, v4, mappedAdmit)
		}
	}
}

// planRef: doc 09 §4 DNS-4 Done-when ('never to an internal one incl. the IPv4-mapped-IPv6 case') + doc 06 §3(c)
func TestRebind_PrivateReResolution_ScrubbedNeverAdmittedNeverAnswered(t *testing.T) {
	publicAddr := mkAddr("93.184.216.34")
	internal := []struct {
		addr       string
		wantReason ScrubReason
	}{
		{"10.0.0.5", ReasonPrivate4},
		{"127.0.0.1", ReasonLoopback4},
		{"169.254.169.254", ReasonLinkLocal4},
		{"::ffff:10.0.0.5", ReasonEmbedded4},
		{"64:ff9b::a00:5", ReasonEmbedded4}, // NAT64 embedding 10.0.0.5
		{"198.51.100.7", ReasonHostRange4},  // host boundary addr
	}
	for _, tc := range internal {
		t.Run(tc.addr, func(t *testing.T) {
			e := newEnv(t)
			e.policy.set("rebind.example", allowDec("org/rebind"))
			internalChain := ResolutionChain{
				QueryName: "rebind.example",
				Terminal:  []AddrRecord{{Addr: mkAddr(tc.addr), TTL: 60}},
			}
			e.upstream.script("rebind.example",
				aChain("rebind.example", 60, publicAddr.String()),
				internalChain,
			)
			q := Query{Session: sess1, Name: "rebind.example", Type: TypeA, Proto: "udp"}

			// First resolution: public, admitted.
			ans1 := e.mustServe(q)
			if ans1.RCode != RCodeNoError || !answerAddrSet(ans1)[publicAddr] {
				t.Fatalf("first resolution rcode=%d addrs=%v, want NoError with %s", ans1.RCode, addrRecords(ans1), publicAddr)
			}
			if !e.containsAddr(sess1, publicAddr) {
				t.Fatal("public addr not admitted on first resolution")
			}
			expBefore, ok := e.lookup(sess1, "rebind.example", publicAddr)
			if !ok {
				t.Fatal("public admission missing from the map")
			}

			// TTL expires (answer TTL 60s; admission 60s+45s grace still live);
			// the upstream has rebound to an internal address.
			e.clock.Advance(61 * time.Second)
			ans2 := e.mustServe(q)
			if ans2.RCode != RCodeNoError {
				t.Errorf("re-query RCode = %d, want NoError with zero address records (scrubbed, not refused)", ans2.RCode)
			}
			if n := len(addrRecords(ans2)); n != 0 {
				t.Errorf("re-query answered %d address records (%v) — internal address leaked", n, addrRecords(ans2))
			}
			internalAddr := mkAddr(tc.addr)
			if e.containsAddr(sess1, internalAddr) {
				t.Errorf("ContainsAddr(%s) = true — internal address entered the allow-set", internalAddr)
			}
			if _, ok := e.lookup(sess1, "rebind.example", internalAddr); ok {
				t.Errorf("Lookup(rebind.example, %s) hit — internal address entered the admission map", internalAddr)
			}
			// Original public admission untouched (not extended, not destroyed).
			expAfter, ok := e.lookup(sess1, "rebind.example", publicAddr)
			if !ok {
				t.Error("original public admission destroyed by the scrubbed re-resolution")
			} else if !expAfter.ExpiresAt.Equal(expBefore.ExpiresAt) {
				t.Errorf("original public admission expiry changed: %v → %v", expBefore.ExpiresAt, expAfter.ExpiresAt)
			}

			// Pure half: Plan.Scrubbed records the addr + reason for the audit trail.
			plan, err := PlanResponse(q, allowDec("org/rebind"), &internalChain, e.cfg, e.clock.Now())
			if err != nil {
				t.Fatalf("PlanResponse: %v", err)
			}
			if plan.Admission != nil {
				t.Errorf("Plan.Admission = %+v for an all-internal chain, want nil", plan.Admission)
			}
			if n := len(addrRecords(plan.Answer)); n != 0 {
				t.Errorf("Plan answers %d address records for an all-internal chain", n)
			}
			found := false
			for _, s := range plan.Scrubbed {
				if s.Addr == internalAddr {
					found = true
					if s.Reason != tc.wantReason {
						t.Errorf("Plan.Scrubbed reason for %s = %d, want %d", internalAddr, s.Reason, tc.wantReason)
					}
				}
			}
			if !found {
				t.Errorf("Plan.Scrubbed missing audit entry for %s", internalAddr)
			}
		})
	}
}

// planRef: doc 09 §4 DNS-4 rule 3 (re-resolutions go through full admission) + §9 'allow-set never silently widens'
func TestRebind_ReResolutionGoesThroughFullAdmission_NoSilentWidening(t *testing.T) {
	a1, a2 := mkAddr("93.184.216.34"), mkAddr("203.0.113.10")

	t.Run("new public address requires policy+scrub+Admit again", func(t *testing.T) {
		e := newEnv(t)
		e.policy.set("rotate.example", allowDec("org/rotate"))
		e.upstream.script("rotate.example",
			aChain("rotate.example", 60, a1.String()),
			aChain("rotate.example", 60, a2.String()),
		)
		q := Query{Session: sess1, Name: "rotate.example", Type: TypeA, Proto: "udp"}

		ans1 := e.mustServe(q)
		if ans1.RCode != RCodeNoError || !answerAddrSet(ans1)[a1] {
			t.Fatalf("first resolution: rcode=%d addrs=%v", ans1.RCode, addrRecords(ans1))
		}
		if got := len(e.policy.callLog()); got != 1 {
			t.Fatalf("EvaluateDomain calls after first query = %d, want 1", got)
		}

		e.clock.Advance(61 * time.Second)
		ans2 := e.mustServe(q)
		if ans2.RCode != RCodeNoError || !answerAddrSet(ans2)[a2] {
			t.Fatalf("re-resolution: rcode=%d addrs=%v, want NoError with %s", ans2.RCode, addrRecords(ans2), a2)
		}
		// Full admission again: policy re-evaluated, fresh AdmissionTx for A2
		// recorded before the answer — never an answer-without-Admit.
		if got := len(e.policy.callLog()); got != 2 {
			t.Errorf("EvaluateDomain calls after re-resolution = %d, want 2 (full re-admission)", got)
		}
		admits := e.store.admitLog()
		if len(admits) != 2 {
			t.Fatalf("AdmissionTx count = %d, want 2 (one per resolution)", len(admits))
		}
		secondAddrs := admits[1].Tx.Addrs
		if len(secondAddrs) != 1 || secondAddrs[0] != a2 {
			t.Errorf("second AdmissionTx.Addrs = %v, want exactly %s", secondAddrs, a2)
		}
		if !e.containsAddr(sess1, a2) {
			t.Error("A2 answered but not in the allow-set")
		}
	})

	t.Run("policy flipped to Deny between resolutions", func(t *testing.T) {
		e := newEnv(t)
		e.policy.set("rotate.example", allowDec("org/rotate"))
		e.upstream.script("rotate.example",
			aChain("rotate.example", 60, a1.String()),
			aChain("rotate.example", 60, a2.String()),
		)
		q := Query{Session: sess1, Name: "rotate.example", Type: TypeA, Proto: "udp"}

		ans1 := e.mustServe(q)
		if ans1.RCode != RCodeNoError {
			t.Fatalf("first resolution rcode = %d", ans1.RCode)
		}
		expBefore, ok := e.lookup(sess1, "rotate.example", a1)
		if !ok {
			t.Fatal("A1 admission missing")
		}

		e.policy.set("rotate.example", denyDec("org/blocked-now"))
		e.clock.Advance(61 * time.Second)

		ans2 := e.mustServe(q)
		if ans2.RCode != RCodeRefused {
			t.Errorf("post-flip RCode = %d, want REFUSED", ans2.RCode)
		}
		if answerAddrSet(ans2)[a2] || e.containsAddr(sess1, a2) {
			t.Errorf("A2 leaked after the policy flip (answered=%v, in set=%v)", answerAddrSet(ans2)[a2], e.containsAddr(sess1, a2))
		}
		// A1's existing entry is not extended by the refused re-query.
		expAfter, ok := e.lookup(sess1, "rotate.example", a1)
		if ok && !expAfter.ExpiresAt.Equal(expBefore.ExpiresAt) {
			t.Errorf("A1 admission extended by a refused query: %v → %v", expBefore.ExpiresAt, expAfter.ExpiresAt)
		}
	})
}

// planRef: doc 09 §4 DNS-4 rule 1 (the VM is only ever answered with addresses that were actually admitted)
func TestPlanResponse_AnsweredAddrsSubsetOfAdmitted_Property(t *testing.T) {
	cfg := defaultConfig()
	now := newFakeClock().Now()
	q := Query{Session: sess1, Name: "prop.example", Type: TypeA, Proto: "udp"}
	dec := allowDec("org/prop")

	check := func(t *testing.T, terminal []netip.Addr) {
		t.Helper()
		chain := ResolutionChain{QueryName: "prop.example"}
		for _, a := range terminal {
			chain.Terminal = append(chain.Terminal, AddrRecord{Addr: a, TTL: 120})
		}
		plan, err := PlanResponse(q, dec, &chain, cfg, now)
		if err != nil {
			t.Fatalf("PlanResponse(%v): %v", terminal, err)
		}
		admitted := map[netip.Addr]bool{}
		if plan.Admission != nil {
			for _, a := range plan.Admission.Addrs {
				admitted[a] = true
			}
		}
		answered := answerAddrSet(plan.Answer)
		for a := range answered {
			if !admitted[a] {
				t.Errorf("terminal %v: answered addr %s was not admitted (answer ⊄ admission)", terminal, a)
			}
		}
		// Every excluded addr appears in Plan.Scrubbed with a real reason.
		scrubbed := map[netip.Addr]ScrubReason{}
		for _, s := range plan.Scrubbed {
			scrubbed[s.Addr] = s.Reason
		}
		for _, a := range terminal {
			if admitted[a] {
				continue
			}
			r, ok := scrubbed[a]
			if !ok {
				t.Errorf("terminal %v: excluded addr %s missing from Plan.Scrubbed", terminal, a)
			} else if r == ReasonNone {
				t.Errorf("terminal %v: excluded addr %s scrubbed with ReasonNone", terminal, a)
			}
		}
	}

	t.Run("mixed public+private answers and admits only the public addr", func(t *testing.T) {
		pub, priv := mkAddr("93.184.216.34"), mkAddr("10.0.0.5")
		chain := ResolutionChain{QueryName: "prop.example", Terminal: []AddrRecord{{Addr: pub, TTL: 120}, {Addr: priv, TTL: 120}}}
		plan, err := PlanResponse(q, dec, &chain, cfg, now)
		if err != nil {
			t.Fatalf("PlanResponse: %v", err)
		}
		if plan.Admission == nil {
			t.Fatal("no admission for the mixed case")
		}
		if !reflect.DeepEqual(plan.Admission.Addrs, []netip.Addr{pub}) {
			t.Errorf("admitted = %v, want exactly [%s]", plan.Admission.Addrs, pub)
		}
		ansSet := answerAddrSet(plan.Answer)
		if !ansSet[pub] || ansSet[priv] || len(ansSet) != 1 {
			t.Errorf("answered = %v, want exactly {%s}", ansSet, pub)
		}
		check(t, []netip.Addr{pub, priv})
	})

	t.Run("all-private admits nothing and answers nothing", func(t *testing.T) {
		priv := []netip.Addr{mkAddr("10.0.0.5"), mkAddr("192.168.0.1")}
		chain := ResolutionChain{QueryName: "prop.example", Terminal: []AddrRecord{{Addr: priv[0], TTL: 120}, {Addr: priv[1], TTL: 120}}}
		plan, err := PlanResponse(q, dec, &chain, cfg, now)
		if err != nil {
			t.Fatalf("PlanResponse: %v", err)
		}
		if plan.Admission != nil {
			t.Errorf("Plan.Admission = %+v, want nil for an all-private chain", plan.Admission)
		}
		if n := len(addrRecords(plan.Answer)); n != 0 {
			t.Errorf("answered %d address records for an all-private chain", n)
		}
		check(t, priv)
	})

	t.Run("empty terminal set", func(t *testing.T) {
		check(t, nil)
	})

	t.Run("duplicates", func(t *testing.T) {
		check(t, []netip.Addr{mkAddr("8.8.8.8"), mkAddr("8.8.8.8"), mkAddr("10.0.0.5")})
	})

	t.Run("embedded mix", func(t *testing.T) {
		check(t, []netip.Addr{mkAddr("93.184.216.34"), mkAddr("::ffff:10.0.0.5")})
	})

	t.Run("randomized sweep", func(t *testing.T) {
		pool := []netip.Addr{
			mkAddr("93.184.216.34"), mkAddr("8.8.8.8"), mkAddr("1.1.1.1"), mkAddr("203.0.113.10"),
			mkAddr("10.0.0.5"), mkAddr("192.168.0.1"), mkAddr("172.16.1.1"), mkAddr("127.0.0.1"),
			mkAddr("169.254.169.254"), mkAddr("::ffff:10.0.0.5"), mkAddr("64:ff9b::7f00:1"),
			mkAddr("198.51.100.7"), mkAddr("0.0.0.0"),
		}
		rng := rand.New(rand.NewSource(0xD5)) // deterministic
		for i := 0; i < 200; i++ {
			n := rng.Intn(6)
			set := make([]netip.Addr, 0, n)
			for j := 0; j < n; j++ {
				set = append(set, pool[rng.Intn(len(pool))])
			}
			check(t, set)
		}
	})
}

// planRef: doc 09 §4 DNS-4 rule 4 (HTTPS/SVCB suppressed entirely) + §9 'no HTTPS/SVCB answer reaches a VM'
func TestSuppress_HTTPSAndSVCBQueries_NeverAnswered(t *testing.T) {
	// A real-shaped HTTPS rdata: priority 1, ech config, alpn h3,h2.
	echRdata := []byte("\x00\x01\x00ech=AEX+DQBA0gAgACCm...;alpn=h3,h2")
	for _, tc := range []struct {
		name  string
		qtype RRType
	}{
		{"HTTPS(65)", TypeHTTPS},
		{"SVCB(64)", TypeSVCB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.policy.set("svc.example", allowDec("org/svc"))
			e.upstream.scriptQ("svc.example", tc.qtype, ResolutionChain{
				QueryName: "svc.example",
				Extra: []RR{
					{Name: "svc.example", Type: tc.qtype, TTL: 300, Data: echRdata},
				},
			})
			// Also script the generic path in case the gate resolves A instead.
			e.upstream.script("svc.example", aChain("svc.example", 300, "93.184.216.34"))

			ans := e.mustServe(Query{Session: sess1, Name: "svc.example", Type: tc.qtype, Proto: "udp"})

			// Suppression, not denial: the domain is allowed.
			if ans.RCode != RCodeNoError {
				t.Errorf("RCode = %d, want NoError (suppression, not denial)", ans.RCode)
			}
			// Sweep over Answers+Authority+Additionals.
			for _, qt := range []RRType{TypeHTTPS, TypeSVCB} {
				if got := recordsOfType(ans, qt); len(got) != 0 {
					t.Errorf("answer carries %d type-%d records: %v", len(got), qt, got)
				}
			}
			if n := len(ans.Answers); n != 0 {
				t.Errorf("suppressed qtype answered %d records, want empty answer section", n)
			}
			// Nothing admitted from the suppressed records.
			if n := len(e.store.admitLog()); n != 0 {
				t.Errorf("%d AdmissionTx from a suppressed-type query, want 0", n)
			}
		})
	}
}

// planRef: doc 09 §4 DNS-4 rule 4 + DNS-2 chain handling (chain.Extra path)
func TestSuppress_HTTPSRecordSmuggledInAdditionals_Stripped(t *testing.T) {
	e := newEnv(t)
	e.policy.set("smuggle.example", allowDec("org/smuggle"))
	terminal := mkAddr("93.184.216.34")
	chain := aChain("smuggle.example", 120, terminal.String())
	chain.Extra = []RR{
		// Legitimate-looking glue.
		{Name: "ns.smuggle.example", Type: TypeA, TTL: 300, Addr: mkAddr("203.0.113.53")},
		// Smuggled type-65/64 with ECH + h3 steering rdata.
		{Name: "smuggle.example", Type: TypeHTTPS, TTL: 300, Data: []byte("ech=AEX...;alpn=h3,h2")},
		{Name: "smuggle.example", Type: TypeSVCB, TTL: 300, Data: []byte("alpn=h3")},
	}
	e.upstream.script("smuggle.example", chain)

	ans := e.mustServe(Query{Session: sess1, Name: "smuggle.example", Type: TypeA, Proto: "udp"})
	if ans.RCode != RCodeNoError {
		t.Fatalf("RCode = %d, want NoError", ans.RCode)
	}
	if got := recordsOfType(ans, TypeA); len(got) == 0 || got[0].Addr != terminal {
		t.Errorf("legitimate A record missing or wrong: %v", got)
	}
	for _, qt := range []RRType{TypeHTTPS, TypeSVCB} {
		if got := recordsOfType(ans, qt); len(got) != 0 {
			t.Errorf("type-%d record smuggled through (%d records) — ECH config escaped suppression", qt, len(got))
		}
	}

	// Pure half: the strip is section-independent and composes with AAAA-strip.
	a := RR{Name: "smuggle.example", Type: TypeA, TTL: 120, Addr: terminal}
	aaaa := RR{Name: "smuggle.example", Type: TypeAAAA, TTL: 120, Addr: mkAddr("2606:4700:4700::1111")}
	cname := RR{Name: "smuggle.example", Type: TypeCNAME, TTL: 120, Target: "cdn.example"}
	https := RR{Name: "smuggle.example", Type: TypeHTTPS, TTL: 300, Data: []byte("ech=AEX...")}
	svcb := RR{Name: "smuggle.example", Type: TypeSVCB, TTL: 300, Data: []byte("alpn=h3")}
	cases := []struct {
		name    string
		in      []RR
		posture Posture
		want    []RR
	}{
		{"suppress only", []RR{a, https, aaaa, svcb, cname}, Posture{SuppressHTTPSSVCB: true}, []RR{a, aaaa, cname}},
		{"suppress composes with AAAA strip", []RR{a, https, aaaa, svcb, cname}, Posture{StripAAAA: true, SuppressHTTPSSVCB: true}, []RR{a, cname}},
		{"all suppressed", []RR{https, svcb}, Posture{SuppressHTTPSSVCB: true}, []RR{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FilterRecords(tc.in, tc.posture)
			if len(got) != len(tc.want) || (len(got) > 0 && !reflect.DeepEqual(got, tc.want)) {
				t.Errorf("FilterRecords = %v, want %v", got, tc.want)
			}
		})
	}
}
