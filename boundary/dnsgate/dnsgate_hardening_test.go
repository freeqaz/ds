package dnsgate

// DNS-5 — hardening: malformed packets, UDP truncation + TCP retry, cache
// behavior vs live admission, poisoning posture, fleet-storm concurrency.

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// planRef: doc 09 §4 DNS-5 (malformed queries)
func TestHardening_MalformedPackets_NoPanicNoAdmission(t *testing.T) {
	e := newEnv(t)
	e.policy.set("ok.example", allowDec("org/ok"))
	e.upstream.script("ok.example", aChain("ok.example", 120, "93.184.216.34"))

	rng := rand.New(rand.NewSource(0xBAD))
	random64k := make([]byte, 64*1024)
	rng.Read(random64k)

	// Header claiming QDCOUNT=5 with only one question present.
	qdcount5 := dnsQueryPacket(0x1001, "x.example", TypeA)
	qdcount5[4], qdcount5[5] = 0x00, 0x05

	// Name-compression pointer loop: the QNAME is a pointer to itself.
	loop := []byte{0x10, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x0C, // pointer to offset 12 = the pointer itself
		0x00, 0x01, 0x00, 0x01}

	// Label with an invalid >63 length octet (0x44 = 68; 01xxxxxx is reserved).
	longLabel := append([]byte{0x10, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44},
		bytes.Repeat([]byte{'a'}, 68)...)
	longLabel = append(longLabel, 0x00, 0x00, 0x01, 0x00, 0x01)

	// Total name >255 bytes: five 63-byte labels.
	longName := []byte{0x10, 0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 5; i++ {
		longName = append(longName, 63)
		longName = append(longName, bytes.Repeat([]byte{'b'}, 63)...)
	}
	longName = append(longName, 0x00, 0x00, 0x01, 0x00, 0x01)

	// Per-case verdict (DNS-5.a "FORMERR or no response (dropped) per case"):
	//   wantDrop    — no complete header to answer: the packet must be dropped.
	//   wantFormErr — complete 12-byte header with a recoverable ID and a
	//                 malformed question: an in-band FORMERR echoing the query
	//                 ID, so the VM's stub resolver fails fast instead of
	//                 retrying into a black hole.
	//   wantEither  — header bytes present but untrustworthy: drop is fine;
	//                 any response that IS sent must still be a FORMERR.
	const (
		wantDrop = iota
		wantFormErr
		wantEither
	)

	cases := []struct {
		name   string
		packet []byte
		want   int
		id     uint16 // the query ID a FORMERR must echo (wantFormErr only)
	}{
		{"truncated 4-byte header", []byte{0x12, 0x34, 0x01, 0x00}, wantDrop, 0},
		{"QDCOUNT=5 with one question", qdcount5, wantFormErr, 0x1001},
		{"compression pointer loop", loop, wantFormErr, 0x1002},
		{"label longer than 63 bytes", longLabel, wantFormErr, 0x1003},
		{"name longer than 255 bytes", longName, wantFormErr, 0x1004},
		{"zero-byte packet", []byte{}, wantDrop, 0},
		{"64KiB random bytes", random64k, wantEither, 0},
		{"valid header plus trailing garbage", append(dnsQueryPacket(0x1005, "ok.example", TypeA), random64k[:100]...), wantEither, 0x1005},
	}

	assertFormErr := func(t *testing.T, resp []byte, wantID uint16, checkID bool) {
		t.Helper()
		if len(resp) < 12 {
			t.Fatalf("response shorter than a DNS header: %d bytes", len(resp))
		}
		if !rawQR(resp) {
			t.Error("response does not have the QR bit set")
		}
		if rc := rawRCode(resp); rc != RCodeFormErr {
			t.Errorf("RCODE = %d, want FORMERR", rc)
		}
		if checkID {
			if got := rawID(resp); got != wantID {
				t.Errorf("response ID = %#04x, want the query ID %#04x echoed", got, wantID)
			}
		}
	}

	for _, proto := range []string{"udp", "tcp"} {
		for _, tc := range cases {
			t.Run(proto+"/"+tc.name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("ServeRaw panicked on %s: %v", tc.name, r)
					}
				}()
				resp, err := e.resp.ServeRaw(context.Background(), sess1, proto, tc.packet)
				responded := err == nil && len(resp) > 0
				switch tc.want {
				case wantDrop:
					if responded {
						t.Errorf("got a %d-byte response, want the packet dropped (no response)", len(resp))
					}
				case wantFormErr:
					if !responded {
						t.Fatalf("packet dropped (err=%v, %d bytes), want an in-band FORMERR", err, len(resp))
					}
					assertFormErr(t, resp, tc.id, true)
				case wantEither:
					if responded {
						assertFormErr(t, resp, tc.id, tc.id != 0)
					}
				}
			})
		}
	}

	// Garbage mutated nothing.
	if n := len(e.store.admitLog()); n != 0 {
		t.Errorf("%d Admit calls caused by malformed packets, want 0", n)
	}
	if n := len(e.upstream.callLog()); n != 0 {
		t.Errorf("%d Upstream.Resolve calls caused by malformed packets, want 0", n)
	}
	if n := len(e.notifier.requests()); n != 0 {
		t.Errorf("%d Notify calls caused by malformed packets, want 0", n)
	}

	// A subsequent valid query on the SAME Responder still works — through the
	// raw path itself. ServeRaw is the real port-53 surface: a drop-everything
	// raw path (which would trivially satisfy the garbage table) must fail
	// here, and insert-then-answer must hold on the raw path too.
	okAddr := mkAddr("93.184.216.34")
	for i, proto := range []string{"udp", "tcp"} {
		id := uint16(0x2001 + i)
		resp, err := e.resp.ServeRaw(context.Background(), sess1, proto, dnsQueryPacket(id, "ok.example", TypeA))
		if err != nil {
			t.Fatalf("ServeRaw(%s) for a valid query after the garbage table: %v — the raw surface must still serve", proto, err)
		}
		if len(resp) < 12 {
			t.Fatalf("ServeRaw(%s) valid-query response shorter than a DNS header: %d bytes", proto, len(resp))
		}
		if !rawQR(resp) {
			t.Errorf("ServeRaw(%s) valid-query response does not have the QR bit set", proto)
		}
		if got := rawID(resp); got != id {
			t.Errorf("ServeRaw(%s) valid-query response ID = %#04x, want %#04x", proto, got, id)
		}
		if rc := rawRCode(resp); rc != RCodeNoError {
			t.Errorf("ServeRaw(%s) valid-query RCODE = %d, want NoError", proto, rc)
		}
		if !e.containsAddr(sess1, okAddr) {
			t.Errorf("ServeRaw(%s) answered ok.example without admitting %s — insert-then-answer must hold on the raw path", proto, okAddr)
		}
	}

	// Second probe: the structured path also still works.
	ans := e.mustServe(Query{Session: sess1, Name: "ok.example", Type: TypeA, Proto: "udp"})
	if ans.RCode != RCodeNoError || !answerAddrSet(ans)[okAddr] {
		t.Errorf("valid query after the garbage table: rcode=%d addrs=%v, want NoError with 93.184.216.34", ans.RCode, addrRecords(ans))
	}
}

// planRef: doc 09 §4 DNS-5 (large answers over TCP)
func TestHardening_LargeAnswer_UDPTruncatesThenTCPFull_AdmissionOrderingHolds(t *testing.T) {
	e := newEnv(t)
	e.policy.set("big.example", allowDec("org/big"))
	var all []netip.Addr
	chain := ResolutionChain{QueryName: "big.example"}
	for i := 1; i <= 40; i++ {
		a := mkAddr(fmt.Sprintf("93.184.217.%d", i))
		all = append(all, a)
		chain.Terminal = append(chain.Terminal, AddrRecord{Addr: a, TTL: 300})
	}
	e.upstream.script("big.example", chain)

	// UDP first: the 40-record answer exceeds the UDP payload limit.
	udpAns := e.mustServe(Query{Session: sess1, Name: "big.example", Type: TypeA, Proto: "udp"})
	if udpAns.RCode != RCodeNoError {
		t.Fatalf("UDP RCode = %d, want NoError", udpAns.RCode)
	}
	if !udpAns.Truncated {
		t.Error("UDP answer with 40 A records is not Truncated — TC bit missing, clients will never retry over TCP")
	}
	for _, rr := range addrRecords(udpAns) {
		if !e.containsAddr(sess1, rr.Addr) {
			t.Errorf("UDP answered %s without admission", rr.Addr)
		}
	}

	// TCP retry: a first-class admission path — insert-then-answer holds too.
	tcpAns := e.assertInsertThenAnswer(Query{Session: sess1, Name: "big.example", Type: TypeA, Proto: "tcp"})
	if tcpAns.RCode != RCodeNoError {
		t.Fatalf("TCP RCode = %d, want NoError", tcpAns.RCode)
	}
	if tcpAns.Truncated {
		t.Error("TCP answer is Truncated — the full set must fit over TCP")
	}
	got := answerAddrSet(tcpAns)
	for _, a := range all {
		if !got[a] {
			t.Errorf("TCP answer missing %s (want the full 40-record set)", a)
		}
		if !e.containsAddr(sess1, a) {
			t.Errorf("TCP answered %s without admission", a)
		}
	}
	// One admission map entry covering the full set.
	adm, ok := e.lookup(sess1, "big.example", all[0])
	if !ok {
		t.Fatal("admission map missing big.example")
	}
	have := map[netip.Addr]bool{}
	for _, a := range adm.Addrs {
		have[a] = true
	}
	for _, a := range all {
		if !have[a] {
			t.Errorf("admission map entry missing %s — must cover the full set", a)
		}
	}
}

// planRef: doc 09 §4 DNS-5 (cache behavior) + DNS-4 rule 1 + OQ3
func TestHardening_CacheHit_StillGuaranteesLiveAdmissionBeforeAnswer(t *testing.T) {
	e := newEnv(t)
	e.policy.set("cached.example", allowDec("org/cached"))
	addr := mkAddr("93.184.216.34")
	// Upstream TTL 3600s: the answered TTL clamps to the 900s ceiling, the
	// allow-set element expires at 900s clamp + 45s grace = 945s, but any
	// answer cache keyed on the UPSTREAM TTL still holds the answer at +946s.
	// This puts the clock exactly in the spec's window: past admission expiry
	// but within the answer-cache lifetime.
	e.upstream.script("cached.example", aChain("cached.example", 3600, addr.String()))
	q := Query{Session: sess1, Name: "cached.example", Type: TypeA, Proto: "udp"}

	ans1 := e.mustServe(q)
	if ans1.RCode != RCodeNoError {
		t.Fatalf("first query rcode = %d", ans1.RCode)
	}
	firstAdmits := len(e.store.admitLog())
	if firstAdmits == 0 {
		t.Fatal("first query produced no admission")
	}

	// Past the allow-set element expiry (900s clamp + 45s grace = 945s) and
	// within the upstream's 3600s answer lifetime: an internal answer cache
	// may still hold the answer, but the firewall no longer admits the addr.
	e.clock.Advance(946 * time.Second)
	if e.containsAddr(sess1, addr) {
		t.Fatal("test precondition: admission should have expired at +946s")
	}

	ans2 := e.mustServe(q)
	if ans2.RCode != RCodeNoError {
		t.Fatalf("re-query rcode = %d, want NoError", ans2.RCode)
	}
	if !answerAddrSet(ans2)[addr] {
		t.Fatalf("re-query missing %s", addr)
	}
	// At the instant the second answer returned, admission is live again:
	// a cache hit must re-arm admission before answering, never release the
	// answer against an expired firewall entry.
	if !e.containsAddr(sess1, addr) {
		t.Error("answer released while ContainsAddr=false — answered-but-expired-in-the-firewall window")
	}
	if _, ok := e.lookup(sess1, "cached.example", addr); !ok {
		t.Error("answer released while the admission map entry is expired")
	}
	admits := e.store.admitLog()
	if len(admits) <= firstAdmits {
		t.Error("no fresh/refreshed AdmissionTx recorded for the post-expiry answer")
	} else {
		last := admits[len(admits)-1]
		if !last.At.Equal(e.clock.Now()) {
			t.Errorf("refreshed AdmissionTx recorded at %v, want the second-query instant %v", last.At, e.clock.Now())
		}
	}
	// If an upstream re-resolution happened, it went through full DNS-4.e
	// admission (policy re-evaluated).
	if len(e.upstream.callLog()) > 1 && len(e.policy.callLog()) < 2 {
		t.Error("re-resolved upstream without re-evaluating policy — bypassed full admission")
	}
}

// planRef: doc 09 §4 DNS-5 (poisoning posture: upstream path uses host's protected egress) + POL-2 resolver rows
func TestHardening_UpstreamOnlyViaConfiguredResolvers(t *testing.T) {
	e := newEnv(t)
	e.policy.set("ns-trap.example", allowDec("org/ns-trap"))
	terminal := mkAddr("93.184.216.34")
	glueAddr := mkAddr("203.0.113.66")
	chain := aChain("ns-trap.example", 120, terminal.String())
	// VM/attacker-influenceable NS + glue hints pointing at a rogue resolver.
	chain.Extra = []RR{
		{Name: "ns-trap.example", Type: TypeNS, TTL: 300, Target: "attacker-resolver.example"},
		{Name: "attacker-resolver.example", Type: TypeA, TTL: 300, Addr: glueAddr},
	}
	e.upstream.script("ns-trap.example", chain)
	// Deliberately NO script for attacker-resolver.example: a Resolve call for
	// it (i.e. following the hint) errors out of the fake and shows in the log.

	ans := e.mustServe(Query{Session: sess1, Name: "ns-trap.example", Type: TypeA, Proto: "udp"})
	if ans.RCode != RCodeNoError || !answerAddrSet(ans)[terminal] {
		t.Fatalf("rcode=%d addrs=%v, want NoError with %s", ans.RCode, addrRecords(ans), terminal)
	}

	// Every Resolve call targets only the configured D64 resolvers, for the
	// query name — the NS/glue hints are never followed, and nothing
	// VM/upstream-supplied redirects the gate's own upstream path.
	calls := e.upstream.callLog()
	if len(calls) == 0 {
		t.Fatal("answer produced without any Upstream.Resolve call")
	}
	for _, c := range calls {
		if c.Name != "ns-trap.example" {
			t.Errorf("Upstream.Resolve(%q) — the gate followed a VM/upstream-supplied hint off the configured resolvers", c.Name)
		}
		if !e.isConfiguredResolver(c.Resolver) {
			t.Errorf("Upstream.Resolve targeted %s — not one of the configured D64 resolvers %v", c.Resolver, e.resolvers)
		}
		if c.Resolver.Addr() == glueAddr {
			t.Errorf("Upstream.Resolve targeted the planted rogue resolver %s — glue hint redirected the upstream path", glueAddr)
		}
	}

	// Planted glue never answered, never admitted.
	if answerAddrSet(ans)[glueAddr] {
		t.Errorf("planted glue addr %s appeared in the answer", glueAddr)
	}
	for _, rr := range allSections(ans) {
		if rr.Type == TypeNS && rr.Target == "attacker-resolver.example" {
			t.Error("planted NS hint forwarded to the VM")
		}
		if rr.Name == "attacker-resolver.example" {
			t.Errorf("planted glue record forwarded to the VM: %+v", rr)
		}
	}
	if e.containsAddr(sess1, glueAddr) {
		t.Errorf("planted glue addr %s was admitted", glueAddr)
	}
}

// planRef: doc 09 §4 DNS-5 (concurrency under a fleet of VMs) + doc 06 §3(d)
func TestLoad_ConcurrentFleetStorm_NoCrossSessionLeakUnderRace(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	const nSessions = 100
	const queriesPerSession = 100

	e := newEnv(t)

	// 20-domain mix: allow (plain + CNAME), deny, ask, rebind flips, TTL=0.
	type domainSpec struct {
		name    string
		verdict Verdict
	}
	var mix []domainSpec
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("allow%d.example", i)
		e.policy.set(name, allowDec("org/"+name))
		if i%2 == 0 {
			e.upstream.script(name, aChain(name, 120, fmt.Sprintf("93.184.220.%d", i+1)))
		} else {
			e.upstream.script(name, ResolutionChain{
				QueryName: name,
				Links:     []CNAMELink{{From: name, To: "cdn." + name, TTL: 300}},
				Terminal:  []AddrRecord{{Addr: mkAddr(fmt.Sprintf("151.101.20.%d", i+1)), TTL: 120}},
			})
		}
		mix = append(mix, domainSpec{name, VerdictAllow})
	}
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("deny%d.example", i)
		e.policy.set(name, denyDec("org/"+name))
		mix = append(mix, domainSpec{name, VerdictDeny})
	}
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("ask%d.example", i)
		e.policy.set(name, askDec("org/"+name))
		mix = append(mix, domainSpec{name, VerdictAsk})
	}
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("rebind%d.example", i)
		e.policy.set(name, allowDec("org/"+name))
		e.upstream.script(name,
			aChain(name, 60, fmt.Sprintf("93.184.221.%d", i+1)),
			ResolutionChain{QueryName: name, Terminal: []AddrRecord{{Addr: mkAddr("10.0.0.99"), TTL: 60}}},
		)
		mix = append(mix, domainSpec{name, VerdictAllow})
	}
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("ttl0-%d.example", i)
		e.policy.set(name, allowDec("org/"+name))
		e.upstream.script(name, aChain(name, 0, fmt.Sprintf("93.184.222.%d", i+1)))
		mix = append(mix, domainSpec{name, VerdictAllow})
	}

	type result struct {
		sess   SessionRef
		domain string
		ans    Answer
		err    error
	}
	results := make([][]result, nSessions)
	var wg sync.WaitGroup
	for s := 0; s < nSessions; s++ {
		sess := SessionRef{ID: fmt.Sprintf("st%03d", s), Interface: fmt.Sprintf("dstap-st%03d", s)}
		rng := rand.New(rand.NewSource(int64(s) + 7))
		wg.Add(1)
		go func(s int, sess SessionRef, rng *rand.Rand) {
			defer wg.Done()
			local := make([]result, 0, queriesPerSession)
			for j := 0; j < queriesPerSession; j++ {
				d := mix[rng.Intn(len(mix))]
				proto := "udp"
				if rng.Intn(2) == 1 {
					proto = "tcp"
				}
				ans, err := e.resp.Serve(context.Background(), Query{Session: sess, Name: d.name, Type: TypeA, Proto: proto})
				local = append(local, result{sess, d.name, ans, err})
			}
			results[s] = local
		}(s, sess, rng)
	}
	wg.Wait()

	verdictFor := map[string]Verdict{}
	for _, d := range mix {
		verdictFor[d.name] = d.verdict
	}

	// Per-(session, domain) admitted-addr union from the fake store's log,
	// plus session-attribution audit.
	queried := map[string]map[string]bool{} // sessID → domain → true
	for _, batch := range results {
		for _, r := range batch {
			if queried[r.sess.ID] == nil {
				queried[r.sess.ID] = map[string]bool{}
			}
			queried[r.sess.ID][r.domain] = true
		}
	}
	admitted := map[string]map[netip.Addr]bool{} // sessID|domain → addrs
	for _, rec := range e.store.admitLog() {
		if !queried[rec.Tx.Session.ID][rec.Tx.Domain] {
			t.Errorf("AdmissionTx for (%s, %s) — that session never queried that domain (cross-session leak)", rec.Tx.Session.ID, rec.Tx.Domain)
		}
		if verdictFor[rec.Tx.Domain] != VerdictAllow {
			t.Errorf("AdmissionTx for non-allow domain %s — deny/ask must be side-effect-free", rec.Tx.Domain)
		}
		key := rec.Tx.Session.ID + "|" + rec.Tx.Domain
		if admitted[key] == nil {
			admitted[key] = map[netip.Addr]bool{}
		}
		for _, a := range rec.Tx.Addrs {
			admitted[key][a] = true
		}
	}

	for _, batch := range results {
		for _, r := range batch {
			if r.err != nil {
				t.Fatalf("Serve(%s, %s) error under storm: %v", r.sess.ID, r.domain, r.err)
			}
			switch verdictFor[r.domain] {
			case VerdictAllow:
				for _, rr := range addrRecords(r.ans) {
					if !admitted[r.sess.ID+"|"+r.domain][rr.Addr] {
						t.Errorf("session %s answered %s for %s without a matching admission in that session", r.sess.ID, rr.Addr, r.domain)
					}
				}
			default:
				if r.ans.RCode != RCodeRefused {
					t.Errorf("%s/%s: rcode %d, want REFUSED", r.sess.ID, r.domain, r.ans.RCode)
				}
				if n := len(addrRecords(r.ans)); n != 0 {
					t.Errorf("%s/%s: %d address records on a non-allow verdict", r.sess.ID, r.domain, n)
				}
			}
		}
	}

	// No lost or duplicated DNSEvents: one per AdmissionTx, matching 1:1.
	evs := e.events.dnsEvents()
	admitsLog := e.store.admitLog()
	if len(evs) != len(admitsLog) {
		t.Errorf("DNSEvents = %d, AdmissionTx = %d — events lost or duplicated", len(evs), len(admitsLog))
	}
	evCount := map[string]int{}
	for _, ev := range evs {
		evCount[ev.Session.ID+"|"+ev.Domain]++
	}
	admitCount := map[string]int{}
	for _, rec := range admitsLog {
		admitCount[rec.Tx.Session.ID+"|"+rec.Tx.Domain]++
	}
	for k, n := range admitCount {
		if evCount[k] != n {
			t.Errorf("admissions for %s: %d, DNSEvents: %d", k, n, evCount[k])
		}
	}
}
