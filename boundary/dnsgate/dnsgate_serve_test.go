package dnsgate

// DNS-1 — serve and resolve: allowed names resolve through us, TTLs clamp,
// v0 AAAA posture holds, attribution is by source interface, p99 budget.

import (
	"context"
	"math"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// planRef: doc 09 §4 DNS-1 Done-when (allowed name resolves through us)
func TestServe_AllowedDomain_AnswersTerminalAddrs(t *testing.T) {
	e := newEnv(t)
	e.policy.set("api.anthropic.com", allowDec("baseline/anthropic"))
	e.upstream.script("api.anthropic.com", aChain("api.anthropic.com", 300, "160.79.104.10"))

	ans := e.mustServe(Query{Session: sess1, Name: "api.anthropic.com", Type: TypeA, Proto: "udp"})

	if ans.RCode != RCodeNoError {
		t.Fatalf("RCode = %d, want NoError", ans.RCode)
	}
	if len(ans.Answers) != 1 {
		t.Fatalf("got %d answer records, want exactly the upstream terminal A record", len(ans.Answers))
	}
	rr := ans.Answers[0]
	if rr.Type != TypeA {
		t.Errorf("answer type = %d, want A", rr.Type)
	}
	if rr.Name != "api.anthropic.com" {
		t.Errorf("answer name = %q, want the query name", rr.Name)
	}
	if rr.Addr != mkAddr("160.79.104.10") {
		t.Errorf("answer addr = %s, want 160.79.104.10", rr.Addr)
	}
	// Upstream TTL 300 is inside [60s, 900s] → answered unchanged.
	if rr.TTL != 300 {
		t.Errorf("answer TTL = %d, want clamped 300", rr.TTL)
	}
	// Exactly one upstream resolution, for the query name, via the configured
	// resolver seam — nothing VM-supplied redirects the upstream path.
	calls := e.upstream.callLog()
	if len(calls) != 1 {
		t.Fatalf("Upstream.Resolve called %d times, want exactly 1", len(calls))
	}
	if calls[0].Name != "api.anthropic.com" {
		t.Errorf("Resolve target = %q, want the query name", calls[0].Name)
	}
	if !e.isConfiguredResolver(calls[0].Resolver) {
		t.Errorf("Resolve went via %s — not one of the configured D64 resolvers %v", calls[0].Resolver, e.resolvers)
	}
}

// planRef: doc 09 §4 DNS-1 (clamped TTLs) + DNS-4 rule 3 (TTL floors) + NFT-3 grace
func TestClampTTL_FloorCeilingTable(t *testing.T) {
	p := defaultTTLPolicy() // Floor 60s, Ceiling 900s, Grace 45s
	in := []uint32{0, 1, 59, 60, 300, 900, 3600, 86400, math.MaxUint32}
	want := []uint32{60, 60, 60, 60, 300, 900, 900, 900, 900}

	var prev uint32
	for i, ttl := range in {
		got := ClampTTL(ttl, p)
		if got != want[i] {
			t.Errorf("ClampTTL(%d) = %d, want %d", ttl, got, want[i])
		}
		if got == 0 {
			t.Errorf("ClampTTL(%d) = 0 — a churn-forcing TTL=0 answer must never produce a zero clamp", ttl)
		}
		if got < prev {
			t.Errorf("ClampTTL not monotonic: ClampTTL(%d)=%d < previous %d", ttl, got, prev)
		}
		prev = got
	}

	// AdmissionTx.Timeout in PlanResponse equals clamp+Grace, so the kernel
	// entry strictly outlives any TTL-honoring client cache.
	q := Query{Session: sess1, Name: "api.anthropic.com", Type: TypeA, Proto: "udp"}
	chain := aChain("api.anthropic.com", 300, "160.79.104.10")
	plan, err := PlanResponse(q, allowDec("baseline/anthropic"), &chain, defaultConfig(), newFakeClock().Now())
	if err != nil {
		t.Fatalf("PlanResponse: %v", err)
	}
	if plan.Admission == nil {
		t.Fatal("PlanResponse produced no AdmissionTx for an allowed public resolution")
	}
	wantTimeout := 300*time.Second + p.Grace
	if plan.Admission.Timeout != wantTimeout {
		t.Errorf("AdmissionTx.Timeout = %v, want clamp+Grace = %v", plan.Admission.Timeout, wantTimeout)
	}
}

// planRef: doc 09 §4 DNS-1 v0 IPv6 posture (strip AAAA, allow6 dormant; OQ10)
func TestServe_V0AAAAStrip_NoIPv6ReachesVMOrSets(t *testing.T) {
	t.Run("direct AAAA query answers empty NoError", func(t *testing.T) {
		e := newEnv(t)
		e.policy.set("v6.example", allowDec("org/v6"))
		v6chain := ResolutionChain{
			QueryName: "v6.example",
			Terminal:  []AddrRecord{{Addr: mkAddr("2606:4700:4700::1111"), TTL: 300}},
		}
		e.upstream.script("v6.example", v6chain)

		ans := e.mustServe(Query{Session: sess1, Name: "v6.example", Type: TypeAAAA, Proto: "udp"})
		// The domain is allowed: NoError, not REFUSED — the TYPE is stripped.
		if ans.RCode != RCodeNoError {
			t.Fatalf("RCode = %d, want NoError (allowed domain, stripped type)", ans.RCode)
		}
		if n := len(allSections(ans)); n != 0 {
			t.Errorf("got %d records across sections, want zero (AAAA stripped)", n)
		}
		assertNoIPv6Admitted(t, e)
	})

	t.Run("AAAA smuggled in chain.Extra never reaches any section", func(t *testing.T) {
		e := newEnv(t)
		e.policy.set("mixed.example", allowDec("org/mixed"))
		chain := aChain("mixed.example", 300, "93.184.216.34")
		chain.Extra = []RR{
			{Name: "mixed.example", Type: TypeAAAA, TTL: 300, Addr: mkAddr("2606:4700:4700::1111")},
		}
		e.upstream.script("mixed.example", chain)

		ans := e.mustServe(Query{Session: sess1, Name: "mixed.example", Type: TypeA, Proto: "udp"})
		if ans.RCode != RCodeNoError {
			t.Fatalf("RCode = %d, want NoError", ans.RCode)
		}
		if got := len(recordsOfType(ans, TypeAAAA)); got != 0 {
			t.Errorf("found %d AAAA records in the answer — smuggled AAAA must be stripped from every section", got)
		}
		// The legitimate A record must still be answered.
		if got := recordsOfType(ans, TypeA); len(got) != 1 || got[0].Addr != mkAddr("93.184.216.34") {
			t.Errorf("A records = %v, want exactly 93.184.216.34", got)
		}
		assertNoIPv6Admitted(t, e)
	})

	t.Run("FilterRecords strips AAAA section-independently", func(t *testing.T) {
		// planRef: doc 09 §4 DNS-1 (pure half of the strip)
		a := RR{Name: "x.example", Type: TypeA, TTL: 60, Addr: mkAddr("93.184.216.34")}
		aaaa := RR{Name: "x.example", Type: TypeAAAA, TTL: 60, Addr: mkAddr("2606:4700:4700::1111")}
		cname := RR{Name: "x.example", Type: TypeCNAME, TTL: 60, Target: "y.example"}
		cases := []struct {
			name string
			in   []RR
			want []RR
		}{
			{"mixed", []RR{a, aaaa, cname}, []RR{a, cname}},
			{"only AAAA", []RR{aaaa, aaaa}, []RR{}},
			{"no AAAA", []RR{a, cname}, []RR{a, cname}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := FilterRecords(tc.in, Posture{StripAAAA: true})
				if len(got) != len(tc.want) || (len(got) > 0 && !reflect.DeepEqual(got, tc.want)) {
					t.Errorf("FilterRecords(%v) = %v, want %v", tc.in, got, tc.want)
				}
			})
		}
	})
}

func assertNoIPv6Admitted(t *testing.T, e *env) {
	t.Helper()
	for _, rec := range e.store.admitLog() {
		for _, a := range rec.Tx.Addrs {
			// Every admitted address must be plain IPv4. No exemption for
			// IPv4-mapped forms: a ::ffff:a.b.c.d literal is an IPv6-typed
			// element that would land in a v6-typed kernel set while allow6
			// is dormant — an unenforced entry. The implementation must
			// unmap 4-in-6 forms to plain IPv4 before admission.
			if !a.Is4() {
				t.Errorf("non-IPv4 addr %s was admitted while allow6 is dormant (AdmissionTx for %q)", a, rec.Tx.Domain)
			}
		}
	}
}

// planRef: doc 09 §4 DNS-1 (per-session view, attributed by source interface) + §7 LOG-2 join key
func TestServe_AttributionBySourceInterface(t *testing.T) {
	e := newEnv(t)
	e.policy.set("github.com", allowDec("baseline/github"))
	e.upstream.script("github.com", aChain("github.com", 120, "140.82.114.3"))
	addr := mkAddr("140.82.114.3")

	// Session 1 queries first: its admission must be visible only to s1.
	ans1 := e.mustServe(Query{Session: sess1, Name: "github.com", Type: TypeA, Proto: "udp"})
	if ans1.RCode != RCodeNoError {
		t.Fatalf("s1 RCode = %d, want NoError", ans1.RCode)
	}
	if _, ok := e.lookup(sess1, "github.com", addr); !ok {
		t.Error("Lookup under originating session s1 missed")
	}
	if _, ok := e.lookup(sess2, "github.com", addr); ok {
		t.Error("Lookup under s2 hit before s2 ever queried — admission leaked across sessions")
	}

	ans2 := e.mustServe(Query{Session: sess2, Name: "github.com", Type: TypeA, Proto: "udp"})
	if ans2.RCode != RCodeNoError {
		t.Fatalf("s2 RCode = %d, want NoError", ans2.RCode)
	}
	if _, ok := e.lookup(sess2, "github.com", addr); !ok {
		t.Error("Lookup under originating session s2 missed after s2's own query")
	}

	// Two AdmissionTx, each attributed to the correct distinct session.
	admits := e.store.admitLog()
	if len(admits) != 2 {
		t.Fatalf("got %d AdmissionTx, want 2 (one per session)", len(admits))
	}
	gotSess := []string{admits[0].Tx.Session.ID, admits[1].Tx.Session.ID}
	if !(gotSess[0] == "s1" && gotSess[1] == "s2") {
		t.Errorf("AdmissionTx sessions = %v, want [s1 s2] in query order", gotSess)
	}
	for _, rec := range admits {
		want := "dstap-" + rec.Tx.Session.ID
		if rec.Tx.Session.Interface != want {
			t.Errorf("AdmissionTx interface = %q, want %q (attribution by source interface)", rec.Tx.Session.Interface, want)
		}
	}

	// DNSEvents carry the right SessionRef.
	evs := e.events.dnsEvents()
	if len(evs) != 2 {
		t.Fatalf("got %d DNSEvents, want 2", len(evs))
	}
	evSess := []string{evs[0].Session.ID, evs[1].Session.ID}
	sort.Strings(evSess)
	if !reflect.DeepEqual(evSess, []string{"s1", "s2"}) {
		t.Errorf("DNSEvent sessions = %v, want {s1, s2}", evSess)
	}
}

// planRef: doc 09 §4 DNS-1 Done-when (p99 added latency ≤10ms warm; doc 06 §3(d))
func TestLoad_ResolutionP99_WarmWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	// Budget is a tunable const, per the Stage-5 (d) rig note.
	const p99Budget = 10 * time.Millisecond
	const sessions = 200
	const queriesPerSession = 50

	e := newEnv(t)
	e.policy.set("api.anthropic.com", allowDec("baseline/anthropic"))
	e.upstream.script("api.anthropic.com", aChain("api.anthropic.com", 300, "160.79.104.10"))

	var mu sync.Mutex
	durations := make([]time.Duration, 0, sessions*queriesPerSession)
	var errCount int

	var wg sync.WaitGroup
	for i := 0; i < sessions; i++ {
		sess := SessionRef{ID: "ld" + string(rune('A'+i%26)) + string(rune('0'+i/26)), Interface: "dstap-ld"}
		wg.Add(1)
		go func(sess SessionRef) {
			defer wg.Done()
			local := make([]time.Duration, 0, queriesPerSession)
			errs := 0
			for j := 0; j < queriesPerSession; j++ {
				start := time.Now()
				_, err := e.resp.Serve(context.Background(), Query{Session: sess, Name: "api.anthropic.com", Type: TypeA, Proto: "udp"})
				local = append(local, time.Since(start))
				if err != nil {
					errs++
				}
			}
			mu.Lock()
			durations = append(durations, local...)
			errCount += errs
			mu.Unlock()
		}(sess)
	}
	wg.Wait()

	if errCount != 0 {
		t.Fatalf("%d Serve errors under warm fan-out, want zero", errCount)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p99 := durations[len(durations)*99/100]
	if p99 > p99Budget {
		t.Errorf("warm p99 added latency = %v, budget %v", p99, p99Budget)
	}
}
