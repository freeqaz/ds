package dnsgate

// DNS-2 — admission into the allow-set: insert-then-answer ordering, write
// failure withholds addrs, CNAME chains keyed on the original query name,
// chain-minimum TTL, the DNS event join key, and the M0 walking skeleton.

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sort"
	"testing"
	"time"
)

// planRef: doc 09 §4 DNS-2 (insert-then-answer ordering)
func TestAdmission_InsertCompletesBeforeAnswerReleased(t *testing.T) {
	e := newEnv(t)
	e.policy.set("github.com", allowDec("baseline/github"))
	e.upstream.script("github.com", aChain("github.com", 120, "140.82.114.3"))

	ans := e.assertInsertThenAnswer(Query{Session: sess1, Name: "github.com", Type: TypeA, Proto: "udp"})

	if ans.RCode != RCodeNoError {
		t.Fatalf("RCode = %d, want NoError", ans.RCode)
	}
	got := addrRecords(ans)
	if len(got) != 1 || got[0].Addr != mkAddr("140.82.114.3") {
		t.Errorf("answered addrs = %v, want exactly 140.82.114.3", got)
	}
	// The fake's call log proves Admit happened-before the answer release
	// (assertInsertThenAnswer already failed otherwise); the admitted addrs
	// are ContainsAddr=true at the instant Serve returned.
	admits := e.store.admitLog()
	if len(admits) != 1 {
		t.Fatalf("got %d AdmissionTx, want exactly 1", len(admits))
	}
}

// planRef: doc 09 §4 DNS-2 insert-then-answer + DNS-4 rule 1 (no answer bypasses insertion)
func TestAdmission_WriteFailure_AnswerWithholdsAddrs(t *testing.T) {
	e := newEnv(t)

	// Control: prove the pipeline answers an allowed name when admission works.
	e.policy.set("ok.example", allowDec("org/ok"))
	e.upstream.script("ok.example", aChain("ok.example", 120, "93.184.216.34"))
	ctl := e.mustServe(Query{Session: sess1, Name: "ok.example", Type: TypeA, Proto: "udp"})
	if ctl.RCode != RCodeNoError || len(addrRecords(ctl)) != 1 {
		t.Fatalf("control query failed: rcode=%d addrs=%v", ctl.RCode, addrRecords(ctl))
	}
	before := e.store.snapshot()
	eventsBefore := len(e.events.dnsEvents())

	// Now inject an Admit failure for an otherwise-allowed resolution.
	failAddr := mkAddr("198.18.7.7")
	e.policy.set("fail.example", allowDec("org/fail"))
	e.upstream.script("fail.example", aChain("fail.example", 120, failAddr.String()))
	e.store.failDomain("fail.example", errors.New("injected nft write failure"))

	ans, err := e.resp.Serve(context.Background(), Query{Session: sess1, Name: "fail.example", Type: TypeA, Proto: "udp"})
	// A Serve error (no answer released) or a ServFail are both acceptable;
	// any answer that includes the unadmitted addrs is a bypass.
	if err == nil {
		for _, rr := range addrRecords(ans) {
			t.Errorf("answer carries address record %s although admission failed — degraded into a bypass (rcode=%d)", rr.Addr, ans.RCode)
		}
	}
	if e.containsAddr(sess1, failAddr) {
		t.Errorf("allow-set contains %s although Admit failed", failAddr)
	}
	if got := e.store.snapshot(); got != before {
		t.Errorf("allow-set/admission-map changed across a failed Admit:\nbefore:\n%s\nafter:\n%s", before, got)
	}
	for _, ev := range e.events.dnsEvents()[eventsBefore:] {
		if ev.Domain == "fail.example" {
			t.Errorf("DNSEvent emitted claiming admission of fail.example: %+v", ev)
		}
	}
}

// planRef: doc 09 §4 DNS-2 (admission keyed on original query name; intermediates never policy-evaluated)
func TestCNAME_OnlyOriginalQueryNamePolicyEvaluated(t *testing.T) {
	e := newEnv(t)
	e.policy.set("registry.npmjs.org", allowDec("baseline/npm"))
	// The fake would DENY the CDN intermediate if it were ever consulted.
	e.policy.set("cdn.fastly.example", denyDec("org/never-ask-me"))
	e.upstream.script("registry.npmjs.org", ResolutionChain{
		QueryName: "registry.npmjs.org",
		Links:     []CNAMELink{{From: "registry.npmjs.org", To: "cdn.fastly.example", TTL: 300}},
		Terminal:  []AddrRecord{{Addr: mkAddr("151.101.0.1"), TTL: 120}},
	})

	ans := e.mustServe(Query{Session: sess1, Name: "registry.npmjs.org", Type: TypeA, Proto: "udp"})
	if ans.RCode != RCodeNoError {
		t.Fatalf("RCode = %d, want NoError — the deny-if-asked intermediate must not affect resolution", ans.RCode)
	}
	got := addrRecords(ans)
	if len(got) != 1 || got[0].Addr != mkAddr("151.101.0.1") {
		t.Errorf("answered addrs = %v, want exactly the chain terminal 151.101.0.1", got)
	}

	calls := e.policy.callLog()
	if len(calls) != 1 {
		t.Fatalf("EvaluateDomain called %d times %v, want exactly once", len(calls), calls)
	}
	if calls[0].Domain != "registry.npmjs.org" {
		t.Errorf("EvaluateDomain called for %q, want the ORIGINAL query name registry.npmjs.org", calls[0].Domain)
	}

	admits := e.store.admitLog()
	if len(admits) != 1 {
		t.Fatalf("got %d AdmissionTx, want 1", len(admits))
	}
	if admits[0].Tx.Domain != "registry.npmjs.org" {
		t.Errorf("AdmissionTx.Domain = %q, want the original query name (the SNI join key)", admits[0].Tx.Domain)
	}
}

// planRef: doc 09 §4 DNS-2 (only the chain's terminal addresses enter the set)
func TestCNAME_TerminalAddrsOnly_IntermediateNamesNeverAdmitted(t *testing.T) {
	e := newEnv(t)
	e.policy.set("a.example", allowDec("org/a"))
	strayAddr := mkAddr("151.101.128.99")
	terminal1, terminal2 := mkAddr("151.101.0.1"), mkAddr("151.101.64.1")
	e.upstream.script("a.example", ResolutionChain{
		QueryName: "a.example",
		Links: []CNAMELink{
			{From: "a.example", To: "b.cdn.example", TTL: 300},
			{From: "b.cdn.example", To: "c.cdn.example", TTL: 300},
		},
		Terminal: []AddrRecord{{Addr: terminal1, TTL: 120}, {Addr: terminal2, TTL: 120}},
		// Adversarial: upstream plants a stray A record for an intermediate.
		Extra: []RR{{Name: "b.cdn.example", Type: TypeA, TTL: 300, Addr: strayAddr}},
	})

	ans := e.mustServe(Query{Session: sess1, Name: "a.example", Type: TypeA, Proto: "udp"})
	if ans.RCode != RCodeNoError {
		t.Fatalf("RCode = %d, want NoError", ans.RCode)
	}

	admits := e.store.admitLog()
	if len(admits) != 1 {
		t.Fatalf("got %d AdmissionTx, want exactly 1", len(admits))
	}
	tx := admits[0].Tx
	if tx.Domain != "a.example" {
		t.Errorf("AdmissionTx.Domain = %q, want a.example", tx.Domain)
	}
	var gotAddrs []string
	for _, a := range tx.Addrs {
		gotAddrs = append(gotAddrs, a.String())
	}
	sort.Strings(gotAddrs)
	if !reflect.DeepEqual(gotAddrs, []string{"151.101.0.1", "151.101.64.1"}) {
		t.Errorf("AdmissionTx.Addrs = %v, want exactly the two chain terminals", gotAddrs)
	}

	for _, intermediate := range []string{"b.cdn.example", "c.cdn.example"} {
		for _, a := range []string{"151.101.0.1", "151.101.64.1", strayAddr.String()} {
			if _, ok := e.lookup(sess1, intermediate, mkAddr(a)); ok {
				t.Errorf("Lookup(%q, %s) hit — intermediate names must never key admissions", intermediate, a)
			}
		}
	}

	// The stray Extra A record is neither answered nor admitted.
	if answerAddrSet(ans)[strayAddr] {
		t.Errorf("stray Extra A record %s appeared in the answer", strayAddr)
	}
	if e.containsAddr(sess1, strayAddr) {
		t.Errorf("stray Extra A record %s entered the allow-set", strayAddr)
	}
}

// planRef: doc 09 §4 DNS-2 (element timeout from minimum TTL along the chain) + OQ3
func TestCNAME_ChainMinimumTTL_Table(t *testing.T) {
	cfg := defaultConfig()
	grace := cfg.TTL.Grace
	now := newFakeClock().Now()

	mkChain := func(linkTTLs []uint32, terminalTTLs ...uint32) ResolutionChain {
		c := ResolutionChain{QueryName: "chain.example"}
		from := "chain.example"
		for i, ttl := range linkTTLs {
			to := from + ".hop"
			c.Links = append(c.Links, CNAMELink{From: from, To: to, TTL: ttl})
			from = to
			_ = i
		}
		for i, ttl := range terminalTTLs {
			c.Terminal = append(c.Terminal, AddrRecord{Addr: mkAddr("93.184.216." + string(rune('1'+i))), TTL: ttl})
		}
		return c
	}

	cases := []struct {
		name      string
		chain     ResolutionChain
		wantRaw   uint32
		wantClamp uint32
	}{
		{"CNAME 300, CNAME 60, A 3600", mkChain([]uint32{300, 60}, 3600), 60, 60},
		{"CNAME 30, A 3600 → floor", mkChain([]uint32{30}, 3600), 30, 60},
		{"A 120 alone", mkChain(nil, 120), 120, 120},
		{"CNAME 900, A 45 → floor", mkChain([]uint32{900}, 45), 45, 60},
		{"empty links → min of terminal TTLs", mkChain(nil, 300, 120), 120, 120},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ChainMinTTL(tc.chain); got != tc.wantRaw {
				t.Errorf("ChainMinTTL = %d, want raw minimum %d", got, tc.wantRaw)
			}
			q := Query{Session: sess1, Name: "chain.example", Type: TypeA, Proto: "udp"}
			plan, err := PlanResponse(q, allowDec("org/chain"), &tc.chain, cfg, now)
			if err != nil {
				t.Fatalf("PlanResponse: %v", err)
			}
			for _, rr := range addrRecords(plan.Answer) {
				if rr.TTL != tc.wantClamp {
					t.Errorf("answer TTL = %d, want ClampTTL(min) = %d", rr.TTL, tc.wantClamp)
				}
			}
			if len(addrRecords(plan.Answer)) == 0 {
				t.Error("plan answered zero address records for an allowed public chain")
			}
			if plan.Admission == nil {
				t.Fatal("plan has no AdmissionTx for an allowed public chain")
			}
			want := time.Duration(tc.wantClamp)*time.Second + grace
			if plan.Admission.Timeout != want {
				t.Errorf("Admission.Timeout = %v, want clamp+Grace = %v", plan.Admission.Timeout, want)
			}
		})
	}
}

// planRef: doc 09 §4 DNS-2 (record (session, domain, IPs, TTL, policy rule)) + §7 LOG-2 + POL-3
func TestDNSEvent_CarriesAdmittingDomainJoinKey(t *testing.T) {
	e := newEnv(t)
	dec := Decision{Verdict: VerdictAllow, RuleID: "baseline/npm", PolicyLayer: "system", PolicyVersion: "v0.3"}
	e.policy.set("registry.npmjs.org", dec)
	e.upstream.script("registry.npmjs.org", ResolutionChain{
		QueryName: "registry.npmjs.org",
		Links:     []CNAMELink{{From: "registry.npmjs.org", To: "cdn.fastly.example", TTL: 300}},
		Terminal:  []AddrRecord{{Addr: mkAddr("151.101.0.1"), TTL: 120}},
	})

	e.mustServe(Query{Session: sess1, Name: "registry.npmjs.org", Type: TypeA, Proto: "udp"})

	evs := e.events.dnsEvents()
	if len(evs) != 1 {
		t.Fatalf("got %d DNSEvents, want exactly 1", len(evs))
	}
	ev := evs[0]
	if ev.Session != sess1 {
		t.Errorf("DNSEvent.Session = %+v, want %+v", ev.Session, sess1)
	}
	if ev.Domain != "registry.npmjs.org" {
		t.Errorf("DNSEvent.Domain = %q, want the ORIGINAL query name (the §7 join key)", ev.Domain)
	}
	if len(ev.Addrs) != 1 || ev.Addrs[0] != mkAddr("151.101.0.1") {
		t.Errorf("DNSEvent.Addrs = %v, want the admitted addr 151.101.0.1", ev.Addrs)
	}
	if ev.TTL != 120 { // 120 is inside the clamp window
		t.Errorf("DNSEvent.TTL = %d, want clamped 120", ev.TTL)
	}
	// POL-3: zero-value provenance fails the test.
	if ev.Decision.RuleID == "" || ev.Decision.PolicyLayer == "" || ev.Decision.PolicyVersion == "" {
		t.Fatalf("DNSEvent decision provenance incomplete: %+v (POL-3 missing-provenance rule)", ev.Decision)
	}
	if ev.Decision != dec {
		t.Errorf("DNSEvent.Decision = %+v, want full provenance %+v", ev.Decision, dec)
	}
}

// planRef: doc 09 §4 DNS-2 Done-when (M0 smoke: allowed domain flows, everything else drops)
func TestE2E_M0WalkingSkeleton_AllowedFlowsElseRefused(t *testing.T) {
	e := newEnv(t)
	// D64-shaped baseline (doc 09 §6 POL-2).
	e.policy.set("api.anthropic.com", allowDec("baseline/anthropic"))
	e.policy.set("github.com", allowDec("baseline/github"))
	e.policy.set("registry.npmjs.org", allowDec("baseline/npm"))

	e.upstream.script("api.anthropic.com", aChain("api.anthropic.com", 300, "160.79.104.10"))
	e.upstream.script("github.com", aChain("github.com", 120, "140.82.114.3"))
	// registry.npmjs.org exercises the CNAME-chained CDN path.
	e.upstream.script("registry.npmjs.org", ResolutionChain{
		QueryName: "registry.npmjs.org",
		Links:     []CNAMELink{{From: "registry.npmjs.org", To: "cdn.fastly.example", TTL: 300}},
		Terminal:  []AddrRecord{{Addr: mkAddr("151.101.0.1"), TTL: 120}},
	})

	baseline := map[string][]netip.Addr{
		"api.anthropic.com":  {mkAddr("160.79.104.10")},
		"github.com":         {mkAddr("140.82.114.3")},
		"registry.npmjs.org": {mkAddr("151.101.0.1")},
	}
	for name, wantAddrs := range baseline {
		ans := e.mustServe(Query{Session: sess1, Name: name, Type: TypeA, Proto: "udp"})
		if ans.RCode != RCodeNoError {
			t.Errorf("%s: RCode = %d, want NoError", name, ans.RCode)
			continue
		}
		got := answerAddrSet(ans)
		for _, want := range wantAddrs {
			if !got[want] {
				t.Errorf("%s: answer missing %s", name, want)
			}
			if !e.containsAddr(sess1, want) {
				t.Errorf("%s: %s answered but not in the allow-set (admitted-before-answer broken)", name, want)
			}
			if _, ok := e.lookup(sess1, name, want); !ok {
				t.Errorf("%s: admission-map Lookup missed for %s", name, want)
			}
		}
	}

	admitsAfterBaseline := len(e.store.admitLog())
	decisionsBefore := len(e.events.decisionEvents())

	refusedNames := []string{"evil.example", "zq1x9-random-name.example"}
	for _, name := range refusedNames {
		ans := e.mustServe(Query{Session: sess1, Name: name, Type: TypeA, Proto: "udp"})
		if ans.RCode != RCodeRefused {
			t.Errorf("%s: RCode = %d, want REFUSED", name, ans.RCode)
		}
		if n := len(addrRecords(ans)); n != 0 {
			t.Errorf("%s: %d address records answered for a non-baseline name", name, n)
		}
	}
	if got := len(e.store.admitLog()); got != admitsAfterBaseline {
		t.Errorf("AdmissionStore touched by refused queries: %d new AdmissionTx", got-admitsAfterBaseline)
	}
	// Exactly one PolicyDecisionEvent per refused name, each correctly
	// attributed and carrying full POL-3 provenance — two arbitrary events
	// must not satisfy the M0 Done-when.
	newEvs := e.events.decisionEvents()[decisionsBefore:]
	if len(newEvs) != 2 {
		t.Fatalf("got %d new PolicyDecisionEvents for the two refused names, want 2", len(newEvs))
	}
	perDomain := map[string]int{}
	for _, ev := range newEvs {
		perDomain[ev.Domain]++
		if ev.Session != sess1 {
			t.Errorf("PolicyDecisionEvent for %q attributed to %+v, want %+v", ev.Domain, ev.Session, sess1)
		}
		if ev.RCode != RCodeRefused {
			t.Errorf("PolicyDecisionEvent for %q carries RCode %d, want REFUSED", ev.Domain, ev.RCode)
		}
		if ev.Decision.RuleID == "" || ev.Decision.PolicyLayer == "" || ev.Decision.PolicyVersion == "" {
			t.Errorf("PolicyDecisionEvent for %q missing rule/layer/version provenance: %+v (POL-3)", ev.Domain, ev.Decision)
		}
	}
	for _, name := range refusedNames {
		if perDomain[name] != 1 {
			t.Errorf("got %d PolicyDecisionEvents for %q, want exactly 1", perDomain[name], name)
		}
	}
}
