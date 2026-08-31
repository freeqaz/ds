package dnsgate

// DNS-3 — denial and ask-user semantics: explicit refusal with provenance,
// REFUSED-not-NXDOMAIN/SERVFAIL (no cacheable negative signal), the Stage-0
// ask-user seam, the ask→approve→retry lifecycle, DoH blocklist precedence,
// and zero side effects on non-allow verdicts.

import (
	"fmt"
	"testing"
	"time"
)

// hardDenyRCode is the OQ6 working answer for hard denials. Resolving OQ6
// (REFUSED vs NXDOMAIN vs sinkhole) edits exactly this one line.
const hardDenyRCode = RCodeRefused

// planRef: doc 09 §4 DNS-3 (hard denial; denials are policy-decision events; OQ6)
func TestDeny_HardDeniedName_ExplicitRefusalWithProvenance(t *testing.T) {
	e := newEnv(t)
	dec := Decision{Verdict: VerdictDeny, RuleID: "org/blocklist-7", PolicyLayer: "org", PolicyVersion: "v0.3"}
	e.policy.set("evil.example", dec)
	e.upstream.failAll = true // armed: any Resolve call is a silent forward

	ans := e.mustServe(Query{Session: sess1, Name: "evil.example", Type: TypeA, Proto: "udp"})

	if ans.RCode != hardDenyRCode {
		t.Errorf("RCode = %d, want explicit in-band refusal %d", ans.RCode, hardDenyRCode)
	}
	if n := len(addrRecords(ans)); n != 0 {
		t.Errorf("%d address records answered for a hard-denied name", n)
	}
	if calls := e.upstream.callLog(); len(calls) != 0 {
		t.Errorf("Upstream.Resolve called %d times for a hard-denied name — silent forward", len(calls))
	}
	if admits := e.store.admitLog(); len(admits) != 0 {
		t.Errorf("%d AdmissionTx for a hard-denied name", len(admits))
	}
	evs := e.events.decisionEvents()
	if len(evs) != 1 {
		t.Fatalf("got %d PolicyDecisionEvents, want exactly 1", len(evs))
	}
	ev := evs[0]
	if ev.Decision != dec {
		t.Errorf("PolicyDecisionEvent.Decision = %+v, want full provenance %+v", ev.Decision, dec)
	}
	if ev.Decision.RuleID == "" || ev.Decision.PolicyLayer == "" || ev.Decision.PolicyVersion == "" {
		t.Error("decision event missing rule/layer/version provenance (POL-3)")
	}
	if ev.RCode != hardDenyRCode {
		t.Errorf("PolicyDecisionEvent.RCode = %d, want %d", ev.RCode, hardDenyRCode)
	}
	if ev.Domain != "evil.example" || ev.Session != sess1 {
		t.Errorf("PolicyDecisionEvent attribution = (%q, %+v), want (evil.example, s1)", ev.Domain, ev.Session)
	}
}

// planRef: doc 09 §4 DNS-3 (REFUSED because NXDOMAIN/SERVFAIL are negatively cached — RFC 2308/9520)
func TestAsk_RefusedNeverNXDOMAINOrSERVFAIL_NoCacheableSignal(t *testing.T) {
	names := []string{"ask-one.example", "ask-two.internal.example"}
	for _, name := range names {
		for _, proto := range []string{"udp", "tcp"} {
			for _, qtype := range []RRType{TypeA, TypeAAAA} {
				t.Run(fmt.Sprintf("%s/%s/qtype%d", name, proto, qtype), func(t *testing.T) {
					e := newEnv(t)
					e.policy.set(name, askDec("org/ask-default"))

					ans := e.mustServe(Query{Session: sess1, Name: name, Type: qtype, Proto: proto})

					if ans.RCode != RCodeRefused {
						t.Errorf("RCode = %d, want REFUSED", ans.RCode)
					}
					// Explicit: never a cacheable negative signal.
					if ans.RCode == RCodeNXDomain {
						t.Error("ask path answered NXDOMAIN — negatively cached by in-VM stubs (RFC 2308), blinds the retry")
					}
					if ans.RCode == RCodeServFail {
						t.Error("ask path answered SERVFAIL — failure-cached (RFC 2308 §7.1 / RFC 9520), blinds the retry")
					}
					if n := len(ans.Answers); n != 0 {
						t.Errorf("%d answer records on the ask path, want zero", n)
					}
					// Nothing for RFC 2308 negative caching to latch onto.
					for _, rr := range ans.Authority {
						if rr.Type == TypeSOA {
							t.Errorf("Authority carries an SOA record (%+v) — a cacheable negative-TTL anchor", rr)
						}
					}
				})
			}
		}
	}
}

// planRef: doc 09 §4 DNS-3 (prompt travels the ask-user seam frozen at Stage 0; §8 AskUserRequest shape)
func TestAsk_NotifiesStage0Seam_WithMatchedRule(t *testing.T) {
	t.Run("exactly one prompt shape with matched rule", func(t *testing.T) {
		e := newEnv(t)
		dec := Decision{Verdict: VerdictAsk, RuleID: "repo/ask-internal", PolicyLayer: "repo", PolicyVersion: "v0.4"}
		e.policy.set("internal-tool.example", dec)

		// Same query repeated 3 times rapidly.
		for i := 0; i < 3; i++ {
			ans := e.mustServe(Query{Session: sess1, Name: "internal-tool.example", Type: TypeA, Proto: "udp"})
			if ans.RCode != RCodeRefused {
				t.Fatalf("query %d: RCode = %d, want REFUSED", i+1, ans.RCode)
			}
		}

		reqs := e.notifier.requests()
		if len(reqs) == 0 {
			t.Fatal("AskUserNotifier.Notify never called for an ask-posture query")
		}
		want := AskUserRequest{
			Session:       sess1,
			ResourceKind:  "domain",
			Name:          "internal-tool.example",
			RuleID:        "repo/ask-internal",
			PolicyLayer:   "repo",
			PolicyVersion: "v0.4",
		}
		if reqs[0] != want {
			t.Errorf("AskUserRequest = %+v, want %+v", reqs[0], want)
		}
		// Duplicate-prompt suppression: at most one prompt per query — a
		// prompt-storming gate (several Notify calls per query) must fail.
		if len(reqs) > 3 {
			t.Errorf("%d Notify calls for 3 rapid identical queries — prompt storm (want at most one prompt per query)", len(reqs))
		}
		// Every prompt that was sent is the same well-formed request.
		for i, r := range reqs {
			if r != want {
				t.Errorf("Notify call %d = %+v, want %+v", i+1, r, want)
			}
		}
		t.Logf("duplicate-prompt suppression: %d Notify calls for 3 rapid identical queries", len(reqs))
	})

	t.Run("slow or failing notifier neither stalls nor changes the answer", func(t *testing.T) {
		e := newEnv(t)
		e.policy.set("internal-tool.example", askDec("repo/ask-internal"))
		block := make(chan struct{})
		e.notifier.block = block
		e.notifier.err = fmt.Errorf("injected notifier outage")
		defer close(block)

		// One-way seam: the DNS answer must come back promptly regardless.
		ch := serveAsync(e.resp, Query{Session: sess1, Name: "internal-tool.example", Type: TypeA, Proto: "udp"})
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("Serve: %v", r.err)
			}
			if r.ans.RCode != RCodeRefused {
				t.Errorf("RCode = %d with a blocked notifier, want REFUSED — notifier outcome must not change the answer", r.ans.RCode)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("Serve stalled behind a slow AskUserNotifier — the seam must be one-way/non-blocking")
		}
	})
}

// planRef: doc 09 §4 DNS-3 Done-when (prompt now, FIRST post-approval retry succeeds)
func TestAsk_FirstRetryAfterApproval_SucceedsAndAdmits(t *testing.T) {
	e := newEnv(t)
	e.policy.set("internal-tool.example", askDec("repo/ask-internal"))
	addr := mkAddr("93.184.216.40")
	e.upstream.script("internal-tool.example", aChain("internal-tool.example", 120, addr.String()))

	// Query #1: ask → REFUSED + Notify.
	ans1 := e.mustServe(Query{Session: sess1, Name: "internal-tool.example", Type: TypeA, Proto: "udp"})
	if ans1.RCode != RCodeRefused {
		t.Fatalf("query #1 RCode = %d, want REFUSED", ans1.RCode)
	}
	if len(e.notifier.requests()) == 0 {
		t.Fatal("query #1 produced no ask-user prompt")
	}
	if len(e.store.admitLog()) != 0 {
		t.Fatal("ask path touched the admission store")
	}

	// Approval: a session-scoped TTL'd allow grant on the policy stream —
	// the approval path's real mechanism (Stage-0 seam is one-way).
	grant := Decision{Verdict: VerdictAllow, RuleID: "grant/s1-internal-tool", PolicyLayer: "session", PolicyVersion: "v0.5"}
	e.policy.setForSession(sess1, "internal-tool.example", grant)

	// Query #2 immediately: the very next query resolves and admits, with the
	// DNS-2.a insert-then-answer property holding on the retry path too.
	ans2 := e.assertInsertThenAnswer(Query{Session: sess1, Name: "internal-tool.example", Type: TypeA, Proto: "udp"})
	if ans2.RCode != RCodeNoError {
		t.Fatalf("first post-approval retry RCode = %d, want NoError (no stale REFUSED from any internal cache)", ans2.RCode)
	}
	if !answerAddrSet(ans2)[addr] {
		t.Errorf("retry answer missing %s", addr)
	}
	admits := e.store.admitLog()
	if len(admits) != 1 {
		t.Fatalf("got %d AdmissionTx on the retry, want 1", len(admits))
	}
	if admits[0].Tx.Domain != "internal-tool.example" {
		t.Errorf("AdmissionTx.Domain = %q", admits[0].Tx.Domain)
	}
	evs := e.events.dnsEvents()
	if len(evs) != 1 {
		t.Fatalf("got %d DNSEvents, want 1 (the post-approval admission)", len(evs))
	}
	if evs[0].Decision.RuleID != "grant/s1-internal-tool" {
		t.Errorf("DNSEvent rule = %q, want the grant's rule id grant/s1-internal-tool", evs[0].Decision.RuleID)
	}
}

// planRef: doc 09 §9 row 'DoH endpoint blocking (baseline blocklist…)' (POL-2 + DNS-3 + NFT-4)
func TestDeny_DoHResolverDomains_BaselineBlocklistWins(t *testing.T) {
	// Each name is BOTH on the org allowlist and the D64 baseline blocklist;
	// the policy fake models POL-1 deny-overrides composition by returning the
	// blocklist decision. The test pins the provenance to the blocklist rule —
	// if composition ever flips to the allowlist rule, this fails.
	blocklistDec := Decision{Verdict: VerdictDeny, RuleID: "baseline/blocklist-doh", PolicyLayer: "system", PolicyVersion: "v0.3"}
	for _, name := range []string{"dns.google", "cloudflare-dns.com", "dns.quad9.net"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.policy.set(name, blocklistDec) // deny-overrides: blocklist beats org allowlist "org/allow-all"
			e.upstream.failAll = true

			ans := e.mustServe(Query{Session: sess1, Name: name, Type: TypeA, Proto: "udp"})

			if ans.RCode != RCodeRefused {
				t.Errorf("RCode = %d, want REFUSED", ans.RCode)
			}
			if n := len(e.store.admitLog()); n != 0 {
				t.Errorf("%d Admit calls for a blocklisted DoH resolver", n)
			}
			if n := len(e.upstream.callLog()); n != 0 {
				t.Errorf("%d upstream resolutions for a blocklisted DoH resolver", n)
			}
			evs := e.events.decisionEvents()
			if len(evs) != 1 {
				t.Fatalf("got %d PolicyDecisionEvents, want 1", len(evs))
			}
			if evs[0].Decision.RuleID != "baseline/blocklist-doh" {
				t.Errorf("provenance rule = %q, want the BLOCKLIST rule baseline/blocklist-doh (deny-overrides)", evs[0].Decision.RuleID)
			}
			if evs[0].Decision.RuleID == "org/allow-all" {
				t.Error("provenance names the allowlist rule — composition inverted")
			}
		})
	}
}

// planRef: doc 09 §4 DNS-3 + DNS-4 rule 1 (denial paths must not touch admission state)
func TestNonAllowVerdicts_ZeroSideEffects(t *testing.T) {
	e := newEnv(t)
	// Prior allow-set contents: one live admission that must stay bit-identical.
	e.policy.set("prior.example", allowDec("org/prior"))
	e.upstream.script("prior.example", aChain("prior.example", 300, "93.184.216.34"))
	pre := e.mustServe(Query{Session: sess1, Name: "prior.example", Type: TypeA, Proto: "udp"})
	if pre.RCode != RCodeNoError {
		t.Fatalf("priming query RCode = %d, want NoError", pre.RCode)
	}
	before := e.store.snapshot()
	admitsBefore := len(e.store.admitLog())
	resolvesBefore := len(e.upstream.callLog())

	verdicts := map[string]Decision{
		"deny": denyDec("org/deny-cell"),
		"ask":  askDec("org/ask-cell"),
	}
	qtypes := map[string]RRType{"A": TypeA, "AAAA": TypeAAAA, "HTTPS": TypeHTTPS}

	cell := 0
	for vName, dec := range verdicts {
		for qName, qtype := range qtypes {
			for _, proto := range []string{"udp", "tcp"} {
				cell++
				name := fmt.Sprintf("cell%d.%s.example", cell, vName)
				e.policy.set(name, dec)
				t.Run(fmt.Sprintf("%s/%s/%s", vName, qName, proto), func(t *testing.T) {
					ans := e.mustServe(Query{Session: sess1, Name: name, Type: qtype, Proto: proto})
					if ans.RCode != RCodeRefused {
						t.Errorf("RCode = %d, want REFUSED", ans.RCode)
					}
					if n := len(addrRecords(ans)); n != 0 {
						t.Errorf("%d address records answered on a %s verdict", n, vName)
					}
				})
			}
		}
	}

	if got := len(e.store.admitLog()) - admitsBefore; got != 0 {
		t.Errorf("%d AdmissionTx recorded across 12 deny/ask cells, want 0", got)
	}
	if got := len(e.upstream.callLog()) - resolvesBefore; got != 0 {
		t.Errorf("%d Upstream.Resolve calls across 12 deny/ask cells, want 0", got)
	}
	if after := e.store.snapshot(); after != before {
		t.Errorf("allow-set contents changed across refusals:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
