package policycore

// POL-5: escape hatches (the binary-protocol whitelist), ask-user routing
// over the frozen Stage-0 seam, and approvals returning as session-scoped
// TTL'd grants on the policy stream.

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func hatchPolicy() *Policy {
	return &Policy{
		SchemaVersion: SchemaV0,
		Name:          "hatch-pol",
		PackVersion:   "0.0.1",
		Posture:       PostureLocked,
		Allow:         []AllowRule{{ID: "alw-github", Domain: "github.com"}},
		EscapeHatches: []EscapeHatchRule{
			{ID: "hatch-ssh", Protocol: "ssh", Port: 22, Scope: GrantScope{Session: "S1"}},
		},
		AskDefaults: AskDefaults{UnlistedDomain: ActionDeny},
	}
}

func askPolicy() *Policy {
	return &Policy{
		SchemaVersion: SchemaV0,
		Name:          "ask-pol",
		PackVersion:   "0.0.1",
		Posture:       PostureStandard,
		AskDefaults:   AskDefaults{UnlistedDomain: ActionAsk, GrantTTL: 5 * time.Minute},
	}
}

func TestEscapeHatch_WhitelistedProtocolFlowsDirect(t *testing.T) {
	// planRef: doc 09 §6 POL-5 Done-when: a whitelisted binary protocol
	// flows direct, gated by the allow-set (the NFT-3 half gates the IPs;
	// this is the decision-layer verdict).
	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: hatchPolicy()})
	dec := mustEvaluate(t, NewEvaluator(), snap, l4Req(sessS1, "github.com", testIP, 22, "ssh"), testT0)
	if dec.Action != ActionAllow {
		t.Fatalf("Action = %q, want %q", dec.Action, ActionAllow)
	}
	if !dec.DirectL4 {
		t.Errorf("DirectL4 = false; an escape-hatch allow must mark the flow direct")
	}
	if dec.SwapService != "" {
		t.Errorf("SwapService = %q on a direct L4 flow, want empty", dec.SwapService)
	}
	if dec.PassThrough {
		t.Errorf("PassThrough = true on a direct L4 flow, want false")
	}
	if dec.Provenance.RuleID != "hatch-ssh" {
		t.Errorf("Provenance.RuleID = %q, want the hatch rule %q", dec.Provenance.RuleID, "hatch-ssh")
	}
	if dec.Provenance.Layer != LayerSystem {
		t.Errorf("Provenance.Layer = %q, want %q (the hatch's defining layer)", dec.Provenance.Layer, LayerSystem)
	}
}

func TestEscapeHatch_UnlistedPortDeniedWithLoggableDecision(t *testing.T) {
	// planRef: doc 09 §6 POL-5 Done-when: an unlisted port drops and logs.
	// ADVERSARIAL: every near-miss bypass is denied, and the denial is a
	// fully-attributed PolicyDecision event emittable to ds-flowlog.
	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: hatchPolicy()})
	eval := NewEvaluator()

	cases := []struct {
		name string
		req  Request
	}{
		{"right protocol wrong port (ssh/2222)", l4Req(sessS1, "github.com", testIP, 2222, "ssh")},
		{"wrong protocol right port (telnet/22)", l4Req(sessS1, "github.com", testIP, 22, "telnet")},
		{"udp/123 NTP", l4Req(sessS1, "pool.ntp.example", testIP, 123, "udp")},
		{"tcp/25 SMTP", l4Req(sessS1, "smtp.example", testIP, 25, "tcp")},
		{"tcp/22 from out-of-scope session S2", l4Req(sessS2, "github.com", testIP, 22, "ssh")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := mustEvaluate(t, eval, snap, tc.req, testT0)
			if dec.Action != ActionDeny {
				t.Fatalf("Action = %q, want %q", dec.Action, ActionDeny)
			}
			if dec.DirectL4 {
				t.Errorf("DirectL4 = true on a denied flow")
			}
			// "drops and logs": the deny must be a valid, fully-attributed
			// decision event.
			if err := ValidateDecisionEvent(dec); err != nil {
				t.Errorf("denial is not a loggable decision event: %v", err)
			}
			assertFullProvenance(t, dec, snap)
		})
	}
}

func TestEscapeHatch_ScopeConfinement(t *testing.T) {
	// planRef: doc 09 §6 POL-5 scoped per-session/host/org (doc 03 OQ7).
	// ADVERSARIAL: a hatch granted to one session/host/org never leaks to
	// another; the unscoped hatch is pinned deny-by-default until OQ7
	// resolves, so a future widening is a conscious change.
	pol := &Policy{
		SchemaVersion: SchemaV0,
		Name:          "scoped-hatches",
		PackVersion:   "0.0.1",
		Posture:       PostureLocked,
		EscapeHatches: []EscapeHatchRule{
			{ID: "hatch-sess", Protocol: "ssh", Port: 22, Scope: GrantScope{Session: "S1"}},
			{ID: "hatch-org", Protocol: "rsync", Port: 873, Scope: GrantScope{Org: "O1"}},
			{ID: "hatch-host", Protocol: "nfs", Port: 2049, Scope: GrantScope{Host: "H1"}},
			{ID: "hatch-unscoped", Protocol: "telnet", Port: 23, Scope: GrantScope{}},
		},
		AskDefaults: AskDefaults{UnlistedDomain: ActionDeny},
	}
	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: pol})
	eval := NewEvaluator()

	inO1 := SessionRef{Session: "S9", Host: "H9", Org: "O1"}
	inO2 := SessionRef{Session: "S9", Host: "H9", Org: "O2"}
	onH1 := SessionRef{Session: "S8", Host: "H1", Org: "O9"}
	onH2 := SessionRef{Session: "S8", Host: "H2", Org: "O9"}

	cases := []struct {
		name       string
		req        Request
		wantAllow  bool
		wantRuleID string // asserted on allow cells
	}{
		{"session-scoped hatch from S1", l4Req(sessS1, "target.example", testIP, 22, "ssh"), true, "hatch-sess"},
		{"session-scoped hatch from S2", l4Req(sessS2, "target.example", testIP, 22, "ssh"), false, ""},
		{"org-scoped hatch from a session in O1", l4Req(inO1, "target.example", testIP, 873, "rsync"), true, "hatch-org"},
		{"org-scoped hatch from a session in O2", l4Req(inO2, "target.example", testIP, 873, "rsync"), false, ""},
		{"host-scoped hatch from H1", l4Req(onH1, "target.example", testIP, 2049, "nfs"), true, "hatch-host"},
		{"host-scoped hatch from H2", l4Req(onH2, "target.example", testIP, 2049, "nfs"), false, ""},
		{"unscoped hatch denies by default (OQ7 conservative pin)", l4Req(sessS1, "target.example", testIP, 23, "telnet"), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := mustEvaluate(t, eval, snap, tc.req, testT0)
			if tc.wantAllow {
				if dec.Action != ActionAllow {
					t.Fatalf("Action = %q, want %q", dec.Action, ActionAllow)
				}
				if !dec.DirectL4 {
					t.Errorf("DirectL4 = false on an in-scope hatch allow")
				}
				if dec.Provenance.RuleID != tc.wantRuleID {
					t.Errorf("Provenance.RuleID = %q, want %q", dec.Provenance.RuleID, tc.wantRuleID)
				}
			} else {
				if dec.Action != ActionDeny {
					t.Fatalf("Action = %q, want %q (scope must confine the hatch)", dec.Action, ActionDeny)
				}
				if dec.DirectL4 {
					t.Errorf("DirectL4 = true on a denied flow")
				}
			}
			assertFullProvenance(t, dec, snap)
		})
	}
}

func TestAskUser_RoutedOverStage0Seam_WithProvenance(t *testing.T) {
	// planRef: doc 09 §6 POL-5 Done-when: an ask-routed request surfaces in
	// the (fake) client wrapper over the Stage-0 ask-user seam; doc 09 §8
	// Stage 0 AskUserRequest contract. The boundary grows no approval UI.
	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: askPolicy()})
	req := dnsReq(sessS1, "newdomain.example")
	dec := mustEvaluate(t, NewEvaluator(), snap, req, testT0)
	if dec.Action != ActionAsk {
		t.Fatalf("Action = %q, want %q (standard posture, unlisted domain)", dec.Action, ActionAsk)
	}
	if err := ValidateProvenance(dec.Provenance); err != nil {
		t.Fatalf("ask decision provenance invalid: %v", err)
	}

	// Drive the PRODUCTION dispatch seam: DispatchAsk must derive the
	// AskUserRequest from (req, decision) itself — this test hands it
	// nothing to echo back, so an implementation that never routes asks, or
	// routes the wrong session/name/rule, fails here.
	router := &recordingAskRouter{}
	if err := DispatchAsk(context.Background(), router, req, dec); err != nil {
		t.Fatalf("DispatchAsk: %v", err)
	}

	got := router.recorded()
	if len(got) != 1 {
		t.Fatalf("recorded %d AskUserRequests, want exactly 1", len(got))
	}
	want := AskUserRequest{
		Session:      req.Session,    // derived from the request: S1
		ResourceKind: "domain",       // derived from the request shape (KindDNSResolve)
		Name:         req.Domain,     // the asked-about resource: newdomain.example
		MatchedRule:  dec.Provenance, // POL-3: the rule that decided Ask
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("dispatched AskUserRequest = %+v, want %+v", got[0], want)
	}
	// Fire-and-forget: no response payload exists on this seam; approvals
	// return only as grants on the policy stream (POL-5.e).
}

func TestAskApproval_TTLGrantOnPolicyStream_ThenExpires(t *testing.T) {
	// planRef: doc 09 §8 Stage 0: approvals return as session-scoped TTL'd
	// allow grants on the already-frozen policy stream; doc 09 §6 POL-5.
	// ADVERSARIAL: an expired grant readmits nothing; a lookalike name was
	// never admitted.
	const approved = "newdomain.example"
	const lookalike = "newdomain.example.evil.test" // approved name as a label prefix

	snapN := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: askPolicy()})
	snapN.Seq = 7
	eval := NewEvaluator()
	clock := newFakeClock(testT0)

	// Pre-grant: the name asks.
	pre := mustEvaluate(t, eval, snapN, dnsReq(sessS1, approved), clock.Now())
	if pre.Action != ActionAsk {
		t.Fatalf("pre-grant Action = %q, want %q", pre.Action, ActionAsk)
	}

	grant := Grant{Session: sessS1, Domain: approved, ExpiresAt: testT0.Add(5 * time.Minute), Seq: 8}
	snapN1, err := ApplyGrant(snapN, grant)
	if err != nil {
		t.Fatalf("ApplyGrant: %v", err)
	}
	if snapN1.Seq != 8 {
		t.Errorf("granted snapshot Seq = %d, want %d (next Seq)", snapN1.Seq, 8)
	}
	if snapN1.PolicyVersion == snapN.PolicyVersion {
		t.Errorf("granted snapshot PolicyVersion %q equals the pre-grant version — grant-window decisions must cite a distinct policy version so flow logs can attribute what the approval admitted", snapN1.PolicyVersion)
	}

	clock.Advance(1 * time.Minute) // T+1m
	dec := mustEvaluate(t, eval, snapN1, dnsReq(sessS1, approved), clock.Now())
	if dec.Action != ActionAllow {
		t.Fatalf("T+1m Action = %q, want %q (grant live)", dec.Action, ActionAllow)
	}
	if dec.Provenance.Layer != LayerSession {
		t.Errorf("grant provenance Layer = %q, want %q", dec.Provenance.Layer, LayerSession)
	}
	if dec.Provenance.PolicyVersion != snapN1.PolicyVersion {
		t.Errorf("grant provenance PolicyVersion = %q, want the granted snapshot's %q", dec.Provenance.PolicyVersion, snapN1.PolicyVersion)
	}
	if dec.Provenance.RuleID == "" {
		t.Errorf("grant decision carries empty RuleID")
	}

	clock.Advance(3*time.Minute + 59*time.Second) // T+4m59s
	dec = mustEvaluate(t, eval, snapN1, dnsReq(sessS1, approved), clock.Now())
	if dec.Action != ActionAllow {
		t.Fatalf("T+4m59s Action = %q, want %q (grant still live)", dec.Action, ActionAllow)
	}

	clock.Advance(2 * time.Second) // T+5m1s — past expiry, no wall-clock sleep
	dec = mustEvaluate(t, eval, snapN1, dnsReq(sessS1, approved), clock.Now())
	if dec.Action != ActionAsk {
		t.Fatalf("T+5m1s Action = %q, want %q (expired grant readmits nothing)", dec.Action, ActionAsk)
	}

	// The lookalike name was never covered by the grant.
	dec = mustEvaluate(t, eval, snapN1, dnsReq(sessS1, lookalike), testT0.Add(1*time.Minute))
	if dec.Action == ActionAllow {
		t.Fatalf("lookalike %q admitted by a grant for %q", lookalike, approved)
	}
	if dec.Action != ActionAsk && dec.Action != ActionDeny {
		t.Errorf("lookalike Action = %q, want Ask or Deny", dec.Action)
	}

	// Immutability: the original Seq-N snapshot still asks within the window.
	dec = mustEvaluate(t, eval, snapN, dnsReq(sessS1, approved), testT0.Add(1*time.Minute))
	if dec.Action != ActionAsk {
		t.Errorf("original snapshot Action = %q after ApplyGrant, want %q (prior snapshot must be unchanged)", dec.Action, ActionAsk)
	}
	if snapN.Seq != 7 {
		t.Errorf("original snapshot Seq mutated: %d, want 7", snapN.Seq)
	}
}

func TestAskGrant_SessionScoped_NoCrossSessionAdmission(t *testing.T) {
	// planRef: doc 09 §8 Stage 0 (session-scoped grants) + doc 06 §3(c)
	// spirit: session A's privileges never reach session B. ADVERSARIAL:
	// and a grant can never punch through a blocklist.
	eval := NewEvaluator()
	clock := newFakeClock(testT0)

	t.Run("grant for S1 never admits S2", func(t *testing.T) {
		snapN := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: askPolicy()})
		snapN.Seq = 7
		grant := Grant{Session: sessS1, Domain: "newdomain.example", ExpiresAt: testT0.Add(5 * time.Minute), Seq: 8}
		snapN1, err := ApplyGrant(snapN, grant)
		if err != nil {
			t.Fatalf("ApplyGrant: %v", err)
		}
		// Sanity: S1 is admitted inside the TTL window.
		dec := mustEvaluate(t, eval, snapN1, dnsReq(sessS1, "newdomain.example"), clock.Now().Add(time.Minute))
		if dec.Action != ActionAllow {
			t.Fatalf("S1 Action = %q, want %q", dec.Action, ActionAllow)
		}
		// S2 must stay Ask/Deny within the same window.
		dec = mustEvaluate(t, eval, snapN1, dnsReq(sessS2, "newdomain.example"), clock.Now().Add(time.Minute))
		if dec.Action == ActionAllow {
			t.Fatalf("S2 admitted by S1's grant — grants must be session-scoped")
		}
		if dec.Action != ActionAsk && dec.Action != ActionDeny {
			t.Errorf("S2 Action = %q, want Ask or Deny", dec.Action)
		}
	})

	t.Run("grant cannot punch through the baseline blocklist", func(t *testing.T) {
		bl := mustBaseline(t)
		snapB := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: bl})
		snapB.Seq = 11
		grant := Grant{Session: sessS1, Domain: "dns.google", ExpiresAt: testT0.Add(5 * time.Minute), Seq: 12}
		snapB2, err := ApplyGrant(snapB, grant)
		if err != nil {
			// Refusing the grant outright is acceptable — but it must be a
			// real refusal, not an unimplemented stub.
			if errors.Is(err, ErrNotImplemented) {
				t.Fatalf("ApplyGrant is not implemented: %v", err)
			}
			return
		}
		dec := mustEvaluate(t, eval, snapB2, dnsReq(sessS1, "dns.google"), clock.Now().Add(time.Minute))
		if dec.Action != ActionDeny {
			t.Fatalf("dns.google Action = %q under an approval grant, want %q — deny-overrides applies to grants too", dec.Action, ActionDeny)
		}
		if want := blockRuleID(t, bl, "dns.google"); dec.Provenance.RuleID != want {
			t.Errorf("Provenance.RuleID = %q, want the blocklist rule %q", dec.Provenance.RuleID, want)
		}
		if dec.Provenance.Layer != LayerSystem {
			t.Errorf("Provenance.Layer = %q, want %q", dec.Provenance.Layer, LayerSystem)
		}
	})
}
