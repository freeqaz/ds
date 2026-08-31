package policycore

// POL-3: one engine, decision provenance. Every decision carries rule id +
// layer + policy version; a missing-provenance event is a failure; Evaluate
// is a pure deterministic function; all caller shapes agree.

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// provenanceMatrixSnapshot composes the three-layer snapshot used by
// POL-3.a: posture standard with ask defaults, a pass-through domain, a
// cred-swap service, and a session-scoped escape hatch at the system layer;
// allow/block at the org layer; one session-layer allow.
func provenanceMatrixSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	system := &Policy{
		SchemaVersion: SchemaV0,
		Name:          "sys",
		PackVersion:   "1.0.0",
		Posture:       PostureStandard,
		Allow: []AllowRule{
			{ID: "alw-sys-github", Domain: "github.com", Service: "github"},
			{ID: "alw-sys-api-github", Domain: "api.github.com", Service: "github"},
			{ID: "alw-sys-pinned", Domain: "pinned.example"},
		},
		PassThrough: []string{"pinned.example"},
		CredSwap: []SwapServiceRule{
			{ID: "swap-github", Service: "github", Hosts: []string{"github.com", "api.github.com"}, CredentialLocation: "Authorization"},
		},
		EscapeHatches: []EscapeHatchRule{
			{ID: "hatch-ssh", Protocol: "ssh", Port: 22, Scope: GrantScope{Session: "S1"}},
		},
		AskDefaults: AskDefaults{UnlistedDomain: ActionAsk, GrantTTL: 5 * time.Minute},
	}
	org := &Policy{
		SchemaVersion: SchemaV0,
		Name:          "org",
		PackVersion:   "1.0.0",
		Posture:       PostureStandard,
		Allow:         []AllowRule{{ID: "alw-org-allowed", Domain: "allowed.example"}},
		Block:         []BlockRule{{ID: "blk-org-blocked", Domain: "blocked.example"}},
	}
	sess := &Policy{
		SchemaVersion: SchemaV0,
		Name:          "sess",
		PackVersion:   "1.0.0",
		Posture:       PostureStandard,
		Allow:         []AllowRule{{ID: "alw-sess", Domain: "session-allowed.example"}},
	}
	return mustCompose(t,
		LayeredPolicy{Layer: LayerSystem, Policy: system},
		LayeredPolicy{Layer: LayerOrg, Policy: org},
		LayeredPolicy{Layer: LayerSession, Policy: sess},
	)
}

func TestEvaluate_EveryDecisionCarriesFullProvenance(t *testing.T) {
	// planRef: doc 09 §6 POL-3 Done-when: every event carries rule id,
	// policy layer, policy version — including default-deny and Ask.
	snap := provenanceMatrixSnapshot(t)
	eval := NewEvaluator()

	type cell struct {
		name       string
		req        Request
		wantAction Action
		// looseAction: semantics still open (doc 03 OQ7 territory); only
		// require the decision is not an Allow. Provenance is asserted
		// unconditionally for every cell.
		looseAction bool
		check       func(t *testing.T, d Decision)
	}

	cases := []cell{
		// KindDNSResolve
		{name: "dns/explicit-allow", req: dnsReq(sessS1, "allowed.example"), wantAction: ActionAllow},
		{name: "dns/blocklist-deny", req: dnsReq(sessS1, "blocked.example"), wantAction: ActionDeny},
		{name: "dns/default-deny-zero-scope", req: zeroScope(dnsReq(sessS1, "allowed.example")), wantAction: ActionDeny},
		{name: "dns/ask-unlisted", req: dnsReq(sessS1, "unlisted.example"), wantAction: ActionAsk},
		{name: "dns/pass-through-domain", req: dnsReq(sessS1, "pinned.example"), wantAction: ActionAllow},
		{name: "dns/swap-service-domain", req: dnsReq(sessS1, "github.com"), wantAction: ActionAllow},
		{name: "dns/session-layer-allow", req: dnsReq(sessS1, "session-allowed.example"), wantAction: ActionAllow,
			check: func(t *testing.T, d Decision) {
				if d.Provenance.Layer != LayerSession {
					t.Errorf("Layer = %q, want %q", d.Provenance.Layer, LayerSession)
				}
			}},

		// KindTLSSNI
		{name: "sni/explicit-allow", req: sniReq(sessS1, "allowed.example"), wantAction: ActionAllow},
		{name: "sni/blocklist-deny", req: sniReq(sessS1, "blocked.example"), wantAction: ActionDeny},
		{name: "sni/default-deny-zero-scope", req: zeroScope(sniReq(sessS1, "allowed.example")), wantAction: ActionDeny},
		{name: "sni/ask-unlisted", req: sniReq(sessS1, "unlisted.example"), wantAction: ActionAsk},
		{name: "sni/pass-through", req: sniReq(sessS1, "pinned.example"), wantAction: ActionAllow,
			check: func(t *testing.T, d Decision) {
				if !d.PassThrough {
					t.Errorf("PassThrough = false for a pass-through-listed domain")
				}
				if d.SwapService != "" {
					t.Errorf("SwapService = %q on a pass-through tunnel; never combined", d.SwapService)
				}
			}},
		{name: "sni/swap-service", req: sniReq(sessS1, "github.com"), wantAction: ActionAllow,
			check: func(t *testing.T, d Decision) {
				if d.SwapService != "github" {
					t.Errorf("SwapService = %q, want %q", d.SwapService, "github")
				}
				if d.PassThrough {
					t.Errorf("PassThrough = true on a swap-service flow; never combined")
				}
			}},
		{name: "sni/session-layer-allow", req: sniReq(sessS1, "session-allowed.example"), wantAction: ActionAllow},

		// KindHTTPRequest
		{name: "http/explicit-allow", req: httpReq(sessS1, "allowed.example", "GET", "/"), wantAction: ActionAllow},
		{name: "http/blocklist-deny", req: httpReq(sessS1, "blocked.example", "GET", "/"), wantAction: ActionDeny},
		{name: "http/default-deny-zero-scope", req: zeroScope(httpReq(sessS1, "allowed.example", "GET", "/")), wantAction: ActionDeny},
		{name: "http/ask-unlisted", req: httpReq(sessS1, "unlisted.example", "GET", "/"), wantAction: ActionAsk},
		{name: "http/pass-through-host", req: httpReq(sessS1, "pinned.example", "GET", "/"), wantAction: ActionAllow},
		{name: "http/swap-service", req: httpReq(sessS1, "api.github.com", "POST", "/repos"), wantAction: ActionAllow,
			check: func(t *testing.T, d Decision) {
				if d.SwapService != "github" {
					t.Errorf("SwapService = %q, want %q", d.SwapService, "github")
				}
			}},
		{name: "http/session-layer-allow", req: httpReq(sessS1, "session-allowed.example", "GET", "/"), wantAction: ActionAllow},

		// KindL4Direct
		{name: "l4/escape-hatch-allow", req: l4Req(sessS1, "github.com", testIP, 22, "ssh"), wantAction: ActionAllow,
			check: func(t *testing.T, d Decision) {
				if !d.DirectL4 {
					t.Errorf("DirectL4 = false on an escape-hatch allow")
				}
			}},
		{name: "l4/blocklist-deny", req: l4Req(sessS1, "blocked.example", testIP, 22, "ssh"), wantAction: ActionDeny},
		{name: "l4/default-deny-unlisted-port", req: l4Req(sessS1, "smtp.example", testIP, 25, "tcp"), wantAction: ActionDeny},
		{name: "l4/hatch-out-of-scope", req: l4Req(sessS2, "github.com", testIP, 22, "ssh"), wantAction: ActionDeny},
		{name: "l4/default-deny-zero-scope", req: zeroScope(l4Req(sessS1, "github.com", testIP, 22, "ssh")), wantAction: ActionDeny},
		{name: "l4/unlisted-protocol-never-allow", req: l4Req(sessS1, "ntp.example", testIP, 123, "udp"), looseAction: true},
		{name: "l4/pass-through-direct-no-hatch", req: l4Req(sessS1, "pinned.example", testIP, 443, "tcp"), wantAction: ActionDeny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := eval.Evaluate(snap, tc.req, testT0)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if tc.looseAction {
				if dec.Action == ActionAllow {
					t.Fatalf("Action = %q; this cell must never be an allow", dec.Action)
				}
			} else if dec.Action != tc.wantAction {
				t.Fatalf("Action = %q, want %q", dec.Action, tc.wantAction)
			}
			// The CI gate function must accept every cell's provenance.
			if perr := ValidateProvenance(dec.Provenance); perr != nil {
				t.Errorf("ValidateProvenance: %v (provenance %+v)", perr, dec.Provenance)
			}
			assertFullProvenance(t, dec, snap)
			if tc.check != nil {
				tc.check(t, dec)
			}
		})
	}

	t.Run("default-deny rule id is synthetic but stable", func(t *testing.T) {
		req := zeroScope(dnsReq(sessS1, "allowed.example"))
		d1, err1 := eval.Evaluate(snap, req, testT0)
		d2, err2 := eval.Evaluate(snap, req, testT0)
		if err1 != nil || err2 != nil {
			t.Fatalf("Evaluate: %v / %v", err1, err2)
		}
		if d1.Provenance.RuleID == "" {
			t.Fatalf("implicit default-deny carries an empty rule id; want a synthetic stable one (e.g. \"default-deny\")")
		}
		if d1.Provenance.RuleID != d2.Provenance.RuleID {
			t.Errorf("default-deny rule id is unstable: %q vs %q", d1.Provenance.RuleID, d2.Provenance.RuleID)
		}
	})
}

func TestValidateProvenance_MissingProvenanceIsAFailure(t *testing.T) {
	// planRef: doc 09 §6 POL-3 Done-when: a missing-provenance event fails
	// CI. This function is the hook the doc-09 CI rule wires in.
	full := Provenance{RuleID: "alw-1", Layer: LayerOrg, PolicyVersion: "v1.2.3"}
	cases := []struct {
		name      string
		p         Provenance
		wantToken string // the missing/invalid field the error must identify
	}{
		{"zero-value provenance", Provenance{}, "rule"},
		{"missing RuleID only", Provenance{Layer: LayerSystem, PolicyVersion: "v1"}, "rule"},
		{"missing Layer only", Provenance{RuleID: "r1", PolicyVersion: "v1"}, "layer"},
		{"missing PolicyVersion only", Provenance{RuleID: "r1", Layer: LayerSession}, "version"},
		{"undefined Layer value", Provenance{RuleID: "r1", Layer: Layer("global"), PolicyVersion: "v1"}, "layer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProvenance(tc.p)
			if err == nil {
				t.Fatalf("incomplete provenance %+v accepted; the CI gate is open", tc.p)
			}
			if errors.Is(err, ErrNotImplemented) {
				t.Fatalf("provenance gate is not implemented: %v", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantToken) {
				t.Errorf("error %q does not identify the missing/invalid field (%q)", err, tc.wantToken)
			}
		})
	}

	t.Run("fully populated provenance passes", func(t *testing.T) {
		if err := ValidateProvenance(full); err != nil {
			t.Fatalf("ValidateProvenance(full) = %v, want nil", err)
		}
	})

	t.Run("ValidateDecisionEvent enforces the same gate", func(t *testing.T) {
		if err := ValidateDecisionEvent(Decision{Action: ActionDeny}); err == nil {
			t.Fatalf("provenance-free decision event accepted")
		} else if errors.Is(err, ErrNotImplemented) {
			t.Fatalf("decision-event gate is not implemented: %v", err)
		}
		ok := Decision{Action: ActionAllow, Provenance: full}
		if err := ValidateDecisionEvent(ok); err != nil {
			t.Fatalf("ValidateDecisionEvent(populated) = %v, want nil", err)
		}
	})
}

func TestProvenance_AttributesTheActuallyMatchedRule(t *testing.T) {
	// planRef: doc 09 §6 POL-3: "why was this blocked?" must always have a
	// one-line answer — provenance names the rule that DECIDED, not merely a
	// rule that matched.
	const domain = "contested.example"
	system := &Policy{
		SchemaVersion: SchemaV0, Name: "sys", PackVersion: "0.0.1", Posture: PostureStandard,
		Allow:       []AllowRule{{ID: "A2", Domain: domain}},
		AskDefaults: AskDefaults{UnlistedDomain: ActionAsk, GrantTTL: 5 * time.Minute},
	}
	org := &Policy{
		SchemaVersion: SchemaV0, Name: "org", PackVersion: "0.0.1", Posture: PostureStandard,
		Block: []BlockRule{{ID: "B1", Domain: domain}},
	}
	sess := &Policy{
		SchemaVersion: SchemaV0, Name: "sess", PackVersion: "0.0.1", Posture: PostureStandard,
		Allow: []AllowRule{{ID: "A1", Domain: domain}},
	}
	snap := mustCompose(t,
		LayeredPolicy{Layer: LayerSystem, Policy: system},
		LayeredPolicy{Layer: LayerOrg, Policy: org},
		LayeredPolicy{Layer: LayerSession, Policy: sess},
	)
	dec := mustEvaluate(t, NewEvaluator(), snap, dnsReq(sessS1, domain), testT0)
	if dec.Action != ActionDeny {
		t.Fatalf("Action = %q, want %q", dec.Action, ActionDeny)
	}
	if dec.Provenance.RuleID != "B1" {
		t.Errorf("Provenance.RuleID = %q, want %q (the deciding block rule, never A1/A2)", dec.Provenance.RuleID, "B1")
	}
	if dec.Provenance.Layer != LayerOrg {
		t.Errorf("Provenance.Layer = %q, want %q", dec.Provenance.Layer, LayerOrg)
	}
}

func TestEvaluate_PureDeterministicAndRaceFree(t *testing.T) {
	// planRef: doc 09 §6 POL-3 / §2: one engine, identical decision
	// semantics. Same (snapshot, request, now) => identical Decision, no
	// mutation, concurrency-safe under -race.
	mkLayers := func() []LayeredPolicy {
		return []LayeredPolicy{
			{Layer: LayerSystem, Policy: &Policy{
				SchemaVersion: SchemaV0, Name: "sys", PackVersion: "1.0.0", Posture: PostureStandard,
				Allow:       []AllowRule{{ID: "alw-1", Domain: "allowed.example"}},
				Block:       []BlockRule{{ID: "blk-1", Domain: "blocked.example"}},
				AskDefaults: AskDefaults{UnlistedDomain: ActionAsk, GrantTTL: 5 * time.Minute},
			}},
		}
	}
	snap := mustCompose(t, mkLayers()...)
	reference := mustCompose(t, mkLayers()...)
	if !reflect.DeepEqual(snap, reference) {
		t.Fatalf("Compose is not deterministic for identical inputs")
	}

	eval := NewEvaluator()
	req := dnsReq(sessS1, "allowed.example")

	const goroutines = 32
	const perGoroutine = 32 // ~1000 evaluations total
	decs := make([][]Decision, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				d, err := eval.Evaluate(snap, req, testT0)
				if err != nil {
					errs[i] = err
					return
				}
				decs[i] = append(decs[i], d)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Evaluate: %v", i, err)
		}
	}

	first := decs[0][0]
	if first.Action != ActionAllow {
		t.Fatalf("Action = %q, want %q", first.Action, ActionAllow)
	}
	for i := range decs {
		for j := range decs[i] {
			if !reflect.DeepEqual(decs[i][j], first) {
				t.Fatalf("decision diverged at goroutine %d call %d:\n got = %+v\nwant = %+v", i, j, decs[i][j], first)
			}
		}
	}

	// Immutability: the snapshot is byte-identical to the untouched reference
	// composed from the same inputs.
	if !reflect.DeepEqual(snap, reference) {
		t.Errorf("Evaluate mutated the snapshot")
	}

	// Calling order has no effect: the same single call twice agrees.
	d1 := mustEvaluate(t, eval, snap, req, testT0)
	d2 := mustEvaluate(t, eval, snap, req, testT0)
	if !reflect.DeepEqual(d1, d2) {
		t.Errorf("repeated identical call returned different decisions:\n%+v\n%+v", d1, d2)
	}
}

func TestOneEngine_AllCallerShapesAgree(t *testing.T) {
	// planRef: doc 09 §6 intro: "the DNS gate, the TLS proxy, and the
	// firewall programming can never disagree about a rule" — the D63
	// siblings-can't-skew property at the pure-function level.
	system := &Policy{
		SchemaVersion: SchemaV0, Name: "sys", PackVersion: "1.0.0", Posture: PostureStandard,
		Allow: []AllowRule{{ID: "alw-1", Domain: "allowed.example"}},
		Block: []BlockRule{
			{ID: "blk-1", Domain: "blocked.example"},
			{ID: "blk-wild", Domain: "*.denied.example"},
		},
		AskDefaults: AskDefaults{UnlistedDomain: ActionAsk, GrantTTL: 5 * time.Minute},
	}
	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: system})
	eval := NewEvaluator()

	cases := []struct {
		domain     string
		wantAction Action
		wantRuleID string // empty = only require cross-kind identity
	}{
		{"allowed.example", ActionAllow, "alw-1"},
		{"blocked.example", ActionDeny, "blk-1"},
		{"sub.denied.example", ActionDeny, "blk-wild"},
		{"newdomain.example", ActionAsk, ""},
	}
	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			reqs := []Request{
				dnsReq(sessS1, tc.domain),
				sniReq(sessS1, tc.domain),
				httpReq(sessS1, tc.domain, "GET", "/"),
			}
			decs := make([]Decision, len(reqs))
			for i, req := range reqs {
				decs[i] = mustEvaluate(t, eval, snap, req, testT0)
			}
			for i, dec := range decs {
				if dec.Action != tc.wantAction {
					t.Errorf("%s: Action = %q, want %q", reqs[i].Kind, dec.Action, tc.wantAction)
				}
				if tc.wantRuleID != "" && dec.Provenance.RuleID != tc.wantRuleID {
					t.Errorf("%s: RuleID = %q, want %q", reqs[i].Kind, dec.Provenance.RuleID, tc.wantRuleID)
				}
				// The verdict and the deciding rule must be identical across
				// caller shapes (kind-specific fields like SwapService may differ).
				if dec.Action != decs[0].Action || dec.Provenance.RuleID != decs[0].Provenance.RuleID {
					t.Errorf("caller shapes disagree: %s got (%q, %q), %s got (%q, %q)",
						reqs[0].Kind, decs[0].Action, decs[0].Provenance.RuleID,
						reqs[i].Kind, dec.Action, dec.Provenance.RuleID)
				}
			}
		})
	}
}
