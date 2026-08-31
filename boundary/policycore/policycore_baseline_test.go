package policycore

// POL-2: the D64 (amended by D74) default baseline pack — exact admit
// surface, default-deny for everything else, gate-upstream-only resolvers,
// the DoH/DoT blocklist, and "nothing magic about the defaults".

import (
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// baselineVMEndpoints is the exact strawman admit surface from the doc 09 §6
// POL-2 table: no more, no fewer. Adding an endpoint to the shipped pack
// without updating this spec fails RED.
var baselineVMEndpoints = []string{
	"api.anthropic.com",
	"github.com",
	"api.github.com",
	"codeload.github.com",
	"objects.githubusercontent.com",
	"raw.githubusercontent.com",
	"registry.npmjs.org",
}

// baselineUpstreamResolvers are host-side egress for ds-dnsgate's own
// upstream queries only — never direct VM resolver access.
var baselineUpstreamResolvers = []string{"1.1.1.1", "8.8.8.8"}

// baselineDoHBlocklist is the resolver-lock blocklist shipped in the pack.
var baselineDoHBlocklist = []string{"dns.google", "cloudflare-dns.com", "dns.quad9.net"}

func baselineAllowDomainsByScope(p *Policy) (vm, gateUpstream []string) {
	for _, a := range p.Allow {
		if a.Scope == ScopeGateUpstream {
			gateUpstream = append(gateUpstream, a.Domain)
		} else {
			vm = append(vm, a.Domain)
		}
	}
	return vm, gateUpstream
}

func TestBaseline_AdmitsExactlyTheIntendedEndpoints(t *testing.T) {
	// planRef: doc 09 §6 POL-2 Done-when: every endpoint the §1 test touches
	// is admitted by the shipped pack and nothing else.
	bl := mustBaseline(t)
	if bl.Name != BaselinePackName {
		t.Errorf("pack Name = %q, want %q", bl.Name, BaselinePackName)
	}

	vmDomains, _ := baselineAllowDomainsByScope(bl)
	if got, want := sortedStrings(vmDomains), sortedStrings(baselineVMEndpoints); !reflect.DeepEqual(got, want) {
		t.Errorf("baseline VM-scoped allowlist != the enumerated endpoint set:\n got = %v\nwant = %v", got, want)
	}

	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: bl})
	eval := NewEvaluator()
	for _, domain := range baselineVMEndpoints {
		for _, req := range []Request{dnsReq(sessS1, domain), sniReq(sessS1, domain)} {
			t.Run(string(req.Kind)+"/"+domain, func(t *testing.T) {
				dec := mustEvaluate(t, eval, snap, req, testT0)
				if dec.Action != ActionAllow {
					t.Fatalf("Action = %q, want %q", dec.Action, ActionAllow)
				}
				if dec.Provenance.Layer != LayerSystem {
					t.Errorf("Provenance.Layer = %q, want %q (the shipped pack)", dec.Provenance.Layer, LayerSystem)
				}
				if dec.Provenance.RuleID == "" {
					t.Errorf("allow decision carries empty RuleID")
				}
				if dec.Provenance.PolicyVersion != snap.PolicyVersion {
					t.Errorf("Provenance.PolicyVersion = %q, want %q", dec.Provenance.PolicyVersion, snap.PolicyVersion)
				}
			})
		}
	}
}

func TestBaseline_DeniesEverythingElse_IncludingLookalikes(t *testing.T) {
	// planRef: doc 09 §6 POL-2 Done-when ("and nothing else") + doc 06 §3(c)
	// default-deny row. ADVERSARIAL: suffix/prefix lookalikes never admit.
	bl := mustBaseline(t)
	// Compose with posture locked to isolate the allowlist from standard-
	// posture ask defaults (the baseline is ordinary policy data — POL-2.e).
	bl.Posture = PostureLocked
	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: bl})
	eval := NewEvaluator()

	lookalikes := []string{
		"example.com",
		"api.anthropic.com.evil.test",         // allowed name as a label prefix
		"evil-github.com",                     // prefix lookalike
		"github.com.attacker.io",              // allowed name as a suffix label chain
		"xgithub.com",                         // near-miss
		"registry.npmjs.org.cdn.attacker.net", // allowed name buried in attacker zone
		"GITHUB.COM%00.evil.test",             // case + NUL-injection lookalike
	}
	for _, domain := range lookalikes {
		for _, req := range []Request{dnsReq(sessS1, domain), sniReq(sessS1, domain)} {
			t.Run(string(req.Kind)+"/"+domain, func(t *testing.T) {
				dec := mustEvaluate(t, eval, snap, req, testT0)
				if dec.Action != ActionDeny {
					t.Fatalf("Action = %q, want %q — default-deny must hold", dec.Action, ActionDeny)
				}
				assertFullProvenance(t, dec, snap)
			})
		}
	}

	t.Run("l4-direct/ssh github.com:22 without a hatch", func(t *testing.T) {
		// SSH stays off unless an escape hatch admits it (doc 09 §6 POL-2 table).
		dec := mustEvaluate(t, eval, snap, l4Req(sessS1, "github.com", netip.MustParseAddr("140.82.112.3"), 22, "ssh"), testT0)
		if dec.Action != ActionDeny {
			t.Fatalf("Action = %q, want %q", dec.Action, ActionDeny)
		}
		if dec.DirectL4 {
			t.Errorf("DirectL4 = true on a denied flow")
		}
		assertFullProvenance(t, dec, snap)
	})

	t.Run("empty-domain request denied", func(t *testing.T) {
		dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, ""), testT0)
		if dec.Action != ActionDeny {
			t.Fatalf("Action = %q, want %q", dec.Action, ActionDeny)
		}
		assertFullProvenance(t, dec, snap)
	})
}

func TestBaseline_HostResolvers_GateUpstreamOnly_NeverVM(t *testing.T) {
	// planRef: doc 09 §6 POL-2 baseline table row: 1.1.1.1/8.8.8.8 are
	// host-side egress for ds-dnsgate's own upstream only. ADVERSARIAL: the
	// VM can never exploit the resolver entries to reach them directly.
	bl := mustBaseline(t)
	_, upstream := baselineAllowDomainsByScope(bl)
	if got, want := sortedStrings(upstream), sortedStrings(baselineUpstreamResolvers); !reflect.DeepEqual(got, want) {
		t.Errorf("baseline gate-upstream entries = %v, want exactly %v", got, want)
	}

	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: bl})
	eval := NewEvaluator()

	mkReq := func(ip string, port uint16, proto string, scope RequestScope) Request {
		return Request{
			Session:  sessS1,
			Kind:     KindL4Direct,
			Scope:    scope,
			DstIP:    netip.MustParseAddr(ip),
			DstPort:  port,
			Protocol: proto,
		}
	}

	// All six VM-scoped attempts at the resolvers must deny.
	for _, ip := range baselineUpstreamResolvers {
		for _, pp := range []struct {
			port  uint16
			proto string
		}{{53, "udp"}, {853, "tcp"}, {443, "tcp"}} {
			req := mkReq(ip, pp.port, pp.proto, ScopeVM)
			t.Run("vm-scope/"+ip+"/"+req.Protocol, func(t *testing.T) {
				dec := mustEvaluate(t, eval, snap, req, testT0)
				if dec.Action != ActionDeny {
					t.Fatalf("VM reached resolver %s:%d directly: Action = %q, want %q", ip, pp.port, dec.Action, ActionDeny)
				}
				assertFullProvenance(t, dec, snap)
			})
		}
	}

	// The gate's own upstream egress on port 53 is allowed, attributed to
	// the pack's actual gate-upstream allow rule (not just any rule).
	for _, ip := range baselineUpstreamResolvers {
		req := mkReq(ip, 53, "udp", ScopeGateUpstream)
		wantRule := gateUpstreamRuleID(t, bl, ip)
		t.Run("gate-upstream/"+ip, func(t *testing.T) {
			dec := mustEvaluate(t, eval, snap, req, testT0)
			if dec.Action != ActionAllow {
				t.Fatalf("gate upstream egress to %s:53 denied: Action = %q, want %q", ip, dec.Action, ActionAllow)
			}
			if dec.Provenance.Layer != LayerSystem {
				t.Errorf("Provenance.Layer = %q, want %q (upstream-resolution baseline rule)", dec.Provenance.Layer, LayerSystem)
			}
			if dec.Provenance.RuleID != wantRule {
				t.Errorf("Provenance.RuleID = %q, want the upstream-resolution baseline rule %q", dec.Provenance.RuleID, wantRule)
			}
			if dec.Provenance.PolicyVersion != snap.PolicyVersion {
				t.Errorf("Provenance.PolicyVersion = %q, want %q", dec.Provenance.PolicyVersion, snap.PolicyVersion)
			}
		})
	}

	// ADVERSARIAL: ScopeGateUpstream is NOT an unconstrained egress channel.
	// Only the baseline resolver IPs on port 53 are admitted — any other
	// destination or port under the gate-upstream scope must deny.
	for _, tc := range []struct {
		name string
		req  Request
	}{
		{"non-baseline resolver 9.9.9.9:53", mkReq("9.9.9.9", 53, "udp", ScopeGateUpstream)},
		{"baseline resolver on https port 1.1.1.1:443", mkReq("1.1.1.1", 443, "tcp", ScopeGateUpstream)},
		{"baseline resolver on dot port 8.8.8.8:853", mkReq("8.8.8.8", 853, "tcp", ScopeGateUpstream)},
	} {
		t.Run("gate-upstream-deny/"+tc.name, func(t *testing.T) {
			dec := mustEvaluate(t, eval, snap, tc.req, testT0)
			if dec.Action != ActionDeny {
				t.Fatalf("gate-upstream egress to %s:%d admitted: Action = %q, want %q — the gate's upstream leg must not become an open egress channel",
					tc.req.DstIP, tc.req.DstPort, dec.Action, ActionDeny)
			}
			assertFullProvenance(t, dec, snap)
		})
	}

	t.Run("zero-value scope is denied, never defaulted permissive", func(t *testing.T) {
		req := mkReq("1.1.1.1", 53, "udp", "")
		dec := mustEvaluate(t, eval, snap, req, testT0)
		if dec.Action != ActionDeny {
			t.Fatalf("zero-scope request got Action = %q, want %q", dec.Action, ActionDeny)
		}
		assertFullProvenance(t, dec, snap)
	})
}

func TestBaseline_DoHDoTResolverBlocklist_Wins(t *testing.T) {
	// planRef: doc 09 §9 "DoH endpoint blocking (baseline blocklist...)" row
	// owned by POL-2; doc 06 §3(c) DoH/DoT-bypass row. ADVERSARIAL: no
	// downstream allowlist can reopen a baseline-blocked resolver.
	bl := mustBaseline(t)
	eval := NewEvaluator()

	// Part 1: baseline alone blocks the known public DoH/DoT resolvers.
	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: bl})
	for _, domain := range baselineDoHBlocklist {
		wantRule := blockRuleID(t, bl, domain)
		for _, req := range []Request{dnsReq(sessS1, domain), sniReq(sessS1, domain)} {
			t.Run("baseline/"+string(req.Kind)+"/"+domain, func(t *testing.T) {
				dec := mustEvaluate(t, eval, snap, req, testT0)
				if dec.Action != ActionDeny {
					t.Fatalf("Action = %q, want %q", dec.Action, ActionDeny)
				}
				if dec.Provenance.RuleID != wantRule {
					t.Errorf("Provenance.RuleID = %q, want the baseline blocklist rule %q", dec.Provenance.RuleID, wantRule)
				}
				if dec.Provenance.Layer != LayerSystem {
					t.Errorf("Provenance.Layer = %q, want %q", dec.Provenance.Layer, LayerSystem)
				}
			})
		}
	}

	// Part 2 (bypass attempt): org AND session layers explicitly allowlist
	// dns.google — deny-overrides keeps it blocked.
	orgPol := &Policy{
		SchemaVersion: SchemaV0, Name: "org-doh-bypass", PackVersion: "0.0.1", Posture: PostureStandard,
		Allow: []AllowRule{{ID: "alw-org-doh", Domain: "dns.google"}},
	}
	sessPol := &Policy{
		SchemaVersion: SchemaV0, Name: "session-doh-bypass", PackVersion: "0.0.1", Posture: PostureStandard,
		Allow: []AllowRule{{ID: "alw-sess-doh", Domain: "dns.google"}},
	}
	snap2 := mustCompose(t,
		LayeredPolicy{Layer: LayerSystem, Policy: bl},
		LayeredPolicy{Layer: LayerOrg, Policy: orgPol},
		LayeredPolicy{Layer: LayerSession, Policy: sessPol},
	)
	wantRule := blockRuleID(t, bl, "dns.google")
	for _, req := range []Request{dnsReq(sessS1, "dns.google"), sniReq(sessS1, "dns.google")} {
		t.Run("bypass-attempt/"+string(req.Kind), func(t *testing.T) {
			dec := mustEvaluate(t, eval, snap2, req, testT0)
			if dec.Action != ActionDeny {
				t.Fatalf("downstream allowlist reopened a baseline-blocked resolver: Action = %q, want %q", dec.Action, ActionDeny)
			}
			if dec.Provenance.RuleID != wantRule {
				t.Errorf("Provenance.RuleID = %q, want %q", dec.Provenance.RuleID, wantRule)
			}
			if dec.Provenance.Layer != LayerSystem {
				t.Errorf("Provenance.Layer = %q, want %q", dec.Provenance.Layer, LayerSystem)
			}
		})
	}
}

func TestBaseline_IsOrdinaryPolicy_EmptyExtendReplace(t *testing.T) {
	// planRef: doc 09 §6 POL-2: "a team can empty it, extend it, or replace
	// it through the same engine — nothing magic about the defaults".
	eval := NewEvaluator()

	t.Run("emptied: baseline admits live in data, not code", func(t *testing.T) {
		empty := &Policy{SchemaVersion: SchemaV0, Name: "emptied", PackVersion: "0.0.1", Posture: PostureLocked}
		snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: empty})
		dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, "api.anthropic.com"), testT0)
		if dec.Action != ActionDeny {
			t.Fatalf("api.anthropic.com allowed with the baseline removed: a hardcoded allow path exists (Action %q)", dec.Action)
		}
	})

	t.Run("extended: org layer adds pypi.org", func(t *testing.T) {
		bl := mustBaseline(t)
		org := &Policy{
			SchemaVersion: SchemaV0, Name: "org-extend", PackVersion: "0.0.1", Posture: PostureStandard,
			Allow: []AllowRule{{ID: "alw-org-pypi", Domain: "pypi.org"}},
		}
		snap := mustCompose(t,
			LayeredPolicy{Layer: LayerSystem, Policy: bl},
			LayeredPolicy{Layer: LayerOrg, Policy: org},
		)
		dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, "pypi.org"), testT0)
		if dec.Action != ActionAllow {
			t.Fatalf("pypi.org Action = %q, want %q", dec.Action, ActionAllow)
		}
		if dec.Provenance.Layer != LayerOrg {
			t.Errorf("Provenance.Layer = %q, want %q", dec.Provenance.Layer, LayerOrg)
		}
		if dec.Provenance.RuleID != "alw-org-pypi" {
			t.Errorf("Provenance.RuleID = %q, want %q", dec.Provenance.RuleID, "alw-org-pypi")
		}
	})

	t.Run("replaced: custom pack admits only internal.corp.example", func(t *testing.T) {
		custom := &Policy{
			SchemaVersion: SchemaV0, Name: "corp-pack", PackVersion: "1.0.0", Posture: PostureLocked,
			Allow: []AllowRule{{ID: "alw-internal", Domain: "internal.corp.example"}},
		}
		snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: custom})
		dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, "internal.corp.example"), testT0)
		if dec.Action != ActionAllow {
			t.Fatalf("internal.corp.example Action = %q, want %q", dec.Action, ActionAllow)
		}
		for _, domain := range baselineVMEndpoints {
			dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, domain), testT0)
			if dec.Action != ActionDeny {
				t.Errorf("baseline endpoint %s survived a wholesale pack replacement: Action = %q, want %q", domain, dec.Action, ActionDeny)
			}
		}
	})
}

func TestBaseline_PackIsVersionedAndCitedInProvenance(t *testing.T) {
	// planRef: doc 09 §6 POL-2 "a versioned, named policy pack" + POL-3
	// provenance: every baseline decision is attributable to a shipped pack
	// version.
	bl := mustBaseline(t)
	if bl.Name != BaselinePackName {
		t.Errorf("Name = %q, want %q", bl.Name, BaselinePackName)
	}
	semver := regexp.MustCompile(`^v?\d+\.\d+\.\d+`)
	if bl.PackVersion == "" || !semver.MatchString(bl.PackVersion) {
		t.Errorf("PackVersion = %q, want non-empty semver-shaped", bl.PackVersion)
	}

	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: bl})
	if !strings.Contains(snap.PolicyVersion, bl.PackVersion) {
		t.Errorf("snapshot PolicyVersion %q does not embed the pack version %q", snap.PolicyVersion, bl.PackVersion)
	}

	eval := NewEvaluator()
	allowed := mustEvaluate(t, eval, snap, dnsReq(sessS1, "github.com"), testT0)
	blocked := mustEvaluate(t, eval, snap, dnsReq(sessS1, "dns.google"), testT0)
	if allowed.Action != ActionAllow {
		t.Errorf("github.com Action = %q, want %q", allowed.Action, ActionAllow)
	}
	if blocked.Action != ActionDeny {
		t.Errorf("dns.google Action = %q, want %q", blocked.Action, ActionDeny)
	}
	for _, dec := range []Decision{allowed, blocked} {
		if dec.Provenance.PolicyVersion != snap.PolicyVersion {
			t.Errorf("Provenance.PolicyVersion = %q, want the composed snapshot version %q", dec.Provenance.PolicyVersion, snap.PolicyVersion)
		}
	}
}

func TestE2E_FreshInstall_ReachabilityHalf_ZeroConfig(t *testing.T) {
	// planRef: doc 09 §6 POL-2 Done-when: the reachability half of the §1
	// developer-value test passes on a fresh install with zero policy
	// configuration. Fake ds-dnsgate + ds-tlsproxy shapes wired to the one
	// engine, DefaultBaseline as the only layer.
	bl := mustBaseline(t)
	snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: bl})
	// Reference snapshot composed from identical inputs: any mutation of the
	// live snapshot during the run (compiled rule state, PolicyVersion, Seq)
	// is detectable by deep comparison, not just via the Seq field.
	reference := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: mustBaseline(t)})
	seqBefore := snap.Seq

	eval := NewEvaluator()
	gate := &fakeDNSGate{eval: eval, snap: snap}
	proxy := &fakeTLSProxy{eval: eval, snap: snap}

	// Fresh-session lifecycle: resolve + connect for each baseline domain.
	for _, domain := range baselineVMEndpoints {
		dec, err := gate.Resolve(sessS1, domain, testT0)
		if err != nil {
			t.Fatalf("dnsgate resolve %s: %v", domain, err)
		}
		if dec.Action != ActionAllow {
			t.Errorf("dnsgate resolve %s: Action = %q, want %q", domain, dec.Action, ActionAllow)
		}
		dec, err = proxy.ConnectSNI(sessS1, domain, testT0)
		if err != nil {
			t.Fatalf("tlsproxy connect %s: %v", domain, err)
		}
		if dec.Action != ActionAllow {
			t.Errorf("tlsproxy connect %s: Action = %q, want %q", domain, dec.Action, ActionAllow)
		}
	}

	// Everything else drops with no policy configured.
	dec, err := gate.Resolve(sessS1, "example.com", testT0)
	if err != nil {
		t.Fatalf("dnsgate resolve example.com: %v", err)
	}
	if dec.Action != ActionDeny {
		t.Errorf("dnsgate resolve example.com: Action = %q, want %q", dec.Action, ActionDeny)
	}
	dec, err = proxy.ConnectSNI(sessS1, "example.com", testT0)
	if err != nil {
		t.Fatalf("tlsproxy connect example.com: %v", err)
	}
	if dec.Action != ActionDeny {
		t.Errorf("tlsproxy connect example.com: Action = %q, want %q", dec.Action, ActionDeny)
	}
	dec = mustEvaluate(t, eval, snap, l4Req(sessS1, "", netip.MustParseAddr("93.184.216.34"), 443, "tcp"), testT0)
	if dec.Action != ActionDeny {
		t.Errorf("raw-IP dial 93.184.216.34:443: Action = %q, want %q", dec.Action, ActionDeny)
	}

	// Zero policy-layer mutations occurred during the run: the live snapshot
	// is byte-identical to the untouched reference, not merely same-Seq.
	if snap.Seq != seqBefore {
		t.Errorf("snapshot Seq changed during the run: %d -> %d", seqBefore, snap.Seq)
	}
	if !reflect.DeepEqual(snap, reference) {
		t.Errorf("snapshot mutated during the run:\n got = %+v\nwant untouched reference = %+v", snap, reference)
	}
}
