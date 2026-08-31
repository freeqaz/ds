package policycore

// POL-1: policy schema v0, parse/validate/round-trip, layered composition
// with deny-overrides, posture semantics.

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const lockedFixtureYAML = `schema_version: v0
name: sample-locked
pack_version: 1.0.0
posture: locked
allow:
  - id: alw-anthropic
    domain: api.anthropic.com
  - id: alw-github
    domain: github.com
    service: github
block:
  - id: blk-doh
    domain: dns.google
rate_limits:
  - id: rl-github
    service: github
    per_session: 100
    per_service: 1000
    window: 1m
escape_hatches:
  - id: hatch-ssh
    protocol: ssh
    port: 22
    scope:
      session: S1
pass_through:
  - pinned.example.com
cred_swap:
  - id: swap-github
    service: github
    hosts: [github.com, api.github.com]
    credential_location: Authorization
ask_defaults:
  unlisted_domain: deny
  grant_ttl: 5m
`

const standardFixtureYAML = `schema_version: v0
name: sample-standard
pack_version: 1.1.0
posture: standard
allow:
  - id: alw-npm
    domain: registry.npmjs.org
    service: npm
block:
  - id: blk-quad9
    domain: dns.quad9.net
rate_limits:
  - id: rl-npm
    service: npm
    per_session: 50
    per_service: 500
    window: 30s
escape_hatches:
  - id: hatch-rsync
    protocol: rsync
    port: 873
    scope:
      org: O1
pass_through:
  - vault.pinned.example
cred_swap:
  - id: swap-npm
    service: npm
    hosts: [registry.npmjs.org]
    credential_location: Authorization
ask_defaults:
  unlisted_domain: ask
  grant_ttl: 10m
`

const openFixtureYAML = `schema_version: v0
name: sample-open
pack_version: 2.0.0
posture: open
allow:
  - id: alw-internal
    domain: internal.corp.example
block:
  - id: blk-cf-doh
    domain: cloudflare-dns.com
rate_limits:
  - id: rl-all
    service: any
    per_session: 1000
    per_service: 10000
    window: 1m
escape_hatches:
  - id: hatch-nfs
    protocol: nfs
    port: 2049
    scope:
      host: H1
pass_through:
  - pinned.open.example
cred_swap:
  - id: swap-internal
    service: internal
    hosts: [internal.corp.example]
    credential_location: Authorization
ask_defaults:
  unlisted_domain: allow
  grant_ttl: 1m
`

func TestParse_SamplePolicyPerPosture_RoundTrips(t *testing.T) {
	// planRef: doc 09 §6 POL-1 Done-when: a sample policy per posture round-trips parse→evaluate.
	cases := []struct {
		name    string
		yaml    string
		posture Posture
	}{
		{"locked", lockedFixtureYAML, PostureLocked},
		{"standard", standardFixtureYAML, PostureStandard},
		{"open", openFixtureYAML, PostureOpen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if p.SchemaVersion != SchemaV0 {
				t.Errorf("SchemaVersion = %q, want %q", p.SchemaVersion, SchemaV0)
			}
			if p.Posture != tc.posture {
				t.Errorf("Posture = %q, want %q", p.Posture, tc.posture)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			// Every documented schema section must be represented.
			if len(p.Allow) == 0 || len(p.Block) == 0 || len(p.RateLimits) == 0 ||
				len(p.EscapeHatches) == 0 || len(p.PassThrough) == 0 || len(p.CredSwap) == 0 {
				t.Errorf("fixture sections lost in parse: %+v", p)
			}
			if p.AskDefaults.GrantTTL <= 0 {
				t.Errorf("AskDefaults.GrantTTL not parsed, got %v", p.AskDefaults.GrantTTL)
			}
			// Stable round-trip: MarshalYAML -> Parse yields a deeply-equal policy.
			out, err := p.MarshalYAML()
			if err != nil {
				t.Fatalf("MarshalYAML: %v", err)
			}
			p2, err := Parse(out)
			if err != nil {
				t.Fatalf("re-Parse of marshaled policy: %v", err)
			}
			if !reflect.DeepEqual(p, p2) {
				t.Errorf("round-trip not stable:\n first = %+v\nsecond = %+v", p, p2)
			}
		})
	}
}

func TestParse_InvalidPolicies_Rejected(t *testing.T) {
	// planRef: doc 09 §6 POL-1 (schema validation half). ADVERSARIAL: a
	// malformed policy can never load and silently widen access.
	valid := func(body string) string {
		return "schema_version: v0\nname: invalid-fixture\npack_version: 0.0.1\nposture: locked\n" + body
	}
	cases := []struct {
		name      string
		yaml      string
		wantToken string // the offending field/value the error must name
	}{
		{"unknown posture value",
			"schema_version: v0\nname: x\npack_version: 0.0.1\nposture: yolo\n", "yolo"},
		{"unknown schema version",
			"schema_version: v999\nname: x\npack_version: 0.0.1\nposture: locked\n", "v999"},
		{"unknown top-level field",
			valid("bogus_section:\n  - nope\n"), "bogus_section"},
		{"domain with embedded whitespace",
			valid("allow:\n  - id: alw-1\n    domain: \"bad domain.com\"\n"), "bad domain.com"},
		{"domain with leading dot",
			valid("allow:\n  - id: alw-2\n    domain: .example.com\n"), ".example.com"},
		{"bare IP in domain allowlist",
			valid("allow:\n  - id: alw-3\n    domain: 10.0.0.1\n"), "10.0.0.1"},
		{"negative rate limit",
			valid("rate_limits:\n  - id: rl-1\n    service: github\n    per_session: -5\n    per_service: 10\n    window: 1m\n"), "-5"},
		{"escape hatch port 0",
			valid("escape_hatches:\n  - id: hatch-1\n    protocol: ssh\n    port: 0\n    scope:\n      session: S1\n"), "port"},
		{"escape hatch port 65536",
			valid("escape_hatches:\n  - id: hatch-2\n    protocol: ssh\n    port: 65536\n    scope:\n      session: S1\n"), "65536"},
		{"cred-swap entry with empty hosts",
			valid("cred_swap:\n  - id: swap-1\n    service: github\n    hosts: []\n    credential_location: Authorization\n"), "hosts"},
		{"duplicate rule IDs",
			valid("allow:\n  - id: dup-1\n    domain: a.example\n  - id: dup-1\n    domain: b.example\n"), "dup-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.yaml))
			if err != nil {
				// Parse-stage rejection: no partial Policy alongside the error.
				if p != nil {
					t.Errorf("Parse returned a partial Policy alongside error %v", err)
				}
			} else {
				if p == nil {
					t.Fatalf("Parse returned nil policy and nil error")
				}
				err = p.Validate()
			}
			if err == nil {
				t.Fatalf("invalid policy was accepted; want a rejection naming %q", tc.wantToken)
			}
			if errors.Is(err, ErrNotImplemented) {
				t.Fatalf("schema validation is not implemented: %v", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantToken)) {
				t.Errorf("rejection error %q does not name the offending field/value %q", err, tc.wantToken)
			}
		})
	}
}

func TestSchemaV0_ContractPackageVersioning(t *testing.T) {
	// planRef: doc 09 §6 POL-1 Done-when: schema merged into the shared
	// contract package and versioned per doc 06 §2. An unversioned or
	// future-versioned document is refused, never guessed at.
	t.Run("absent schema_version rejected", func(t *testing.T) {
		p, err := Parse([]byte("name: noversion\npack_version: 0.0.1\nposture: locked\n"))
		if err == nil {
			t.Fatalf("document without schema_version was accepted: %+v", p)
		}
		if errors.Is(err, ErrNotImplemented) {
			t.Fatalf("version gating is not implemented: %v", err)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "version") {
			t.Errorf("rejection %q is not a version error", err)
		}
		if p != nil {
			t.Errorf("partial Policy returned alongside the version error")
		}
	})
	t.Run("future schema_version v1 rejected", func(t *testing.T) {
		p, err := Parse([]byte("schema_version: v1\nname: future\npack_version: 0.0.1\nposture: locked\n"))
		if err == nil {
			t.Fatalf("schema_version v1 (not yet defined) was accepted: %+v", p)
		}
		if errors.Is(err, ErrNotImplemented) {
			t.Fatalf("version gating is not implemented: %v", err)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "version") {
			t.Errorf("rejection %q is not a version error", err)
		}
		if p != nil {
			t.Errorf("partial Policy returned alongside the version error")
		}
	})
	t.Run("v0 golden fixture pinned", func(t *testing.T) {
		// Golden fixture: a silent schema reshape breaks this contract test.
		// Every security-load-bearing section is pinned field-by-field with
		// DISTINCT values so a parser that mismaps fields (scope.session ->
		// Org, per_session <-> per_service, dropped credential_location, ...)
		// cannot round-trip its way past the suite and silently widen a
		// deployed YAML policy (e.g. a session-scoped hatch becoming
		// org-wide).
		golden := `schema_version: v0
name: golden
pack_version: 0.1.0
posture: standard
allow:
  - id: alw-1
    domain: example.org
  - id: alw-2
    domain: api.example.org
    service: example
block:
  - id: blk-1
    domain: dns.google
rate_limits:
  - id: rl-1
    service: example
    per_session: 7
    per_service: 70
    window: 90s
escape_hatches:
  - id: hatch-1
    protocol: ssh
    port: 22
    scope:
      session: sess-A
      host: host-B
      org: org-C
  - id: hatch-2
    protocol: rsync
    port: 873
    scope:
      org: org-only
pass_through:
  - pinned.example.org
cred_swap:
  - id: swap-1
    service: example
    hosts: [api.example.org, example.org]
    credential_location: Authorization
ask_defaults:
  unlisted_domain: ask
  grant_ttl: 5m
`
		p, err := Parse([]byte(golden))
		if err != nil {
			t.Fatalf("Parse(golden v0): %v", err)
		}
		want := &Policy{
			SchemaVersion: SchemaV0,
			Name:          "golden",
			PackVersion:   "0.1.0",
			Posture:       PostureStandard,
			Allow: []AllowRule{
				{ID: "alw-1", Domain: "example.org"},
				{ID: "alw-2", Domain: "api.example.org", Service: "example"},
			},
			Block: []BlockRule{{ID: "blk-1", Domain: "dns.google"}},
			RateLimits: []RateLimitRule{
				// PerSession != PerService so a swapped mapping is caught.
				{ID: "rl-1", Service: "example", PerSession: 7, PerService: 70, Window: 90 * time.Second},
			},
			EscapeHatches: []EscapeHatchRule{
				// All three scope fields populated with distinct values so a
				// session->org (or any other) scope mismap is caught.
				{ID: "hatch-1", Protocol: "ssh", Port: 22, Scope: GrantScope{Session: "sess-A", Host: "host-B", Org: "org-C"}},
				{ID: "hatch-2", Protocol: "rsync", Port: 873, Scope: GrantScope{Org: "org-only"}},
			},
			PassThrough: []string{"pinned.example.org"},
			CredSwap: []SwapServiceRule{
				{ID: "swap-1", Service: "example", Hosts: []string{"api.example.org", "example.org"}, CredentialLocation: "Authorization"},
			},
			AskDefaults: AskDefaults{UnlistedDomain: ActionAsk, GrantTTL: 5 * time.Minute},
		}
		if !reflect.DeepEqual(p, want) {
			t.Errorf("golden v0 fixture parse drifted:\n got = %+v\nwant = %+v", p, want)
		}
	})
}

func TestCompose_SystemOrgSession_DenyOverrides(t *testing.T) {
	// planRef: doc 09 §6 POL-1 Done-when: layered system→org→session
	// composition with deny-overrides precedence covered by tests.
	// ADVERSARIAL: a Block at any layer beats an Allow at any layer — all
	// nine (blocking layer, allowing layer) cells must deny.
	const domain = "contested.example"
	layers := []Layer{LayerSystem, LayerOrg, LayerSession}
	eval := NewEvaluator()
	for _, blockLayer := range layers {
		for _, allowLayer := range layers {
			t.Run(string(blockLayer)+"-blocks_"+string(allowLayer)+"-allows", func(t *testing.T) {
				pols := map[Layer]*Policy{}
				for _, l := range layers {
					pols[l] = &Policy{
						SchemaVersion: SchemaV0,
						Name:          "deny-overrides-" + string(l),
						PackVersion:   "0.0.1",
						Posture:       PostureOpen, // open posture so only the block can deny
					}
				}
				pols[blockLayer].Block = append(pols[blockLayer].Block, BlockRule{ID: "blk-d", Domain: domain})
				pols[allowLayer].Allow = append(pols[allowLayer].Allow, AllowRule{ID: "alw-d", Domain: domain})
				snap := mustCompose(t,
					LayeredPolicy{Layer: LayerSystem, Policy: pols[LayerSystem]},
					LayeredPolicy{Layer: LayerOrg, Policy: pols[LayerOrg]},
					LayeredPolicy{Layer: LayerSession, Policy: pols[LayerSession]},
				)
				dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, domain), testT0)
				if dec.Action != ActionDeny {
					t.Fatalf("Action = %q, want %q (deny-overrides)", dec.Action, ActionDeny)
				}
				if dec.Provenance.RuleID != "blk-d" {
					t.Errorf("Provenance.RuleID = %q, want %q (the block rule)", dec.Provenance.RuleID, "blk-d")
				}
				if dec.Provenance.Layer != blockLayer {
					t.Errorf("Provenance.Layer = %q, want %q (the blocking layer)", dec.Provenance.Layer, blockLayer)
				}
			})
		}
	}
}

func TestCompose_SameLayerAllowAndBlock_BlockWins(t *testing.T) {
	// planRef: doc 09 §6 POL-1 (blocklists always win). ADVERSARIAL: within a
	// single layer, block beats allow regardless of document rule order.
	const domain = "contested.example"
	eval := NewEvaluator()

	allowFirst := `schema_version: v0
name: same-layer
pack_version: 0.0.1
posture: open
allow:
  - id: alw-d
    domain: contested.example
block:
  - id: blk-d
    domain: contested.example
`
	blockFirst := `schema_version: v0
name: same-layer
pack_version: 0.0.1
posture: open
block:
  - id: blk-d
    domain: contested.example
allow:
  - id: alw-d
    domain: contested.example
`
	for _, tc := range []struct {
		name string
		doc  string
	}{
		{"allow rule before block rule", allowFirst},
		{"allow rule after block rule", blockFirst},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.doc))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: p})
			dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, domain), testT0)
			if dec.Action != ActionDeny {
				t.Fatalf("Action = %q, want %q — rule order in the document must not matter", dec.Action, ActionDeny)
			}
			if dec.Provenance.RuleID != "blk-d" {
				t.Errorf("Provenance.RuleID = %q, want %q", dec.Provenance.RuleID, "blk-d")
			}
		})
	}

	t.Run("wildcard allow beaten by specific block", func(t *testing.T) {
		p := &Policy{
			SchemaVersion: SchemaV0,
			Name:          "wildcard-vs-block",
			PackVersion:   "0.0.1",
			Posture:       PostureLocked,
			Allow:         []AllowRule{{ID: "alw-wild", Domain: "*.example.com"}},
			Block:         []BlockRule{{ID: "blk-bad", Domain: "bad.example.com"}},
		}
		snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: p})
		dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, "bad.example.com"), testT0)
		if dec.Action != ActionDeny {
			t.Fatalf("Action = %q, want %q (block beats wildcard allow)", dec.Action, ActionDeny)
		}
		if dec.Provenance.RuleID != "blk-bad" {
			t.Errorf("Provenance.RuleID = %q, want %q", dec.Provenance.RuleID, "blk-bad")
		}
	})
}

func TestEvaluate_PostureSemantics(t *testing.T) {
	// planRef: doc 09 §6 POL-1 posture (locked/standard/open): posture sets
	// the default verdict for unlisted domains; blocklist still beats posture.
	eval := NewEvaluator()
	mkPolicy := func(posture Posture, unlisted Action, blocks ...BlockRule) *Policy {
		return &Policy{
			SchemaVersion: SchemaV0,
			Name:          "posture-" + string(posture),
			PackVersion:   "0.0.1",
			Posture:       posture,
			Block:         blocks,
			AskDefaults:   AskDefaults{UnlistedDomain: unlisted, GrantTTL: 5 * time.Minute},
		}
	}
	cases := []struct {
		name       string
		policy     *Policy
		domain     string
		wantAction Action
		wantRuleID string // empty = only assert non-empty
	}{
		{"unlisted under locked denies", mkPolicy(PostureLocked, ActionDeny), "unlisted.example", ActionDeny, ""},
		{"unlisted under standard asks", mkPolicy(PostureStandard, ActionAsk), "unlisted.example", ActionAsk, ""},
		{"unlisted under open allows", mkPolicy(PostureOpen, ActionAllow), "unlisted.example", ActionAllow, ""},
		{"blocked domain under open still denies",
			mkPolicy(PostureOpen, ActionAllow, BlockRule{ID: "blk-evil", Domain: "evil.example"}),
			"evil.example", ActionDeny, "blk-evil"},
		// Posture vs AskDefaults disagreement, pinned both ways so an
		// implementation cannot key on only one of the two fields:
		// (1) locked is locked — an AskDefaults.UnlistedDomain of allow can
		// never widen a locked posture to allow-by-default;
		{"locked posture cannot be widened by ask-defaults allow",
			mkPolicy(PostureLocked, ActionAllow), "unlisted.example", ActionDeny, ""},
		// (2) AskDefaults.UnlistedDomain is the verdict under standard
		// posture, so a deny default must actually deny (not ask).
		{"standard posture honors ask-defaults deny",
			mkPolicy(PostureStandard, ActionDeny), "unlisted.example", ActionDeny, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := mustCompose(t, LayeredPolicy{Layer: LayerSystem, Policy: tc.policy})
			dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, tc.domain), testT0)
			if dec.Action != tc.wantAction {
				t.Fatalf("Action = %q, want %q", dec.Action, tc.wantAction)
			}
			// Every decision — including the posture default — carries provenance.
			assertFullProvenance(t, dec, snap)
			if tc.wantRuleID != "" && dec.Provenance.RuleID != tc.wantRuleID {
				t.Errorf("Provenance.RuleID = %q, want %q", dec.Provenance.RuleID, tc.wantRuleID)
			}
		})
	}

	t.Run("layered posture: session open cannot widen system locked", func(t *testing.T) {
		// POL-1.f guardrail clause: posture is itself subject to layering.
		// ADVERSARIAL: a malicious session-layer policy declaring posture
		// open (with an allow ask-default) must not widen the system-layer
		// locked default for unlisted domains — the conservative posture
		// wins, pinned here the way the OQ7 unscoped-hatch cell is pinned.
		system := mkPolicy(PostureLocked, ActionDeny)
		session := mkPolicy(PostureOpen, ActionAllow)
		snap := mustCompose(t,
			LayeredPolicy{Layer: LayerSystem, Policy: system},
			LayeredPolicy{Layer: LayerSession, Policy: session},
		)
		dec := mustEvaluate(t, eval, snap, dnsReq(sessS1, "unlisted.example"), testT0)
		if dec.Action != ActionDeny {
			t.Fatalf("Action = %q, want %q — a session-layer posture=open widened a system-locked default", dec.Action, ActionDeny)
		}
		assertFullProvenance(t, dec, snap)
	})
}
