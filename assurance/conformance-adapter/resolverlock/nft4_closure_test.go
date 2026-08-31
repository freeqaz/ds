// SPDX-License-Identifier: Apache-2.0

package resolverlock

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ── Offline half: the shipped NFT-4 artifact satisfies the doc 06 (c) rows ─────

// TestShippedNFT4ClosureShape is the live tripwire over the SHIPPED NFT-4
// resolver-bypass-closure artifact (read only): it must carry all three controls
// (port-53 capture observability, DoT 853 drop, udp/443 QUIC reject-not-drop +
// counter) in the doc 06 (c) shape — port-53/DoT/QUIC bypass assertions, in their
// non-live (offline) form. A read failure or any closure-shape weakening fails
// LOUDLY here, the same way the Rust ds-nft quic_reject/redirect lints fail on
// their synthetic fixtures. This is the offline truth the live half (env-gated)
// asserts on the wire.
func TestShippedNFT4ClosureShape(t *testing.T) {
	if err := AssertNFT4ClosureShape(); err != nil {
		t.Fatalf("shipped NFT-4 artifact (%s) fails a doc 06 (c) resolver-bypass-closure "+
			"row: %v", NFT4ArtifactPath(), err)
	}
}

// A minimal, well-formed synthetic NFT-4 closure ruleset — the BASELINE the drift
// cases perturb. Built from synthetic strings in-test (negative cases are proven
// against synthetic strings, NEVER by mutating the shipped artifact, which stays
// read-only). It mirrors the shipped shape so each perturbation isolates one
// control.
const goodNFT4 = `table inet ds_resolver_closure {
  chain resolver_bypass_observe {
    type nat hook prerouting priority -101; policy accept;
    iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
    iifname "dstap-*" tcp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
  }
  chain resolver_closure_forward {
    type filter hook forward priority 1; policy accept;
    iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop
    iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop
    iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable
  }
}
`

// TestParseGoodNFT4 pins that a well-formed synthetic closure ruleset passes
// (no false positive from the shape checks).
func TestParseGoodNFT4(t *testing.T) {
	if err := assertNFT4ClosureShape(goodNFT4); err != nil {
		t.Fatalf("well-formed synthetic NFT-4 ruleset must pass cleanly, got: %v", err)
	}
}

// TestNFT4ClosureDrift is the table-driven drift gate: each row perturbs the
// good ruleset into ONE closure-shape failure, asserting the driver fails with
// the SPECIFIC named sentinel (errors.Is) rather than passing vacuously. These
// are the doc 06 (c) bypass rows in negative form.
func TestNFT4ClosureDrift(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr error
	}{
		{
			// QUIC silently dropped — the precise regression D70 amended away
			// ("dropped" → "rejected (icmp port-unreachable) + counted").
			name: "QUIC silent drop",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
				`iifname "dstap-*" udp dport 443 counter drop`, 1),
			wantErr: ErrQUICNotRejected,
		},
		{
			// QUIC reject rule drops the unforgeable iifname anchor — a future
			// ruleset edit could un-anchor JUST this rule (doc 03 §3, doc 06 (c)
			// in-VM-spoofing, D44/D69). With no iifname the rule is no longer scoped
			// to the session's dstap-* attachment point.
			name: "QUIC rule not iifname-anchored",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
				`udp dport 443 counter reject with icmpx type port-unreachable`, 1),
			wantErr: ErrQUICNotInterfaceAnchored,
		},
		{
			// QUIC reject rule matches the forgeable `ip saddr` instead of the
			// unforgeable iifname — the in-VM agent can spoof its source, so the
			// rule must key on the interface only (doc 03 §3, doc 06 (c)).
			name: "QUIC rule matches ip saddr",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
				`ip saddr 10.0.0.0/8 udp dport 443 counter reject with icmpx type port-unreachable`, 1),
			wantErr: ErrQUICNotInterfaceAnchored,
		},
		{
			// QUIC reject rule anchors on a NON-dstap iifname ("eth0") — the iifname
			// KEYWORD is present (so the old presence-only check would pass) but the
			// VALUE is not the session-scoped dstap-* pattern (the D50/D66
			// interface-naming contract), so the rule is NOT scoped to the session
			// tap. The strengthened anchoring check requires the dstap-* glob VALUE.
			name: "QUIC rule anchored on non-dstap iifname (eth0)",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
				`iifname "eth0" udp dport 443 counter reject with icmpx type port-unreachable`, 1),
			wantErr: ErrQUICNotInterfaceAnchored,
		},
		{
			// QUIC rejected but not as icmp(x) port-unreachable (a bare reject).
			name: "QUIC bare reject (no port-unreachable)",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
				`iifname "dstap-*" udp dport 443 counter reject`, 1),
			wantErr: ErrQUICNotPortUnreachable,
		},
		{
			// QUIC reject with no counter — not countable per session.
			name: "QUIC reject missing counter",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
				`iifname "dstap-*" udp dport 443 reject with icmpx type port-unreachable`, 1),
			wantErr: ErrQUICMissingCounter,
		},
		{
			// No udp/443 rule at all — the sole non-cooperative-client control is
			// missing.
			name: "QUIC rule absent",
			yaml: strings.Replace(goodNFT4,
				`    iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable
`, "", 1),
			wantErr: ErrNoUDP443Rule,
		},
		{
			// DoT (853) not dropped — a stray accept verdict.
			name: "DoT udp not dropped",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`iifname "dstap-*" udp dport 853 counter accept`, 1),
			wantErr: ErrNoDoTDrop,
		},
		{
			// DoT tcp transport missing — only one transport closed.
			name: "DoT tcp transport missing",
			yaml: strings.Replace(goodNFT4,
				`    iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop
`, "", 1),
			wantErr: ErrNoDoTDrop,
		},
		{
			// DoT 853 udp drop rule drops the unforgeable iifname anchor — a future
			// ruleset edit could un-anchor JUST a 853 rule (doc 03 §3, doc 06 (c)
			// in-VM-spoofing, D44/D69). With no iifname the drop is no longer scoped to
			// the session's dstap-* attachment point.
			name: "DoT udp rule not iifname-anchored",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
			wantErr: ErrDoTNotInterfaceAnchored,
		},
		{
			// DoT 853 udp drop rule matches the forgeable `ip saddr` instead of the
			// unforgeable iifname — the in-VM agent can spoof its source, so the rule
			// must key on the interface only (doc 03 §3, doc 06 (c)).
			name: "DoT udp rule matches ip saddr",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`ip saddr 10.0.0.0/8 udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
			wantErr: ErrDoTNotInterfaceAnchored,
		},
		{
			// DoT 853 tcp drop rule drops the iifname anchor — the tcp transport leg
			// of the per-control DoT anchoring (mirrors the udp leg above).
			name: "DoT tcp rule not iifname-anchored",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
			wantErr: ErrDoTNotInterfaceAnchored,
		},
		{
			// DoT 853 udp drop rule anchors on a NON-dstap iifname ("eth0") — the
			// iifname KEYWORD is present but the VALUE is not the session-scoped
			// dstap-* pattern (D50/D66), so the drop is NOT scoped to the session
			// tap. The strengthened anchoring check requires the dstap-* glob VALUE.
			name: "DoT udp rule anchored on non-dstap iifname (eth0)",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`iifname "eth0" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
			wantErr: ErrDoTNotInterfaceAnchored,
		},
		{
			// DoT 853 tcp drop rule anchored on a non-dstap iifname ("eth0") — the
			// tcp transport leg of the per-control dstap-* VALUE check (mirrors the
			// udp leg above).
			name: "DoT tcp rule anchored on non-dstap iifname (eth0)",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`iifname "eth0" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
			wantErr: ErrDoTNotInterfaceAnchored,
		},
		{
			// Port-53 capture observability absent — no counter+log iifname rule.
			name: "port-53 capture absent",
			yaml: strings.NewReplacer(
				`    iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
`, "",
				`    iifname "dstap-*" tcp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
`, "",
			).Replace(goodNFT4),
			wantErr: ErrNoPort53Capture,
		},
		{
			// Port-53 rule matches forgeable source IP — the in-VM-spoofing
			// invariant (doc 06 (c)). Must match iifname only.
			name: "port-53 matches ip saddr",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4`,
				`ip saddr 10.0.0.0/8 udp dport 53 counter log prefix "x " group 4`, 1),
			wantErr: ErrPort53SourceIPMatch,
		},
		{
			// Port-53 capture rule anchors on a NON-dstap iifname ("eth0") — the
			// iifname KEYWORD is present but the VALUE is not the session-scoped
			// dstap-* pattern (D50/D66), so the observe rule is NOT scoped to the
			// session tap. The strengthened port-53 anchoring check (the
			// ErrPort53SourceIPMatch path) requires the dstap-* glob VALUE, so this
			// fires the same per-control anchoring sentinel a forgeable saddr does.
			name: "port-53 anchored on non-dstap iifname (eth0)",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4`,
				`iifname "eth0" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4`, 1),
			wantErr: ErrPort53SourceIPMatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := assertNFT4ClosureShape(tc.yaml)
			if err == nil {
				t.Fatalf("drift case %q must fail loudly, got nil (vacuous pass)", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("drift case %q: want error %v, got %v", tc.name, tc.wantErr, err)
			}
			if strings.TrimSpace(err.Error()) == "" {
				t.Errorf("drift case %q: error message must be non-empty", tc.name)
			}
		})
	}
}

// TestNFT4SourceIPNeverMatchedInShippedArtifact pins the doc 06 (c)
// in-VM-spoofing invariant directly over the shipped artifact: no rule consults
// `ip saddr` / `ip6 saddr` — every session-scoped rule matches the unforgeable
// `iifname` attachment point (doc 03 §3).
func TestNFT4SourceIPNeverMatchedInShippedArtifact(t *testing.T) {
	data := readShippedNFT4(t)
	for i, raw := range strings.Split(data, "\n") {
		lc := strings.ToLower(stripNftComment(raw))
		if matchesSourceIP(lc) {
			t.Errorf("NFT-4 artifact line %d matches a forgeable source IP (`ip saddr`): %q "+
				"— match the unforgeable iifname only (doc 03 §3, doc 06 (c))", i+1, strings.TrimSpace(raw))
		}
	}
}

// TestNFT4QUICRuleIsInterfaceAnchored pins the per-control in-VM-spoofing
// invariant for the udp/443 QUIC reject rule directly (doc 03 §3, doc 06 (c),
// D44/D69), the way TestNFT4SourceIPNeverMatchedInShippedArtifact pins it for the
// whole artifact: the QUIC rule MUST read the unforgeable `iifname` (the dstap-*
// attachment point) and MUST NOT match the forgeable `ip saddr`.
//
// FIRES on synthetic fixtures whose QUIC rule is un-anchored (iifname dropped, or
// an ip-saddr match added), and stays SILENT on the shipped anchored rule — proven
// here against synthetic strings (the shipped artifact stays read-only; the
// SILENT half is asserted by TestShippedNFT4ClosureShape, which would surface
// ErrQUICNotInterfaceAnchored if the shipped QUIC rule ever lost its anchor).
func TestNFT4QUICRuleIsInterfaceAnchored(t *testing.T) {
	// SILENT on the shipped-shape anchored baseline.
	if err := assertNFT4ClosureShape(goodNFT4); err != nil {
		t.Fatalf("the anchored synthetic QUIC rule must pass cleanly (no false "+
			"ErrQUICNotInterfaceAnchored), got: %v", err)
	}

	fires := []struct {
		name string
		yaml string
	}{
		{
			name: "iifname dropped",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
				`udp dport 443 counter reject with icmpx type port-unreachable`, 1),
		},
		{
			name: "ip saddr matched",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
				`ip saddr 10.0.0.0/8 udp dport 443 counter reject with icmpx type port-unreachable`, 1),
		},
		{
			// iifname KEYWORD present but anchored on a NON-dstap interface ("eth0")
			// — not the session-scoped dstap-* pattern (D50/D66). The strengthened
			// check asserts the iifname VALUE, not merely the keyword, so this fires
			// even though hasWord(lc, "iifname") is satisfied.
			name: "non-dstap iifname (eth0)",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
				`iifname "eth0" udp dport 443 counter reject with icmpx type port-unreachable`, 1),
		},
	}
	for _, tc := range fires {
		t.Run(tc.name, func(t *testing.T) {
			err := assertNFT4ClosureShape(tc.yaml)
			if !errors.Is(err, ErrQUICNotInterfaceAnchored) {
				t.Fatalf("an un-anchored QUIC rule (%s) must fire "+
					"ErrQUICNotInterfaceAnchored, got: %v", tc.name, err)
			}
		})
	}
}

// TestNFT4DoTRuleIsInterfaceAnchored pins the per-control in-VM-spoofing invariant
// for the port-853 (DNS-over-TLS) drop rules directly (doc 03 §3, doc 06 (c),
// D44/D69), the way TestNFT4QUICRuleIsInterfaceAnchored pins it for the udp/443
// QUIC reject: each DoT drop rule MUST read the unforgeable `iifname` (the dstap-*
// attachment point) and MUST NOT match the forgeable `ip saddr`. This is the DoT
// leg of the per-control anchoring trilogy (port-53, QUIC, DoT).
//
// FIRES on synthetic fixtures whose DoT rule is un-anchored (iifname dropped, or an
// ip-saddr match added) on either transport, and stays SILENT on the shipped
// anchored rules — proven here against synthetic strings (the shipped artifact
// stays read-only; the SILENT half is asserted by TestShippedNFT4ClosureShape,
// which would surface ErrDoTNotInterfaceAnchored if a shipped DoT rule ever lost
// its anchor).
func TestNFT4DoTRuleIsInterfaceAnchored(t *testing.T) {
	// SILENT on the shipped-shape anchored baseline.
	if err := assertNFT4ClosureShape(goodNFT4); err != nil {
		t.Fatalf("the anchored synthetic DoT rules must pass cleanly (no false "+
			"ErrDoTNotInterfaceAnchored), got: %v", err)
	}

	fires := []struct {
		name string
		yaml string
	}{
		{
			name: "udp iifname dropped",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
		},
		{
			name: "udp ip saddr matched",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`ip saddr 10.0.0.0/8 udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
		},
		{
			name: "tcp iifname dropped",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
		},
		{
			name: "tcp ip saddr matched",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`ip saddr 10.0.0.0/8 tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
		},
		{
			// udp 853 drop with the iifname KEYWORD present but anchored on a
			// NON-dstap interface ("eth0") — not the session-scoped dstap-* pattern
			// (D50/D66). The strengthened check asserts the iifname VALUE.
			name: "udp non-dstap iifname (eth0)",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`iifname "eth0" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
		},
		{
			// tcp 853 drop anchored on a non-dstap interface ("eth0") — the tcp leg
			// of the dstap-* VALUE check (mirrors the udp leg above).
			name: "tcp non-dstap iifname (eth0)",
			yaml: strings.Replace(goodNFT4,
				`iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
				`iifname "eth0" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`, 1),
		},
	}
	for _, tc := range fires {
		t.Run(tc.name, func(t *testing.T) {
			err := assertNFT4ClosureShape(tc.yaml)
			if !errors.Is(err, ErrDoTNotInterfaceAnchored) {
				t.Fatalf("an un-anchored DoT rule (%s) must fire "+
					"ErrDoTNotInterfaceAnchored, got: %v", tc.name, err)
			}
		})
	}
}

// TestAnchorsOnDstapGlob unit-tests the anchorsOnDstapGlob operand-level helper
// directly (the dstap-* VALUE check the three per-control anchoring sentinels now
// require, the D50/D66 interface-naming contract). It must ACCEPT every way the
// session-scoped dstap-prefixed interface can be written and REJECT a missing or
// non-dstap (e.g. "eth0") operand — the exact gap the keyword-only presence check
// left open. Input is the lowercased, comment-stripped line the analyzer feeds it.
func TestAnchorsOnDstapGlob(t *testing.T) {
	accepts := []struct {
		name, line string
	}{
		{"quoted glob (shipped form)", `iifname "dstap-*" udp dport 443 counter reject`},
		{"quoted concrete session iface", `iifname "dstap-abc123" tcp dport 853 counter drop`},
		{"unquoted glob", `iifname dstap-* udp dport 53 counter log`},
		{"anonymous set member", `iifname { "dstap-a", "dstap-b" } udp dport 443 counter reject`},
		{"anonymous set, three all-dstap members", `iifname { "dstap-a", "dstap-b", "dstap-c" } udp dport 53 counter log`},
		{"anonymous set, glued brace forms", `iifname {"dstap-a","dstap-b"} udp dport 443 counter reject`},
	}
	for _, tc := range accepts {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if !anchorsOnDstapGlob(tc.line) {
				t.Fatalf("anchorsOnDstapGlob(%q) = false, want true — a dstap-prefixed "+
					"iifname operand is the session-scoped attachment point (D50/D66)", tc.line)
			}
		})
	}

	rejects := []struct {
		name, line string
	}{
		{"non-dstap iifname (eth0)", `iifname "eth0" udp dport 443 counter reject`},
		{"non-dstap iifname (lo)", `iifname "lo" tcp dport 853 counter drop`},
		{"no iifname at all", `udp dport 443 counter reject with icmpx type port-unreachable`},
		{"dstap as a substring elsewhere, not the iifname operand", `iifname "eth0" log prefix "dstap-x "`},
		// ANON-SET TOTALITY (adversarial-pass fix): a MIXED anonymous set whose
		// FIRST member is dstap- but which also admits a non-dstap interface must
		// NOT pass — every member must be dstap-prefixed or the set is not scoped
		// to the session tap. Before the fix anchorsOnDstapGlob returned true on
		// the first dstap- member and wrongly accepted these.
		{"mixed anon set, dstap- first then eth0", `iifname { "dstap-a", "eth0" } udp dport 443 counter reject`},
		{"mixed anon set, dstap- first then lo", `iifname { "dstap-a", "lo" } tcp dport 853 counter drop`},
		{"mixed anon set, dstap- last (non-dstap first)", `iifname { "eth0", "dstap-b" } udp dport 53 counter log`},
		{"mixed anon set, three members one non-dstap", `iifname { "dstap-a", "dstap-b", "wg0" } udp dport 443 counter reject`},
	}
	for _, tc := range rejects {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if anchorsOnDstapGlob(tc.line) {
				t.Fatalf("anchorsOnDstapGlob(%q) = true, want false — only a dstap-* "+
					"iifname OPERAND is the session attachment point; a non-dstap interface "+
					"(or dstap appearing elsewhere on the line) must NOT satisfy it", tc.line)
			}
		})
	}
}

// TestIifnameOperands pins the operand-extraction helper that backs the tightened
// anchorsOnDstapGlob totality check: it must recover the COMPLETE ordered set of
// interface operands an iifname match keys on — the single operand for the scalar
// forms, and EVERY member for the anonymous-set form (the case the first-match scan
// got wrong). A set form that returned only the first member would silently re-open
// the mixed-set hole, so the multi-member extraction is asserted directly here.
func TestIifnameOperands(t *testing.T) {
	cases := []struct {
		name string
		line string
		want []string
	}{
		{"quoted scalar", `iifname "dstap-*" udp dport 443 counter reject`, []string{"dstap-*"}},
		{"unquoted scalar", `iifname dstap-0 udp dport 53 counter log`, []string{"dstap-0"}},
		{"two-member set", `iifname { "dstap-a", "dstap-b" } udp dport 443 counter reject`, []string{"dstap-a", "dstap-b"}},
		{"mixed two-member set keeps BOTH", `iifname { "dstap-a", "eth0" } udp dport 443 counter reject`, []string{"dstap-a", "eth0"}},
		{"three-member set", `iifname { "dstap-a", "eth0", "lo" } tcp dport 853 drop`, []string{"dstap-a", "eth0", "lo"}},
		{"glued braces", `iifname {"dstap-a","dstap-b"} udp dport 443 counter reject`, []string{"dstap-a", "dstap-b"}},
		{"no iifname", `udp dport 443 counter reject`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := iifnameOperands(tc.line)
			if len(got) != len(tc.want) {
				t.Fatalf("iifnameOperands(%q) = %v (len %d), want %v (len %d) — the anon-set "+
					"form MUST yield every member so the all-dstap totality check can bite a "+
					"mixed set", tc.line, got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("iifnameOperands(%q)[%d] = %q, want %q", tc.line, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestNFT4PerControlDstapGlobTightening is the consolidated dstap-* VALUE contract
// for ALL THREE per-control anchoring sentinels (port-53 via ErrPort53SourceIPMatch,
// QUIC via ErrQUICNotInterfaceAnchored, DoT via ErrDoTNotInterfaceAnchored): each
// stays SILENT on the shipped `iifname "dstap-*"` baseline (no false positive from
// the strengthened VALUE check) and FIRES on a synthetic fixture whose control rule
// anchors on a NON-dstap iifname ("eth0") — the iifname KEYWORD present, but the
// VALUE not the session-scoped dstap-* pattern (D50/D66). This pins the gap the
// task closes: before this, a rule could anchor on `iifname "eth0"` and pass every
// sentinel; now the per-control check requires the dstap-* glob VALUE, not merely
// the keyword.
func TestNFT4PerControlDstapGlobTightening(t *testing.T) {
	// SILENT on the shipped-shape dstap-* baseline across all three controls.
	if err := assertNFT4ClosureShape(goodNFT4); err != nil {
		t.Fatalf("the shipped-shape dstap-* baseline must pass cleanly under the "+
			"strengthened per-control dstap-glob VALUE check (no false positive), got: %v", err)
	}

	cases := []struct {
		name    string
		from    string // the shipped dstap-* control rule
		to      string // the same rule re-anchored on a non-dstap iifname
		wantErr error
	}{
		{
			name:    "port-53 capture",
			from:    `iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4`,
			to:      `iifname "eth0" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4`,
			wantErr: ErrPort53SourceIPMatch,
		},
		{
			name:    "DoT 853 udp drop",
			from:    `iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			to:      `iifname "eth0" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			wantErr: ErrDoTNotInterfaceAnchored,
		},
		{
			name:    "QUIC udp/443 reject",
			from:    `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
			to:      `iifname "eth0" udp dport 443 counter reject with icmpx type port-unreachable`,
			wantErr: ErrQUICNotInterfaceAnchored,
		},
		// ANON-SET TOTALITY (adversarial-pass fix): a MIXED anonymous set whose first
		// member is dstap- but which also admits "eth0" must FIRE the per-control
		// anchoring sentinel — before the fix the first-dstap-member scan passed it,
		// laundering a non-session interface through a per-control control rule.
		{
			name:    "QUIC udp/443 reject on a MIXED anon set (dstap- + eth0)",
			from:    `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
			to:      `iifname { "dstap-a", "eth0" } udp dport 443 counter reject with icmpx type port-unreachable`,
			wantErr: ErrQUICNotInterfaceAnchored,
		},
		{
			name:    "DoT 853 udp drop on a MIXED anon set (dstap- + eth0)",
			from:    `iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			to:      `iifname { "dstap-a", "eth0" } udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			wantErr: ErrDoTNotInterfaceAnchored,
		},
		{
			name:    "port-53 capture on a MIXED anon set (dstap- + eth0)",
			from:    `iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4`,
			to:      `iifname { "dstap-a", "eth0" } udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4`,
			wantErr: ErrPort53SourceIPMatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drifted := strings.Replace(goodNFT4, tc.from, tc.to, 1)
			if drifted == goodNFT4 {
				t.Fatalf("perturbation for %q did not change the baseline — the `from` "+
					"rule string is stale (no dstap-* rule was re-anchored)", tc.name)
			}
			err := assertNFT4ClosureShape(drifted)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("a %s control anchored on a NON-dstap iifname (\"eth0\") must fire "+
					"%v, got: %v", tc.name, tc.wantErr, err)
			}
		})
	}
}

// scanUnanchoredIifnameRules runs the by-construction scan over an nft ruleset
// body: it strips each line's comment, and for every line carrying an `iifname`
// operand (a session-scoped rule) records the (1-based line number, raw line)
// of any whose operand is NOT the session-scoped dstap-* glob — reusing the
// package-private anchorsOnDstapGlob helper (the same operand-level check the
// three per-control sentinels require). It also returns how many iifname-bearing
// lines it saw so callers can refuse a vacuous (zero-rule) pass. Pure string
// scan; reused verbatim by both the shipped-artifact tripwire and its synthetic
// bite-proof so the two exercise identical logic.
func scanUnanchoredIifnameRules(body string) (offenders []string, iifnameRules int) {
	for i, raw := range strings.Split(body, "\n") {
		lc := strings.ToLower(stripNftComment(raw))
		if !hasWord(lc, "iifname") {
			continue
		}
		iifnameRules++
		if !anchorsOnDstapGlob(lc) {
			offenders = append(offenders,
				strings.TrimSpace(stripNftComment(raw))+" (line "+itoa(i+1)+")")
		}
	}
	return offenders, iifnameRules
}

// iifnameOperandIsLoopback reports whether a line's `iifname` operand is EXACTLY
// the loopback interface "lo". It mirrors anchorsOnDstapGlob's operand extraction
// (next field after the `iifname` token, with the surrounding nft punctuation —
// quotes, set braces, a leading comma — trimmed so the test keys on the interface
// NAME, not its syntactic wrapping), but tests for an exact "lo" match instead of
// the dstap- prefix. Input is the lowercased, comment-stripped line.
//
// This backs the DOCUMENTED loopback exemption (see scanUnanchoredIifnameRules
// ExemptLoopback): the shipped host-bootstrap floor carries ONE legitimate
// non-dstap iifname rule — `iifname "lo" accept` in nft-1-bootstrap.nft — the
// loopback-accept infrastructure rule (host self-traffic, NOT session traffic on
// a per-session tap), so it is NOT required to anchor on the session-scoped
// dstap-* attachment point (doc 03 §3, D66). It is the ONLY such operand across
// all shipped artifacts; every OTHER iifname rule must still anchor on dstap-*.
func iifnameOperandIsLoopback(lc string) bool {
	fields := strings.Fields(lc)
	for i, f := range fields {
		if f != "iifname" || i+1 >= len(fields) {
			continue
		}
		operand := strings.Trim(fields[i+1], `"{},`)
		if operand == "" && i+2 < len(fields) {
			operand = strings.Trim(fields[i+2], `"{},`)
		}
		if operand == "lo" {
			return true
		}
	}
	return false
}

// scanUnanchoredIifnameRulesExemptLoopback is the loopback-exempt generalization of
// scanUnanchoredIifnameRules, used by the NFT-1/NFT-2 tripwires (which scan the
// host-bootstrap floor, where the lone `iifname "lo" accept` infrastructure rule
// legitimately does not — and must not — anchor on a session tap). It runs the same
// by-construction scan — strip each line's comment, and for every `iifname`-bearing
// (session-scoped) rule record the offending (raw line + 1-based line number) of any
// whose operand is NOT the session-scoped dstap-* glob — but FIRST skips a rule whose
// iifname operand is exactly the loopback "lo" (iifnameOperandIsLoopback), the single
// documented exemption (the host loopback-accept rule, doc 09 §3, doc 03 §3, D66).
// A skipped lo rule is counted in neither offenders NOR iifnameRules, so a vacuous
// (zero session-scoped iifname rule) pass is still refused by callers.
//
// The exemption is NARROW — exactly "lo" and nothing else — so it cannot launder a
// non-dstap rule (e.g. `iifname "eth0"`), which still surfaces as an offender. It is a
// strict superset of scanUnanchoredIifnameRules on lo-free input (NFT-4, goodNFT4):
// with no lo rule to skip the two scans return identical results, so NFT-4's existing
// scan stays UNCHANGED and unweakened — proven by TestLoopbackExemptionIsNoOpForNFT4.
func scanUnanchoredIifnameRulesExemptLoopback(body string) (offenders []string, iifnameRules int) {
	for i, raw := range strings.Split(body, "\n") {
		lc := strings.ToLower(stripNftComment(raw))
		if !hasWord(lc, "iifname") {
			continue
		}
		// DOCUMENTED loopback exemption: the host loopback-accept rule
		// (`iifname "lo" accept`) is host self-traffic, not session traffic on a
		// per-session dstap tap, so it is neither required to anchor on dstap-* nor
		// counted as a session-scoped rule. This is the ONLY non-dstap iifname
		// operand across all shipped artifacts (doc 09 §3, doc 03 §3, D66).
		if iifnameOperandIsLoopback(lc) {
			continue
		}
		iifnameRules++
		if !anchorsOnDstapGlob(lc) {
			offenders = append(offenders,
				strings.TrimSpace(stripNftComment(raw))+" (line "+itoa(i+1)+")")
		}
	}
	return offenders, iifnameRules
}

// nft1ArtifactRelPath / nft2ArtifactRelPath are the paths from THIS source file to
// the other shipped session-scoped nft artifacts, mirroring nft4ArtifactRelPath so
// the by-construction tripwire generalizes to the whole shipped fleet. Read-only:
// these are scanned via os.ReadFile, never edited (dataplane/** is read-only here).
// Each routes THROUGH the tracked in-module symlink testdata/srclinks/… (not
// ../../../dataplane/… directly) so a warm test cache re-hashes the shipped artifact
// on change instead of serving a stale PASS — see srclinks.go.
const (
	nft1ArtifactRelPath = "testdata/srclinks/" + srcLinkNFT1Bootstrap
	nft2ArtifactRelPath = "testdata/srclinks/" + srcLinkNFT2bSpike
	// nft3ArtifactRelPath is the shipped NFT-3b OUTPUT-chain containment artifact
	// (D76). Unlike NFT-1/2/4 it is an EGRESS (output-chain) artifact keyed on
	// `oifname` + the per-session `ct mark` and the `@allow4_<session>` allow-set —
	// the per-session allow-set the task names. It carries NO `iifname` (ingress)
	// rules by design, so the ingress dstap-anchoring tripwire must TOLERATE a
	// zero-iifname result for it (vs. the no-vacuous-pass fatal the ingress
	// artifacts NFT-1/2/4 take) — see assertArtifactHasNoUnanchoredIifname.
	nft3ArtifactRelPath = "testdata/srclinks/" + srcLinkNFT3bOutput
)

// readShippedArtifact reads a shipped nft artifact (read-only) given its path
// relative to THIS source file, anchored off runtime.Caller the same way
// NFT4ArtifactPath anchors the NFT-4 path — so the scan works under `go test` from
// any cwd. Used by the NFT-1/NFT-2 by-construction tripwires; NFT-4 keeps its own
// NFT4ArtifactPath()/readShippedNFT4 path (unchanged).
func readShippedArtifact(t *testing.T, relPath string) (path, body string) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed — cannot anchor the artifact path for %s", relPath)
	}
	path = filepath.Clean(filepath.Join(filepath.Dir(thisFile), relPath))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading shipped nft artifact %s: %v", path, err)
	}
	return path, string(data)
}

// assertShippedArtifactAnchorsOnDstap is the shared driver behind the NFT-1 and
// NFT-2 by-construction tripwires: it scans a shipped artifact (read-only) with the
// loopback-exempt scanner and fails LOUDLY if any non-exempt iifname rule does not
// anchor on the session-scoped dstap-* interface, or if ZERO session-scoped iifname
// rules are found (no vacuous pass — these artifacts are built from session-scoped
// rules). label/relPath name the artifact in failure messages.
func assertShippedArtifactAnchorsOnDstap(t *testing.T, label, relPath string) {
	t.Helper()
	path, body := readShippedArtifact(t, relPath)
	offenders, iifnameRules := scanUnanchoredIifnameRulesExemptLoopback(body)
	if iifnameRules == 0 {
		t.Fatalf("by-construction scan found ZERO session-scoped iifname-bearing rules in the "+
			"shipped %s artifact (%s) — the session-scoped rules vanished or the scan drifted "+
			"(the `iifname \"lo\"` loopback rule is exempt and uncounted); refusing a vacuous pass",
			label, path)
	}
	if len(offenders) > 0 {
		t.Fatalf("shipped %s artifact (%s): %d of %d session-scoped iifname-bearing rule(s) do "+
			"NOT anchor on the session-scoped dstap-* interface (D50/D66, doc 03 §3, doc 06 (c)) "+
			"— a non-dstap or un-anchored iifname rule is NOT scoped to the session tap (the only "+
			"exempt non-dstap operand is the host `iifname \"lo\"` loopback-accept rule):\n  %s",
			label, path, len(offenders), iifnameRules, strings.Join(offenders, "\n  "))
	}
}

// assertArtifactHasNoUnanchoredIifname is the EGRESS-artifact generalization of the
// dstap-anchoring tripwire: like assertShippedArtifactAnchorsOnDstap it scans a shipped
// artifact (read-only, loopback-exempt) and fails LOUDLY on any non-exempt iifname rule
// that does not anchor on the session-scoped dstap-* interface — but it TOLERATES a
// zero-iifname-rule result instead of treating it as a vacuous-pass fatal. That is the
// right shape for an OUTPUT-chain artifact (NFT-3b) whose containment keys on `oifname` +
// the per-session `ct mark` and `@allow4_<session>` allow-set, NOT on ingress `iifname`:
// it legitimately carries zero iifname rules today. The bite still has teeth — if a future
// edit ever ADDS an ingress iifname rule to such an artifact, it MUST anchor on dstap-* or
// this fires, naming the offender. label/relPath name the artifact in failure messages.
//
// NFT-5 NOTE (pending): doc 09 §3's NFT-5 ct-mark artifact has NOT landed under
// dataplane/artifacts/nft/ yet (only nft-1/2b/3b/4 ship). When it lands, wire it here the
// same way (a new const + a TestNFT5… that routes through this driver if it is ct-mark/
// egress-shaped, or through assertShippedArtifactAnchorsOnDstap if it carries ingress
// iifname rules); tracked as the dataplane-mirror follow-up.
func assertArtifactHasNoUnanchoredIifname(t *testing.T, label, relPath string) {
	t.Helper()
	path, body := readShippedArtifact(t, relPath)
	offenders, _ := scanUnanchoredIifnameRulesExemptLoopback(body)
	if len(offenders) > 0 {
		t.Fatalf("shipped %s artifact (%s): %d session-scoped iifname-bearing rule(s) do NOT "+
			"anchor on the session-scoped dstap-* interface (D50/D66, doc 03 §3, doc 06 (c)) — "+
			"an egress/output-chain artifact keys on oifname + ct mark + the per-session "+
			"allow-set, so any ingress iifname rule that DOES appear must still anchor on the "+
			"session tap:\n  %s", label, path, len(offenders), strings.Join(offenders, "\n  "))
	}
}

// TestNFT3ShippedRulesAnchorOnDstapByConstruction generalizes the by-construction
// dstap-anchoring tripwire to the SHIPPED NFT-3b OUTPUT-chain containment artifact (D76,
// read only) — the per-session allow-set artifact the task names. NFT-3b is an EGRESS
// artifact: its containment keys on `oifname` + the per-session `ct mark` and the
// `@allow4_<session>` allow-set, so it carries NO ingress `iifname` rules by design and
// the zero-iifname result is TOLERATED (vs. the no-vacuous-pass fatal the ingress NFT-1/2/4
// tripwires take). The control-agnostic bite still holds: a FUTURE or ADDITIONAL ingress
// iifname rule anchored on a non-dstap interface (e.g. `iifname "eth0"`) would be caught
// here, named, and fail LOUDLY. The shipped artifact stays read-only.
func TestNFT3ShippedRulesAnchorOnDstapByConstruction(t *testing.T) {
	assertArtifactHasNoUnanchoredIifname(t, "NFT-3b OUTPUT-chain containment", nft3ArtifactRelPath)
}

// itoa is a tiny stdlib-free int formatter for the offender line tags (keeps the
// import set to the existing errors/os/strings/testing — no strconv).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// TestNFT4ShippedRulesAnchorOnDstapByConstruction is the by-construction tripwire
// over the SHIPPED NFT-4 artifact (read only): EVERY line carrying an `iifname`
// operand — i.e. every session-scoped rule — MUST anchor on the dstap-* glob (the
// D50/D66 interface-naming contract, doc 03 §3, doc 06 (c)). TestShippedNFT4Closure
// Shape proves the analyzer PASSES the artifact, and the three per-control
// sentinels (port-53, QUIC, DoT) check the KNOWN controls; this is the direct,
// control-agnostic mirror: a FUTURE or ADDITIONAL iifname rule that anchored on a
// non-dstap interface (e.g. `iifname "eth0"`) — a control no per-control sentinel
// knows about — would slip past them but is caught here, named, and fails LOUDLY.
//
// A zero-iifname-rules result is Fatal (no vacuous pass): the shipped closure is
// built from session-scoped rules, so an empty scan means the artifact (or this
// scan) drifted out from under the contract. The shipped artifact stays read-only
// (scanned via readShippedNFT4 → NFT4ArtifactPath()/os.ReadFile); the bite is
// proven separately against a synthetic non-dstap fixture in
// TestNFT4ByConstructionTripwireBites.
func TestNFT4ShippedRulesAnchorOnDstapByConstruction(t *testing.T) {
	data := readShippedNFT4(t)
	offenders, iifnameRules := scanUnanchoredIifnameRules(data)
	if iifnameRules == 0 {
		t.Fatalf("by-construction scan found ZERO iifname-bearing rules in the shipped "+
			"NFT-4 artifact (%s) — the session-scoped closure rules vanished or the scan "+
			"drifted; refusing a vacuous pass", NFT4ArtifactPath())
	}
	if len(offenders) > 0 {
		t.Fatalf("shipped NFT-4 artifact (%s): %d of %d iifname-bearing rule(s) do NOT "+
			"anchor on the session-scoped dstap-* interface (D50/D66, doc 03 §3, doc 06 (c)) "+
			"— a non-dstap or un-anchored iifname rule is NOT scoped to the session tap and "+
			"would let a future/additional rule key on a forgeable interface:\n  %s",
			NFT4ArtifactPath(), len(offenders), iifnameRules, strings.Join(offenders, "\n  "))
	}
}

// TestNFT4ByConstructionTripwireBites proves the tripwire actually BITES: it runs
// the SAME scan logic (scanUnanchoredIifnameRules) the shipped tripwire uses over a
// SYNTHETIC fixture that injects one non-dstap iifname rule (`iifname "eth0"`)
// alongside the legitimate dstap-* rules, and asserts the scan flags exactly that
// rule by NAME — the read-only mirror of the negative-fixture proofs the
// per-control sentinels use. The shipped artifact is NEVER mutated; this fixture is
// an in-test synthetic string (D50), so no planted rule can leak into the artifact.
func TestNFT4ByConstructionTripwireBites(t *testing.T) {
	// SILENT on the well-formed all-dstap baseline (no false positive: every
	// iifname rule in goodNFT4 anchors on dstap-*).
	clean, cleanRules := scanUnanchoredIifnameRules(goodNFT4)
	if cleanRules == 0 {
		t.Fatalf("baseline goodNFT4 must contain iifname rules for the scan to be " +
			"meaningful, got zero")
	}
	if len(clean) != 0 {
		t.Fatalf("the all-dstap baseline must produce NO offenders (no false positive), "+
			"got: %v", clean)
	}

	// Inject ONE non-dstap iifname rule (eth0) next to the legitimate dstap-* rules.
	planted := strings.Replace(goodNFT4,
		`    iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
		`    iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable
    iifname "eth0" udp dport 4433 counter drop`, 1)
	if planted == goodNFT4 {
		t.Fatal("synthetic mutation did not change the baseline — the anchor rule string is stale")
	}

	offenders, rules := scanUnanchoredIifnameRules(planted)
	if rules <= cleanRules {
		t.Fatalf("planted fixture must add an iifname rule (was %d, now %d)", cleanRules, rules)
	}
	if len(offenders) != 1 {
		t.Fatalf("the by-construction scan must flag exactly the ONE planted non-dstap "+
			"iifname rule, got %d offender(s): %v", len(offenders), offenders)
	}
	if !strings.Contains(offenders[0], `iifname "eth0"`) {
		t.Fatalf("the flagged offender must NAME the non-dstap rule (`iifname \"eth0\"`), "+
			"got: %q", offenders[0])
	}
	// The legitimate dstap-* rules are NOT flagged — only the planted eth0 rule is.
	if strings.Contains(offenders[0], "dstap-") {
		t.Fatalf("a legitimate dstap-* rule was wrongly flagged: %q", offenders[0])
	}
}

func readShippedNFT4(t *testing.T) string {
	t.Helper()
	if err := AssertNFT4ClosureShape(); err != nil {
		t.Fatalf("shipped NFT-4 artifact precondition failed: %v", err)
	}
	// Re-read for the raw scan through the SAME single Caller(0)-anchored reader the
	// NFT-1/NFT-2 tripwires use (readShippedArtifact), so there is ONE artifact-read
	// path across all four artifacts rather than NFT-4 keeping a near-duplicate
	// NFT4ArtifactPath()/os.ReadFile reader of its own. The relPath is the production
	// nft4ArtifactRelPath constant (nft4_closure.go), so the path NFT4ArtifactPath()
	// resolves and the path readShippedArtifact resolves are the SAME location —
	// pinned by TestReadShippedNFT4MatchesArtifactPath below.
	_, body := readShippedArtifact(t, nft4ArtifactRelPath)
	return body
}

// TestReadShippedNFT4MatchesArtifactPath pins the Caller(0)-reader consolidation: the
// single shared reader (readShippedArtifact, used by NFT-1/NFT-2/NFT-4) resolves NFT-4
// to the SAME absolute path as the production NFT4ArtifactPath() helper, and reads the
// SAME bytes. readShippedNFT4 now routes through readShippedArtifact rather than its own
// near-duplicate NFT4ArtifactPath()/os.ReadFile reader; this guards that the two anchors
// stay co-resolved (both runtime.Caller(0) off THIS package directory) so the
// consolidation cannot silently drift the NFT-4 read off the artifact NFT4ArtifactPath()
// governs. A read failure or a path divergence fails LOUDLY here.
func TestReadShippedNFT4MatchesArtifactPath(t *testing.T) {
	sharedPath, sharedBody := readShippedArtifact(t, nft4ArtifactRelPath)
	if sharedPath != NFT4ArtifactPath() {
		t.Fatalf("the shared reader resolved NFT-4 to %q but NFT4ArtifactPath() resolves "+
			"%q — the consolidated readShippedArtifact path and the production NFT-4 path "+
			"must be the SAME location, or readShippedNFT4 would read a different artifact "+
			"than the per-control sentinels govern", sharedPath, NFT4ArtifactPath())
	}
	direct, err := os.ReadFile(NFT4ArtifactPath())
	if err != nil {
		t.Fatalf("reading the shipped NFT-4 artifact via NFT4ArtifactPath(): %v", err)
	}
	if string(direct) != sharedBody {
		t.Fatalf("the shared reader read different bytes for NFT-4 than NFT4ArtifactPath() " +
			"— the single-reader consolidation must read the identical artifact")
	}
}

// TestNFT1ShippedRulesAnchorOnDstapByConstruction generalizes the by-construction
// dstap-anchoring tripwire to the SHIPPED NFT-1 host-bootstrap artifact (read only):
// EVERY session-scoped (iifname-bearing) rule MUST anchor on the dstap-* glob (the
// D50/D66 interface-naming contract, doc 03 §3, doc 06 (c)), EXCEPT the one documented
// loopback exemption — the host `iifname "lo" accept` infrastructure rule (host
// self-traffic, not session traffic on a per-session tap, doc 09 §3). This is the
// control-agnostic mirror for NFT-1: a FUTURE or ADDITIONAL iifname rule anchored on a
// non-dstap, non-lo interface (e.g. `iifname "eth0"`) — which the NFT-1 redirect-shape
// sentinels need not know about — slips past them but is caught here, named, and fails
// LOUDLY. A zero-(session-scoped)-iifname-rules result is Fatal (no vacuous pass: NFT-1
// carries the udp/tcp 53 dstap-* redirect + the dstap-* forward no-op). The shipped
// artifact stays read-only; the bite is proven separately against a synthetic non-dstap
// non-lo fixture in TestNFT1ByConstructionTripwireBites.
func TestNFT1ShippedRulesAnchorOnDstapByConstruction(t *testing.T) {
	assertShippedArtifactAnchorsOnDstap(t, "NFT-1 host-bootstrap", nft1ArtifactRelPath)
}

// TestNFT2ShippedRulesAnchorOnDstapByConstruction generalizes the by-construction
// dstap-anchoring tripwire to the SHIPPED NFT-2b transparent-redirect artifact (read
// only): EVERY session-scoped (iifname-bearing) rule MUST anchor on the dstap-* glob
// (D50/D66, doc 03 §3, doc 06 (c)). NFT-2b carries the tcp 80/443 → ds-tlsproxy
// redirects on `iifname "dstap-0"` (a concrete session tap, which the dstap- prefix
// test accepts) and NO loopback rule, so the lo-exemption is a no-op here. The
// control-agnostic mirror for NFT-2: a future/additional rule anchored on a non-dstap
// interface fails LOUDLY here. A zero-iifname-rules result is Fatal (no vacuous pass).
// The shipped artifact stays read-only.
func TestNFT2ShippedRulesAnchorOnDstapByConstruction(t *testing.T) {
	assertShippedArtifactAnchorsOnDstap(t, "NFT-2b transparent-redirect", nft2ArtifactRelPath)
}

// TestLoopbackExemptionIsNoOpForNFT4 pins that the loopback exemption does NOT weaken
// the existing NFT-4 scan: the shipped NFT-4 artifact carries no `iifname "lo"` rule,
// so scanUnanchoredIifnameRulesExemptLoopback and the original scanUnanchoredIifname
// Rules return IDENTICAL results over it (same offenders, same iifname-rule count). The
// generalized scanner is a strict superset on lo-free input, so NFT-4's by-construction
// tripwire (TestNFT4ShippedRulesAnchorOnDstapByConstruction) stays GREEN and unweakened.
func TestLoopbackExemptionIsNoOpForNFT4(t *testing.T) {
	data := readShippedNFT4(t)

	base, baseRules := scanUnanchoredIifnameRules(data)
	exempt, exemptRules := scanUnanchoredIifnameRulesExemptLoopback(data)

	if baseRules != exemptRules {
		t.Fatalf("loopback exemption changed the NFT-4 iifname-rule count (%d → %d) — NFT-4 "+
			"has no `iifname \"lo\"` rule, so the exemption must be a no-op for it", baseRules, exemptRules)
	}
	if len(base) != len(exempt) {
		t.Fatalf("loopback exemption changed the NFT-4 offender count (%d → %d) — the exemption "+
			"must not alter NFT-4's result", len(base), len(exempt))
	}
	for i := range base {
		if base[i] != exempt[i] {
			t.Fatalf("loopback exemption changed NFT-4 offender %d: %q → %q", i, base[i], exempt[i])
		}
	}
	// Sanity: NFT-4 itself stays clean (every iifname rule anchors on dstap-*).
	if len(exempt) != 0 {
		t.Fatalf("the shipped NFT-4 artifact must have no dstap-anchoring offenders, got: %v", exempt)
	}
}

// TestIifnameOperandIsLoopback unit-tests the loopback-operand helper backing the
// documented exemption: it must ACCEPT only an `iifname` operand that is exactly the
// loopback "lo" (in the nft punctuation forms it can be written) and REJECT a dstap-*
// operand, a different non-dstap interface (e.g. "eth0"), a missing iifname, and the
// case where "lo" appears elsewhere on the line but is NOT the iifname operand — so
// the exemption is narrow and cannot launder a non-loopback rule.
func TestIifnameOperandIsLoopback(t *testing.T) {
	accepts := []struct{ name, line string }{
		{"quoted lo (shipped form)", `iifname "lo" accept`},
		{"unquoted lo", `iifname lo accept`},
		{"lo in an anonymous set", `iifname { "lo" } accept`},
	}
	for _, tc := range accepts {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if !iifnameOperandIsLoopback(strings.ToLower(tc.line)) {
				t.Fatalf("iifnameOperandIsLoopback(%q) = false, want true — the host "+
					"loopback-accept rule is the single documented exemption", tc.line)
			}
		})
	}

	rejects := []struct{ name, line string }{
		{"dstap-* glob", `iifname "dstap-*" udp dport 53 redirect to :15353`},
		{"non-dstap non-lo (eth0)", `iifname "eth0" udp dport 4433 counter drop`},
		{"no iifname at all", `ct state established,related accept`},
		{"lo appears elsewhere, not the iifname operand", `iifname "dstap-*" log prefix "lo "`},
		{"loopback prefix but not exactly lo (lo0)", `iifname "lo0" accept`},
	}
	for _, tc := range rejects {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			if iifnameOperandIsLoopback(strings.ToLower(tc.line)) {
				t.Fatalf("iifnameOperandIsLoopback(%q) = true, want false — only an iifname "+
					"operand of exactly \"lo\" is the loopback exemption; a dstap-*, a different "+
					"interface, or \"lo\" appearing elsewhere must NOT satisfy it", tc.line)
			}
		})
	}
}

// TestNFT1ByConstructionTripwireBites proves the GENERALIZED (loopback-exempt) tripwire
// actually BITES: it runs the SAME scan logic (scanUnanchoredIifnameRulesExemptLoopback)
// the NFT-1/NFT-2 shipped tripwires use over a SYNTHETIC NFT-1-shaped body that injects
// ONE non-dstap, NON-lo iifname rule (`iifname "eth0" ... drop`) alongside the legitimate
// `iifname "lo" accept` and the dstap-* rules, and asserts the scan flags exactly that
// eth0 rule by NAME — while the legitimate lo rule is EXEMPT (uncounted, never flagged)
// and the dstap-* rules pass. The shipped artifacts are NEVER mutated; this fixture is an
// in-test synthetic string (D50), so no planted rule can leak into an artifact.
func TestNFT1ByConstructionTripwireBites(t *testing.T) {
	// A synthetic NFT-1-shaped body: the host loopback-accept rule (the exemption),
	// the dstap-* forward no-op, and the dstap-* udp/tcp 53 redirects — every iifname
	// rule legitimate, so the scan must be SILENT (lo exempt, the rest anchor dstap-*).
	const goodNFT1 = `table inet ds_boundary {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    iifname "lo" accept
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    iifname "dstap-*" ct state new drop
  }
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "dstap-*" udp dport 53 redirect to :15353
    iifname "dstap-*" tcp dport 53 redirect to :15353
  }
}
`
	clean, cleanRules := scanUnanchoredIifnameRulesExemptLoopback(goodNFT1)
	if cleanRules == 0 {
		t.Fatal("baseline goodNFT1 must contain session-scoped iifname rules (the lo rule is " +
			"exempt and uncounted) for the scan to be meaningful, got zero")
	}
	if len(clean) != 0 {
		t.Fatalf("the well-formed NFT-1 baseline must produce NO offenders (lo exempt, the rest "+
			"anchor on dstap-*), got: %v", clean)
	}

	// Inject ONE non-dstap, NON-lo iifname rule (eth0) next to the legitimate rules.
	planted := strings.Replace(goodNFT1,
		`    iifname "dstap-*" ct state new drop`,
		`    iifname "dstap-*" ct state new drop
    iifname "eth0" ct state new drop`, 1)
	if planted == goodNFT1 {
		t.Fatal("synthetic mutation did not change the baseline — the anchor rule string is stale")
	}

	offenders, rules := scanUnanchoredIifnameRulesExemptLoopback(planted)
	if rules <= cleanRules {
		t.Fatalf("planted fixture must add a session-scoped iifname rule (was %d, now %d)", cleanRules, rules)
	}
	if len(offenders) != 1 {
		t.Fatalf("the loopback-exempt by-construction scan must flag exactly the ONE planted "+
			"non-dstap non-lo iifname rule, got %d offender(s): %v", len(offenders), offenders)
	}
	if !strings.Contains(offenders[0], `iifname "eth0"`) {
		t.Fatalf("the flagged offender must NAME the non-dstap non-lo rule (`iifname \"eth0\"`), "+
			"got: %q", offenders[0])
	}
	// The legitimate dstap-* rules are NOT flagged...
	if strings.Contains(offenders[0], "dstap-") {
		t.Fatalf("a legitimate dstap-* rule was wrongly flagged: %q", offenders[0])
	}
	// ...and the exempt `iifname "lo"` rule is NEVER flagged (it is the documented exemption).
	if strings.Contains(offenders[0], `"lo"`) {
		t.Fatalf("the exempt loopback rule (`iifname \"lo\"`) must NEVER be flagged, got: %q", offenders[0])
	}
}

// ── SECURITY-AUDIT soundness holes (ds-security-core-audit wf_349402e8) ────────
//
// Each of the four cases below is a genuinely-broken nft artifact that PASSED the
// sentinel before its fix — a by-construction false green (no shipped artifact
// trips them today; all are latent holes the audit found). Each row REDDENS now,
// failing with the specific named sentinel. These are RED-first proofs: the crafted
// rule passed assertNFT4ClosureShape before the fix and fails it after.

// TestNFT4VerdictAwareAcceptGuard (R2) — the udp/443 QUIC and port-853 DoT controls
// keyed on verdict-TOKEN presence (reject present / drop absent for QUIC; drop
// present for DoT) and never on the terminal VERDICT, so a rule carrying an explicit
// PERMIT verdict (`accept`) alongside the expected tokens PASSED — the permit wins at
// runtime, the expected verdict is dead. There was NO anti-permit guard anywhere in
// the file. Each row mixes an `accept` into a control rule and asserts it now fails
// the relevant sentinel.
func TestNFT4VerdictAwareAcceptGuard(t *testing.T) {
	cases := []struct {
		name    string
		from    string
		to      string
		wantErr error
	}{
		{
			// THE R2 HEADLINE: `... counter accept reject with icmpx type
			// port-unreachable`. reject is present, drop is absent, port-unreachable
			// is named, counter is present — every old check passed; the stray
			// `accept` permits udp/443. Now the anti-permit guard reddens it.
			name:    "QUIC accept+reject mix (accept wins, reject dead)",
			from:    `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
			to:      `iifname "dstap-*" udp dport 443 counter accept reject with icmpx type port-unreachable`,
			wantErr: ErrQUICNotRejected,
		},
		{
			// A bare `accept` on udp/443 (no reject at all) — would have failed the
			// reject-absence check before, but the anti-permit guard now fires FIRST
			// and on the precise reason (a permit verdict), which is the actionable
			// message. Asserting the QUIC sentinel still fires keeps the verdict the
			// stable contract.
			name:    "QUIC bare accept (no reject)",
			from:    `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
			to:      `iifname "dstap-*" udp dport 443 counter accept`,
			wantErr: ErrQUICNotRejected,
		},
		{
			// THE R2 DoT MIRROR: `... counter accept drop`. drop is present (old
			// !hasWord(drop) check passed) but the contradictory `accept` permits
			// DNS-over-TLS. Now the DoT anti-permit guard reddens it.
			name:    "DoT udp accept+drop mix (accept wins, drop dead)",
			from:    `iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			to:      `iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 accept drop`,
			wantErr: ErrNoDoTDrop,
		},
		{
			// DoT tcp transport, accept+drop — the tcp leg of the DoT anti-permit
			// guard (mirrors the udp leg above).
			name:    "DoT tcp accept+drop mix",
			from:    `iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			to:      `iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 accept drop`,
			wantErr: ErrNoDoTDrop,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drifted := strings.Replace(goodNFT4, tc.from, tc.to, 1)
			if drifted == goodNFT4 {
				t.Fatalf("perturbation for %q did not change the baseline — the `from` "+
					"rule string is stale", tc.name)
			}
			err := assertNFT4ClosureShape(drifted)
			if err == nil {
				t.Fatalf("R2 case %q must fail loudly (a permit verdict on a control "+
					"that must reject/drop), got nil — the verdict-aware anti-permit "+
					"guard regressed (this was the false green the audit found)", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("R2 case %q: want %v, got %v", tc.name, tc.wantErr, err)
			}
		})
	}
}

// TestNFT4CommentStringStripped (R1) — stripNftComment dropped only the trailing
// `#`-comment, so the nft `comment "<...>"` KEYWORD string survived into the
// lowercased token bag and supplied hidden icmp / port-unreachable / verdict tokens.
// A bare `reject comment "use icmp port-unreachable"` thereby satisfied
// namesPortUnreachable and passed. Each row hides tokens in a comment string and
// asserts the rule now fails (the comment text no longer leaks tokens).
func TestNFT4CommentStringStripped(t *testing.T) {
	cases := []struct {
		name    string
		from    string
		to      string
		wantErr error
	}{
		{
			// THE R1 HEADLINE: a BARE reject (no real `with icmp type
			// port-unreachable` verdict) whose comment text spells "icmp" and
			// "port-unreachable". Before the strip, namesPortUnreachable matched the
			// comment tokens and the rule passed; now the comment is excised first so
			// the bare reject is caught.
			name:    "comment supplies icmp port-unreachable tokens to a bare reject",
			from:    `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
			to:      `iifname "dstap-*" udp dport 443 counter reject comment "use icmp port-unreachable"`,
			wantErr: ErrQUICNotPortUnreachable,
		},
		{
			// A comment that smuggles a `drop` token onto an otherwise-valid QUIC
			// reject would, unstripped, trip the reject-not-drop contradiction
			// (hasWord(drop)) and fire ErrQUICNotRejected — a confusing false RED on a
			// VALID rule. After the strip the comment `drop` is gone and the valid
			// rule is unaffected. This proves the strip does not just harden, it also
			// removes a comment-induced false positive: the row asserts the rule with
			// a `drop`-bearing comment now PASSES (no error).
			name:    "comment with a stray drop token does not falsely redden a valid reject",
			from:    `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
			to:      `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable comment "never drop this"`,
			wantErr: nil, // valid rule must still PASS after the comment is stripped
		},
		{
			// A comment smuggling `accept` onto a DoT drop rule. Before the strip the
			// comment `accept` would (post-R2) trip the new anti-permit guard — a
			// false RED on a valid drop rule; after the strip the comment is gone and
			// the valid drop rule passes. Asserts the valid rule still PASSES.
			name:    "comment with a stray accept token does not falsely redden a valid DoT drop",
			from:    `iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			to:      `iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop comment "do not accept dot"`,
			wantErr: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drifted := strings.Replace(goodNFT4, tc.from, tc.to, 1)
			if drifted == goodNFT4 {
				t.Fatalf("perturbation for %q did not change the baseline — the `from` "+
					"rule string is stale", tc.name)
			}
			err := assertNFT4ClosureShape(drifted)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("R1 case %q: a valid rule with a comment string must PASS "+
						"after the comment is stripped, got: %v", tc.name, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("R1 case %q must fail loudly (a comment string fed hidden "+
					"tokens into the bag), got nil — the comment-keyword strip "+
					"regressed (this was the false green the audit found)", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("R1 case %q: want %v, got %v", tc.name, tc.wantErr, err)
			}
		})
	}
}

// TestNFT4SemicolonSplit (R3) — analysis was strictly newline-split, so several
// `;`-joined statements on ONE physical line collapsed into a single token bag and a
// permissive SECOND statement went invisible. A drop-then-accept `;`-joined pair
// satisfied the DoT drop check while the stray accept hid. Each row joins a
// permissive second statement and asserts the line now reddens.
func TestNFT4SemicolonSplit(t *testing.T) {
	cases := []struct {
		name    string
		from    string
		to      string
		wantErr error
	}{
		{
			// THE R3 HEADLINE: `... counter ... drop; iifname "dstap-*" udp dport 853
			// counter accept`. Newline-split, the bag has BOTH drop and accept and
			// (pre-R2) passed; even post-R2 the accept would only be seen if the
			// statement is split out. Splitting on `;` surfaces the second statement,
			// which trips the DoT anti-permit guard.
			name:    "DoT drop;accept second statement on one line",
			from:    `iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			to:      `iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop; iifname "dstap-*" udp dport 853 counter accept`,
			wantErr: ErrNoDoTDrop,
		},
		{
			// A `;`-joined QUIC pair: a valid reject FIRST statement and a permissive
			// `udp dport 443 counter accept` SECOND. Split out, the second statement
			// is a udp/443 rule with an accept verdict and reddens the QUIC control.
			name:    "QUIC reject;accept second statement on one line",
			from:    `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
			to:      `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable; iifname "dstap-*" udp dport 443 counter accept`,
			wantErr: ErrQUICNotRejected,
		},
		{
			// A `;`-joined DoT pair where the second statement is a SILENT-drop-less
			// stray: `... drop; iifname "dstap-*" tcp dport 853 counter` with no
			// verdict at all (so neither drop nor accept) — split out it is a 853 rule
			// with no drop, tripping ErrNoDoTDrop. Guards that the split does not just
			// catch accept but any non-drop second 853 statement.
			name:    "DoT drop;no-verdict second statement",
			from:    `iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			to:      `iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop; iifname "dstap-*" tcp dport 853 counter`,
			wantErr: ErrNoDoTDrop,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drifted := strings.Replace(goodNFT4, tc.from, tc.to, 1)
			if drifted == goodNFT4 {
				t.Fatalf("perturbation for %q did not change the baseline — the `from` "+
					"rule string is stale", tc.name)
			}
			err := assertNFT4ClosureShape(drifted)
			if err == nil {
				t.Fatalf("R3 case %q must fail loudly (a permissive `;`-joined second "+
					"statement on one physical line), got nil — the semicolon split "+
					"regressed (this was the false green the audit found)", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("R3 case %q: want %v, got %v", tc.name, tc.wantErr, err)
			}
		})
	}
}

// TestNFT4SourceKeyGuardBroadened (R6) — matchesSourceIP matched only literal
// `ip saddr` / `ip6 saddr`, so a source match keyed on a different layer
// (`ether saddr <mac>`, or any non-ip `... saddr ...` form) EVADED the
// forgeable-source guard. Broadened to the `saddr` token, every source-keyed form is
// caught. Each row adds a non-ip source match to a control rule and asserts the
// per-control anchoring sentinel now fires.
func TestNFT4SourceKeyGuardBroadened(t *testing.T) {
	cases := []struct {
		name    string
		from    string
		to      string
		wantErr error
	}{
		{
			// THE R6 HEADLINE: `ether saddr <mac>` on the QUIC reject — a link-layer
			// source match the old `ip saddr`/`ip6 saddr` check did not see. Now the
			// broadened `saddr`-token guard reddens it via the per-control QUIC anchor
			// sentinel (matchesSourceIP is the first clause).
			name:    "QUIC ether saddr source match",
			from:    `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
			to:      `iifname "dstap-*" ether saddr 00:11:22:33:44:55 udp dport 443 counter reject with icmpx type port-unreachable`,
			wantErr: ErrQUICNotInterfaceAnchored,
		},
		{
			// `ether saddr` on a DoT drop rule — the DoT leg of the broadened guard.
			name:    "DoT ether saddr source match",
			from:    `iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			to:      `iifname "dstap-*" ether saddr 00:11:22:33:44:55 udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
			wantErr: ErrDoTNotInterfaceAnchored,
		},
		{
			// `ether saddr` on the port-53 capture rule — the port-53 leg. Fires the
			// ErrPort53SourceIPMatch sentinel (matchesSourceIP is its first clause).
			name:    "port-53 ether saddr source match",
			from:    `iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4`,
			to:      `iifname "dstap-*" ether saddr 00:11:22:33:44:55 udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4`,
			wantErr: ErrPort53SourceIPMatch,
		},
		{
			// An `ip6 saddr <set>` form (a named set, not the literal `ip6 saddr
			// <addr>` the old substring check anchored on) on the QUIC reject — proves
			// the token guard catches every saddr spelling, not just the two literals.
			name:    "QUIC ip6 saddr set source match",
			from:    `iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
			to:      `iifname "dstap-*" ip6 saddr @blocked6 udp dport 443 counter reject with icmpx type port-unreachable`,
			wantErr: ErrQUICNotInterfaceAnchored,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drifted := strings.Replace(goodNFT4, tc.from, tc.to, 1)
			if drifted == goodNFT4 {
				t.Fatalf("perturbation for %q did not change the baseline — the `from` "+
					"rule string is stale", tc.name)
			}
			err := assertNFT4ClosureShape(drifted)
			if err == nil {
				t.Fatalf("R6 case %q must fail loudly (a non-ip forgeable source match "+
					"`%s`), got nil — the broadened saddr-token guard regressed (this "+
					"was the false green the audit found)", tc.name, tc.to)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("R6 case %q: want %v, got %v", tc.name, tc.wantErr, err)
			}
		})
	}
}

// TestNFT4EtherSaddrTrippedByGlobalSourceScan pins R6 directly through the
// whole-artifact source-key scan path matchesSourceIP backs
// (TestNFT4SourceIPNeverMatchedInShippedArtifact uses it): an `ether saddr` line is
// now flagged where before only `ip saddr`/`ip6 saddr` were. The shipped artifact
// stays clean (no saddr of any form); this asserts the helper bites the broader
// family on synthetic input.
func TestNFT4EtherSaddrTrippedByGlobalSourceScan(t *testing.T) {
	if matchesSourceIP(`iifname "dstap-*" udp dport 443 counter reject`) {
		t.Fatal("a saddr-free rule must NOT be flagged by matchesSourceIP (false positive)")
	}
	forms := []string{
		`ether saddr 00:11:22:33:44:55 udp dport 443 counter drop`,
		`ip saddr 10.0.0.0/8 udp dport 53 counter log`,
		`ip6 saddr ::1 tcp dport 853 drop`,
		`ip6 saddr @blocked6 udp dport 443 counter reject`,
	}
	for _, f := range forms {
		if !matchesSourceIP(f) {
			t.Errorf("matchesSourceIP(%q) = false, want true — every nft source match "+
				"spells the `saddr` keyword and must be caught (R6)", f)
		}
	}
	// `daddr` (the DESTINATION twin) must NOT be mistaken for a source match.
	if matchesSourceIP(`ip daddr 1.2.3.4 udp dport 443 counter reject`) {
		t.Fatal("matchesSourceIP must NOT flag a `daddr` destination match — only `saddr`")
	}
}

// TestStripNftCommentKeyword unit-tests the R1 comment-keyword stripper directly:
// it must excise the nft `comment "<...>"` clause (so its text cannot leak tokens),
// leave non-comment code intact, never mistake a `comment` substring inside ANOTHER
// quoted string for the keyword, and handle multiple/edge-case clauses.
func TestStripNftCommentKeyword(t *testing.T) {
	cases := []struct {
		name, in string
		// want is checked by token presence/absence rather than exact bytes, since
		// the clause is replaced by a single space; we assert the comment text tokens
		// are gone and the rule code tokens survive.
		mustHave   []string
		mustntHave []string
	}{
		{
			name:       "comment text tokens excised, rule code kept",
			in:         `udp dport 443 counter reject comment "use icmp port-unreachable"`,
			mustHave:   []string{"reject", "counter", "443"},
			mustntHave: []string{"icmp", "port-unreachable", "comment"},
		},
		{
			name:       "comment naming a verdict cannot smuggle it",
			in:         `udp dport 853 counter drop comment "never accept this"`,
			mustHave:   []string{"drop", "853"},
			mustntHave: []string{"accept", "comment"},
		},
		{
			name:       "comment substring inside a log prefix string is NOT the keyword",
			in:         `udp dport 53 counter log prefix "comment here " group 4`,
			mustHave:   []string{"log", "prefix", "53"},
			mustntHave: nil, // the prefix string survives; nothing to strip
		},
		{
			name:       "two comment clauses both removed",
			in:         `reject comment "a icmp" counter comment "b accept"`,
			mustHave:   []string{"reject", "counter"},
			mustntHave: []string{"icmp", "accept", "comment"},
		},
		{
			name:       "comment is not matched inside a longer word",
			in:         `udp dport 443 commentary "icmp" counter`,
			mustHave:   []string{"commentary", "counter"},
			mustntHave: nil, // `commentary` is not the keyword, its quoted text survives
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.ToLower(stripNftCommentKeyword(tc.in))
			for _, w := range tc.mustHave {
				if !strings.Contains(got, w) {
					t.Errorf("stripNftCommentKeyword(%q) dropped expected rule token %q: %q", tc.in, w, got)
				}
			}
			for _, w := range tc.mustntHave {
				if strings.Contains(got, w) {
					t.Errorf("stripNftCommentKeyword(%q) leaked comment token %q: %q", tc.in, w, got)
				}
			}
		})
	}
}

// TestSplitStatements unit-tests the R3 statement splitter directly: it must split a
// physical line on `;`, respect quoted strings (a `;` inside a `log prefix "a;b "`
// is NOT a separator), and return trimmed non-empty statements in order.
func TestSplitStatements(t *testing.T) {
	cases := []struct {
		name, in string
		want     []string
	}{
		{"no semicolon", `iifname "dstap-*" udp dport 443 counter reject`, []string{`iifname "dstap-*" udp dport 443 counter reject`}},
		{"two statements", `a drop; b accept`, []string{"a drop", "b accept"}},
		{"three statements", `a; b; c`, []string{"a", "b", "c"}},
		{"semicolon inside a quoted prefix is not a separator", `counter log prefix "a;b " drop`, []string{`counter log prefix "a;b " drop`}},
		{"trailing semicolon yields no empty statement", `a drop;`, []string{"a drop"}},
		{"leading semicolon yields no empty statement", `;a drop`, []string{"a drop"}},
		{"empty between semicolons skipped", `a;; b`, []string{"a", "b"}},
		{"all whitespace yields none", `   `, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitStatements(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("splitStatements(%q) = %v (len %d), want %v (len %d)", tc.in, got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("splitStatements(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestNFT4LegitimateCommentAndPrefixStillPass guards the soundness fixes against
// false positives on the BENIGN forms they must tolerate: a control rule may carry a
// legitimate `comment "..."` (R1 must strip it without harming the rule) and a
// `log prefix "..."` whose text could contain a `;` (R3 must not split on it). The
// baseline-with-benign-decorations must still PASS cleanly.
func TestNFT4LegitimateCommentAndPrefixStillPass(t *testing.T) {
	decorated := strings.NewReplacer(
		`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable`,
		`iifname "dstap-*" udp dport 443 counter reject with icmpx type port-unreachable comment "D70 quic reject"`,
		`iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop`,
		`iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop;leg " group 4 drop comment "DoT closed"`,
	).Replace(goodNFT4)
	if decorated == goodNFT4 {
		t.Fatal("decoration did not change the baseline — the rule strings are stale")
	}
	if err := assertNFT4ClosureShape(decorated); err != nil {
		t.Fatalf("a baseline decorated with legitimate `comment \"...\"` clauses and a "+
			"`;`-bearing log-prefix string must still PASS (the R1 strip and R3 split "+
			"must not falsely redden benign forms), got: %v", err)
	}
}
