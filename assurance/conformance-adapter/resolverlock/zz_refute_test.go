// SPDX-License-Identifier: Apache-2.0
package resolverlock

import (
	"errors"
	"testing"
)

// Example 1: accept verdict with `reject ... port-unreachable` in an nft comment STATEMENT (no '#')
func TestRefuteExample1Comment(t *testing.T) {
	ruleset := `table inet ds_resolver_closure {
  chain resolver_bypass_observe {
    iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
    iifname "dstap-*" tcp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
  }
  chain resolver_closure_forward {
    iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop
    iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop
    iifname "dstap-*" udp dport 443 counter accept comment "reject icmp port-unreachable"
  }
}
`
	err := assertNFT4ClosureShape(ruleset)
	if err == nil {
		t.Logf("EXAMPLE 1 (comment): PASSES (nil) -- accept verdict with reject in comment is GREEN. DEFECT CONFIRMED for example 1.")
	} else if errors.Is(err, ErrQUICNotRejected) {
		t.Logf("EXAMPLE 1 (comment): caught by ErrQUICNotRejected -- not a defect for example 1")
	} else {
		t.Logf("EXAMPLE 1 (comment): error = %v", err)
	}
}

// Example 2: accept AND reject as two semicolon/space-joined statements on one line
func TestRefuteExample2SecondStatement(t *testing.T) {
	ruleset := `table inet ds_resolver_closure {
  chain resolver_bypass_observe {
    iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
    iifname "dstap-*" tcp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
  }
  chain resolver_closure_forward {
    iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop
    iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop
    iifname "dstap-*" udp dport 443 counter accept reject with icmpx type port-unreachable
  }
}
`
	err := assertNFT4ClosureShape(ruleset)
	if err == nil {
		t.Logf("EXAMPLE 2 (accept+reject): PASSES (nil) -- accept verdict with trailing reject is GREEN. DEFECT CONFIRMED for example 2.")
	} else if errors.Is(err, ErrQUICNotRejected) {
		t.Logf("EXAMPLE 2 (accept+reject): caught by ErrQUICNotRejected -- not a defect for example 2")
	} else {
		t.Logf("EXAMPLE 2 (accept+reject): error = %v", err)
	}
}

// Control: a pure accept (no reject token anywhere) -- should be caught
func TestRefutePureAccept(t *testing.T) {
	ruleset := `table inet ds_resolver_closure {
  chain resolver_bypass_observe {
    iifname "dstap-*" udp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
    iifname "dstap-*" tcp dport 53 counter log prefix "ds-nft4 resolver-bypass " group 4
  }
  chain resolver_closure_forward {
    iifname "dstap-*" udp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop
    iifname "dstap-*" tcp dport 853 counter log prefix "ds-nft4 dot-drop " group 4 drop
    iifname "dstap-*" udp dport 443 counter accept
  }
}
`
	err := assertNFT4ClosureShape(ruleset)
	if err == nil {
		t.Logf("PURE ACCEPT: PASSES (nil) -- would be a defect")
	} else {
		t.Logf("PURE ACCEPT: caught: %v", err)
	}
}
