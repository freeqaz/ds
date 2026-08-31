// SPDX-License-Identifier: Apache-2.0
package resolverlock

import (
	"errors"
	"testing"
)

func TestRefuteCommentInjection(t *testing.T) {
	// The claimed attack rule: real verdict is ACCEPT, keywords stuffed in comment.
	attack := `iifname "dstap-*" udp dport 443 accept comment "counter reject icmp port-unreachable"`
	err := assertNFT4ClosureShape(attack)
	t.Logf("attack-only result: %v", err)

	// Also test it embedded in an otherwise-passing artifact so the global
	// flags (port53, DoT) are satisfied and only the QUIC rule is the attack.
	full := `
iifname "dstap-*" udp dport 53 counter log accept
iifname "dstap-*" tcp dport 53 counter log accept
iifname "dstap-*" udp dport 853 drop
iifname "dstap-*" tcp dport 853 drop
iifname "dstap-*" udp dport 443 accept comment "counter reject icmp port-unreachable"
`
	err2 := assertNFT4ClosureShape(full)
	t.Logf("full-artifact result: %v", err2)
	if err2 == nil {
		t.Errorf("FALSE GREEN: attack passed (returned nil)")
	}
	if errors.Is(err2, ErrQUICNotRejected) {
		t.Logf("caught by ErrQUICNotRejected")
	}
}
