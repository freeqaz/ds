// SPDX-License-Identifier: Apache-2.0

package netflowadapter

// helpers_test.go — shared test helpers for the conformance suite (LOG-1/LOG-4/
// LOG-5 additions). bg, t0, mkRef, dnsEvent, dnsEventWindow, mustObserve live in
// netflowadapter_test.go; these are the additions the schema/reconcile/audit
// tests share.

import (
	"fmt"
	"net/netip"
	"testing"

	flowlog "github.com/dream-serpent/dream-serpent/boundary/flowlog"
)

func mustAP(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
func mustAddr(s string) netip.Addr   { return netip.MustParseAddr(s) }

// mustFP fingerprints a secret, failing the test on error.
func mustFP(t *testing.T, secret []byte) flowlog.CredentialFingerprint {
	t.Helper()
	fp, err := FingerprintCredential(secret)
	if err != nil {
		t.Fatalf("FingerprintCredential: %v", err)
	}
	return fp
}

// typeName renders the short type name of an event for subtest naming.
func typeName(ev flowlog.Event) string {
	return fmt.Sprintf("%T", ev)
}
