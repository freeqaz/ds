// SPDX-License-Identifier: Apache-2.0

package nftgate

// live_probe_dns_test.go — the dnsgate-enforced wired live runners (the DNS legs
// of RowPort53Redirect, RowECHSVCBSuppression, RowIPv6Closure), driven against a
// real ds-dnsgate on the M0 boundary. Like the L3/4 runner they observe the wire
// from the guest and are cross-checked against referencePosture by the
// TestLive_M0Boundary loop. Gated behind DS_NFTGATE_LIVE=1 + a provisioned
// boundary; skip-by-default offline/CI.
//
// FAITHFULNESS (non-vacuity): each runner queries a REAL allowlisted name that
// genuinely HAS the upstream record being stripped/suppressed (AAAA, HTTPS) — so
// a NODATA answer is the boundary's doing, not an absent upstream record — and
// pairs it with a control A query that DOES resolve, proving NODATA is
// suppression rather than refusal/NXDOMAIN. The :53-redirect runner queries a
// non-allowlisted name the FOREIGN resolver would have resolved, so ds-dnsgate's
// REFUSED is proof the query was funneled to ds-dnsgate.

import (
	"strings"
	"testing"
)

// oneLine collapses a multi-line command output to a single line for compact
// failure messages.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// guestHost runs `host [-t qtype] name [server]` FROM THE GUEST and returns the
// trimmed output. server "" uses the guest's configured resolver (ds-dnsgate).
func (b liveBoundary) guestHost(t *testing.T, qtype, name, server string) string {
	t.Helper()
	cmd := "host"
	if qtype != "" {
		cmd += " -t " + qtype
	}
	cmd += " " + name
	if server != "" {
		cmd += " " + server
	}
	out, _ := b.guestSSHCmd(t, "timeout 8 "+cmd+" 2>&1 || true")
	return out
}

// port53RedirectLiveRunner — RowPort53Redirect (NFT-4 port-53 redirect): an in-VM
// query aimed at a FOREIGN resolver is funneled to ds-dnsgate. Proof: a
// non-allowlisted name the foreign resolver WOULD resolve comes back with
// ds-dnsgate's REFUSED — identical to the in-VM-resolver path.
func port53RedirectLiveRunner(t *testing.T, f Fixture) {
	if f.Kind != AttemptPort53 {
		t.Fatalf("port53RedirectLiveRunner: unexpected attempt kind %q for %q", f.Kind, f.Attempt.Name)
	}
	b := liveBoundaryFromEnv(t)
	atForeign := b.guestHost(t, "", b.blockedName, b.foreignResolver)
	if !strings.Contains(atForeign, "REFUSED") {
		t.Fatalf("port53-redirect[%s]: query %q @%s did NOT return ds-dnsgate's REFUSED (got %q); the foreign "+
			"resolver would have resolved it, so a non-REFUSED answer means the :53 redirect is not in force",
			f.Attempt.Name, b.blockedName, b.foreignResolver, oneLine(atForeign))
	}
	viaGate := b.guestHost(t, "", b.blockedName, "")
	if !strings.Contains(viaGate, "REFUSED") {
		t.Fatalf("port53-redirect[%s]: query %q via the in-VM resolver did not REFUSE (got %q); cannot confirm the "+
			"foreign-resolver path was funneled to the SAME ds-dnsgate", f.Attempt.Name, b.blockedName, oneLine(viaGate))
	}
	t.Logf("WIRE OK port53-redirect[%s]: %q @%s funneled to ds-dnsgate (REFUSED, matches the in-VM-resolver path), want=%s",
		f.Attempt.Name, b.blockedName, b.foreignResolver, f.Want)
}

// svcbSuppressLiveRunner — RowECHSVCBSuppression. The SVCB/HTTPS leg is wired; the
// ECH-ClientHello leg is honestly skipped until ds-tlsproxy (TLS-1) is stood up.
func svcbSuppressLiveRunner(t *testing.T, f Fixture) {
	if f.Kind == AttemptECHHello {
		t.Skipf("ECH ClientHello fixture %q (want %q) needs ds-tlsproxy (TLS-1) stood up to refuse an ECH hello; "+
			"the SVCB-suppression leg is wired, the ECH leg is the next stand-up step", f.Attempt.Name, f.Want)
	}
	if f.Kind != AttemptHTTPSSVCBQuery {
		t.Fatalf("svcbSuppressLiveRunner: unexpected attempt kind %q for %q", f.Kind, f.Attempt.Name)
	}
	b := liveBoundaryFromEnv(t)
	https := b.guestHost(t, "HTTPS", b.allowedName, "")
	if !strings.Contains(https, "has no HTTPS record") {
		t.Fatalf("svcb-suppress[%s]: HTTPS query for %q did NOT return NODATA 'has no HTTPS record' (got %q); the "+
			"record type must be suppressed so no ECH config / h3 hint reaches the guest (DNS-4)",
			f.Attempt.Name, b.allowedName, oneLine(https))
	}
	// Control: the name DOES resolve A (it is admitted), so the NODATA is suppression, not refusal/NXDOMAIN.
	a := b.guestHost(t, "A", b.allowedName, "")
	if !strings.Contains(a, "has address") {
		t.Fatalf("svcb-suppress[%s]: control A query for %q did not resolve (got %q); cannot attribute the HTTPS "+
			"NODATA to suppression rather than an unresolvable name", f.Attempt.Name, b.allowedName, oneLine(a))
	}
	t.Logf("WIRE OK svcb-suppress[%s]: HTTPS for %q suppressed to NODATA while A still resolves, want=%s",
		f.Attempt.Name, b.allowedName, f.Want)
}

// aaaaStripLiveRunner — RowIPv6Closure. The AAAA-strip leg is wired; the v6-reach
// boundary-host leg is honestly skipped until a v6 probe is stood up.
func aaaaStripLiveRunner(t *testing.T, f Fixture) {
	if f.Kind != AttemptAAAAQuery {
		t.Skipf("v6-closure fixture %q (kind %q, want %q) needs a v6 boundary-host reach probe stood up; "+
			"the AAAA-strip leg is wired, the v6-reach leg is the next stand-up step", f.Attempt.Name, f.Kind, f.Want)
	}
	b := liveBoundaryFromEnv(t)
	aaaa := b.guestHost(t, "AAAA", b.allowedName, "")
	if !strings.Contains(aaaa, "has no AAAA record") {
		t.Fatalf("aaaa-strip[%s]: AAAA query for %q did NOT return NODATA 'has no AAAA record' (got %q); the AAAA "+
			"must be stripped so the guest is handed no v6 address (DNS-4 / D75 dormant-v6)",
			f.Attempt.Name, b.allowedName, oneLine(aaaa))
	}
	a := b.guestHost(t, "A", b.allowedName, "")
	if !strings.Contains(a, "has address") {
		t.Fatalf("aaaa-strip[%s]: control A query for %q did not resolve (got %q); cannot attribute the AAAA NODATA "+
			"to stripping rather than an unresolvable name", f.Attempt.Name, b.allowedName, oneLine(a))
	}
	t.Logf("WIRE OK aaaa-strip[%s]: AAAA for %q stripped to NODATA while A still resolves, want=%s",
		f.Attempt.Name, b.allowedName, f.Want)
}
