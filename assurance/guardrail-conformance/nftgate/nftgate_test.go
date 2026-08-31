// SPDX-License-Identifier: Apache-2.0

package nftgate

import (
	"net/netip"
	"testing"
)

// referencePosture is the documented M0 boundary posture the offline fixtures
// are asserted against (the spec read of doc 09 §9 / doc 11 §6 / D70). One
// session has a single allowlisted domain admitting a single documentation-range
// IP; the POL-2 baseline blocklist names the public DoH resolver domains. This
// is the model the assertions try to defeat — every fixture is an attempt to
// make a guardrail fail against this posture.
func referencePosture() Posture {
	allowedIP := netip.MustParseAddr("203.0.113.10")
	return Posture{
		AdmittedDomains: map[string]bool{
			"api.allowed.example": true,
		},
		Admitted: map[string]map[netip.Addr]bool{
			"api.allowed.example": {allowedIP: true},
		},
		DoHResolverDomains: map[string]bool{
			// The D64 POL-2 baseline blocklist's known public DoH resolver domains
			// (named verbatim in the docs).
			"dns.google":                 true,
			"cloudflare-dns.com":         true,
			"mozilla.cloudflare-dns.com": true,
		},
	}
}

// TestM0Rows_FixturesDisposeAsDocumented is the heart of the suite: every
// synthetic egress-attempt fixture is driven through the modeled boundary
// disposition, and the result must equal the disposition the docs require. A
// mismatch means either the model drifted from doc 09/11/D70 or a fixture's
// required disposition is wrong — either way the guardrail claim is unproven.
func TestM0Rows_FixturesDisposeAsDocumented(t *testing.T) {
	p := referencePosture()
	fixtures, err := LoadFixtures()
	if err != nil {
		t.Fatalf("loading egress-attempt fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no egress-attempt fixtures found; the M0 rows must be seeded as assertions")
	}
	for _, f := range fixtures {
		t.Run(f.Attempt.Name, func(t *testing.T) {
			got := p.Dispose(f.Attempt)
			if got != f.Want {
				t.Fatalf("row %q attempt %q (%s): boundary disposition = %q, docs require %q\n  why: %s",
					f.Row, f.Attempt.Name, f.Kind, got, f.Want, f.Why)
			}
		})
	}
}

// TestAllRowsSeeded asserts every modeled (c) row — the M0 seed set in
// RowOwners() AND the band-c extension rows in BandCRowOwners() — is seeded by at
// least one fixture, and that no fixture names a row outside the union table.
// This is the not-vacuous guard: the suite cannot quietly drop a row from the
// table (or seed a fixture for an unmodeled row) and still pass.
func TestAllRowsSeeded(t *testing.T) {
	fixtures, err := LoadFixtures()
	if err != nil {
		t.Fatalf("loading egress-attempt fixtures: %v", err)
	}
	seeded := map[Row]int{}
	owners := AllRowOwners()
	for _, f := range fixtures {
		if _, ok := owners[f.Row]; !ok {
			t.Errorf("fixture %q names row %q which is not in the AllRowOwners table", f.Attempt.Name, f.Row)
		}
		seeded[f.Row]++
	}
	for row := range owners {
		if seeded[row] == 0 {
			t.Errorf("(c) row %q has no seeding fixture; every advertised guardrail must become a test", row)
		}
	}
}

// TestRowOwnersNameRealSteps asserts every modeled (c) row — across the M0 seed
// set AND the band-c extension — names at least one doc 09 §9 boundary step as
// its owner, drawn from the known Step set. This pins the §9 step-ownership
// mapping the diff-scoped (c) subset selection (D47) relies on.
func TestRowOwnersNameRealSteps(t *testing.T) {
	known := map[Step]bool{
		StepNFT1: true, StepNFT2: true, StepNFT3: true, StepNFT4: true,
		StepDNS4: true, StepTLS1: true, StepPOL2: true, StepSeg2: true,
	}
	for row, steps := range AllRowOwners() {
		if len(steps) == 0 {
			t.Errorf("(c) row %q names no owning step (doc 09 §9)", row)
		}
		for _, s := range steps {
			if !known[s] {
				t.Errorf("(c) row %q names unknown step %q", row, s)
			}
		}
	}
}

// TestDefaultDeny_BothLegs asserts the D4 row explicitly drives BOTH legs the
// docs name: an L3/4 reach to an unadmitted IP is dropped before the proxy, and
// a proxied connection to an unadmitted (domain, IP) pair is refused at the
// egress gateway. The allowlisted controls prove the deny is the DEFAULT, not a
// blanket block.
func TestDefaultDeny_BothLegs(t *testing.T) {
	p := referencePosture()
	unadmittedIP := "198.51.100.7"
	admittedIP := "203.0.113.10"

	// L3/4 leg (NFT-1, before the proxy).
	if got := p.Dispose(Attempt{Kind: AttemptL34Direct, DstIP: unadmittedIP}); got != DispDropL34 {
		t.Errorf("L3/4 reach to unadmitted IP: got %q, want %q (NFT-1 default-drop)", got, DispDropL34)
	}
	if got := p.Dispose(Attempt{Kind: AttemptL34Direct, DstIP: admittedIP}); got != DispAllow {
		t.Errorf("L3/4 reach to admitted IP (control): got %q, want %q", got, DispAllow)
	}

	// Via-proxy leg (TLS-1). Unadmitted domain refused even on an IP admitted for
	// another domain (the shared-CDN-IP hole stays closed).
	if got := p.Dispose(Attempt{Kind: AttemptProxiedTLS, Domain: "evil.notallowed.example", DstIP: admittedIP}); got != DispRefuseProxy {
		t.Errorf("proxied reach for unadmitted domain on a shared admitted IP: got %q, want %q (TLS-1 domain+IP admission)", got, DispRefuseProxy)
	}
	if got := p.Dispose(Attempt{Kind: AttemptProxiedTLS, Domain: "api.allowed.example", DstIP: admittedIP}); got != DispAllow {
		t.Errorf("proxied reach for admitted (domain, IP) (control): got %q, want %q", got, DispAllow)
	}
}

// TestQUIC_RejectNotDrop is the D70 row's load-bearing assertion: udp/443 is
// rejected-with-ICMP-and-counted, which is a DISTINCT disposition from a silent
// L3/4 drop. The test pins that the model never collapses the two — a silent
// drop would defeat the "force TCP fallback the proxy can see" property even
// though the packet does not egress either way.
func TestQUIC_RejectNotDrop(t *testing.T) {
	p := referencePosture()
	got := p.Dispose(Attempt{Kind: AttemptQUIC, DstIP: "203.0.113.10"})
	if got != DispRejectICMPCounted {
		t.Fatalf("QUIC udp/443: got %q, want %q (D70 reject-with-ICMP + counted)", got, DispRejectICMPCounted)
	}
	if got == DispDropL34 {
		t.Fatal("QUIC disposed as a silent L3/4 drop; D70 requires reject-with-ICMP + counted, never a silent drop")
	}
}

// TestPort53_RedirectHolds asserts the NFT-4 port-53 closure: a port-53 attempt
// is redirected onto ds-dnsgate regardless of the aimed-at IP — there is no
// foreign-resolver IP that escapes the redirect.
func TestPort53_RedirectHolds(t *testing.T) {
	p := referencePosture()
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "203.0.113.10", "198.51.100.7"} {
		if got := p.Dispose(Attempt{Kind: AttemptPort53, DstIP: ip}); got != DispRedirectResolver {
			t.Errorf("port-53 aimed at %s: got %q, want %q (NFT-4 redirect holds for any IP)", ip, got, DispRedirectResolver)
		}
	}
}

// TestRebinding_ScrubRanges drives the DNS-4 dual-stack sanity scrub directly:
// every range DNS-4 rule 2 refuses to admit must scrub, and a public answer must
// NOT scrub (so the scrub is targeted, not a blanket refusal that would break
// legitimate re-resolution).
func TestRebinding_ScrubRanges(t *testing.T) {
	scrubbed := []string{
		"10.0.0.5",        // RFC1918 private
		"192.168.1.1",     // RFC1918 private
		"172.16.0.1",      // RFC1918 private
		"127.0.0.1",       // loopback
		"169.254.0.1",     // link-local
		"::1",             // v6 loopback
		"fe80::1",         // v6 link-local
		"fc00::1",         // v6 ULA
		"::ffff:10.0.0.5", // IPv4-mapped private
		"64:ff9b::a00:5",  // NAT64-embedded 10.0.0.5
	}
	for _, s := range scrubbed {
		addr := netip.MustParseAddr(s)
		if !IsScrubbed(addr) {
			t.Errorf("DNS-4 scrub: %s should be scrubbed (never admitted), but IsScrubbed=false", s)
		}
	}
	notScrubbed := []string{
		"203.0.113.10",       // public documentation v4
		"198.51.100.7",       // public documentation v4
		"2001:db8::1",        // public documentation v6
		"64:ff9b::cb00:710b", // NAT64-embedded 203.0.113.11 (public) — must NOT scrub
	}
	for _, s := range notScrubbed {
		addr := netip.MustParseAddr(s)
		if IsScrubbed(addr) {
			t.Errorf("DNS-4 scrub: %s is a public answer and must NOT be scrubbed, but IsScrubbed=true", s)
		}
	}
}

// TestRebinding_NoSilentWiden asserts the re-resolution disposition is always
// "scrub, no silent widen" — re-resolutions go through full admission again
// rather than the OLD admission silently carrying the NEW flow (DNS-4 rule 3 +
// NFT-3). The model never returns DispAllow for a re-resolve attempt off the
// back of a stale admission.
func TestRebinding_NoSilentWiden(t *testing.T) {
	p := referencePosture()
	// An approved name re-resolving to a brand-new public IP that was never
	// admitted for it: it does not silently ride the old admission.
	got := p.Dispose(Attempt{Kind: AttemptReResolve, Domain: "api.allowed.example", DstIP: "203.0.113.99"})
	if got == DispAllow {
		t.Fatal("re-resolution silently admitted off a stale allow-set entry; DNS-4 rule 3 forbids silent widening")
	}
	if got != DispScrubNoWiden {
		t.Fatalf("re-resolution disposition = %q, want %q (DNS-4 re-admission, no silent widen)", got, DispScrubNoWiden)
	}
}

// TestDoHDoT_AllResolutionForcedThroughResolver asserts the NFT-4 + POL-2
// no-bypass family: a DoT attempt drops, a DoH attempt to a known resolver is
// denied, and a port-53 attempt is redirected — all resolution is forced through
// ds-dnsgate, none escapes.
func TestDoHDoT_AllResolutionForcedThroughResolver(t *testing.T) {
	p := referencePosture()
	if got := p.Dispose(Attempt{Kind: AttemptDoT, Domain: "one.one.one.one", DstIP: "1.1.1.1"}); got != DispDropDoT {
		t.Errorf("DoT tcp/853: got %q, want %q (NFT-4 drop)", got, DispDropDoT)
	}
	if got := p.Dispose(Attempt{Kind: AttemptDoH, Domain: "dns.google", DstIP: "8.8.8.8"}); got != DispDenyDoH {
		t.Errorf("DoH to known resolver: got %q, want %q (NFT-4 + POL-2 blocklist)", got, DispDenyDoH)
	}
}

// TestUnknownAttemptFailsClosed asserts an unmodeled attempt kind disposes to a
// deny, never an allow — an unmapped shape can never read as permitted (fail
// closed, matching the D47 unmapped-path posture in spirit).
func TestUnknownAttemptFailsClosed(t *testing.T) {
	p := referencePosture()
	got := p.Dispose(Attempt{Kind: AttemptKind("totally-unmodeled-shape")})
	if got == DispAllow {
		t.Fatal("an unmodeled attempt kind disposed to allow; the model must fail closed")
	}
}

// ── Band-c rows: the remaining doc 06 §3c / doc 09 §9 (c) assertions ─────────

// TestInterfaceMatch_SpoofedSourceDoesNotEscape is the NFT-2 row's load-bearing
// assertion: the prerouting redirect matches the VM's attachment interface
// (`iifname`), never source IP, so a forged in-VM source address has NO effect on
// the disposition — a spoofed connect to an unadmitted destination is dropped
// exactly as the unspoofed one is, and a spoofed connect cannot reach a
// destination an unspoofed one could not. The forge buys nothing.
func TestInterfaceMatch_SpoofedSourceDoesNotEscape(t *testing.T) {
	p := referencePosture()
	unadmittedIP := "198.51.100.7"
	admittedIP := "203.0.113.10"

	// A spoofed-source connect to an UNADMITTED destination is still dropped: NFT-2
	// matched the interface, NFT-1 default-drop applied for the unadmitted dest.
	spoofed := Attempt{Kind: AttemptSpoofedSource, DstIP: unadmittedIP, SrcSpoofed: true}
	if got := p.Dispose(spoofed); got != DispDropL34 {
		t.Errorf("spoofed-source connect to unadmitted IP: got %q, want %q (NFT-2 iifname match, NFT-1 drop)", got, DispDropL34)
	}

	// The spoof had NO effect: the same shape WITHOUT the forge disposes identically.
	unspoofed := Attempt{Kind: AttemptL34Direct, DstIP: unadmittedIP}
	if p.Dispose(spoofed) != p.Dispose(unspoofed) {
		t.Errorf("forged source changed the disposition (spoofed=%q unspoofed=%q); NFT-2 must match the interface, not source IP",
			p.Dispose(spoofed), p.Dispose(unspoofed))
	}

	// And a spoofed source cannot REACH a destination the interface gate does not
	// admit just by forging — reaching the admitted destination is the destination's
	// admission, not the source's: the control still admits on the admitted dest.
	if got := p.Dispose(Attempt{Kind: AttemptSpoofedSource, DstIP: admittedIP, SrcSpoofed: true}); got != DispAllow {
		t.Errorf("spoofed-source connect to an admitted destination (control): got %q, want %q (admission is by destination, unaffected by the forge)", got, DispAllow)
	}
}

// TestECHSVCBSuppression_NoHiddenDomainNoRecord drives the DNS-4 rule 4 + TLS-1
// row: an HTTPS (type 65) / SVCB query is answered with the record type
// suppressed entirely (no ECH config / alpn=h3 reaches a VM), and an ECH
// ClientHello on an IP admitted for a DIFFERENT (outer) domain is refused — so
// ECH cannot hide a non-admitted inner domain behind an admitted CDN IP.
func TestECHSVCBSuppression_NoHiddenDomainNoRecord(t *testing.T) {
	p := referencePosture()

	// No HTTPS/SVCB answer reaches a VM (DNS-4 rule 4).
	if got := p.Dispose(Attempt{Kind: AttemptHTTPSSVCBQuery, Domain: "api.allowed.example"}); got != DispSuppressHTTPSSVCB {
		t.Errorf("HTTPS/SVCB query: got %q, want %q (DNS-4 rule 4 suppresses the record type)", got, DispSuppressHTTPSSVCB)
	}

	// An ECH ClientHello on an admitted CDN IP is refused (TLS-1) — even though the
	// IP 203.0.113.10 is admitted for api.allowed.example, the encrypted inner name
	// could be a NON-admitted domain, so the hello is refused regardless of the
	// outer-domain admission.
	ech := Attempt{Kind: AttemptECHHello, Domain: "api.allowed.example", DstIP: "203.0.113.10", ECH: true}
	if got := p.Dispose(ech); got != DispRefuseECH {
		t.Errorf("ECH ClientHello on an admitted CDN IP: got %q, want %q (TLS-1 refuses ECH)", got, DispRefuseECH)
	}
	if p.Dispose(ech) == DispAllow {
		t.Fatal("ECH ClientHello admitted; TLS-1 must refuse ECH so a hidden inner name cannot ride an admitted IP")
	}
}

// TestSessionIsolation_NoL2Path is the §2-placement + NFT-1 row: session A cannot
// reach session B — there is no L2 path between agent VMs (a structural /
// flag-audited proof, never inherited from the inet default-deny ruleset, since
// bridged frames bypass the inet forward chain, D66). The reach is denied for any
// destination IP, since the isolation is the absence of a path, not a dst filter.
func TestSessionIsolation_NoL2Path(t *testing.T) {
	p := referencePosture()
	for _, ip := range []string{"203.0.113.10", "198.51.100.7", "10.0.0.5"} {
		got := p.Dispose(Attempt{Kind: AttemptCrossSession, DstIP: ip, PeerSession: "session-b"})
		if got != DispNoL2Path {
			t.Errorf("cross-session reach toward %s: got %q, want %q (§2 placement + NFT-1, no L2 path)", ip, got, DispNoL2Path)
		}
		if got == DispAllow {
			t.Fatalf("session A reached session B at %s; there must be no L2 path between agent VMs", ip)
		}
	}
}

// TestIPv6Closure_DormantPostureHolds is the D75 v6-closure row: in the v0
// dormant-v6 posture an AAAA query is stripped and answered NOERROR/NODATA (never
// dropped / SERVFAIL), so the guest is handed no v6 address; and an IPv6 egress
// from a VM interface (incl. an fe80 sibling probe) is denied at the BOUNDARY
// HOST netns — not the guest sysctl — so the closure survives a guest that
// re-enables v6.
func TestIPv6Closure_DormantPostureHolds(t *testing.T) {
	p := referencePosture()

	// AAAA strip: NOERROR/NODATA, never a drop / SERVFAIL.
	if got := p.Dispose(Attempt{Kind: AttemptAAAAQuery, Domain: "api.allowed.example"}); got != DispStripAAAANoData {
		t.Errorf("AAAA query in dormant-v6 posture: got %q, want %q (D75 strip → NOERROR/NODATA)", got, DispStripAAAANoData)
	}

	// v6 egress (incl. an fe80 link-local sibling probe) denied at the boundary host.
	for _, ip := range []string{"fe80::1", "2001:db8::1", "::1"} {
		got := p.Dispose(Attempt{Kind: AttemptV6LinkLocalReach, DstIP: ip})
		if got != DispDenyV6Dormant {
			t.Errorf("v6 reach to %s in dormant posture: got %q, want %q (D75 boundary-host netns holds the line)", ip, got, DispDenyV6Dormant)
		}
		if got == DispAllow {
			t.Fatalf("v6 egress to %s admitted in the dormant-v6 posture; the boundary host must hold the line", ip)
		}
	}
}

// TestBandCRowsSeeded asserts every band-c row in BandCRowOwners() is seeded by
// at least one fixture and that the band-c rows are disjoint from the M0 rows
// (no row is double-owned across the two tables). This is the band-c not-vacuous
// guard, mirroring TestAllRowsSeeded but pinning the band-c subset specifically.
func TestBandCRowsSeeded(t *testing.T) {
	fixtures, err := LoadFixtures()
	if err != nil {
		t.Fatalf("loading egress-attempt fixtures: %v", err)
	}
	bandC := BandCRowOwners()
	m0 := RowOwners()
	for row := range bandC {
		if _, dup := m0[row]; dup {
			t.Errorf("band-c row %q is also in the M0 RowOwners table; the two tables must be disjoint", row)
		}
	}
	seeded := map[Row]int{}
	for _, f := range fixtures {
		if _, ok := bandC[f.Row]; ok {
			seeded[f.Row]++
		}
	}
	for row := range bandC {
		if seeded[row] == 0 {
			t.Errorf("band-c (c) row %q has no seeding fixture; every advertised guardrail must become a test", row)
		}
	}
}

// TestBandCNegativeControl is the load-bearing proof the band-c assertions are
// NOT vacuous: against a broken allow-everything boundary, the four band-c
// guardrail shapes would each be ADMITTED — i.e. the boundary did not hold — so a
// regression that widened any of these to allow-by-default is caught. (Twin of
// TestDefaultDenyNegativeControl for the band-c rows.)
func TestBandCNegativeControl(t *testing.T) {
	broken := allowEverythingBoundary{}
	p := referencePosture()

	cases := []struct {
		name string
		a    Attempt
	}{
		{"interface-match spoofed source", Attempt{Kind: AttemptSpoofedSource, DstIP: "198.51.100.7", SrcSpoofed: true}},
		{"ECH ClientHello on a shared admitted IP", Attempt{Kind: AttemptECHHello, Domain: "api.allowed.example", DstIP: "203.0.113.10", ECH: true}},
		{"cross-session L2 reach", Attempt{Kind: AttemptCrossSession, DstIP: "203.0.113.10", PeerSession: "session-b"}},
		{"v6 egress in dormant posture", Attempt{Kind: AttemptV6LinkLocalReach, DstIP: "fe80::1"}},
	}
	for _, c := range cases {
		// Against the BROKEN boundary the shape leaks (admitted) — proving the
		// real-posture assertions below have teeth.
		if got := broken.Dispose(c.a); got != DispAllow {
			t.Fatalf("negative control is itself broken: %s against an allow-everything boundary did not leak (disp=%q)", c.name, got)
		}
		// Against the REAL posture the same shape must NOT be admitted.
		if got := p.Dispose(c.a); got == DispAllow {
			t.Fatalf("%s leaked against the REAL posture (disp=%q) — the band-c guardrail does not hold", c.name, got)
		}
	}
}
