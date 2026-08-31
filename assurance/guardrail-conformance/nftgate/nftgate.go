// SPDX-License-Identifier: Apache-2.0

package nftgate

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// ── Boundary steps that own each M0 row (doc 09 §9) ──────────────────────────
//
// The §9 assurance-hook table maps each guardrail to the boundary step that owns
// it. Carrying the owner on each modeled claim lets a boundary PR's diff-scoped
// (c) subset be selected (D47 guardrail-map) and lets the suite assert that every
// M0 row names a real step.

// Step is a doc 09 boundary build-plan step id (the §9 owner of a claim).
type Step string

const (
	// StepNFT1 — NFT-1 host bootstrap ruleset: inet default-drop on agent-VM
	// interfaces. Owns the default-deny row's L3/4 leg, co-owns session-isolation
	// (the inet base chains) and the IPv6-closure boundary-host posture.
	StepNFT1 Step = "NFT-1"
	// StepNFT2 — NFT-2 interface-matched transparent redirect: prerouting rules
	// match on the VM's attachment interface (`iifname`), NEVER on source IP, so a
	// forged in-VM source address cannot escape the redirect. Owns the interface-
	// match (in-VM spoofing) row.
	StepNFT2 Step = "NFT-2"
	// StepNFT3 — NFT-3 per-session allow-sets (the kernel set the allow lives in;
	// gates new flows only, element timeout = clamped TTL + grace). Co-owns the
	// rebinding / no-silent-widen row.
	StepNFT3 Step = "NFT-3"
	// StepNFT4 — NFT-4 resolver-bypass closure: port-53 redirect, DoT drop, DoH
	// blocklist enforcement, QUIC reject-not-drop. Owns the port-53/DoT/QUIC rows.
	StepNFT4 Step = "NFT-4"
	// StepDNS4 — DNS-4 rebinding defense: insert-then-answer, dual-stack sanity
	// scrub, TTL floors, HTTPS/SVCB suppression. Co-owns the rebinding row.
	StepDNS4 Step = "DNS-4"
	// StepTLS1 — TLS-1 SNI-checked tunnel: domain + admitted-IP admission at the
	// egress gateway. Owns the default-deny row's via-proxy leg.
	StepTLS1 Step = "TLS-1"
	// StepPOL2 — POL-2 system default baseline (D64): the named-DoH-resolver
	// blocklist the NFT-4 / DNS-3 denial enforces. Owns the known-DoH-denial row.
	StepPOL2 Step = "POL-2"
	// StepSeg2 — the doc 09 §2 placement guarantee: per-session attachment is a
	// native Linux construct (per-session bridge / routed tap / shared-bridge +
	// BR_ISOLATED) with a STRUCTURAL no-L2-path proof — bridged frames bypass the
	// inet forward chain, so the proof is never inherited from the inet default-
	// deny ruleset (D66). Co-owns the session-isolation row with NFT-1.
	StepSeg2 Step = "§2-placement"
)

// ── The M0 (c) rows ──────────────────────────────────────────────────────────

// Row names one M0 guardrail-conformance row. Each row is a CLAIM ("the
// guardrail does X") whose assertion tries to make it fail and asserts it holds.
type Row string

const (
	// RowDefaultDeny — default-deny outbound (D4): a non-allowlisted destination
	// is denied at L3/4 before the proxy AND via the proxy.
	RowDefaultDeny Row = "default-deny-outbound"
	// RowRebinding — DNS rebinding fails (DNS-4 + NFT-3): an approved name
	// re-resolving to a new IP does not silently widen the allow-set.
	RowRebinding Row = "dns-rebinding-fails"
	// RowDoHDoTBypass — DoH/DoT bypass fails (NFT-4 + POL-2): all resolution is
	// forced through our resolver.
	RowDoHDoTBypass Row = "doh-dot-bypass-fails"
	// RowPort53Redirect — port-53 redirect holds (NFT-4): port-53 traffic lands on
	// ds-dnsgate regardless of the aimed-at IP.
	RowPort53Redirect Row = "port-53-redirect-holds"
	// RowQUICReject — QUIC udp/443 rejected-not-dropped (D70, NFT-4): rejected with
	// ICMP port-unreachable and counted per session, never silently dropped.
	RowQUICReject Row = "quic-udp443-reject-not-drop"
)

// ── The remaining doc 06 §3c / doc 09 §9 boundary (c) rows ───────────────────
//
// These extend the band to the four §9 (c)-matrix rows the M0 seed set above did
// not yet cover. They share the same Row/Check/disposition vocabulary and the
// same offline-synthetic-fixture discipline (D50). Their owning steps and
// fixture-coverage are tracked in a SEPARATE BandCRowOwners() table (not the M0
// RowOwners() table) so the M0 live-half scaffolding (live_test.go's per-M0-row
// runner registry) stays untouched: these rows are spec-vs-model checks whose
// live wiring is a later step, and folding them into RowOwners() would demand a
// live runner each before that wiring exists.

const (
	// RowInterfaceMatch — in-VM spoofing fails (NFT-2): the transparent redirect
	// matches on the VM's attachment interface (`iifname`), never on source IP, so
	// a forged in-VM source address still lands on the redirect — the attachment
	// point cannot be forged from inside the VM. doc 06 §3c "In-VM spoofing fails
	// (interface match)".
	RowInterfaceMatch Row = "interface-match-not-source-ip"
	// RowECHSVCBSuppression — ECH cannot hide a non-admitted domain behind an
	// admitted IP, and no HTTPS/SVCB answer reaches a VM (DNS-4 rule 4 + TLS-1):
	// HTTPS (type 65) / SVCB answers are suppressed entirely (they advertise ECH
	// configs + alpn=h3), and an ECH ClientHello is refused at the egress gateway.
	// doc 06 §3c "ECH can't hide a non-admitted domain behind an admitted IP; no
	// HTTPS/SVCB answer reaches a VM".
	RowECHSVCBSuppression Row = "ech-svcb-suppression"
	// RowSessionIsolation — session A cannot reach session B (§2 placement + NFT-1):
	// there is no L2 path between two agent VMs (structural / flag-audited proof,
	// never inherited from the inet default-deny ruleset, since bridged frames
	// bypass the inet forward chain — D66). doc 06 §3c "Session A cannot reach
	// session B (no L2 path between agent VMs)".
	RowSessionIsolation Row = "session-isolation-no-l2-path"
	// RowIPv6Closure — the dormant guest-v6 posture holds (D75): v0 strips AAAA
	// (answered as NOERROR/NODATA with the D71-authored SOA, never dropped), the
	// `allow6` sets stay dormant, and the boundary host netns — not the guest
	// sysctl — holds the line (a fe80 sibling probe from a VM interface is denied).
	// doc 06 §3c v6-closure (c) row.
	RowIPv6Closure Row = "ipv6-closure-dormant-posture-holds"
)

// ── The documented boundary posture (the frozen spec read) ───────────────────
//
// Posture is the small auditable model of the doc 09 / doc 11 / D70 boundary
// disposition the M0 rows are asserted against. It is NOT live state: it is the
// spec read of the frozen plan, so the offline assertions can run anywhere with
// no data plane. The live half (live_test.go) drives the SAME model against a
// real boundary.

// Posture models one session's admission state plus the frozen NFT-4 / D70
// dispositions that do not depend on per-session state.
type Posture struct {
	// AdmittedDomains is the policy-allowed domain set for the session (TLS-1 SNI
	// admission: an SNI not in this set is refused). An empty set means the
	// session has no allow grants yet — every domain is non-admitted.
	AdmittedDomains map[string]bool
	// Admitted is the per-(domain) set of admitted addresses written by DNS-2's
	// insert-then-answer transaction (the NFT-3 set / DNS-2b map). A bare IP not
	// admitted FOR THE DOMAIN does not pass TLS-1 even if some other domain
	// admitted it (the shared-CDN-IP hole, doc 03 OQ1).
	Admitted map[string]map[netip.Addr]bool
	// DoHResolverDomains is the D64 POL-2 baseline blocklist of known public DoH
	// resolver domains (NFT-4 / DNS-3 named-resolver half).
	DoHResolverDomains map[string]bool
}

// ── Egress attempts (the VM, treated as untrusted, tries to defeat a guardrail) ──

// AttemptKind enumerates the L3/4-and-up shapes a VM egress attempt can take.
// These are the documented dimensions the boundary dispositions turn on, not an
// attack taxonomy: each is a thing a misbehaving (or merely misconfigured) VM
// does, that the boundary must dispose of correctly.
type AttemptKind string

const (
	// AttemptL34Direct — a raw L3/4 connect to a destination IP on tcp 80/443,
	// before any proxy. Disposed by NFT-1 (default-drop unless the dest IP is in
	// the session allow-set, the Stage-1 interim NFT-3 gate).
	AttemptL34Direct AttemptKind = "l3l4-direct-connect"
	// AttemptProxiedTLS — a TLS connection through the egress gateway carrying an
	// SNI for an OriginalDst IP. Disposed by TLS-1 (domain allowed AND IP admitted
	// for that domain).
	AttemptProxiedTLS AttemptKind = "proxied-tls-connect"
	// AttemptPort53 — destination-port-53 traffic aimed at AimedResolver.
	// Disposed by NFT-4 (always redirected to ds-dnsgate).
	AttemptPort53 AttemptKind = "port-53-resolution"
	// AttemptDoT — a DNS-over-TLS attempt (tcp/853). Disposed by NFT-4 (dropped).
	AttemptDoT AttemptKind = "dns-over-tls-853"
	// AttemptDoH — a DNS-over-HTTPS attempt to a resolver Domain. Disposed by NFT-4
	// + POL-2 (denied when Domain is a known DoH resolver).
	AttemptDoH AttemptKind = "dns-over-https"
	// AttemptQUIC — a udp/443 (QUIC) connect. Disposed by NFT-4 / D70 (rejected
	// with ICMP port-unreachable and counted, never silently dropped).
	AttemptQUIC AttemptKind = "quic-udp-443"
	// AttemptReResolve — an approved name re-resolving to a NEW answer (the
	// rebinding shape). Disposed by DNS-4 (the answer is sanity-scrubbed before
	// admission, and re-admission never silently widens the set).
	AttemptReResolve AttemptKind = "approved-name-re-resolves"
	// AttemptSpoofedSource — an L3/4 egress whose IN-VM SOURCE ADDRESS is forged
	// (SrcSpoofed=true), arriving on the VM's attachment interface. Disposed by
	// NFT-2: the prerouting rule matches `iifname`, not source IP, so the forge
	// buys nothing — the attempt is still gated by the interface-anchored path and
	// (here) dropped by NFT-1 default-drop for the unadmitted destination.
	AttemptSpoofedSource AttemptKind = "spoofed-in-vm-source-addr"
	// AttemptHTTPSSVCBQuery — a DNS query for an HTTPS (type 65) / SVCB record.
	// Disposed by DNS-4 rule 4: the record type is suppressed entirely, so no
	// HTTPS/SVCB answer (and thus no ECH config / alpn=h3 hint) ever reaches a VM.
	AttemptHTTPSSVCBQuery AttemptKind = "https-svcb-record-query"
	// AttemptECHHello — a TLS ClientHello carrying an Encrypted Client Hello
	// extension, for an OriginalDst IP admitted for a DIFFERENT (outer) domain.
	// Disposed by TLS-1: ECH ClientHellos are refused, so an encrypted inner name
	// cannot ride an admitted CDN IP to reach a non-admitted domain.
	AttemptECHHello AttemptKind = "ech-clienthello"
	// AttemptCrossSession — an L2 reach from session A's VM toward session B's VM
	// address (PeerSession set). Disposed by §2 placement + NFT-1: there is no L2
	// path between agent VMs (structural / flag-audited), so B is unreachable.
	AttemptCrossSession AttemptKind = "cross-session-l2-reach"
	// AttemptAAAAQuery — a DNS AAAA query in the v0 dormant-IPv6 posture. Disposed
	// by DNS-1/D75: AAAA is stripped and answered NOERROR/NODATA (never dropped /
	// SERVFAIL), so the guest is handed no v6 address and `allow6` stays dormant.
	AttemptAAAAQuery AttemptKind = "aaaa-query-dormant-v6"
	// AttemptV6LinkLocalReach — an IPv6 reach from a VM interface (e.g. an fe80
	// sibling probe) in the dormant-v6 posture. Disposed by NFT-1/D75: the boundary
	// host netns holds the line (not the guest sysctl), so v6 egress is denied.
	AttemptV6LinkLocalReach AttemptKind = "v6-reach-dormant-posture"
)

// Attempt is one synthetic egress attempt: the VM, treated as untrusted, trying
// to reach a destination. The fields populated depend on Kind.
type Attempt struct {
	// Name labels the attempt for assertion messages (filled from the fixture
	// filename when loaded via LoadAttempt).
	Name string `json:"-"`
	// Kind selects which boundary disposition applies.
	Kind AttemptKind `json:"kind"`
	// Domain is the SNI / DoH-resolver / re-resolved name (proxied, DoH, re-resolve).
	Domain string `json:"domain,omitempty"`
	// DstIP is the destination IP the attempt aims at (L3/4 direct, proxied
	// original-dst, port-53 aimed resolver, re-resolve answer, cross-session peer,
	// v6 reach). Parsed as a netip.
	DstIP string `json:"dst_ip,omitempty"`
	// SrcSpoofed marks an L3/4 attempt whose in-VM SOURCE address is forged (the
	// NFT-2 interface-match shape). It never changes the disposition — that is the
	// point: NFT-2 matches the attachment interface, not source IP, so a forged
	// source buys nothing. Carried so the assertion can pin the spoof had no effect.
	SrcSpoofed bool `json:"src_spoofed,omitempty"`
	// ECH marks a proxied ClientHello that carries an Encrypted Client Hello
	// extension (the TLS-1 refusal shape). The inner name is hidden; only the outer
	// (CDN) name would be visible, so it is refused regardless of Domain admission.
	ECH bool `json:"ech,omitempty"`
	// PeerSession names the OTHER session whose VM this attempt tries to reach (the
	// §2-placement / NFT-1 session-isolation shape). A non-empty value marks a
	// cross-session reach; there is no L2 path, so it is denied.
	PeerSession string `json:"peer_session,omitempty"`
	// Why records, in the fixture, WHY the boundary disposes of the attempt the
	// way it does (the doc anchor). Carried into messages, never used for logic.
	Why string `json:"why,omitempty"`
}

// addr parses a.DstIP, returning the zero Addr if empty/invalid (callers that
// need a valid addr check Addr.IsValid()).
func (a Attempt) addr() netip.Addr {
	ip, err := netip.ParseAddr(strings.TrimSpace(a.DstIP))
	if err != nil {
		return netip.Addr{}
	}
	return ip
}

// ── The disposition the boundary must produce ────────────────────────────────

// Disposition is what the boundary does with an egress attempt. The values are
// chosen so a SILENT DROP is distinguishable from a REJECT-WITH-ICMP — the D70
// row turns on exactly that distinction.
type Disposition string

const (
	// DispAllow — the attempt is admitted (the allowlisted control; a default-deny
	// suite that never allowed anything would be a blanket block, not a default).
	DispAllow Disposition = "allow"
	// DispDropL34 — dropped at L3/4 by the NFT-1 default-drop base chains (no
	// response; the destination is not in the session allow-set).
	DispDropL34 Disposition = "drop-l3l4-default-deny"
	// DispRefuseProxy — refused at the egress gateway by the TLS-1 admission check
	// (domain not allowed, or IP not admitted for the domain).
	DispRefuseProxy Disposition = "refuse-at-egress-gateway"
	// DispRedirectResolver — redirected onto ds-dnsgate regardless of aimed-at IP
	// (NFT-4 port-53 closure). The bypass did not hold; our resolver answered.
	DispRedirectResolver Disposition = "redirect-to-ds-dnsgate"
	// DispDropDoT — DoT (tcp/853) dropped (NFT-4).
	DispDropDoT Disposition = "drop-dns-over-tls"
	// DispDenyDoH — DoH to a known resolver denied (NFT-4 + POL-2 baseline blocklist).
	DispDenyDoH Disposition = "deny-known-doh-resolver"
	// DispRejectICMPCounted — QUIC udp/443 rejected with ICMP port-unreachable AND
	// counted per session (D70). NOT a silent drop — that distinction is the row.
	DispRejectICMPCounted Disposition = "reject-icmp-port-unreachable-counted"
	// DispScrubNoWiden — a re-resolution whose answer is sanity-scrubbed and does
	// NOT silently widen the allow-set (DNS-4). The new flow is not admitted off
	// the back of a stale or out-of-range answer.
	DispScrubNoWiden Disposition = "scrub-no-silent-widen"
	// DispSuppressHTTPSSVCB — an HTTPS (type 65) / SVCB query is answered with the
	// record type SUPPRESSED entirely (DNS-4 rule 4): no ECH config and no alpn=h3
	// hint reaches the VM, forcing plaintext-SNI TCP the boundary can see.
	DispSuppressHTTPSSVCB Disposition = "suppress-https-svcb-record"
	// DispRefuseECH — a ClientHello carrying an Encrypted Client Hello extension is
	// refused at the egress gateway (TLS-1): an encrypted inner name would show the
	// boundary only the outer CDN name, reopening the shared-IP hole.
	DispRefuseECH Disposition = "refuse-ech-clienthello"
	// DispNoL2Path — a cross-session reach is denied: there is no L2 path between
	// agent VMs (§2 placement + NFT-1). Session A cannot reach session B.
	DispNoL2Path Disposition = "no-l2-path-between-sessions"
	// DispStripAAAANoData — an AAAA query in the dormant-v6 posture is answered
	// NOERROR/NODATA with the D71-authored SOA (D75): the guest is handed no v6
	// address, never a drop / SERVFAIL.
	DispStripAAAANoData Disposition = "strip-aaaa-noerror-nodata"
	// DispDenyV6Dormant — an IPv6 egress from a VM interface in the dormant-v6
	// posture is denied at the boundary host netns (D75): the host, not the guest
	// sysctl, holds the line, so the closure survives a guest that re-enables v6.
	DispDenyV6Dormant Disposition = "deny-v6-dormant-boundary-host"
)

// ── The model: how the boundary disposes of each attempt ─────────────────────

// Dispose returns the disposition the documented boundary posture produces for
// an attempt. This is the single decision function the offline assertions and
// the live runners both consult, so they can never disagree on a verdict.
//
// It is deliberately small and auditable: each branch cites the doc 09 / doc 11
// / D70 clause it encodes.
func (p Posture) Dispose(a Attempt) Disposition {
	switch a.Kind {

	case AttemptL34Direct:
		// NFT-1 default-drop: a raw L3/4 connect is dropped unless the dest IP is
		// in the session's allow-set (admitted for SOME admitted domain — the
		// Stage-1 interim NFT-3 IP gate). This is the "before the proxy" leg.
		if p.ipAdmittedAnywhere(a.addr()) {
			return DispAllow
		}
		return DispDropL34

	case AttemptProxiedTLS:
		// TLS-1: the SNI's domain must be policy-allowed AND the original-dst IP
		// must be one admitted FOR THAT DOMAIN (closes the shared-CDN-IP hole).
		if p.AdmittedDomains[a.Domain] && p.domainAdmits(a.Domain, a.addr()) {
			return DispAllow
		}
		return DispRefuseProxy

	case AttemptPort53:
		// NFT-4: ALL destination-port-53 traffic lands on ds-dnsgate no matter what
		// IP the VM aimed at (an in-VM `nameserver 8.8.8.8` still resolves through
		// us). The bypass never holds.
		return DispRedirectResolver

	case AttemptDoT:
		// NFT-4: DNS-over-TLS (tcp/853) is dropped.
		return DispDropDoT

	case AttemptDoH:
		// NFT-4 + POL-2: a DoH attempt to a known public DoH resolver domain (D64
		// baseline blocklist) is denied (DNS-3 denial + TLS-1 SNI check). The
		// HTTP-level half on otherwise-allowed hosts is TLS-6 (deferred, not M0).
		if p.DoHResolverDomains[a.Domain] {
			return DispDenyDoH
		}
		// A DoH attempt to a host that is NOT a known resolver is not caught at the
		// baseline-blocklist layer; M0 disposes of it as the generic proxied path
		// (the HTTP-level detection that would catch it is TLS-6, deferred). We do
		// not over-claim here: a non-blocklisted DoH host is refused only if its
		// domain is not admitted — exactly the TLS-1 disposition.
		if p.AdmittedDomains[a.Domain] && p.domainAdmits(a.Domain, a.addr()) {
			return DispAllow
		}
		return DispRefuseProxy

	case AttemptQUIC:
		// D70 / NFT-4: udp/443 is REJECTED with ICMP port-unreachable and COUNTED
		// per session — never silently dropped — to force TCP fallback.
		return DispRejectICMPCounted

	case AttemptReResolve:
		// DNS-4: a re-resolution to a NEW address goes through full admission again.
		// If the new answer is in a scrubbed range (private/link-local/loopback,
		// or an IPv4-mapped/NAT64-embedded v4 that fails the v4 rules), it is never
		// inserted; either way the OLD admission does not silently carry the new
		// flow. The disposition is "scrub, no silent widen".
		return DispScrubNoWiden

	case AttemptSpoofedSource:
		// NFT-2: the prerouting redirect matches on the VM's attachment interface
		// (`iifname`), NEVER on source IP — a forged in-VM source address can't be
		// forged for the attachment point, so the spoof has no effect on the
		// disposition. The attempt is gated exactly as the same unspoofed L3/4
		// connect would be: dropped by NFT-1 default-drop unless the DESTINATION is
		// admitted. (The forged SOURCE never widens what is reachable.)
		if p.ipAdmittedAnywhere(a.addr()) {
			return DispAllow
		}
		return DispDropL34

	case AttemptHTTPSSVCBQuery:
		// DNS-4 rule 4: HTTPS (type 65) / SVCB answers are suppressed entirely. No
		// ECH config and no alpn=h3 hint reaches the VM, forcing plaintext-SNI TCP.
		return DispSuppressHTTPSSVCB

	case AttemptECHHello:
		// TLS-1: an ECH ClientHello is refused — an encrypted inner name would show
		// the boundary only the outer CDN name, reopening the shared-IP hole. The
		// refusal does not depend on the outer-domain admission: even on an admitted
		// CDN IP, ECH is refused so it can never hide a non-admitted inner domain.
		if a.ECH {
			return DispRefuseECH
		}
		// A non-ECH ClientHello on this kind is a malformed fixture; fall through to
		// the TLS-1 admission disposition (fail closed unless the (domain, IP) pair
		// is admitted), so a fixture that drops the ECH flag can never read as allow
		// off this branch.
		if p.AdmittedDomains[a.Domain] && p.domainAdmits(a.Domain, a.addr()) {
			return DispAllow
		}
		return DispRefuseProxy

	case AttemptCrossSession:
		// §2 placement + NFT-1: there is no L2 path between two agent VMs (the proof
		// is structural / flag-audited, never inherited from the inet default-deny
		// ruleset since bridged frames bypass the inet forward chain — D66). Session
		// A's reach toward session B's VM is denied.
		return DispNoL2Path

	case AttemptAAAAQuery:
		// DNS-1 / D75 (v0 dormant-v6 posture): AAAA is stripped and answered
		// NOERROR/NODATA with the D71-authored SOA (never a drop / SERVFAIL), so the
		// guest is handed no v6 address and `allow6` stays dormant.
		return DispStripAAAANoData

	case AttemptV6LinkLocalReach:
		// NFT-1 / D75: an IPv6 egress from a VM interface in the dormant-v6 posture
		// is denied at the BOUNDARY HOST netns — not the guest sysctl — so the
		// closure survives a guest that re-enables v6 (the fe80 sibling-probe row).
		return DispDenyV6Dormant

	default:
		// An unknown attempt kind is itself a failure to disposition — fail closed
		// to the strongest deny so an unmodeled shape can never read as allow.
		return DispDropL34
	}
}

// ipAdmittedAnywhere reports whether ip is admitted for ANY admitted domain (the
// Stage-1 NFT-3 IP set the L3/4 leg gates against). A zero/invalid Addr is never
// admitted.
func (p Posture) ipAdmittedAnywhere(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	for _, ips := range p.Admitted {
		if ips[ip] {
			return true
		}
	}
	return false
}

// domainAdmits reports whether ip is admitted specifically for domain (the
// TLS-1 (domain, IP) pair). A zero/invalid Addr is never admitted.
func (p Posture) domainAdmits(domain string, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	return p.Admitted[domain][ip]
}

// ── The DNS-4 dual-stack sanity scrub (the rebinding defense, rule 2) ────────

// IsScrubbed reports whether addr falls in a range DNS-4 rule (2) refuses to
// admit and always scrubs from answers: for IPv4 — private, link-local,
// loopback; for IPv6 — loopback (::1), link-local (fe80::/10), ULA (fc00::/7),
// and any address with an EMBEDDED IPv4 (IPv4-mapped ::ffff:0:0/96 and NAT64
// 64:ff9b::/96) whose embedded v4 fails the v4 rules. This is the load-bearing
// half of the rebinding row: an approved domain that re-resolves to an internal
// address gains nothing.
//
// (Host/boundary-specific ranges in DNS-4 rule 2 — the gateway's own addresses —
// are deployment state, not a fixed CIDR, so they are asserted by the live half
// against a real boundary, not modeled here. The fixed ranges below are the
// universally-true subset and are sufficient for the M0 synthetic assertions.)
func IsScrubbed(addr netip.Addr) bool {
	if !addr.IsValid() {
		// An unparseable answer is never admitted — fail closed.
		return true
	}
	// Unmap an IPv4-mapped v6 to its embedded v4 so ::ffff:10.0.0.5 is judged by
	// the v4 rules (DNS-4 rule 2: "the embedded address is checked against the
	// IPv4 rules before admission").
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	// NAT64 64:ff9b::/96 embeds an IPv4 in the low 32 bits; check that embedded v4.
	if v4, ok := nat64Embedded(addr); ok {
		addr = v4
	}
	if addr.Is4() {
		return addr.IsPrivate() ||
			addr.IsLoopback() ||
			addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() ||
			addr.IsUnspecified()
	}
	// IPv6 (non-embedded).
	return addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsPrivate() || // ULA fc00::/7
		addr.IsUnspecified()
}

// nat64WellKnown is the NAT64 well-known prefix 64:ff9b::/96.
var nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")

// nat64Embedded returns the embedded IPv4 of a NAT64 64:ff9b::/96 address (the
// low 32 bits), or ok=false if addr is not in that prefix.
func nat64Embedded(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() || !nat64WellKnown.Contains(addr) {
		return netip.Addr{}, false
	}
	b := addr.As16()
	v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	return v4, true
}

// ── Loading synthetic fixtures (cwd-independent) ─────────────────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored),
// so fixture lookups work under `go test` from any cwd — the same technique the
// appinstall / resolverlock corpora use.
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// Fixture is one synthetic egress-attempt fixture: the attempt plus the
// disposition the docs REQUIRE for it. The offline test diffs the modeled
// disposition against Want.
type Fixture struct {
	Attempt
	// Want is the disposition the boundary must produce. A mismatch between the
	// model and Want is a failure — either the model drifted from the docs or the
	// fixture's required disposition is wrong.
	Want Disposition `json:"want"`
	// Row names which M0 row this fixture seeds (for coverage assertions).
	Row Row `json:"row"`
}

// LoadFixture reads a synthetic egress-attempt fixture from a JSON file and
// labels the attempt with the file's base name for assertion messages.
func LoadFixture(path string) (Fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, fmt.Errorf("reading egress-attempt fixture %s: %w", path, err)
	}
	var f Fixture
	if err := json.Unmarshal(data, &f); err != nil {
		return Fixture{}, fmt.Errorf("parsing egress-attempt fixture %s: %w", path, err)
	}
	f.Attempt.Name = filepath.Base(path)
	if f.Kind == "" {
		return Fixture{}, fmt.Errorf("egress-attempt fixture %s declares no kind", path)
	}
	if f.Want == "" {
		return Fixture{}, fmt.Errorf("egress-attempt fixture %s declares no want disposition", path)
	}
	if f.Row == "" {
		return Fixture{}, fmt.Errorf("egress-attempt fixture %s declares no M0 row", path)
	}
	return f, nil
}

// LoadFixtures loads every *.json fixture under FixturesDir in stable filename
// order. The `.provenance` sidecars and PROVENANCE.md are ignored.
func LoadFixtures() ([]Fixture, error) {
	dir := FixturesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading fixtures dir %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Fixture
	for _, n := range names {
		f, err := LoadFixture(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// ── Row → owning step (doc 09 §9), the coverage anchor ───────────────────────

// RowOwners maps each M0 row to the doc 09 §9 boundary step(s) that own it. The
// suite asserts the M0 row set here matches the rows the fixtures seed, so a row
// can never be silently dropped from the table.
func RowOwners() map[Row][]Step {
	return map[Row][]Step{
		RowDefaultDeny:    {StepNFT1, StepTLS1},
		RowRebinding:      {StepDNS4, StepNFT3},
		RowDoHDoTBypass:   {StepNFT4, StepPOL2},
		RowPort53Redirect: {StepNFT4},
		RowQUICReject:     {StepNFT4},
	}
}

// BandCRowOwners maps the REMAINING doc 06 §3c / doc 09 §9 boundary (c) rows
// (the four this band added beyond the M0 seed set) to their owning §9 steps.
// It is kept separate from RowOwners() because the M0 rows additionally carry a
// scaffolded live runner (live_test.go); these rows are offline spec-vs-model
// checks whose live wiring is a later step, so they are owned and coverage-
// asserted here without a per-row live-runner obligation. The suite asserts this
// table's rows are exactly the rows the band-c fixtures seed and that every owner
// is a real §9 step.
func BandCRowOwners() map[Row][]Step {
	return map[Row][]Step{
		RowInterfaceMatch:     {StepNFT2},
		RowECHSVCBSuppression: {StepDNS4, StepTLS1},
		RowSessionIsolation:   {StepSeg2, StepNFT1},
		RowIPv6Closure:        {StepNFT1, StepDNS4},
	}
}

// AllRowOwners is the union of the M0 seed rows (RowOwners) and the band-c rows
// (BandCRowOwners) — the full set of doc 06 §3c / doc 09 §9 (c) rows this package
// models. Fixture-coverage assertions diff every loaded fixture's row against
// this union, so a fixture can name any modeled row but never an unmodeled one.
func AllRowOwners() map[Row][]Step {
	out := map[Row][]Step{}
	for r, s := range RowOwners() {
		out[r] = s
	}
	for r, s := range BandCRowOwners() {
		out[r] = s
	}
	return out
}
