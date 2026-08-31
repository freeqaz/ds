// SPDX-License-Identifier: Apache-2.0

package resolverhardening

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// resolverhardening models the D42 "resolver hardening holds as a unit" (c) row
// (doc.go states the claim, its nine clauses, and their anchors). The whole row
// is modeled as ONE Decide function (DisposeResolution) over a synthetic
// resolution attempt, with a per-clause ViolationClass taxonomy so a single
// regression in any clause "fails NAMED". Everything is SYNTHETIC (D50): Go-literal
// inputs the test builds, never a live ds-dnsgate / ds-tlsproxy / NFTables / VM /
// KVM / podman run.
//
// The doc 06 §3c language note is binding here: nothing is named attack /
// redteam / intrusion. Every check is phrased as "the guardrail HOLDS, and this
// is the named way a regression would let it slip."

// ── Single-sourced guardrail tag (doc.go REGISTRATION; guardrail-map.yaml) ──
//
// Tag is the single doc 06 §3c <domain>-conformance tag this row carries. It is
// the SINGLE SOURCE for the row name: the repo-root guardrail-map.yaml's
// resolverhardening glob row (at the first per-claim seeding) must name this SAME
// tag, and TestTagStable pins it so a silent drift fails HERE rather than against
// a differently-named map row. guardrail-map.yaml is never edited from this
// package (a new unmapped subdir self-gates fail-closed, D47; the map is
// Boundary-owned). It is NOT written into the map here.
const Tag = "resolver-hardening-holds-as-unit"

// ── The documented clamp window (the FLOOR/CEIL the docs fix) ───────────────

// FloorTTLSeconds and CeilTTLSeconds are the v0 per-session allow-set TTL clamp
// bounds the docs fix: FLOOR=60s, CEIL=900s (15 min) (doc 11 §3 W2, doc 20 §4
// claim 1, D42/D68). They live in the POL-1 schema (tunable per push); these
// restate the v0 defaults so a clause-9 / clause-7 check has a concrete window,
// and TestClampWindowMatchesDocumentedCadence pins them to the documented values
// (the goldenfreshness/orchctl anchor-guard discipline).
const (
	FloorTTLSeconds = 60  // 60 s floor (D42)
	CeilTTLSeconds  = 900 // 900 s = 15 min cap (D42)
)

// ClampTTL applies the W2 clamp to an upstream chain-min TTL: the VM is answered
// clamp(ttl, FLOOR, CEIL). (The kernel/map deadline additionally adds GRACE; the
// VM-facing answer is the clamped value without grace — W2.)
func ClampTTL(upstreamTTLSeconds int) int {
	if upstreamTTLSeconds < FloorTTLSeconds {
		return FloorTTLSeconds
	}
	if upstreamTTLSeconds > CeilTTLSeconds {
		return CeilTTLSeconds
	}
	return upstreamTTLSeconds
}

// ── Per-clause violation taxonomy (the nine D42 clauses) ─────────────────────

// ViolationClass names a single clause of the D42 resolver-hardening unit that a
// regression tripped, so the row "fails NAMED" rather than with a bare boolean.
type ViolationClass string

const (
	// ClauseSoleResolutionPath — clause (1): port-53 traffic did NOT land on
	// ds-dnsgate (a foreign resolver answered); the sole-resolution-path bypass held.
	ClauseSoleResolutionPath ViolationClass = "sole-resolution-path-bypassed"
	// ClauseDoTDropped — clause (2): DNS-over-TLS (tcp/853) was not dropped.
	ClauseDoTDropped ViolationClass = "dot-not-dropped"
	// ClauseDoHBlocked — clause (3): a known public DoH resolver domain was not
	// blocked at L3+L7 (the baseline-blocklist denial did not fire).
	ClauseDoHBlocked ViolationClass = "doh-known-resolver-not-blocked"
	// ClauseBypassAttemptCounted — clause (4): a foreign-resolver bypass attempt was
	// not counted per session (the NFT-5 counter + nflog rule did not increment).
	ClauseBypassAttemptCounted ViolationClass = "foreign-resolver-bypass-not-counted"
	// ClauseECHStripped — clause (5): an HTTPS/SVCB answer carrying ECH params was
	// delivered to the VM instead of suppressed (the ECH configs were not stripped).
	ClauseECHStripped ViolationClass = "ech-params-not-stripped"
	// ClausePrivateRangeNotAdmitted — clause (6): a private/internal-range answer was
	// admitted instead of scrubbed by the W5 dual-stack sanity filter.
	ClausePrivateRangeNotAdmitted ViolationClass = "private-range-answer-admitted"
	// ClauseTTLClamp — clause (7): the per-session allow-set TTL was not clamped to
	// the [60s, 900s] window (it escaped the floor or the cap).
	ClauseTTLClamp ViolationClass = "ttl-not-clamped-to-window"
	// ClauseReResolveWidened — clause (7, no-silent-widen half): a re-resolution
	// silently widened the allow-set (a new answer was admitted without going through
	// full admission / sanity scrub).
	ClauseReResolveWidened ViolationClass = "re-resolution-silently-widened"
	// ClauseQUICRejectCounted — clause (8): udp/443 (QUIC) was silently dropped rather
	// than REJECTED with ICMP port-unreachable and counted per session (D70).
	ClauseQUICRejectCounted ViolationClass = "quic-silently-dropped-not-rejected"
	// ClauseSNICrossCheck — clause (9): the SNI↔admitted-IP cross-check did not hold
	// (a domain was admitted on an IP not admitted FOR THAT DOMAIN — the shared-CDN-IP hole).
	ClauseSNICrossCheck ViolationClass = "sni-admitted-ip-cross-check-failed"
)

// Violation is a single clause breach: which clause, which subject (the resolver /
// domain / address / session the check ran against), and a human-readable reason
// citing the governing anchor.
type Violation struct {
	Class   ViolationClass
	Subject string
	Reason  string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Subject, v.Reason)
}

// sortViolations orders a slice by (class, subject) so failure messages and
// class-set comparisons are stable across runs.
func sortViolations(vs []Violation) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Subject < vs[j].Subject
	})
}

// ── The W5 / DNS-4 dual-stack sanity scrub (clause 6, a pure function) ───────

// IsPrivateRange reports whether addr falls in a range the W5 / DNS-4 dual-stack
// sanity filter refuses to admit and always scrubs from answers: for IPv4 —
// private, link-local, loopback, unspecified; for IPv6 — loopback (::1),
// link-local (fe80::/10), ULA (fc00::/7), unspecified, and any address with an
// EMBEDDED IPv4 (IPv4-mapped ::ffff:0:0/96 and NAT64 64:ff9b::/96) whose embedded
// v4 fails the v4 rules — so an approved domain answering ::ffff:10.0.0.5 gains
// nothing (doc 11 W5, DNS-4 rule 2, D42).
//
// (Host/boundary-specific ranges in DNS-4 rule 2 — the gateway's own addresses —
// are deployment state, not a fixed CIDR, so they are asserted by the live half
// against a real boundary, not modeled here. The fixed ranges below are the
// universally-true subset, sufficient for the synthetic assertions; the same
// split the nftgate IsScrubbed sibling makes.)
func IsPrivateRange(addr netip.Addr) bool {
	if !addr.IsValid() {
		// An unparseable answer is never admitted — fail closed.
		return true
	}
	// Unmap an IPv4-mapped v6 to its embedded v4 so ::ffff:10.0.0.5 is judged by the
	// v4 rules (DNS-4 rule 2: the embedded address is checked against the IPv4 rules).
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

// ── The synthetic resolution attempt (the fixture) ──────────────────────────

// Transport is the resolution transport a VM attempted.
type Transport string

const (
	// TransportPlain53 — plain DNS on udp/tcp 53 (the only path that should reach a
	// resolver, via the redirect onto ds-dnsgate).
	TransportPlain53 Transport = "plain-dns-53"
	// TransportDoT — DNS-over-TLS on tcp/853 (must be dropped).
	TransportDoT Transport = "dns-over-tls-853"
	// TransportDoH — DNS-over-HTTPS to a resolver domain (blocked when the domain is a
	// known public DoH resolver).
	TransportDoH Transport = "dns-over-https"
)

// RecordType is a DNS record type relevant to the ECH-stripping clause.
type RecordType string

const (
	RecordA     RecordType = "A"     // ordinary v4 address
	RecordHTTPS RecordType = "HTTPS" // type 65 — must be suppressed (ECH params stripped)
	RecordSVCB  RecordType = "SVCB"  // type 64 — must be suppressed
)

// Posture is the small auditable model of the documented resolver posture the
// clauses are asserted against. It is NOT live state: it is the spec read of the
// frozen plan, so the offline assertions can run anywhere with no data plane.
type Posture struct {
	// OurResolvers is the set of addresses that ARE ds-dnsgate (the sole resolution
	// path). Any port-53 traffic, no matter what IP the VM aimed at, must land here.
	OurResolvers map[netip.Addr]bool
	// DoHResolverDomains is the D64 POL-2 baseline blocklist of known public DoH
	// resolver domains.
	DoHResolverDomains map[string]bool
	// AdmittedDomains is the policy-allowed domain set (TLS-1 SNI admission).
	AdmittedDomains map[string]bool
	// Admitted is the per-(domain) set of admitted addresses (the DNS-2b map / NFT-3
	// set). An IP admitted for one domain does not admit another (the shared-CDN-IP hole).
	Admitted map[string]map[netip.Addr]bool
}

// ResolutionAttempt is one synthetic resolution / connection attempt the VM (treated
// as untrusted) makes. The fields populated depend on the clause under test.
type ResolutionAttempt struct {
	// Name labels the attempt for assertion messages.
	Name string
	// Transport is the resolution transport (plain-53 / DoT / DoH).
	Transport Transport
	// AimedResolver is the IP the VM aimed its port-53 / DoT traffic at (may be a
	// foreign resolver like 8.8.8.8 — it must still land on ds-dnsgate).
	AimedResolver string
	// Domain is the DoH resolver domain (DoH) or the SNI domain (clause 9) or the
	// re-resolved name (clause 7).
	Domain string
	// RecordType is the record type queried/answered (clause 5).
	RecordType RecordType
	// Answer is an address the resolver returned (clause 6 / clause 7).
	Answer string
	// OriginalDst is the original-destination IP a TLS connection aimed at (clause 9).
	OriginalDst string
	// UpstreamTTLSeconds is the upstream chain-min TTL (clause 7 clamp input).
	UpstreamTTLSeconds int
	// QUIC marks a udp/443 attempt (clause 8).
	QUIC bool
}

// addr parses s into a netip.Addr, returning the zero Addr (invalid) on failure.
func addr(s string) netip.Addr {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}
	}
	return ip
}

// ── The unit decision functions (one per clause; the model the live half reuses) ──

// LandsOnOurResolver reports whether a port-53 / DoT attempt aimed at AimedResolver
// lands on ds-dnsgate. In the documented posture the answer is ALWAYS true (NFT-4
// redirects all port-53 regardless of aimed IP) — the model returns the documented
// disposition, and a fixture that records a foreign resolver answering instead is
// what trips clause 1.
func (p Posture) LandsOnOurResolver(_ ResolutionAttempt) bool { return true }

// DomainAdmitsIP reports whether ip is admitted specifically for domain (the TLS-1
// (domain, IP) pair; clause 9). A zero/invalid Addr is never admitted.
func (p Posture) DomainAdmitsIP(domain string, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	return p.Admitted[domain][ip]
}

// ── Check: the whole D42 unit, clause by clause ──────────────────────────────

// Observation is what the boundary actually did with a resolution attempt — the
// observed half the synthetic fixture pairs with the attempt. Each field is the
// observation a clause checks against the documented disposition.
type Observation struct {
	// LandedOnDsDnsgate records whether the port-53/DoT traffic actually landed on
	// ds-dnsgate (clause 1: must be true regardless of AimedResolver).
	LandedOnDsDnsgate bool
	// DoTDropped records whether a DoT (tcp/853) attempt was dropped (clause 2).
	DoTDropped bool
	// DoHDenied records whether a DoH attempt to a known resolver domain was denied
	// (clause 3).
	DoHDenied bool
	// BypassAttemptCounted records whether a foreign-resolver bypass attempt was
	// counted per session (clause 4).
	BypassAttemptCounted bool
	// RecordDelivered records whether an HTTPS/SVCB record was delivered to the VM
	// (clause 5: must be false — suppressed).
	RecordDelivered bool
	// AnswerAdmitted records whether the resolver admitted the Answer address
	// (clause 6: a private-range answer must NOT be admitted).
	AnswerAdmitted bool
	// AnsweredTTLSeconds records the TTL the VM was answered (clause 7 clamp).
	AnsweredTTLSeconds int
	// ReResolveWentThroughAdmission records whether a re-resolution went through full
	// admission (sanity scrub + insert) rather than silently widening (clause 7).
	ReResolveWentThroughAdmission bool
	// QUICRejectedWithICMP records whether udp/443 was rejected with ICMP
	// port-unreachable (clause 8: must be true, never a silent drop).
	QUICRejectedWithICMP bool
	// QUICCounted records whether the udp/443 reject was counted per session (clause 8).
	QUICCounted bool
	// TLSAdmitted records whether a TLS connection was admitted (clause 9).
	TLSAdmitted bool
}

// CheckUnit asserts the whole D42 resolver-hardening unit for one (attempt,
// observation) pair, returning every NAMED clause a regression tripped. An empty
// result means the unit held for this attempt. The decision is keyed on the
// attempt's Transport / RecordType / QUIC fields so each clause is exercised by
// the attempt shape that triggers it.
func (p Posture) CheckUnit(a ResolutionAttempt, o Observation) []Violation {
	var vs []Violation
	subject := a.Name

	switch {
	case a.QUIC:
		// Clause 8 — udp/443 REJECTED + counted, never silently dropped (D70).
		if !o.QUICRejectedWithICMP {
			vs = append(vs, Violation{
				Class:   ClauseQUICRejectCounted,
				Subject: subject,
				Reason: "udp/443 (QUIC) was silently dropped, not REJECTED with ICMP port-unreachable; " +
					"D70 amends NFT-4 to reject-not-drop and count per session, to force the TCP " +
					"fallback the proxy can see (doc 20 §4 claim 1, doc 11 §3.3, D70)",
			})
		}
		if o.QUICRejectedWithICMP && !o.QUICCounted {
			vs = append(vs, Violation{
				Class:   ClauseQUICRejectCounted,
				Subject: subject,
				Reason: "udp/443 (QUIC) was rejected but NOT counted per session; D70 requires the " +
					"reject be counted into LOG-1 with a quic-blocked reason code — a reject without " +
					"the count loses the bypass-attempt visibility (doc 20 §4 claim 1, D70)",
			})
		}

	case a.Transport == TransportDoT:
		// Clause 2 — DoT (tcp/853) dropped; clause 4 — bypass attempt counted.
		if !o.DoTDropped {
			vs = append(vs, Violation{
				Class:   ClauseDoTDropped,
				Subject: subject,
				Reason: "a DNS-over-TLS attempt (tcp/853) was not dropped; NFT-4 drops DoT so all " +
					"resolution is forced through our resolver (doc 20 §4 claim 1, doc 09 §3 NFT-4)",
			})
		}
		if !o.BypassAttemptCounted {
			vs = append(vs, Violation{
				Class:   ClauseBypassAttemptCounted,
				Subject: subject,
				Reason: "a foreign-resolver bypass attempt (DoT) was not counted per session; the " +
					"frozen NFT-5 counter + nflog rule counts bypass *attempts* so they are visible " +
					"in the flow ledger, never silent (doc 20 §3.1, D69/D42)",
			})
		}

	case a.Transport == TransportDoH:
		// Clause 3 — known DoH resolver domain blocked at L3+L7; clause 4 — counted.
		if p.DoHResolverDomains[a.Domain] {
			if !o.DoHDenied {
				vs = append(vs, Violation{
					Class:   ClauseDoHBlocked,
					Subject: subject,
					Reason: fmt.Sprintf("a DoH attempt to known public resolver domain %q was not "+
						"denied; known DoH resolver domains ship in the D64 baseline blocklist (POL-2), "+
						"enforced by DNS-3 denial (L7) and the L3 closure (doc 20 §4 claim 1, doc 09 §3 "+
						"NFT-4, doc 11 §6)", a.Domain),
				})
			}
			if !o.BypassAttemptCounted {
				vs = append(vs, Violation{
					Class:   ClauseBypassAttemptCounted,
					Subject: subject,
					Reason: fmt.Sprintf("a foreign-resolver bypass attempt (DoH to %q) was not counted "+
						"per session; the NFT-5 counter + nflog rule counts bypass attempts so they are "+
						"visible in the flow ledger (doc 20 §3.1, D69/D42)", a.Domain),
				})
			}
		}

	case a.Transport == TransportPlain53:
		// Clause 1 — sole resolution path: lands on ds-dnsgate regardless of aimed IP.
		if !o.LandedOnDsDnsgate {
			vs = append(vs, Violation{
				Class:   ClauseSoleResolutionPath,
				Subject: subject,
				Reason: fmt.Sprintf("port-53 traffic aimed at %q did NOT land on ds-dnsgate (a foreign "+
					"resolver answered); NFT-4 redirects ALL destination-port-53 traffic onto ds-dnsgate "+
					"no matter what IP the VM aimed at — an in-VM `nameserver 8.8.8.8` still resolves "+
					"through us (doc 20 §3.1, doc 09 §3 NFT-4)", a.AimedResolver),
			})
		}
		// If the VM aimed at a foreign (non-our) resolver, that is a bypass attempt and
		// must be counted (clause 4).
		if ar := addr(a.AimedResolver); ar.IsValid() && !p.OurResolvers[ar] {
			if !o.BypassAttemptCounted {
				vs = append(vs, Violation{
					Class:   ClauseBypassAttemptCounted,
					Subject: subject,
					Reason: fmt.Sprintf("a foreign-resolver bypass attempt (port-53 aimed at %q, not one "+
						"of our resolvers) was not counted per session; the frozen NFT-5 counter + nflog "+
						"rule counts bypass attempts (doc 20 §3.1, D69/D42)", a.AimedResolver),
				})
			}
		}
	}

	// Clause 5 — ECH params stripped: an HTTPS/SVCB answer must not be delivered.
	if a.RecordType == RecordHTTPS || a.RecordType == RecordSVCB {
		if o.RecordDelivered {
			vs = append(vs, Violation{
				Class:   ClauseECHStripped,
				Subject: subject,
				Reason: fmt.Sprintf("a %s record was delivered to the VM with its ECH params intact; "+
					"DNS-4 rule 4 suppresses HTTPS (type 65) / SVCB (type 64) answers, stripping the ECH "+
					"configs that would let a client encrypt the inner server name and defeat the TLS-1 "+
					"SNI check (doc 20 §4 claim 1, doc 11 §3.3)", a.RecordType),
			})
		}
	}

	// Clause 6 — private-range answers never admitted (the W5 dual-stack scrub).
	if ans := addr(a.Answer); ans.IsValid() {
		if IsPrivateRange(ans) && o.AnswerAdmitted {
			vs = append(vs, Violation{
				Class:   ClausePrivateRangeNotAdmitted,
				Subject: subject,
				Reason: fmt.Sprintf("a private/internal-range answer %q was admitted; the W5 dual-stack "+
					"sanity filter scrubs private / link-local / loopback / embedded-IPv4 answers ahead "+
					"of every insert — an approved domain re-resolving to an internal address gains "+
					"nothing (doc 20 §4 claim 1, doc 11 W5, DNS-4 rule 2, D42)", a.Answer),
			})
		}
	}

	// Clause 7 — TTL clamped to [FLOOR, CEIL]; re-resolution never silently widens.
	if a.UpstreamTTLSeconds > 0 {
		want := ClampTTL(a.UpstreamTTLSeconds)
		if o.AnsweredTTLSeconds != want {
			vs = append(vs, Violation{
				Class:   ClauseTTLClamp,
				Subject: subject,
				Reason: fmt.Sprintf("the answered TTL %ds is not the clamped value %ds for upstream "+
					"%ds; per-session allow-set TTLs are clamped to [%ds floor, %ds cap] (doc 20 §4 "+
					"claim 1, doc 11 W2, D42/D68)", o.AnsweredTTLSeconds, want, a.UpstreamTTLSeconds,
					FloorTTLSeconds, CeilTTLSeconds),
			})
		}
	}

	sortViolations(vs)
	return vs
}

// CheckReResolve asserts the no-silent-widen half of clause 7 for a re-resolution:
// a new answer is admitted only if it went through full admission (sanity scrub +
// insert), never silently widening the set. A re-resolution to a private-range
// address that was admitted without the scrub trips both clause 7 (widen) and
// clause 6 (private-range) — both NAMED.
func (p Posture) CheckReResolve(a ResolutionAttempt, o Observation) []Violation {
	var vs []Violation
	subject := a.Name

	if o.AnswerAdmitted && !o.ReResolveWentThroughAdmission {
		vs = append(vs, Violation{
			Class:   ClauseReResolveWidened,
			Subject: subject,
			Reason: fmt.Sprintf("a re-resolution of %q admitted a new answer %q without going through "+
				"full admission (sanity scrub + insert); DNS-4 rule 3 sends re-resolutions through full "+
				"admission again rather than silently widening the set (doc 20 §4 claim 1, doc 11 W3, "+
				"DNS-4 rule 3, D42)", a.Domain, a.Answer),
		})
	}
	if ans := addr(a.Answer); ans.IsValid() && IsPrivateRange(ans) && o.AnswerAdmitted {
		vs = append(vs, Violation{
			Class:   ClausePrivateRangeNotAdmitted,
			Subject: subject,
			Reason: fmt.Sprintf("a re-resolution of %q admitted private-range answer %q; the W5 scrub "+
				"refuses it on re-admission too — re-resolution to an internal address never widens the "+
				"set (doc 20 §4 claim 1, doc 11 W5, DNS-4 rule 2/3, D42)", a.Domain, a.Answer),
		})
	}
	sortViolations(vs)
	return vs
}

// CheckSNICrossCheck asserts clause 9 for a TLS connection: it is admitted only
// when the SNI's domain is policy-allowed AND the original-destination IP is one
// admitted FOR THAT DOMAIN (closing the shared-CDN-IP hole). An admission on an IP
// not admitted for the domain trips the clause.
func (p Posture) CheckSNICrossCheck(a ResolutionAttempt, o Observation) []Violation {
	var vs []Violation
	subject := a.Name

	dst := addr(a.OriginalDst)
	shouldAdmit := p.AdmittedDomains[a.Domain] && p.DomainAdmitsIP(a.Domain, dst)

	if o.TLSAdmitted && !shouldAdmit {
		vs = append(vs, Violation{
			Class:   ClauseSNICrossCheck,
			Subject: subject,
			Reason: fmt.Sprintf("a TLS connection for SNI %q to original-dst %q was admitted, but that "+
				"IP is not admitted FOR THAT DOMAIN; TLS-1 cross-checks the SNI domain against the "+
				"DNS-2b admission map per domain — an IP admitted for some OTHER domain on a shared CDN "+
				"must not admit this one (doc 20 §4 claim 1, doc 03 OQ1, D42)", a.Domain, a.OriginalDst),
		})
	}
	sortViolations(vs)
	return vs
}

// Clauses is the ordered set of all nine D42 clause classes the unit enumerates,
// for the coverage gate to assert every clause is exercised.
func Clauses() []ViolationClass {
	return []ViolationClass{
		ClauseSoleResolutionPath,
		ClauseDoTDropped,
		ClauseDoHBlocked,
		ClauseBypassAttemptCounted,
		ClauseECHStripped,
		ClausePrivateRangeNotAdmitted,
		ClauseTTLClamp,
		ClauseReResolveWidened,
		ClauseQUICRejectCounted,
		ClauseSNICrossCheck,
	}
}
