// SPDX-License-Identifier: Apache-2.0

package netisolation

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// netisolation models the doc 06 §3c Stage-2 network-isolation (c) rows
// (doc.go states the claims and their anchors). Each row below is a small,
// deterministic Check over a SYNTHETIC fixture (D50) — Go-literal inputs the test
// builds, never a live VM / NFTables ruleset / ds-dnsgate / ds-tlsproxy / KVM /
// podman run. The shape mirrors the orchctl sibling: a typed fixture + a typed
// violation taxonomy + a pure Check returning every NAMED violation.
//
// The doc 06 §3c language note is binding here: nothing is named attack /
// redteam / intrusion. Every check is phrased as "the guardrail HOLDS, and this
// is the named way a regression would let it slip."

// ── Single-sourced guardrail tags (doc.go REGISTRATION; guardrail-map.yaml) ──
//
// The five doc 06 §3c <domain>-conformance tags this package's rows carry, in the
// doc.go REGISTRATION order. Tags is the SINGLE SOURCE for the row names: the
// repo-root guardrail-map.yaml's netisolation glob row (at the first per-claim
// seeding) and this slice must name the SAME rows, and TestTagsStable pins the
// slice so a silent drift fails HERE rather than against a differently-named map
// row. guardrail-map.yaml is never edited from this package (a new unmapped
// subdir self-gates fail-closed, D47; the map is Boundary-owned).
const (
	// TagInVMSpoofingFails — row (1) in-VM IP-spoofing fails / interface-match (NFT-2).
	TagInVMSpoofingFails = "netiso-in-vm-spoofing-fails"
	// TagECHHTTPSSVCBSuppression — row (2) ECH / HTTPS-SVCB suppression (D68/D75).
	TagECHHTTPSSVCBSuppression = "netiso-ech-https-svcb-suppression"
	// TagSessionANotBNoL2Path — row (3) session A ↛ B isolation / no-L2-path (D66).
	TagSessionANotBNoL2Path = "netiso-session-a-not-b-no-l2-path"
	// TagIPv6ClosureDormantFe80Probe — row (4) IPv6 closure holds while dormant + fe80 probe (D75).
	TagIPv6ClosureDormantFe80Probe = "netiso-ipv6-closure-dormant-fe80-probe"
	// TagControlsUnreachableFromVM — row (5) controls unreachable from the VM (doc 04 §5).
	TagControlsUnreachableFromVM = "netiso-controls-unreachable-from-vm"
)

// Tags is the ordered set of single-sourced guardrail tags this package owns or
// co-owns, for the guardrail-map.yaml netisolation row to name the SAME rows.
var Tags = []string{
	TagInVMSpoofingFails,
	TagECHHTTPSSVCBSuppression,
	TagSessionANotBNoL2Path,
	TagIPv6ClosureDormantFe80Probe,
	TagControlsUnreachableFromVM,
}

// ── Shared violation type ───────────────────────────────────────────────────

// ViolationClass names a single failure mode one of the five rows enumerates, so
// every violation reports WHICH rule it tripped (the "fails NAMED" bar). The
// constants are grouped per row below.
type ViolationClass string

// Violation is a single guardrail breach: which rule, which subject (the
// session / tap / domain / probe the check ran against), and a human-readable
// reason citing the governing anchor.
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

// ────────────────────────────────────────────────────────────────────────────
// ROW 1 — in-VM IP-spoofing fails / interface-match (doc 06 §3c "In-VM IP
//         spoofing fails"; doc 09 §9 NFT-2; doc 03 §3; D44 three-keys, D69).
//
// THE CLAIM: the prerouting redirect and the per-session attribution key match on
// the INTERFACE the VM is attached to (`iifname` / the `dstap-<idx>` tap), never
// on source IP — addresses can be forged from inside the VM, the attachment point
// cannot. So the disposition of a packet turns on the arrival interface; a forged
// source address does not escape the interface-matched redirect. D44's
// three-keys-must-agree rule (iif / assigned guest IP / ct mark) is the
// structural backstop: a disagreement is a kernel drop, never an honored claim.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationSpoofMatchedOnSourceIP — the redirect/attribution matched on the
	// CLAIMED source IP rather than the arrival interface; a forged source address
	// would then steer the disposition (the bug NFT-2's `iifname` match exists to
	// prevent).
	ViolationSpoofMatchedOnSourceIP ViolationClass = "spoof-matched-on-source-ip"
	// ViolationSpoofForgedSrcEscapedRedirect — a packet on an agent tap with a
	// forged source IP escaped the interface-matched redirect (it was NOT redirected
	// to the boundary); the forge bought an egress path.
	ViolationSpoofForgedSrcEscapedRedirect ViolationClass = "spoof-forged-source-escaped-redirect"
	// ViolationSpoofThreeKeysDisagreeNotDropped — the three-keys (iif / assigned
	// guest IP / ct mark) disagreed but the packet was NOT dropped; D44/D69 make a
	// disagreement a kernel drop, never an honored claim.
	ViolationSpoofThreeKeysDisagreeNotDropped ViolationClass = "spoof-three-keys-disagree-not-dropped"
)

// SpoofProbe is a synthetic fixture: a packet arriving on an agent tap with a
// possibly-forged source IP, plus what the boundary actually did with it.
type SpoofProbe struct {
	// Tap is the per-session interface the packet arrived on (`dstap-<idx>`), the
	// frozen NFT-2 attribution key.
	Tap string
	// ClaimedSrc is the source address inside the packet — possibly forged.
	ClaimedSrc string
	// AssignedGuestIP is the address actually assigned to this tap's guest (the
	// D44 second key); a ClaimedSrc != AssignedGuestIP packet is a forge.
	AssignedGuestIP string
	// CtMarkMatchesSession records whether the packet's ct mark matched the session
	// the tap belongs to (the D44 third key).
	CtMarkMatchesSession bool
	// MatchedOnInterface records whether the boundary disposed of the packet by
	// matching the ARRIVAL INTERFACE (the NFT-2 `iifname` rule). False means it
	// matched the claimed source IP — the regression.
	MatchedOnInterface bool
	// RedirectedToBoundary records whether the packet was redirected to the
	// boundary (ds-dnsgate / ds-tlsproxy) as the interface match requires.
	RedirectedToBoundary bool
	// Dropped records whether the packet was dropped (e.g. on a three-keys
	// disagreement).
	Dropped bool
}

// forged reports whether the claimed source differs from the tap's assigned guest
// IP (a forge attempt). A malformed/empty ClaimedSrc is treated as a forge.
func (p SpoofProbe) forged() bool {
	c, err := netip.ParseAddr(strings.TrimSpace(p.ClaimedSrc))
	if err != nil {
		return true
	}
	a, err := netip.ParseAddr(strings.TrimSpace(p.AssignedGuestIP))
	if err != nil {
		return true
	}
	return c != a
}

// threeKeysAgree reports whether the D44 three keys agree: the claimed source
// matches the tap's assigned guest IP AND the ct mark matches the session.
func (p SpoofProbe) threeKeysAgree() bool {
	return !p.forged() && p.CtMarkMatchesSession
}

// CheckInVMSpoofing asserts the interface-match guardrail for one probe: the
// disposition matched on the arrival interface (not the source IP), a forged
// source did not escape the redirect, and a three-keys disagreement was dropped.
func CheckInVMSpoofing(p SpoofProbe) []Violation {
	var vs []Violation

	if !p.MatchedOnInterface {
		vs = append(vs, Violation{
			Class:   ViolationSpoofMatchedOnSourceIP,
			Subject: p.Tap,
			Reason: "the redirect/attribution matched on the CLAIMED source IP rather than the " +
				"arrival interface; NFT-2 matches `iifname` (the per-session tap) never source IP, " +
				"because addresses can be forged from inside the VM and the attachment point cannot " +
				"(doc 09 §9 NFT-2, doc 03 §3, D69)",
		})
	}

	// A three-keys disagreement (forged source, or a ct mark that does not match the
	// session) must be a kernel drop (D44/D69). If it was not dropped, the boundary
	// honored a claim it must have rejected.
	if !p.threeKeysAgree() && !p.Dropped {
		vs = append(vs, Violation{
			Class:   ViolationSpoofThreeKeysDisagreeNotDropped,
			Subject: p.Tap,
			Reason: "the three keys (iif / assigned guest IP / ct mark) disagreed but the packet " +
				"was not dropped; D44's three-keys-must-agree rule makes a disagreement a kernel " +
				"drop, never an honored claim (doc 09 §9 NFT-2, D44/D69)",
		})
	}

	// The headline property: a forged-source packet on an agent tap must NOT have
	// escaped the interface-matched redirect (it is redirected to the boundary or
	// dropped, never routed out on the forged claim).
	if p.forged() && p.RedirectedToBoundary == false && !p.Dropped {
		vs = append(vs, Violation{
			Class:   ViolationSpoofForgedSrcEscapedRedirect,
			Subject: p.Tap,
			Reason: fmt.Sprintf("a packet on agent tap %q with a forged source %q (assigned guest "+
				"IP is %q) escaped the interface-matched redirect — it was neither redirected to "+
				"the boundary nor dropped; forging a source address must not buy an egress path "+
				"(doc 09 §9 NFT-2, doc 03 §3)", p.Tap, p.ClaimedSrc, p.AssignedGuestIP),
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 2 — ECH / HTTPS-SVCB suppression (doc 06 §3c "ECH / HTTPS-SVCB
//         suppression"; doc 09 §9 DNS-4 + TLS-1; doc 11 §3.3; D68/D75).
//
// THE CLAIM: no HTTPS (type 65) or SVCB (type 64) answer reaches a VM —
// suppressed entirely, an explicit type-65 query returns NODATA with an authored
// SOA — and ECH cannot hide a non-admitted domain behind an admitted IP. DNS-4
// rule 4 removes the records that advertise real ECH configs (so what remains is
// browser GREASE), and TLS-1 refuses an ECH ClientHello, forcing plaintext-SNI
// TCP — exactly the path the boundary can see.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationHTTPSSVCBReachedVM — an HTTPS (type 65) or SVCB (type 64) record was
	// delivered to the VM instead of being suppressed; the record advertises ECH
	// configs (defeating the SNI check) and alpn=h3 (steering at the QUIC we drop).
	ViolationHTTPSSVCBReachedVM ViolationClass = "https-svcb-record-reached-vm"
	// ViolationTypeQuerySVCBNotNODATA — an explicit type-65 query was answered with
	// something other than a NODATA + authored SOA (e.g. dropped/SERVFAIL/REFUSED, or
	// an actual record); §3.3 fixes the suppression shape as NODATA with an SOA.
	ViolationTypeQuerySVCBNotNODATA ViolationClass = "type65-query-not-nodata-with-soa"
	// ViolationECHClientHelloAdmitted — a TLS ClientHello carrying an ECH extension
	// (a real, DNS-published config) was admitted rather than refused; an encrypted
	// inner name would show only the CDN outer name, reopening the shared-IP hole.
	ViolationECHClientHelloAdmitted ViolationClass = "ech-clienthello-admitted"
)

// RecordType is a DNS record type relevant to the suppression rule.
type RecordType string

const (
	RecordA     RecordType = "A"     // ordinary v4 address — admitted through the normal path
	RecordHTTPS RecordType = "HTTPS" // type 65 — suppressed entirely
	RecordSVCB  RecordType = "SVCB"  // type 64 — suppressed entirely
)

// AnswerShape is the wire shape an answer took for a record type.
type AnswerShape string

const (
	// ShapeDelivered — the record was delivered to the VM (the regression for HTTPS/SVCB).
	ShapeDelivered AnswerShape = "delivered-to-vm"
	// ShapeSuppressedNODATA — the type was suppressed: NODATA with the D71 authored
	// SOA in authority (§3.3), the correct shape for an explicit type-65/64 query.
	ShapeSuppressedNODATA AnswerShape = "suppressed-nodata-with-soa"
	// ShapeDroppedOrServfail — the answer was dropped / SERVFAIL / REFUSED — the
	// forbidden shape for suppression (it stalls clients; §3.3 says NEVER do this).
	ShapeDroppedOrServfail AnswerShape = "dropped-or-servfail"
)

// RecordProbe is a synthetic fixture: a DNS answer of some record type for a
// domain, the wire shape it took, and (for the TLS side) whether a ClientHello
// carrying an ECH extension was admitted.
type RecordProbe struct {
	Domain string
	// Type is the record type the answer carried.
	Type RecordType
	// Shape is how the answer was disposed on the wire.
	Shape AnswerShape
	// ClientHelloHasECH records whether the matching TLS ClientHello carried an ECH
	// extension. Meaningful only for the TLS-1 half (an A-record flow that then
	// connects). False means plaintext SNI.
	ClientHelloHasECH bool
	// ECHAdmitted records whether an ECH ClientHello was admitted (true) or refused
	// (false). Meaningful only when ClientHelloHasECH is true.
	ECHAdmitted bool
}

// CheckECHSuppression asserts the ECH / HTTPS-SVCB suppression guardrail for one
// probe: HTTPS/SVCB never reaches the VM (an explicit query gets NODATA + SOA,
// never dropped/SERVFAIL), and an ECH ClientHello is refused.
func CheckECHSuppression(p RecordProbe) []Violation {
	var vs []Violation

	switch p.Type {
	case RecordHTTPS, RecordSVCB:
		switch p.Shape {
		case ShapeDelivered:
			vs = append(vs, Violation{
				Class:   ViolationHTTPSSVCBReachedVM,
				Subject: p.Domain,
				Reason: fmt.Sprintf("a %s record was delivered to the VM; HTTPS (type 65) / SVCB "+
					"(type 64) are suppressed ENTIRELY — they advertise ECH configs (defeating the "+
					"TLS-1 SNI check) and alpn=h3 (steering at the QUIC we drop), so no such answer "+
					"reaches a VM (doc 06 §3c, doc 09 §9 DNS-4, doc 11 §3.3, D68/D75)", p.Type),
			})
		case ShapeDroppedOrServfail:
			vs = append(vs, Violation{
				Class:   ViolationTypeQuerySVCBNotNODATA,
				Subject: p.Domain,
				Reason: fmt.Sprintf("an explicit %s query was dropped / SERVFAIL / REFUSED; §3.3 "+
					"fixes the suppression shape as a fast NODATA with the D71 authored SOA — a "+
					"drop stalls glibc and musl ~5s per fresh name, the exact failure suppression "+
					"must avoid (doc 11 §3.3, D75)", p.Type),
			})
		case ShapeSuppressedNODATA:
			// correct — suppressed as NODATA with an authored SOA.
		}
	case RecordA:
		// The A-record flow that then connects: the TLS-1 ECH half. An ECH
		// ClientHello must be refused (DNS-4 rule 4 already removed the real configs,
		// so what arrives is GREASE — refused, and acceptable for the curl/git/npm/SDK
		// set as a documented behavior).
		if p.ClientHelloHasECH && p.ECHAdmitted {
			vs = append(vs, Violation{
				Class:   ViolationECHClientHelloAdmitted,
				Subject: p.Domain,
				Reason: "a TLS ClientHello carrying an ECH extension was admitted; TLS-1 REFUSES " +
					"ECH ClientHellos — an encrypted inner name would show us only the CDN outer " +
					"name, reopening the shared-CDN-IP hole DNS-4 + TLS-1 close together (doc 06 " +
					"§3c, doc 09 §9 TLS-1, doc 11 §3.3, D68/D75)",
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 3 — session A ↛ B isolation / no-L2-path (doc 06 §3c "Session isolation";
//         doc 09 §9 "§2 placement + NFT-1", doc 09 §2 placement note; D66).
//
// THE CLAIM: no L2 path exists between two agent VMs — session A cannot reach
// session B. The proof must be STRUCTURAL or FLAG-AUDITED, never inherited from
// the `inet` default-deny ruleset, because bridged frames bypass the `inet`
// forward chain (the L3/4 deny does not cover the L2 hole). A routed tap /
// per-session bridge gives the structural no-L2-path proof; `BR_ISOLATED` is
// honored only behind a continuous flag audit.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationL2PathBetweenAgentTaps — a direct L2 (link-layer) path existed
	// between two distinct agent taps; session A could reach session B at L2.
	ViolationL2PathBetweenAgentTaps ViolationClass = "l2-path-between-agent-taps"
	// ViolationIsolationInheritedFromInetDeny — isolation was claimed solely from the
	// `inet` default-deny ruleset; bridged frames bypass the `inet` forward chain, so
	// this does NOT prove no-L2-path (doc 09 §2 / D66).
	ViolationIsolationInheritedFromInetDeny ViolationClass = "isolation-inherited-from-inet-deny"
	// ViolationBrIsolatedWithoutFlagAudit — the proof rested on `BR_ISOLATED` without
	// the continuous flag audit D66 requires; the flag is honored only when audited,
	// not assumed.
	ViolationBrIsolatedWithoutFlagAudit ViolationClass = "br-isolated-without-flag-audit"
)

// IsolationMechanism is how no-L2-path is established between agent taps.
type IsolationMechanism string

const (
	// MechRoutedTap — routed tap / per-session bridge: a structural no-L2-path proof
	// (no shared L2 segment), the D66 default-lean.
	MechRoutedTap IsolationMechanism = "routed-tap-structural"
	// MechBrIsolated — shared bridge with BR_ISOLATED set on the ports: honored only
	// behind a continuous flag audit (D66).
	MechBrIsolated IsolationMechanism = "br-isolated-flag"
	// MechInetDenyOnly — isolation claimed from the `inet` default-deny ruleset
	// alone: NOT a valid no-L2-path proof (bridged frames bypass the inet chain).
	MechInetDenyOnly IsolationMechanism = "inet-deny-only"
)

// IsolationProbe is a synthetic fixture: a pair of agent taps, the mechanism that
// establishes their isolation, whether a direct L2 path was observed between them,
// and (for BR_ISOLATED) whether the continuous flag audit is in place.
type IsolationProbe struct {
	// TapA, TapB are two distinct per-session agent taps.
	TapA string
	TapB string
	// Mechanism is how no-L2-path is established.
	Mechanism IsolationMechanism
	// L2PathObserved records whether a direct L2 path was observed between TapA and
	// TapB (the structural proof's negative obligation).
	L2PathObserved bool
	// FlagAuditInPlace records whether the continuous BR_ISOLATED flag audit is
	// active. Meaningful only when Mechanism is MechBrIsolated.
	FlagAuditInPlace bool
}

// CheckSessionIsolation asserts the no-L2-path guardrail for one tap-pair: no L2
// path is observed, isolation is not merely inherited from the inet default-deny,
// and a BR_ISOLATED proof carries its continuous flag audit.
func CheckSessionIsolation(p IsolationProbe) []Violation {
	var vs []Violation
	subject := p.TapA + "↛" + p.TapB

	if p.L2PathObserved {
		vs = append(vs, Violation{
			Class:   ViolationL2PathBetweenAgentTaps,
			Subject: subject,
			Reason: "a direct L2 path was observed between two agent taps; session A must not " +
				"reach session B — no L2 path between agent VMs (doc 06 §3c session isolation, " +
				"doc 09 §9 §2 placement + NFT-1, D66)",
		})
	}

	switch p.Mechanism {
	case MechInetDenyOnly:
		vs = append(vs, Violation{
			Class:   ViolationIsolationInheritedFromInetDeny,
			Subject: subject,
			Reason: "no-L2-path was claimed solely from the `inet` default-deny ruleset; bridged " +
				"frames BYPASS the `inet` forward chain, so the L3/4 deny does not prove L2 " +
				"isolation — the proof must be structural (routed tap / per-session bridge) or " +
				"flag-audited (doc 09 §2 placement note, D66)",
		})
	case MechBrIsolated:
		if !p.FlagAuditInPlace {
			vs = append(vs, Violation{
				Class:   ViolationBrIsolatedWithoutFlagAudit,
				Subject: subject,
				Reason: "isolation rested on `BR_ISOLATED` without the continuous flag audit; D66 " +
					"honors `BR_ISOLATED` only behind a continuous flag audit — an unaudited flag " +
					"can be cleared without the structural segment ever changing (doc 09 §2, D66)",
			})
		}
	case MechRoutedTap:
		// structural no-L2-path proof — the D66 default-lean; no audit obligation.
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 4 — IPv6 closure holds while dormant + the fe80 probe (doc 06 §3c "IPv6
//         closure holds while dormant"; doc 09 §9 / doc 11 §3.3/§3.5/§6 "nightly
//         from Stage 2"; D75).
//
// THE CLAIM: in the v0/dormant posture the guest is v4-only. AAAA is answered as
// a fast NOERROR/NODATA (never dropped/SERVFAIL/REFUSED — a dropped AAAA stalls
// glibc and musl ~5s per fresh name, RFC 4074). The nightly v6-closure row —
// including a sibling fe80 probe — proves the boundary HOST netns (not the guest
// sysctl) holds the line: a link-local fe80::/10 reach between agent taps is
// closed structurally, so the dormant posture cannot become a silent v6 escape.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationAAAADroppedNotNODATA — an AAAA query was dropped / SERVFAIL / REFUSED
	// instead of answered as a fast NOERROR/NODATA; the wrong shape stalls glibc and
	// musl ~5s per fresh name (§3.3, RFC 4074).
	ViolationAAAADroppedNotNODATA ViolationClass = "aaaa-dropped-not-nodata"
	// ViolationDormantV6ReachOpen — a v6 reach was open from an agent tap while v6
	// is dormant; the dormant posture must HOLD, not become a silent escape.
	ViolationDormantV6ReachOpen ViolationClass = "dormant-v6-reach-open"
	// ViolationFe80ReachBetweenTaps — a link-local fe80::/10 reach existed between
	// agent taps; the boundary host netns (not the guest sysctl) must close the
	// fe80 path structurally (the nightly fe80 probe, D75).
	ViolationFe80ReachBetweenTaps ViolationClass = "fe80-link-local-reach-between-taps"
)

// V6Closure is a synthetic fixture for the dormant-v6 closure + fe80 probe: how
// an AAAA query was answered, whether any v6 reach was open from an agent tap, and
// whether a link-local fe80 reach was observed between agent taps.
type V6Closure struct {
	// Domain is the name the AAAA query was for.
	Domain string
	// AAAAShape is how the AAAA query was disposed (must be ShapeSuppressedNODATA in
	// the dormant posture — fast NOERROR/NODATA with an authored SOA).
	AAAAShape AnswerShape
	// V6ReachOpenFromTap records whether any IPv6 reach was open from an agent tap
	// (e.g. a v6 destination connected) while v6 is dormant.
	V6ReachOpenFromTap bool
	// Fe80ReachBetweenTaps records whether a link-local fe80::/10 reach was observed
	// between two agent taps (the sibling fe80 probe's negative obligation).
	Fe80ReachBetweenTaps bool
}

// CheckV6Closure asserts the dormant-v6 closure + fe80 probe for one fixture:
// AAAA is answered as a fast NODATA (never dropped/SERVFAIL), no v6 reach is open
// from an agent tap, and no fe80 reach exists between agent taps.
func CheckV6Closure(c V6Closure) []Violation {
	var vs []Violation

	// Dormant posture: AAAA → fast NOERROR/NODATA with an authored SOA. A
	// drop/SERVFAIL/REFUSED is the forbidden shape (§3.3); a delivered AAAA would be
	// v6 leaking into a v4-only guest.
	switch c.AAAAShape {
	case ShapeDroppedOrServfail:
		vs = append(vs, Violation{
			Class:   ViolationAAAADroppedNotNODATA,
			Subject: c.Domain,
			Reason: "an AAAA query was dropped / SERVFAIL / REFUSED; the dormant v0 posture answers " +
				"AAAA as a FAST NOERROR/NODATA with the D71 authored SOA — never drop/SERVFAIL/" +
				"REFUSED, which stalls glibc and musl ~5s per fresh name (doc 11 §3.3, RFC 4074, D75)",
		})
	case ShapeDelivered:
		// A delivered AAAA in the dormant posture is a v6 reach opening; surface it
		// under the dormant-reach class (the headline closure obligation).
		vs = append(vs, Violation{
			Class:   ViolationDormantV6ReachOpen,
			Subject: c.Domain,
			Reason: "an AAAA record was delivered to a v4-only dormant guest; the dormant posture " +
				"strips AAAA (answers NODATA) — delivering one opens a v6 reach the dormant " +
				"closure must hold against (doc 11 §3.3/§3.5, D75)",
		})
	case ShapeSuppressedNODATA:
		// correct dormant shape.
	}

	if c.V6ReachOpenFromTap {
		vs = append(vs, Violation{
			Class:   ViolationDormantV6ReachOpen,
			Subject: c.Domain,
			Reason: "a v6 reach was open from an agent tap while v6 is dormant; the nightly " +
				"v6-closure row proves the boundary host netns holds the line — the dormant " +
				"posture must HOLD, not become a silent v6 escape (doc 11 §6, doc 09 §9, D75)",
		})
	}

	if c.Fe80ReachBetweenTaps {
		vs = append(vs, Violation{
			Class:   ViolationFe80ReachBetweenTaps,
			Subject: c.Domain,
			Reason: "a link-local fe80::/10 reach was observed between agent taps; the sibling " +
				"fe80 probe must show the boundary HOST netns (not the guest sysctl) closes the " +
				"link-local path structurally — a fe80 reach is a v6 escape the per-interface " +
				"sysctl alone would not catch (doc 09 §9 D75 fe80 probe, doc 11 §3.5)",
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 5 — controls unreachable from the VM (doc 06 §3c "Controls live outside
//         the agent's reach", doc 04 §5; doc 09 §9 "NFT-1 + §2 placement").
//
// THE CLAIM: from inside the VM the proxy / NFTables / policy engine / identity
// plane are neither observable nor modifiable. The boundary stack runs in the
// virtual-metal host network namespace the VM has no path into (NFT-1
// default-drop + §2 placement), so a probe at a control-plane endpoint from a VM
// interface is dropped, not answered.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationControlEndpointReachable — a control-plane endpoint (proxy admin /
	// NFTables socket / policy engine / identity plane) was reachable from a VM
	// interface; the controls must be unreachable, not merely access-controlled.
	ViolationControlEndpointReachable ViolationClass = "control-endpoint-reachable-from-vm"
	// ViolationControlEndpointObservable — a control-plane endpoint was observable
	// from the VM (its presence/port disclosed) even if not modifiable; doc 04 §5
	// requires unobservable AND unmodifiable.
	ViolationControlEndpointObservable ViolationClass = "control-endpoint-observable-from-vm"
	// ViolationControlEndpointModifiable — a control-plane endpoint accepted a
	// modify/write from a VM interface; the controls must not be modifiable from
	// inside the VM.
	ViolationControlEndpointModifiable ViolationClass = "control-endpoint-modifiable-from-vm"
)

// ControlPlane names a control-plane component the VM must not reach (doc 04 §5).
type ControlPlane string

const (
	ControlProxy    ControlPlane = "ds-tlsproxy" // the egress gateway
	ControlNFTables ControlPlane = "nftables"    // the kernel ruleset / nft socket
	ControlPolicy   ControlPlane = "policy-core" // the policy engine
	ControlIdentity ControlPlane = "identity"    // the identity / credential plane
)

// ControlProbe is a synthetic fixture: a probe from a VM interface at a
// control-plane component, and what the boundary did with it.
type ControlProbe struct {
	// Tap is the agent tap the probe originated on.
	Tap string
	// Target is the control-plane component the probe aimed at.
	Target ControlPlane
	// Reachable records whether the probe reached the component at all (a connect
	// that was answered). The controls must be unreachable (dropped) from a VM.
	Reachable bool
	// Observable records whether the component's presence/port was disclosed to the
	// VM (e.g. a refused-with-RST vs a silent drop), even if not reachable.
	Observable bool
	// ModifyAccepted records whether a modify/write from the VM was accepted by the
	// component. Meaningful only when Reachable is true.
	ModifyAccepted bool
}

// CheckControlsUnreachable asserts the controls-unreachable guardrail for one
// probe: a control-plane component is neither reachable, observable, nor
// modifiable from a VM interface.
func CheckControlsUnreachable(p ControlProbe) []Violation {
	var vs []Violation
	subject := p.Tap + "→" + string(p.Target)

	if p.Reachable {
		vs = append(vs, Violation{
			Class:   ViolationControlEndpointReachable,
			Subject: subject,
			Reason: fmt.Sprintf("the %s control-plane endpoint was reachable from VM tap %q; the "+
				"boundary stack runs in the virtual-metal host network namespace the VM has no path "+
				"into — NFT-1 default-drop + §2 placement make the controls UNREACHABLE, not merely "+
				"access-controlled (doc 06 §3c, doc 04 §5, doc 09 §9 NFT-1 + §2 placement)", p.Target, p.Tap),
		})
	}
	if p.Observable {
		vs = append(vs, Violation{
			Class:   ViolationControlEndpointObservable,
			Subject: subject,
			Reason: fmt.Sprintf("the %s control-plane endpoint was observable from VM tap %q (its "+
				"presence/port disclosed); doc 04 §5 requires the controls be UNOBSERVABLE as well "+
				"as unmodifiable — a disclosed endpoint is an information leak the placement must "+
				"close (doc 06 §3c, doc 04 §5)", p.Target, p.Tap),
		})
	}
	if p.Reachable && p.ModifyAccepted {
		vs = append(vs, Violation{
			Class:   ViolationControlEndpointModifiable,
			Subject: subject,
			Reason: fmt.Sprintf("the %s control-plane endpoint accepted a modify/write from VM tap "+
				"%q; the controls must not be MODIFIABLE from inside the VM — a VM that could rewrite "+
				"the ruleset or policy would defeat every other guardrail (doc 06 §3c, doc 04 §5)",
				p.Target, p.Tap),
		})
	}
	sortViolations(vs)
	return vs
}
