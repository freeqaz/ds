// SPDX-License-Identifier: Apache-2.0

package resolverhardening

import (
	"net/netip"
	"sort"
	"strings"
	"testing"
)

// This file exercises the D42 "resolver hardening holds as a unit" (c) row as the
// orchctl/nftgate siblings do: a CONFORMING control for each clause must pass
// clean, and each NAMED clause must be tripped by at least one synthetic fixture
// (D50). All fixtures are in-code Go literals — there is no fixtures/ dir, no file
// I/O, and no working-directory dependency; "synthetic only" is structural here.
// A coverage gate fails closed if a declared clause is never exercised, so a new
// clause cannot land un-asserted.

// ── reference posture (the spec read of the documented resolver posture) ─────

// referencePosture is the documented resolver posture the offline fixtures are
// asserted against (the spec read of doc 09 §3 / doc 11 §3 / doc 20 §4). One of
// our resolvers is ds-dnsgate's listener; one allowlisted domain admits one
// documentation-range IP; the POL-2 baseline blocklist names the public DoH
// resolver domains.
func referencePosture() Posture {
	ours := netip.MustParseAddr("10.66.0.1")
	allowedIP := netip.MustParseAddr("203.0.113.10")
	return Posture{
		OurResolvers: map[netip.Addr]bool{ours: true},
		DoHResolverDomains: map[string]bool{
			"dns.google":                 true,
			"cloudflare-dns.com":         true,
			"mozilla.cloudflare-dns.com": true,
		},
		AdmittedDomains: map[string]bool{
			"api.allowed.example": true,
		},
		Admitted: map[string]map[netip.Addr]bool{
			"api.allowed.example": {allowedIP: true},
		},
	}
}

// ── shared helpers ──────────────────────────────────────────────────────────

func classesOf(vs []Violation) []ViolationClass {
	set := map[ViolationClass]bool{}
	for _, v := range vs {
		set[v.Class] = true
	}
	out := make([]ViolationClass, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sameClasses(got []Violation, want []ViolationClass) bool {
	g := classesOf(got)
	w := append([]ViolationClass(nil), want...)
	sort.Slice(w, func(i, j int) bool { return w[i] < w[j] })
	if len(g) != len(w) {
		return false
	}
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

func render(vs []Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("  ")
		b.WriteString(v.String())
		b.WriteString("\n")
	}
	return b.String()
}

func assertClasses(t *testing.T, name string, got []Violation, want []ViolationClass) {
	t.Helper()
	if len(want) == 0 {
		if len(got) != 0 {
			t.Fatalf("CONFORMING fixture %q reported %d violation(s) — the unit holds, so this must "+
				"pass clean:\n%s", name, len(got), render(got))
		}
		return
	}
	if len(got) == 0 {
		t.Fatalf("VIOLATION fixture %q reported NO violations — the check must fail on %v (a silent "+
			"pass is the regression this clause exists to catch)", name, want)
	}
	if !sameClasses(got, want) {
		t.Fatalf("VIOLATION fixture %q reported the WRONG clause set —\n want: %v\n got: %v\nfull:\n%s",
			name, want, classesOf(got), render(got))
	}
}

// ── the documented-vocabulary guard (doc 06 §3c language note) ──────────────

func TestNoAttackVocabulary(t *testing.T) {
	banned := []string{"attack", "redteam", "red-team", "intrusion", "exploit", "adversary"}
	for _, c := range Clauses() {
		low := strings.ToLower(string(c))
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("clause class %q carries banned %q framing — doc 06 §3c forbids "+
					"attack/redteam/intrusion naming; name the clause for the property it proves", c, b)
			}
		}
	}
}

// ── the tag guard (the credswap/suspendbreach const-Tag discipline) ─────────

func TestTagStable(t *testing.T) {
	if Tag != "resolver-hardening-holds-as-unit" {
		t.Fatalf("Tag = %q, want resolver-hardening-holds-as-unit (doc.go REGISTRATION; the "+
			"guardrail-map.yaml resolverhardening row must match)", Tag)
	}
}

// ── the anchor guard (the goldenfreshness/orchctl anchor-guard discipline) ──

// TestClampWindowMatchesDocumentedCadence pins FLOOR/CEIL to the documented v0
// per-session allow-set TTL clamp window: 60 s floor / 900 s (15 min) cap (doc 11
// §3 W2, doc 20 §4 claim 1, D42). If a constant drifts without re-ratifying the
// window, this fails HERE rather than letting clause 7 quietly judge against a
// different window than the doc promises.
func TestClampWindowMatchesDocumentedCadence(t *testing.T) {
	const (
		documentedFloor = 60
		documentedCeil  = 900
	)
	if FloorTTLSeconds != documentedFloor {
		t.Errorf("FloorTTLSeconds = %d, want %d (doc 11 §3 W2 / doc 20 §4 claim 1 60 s floor; D42)",
			FloorTTLSeconds, documentedFloor)
	}
	if CeilTTLSeconds != documentedCeil {
		t.Errorf("CeilTTLSeconds = %d, want %d (doc 11 §3 W2 / doc 20 §4 claim 1 900 s / 15 min cap; D42)",
			CeilTTLSeconds, documentedCeil)
	}
}

// TestClampTTL exercises the clamp behavior the clause-7 check depends on: below
// the floor clamps up, above the cap clamps down, in-window passes through.
func TestClampTTL(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{5, 60},     // below floor → floor
		{60, 60},    // at floor
		{300, 300},  // in window
		{900, 900},  // at cap
		{3600, 900}, // above cap → cap
	}
	for _, c := range cases {
		if got := ClampTTL(c.in); got != c.want {
			t.Errorf("ClampTTL(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// ── the unit: clauses 1–8 over (attempt, observation) pairs ─────────────────

// TestResolverHardeningUnit exercises CheckUnit clause by clause. The coverage
// gate at the end fails closed if any unit-level clause is never exercised or no
// conforming control is proven. (Clauses 7-no-silent-widen and 9 have dedicated
// entry points — CheckReResolve / CheckSNICrossCheck — exercised in their own
// tests below; the gate here covers the CheckUnit clauses plus folds in those two
// via the shared `seen` set.)
func TestResolverHardeningUnit(t *testing.T) {
	p := referencePosture()

	type tc struct {
		name string
		a    ResolutionAttempt
		o    Observation
		want []ViolationClass
	}
	cases := []tc{
		// clause 1 — sole resolution path
		{
			name: "conforming-port53-foreign-aim-lands-on-dsdnsgate-counted",
			a:    ResolutionAttempt{Name: "c1-ok", Transport: TransportPlain53, AimedResolver: "8.8.8.8"},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: true},
			want: nil,
		},
		{
			name: "violation-port53-foreign-resolver-answered",
			a:    ResolutionAttempt{Name: "c1-bad", Transport: TransportPlain53, AimedResolver: "8.8.8.8"},
			o:    Observation{LandedOnDsDnsgate: false, BypassAttemptCounted: true},
			want: []ViolationClass{ClauseSoleResolutionPath},
		},
		{
			name: "violation-port53-bypass-not-counted",
			a:    ResolutionAttempt{Name: "c4-bad-53", Transport: TransportPlain53, AimedResolver: "8.8.8.8"},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: false},
			want: []ViolationClass{ClauseBypassAttemptCounted},
		},
		// clause 2 — DoT dropped
		{
			name: "conforming-dot-dropped-counted",
			a:    ResolutionAttempt{Name: "c2-ok", Transport: TransportDoT, AimedResolver: "8.8.8.8"},
			o:    Observation{DoTDropped: true, BypassAttemptCounted: true},
			want: nil,
		},
		{
			name: "violation-dot-not-dropped",
			a:    ResolutionAttempt{Name: "c2-bad", Transport: TransportDoT, AimedResolver: "8.8.8.8"},
			o:    Observation{DoTDropped: false, BypassAttemptCounted: true},
			want: []ViolationClass{ClauseDoTDropped},
		},
		// clause 3 — DoH known resolver blocked
		{
			name: "conforming-doh-known-resolver-denied-counted",
			a:    ResolutionAttempt{Name: "c3-ok", Transport: TransportDoH, Domain: "dns.google"},
			o:    Observation{DoHDenied: true, BypassAttemptCounted: true},
			want: nil,
		},
		{
			name: "violation-doh-known-resolver-not-denied",
			a:    ResolutionAttempt{Name: "c3-bad", Transport: TransportDoH, Domain: "cloudflare-dns.com"},
			o:    Observation{DoHDenied: false, BypassAttemptCounted: true},
			want: []ViolationClass{ClauseDoHBlocked},
		},
		// clause 4 — bypass attempt counted (via DoH)
		{
			name: "violation-doh-bypass-not-counted",
			a:    ResolutionAttempt{Name: "c4-bad-doh", Transport: TransportDoH, Domain: "dns.google"},
			o:    Observation{DoHDenied: true, BypassAttemptCounted: false},
			want: []ViolationClass{ClauseBypassAttemptCounted},
		},
		// clause 5 — ECH params stripped (HTTPS/SVCB suppressed)
		{
			name: "conforming-https-record-suppressed",
			a:    ResolutionAttempt{Name: "c5-ok", Transport: TransportPlain53, AimedResolver: "10.66.0.1", RecordType: RecordHTTPS},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: true, RecordDelivered: false},
			want: nil,
		},
		{
			name: "violation-https-record-delivered-ech-intact",
			a:    ResolutionAttempt{Name: "c5-bad", Transport: TransportPlain53, AimedResolver: "10.66.0.1", RecordType: RecordHTTPS},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: true, RecordDelivered: true},
			want: []ViolationClass{ClauseECHStripped},
		},
		// clause 6 — private-range answer never admitted
		{
			name: "conforming-public-answer-admitted",
			a:    ResolutionAttempt{Name: "c6-ok", Transport: TransportPlain53, AimedResolver: "10.66.0.1", Answer: "203.0.113.10"},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: true, AnswerAdmitted: true},
			want: nil,
		},
		{
			name: "violation-private-range-answer-admitted",
			a:    ResolutionAttempt{Name: "c6-bad-rfc1918", Transport: TransportPlain53, AimedResolver: "10.66.0.1", Answer: "10.0.0.5"},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: true, AnswerAdmitted: true},
			want: []ViolationClass{ClausePrivateRangeNotAdmitted},
		},
		{
			name: "violation-embedded-v4-private-answer-admitted",
			a:    ResolutionAttempt{Name: "c6-bad-mapped", Transport: TransportPlain53, AimedResolver: "10.66.0.1", Answer: "::ffff:10.0.0.5"},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: true, AnswerAdmitted: true},
			want: []ViolationClass{ClausePrivateRangeNotAdmitted},
		},
		// clause 7 — TTL clamp to [60s, 900s]
		{
			name: "conforming-ttl-clamped-up-to-floor",
			a:    ResolutionAttempt{Name: "c7-ok-floor", Transport: TransportPlain53, AimedResolver: "10.66.0.1", UpstreamTTLSeconds: 5},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: true, AnsweredTTLSeconds: 60},
			want: nil,
		},
		{
			name: "violation-ttl-below-floor-not-clamped",
			a:    ResolutionAttempt{Name: "c7-bad-floor", Transport: TransportPlain53, AimedResolver: "10.66.0.1", UpstreamTTLSeconds: 5},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: true, AnsweredTTLSeconds: 5},
			want: []ViolationClass{ClauseTTLClamp},
		},
		{
			name: "violation-ttl-above-cap-not-clamped",
			a:    ResolutionAttempt{Name: "c7-bad-cap", Transport: TransportPlain53, AimedResolver: "10.66.0.1", UpstreamTTLSeconds: 3600},
			o:    Observation{LandedOnDsDnsgate: true, BypassAttemptCounted: true, AnsweredTTLSeconds: 3600},
			want: []ViolationClass{ClauseTTLClamp},
		},
		// clause 8 — udp/443 reject + counted
		{
			name: "conforming-quic-rejected-and-counted",
			a:    ResolutionAttempt{Name: "c8-ok", QUIC: true},
			o:    Observation{QUICRejectedWithICMP: true, QUICCounted: true},
			want: nil,
		},
		{
			name: "violation-quic-silently-dropped",
			a:    ResolutionAttempt{Name: "c8-bad-drop", QUIC: true},
			o:    Observation{QUICRejectedWithICMP: false, QUICCounted: false},
			want: []ViolationClass{ClauseQUICRejectCounted},
		},
		{
			name: "violation-quic-rejected-not-counted",
			a:    ResolutionAttempt{Name: "c8-bad-count", QUIC: true},
			o:    Observation{QUICRejectedWithICMP: true, QUICCounted: false},
			want: []ViolationClass{ClauseQUICRejectCounted},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := p.CheckUnit(c.a, c.o)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}

	// Fold in the two dedicated-entry-point clauses so the unit-level coverage gate
	// sees them exercised (their assertions run in TestReResolve / TestSNICrossCheck).
	seen[ClauseReResolveWidened] = exerciseReResolve(t, p)
	seen[ClauseSNICrossCheck] = exerciseSNICrossCheck(t, p)

	if !sawControl {
		t.Error("no CONFORMING control fixture passed clean — the green case must be proven")
	}
	for _, c := range Clauses() {
		if !seen[c] {
			t.Errorf("D42 clause %q is never exercised by a fixture — every clause of the unit must "+
				"have a named fixture (fail-closed coverage gate)", c)
		}
	}
}

// ── clause 7 (no-silent-widen half) — CheckReResolve ────────────────────────

// exerciseReResolve runs the re-resolve violation and reports whether the widen
// clause was tripped (feeding the unit coverage gate). The full assertions live in
// TestReResolve.
func exerciseReResolve(t *testing.T, p Posture) bool {
	t.Helper()
	got := p.CheckReResolve(
		ResolutionAttempt{Name: "rr-widen", Domain: "api.allowed.example", Answer: "203.0.113.99"},
		Observation{AnswerAdmitted: true, ReResolveWentThroughAdmission: false},
	)
	for _, v := range got {
		if v.Class == ClauseReResolveWidened {
			return true
		}
	}
	t.Error("CheckReResolve did not trip ClauseReResolveWidened on a silent-widen fixture")
	return false
}

func TestReResolve(t *testing.T) {
	p := referencePosture()
	type tc struct {
		name string
		a    ResolutionAttempt
		o    Observation
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-re-resolve-through-full-admission",
			a:    ResolutionAttempt{Name: "rr-ok", Domain: "api.allowed.example", Answer: "203.0.113.11"},
			o:    Observation{AnswerAdmitted: true, ReResolveWentThroughAdmission: true},
			want: nil,
		},
		{
			name: "conforming-re-resolve-not-admitted",
			a:    ResolutionAttempt{Name: "rr-noadmit", Domain: "api.allowed.example", Answer: "203.0.113.12"},
			o:    Observation{AnswerAdmitted: false},
			want: nil,
		},
		{
			name: "violation-re-resolve-silently-widened",
			a:    ResolutionAttempt{Name: "rr-widen", Domain: "api.allowed.example", Answer: "203.0.113.99"},
			o:    Observation{AnswerAdmitted: true, ReResolveWentThroughAdmission: false},
			want: []ViolationClass{ClauseReResolveWidened},
		},
		{
			name: "violation-re-resolve-to-private-range-widened",
			a:    ResolutionAttempt{Name: "rr-private", Domain: "api.allowed.example", Answer: "192.168.1.5"},
			o:    Observation{AnswerAdmitted: true, ReResolveWentThroughAdmission: false},
			// silently widened AND to a private range — both NAMED.
			want: []ViolationClass{ClauseReResolveWidened, ClausePrivateRangeNotAdmitted},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := p.CheckReResolve(c.a, c.o)
			assertClasses(t, c.name, got, c.want)
		})
	}
}

// ── clause 9 — CheckSNICrossCheck ───────────────────────────────────────────

// exerciseSNICrossCheck runs the cross-check violation and reports whether the
// clause was tripped (feeding the unit coverage gate). Full assertions in
// TestSNICrossCheck.
func exerciseSNICrossCheck(t *testing.T, p Posture) bool {
	t.Helper()
	got := p.CheckSNICrossCheck(
		ResolutionAttempt{Name: "sni-cdn-hole", Domain: "api.allowed.example", OriginalDst: "203.0.113.200"},
		Observation{TLSAdmitted: true},
	)
	for _, v := range got {
		if v.Class == ClauseSNICrossCheck {
			return true
		}
	}
	t.Error("CheckSNICrossCheck did not trip ClauseSNICrossCheck on a shared-CDN-IP fixture")
	return false
}

func TestSNICrossCheck(t *testing.T) {
	p := referencePosture()
	type tc struct {
		name string
		a    ResolutionAttempt
		o    Observation
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-domain-and-ip-admitted",
			a:    ResolutionAttempt{Name: "sni-ok", Domain: "api.allowed.example", OriginalDst: "203.0.113.10"},
			o:    Observation{TLSAdmitted: true},
			want: nil,
		},
		{
			name: "conforming-not-admitted-not-connected",
			a:    ResolutionAttempt{Name: "sni-refused", Domain: "evil.example", OriginalDst: "203.0.113.10"},
			o:    Observation{TLSAdmitted: false},
			want: nil,
		},
		{
			name: "violation-shared-cdn-ip-admitted-for-wrong-domain",
			a:    ResolutionAttempt{Name: "sni-cdn-hole", Domain: "api.allowed.example", OriginalDst: "203.0.113.200"},
			o:    Observation{TLSAdmitted: true},
			want: []ViolationClass{ClauseSNICrossCheck},
		},
		{
			name: "violation-disallowed-domain-admitted",
			a:    ResolutionAttempt{Name: "sni-baddomain", Domain: "evil.example", OriginalDst: "203.0.113.10"},
			o:    Observation{TLSAdmitted: true},
			want: []ViolationClass{ClauseSNICrossCheck},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := p.CheckSNICrossCheck(c.a, c.o)
			assertClasses(t, c.name, got, c.want)
		})
	}
}

// TestClausesComplete pins the clause set to all nine D42 clauses so a dropped or
// renamed clause fails HERE (the unit must enumerate every clause it claims).
func TestClausesComplete(t *testing.T) {
	if len(Clauses()) != 10 {
		t.Fatalf("Clauses() has %d entries, want 10 (the D42 nine clauses, with clause 7 split into "+
			"the clamp half and the no-silent-widen half)", len(Clauses()))
	}
}
