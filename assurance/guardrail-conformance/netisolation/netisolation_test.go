// SPDX-License-Identifier: Apache-2.0

package netisolation

import (
	"sort"
	"strings"
	"testing"
)

// This file exercises the five doc 06 §3c Stage-2 network-isolation (c) rows as
// the orchctl sibling does: per row, a CONFORMING control fixture must pass clean,
// and each NAMED violation class must be tripped by at least one synthetic fixture
// (D50). All fixtures are in-code Go literals — there is no fixtures/ dir, no file
// I/O, and no working-directory dependency; "synthetic only" is structural here.
// A per-row coverage gate fails closed if a declared violation class is never
// exercised, so a new class cannot land un-asserted.

// ── shared helpers ──────────────────────────────────────────────────────────

// classesOf collects the sorted, deduped violation classes a check reported.
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

// sameClasses reports whether got's class set equals want exactly.
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

// render formats a violation slice for failure messages.
func render(vs []Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("  ")
		b.WriteString(v.String())
		b.WriteString("\n")
	}
	return b.String()
}

// coverageGate asserts that the union of violation classes the row's fixtures
// produced equals the declared class set for that row — a CONFORMING control was
// proven (the green case) AND every declared class was exercised at least once,
// failing closed on either a missing control or an un-exercised class.
func coverageGate(t *testing.T, row string, declared []ViolationClass, seen map[ViolationClass]bool, sawControl bool) {
	t.Helper()
	if !sawControl {
		t.Errorf("%s: no CONFORMING control fixture passed clean — the green case must be proven", row)
	}
	for _, c := range declared {
		if !seen[c] {
			t.Errorf("%s: violation class %q is never exercised by a fixture — every declared "+
				"failure mode must have a named fixture (fail-closed coverage gate)", row, c)
		}
	}
}

// assertClasses is the shared per-case assertion: a CONFORMING fixture (want
// empty) must report NO violations, and a violation fixture must FAIL with its
// NAMED class set exactly — a silent pass is the regression each row exists to
// catch.
func assertClasses(t *testing.T, name string, got []Violation, want []ViolationClass) {
	t.Helper()
	if len(want) == 0 {
		if len(got) != 0 {
			t.Fatalf("CONFORMING fixture %q reported %d violation(s) — the guardrail holds, so "+
				"this must pass clean:\n%s", name, len(got), render(got))
		}
		return
	}
	if len(got) == 0 {
		t.Fatalf("VIOLATION fixture %q reported NO violations — the check must fail on %v (a "+
			"silent pass is the regression this row exists to catch)", name, want)
	}
	if !sameClasses(got, want) {
		t.Fatalf("VIOLATION fixture %q reported the WRONG violation class set —\n want: %v\n "+
			"got: %v\nfull:\n%s", name, want, classesOf(got), render(got))
	}
}

// ── the documented-vocabulary guard (doc 06 §3c language note) ──────────────

// TestNoAttackVocabulary pins the doc 06 §3c language note for this package: no
// ViolationClass string may carry attack / redteam / intrusion framing. These are
// assurance tests for advertised properties, not a security-audit exercise.
func TestNoAttackVocabulary(t *testing.T) {
	banned := []string{"attack", "redteam", "red-team", "intrusion", "exploit", "adversary"}
	all := []ViolationClass{
		// row 1
		ViolationSpoofMatchedOnSourceIP, ViolationSpoofForgedSrcEscapedRedirect,
		ViolationSpoofThreeKeysDisagreeNotDropped,
		// row 2
		ViolationHTTPSSVCBReachedVM, ViolationTypeQuerySVCBNotNODATA,
		ViolationECHClientHelloAdmitted,
		// row 3
		ViolationL2PathBetweenAgentTaps, ViolationIsolationInheritedFromInetDeny,
		ViolationBrIsolatedWithoutFlagAudit,
		// row 4
		ViolationAAAADroppedNotNODATA, ViolationDormantV6ReachOpen,
		ViolationFe80ReachBetweenTaps,
		// row 5
		ViolationControlEndpointReachable, ViolationControlEndpointObservable,
		ViolationControlEndpointModifiable,
	}
	for _, c := range all {
		low := strings.ToLower(string(c))
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("violation class %q carries banned %q framing — doc 06 §3c forbids "+
					"attack/redteam/intrusion naming; name the row for the property it proves", c, b)
			}
		}
	}
}

// ── the tag guard (the orchctl/goldenfreshness const-Tag discipline) ────────

// TestTagsStable pins the single-sourced guardrail tags to the doc.go
// REGISTRATION values, in order. The repo-root guardrail-map.yaml's netisolation
// glob row (at the first per-claim seeding) names these SAME tags; if a tag string
// drifts without re-reconciling the map row and the doc.go table, this fails HERE
// rather than letting the package and the map name different rows.
func TestTagsStable(t *testing.T) {
	want := []string{
		"netiso-in-vm-spoofing-fails",
		"netiso-ech-https-svcb-suppression",
		"netiso-session-a-not-b-no-l2-path",
		"netiso-ipv6-closure-dormant-fe80-probe",
		"netiso-controls-unreachable-from-vm",
	}
	if len(Tags) != len(want) {
		t.Fatalf("Tags has %d entries, want %d (the five doc 06 §3c Stage-2 network-isolation (c) "+
			"rows; doc.go REGISTRATION)", len(Tags), len(want))
	}
	for i := range want {
		if Tags[i] != want[i] {
			t.Errorf("Tags[%d] = %q, want %q (doc.go REGISTRATION / guardrail-map.yaml netisolation row)",
				i, Tags[i], want[i])
		}
	}
}

// ── ROW 1 — in-VM IP-spoofing fails / interface-match (NFT-2) ───────────────

func TestRowInVMSpoofing(t *testing.T) {
	declared := []ViolationClass{
		ViolationSpoofMatchedOnSourceIP, ViolationSpoofForgedSrcEscapedRedirect,
		ViolationSpoofThreeKeysDisagreeNotDropped,
	}
	type tc struct {
		name  string
		probe SpoofProbe
		want  []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-honest-src-interface-matched-redirected",
			probe: SpoofProbe{
				Tap: "dstap-0", ClaimedSrc: "10.66.0.2", AssignedGuestIP: "10.66.0.2",
				CtMarkMatchesSession: true, MatchedOnInterface: true, RedirectedToBoundary: true,
			},
			want: nil,
		},
		{
			name: "conforming-forged-src-dropped-on-three-keys-disagreement",
			probe: SpoofProbe{
				Tap: "dstap-1", ClaimedSrc: "10.66.0.99", AssignedGuestIP: "10.66.0.3",
				CtMarkMatchesSession: false, MatchedOnInterface: true, RedirectedToBoundary: false, Dropped: true,
			},
			want: nil, // forged + three-keys disagree, but DROPPED — the correct disposition
		},
		{
			name: "violation-matched-on-source-ip",
			probe: SpoofProbe{
				Tap: "dstap-2", ClaimedSrc: "10.66.0.4", AssignedGuestIP: "10.66.0.4",
				CtMarkMatchesSession: true, MatchedOnInterface: false, RedirectedToBoundary: true,
			},
			want: []ViolationClass{ViolationSpoofMatchedOnSourceIP},
		},
		{
			name: "violation-forged-src-escaped-redirect",
			probe: SpoofProbe{
				Tap: "dstap-3", ClaimedSrc: "203.0.113.7", AssignedGuestIP: "10.66.0.5",
				CtMarkMatchesSession: true, MatchedOnInterface: true, RedirectedToBoundary: false, Dropped: false,
			},
			// forged source (claimed != assigned) escaped: not redirected, not dropped.
			// Also the three keys disagree (forged) and it was not dropped — both NAMED.
			want: []ViolationClass{ViolationSpoofForgedSrcEscapedRedirect, ViolationSpoofThreeKeysDisagreeNotDropped},
		},
		{
			name: "violation-three-keys-disagree-not-dropped-ct-mark",
			probe: SpoofProbe{
				Tap: "dstap-4", ClaimedSrc: "10.66.0.6", AssignedGuestIP: "10.66.0.6",
				CtMarkMatchesSession: false, MatchedOnInterface: true, RedirectedToBoundary: true, Dropped: false,
			},
			// ct mark disagrees (third key) though the source is honest — must be dropped.
			want: []ViolationClass{ViolationSpoofThreeKeysDisagreeNotDropped},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckInVMSpoofing(c.probe)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "in-vm-spoofing-fails", declared, seen, sawControl)
}

// ── ROW 2 — ECH / HTTPS-SVCB suppression (D68/D75) ──────────────────────────

func TestRowECHSuppression(t *testing.T) {
	declared := []ViolationClass{
		ViolationHTTPSSVCBReachedVM, ViolationTypeQuerySVCBNotNODATA,
		ViolationECHClientHelloAdmitted,
	}
	type tc struct {
		name  string
		probe RecordProbe
		want  []ViolationClass
	}
	cases := []tc{
		{
			name:  "conforming-https-suppressed-nodata",
			probe: RecordProbe{Domain: "api.allowed.example", Type: RecordHTTPS, Shape: ShapeSuppressedNODATA},
			want:  nil,
		},
		{
			name:  "conforming-svcb-suppressed-nodata",
			probe: RecordProbe{Domain: "cdn.allowed.example", Type: RecordSVCB, Shape: ShapeSuppressedNODATA},
			want:  nil,
		},
		{
			name:  "conforming-a-record-plaintext-sni-no-ech",
			probe: RecordProbe{Domain: "api.allowed.example", Type: RecordA, Shape: ShapeDelivered, ClientHelloHasECH: false},
			want:  nil,
		},
		{
			name:  "conforming-a-record-ech-refused",
			probe: RecordProbe{Domain: "api.allowed.example", Type: RecordA, Shape: ShapeDelivered, ClientHelloHasECH: true, ECHAdmitted: false},
			want:  nil, // ECH ClientHello present but REFUSED — the correct TLS-1 disposition
		},
		{
			name:  "violation-https-reached-vm",
			probe: RecordProbe{Domain: "api.allowed.example", Type: RecordHTTPS, Shape: ShapeDelivered},
			want:  []ViolationClass{ViolationHTTPSSVCBReachedVM},
		},
		{
			name:  "violation-type65-query-dropped-not-nodata",
			probe: RecordProbe{Domain: "api.allowed.example", Type: RecordHTTPS, Shape: ShapeDroppedOrServfail},
			want:  []ViolationClass{ViolationTypeQuerySVCBNotNODATA},
		},
		{
			name:  "violation-ech-clienthello-admitted",
			probe: RecordProbe{Domain: "api.allowed.example", Type: RecordA, Shape: ShapeDelivered, ClientHelloHasECH: true, ECHAdmitted: true},
			want:  []ViolationClass{ViolationECHClientHelloAdmitted},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckECHSuppression(c.probe)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "ech-https-svcb-suppression", declared, seen, sawControl)
}

// ── ROW 3 — session A ↛ B isolation / no-L2-path (D66) ──────────────────────

func TestRowSessionIsolation(t *testing.T) {
	declared := []ViolationClass{
		ViolationL2PathBetweenAgentTaps, ViolationIsolationInheritedFromInetDeny,
		ViolationBrIsolatedWithoutFlagAudit,
	}
	type tc struct {
		name  string
		probe IsolationProbe
		want  []ViolationClass
	}
	cases := []tc{
		{
			name:  "conforming-routed-tap-structural-no-l2-path",
			probe: IsolationProbe{TapA: "dstap-0", TapB: "dstap-1", Mechanism: MechRoutedTap, L2PathObserved: false},
			want:  nil,
		},
		{
			name:  "conforming-br-isolated-with-flag-audit",
			probe: IsolationProbe{TapA: "dstap-2", TapB: "dstap-3", Mechanism: MechBrIsolated, L2PathObserved: false, FlagAuditInPlace: true},
			want:  nil,
		},
		{
			name:  "violation-l2-path-between-agent-taps",
			probe: IsolationProbe{TapA: "dstap-4", TapB: "dstap-5", Mechanism: MechRoutedTap, L2PathObserved: true},
			want:  []ViolationClass{ViolationL2PathBetweenAgentTaps},
		},
		{
			name:  "violation-isolation-inherited-from-inet-deny",
			probe: IsolationProbe{TapA: "dstap-6", TapB: "dstap-7", Mechanism: MechInetDenyOnly, L2PathObserved: false},
			want:  []ViolationClass{ViolationIsolationInheritedFromInetDeny},
		},
		{
			name:  "violation-br-isolated-without-flag-audit",
			probe: IsolationProbe{TapA: "dstap-8", TapB: "dstap-9", Mechanism: MechBrIsolated, L2PathObserved: false, FlagAuditInPlace: false},
			want:  []ViolationClass{ViolationBrIsolatedWithoutFlagAudit},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckSessionIsolation(c.probe)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "session-a-not-b-no-l2-path", declared, seen, sawControl)
}

// ── ROW 4 — IPv6 closure holds while dormant + fe80 probe (D75) ─────────────

func TestRowV6Closure(t *testing.T) {
	declared := []ViolationClass{
		ViolationAAAADroppedNotNODATA, ViolationDormantV6ReachOpen,
		ViolationFe80ReachBetweenTaps,
	}
	type tc struct {
		name string
		clo  V6Closure
		want []ViolationClass
	}
	cases := []tc{
		{
			name: "conforming-aaaa-nodata-no-v6-reach-no-fe80",
			clo:  V6Closure{Domain: "api.allowed.example", AAAAShape: ShapeSuppressedNODATA, V6ReachOpenFromTap: false, Fe80ReachBetweenTaps: false},
			want: nil,
		},
		{
			name: "violation-aaaa-dropped-not-nodata",
			clo:  V6Closure{Domain: "api.allowed.example", AAAAShape: ShapeDroppedOrServfail, V6ReachOpenFromTap: false, Fe80ReachBetweenTaps: false},
			want: []ViolationClass{ViolationAAAADroppedNotNODATA},
		},
		{
			name: "violation-aaaa-delivered-dormant-reach",
			clo:  V6Closure{Domain: "api.allowed.example", AAAAShape: ShapeDelivered, V6ReachOpenFromTap: false, Fe80ReachBetweenTaps: false},
			want: []ViolationClass{ViolationDormantV6ReachOpen},
		},
		{
			name: "violation-v6-reach-open-from-tap",
			clo:  V6Closure{Domain: "api.allowed.example", AAAAShape: ShapeSuppressedNODATA, V6ReachOpenFromTap: true, Fe80ReachBetweenTaps: false},
			want: []ViolationClass{ViolationDormantV6ReachOpen},
		},
		{
			name: "violation-fe80-reach-between-taps",
			clo:  V6Closure{Domain: "api.allowed.example", AAAAShape: ShapeSuppressedNODATA, V6ReachOpenFromTap: false, Fe80ReachBetweenTaps: true},
			want: []ViolationClass{ViolationFe80ReachBetweenTaps},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckV6Closure(c.clo)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "ipv6-closure-dormant-fe80-probe", declared, seen, sawControl)
}

// ── ROW 5 — controls unreachable from the VM (doc 04 §5) ────────────────────

func TestRowControlsUnreachable(t *testing.T) {
	declared := []ViolationClass{
		ViolationControlEndpointReachable, ViolationControlEndpointObservable,
		ViolationControlEndpointModifiable,
	}
	type tc struct {
		name  string
		probe ControlProbe
		want  []ViolationClass
	}
	cases := []tc{
		{
			name:  "conforming-proxy-unreachable-unobservable",
			probe: ControlProbe{Tap: "dstap-0", Target: ControlProxy, Reachable: false, Observable: false},
			want:  nil,
		},
		{
			name:  "conforming-nftables-unreachable",
			probe: ControlProbe{Tap: "dstap-1", Target: ControlNFTables, Reachable: false, Observable: false},
			want:  nil,
		},
		{
			name:  "violation-policy-endpoint-reachable",
			probe: ControlProbe{Tap: "dstap-2", Target: ControlPolicy, Reachable: true, Observable: false, ModifyAccepted: false},
			want:  []ViolationClass{ViolationControlEndpointReachable},
		},
		{
			name:  "violation-identity-endpoint-observable",
			probe: ControlProbe{Tap: "dstap-3", Target: ControlIdentity, Reachable: false, Observable: true},
			want:  []ViolationClass{ViolationControlEndpointObservable},
		},
		{
			name:  "violation-nftables-modifiable",
			probe: ControlProbe{Tap: "dstap-4", Target: ControlNFTables, Reachable: true, Observable: false, ModifyAccepted: true},
			// reachable AND modifiable — both NAMED (a modifiable endpoint was necessarily reached).
			want: []ViolationClass{ViolationControlEndpointReachable, ViolationControlEndpointModifiable},
		},
	}

	seen := map[ViolationClass]bool{}
	sawControl := false
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckControlsUnreachable(c.probe)
			assertClasses(t, c.name, got, c.want)
		})
		if len(c.want) == 0 {
			sawControl = true
		}
		for _, v := range c.want {
			seen[v] = true
		}
	}
	coverageGate(t, "controls-unreachable-from-vm", declared, seen, sawControl)
}
