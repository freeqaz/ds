// SPDX-License-Identifier: Apache-2.0

package nftgate

// default_deny_test.go is the FIRST guardrail-assurance test of the M0 guardrail
// statement (doc 06 §3c / doc 05 §5): the default-deny boundary actually holds —
// even the walking skeleton cannot exfiltrate — BEFORE any credentials worth
// stealing exist. Default-deny outbound (D4) is THE M0 row: a non-allowlisted
// destination is denied at L3/4 (NFT-1, before the proxy) AND via the egress
// gateway (TLS-1), and the deny is the DEFAULT — only an explicitly-admitted
// (domain, IP) pair gets out.
//
// This complements the broader fixture-driven suite in nftgate_test.go (which
// drives EVERY M0 row from the synthetic corpus). Here we (1) state the
// default-deny claim directly and exhaustively over both legs, and (2) carry the
// load-bearing NEGATIVE CONTROL the acceptance criterion demands: a deliberately
// BROKEN boundary (a posture whose Dispose admits everything) MUST make the
// default-deny assertion FAIL. Without that control the assertion could pass
// vacuously against any model; with it, a regression that silently widens the
// boundary to allow-by-default is caught.
//
// Synthetic + offline (D50): this asserts the documented boundary posture (the
// spec read of doc 09 §9 / doc 11 §6), never a live ds-nft ruleset. The live half
// (live_test.go, DS_NFTGATE_LIVE=1) drives the SAME model against a real boundary
// and is a deferred manual pass (no CAP_NET_ADMIN / live nft in CI).

import "testing"

// defaultDenyVerdict is the disposition the model produces for one egress attempt
// plus whether the boundary HELD (the attempt did NOT get out). It is the single
// place the "held vs leaked" judgement lives, so the positive assertion and the
// negative control share one definition of what "default-deny holds" means.
type defaultDenyVerdict struct {
	disp   Disposition
	leaked bool // true iff the attempt was admitted (DispAllow) — i.e. it escaped
}

// disposer is the narrow face the default-deny assertion runs against: anything
// that can dispose of an egress attempt. Both the real Posture and the broken
// allow-everything control below satisfy it, so the SAME assertion can be pointed
// at either — which is exactly what makes the negative control meaningful (it
// proves the assertion fails for a boundary that does not hold).
type disposer interface {
	Dispose(a Attempt) Disposition
}

// judgeDefaultDeny disposes of an attempt through the given boundary and reports
// whether it leaked. An attempt "leaks" iff it is admitted (DispAllow) — any deny
// disposition (drop at L3/4, refuse at the gateway, redirect, reject, …) means the
// default-deny boundary held.
func judgeDefaultDeny(d disposer, a Attempt) defaultDenyVerdict {
	disp := d.Dispose(a)
	return defaultDenyVerdict{disp: disp, leaked: disp == DispAllow}
}

// exfilAttempts is the set of non-allowlisted egress attempts the M0 skeleton
// might make to exfiltrate — across BOTH default-deny legs. None of these targets
// is in the reference posture's admit set, so against a boundary that HOLDS every
// one must be denied; against a broken (allow-everything) boundary every one
// leaks. These are the documented dimensions, not an attack taxonomy: each is a
// thing a misbehaving VM does that the default-deny boundary must dispose of.
func exfilAttempts() []Attempt {
	return []Attempt{
		// L3/4 leg (NFT-1, before the proxy): raw connects to non-allowlisted IPs.
		{Name: "l34-public-unadmitted", Kind: AttemptL34Direct, DstIP: "198.51.100.7", Why: "raw L3/4 connect to a non-allowlisted IP must be dropped by NFT-1 default-drop"},
		{Name: "l34-other-public-unadmitted", Kind: AttemptL34Direct, DstIP: "192.0.2.55", Why: "a second non-allowlisted IP — the deny is the default, not a single blocklist entry"},
		// Via-proxy leg (TLS-1): SNIs for non-admitted domains, including the
		// shared-CDN-IP hole (an unadmitted domain riding an IP admitted for ANOTHER
		// domain must still be refused).
		{Name: "proxy-unadmitted-domain", Kind: AttemptProxiedTLS, Domain: "exfil.notallowed.example", DstIP: "198.51.100.7", Why: "TLS to a non-allowlisted domain must be refused at the egress gateway (TLS-1)"},
		{Name: "proxy-unadmitted-domain-on-shared-admitted-ip", Kind: AttemptProxiedTLS, Domain: "exfil.notallowed.example", DstIP: "203.0.113.10", Why: "an unadmitted domain on an IP admitted for ANOTHER domain must still be refused (the shared-CDN-IP hole stays closed)"},
	}
}

// TestDefaultDenyHolds is the M0 guardrail statement, stated directly: against the
// documented reference posture, EVERY non-allowlisted exfiltration attempt is
// denied — the skeleton cannot get out by default. The allowlisted controls (the
// one admitted (domain, IP) pair) prove the deny is the DEFAULT, not a blanket
// block that would make the assertion trivially true.
func TestDefaultDenyHolds(t *testing.T) {
	p := referencePosture()

	// Every non-allowlisted attempt must be denied (the boundary holds).
	for _, a := range exfilAttempts() {
		v := judgeDefaultDeny(p, a)
		if v.leaked {
			t.Errorf("default-deny BREACHED: attempt %q (%s) was ADMITTED (%q) — the skeleton exfiltrated\n  why it must be denied: %s",
				a.Name, a.Kind, v.disp, a.Why)
		}
	}

	// Controls: the deny is the DEFAULT, not a blanket block. The single admitted
	// (domain, IP) pair gets out on both legs, so a passing default-deny assertion
	// is not the degenerate "deny everything" case.
	admittedL34 := Attempt{Kind: AttemptL34Direct, DstIP: "203.0.113.10"}
	if v := judgeDefaultDeny(p, admittedL34); v.leaked != true {
		t.Errorf("control: an admitted IP must be allowed at L3/4 (else the deny is a blanket block, not a default) — disp=%q", v.disp)
	}
	admittedProxy := Attempt{Kind: AttemptProxiedTLS, Domain: "api.allowed.example", DstIP: "203.0.113.10"}
	if v := judgeDefaultDeny(p, admittedProxy); v.leaked != true {
		t.Errorf("control: an admitted (domain, IP) pair must be allowed via the gateway — disp=%q", v.disp)
	}
}

// allowEverythingBoundary is a deliberately BROKEN boundary: it disposes of EVERY
// attempt as DispAllow — the default-deny guarantee inverted to allow-by-default.
// It is the negative control's stand-in for a regression that silently widens the
// boundary (an NFT-1 base chain that defaults to accept, a TLS-1 admission check
// that waves everything through). It satisfies the same disposer face as Posture.
type allowEverythingBoundary struct{}

func (allowEverythingBoundary) Dispose(Attempt) Disposition { return DispAllow }

// TestDefaultDenyNegativeControl is the load-bearing proof that TestDefaultDenyHolds
// is NOT vacuous: the SAME exfiltration attempts, judged against a BROKEN
// allow-everything boundary, MUST be detected as leaks. If this control did not
// detect the breach, the default-deny assertion above would pass for any boundary
// — including one that does not hold — and the M0 guardrail statement would be
// meaningless. This is the "prove it by a negative control" acceptance criterion:
// the guardrail test FAILS if default-deny is broken.
func TestDefaultDenyNegativeControl(t *testing.T) {
	broken := allowEverythingBoundary{}

	attempts := exfilAttempts()
	if len(attempts) == 0 {
		t.Fatal("no exfiltration attempts defined; the negative control would be vacuous")
	}

	// Against the broken boundary, EVERY exfiltration attempt must be observed to
	// leak — i.e. the same judgement TestDefaultDenyHolds applies would FAIL for
	// every one of them. This is what proves the positive test has teeth.
	for _, a := range attempts {
		v := judgeDefaultDeny(broken, a)
		if !v.leaked {
			t.Fatalf("negative control is itself broken: attempt %q against an allow-everything boundary "+
				"was NOT detected as a leak (disp=%q) — the default-deny assertion cannot be trusted to catch a real breach",
				a.Name, v.disp)
		}
	}

	// And the converse: those same attempts judged against the REAL posture must
	// NOT leak. Stated here too so this one test fully captures "holds against the
	// real boundary, fails against a broken one" — the negative control proves the
	// difference is real, not an artifact of the attempt set.
	p := referencePosture()
	for _, a := range attempts {
		if v := judgeDefaultDeny(p, a); v.leaked {
			t.Fatalf("attempt %q leaked against the REAL posture (disp=%q) — default-deny does not hold", a.Name, v.disp)
		}
	}
}
