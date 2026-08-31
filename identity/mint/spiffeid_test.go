// SPDX-License-Identifier: Apache-2.0

// Acceptance tests for the typed SPIFFE-ID model + WorkloadAuthority seam
// (doc 16 §3.1; doc 05 §7 edge 5). These pin the two load-bearing correspondences
// the M3 SPIRE substrate swap relies on:
//
//   - Build(org, session) reproduces the legacy spiffeURI(org, session) output
//     BYTE-FOR-BYTE, and ParseSpiffeID(Build(org, session)) round-trips, so the
//     M1 own-CA name and any swapped-in SPIRE-backed name are produced by the SAME
//     helper (the naming is pure across the swap).
//   - The DEFAULT WorkloadAuthority installed by NewShim is the M1 own-CA impl, so
//     the swap is selectable beside the own-CA path, never a replacement.
//
// They are additive: no existing Validate/ca_m1/grpc_seam test is touched.
package mint

import (
	"testing"
	"time"
)

// fixedClock is a pinned clock for the seam tests, matching the established
// newTestShim time so these shims behave like every other test shim.
func fixedClock() time.Time { return time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC) }

// TestBuild_MatchesLegacySpiffeURI_ByteForByte asserts the typed Build helper and
// the legacy string-concatenation spiffeURI emit IDENTICAL bytes for the §3.1
// session name. This is the M1<->SPIFFE naming correspondence: spiffeURI now
// delegates to Build (jwt.go), so a regression in either drifts the URI SAN, the
// JWT `sub`, and the grant identity axis off the SPIRE-backed name.
func TestBuild_MatchesLegacySpiffeURI_ByteForByte(t *testing.T) {
	cases := []struct {
		org, session string
	}{
		{"acme", "01HVALIDULID0000000000000"},
		{"acme.example", "session-with-dashes"},
		{"org", ""},                   // empty session: still a well-formed prefix
		{"sub.domain.example", "x"},   // dotted trust domain
		{"o", "0123456789abcdef0123"}, // single-char org
	}
	for _, tc := range cases {
		legacy := "spiffe://" + tc.org + "/session/" + tc.session
		got := Build(tc.org, tc.session)
		if got != legacy {
			t.Errorf("Build(%q,%q)=%q, want byte-for-byte legacy %q", tc.org, tc.session, got, legacy)
		}
		// spiffeURI is the package-internal legacy helper Build is wired to replace;
		// it must agree too (the delegation contract in jwt.go).
		if uri := spiffeURI(tc.org, tc.session); uri != got {
			t.Errorf("spiffeURI(%q,%q)=%q != Build %q", tc.org, tc.session, uri, got)
		}
	}
}

// TestParseSpiffeID_RoundTrip asserts ParseSpiffeID(Build(org, session)) yields a
// SpiffeID whose String() reproduces the input exactly, and whose TrustDomain /
// Path decompose as §3.1 specifies (trust domain = org, path = /session/<uuid>).
func TestParseSpiffeID_RoundTrip(t *testing.T) {
	cases := []struct {
		org, session string
	}{
		{"acme", "01HVALIDULID0000000000000"},
		{"acme.example", "session-with-dashes"},
		{"sub.domain.example", "x"},
		{"o", "0123456789abcdef0123"},
	}
	for _, tc := range cases {
		uri := Build(tc.org, tc.session)
		id, err := ParseSpiffeID(uri)
		if err != nil {
			t.Fatalf("ParseSpiffeID(%q): unexpected error %v", uri, err)
		}
		if got := id.String(); got != uri {
			t.Errorf("round-trip: ParseSpiffeID(%q).String()=%q", uri, got)
		}
		if id.TrustDomain != tc.org {
			t.Errorf("TrustDomain=%q, want org %q", id.TrustDomain, tc.org)
		}
		if wantPath := "/session/" + tc.session; id.Path != wantPath {
			t.Errorf("Path=%q, want %q", id.Path, wantPath)
		}
	}
}

// TestParseSpiffeID_Rejects asserts the parser fails closed on non-spiffe schemes
// and empty trust domains (the SPIFFE-ID spec invariants doc 16 §3.1 adopts). The
// format is owned here, not delegated to net/url, so these MUST reject.
func TestParseSpiffeID_Rejects(t *testing.T) {
	bad := []string{
		"",                       // empty
		"https://acme/session/x", // wrong scheme
		"spiffe:/acme/session/x", // malformed authority marker
		"spiffe://",              // empty trust domain, no path
		"spiffe:///session/x",    // empty trust domain, has path
	}
	for _, uri := range bad {
		if id, err := ParseSpiffeID(uri); err == nil {
			t.Errorf("ParseSpiffeID(%q) accepted, got %+v; want error", uri, id)
		}
	}
}

// TestParseSpiffeID_BareTrustDomain asserts a trust-domain-only ID (no path) parses
// and round-trips with an empty Path — the SpiffeID model is a general SPIFFE-ID
// model, not only the session shape.
func TestParseSpiffeID_BareTrustDomain(t *testing.T) {
	id, err := ParseSpiffeID("spiffe://acme")
	if err != nil {
		t.Fatalf("ParseSpiffeID bare trust domain: %v", err)
	}
	if id.TrustDomain != "acme" || id.Path != "" {
		t.Errorf("bare trust domain: got %+v, want {acme }", id)
	}
	if got := id.String(); got != "spiffe://acme" {
		t.Errorf("bare round-trip: got %q", got)
	}
}

// TestNewShim_DefaultsToOwnCAWorkloadAuthority asserts the DEFAULT authority is the
// M1 own-CA impl (doc 16 §2): the swap is selectable BESIDE the own-CA path, never
// a replacement. Absent WithWorkloadAuthority, NewShim must install
// *ownCAWorkloadAuthority.
func TestNewShim_DefaultsToOwnCAWorkloadAuthority(t *testing.T) {
	shim, err := NewShim(WithClock(fixedClock))
	if err != nil {
		t.Fatal(err)
	}
	a, ok := shim.workloadAuthority.(*ownCAWorkloadAuthority)
	if !ok {
		t.Fatalf("default workloadAuthority = %T, want *ownCAWorkloadAuthority", shim.workloadAuthority)
	}
	if a.shim != shim {
		t.Errorf("ownCAWorkloadAuthority.shim back-reference not wired to its shim")
	}
}

// TestWithWorkloadAuthority_Overrides asserts WithWorkloadAuthority swaps the
// substrate in beside the own-CA default — the seam is genuinely fakeable, the
// DI knob the M3 SPIRE substrate uses (D50 synthetic posture; no live SPIRE).
func TestWithWorkloadAuthority_Overrides(t *testing.T) {
	fake := &fakeWorkloadAuthority{}
	shim, err := NewShim(WithClock(fixedClock), WithWorkloadAuthority(fake))
	if err != nil {
		t.Fatal(err)
	}
	if shim.workloadAuthority != fake {
		t.Fatalf("WithWorkloadAuthority did not install the fake (got %T)", shim.workloadAuthority)
	}
}

// fakeWorkloadAuthority is a synthetic WorkloadAuthority proving the seam is
// fakeable from documented wire shapes (D50) — it implements the interface and
// records nothing live. It exists only to prove the swap-in path compiles + binds.
type fakeWorkloadAuthority struct{}

func (f *fakeWorkloadAuthority) MintWorkload(WorkloadMintRequest) (WorkloadMintResult, error) {
	return WorkloadMintResult{}, nil
}

func (f *fakeWorkloadAuthority) VerifyPresented([]byte, string, time.Time) (jwtClaims, error) {
	return jwtClaims{}, nil
}
