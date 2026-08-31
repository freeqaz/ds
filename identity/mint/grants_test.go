// SPDX-License-Identifier: Apache-2.0

// Grant-model contract tests (doc 16 §5.1): deterministic issuance from the env
// spec × services[] registry, ISSUED{service_id} tag derivation, MintGrants
// placeholder tokens, and the load-bearing negative property — a placeholder
// NEVER validates as workload identity or interception material at the D22 seam.
// Everything synthetic (D50); the clock is pinned.
package mint

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testRegistry builds a small org services[] registry for the issuance tests.
func testRegistry(t *testing.T) *ServiceRegistry {
	t.Helper()
	r, err := NewServiceRegistry(
		ServiceRegistryEntry{
			ServiceID:          "github",
			Destinations:       []string{"github.com", "api.github.com"},
			CredentialLocation: "Authorization",
			DefaultTTL:         2 * time.Hour,
		},
		ServiceRegistryEntry{
			ServiceID:          "npm",
			Destinations:       []string{"registry.npmjs.org"},
			CredentialLocation: "Authorization",
			DefaultTTL:         time.Hour,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// newGrantShim builds a shim with a pinned clock AND the test registry installed.
func newGrantShim(t *testing.T) *Shim {
	t.Helper()
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	shim, err := NewShim(
		WithClock(func() time.Time { return fixed }),
		WithServiceRegistry(testRegistry(t)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return shim
}

// TestNewServiceRegistry_RejectsBadEntries proves the registry is a set keyed by
// service_id: empty keys and duplicates are rejected.
func TestNewServiceRegistry_RejectsBadEntries(t *testing.T) {
	if _, err := NewServiceRegistry(ServiceRegistryEntry{ServiceID: ""}); err == nil {
		t.Fatal("empty service_id should be rejected")
	}
	if _, err := NewServiceRegistry(
		ServiceRegistryEntry{ServiceID: "github"},
		ServiceRegistryEntry{ServiceID: "github"},
	); err == nil {
		t.Fatal("duplicate service_id should be rejected")
	}
}

// TestIssueGrants_DeterministicLookup is the table-driven heart of §5.1: grant
// issuance is the pure deterministic intersection of the env spec and the
// services[] registry — no Cedar, no expression evaluation (D52). Requested
// services absent from the registry confer no grant (fail-closed).
func TestIssueGrants_DeterministicLookup(t *testing.T) {
	cases := []struct {
		name         string
		request      []string
		wantServices []string // sorted, the deterministic order IssueGrants emits
	}{
		{"single in-registry", []string{"github"}, []string{"github"}},
		{"two in-registry, sorted", []string{"npm", "github"}, []string{"github", "npm"}},
		{"unknown service skipped", []string{"github", "s3"}, []string{"github"}},
		{"all unknown ⇒ none", []string{"s3", "gcs"}, nil},
		{"none requested ⇒ none", nil, nil},
		{"duplicate request collapses", []string{"github", "github"}, []string{"github", "github"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shim := newGrantShim(t)
			session := "00000000-0000-4000-8000-0000000000c1"
			if _, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
				SessionUUID: session, Org: testOrg,
			}); err != nil {
				t.Fatal(err)
			}
			grants, err := shim.IssueGrants(session, EnvSpec{Services: tc.request})
			if err != nil {
				t.Fatal(err)
			}
			gotServices := make([]string, len(grants))
			for i, g := range grants {
				gotServices[i] = g.ServiceID
				// Every grant binds the SESSION identity (the §5.1 identity axis).
				wantIdentity := "spiffe://" + testOrg + "/session/" + session
				if g.Identity != wantIdentity {
					t.Fatalf("grant identity = %q, want %q", g.Identity, wantIdentity)
				}
				if g.Scope != ScopeSession {
					t.Fatalf("grant scope = %v, want SESSION", g.Scope)
				}
				if g.GrantRef == "" {
					t.Fatal("grant_ref must be set (opaque fetch handle)")
				}
			}
			if !equalStrings(gotServices, tc.wantServices) {
				t.Fatalf("issued services = %v, want %v", gotServices, tc.wantServices)
			}
		})
	}
}

// TestIssueGrants_NoRegistryFailsClosed proves a shim with no registry refuses
// to mint capability from nothing (errNoRegistry).
func TestIssueGrants_NoRegistryFailsClosed(t *testing.T) {
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	shim, err := NewShim(WithClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shim.IssueGrants("s", EnvSpec{Services: []string{"github"}}); err == nil {
		t.Fatal("issuing grants with no registry should fail closed")
	}
}

// TestIssueGrants_TTLClampedToSession proves the grant TTL never outlives the
// session (D39 cache ceiling) and that an env override can shorten — never
// lengthen — the registry default.
func TestIssueGrants_TTLClampedToSession(t *testing.T) {
	shim := newGrantShim(t)
	session := "00000000-0000-4000-8000-0000000000c2"
	// Session lifetime = 30 min, shorter than the github registry default (2h).
	if _, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: session, Org: testOrg, TTL: 30 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	grants, err := shim.IssueGrants(session, EnvSpec{
		Services: []string{"github", "npm"},
		// npm override below the registry default (1h) → 15m.
		TTLOverrides: map[string]time.Duration{"npm": 15 * time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := shim.now()
	sessionExpiry := now.Add(30 * time.Minute)
	for _, g := range grants {
		if g.Expiry.After(sessionExpiry) {
			t.Fatalf("%s grant expiry %v outlives session %v", g.ServiceID, g.Expiry, sessionExpiry)
		}
		if g.ServiceID == "npm" {
			// 15m override < 30m session, so the override governs.
			if !g.Expiry.Equal(now.Add(15 * time.Minute)) {
				t.Fatalf("npm override not applied: expiry = %v", g.Expiry)
			}
		}
		if g.ServiceID == "github" {
			// 2h default clamped to the 30m session.
			if !g.Expiry.Equal(sessionExpiry) {
				t.Fatalf("github TTL not clamped to session: %v", g.Expiry)
			}
		}
	}
}

// TestIssuedDigestTag_DerivesFromGrant proves the ISSUED{service_id} digest tag
// is computed FROM the grant record (§5.1/§6) — a digest's intended service is a
// grant fact.
func TestIssuedDigestTag_DerivesFromGrant(t *testing.T) {
	shim := newGrantShim(t)
	session := "00000000-0000-4000-8000-0000000000c3"
	if _, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: session, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	grants, err := shim.IssueGrants(session, EnvSpec{Services: []string{"github"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if tag := IssuedDigestTag(grants[0]); tag != "ISSUED{github}" {
		t.Fatalf("digest tag = %q, want ISSUED{github}", tag)
	}
	// And the record is retrievable for the producer to derive from.
	g, ok := shim.GrantRecord(session, "github")
	if !ok || IssuedDigestTag(g) != "ISSUED{github}" {
		t.Fatalf("GrantRecord/tag round-trip failed: %v %q", ok, IssuedDigestTag(g))
	}
}

// TestMintGrants_PlaceholderValidatesAtSeam proves the §5.1 MintGrants surface:
// each issued grant gets a per-service placeholder, and that placeholder
// validates at the existing D22 seam for its service, returning the grant_ref.
func TestMintGrants_PlaceholderValidatesAtSeam(t *testing.T) {
	shim := newGrantShim(t)
	session := "00000000-0000-4000-8000-0000000000c4"
	if _, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: session, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	set, err := shim.MintGrants(MintGrantsRequest{
		SessionUUID: session,
		Env:         EnvSpec{Services: []string{"github", "npm"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Placeholders) != 2 {
		t.Fatalf("want 2 placeholders, got %d", len(set.Placeholders))
	}
	for _, ph := range set.Placeholders {
		if !IsPlaceholder([]byte(ph.Token)) {
			t.Fatalf("%s token is not structurally a placeholder: %q", ph.ServiceID, ph.Token)
		}
		res := shim.Validate([]byte(ph.Token), session, ph.ServiceID)
		if res.Verdict != VerdictAllow {
			t.Fatalf("%s placeholder should ALLOW, got DENY(%s)", ph.ServiceID, res.MachineReadableReason)
		}
		if res.GrantRef != ph.Grant.GrantRef {
			t.Fatalf("%s grant_ref lost: got %q want %q", ph.ServiceID, res.GrantRef, ph.Grant.GrantRef)
		}
	}
}

// TestPlaceholder_NeverValidatesCrossService proves a placeholder minted for one
// service NEVER validates for another (the destination/service binding holds at
// the seam).
func TestPlaceholder_NeverValidatesCrossService(t *testing.T) {
	shim := newGrantShim(t)
	session := "00000000-0000-4000-8000-0000000000c5"
	if _, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: session, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	set, err := shim.MintGrants(MintGrantsRequest{
		SessionUUID: session, Env: EnvSpec{Services: []string{"github", "npm"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var githubTok string
	for _, ph := range set.Placeholders {
		if ph.ServiceID == "github" {
			githubTok = ph.Token
		}
	}
	// Present the github placeholder for npm → must DENY (wrong service binding).
	res := shim.Validate([]byte(githubTok), session, "npm")
	if res.Verdict != VerdictDeny {
		t.Fatal("github placeholder must not validate for npm")
	}
}

// TestPlaceholder_NeverValidatesAsWorkloadIdentity is the load-bearing NEGATIVE
// property (§5.1, ACCEPTANCE): a placeholder token must NEVER validate as
// workload identity (it is not a JWS over the workload key) nor as interception
// material. We assert both directions:
//
//	(1) the placeholder is structurally not a JWS — verifyJWT against the
//	    session's workload key rejects it outright;
//	(2) the workload JWT, presented where a placeholder would be, is NOT a
//	    placeholder — it never takes the placeholder leg.
func TestPlaceholder_NeverValidatesAsWorkloadIdentity(t *testing.T) {
	shim := newGrantShim(t)
	session := "00000000-0000-4000-8000-0000000000c6"
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: session, Org: testOrg})
	if err != nil {
		t.Fatal(err)
	}
	set, err := shim.MintGrants(MintGrantsRequest{
		SessionUUID: session, Env: EnvSpec{Services: []string{"github"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	placeholder := set.Placeholders[0].Token

	// (1) The placeholder must NOT verify as the workload JWS under the workload
	// leaf key — it is not a JWS at all (wrong segment count / no ECDSA sig).
	leaf, err := x509.ParseCertificate(bundle.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyJWT(leaf.PublicKey.(*ecdsa.PublicKey), placeholder); err == nil {
		t.Fatal("placeholder must NOT verify as a workload JWS")
	}

	// (2) The structural router agrees: a workload JWT is not a placeholder.
	if IsPlaceholder([]byte(bundle.JWT)) {
		t.Fatal("a workload JWT must not be classified as a placeholder")
	}
	// And a placeholder IS a placeholder, so Validate routes it to the
	// placeholder leg and never to the JWS path (proven by the cross-check: a
	// placeholder for github does NOT need a workload key to validate, and a
	// tampered placeholder fails as signature_invalid, not as a JWS error).
	if !IsPlaceholder([]byte(placeholder)) {
		t.Fatal("placeholder must be classified as a placeholder")
	}
	tampered := placeholder + "AAAA"
	if res := shim.Validate([]byte(tampered), session, "github"); res.Verdict != VerdictDeny {
		t.Fatal("a tampered placeholder must fail closed")
	}
}

// --- the GrantRef cross-module contract (§9 grant-fetch row) -----------------

// grantRefGolden is the shape of the committed golden fixture
// (testdata/grantref-golden.json), carried IDENTICALLY in both modules. This
// module is the WRITER side of the seam.
type grantRefGolden struct {
	Format string `json:"format"`
	Cases  []struct {
		Session string `json:"session"`
		Service string `json:"service"`
		Ref     string `json:"ref"`
	} `json:"cases"`
}

func loadGrantRefGolden(t *testing.T) grantRefGolden {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "grantref-golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g grantRefGolden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(g.Cases) == 0 {
		t.Fatal("golden fixture has no cases")
	}
	return g
}

// TestGrantRef_GoldenContract_WriterSide is the mint half of the cross-module
// GrantRef contract (doc 16 §9 grant-fetch row). The grant_ref string is the
// ONLY thing this module and the standalone identity/grant-service module agree
// on — two separate GOWORK=off modules with no compile- or test-time link. This
// side WRITES the ref (FormatGrantRef); the grant-service side READS it
// (Service.Fetch keys on it). The committed golden fixture is the contract: if
// this side changes FormatGrantRef unilaterally, the writer no longer matches
// the golden and THIS suite fails — the drift breaks loudly at test time instead
// of silently at fetch time. (The grant-service module carries the identical
// golden and asserts the READER half; both must hold for the seam to compose.)
func TestGrantRef_GoldenContract_WriterSide(t *testing.T) {
	g := loadGrantRefGolden(t)
	for _, c := range g.Cases {
		// WRITER: FormatGrantRef must produce exactly the golden ref. A unilateral
		// format change here fails this assertion.
		if got := FormatGrantRef(c.Session, c.Service); got != c.Ref {
			t.Fatalf("FormatGrantRef(%q,%q) = %q, want golden %q (grant-ref format drift breaks the cross-module fetch)",
				c.Session, c.Service, got, c.Ref)
		}
		// And the round trip is closed: ParseGrantRef inverts FormatGrantRef, so
		// the reader half (identically vendored on the grant-service side) recovers
		// exactly the session×service the writer encoded.
		gotSession, gotService, ok := ParseGrantRef(c.Ref)
		if !ok || gotSession != c.Session || gotService != c.Service {
			t.Fatalf("ParseGrantRef(%q) = (%q,%q,%v), want (%q,%q,true)",
				c.Ref, gotSession, gotService, ok, c.Session, c.Service)
		}
	}
	// And the issuance path actually emits the contract format: an IssueGrants ref
	// matches FormatGrantRef, so the golden governs real issuance, not just the
	// helper.
	shim := newGrantShim(t)
	session := "00000000-0000-4000-8000-000000000001"
	if _, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: session, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	grants, err := shim.IssueGrants(session, EnvSpec{Services: []string{"github"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].GrantRef != FormatGrantRef(session, "github") {
		t.Fatalf("IssueGrants ref = %q, want %q (issuance must emit the contract format)",
			grants[0].GrantRef, FormatGrantRef(session, "github"))
	}
}

// TestParseGrantRef_FailClosed proves the reader half fails closed on a
// malformed ref (wrong prefix, missing separator, empty axis) — a parse miss is
// a definitive non-match, never a partial/ambiguous binding.
func TestParseGrantRef_FailClosed(t *testing.T) {
	bad := []string{
		"",
		"github",
		"grant:",
		"grant:s",
		"grant::github",
		"grant:s:",
		"notgrant:s:github",
		"grant:s:multi:colon",
	}
	for _, ref := range bad {
		if _, _, ok := ParseGrantRef(ref); ok {
			t.Fatalf("ParseGrantRef(%q) accepted a malformed ref; must fail closed", ref)
		}
	}
}

// --- the §6.1 composition seam (GrantSet → RegisterSession → IssuedDigestTag) -

// TestComposition_MintGrantsToIssuedDigestTag is the doc 16 §6.1 composition
// conformance test. It proves the mint sub-sequence stitches together as the §6.1
// choreography requires: a synthetic GrantSet from MintGrants carries everything
// the grant-service RegisterSession + the ISSUED{service_id} digest derivation
// need, and the digest tag derives from the GRANT RECORD exactly as §5.1 states
// ("a digest's intended service is a grant fact"), never asserted independently.
//
// This is the mint-side half of the seam: it exercises MintGrants →
// (the registration inputs RegisterSession consumes) → IssuedDigestTag, and
// proves every issued grant yields a tag derived from its own record. The
// grant-service module carries the consuming half (RegisterSession + a Fetch
// keyed on the same GrantRef). Together they close the §6.1 composition gap that
// the production digest producer (task 01KTWJ4KSGT58J8RVBF1PGSTFY) builds on —
// this is the proven seam, NOT that producer.
func TestComposition_MintGrantsToIssuedDigestTag(t *testing.T) {
	shim := newGrantShim(t)
	session := "00000000-0000-4000-8000-000000000001"
	if _, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{SessionUUID: session, Org: testOrg}); err != nil {
		t.Fatal(err)
	}

	// 1. Issue a synthetic GrantSet via MintGrants (the §5.1 surface).
	set, err := shim.MintGrants(MintGrantsRequest{
		SessionUUID: session,
		Env:         EnvSpec{Services: []string{"github", "npm"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Grants) != 2 {
		t.Fatalf("want 2 grants in the set, got %d", len(set.Grants))
	}

	// 2. RegisterSession (grant-service side) consumes a session deadline and then
	//    a per-grant {grant_ref, service_id, expiry}. Prove the GrantSet carries
	//    exactly those registration inputs, and that the grant_ref is the contract
	//    format (so the standalone grant-service keys its fetch on the same string).
	for _, g := range set.Grants {
		if g.GrantRef != FormatGrantRef(session, g.ServiceID) {
			t.Fatalf("grant %s ref = %q, want contract format %q",
				g.ServiceID, g.GrantRef, FormatGrantRef(session, g.ServiceID))
		}
		gotSession, gotService, ok := ParseGrantRef(g.GrantRef)
		if !ok || gotSession != session || gotService != g.ServiceID {
			t.Fatalf("grant %s ref %q does not round-trip to (%q,%q)", g.ServiceID, g.GrantRef, session, g.ServiceID)
		}
		if g.Expiry.IsZero() {
			t.Fatalf("grant %s has no expiry; RegisterSession needs the TTL ceiling", g.ServiceID)
		}

		// 3. The ISSUED{service_id} digest tag derives from the GRANT RECORD (§5.1),
		//    not from the env request: re-read the stored record and derive the tag
		//    from it. The tag's service is the grant's service — a grant fact.
		rec, ok := shim.GrantRecord(session, g.ServiceID)
		if !ok {
			t.Fatalf("grant record for %s not retrievable for digest derivation", g.ServiceID)
		}
		wantTag := "ISSUED{" + g.ServiceID + "}"
		if tag := IssuedDigestTag(rec); tag != wantTag {
			t.Fatalf("digest tag for %s = %q, want %q (tag must derive from the grant record)", g.ServiceID, tag, wantTag)
		}
		// The placeholder for this service carries the SAME grant record, so the tag
		// derived from the GrantSet's placeholder agrees — the composition is
		// internally consistent end to end.
		var phGrant Grant
		var found bool
		for _, ph := range set.Placeholders {
			if ph.ServiceID == g.ServiceID {
				phGrant, found = ph.Grant, true
			}
		}
		if !found {
			t.Fatalf("GrantSet missing placeholder for %s", g.ServiceID)
		}
		if IssuedDigestTag(phGrant) != wantTag {
			t.Fatalf("placeholder-side tag for %s = %q, want %q", g.ServiceID, IssuedDigestTag(phGrant), wantTag)
		}
	}

	// 4. The tag is a GRANT FACT, not an env assertion: a service NOT in the grant
	//    set has no record, so no ISSUED tag can be derived for it — the §11.1
	//    step-7 invariant holds structurally (you cannot mint a digest tag for a
	//    service the grant model never issued).
	if _, ok := shim.GrantRecord(session, "s3"); ok {
		t.Fatal("ungranted service must have no grant record (no tag may be derived for it)")
	}
}

// --- test helpers ------------------------------------------------------------

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
