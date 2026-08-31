// SPDX-License-Identifier: Apache-2.0

// Acceptance tests for the M3 SPIRE-backed WorkloadAuthority (spire_authority.go)
// over the synthetic SPIRE-Workload-API-shaped fake (spire_fake.go), driven through
// the frozen D24 Validate contract a Shim built WithSpireAuthority(fake) exposes
// (mint.go).
//
// These prove the doc 05 §7 edge-5 invariant — "a substrate swap behind a frozen
// contract, not a rebuild": the SPIRE substrate satisfies the SAME Validate contract
// the M1 own-CA substrate satisfies, FIELD-FOR-FIELD, with NO contract change. The
// own-CA acceptance suite (mint_test.go) asserts the own-CA leg; this file asserts the
// SPIRE leg with the IDENTICAL request/verdict shapes, so the swap is observably pure:
//
//   - PARITY: WithSpireAuthority(fake) mints the §3.1 workload identity whose SPIFFE
//     URI SAN is spiffe://<org>/session/<uuid>, byte-identical to the own-CA path
//     (same Build helper, same claim set, same JWS shape), and the leaf chains to the
//     trust bundle the SVIDSource publishes (the SPIRE authenticity root).
//   - ALLOW: a fresh granted credential Validates ALLOW.
//   - DENY (fail-closed): revoked / unknown-session / out-of-grant / wrong-identity
//     (a credential that chains to the bundle but names the wrong SPIFFE ID) /
//     malformed all DENY with the right D77 machine-readable reason.
//
// Everything synthetic (D50): the fake's trust-domain CA, every leaf key, every SVID
// is synthetic — no live SPIRE, no Workload-API socket, no go-spiffe dependency.
package mint

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// newSpireTestShim builds a Shim on the SPIRE substrate (WithSpireAuthority over the
// synthetic fake) with the SAME pinned clock newTestShim uses, so the SPIRE-leg
// assertions line up field-for-field with the own-CA suite. The fake shares the
// shim's clock so SVID validity and Validate freshness agree deterministically.
func newSpireTestShim(t *testing.T) *Shim {
	t.Helper()
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }
	src, err := NewFakeSVIDSource(clock)
	if err != nil {
		t.Fatalf("NewFakeSVIDSource: %v", err)
	}
	shim, err := NewShim(WithClock(clock), WithSpireAuthority(src))
	if err != nil {
		t.Fatalf("NewShim WithSpireAuthority: %v", err)
	}
	return shim
}

// TestSpireAuthority_MintParityWithOwnCA proves the SPIRE substrate emits the SAME
// §3.1 workload identity the own-CA substrate emits: the SPIFFE URI SAN, the JWT
// `sub`, and the full claim set are byte-identical, and the X.509-SVID leaf chains to
// the trust bundle the SVIDSource publishes (the SPIRE authenticity check the own-CA
// path did against the per-session recorded key). The swap is pure: same Build helper
// upstream of the authority, so the name never drifts.
func TestSpireAuthority_MintParityWithOwnCA(t *testing.T) {
	// Own-CA baseline: mint the SAME request on the default substrate.
	ownCA := newTestShim(t)
	req := WorkloadIdentityRequest{
		SessionUUID:   testSession,
		LaunchingUser: "idp-subject-xyz",
		Org:           testOrg,
		RepoBranch:    "acme/app@main",
		Runtime:       "claude-code",
		ParentSession: "00000000-0000-4000-8000-0000000000pp",
	}
	ownBundle, err := ownCA.MintWorkloadIdentity(req)
	if err != nil {
		t.Fatalf("own-CA mint: %v", err)
	}

	// SPIRE substrate: mint the IDENTICAL request.
	spire := newSpireTestShim(t)
	spireBundle, err := spire.MintWorkloadIdentity(req)
	if err != nil {
		t.Fatalf("spire mint: %v", err)
	}

	// PARITY (1): the §3.1 SPIFFE URI SAN is byte-identical across substrates — the
	// correspondence the pure swap relies on (same Build helper upstream).
	wantURI := "spiffe://" + testOrg + "/session/" + testSession
	if ownBundle.SPIFFEURI != wantURI {
		t.Fatalf("own-CA spiffe uri = %q, want %q", ownBundle.SPIFFEURI, wantURI)
	}
	if spireBundle.SPIFFEURI != ownBundle.SPIFFEURI {
		t.Fatalf("spire spiffe uri = %q, want own-CA %q (swap not pure)", spireBundle.SPIFFEURI, ownBundle.SPIFFEURI)
	}

	// PARITY (2): the X.509-SVID leaf carries EXACTLY the §3.1 URI SAN as its sole URI.
	leaf, err := x509.ParseCertificate(spireBundle.CertDER)
	if err != nil {
		t.Fatalf("parse spire svid leaf: %v", err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != wantURI {
		t.Fatalf("spire leaf URI SAN = %v, want sole [%s]", leaf.URIs, wantURI)
	}

	// PARITY (3): the parallel JWS verifies against the SVID leaf's OWN key and carries
	// the SAME §3.1 claim set the own-CA path stamps — sub = the SPIFFE URI, the full
	// identity axis, service_principal reserved-false.
	claims, err := verifyJWT(leaf.PublicKey.(*ecdsa.PublicKey), spireBundle.JWT)
	if err != nil {
		t.Fatalf("spire jws verify against leaf key: %v", err)
	}
	if claims.Subject != wantURI {
		t.Fatalf("spire jwt sub = %q, want spiffe uri %q", claims.Subject, wantURI)
	}
	if claims.SessionUUID != testSession || claims.LaunchingUser != "idp-subject-xyz" ||
		claims.Org != testOrg || claims.RepoBranch != "acme/app@main" ||
		claims.Runtime != "claude-code" || claims.ParentSession != "00000000-0000-4000-8000-0000000000pp" {
		t.Fatalf("spire jwt claim set drifted from own-CA: %+v", claims)
	}
	if claims.ServicePrincipal {
		t.Fatal("service_principal must be false (agent face, reserved marker only)")
	}

	// AUTHENTICITY: the SVID leaf chains to the trust bundle the SVIDSource publishes
	// — the SPIRE authority root (the own-CA path verified the per-session recorded
	// key; the SPIRE path verifies the trust-domain chain).
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:       trustBundleOf(t, spire),
		CurrentTime: spire.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr != nil {
		t.Fatalf("spire svid leaf does not chain to the trust bundle: %v", verr)
	}
}

// trustBundleOf reaches the SPIRE authority's SVIDSource trust bundle for the
// chain-parity assertion. The Shim's workloadAuthority is the spireWorkloadAuthority
// (in-package), so the test can read its source's bundle directly.
func trustBundleOf(t *testing.T, s *Shim) *x509.CertPool {
	t.Helper()
	a, ok := s.workloadAuthority.(*spireWorkloadAuthority)
	if !ok {
		t.Fatalf("workloadAuthority is %T, want *spireWorkloadAuthority", s.workloadAuthority)
	}
	return a.source.TrustBundle()
}

// TestSpireAuthority_ValidateAllow proves a fresh granted credential minted on the
// SPIRE substrate Validates ALLOW — the frozen-contract ALLOW the own-CA path also
// emits (mint_test.go TestRevokeSession_ValidateFailsClosed pre-revoke leg).
func TestSpireAuthority_ValidateAllow(t *testing.T) {
	shim := newSpireTestShim(t)
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	res := shim.Validate([]byte(bundle.JWT), testSession, testSvc)
	if res.Verdict != VerdictAllow {
		t.Fatalf("want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	if res.GrantRef != "g1" {
		t.Fatalf("grant_ref = %q, want g1", res.GrantRef)
	}
}

// TestSpireAuthority_ValidateRevoked proves the SPIRE substrate's still-valid
// credential fails CLOSED the instant the session is revoked — liveness-as-revocation
// (doc 16 §5.4), identical to the own-CA leg. The revoke reason rides the D77 channel.
func TestSpireAuthority_ValidateRevoked(t *testing.T) {
	shim := newSpireTestShim(t)
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if res := shim.Validate([]byte(bundle.JWT), testSession, testSvc); res.Verdict != VerdictAllow {
		t.Fatalf("pre-revoke want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	if err := shim.RevokeSession(testSession, "admin_kill"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	res := shim.Validate([]byte(bundle.JWT), testSession, testSvc)
	if res.Verdict != VerdictDeny {
		t.Fatal("post-revoke want DENY, got ALLOW")
	}
	if res.MachineReadableReason != "admin_kill" {
		t.Fatalf("revoke reason not surfaced on the D77 channel: %q", res.MachineReadableReason)
	}
}

// TestSpireAuthority_ValidateFailClosed exercises the remaining DENY branches on the
// SPIRE substrate, asserting the SAME D77 machine-readable reasons the own-CA suite
// asserts (mint_test.go TestValidate_FailClosedBranches) — field-for-field across the
// swap. It adds the SPIRE-SPECIFIC fail-closed case: a credential that DOES chain to
// the trust bundle but carries the WRONG URI SAN (an authentic-but-wrong-identity
// SVID) must fail closed as signature_invalid (the errSVIDName → signature_invalid
// mapping), proving the "right identity" SPIRE check, not just authenticity.
func TestSpireAuthority_ValidateFailClosed(t *testing.T) {
	shim := newSpireTestShim(t)
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// A credential that CHAINS to the trust bundle but names the WRONG SPIFFE ID: mint
	// it through the shim's own SVIDSource with the failURI hook, so it is authentic
	// (chains) yet wrong-identity (SAN != the session's §3.1 name). It must fail closed.
	wrongIdentityCred := mintWrongSANSvid(t, shim)

	cases := []struct {
		name       string
		cred       []byte
		session    string
		service    string
		wantReason string
	}{
		{"unknown session", []byte(bundle.JWT), "no-such-session", testSvc, ReasonUnknownSession},
		{"out of grant", []byte(bundle.JWT), testSession, "other-svc", ReasonOutOfGrant},
		{"malformed credential", []byte("not-a-jws"), testSession, testSvc, ReasonMalformed},
		// Authentic-but-wrong-identity (chains to bundle, wrong URI SAN): the SPIRE
		// "right identity" check fails closed to signature_invalid (errSVIDName).
		{"authentic wrong identity", wrongIdentityCred, testSession, testSvc, ReasonSignatureInvalid},
		// Forged: a SPIRE-shaped credential minted under a DIFFERENT (unknown) trust
		// domain does not chain to this shim's bundle — fail closed (signature_invalid).
		{"unknown trust domain", mintForeignSvid(t), testSession, testSvc, ReasonSignatureInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := shim.Validate(tc.cred, tc.session, tc.service)
			if res.Verdict != VerdictDeny {
				t.Fatalf("want DENY, got ALLOW")
			}
			if res.MachineReadableReason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", res.MachineReadableReason, tc.wantReason)
			}
		})
	}
}

// mintWrongSANSvid mints, through the shim's OWN SVIDSource, an X.509-SVID that chains
// to the trust bundle (authentic) but carries a deliberately WRONG URI SAN (the
// failURI hook). It is the authentic-but-wrong-identity adversary: Validate must fail
// it closed on the SAN-equality check, not the chain check.
func mintWrongSANSvid(t *testing.T, shim *Shim) []byte {
	t.Helper()
	a, ok := shim.workloadAuthority.(*spireWorkloadAuthority)
	if !ok {
		t.Fatalf("workloadAuthority is %T, want *spireWorkloadAuthority", shim.workloadAuthority)
	}
	src, ok := a.source.(*fakeSVIDSource)
	if !ok {
		t.Fatalf("SVIDSource is %T, want *fakeSVIDSource", a.source)
	}
	src.failURI = true
	defer func() { src.failURI = false }()
	now := shim.now()
	svid, err := src.FetchX509SVID(X509SVIDRequest{
		SpiffeID:  "spiffe://" + testOrg + "/session/" + testSession,
		Claims:    jwtClaims{SessionUUID: testSession, Subject: "spiffe://" + testOrg + "/session/" + testSession},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("mint wrong-SAN svid: %v", err)
	}
	return []byte(svid.JWT)
}

// mintForeignSvid mints a SPIRE-shaped credential under a FRESH, independent synthetic
// trust domain (a different fake), so it never chains to the shim-under-test's bundle.
// It is the unknown-authority adversary: Validate must fail it closed on the chain
// check (signature_invalid), proving the trust bundle is the authority root.
func mintForeignSvid(t *testing.T) []byte {
	t.Helper()
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	foreign, err := newFakeSVIDSource(func() time.Time { return fixed })
	if err != nil {
		t.Fatalf("foreign fake: %v", err)
	}
	svid, err := foreign.FetchX509SVID(X509SVIDRequest{
		SpiffeID:  "spiffe://" + testOrg + "/session/" + testSession,
		Claims:    jwtClaims{SessionUUID: testSession, Subject: "spiffe://" + testOrg + "/session/" + testSession},
		NotBefore: fixed.Add(-time.Minute),
		NotAfter:  fixed.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("foreign svid: %v", err)
	}
	return []byte(svid.JWT)
}

// TestSpireAuthority_DialLiveDeferred pins the env-gated boundary of the live SPIRE
// Workload-API dial (D50: the synthetic fake / in-memory fake provider remain the only
// SVIDSources exercised in CI — see spire_live_test.go). The live dial is now BUILT
// behind go-spiffe/v2 (spire_live.go) but env-gated on SPIFFE_ENDPOINT_SOCKET, and it
// fails closed two distinct ways:
//   - an UNCONFIGURED (empty) socket returns errSpireLiveDeferred + a nil source, so a
//     caller that forgot to supply the synthetic fake never silently dials nothing;
//   - a CONFIGURED-but-unreachable socket ATTEMPTS the live dial and fails closed with a
//     dial error that is NOT the deferred sentinel (proving the dial is wired, not a
//     stub) — and still never returns a non-nil source.
//
// The live dial against a real SPIRE Agent is the deferred manual step, never run in CI.
func TestSpireAuthority_DialLiveDeferred(t *testing.T) {
	// Unconfigured socket: deferral sentinel, fail closed.
	if src, err := DialSpireWorkloadAPI(""); !errors.Is(err, errSpireLiveDeferred) {
		t.Fatalf(`DialSpireWorkloadAPI("") err = %v; want errSpireLiveDeferred`, err)
	} else if src != nil {
		t.Fatal(`DialSpireWorkloadAPI("") returned a non-nil source; must fail closed`)
	}
	// Configured but unreachable socket: the dial is ATTEMPTED (built, env-gated) and
	// fails closed with a dial error that is NOT the deferred sentinel.
	const deadSocket = "unix:///tmp/ds-spire-agent-does-not-exist.sock"
	src, err := DialSpireWorkloadAPI(deadSocket)
	if err == nil {
		t.Fatalf("DialSpireWorkloadAPI(%q) returned nil error; an unreachable socket must fail closed", deadSocket)
	}
	if errors.Is(err, errSpireLiveDeferred) {
		t.Fatalf("DialSpireWorkloadAPI(%q) returned errSpireLiveDeferred; a configured socket must ATTEMPT the live dial, not defer", deadSocket)
	}
	if src != nil {
		t.Fatalf("DialSpireWorkloadAPI(%q) returned a non-nil source; must fail closed", deadSocket)
	}
}

// TestSpireAuthority_NilSourceFailsClosed guards an authority built without a source:
// both legs fail closed rather than panic.
func TestSpireAuthority_NilSourceFailsClosed(t *testing.T) {
	a := NewSpireWorkloadAuthority(nil)
	if _, err := a.MintWorkload(WorkloadMintRequest{Spiffe: "spiffe://" + testOrg + "/session/" + testSession}); err == nil {
		t.Fatal("MintWorkload with nil source must error")
	}
	if _, err := a.VerifyPresented([]byte("x.y.z"), "spiffe://"+testOrg+"/session/"+testSession, time.Now()); err == nil {
		t.Fatal("VerifyPresented with nil source must error")
	}
}

// newHierarchicalSpireTestShim builds a Shim on the SPIRE substrate over the
// HIERARCHICAL synthetic fake (an interposed signing intermediate CA, so a leaf chains
// leaf -> intermediate -> root rather than directly to the published bundle) with the
// SAME pinned clock as newSpireTestShim, so the chain-walk assertions line up with the
// flat-domain suite.
func newHierarchicalSpireTestShim(t *testing.T) *Shim {
	t.Helper()
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }
	src, err := NewHierarchicalFakeSVIDSource(clock)
	if err != nil {
		t.Fatalf("NewHierarchicalFakeSVIDSource: %v", err)
	}
	shim, err := NewShim(WithClock(clock), WithSpireAuthority(src))
	if err != nil {
		t.Fatalf("NewShim WithSpireAuthority (hierarchical): %v", err)
	}
	return shim
}

// TestSpireAuthority_HierarchicalChainWalkAllow proves a credential minted under a
// HIERARCHICAL trust domain — the leaf signed by a synthetic intermediate CA, which is
// in turn signed by the published trust-domain root — Validates ALLOW through the full
// grpc Validate path. This exercises the authority's intermediate chain-walk
// (spire_authority.go VerifyPresented: x5c[1:] -> Intermediates pool, leaf ->
// intermediate -> root), the ONLY authority branch the flat-domain fake never reaches.
func TestSpireAuthority_HierarchicalChainWalkAllow(t *testing.T) {
	shim := newHierarchicalSpireTestShim(t)

	// The minted SVID's JWS x5c carries the FULL chain [leaf, intermediate]: the leaf
	// does NOT chain directly to the bundle, so the authority must walk the intermediate.
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if got := x5cLen(t, bundle.JWT); got != 2 {
		t.Fatalf("hierarchical SVID x5c chain length = %d, want 2 (leaf + intermediate)", got)
	}
	// The leaf must NOT chain to the bundle WITHOUT the intermediate — proving the walk
	// is load-bearing, not incidental.
	leaf, err := x509.ParseCertificate(bundle.CertDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:       trustBundleOf(t, shim),
		CurrentTime: shim.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr == nil {
		t.Fatal("hierarchical leaf chained to the bundle with NO intermediate; the intermediate is not load-bearing")
	}

	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	res := validateOverWire(t, shim, []byte(bundle.JWT), testSession, testSvc)
	if res.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("hierarchical SVID want ALLOW, got DENY(%s)", res.GetMachineReadableReason())
	}
	if res.GetGrantRef() != "g1" {
		t.Fatalf("grant_ref = %q, want g1", res.GetGrantRef())
	}
}

// TestSpireAuthority_HierarchicalDropIntermediateDeny is the NEGATIVE of the chain-walk
// ALLOW: take the hierarchical SVID's JWS and DROP the interposed intermediate from its
// x5c (leaf-only). The leaf can no longer chain to the published root (the intermediate
// is the missing link), so the authority's chain verify fails CLOSED — DENY
// signature_invalid — exactly the "without the interposed CA the leaf is untrusted"
// fail-closed property a hierarchical trust domain must enforce.
func TestSpireAuthority_HierarchicalDropIntermediateDeny(t *testing.T) {
	shim := newHierarchicalSpireTestShim(t)
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	// Sanity: the unmodified credential ALLOWs (so the DENY below is the dropped
	// intermediate, not an unrelated set-up fault).
	if res := validateOverWire(t, shim, []byte(bundle.JWT), testSession, testSvc); res.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("pre-drop want ALLOW, got DENY(%s)", res.GetMachineReadableReason())
	}

	dropped := dropIntermediateFromX5c(t, bundle.JWT)
	res := validateOverWire(t, shim, dropped, testSession, testSvc)
	if res.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY {
		t.Fatal("dropped-intermediate SVID want DENY, got ALLOW (the leaf must not chain without the interposed CA)")
	}
	if res.GetMachineReadableReason() != ReasonSignatureInvalid {
		t.Fatalf("dropped-intermediate reason = %q, want %q (chain fails closed)", res.GetMachineReadableReason(), ReasonSignatureInvalid)
	}
}

// TestSpireAuthority_MalformedX5cAndAlg pins the SPIRE leg's malformed_credential vs
// signature_invalid disambiguation across the malformed-x5c / wrong-alg surface — the
// SAME ReasonMalformed the own-CA leg reaches for a structurally bad token. Each case
// is a structurally bad SVID-shaped credential that must DENY ReasonMalformed (NOT
// signature_invalid), presented through the full grpc Validate path against a live,
// granted session (so the failure is the credential's shape, not a liveness gate):
//   - missing x5c header: no leaf to chain (spire_authority.go ~221-223);
//   - non-DER bytes in x5c[0]: the leaf does not parse (~224-231);
//   - alg != ES256: splitJWS rejects the header (~335).
func TestSpireAuthority_MalformedX5cAndAlg(t *testing.T) {
	shim := newSpireTestShim(t)
	// A live, granted session so the credential reaches the signature/shape gate rather
	// than tripping the unknown-session liveness gate first.
	if _, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatalf("grant: %v", err)
	}

	cases := []struct {
		name string
		cred []byte
	}{
		{"missing x5c header", []byte(malformedSpireJWS(t, jwsHeaderForge{alg: "ES256", omitX5c: true}))},
		{"non-DER x5c leaf", []byte(malformedSpireJWS(t, jwsHeaderForge{alg: "ES256", x5c: []string{b64url.EncodeToString([]byte("not-a-der-cert"))}}))},
		{"wrong alg RS256", []byte(malformedSpireJWS(t, jwsHeaderForge{alg: "RS256", x5c: []string{b64url.EncodeToString([]byte("anything"))}}))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := validateOverWire(t, shim, tc.cred, testSession, testSvc)
			if res.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY {
				t.Fatalf("want DENY, got ALLOW")
			}
			if res.GetMachineReadableReason() != ReasonMalformed {
				t.Fatalf("reason = %q, want %q (malformed, not signature_invalid)", res.GetMachineReadableReason(), ReasonMalformed)
			}
		})
	}
}

// x5cLen decodes the JWS protected header and returns its x5c chain length. It is the
// chain-shape assertion helper for the hierarchical suite (a flat SVID carries 1, a
// single-intermediate one 2: leaf + intermediate, a 2-level one 3: leaf + int2 + int1).
func x5cLen(t *testing.T, jws string) int {
	t.Helper()
	return len(parseJWSHeaderForTest(t, jws).X5c)
}

// newDeepHierarchicalSpireTestShim builds a Shim on the SPIRE substrate over the WELL-FORMED
// DEEPER (2-level) synthetic fake — root -> int1 -> int2 -> leaf, two interposed CAs, so a
// leaf chains leaf -> int2 -> int1 -> root — with the SAME pinned clock as
// newSpireTestShim, so the depth-2 chain-walk assertions line up with the flat / single-
// intermediate suites.
func newDeepHierarchicalSpireTestShim(t *testing.T) *Shim {
	t.Helper()
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }
	src, err := NewDeepHierarchicalFakeSVIDSource(clock)
	if err != nil {
		t.Fatalf("NewDeepHierarchicalFakeSVIDSource: %v", err)
	}
	shim, err := NewShim(WithClock(clock), WithSpireAuthority(src))
	if err != nil {
		t.Fatalf("NewShim WithSpireAuthority (deep hierarchical): %v", err)
	}
	return shim
}

// newBrokenDeepSpireTestShim builds a Shim on the SPIRE substrate over a DEEPER (2-level)
// synthetic fake whose UPPER intermediate (int1) is deliberately BROKEN per opts (a non-CA,
// an over-long path budget, or a validity window that does not cover the pinned clock), with
// the SAME pinned clock as newSpireTestShim. It drives the negative chain-walk rows: the Go
// verifier's basic-constraints / path-length / chain-time enforcement on the INTERPOSED CA
// (the surface the single-intermediate fake never reached).
func newBrokenDeepSpireTestShim(t *testing.T, opts deepHierarchyOpts) *Shim {
	t.Helper()
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }
	src, err := newDeepHierarchicalFakeSVIDSource(clock, opts)
	if err != nil {
		t.Fatalf("newDeepHierarchicalFakeSVIDSource(%+v): %v", opts, err)
	}
	shim, err := NewShim(WithClock(clock), WithSpireAuthority(src))
	if err != nil {
		t.Fatalf("NewShim WithSpireAuthority (broken deep hierarchical): %v", err)
	}
	return shim
}

// TestSpireAuthority_DeepHierarchicalChainWalkAllow proves a credential minted under a
// 2-LEVEL trust domain — the leaf signed by the deepest intermediate (int2), int2 signed by
// the upper intermediate (int1), int1 signed by the published trust-domain root — Validates
// ALLOW through the full grpc Validate path. It is the DEPTH-2 reach of the authority's
// intermediate chain-walk (spire_authority.go VerifyPresented: x5c[1:] -> Intermediates pool,
// leaf -> int2 -> int1 -> root): the single-intermediate fake walks ONE CA, this walks TWO.
// The x5c carries the full [leaf, int2, int1] chain (len 3) and the leaf must NOT chain to
// the bundle with BOTH intermediates removed — proving the deeper walk is load-bearing.
func TestSpireAuthority_DeepHierarchicalChainWalkAllow(t *testing.T) {
	shim := newDeepHierarchicalSpireTestShim(t)

	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// The 2-level SVID's x5c carries the FULL chain [leaf, int2, int1]: TWO interposed CAs.
	if got := x5cLen(t, bundle.JWT); got != 3 {
		t.Fatalf("deep hierarchical SVID x5c chain length = %d, want 3 (leaf + int2 + int1)", got)
	}
	// The leaf must NOT chain to the bundle WITHOUT the intermediates — proving the depth-2
	// walk is load-bearing, not incidental (no intermediate pool => the leaf is untrusted).
	leaf, err := x509.ParseCertificate(bundle.CertDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:       trustBundleOf(t, shim),
		CurrentTime: shim.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr == nil {
		t.Fatal("deep hierarchical leaf chained to the bundle with NO intermediates; the chain is not load-bearing")
	}
	// And it must NOT chain with ONLY the deepest intermediate (int2) present — the UPPER
	// intermediate (int1) is the missing link to the root, so the full walk is required.
	int2Only := x509.NewCertPool()
	int2Only.AddCert(intermediateCert(t, bundle, 0)) // x5c[1] = int2 (the leaf-signing intermediate)
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:         trustBundleOf(t, shim),
		Intermediates: int2Only,
		CurrentTime:   shim.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr == nil {
		t.Fatal("deep hierarchical leaf chained with only the deepest intermediate; the upper CA is not load-bearing")
	}

	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	res := validateOverWire(t, shim, []byte(bundle.JWT), testSession, testSvc)
	if res.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("deep hierarchical SVID want ALLOW, got DENY(%s)", res.GetMachineReadableReason())
	}
	if res.GetGrantRef() != "g1" {
		t.Fatalf("grant_ref = %q, want g1", res.GetGrantRef())
	}
}

// TestSpireAuthority_DeepHierarchicalCAConstraintFailClosed pins the verifier's
// basic-constraints / path-length enforcement on an INTERPOSED CA — the surface the single-
// intermediate fake (one well-formed CA) cannot reach. Each row mints a 2-level chain whose
// UPPER intermediate (int1) is broken and asserts the credential fails CLOSED (DENY
// signature_invalid) through the full grpc Validate path against a live, granted session:
//   - non-CA interposed cert: int1 lacks the CA basic constraint (IsCA=false), so a non-CA in
//     a signing position breaks the chain — the verifier rejects it fail-closed.
//   - path-length violation: int1 has MaxPathLen:0 (it may sign LEAVES only) yet signs int2 (a
//     CA), so the path-length budget is exceeded — the verifier rejects the over-long path.
func TestSpireAuthority_DeepHierarchicalCAConstraintFailClosed(t *testing.T) {
	cases := []struct {
		name string
		opts deepHierarchyOpts
	}{
		{"non-CA interposed intermediate", deepHierarchyOpts{int1NotCA: true}},
		{"path-length violating interposed intermediate", deepHierarchyOpts{int1MaxPathLenZero: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shim := newBrokenDeepSpireTestShim(t, tc.opts)
			bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
				SessionUUID: testSession, Org: testOrg,
			})
			if err != nil {
				t.Fatalf("mint: %v", err)
			}
			// Live + granted so the failure is the CA-constraint chain check, not a liveness
			// or out-of-grant gate.
			if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
				t.Fatalf("grant: %v", err)
			}
			res := validateOverWire(t, shim, []byte(bundle.JWT), testSession, testSvc)
			if res.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY {
				t.Fatal("broken-CA-constraint chain want DENY, got ALLOW (the interposed CA constraint must fail closed)")
			}
			if res.GetMachineReadableReason() != ReasonSignatureInvalid {
				t.Fatalf("broken-CA-constraint reason = %q, want %q (chain fails closed)", res.GetMachineReadableReason(), ReasonSignatureInvalid)
			}
		})
	}
}

// TestSpireAuthority_DeepHierarchicalChainTimeFailClosed pins that VerifyPresented's
// CurrentTime check covers the INTERPOSED CA, not just the leaf — the SECOND validity window
// the flat fake never had. Each row mints a 2-level chain whose UPPER intermediate (int1) has
// a validity window that does NOT cover the pinned clock (while the leaf and the deepest
// intermediate stay time-valid) and asserts the credential fails CLOSED (DENY
// signature_invalid) through the full grpc Validate path against a live, granted session:
//   - expired interposed CA: int1.NotAfter is BEFORE the clock (an expired CA in the path).
//   - not-yet-valid interposed CA: int1.NotBefore is AFTER the clock (a future-dated CA).
//
// The leaf alone would pass its own validity check; the chain fails because the verifier
// time-gates EVERY cert in the path — so an expired/not-yet-valid interposed CA fails closed.
func TestSpireAuthority_DeepHierarchicalChainTimeFailClosed(t *testing.T) {
	clock := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		opts deepHierarchyOpts
	}{
		{
			// int1 expired well before the clock (its window ended an hour ago) while the
			// leaf is still valid — the interposed CA's NotAfter gates the chain.
			name: "expired interposed CA",
			opts: deepHierarchyOpts{
				int1NotBefore: clock.Add(-48 * time.Hour),
				int1NotAfter:  clock.Add(-time.Hour),
			},
		},
		{
			// int1 not valid until an hour from now (a future-dated CA) while the leaf is
			// already valid — the interposed CA's NotBefore gates the chain.
			name: "not-yet-valid interposed CA",
			opts: deepHierarchyOpts{
				int1NotBefore: clock.Add(time.Hour),
				int1NotAfter:  clock.Add(48 * time.Hour),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shim := newBrokenDeepSpireTestShim(t, tc.opts)
			bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
				SessionUUID: testSession, Org: testOrg,
			})
			if err != nil {
				t.Fatalf("mint: %v", err)
			}
			// Sanity: the LEAF itself is time-valid at the clock (only the interposed CA's
			// window is off), so the DENY below is the chain-time check on int1, not the leaf.
			leaf, err := x509.ParseCertificate(bundle.CertDER)
			if err != nil {
				t.Fatalf("parse leaf: %v", err)
			}
			if shim.now().Before(leaf.NotBefore) || shim.now().After(leaf.NotAfter) {
				t.Fatalf("leaf is itself outside its validity window [%s, %s] at %s; the test would not isolate the interposed-CA check", leaf.NotBefore, leaf.NotAfter, shim.now())
			}
			if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
				t.Fatalf("grant: %v", err)
			}
			res := validateOverWire(t, shim, []byte(bundle.JWT), testSession, testSvc)
			if res.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY {
				t.Fatal("interposed-CA-outside-validity-window chain want DENY, got ALLOW (the chain-time check must cover the interposed CA)")
			}
			if res.GetMachineReadableReason() != ReasonSignatureInvalid {
				t.Fatalf("chain-time reason = %q, want %q (chain fails closed)", res.GetMachineReadableReason(), ReasonSignatureInvalid)
			}
		})
	}
}

// intermediateCert parses the X.509 cert at x5c[idx+1] (the idx-th INTERMEDIATE, since x5c[0]
// is the leaf) from a minted SVID bundle's JWS — the chain-shape assertion helper for the
// deep-hierarchical suite (idx 0 = the deepest, leaf-signing intermediate). It reads the
// recorded SVID's parallel JWS, the same x5c the authority walks.
func intermediateCert(t *testing.T, bundle *WorkloadIdentityBundle, idx int) *x509.Certificate {
	t.Helper()
	hdr := parseJWSHeaderForTest(t, bundle.JWT)
	if len(hdr.X5c) < idx+2 {
		t.Fatalf("x5c has %d entries, want at least %d (leaf + intermediate %d)", len(hdr.X5c), idx+2, idx)
	}
	der, err := b64url.DecodeString(hdr.X5c[idx+1])
	if err != nil {
		t.Fatalf("decode x5c[%d]: %v", idx+1, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate x5c[%d]: %v", idx+1, err)
	}
	return cert
}

// dropIntermediateFromX5c rewrites a hierarchical SVID's JWS protected header to carry
// ONLY the leaf in x5c (dropping the interposed intermediate), leaving the payload and
// signature segments verbatim. The authority's chain check runs BEFORE signature
// verification, so the leaf — now unable to reach the root without the intermediate —
// fails the chain walk closed; the (now stale) signature is never reached. It is the
// adversary that strips the trust path a hierarchical domain requires.
func dropIntermediateFromX5c(t *testing.T, jws string) []byte {
	t.Helper()
	hdr := parseJWSHeaderForTest(t, jws)
	if len(hdr.X5c) < 2 {
		t.Fatalf("expected a hierarchical SVID (x5c len >= 2), got %d", len(hdr.X5c))
	}
	hdr.X5c = hdr.X5c[:1] // leaf only — the intermediate is dropped
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("jws has %d segments, want 3", len(parts))
	}
	newHdrJSON, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal rewritten header: %v", err)
	}
	parts[0] = b64url.EncodeToString(newHdrJSON)
	return []byte(strings.Join(parts, "."))
}

// jwsHeaderForge describes a deliberately malformed SVID-shaped JWS the SPIRE leg must
// reject as ReasonMalformed: a chosen alg, and an x5c that is either omitted or carries
// non-DER junk.
type jwsHeaderForge struct {
	alg     string
	x5c     []string
	omitX5c bool
}

// malformedSpireJWS forges a three-segment JWS with the requested protected header and
// an arbitrary (signature-irrelevant) payload + signature segment. The malformed cases
// fail at the header/x5c structural gate BEFORE any signature check, so the signature
// segment need not verify — the credential is rejected on shape alone (ReasonMalformed).
func malformedSpireJWS(t *testing.T, f jwsHeaderForge) string {
	t.Helper()
	hdr := jwsHeader{Alg: f.alg, Typ: "JWT"}
	if !f.omitX5c {
		hdr.X5c = f.x5c
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal forged header: %v", err)
	}
	payload, err := json.Marshal(jwtClaims{SessionUUID: testSession, Subject: "spiffe://" + testOrg + "/session/" + testSession})
	if err != nil {
		t.Fatalf("marshal forged payload: %v", err)
	}
	// A 64-byte (R||S-shaped) all-zero signature segment: structurally plausible but
	// never reached (the header/x5c gate rejects these cases first).
	sig := make([]byte, 64)
	return b64url.EncodeToString(hdrJSON) + "." + b64url.EncodeToString(payload) + "." + b64url.EncodeToString(sig)
}

// parseJWSHeaderForTest decodes the protected header of a compact JWS for the in-package
// SVID-shape assertions. It mirrors the authority's own header decode (splitJWS) without
// reaching into production code paths.
func parseJWSHeaderForTest(t *testing.T, jws string) jwsHeader {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("jws has %d segments, want 3", len(parts))
	}
	raw, err := b64url.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jws header: %v", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("unmarshal jws header: %v", err)
	}
	return hdr
}
