// SPDX-License-Identifier: Apache-2.0

// Native-seam contract tests (MintWorkloadIdentity, RevokeSession) and the two
// doc 16 §13 isolation properties as EXECUTABLE assertions:
//
//	(1) per-session CA isolation — session A's interception CA never validates a
//	    leaf/cert from session B (and vice versa);
//	(2) hierarchy separation — an interception-root signature never validates as
//	    workload identity (and vice versa).
//
// Everything synthetic (D50). The shim's clock is pinned so freshness/liveness
// branches are deterministic.
package mint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// newTestShim builds a shim with a pinned clock at a fixed instant.
func newTestShim(t *testing.T) *Shim {
	t.Helper()
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	shim, err := NewShim(WithClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatal(err)
	}
	return shim
}

func TestMintWorkloadIdentity_ClaimSetAndSPIFFE(t *testing.T) {
	shim := newTestShim(t)
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID:   testSession,
		LaunchingUser: "idp-subject-xyz",
		Org:           testOrg,
		RepoBranch:    "acme/app@main",
		Runtime:       "claude-code",
		ParentSession: "00000000-0000-4000-8000-0000000000pp",
	})
	if err != nil {
		t.Fatal(err)
	}

	// SPIFFE-compatible URI SAN naming (§3.1).
	wantURI := "spiffe://" + testOrg + "/session/" + testSession
	if bundle.SPIFFEURI != wantURI {
		t.Fatalf("spiffe uri = %q, want %q", bundle.SPIFFEURI, wantURI)
	}

	// The X.509 leaf carries the SPIFFE URI SAN and chains to the workload root.
	leaf, err := x509.ParseCertificate(bundle.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != wantURI {
		t.Fatalf("leaf URI SAN = %v, want [%s]", leaf.URIs, wantURI)
	}
	if err := shim.workloadRoot.verifyLeaf(bundle.CertDER, shim.now()); err != nil {
		t.Fatalf("workload leaf does not chain to hierarchy-1 root: %v", err)
	}

	// The parallel JWT presentation verifies against the leaf key and carries the
	// full §3.1 claim set incl. the reserved service_principal marker.
	claims, err := verifyJWT(leaf.PublicKey.(*ecdsa.PublicKey), bundle.JWT)
	if err != nil {
		t.Fatalf("jwt verify against leaf key: %v", err)
	}
	if claims.Subject != wantURI {
		t.Fatalf("jwt sub = %q, want spiffe uri %q", claims.Subject, wantURI)
	}
	if claims.SessionUUID != testSession || claims.LaunchingUser != "idp-subject-xyz" ||
		claims.Org != testOrg || claims.RepoBranch != "acme/app@main" ||
		claims.Runtime != "claude-code" || claims.ParentSession != "00000000-0000-4000-8000-0000000000pp" {
		t.Fatalf("jwt claim set incomplete: %+v", claims)
	}
	if claims.ServicePrincipal {
		t.Fatal("service_principal must be false (agent face) at M0 — reserved marker only")
	}
}

func TestPrincipalResolver_Seam(t *testing.T) {
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	// The resolver stands in for the orchestrator principal-store linkage WITHOUT
	// importing orchestrator/: it maps a hint to the canonical IdP subject.
	shim, err := NewShim(
		WithClock(func() time.Time { return fixed }),
		WithPrincipalResolver(func(sessionUUID, hint string) (string, error) {
			if hint == "alias@acme" {
				return "idp|canonical-subject", nil
			}
			return hint, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, LaunchingUser: "alias@acme", Org: testOrg,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(bundle.CertDER)
	claims, err := verifyJWT(leaf.PublicKey.(*ecdsa.PublicKey), bundle.JWT)
	if err != nil {
		t.Fatal(err)
	}
	if claims.LaunchingUser != "idp|canonical-subject" {
		t.Fatalf("resolver not applied: launching_user = %q", claims.LaunchingUser)
	}
}

func TestRevokeSession_ValidateFailsClosed(t *testing.T) {
	shim := newTestShim(t)
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatal(err)
	}

	// Before revoke: ALLOW.
	if res := shim.Validate([]byte(bundle.JWT), testSession, testSvc); res.Verdict != VerdictAllow {
		t.Fatalf("pre-revoke want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}

	// Revoke marks the record; Validate then fails CLOSED with the reason in the
	// D77 in-band-403 shape — the same still-valid cert now fails immediately
	// (doc 16 §5.4: liveness-as-revocation, no CRL/OCSP).
	if err := shim.RevokeSession(testSession, "admin_kill"); err != nil {
		t.Fatal(err)
	}
	res := shim.Validate([]byte(bundle.JWT), testSession, testSvc)
	if res.Verdict != VerdictDeny {
		t.Fatal("post-revoke want DENY, got ALLOW")
	}
	if res.MachineReadableReason != "admin_kill" {
		t.Fatalf("revoke reason not surfaced: %q", res.MachineReadableReason)
	}
}

func TestValidate_FailClosedBranches(t *testing.T) {
	shim := newTestShim(t)
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(testSession, testSvc, "g1")

	cases := []struct {
		name       string
		cred       []byte
		session    string
		service    string
		wantReason string
	}{
		{"unknown session", []byte(bundle.JWT), "no-such-session", testSvc, ReasonUnknownSession},
		{"out of grant", []byte(bundle.JWT), testSession, "other-svc", ReasonOutOfGrant},
		{"malformed credential", []byte("not-a-jwt"), testSession, testSvc, ReasonMalformed},
		{"bad signature", forgeToken(t), testSession, testSvc, ReasonSignatureInvalid},
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

// forgeToken signs a token for testSession with a DIFFERENT key than the shim
// minted — it must fail signature verification (fail closed).
func forgeToken(t *testing.T) []byte {
	t.Helper()
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok, err := signJWT(otherKey, jwtClaims{
		SessionUUID: testSession,
		Expiry:      time.Now().Add(time.Hour).Unix(),
		NotBefore:   time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(tok)
}

// --- own-CA no-intermediate / no-trust-bundle asymmetry map ------------------

// TestOwnCANoIntermediateAsymmetry pins the structural ASYMMETRY between the two
// workload substrates so the dual-substrate coverage map is EXPLICIT and a future
// reviewer cannot mistake the own-CA no-chain for a coverage GAP:
//
//	SPIRE leg (spire_authority.go): the presented credential carries the X.509-SVID
//	    leaf (and any interposed intermediates) in its JWS `x5c`; VerifyPresented
//	    CHAINS leaf -> interposed-CA(s) -> root to the TRUST BUNDLE the SVIDSource
//	    publishes (the depth-1/2 chain-walk the spire_authority suite and the synthetic
//	    multi-level / CA-constraint / chain-time fakes exercise — 01KV8Z92 / 01KV6ER3KP).
//	own-CA leg (ownCAWorkloadAuthority, mint.go): MintWorkload mints a plain ES256 JWS
//	    via signJWT with NO `x5c` chain, and VerifyPresented checks the PER-SESSION
//	    RECORDED key (workloadPubForSession) — there is structurally NO SVIDSource and
//	    NO TrustBundle to consult, so there is NO chain-walk surface and NO interposed
//	    intermediates. The asymmetry is BY DESIGN, not a missing test.
//
// The assertions below make all three legs of that map executable.
func TestOwnCANoIntermediateAsymmetry(t *testing.T) {
	shim := newTestShim(t)

	// The DEFAULT substrate is the M1 own-CA impl — assert it, so a future swap of the
	// default does not silently re-point this asymmetry test at a different substrate.
	if _, ok := shim.workloadAuthority.(*ownCAWorkloadAuthority); !ok {
		t.Fatalf("default workloadAuthority is %T, want *ownCAWorkloadAuthority (own-CA is the M1 default)", shim.workloadAuthority)
	}

	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatalf("mint own-CA workload identity: %v", err)
	}

	// (1) NO x5c, NO intermediates. The own-CA JWS is a plain ES256 JWS (signJWT) with
	// no interposed cert/chain — decode its protected header and assert x5c is absent.
	hdr := ownCAJWSHeader(t, bundle.JWT)
	if len(hdr.X5c) != 0 {
		t.Fatalf("own-CA JWS protected header carries x5c=%v; the own-CA leg must carry NO x5c chain (no interposed cert)", hdr.X5c)
	}
	if hdr.Alg != "ES256" {
		t.Fatalf("own-CA JWS alg = %q, want ES256", hdr.Alg)
	}
	// The minted leaf itself is a flat hierarchy-1 leaf: it carries no interposed CA
	// between it and the workload root (chains DIRECTLY to the root, asserted below) —
	// the own-CA analogue of "no intermediates".
	leaf, err := x509.ParseCertificate(bundle.CertDER)
	if err != nil {
		t.Fatalf("parse own-CA leaf: %v", err)
	}

	// (2) own-CA VerifyPresented ALLOWs the bundle via the PER-SESSION RECORDED key,
	// WITHOUT any trust bundle being consulted. The ownCAWorkloadAuthority holds only a
	// Shim back-reference (no SVIDSource, no TrustBundle) — structurally recorded-key
	// only. Drive its VerifyPresented directly (the signature+claims half of the
	// Validate workload leg) at the §3.1 expected name.
	ownAuth, ok := shim.workloadAuthority.(*ownCAWorkloadAuthority)
	if !ok {
		t.Fatalf("workloadAuthority is %T, want *ownCAWorkloadAuthority", shim.workloadAuthority)
	}
	claims, err := ownAuth.VerifyPresented([]byte(bundle.JWT), bundle.SPIFFEURI, shim.now())
	if err != nil {
		t.Fatalf("own-CA VerifyPresented DENIED (%v); want ALLOW via the per-session recorded key", err)
	}
	if claims.Subject != bundle.SPIFFEURI {
		t.Fatalf("own-CA verified claims sub = %q, want the §3.1 name %q", claims.Subject, bundle.SPIFFEURI)
	}
	// The verify path resolves the per-session recorded key — confirm that key IS on
	// record (the recorded-key axis the own-CA leg verifies against), so the ALLOW above
	// is the recorded-key path, not an accident.
	if pub := shim.workloadPubForSession(testSession); pub == nil {
		t.Fatal("own-CA leg must record the per-session workload key (workloadPubForSession); it is the verify axis")
	} else if !pub.Equal(leaf.PublicKey.(*ecdsa.PublicKey)) {
		t.Fatal("recorded per-session key != the minted leaf key; the own-CA verify axis drifted from the mint")
	}

	// (3) The asymmetry, made explicit & executable: the own-CA leg has structurally
	// NO trust bundle. It is the *ownCAWorkloadAuthority (a Shim-backed recorded-key
	// verifier), NOT a *spireWorkloadAuthority — so there is no SVIDSource.TrustBundle()
	// to chain to. A SPIRE-trust-bundle pool must therefore NOT be what authenticates
	// the own-CA leaf: prove the own-CA leaf chains DIRECTLY to the workload ROOT (the
	// flat M1 hierarchy 1) with NO intermediates pool — the recorded-key substrate's
	// analogue of the SPIRE chain-to-bundle, and decidedly NOT a trust-bundle walk.
	if _, isSpire := shim.workloadAuthority.(*spireWorkloadAuthority); isSpire {
		t.Fatal("own-CA substrate must not be a *spireWorkloadAuthority (it has no SVIDSource / TrustBundle)")
	}
	workloadPool := poolFromDER(t, shim.WorkloadRootDER())
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:       workloadPool,
		CurrentTime: shim.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr != nil {
		t.Fatalf("own-CA leaf must chain DIRECTLY to the workload root with no intermediates: %v", verr)
	}
	// And — the load-bearing half of the asymmetry — the own-CA verify path does NOT
	// need that pool at all: VerifyPresented above ALLOWed using only the recorded key,
	// no Roots/Intermediates argument anywhere. Re-assert the recorded-key path is
	// self-sufficient by tearing the session down (dropping the recorded key) and
	// confirming VerifyPresented then fails CLOSED for lack of a key — proving the key,
	// not a trust bundle, is what the own-CA leg consults.
	if err := shim.TeardownSession(testSession); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if _, err := ownAuth.VerifyPresented([]byte(bundle.JWT), bundle.SPIFFEURI, shim.now()); err == nil {
		t.Fatal("after teardown drops the recorded key, own-CA VerifyPresented must fail CLOSED (no key) — confirming the recorded key, not a trust bundle, is the verify axis")
	}
}

// ownCAJWSHeader decodes the protected header of the own-CA leg's compact JWS so the
// asymmetry test can assert it carries NO `x5c` chain (the own-CA leg signs via
// signJWT, which emits a plain ES256 header — no interposed cert). It mirrors the
// authority's own header decode without reaching into production code.
func ownCAJWSHeader(t *testing.T, jws string) jwsHeader {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("own-CA jws has %d segments, want 3", len(parts))
	}
	raw, err := b64url.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode own-CA jws header: %v", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("unmarshal own-CA jws header: %v", err)
	}
	return hdr
}

// --- doc 16 §13 isolation property 1: per-session CA isolation ---------------

// TestPerSessionCAIsolation proves session A's interception CA never validates a
// leaf minted under session B's interception CA, and vice versa. Each session's
// interception CA chains to its OWN per-session root; a leaf chain built for one
// session fails to verify against the other session's root pool.
func TestPerSessionCAIsolation(t *testing.T) {
	shim := newTestShim(t)
	sessionA := "00000000-0000-4000-8000-00000000000a"
	sessionB := "00000000-0000-4000-8000-00000000000b"

	caA, err := shim.mintInterceptionCA(sessionA)
	if err != nil {
		t.Fatal(err)
	}
	caB, err := shim.mintInterceptionCA(sessionB)
	if err != nil {
		t.Fatal(err)
	}

	// Mint an origin leaf under each session's interception CA (the per-origin
	// leaf ds-tlsproxy mints on the fly), then build each session's full pool
	// (per-session root + its interception CA as intermediate).
	leafA := mintOriginLeaf(t, caA, "github.com")
	leafB := mintOriginLeaf(t, caB, "github.com")

	poolA := sessionVerifyOpts(t, shim.InterceptionRootDER(sessionA), caA.CACertDER)
	poolB := sessionVerifyOpts(t, shim.InterceptionRootDER(sessionB), caB.CACertDER)

	// A leaf verifies under its own session's pool ...
	if _, err := leafA.Verify(poolA); err != nil {
		t.Fatalf("session-A leaf should verify under session-A pool: %v", err)
	}
	if _, err := leafB.Verify(poolB); err != nil {
		t.Fatalf("session-B leaf should verify under session-B pool: %v", err)
	}
	// ... and NEVER under the other session's pool (the §13 isolation property).
	if _, err := leafA.Verify(poolB); err == nil {
		t.Fatal("ISOLATION BREACH: session-A leaf validated against session-B CA")
	}
	if _, err := leafB.Verify(poolA); err == nil {
		t.Fatal("ISOLATION BREACH: session-B leaf validated against session-A CA")
	}
}

// --- doc 16 §13 isolation property 2: hierarchy separation -------------------

// TestHierarchySeparation proves an interception-hierarchy (hierarchy 2)
// certificate never validates as a workload identity (hierarchy 1), and a
// workload leaf never validates against an interception root (D82). The two root
// hierarchies are structurally disjoint, so neither pool accepts the other's
// material.
func TestHierarchySeparation(t *testing.T) {
	shim := newTestShim(t)

	// A workload leaf (hierarchy 1).
	wl, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A per-session interception CA + an origin leaf under it (hierarchy 2).
	ca, err := shim.mintInterceptionCA(testSession)
	if err != nil {
		t.Fatal(err)
	}
	interceptionLeaf := mintOriginLeaf(t, ca, "github.com")

	// Pool seeded with ONLY the workload root (hierarchy 1).
	workloadPool := poolFromDER(t, shim.WorkloadRootDER())
	// Pool seeded with the interception hierarchy (per-session root + CA).
	interceptionPool := sessionVerifyOpts(t, shim.InterceptionRootDER(testSession), ca.CACertDER)

	// The workload leaf verifies under the workload root ...
	if err := shim.workloadRoot.verifyLeaf(wl.CertDER, shim.now()); err != nil {
		t.Fatalf("workload leaf should verify under hierarchy 1: %v", err)
	}
	// ... but an interception-hierarchy leaf must NEVER validate as workload id.
	if _, err := interceptionLeaf.Verify(x509.VerifyOptions{
		Roots:       workloadPool,
		CurrentTime: shim.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		t.Fatal("SEPARATION BREACH: interception-hierarchy cert validated as workload identity")
	}

	// And the workload leaf must NEVER validate against the interception root.
	wlLeaf, err := x509.ParseCertificate(wl.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wlLeaf.Verify(interceptionPool); err == nil {
		t.Fatal("SEPARATION BREACH: workload leaf validated against the interception root")
	}

	// The interception CA cert itself must not chain to the workload root.
	caCert, err := x509.ParseCertificate(ca.CACertDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caCert.Verify(x509.VerifyOptions{
		Roots:       workloadPool,
		CurrentTime: shim.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		t.Fatal("SEPARATION BREACH: interception CA chained to the workload root")
	}
}

// --- test helpers ------------------------------------------------------------

// mintOriginLeaf signs a per-origin server leaf under a session's interception
// CA, the way ds-tlsproxy mints leaves on the fly during TLS termination.
func mintOriginLeaf(t *testing.T, ca *InterceptionCABundle, host string) *x509.Certificate {
	t.Helper()
	caCert, err := x509.ParseCertificate(ca.CACertDER)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := x509.ParsePKCS8PrivateKey(ca.CAKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := randomSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    caCert.NotBefore,
		NotAfter:     caCert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// sessionVerifyOpts builds verify options with the per-session root as the trust
// anchor and the session's interception CA as the intermediate.
func sessionVerifyOpts(t *testing.T, rootDER, caDER []byte) x509.VerifyOptions {
	t.Helper()
	roots := poolFromDER(t, rootDER)
	inters := poolFromDER(t, caDER)
	return x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func poolFromDER(t *testing.T, der []byte) *x509.CertPool {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
