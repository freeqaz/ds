// SPDX-License-Identifier: Apache-2.0

// HERMETIC tests for the LIVE SPIRE Workload-API adapter (spire_live.go). No gRPC
// server, no live socket, no SPIRE Agent: an in-memory fake x509SVIDProvider hands
// the liveSVIDSource adapter a SYNTHETIC ECDSA-leaf X.509-SVID (leaf signed by a
// synthetic trust-domain CA, sole URI SAN = a spiffe:// id) + an x509bundle.Bundle
// holding that CA. These exercise the ADAPTATION logic — fetch → adapt → sign the
// parallel JWS with the fetched leaf key → chain via TrustBundle — which is exactly
// what is uncovered by the live dial being deferred. The live dial itself
// (DialSpireWorkloadAPI with a real socket) is NEVER run in CI; the only DialSpire
// path tested here is the empty-socket deferral sentinel.
//
// SYNTHETIC ONLY: every key, cert and bundle is minted in-test. No live SPIRE
// material ever appears. The cert helpers are local to this file (spire_fake.go is
// owned by a concurrent task and is NOT touched); they reuse the in-package
// randomSerial + b64url helpers only.
package mint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// stubX509Provider is the in-memory fake x509SVIDProvider (spire_live.go) — a stand-in
// for *workloadapi.X509Source. It returns a fixed synthetic SVID + bundle, or an
// error, so the adapter's fetch/adapt/chain logic is exercised without any live
// Workload-API client.
type stubX509Provider struct {
	svid      *x509svid.SVID
	bundle    *x509bundle.Bundle
	svidErr   error
	bundleErr error
}

func (s *stubX509Provider) GetX509SVID() (*x509svid.SVID, error) {
	if s.svidErr != nil {
		return nil, s.svidErr
	}
	return s.svid, nil
}

func (s *stubX509Provider) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if s.bundleErr != nil {
		return nil, s.bundleErr
	}
	return s.bundle, nil
}

// liveTestClock is the pinned clock the live-adapter tests share (the spire suite's
// convention) so the synthetic CA/leaf validity windows are deterministic.
func liveTestClock() time.Time { return time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC) }

// newSyntheticWorkloadSVID mints a synthetic SPIRE-shaped X.509-SVID the way a live
// Workload API would hand one to the workload: a fresh ECDSA leaf (sole URI SAN =
// spiffeID, client-auth) signed by a synthetic trust-domain CA, plus the
// x509bundle.Bundle holding that CA. The leaf private key is returned as the
// SVID.PrivateKey (a crypto.Signer) — what the adapter signs the parallel JWS with.
func newSyntheticWorkloadSVID(t *testing.T, spiffeID string, now time.Time) (*x509svid.SVID, *x509bundle.Bundle) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen synthetic ca key: %v", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		t.Fatalf("ca serial: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "ds-live-test-synthetic-trust-domain"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create synthetic ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse synthetic ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen synthetic leaf key: %v", err)
	}
	sanURI, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("parse spiffe id: %v", err)
	}
	leafSerial, err := randomSerial()
	if err != nil {
		t.Fatalf("leaf serial: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "live-test-workload"},
		URIs:         []*url.URL{sanURI},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create synthetic leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse synthetic leaf: %v", err)
	}

	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		t.Fatalf("spiffeid.FromString: %v", err)
	}
	svid := &x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{leafCert},
		PrivateKey:   leafKey,
	}
	bundle := x509bundle.FromX509Authorities(id.TrustDomain(), []*x509.Certificate{caCert})
	return svid, bundle
}

// TestLiveSVIDSource_AdaptedSVIDVerifies asserts the core adaptation: the live
// adapter (a) produces an X509SVID whose parallel JWS verifies against the fetched
// leaf key, (b) carries that leaf as CertDER, and (c) publishes a TrustBundle that
// CHAINS the leaf. This is the live-leg counterpart to the synthetic fake's mint.
func TestLiveSVIDSource_AdaptedSVIDVerifies(t *testing.T) {
	now := liveTestClock()
	spiffeID := "spiffe://" + testOrg + "/session/" + testSession
	svid, bundle := newSyntheticWorkloadSVID(t, spiffeID, now)
	src := &liveSVIDSource{src: &stubX509Provider{svid: svid, bundle: bundle}}

	out, err := src.FetchX509SVID(X509SVIDRequest{
		SpiffeID:  spiffeID,
		Claims:    jwtClaims{Subject: spiffeID, Issuer: issuerName, SessionUUID: testSession, Org: testOrg},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}

	// (a) the parallel JWS verifies against the fetched leaf key.
	claims, err := verifyJWT(out.PublicKey, out.JWT)
	if err != nil {
		t.Fatalf("parallel JWS does not verify against the adapted leaf key: %v", err)
	}
	if claims.Subject != spiffeID {
		t.Fatalf("JWS sub = %q, want %q", claims.Subject, spiffeID)
	}

	// (b) CertDER is the fetched leaf, and its key matches the returned PublicKey.
	leaf, err := x509.ParseCertificate(out.CertDER)
	if err != nil {
		t.Fatalf("parse adapted CertDER: %v", err)
	}
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafKey.Equal(out.PublicKey) {
		t.Fatal("adapted CertDER leaf key does not match the returned PublicKey")
	}
	if out.Expiry != leaf.NotAfter {
		t.Fatalf("Expiry = %v, want leaf.NotAfter %v", out.Expiry, leaf.NotAfter)
	}

	// (c) TrustBundle chains the leaf.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       src.TrustBundle(),
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("adapted leaf does not chain to the live TrustBundle: %v", err)
	}
}

// TestLiveSVIDSource_AuthorityAllowsAdaptedSVID drives the adapted SVID through the
// FULL authority (NewSpireWorkloadAuthority over the liveSVIDSource): MintWorkload
// then VerifyPresented must ALLOW it — the live adapter is interchangeable with the
// synthetic fake at the SVIDSource seam. The expected name is the WORKLOAD's own
// SVID SAN (the live leg serves the workload's own identity; see spire_live.go).
func TestLiveSVIDSource_AuthorityAllowsAdaptedSVID(t *testing.T) {
	now := liveTestClock()
	spiffeID := "spiffe://" + testOrg + "/session/" + testSession
	svid, bundle := newSyntheticWorkloadSVID(t, spiffeID, now)
	authority := NewSpireWorkloadAuthority(&liveSVIDSource{src: &stubX509Provider{svid: svid, bundle: bundle}})

	res, err := authority.MintWorkload(WorkloadMintRequest{
		Spiffe:      spiffeID,
		SessionUUID: testSession,
		Org:         testOrg,
		NotBefore:   now,
		NotAfter:    now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("MintWorkload over live adapter: %v", err)
	}
	claims, err := authority.VerifyPresented([]byte(res.JWT), spiffeID, now)
	if err != nil {
		t.Fatalf("VerifyPresented must ALLOW the adapted SVID: %v", err)
	}
	if claims.Subject != spiffeID {
		t.Fatalf("verified claims sub = %q, want %q", claims.Subject, spiffeID)
	}
}

// TestLiveSVIDSource_ProviderErrorFailsClosed proves the adapter fails CLOSED when
// the underlying Workload-API provider errors: FetchX509SVID surfaces the error, and
// TrustBundle returns a non-nil EMPTY pool (so a presented SVID cannot chain → DENY)
// rather than nil or a panic.
func TestLiveSVIDSource_ProviderErrorFailsClosed(t *testing.T) {
	boom := errors.New("workload api unavailable")
	src := &liveSVIDSource{src: &stubX509Provider{svidErr: boom}}

	if _, err := src.FetchX509SVID(X509SVIDRequest{SpiffeID: "spiffe://" + testOrg + "/session/" + testSession}); err == nil {
		t.Fatal("FetchX509SVID must error when the provider errors")
	}
	pool := src.TrustBundle()
	if pool == nil {
		t.Fatal("TrustBundle must return a non-nil (empty) pool on provider error, never nil")
	}
	// An empty pool means nothing chains: confirm a real synthetic leaf is rejected.
	now := liveTestClock()
	svid, _ := newSyntheticWorkloadSVID(t, "spiffe://"+testOrg+"/session/"+testSession, now)
	leaf := svid.Certificates[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("an empty fail-closed TrustBundle must not chain any leaf")
	}
}

// TestLiveSVIDSource_NoCertificatesFailsClosed guards the degenerate SVID (no
// certificates) — the adapter must error, not index out of range.
func TestLiveSVIDSource_NoCertificatesFailsClosed(t *testing.T) {
	src := &liveSVIDSource{src: &stubX509Provider{svid: &x509svid.SVID{}}}
	if _, err := src.FetchX509SVID(X509SVIDRequest{SpiffeID: "spiffe://" + testOrg + "/session/" + testSession}); err == nil {
		t.Fatal("FetchX509SVID must error on an SVID with no certificates")
	}
}

// TestDialSpireWorkloadAPI_EmptySocketDeferred locks in the empty-socket deferral
// sentinel after wiring the live leg: DialSpireWorkloadAPI("") must STILL return
// errSpireLiveDeferred and a nil source (no live dial is ever attempted in CI, which
// supplies no socket). This is the live-file twin of the existing
// TestSpireAuthority_DialLiveDeferred (which this must NOT duplicate by name); it
// additionally asserts the sentinel error identity via errors.Is.
func TestDialSpireWorkloadAPI_EmptySocketDeferred(t *testing.T) {
	src, err := DialSpireWorkloadAPI("")
	if err == nil {
		t.Fatal("DialSpireWorkloadAPI(\"\") must return an error (deferred)")
	}
	if !errors.Is(err, errSpireLiveDeferred) {
		t.Fatalf("DialSpireWorkloadAPI(\"\") error = %v, want errSpireLiveDeferred", err)
	}
	if src != nil {
		t.Fatal("DialSpireWorkloadAPI(\"\") must return a nil source")
	}
}
