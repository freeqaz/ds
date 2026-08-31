// SPDX-License-Identifier: Apache-2.0

// The LIVE SPIRE Workload-API SVIDSource (D50; doc 16 §2/§9) — the deferred,
// env-gated leg behind DialSpireWorkloadAPI, now wired against a real
// go-spiffe/v2 Workload-API client.
//
// SCOPE & POSTURE. This file is the ONLY place go-spiffe/v2 is reached. It is a
// DEFERRED MANUAL leg (D50): the dial talks to a real SPIRE Agent's Workload API
// socket and is NEVER exercised in CI (there is no live SPIRE Agent in-wave). The
// synthetic fake (spire_fake.go) remains the sole in-CI SVIDSource. The adapter
// here (liveSVIDSource) is, however, fully unit-tested against an in-memory fake
// provider (spire_live_test.go) so the *adaptation logic* — not the live dial — is
// covered hermetically.
//
// WHAT A LIVE WORKLOAD API GIVES YOU (the architectural boundary — read carefully).
// A SPIRE Workload API hands a workload its OWN X.509-SVID: the workload's leaf
// cert chain + the workload's leaf private key, plus the trust-domain X.509 bundle.
// It is NOT a per-session minting service like the synthetic CA fake. So the live
// FetchX509SVID does NOT mint an arbitrary per-session cert for req.SpiffeID — it
// FETCHES this workload's current SVID and ADAPTS it to the X509SVID shape,
// signing req.Claims as the parallel ES256 JWS with the FETCHED LEAF'S private key.
//
// Consequently the live SVID's identity is the WORKLOAD'S OWN SPIFFE ID (whatever
// SPIRE issued it), which need not equal req.SpiffeID (the §3.1
// spiffe://<org>/session/<uuid> the Shim computed). The per-session-NAME minting
// semantics of the synthetic fake — a fresh leaf whose URI SAN is exactly
// req.SpiffeID — are a SEPARATE concern this deferred live leg does NOT attempt
// (reconciling them would require SPIRE registration-entry / delegated-identity
// provisioning, out of scope for this dial). We therefore treat req.SpiffeID
// LENIENTLY: it is NOT asserted against the fetched leaf's SAN here; the returned
// SVID carries the fetched leaf's own URI SAN, and the parallel JWS `sub` carries
// whatever req.Claims.Subject the Shim set. A deployment that wants the §3.1
// per-session name to ride the live SVID must provision SPIRE to issue that name.
package mint

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// x509SVIDProvider is the NARROW unexported seam the live adapter depends on — the
// two Workload-API reads the SPIRE X.509-SVID flow needs. The concrete
// *workloadapi.X509Source satisfies BOTH methods, so the live dial wires the real
// source through here; the hermetic test (spire_live_test.go) supplies an in-memory
// fake. Keeping it unexported + minimal mirrors the SVIDSource posture: nothing
// beyond fetch-my-SVID + read-the-bundle is reachable.
type x509SVIDProvider interface {
	// GetX509SVID returns THIS workload's current X.509-SVID (leaf-first cert chain
	// + leaf private key + the workload's SPIFFE ID).
	GetX509SVID() (*x509svid.SVID, error)
	// GetX509BundleForTrustDomain returns the published X.509 trust bundle (the CA
	// authorities) for a trust domain.
	GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error)
}

// liveSVIDSource adapts a live go-spiffe Workload-API source to the narrow
// SVIDSource seam (spire_authority.go). It owns NO key material and NO synthetic CA
// (unlike fakeSVIDSource): every cert + key comes from SPIRE over src. Synthetic
// material never appears here — this is the real-deployment leg (D50).
type liveSVIDSource struct {
	src x509SVIDProvider
}

// FetchX509SVID fetches THIS workload's current X.509-SVID from SPIRE and adapts it
// to the X509SVID shape, signing req.Claims as the parallel ES256 JWS with the
// fetched leaf's OWN private key (the cert and token stay two presentations of one
// identity — the own-CA invariant, preserved). It does NOT mint a per-session cert
// for req.SpiffeID (see the package doc): the returned SVID carries the WORKLOAD'S
// own URI SAN, and req.SpiffeID is treated leniently (not asserted here). The JWS
// `x5c` carries the fetched leaf + intermediates so the authority's verify leg can
// chain it to the trust bundle exactly as for the synthetic fake.
func (s *liveSVIDSource) FetchX509SVID(req X509SVIDRequest) (X509SVID, error) {
	svid, err := s.src.GetX509SVID()
	if err != nil {
		return X509SVID{}, fmt.Errorf("mint: live spire fetch x509-svid: %w", err)
	}
	if svid == nil || len(svid.Certificates) == 0 {
		return X509SVID{}, errors.New("mint: live spire x509-svid has no certificates")
	}
	leaf := svid.Certificates[0]
	intermediates := make([][]byte, 0, len(svid.Certificates)-1)
	for _, ic := range svid.Certificates[1:] {
		intermediates = append(intermediates, ic.Raw)
	}
	// The JWS is signed with the FETCHED leaf's key. svid.PrivateKey is a
	// crypto.Signer; in a SPIRE X.509-SVID it is an ECDSA key in practice, which is
	// what the ES256 JWS path (signJWSWithSigner) requires.
	chain := make([][]byte, 0, len(svid.Certificates))
	chain = append(chain, leaf.Raw)
	chain = append(chain, intermediates...)
	jws, err := signJWSWithSigner(svid.PrivateKey, req.Claims, chain)
	if err != nil {
		return X509SVID{}, fmt.Errorf("mint: live spire sign parallel jws: %w", err)
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return X509SVID{}, fmt.Errorf("mint: live spire x509-svid leaf key is %T, want *ecdsa.PublicKey (ES256)", leaf.PublicKey)
	}
	return X509SVID{
		CertDER:       leaf.Raw,
		Intermediates: intermediates,
		JWT:           jws,
		PublicKey:     leafPub,
		Expiry:        leaf.NotAfter,
	}, nil
}

// TrustBundle returns the live trust domain's CA pool — the published X.509
// authorities the authority chains a presented SVID to. The trust domain is derived
// from THIS workload's own SVID ID (the SVID and its bundle share a trust domain).
// Fail-CLOSED on any error: an empty pool means a presented SVID cannot chain
// (DENY), never a panic and never a nil pool. A live deployment renews the bundle
// out of band; the source returns the current snapshot on each call.
func (s *liveSVIDSource) TrustBundle() *x509.CertPool {
	pool := x509.NewCertPool()
	svid, err := s.src.GetX509SVID()
	if err != nil || svid == nil {
		return pool // fail closed: empty pool, nothing chains
	}
	bundle, err := s.src.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil || bundle == nil {
		return pool // fail closed
	}
	for _, ca := range bundle.X509Authorities() {
		pool.AddCert(ca)
	}
	return pool
}

// liveDialTimeout bounds the live Workload-API dial so a misconfigured /
// unreachable socket fails fast (workloadapi.NewX509Source blocks on the initial
// Workload-API update; gRPC otherwise retries an unreachable socket with backoff
// indefinitely). A reachable SPIRE Agent delivers the initial SVID in
// milliseconds, so a few seconds is ample headroom; an unreachable one fails at the
// deadline rather than hanging — and the existing deferred-step test, which dials a
// dead socket and asserts a prompt error + nil source, pays only this bound. It is
// the only knob the live leg adds.
const liveDialTimeout = 2 * time.Second

// DialSpireWorkloadAPI is the LIVE SPIRE Workload-API entry point (D50, env-gated
// deferred manual step). An empty socketAddr is the deferral sentinel — it ALWAYS
// returns errSpireLiveDeferred (a caller that forgot to supply the synthetic fake
// fails closed and loud rather than silently dialing nothing), preserving the
// in-wave/CI contract: no live dial is ever attempted in CI (which passes no
// socket).
//
// With a non-empty socketAddr it dials a REAL SPIRE Agent Workload API at that
// address (the SPIFFE_ENDPOINT_SOCKET / SPIRE_WORKLOAD_API_ADDR the operator
// publishes, e.g. "unix:///run/spire/agent.sock") via go-spiffe/v2's
// workloadapi.X509Source and wraps it in the live SVIDSource adapter. This is the
// deferred MANUAL leg: it requires a reachable SPIRE Agent socket and is NEVER run
// in CI. The dial is bounded by liveDialTimeout so an unreachable socket fails fast.
//
// Read the package doc for the identity boundary: the returned source serves THIS
// workload's own SPIRE-issued X.509-SVID — it is NOT a per-session-name minting
// service like the synthetic fake.
func DialSpireWorkloadAPI(socketAddr string) (SVIDSource, error) {
	if socketAddr == "" {
		return nil, errSpireLiveDeferred
	}
	ctx, cancel := context.WithTimeout(context.Background(), liveDialTimeout)
	defer cancel()
	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketAddr)))
	if err != nil {
		return nil, fmt.Errorf("mint: dial live spire workload api at %q: %w", socketAddr, err)
	}
	return &liveSVIDSource{src: source}, nil
}
