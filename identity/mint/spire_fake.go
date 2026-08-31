// SPDX-License-Identifier: Apache-2.0

// The synthetic SPIRE-Workload-API-shaped fake (D50; doc 16 §2/§9).
//
// fakeSVIDSource is the ONLY SVIDSource in-wave: a behavioral fake of the SPIRE
// X.509-SVID flow, the SAME posture as identity/fakes/digest-publisher — it speaks
// the documented SVID shape end-to-end so the SPIRE-backed WorkloadAuthority
// (spire_authority.go) can be exercised WITHOUT live SPIRE infra. There is no live
// SPIRE Agent, no Workload-API socket, no go-spiffe dependency (verified NOT
// vendored): the fake mints SPIRE-shaped X.509-SVIDs under its own SYNTHETIC
// trust-domain CA and publishes that CA as the trust bundle, so the authority's
// verify leg can chain a presented SVID to it and assert the URI SAN — the full
// SPIRE check, against synthetic material.
//
// SYNTHETIC ONLY (D50): the trust-domain CA, every leaf key, and every SVID minted
// here are synthetic — no real SPIFFE trust domain, no real key, ever appears. This
// mirrors the digest-publisher fake's "every value is synthetic" charter. A live
// deployment swaps this for a real Workload-API-backed SVIDSource behind the same
// narrow seam (DialSpireWorkloadAPI, a DEFERRED env-gated step).
//
// The DEFAULT synthetic CA is a FLAT trust domain (the trust-bundle CA directly
// signs the leaf SVID — no intermediates), the simplest shape that exercises the
// chain-to-bundle check. The authority's verify leg supports intermediates (x5c[1:])
// for a live hierarchical trust domain.
//
// HIERARCHICAL VARIANT (newHierarchicalFakeSVIDSource). A live SPIRE deployment
// commonly interposes a signing INTERMEDIATE CA between the published trust-bundle
// root and the leaf SVID, so the leaf no longer chains DIRECTLY to the bundle — the
// verify leg must walk the leaf -> intermediate -> root chain (the authority's
// x5c[1:] -> Intermediates pool path, spire_authority.go VerifyPresented). The
// hierarchical fake mints a synthetic intermediate CA signed by the trust-domain
// root and signs every leaf with the INTERMEDIATE; the parallel JWS carries the full
// chain [leaf, intermediate] in its `x5c` so the authority can re-assemble it (the
// root alone stays the published bundle). It is the SAME synthetic-only posture (D50)
// — root key, intermediate key, and every leaf key are synthetic, never live.
package mint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// fakeSVIDSource is the synthetic in-memory SVIDSource (D50). It holds ONE synthetic
// trust-domain CA (the SPIRE trust bundle the authority chains presented SVIDs to)
// and mints SPIRE-shaped X.509-SVIDs under it on demand. Stateless beyond the CA:
// each FetchX509SVID mints a fresh leaf key + cert + parallel JWS, exactly as a
// SPIRE Agent issues a fresh X.509-SVID per workload.
type fakeSVIDSource struct {
	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	caDER   []byte
	bundle  *x509.CertPool
	now     func() time.Time
	failURI bool // test hook: stamp a WRONG URI SAN to prove the authority's SAN check fails closed

	// HIERARCHICAL trust-domain variant (newHierarchicalFakeSVIDSource): a synthetic
	// signing INTERMEDIATE CA signed by the trust-domain root (caCert/caKey). When set,
	// the leaf is signed by the intermediate (NOT the root) and the parallel JWS carries
	// the full chain [leaf, intermediate] in `x5c`, so the leaf no longer chains DIRECTLY
	// to the published bundle — the authority must walk leaf -> intermediate -> root. The
	// published trust bundle still holds ONLY the root (intKey/intCert are nil in the flat
	// default, leaving FetchX509SVID's behavior byte-identical to the flat trust domain).
	// intKey/intCert/intDER are the LEAF-SIGNING (deepest) intermediate so the flat and
	// single-intermediate paths stay byte-identical when aboveInt is empty.
	intKey  *ecdsa.PrivateKey
	intCert *x509.Certificate
	intDER  []byte

	// aboveInt holds any EXTRA intermediate CA certs interposed ABOVE the leaf-signing
	// intermediate (intCert), root-ward — DER, ordered nearest-the-leaf first (so a 2-level
	// root -> int1 -> int2 -> leaf chain stores int1 here, int2 in intCert). It is nil for
	// the flat default and the SINGLE-intermediate variant, leaving FetchX509SVID and
	// intermediatesOf byte-identical for those paths; the deeper-chain builder
	// (newDeepHierarchicalFakeSVIDSource) populates it so the authority's x5c[1:] ->
	// Intermediates pool walk is exercised at depth 2, the shape a multi-tier live SPIRE
	// trust domain produces. These certs ride the SVID's x5c + Intermediates alongside
	// intDER so the verify leg re-assembles the full leaf -> int2 -> int1 -> root path.
	aboveInt [][]byte
}

// NewFakeSVIDSource builds the synthetic SPIRE fake: a fresh synthetic trust-domain
// CA (D50) whose self-signed cert IS the trust bundle. now pins the CA validity
// window (tests pass a fixed clock so freshness is deterministic); a nil now uses
// time.Now. This is the in-wave SVIDSource passed to WithSpireAuthority /
// NewSpireWorkloadAuthority — the ONLY one, since live SPIRE is deferred (D50).
func NewFakeSVIDSource(now func() time.Time) (SVIDSource, error) {
	return newFakeSVIDSource(now)
}

// newFakeSVIDSource is the concrete constructor (returns the typed *fakeSVIDSource
// so in-package tests can reach the failURI hook). The trust-domain CA is a
// synthetic self-signed root marked for cert-signing — the SPIRE trust domain's
// signing authority, published as the trust bundle.
func newFakeSVIDSource(now func() time.Time) (*fakeSVIDSource, error) {
	if now == nil {
		now = time.Now
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint: generate synthetic trust-domain ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	t := now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ds-synthetic-spire-trust-domain",
			Organization: []string{"dream-serpent (synthetic SPIRE trust domain, D50)"},
		},
		NotBefore:             t.Add(-time.Minute),
		NotAfter:              t.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("mint: create synthetic trust-domain ca cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("mint: parse synthetic trust-domain ca cert: %w", err)
	}
	bundle := x509.NewCertPool()
	bundle.AddCert(caCert)
	return &fakeSVIDSource{
		caKey:  caKey,
		caCert: caCert,
		caDER:  caDER,
		bundle: bundle,
		now:    now,
	}, nil
}

// TrustBundle returns the synthetic trust domain's CA pool — the SPIRE trust bundle
// the authority chains a presented X.509-SVID to. Seeded with ONLY this fake's CA,
// so an SVID minted by a DIFFERENT (unknown) authority never chains here — the
// fail-closed property the DENY-for-unknown acceptance case exercises.
func (f *fakeSVIDSource) TrustBundle() *x509.CertPool {
	return f.bundle
}

// FetchX509SVID mints a SPIRE-shaped X.509-SVID for the normalized request: a
// client-auth leaf whose SOLE URI SAN is req.SpiffeID (spiffe://<org>/session/<uuid>,
// the §3.1 name), signed by the synthetic trust-domain CA so it chains to the
// bundle, plus the parallel ES256 JWS over req.Claims signed with the SAME leaf key
// (the cert and token are two presentations of one identity — the own-CA invariant,
// preserved across the swap). The JWS carries the leaf cert in its `x5c` header so
// the authority's verify leg can chain it to the bundle without an out-of-band
// fetch. Synthetic (D50): a fresh leaf key per call, never reused, never persisted.
func (f *fakeSVIDSource) FetchX509SVID(req X509SVIDRequest) (X509SVID, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return X509SVID{}, fmt.Errorf("mint: generate synthetic svid leaf key: %w", err)
	}
	// The sole URI SAN is the §3.1 SPIFFE name (or, under the failURI test hook, a
	// deliberately WRONG name to prove the authority's SAN equality check fails closed
	// even for a credential that DOES chain to the bundle).
	sanString := req.SpiffeID
	if f.failURI {
		sanString = req.SpiffeID + "/tampered"
	}
	sanURI, err := svidURISAN(sanString)
	if err != nil {
		return X509SVID{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return X509SVID{}, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: req.Claims.SessionUUID,
		},
		URIs:        []*url.URL{sanURI}, // the SPIRE X.509-SVID's single URI SAN (the SPIFFE ID)
		NotBefore:   req.NotBefore,
		NotAfter:    req.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	// The leaf is signed by the INTERMEDIATE when this is a hierarchical trust domain,
	// otherwise directly by the trust-domain root (the flat default — byte-identical
	// to the original flat fake when intKey/intCert are nil).
	signerCert, signerKey := f.caCert, f.caKey
	if f.intKey != nil {
		signerCert, signerKey = f.intCert, f.intKey
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, signerCert, &leafKey.PublicKey, signerKey)
	if err != nil {
		return X509SVID{}, fmt.Errorf("mint: sign synthetic x509-svid leaf: %w", err)
	}
	// The parallel JWS carries the X.509-SVID chain in `x5c` (leaf-first) so
	// VerifyPresented can chain the SVID to the trust bundle (the SPIRE authenticity
	// check). A flat trust domain carries just the leaf; a single-intermediate one appends
	// the interposed intermediate (x5c[1:]); a DEEPER (2-level) one appends every
	// interposed CA, leaf-ward first (leaf, int2, int1), so the authority walks
	// leaf -> int2 -> int1 -> root — the published bundle still holds only the root.
	chain := [][]byte{leafDER}
	if f.intDER != nil {
		chain = append(chain, f.intDER)
		chain = append(chain, f.aboveInt...)
	}
	jws, err := signJWSWithX5c(leafKey, req.Claims, chain)
	if err != nil {
		return X509SVID{}, err
	}
	return X509SVID{
		CertDER:       leafDER,
		Intermediates: intermediatesOf(f),
		JWT:           jws,
		PublicKey:     &leafKey.PublicKey,
		Expiry:        req.NotAfter,
	}, nil
}

// intermediatesOf returns the interposed intermediate chain (DER) the source signs
// leaves with — empty for a flat trust domain, the single synthetic intermediate for
// the single-level hierarchical variant, and the FULL stack (leaf-signing intermediate
// first, then each CA above it root-ward) for the deeper 2-level variant. It populates
// X509SVID.Intermediates so a caller that records the SVID (not just the JWS x5c)
// carries the full chain, matching the documented X509SVID shape (spire_authority.go).
func intermediatesOf(f *fakeSVIDSource) [][]byte {
	if f.intDER == nil {
		return nil
	}
	out := make([][]byte, 0, 1+len(f.aboveInt))
	out = append(out, f.intDER)
	out = append(out, f.aboveInt...)
	return out
}

// newHierarchicalFakeSVIDSource builds the HIERARCHICAL synthetic trust domain (D50):
// a synthetic signing INTERMEDIATE CA signed by the trust-domain root, with every leaf
// SVID signed by the intermediate (NOT the root). The published trust bundle holds
// ONLY the root, so a presented leaf no longer chains DIRECTLY to it — the authority
// must walk leaf -> intermediate -> root via the JWS `x5c[1:]` chain. This exercises
// the authority's intermediate chain-walk (spire_authority.go VerifyPresented), the
// shape a live SPIRE deployment with an interposed signing CA produces. now pins the
// CA validity windows (a nil now uses time.Now), shared with the test clock so
// validity is deterministic. Returns the typed *fakeSVIDSource so in-package tests can
// reach the chain internals; NewHierarchicalFakeSVIDSource is the interface-returning
// public constructor.
func newHierarchicalFakeSVIDSource(now func() time.Time) (*fakeSVIDSource, error) {
	f, err := newFakeSVIDSource(now)
	if err != nil {
		return nil, err
	}
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint: generate synthetic intermediate ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	t := f.now()
	intTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ds-synthetic-spire-signing-intermediate",
			Organization: []string{"dream-serpent (synthetic SPIRE trust domain, D50)"},
		},
		NotBefore:             t.Add(-time.Minute),
		NotAfter:              t.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // the intermediate may sign leaves only (no further CA below it)
		MaxPathLenZero:        true,
	}
	// The intermediate is signed by the trust-domain ROOT (f.caCert/f.caKey), so it
	// chains to the published bundle while the leaf chains only THROUGH it.
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, f.caCert, &intKey.PublicKey, f.caKey)
	if err != nil {
		return nil, fmt.Errorf("mint: create synthetic intermediate ca cert: %w", err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		return nil, fmt.Errorf("mint: parse synthetic intermediate ca cert: %w", err)
	}
	f.intKey = intKey
	f.intCert = intCert
	f.intDER = intDER
	return f, nil
}

// NewHierarchicalFakeSVIDSource is the interface-returning public constructor for the
// hierarchical synthetic trust domain (D50): a synthetic intermediate CA signed by the
// trust-domain root, leaves signed by the intermediate, so a presented SVID chains
// leaf -> intermediate -> root. The published bundle still holds ONLY the root — the
// authority re-assembles the chain from the JWS `x5c`. Use it BESIDE NewFakeSVIDSource
// (the flat default) to exercise the authority's intermediate chain-walk.
func NewHierarchicalFakeSVIDSource(now func() time.Time) (SVIDSource, error) {
	return newHierarchicalFakeSVIDSource(now)
}

// deepHierarchyOpts parameterizes the DEEPER (2-level) synthetic trust domain
// (newDeepHierarchicalFakeSVIDSource): root -> int1 -> int2 -> leaf. The defaults
// (a zero deepHierarchyOpts) mint a WELL-FORMED 2-level chain — int1 a CA with
// MaxPathLen:1 (it may sign one more CA below it), int2 a CA with MaxPathLen:0 (leaves
// only), both with the SAME validity window as the root — so the happy path Validates
// ALLOW. The negative knobs deliberately BREAK the UPPER intermediate (int1, the CA the
// single-intermediate fake never had) so the Go verifier's basic-constraints /
// path-length / chain-time enforcement is exercised on an INTERPOSED CA, not just the
// leaf:
//
//   - int1NotCA: mint int1 WITHOUT the CA basic constraint (IsCA=false). A non-CA cert
//     in a signing position breaks the chain — the verifier rejects it fail-closed.
//   - int1MaxPathLenZero: mint int1 with MaxPathLen:0 (it may sign leaves only, not a CA
//     below it). int2 IS a CA below it, so the path-length budget is exceeded — the
//     verifier rejects the over-long path fail-closed.
//   - int1NotBefore / int1NotAfter: override int1's validity window so it does NOT cover
//     the pinned clock (an expired or not-yet-valid interposed CA) while the leaf stays
//     time-valid — the verifier's CurrentTime check must cover the interposed CA, not
//     just the leaf, so the chain fails closed.
type deepHierarchyOpts struct {
	int1NotCA          bool
	int1MaxPathLenZero bool
	int1NotBefore      time.Time // zero => root-equal window
	int1NotAfter       time.Time // zero => root-equal window
}

// newDeepHierarchicalFakeSVIDSource builds a DEEPER (2-level) synthetic trust domain
// (D50): root -> int1 -> int2 -> leaf, with the leaf signed by the deepest intermediate
// (int2) and the parallel JWS carrying the FULL chain [leaf, int2, int1] in `x5c`, so a
// presented leaf chains leaf -> int2 -> int1 -> root. The published trust bundle still
// holds ONLY the root, so the authority must walk BOTH interposed CAs (the x5c[1:] ->
// Intermediates pool path at depth 2) — the shape a multi-tier live SPIRE trust domain
// produces and the deepest reach of the authority's chain-walk the single-intermediate
// fake cannot exercise. opts deliberately breaks int1 (the upper CA) for the
// CA-constraint / path-length / chain-time fail-closed rows; a zero opts mints a
// well-formed chain that Validates ALLOW. now pins every validity window (a nil now uses
// time.Now), shared with the test clock so validity is deterministic. Returns the typed
// *fakeSVIDSource so in-package tests can reach the chain internals.
func newDeepHierarchicalFakeSVIDSource(now func() time.Time, opts deepHierarchyOpts) (*fakeSVIDSource, error) {
	f, err := newFakeSVIDSource(now)
	if err != nil {
		return nil, err
	}
	t := f.now()

	// int1: the UPPER intermediate, signed by the trust-domain ROOT. By default a CA with
	// a path-length budget of 1 (it may sign one more CA — int2 — below it).
	int1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint: generate synthetic upper-intermediate ca key: %w", err)
	}
	int1Serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	int1NotBefore := t.Add(-time.Minute)
	int1NotAfter := t.Add(rootValidity)
	if !opts.int1NotBefore.IsZero() {
		int1NotBefore = opts.int1NotBefore
	}
	if !opts.int1NotAfter.IsZero() {
		int1NotAfter = opts.int1NotAfter
	}
	int1Tmpl := &x509.Certificate{
		SerialNumber: int1Serial,
		Subject: pkix.Name{
			CommonName:   "ds-synthetic-spire-upper-intermediate",
			Organization: []string{"dream-serpent (synthetic SPIRE trust domain, D50)"},
		},
		NotBefore:             int1NotBefore,
		NotAfter:              int1NotAfter,
		BasicConstraintsValid: true,
	}
	switch {
	case opts.int1NotCA:
		// int1 is NOT a CA — a leaf-shaped cert interposed in a signing slot. It carries
		// digital-signature usage (a leaf's usage) and NO CA basic constraint / MaxPathLen
		// (x509.CreateCertificate refuses MaxPathLen on a non-CA), so the verifier rejects
		// the non-CA-in-a-signing-position chain fail-closed.
		int1Tmpl.IsCA = false
		int1Tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	case opts.int1MaxPathLenZero:
		// MaxPathLen:0 means int1 may sign LEAVES only — int2 (a CA) below it exceeds the
		// budget, so the path is over-long and the verifier rejects it fail-closed.
		int1Tmpl.IsCA = true
		int1Tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		int1Tmpl.MaxPathLen = 0
		int1Tmpl.MaxPathLenZero = true
	default:
		// Well-formed upper CA with a path-length budget of 1 (it may sign one CA — int2 —
		// below it).
		int1Tmpl.IsCA = true
		int1Tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		int1Tmpl.MaxPathLen = 1
	}
	int1DER, err := x509.CreateCertificate(rand.Reader, int1Tmpl, f.caCert, &int1Key.PublicKey, f.caKey)
	if err != nil {
		return nil, fmt.Errorf("mint: create synthetic upper-intermediate ca cert: %w", err)
	}
	int1Cert, err := x509.ParseCertificate(int1DER)
	if err != nil {
		return nil, fmt.Errorf("mint: parse synthetic upper-intermediate ca cert: %w", err)
	}

	// int2: the LEAF-SIGNING (deepest) intermediate, signed by int1. A CA with
	// MaxPathLen:0 (leaves only) and the root-equal validity window — it is the well-formed
	// signer the leaf chains through. Stored in intCert/intDER so FetchX509SVID signs with
	// it (the deepest intermediate), exactly like the single-intermediate variant.
	int2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint: generate synthetic leaf-signing intermediate ca key: %w", err)
	}
	int2Serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	int2Tmpl := &x509.Certificate{
		SerialNumber: int2Serial,
		Subject: pkix.Name{
			CommonName:   "ds-synthetic-spire-leaf-signing-intermediate",
			Organization: []string{"dream-serpent (synthetic SPIRE trust domain, D50)"},
		},
		NotBefore:             t.Add(-time.Minute),
		NotAfter:              t.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // the deepest intermediate may sign leaves only
		MaxPathLenZero:        true,
	}
	int2DER, err := x509.CreateCertificate(rand.Reader, int2Tmpl, int1Cert, &int2Key.PublicKey, int1Key)
	if err != nil {
		return nil, fmt.Errorf("mint: create synthetic leaf-signing intermediate ca cert: %w", err)
	}
	int2Cert, err := x509.ParseCertificate(int2DER)
	if err != nil {
		return nil, fmt.Errorf("mint: parse synthetic leaf-signing intermediate ca cert: %w", err)
	}

	// The deepest intermediate (int2) is the leaf signer (intKey/intCert/intDER); int1
	// sits ABOVE it (aboveInt), so the published chain is leaf -> int2 -> int1 -> root.
	f.intKey = int2Key
	f.intCert = int2Cert
	f.intDER = int2DER
	f.aboveInt = [][]byte{int1DER}
	return f, nil
}

// NewDeepHierarchicalFakeSVIDSource is the interface-returning public constructor for the
// well-formed DEEPER (2-level) synthetic trust domain (D50): root -> int1 -> int2 ->
// leaf, leaves signed by the deepest intermediate, so a presented SVID chains leaf ->
// int2 -> int1 -> root through TWO interposed CAs. The published bundle still holds ONLY
// the root — the authority re-assembles the chain from the JWS `x5c`. Use it beside
// NewHierarchicalFakeSVIDSource to exercise the authority's chain-walk at depth 2.
func NewDeepHierarchicalFakeSVIDSource(now func() time.Time) (SVIDSource, error) {
	return newDeepHierarchicalFakeSVIDSource(now, deepHierarchyOpts{})
}

// signJWSWithX5c produces a compact ES256 JWS over claims, signed with key, with the
// X.509-SVID chain (DER, leaf-first) carried in the protected header's `x5c` (RFC
// 7515 §4.1.6, base64url DER). It mirrors signJWT (jwt.go) byte-for-byte except for
// the `x5c` header field: the same ES256 R||S over SHA-256(b64(hdr).b64(claims))
// shape, so the authority's verifyJWSWithKey verifies it identically. The chain lets
// the verify leg chain the SVID to the trust bundle without an out-of-band fetch.
func signJWSWithX5c(key *ecdsa.PrivateKey, claims jwtClaims, chainDER [][]byte) (string, error) {
	x5c := make([]string, 0, len(chainDER))
	for _, der := range chainDER {
		x5c = append(x5c, b64url.EncodeToString(der))
	}
	hdrJSON, err := json.Marshal(jwsHeader{Alg: "ES256", Typ: "JWT", X5c: x5c})
	if err != nil {
		return "", fmt.Errorf("mint: marshal svid jws header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("mint: marshal svid jws claims: %w", err)
	}
	signingInput := b64url.EncodeToString(hdrJSON) + "." + b64url.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("mint: sign svid jws: %w", err)
	}
	// JWS ES256 signature is the fixed-width R||S concatenation (RFC 7518 §3.4): each
	// of R and S left-padded to the curve byte size (32 for P-256).
	const p256Bytes = 32
	sig := make([]byte, 2*p256Bytes)
	r.FillBytes(sig[:p256Bytes])
	s.FillBytes(sig[p256Bytes:])
	return signingInput + "." + b64url.EncodeToString(sig), nil
}
