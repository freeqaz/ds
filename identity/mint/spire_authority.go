// SPDX-License-Identifier: Apache-2.0

// The M3 SPIRE-backed WorkloadAuthority (doc 16 §2 substrate progression;
// doc 05 §7 edge 5 — "a substrate swap behind a frozen contract, not a rebuild").
//
// This is the THIRD substrate in the D22 progression (M0 throwaway shim → M1 own
// minimal CA → M3 SPIFFE/SPIRE), swapped in BESIDE the M1 own-CA impl
// (ownCAWorkloadAuthority, mint.go) through the SAME narrow WorkloadAuthority seam
// — never a rebuild, never a contract change. It satisfies the frozen D24 Validate
// contract field-for-field: MintWorkload emits the §3.1 workload identity (an
// X.509-SVID with the URI SAN spiffe://<org>/session/<uuid> plus the parallel JWT
// presentation) and VerifyPresented re-derives the §3.1 claim set, exactly as the
// own-CA impl does — so the workload leg of Validate (validate.go) and
// MintWorkloadIdentity (mint.go) are byte-identical across the swap. The §3.1
// SPIFFE-compatible naming chosen at M1 is what makes this pure: the SPIRE-backed
// name is produced by the SAME Build / BuildSessionSpiffeID helper (spiffeid.go),
// so the URI SAN, the JWT `sub`, and the grant identity axis never drift.
//
// NARROW FAKEABLE SEAM (D50). The SPIRE substrate sits behind a NARROW SVIDSource
// interface — FetchX509SVID + TrustBundle, the two operations the documented SPIRE
// X.509-SVID flow needs — mirroring the established narrow-read-interface +
// synthetic-fake DI pattern (WithCAStore / WithSubstrateSigner). The ONLY in-CI
// SVIDSource is the synthetic in-memory fake (spire_fake.go), which mints
// SPIRE-shaped SVIDs under a synthetic trust-domain CA. A LIVE Workload-API socket
// dial now exists behind an env gate (DialSpireWorkloadAPI, body in spire_live.go)
// using a vendored go-spiffe/v2 client; it is a DEFERRED MANUAL step requiring a
// reachable SPIRE Agent socket and is NEVER exercised in CI (the empty-socket
// sentinel fails closed; CI supplies no socket). The live adapter's *adaptation*
// logic is unit-tested hermetically against an in-memory fake provider
// (spire_live_test.go) — but never a live dial.
//
// DOCUMENTED X.509-SVID SHAPE (built from the wire spec, not a library). A SPIRE
// X.509-SVID is an X.509 leaf whose single URI SAN is the SPIFFE ID, chaining to
// the trust domain's signing authority (the "trust bundle" — the set of CA certs
// the trust domain publishes). VerifyPresented therefore does the two SPIRE checks:
// (1) CHAIN the presented X.509-SVID leaf to the trust bundle (the SVID is
// authentic), and (2) assert the leaf's URI SAN EQUALS the expected spiffe:// name
// (it is the RIGHT identity). The presented credential stays format-opaque at the
// D22 seam (doc 16 §9): like the own-CA impl it is the parallel JWS, but it
// carries the X.509-SVID leaf in its `x5c` header so the verify leg can chain it
// to the trust bundle — the SPIRE authenticity check the M1 path did against a
// per-session recorded key, now done against the trust domain CA.
package mint

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// X509SVIDRequest is the normalized §3.1 claim input the SVIDSource mints an
// X.509-SVID for. It is the SPIRE-substrate face of WorkloadMintRequest: the Shim
// has already resolved the launching_user, computed the §3.1 SPIFFE name, and
// bounded the validity window, so the source only owns the substrate mint (the
// same already-resolved contract every authority impl sees).
type X509SVIDRequest struct {
	// SpiffeID is the §3.1 SPIFFE name (spiffe://<org>/session/<uuid>) the minted
	// X.509-SVID carries as its sole URI SAN and the parallel JWT carries as `sub`.
	SpiffeID string
	// Claims is the §3.1 claim set the parallel JWT presentation carries. The
	// source signs it with the SVID leaf key so the cert and token are two
	// presentations of one identity (the own-CA invariant, preserved).
	Claims jwtClaims
	// NotBefore / NotAfter bound the SVID (TTL = session lifetime, §3.1).
	NotBefore time.Time
	NotAfter  time.Time
}

// X509SVID is the documented SPIRE X.509-SVID a SVISource mints (doc 16 §3.1): the
// leaf certificate (DER) whose sole URI SAN is the SPIFFE ID, the intermediate
// chain (if any) the trust domain interposes between the leaf and the bundle, and
// the parallel JWT presentation signed with the SVID's leaf key. PublicKey is the
// leaf key the JWS verifies against; the Shim records it on the session record so
// the own-CA-shaped Validate workload leg has a key, but a SPIRE deployment
// verifies the JWS against the X.509-SVID's own embedded key on every call (the
// trust-bundle chain is the authority, not a per-session recorded key) — so a swap
// stays pure even for sessions this shim never recorded.
type X509SVID struct {
	// CertDER is the X.509-SVID leaf: a client-auth cert with the single SPIFFE URI
	// SAN, chaining (via Intermediates) to the trust domain's signing authority.
	CertDER []byte
	// Intermediates are any CA certs between the leaf and the trust bundle, DER. A
	// flat trust domain (the synthetic fake) leaves this empty.
	Intermediates [][]byte
	// JWT is the parallel ES256 JWS over Claims, signed with the leaf key — the
	// header-carried presentation (§3.1). Its `x5c` carries CertDER + Intermediates
	// so VerifyPresented can chain the SVID to the trust bundle.
	JWT string
	// PublicKey is the leaf key the JWS verifies against (the SVID's own key).
	PublicKey *ecdsa.PublicKey
	// Expiry is the SVID horizon (= NotAfter; TTL = session lifetime).
	Expiry time.Time
}

// SVIDSource is the NARROW fakeable seam the SPIRE-backed authority routes through
// — the documented two-operation SPIRE X.509-SVID flow: fetch this workload's SVID
// and read the trust bundle to verify a presented one. It mirrors the established
// narrow-read-interface + synthetic-fake DI pattern (CAStore, SubstrateSigner): the
// ONLY in-wave impl is the synthetic in-memory fake (spire_fake.go); a live SPIRE
// Workload-API client is a DEFERRED env-gated step (DialSpireWorkloadAPI), never
// reachable in-wave (D50 — no live SPIRE infra). Deliberately minimal so a swap is
// pure: the authority needs nothing else from SPIRE.
type SVIDSource interface {
	// FetchX509SVID mints (or fetches, against live SPIRE) the X.509-SVID for the
	// normalized request — the §3.1 leaf + parallel JWS + key + expiry.
	FetchX509SVID(req X509SVIDRequest) (X509SVID, error)
	// TrustBundle returns the trust domain's CA pool — the set of CA certs the SPIRE
	// trust domain publishes, against which a presented X.509-SVID is chained. It is
	// the SPIRE authority root: a presented SVID is authentic iff it chains here.
	TrustBundle() *x509.CertPool
}

// spireWorkloadAuthority is the M3 SPIRE-backed WorkloadAuthority over a narrow
// SVIDSource. It holds NO Shim back-reference and NO per-session state: unlike the
// own-CA impl (which verifies against a per-session recorded key), it verifies a
// presented X.509-SVID against the trust BUNDLE the source publishes — which is
// exactly why the seam is narrow and the swap pure. Synthetic only in-wave (D50).
type spireWorkloadAuthority struct {
	source SVIDSource
}

// NewSpireWorkloadAuthority builds the SPIRE-backed authority over src. Pass it to
// WithWorkloadAuthority (or use the WithSpireAuthority convenience, mint.go) to
// select the SPIRE substrate BESIDE the own-CA default — without touching
// MintWorkloadIdentity or Validate (the swap is pure). src is the narrow SVIDSource:
// in-wave the synthetic fake (NewFakeSVIDSource), live SPIRE behind the deferred
// env-gated dialer.
func NewSpireWorkloadAuthority(src SVIDSource) WorkloadAuthority {
	return &spireWorkloadAuthority{source: src}
}

// errNilSVIDSource guards a SPIRE authority built without a source.
var errNilSVIDSource = errors.New("mint: spire authority has no SVIDSource")

// errSVIDName is returned when a presented X.509-SVID's URI SAN does not equal the
// expected §3.1 spiffe:// name — the SPIRE "right identity" check. The caller maps
// it to signature_invalid (the credential is authentic-but-wrong-identity, which
// fails closed exactly like a bad signature on the workload leg).
var errSVIDName = errors.New("mint: x509-svid uri san does not match expected spiffe id")

// MintWorkload delegates the substrate mint to the SVIDSource: the source mints a
// SPIRE-shaped X.509-SVID (URI SAN = req.Spiffe, chaining to the trust domain CA)
// plus the parallel JWS over the §3.1 claim set. The result is mapped onto the
// shared WorkloadMintResult so MintWorkloadIdentity (mint.go) records it on the
// session record identically to the own-CA path — the SPIFFE name, the cert, the
// JWT, and the expiry are byte-for-byte the §3.1 shape the own-CA impl emits. The
// claim set is assembled by the Shim's caller contract (the same fields the own-CA
// impl stamps), so the JWT `sub` = req.Spiffe and the identity axis never drifts.
func (a *spireWorkloadAuthority) MintWorkload(req WorkloadMintRequest) (WorkloadMintResult, error) {
	if a.source == nil {
		return WorkloadMintResult{}, errNilSVIDSource
	}
	claims := jwtClaims{
		Subject:          req.Spiffe,
		Issuer:           issuerName,
		IssuedAt:         toUnix(req.NotBefore.Add(time.Minute)), // iat = mint instant (NotBefore = mint - 1m)
		NotBefore:        toUnix(req.NotBefore),
		Expiry:           toUnix(req.NotAfter),
		SessionUUID:      req.SessionUUID,
		LaunchingUser:    req.LaunchingUser,
		Org:              req.Org,
		RepoBranch:       req.RepoBranch,
		Runtime:          req.Runtime,
		ParentSession:    req.ParentSession,
		ServicePrincipal: false, // RESERVED D16 marker, always the agent face at M0
	}
	svid, err := a.source.FetchX509SVID(X509SVIDRequest{
		SpiffeID:  req.Spiffe,
		Claims:    claims,
		NotBefore: req.NotBefore,
		NotAfter:  req.NotAfter,
	})
	if err != nil {
		return WorkloadMintResult{}, fmt.Errorf("mint: fetch x509-svid: %w", err)
	}
	return WorkloadMintResult{
		CertDER:   svid.CertDER,
		JWT:       svid.JWT,
		PublicKey: svid.PublicKey,
		Expiry:    svid.Expiry,
	}, nil
}

// VerifyPresented runs the two SPIRE X.509-SVID checks then re-derives the §3.1
// claim set, returning it for the liveness/freshness/grant decision Validate keeps
// (validate.go). It is the format-opaque signature+claims half of the frozen D22
// workload leg (doc 16 §9), now backed by the trust BUNDLE rather than a per-session
// key:
//
//  1. AUTHENTICITY: the presented credential carries the X.509-SVID leaf (its `x5c`
//     header); the leaf is CHAINED to the SPIRE trust bundle (the source's
//     TrustBundle pool). A SVID that does not chain is rejected — this is the SPIRE
//     authority check, replacing the own-CA impl's per-session-key lookup.
//  2. RIGHT IDENTITY: the leaf's sole URI SAN must EQUAL expectedSpiffe (the §3.1
//     name the Validate caller derives from the session record). An authentic SVID
//     for a DIFFERENT identity fails closed (errSVIDName → signature_invalid).
//
// It then verifies the parallel JWS against the SVID leaf's own key (the cert and
// token are two presentations of one identity) and confirms the JWS `sub` equals
// the SAN — so a tampered JWS body never slips a different name past the SAN check.
// errMalformedJWT (a structurally bad credential) is preserved so the caller maps
// it to ReasonMalformed; everything else fails closed to signature_invalid.
//
// An empty expectedSpiffe skips the name binding (the caller binds on session_uuid
// instead, the legacy path), but the trust-bundle chain still gates authenticity.
func (a *spireWorkloadAuthority) VerifyPresented(presented []byte, expectedSpiffe string, at time.Time) (jwtClaims, error) {
	if a.source == nil {
		return jwtClaims{}, errNilSVIDSource
	}
	hdr, signingInput, sigB64, err := splitJWS(string(presented))
	if err != nil {
		return jwtClaims{}, err
	}
	// The X.509-SVID leaf rides in the JWS `x5c` header (DER, base64url). Without it
	// there is no SVID to chain — fail closed as malformed.
	if len(hdr.X5c) == 0 {
		return jwtClaims{}, errMalformedJWT
	}
	leafDER, err := b64url.DecodeString(hdr.X5c[0])
	if err != nil {
		return jwtClaims{}, errMalformedJWT
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return jwtClaims{}, errMalformedJWT
	}
	// (1) AUTHENTICITY: chain the X.509-SVID leaf to the SPIRE trust bundle. Any
	// intermediates the trust domain interposes ride in x5c[1:].
	intermediates := x509.NewCertPool()
	for _, ic := range hdr.X5c[1:] {
		icDER, derr := b64url.DecodeString(ic)
		if derr != nil {
			return jwtClaims{}, errMalformedJWT
		}
		icCert, perr := x509.ParseCertificate(icDER)
		if perr != nil {
			return jwtClaims{}, errMalformedJWT
		}
		intermediates.AddCert(icCert)
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:         a.source.TrustBundle(),
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr != nil {
		// Authentic-failure: the SVID does not chain to the trust domain. Fail closed
		// (the caller maps to signature_invalid).
		return jwtClaims{}, errJWTSignature
	}
	// (2) RIGHT IDENTITY: the leaf's sole URI SAN must equal the expected §3.1 name.
	if expectedSpiffe != "" {
		if !svidNamesExactly(leaf, expectedSpiffe) {
			return jwtClaims{}, errSVIDName
		}
	}
	// The JWS verifies against the SVID leaf's OWN key (the cert and token are two
	// presentations of one identity — the own-CA invariant, preserved).
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return jwtClaims{}, errMalformedJWT
	}
	claims, err := verifyJWSWithKey(leafKey, signingInput, sigB64)
	if err != nil {
		return jwtClaims{}, err
	}
	// Defense in depth: a tampered JWS body must not name a DIFFERENT identity than
	// the SAN the trust bundle just authenticated.
	if expectedSpiffe != "" && claims.Subject != expectedSpiffe {
		return jwtClaims{}, errSVIDName
	}
	return claims, nil
}

// svidNamesExactly reports whether leaf carries EXACTLY one URI SAN equal to the
// expected §3.1 spiffe:// name. A SPIRE X.509-SVID carries exactly one URI SAN (its
// SPIFFE ID); requiring exactly one closes the "extra SAN smuggling a second
// identity" gap.
func svidNamesExactly(leaf *x509.Certificate, expectedSpiffe string) bool {
	if len(leaf.URIs) != 1 {
		return false
	}
	return leaf.URIs[0].String() == expectedSpiffe
}

// jwsHeader is the parsed JWS protected header. It extends the fixed ES256 header
// with the `x5c` chain SPIRE uses to carry the X.509-SVID leaf (+ any
// intermediates) so the verify leg can chain it to the trust bundle. base64url
// (RawURLEncoding) DER, leaf-first — the JWS `x5c` convention (RFC 7515 §4.1.6),
// reused here for the SVID rather than fetching it out of band.
type jwsHeader struct {
	Alg string   `json:"alg"`
	Typ string   `json:"typ"`
	X5c []string `json:"x5c,omitempty"`
}

// splitJWS splits a compact JWS into its parsed header, the canonical signing input
// (the verbatim `header.payload` the signature covers — RFC 7515 §5.1), and the
// trailing signature segment, validating the three-segment shape. Returning the
// signing input verbatim (not a re-encoded header+payload) keeps the verify digest
// byte-exact with what signJWT signed. It is the SPIRE verify leg's structural gate:
// a non-JWS / wrong-segment-count / wrong-alg credential fails as errMalformedJWT
// (the caller maps to ReasonMalformed), keeping the leg fail-closed.
func splitJWS(token string) (hdr jwsHeader, signingInput, sigB64 string, err error) {
	first := -1
	last := -1
	dots := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			dots++
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if dots != 2 {
		return hdr, "", "", errMalformedJWT
	}
	hdrB64 := token[:first]
	signingInput = token[:last] // verbatim header.payload — the bytes the signature covers
	sigB64 = token[last+1:]
	hdrJSON, derr := b64url.DecodeString(hdrB64)
	if derr != nil {
		return hdr, "", "", errMalformedJWT
	}
	if uerr := json.Unmarshal(hdrJSON, &hdr); uerr != nil {
		return hdr, "", "", errMalformedJWT
	}
	if hdr.Alg != "ES256" {
		return hdr, "", "", errMalformedJWT
	}
	return hdr, signingInput, sigB64, nil
}

// verifyJWSWithKey verifies the ES256 signature over the canonical signing input
// (the verbatim `header.payload` splitJWS returns) against pub and returns the
// decoded §3.1 claim set. It is the SPIRE-leg counterpart to verifyJWT (jwt.go):
// verifyJWT verifies against a per-session recorded key, but the SPIRE leg has
// already chained the X.509-SVID leaf to the trust bundle and verifies against the
// leaf's OWN key — the same ES256 R||S over SHA-256(signingInput) shape signJWT
// emits. The signing input is the bytes signJWT signed verbatim, so re-deriving the
// payload from it (rather than from splitJWS) keeps the digest byte-exact. Fails
// closed: a bad base64, wrong signature length, or a failed verify is
// errMalformedJWT / errJWTSignature — the reasons the caller maps to
// ReasonMalformed / signature_invalid.
func verifyJWSWithKey(pub *ecdsa.PublicKey, signingInput, sigB64 string) (jwtClaims, error) {
	var out jwtClaims
	sig, err := b64url.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return out, errMalformedJWT
	}
	digest := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(sig[:32])
	sScalar := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, sScalar) {
		return out, errJWTSignature
	}
	// The payload is the segment AFTER the single dot in the signing input (signJWT
	// builds signingInput = b64(header) + "." + b64(claims)).
	dot := -1
	for i := 0; i < len(signingInput); i++ {
		if signingInput[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return out, errMalformedJWT
	}
	claimsJSON, err := b64url.DecodeString(signingInput[dot+1:])
	if err != nil {
		return out, errMalformedJWT
	}
	if err := json.Unmarshal(claimsJSON, &out); err != nil {
		return out, errMalformedJWT
	}
	return out, nil
}

// svidURISAN parses a §3.1 spiffe:// string into the *url.URL a SPIRE X.509-SVID
// carries as its sole URI SAN. It is the minting-side counterpart to
// svidNamesExactly: the fake (and a live SPIRE authority) stamp this exact SAN so
// the verify leg's SAN equality holds.
func svidURISAN(spiffeID string) (*url.URL, error) {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("mint: parse spiffe id for svid san: %w", err)
	}
	return u, nil
}

// signJWSWithSigner produces a compact ES256 JWS over claims, signed with a
// crypto.Signer leaf key, with the X.509-SVID chain (DER, leaf-first) carried in the
// protected header's `x5c`. It is the crypto.Signer counterpart to spire_fake.go's
// signJWSWithX5c (which signs with a concrete *ecdsa.PrivateKey): a LIVE SPIRE
// X.509-SVID hands the workload a crypto.Signer (an ECDSA key in practice), not a
// raw *ecdsa.PrivateKey, so the live adapter (spire_live.go) signs the parallel JWS
// through this path. The output is byte-shape-identical to signJWSWithX5c — the same
// ES256 R||S (fixed-width, JWS RFC 7518 §3.4) over SHA-256(b64(hdr).b64(claims)) —
// so the authority's verifyJWSWithKey verifies it identically. A crypto.Signer's
// Sign emits an ASN.1 DER ECDSA signature; this re-encodes it to the fixed-width
// R||S the JWS wire form requires. Non-ECDSA keys (the SVID leaf key must be ECDSA
// for ES256) fail closed.
func signJWSWithSigner(signer crypto.Signer, claims jwtClaims, chainDER [][]byte) (string, error) {
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("mint: svid leaf key is %T, want an ecdsa key (ES256)", signer.Public())
	}
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
	derSig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("mint: sign svid jws: %w", err)
	}
	// crypto.Signer (ECDSA) emits an ASN.1 DER SEQUENCE{ r, s }; the JWS wire form is
	// the fixed-width R||S concatenation (RFC 7518 §3.4), each scalar left-padded to
	// the curve byte size.
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(derSig, &parsed); err != nil {
		return "", fmt.Errorf("mint: parse ecdsa der signature: %w", err)
	}
	keyBytes := (pub.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*keyBytes)
	parsed.R.FillBytes(sig[:keyBytes])
	parsed.S.FillBytes(sig[keyBytes:])
	return signingInput + "." + b64url.EncodeToString(sig), nil
}

// DialSpireWorkloadAPI is the live-SPIRE Workload-API entry point. Its body lives in
// spire_live.go (it dials a real SPIRE Agent socket via the vendored go-spiffe/v2
// Workload-API client and wraps it in liveSVIDSource); see that file's package doc
// for the identity boundary (a live Workload API serves THIS workload's own SVID, it
// is NOT a per-session-name minting service). The empty-socket sentinel always
// returns errSpireLiveDeferred — the in-CI contract: no live dial is ever attempted
// in CI (which supplies no socket), and the synthetic fake (NewFakeSVIDSource)
// remains the only in-CI SVIDSource.

// errSpireLiveDeferred is the empty-socket deferral sentinel (D50: no live SPIRE in
// CI). DialSpireWorkloadAPI("") returns it so a caller that forgot to supply the
// synthetic fake (and supplied no socket) fails closed and loud rather than silently
// dialing nothing. A non-empty socket attempts the live (deferred, manual) dial.
var errSpireLiveDeferred = errors.New("mint: live SPIRE Workload API dial is a deferred manual step (D50, no live SPIRE in-wave)")
