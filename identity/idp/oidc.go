// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// This file is the OIDC core: discovery-document resolution, JWKS fetch, and ID
// token validation (signature against the IdP JWKS + iss/aud/exp/nonce — doc 16
// §11.2 step 4). It is stdlib-only: a JWS over RS256/ES256 is encoding/base64 +
// crypto/rsa|ecdsa + crypto/sha256, so no JWT library is needed (the same
// stdlib-is-sufficient judgment the M0 mint shim records).

// ErrToken is returned when an OIDC ID token fails validation (bad signature,
// wrong issuer/audience, expired, nonce mismatch, or a missing required claim).
// Every validation failure surfaces as ErrToken so the caller refuses launch
// uniformly — the §11.2 "IdP-asserted or absent, never self-declared" contract
// admits no partially-trusted token.
var ErrToken = errors.New("idp: id token validation failed")

// ErrDiscovery is returned when the OIDC discovery document or JWKS cannot be
// fetched or parsed. It is an availability/config fault, distinct from a token
// fault, so the caller can tell "the IdP is unreachable" from "the human
// presented a bad token".
var ErrDiscovery = errors.New("idp: discovery/jwks fetch failed")

// Discovery is the subset of the OIDC discovery document this package consumes
// (doc 16 §11.2: the device-authorization and authorization endpoints are
// resolved FROM discovery, not hardcoded — that is what makes a second IdP a
// config row). Fields beyond these are ignored.
type Discovery struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	JWKSURI                     string `json:"jwks_uri"`
}

// jsonWebKey is one JWKS entry. Only RSA (kty=RSA: n,e) and EC P-256 (kty=EC,
// crv=P-256: x,y) keys are parsed — the two signature families OIDC ID tokens
// use in practice (RS256, ES256). The IdP's signing key is fetched from JWKS at
// token-validation time; the platform never holds a long-lived IdP key.
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`   // RSA modulus (base64url)
	E   string `json:"e"`   // RSA exponent (base64url)
	Crv string `json:"crv"` // EC curve
	X   string `json:"x"`   // EC x (base64url)
	Y   string `json:"y"`   // EC y (base64url)
}

type jwksDoc struct {
	Keys []jsonWebKey `json:"keys"`
}

// HTTPClient is the minimal HTTP seam the OIDC core needs (discovery, JWKS,
// token, device-authorization). It is an interface, not *http.Client, so tests
// drive every flow against a fake OIDC server's handler without a live network
// and production injects a real client with the org's timeouts/proxy.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider resolves and caches an org's OIDC endpoints + JWKS and validates ID
// tokens against them. It is constructed once per Config and reused; the device
// and redirect flows both drive it. It holds NO long-lived secret — JWKS keys
// are public and re-fetched on a kid miss (key rotation), and the client secret
// lives on the Config.
type Provider struct {
	cfg    Config
	http   HTTPClient
	now    func() time.Time
	disco  *Discovery
	jwks   map[string]crypto.PublicKey // kid → public key
	leeway time.Duration               // clock-skew tolerance on exp/iat
}

// Option tunes a Provider (test seams: injected clock, injected HTTP client,
// clock-skew leeway). Production uses the defaults.
type Option func(*Provider)

// WithHTTPClient injects the HTTP client (the fake OIDC server's, in tests).
func WithHTTPClient(c HTTPClient) Option { return func(p *Provider) { p.http = c } }

// WithClock injects the clock (deterministic exp/nonce tests).
func WithClock(now func() time.Time) Option { return func(p *Provider) { p.now = now } }

// WithLeeway sets the clock-skew tolerance applied to exp/iat (default 60s).
func WithLeeway(d time.Duration) Option { return func(p *Provider) { p.leeway = d } }

// NewProvider constructs a Provider for cfg. It validates the config eagerly
// (ErrConfig on a malformed relying-party config) so a bad config fails at setup.
func NewProvider(cfg Config, opts ...Option) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Provider{
		cfg:    cfg,
		http:   http.DefaultClient,
		now:    time.Now,
		jwks:   map[string]crypto.PublicKey{},
		leeway: 60 * time.Second,
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Discovery resolves (and caches) the OIDC discovery document. The device and
// redirect flows call it to learn the device-authorization / token /
// authorization endpoints — doc 16 §11.2's "resolved from OIDC discovery".
func (p *Provider) Discovery(ctx context.Context) (Discovery, error) {
	if p.disco != nil {
		return *p.disco, nil
	}
	var d Discovery
	if err := p.getJSON(ctx, p.cfg.discoveryURL(), &d); err != nil {
		return Discovery{}, fmt.Errorf("%w: discovery: %v", ErrDiscovery, err)
	}
	if d.Issuer == "" {
		return Discovery{}, fmt.Errorf("%w: discovery document has no issuer", ErrDiscovery)
	}
	p.disco = &d
	return d, nil
}

// refreshJWKS fetches the JWKS and replaces the cached key map. It is called on
// construction-lazy first use and again on a kid miss (key rotation), so a
// rotated signing key is picked up without a restart.
func (p *Provider) refreshJWKS(ctx context.Context) error {
	d, err := p.Discovery(ctx)
	if err != nil {
		return err
	}
	if d.JWKSURI == "" {
		return fmt.Errorf("%w: discovery document has no jwks_uri", ErrDiscovery)
	}
	var doc jwksDoc
	if err := p.getJSON(ctx, d.JWKSURI, &doc); err != nil {
		return fmt.Errorf("%w: jwks: %v", ErrDiscovery, err)
	}
	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := k.publicKey()
		if err != nil {
			continue // skip unparseable / unsupported key types
		}
		keys[k.Kid] = pub
	}
	p.jwks = keys
	return nil
}

// keyFor returns the public key for kid, refreshing the JWKS once on a miss
// (key rotation). A still-missing kid after refresh is a hard ErrToken — the
// token is signed by a key the IdP does not publish.
func (p *Provider) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if pub, ok := p.jwks[kid]; ok {
		return pub, nil
	}
	if err := p.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	if pub, ok := p.jwks[kid]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("%w: no JWKS key for kid %q", ErrToken, kid)
}

// IDTokenClaims is the validated claim set extracted from an OIDC ID token (doc
// 16 §11.2 step 4 / claim mapping). Subject is the STABLE `sub` claim — the
// §3.2 IdP-subject key, NEVER email/preferred_username (which can be reassigned).
// Groups feeds Config.MapGroups; Email/Name are display metadata only.
type IDTokenClaims struct {
	Issuer   string
	Subject  string
	Audience []string
	Email    string
	Name     string
	Groups   []string
	Nonce    string
	IssuedAt time.Time
	Expiry   time.Time
}

// rawClaims is the JSON shape claims are decoded from before normalization
// (audience and groups are union-typed in the wild: string or []string).
type rawClaims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	Email    string          `json:"email"`
	Name     string          `json:"name"`
	Nonce    string          `json:"nonce"`
	IssuedAt int64           `json:"iat"`
	Expiry   int64           `json:"exp"`
	// Groups is decoded dynamically via the configured groups-claim name.
}

// ValidateIDToken validates a compact-JWS OIDC ID token (doc 16 §11.2 step 4):
// it verifies the signature against the IdP JWKS, then checks iss, aud, exp, and
// (when expectedNonce != "") the nonce. On success it returns the extracted
// claims with the configured groups-claim mapped to IDTokenClaims.Groups. Any
// failure is ErrToken — there is no partially-valid token (the §11.2 contract).
func (p *Provider) ValidateIDToken(ctx context.Context, idToken, expectedNonce string) (IDTokenClaims, error) {
	header, payload, signingInput, sig, err := splitJWS(idToken)
	if err != nil {
		return IDTokenClaims{}, err
	}

	// Structural alg allowlist, asserted BEFORE key resolution: an alg outside
	// {RS256, ES256} (a symmetric alg, "none", or any unknown value) never reaches
	// keyFor, never triggers a JWKS lookup, and never reaches a verify path. This
	// is the same gate verifyJWS re-asserts; checking it here too makes the
	// never-reach-HMAC invariant hold at the key-resolution boundary as well, so
	// the property is visible at every stage rather than inferred from a missing
	// switch case (doc 16 §11.2).
	if !algAllowed(header.Alg) {
		return IDTokenClaims{}, fmt.Errorf("%w: unsupported or unsafe signing alg %q (only RS256/ES256)", ErrToken, header.Alg)
	}

	pub, err := p.keyFor(ctx, header.Kid)
	if err != nil {
		return IDTokenClaims{}, err
	}
	if err := verifyJWS(header.Alg, pub, signingInput, sig); err != nil {
		return IDTokenClaims{}, err
	}

	var rc rawClaims
	if err := json.Unmarshal(payload, &rc); err != nil {
		return IDTokenClaims{}, fmt.Errorf("%w: claims decode: %v", ErrToken, err)
	}

	// iss: must equal the configured issuer (mix-up defense).
	if rc.Issuer != p.cfg.Issuer {
		return IDTokenClaims{}, fmt.Errorf("%w: issuer %q != expected %q", ErrToken, rc.Issuer, p.cfg.Issuer)
	}
	// sub: the stable identity key MUST be present (the §3.2 business key).
	if strings.TrimSpace(rc.Subject) == "" {
		return IDTokenClaims{}, fmt.Errorf("%w: token carries no subject (sub) claim", ErrToken)
	}

	aud := decodeStringOrSlice(rc.Audience)
	if !contains(aud, p.cfg.audience()) {
		return IDTokenClaims{}, fmt.Errorf("%w: audience %v does not include %q", ErrToken, aud, p.cfg.audience())
	}

	now := p.now()
	if rc.Expiry == 0 {
		return IDTokenClaims{}, fmt.Errorf("%w: token carries no exp claim", ErrToken)
	}
	exp := time.Unix(rc.Expiry, 0)
	if now.After(exp.Add(p.leeway)) {
		return IDTokenClaims{}, fmt.Errorf("%w: token expired at %s (now %s)", ErrToken, exp.UTC(), now.UTC())
	}

	if expectedNonce != "" && rc.Nonce != expectedNonce {
		return IDTokenClaims{}, fmt.Errorf("%w: nonce mismatch", ErrToken)
	}

	groups, err := decodeGroups(payload, p.cfg.groupsClaim())
	if err != nil {
		return IDTokenClaims{}, err
	}

	claims := IDTokenClaims{
		Issuer:   rc.Issuer,
		Subject:  rc.Subject,
		Audience: aud,
		Email:    rc.Email,
		Name:     rc.Name,
		Groups:   groups,
		Nonce:    rc.Nonce,
		Expiry:   exp,
	}
	if rc.IssuedAt != 0 {
		claims.IssuedAt = time.Unix(rc.IssuedAt, 0)
	}
	return claims, nil
}

// --- JWS primitives (compact serialization, RS256 / ES256) ---

// jwsHeader is the protected JWS header. Only `alg` + `kid` select the verifying
// key, and the key they select comes EXCLUSIVELY from the IdP-published JWKS (doc
// 16 §11.2: the key source is "IdP-asserted, never self-declared"). The remaining
// members are parsed NOT because we honor them but so we can DETECT and refuse an
// attacker who tries to steer key resolution or smuggle a critical extension:
//
//   - jku/x5u — URLs naming an attacker-controlled JWKS / cert chain. Honoring
//     either would move key resolution OFF the IdP JWKS (the whole point of the
//     §11.2 contract), so their mere presence is a hard refusal here.
//   - x5c — an inline X.509 cert chain offered as a self-declared key source. Same
//     refusal: the key is the JWKS key for `kid`, never a token-embedded cert.
//   - x5t / x5t#S256 — X.509 cert thumbprints (SHA-1 / SHA-256 of the DER cert,
//     RFC 7515 §4.1.7/§4.1.8). They are the same self-declared-cert family as
//     x5c/x5u: a thumbprint NAMES a specific certificate the TOKEN chose, not the
//     JWKS key the `kid` resolves. We refuse their mere presence for fence
//     consistency with x5c/x5u and as defense-in-depth — see x5tDecision below for
//     the full rationale (the thumbprint can only describe key resolution, never
//     move it, but a thumbprint naming a cert OTHER than the kid-resolved JWKS key
//     is a confusion signal we fail closed on rather than silently ignore).
//   - crit — RFC 7515 §4.1.11 marks header members the verifier MUST understand or
//     reject. This verifier understands no extensions, so ANY non-empty crit is an
//     unknown-critical-extension → fail closed (refuse), never ignore.
//
// `crit` is []string; jku/x5u/x5t/x5t#S256 are strings; x5c is a []string (base64
// DER certs). They are decoded with encoding/json only (no new dependency) purely
// to test for presence; their values are never used to resolve a key.
type jwsHeader struct {
	Alg     string          `json:"alg"`
	Kid     string          `json:"kid"`
	Typ     string          `json:"typ"`
	Crit    []string        `json:"crit"`
	JKU     string          `json:"jku"`
	X5U     string          `json:"x5u"`
	X5C     json.RawMessage `json:"x5c"`
	X5T     string          `json:"x5t"`      // X.509 cert SHA-1 thumbprint (RFC 7515 §4.1.7)
	X5TS256 string          `json:"x5t#S256"` // X.509 cert SHA-256 thumbprint (RFC 7515 §4.1.8)
}

// x5tDecision records the deliberate ruling on the x5t / x5t#S256 cert-thumbprint
// header members (idp-x5t, orch16 — sibling to the x5c/x5u/jku/crit fence and the
// typ policy). RFC 7515 §4.1.7/§4.1.8 define x5t (SHA-1) and x5t#S256 (SHA-256) as
// base64url digests of the DER X.509 cert that corresponds to the signing key —
// they ASSERT a specific certificate the token chose.
//
// The narrow argument for IGNORING them: key resolution here is kid-ONLY (keyFor
// looks up the `kid` in the IdP JWKS and uses nothing else), so a thumbprint can
// only DESCRIBE the key, never MOVE resolution onto a token-chosen cert the way
// x5u (a URL) or x5c (an inline chain) could. On that reading a thumbprint is inert.
//
// We REFUSE anyway, for two reasons:
//
//  1. Fence consistency. x5t/x5t#S256 are the SAME self-declared-cert family as
//     x5c/x5u — all four name a certificate the token asserts rather than the JWKS
//     key the `kid` resolves. The verifier refuses x5c/x5u on presence; ignoring
//     x5t/x5t#S256 would leave a reviewer reasoning about why two cert references
//     are fatal and two are fine. Uniform "the key source is the IdP JWKS only, and
//     the header may not carry ANY competing cert reference" is the reviewable
//     invariant (doc 16 §11.2).
//  2. Defense-in-depth (the confusion signal). A thumbprint that names a DIFFERENT
//     cert than the kid-resolved JWKS key is, by construction, a token claiming its
//     signature corresponds to a cert the verifier did not select. We process no
//     thumbprint — we never fetch the named cert, never compare it to the JWKS key —
//     so an UNVERIFIED cert assertion riding in the protected header is precisely the
//     kind of "header member we do not understand" that the crit rule fails closed
//     on. Refusing on presence is the same fail-closed posture, applied to a member
//     RFC 7515 happens not to require listing in crit.
//
// This is a present-detection refusal, identical in shape to x5c/x5u: the values
// are never parsed or matched, only their presence is fatal.
const x5tDecision = "refuse: x5t/x5t#S256 are self-declared cert thumbprints (RFC 7515 §4.1.7/§4.1.8) — same fence as x5c/x5u, fail closed on presence"

// validate enforces the §11.2 header-member contract: reject any attacker-supplied
// member that would either move key resolution off the IdP JWKS (jku/x5u/x5c) or
// assert a competing certificate the token chose (x5t/x5t#S256 thumbprints, the
// same self-declared-cert fence as x5c/x5u — see x5tDecision), assert an extension
// the verifier does not understand (crit), or declare a JOSE object type that is
// not an OIDC ID token (typ). It runs at header parse — before
// keyFor and before the alg switch — so a header carrying any of these never
// reaches key resolution or signature math. A token with only the understood
// kid/alg/typ members passes cleanly (the legitimate shape).
func (h jwsHeader) validate() error {
	// jku/x5u/x5c — self-declared key sources. The key is ALWAYS the JWKS key the
	// `kid` names; a token may not point the verifier at any other key material.
	if h.JKU != "" {
		return fmt.Errorf("%w: JWS header carries a jku (self-declared key URL); key source is the IdP JWKS only", ErrToken)
	}
	if h.X5U != "" {
		return fmt.Errorf("%w: JWS header carries an x5u (self-declared cert-chain URL); key source is the IdP JWKS only", ErrToken)
	}
	if len(h.X5C) != 0 && string(h.X5C) != "null" {
		return fmt.Errorf("%w: JWS header carries an x5c (self-declared cert chain); key source is the IdP JWKS only", ErrToken)
	}
	// x5t / x5t#S256 — X.509 cert thumbprints (RFC 7515 §4.1.7/§4.1.8). They name a
	// specific certificate the token chose; the same self-declared-cert family as
	// x5c/x5u, refused on presence for fence consistency + defense-in-depth (see
	// x5tDecision). The thumbprint can only describe — never move — kid-only key
	// resolution, but an unverified cert assertion in the protected header is a
	// member we do not process, so we fail closed rather than ignore it.
	if h.X5T != "" {
		return fmt.Errorf("%w: JWS header carries an x5t (self-declared cert thumbprint); key source is the IdP JWKS only", ErrToken)
	}
	if h.X5TS256 != "" {
		return fmt.Errorf("%w: JWS header carries an x5t#S256 (self-declared cert thumbprint); key source is the IdP JWKS only", ErrToken)
	}
	// crit — RFC 7515 §4.1.11: every listed member is one the verifier MUST
	// understand and process, or reject the JWS. We process no header extensions,
	// so any non-empty crit is an unknown critical extension → fail closed.
	if len(h.Crit) != 0 {
		return fmt.Errorf("%w: JWS header marks unknown critical extension(s) %v; refusing (crit fails closed)", ErrToken, h.Crit)
	}
	// typ — the JOSE object type. An OIDC ID token's `typ` is OPTIONAL (RFC 7519
	// §5.1: many IdPs omit it on ID tokens), so absence is accepted; when present it
	// must be a JWT-family value ("JWT" / "application/JWT", the media type a plain
	// JWT carries). A `typ` that names a DIFFERENT, explicitly-typed JOSE object —
	// "at+jwt" (RFC 9068 access token), "logout+jwt" (RFC 8417/OIDC back-channel
	// logout), "dpop+jwt" (RFC 9449), etc. — is a token the IdP minted for some
	// OTHER purpose; accepting it here as an ID token is the `typ`-confusion replay
	// (an access/logout token presented to the ID-token verifier). Such a typ is a
	// hard refusal, the same fail-closed treatment the alg set and the other header
	// members get (doc 16 §11.2).
	if !typAllowed(h.Typ) {
		return fmt.Errorf("%w: JWS header typ %q is not an OIDC ID token (expected absent or a JWT-family value, not a distinct JOSE object type)", ErrToken, h.Typ)
	}
	return nil
}

// splitJWS splits a compact JWS into its decoded header, raw payload bytes, the
// signing input (header.payload, the bytes actually signed), and the decoded
// signature. A malformed token is ErrToken.
func splitJWS(token string) (jwsHeader, []byte, []byte, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: token is not a compact JWS (got %d segments)", ErrToken, len(parts))
	}
	hdrBytes, err := b64.DecodeString(parts[0])
	if err != nil {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: header decode: %v", ErrToken, err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: header parse: %v", ErrToken, err)
	}
	// Enforce the §11.2 header-member contract at parse time: reject any member
	// that would redirect key resolution off the IdP JWKS (jku/x5u/x5c), assert a
	// competing cert thumbprint (x5t/x5t#S256), or assert an unknown critical
	// extension (crit). This runs before keyFor/verifyJWS, so a steered header never
	// reaches key resolution.
	if err := hdr.validate(); err != nil {
		return jwsHeader{}, nil, nil, nil, err
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: payload decode: %v", ErrToken, err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: signature decode: %v", ErrToken, err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	return hdr, payload, signingInput, sig, nil
}

// allowedAlgs is the structural allowlist of signing algorithms this verifier
// will EVER process — the two asymmetric algorithms OIDC ID tokens use in
// practice (doc 16 §11.2: "signature against the IdP JWKS", RS256/ES256). It is
// an explicit set rather than an implicit consequence of which switch arms exist:
// the invariant "no symmetric/`none`/unknown alg is ever handed to a verify path"
// is reviewable at a glance here, and a future arm added to verifyJWS for any
// other alg is still refused by this gate unless it is also added to the set
// (which would be the reviewable decision, not a silent regression). This is what
// makes never-reach-HMAC a STRUCTURAL property: the HMAC family is not in the set,
// so an HS256 verify path is unreachable by construction, not merely absent.
var allowedAlgs = map[string]struct{}{
	"RS256": {},
	"ES256": {},
}

// algAllowed reports whether alg is in the structural allowlist. The comparison
// is exact (case-sensitive): "RS256"/"ES256" only — "none", "None", "HS256", and
// every other value fall outside the set and are refused before any verify path.
func algAllowed(alg string) bool {
	_, ok := allowedAlgs[alg]
	return ok
}

// typAllowed reports whether the JWS `typ` header member is acceptable on an OIDC
// ID token. The accepted set is {absent, JWT-family} (doc 16 §11.2):
//
//   - ABSENT ("") — accepted. `typ` is OPTIONAL on a JWT (RFC 7519 §5.1) and many
//     IdPs omit it on ID tokens, so requiring it would break interop; an absent
//     `typ` is the common, legitimate ID-token shape.
//   - A JWT-family value — accepted. RFC 7519 §5.1 RECOMMENDS `typ:"JWT"`, whose
//     media type is `application/JWT`; media types are case-insensitive and the
//     `application/` prefix MAY be omitted, so "JWT", "jwt", and "application/jwt"
//     are the same media type and all accepted.
//
// Everything else — most importantly a `+jwt` STRUCTURED-SUFFIX type that names a
// DIFFERENT JOSE object ("at+jwt", "logout+jwt", "dpop+jwt", "secevent+jwt", …) —
// is REJECTED: such a token was minted by the IdP for some other purpose and must
// not be replayed as an ID token (the `typ`-confusion defense). The match is on
// the media type only; this does NOT widen to any value merely ending in "jwt".
func typAllowed(typ string) bool {
	if typ == "" {
		return true // typ is optional on an OIDC ID token; absence is the common shape
	}
	// Media types are case-insensitive (RFC 2045 §5.1) and the "application/"
	// prefix is optional for the JWT type (RFC 7519 §5.1). Normalize both, then
	// require an EXACT media-type match against the JWT type — a structured-suffix
	// type like "at+jwt" is a distinct media type and does NOT match.
	t := strings.ToLower(strings.TrimSpace(typ))
	t = strings.TrimPrefix(t, "application/")
	return t == "jwt"
}

// verifyJWS verifies signingInput's signature with pub under alg. Only RS256 and
// ES256 are accepted — the two algorithms OIDC ID tokens use in practice; "none"
// and any unsupported alg are a hard ErrToken (alg-confusion defense: the alg
// must match the JWKS key type).
//
// The allowlist gate runs FIRST, BEFORE the switch: an alg outside {RS256, ES256}
// can never reach a verify branch (and there is no HMAC branch to reach). The
// switch's own default arm is kept as defense-in-depth — it pins the same named
// reason the orch13 alg-confusion/symmetric-confusion tests assert — but the
// allowlist is the load-bearing structural invariant: a symmetric alg is rejected
// here, never type-asserted against a JWKS key, never fed to an HMAC verify.
func verifyJWS(alg string, pub crypto.PublicKey, signingInput, sig []byte) error {
	if !algAllowed(alg) {
		return fmt.Errorf("%w: unsupported or unsafe signing alg %q (only RS256/ES256)", ErrToken, alg)
	}
	digest := sha256.Sum256(signingInput)
	switch alg {
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: RS256 token but JWKS key is not RSA", ErrToken)
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("%w: RS256 signature invalid", ErrToken)
		}
		return nil
	case "ES256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: ES256 token but JWKS key is not EC", ErrToken)
		}
		// ES256 raw signature is R||S, each 32 bytes (P-256).
		if len(sig) != 64 {
			return fmt.Errorf("%w: ES256 signature length %d != 64", ErrToken, len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecPub, digest[:], r, s) {
			return fmt.Errorf("%w: ES256 signature invalid", ErrToken)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported or unsafe signing alg %q (only RS256/ES256)", ErrToken, alg)
	}
}

// publicKey parses a JWKS entry into a crypto.PublicKey. Only RSA and EC P-256
// are supported; any other key type returns an error (the caller skips it).
func (k jsonWebKey) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := b64.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := b64.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		// The exponent is a big-endian unsigned integer (AQAB → 65537). Reject a
		// zero/empty exponent — a malformed key rather than a usable one.
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Sign() == 0 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		xBytes, err := b64.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := b64.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

// --- small helpers ---

// b64 is the JWS base64url alphabet (no padding), used for every segment.
var b64 = base64.RawURLEncoding

// getJSON GETs url and decodes the JSON body into v.
func (p *Provider) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// decodeJSON decodes a response body into v. Unlike getJSON it does NOT require
// a 200 status: OAuth error responses (RFC 6749 §5.2) are JSON on a 400, and the
// caller branches on the decoded error field, so the body is always decoded.
func decodeJSON(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}

// decodeStringOrSlice normalizes the union-typed `aud` claim (string or
// []string) into a slice.
func decodeStringOrSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

// decodeGroups reads the configured groups claim from the raw payload. The claim
// is union-typed (string or []string) and may be absent (no groups → no roles,
// the fail-closed default). A present-but-malformed groups claim is ErrToken.
func decodeGroups(payload []byte, claimName string) ([]string, error) {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(payload, &generic); err != nil {
		return nil, fmt.Errorf("%w: groups decode: %v", ErrToken, err)
	}
	raw, ok := generic[claimName]
	if !ok {
		return nil, nil // no groups claim → roleless principal (fail-closed)
	}
	groups := decodeStringOrSlice(raw)
	return groups, nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
