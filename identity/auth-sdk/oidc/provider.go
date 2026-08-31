// SPDX-License-Identifier: Apache-2.0

// Package oidc is the relying-party OIDC core for the auth SDK: discovery-document
// resolution, JWKS fetch, ID-token validation, and the PKCE authorization-code +
// device-code flow entry points. It is stdlib-only (no external JWT/OIDC library),
// using the same JWS/JWKS primitives established in identity/idp (RS256/ES256,
// kid-only JWKS key resolution, full §11.2 header-member contract).
package oidc

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

// ErrToken is returned when an OIDC ID token fails validation (bad signature,
// wrong issuer/audience, expired, nonce mismatch, or a missing required claim).
// Every validation failure surfaces as ErrToken so the caller refuses uniformly.
var ErrToken = errors.New("oidc: id token validation failed")

// ErrDiscovery is returned when the OIDC discovery document or JWKS cannot be
// fetched or parsed. It is an availability/config fault, distinct from a token
// fault, so the caller can tell "the IdP is unreachable" from "the human
// presented a bad token".
var ErrDiscovery = errors.New("oidc: discovery/jwks fetch failed")

// Discovery is the subset of the OIDC discovery document this package consumes.
// Fields beyond these are ignored. Endpoints are resolved from discovery at use
// time; the device and redirect flows call Discovery() to learn them.
type Discovery struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	JWKSURI                     string `json:"jwks_uri"`
}

// jsonWebKey is one JWKS entry. Only RSA (kty=RSA: n,e) and EC P-256 (kty=EC,
// crv=P-256: x,y) keys are parsed — the two signature families OIDC ID tokens
// use in practice (RS256, ES256).
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
// token, device-authorization). An interface rather than *http.Client so tests
// drive every flow against a fake OIDC server without a live network.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider resolves and caches an org's OIDC endpoints + JWKS and validates ID
// tokens against them. It is constructed once per Config and reused.
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
// redirect flows call it to learn the token / authorization / device-authorization
// endpoints — resolved from OIDC discovery, not hardcoded.
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

// refreshJWKS fetches the JWKS and replaces the cached key map. Called on first
// use and again on a kid miss (key rotation).
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
// (key rotation). A still-missing kid after refresh is a hard ErrToken.
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

// IDTokenClaims is the validated claim set extracted from an OIDC ID token.
// Subject is the stable `sub` claim — the IdP-subject key, NEVER email which
// can be reassigned. Groups feeds the caller's role-mapping logic.
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
}

// ValidateIDToken validates a compact-JWS OIDC ID token:
// it verifies the signature against the IdP JWKS, then checks iss, aud, exp,
// and (when expectedNonce != "") the nonce. On success it returns the extracted
// claims. Any failure is ErrToken — there is no partially-valid token.
func (p *Provider) ValidateIDToken(ctx context.Context, idToken, expectedNonce string) (IDTokenClaims, error) {
	header, payload, signingInput, sig, err := splitJWS(idToken)
	if err != nil {
		return IDTokenClaims{}, err
	}

	// Structural alg allowlist, asserted BEFORE key resolution: an alg outside
	// {RS256, ES256} never reaches keyFor, never triggers a JWKS lookup, and
	// never reaches a verify path.
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
	// sub: the stable identity key MUST be present.
	if strings.TrimSpace(rc.Subject) == "" {
		return IDTokenClaims{}, fmt.Errorf("%w: token carries no subject (sub) claim", ErrToken)
	}

	aud := decodeStringOrSlice(rc.Audience)
	if !contains(aud, p.cfg.ClientID) {
		return IDTokenClaims{}, fmt.Errorf("%w: audience %v does not include %q", ErrToken, aud, p.cfg.ClientID)
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
// key, and the key they select comes EXCLUSIVELY from the IdP-published JWKS.
// The remaining members are parsed so we can DETECT and refuse an attacker who
// tries to steer key resolution or smuggle a critical extension:
//
//   - jku/x5u — URLs naming an attacker-controlled JWKS / cert chain. Their mere
//     presence is a hard refusal.
//   - x5c — an inline X.509 cert chain offered as a self-declared key source.
//     Same refusal: the key is the JWKS key for `kid`, never a token-embedded cert.
//   - x5t / x5t#S256 — X.509 cert thumbprints. Same self-declared-cert family as
//     x5c/x5u; refused on presence for fence consistency.
//   - crit — RFC 7515 §4.1.11: this verifier understands no extensions, so ANY
//     non-empty crit is an unknown-critical-extension → fail closed.
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

// validate enforces the header-member contract: reject any attacker-supplied
// member that would move key resolution off the IdP JWKS, assert a competing
// certificate, assert an unknown critical extension, or declare a JOSE object
// type that is not an OIDC ID token. It runs at header parse — before keyFor
// and before the alg switch.
func (h jwsHeader) validate() error {
	if h.JKU != "" {
		return fmt.Errorf("%w: JWS header carries a jku (self-declared key URL); key source is the IdP JWKS only", ErrToken)
	}
	if h.X5U != "" {
		return fmt.Errorf("%w: JWS header carries an x5u (self-declared cert-chain URL); key source is the IdP JWKS only", ErrToken)
	}
	if len(h.X5C) != 0 && string(h.X5C) != "null" {
		return fmt.Errorf("%w: JWS header carries an x5c (self-declared cert chain); key source is the IdP JWKS only", ErrToken)
	}
	if h.X5T != "" {
		return fmt.Errorf("%w: JWS header carries an x5t (self-declared cert thumbprint); key source is the IdP JWKS only", ErrToken)
	}
	if h.X5TS256 != "" {
		return fmt.Errorf("%w: JWS header carries an x5t#S256 (self-declared cert thumbprint); key source is the IdP JWKS only", ErrToken)
	}
	if len(h.Crit) != 0 {
		return fmt.Errorf("%w: JWS header marks unknown critical extension(s) %v; refusing (crit fails closed)", ErrToken, h.Crit)
	}
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
	// Enforce the header-member contract at parse time: reject any member that
	// would redirect key resolution off the IdP JWKS (jku/x5u/x5c), assert a
	// competing cert thumbprint (x5t/x5t#S256), or assert an unknown critical
	// extension (crit). This runs before keyFor/verifyJWS.
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
// will ever process — RS256 and ES256 only. A symmetric alg, "none", or any
// unknown value falls outside the set and is refused before any verify path.
var allowedAlgs = map[string]struct{}{
	"RS256": {},
	"ES256": {},
}

// algAllowed reports whether alg is in the structural allowlist.
func algAllowed(alg string) bool {
	_, ok := allowedAlgs[alg]
	return ok
}

// typAllowed reports whether the JWS `typ` header member is acceptable on an
// OIDC ID token. Accepted: absent ("") or a JWT-family value (RFC 7519 §5.1).
// Rejected: structured-suffix types like "at+jwt", "logout+jwt", "dpop+jwt".
func typAllowed(typ string) bool {
	if typ == "" {
		return true
	}
	t := strings.ToLower(strings.TrimSpace(typ))
	t = strings.TrimPrefix(t, "application/")
	return t == "jwt"
}

// verifyJWS verifies signingInput's signature with pub under alg. Only RS256
// and ES256 are accepted; "none" and any unsupported alg are a hard ErrToken.
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
// is union-typed (string or []string) and may be absent (no groups → roleless,
// fail-closed). A present-but-malformed groups claim is ErrToken.
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
