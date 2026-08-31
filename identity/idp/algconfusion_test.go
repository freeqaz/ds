// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// algconfusion_test.go pins the classic JWS verification CVEs as negative tests
// (doc 16 §11.2 step 4 / oidc.go verifyJWS's "alg must match the JWKS key type"
// contract). The defense lives in verifyJWS — the alg switch type-asserts the
// JWKS key and treats "none"/unknown alg as a hard ErrToken — but the existing
// suite only exercised the tampered-signature path. These cases assert the
// REFUSAL of the four canonical attacks directly:
//
//  1. alg:none           — header alg "none" with a blank/absent signature.
//  2. RS256-over-EC-key  — an RS256 header verified against an EC JWKS key.
//  3. ES256-over-RSA-key — an ES256 header verified against an RSA JWKS key.
//  4. kid-swap           — a valid signature from key A presented under key B's
//                          kid (the verifier must use the kid's key, not trust
//                          the attacker-chosen one).
//  5. HS256-over-pubkey  — the classic RS256/ES256→HS256 symmetric-confusion
//                          downgrade: a token signed HS256 with the SERVER PUBLIC
//                          KEY BYTES (published in the JWKS, so attacker-known) as
//                          the HMAC secret. verifyJWS has no HS256 arm, so it must
//                          fall to the default "unsupported or unsafe signing alg"
//                          refusal — pinning that named reason is the regression
//                          tripwire: a future HS256 arm that fed the JWKS key to an
//                          HMAC verify would silently open the hole and flip this
//                          reason, failing the test.
//
// Each must surface ErrToken and never validate (the §11.2 "IdP-asserted or
// absent, never self-declared" contract admits no partially-trusted token).
// Synthetic in-test keys only — no live IdP / network (D50). The server is
// self-contained here (it serves an attacker-chosen JWKS + token), so it does
// not disturb the shared fakeOIDC double in fakeoidc_test.go.

// confuser is a minimal OIDC IdP double that gives the test full control over
// the published JWKS and the exact bytes of the minted token — the two levers an
// alg-confusion attack pulls. It is deliberately separate from fakeOIDC, whose
// JWKS is locked to its own signing alg.
type confuser struct {
	t      *testing.T
	server *httptest.Server
	jwks   jwksDoc // the JWKS the attacker-controlled-discovery endpoint serves
}

// newConfuser starts a discovery+JWKS server publishing jwks. The token endpoint
// is unused (these tests call ValidateIDToken with a hand-built token directly).
func newConfuser(t *testing.T, jwks jwksDoc) *confuser {
	t.Helper()
	c := &confuser{t: t, jwks: jwks}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, Discovery{
			Issuer:                c.server.URL,
			AuthorizationEndpoint: c.server.URL + "/authorize",
			TokenEndpoint:         c.server.URL + "/token",
			JWKSURI:               c.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, c.jwks) })
	c.server = httptest.NewServer(mux)
	t.Cleanup(c.server.Close)
	return c
}

// config returns a relying-party Config pointed at this double.
func (c *confuser) config() Config {
	return Config{Org: "acme", Issuer: c.server.URL, ClientID: "ds-client"}
}

// provider builds a Provider over the double with a fixed clock so exp never
// interferes with the signature-stage assertions under test.
func (c *confuser) provider() *Provider {
	c.t.Helper()
	p, err := NewProvider(c.config(),
		WithHTTPClient(c.server.Client()),
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	if err != nil {
		c.t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// goodClaims is a claim set that passes EVERY check after the signature — so the
// ONLY thing a test can be failing on is the signature/alg stage. iss/aud must
// match the config; exp is well past the fixed clock; sub is present.
func (c *confuser) goodClaims() map[string]any {
	return map[string]any{
		"iss": c.server.URL,
		"aud": "ds-client",
		"sub": "okta|ada",
		"exp": int64(2_000_000_000), // well after the fixed clock (1.7e9)
		"iat": int64(1_700_000_000),
	}
}

// encodeSegments assembles a compact JWS from a header map, a claims map, and a
// raw signature. The signature segment may be empty (alg:none).
func encodeSegments(t *testing.T, header, claims map[string]any, sig []byte) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb) + "." + b64url.EncodeToString(sig)
}

// signRS256 signs signingInput with key, returning the PKCS#1 v1.5 signature.
func signRS256(t *testing.T, key *rsa.PrivateKey, signingInput string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	return sig
}

// signES256 signs signingInput with key, returning the raw R||S (64-byte) form.
func signES256(t *testing.T, key *ecdsa.PrivateKey, signingInput string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}
	return append(padTo32(r.Bytes()), padTo32(s.Bytes())...)
}

func rsaJWK(t *testing.T, kid string, key *rsa.PrivateKey) jsonWebKey {
	t.Helper()
	pub := key.Public().(*rsa.PublicKey)
	return jsonWebKey{
		Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig",
		N: b64url.EncodeToString(pub.N.Bytes()),
		E: b64url.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(t *testing.T, kid string, key *ecdsa.PrivateKey) jsonWebKey {
	t.Helper()
	pub := key.Public().(*ecdsa.PublicKey)
	return jsonWebKey{
		Kty: "EC", Kid: kid, Alg: "ES256", Use: "sig", Crv: "P-256",
		X: b64url.EncodeToString(pub.X.Bytes()),
		Y: b64url.EncodeToString(pub.Y.Bytes()),
	}
}

func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return k
}

func genEC(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return k
}

// mustReject asserts the token is refused as ErrToken AND that the named reason
// substring is present — the case must fail at the intended stage, not slip past
// the signature only to be caught by an unrelated claim check.
func mustReject(t *testing.T, p *Provider, token, wantReason string) {
	t.Helper()
	_, err := p.ValidateIDToken(context.Background(), token, "")
	if err == nil {
		t.Fatalf("token VALIDATED but must be rejected (alg-confusion defense breached)")
	}
	if !errors.Is(err, ErrToken) {
		t.Fatalf("want ErrToken, got %v", err)
	}
	if wantReason != "" && !strings.Contains(err.Error(), wantReason) {
		t.Fatalf("rejected, but reason %q lacks %q (rejected at the wrong stage?)", err.Error(), wantReason)
	}
}

// (1) alg:none — the unsigned-token attack. A header asserting alg "none" with a
// blank signature must be a hard refusal; verifyJWS has no "none" case, so it
// falls to the default "unsupported or unsafe signing alg" ErrToken. We publish
// a real RSA key under the claimed kid so the failure is the alg, not a kid miss.
func TestAlgConfusion_None(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	header := map[string]any{"alg": "none", "kid": "kid-rsa", "typ": "JWT"}
	// alg:none → empty signature segment (the canonical CVE shape).
	token := encodeSegments(t, header, c.goodClaims(), nil)
	mustReject(t, p, token, "unsupported or unsafe signing alg")

	// A "none" token whose author tries to smuggle bytes into the signature
	// segment must be refused identically (the alg, not the bytes, is fatal).
	tokenWithBytes := encodeSegments(t, header, c.goodClaims(), []byte("forged"))
	mustReject(t, p, tokenWithBytes, "unsupported or unsafe signing alg")

	// Casing/whitespace variants of "none" must not slip past the exact-match
	// switch either — anything that is not RS256/ES256 is unsafe.
	for _, variant := range []string{"None", "NONE", "nOnE"} {
		h := map[string]any{"alg": variant, "kid": "kid-rsa", "typ": "JWT"}
		mustReject(t, p, encodeSegments(t, h, c.goodClaims(), nil), "unsupported or unsafe signing alg")
	}
}

// (2) RS256-over-EC-key — the attacker presents an RS256 header, but the JWKS key
// at that kid is EC. verifyJWS type-asserts pub.(*rsa.PublicKey) and refuses.
func TestAlgConfusion_RS256OverECKey(t *testing.T) {
	ecKey := genEC(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{ecJWK(t, "kid-ec", ecKey)}})
	p := c.provider()

	// Sign with an unrelated RSA key (the attacker's own) and claim RS256 — the
	// signature is well-formed RS256, only the JWKS key type is wrong.
	attacker := genRSA(t)
	header := map[string]any{"alg": "RS256", "kid": "kid-ec", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(c.goodClaims())
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	sig := signRS256(t, attacker, signingInput)

	token := signingInput + "." + b64url.EncodeToString(sig)
	mustReject(t, p, token, "RS256 token but JWKS key is not RSA")
}

// (3) ES256-over-RSA-key — the mirror: an ES256 header against an RSA JWKS key.
// verifyJWS type-asserts pub.(*ecdsa.PublicKey) and refuses.
func TestAlgConfusion_ES256OverRSAKey(t *testing.T) {
	rsaKey := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", rsaKey)}})
	p := c.provider()

	attacker := genEC(t)
	header := map[string]any{"alg": "ES256", "kid": "kid-rsa", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(c.goodClaims())
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	sig := signES256(t, attacker, signingInput)

	token := signingInput + "." + b64url.EncodeToString(sig)
	mustReject(t, p, token, "ES256 token but JWKS key is not EC")
}

// (4) kid-swap — a valid signature from one key in the JWKS, presented under a
// DIFFERENT key's kid. The verifier must select the key the kid names (not the
// one that actually signed), so the well-formed signature fails verification.
// This proves the verifier trusts the kid→key binding, never the signature's
// own provenance. Both keys share the same family (RSA) so the failure is the
// signature mismatch, not a key-type mismatch.
func TestAlgConfusion_KidSwap(t *testing.T) {
	keyA := genRSA(t)
	keyB := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{
		rsaJWK(t, "kid-A", keyA),
		rsaJWK(t, "kid-B", keyB),
	}})
	p := c.provider()

	// Sign with keyA but label the token kid-B. The verifier resolves kid-B's
	// PUBLIC key (keyB), against which keyA's signature does not verify.
	header := map[string]any{"alg": "RS256", "kid": "kid-B", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(c.goodClaims())
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	sig := signRS256(t, keyA, signingInput)

	token := signingInput + "." + b64url.EncodeToString(sig)
	mustReject(t, p, token, "RS256 signature invalid")

	// Control: the SAME token labeled with the kid that actually signed it
	// (kid-A) must validate — proving the rejection above is the kid binding,
	// not a broken harness.
	okHeader := map[string]any{"alg": "RS256", "kid": "kid-A", "typ": "JWT"}
	okHB, _ := json.Marshal(okHeader)
	okSigningInput := b64url.EncodeToString(okHB) + "." + b64url.EncodeToString(pb)
	okSig := signRS256(t, keyA, okSigningInput)
	okToken := okSigningInput + "." + b64url.EncodeToString(okSig)
	if _, err := p.ValidateIDToken(context.Background(), okToken, ""); err != nil {
		t.Fatalf("control: correctly-kid'd token must validate, got %v", err)
	}
}

// kid-miss — a token naming a kid absent from the JWKS is refused at key
// resolution (keyFor), before any signature math. Bundled here because it is the
// same family of "the attacker chose the kid" abuse as the swap above.
func TestAlgConfusion_UnknownKid(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-real", signer)}})
	p := c.provider()

	header := map[string]any{"alg": "RS256", "kid": "kid-ghost", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(c.goodClaims())
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	sig := signRS256(t, signer, signingInput)

	token := signingInput + "." + b64url.EncodeToString(sig)
	mustReject(t, p, token, "no JWKS key for kid")
}

// signHS256 signs signingInput with secret using HMAC-SHA256 — the symmetric
// primitive an HS256 token carries. The forger's whole gambit is that the secret
// here (the server's PUBLIC key bytes) is something they already know, unlike a
// real RSA/EC private key.
func signHS256(t *testing.T, secret []byte, signingInput string) []byte {
	t.Helper()
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

// pubKeyBytes returns the DER (PKIX SubjectPublicKeyInfo) encoding of pub — the
// canonical "server public key bytes" an attacker scrapes from the JWKS / a PEM
// to seed the HS256 downgrade. The exact byte form is immaterial to the verifier
// (it never reaches an HMAC arm), but using the real PKIX bytes keeps the fixture
// faithful to the documented CVE.
func pubKeyBytes(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return der
}

// (5a) HS256-over-RSA-public-key — the classic RS256→HS256 downgrade. The JWKS
// publishes an RSA signing key; the attacker re-signs a token under alg "HS256"
// using THAT key's public bytes as the HMAC secret. A naive verifier that grew an
// HS256 arm and handed the kid's key to an HMAC verify would accept this forgery,
// because the public bytes are not secret. verifyJWS has no HS256 case, so the
// token falls to the default unsupported-alg refusal — and we pin that named
// reason so re-introducing the hole flips the reason and fails this test.
func TestSymConfusion_HS256OverRSAPublicKey(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	secret := pubKeyBytes(t, signer.Public()) // attacker-known: the published RSA pubkey
	header := map[string]any{"alg": "HS256", "kid": "kid-rsa", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(c.goodClaims())
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	sig := signHS256(t, secret, signingInput)

	token := signingInput + "." + b64url.EncodeToString(sig)
	mustReject(t, p, token, "unsupported or unsafe signing alg")

	// The raw RSA modulus bytes are the OTHER obvious "public key bytes" an
	// attacker would try (it is literally what the JWKS `n` member publishes).
	// It must be refused identically — the alg, not the secret encoding, is fatal.
	modSecret := signer.Public().(*rsa.PublicKey).N.Bytes()
	modSig := signHS256(t, modSecret, signingInput)
	mustReject(t, p, signingInput+"."+b64url.EncodeToString(modSig), "unsupported or unsafe signing alg")
}

// (5b) HS256-over-EC-public-key — the same downgrade against an EC (ES256) signing
// key: the kid points at an asymmetric EC key, the alg is the symmetric HS256, and
// the HMAC secret is that EC key's public bytes. Pinning the EC mirror proves the
// refusal is the alg switch's default arm, not anything RSA-specific.
func TestSymConfusion_HS256OverECPublicKey(t *testing.T) {
	signer := genEC(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{ecJWK(t, "kid-ec", signer)}})
	p := c.provider()

	secret := pubKeyBytes(t, signer.Public()) // attacker-known: the published EC pubkey
	header := map[string]any{"alg": "HS256", "kid": "kid-ec", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(c.goodClaims())
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	sig := signHS256(t, secret, signingInput)

	token := signingInput + "." + b64url.EncodeToString(sig)
	mustReject(t, p, token, "unsupported or unsafe signing alg")

	// Casing variants of the symmetric alg must not slip past the exact-match
	// switch either — only RS256/ES256 are accepted, everything else is unsafe.
	for _, variant := range []string{"hs256", "Hs256", "HS384", "HS512"} {
		h := map[string]any{"alg": variant, "kid": "kid-ec", "typ": "JWT"}
		vhb, _ := json.Marshal(h)
		vInput := b64url.EncodeToString(vhb) + "." + b64url.EncodeToString(pb)
		vSig := signHS256(t, secret, vInput)
		mustReject(t, p, vInput+"."+b64url.EncodeToString(vSig), "unsupported or unsafe signing alg")
	}
}

// (5c) HS256-kid-pointing-at-asymmetric-key — the variant the alg-confusion unit
// deferred, stated explicitly: a symmetric alg whose kid resolves to an asymmetric
// JWKS key. This is the precondition for the downgrade (an HS256 arm would fetch
// that asymmetric key and HMAC against its bytes). The control below confirms the
// kid resolves to a real RSA key, so the refusal is the symmetric alg over an
// asymmetric key — not a kid miss (which TestAlgConfusion_UnknownKid already pins).
func TestSymConfusion_HS256KidPointsAtAsymmetricKey(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	pb, _ := json.Marshal(c.goodClaims())

	// HS256 over the asymmetric (RSA) key the kid names — refused as unsupported.
	header := map[string]any{"alg": "HS256", "kid": "kid-rsa", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	sig := signHS256(t, pubKeyBytes(t, signer.Public()), signingInput)
	mustReject(t, p, signingInput+"."+b64url.EncodeToString(sig), "unsupported or unsafe signing alg")

	// Control: the SAME kid with the alg the JWKS key actually supports (RS256)
	// and a genuine private-key signature validates — proving kid-rsa resolves to
	// a usable asymmetric key, so the rejection above is the symmetric alg, not a
	// missing/unparseable key.
	okHeader := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT"}
	okHB, _ := json.Marshal(okHeader)
	okInput := b64url.EncodeToString(okHB) + "." + b64url.EncodeToString(pb)
	okSig := signRS256(t, signer, okInput)
	if _, err := p.ValidateIDToken(context.Background(), okInput+"."+b64url.EncodeToString(okSig), ""); err != nil {
		t.Fatalf("control: correctly-RS256'd token must validate, got %v", err)
	}
}

// --- structural {RS256, ES256} allowlist (oidc.go: algAllowed / verifyJWS) ---
//
// orch13 pinned the symmetric-confusion refusal behaviorally — there is no HS256
// arm, so an HS256 token falls to verifyJWS's default arm. orch14 makes that an
// explicit STRUCTURAL invariant: an allowlist checked BEFORE the alg switch, so no
// alg outside {RS256, ES256} ever reaches a verify branch (and a future arm added
// for some other alg is still gated unless the allowlist is also widened, which is
// the reviewable decision). These tests prove the gate is present and ordered
// first; the orch13 cases above remain green, asserting the behavior is unchanged.

// TestAlgAllowlist_OnlyRS256ES256 pins the exact membership of the structural
// allowlist: precisely RS256 and ES256 are permitted, and every other alg an
// attacker might assert — the symmetric family, "none" and its casings, the other
// asymmetric algs we deliberately do NOT support, and junk — is rejected. This is
// the one-glance review surface the unit's charter asks for.
func TestAlgAllowlist_OnlyRS256ES256(t *testing.T) {
	allowed := []string{"RS256", "ES256"}
	for _, alg := range allowed {
		if !algAllowed(alg) {
			t.Fatalf("alg %q must be in the structural allowlist", alg)
		}
	}
	// Everything else is OUT: symmetric (HMAC) algs are the never-reach-HMAC case;
	// "none" is the unsigned attack; RS384/512, ES384/512, PS*, EdDSA are asymmetric
	// algs we do not support (not on the JWKS path); casing/whitespace variants must
	// not slip past the exact-match set; empty is the absent-alg case.
	denied := []string{
		"HS256", "HS384", "HS512", "hs256", "Hs256", "HmacSHA256",
		"none", "None", "NONE", "nOnE", " none ",
		"RS384", "RS512", "rs256", "RS256 ", " RS256",
		"ES384", "ES512", "es256", "ES256 ",
		"PS256", "PS384", "PS512", "EdDSA", "Ed25519",
		"", "garbage", "RSA-OAEP", "A128KW",
	}
	for _, alg := range denied {
		if algAllowed(alg) {
			t.Fatalf("alg %q must NOT be in the structural allowlist (never-reach-HMAC / asymmetric-only invariant breached)", alg)
		}
	}
}

// TestAlgAllowlist_GateRunsBeforeSwitch proves the allowlist is checked BEFORE the
// type-asserting switch, not merely as a default arm. We call verifyJWS directly
// with a disallowed alg and a deliberately MISMATCHED key type (an RSA key under an
// "HS256"/"ES256"-shaped attack). If the gate did not run first, an arm that
// type-asserts the key could be reached; because the gate runs first, every
// disallowed alg returns the unsupported-alg reason without ever touching the
// switch. A nil signature and key exercise that no verify math runs either.
func TestAlgAllowlist_GateRunsBeforeSwitch(t *testing.T) {
	rsaKey := genRSA(t)
	for _, alg := range []string{"HS256", "none", "RS384", "ES384", "PS256", "", "garbage"} {
		// pub is a valid RSA key, but the alg is not RS256, so a switch reached
		// without the gate would fall to default anyway; the load-bearing check is
		// that the gate's reason is returned and NOTHING panics on a type assertion.
		err := verifyJWS(alg, rsaKey.Public(), []byte("header.payload"), []byte("sig"))
		if err == nil {
			t.Fatalf("verifyJWS(%q) returned nil; disallowed alg must be refused", alg)
		}
		if !errors.Is(err, ErrToken) {
			t.Fatalf("verifyJWS(%q): want ErrToken, got %v", alg, err)
		}
		if !strings.Contains(err.Error(), "unsupported or unsafe signing alg") {
			t.Fatalf("verifyJWS(%q): want allowlist reason, got %q", alg, err.Error())
		}
	}
	// Control: an allowed alg with the right key type still verifies (the gate does
	// not break the happy path) — proven indirectly by the orch13 happy-path
	// controls above; here we just confirm an allowed alg PASSES the gate and
	// reaches its switch arm, failing on the signature rather than the alg.
	err := verifyJWS("RS256", rsaKey.Public(), []byte("header.payload"), []byte("not-a-real-sig"))
	if err == nil {
		t.Fatalf("RS256 with a bogus signature must still fail (at the signature, not the gate)")
	}
	if strings.Contains(err.Error(), "unsupported or unsafe signing alg") {
		t.Fatalf("RS256 is allowed and must pass the gate to reach the switch; got allowlist reason %q", err.Error())
	}
	if !strings.Contains(err.Error(), "RS256 signature invalid") {
		t.Fatalf("RS256 with a bad signature must fail at the signature arm, got %q", err.Error())
	}
}

// --- §11.2 header-member contract (crit / jku / x5u / x5c) ---
//
// doc 16 §11.2: the key source is the IdP-published JWKS, "IdP-asserted, never
// self-declared". The JWS protected header may not steer key resolution off that
// JWKS, nor assert a critical extension the verifier does not understand. These
// cases pin that every attacker-supplied member is refused at header parse — before
// keyFor and before the signature switch. We publish a real RSA key under the
// claimed kid and otherwise produce a genuine RS256 signature, so the ONLY reason a
// case can fail is the offending header member (not a kid miss or a bad signature).

// signedRS256Token mints a fully-valid RS256 token over header+claims signed by
// key — used so header-member tests fail ONLY on the injected member, never on the
// signature or a kid miss.
func signedRS256Token(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(pb)
	sig := signRS256(t, key, signingInput)
	return signingInput + "." + b64url.EncodeToString(sig)
}

// TestHeaderContract_CritFailsClosed — RFC 7515 §4.1.11: a `crit` member lists
// header members the verifier MUST understand or reject. This verifier understands
// NO extensions, so ANY non-empty crit is an unknown critical extension and must
// fail closed (refuse), never be ignored. Pinning a genuinely-signed token proves
// the refusal is the crit member, not a signature/kid problem.
func TestHeaderContract_CritFailsClosed(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	// A crit naming a member we don't process — the canonical unknown-critical case.
	for _, crit := range [][]string{
		{"b64"},                 // the famous RFC 7797 unencoded-payload extension
		{"exp"},                 // an attacker re-labeling a claim as a critical header
		{"http://attacker/ext"}, // arbitrary extension URI
		{"alg"},                 // even a known member, if marked crit, we do not process crit at all → refuse
		{"kid", "typ"},          // multiple
	} {
		header := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "crit": crit}
		token := signedRS256Token(t, signer, header, c.goodClaims())
		mustReject(t, p, token, "unknown critical extension")
	}

	// An EMPTY crit array is not an unknown-extension assertion; it must NOT trip the
	// fail-closed path (we only refuse a NON-empty crit). The token is otherwise
	// valid, so it must validate — proving the refusal above is the crit CONTENTS,
	// not the mere presence of the member, and that we did not over-reject.
	okHeader := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "crit": []string{}}
	okToken := signedRS256Token(t, signer, okHeader, c.goodClaims())
	if _, err := p.ValidateIDToken(context.Background(), okToken, ""); err != nil {
		t.Fatalf("control: empty crit must not fail closed (token otherwise valid), got %v", err)
	}
}

// TestHeaderContract_JKUNeverRedirects — `jku` is a URL to a JWKS. Honoring it
// would move key resolution OFF the IdP JWKS to an attacker-controlled endpoint
// (the §11.2 violation). The header carries a valid kid that DOES resolve on the
// real JWKS and a genuine signature, so if jku were ignored the token would
// validate; it must be REFUSED at parse instead, proving jku can never redirect.
func TestHeaderContract_JKUNeverRedirects(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	// Point jku at a hostile JWKS URL. The kid + signature are otherwise valid.
	for _, jku := range []string{
		"https://attacker.example/jwks.json",
		c.server.URL + "/jwks",        // even the REAL server's URL must be refused: the key source is config, never the header
		"http://169.254.169.254/jwks", // SSRF-flavored
	} {
		header := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "jku": jku}
		token := signedRS256Token(t, signer, header, c.goodClaims())
		mustReject(t, p, token, "jku")
	}

	// Control: the SAME kid + claims WITHOUT a jku validates — proving the rejection
	// is the jku member, not the kid or signature.
	okHeader := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT"}
	okToken := signedRS256Token(t, signer, okHeader, c.goodClaims())
	if _, err := p.ValidateIDToken(context.Background(), okToken, ""); err != nil {
		t.Fatalf("control: jku-free token must validate, got %v", err)
	}
}

// TestHeaderContract_X5UNeverRedirects — `x5u` is a URL to an X.509 cert chain;
// same family as jku (a self-declared, off-JWKS key source). Refused at parse.
func TestHeaderContract_X5UNeverRedirects(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	for _, x5u := range []string{
		"https://attacker.example/chain.pem",
		c.server.URL + "/x5u",
	} {
		header := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "x5u": x5u}
		token := signedRS256Token(t, signer, header, c.goodClaims())
		mustReject(t, p, token, "x5u")
	}
}

// TestHeaderContract_X5CNeverRedirects — `x5c` is an INLINE base64-DER X.509 cert
// chain offered as a self-declared key source. A verifier that trusted x5c would
// take the token's own embedded cert as the signing key, bypassing the JWKS
// entirely. It must be refused at parse — the key is the JWKS key for kid, never a
// token-embedded cert. We pin both a populated chain and a single-element one.
func TestHeaderContract_X5CNeverRedirects(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	// The attacker's own cert bytes (DER → base64) — the shape an x5c carries. The
	// exact contents are immaterial (the verifier never parses them; it refuses on
	// presence), but a faithful fixture uses a real DER blob.
	attackerCert := b64url.EncodeToString(pubKeyBytes(t, signer.Public()))
	for _, x5c := range [][]string{
		{attackerCert},
		{attackerCert, attackerCert}, // a chain
	} {
		header := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "x5c": x5c}
		token := signedRS256Token(t, signer, header, c.goodClaims())
		mustReject(t, p, token, "x5c")
	}

	// A JSON null / absent x5c must NOT be treated as present (no over-rejection):
	// the otherwise-valid token validates.
	okHeader := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "x5c": nil}
	okToken := signedRS256Token(t, signer, okHeader, c.goodClaims())
	if _, err := p.ValidateIDToken(context.Background(), okToken, ""); err != nil {
		t.Fatalf("control: x5c:null must not be treated as present, got %v", err)
	}
}

// TestHeaderContract_X5TThumbprintRefused — `x5t` (RFC 7515 §4.1.7) and `x5t#S256`
// (§4.1.8) are X.509 cert thumbprints: base64url SHA-1/SHA-256 digests of the DER
// cert that corresponds to the signing key. They are the SAME self-declared-cert
// family as x5c/x5u — a thumbprint NAMES a certificate the token chose, not the JWKS
// key the `kid` resolves. The idp-x5t (orch16) decision is to REFUSE them on
// presence for fence consistency with x5c/x5u and as defense-in-depth: key
// resolution is kid-only (a thumbprint cannot MOVE resolution), but an unverified
// cert assertion in the protected header is a member we do not process, so we fail
// closed rather than ignore it (see oidc.go x5tDecision). This pins the decision: a
// genuinely-signed, otherwise-valid token carrying x5t / x5t#S256 must be refused at
// parse with the named reason, proving the refusal is the thumbprint member — not a
// signature, kid, or claim problem. The control (no thumbprint) validates.
func TestHeaderContract_X5TThumbprintRefused(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	// A plausible thumbprint value (base64url of a 20-byte SHA-1 / 32-byte SHA-256
	// digest). The verifier never parses it — presence alone is fatal — but a
	// faithful fixture uses a digest-shaped blob.
	sha1Print := b64url.EncodeToString(make([]byte, 20))
	sha256Print := b64url.EncodeToString(make([]byte, 32))

	// x5t (SHA-1 thumbprint) — refused on presence.
	for _, x5t := range []string{sha1Print, "thumb", c.server.URL} {
		header := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "x5t": x5t}
		token := signedRS256Token(t, signer, header, c.goodClaims())
		mustReject(t, p, token, "x5t (self-declared cert thumbprint)")
	}

	// x5t#S256 (SHA-256 thumbprint) — the modern member, refused identically. The
	// member name carries a '#', so the JSON tag `x5t#S256` must match it exactly.
	for _, x5ts256 := range []string{sha256Print, "thumb256"} {
		header := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "x5t#S256": x5ts256}
		token := signedRS256Token(t, signer, header, c.goodClaims())
		mustReject(t, p, token, "x5t#S256 (self-declared cert thumbprint)")
	}

	// Both thumbprints present at once — still refused (x5t is checked first, so the
	// x5t reason wins; the point is that the token never validates).
	bothHeader := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "x5t": sha1Print, "x5t#S256": sha256Print}
	mustReject(t, p, signedRS256Token(t, signer, bothHeader, c.goodClaims()), "self-declared cert thumbprint")

	// Control: the SAME kid + claims WITHOUT any thumbprint validates — proving the
	// rejection is the x5t/x5t#S256 member, not the kid or signature, and that an
	// empty/absent thumbprint is NOT treated as present (no over-rejection).
	okHeader := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT"}
	if _, err := p.ValidateIDToken(context.Background(), signedRS256Token(t, signer, okHeader, c.goodClaims()), ""); err != nil {
		t.Fatalf("control: thumbprint-free token must validate, got %v", err)
	}
	// An explicitly-empty thumbprint string is absent, not present → must validate.
	emptyHeader := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": "JWT", "x5t": "", "x5t#S256": ""}
	if _, err := p.ValidateIDToken(context.Background(), signedRS256Token(t, signer, emptyHeader, c.goodClaims()), ""); err != nil {
		t.Fatalf("control: empty x5t/x5t#S256 must not be treated as present, got %v", err)
	}
}

// TestHeaderContract_X5TRejectedBeforeKeyResolution proves the thumbprint refusal
// happens at PARSE, before keyFor — so a token carrying x5t / x5t#S256 is refused
// even when the kid it names is ABSENT from the JWKS (it never reaches the kid
// lookup). If the contract were enforced after key resolution, this would fail with
// a kid miss instead of the thumbprint reason — mirroring the jku/x5u/x5c/crit case.
func TestHeaderContract_X5TRejectedBeforeKeyResolution(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	for _, tc := range []struct {
		member string
		want   string
		header map[string]any
	}{
		{"x5t", "x5t (self-declared cert thumbprint)", map[string]any{"alg": "RS256", "kid": "kid-ghost", "typ": "JWT", "x5t": "AAAA"}},
		{"x5t#S256", "x5t#S256 (self-declared cert thumbprint)", map[string]any{"alg": "RS256", "kid": "kid-ghost", "typ": "JWT", "x5t#S256": "AAAA"}},
	} {
		token := signedRS256Token(t, signer, tc.header, c.goodClaims())
		mustReject(t, p, token, tc.want)
		_, err := p.ValidateIDToken(context.Background(), token, "")
		if strings.Contains(err.Error(), "no JWKS key for kid") {
			t.Fatalf("%s: refused at key resolution (%q), but the thumbprint must be refused at PARSE, before keyFor", tc.member, err.Error())
		}
	}
}

// TestHeaderContract_MembersRejectedBeforeKeyResolution proves the header-member
// refusal happens at PARSE, before keyFor — so a steered header is refused even
// when the kid it names is ABSENT from the JWKS (it never reaches the kid lookup).
// If the contract were enforced after key resolution, this would fail with a kid
// miss instead of the member reason.
func TestHeaderContract_MembersRejectedBeforeKeyResolution(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	// kid-ghost is NOT in the JWKS; the offending member must still be the reason.
	cases := []struct {
		member string
		want   string
		header map[string]any
	}{
		{"jku", "jku", map[string]any{"alg": "RS256", "kid": "kid-ghost", "typ": "JWT", "jku": "https://attacker/jwks"}},
		{"x5u", "x5u", map[string]any{"alg": "RS256", "kid": "kid-ghost", "typ": "JWT", "x5u": "https://attacker/chain"}},
		{"x5c", "x5c", map[string]any{"alg": "RS256", "kid": "kid-ghost", "typ": "JWT", "x5c": []string{"AAAA"}}},
		{"crit", "unknown critical extension", map[string]any{"alg": "RS256", "kid": "kid-ghost", "typ": "JWT", "crit": []string{"b64"}}},
	}
	for _, tc := range cases {
		token := signedRS256Token(t, signer, tc.header, c.goodClaims())
		// must be the MEMBER reason, not "no JWKS key for kid"
		mustReject(t, p, token, tc.want)
		_, err := p.ValidateIDToken(context.Background(), token, "")
		if strings.Contains(err.Error(), "no JWKS key for kid") {
			t.Fatalf("%s: refused at key resolution (%q), but the header member must be refused at PARSE, before keyFor", tc.member, err.Error())
		}
	}
}

// --- §11.2 typ-header policy (oidc.go: typAllowed / jwsHeader.validate) ---
//
// The JWS `typ` member declares the JOSE object type. An OIDC ID token's typ is
// OPTIONAL (RFC 7519 §5.1: many IdPs omit it) and, when present, is the JWT media
// type ("JWT" / "application/JWT", case-insensitively). A typ naming a DIFFERENT,
// explicitly-typed JOSE object — "at+jwt" (RFC 9068 access token), "logout+jwt"
// (RFC 8417 / OIDC back-channel logout), "dpop+jwt" (RFC 9449), … — is a token the
// IdP minted for some OTHER purpose; accepting it as an ID token is the typ-confusion
// replay. The policy is {absent, JWT-family} accept, everything else a hard refusal —
// the same fail-closed treatment the alg set and the other header members get. These
// cases pin both sides: the accepted shapes validate, the wrong-type ones are refused
// with the named typ reason at header parse (before keyFor).

// TestTypPolicy_AbsentOrJWTAccepted — the legitimate ID-token shapes. typ absent
// (the common case — many IdPs omit it), and the JWT-family media-type spellings
// ("JWT", lowercase "jwt", "application/JWT" with/without the optional prefix and
// case), all validate. The token is otherwise fully valid, so a failure here would
// be over-rejection of a real ID token.
func TestTypPolicy_AbsentOrJWTAccepted(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	// typ ABSENT — omit the member entirely (RFC 7519 §5.1: typ is optional).
	absentHeader := map[string]any{"alg": "RS256", "kid": "kid-rsa"}
	if _, err := p.ValidateIDToken(context.Background(), signedRS256Token(t, signer, absentHeader, c.goodClaims()), ""); err != nil {
		t.Fatalf("typ absent must validate (it is the common ID-token shape), got %v", err)
	}

	// JWT-family values — the media type is case-insensitive and the "application/"
	// prefix is optional, so every spelling below is the SAME JWT media type.
	for _, typ := range []string{"JWT", "jwt", "Jwt", "application/JWT", "application/jwt", " JWT "} {
		header := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": typ}
		if _, err := p.ValidateIDToken(context.Background(), signedRS256Token(t, signer, header, c.goodClaims()), ""); err != nil {
			t.Fatalf("typ %q is a JWT-family value and must validate, got %v", typ, err)
		}
	}
}

// TestTypPolicy_WrongJOSETypeRejected — the typ-confusion defense. A typ naming a
// distinct JOSE object type must be refused as an ID token, even though the token
// is otherwise genuinely signed by the JWKS key (so if typ were unconstrained it
// WOULD validate). The refusal must be the named typ reason, at parse — proving the
// rejection is the typ policy, not a signature/kid/claim problem. The canonical
// attack tokens are the structured "+jwt" object types an IdP issues for other
// purposes: access tokens (at+jwt), logout tokens (logout+jwt), DPoP proofs
// (dpop+jwt), and security event tokens (secevent+jwt).
func TestTypPolicy_WrongJOSETypeRejected(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	for _, typ := range []string{
		"at+jwt", // RFC 9068 OAuth 2.0 access token — the headline replay
		"application/at+jwt",
		"logout+jwt",   // OIDC back-channel logout token
		"dpop+jwt",     // RFC 9449 DPoP proof
		"secevent+jwt", // RFC 8417 security event token
		"refresh+jwt",  // a refresh-style token re-presented as an ID token
		"JOSE",         // a non-JWT JOSE object entirely
		"JOSE+JSON",
		"jwt+something", // a structured suffix on jwt is still NOT the jwt media type
		"not-a-jwt",
	} {
		header := map[string]any{"alg": "RS256", "kid": "kid-rsa", "typ": typ}
		token := signedRS256Token(t, signer, header, c.goodClaims())
		mustReject(t, p, token, "is not an OIDC ID token")
	}
}

// TestTypPolicy_RejectedBeforeKeyResolution proves the typ refusal happens at PARSE,
// before keyFor — so a wrong-type token is refused even when the kid it names is
// ABSENT from the JWKS (it never reaches the kid lookup). If the policy were enforced
// after key resolution this would fail with a kid miss instead of the typ reason.
func TestTypPolicy_RejectedBeforeKeyResolution(t *testing.T) {
	signer := genRSA(t)
	c := newConfuser(t, jwksDoc{Keys: []jsonWebKey{rsaJWK(t, "kid-rsa", signer)}})
	p := c.provider()

	// kid-ghost is NOT in the JWKS; the typ must still be the reason.
	header := map[string]any{"alg": "RS256", "kid": "kid-ghost", "typ": "at+jwt"}
	token := signedRS256Token(t, signer, header, c.goodClaims())
	mustReject(t, p, token, "is not an OIDC ID token")
	_, err := p.ValidateIDToken(context.Background(), token, "")
	if strings.Contains(err.Error(), "no JWKS key for kid") {
		t.Fatalf("refused at key resolution (%q), but a wrong typ must be refused at PARSE, before keyFor", err.Error())
	}
}

// TestTypAllowed_Membership pins the typAllowed predicate directly — the one-glance
// review surface for the {absent, JWT-family} policy, mirroring TestAlgAllowlist's
// membership pin. Absent and the JWT media-type spellings are IN; every distinct
// JOSE object type is OUT.
func TestTypAllowed_Membership(t *testing.T) {
	for _, typ := range []string{"", "JWT", "jwt", "Jwt", "JWt", "application/JWT", "application/jwt", " JWT ", "\tjwt\n"} {
		if !typAllowed(typ) {
			t.Fatalf("typ %q must be accepted (absent or JWT-family)", typ)
		}
	}
	for _, typ := range []string{
		"at+jwt", "application/at+jwt", "logout+jwt", "dpop+jwt", "secevent+jwt",
		"refresh+jwt", "jwt+x", "x+jwt", "JOSE", "JOSE+JSON", "not-a-jwt", "jw", "jwts",
		"application/", "application/jose", "+jwt",
	} {
		if typAllowed(typ) {
			t.Fatalf("typ %q must be REJECTED (a distinct JOSE object type, not the JWT media type)", typ)
		}
	}
}
