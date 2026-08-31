// SPDX-License-Identifier: Apache-2.0
package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// acsNoCertConfig builds a Config whose IdP metadata has NO signing certificate
// configured, which a production SAML deployment must treat as a hard refusal
// (D124 round-5 packet sec4). Synthetic fixtures only (D50).
func acsNoCertConfig(t *testing.T) Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return Config{
		OrgID:      "org-synthetic-saml-acs-test",
		SPEntityID: "https://platform.example.com/saml/metadata",
		ACSURL:     "https://platform.example.com/saml/acs",
		SigningKey: key,
		IDPMetadata: &IDPMetadata{
			EntityID: "https://idp.example.com/saml/metadata",
			SSOURL:   "https://idp.example.com/saml/sso",
			// SigningCertificate deliberately nil.
		},
	}
}

// buildResponseB64 constructs a base64-encoded, otherwise well-formed SAML
// Response that passes the status/destination/issuer/assertion checks so that
// ValidateResponse reaches the signature-verification stage. When withSig is
// true, the assertion carries a (structurally present) Signature element.
func buildResponseB64(withSig bool) string {
	sig := ""
	if withSig {
		sig = `<Signature>` +
			`<SignedInfo><Reference URI="#a1"><DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue></Reference></SignedInfo>` +
			`<SignatureValue>QkJCQg==</SignatureValue>` +
			`</Signature>`
	}
	doc := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://platform.example.com/saml/acs">` +
		`<Issuer>https://idp.example.com/saml/metadata</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion ID="a1">` +
		`<Issuer>https://idp.example.com/saml/metadata</Issuer>` +
		sig +
		`<Subject><NameID>user@example.com</NameID></Subject>` +
		`</Assertion>` +
		`</samlp:Response>`
	return base64.StdEncoding.EncodeToString([]byte(doc))
}

// TestValidateResponse_NoIDPCert_HardRefusal is the core D124 obligation: with
// NO IdP signing certificate configured, an assertion must be REJECTED with a
// hard error — never accepted unverified — whether or not a signature element
// is present.
func TestValidateResponse_NoIDPCert_HardRefusal(t *testing.T) {
	cfg := acsNoCertConfig(t)

	for _, tc := range []struct {
		name    string
		withSig bool
	}{
		{"with assertion signature element", true},
		{"without any signature element", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b64 := buildResponseB64(tc.withSig)
			claims, err := ValidateResponse(cfg, b64, "", 0)
			if err == nil {
				t.Fatalf("ValidateResponse accepted assertion with no configured IdP cert; must hard-refuse (claims=%+v)", claims)
			}
			if !errors.Is(err, ErrResponse) {
				t.Errorf("error = %v, want it to wrap ErrResponse", err)
			}
			if claims.Subject != "" || claims.Email != "" || len(claims.Groups) != 0 {
				t.Errorf("claims must be zero on refusal, got %+v", claims)
			}
		})
	}
}

// TestVerifyIDPSignature_NilCert_Errors pins verifyIDPSignature itself: a nil
// certificate is a hard error, not a fail-open nil return.
func TestVerifyIDPSignature_NilCert_Errors(t *testing.T) {
	sig := &samlSignature{}
	if err := verifyIDPSignature(sig, []byte("doc"), nil); err == nil {
		t.Fatal("verifyIDPSignature(nil cert) = nil; want a hard-refusal error")
	}
}

// TestVerifyIDPSignature_WithCert_ReachesCryptoCheck confirms the behavior is
// unchanged when a cert IS configured: the function proceeds past the nil-cert
// gate into the cryptographic checks (here failing at the digest step), rather
// than returning the no-cert refusal.
func TestVerifyIDPSignature_WithCert_ReachesCryptoCheck(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "synthetic-idp"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	sig := &samlSignature{}
	sig.SignedInfo.Reference.DigestValue = base64.StdEncoding.EncodeToString(make([]byte, 32)) // wrong digest
	sig.SignatureValue = base64.StdEncoding.EncodeToString([]byte("sig"))

	err = verifyIDPSignature(sig, []byte("some document"), cert)
	if err == nil {
		t.Fatal("verifyIDPSignature with a mismatching digest unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "no idp signing certificate") {
		t.Errorf("with a cert configured, must reach the crypto check, not the no-cert refusal; got %v", err)
	}
	// sanity: it should be the digest mismatch path.
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("expected a digest-related error with a configured cert, got %v", err)
	}
}

// synthIDPKeyCert generates a synthetic RSA key + self-signed certificate
// standing in for the IdP assertion-signing credential (D50 synthetic fixtures).
func synthIDPKeyCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "synthetic-idp-signing"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

// acsSignedConfig builds a Config whose IdP metadata trusts cert as the
// assertion-signing certificate.
func acsSignedConfig(t *testing.T, cert *x509.Certificate) Config {
	t.Helper()
	spKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate SP RSA key: %v", err)
	}
	return Config{
		OrgID:      "org-synthetic-saml-signed",
		SPEntityID: "https://platform.example.com/saml/metadata",
		ACSURL:     "https://platform.example.com/saml/acs",
		SigningKey: spKey,
		IDPMetadata: &IDPMetadata{
			EntityID:           "https://idp.example.com/saml/metadata",
			SSOURL:             "https://idp.example.com/saml/sso",
			SigningCertificate: cert,
		},
	}
}

// signedResponseXML wraps a signature-free assertion (a complete
// <Assertion ID="a1">…</Assertion> element, compact / no inter-tag whitespace)
// in a SAML Response, computes the DigestValue/SignatureValue over the
// Exclusive-C14N canonicalization of the assertion (enveloped-signature
// transform applied), embeds the resulting <Signature> into the assertion, and
// returns the complete signed document.  Because the canonicalizer is invariant
// to the signature it strips, the digest computed over the signature-free form
// matches the digest verifyIDPSignature computes over the signed form.
func signedResponseXML(t *testing.T, key *rsa.PrivateKey, assertion string) string {
	t.Helper()
	const respOpen = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://platform.example.com/saml/acs">` +
		`<Issuer>https://idp.example.com/saml/metadata</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>`
	const respClose = `</samlp:Response>`

	canon, err := canonicalizeSignedElement([]byte(respOpen+assertion+respClose), "#a1")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	digest := sha256.Sum256(canon)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	sigElem := `<Signature>` +
		`<SignedInfo><Reference URI="#a1"><DigestValue>` +
		base64.StdEncoding.EncodeToString(digest[:]) +
		`</DigestValue></Reference></SignedInfo>` +
		`<SignatureValue>` +
		base64.StdEncoding.EncodeToString(sigBytes) +
		`</SignatureValue>` +
		`</Signature>`
	// Insert the Signature as the last child of the assertion, i.e. immediately
	// before the assertion's own closing tag (the last "</" in the string) —
	// robust to whether the element is default- or prefix-namespaced.
	closeIdx := strings.LastIndex(assertion, "</")
	if closeIdx < 0 {
		t.Fatalf("could not locate assertion closing tag in %q", assertion)
	}
	signedAssertion := assertion[:closeIdx] + sigElem + assertion[closeIdx:]
	return respOpen + signedAssertion + respClose
}

// TestCanonicalizeSignedElement_EquivalentSerializations pins the C14N
// invariant: two byte-different but canonically-equivalent serializations of the
// signed element (differing in attribute order, self-closing vs explicit empty
// tags, namespace prefix, and a redundant xmlns declaration) canonicalize to
// identical octets.
func TestCanonicalizeSignedElement_EquivalentSerializations(t *testing.T) {
	variantA := `<Assertion ID="a1" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer>https://idp.example.com/saml/metadata</Issuer>` +
		`<Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2100-01-01T00:00:00Z"/>` +
		`<Subject><NameID>user@example.com</NameID></Subject>` +
		`</Assertion>`
	// variantB: attributes reordered, prefix instead of default ns, redundant
	// xmlns declaration, and an explicit empty-tag pair for Conditions.
	variantB := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">` +
		`<saml:Issuer>https://idp.example.com/saml/metadata</saml:Issuer>` +
		`<saml:Conditions NotOnOrAfter="2100-01-01T00:00:00Z" NotBefore="2020-01-01T00:00:00Z"></saml:Conditions>` +
		`<saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:NameID>user@example.com</saml:NameID></saml:Subject>` +
		`</saml:Assertion>`

	canonA, err := canonicalizeSignedElement([]byte(variantA), "#a1")
	if err != nil {
		t.Fatalf("canonicalize A: %v", err)
	}
	canonB, err := canonicalizeSignedElement([]byte(variantB), "#a1")
	if err != nil {
		t.Fatalf("canonicalize B: %v", err)
	}
	if string(canonA) != string(canonB) {
		t.Fatalf("canonically-equivalent serializations produced different octets:\nA=%s\nB=%s", canonA, canonB)
	}
	if len(canonA) == 0 {
		t.Fatal("canonicalization produced empty octets; element not located")
	}
}

// TestValidateResponse_C14N_EquivalentSerializationsVerify confirms that two
// byte-different-but-canonically-equivalent signed responses both verify with an
// identical signature — end to end through ValidateResponse.
func TestValidateResponse_C14N_EquivalentSerializationsVerify(t *testing.T) {
	key, cert := synthIDPKeyCert(t)
	cfg := acsSignedConfig(t, cert)
	const nowUnix = 1700000000 // 2023, within the assertion conditions window

	assertionA := `<Assertion ID="a1" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer>https://idp.example.com/saml/metadata</Issuer>` +
		`<Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2100-01-01T00:00:00Z"/>` +
		`<Subject><NameID>user@example.com</NameID></Subject>` +
		`</Assertion>`
	assertionB := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">` +
		`<saml:Issuer>https://idp.example.com/saml/metadata</saml:Issuer>` +
		`<saml:Conditions NotOnOrAfter="2100-01-01T00:00:00Z" NotBefore="2020-01-01T00:00:00Z"></saml:Conditions>` +
		`<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>` +
		`</saml:Assertion>`

	for _, tc := range []struct {
		name      string
		assertion string
	}{
		{"default-namespace serialization", assertionA},
		{"prefixed reordered serialization", assertionB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := signedResponseXML(t, key, tc.assertion)
			b64 := base64.StdEncoding.EncodeToString([]byte(doc))
			claims, err := ValidateResponse(cfg, b64, "", nowUnix)
			if err != nil {
				t.Fatalf("ValidateResponse rejected a validly-signed assertion: %v", err)
			}
			if claims.Subject != "user@example.com" {
				t.Errorf("Subject = %q, want user@example.com", claims.Subject)
			}
		})
	}
}

// TestValidateResponse_TamperedSignedElement_Rejected confirms that mutating the
// signed content after signing breaks the canonical digest and is rejected.
func TestValidateResponse_TamperedSignedElement_Rejected(t *testing.T) {
	key, cert := synthIDPKeyCert(t)
	cfg := acsSignedConfig(t, cert)
	const nowUnix = 1700000000

	assertion := `<Assertion ID="a1" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer>https://idp.example.com/saml/metadata</Issuer>` +
		`<Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2100-01-01T00:00:00Z"/>` +
		`<Subject><NameID>user@example.com</NameID></Subject>` +
		`</Assertion>`
	doc := signedResponseXML(t, key, assertion)

	// Sanity: the untampered document verifies.
	if _, err := ValidateResponse(cfg, base64.StdEncoding.EncodeToString([]byte(doc)), "", nowUnix); err != nil {
		t.Fatalf("baseline (untampered) response failed to verify: %v", err)
	}

	// Tamper the signed NameID (leaving the signature bytes intact).
	tampered := strings.Replace(doc, "user@example.com", "attacker@evil.example.com", 1)
	if tampered == doc {
		t.Fatal("tamper replacement did not modify the document")
	}
	claims, err := ValidateResponse(cfg, base64.StdEncoding.EncodeToString([]byte(tampered)), "", nowUnix)
	if err == nil {
		t.Fatalf("ValidateResponse accepted a tampered signed element (claims=%+v)", claims)
	}
	if !errors.Is(err, ErrResponse) {
		t.Errorf("error = %v, want it to wrap ErrResponse", err)
	}
}

// TestValidateForACS_NoIDPCert_ConstructionError pins the startup-time gate: a
// Config whose IdP metadata has no signing certificate is rejected at load, not
// silently at first login.
func TestValidateForACS_NoIDPCert_ConstructionError(t *testing.T) {
	cfg := acsNoCertConfig(t) // IDPMetadata.SigningCertificate is nil

	// The base Validate() intentionally still passes (unchanged contract)...
	if err := cfg.Validate(); err != nil {
		t.Fatalf("base Validate() should be unchanged, got %v", err)
	}
	// ...but the ACS-path validation must reject the missing cert.
	err := cfg.ValidateForACS()
	if err == nil {
		t.Fatal("ValidateForACS accepted a Config with no IdP signing certificate")
	}
	if !errors.Is(err, ErrConfig) {
		t.Errorf("error = %v, want it to wrap ErrConfig", err)
	}

	// A Config WITH a cert passes ValidateForACS.
	_, cert := synthIDPKeyCert(t)
	if err := acsSignedConfig(t, cert).ValidateForACS(); err != nil {
		t.Errorf("ValidateForACS rejected a fully-configured Config: %v", err)
	}
}

// TestNewIDPMetadata_NilCert_Error pins the direct-assembly gate.
func TestNewIDPMetadata_NilCert_Error(t *testing.T) {
	if _, err := NewIDPMetadata("https://idp.example.com/saml/metadata", "https://idp.example.com/saml/sso", nil); err == nil {
		t.Fatal("NewIDPMetadata(nil cert) = nil error; want a construction error")
	} else if !errors.Is(err, ErrConfig) {
		t.Errorf("error = %v, want it to wrap ErrConfig", err)
	}

	_, cert := synthIDPKeyCert(t)
	md, err := NewIDPMetadata("https://idp.example.com/saml/metadata", "https://idp.example.com/saml/sso", cert)
	if err != nil {
		t.Fatalf("NewIDPMetadata with a cert: %v", err)
	}
	if md.SigningCertificate != cert || md.EntityID == "" {
		t.Errorf("assembled metadata malformed: %+v", md)
	}
}

// TestParseIDPMetadata_RequiresSigningCert pins the metadata-load gate: metadata
// carrying a signing certificate assembles; metadata with none is rejected.
func TestParseIDPMetadata_RequiresSigningCert(t *testing.T) {
	_, cert := synthIDPKeyCert(t)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	withCert := `<?xml version="1.0"?>` +
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/saml/metadata">` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<KeyDescriptor use="signing">` +
		`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + certB64 +
		`</X509Certificate></X509Data></KeyInfo>` +
		`</KeyDescriptor>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml/sso"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`

	md, err := ParseIDPMetadata([]byte(withCert))
	if err != nil {
		t.Fatalf("ParseIDPMetadata with a signing cert: %v", err)
	}
	if md.EntityID != "https://idp.example.com/saml/metadata" {
		t.Errorf("EntityID = %q", md.EntityID)
	}
	if md.SSOURL != "https://idp.example.com/saml/sso" {
		t.Errorf("SSOURL = %q", md.SSOURL)
	}
	if md.SigningCertificate == nil || !md.SigningCertificate.Equal(cert) {
		t.Error("parsed metadata did not carry the expected signing certificate")
	}

	noCert := `<?xml version="1.0"?>` +
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/saml/metadata">` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml/sso"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`

	if _, err := ParseIDPMetadata([]byte(noCert)); err == nil {
		t.Fatal("ParseIDPMetadata accepted metadata with no signing certificate")
	} else if !errors.Is(err, ErrConfig) {
		t.Errorf("error = %v, want it to wrap ErrConfig", err)
	}
}
