// SPDX-License-Identifier: Apache-2.0
package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"
)

// AuthnRequest is the SAML 2.0 SP-initiated AuthnRequest.
type AuthnRequest struct {
	ID           string // random unique ID (underscore-prefixed, RFC 4122 MUST NOT start with digit)
	IssueInstant string // UTC ISO 8601
	Destination  string // IdP SSO URL
	ACSURL       string // SP ACS URL
	Issuer       string // SP entity ID
	RelayState   string // signed nonce (CSRF + correlation)
}

// authnRequestXML is the encoding/xml representation of a SAML 2.0 AuthnRequest.
type authnRequestXML struct {
	XMLName                     xml.Name        `xml:"samlp:AuthnRequest"`
	SamlpNS                     string          `xml:"xmlns:samlp,attr"`
	SamlNS                      string          `xml:"xmlns:saml,attr"`
	ID                          string          `xml:"ID,attr"`
	Version                     string          `xml:"Version,attr"`
	IssueInstant                string          `xml:"IssueInstant,attr"`
	Destination                 string          `xml:"Destination,attr"`
	AssertionConsumerServiceURL string          `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string          `xml:"ProtocolBinding,attr"`
	Issuer                      samlIssuerXML   `xml:"saml:Issuer"`
	NameIDPolicy                nameIDPolicyXML `xml:"samlp:NameIDPolicy"`
}

type samlIssuerXML struct {
	Value string `xml:",chardata"`
}

type nameIDPolicyXML struct {
	AllowCreate bool   `xml:"AllowCreate,attr"`
	Format      string `xml:"Format,attr"`
}

// signatureXML is the XML-DSig Signature element (enveloped).
type signatureXML struct {
	XMLName        xml.Name      `xml:"ds:Signature"`
	XMLDSNS        string        `xml:"xmlns:ds,attr"`
	SignedInfo     signedInfoXML `xml:"ds:SignedInfo"`
	SignatureValue string        `xml:"ds:SignatureValue"`
	KeyInfo        keyInfoXML    `xml:"ds:KeyInfo"`
}

type signedInfoXML struct {
	CanonicalizationMethod canonMethodXML `xml:"ds:CanonicalizationMethod"`
	SignatureMethod        sigMethodXML   `xml:"ds:SignatureMethod"`
	Reference              referenceXML   `xml:"ds:Reference"`
}

type canonMethodXML struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type sigMethodXML struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type referenceXML struct {
	URI          string          `xml:"URI,attr"`
	Transforms   transformsXML   `xml:"ds:Transforms"`
	DigestMethod digestMethodXML `xml:"ds:DigestMethod"`
	DigestValue  string          `xml:"ds:DigestValue"`
}

type transformsXML struct {
	Transforms []transformXML `xml:"ds:Transform"`
}

type transformXML struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type digestMethodXML struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type keyInfoXML struct {
	X509Data x509DataXML `xml:"ds:X509Data"`
}

type x509DataXML struct {
	X509Certificate string `xml:"ds:X509Certificate"`
}

// GenerateRelayState returns 16 random bytes encoded as base64url (URL-safe, no padding).
// It is used as a CSRF nonce and correlation token.
func GenerateRelayState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("saml: generate relay state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewAuthnRequest constructs an AuthnRequest from cfg, filling ID and IssueInstant.
// The cfg must pass Validate().
func NewAuthnRequest(cfg Config) (AuthnRequest, error) {
	if err := cfg.Validate(); err != nil {
		return AuthnRequest{}, err
	}
	relayState, err := GenerateRelayState()
	if err != nil {
		return AuthnRequest{}, err
	}
	id, err := generateID()
	if err != nil {
		return AuthnRequest{}, err
	}
	return AuthnRequest{
		ID:           id,
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Destination:  cfg.IDPMetadata.SSOURL,
		ACSURL:       cfg.ACSURL,
		Issuer:       cfg.SPEntityID,
		RelayState:   relayState,
	}, nil
}

// generateID returns an underscore-prefixed random ID safe for XML (MUST NOT start with digit).
// Uses 16 random bytes encoded as hex, prefixed with "_".
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("saml: generate id: %w", err)
	}
	return "_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// BuildXML marshals the AuthnRequest to XML bytes (without Signature element).
func BuildXML(req AuthnRequest) ([]byte, error) {
	x := authnRequestXML{
		SamlpNS:                     "urn:oasis:names:tc:SAML:2.0:protocol",
		SamlNS:                      "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:                          req.ID,
		Version:                     "2.0",
		IssueInstant:                req.IssueInstant,
		Destination:                 req.Destination,
		AssertionConsumerServiceURL: req.ACSURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Issuer:                      samlIssuerXML{Value: req.Issuer},
		NameIDPolicy: nameIDPolicyXML{
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		},
	}
	out, err := xml.MarshalIndent(x, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal authn request: %w", err)
	}
	return append([]byte(xml.Header), out...), nil
}

// SignXML takes the raw XML bytes of an AuthnRequest (as produced by BuildXML)
// and returns a new XML document with an enveloped XML-DSig Signature element
// inserted as a child of samlp:AuthnRequest.
//
// Signing algorithm: RSA-SHA256 (http://www.w3.org/2001/04/xmldsig-more#rsa-sha256).
// Canonicalization: Exclusive C14N (http://www.w3.org/2001/10/xml-exc-c14n#).
//
// The document digest is computed over xmlBytes (the unsigned form); the
// SignedInfo is then signed with RSA-PKCS1v15.
func SignXML(xmlBytes []byte, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	// 1. Compute the SHA-256 digest of the raw XML bytes (the unsigned document).
	digest := sha256.Sum256(xmlBytes)
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// 2. Build the SignedInfo XML.  Reference URI="" = whole document (enveloped).
	signedInfo := signedInfoXML{
		CanonicalizationMethod: canonMethodXML{
			Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
		},
		SignatureMethod: sigMethodXML{
			Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		},
		Reference: referenceXML{
			URI: "",
			Transforms: transformsXML{
				Transforms: []transformXML{
					{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
					{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
				},
			},
			DigestMethod: digestMethodXML{
				Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
			},
			DigestValue: digestB64,
		},
	}

	// Serialize the SignedInfo for signing.
	siBytes, err := xml.Marshal(signedInfo)
	if err != nil {
		return nil, fmt.Errorf("saml: marshal signed info: %w", err)
	}

	// 3. Compute SHA-256 of the SignedInfo bytes and sign with RSA-PKCS1v15.
	siDigest := sha256.Sum256(siBytes)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, siDigest[:])
	if err != nil {
		return nil, fmt.Errorf("saml: rsa sign: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// 4. Build the KeyInfo (certificate in PEM-like DER-base64 form).
	var certB64 string
	if cert != nil {
		certB64 = base64.StdEncoding.EncodeToString(cert.Raw)
	}

	sig := signatureXML{
		XMLDSNS:        "http://www.w3.org/2000/09/xmldsig#",
		SignedInfo:     signedInfo,
		SignatureValue: sigB64,
		KeyInfo: keyInfoXML{
			X509Data: x509DataXML{X509Certificate: certB64},
		},
	}

	// 5. Build the signed document: strip the <?xml?> header from xmlBytes,
	//    find the closing tag of the root element, insert the Signature before it,
	//    then re-add the XML header.
	sigXML, err := xml.MarshalIndent(sig, "  ", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal signature: %w", err)
	}

	body := stripXMLHeader(xmlBytes)
	signed, err := injectSignatureBeforeClose(body, sigXML)
	if err != nil {
		return nil, fmt.Errorf("saml: inject signature: %w", err)
	}
	return append([]byte(xml.Header), signed...), nil
}

// injectSignatureBeforeClose inserts sigXML immediately before the closing tag
// of the root element in bodyXML (e.g. </samlp:AuthnRequest>).
func injectSignatureBeforeClose(bodyXML, sigXML []byte) ([]byte, error) {
	body := string(bodyXML)
	// Find the last occurrence of a closing tag that ends the root element.
	// We look for the last "</" as a heuristic for the root closing tag.
	idx := findRootClosingTag(body)
	if idx < 0 {
		return nil, fmt.Errorf("could not find root closing tag in XML document")
	}
	var out []byte
	out = append(out, bodyXML[:idx]...)
	out = append(out, '\n')
	out = append(out, sigXML...)
	out = append(out, '\n')
	out = append(out, bodyXML[idx:]...)
	return out, nil
}

// findRootClosingTag returns the byte index of the last top-level closing tag
// in the XML document (the position of the last "</").
func findRootClosingTag(s string) int {
	idx := -1
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '<' && s[i+1] == '/' {
			idx = i
		}
	}
	return idx
}

// stripXMLHeader removes a leading <?xml...?> processing instruction from XML bytes.
func stripXMLHeader(b []byte) []byte {
	if len(b) < 5 {
		return b
	}
	// Find end of processing instruction
	for i := 0; i < len(b)-1; i++ {
		if b[i] == '?' && b[i+1] == '>' {
			rest := b[i+2:]
			// Skip whitespace
			j := 0
			for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t' || rest[j] == '\n' || rest[j] == '\r') {
				j++
			}
			return rest[j:]
		}
	}
	return b
}
