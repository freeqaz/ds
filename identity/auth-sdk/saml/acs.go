// SPDX-License-Identifier: Apache-2.0
package saml

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// AssertionClaims is the validated claim set from a SAML assertion.
type AssertionClaims struct {
	Subject      string   // NameID (stable identity)
	Email        string   // email attribute
	Name         string   // displayName attribute
	Groups       []string // group membership (for platform role mapping)
	SessionIdx   string   // AuthnStatement SessionIndex
	NotOnOrAfter string   // expiry from SubjectConfirmationData
}

// --- XML parsing types for SAML Responses ---

type samlResponseEnvelope struct {
	XMLName      xml.Name       `xml:"Response"`
	ID           string         `xml:"ID,attr"`
	InResponseTo string         `xml:"InResponseTo,attr"`
	Destination  string         `xml:"Destination,attr"`
	IssueInstant string         `xml:"IssueInstant,attr"`
	Issuer       string         `xml:"Issuer"`
	Status       samlStatus     `xml:"Status"`
	Signature    *samlSignature `xml:"Signature"`
	Assertion    *samlAssertion `xml:"Assertion"`
}

type samlStatus struct {
	StatusCode samlStatusCode `xml:"StatusCode"`
}

type samlStatusCode struct {
	Value string `xml:"Value,attr"`
}

type samlSignature struct {
	SignedInfo     samlSignedInfo `xml:"SignedInfo"`
	SignatureValue string         `xml:"SignatureValue"`
}

type samlSignedInfo struct {
	Reference samlReference `xml:"Reference"`
}

type samlReference struct {
	URI         string `xml:"URI,attr"`
	DigestValue string `xml:"DigestValue"`
}

type samlAssertion struct {
	ID                 string                 `xml:"ID,attr"`
	IssueInstant       string                 `xml:"IssueInstant,attr"`
	Issuer             string                 `xml:"Issuer"`
	Signature          *samlSignature         `xml:"Signature"`
	Subject            samlSubject            `xml:"Subject"`
	Conditions         samlConditions         `xml:"Conditions"`
	AuthnStatement     samlAuthnStatement     `xml:"AuthnStatement"`
	AttributeStatement samlAttributeStatement `xml:"AttributeStatement"`
}

type samlSubject struct {
	NameID              samlNameID              `xml:"NameID"`
	SubjectConfirmation samlSubjectConfirmation `xml:"SubjectConfirmation"`
}

type samlNameID struct {
	Value string `xml:",chardata"`
}

type samlSubjectConfirmation struct {
	SubjectConfirmationData samlSubjectConfirmationData `xml:"SubjectConfirmationData"`
}

type samlSubjectConfirmationData struct {
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Recipient    string `xml:"Recipient,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`
}

type samlConditions struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}

type samlAuthnStatement struct {
	SessionIndex string `xml:"SessionIndex,attr"`
}

type samlAttributeStatement struct {
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	Name   string          `xml:"Name,attr"`
	Values []samlAttrValue `xml:"AttributeValue"`
}

type samlAttrValue struct {
	Value string `xml:",chardata"`
}

// ValidateResponse parses and validates a base64-encoded SAML Response.
// Validates: Destination matches ACSURL, Issuer matches IdP entityID,
// signature on the Response OR the Assertion (at least one must be signed
// by the IdP signing cert), Conditions NotBefore/NotOnOrAfter,
// SubjectConfirmation NotOnOrAfter.
func ValidateResponse(cfg Config, samlResponseB64 string, relayState string, nowUnix int64) (AssertionClaims, error) {
	// 1. Decode base64.
	rawXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return AssertionClaims{}, fmt.Errorf("%w: base64 decode: %v", ErrResponse, err)
	}

	// 2. Parse the XML.
	var resp samlResponseEnvelope
	if err := xml.Unmarshal(rawXML, &resp); err != nil {
		return AssertionClaims{}, fmt.Errorf("%w: xml parse: %v", ErrResponse, err)
	}

	// 3. Status must be Success.
	const successCode = "urn:oasis:names:tc:SAML:2.0:status:Success"
	if resp.Status.StatusCode.Value != successCode {
		return AssertionClaims{}, fmt.Errorf("%w: non-success status: %s", ErrResponse, resp.Status.StatusCode.Value)
	}

	// 4. Destination must match ACS URL.
	if resp.Destination != "" && resp.Destination != cfg.ACSURL {
		return AssertionClaims{}, fmt.Errorf("%w: destination mismatch: got %q want %q", ErrResponse, resp.Destination, cfg.ACSURL)
	}

	// 5. Issuer must match IdP entityID.
	respIssuer := strings.TrimSpace(resp.Issuer)
	if respIssuer != cfg.IDPMetadata.EntityID {
		return AssertionClaims{}, fmt.Errorf("%w: issuer mismatch: got %q want %q", ErrResponse, respIssuer, cfg.IDPMetadata.EntityID)
	}

	// 6. Assertion must be present.
	if resp.Assertion == nil {
		return AssertionClaims{}, fmt.Errorf("%w: missing Assertion element", ErrResponse)
	}
	a := resp.Assertion

	// 7. Signature verification: at least one of Response-level or Assertion-level
	//    signature must be present and valid.  For simplicity in this stdlib
	//    implementation, we verify whichever signature element is present using
	//    the IdP signing certificate.
	sigVerified := false
	if resp.Signature != nil {
		if verifyIDPSignature(resp.Signature, rawXML, cfg.IDPMetadata.SigningCertificate) == nil {
			sigVerified = true
		}
	}
	if !sigVerified && a.Signature != nil {
		if verifyIDPSignature(a.Signature, rawXML, cfg.IDPMetadata.SigningCertificate) == nil {
			sigVerified = true
		}
	}
	if !sigVerified {
		// No valid signature was established.  This covers both a configured
		// cert whose signature failed to verify AND the no-cert case, where
		// verifyIDPSignature now hard-refuses rather than fail-open (D124).
		return AssertionClaims{}, fmt.Errorf("%w: no valid signature found", ErrResponse)
	}

	// 8. Time conditions.
	now := time.Unix(nowUnix, 0).UTC()
	if a.Conditions.NotBefore != "" {
		nb, err := time.Parse(time.RFC3339, a.Conditions.NotBefore)
		if err == nil && now.Before(nb) {
			return AssertionClaims{}, fmt.Errorf("%w: assertion not yet valid (NotBefore=%s)", ErrResponse, a.Conditions.NotBefore)
		}
	}
	if a.Conditions.NotOnOrAfter != "" {
		noa, err := time.Parse(time.RFC3339, a.Conditions.NotOnOrAfter)
		if err == nil && !now.Before(noa) {
			return AssertionClaims{}, fmt.Errorf("%w: assertion expired (NotOnOrAfter=%s)", ErrResponse, a.Conditions.NotOnOrAfter)
		}
	}

	// SubjectConfirmation NotOnOrAfter.
	scNOA := a.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	if scNOA != "" {
		noa, err := time.Parse(time.RFC3339, scNOA)
		if err == nil && !now.Before(noa) {
			return AssertionClaims{}, fmt.Errorf("%w: subject confirmation expired (NotOnOrAfter=%s)", ErrResponse, scNOA)
		}
	}

	// 9. Extract claims.
	subject := strings.TrimSpace(a.Subject.NameID.Value)
	if subject == "" {
		return AssertionClaims{}, fmt.Errorf("%w: empty NameID", ErrResponse)
	}

	claims := AssertionClaims{
		Subject:      subject,
		SessionIdx:   a.AuthnStatement.SessionIndex,
		NotOnOrAfter: scNOA,
	}

	// Parse attributes.
	for _, attr := range a.AttributeStatement.Attributes {
		switch attr.Name {
		case "email",
			"urn:oid:1.2.840.113549.1.9.1",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
			if len(attr.Values) > 0 {
				claims.Email = strings.TrimSpace(attr.Values[0].Value)
			}
		case "displayName",
			"urn:oid:2.16.840.1.113730.3.1.241",
			"http://schemas.microsoft.com/identity/claims/displayname":
			if len(attr.Values) > 0 {
				claims.Name = strings.TrimSpace(attr.Values[0].Value)
			}
		case "groups",
			"memberOf",
			"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups":
			for _, v := range attr.Values {
				if g := strings.TrimSpace(v.Value); g != "" {
					claims.Groups = append(claims.Groups, g)
				}
			}
		}
	}

	return claims, nil
}

// verifyIDPSignature performs RSA-SHA256 signature verification against the IdP
// certificate.  It reconstructs the digest the way a conforming SAML IdP does:
// it locates the element referenced by the SignedInfo Reference URI, applies the
// enveloped-signature transform (removing the ds:Signature subtree) and
// Exclusive XML C14N (canonicalizeSignedElement), and takes SHA-256 of the
// resulting canonical octets.  The Reference DigestValue is verified against
// that canonical digest — NOT against a raw hash of the full document, so two
// byte-different-but-canonically-equivalent serializations verify identically
// while any tamper of the signed content is rejected.  The SignatureValue is
// then verified as an RSA-PKCS1v15 signature over that canonical digest.
//
// A nil certificate is a hard refusal (never fail-open) — the ratified D124
// obligation, round-5 packet sec4; the Config-load gate (Config.ValidateForACS,
// NewIDPMetadata, ParseIDPMetadata) additionally rejects that misconfiguration
// at startup.
func verifyIDPSignature(sig *samlSignature, docBytes []byte, cert *x509.Certificate) error {
	if sig == nil {
		return fmt.Errorf("nil signature element")
	}
	if cert == nil {
		// No IdP signing certificate configured.  A production SAML deployment
		// MUST NOT accept an unverified assertion, so this is a hard refusal
		// (never fail-open) — the ratified D124 obligation, round-5 packet sec4.
		return fmt.Errorf("no idp signing certificate configured: refusing to accept unverified assertion")
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("idp cert public key is not RSA")
	}

	// Canonicalize the referenced signed element (enveloped-signature transform
	// + Exclusive C14N) and digest the canonical octets.
	canon, err := canonicalizeSignedElement(docBytes, sig.SignedInfo.Reference.URI)
	if err != nil {
		return fmt.Errorf("canonicalize signed element: %w", err)
	}
	computedDigest := sha256.Sum256(canon)

	// The DigestValue must match the SHA-256 of the canonicalized element.
	digestBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig.SignedInfo.Reference.DigestValue))
	if err != nil {
		return fmt.Errorf("decode digest value: %w", err)
	}
	if len(digestBytes) != sha256.Size {
		return fmt.Errorf("unexpected digest length %d", len(digestBytes))
	}
	var gotDigest [sha256.Size]byte
	copy(gotDigest[:], digestBytes)
	if gotDigest != computedDigest {
		return fmt.Errorf("digest value mismatch")
	}

	// Verify the SignatureValue over the canonical digest.
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig.SignatureValue))
	if err != nil {
		return fmt.Errorf("decode signature value: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, computedDigest[:], sigBytes); err != nil {
		return fmt.Errorf("signature invalid: %w", err)
	}
	return nil
}

// canonicalizeSignedElement returns the Exclusive-C14N canonical octets of the
// element referenced by refURI within docBytes, with the enveloped-signature
// transform applied (any ds:Signature subtree inside the referenced element is
// removed before canonicalization).
//
// refURI is a SAML Reference URI: "" (or "#") denotes the whole document (the
// root element); "#id" denotes the element carrying ID="id".  This is a
// stdlib-only, prefix-independent canonicalizer built on encoding/xml's
// namespace-resolving tokenizer: element and attribute names are emitted in
// resolved {namespace-uri}local form (so a prefix rename or a redundant xmlns
// declaration is canonically invisible), namespace-declaration attributes are
// dropped, the remaining attributes are sorted by (namespace, local), empty
// elements are expanded to start/end tag pairs, and text/attribute octets are
// canonically escaped.  Two byte-different-but-canonically-equivalent
// serializations of the signed element therefore produce identical octets and
// hence an identical digest, while any change to signed content changes them.
//
// If the referenced element is not found the canonical octets are empty; a
// downstream digest comparison then fails closed (an attacker cannot forge a
// matching DigestValue + IdP signature over the empty canonicalization).
func canonicalizeSignedElement(docBytes []byte, refURI string) ([]byte, error) {
	refID := strings.TrimPrefix(strings.TrimSpace(refURI), "#")
	dec := xml.NewDecoder(bytes.NewReader(docBytes))
	var buf bytes.Buffer
	depth := 0        // absolute element nesting depth (root == 1)
	targetDepth := -1 // depth of the referenced element once found
	skipDepth := -1   // depth of a ds:Signature subtree being skipped
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tokenize: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if targetDepth == -1 && isSignedTarget(t, refID, depth) {
				targetDepth = depth
			}
			if targetDepth != -1 && depth >= targetDepth {
				if skipDepth == -1 && t.Name.Local == "Signature" {
					// Enveloped-signature transform: elide the Signature subtree.
					skipDepth = depth
				}
				if skipDepth == -1 {
					c14nWriteStart(&buf, t)
				}
			}
		case xml.EndElement:
			if targetDepth != -1 && depth >= targetDepth {
				if skipDepth != -1 {
					if depth == skipDepth {
						skipDepth = -1
					}
				} else {
					buf.WriteString("</")
					buf.WriteString(c14nName(t.Name))
					buf.WriteByte('>')
				}
			}
			if depth == targetDepth {
				// Reached the end of the referenced element: done.
				return buf.Bytes(), nil
			}
			depth--
		case xml.CharData:
			if targetDepth != -1 && depth >= targetDepth && skipDepth == -1 {
				c14nWriteText(&buf, []byte(t))
			}
		}
	}
	return buf.Bytes(), nil
}

// isSignedTarget reports whether t is the element referenced by refID.  An empty
// refID (whole-document reference) matches the root element (depth == 1);
// otherwise it matches the element carrying an ID attribute equal to refID.
func isSignedTarget(t xml.StartElement, refID string, depth int) bool {
	if refID == "" {
		return depth == 1
	}
	for _, a := range t.Attr {
		if a.Name.Local == "ID" && a.Value == refID {
			return true
		}
	}
	return false
}

// c14nName renders an XML name in resolved {namespace-uri}local form (Clark
// notation), or bare local when unqualified — making canonicalization
// independent of the prefix chosen for a namespace.
func c14nName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return "{" + n.Space + "}" + n.Local
}

// isNamespaceDecl reports whether a is an xmlns / xmlns:prefix declaration
// attribute (which Exclusive C14N handles via the resolved names, so it is
// dropped from the canonical serialization here).
func isNamespaceDecl(a xml.Attr) bool {
	if a.Name.Space == "xmlns" || a.Name.Space == "http://www.w3.org/2000/xmlns/" {
		return true
	}
	if a.Name.Space == "" && a.Name.Local == "xmlns" {
		return true
	}
	return false
}

// c14nWriteStart writes the canonical start tag for t: resolved name, namespace
// declarations dropped, remaining attributes sorted by (namespace, local).
func c14nWriteStart(buf *bytes.Buffer, t xml.StartElement) {
	buf.WriteByte('<')
	buf.WriteString(c14nName(t.Name))
	attrs := make([]xml.Attr, 0, len(t.Attr))
	for _, a := range t.Attr {
		if isNamespaceDecl(a) {
			continue
		}
		attrs = append(attrs, a)
	}
	sort.SliceStable(attrs, func(i, j int) bool {
		if attrs[i].Name.Space != attrs[j].Name.Space {
			return attrs[i].Name.Space < attrs[j].Name.Space
		}
		return attrs[i].Name.Local < attrs[j].Name.Local
	})
	for _, a := range attrs {
		buf.WriteByte(' ')
		buf.WriteString(c14nName(a.Name))
		buf.WriteString(`="`)
		c14nWriteAttrValue(buf, a.Value)
		buf.WriteByte('"')
	}
	buf.WriteByte('>')
}

// c14nWriteText writes canonical character-data octets (C14N text escaping).
func c14nWriteText(buf *bytes.Buffer, s []byte) {
	for _, b := range s {
		switch b {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		case '>':
			buf.WriteString("&gt;")
		case '\r':
			buf.WriteString("&#xD;")
		default:
			buf.WriteByte(b)
		}
	}
}

// c14nWriteAttrValue writes a canonical attribute value (C14N attribute-value
// escaping).
func c14nWriteAttrValue(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		case '"':
			buf.WriteString("&quot;")
		case '\t':
			buf.WriteString("&#x9;")
		case '\n':
			buf.WriteString("&#xA;")
		case '\r':
			buf.WriteString("&#xD;")
		default:
			buf.WriteByte(s[i])
		}
	}
}
