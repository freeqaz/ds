// SPDX-License-Identifier: Apache-2.0

package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
)

// spMetadata is the XML structure for SAML 2.0 SP metadata (SAMLMetadata schema).
type spMetadata struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string   `xml:"entityID,attr"`
	SPSSO    spssodescriptor
}

type spssodescriptor struct {
	XMLName                  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	AuthnRequestsSigned      bool     `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned     bool     `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnum      string   `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor            keyDescriptor
	AssertionConsumerService acsService
}

type keyDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	Use     string   `xml:"use,attr"`
	KeyInfo keyInfo
}

type keyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data x509Data
}

type x509Data struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	Certificate string   `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type acsService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
	Index    int      `xml:"index,attr"`
}

// SPMetadataXML generates the SAML SP metadata XML document for the given Config.
// The IdP operator installs this document to configure the trust relationship.
func SPMetadataXML(cfg Config) ([]byte, error) {
	if cfg.SigningCert == nil {
		return nil, fmt.Errorf("saml: signing certificate required for metadata")
	}
	certB64 := certBase64(cfg.SigningCert)
	meta := spMetadata{
		EntityID: cfg.SPEntityID,
		SPSSO: spssodescriptor{
			AuthnRequestsSigned:  true,
			WantAssertionsSigned: true,
			ProtocolSupportEnum:  "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptor: keyDescriptor{
				Use: "signing",
				KeyInfo: keyInfo{
					X509Data: x509Data{Certificate: certB64},
				},
			},
			AssertionConsumerService: acsService{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				Location: cfg.ACSURL,
				Index:    1,
			},
		},
	}
	out, err := xml.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal SP metadata: %w", err)
	}
	return append([]byte(xml.Header), out...), nil
}

// MetadataHandler returns an http.Handler that serves the SP metadata XML.
// Mount at /auth/saml/metadata (GET).
func MetadataHandler(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := SPMetadataXML(cfg)
		if err != nil {
			http.Error(w, "failed to build SP metadata", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}

// certBase64 returns the DER-encoded certificate as base64 (no PEM headers).
func certBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// --- IdP metadata assembly (D124) ---
//
// A misconfigured IdP trust record with NO signing certificate can never verify
// any assertion.  Both assembly paths below reject that at Config load/assembly
// time so a deployment fails loudly at startup, complementing the verify-time
// hard refusal in verifyIDPSignature (round-5 packet sec4).

// idpEntityDescriptor is the minimal IdP-side SAML 2.0 metadata structure.
type idpEntityDescriptor struct {
	XMLName  xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string           `xml:"entityID,attr"`
	IDPSSO   idpSSODescriptor `xml:"IDPSSODescriptor"`
}

type idpSSODescriptor struct {
	XMLName        xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	KeyDescriptors []keyDescriptor `xml:"KeyDescriptor"`
	SSOServices    []ssoService    `xml:"SingleSignOnService"`
}

type ssoService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// NewIDPMetadata assembles a validated IDPMetadata, REJECTING a nil signing
// certificate (or empty entityID) at construction time so a misconfigured
// deployment cannot produce a Config that silently accepts unverified
// assertions.
func NewIDPMetadata(entityID, ssoURL string, signingCert *x509.Certificate) (*IDPMetadata, error) {
	if entityID == "" {
		return nil, fmt.Errorf("%w: idp entity_id required", ErrConfig)
	}
	if signingCert == nil {
		return nil, fmt.Errorf("%w: idp signing certificate required (refusing to assemble a config that cannot verify assertions)", ErrConfig)
	}
	return &IDPMetadata{
		EntityID:           entityID,
		SSOURL:             ssoURL,
		SigningCertificate: signingCert,
	}, nil
}

// ParseIDPMetadata parses an IdP SAML 2.0 metadata document and assembles a
// validated IDPMetadata.  It REQUIRES a signing certificate: metadata with no
// usable signing KeyDescriptor is rejected at load time (never assembled into a
// fail-open Config).
func ParseIDPMetadata(xmlBytes []byte) (*IDPMetadata, error) {
	var ed idpEntityDescriptor
	if err := xml.Unmarshal(xmlBytes, &ed); err != nil {
		return nil, fmt.Errorf("%w: parse idp metadata: %v", ErrConfig, err)
	}
	if ed.EntityID == "" {
		return nil, fmt.Errorf("%w: idp metadata missing entityID", ErrConfig)
	}

	var cert *x509.Certificate
	for _, kd := range ed.IDPSSO.KeyDescriptors {
		// use="signing" or an unspecified use is eligible; skip encryption keys.
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		raw := stripB64Whitespace(kd.KeyInfo.X509Data.Certificate)
		if raw == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: decode idp signing certificate: %v", ErrConfig, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: parse idp signing certificate: %v", ErrConfig, err)
		}
		cert = c
		break
	}
	if cert == nil {
		return nil, fmt.Errorf("%w: idp metadata has no signing certificate (refusing to assemble a config that cannot verify assertions)", ErrConfig)
	}

	var ssoURL string
	for _, s := range ed.IDPSSO.SSOServices {
		if s.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
			ssoURL = s.Location
			break
		}
		if ssoURL == "" {
			ssoURL = s.Location
		}
	}

	return &IDPMetadata{
		EntityID:           ed.EntityID,
		SSOURL:             ssoURL,
		SigningCertificate: cert,
	}, nil
}

// stripB64Whitespace removes ASCII whitespace so a PEM/base64 blob wrapped
// across lines in metadata decodes cleanly.
func stripB64Whitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}
