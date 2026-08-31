// SPDX-License-Identifier: Apache-2.0
package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

// syntheticConfig builds a minimal Config with a freshly-generated RSA key and
// a no-certificate IdP metadata stub, sufficient for unit testing the SP-side
// AuthnRequest generation paths.  Synthetic fixtures only (D50).
func syntheticConfig(t *testing.T) Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return Config{
		OrgID:      "org-synthetic-saml-test",
		SPEntityID: "https://platform.example.com/saml/metadata",
		ACSURL:     "https://platform.example.com/saml/acs",
		SigningKey: key,
		IDPMetadata: &IDPMetadata{
			EntityID: "https://idp.example.com/saml/metadata",
			SSOURL:   "https://idp.example.com/saml/sso",
		},
	}
}

func TestNewAuthnRequest_NonEmptyIDAndIssueInstant(t *testing.T) {
	cfg := syntheticConfig(t)
	req, err := NewAuthnRequest(cfg)
	if err != nil {
		t.Fatalf("NewAuthnRequest: %v", err)
	}
	if req.ID == "" {
		t.Error("AuthnRequest.ID must not be empty")
	}
	if req.IssueInstant == "" {
		t.Error("AuthnRequest.IssueInstant must not be empty")
	}
	// ID must be underscore-prefixed (RFC 4122 MUST NOT start with digit).
	if req.ID[0] != '_' {
		t.Errorf("AuthnRequest.ID must start with underscore, got %q", req.ID[:1])
	}
}

func TestGenerateRelayState_NonEmptyBase64URL(t *testing.T) {
	rs, err := GenerateRelayState()
	if err != nil {
		t.Fatalf("GenerateRelayState: %v", err)
	}
	if rs == "" {
		t.Error("relay state must not be empty")
	}
	// base64url characters: A-Z, a-z, 0-9, -, _  (no padding '=')
	for _, c := range rs {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			t.Errorf("relay state contains non-base64url character %q in %q", c, rs)
			break
		}
	}
}

func TestBuildXML_ContainsSamlpAuthnRequest(t *testing.T) {
	cfg := syntheticConfig(t)
	req, err := NewAuthnRequest(cfg)
	if err != nil {
		t.Fatalf("NewAuthnRequest: %v", err)
	}
	xmlBytes, err := BuildXML(req)
	if err != nil {
		t.Fatalf("BuildXML: %v", err)
	}
	if len(xmlBytes) == 0 {
		t.Fatal("BuildXML returned empty bytes")
	}
	xmlStr := string(xmlBytes)
	if !strings.Contains(xmlStr, "samlp:AuthnRequest") {
		t.Errorf("BuildXML output does not contain %q; got:\n%s", "samlp:AuthnRequest", xmlStr)
	}
}

func TestBuildXML_ContainsExpectedFields(t *testing.T) {
	cfg := syntheticConfig(t)
	req, err := NewAuthnRequest(cfg)
	if err != nil {
		t.Fatalf("NewAuthnRequest: %v", err)
	}
	xmlBytes, err := BuildXML(req)
	if err != nil {
		t.Fatalf("BuildXML: %v", err)
	}
	xmlStr := string(xmlBytes)

	checks := []struct {
		label string
		want  string
	}{
		{"SP entity ID / Issuer", cfg.SPEntityID},
		{"ACS URL", cfg.ACSURL},
		{"IdP SSO URL / Destination", cfg.IDPMetadata.SSOURL},
		{"SAML protocol namespace", "urn:oasis:names:tc:SAML:2.0:protocol"},
		{"SAML assertion namespace", "urn:oasis:names:tc:SAML:2.0:assertion"},
		{"AuthnRequest ID", req.ID},
		{"IssueInstant", req.IssueInstant},
	}
	for _, c := range checks {
		if !strings.Contains(xmlStr, c.want) {
			t.Errorf("BuildXML output missing %s (%q)", c.label, c.want)
		}
	}
}

func TestSignXML_ProducesSignedDocument(t *testing.T) {
	cfg := syntheticConfig(t)
	req, err := NewAuthnRequest(cfg)
	if err != nil {
		t.Fatalf("NewAuthnRequest: %v", err)
	}
	xmlBytes, err := BuildXML(req)
	if err != nil {
		t.Fatalf("BuildXML: %v", err)
	}
	signed, err := SignXML(xmlBytes, cfg.SigningKey, cfg.SigningCert)
	if err != nil {
		t.Fatalf("SignXML: %v", err)
	}
	if len(signed) == 0 {
		t.Fatal("SignXML returned empty bytes")
	}
	signedStr := string(signed)
	if !strings.Contains(signedStr, "ds:Signature") {
		t.Error("signed document does not contain ds:Signature element")
	}
	if !strings.Contains(signedStr, "ds:SignatureValue") {
		t.Error("signed document does not contain ds:SignatureValue")
	}
	if !strings.Contains(signedStr, "ds:DigestValue") {
		t.Error("signed document does not contain ds:DigestValue")
	}
}

func TestConfigValidate_MissingFields(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		name   string
		cfg    Config
		wantOK bool
	}{
		{
			name: "valid",
			cfg: Config{
				OrgID: "org", SPEntityID: "sp", ACSURL: "acs",
				SigningKey:  key,
				IDPMetadata: &IDPMetadata{EntityID: "idp", SSOURL: "sso"},
			},
			wantOK: true,
		},
		{"missing org_id", Config{SPEntityID: "sp", ACSURL: "acs", SigningKey: key, IDPMetadata: &IDPMetadata{}}, false},
		{"missing sp_entity_id", Config{OrgID: "org", ACSURL: "acs", SigningKey: key, IDPMetadata: &IDPMetadata{}}, false},
		{"missing acs_url", Config{OrgID: "org", SPEntityID: "sp", SigningKey: key, IDPMetadata: &IDPMetadata{}}, false},
		{"missing signing_key", Config{OrgID: "org", SPEntityID: "sp", ACSURL: "acs", IDPMetadata: &IDPMetadata{}}, false},
		{"missing idp_metadata", Config{OrgID: "org", SPEntityID: "sp", ACSURL: "acs", SigningKey: key}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantOK && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
			if !tc.wantOK && err == nil {
				t.Error("Validate() = nil, want error")
			}
		})
	}
}
