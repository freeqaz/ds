// SPDX-License-Identifier: Apache-2.0
package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

var ErrConfig = errors.New("saml: invalid config")
var ErrResponse = errors.New("saml: response validation failed")

// Config is the SAML SP configuration for one org (D124).
type Config struct {
	OrgID       string            // identifies the org / IdP config row
	SPEntityID  string            // SP entityID (e.g. https://platform.example.com/saml/metadata)
	ACSURL      string            // Assertion Consumer Service URL (where IdP POSTs the SAMLResponse)
	SigningKey  *rsa.PrivateKey   // SP signing key for AuthnRequests
	SigningCert *x509.Certificate // SP certificate (embedded in metadata)
	IDPMetadata *IDPMetadata      // resolved from IdP metadata URL
}

func (c Config) Validate() error {
	if c.OrgID == "" {
		return fmt.Errorf("%w: org_id required", ErrConfig)
	}
	if c.SPEntityID == "" {
		return fmt.Errorf("%w: sp_entity_id required", ErrConfig)
	}
	if c.ACSURL == "" {
		return fmt.Errorf("%w: acs_url required", ErrConfig)
	}
	if c.SigningKey == nil {
		return fmt.Errorf("%w: signing_key required", ErrConfig)
	}
	if c.IDPMetadata == nil {
		return fmt.Errorf("%w: idp_metadata required", ErrConfig)
	}
	return nil
}

// ValidateForACS validates cfg for use on the Assertion Consumer Service path,
// which — beyond the base Validate() requirements — REQUIRES a configured IdP
// signing certificate.  A deployment missing the cert can never verify any
// assertion, so this fails loudly at Config load/assembly (startup) rather than
// silently at first login, complementing the verify-time hard refusal in
// verifyIDPSignature (D124; round-5 packet sec4).
func (c Config) ValidateForACS() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.IDPMetadata.SigningCertificate == nil {
		return fmt.Errorf("%w: idp_metadata.signing_certificate required to verify assertions (refusing to start unverified)", ErrConfig)
	}
	return nil
}

// IDPMetadata is the minimal set of fields consumed from IdP SAML metadata.
type IDPMetadata struct {
	EntityID           string            // IdP entityID
	SSOURL             string            // IdP SSO HTTP-POST binding URL
	SigningCertificate *x509.Certificate // IdP assertion-signing certificate
}
