// SPDX-License-Identifier: Apache-2.0
package oidc

import (
	"errors"
	"fmt"
	"strings"
)

var ErrConfig = errors.New("oidc: invalid config")

// Config is the relying-party OIDC configuration for one org.
// All fields are required unless noted.
type Config struct {
	OrgID        string // identifies the org / IdP config row
	Issuer       string // OIDC issuer URL (e.g. https://accounts.google.com)
	ClientID     string // OAuth2 client_id registered with the IdP
	ClientSecret string // OAuth2 client_secret (not present for device-code with public clients)
	// RedirectURIs is the allowlist of redirect URIs for authz-code flows.
	RedirectURIs []string
	// GroupsClaim is the JWT claim name carrying group membership (default "groups").
	GroupsClaim string
}

func (c Config) Validate() error {
	if c.OrgID == "" {
		return fmt.Errorf("%w: org_id required", ErrConfig)
	}
	if c.Issuer == "" {
		return fmt.Errorf("%w: issuer required", ErrConfig)
	}
	if c.ClientID == "" {
		return fmt.Errorf("%w: client_id required", ErrConfig)
	}
	return nil
}

func (c Config) discoveryURL() string {
	return strings.TrimSuffix(c.Issuer, "/") + "/.well-known/openid-configuration"
}

func (c Config) groupsClaim() string {
	if c.GroupsClaim != "" {
		return c.GroupsClaim
	}
	return "groups"
}
