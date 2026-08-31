// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"fmt"
	"sync"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/oidc"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/saml"
)

// ErrOrgNotFound is returned when org_id is not registered.
var ErrOrgNotFound = errors.New("service: org not found in IdP registry")

// Protocol is the auth protocol for an org's IdP.
type Protocol string

const (
	ProtocolOIDC Protocol = "oidc"
	ProtocolSAML Protocol = "saml"
)

// OrgConfig holds the resolved IdP configuration for one organisation.
type OrgConfig struct {
	Protocol   Protocol
	OIDCConfig *oidc.Config // set when Protocol==oidc
	SAMLConfig *saml.Config // set when Protocol==saml
}

// Registry maps org_id → OrgConfig. Thread-safe; built at service startup.
type Registry struct {
	mu   sync.RWMutex
	orgs map[string]OrgConfig
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{orgs: make(map[string]OrgConfig)}
}

// RegisterOIDC adds an OIDC IdP config for orgID. Overwrites any existing entry.
func (r *Registry) RegisterOIDC(orgID string, cfg oidc.Config) error {
	if orgID == "" {
		return fmt.Errorf("service: RegisterOIDC: org_id required")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("service: RegisterOIDC: %w", err)
	}
	r.mu.Lock()
	r.orgs[orgID] = OrgConfig{Protocol: ProtocolOIDC, OIDCConfig: &cfg}
	r.mu.Unlock()
	return nil
}

// RegisterSAML adds a SAML IdP config for orgID. Overwrites any existing entry.
func (r *Registry) RegisterSAML(orgID string, cfg saml.Config) error {
	if orgID == "" {
		return fmt.Errorf("service: RegisterSAML: org_id required")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("service: RegisterSAML: %w", err)
	}
	r.mu.Lock()
	r.orgs[orgID] = OrgConfig{Protocol: ProtocolSAML, SAMLConfig: &cfg}
	r.mu.Unlock()
	return nil
}

// Lookup returns the OrgConfig for orgID or ErrOrgNotFound.
func (r *Registry) Lookup(orgID string) (OrgConfig, error) {
	r.mu.RLock()
	cfg, ok := r.orgs[orgID]
	r.mu.RUnlock()
	if !ok {
		return OrgConfig{}, fmt.Errorf("%w: %q", ErrOrgNotFound, orgID)
	}
	return cfg, nil
}
