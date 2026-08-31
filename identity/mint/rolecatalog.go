// SPDX-License-Identifier: Apache-2.0

// rolecatalog.go is the M0 ORG-CATALOG-backed RoleTemplateResolver (doc 18 §8,
// doc 19 §11): it installs behind the SAME doc 19 §11 role-template hook the v0
// DefaultRoleTemplateResolver occupies (roletemplate.go), but resolves the FULL
// checked-in role catalog instead of only the recorded default — WITHOUT changing
// the consumer (MintGrantsScoped/IssueGrantsScoped key on the resolved
// RoleAttenuationTemplate, never on which resolver produced it, so the catalog
// successor needs no edit at the consumption site, doc 19 §11). v0 recognized only
// `default`; this resolves every built-in role's scope_template.
//
// ONE CONTENT_HASH ACROSS THE MODULE BOUNDARY (roles/SCHEMA.md rule 5). The
// role_content_hash is the orchestrator's concern (it pins the triple into the
// session record); identity/mint consumes the scope_template, not the hash. But the
// two MUST agree on ONE content_hash per role so a catalog update to the same
// (name, version) is the SAME distinct pin in BOTH trees. identity/mint is a
// SEPARATE Go module (GOWORK=off) and the only legal cross-tree import is
// proto/gen/go — so it CANNOT import the orchestrator's nftbridge canonicalizer.
// The single source both seams share is the committed roles/content-hash-goldens.json:
// the orchestrator side ANCHORS that file to its nftbridge-computed bytes
// (orchestrator TestCatalogContentHash_AnchoredToCanonicalBytes); identity/mint
// READS the same file. So both seams carry the byte-identical hash per role without
// re-implementing the JCS canonicalizer here (the byte-identity-precedent discipline
// the grantref-golden cross-module check already uses, grants_test.go).
//
// THE TEMPLATE IS THE GOLDEN'S scope dimension (doc 18 §8). The golden carries each
// role's scope_template presence + service ceiling (the orchestrator parsed them
// from the YAML and committed them alongside the hash); this resolver reads them
// straight into a RoleAttenuationTemplate. NULL template (scope_template: null) →
// nil Services (no narrowing, full envelope); present-but-empty services:[] → a
// non-nil empty Services (mints nothing) — the doc 18 §8 boundary preserved exactly
// as RoleScopeTemplateFrom expects. NEVER credential material (D39): service IDs +
// nothing else.
//
// Synthetic catalog only (D50): the committed golden over the checked-in roles/,
// no live org catalog.
package mint

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// CatalogRoleEntry is one parsed role from roles/content-hash-goldens.json — the
// fields identity/mint needs: the pinned identity (name/version/content_hash, for
// the cross-module agreement) and the scope_template dimension (presence + service
// ceiling, for the RoleAttenuationTemplate this resolver yields).
type CatalogRoleEntry struct {
	Name                 string
	Version              string
	ContentHash          string // role_content_hash — the SHARED canonical hash (rule 5)
	ScopeTemplatePresent bool   // false = scope_template null (no narrowing, full envelope)
	ScopeServices        []string
}

// Ref returns the canonical `<name>@<version>` form (doc 18 §7's recorded ref) —
// the key the spine's pinned role_ref carries into MintGrantsScoped.
func (e CatalogRoleEntry) Ref() string {
	if e.Version == "" {
		return e.Name
	}
	return e.Name + "@" + e.Version
}

// Template projects the entry's scope dimension into the doc 19 §11 seam record.
// NULL (scope_template: null) → nil Services (no narrowing); present services:[]
// (possibly empty) → a non-nil slice (empty = mints nothing) — exactly the boundary
// RoleScopeTemplateFrom keys on.
func (e CatalogRoleEntry) Template() RoleAttenuationTemplate {
	if !e.ScopeTemplatePresent {
		return RoleAttenuationTemplate{} // nil Services → no narrowing (full envelope)
	}
	svc := make([]string, len(e.ScopeServices)) // non-nil even when empty (mints nothing)
	copy(svc, e.ScopeServices)
	sort.Strings(svc)
	return RoleAttenuationTemplate{Services: svc}
}

// CatalogRoleTemplateResolver is the M0 catalog-backed RoleTemplateResolver: it
// resolves a role_ref against the entries loaded from the shared golden, yielding
// the role's scope_template (or ok=false for an unknown ref). It satisfies the
// doc 19 §11 hook unchanged. It additionally exposes ContentHash so the
// cross-module agreement test can assert identity/mint and the orchestrator carry
// the SAME role_content_hash per role.
type CatalogRoleTemplateResolver struct {
	byName    map[string]CatalogRoleEntry
	byVersion map[string]CatalogRoleEntry // keyed by "name@version"
}

// NewCatalogRoleTemplateResolver builds a resolver over the given entries, keyed by
// name (M0 pins the recorded current version of each role). A duplicate name is
// rejected (the catalog is a set keyed by name).
func NewCatalogRoleTemplateResolver(entries []CatalogRoleEntry) (*CatalogRoleTemplateResolver, error) {
	byName := make(map[string]CatalogRoleEntry, len(entries))
	byVersion := make(map[string]CatalogRoleEntry, len(entries))
	for _, e := range entries {
		if e.Name == "" {
			return nil, fmt.Errorf("mint: catalog role with empty name")
		}
		if _, dup := byName[e.Name]; dup {
			return nil, fmt.Errorf("mint: duplicate catalog role name %q", e.Name)
		}
		byName[e.Name] = e
		byVersion[e.Ref()] = e
	}
	return &CatalogRoleTemplateResolver{byName: byName, byVersion: byVersion}, nil
}

// Resolve is the doc 19 §11 hook: a role_ref → (template, ok). A bare name resolves
// the recorded current version; an explicit `name@version` resolves only when it
// matches the catalog entry's version (M0 pins the recorded current). An unknown ref
// is ok=false — NOT an error (fail-OPEN on the role axis is safe; the registry
// intersection is the floor, doc 19 §11).
func (c *CatalogRoleTemplateResolver) Resolve(roleRef string) (RoleAttenuationTemplate, bool) {
	if roleRef == "" {
		return RoleAttenuationTemplate{}, false
	}
	// Exact name@version match first.
	if e, ok := c.byVersion[roleRef]; ok {
		return e.Template(), true
	}
	name := roleNameOf(roleRef)
	if name == roleRef {
		// A bare name (no @version): resolve the recorded current.
		if e, ok := c.byName[name]; ok {
			return e.Template(), true
		}
		return RoleAttenuationTemplate{}, false
	}
	// An explicit name@version whose version did not match an entry: unknown (M0
	// pins the recorded current version, not an arbitrary requested one).
	return RoleAttenuationTemplate{}, false
}

// AsResolver adapts the catalog resolver to the bare RoleTemplateResolver func the
// consumer (MintGrantsScoped/IssueGrantsScoped) keys on — so the catalog installs
// behind the doc 19 §11 hook WITHOUT changing the consumer.
func (c *CatalogRoleTemplateResolver) AsResolver() RoleTemplateResolver {
	return c.Resolve
}

// ContentHash returns the role_content_hash for a role_ref (the SHARED canonical
// hash, rule 5) — the field the cross-module agreement test compares against the
// orchestrator's nftbridge-computed hash. Empty for an unknown ref.
func (c *CatalogRoleTemplateResolver) ContentHash(roleRef string) string {
	if e, ok := c.byVersion[roleRef]; ok {
		return e.ContentHash
	}
	if e, ok := c.byName[roleNameOf(roleRef)]; ok {
		return e.ContentHash
	}
	return ""
}

// Entries returns the loaded catalog entries (sorted by name), for the agreement
// test to walk the full set.
func (c *CatalogRoleTemplateResolver) Entries() []CatalogRoleEntry {
	out := make([]CatalogRoleEntry, 0, len(c.byName))
	for _, e := range c.byName {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// compile-time assertion: the catalog resolver's method satisfies the doc 19 §11
// hook signature.
var _ RoleTemplateResolver = (*CatalogRoleTemplateResolver)(nil).Resolve

// goldenSchema mirrors roles/content-hash-goldens.json (the single-source hash
// file the orchestrator anchors to its nftbridge canonical bytes). identity/mint
// READS it; it never writes it.
type goldenSchema struct {
	DefaultRole string `json:"default_role"`
	Roles       []struct {
		Name                 string   `json:"name"`
		Version              string   `json:"version"`
		ContentHash          string   `json:"content_hash"`
		ScopeTemplatePresent bool     `json:"scope_template_present"`
		ScopeServices        []string `json:"scope_services"`
	} `json:"roles"`
}

// LoadCatalogFromGolden reads roles/content-hash-goldens.json (at goldenPath) into
// catalog entries — the single source both seams share for the role_content_hash
// (rule 5) and the scope_template ceiling. It is the M0 catalog loader for the mint
// side (the orchestrator side loads from the YAML + anchors the golden; the mint
// side reads the anchored golden, never re-canonicalizing).
func LoadCatalogFromGolden(goldenPath string) ([]CatalogRoleEntry, error) {
	b, err := os.ReadFile(goldenPath)
	if err != nil {
		return nil, fmt.Errorf("mint: read role golden %q: %w", goldenPath, err)
	}
	var g goldenSchema
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, fmt.Errorf("mint: parse role golden %q: %w", goldenPath, err)
	}
	if len(g.Roles) == 0 {
		return nil, fmt.Errorf("mint: role golden %q has no roles", goldenPath)
	}
	out := make([]CatalogRoleEntry, 0, len(g.Roles))
	for _, r := range g.Roles {
		if r.Name == "" || r.Version == "" || r.ContentHash == "" {
			return nil, fmt.Errorf("mint: role golden entry %q has an incomplete pin", r.Name)
		}
		out = append(out, CatalogRoleEntry{
			Name:                 r.Name,
			Version:              r.Version,
			ContentHash:          r.ContentHash,
			ScopeTemplatePresent: r.ScopeTemplatePresent,
			ScopeServices:        r.ScopeServices,
		})
	}
	return out, nil
}

// NewCatalogResolverFromGolden is the M0 wiring convenience: load the shared golden
// and build the catalog-backed role-template resolver.
func NewCatalogResolverFromGolden(goldenPath string) (*CatalogRoleTemplateResolver, error) {
	entries, err := LoadCatalogFromGolden(goldenPath)
	if err != nil {
		return nil, err
	}
	return NewCatalogRoleTemplateResolver(entries)
}
