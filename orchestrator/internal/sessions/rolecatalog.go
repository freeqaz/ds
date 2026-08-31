package sessions

// rolecatalog.go is the M0 ORG-CATALOG-backed RoleResolver (doc 18 §4/§7): it
// installs behind the SAME steps-1–2 RoleResolver seam (roleref.go) the v0
// DefaultRoleResolver occupies, but resolves the FULL checked-in role catalog
// (roles/*.yaml) instead of only the recorded default — WITHOUT changing the seam
// shape (the precedent roleref.go names: "doc 18 installs the real org-catalog
// resolver behind this same seam WITHOUT changing this shape"). v0 read the
// recorded default with a fixed content-hash marker; this reads every built-in
// role and computes the REAL `role_content_hash` (roles/SCHEMA.md rule 5).
//
// ONE CANONICALIZATION SPEC, NOT TWO (roles/SCHEMA.md rule 5, doc 15 OQ3 / doc 13
// OQ2). The role_content_hash rides the SAME canonical-serialization machinery the
// PolicySnapshot content_hash uses: nftbridge.CanonicalHash (produce-once RFC 8785
// (JCS) canonical JSON, SHA-256 over the exact bytes — the orch8 canonicalizer the
// doc 18 role-document golden fixture proves). The role's canonical document is the
// nftbridge.Value tree CanonicalRoleDocumentValue builds (rolecanonical.go); the
// hash is the hex of those bytes. The identity/mint-side CatalogRoleTemplateResolver
// agrees on the SAME hash for the same role because both read the same committed
// roles/content-hash-goldens.json, which the orchestrator side anchors to the
// nftbridge-computed bytes (the cross-module agreement test).
//
// NOT THE ROLE ENGINE (the same fence roleref.go draws). This resolver RESOLVES +
// PINS; role semantics, authority, lifecycle, and the catalog WRITE path live in
// doc 18 and the dataplane policy-core role validator. This is the read-side M0
// catalog: parse the checked-in YAML, project the pinned identity + the widening
// posture, hand back a RoleResolution. Synthetic catalog only (D50): the built-in
// roles/*.yaml, no live org catalog.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CatalogRole is one parsed catalog entry — the projection of a roles/*.yaml the
// steps-1–2 resolver needs: the pinned identity (name, version, content_hash), the
// recorded default flag, and the widening posture (the §9 widening-gate inputs).
// It carries NO credential material (D39) — the scope_template lives mint-side; this
// projection is identity + the §9 widening posture only.
type CatalogRole struct {
	Name        string
	Version     string
	ContentHash string // role_content_hash — nftbridge JCS canonical (roles/SCHEMA.md rule 5)
	// Widenings is the role's UNRATIFIED widening requests (allowlist entries beyond
	// the org envelope, pack-family tier flips — doc 18 §9). Empty for a role that
	// requests no widening. When non-empty AND not WideningsRatified, the create
	// proceeds with them inert + a logged warning (the widening-gate row).
	Widenings []string
	// WideningsRatified is whether this role version's widened envelope is org-ratified
	// (the actor-recorded catalog act, doc 18 §9). The built-in catalog ships every
	// role UNRATIFIED (no role version is org-ratified at M0 — ratification is an org
	// admin act, not a checked-in fact), so a built-in role with widenings rides inert.
	WideningsRatified bool
}

// CatalogRoleResolver is the M0 org-catalog-backed RoleResolver: it resolves a
// requested role_ref against a fixed set of parsed CatalogRoles (the checked-in
// roles/*.yaml). It satisfies the roleref.go RoleResolver seam unchanged.
//
// DefaultName/DefaultVersion name the recorded current default (`default@<current>`)
// the absent-role_ref posture resolves to (doc 18 §7). Resolve recognizes a role by
// NAME (any explicit version that does not match the catalog entry's version is
// unknown — M0 pins the recorded current version of each role, the historical-version
// lookup is the live catalog's, not the built-in set's).
type CatalogRoleResolver struct {
	byName      map[string]CatalogRole
	defaultName string
}

// NewCatalogRoleResolver builds a resolver over the given catalog roles, keyed by
// name. A duplicate role name is rejected (the catalog is a set keyed by name). The
// defaultName MUST name a role present in the set (the recorded default must resolve).
func NewCatalogRoleResolver(roles []CatalogRole, defaultName string) (*CatalogRoleResolver, error) {
	byName := make(map[string]CatalogRole, len(roles))
	for _, r := range roles {
		if r.Name == "" {
			return nil, fmt.Errorf("sessions: catalog role with empty name")
		}
		if r.Version == "" || r.ContentHash == "" {
			return nil, fmt.Errorf("sessions: catalog role %q has an incomplete pin (version=%q content_hash=%q)", r.Name, r.Version, r.ContentHash)
		}
		if _, dup := byName[r.Name]; dup {
			return nil, fmt.Errorf("sessions: duplicate catalog role name %q", r.Name)
		}
		byName[r.Name] = r
	}
	if defaultName == "" {
		defaultName = defaultRoleName
	}
	if _, ok := byName[defaultName]; !ok {
		return nil, fmt.Errorf("sessions: recorded default role %q absent from the catalog", defaultName)
	}
	return &CatalogRoleResolver{byName: byName, defaultName: defaultName}, nil
}

// Resolve resolves a NON-EMPTY requested ref against the catalog (roleref.go seam).
// A name not in the catalog is unknown (ok=false → structural refusal). An explicit
// `<name>@<version>` whose version does not match the catalog entry is unknown (M0
// pins the recorded current version). A bare name (no `@`) resolves the recorded
// current version of that role.
func (c *CatalogRoleResolver) Resolve(_ context.Context, ref string) (RoleResolution, bool, error) {
	name, version := splitRoleRef(ref)
	role, ok := c.byName[name]
	if !ok {
		return RoleResolution{}, false, nil
	}
	if version != "" && version != role.Version {
		// An explicit historical/other version the M0 built-in set does not carry.
		return RoleResolution{}, false, nil
	}
	return roleToResolution(role), true, nil
}

// Default returns the recorded current default (`default@<current>`) — the explicit,
// auditable default-role pin for the absent-role_ref posture (doc 18 §7). It never
// faults: the recorded default is validated present at construction.
func (c *CatalogRoleResolver) Default(_ context.Context) (RoleResolution, error) {
	role, ok := c.byName[c.defaultName]
	if !ok {
		return RoleResolution{}, fmt.Errorf("sessions: catalog missing recorded default %q", c.defaultName)
	}
	return roleToResolution(role), nil
}

// roleToResolution projects a CatalogRole into the seam's RoleResolution.
func roleToResolution(r CatalogRole) RoleResolution {
	res := RoleResolution{
		Name:              r.Name,
		Version:           r.Version,
		ContentHash:       r.ContentHash,
		WideningsRatified: r.WideningsRatified,
	}
	if len(r.Widenings) > 0 {
		res.Widenings = append([]string(nil), r.Widenings...)
		sort.Strings(res.Widenings)
	}
	return res
}

// compile-time assertion: the catalog resolver satisfies the steps-1–2 seam.
var _ RoleResolver = (*CatalogRoleResolver)(nil)

// LoadCatalogRoles reads every role/*.yaml in dir into a CatalogRole, computing the
// role_content_hash via the shared nftbridge JCS path (roles/SCHEMA.md rule 5). It
// is the M0 catalog loader: the checked-in roles/ tree IS the catalog (synthetic,
// D50 — no live org catalog). The built-in roles ship UNRATIFIED (no role version is
// org-ratified at M0), so a role with widenings is returned with WideningsRatified
// false (it rides inert at create). A malformed role file is a hard error (the
// catalog refuses to load a role it cannot pin).
func LoadCatalogRoles(dir string) ([]CatalogRole, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("sessions: read roles dir %q: %w", dir, err)
	}
	var roles []CatalogRole
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("sessions: read role %q: %w", e.Name(), err)
		}
		doc, err := parseRoleYAML(string(body))
		if err != nil {
			return nil, fmt.Errorf("sessions: parse role %q: %w", e.Name(), err)
		}
		_, hashHex := canonicalRoleHashHex(doc)
		roles = append(roles, CatalogRole{
			Name:        doc.Name,
			Version:     doc.Version,
			ContentHash: hashHex,
			Widenings:   doc.widenings(),
			// M0: no built-in role version is org-ratified (ratification is an org-admin
			// catalog act, doc 18 §9, never a checked-in fact).
			WideningsRatified: false,
		})
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("sessions: no role/*.yaml found in %q", dir)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	return roles, nil
}

// NewCatalogRoleResolverFromDir is the M0 wiring convenience: load the checked-in
// roles/ catalog and build the resolver with `default` as the recorded default.
func NewCatalogRoleResolverFromDir(dir string) (*CatalogRoleResolver, error) {
	roles, err := LoadCatalogRoles(dir)
	if err != nil {
		return nil, err
	}
	return NewCatalogRoleResolver(roles, defaultRoleName)
}

// CatalogScopeTemplate is the read-path projection of a role's credential-scope
// template (roles/SCHEMA.md axis (d) / rule 4; doc 18 §8). It is a TEMPLATE, never
// credential material (D39) — `Services` are org registry KEYS, `Mode` is the
// read-only|read-write strawman string. The null-vs-present boundary is carried by
// CatalogRoleDocument.ScopeTemplatePresent, NOT by this struct being nil.
type CatalogScopeTemplate struct {
	Services []string
	Mode     string
}

// CatalogRoleDocument is the FULL read-path projection of one checked-in role/v0
// document — the catalog READ API's (ListRoles/GetRole, doc 18 §6) view of a role.
// It carries the pinned identity triple (doc 18 §7) + ALL FIVE composition axes
// (doc 18 §2) as REFERENCES + the credential TEMPLATE (never material, D39). It is
// the orchestrator-side source the control-plane RoleCatalogService projects onto
// the dreamserpent.roles.v1.Role wire message. The hashed projection
// (ContentHash) is exactly roles/SCHEMA.md rule 5's; the non-hashed axes
// (Description/ImageLayers/Skills/RuntimeOverlayRef) are surfaced for inspection.
type CatalogRoleDocument struct {
	Name          string
	Version       string
	ContentHash   string // role_content_hash (nftbridge JCS canonical, rule 5; lowercase hex)
	SchemaVersion string
	Description   string

	ImageLayers []string // axis (a) — content-addressed tool-layer refs (refs only, rule 1)
	Skills      []string // axis (b) — skill-bundle refs (strawman; OQ2 named gap)

	Posture      string   // axis (c) — locked|standard|open
	PackFamilies []string // axis (c) — tier-flip requests (widening posture; §9)
	Allowlist    []string // axis (c) — extra domain entries (widening posture; §9)

	// ScopeTemplatePresent distinguishes `scope_template: null` (false → no
	// narrowing, full envelope — the `default` role) from a present template (true
	// → ScopeTemplate set, services possibly empty — the `researcher` role). The
	// load-bearing doc 18 §8 boundary the content_hash preserves (rule 5).
	ScopeTemplatePresent bool
	ScopeTemplate        CatalogScopeTemplate // axis (d) — valid only when ScopeTemplatePresent

	RuntimeOverlayRef string // axis (e) — opaque overlay ref (D38/D20); empty for null

	// Widenings is the role's UNRATIFIED widening requests (allowlist entries +
	// pack-family tier flips beyond the org envelope, doc 18 §9). Empty for a role
	// that requests none.
	Widenings []string
	// WideningsRatified is whether this role version's widened envelope is
	// org-ratified (doc 18 §9). The built-in catalog ships every role UNRATIFIED,
	// so at M0 this is false for every built-in.
	WideningsRatified bool
}

// LoadCatalogRoleDocuments reads every role/*.yaml in dir into a full read-path
// CatalogRoleDocument, computing the role_content_hash via the same shared
// nftbridge JCS path the resolver uses (roles/SCHEMA.md rule 5 — ONE spec). It is
// the M0 read-path catalog loader for the control-plane RoleCatalogService; the
// built-in roles ship UNRATIFIED. Documents are returned sorted by name (a stable
// ListRoles ordering). A malformed role file is a hard error (the catalog refuses
// to surface a role it cannot pin).
func LoadCatalogRoleDocuments(dir string) ([]CatalogRoleDocument, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("sessions: read roles dir %q: %w", dir, err)
	}
	var docs []CatalogRoleDocument
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("sessions: read role %q: %w", e.Name(), err)
		}
		doc, err := parseRoleYAML(string(body))
		if err != nil {
			return nil, fmt.Errorf("sessions: parse role %q: %w", e.Name(), err)
		}
		_, hashHex := canonicalRoleHashHex(doc)
		cd := CatalogRoleDocument{
			Name:          doc.Name,
			Version:       doc.Version,
			ContentHash:   hashHex,
			SchemaVersion: doc.SchemaVersion,
			Description:   doc.Description,
			ImageLayers:   append([]string(nil), doc.ImageLayers...),
			Skills:        append([]string(nil), doc.SkillsInstall...),
			Posture:       doc.Posture,
			PackFamilies:  append([]string(nil), doc.PackFamilies...),
			Allowlist:     append([]string(nil), doc.Allowlist...),

			ScopeTemplatePresent: doc.ScopeTemplatePresent,
			RuntimeOverlayRef:    doc.RuntimeOverlayRef,
			Widenings:            doc.widenings(),
			// M0: no built-in role version is org-ratified (doc 18 §9).
			WideningsRatified: false,
		}
		if doc.ScopeTemplatePresent {
			cd.ScopeTemplate = CatalogScopeTemplate{
				Services: append([]string(nil), doc.ScopeServices...),
				Mode:     doc.ScopeMode,
			}
		}
		docs = append(docs, cd)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("sessions: no role/*.yaml found in %q", dir)
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].Name < docs[j].Name })
	return docs, nil
}

// DefaultCatalogRoleName is the recorded default role name (doc 18 §7) the
// read-path catalog names as `default_role` in ListRoles and resolves an absent
// GetRole ref to. It is the exported form of the package's defaultRoleName so the
// control-plane RoleCatalogService names one default across the seam.
const DefaultCatalogRoleName = defaultRoleName
