// SPDX-License-Identifier: Apache-2.0

// Tests for the M0 catalog-backed RoleTemplateResolver (rolecatalog.go) and the
// end-to-end STEP-5 JOIN it completes: a pinned role_ref → the catalog's
// scope_template → MintGrantsScoped narrows the grant set by intersection
// (doc 15 §4.1 step 5, doc 18 §8). The cross-module agreement on the SHARED
// role_content_hash (roles/SCHEMA.md rule 5) is asserted against the same committed
// roles/content-hash-goldens.json the orchestrator anchors to its nftbridge bytes.
// Synthetic catalog only (D50).
package mint

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

// goldenCatalogPath locates the shared role golden relative to the mint module's
// test cwd (identity/mint → ../../roles/content-hash-goldens.json).
var goldenCatalogPath = filepath.Join("..", "..", "roles", "content-hash-goldens.json")

func loadCatalogResolver(t *testing.T) *CatalogRoleTemplateResolver {
	t.Helper()
	c, err := NewCatalogResolverFromGolden(goldenCatalogPath)
	if err != nil {
		t.Fatalf("load catalog resolver: %v", err)
	}
	return c
}

// TestCatalogResolver_TemplatesFromGolden proves the catalog resolver yields each
// built-in role's scope_template from the shared golden, preserving the doc 18 §8
// null-vs-empty boundary: default = NULL (nil Services, full envelope), researcher =
// present-but-empty (non-nil empty Services, mints nothing), developer/
// security-engineer = present [github].
func TestCatalogResolver_TemplatesFromGolden(t *testing.T) {
	c := loadCatalogResolver(t)

	// default: known role, NO narrowing (nil Services).
	if tmpl, ok := c.Resolve("default@2026.06.11-v1"); !ok || tmpl.Services != nil {
		t.Fatalf("default must resolve to a null template (nil Services), got ok=%v tmpl=%+v", ok, tmpl)
	}
	// developer: present [github].
	if tmpl, ok := c.Resolve("developer@2026.06.11-v1"); !ok || !reflect.DeepEqual(tmpl.Services, []string{"github"}) {
		t.Fatalf("developer scope_template = %+v ok=%v, want services [github]", tmpl, ok)
	}
	// researcher: present but EMPTY (non-nil empty Services) — distinct from null.
	tmpl, ok := c.Resolve("researcher@2026.06.11-v1")
	if !ok {
		t.Fatal("researcher must resolve")
	}
	if tmpl.Services == nil {
		t.Fatal("researcher's present-but-empty services:[] must be a NON-NIL empty slice (distinct from null)")
	}
	if len(tmpl.Services) != 0 {
		t.Fatalf("researcher services = %v, want empty (mints nothing)", tmpl.Services)
	}
	// Unknown ref → ok=false (NOT an error).
	if _, ok := c.Resolve("ghost@9"); ok {
		t.Fatal("unknown ref must be ok=false")
	}
}

// TestStep5Join_PinToTemplateToScopedGrants is the headline end-to-end join: a
// PINNED role_ref (what the spine stamps onto the step-5 mint request) flows through
// the catalog resolver → the role scope_template → MintGrantsScoped, which narrows
// the issued grant set by intersection. Widening is impossible end to end (the
// scoped set is ⊆ the unscoped set for the same env). Non-strict path.
func TestStep5Join_PinToTemplateToScopedGrants(t *testing.T) {
	resolver := loadCatalogResolver(t).AsResolver()
	shim := newGrantShim(t)

	// env requests github + npm (both in the registry); the developer role ceiling is
	// [github] → npm is narrowed out at mint.
	env := EnvSpec{Services: []string{"github", "npm"}}
	const pinnedRef = "developer@2026.06.11-v1" // the spine's pinned role_ref

	gs, err := shim.MintGrantsScoped(MintGrantsRequest{SessionUUID: "sess-join", Env: env}, pinnedRef, resolver, false)
	if err != nil {
		t.Fatalf("MintGrantsScoped(pinned developer): %v", err)
	}
	if got := serviceIDs(gs.Grants); !reflect.DeepEqual(got, []string{"github"}) {
		t.Fatalf("pinned developer must narrow grants to [github], got %v", got)
	}

	// Widening impossible: the scoped set is ⊆ the unscoped set for the same env.
	shimBase := newGrantShim(t)
	base, err := shimBase.IssueGrants("sess-base", env)
	if err != nil {
		t.Fatal(err)
	}
	baseSet := map[string]struct{}{}
	for _, g := range base {
		baseSet[g.ServiceID] = struct{}{}
	}
	for _, g := range gs.Grants {
		if _, ok := baseSet[g.ServiceID]; !ok {
			t.Fatalf("pinned-role join WIDENED the grant set: %q absent from unscoped %v", g.ServiceID, serviceIDs(base))
		}
	}

	// The placeholders match the narrowed grant set (the role narrows what is minted).
	if len(gs.Placeholders) != 1 || gs.Placeholders[0].ServiceID != "github" {
		t.Fatalf("placeholder set = %+v, want exactly the narrowed [github]", gs.Placeholders)
	}
}

// TestStep5Join_NullTemplateFullEnvelope proves the recorded-default pin (the
// absent-role posture's pin) is the NULL-template path through the join: the full
// envelope mints unchanged (byte-identical to a bare MintGrants).
func TestStep5Join_NullTemplateFullEnvelope(t *testing.T) {
	resolver := loadCatalogResolver(t).AsResolver()
	env := EnvSpec{Services: []string{"github", "npm"}}

	shimScoped := newGrantShim(t)
	scoped, err := shimScoped.MintGrantsScoped(MintGrantsRequest{SessionUUID: "s", Env: env}, "default@2026.06.11-v1", resolver, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := serviceIDs(scoped.Grants); !reflect.DeepEqual(got, []string{"github", "npm"}) {
		t.Fatalf("recorded-default pin must leave the full envelope, got %v", got)
	}
}

// TestStep5Join_EmptyTemplateMintsNothing proves the researcher pin (present-empty
// services:[]) mints NOTHING through the join — the strictest narrowing, distinct
// from the null/full-envelope default.
func TestStep5Join_EmptyTemplateMintsNothing(t *testing.T) {
	resolver := loadCatalogResolver(t).AsResolver()
	env := EnvSpec{Services: []string{"github", "npm"}}

	shim := newGrantShim(t)
	gs, err := shim.MintGrantsScoped(MintGrantsRequest{SessionUUID: "s-empty", Env: env}, "researcher@2026.06.11-v1", resolver, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs.Grants) != 0 {
		t.Fatalf("researcher (empty services:[]) must mint nothing, got %v", serviceIDs(gs.Grants))
	}
}

// TestStep5Join_StrictUnknownScopeFailsClosedNamed proves the STRICT path of the
// join surfaces UnknownRoleScopeError when a pinned role's scope_template names a
// service the org grant set (env ∩ registry) does not contain — loud at mint time,
// never widening. We use a SYNTHETIC catalog entry naming a non-registry service
// (the built-ins all name `github`, which IS registered, so the fail-closed case
// needs a constructed entry — D50 synthetic).
func TestStep5Join_StrictUnknownScopeFailsClosedNamed(t *testing.T) {
	// A synthetic catalog entry whose scope_template names `github` (registered) AND
	// `s3` (NOT in the test registry: github, npm). The env requests both, so the
	// template selects both, but the registry confers no grant for s3 → strict
	// fail-closed, named; github still mints.
	c, err := NewCatalogRoleTemplateResolver([]CatalogRoleEntry{
		{
			Name: "audit", Version: "2026.06.11-v1",
			ContentHash:          "00000000000000000000000000000000000000000000000000000000deadbeef",
			ScopeTemplatePresent: true,
			ScopeServices:        []string{"github", "s3"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := c.AsResolver()
	shim := newGrantShim(t)
	env := EnvSpec{Services: []string{"github", "s3"}} // s3 requested + role-named, but not in registry

	_, err = shim.MintGrantsScoped(MintGrantsRequest{SessionUUID: "s-strict", Env: env}, "audit@2026.06.11-v1", resolver, true /* strict */)
	if err == nil {
		t.Fatal("strict mode must fail closed when the pinned role names a capability the org lacks")
	}
	var ure *UnknownRoleScopeError
	if !errors.As(err, &ure) {
		t.Fatalf("want *UnknownRoleScopeError, got %T: %v", err, err)
	}
	if ure.Service != "s3" || ure.RoleRef != "audit@2026.06.11-v1" {
		t.Fatalf("UnknownRoleScopeError = %+v, want service s3 / role audit@2026.06.11-v1", ure)
	}
	if !errors.Is(err, errUnknownRoleScope) {
		t.Fatal("the typed error must wrap the errUnknownRoleScope sentinel")
	}

	// NON-STRICT path over the SAME pin never errors and never widens: s3 is silently
	// dropped (the registry already fails it closed), github mints.
	shim2 := newGrantShim(t)
	gs, err := shim2.MintGrantsScoped(MintGrantsRequest{SessionUUID: "s-nonstrict", Env: env}, "audit@2026.06.11-v1", resolver, false)
	if err != nil {
		t.Fatalf("non-strict must not error on an absent capability: %v", err)
	}
	if got := serviceIDs(gs.Grants); !reflect.DeepEqual(got, []string{"github"}) {
		t.Fatalf("non-strict join = %v, want [github] (s3 dropped, never widened)", got)
	}
}

// TestCrossModuleContentHashAgreement is the rule-5 cross-module check: the
// identity/mint catalog resolver carries the SAME role_content_hash per role as the
// orchestrator pins. Both read the committed roles/content-hash-goldens.json (the
// orchestrator anchors that file to its nftbridge canonical bytes in
// TestCatalogContentHash_AnchoredToCanonicalBytes; this side reads the same hashes),
// so a catalog update to the same (name, version) is the SAME distinct pin in BOTH
// trees. The hashes here are exactly the orchestrator-anchored values (the precedent
// the grantref-golden cross-module byte-identity check sets).
func TestCrossModuleContentHashAgreement(t *testing.T) {
	c := loadCatalogResolver(t)

	// The orchestrator-anchored content hashes (the values
	// orchestrator/internal/sessions/TestCatalogContentHash_AnchoredToCanonicalBytes
	// proves match nftbridge.CanonicalHash over the role YAMLs). Reproduced here as
	// the FROZEN cross-module expectation so a drift on EITHER side — the golden
	// changing without the orchestrator anchor, or the mint reader diverging — fails
	// this test loudly.
	want := map[string]string{
		"default@2026.06.11-v1":           "658dfdb08b20a4e2a4cf33a78e083c673cce838c2977445792bc5d8c3f37ad0d",
		"developer@2026.06.11-v1":         "d548f4c0d6e793b66765271f8feaeb904274ded563c077b7d6df4ead42adbf2c",
		"researcher@2026.06.11-v1":        "8e38d2b09a48d85933a90fb142f8ad1034d0356ba8a7c9acfc9d1897ba420b32",
		"security-engineer@2026.06.11-v1": "c4dcab51c1a60e9f22b5c6006d3643717ac51032de25363601da614a8bcaea7b",
	}
	seen := map[string]bool{}
	for _, e := range c.Entries() {
		ref := e.Ref()
		w, ok := want[ref]
		if !ok {
			t.Fatalf("catalog carries an unexpected role %q (cross-module set drift)", ref)
		}
		if e.ContentHash != w {
			t.Fatalf("role %q content_hash = %s, want the orchestrator-anchored %s", ref, e.ContentHash, w)
		}
		// The resolver's ContentHash lookup agrees with the entry.
		if got := c.ContentHash(ref); got != w {
			t.Fatalf("ContentHash(%q) = %s, want %s", ref, got, w)
		}
		seen[ref] = true
	}
	for ref := range want {
		if !seen[ref] {
			t.Fatalf("expected role %q absent from the mint catalog (cross-module set drift)", ref)
		}
	}
}
