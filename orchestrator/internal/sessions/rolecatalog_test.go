package sessions

// Tests for the M0 org-catalog-backed RoleResolver (rolecatalog.go) and the
// canonical role-document hash (rolecanonical.go). Synthetic catalog only (D50):
// the checked-in roles/*.yaml. The headline guarantee is roles/SCHEMA.md rule 5 —
// ONE canonical-serialization spec: every role's content_hash is the nftbridge JCS
// canonical hash, anchored to the committed roles/content-hash-goldens.json that
// the identity/mint-side resolver also reads (the cross-module agreement).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// rolesDir / goldenPath locate the catalog relative to this package's test cwd
// (orchestrator/internal/sessions → ../../../roles).
const rolesDir = "../../../roles"
const goldenPath = "../../../roles/content-hash-goldens.json"

// goldenFile mirrors roles/content-hash-goldens.json (the single-source hash file).
type goldenFile struct {
	DefaultRole string `json:"default_role"`
	Roles       []struct {
		Name                 string   `json:"name"`
		Version              string   `json:"version"`
		ContentHash          string   `json:"content_hash"`
		Payload              string   `json:"payload"`
		ScopeTemplatePresent bool     `json:"scope_template_present"`
		ScopeServices        []string `json:"scope_services"`
		Widenings            []string `json:"widenings"`
	} `json:"roles"`
}

func loadGolden(t *testing.T) goldenFile {
	t.Helper()
	b, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g goldenFile
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	return g
}

// TestCatalogContentHash_AnchoredToCanonicalBytes is the rule-5 anchor: for every
// checked-in role, the canonical role-document PAYLOAD and its content_hash are
// re-derived from the YAML via the nftbridge JCS path and MUST match the committed
// golden byte-for-byte. This proves the golden is not a free-floating second hash
// spec — it is exactly what the shared canonicalizer produces (one spec, not two).
func TestCatalogContentHash_AnchoredToCanonicalBytes(t *testing.T) {
	g := loadGolden(t)
	byName := map[string]struct {
		hash    string
		payload string
	}{}
	for _, r := range g.Roles {
		byName[r.Name] = struct {
			hash    string
			payload string
		}{r.ContentHash, r.Payload}
	}

	entries, err := os.ReadDir(rolesDir)
	if err != nil {
		t.Fatalf("read roles dir: %v", err)
	}
	seen := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(rolesDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		doc, err := parseRoleYAML(string(body))
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		payload, hashHex := canonicalRoleHashHex(doc)
		want, ok := byName[doc.Name]
		if !ok {
			t.Fatalf("role %q parsed from %s is absent from the golden", doc.Name, e.Name())
		}
		if string(payload) != want.payload {
			t.Fatalf("role %q canonical payload drift:\n got: %s\nwant: %s", doc.Name, payload, want.payload)
		}
		if hashHex != want.hash {
			t.Fatalf("role %q content_hash drift: got %s want %s", doc.Name, hashHex, want.hash)
		}
		seen++
	}
	if seen != len(g.Roles) {
		t.Fatalf("anchored %d roles, golden has %d", seen, len(g.Roles))
	}
}

// TestCatalogRoleResolver_ResolvesBuiltins proves the catalog resolver resolves
// every built-in role to its golden pin (name/version/content_hash), recognizes the
// recorded default for the absent posture, and refuses an unknown ref fail-closed.
func TestCatalogRoleResolver_ResolvesBuiltins(t *testing.T) {
	g := loadGolden(t)
	resolver, err := NewCatalogRoleResolverFromDir(rolesDir)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	ctx := context.Background()

	for _, r := range g.Roles {
		res, ok, err := resolver.Resolve(ctx, r.Name+"@"+r.Version)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", r.Name, err)
		}
		if !ok {
			t.Fatalf("Resolve(%s) reported unknown", r.Name)
		}
		if res.Name != r.Name || res.Version != r.Version || res.ContentHash != r.ContentHash {
			t.Fatalf("Resolve(%s) = %+v, want golden pin %s@%s/%s", r.Name, res, r.Name, r.Version, r.ContentHash)
		}
		// A bare name resolves the recorded current version too.
		res2, ok2, _ := resolver.Resolve(ctx, r.Name)
		if !ok2 || res2.ContentHash != r.ContentHash {
			t.Fatalf("Resolve(%s) bare-name = %+v ok=%v, want the recorded current pin", r.Name, res2, ok2)
		}
	}

	// Absent posture → recorded default, explicit and non-empty (doc 18 §7).
	dres, err := resolver.Default(ctx)
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if dres.Name != "default" || dres.ContentHash == "" {
		t.Fatalf("Default = %+v, want the recorded default with a content hash", dres)
	}

	// Unknown ref → fail-closed (ok=false → structural refusal).
	if _, ok, err := resolver.Resolve(ctx, "ghost@9"); ok || err != nil {
		t.Fatalf("Resolve(ghost@9) = ok=%v err=%v, want unknown (ok=false, no error)", ok, err)
	}
	// An explicit historical version the M0 set does not carry is unknown.
	if _, ok, _ := resolver.Resolve(ctx, "developer@1999.01.01-v0"); ok {
		t.Fatal("Resolve(developer@<wrong-version>) must be unknown — M0 pins the recorded current version")
	}
}

// TestCatalogRoleResolver_WideningPostureRidesInert proves the researcher role's
// UNRATIFIED widenings ride inert through ResolveAndPinRole (the §9 widening-gate
// row): the create PROCEEDS with the widenings recorded inert, NOT refused.
func TestCatalogRoleResolver_WideningPostureRidesInert(t *testing.T) {
	resolver, err := NewCatalogRoleResolverFromDir(rolesDir)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	pin, err := ResolveAndPinRole(context.Background(), resolver, "researcher@2026.06.11-v1", nil)
	if err != nil {
		t.Fatalf("researcher must resolve (widenings ride inert, not refuse): %v", err)
	}
	if len(pin.InertWidenings) == 0 {
		t.Fatal("researcher's unratified widenings must ride INERT on the pin (doc 18 §9 widening-gate)")
	}
	if pin.WideningsRatified {
		t.Fatal("the built-in catalog ships UNRATIFIED — researcher's widenings are not ratified at M0")
	}
	// A role with no widenings (default) carries no inert widenings.
	dpin, err := ResolveAndPinRole(context.Background(), resolver, "default", nil)
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	if len(dpin.InertWidenings) != 0 {
		t.Fatalf("default requests no widening; got inert %v", dpin.InertWidenings)
	}
}

// TestCatalogScopeTemplateBoundary proves the doc 18 §8 null-vs-empty boundary is
// preserved in the canonical projection: default = scope_template null (no
// narrowing), researcher = present-but-empty services:[] (mints nothing). These
// produce DISTINCT canonical bytes (and therefore distinct hashes).
func TestCatalogScopeTemplateBoundary(t *testing.T) {
	g := loadGolden(t)
	byName := map[string]struct {
		present  bool
		services []string
		hash     string
	}{}
	for _, r := range g.Roles {
		svc := r.ScopeServices
		if svc == nil {
			svc = []string{}
		}
		byName[r.Name] = struct {
			present  bool
			services []string
			hash     string
		}{r.ScopeTemplatePresent, svc, r.ContentHash}
	}

	def := byName["default"]
	res := byName["researcher"]
	if def.present {
		t.Fatal("default must carry scope_template: null (Present=false, full envelope)")
	}
	if !res.present || len(res.services) != 0 {
		t.Fatalf("researcher must carry a present-but-empty services:[] (mints nothing), got present=%v services=%v", res.present, res.services)
	}
	if def.hash == res.hash {
		t.Fatal("null vs present-empty scope_template must hash DIFFERENTLY (distinct canonical bytes)")
	}
}

// TestCanonicalRoleDocument_PinnedFieldsChangeHash proves a catalog update to the
// SAME (name, version) that changes a grant-relevant field produces a DISTINCT
// content_hash (roles/SCHEMA.md rule 5: a same-(name,version) byte change is a
// distinct pin). We mutate the parsed projection and re-hash.
func TestCanonicalRoleDocument_PinnedFieldsChangeHash(t *testing.T) {
	base := roleDocument{
		SchemaVersion: "role/v0", Name: "developer", Version: "2026.06.11-v1",
		Posture: "standard", ScopeTemplatePresent: true, ScopeServices: []string{"github"}, ScopeMode: "read-write",
	}
	_, h0 := canonicalRoleHashHex(base)

	// Add a service to the scope_template → distinct pin.
	widened := base
	widened.ScopeServices = []string{"github", "npm"}
	_, h1 := canonicalRoleHashHex(widened)
	if h0 == h1 {
		t.Fatal("changing the scope_template services must change the content_hash (distinct pin)")
	}

	// Flip the posture → distinct pin.
	posture := base
	posture.Posture = "locked"
	_, h2 := canonicalRoleHashHex(posture)
	if h0 == h2 {
		t.Fatal("changing the policy posture must change the content_hash (distinct pin)")
	}

	// Re-hashing the SAME projection is stable (produce-once determinism).
	_, h0again := canonicalRoleHashHex(base)
	if h0 != h0again {
		t.Fatal("the canonical hash must be deterministic for the same role document")
	}
}

// TestGoldenScopeServicesMatchParse keeps the golden's scope_services in sync with
// what the parser reads from the YAML (so the identity/mint side, which reads the
// golden's scope_services to build its template, sees the SAME ceiling the
// orchestrator parses).
func TestGoldenScopeServicesMatchParse(t *testing.T) {
	g := loadGolden(t)
	byName := map[string][]string{}
	present := map[string]bool{}
	for _, r := range g.Roles {
		byName[r.Name] = r.ScopeServices
		present[r.Name] = r.ScopeTemplatePresent
	}
	entries, _ := os.ReadDir(rolesDir)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		body, _ := os.ReadFile(filepath.Join(rolesDir, e.Name()))
		doc, err := parseRoleYAML(string(body))
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		gotSvc := doc.ScopeServices
		wantSvc := byName[doc.Name]
		if gotSvc == nil {
			gotSvc = []string{}
		}
		if wantSvc == nil {
			wantSvc = []string{}
		}
		if doc.ScopeTemplatePresent != present[doc.Name] {
			t.Fatalf("role %q scope_template present = %v, golden = %v", doc.Name, doc.ScopeTemplatePresent, present[doc.Name])
		}
		if !reflect.DeepEqual(gotSvc, wantSvc) {
			t.Fatalf("role %q scope_services = %v, golden = %v", doc.Name, gotSvc, wantSvc)
		}
	}
}
