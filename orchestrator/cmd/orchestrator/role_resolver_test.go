package main

// role_resolver_test.go proves the LIVE create-path role resolver wiring (roleResolver,
// main.go) is the M0 ORG-CATALOG-backed resolver over the checked-in roles/ tree — NOT
// the v0 default-only marker resolver — so the orchestrator binary resolves+pins every
// built-in role and pins each role's CANONICAL role_content_hash (roles/SCHEMA.md rule 5),
// the SAME bytes the roles.v1 READ path (RoleCatalogService) serves. The unit-level
// resolve+pin behavior is proven exhaustively in internal/sessions; these tests guard the
// one thing only the binary wiring can break — that the create path is pointed at the
// catalog, agreeing with the read path, not at a divergent placeholder hash.
//
// The catalog dir is the repo's top-level roles/ tree (../../../roles from this package's
// test cwd), set through the DS_ORCH_ROLES_DIR deployment knob both roleResolver() and the
// read-path catalog read.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"

	rolesv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/roles/v1"
)

const testRolesDir = "../../../roles"
const testGoldenPath = "../../../roles/content-hash-goldens.json"

// roleGolden mirrors the fields of roles/content-hash-goldens.json this test reads — the
// single-source canonical content_hash file the catalog + the read path + the resolver all
// anchor to (roles/SCHEMA.md rule 5). Synthetic fixture (D50): the checked-in catalog.
type roleGolden struct {
	DefaultRole string `json:"default_role"`
	Roles       []struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		ContentHash string `json:"content_hash"`
	} `json:"roles"`
}

func loadRoleGolden(t *testing.T) roleGolden {
	t.Helper()
	b, err := os.ReadFile(testGoldenPath)
	if err != nil {
		t.Fatalf("read golden %q: %v", testGoldenPath, err)
	}
	var g roleGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	return g
}

// withRolesDir points both roleResolver() and the read-path catalog at the checked-in
// roles/ tree for the duration of a test (DS_ORCH_ROLES_DIR is the dir both read).
func withRolesDir(t *testing.T) {
	t.Helper()
	t.Setenv("DS_ORCH_ROLES_DIR", testRolesDir)
}

// TestRoleResolver_IsCatalogBacked proves the live create-path resolver is the
// CatalogRoleResolver over the checked-in roles/ tree — not the v0 default-only resolver.
// The discriminator: the default-only resolver REFUSES every non-default ref, so resolving
// a non-default built-in (developer) succeeding proves the binary is wired to the catalog.
func TestRoleResolver_IsCatalogBacked(t *testing.T) {
	withRolesDir(t)
	if _, ok := roleResolver().(*sessions.CatalogRoleResolver); !ok {
		t.Fatalf("roleResolver() = %T, want *sessions.CatalogRoleResolver (the create path must resolve the full catalog, doc 18 §4/§7)", roleResolver())
	}
}

// TestRoleResolver_ResolvesNameAtVersion_PinsCanonicalHash proves the live resolver
// resolves <name>@<version> for every built-in role AND pins the matching CANONICAL
// content_hash from the golden (roles/SCHEMA.md rule 5) — never a recomputed/divergent
// hash. This is the headline guarantee: the create path pins the SAME bytes the catalog
// records.
func TestRoleResolver_ResolvesNameAtVersion_PinsCanonicalHash(t *testing.T) {
	withRolesDir(t)
	g := loadRoleGolden(t)
	r := roleResolver()
	ctx := context.Background()

	for _, role := range g.Roles {
		ref := role.Name + "@" + role.Version
		pin, err := sessions.ResolveAndPinRole(ctx, r, ref, slog.Default())
		if err != nil {
			t.Fatalf("ResolveAndPinRole(%q): %v", ref, err)
		}
		if pin.Name != role.Name || pin.Version != role.Version {
			t.Fatalf("ResolveAndPinRole(%q) pinned %s@%s, want %s@%s", ref, pin.Name, pin.Version, role.Name, role.Version)
		}
		if pin.ContentHash != role.ContentHash {
			t.Fatalf("ResolveAndPinRole(%q) pinned content_hash %q, want the golden canonical hash %q (roles/SCHEMA.md rule 5 — the create path must NOT recompute a divergent hash)", ref, pin.ContentHash, role.ContentHash)
		}
	}
}

// TestRoleResolver_AbsentRecordsDefaultExplicitly proves an ABSENT role_ref ("") records
// `default@<current>` EXPLICITLY with the CANONICAL default content_hash — so "no role" and
// "default role" are the SAME auditable fact (doc 18 §7), and the pinned default hash is
// the catalog's canonical hash, NOT the v0 placeholder marker the degraded fallback uses.
func TestRoleResolver_AbsentRecordsDefaultExplicitly(t *testing.T) {
	withRolesDir(t)
	g := loadRoleGolden(t)
	var wantHash, wantVersion string
	for _, role := range g.Roles {
		if role.Name == g.DefaultRole {
			wantHash, wantVersion = role.ContentHash, role.Version
		}
	}
	if wantHash == "" {
		t.Fatalf("golden default_role %q absent from the golden roles", g.DefaultRole)
	}

	pin, err := sessions.ResolveAndPinRole(context.Background(), roleResolver(), "", slog.Default())
	if err != nil {
		t.Fatalf("ResolveAndPinRole(absent): %v", err)
	}
	if pin.Name != g.DefaultRole || pin.Version != wantVersion {
		t.Fatalf("absent role_ref pinned %s@%s, want the recorded default %s@%s (explicit, never null)", pin.Name, pin.Version, g.DefaultRole, wantVersion)
	}
	if pin.ContentHash != wantHash {
		t.Fatalf("absent role_ref pinned content_hash %q, want the CANONICAL default hash %q (doc 18 §7 — recorded explicitly, not the v0 marker)", pin.ContentHash, wantHash)
	}
	if pin.Ref() != g.DefaultRole+"@"+wantVersion {
		t.Fatalf("absent role_ref recorded Ref() %q, want the explicit %s@%s", pin.Ref(), g.DefaultRole, wantVersion)
	}
}

// TestRoleResolver_UnknownRefStructuralRefusal proves an unknown/unresolvable ref is a
// STRUCTURAL REFUSAL (ErrRoleRefRefused, the D56 two-key posture) through the live
// resolver — fail-closed, distinct, machine-classifiable via ErrIsRoleRefused.
func TestRoleResolver_UnknownRefStructuralRefusal(t *testing.T) {
	withRolesDir(t)
	_, err := sessions.ResolveAndPinRole(context.Background(), roleResolver(), "ghost@9999.99.99-v0", slog.Default())
	if err == nil {
		t.Fatal("ResolveAndPinRole(ghost@…) returned nil, want a structural refusal")
	}
	if !sessions.ErrIsRoleRefused(err) {
		t.Fatalf("ResolveAndPinRole(ghost@…) err = %v, want ErrRoleRefRefused (structural refusal, doc 18 §6)", err)
	}
}

// TestRoleResolver_UnratifiedWideningsProceedNotRefused proves a role whose widenings are
// UNRATIFIED (the researcher role ships unratified at M0) is NOT a refusal: the create
// PROCEEDS, the widenings ride INERT on the pin (admitting nothing) — the §9 widening-gate
// row (doc 18 §9, D91). It is the explicit anti-refusal: an unratified-widening role must
// resolve and pin like any other, never fail-closed.
func TestRoleResolver_UnratifiedWideningsProceedNotRefused(t *testing.T) {
	withRolesDir(t)
	pin, err := sessions.ResolveAndPinRole(context.Background(), roleResolver(), "researcher@2026.06.11-v1", slog.Default())
	if err != nil {
		t.Fatalf("ResolveAndPinRole(researcher) = %v, want the create to PROCEED (unratified widenings are NOT a refusal, doc 18 §9)", err)
	}
	if sessions.ErrIsRoleRefused(err) {
		t.Fatal("unratified widenings must NOT be a structural refusal")
	}
	if pin.WideningsRatified {
		t.Fatal("the researcher role ships UNRATIFIED at M0 (doc 18 §9) — WideningsRatified must be false")
	}
	if len(pin.InertWidenings) == 0 {
		t.Fatal("the researcher role carries widenings that must ride INERT on the pin (recorded, admitting nothing)")
	}
}

// TestRoleResolver_PinHashEqualsReadPathContentHash proves the create-path PIN's content
// hash equals the roles.v1 READ path's Role.content_hash for the SAME role — the one-spec
// guarantee across the two seams (roles/SCHEMA.md rule 5). The pin carries lowercase hex;
// the read path carries the raw digest bytes (hex-decoded), so the test decodes the pin's
// hex and compares the raw bytes the wire field carries. This is the cross-seam agreement
// the task asks to verify: the create path does NOT recompute a divergent hash.
func TestRoleResolver_PinHashEqualsReadPathContentHash(t *testing.T) {
	withRolesDir(t)
	catalog, err := controlplane.NewRoleCatalogServiceFromDir(rolesCatalogDir(), slog.Default())
	if err != nil {
		t.Fatalf("NewRoleCatalogServiceFromDir(%q): %v", rolesCatalogDir(), err)
	}
	r := roleResolver()
	ctx := context.Background()

	for _, ref := range []string{"default", "developer", "researcher", "security-engineer"} {
		// Create-path pin (lowercase-hex content_hash).
		pin, err := sessions.ResolveAndPinRole(ctx, r, ref, slog.Default())
		if err != nil {
			t.Fatalf("ResolveAndPinRole(%q): %v", ref, err)
		}
		pinBytes, err := hex.DecodeString(pin.ContentHash)
		if err != nil {
			t.Fatalf("pin content_hash for %q is not hex: %v", ref, err)
		}

		// Read-path Role.content_hash (raw digest bytes).
		resp, err := catalog.GetRole(ctx, &rolesv1.GetRoleRequest{RoleRef: pin.Ref()})
		if err != nil {
			t.Fatalf("read-path GetRole(%q): %v", pin.Ref(), err)
		}
		readBytes := resp.GetRole().GetContentHash()
		if len(readBytes) == 0 {
			t.Fatalf("read-path Role.content_hash for %q is empty", pin.Ref())
		}
		if string(pinBytes) != string(readBytes) {
			t.Fatalf("content_hash DISAGREES for %q: create-path pin %x vs read-path Role.content_hash %x (roles/SCHEMA.md rule 5 — one spec, not two)", pin.Ref(), pinBytes, readBytes)
		}
	}
}
