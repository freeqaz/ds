package controlplane

// rolecatalog_test.go is the roles.v1 RoleCatalogService READ-path validation suite
// (doc 18 §11 schema-validation row, the freeze-checklist requirement). It proves the
// catalog read API (ListRoles / GetRole, doc 18 §6) projects the four checked-in
// built-in roles (D50/D93) onto the FROZEN dreamserpent.roles.v1.Role wire message
// FAITHFULLY — the pinned identity triple anchored to roles/content-hash-goldens.json
// (roles/SCHEMA.md rule 5, ONE canonicalization spec), all five composition axes, and
// the load-bearing scope_template null-vs-present-empty boundary (rule 4 / doc 18 §8).
// It also pins the READ-PATH-ONLY structural invariant: the M2-deferred write verbs
// (PutRole / ratification) are NOT implemented — the embedded
// UnimplementedRoleCatalogServiceServer leaves them Unimplemented.
//
// Synthetic catalog only (D50): the checked-in roles/*.yaml + the committed golden.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	rolesv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/roles/v1"
)

// goldenRoles mirrors roles/content-hash-goldens.json (the single-source hash file the
// orchestrator and identity/mint resolvers both read). The read-path catalog must
// surface exactly these (name, version, content_hash, scope_template_present,
// scope_services, widenings) — proving it is not a free-floating second projection.
type goldenRoles struct {
	DefaultRole string `json:"default_role"`
	Roles       []struct {
		Name                 string   `json:"name"`
		Version              string   `json:"version"`
		ContentHash          string   `json:"content_hash"`
		ScopeTemplatePresent bool     `json:"scope_template_present"`
		ScopeServices        []string `json:"scope_services"`
		Widenings            []string `json:"widenings"`
	} `json:"roles"`
}

func loadGoldenRoles(t *testing.T) goldenRoles {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testRolesDir, "content-hash-goldens.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g goldenRoles
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	return g
}

func newCatalogForTest(t *testing.T) *RoleCatalogService {
	t.Helper()
	svc, err := NewRoleCatalogServiceFromDir(testRolesDir, nil)
	if err != nil {
		t.Fatalf("load role catalog: %v", err)
	}
	return svc
}

// TestRoleCatalog_ListRoles_ProjectsBuiltinsAnchoredToGolden is the §11 schema row for
// the read path: ListRoles surfaces all four built-ins, name-sorted, each pinned to the
// golden (name/version/content_hash), and names the recorded default. The content_hash
// is the lowercase-hex of the bytes field — anchored to roles/SCHEMA.md rule 5's
// canonical hash (the same the resolver pins), NOT a re-implemented projection.
func TestRoleCatalog_ListRoles_ProjectsBuiltinsAnchoredToGolden(t *testing.T) {
	g := loadGoldenRoles(t)
	svc := newCatalogForTest(t)

	resp, err := svc.ListRoles(context.Background(), &rolesv1.ListRolesRequest{})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if resp.GetDefaultRole() != g.DefaultRole {
		t.Fatalf("ListRoles default_role = %q, want golden %q", resp.GetDefaultRole(), g.DefaultRole)
	}
	if len(resp.GetRoles()) != len(g.Roles) {
		t.Fatalf("ListRoles returned %d roles, golden has %d", len(resp.GetRoles()), len(g.Roles))
	}

	// Name-sorted ordering is stable (the catalog is a set; a deterministic order).
	names := make([]string, 0, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		names = append(names, r.GetName())
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("ListRoles roles are not name-sorted: %v", names)
	}

	byGolden := map[string]struct {
		version string
		hash    string
	}{}
	for _, r := range g.Roles {
		byGolden[r.Name] = struct {
			version string
			hash    string
		}{r.Version, r.ContentHash}
	}
	for _, r := range resp.GetRoles() {
		want, ok := byGolden[r.GetName()]
		if !ok {
			t.Fatalf("ListRoles surfaced %q absent from the golden", r.GetName())
		}
		if r.GetVersion() != want.version {
			t.Errorf("role %q version = %q, want golden %q", r.GetName(), r.GetVersion(), want.version)
		}
		gotHash := hex.EncodeToString(r.GetContentHash())
		if gotHash != want.hash {
			t.Errorf("role %q content_hash = %s, want golden %s (roles/SCHEMA.md rule 5 — one spec)", r.GetName(), gotHash, want.hash)
		}
		if len(r.GetContentHash()) != 32 {
			t.Errorf("role %q content_hash is %d bytes, want 32 (SHA-256 full digest)", r.GetName(), len(r.GetContentHash()))
		}
	}
}

// TestRoleCatalog_ScopeTemplateBoundary is the doc 18 §8 / roles/SCHEMA.md rule-4
// boundary on the WIRE: `default` carries scope_template_present=false with NO
// scope_template message (null = no narrowing, full envelope); `researcher` carries
// scope_template_present=true with a PRESENT-but-empty services:[] (mint nothing). The
// two are distinct on the wire, mirroring their distinct content_hash. A miss here
// collapses the boundary — the failure roles/SCHEMA.md rule 4 forbids.
func TestRoleCatalog_ScopeTemplateBoundary(t *testing.T) {
	svc := newCatalogForTest(t)
	roles := listRolesByName(t, svc)

	def := roles["default"]
	if def.GetScopeTemplatePresent() {
		t.Error("default must carry scope_template_present=false (null = no narrowing, full envelope)")
	}
	if def.GetScopeTemplate() != nil {
		t.Error("default must OMIT the scope_template message entirely (the null boundary)")
	}

	res := roles["researcher"]
	if !res.GetScopeTemplatePresent() {
		t.Fatal("researcher must carry scope_template_present=true (a present template)")
	}
	if res.GetScopeTemplate() == nil {
		t.Fatal("researcher must carry a PRESENT scope_template (services:[] = mint nothing, not null)")
	}
	if len(res.GetScopeTemplate().GetServices()) != 0 {
		t.Errorf("researcher scope_template services = %v, want empty (mint nothing)", res.GetScopeTemplate().GetServices())
	}
	if res.GetScopeTemplate().GetMode() != rolesv1.ScopeMode_SCOPE_MODE_READ_ONLY {
		t.Errorf("researcher scope mode = %v, want READ_ONLY", res.GetScopeTemplate().GetMode())
	}
}

// TestRoleCatalog_AllFiveAxes_DeveloperProjection proves the full axis projection on a
// rich role: developer carries the image layer (axis a), the three skill refs (axis b),
// the standard posture (axis c), the github read-write scope template (axis d), and no
// runtime overlay (axis e null). REFERENCES ONLY (roles/SCHEMA.md rule 1) — never inline
// content, never credential material (D39).
func TestRoleCatalog_AllFiveAxes_DeveloperProjection(t *testing.T) {
	svc := newCatalogForTest(t)
	dev := listRolesByName(t, svc)["developer"]

	// Axis (a): image layers (refs only).
	if got := dev.GetImage().GetRefs(); len(got) != 1 || got[0] != "images:layer/dev-tools@STRAWMAN" {
		t.Errorf("developer image refs = %v, want the dev-tools strawman layer", got)
	}
	// Axis (b): skills.
	wantSkills := []string{"skills:code-review@1", "skills:test-runner@1", "skills:repo-navigation@1"}
	if got := dev.GetSkills().GetInstall(); !reflect.DeepEqual(got, wantSkills) {
		t.Errorf("developer skills = %v, want %v", got, wantSkills)
	}
	// Axis (c): policy posture.
	if dev.GetPolicy().GetPosture() != "standard" {
		t.Errorf("developer posture = %q, want standard", dev.GetPolicy().GetPosture())
	}
	if len(dev.GetPolicy().GetAllowlist()) != 0 || len(dev.GetPolicy().GetPackFamilies()) != 0 {
		t.Errorf("developer requests no widening; got allowlist=%v pack_families=%v", dev.GetPolicy().GetAllowlist(), dev.GetPolicy().GetPackFamilies())
	}
	// Axis (d): scope template — github read-write (commits are the point).
	if !dev.GetScopeTemplatePresent() || dev.GetScopeTemplate() == nil {
		t.Fatal("developer must carry a present scope_template")
	}
	if got := dev.GetScopeTemplate().GetServices(); !reflect.DeepEqual(got, []string{"github"}) {
		t.Errorf("developer scope services = %v, want [github]", got)
	}
	if dev.GetScopeTemplate().GetMode() != rolesv1.ScopeMode_SCOPE_MODE_READ_WRITE {
		t.Errorf("developer scope mode = %v, want READ_WRITE", dev.GetScopeTemplate().GetMode())
	}
	// Axis (e): no runtime overlay (the YAML null).
	if dev.GetRuntime() != nil {
		t.Errorf("developer must carry no runtime overlay (null); got %v", dev.GetRuntime())
	}
	// Identity.
	if dev.GetSchemaVersion() != "role/v0" {
		t.Errorf("developer schema_version = %q, want role/v0", dev.GetSchemaVersion())
	}
}

// TestRoleCatalog_WideningPostureSurfaced is the §11 widening-gate row on the read path:
// the researcher's UNRATIFIED widening requests (the wikipedia/arxiv allowlist beyond
// the org envelope, doc 18 §9) are surfaced on the policy allowlist AND
// widenings_ratified is false (the built-in catalog ships unratified). The
// security-engineer (narrowing-only, locked posture) requests no widening and is also
// unratified-but-nothing-to-gate.
func TestRoleCatalog_WideningPostureSurfaced(t *testing.T) {
	g := loadGoldenRoles(t)
	svc := newCatalogForTest(t)
	roles := listRolesByName(t, svc)

	wantWideningByName := map[string][]string{}
	for _, r := range g.Roles {
		wantWideningByName[r.Name] = r.Widenings
	}

	res := roles["researcher"]
	gotAllow := append([]string(nil), res.GetPolicy().GetAllowlist()...)
	sort.Strings(gotAllow)
	want := append([]string(nil), wantWideningByName["researcher"]...)
	sort.Strings(want)
	if !reflect.DeepEqual(gotAllow, want) {
		t.Errorf("researcher allowlist (widening requests) = %v, want golden %v", gotAllow, want)
	}
	if res.GetWideningsRatified() {
		t.Error("researcher widenings must be UNRATIFIED at M0 (the built-in catalog ships unratified, doc 18 §9)")
	}

	se := roles["security-engineer"]
	if se.GetPolicy().GetPosture() != "locked" {
		t.Errorf("security-engineer posture = %q, want locked (narrower than default, doc 18 §9)", se.GetPolicy().GetPosture())
	}
	if len(se.GetPolicy().GetAllowlist()) != 0 {
		t.Errorf("security-engineer requests no widening; got %v", se.GetPolicy().GetAllowlist())
	}
}

// TestRoleCatalog_GetRole_ResolvesRefForms is the §11 read-path resolution row: GetRole
// resolves a bare name, an explicit recorded version, and an EMPTY ref (the recorded
// default, doc 18 §7), and refuses an unknown/wrong-version ref with NotFound (the
// read-path analog of the create-time structural refusal, doc 18 §6 row 1–2).
func TestRoleCatalog_GetRole_ResolvesRefForms(t *testing.T) {
	svc := newCatalogForTest(t)
	ctx := context.Background()

	// Bare name → the recorded current version.
	bare, err := svc.GetRole(ctx, &rolesv1.GetRoleRequest{RoleRef: "developer"})
	if err != nil {
		t.Fatalf("GetRole(developer): %v", err)
	}
	if bare.GetRole().GetName() != "developer" {
		t.Fatalf("GetRole(developer) = %q", bare.GetRole().GetName())
	}

	// Explicit recorded version matches.
	exp, err := svc.GetRole(ctx, &rolesv1.GetRoleRequest{RoleRef: "developer@2026.06.11-v1"})
	if err != nil {
		t.Fatalf("GetRole(developer@2026.06.11-v1): %v", err)
	}
	if !reflect.DeepEqual(exp.GetRole().GetContentHash(), bare.GetRole().GetContentHash()) {
		t.Error("bare-name and explicit-version GetRole must resolve the SAME pinned role")
	}

	// Empty ref → the recorded default (doc 18 §7).
	def, err := svc.GetRole(ctx, &rolesv1.GetRoleRequest{RoleRef: ""})
	if err != nil {
		t.Fatalf("GetRole(\"\") (default): %v", err)
	}
	if def.GetRole().GetName() != "default" {
		t.Errorf("GetRole(\"\") = %q, want the recorded default `default` (doc 18 §7)", def.GetRole().GetName())
	}

	// Unknown ref → NotFound (fail-closed structural refusal).
	if _, err := svc.GetRole(ctx, &rolesv1.GetRoleRequest{RoleRef: "ghost@9"}); status.Code(err) != codes.NotFound {
		t.Errorf("GetRole(ghost@9) code = %v, want NotFound", status.Code(err))
	}
	// An explicit historical/other version the M0 set does not carry → NotFound.
	if _, err := svc.GetRole(ctx, &rolesv1.GetRoleRequest{RoleRef: "developer@1999.01.01-v0"}); status.Code(err) != codes.NotFound {
		t.Errorf("GetRole(developer@<wrong-version>) code = %v, want NotFound (M0 pins the recorded current version)", status.Code(err))
	}
}

// TestRoleCatalog_WritePathReserved_NotImplemented is the READ-PATH-ONLY structural
// invariant: the M2-deferred write path (PutRole / ratification) is RESERVED in the
// proto and NOT implemented. The embedded UnimplementedRoleCatalogServiceServer leaves
// the service with EXACTLY the two read RPCs — proven by the frozen ServiceDesc carrying
// only ListRoles + GetRole. A future additive write RPC would grow this set; a v1 with a
// write RPC in the ServiceDesc would fail this test (the freeze's read-path-only claim).
func TestRoleCatalog_WritePathReserved_NotImplemented(t *testing.T) {
	methods := map[string]bool{}
	for _, m := range rolesv1.RoleCatalogService_ServiceDesc.Methods {
		methods[m.MethodName] = true
	}
	if !methods["ListRoles"] || !methods["GetRole"] {
		t.Fatalf("RoleCatalogService must expose ListRoles + GetRole; got %v", methods)
	}
	if len(methods) != 2 {
		t.Fatalf("RoleCatalogService must expose EXACTLY the two READ RPCs at this freeze (write path M2-deferred + reserved); got %v", methods)
	}
	for _, banned := range []string{"PutRole", "RatifyRoleWidening", "DeleteRole"} {
		if methods[banned] {
			t.Fatalf("write-path RPC %q is implemented — the read-path-only freeze invariant is violated (write path is M2-deferred, doc 18 OQ5)", banned)
		}
	}
}

// TestRoleCatalog_OverWire_ServedAlongsideSessionService proves the catalog read path is
// REGISTERED on the same control-plane server as CreateSession (cp.Register) and
// round-trips over the WIRE (a real gRPC client over bufconn, D50) — the doc 18 §4 point
// 3 / D80 requirement that the catalog read path exists WHEREVER CreateSession is. This
// is the registration + transport assertion, not an in-process handler call.
func TestRoleCatalog_OverWire_ServedAlongsideSessionService(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	f.cp.Register(srv) // registers SessionService + HostAgentService + RoleCatalogService
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	client := rolesv1.NewRoleCatalogServiceClient(dialBufconn(t, lis))

	list, err := client.ListRoles(ctx, &rolesv1.ListRolesRequest{})
	if err != nil {
		t.Fatalf("ListRoles over the wire: %v", err)
	}
	if len(list.GetRoles()) != 4 || list.GetDefaultRole() != "default" {
		t.Fatalf("over-the-wire ListRoles = %d roles default=%q, want 4 / default", len(list.GetRoles()), list.GetDefaultRole())
	}

	get, err := client.GetRole(ctx, &rolesv1.GetRoleRequest{RoleRef: "security-engineer"})
	if err != nil {
		t.Fatalf("GetRole over the wire: %v", err)
	}
	if get.GetRole().GetPolicy().GetPosture() != "locked" {
		t.Errorf("over-the-wire security-engineer posture = %q, want locked", get.GetRole().GetPolicy().GetPosture())
	}

	// An unknown ref fails closed over the wire (NotFound), same as in-process.
	if _, err := client.GetRole(ctx, &rolesv1.GetRoleRequest{RoleRef: "ghost"}); status.Code(err) != codes.NotFound {
		t.Errorf("over-the-wire GetRole(ghost) code = %v, want NotFound", status.Code(err))
	}
}

// TestRoleCatalog_ListRoles_Paging proves the forward-compatible paging field is honored
// (a non-zero page_size caps the single M0 page) without breaking the small-catalog
// posture — the documented-now-grow-later shape.
func TestRoleCatalog_ListRoles_Paging(t *testing.T) {
	svc := newCatalogForTest(t)
	resp, err := svc.ListRoles(context.Background(), &rolesv1.ListRolesRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("ListRoles(page_size=2): %v", err)
	}
	if len(resp.GetRoles()) != 2 {
		t.Fatalf("ListRoles(page_size=2) returned %d roles, want 2", len(resp.GetRoles()))
	}
}

// listRolesByName is a small helper returning the ListRoles projection keyed by name.
func listRolesByName(t *testing.T, svc *RoleCatalogService) map[string]*rolesv1.Role {
	t.Helper()
	resp, err := svc.ListRoles(context.Background(), &rolesv1.ListRolesRequest{})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	out := make(map[string]*rolesv1.Role, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		out[r.GetName()] = r
	}
	return out
}
