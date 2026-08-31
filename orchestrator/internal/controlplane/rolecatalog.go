package controlplane

// rolecatalog.go is the orchestrator's RoleCatalogService server — the catalog
// READ path (roles.v1 ListRoles / GetRole, doc 18 §6 seam 2; D89–D96). It is the
// control-plane sibling of the SessionService CreateSession handler
// (sessionservice.go): a read-only API serving the org role catalog, backed at M0
// by the checked-in roles/*.yaml (the four built-in strawmen, D50/D93). It serves
// WHEREVER CreateSession is — incl. orchestrator-lite, the OSS single-host
// all-in-one (D80, doc 18 §4 point 3) — because it is registered alongside
// SessionService in ControlPlane.Register (serve.go).
//
// WHAT THIS IS AND IS NOT (the roleref.go / rolecatalog.go fence):
//   - IS: the read-side catalog projection. It loads the checked-in roles/ catalog
//     into the full read-path projection (sessions.LoadCatalogRoleDocuments — the
//     pinned identity triple + all five composition axes, doc 18 §2/§7) and
//     projects each onto the FROZEN roles.v1.Role wire message. The role_content_hash
//     rides the SAME canonical-serialization spec the resolver + the goldens use
//     (roles/SCHEMA.md rule 5 — one spec, not two).
//   - IS NOT: the role ENGINE, the create-time resolve+pin stage (that is
//     sessions.RoleResolver, used by CreateSession), or the catalog WRITE path. The
//     roles.v1 WRITE path (PutRole + ratification verbs) is M2-DEFERRED (doc 18 OQ5)
//     and RESERVED in the proto, NOT implemented here. This server implements ONLY
//     the two frozen read RPCs.

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	rolesv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/roles/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
)

// RoleCatalogService is the roles.v1 RoleCatalogService server (doc 18 §6 read
// path). It embeds the frozen UnimplementedRoleCatalogServiceServer so the
// M2-deferred write RPCs (added additively later) stay unimplemented, and serves
// ListRoles / GetRole over an immutable, name-sorted snapshot of the catalog
// loaded at construction. Construct with NewRoleCatalogService (the catalog is the
// checked-in roles/ tree at M0).
type RoleCatalogService struct {
	rolesv1.UnimplementedRoleCatalogServiceServer

	// docs is the name-sorted catalog snapshot (the built-in four at M0). Immutable
	// after construction — the read path serves a fixed catalog (the write path that
	// would mutate it is M2-deferred).
	docs []sessions.CatalogRoleDocument
	// byRef indexes a resolvable ref form (`name`, `name@version`) → doc index, so
	// GetRole resolves both the bare-name and the explicit-version ref (doc 18 §7).
	byRef map[string]int
	// defaultRole is the recorded default role name (`default` at M0, doc 18 §7) —
	// ListRoles names it and an absent GetRole ref resolves to it.
	defaultRole string

	logger *slog.Logger
}

// Compile-time proof the handler satisfies the frozen roles.v1 server interface.
var _ rolesv1.RoleCatalogServiceServer = (*RoleCatalogService)(nil)

// NewRoleCatalogService builds the read-path catalog server over a set of loaded
// role documents (the checked-in roles/ catalog at M0). The defaultRole MUST name
// a role present in the set (the recorded default must resolve — doc 18 §7). The
// docs are sorted by name for a stable ListRoles order and indexed by ref.
func NewRoleCatalogService(docs []sessions.CatalogRoleDocument, defaultRole string, logger *slog.Logger) (*RoleCatalogService, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(docs) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "controlplane: empty role catalog")
	}
	if defaultRole == "" {
		defaultRole = sessions.DefaultCatalogRoleName
	}

	sorted := append([]sessions.CatalogRoleDocument(nil), docs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	byRef := make(map[string]int, len(sorted)*2)
	defaultPresent := false
	for i, d := range sorted {
		if d.Name == defaultRole {
			defaultPresent = true
		}
		byRef[d.Name] = i               // bare name → recorded current version
		byRef[d.Name+"@"+d.Version] = i // explicit recorded version
	}
	if !defaultPresent {
		return nil, status.Errorf(codes.FailedPrecondition, "controlplane: recorded default role %q absent from the catalog", defaultRole)
	}

	return &RoleCatalogService{docs: sorted, byRef: byRef, defaultRole: defaultRole, logger: logger}, nil
}

// NewRoleCatalogServiceFromDir is the M0 wiring convenience: load the checked-in
// roles/ catalog (the four built-in strawmen, D50/D93) and build the read-path
// server with `default` as the recorded default (doc 18 §7). It is what the
// control-plane wiring (NewControlPlane) calls so the catalog serves wherever
// CreateSession does (incl. orchestrator-lite, D80).
func NewRoleCatalogServiceFromDir(dir string, logger *slog.Logger) (*RoleCatalogService, error) {
	docs, err := sessions.LoadCatalogRoleDocuments(dir)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "controlplane: load role catalog %q: %v", dir, err)
	}
	return NewRoleCatalogService(docs, sessions.DefaultCatalogRoleName, logger)
}

// ListRoles enumerates the catalog (doc 18 §6 read path). It returns every built-in
// role's full Role projection (name-sorted) plus the recorded default name (doc 18
// §7), so a client reads "no role" and "default role" as the same auditable fact.
// Paging fields are honored forward-compatibly: at M0 the catalog is the four
// built-ins and fits one page, so a non-zero page_size simply caps the page; an
// unrecognized page_token returns the first page (the catalog is small and stable).
func (s *RoleCatalogService) ListRoles(ctx context.Context, req *rolesv1.ListRolesRequest) (*rolesv1.ListRolesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "controlplane: nil ListRolesRequest")
	}

	roles := make([]*rolesv1.Role, 0, len(s.docs))
	for i := range s.docs {
		roles = append(roles, roleToProto(s.docs[i]))
	}

	// Forward-compatible paging: the M0 catalog is small and stable (the built-in
	// four), so a request page_size > 0 caps the single page and no continuation is
	// needed. This is the documented-now-grow-later shape (the orchestrator.v1
	// ListSessions precedent) — a large hosted catalog grows real paging additively.
	if ps := int(req.GetPageSize()); ps > 0 && ps < len(roles) {
		roles = roles[:ps]
	}

	return &rolesv1.ListRolesResponse{
		Roles:         roles,
		DefaultRole:   s.defaultRole,
		NextPageToken: "", // single page at M0 (the built-in catalog fits one page)
	}, nil
}

// GetRole reads ONE role by ref (doc 18 §6 read path). An empty ref resolves the
// recorded default (`default@<current>`, doc 18 §7). A bare `<name>` resolves the
// recorded current version; an explicit `<name>@<version>` matches only the
// recorded pin (M0 pins the recorded current version of each built-in). An
// unknown/unresolvable ref is a gRPC NotFound — the read-path analog of the
// create-time structural refusal (doc 18 §6 row 1–2), so "the ref is bad" is
// unambiguous.
func (s *RoleCatalogService) GetRole(ctx context.Context, req *rolesv1.GetRoleRequest) (*rolesv1.GetRoleResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "controlplane: nil GetRoleRequest")
	}

	ref := strings.TrimSpace(req.GetRoleRef())
	if ref == "" {
		// Absent ref → the recorded default (doc 18 §7), resolved explicitly.
		ref = s.defaultRole
	}

	idx, ok := s.byRef[ref]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "controlplane: role %q not found in the catalog (doc 18 §6 read path)", ref)
	}
	return &rolesv1.GetRoleResponse{Role: roleToProto(s.docs[idx])}, nil
}

// roleToProto projects a read-path CatalogRoleDocument onto the FROZEN
// dreamserpent.roles.v1.Role wire message (doc 18 §2/§7; roles/SCHEMA.md). The
// pinned identity triple + all five composition axes map field-for-field; the
// scope_template null-vs-present boundary (roles/SCHEMA.md rule 4 / doc 18 §8) is
// carried by the scope_template_present flag (present=false omits scope_template).
// NEVER emits credential material (D39) — the credential axis is services + mode.
func roleToProto(d sessions.CatalogRoleDocument) *rolesv1.Role {
	role := &rolesv1.Role{
		Name:                 d.Name,
		Version:              d.Version,
		ContentHash:          contentHashBytesFromHex(d.ContentHash),
		SchemaVersion:        d.SchemaVersion,
		Description:          d.Description,
		ScopeTemplatePresent: d.ScopeTemplatePresent,
		WideningsRatified:    d.WideningsRatified,
	}

	// Axis (a): image layers (omit the message for a role with no layers — the
	// `default` role — so absence reads cleanly).
	if len(d.ImageLayers) > 0 {
		role.Image = &rolesv1.ImageLayers{Refs: append([]string(nil), d.ImageLayers...)}
	}
	// Axis (b): skills.
	if len(d.Skills) > 0 {
		role.Skills = &rolesv1.Skills{Install: append([]string(nil), d.Skills...)}
	}
	// Axis (c): the restricted policy projection + the §9 widening posture. Always
	// present (every role declares a posture).
	role.Policy = &rolesv1.RolePolicy{
		Posture:      d.Posture,
		PackFamilies: append([]string(nil), d.PackFamilies...),
		Allowlist:    append([]string(nil), d.Allowlist...),
	}
	// Axis (d): the credential-scope TEMPLATE — set IFF present (the null boundary,
	// roles/SCHEMA.md rule 4 / doc 18 §8). present=false omits the message entirely
	// (the `default` role: null = no narrowing); present=true carries it (services
	// may be empty = mint nothing — the `researcher` role).
	if d.ScopeTemplatePresent {
		role.ScopeTemplate = &rolesv1.CredentialScopeTemplate{
			Services: append([]string(nil), d.ScopeTemplate.Services...),
			Mode:     scopeModeToProto(d.ScopeTemplate.Mode),
		}
	}
	// Axis (e): the opaque runtime overlay (omit for the YAML `null`).
	if d.RuntimeOverlayRef != "" {
		role.Runtime = &rolesv1.RoleRuntime{EntrypointConfigOverlayRef: d.RuntimeOverlayRef}
	}

	return role
}

// scopeModeToProto maps the role/v0 mode strawman string onto the frozen
// roles.v1.ScopeMode enum (roles/SCHEMA.md axis (d); doc 18 §8). An unrecognized
// mode maps to UNSPECIFIED (defensive — the validator pins the vocabulary, so this
// is never reached for a checked-in role).
func scopeModeToProto(mode string) rolesv1.ScopeMode {
	switch mode {
	case "read-only":
		return rolesv1.ScopeMode_SCOPE_MODE_READ_ONLY
	case "read-write":
		return rolesv1.ScopeMode_SCOPE_MODE_READ_WRITE
	default:
		return rolesv1.ScopeMode_SCOPE_MODE_UNSPECIFIED
	}
}

// contentHashBytesFromHex decodes the lowercase-hex role_content_hash (roles/SCHEMA.md
// rule 5) into the raw 32-byte digest the Role.content_hash bytes field carries
// (matching orchestrator.v1.Session.pinned_role_content_hash being bytes). An
// odd-length or non-hex string (never produced by the canonicalizer) yields nil
// rather than a panic — the read path surfaces what it can, never a malformed wire.
func contentHashBytesFromHex(hexStr string) []byte {
	if len(hexStr)%2 != 0 || hexStr == "" {
		return nil
	}
	out := make([]byte, len(hexStr)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexNibble(hexStr[i*2])
		lo, ok2 := hexNibble(hexStr[i*2+1])
		if !ok1 || !ok2 {
			return nil
		}
		out[i] = hi<<4 | lo
	}
	return out
}

// hexNibble decodes one lowercase-hex digit; ok=false on a non-hex byte.
func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}
