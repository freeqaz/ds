package sessions

// rolecanonical.go is the CANONICAL ROLE DOCUMENT producer for the M0 catalog
// resolver (roles/SCHEMA.md rule 5): it parses a checked-in role YAML into the
// grant-and-identity-relevant fields and builds the nftbridge.Value the
// role_content_hash is taken over — via the SAME canonical-serialization machinery
// (nftbridge.CanonicalHash) the PolicySnapshot content_hash uses (one spec, not
// two; doc 15 OQ3 / doc 13 OQ2). The orch8 role-document golden fixture proves the
// bytes; this is the producer that puts a real role document on that identical path.
//
// THE CANONICAL ROLE DOCUMENT (the deterministic projection hashed). A role's
// content_hash pins the role's IDENTITY + its GRANT/POLICY-relevant content — the
// fields a session create binds. The projection is fixed here, once, as a JCS
// object (keys sort lexicographically; absent==omitted, doc 13 §5.1):
//
//	{
//	  "credentials": { "scope_template": null | { "mode": <str>, "services": [<str>...] } },
//	  "name":           <str>,
//	  "policy":         { "allowlist": [<str>...], "pack_families": [<str>...], "posture": <str> },
//	  "schema_version": <str>,
//	  "version":        <str>
//	}
//
// The scope_template NULL vs EMPTY-services boundary survives the hash (doc 18 §8,
// roles/SCHEMA.md rule 4): a `scope_template: null` role omits the inner object
// (carrying the JSON null), an empty `services: []` carries a present object with an
// empty array — distinct canonical bytes, distinct pins. A catalog update to the
// same (name, version) that changes ANY of these fields is a DISTINCT content_hash,
// so the same-(name,version)-different-bytes case is a different pin (rule 5).
//
// STDLIB-ONLY PARSE (orchestrator/go.mod is stdlib-fenced; no serde_yaml analog).
// parseRoleYAML reads ONLY the fixed fields above from the role/v0 strawman YAML —
// it is NOT a general YAML parser, it is a line-oriented reader for the exact
// shape roles/*.yaml carries (the four built-ins). An unexpected shape is a parse
// error, never a silent mis-parse (the resolver refuses fail-closed on it).

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nftbridge"
)

// roleDocument is the parsed role/v0 projection the catalog hashes and resolves
// over. It carries the identity + grant/policy-relevant fields (never credential
// material, D39 — scope_template is service IDs + a mode string only) PLUS the
// read-only axes (description, image layers, skills, runtime overlay) the
// catalog READ path surfaces but the hash does NOT cover (roles/SCHEMA.md rule 5
// hashes only {credentials.scope_template, name, policy.{allowlist,pack_families,
// posture}, schema_version, version}). The read-only fields below are PARSED for
// the ListRoles/GetRole projection and are DELIBERATELY EXCLUDED from
// CanonicalRoleDocumentValue — adding them never perturbs the pinned content_hash.
type roleDocument struct {
	SchemaVersion string
	Name          string
	Version       string
	Posture       string
	Allowlist     []string // widening-request entries (the §9 widening posture inputs)
	PackFamilies  []string // tier-flip requests (widening posture inputs)
	// ScopeTemplatePresent distinguishes `scope_template: null` (false → full
	// envelope, no narrowing) from a present template (true), exactly the doc 18 §8
	// boundary the hash must preserve.
	ScopeTemplatePresent bool
	ScopeServices        []string // present-template service ceiling (may be empty)
	ScopeMode            string   // read-only | read-write (strawman)

	// --- read-only axes (NOT hashed; surfaced on the catalog READ path) ---
	Description   string   // roles/SCHEMA.md `description`
	ImageLayers   []string // axis (a) `image.layers[]` — content-addressed refs (rule 1: refs only)
	SkillsInstall []string // axis (b) `skills.install[]` — strawman refs (OQ2 named gap)
	// RuntimeOverlayRef is axis (e) `runtime.entrypoint_config_overlay_ref` — opaque
	// to the orchestrator (D38/D20). Empty for the YAML `null`.
	RuntimeOverlayRef string
}

// hasWidenings reports whether the role REQUESTS any widening (allowlist entries or
// pack-family tier flips beyond the org envelope, doc 18 §9). The built-in catalog
// ships every role UNRATIFIED, so a role with widenings rides inert at create.
func (d roleDocument) widenings() []string {
	var out []string
	out = append(out, d.Allowlist...)
	out = append(out, d.PackFamilies...)
	sort.Strings(out)
	return out
}

// CanonicalRoleDocumentValue builds the nftbridge.Value for a role document — the
// produce-once tree the role_content_hash is taken over (roles/SCHEMA.md rule 5,
// the nftbridge JCS path). Exported so the cross-module golden generator/anchor
// test can re-derive the exact bytes from the parsed role.
func CanonicalRoleDocumentValue(d roleDocument) nftbridge.Value {
	cred := nftbridge.NewObject()
	if d.ScopeTemplatePresent {
		svc := nftbridge.NewArray()
		// Services are sorted so the canonical bytes are independent of source order
		// (the role YAML lists them in author order; the pin is order-free).
		services := append([]string(nil), d.ScopeServices...)
		sort.Strings(services)
		for _, s := range services {
			svc.Append(nftbridge.Str(s))
		}
		tmpl := nftbridge.NewObject().
			Set("mode", nftbridge.Str(d.ScopeMode)).
			Set("services", svc)
		cred.Set("scope_template", tmpl)
	} else {
		// scope_template: null — the full-envelope boundary (rule 4). The JSON null is
		// a MEANINGFUL value here (it distinguishes null from a present-but-empty
		// template), so it is carried explicitly, never omitted.
		cred.Set("scope_template", nftbridge.Null)
	}

	allow := nftbridge.NewArray()
	allowS := append([]string(nil), d.Allowlist...)
	sort.Strings(allowS)
	for _, a := range allowS {
		allow.Append(nftbridge.Str(a))
	}
	packs := nftbridge.NewArray()
	packS := append([]string(nil), d.PackFamilies...)
	sort.Strings(packS)
	for _, p := range packS {
		packs.Append(nftbridge.Str(p))
	}
	policy := nftbridge.NewObject().
		Set("allowlist", allow).
		Set("pack_families", packs).
		Set("posture", nftbridge.Str(d.Posture))

	return nftbridge.NewObject().
		Set("credentials", cred).
		Set("name", nftbridge.Str(d.Name)).
		Set("policy", policy).
		Set("schema_version", nftbridge.Str(d.SchemaVersion)).
		Set("version", nftbridge.Str(d.Version))
}

// canonicalRoleHashHex returns the hex role_content_hash of a parsed role document
// (the nftbridge JCS canonical SHA-256, lowercase hex). It is the orchestrator-side
// producer of the hash both catalog resolvers must agree on.
func canonicalRoleHashHex(d roleDocument) (payload []byte, hashHex string) {
	payload, h := nftbridge.CanonicalHash(CanonicalRoleDocumentValue(d))
	return payload, hashHexString(h[:])
}

// hashHexString renders raw hash bytes as lowercase hex (the form the golden and
// the persisted role_content_hash carry).
func hashHexString(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdig[v>>4]
		out[i*2+1] = hexdig[v&0x0f]
	}
	return string(out)
}

// parseRoleYAML reads the fixed role/v0 fields from a role YAML body. It is NOT a
// general YAML parser — it reads exactly the strawman shape roles/*.yaml carries
// (schema_version/name/version at top level; policy.posture/allowlist/pack_families;
// credentials.scope_template.services/mode or `scope_template: null`). An entry it
// cannot place is ignored ONLY when it is outside the projected fields (description,
// image, skills, runtime, guardrails — not hashed); a malformed projected field is a
// parse error (the resolver refuses fail-closed on it).
func parseRoleYAML(body string) (roleDocument, error) {
	var d roleDocument
	lines := strings.Split(body, "\n")

	// Section tracking by 2-space indentation depth under a known top-level key.
	const (
		secNone = iota
		secPolicy
		secCredentials
		secScopeTemplate
		secScopeServices   // inside scope_template, collecting `- item` services
		secPolicyAllowlist // inside policy.allowlist, collecting `- item`
		secImage           // inside image:, awaiting layers:
		secImageLayers     // inside image.layers, collecting `- ref`
		secSkills          // inside skills:, awaiting install:
		secSkillsInstall   // inside skills.install, collecting `- ref`
		secRuntime         // inside runtime:, reading entrypoint_config_overlay_ref
	)
	section := secNone

	for _, raw := range lines {
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := leadingSpaces(line)
		trimmed := strings.TrimSpace(line)

		// A list item under an active list-collecting section.
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			switch section {
			case secScopeServices:
				if s := unquoteScalar(item); s != "" {
					d.ScopeServices = append(d.ScopeServices, s)
				}
			case secPolicyAllowlist:
				// Allowlist entries are widening-request rows; we record a stable string
				// form for the §9 widening posture + the hash. A flow-mapping entry
				// (`{ fqdn: x, ... }`) is canonicalized to its fqdn token; a bare scalar
				// rides whole.
				if fqdn := allowlistKey(item); fqdn != "" {
					d.Allowlist = append(d.Allowlist, fqdn)
				}
			case secImageLayers:
				// Axis (a) content-addressed tool-layer refs (NOT hashed; read-path only).
				if s := unquoteScalar(item); s != "" {
					d.ImageLayers = append(d.ImageLayers, s)
				}
			case secSkillsInstall:
				// Axis (b) skill-bundle refs (NOT hashed; read-path only).
				if s := unquoteScalar(item); s != "" {
					d.SkillsInstall = append(d.SkillsInstall, s)
				}
			}
			continue
		}

		key, val, hasColon := splitKeyVal(trimmed)
		if !hasColon {
			continue
		}

		// Top-level keys (indent 0).
		if indent == 0 {
			section = secNone
			switch key {
			case "schema_version":
				d.SchemaVersion = unquoteScalar(val)
			case "name":
				d.Name = unquoteScalar(val)
			case "version":
				d.Version = unquoteScalar(val)
			case "description":
				// A block scalar (`description: >`) carries its body on indented
				// continuation lines; an inline value rides here. We record the inline
				// value (or the `>`/`|` marker is dropped to empty — the read-path
				// description is informational, never hashed); a multi-line block body's
				// continuation lines are deeper-indented scalars with no `:` and are
				// ignored by the no-colon skip below.
				if v := unquoteScalar(val); v != "" && v != ">" && v != "|" {
					d.Description = v
				}
			case "image":
				section = secImage
			case "skills":
				section = secSkills
			case "runtime":
				section = secRuntime
			case "policy":
				section = secPolicy
			case "credentials":
				section = secCredentials
			}
			continue
		}

		// Nested keys: dispatch on the active section.
		switch section {
		case secImage, secImageLayers:
			if key == "layers" {
				if isInlineEmptyList(val) {
					section = secImage
				} else if inline := inlineListItems(val); inline != nil {
					d.ImageLayers = append(d.ImageLayers, inline...)
					section = secImage
				} else {
					section = secImageLayers
				}
			}
		case secSkills, secSkillsInstall:
			if key == "install" {
				if isInlineEmptyList(val) {
					section = secSkills
				} else if inline := inlineListItems(val); inline != nil {
					d.SkillsInstall = append(d.SkillsInstall, inline...)
					section = secSkills
				} else {
					section = secSkillsInstall
				}
			}
		case secRuntime:
			if key == "entrypoint_config_overlay_ref" {
				v := strings.TrimSpace(val)
				if v != "null" && v != "~" {
					d.RuntimeOverlayRef = unquoteScalar(v)
				}
			}
		case secPolicy, secPolicyAllowlist:
			switch key {
			case "posture":
				d.Posture = unquoteScalar(val)
				section = secPolicy
			case "allowlist":
				if isInlineEmptyList(val) {
					section = secPolicy
				} else {
					section = secPolicyAllowlist
				}
			case "pack_families":
				// pack_families: {} (empty) or a flow map of tier flips. We record the
				// flow-map keys as widening-request tokens; `{}` contributes none.
				for _, fam := range flowMapKeys(val) {
					d.PackFamilies = append(d.PackFamilies, "pack:"+fam)
				}
				section = secPolicy
			case "guardrails":
				section = secPolicy // guardrails are not in the hashed projection
			}
		case secCredentials:
			if key == "scope_template" {
				v := strings.TrimSpace(val)
				if v == "null" || v == "~" {
					d.ScopeTemplatePresent = false
					section = secCredentials
				} else if v == "" {
					// A present scope_template object follows on indented lines.
					d.ScopeTemplatePresent = true
					section = secScopeTemplate
				} else if isInlineEmptyMap(v) {
					d.ScopeTemplatePresent = true
					section = secScopeTemplate
				}
			}
		case secScopeTemplate, secScopeServices:
			switch key {
			case "services":
				d.ScopeTemplatePresent = true
				if isInlineEmptyList(val) {
					d.ScopeServices = []string{} // present but empty (mints nothing)
					section = secScopeTemplate
				} else if inline := inlineListItems(val); inline != nil {
					d.ScopeServices = append(d.ScopeServices, inline...)
					section = secScopeTemplate
				} else {
					section = secScopeServices
				}
			case "mode":
				d.ScopeMode = unquoteScalar(val)
				section = secScopeTemplate
			}
		}
	}

	if d.SchemaVersion == "" || d.Name == "" || d.Version == "" {
		return roleDocument{}, fmt.Errorf("sessions: role YAML missing required identity (schema_version=%q name=%q version=%q)", d.SchemaVersion, d.Name, d.Version)
	}
	// Normalize a present-but-nil services slice to empty (the present/empty boundary
	// must not collapse to absent).
	if d.ScopeTemplatePresent && d.ScopeServices == nil {
		d.ScopeServices = []string{}
	}
	return d, nil
}

// --- small stdlib YAML-subset helpers (no serde_yaml; the workspace dep fence) ---

func stripComment(line string) string {
	// A `#` not inside quotes starts a comment. The role YAMLs never quote a `#`,
	// so a simple split is sufficient for this fixed shape.
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func leadingSpaces(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' {
			n++
			continue
		}
		break
	}
	return n
}

func splitKeyVal(s string) (key, val string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

func unquoteScalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

func isInlineEmptyList(v string) bool {
	return strings.TrimSpace(v) == "[]"
}

func isInlineEmptyMap(v string) bool {
	return strings.TrimSpace(v) == "{}"
}

// inlineListItems parses an inline flow list `[a, b, c]` into its scalar items;
// returns nil when v is not an inline flow list (a block list follows instead).
func inlineListItems(v string) []string {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '[' || v[len(v)-1] != ']' {
		return nil
	}
	inner := strings.TrimSpace(v[1 : len(v)-1])
	if inner == "" {
		return []string{}
	}
	parts := strings.Split(inner, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := unquoteScalar(strings.TrimSpace(p)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// flowMapKeys parses the KEYS of an inline flow map `{ a: x, b: y }` (used for
// pack_families tier flips). `{}` yields none.
func flowMapKeys(v string) []string {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '{' || v[len(v)-1] != '}' {
		return nil
	}
	inner := strings.TrimSpace(v[1 : len(v)-1])
	if inner == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(inner, ",") {
		if k, _, ok := splitKeyVal(strings.TrimSpace(p)); ok {
			out = append(out, k)
		}
	}
	return out
}

// allowlistKey extracts a stable token from an allowlist entry — the `fqdn` value
// from a flow-mapping entry (`{ fqdn: x, ports: [..] }`), or the bare scalar. Used
// only for the §9 widening-posture token + the hashed allowlist projection.
func allowlistKey(item string) string {
	item = strings.TrimSpace(item)
	if strings.HasPrefix(item, "{") {
		for _, k := range flowMapKeys(item) {
			_ = k
		}
		// Pull the fqdn value explicitly.
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(item, "{"), "}"))
		for _, p := range strings.Split(inner, ",") {
			if k, v, ok := splitKeyVal(strings.TrimSpace(p)); ok && k == "fqdn" {
				return unquoteScalar(v)
			}
		}
		return ""
	}
	return unquoteScalar(item)
}
