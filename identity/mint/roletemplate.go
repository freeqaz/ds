// SPDX-License-Identifier: Apache-2.0

// The doc 19 §11 / doc 18 §8 role-template RESOLVER — the hook the orch10
// attenuation-template wave DEFERRED (v0 shipped the seam type and a nil hook;
// this installs the default resolver behind it).
//
// THE SEAM (recap, owned by attenuation_template.go): doc 19 §11 reserves exactly
// one coupling between this design and the agent-roles design — a role MAY carry a
// default token-scope / attenuation template keyed by role_ref, consumed at
// doc 15 §4.1 step 5. RoleTemplateResolver (attenuation_template.go) is that hook:
// role_ref → (RoleAttenuationTemplate, ok). BuildChildAttenuation folds the
// resolved template's narrowing in. Role SEMANTICS, authority, and lifecycle are
// entirely doc 18's; this file "consumes the template and designs nothing further"
// (doc 19 §11) — it ships ONLY the v0 default resolver, no role engine.
//
// THE RECORDED DE-RISKING DEFAULT (doc 18 §7/§8, roles/SCHEMA.md rule 4). A create
// without an explicit role records `default@<vN>`, never null (doc 18 §7:
// "Default is recorded, not null"). The `default` role's scope_template is `null`
// — "no narrowing — the full doc 16 §5.1 env-spec × services[] envelope applies
// unchanged" (roles/SCHEMA.md rule 4). So the de-risking default a v0 resolver
// yields is an EMPTY RoleAttenuationTemplate (ok=true): the role is KNOWN and
// asserts NO additional narrowing — distinct from an unknown role_ref (ok=false,
// also no narrowing, but for the "this resolver doesn't recognize the ref"
// reason). Both are safe: the substrate fails any resulting widening closed
// regardless (doc 19 §11). NO free-form Datalog, NO string-typed caveat — the
// resolver only ever yields the four typed grant-model dimensions (D52).
package mint

import "strings"

// defaultRoleName is the recorded default role (doc 18 §7: a create without an
// explicit role_ref records `default@<vN>`, never null). The de-risking default
// template is keyed on this name (any version) — the `default` role narrows
// nothing (roles/SCHEMA.md rule 4: scope_template null = full envelope).
const defaultRoleName = "default"

// roleNameOf extracts the role NAME from a `name@version` role_ref (doc 18 §7's
// recorded form, e.g. `default@v3`). A ref with no `@` is taken whole as the name;
// an empty ref yields an empty name. The resolver keys on the name only — the
// de-risking default applies to every version of `default`, and version/content-
// hash pinning is doc 18's concern (the create records the pinned triple), not the
// attenuation resolver's (doc 19 §11: "designs nothing further").
func roleNameOf(roleRef string) string {
	if i := strings.IndexByte(roleRef, '@'); i >= 0 {
		return roleRef[:i]
	}
	return roleRef
}

// DefaultRoleTemplateResolver is the v0 role-template resolver (doc 19 §11): it
// recognizes ONLY the recorded de-risking default role (`default@<vN>`) and yields
// its template — an EMPTY RoleAttenuationTemplate, ok=true (the `default` role
// narrows nothing, roles/SCHEMA.md rule 4). Every other role_ref is UNKNOWN to
// this v0 resolver (ok=false): doc 18 installs the real catalog-backed resolver
// WITHOUT changing this shape (doc 19 §11). An empty role_ref is also unknown
// (ok=false) — the caller passes the recorded `default@<vN>`, not a bare "".
//
// Returning ok=true with an empty template for `default` (vs ok=false for an
// unknown ref) is deliberate: it makes "the recorded default role contributed no
// narrowing" an explicit, auditable resolver outcome distinct from "this resolver
// did not recognize the ref" — the doc 18 §7 "recorded, not null" posture carried
// into the attenuation seam. Both contribute no narrowing; the substrate fails any
// widening closed regardless (doc 19 §11), so the resolver is never the trust
// boundary for the monotonic-narrowing property.
func DefaultRoleTemplateResolver(roleRef string) (RoleAttenuationTemplate, bool) {
	if roleNameOf(roleRef) == defaultRoleName {
		// The recorded de-risking default: KNOWN role, NO narrowing (the full
		// envelope, roles/SCHEMA.md rule 4). An empty template folds nothing in.
		return RoleAttenuationTemplate{}, true
	}
	return RoleAttenuationTemplate{}, false
}

// compile-time assertion: the default resolver satisfies the doc 19 §11 hook.
var _ RoleTemplateResolver = DefaultRoleTemplateResolver
