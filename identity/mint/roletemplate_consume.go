// SPDX-License-Identifier: Apache-2.0

// CONSUMPTION of the role credential-scope template at grant mint (doc 18 §8,
// doc 19 §11), the consumption point doc 15 §4.1 step 5 reserves.
//
// THE GAP THIS CLOSES. orch10/11 shipped the SEAM (attenuation_template.go:
// RoleAttenuationTemplate + RoleTemplateResolver) and the v0 default resolver
// (roletemplate.go: DefaultRoleTemplateResolver). The fan-out side already
// consumes it offline (BuildChildAttenuation). What was UNBUILT is the
// consumption at MintGrants/IssueGrants (doc 15 §4.1 step 5): doc 18 §8 says the
// role scope_template is "input to grant issuance (doc 16 §5.1)" — it "selects/
// narrows the scope dimension" of the env-spec × services[] envelope. This file
// is that consumption: a pure narrowing filter the issuance leg folds in.
//
// INTERSECTION SEMANTICS (doc 18 §8, roles/SCHEMA.md rule 4). The template can
// only ever NARROW the doc 16 §5.1 env-spec × services[] envelope, never widen:
// the effective request is (env-spec services) ∩ (role scope_template services),
// further intersected against the org registry by the existing deterministic
// lookup. A template naming a scope the org grant set does not contain yields NO
// grant for it (fail-closed) — it cannot conjure a capability the registry never
// defined. Two boundary cases are distinct BY DESIGN:
//   - NULL template  (Present=false): NO narrowing — the full envelope applies
//     unchanged (roles/SCHEMA.md rule 4: "scope_template null = full envelope").
//   - EMPTY services: [] (Present=true, Services len 0): an empty intersection —
//     mints NOTHING (rule 4: "empty services:[] is an empty intersection and
//     mints nothing"). This is the strictest narrowing, NOT the absence of one.
//
// The Go nil-vs-empty-slice distinction is the WRONG carrier for this boundary
// (a nil RoleAttenuationTemplate.Services already means "the role asserts no
// service default" on the fan-out path), so the consumption record carries the
// Present flag EXPLICITLY rather than overloading slice nilness — the null vs
// empty boundary is a typed field, not a representation accident (D52).
//
// NEVER CREDENTIAL MATERIAL (D39, D8). The template carries only the typed
// service vocabulary (attenuation_template.go's RoleAttenuationTemplate) — no
// secret, no token, no caveat string — so consuming it never moves credential
// material toward the VM. It is a pure FILTER over service_ids.
//
// THE RESERVED SEAM (doc 18 §8 sibling cross-link, doc 19 §11). doc 18 §8
// reserves the role scope_template as the source of the INITIAL ATTENUATION for
// the doc 19 attenuable scoped tokens (Biscuit/macaroon): "role-shaped caveats
// (service set, …) attenuate the session token at issue time." Until that token
// pass fully lands the template "degrades gracefully to a grant-narrowing filter
// over the existing D22/D39 machinery" (doc 18 §8). This file IS that graceful
// degradation. The catalog-backed successor to DefaultRoleTemplateResolver
// (doc 18 §8) installs behind the SAME RoleTemplateResolver hook unchanged — the
// consumption here keys on the resolved RoleAttenuationTemplate, not on which
// resolver produced it, so swapping in the real role catalog needs no edit here.
package mint

import (
	"errors"
	"fmt"
	"sort"
)

// RoleScopeTemplate is the TYPED consumption record for the role credential-scope
// template at grant mint (doc 18 §8). It is the grant-mint-side counterpart to
// the fan-out-side RoleAttenuationTemplate: it carries only the SERVICE/SCOPE
// dimension a role's scope_template narrows the doc 16 §5.1 envelope along
// (identity/TTL are governed by the existing IssueGrants machinery, not widened
// by the template), plus the explicit NULL-vs-EMPTY boundary the Go nil slice
// cannot carry. It never holds credential material (D39, D8) — it is a pure
// service_id filter (D52: typed vocabulary, no free-form policy).
type RoleScopeTemplate struct {
	// Present distinguishes the two doc 18 §8 / roles/SCHEMA.md rule 4 boundary
	// cases that a nil/empty slice alone cannot:
	//   Present=false → NULL template: NO narrowing, the full env-spec × services[]
	//     envelope applies unchanged.
	//   Present=true  → the template asserts a scope_template; Services (possibly
	//     empty) is the role's service ceiling and the request is narrowed to its
	//     intersection. Present=true with an EMPTY Services is an empty intersection
	//     → mints nothing (the strictest narrowing, distinct from absent).
	Present bool
	// Services is the role's scope_template service ceiling (the SERVICE/SCOPE axis,
	// doc 16 §5.1) — the set of service_ids the role permits. Meaningful only when
	// Present is true. The effective grant request is intersected against this set:
	// a service not in Services is dropped (the role narrows it out); a service in
	// Services but not in the org registry confers no grant (fail-closed — the
	// template cannot widen the registry). When Present is true and Services is
	// empty, the intersection is empty and nothing is minted.
	Services []string
}

// RoleScopeTemplateFrom adapts a resolved RoleAttenuationTemplate (the doc 19 §11
// seam record, produced by any RoleTemplateResolver) into the grant-mint
// consumption record. ok is the resolver's recognition flag:
//
//   - ok=false (UNKNOWN role_ref, or no resolver / empty role_ref): the role
//     contributes NO narrowing — a NULL template (Present=false, full envelope).
//     This is the v0/de-risking-safe default: an unrecognized role does not
//     fail-close the whole mint, it simply asserts no role ceiling (doc 19 §11:
//     "fail-OPEN on the role axis is safe because the substrate fails any
//     resulting widening closed regardless" — and here the registry intersection
//     is that floor: the role can never ADD a service the env-spec/registry lack).
//   - ok=true with a NIL Services: the role is KNOWN and asserts NO service
//     ceiling (the recorded de-risking `default` role, roles/SCHEMA.md rule 4) →
//     a NULL template (Present=false, full envelope). The empty
//     RoleAttenuationTemplate{} the DefaultRoleTemplateResolver yields lands here.
//   - ok=true with a NON-NIL Services (possibly empty): the role asserts an
//     explicit scope_template → Present=true, narrowing applies. A non-nil but
//     EMPTY Services is the "empty services:[] mints nothing" boundary case.
//
// The nil-vs-non-nil split on a KNOWN role's Services is exactly the doc 18 §8
// boundary: a role with `scope_template: null` resolves to nil Services (no
// narrowing); a role with `scope_template: { services: [] }` resolves to a
// non-nil empty Services (empty intersection, mints nothing). A real catalog
// resolver (doc 18 §8 successor) preserves that nil/non-nil distinction when it
// builds the RoleAttenuationTemplate, so this adapter needs no change for it.
func RoleScopeTemplateFrom(tmpl RoleAttenuationTemplate, ok bool) RoleScopeTemplate {
	if !ok || tmpl.Services == nil {
		// Unknown role, or a known role asserting no service ceiling → NULL template
		// (full envelope, no narrowing).
		return RoleScopeTemplate{Present: false}
	}
	return RoleScopeTemplate{Present: true, Services: tmpl.Services}
}

// resolveRoleScopeTemplate resolves a role_ref through the seam hook into the
// grant-mint consumption record. A nil resolver or empty role_ref yields a NULL
// template (no narrowing) — the v0 posture (no resolver installed) and the bare
// "" ref both degrade to the full envelope, never fail-closed (the registry
// intersection in IssueGrants is the floor that keeps even an unfiltered request
// from widening past the org capabilities).
func resolveRoleScopeTemplate(roleRef string, resolver RoleTemplateResolver) RoleScopeTemplate {
	if roleRef == "" || resolver == nil {
		return RoleScopeTemplate{Present: false}
	}
	tmpl, ok := resolver(roleRef)
	return RoleScopeTemplateFrom(tmpl, ok)
}

// errUnknownRoleScope reports a role scope_template that names a service the org
// grant set (env-spec × registry) does not contain — the fail-closed, NAMED
// outcome the brief requires. It is returned by IssueGrantsScoped only when the
// caller opts into strict reporting (StrictUnknownScope); the default issuance
// path drops such services silently (the registry intersection already fails them
// closed — they confer no grant), so a role naming a scope the org lacks NEVER
// widens, it only ever fails to mint for that scope.
var errUnknownRoleScope = errors.New("mint: role scope_template names a service absent from the org grant set")

// UnknownRoleScopeError is the typed, NAMED fail-closed error for the strict
// consumption path: a role scope_template named a service that the resolved
// org grant set (env-spec ∩ registry) does not contain, so no grant could be
// minted for it. The named service is carried so the log/audit shape identifies
// exactly which template entry failed closed (doc 18 §8: the template "selects/
// narrows" — a selection of a non-existent capability is a fail-closed event, not
// a widening). The grant set the template narrows is NEVER widened by this — the
// service simply yields no grant; the strict mode surfaces it as an error instead
// of a silent drop so a mis-specified role is loud at mint time, not silent.
type UnknownRoleScopeError struct {
	// Service is the service_id the role scope_template named but the org grant set
	// (env-spec × registry) did not contain.
	Service string
	// RoleRef is the role_ref whose scope_template named the absent service (for the
	// audit/log join — which role's template was mis-specified).
	RoleRef string
}

func (e *UnknownRoleScopeError) Error() string {
	return fmt.Sprintf("%v: service %q named by role %q", errUnknownRoleScope, e.Service, e.RoleRef)
}

// Unwrap exposes the sentinel so errors.Is(err, errUnknownRoleScope) holds for
// the typed error (the named fail-closed class is matchable without string
// scraping).
func (e *UnknownRoleScopeError) Unwrap() error { return errUnknownRoleScope }

// ScopedEnvSpec narrows an EnvSpec's requested services by a role scope_template,
// returning the narrowed EnvSpec the deterministic IssueGrants leg then
// intersects against the org registry. This is the doc 15 §4.1 step 5 consumption
// in pure form:
//
//   - NULL template (Present=false): returns env UNCHANGED (full envelope, no
//     narrowing). A copy is NOT forced — the env-spec is byte-identical to the
//     input, so the existing orch6/7 GrantRef goldens stay byte-identical when no
//     template narrows (the default v0 path).
//   - Present=true: the requested services are intersected with the template's
//     Services. The result is ⊆ the original request (intersection is monotone),
//     so issuance can only ever NARROW. An EMPTY template (Present=true, no
//     Services) yields an EMPTY service request → mints nothing.
//
// TTLOverrides ride through unchanged (the template narrows only the SERVICE/SCOPE
// axis — TTL is the existing IssueGrants clamp's concern, doc 16 §5.1, never
// widened here). The narrowed slice is deterministic (the intersect primitive
// preserves the request's first-seen order); IssueGrants sorts it regardless.
func ScopedEnvSpec(env EnvSpec, tmpl RoleScopeTemplate) EnvSpec {
	if !tmpl.Present {
		// NULL template: full envelope, byte-identical request (no narrowing).
		return env
	}
	// Present (possibly empty): intersect the request with the role ceiling. An
	// empty ceiling yields an empty (non-nil-irrelevant) request → mints nothing.
	narrowed := intersect(env.Services, tmpl.Services)
	return EnvSpec{
		Services:     narrowed,
		TTLOverrides: env.TTLOverrides,
	}
}

// IssueGrantsScoped is the role-template-aware grant-issuance leg (doc 18 §8 /
// doc 15 §4.1 step 5): it resolves the role's scope_template through the seam
// hook, narrows the env spec by INTERSECTION, then runs the existing
// deterministic IssueGrants over the narrowed envelope. The role template can
// only NARROW (a service it omits is dropped; a service it names that the env
// spec did not request is never added — intersection is bounded by the request),
// and it can NEVER widen past the org registry (IssueGrants's registry lookup is
// the floor: a service the registry lacks confers no grant regardless).
//
// strict controls the NAMED fail-closed reporting (the brief's "unknown-scope
// fail-closed named"): when strict is true and the role template names a service
// that the resolved org grant set (env-spec ∩ registry) does NOT contain, the
// call returns an UnknownRoleScopeError identifying the service and role_ref —
// the mis-specified role is loud at mint time. When strict is false (the default,
// orch6/7-compatible path), such a service is silently dropped (it already
// confers no grant). EITHER WAY the grant set is never widened: strict mode only
// changes whether the absent-capability case is an error or a silent no-grant.
//
// resolver may be nil (v0: no role catalog installed → NULL template → full
// envelope, byte-identical to a bare IssueGrants). roleRef may be empty (same).
func (s *Shim) IssueGrantsScoped(sessionUUID, roleRef string, env EnvSpec, resolver RoleTemplateResolver, strict bool) ([]Grant, error) {
	tmpl := resolveRoleScopeTemplate(roleRef, resolver)
	scoped := ScopedEnvSpec(env, tmpl)

	grants, err := s.IssueGrants(sessionUUID, scoped)
	if err != nil {
		return nil, err
	}

	if strict && tmpl.Present {
		// A role-named service that survived the env-spec intersection but minted no
		// grant (the registry lacked it) is the fail-closed NAMED case. Walk the
		// template's services ∩ env request and assert each one produced a grant.
		granted := make(map[string]struct{}, len(grants))
		for _, g := range grants {
			granted[g.ServiceID] = struct{}{}
		}
		// The set the template actually selected from the request (template ∩ request):
		// only these could have been expected to mint. A template service the request
		// never asked for is not a fail-closed case — the request bounds the envelope.
		selected := intersect(tmpl.Services, env.Services)
		var missing []string
		for _, svc := range selected {
			if _, ok := granted[svc]; !ok {
				missing = append(missing, svc)
			}
		}
		if len(missing) > 0 {
			// Deterministic, named: report the lexicographically-first absent service
			// (stable across runs for the audit/log shape; the full set is recoverable
			// by re-running, and the first is sufficient to name the mis-spec).
			sort.Strings(missing)
			return nil, &UnknownRoleScopeError{Service: missing[0], RoleRef: roleRef}
		}
	}

	return grants, nil
}

// MintGrantsScoped is the role-template-aware MintGrants surface (doc 16 §5.1 +
// doc 18 §8): it issues the role-narrowed grant set (IssueGrantsScoped) then
// mints the per-service placeholder tokens exactly as MintGrants does. The role
// template narrows the GrantSet's Grants (and therefore its Placeholders) by
// intersection — never widens. A NULL template (no resolver / unknown role /
// `default` role) yields a GrantSet BYTE-IDENTICAL to a bare MintGrants (the v0
// path), so the orch6/7 goldens stay green. An EMPTY template (Present, no
// services) mints an EMPTY GrantSet.
//
// strict carries the named fail-closed reporting through to the placeholder mint
// (see IssueGrantsScoped): a role naming a service the org lacks returns an
// UnknownRoleScopeError instead of a partial GrantSet, so the placeholder set is
// never built over a mis-specified role.
func (s *Shim) MintGrantsScoped(req MintGrantsRequest, roleRef string, resolver RoleTemplateResolver, strict bool) (*GrantSet, error) {
	grants, err := s.IssueGrantsScoped(req.SessionUUID, roleRef, req.Env, resolver, strict)
	if err != nil {
		return nil, err
	}
	return s.mintPlaceholdersFor(req.SessionUUID, grants), nil
}

// mintPlaceholdersFor builds the per-service placeholder tokens for an already-
// issued grant slice and registers them on the session record — the placeholder
// leg of MintGrants factored out so the scoped and unscoped surfaces share ONE
// placeholder-minting path (no drift between MintGrants and MintGrantsScoped).
// It is identical in effect to MintGrants's inline loop: each placeholder is
// registered under its service_id so Validate accepts it for that service and
// nothing else.
func (s *Shim) mintPlaceholdersFor(sessionUUID string, grants []Grant) *GrantSet {
	out := &GrantSet{Grants: grants}
	s.mu.Lock()
	rec := s.sessions[sessionUUID]
	if rec != nil && rec.placeholders == nil {
		rec.placeholders = make(map[string]string)
	}
	key := s.placeholderKey
	s.mu.Unlock()

	for _, g := range grants {
		tok := mintPlaceholder(key, sessionUUID, g)
		out.Placeholders = append(out.Placeholders, PlaceholderToken{
			ServiceID: g.ServiceID,
			Grant:     g,
			Token:     tok,
		})
		s.mu.Lock()
		if rec != nil {
			if rec.placeholders == nil {
				rec.placeholders = make(map[string]string)
			}
			rec.placeholders[g.ServiceID] = tok
		}
		s.mu.Unlock()
	}
	return out
}
