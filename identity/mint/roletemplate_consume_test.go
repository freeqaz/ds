// SPDX-License-Identifier: Apache-2.0

// Consumption tests for the role credential-scope template at grant mint
// (doc 18 §8, doc 19 §11, doc 15 §4.1 step 5). The template can only ever NARROW
// the env-spec × services[] envelope by intersection; the boundary cases (NULL =
// full envelope, empty services:[] = mint nothing) are distinct by design; a
// service named by the template but absent from the org grant set fails closed,
// named, never widening. Everything synthetic (D50); the clock is pinned.
package mint

import (
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"
)

// serviceIDs extracts the sorted service_id set from a grant slice — the stable
// shape the narrowing/no-widening assertions compare on.
func serviceIDs(grants []Grant) []string {
	if len(grants) == 0 {
		return nil
	}
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		out = append(out, g.ServiceID)
	}
	sort.Strings(out)
	return out
}

// roleResolver builds a RoleTemplateResolver over a fixed role_ref → template map
// for the consumption tests. A ref absent from the map is UNKNOWN (ok=false). A
// ref mapped to a non-nil (possibly empty) Services asserts a scope_template;
// mapping to RoleAttenuationTemplate{} (nil Services) is the de-risking `default`
// shape (known, no narrowing).
func roleResolver(m map[string]RoleAttenuationTemplate) RoleTemplateResolver {
	return func(roleRef string) (RoleAttenuationTemplate, bool) {
		t, ok := m[roleRef]
		return t, ok
	}
}

// TestScopedEnvSpec_NarrowsByIntersection is the core doc 18 §8 property: a
// present template intersects the request, a NULL template returns it unchanged.
func TestScopedEnvSpec_NarrowsByIntersection(t *testing.T) {
	base := EnvSpec{
		Services:     []string{"github", "npm", "s3"},
		TTLOverrides: map[string]time.Duration{"github": time.Minute},
	}
	cases := []struct {
		name string
		tmpl RoleScopeTemplate
		want []string // the narrowed Services (intersection order = request order)
	}{
		{
			name: "null template = full envelope (unchanged)",
			tmpl: RoleScopeTemplate{Present: false},
			want: []string{"github", "npm", "s3"},
		},
		{
			name: "present template narrows to its intersection",
			tmpl: RoleScopeTemplate{Present: true, Services: []string{"npm", "github"}},
			want: []string{"github", "npm"},
		},
		{
			name: "present template can only narrow — a service it names that the request lacks is NOT added",
			tmpl: RoleScopeTemplate{Present: true, Services: []string{"github", "gcs"}},
			want: []string{"github"},
		},
		{
			name: "empty services:[] = empty intersection (mints nothing)",
			tmpl: RoleScopeTemplate{Present: true, Services: []string{}},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScopedEnvSpec(base, tc.tmpl)
			gotS := append([]string(nil), got.Services...)
			sort.Strings(gotS)
			wantS := append([]string(nil), tc.want...)
			sort.Strings(wantS)
			if !reflect.DeepEqual(gotS, wantS) {
				t.Fatalf("narrowed services = %v, want %v", gotS, tc.want)
			}
			// TTLOverrides ride through unchanged on every path (template narrows only
			// the SERVICE/SCOPE axis, never the TTL axis).
			if !reflect.DeepEqual(got.TTLOverrides, base.TTLOverrides) {
				t.Fatalf("TTLOverrides mutated: got %v, want %v", got.TTLOverrides, base.TTLOverrides)
			}
		})
	}
}

// TestScopedEnvSpec_NullTemplateIsIdentity proves a NULL template returns the
// env-spec UNCHANGED (the same value), so the v0/default path is byte-identical
// to a bare IssueGrants and the orch6/7 goldens stay green.
func TestScopedEnvSpec_NullTemplateIsIdentity(t *testing.T) {
	env := EnvSpec{Services: []string{"github", "npm"}}
	got := ScopedEnvSpec(env, RoleScopeTemplate{Present: false})
	if !reflect.DeepEqual(got, env) {
		t.Fatalf("null template should be identity: got %+v, want %+v", got, env)
	}
}

// TestIssueGrantsScoped_NarrowingApplied is the end-to-end NARROWING property at
// MintGrants (doc 15 §4.1 step 5): the role template narrows the issued grant set
// to the intersection of the env spec, the role ceiling, AND the org registry.
func TestIssueGrantsScoped_NarrowingApplied(t *testing.T) {
	shim := newGrantShim(t)
	const sess = "session-narrow"
	// env requests github + npm (both registered); role ceiling allows only github.
	env := EnvSpec{Services: []string{"github", "npm"}}
	res := roleResolver(map[string]RoleAttenuationTemplate{
		"reviewer@v1": {Services: []string{"github"}},
	})
	grants, err := shim.IssueGrantsScoped(sess, "reviewer@v1", env, res, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := serviceIDs(grants); !reflect.DeepEqual(got, []string{"github"}) {
		t.Fatalf("role-narrowed grants = %v, want [github] (npm narrowed out)", got)
	}
}

// TestIssueGrantsScoped_NeverWidens is the load-bearing monotone property: the
// scoped grant set is ALWAYS ⊆ the unscoped grant set for the same env spec — the
// template can subtract services but never add one, for ANY template shape.
func TestIssueGrantsScoped_NeverWidens(t *testing.T) {
	env := EnvSpec{Services: []string{"github", "npm"}}
	res := roleResolver(map[string]RoleAttenuationTemplate{
		// A role naming services OUTSIDE the env request (gcs) and one inside it.
		"wide@v1": {Services: []string{"github", "gcs", "s3"}},
		// The de-risking default: known, nil Services = no narrowing.
		"default@v2": {},
	})
	for _, roleRef := range []string{"wide@v1", "default@v2", "unknown@v9", ""} {
		t.Run("role="+roleRef, func(t *testing.T) {
			shim := newGrantShim(t)
			const sess = "session-widen"
			// Baseline: the UNSCOPED grant set for this env spec.
			base, err := shim.IssueGrants(sess, env)
			if err != nil {
				t.Fatal(err)
			}
			baseSet := make(map[string]struct{}, len(base))
			for _, g := range base {
				baseSet[g.ServiceID] = struct{}{}
			}
			// Fresh shim so the scoped issuance is independent of the baseline state.
			shim2 := newGrantShim(t)
			scoped, err := shim2.IssueGrantsScoped("session-widen-2", roleRef, env, res, false)
			if err != nil {
				t.Fatal(err)
			}
			for _, g := range scoped {
				if _, ok := baseSet[g.ServiceID]; !ok {
					t.Fatalf("role %q WIDENED the grant set: %q not in the unscoped set %v",
						roleRef, g.ServiceID, serviceIDs(base))
				}
			}
		})
	}
}

// TestIssueGrantsScoped_NullTemplateFullEnvelope proves the NULL-template boundary
// (unknown role, no resolver, empty role_ref, and the de-risking `default` role)
// ALL leave the full envelope — byte-identical to a bare IssueGrants.
func TestIssueGrantsScoped_NullTemplateFullEnvelope(t *testing.T) {
	env := EnvSpec{Services: []string{"github", "npm"}}
	want := []string{"github", "npm"} // the full in-registry envelope

	res := roleResolver(map[string]RoleAttenuationTemplate{
		"default@v3": {}, // known default → nil Services → no narrowing
	})
	cases := []struct {
		name     string
		roleRef  string
		resolver RoleTemplateResolver
	}{
		{"no resolver installed (v0)", "anyrole@v1", nil},
		{"empty role_ref", "", res},
		{"unknown role_ref (ok=false)", "unknown@v9", res},
		{"recorded de-risking default (known, nil services)", "default@v3", res},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shim := newGrantShim(t)
			grants, err := shim.IssueGrantsScoped("session-full", tc.roleRef, env, tc.resolver, false)
			if err != nil {
				t.Fatal(err)
			}
			if got := serviceIDs(grants); !reflect.DeepEqual(got, want) {
				t.Fatalf("null-template path narrowed the envelope: got %v, want %v", got, want)
			}
		})
	}
}

// TestIssueGrantsScoped_EmptyServicesMintsNothing is the OTHER boundary case,
// DISTINCT from NULL: a present template with an empty services:[] is an empty
// intersection — it mints NOTHING (the strictest narrowing).
func TestIssueGrantsScoped_EmptyServicesMintsNothing(t *testing.T) {
	shim := newGrantShim(t)
	env := EnvSpec{Services: []string{"github", "npm"}}
	res := roleResolver(map[string]RoleAttenuationTemplate{
		// Non-nil but EMPTY Services = present scope_template with no permitted service.
		"locked@v1": {Services: []string{}},
	})
	grants, err := shim.IssueGrantsScoped("session-empty", "locked@v1", env, res, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("empty services:[] should mint nothing, got %v", serviceIDs(grants))
	}
}

// TestNullVsEmptyAreDistinct nails the brief's central boundary: NULL (no
// narrowing, full envelope) and EMPTY services:[] (empty intersection, nothing
// minted) produce STRICTLY DIFFERENT outcomes for the same env spec.
func TestNullVsEmptyAreDistinct(t *testing.T) {
	env := EnvSpec{Services: []string{"github", "npm"}}

	nullTmpl := RoleScopeTemplate{Present: false}                       // null
	emptyTmpl := RoleScopeTemplate{Present: true, Services: []string{}} // empty services:[]

	nullEnv := ScopedEnvSpec(env, nullTmpl)
	emptyEnv := ScopedEnvSpec(env, emptyTmpl)

	if len(nullEnv.Services) != 2 {
		t.Fatalf("null template should keep the full envelope (2 services), got %v", nullEnv.Services)
	}
	if len(emptyEnv.Services) != 0 {
		t.Fatalf("empty services:[] should yield an empty request, got %v", emptyEnv.Services)
	}

	// And end-to-end at issuance: distinct grant counts.
	shimNull := newGrantShim(t)
	gNull, err := shimNull.IssueGrantsScoped("s-null", "r", env,
		roleResolver(map[string]RoleAttenuationTemplate{}), false) // unknown ref → null
	if err != nil {
		t.Fatal(err)
	}
	shimEmpty := newGrantShim(t)
	gEmpty, err := shimEmpty.IssueGrantsScoped("s-empty", "locked@v1", env,
		roleResolver(map[string]RoleAttenuationTemplate{"locked@v1": {Services: []string{}}}), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(gNull) == 0 {
		t.Fatal("null template minted nothing — should be the full envelope")
	}
	if len(gEmpty) != 0 {
		t.Fatalf("empty template minted %v — should be nothing", serviceIDs(gEmpty))
	}
}

// TestIssueGrantsScoped_UnknownScopeFailClosedNamed is the fail-closed NAMED
// property: a role scope_template that names a service the org grant set
// (env-spec ∩ registry) does not contain fails closed under strict mode, naming
// the service AND the role_ref — never widening, never minting for the absent
// capability.
func TestIssueGrantsScoped_UnknownScopeFailClosedNamed(t *testing.T) {
	shim := newGrantShim(t)
	// env requests github + s3; s3 is NOT in the test registry. The role names s3
	// (and github) — s3 survives the env-spec intersection but the registry has no
	// such capability, so it can mint no grant: the fail-closed NAMED case.
	env := EnvSpec{Services: []string{"github", "s3"}}
	res := roleResolver(map[string]RoleAttenuationTemplate{
		"mis-spec@v1": {Services: []string{"github", "s3"}},
	})
	_, err := shim.IssueGrantsScoped("session-failclosed", "mis-spec@v1", env, res, true /* strict */)
	if err == nil {
		t.Fatal("strict mode should fail closed when the template names an absent capability")
	}
	var ure *UnknownRoleScopeError
	if !errors.As(err, &ure) {
		t.Fatalf("want *UnknownRoleScopeError, got %T: %v", err, err)
	}
	if ure.Service != "s3" {
		t.Fatalf("error should NAME the absent service: got %q, want s3", ure.Service)
	}
	if ure.RoleRef != "mis-spec@v1" {
		t.Fatalf("error should NAME the role_ref: got %q, want mis-spec@v1", ure.RoleRef)
	}
	// The sentinel is matchable without string-scraping.
	if !errors.Is(err, errUnknownRoleScope) {
		t.Fatal("error should wrap the errUnknownRoleScope sentinel")
	}
}

// TestIssueGrantsScoped_NonStrictDropsAbsentSilently proves the DEFAULT
// (non-strict) path NEVER widens either: a template naming an absent capability
// simply yields no grant for it (silent drop), still ⊆ the request — no error,
// no widening, the registry intersection is the floor.
func TestIssueGrantsScoped_NonStrictDropsAbsentSilently(t *testing.T) {
	shim := newGrantShim(t)
	env := EnvSpec{Services: []string{"github", "s3"}}
	res := roleResolver(map[string]RoleAttenuationTemplate{
		"mis-spec@v1": {Services: []string{"github", "s3"}},
	})
	grants, err := shim.IssueGrantsScoped("session-drop", "mis-spec@v1", env, res, false /* non-strict */)
	if err != nil {
		t.Fatalf("non-strict path should NOT error on an absent capability: %v", err)
	}
	if got := serviceIDs(grants); !reflect.DeepEqual(got, []string{"github"}) {
		t.Fatalf("absent s3 should be silently dropped, got %v, want [github]", got)
	}
}

// TestIssueGrantsScoped_StrictAllInRegistryNoError proves strict mode does NOT
// false-positive: when every template-named, request-selected service mints a
// grant, strict issuance succeeds (the fail-closed branch is reserved for genuine
// absent-capability mis-specs).
func TestIssueGrantsScoped_StrictAllInRegistryNoError(t *testing.T) {
	shim := newGrantShim(t)
	env := EnvSpec{Services: []string{"github", "npm"}}
	res := roleResolver(map[string]RoleAttenuationTemplate{
		"ok@v1": {Services: []string{"github", "npm"}},
	})
	grants, err := shim.IssueGrantsScoped("session-strict-ok", "ok@v1", env, res, true)
	if err != nil {
		t.Fatalf("strict should not error when all selected services mint: %v", err)
	}
	if got := serviceIDs(grants); !reflect.DeepEqual(got, []string{"github", "npm"}) {
		t.Fatalf("grants = %v, want [github npm]", got)
	}
}

// TestMintGrantsScoped_NarrowsAndPlaceholdersValidate is the MintGrants surface:
// the scoped grant set carries per-service placeholders, each validating at the
// D22 seam for its service only, exactly as the unscoped MintGrants does — the
// role narrowing applies before the placeholder mint, so a narrowed-out service
// has neither grant NOR placeholder.
func TestMintGrantsScoped_NarrowsAndPlaceholdersValidate(t *testing.T) {
	shim := newGrantShim(t)
	const sess = "session-mint-scoped"
	// Register the session so placeholders attach to a known record.
	env := EnvSpec{Services: []string{"github", "npm"}}
	res := roleResolver(map[string]RoleAttenuationTemplate{
		"reviewer@v1": {Services: []string{"github"}},
	})
	gs, err := shim.MintGrantsScoped(MintGrantsRequest{SessionUUID: sess, Env: env}, "reviewer@v1", res, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := serviceIDs(gs.Grants); !reflect.DeepEqual(got, []string{"github"}) {
		t.Fatalf("scoped MintGrants grants = %v, want [github]", got)
	}
	if len(gs.Placeholders) != 1 || gs.Placeholders[0].ServiceID != "github" {
		t.Fatalf("want exactly one placeholder for github, got %+v", gs.Placeholders)
	}
	// The github placeholder validates at the Validate seam for github.
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	ph := gs.Placeholders[0]
	got := shim.validatePlaceholder([]byte(ph.Token), sess, "github", now)
	if got.Verdict != VerdictAllow {
		t.Fatalf("scoped placeholder should ALLOW at the seam, got %+v", got)
	}
	// And nothing for the narrowed-out npm: no grant ⇒ out_of_grant.
	npmGot := shim.validatePlaceholder([]byte(ph.Token), sess, "npm", now)
	if npmGot.Verdict != VerdictDeny {
		t.Fatalf("narrowed-out npm should DENY (no grant), got %+v", npmGot)
	}
}

// TestMintGrantsScoped_EmptyTemplateMintsEmptyGrantSet proves the empty-services
// boundary at the MintGrants surface: a present-but-empty template mints an EMPTY
// GrantSet (no grants, no placeholders).
func TestMintGrantsScoped_EmptyTemplateMintsEmptyGrantSet(t *testing.T) {
	shim := newGrantShim(t)
	env := EnvSpec{Services: []string{"github", "npm"}}
	res := roleResolver(map[string]RoleAttenuationTemplate{
		"locked@v1": {Services: []string{}},
	})
	gs, err := shim.MintGrantsScoped(MintGrantsRequest{SessionUUID: "s-empty-mint", Env: env}, "locked@v1", res, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs.Grants) != 0 || len(gs.Placeholders) != 0 {
		t.Fatalf("empty template should mint an empty GrantSet, got grants=%v placeholders=%v",
			serviceIDs(gs.Grants), gs.Placeholders)
	}
}

// TestMintGrantsScoped_NullTemplateByteIdenticalToMintGrants is the orch6/7
// goldens guard: a NULL-template MintGrantsScoped produces a GrantSet
// byte-identical to a bare MintGrants for the same request, so the default (v0)
// path leaves existing grant issuance unchanged. The placeholder tokens are
// deterministic per session×service×grant, so two fresh shims with the same
// pinned clock and the same synthetic placeholder key... actually mint different
// keys (rand), so we compare on the GRANT records (deterministic) not the
// placeholder bytes (per-shim key).
func TestMintGrantsScoped_NullTemplateByteIdenticalToMintGrants(t *testing.T) {
	env := EnvSpec{Services: []string{"npm", "github"}}
	req := MintGrantsRequest{SessionUUID: "s-identical", Env: env}

	shimA := newGrantShim(t)
	want, err := shimA.MintGrants(req)
	if err != nil {
		t.Fatal(err)
	}

	shimB := newGrantShim(t)
	// Unknown role + nil-or-any resolver = NULL template = full envelope.
	got, err := shimB.MintGrantsScoped(req, "", nil, false)
	if err != nil {
		t.Fatal(err)
	}

	// The deterministic grant records (identity × service × scope × TTL × grant_ref)
	// must be identical between the unscoped and the null-scoped path.
	if !reflect.DeepEqual(want.Grants, got.Grants) {
		t.Fatalf("null-template MintGrantsScoped diverged from MintGrants:\n  unscoped=%+v\n  scoped  =%+v",
			want.Grants, got.Grants)
	}
}

// TestRoleScopeTemplateFrom_BoundaryMapping pins the adapter from the doc 19 §11
// seam record to the grant-mint consumption record across every boundary: unknown
// role (ok=false) and known-but-nil-Services both map to NULL (no narrowing); a
// known non-nil Services (even empty) maps to a PRESENT template.
func TestRoleScopeTemplateFrom_BoundaryMapping(t *testing.T) {
	cases := []struct {
		name        string
		tmpl        RoleAttenuationTemplate
		ok          bool
		wantPresent bool
		wantSvcs    []string
	}{
		{"unknown role (ok=false)", RoleAttenuationTemplate{Services: []string{"x"}}, false, false, nil},
		{"known default, nil services", RoleAttenuationTemplate{}, true, false, nil},
		{"known, non-nil empty services", RoleAttenuationTemplate{Services: []string{}}, true, true, []string{}},
		{"known, non-empty services", RoleAttenuationTemplate{Services: []string{"github"}}, true, true, []string{"github"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RoleScopeTemplateFrom(tc.tmpl, tc.ok)
			if got.Present != tc.wantPresent {
				t.Fatalf("Present = %v, want %v", got.Present, tc.wantPresent)
			}
			if tc.wantPresent && !reflect.DeepEqual(got.Services, tc.wantSvcs) {
				t.Fatalf("Services = %v, want %v", got.Services, tc.wantSvcs)
			}
		})
	}
}

// TestDefaultRoleTemplateResolver_FoldsThroughGrantMint proves the v0 default
// resolver (roletemplate.go) composes through the grant-mint consumption exactly
// like through the fan-out path: the recorded `default@<vN>` role adds NO
// narrowing (full envelope), and the catalog-backed successor installs behind the
// SAME RoleTemplateResolver hook unchanged.
func TestDefaultRoleTemplateResolver_FoldsThroughGrantMint(t *testing.T) {
	shim := newGrantShim(t)
	env := EnvSpec{Services: []string{"github", "npm"}}
	grants, err := shim.IssueGrantsScoped("s-default-fold", "default@v7", env, DefaultRoleTemplateResolver, true)
	if err != nil {
		t.Fatalf("the recorded default role should fold through with no error: %v", err)
	}
	if got := serviceIDs(grants); !reflect.DeepEqual(got, []string{"github", "npm"}) {
		t.Fatalf("default role added narrowing: got %v, want the full envelope [github npm]", got)
	}
}
