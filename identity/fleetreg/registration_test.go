// SPDX-License-Identifier: Apache-2.0

package fleetreg

import "testing"

// TestDefaultNonePosture: an unconfigured Registry designates nothing — the
// default-none posture (doc 16 §11.3 step 1). Covers nothing, Empty is true.
func TestDefaultNonePosture(t *testing.T) {
	cases := []struct {
		name  string
		reg   *Registry
		mount string
		path  string
	}{
		{"fresh registry", NewRegistry(), "secret", "data/dreamserpent/github"},
		{"zero-value registry", &Registry{}, "secret", "data/anything"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.reg.Empty() {
				t.Fatalf("default registry must be Empty (default-none)")
			}
			if tc.reg.Covers(tc.mount, tc.path) {
				t.Fatalf("default-none registry must Cover nothing; covered %s/%s", tc.mount, tc.path)
			}
			if cov, _, _ := tc.reg.CoverageOf(tc.mount, tc.path); cov != CoverageNone {
				t.Fatalf("default-none CoverageOf = %v, want CoverageNone", cov)
			}
		})
	}
}

// TestPrefixDesignationAndInheritance: designating a prefix auto-covers
// everything under it (step 3) AND a newly-written secret under the prefix
// inherits protection without re-designation (step 4) — the property per-secret
// registration cannot give.
func TestPrefixDesignationAndInheritance(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Designate(Designation{Mount: "secret", Prefix: "data/dreamserpent", Ownership: OwnershipOrg}); err != nil {
		t.Fatalf("Designate: %v", err)
	}

	cases := []struct {
		name string
		path string
		want Coverage
	}{
		{"existing leaf under prefix", "data/dreamserpent/github", CoveragePrefix},
		{"deeper leaf under prefix", "data/dreamserpent/team/aws", CoveragePrefix},
		{"the prefix path itself", "data/dreamserpent", CoveragePrefix},
		// Inheritance: a secret that did not exist at designation time is covered
		// the instant it appears under the prefix — no re-designation needed.
		{"newly-written leaf inherits", "data/dreamserpent/brand-new-secret", CoveragePrefix},
		// Segment-boundary discipline: a sibling tree that merely shares a string
		// prefix is NOT covered.
		{"sibling string-prefix not covered", "data/dreamserpent-other/x", CoverageNone},
		{"outside the prefix not covered", "data/teams/ci/deploy", CoverageNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _ := reg.CoverageOf("secret", tc.path)
			if got != tc.want {
				t.Fatalf("CoverageOf(%s) = %v, want %v", tc.path, got, tc.want)
			}
			if (tc.want != CoverageNone) != reg.Covers("secret", tc.path) {
				t.Fatalf("Covers(%s) disagrees with CoverageOf", tc.path)
			}
		})
	}
}

// TestPerSecretEscapeHatch: a path OUTSIDE any designated prefix joins the feed
// via explicit per-secret registration (step 5), and only that exact path is
// covered — siblings stay uncovered.
func TestPerSecretEscapeHatch(t *testing.T) {
	reg := NewRegistry()
	if err := reg.RegisterSecret(Secret{Mount: "secret", Path: "data/teams/ci/deploy", Ownership: OwnershipOrg}); err != nil {
		t.Fatalf("RegisterSecret: %v", err)
	}

	cases := []struct {
		name string
		path string
		want Coverage
	}{
		{"the registered path", "data/teams/ci/deploy", CoverageEscapeHatch},
		{"sibling not covered (escape hatch is one path, not a tree)", "data/teams/ci/other", CoverageNone},
		{"parent tree not covered", "data/teams/ci", CoverageNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _, _ := reg.CoverageOf("secret", tc.path); got != tc.want {
				t.Fatalf("CoverageOf(%s) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}

	// Prefix wins over escape-hatch when both could apply (precedence).
	if err := reg.Designate(Designation{Mount: "secret", Prefix: "data/teams", Ownership: OwnershipOrg}); err != nil {
		t.Fatalf("Designate: %v", err)
	}
	if got, _, _ := reg.CoverageOf("secret", "data/teams/ci/deploy"); got != CoveragePrefix {
		t.Fatalf("prefix must win over escape-hatch: got %v", got)
	}
}

// TestRemoveDesignationAndSecret: revoking a designation drops auto-coverage for
// its leaves (unless an escape-hatch independently covers one); removing a secret
// drops just that path.
func TestRemoveDesignationAndSecret(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Designate(Designation{Mount: "secret", Prefix: "data/dreamserpent", Ownership: OwnershipOrg})
	_ = reg.RegisterSecret(Secret{Mount: "secret", Path: "data/odd/one-off", Ownership: OwnershipOrg})

	if !reg.RemoveDesignation("secret", "data/dreamserpent") {
		t.Fatalf("RemoveDesignation should report the prefix was present")
	}
	if reg.Covers("secret", "data/dreamserpent/github") {
		t.Fatalf("after removing the designation, its leaves must not be covered")
	}
	if reg.RemoveDesignation("secret", "data/dreamserpent") {
		t.Fatalf("RemoveDesignation of an absent prefix must report false")
	}

	if !reg.Covers("secret", "data/odd/one-off") {
		t.Fatalf("escape-hatch secret must survive a designation removal")
	}
	if !reg.RemoveSecret("secret", "data/odd/one-off") {
		t.Fatalf("RemoveSecret should report the secret was present")
	}
	if reg.Covers("secret", "data/odd/one-off") {
		t.Fatalf("after RemoveSecret the path must not be covered")
	}
	if !reg.Empty() {
		t.Fatalf("registry should be back to default-none after both removals")
	}
}

// TestExactTarget pins the revoke-target resolution: ExactTarget matches only an
// entry registered at exactly (mount, path) — a designated prefix or an exact
// escape-hatch secret — and returns CoverageNone for a leaf that merely falls
// under a prefix (which CoverageOf would call CoveragePrefix via inheritance).
// Escape-hatch wins a tie against a coincident prefix.
func TestExactTarget(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Designate(Designation{Mount: "secret", Prefix: "data/dreamserpent", Ownership: OwnershipOrg})
	_ = reg.RegisterSecret(Secret{Mount: "secret", Path: "data/odd/one-off", Ownership: OwnershipDeveloper, Owner: "alice@idp"})

	// Exact prefix → CoveragePrefix carrying the designation's authority.
	if cov, d, _ := reg.ExactTarget("secret", "data/dreamserpent"); cov != CoveragePrefix || d.Ownership != OwnershipOrg {
		t.Fatalf("exact prefix should resolve to the designation, got cov=%v ownership=%v", cov, d.Ownership)
	}
	// A LEAF under the prefix is read-covered but NOT an exact target.
	if cov, _, _ := reg.ExactTarget("secret", "data/dreamserpent/github"); cov != CoverageNone {
		t.Fatalf("a leaf under a prefix is not an exact revoke target, got %v", cov)
	}
	// CoverageOf, by contrast, calls that leaf CoveragePrefix (inheritance) — the
	// two predicates intentionally differ.
	if cov, _, _ := reg.CoverageOf("secret", "data/dreamserpent/github"); cov != CoveragePrefix {
		t.Fatalf("CoverageOf should still cover the leaf via inheritance, got %v", cov)
	}
	// Exact escape-hatch secret → CoverageEscapeHatch carrying its authority.
	if cov, _, s := reg.ExactTarget("secret", "data/odd/one-off"); cov != CoverageEscapeHatch || s.Owner != "alice@idp" {
		t.Fatalf("exact secret should resolve to the escape hatch, got cov=%v owner=%q", cov, s.Owner)
	}
	// Unregistered path → none.
	if cov, _, _ := reg.ExactTarget("secret", "data/nope"); cov != CoverageNone {
		t.Fatalf("unregistered path should be CoverageNone, got %v", cov)
	}

	// Tie-break: a path registered BOTH as an escape-hatch secret and as a
	// designated prefix resolves to the secret (escape-hatch wins).
	tie := NewRegistry()
	_ = tie.Designate(Designation{Mount: "secret", Prefix: "data/shared", Ownership: OwnershipOrg})
	_ = tie.RegisterSecret(Secret{Mount: "secret", Path: "data/shared", Ownership: OwnershipOrg})
	if cov, _, _ := tie.ExactTarget("secret", "data/shared"); cov != CoverageEscapeHatch {
		t.Fatalf("escape-hatch should win the exact-target tie, got %v", cov)
	}
}

// TestAuthorityDefaults exercises the D84 authority defaults at the registration
// entrypoint (doc 16 §6.4): org admin for org credentials, any developer for
// credentials they own. Table-driven across the (actor, ownership, owner) matrix.
func TestAuthorityDefaults(t *testing.T) {
	orgAdmin := Principal{Subject: "admin@idp", Roles: []Role{RoleOrgAdmin}}
	devAlice := Principal{Subject: "alice@idp", Roles: []Role{RoleDeveloper}}
	devBob := Principal{Subject: "bob@idp", Roles: []Role{RoleDeveloper}}
	anon := Principal{}

	cases := []struct {
		name      string
		actor     Principal
		ownership Ownership
		owner     string
		wantOK    bool
	}{
		{"org-admin on org credential", orgAdmin, OwnershipOrg, "", true},
		{"developer on org credential denied", devAlice, OwnershipOrg, "", false},
		{"anon on org credential denied", anon, OwnershipOrg, "", false},
		{"owner on own credential", devAlice, OwnershipDeveloper, "alice@idp", true},
		{"non-owner developer on someone else's credential denied", devBob, OwnershipDeveloper, "alice@idp", false},
		{"org-admin on a developer-owned credential (superset)", orgAdmin, OwnershipDeveloper, "alice@idp", true},
		{"unspecified ownership requires org-admin (fail-closed)", devAlice, OwnershipUnspecified, "", false},
		{"org-admin on unspecified ownership", orgAdmin, OwnershipUnspecified, "", true},
		{"empty-subject owner never matches empty owner", anon, OwnershipDeveloper, "", false},
	}
	var az Authorizer
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := az.Authorize(tc.actor, tc.ownership, tc.owner)
			if tc.wantOK && err != nil {
				t.Fatalf("expected authorized, got %v", err)
			}
			if !tc.wantOK {
				if err == nil {
					t.Fatalf("expected unauthorized, got nil")
				}
				if !isUnauthorized(err) {
					t.Fatalf("expected ErrUnauthorized, got %v", err)
				}
			}
		})
	}
}

func isUnauthorized(err error) bool {
	for e := err; e != nil; {
		if e == ErrUnauthorized {
			return true
		}
		un, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = un.Unwrap()
	}
	return false
}

// TestDesignateValidation: fail-closed input guards.
func TestDesignateValidation(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Designate(Designation{Mount: "", Prefix: "x", Ownership: OwnershipOrg}); err == nil {
		t.Fatalf("empty mount must be rejected (default-none cannot be inverted by an empty designation)")
	}
	if err := reg.Designate(Designation{Mount: "secret", Ownership: OwnershipDeveloper}); err == nil {
		t.Fatalf("developer-owned designation without an owner must be rejected")
	}
	if err := reg.RegisterSecret(Secret{Mount: "secret", Path: "", Ownership: OwnershipOrg}); err == nil {
		t.Fatalf("escape-hatch without a path must be rejected")
	}
	if !reg.Empty() {
		t.Fatalf("no failed registration should have mutated the surface")
	}
}

// TestCanonPath / TestPrefixContains pin the path normalization the coverage
// logic rests on.
func TestCanonPath(t *testing.T) {
	cases := []struct {
		mount, path, want string
	}{
		{"secret", "data/x", "secret/data/x"},
		{"/secret/", "/data/x/", "secret/data/x"},
		{" secret ", " data/x ", "secret/data/x"},
		{"secret", "", "secret"},
		{"", "data/x", "data/x"},
	}
	for _, tc := range cases {
		if got := canonPath(tc.mount, tc.path); got != tc.want {
			t.Fatalf("canonPath(%q,%q) = %q, want %q", tc.mount, tc.path, got, tc.want)
		}
	}
}

func TestPrefixContains(t *testing.T) {
	cases := []struct {
		prefix, path string
		want         bool
	}{
		{"secret/data", "secret/data", true},
		{"secret/data", "secret/data/x", true},
		{"secret/data", "secret/database/x", false}, // segment boundary
		{"secret", "secret/anything/deep", true},    // bare-mount contains all
		{"secret/a", "secret/b", false},
	}
	for _, tc := range cases {
		if got := prefixContains(tc.prefix, tc.path); got != tc.want {
			t.Fatalf("prefixContains(%q,%q) = %v, want %v", tc.prefix, tc.path, got, tc.want)
		}
	}
}
