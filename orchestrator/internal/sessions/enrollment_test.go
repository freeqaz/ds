package sessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// fixedClock returns a deterministic clock for the registry's audit timestamps.
func fixedClock() func() time.Time {
	t := time.Unix(1_700_000_000, 0).UTC()
	return func() time.Time { return t }
}

// repoAdmin / orgAdmin / launcher are the actor fixtures the permission tests drive.
func repoAdmin() FlipActor {
	return FlipActor{PrincipalID: "p-repo-admin", Roles: []store.PrincipalRole{store.RoleRepoAdmin}}
}
func orgAdmin() FlipActor {
	return FlipActor{PrincipalID: "p-org-admin", Roles: []store.PrincipalRole{store.RoleOrgAdmin}}
}
func launcher() FlipActor {
	return FlipActor{PrincipalID: "p-launcher", Roles: []store.PrincipalRole{store.RoleLauncher}}
}

// restrictedOrg is an OrgRestrictionSource that reports every repo's org as restricting
// enrollment to org admins (the D56 org-owner-restrictable posture engaged).
type restrictedOrg struct{ err error }

func (r restrictedOrg) OrgRestrictsEnrollment(context.Context, string) (bool, error) {
	return r.err == nil, r.err
}

// TestCanFlipEnrollment_PermissionModel proves the D56 flip-permission rule as a pure
// predicate: repo-admin flips by default, org-admin flips under any posture, an org-owner
// restriction narrows repo-admin out (only org-admin then flips), and a launcher never flips.
func TestCanFlipEnrollment_PermissionModel(t *testing.T) {
	cases := []struct {
		name       string
		actor      FlipActor
		restricted bool
		want       bool
	}{
		{"repo-admin flips by default", repoAdmin(), false, true},
		{"repo-admin CANNOT flip under org restriction", repoAdmin(), true, false},
		{"org-admin flips by default", orgAdmin(), false, true},
		{"org-admin flips under org restriction", orgAdmin(), true, true},
		{"launcher never flips (default)", launcher(), false, false},
		{"launcher never flips (restricted)", launcher(), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanFlipEnrollment(tc.actor, tc.restricted); got != tc.want {
				t.Errorf("CanFlipEnrollment(%v, restricted=%t) = %t, want %t", tc.actor.Roles, tc.restricted, got, tc.want)
			}
		})
	}
}

// TestEnrollmentRegistry_RepoAdminCanFlipByDefault proves the D56 default: a repo admin
// may enroll their own repo (the first key becomes present), and the create-step-1
// resolver then reads it as enrolled + authoritative.
func TestEnrollmentRegistry_RepoAdminCanFlipByDefault(t *testing.T) {
	reg := NewEnrollmentRegistry(nil, fixedClock()) // nil source = unrestricted default
	ctx := context.Background()

	// Before any flip, the repo is NOT enrolled (the empty-registry fail-closed default).
	if _, ok, _ := reg.ResolveEnrollment(ctx, testRepo); ok {
		t.Fatal("a fresh registry must report no repo enrolled")
	}

	// A repo admin enrolls the repo (the default authority).
	setting, err := reg.Flip(ctx, testRepo, repoAdmin(), true)
	if err != nil {
		t.Fatalf("repo-admin enroll must succeed by default, got %v", err)
	}
	if !setting.Enabled || setting.FlippedByRole != store.RoleRepoAdmin {
		t.Errorf("recorded setting = %+v, want Enabled with repo-admin authority", setting)
	}

	// The create-step-1 resolver now reads it as enrolled, enabled, authoritative.
	enr, ok, err := reg.ResolveEnrollment(ctx, testRepo)
	if err != nil || !ok {
		t.Fatalf("after enroll, ResolveEnrollment must report enrolled, got ok=%t err=%v", ok, err)
	}
	if enr.Disabled {
		t.Error("an enrolled repo must not read as Disabled")
	}
	if !enr.enrollmentAuthoritative() {
		t.Error("a repo-admin enrollment (unrestricted) must be authoritative")
	}
}

// TestEnrollmentRegistry_OrgOwnerRestrictable proves the D56 restriction: under an
// org-owner restriction a repo admin may NOT flip (ErrEnrollmentForbidden, setting
// unchanged), but an org admin still may.
func TestEnrollmentRegistry_OrgOwnerRestrictable(t *testing.T) {
	reg := NewEnrollmentRegistry(restrictedOrg{}, fixedClock())
	ctx := context.Background()

	// A repo admin is refused under the restriction; the setting is unchanged.
	_, err := reg.Flip(ctx, testRepo, repoAdmin(), true)
	if !errors.Is(err, ErrEnrollmentForbidden) {
		t.Fatalf("repo-admin flip under org restriction must be forbidden, got %v", err)
	}
	if _, ok := reg.Get(testRepo); ok {
		t.Error("a forbidden flip must leave the setting unrecorded (fail-closed, unchanged)")
	}

	// An org admin may flip under the restriction; the recorded posture is restricted.
	setting, err := reg.Flip(ctx, testRepo, orgAdmin(), true)
	if err != nil {
		t.Fatalf("org-admin flip under org restriction must succeed, got %v", err)
	}
	if !setting.OrgRestricted || setting.FlippedByRole != store.RoleOrgAdmin {
		t.Errorf("recorded setting = %+v, want org-restricted org-admin authority", setting)
	}
	// The create-step-1 resolver reads it as authoritative even under restriction (org-admin).
	enr, ok, _ := reg.ResolveEnrollment(ctx, testRepo)
	if !ok || !enr.enrollmentAuthoritative() {
		t.Error("an org-admin enrollment under restriction must resolve authoritative")
	}
}

// TestEnrollmentRegistry_LauncherForbidden proves a non-admin (launcher) may never flip,
// regardless of posture — enrollment is an admin act, never self-serve.
func TestEnrollmentRegistry_LauncherForbidden(t *testing.T) {
	reg := NewEnrollmentRegistry(nil, fixedClock())
	if _, err := reg.Flip(context.Background(), testRepo, launcher(), true); !errors.Is(err, ErrEnrollmentForbidden) {
		t.Fatalf("launcher flip must be forbidden, got %v", err)
	}
}

// TestEnrollmentRegistry_FlipOffDisables proves a flip to disabled retains the record but
// reads as the first key being absent (Disabled), so a previously-enrolled repo can be
// turned off and the create-step-1 check refuses it.
func TestEnrollmentRegistry_FlipOffDisables(t *testing.T) {
	reg := NewEnrollmentRegistry(nil, fixedClock())
	ctx := context.Background()

	if _, err := reg.Flip(ctx, testRepo, repoAdmin(), true); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := reg.Flip(ctx, testRepo, repoAdmin(), false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	enr, ok, _ := reg.ResolveEnrollment(ctx, testRepo)
	if !ok {
		t.Fatal("a disabled repo retains its record (ok=true) for the audit trail")
	}
	if !enr.Disabled {
		t.Error("a flipped-off enrollment must read as Disabled (first key absent)")
	}
}

// TestEnrollmentRegistry_InvalidRequests proves a malformed flip (empty repo, empty
// principal) is refused ErrEnrollmentInvalid before the authority check.
func TestEnrollmentRegistry_InvalidRequests(t *testing.T) {
	reg := NewEnrollmentRegistry(nil, fixedClock())
	ctx := context.Background()
	if _, err := reg.Flip(ctx, "", repoAdmin(), true); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Errorf("empty repo must be invalid, got %v", err)
	}
	if _, err := reg.Flip(ctx, testRepo, FlipActor{Roles: []store.PrincipalRole{store.RoleRepoAdmin}}, true); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Errorf("empty principal must be invalid, got %v", err)
	}
}

// TestEnrollmentRegistry_RestrictionFaultFailsClosed proves an org-restriction resolver
// FAULT fails the flip closed (surfaced verbatim, NOT ErrEnrollmentForbidden) — the
// authority check cannot be evaluated against an unknown posture.
func TestEnrollmentRegistry_RestrictionFaultFailsClosed(t *testing.T) {
	boom := errors.New("org policy store unreachable")
	reg := NewEnrollmentRegistry(restrictedOrg{err: boom}, fixedClock())
	_, err := reg.Flip(context.Background(), testRepo, orgAdmin(), true)
	if err == nil {
		t.Fatal("an org-restriction fault must fail the flip")
	}
	if errors.Is(err, ErrEnrollmentForbidden) {
		t.Error("a restriction FAULT must not be classified as a permission refusal")
	}
	if !errors.Is(err, boom) {
		t.Errorf("the restriction fault must surface verbatim, got %v", err)
	}
}

// TestEnrollmentRegistry_BacksTwoKeyEndToEnd proves the registry drops into the
// create-step-1 two-key check as the real first-key backing: a repo a repo-admin enrolled
// + a checked-in env spec activates; the same repo before enrollment refuses ErrNotEnrolled.
func TestEnrollmentRegistry_BacksTwoKeyEndToEnd(t *testing.T) {
	ctx := context.Background()
	mem, ref := seedEnvConfig(t, testRepo)
	reg := NewEnrollmentRegistry(nil, fixedClock())
	req := TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ref}

	// Env spec present but NOT enrolled: the first key is absent (machine-readable not-enrolled).
	_, err := CheckTwoKeyActivation(ctx, reg, mem, req)
	if TwoKeyReasonOf(err) != ReasonNotEnrolled {
		t.Fatalf("before enrollment, reason = %v (err=%v), want not-enrolled", TwoKeyReasonOf(err), err)
	}

	// A repo admin enrolls it: both keys now present, the create activates.
	if _, err := reg.Flip(ctx, testRepo, repoAdmin(), true); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := CheckTwoKeyActivation(ctx, reg, mem, req); err != nil {
		t.Fatalf("after enrollment, both keys present must activate, got %v", err)
	}
}
