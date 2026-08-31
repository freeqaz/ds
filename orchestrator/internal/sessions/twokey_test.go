package sessions

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// enrollmentFake is a synthetic EnrollmentResolver: it scripts a per-repo enrollment
// (presence ⇒ ok=true) or a resolver fault, and records the repos it was asked about.
type enrollmentFake struct {
	byRepo     map[string]Enrollment // repo -> enrollment (presence => enrolled)
	resolveErr error                 // a store fault on resolve
	seen       []string
}

func (f *enrollmentFake) ResolveEnrollment(_ context.Context, repoID string) (Enrollment, bool, error) {
	f.seen = append(f.seen, repoID)
	if f.resolveErr != nil {
		return Enrollment{}, false, f.resolveErr
	}
	e, ok := f.byRepo[repoID]
	return e, ok, nil
}

// seedEnvConfig records a repo-referenced env config in a fresh store and returns the
// store + the recorded ref (the second-key handle).
func seedEnvConfig(t *testing.T, repoRef string) (*store.Memory, string) {
	t.Helper()
	mem := store.NewMemory()
	rec, err := RecordEnvConfig(context.Background(), mem, RecordEnvConfigInput{
		RepoRef: repoRef, SpecHash: "spec-hash-1", ImageID: "img-1", Coupled: goodCoupling(),
	})
	if err != nil {
		t.Fatalf("seed env config: %v", err)
	}
	return mem, rec.Ref
}

const testRepo = "github.com/acme/repo"

// TestCheckTwoKeyActivation_BothKeysPresent proves the happy path (D56): a repo
// enrolled by a repo-admin AND a checked-in env spec for the SAME repo activates.
func TestCheckTwoKeyActivation_BothKeysPresent(t *testing.T) {
	mem, ref := seedEnvConfig(t, testRepo)
	enroll := &enrollmentFake{byRepo: map[string]Enrollment{
		testRepo: {RepoID: testRepo, EnrolledByPrincipal: "p-admin", EnrolledByRole: store.RoleRepoAdmin},
	}}
	res, err := CheckTwoKeyActivation(context.Background(), enroll, mem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ref})
	if err != nil {
		t.Fatalf("both keys present must activate, got %v", err)
	}
	if res.Enrollment.RepoID != testRepo {
		t.Errorf("resolved enrollment repo = %q, want %q", res.Enrollment.RepoID, testRepo)
	}
	if res.EnvConfig.Ref != ref {
		t.Errorf("resolved env config ref = %q, want %q", res.EnvConfig.Ref, ref)
	}
	if res.EnvConfig.ImageID != "img-1" {
		t.Errorf("step-2 must see the resolved image lineage, got %q", res.EnvConfig.ImageID)
	}
}

// TestCheckTwoKeyActivation_MissingEitherKeyRefuses proves "neither alone activates a
// repo" (D56): each key alone is refused fail-closed (ErrTwoKeyRefused).
func TestCheckTwoKeyActivation_MissingEitherKeyRefuses(t *testing.T) {
	mem, ref := seedEnvConfig(t, testRepo)

	// KEY 1 ONLY (enrolled, but no env spec): empty env_config_ref.
	enrolledOnly := &enrollmentFake{byRepo: map[string]Enrollment{
		testRepo: {RepoID: testRepo, EnrolledByPrincipal: "p", EnrolledByRole: store.RoleRepoAdmin},
	}}
	if _, err := CheckTwoKeyActivation(context.Background(), enrolledOnly, mem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ""}); !errors.Is(err, ErrTwoKeyRefused) {
		t.Errorf("enrollment alone must refuse (no env spec), got %v", err)
	}
	// A non-empty but UNRESOLVABLE env_config_ref is also the missing second key.
	if _, err := CheckTwoKeyActivation(context.Background(), enrolledOnly, mem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: "env-nonexistent"}); !errors.Is(err, ErrTwoKeyRefused) {
		t.Errorf("unresolvable env_config_ref must refuse (no env spec), got %v", err)
	}

	// KEY 2 ONLY (env spec recorded, but repo NOT enrolled).
	notEnrolled := &enrollmentFake{byRepo: map[string]Enrollment{}}
	if _, err := CheckTwoKeyActivation(context.Background(), notEnrolled, mem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ref}); !errors.Is(err, ErrTwoKeyRefused) {
		t.Errorf("env spec alone must refuse (not enrolled), got %v", err)
	}
}

// TestCheckTwoKeyActivation_EnrollmentAuthority proves the D56 authority posture:
// enrollment by a non-authority is refused; org-owner restriction narrows repo-admin
// out (only org-admin then activates).
func TestCheckTwoKeyActivation_EnrollmentAuthority(t *testing.T) {
	mem, ref := seedEnvConfig(t, testRepo)
	req := TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ref}

	// A launcher is NOT an enrollment authority.
	launcher := &enrollmentFake{byRepo: map[string]Enrollment{
		testRepo: {RepoID: testRepo, EnrolledByPrincipal: "p", EnrolledByRole: store.RoleLauncher},
	}}
	if _, err := CheckTwoKeyActivation(context.Background(), launcher, mem, req); !errors.Is(err, ErrTwoKeyRefused) {
		t.Errorf("launcher enrollment must refuse (not an authority), got %v", err)
	}

	// Org-restricted: a repo-admin enrollment is NOT sufficient.
	restricted := &enrollmentFake{byRepo: map[string]Enrollment{
		testRepo: {RepoID: testRepo, EnrolledByPrincipal: "p", EnrolledByRole: store.RoleRepoAdmin, OrgRestricted: true},
	}}
	if _, err := CheckTwoKeyActivation(context.Background(), restricted, mem, req); !errors.Is(err, ErrTwoKeyRefused) {
		t.Errorf("org-restricted repo-admin enrollment must refuse, got %v", err)
	}

	// Org-restricted: an org-admin enrollment IS sufficient.
	orgAdmin := &enrollmentFake{byRepo: map[string]Enrollment{
		testRepo: {RepoID: testRepo, EnrolledByPrincipal: "p", EnrolledByRole: store.RoleOrgAdmin, OrgRestricted: true},
	}}
	if _, err := CheckTwoKeyActivation(context.Background(), orgAdmin, mem, req); err != nil {
		t.Errorf("org-admin enrollment under restriction must activate, got %v", err)
	}
}

// TestCheckTwoKeyActivation_SameRepoJoin proves the two keys must be about the SAME
// repo: a repo-referenced env spec for a DIFFERENT repo cannot satisfy this
// enrollment's second key.
func TestCheckTwoKeyActivation_SameRepoJoin(t *testing.T) {
	// Env spec is checked into a DIFFERENT repo than the one being activated.
	mem, ref := seedEnvConfig(t, "github.com/other/repo")
	enroll := &enrollmentFake{byRepo: map[string]Enrollment{
		testRepo: {RepoID: testRepo, EnrolledByPrincipal: "p", EnrolledByRole: store.RoleRepoAdmin},
	}}
	if _, err := CheckTwoKeyActivation(context.Background(), enroll, mem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ref}); !errors.Is(err, ErrTwoKeyRefused) {
		t.Errorf("env spec for a different repo must refuse (same-repo join), got %v", err)
	}

	// An INLINE env spec (no RepoRef) rides the enrolled repo — the join is satisfied.
	inlineMem := store.NewMemory()
	inlineRec, err := RecordEnvConfig(context.Background(), inlineMem, RecordEnvConfigInput{
		InlineSpec: []byte("inline-body"), ImageID: "img-9", Coupled: goodCoupling(),
	})
	if err != nil {
		t.Fatalf("seed inline env config: %v", err)
	}
	if _, err := CheckTwoKeyActivation(context.Background(), enroll, inlineMem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: inlineRec.Ref}); err != nil {
		t.Errorf("inline env spec must ride the enrolled repo, got %v", err)
	}
}

// TestCheckTwoKeyActivation_MachineReadableReason proves the two failure modes carry a
// MACHINE-READABLE which-key reason (D56 / doc 07 §2a-spec): a not-enrolled repo refuses
// with ReasonNotEnrolled (errors.Is ErrNotEnrolled), a missing env spec refuses with
// ReasonNoEnvSpec (errors.Is ErrNoEnvSpec), and BOTH still classify under the umbrella
// ErrTwoKeyRefused so existing callers are unchanged.
func TestCheckTwoKeyActivation_MachineReadableReason(t *testing.T) {
	mem, ref := seedEnvConfig(t, testRepo)
	enrolled := &enrollmentFake{byRepo: map[string]Enrollment{
		testRepo: {RepoID: testRepo, EnrolledByPrincipal: "p", EnrolledByRole: store.RoleRepoAdmin},
	}}
	notEnrolled := &enrollmentFake{byRepo: map[string]Enrollment{}}

	// FIRST-KEY absence: enrolled-fake empty ⇒ not-enrolled.
	_, errNE := CheckTwoKeyActivation(context.Background(), notEnrolled, mem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ref})
	if !errors.Is(errNE, ErrNotEnrolled) {
		t.Errorf("not-enrolled refusal must wrap ErrNotEnrolled, got %v", errNE)
	}
	if errors.Is(errNE, ErrNoEnvSpec) {
		t.Error("a not-enrolled refusal must NOT also read as no-env-spec")
	}
	if !errors.Is(errNE, ErrTwoKeyRefused) {
		t.Error("not-enrolled must still classify under the umbrella ErrTwoKeyRefused")
	}
	if got := TwoKeyReasonOf(errNE); got != ReasonNotEnrolled {
		t.Errorf("TwoKeyReasonOf(not-enrolled) = %v, want %v", got, ReasonNotEnrolled)
	}

	// SECOND-KEY absence: enrolled but empty env_config_ref ⇒ no-env-spec.
	_, errNS := CheckTwoKeyActivation(context.Background(), enrolled, mem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ""})
	if !errors.Is(errNS, ErrNoEnvSpec) {
		t.Errorf("no-env-spec refusal must wrap ErrNoEnvSpec, got %v", errNS)
	}
	if errors.Is(errNS, ErrNotEnrolled) {
		t.Error("a no-env-spec refusal must NOT also read as not-enrolled")
	}
	if !errors.Is(errNS, ErrTwoKeyRefused) {
		t.Error("no-env-spec must still classify under the umbrella ErrTwoKeyRefused")
	}
	if got := TwoKeyReasonOf(errNS); got != ReasonNoEnvSpec {
		t.Errorf("TwoKeyReasonOf(no-env-spec) = %v, want %v", got, ReasonNoEnvSpec)
	}

	// A disabled enrollment is ALSO the first-key absence (not-enrolled).
	disabled := &enrollmentFake{byRepo: map[string]Enrollment{
		testRepo: {RepoID: testRepo, EnrolledByPrincipal: "p", EnrolledByRole: store.RoleRepoAdmin, Disabled: true},
	}}
	_, errDis := CheckTwoKeyActivation(context.Background(), disabled, mem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ref})
	if TwoKeyReasonOf(errDis) != ReasonNotEnrolled {
		t.Errorf("a disabled enrollment must read as not-enrolled, got %v (err=%v)", TwoKeyReasonOf(errDis), errDis)
	}

	// A non-two-key error classifies as ReasonNone.
	if got := TwoKeyReasonOf(errors.New("some store fault")); got != ReasonNone {
		t.Errorf("TwoKeyReasonOf(non-two-key) = %v, want ReasonNone", got)
	}
}

// TestCheckTwoKeyActivation_FaultNotRefusal proves a resolver/store FAULT is surfaced
// verbatim (NOT ErrTwoKeyRefused) — the create-driver-vs-stall distinction.
func TestCheckTwoKeyActivation_FaultNotRefusal(t *testing.T) {
	mem, ref := seedEnvConfig(t, testRepo)
	boom := errors.New("enrollment store unreachable")
	faulting := &enrollmentFake{resolveErr: boom}
	_, err := CheckTwoKeyActivation(context.Background(), faulting, mem, TwoKeyRequest{RepoID: testRepo, EnvConfigRef: ref})
	if err == nil {
		t.Fatal("a resolver fault must surface an error")
	}
	if errors.Is(err, ErrTwoKeyRefused) {
		t.Error("a resolver fault must NOT be classified as a two-key refusal")
	}
	if !errors.Is(err, boom) {
		t.Errorf("a resolver fault must be surfaced verbatim, got %v", err)
	}
}
