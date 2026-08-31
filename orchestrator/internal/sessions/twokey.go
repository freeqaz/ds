package sessions

// twokey.go is the doc 15 §4.1 STEP-1 TWO-KEY ACTIVATION CHECK (D56) — the FIRST
// stage of the create choreography, the structural gate that refuses session-create
// unless BOTH keys are present:
//
//	KEY 1 (whether): control-plane ENROLLMENT — the repo is enrolled in the control
//	  plane by an authorized principal (repo admins by default; org-owner
//	  restrictable, D56). This is the "whether the repo may run at all" key.
//	KEY 2 (how): a checked-in ENV SPEC — a recorded D7 env config (envconfig.go /
//	  RecordEnvConfig), drafted by the onboarding agent as a PR (D56). This is the
//	  "how the repo runs" key.
//
// D56, verbatim: "Repo opt-in is two-key: control-plane enrollment … answers
// *whether*, and a checked-in env spec (D7 …) answers *how*; neither alone activates
// a repo." This stage is where that "neither alone activates" becomes a STRUCTURAL
// property of create rather than a convention — both keys are resolved here, at
// §4.1 step 1, BEFORE the session record exists (step 2) and BEFORE the launch gate /
// role pin / mint cluster (createspine.go). A missing key is a fail-closed refusal
// (ErrTwoKeyRefused), the same posture as the steps-1–2 role refusal and the
// coupled-invariant split.
//
// FROZEN PRECEDENCE (doc 15 §4.1: "1 ≺ 2 ≺ 3 ≺ {6,7,8}"; §10 row "§4.1 canonical
// create order's precedence constraints (D56/…)"). The two-key check IS step 1: it
// runs FIRST, before the session record is created. This stage is the standalone
// step-1 gate a create driver calls AHEAD of the steps-1–2 + step-5 spine
// (RunCreateSpine) — keeping the two-key gate a distinct, independently-testable
// stage (the createspine.go header notes the spine "does NOT implement" the earlier
// gates beyond the launch/role cluster; this is the step-1 gate that precedes it).
//
// WHAT THIS STAGE IS NOT. It is NOT enrollment itself (enrolling a repo — the
// control-plane act an org/repo admin performs — is an authoring-surface verb that
// freezes with the M2 product band, doc 15 §10; this stage READS the enrolled fact
// through a seam, it never writes it). It is NOT the env-spec recorder (that is
// envconfig.go / RecordEnvConfig; this stage READS that a recorded env config exists
// for the repo). It only JOINS the two keys at create step 1.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// ErrTwoKeyRefused is the structural refusal of the §4.1 step-1 two-key check (D56):
// a session-create with EITHER key missing — no control-plane enrollment, or no
// checked-in env spec — is refused fail-closed. "Neither alone activates a repo"
// (D56) is enforced here: both keys present or the create never proceeds to step 2.
// It is the activation-gate analog of ErrRoleRefRefused (the role gate) and
// ErrLaunchRefused (the launch gate) — the three fail-closed, attributable create
// refusals the early steps surface.
//
// It is the UMBRELLA sentinel every two-key refusal carries (errors.Is(err,
// ErrTwoKeyRefused) classifies ANY two-key refusal). The two distinct failure modes —
// ErrNotEnrolled (first key) and ErrNoEnvSpec (second key) — WRAP this sentinel, so a
// caller that only needs "was this a two-key refusal?" stays unchanged, while a caller
// that needs the MACHINE-READABLE which-key (the §2a-spec failure modes: a distinct
// "not enrolled" vs "no env spec" message, doc 07 §2a-spec) discriminates on the two.
var ErrTwoKeyRefused = errors.New("sessions: two-key activation refused (D56: both control-plane enrollment AND a checked-in env spec are required)")

// ErrNotEnrolled is the FIRST-KEY refusal (D56 "whether"): the repo is not enrolled in
// the control plane (no enrollment record, or an enrollment record that does not carry
// the D56 admin authority). It WRAPS ErrTwoKeyRefused so the umbrella classification
// still holds (errors.Is(err, ErrTwoKeyRefused) is true), while errors.Is(err,
// ErrNotEnrolled) distinguishes THIS key's absence from the second key's — the
// machine-readable distinction the doc 07 §2a-spec failure modes require ("Repo … is
// not enrolled. A repo admin must enroll it" vs "Env spec not found …").
var ErrNotEnrolled = fmt.Errorf("%w: not enrolled (D56 first key absent — control-plane enrollment answers WHETHER)", ErrTwoKeyRefused)

// ErrNoEnvSpec is the SECOND-KEY refusal (D56 "how"): no valid checked-in env spec
// resolves for the create (empty/unresolvable env_config_ref, or an env spec checked
// into a DIFFERENT repo than the one enrolled). It WRAPS ErrTwoKeyRefused so the
// umbrella classification still holds, while errors.Is(err, ErrNoEnvSpec) distinguishes
// THIS key's absence from the first key's (doc 07 §2a-spec: "Env spec not found at
// branch … The onboarding PR has not been merged").
var ErrNoEnvSpec = fmt.Errorf("%w: no checked-in env spec (D56 second key absent — the env spec answers HOW)", ErrTwoKeyRefused)

// TwoKeyReason is the MACHINE-READABLE which-key tag on a two-key refusal (D56). It is
// the discriminant the create-path error mapping carries onto the wire so a client tells
// "not enrolled" (fix: a repo admin enrolls the repo) from "no env spec" (fix: merge the
// onboarding PR) — the two distinct §2a-spec failure modes. It is NOT a proto enum (no
// contract change); it is the in-package failure-site vocabulary, mirrored as a string in
// the gRPC status message by the handler.
type TwoKeyReason int

const (
	// ReasonNone is the zero value: not a two-key refusal (the create reached step 2).
	ReasonNone TwoKeyReason = iota
	// ReasonNotEnrolled is the FIRST-KEY absence (ErrNotEnrolled): the repo is not
	// enrolled (or enrolled without the D56 admin authority).
	ReasonNotEnrolled
	// ReasonNoEnvSpec is the SECOND-KEY absence (ErrNoEnvSpec): no valid checked-in env
	// spec resolves for the create.
	ReasonNoEnvSpec
)

// String renders the two-key reason for audit/wire text (the handler stamps it into the
// gRPC status message so the distinction is visible to the client).
func (r TwoKeyReason) String() string {
	switch r {
	case ReasonNotEnrolled:
		return "not-enrolled"
	case ReasonNoEnvSpec:
		return "no-env-spec"
	default:
		return "none"
	}
}

// TwoKeyReasonOf classifies a two-key refusal error into its machine-readable reason.
// It returns ReasonNotEnrolled / ReasonNoEnvSpec for the two distinct key-absence modes
// and ReasonNone for an error that is NOT a two-key refusal (a resolver/store fault, or
// any non-two-key error) — so the caller branches on the which-key only for an actual
// refusal. It reads the wrapped sentinels (errors.Is), so it is robust to additional
// wrapping by the create coordinator (the CreateError chain).
func TwoKeyReasonOf(err error) TwoKeyReason {
	switch {
	case errors.Is(err, ErrNotEnrolled):
		return ReasonNotEnrolled
	case errors.Is(err, ErrNoEnvSpec):
		return ReasonNoEnvSpec
	default:
		return ReasonNone
	}
}

// EnrollmentResolver is the doc 15 §4.1 step-1 ENROLLMENT seam (D56 first key): it
// reports whether a repo is enrolled in the control plane, and by which authorized
// principal. It is the orchestrator-side analog of roleref.go's RoleResolver — a
// narrow data seam the v0 default backs and the M2 authoring/enrollment surface
// (doc 15 §10) installs the real implementation behind WITHOUT changing this shape.
//
// ResolveEnrollment(repoID) returns the enrollment record + ok=false when the repo is
// NOT enrolled (the first-key refusal). A resolver FAULT (the enrollment store
// unreachable) is the error return — distinct from "not enrolled" (ok=false), so the
// create driver tells a missing key (refuse, attributably) from a transient stall
// (the §4.1 rollback note covers it). The enrollment AUTHORITY check — that the
// enroller held repo-admin/org-admin (D56: "repo admins by default; org-owner
// restrictable") — is recorded on the Enrollment by whoever wrote it; this stage
// verifies the recorded authority is one D56 admits, never re-derives it.
type EnrollmentResolver interface {
	ResolveEnrollment(ctx context.Context, repoID string) (Enrollment, bool, error)
}

// Enrollment is the control-plane enrollment fact (D56 first key) for a repo: the
// repo it enrolls, the principal who enrolled it, and that principal's role at
// enrollment time (the D56 authority: repo-admin by default, org-owner restrictable).
// It is the in-package projection the EnrollmentResolver yields; the enrollment WRITE
// path (the M2 authoring surface, doc 15 §10) is out of scope here.
type Enrollment struct {
	// RepoID is the enrolled repo (the join key with the env config's RepoRef).
	RepoID string
	// EnrolledByPrincipal is the stable ID of the principal who enrolled the repo
	// (the actor recorded on the enrollment, for the audit trail). Non-empty for a
	// valid enrollment.
	EnrolledByPrincipal string
	// EnrolledByRole is that principal's role at enrollment (D56: enrollment is a
	// repo-admin/org-admin act; "org-owner restrictable" narrows WHO may enroll, but
	// the recorded authority must be one the policy admits). This stage verifies the
	// recorded role is enrollment-authoritative; it does not re-run the org policy.
	EnrolledByRole store.PrincipalRole
	// OrgRestricted records the D56 "org-owner restrictable" posture: when true, the
	// org owner has restricted enrollment authority to org-admins only, so a
	// repo-admin enrollment is NOT sufficient — only org-admin enrollment activates.
	// When false (the default), repo-admin enrollment is sufficient.
	OrgRestricted bool
	// Disabled records that an existing enrollment record was flipped OFF (the D56
	// "whether" toggle set to no). It is the NEGATIVE form so the zero value is the
	// common "enabled" case: a resolver that returns ok=true for a live enrollment
	// (the openPoolEnrollment v0 default, the existing test fakes) leaves Disabled
	// false and so reads as enrolled, unchanged. Flipping enrollment off without
	// deleting the record (preserving the audit trail of who enrolled it) sets this.
	Disabled bool
}

// enrollmentAuthoritative reports whether the recorded enroller's role is one D56
// admits as an enrollment authority, honoring the org-owner restriction:
//   - default (OrgRestricted == false): repo-admin OR org-admin enrolls (D56 "repo
//     admins by default").
//   - restricted (OrgRestricted == true): ONLY org-admin enrolls (D56 "org-owner
//     restrictable" — the org owner has narrowed enrollment to org-admins).
//
// A repo enrolled by a non-authoritative role is not a valid first key — the
// enrollment record exists but does not carry the authority D56 requires, so it is
// refused as if absent (a "self-enrolled" repo would otherwise activate without the
// admin act D56 mandates).
func (e Enrollment) enrollmentAuthoritative() bool {
	switch e.EnrolledByRole {
	case store.RoleOrgAdmin:
		return true // org-admin enrolls under either posture.
	case store.RoleRepoAdmin:
		return !e.OrgRestricted // repo-admin enrolls only when NOT org-restricted.
	default:
		return false // launcher/viewer/approver are not enrollment authorities (D56).
	}
}

// envConfigReader is the doc 15 §4.1 step-1 ENV-SPEC seam (D56 second key): it reports
// whether a recorded env config exists for the create (the "checked-in env spec" key).
// It is the EXISTING store.GetEnvConfig reference-shape reader (store stays frozen) —
// the read counterpart of envconfig.go's envConfigStore. The create supplies the
// env_config_ref it intends to launch against (CreateSession's env_config_ref); this
// stage confirms that ref resolves to a recorded env config whose RepoRef matches the
// enrolled repo, so the two keys are about the SAME repo (an env config for repo A
// cannot satisfy the second key for an enrollment of repo B).
type envConfigReader interface {
	GetEnvConfig(ctx context.Context, ref string) (store.EnvConfig, error)
}

// TwoKeyRequest is the input to the §4.1 step-1 check: the repo being activated and
// the env_config_ref the create intends to launch against. RepoID is the first-key
// lookup; EnvConfigRef is the second-key lookup. Both are required — the check exists
// precisely to refuse when either is absent or unresolvable.
type TwoKeyRequest struct {
	// RepoID is the repo the create activates (the enrollment lookup key, D56 first
	// key). Required.
	RepoID string
	// EnvConfigRef is the recorded env-config reference the create launches against
	// (the §4.1 step-1 "RecordEnvConfig reference resolved" — D7/§9, the second key).
	// Required: an empty ref is the missing second key.
	EnvConfigRef string
}

// TwoKeyResult is the step-1 check's output on success: the resolved enrollment (the
// first key) and the resolved env config (the second key). It is the DATA step 2 of
// the create choreography consumes — the env config's resolved ImageID + coupled
// invariants attach to the session record (doc 15 §4.1 step 2: "env-config + image
// references attached"), and the enrollment is the audit fact recorded alongside.
type TwoKeyResult struct {
	// Enrollment is the resolved first key (D56 whether) — the enrolled repo + the
	// authorized enroller, carried as the audit fact for the session record.
	Enrollment Enrollment
	// EnvConfig is the resolved second key (D56 how) — the recorded env config the
	// create launches against, whose ImageID + coupled invariants step 2 attaches.
	EnvConfig store.EnvConfig
}

// CheckTwoKeyActivation is the doc 15 §4.1 STEP-1 stage: it resolves BOTH D56 keys and
// refuses the create fail-closed unless both are present, authoritative, and about the
// SAME repo. "Neither alone activates a repo" (D56) is enforced here as a structural
// property: a create cannot reach step 2 without both keys.
//
// Order (all refusals fail-closed, ErrTwoKeyRefused; a resolver FAULT is surfaced
// verbatim, never as ErrTwoKeyRefused — the create-driver-vs-stall distinction):
//  1. ENROLLMENT (key 1) — ResolveEnrollment(repoID). ok=false ⇒ refused (repo not
//     enrolled). A fault is surfaced verbatim.
//  2. ENROLLMENT AUTHORITY — enrollmentAuthoritative(). A repo enrolled by a
//     non-authoritative role (or by repo-admin under an org-owner restriction) is
//     refused: the enrollment exists but lacks the D56 admin authority.
//  3. ENV SPEC (key 2) — GetEnvConfig(env_config_ref). store.ErrNotFound ⇒ refused
//     (no checked-in env spec). Any other store error is a fault, surfaced verbatim.
//  4. SAME-REPO JOIN — the resolved env config's RepoRef must match the enrolled
//     RepoID (when the env config is repo-referenced). An env config for a DIFFERENT
//     repo cannot satisfy the second key for THIS enrollment — the two keys must be
//     about the same repo or "both present" is an illusion. An INLINE env config (no
//     RepoRef) rides the enrolled repo (it is request-carried for this create), so
//     the join is satisfied by the create's explicit pairing.
//
// On success it returns both resolved keys for step 2 to attach. The seams are the
// SAME backing store the rest of create uses (the real *store.Memory / *store.Postgres
// satisfies envConfigReader; the EnrollmentResolver is the v0 default until the M2
// enrollment surface lands).
func CheckTwoKeyActivation(
	ctx context.Context,
	enroll EnrollmentResolver,
	envs envConfigReader,
	req TwoKeyRequest,
) (TwoKeyResult, error) {
	if enroll == nil {
		return TwoKeyResult{}, fmt.Errorf("sessions: CheckTwoKeyActivation: no enrollment resolver configured")
	}
	if envs == nil {
		return TwoKeyResult{}, fmt.Errorf("sessions: CheckTwoKeyActivation: no env-config reader configured")
	}

	repoID := strings.TrimSpace(req.RepoID)
	if repoID == "" {
		return TwoKeyResult{}, fmt.Errorf("%w: no repo to activate", ErrTwoKeyRefused)
	}
	envRef := strings.TrimSpace(req.EnvConfigRef)
	if envRef == "" {
		// The second key is structurally absent — no env_config_ref to resolve.
		return TwoKeyResult{}, fmt.Errorf("%w (empty env_config_ref) for repo %q", ErrNoEnvSpec, repoID)
	}

	// (1) ENROLLMENT — the first key.
	enrollment, ok, err := enroll.ResolveEnrollment(ctx, repoID)
	if err != nil {
		// A resolver fault (enrollment store unreachable) — NOT "not enrolled".
		// Surfaced verbatim so the create driver can stall/retry, never attributed as
		// a refusal to the requester (the §4.1 rollback note).
		return TwoKeyResult{}, fmt.Errorf("sessions: CheckTwoKeyActivation: resolve enrollment for repo %q: %w", repoID, err)
	}
	if !ok {
		return TwoKeyResult{}, fmt.Errorf("%w: repo %q is not enrolled in the control plane", ErrNotEnrolled, repoID)
	}

	// (1b) ENROLLMENT ENABLED — the D56 "whether" toggle. An enrollment record whose
	// setting was flipped OFF (a repo admin enrolled it and then disabled it) is the
	// first key being absent just as much as no record at all: the control plane answers
	// WHETHER, and the answer is no. The field is Disabled (zero=enabled) so an existing
	// resolver that returns ok=true for a live enrollment is unchanged.
	if enrollment.Disabled {
		return TwoKeyResult{}, fmt.Errorf("%w: repo %q enrollment is disabled in the control plane", ErrNotEnrolled, repoID)
	}

	// (2) ENROLLMENT AUTHORITY — the D56 admin act (repo-admin default; org-owner
	// restrictable to org-admin). A repo enrolled by a non-authority is refused.
	if !enrollment.enrollmentAuthoritative() {
		return TwoKeyResult{}, fmt.Errorf("%w: repo %q enrolled by role %q is not an enrollment authority (D56: repo-admin by default, org-admin when org-restricted=%t)",
			ErrNotEnrolled, repoID, enrollment.EnrolledByRole, enrollment.OrgRestricted)
	}

	// (3) ENV SPEC — the second key.
	envCfg, err := envs.GetEnvConfig(ctx, envRef)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// No recorded env config for this ref: the second key is absent — refused.
			return TwoKeyResult{}, fmt.Errorf("%w resolves for ref %q (repo %q)", ErrNoEnvSpec, envRef, repoID)
		}
		// Any other store error is a fault, surfaced verbatim (not a refusal).
		return TwoKeyResult{}, fmt.Errorf("sessions: CheckTwoKeyActivation: resolve env config %q: %w", envRef, err)
	}

	// (4) SAME-REPO JOIN — both keys must be about the SAME repo. A repo-referenced
	// env config for a DIFFERENT repo cannot satisfy this enrollment's second key. An
	// INLINE env config (no RepoRef) is request-carried for THIS create and rides the
	// enrolled repo, so its join is the create's explicit pairing.
	if envCfg.RepoRef != "" && strings.TrimSpace(envCfg.RepoRef) != repoID {
		return TwoKeyResult{}, fmt.Errorf("%w: env spec %q is checked into repo %q, not the enrolled repo %q (the two keys must be about the same repo)",
			ErrNoEnvSpec, envRef, envCfg.RepoRef, repoID)
	}

	return TwoKeyResult{Enrollment: enrollment, EnvConfig: envCfg}, nil
}

// ErrIsTwoKeyRefused reports whether err is the §4.1 step-1 two-key refusal
// (ErrTwoKeyRefused) — exposed so a create driver can distinguish a missing activation
// key (attributable: the repo isn't fully opted in) from a resolver/store fault (a
// transient stall the §4.1 rollback note covers). It is the activation-gate analog of
// ErrIsRoleRefused / ErrIsLaunchRefused.
func ErrIsTwoKeyRefused(err error) bool { return errors.Is(err, ErrTwoKeyRefused) }
