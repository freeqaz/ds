package sessions

// This file is the §4.1 STEP-5 create-choreography stage (doc 15 §4.1 step 5,
// D82/D99): "Identity + interception-CA mint". It is the create-sequence point
// where the per-session workload identity is minted, and per the round-3
// adjudication the claims that mint carries are sourced from the launching_user
// RESOLVER, never fabricated. This stage is the honest minimal driver of that
// point: it CONSULTS ResolveMintClaims (mintrequest.go) to assemble the
// launching-user portion of the mint request, threading the resolver's nullable
// (ok=false) outcome through as a first-class, non-error mint shape.
//
// What this stage is and is NOT:
//   - IS: the create-sequence stage that, at step 5, calls ResolveMintClaims and
//     produces the assembled MintWorkloadIdentity request the orchestrator hands
//     to identity/mint across the proto seam (when the proto lands). It proves
//     the resolver is consulted, including the ok=false nullable case.
//   - IS NOT: the mint RPC itself (identity/mint is a separate module; the only
//     legal cross-tree import is proto/gen/go, so this stage carries the request
//     as DATA — MintWorkloadIdentityClaims — never the mint module's type) and
//     IS NOT role_ref resolution/pinning. Per the frozen precedence (§4.1:
//     `1 ≺ 2 ≺ 3 ≺ {6,7,8}; 5 ≺ 6; 5 ≺ 7's injection`), step 5 runs AFTER the
//     session record exists (step 2) and BEFORE the digest write (step 6) and
//     the step-7 CA injection.
//
// role_ref status at step 5 TODAY (recorded per the deferral coordination with
// taskdb 01KTWJ5A88, "Wire role_ref resolution and pinning into the CreateSession
// choreography"): role_ref resolution + pinning is a SEPARATE, still-open task
// (its deps unmet) that lands at §4.1 steps 1–2, not step 5. So this step-5 mint
// assembly passes NO resolved role_ref today: RoleRef is the empty/default
// posture (default@<current>, recorded explicitly so "no role" and "default
// role" are the same auditable fact — but the RESOLUTION of that to a pinned
// (role_name, role_version, role_content_hash) is 01KTWJ5A88's job, not this
// caller's). This stage carries the field so the seam exists, defaulted empty,
// and threads only the launching_user claims that orch8's resolver sources.

import "context"

// CreateStep5Request is the input to the step-5 mint-assembly stage: the session
// being created (its UUID is the resolver key and the MintReq.session_uuid) plus
// the role_ref the create chose at steps 1–2. RoleRef is the verbatim ref token
// the create resolved (or the empty/default posture); step 5 carries it onto the
// assembled request WITHOUT resolving it — the resolution + content-hash pinning
// is taskdb 01KTWJ5A88's deferred work at steps 1–2, not this stage's.
type CreateStep5Request struct {
	SessionUUID string // the session the identity is minted for (resolver key + MintReq.session_uuid)
	RoleRef     string // the role ref the create chose at §4.1 steps 1–2 ("" = default@<current>, unresolved here)
}

// CreateStep5Result is the assembled §4.1 step-5 output: the launching-user
// claims the mint request carries (resolver-sourced, nullable-aware) plus the
// role_ref carried through from the create. It is the DATA the orchestrator's
// mint-fronting code populates the generated proto MintWorkloadIdentityReq from
// when the proto lands; until then it is the honest assembled shape.
type CreateStep5Result struct {
	// Claims is the launching-user portion of the mint request, sourced from the
	// launching_user resolver via ResolveMintClaims. Claims.HasLaunchingUser
	// distinguishes the resolved case from the nullable (resolver ok=false) case;
	// in the nullable case the three attribution fields are empty and the mint
	// stamps NO launching_user claim (never a fabricated subject — doc 16 §3.1).
	Claims MintWorkloadIdentityClaims

	// RoleRef is carried verbatim from the create (CreateStep5Request.RoleRef).
	// It is the empty/default posture today; resolution/pinning is the deferred
	// taskdb 01KTWJ5A88 work at steps 1–2, not stamped here.
	RoleRef string
}

// AssembleStep5MintRequest is the §4.1 step-5 stage: it CONSULTS the launching_user
// resolver (via ResolveMintClaims) to assemble the launching-user portion of the
// MintWorkloadIdentity request for req.SessionUUID, and carries the create's
// role_ref through verbatim. It is the create-sequence point that threads the
// resolver, including the nullable (ok=false) outcome:
//
//   - resolved: Claims.HasLaunchingUser==true with the IdP subject, principal ID,
//     and org sourced from the linked principal — the mint stamps a real
//     launching_user claim.
//   - NULLABLE (resolver ok==false, no error): Claims.HasLaunchingUser==false and
//     the attribution fields empty — the session has no launching principal (a
//     pre-mint / system session), so the mint stamps NO launching_user claim.
//     This is a VALID, non-error mint shape: the stage returns it with a nil
//     error, never fabricating a subject. This is the explicit ok=false case the
//     acceptance calls out.
//   - error: an unknown session or a dangling principal link is surfaced from the
//     resolver (ResolveMintClaims wraps store.ErrNotFound / store.ErrInvalid),
//     never swallowed into a fabricated claim. Per §4.1's rollback note, a
//     failure at step 5 signals identity/CA revocation to Identity — surfacing
//     the error here is what lets the create driver drive that compensation.
func AssembleStep5MintRequest(ctx context.Context, r launchingUserResolver, req CreateStep5Request) (CreateStep5Result, error) {
	claims, err := ResolveMintClaims(ctx, r, req.SessionUUID)
	if err != nil {
		return CreateStep5Result{}, err
	}
	return CreateStep5Result{
		Claims:  claims,
		RoleRef: req.RoleRef,
	}, nil
}
