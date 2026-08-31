package sessions

// This file is the ORCHESTRATOR-SIDE CALLER of the `launching_user` resolver
// seam (store.ResolveLaunchingUserClaim, doc 16 §3.1/§4): the path that
// assembles the MintWorkloadIdentity request sources its launching-user claim
// VALUE from the resolver instead of a fabricated placeholder. The store
// resolved the claim from the session→principal linkage; this caller carries
// that VALUE across the proto seam into the request fields.
//
// Cross-tree note (binding): identity/mint is a SEPARATE Go module and the only
// legal cross-tree import is proto/gen/go (CI-enforced). So this caller does NOT
// import the mint module's request type, and the resolved claim crosses the seam
// as DATA, not as a store handle: MintWorkloadIdentityClaims is the in-package
// projection of exactly the wire fields the §4 MintWorkloadIdentityReq names
// (session_uuid, launching_principal, org). The orchestrator's mint-fronting
// code populates the generated proto request from this value when the proto
// lands; until then this is the honest caller shape, resolver-sourced.

import (
	"context"
	"fmt"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// launchingUserResolver is the narrow read-seam this caller needs: the
// `launching_user` resolver (store.ResolveLaunchingUserClaim). It is a
// dependency-injected interface, not the full store.Repository, so the mint
// request assembly depends only on the one method it consumes and a test fake or
// either store impl (*store.Memory / *store.Postgres) satisfies it identically.
//
// The (claim, ok, err) shape is the resolver's: ok==false with a nil error is
// the NULLABLE case (the session has no launching principal — a pre-mint or
// system session); a non-nil error is an unknown session or a dangling link.
type launchingUserResolver interface {
	ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error)
}

// MintWorkloadIdentityClaims is the in-package projection of the launching-user
// portion of the §4 MintWorkloadIdentityReq — the fields that the resolver
// sources (session_uuid, launching_principal, org, and the launching_user claim
// VALUE). It is the DATA the orchestrator carries across the proto seam to
// identity/mint, never a store handle and never the mint module's own type
// (which this module must not import).
//
// HasLaunchingUser distinguishes the resolved case from the NULLABLE case
// (resolver ok==false): when false, LaunchingUser/LaunchingPrincipal/Org are
// empty by construction and the mint call stamps NO launching_user claim — never
// a fabricated subject. The doc 16 §3.1 contract is that the claim is
// IdP-asserted or absent, never self-declared.
type MintWorkloadIdentityClaims struct {
	SessionUUID string // the session the identity is minted for (MintReq.session_uuid)

	// Resolved launching-user attribution. All three are empty when
	// HasLaunchingUser is false (the nullable / system-session case).
	HasLaunchingUser   bool
	LaunchingUser      string // the IdP subject — the launching_user claim VALUE (§3.1)
	LaunchingPrincipal string // the principal's stable ID (MintReq.launching_principal)
	Org                string // the org the subject is asserted within (MintReq.org)
}

// ResolveMintClaims assembles the launching-user portion of a
// MintWorkloadIdentity request for sessionUUID by calling the resolver seam.
// It is the caller that orch8 landed the resolver for: the mint-request path
// sources its launching_user claim VALUE here instead of a placeholder.
//
// Outcomes mirror the resolver contract (store.ResolveLaunchingUserClaim):
//   - resolved: HasLaunchingUser==true with the IdP subject, principal ID, and
//     org populated from the linked principal.
//   - NULLABLE (resolver ok==false, no error): HasLaunchingUser==false and the
//     three attribution fields empty — the session has no launching principal,
//     so the request carries SessionUUID only and the mint stamps no
//     launching_user. This is the explicit ok=false nullable case the acceptance
//     calls out: it is a valid, non-error mint shape, never a fabricated subject.
//   - error: an unknown session (store.ErrNotFound) or a dangling principal link
//     (store.ErrInvalid) is surfaced, never swallowed into a fabricated claim.
func ResolveMintClaims(ctx context.Context, r launchingUserResolver, sessionUUID string) (MintWorkloadIdentityClaims, error) {
	claim, ok, err := r.ResolveLaunchingUserClaim(ctx, sessionUUID)
	if err != nil {
		return MintWorkloadIdentityClaims{}, fmt.Errorf("resolve launching_user for session %s: %w", sessionUUID, err)
	}
	req := MintWorkloadIdentityClaims{SessionUUID: sessionUUID}
	if !ok {
		// Nullable case: no launching principal. Stamp no launching_user claim.
		return req, nil
	}
	req.HasLaunchingUser = true
	req.LaunchingUser = claim.Subject
	req.LaunchingPrincipal = claim.PrincipalID
	req.Org = claim.Org
	return req, nil
}
