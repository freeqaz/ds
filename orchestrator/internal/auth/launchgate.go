package auth

import (
	"context"
	"fmt"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// launchgate.go is the LAUNCH GATE (doc 16 §11.2): a session may be launched
// ONLY by an IdP-authenticated human, and the resolved principal is linked to
// the session so store.ResolveLaunchingUserClaim — the seam orch8 landed and
// sessions.ResolveMintClaims consumes — yields the IdP-backed subject the
// MintWorkloadIdentity request stamps as `launching_user` (doc 16 §3.1/§4).
//
// THE LOAD-BEARING SEPARATION (stated where it is visible in code). This gate
// runs ONCE, at launch — it authenticates the human and links the principal. It
// is NOT the per-request authority: every egress request's credential is
// validated at the frozen D22 `Validate` seam (identity/mint), with no call to
// the IdP and no call to this gate. The gate's output is a stored principal +
// a session link; the request hot path never reaches back here.

// sessionLinker is the narrow store seam the launch gate writes through: it
// links a session to its launching principal (the §3.1 attribution shape) and,
// for the gate's proof, resolves the launching_user claim back out. Both are
// EXISTING exported store methods (orchestrator/internal/store stays frozen);
// the gate only calls them.
type sessionLinker interface {
	SetSessionLaunchingPrincipal(ctx context.Context, sessionUUID, principalID string) error
	ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error)
}

// LaunchGate refuses an unauthenticated launch and links an authenticated one's
// principal to its session. It composes the principal Resolver (upsert) with the
// session linker; the orchestrator session-create choreography calls AuthorizeLaunch
// after the session row exists and before the MintWorkloadIdentity request is
// assembled (sessions.ResolveMintClaims then reads the link the gate wrote).
type LaunchGate struct {
	resolver *Resolver
	linker   sessionLinker
}

// NewLaunchGate composes a LaunchGate from a principal Resolver and the session
// linker (typically the same store value satisfies the linker; the resolver
// wraps it for the upsert).
func NewLaunchGate(resolver *Resolver, linker sessionLinker) *LaunchGate {
	return &LaunchGate{resolver: resolver, linker: linker}
}

// LaunchAuthorization is the gate's result: the IdP-backed principal that
// launched the session and the resolved launching_user claim value the
// MintWorkloadIdentity request will stamp (doc 16 §3.1/§4). Returning the
// resolved claim is the gate's PROOF that the authenticated launch feeds the
// mint shape — ResolveLaunchingUserClaim, read back through the link the gate
// just wrote, yields the IdP subject (not a placeholder).
type LaunchAuthorization struct {
	Principal store.Principal          // the IdP-backed launching principal (§3.2)
	Claim     store.LaunchingUserClaim // the resolved launching_user value (§3.1/§4)
}

// AuthorizeLaunch is the gate. It REFUSES an unauthenticated launch — a nil
// *ResolvedAuth (no IdP auth happened) is ErrAuth, no session link, no mint — so
// a session can be launched ONLY by an IdP-authenticated user (the acceptance's
// "unauthenticated launch refused"). For an authenticated launch it:
//
//  1. upserts the resolved human into the §3.2 principal record (Resolver),
//  2. links the principal to the session (SetSessionLaunchingPrincipal), so
//  3. ResolveLaunchingUserClaim yields the IdP subject — the proof the
//     authenticated launch feeds the mint request shape (the acceptance's
//     "authenticated launch yields an IdP-backed principal whose
//     ResolveLaunchingUserClaim value feeds the mint request shape").
//
// A nil ra is the unauthenticated case; pass a non-nil *ResolvedAuth from the
// IdP flow for an authenticated launch.
func (g *LaunchGate) AuthorizeLaunch(ctx context.Context, sessionUUID string, ra *ResolvedAuth) (LaunchAuthorization, error) {
	if ra == nil {
		// Unauthenticated launch: no IdP auth result, so no principal. Refuse —
		// the workload identity would otherwise carry a self-declared subject,
		// which the §3.1 "IdP-asserted or absent, never self-declared" contract
		// forbids for a USER-launched session.
		return LaunchAuthorization{}, fmt.Errorf("%w: launch requires an IdP-authenticated user", ErrAuth)
	}

	principal, err := g.resolver.ResolvePrincipal(ctx, *ra)
	if err != nil {
		return LaunchAuthorization{}, err // already wrapped (ErrAuth / store fault)
	}

	if err := g.linker.SetSessionLaunchingPrincipal(ctx, sessionUUID, principal.ID); err != nil {
		return LaunchAuthorization{}, fmt.Errorf("auth: link principal %s to session %s: %w", principal.ID, sessionUUID, err)
	}

	// Read the claim back through the link the gate just wrote — this is the
	// VALUE sessions.ResolveMintClaims will source for the MintWorkloadIdentity
	// request, so returning it proves the authenticated launch feeds the mint
	// shape with an IdP-backed subject (not a placeholder).
	claim, ok, err := g.linker.ResolveLaunchingUserClaim(ctx, sessionUUID)
	if err != nil {
		return LaunchAuthorization{}, fmt.Errorf("auth: resolve launching_user for session %s: %w", sessionUUID, err)
	}
	if !ok {
		// The link was just written, so the resolver MUST see it; a miss is a
		// store inconsistency surfaced loudly rather than minting a placeholder.
		return LaunchAuthorization{}, fmt.Errorf("%w: linked principal did not resolve for session %s", ErrAuth, sessionUUID)
	}

	return LaunchAuthorization{Principal: principal, Claim: claim}, nil
}
