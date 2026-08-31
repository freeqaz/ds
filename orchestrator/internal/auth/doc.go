// Package auth is the orchestrator-side half of the Okta-via-generic-OIDC
// launch-time human-auth integration (doc 16 §11.2; doc 07 §2c). The IdP front
// end — the device-code / redirect flows, ID-token validation, and the
// group→role mapping — lives in the standalone identity/idp module; THIS package
// is what the orchestrator runs at session-create time:
//
//   - PRINCIPAL RESOLUTION (resolve.go): it upserts the IdP-authenticated
//     human's resolved auth result into the control-plane principal record
//     (doc 16 §3.2) via the EXPORTED store APIs (GetPrincipalByIdP /
//     CreatePrincipal / SetPrincipalRoles) — the orchestrator/internal/store
//     shared files stay FROZEN; this package only CALLS them. The OIDC subject
//     becomes the §3.2 IdP-subject key and the value the workload identity's
//     `launching_user` claim carries; the §11.2 group→role mapping becomes the
//     principal's role set (DERIVED from the asserted groups, never a parallel
//     stored ACL the IdP can drift from).
//
//   - THE LAUNCH GATE (launchgate.go): it refuses an UNAUTHENTICATED launch
//     (no IdP-backed principal) and, for an authenticated launch, links the
//     resolved principal to the new session (SetSessionLaunchingPrincipal) so
//     store.ResolveLaunchingUserClaim — the seam orch8 landed and
//     sessions.ResolveMintClaims consumes — yields the IdP-backed subject the
//     MintWorkloadIdentity request stamps. A launch with no principal is
//     refused, never minted with a fabricated subject (the §3.1
//     "IdP-asserted or absent, never self-declared" contract).
//
// THE MINT-TIME-ONLY BOUNDARY (doc 16 §11.2, load-bearing — stated here because
// this is where the boundary is visible in code). The IdP and this package
// participate ONLY at mint/launch time. Per-request workload validation is the
// frozen D22 `Validate` seam (identity/mint), NEVER the IdP and NEVER this
// package: nothing here is on the egress hot path. Putting the IdP on the
// request path would break the §5.1 "fetch per-grant, never per-request" latency
// story and re-introduce the availability dependency the D22 seam keeps off the
// hot path.
//
// CROSS-MODULE DISCIPLINE. identity/idp is a SEPARATE Go module; the only legal
// cross-tree import is proto/gen/go. This package depends on the store (same
// module — legal) and consumes the idp module's AuthResult as the DATA shape it
// upserts, mirrored locally (resolve.go ResolvedAuth) so the orchestrator does
// not take a cross-module import to carry a value across the boundary — the same
// discipline sessions.MintWorkloadIdentityClaims uses to carry the claim across
// the proto seam as data.
package auth
