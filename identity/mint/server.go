// SPDX-License-Identifier: Apache-2.0

// gRPC server adapters for the GENERATED identity.v1 seams (doc 16 §9).
//
// IdentityValidationService.Validate is the D22 seam. IdentityMintService now
// exposes all FIVE mint methods as generated grpc servers — MintInterceptionCA
// (Stage-0) plus the D111 M0-window additive promotions MintGrants,
// MintWorkloadIdentity, RevokeSession, and MintSessionToken (ca_mint.proto /
// grants.proto). These adapters embed the generated Unimplemented*Server
// (forward-compat) and translate the proto request/response onto the native Shim
// methods, doing the boundary impedance conversion (time.Time ↔ int64
// unix-seconds, time.Duration ↔ int64 seconds, the GrantScope enum zero-value
// shift, string↔bytes for the placeholder token), so the shim is exercised over a
// real in-process grpc client exactly like identity/fakes/digest-publisher. No
// mint RPC remains RESERVED-only; MintSessionToken is now wired (the doc 19 token
// work, D99/D97 — the U5 host-agent shim dials it for a real per-session token).
package mint

import (
	"context"
	"time"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// Operation names a coarse-grained action a swap-path caller is about to
// perform. The D22 Validate seam asserts the presented sub-token's `ds_scopes`
// COVER the D127 scope(s) the operation maps to (doc 23 §6). This is the CALLER
// side of the predicate that server.go's Validate reads: before presenting a
// credential the swap executor maps its operation onto
// ValidateRequest.desired_scopes off [OperationScopes], so an unqualified call
// (empty desired_scopes) is a deliberate no-scope-assertion, never an accidental
// one. identity/mint's only legal cross-tree import is proto/gen/go (D80), so
// the doc 23 §6 scope strings are named here as literals — byte-identical to
// identity/auth-sdk/token and the Rust corpus — rather than imported from
// auth-sdk. Parity with the canonical taxonomy is asserted by this package's own
// tests (desired_scopes_caller_test.go pins each literal, and the live-seam test
// mints against them); scripts/check-corpus-suffix.sh pins the auth-sdk↔Rust
// pair only and does NOT scan this file, so a mint-side typo is a test failure,
// not a corpus-suffix failure.
type Operation string

const (
	// OpWorkspaceRead reads source, filesystem contents, test output
	// (doc 23 §6 v1:code:read).
	OpWorkspaceRead Operation = "workspace:read"
	// OpWorkspaceWrite writes source, stages/commits/pushes
	// (doc 23 §6 v1:code:write).
	OpWorkspaceWrite Operation = "workspace:write"
	// OpSecretsFetch reaches the credential-swap path / a KV read
	// (doc 23 §6 v1:secrets:read).
	OpSecretsFetch Operation = "secrets:fetch"
	// OpEgressConnect initiates an outbound connect via the egress gateway
	// (doc 23 §6 v1:network:egress).
	OpEgressConnect Operation = "egress:connect"
	// OpSubtokenMint derives further sub-tokens — orchestrator only
	// (doc 23 §6 v1:identity:mint).
	OpSubtokenMint Operation = "subtoken:mint"
	// OpNotifyReceive receives token-lifecycle push events
	// (doc 23 §6 v1:notify:receive).
	OpNotifyReceive Operation = "notify:receive"
	// OpPolicyRead reads the composed policy snapshot
	// (doc 23 §6 v1:policy:read).
	OpPolicyRead Operation = "policy:read"
	// OpAuditWrite emits audit events to ds-telemetry (doc 23 §6 v1:audit:write).
	OpAuditWrite Operation = "audit:write"
)

// OperationScopes is the operation→required-scope(s) table (doc 23 §6). The swap
// executor maps the operation it is about to perform onto the D127 scope(s) it
// requires and lists them in ValidateRequest.desired_scopes; the seam denies
// scope_insufficient unless the presented sub-token's `ds_scopes` cover them.
// Package-level and treated as immutable — [ScopesForOperation] hands back copies.
var OperationScopes = map[Operation][]string{
	OpWorkspaceRead:  {"v1:code:read"},
	OpWorkspaceWrite: {"v1:code:write"},
	OpSecretsFetch:   {"v1:secrets:read"},
	OpEgressConnect:  {"v1:network:egress"},
	OpSubtokenMint:   {"v1:identity:mint"},
	OpNotifyReceive:  {"v1:notify:receive"},
	OpPolicyRead:     {"v1:policy:read"},
	OpAuditWrite:     {"v1:audit:write"},
}

// ScopesForOperation returns a COPY of the D127 scope(s) an operation requires
// (doc 23 §6), or nil for an unmapped/empty operation. Nil preserves the
// scope-unqualified Validate semantics exactly: no scope assertion is made, so
// grant + liveness govern alone. Returning a copy keeps the package-level table
// immutable under a caller that appends.
func ScopesForOperation(op Operation) []string {
	req := OperationScopes[op]
	if len(req) == 0 {
		return nil
	}
	out := make([]string, len(req))
	copy(out, req)
	return out
}

// NewScopedValidateRequest builds a ValidateRequest whose desired_scopes carry
// the D127 scope(s) the operation requires (doc 23 §6). This is the caller-side
// wiring the D22 seam was missing: server.go threads req.GetDesiredScopes() into
// ValidateScoped, but nothing populated it on the live path, so Go-side scope
// enforcement was inert outside tests. A real swap-path presentation names its
// operation here and desired_scopes is populated for it — non-empty for every
// mapped operation. An unmapped/empty operation yields empty desired_scopes (the
// frozen scope-unqualified semantics), never a panic.
func NewScopedValidateRequest(op Operation, presentedCredential []byte, sessionUUID, serviceID string) *identityv1.ValidateRequest {
	return &identityv1.ValidateRequest{
		PresentedCredential: presentedCredential,
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: sessionUUID},
		ServiceId:           serviceID,
		DesiredScopes:       ScopesForOperation(op),
	}
}

// ValidationServer adapts the Shim onto IdentityValidationServiceServer (the D22
// seam). It embeds UnimplementedIdentityValidationServiceServer for forward
// compatibility (the generated-stub contract).
type ValidationServer struct {
	identityv1.UnimplementedIdentityValidationServiceServer
	shim *Shim
}

// NewValidationServer wires a Shim behind the generated Validate seam.
func NewValidationServer(shim *Shim) *ValidationServer {
	return &ValidationServer{shim: shim}
}

// Validate translates the proto request onto Shim.Validate and maps the native
// verdict back onto the frozen ValidateResponse shape (verdict ALLOW | DENY{
// machine_readable_reason}, grant_ref, expiry_unix_seconds). A DENY is the D77
// in-band-403 payload — never a grpc error status, so the agent fails fast on a
// structured body rather than on a transport fault.
func (v *ValidationServer) Validate(_ context.Context, req *identityv1.ValidateRequest) (*identityv1.ValidateResponse, error) {
	// ValidateScoped folds the D127 scope predicate (doc 23 §6) onto the D22
	// check: desired_scopes carries the scope(s) the requested operation needs;
	// a token whose ds_scopes do not cover them denies scope_insufficient. An
	// empty desired_scopes preserves the scope-unqualified semantics exactly.
	res := v.shim.ValidateScoped(
		req.GetPresentedCredential(),
		req.GetSessionRef().GetSessionUuid(),
		req.GetServiceId(),
		req.GetDesiredScopes(),
	)
	resp := &identityv1.ValidateResponse{}
	if res.Verdict == VerdictAllow {
		resp.Verdict = identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW
		resp.GrantRef = res.GrantRef
		resp.ExpiryUnixSeconds = toUnix(res.Expiry)
	} else {
		resp.Verdict = identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY
		resp.MachineReadableReason = res.MachineReadableReason
	}
	return resp, nil
}

// MintServer adapts the Shim onto IdentityMintServiceServer. All five mint
// methods are generated grpc servers (MintInterceptionCA Stage-0 + the D111
// promotions MintGrants/MintWorkloadIdentity/RevokeSession/MintSessionToken); it
// embeds UnimplementedIdentityMintServiceServer for forward compatibility with
// any later additive RPC (no mint RPC remains reserved today).
type MintServer struct {
	identityv1.UnimplementedIdentityMintServiceServer
	shim *Shim
}

// NewMintServer wires a Shim behind the generated IdentityMint seam.
func NewMintServer(shim *Shim) *MintServer {
	return &MintServer{shim: shim}
}

// MintInterceptionCA translates the proto request onto the native interception
// mint (hierarchy 2, D82) and returns the per-session CA cert + proxy-bound key
// + session-lifetime expiry on the frozen MintInterceptionCAResponse shape.
func (m *MintServer) MintInterceptionCA(_ context.Context, req *identityv1.MintInterceptionCARequest) (*identityv1.MintInterceptionCAResponse, error) {
	bundle, err := m.shim.mintInterceptionCA(req.GetSessionRef().GetSessionUuid())
	if err != nil {
		return nil, err
	}
	return &identityv1.MintInterceptionCAResponse{
		CaCertificate:     bundle.CACertDER,
		CaPrivateKey:      bundle.CAKeyDER,
		ExpiryUnixSeconds: toUnix(bundle.Expiry),
	}, nil
}

// MintWorkloadIdentity translates the proto request onto the native hierarchy-1
// workload mint (doc 16 §3.1, D82) and returns the X.509 leaf (SPIFFE SAN) +
// parallel JWT + session-lifetime expiry on the MintWorkloadIdentityResponse
// shape. The TTL impedance conversion is int64 whole-seconds → time.Duration
// (zero seconds → zero Duration → the shim's default session TTL).
func (m *MintServer) MintWorkloadIdentity(_ context.Context, req *identityv1.MintWorkloadIdentityRequest) (*identityv1.MintWorkloadIdentityResponse, error) {
	bundle, err := m.shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID:   req.GetSessionUuid(),
		LaunchingUser: req.GetLaunchingUser(),
		Org:           req.GetOrg(),
		RepoBranch:    req.GetRepoBranch(),
		Runtime:       req.GetRuntime(),
		ParentSession: req.GetParentSession(),
		TTL:           time.Duration(req.GetTtlSeconds()) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &identityv1.MintWorkloadIdentityResponse{
		CertDer:           bundle.CertDER,
		SpiffeUri:         bundle.SPIFFEURI,
		Jwt:               bundle.JWT,
		ExpiryUnixSeconds: toUnix(bundle.Expiry),
	}, nil
}

// MintGrants translates the proto request onto the native deterministic grant
// issuance (doc 16 §5.1; IssueGrants + per-service placeholder mint) and maps the
// native GrantSet back onto the proto GrantSet shape. The shim-wide org
// `services[]` registry (WithServiceRegistry) is NOT a request field — only the
// env spec rides the wire — so a session with no registry installed fails closed
// (errNoRegistry) exactly as the native surface does.
func (m *MintServer) MintGrants(_ context.Context, req *identityv1.MintGrantsRequest) (*identityv1.GrantSet, error) {
	set, err := m.shim.MintGrants(MintGrantsRequest{
		SessionUUID: req.GetSessionUuid(),
		Env:         envSpecFromProto(req.GetEnv()),
	})
	if err != nil {
		return nil, err
	}
	return grantSetToProto(set), nil
}

// RevokeSession translates the proto request onto the native active-eviction
// path (doc 16 §5.4): it marks the session record revoked so a subsequent
// Validate fails CLOSED (D77 in-band-403). The native surface returns only error;
// a nil error IS the ack — never a transport error for the eviction itself — so
// the response body is the (currently empty) RevokeSessionResponse.
func (m *MintServer) RevokeSession(_ context.Context, req *identityv1.RevokeSessionRequest) (*identityv1.RevokeSessionResponse, error) {
	if err := m.shim.RevokeSession(req.GetSessionUuid(), req.GetReason()); err != nil {
		return nil, err
	}
	return &identityv1.RevokeSessionResponse{}, nil
}

// MintSessionToken translates the proto request onto the native scoped per-session
// base-token mint (doc 19 §3, D99/D97) and maps the returned SessionTokenBundle
// onto the MintSessionTokenResponse shape. The TTL impedance conversion is int64
// whole-seconds → time.Duration (zero seconds → zero Duration → the shim's default
// session TTL); the Expiry impedance conversion is time.Time → int64 unix-seconds
// (toUnix). The token bytes are the format-opaque presented credential (doc 19 §5)
// — never parsed here, just carried. parent_session is NOT a field: the base token
// always has an empty parent_session (doc 19 §3), and child hops come from offline
// AttenuateSessionToken, never a second mint (doc 19 §4).
func (m *MintServer) MintSessionToken(_ context.Context, req *identityv1.MintSessionTokenRequest) (*identityv1.MintSessionTokenResponse, error) {
	bundle, err := m.shim.MintSessionToken(MintSessionTokenReq{
		SessionUUID:   req.GetSessionUuid(),
		LaunchingUser: req.GetLaunchingUser(),
		Org:           req.GetOrg(),
		RepoBranch:    req.GetRepoBranch(),
		RoleRef:       req.GetRoleRef(),
		TaskRef:       req.GetTaskRef(),
		Services:      req.GetServices(),
		TTL:           time.Duration(req.GetTtlSeconds()) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &identityv1.MintSessionTokenResponse{
		Token:             bundle.Token,
		ExpiryUnixSeconds: toUnix(bundle.Expiry),
		SessionUuid:       bundle.SessionUUID,
		RevocationIds:     bundle.RevocationIDs,
		AttenuationDepth:  int32(bundle.AttenuationDepth),
	}, nil
}

// --- boundary conversion helpers (native mint types ↔ generated proto) -------

// envSpecFromProto maps the wire EnvSpec onto the native one. The proto TTL
// overrides are whole-seconds (int64); the native model carries time.Duration.
func envSpecFromProto(env *identityv1.EnvSpec) EnvSpec {
	out := EnvSpec{Services: env.GetServices()}
	if ov := env.GetTtlOverrideSeconds(); len(ov) > 0 {
		out.TTLOverrides = make(map[string]time.Duration, len(ov))
		for svc, secs := range ov {
			out.TTLOverrides[svc] = time.Duration(secs) * time.Second
		}
	}
	return out
}

// grantToProto maps one native Grant onto the wire Grant, doing the impedance
// conversions: time.Time → int64 unix-seconds, the GrantScope enum zero-value
// shift (native ScopeSession is iota 0; the proto reserves 0 for _UNSPECIFIED so
// SESSION is value 1 — a missing/never-set scope must be distinguishable from a
// deliberate SESSION on the wire, grants.proto), and the DERIVED cred_class
// digest tag (ISSUED{service_id}) carried on the record (§6/§11.1 step 7).
func grantToProto(g Grant) *identityv1.Grant {
	return &identityv1.Grant{
		Identity:            g.Identity,
		ServiceId:           g.ServiceID,
		Scope:               grantScopeToProto(g.Scope),
		IssuedAtUnixSeconds: toUnix(g.IssuedAt),
		ExpiryUnixSeconds:   toUnix(g.Expiry),
		GrantRef:            g.GrantRef,
		CredClassDigestTag:  IssuedDigestTag(g),
	}
}

// grantScopeToProto shifts the native iota-0 GrantScope onto the proto enum,
// whose 0 is reserved for _UNSPECIFIED (SESSION is value 1, FLEET is 2).
func grantScopeToProto(s GrantScope) identityv1.GrantScope {
	switch s {
	case ScopeFleet:
		return identityv1.GrantScope_GRANT_SCOPE_FLEET
	default:
		return identityv1.GrantScope_GRANT_SCOPE_SESSION
	}
}

// grantSetToProto maps the native GrantSet onto the wire GrantSet, including the
// per-service placeholder tokens (native Token is a string; the wire token is
// bytes — the opaque bearer material, never parsed by consumers).
func grantSetToProto(set *GrantSet) *identityv1.GrantSet {
	out := &identityv1.GrantSet{}
	for _, g := range set.Grants {
		out.Grants = append(out.Grants, grantToProto(g))
	}
	for _, ph := range set.Placeholders {
		out.Placeholders = append(out.Placeholders, &identityv1.PlaceholderToken{
			ServiceId: ph.ServiceID,
			Grant:     grantToProto(ph.Grant),
			Token:     []byte(ph.Token),
		})
	}
	return out
}
