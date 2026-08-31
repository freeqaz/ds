// SPDX-License-Identifier: Apache-2.0
package token

import "errors"

// Scope constants (D127 — doc 23 §6). The v1: prefix is the taxonomy version.
const (
	ScopeCodeRead    = "v1:code:read"
	ScopeCodeWrite   = "v1:code:write"
	ScopeSecretsRead = "v1:secrets:read"
	ScopeNetEgress   = "v1:network:egress"
	ScopeIdentMint   = "v1:identity:mint"
	ScopeNotifyRecv  = "v1:notify:receive"
	ScopePolicyRead  = "v1:policy:read"
	ScopeAuditWrite  = "v1:audit:write"
)

// AllScopes is the full D127 scope set.
var AllScopes = []string{ScopeCodeRead, ScopeCodeWrite, ScopeSecretsRead,
	ScopeNetEgress, ScopeIdentMint, ScopeNotifyRecv, ScopePolicyRead, ScopeAuditWrite}

// Operation names a coarse-grained action a session may request. The D22
// Validate seam asserts the presented sub-token's ds_scopes COVER the D127
// scope(s) an operation maps to (doc 23 §6); a caller maps its operation onto
// ValidateRequest.desired_scopes off [OperationScopes] before presenting.
type Operation string

const (
	// OpWorkspaceRead reads source, filesystem contents, test output.
	OpWorkspaceRead Operation = "workspace:read"
	// OpWorkspaceWrite writes source, stages/commits/pushes.
	OpWorkspaceWrite Operation = "workspace:write"
	// OpSecretsFetch reaches the credential-swap path / a Vault KV read.
	OpSecretsFetch Operation = "secrets:fetch"
	// OpEgressConnect initiates an outbound connect via the egress gateway.
	OpEgressConnect Operation = "egress:connect"
	// OpSubtokenMint derives further sub-tokens (restricted: orchestrator only).
	OpSubtokenMint Operation = "subtoken:mint"
	// OpNotifyReceive receives token-lifecycle push events.
	OpNotifyReceive Operation = "notify:receive"
	// OpPolicyRead reads the composed policy snapshot.
	OpPolicyRead Operation = "policy:read"
	// OpAuditWrite emits audit events to ds-telemetry.
	OpAuditWrite Operation = "audit:write"
)

// OperationScopes maps a requested operation onto the D127 scope(s) it needs
// (doc 23 §6 token scope taxonomy): e.g. an egress connect asserts
// v1:network:egress, a workspace write asserts v1:code:write. The auth SDK owns
// the doc 23 taxonomy, so this is its canonical home; identity/mint keeps a
// byte-identical parallel table because the D80 fence bars it from importing
// this package. Package-level and treated as immutable — [ScopesForOperation]
// returns copies.
var OperationScopes = map[Operation][]string{
	OpWorkspaceRead:  {ScopeCodeRead},
	OpWorkspaceWrite: {ScopeCodeWrite},
	OpSecretsFetch:   {ScopeSecretsRead},
	OpEgressConnect:  {ScopeNetEgress},
	OpSubtokenMint:   {ScopeIdentMint},
	OpNotifyReceive:  {ScopeNotifyRecv},
	OpPolicyRead:     {ScopePolicyRead},
	OpAuditWrite:     {ScopeAuditWrite},
}

// ScopesForOperation returns a COPY of the D127 scope(s) an operation requires
// (doc 23 §6), or nil for an unmapped/empty operation. Nil preserves the
// scope-unqualified Validate semantics: no scope assertion is made. Returning a
// copy keeps the package-level table immutable under a caller that appends.
func ScopesForOperation(op Operation) []string {
	req := OperationScopes[op]
	if len(req) == 0 {
		return nil
	}
	out := make([]string, len(req))
	copy(out, req)
	return out
}

var ErrToken = errors.New("token: validation failed")
var ErrRevoked = errors.New("token: token has been revoked")
