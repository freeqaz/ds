// SPDX-License-Identifier: Apache-2.0

// D127 token-scope enforcement at the D22 Validate seam (doc 23 §6, the
// `Validate`-seam enforcement point). These tests exercise the scope predicate
// on the scoped session token (doc 19 §3/§5): a presentation is denied
// `scope_insufficient` when the token's `ds_scopes` do not COVER a scope the
// requested operation asserted via `ValidateRequest.desired_scopes`, and passes
// unchanged when the scope set covers the demand (or no demand is made). The
// seam dual-run case proves the REAL server adapter and an independently
// programmed FAKE agree on the scope-insufficient verdict over the same wire.
// Everything synthetic (D50).
package mint

import (
	"context"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
)

// The D127 scope strings under test (doc 23 §6). Named locally rather than
// imported: identity/mint's only legal cross-tree import is proto/gen/go (D80),
// so the auth-sdk/token scope constants are not reachable here — the seam
// asserts opaque scope STRINGS carried on the token and on desired_scopes, and
// the byte-identical Go/Rust coupling is pinned by scripts/check-corpus-suffix.sh.
const (
	scopeNetEgress = "v1:network:egress"
	scopeCodeRead  = "v1:code:read"
	scopeCodeWrite = "v1:code:write"
)

// mintScopedBase mints a base session token carrying scopes and registers the
// session's grant so the D22 signature/liveness/grant checks pass — leaving the
// scope predicate as the only variable under test.
func mintScopedBase(t *testing.T, shim *Shim, scopes []string) *SessionTokenBundle {
	t.Helper()
	req := baseTokenReq()
	req.Scopes = scopes
	bundle, err := shim.MintSessionToken(req)
	if err != nil {
		t.Fatalf("MintSessionToken: %v", err)
	}
	if err := shim.GrantSession(testSession, testSvc, "grant-ref-scope"); err != nil {
		t.Fatalf("GrantSession: %v", err)
	}
	return bundle
}

// TestValidateScoped_CoversAndDenies pins both arms of the native predicate: a
// demanded scope the token HOLDS passes (ALLOW), a demanded scope the token
// LACKS denies scope_insufficient, and an EMPTY demand makes no assertion
// (backward-compatible with the scope-unqualified Validate).
func TestValidateScoped_CoversAndDenies(t *testing.T) {
	shim := newTestShim(t)
	bundle := mintScopedBase(t, shim, []string{scopeCodeRead, scopeNetEgress})

	// COVERED: the token holds v1:network:egress → ALLOW.
	if res := shim.ValidateScoped(bundle.Token, testSession, testSvc, []string{scopeNetEgress}); res.Verdict != VerdictAllow {
		t.Fatalf("held scope want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	// COVERED (multi): both demanded scopes are held → ALLOW.
	if res := shim.ValidateScoped(bundle.Token, testSession, testSvc, []string{scopeCodeRead, scopeNetEgress}); res.Verdict != VerdictAllow {
		t.Fatalf("held multi-scope want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	// NOT COVERED: v1:code:write is not on the token → DENY scope_insufficient.
	res := shim.ValidateScoped(bundle.Token, testSession, testSvc, []string{scopeCodeWrite})
	if res.Verdict != VerdictDeny {
		t.Fatal("unheld scope want DENY, got ALLOW")
	}
	if res.MachineReadableReason != ReasonScopeInsufficient {
		t.Fatalf("reason = %q, want %q", res.MachineReadableReason, ReasonScopeInsufficient)
	}
	// NOT COVERED (partial): one held, one not → the whole demand fails closed.
	if res := shim.ValidateScoped(bundle.Token, testSession, testSvc, []string{scopeNetEgress, scopeCodeWrite}); res.MachineReadableReason != ReasonScopeInsufficient {
		t.Fatalf("partial-cover reason = %q, want %q", res.MachineReadableReason, ReasonScopeInsufficient)
	}
	// EMPTY demand: no scope assertion — ALLOW (the pre-scope path), identical to
	// the scope-unqualified Validate.
	if res := shim.ValidateScoped(bundle.Token, testSession, testSvc, nil); res.Verdict != VerdictAllow {
		t.Fatalf("empty demand want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	if plain := shim.Validate(bundle.Token, testSession, testSvc); plain.Verdict != VerdictAllow {
		t.Fatalf("scope-unqualified Validate want ALLOW, got DENY(%s)", plain.MachineReadableReason)
	}
}

// TestValidateScoped_AttenuationDropsScope proves the doc 19 §4 monotonic
// property carries D127 scopes: a child token that narrows scopes to drop
// v1:network:egress is then DENIED scope_insufficient when that scope is
// demanded — even though the parent held it — and a widening re-add fails closed.
func TestValidateScoped_AttenuationDropsScope(t *testing.T) {
	shim := newTestShim(t)
	base := mintScopedBase(t, shim, []string{scopeCodeRead, scopeNetEgress})

	childSession := "00000000-0000-4000-8000-0000000000c1"
	child, err := shim.AttenuateSessionToken(base, SessionTokenAttenuation{
		ChildSessionUUID: childSession,
		Scopes:           []string{scopeCodeRead}, // drop v1:network:egress (⊆ parent)
	})
	if err != nil {
		t.Fatalf("AttenuateSessionToken: %v", err)
	}
	// Establish the child as a token-bearing, granted session so only the scope
	// predicate varies.
	if _, err := shim.MintSessionToken(MintSessionTokenReq{SessionUUID: childSession, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	if err := shim.GrantSession(childSession, testSvc, "grant-ref-child"); err != nil {
		t.Fatal(err)
	}

	// The child still covers v1:code:read ...
	if res := shim.ValidateScoped(child.Token, childSession, testSvc, []string{scopeCodeRead}); res.Verdict != VerdictAllow {
		t.Fatalf("child held scope want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	// ... but no longer covers the dropped v1:network:egress → scope_insufficient.
	if res := shim.ValidateScoped(child.Token, childSession, testSvc, []string{scopeNetEgress}); res.MachineReadableReason != ReasonScopeInsufficient {
		t.Fatalf("child dropped scope want %q, got verdict=%v reason=%q", ReasonScopeInsufficient, res.Verdict, res.MachineReadableReason)
	}
	// A widening re-add of a scope the parent held but the child dropped fails
	// closed (monotonic narrowing, doc 19 §4).
	if _, err := shim.AttenuateSessionToken(child, SessionTokenAttenuation{
		Scopes: []string{scopeCodeRead, scopeNetEgress},
	}); err != errSessionTokenScope {
		t.Fatalf("scope-widening want errSessionTokenScope, got %v", err)
	}
}

// TestValidateScoped_EmptyParentScopeIsFloorNotWildcard pins the security-critical
// direction: an UNSCOPED base token (empty ds_scopes) is the FLOOR, not an
// "unrestricted" wildcard. A child attenuation that tries to ADD any scope to an
// empty parent is a widening and MUST fail closed (errSessionTokenScope), and the
// unscoped token itself covers NO demanded scope at the D22 seam. This guards
// against a future refactor that (mis)reads empty-parent as a wildcard — which
// would let a fan-out hop mint egress authority its parent never held.
func TestValidateScoped_EmptyParentScopeIsFloorNotWildcard(t *testing.T) {
	shim := newTestShim(t)
	base := mintScopedBase(t, shim, nil) // empty ds_scopes

	// The unscoped base covers no demanded scope (fail-closed at the seam).
	if res := shim.ValidateScoped(base.Token, testSession, testSvc, []string{scopeNetEgress}); res.MachineReadableReason != ReasonScopeInsufficient {
		t.Fatalf("unscoped base want %q, got verdict=%v reason=%q", ReasonScopeInsufficient, res.Verdict, res.MachineReadableReason)
	}
	// ... yet an empty demand still ALLOWs (no scope assertion).
	if res := shim.ValidateScoped(base.Token, testSession, testSvc, nil); res.Verdict != VerdictAllow {
		t.Fatalf("unscoped base empty-demand want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	// A child that tries to ADD a scope to the empty parent is a widening → closed.
	if _, err := shim.AttenuateSessionToken(base, SessionTokenAttenuation{
		ChildSessionUUID: "00000000-0000-4000-8000-0000000000c2",
		Scopes:           []string{scopeCodeRead},
	}); err != errSessionTokenScope {
		t.Fatalf("empty-parent widening want errSessionTokenScope, got %v", err)
	}
}

// TestValidateScoped_NonScopedCredentialFailsClosed proves a credential that
// carries NO ds_scopes claim (a workload JWT — §3.1) cannot satisfy a non-empty
// scope demand: it denies scope_insufficient (fail-closed), while an empty demand
// leaves the workload leg's ALLOW unchanged.
func TestValidateScoped_NonScopedCredentialFailsClosed(t *testing.T) {
	shim := newTestShim(t)
	wl, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID:   testSession,
		LaunchingUser: "idp-subject-xyz",
		Org:           testOrg,
		RepoBranch:    "acme/app@main",
		Runtime:       "claude-code",
	})
	if err != nil {
		t.Fatalf("MintWorkloadIdentity: %v", err)
	}
	if err := shim.GrantSession(testSession, testSvc, "grant-ref-wl"); err != nil {
		t.Fatal(err)
	}
	// Empty demand: the workload JWT validates as before (no scope assertion).
	if res := shim.ValidateScoped([]byte(wl.JWT), testSession, testSvc, nil); res.Verdict != VerdictAllow {
		t.Fatalf("workload JWT empty-demand want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	// Non-empty demand against an unscoped credential fails CLOSED.
	res := shim.ValidateScoped([]byte(wl.JWT), testSession, testSvc, []string{scopeNetEgress})
	if res.Verdict != VerdictDeny || res.MachineReadableReason != ReasonScopeInsufficient {
		t.Fatalf("workload JWT scoped-demand want DENY(%s), got verdict=%v reason=%q", ReasonScopeInsufficient, res.Verdict, res.MachineReadableReason)
	}
}

// scopeReferenceValidate is an independent reference implementation of the D22 +
// D127 scope contract for the dual-run FAKE: given the scenario's known token
// scopes, it returns exactly the verdict the seam must produce for a demanded
// scope set. It is deliberately NOT the production predicate — it is the
// specification the real adapter is checked against, so a real-vs-fake match is
// meaningful.
func scopeReferenceValidate(tokenScopes, desired []string) *identityv1.ValidateResponse {
	held := make(map[string]struct{}, len(tokenScopes))
	for _, s := range tokenScopes {
		held[s] = struct{}{}
	}
	for _, d := range desired {
		if _, ok := held[d]; !ok {
			return &identityv1.ValidateResponse{
				Verdict:               identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY,
				MachineReadableReason: ReasonScopeInsufficient,
			}
		}
	}
	return &identityv1.ValidateResponse{Verdict: identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW}
}

// TestValidateSeam_ScopeDualRun is the seam DUAL-RUN: it drives the SAME
// ValidateRequest (a scoped session token + a demanded scope the token lacks)
// through BOTH the REAL server adapter (NewValidationServer over the in-process
// wire) AND an independently programmed FAKE (identityv1fake), and asserts they
// agree on the scope_insufficient verdict — the D24/D14 dual-run contract, here
// covering the D127 enforcement point (doc 23 §6). It also runs the ALLOW arm so
// the agreement is proven on both sides of the predicate, not just the deny.
func TestValidateSeam_ScopeDualRun(t *testing.T) {
	shim := newTestShim(t)
	tokenScopes := []string{scopeCodeRead, scopeNetEgress}
	bundle := mintScopedBase(t, shim, tokenScopes)

	// REAL: the shim adapter behind the generated Validate seam, over bufconn.
	realClient, _ := dialInProcess(t, shim)

	cases := []struct {
		name    string
		desired []string
	}{
		{"deny_unheld_scope", []string{scopeCodeWrite}},                  // not held → scope_insufficient
		{"allow_held_scope", []string{scopeNetEgress}},                   // held → ALLOW
		{"deny_partial_cover", []string{scopeNetEgress, scopeCodeWrite}}, // one missing → deny
		{"allow_empty_demand", nil},                                      // no assertion → ALLOW
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &identityv1.ValidateRequest{
				PresentedCredential: bundle.Token,
				SessionRef:          &boundaryv1.SessionRef{SessionUuid: testSession},
				ServiceId:           testSvc,
				DesiredScopes:       tc.desired,
			}

			// FAKE: programmed to the reference contract for this token's scopes.
			fake := &identityv1fake.IdentityValidationServiceFake{
				ValidateResponder: func(_ context.Context, r *identityv1.ValidateRequest) (*identityv1.ValidateResponse, error) {
					return scopeReferenceValidate(tokenScopes, r.GetDesiredScopes()), nil
				},
			}

			realResp, err := realClient.Validate(context.Background(), req)
			if err != nil {
				t.Fatalf("real Validate returned a transport error, not an in-band verdict: %v", err)
			}
			fakeResp, err := fake.Validate(context.Background(), req)
			if err != nil {
				t.Fatalf("fake Validate: %v", err)
			}

			// The dual-run assertion: real and fake AGREE on the verdict and the
			// machine-readable reason (the scope_insufficient body on a deny).
			if realResp.GetVerdict() != fakeResp.GetVerdict() {
				t.Fatalf("real/fake verdict disagree: real=%v fake=%v", realResp.GetVerdict(), fakeResp.GetVerdict())
			}
			if realResp.GetMachineReadableReason() != fakeResp.GetMachineReadableReason() {
				t.Fatalf("real/fake reason disagree: real=%q fake=%q", realResp.GetMachineReadableReason(), fakeResp.GetMachineReadableReason())
			}
			// And the fake recorded the presentation (it is a stand-in, not a stub).
			if got := fake.ValidateRecorded(); len(got) != 1 {
				t.Fatalf("fake recorded %d calls, want 1", len(got))
			}
		})
	}
}
