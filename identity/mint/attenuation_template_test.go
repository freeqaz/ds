// SPDX-License-Identifier: Apache-2.0

// Offline-attenuation TEMPLATE VOCABULARY + fan-out RESIDUE tests (doc 19 §4/§8/
// §11/§13). These cover the genuine residue beyond the AttenuateSessionToken core
// (sessiontoken_test.go): the typed template constructors (BuildChildAttenuation /
// DeriveChildSession), the role-template §11 seam, depth-≥2 child-of-child fan-out
// with widening rejection at the deeper hop, and the §13 narrowing-monotonicity
// rows proved end-to-end through the template surface. Everything synthetic (D50);
// the derivation is pure (no mint RPC, no network) — asserted via a counting
// substrate signer.
package mint

import (
	"testing"
	"time"
)

const (
	tmplRootSession  = "00000000-0000-4000-8000-000000000a01" // == testSession
	tmplChildSession = "00000000-0000-4000-8000-0000000000c1"
	tmplGrandSession = "00000000-0000-4000-8000-0000000000c2"
)

func tmplBaseReq() MintSessionTokenReq {
	return MintSessionTokenReq{
		SessionUUID:   tmplRootSession,
		LaunchingUser: testLaunchingUser,
		Org:           testOrg,
		RepoBranch:    "acme/app@main",
		RoleRef:       testRoleRef,
		TaskRef:       testTaskRef,
		Services:      []string{"github", "npm", "pypi"},
	}
}

// --- BuildChildAttenuation: the typed template vocabulary (doc 19 §4, D52) ----

// TestBuildChildAttenuation_NarrowsAllAxes proves the typed template composes the
// four grant-model dimensions (identity × service × scope × TTL) into a narrowing
// record — no hand-authored caveat anywhere. Service set intersects to ⊆ parent;
// the TTL clamps to the soonest horizon; identity/task ride as the lineage hop.
func TestBuildChildAttenuation_NarrowsAllAxes(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	parentExpiry := now.Add(4 * time.Hour)
	parentServices := []string{"github", "npm", "pypi"}

	got := BuildChildAttenuation(ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github", "npm"}, // ⊆ parent
		TTL:              time.Hour,                 // shorter than the 4h parent horizon
		TaskRef:          "task:child",
	}, parentExpiry, parentServices, now, nil)

	if got.ChildSessionUUID != tmplChildSession {
		t.Fatalf("identity axis: child session = %q, want %q", got.ChildSessionUUID, tmplChildSession)
	}
	if len(got.Services) != 2 || got.Services[0] != "github" || got.Services[1] != "npm" {
		t.Fatalf("service axis: got %v, want [github npm]", got.Services)
	}
	wantExpiry := now.Add(time.Hour)
	if !got.Expiry.Equal(wantExpiry) {
		t.Fatalf("ttl axis: expiry = %v, want soonest %v", got.Expiry, wantExpiry)
	}
	if got.TaskRef != "task:child" {
		t.Fatalf("task_ref = %q, want task:child", got.TaskRef)
	}
}

// TestBuildChildAttenuation_NeverWidens proves the template can ONLY narrow: an
// explicit service set NOT ⊆ the parent is intersected DOWN to the overlap (it can
// never add a service the parent lacks), and a TTL longer than the parent horizon
// is clamped to the parent expiry.
func TestBuildChildAttenuation_NeverWidens(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	parentExpiry := now.Add(time.Hour)

	got := BuildChildAttenuation(ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github", "s3"}, // s3 NOT in the parent scope
		TTL:              8 * time.Hour,            // longer than the 1h parent horizon
	}, parentExpiry, []string{"github", "npm"}, now, nil)

	// Service: only the overlap survives — s3 is dropped, never added.
	if len(got.Services) != 1 || got.Services[0] != "github" {
		t.Fatalf("widening service request must intersect down: got %v, want [github]", got.Services)
	}
	// TTL: an over-long request can never widen past the parent. The template
	// expresses "no TTL narrowing beyond the parent" as a ZERO attenuation Expiry
	// (the substrate then keeps the parent horizon) — so the effective child horizon
	// is the parent expiry, asserted via the effective-horizon helper below.
	if eff := effectiveChildExpiry(got.Expiry, parentExpiry); !eff.Equal(parentExpiry) {
		t.Fatalf("over-long TTL must not widen past parent expiry %v, effective got %v", parentExpiry, eff)
	}
	if got.Expiry.After(parentExpiry) {
		t.Fatalf("attenuation expiry %v must never exceed parent %v", got.Expiry, parentExpiry)
	}
}

// effectiveChildExpiry resolves what AttenuateSessionToken will use: the narrowing
// Expiry when set, else the inherited parent horizon. Mirrors the substrate's own
// "zero narrow.Expiry keeps the parent expiry" rule (sessiontoken.go).
func effectiveChildExpiry(attenuationExpiry, parentExpiry time.Time) time.Time {
	if attenuationExpiry.IsZero() {
		return parentExpiry
	}
	return attenuationExpiry
}

// TestBuildChildAttenuation_InheritsWhenUnconstrained proves an empty params set
// (no service narrowing, no TTL) yields a record that asserts NO narrowing on the
// service/TTL axes (nil Services, zero Expiry) — the substrate then keeps the
// parent scope/horizon, and the only change is the appended identity-lineage hop.
func TestBuildChildAttenuation_InheritsWhenUnconstrained(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	parentExpiry := now.Add(time.Hour)

	got := BuildChildAttenuation(ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
	}, parentExpiry, []string{"github", "npm"}, now, nil)

	if got.Services != nil {
		t.Fatalf("unconstrained service axis should be nil (inherit), got %v", got.Services)
	}
	if !got.Expiry.IsZero() {
		t.Fatalf("unconstrained TTL axis should be zero (inherit), got %v", got.Expiry)
	}
	if got.ChildSessionUUID != tmplChildSession {
		t.Fatalf("identity hop missing: %q", got.ChildSessionUUID)
	}
}

// --- the role-template §11 seam (doc 19 §11, doc 18 §8) ----------------------

// TestRoleTemplateSeam_AppliesDefaultNarrowing proves the §11 role-template hook
// folds a role's default service ceiling + MaxTTL into the derivation, keyed by
// role_ref — the typed seam record, not a role engine. The role narrows further
// than the explicit request alone.
func TestRoleTemplateSeam_AppliesDefaultNarrowing(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	parentExpiry := now.Add(8 * time.Hour)

	// A resolver that maps role:reviewer -> {github} ceiling, 30m MaxTTL.
	resolver := func(roleRef string) (RoleAttenuationTemplate, bool) {
		if roleRef == "role:reviewer" {
			return RoleAttenuationTemplate{Services: []string{"github"}, MaxTTL: 30 * time.Minute}, true
		}
		return RoleAttenuationTemplate{}, false
	}

	got := BuildChildAttenuation(ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github", "npm"}, // explicit asks for both ...
		RoleRef:          "role:reviewer",
	}, parentExpiry, []string{"github", "npm", "pypi"}, now, resolver)

	// ... but the role ceiling {github} intersects it down to {github}.
	if len(got.Services) != 1 || got.Services[0] != "github" {
		t.Fatalf("role ceiling must narrow to [github], got %v", got.Services)
	}
	// The role MaxTTL (30m) is the soonest horizon, beating the 8h parent.
	wantExpiry := now.Add(30 * time.Minute)
	if !got.Expiry.Equal(wantExpiry) {
		t.Fatalf("role MaxTTL must clamp expiry to %v, got %v", wantExpiry, got.Expiry)
	}
}

// TestRoleTemplateSeam_UnknownRoleIsNoDefault proves an unknown role_ref (resolver
// returns ok=false) is NOT an error — the derivation proceeds with no role default
// (safe: the substrate fails any widening closed regardless). v0's nil-resolver
// posture is the same: no role default.
func TestRoleTemplateSeam_UnknownRoleIsNoDefault(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	parentExpiry := now.Add(time.Hour)
	resolver := func(string) (RoleAttenuationTemplate, bool) { return RoleAttenuationTemplate{}, false }

	got := BuildChildAttenuation(ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github"},
		RoleRef:          "role:unknown",
	}, parentExpiry, []string{"github", "npm"}, now, resolver)
	if len(got.Services) != 1 || got.Services[0] != "github" {
		t.Fatalf("unknown role must apply no default: got %v", got.Services)
	}

	// nil resolver: identical no-default behavior.
	got2 := BuildChildAttenuation(ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github"},
		RoleRef:          "role:reviewer",
	}, parentExpiry, []string{"github", "npm"}, now, nil)
	if len(got2.Services) != 1 || got2.Services[0] != "github" {
		t.Fatalf("nil resolver must apply no default: got %v", got2.Services)
	}
}

// --- DeriveChildSession: the offline fan-out entrypoint (doc 19 §4) ----------

// TestDeriveChildSession_OfflineNarrowingThroughTemplate proves the convenience
// fan-out entrypoint derives a strictly-narrower child token from the parent
// bundle's OWN claims (the parent scope is read from the token, not caller-
// asserted), via the typed template — and the child validates for its narrowed
// service, denied for one outside it (the doc 19 §8 grant ∩ token-scope row).
func TestDeriveChildSession_OfflineNarrowingThroughTemplate(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq()) // scope {github, npm, pypi}
	if err != nil {
		t.Fatal(err)
	}
	child, err := shim.DeriveChildSession(base, ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github"},
		TaskRef:          "task:child",
	}, nil, shim.now())
	if err != nil {
		t.Fatal(err)
	}
	if child.AttenuationDepth != 1 {
		t.Fatalf("child depth = %d, want 1", child.AttenuationDepth)
	}

	claims, _, err := shim.tokenSigner.Verify(child.Token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.SessionUUID != tmplChildSession || claims.ParentSession != tmplRootSession {
		t.Fatalf("lineage hop wrong: session=%q parent=%q", claims.SessionUUID, claims.ParentSession)
	}
	if len(claims.Services) != 1 || claims.Services[0] != "github" {
		t.Fatalf("child scope = %v, want [github]", claims.Services)
	}

	// Register the child as a token-bearing session and validate the §8 intersection.
	if _, err := shim.MintSessionToken(MintSessionTokenReq{SessionUUID: tmplChildSession, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(tmplChildSession, "github", "cg")
	_ = shim.GrantSession(tmplChildSession, "npm", "cn")
	if res := shim.Validate(child.Token, tmplChildSession, "github"); res.Verdict != VerdictAllow {
		t.Fatalf("child want ALLOW for github, got DENY(%s)", res.MachineReadableReason)
	}
	if res := shim.Validate(child.Token, tmplChildSession, "npm"); res.Verdict != VerdictDeny {
		t.Fatal("child want DENY for npm (outside narrowed scope), got ALLOW")
	}
}

// TestDeriveChildSession_RejectsMissingInputs proves the entrypoint guards: no
// parent token, no child session_uuid each fail closed with a typed error.
func TestDeriveChildSession_RejectsMissingInputs(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shim.DeriveChildSession(nil, ChildSessionParams{ChildSessionUUID: tmplChildSession}, nil, shim.now()); err != errNoParentToken {
		t.Fatalf("nil parent want errNoParentToken, got %v", err)
	}
	if _, err := shim.DeriveChildSession(base, ChildSessionParams{}, nil, shim.now()); err != errNoChildSession {
		t.Fatalf("empty child session want errNoChildSession, got %v", err)
	}
}

// --- DEPTH ≥ 2: child-of-child fan-out (the brief's acceptance bar) ----------

// TestDeriveChildSession_DepthTwoChildOfChild proves the fan-out derivation at
// DEPTH ≥ 2 (a child-of-child): grandchild ⊆ child ⊆ root on the service axis, the
// parent_session lineage hop advances at each level, and a WIDENING attempt at the
// DEEPER hop (the grandchild trying to re-add a service the child dropped) fails
// closed (monotonic narrowing, doc 19 §4 / §13). This is the brief's required
// depth-≥2 + widening-rejection coverage.
func TestDeriveChildSession_DepthTwoChildOfChild(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq()) // {github, npm, pypi}
	if err != nil {
		t.Fatal(err)
	}

	// Depth 1: child narrows to {github, npm}.
	child, err := shim.DeriveChildSession(base, ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github", "npm"},
		TaskRef:          "task:child",
	}, nil, shim.now())
	if err != nil {
		t.Fatal(err)
	}
	if child.AttenuationDepth != 1 {
		t.Fatalf("child depth = %d, want 1", child.AttenuationDepth)
	}

	// Depth 2: grandchild narrows further to {github} — a child-of-child.
	grand, err := shim.DeriveChildSession(child, ChildSessionParams{
		ChildSessionUUID: tmplGrandSession,
		Services:         []string{"github"},
		TaskRef:          "task:grandchild",
	}, nil, shim.now())
	if err != nil {
		t.Fatal(err)
	}
	if grand.AttenuationDepth != 2 {
		t.Fatalf("grandchild depth = %d, want 2 (child-of-child)", grand.AttenuationDepth)
	}
	if len(grand.RevocationIDs) != 3 {
		t.Fatalf("grandchild revocation IDs = %d, want 3 (base + 2 hops)", len(grand.RevocationIDs))
	}

	gClaims, depth, err := shim.tokenSigner.Verify(grand.Token)
	if err != nil {
		t.Fatal(err)
	}
	if depth != 2 {
		t.Fatalf("decoded grandchild depth = %d, want 2", depth)
	}
	// Lineage: the grandchild's parent_session is the CHILD session (the hop
	// advanced), and its own session is the grandchild session.
	if gClaims.SessionUUID != tmplGrandSession {
		t.Fatalf("grandchild session = %q, want %q", gClaims.SessionUUID, tmplGrandSession)
	}
	if gClaims.ParentSession != tmplChildSession {
		t.Fatalf("grandchild parent_session = %q, want the child hop %q", gClaims.ParentSession, tmplChildSession)
	}
	// Service: ⊆ child ⊆ root.
	if len(gClaims.Services) != 1 || gClaims.Services[0] != "github" {
		t.Fatalf("grandchild scope = %v, want [github]", gClaims.Services)
	}

	// WIDENING AT THE DEEPER HOP: the grandchild cannot re-add npm (which the child
	// still held but the grandchild dropped) — fails closed (doc 19 §4 / §13).
	if _, err := shim.AttenuateSessionToken(grand, SessionTokenAttenuation{
		Services: []string{"github", "npm"},
	}); err != errSessionTokenScope {
		t.Fatalf("depth-3 widening want errSessionTokenScope, got %v", err)
	}

	// And the grandchild validates ONLY for github under its own session.
	if _, err := shim.MintSessionToken(MintSessionTokenReq{SessionUUID: tmplGrandSession, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(tmplGrandSession, "github", "gg")
	_ = shim.GrantSession(tmplGrandSession, "npm", "gn")
	if res := shim.Validate(grand.Token, tmplGrandSession, "github"); res.Verdict != VerdictAllow {
		t.Fatalf("grandchild want ALLOW for github, got DENY(%s)", res.MachineReadableReason)
	}
	if res := shim.Validate(grand.Token, tmplGrandSession, "npm"); res.Verdict != VerdictDeny {
		t.Fatal("grandchild want DENY for npm (dropped at depth 2), got ALLOW")
	}
}

// --- doc 19 §7 / §13: WHOLE-CHAIN liveness keyed on the ROOT session -----------

// TestChainRevocation_RootRevokeFailsDescendantClosed proves the doc 19 §7 / §13
// chain-revocation row: RevokeSession on the ROOT session fails a DESCENDANT token
// closed IMMEDIATELY, even while the descendant's OWN session is independently live
// and granted. This is the residue the Validate-fold was missing — a child carries
// the originating root_session claim, and Validate keys whole-chain liveness on it.
func TestChainRevocation_RootRevokeFailsDescendantClosed(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq()) // root = tmplRootSession
	if err != nil {
		t.Fatal(err)
	}
	child, err := shim.DeriveChildSession(base, ChildSessionParams{
		ChildSessionUUID: tmplChildSession,
		Services:         []string{"github"},
	}, nil, shim.now())
	if err != nil {
		t.Fatal(err)
	}
	// The child's own session is independently live + granted (its create
	// choreography minted a base for it).
	if _, err := shim.MintSessionToken(MintSessionTokenReq{SessionUUID: tmplChildSession, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(tmplChildSession, "github", "cg")

	// Pre-revoke: the child validates.
	if res := shim.Validate(child.Token, tmplChildSession, "github"); res.Verdict != VerdictAllow {
		t.Fatalf("pre-revoke child want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}

	// REVOKE THE ROOT — the WHOLE chain must fail closed immediately (doc 19 §7),
	// surfacing the operator reason on the D77 channel, even though the child
	// session itself is untouched.
	if err := shim.RevokeSession(tmplRootSession, "root_killed"); err != nil {
		t.Fatal(err)
	}
	res := shim.Validate(child.Token, tmplChildSession, "github")
	if res.Verdict != VerdictDeny {
		t.Fatal("post-root-revoke child want DENY (whole-chain liveness, doc 19 §7), got ALLOW")
	}
	if res.MachineReadableReason != "root_killed" {
		t.Fatalf("root revoke reason not surfaced on the chain: %q", res.MachineReadableReason)
	}

	// The base (root) token itself of course also fails closed.
	_ = shim.GrantSession(tmplRootSession, "github", "rg")
	if res := shim.Validate(base.Token, tmplRootSession, "github"); res.Verdict != VerdictDeny {
		t.Fatal("post-revoke root token want DENY, got ALLOW")
	}
}

// TestChainRevocation_RootRevokeFailsGrandchildClosed extends the §7 row to DEPTH 2
// (a grandchild): the originating root is pinned and inherited unchanged through
// both hops, so a root revoke fails the GRANDCHILD closed too — the property holds
// for the whole descendant tree, not just immediate children.
func TestChainRevocation_RootRevokeFailsGrandchildClosed(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq())
	if err != nil {
		t.Fatal(err)
	}
	child, err := shim.DeriveChildSession(base, ChildSessionParams{
		ChildSessionUUID: tmplChildSession, Services: []string{"github", "npm"},
	}, nil, shim.now())
	if err != nil {
		t.Fatal(err)
	}
	grand, err := shim.DeriveChildSession(child, ChildSessionParams{
		ChildSessionUUID: tmplGrandSession, Services: []string{"github"},
	}, nil, shim.now())
	if err != nil {
		t.Fatal(err)
	}

	// The grandchild's claims pin the ORIGINATING root (not the immediate parent):
	// parent_session = child, root_session = the base.
	gClaims, _, err := shim.tokenSigner.Verify(grand.Token)
	if err != nil {
		t.Fatal(err)
	}
	if gClaims.ParentSession != tmplChildSession {
		t.Fatalf("grandchild parent_session = %q, want %q", gClaims.ParentSession, tmplChildSession)
	}
	if gClaims.RootSession != tmplRootSession {
		t.Fatalf("grandchild root_session = %q, want the originating root %q", gClaims.RootSession, tmplRootSession)
	}

	// The grandchild's own session is independently live + granted.
	if _, err := shim.MintSessionToken(MintSessionTokenReq{SessionUUID: tmplGrandSession, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(tmplGrandSession, "github", "gg")
	if res := shim.Validate(grand.Token, tmplGrandSession, "github"); res.Verdict != VerdictAllow {
		t.Fatalf("pre-revoke grandchild want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}

	// Revoke the ROOT — the grandchild (depth 2) fails closed.
	if err := shim.RevokeSession(tmplRootSession, "root_killed"); err != nil {
		t.Fatal(err)
	}
	if res := shim.Validate(grand.Token, tmplGrandSession, "github"); res.Verdict != VerdictDeny {
		t.Fatal("post-root-revoke grandchild want DENY (whole-chain liveness at depth 2), got ALLOW")
	}
}

// TestChainRevocation_UnknownRootDoesNotFailLocally proves the bound on the §7
// check: a descendant whose ORIGINATING root the shim has NO record of (the root
// lives on another host) is NOT failed by the local root check — the descendant's
// own liveness governs, and cross-host revocation rides the fleet list (doc 19 §7),
// not this local lookup. This keeps the check fail-CLOSED only on roots the shim
// actually knows are dead, never fail-closed on an absent root.
func TestChainRevocation_UnknownRootDoesNotFailLocally(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(tmplBaseReq())
	if err != nil {
		t.Fatal(err)
	}
	child, err := shim.DeriveChildSession(base, ChildSessionParams{
		ChildSessionUUID: tmplChildSession, Services: []string{"github"},
	}, nil, shim.now())
	if err != nil {
		t.Fatal(err)
	}
	// Forget the root record entirely (simulating "root lives on another host"):
	// drop it from this shim's store, leaving only the child live.
	shim.mu.Lock()
	delete(shim.sessions, tmplRootSession)
	shim.mu.Unlock()

	if _, err := shim.MintSessionToken(MintSessionTokenReq{SessionUUID: tmplChildSession, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(tmplChildSession, "github", "cg")
	// The child still validates: an UNKNOWN root is not a local liveness failure.
	if res := shim.Validate(child.Token, tmplChildSession, "github"); res.Verdict != VerdictAllow {
		t.Fatalf("unknown-root child want ALLOW (descendant liveness governs), got DENY(%s)", res.MachineReadableReason)
	}
}

// TestDeriveChildSession_FanOutZeroMintRPCs proves the killer-fit property through
// the TEMPLATE entrypoint: a 5-wide fan-out (and a depth-2 hop) derive from one
// base mint with ZERO additional mint calls — the derivation path is pure library,
// no network (doc 19 §4). A counting substrate signer asserts only the base mint
// (plus the child-session base mints the test itself makes) hit Mint; the
// derivation hops never do.
func TestDeriveChildSession_FanOutZeroMintRPCs(t *testing.T) {
	shim := newTestShim(t)
	counter := &countingSigner{SubstrateSigner: shim.tokenSigner}
	shim.tokenSigner = counter

	base, err := shim.MintSessionToken(tmplBaseReq())
	if err != nil {
		t.Fatal(err)
	}
	if counter.mints != 1 {
		t.Fatalf("base mint count = %d, want 1", counter.mints)
	}

	// 5-wide fan-out via the template entrypoint — each derivation is pure (no mint).
	for i := 0; i < 5; i++ {
		child, err := shim.DeriveChildSession(base, ChildSessionParams{
			ChildSessionUUID: tmplChildSession,
			Services:         []string{"github"},
		}, nil, shim.now())
		if err != nil {
			t.Fatal(err)
		}
		// A depth-2 hop off each child — still no mint.
		if _, err := shim.DeriveChildSession(child, ChildSessionParams{
			ChildSessionUUID: tmplGrandSession,
			Services:         []string{"github"},
		}, nil, shim.now()); err != nil {
			t.Fatal(err)
		}
	}
	if counter.mints != 1 {
		t.Fatalf("after fan-out + depth-2 hops mint count = %d, want 1 (zero mint RPCs at fan-out, doc 19 §4)", counter.mints)
	}
}
